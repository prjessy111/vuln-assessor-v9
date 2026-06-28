'use strict';
/**
 * 점검 스크립트 자동 생성기 (VULN_ASSESSOR_TODO.md §3-2)
 *
 * 항목의 자연어 설명 + 대상 OS → 점검 명령/스크립트 자동 생성.
 *  - Linux  → POSIX sh
 *  - Windows → PowerShell
 *
 * 생성된 스크립트는 반드시 safetyGate.inspect()를 통과해야 하며,
 * 실행 전 사람 승인 단계를 거친다(라우트에서 게이트 처리).
 *
 * LLM 미설정(개발/폐쇄망) 시 템플릿 폴백으로 읽기 전용 스캐폴드를 생성하되,
 * generated_by='template-fallback'로 명시한다(임의 판정 아님을 표기).
 */

const safetyGate = require('./safetyGate');
const { buildClient, resolveBackend, isBackendConfigured } = require('./llmClient');

const SYSTEM_PROMPT =
  '당신은 시스템 보안 점검 스크립트 작성 전문가입니다. ' +
  '주어진 점검 항목 설명을 읽고, 대상 OS에서 "읽기 전용"으로 현재 설정 상태를 ' +
  '수집하는 점검 스크립트를 작성합니다.\n' +
  '엄수 규칙:\n' +
  '1) 절대 시스템 상태를 변경하지 않는다 (조회/출력만). ' +
  'rm, chmod, chown, systemctl start/stop, 레지스트리 쓰기, 파일 쓰기, ' +
  '외부 네트워크 통신(curl/wget/Invoke-WebRequest) 금지.\n' +
  '2) Linux는 POSIX sh, Windows는 PowerShell로 작성한다.\n' +
  '3) 사람이 판정할 수 있도록 관련 설정값을 라벨과 함께 그대로 출력한다.\n' +
  '4) 출력은 반드시 JSON 한 개만: ' +
  '{"lang":"sh|powershell","code":"<스크립트 본문>","explanation":"<무엇을 어떻게 점검하는지>","expected_output":"<예상 출력 형태>"}';

function buildUserPrompt(item) {
  const os = item.os_target === 'windows' ? 'Windows (PowerShell)' : 'Linux (POSIX sh)';
  return [
    `[점검 항목]`,
    `제목: ${item.title}`,
    `대상 OS: ${os}`,
    `중요도: ${item.severity}`,
    item.source_ref ? `근거: ${item.source} / ${item.source_ref}` : `근거: ${item.source}`,
    ``,
    `[설명 — 이 내용을 점검하는 읽기 전용 스크립트를 작성하세요]`,
    item.description,
    ``,
    `반드시 JSON 한 개만 출력하세요.`,
  ].join('\n');
}

/**
 * 템플릿 폴백 — LLM 미설정 시 읽기 전용 스캐폴드 생성.
 * 실제 점검 로직은 운영자가 채워넣어야 하므로 그 사실을 스크립트에 명시한다.
 */
function templateFallback(item) {
  const isWin = item.os_target === 'windows';
  if (isWin) {
    const code = [
      '# [자동 생성 스캐폴드 - 운영자 검토 필요]',
      `# 점검 항목: ${item.title}`,
      `# 설명: ${item.description.replace(/\r?\n/g, ' ')}`,
      'Write-Output "=== 점검 대상 정보 ==="',
      'Write-Output "Host: $env:COMPUTERNAME"',
      'Write-Output "Date: $(Get-Date -Format o)"',
      'Write-Output "=== TODO: 위 설명에 맞는 읽기 전용 점검 명령을 추가하세요 ==="',
      '# 예) Get-ItemProperty, Get-LocalUser, Get-Service, Get-Content 등 조회 전용',
    ].join('\n');
    return { lang: 'powershell', code, explanation: '템플릿 폴백(스캐폴드). LLM 미설정으로 자동 생성 불가 — 운영자가 점검 명령을 채워야 합니다.', expected_output: '항목 설명에 해당하는 설정값 출력', generated_by: 'template-fallback' };
  }
  const code = [
    '#!/bin/sh',
    '# [자동 생성 스캐폴드 - 운영자 검토 필요]',
    `# 점검 항목: ${item.title}`,
    `# 설명: ${item.description.replace(/\r?\n/g, ' ')}`,
    'echo "=== 점검 대상 정보 ==="',
    'echo "Host: $(hostname 2>/dev/null)"',
    'echo "Date: $(date 2>/dev/null)"',
    'echo "=== TODO: 위 설명에 맞는 읽기 전용 점검 명령을 추가하세요 ==="',
    '# 예) cat / grep / stat / systemctl is-enabled / sshd -T 등 조회 전용',
  ].join('\n');
  return { lang: 'sh', code, explanation: '템플릿 폴백(스캐폴드). LLM 미설정으로 자동 생성 불가 — 운영자가 점검 명령을 채워야 합니다.', expected_output: '항목 설명에 해당하는 설정값 출력', generated_by: 'template-fallback' };
}

function _parseScriptJson(text) {
  if (!text) return null;
  const { _parseJsonResponse } = require('../engine/llm/client');
  const obj = _parseJsonResponse(text);
  if (!obj || !obj.code) return null;
  return {
    lang: obj.lang === 'powershell' || obj.lang === 'ps1' ? 'powershell' : 'sh',
    code: String(obj.code),
    explanation: String(obj.explanation || ''),
    expected_output: String(obj.expected_output || ''),
  };
}

/**
 * 항목에 대한 점검 스크립트 생성.
 * @param {object} item - itemRegistry 항목
 * @param {object} opts - { backend, model, timeoutMs }
 * @returns {Promise<object>} script 객체 (lang, code, explanation, expected_output, safety, generated_by, generated_at, model)
 */
async function generate(item, opts = {}) {
  const backend = resolveBackend(opts.backend);
  const now = () => new Date().toISOString().slice(0, 19).replace('T', ' ');

  let script;
  let model = null;

  if (!isBackendConfigured(backend)) {
    // LLM 미설정 → 템플릿 폴백
    script = templateFallback(item);
  } else {
    try {
      const client = buildClient(backend, opts);
      model = client.config.model;
      const res = await client.complete({
        system: SYSTEM_PROMPT,
        user: buildUserPrompt(item),
        responseFormat: 'json',
        temperature: 0.0,
      });
      const parsed = _parseScriptJson(res.text);
      if (!parsed) {
        script = { ...templateFallback(item), explanation: 'LLM 응답 파싱 실패 → 템플릿 폴백', generated_by: 'template-fallback' };
      } else {
        script = { ...parsed, generated_by: backend };
      }
    } catch (e) {
      script = { ...templateFallback(item), explanation: `LLM 호출 실패(${e.message}) → 템플릿 폴백`, generated_by: 'template-fallback' };
    }
  }

  // 안전 게이트 정적 검사
  script.safety = safetyGate.inspect(script.code);
  script.model = model;
  script.generated_at = now();
  return script;
}

module.exports = { generate, templateFallback, SYSTEM_PROMPT };

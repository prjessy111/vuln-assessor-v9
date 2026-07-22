'use strict';
/**
 * 자율 진단 파이프라인 (VULN_ASSESSOR_TODO.md §3-4)
 *
 * 3-1(항목 편입) → 3-2(스크립트 생성) → [게이트1: 사람 승인] → 수집 →
 * 3-3(자동 판정) → [게이트2: 불일치·애매 항목 사람 검토] 를 하나의 루프로 연결.
 *
 * 사람 확인 게이트(§0)는 코드로 강제한다:
 *  - 안전게이트 blocked 스크립트는 승인 불가.
 *  - 승인 전에는 수집·판정 단계로 진행 불가.
 *  - 판정이 needs_review면 confirm 전까지 confirmed로 못 간다.
 *
 * 모든 단계는 itemRegistry.update로 상태/이력을 남긴다.
 */

const itemRegistry = require('./itemRegistry');
const scriptGenerator = require('./scriptGenerator');
const autoJudge = require('./autoJudge');

/**
 * 3-2: 점검 스크립트 생성 (또는 재생성).
 * 항목 상태를 draft/rejected → script_generated 로 전이.
 */
async function generateScript(storage, itemId, opts = {}) {
  const item = itemRegistry.get(storage, itemId);
  if (!item) throw new Error(`항목 없음: ${itemId}`);

  const script = await scriptGenerator.generate(item, opts);
  return itemRegistry.update(
    storage, itemId,
    { script, status: 'script_generated', approval: null },
    `script_generated (${script.generated_by}, safety=${script.safety.risk})`,
    opts.by || 'agent'
  );
}

// 스크립트 코드에서 결과 파일 위치(글롭)를 추정. 결과를 파일에 쓰는 스크립트 대응(예: ad_collect → *_AD_DC.txt).
// 미검출 시 null 반환 → 실행부는 stdout 을 수집. (특정 형식 하드코딩 아님, 파일 위치 힌트만.)
function _detectResultGlob(code) {
  const c = String(code || '');
  // 1) '<이름>_AD_DC.txt' 산출 패턴 + OutDir 기본값
  if (/_AD_DC\.txt/i.test(c)) {
    const m = c.match(/OutDir\s*=\s*["']([^"']+)["']/i);
    const dir = m ? m[1].replace(/[\\/]+$/, '') : 'C:\\ad_audit';
    return `${dir}\\*_AD_DC.txt`;
  }
  // 2) PowerShell: Out-File -FilePath <path> / Set-Content -Path <path> (리터럴 경로일 때만)
  let m = c.match(/(?:Out-File|Set-Content)[^\n]*?(?:-(?:File)?Path\s+)?["']([A-Za-z]:\\[^"'\n]+\.\w+)["']/i);
  if (m) { const p = m[1]; const dir = p.replace(/\\[^\\]*$/, ''); const ext = (p.match(/\.(\w+)$/) || [])[1] || 'txt'; return `${dir}\\*.${ext}`; }
  // 3) sh: 리다이렉트 '> /abs/path.ext'
  m = c.match(/>\s*["']?(\/[^\s"'|;>]+\.\w+)["']?/);
  if (m) { const p = m[1]; const dir = p.replace(/\/[^/]*$/, ''); const ext = (p.match(/\.(\w+)$/) || [])[1] || 'txt'; return `${dir}/*.${ext}`; }
  return null;
}

/**
 * 3-2': 점검 스크립트 "직접 입력" (자연어 생성 대신 운영자가 스크립트를 그대로 제공).
 * 자연어→scriptGenerator 단계를 건너뛰고, 이후 승인→원격실행→판정 파이프라인은 그대로 재사용.
 * @param {object} input - { code, lang?, note?, expected_output?, by? }
 */
function provideScript(storage, itemId, input = {}) {
  const safetyGate = require('./safetyGate');
  const item = itemRegistry.get(storage, itemId);
  if (!item) throw new Error(`항목 없음: ${itemId}`);
  const code = String(input.code || '').trim();
  if (!code) throw new Error('스크립트 내용(code)이 필요합니다');

  // 언어 추정 (미지정 시)
  let lang = input.lang;
  if (!lang) {
    if (/#!\s*\/.*\b(ba)?sh\b/.test(code) || /\b(grep|awk|sed|chmod|\/etc\/)\b/.test(code)) lang = 'bash';
    else if (/param\s*\(|Get-\w+|\$env:|Import-Module|powershell/i.test(code)) lang = 'powershell';
    else lang = 'text';
  }
  const safety = safetyGate.inspect(code);
  // 결과 파일 위치(글롭) — 명시값 우선, 없으면 코드에서 자동 감지. 미검출 시 null → stdout 수집.
  const result_glob = input.result_glob || _detectResultGlob(code);
  const script = {
    lang,
    code,
    explanation: input.note || '운영자 직접 입력 스크립트',
    expected_output: input.expected_output || '',
    result_glob: result_glob || null,
    safety,
    generated_at: new Date().toISOString().slice(0, 19).replace('T', ' '),
    generated_by: 'manual',
  };
  return itemRegistry.update(
    storage, itemId,
    { script, status: 'script_generated', approval: null },
    `script_provided (manual, safety=${safety.risk})`,
    input.by || 'operator'
  );
}

/**
 * 게이트1: 스크립트 실행 승인/거부.
 * @param {object} decision - { decision:'approve'|'reject', by, note, force }
 *   force=true: 안전게이트 blocked 라도 승인 — **운영자 직접 입력(manual) 스크립트에 한함**.
 *   AI 생성 스크립트는 force 여도 승인 불가(재생성 필요).
 */
function reviewScript(storage, itemId, decision = {}) {
  const item = itemRegistry.get(storage, itemId);
  if (!item) throw new Error(`항목 없음: ${itemId}`);
  if (item.status !== 'script_generated') {
    throw new Error(`승인 가능한 상태가 아닙니다 (현재: ${item.status})`);
  }
  const approve = decision.decision === 'approve';

  let forced = false;
  if (approve && item.script?.safety?.risk === 'blocked') {
    const isManual = item.script?.generated_by === 'manual';
    if (decision.force && isManual) {
      forced = true;   // 운영자가 직접 넣은 스크립트 — 위험 내역 확인 후 강제 승인(감사 기록)
    } else {
      throw new Error(isManual
        ? '안전게이트 blocked. 직접 입력 스크립트를 실행하려면 위험 내역 확인 후 강제 승인(force)이 필요합니다.'
        : '안전게이트 blocked 스크립트는 승인할 수 없습니다. 재생성하세요.');
    }
  }

  const approval = {
    decision: approve ? 'approved' : 'rejected',
    by: decision.by || 'operator',
    at: new Date().toISOString().slice(0, 19).replace('T', ' '),
    note: decision.note || '',
    forced,
    safety_risk: item.script?.safety?.risk || null,
  };
  return itemRegistry.update(
    storage, itemId,
    { approval, status: approve ? 'approved' : 'rejected' },
    `script_${approval.decision}${forced ? '(force, blocked 무시)' : ''} by ${approval.by}`,
    approval.by
  );
}

/**
 * 수집: 승인된 항목에 raw 출력 적재.
 * (스크립트는 폐쇄망/안전 정책상 자동 원격 실행하지 않고, 운영자가 실행 결과를
 *  붙여넣거나 agent 토큰 push로 올린다 — §5-3 폐쇄망 방식과 일치.)
 * @param {object} input - { output, source }
 */
function ingestRaw(storage, itemId, input = {}) {
  const item = itemRegistry.get(storage, itemId);
  if (!item) throw new Error(`항목 없음: ${itemId}`);
  if (item.status !== 'approved' && item.status !== 'collected' && item.status !== 'judged' && item.status !== 'needs_review') {
    throw new Error(`raw 수집은 승인(approved) 이후에만 가능합니다 (현재: ${item.status})`);
  }
  const output = String(input.output || '');
  if (!output.trim()) throw new Error('raw 출력이 비어 있습니다');

  const raw = {
    output,
    source: input.source || 'manual',
    ingested_at: new Date().toISOString().slice(0, 19).replace('T', ' '),
  };
  return itemRegistry.update(
    storage, itemId,
    { raw, status: 'collected' },
    `raw_ingested (${raw.source}, ${output.length} chars)`,
    input.by || 'operator'
  );
}

/**
 * result_glob(결과 파일 산출형) 스크립트를 검증된 scriptDeployService 경로로 원격 실행·회수.
 *  - 스크립트 코드를 임시 파일로 저장 → runDirectScriptDeployment(원격 배포·실행·base64 다운로드).
 *  - result_glob 이 절대경로(C:\ad_audit\*_AD_DC.txt)면 dir/pattern 으로 분리해
 *    remoteResultDir 로 넘겨 결과 탐색 경로에 포함시킨다.
 *  - WinRM(Windows)·SSH(Linux) 분기는 scriptDeployService 가 담당.
 * @returns {{output:string, source:string}}
 */
async function _runViaScriptDeploy(server, script, opts = {}) {
  const fs = require('fs');
  const os = require('os');
  const path = require('path');
  const scriptDeploy = require('../services/scriptDeployService');

  const lang = String(script.lang || '').toLowerCase();
  const ext = /power|ps1|win/.test(lang) ? 'ps1' : (/bash|sh|unix|linux/.test(lang) ? 'sh' : 'ps1');
  const tmpName = `adv-adhoc-${String(script.item_id || 'x').replace(/[^\w.-]/g, '_')}-${process.pid}.${ext}`;
  const tmpPath = path.join(os.tmpdir(), tmpName);

  // 인코딩: PowerShell 5.1 은 BOM 없는 파일을 cp949(ANSI)로 읽어 한글 주석/문자열이 깨져
  //   원격 실행 시 파싱오류(예: ad_collect "…명" → 97행 char 57)가 난다.
  //   → .ps1 은 UTF-8 BOM 을 붙여 원격 PS 가 UTF-8 로 인식하게 한다.
  //   단, 이미 BOM 이 있으면 중복 금지(이중 BOM 은 3행부터 깨짐). .sh 는 shebang 보존 위해 BOM 미부착.
  let code = String(script.code || '');
  if (ext === 'ps1' && code.charCodeAt(0) !== 0xFEFF) code = '﻿' + code;
  fs.writeFileSync(tmpPath, code, 'utf8');

  // result_glob 파싱: 절대 디렉터리 + 패턴 분리
  const glob = String(script.result_glob || '').trim();
  let resultGlob = glob;
  let remoteResultDir = null;
  if (glob) {
    const norm = glob.replace(/\//g, '\\');
    const m = norm.match(/^(.*[\\])([^\\]+)$/);          // dir\pattern
    const hasDir = /^[A-Za-z]:\\/.test(norm) || norm.startsWith('\\\\') || glob.startsWith('/');
    if (m && hasDir) {
      remoteResultDir = m[1].replace(/\\+$/, '');
      resultGlob = m[2];
    } else {
      resultGlob = glob.replace(/^.*[\\/]/, '');           // 상대 → 패턴만
    }
  }

  try {
    const dep = await scriptDeploy.runDirectScriptDeployment(server, tmpPath, {
      resultGlob: resultGlob || undefined,
      remoteResultDir: remoteResultDir || undefined,
      timeout: opts.timeout,
      by: opts.by || 'agent',
      noOutputDirArg: true,   // 임의 스크립트 — 앱이 -OutputDir 강제 주입하지 않음(스크립트별 인자명 상이)
      onProgress: typeof opts.onProgress === 'function' ? opts.onProgress : undefined,
    });
    let output = '';
    if (dep && dep.local_result_path && fs.existsSync(dep.local_result_path)) {
      output = fs.readFileSync(dep.local_result_path, 'utf8');
    }
    if (!output || String(output).trim().length < 2) {
      // 결과 파일이 비면 stdout 라도 보존 (판정기에서 사유 판별)
      output = String((dep && dep.stdout) || '').trim();
    }
    const transport = (dep && dep.transport) || 'remote';
    const rr = (dep && dep.remote_result) || remoteResultDir || resultGlob || '';
    return { output, source: `${transport}:${dep && dep.hostname || server.hostname || server.name} (${rr})` };
  } finally {
    try { fs.unlinkSync(tmpPath); } catch (_) {}
  }
}

/**
 * 3-2(실행): 승인된 스크립트를 대상 서버에서 실행 → raw 자동 수집 → (옵션) 자동 판정.
 * 게이트 보강: 승인(approved) 상태 + 실행 직전 안전 재검사(blocked면 거부).
 * @param {object} server - servers 레코드
 * @param {object} opts - { autoJudge, backend, secums_verdict, useSudo, by }
 */
async function runOnTarget(storage, itemId, server, opts = {}) {
  const safetyGate = require('./safetyGate');
  const scriptRunner = require('./scriptRunner');

  const item = itemRegistry.get(storage, itemId);
  if (!item) throw new Error(`항목 없음: ${itemId}`);
  if (!['approved', 'collected', 'judged', 'needs_review'].includes(item.status)) {
    throw new Error(`대상 실행은 승인(approved) 이후에만 가능합니다 (현재: ${item.status})`);
  }
  if (!item.script?.code) throw new Error('생성된 스크립트가 없습니다');

  // 실행 직전 안전 재검사 (승인 후 변조/누락 방어)
  // 단, 운영자가 직접 넣은 수동 스크립트를 게이트1에서 강제승인(forced)한 경우는 허용
  //  — AI 생성 스크립트는 계속 차단(강제승인 대상 아님).
  const safety = safetyGate.inspect(item.script.code);
  const forcedManual = !!item.approval?.forced && item.script.generated_by === 'manual';
  if (safety.risk === 'blocked' && !forcedManual) {
    throw new Error('안전게이트 blocked — 실행 거부. 스크립트를 재생성하세요.');
  }

  const prog = typeof opts.onProgress === 'function' ? opts.onProgress : () => {};
  prog(5, `${server.hostname || server.name} 원격 실행 준비`);

  let res;
  if (item.script.result_glob) {
    // ── 결과 파일 산출형(ad_collect 등) → 검증된 scriptDeployService 경로 재사용 ──
    //    원격 배포 → 실행 → 결과 파일 base64 청크 다운로드 (107/fsi 에서 검증됨).
    //    WinRM(Windows)·SSH(Linux) 모두 runDirectScriptDeployment 가 분기 처리.
    res = await _runViaScriptDeploy(server, item.script, opts);
  } else {
    // ── stdout 캡처형(기존 agent 항목) → 기존 scriptRunner 경로 ──
    prog(40, '원격 스크립트 실행 중');
    const r = await scriptRunner.run(server, item.script, {
      useSudo: opts.useSudo != null ? opts.useSudo : !!server.use_sudo,
      timeout: opts.timeout,
    });
    res = { output: r.output, source: `ssh:${r.target} (exit=${r.exit_code})` };
  }

  prog(85, '결과 수집 완료 · 적재 중');
  let updated = ingestRaw(storage, itemId, {
    output: res.output,
    source: res.source,
    by: opts.by || 'agent',
  });

  if (opts.autoJudge) {
    prog(90, '판정 중');
    updated = await runJudge(storage, itemId, { backend: opts.backend, secums_verdict: opts.secums_verdict });
  }
  prog(100, `완료${updated.judgment ? ' · 판정 ' + updated.judgment.verdict : ''}`);
  return updated;
}

/**
 * 3-3: 자동 판정.
 * collected → judged (needs_review면 needs_review).
 */
async function runJudge(storage, itemId, opts = {}) {
  const item = itemRegistry.get(storage, itemId);
  if (!item) throw new Error(`항목 없음: ${itemId}`);
  if (!item.raw?.output) throw new Error('수집된 raw 출력이 없습니다');

  const raw = item.raw.output;

  // ① 등록된 구조 판정기(AD 등 다항목 결과)가 형식을 인식하면 확장 판정 — LLM 없이 결정적, 다항목 findings 보존
  const adhoc = require('../engine/adhocJudge');
  const structured = adhoc.detectAndEvaluate(raw);
  if (structured) {
    const vuln = structured.findings.filter(f => f.verdict === '취약').length;
    const judgment = {
      verdict: vuln > 0 ? '취약' : '양호',
      reason: structured.summary,
      findings: structured.findings,      // 다항목 상세 (AD 20+ 항목 등)
      evidence: '',
      recommend: '',
      confidence: 0.9,
      needs_review: false,
      review_reason: '',
      secums_verdict: opts.secums_verdict || null,
      model: `structured:${structured.evaluator}`,
      backend: 'mock',
      judged_at: new Date().toISOString().slice(0, 19).replace('T', ' '),
    };
    return itemRegistry.update(
      storage, itemId,
      { judgment, status: 'judged' },
      `judged(structured:${structured.evaluator}): ${judgment.verdict} — ${structured.findings.length}개 항목`,
      opts.by || 'agent'
    );
  }

  // ② 단일 항목 결과 → 기존 LLM/mock 판정
  const judgment = await autoJudge.judge(item, raw, opts);
  const status = judgment.needs_review ? 'needs_review' : 'judged';
  return itemRegistry.update(
    storage, itemId,
    { judgment, status },
    `judged: ${judgment.verdict} (conf=${(judgment.confidence ?? 0).toFixed(2)}, ${status})`,
    'agent'
  );
}

/**
 * 게이트2: 판정 사람 검토 확정.
 * @param {object} decision - { decision:'confirm'|'override', verdict?, by, note }
 */
function confirmJudgment(storage, itemId, decision = {}) {
  const item = itemRegistry.get(storage, itemId);
  if (!item) throw new Error(`항목 없음: ${itemId}`);
  if (item.status !== 'judged' && item.status !== 'needs_review') {
    throw new Error(`검토 확정 가능한 상태가 아닙니다 (현재: ${item.status})`);
  }
  const override = decision.decision === 'override' && decision.verdict;
  const finalVerdict = override ? decision.verdict : item.judgment?.verdict;

  const review = {
    decision: override ? 'override' : 'confirm',
    verdict: finalVerdict,
    by: decision.by || 'operator',
    at: new Date().toISOString().slice(0, 19).replace('T', ' '),
    note: decision.note || '',
  };
  return itemRegistry.update(
    storage, itemId,
    { review, status: 'confirmed' },
    `review_${review.decision}: ${finalVerdict} by ${review.by}`,
    review.by
  );
}

/**
 * 3소스 합의 계산 (VULN_ASSESSOR_TODO.md §4-4 하이브리드 / 3-way 합류).
 * 소스: ① 1차 판정(judgment, 보통 LSAP) ② 교차검증(cross, 보통 Claude) ③ SecuMS 자체판정.
 * 양호/취약 등 결정적 판정만 비교 모수에 포함.
 */
function computeAgreement(item) {
  const norm = (v) => {
    const s = String(v || '').trim().toUpperCase();
    if (s === '취약' || s === 'BAD' || s === 'FAIL' || s === 'VULN') return '취약';
    if (s === '양호' || s === 'OK' || s === 'PASS' || s === 'GOOD') return '양호';
    return null; // 점검불가/INFO/WAIT 등은 비교 제외
  };
  const sources = {
    primary: norm(item.judgment?.verdict),
    cross: norm(item.cross?.verdict),
    secums: norm(item.judgment?.secums_verdict || item.cross?.secums_verdict),
  };
  const decisive = Object.values(sources).filter(Boolean);
  let status;
  if (decisive.length < 2) status = 'no_data';
  else status = decisive.every(x => x === decisive[0]) ? 'agree' : 'mismatch';
  return { sources, decisive_count: decisive.length, status };
}

/**
 * 교차 검증 → 3소스 합의 기록 (§4-4 하이브리드).
 * 보안 기본: 사내 LSAP로 "독립 재검토"(샘플링 온도를 올려 같은 모델에서 다른 표본을 얻음).
 *   - 외부 Claude 2차는 opts.backend='claude' + AGENT_ALLOW_EXTERNAL=true 일 때만 허용된다.
 * collected/judged/needs_review 상태에서 호출 가능. 상태는 바꾸지 않고 cross/agreement만 추가.
 */
async function crossVerify(storage, itemId, opts = {}) {
  const item = itemRegistry.get(storage, itemId);
  if (!item) throw new Error(`항목 없음: ${itemId}`);
  if (!item.raw?.output) throw new Error('수집된 raw 출력이 없습니다');

  // 기본 = 사내(LSAP) 재검토. 외부 백엔드는 명시 요청 시에만.
  const backend = opts.backend || process.env.AGENT_CROSS_BACKEND || 'lsap';
  // 같은 모델 재검토면 독립 표본을 위해 온도를 올린다(외부 백엔드는 결정성 유지).
  const temperature = backend === 'claude'
    ? undefined
    : parseFloat(process.env.AGENT_CROSS_TEMPERATURE || '0.5');
  const cross = await autoJudge.judge(item, item.raw.output, {
    backend,
    temperature,
    secums_verdict: opts.secums_verdict || item.judgment?.secums_verdict,
  });

  const patched = { ...item, cross };
  const agreement = computeAgreement(patched);

  return itemRegistry.update(
    storage, itemId,
    { cross, agreement },
    `cross_verify(${backend}): ${cross.verdict} → 합의 ${agreement.status}`,
    'agent'
  );
}

/**
 * 현황 요약 — 대시보드/검토 큐용.
 */
function summary(storage) {
  const items = itemRegistry.load(storage);
  const byStatus = {};
  for (const it of items) byStatus[it.status] = (byStatus[it.status] || 0) + 1;
  return {
    total: items.length,
    byStatus,
    pending_approval: items.filter(i => i.status === 'script_generated').length, // 게이트1 대기
    needs_review: items.filter(i => i.status === 'needs_review').length,          // 게이트2 대기
    confirmed: items.filter(i => i.status === 'confirmed').length,
  };
}

module.exports = {
  generateScript,
  provideScript,
  reviewScript,
  ingestRaw,
  runOnTarget,
  runJudge,
  crossVerify,
  computeAgreement,
  confirmJudgment,
  summary,
};

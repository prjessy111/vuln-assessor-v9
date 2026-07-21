'use strict';
/**
 * ADV agent 파이프라인 셀프 테스트 (WinRM 전송만 stub, 나머지는 실제 코드).
 *  provideScript(수동 스크립트 직접 입력) → reviewScript(강제승인) → runOnTarget
 *   → scriptDeployService 위임 → (stub) 결과=실제 JESSY-PC_AD_DC.txt → 구조 판정.
 *
 * 검증 포인트:
 *  1) result_glob 자동감지(ad_collect → C:\ad_audit\*_AD_DC.txt)
 *  2) runOnTarget 이 runDirectScriptDeployment 에 넘기는 opts(resultGlob·remoteResultDir)
 *  3) 강제승인된 blocked 수동 스크립트가 실행 재검사를 통과
 *  4) 다운로드된 결과 파일이 adhocJudge 로 다항목 판정됨
 *
 * 실행: node scripts/mock-verify/adhoc-pipeline-selftest.js
 */
const path = require('path');
const fs = require('fs');
const Module = require('module');

const ROOT = path.resolve(__dirname, '..', '..');
const FIXTURE = path.join(ROOT, 'JESSY-PC_AD_DC.txt');

// ── scriptDeployService.runDirectScriptDeployment 을 stub (실제 WinRM 대신 fixture 반환) ──
let captured = null;
const realResolve = Module._resolveFilename;
const sdsPath = require.resolve(path.join(ROOT, 'src/services/scriptDeployService.js'));
const sds = require(sdsPath);
sds.runDirectScriptDeployment = async (server, localScriptPath, opts) => {
  captured = { server, localScriptPath, opts, scriptExists: fs.existsSync(localScriptPath) };
  return {
    status: 'success',
    hostname: server.hostname || server.name,
    transport: 'winrm',
    remote_result: 'C:\\ad_audit\\JESSY-PC_AD_DC.txt',
    local_result_path: FIXTURE,
    stdout: '(stub) executed',
  };
};

const pipeline = require(path.join(ROOT, 'src/agent/pipeline.js'));
const itemRegistry = require(path.join(ROOT, 'src/agent/itemRegistry.js'));

// ── 인메모리 storage ──
const mem = {};
const storage = {
  loadSync: (k) => (k in mem ? JSON.parse(JSON.stringify(mem[k])) : null),
  saveSync: (k, v) => { mem[k] = JSON.parse(JSON.stringify(v)); return v; },
};

// ── 대상 서버(110.91 DC 예시) ──
const server = {
  hostname: 'JESSY-PC', name: 'JESSY-PC',
  os_type: 'windows', ip_address: '192.168.110.91',
  ssh_user: 'Administrator', ssh_password: '!1qazxsw2@',
  winrm_port: 5985,
};

// ── ad_collect.ps1 축약(결과 파일 경로 감지용 핵심부) ──
const AD_SCRIPT = [
  'param([string]$OutDir = "C:\\ad_audit")',
  '$ErrorActionPreference = "SilentlyContinue"',
  'New-Item -ItemType Directory -Force -Path $OutDir | Out-Null',
  '$host2 = $env:COMPUTERNAME',
  '$out = Join-Path $OutDir ("{0}_AD_DC.txt" -f $host2)',
  '# ... AD 수집 ...',
  '$result | ConvertTo-Json -Depth 6 | Out-File -FilePath $out -Encoding UTF8',
  'Remove-Item -Path $env:TEMP\\adtmp -Recurse -Force  # (blocked 유발: Remove-Item)',
].join('\n');

(async () => {
  const fail = (m) => { console.error('  ✗ ' + m); process.exitCode = 1; };
  const ok = (m) => console.log('  ✓ ' + m);

  // 1) 항목 생성
  const created = itemRegistry.create(storage, {
    title: 'AD DC 보안 점검', description: 'AD 도메인 컨트롤러 계정/정책 수집·점검',
    os_target: 'windows', source: 'custom',
  });
  const id = created.item_id;

  // 2) 스크립트 직접 입력
  let item = pipeline.provideScript(storage, id, { code: AD_SCRIPT, by: 'tester' });
  console.log('\n[1] provideScript');
  console.log('    lang        =', item.script.lang);
  console.log('    result_glob =', item.script.result_glob);
  console.log('    safety.risk =', item.script.safety.risk);
  item.script.result_glob && /ad_audit/i.test(item.script.result_glob)
    ? ok('result_glob 자동감지 → ' + item.script.result_glob)
    : fail('result_glob 미검출 (기대: C:\\ad_audit\\*_AD_DC.txt)');

  // 3) 게이트1 — blocked 여도 수동 스크립트 강제승인
  console.log('\n[2] reviewScript(force approve)');
  try {
    item = pipeline.reviewScript(storage, id, { decision: 'approve', force: true, by: 'tester' });
    item.status === 'approved' ? ok('강제승인 성공 (status=approved, forced 기록)') : fail('상태=' + item.status);
  } catch (e) { fail('승인 실패: ' + e.message); }

  // 4) 실행 → 위임 → 판정
  console.log('\n[3] runOnTarget → scriptDeployService(위임, stub) → 판정');
  if (!fs.existsSync(FIXTURE)) return fail('fixture 없음: ' + FIXTURE);
  try {
    item = await pipeline.runOnTarget(storage, id, server, { autoJudge: true, by: 'tester' });
  } catch (e) { return fail('runOnTarget 예외: ' + e.message); }

  // 4a) 위임 opts 검증
  console.log('\n[4] 위임 opts (runDirectScriptDeployment 로 전달된 값)');
  console.log('    resultGlob      =', captured.opts.resultGlob);
  console.log('    remoteResultDir =', captured.opts.remoteResultDir);
  console.log('    임시 스크립트 존재 =', captured.scriptExists);
  captured.opts.resultGlob === '*_AD_DC.txt' ? ok('resultGlob=패턴만 분리됨') : fail('resultGlob=' + captured.opts.resultGlob);
  /ad_audit$/i.test(captured.opts.remoteResultDir || '') ? ok('remoteResultDir=C:\\ad_audit') : fail('remoteResultDir=' + captured.opts.remoteResultDir);
  captured.scriptExists ? ok('임시 .ps1 파일 생성·전달됨') : fail('임시 스크립트 파일 없음');

  // 4b) 판정 결과
  console.log('\n[5] 판정 결과');
  const j = item.judgment || {};
  console.log('    status   =', item.status);
  console.log('    verdict  =', j.verdict);
  console.log('    model    =', j.model);
  console.log('    findings =', (j.findings || []).length, '개');
  if ((j.findings || []).length) {
    const v = j.findings.filter(f => f.verdict === '취약').length;
    const g = j.findings.filter(f => f.verdict === '양호').length;
    const n = j.findings.filter(f => f.verdict !== '취약' && f.verdict !== '양호').length;
    console.log(`    (취약 ${v} · 양호 ${g} · 기타 ${n})`);
    ok(`구조 판정 성공 — ${j.findings.length}개 항목 (model=${j.model})`);
  } else {
    fail('findings 0 — 구조 판정 실패 (원문 앞 120자: ' + String(item.raw && item.raw.output).slice(0, 120) + ')');
  }

  console.log('\n' + (process.exitCode ? '❌ 일부 실패' : '✅ 전체 통과 — WinRM 전송만 실제 환경에서 확인하면 됨'));
})();

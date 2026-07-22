'use strict';
/**
 * BOM 수정 검증 — 앱의 배포 경로(scriptDeployService)를 그대로 재현해 110.91에 ad_collect 원격 실행.
 *   가설: BOM 없는 UTF-8 → 원격 PS5.1이 ANSI로 읽어 한글 깨짐 → line 97 파싱오류.
 *   검증: UTF-8 BOM 붙여 업로드하면 정상 실행 + 결과 회수되는가?
 * 실행: node scripts/mock-verify/ad-winrm-bom-test.js
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const ROOT = path.resolve(__dirname, '..', '..');
const scriptDeploy = require(path.join(ROOT, 'src/services/scriptDeployService.js'));
const { getTargetServersFromFile } = require(path.join(ROOT, 'src/services/scheduler.js'));

(async () => {
  const cred = (getTargetServersFromFile() || []).find(t => String(t.ip) === '192.168.110.91');
  if (!cred) { console.error('110.91 없음'); process.exit(1); }
  const server = {
    server_id: cred.server_id, hostname: cred.hostname, name: cred.hostname,
    ip_address: cred.ip, os_type: cred.os,
    ssh_user: cred.username, username: cred.username,
    ssh_password: cred.password, password: cred.password,
  };
  console.log(`[대상] ${server.hostname} (${server.ip_address}) 계정=${server.username}`);

  // repo 파일엔 BOM 이 있으므로 제거 → 사용자가 붙여넣은 내용(BOM 없음)과 동일 조건으로 만든다.
  let code = fs.readFileSync(path.join(ROOT, 'ad_collect.ps1'), 'utf8');
  if (code.charCodeAt(0) === 0xFEFF) code = code.slice(1);   // strip BOM → "붙여넣기" 재현

  for (const withBom of [false, true]) {
    const tmp = path.join(os.tmpdir(), `bomtest-${withBom ? 'bom' : 'nobom'}-${process.pid}.ps1`);
    fs.writeFileSync(tmp, (withBom ? '﻿' : '') + code, 'utf8');
    console.log(`\n===== ${withBom ? 'BOM 추가(수정본)' : 'BOM 없음(붙여넣기 재현=기존 버그)'} =====`);
    try {
      const dep = await scriptDeploy.runDirectScriptDeployment(server, tmp, {
        resultGlob: '*_AD_DC.txt', remoteResultDir: 'C:\\ad_audit',
        noOutputDirArg: true, timeout: 120000,
        onProgress: (p, m) => process.stdout.write(`  [${p}%] ${m}\r`),
      });
      const sz = dep.local_result_path && fs.existsSync(dep.local_result_path) ? fs.statSync(dep.local_result_path).size : 0;
      console.log(`\n  ✅ 성공 — 결과회수 ${sz} bytes (remote=${dep.remote_result})`);
    } catch (e) {
      console.log(`\n  ❌ 실패 — ${String(e.message).split('\n')[0].slice(0, 160)}`);
    } finally {
      try { fs.unlinkSync(tmp); } catch (_) {}
    }
  }
})();

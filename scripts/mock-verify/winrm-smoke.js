'use strict';
/**
 * WinRM 연결 스모크 테스트 — 실제 DC에 붙어 `hostname`만 실행해 연결/인증을 확인한다.
 * (전체 ad_collect 실행 전에 WinRM 도달성만 먼저 격리 검증)
 *
 * 사용:
 *   node scripts/mock-verify/winrm-smoke.js <IP> <USER> <PASS> [PORT]
 * 예:
 *   node scripts/mock-verify/winrm-smoke.js 192.168.100.91 "JESSYDOMAIN\\Administrator" "!1qazxsw2@" 5985
 *
 * 성공: 원격 hostname 출력.  실패: 사유(인증/방화벽/미활성) 출력.
 */
const winrm = require('nodejs-winrm');

const [ip, user, pass, portArg] = process.argv.slice(2);
const port = Number(portArg || 5985);

if (!ip || !user || !pass) {
  console.error('사용법: node scripts/mock-verify/winrm-smoke.js <IP> <USER> <PASS> [PORT]');
  process.exit(2);
}

(async () => {
  const t0 = Date.now();
  try {
    console.log(`[WinRM] ${user}@${ip}:${port} 접속 시도 …`);
    const out = await Promise.race([
      winrm.runPowershell('hostname; whoami', ip, user, pass, port),
      new Promise((_, rej) => setTimeout(() => rej(new Error('타임아웃 20s (방화벽 5985 차단 또는 WinRM 미활성?)')), 20000)),
    ]);
    const text = (Array.isArray(out) ? out.join('\n') : String(out == null ? '' : out)).trim();
    // nodejs-winrm 은 인증/실행 실패를 throw 대신 에러 문자열로 반환하기도 함 — 내용으로 판별
    if (!text || /Failed to process the request|status Code:|Access is denied|401|Unauthorized/i.test(text)) {
      throw new Error(`WinRM 요청 처리 실패 — 포트는 열렸으나(도달 ${Date.now() - t0}ms) 인증/설정 문제. 응답: ${text || '(빈 응답)'}`);
    }
    console.log(`[OK] 연결·인증·실행 성공 (${Date.now() - t0}ms)`);
    console.log('원격 출력:\n' + text);
  } catch (e) {
    console.error(`[FAIL] ${e.message}`);
    console.error('\n점검 항목:');
    console.error('  1) DC에서 Enable-PSRemoting -Force 실행했는가');
    console.error('  2) 방화벽 5985(WinRM-HTTP) 인바운드 허용됐는가');
    console.error('  3) 도메인 계정 Basic 인증 문제일 수 있음 — 아래 DC 설정 필요:');
    console.error('     Set-Item WSMan:\\localhost\\Service\\AllowUnencrypted $true');
    console.error('     Set-Item WSMan:\\localhost\\Service\\Auth\\Basic $true');
    console.error('  4) IP/계정/비번이 정확한가 (servers.csv 와 일치)');
    process.exit(1);
  }
})();

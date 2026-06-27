'use strict';
/**
 * 5단계 SSH 연결 테스트. 각 단계 결과를 배열로 반환하여 화면에 표시.
 */
const net = require('net');
const { withConnection, exec } = require('../engine/sshClient');
const { decrypt } = require('../util/crypto');

const PASS = (msg) => ({ status: 'ok', message: msg });
const FAIL = (msg) => ({ status: 'fail', message: msg });
const SKIP = (msg) => ({ status: 'skip', message: msg });

async function testTcpConnect(host, port, timeout = 5000) {
  return new Promise((resolve) => {
    const s = new net.Socket();
    let done = false;
    const finish = (r) => { if (done) return; done = true; s.destroy(); resolve(r); };
    s.setTimeout(timeout);
    s.once('connect', () => finish(PASS(`TCP ${host}:${port} 연결 성공`)));
    s.once('timeout', () => finish(FAIL(`TCP ${host}:${port} 타임아웃 (${timeout}ms)`)));
    s.once('error', (e) => finish(FAIL(`TCP 연결 실패: ${e.code || e.message}`)));
    s.connect(port, host);
  });
}

/**
 * 서버 객체(servers row)를 받아 5단계 테스트 수행.
 */
async function testConnection(server) {
  const steps = [];

  // ---- 1) TCP ----
  const tcp = await testTcpConnect(server.hostname, server.ssh_port || 22);
  steps.push({ name: '1. TCP 연결', ...tcp });
  if (tcp.status === 'fail') return steps;

  // ---- SSH 인증 정보 준비 ----
  let password = null;
  if (server.ssh_auth_type === 'password') {
    try {
      password = decrypt(server.ssh_password_enc);
    } catch (e) {
      steps.push({ name: '2. SSH 인증', ...FAIL('비밀번호 복호화 실패: ' + e.message) });
      return steps;
    }
  }

  const sshOpts = {
    host: server.hostname,
    port: server.ssh_port || 22,
    username: server.ssh_user,
    privateKeyPath: server.ssh_auth_type === 'key' ? server.ssh_key_path : null,
    password,
    readyTimeout: 10000,
  };

  try {
    await withConnection(sshOpts, async (conn) => {
      // ---- 2) SSH 인증 + echo ----
      const r = await exec(conn, 'echo VULN_CHECK_OK');
      if (r.code === 0 && r.stdout.includes('VULN_CHECK_OK')) {
        steps.push({ name: '2. SSH 인증', ...PASS(`사용자 ${server.ssh_user} 로그인 성공`) });
      } else {
        steps.push({ name: '2. SSH 인증', ...FAIL(`echo 응답 이상: ${r.stderr || r.stdout}`) });
        return;
      }

      // ---- 3) raw 파일 존재 ----
      const sudo = server.use_sudo ? 'sudo ' : '';
      const lsCmd = `${sudo}ls -la '${server.remote_raw_path}' 2>&1`;
      const r3 = await exec(conn, lsCmd);
      if (r3.code === 0) {
        steps.push({ name: '3. raw 파일 존재', ...PASS(r3.stdout.trim()) });
      } else {
        steps.push({ name: '3. raw 파일 존재', ...FAIL(`경로 확인 실패: ${r3.stdout || r3.stderr}`) });
        return;
      }

      // ---- 4) sudo 권한 ----
      if (server.use_sudo) {
        const r4 = await exec(conn, 'sudo -n true 2>&1');
        if (r4.code === 0) {
          steps.push({ name: '4. sudo 권한', ...PASS('NOPASSWD sudo 동작') });
        } else {
          steps.push({ name: '4. sudo 권한', ...FAIL(`sudo 실행 실패: ${r4.stdout || r4.stderr}`) });
          return;
        }
      } else {
        steps.push({ name: '4. sudo 권한', ...SKIP('use_sudo=false') });
      }

      // ---- 5) SQLite 무결성 ----
      const intCmd = `${sudo}sqlite3 '${server.remote_raw_path}' "PRAGMA quick_check;" 2>&1`;
      const r5 = await exec(conn, intCmd, { timeout: 30000 });
      if (r5.code === 0 && r5.stdout.trim().toLowerCase().startsWith('ok')) {
        steps.push({ name: '5. SQLite 무결성', ...PASS('quick_check=ok') });
      } else {
        steps.push({ name: '5. SQLite 무결성',
          ...FAIL(`PRAGMA quick_check 결과 이상: ${r5.stdout || r5.stderr}`) });
      }
    });
  } catch (e) {
    steps.push({ name: '2. SSH 인증', ...FAIL('연결 실패: ' + e.message) });
  }

  return steps;
}

module.exports = { testConnection };

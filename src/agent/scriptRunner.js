'use strict';
/**
 * 승인된 점검 스크립트 원격 실행 (VULN_ASSESSOR_TODO.md §3-2 "실행")
 *
 * 게이트1(사람 승인)을 통과한 스크립트만 대상 서버에서 실행한다.
 * 기존 SSH 인프라(src/engine/sshClient)와 자격증명 규약(connectionTester)을 재사용.
 *
 * 안전:
 *  - 실행 직전 safetyGate를 다시 통과해야 한다(호출 측에서 강제).
 *  - 스크립트는 base64로 전달 후 `base64 -d | sh`로 실행 → 따옴표/개행 깨짐 방지.
 *    (래퍼 명령은 우리가 통제하는 신뢰 코드. 스크립트 본문 자체는 이미 정적 검사됨.)
 *  - Windows(WinRM) 자동 실행은 아직 미지원 → 운영자가 결과 붙여넣기.
 */

const fs = require('fs');
const path = require('path');
const sshClient = require('../engine/sshClient');

// 자격증명 폴백 파일 (gitignore 대상, 재시작·시드에도 유지)
//   { "<server_id>": { "password": "...", "ssh_user": "root", "key_path": "...", "use_sudo": true } }
const CRED_FILE = path.resolve(__dirname, '../../data/agent-credentials.json');

function _loadCredFile() {
  try {
    if (!fs.existsSync(CRED_FILE)) return {};
    return JSON.parse(fs.readFileSync(CRED_FILE, 'utf8')) || {};
  } catch (_) { return {}; }
}

// servers.csv 자격증명 (단일 소스: hostname,ip,os,username,password,asset_no,server_id)
function _csvCreds() {
  try {
    const { getTargetServersFromFile } = require('../services/scheduler');
    return getTargetServersFromFile() || [];
  } catch (_) { return []; }
}

function credFor(server) {
  // 1) 폴백 파일(override) 우선
  const all = _loadCredFile();
  const f = all[String(server.server_id)] || all[server.hostname] || all[server.ip_address];
  if (f) return f;
  // 2) servers.csv 에서 server_id/ip/hostname 매칭
  const csv = _csvCreds().find(c =>
    String(c.server_id) === String(server.server_id) ||
    c.ip === server.ip_address || c.hostname === server.hostname);
  if (csv && csv.password) return { password: csv.password, ssh_user: csv.username };
  return null;
}

/**
 * 서버 비밀번호 해석.
 *  1) 서버 레코드의 암호화 비번(connectionTester 규약)  2) 폴백 파일(평문, gitignore)
 */
function resolvePassword(server) {
  if (server.ssh_auth_type === 'password' && server.ssh_password_enc) {
    const { decrypt } = require('../util/crypto');
    return decrypt(server.ssh_password_enc);
  }
  const c = credFor(server);
  return c && c.password ? c.password : null;
}

/**
 * 서버 레코드 → SSH 접속 옵션. 접속 호스트는 IP 우선(이름 미해석 방지).
 */
function buildSshOpts(server) {
  const c = credFor(server) || {};
  const password = resolvePassword(server);
  const privateKeyPath = (server.ssh_auth_type === 'key' ? server.ssh_key_path : null) || c.key_path || null;
  const opts = {
    host: server.ip_address || server.hostname,
    port: server.ssh_port || c.ssh_port || 22,
    username: server.ssh_user || c.ssh_user,
    privateKeyPath,
    password,
    readyTimeout: 15000,
  };
  if (!opts.privateKeyPath && !opts.password) {
    throw new Error(`서버 SSH 자격증명 없음 (server_id=${server.server_id}). data/agent-credentials.json 또는 서버 관리에 인증정보를 등록하세요.`);
  }
  return opts;
}

function isWindows(server) {
  return String(server.os_type || server.os || '').toLowerCase().includes('win');
}

/**
 * Linux 대상에서 sh 스크립트 실행.
 * @returns {{ stdout, stderr, code }}
 */
async function runLinux(server, code, { timeout = 60000, useSudo = false } = {}) {
  const b64 = Buffer.from(String(code), 'utf8').toString('base64');
  const runner = useSudo ? 'sudo sh' : 'sh';
  // printf로 base64 문자열을 안전하게 전달 → 디코드 → sh 실행
  const command = `printf '%s' '${b64}' | base64 -d | ${runner}`;
  const opts = buildSshOpts(server);
  return sshClient.withConnection(opts, (conn) => sshClient.exec(conn, command, { timeout }));
}

/**
 * Windows 대상에서 PowerShell 스크립트 실행 (WinRM, nodejs-winrm 재사용).
 * @returns {{ stdout, stderr, code }}
 */
async function runWindows(server, code, { timeout = 120000 } = {}) {
  const winrm = require('nodejs-winrm');
  const password = resolvePassword(server);
  const host = server.ip_address || server.hostname;  // IP 우선 (호스트명 미해석 방지)
  const username = server.ssh_user || server.winrm_user;
  const port = Number(server.winrm_port || server.ssh_port || 5985);
  if (!password) {
    throw new Error(`서버 WinRM 자격증명 없음 (server_id=${server.server_id}). 서버 관리에서 인증정보를 등록하세요.`);
  }
  // nodejs-winrm: runPowershell(script, host, username, password, port)
  const out = await Promise.race([
    winrm.runPowershell(code, host, username, password, port),
    new Promise((_, rej) => setTimeout(() => rej(new Error(`WinRM 실행 타임아웃 (${timeout}ms)`)), timeout)),
  ]);
  const stdout = Array.isArray(out) ? out.join('\n') : String(out == null ? '' : out);
  return { stdout, stderr: '', code: 0 };
}

/**
 * 대상 서버에서 점검 스크립트 실행 → raw 텍스트 반환.
 * Linux=SSH(sh), Windows=WinRM(PowerShell).
 * @param {object} server - servers 레코드
 * @param {object} script - { lang, code }
 * @param {object} opts - { timeout, useSudo }
 * @returns {Promise<{ output, exit_code, target }>}
 */
async function run(server, script, opts = {}) {
  if (!server) throw new Error('대상 서버가 지정되지 않았습니다');
  if (!script || !script.code) throw new Error('실행할 스크립트가 없습니다');

  const r = isWindows(server)
    ? await runWindows(server, script.code, opts)
    : await runLinux(server, script.code, opts);

  let output = r.stdout || '';
  if (r.stderr && r.stderr.trim()) {
    output += (output ? '\n' : '') + '[stderr]\n' + r.stderr.trim();
  }
  return { output, exit_code: r.code, target: server.hostname || server.ip_address };
}

module.exports = { run, runLinux, runWindows, buildSshOpts, resolvePassword, isWindows };

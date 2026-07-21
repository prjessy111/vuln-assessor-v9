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

const { execFile } = require('child_process');
const os = require('os');

/**
 * 내 PC의 native PowerShell(Invoke-Command)로 원격 실행 — Negotiate 인증.
 * 도메인 계정(DC)은 Kerberos/Negotiate, 워크그룹/로컬 계정은 NTLM(+TrustedHosts)로 붙는다.
 * nodejs-winrm(Basic 전용)의 한계를 우회 — Basic·평문 활성화 불필요, DC 보안 저하 없음.
 * @param {object} server
 * @param {object} action - { filePath } 로컬 .ps1 을 원격 실행 | { scriptBlock, argList } 원격 스크립트블록 실행
 * @returns {Promise<{ stdout, stderr, code }>}
 */
function _invokeRemotePwsh(server, action, { timeout = 180000 } = {}) {
  const host = server.ip_address || server.hostname;
  const username = server.ssh_user || server.winrm_user;
  const password = resolvePassword(server);
  const port = Number(server.winrm_port || server.ssh_port || 5985);
  if (!username || !password) {
    return Promise.reject(new Error(`서버 WinRM 자격증명 없음 (server_id=${server.server_id}). servers.csv 또는 서버 관리에 인증정보를 등록하세요.`));
  }

  // 원격에서 수행할 부분(액션)을 wrapper 안에 조립. 시크릿/경로는 환경변수로 전달(주입·따옴표 문제 방지).
  let actionLine;
  const env = {
    ...process.env,
    __WR_HOST: host,
    __WR_USER: username,
    __WR_PASS: password,
    __WR_PORT: String(port),
  };
  if (action.filePath) {
    env.__WR_FILE = action.filePath;
    actionLine = 'Invoke-Command -ComputerName $env:__WR_HOST -Port ([int]$env:__WR_PORT) -Credential $c -Authentication Negotiate -FilePath $env:__WR_FILE';
  } else {
    env.__WR_GLOB = action.argList || '';
    // 결과 파일 회수용 스크립트블록 (최신 매칭 파일 Get-Content -Raw)
    actionLine = "Invoke-Command -ComputerName $env:__WR_HOST -Port ([int]$env:__WR_PORT) -Credential $c -Authentication Negotiate -ScriptBlock { param($g) $ErrorActionPreference='SilentlyContinue'; $d=Split-Path $g -Parent; if(-not $d){$d='.'}; $p=Split-Path $g -Leaf; $f=Get-ChildItem -Path $d -Filter $p -Recurse -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1; if($f){ Get-Content -Raw -LiteralPath $f.FullName } } -ArgumentList $env:__WR_GLOB";
  }

  // Windows PowerShell 5.1 호환(삼항연산자 미사용). 워크그룹/로컬계정 대비 TrustedHosts 보강.
  const wrapper = [
    "$ErrorActionPreference='Stop';",
    '$s=ConvertTo-SecureString $env:__WR_PASS -AsPlainText -Force;',
    '$c=New-Object System.Management.Automation.PSCredential($env:__WR_USER,$s);',
    "try{ $th=(Get-Item WSMan:\\localhost\\Client\\TrustedHosts -ErrorAction Stop).Value }catch{ $th='' };",
    'if($th -notmatch [regex]::Escape($env:__WR_HOST)){ $nv=$env:__WR_HOST; if($th){ $nv=$th+","+$env:__WR_HOST }; try{ Set-Item WSMan:\\localhost\\Client\\TrustedHosts -Value $nv -Force -ErrorAction SilentlyContinue }catch{} }',
    ';',
    actionLine,
  ].join(' ');

  return new Promise((resolve, reject) => {
    execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', wrapper],
      { env, timeout, maxBuffer: 64 * 1024 * 1024, windowsHide: true },
      (err, stdout, stderr) => {
        if (err && err.killed) return reject(new Error(`원격 실행 타임아웃 (${timeout}ms)`));
        // Invoke-Command 인증/접속 실패는 stderr 에 담김
        if (err && !stdout) return reject(new Error(`원격 실행 실패: ${(stderr || err.message || '').trim().slice(0, 500)}`));
        resolve({ stdout: String(stdout || ''), stderr: String(stderr || ''), code: err ? (err.code || 1) : 0 });
      });
  });
}

/**
 * Windows 대상에서 PowerShell 스크립트 실행 — native Invoke-Command(Negotiate).
 * 스크립트 본문을 임시 .ps1 로 저장 후 -FilePath 로 원격 실행(따옴표/개행 안전).
 * @returns {{ stdout, stderr, code }}
 */
async function runWindows(server, code, { timeout = 180000 } = {}) {
  const tmp = path.join(os.tmpdir(), `vuln-adhoc-${Date.now()}-${Math.random().toString(36).slice(2)}.ps1`);
  fs.writeFileSync(tmp, String(code), 'utf8');
  try {
    return await _invokeRemotePwsh(server, { filePath: tmp }, { timeout });
  } finally {
    try { fs.unlinkSync(tmp); } catch (_) {}
  }
}

/**
 * 원격에서 결과 파일(글롭)의 최신 파일 내용을 읽어온다.
 * 스크립트가 결과를 stdout이 아니라 "파일"에 쓰는 경우(예: ad_collect.ps1 → C:\ad_audit\*_AD_DC.txt) 회수용.
 * @param {string} glob - 전체 경로+와일드카드. 예) 'C:\\ad_audit\\*_AD_DC.txt' 또는 '/var/log/scan/*.json'
 * @returns {Promise<string>} 파일 내용(없으면 '')
 */
async function readRemoteResult(server, glob, opts = {}) {
  const g = String(glob || '').trim();
  if (!g) return '';
  const timeout = opts.timeout || 60000;

  if (isWindows(server)) {
    // 디렉터리/패턴을 JS에서 분리(원격 Split-Path 가 와일드카드 경로에서 오작동) + 슬래시 정규화
    const gNorm = g.replace(/\\/g, '/');
    const sl = gNorm.lastIndexOf('/');
    const dir = (sl >= 0 ? gNorm.slice(0, sl) : '.').replace(/'/g, "''");
    const pat = (sl >= 0 ? gNorm.slice(sl + 1) : gNorm).replace(/'/g, "''");
    // ★ 대용량 회수: -Raw 단일 문자열은 WinRM 재사용 연결에서 유실됨(검증). 파일을 base64 로 읽어
    //   작은 청크(줄 단위)로 전송 → 노드에서 합쳐 디코드. (기존 scriptDeployService 와 동일 방식)
    const chunk = Number(process.env.AGENT_WINRM_CHUNK || 4000);
    const ps =
      `$f=Get-ChildItem -Path '${dir}' -Filter '${pat}' -Recurse -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1; ` +
      `if($f){ $b=[Convert]::ToBase64String([System.IO.File]::ReadAllBytes($f.FullName)); for($i=0;$i -lt $b.Length;$i+=${chunk}){ $b.Substring($i,[Math]::Min(${chunk},$b.Length-$i)) } }`;
    const r = await runWindows(server, ps, { timeout });
    const b64 = String(r.stdout || '').replace(/[\r\n\s]+/g, '');
    if (!b64) return '';
    let text = Buffer.from(b64, 'base64').toString('utf8');
    return text.replace(/^﻿/, '').replace(/^﻿/, '').trim();  // BOM 제거
  }

  // Linux: 최신 매칭 파일 cat
  const shGlob = g.replace(/'/g, `'\\''`);
  const cmd = `f=$(ls -t ${shGlob} 2>/dev/null | head -1); if [ -n "$f" ] && [ -f "$f" ]; then cat "$f"; fi`;
  const sshOpts = buildSshOpts(server);
  const r = await sshClient.withConnection(sshOpts, (conn) => sshClient.exec(conn, cmd, { timeout }));
  return (r.stdout || '').trim();
}

/**
 * 대상 서버에서 점검 스크립트 실행 → raw 텍스트 반환.
 * Linux=SSH(sh), Windows=WinRM(PowerShell).
 * 스크립트가 결과를 파일에 쓰면(script.result_glob 또는 opts.resultGlob 지정) 그 파일을 회수해 raw 로 사용.
 * (지정 없으면 stdout 을 raw 로 사용 — 기존 동작)
 * @param {object} server - servers 레코드
 * @param {object} script - { lang, code, result_glob? }
 * @param {object} opts - { timeout, useSudo, resultGlob? }
 * @returns {Promise<{ output, exit_code, target, collected_from }>}
 */
async function run(server, script, opts = {}) {
  if (!server) throw new Error('대상 서버가 지정되지 않았습니다');
  if (!script || !script.code) throw new Error('실행할 스크립트가 없습니다');

  const resultGlob = script.result_glob || opts.resultGlob || null;
  const win = isWindows(server);
  const target = server.hostname || server.ip_address;

  // Windows + 결과파일 지정: "실행 + base64 청크 회수"를 한 연결(같은 세션)에서 수행.
  //  - 무거운 실행 직후 별도 2번째 WinRM 연결이 불안정 → 연결 1개로 통합
  //  - 대용량은 base64 청크(줄 단위)로 전송 → 유실 방지 (검증됨)
  if (win && resultGlob) {
    const marker = 'VULNRESULT' + Date.now();
    const gNorm = String(resultGlob).replace(/\\/g, '/');
    const sl = gNorm.lastIndexOf('/');
    const dir = (sl >= 0 ? gNorm.slice(0, sl) : '.').replace(/'/g, "''");
    const pat = (sl >= 0 ? gNorm.slice(sl + 1) : gNorm).replace(/'/g, "''");
    const chunk = Number(process.env.AGENT_WINRM_CHUNK || 4000);
    const combined = String(script.code) + '\n' +
      `Write-Output '${marker}'; ` +
      `$__f=Get-ChildItem -Path '${dir}' -Filter '${pat}' -Recurse -File -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1; ` +
      `if($__f){ $__b=[Convert]::ToBase64String([System.IO.File]::ReadAllBytes($__f.FullName)); for($__i=0;$__i -lt $__b.Length;$__i+=${chunk}){ $__b.Substring($__i,[Math]::Min(${chunk},$__b.Length-$__i)) } }`;
    const r = await runWindows(server, combined, opts);
    const stdout = r.stdout || '';
    const idx = stdout.indexOf(marker);
    let output, collectedFrom;
    if (idx >= 0) {
      const b64 = stdout.slice(idx + marker.length).replace(/[\r\n\s]+/g, '');
      if (b64) {
        output = Buffer.from(b64, 'base64').toString('utf8').replace(/^﻿/, '').trim();
        collectedFrom = `file:${resultGlob} (same-session, base64)`;
      } else {
        output = stdout.slice(0, idx).trim();
        collectedFrom = 'stdout (결과파일 없음/비어있음)';
      }
    } else {
      output = stdout.trim();
      collectedFrom = 'stdout (마커 없음)';
    }
    if (r.stderr && r.stderr.trim()) output += '\n[stderr]\n' + r.stderr.trim();
    return { output, exit_code: r.code, target, collected_from: collectedFrom, stdout_log: stdout };
  }

  // 그 외(Linux, 또는 결과파일 미지정): 실행 후 필요 시 별도 세션 회수.
  const r = win ? await runWindows(server, script.code, opts) : await runLinux(server, script.code, opts);
  const stdout = r.stdout || '';
  const stderrText = r.stderr && r.stderr.trim() ? '\n[stderr]\n' + r.stderr.trim() : '';
  let collectedFrom = 'stdout';
  let output = stdout + stderrText;
  if (resultGlob) {
    try {
      const fileContent = await readRemoteResult(server, resultGlob, opts);
      if (fileContent) { output = fileContent; collectedFrom = `file:${resultGlob}`; }
      else { collectedFrom = 'stdout (결과파일 없음/비어있음)'; }
    } catch (e) {
      output = (output ? output + '\n' : '') + `[result-file 회수 실패: ${e.message}]`;
    }
  }
  return { output, exit_code: r.code, target, collected_from: collectedFrom, stdout_log: stdout };
}

module.exports = { run, runLinux, runWindows, readRemoteResult, buildSshOpts, resolvePassword, isWindows };

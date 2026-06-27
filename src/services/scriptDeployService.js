'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { pipeline } = require('stream/promises');
const { execFile } = require('child_process');
const SMB2 = require('@marsaud/smb2');
const winrm = require('nodejs-winrm');
const { withConnection, exec, downloadFile } = require('../engine/sshClient');

const UPLOAD_TMP_DIR = process.env.UPLOAD_TMP_DIR || path.resolve(__dirname, '../../data/uploads');
const PACKAGE_EXTRACT_DIR = process.env.SCRIPT_PACKAGE_EXTRACT_DIR || path.resolve(__dirname, '../../data/script-deploy/extracted');
const DEFAULT_WINDOWS_REMOTE_BASE_DIR = process.env.SCRIPT_DEPLOY_WINDOWS_BASE_DIR || 'C:\\Windows\\Temp';
const DEFAULT_UNIX_REMOTE_BASE_DIR = process.env.SCRIPT_DEPLOY_UNIX_BASE_DIR || '/tmp';
const KEEP_REMOTE_WORKSPACE = /^(1|true|yes)$/i.test(String(process.env.SCRIPT_DEPLOY_KEEP_REMOTE || ''));
const SCRIPT_EXTENSIONS = ['.sh', '.bash', '.ps1', '.bat', '.cmd', '.py', '.pl'];
const WINDOWS_SCRIPT_EXTENSIONS = ['.bat', '.cmd', '.ps1', '.py'];
const UNIX_SCRIPT_EXTENSIONS = ['.sh', '.bash', '.py', '.pl'];

function safeName(value, fallback = 'target') {
  return String(value || fallback)
    .trim()
    .replace(/\.[^.]+$/, '')
    .replace(/[^a-zA-Z0-9._-]/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '') || fallback;
}

function todayParts() {
  const now = new Date();
  const yyyy = String(now.getFullYear());
  const mm = String(now.getMonth() + 1).padStart(2, '0');
  const dd = String(now.getDate()).padStart(2, '0');
  return { folder: `${yyyy}-${mm}-${dd}`, compact: `${yyyy}${mm}${dd}` };
}

function quoteSh(value) {
  return `'${String(value ?? '').replace(/'/g, `'\\''`)}'`;
}

function quotePs(value) {
  return `'${String(value ?? '').replace(/'/g, "''")}'`;
}

function remotePathJoin(dir, file) {
  return `${String(dir).replace(/[\\/]+$/, '')}/${file}`;
}

function normalizeSftpPath(remotePath) {
  return String(remotePath || '').replace(/\\/g, '/');
}

function remoteDirname(remotePath) {
  const normalized = normalizeSftpPath(remotePath);
  const idx = normalized.lastIndexOf('/');
  return idx > 0 ? normalized.slice(0, idx) : '';
}

function assertInside(parent, target) {
  const base = path.resolve(parent);
  const full = path.resolve(target);
  const rel = path.relative(base, full);
  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    throw new Error(`unsafe package path: ${target}`);
  }
}

function uploadFile(conn, localPath, remotePath) {
  return new Promise((resolve, reject) => {
    conn.sftp((err, sftp) => {
      if (err) return reject(err);
      sftp.fastPut(localPath, normalizeSftpPath(remotePath), (putErr) => {
        if (putErr) return reject(putErr);
        resolve();
      });
    });
  });
}

function smbCall(client, method, ...args) {
  return new Promise((resolve, reject) => {
    client[method](...args, (err, result) => {
      if (err) return reject(err);
      resolve(result);
    });
  });
}

function winPathJoin(...parts) {
  return parts
    .filter(part => part !== undefined && part !== null && String(part) !== '')
    .map((part, idx) => {
      const value = String(part).replace(/[\\/]+/g, '\\');
      return idx === 0 ? value.replace(/[\\]+$/g, '') : value.replace(/^[\\]+|[\\]+$/g, '');
    })
    .join('\\');
}

function normalizeWinAbsPath(value, fallback = DEFAULT_WINDOWS_REMOTE_BASE_DIR) {
  const selected = String(value || fallback || 'C:\\Windows\\Temp')
    .trim()
    .replace(/^["']|["']$/g, '')
    .replace(/[\\/]+/g, '\\');
  const withDrive = /^[a-zA-Z]:/.test(selected)
    ? selected
    : `C:\\${selected.replace(/^[\\]+/, '')}`;
  const withoutTrailing = withDrive.replace(/[\\]+$/g, '');
  return /^[a-zA-Z]:$/.test(withoutTrailing) ? `${withoutTrailing}\\` : withoutTrailing;
}

function windowsAdminShareForAbs(host, absPath) {
  const normalized = normalizeWinAbsPath(absPath);
  const match = normalized.match(/^([a-zA-Z]):\\?(.*)$/);
  if (!match) {
    throw new Error(`Windows absolute path is required: ${absPath}`);
  }
  return {
    share: `\\\\${host}\\${match[1].toUpperCase()}$`,
    relative: String(match[2] || '').replace(/[\\/]+/g, '\\'),
  };
}

function resolveWindowsRemoteBaseDir(server, opts = {}) {
  return normalizeWinAbsPath(
    opts.remoteWorkDir ||
    opts.remote_work_dir ||
    server.script_deploy_dir ||
    server.remote_script_dir ||
    server.remote_work_dir ||
    DEFAULT_WINDOWS_REMOTE_BASE_DIR
  );
}

function resolveUnixRemoteBaseDir(server, opts = {}) {
  return String(
    opts.remoteWorkDir ||
    opts.remote_work_dir ||
    server.script_deploy_dir ||
    server.remote_script_dir ||
    server.remote_work_dir ||
    DEFAULT_UNIX_REMOTE_BASE_DIR
  ).trim().replace(/\/+$/g, '') || '/tmp';
}

function parseWindowsPathList(value) {
  return String(value || '')
    .split(/[;\r\n]+/)
    .map(x => x.trim())
    .filter(Boolean)
    .map(x => normalizeWinAbsPath(x));
}

function uniqueList(values) {
  return Array.from(new Set(values.filter(Boolean)));
}

function addPowerShellOutputDirArg(args, outputDirAbs) {
  const argText = String(args || '').trim();
  if (!outputDirAbs || /(^|\s)-(?:OutputDir|OutputPath)\b/i.test(argText)) return argText;
  return `${argText} -OutputDir ${quotePs(outputDirAbs)}`.trim();
}

function winDirname(remotePath) {
  const normalized = String(remotePath || '').replace(/[\\/]+/g, '\\');
  const idx = normalized.lastIndexOf('\\');
  return idx > 0 ? normalized.slice(0, idx) : '';
}

function winAbsFromCShare(relativePath) {
  return `C:\\${String(relativePath || '').replace(/^[\\/]+/, '').replace(/[\\/]+/g, '\\')}`;
}

function winShareRelativeFromAbs(absPath) {
  return String(absPath || '')
    .replace(/^["']|["']$/g, '')
    .replace(/^[a-zA-Z]:[\\/]+/, '')
    .replace(/[\\/]+/g, '\\')
    .trim();
}

async function ensureSmbDir(client, remoteDir) {
  const parts = String(remoteDir || '').replace(/[\\/]+/g, '\\').split('\\').filter(Boolean);
  let current = '';
  for (const part of parts) {
    current = current ? `${current}\\${part}` : part;
    await smbCall(client, 'mkdir', current).catch(() => {});
  }
}

function localPayloadFilePath(payload, file) {
  if (file.sourcePath) return file.sourcePath;
  return path.join(payload.rootDir, ...file.relativePath.split('/'));
}

async function uploadWindowsPayloadFiles(client, payload, remoteDir) {
  await ensureSmbDir(client, remoteDir);
  for (const file of payload.files) {
    const relative = String(file.relativePath || '').replace(/\//g, '\\');
    const remoteFile = winPathJoin(remoteDir, relative);
    const remoteFileDir = winDirname(remoteFile);
    if (remoteFileDir) await ensureSmbDir(client, remoteFileDir);
    await smbCall(client, 'writeFile', remoteFile, fs.readFileSync(localPayloadFilePath(payload, file)));
  }
}

async function ensureRemoteDir(conn, target, remoteDir) {
  if (!remoteDir) return;
  if (target.isWindows) {
    const r = await exec(conn, `powershell -NoProfile -Command "New-Item -ItemType Directory -Force -Path ${quotePs(remoteDir)} | Out-Null"`, { timeout: 30000 });
    if (r.code !== 0) throw new Error(`Windows 원격 폴더 생성 실패: ${r.stderr || r.stdout}`);
  } else {
    const r = await exec(conn, `mkdir -p ${quoteSh(remoteDir)}`, { timeout: 30000 });
    if (r.code !== 0) throw new Error(`원격 폴더 생성 실패: ${r.stderr || r.stdout}`);
  }
}

async function uploadPackageFiles(conn, target, packageRoot, files, remoteDir) {
  const madeDirs = new Set();
  for (const file of files) {
    const remoteFile = remotePathJoin(remoteDir, file.relativePath);
    const dir = remoteDirname(remoteFile);
    if (dir && !madeDirs.has(dir)) {
      await ensureRemoteDir(conn, target, dir);
      madeDirs.add(dir);
    }
    const localPath = path.join(packageRoot, ...file.relativePath.split('/'));
    await uploadFile(conn, localPath, remoteFile);
  }
}

function resolveTarget(server) {
  let decrypted = null;
  if (!server.password && !server.ssh_password && server.ssh_password_enc) {
    try {
      const { decrypt } = require('../util/crypto');
      decrypted = decrypt(server.ssh_password_enc);
    } catch (_) {}
  }

  const os = String(server.os || server.os_type || '').toLowerCase();
  const host = server.ip || server.ip_address || server.host || server.hostname;
  const username = server.username || server.ssh_user || server.user;
  const password = server.password || server.ssh_password || decrypted;
  const port = Number(server.ssh_port || server.port || 22);
  const isWindows = os.includes('win');
  const winrmPort = Number(server.winrm_port || server.winrmPort || server.remote_port || (server.port && isWindows ? server.port : 5985));

  if (!host) throw new Error('원격 실행 대상 IP/host가 없습니다.');
  if (!username) throw new Error('원격 실행 사용자(username/ssh_user)가 없습니다.');
  if (isWindows && !password) throw new Error('Windows WinRM 인증 정보(password)가 없습니다.');
  if (!isWindows && !password && !server.ssh_key_path) throw new Error('원격 실행 인증 정보(password 또는 ssh_key_path)가 없습니다.');

  return {
    host,
    port,
    winrmPort,
    username,
    password,
    domain: server.domain || server.winrm_domain || 'WORKGROUP',
    privateKeyPath: server.ssh_key_path || null,
    os,
    isWindows,
  };
}

function localResultPath(hostname) {
  const { folder, compact } = todayParts();
  const dir = path.join(UPLOAD_TMP_DIR, folder);
  fs.mkdirSync(dir, { recursive: true });
  return path.join(dir, `${safeName(hostname)}_script_${compact}.xml`);
}

function safeRelativePackagePath(entryPath) {
  const raw = String(entryPath || '').replace(/\\/g, '/');
  if (!raw || raw.startsWith('/') || /^[a-zA-Z]:/.test(raw)) return null;

  const normalized = path.posix.normalize(raw);
  if (!normalized || normalized === '.' || normalized === '..' || normalized.startsWith('../') || path.posix.isAbsolute(normalized)) {
    return null;
  }
  return normalized;
}

async function extractZipPackage(zipPath, jobId) {
  let unzipper;
  try {
    unzipper = require('unzipper');
  } catch (e) {
    throw new Error(`ZIP 패키지 처리를 위해 unzipper 모듈이 필요합니다: ${e.message}`);
  }

  fs.mkdirSync(PACKAGE_EXTRACT_DIR, { recursive: true });
  const outDir = path.join(PACKAGE_EXTRACT_DIR, safeName(jobId || `pkg-${Date.now()}`, 'pkg'));
  assertInside(PACKAGE_EXTRACT_DIR, outDir);
  if (fs.existsSync(outDir)) fs.rmSync(outDir, { recursive: true, force: true });
  fs.mkdirSync(outDir, { recursive: true });

  const directory = await unzipper.Open.file(zipPath);
  const files = [];

  for (const entry of directory.files) {
    const relativePath = safeRelativePackagePath(entry.path);
    if (!relativePath) continue;

    const outPath = path.join(outDir, ...relativePath.split('/'));
    assertInside(outDir, outPath);

    if (entry.type === 'Directory') {
      fs.mkdirSync(outPath, { recursive: true });
      continue;
    }

    fs.mkdirSync(path.dirname(outPath), { recursive: true });
    await pipeline(entry.stream(), fs.createWriteStream(outPath));
    files.push({ relativePath });
  }

  if (!files.length) {
    throw new Error('ZIP 패키지 안에 배포할 파일이 없습니다.');
  }

  return { rootDir: outDir, files };
}

function choosePackageScript(files, target, requestedScript) {
  const requested = String(requestedScript || '').trim().replace(/\\/g, '/').toLowerCase();
  const scriptFiles = files.filter(file => SCRIPT_EXTENSIONS.includes(path.extname(file.relativePath).toLowerCase()));

  if (requested) {
    const found = scriptFiles.find(file => {
      const rel = file.relativePath.toLowerCase();
      return rel === requested || path.posix.basename(rel) === requested;
    });
    if (found) return found;
    throw new Error(`ZIP 안에서 실행 스크립트를 찾지 못했습니다: ${requestedScript}`);
  }

  const extOrder = target.isWindows ? WINDOWS_SCRIPT_EXTENSIONS : UNIX_SCRIPT_EXTENSIONS;
  const preferredNames = target.isWindows
    ? ['fsi_win_ai', 'fsi_win', 'windows', 'win']
    : ['fsi_unix_ai', 'fsi_unix', 'unix', 'linux'];

  const sorted = scriptFiles
    .filter(file => extOrder.includes(path.extname(file.relativePath).toLowerCase()))
    .sort((a, b) => {
      const aBase = path.posix.basename(a.relativePath).toLowerCase();
      const bBase = path.posix.basename(b.relativePath).toLowerCase();
      const aScore = preferredNames.findIndex(name => aBase.includes(name));
      const bScore = preferredNames.findIndex(name => bBase.includes(name));
      const normalizedA = aScore === -1 ? 999 : aScore;
      const normalizedB = bScore === -1 ? 999 : bScore;
      if (normalizedA !== normalizedB) return normalizedA - normalizedB;
      return a.relativePath.split('/').length - b.relativePath.split('/').length;
    });

  if (sorted[0]) return sorted[0];
  throw new Error('ZIP 패키지 안에 실행 가능한 스크립트(.bat/.cmd/.ps1/.sh/.py 등)가 없습니다.');
}

async function prepareDeployPayload(localScriptPath, target, opts = {}) {
  const originalName = opts.originalName || path.basename(localScriptPath);
  const originalExt = path.extname(originalName || localScriptPath).toLowerCase();
  const jobId = opts.jobId || `direct-${Date.now()}`;

  if (originalExt === '.zip') {
    const pkg = await extractZipPackage(localScriptPath, jobId);
    const script = choosePackageScript(pkg.files, target, opts.packageScript);
    return {
      kind: 'package',
      rootDir: pkg.rootDir,
      files: pkg.files,
      scriptRelativePath: script.relativePath,
      scriptName: path.posix.basename(script.relativePath),
      ext: path.extname(script.relativePath).toLowerCase(),
      cleanupDir: pkg.rootDir,
    };
  }

  const ext = path.extname(originalName || localScriptPath).toLowerCase();
  const scriptName = safeName(originalName || path.basename(localScriptPath), 'deploy_script') + ext;
  return {
    kind: 'single',
    rootDir: path.dirname(localScriptPath),
    files: [{ relativePath: scriptName, sourcePath: localScriptPath }],
    scriptRelativePath: scriptName,
    scriptName,
    ext,
    cleanupDir: null,
  };
}

function cleanupDeployPayload(payload) {
  if (!payload?.cleanupDir) return;
  assertInside(PACKAGE_EXTRACT_DIR, payload.cleanupDir);
  fs.rmSync(payload.cleanupDir, { recursive: true, force: true });
}

function unixRunCommand(remoteDir, remoteScript, ext, args) {
  const quotedScript = quoteSh(remoteScript);
  const quotedDir = quoteSh(remoteDir);
  const argText = String(args || '').trim();
  if (ext === '.sh' || ext === '.bash') {
    return `cd ${quotedDir} && sh ${quotedScript} ${argText}`;
  }
  if (ext === '.py') {
    return `cd ${quotedDir} && (python3 ${quotedScript} ${argText} || python ${quotedScript} ${argText})`;
  }
  if (ext === '.pl') {
    return `cd ${quotedDir} && perl ${quotedScript} ${argText}`;
  }
  return `cd ${quotedDir} && ${quotedScript} ${argText}`;
}

function windowsRunCommand(remoteDir, remoteScript, ext, args) {
  const dir = quotePs(remoteDir);
  const script = quotePs(remoteScript);
  const argText = String(args || '').trim();
  if (ext === '.ps1') {
    return `powershell -NoProfile -ExecutionPolicy Bypass -Command "Set-Location ${dir}; & ${script} ${argText}"`;
  }
  if (ext === '.bat' || ext === '.cmd') {
    return `cmd /c "cd /d \\"${remoteDir}\\" && \\"${remoteScript}\\" ${argText}"`;
  }
  if (ext === '.py') {
    return `powershell -NoProfile -Command "Set-Location ${dir}; python ${script} ${argText}"`;
  }
  return `powershell -NoProfile -Command "Set-Location ${dir}; & ${script} ${argText}"`;
}

async function findUnixResult(conn, remoteDir, resultGlob) {
  const cmd = `find ${quoteSh(remoteDir)} -type f -name ${quoteSh(resultGlob || '*.xml')} -exec ls -t {} + 2>/dev/null | head -1`;
  const r = await exec(conn, cmd, { timeout: 30000 });
  return r.code === 0 ? r.stdout.trim().split(/\r?\n/)[0] : '';
}

async function findWindowsResult(conn, remoteDir, resultGlob) {
  const cmd = `powershell -NoProfile -Command "$f = Get-ChildItem -Path ${quotePs(remoteDir)} -Recurse -File -Filter ${quotePs(resultGlob || '*.xml')} -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1; if ($f) { $f.FullName }"`;
  const r = await exec(conn, cmd, { timeout: 30000 });
  return r.code === 0 ? r.stdout.trim().split(/\r?\n/)[0] : '';
}

function normalizeWinRmOutput(output, label) {
  if (output instanceof Error) {
    throw new Error(`${label}: ${output.message}`);
  }
  return String(output || '').trim();
}

function encodePowerShellCommand(script) {
  return Buffer.from(String(script || ''), 'utf16le').toString('base64');
}

function runLocalPowerShell(args, opts = {}) {
  const exe = process.env.POWERSHELL_EXE || 'powershell.exe';
  return new Promise((resolve, reject) => {
    execFile(exe, args, {
      timeout: Number(opts.timeout || process.env.SCRIPT_DEPLOY_WINRM_TIMEOUT || 900000),
      windowsHide: true,
      maxBuffer: Number(opts.maxBuffer || 20 * 1024 * 1024),
    }, (error, stdout, stderr) => {
      if (error) {
        error.stdout = stdout;
        error.stderr = stderr;
        return reject(error);
      }
      resolve({ stdout, stderr });
    });
  });
}

async function runLocalPowerShellScript(script, opts = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vuln-winrm-'));
  const scriptPath = path.join(dir, 'invoke.ps1');
  fs.writeFileSync(scriptPath, `\uFEFF${script}`, 'utf8');
  try {
    return await runLocalPowerShell([
      '-NoProfile',
      '-ExecutionPolicy',
      'Bypass',
      '-File',
      scriptPath,
    ], opts);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function compactPowerShellError(error) {
  const rawText = [error?.stderr, error?.stdout, error?.message]
    .filter(Boolean)
    .join(' ');
  const normalized = String(rawText || '')
    .replace(/Command failed:\s*powershell\.exe\s+-NoProfile\s+-ExecutionPolicy\s+Bypass\s+-EncodedCommand\s+\S+/ig, '')
    .replace(/#<\s*CLIXML/ig, ' ')
    .replace(/<[^>]+>/g, ' ')
    .replace(/_x000D__x000A_/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  if (/AccessDenied|PSSessionStateBroken|access is denied|access denied|액세스가 거부/i.test(normalized)) {
    return 'PowerShell Remoting access denied. Check the remote account/password, administrator or Remote Management Users permission, and local-account remote UAC policy on the target Windows server.';
  }
  if (/TrustedHosts|WinRM client cannot process the request|신뢰/i.test(normalized)) {
    return 'PowerShell Remoting TrustedHosts/client trust error. Add the target IP/host to TrustedHosts on the vuln-assessor PC.';
  }
  if (/Logon failure|user name or password|로그온|암호|password/i.test(normalized)) {
    return 'PowerShell Remoting logon failed. Check the username/password and use TARGETHOST\\username for a local account.';
  }

  const parts = [error?.stderr, error?.stdout]
    .filter(Boolean)
    .map(text => String(text).replace(/\s+/g, ' ').trim())
    .filter(Boolean);
  if (parts.length) return parts.join(' | ');

  const codeText = error?.code ? `exit code ${error.code}` : '';
  const signalText = error?.signal ? `signal ${error.signal}` : '';
  const fallback = [codeText, signalText].filter(Boolean).join(', ');
  return fallback || 'PowerShell command failed. Check WinRM connectivity, TrustedHosts, and credentials.';
}

async function runWindowsPowerShellViaLocalRemoting(target, script, label) {
  const remoteEncoded = encodePowerShellCommand(script);
  const localScript = [
    '$ErrorActionPreference = "Stop"',
    `$sec = ConvertTo-SecureString ${quotePs(target.password)} -AsPlainText -Force`,
    `$cred = New-Object System.Management.Automation.PSCredential(${quotePs(target.username)}, $sec)`,
    `$sessionOpt = New-PSSessionOption -OperationTimeout 900000`,
    `$params = @{ ComputerName = ${quotePs(target.host)}; Credential = $cred; ScriptBlock = { param($encoded) powershell.exe -NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded }; ArgumentList = ${quotePs(remoteEncoded)}; SessionOption = $sessionOpt }`,
    target.winrmPort ? `$params.Port = ${Number(target.winrmPort)}` : '',
    'Invoke-Command @params',
  ].filter(Boolean).join('; ');

  try {
    const result = await runLocalPowerShellScript(localScript);
    return String(result.stdout || '').trim();
  } catch (e) {
    const detail = compactPowerShellError(e);
    throw new Error(`${label || 'WinRM PowerShell failed'}: ${detail || 'Invoke-Command failed'}`);
  }
}

function windowsWinRmRunScript(remoteWorkDirAbs, remoteScriptAbs, ext, args, debugLogAbs, outputDirAbs) {
  const rawArgs = String(args || '').trim();
  const argText = ext === '.ps1' ? addPowerShellOutputDirArg(rawArgs, outputDirAbs) : rawArgs;
  const commands = [
    '$ErrorActionPreference = "Continue"',
    `Set-Location -LiteralPath ${quotePs(remoteWorkDirAbs)}`,
    `Remove-Item -LiteralPath ${quotePs(debugLogAbs)} -Force -ErrorAction SilentlyContinue`,
  ];

  if (ext === '.ps1') {
    commands.push(`& ${quotePs(remoteScriptAbs)} ${argText} *> ${quotePs(debugLogAbs)}`);
  } else if (ext === '.bat' || ext === '.cmd') {
    commands.push(`cmd.exe /c ${quotePs(`"${remoteScriptAbs}" ${argText}`)} *> ${quotePs(debugLogAbs)}`);
  } else if (ext === '.py') {
    commands.push(`python ${quotePs(remoteScriptAbs)} ${argText} *> ${quotePs(debugLogAbs)}`);
  } else {
    commands.push(`& ${quotePs(remoteScriptAbs)} ${argText} *> ${quotePs(debugLogAbs)}`);
  }
  commands.push('if ($LASTEXITCODE -ne $null) { exit $LASTEXITCODE }');
  return commands.join('; ');
}

async function findWindowsResultViaWinRm(target, remoteDirsAbs, resultGlob) {
  const dirs = uniqueList((Array.isArray(remoteDirsAbs) ? remoteDirsAbs : [remoteDirsAbs]).map(x => normalizeWinAbsPath(x)));
  const psDirs = dirs.map(quotePs).join(', ');
  const script = [
    `$dirs = @(${psDirs})`,
    `$files = foreach ($d in $dirs) { if (Test-Path -LiteralPath $d) { Get-ChildItem -LiteralPath $d -Recurse -File -Filter ${quotePs(resultGlob || '*.xml')} -ErrorAction SilentlyContinue } }`,
    '$f = $files | Sort-Object LastWriteTime -Descending | Select-Object -First 1',
    'if ($f) { $f.FullName }',
  ].join('; ');
  const output = await runWindowsPowerShell(target, script, 'WinRM result XML search failed');
  return normalizeWinRmOutput(output, 'WinRM 결과 XML 탐색 실패').split(/\r?\n/).map(x => x.trim()).filter(Boolean).pop() || '';
}

async function runWindowsPowerShell(target, script, label) {
  const mode = String(process.env.SCRIPT_DEPLOY_WINDOWS_WINRM_MODE || 'powershell-only').toLowerCase();
  if (mode === 'nodejs-winrm' || mode === 'basic') {
    const output = await winrm.runPowershell(script, target.host, target.username, target.password, target.winrmPort);
    return normalizeWinRmOutput(output, label || 'WinRM PowerShell failed');
  }

  try {
    return await runWindowsPowerShellViaLocalRemoting(target, script, label);
  } catch (primaryError) {
    if (mode === 'powershell-only') throw primaryError;
    const output = await winrm.runPowershell(script, target.host, target.username, target.password, target.winrmPort);
    return normalizeWinRmOutput(output, `${label || 'WinRM PowerShell failed'}; PowerShell remoting also failed: ${primaryError.message}`);
  }
}

async function uploadWindowsFileViaWinRm(target, localPath, remotePathAbs) {
  const data = fs.readFileSync(localPath).toString('base64');
  const chunkSize = Number(process.env.SCRIPT_DEPLOY_WINRM_CHUNK_SIZE || 6000);
  const chunks = data.match(new RegExp(`.{1,${chunkSize}}`, 'g')) || [''];

  for (let i = 0; i < chunks.length; i += 1) {
    const script = [
      `$path = ${quotePs(remotePathAbs)}`,
      '$dir = Split-Path -Parent $path',
      'New-Item -ItemType Directory -Force -Path $dir | Out-Null',
      i === 0 ? 'Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue' : '',
      `$bytes = [Convert]::FromBase64String(${quotePs(chunks[i])})`,
      '$fs = [IO.File]::Open($path, [IO.FileMode]::Append, [IO.FileAccess]::Write)',
      'try { $fs.Write($bytes, 0, $bytes.Length) } finally { $fs.Close() }',
    ].filter(Boolean).join('; ');
    await runWindowsPowerShell(target, script, `WinRM file upload failed: ${remotePathAbs}`);
  }
}

async function uploadWindowsPayloadFilesViaWinRm(target, payload, remoteDirAbs) {
  await runWindowsPowerShell(
    target,
    `New-Item -ItemType Directory -Force -Path ${quotePs(remoteDirAbs)} | Out-Null`,
    'WinRM remote directory create failed'
  );

  for (const file of payload.files) {
    const relative = String(file.relativePath || '').replace(/\//g, '\\');
    const remoteFileAbs = winPathJoin(remoteDirAbs, relative);
    await uploadWindowsFileViaWinRm(target, localPayloadFilePath(payload, file), remoteFileAbs);
  }
}

async function downloadWindowsFileViaWinRm(target, remotePathAbs, localPath) {
  const script = [
    `$path = ${quotePs(remotePathAbs)}`,
    'if (-not (Test-Path -LiteralPath $path)) { throw "File not found: $path" }',
    '$b64 = [Convert]::ToBase64String([IO.File]::ReadAllBytes($path))',
    '$chunk = 60000',
    'for ($i = 0; $i -lt $b64.Length; $i += $chunk) {',
    '  $len = [Math]::Min($chunk, $b64.Length - $i)',
    '  $b64.Substring($i, $len)',
    '}',
  ].join('; ');
  const stdout = await runWindowsPowerShell(target, script, `WinRM file download failed: ${remotePathAbs}`);
  const b64 = stdout.split(/\r?\n/).map(x => x.trim()).filter(Boolean).join('');
  const bytes = Buffer.from(b64, 'base64');
  if (!bytes.length) throw new Error(`WinRM file download returned empty data: ${remotePathAbs}`);
  fs.writeFileSync(localPath, bytes);
  return bytes.length;
}

async function runWindowsWinRmScriptDeployment(server, localScriptPath, opts = {}) {
  const target = resolveTarget(server);
  const hostname = server.hostname || server.name || target.host;
  const jobId = opts.jobId || `direct-${Date.now()}`;
  const localXmlPath = localResultPath(hostname);
  const onProgress = typeof opts.onProgress === 'function' ? opts.onProgress : async () => {};
  const payload = await prepareDeployPayload(localScriptPath, target, { ...opts, jobId });
  const remoteBaseAbs = resolveWindowsRemoteBaseDir(server, opts);
  const remoteDirAbs = winPathJoin(remoteBaseAbs, `vuln-assessor-${jobId}`);
  const remoteScriptAbs = winPathJoin(remoteDirAbs, String(payload.scriptRelativePath).replace(/\//g, '\\'));
  const remoteWorkDirAbs = winDirname(remoteScriptAbs) || remoteDirAbs;
  const outputDirAbs = normalizeWinAbsPath(opts.remoteResultDir || opts.remote_result_dir || process.env.SCRIPT_DEPLOY_WINDOWS_OUTPUT_DIR || remoteWorkDirAbs);
  const debugLogAbs = winPathJoin(remoteDirAbs, 'debug_log.txt');
  const resultSearchDirs = uniqueList([
    remoteDirAbs,
    remoteWorkDirAbs,
    outputDirAbs,
    ...parseWindowsPathList(process.env.SCRIPT_DEPLOY_WINDOWS_RESULT_SEARCH_DIRS),
  ]);

  try {
    await onProgress(18, 'WinRM connection preparing');
    await uploadWindowsPayloadFilesViaWinRm(target, payload, remoteDirAbs);
    await onProgress(35, 'script uploaded via WinRM');

    if (opts.deployOnly) {
      await onProgress(100, 'script deployed only');
      return {
        status: 'success',
        hostname,
        package_mode: payload.kind,
        package_script: payload.scriptRelativePath,
        remote_dir: remoteDirAbs,
        remote_script: remoteScriptAbs,
        remote_output_dir: outputDirAbs,
        remote_result: null,
        local_result_path: null,
        local_result_file: null,
        size: 0,
        stdout: '',
        stderr: '',
        exit_code: null,
        deployed_only: true,
        transport: 'winrm',
      };
    }

    await onProgress(45, 'script executing via WinRM');
    const runScript = windowsWinRmRunScript(remoteWorkDirAbs, remoteScriptAbs, payload.ext, opts.scriptArgs, debugLogAbs, outputDirAbs);
    const runOutput = await runWindowsPowerShell(target, runScript, 'WinRM PowerShell execution failed');
    const stdout = normalizeWinRmOutput(runOutput, 'WinRM PowerShell 실행 실패');

    await onProgress(65, 'result xml searching');
    let remoteResultAbs = await findWindowsResultViaWinRm(target, resultSearchDirs, opts.resultGlob);
    if (!remoteResultAbs && opts.resultGlob !== '*.xml') {
      remoteResultAbs = await findWindowsResultViaWinRm(target, resultSearchDirs, '*.xml');
    }
    if (!remoteResultAbs) {
      throw new Error(`Windows Script 실행은 완료됐지만 결과 XML(${opts.resultGlob || '*.xml'})을 찾지 못했습니다. 탐색 경로: ${resultSearchDirs.join(', ')}`);
    }

    await onProgress(75, 'result xml downloading via WinRM');
    const size = await downloadWindowsFileViaWinRm(target, remoteResultAbs, localXmlPath);
    const xmlData = fs.readFileSync(localXmlPath, 'utf8');
    if (!xmlData || String(xmlData).trim().length < 20) {
      throw new Error('Windows Script 결과 XML이 비어 있거나 너무 작습니다.');
    }
    await onProgress(82, 'result xml downloaded');

    return {
      status: 'success',
      hostname,
      package_mode: payload.kind,
      package_script: payload.scriptRelativePath,
      remote_dir: remoteDirAbs,
      remote_script: remoteScriptAbs,
      remote_output_dir: outputDirAbs,
      remote_result: remoteResultAbs,
      local_result_path: localXmlPath,
      local_result_file: path.basename(localXmlPath),
      size,
      stdout,
      stderr: '',
      exit_code: 0,
      transport: 'winrm',
    };
  } finally {
    if (!opts.deployOnly && !KEEP_REMOTE_WORKSPACE) {
      const cleanup = `Remove-Item -LiteralPath ${quotePs(remoteDirAbs)} -Recurse -Force -ErrorAction SilentlyContinue`;
      await runWindowsPowerShell(target, cleanup, 'WinRM cleanup failed').catch(() => {});
    }
    cleanupDeployPayload(payload);
  }
}

async function runDirectScriptDeployment(server, localScriptPath, opts = {}) {
  const target = resolveTarget(server);
  if (target.isWindows) {
    return runWindowsWinRmScriptDeployment(server, localScriptPath, opts);
  }
  const hostname = server.hostname || server.name || target.host;
  const jobId = opts.jobId || `direct-${Date.now()}`;
  const localXmlPath = localResultPath(hostname);
  const onProgress = typeof opts.onProgress === 'function' ? opts.onProgress : async () => {};
  await onProgress(12, 'SSH connection preparing');
  const payload = await prepareDeployPayload(localScriptPath, target, { ...opts, jobId });

  try {
    return await withConnection({
    host: target.host,
    port: target.port,
    username: target.username,
    password: target.password,
    privateKeyPath: target.privateKeyPath,
    readyTimeout: opts.readyTimeout || 15000,
  }, async (conn) => {
    await onProgress(20, 'remote workspace preparing');
    let remoteDir;
    if (target.isWindows) {
      const r = await exec(conn, `powershell -NoProfile -Command "$d = Join-Path $env:TEMP ${quotePs(`vuln-assessor-${jobId}`)}; New-Item -ItemType Directory -Force -Path $d | Out-Null; $d"`);
      if (r.code !== 0 || !r.stdout.trim()) throw new Error(`Windows 원격 작업 폴더 생성 실패: ${r.stderr || r.stdout}`);
      remoteDir = r.stdout.trim().split(/\r?\n/).pop();
    } else {
      remoteDir = `${resolveUnixRemoteBaseDir(server, opts)}/vuln-assessor-${jobId}`;
      const r = await exec(conn, `mkdir -p ${quoteSh(remoteDir)}`);
      if (r.code !== 0) throw new Error(`원격 작업 폴더 생성 실패: ${r.stderr || r.stdout}`);
    }

    const remoteScript = remotePathJoin(remoteDir, payload.scriptRelativePath);
    const remoteWorkDir = remoteDirname(remoteScript) || remoteDir;
    await onProgress(30, 'script uploading');
    if (payload.kind === 'package') {
      await uploadPackageFiles(conn, target, payload.rootDir, payload.files, remoteDir);
    } else {
      await uploadFile(conn, localScriptPath, remoteScript);
    }

    if (!target.isWindows) {
      await exec(conn, `chmod 700 ${quoteSh(remoteScript)}`).catch(() => {});
    }

    if (opts.deployOnly) {
      await onProgress(100, 'script deployed only');
      return {
        status: 'success',
        hostname,
        package_mode: payload.kind,
        package_script: payload.scriptRelativePath,
        remote_dir: remoteDir,
        remote_script: remoteScript,
        remote_result: null,
        local_result_path: null,
        local_result_file: null,
        size: 0,
        stdout: '',
        stderr: '',
        exit_code: null,
        deployed_only: true,
      };
    }

    const runCmd = target.isWindows
      ? windowsRunCommand(remoteWorkDir, remoteScript, payload.ext, opts.scriptArgs)
      : unixRunCommand(remoteWorkDir, remoteScript, payload.ext, opts.scriptArgs);
    await onProgress(45, 'script executing');
    const runResult = await exec(conn, runCmd, { timeout: opts.timeout || 300000 });
    if (runResult.code !== 0) {
      throw new Error(`원격 Script 실행 실패(exit ${runResult.code}): ${runResult.stderr || runResult.stdout}`);
    }

    await onProgress(65, 'result xml searching');
    let remoteResult = target.isWindows
      ? await findWindowsResult(conn, remoteDir, opts.resultGlob)
      : await findUnixResult(conn, remoteDir, opts.resultGlob);
    if (!remoteResult && opts.resultGlob !== '*.xml') {
      remoteResult = target.isWindows
        ? await findWindowsResult(conn, remoteDir, '*.xml')
        : await findUnixResult(conn, remoteDir, '*.xml');
    }
    if (!remoteResult) {
      throw new Error(`원격 Script 실행은 완료됐지만 결과 XML(${opts.resultGlob || '*.xml'})을 찾지 못했습니다.`);
    }

    await onProgress(75, 'result xml downloading');
    const size = await downloadFile(conn, normalizeSftpPath(remoteResult), localXmlPath);
    await onProgress(82, 'result xml downloaded');
    return {
      status: 'success',
      hostname,
      package_mode: payload.kind,
      package_script: payload.scriptRelativePath,
      remote_dir: remoteDir,
      remote_script: remoteScript,
      remote_result: remoteResult,
      local_result_path: localXmlPath,
      local_result_file: path.basename(localXmlPath),
      size,
      stdout: runResult.stdout,
      stderr: runResult.stderr,
      exit_code: runResult.code,
    };
    });
  } finally {
    cleanupDeployPayload(payload);
  }
}

module.exports = {
  runDirectScriptDeployment,
  runWindowsWinRmScriptDeployment,
  runWindowsPowerShell,
  prepareDeployPayload,
  cleanupDeployPayload,
  resolveTarget,
};

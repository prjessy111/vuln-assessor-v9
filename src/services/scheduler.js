'use strict';

require('../config');

const fs = require('fs');
const path = require('path');
const SMB2 = require('@marsaud/smb2');
const winrm = require('nodejs-winrm');
const { XMLParser } = require('fast-xml-parser');

const kvStorage = require('../storage');
const fetcher = require('./fetcher');
const { executeAiDiagnosis, executeLlmDiagnosis } = require('../engine/aiAssessment');
const { withConnection, exec, downloadFile } = require('../engine/sshClient');

const UNIX_FAMILY = ['linux', 'solaris', 'aix', 'hp-ux'];
const AI_DIAGNOSE_SUPPORTED = ['linux', 'solaris', 'aix', 'hp-ux', 'windows'];
const UPLOAD_TMP_DIR = process.env.UPLOAD_TMP_DIR || path.resolve(__dirname, '../../data/uploads');
const UNIX_EXISTING_SCRIPT_XML_DIRS = [
  '/opt/lsware/secums/agent/bin',
  '/opt/lswaer/secums/agent/bin',
  '/var/lib/secums',
  '/var/lib/secums/script',
];
const WINDOWS_EXISTING_SCRIPT_XML_DIRS = [
  'Program Files (x86)\\lsware\\secums\\agent\\bin',
  'Program Files\\lsware\\secums\\agent\\bin',
  'lsware\\secums\\agent\\bin',
];

function safeName(value, fallback = 'target') {
  return String(value || fallback)
    .trim()
    .replace(/\.[^.]+$/, '')
    .replace(/[^a-zA-Z0-9._-]/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '') || fallback;
}

function todayParts(date = new Date()) {
  const yyyy = String(date.getFullYear());
  const mm = String(date.getMonth() + 1).padStart(2, '0');
  const dd = String(date.getDate()).padStart(2, '0');
  return { folder: `${yyyy}-${mm}-${dd}`, compact: `${yyyy}${mm}${dd}` };
}

function getDailyUploadPath(hostname, source = 'script') {
  const { folder, compact } = todayParts();
  const uploadDir = path.join(UPLOAD_TMP_DIR, folder);
  fs.mkdirSync(uploadDir, { recursive: true });
  return path.join(uploadDir, `${safeName(hostname)}_${source}_${compact}.xml`);
}

function quoteSh(value) {
  return `'${String(value ?? '').replace(/'/g, `'\\''`)}'`;
}

function quotePs(value) {
  return `'${String(value ?? '').replace(/'/g, "''")}'`;
}

function looksLikeScriptXml(filename) {
  const lower = String(filename || '').toLowerCase();
  return lower.endsWith('.xml') && (
    lower.includes('script') ||
    /-s-\d{8}\.xml$/.test(lower) ||
    /_s_\d{8}\.xml$/.test(lower) ||
    /^.*\.xml$/.test(lower)
  );
}

function resolveExistingFile(candidates, label) {
  const found = candidates.find(file => fs.existsSync(file));
  if (!found) {
    throw new Error(`${label} file not found: ${candidates.join(', ')}`);
  }
  return found;
}

function validateXml(xmlData, label) {
  if (!xmlData || String(xmlData).trim().length < 20) {
    throw new Error(`${label} is empty or too small`);
  }
  new XMLParser().parse(xmlData);
}

function normalizeDiagnosisEngine(value) {
  if (value === 'ai_llm' || value === 'ai-llm' || value === 'both') return 'ai_llm';
  if (value === 'llm') return 'llm';
  return 'ai';
}

function normalizeScheduledSource(value) {
  return ['secums', 'script', 'both'].includes(value) ? value : 'both';
}

async function runDiagnosisByEngine(engine, server, opts = {}) {
  if (engine === 'ai_llm') {
    const aiResult = await executeAiDiagnosis(server, opts);
    if (aiResult.status !== 'success') {
      return {
        ...aiResult,
        diagnose_type: 'ai_llm',
        phase: 'ai',
        error: `AI diagnosis failed: ${aiResult.error || 'unknown error'}`,
      };
    }

    const llmFilter = opts.llmFilter || opts.llm_filter || opts.filter || process.env.LLM_DETAIL_FILTER || 'review_needed';
    const llmResult = await executeLlmDiagnosis(server, {
      ...opts,
      filter: llmFilter,
      baseAssessmentId: aiResult.assessment_id,
    });
    if (llmResult.status !== 'success') {
      return {
        ...llmResult,
        diagnose_type: 'ai_llm',
        phase: 'llm',
        ai_assessment_id: aiResult.assessment_id,
        error: `AI diagnosis completed but LLM diagnosis failed: ${llmResult.error || 'unknown error'}`,
      };
    }

    return {
      ...llmResult,
      diagnose_type: 'ai_llm',
      ai_assessment_id: aiResult.assessment_id,
      llm_assessment_id: llmResult.assessment_id,
      assessment_id: llmResult.assessment_id,
      ai_summary: aiResult.summary,
      llm_summary: llmResult.summary,
      llm_filter: llmFilter,
      elapsed_ms: (aiResult.elapsed_ms || 0) + (llmResult.elapsed_ms || 0),
      message: `AI diagnosis #${aiResult.assessment_id} and LLM diagnosis #${llmResult.assessment_id} completed`,
    };
  }

  return engine === 'llm'
    ? executeLlmDiagnosis(server, opts)
    : executeAiDiagnosis(server, opts);
}

function getTargetServersFromFile() {
  const csvPath = path.resolve(__dirname, '../../servers.csv');
  if (!fs.existsSync(csvPath)) return [];

  return fs.readFileSync(csvPath, 'utf8')
    .split(/\r?\n/)
    .map(line => line.trim())
    .filter(line => line && !line.startsWith('#'))
    .map(line => line.split(',').map(part => part.trim()))
    .filter(parts => parts.length >= 5)
    .map(parts => ({
      hostname: parts[0],
      ip: parts[1],
      os: parts[2],
      username: parts[3],
      password: parts[4],
      asset_no: parts[5] || parts[0],
      server_id: parts[6] || parts[1],
    }));
}

function appendRunLog(record) {
  try {
    let history = kvStorage.loadSync('scheduler_runs') || [];
    if (!Array.isArray(history)) history = [];
    history.unshift(record);
    if (history.length > 500) history.length = 500;
    kvStorage.saveSync('scheduler_runs', history);
  } catch (e) {
    console.error('[Scheduler] run log save failed:', e.message);
  }
}

function uploadFile(conn, localPath, remotePath) {
  return new Promise((resolve, reject) => {
    conn.sftp((err, sftp) => {
      if (err) return reject(err);
      sftp.fastPut(localPath, remotePath, (putErr) => {
        if (putErr) return reject(putErr);
        resolve();
      });
    });
  });
}

async function fetchExistingScriptXmlViaSSH(targetServer) {
  const hostname = targetServer.hostname || targetServer.name || targetServer.ip;
  const localXmlPath = getDailyUploadPath(hostname, 'script');
  const dirs = UNIX_EXISTING_SCRIPT_XML_DIRS.map(quoteSh).join(' ');

  return withConnection({
    host: targetServer.ip,
    port: Number(targetServer.port || targetServer.ssh_port || 22),
    username: targetServer.username,
    password: targetServer.password,
    readyTimeout: 20000,
  }, async (conn) => {
    const findCmd = [
      `for dir in ${dirs}; do`,
      '  [ -d "$dir" ] || continue;',
      '  ls -1t "$dir"/*-s-*.xml "$dir"/script*.xml "$dir"/*.xml 2>/dev/null;',
      'done | head -1',
    ].join(' ');
    const found = await exec(conn, findCmd, { timeout: 30000 });
    const remoteXml = found.stdout.trim().split(/\r?\n/)[0];
    if (!remoteXml) return null;

    await downloadFile(conn, remoteXml, localXmlPath);
    validateXml(fs.readFileSync(localXmlPath, 'utf8'), 'existing UNIX script XML');
    return localXmlPath;
  });
}

async function fetchCustomXmlViaSSH(targetServer) {
  const hostname = targetServer.hostname || targetServer.name || targetServer.ip;
  const localScript = resolveExistingFile([
    path.resolve(__dirname, '../../scripts/ai-ready/fsi_unix_ai.sh'),
    path.resolve(__dirname, '../../scripts/fsi_unix_ai.sh'),
  ], 'UNIX script');

  const jobId = `vuln-assessor-${Date.now()}-${safeName(hostname)}`;
  const remoteDir = `/tmp/${jobId}`;
  const remoteScript = `${remoteDir}/fsi_unix_ai.sh`;
  const localXmlPath = getDailyUploadPath(hostname, 'script');

  return withConnection({
    host: targetServer.ip,
    port: Number(targetServer.port || targetServer.ssh_port || 22),
    username: targetServer.username,
    password: targetServer.password,
    readyTimeout: 20000,
  }, async (conn) => {
    const mkdir = await exec(conn, `mkdir -p ${quoteSh(remoteDir)}`, { timeout: 30000 });
    if (mkdir.code !== 0) throw new Error(`UNIX remote workdir create failed: ${mkdir.stderr || mkdir.stdout}`);

    try {
      await uploadFile(conn, localScript, remoteScript);
      const run = await exec(
        conn,
        `cd ${quoteSh(remoteDir)} && chmod 700 ./fsi_unix_ai.sh && ./fsi_unix_ai.sh < /dev/null`,
        { timeout: 900000 }
      );

      const findCmd = `find ${quoteSh(remoteDir)} -maxdepth 1 -type f \\( -name '*-s-*.xml' -o -name '*.xml' \\) -exec ls -t {} + 2>/dev/null | head -1`;
      const found = await exec(conn, findCmd, { timeout: 30000 });
      const remoteResult = found.stdout.trim().split(/\r?\n/)[0];
      if (!remoteResult) {
        throw new Error(`UNIX script result XML not found. exit=${run.code}, stderr=${run.stderr || ''}`);
      }

      await downloadFile(conn, remoteResult, localXmlPath);
      validateXml(fs.readFileSync(localXmlPath, 'utf8'), 'UNIX script XML');
      return localXmlPath;
    } finally {
      await exec(conn, `rm -rf ${quoteSh(remoteDir)}`, { timeout: 30000 }).catch(() => {});
    }
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

async function smbExists(client, remotePath) {
  return smbCall(client, 'exists', remotePath);
}

async function fetchExistingScriptXmlViaWindows(targetServer) {
  const hostname = targetServer.hostname || targetServer.name || targetServer.ip;
  const localXmlPath = getDailyUploadPath(hostname, 'script');
  const smbClient = new SMB2({
    share: `\\\\${targetServer.ip}\\C$`,
    domain: targetServer.domain || 'WORKGROUP',
    username: targetServer.username,
    password: targetServer.password,
    autoCloseTimeout: 0,
  });

  try {
    const candidates = [];
    for (const dir of WINDOWS_EXISTING_SCRIPT_XML_DIRS) {
      let entries = [];
      try {
        entries = await smbCall(smbClient, 'readdir', dir, { stats: true });
      } catch (_) {
        continue;
      }
      for (const entry of entries || []) {
        const name = typeof entry === 'string' ? entry : entry.name;
        if (!looksLikeScriptXml(name)) continue;
        const remotePath = `${dir}\\${name}`;
        candidates.push({
          remotePath,
          mtime: entry && entry.mtime ? new Date(entry.mtime).getTime() : 0,
        });
      }
    }
    if (!candidates.length) return null;
    candidates.sort((a, b) => b.mtime - a.mtime);

    const xmlData = await smbCall(smbClient, 'readFile', candidates[0].remotePath, 'utf8');
    validateXml(xmlData, 'existing Windows script XML');
    fs.writeFileSync(localXmlPath, xmlData);
    return localXmlPath;
  } finally {
    try { smbClient.disconnect(); } catch (_) {}
  }
}

async function fetchCustomXmlViaWindows(targetServer) {
  const hostname = targetServer.hostname || targetServer.name || targetServer.ip;
  const localPs1 = resolveExistingFile([
    path.resolve(__dirname, '../../scripts/ai-ready/fsi_win_ai.ps1'),
    path.resolve(__dirname, '../../scripts/fsi_win_ai.ps1'),
  ], 'Windows PowerShell script');

  const jobId = `vuln-assessor-${Date.now()}-${safeName(hostname)}`;
  const remoteDir = `Windows\\Temp\\${jobId}`;
  const remoteDirAbs = `C:\\${remoteDir}`;
  const remotePs1Path = `${remoteDir}\\fsi_win_ai.ps1`;
  const remotePs1Abs = `${remoteDirAbs}\\fsi_win_ai.ps1`;
  const remoteXmlPath = `${remoteDir}\\fsi_result_win.xml`;
  const remoteXmlAbs = `${remoteDirAbs}\\fsi_result_win.xml`;
  const debugLogAbs = `${remoteDirAbs}\\debug_log.txt`;
  const localXmlPath = getDailyUploadPath(hostname, 'script');
  // 기본 full — fast면 systeminfo/hotfix/schtasks/tasklist 스킵 → 판정불가(N/A) 양산. 정확 진단 위해 full 기본.
  const scriptMode = String(process.env.SCHEDULER_SCRIPT_MODE || 'full').toLowerCase();
  const scriptArgs = scriptMode === 'fast' ? '-Fast' : '-Full';

  const smbClient = new SMB2({
    share: `\\\\${targetServer.ip}\\C$`,
    domain: targetServer.domain || 'WORKGROUP',
    username: targetServer.username,
    password: targetServer.password,
    autoCloseTimeout: 0,
  });

  try {
    await smbCall(smbClient, 'mkdir', remoteDir).catch(() => {});
    await smbCall(smbClient, 'writeFile', remotePs1Path, fs.readFileSync(localPs1));

    const runScript = [
      `Set-Location -LiteralPath ${quotePs(remoteDirAbs)}`,
      `Remove-Item -LiteralPath ${quotePs(remoteXmlAbs)} -Force -ErrorAction SilentlyContinue`,
      `& ${quotePs(remotePs1Abs)} ${scriptArgs} *> ${quotePs(debugLogAbs)}`,
    ].join('; ');

    const winrmPort = Number(targetServer.winrm_port || targetServer.winrmPort || 5985);
    const output = await winrm.runPowershell(runScript, targetServer.ip, targetServer.username, targetServer.password, winrmPort);
    if (output instanceof Error) {
      throw new Error(`WinRM PowerShell execution failed: ${output.message}`);
    }

    for (let attempt = 1; attempt <= 30; attempt += 1) {
      if (await smbExists(smbClient, remoteXmlPath)) {
        const xmlData = await smbCall(smbClient, 'readFile', remoteXmlPath, 'utf8');
        validateXml(xmlData, 'Windows script XML');
        fs.writeFileSync(localXmlPath, xmlData);
        return localXmlPath;
      }
      await new Promise(resolve => setTimeout(resolve, 10000));
    }

    throw new Error('Windows script result XML was not created within 5 minutes');
  } finally {
    const cleanup = `Remove-Item -LiteralPath ${quotePs(remoteDirAbs)} -Recurse -Force -ErrorAction SilentlyContinue`;
    await winrm.runPowershell(
      cleanup,
      targetServer.ip,
      targetServer.username,
      targetServer.password,
      Number(targetServer.winrm_port || targetServer.winrmPort || 5985)
    ).catch(() => {});
    try { smbClient.disconnect(); } catch (_) {}
  }
}

async function fetchSecumsRaw(targetServer, osType, hostname) {
  if (UNIX_FAMILY.includes(osType)) {
    return fetcher.fetchFromUnix(targetServer.ip, targetServer.username, targetServer.password, hostname);
  }
  if (osType === 'windows') {
    return fetcher.fetchFromWindows(targetServer.ip, targetServer.username, targetServer.password, hostname);
  }
  throw new Error(`unsupported OS type: ${targetServer.os}`);
}

async function fetchScriptRaw(targetServer, osType) {
  const mode = String(process.env.SCHEDULER_SCRIPT_XML_MODE || 'prefer_existing').toLowerCase();
  const preferExisting = mode !== 'run_script';
  const existingOnly = mode === 'existing_only';

  if (UNIX_FAMILY.includes(osType)) {
    if (preferExisting) {
      try {
        const existing = await fetchExistingScriptXmlViaSSH(targetServer);
        if (existing) return existing;
      } catch (e) {
        console.warn(`[Scheduler] existing UNIX script XML fetch failed: ${e.message}`);
        if (existingOnly) throw e;
      }
      if (existingOnly) throw new Error('existing UNIX script XML not found');
    }
    return fetchCustomXmlViaSSH(targetServer);
  }

  if (osType === 'windows') {
    if (preferExisting) {
      try {
        const existing = await fetchExistingScriptXmlViaWindows(targetServer);
        if (existing) return existing;
      } catch (e) {
        console.warn(`[Scheduler] existing Windows script XML fetch failed: ${e.message}`);
        if (existingOnly) throw e;
      }
      if (existingOnly) throw new Error('existing Windows script XML not found');
    }
    return fetchCustomXmlViaWindows(targetServer);
  }

  throw new Error(`unsupported OS type: ${targetServer.os}`);
}

async function runScheduledDiagnosis(targetServer, options = {}) {
  const hostname = targetServer.hostname || targetServer.name || `unknown-${targetServer.ip}`;
  const osType = String(targetServer.os || '').toLowerCase();
  const requestedSource = normalizeScheduledSource(
    options.source || targetServer.source || process.env.SCHEDULER_SOURCE || 'both'
  );
  const started = Date.now();
  const runRecord = {
    started_at: new Date(started).toLocaleString('sv-SE'), // 로컬(KST) — toISOString은 UTC라 9시간 밀림
    hostname,
    ip: targetServer.ip,
    os: osType,
    fetch_status: null,
    fetch_error: null,
    secums_fetch_status: null,
    secums_fetch_error: null,
    script_fetch_status: null,
    script_fetch_error: null,
    requested_source: requestedSource,
    source_type: null,
    local_db_path: null,
    local_script_path: null,
    diagnose_type: null,
    diagnose_status: null,
    diagnose_error: null,
    assessment_id: null,
    ai_assessment_id: null,
    llm_assessment_id: null,
    summary: null,
    elapsed_ms: null,
  };

  try {
    console.log(`[Scheduler] [${hostname}] collection started (${targetServer.ip}, ${osType}, source=${requestedSource})`);

    let localDbPath = null;
    if (requestedSource === 'secums' || requestedSource === 'both') {
      try {
        localDbPath = await fetchSecumsRaw(targetServer, osType, hostname);
        runRecord.secums_fetch_status = 'success';
        runRecord.local_db_path = localDbPath;
        console.log(`[Scheduler] [${hostname}] SecuMS raw collected: ${localDbPath}`);
      } catch (e) {
        runRecord.secums_fetch_status = 'failed';
        runRecord.secums_fetch_error = e.message;
        console.warn(`[Scheduler] [${hostname}] SecuMS raw collection failed: ${e.message}`);
      }
    } else {
      runRecord.secums_fetch_status = 'skipped';
    }

    let scriptPath = null;
    if (requestedSource === 'script' || requestedSource === 'both') {
      try {
        scriptPath = await fetchScriptRaw(targetServer, osType);
        runRecord.script_fetch_status = 'success';
        runRecord.local_script_path = scriptPath;
        console.log(`[Scheduler] [${hostname}] Script raw XML collected: ${scriptPath}`);
      } catch (e) {
        runRecord.script_fetch_status = 'failed';
        runRecord.script_fetch_error = e.message;
        console.warn(`[Scheduler] [${hostname}] Script raw XML collection failed: ${e.message}`);
      }
    } else {
      runRecord.script_fetch_status = 'skipped';
    }

    if (!localDbPath && !scriptPath) {
      const reasons = [
        runRecord.secums_fetch_error ? `SecuMS: ${runRecord.secums_fetch_error}` : null,
        runRecord.script_fetch_error ? `Script: ${runRecord.script_fetch_error}` : null,
      ].filter(Boolean).join(' | ');
      throw new Error(`${requestedSource} 수집 실패 — ${reasons || '수집된 데이터 없음 (원인 미상)'}`);
    }

    runRecord.fetch_status = 'success';
    runRecord.source_type = localDbPath && scriptPath ? 'both' : (scriptPath ? 'script' : 'secums');

    if (!AI_DIAGNOSE_SUPPORTED.includes(osType)) {
      runRecord.diagnose_status = 'skipped';
      runRecord.diagnose_error = `AI diagnosis unsupported OS: ${osType}`;
      return runRecord;
    }

    const serverForDiagnosis = {
      server_id: targetServer.server_id || targetServer.ip,
      name: targetServer.name || hostname,
      hostname,
      asset_no: targetServer.asset_no || hostname,
      os: targetServer.os,
    };

    const diagnosisEngine = normalizeDiagnosisEngine(
      options.engine || targetServer.diagnosis_engine || targetServer.engine || process.env.SCHEDULER_DIAGNOSIS_ENGINE || 'ai_llm'
    );
    runRecord.diagnose_type = diagnosisEngine;

    // LLM 모델 선택 (사내 LLM / Claude Haiku / Claude Sonnet) → LLM 2차 진단에 적용
    let clientOverride;
    const llmChoice = String(options.llm || '').toLowerCase();
    if (llmChoice === 'haiku') clientOverride = { provider: 'anthropic', model: 'claude-haiku-4-5' };
    else if (llmChoice === 'sonnet') clientOverride = { provider: 'anthropic', model: 'claude-sonnet-4-6' };
    // 'internal'/기본 → clientOverride 없음 → 사내 LLM(env LLM_PROVIDER)

    console.log(`[Scheduler] [${hostname}] diagnosis started: engine=${diagnosisEngine}, source=${runRecord.source_type}, llm=${llmChoice || '사내'}`);
    const result = await runDiagnosisByEngine(diagnosisEngine, serverForDiagnosis, {
      executed_by: 'scheduler',
      triggered_by: 'scheduler',
      source: runRecord.source_type,
      rawPath: localDbPath || undefined,
      scriptPath: scriptPath || undefined,
      clientOverride,
    });

    runRecord.diagnose_status = result.status;
    runRecord.assessment_id = result.assessment_id || null;
    runRecord.ai_assessment_id = result.ai_assessment_id || (diagnosisEngine === 'ai' ? result.assessment_id : null);
    runRecord.llm_assessment_id = result.llm_assessment_id || (diagnosisEngine === 'llm' ? result.assessment_id : null);
    runRecord.summary = result.summary || null;
    runRecord.elapsed_ms = result.elapsed_ms || null;
    runRecord.diagnose_error = result.error || null;

    if (result.status === 'success') {
      console.log(`[Scheduler] [${hostname}] diagnosis completed: id=${result.assessment_id}`);
    } else {
      console.error(`[Scheduler] [${hostname}] diagnosis failed: ${result.error}`);
    }
  } catch (error) {
    if (!runRecord.fetch_status) {
      runRecord.fetch_status = 'failed';
      runRecord.fetch_error = error.message;
    } else {
      runRecord.diagnose_status = 'failed';
      runRecord.diagnose_error = error.message;
    }
    console.error(`[Scheduler] [${hostname}] failed: ${error.message}`);
  } finally {
    runRecord.finished_at = new Date().toLocaleString('sv-SE'); // 로컬(KST)
    runRecord.elapsed_ms = runRecord.elapsed_ms || (Date.now() - started);
    appendRunLog(runRecord);
  }

  return runRecord;
}

async function startScheduler(options = {}) {
  console.log('[Scheduler] SecuMS + Script collection scheduler started');
  const targetServers = getTargetServersFromFile();
  if (targetServers.length === 0) {
    console.log('[Scheduler] no target servers in servers.csv');
    return;
  }

  const summary = { total: 0, success: 0, fetched_only: 0, failed: 0 };
  for (const server of targetServers) {
    const result = await runScheduledDiagnosis(server, options);
    summary.total += 1;
    if (result.diagnose_status === 'success') summary.success += 1;
    else if (result.fetch_status === 'success' && result.diagnose_status === 'skipped') summary.fetched_only += 1;
    else summary.failed += 1;
  }

  console.log(`[Scheduler] done: total=${summary.total}, diagnosed=${summary.success}, fetched_only=${summary.fetched_only}, failed=${summary.failed}`);
}

module.exports = {
  startScheduler,
  runScheduledDiagnosis,
  getTargetServersFromFile,
  normalizeScheduledSource,
  fetchExistingScriptXmlViaSSH,
  fetchExistingScriptXmlViaWindows,
  fetchCustomXmlViaSSH,
  fetchCustomXmlViaWindows,
};

if (require.main === module) {
  (async () => {
    try {
      const status = await kvStorage.initialize();
      if (status.mode === 'mysql' && status.status === 'ok') await kvStorage.preloadAll();
      await startScheduler();
    } catch (e) {
      console.error('[Scheduler] init failed:', e);
      process.exitCode = 1;
    }
  })();
}

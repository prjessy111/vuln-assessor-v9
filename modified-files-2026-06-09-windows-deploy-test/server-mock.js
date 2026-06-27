'use strict';
/**
 * Vuln Assessor — Mock 모드 서버.
 *
 * 목적: DB/SSH 설정 없이 화면 + 룰 엔진 동작을 즉시 검증.
 *
 * 사용법:
 *   npm install
 *   npm run mock
 *   → http://localhost:3000 접속
 *
 * 데이터 저장:
 *   - 룰셋: rules/*.yaml (파일)
 *   - 진단 결과: data/mock/assessments.json
 *   - 서버 목록: data/mock/servers.json
 *   - 스케줄: data/mock/schedules.json
 *   - Raw SQLite: data/mock/raw/{server_id}.db (또는 업로드된 샘플 사용)
 */

// ⚠ 가장 먼저 .env 로드 — DB_MODE 등이 process.env 에 들어가야
//    이후 require('./src/storage') 가 MySQL 모드를 인식
require('./src/config');

const express = require('express');
const path = require('path');
const fs = require('fs');
const yaml = require('js-yaml');
const multer = require('multer');
const auth = require('./src/auth/auth');

const app = express();
const PORT = process.env.PORT || 3000;
const ROOT = __dirname;
const MOCK_DIR = path.join(ROOT, 'data/mock');
const UPLOAD_DIR = path.join(ROOT, 'data/uploads');
const SCRIPT_DEPLOY_DIR = path.join(ROOT, 'data/script-deploy');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });
fs.mkdirSync(SCRIPT_DEPLOY_DIR, { recursive: true });

function uploadDateParts(date = new Date()) {
  const yyyy = String(date.getFullYear());
  const mm = String(date.getMonth() + 1).padStart(2, '0');
  const dd = String(date.getDate()).padStart(2, '0');
  return { folder: `${yyyy}-${mm}-${dd}`, compact: `${yyyy}${mm}${dd}` };
}

function safeUploadPart(value, fallback = 'unknown') {
  const safe = String(value || fallback)
    .trim()
    .replace(/\.[^.]+$/, '')
    .replace(/[^a-zA-Z0-9._-]/g, '_')
    .replace(/_+/g, '_')
    .replace(/^_+|_+$/g, '');
  return safe || fallback;
}

function inferUploadSource(file) {
  if (file.fieldname === 'dbfile') return 'secums';
  if (file.fieldname === 'scriptfile' || file.fieldname === 'script_file') return 'script';
  return safeUploadPart(file.fieldname || 'file');
}

function inferUploadHostname(req, file) {
  if (req.body?.hostname) return req.body.hostname;
  if (req.body?.server_name) return req.body.server_name;
  if (req.body?.server_id) {
    try {
      const servers = loadMock('servers') || [];
      const found = servers.find(s => String(s.server_id) === String(req.body.server_id));
      if (found?.hostname || found?.name) return found.hostname || found.name;
    } catch (_) {}
  }

  const originalBase = path.basename(file.originalname || 'unknown', path.extname(file.originalname || ''));
  const match = originalBase.match(/^(.+?)(?:[-_](?:s|script|secums|raw|exportData).*)?$/i);
  return match?.[1] || originalBase || 'unknown';
}

// 수집/진단 raw 파일 저장 규칙:
// data/uploads/YYYY-MM-DD/hostname_source_YYYYMMDD.ext
const dataUploadStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const { folder } = uploadDateParts();
    const dir = path.join(UPLOAD_DIR, folder);
    fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const { compact } = uploadDateParts();
    const host = safeUploadPart(inferUploadHostname(req, file), 'unknown');
    const source = inferUploadSource(file);
    const ext = path.extname(file.originalname || '').toLowerCase() || (source === 'script' ? '.xml' : '.db');
    cb(null, `${host}_${source}_${compact}${ext}`);
  },
});

// 일반 관리 파일(CVE feed 등)은 기존 timestamp 방식 유지
const genericStorage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const ts = Date.now();
    const safe = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
    cb(null, `${ts}_${safe}`);
  },
});
const upload = multer({
  storage: dataUploadStorage,
  limits: { fileSize: 100 * 1024 * 1024 },  // 100MB
  fileFilter: (req, file, cb) => {
    const ok = /\.(db|sqlite|sqlite3)$/i.test(file.originalname);
    cb(ok ? null : new Error('SQLite 파일만 허용됩니다 (.db, .sqlite, .sqlite3)'), ok);
  },
});

const collectUpload = multer({
  storage: dataUploadStorage,
  limits: { fileSize: 100 * 1024 * 1024 },  // 100MB
  fileFilter: (req, file, cb) => {
    const isDb = file.fieldname === 'dbfile' &&
      /\.(db|sqlite|sqlite3)$/i.test(file.originalname);
    const isScriptXml = ['scriptfile', 'script_file'].includes(file.fieldname) &&
      /\.xml$/i.test(file.originalname);
    const ok = isDb || isScriptXml;
    cb(ok ? null : new Error('dbfile은 SQLite, scriptfile은 XML 파일만 허용합니다'), ok);
  },
});

const scriptDeployStorage = multer.diskStorage({
  destination: (req, file, cb) => {
    const { folder } = uploadDateParts();
    const dir = path.join(SCRIPT_DEPLOY_DIR, folder);
    fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    const { compact } = uploadDateParts();
    const hhmmss = new Date().toTimeString().slice(0, 8).replace(/:/g, '');
    const host = safeUploadPart(req.body?.hostname || req.body?.server_id || 'target');
    const base = safeUploadPart(path.basename(file.originalname || 'script', path.extname(file.originalname || '')));
    const ext = path.extname(file.originalname || '').toLowerCase() || '.sh';
    cb(null, `${host}_deploy_${compact}${hhmmss}_${base}${ext}`);
  },
});

const scriptDeployUpload = multer({
  storage: scriptDeployStorage,
  limits: { fileSize: 100 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok = /\.(sh|bash|ps1|bat|cmd|py|pl|xml|zip)$/i.test(file.originalname || '');
    cb(ok ? null : new Error('배포 스크립트는 .sh, .ps1, .bat, .cmd, .py, .pl, .xml, .zip 만 허용합니다'), ok);
  },
});

// CVE Sync 전용 — NVD 피드 (.json / .json.gz) 업로드용
const uploadCveFeed = multer({
  storage: genericStorage,
  limits: { fileSize: 200 * 1024 * 1024 },  // 200MB (NVD modified feed 정도)
  fileFilter: (req, file, cb) => {
    const ok = /\.(json|gz)$/i.test(file.originalname);
    cb(ok ? null : new Error('NVD 피드만 허용됩니다 (.json, .json.gz)'), ok);
  },
});

// ─── Mock 데이터 저장소 (storage 모듈로 위임) ───────────
const kvStorage = require('./src/storage');

function loadMock(name) {
  return kvStorage.loadSync(name);
}
function saveMock(name, data) {
  return kvStorage.saveSync(name, data);
}

// 초기 mock 데이터 생성
function seedMockData() {
  fs.mkdirSync(MOCK_DIR, { recursive: true });
  if (!loadMock('servers')) {
    saveMock('servers', require('./scripts/seed-servers.json'));
  }
  if (!loadMock('schedules')) {
    saveMock('schedules', require('./scripts/seed-schedules.json'));
  }
  console.log('✓ Mock data seeded');
}

// ─── Express 설정 ────────────────────────────────────────
app.set('view engine', 'ejs');
app.set('views', path.join(ROOT, 'src/views'));
app.use('/static', express.static(path.join(ROOT, 'src/public')));
app.use('/css', express.static(path.join(ROOT, 'src/public/css')));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// ─── 인증 미들웨어 ──────────────────────────────────────────
// 기본 admin 계정 생성 (최초 실행 시)
const adminCreated = auth.ensureDefaultAdmin(MOCK_DIR);

// 세션 미들웨어 (모든 요청)
app.use(auth.sessionMiddleware);

// 뷰에서 사용할 currentUser 주입
app.use((req, res, next) => {
  res.locals.currentUser = req.session || null;
  next();
});

// 인증 제외 경로
// - /login: 로그인 화면 (세션 없음 허용)
// - /static, /css: 정적 리소스
// - /api: Agent Push REST API (별도 토큰 인증)
const PUBLIC_PATHS = ['/login', '/static', '/css', '/api'];

app.use((req, res, next) => {
  const isPublic = PUBLIC_PATHS.some(p => req.path === p || req.path.startsWith(p + '/'));
  if (isPublic) return next();
  return auth.requireAuth(req, res, next);
});


// ─── 로그인/로그아웃 ────────────────────────────────────────
app.get('/login', (req, res) => {
  // 이미 로그인됨
  if (req.session) return res.redirect('/');
  res.render('login', {
    error: null,
    from: req.query.from || '/',
    firstRun: adminCreated !== null,  // 최초 실행 시에만 안내
  });
});

app.post('/login', (req, res) => {
  const { username, password, from } = req.body;
  const user = auth.findUserByUsername(MOCK_DIR, username);
  if (!user || !auth.verifyPassword(password, user.password_hash)) {
    return res.render('login', {
      error: '아이디 또는 비밀번호가 올바르지 않습니다.',
      from: from || '/',
      firstRun: false,
    });
  }
  // 세션 생성
  const sid = auth.createSession(user);
  auth.recordLogin(MOCK_DIR, user.user_id);
  res.setHeader('Set-Cookie', `vasid=${sid}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${8 * 60 * 60}`);
  
  // 비밀번호 변경 강제
  if (user.must_change_password) {
    return res.redirect('/users/me/password?must=1');
  }
  res.redirect(from || '/');
});

app.post('/logout', (req, res) => {
  if (req.sessionId) auth.destroySession(req.sessionId);
  res.setHeader('Set-Cookie', 'vasid=; HttpOnly; Path=/; Max-Age=0');
  res.redirect('/login');
});

app.get('/logout', (req, res) => {
  if (req.sessionId) auth.destroySession(req.sessionId);
  res.setHeader('Set-Cookie', 'vasid=; HttpOnly; Path=/; Max-Age=0');
  res.redirect('/login');
});


// ─── 사용자 관리 (admin만) ──────────────────────────────────
app.get('/users', auth.requireRole('admin'), (req, res) => {
  const users = auth.loadUsers(MOCK_DIR).map(u => {
    const { password_hash, ...rest } = u;
    return rest;
  });
  res.render('users/index', { users, activeMenu: 'users' });
});

app.get('/users/new', auth.requireRole('admin'), (req, res) => {
  res.render('users/form', { isEdit: false, user: null, activeMenu: 'users' });
});

app.post('/users/save', auth.requireRole('admin'), (req, res) => {
  try {
    const { username, password, name, email, role } = req.body;
    if (!username || !password || !name) {
      return res.status(400).json({ status: 'error', error: '필수 필드 누락' });
    }
    if (!['admin', 'operator', 'viewer'].includes(role)) {
      return res.status(400).json({ status: 'error', error: '잘못된 권한' });
    }
    if (password.length < 8) {
      return res.status(400).json({ status: 'error', error: '비밀번호는 최소 8자' });
    }
    const user = auth.createUser(MOCK_DIR, { username, password, name, email, role });
    res.json({ status: 'success', user_id: user.user_id });
  } catch (e) {
    res.status(400).json({ status: 'error', error: e.message });
  }
});

app.get('/users/:id/edit', auth.requireRole('admin'), (req, res) => {
  const user = auth.findUserById(MOCK_DIR, req.params.id);
  if (!user) return res.status(404).send('사용자를 찾을 수 없습니다');
  const { password_hash, ...rest } = user;
  res.render('users/form', { isEdit: true, user: rest, activeMenu: 'users' });
});

app.post('/users/:id/update', auth.requireRole('admin'), (req, res) => {
  try {
    const { name, email, role, password, enabled } = req.body;
    const data = { name, email, role, enabled: enabled === '1' || enabled === 1 || enabled === true };
    if (password && password.length >= 8) data.password = password;
    auth.updateUser(MOCK_DIR, req.params.id, data);
    res.json({ status: 'success' });
  } catch (e) {
    res.status(400).json({ status: 'error', error: e.message });
  }
});

app.post('/users/:id/delete', auth.requireRole('admin'), (req, res) => {
  try {
    // 본인 삭제 금지
    if (req.session.user_id == req.params.id) {
      return res.status(400).json({ status: 'error', error: '본인 계정은 삭제할 수 없습니다.' });
    }
    auth.deleteUser(MOCK_DIR, req.params.id);
    res.json({ status: 'success' });
  } catch (e) {
    res.status(400).json({ status: 'error', error: e.message });
  }
});


// ─── 비밀번호 변경 (본인) ───────────────────────────────────
app.get('/users/me/password', (req, res) => {
  res.render('users/password', { 
    mustChange: req.query.must === '1', 
    activeMenu: '' 
  });
});

app.post('/users/me/password', (req, res) => {
  try {
    const { current_password, new_password } = req.body;
    if (!new_password || new_password.length < 8) {
      return res.status(400).json({ status: 'error', error: '새 비밀번호는 최소 8자' });
    }
    const user = auth.findUserById(MOCK_DIR, req.session.user_id);
    if (!user || !auth.verifyPassword(current_password, user.password_hash)) {
      return res.status(400).json({ status: 'error', error: '현재 비밀번호가 올바르지 않습니다.' });
    }
    auth.updateUser(MOCK_DIR, req.session.user_id, { password: new_password });
    res.json({ status: 'success' });
  } catch (e) {
    res.status(400).json({ status: 'error', error: e.message });
  }
});


// ─── 라우트 ──────────────────────────────────────────────

// 대시보드
app.get('/', (req, res) => {
  res.render('dashboard', {
    activeMenu: 'dashboard',
    now: new Date().toISOString().slice(0, 16).replace('T', ' '),
    kpi: {
      totalVuln: 47, severeVuln: 18, newVuln: 8, newPct: 17,
      pending: 31, noAssignee: 12, fixed: 11, fixRate: 23,
      serverCount: 7, recentAssess: 28,
    },
    categoryStats: { '계정관리': 14, '서비스관리': 9, '파일권한': 11, '로그관리': 5, '패치관리': 4, '기타': 4 },
    trend: [
      { label: '4주 전', vuln: 14 }, { label: '3주 전', vuln: 11 },
      { label: '2주 전', vuln: 9 },  { label: '이번주', vuln: 7 }
    ],
    hostStats: loadMock('servers').map(s => ({
      hostname: s.hostname, service_name: s.service_name,
      sev_high: 2 + (s.server_id % 3), sev_mid: 2, sev_low: 1, total: 5 + (s.server_id % 3),
    })),
    workqueue: [],
    summaries: loadMock('servers').map(s => ({
      ...s, assessment_id: 2025, executed_at: '2026-05-23 06:30:00',
      total_count: 14, vuln_count: 5, safe_count: 8, na_count: 1,
    })),
  });
});

// 진단 관리
app.get('/diagnosis', (req, res) => {
  const diagnoses = loadMock('diagnoses') || [];
  res.render('diagnosis/index', {
    activeMenu: 'diagnosis',
    diagnoses,
    kpi: { success7d: 23, total7d: 28, failed7d: 4, running: 1, avgElapsedMs: 685 },
    failPatterns: [
      { phase: 'ssh', phase_label: 'SSH', error_pattern: 'SSH 연결 타임아웃', count: 7 },
      { phase: 'llm', phase_label: 'LLM', error_pattern: 'Ollama 응답 없음', count: 4 },
    ],
  });
});

// AI 진단 실행 — 분리된 모듈을 그대로 노출 (fetcher.js와 공유)
const aiAssessment = require('./src/engine/aiAssessment');
const executeAiDiagnosis = aiAssessment.executeAiDiagnosis;
const executeLlmDiagnosis = aiAssessment.executeLlmDiagnosis;
const { runDirectScriptDeployment } = require('./src/services/scriptDeployService');

function normalizeDiagnosisSource(value) {
  return ['secums', 'script', 'both'].includes(value) ? value : 'secums';
}

function normalizeDiagnosisEngine(value) {
  if (value === 'ai_llm' || value === 'ai-llm' || value === 'both') return 'ai_llm';
  return value === 'llm' ? 'llm' : 'ai';
}

async function runDiagnosisByEngine(engine, server, opts = {}) {
  if (engine === 'ai_llm') {
    const aiResult = await executeAiDiagnosis(server, opts);
    if (aiResult.status !== 'success') {
      return {
        ...aiResult,
        diagnose_type: 'ai_llm',
        phase: 'ai',
        error: `AI 1차 진단 실패: ${aiResult.error || 'unknown error'}`,
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
        error: `AI 1차 진단은 완료됐지만 LLM 상세 진단 실패: ${llmResult.error || 'unknown error'}`,
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
      message: `AI 1차 진단(#${aiResult.assessment_id}) 후 LLM 상세 진단(#${llmResult.assessment_id}) 완료`,
    };
  }

  return engine === 'llm'
    ? executeLlmDiagnosis(server, opts)
    : executeAiDiagnosis(server, opts);
}

function getDiagnosisRunner(engine) {
  return (server, opts) => runDiagnosisByEngine(engine, server, opts);
}

function findServerForUpload(serverId, hostname) {
  const servers = loadMock('servers') || [];
  let server = servers.find(s => String(s.server_id) === String(serverId));
  if (!server && hostname) {
    server = servers.find(s => String(s.hostname || '').toLowerCase() === String(hostname).toLowerCase());
  }
  try {
    const { getTargetServersFromFile } = require('./src/services/scheduler');
    const csvServers = getTargetServersFromFile();
    const csvHit = csvServers.find(s =>
      String(s.server_id) === String(serverId) ||
      String(s.ip) === String(serverId) ||
      String(s.hostname || '').toLowerCase() === String(hostname || '').toLowerCase()
    );
    if (csvHit) {
      const csvServer = {
        server_id: csvHit.server_id || csvHit.ip || hostname,
        name: csvHit.hostname,
        hostname: csvHit.hostname,
        asset_no: csvHit.asset_no,
        ip: csvHit.ip,
        ip_address: csvHit.ip,
        username: csvHit.username,
        password: csvHit.password,
        ssh_user: csvHit.username,
        ssh_password: csvHit.password,
        os: csvHit.os,
        os_type: csvHit.os,
      };
      server = server ? { ...server, ...csvServer } : csvServer;
    }
  } catch (_) {}
  if (!server && hostname) {
    server = {
      server_id: serverId || hostname,
      name: hostname,
      hostname,
      asset_no: '',
      ip: '',
      ip_address: '',
      os: '',
      os_type: '',
    };
  }
  return server || null;
}

function withScriptDeployAuthOverrides(server, body = {}) {
  const target = { ...(server || {}) };
  const username = String(body.remote_username || '').trim();
  const password = String(body.remote_password || '');
  const sshKeyPath = String(body.remote_ssh_key_path || '').trim();
  const port = String(body.remote_port || '').trim();

  if (username) {
    target.username = username;
    target.ssh_user = username;
  }
  if (password) {
    target.password = password;
    target.ssh_password = password;
    delete target.ssh_password_enc;
  }
  if (sshKeyPath) {
    target.ssh_key_path = sshKeyPath;
  }
  if (port) {
    const n = Number(port);
    if (Number.isInteger(n) && n > 0 && n <= 65535) {
      target.port = n;
      target.ssh_port = n;
      target.winrm_port = n;
      target.winrmPort = n;
    }
  }

  return target;
}

function normalizeScriptDeployAction(value, runImmediatelyValue) {
  const raw = String(value || '').trim().toLowerCase();
  if (raw === 'deploy_only' || raw === 'deploy-only' || raw === 'deploy') return 'deploy_only';
  if (raw === 'deploy_run' || raw === 'deploy-run' || raw === 'run') return 'deploy_run';
  if (raw === 'deploy_run_diagnose' || raw === 'deploy-run-diagnose' || raw === 'diagnose') return 'deploy_run_diagnose';

  const runImmediately = runImmediatelyValue === 'on' || runImmediatelyValue === 'true' || runImmediatelyValue === true;
  return runImmediately ? 'deploy_run_diagnose' : 'deploy_run';
}

function labelScriptDeployAction(action) {
  if (action === 'deploy_only') return 'Script 배포만 완료';
  if (action === 'deploy_run') return 'Script 배포/실행 완료';
  return 'Script 배포/실행 및 진단 완료';
}

function loadScriptDeployJobs() {
  return kvStorage.loadSync('script_deploy_jobs') || [];
}

function saveScriptDeployJobs(jobs) {
  kvStorage.saveSync('script_deploy_jobs', jobs);
}

function makeScriptDeployJobId() {
  return `script-${Date.now()}-${Math.random().toString(16).slice(2, 8)}`;
}

function clampProgressPercent(value) {
  const n = Number(value);
  if (!Number.isFinite(n)) return 0;
  return Math.max(0, Math.min(100, Math.round(n)));
}

function progressForScriptJobStatus(status, message = '') {
  const text = String(message || '').toLowerCase();
  if (status === 'queued') return 5;
  if (status === 'assigned') return 15;
  if (status === 'running') {
    if (text.includes('download')) return 35;
    if (text.includes('execut')) return 65;
    if (text.includes('upload')) return 80;
    return 45;
  }
  if (status === 'diagnosing') return 85;
  if (status === 'completed') return 100;
  if (status === 'diagnosed') return 100;
  if (status === 'failed' || status === 'diagnosis_failed') return 100;
  return 0;
}

function patchScriptDeployJob(jobId, patch = {}) {
  const jobs = loadScriptDeployJobs();
  const idx = jobs.findIndex(job => String(job.job_id) === String(jobId));
  if (idx < 0) return null;

  const next = { ...jobs[idx], ...patch };
  if (Object.prototype.hasOwnProperty.call(patch, 'progress_percent')) {
    next.progress_percent = clampProgressPercent(patch.progress_percent);
  }
  next.updated_at = new Date().toISOString().slice(0, 19).replace('T', ' ');
  jobs[idx] = next;
  saveScriptDeployJobs(jobs);
  return next;
}

function getPublicBaseUrl(req) {
  return `${req.protocol}://${req.get('host')}`;
}

function shellQuote(value) {
  return `'${String(value ?? '').replace(/'/g, `'\\''`)}'`;
}

function sendEnvJobResponse(res, payload) {
  const lines = Object.entries(payload)
    .map(([key, value]) => `${key}=${shellQuote(value)}`)
    .join('\n');
  res.type('text/plain; charset=utf-8').send(lines + '\n');
}

function appendCollectionHistory(record) {
  const history = kvStorage.loadSync('scheduler_runs') || [];
  history.unshift(record);
  kvStorage.saveSync('scheduler_runs', history);
}

function findOwnedScriptJob(jobId, server) {
  const jobs = loadScriptDeployJobs();
  const idx = jobs.findIndex(job =>
    String(job.job_id) === String(jobId) &&
    String(job.server_id) === String(server.server_id)
  );
  return { jobs, idx, job: idx >= 0 ? jobs[idx] : null };
}

/**
 * AI 진단 실행 — raw DB 64항목 전체를 AI가 판정.
 */
app.post('/diagnosis/ai-run', async (req, res) => {
  try {
    const { server_id } = req.body;
    const source = normalizeDiagnosisSource(req.body.source);
    const servers = loadMock('servers');
    const server = servers.find(s => s.server_id == server_id);
    if (!server) return res.status(404).json({ error: 'Server not found' });

    const result = await executeAiDiagnosis(server, {
      executed_by: req.session?.username || 'mock-user',
      triggered_by: 'manual',
      source,
    });
    if (result.status === 'success') return res.json(result);
    return res.status(500).json(result);
  } catch (e) {
    console.error('AI Diagnosis error:', e);
    res.status(500).json({ status: 'failed', error: e.message, stack: e.stack });
  }
});

/**
 * LLM detailed diagnosis. Script XML is treated as evidence only; the LLM
 * makes the detailed judgement from collected command output.
 */
app.post('/diagnosis/llm-run', async (req, res) => {
  try {
    const { server_id } = req.body;
    const source = normalizeDiagnosisSource(req.body.source);
    const servers = loadMock('servers');
    const server = servers.find(s => s.server_id == server_id);
    if (!server) return res.status(404).json({ error: 'Server not found' });

    const result = await executeLlmDiagnosis(server, {
      executed_by: req.session?.username || 'mock-user',
      triggered_by: 'manual',
      source,
      filter: req.body.filter || 'all',
      baseAssessmentId: req.body.base_assessment_id ? Number(req.body.base_assessment_id) : undefined,
    });
    if (result.status === 'success') return res.json(result);
    return res.status(500).json(result);
  } catch (e) {
    console.error('LLM Diagnosis error:', e);
    res.status(500).json({ status: 'failed', error: e.message, stack: e.stack });
  }
});

/**
 * 원격 수집 + AI 진단 — fetcher 로 raw DB 가져오고 AI 진단 자동 실행.
 * 단일 서버 처리 (서버 관리/진단 관리 화면에서 호출).
 *
 * 서버 정보 우선순위:
 *   1. servers.json 에서 server_id 일치하는 행
 *   2. servers.csv 에서 ip 일치하는 행 (server_id 가 ip 인 경우)
 */
app.post('/diagnosis/fetch-and-run', async (req, res) => {
  try {
    const { server_id } = req.body;
    const source = normalizeDiagnosisSource(req.body.source);
    
    // 1) servers.json 에서 찾기
    const servers = loadMock('servers') || [];
    let server = servers.find(s => s.server_id == server_id);
    
    // 2) 없으면 servers.csv 에서 찾기 (ip 매칭)
    if (!server) {
      try {
        const { getTargetServersFromFile } = require('./src/services/scheduler');
        const csvServers = getTargetServersFromFile();
        const csvHit = csvServers.find(s => s.server_id == server_id || s.ip == server_id);
        if (csvHit) {
          server = {
            server_id: csvHit.server_id,
            name:      csvHit.hostname,
            hostname:  csvHit.hostname,
            asset_no:  csvHit.asset_no,
            ip:        csvHit.ip,
            username:  csvHit.username,
            password:  csvHit.password,
            os:        csvHit.os,
          };
        }
      } catch (e) {
        console.warn('[웹] servers.csv 로드 실패:', e.message);
      }
    }
    
    if (!server) {
      return res.status(404).json({
        status: 'failed',
        error: `server_id=${server_id} 를 찾을 수 없습니다 (servers.json, servers.csv 모두 확인)`,
      });
    }

    // scheduler.js 의 runScheduledDiagnosis 재사용
    const { runScheduledDiagnosis } = require('./src/services/scheduler');
    
    // servers.json 형식(ip_address/ssh_user/os_type)을 scheduler 형식(ip/username/os)으로 변환
    const target = {
      server_id: server.server_id,
      name:      server.name,
      hostname:  server.hostname,
      asset_no:  server.asset_no,
      ip:        server.ip       || server.ip_address || server.host,
      username:  server.username || server.ssh_user   || server.user,
      password:  server.password || server.ssh_password,
      os:        server.os       || server.os_type    || 'linux',
    };
    
    if (!target.ip || !target.username || !target.password || !target.os) {
      const missing = [];
      if (!target.ip)       missing.push('ip(또는 ip_address)');
      if (!target.username) missing.push('username(또는 ssh_user)');
      if (!target.password) missing.push('password');
      if (!target.os)       missing.push('os(또는 os_type)');
      return res.status(400).json({
        status: 'failed',
        error: `필수 fetcher 정보가 없습니다: ${missing.join(', ')}`,
        hint: `servers.json 또는 servers.csv 에 해당 필드를 추가하세요`,
      });
    }
    
    console.log(`[웹] [${target.hostname}] ${source} 수집 + 진단 실행 요청 (by ${req.session?.username || '?'})`);
    const result = await runScheduledDiagnosis(target, { source });
    
    res.json({
      status: result.diagnose_status === 'success' ? 'success' : 'failed',
      hostname: result.hostname,
      requested_source: result.requested_source,
      source_type: result.source_type,
      fetch_status: result.fetch_status,
      fetch_error:  result.fetch_error,
      diagnose_status: result.diagnose_status,
      diagnose_error:  result.diagnose_error,
      assessment_id: result.assessment_id,
      summary: result.summary,
      elapsed_ms: result.elapsed_ms,
    });
  } catch (e) {
    console.error('[웹] 수집+진단 오류:', e);
    res.status(500).json({ status: 'failed', error: e.message, stack: e.stack });
  }
});

/**
 * 자동 수집 이력 조회 (스케줄러 실행 로그).
 * data/mock/scheduler_runs.json 에서 최근 N건 반환.
 */
app.get('/scheduler/history', (req, res) => {
  // 호환성을 위해 /collection/history 로 리다이렉트
  res.redirect('/collection/history');
});

/**
 * [수집 관리] - servers.csv 등록 서버 + 실행 버튼
 */
app.get('/collection', (req, res) => {
  try {
    let csvServers = [];
    try {
      const { getTargetServersFromFile } = require('./src/services/scheduler');
      csvServers = getTargetServersFromFile().map(s => ({
        server_id: s.server_id || s.ip,
        hostname: s.hostname, ip: s.ip, os: s.os,
        username: s.username, asset_no: s.asset_no,
      }));
    } catch (_) {}

    res.render('collection/index', {
      activeMenu: 'collection',
      csvServers,
      scriptDeployJobs: loadScriptDeployJobs().slice(0, 20),
    });
  } catch (e) {
    res.status(500).send('수집 관리 화면 오류: ' + e.message);
  }
});

/**
 * [수집 관리] Script XML 수동 업로드.
 * 저장 규칙: data/uploads/YYYY-MM-DD/hostname_script_YYYYMMDD.xml
 */
app.post('/collection/script-upload', collectUpload.single('scriptfile'), async (req, res) => {
  const startedAt = new Date();
  const runRecord = {
    started_at: startedAt.toISOString().slice(0, 19).replace('T', ' '),
    source_type: 'script',
    fetch_status: 'success',
    diagnose_status: 'skipped',
  };

  try {
    const scriptFile = req.file;
    if (!scriptFile) {
      return res.status(400).json({ status: 'failed', error: 'scriptfile XML 파일이 필요합니다' });
    }
    if (scriptFile.size < 20) {
      return res.status(400).json({ status: 'failed', error: 'Script XML 파일이 너무 작습니다.' });
    }

    const hostname = req.body.hostname || '';
    const server = findServerForUpload(req.body.server_id, hostname);
    if (!server) {
      return res.status(404).json({ status: 'failed', error: '서버를 찾을 수 없습니다. hostname을 입력해 주세요.' });
    }

    const engine = normalizeDiagnosisEngine(req.body.engine);
    const runImmediately = req.body.run_immediately === 'on' || req.body.run_immediately === 'true';

    Object.assign(runRecord, {
      hostname: server.hostname || hostname,
      ip: server.ip || server.ip_address || '',
      os: server.os || server.os_type || '',
      script_file: scriptFile.filename,
      script_path: path.relative(ROOT, scriptFile.path),
      file_size: scriptFile.size,
    });

    let diagnosisResult = null;
    if (runImmediately) {
      const runDiagnosis = getDiagnosisRunner(engine);
      diagnosisResult = await runDiagnosis(server, {
        executed_by: req.session?.username || 'collection-user',
        triggered_by: 'collection-script-upload',
        source: 'script',
        scriptPath: scriptFile.path,
        script_file: scriptFile.filename,
      });

      runRecord.diagnose_status = diagnosisResult.status === 'success' ? 'success' : 'failed';
      runRecord.assessment_id = diagnosisResult.assessment_id || null;
      runRecord.summary = diagnosisResult.summary || null;
      runRecord.diagnose_error = diagnosisResult.error || null;
    }

    runRecord.elapsed_ms = Date.now() - startedAt.getTime();
    const history = kvStorage.loadSync('scheduler_runs') || [];
    history.unshift(runRecord);
    kvStorage.saveSync('scheduler_runs', history);

    if (diagnosisResult && diagnosisResult.status !== 'success') {
      return res.status(500).json({
        status: 'failed',
        error: diagnosisResult.error || `${engine.toUpperCase()} Script 진단 실패`,
        saved_path: path.relative(ROOT, scriptFile.path),
      });
    }

    res.json({
      status: 'success',
      source_type: 'script',
      diagnose_type: runImmediately ? engine : null,
      assessment_id: diagnosisResult?.assessment_id || null,
      summary: diagnosisResult?.summary || null,
      elapsed_ms: diagnosisResult?.elapsed_ms || runRecord.elapsed_ms,
      uploaded_file: scriptFile.originalname,
      saved_file: scriptFile.filename,
      saved_path: path.relative(ROOT, scriptFile.path),
      message: runImmediately
        ? (diagnosisResult?.message || 'Script XML 업로드 및 진단 완료')
        : 'Script XML 업로드 완료',
    });
  } catch (e) {
    console.error('[Script 업로드 오류]', e);
    runRecord.fetch_status = runRecord.fetch_status || 'failed';
    runRecord.diagnose_status = 'failed';
    runRecord.diagnose_error = e.message;
    runRecord.elapsed_ms = Date.now() - startedAt.getTime();
    try {
      const history = kvStorage.loadSync('scheduler_runs') || [];
      history.unshift(runRecord);
      kvStorage.saveSync('scheduler_runs', history);
    } catch (_) {}
    res.status(500).json({
      status: 'failed',
      error: e.message,
      stack: process.env.NODE_ENV === 'production' ? undefined : e.stack,
    });
  }
});

/**
 * [수집 관리] Script 배포 작업 등록.
 *
 * 대상 서버의 Agent push 스크립트가 /api/script-job 을 확인하고,
 * 작업을 내려받아 실행한 뒤 결과 XML을 /api/script-job/:id/result 로 업로드한다.
 */
app.post('/collection/script-deploy', scriptDeployUpload.single('deploy_script'), async (req, res) => {
  try {
    const startedAt = Date.now();
    const deployFile = req.file;
    if (!deployFile) {
      return res.status(400).json({ status: 'failed', error: 'deploy_script 파일이 필요합니다' });
    }

    const hostname = req.body.hostname || '';
    const server = findServerForUpload(req.body.server_id, hostname);
    if (!server) {
      return res.status(404).json({ status: 'failed', error: '서버를 찾을 수 없습니다. hostname을 입력해 주세요.' });
    }
    const deployTarget = withScriptDeployAuthOverrides(server, req.body);

    const engine = normalizeDiagnosisEngine(req.body.engine);
    const scriptAction = normalizeScriptDeployAction(req.body.script_action, req.body.run_immediately);
    const deployOnly = scriptAction === 'deploy_only';
    const runImmediately = scriptAction === 'deploy_run_diagnose';
    const resultGlob = String(req.body.result_glob || '*.xml').trim() || '*.xml';
    const requestedScriptArgs = String(req.body.script_args || '').trim();
    const remoteWorkDir = String(req.body.remote_work_dir || '').trim();
    const defaultScriptArgs = /\.ps1$/i.test(deployFile.originalname || '') && /fsi_win_ai/i.test(deployFile.originalname || '')
      ? '-Fast'
      : '';
    const scriptArgs = requestedScriptArgs || defaultScriptArgs;
    const packageScript = String(req.body.package_script || '').trim();
    const now = new Date();
    const job = {
      job_id: makeScriptDeployJobId(),
      status: 'queued',
      server_id: String(deployTarget.server_id || req.body.server_id || hostname),
      hostname: deployTarget.hostname || hostname,
      ip: deployTarget.ip || deployTarget.ip_address || '',
      os: deployTarget.os || deployTarget.os_type || '',
      engine,
      script_action: scriptAction,
      run_immediately: runImmediately,
      result_glob: resultGlob,
      script_args: scriptArgs,
      remote_work_dir: remoteWorkDir,
      package_script: packageScript,
      original_name: deployFile.originalname,
      script_file: deployFile.filename,
      script_path: path.relative(ROOT, deployFile.path),
      file_size: deployFile.size,
      created_at: now.toISOString().slice(0, 19).replace('T', ' '),
      created_by: req.session?.username || 'collection-user',
      deploy_mode: req.body.deploy_mode === 'agent' ? 'agent' : 'direct',
      progress_percent: 5,
      progress_message: 'queued',
    };

    if (job.deploy_mode === 'direct') {
      const jobs = loadScriptDeployJobs();
      job.status = 'running';
      job.progress_percent = 10;
      job.progress_message = 'direct deployment started';
      job.started_at = job.created_at;
      jobs.unshift(job);
      saveScriptDeployJobs(jobs);

      let directResult = null;
      let diagnosisResult = null;
      try {
        directResult = await runDirectScriptDeployment(deployTarget, deployFile.path, {
          jobId: job.job_id,
          originalName: deployFile.originalname,
          packageScript,
          resultGlob,
          scriptArgs,
          remoteWorkDir,
          deployOnly,
          onProgress: async (percent, message) => {
            const updated = patchScriptDeployJob(job.job_id, {
              status: 'running',
              progress_percent: percent,
              progress_message: message,
            });
            if (updated) Object.assign(job, updated);
          },
        });

        Object.assign(job, {
          status: runImmediately ? 'diagnosing' : 'completed',
          progress_percent: runImmediately ? 85 : 100,
          progress_message: deployOnly ? 'deployed only' : (runImmediately ? 'diagnosis running' : 'completed'),
          result_file: directResult.local_result_file,
          result_path: directResult.local_result_path ? path.relative(ROOT, directResult.local_result_path) : null,
          result_size: directResult.size,
          package_mode: directResult.package_mode,
          package_script: directResult.package_script || packageScript,
          remote_dir: directResult.remote_dir,
          remote_output_dir: directResult.remote_output_dir,
          remote_result: directResult.remote_result,
          uploaded_at: new Date().toISOString().slice(0, 19).replace('T', ' '),
          exit_code: directResult.exit_code,
        });
        patchScriptDeployJob(job.job_id, {
          status: job.status,
          progress_percent: job.progress_percent,
          progress_message: job.progress_message,
          result_file: job.result_file,
          result_path: job.result_path,
          result_size: job.result_size,
          uploaded_at: job.uploaded_at,
          exit_code: job.exit_code,
        });

        if (runImmediately) {
          const runDiagnosis = getDiagnosisRunner(engine);
          diagnosisResult = await runDiagnosis(deployTarget, {
            executed_by: req.session?.username || 'node-direct-script',
            triggered_by: 'script-direct',
            source: 'script',
            scriptPath: directResult.local_result_path,
            script_file: directResult.local_result_file,
          });
          job.status = diagnosisResult.status === 'success' ? 'diagnosed' : 'diagnosis_failed';
          job.progress_percent = 100;
          job.progress_message = diagnosisResult.status === 'success' ? 'diagnosis completed' : 'diagnosis failed';
          job.assessment_id = diagnosisResult.assessment_id || null;
          job.summary = diagnosisResult.summary || null;
          job.diagnose_error = diagnosisResult.error || null;
        }

        job.completed_at = new Date().toISOString().slice(0, 19).replace('T', ' ');
        const latest = loadScriptDeployJobs();
        const idx = latest.findIndex(x => x.job_id === job.job_id);
        if (idx >= 0) latest[idx] = job;
        saveScriptDeployJobs(latest);

        appendCollectionHistory({
          started_at: job.started_at,
          finished_at: job.completed_at,
          source_type: 'script_deploy',
          hostname: job.hostname,
          ip: job.ip,
          os: job.os,
          fetch_status: 'success',
          diagnose_status: diagnosisResult ? (diagnosisResult.status === 'success' ? 'success' : 'failed') : 'skipped',
          assessment_id: diagnosisResult?.assessment_id || null,
          summary: diagnosisResult?.summary || null,
          diagnose_error: diagnosisResult?.error || null,
          script_file: directResult.local_result_file || job.script_file,
          script_path: directResult.local_result_path ? path.relative(ROOT, directResult.local_result_path) : job.script_path,
          file_size: directResult.size,
          deploy_job_id: job.job_id,
          elapsed_ms: Date.now() - startedAt,
        });

        if (diagnosisResult && diagnosisResult.status !== 'success') {
          return res.status(500).json({
            status: 'failed',
            job_id: job.job_id,
            deploy_status: job.status,
            error: diagnosisResult.error || 'Script 결과 진단 실패',
            saved_path: job.script_path,
            result_path: job.result_path,
          });
        }

        return res.json({
          status: 'success',
          job_id: job.job_id,
          deploy_status: job.status,
          assessment_id: diagnosisResult?.assessment_id || null,
          summary: diagnosisResult?.summary || null,
          saved_path: job.script_path,
          result_path: job.result_path,
          message: `Node.js SSH ${labelScriptDeployAction(scriptAction)}`,
        });
      } catch (err) {
        job.status = 'failed';
        job.progress_percent = 100;
        job.progress_message = 'failed';
        job.failed_at = new Date().toISOString().slice(0, 19).replace('T', ' ');
        job.error = err.message;
        const latest = loadScriptDeployJobs();
        const idx = latest.findIndex(x => x.job_id === job.job_id);
        if (idx >= 0) latest[idx] = job;
        saveScriptDeployJobs(latest);
        appendCollectionHistory({
          started_at: job.started_at,
          finished_at: job.failed_at,
          source_type: 'script_deploy',
          hostname: job.hostname,
          ip: job.ip,
          os: job.os,
          fetch_status: 'failed',
          fetch_error: err.message,
          diagnose_status: 'failed',
          diagnose_error: err.message,
          script_file: job.script_file,
          script_path: job.script_path,
          file_size: job.file_size,
          deploy_job_id: job.job_id,
        });
        return res.status(500).json({
          status: 'failed',
          job_id: job.job_id,
          deploy_status: job.status,
          error: err.message,
        });
      }
    }

    const jobs = loadScriptDeployJobs();
    jobs.unshift(job);
    saveScriptDeployJobs(jobs);

    appendCollectionHistory({
      started_at: job.created_at,
      source_type: 'script_deploy',
      hostname: job.hostname,
      ip: job.ip,
      os: job.os,
      fetch_status: 'queued',
      diagnose_status: runImmediately ? 'waiting_agent' : 'skipped',
      script_file: job.script_file,
      script_path: job.script_path,
      file_size: job.file_size,
      deploy_job_id: job.job_id,
    });

    res.json({
      status: 'success',
      job_id: job.job_id,
      deploy_status: job.status,
      saved_path: job.script_path,
      message: `${labelScriptDeployAction(scriptAction)} 작업이 등록되었습니다. 대상 Agent push 스크립트가 실행되면 처리합니다.`,
    });
  } catch (e) {
    console.error('[Script 배포 등록 오류]', e);
    res.status(500).json({
      status: 'failed',
      error: e.message,
      stack: process.env.NODE_ENV === 'production' ? undefined : e.stack,
    });
  }
});

app.get('/collection/script-deploy/:jobId/status', (req, res) => {
  const jobs = loadScriptDeployJobs();
  const job = jobs.find(j => String(j.job_id) === String(req.params.jobId));
  if (!job) {
    return res.status(404).json({ status: 'failed', error: 'Script deploy job not found' });
  }
  res.json({
    status: 'success',
    job_id: job.job_id,
    job_status: job.status,
    progress_percent: clampProgressPercent(job.progress_percent ?? progressForScriptJobStatus(job.status, job.progress_message || job.agent_message)),
    progress_message: job.progress_message || job.agent_message || job.status,
    assessment_id: job.assessment_id || null,
    diagnose_error: job.diagnose_error || job.error || null,
    result_file: job.result_file || null,
    updated_at: job.updated_at || job.completed_at || job.started_at || job.created_at || null,
  });
});

/**
 * [수집 이력] - 실행 이력만
 */
app.get('/collection/history', (req, res) => {
  try {
    // kvStorage 사용 — MySQL 모드에서도 정상 조회
    let history = kvStorage.loadSync('scheduler_runs') || [];
    if (!Array.isArray(history)) history = [];
    const limit = parseInt(req.query.limit || '50', 10);

    res.render('collection/history', {
      activeMenu: 'collection',
      history: history.slice(0, limit),
      total: history.length,
    });
  } catch (e) {
    res.status(500).send('이력 조회 오류: ' + e.message);
  }
});

/**
 * CSV 의 모든 서버 일괄 [수집 + 진단] — 웹에서 npm run scheduler 와 동일 효과.
 * 실행 후 결과 요약 반환 (긴 작업이라 클라이언트는 진행 표시 필요).
 */
app.post('/scheduler/run-all', async (req, res) => {
  try {
    const { getTargetServersFromFile, runScheduledDiagnosis } = require('./src/services/scheduler');
    const source = normalizeDiagnosisSource(req.body?.source || req.query?.source);
    const targets = getTargetServersFromFile();
    
    if (targets.length === 0) {
      return res.status(400).json({
        status: 'failed',
        error: 'servers.csv 에 등록된 서버가 없습니다',
        hint: 'vuln-assessor-v9/servers.csv 파일 확인',
      });
    }
    
    console.log(`[웹] 일괄 [${source} 수집+진단] 시작 — ${targets.length}개 서버 (by ${req.session?.username || '?'})`);
    
    const results = [];
    for (const target of targets) {
      const r = await runScheduledDiagnosis(target, { source });
      results.push({
        hostname: r.hostname, ip: r.ip, os: r.os,
        requested_source: r.requested_source,
        source_type:      r.source_type,
        fetch_status:    r.fetch_status,
        diagnose_status: r.diagnose_status,
        assessment_id:   r.assessment_id,
        summary:         r.summary,
        error: r.fetch_error || r.diagnose_error,
      });
    }
    
    const summary = {
      total: results.length,
      success:      results.filter(r => r.diagnose_status === 'success').length,
      fetched_only: results.filter(r => r.fetch_status === 'success' && r.diagnose_status === 'skipped').length,
      failed:       results.filter(r => r.fetch_status === 'failed' || r.diagnose_status === 'failed').length,
    };
    
    res.json({ status: 'completed', summary, results });
  } catch (e) {
    console.error('[웹] 일괄 실행 오류:', e);
    res.status(500).json({ status: 'failed', error: e.message });
  }
});

/**
 * SQLite DB open — 3단계 폴백:
 *   1. better-sqlite3 (가장 빠름, native binding)
 *   2. sqlite3 (prebuilt binary)
 *   3. sql.js (WASM, 어디서든 동작, 가장 느림)
 */
async function openSqliteDb(dbPath) {
  // 1) better-sqlite3
  try {
    const Database = require('better-sqlite3');
    return new Database(dbPath, { readonly: true });
  } catch (e) {
    console.warn('[sqlite] better-sqlite3 unavailable, trying sqlite3...');
  }

  // 2) sqlite3 (prebuilt)
  try {
    const sqlite3 = require('sqlite3');
    const sdb = new sqlite3.Database(dbPath, sqlite3.OPEN_READONLY);
    return _wrapNodeSqlite3(sdb);
  } catch (e) {
    console.warn('[sqlite] sqlite3 unavailable, falling back to sql.js (WASM)...');
  }

  // 3) sql.js (WASM, 최종 폴백 — 어디서든 동작)
  try {
    const initSqlJs = require('sql.js');
    const SQL = await initSqlJs();
    const buf = fs.readFileSync(dbPath);
    const db = new SQL.Database(buf);
    return _wrapSqlJs(db);
  } catch (e) {
    throw new Error('SQLite 모듈 모두 사용 불가 (better-sqlite3, sqlite3, sql.js). npm install sql.js 권장');
  }
}

// node sqlite3 → better-sqlite3 호환 래퍼 (동기 인터페이스 시뮬레이션)
function _wrapNodeSqlite3(sdb) {
  // node sqlite3는 async 기반. 룰엔진이 동기 호출하므로 promisify 처리는 어댑터에서 함.
  // 여기선 better-sqlite3와 같은 동기 prepare 인터페이스를 흉내냄.
  // 실제론 SecuMS 어댑터의 querySlice가 single-shot이라 sql.js 폴백을 권장.
  return {
    prepare(sql) {
      return {
        all: (...args) => {
          // sync 동작 시뮬: deasync 없이는 어려움. 사용자는 sql.js 폴백 사용 권장.
          throw new Error('sqlite3는 동기 호출이 불가합니다. sql.js를 설치하세요: npm install sql.js');
        },
        get: () => { throw new Error('sqlite3 동기 호출 불가'); },
      };
    },
    close() { sdb.close(); },
  };
}

// sql.js → better-sqlite3 호환 래퍼 (동기 인터페이스)
function _wrapSqlJs(db) {
  return {
    prepare(sql) {
      return {
        // .all(...args) 와 .all() 양쪽 지원
        all(...args) {
          let rows;
          if (args.length === 0) {
            const result = db.exec(sql);
            if (!result.length) return [];
            const { columns, values } = result[0];
            rows = values.map(row => {
              const obj = {};
              columns.forEach((c, i) => { obj[c] = row[i]; });
              return obj;
            });
            return rows;
          }
          // 매개변수가 있는 경우 prepared statement 사용
          const stmt = db.prepare(sql);
          try {
            stmt.bind(args);
            rows = [];
            while (stmt.step()) {
              rows.push(stmt.getAsObject());
            }
            return rows;
          } finally {
            stmt.free();
          }
        },
        get(...args) {
          const rows = this.all(...args);
          return rows[0];
        },
      };
    },
    close() { db.close(); },
  };
}

// 서버 관리 + 헬스체크
app.get('/servers', (req, res) => {
  res.render('servers/index', {
    activeMenu: 'servers',
    servers: loadMock('servers') || [],
    health: { total: 7, healthy: 3, unhealthy: 4, unreachable: 2, avgRtt: 121 },
    now: new Date().toISOString().slice(0, 16).replace('T', ' '),
  });
});

// 헬스체크 실행 (실제 동작)
app.post('/servers/:id/healthcheck', async (req, res) => {
  const { id } = req.params;
  const servers = loadMock('servers');
  const server = servers.find(s => s.server_id == id);
  if (!server) return res.status(404).json({ error: 'not found' });

  // Mock 모드에서는 가짜 결과 반환
  const result = {
    ssh_status: Math.random() > 0.2 ? 'ok' : 'timeout',
    ssh_rtt: Math.round(50 + Math.random() * 200),
    agent_status: Math.random() > 0.3 ? 'running' : 'stopped',
    agent_version: '3.4.5',
    disk_usage_pct: Math.round(30 + Math.random() * 60),
    checked_at: new Date().toISOString(),
  };

  Object.assign(server, result);
  server.overall_health = result.disk_usage_pct > 90 ? 'critical'
                        : result.disk_usage_pct > 80 ? 'warning'
                        : result.ssh_status !== 'ok' ? 'critical'
                        : 'healthy';
  saveMock('servers', servers);
  res.json(result);
});
// 스케줄 관리
// ─── 예약 진단 (구 "스케줄 점검") ─────────────────────────
const cronUtil = require('./src/scheduler/cron');

/**
 * 7일 캘린더용 days 배열 생성 (오늘 기준 ±N일).
 * 각 스케줄을 cron으로 풀어 해당 일에 떨어지는 실행 시각을 표시.
 */
function buildCalendarDays(schedules, runs) {
  const days = ['일','월','화','수','목','금','토'];
  const today = new Date(); today.setHours(0,0,0,0);

  // 월요일 시작 ~ 일요일 끝
  const monday = new Date(today);
  const dayIdx = (today.getDay() + 6) % 7;  // 월=0
  monday.setDate(monday.getDate() - dayIdx);

  const result = [];
  for (let i = 0; i < 7; i++) {
    const d = new Date(monday); d.setDate(monday.getDate() + i);
    const events = [];
    for (const s of (schedules || [])) {
      if (!s.enabled || !s.cron_expr || s.cron_expr === 'manual') continue;
      try {
        // 그 날 00:00 ~ 23:59 사이 실행 시각 추출
        let cursor = new Date(d); cursor.setHours(0,0,0,0); cursor.setMinutes(-1);
        const dayEnd = new Date(d); dayEnd.setHours(23,59,59,999);
        let next = cronUtil.nextRunAfter(s.cron_expr, cursor);
        let safety = 0;
        while (next <= dayEnd && safety < 24) {
          // 과거면 last_status, 미래면 pending
          const isPast = next < new Date();
          let status = 'pending';
          if (isPast) {
            const lastRun = (runs || []).find(r => r.schedule_id === s.schedule_id);
            status = lastRun?.status === '성공' ? 'success'
                   : lastRun?.status === '실패' ? 'failed'
                   : lastRun?.status === '부분실패' ? 'failed'
                   : 'pending';
          }
          events.push({
            status,
            time: `${String(next.getHours()).padStart(2,'0')}:${String(next.getMinutes()).padStart(2,'0')}`,
            name: s.name,
            target: `${s.target_count || '?'}대`,
          });
          cursor = next;
          next = cronUtil.nextRunAfter(s.cron_expr, next);
          safety++;
        }
      } catch (_) { /* manual 등 */ }
    }
    events.sort((a, b) => a.time.localeCompare(b.time));
    result.push({
      day_name: days[d.getDay()],
      date: `${d.getMonth()+1}/${d.getDate()}`,
      is_today: d.getTime() === today.getTime(),
      events,
    });
  }
  return result;
}

app.get('/schedules', (req, res) => {
  const schedules = loadMock('schedules') || [];
  const runs = loadMock('schedule_runs') || [];

  // 다음 실행 시각 미리 계산해서 화면에 표시 (cron_expr 변경 시에도 즉시 반영)
  const now = new Date();
  const enriched = schedules.map(s => {
    let nextRun = s.next_run_at || '-';
    let cronHuman = s.cron_humanized;
    if (s.enabled && s.cron_expr && s.cron_expr !== 'manual') {
      try {
        const nxt = cronUtil.nextRunAfter(s.cron_expr, now);
        nextRun = nxt.toISOString().slice(0, 16).replace('T', ' ');
      } catch (_) { /* invalid */ }
    }
    if (!cronHuman) {
      try { cronHuman = cronUtil.humanize(s.cron_expr); } catch (_) { cronHuman = s.cron_expr; }
    }
    return { ...s, next_run_at: nextRun, cron_humanized: cronHuman };
  });

  // KPI 실데이터 계산
  const enabledRuns = runs.filter(r => {
    const t = new Date(r.started_at);
    return (now - t) < 24 * 3600 * 1000;
  });
  const successRuns = runs.filter(r => r.status === '성공').length;
  const kpi = {
    activeSchedules: schedules.filter(s => s.enabled && s.cron_expr !== 'manual').length,
    totalSchedules: schedules.length,
    todayPending: schedules.filter(s => {
      if (!s.enabled || s.cron_expr === 'manual') return false;
      try {
        const nxt = cronUtil.nextRunAfter(s.cron_expr, now);
        const todayEnd = new Date(); todayEnd.setHours(23,59,59,999);
        return nxt <= todayEnd;
      } catch (_) { return false; }
    }).length,
    nextRunAt: enriched
      .filter(s => s.enabled && s.next_run_at !== '-')
      .map(s => s.next_run_at)
      .sort()[0] || '-',
    runs24h: enabledRuns.length,
    successRate: runs.length > 0 ? Math.round(successRuns / runs.length * 100) : 0,
    notifications: (() => {
      const hist = loadMock('notifications') || [];
      const cutoff = new Date(); cutoff.setDate(cutoff.getDate() - 7);
      return hist.filter(n => new Date(n.sent_at) >= cutoff).length;
    })(),
  };

  res.render('schedules/index', {
    activeMenu: 'schedules',
    schedules: enriched,
    kpi,
    runs: runs.slice(0, 30),
    days: buildCalendarDays(enriched, runs),
  });
});

/**
 * 새 예약 등록 폼.
 */
app.get('/schedules/new', auth.requireRole('admin', 'operator'), (req, res) => {
  res.render('schedules/form', {
    activeMenu: 'schedules',
    isEdit: false,
    schedule: null,
  });
});

/**
 * 예약 편집 폼.
 */
app.get('/schedules/:id/edit', auth.requireRole('admin', 'operator'), (req, res) => {
  const schedules = loadMock('schedules') || [];
  const schedule = schedules.find(s => s.schedule_id == req.params.id);
  if (!schedule) return res.status(404).send('스케줄을 찾을 수 없습니다');
  res.render('schedules/form', {
    activeMenu: 'schedules',
    isEdit: true,
    schedule,
  });
});

/**
 * cron 표현식 미리보기 (등록 폼에서 AJAX).
 */
app.get('/schedules/preview-cron', (req, res) => {
  try {
    const expr = String(req.query.expr || '').trim();
    if (!expr || expr === 'manual') {
      return res.json({ status: 'error', error: '자동 실행 대상이 아닌 표현식입니다' });
    }
    cronUtil.parseCronExpression(expr);  // 검증
    const humanized = cronUtil.humanize(expr);
    // 다음 5회 실행 시각
    const nextRuns = [];
    let cursor = new Date();
    for (let i = 0; i < 5; i++) {
      const nxt = cronUtil.nextRunAfter(expr, cursor);
      nextRuns.push(nxt.toISOString().slice(0, 16).replace('T', ' '));
      cursor = nxt;
    }
    res.json({ status: 'success', humanized, next_runs: nextRuns });
  } catch (e) {
    res.json({ status: 'error', error: e.message });
  }
});

app.post('/schedules/save', auth.requireRole('admin', 'operator'), (req, res) => {
  try {
    const body = req.body || {};
    const cron_expr = String(body.cron_expr || '').trim();

    // cron 검증 (manual은 통과)
    if (cron_expr !== 'manual') {
      cronUtil.parseCronExpression(cron_expr);  // throw on invalid
    }

    const schedules = loadMock('schedules') || [];
    const newId = schedules.length
      ? Math.max(...schedules.map(s => s.schedule_id)) + 1
      : 1;

    const schedule = {
      schedule_id: newId,
      name: String(body.name || '').trim() || `예약 #${newId}`,
      description: body.description || '',
      cron_expr,
      cron_humanized: cron_expr === 'manual' ? '수동 실행' : cronUtil.humanize(cron_expr),
      server_scope: body.server_scope || 'all',
      server_group: body.server_group || null,
      server_ids: body.server_ids || null,
      target_count: body.target_count || ((loadMock('servers') || []).length),
      ruleset_ver: body.ruleset_ver || 'v2.0',
      enabled: body.enabled !== undefined ? !!body.enabled : true,
      notify_on_vuln: !!body.notify_on_vuln,
      notify_on_failure: !!body.notify_on_failure,
      last_run_at: null,
      last_status: null,
      created_at: new Date().toISOString().slice(0, 19).replace('T', ' '),
      created_by: req.session?.username || 'unknown',
    };

    // 다음 실행 시각 미리 계산
    if (schedule.enabled && cron_expr !== 'manual') {
      try {
        const nxt = cronUtil.nextRunAfter(cron_expr, new Date());
        schedule.next_run_at_iso = nxt.toISOString();
        schedule.next_run_at = nxt.toISOString().slice(0, 16).replace('T', ' ');
      } catch (_) { /* manual */ }
    } else {
      schedule.next_run_at = '-';
    }

    schedules.push(schedule);
    saveMock('schedules', schedules);
    res.json({ status: 'success', schedule_id: newId });
  } catch (e) {
    res.status(400).json({ status: 'error', error: e.message });
  }
});

/**
 * 예약 수정.
 * 변경 가능: name, description, cron_expr, server_scope/group, notify_*, enabled
 * 변경 불가: schedule_id, created_at, created_by, last_run_at, last_status
 */
app.post('/schedules/:id/update', auth.requireRole('admin', 'operator'), (req, res) => {
  try {
    const schedules = loadMock('schedules') || [];
    const s = schedules.find(x => x.schedule_id == req.params.id);
    if (!s) return res.status(404).json({ status: 'error', error: 'not found' });

    const body = req.body || {};
    const cron_expr = body.cron_expr !== undefined
      ? String(body.cron_expr || '').trim()
      : s.cron_expr;

    // cron 검증 (manual은 통과)
    if (cron_expr !== 'manual' && cron_expr !== s.cron_expr) {
      cronUtil.parseCronExpression(cron_expr);
    }

    if (body.name !== undefined)        s.name = String(body.name).trim() || s.name;
    if (body.description !== undefined) s.description = body.description;
    if (body.cron_expr !== undefined) {
      s.cron_expr = cron_expr;
      s.cron_humanized = cron_expr === 'manual' ? '수동 실행' : cronUtil.humanize(cron_expr);
    }
    if (body.server_scope !== undefined) s.server_scope = body.server_scope;
    if (body.server_group !== undefined) s.server_group = body.server_group || null;
    if (body.notify_on_vuln !== undefined)    s.notify_on_vuln = !!body.notify_on_vuln;
    if (body.notify_on_failure !== undefined) s.notify_on_failure = !!body.notify_on_failure;
    if (body.enabled !== undefined)     s.enabled = !!body.enabled;

    s.updated_at = new Date().toISOString().slice(0, 19).replace('T', ' ');
    s.updated_by = req.session?.username || 'unknown';

    // cron 또는 enabled 변경 시 next_run_at 재계산
    if (s.enabled && s.cron_expr && s.cron_expr !== 'manual') {
      try {
        const nxt = cronUtil.nextRunAfter(s.cron_expr, new Date());
        s.next_run_at_iso = nxt.toISOString();
        s.next_run_at = nxt.toISOString().slice(0, 16).replace('T', ' ');
      } catch (_) {}
    } else {
      s.next_run_at_iso = null;
      s.next_run_at = '-';
    }

    saveMock('schedules', schedules);
    res.json({ status: 'success', schedule_id: s.schedule_id });
  } catch (e) {
    res.status(400).json({ status: 'error', error: e.message });
  }
});

/**
 * 예약 활성/비활성 토글.
 */
app.post('/schedules/:id/toggle', auth.requireRole('admin', 'operator'), (req, res) => {
  const schedules = loadMock('schedules') || [];
  const s = schedules.find(x => x.schedule_id == req.params.id);
  if (!s) return res.status(404).json({ status: 'error', error: 'not found' });
  s.enabled = !s.enabled;
  // 활성화 시 다음 실행 시각 재계산
  if (s.enabled && s.cron_expr && s.cron_expr !== 'manual') {
    try {
      const nxt = cronUtil.nextRunAfter(s.cron_expr, new Date());
      s.next_run_at_iso = nxt.toISOString();
      s.next_run_at = nxt.toISOString().slice(0, 16).replace('T', ' ');
    } catch (_) {}
  }
  saveMock('schedules', schedules);
  res.json({ status: 'success', enabled: s.enabled });
});

/**
 * 예약 삭제.
 */
app.post('/schedules/:id/delete', auth.requireRole('admin'), (req, res) => {
  const schedules = loadMock('schedules') || [];
  const idx = schedules.findIndex(x => x.schedule_id == req.params.id);
  if (idx < 0) return res.status(404).json({ status: 'error', error: 'not found' });
  schedules.splice(idx, 1);
  saveMock('schedules', schedules);
  res.json({ status: 'success' });
});

/**
 * 예약 편집 폼.
 */
app.get('/schedules/:id/edit', auth.requireRole('admin', 'operator'), (req, res) => {
  const schedules = loadMock('schedules') || [];
  const schedule = schedules.find(x => x.schedule_id == req.params.id);
  if (!schedule) return res.status(404).send('예약을 찾을 수 없습니다');
  res.render('schedules/edit', { activeMenu: 'schedules', schedule });
});

/**
 * 예약 수정.
 */
app.post('/schedules/:id/update', auth.requireRole('admin', 'operator'), (req, res) => {
  try {
    const schedules = loadMock('schedules') || [];
    const s = schedules.find(x => x.schedule_id == req.params.id);
    if (!s) return res.status(404).json({ status: 'error', error: 'not found' });

    const body = req.body || {};
    const newCron = String(body.cron_expr || s.cron_expr || '').trim();
    if (newCron !== 'manual') {
      cronUtil.parseCronExpression(newCron);
    }

    s.name = body.name || s.name;
    s.description = body.description !== undefined ? body.description : s.description;
    s.cron_expr = newCron;
    s.cron_humanized = newCron === 'manual' ? '수동 실행' : cronUtil.humanize(newCron);
    if (body.server_scope) s.server_scope = body.server_scope;
    if (body.server_group !== undefined) s.server_group = body.server_group;
    if (body.notify_on_vuln !== undefined) s.notify_on_vuln = !!body.notify_on_vuln;
    if (body.notify_on_failure !== undefined) s.notify_on_failure = !!body.notify_on_failure;
    if (body.enabled !== undefined) s.enabled = !!body.enabled;

    // cron이 바뀌었으면 next 재계산
    if (s.enabled && newCron !== 'manual') {
      try {
        const nxt = cronUtil.nextRunAfter(newCron, new Date());
        s.next_run_at_iso = nxt.toISOString();
        s.next_run_at = nxt.toISOString().slice(0, 16).replace('T', ' ');
      } catch (_) {}
    }
    s.updated_at = new Date().toISOString().slice(0, 19).replace('T', ' ');
    s.updated_by = req.session?.username;
    saveMock('schedules', schedules);
    res.json({ status: 'success' });
  } catch (e) {
    res.status(400).json({ status: 'error', error: e.message });
  }
});

/**
 * 실행 이력 상세 페이지.
 */
app.get('/schedules/runs/:runId', (req, res) => {
  const runs = loadMock('schedule_runs') || [];
  const run = runs.find(r => r.run_id == req.params.runId);
  if (!run) return res.status(404).send('실행 이력을 찾을 수 없습니다');
  res.render('schedules/run_detail', { activeMenu: 'schedules', run });
});

/**
 * 지금 즉시 실행 (수동 트리거).
 */
app.post('/schedules/:id/run-now', auth.requireRole('admin', 'operator'), async (req, res) => {
  try {
    const schedules = loadMock('schedules') || [];
    const s = schedules.find(x => x.schedule_id == req.params.id);
    if (!s) return res.status(404).json({ status: 'error', error: 'not found' });

    const runner = require('./src/scheduler/runner');
    // runDiagnosis 함수가 startServer에서 주입된 상태여야 함 — runner.runSchedule 직접 호출
    await runner.runSchedule(s, new Date(), { triggered_by: 'manual' });
    res.json({ status: 'success', message: `"${s.name}" 실행 완료` });
  } catch (e) {
    res.status(500).json({ status: 'error', error: e.message });
  }
});

/**
 * 예약 실행 이력 상세.
 */
app.get('/schedules/runs/:run_id', (req, res) => {
  const runs = loadMock('schedule_runs') || [];
  const run = runs.find(r => r.run_id == req.params.run_id);
  if (!run) return res.status(404).send('실행 이력을 찾을 수 없습니다');

  // 해당 스케줄 정보 (이름 등)
  const schedules = loadMock('schedules') || [];
  const schedule = schedules.find(s => s.schedule_id === run.schedule_id);

  res.render('schedules/run_detail', {
    activeMenu: 'schedules',
    run,
    schedule,
  });
});

// ─── 알림 관리 ──────────────────────────────────────────
app.get('/notifications', (req, res) => {
  const notifications = loadMock('notifications') || [];
  const now = new Date();
  const cutoff7d = new Date(); cutoff7d.setDate(cutoff7d.getDate() - 7);
  const cutoff24h = new Date(); cutoff24h.setDate(cutoff24h.getDate() - 1);

  // notifier 모듈의 적재 구조: { results: [{channel, ok, ...}, ...] }
  // failures = results 배열에 ok=false가 하나라도 있는 알림
  const failuresCount = notifications.filter(n =>
    Array.isArray(n.results) && n.results.some(r => r && r.ok === false)
  ).length;

  const kpi = {
    total: notifications.length,
    last7d: notifications.filter(n => new Date(n.sent_at) >= cutoff7d).length,
    last24h: notifications.filter(n => new Date(n.sent_at) >= cutoff24h).length,
    failures: failuresCount,
    by_severity: notifications.reduce((acc, n) => {
      acc[n.severity] = (acc[n.severity] || 0) + 1;
      return acc;
    }, {}),
  };

  // 현재 알림 채널 (notifier 모듈에서 가져옴)
  let channels = ['console'];
  try {
    // configure 후의 상태를 직접 알 수 없으므로 환경변수에서 추론
    if (process.env.NOTIFIER_CHANNELS) {
      channels = process.env.NOTIFIER_CHANNELS.split(',').map(s => s.trim()).filter(Boolean);
    }
  } catch (_) {}

  res.render('notifications/index', {
    activeMenu: 'notifications',
    notifications: notifications.slice(0, 100),
    kpi,
    channel: channels.join(', '),
    config: {
      slack_configured: !!process.env.SLACK_WEBHOOK_URL,
      smtp_configured:  !!process.env.SMTP_HOST,
      webhook_configured: false,  // notifier 모듈은 webhook 미지원
    },
  });
});

/**
 * 알림 테스트 발송 (현재 채널 설정으로 즉시 전송 시도).
 */
app.post('/notifications/test', auth.requireRole('admin', 'operator'), async (req, res) => {
  try {
    const notifier = require('./src/notifier');
    const results = await notifier.notify({
      event: 'test',
      severity: req.body.severity || 'info',
      title: req.body.title || '테스트 알림',
      body: req.body.body || req.body.message || `${req.session?.username || '사용자'}가 발송한 테스트 알림입니다.`,
      details: { triggered_by: req.session?.username, timestamp: new Date().toISOString() },
    });
    res.json({ status: 'success', results });
  } catch (e) {
    res.status(500).json({ status: 'error', error: e.message });
  }
});

// ─── CVE Sync 관리 ──────────────────────────────────────
app.get('/cve-sync', (req, res) => {
  try {
    const enrichment = require('./src/cve/enrichment');
    const stats = enrichment.getEnrichmentStats();
    const history = enrichment.getSyncHistory();
    const untrackedKev = enrichment.getUntrackedKevCves();

    res.render('cve-sync/index', {
      activeMenu: 'cve-sync',
      stats,
      history: (history || []).slice(0, 30),
      untrackedKev: untrackedKev || [],
    });
  } catch (e) {
    console.error('[cve-sync 오류]', e);
    res.status(500).send('CVE Sync 페이지 오류: ' + e.message);
  }
});

/**
 * CVE 동기화 실행 (관리자만).
 * 폐쇄망 운영: NVD 피드 파일 업로드 받아서 처리.
 *
 * Form-data:
 *   - feed_file (선택): NVD JSON 또는 .json.gz 피드
 *   - kev_only=true   (선택): KEV 채널만 사용 (NVD 무시)
 *   - dry_run=true    (선택): 실제 저장 안 함
 *
 * feed_file 없이 호출 시: 인터넷 환경이면 NVD 라이브 다운로드, 폐쇄망에선 실패.
 */
app.post('/cve-sync/run', auth.requireRole('admin'), uploadCveFeed.single('feed_file'), async (req, res) => {
  try {
    const sync = require('./scripts/sync-cve');
    const opts = {
      kevOnly: req.body.kev_only === 'true' || req.body.kev_only === 'on',
      dryRun:  req.body.dry_run === 'true'  || req.body.dry_run  === 'on',
      fromFile: req.file ? req.file.path : undefined,
    };

    // 동기화 실행 (로그는 콘솔로 직접 출력됨)
    await sync.run(opts);

    // 매처 캐시 무효화 — 다음 진단부터 갱신된 CVE DB 반영
    try {
      const matcher = require('./src/cve/matcher');
      if (matcher.invalidateCveCache) matcher.invalidateCveCache();
    } catch (_) {}

    // 결과 통계 (sync 직후 enrichment 다시 로드)
    const enrichment = require('./src/cve/enrichment');
    enrichment.invalidateCache && enrichment.invalidateCache();
    const stats = enrichment.getEnrichmentStats();
    const recent = (enrichment.getSyncHistory() || [])[0];

    res.json({
      status: 'success',
      message: opts.dryRun ? 'dry-run 완료 (저장 안 함)' : '동기화 완료',
      stats,
      latest: recent,
    });
  } catch (e) {
    console.error('[cve-sync/run 오류]', e);
    res.status(500).json({ status: 'error', error: e.message });
  }
});

// ─── 업로드 화면 ──────────────────────────────────────────
app.get('/diagnosis/upload', (req, res) => {
  res.render('diagnosis/upload', {
    activeMenu: 'diagnosis',
    servers: loadMock('servers') || [],
  });
});

// ─── 업로드 + 자동 진단 ──────────────────────────────────
app.post('/diagnosis/upload', collectUpload.fields([
  { name: 'dbfile', maxCount: 1 },
  { name: 'scriptfile', maxCount: 1 },
  { name: 'script_file', maxCount: 1 },
]), async (req, res) => {
  try {
    const rawFile = req.files?.dbfile?.[0] || null;
    const scriptFile = req.files?.scriptfile?.[0] || req.files?.script_file?.[0] || null;
    if (!rawFile && !scriptFile) {
      return res.status(400).json({ status: 'failed', error: 'Raw DB 또는 Script XML 파일이 필요합니다' });
    }

    const { server_id, run_immediately } = req.body;
    const requestedSource = normalizeDiagnosisSource(req.body.source);
    const engine = normalizeDiagnosisEngine(req.body.engine);
    const servers = loadMock('servers');
    const server = servers.find(s => s.server_id == server_id);
    if (!server) {
      return res.status(404).json({ status: 'failed', error: `server_id ${server_id} not found` });
    }

    if (rawFile) console.log(`[업로드] Raw DB: ${rawFile.originalname} → ${rawFile.path}`);
    if (scriptFile) console.log(`[업로드] Script XML: ${scriptFile.originalname} → ${scriptFile.path}`);
    console.log(`[업로드] 서버: ${server.name} (${server.hostname})`);

    const stats = {};
    if (rawFile) {
      try { stats.raw = fs.statSync(rawFile.path); } catch (e) {
        return res.status(500).json({ status: 'failed', error: 'Raw DB 파일 접근 실패: ' + e.message });
      }
      if (stats.raw.size < 100) {
        return res.status(400).json({ status: 'failed', error: 'Raw DB 파일이 너무 작습니다. SQLite 파일이 아닐 수 있습니다.' });
      }
    }
    if (scriptFile) {
      try { stats.script = fs.statSync(scriptFile.path); } catch (e) {
        return res.status(500).json({ status: 'failed', error: 'Script XML 파일 접근 실패: ' + e.message });
      }
      if (stats.script.size < 20) {
        return res.status(400).json({ status: 'failed', error: 'Script XML 파일이 너무 작습니다.' });
      }
    }

    const availableSource = rawFile && scriptFile ? 'both' : (scriptFile ? 'script' : 'secums');
    const source = requestedSource === 'both'
      ? availableSource
      : (requestedSource === 'script' && scriptFile ? 'script'
        : (requestedSource === 'secums' && rawFile ? 'secums' : availableSource));

    if (run_immediately !== 'on' && !run_immediately) {
      return res.json({
        status: 'success',
        uploaded_files: {
          raw: rawFile?.originalname || null,
          script: scriptFile?.originalname || null,
        },
        saved_paths: {
          raw: rawFile?.path || null,
          script: scriptFile?.path || null,
        },
        source_type: source,
        engine,
        size: (stats.raw?.size || 0) + (stats.script?.size || 0),
        message: '업로드만 완료 (진단은 별도 실행 필요)',
      });
    }

    const runDiagnosis = getDiagnosisRunner(engine);
    const result = await runDiagnosis(server, {
      executed_by: req.session?.username || 'upload-user',
      triggered_by: 'upload',
      source,
      raw_file: rawFile?.filename,
      script_file: scriptFile?.filename,
    });

    if (result.status !== 'success') {
      return res.status(500).json({
        status: 'failed',
        error: result.error || `${engine.toUpperCase()} 진단 실패`,
      });
    }

    res.json({
      status: 'success',
      uploaded_files: {
        raw: rawFile?.originalname || null,
        script: scriptFile?.originalname || null,
      },
      saved_paths: {
        raw: rawFile ? path.relative(ROOT, rawFile.path) : null,
        script: scriptFile ? path.relative(ROOT, scriptFile.path) : null,
      },
      source_type: source,
      diagnose_type: engine,
      size: (stats.raw?.size || 0) + (stats.script?.size || 0),
      assessment_id: result.assessment_id,
      summary: result.summary,
      elapsed_ms: result.elapsed_ms,
      message: result.message,
    });
  } catch (e) {
    console.error('[업로드 오류]', e);
    res.status(500).json({
      status: 'failed',
      error: e.message,
      stack: process.env.NODE_ENV === 'production' ? undefined : e.stack,
    });
  }
});

// ─── 리포트 화면 (리포트1/리포트2) ────────────────────
// 헬퍼: AI 진단인지 확인
// ─── 예외 관리 ──────────────────────────────────────────
app.get('/exceptions', (req, res) => {
  const exceptions = loadMock('exceptions') || [];
  const today = new Date().toISOString().slice(0, 10);
  const enriched = exceptions.map(e => ({
    ...e,
    is_expired: e.effective_until && e.effective_until < today,
    days_left: e.effective_until
      ? Math.round((new Date(e.effective_until) - new Date(today)) / 86400000)
      : null,
  }));
  res.render('exceptions/index', {
    activeMenu: 'exceptions',
    exceptions: enriched,
    kpi: {
      total: exceptions.length,
      active: enriched.filter(e => e.enabled && e.approval_status === '승인' && !e.is_expired).length,
      pending: exceptions.filter(e => e.approval_status === '대기').length,
      expiring: enriched.filter(e => e.days_left !== null && e.days_left >= 0 && e.days_left <= 30).length,
      expired: enriched.filter(e => e.is_expired).length,
    },
  });
});

// 예외 신청 화면
app.get('/exceptions/new', (req, res) => {
  const { result_id, rule_id, server_id } = req.query;
  res.render('exceptions/new', {
    activeMenu: 'exceptions',
    prefill: { result_id, rule_id, server_id },
    servers: loadMock('servers') || [],
  });
});

// 예외 등록
app.post('/exceptions/save', (req, res) => {
  const exceptions = loadMock('exceptions') || [];
  const newId = exceptions.length ? Math.max(...exceptions.map(e => e.exception_id)) + 1 : 1001;
  const exception = {
    exception_id: newId,
    ...req.body,
    requested_by: req.body.requested_by || (req.session ? req.session.username : 'operator1'),
    requested_at: new Date().toISOString().slice(0, 19).replace('T', ' '),
    approval_status: req.body.approval_status || '대기',
    enabled: 1,
    created_at: new Date().toISOString().slice(0, 19).replace('T', ' '),
  };
  exceptions.unshift(exception);
  saveMock('exceptions', exceptions);
  res.json({ status: 'success', exception_id: newId });
});

// 예외 승인/반려
app.post('/exceptions/:id/approve', (req, res) => {
  const exceptions = loadMock('exceptions') || [];
  const e = exceptions.find(x => x.exception_id == req.params.id);
  if (!e) return res.status(404).json({ error: 'not found' });
  e.approval_status = req.body.action === 'approve' ? '승인' : '반려';
  e.approved_by = req.body.approver || (req.session ? req.session.username : 'CISO');
  e.approved_at = new Date().toISOString().slice(0, 19).replace('T', ' ');
  e.approval_note = req.body.note;
  saveMock('exceptions', exceptions);
  res.json({ status: 'success' });
});

/**
 * 예외 유효기간 연장.
 * 만료 임박 또는 만료된 예외를 새 기간으로 갱신.
 */
app.post('/exceptions/:id/extend', auth.requireRole('admin', 'operator'), (req, res) => {
  try {
    const { effective_until } = req.body;
    if (!effective_until || !/^\d{4}-\d{2}-\d{2}$/.test(effective_until)) {
      return res.status(400).json({ status: 'error', error: '유효한 날짜를 입력하세요 (YYYY-MM-DD)' });
    }
    const exceptions = loadMock('exceptions') || [];
    const e = exceptions.find(x => x.exception_id == req.params.id);
    if (!e) return res.status(404).json({ status: 'error', error: '예외를 찾을 수 없습니다' });
    
    const oldUntil = e.effective_until;
    e.effective_until = effective_until;
    e.extended_by = req.session.username;
    e.extended_at = new Date().toISOString().slice(0, 19).replace('T', ' ');
    e.extension_history = e.extension_history || [];
    e.extension_history.push({
      from: oldUntil,
      to: effective_until,
      by: req.session.username,
      at: e.extended_at,
    });
    
    saveMock('exceptions', exceptions);
    res.json({ status: 'success', exception: e });
  } catch (err) {
    res.status(500).json({ status: 'error', error: err.message });
  }
});

// ─── 제외 관리 ──────────────────────────────────────────
app.get('/exclusions', (req, res) => {
  const exclusions = loadMock('exclusions') || [];
  res.render('exclusions/index', {
    activeMenu: 'exclusions',
    exclusions,
    kpi: {
      total: exclusions.length,
      active: exclusions.filter(e => e.enabled).length,
      by_target_type: exclusions.reduce((acc, e) => {
        const k = e.target_type || 'unknown';
        acc[k] = (acc[k] || 0) + 1;
        return acc;
      }, {}),
    },
  });
});

app.get('/exclusions/new', (req, res) => {
  const { rule_id, server_id } = req.query;
  res.render('exclusions/new', {
    activeMenu: 'exclusions',
    prefill: { rule_id, server_id },
    servers: loadMock('servers') || [],
  });
});

app.post('/exclusions/save', (req, res) => {
  const exclusions = loadMock('exclusions') || [];
  const newId = exclusions.length ? Math.max(...exclusions.map(e => e.exclusion_id)) + 1 : 2001;
  const exclusion = {
    exclusion_id: newId,
    ...req.body,
    registered_by: req.body.registered_by || 'operator1',
    registered_at: new Date().toISOString().slice(0, 19).replace('T', ' '),
    enabled: 1,
    created_at: new Date().toISOString().slice(0, 19).replace('T', ' '),
  };
  exclusions.unshift(exclusion);
  saveMock('exclusions', exclusions);
  res.json({ status: 'success', exclusion_id: newId });
});

app.post('/exclusions/:id/toggle', (req, res) => {
  const exclusions = loadMock('exclusions') || [];
  const e = exclusions.find(x => x.exclusion_id == req.params.id);
  if (!e) return res.status(404).json({ error: 'not found' });
  e.enabled = e.enabled ? 0 : 1;
  saveMock('exclusions', exclusions);
  res.json({ status: 'success', enabled: e.enabled });
});

// ─── 정합성 검증 ──────────────────────────────────────────
/**
 * KISA U-XX 룰 ID → SecuMS CHK_ID 매핑.
 *
 * 매핑 근거: SecuMS raw DB의 BAD 항목 MSG 분석 + 점검 영역 비교.
 * 일부 KISA 항목은 SecuMS에 대응 항목이 없거나 다른 방식으로 분할되어 있음.
 *
 * 매핑 상태:
 *   ✓ 검증됨: raw DB MSG로 점검 대상이 일치함을 확인
 *   ? 추정: 점검 영역이 같지만 raw DB에 BAD가 없어 직접 검증 불가
 *   - 없음: SecuMS에 대응 항목이 없거나 KISA 30 외 영역
 */
const RULE_TO_SECUMS_MAPPING = {
  'U-01': ['os-linux-383'],    // ✓ root 원격 접속 (PermitRootLogin)
  'U-02': ['os-linux-378'],    // ? 패스워드 복잡성 (pam_pwquality)
  'U-03': ['os-linux-381'],    // ? 계정 잠금 임계값 (pam_tally2 / faillock)
  'U-04': ['os-linux-377'],    // ✓ PASS_MAX_DAYS 등 login.defs
  'U-05': ['os-linux-379'],    // ? 패스워드 파일 보호 (빈 패스워드)
  'U-06': ['os-linux-25'],     // ? 파일/디렉터리 소유자
  'U-07': ['os-linux-61'],     // ? /etc/passwd 권한
  'U-08': ['os-linux-84'],     // ? /etc/shadow 권한
  'U-09': ['os-linux-188'],    // ? /etc/hosts 권한
  'U-10': ['os-linux-207'],    // ? /etc/(x)inetd.conf 권한
  'U-11': ['os-linux-227'],    // ? /etc/(r)syslog.conf 권한
  'U-12': ['os-linux-237'],    // ? /etc/services 권한
  'U-13': ['os-linux-273'],    // ✓ SUID/SGID/Sticky bit
  'U-14': ['os-linux-1998'],   // ✓ 사용자 시작/환경 파일 권한
  'U-15': ['os-linux-285'],    // ? world writable
  'U-16': ['os-linux-286'],    // ? .rhosts, hosts.equiv
  'U-17': ['os-linux-254'],    // ✓ TCP Wrappers
  'U-18': ['os-linux-289'],    // ? finger
  'U-19': ['os-linux-2389'],   // ✓ Anonymous FTP
  'U-20': ['os-linux-293'],    // ? r 계열 서비스
  'U-21': ['os-linux-34'],     // ✓ cron 파일 권한
  'U-22': ['os-linux-306'],    // ? DoS 취약 서비스
  'U-23': ['os-linux-320'],    // ? NFS
  'U-24': ['os-linux-324'],    // ? NFS 접근 통제
  'U-25': ['os-linux-337'],    // ? automountd
  'U-26': ['os-linux-338'],    // ? RPC
  'U-27': ['os-linux-341'],    // ? NIS/NIS+
  'U-28': ['os-linux-342'],    // ? tftp, talk
  'U-29': ['os-linux-361'],    // ? Sendmail 버전
  'U-30': ['os-linux-335'],    // ✓ 스팸 메일 릴레이 (postfix disable_vrfy)
};

// 검증된 매핑 (raw DB MSG로 확인됨)
const VERIFIED_MAPPINGS = new Set([
  'U-01', 'U-04', 'U-13', 'U-14', 'U-17', 'U-19', 'U-21', 'U-30',
]);
// ─── CVE 자동 진단 ──────────────────────────────────────────
app.get('/diagnosis/:id/cve', async (req, res) => {
  try {
    const id = req.params.id;
    const diagnoses = loadMock('diagnoses') || [];
    const diag = diagnoses.find(d => d.assessment_id == id);
    if (!diag) return res.status(404).send('진단 결과를 찾을 수 없습니다');

    // raw DB 경로 추출
    // 1) 진단 시 업로드된 파일이 있으면 그것 사용
    // 2) 없으면 data/uploads/exportData-SSUnix.db (기본 샘플) 사용
    const rawPath = diag.raw_file
      ? path.join(UPLOAD_DIR, diag.raw_file)
      : path.join(ROOT, 'data/uploads/exportData-SSUnix.db');
    const realPath = fs.existsSync(rawPath)
      ? rawPath
      : path.join(ROOT, 'data/uploads/exportData-SSUnix.db');

    const cveScanner = require('./src/cve/scanner');
    const enrichment = require('./src/cve/enrichment');
    const servers = loadMock('servers') || [];
    const server = servers.find(s => s.server_id == diag.server_id) || {};

    const result = await cveScanner.runCveScan(realPath, {
      hostname: diag.hostname || server.hostname,
      os_distro: 'CentOS',
      os_version: diag.os || server.os_version || 'CentOS 7.5',
    });

    // 보강 정보 추가 (화면 배너용)
    const enrichStats = enrichment.getEnrichmentStats();
    const lastSync = enrichment.getSyncHistory(1)[0] || null;
    const untrackedKev = enrichment.getUntrackedKevCves(10);

    res.render('cve/scan', {
      activeMenu: 'diagnosis',
      assessment_id: id,
      diag,
      result,
      enrichment: {
        stats: enrichStats,
        last_sync: lastSync,
        untracked_kev: untrackedKev,
      },
    });
  } catch (e) {
    console.error('[CVE 오류]', e);
    res.status(500).send('CVE 진단 오류: ' + e.message);
  }
});

/**
 * AI 진단 결과 화면.
 * 64개 SecuMS 항목에 대한 AI 판정 + SecuMS 정합성 표시.
 */
app.get('/diagnosis/:id/ai', (req, res) => {
  try {
    const id = req.params.id;
    const diagnoses = loadMock('diagnoses') || [];
    const diag = diagnoses.find(d => d.assessment_id == id);
    if (!diag) return res.status(404).send('진단 결과를 찾을 수 없습니다');
    if (diag.diagnose_type !== 'ai' && diag.diagnose_type !== 'llm') {
      return res.status(400).send(
        `이 진단은 AI/LLM 진단이 아닙니다 (type=${diag.diagnose_type || 'rule'}). ` +
        `<a href="/diagnosis">진단 관리</a>로 돌아가서 진단을 재실행하세요.`
      );
    }

    const baseAiDiag = diag.diagnose_type === 'llm' && diag.base_assessment_id
      ? diagnoses.find(d => d.assessment_id == diag.base_assessment_id) || null
      : null;
    const relatedLlmDiags = diag.diagnose_type === 'ai'
      ? diagnoses
          .filter(d => d.diagnose_type === 'llm' && d.base_assessment_id == diag.assessment_id)
          .map(d => ({
            assessment_id: d.assessment_id,
            total_count: d.total_count,
            vuln_count: d.vuln_count,
            safe_count: d.safe_count,
            info_count: d.info_count,
            na_count: d.na_count,
            filter: d.filter || 'all',
            executed_at: d.executed_at,
          }))
      : [];
    const resultScope = diag.diagnose_type === 'llm'
      ? {
          mode: 'llm_detail',
          label: 'LLM 상세 결과',
          description: baseAiDiag
            ? `AI 전체 ${baseAiDiag.total_count || 0}개 중 LLM 상세 검토 대상 ${diag.total_count || 0}개를 표시합니다.`
            : `LLM 상세 검토 대상 ${diag.total_count || 0}개를 표시합니다.`,
        }
      : {
          mode: 'ai_full',
          label: 'AI 전체 결과',
          description: `AI가 수집 원자료에서 추출한 전체 ${diag.total_count || 0}개 항목을 표시합니다.`,
        };

    // 카테고리별/심각도별 그룹
    const byCategory = {};
    const bySeverity = { 상: 0, 중: 0, 하: 0 };
    for (const r of (diag.results || [])) {
      const cat = r.ai_category || '미분류';
      if (!byCategory[cat]) byCategory[cat] = { total: 0, vuln: 0, safe: 0, na: 0, info: 0 };
      byCategory[cat].total++;
      const k = r.ai_verdict === '취약' ? 'vuln'
              : r.ai_verdict === '양호' ? 'safe'
              : (r.ai_verdict === '정보제공' || r.ai_verdict === '정보') ? 'info' : 'na';
      byCategory[cat][k]++;
      if (r.ai_verdict === '취약') {
        bySeverity[r.ai_severity] = (bySeverity[r.ai_severity] || 0) + 1;
      }
    }

    res.render('diagnosis/ai_result', {
      activeMenu: 'diagnosis',
      diag,
      baseAiDiag,
      relatedLlmDiags,
      resultScope,
      byCategory,
      bySeverity,
    });
  } catch (e) {
    console.error('[AI 결과 화면 오류]', e);
    res.status(500).send('오류: ' + e.message);
  }
});

// ─── 리포트 ───────────────────────────────────────────────
// AI 진단 결과를 고객사 양식(리포트1/리포트2)으로 출력

// 리포트 인덱스 — 진단 목록에서 리포트 선택
app.get('/reports', (req, res) => {
  const diagnoses = (loadMock('diagnoses') || [])
    .filter(d => d.status === 'success' && d.diagnose_type === 'ai')
    .slice(0, 100);
  res.render('reports/index', {
    activeMenu: 'reports',
    diagnoses,
  });
});

// 리포트 데이터 빌더 — AI 진단을 양식 데이터로 변환
function buildAiReportData(assessment_id) {
  const diagnoses = loadMock('diagnoses') || [];
  const diag = diagnoses.find(d => d.assessment_id == assessment_id);
  if (!diag) return null;
  if (diag.diagnose_type !== 'ai') return { _notAi: true, diag };

  const servers = loadMock('servers') || [];
  let server = servers.find(s => s.server_id == diag.server_id) || {};
  try {
    const { getTargetServersFromFile } = require('./src/services/scheduler');
    const csvServers = getTargetServersFromFile();
    const csvHit = csvServers.find(s =>
      String(s.server_id || '') === String(diag.server_id || '') ||
      String(s.hostname || '').toLowerCase() === String(diag.hostname || server.hostname || '').toLowerCase()
    );
    if (csvHit) {
      server = {
        ...server,
        server_id: csvHit.server_id || server.server_id || diag.server_id,
        name: csvHit.hostname || server.name || diag.server_name,
        hostname: csvHit.hostname || server.hostname || diag.hostname,
        asset_no: csvHit.asset_no || server.asset_no || diag.asset_no,
        ip: csvHit.ip || server.ip,
        ip_address: csvHit.ip || server.ip_address,
        os: csvHit.os || server.os,
        os_type: csvHit.os || server.os_type,
        username: csvHit.username || server.username || server.ssh_user,
      };
    }
  } catch (e) {
    console.warn('[reports] servers.csv metadata merge failed:', e.message);
  }

  const { buildReportFromAi } = require('./src/engine/aiReportAdapter');
  const report = buildReportFromAi(diag, server);
  return { ...report, sourceDiag: diag };
}

// /reports/:id → 리포트1으로
app.get('/reports/:id', (req, res) => {
  res.redirect(`/reports/${req.params.id}/fsi`);
});

// 리포트1 (금보원 양식) — 전체
app.get('/reports/:id/fsi', (req, res) => {
  const data = buildAiReportData(req.params.id);
  if (!data) return res.status(404).send('진단 결과를 찾을 수 없습니다.');
  if (data._notAi) {
    return res.status(400).send(
      `이 진단은 AI 진단이 아닙니다. 리포트는 AI 진단 결과만 지원합니다. ` +
      `<a href="/diagnosis">진단 관리</a>에서 AI 진단을 실행하세요.`
    );
  }
  res.render('reports/view_fsi', { activeMenu: 'reports', ...data });
});

// 취약점 리포트1 — 취약 항목만
app.get('/reports/:id/fsi/vuln', (req, res) => {
  const data = buildAiReportData(req.params.id);
  if (!data) return res.status(404).send('진단 결과를 찾을 수 없습니다.');
  if (data._notAi) {
    return res.status(400).send(
      `이 진단은 AI 진단이 아닙니다. <a href="/diagnosis">진단 관리</a>로 가세요.`
    );
  }
  res.render('reports/view_fsi_vuln', { activeMenu: 'reports', ...data });
});

// 리포트2 (삼성 양식) — 전체
app.get('/reports/:id/samsung', (req, res) => {
  const data = buildAiReportData(req.params.id);
  if (!data) return res.status(404).send('진단 결과를 찾을 수 없습니다.');
  if (data._notAi) {
    return res.status(400).send(
      `이 진단은 AI 진단이 아닙니다. 리포트는 AI 진단 결과만 지원합니다. ` +
      `<a href="/diagnosis">진단 관리</a>에서 AI 진단을 실행하세요.`
    );
  }
  res.render('reports/view_samsung', { activeMenu: 'reports', ...data });
});

// 취약점 리포트2 — 취약 항목만
app.get('/reports/:id/samsung/vuln', (req, res) => {
  const data = buildAiReportData(req.params.id);
  if (!data) return res.status(404).send('진단 결과를 찾을 수 없습니다.');
  if (data._notAi) {
    return res.status(400).send(
      `이 진단은 AI 진단이 아닙니다. <a href="/diagnosis">진단 관리</a>로 가세요.`
    );
  }
  res.render('reports/view_samsung_vuln', { activeMenu: 'reports', ...data });
});

// 리포트3 (SecuMS raw DB / Script raw 정합성)
app.get('/reports/:id/report3', async (req, res) => {
  try {
    const data = buildAiReportData(req.params.id);
    if (!data) return res.status(404).send('진단 결과를 찾을 수 없습니다.');
    if (data._notAi) {
      return res.status(400).send(
        `이 진단은 AI 진단이 아닙니다. 리포트3는 AI 진단 결과만 지원합니다. ` +
        `<a href="/diagnosis">진단 관리</a>에서 AI 진단을 실행하세요.`
      );
    }

    const diagnoses = loadMock('diagnoses') || [];
    const { buildReport3Data } = require('./src/services/report3Service');
    const report3 = await buildReport3Data(data, diagnoses, { rootDir: ROOT });
    res.render('reports/view_report3', { activeMenu: 'reports', ...data, report3 });
  } catch (e) {
    console.error('[리포트3 화면 오류]', e);
    res.status(500).send('리포트3 생성 실패: ' + e.message);
  }
});

// ─── XLSX 다운로드 ──────────────────────────────────────
/**
 * 공통 XLSX 빌더. rows 배열 + 메타 정보를 받아 Excel 파일 생성.
 *
 * @param {Array} rows - 출력할 항목 배열 (toReportRow 결과)
 * @param {object} session - 헤더 메타
 * @param {string} sheetName - 시트명
 * @returns {Promise<Buffer>} XLSX 바이너리
 */
async function buildReportXlsx(rows, session, sheetName) {
  const ExcelJS = require('exceljs');
  const wb = new ExcelJS.Workbook();
  wb.creator = 'Vuln Assessor';
  wb.created = new Date();

  // 메타 시트
  const meta = wb.addWorksheet('진단 정보');
  meta.columns = [{ width: 20 }, { width: 50 }];
  meta.addRows([
    ['진단 ID', session.assessment_id],
    ['호스트명', session.hostname],
    ['자산번호', session.asset_no || '-'],
    ['IP', session.ip_address || '-'],
    ['업무명/용도', session.service_name || '-'],
    ['OS', `${session.os_type || ''} ${session.os_version || ''}`.trim()],
    ['정책명', session.policy_name || '-'],
    ['진단일시', session.executed_at],
    ['실행자', session.executed_by || '-'],
    ['LLM', session.llm_engine || '-'],
    [],
    ['전체 항목', session.total_count],
    ['취약', session.vuln_count],
    ['양호', session.safe_count],
    ['정보제공', session.info_count],
    ['판정불가', session.na_count],
    ['SecuMS 일치율', `${session.secums_agreement_rate || 0}%`],
    ['검증 실패율', `${session.validation_failure_rate || 0}%`],
    ['실제 불일치', session.secums_disagree_real_count || 0],
    ['검토 필요', session.secums_needs_review_count || 0],
  ]);
  // 첫 컬럼 강조
  meta.getColumn(1).font = { bold: true };
  meta.getColumn(1).alignment = { vertical: 'middle' };

  // 결과 시트
  const ws = wb.addWorksheet(sheetName);
  ws.columns = [
    { header: '관리번호',     key: 'management_no',  width: 18 },
    { header: '항목ID',       key: 'rule_id',        width: 18 },
    { header: '제목',         key: 'title',          width: 30 },
    { header: '카테고리',     key: 'category',       width: 14 },
    { header: '판정',         key: 'status',         width: 10 },
    { header: '양호 유형',    key: 'safe_type',      width: 12 },
    { header: '심각도',       key: 'severity',       width: 8  },
    { header: '사유',         key: 'reason',         width: 60 },
    { header: '증거',         key: 'evidence',       width: 40 },
    { header: '조치 권고',    key: 'recommend',      width: 50 },
    { header: 'SecuMS 판정',  key: 'secums_verdict', width: 12 },
    { header: '일치 여부',    key: 'agreement',      width: 12 },
  ];
  // 헤더 행 스타일
  const hdr = ws.getRow(1);
  hdr.font = { bold: true, color: { argb: 'FFFFFFFF' } };
  hdr.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF34495E' } };
  hdr.alignment = { horizontal: 'center', vertical: 'middle' };
  hdr.height = 22;

  // 데이터 행
  for (const r of rows) {
    const row = ws.addRow({
      management_no:  r.management_no,
      rule_id:        r.rule_id,
      title:          r.title,
      category:       r.category,
      status:         r.status,
      safe_type:      r.safe_type || '',
      severity:       r.severity,
      reason:         r.reason,
      evidence:       r.evidence,
      recommend:      r.recommend,
      secums_verdict: r.secums_verdict || '-',
      agreement:      r.agreement === 'agree' ? '일치'
                     : r.agreement === 'disagree_real' ? '검증 실패'
                     : r.agreement === 'needs_review' ? '검토 필요'
                     : r.agreement === 'disagree' ? '불일치(이전 결과)'
                     : r.agreement === 'secums_wait' ? 'SecuMS 미점검(AI 추론)'
                     : '-',
    });
    // 상태별 행 색상
    if (r.status === '취약') {
      row.eachCell((cell) => {
        cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFFFEEEE' } };
      });
    } else if (r.status === '양호') {
      row.getCell('status').font = { color: { argb: 'FF27AE60' }, bold: true };
    } else if (r.status === '정보제공' || r.status === '정보') {
      row.getCell('status').font = { color: { argb: 'FF1976D2' } };
    } else if (r.status === '판정불가') {
      row.getCell('status').font = { color: { argb: 'FF888888' } };
    }
    row.alignment = { wrapText: true, vertical: 'top' };
  }
  // 자동 필터
  ws.autoFilter = { from: 'A1', to: `L${rows.length + 1}` };
  // 첫 행 고정
  ws.views = [{ state: 'frozen', xSplit: 0, ySplit: 1 }];

  return wb.xlsx.writeBuffer();
}

/**
 * 한글 파일명 안전 인코딩 (Content-Disposition).
 */
function encodeFilename(name) {
  return encodeURIComponent(name).replace(/['()]/g, escape);
}

// 리포트1 (전체) XLSX
app.get('/reports/:id/fsi/xlsx', async (req, res) => {
  try {
    const data = buildAiReportData(req.params.id);
    if (!data) return res.status(404).send('진단 결과를 찾을 수 없습니다.');
    if (data._notAi) return res.status(400).send('AI 진단 결과만 다운로드 가능합니다.');

    const buf = await buildReportXlsx(data.allRows, data.session, '전체 진단 결과');
    const fname = `리포트1_전체_${data.session.hostname || 'host'}_${req.params.id}.xlsx`;
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="report1_full_${req.params.id}.xlsx"; filename*=UTF-8''${encodeFilename(fname)}`);
    res.send(Buffer.from(buf));
  } catch (e) {
    console.error('[XLSX 리포트1 오류]', e);
    res.status(500).send('XLSX 생성 실패: ' + e.message);
  }
});

// 취약점 리포트1 XLSX
app.get('/reports/:id/fsi/vuln/xlsx', async (req, res) => {
  try {
    const data = buildAiReportData(req.params.id);
    if (!data) return res.status(404).send('진단 결과를 찾을 수 없습니다.');
    if (data._notAi) return res.status(400).send('AI 진단 결과만 다운로드 가능합니다.');

    const buf = await buildReportXlsx(data.vulnRows, data.session, '취약 항목');
    const fname = `취약점리포트1_${data.session.hostname || 'host'}_${req.params.id}.xlsx`;
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="report1_vuln_${req.params.id}.xlsx"; filename*=UTF-8''${encodeFilename(fname)}`);
    res.send(Buffer.from(buf));
  } catch (e) {
    console.error('[XLSX 취약점 리포트1 오류]', e);
    res.status(500).send('XLSX 생성 실패: ' + e.message);
  }
});

// 리포트2 (전체) XLSX
app.get('/reports/:id/samsung/xlsx', async (req, res) => {
  try {
    const data = buildAiReportData(req.params.id);
    if (!data) return res.status(404).send('진단 결과를 찾을 수 없습니다.');
    if (data._notAi) return res.status(400).send('AI 진단 결과만 다운로드 가능합니다.');

    const buf = await buildReportXlsx(data.allRows, data.session, '전체 진단 결과');
    const fname = `리포트2_전체_${data.session.hostname || 'host'}_${req.params.id}.xlsx`;
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="report2_full_${req.params.id}.xlsx"; filename*=UTF-8''${encodeFilename(fname)}`);
    res.send(Buffer.from(buf));
  } catch (e) {
    console.error('[XLSX 리포트2 오류]', e);
    res.status(500).send('XLSX 생성 실패: ' + e.message);
  }
});

// 취약점 리포트2 XLSX
app.get('/reports/:id/samsung/vuln/xlsx', async (req, res) => {
  try {
    const data = buildAiReportData(req.params.id);
    if (!data) return res.status(404).send('진단 결과를 찾을 수 없습니다.');
    if (data._notAi) return res.status(400).send('AI 진단 결과만 다운로드 가능합니다.');

    const buf = await buildReportXlsx(data.vulnRows, data.session, '취약 항목');
    const fname = `취약점리포트2_${data.session.hostname || 'host'}_${req.params.id}.xlsx`;
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="report2_vuln_${req.params.id}.xlsx"; filename*=UTF-8''${encodeFilename(fname)}`);
    res.send(Buffer.from(buf));
  } catch (e) {
    console.error('[XLSX 취약점 리포트2 오류]', e);
    res.status(500).send('XLSX 생성 실패: ' + e.message);
  }
});

// 리포트3 정합성 XLSX
app.get('/reports/:id/report3/xlsx', async (req, res) => {
  try {
    const data = buildAiReportData(req.params.id);
    if (!data) return res.status(404).send('진단 결과를 찾을 수 없습니다.');
    if (data._notAi) return res.status(400).send('AI 진단 결과만 다운로드 가능합니다.');

    const diagnoses = loadMock('diagnoses') || [];
    const { buildReport3Workbook } = require('./src/services/report3Service');
    const { workbook } = await buildReport3Workbook(data, diagnoses, { rootDir: ROOT });
    const buf = await workbook.xlsx.writeBuffer();
    const fname = `리포트3_정합성_${data.session.hostname || 'host'}_${req.params.id}.xlsx`;
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="report3_consistency_${req.params.id}.xlsx"; filename*=UTF-8''${encodeFilename(fname)}`);
    res.send(Buffer.from(buf));
  } catch (e) {
    console.error('[XLSX 리포트3 오류]', e);
    res.status(500).send('XLSX 생성 실패: ' + e.message);
  }
});

// 옛 /reports/:id/xlsx (리포트2 호환) → 리포트2 전체로 리다이렉트
app.get('/reports/:id/xlsx', (req, res) => {
  res.redirect(`/reports/${req.params.id}/samsung/xlsx`);
});

/**
 * CVE 동기화 관리 페이지.
 */
app.get('/cve/sync', (req, res) => {
  const enrichment = require('./src/cve/enrichment');
  res.render('cve/sync', {
    activeMenu: 'diagnosis',
    stats: enrichment.getEnrichmentStats(),
    history: enrichment.getSyncHistory(20),
    untracked_kev: enrichment.getUntrackedKevCves(50),
  });
});

/**
 * 수동 sync 트리거 (인터넷 가능 환경 / --from-file 옵션은 별도).
 * 백그라운드에서 sync-cve.js 를 spawn 한다.
 */
app.post('/cve/sync/run', auth.requireRole('admin', 'operator'), (req, res) => {
  const { spawn } = require('child_process');
  const script = path.join(ROOT, 'scripts', 'sync-cve.js');
  const args = [script];
  if (req.body && req.body.from_file) args.push('--from-file=' + req.body.from_file);
  if (req.body && req.body.dry_run) args.push('--dry-run');

  const child = spawn('node', args, { cwd: ROOT, detached: false });
  let stdout = '', stderr = '';
  child.stdout.on('data', d => { stdout += d.toString(); });
  child.stderr.on('data', d => { stderr += d.toString(); });
  child.on('close', code => {
    // 캐시 무효화 → 다음 CVE 진단부터 보강된 DB 사용
    try { require('./src/cve/matcher').invalidateCveCache(); } catch (_) {}
    res.json({
      status: code === 0 ? 'success' : 'error',
      exit_code: code,
      stdout: stdout.slice(-4000),  // 마지막 4KB만
      stderr: stderr.slice(-2000),
    });
  });
  child.on('error', e => {
    res.status(500).json({ status: 'error', error: e.message });
  });
});

async function startServer() {
  // Storage 초기화 (MySQL 모드인 경우 연결 + 테이블 확인)
  const storageStatus = await kvStorage.initialize();
  
  if (storageStatus.mode === 'mysql' && storageStatus.status === 'ok') {
    // MySQL 모드: 캐시 프리로드
    await kvStorage.preloadAll();
  } else if (storageStatus.status === 'fallback') {
    // MySQL 실패 → mock 폴백 (storage 내부에서 처리됨)
  }

  // 알림 모듈 초기화 (storage 주입 — 이력 파일 적재)
  const notifier = require('./src/notifier');
  notifier.configure({
    storage: kvStorage,
    log: console,
  });

  // 스케줄러 시작 — AI 진단만 호출
  const scheduler = require('./src/scheduler/runner');
  scheduler.start({
    storage: kvStorage,
    runDiagnosis: async (server, runOpts) => executeAiDiagnosis(server, {
      triggered_by: (runOpts && runOpts.triggered_by) || 'cron',
      executed_by: 'scheduler',
    }),
    notifier,
    log: console,
  });

  // ═════════════════════════════════════════════════════════
// 취약점 관리 (모든 진단 결과의 취약 항목 통합 뷰)
// ═════════════════════════════════════════════════════════

/**
 * 모든 진단 결과에서 취약 항목만 평탄화.
 * 같은 (server, rule) 조합은 최신 진단만 사용.
 */
function buildVulnList() {
  const diagnoses = loadMock('diagnoses') || [];
  const servers = loadMock('servers') || [];
  const exceptions = (loadMock('exceptions') || []).filter(e => e.enabled);
  const remediations = loadMock('remediations') || [];
  const serverMap = new Map(servers.map(s => [s.server_id, s]));
  
  // (server_id, rule_id) → 최신 진단의 결과
  const latest = new Map();
  
  // diagnoses는 최신순으로 정렬되어 있다고 가정
  for (const diag of diagnoses) {
    for (const r of diag.results || []) {
      if (r.status !== '취약') continue;
      const key = `${diag.server_id}::${r.rule_id}`;
      if (latest.has(key)) continue;  // 이미 더 최신 진단의 결과 있음
      
      const server = serverMap.get(diag.server_id) || {};
      // 진단의 실제 시간 필드는 executed_at (manual upload) 또는 completed_at (agent push)
      const diagTime = diag.executed_at || diag.completed_at || diag.started_at;
      const diagTs = diagTime ? new Date(diagTime.replace(' ', 'T')).getTime() : Date.now();
      const daysOld = Math.max(0, Math.floor((Date.now() - diagTs) / 86400000));
      
      // 조치 상태 확인
      const rem = remediations.find(x => 
        x.server_id === diag.server_id && 
        x.rule_id === r.rule_id && 
        x.assessment_id === diag.assessment_id
      );
      
      // 예외 적용 여부
      const hasException = exceptions.some(e =>
        (e.scope_type === 'result' && e.result_id === r.result_id) ||
        (e.scope_type === 'rule_host' && e.rule_id === r.rule_id && e.server_id === diag.server_id) ||
        (e.scope_type === 'rule_global' && e.rule_id === r.rule_id)
      );
      
      latest.set(key, {
        result_id: r.result_id || `${diag.assessment_id}-${r.rule_id}`,
        assessment_id: diag.assessment_id,
        management_no: r.management_no || `${new Date(diag.executed_at || diag.completed_at || Date.now()).getFullYear()}-${String(latest.size + 1).padStart(3, '0')}`,
        server_id: diag.server_id,
        hostname: diag.hostname || server.hostname,
        asset_no: diag.asset_no || server.asset_no,
        service_name: diag.service_name || server.service_name,
        rule_id: r.rule_id,
        title: r.title,
        category: r.category || '',
        severity: r.severity || r.weight || '상',
        reason: r.reason || '',
        evidence: r.evidence || '',
        eval_method: r.eval_method,
        discovered_at: diag.executed_at || diag.completed_at || diag.started_at,
        is_new: daysOld <= 7,
        days_old: daysOld,
        is_per_row: !!(r.subs && r.subs.length),
        sub_count: (r.subs || []).length,
        sub_vuln: (r.subs || []).filter(s => s.status === '취약').length,
        cves: r.cves || [],
        has_exception: hasException,
        fix_status: rem?.fix_status || (hasException ? '예외' : '미조치'),
        assignee: rem?.assignee || null,
        fixed_at: rem?.fixed_at || null,
        subs: r.subs || [],
      });
    }
  }
  
  return Array.from(latest.values()).sort((a, b) => {
    // 1순위: 신규
    if (a.is_new !== b.is_new) return a.is_new ? -1 : 1;
    // 2순위: 위험도 (상 > 중 > 하)
    const sevOrder = { '상': 0, '중': 1, '하': 2, '정보': 3 };
    if (a.severity !== b.severity) return (sevOrder[a.severity] || 9) - (sevOrder[b.severity] || 9);
    // 3순위: 호스트
    return (a.hostname || '').localeCompare(b.hostname || '');
  });
}

app.get('/vulnerabilities', (req, res) => {
  const vulns = buildVulnList();
  
  // KPI 계산
  const sevenDaysAgo = Date.now() - 7 * 86400000;
  const stats = {
    total: vulns.length,
    new: vulns.filter(v => v.is_new).length,
    cve_mapped: vulns.filter(v => v.cves && v.cves.length).length,
    sub_total: vulns.reduce((s, v) => s + v.sub_vuln, 0),
    fixed: vulns.filter(v => v.fix_status === '조치완료').length,
    fix_rate: vulns.length > 0 ? Math.round(vulns.filter(v => v.fix_status === '조치완료').length / vulns.length * 100) : 0,
    by_severity: {
      상: vulns.filter(v => v.severity === '상').length,
      중: vulns.filter(v => v.severity === '중').length,
      하: vulns.filter(v => v.severity === '하').length,
    },
  };
  
  res.render('vulnerabilities/index', {
    activeMenu: 'vuln',
    vulns,
    stats,
    servers: loadMock('servers') || [],
  });
});

app.get('/vulnerabilities/:resultId', (req, res) => {
  const vulns = buildVulnList();
  const vuln = vulns.find(v => String(v.result_id) === String(req.params.resultId));
  if (!vuln) return res.status(404).send('취약점을 찾을 수 없습니다');
  
  res.render('vulnerabilities/detail', {
    activeMenu: 'vuln',
    vuln,
  });
});


// ═════════════════════════════════════════════════════════
// 조치 관리 (취약점별 조치 워크플로)
// ═════════════════════════════════════════════════════════

app.get('/remediation', (req, res) => {
  const vulns = buildVulnList();
  
  // 조치 상태별 분류
  const byStatus = {
    미조치: vulns.filter(v => v.fix_status === '미조치'),
    진행중: vulns.filter(v => v.fix_status === '진행중'),
    조치완료: vulns.filter(v => v.fix_status === '조치완료'),
    예외: vulns.filter(v => v.fix_status === '예외'),
  };
  
  const stats = {
    total: vulns.length,
    미조치: byStatus.미조치.length,
    진행중: byStatus.진행중.length,
    조치완료: byStatus.조치완료.length,
    예외: byStatus.예외.length,
    overdue: vulns.filter(v => v.fix_status === '미조치' && v.days_old > 30).length,
    completion_rate: vulns.length > 0 
      ? Math.round((byStatus.조치완료.length + byStatus.예외.length) / vulns.length * 100) 
      : 0,
  };
  
  res.render('remediation/index', {
    activeMenu: 'remediation',
    vulns,
    byStatus,
    stats,
    servers: loadMock('servers') || [],
  });
});

app.post('/remediation/:resultId/update', auth.requireRole('admin', 'operator'), (req, res) => {
  try {
    const { fix_status, fix_method, assignee, misnotice_reason, note } = req.body;
    
    // 해당 진단 결과 찾기
    const diagnoses = loadMock('diagnoses') || [];
    let found = null;
    for (const diag of diagnoses) {
      for (const r of (diag.results || [])) {
        const rid = r.result_id || `${diag.assessment_id}-${r.rule_id}`;
        if (String(rid) === String(req.params.resultId)) {
          found = { diag, rule: r };
          break;
        }
      }
      if (found) break;
    }
    
    if (!found) return res.status(404).json({ status: 'error', error: '대상을 찾을 수 없습니다' });
    
    // remediations 별도 저장 (진단 결과는 불변)
    const remediations = loadMock('remediations') || [];
    const existingIdx = remediations.findIndex(x =>
      x.server_id === found.diag.server_id &&
      x.rule_id === found.rule.rule_id &&
      x.assessment_id === found.diag.assessment_id
    );
    
    const remediation = {
      remediation_id: existingIdx >= 0 ? remediations[existingIdx].remediation_id : Date.now(),
      assessment_id: found.diag.assessment_id,
      server_id: found.diag.server_id,
      rule_id: found.rule.rule_id,
      result_id: req.params.resultId,
      fix_status: fix_status || '미조치',
      assignee: assignee || null,
      fix_method: fix_method || null,
      misnotice_reason: misnotice_reason || null,
      note: note || null,
      fixed_at: fix_status === '조치완료' ? new Date().toISOString().slice(0, 19).replace('T', ' ') : null,
      updated_by: req.session.username,
      updated_at: new Date().toISOString().slice(0, 19).replace('T', ' '),
    };
    
    if (existingIdx >= 0) {
      remediations[existingIdx] = remediation;
    } else {
      remediations.unshift(remediation);
    }
    saveMock('remediations', remediations);
    
    res.json({ status: 'success', remediation });
  } catch (e) {
    res.status(500).json({ status: 'error', error: e.message });
  }
});


// ═════════════════════════════════════════════════════════
// Agent Push REST API
// ═════════════════════════════════════════════════════════
const agentToken = require('./src/agent/token');

/**
 * Agent에서 raw 데이터 업로드.
 *
 * POST /api/collect
 *   Headers: X-Agent-Token: <token>
 *   Body: multipart/form-data
 *     - hostname
 *     - os_type
 *     - os_version (선택)
 *     - agent_version (선택)
 *     - dbfile (선택, binary, SecuMS DB)
 *     - scriptfile (선택, binary, SecuMS script XML)
 *
 * Response:
 *   { status: 'success', job_id, message }
 *   { status: 'error', error }
 */
app.post('/api/collect', collectUpload.fields([
  { name: 'dbfile', maxCount: 1 },
  { name: 'scriptfile', maxCount: 1 },
  { name: 'script_file', maxCount: 1 },
]), async (req, res) => {
  try {
    // 1. 토큰 검증
    const token = req.headers['x-agent-token'];
    if (!token) {
      return res.status(401).json({
        status: 'error',
        error: 'X-Agent-Token 헤더 필요',
      });
    }
    
    const server = agentToken.findServerByToken(kvStorage, token);
    if (!server) {
      return res.status(401).json({
        status: 'error',
        error: '유효하지 않은 토큰',
      });
    }

    const rawFile = req.files?.dbfile?.[0] || null;
    const scriptFile = req.files?.scriptfile?.[0] || req.files?.script_file?.[0] || null;

    // 2. 파일 검증
    if (!rawFile && !scriptFile) {
      return res.status(400).json({
        status: 'error',
        error: 'dbfile 또는 scriptfile 필드 필요 (multipart/form-data)',
      });
    }

    const { hostname, os_type, os_version, agent_version } = req.body;

    // 3. 메타데이터 기록
    agentToken.recordPush(kvStorage, server.server_id, {
      hostname: hostname || server.hostname,
      os_type: os_type || server.os_type,
      os_version: os_version || '',
      agent_version: agent_version || '',
      source_type: rawFile && scriptFile ? 'both' : (scriptFile ? 'script' : 'secums'),
      file_size: (rawFile?.size || 0) + (scriptFile?.size || 0),
      raw_file_size: rawFile?.size || 0,
      script_file_size: scriptFile?.size || 0,
      ip_address: req.ip || req.connection.remoteAddress,
    });

    // 4. 자동 진단 실행 (비동기, 응답 즉시 반환)
    const assessmentId = Date.now();  // 임시 ID
    
    setImmediate(async () => {
      try {
        await runAssessmentInBackground({
          rawPath: rawFile?.path,
          scriptPath: scriptFile?.path,
          server,
          assessmentId,
        });
      } catch (e) {
        console.error('[Agent Push] 진단 실패:', e);
      }
    });

    res.json({
      status: 'success',
      job_id: assessmentId,
      message: '진단 작업이 큐에 등록되었습니다',
      server_id: server.server_id,
      hostname: server.hostname,
      source_type: rawFile && scriptFile ? 'both' : (scriptFile ? 'script' : 'secums'),
      uploaded_size: (rawFile?.size || 0) + (scriptFile?.size || 0),
      raw_uploaded: !!rawFile,
      script_uploaded: !!scriptFile,
    });
    
  } catch (e) {
    console.error('[Agent Push] 오류:', e);
    res.status(500).json({
      status: 'error',
      error: e.message,
    });
  }
});

/**
 * Agent 헬스체크 (토큰 검증 + 서버 상태 확인).
 *
 * GET /api/ping
 *   Headers: X-Agent-Token: <token>
 *
 * Response: { status, server_id, hostname, server_time }
 */
app.get('/api/ping', (req, res) => {
  const token = req.headers['x-agent-token'];
  if (!token) {
    return res.status(401).json({ status: 'error', error: '토큰 필요' });
  }
  const server = agentToken.findServerByToken(kvStorage, token);
  if (!server) {
    return res.status(401).json({ status: 'error', error: '유효하지 않은 토큰' });
  }
  res.json({
    status: 'ok',
    server_id: server.server_id,
    hostname: server.hostname,
    server_time: new Date().toISOString(),
  });
});

/**
 * Agent Script 배포 작업 조회.
 *
 * GET /api/script-job
 *   Headers: X-Agent-Token: <token>
 *   Query: format=env 이면 Linux shell source 용 key=value 응답
 */
app.get('/api/script-job', (req, res) => {
  const token = req.headers['x-agent-token'];
  if (!token) {
    return res.status(401).json({ status: 'error', error: '토큰 필요' });
  }
  const server = agentToken.findServerByToken(kvStorage, token);
  if (!server) {
    return res.status(401).json({ status: 'error', error: '유효하지 않은 토큰' });
  }

  const jobs = loadScriptDeployJobs();
  const idx = jobs.findIndex(job =>
    String(job.server_id) === String(server.server_id) &&
    ['queued', 'assigned'].includes(job.status)
  );
  if (idx < 0) {
    if (req.query.format === 'env') return sendEnvJobResponse(res, { STATUS: 'none' });
    return res.json({ status: 'none', message: '대기 중인 Script 배포 작업이 없습니다' });
  }

  const job = jobs[idx];
  if (job.status === 'queued') {
    job.status = 'assigned';
    job.progress_percent = 15;
    job.progress_message = 'agent assigned';
    job.assigned_at = new Date().toISOString().slice(0, 19).replace('T', ' ');
    jobs[idx] = job;
    saveScriptDeployJobs(jobs);
  }

  const base = getPublicBaseUrl(req);
  const payload = {
    status: 'pending',
    job_id: job.job_id,
    script_name: job.original_name || job.script_file,
    script_args: job.script_args || '',
    package_script: job.package_script || '',
    result_glob: job.result_glob || '*.xml',
    engine: job.engine || 'ai',
    script_action: job.script_action || (job.run_immediately ? 'deploy_run_diagnose' : 'deploy_run'),
    run_immediately: job.run_immediately ? 'true' : 'false',
    download_url: `${base}/api/script-job/${encodeURIComponent(job.job_id)}/download`,
    upload_url: `${base}/api/script-job/${encodeURIComponent(job.job_id)}/result`,
    status_url: `${base}/api/script-job/${encodeURIComponent(job.job_id)}/status`,
  };

  if (req.query.format === 'env') {
    return sendEnvJobResponse(res, {
      STATUS: payload.status,
      JOB_ID: payload.job_id,
      SCRIPT_NAME: payload.script_name,
      SCRIPT_ARGS: payload.script_args,
      PACKAGE_SCRIPT: payload.package_script,
      RESULT_GLOB: payload.result_glob,
      ENGINE: payload.engine,
      SCRIPT_ACTION: payload.script_action,
      RUN_IMMEDIATELY: payload.run_immediately,
      DOWNLOAD_URL: payload.download_url,
      UPLOAD_URL: payload.upload_url,
      STATUS_URL: payload.status_url,
    });
  }
  res.json(payload);
});

app.get('/api/script-job/:jobId/download', (req, res) => {
  const token = req.headers['x-agent-token'];
  if (!token) return res.status(401).send('토큰 필요');
  const server = agentToken.findServerByToken(kvStorage, token);
  if (!server) return res.status(401).send('유효하지 않은 토큰');

  const { job } = findOwnedScriptJob(req.params.jobId, server);
  if (!job) return res.status(404).send('Script 배포 작업을 찾을 수 없습니다');

  const fullPath = path.join(ROOT, job.script_path || '');
  if (!fs.existsSync(fullPath)) return res.status(404).send('배포 스크립트 파일이 없습니다');
  res.download(fullPath, job.original_name || path.basename(fullPath));
});

app.post('/api/script-job/:jobId/status', express.json(), (req, res) => {
  const token = req.headers['x-agent-token'];
  if (!token) return res.status(401).json({ status: 'error', error: '토큰 필요' });
  const server = agentToken.findServerByToken(kvStorage, token);
  if (!server) return res.status(401).json({ status: 'error', error: '유효하지 않은 토큰' });

  const { jobs, idx, job } = findOwnedScriptJob(req.params.jobId, server);
  if (!job) return res.status(404).json({ status: 'error', error: 'Script 배포 작업을 찾을 수 없습니다' });

  const nextStatus = String(req.body.status || '').toLowerCase();
  if (!['running', 'failed', 'completed'].includes(nextStatus)) {
    return res.status(400).json({ status: 'error', error: 'status는 running/failed/completed 중 하나여야 합니다' });
  }

  job.status = nextStatus;
  job.agent_message = String(req.body.message || '').slice(0, 1000);
  const requestedProgress = req.body.progress_percent ?? req.body.progress;
  job.progress_percent = requestedProgress === undefined
    ? progressForScriptJobStatus(nextStatus, job.agent_message)
    : clampProgressPercent(requestedProgress);
  job.progress_message = job.agent_message || nextStatus;
  job.exit_code = req.body.exit_code ?? job.exit_code;
  job.updated_at = new Date().toISOString().slice(0, 19).replace('T', ' ');
  if (nextStatus === 'running') job.started_at = job.started_at || job.updated_at;
  if (nextStatus === 'failed') job.failed_at = job.updated_at;
  if (nextStatus === 'completed') job.completed_at = job.updated_at;
  jobs[idx] = job;
  saveScriptDeployJobs(jobs);
  res.json({ status: 'success', job_status: job.status });
});

app.post('/api/script-job/:jobId/result', collectUpload.single('scriptfile'), async (req, res) => {
  const startedAt = new Date();
  try {
    const token = req.headers['x-agent-token'];
    if (!token) return res.status(401).json({ status: 'error', error: '토큰 필요' });
    const tokenServer = agentToken.findServerByToken(kvStorage, token);
    if (!tokenServer) return res.status(401).json({ status: 'error', error: '유효하지 않은 토큰' });

    const { jobs, idx, job } = findOwnedScriptJob(req.params.jobId, tokenServer);
    if (!job) return res.status(404).json({ status: 'error', error: 'Script 배포 작업을 찾을 수 없습니다' });

    const scriptFile = req.file;
    if (!scriptFile) {
      job.status = 'failed';
      job.agent_message = '결과 XML(scriptfile)이 업로드되지 않았습니다';
      job.progress_percent = 100;
      job.progress_message = 'result xml missing';
      job.failed_at = new Date().toISOString().slice(0, 19).replace('T', ' ');
      jobs[idx] = job;
      saveScriptDeployJobs(jobs);
      return res.status(400).json({ status: 'error', error: 'scriptfile XML 파일이 필요합니다' });
    }

    job.status = job.run_immediately ? 'diagnosing' : 'completed';
    job.progress_percent = job.run_immediately ? 85 : 100;
    job.progress_message = job.run_immediately ? 'diagnosis running' : 'completed';
    job.result_file = scriptFile.filename;
    job.result_path = path.relative(ROOT, scriptFile.path);
    job.result_size = scriptFile.size;
    job.uploaded_at = new Date().toISOString().slice(0, 19).replace('T', ' ');
    jobs[idx] = job;
    saveScriptDeployJobs(jobs);

    const server = findServerForUpload(job.server_id, job.hostname) || tokenServer;
    let diagnosisResult = null;
    if (job.run_immediately) {
      const runDiagnosis = getDiagnosisRunner(job.engine);
      diagnosisResult = await runDiagnosis(server, {
        executed_by: 'agent-script-deploy',
        triggered_by: 'script-deploy',
        source: 'script',
        scriptPath: scriptFile.path,
        script_file: scriptFile.filename,
      });

      const refreshed = loadScriptDeployJobs();
      const jIdx = refreshed.findIndex(x => x.job_id === job.job_id);
      const currentJob = jIdx >= 0 ? refreshed[jIdx] : job;
      currentJob.status = diagnosisResult.status === 'success' ? 'diagnosed' : 'diagnosis_failed';
      currentJob.progress_percent = 100;
      currentJob.progress_message = diagnosisResult.status === 'success' ? 'diagnosis completed' : 'diagnosis failed';
      currentJob.assessment_id = diagnosisResult.assessment_id || null;
      currentJob.summary = diagnosisResult.summary || null;
      currentJob.diagnose_error = diagnosisResult.error || null;
      currentJob.completed_at = new Date().toISOString().slice(0, 19).replace('T', ' ');
      if (jIdx >= 0) refreshed[jIdx] = currentJob;
      saveScriptDeployJobs(refreshed);
    }

    appendCollectionHistory({
      started_at: startedAt.toISOString().slice(0, 19).replace('T', ' '),
      source_type: 'script_deploy',
      hostname: job.hostname,
      ip: job.ip,
      os: job.os,
      fetch_status: 'success',
      diagnose_status: diagnosisResult ? (diagnosisResult.status === 'success' ? 'success' : 'failed') : 'skipped',
      assessment_id: diagnosisResult?.assessment_id || null,
      summary: diagnosisResult?.summary || null,
      diagnose_error: diagnosisResult?.error || null,
      script_file: scriptFile.filename,
      script_path: path.relative(ROOT, scriptFile.path),
      file_size: scriptFile.size,
      deploy_job_id: job.job_id,
      elapsed_ms: Date.now() - startedAt.getTime(),
    });

    if (diagnosisResult && diagnosisResult.status !== 'success') {
      return res.status(500).json({
        status: 'error',
        error: diagnosisResult.error || 'Script 결과 진단 실패',
        job_id: job.job_id,
      });
    }

    res.json({
      status: 'success',
      job_id: job.job_id,
      job_status: diagnosisResult ? 'diagnosed' : 'completed',
      assessment_id: diagnosisResult?.assessment_id || null,
      summary: diagnosisResult?.summary || null,
      message: diagnosisResult ? 'Script 결과 업로드 및 진단 완료' : 'Script 결과 업로드 완료',
    });
  } catch (e) {
    console.error('[Script 배포 결과 처리 오류]', e);
    res.status(500).json({ status: 'error', error: e.message });
  }
});


/**
 * 비동기 AI 진단 실행 (Agent Push 후 호출).
 */
async function runAssessmentInBackground({ rawPath, scriptPath, server, assessmentId }) {
  console.log(`[Agent Push] AI 진단 시작: ${server.hostname} (#${server.server_id})`);
  try {
    const rawFileName = rawPath ? path.basename(rawPath) : undefined;
    const scriptFileName = scriptPath ? path.basename(scriptPath) : undefined;
    const source = rawFileName && scriptFileName ? 'both' : (scriptFileName ? 'script' : 'secums');
    const result = await executeAiDiagnosis(server, {
      executed_by: 'agent-push',
      triggered_by: 'agent',
      source,
      raw_file: rawFileName,
      script_file: scriptFileName,
    });
    if (result.status === 'success') {
      console.log(`[Agent Push] AI 진단 완료: assessment_id=${result.assessment_id}`);
    } else {
      console.error(`[Agent Push] AI 진단 실패: ${result.error}`);
    }
  } catch (e) {
    console.error(`[Agent Push] 진단 오류:`, e);
  }
}


// ═════════════════════════════════════════════════════════
// Agent Token 관리 UI (admin/operator)
// ═════════════════════════════════════════════════════════

/**
 * 서버에 새 토큰 발급.
 * 기존 토큰은 무효화됨.
 */
app.post('/servers/:id/agent-token', auth.requireRole('admin', 'operator'), (req, res) => {
  try {
    const rawToken = agentToken.issueToken(kvStorage, req.params.id);
    // 원본 토큰은 단 1회만 반환 (보안)
    res.json({
      status: 'success',
      token: rawToken,
      warning: '이 토큰은 다시 표시되지 않습니다. 즉시 복사해서 Agent에 저장하세요.',
    });
  } catch (e) {
    res.status(400).json({ status: 'error', error: e.message });
  }
});

/**
 * 토큰 폐기.
 */
app.post('/servers/:id/agent-token/revoke', auth.requireRole('admin', 'operator'), (req, res) => {
  try {
    agentToken.revokeToken(kvStorage, req.params.id);
    res.json({ status: 'success' });
  } catch (e) {
    res.status(400).json({ status: 'error', error: e.message });
  }
});


/**
 * Wrapper script 다운로드 (Linux/Unix용 sh 또는 Windows용 ps1).
 *
 * GET /servers/:id/agent-script/linux  → push.sh
 * GET /servers/:id/agent-script/windows → push.ps1
 *
 * 토큰은 발급 시점에 받은 것을 운영자가 직접 채워 넣어야 함.
 * (보안: URL로 토큰 전달 회피)
 */
app.get('/servers/:id/agent-script/:os', auth.requireRole('admin', 'operator'), (req, res) => {
  const servers = loadMock('servers') || [];
  const server = servers.find(s => s.server_id == req.params.id);
  if (!server) return res.status(404).send('서버를 찾을 수 없습니다');
  
  const protocol = req.protocol;
  const host = req.get('host');
  const apiUrl = `${protocol}://${host}/api/collect`;
  
  if (req.params.os === 'linux' || req.params.os === 'unix') {
    res.setHeader('Content-Type', 'text/x-shellscript; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="lsware-push-${server.hostname}.sh"`);
    res.send(generateLinuxScript(apiUrl, server));
  } else if (req.params.os === 'windows') {
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="lsware-push-${server.hostname}.ps1"`);
    res.send(generateWindowsScript(apiUrl, server));
  } else {
    res.status(400).send('지원하지 않는 OS (linux/unix/windows)');
  }
});

function generateLinuxScript(apiUrl, server) {
  const apiBase = apiUrl.replace(/\/collect$/, '');
  return `#!/bin/sh
# ═══════════════════════════════════════════════════════
# LSware Vuln Assessor - Agent Push Script (Linux/Unix)
# 대상: ${server.hostname} (자산: ${server.asset_no || 'N/A'})
# 생성: ${new Date().toISOString().slice(0, 19)}
# ═══════════════════════════════════════════════════════
#
# [설치]
# 1. 이 파일을 점검 대상에 복사: /opt/lsware/push.sh
# 2. 실행 권한: chmod +x /opt/lsware/push.sh
# 3. 토큰 설정: vi /etc/lsware/agent.token
#    (서버 관리 화면에서 발급받은 토큰을 첫 줄에 저장)
# 4. SecuMS Agent가 raw DB를 생성하는 경로 확인
# 5. cron 등록 (매일 새벽 2시 예시):
#    0 2 * * * /opt/lsware/push.sh >> /var/log/lsware/push.log 2>&1
#

# ── 설정 ─────────────────────────────────────────────
ASSESSOR_URL="${apiUrl}"
SCRIPT_JOB_URL="${apiBase}/script-job"
TOKEN_FILE="/etc/lsware/agent.token"
RAW_DB_PATH="${server.remote_raw_path || '/var/lib/secums/data.db'}"
SCRIPT_XML_PATH=""
LOG_FILE="/var/log/lsware/push.log"

# ── 토큰 로드 ────────────────────────────────────────
if [ ! -f "$TOKEN_FILE" ]; then
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: 토큰 파일 없음: $TOKEN_FILE" >&2
  exit 1
fi
TOKEN=$(head -1 "$TOKEN_FILE" | tr -d '\\r\\n ')

# ── 배포 Script 작업 확인/실행 ────────────────────────
run_script_deploy_job() {
  JOB_ENV="/tmp/lsware-script-job.env"
  if ! curl --silent --show-error --fail \\
    -H "X-Agent-Token: $TOKEN" \\
    "$SCRIPT_JOB_URL?format=env" \\
    -o "$JOB_ENV"; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARN: Script 배포 작업 조회 실패" >&2
    return 0
  fi

  . "$JOB_ENV"
  if [ "$STATUS" != "pending" ]; then
    return 0
  fi

  WORK_DIR="/tmp/lsware-script-$JOB_ID"
  mkdir -p "$WORK_DIR"
  SCRIPT_PATH="$WORK_DIR/$SCRIPT_NAME"
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] Script 배포 작업 수신: $JOB_ID ($SCRIPT_NAME)"

  if ! curl --silent --show-error --fail \\
    -H "X-Agent-Token: $TOKEN" \\
    "$DOWNLOAD_URL" \\
    -o "$SCRIPT_PATH"; then
    curl --silent --show-error -X POST "$STATUS_URL" \\
      -H "X-Agent-Token: $TOKEN" \\
      -H "Content-Type: application/json" \\
      -d '{"status":"failed","progress_percent":100,"message":"download failed"}' >/dev/null 2>&1 || true
    return 0
  fi

  chmod +x "$SCRIPT_PATH" 2>/dev/null || true
  curl --silent --show-error -X POST "$STATUS_URL" \\
    -H "X-Agent-Token: $TOKEN" \\
    -H "Content-Type: application/json" \\
    -d '{"status":"running","progress_percent":35,"message":"script downloaded"}' >/dev/null 2>&1 || true

  if [ "\${SCRIPT_ACTION:-deploy_run}" = "deploy_only" ]; then
    curl --silent --show-error -X POST "$STATUS_URL" \\
      -H "X-Agent-Token: $TOKEN" \\
      -H "Content-Type: application/json" \\
      -d '{"status":"completed","progress_percent":100,"message":"script deployed only"}' >/dev/null 2>&1 || true
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Script 배포만 완료: $JOB_ID"
    return 0
  fi

  case "$SCRIPT_PATH" in
    *.sh|*.bash) (cd "$WORK_DIR" && sh "$SCRIPT_PATH" $SCRIPT_ARGS) > "$WORK_DIR/stdout.log" 2> "$WORK_DIR/stderr.log" ;;
    *.py) (cd "$WORK_DIR" && (python3 "$SCRIPT_PATH" $SCRIPT_ARGS || python "$SCRIPT_PATH" $SCRIPT_ARGS)) > "$WORK_DIR/stdout.log" 2> "$WORK_DIR/stderr.log" ;;
    *) (cd "$WORK_DIR" && "$SCRIPT_PATH" $SCRIPT_ARGS) > "$WORK_DIR/stdout.log" 2> "$WORK_DIR/stderr.log" ;;
  esac
  EXIT_CODE=$?

  if [ $EXIT_CODE -ne 0 ]; then
    curl --silent --show-error -X POST "$STATUS_URL" \\
      -H "X-Agent-Token: $TOKEN" \\
      -H "Content-Type: application/json" \\
      -d "{\\"status\\":\\"failed\\",\\"progress_percent\\":100,\\"exit_code\\":$EXIT_CODE,\\"message\\":\\"script execution failed\\"}" >/dev/null 2>&1 || true
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARN: Script 실행 실패: $JOB_ID exit=$EXIT_CODE" >&2
    return 0
  fi
  curl --silent --show-error -X POST "$STATUS_URL" \\
    -H "X-Agent-Token: $TOKEN" \\
    -H "Content-Type: application/json" \\
    -d '{"status":"running","progress_percent":65,"message":"script executed"}' >/dev/null 2>&1 || true

  RESULT_FILE=$(find "$WORK_DIR" -type f -name "\${RESULT_GLOB:-*.xml}" -printf '%T@ %p\\n' 2>/dev/null | sort -nr | head -1 | cut -d' ' -f2-)
  if [ -z "$RESULT_FILE" ]; then
    RESULT_FILE=$(find "$WORK_DIR" -type f -name "*.xml" -printf '%T@ %p\\n' 2>/dev/null | sort -nr | head -1 | cut -d' ' -f2-)
  fi

  if [ -z "$RESULT_FILE" ] || [ ! -f "$RESULT_FILE" ]; then
    curl --silent --show-error -X POST "$STATUS_URL" \\
      -H "X-Agent-Token: $TOKEN" \\
      -H "Content-Type: application/json" \\
      -d '{"status":"failed","progress_percent":100,"message":"result xml not found"}' >/dev/null 2>&1 || true
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARN: Script 결과 XML 없음: $JOB_ID" >&2
    return 0
  fi
  curl --silent --show-error -X POST "$STATUS_URL" \\
    -H "X-Agent-Token: $TOKEN" \\
    -H "Content-Type: application/json" \\
    -d '{"status":"running","progress_percent":80,"message":"uploading result"}' >/dev/null 2>&1 || true

  RESPONSE=$(curl --silent --show-error --fail \\
    -X POST "$UPLOAD_URL" \\
    -H "X-Agent-Token: $TOKEN" \\
    -F "hostname=$(hostname)" \\
    -F "os_type=$(uname -s | tr '[:upper:]' '[:lower:]')" \\
    -F "agent_version=script-deploy-1.0" \\
    -F "scriptfile=@$RESULT_FILE" \\
    2>&1)

  if [ $? -eq 0 ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] Script 결과 업로드 완료: $RESPONSE"
  else
    curl --silent --show-error -X POST "$STATUS_URL" \\
      -H "X-Agent-Token: $TOKEN" \\
      -H "Content-Type: application/json" \\
      -d '{"status":"failed","progress_percent":100,"message":"result upload failed"}' >/dev/null 2>&1 || true
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] WARN: Script 결과 업로드 실패: $RESPONSE" >&2
  fi
}

run_script_deploy_job

# ── Script XML 탐색 ─────────────────────────────────
for dir in /opt/lsware/secums/agent/bin /opt/lswaer/secums/agent/bin /var/lib/secums /var/lib/secums/script; do
  [ -d "$dir" ] || continue
  for f in "$dir"/*-s-*.xml "$dir"/script*.xml "$dir"/*.xml; do
    [ -f "$f" ] || continue
    if [ -z "$SCRIPT_XML_PATH" ] || [ "$f" -nt "$SCRIPT_XML_PATH" ]; then
      SCRIPT_XML_PATH="$f"
    fi
  done
done

# ── 수집 파일 확인 ──────────────────────────────────
if [ ! -f "$RAW_DB_PATH" ] && [ -z "$SCRIPT_XML_PATH" ]; then
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: Raw DB와 Script XML 모두 없음" >&2
  echo "  RAW_DB_PATH=$RAW_DB_PATH" >&2
  echo "  Script XML search dirs: /opt/lsware/secums/agent/bin /opt/lswaer/secums/agent/bin /var/lib/secums /var/lib/secums/script" >&2
  exit 1
fi

# ── 업로드 ───────────────────────────────────────────
echo "[$(date '+%Y-%m-%d %H:%M:%S')] 시작: $(hostname) → $ASSESSOR_URL"

if [ -f "$RAW_DB_PATH" ] && [ -n "$SCRIPT_XML_PATH" ]; then
  RESPONSE=$(curl --silent --show-error --fail \\
    --max-time 60 \\
    -X POST "$ASSESSOR_URL" \\
    -H "X-Agent-Token: $TOKEN" \\
    -F "hostname=$(hostname)" \\
    -F "os_type=$(uname -s | tr '[:upper:]' '[:lower:]')" \\
    -F "os_version=$(uname -r)" \\
    -F "agent_version=secums-1.0" \\
    -F "dbfile=@$RAW_DB_PATH" \\
    -F "scriptfile=@$SCRIPT_XML_PATH" \\
    2>&1)
elif [ -f "$RAW_DB_PATH" ]; then
  RESPONSE=$(curl --silent --show-error --fail \\
    --max-time 60 \\
    -X POST "$ASSESSOR_URL" \\
    -H "X-Agent-Token: $TOKEN" \\
    -F "hostname=$(hostname)" \\
    -F "os_type=$(uname -s | tr '[:upper:]' '[:lower:]')" \\
    -F "os_version=$(uname -r)" \\
    -F "agent_version=secums-1.0" \\
    -F "dbfile=@$RAW_DB_PATH" \\
    2>&1)
else
  RESPONSE=$(curl --silent --show-error --fail \\
    --max-time 60 \\
    -X POST "$ASSESSOR_URL" \\
    -H "X-Agent-Token: $TOKEN" \\
    -F "hostname=$(hostname)" \\
    -F "os_type=$(uname -s | tr '[:upper:]' '[:lower:]')" \\
    -F "os_version=$(uname -r)" \\
    -F "agent_version=secums-1.0" \\
    -F "scriptfile=@$SCRIPT_XML_PATH" \\
    2>&1)
fi

if [ $? -eq 0 ]; then
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] 성공: $RESPONSE"
  exit 0
else
  echo "[$(date '+%Y-%m-%d %H:%M:%S')] 실패: $RESPONSE" >&2
  exit 1
fi
`;
}

function generateWindowsScript(apiUrl, server) {
  const apiBase = apiUrl.replace(/\/collect$/, '');
  return `# ═══════════════════════════════════════════════════════
# LSware Vuln Assessor - Agent Push Script (Windows)
# 대상: ${server.hostname} (자산: ${server.asset_no || 'N/A'})
# 생성: ${new Date().toISOString().slice(0, 19)}
# ═══════════════════════════════════════════════════════
#
# [설치]
# 1. 이 파일을 점검 대상에 복사: C:\\LSware\\push.ps1
# 2. 토큰 설정: C:\\LSware\\agent.token 파일에 토큰 저장
# 3. 실행 정책 (관리자):
#    Set-ExecutionPolicy -Scope LocalMachine RemoteSigned
# 4. SecuMS Windows Agent가 raw DB 생성하는 경로 확인
# 5. 작업 스케줄러 등록 (매일 새벽 2시):
#    schtasks /create /tn "LSware Push" /tr "powershell -File C:\\LSware\\push.ps1" /sc daily /st 02:00
#

# ── 설정 ─────────────────────────────────────────────
$AssessorUrl = "${apiUrl}"
$ScriptJobUrl = "${apiBase}/script-job"
$TokenFile = "C:\\LSware\\agent.token"
$RawDbPath = "${String(server.remote_raw_path || 'C:\\Program Files (x86)\\lsware\\secums\\agent\\bin\\exportData-SSWindows.db').replace(/"/g, '`"')}"
$LogFile = "C:\\LSware\\Logs\\push.log"
$ScriptSearchDirs = @(
  "C:\\Program Files (x86)\\lsware\\secums\\agent\\bin",
  "C:\\Program Files\\lsware\\secums\\agent\\bin",
  "C:\\LSware\\SecuMS"
)

# ── 로그 함수 ────────────────────────────────────────
function Write-Log($msg) {
  $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
  $line = "[$ts] $msg"
  Write-Host $line
  if (Test-Path (Split-Path $LogFile)) {
    Add-Content -Path $LogFile -Value $line
  }
}

# ── 토큰 로드 ────────────────────────────────────────
if (-not (Test-Path $TokenFile)) {
  Write-Log "ERROR: 토큰 파일 없음: $TokenFile"
  exit 1
}
$Token = (Get-Content $TokenFile -First 1).Trim()

# ── 배포 Script 작업 확인/실행 ────────────────────────
function Invoke-ScriptDeployJob {
  try {
    $job = Invoke-RestMethod -Uri $ScriptJobUrl -Method GET -Headers @{ "X-Agent-Token" = $Token } -TimeoutSec 30
  }
  catch {
    Write-Log "WARN: Script 배포 작업 조회 실패: $($_.Exception.Message)"
    return
  }

  if ($null -eq $job -or $job.status -ne "pending") {
    return
  }

  $jobId = [string]$job.job_id
  $workRoot = "C:\\LSware\\Jobs"
  $workDir = Join-Path $workRoot $jobId
  New-Item -ItemType Directory -Force -Path $workDir | Out-Null
  $scriptName = if ([string]::IsNullOrWhiteSpace($job.script_name)) { "deploy-script.ps1" } else { [IO.Path]::GetFileName([string]$job.script_name) }
  $scriptPath = Join-Path $workDir $scriptName
  Write-Log "Script 배포 작업 수신: $jobId ($scriptName)"

  try {
    Invoke-WebRequest -Uri $job.download_url -Headers @{ "X-Agent-Token" = $Token } -OutFile $scriptPath -TimeoutSec 60
    $body = @{ status = "running"; progress_percent = 35; message = "script downloaded" } | ConvertTo-Json -Compress
    Invoke-RestMethod -Uri $job.status_url -Method POST -Headers @{ "X-Agent-Token" = $Token } -ContentType "application/json" -Body $body -TimeoutSec 20 | Out-Null
  }
  catch {
    $body = @{ status = "failed"; progress_percent = 100; message = "download failed: $($_.Exception.Message)" } | ConvertTo-Json -Compress
    try { Invoke-RestMethod -Uri $job.status_url -Method POST -Headers @{ "X-Agent-Token" = $Token } -ContentType "application/json" -Body $body -TimeoutSec 20 | Out-Null } catch {}
    Write-Log "WARN: Script 다운로드 실패: $($_.Exception.Message)"
    return
  }

  if ([string]$job.script_action -eq "deploy_only") {
    $body = @{ status = "completed"; progress_percent = 100; message = "script deployed only" } | ConvertTo-Json -Compress
    try { Invoke-RestMethod -Uri $job.status_url -Method POST -Headers @{ "X-Agent-Token" = $Token } -ContentType "application/json" -Body $body -TimeoutSec 20 | Out-Null } catch {}
    Write-Log "Script 배포만 완료: $jobId"
    return
  }

  if ([IO.Path]::GetExtension($scriptPath).ToLowerInvariant() -eq ".zip") {
    try {
      $packageDir = Join-Path $workDir "package"
      New-Item -ItemType Directory -Force -Path $packageDir | Out-Null
      Expand-Archive -Path $scriptPath -DestinationPath $packageDir -Force
      $scriptCandidates = Get-ChildItem -Path $packageDir -Recurse -File -ErrorAction SilentlyContinue |
        Where-Object { @(".bat", ".cmd", ".ps1", ".py").Contains($_.Extension.ToLowerInvariant()) }
      $packageScript = [string]$job.package_script
      if (-not [string]::IsNullOrWhiteSpace($packageScript)) {
        $wanted = $packageScript.Replace([char]92, "/").ToLowerInvariant()
        $scriptMatch = $scriptCandidates |
          Where-Object { $_.FullName.Replace([char]92, "/").ToLowerInvariant().EndsWith($wanted) -or $_.Name.ToLowerInvariant() -eq $wanted } |
          Select-Object -First 1
      }
      else {
        $scriptMatch = $scriptCandidates |
          Sort-Object @{ Expression = { if ($_.BaseName.ToLowerInvariant().Contains("fsi_win_ai")) { 0 } elseif ($_.BaseName.ToLowerInvariant().Contains("fsi_win")) { 1 } else { 9 } } }, FullName |
          Select-Object -First 1
      }
      if ($null -eq $scriptMatch) { throw "ZIP package script not found" }
      $scriptPath = $scriptMatch.FullName
      Write-Log "ZIP package extracted; script=$scriptPath"
    }
    catch {
      $body = @{ status = "failed"; progress_percent = 100; message = "zip package extract failed: $($_.Exception.Message)" } | ConvertTo-Json -Compress
      try { Invoke-RestMethod -Uri $job.status_url -Method POST -Headers @{ "X-Agent-Token" = $Token } -ContentType "application/json" -Body $body -TimeoutSec 20 | Out-Null } catch {}
      Write-Log "WARN: ZIP package 처리 실패: $($_.Exception.Message)"
      return
    }
  }

  $stdout = Join-Path $workDir "stdout.log"
  $stderr = Join-Path $workDir "stderr.log"
  $argsLine = [string]$job.script_args
  $ext = [IO.Path]::GetExtension($scriptPath).ToLowerInvariant()
  $scriptDir = Split-Path $scriptPath -Parent
  try {
    if ($ext -eq ".ps1") {
      $proc = Start-Process powershell.exe -ArgumentList @("-ExecutionPolicy", "Bypass", "-File", $scriptPath, $argsLine) -WorkingDirectory $scriptDir -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    }
    elseif ($ext -eq ".bat" -or $ext -eq ".cmd") {
      $proc = Start-Process cmd.exe -ArgumentList @("/c", "\`"$scriptPath\`" $argsLine") -WorkingDirectory $scriptDir -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    }
    elseif ($ext -eq ".py") {
      $proc = Start-Process python.exe -ArgumentList @($scriptPath, $argsLine) -WorkingDirectory $scriptDir -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    }
    else {
      $proc = Start-Process $scriptPath -ArgumentList $argsLine -WorkingDirectory $scriptDir -Wait -PassThru -WindowStyle Hidden -RedirectStandardOutput $stdout -RedirectStandardError $stderr
    }
  }
  catch {
    $body = @{ status = "failed"; progress_percent = 100; message = "script start failed: $($_.Exception.Message)" } | ConvertTo-Json -Compress
    try { Invoke-RestMethod -Uri $job.status_url -Method POST -Headers @{ "X-Agent-Token" = $Token } -ContentType "application/json" -Body $body -TimeoutSec 20 | Out-Null } catch {}
    Write-Log "WARN: Script 실행 시작 실패: $($_.Exception.Message)"
    return
  }

  if ($proc.ExitCode -ne 0) {
    $body = @{ status = "failed"; progress_percent = 100; exit_code = $proc.ExitCode; message = "script execution failed" } | ConvertTo-Json -Compress
    try { Invoke-RestMethod -Uri $job.status_url -Method POST -Headers @{ "X-Agent-Token" = $Token } -ContentType "application/json" -Body $body -TimeoutSec 20 | Out-Null } catch {}
    Write-Log "WARN: Script 실행 실패: $jobId exit=$($proc.ExitCode)"
    return
  }

  $body = @{ status = "running"; progress_percent = 65; message = "script executed" } | ConvertTo-Json -Compress
  try { Invoke-RestMethod -Uri $job.status_url -Method POST -Headers @{ "X-Agent-Token" = $Token } -ContentType "application/json" -Body $body -TimeoutSec 20 | Out-Null } catch {}

  $resultGlob = if ([string]::IsNullOrWhiteSpace($job.result_glob)) { "*.xml" } else { [string]$job.result_glob }
  $resultFile = Get-ChildItem -Path $workDir -Filter $resultGlob -File -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  if ($null -eq $resultFile) {
    $resultFile = Get-ChildItem -Path $workDir -Filter "*.xml" -File -Recurse -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
  }

  if ($null -eq $resultFile) {
    $body = @{ status = "failed"; progress_percent = 100; message = "result xml not found" } | ConvertTo-Json -Compress
    try { Invoke-RestMethod -Uri $job.status_url -Method POST -Headers @{ "X-Agent-Token" = $Token } -ContentType "application/json" -Body $body -TimeoutSec 20 | Out-Null } catch {}
    Write-Log "WARN: Script 결과 XML 없음: $jobId"
    return
  }

  try {
    $body = @{ status = "running"; progress_percent = 80; message = "uploading result" } | ConvertTo-Json -Compress
    try { Invoke-RestMethod -Uri $job.status_url -Method POST -Headers @{ "X-Agent-Token" = $Token } -ContentType "application/json" -Body $body -TimeoutSec 20 | Out-Null } catch {}
    $form = @{
      hostname = $env:COMPUTERNAME
      os_type = "windows"
      agent_version = "script-deploy-win-1.0"
      scriptfile = Get-Item $resultFile.FullName
    }
    $response = Invoke-RestMethod -Uri $job.upload_url -Method POST -Headers @{ "X-Agent-Token" = $Token } -Form $form -TimeoutSec 120
    Write-Log "Script 결과 업로드 완료: $($response | ConvertTo-Json -Compress)"
  }
  catch {
    $body = @{ status = "failed"; progress_percent = 100; message = "result upload failed: $($_.Exception.Message)" } | ConvertTo-Json -Compress
    try { Invoke-RestMethod -Uri $job.status_url -Method POST -Headers @{ "X-Agent-Token" = $Token } -ContentType "application/json" -Body $body -TimeoutSec 20 | Out-Null } catch {}
    Write-Log "WARN: Script 결과 업로드 실패: $($_.Exception.Message)"
  }
}

Invoke-ScriptDeployJob

# ── Script XML 탐색 ─────────────────────────────────
$ScriptXmlCandidates = foreach ($dir in $ScriptSearchDirs) {
  if (Test-Path $dir) {
    Get-ChildItem -Path (Join-Path $dir "*") -Include "*-s-*.xml", "script*.xml", "*.xml" -File -ErrorAction SilentlyContinue
  }
}
$ScriptXmlPath = $ScriptXmlCandidates | Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName

# ── 수집 파일 확인 ──────────────────────────────────
$HasRawDb = Test-Path $RawDbPath
$HasScriptXml = -not [string]::IsNullOrWhiteSpace($ScriptXmlPath)
if (-not $HasRawDb -and -not $HasScriptXml) {
  Write-Log "ERROR: Raw DB와 Script XML 모두 없음. Raw=$RawDbPath"
  exit 1
}

# ── 업로드 ───────────────────────────────────────────
Write-Log "시작: $env:COMPUTERNAME -> $AssessorUrl"

try {
  $form = @{
    hostname = $env:COMPUTERNAME
    os_type = "windows"
    os_version = (Get-CimInstance Win32_OperatingSystem).Version
    agent_version = "secums-win-1.0"
  }
  if ($HasRawDb) {
    $form.dbfile = Get-Item $RawDbPath
  }
  if ($HasScriptXml) {
    $form.scriptfile = Get-Item $ScriptXmlPath
  }
  
  $response = Invoke-RestMethod -Uri $AssessorUrl \`
    -Method POST \`
    -Headers @{ "X-Agent-Token" = $Token } \`
    -Form $form \`
    -TimeoutSec 60
  
  Write-Log "성공: $($response | ConvertTo-Json -Compress)"
  exit 0
}
catch {
  Write-Log "실패: $($_.Exception.Message)"
  exit 1
}
`;
}


app.listen(PORT, () => {
    if (kvStorage.mode === 'mock' || storageStatus.status === 'fallback') {
      seedMockData();
    }
    
    const modeLabel = storageStatus.status === 'fallback' ? 'Mock (MySQL 폴백)' 
                    : kvStorage.mode === 'mysql' ? 'MySQL'
                    : 'Mock';
    
    console.log(`\n╔════════════════════════════════════════════════════════╗`);
    console.log(`║   Vuln Assessor (${modeLabel} Mode)`.padEnd(57) + '║');
    console.log(`║   → http://localhost:${PORT}`.padEnd(57) + '║');
    console.log(`╚════════════════════════════════════════════════════════╝\n`);
    
    if (kvStorage.mode === 'mysql' && storageStatus.status === 'ok') {
      console.log('MySQL 모드:');
      console.log(`  ✓ 연결: ${require('./src/config').db.host}:${require('./src/config').db.port}/${require('./src/config').db.database}`);
      console.log('  ✓ _kv_store 테이블 사용');
      console.log('  ✓ 캐시 프리로드 완료');
    } else {
      console.log('Mock 모드:');
      console.log('  ✓ DB 없이 파일 기반 저장 (data/mock/*.json)');
      console.log('  ✓ Raw SQLite는 data/uploads/exportData-SSUnix.db 자동 사용');
    }
    console.log('  ✓ LLM_PROVIDER=mock (외부 호출 없음)');
    console.log('');
    console.log('전환: DB_MODE=mysql 환경변수로 MySQL 모드 활성화');
  });
}

startServer().catch(e => {
  console.error('서버 시작 실패:', e);
  process.exit(1);
});

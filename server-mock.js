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

// 콘솔 로그에 시각 prefix [HH:MM:SS] — 스케줄러/진단 로그가 언제 찍혔는지 추적용
{
  const _pad = (n) => String(n).padStart(2, '0');
  const _ts = () => { const d = new Date(); return `[${_pad(d.getHours())}:${_pad(d.getMinutes())}:${_pad(d.getSeconds())}]`; };
  const _log = console.log.bind(console);
  const _err = console.error.bind(console);
  console.log = (...a) => _log(_ts(), ...a);
  console.error = (...a) => _err(_ts(), ...a);
}

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
  // 서버 목록은 servers.csv(실 관리 대상)를 항상 기준으로 동기화. 기존 헬스 데이터는 overlay 유지.
  try {
    const { getTargetServersFromFile } = require('./src/services/scheduler');
    const targets = getTargetServersFromFile() || [];
    if (targets.length) {
      const prev = loadMock('servers') || [];
      const merged = targets.map(t => {
        const p = prev.find(s => String(s.server_id) === String(t.server_id) || s.hostname === t.hostname) || {};
        const isWin = String(t.os || '').includes('win');
        return {
          server_id: Number(t.server_id) || t.server_id,
          name: t.hostname, hostname: t.hostname, ip_address: t.ip, os_type: t.os, asset_no: t.asset_no,
          service_name: p.service_name || (isWin ? 'Windows 점검 대상' : 'Linux 점검 대상 (CentOS 7)'),
          ssh_port: isWin ? 5985 : 22, ssh_user: t.username,
          ssh_status: p.ssh_status, ssh_rtt: p.ssh_rtt, agent_status: p.agent_status, agent_version: p.agent_version,
          cpu_usage_pct: p.cpu_usage_pct, mem_usage_pct: p.mem_usage_pct, disk_usage_pct: p.disk_usage_pct,
          overall_health: p.overall_health, last_collected_at: p.last_collected_at, last_diagnosed_at: p.last_diagnosed_at, checked_at: p.checked_at,
        };
      });
      saveMock('servers', merged);
    } else if (!loadMock('servers')) {
      saveMock('servers', require('./scripts/seed-servers.json'));
    }
  } catch (_) {
    if (!loadMock('servers')) saveMock('servers', require('./scripts/seed-servers.json'));
  }
  if (!loadMock('schedules')) {
    saveMock('schedules', require('./scripts/seed-schedules.json'));
  }
  console.log('✓ Mock data seeded (servers ← servers.csv)');
}

// 예약/알림/실행이력 정리 — 모드 무관(MySQL 포함) 항상 실행. 가짜 데이터(DMZ/DB·jessy62·7대 등)를 servers.csv 기준으로 정리.
function reconcileMockData() {
  try {
    const { getTargetServersFromFile } = require('./src/services/scheduler');
    const targets = getTargetServersFromFile() || [];
    const validHosts = new Set(targets.map(t => t.hostname));
    const cnt = targets.length || 0;

    // 예약 진단: 가짜 시드(dmz/db 그룹·5대+ 등) 감지 시 servers.csv 기준 현실값으로 교체
    const cur = loadMock('schedules') || [];
    const looksFake = cur.length === 0 ||
      cur.some(s => ['dmz', 'db', 'web'].includes(s.server_group) || s.target_count >= 5 ||
        ['DMZ 시간별 점검', 'DB 서버 주간', '긴급 CVE 발생 시'].includes(s.name));
    if (looksFake) {
      saveMock('schedules', [
        { schedule_id: 1, name: '야간 전체 점검', description: '매일 02:00 전체 대상 서버 진단',
          cron_expr: '0 2 * * *', cron_humanized: '매일 02:00', policy: '전자금융기반시설_2026',
          server_scope: 'all', target_count: cnt, ruleset_ver: 'v2.0', engine: 'ai_llm',
          enabled: true, notify_on_vuln: true, notify_on_failure: true,
          created_by: 'admin', last_run_at: null, last_status: null, next_run_at: '-' },
        { schedule_id: 2, name: '주간 점검 (일요일)', description: '매주 일요일 03:00 전체 대상',
          cron_expr: '0 3 * * 0', cron_humanized: '매주 일요일 03:00', policy: '전자금융기반시설_2026',
          server_scope: 'all', target_count: cnt, ruleset_ver: 'v2.0', engine: 'ai_llm',
          enabled: false, notify_on_vuln: true, notify_on_failure: true,
          created_by: 'admin', last_run_at: null, last_status: null, next_run_at: '-' },
      ]);
    }

    // 알림: servers.csv에 없는 호스트(예: jessy62) 참조분 제거
    const notis = loadMock('notifications') || [];
    const cleaned = notis.filter(n => {
      const hosts = (JSON.stringify(n).match(/jessy\d+/g) || []);
      return hosts.every(h => validHosts.has(h));
    });
    if (cleaned.length !== notis.length) saveMock('notifications', cleaned);

    // 실행 이력: 가짜 산물(DMZ/DB 서버, jessy62 등 비대상 호스트) 제거
    const runs = loadMock('schedule_runs') || [];
    const runsClean = runs.filter(r => {
      const j = JSON.stringify(r);
      if (/DMZ|DB 서버/i.test(j)) return false;
      const hosts = (j.match(/jessy\d+/g) || []);
      return hosts.every(h => validHosts.has(h));
    });
    if (runsClean.length !== runs.length) saveMock('schedule_runs', runsClean);
    console.log('✓ reconcileMockData: 예약/알림/실행이력 정리 완료');
  } catch (e) { console.log('reconcileMockData skip:', e.message); }
}

// ─── Express 설정 ────────────────────────────────────────
app.set('view engine', 'ejs');
app.set('views', path.join(ROOT, 'src/views'));

// 모든 뷰 공통 시간 포맷 헬퍼 — ms를 사람이 읽기 쉽게 (<1초=ms, 분/초, 시간/분)
app.locals.fmtMs = function (ms) {
  ms = Number(ms) || 0;
  if (ms < 1000) return ms + 'ms';
  let s = Math.round(ms / 1000);
  if (s < 60) return s + '초';
  let m = Math.floor(s / 60), ss = s % 60;
  if (m < 60) return ss ? `${m}분 ${ss}초` : `${m}분`;
  let h = Math.floor(m / 60), mm = m % 60;
  return mm ? `${h}시간 ${mm}분` : `${h}시간`;
};
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

// ─── 감사 로그 — 주요 변경 액션 자동 기록 ──────────────────────
function logAudit(entry) {
  try {
    const logs = loadMock('audit_logs') || [];
    logs.unshift({ id: (logs.length ? logs[0].id : 0) + 1, ...entry });
    if (logs.length > 1000) logs.length = 1000;
    saveMock('audit_logs', logs);
  } catch (_) {}
}
const AUDIT_RULES = [
  { re: /^\/login$/, action: '로그인' },
  { re: /^\/logout$/, action: '로그아웃' },
  { re: /^\/diagnosis\/(ai-run|llm-run|fetch-and-run|run)/, action: '진단 실행' },
  { re: /^\/collection\/script-deploy/, action: '스크립트 배포·진단' },
  { re: /^\/exceptions\/save/, action: '예외 신청' },
  { re: /\/exceptions\/\d+\/(approve|extend)/, action: '예외 승인/연장' },
  { re: /^\/exclusions\/save/, action: '제외 등록' },
  { re: /^\/remediation/, action: '조치 변경' },
  { re: /^\/schedules\/(save|\d+\/(update|delete|toggle|run-now))/, action: '예약 변경' },
  { re: /\/healthcheck/, action: '헬스체크' },
];
app.use((req, res, next) => {
  if (req.method === 'POST') {
    const rule = AUDIT_RULES.find(r => r.re.test(req.path));
    if (rule) {
      const b = req.body || {};
      const target = b.hostname || b.host || b.server_id || b.rule_id || b.username || (req.params && req.params.id) || req.path;
      res.on('finish', () => {
        logAudit({
          at: new Date().toISOString().slice(0, 19).replace('T', ' '),
          user: (req.session && req.session.username) || b.username || '-',
          role: (req.session && req.session.role) || '-',
          action: rule.action,
          target: String(target).slice(0, 60),
          result: res.statusCode < 400 ? '성공' : '실패',
          ip: String(req.headers['x-forwarded-for'] || (req.socket && req.socket.remoteAddress) || '').replace('::ffff:', ''),
        });
      });
    }
  }
  next();
});

// 감사 로그 조회
app.get('/audit', (req, res) => {
  const all = loadMock('audit_logs') || [];
  const q = (req.query.q || '').toString().toLowerCase();
  const act = (req.query.action || '').toString();
  let logs = all;
  if (q) logs = logs.filter(l => JSON.stringify(l).toLowerCase().includes(q));
  if (act) logs = logs.filter(l => l.action === act);
  const actions = [...new Set(all.map(l => l.action))].sort();
  res.render('audit/index', {
    activeMenu: 'audit',
    now: new Date().toISOString().slice(0, 16).replace('T', ' '),
    logs: logs.slice(0, 300), total: all.length, actions, q, act,
  });
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
  // 로그인 첫 화면은 항상 대시보드 (from 무시)
  res.redirect('/');
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

// 점검항목 목록(크로스워크 SRV+제목) — 예외/제외 드롭다운용. 모듈 스코프(여러 라우트 공용).
function buildCheckItemList() {
  try {
    const cw = require('./src/services/threeWayService').loadCrosswalk();
    const seen = new Set();
    return [...(cw.linux || []), ...(cw.windows || [])]
      .filter(x => x && x.srv && x.title && !seen.has(x.srv) && seen.add(x.srv))
      .map(x => ({ srv: x.srv, title: x.title }))
      .sort((a, b) => String(a.srv).localeCompare(String(b.srv), undefined, { numeric: true }));
  } catch (_) { return []; }
}

// ─── 점검현황 / 보안등급 (servers.csv 실데이터) ───────────────────────────
// 서버별 점검 여부·취약/양호·등급(양호÷전체) 산출. 점검현황·보안등급 화면 공통.
function buildAgentGrades() {
  const servers = loadMock('servers') || [];
  const diagnoses = loadMock('diagnoses') || [];
  const ts = (d) => { const t = d.executed_at || d.completed_at || d.started_at; return t ? new Date(String(t).replace(' ', 'T')).getTime() : 0; };
  const verdictOf = (r) => r.status || r.ai_verdict;
  const letter = (p) => p == null ? '-' : p >= 90 ? 'A' : p >= 80 ? 'B' : p >= 70 ? 'C' : p >= 60 ? 'D' : 'F';
  return servers.map(s => {
    const ds = diagnoses.filter(d => d.hostname === s.hostname).sort((a, b) => ts(b) - ts(a));
    const latest = ds[0];
    const results = latest ? (latest.results || []) : [];
    const total = results.length;
    const vuln = results.filter(r => verdictOf(r) === '취약').length;
    const safe = results.filter(r => verdictOf(r) === '양호').length;
    const checked = !!latest;
    const gradePct = total ? Math.round(safe / total * 100) : null;
    return {
      hostname: s.hostname, os_type: s.os_type, ip_address: s.ip_address,
      operator: s.ssh_user || 'admin', domain: 'Default', channel: 'Agentless',
      checked,
      vuln_count: checked ? vuln : null,
      total_count: total, safe_count: safe,
      score: total ? safe : null, score_total: total || null,   // 등급(점수/총점) = 양호/전체
      grade_pct: gradePct, grade: letter(gradePct),
      last_at: latest ? (latest.executed_at || latest.completed_at || latest.started_at) : null,
      assessment_id: latest ? latest.assessment_id : null,
    };
  });
}

// 점검현황 — OS별 전체/미점검 + 에이전트 목록
app.get('/inspection-status', (req, res) => {
  const agents = buildAgentGrades();
  const byOs = {};
  agents.forEach(a => {
    const k = (a.os_type || '기타');
    byOs[k] = byOs[k] || { os: k, total: 0, unchecked: 0 };
    byOs[k].total++; if (!a.checked) byOs[k].unchecked++;
  });
  res.render('inspection/status', {
    activeMenu: 'inspection-status',
    now: new Date().toISOString().slice(0, 10),
    agents, osSummary: Object.values(byOs),
    checkedCount: agents.filter(a => a.checked).length, totalCount: agents.length,
  });
});

// 보안등급 — 서버별 등급(점수/총점)·취약점 개수 목록
app.get('/security-grade', (req, res) => {
  res.render('security/grade', {
    activeMenu: 'security-grade',
    now: new Date().toISOString().slice(0, 10),
    agents: buildAgentGrades(),
  });
});

// 서버별 점검 이력 상세 — 한 호스트의 과거 진단 추이(진단일시·소요·취약/양호·준수율)
function buildServerHistory(host) {
  const servers = loadMock('servers') || [];
  const server = servers.find(s => s.hostname === host) || { hostname: host };
  const ts = (d) => { const t = d.executed_at || d.completed_at || d.started_at; return t ? new Date(String(t).replace(' ', 'T')).getTime() : 0; };
  const verdictOf = (r) => r.status || r.ai_verdict;
  const rows = (loadMock('diagnoses') || [])
    .filter(d => d.hostname === host)
    .sort((a, b) => ts(b) - ts(a))
    .map(d => {
      const results = d.results || [];
      const total = results.length;
      const safe = results.filter(r => verdictOf(r) === '양호').length;
      const na = results.filter(r => { const x = verdictOf(r); return x === '판정불가' || x === 'N/A'; }).length;
      return {
        assessment_id: d.assessment_id,
        started_at: d.started_at || d.executed_at || d.completed_at,
        finished_at: d.completed_at || d.executed_at,
        elapsed_ms: d.elapsed_ms,
        diagnose_type: d.diagnose_type,   // ai / llm
        source_type: d.source_type,       // secums / script
        total, vuln: results.filter(r => verdictOf(r) === '취약').length, safe, na,
        grade_pct: total ? Math.round(safe / total * 100) : null,
      };
    });
  return { server, rows };
}

app.get('/security-grade/:host', (req, res) => {
  const { server, rows } = buildServerHistory(req.params.host);
  res.render('security/grade_detail', {
    activeMenu: 'security-grade',
    now: new Date().toISOString().slice(0, 10),
    server, rows,
  });
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

// 대시보드(/) 라우트는 startServer() 내부에 등록 — buildDashboardData 가 그 스코프에 있어 스코프 일치 필요

// 진단 관리
app.get('/diagnosis', (req, res) => {
  const diagnoses = loadMock('diagnoses') || [];
  // KPI 실데이터 계산 (하드코딩 제거)
  const ts = (d) => { const t = d.executed_at || d.completed_at || d.started_at; return t ? new Date(String(t).replace(' ', 'T')).getTime() : 0; };
  const sevenAgo = Date.now() - 7 * 86400000;
  const recent = diagnoses.filter(d => ts(d) >= sevenAgo);
  const isFail = (d) => d.status === 'failed' || d.status === '실패' || d.fetch_status === 'failed' || d.diagnose_status === 'failed';
  const isRunning = (d) => d.status === 'running' || d.status === 'diagnosing' || d.status === '실행중';
  const elapsed = diagnoses.map(d => Number(d.elapsed_ms) || 0).filter(v => v > 0).slice(0, 30);
  const avgElapsedMs = elapsed.length ? Math.round(elapsed.reduce((a, b) => a + b, 0) / elapsed.length) : 0;
  const kpi = {
    total7d: recent.length,
    failed7d: recent.filter(isFail).length,
    success7d: recent.filter(d => !isFail(d) && !isRunning(d)).length,
    running: diagnoses.filter(isRunning).length,
    avgElapsedMs,
  };
  res.render('diagnosis/index', {
    activeMenu: 'diagnosis',
    diagnoses,
    kpi,
    failPatterns: [],
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
  // 기본 = ai_llm (mock 1차 + LLM 2차). 빠른 점검이 필요하면 명시적으로 'ai'(mock) 선택.
  if (value === 'ai') return 'ai';          // 빠른 옵션 (mock 단독)
  if (value === 'llm') return 'llm';        // LLM 전수 (가장 느림/정밀)
  return 'ai_llm';                          // 기본값 (미지정·ai_llm·both 모두 여기로)
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

// 날짜 폴더 포함해 파일 후보 경로 생성.
function _withDatedDirs(filename) {
  const out = [path.join(UPLOAD_DIR, filename)];
  try {
    for (const d of fs.readdirSync(UPLOAD_DIR)) {
      if (/^\d{4}-\d{2}-\d{2}$/.test(d)) out.push(path.join(UPLOAD_DIR, d, filename));
    }
  } catch (_) {}
  return out;
}

// script XML 의 OS 판별 (헤더만 살짝 읽음).
function _sniffScriptOs(xmlPath) {
  try {
    const head = fs.readFileSync(xmlPath, 'utf8').slice(0, 600).toLowerCase();
    if (/<os>\s*windows|os_family=windows|windows nt/.test(head)) return 'windows';
    if (/<os>\s*(linux|unix)|os_family=linux/.test(head)) return 'linux';
  } catch (_) {}
  return 'unknown';
}

// CVE 진단 소스 해석 — 이 서버 고유 데이터만 사용(전역 fallback 금지).
// 반환: { platform: 'linux'|'windows', kind: 'secums_db'|'script_xml'|null, path }
function resolveCveSource(diag, server) {
  const host = diag.hostname || server.hostname;
  const osType = String(server.os_type || '').toLowerCase();

  // 1) SecuMS Unix(RPM) DB
  const unixCands = [];
  if (diag.secums_file) unixCands.push(..._withDatedDirs(diag.secums_file));
  if (host) unixCands.push(..._withDatedDirs(`${host}_exportData-SSUnix.db`));
  unixCands.push(path.join(ROOT, 'data/mock/raw', `${server.server_id}.db`));
  for (const p of unixCands) {
    if (p && fs.existsSync(p)) return { platform: 'linux', kind: 'secums_db', path: p };
  }

  // 2) SecuMS Windows DB (W_HOTFIX 등) — 구조화 핫픽스가 있어 우선.
  if (host) {
    for (const w of _withDatedDirs(`${host}_exportData-SSWindows.db`)) {
      if (fs.existsSync(w)) return { platform: 'windows', kind: 'secums_db', path: w };
    }
  }

  // 3) 배포 스크립트 XML (이 호스트) — OS 판별 후 사용.
  try {
    const xml = aiAssessment.resolveScriptXmlPath(
      { hostname: host, server_id: server.server_id },
      { script_file: diag.script_file }
    );
    if (xml && fs.existsSync(xml)) {
      const os = _sniffScriptOs(xml);
      if (os === 'windows') return { platform: 'windows', kind: 'script_xml', path: xml };
      // linux script XML 은 rpm 인벤토리가 없어 CVE 진단 불가(아래에서 안내).
      return { platform: 'linux', kind: 'script_xml', path: xml };
    }
  } catch (_) {}

  // 4) 데이터 없음
  return { platform: osType.includes('win') ? 'windows' : 'linux', kind: null, path: null };
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
    
    const llm = String(req.body?.llm || '').toLowerCase();
    console.log(`[웹] [${target.hostname}] ${source} 수집 + 진단 실행 요청, LLM=${llm || '사내'} (by ${req.session?.username || '?'})`);
    const result = await runScheduledDiagnosis(target, { source, llm });
    
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

    // 서버를 먼저 확인 (표준 모드는 OS로 스크립트를 정하므로 파일보다 서버가 먼저)
    const hostname = req.body.hostname || '';
    const server = findServerForUpload(req.body.server_id, hostname);
    if (!server) {
      return res.status(404).json({ status: 'failed', error: '서버를 찾을 수 없습니다. hostname을 입력해 주세요.' });
    }
    const deployTarget = withScriptDeployAuthOverrides(server, req.body);
    const osType = String(deployTarget.os || deployTarget.os_type || '').toLowerCase();
    const isWin = osType.includes('win');

    // 파일: 업로드가 있으면 그것을, 없고 use_standard_script면 OS별 표준 점검 스크립트 자동 선택
    const useStandardScript = ['1', 'true', 'on', 'yes'].includes(String(req.body.use_standard_script || '').toLowerCase());
    let deployFile = req.file;
    if (!deployFile) {
      if (useStandardScript) {
        const stdRel = isWin ? 'scripts/ai-ready/fsi_win_ai.ps1' : 'scripts/ai-ready/fsi_unix_ai.sh';
        const stdPath = path.join(ROOT, stdRel);
        if (!fs.existsSync(stdPath)) {
          return res.status(500).json({ status: 'failed', error: `표준 점검 스크립트를 찾을 수 없습니다: ${stdRel}` });
        }
        const stStd = fs.statSync(stdPath);
        deployFile = {
          path: stdPath,
          originalname: path.basename(stdPath),
          filename: path.basename(stdPath),
          size: stStd.size,
        };
      } else {
        return res.status(400).json({ status: 'failed', error: 'deploy_script 파일이 필요합니다' });
      }
    }

    const engine = normalizeDiagnosisEngine(req.body.engine);
    const scriptAction = normalizeScriptDeployAction(req.body.script_action, req.body.run_immediately);
    const deployOnly = scriptAction === 'deploy_only';
    const runImmediately = scriptAction === 'deploy_run_diagnose';
    const resultGlob = String(req.body.result_glob || '*.xml').trim() || '*.xml';
    const requestedScriptArgs = String(req.body.script_args || '').trim();
    const remoteWorkDir = String(req.body.remote_work_dir || '').trim();
    // 점검 강도(full/fast)를 OS별 인자로 매핑. 무인자 = 전체(full).
    const scanMode = String(req.body.scan_mode || '').trim().toLowerCase();
    const scanModeArgs = scanMode === 'fast' ? (isWin ? '-Fast' : '--fast')
      : scanMode === 'full' ? ''
      : null;
    // 무인자 = 전체(full) 점검 (수집 스크립트 기본값이 full)
    const scriptArgs = requestedScriptArgs || (scanModeArgs !== null ? scanModeArgs : '');
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

// 진단 배치 중지 — 진행 중인 항목까지만 마치고 다음 항목/서버로 안 넘어감
app.post('/scheduler/cancel', (req, res) => {
  require('./src/engine/cancel').request();
  console.log(`[웹] 진단 배치 중지 요청됨 (by ${req.session?.username || '?'})`);
  res.json({ status: 'ok', message: '중지 요청됨 — 진행 중인 항목까지만 마치고 멈춥니다.' });
});

/**
 * CSV 의 모든 서버 일괄 [수집 + 진단] — 웹에서 npm run scheduler 와 동일 효과.
 * 실행 후 결과 요약 반환 (긴 작업이라 클라이언트는 진행 표시 필요).
 */
app.post('/scheduler/run-all', async (req, res) => {
  try {
    const { getTargetServersFromFile, runScheduledDiagnosis } = require('./src/services/scheduler');
    const source = normalizeDiagnosisSource(req.body?.source || req.query?.source);
    let targets = getTargetServersFromFile();

    // 선택 진단: server_ids 가 오면 그 서버들만, 없으면 전체 (기존 동작 유지)
    const rawIds = req.body?.server_ids;
    const requestedIds = Array.isArray(rawIds)
      ? rawIds.map(v => String(v).trim()).filter(Boolean)
      : (rawIds ? String(rawIds).split(',').map(v => v.trim()).filter(Boolean) : []);
    if (requestedIds.length) {
      const idSet = new Set(requestedIds);
      targets = targets.filter(t => idSet.has(String(t.server_id)) || idSet.has(String(t.ip)));
    }

    if (targets.length === 0) {
      return res.status(400).json({
        status: 'failed',
        error: requestedIds.length
          ? '선택한 server_ids 와 일치하는 서버가 servers.csv 에 없습니다'
          : 'servers.csv 에 등록된 서버가 없습니다',
        hint: 'vuln-assessor-v9/servers.csv 파일 확인',
      });
    }

    const llm = String(req.body?.llm || req.query?.llm || '').toLowerCase(); // '' | 'internal' | 'haiku' | 'sonnet'
    console.log(`[웹] ${requestedIds.length ? '선택' : '일괄'} [${source} 수집+진단] 시작 — ${targets.length}개 서버, LLM=${llm || '사내'} (by ${req.session?.username || '?'})`);

    const cancel = require('./src/engine/cancel');
    cancel.reset();
    const results = [];
    for (const target of targets) {
      if (cancel.isCancelled()) { console.log('[웹] 배치 중지됨 (사용자 취소) — 남은 서버 스킵'); break; }
      const r = await runScheduledDiagnosis(target, { source, llm });
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
      cancelled:    cancel.isCancelled(),
    };

    res.json({ status: cancel.isCancelled() ? 'cancelled' : 'completed', summary, results });
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

// 서버 헬스 CSV 다운로드
app.get('/servers/export.csv', (req, res) => {
  const servers = loadMock('servers') || [];
  const head = ['서버명', 'Online', '자산번호', '호스트', 'IP', 'OS', '상태',
    'CPU 사용(%)', 'CPU 전체(core)', '메모리 사용(%)', '메모리(사용/전체 GB)',
    '디스크 사용(%)', '디스크(사용/전체 GB)', '마지막수집', '마지막진단'];
  const cell = (v) => `"${String(v == null ? '' : v).replace(/"/g, '""')}"`;
  const online = (s) => s.ssh_status === 'ok' ? 'Online' : (s.ssh_status ? 'Offline' : '미확인');
  const ab = (u, t, unit) => (u != null && t != null) ? `${u}/${t}${unit}` : '';
  const gb = (mb) => (mb != null) ? (mb / 1024).toFixed(1) : null;
  const rows = servers.map(s => [s.name, online(s), s.asset_no, s.hostname, s.ip_address, s.os_type, s.overall_health,
    s.cpu_usage_pct, s.cpu_cores,
    s.mem_usage_pct, ab(gb(s.mem_used_mb), gb(s.mem_total_mb), 'GB'),
    s.disk_usage_pct, ab(s.disk_used_gb, s.disk_total_gb, 'GB'),
    s.last_collected_at, s.last_diagnosed_at].map(cell).join(','));
  const csv = '﻿' + [head.map(cell).join(','), ...rows].join('\r\n');
  res.setHeader('Content-Type', 'text/csv; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="servers_health.csv"');
  res.send(csv);
});

// 서버 관리 + 헬스체크
app.get('/servers', (req, res) => {
  // 서버 관리 목록 = servers.csv(실 관리 대상)를 소스로. 헬스 데이터는 servers.json 에서 overlay 후 동기화.
  let servers = loadMock('servers') || [];
  try {
    const { getTargetServersFromFile } = require('./src/services/scheduler');
    const targets = getTargetServersFromFile() || [];
    if (targets.length) {
      const stored = servers;
      // 마지막 진단 (diagnoses) · 마지막 수집 (uploads 파일 mtime) — 호스트별 실값
      const diagnoses = loadMock('diagnoses') || [];
      const lastDiag = {};
      for (const d of diagnoses) {
        if (d.status !== 'success') continue;
        const h = d.hostname || d.server_name; if (!h) continue;
        const t = (d.executed_at || d.completed_at || '').slice(0, 16);
        if (t && (!lastDiag[h] || t > lastDiag[h])) lastDiag[h] = t;
      }
      const lastCollect = {};
      try {
        const upRoot = path.join(ROOT, 'data/uploads');
        const walk = (dir) => {
          for (const f of fs.readdirSync(dir, { withFileTypes: true })) {
            const fp = path.join(dir, f.name);
            if (f.isDirectory()) { walk(fp); continue; }
            const m = f.name.match(/^([A-Za-z0-9._-]+?)_(script|exportData)/);
            if (m) {
              const host = m[1];
              const mt = fs.statSync(fp).mtime.toISOString().slice(0, 16).replace('T', ' ');
              if (!lastCollect[host] || mt > lastCollect[host]) lastCollect[host] = mt;
            }
          }
        };
        if (fs.existsSync(upRoot)) walk(upRoot);
      } catch (_) {}

      servers = targets.map(t => {
        const prev = stored.find(s => String(s.server_id) === String(t.server_id) || s.hostname === t.hostname) || {};
        const isWin = String(t.os || '').includes('win');
        return {
          server_id: Number(t.server_id) || t.server_id,
          name: t.hostname,
          hostname: t.hostname,
          ip_address: t.ip,
          os_type: t.os,
          asset_no: t.asset_no,
          service_name: prev.service_name || (isWin ? 'Windows 점검 대상' : 'Linux 점검 대상 (CentOS 7)'),
          ssh_port: isWin ? 5985 : 22,
          ssh_user: t.username,
          // 헬스 overlay (servers.json 에 저장된 직전 헬스체크 결과 유지)
          ssh_status: prev.ssh_status, ssh_rtt: prev.ssh_rtt,
          agent_status: prev.agent_status, agent_version: prev.agent_version,
          cpu_usage_pct: prev.cpu_usage_pct, mem_usage_pct: prev.mem_usage_pct, disk_usage_pct: prev.disk_usage_pct,
          mem_used_mb: prev.mem_used_mb, mem_total_mb: prev.mem_total_mb, disk_used_gb: prev.disk_used_gb, disk_total_gb: prev.disk_total_gb, cpu_cores: prev.cpu_cores, cpu_mhz: prev.cpu_mhz,
          overall_health: prev.overall_health,
          last_collected_at: lastCollect[t.hostname] || prev.last_collected_at,
          last_diagnosed_at: lastDiag[t.hostname] || prev.last_diagnosed_at,
          checked_at: prev.checked_at,
        };
      });
      saveMock('servers', servers); // healthcheck 가 servers.json 에서 찾을 수 있게 동기화 (csv 없는 옛 시드 제거)
    }
  } catch (_) {}

  const rtts = servers.map(s => (typeof s.ssh_rtt === 'number' ? s.ssh_rtt : null)).filter(v => v != null);
  const health = {
    total: servers.length,
    healthy: servers.filter(s => s.overall_health === 'healthy').length,
    unhealthy: servers.filter(s => s.overall_health === 'warning' || s.overall_health === 'critical').length,
    unreachable: servers.filter(s => s.ssh_status && s.ssh_status !== 'ok').length,
    avgRtt: rtts.length ? Math.round(rtts.reduce((a, b) => a + b, 0) / rtts.length) : 0,
  };
  res.render('servers/index', {
    activeMenu: 'servers',
    servers,
    health,
    now: new Date().toISOString().slice(0, 16).replace('T', ' '),
  });
});

// 헬스체크 로직 — SSH(Linux)/WinRM(Windows)로 CPU·메모리·디스크 실수집 (server 객체를 갱신)
async function healthcheckServer(server) {
  let cred = {};
  try {
    const { getTargetServersFromFile } = require('./src/services/scheduler');
    const csv = getTargetServersFromFile() || [];
    cred = csv.find(c => c.hostname === server.hostname || c.ip === server.ip_address) || {};
  } catch (_) {}
  const host = server.ip_address || server.hostname;
  const username = cred.username || server.ssh_user;
  const password = cred.password || server._decrypted_password;
  const pct = (s) => { const n = parseInt(String(s).replace(/[^0-9-]/g, ''), 10); return isNaN(n) ? null : Math.max(0, Math.min(100, n)); };

  let result;
  if (String(server.os_type || '').includes('win')) {
    const deploy = require('./src/services/scriptDeployService');
    const target = deploy.resolveTarget({ ...server, os: 'windows', winrm_port: server.ssh_port || 5985, username, password });
    const ps = '$c=(Get-CimInstance Win32_Processor|Measure-Object -Property LoadPercentage -Average).Average;'
      + '$cc=(Get-CimInstance Win32_Processor|Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum;'
      + '$mhz=(Get-CimInstance Win32_Processor|Measure-Object -Property MaxClockSpeed -Maximum).Maximum;'
      + '$o=Get-CimInstance Win32_OperatingSystem;'
      + '$mt=[math]::Round($o.TotalVisibleMemorySize/1024);$mf=[math]::Round($o.FreePhysicalMemory/1024);$mu=$mt-$mf;'
      + '$m=[math]::Round(($mu/$mt)*100);'
      + '$d=Get-CimInstance Win32_LogicalDisk -Filter "DeviceID=\'C:\'";'
      + '$dt=[math]::Round($d.Size/1GB);$dfree=[math]::Round($d.FreeSpace/1GB);$du=$dt-$dfree;'
      + '$k=[math]::Round(((($d.Size-$d.FreeSpace)/$d.Size)*100));'
      + 'Write-Output ("HC:"+[int]$c+","+$m+","+$k+","+$mu+","+$mt+","+$du+","+$dt+","+$cc+","+$mhz)';
    const t0 = Date.now();
    const out = await deploy.runWindowsPowerShell(target, ps, 'healthcheck');
    const line = String(out).split(/\r?\n/).map(x => x.trim()).filter(x => x.indexOf('HC:') === 0).pop() || '';
    const p = line.replace('HC:', '').split(',');
    const num = (v) => { const n = parseInt(String(v).replace(/[^0-9-]/g, ''), 10); return isNaN(n) ? null : n; };
    result = { ssh_status: 'ok', ssh_rtt: Date.now() - t0, agent_status: 'running', agent_version: '-',
      cpu_usage_pct: pct(p[0]), mem_usage_pct: pct(p[1]), disk_usage_pct: pct(p[2]),
      mem_used_mb: num(p[3]), mem_total_mb: num(p[4]), disk_used_gb: num(p[5]), disk_total_gb: num(p[6]), cpu_cores: num(p[7]), cpu_mhz: num(p[8]),
      checked_at: new Date().toISOString() };
  } else {
    const { withConnection, exec } = require('./src/engine/sshClient');
    result = await withConnection({ host, port: server.ssh_port || 22, username, password, readyTimeout: 12000 }, async (conn) => {
      const t0 = Date.now();
      const cpu = await exec(conn, "vmstat 1 2 2>/dev/null | tail -1 | awk '{print 100-$15}'", { timeout: 9000 });
      const cores = await exec(conn, "nproc 2>/dev/null", { timeout: 5000 });
      const mhz1 = await exec(conn, "lscpu 2>/dev/null | awk -F: '/[Mm]ax MHz/{gsub(/[^0-9.]/,\"\",$2);print $2;exit}'", { timeout: 5000 });
      const mhz2 = await exec(conn, "awk -F'@' '/model name/{n=$2} END{gsub(/[^0-9.]/,\"\",n);print n}' /proc/cpuinfo 2>/dev/null", { timeout: 5000 });
      const mem = await exec(conn, "free -m 2>/dev/null | awk '/Mem:/{printf \"%d|%d|%d\", $3/$2*100, $3, $2}'", { timeout: 8000 });
      const disk = await exec(conn, "df -P -BG / 2>/dev/null | tail -1 | awk '{u=$3;gsub(\"G\",\"\",u);t=$2;gsub(\"G\",\"\",t);p=$5;gsub(\"%\",\"\",p);printf \"%d|%d|%d\", p, u, t}'", { timeout: 8000 });
      const num = (v) => { const n = parseInt(String(v).replace(/[^0-9-]/g, ''), 10); return isNaN(n) ? null : n; };
      let cpuMhz = num(mhz1.stdout);
      if (!cpuMhz) { const ghz = parseFloat(String(mhz2.stdout).trim()); if (ghz) cpuMhz = Math.round(ghz * 1000); }
      const mp = String(mem.stdout).split('|'); const dp = String(disk.stdout).split('|');
      return { ssh_status: 'ok', ssh_rtt: Date.now() - t0, agent_status: 'running', agent_version: '-',
        cpu_usage_pct: pct(cpu.stdout), mem_usage_pct: pct(mp[0]), disk_usage_pct: pct(dp[0]),
        mem_used_mb: num(mp[1]), mem_total_mb: num(mp[2]), disk_used_gb: num(dp[1]), disk_total_gb: num(dp[2]), cpu_cores: num(cores.stdout), cpu_mhz: cpuMhz,
        checked_at: new Date().toISOString() };
    });
  }
  Object.assign(server, result);
  const mx = Math.max(result.cpu_usage_pct || 0, result.mem_usage_pct || 0, result.disk_usage_pct || 0);
  server.overall_health = result.ssh_status !== 'ok' ? 'critical' : mx > 90 ? 'critical' : mx > 80 ? 'warning' : 'healthy';
  return result;
}

// 개별 헬스체크
app.post('/servers/:id/healthcheck', async (req, res) => {
  const servers = loadMock('servers');
  const server = servers.find(s => s.server_id == req.params.id);
  if (!server) return res.status(404).json({ error: 'not found' });
  try {
    const result = await healthcheckServer(server);
    saveMock('servers', servers);
    res.json(result);
  } catch (e) {
    server.ssh_status = 'timeout'; server.overall_health = 'critical'; server.checked_at = new Date().toISOString();
    saveMock('servers', servers);
    res.status(200).json({ ssh_status: 'timeout', error: e.message });
  }
});

// 전체 헬스체크 (jessy207·167 등 등록 서버 일괄)
app.post('/servers/healthcheck/all', async (req, res) => {
  const servers = loadMock('servers');
  const results = [];
  for (const server of servers) {
    try { const r = await healthcheckServer(server); results.push({ id: server.server_id, ok: true, ...r }); }
    catch (e) {
      server.ssh_status = 'timeout'; server.overall_health = 'critical'; server.checked_at = new Date().toISOString();
      results.push({ id: server.server_id, ok: false, error: e.message });
    }
  }
  saveMock('servers', servers);
  res.json({ status: 'success', count: results.length, results });
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

  // 실행 이력: 스케줄명 보정(AUTO/누락 → 실제 이름), 최신순
  const schedNameById = new Map(schedules.map(s => [s.schedule_id, s.name]));
  const runsView = runs.slice(0, 30).map(r => ({
    ...r,
    schedule_name: (r.schedule_name && r.schedule_name !== 'AUTO')
      ? r.schedule_name
      : (schedNameById.get(r.schedule_id) || r.schedule_name || '예약 진단'),
  }));

  res.render('schedules/index', {
    activeMenu: 'schedules',
    schedules: enriched,
    kpi,
    runs: runsView,
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
    servers: loadMock('servers') || [],
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
    servers: loadMock('servers') || [],
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
    if (body.server_ids !== undefined)   s.server_ids = body.server_ids || null;
    if (body.target_count !== undefined) s.target_count = body.target_count;
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
  const { result_id, rule_id, server_id, username } = req.query;
  res.render('exceptions/new', {
    activeMenu: 'exceptions',
    prefill: { result_id, rule_id, server_id, username },
    checkItems: buildCheckItemList(),
    servers: loadMock('servers') || [],
  });
});

// 예외 등록 (단일 또는 CSV 일괄: targets=[{hostname,username}, ...])
app.post('/exceptions/save', (req, res) => {
  const exceptions = loadMock('exceptions') || [];
  let nextId = exceptions.length ? Math.max(...exceptions.map(e => e.exception_id)) + 1 : 1001;
  const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
  const base = { ...req.body };
  const targets = Array.isArray(base.targets) ? base.targets : null;
  // 점검항목 다중(rule_ids) 또는 단일(rule_id)
  let ruleIds = Array.isArray(base.rule_ids) ? base.rule_ids : (base.rule_id ? [base.rule_id] : [null]);
  delete base.targets; delete base.rule_ids;

  const scopeOf = (host, user) => base.scope_type
    || (base.result_id ? 'result' : (user ? 'rule_host_account' : (host ? 'rule_host' : 'rule_global')));

  const mk = (ruleId, host, user) => ({
    exception_id: nextId++,
    ...base,
    rule_id: ruleId,
    hostname: host !== undefined ? host : base.hostname,
    username: user !== undefined ? user : base.username,
    scope_type: scopeOf(host !== undefined ? host : base.hostname, user !== undefined ? user : base.username),
    requested_by: base.requested_by || (req.session ? req.session.username : 'operator1'),
    requested_at: now,
    approval_status: base.approval_status || '대기',
    enabled: 1,
    created_at: now,
  });

  const created = [];
  const tlist = (targets && targets.length) ? targets : [{ hostname: undefined, username: undefined }];
  ruleIds.forEach(rid => tlist.forEach(t => created.push(mk(rid, t.hostname, t.username))));
  created.forEach(r => exceptions.unshift(r));
  saveMock('exceptions', exceptions);
  res.json({ status: 'success', count: created.length, exception_id: created[0].exception_id });
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
  const { rule_id, server_id, result_id, username } = req.query;
  res.render('exclusions/new', {
    activeMenu: 'exclusions',
    prefill: { rule_id, server_id, result_id, username },
    checkItems: buildCheckItemList(),
    servers: loadMock('servers') || [],
  });
});

// 제외 등록 (단일 또는 CSV 일괄: targets=[{hostname,username}, ...])
app.post('/exclusions/save', (req, res) => {
  const exclusions = loadMock('exclusions') || [];
  let nextId = exclusions.length ? Math.max(...exclusions.map(e => e.exclusion_id)) + 1 : 2001;
  const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
  const base = { ...req.body };
  const targets = Array.isArray(base.targets) ? base.targets : null;
  delete base.targets;

  const mk = (host, user) => ({
    exclusion_id: nextId++,
    ...base,
    hostname: host !== undefined ? host : base.hostname,
    username: user !== undefined ? user : base.username,
    registered_by: base.registered_by || 'operator1',
    registered_at: now,
    enabled: 1,
    created_at: now,
  });

  const created = [];
  if (targets && targets.length) {
    targets.forEach(t => created.push(mk(t.hostname, t.username)));
  } else {
    created.push(mk(undefined, undefined));
  }
  created.forEach(r => exclusions.unshift(r));
  saveMock('exclusions', exclusions);
  res.json({ status: 'success', count: created.length, exclusion_id: created[0].exclusion_id });
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

    const cveScanner = require('./src/cve/scanner');
    const enrichment = require('./src/cve/enrichment');
    const servers = loadMock('servers') || [];
    const server = servers.find(s => s.server_id == diag.server_id)
      || { server_id: diag.server_id, hostname: diag.hostname };

    // 이 서버 고유 데이터만으로 소스 해석 (전역 fallback 금지).
    // 리눅스=rpm -qa(SecuMS DB), 윈도우=핫픽스/OS빌드(SecuMS Windows DB 또는 script XML).
    const src = resolveCveSource(diag, server);

    const enrichBundle = {
      stats: enrichment.getEnrichmentStats(),
      last_sync: enrichment.getSyncHistory(1)[0] || null,
      untracked_kev: enrichment.getUntrackedKevCves(10),
    };
    const hostName = diag.hostname || server.hostname || '-';

    // ── Windows: 핫픽스/OS빌드 기반 CVE 진단 (DB 또는 script XML) ──
    if (src.platform === 'windows') {
      const winScanner = require('./src/cve/winScanner');
      if (src.kind === 'secums_db') {
        const winResult = await winScanner.runWindowsCveScan(src.path, { hostname: hostName });
        return res.render('cve/scan_windows', { activeMenu: 'diagnosis', assessment_id: id, diag, result: winResult, enrichment: enrichBundle });
      }
      if (src.kind === 'script_xml') {
        const winResult = await winScanner.runWindowsCveScanFromScript(src.path, { hostname: hostName });
        return res.render('cve/scan_windows', { activeMenu: 'diagnosis', assessment_id: id, diag, result: winResult, enrichment: enrichBundle });
      }
      return res.render('cve/scan_windows', {
        activeMenu: 'diagnosis', assessment_id: id, diag, enrichment: enrichBundle,
        result: { error: `Windows CVE 진단 불가: 이 서버(host=${hostName})의 핫픽스 수집 데이터(SecuMS Windows DB의 W_HOTFIX 또는 스크립트 SRV-120/117)를 찾을 수 없습니다.`, packages_count: 0, hotfixes: [], matches: [], summary: { total: 0, actually_vulnerable: 0, by_severity: {}, by_priority: {}, kev_count: 0, patched_count: 0 }, env: { hostname: hostName, os_distro: 'Windows', os_version: '-' } },
      });
    }

    // ── Linux: rpm -qa 기반 CVE 진단 ──
    // script XML 도 `rpm -qa -i` 인벤토리가 있으면 CVE 진단(SecuMS DB 불필요).
    if (src.kind === 'script_xml') {
      const result = await cveScanner.runCveScanFromScript(src.path, { hostname: hostName });
      return res.render('cve/scan', { activeMenu: 'diagnosis', assessment_id: id, diag, result, enrichment: enrichBundle });
    }
    if (src.kind !== 'secums_db') {
      return res.render('cve/scan', {
        activeMenu: 'diagnosis', assessment_id: id, diag, enrichment: enrichBundle,
        result: { error: `CVE 진단 불가: 이 서버(host=${hostName})의 rpm 수집 데이터(SecuMS rpm -qa 또는 script rpm -qa -i)를 찾을 수 없습니다.`, packages_count: 0, matches: [], summary: { total: 0 } },
      });
    }
    const result = await cveScanner.runCveScan(src.path, { hostname: hostName });
    res.render('cve/scan', {
      activeMenu: 'diagnosis',
      assessment_id: id,
      diag,
      result,
      enrichment: enrichBundle,
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
    const llmReviewedCount = (diag.results || []).filter(r => r._llm_reviewed).length;
    const resultScope = diag.diagnose_type === 'llm'
      ? {
          mode: 'llm_detail',
          label: 'LLM 상세 결과',
          description: llmReviewedCount && llmReviewedCount < (diag.results || []).length
            ? `전체 ${diag.total_count || 0}개 항목 — 이 중 LLM 상세 재검토 ${llmReviewedCount}개 반영, 나머지는 AI 1차 판정 유지.`
            : baseAiDiag
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
    // mock(ai 1차) + LLM(2차) 둘 다 표시 — mock = "LLM 미사용 기준선", LLM = 최종. 대비로 LLM 효과 확인.
    .filter(d => d.status === 'success' && (d.diagnose_type === 'ai' || d.diagnose_type === 'llm'))
    .sort((a, b) => (b.assessment_id || 0) - (a.assessment_id || 0)) // 최신순 — 방금 돌린 게 맨 위
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
  if (diag.diagnose_type !== 'ai' && diag.diagnose_type !== 'llm') return { _notAi: true, diag };

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

// 3-way 정합성 (①secums raw AI ②script AI ③secums 자체판정)
app.get('/reports/:id/threeway', async (req, res) => {
  try {
    const id = req.params.id;
    const diagnoses = loadMock('diagnoses') || [];
    const ref = diagnoses.find(d => d.assessment_id == id);
    if (!ref) return res.status(404).send('진단 결과를 찾을 수 없습니다');
    const host = ref.hostname;

    const { buildThreeWay, loadCrosswalk } = require('./src/services/threeWayService');
    const cw = loadCrosswalk();
    const scanSet = new Set([...cw.windows, ...cw.linux].map(x => x.scan_id));

    const bySource = (src) => diagnoses
      .filter(d => d.hostname === host && new RegExp(src, 'i').test(d.source_type || d.diagnose_type || ''))
      .sort((a, b) => (b.assessment_id || 0) - (a.assessment_id || 0));

    // secums: 크로스워크 코드(os-xxx-2508 계열)를 쓰는 최신 레코드 우선 (옛 seed=os-win-330 제외)
    const secumsCands = bySource('secums');
    const secumsRec = secumsCands.find(d => (d.results || []).some(it => scanSet.has(String(it.chk_id)))) || secumsCands[0] || null;
    const scriptRec = bySource('script')[0] || null;

    const osType = (secumsRec && (secumsRec.results || []).some(it => /os-win/.test(it.chk_id))) ? 'windows'
      : (secumsRec && (secumsRec.results || []).some(it => /os-linux/.test(it.chk_id))) ? 'linux'
      : /win/i.test(ref.os_type || '') ? 'windows' : 'linux';

    // 업로드된 SecuMS 상세리포트 정답지(③) — 있으면 raw DB RESULT 대신 우선 사용
    const secumsAnswer = require('./src/services/secumsAnswerService').loadAnswer(host);

    const data = buildThreeWay(secumsRec, scriptRec, osType, secumsAnswer);
    res.render('reports/view_threeway', {
      activeMenu: 'reports',
      hostname: host,
      ref_id: id,
      secums_id: secumsRec && secumsRec.assessment_id,
      script_id: scriptRec && scriptRec.assessment_id,
      secums_answer: secumsAnswer ? { updated_at: secumsAnswer.updated_at, count: Object.keys(secumsAnswer.verdicts || {}).length } : null,
      ...data,
    });
  } catch (e) {
    console.error('[3-way 오류]', e);
    res.status(500).send('3-way 비교 생성 실패: ' + e.message);
  }
});

// SecuMS 상세리포트(OS_Detail_Report_*.xlsx) 업로드 → ③ 자체판정 정답지 저장
const uploadDetailXlsx = multer({
  storage: genericStorage,
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const ok = /\.xlsx$/i.test(file.originalname);
    cb(ok ? null : new Error('SecuMS 상세리포트 .xlsx 만 허용됩니다'), ok);
  },
});
app.post('/reports/secums-answer/upload', uploadDetailXlsx.single('detail_report'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ status: 'failed', error: 'detail_report .xlsx 파일이 필요합니다' });
    const svc = require('./src/services/secumsAnswerService');
    const { servers, summary } = await svc.parseDetailReport(req.file.path);
    if (!summary.length) return res.status(400).json({ status: 'failed', error: 'SRV 항목을 찾지 못했습니다. OS_Detail_Report 형식인지 확인하세요.' });
    const saved = svc.saveAnswers(servers);
    res.json({ status: 'ok', saved, summary });
  } catch (e) {
    console.error('[SecuMS 정답지 업로드 오류]', e);
    res.status(500).json({ status: 'failed', error: e.message });
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

  // 스케줄러 시작 — 기본 ai_llm (AI 1차 mock 후 LLM 2차 상세 진단까지 자동 수행).
  // SCHEDULER_ENGINE=ai 로 두면 예전처럼 mock 1차만, llm 으로 두면 LLM 전수 진단.
  // SCHEDULER_SOURCE 로 진단 소스 지정 (기본 secums; script/both 가능).
  const scheduler = require('./src/scheduler/runner');
  const SCHEDULER_ENGINE = normalizeDiagnosisEngine(process.env.SCHEDULER_ENGINE || 'ai_llm');
  const SCHEDULER_SOURCE = normalizeDiagnosisSource(process.env.SCHEDULER_SOURCE || 'secums');
  console.log(`[scheduler] 진단 엔진=${SCHEDULER_ENGINE}, 소스=${SCHEDULER_SOURCE}`);
  if (['1', 'true', 'on', 'yes'].includes(String(process.env.SCHEDULER_OFF || '').toLowerCase())) {
    console.log('[scheduler] SCHEDULER_OFF=1 → 자동 스케줄러 비활성화 (데모/수동 모드)');
  } else {
    scheduler.start({
      storage: kvStorage,
      runDiagnosis: async (server, runOpts) => runDiagnosisByEngine(SCHEDULER_ENGINE, server, {
        triggered_by: (runOpts && runOpts.triggered_by) || 'cron',
        executed_by: 'scheduler',
        source: (runOpts && runOpts.source) || SCHEDULER_SOURCE,
      }),
      notifier,
      log: console,
    });
  }

  // ═════════════════════════════════════════════════════════
// 취약점 관리 (모든 진단 결과의 취약 항목 통합 뷰)
// ═════════════════════════════════════════════════════════

/**
 * 모든 진단 결과에서 취약 항목만 평탄화.
 * 같은 (server, rule) 조합은 최신 진단만 사용.
 */
// ── 추이/비교 (Trend) : 진단 시계열 + 최근 2회 신규/해소 취약 비교 ──
function buildTrendData(opts = {}) {
  const diagnoses = loadMock('diagnoses') || [];
  const verdictOf = r => r.ai_verdict || r.status;
  const ts = d => {
    const t = d.executed_at || d.completed_at || d.started_at || '';
    return t ? new Date(String(t).replace(' ', 'T')).getTime() : 0;
  };
  // AI/LLM 성공 진단만, 시간순
  let rows = diagnoses.filter(d => d.status === 'success' &&
    (d.diagnose_type === 'ai' || d.diagnose_type === 'llm') && (d.results || []).length);
  if (opts.host) rows = rows.filter(d => d.hostname === opts.host);
  rows = rows.sort((a, b) => ts(a) - ts(b));

  const series = rows.map(d => {
    const res = d.results || [];
    const vuln = res.filter(r => verdictOf(r) === '취약').length;
    const safe = res.filter(r => verdictOf(r) === '양호').length;
    const na = res.filter(r => verdictOf(r) === '판정불가').length;
    return {
      assessment_id: d.assessment_id,
      hostname: d.hostname,
      source: d.source_type || d.diagnose_type,
      date: (d.executed_at || d.completed_at || d.started_at || '').slice(0, 16),
      agreement_rate: typeof d.agreement_rate === 'number' ? d.agreement_rate : null,
      total: res.length, vuln, safe, na,
    };
  });

  // 최근 2회 비교 (같은 host+source 우선)
  const byKey = {};
  for (const d of rows) {
    const k = `${d.hostname}::${d.source_type || d.diagnose_type}`;
    (byKey[k] = byKey[k] || []).push(d);
  }
  let diff = null;
  const target = opts.host
    ? Object.entries(byKey).filter(([k]) => k.startsWith(opts.host + '::')).map(([, v]) => v).sort((a, b) => b.length - a.length)[0]
    : Object.values(byKey).sort((a, b) => b.length - a.length)[0];
  if (target && target.length >= 2) {
    const prev = target[target.length - 2], cur = target[target.length - 1];
    const mapOf = d => { const m = {}; for (const r of d.results || []) m[r.chk_id] = verdictOf(r); return m; };
    const mPrev = mapOf(prev), mCur = mapOf(cur);
    const added = [], resolved = [];
    for (const id of Object.keys(mCur)) {
      if (mCur[id] === '취약' && mPrev[id] !== '취약') added.push({ chk_id: id, was: mPrev[id] || '(없음)' });
    }
    for (const id of Object.keys(mPrev)) {
      if (mPrev[id] === '취약' && mCur[id] !== '취약') resolved.push({ chk_id: id, now: mCur[id] || '(없음)' });
    }
    diff = {
      hostname: cur.hostname, source: cur.source_type || cur.diagnose_type,
      prev_id: prev.assessment_id, cur_id: cur.assessment_id,
      prev_date: (prev.executed_at || '').slice(0, 16), cur_date: (cur.executed_at || '').slice(0, 16),
      added, resolved,
    };
  }
  const hosts = [...new Set(rows.map(d => d.hostname).filter(Boolean))];
  return { series, diff, hosts };
}

// 예외/제외 폼의 "점검 항목" 드롭다운 목록 (크로스워크: SRV + 제목). srv 기준 중복 제거.
// 대시보드 데이터 — servers.csv(현재 관리 대상: 207/167, jessy62 제외) 실데이터 기준
function buildDashboardData() {
  const servers = loadMock('servers') || [];                 // CSV 동기화본 (jessy62 미포함)
  const validHosts = new Set(servers.map(s => s.hostname));
  const allVulns = buildVulnList();
  const vulns = allVulns.filter(v => validHosts.has(v.hostname));
  const diagnoses = (loadMock('diagnoses') || []).filter(d => validHosts.has(d.hostname));

  const sevenAgo = Date.now() - 7 * 86400000;
  const ts = (d) => { const t = d.executed_at || d.completed_at || d.started_at; return t ? new Date(String(t).replace(' ', 'T')).getTime() : 0; };

  const fixed = vulns.filter(v => v.fix_status === '조치완료').length;
  const pending = vulns.filter(v => v.fix_status === '미조치').length;
  const severe = vulns.filter(v => v.severity === '상').length;
  const newCnt = vulns.filter(v => v.is_new).length;

  // 카테고리별 분포 — AI 카테고리가 잘게 쪼개져 상위 6개 + 기타로 통합
  const catRaw = {};
  vulns.forEach(v => { const c = v.category || '미분류'; catRaw[c] = (catRaw[c] || 0) + 1; });
  const catSorted = Object.entries(catRaw).sort((a, b) => b[1] - a[1]);
  const categoryStats = {};
  let etc = 0;
  catSorted.forEach(([c, n], i) => { if (i < 6) categoryStats[c] = n; else etc += n; });
  if (etc > 0) categoryStats['기타'] = (categoryStats['기타'] || 0) + etc;

  // 호스트별 위험도 누적 (servers.csv 순서)
  const hostStats = servers.map(s => {
    const hv = vulns.filter(v => v.hostname === s.hostname);
    return {
      hostname: s.hostname, service_name: s.service_name,
      sev_high: hv.filter(v => v.severity === '상').length,
      sev_mid: hv.filter(v => v.severity === '중').length,
      sev_low: hv.filter(v => v.severity === '하').length,
      total: hv.length,
    };
  });

  // 최근 4주 신규 취약 추이 (discovered_at 주별 버킷)
  const weekIdx = (t) => Math.floor((Date.now() - t) / (7 * 86400000)); // 0=이번주 ... 3=4주전
  const buckets = [0, 0, 0, 0];
  vulns.forEach(v => {
    const t = v.discovered_at ? new Date(String(v.discovered_at).replace(' ', 'T')).getTime() : 0;
    const w = weekIdx(t);
    if (w >= 0 && w <= 3) buckets[w]++;
  });
  const trend = [
    { label: '4주 전', vuln: buckets[3] }, { label: '3주 전', vuln: buckets[2] },
    { label: '2주 전', vuln: buckets[1] }, { label: '이번주', vuln: buckets[0] },
  ];

  // 서버별 최신 진단 요약
  const summaries = servers.map(s => {
    const ds = diagnoses.filter(d => d.hostname === s.hostname).sort((a, b) => ts(b) - ts(a));
    const latest = ds[0];
    const results = latest ? (latest.results || []) : [];
    const verdictOf = (r) => r.status || r.ai_verdict;
    return {
      ...s,
      assessment_id: latest ? latest.assessment_id : null,
      executed_at: latest ? (latest.executed_at || latest.completed_at || latest.started_at) : null,
      total_count: results.length,
      vuln_count: results.filter(r => verdictOf(r) === '취약').length,
      safe_count: results.filter(r => verdictOf(r) === '양호').length,
      na_count: results.filter(r => { const x = verdictOf(r); return x === '판정불가' || x === 'N/A'; }).length,
    };
  });

  return {
    kpi: {
      totalVuln: vulns.length, severeVuln: severe,
      newVuln: newCnt, newPct: vulns.length ? Math.round(newCnt / vulns.length * 100) : 0,
      pending, noAssignee: vulns.filter(v => v.fix_status === '미조치' && !v.assignee).length,
      fixed, fixRate: vulns.length ? Math.round(fixed / vulns.length * 100) : 0,
      serverCount: servers.length,
      recentAssess: diagnoses.filter(d => ts(d) >= sevenAgo).length,
    },
    categoryStats, trend, hostStats, workqueue: [], summaries,
  };
}

// 대시보드 — buildDashboardData 와 동일 스코프(startServer 내부)에서 등록
app.get('/', (req, res) => {
  res.render('dashboard', { activeMenu: 'dashboard', now: new Date().toISOString().slice(0, 16).replace('T', ' '), ...buildDashboardData() });
});

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
      // 룰엔진(mock) 결과는 status/rule_id, AI·LLM 결과는 ai_verdict/chk_id 를 쓴다 — 둘 다 인식.
      const verdict = r.status || r.ai_verdict;
      if (verdict !== '취약') continue;
      const ruleId = r.rule_id || r.chk_id;
      const resultId = r.result_id || `${diag.assessment_id}-${ruleId}`;
      const key = `${diag.server_id}::${ruleId}`;
      if (latest.has(key)) continue;  // 이미 더 최신 진단의 결과 있음

      const server = serverMap.get(diag.server_id) || {};
      // 진단의 실제 시간 필드는 executed_at (manual upload) 또는 completed_at (agent push)
      const diagTime = diag.executed_at || diag.completed_at || diag.started_at;
      const diagTs = diagTime ? new Date(diagTime.replace(' ', 'T')).getTime() : Date.now();
      const daysOld = Math.max(0, Math.floor((Date.now() - diagTs) / 86400000));

      // 조치 상태 확인
      const rem = remediations.find(x =>
        x.server_id === diag.server_id &&
        x.rule_id === ruleId &&
        x.assessment_id === diag.assessment_id
      );

      // 예외 적용 여부
      // 호스트 매칭: server_id 또는 hostname (폼에서 둘 중 하나로 저장될 수 있음)
      const exHost = (e) => String(e.server_id) === String(diag.server_id) || (e.hostname && e.hostname === (diag.hostname || server.hostname));
      const hasException = exceptions.some(e =>
        (e.scope_type === 'result' && e.result_id === resultId) ||
        (e.scope_type === 'rule_host' && e.rule_id === ruleId && exHost(e)) ||
        // 계정 단위 예외: 룰+호스트 일치 시 해당 항목 예외 처리 (계정 sub-row 단위 세분화는 향후)
        (e.scope_type === 'rule_host_account' && e.rule_id === ruleId && exHost(e)) ||
        (e.scope_type === 'rule_global' && e.rule_id === ruleId)
      );

      latest.set(key, {
        result_id: resultId,
        assessment_id: diag.assessment_id,
        management_no: r.management_no || `${new Date(diag.executed_at || diag.completed_at || Date.now()).getFullYear()}-${String(latest.size + 1).padStart(3, '0')}`,
        server_id: diag.server_id,
        hostname: diag.hostname || server.hostname,
        asset_no: diag.asset_no || server.asset_no,
        service_name: diag.service_name || server.service_name,
        rule_id: ruleId,
        title: r.title || r.ai_title || ruleId,
        category: r.category || r.ai_category || '',
        severity: r.severity || r.ai_severity || r.weight || '상',
        reason: r.reason || r.ai_reason || '',
        evidence: r.evidence || r.ai_evidence || '',
        eval_method: r.eval_method || r._source || r._diagnosis_mode,
        discovered_at: diag.executed_at || diag.completed_at || diag.started_at,
        is_new: daysOld <= 7,
        days_old: daysOld,
        is_per_row: !!(r.subs && r.subs.length),
        sub_count: (r.subs || []).length,
        sub_vuln: (r.subs || []).filter(s => s.status === '취약' || s.ai_verdict === '취약').length,
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

// 추이 / 진단 간 비교
app.get('/trends', (req, res) => {
  const host = req.query.host || '';
  const data = buildTrendData({ host });
  res.render('trends/index', { activeMenu: 'trends', host, ...data });
});

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
    // ai_llm 로 실행해 mock 1차 후 LLM 2차까지 자동 수행(판정불가 해소). 예전엔 mock 1차만 돌았음.
    const agentEngine = normalizeDiagnosisEngine(process.env.SCHEDULER_ENGINE || 'ai_llm');
    const result = await runDiagnosisByEngine(agentEngine, server, {
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
    reconcileMockData();  // 모드 무관(MySQL 포함) — 가짜 예약/알림/실행이력 정리

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

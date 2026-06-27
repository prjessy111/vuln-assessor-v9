'use strict';
/**
 * 가벼운 인증 모듈 (외부 라이브러리 불필요)
 *
 * - 비밀번호 해시: scrypt (Node.js 내장 crypto)
 * - 세션 관리: 메모리 + 쿠키 (커스텀 구현)
 * - 권한: admin / operator / viewer
 *
 * 운영 적용 시 권장:
 *   - bcrypt 또는 argon2 사용 (현재는 scrypt로 충분)
 *   - 세션 저장소를 Redis/MySQL로 전환
 *   - HTTPS 강제
 *   - CSRF 토큰 추가
 */

const crypto = require('crypto');

// ─── 세션 저장소 (메모리) ────────────────────────────────────
const sessions = new Map();
const SESSION_TTL_MS = 8 * 60 * 60 * 1000;  // 8시간

function generateSessionId() {
  return crypto.randomBytes(32).toString('hex');
}

function createSession(user) {
  const sid = generateSessionId();
  sessions.set(sid, {
    user_id: user.user_id,
    username: user.username,
    name: user.name,
    role: user.role,
    created_at: Date.now(),
    expires_at: Date.now() + SESSION_TTL_MS,
  });
  return sid;
}

function getSession(sid) {
  if (!sid) return null;
  const sess = sessions.get(sid);
  if (!sess) return null;
  if (sess.expires_at < Date.now()) {
    sessions.delete(sid);
    return null;
  }
  return sess;
}

function destroySession(sid) {
  sessions.delete(sid);
}

function cleanExpiredSessions() {
  const now = Date.now();
  for (const [sid, sess] of sessions.entries()) {
    if (sess.expires_at < now) sessions.delete(sid);
  }
}

// 1시간마다 만료된 세션 정리
setInterval(cleanExpiredSessions, 60 * 60 * 1000);


// ─── 비밀번호 해싱 (scrypt) ───────────────────────────────────
/**
 * scrypt 기반 비밀번호 해시.
 * 형식: scrypt$N$r$p$salt$hash  (모든 파라미터 명시)
 */
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const N = 16384, r = 8, p = 1, keyLen = 32;
  const hash = crypto.scryptSync(password, salt, keyLen, { N, r, p });
  return `scrypt$${N}$${r}$${p}$${salt.toString('hex')}$${hash.toString('hex')}`;
}

function verifyPassword(password, stored) {
  try {
    const parts = stored.split('$');
    if (parts[0] !== 'scrypt' || parts.length !== 6) return false;
    const [, N, r, p, saltHex, hashHex] = parts;
    const salt = Buffer.from(saltHex, 'hex');
    const expected = Buffer.from(hashHex, 'hex');
    const actual = crypto.scryptSync(password, salt, expected.length, {
      N: parseInt(N), r: parseInt(r), p: parseInt(p),
    });
    return crypto.timingSafeEqual(actual, expected);
  } catch (e) {
    return false;
  }
}


// ─── 미들웨어 ────────────────────────────────────────────────

/**
 * 쿠키에서 세션 ID 추출.
 */
function parseCookies(cookieHeader) {
  const result = {};
  if (!cookieHeader) return result;
  for (const part of cookieHeader.split(';')) {
    const [k, v] = part.trim().split('=');
    if (k) result[k] = decodeURIComponent(v || '');
  }
  return result;
}

/**
 * 요청에 세션 정보 첨부 (req.session).
 * 모든 요청에 적용.
 */
function sessionMiddleware(req, res, next) {
  const cookies = parseCookies(req.headers.cookie);
  const sid = cookies.vasid;
  req.session = getSession(sid);
  req.sessionId = sid;
  next();
}

/**
 * 로그인 필수 미들웨어. 미인증 시 /login으로 리다이렉트.
 */
function requireAuth(req, res, next) {
  if (!req.session) {
    // API 요청이면 401, 페이지 요청이면 리다이렉트
    if (req.path.startsWith('/api/') || req.xhr) {
      return res.status(401).json({ error: 'authentication_required' });
    }
    return res.redirect('/login?from=' + encodeURIComponent(req.originalUrl));
  }
  next();
}

/**
 * 역할 권한 미들웨어 팩토리.
 *   app.post('/users/delete', requireRole('admin'), handler)
 */
function requireRole(...roles) {
  return function (req, res, next) {
    if (!req.session) {
      return res.status(401).json({ error: 'authentication_required' });
    }
    if (!roles.includes(req.session.role)) {
      return res.status(403).render('error', {
        message: '권한이 없습니다.',
        detail: `이 작업은 ${roles.join(', ')} 권한이 필요합니다.`,
        activeMenu: '',
      });
    }
    next();
  };
}


// ─── 사용자 DAO (mock 모드 — JSON 파일) ─────────────────────
const fs = require('fs');
const path = require('path');

function getUsersFile(mockDir) {
  return path.join(mockDir, 'users.json');
}

function loadUsers(mockDir) {
  const file = getUsersFile(mockDir);
  if (!fs.existsSync(file)) return [];
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function saveUsers(mockDir, users) {
  const file = getUsersFile(mockDir);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(users, null, 2));
}

/**
 * 기본 admin 계정 자동 생성 (없을 때만).
 */
function ensureDefaultAdmin(mockDir) {
  const users = loadUsers(mockDir);
  if (users.length > 0) return null;
  
  const defaultPassword = 'admin123!';
  const admin = {
    user_id: 1,
    username: 'admin',
    password_hash: hashPassword(defaultPassword),
    name: '관리자',
    email: 'admin@lsware.local',
    role: 'admin',
    enabled: 1,
    created_at: new Date().toISOString().slice(0, 19).replace('T', ' '),
    last_login_at: null,
    must_change_password: 1,
  };
  saveUsers(mockDir, [admin]);
  console.log('');
  console.log('━'.repeat(60));
  console.log('  최초 실행: 기본 관리자 계정 생성됨');
  console.log(`  아이디: admin`);
  console.log(`  비밀번호: ${defaultPassword}  ← 첫 로그인 시 변경 권장`);
  console.log('━'.repeat(60));
  console.log('');
  return defaultPassword;
}

function findUserByUsername(mockDir, username) {
  return loadUsers(mockDir).find(u => u.username === username && u.enabled);
}

function findUserById(mockDir, userId) {
  return loadUsers(mockDir).find(u => u.user_id == userId);
}

function createUser(mockDir, data) {
  const users = loadUsers(mockDir);
  if (users.some(u => u.username === data.username)) {
    throw new Error('이미 존재하는 아이디입니다.');
  }
  const newId = users.length ? Math.max(...users.map(u => u.user_id)) + 1 : 1;
  const user = {
    user_id: newId,
    username: data.username,
    password_hash: hashPassword(data.password),
    name: data.name,
    email: data.email || '',
    role: data.role || 'operator',
    enabled: 1,
    created_at: new Date().toISOString().slice(0, 19).replace('T', ' '),
    last_login_at: null,
    must_change_password: data.must_change_password ? 1 : 0,
  };
  users.unshift(user);
  saveUsers(mockDir, users);
  return user;
}

function updateUser(mockDir, userId, data) {
  const users = loadUsers(mockDir);
  const u = users.find(x => x.user_id == userId);
  if (!u) throw new Error('사용자를 찾을 수 없습니다.');
  if (data.name !== undefined) u.name = data.name;
  if (data.email !== undefined) u.email = data.email;
  if (data.role !== undefined) u.role = data.role;
  if (data.enabled !== undefined) u.enabled = data.enabled ? 1 : 0;
  if (data.password) {
    u.password_hash = hashPassword(data.password);
    u.must_change_password = 0;
  }
  saveUsers(mockDir, users);
  return u;
}

function deleteUser(mockDir, userId) {
  const users = loadUsers(mockDir);
  const idx = users.findIndex(x => x.user_id == userId);
  if (idx < 0) throw new Error('사용자를 찾을 수 없습니다.');
  // admin 계정 1개 미만 삭제 금지
  const admins = users.filter(u => u.role === 'admin' && u.enabled);
  if (admins.length === 1 && admins[0].user_id == userId) {
    throw new Error('마지막 관리자 계정은 삭제할 수 없습니다.');
  }
  users.splice(idx, 1);
  saveUsers(mockDir, users);
}

function recordLogin(mockDir, userId) {
  const users = loadUsers(mockDir);
  const u = users.find(x => x.user_id == userId);
  if (u) {
    u.last_login_at = new Date().toISOString().slice(0, 19).replace('T', ' ');
    saveUsers(mockDir, users);
  }
}


module.exports = {
  // 비밀번호
  hashPassword,
  verifyPassword,
  // 세션
  createSession,
  getSession,
  destroySession,
  // 미들웨어
  sessionMiddleware,
  requireAuth,
  requireRole,
  // 사용자 DAO
  loadUsers,
  saveUsers,
  findUserByUsername,
  findUserById,
  createUser,
  updateUser,
  deleteUser,
  recordLogin,
  ensureDefaultAdmin,
};

'use strict';
/**
 * KV Storage 추상화 계층.
 *
 * 동작 모드:
 *   1. mock (기본):   data/mock/<name>.json 파일 기반. DB 불필요. 즉시 동작.
 *   2. mysql:         _kv_store(name VARCHAR, data JSON) 테이블 사용.
 *                     실패 시 자동으로 mock 모드로 fallback.
 *
 * 모드 전환:
 *   DB_MODE=mysql      → MySQL 시도, 실패 시 mock 폴백
 *   DB_MODE=mock (기본) → 곧바로 mock
 *
 * 호출 인터페이스 (server-mock.js와 src/agent/token.js가 사용):
 *   loadSync(name)         → 저장된 값 또는 null
 *   saveSync(name, data)   → boolean (성공 여부)
 *   initialize()           → async, { mode, status }
 *                              status: 'ok' | 'fallback' | 'mock'
 *   preloadAll()           → async, MySQL 모드에서만 의미. mock 모드면 no-op.
 *   .mode                  → 'mock' | 'mysql'
 *
 * mock 모드의 동기 인터페이스 유지를 위해 메모리 캐시 + 파일 동기 I/O 사용.
 * MySQL 모드도 호출 측이 동기 호출이므로, initialize 시 모든 키를 메모리에
 * 로드(preloadAll) 후 in-memory 동기 접근 + 쓰기만 비동기 fire-and-forget.
 */

const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..');
const MOCK_DIR = path.join(ROOT, 'data', 'mock');

// 모듈 상태
const state = {
  mode: 'mock',          // 'mock' | 'mysql'
  status: 'mock',        // 'ok' | 'fallback' | 'mock'
  cache: new Map(),      // name → data (메모리 캐시; mock/mysql 공통)
  mysql: {
    pool: null,
    table: '_kv_store',
  },
};

// ───── Mock (파일) 백엔드 ─────────────────────────────────────

function _mockPath(name) {
  return path.join(MOCK_DIR, name + '.json');
}

function _mockLoad(name) {
  const p = _mockPath(name);
  if (!fs.existsSync(p)) return null;
  try {
    const raw = fs.readFileSync(p, 'utf8');
    if (!raw.trim()) return null;
    return JSON.parse(raw);
  } catch (e) {
    console.warn(`[storage] mock 파일 파싱 실패 ${name}: ${e.message}`);
    return null;
  }
}

function _mockSave(name, data) {
  try {
    fs.mkdirSync(MOCK_DIR, { recursive: true });
    // 원자성: tmp 파일에 쓰고 rename
    const finalPath = _mockPath(name);
    const tmpPath = finalPath + '.tmp';
    fs.writeFileSync(tmpPath, JSON.stringify(data, null, 2), 'utf8');
    fs.renameSync(tmpPath, finalPath);
    return true;
  } catch (e) {
    console.error(`[storage] mock 파일 저장 실패 ${name}: ${e.message}`);
    return false;
  }
}

// ───── MySQL 백엔드 ─────────────────────────────────────────

async function _mysqlInit() {
  let mysql;
  try {
    mysql = require('mysql2/promise');
  } catch (e) {
    return { ok: false, error: 'mysql2 패키지가 설치되지 않음 (npm install mysql2)' };
  }

  const config = require('../config').db;

  try {
    const pool = mysql.createPool({
      host: config.host,
      port: config.port,
      user: config.user,
      password: config.password,
      database: config.database,
      connectionLimit: config.connectionLimit,
      charset: config.charset,
      waitForConnections: true,
    });
    // 연결 헬스체크
    const conn = await pool.getConnection();
    await conn.ping();
    conn.release();

    // _kv_store 테이블 확보
    await pool.query(`
      CREATE TABLE IF NOT EXISTS ${state.mysql.table} (
        name VARCHAR(64) PRIMARY KEY,
        data JSON NOT NULL,
        updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                                  ON UPDATE CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
    `);

    state.mysql.pool = pool;
    return { ok: true };
  } catch (e) {
    return { ok: false, error: e.message };
  }
}

async function _mysqlLoadAll() {
  const [rows] = await state.mysql.pool.query(
    `SELECT name, data FROM ${state.mysql.table}`
  );
  for (const r of rows) {
    // mysql2가 JSON 컬럼을 자동 파싱
    state.cache.set(r.name, r.data);
  }
  return rows.length;
}

function _mysqlSaveAsync(name, data) {
  // 호출 측은 동기 인터페이스 — 실패해도 메모리는 이미 갱신됨
  // 운영 환경에선 큐잉/재시도가 필요하지만 PoC 수준에서는 fire-and-forget
  if (!state.mysql.pool) return;
  state.mysql.pool
    .query(
      `INSERT INTO ${state.mysql.table}(name, data) VALUES (?, CAST(? AS JSON))
       ON DUPLICATE KEY UPDATE data = VALUES(data)`,
      [name, JSON.stringify(data)]
    )
    .catch(e => {
      console.error(`[storage] MySQL 저장 실패 ${name}: ${e.message}`);
    });
}

// ───── 외부 인터페이스 ──────────────────────────────────────

function loadSync(name) {
  // mock 모드도 캐시 우선 (성능)
  if (state.cache.has(name)) {
    return state.cache.get(name);
  }
  if (state.mode === 'mock') {
    const data = _mockLoad(name);
    if (data !== null) state.cache.set(name, data);
    return data;
  }
  // MySQL 모드인데 캐시에 없음 = 키 자체가 없음 (preloadAll에서 다 로드됨)
  return null;
}

function saveSync(name, data) {
  // 캐시 먼저 갱신 (즉시 후속 loadSync가 최신값 반환하도록)
  state.cache.set(name, data);

  if (state.mode === 'mock') {
    return _mockSave(name, data);
  }
  if (state.mode === 'mysql') {
    _mysqlSaveAsync(name, data);
    // 백업: mock 파일에도 동기 저장 (DB 장애 시 복구용)
    _mockSave(name, data);
    return true;
  }
  return false;
}

async function initialize() {
  const requestedMode = (process.env.DB_MODE || 'mock').toLowerCase();

  if (requestedMode !== 'mysql') {
    state.mode = 'mock';
    state.status = 'mock';
    // mock 디렉토리 보장
    fs.mkdirSync(MOCK_DIR, { recursive: true });
    return { mode: 'mock', status: 'mock' };
  }

  // MySQL 시도
  const result = await _mysqlInit();
  if (result.ok) {
    state.mode = 'mysql';
    state.status = 'ok';
    return { mode: 'mysql', status: 'ok' };
  }

  // 실패 → mock fallback
  console.warn(`[storage] MySQL 연결 실패 → mock 모드로 폴백: ${result.error}`);
  state.mode = 'mock';
  state.status = 'fallback';
  fs.mkdirSync(MOCK_DIR, { recursive: true });
  return { mode: 'mock', status: 'fallback', error: result.error };
}

async function preloadAll() {
  if (state.mode !== 'mysql') return 0;
  try {
    const n = await _mysqlLoadAll();
    console.log(`[storage] MySQL preload: ${n}개 키 로드`);
    return n;
  } catch (e) {
    console.error(`[storage] preload 실패: ${e.message}`);
    return 0;
  }
}

async function shutdown() {
  if (state.mysql.pool) {
    try { await state.mysql.pool.end(); } catch (_) { /* ignore */ }
    state.mysql.pool = null;
  }
}

// state.mode를 모듈 속성처럼 노출 (server-mock.js가 kvStorage.mode 참조)
module.exports = {
  loadSync,
  saveSync,
  initialize,
  preloadAll,
  shutdown,
  get mode() { return state.mode; },
  get status() { return state.status; },
};

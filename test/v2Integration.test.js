'use strict';
/**
 * 룰 엔진 v2 통합 테스트 — 실제 SecuMS Unix 샘플 사용.
 *
 * better-sqlite3가 없으면 mockDatabase로 폴백 (python sqlite3 사용).
 */

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');
const { spawnSync } = require('child_process');

const FIXTURE = path.join(__dirname, 'fixtures/secums-unix-sample.db');
const RULES_FILE = path.join(__dirname, '../rules/secums-unix-v2.0.yaml');

// better-sqlite3 시도 → 실패하면 python wrapper
let openDB;
try {
  const Database = require('better-sqlite3');
  // 실제로 인스턴스 생성 시도 (native binding이 없으면 여기서 throw)
  const testDb = new Database(FIXTURE, { readonly: true });
  testDb.close();
  openDB = () => new Database(FIXTURE, { readonly: true });
} catch (e) {
  // native binding 실패 → python wrapper로 폴백
  openDB = () => _pythonSqliteWrapper(FIXTURE);
}

function _pythonSqliteWrapper(filepath) {
  function query(sql) {
    const runner = path.join(__dirname, '../../_sqlite_runner.py');
    let runnerPath = runner;
    if (!fs.existsSync(runnerPath)) {
      runnerPath = '/home/claude/_sqlite_runner.py';
    }
    const r = spawnSync('python3', [runnerPath, filepath], { input: sql, encoding: 'utf8' });
    if (r.status !== 0) throw new Error('python: ' + r.stderr);
    return JSON.parse(r.stdout);
  }
  return {
    prepare(sql) {
      return {
        get(...args) { const r = query(_bind(sql, args)); return r[0]; },
        all(...args) { return query(_bind(sql, args)); },
      };
    },
    close() {},
  };
}

function _bind(sql, args) {
  let i = 0;
  return sql.replace(/\?/g, () => {
    const v = args[i++];
    if (typeof v === 'number') return String(v);
    return `'${String(v).replace(/'/g, "''")}'`;
  });
}

const secumsUnix = require('../src/engine/adapters/secumsUnix');
const { evaluateAll } = require('../src/engine/ruleEngineV2');

let rules;
let db;

beforeAll(() => {
  rules = yaml.load(fs.readFileSync(RULES_FILE, 'utf8')).rules;
  db = openDB();
});

afterAll(() => { if (db) db.close(); });

describe('Adapter v5 — Raw 추출만', () => {
  test('detect()', () => {
    expect(secumsUnix.detect(db)).toBe(true);
  });

  test('extractMeta()', () => {
    const meta = secumsUnix.extractMeta(db);
    expect(meta.host).toBe('jessy62');
    expect(meta.hostOs).toBe('linux');
    expect(meta.osVersion).toBe('CentOS7.5.1804');
  });

  test('listTables() — 주요 U_*_TB 발견', () => {
    const tables = secumsUnix.listTables(db);
    const names = tables.map(t => t.table);
    expect(names).toContain('U_PASSWD_TB');
    expect(names).toContain('U_FILEATTR_TB');
    expect(names).toContain('U_LISTENINGPORT_TB');
    expect(names).toContain('U_PAM_TB');
  });

  test('querySlice() — /etc/passwd 권한 조회', () => {
    const rows = secumsUnix.querySlice(db,
      "SELECT FILEPATH, PERMISSION FROM U_FILEATTR_TB WHERE FILEPATH='/etc/passwd'");
    expect(rows.length).toBe(1);
    expect(rows[0].PERMISSION).toBe('0644');
  });

  test('querySlice() — SELECT 외 거부', () => {
    expect(() => secumsUnix.querySlice(db, "DROP TABLE U_PASSWD_TB"))
      .toThrow(/SELECT/);
    expect(() => secumsUnix.querySlice(db, "DELETE FROM U_PASSWD_TB"))
      .toThrow(/SELECT/);  // DELETE는 첫 정규식에서 거부됨
  });
});

describe('룰 엔진 v2 — 현재 룰셋(U-XX, LLM 기반)', () => {
  const { evaluateOne } = require('../src/engine/ruleEngineV2');

  test('evaluateOne(U-01) — LLM 없으면 점검불가(na), 크래시 없음', async () => {
    const rule = rules.find(r => r.rule_id === 'U-01');
    expect(rule).toBeTruthy();
    const r = await evaluateOne({ adapter: secumsUnix, db, rule });
    expect(r.eval_method).toBe('na');
    expect(['양호','취약','판정불가','점검불가']).toContain(r.status);
  });

  test('evaluateOne — rule 누락 방어(점검불가, 크래시 없음)', async () => {
    const r = await evaluateOne({ adapter: secumsUnix, db, rule: undefined });
    expect(r.status).toBe('점검불가');
    expect(r.eval_method).toBe('na');
  });

  test('evaluateAll() — 전체 룰 평가, 크래시 없이 결과 반환', async () => {
    const { results, summary } = await evaluateAll({ adapter: secumsUnix, db, rules, hostOs: 'linux' });
    expect(results.length).toBeGreaterThan(0);
    expect(summary.total).toBe(results.length);
    expect(results.every(r => ['양호','취약','판정불가','점검불가'].includes(r.status))).toBe(true);
  });
});

describe('룰 엔진 v2 — mock LLM (있으면)', () => {
  let llmClient = null;
  try { process.env.LLM_PROVIDER = 'mock'; llmClient = require('../src/engine/llm/client').createClient(); } catch (e) { llmClient = null; }
  const { evaluateOne } = require('../src/engine/ruleEngineV2');
  (llmClient ? test : test.skip)('evaluateOne(U-01) with mock LLM → eval_method llm', async () => {
    const rule = rules.find(r => r.rule_id === 'U-01');
    const r = await evaluateOne({ adapter: secumsUnix, db, rule, llmClient });
    expect(r.eval_method).toBe('llm');
  });
});

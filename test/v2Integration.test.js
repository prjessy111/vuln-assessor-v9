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

describe('룰 엔진 v2 — simple_check 평가', () => {
  test('FILE-001 (/etc/passwd 권한): perm_le 양호', async () => {
    const rule = rules.find(r => r.rule_id === 'FILE-001');
    const { evaluateOne } = require('../src/engine/ruleEngineV2');
    const r = await evaluateOne({ adapter: secumsUnix, db, rule });
    expect(r.eval_method).toBe('simple');
    expect(r.status).toBe('양호');
    expect(r.evidence).toMatch(/0644/);
  });

  test('FILE-002 (/etc/shadow 권한): perm_le 양호 (0000 ≤ 0400)', async () => {
    const rule = rules.find(r => r.rule_id === 'FILE-002');
    const { evaluateOne } = require('../src/engine/ruleEngineV2');
    const r = await evaluateOne({ adapter: secumsUnix, db, rule });
    expect(r.eval_method).toBe('simple');
    expect(r.status).toBe('양호');
  });

  test('SVC-001 (Telnet): row_count_zero 양호 (포트 23 없음)', async () => {
    const rule = rules.find(r => r.rule_id === 'SVC-001');
    const { evaluateOne } = require('../src/engine/ruleEngineV2');
    const r = await evaluateOne({ adapter: secumsUnix, db, rule });
    expect(r.eval_method).toBe('simple');
    expect(r.status).toBe('양호');
  });

  test('SVC-002 (FTP): row_count_zero 취약 (포트 21 발견)', async () => {
    const rule = rules.find(r => r.rule_id === 'SVC-002');
    const { evaluateOne } = require('../src/engine/ruleEngineV2');
    const r = await evaluateOne({ adapter: secumsUnix, db, rule });
    expect(r.eval_method).toBe('simple');
    expect(r.status).toBe('취약');
    expect(r.evidence).toMatch(/rowCount/);
  });

  test('ACC-001 (빈 패스워드): row_count_zero 취약 (NULLPW=YES 3건)', async () => {
    const rule = rules.find(r => r.rule_id === 'ACC-001');
    const { evaluateOne } = require('../src/engine/ruleEngineV2');
    const r = await evaluateOne({ adapter: secumsUnix, db, rule });
    expect(r.eval_method).toBe('simple');
    expect(r.status).toBe('취약');
  });

  test('ACC-003 (시스템 계정 로그인 셸): row_count_zero', async () => {
    const rule = rules.find(r => r.rule_id === 'ACC-003');
    const { evaluateOne } = require('../src/engine/ruleEngineV2');
    const r = await evaluateOne({ adapter: secumsUnix, db, rule });
    expect(r.eval_method).toBe('simple');
    expect(['양호', '취약']).toContain(r.status);
  });
});

describe('룰 엔진 v2 — evaluation_prompt (LLM 필요)', () => {
  test('SVC-003 (RPC): LLM 없으면 점검불가', async () => {
    const rule = rules.find(r => r.rule_id === 'SVC-003');
    const { evaluateOne } = require('../src/engine/ruleEngineV2');
    const r = await evaluateOne({ adapter: secumsUnix, db, rule });
    expect(r.eval_method).toBe('na');
    expect(r.status).toBe('점검불가');
    expect(r.reason).toMatch(/LLM/);
  });

  test('SVC-003 (RPC): mock LLM 클라이언트로 평가', async () => {
    process.env.LLM_PROVIDER = 'mock';
    const { createClient } = require('../src/engine/llm/client');
    const llmClient = createClient();
    const rule = rules.find(r => r.rule_id === 'SVC-003');
    const { evaluateOne } = require('../src/engine/ruleEngineV2');
    const r = await evaluateOne({ adapter: secumsUnix, db, rule, llmClient });
    expect(r.eval_method).toBe('llm');
    expect(['양호', '취약', '점검불가']).toContain(r.status);
  });
});

describe('룰 엔진 v2 — 전체 룰셋 평가', () => {
  test('evaluateAll() — 12개 룰, simple만 사용 (LLM 없음)', async () => {
    const { results, summary } = await evaluateAll({
      adapter: secumsUnix, db, rules, hostOs: 'linux',
    });
    expect(results.length).toBe(12);  // 룰셋의 전체 개수
    expect(summary.total).toBe(12);

    // simple로 평가된 게 절반 이상이어야 함
    const simpleCount = results.filter(r => r.eval_method === 'simple').length;
    expect(simpleCount).toBeGreaterThan(5);
  });

  test('evaluateAll() with mock LLM — LLM 룰도 평가됨', async () => {
    process.env.LLM_PROVIDER = 'mock';
    const { createClient } = require('../src/engine/llm/client');
    const llmClient = createClient();
    const { results, summary } = await evaluateAll({
      adapter: secumsUnix, db, rules, hostOs: 'linux', llmClient,
    });
    // 점검불가('na' eval_method)가 0건이어야 함 (모든 룰이 평가됨)
    const naCount = results.filter(r => r.eval_method === 'na').length;
    expect(naCount).toBe(0);
  });
});

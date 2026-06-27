'use strict';
const fs = require('fs');
const path = require('path');
const os = require('os');
const Database = require('better-sqlite3');
const { loadRaw } = require('../src/engine/rawLoader');

function makeRawDb(rows) {
  const p = path.join(os.tmpdir(), `raw-test-${Date.now()}-${Math.random().toString(36).slice(2)}.db`);
  const db = new Database(p);
  db.exec(`
    CREATE TABLE raw_data (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      host TEXT NOT NULL, os_type TEXT NOT NULL,
      category TEXT, check_key TEXT NOT NULL, value TEXT,
      collected_at TEXT DEFAULT CURRENT_TIMESTAMP
    );`);
  const stmt = db.prepare(
    `INSERT INTO raw_data(host, os_type, category, check_key, value) VALUES (?,?,?,?,?)`
  );
  for (const r of rows) stmt.run(...r);
  db.close();
  return p;
}

describe('rawLoader.loadRaw', () => {
  test('정상 파일 로딩', () => {
    const p = makeRawDb([
      ['linux01', 'linux', 'config', 'passwd_perm', '644'],
      ['linux01', 'linux', 'service', 'telnet_service', 'inactive'],
    ]);
    const r = loadRaw(p, 'linux01');
    expect(r.host).toBe('linux01');
    expect(r.hostOs).toBe('linux');
    expect(r.values.get('passwd_perm')).toBe('644');
    expect(r.sha256).toMatch(/^[a-f0-9]{64}$/);
    fs.unlinkSync(p);
  });

  test('host 필터링 시 데이터 없으면 에러', () => {
    const p = makeRawDb([['linux01', 'linux', 'c', 'k', 'v']]);
    expect(() => loadRaw(p, 'unknown_host')).toThrow(/데이터가 없습니다/);
    fs.unlinkSync(p);
  });

  test('raw_data 테이블 없으면 에러', () => {
    const p = path.join(os.tmpdir(), `empty-${Date.now()}.db`);
    const db = new Database(p); db.exec(`CREATE TABLE other (id INT)`); db.close();
    expect(() => loadRaw(p, null)).toThrow(/raw_data 테이블/);
    fs.unlinkSync(p);
  });

  test('SQLite가 아닌 파일은 거부', () => {
    const p = path.join(os.tmpdir(), `bad-${Date.now()}.db`);
    fs.writeFileSync(p, 'NOT A SQLITE FILE');
    expect(() => loadRaw(p, null)).toThrow(/유효한 SQLite/);
    fs.unlinkSync(p);
  });
});

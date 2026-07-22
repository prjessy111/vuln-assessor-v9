'use strict';
/**
 * SecuMS Unix 어댑터 통합 테스트 (v5 raw 추출 API 기준).
 * 실제 SecuMS Agent에서 export된 SQLite 샘플로 검증.
 * better-sqlite3 native build 실패 시 스킵.
 *
 * ※ 구 monolithic extract() 는 제거되고 extractMeta()+extractDiagnoseItems() 로 분리됨.
 *   판정(OK→양호 등)은 어댑터가 아니라 상위 판정/리포트 계층 책임(수집/판정 분리).
 */
const path = require('path');

const FIXTURE = path.join(__dirname, 'fixtures/secums-unix-sample.db');

let Database;
try {
  Database = require('better-sqlite3');
} catch (e) {
  console.warn('[skip] better-sqlite3 미설치 - SecuMS 어댑터 테스트 스킵');
}

const secumsUnix = require('../src/engine/adapters/secumsUnix');

(Database ? describe : describe.skip)('SecuMS Unix Adapter (real sample)', () => {
  let db;
  beforeAll(() => { db = new Database(FIXTURE, { readonly: true }); });
  afterAll(() => { if (db) db.close(); });

  test('detect() — SecuMS Unix 파일로 인식', () => {
    expect(secumsUnix.detect(db)).toBe(true);
  });

  test('extractMeta() — 기본 정보', () => {
    const m = secumsUnix.extractMeta(db);
    expect(m.host).toBe('jessy62');
    expect(m.hostOs).toBe('linux');
    expect(m.osVersion).toBe('CentOS7.5.1804');
  });

  test('listTables() — 주요 U_*_TB 발견', () => {
    const names = secumsUnix.listTables(db).map(t => t.table);
    expect(names).toContain('U_PASSWD_TB');
    expect(names).toContain('U_FILEATTR_TB');
    expect(names).toContain('U_LISTENINGPORT_TB');
  });

  test('querySlice() — /etc/passwd 권한 조회', () => {
    const rows = secumsUnix.querySlice(db,
      "SELECT FILEPATH, PERMISSION FROM U_FILEATTR_TB WHERE FILEPATH='/etc/passwd'");
    expect(rows.length).toBe(1);
    expect(rows[0].PERMISSION).toBe('0644');
  });

  test('querySlice() — SELECT 외 거부', () => {
    expect(() => secumsUnix.querySlice(db, "DROP TABLE U_PASSWD_TB")).toThrow(/SELECT/);
    expect(() => secumsUnix.querySlice(db, "DELETE FROM U_PASSWD_TB")).toThrow(/SELECT/);
  });

  describe('extractDiagnoseItems() — 점검 항목 추출', () => {
    let items;
    beforeAll(() => { items = secumsUnix.extractDiagnoseItems(db); });

    test('50개 항목', () => {
      expect(Array.isArray(items)).toBe(true);
      expect(items.length).toBe(50);
    });

    test('각 항목에 chk_id·secums_verdict', () => {
      for (const it of items) {
        expect(it.chk_id).toBeTruthy();
        expect(['OK', 'BAD', 'INFO']).toContain(it.secums_verdict);
      }
    });

    test('SecuMS 정답지 분포 — OK 30 · BAD 18 · INFO 2', () => {
      const vd = {};
      for (const it of items) vd[it.secums_verdict] = (vd[it.secums_verdict] || 0) + 1;
      expect(vd.OK).toBe(30);
      expect(vd.BAD).toBe(18);
      expect(vd.INFO).toBe(2);
    });
  });
});

'use strict';
/**
 * SecuMS Unix 어댑터 통합 테스트.
 * 실제 SecuMS Agent에서 export된 SQLite 샘플 파일로 검증.
 *
 * 참고: better-sqlite3는 native build가 필요하므로
 * CI/샌드박스 환경에서 빌드 실패 시 이 테스트는 skip되도록 try-catch 처리.
 */

const path = require('path');

const FIXTURE = path.join(__dirname, 'fixtures/secums-unix-sample.db');

let Database;
try {
  Database = require('better-sqlite3');
} catch (e) {
  console.warn('[skip] better-sqlite3 미설치 환경 - SecuMS 어댑터 통합 테스트 스킵');
}

const secumsUnix = require('../src/engine/adapters/secumsUnix');

(Database ? describe : describe.skip)('SecuMS Unix Adapter (real sample)', () => {
  let db;
  beforeAll(() => { db = new Database(FIXTURE, { readonly: true }); });
  afterAll(() => { if (db) db.close(); });

  test('detect() — SecuMS Unix 파일로 인식', () => {
    expect(secumsUnix.detect(db)).toBe(true);
  });

  test('extract() — 기본 정보 추출', () => {
    const r = secumsUnix.extract(db);
    expect(r.host).toBe('jessy62');
    expect(r.hostOs).toBe('linux');
    expect(r.osVersion).toBe('CentOS7.5.1804');
  });

  test('extract() — 50개 점검 항목, 정확한 카운트', () => {
    const r = secumsUnix.extract(db);
    expect(r.items.length).toBe(50);
    expect(r.summary.total).toBe(50);
    expect(r.summary.vuln).toBe(18);
    expect(r.summary.safe).toBe(30);
    expect(r.summary.na).toBe(2);
  });

  test('extract() — 상태 매핑 (OK→양호, BAD→취약, INFO→점검불가)', () => {
    const r = secumsUnix.extract(db);
    const statuses = new Set(r.items.map(i => i.status));
    expect(statuses).toEqual(new Set(['양호', '취약', '점검불가']));
  });

  test('extract() — BAD 항목은 상세 사유가 포함됨', () => {
    const r = secumsUnix.extract(db);
    const vulns = r.items.filter(i => i.status === '취약');
    for (const v of vulns) {
      expect(v.reason).toBeTruthy();
      expect(v.reason.length).toBeGreaterThan(0);
    }
  });

  test('extract() — 점검명이 채워짐 (대부분의 항목)', () => {
    const r = secumsUnix.extract(db);
    const withTitle = r.items.filter(i => i.title && !i.title.startsWith('(이름 없음'));
    expect(withTitle.length).toBeGreaterThan(40);  // 50건 중 대다수
  });

  test('extract() — 카테고리 자동 분류', () => {
    const r = secumsUnix.extract(db);
    const cats = {};
    for (const it of r.items) cats[it.category] = (cats[it.category] || 0) + 1;
    expect(cats['계정관리']).toBeGreaterThan(0);
    expect(cats['서비스관리']).toBeGreaterThan(0);
    expect(cats['파일및디렉토리관리']).toBeGreaterThan(0);
  });

  test('extract() — 특정 알려진 취약 항목 검증', () => {
    const r = secumsUnix.extract(db);
    const items = new Map(r.items.map(i => [i.rule_id, i]));

    // BAD 항목들의 sample 검증
    expect(items.get('os-linux-340').status).toBe('취약');     // ftp
    expect(items.get('os-linux-2389').status).toBe('취약');    // ftp port listen
    expect(items.get('os-linux-271').status).toBe('취약');     // 계정잠금
    expect(items.get('os-linux-377').status).toBe('취약');     // 패스워드 복잡도

    // OK 항목 검증
    expect(items.get('os-linux-1973').status).toBe('양호');    // telnet (OK)
    expect(items.get('os-linux-188').status).toBe('양호');     // /etc/passwd OK

    // INFO 검증
    expect(items.get('os-linux-380').status).toBe('점검불가'); // cron.allow INFO
  });
});

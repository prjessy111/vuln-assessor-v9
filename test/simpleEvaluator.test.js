'use strict';
const { evaluate } = require('../src/engine/evaluators/simpleEvaluator');

function _rule(simple_check) {
  return { rule_id: 'T-1', simple_check };
}

describe('SimpleEvaluator', () => {
  // ─── perm_le / perm_ge ────────────────────────────────────────────
  test('perm_le: 644 ≤ 644 → 양호', () => {
    const r = evaluate(_rule({ type: 'perm_le', field: 'PERMISSION', max: '0644' }),
                       [{ PERMISSION: '0644' }]);
    expect(r.status).toBe('양호');
  });

  test('perm_le: 0777 > 0644 → 취약', () => {
    const r = evaluate(_rule({ type: 'perm_le', field: 'PERMISSION', max: '0644' }),
                       [{ PERMISSION: '0777' }]);
    expect(r.status).toBe('취약');
  });

  test('perm_le: 빈 context → 점검불가', () => {
    const r = evaluate(_rule({ type: 'perm_le', field: 'PERMISSION', max: '0644' }), []);
    expect(r.status).toBe('점검불가');
  });

  test('perm_le: 대소문자 무시 field 매칭', () => {
    const r = evaluate(_rule({ type: 'perm_le', field: 'permission', max: '0644' }),
                       [{ PERMISSION: '0644' }]);
    expect(r.status).toBe('양호');
  });

  // ─── row_count_zero ───────────────────────────────────────────────
  test('row_count_zero: 0건 → 양호', () => {
    const r = evaluate(_rule({ type: 'row_count_zero' }), []);
    expect(r.status).toBe('양호');
  });

  test('row_count_zero: 5건 → 취약', () => {
    const r = evaluate(_rule({ type: 'row_count_zero' }),
                       [1,2,3,4,5].map(i => ({ x: i })));
    expect(r.status).toBe('취약');
  });

  // ─── service_off / service_on ─────────────────────────────────────
  test('service_off: inactive → 양호', () => {
    const r = evaluate(_rule({ type: 'service_off', field: 'STATE' }),
                       [{ STATE: 'inactive' }]);
    expect(r.status).toBe('양호');
  });

  test('service_off: 빈 결과는 양호로 처리 (서비스 없음 = 비활성)', () => {
    const r = evaluate(_rule({ type: 'service_off', field: 'STATE' }), []);
    expect(r.status).toBe('양호');
  });

  test('service_on: stopped → 취약', () => {
    const r = evaluate(_rule({ type: 'service_on', field: 'STATE' }),
                       [{ STATE: 'stopped' }]);
    expect(r.status).toBe('취약');
  });

  // ─── int_min / int_max ────────────────────────────────────────────
  test('int_min: 8 ≥ 8 → 양호', () => {
    const r = evaluate(_rule({ type: 'int_min', field: 'N', min: 8 }),
                       [{ N: '8' }]);
    expect(r.status).toBe('양호');
  });

  test('int_max: 90 ≤ 90 → 양호', () => {
    const r = evaluate(_rule({ type: 'int_max', field: 'N', max: 90 }),
                       [{ N: '90' }]);
    expect(r.status).toBe('양호');
  });

  // ─── contains / equals / regex ────────────────────────────────────
  test('equals: 대소문자 무시', () => {
    const r = evaluate(_rule({ type: 'equals', field: 'V', expect: 'no' }),
                       [{ V: 'NO' }]);
    expect(r.status).toBe('양호');
  });

  test('regex: 한국어 패턴', () => {
    const r = evaluate(_rule({ type: 'regex', field: 'V', pattern: '^성공|OK$' }),
                       [{ V: '성공' }]);
    expect(r.status).toBe('양호');
  });

  test('not_contains: keyword 없음 → 양호', () => {
    const r = evaluate(_rule({ type: 'not_contains', field: 'V', keyword: 'Administrator' }),
                       [{ V: 'SuperAdmin' }]);
    expect(r.status).toBe('양호');
  });

  // ─── every_row / any_row ──────────────────────────────────────────
  test('every_row: 모든 행이 NULLPW != YES 면 양호', () => {
    const r = evaluate(_rule({ type: 'every_row', field: 'NULLPW', op: '!=', value: 'YES' }),
                       [{ NULLPW: 'NO' }, { NULLPW: 'NO' }, { NULLPW: 'NO' }]);
    expect(r.status).toBe('양호');
  });

  test('every_row: 하나라도 NULLPW=YES면 취약', () => {
    const r = evaluate(_rule({ type: 'every_row', field: 'NULLPW', op: '!=', value: 'YES' }),
                       [{ NULLPW: 'NO' }, { NULLPW: 'YES' }]);
    expect(r.status).toBe('취약');
  });

  test('any_row: 조건 만족 행 1개라도 있으면 양호', () => {
    const r = evaluate(_rule({ type: 'any_row', field: 'PORT', op: '==', value: '22' }),
                       [{ PORT: '21' }, { PORT: '22' }, { PORT: '80' }]);
    expect(r.status).toBe('양호');
  });

  // ─── null 처리 ────────────────────────────────────────────────────
  test('미지원 type → null 반환 (LLM 폴백 신호)', () => {
    const r = evaluate(_rule({ type: 'totally_unknown_type' }), []);
    expect(r).toBeNull();
  });

  test('simple_check 없음 → null', () => {
    const r = evaluate({ rule_id: 'T' }, []);
    expect(r).toBeNull();
  });
});

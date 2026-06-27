'use strict';
const { evaluate } = require('../src/engine/ruleEngine');

describe('ruleEngine.evaluate', () => {
  const rules = [
    { rule_id: 'U-01', title: 'root remote login', category: '계정관리',
      severity: '상', os_target: 'linux', check_key: 'sshd_permit_root_login',
      check_type: 'equals', check_param: { expect: 'no' }, recommend: '...' },
    { rule_id: 'U-05', title: 'passwd perm', category: '파일권한',
      severity: '상', os_target: 'linux', check_key: 'passwd_perm',
      check_type: 'perm_le', check_param: { max: '644' }, recommend: '...' },
    { rule_id: 'W-01', title: 'admin rename', category: '계정관리',
      severity: '상', os_target: 'windows', check_key: 'admin_account_renamed',
      check_type: 'not_contains', check_param: { keyword: 'Administrator' }, recommend: '...' },
  ];

  test('linux 평가 시 windows 룰은 제외', () => {
    const raw = new Map([['sshd_permit_root_login', 'no'], ['passwd_perm', '644']]);
    const { results, summary } = evaluate(rules, raw, 'linux');
    expect(results.length).toBe(2);
    expect(summary.safe).toBe(2);
    expect(summary.vuln).toBe(0);
  });

  test('취약 / N/A 혼합', () => {
    const raw = new Map([['sshd_permit_root_login', 'yes']]); // passwd_perm 없음 → N/A
    const { summary } = evaluate(rules, raw, 'linux');
    expect(summary.vuln).toBe(1);
    expect(summary.na).toBe(1);
    expect(summary.safe).toBe(0);
  });

  test('windows 룰만 적용', () => {
    const raw = new Map([['admin_account_renamed', 'SuperAdmin']]);
    const { results, summary } = evaluate(rules, raw, 'windows');
    expect(results.length).toBe(1);
    expect(summary.safe).toBe(1);
  });
});

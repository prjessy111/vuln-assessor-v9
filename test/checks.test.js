'use strict';
const { runCheck } = require('../src/engine/checks');

describe('checks', () => {
  test('perm_le 양호/취약', () => {
    expect(runCheck('perm_le', '644', { max: '644' }).status).toBe('양호');
    expect(runCheck('perm_le', '777', { max: '644' }).status).toBe('취약');
    expect(runCheck('perm_le', '-rw-r--r-- 644 root', { max: '644' }).status).toBe('양호');
  });

  test('perm_le 파싱 실패', () => {
    expect(runCheck('perm_le', 'abc', { max: '644' }).status).toBe('점검불가');
  });

  test('service_off', () => {
    expect(runCheck('service_off', 'inactive', {}).status).toBe('양호');
    expect(runCheck('service_off', 'active', {}).status).toBe('취약');
    expect(runCheck('service_off', '', {}).status).toBe('점검불가');
  });

  test('service_on', () => {
    expect(runCheck('service_on', 'running', {}).status).toBe('양호');
    expect(runCheck('service_on', 'stopped', {}).status).toBe('취약');
  });

  test('int_min/max', () => {
    expect(runCheck('int_min', '10', { min: 8 }).status).toBe('양호');
    expect(runCheck('int_min', '6',  { min: 8 }).status).toBe('취약');
    expect(runCheck('int_max', '90', { max: 90 }).status).toBe('양호');
    expect(runCheck('int_max', '99999', { max: 90 }).status).toBe('취약');
  });

  test('int_range_inclusive', () => {
    expect(runCheck('int_range_inclusive', '3', { min: 1, max: 5 }).status).toBe('양호');
    expect(runCheck('int_range_inclusive', '0', { min: 1, max: 5 }).status).toBe('취약');
    expect(runCheck('int_range_inclusive', '6', { min: 1, max: 5 }).status).toBe('취약');
  });

  test('contains / not_contains', () => {
    expect(runCheck('contains', 'PermitRootLogin no', { keyword: 'no' }).status).toBe('양호');
    expect(runCheck('not_contains', 'admin', { keyword: 'Administrator' }).status).toBe('양호');
    expect(runCheck('not_contains', 'Administrator', { keyword: 'Administrator' }).status).toBe('취약');
  });

  test('equals (case-insensitive)', () => {
    expect(runCheck('equals', 'False', { expect: 'false' }).status).toBe('양호');
    expect(runCheck('equals', 'True',  { expect: 'false' }).status).toBe('취약');
  });

  test('equals: expect=none', () => {
    expect(runCheck('equals', '', { expect: 'none' }).status).toBe('양호');
    expect(runCheck('equals', 'DATA, BACKUP', { expect: 'none' }).status).toBe('취약');
  });

  test('regex', () => {
    expect(runCheck('regex', 'Success and Failure',
      { pattern: '(?i)success.*failure|failure.*success' }).status).toBe('양호');
    expect(runCheck('regex', 'Success only',
      { pattern: '(?i)success.*failure' }).status).toBe('취약');
  });

  test('알 수 없는 check_type', () => {
    expect(runCheck('unknown_type', 'x', {}).status).toBe('점검불가');
  });

  test('NULL 값은 점검불가', () => {
    expect(runCheck('int_min', null, { min: 8 }).status).toBe('점검불가');
  });
});

'use strict';
// 테스트용 마스터키 사전 주입 (require 전에 설정)
const crypto = require('crypto');
process.env.ENCRYPTION_KEY = crypto.randomBytes(32).toString('base64');

const { encrypt, decrypt, generateMasterKey } = require('../src/util/crypto');

describe('crypto util', () => {
  test('암호화-복호화 라운드트립', () => {
    const plain = 'P@ssw0rd!한글비밀번호 123';
    const enc = encrypt(plain);
    expect(Buffer.isBuffer(enc)).toBe(true);
    expect(enc.length).toBeGreaterThan(plain.length + 28);  // iv+tag 오버헤드
    expect(decrypt(enc)).toBe(plain);
  });

  test('동일 평문이라도 IV가 달라 매번 다른 ciphertext', () => {
    const plain = 'same-password';
    const e1 = encrypt(plain);
    const e2 = encrypt(plain);
    expect(e1.equals(e2)).toBe(false);
    expect(decrypt(e1)).toBe(decrypt(e2));
  });

  test('null/undefined 처리', () => {
    expect(encrypt(null)).toBeNull();
    expect(decrypt(null)).toBeNull();
    expect(decrypt(Buffer.alloc(0))).toBeNull();
  });

  test('변조된 데이터는 인증 실패', () => {
    const enc = encrypt('secret');
    enc[30] = enc[30] ^ 0xFF;  // ciphertext 1바이트 변조
    expect(() => decrypt(enc)).toThrow();
  });

  test('마스터키 생성', () => {
    const k = generateMasterKey();
    expect(Buffer.from(k, 'base64').length).toBe(32);
  });
});

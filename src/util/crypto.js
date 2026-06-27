'use strict';
/**
 * AES-256-GCM 암복호화 유틸.
 *
 * 마스터키: 환경변수 ENCRYPTION_KEY (base64 인코딩된 32바이트)
 * 저장 형식: Buffer [iv(12) | tag(16) | ciphertext]
 *
 * 마스터키가 없으면 require 시점에 종료. 운영 환경에서는 반드시 .env에 설정.
 */
const crypto = require('crypto');

function _loadKey() {
  const b64 = process.env.ENCRYPTION_KEY;
  if (!b64) {
    // 개발 편의를 위해 fallback 키를 생성하되, 경고
    if (process.env.NODE_ENV !== 'production') {
      console.warn('[crypto] ENCRYPTION_KEY 미설정. 개발용 임시 키 사용. 비밀번호 영구 저장 불가.');
      return null;
    }
    throw new Error('ENCRYPTION_KEY 환경변수가 설정되지 않았습니다.');
  }
  const key = Buffer.from(b64, 'base64');
  if (key.length !== 32) {
    throw new Error(`ENCRYPTION_KEY는 base64로 인코딩된 32바이트여야 합니다. (현재 ${key.length} bytes)`);
  }
  return key;
}

const KEY = _loadKey();

/**
 * 평문 문자열을 암호화하여 Buffer로 반환 (DB VARBINARY 컬럼에 저장).
 */
function encrypt(plaintext) {
  if (!KEY) throw new Error('암호화 키가 설정되지 않았습니다.');
  if (plaintext === null || plaintext === undefined) return null;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', KEY, iv);
  const ct = Buffer.concat([cipher.update(String(plaintext), 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ct]);
}

/**
 * DB에서 읽어온 Buffer를 복호화하여 문자열로 반환.
 */
function decrypt(blob) {
  if (!KEY) throw new Error('암호화 키가 설정되지 않았습니다.');
  if (!blob || blob.length < 28) return null;
  const buf = Buffer.isBuffer(blob) ? blob : Buffer.from(blob);
  const iv = buf.subarray(0, 12);
  const tag = buf.subarray(12, 28);
  const ct = buf.subarray(28);
  const decipher = crypto.createDecipheriv('aes-256-gcm', KEY, iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
}

/**
 * 신규 마스터키 생성용 헬퍼 (CLI에서 호출):
 *   node -e "console.log(require('./src/util/crypto').generateMasterKey())"
 */
function generateMasterKey() {
  return crypto.randomBytes(32).toString('base64');
}

module.exports = { encrypt, decrypt, generateMasterKey };

'use strict';
/**
 * Agent Token 관리
 *
 * 각 서버(점검 대상)는 고유 토큰을 가짐.
 * Wrapper script가 이 토큰으로 인증하여 raw 데이터 업로드.
 *
 * 토큰 형식: 32바이트 무작위 hex (64자)
 * 저장: SHA-256 해시로 비교 (원본은 1회만 표시)
 */

const crypto = require('crypto');

/**
 * 새 토큰 생성 (원본 + 해시 반환).
 * 원본은 1회만 표시되고, 저장은 해시만.
 */
function generateToken() {
  const raw = crypto.randomBytes(32).toString('hex');
  const hash = crypto.createHash('sha256').update(raw).digest('hex');
  return { raw, hash };
}

/**
 * 토큰 검증 (timing-safe).
 */
function verifyToken(providedToken, storedHash) {
  if (!providedToken || !storedHash) return false;
  const providedHash = crypto.createHash('sha256').update(providedToken).digest('hex');
  const a = Buffer.from(providedHash, 'hex');
  const b = Buffer.from(storedHash, 'hex');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

/**
 * 토큰으로 서버 찾기.
 */
function findServerByToken(storage, token) {
  if (!token) return null;
  const servers = storage.loadSync('servers') || [];
  return servers.find(s => s.agent_token_hash && verifyToken(token, s.agent_token_hash));
}

/**
 * 서버에 토큰 발급/재발급.
 * 기존 토큰은 무효화됨.
 */
function issueToken(storage, serverId) {
  const servers = storage.loadSync('servers') || [];
  const server = servers.find(s => s.server_id == serverId);
  if (!server) throw new Error('서버를 찾을 수 없습니다');
  
  const { raw, hash } = generateToken();
  server.agent_token_hash = hash;
  server.agent_token_issued_at = new Date().toISOString().slice(0, 19).replace('T', ' ');
  storage.saveSync('servers', servers);
  
  return raw;  // 원본은 1회만 반환
}

/**
 * 토큰 폐기.
 */
function revokeToken(storage, serverId) {
  const servers = storage.loadSync('servers') || [];
  const server = servers.find(s => s.server_id == serverId);
  if (!server) throw new Error('서버를 찾을 수 없습니다');
  
  delete server.agent_token_hash;
  delete server.agent_token_issued_at;
  storage.saveSync('servers', servers);
}

/**
 * Agent 마지막 push 기록.
 */
function recordPush(storage, serverId, metadata) {
  const servers = storage.loadSync('servers') || [];
  const server = servers.find(s => s.server_id == serverId);
  if (!server) return;
  
  server.agent_last_push = new Date().toISOString().slice(0, 19).replace('T', ' ');
  server.agent_last_push_metadata = metadata;
  storage.saveSync('servers', servers);
}

module.exports = {
  generateToken,
  verifyToken,
  findServerByToken,
  issueToken,
  revokeToken,
  recordPush,
};

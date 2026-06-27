'use strict';
/**
 * Raw 수집 오케스트레이션 서비스.
 *
 * 책임:
 *  - 서버 1대 또는 여러 대에 대해 SSH 접속 → SQLite 스냅샷 → /data/raw/로 전송
 *  - collection_history 에 진행/성공/실패 이력 적재
 *  - 동시 수집 제한 (병렬 N개)
 *  - 옵션: 수집 후 자동 진단 실행 (assessmentService 연계)
 */
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const config = require('../config');
const serverDao = require('../dao/serverDao');
const collectionDao = require('../dao/collectionDao');
const { fetchRawSnapshot } = require('../engine/sshClient');
const { decrypt } = require('../util/crypto');

const MAX_CONCURRENT = 5;

function _sha256File(filepath) {
  const buf = fs.readFileSync(filepath);
  return crypto.createHash('sha256').update(buf).digest('hex');
}

function _safeFilename(s) {
  return String(s).replace(/[^a-zA-Z0-9._-]/g, '_');
}

/**
 * 단일 서버 수집.
 *
 * @param {object} server  - serverDao.findById() 결과
 * @param {string} triggeredBy - '수동:user1', '자동:cron', ...
 * @returns {{ ok, raw_file_path, raw_file_hash, file_size, error }}
 */
async function collectOne(server, triggeredBy) {
  // 1) 이력 INSERT (진행중)
  const collectionId = await collectionDao.insertStarted({
    server_id: server.server_id,
    triggered_by: triggeredBy,
  });

  // 2) 출력 경로 결정
  const stamp = new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19);
  const fname = `${_safeFilename(server.hostname)}_${stamp}.db`;
  const outPath = path.join(config.paths.rawStorage, fname);

  try {
    fs.mkdirSync(config.paths.rawStorage, { recursive: true });

    // 3) 비밀번호 인증이면 복호화하여 일시적으로 메모리에 보관
    const serverWithPw = { ...server };
    if (server.ssh_auth_type === 'password' && server.ssh_password_enc) {
      serverWithPw._decrypted_password = decrypt(server.ssh_password_enc);
    }

    // 4) SSH로 스냅샷 가져오기
    const { size } = await fetchRawSnapshot(serverWithPw, outPath);

    // 5) 무결성: SHA-256 계산
    const hash = _sha256File(outPath);

    // 6) 이력 마감(성공)
    await collectionDao.finishSuccess(collectionId, {
      raw_file_path: outPath,
      raw_file_hash: hash,
      file_size: size,
    });
    await serverDao.updateLastCollected(server.server_id);

    return {
      ok: true,
      collection_id: collectionId,
      raw_file_path: outPath,
      raw_file_hash: hash,
      file_size: size,
    };
  } catch (e) {
    // 실패 시 부분 다운로드 파일 정리
    try { if (fs.existsSync(outPath)) fs.unlinkSync(outPath); } catch (_) {}
    await collectionDao.finishFailure(collectionId, e.message);
    return { ok: false, collection_id: collectionId, error: e.message };
  }
}

/**
 * 다중 서버 수집 (동시 N개 제한).
 *
 * @param {number[]} serverIds
 * @param {string}   triggeredBy
 * @returns {Array}  각 서버별 결과
 */
async function collectMany(serverIds, triggeredBy) {
  // server 정보 일괄 로딩
  const servers = [];
  for (const id of serverIds) {
    const s = await serverDao.findById(id);
    if (s) servers.push(s);
  }

  const results = [];
  // 동시 실행 풀
  const queue = [...servers];
  const workers = Array.from({ length: Math.min(MAX_CONCURRENT, queue.length) }, async () => {
    while (queue.length) {
      const s = queue.shift();
      const r = await collectOne(s, triggeredBy);
      results.push({ server_id: s.server_id, hostname: s.hostname, ...r });
    }
  });
  await Promise.all(workers);
  return results;
}

module.exports = { collectOne, collectMany };

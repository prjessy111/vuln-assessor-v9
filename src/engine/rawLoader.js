'use strict';
const Database = require('better-sqlite3');
const fs = require('fs');
const crypto = require('crypto');

/**
 * raw SQLite 파일 검증 및 host별 키-값 맵 구성.
 *
 * @param {string} filePath - 업로드된 raw .db 파일 경로
 * @param {string} expectedHost - 진단 대상 서버의 hostname (필터링용)
 * @returns {{
 *   sha256: string,
 *   hostOs: string,      // 'linux' | 'windows'
 *   values: Map<string,string>  // check_key → value (가장 최근 값)
 * }}
 */
function loadRaw(filePath, expectedHost) {
  const buf = fs.readFileSync(filePath);
  const sha256 = crypto.createHash('sha256').update(buf).digest('hex');

  // SQLite 매직 헤더 검증
  if (buf.length < 16 || buf.slice(0, 16).toString('utf8').indexOf('SQLite format 3') !== 0) {
    throw new Error('유효한 SQLite 파일이 아닙니다.');
  }

  const db = new Database(filePath, { readonly: true, fileMustExist: true });
  try {
    // 스키마 검증
    const tbl = db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='raw_data'"
    ).get();
    if (!tbl) throw new Error("raw_data 테이블이 존재하지 않습니다.");

    // 컬럼 존재 확인
    const cols = db.prepare("PRAGMA table_info(raw_data)").all().map(r => r.name);
    for (const c of ['host', 'os_type', 'check_key', 'value', 'collected_at']) {
      if (!cols.includes(c)) {
        // 'key' 컬럼명을 쓰는 경우 호환 처리
        if (c === 'check_key' && cols.includes('key')) continue;
        throw new Error(`raw_data 테이블에 '${c}' 컬럼이 없습니다.`);
      }
    }
    const keyCol = cols.includes('check_key') ? 'check_key' : 'key';

    // 호스트 필터링 (expectedHost가 주어진 경우)
    const rows = expectedHost
      ? db.prepare(
          `SELECT host, os_type, ${keyCol} AS check_key, value, collected_at
           FROM raw_data WHERE host = ? ORDER BY collected_at DESC`
        ).all(expectedHost)
      : db.prepare(
          `SELECT host, os_type, ${keyCol} AS check_key, value, collected_at
           FROM raw_data ORDER BY collected_at DESC`
        ).all();

    if (rows.length === 0) {
      throw new Error(
        expectedHost
          ? `raw 파일에 호스트 '${expectedHost}' 데이터가 없습니다.`
          : 'raw 파일이 비어 있습니다.'
      );
    }

    // host별 최신값 추출 (이미 DESC 정렬이므로 첫 등장이 최신)
    const values = new Map();
    let hostOs = null;
    let host = null;
    for (const r of rows) {
      if (host === null) { host = r.host; hostOs = r.os_type; }
      if (!values.has(r.check_key)) values.set(r.check_key, r.value);
    }

    if (!hostOs || !['linux', 'windows'].includes(hostOs)) {
      throw new Error(`알 수 없는 os_type: ${hostOs}`);
    }

    return { sha256, host, hostOs, values };
  } finally {
    db.close();
  }
}

module.exports = { loadRaw };

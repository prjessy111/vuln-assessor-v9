'use strict';
/**
 * 기본 어댑터 v5 — 일반 raw_data 테이블을 가진 SQLite.
 * 단순 key-value 형태의 raw 데이터를 받아 동일한 인터페이스 제공.
 */

function detect(db) {
  try {
    const r = db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='raw_data'"
    ).get();
    return !!r;
  } catch (_) { return false; }
}

function extractMeta(db) {
  const first = db.prepare("SELECT host, os_type FROM raw_data LIMIT 1").get();
  return {
    host: first ? first.host : 'unknown',
    hostOs: first ? first.os_type : 'linux',
    osVersion: '',
    collectedAt: null,
  };
}

function listTables(db, { includeSample = false } = {}) {
  const cols = db.prepare("PRAGMA table_info(raw_data)").all().map(c => c.name);
  const cnt = db.prepare("SELECT COUNT(*) AS c FROM raw_data").get().c;
  const entry = { table: 'raw_data', columns: cols, rowCount: cnt };
  if (includeSample && cnt > 0) {
    entry.sample = db.prepare("SELECT * FROM raw_data LIMIT 1").get();
  }
  return [entry];
}

function querySlice(db, sql, { maxRows = 500 } = {}) {
  const trimmed = String(sql).trim();
  if (!/^(SELECT|WITH)\s/i.test(trimmed)) {
    throw new Error('context_sql은 SELECT 문만 허용됩니다.');
  }
  if (/\b(INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|ATTACH|DETACH|PRAGMA)\b/i.test(trimmed)) {
    throw new Error('SELECT 외 키워드는 허용되지 않습니다.');
  }
  return db.prepare(trimmed).all().slice(0, maxRows);
}

module.exports = { name: 'Default (raw_data)', detect, extractMeta, listTables, querySlice };

'use strict';
/**
 * Raw 어댑터 레지스트리 v5.
 *
 * 어댑터의 책임 (v5에서 변경됨):
 *   - 판정/평가 로직은 더 이상 하지 않음
 *   - SQLite raw 파일을 **표준화된 raw context**로 변환만 함
 *
 * 어댑터 인터페이스:
 *   - name             : 표시명
 *   - detect(db)       : 이 SQLite가 해당 형식인지 (true/false)
 *   - extractMeta(db)  : { host, hostOs, osVersion, collectedAt } — 시스템 정보만
 *   - listTables(db)   : [{ table, columns, rowCount, sample? }] — raw 데이터 카탈로그
 *   - querySlice(db, sql) : 임의 SQL 실행 (룰의 context_sql 평가용, 보안상 SELECT만 허용)
 *
 * 판정은 룰 엔진(simpleEvaluator + LLM)이 하고, 어댑터는 raw 슬라이스만 제공.
 */

const secumsUnix = require('./secumsUnix');
const defaultAdapter = require('./default');

const ADAPTERS = [secumsUnix, defaultAdapter];

function detectAdapter(db) {
  for (const a of ADAPTERS) {
    try {
      if (a.detect(db)) return a;
    } catch (e) { /* 다음 어댑터 시도 */ }
  }
  throw new Error('지원되는 어댑터가 없습니다. 알 수 없는 SQLite 스키마입니다.');
}

module.exports = { ADAPTERS, detectAdapter };

'use strict';
/**
 * 진단 실행 오케스트레이션 v4.
 *
 * 변경점 (v3 → v4):
 *  - 어댑터 자동 탐지로 다양한 raw 형식 지원
 *  - SecuMS Unix: RESULT (OK/BAD/INFO) 그대로 사용
 *  - default: 우리 표준 raw_data 스키마 + 룰 엔진
 */
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const config = require('../config');
const serverDao = require('../dao/serverDao');
const assessmentDao = require('../dao/assessmentDao');
const { detectAdapter } = require('../engine/adapters');

/**
 * 진단 실행.
 *
 * @param {object} args
 *   - serverId      : 진단 대상 서버 ID
 *   - uploadedPath  : 업로드/수집된 raw 파일 경로
 *   - originalName  : 원본 파일명
 *   - rulesetVer    : 룰셋 버전 (default 어댑터에서만 사용)
 *   - executedBy    : 실행자
 *
 * @returns {{ assessmentId, summary, items, adapter, elapsedMs }}
 */
async function runAssessment({ serverId, uploadedPath, originalName, rulesetVer = 'v1.0', executedBy }) {
  const t0 = Date.now();

  // 1) 서버 정보 조회
  const server = await serverDao.findById(serverId);
  if (!server) throw new Error(`서버 ID ${serverId} 가 존재하지 않습니다.`);

  // 2) 파일 SHA-256 계산
  const buf = fs.readFileSync(uploadedPath);
  const sha256 = crypto.createHash('sha256').update(buf).digest('hex');

  // 3) SQLite 매직 검증
  if (buf.length < 16 || !buf.slice(0, 16).toString('utf8').startsWith('SQLite format 3')) {
    throw new Error('유효한 SQLite 파일이 아닙니다.');
  }

  // 4) 어댑터 자동 탐지 및 데이터 추출
  const db = new Database(uploadedPath, { readonly: true, fileMustExist: true });
  let extracted, adapterName;
  try {
    const adapter = detectAdapter(db);
    adapterName = adapter.name;
    console.log(`[assessment] 어댑터 매칭: ${adapter.name}`);
    extracted = await adapter.extract(db, { rulesetVer });
  } finally {
    db.close();
  }

  if (!extracted.items.length) {
    throw new Error('어댑터가 추출한 항목이 0건입니다.');
  }

  // 5) host 일치 확인 (경고만, 진행은 계속)
  if (extracted.host && server.hostname &&
      extracted.host.toLowerCase() !== server.hostname.toLowerCase()) {
    console.warn(`[assessment] hostname 불일치: 서버=${server.hostname}, raw=${extracted.host}`);
  }
  if (extracted.hostOs && server.os_type && extracted.hostOs !== server.os_type) {
    console.warn(`[assessment] OS 불일치: 서버=${server.os_type}, raw=${extracted.hostOs}`);
  }

  // 6) raw 파일 영구 저장 (해시 prefix + 원본명)
  fs.mkdirSync(config.paths.rawStorage, { recursive: true });
  const targetPath = path.join(config.paths.rawStorage,
    `${sha256.slice(0,16)}_${path.basename(originalName)}`);
  if (!fs.existsSync(targetPath)) {
    try { fs.renameSync(uploadedPath, targetPath); }
    catch (_) { fs.copyFileSync(uploadedPath, targetPath); fs.unlinkSync(uploadedPath); }
  } else {
    try { fs.unlinkSync(uploadedPath); } catch (_) {}
  }

  // 7) DB 적재
  const elapsedMs = Date.now() - t0;
  const resultRows = extracted.items.map(it => ({
    rule_id: it.rule_id,
    status: it.status,
    collected_value: it.collected_value,
    reason: it.reason,
    severity: it.severity || '중',
  }));

  const assessmentId = await assessmentDao.insertSession({
    session: {
      server_id: serverId,
      raw_file_name: originalName,
      raw_file_hash: sha256,
      ruleset_ver: rulesetVer,
      executed_by: executedBy,
      total_count: extracted.summary.total,
      vuln_count: extracted.summary.vuln,
      safe_count: extracted.summary.safe,
      na_count: extracted.summary.na,
      elapsed_ms: elapsedMs,
    },
    results: resultRows,
  });

  // 8) (어댑터별 항목 메타) - SecuMS의 점검명을 rules 테이블에 자동 등록
  // 룰 테이블에 없는 rule_id가 있을 경우 SecuMS 점검명을 그대로 임시 등록하여
  // 리포트에서 title/recommend 표시가 가능하도록 한다.
  await _upsertRulesFromExtract(extracted.items, rulesetVer);

  return {
    assessmentId,
    adapter: adapterName,
    summary: extracted.summary,
    items: extracted.items,
    elapsedMs,
  };
}

const ruleDao = require('../dao/ruleDao');

async function _upsertRulesFromExtract(items, rulesetVer) {
  // 기존 룰 목록 조회
  const existing = new Set((await ruleDao.listAll(rulesetVer)).map(r => r.rule_id));
  const toAdd = items
    .filter(i => !existing.has(i.rule_id))
    .map(i => ({
      rule_id: i.rule_id,
      title: i.title,
      category: i.category || '기타',
      severity: i.severity || '중',
      os_target: 'linux',  // SecuMS Unix이므로
      check_key: i.rule_id,
      check_type: 'adapter_native',  // 어댑터가 자체 판정
      check_param: {},
      recommend: null,
      enabled: true,
    }));
  if (toAdd.length) {
    await ruleDao.upsertMany(toAdd, rulesetVer);
    console.log(`[assessment] 신규 룰 ${toAdd.length}건 자동 등록 (ruleset ${rulesetVer})`);
  }
}

module.exports = { runAssessment };

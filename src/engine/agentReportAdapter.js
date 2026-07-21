'use strict';
/**
 * 자율 에이전트 / 수집결과 판정의 judgment(findings) → 기존 리포트 파이프라인이 먹는
 * `diagnoses` 레코드(diagnose_type='llm')로 변환하는 어댑터.
 *
 * ★ 새 리포트를 만들지 않는다. 변환만 해서 기존 buildAiReportData→buildReportFromAi
 *   →기존 /reports(fsi/samsung/policy3 HTML + XLSX + 인쇄PDF)를 그대로 재사용한다.
 *
 * buildReportFromAi 가 기대하는 results[] 필드:
 *   chk_id, ai_verdict('취약'|'양호'|'판정불가'), ai_title, ai_category, ai_severity,
 *   ai_reason, ai_evidence, ai_recommend, ai_safe_type, secums_verdict, agreement
 */

function normVerdict(v) {
  const s = String(v || '').trim();
  if (s === '취약') return '취약';
  if (s === '양호') return '양호';
  return '판정불가';   // 점검불가/판정불가/기타 → 판정불가
}

function findingToResult(f, i, item) {
  return {
    chk_id: f.id || f.code || f.chk_id || `ADV-${String(i + 1).padStart(3, '0')}`,
    secums_verdict: f.secums_verdict || null,
    ai_verdict: normVerdict(f.verdict),
    ai_reason: f.reason || '',
    ai_recommend: f.recommend || f.recommendation || '',
    ai_evidence: f.evidence || '',
    ai_category: f.category || item.category || '미분류',
    ai_title: f.item || f.title || f.id || `점검항목 ${i + 1}`,
    ai_severity: f.sev || f.severity || '중',
    ai_safe_type: '',
    agreement: null,
    _source: 'agent',
  };
}

/**
 * @param {object} item - 에이전트 항목 (item.judgment 필요)
 * @param {object} server - { server_id, hostname, os_type, asset_no } (대상 추정값)
 * @param {number|string} assessmentId - 신규 assessment_id (호출측이 유니크 발급)
 * @returns {object} diagnoses 레코드
 */
function buildDiagnosisFromAgentItem(item, server = {}, assessmentId) {
  const j = item.judgment || {};
  const now = new Date().toISOString().slice(0, 19).replace('T', ' ');
  const findings = Array.isArray(j.findings) ? j.findings : [];

  let results;
  if (findings.length) {
    results = findings.map((f, i) => findingToResult(f, i, item));
  } else {
    // 단일 판정(예: cat /etc/passwd) → 1행으로
    results = [{
      chk_id: item.source_ref || `ADV-${String(item.item_id || '001').slice(-3)}`,
      secums_verdict: j.secums_verdict || null,
      ai_verdict: normVerdict(j.verdict),
      ai_reason: j.reason || '',
      ai_recommend: j.recommend || '',
      ai_evidence: j.evidence || '',
      ai_category: item.category || '미분류',
      ai_title: item.title || String(item.item_id || '점검 항목'),
      ai_severity: item.severity || '중',
      ai_safe_type: '',
      agreement: null,
      _source: 'agent',
    }];
  }

  const vuln = results.filter(r => r.ai_verdict === '취약').length;
  const safe = results.filter(r => r.ai_verdict === '양호').length;
  const na   = results.filter(r => r.ai_verdict === '판정불가').length;

  return {
    assessment_id: assessmentId,
    diagnose_type: 'llm',            // 기존 리포트 필터('ai'|'llm') 통과용
    source_type: 'agent',
    server_id: server.server_id != null ? server.server_id : null,
    server_name: server.hostname || item.title || '대상',
    hostname: server.hostname || '',
    asset_no: server.asset_no || '',
    os_type: server.os_type || server.os || item.os_target || '',
    llm_provider: j.backend || 'mock',
    llm_model: j.model || '-',
    executed_at: j.judged_at || now,
    elapsed_ms: 0,
    status: 'success',
    total_count: results.length,
    vuln_count: vuln,
    safe_count: safe,
    na_count: na,
    info_count: 0,
    agreement_rate: 0,
    validation_failure_rate: 0,
    executed_by: 'agent',
    triggered_by: 'agent',
    judgment_basis: `agent:${j.model || j.backend || 'mock'}`,
    results,
    _agent_item_id: item.item_id,
  };
}

module.exports = { buildDiagnosisFromAgentItem, normVerdict };

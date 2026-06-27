'use strict';
/**
 * AI 진단 결과 → 리포트1/리포트2 양식 변환기.
 *
 * AI 진단은 SecuMS 64개 chk_id 기준이고, 리포트 양식은 기존 룰 진단의
 * rule_id/status 형태를 기대하므로 필드 매핑 + 보강 작업이 필요.
 *
 * 출력 형태는 옛 buildReportData()와 호환되도록 다음을 채움:
 *   - session: 헤더 메타 + KPI
 *   - vulnRows: 리포트1용 취약 항목 배열 (management_no, rule_id, title, ...)
 *   - safeRows: 양호 항목 배열
 *   - naRows:   점검불가 항목 배열
 *   - grouped:  리포트2용 카테고리별 그룹
 */

const path = require('path');

function normalizeVerdict(value) {
  if (value === '정보') return '정보제공';
  if (['취약', '양호', '정보제공', '판정불가'].includes(value)) return value;
  return '판정불가';
}

function isInfoVerdict(value) {
  return value === '정보제공' || value === '정보';
}

/**
 * AI 진단 결과(diagnoses.json의 한 항목)를 리포트 양식 데이터로 변환.
 *
 * @param {object} diag - AI 진단 레코드 (diagnose_type === 'ai')
 * @param {object} server - servers.json의 서버 메타
 * @returns {object} { session, vulnRows, safeRows, naRows, grouped }
 */
function buildReportFromAi(diag, server = {}) {
  const results = diag.results || [];

  // 양호/취약/판정불가 분류 (AI 필드 사용)
  const vulnAll = results.filter(r => r.ai_verdict === '취약');
  const safeAll = results.filter(r => r.ai_verdict === '양호');
  const naAll   = results.filter(r => r.ai_verdict === '판정불가');
  const infoAll = results.filter(r => isInfoVerdict(r.ai_verdict));

  // 2026 범위 필터 — 리포트는 2026 70개만 참조("2026외" 추가 수집 항목은 raw로만 보관).
  // 기준: data/srv-2026-scope.json (OS별 70개). 없으면 전체를 2026으로 간주(하위호환).
  const _osKey = /win/i.test(String(server.os_type || server.os || diag.os_type || '')) ? 'windows' : 'linux';
  let _scope2026 = null;
  try {
    const scopeJson = require('../../data/srv-2026-scope.json');
    _scope2026 = new Set((scopeJson[_osKey] || []).map(s => String(s).toUpperCase()));
  } catch (_) { _scope2026 = null; }
  const _srvKey = id => { const m = String(id || '').match(/SRV-(\d+)/i); return m ? 'SRV-' + m[1].padStart(3, '0') : String(id || '').toUpperCase(); };
  const _in2026 = id => (_scope2026 ? _scope2026.has(_srvKey(id)) : true);

  // 리포트1용 행 생성 — AI 필드를 룰 진단 양식 필드로 변환
  function toReportRow(r, index, sectionKind) {
    const status = normalizeVerdict(r.ai_verdict);
    return {
      // 관리번호: 자산번호 + 일련번호 (없으면 진단ID 기반)
      management_no: `${server.asset_no || ('A' + diag.assessment_id)}-${String(index + 1).padStart(3, '0')}`,
      // 룰 ID 자리에 chk_id (SecuMS 항목 ID)
      rule_id: r.chk_id,
      // 제목 — AI가 추론한 한글 제목, 없으면 chk_id
      title: r.ai_title || r.chk_id,
      // 카테고리 — AI 분류
      category: r.ai_category || '미분류',
      // 위험도/심각도
      severity: r.ai_verdict === '취약' ? (r.ai_severity || '중') : '-',
      // 판정 상태 (옛 양식 호환 — '취약'/'양호'/'점검불가')
      status,
      safe_type: r.ai_safe_type || '',
      // 사유
      reason: r.ai_reason || '',
      // 증거 (raw 출력에서 추출된 핵심 라인)
      evidence: r.ai_evidence || '',
      // 권고 (취약일 때만 의미 있음)
      recommend: r.ai_recommend || '',
      // 소항목 — AI 진단은 chk_id 단위라 소항목 없음. 빈 배열로.
      subs: [],
      // 신규 여부 — AI 진단은 신규/기존 추적 안 하므로 일단 모두 신규로
      is_new: true,
      // 조치 정보 — 별도 관리 (조치 관리 메뉴)
      assignee: '',
      delivered_at: '',
      fixed_at: '',
      fix_status: status === '취약' ? '미조치' : (status === '양호' ? '양호' : '-'),
      // SecuMS 자체 판정 (참고용)
      secums_verdict: r.secums_verdict,
      agreement: r.agreement,
      // 평가 방법 (AI 진단은 모두 LLM)
      eval_method: 'llm',
      // 2026 OS 체크리스트 범위 여부 (false = "2026외" 추가 수집 항목)
      in_2026: _in2026(r.chk_id),
    };
  }

  const vulnRows = vulnAll.map((r, i) => toReportRow(r, i, 'vuln'));
  const safeRows = safeAll.map((r, i) => toReportRow(r, i, 'safe'));
  const naRows   = naAll.map((r, i) => toReportRow(r, i, 'na'));
  const infoRows = infoAll.map((r, i) => toReportRow(r, i, 'info'));

  // 전체 항목 (리포트1 전체용)
  const allRows = [...vulnRows, ...safeRows, ...naRows, ...infoRows];

  // 2026 범위 행 / 2026외 행 분리 — 리포트·정합성 비교는 scopedRows(2026 70개)만 사용.
  const scopedRows = _scope2026 ? allRows.filter(r => r.in_2026) : allRows;
  const outOfScopeRows = _scope2026 ? allRows.filter(r => !r.in_2026) : [];
  const _cnt = (rows, v) => rows.filter(r => r.status === v).length;

  // 리포트2용 — 카테고리별 그룹화 (모든 결과 포함)
  const grouped = {};
  for (const row of allRows) {
    const cat = row.category || '미분류';
    if (!grouped[cat]) grouped[cat] = [];
    grouped[cat].push(row);
  }

  // 취약점 리포트2용 — 취약 항목만 카테고리별 그룹
  const vulnGrouped = {};
  for (const row of vulnRows) {
    const cat = row.category || '미분류';
    if (!vulnGrouped[cat]) vulnGrouped[cat] = [];
    vulnGrouped[cat].push(row);
  }

  // 데이터 소스/OS 라벨 (secums raw vs script XML 구분 — 하드코딩 금지)
  const _srcType = String(diag.source_type || 'secums').toLowerCase();
  const _osType = String(server.os_type || diag.os_type || 'linux').toLowerCase();
  const _osLabel = _osType.includes('win') ? 'Windows' : 'Unix';
  const _isScript = _srcType === 'script';
  const _policyName = _isScript
    ? `Script XML AI 진단 (${_osLabel})`
    : `SecuMS ${_osLabel} raw AI 진단`;
  const _adapterName = _isScript
    ? `Script Agent (raw evidence, ${_osLabel})`
    : `SecuMS ${_osLabel} Agent (raw)`;

  // 세션 메타 (헤더 + KPI)
  const session = {
    source_type: _srcType,
    assessment_id: diag.assessment_id,
    server_id: diag.server_id,
    server_name: server.name || diag.server_name || `#${diag.server_id}`,
    hostname: diag.hostname || server.hostname,
    asset_no: server.asset_no || diag.asset_no || '',
    ip_address: server.ip_address || '-',
    service_name: server.service_name || server.purpose || '',
    department: server.department || '',
    os_type: server.os_type || 'linux',
    os_version: server.os_version || '',
    policy_name: _policyName,
    adapter: _adapterName,
    llm_engine: `${diag.llm_provider || 'mock'} / ${diag.llm_model || '-'}`,
    executed_at: diag.executed_at,
    executed_by: diag.executed_by || '-',
    elapsed_ms: diag.elapsed_ms || 0,
    raw_file_name: diag.raw_file || '(서버 기본 파일)',
    raw_file_hash: '(생략)',
    // KPI
    total_count: diag.total_count || results.length,
    vuln_count: diag.vuln_count || vulnAll.length,
    safe_count: diag.safe_count || safeAll.length,
    na_count: diag.na_count || naAll.length,
    info_count: diag.info_count || infoAll.length,
    new_vuln_count: vulnAll.length,  // 모두 신규로 표시
    sub_vuln: 0,  // 소항목 개념 없음
    simple_count: 0,
    llm_count: diag.total_count || results.length,
    // SecuMS 정합성 정보 (리포트에 부가 표시 가능)
    secums_agreement_rate: diag.agreement_rate || 0,
    secums_disagree_count: diag.disagree_count || 0,
    secums_disagree_real_count: diag.disagree_real_count || diag.disagree_count || 0,
    secums_needs_review_count: diag.needs_review_count || 0,
    validation_failure_rate: diag.validation_failure_rate || 0,
    comparison_count: diag.comparison_count || 0,
    secums_wait_count: diag.secums_wait_count || 0,
    // 2026 범위 KPI (리포트 표시는 이 값 기준)
    scope_total: scopedRows.length,
    scope_vuln: _cnt(scopedRows, '취약'),
    scope_safe: _cnt(scopedRows, '양호'),
    scope_na: _cnt(scopedRows, '판정불가'),
    scope_info: scopedRows.filter(r => r.status === '정보제공' || r.status === '정보').length,
    out_of_scope_count: outOfScopeRows.length,
  };

  return { session, vulnRows, safeRows, naRows, infoRows, allRows, scopedRows, outOfScopeRows, grouped, vulnGrouped };
}

module.exports = { buildReportFromAi };

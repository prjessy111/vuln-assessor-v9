'use strict';
/**
 * 리포트3 = 정합성(Consistency) 리포트.
 *
 * AI/LLM 진단 판정과 SecuMS(또는 Script raw) 자체 판정을 항목 단위로 비교해
 * 일치/불일치/검토필요/미점검을 집계한다. 비교 기준(SecuMS 판정)은 진단 시점에
 * 각 row.agreement / row.secums_verdict 로 이미 채워져 들어온다(aiReportAdapter).
 *
 * SecuMS 점검 결과가 없으면(WAIT) 일치율은 계산 불가이며, 그 상태를 그대로 표시한다.
 *
 * buildReport3Data(data, diagnoses, opts)  → 화면용 구조
 * buildReport3Workbook(data, diagnoses, opts) → { workbook } (xlsx)
 */

const ExcelJS = require('exceljs');

// agreement 코드 → 한글 라벨
const AGREEMENT_LABEL = {
  agree: '일치',
  disagree_real: '검증 실패(실제 불일치)',
  needs_review: '검토 필요',
  disagree: '불일치(이전 결과)',
  secums_wait: 'SecuMS 미점검(AI 추론)',
};
// 비교 가능(= SecuMS 판정이 존재)으로 보는 코드
const COMPARABLE = new Set(['agree', 'disagree_real', 'needs_review', 'disagree']);

function agreementLabel(code) {
  return AGREEMENT_LABEL[code] || '-';
}

function summarize(rows) {
  const verdict = {};            // AI 판정 분포
  const agreement = {};          // 일치 여부 분포
  let comparable = 0, agree = 0, waiting = 0;
  for (const r of rows) {
    const v = r.status || '(빈값)';
    verdict[v] = (verdict[v] || 0) + 1;
    const a = r.agreement || 'secums_wait';
    agreement[a] = (agreement[a] || 0) + 1;
    if (COMPARABLE.has(a)) {
      comparable += 1;
      if (a === 'agree') agree += 1;
    }
    if (a === 'secums_wait') waiting += 1;
  }
  const total = rows.length;
  const agreementRate = comparable ? Math.round((agree / comparable) * 1000) / 10 : 0;
  return {
    total,
    verdict,
    agreement,
    comparable,
    waiting,
    agree,
    disagree_real: agreement.disagree_real || 0,
    needs_review: agreement.needs_review || 0,
    disagree: agreement.disagree || 0,
    agreementRate,
    baselinePresent: comparable > 0,
  };
}

/** 일치 여부별로 행을 그룹핑(불일치/검토필요를 앞에 둔다). */
function groupByAgreement(rows) {
  const order = ['disagree_real', 'needs_review', 'disagree', 'agree', 'secums_wait'];
  const groups = {};
  for (const code of order) groups[code] = [];
  for (const r of rows) {
    const a = r.agreement && groups[r.agreement] ? r.agreement : 'secums_wait';
    groups[a].push(r);
  }
  return order
    .filter(code => groups[code].length)
    .map(code => ({ code, label: agreementLabel(code), rows: groups[code] }));
}

async function buildReport3Data(data /*, diagnoses, opts */) {
  const rows = Array.isArray(data.scopedRows) ? data.scopedRows
    : (Array.isArray(data.allRows) ? data.allRows : []);
  const summary = summarize(rows);
  return {
    summary,
    groups: groupByAgreement(rows),
    agreementLabel,
  };
}

async function buildReport3Workbook(data /*, diagnoses, opts */) {
  const rows = Array.isArray(data.scopedRows) ? data.scopedRows
    : (Array.isArray(data.allRows) ? data.allRows : []);
  const session = data.session || {};
  const summary = summarize(rows);

  const wb = new ExcelJS.Workbook();
  wb.creator = 'Vuln Assessor';
  wb.created = new Date();

  // ── 요약 시트 ──
  const meta = wb.addWorksheet('정합성 요약');
  meta.columns = [{ width: 24 }, { width: 44 }];
  meta.addRows([
    ['진단 ID', session.assessment_id],
    ['호스트명', session.hostname],
    ['자산번호', session.asset_no || '-'],
    ['IP', session.ip_address || '-'],
    ['OS', `${session.os_type || ''} ${session.os_version || ''}`.trim()],
    ['진단일시', session.executed_at || '-'],
    ['LLM', session.llm_engine || '-'],
    [],
    ['전체 항목', summary.total],
    ['AI 취약', summary.verdict['취약'] || 0],
    ['AI 양호', summary.verdict['양호'] || 0],
    ['AI 판정불가', summary.verdict['판정불가'] || 0],
    ['AI 정보제공', (summary.verdict['정보제공'] || 0) + (summary.verdict['정보'] || 0)],
    [],
    ['SecuMS 비교 가능', summary.comparable],
    ['└ 일치', summary.agree],
    ['└ 검증 실패(실제 불일치)', summary.disagree_real],
    ['└ 검토 필요', summary.needs_review],
    ['SecuMS 미점검(AI 추론)', summary.waiting],
    ['일치율 (비교가능 기준)', summary.baselinePresent ? `${summary.agreementRate}%` : 'N/A (SecuMS 점검 결과 없음)'],
  ]);
  meta.getColumn(1).font = { bold: true };

  // ── 비교 시트 ──
  const ws = wb.addWorksheet('AI vs SecuMS 비교');
  ws.columns = [
    { header: '관리번호',    key: 'mgmt',     width: 18 },
    { header: '항목ID',      key: 'rid',      width: 14 },
    { header: '제목',        key: 'title',    width: 30 },
    { header: '카테고리',    key: 'cat',      width: 14 },
    { header: 'AI 판정',     key: 'ai',       width: 10 },
    { header: '심각도',      key: 'sev',      width: 8  },
    { header: 'SecuMS 판정', key: 'secums',   width: 12 },
    { header: '일치 여부',   key: 'agree',    width: 22 },
    { header: '사유',        key: 'reason',   width: 60 },
  ];
  const hdr = ws.getRow(1);
  hdr.font = { bold: true, color: { argb: 'FFFFFFFF' } };
  hdr.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF34495E' } };
  hdr.alignment = { horizontal: 'center', vertical: 'middle' };
  hdr.height = 22;

  // 불일치/검토필요를 위로 정렬
  const groups = groupByAgreement(rows);
  for (const g of groups) {
    for (const r of g.rows) {
      const row = ws.addRow({
        mgmt: r.management_no,
        rid: r.rule_id,
        title: r.title,
        cat: r.category,
        ai: r.status,
        sev: r.severity,
        secums: r.secums_verdict || '-',
        agree: g.label,
        reason: r.reason,
      });
      row.alignment = { wrapText: true, vertical: 'top' };
      // 불일치 강조
      if (g.code === 'disagree_real') {
        row.getCell('agree').fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFFADBD8' } };
        row.getCell('agree').font = { color: { argb: 'FFC0392B' }, bold: true };
      } else if (g.code === 'needs_review') {
        row.getCell('agree').fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFFCF3CF' } };
      } else if (g.code === 'agree') {
        row.getCell('agree').font = { color: { argb: 'FF27AE60' }, bold: true };
      } else if (g.code === 'secums_wait') {
        row.getCell('agree').font = { color: { argb: 'FF888888' } };
      }
    }
  }
  ws.autoFilter = { from: 'A1', to: `I${rows.length + 1}` };
  ws.views = [{ state: 'frozen', xSplit: 0, ySplit: 1 }];

  return { workbook: wb, summary };
}

module.exports = { buildReport3Data, buildReport3Workbook, agreementLabel };

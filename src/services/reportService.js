'use strict';
const ExcelJS = require('exceljs');
const assessmentDao = require('../dao/assessmentDao');

async function buildReportData(assessmentId) {
  const session = await assessmentDao.findById(assessmentId);
  if (!session) throw new Error('해당 진단 세션을 찾을 수 없습니다.');
  const results = await assessmentDao.getResults(assessmentId);
  return { session, results };
}

async function exportXlsx(assessmentId, res) {
  const { session, results } = await buildReportData(assessmentId);

  const wb = new ExcelJS.Workbook();
  wb.creator = 'Vuln-Assessor';
  wb.created = new Date();

  // ---------- 요약 시트 ----------
  const sum = wb.addWorksheet('요약');
  sum.addRows([
    ['취약점 진단 리포트'],
    [],
    ['서버명', session.server_name],
    ['호스트', session.hostname],
    ['OS', session.os_type],
    ['진단 ID', String(session.assessment_id)],
    ['진단일시', session.executed_at],
    ['룰셋 버전', session.ruleset_ver],
    ['Raw 파일', session.raw_file_name],
    ['Raw 해시', session.raw_file_hash],
    [],
    ['항목', '건수'],
    ['전체', session.total_count],
    ['취약', session.vuln_count],
    ['양호', session.safe_count],
    ['점검불가', session.na_count],
  ]);
  sum.getCell('A1').font = { size: 16, bold: true };
  sum.columns = [{ width: 14 }, { width: 60 }];

  // ---------- 상세 시트 ----------
  const det = wb.addWorksheet('상세결과');
  det.columns = [
    { header: '항목ID', key: 'rule_id', width: 10 },
    { header: '분류',   key: 'category', width: 16 },
    { header: '점검항목', key: 'title', width: 40 },
    { header: '중요도', key: 'severity', width: 8 },
    { header: '판정',   key: 'status', width: 10 },
    { header: '수집값', key: 'collected_value', width: 30 },
    { header: '사유',   key: 'reason', width: 40 },
    { header: '조치권고', key: 'recommend', width: 50 },
  ];
  det.getRow(1).font = { bold: true };
  det.getRow(1).fill = {
    type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFD9E1F2' },
  };

  for (const r of results) {
    const row = det.addRow(r);
    if (r.status === '취약') {
      row.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFFDF2F0' } };
    } else if (r.status === '점검불가') {
      row.font = { color: { argb: 'FF888888' } };
    }
  }
  det.autoFilter = { from: 'A1', to: 'H1' };
  det.views = [{ state: 'frozen', ySplit: 1 }];

  res.setHeader('Content-Type',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition',
    `attachment; filename="vuln_report_${assessmentId}.xlsx"`);
  await wb.xlsx.write(res);
  res.end();
}

module.exports = { buildReportData, exportXlsx };

'use strict';
/**
 * 금보원 양식 XLSX export (중항목 + 소항목 모두).
 *
 * 출력 컬럼 (18 + α):
 *   관리번호 / 항목번호 / 항목구분 / 자산번호 / 호스트명 / 업무명용도 / IP
 *   / 취약점 / 평가항목 / 위험도 / 분석환경 / 취약항목(사유)
 *   / 신규여부 / 담당자 / 전달일자 / 조치일자 / 조치여부 / 미조치사유 / 비고
 *
 * 행 순서:
 *   - 중항목 행 (parent row)
 *   - 그 아래 소항목 행들 (들여쓰기)
 *
 * 색상:
 *   - 조치완료: 녹색 배경
 *   - 진행중: 주황 배경
 *   - 미조치(취약): 흰색
 *   - 소항목 양호: 옅은 회색
 */

const ExcelJS = require('exceljs');

const HEADERS = [
  { key: 'mgmt_no',        header: '관리번호',    width: 12 },
  { key: 'rule_id',        header: '항목번호',    width: 12 },
  { key: 'item_type',      header: '항목구분',    width: 8  },
  { key: 'asset_no',       header: '자산번호',    width: 16 },
  { key: 'hostname',       header: '호스트명',    width: 14 },
  { key: 'service_name',   header: '업무명/용도', width: 22 },
  { key: 'ip_address',     header: 'IP',          width: 14 },
  { key: 'title',          header: '취약점',      width: 38 },
  { key: 'category',       header: '평가항목',    width: 16 },
  { key: 'severity',       header: '위험도',      width: 8  },
  { key: 'env',            header: '분석환경',    width: 28 },
  { key: 'reason',         header: '취약항목',    width: 36 },
  { key: 'is_new',         header: '신규여부',    width: 10 },
  { key: 'assignee',       header: '담당자',      width: 12 },
  { key: 'delivered_at',   header: '전달일자',    width: 12 },
  { key: 'fixed_at',       header: '조치일자',    width: 12 },
  { key: 'fix_status',     header: '조치여부',    width: 12 },
  { key: 'unfixed_reason', header: '미조치사유',  width: 30 },
  { key: 'remark',         header: '비고',        width: 20 },
];

const COLOR_HEADER = 'FF34495E';
const COLOR_DONE   = 'FFD5F5E3';   // 옅은 녹색
const COLOR_PROG   = 'FFFCF3CF';   // 옅은 노랑
const COLOR_SUB_OK = 'FFF4F6F7';   // 옅은 회색 (소항목 양호)
const COLOR_SUB_NG = 'FFFADBD8';   // 옅은 빨강 (소항목 취약)

async function buildFsiWorkbook({ session, vulnRows }) {
  const wb = new ExcelJS.Workbook();
  wb.creator = 'Vuln Assessor';
  wb.created = new Date();

  const sheet = wb.addWorksheet('취약점 점검 결과', {
    views: [{ state: 'frozen', xSplit: 3, ySplit: 1 }],  // 첫 행 + 좌측 3컬럼 고정
  });
  sheet.columns = HEADERS.map(h => ({ key: h.key, width: h.width, header: h.header }));

  // 헤더 스타일
  const headerRow = sheet.getRow(1);
  headerRow.height = 28;
  headerRow.eachCell(cell => {
    cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: COLOR_HEADER } };
    cell.font = { bold: true, color: { argb: 'FFFFFFFF' }, size: 11 };
    cell.alignment = { vertical: 'middle', horizontal: 'center', wrapText: true };
    cell.border = {
      top: { style: 'thin', color: { argb: 'FF7F8C8D' } },
      bottom: { style: 'thin', color: { argb: 'FF7F8C8D' } },
    };
  });

  const env = `${session.os_type || ''} / ${session.policy_name || ''}`.trim();

  // 행 추가 헬퍼
  function pushRow(data, opts = {}) {
    const row = sheet.addRow(data);
    row.alignment = { vertical: 'top', wrapText: true };

    // 색상 적용
    if (opts.fillColor) {
      row.eachCell(cell => {
        cell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: opts.fillColor } };
      });
    }
    if (opts.indent) {
      // 항목번호 셀 들여쓰기
      const c = row.getCell('rule_id');
      c.alignment = { ...c.alignment, indent: 1 };
      c.value = '  └ ' + (c.value || '');
    }
    if (opts.bold) {
      row.eachCell(cell => { cell.font = { ...(cell.font||{}), bold: true }; });
    }
    if (opts.muted) {
      row.eachCell(cell => { cell.font = { ...(cell.font||{}), color: { argb: 'FF7F8C8D' } }; });
    }
    // 위험도 배경
    const sevCell = row.getCell('severity');
    if (sevCell.value === '상') sevCell.fill = { type:'pattern', pattern:'solid', fgColor:{argb:'FFE74C3C'} };
    else if (sevCell.value === '중') sevCell.fill = { type:'pattern', pattern:'solid', fgColor:{argb:'FFE67E22'} };
    else if (sevCell.value === '하') sevCell.fill = { type:'pattern', pattern:'solid', fgColor:{argb:'FF3498DB'} };
    if (sevCell.value) sevCell.font = { color: {argb:'FFFFFFFF'}, bold: true };

    // 조치여부 배경
    const fsCell = row.getCell('fix_status');
    if (fsCell.value === '조치완료') {
      fsCell.fill = { type:'pattern', pattern:'solid', fgColor:{argb:'FF27AE60'} };
      fsCell.font = { color: {argb:'FFFFFFFF'}, bold: true };
    } else if (fsCell.value === '진행중') {
      fsCell.fill = { type:'pattern', pattern:'solid', fgColor:{argb:'FFE67E22'} };
      fsCell.font = { color: {argb:'FFFFFFFF'}, bold: true };
    } else if (fsCell.value === '미조치') {
      fsCell.fill = { type:'pattern', pattern:'solid', fgColor:{argb:'FFC0392B'} };
      fsCell.font = { color: {argb:'FFFFFFFF'}, bold: true };
    } else if (fsCell.value === '예외') {
      fsCell.fill = { type:'pattern', pattern:'solid', fgColor:{argb:'FF95A5A6'} };
      fsCell.font = { color: {argb:'FFFFFFFF'}, bold: true };
    }

    return row;
  }

  // 데이터 채우기
  for (const r of vulnRows) {
    // 1) 중항목 행
    const mainFill = r.fix_status === '조치완료' ? COLOR_DONE
                  : r.fix_status === '진행중'  ? COLOR_PROG
                  : null;
    pushRow({
      mgmt_no: r.management_no,
      rule_id: r.rule_id,
      item_type: '중항목',
      asset_no: session.asset_no || '',
      hostname: session.hostname,
      service_name: session.service_name || '',
      ip_address: session.ip_address || '',
      title: r.title,
      category: r.category,
      severity: r.severity,
      env: env,
      reason: r.reason + (r.evidence ? `\n→ ${r.evidence}` : ''),
      is_new: r.is_new ? '신규' : '기존',
      assignee: r.assignee || '',
      delivered_at: r.delivered_at || '',
      fixed_at: r.fixed_at || '',
      fix_status: r.fix_status || '미조치',
      unfixed_reason: r.unfixed_reason || '',
      remark: r.remark || '',
    }, { fillColor: mainFill, bold: true });

    // 2) 소항목 행들
    if (Array.isArray(r.subs) && r.subs.length) {
      // 중항목이 종료 상태면 소항목도 동기화하여 표시 (정책: 자동 일괄 종료)
      const isMainClosed = ['조치완료', '예외'].includes(r.fix_status);
      const cascadeStatus = isMainClosed ? r.fix_status : '';
      const cascadeFixedAt = isMainClosed ? r.fixed_at : '';

      for (const s of r.subs) {
        // 평가 결과(status)는 그대로, 운영 상태는 부모를 따름
        const subFill = isMainClosed ? COLOR_DONE
                      : s.status === '취약' ? COLOR_SUB_NG : COLOR_SUB_OK;
        const subFixStatus = isMainClosed
          ? cascadeStatus               // 부모가 조치완료/예외면 동기화
          : (s.status === '취약' ? '미조치' : '');

        pushRow({
          mgmt_no: `${r.management_no}-${s.sub_key || ''}`.slice(0, 50),
          rule_id: s.sub_label || s.sub_key || '',
          item_type: '소항목',
          asset_no: session.asset_no || '',
          hostname: session.hostname,
          service_name: session.service_name || '',
          ip_address: session.ip_address || '',
          title: `↳ ${s.sub_label || s.sub_key}`,
          category: r.category,
          severity: s.status === '취약' ? r.severity : '',
          env: env,
          reason: `[평가: ${s.status}] ${s.reason || ''}` + (s.evidence ? `\n→ ${s.evidence}` : ''),
          is_new: '',
          assignee: '',
          delivered_at: '',
          fixed_at: cascadeFixedAt || '',
          fix_status: subFixStatus,
          unfixed_reason: '',
          remark: isMainClosed ? `↳ 중항목 ${cascadeStatus} 처리에 의해 자동 동기화` : '',
        }, { fillColor: subFill, indent: true, muted: s.status === '양호' && !isMainClosed });
      }
    }
  }

  // 자동 필터
  sheet.autoFilter = {
    from: { row: 1, column: 1 },
    to:   { row: 1, column: HEADERS.length },
  };

  return wb;
}

module.exports = { buildFsiWorkbook };

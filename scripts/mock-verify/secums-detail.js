'use strict';
// OS_Detail 리포트에서 항목별 SecuMS 판정근거(ITEM/MESSAGE) 추출
// 사용: node secums-detail.js <OS_Detail.xlsx> <시트명> <SRV-ID,...>
const ExcelJS = require('exceljs');
const [file, sheetName, idcsv] = process.argv.slice(2);
(async () => {
  const wb = new ExcelJS.Workbook();
  await wb.xlsx.readFile(file);
  const ws = wb.getWorksheet(sheetName);
  const rows = [];
  ws.eachRow((row, n) => { rows[n] = row.values || []; });

  const wanted = idcsv.split(',');
  for (let n = 1; n < rows.length; n++) {
    const c1 = String((rows[n] || [])[1] || '');
    const m = c1.match(/^■ (SRV-\d+)_(.{0,50})/);
    if (!m || !wanted.includes(m[1])) continue;
    console.log('===== ' + m[1] + ' ' + m[2]);
    for (let k = n + 1; k < Math.min(n + 40, rows.length); k++) {
      const v = rows[k] || [];
      const a = String(v[1] || '');
      if (/^■ /.test(a)) break;
      if (a === '결과') console.log('  결과:', v[3], '| 점수:', v[8]);
      // ITEM/MESSAGE 데이터 행: col1=ITEM명, col4=MESSAGE
      if (a && a !== 'ITEM' && a !== '점검 결과' && a !== '결과' && v[4] != null && String(v[4]) !== a
          && !/^(내용|확인 방법|기준|조치법|■)/.test(a)) {
        console.log('  [' + a.slice(0, 40) + '] ' + String(v[4]).replace(/\n/g, ' / ').slice(0, 160));
      }
      if (/^(내용)$/.test(a)) break; // 근거 섹션 끝 (설명 섹션 시작)
    }
  }
})();

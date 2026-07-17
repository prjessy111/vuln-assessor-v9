'use strict';
// 3-way 정합성 비교: SecuMS(OS_Detail) vs Mock vs LLM
// 사용: node threeway-compare.js <OS_Detail.xlsx> <시트명> <mock리포트.xlsx> <llm리포트.xlsx>
const ExcelJS = require('exceljs');
const [secumsFile, sheetName, mockFile, llmFile] = process.argv.slice(2);

async function loadReport1(f) {
  const wb = new ExcelJS.Workbook();
  await wb.xlsx.readFile(f);
  const ws = wb.getWorksheet('전체 진단 결과');
  const m = {};
  ws.eachRow((row, n) => {
    if (n > 1) { const id = row.getCell(2).value; if (!m[id]) m[id] = String(row.getCell(5).value); }
  });
  return m;
}

(async () => {
  const wb = new ExcelJS.Workbook();
  await wb.xlsx.readFile(secumsFile);
  const ws = wb.getWorksheet(sheetName);
  const secums = {};
  ws.eachRow((row) => {
    const v = row.values; if (!v) return;
    const m = String(v[3] || '').match(/^(SRV-\d+)_/);
    if (m && v[9] != null && !secums[m[1]]) secums[m[1]] = String(v[9]);
  });
  const mock = await loadReport1(mockFile);
  const llm = await loadReport1(llmFile);

  const toOur = { OK: '양호', BAD: '취약', INFO: '정보제공', NA: '판정불가', WAIT: '판정불가' };
  const stats = { all3: 0, secumsMock: 0, secumsLlm: 0, mockLlm: 0, total: 0 };
  const rows = [];
  for (const id of Object.keys(secums).sort()) {
    if (!mock[id] && !llm[id]) continue;
    stats.total++;
    const s = toOur[secums[id]] || secums[id];
    const mv = mock[id] || '(없음)', lv = llm[id] || '(없음)';
    const sm = s === mv, sl = s === lv, ml = mv === lv;
    if (sm && sl) stats.all3++;
    if (sm) stats.secumsMock++;
    if (sl) stats.secumsLlm++;
    if (ml) stats.mockLlm++;
    if (!(sm && sl)) rows.push({ id, secums: s + '(' + secums[id] + ')', mock: mv, llm: lv, mark: (sm?'':'M') + (sl?'':'L') });
  }
  console.log('SecuMS 항목 수(공통):', stats.total);
  console.log('3자 완전일치:', stats.all3, '(' + Math.round(stats.all3/stats.total*100) + '%)');
  console.log('SecuMS-Mock 일치:', stats.secumsMock, '(' + Math.round(stats.secumsMock/stats.total*100) + '%)');
  console.log('SecuMS-LLM  일치:', stats.secumsLlm, '(' + Math.round(stats.secumsLlm/stats.total*100) + '%)');
  console.log('Mock-LLM    일치:', stats.mockLlm, '(' + Math.round(stats.mockLlm/stats.total*100) + '%)');
  console.log('\n불일치 상세 (M=mock상이, L=llm상이):');
  console.log('ID        SecuMS        Mock      LLM');
  for (const r of rows) console.log(r.id.padEnd(9), r.secums.padEnd(13), r.mock.padEnd(9), r.llm.padEnd(9), r.mark);
})();

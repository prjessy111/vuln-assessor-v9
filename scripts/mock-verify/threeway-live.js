'use strict';
// 3-way 비교 (mock은 XML에서 현재 코드로 재판정): node threeway-live.js <OS_Detail.xlsx> <시트> <xml> <llm리포트.xlsx>
const ExcelJS = require('exceljs');
const path = require('path');
const ROOT = path.resolve(__dirname, '../..');
const scriptResult = require(ROOT + '/src/engine/adapters/scriptResult.js');
const { buildPrompt } = require(ROOT + '/src/engine/aiDiagnose.js');
const MockProvider = require(ROOT + '/src/engine/llm/providers/mock.js');
const [secumsFile, sheetName, xmlFile, llmFile] = process.argv.slice(2);

(async () => {
  const wb = new ExcelJS.Workbook();
  await wb.xlsx.readFile(path.resolve(ROOT, secumsFile));
  const ws = wb.getWorksheet(sheetName);
  const secums = {};
  ws.eachRow((row) => {
    const v = row.values; if (!v) return;
    const m = String(v[3] || '').match(/^(SRV-\d+)_/);
    if (m && v[9] != null && !secums[m[1]]) secums[m[1]] = String(v[9]);
  });

  const wb2 = new ExcelJS.Workbook();
  await wb2.xlsx.readFile(path.resolve(ROOT, llmFile));
  const ws2 = wb2.getWorksheet('전체 진단 결과');
  const llm = {};
  ws2.eachRow((row, n) => { if (n > 1) { const id = row.getCell(2).value; if (!llm[id]) llm[id] = String(row.getCell(5).value); } });

  const { items, asset } = scriptResult.extractDiagnoseItems(path.resolve(ROOT, xmlFile));
  const p = new MockProvider({});
  const mock = {};
  for (const item of items) {
    item._os = asset.os;
    const r = JSON.parse(await p.complete({ user: buildPrompt(item, { engine: 'ai' }) }));
    if (!mock[item.chk_id]) mock[item.chk_id] = r.verdict;
  }

  const toOur = { OK: '양호', BAD: '취약', INFO: '정보제공', NA: '판정불가' };
  const stats = { all3: 0, sm: 0, sl: 0, ml: 0, total: 0 };
  const rows = [];
  for (const id of Object.keys(secums).sort()) {
    if (!mock[id] && !llm[id]) continue;
    stats.total++;
    const s = toOur[secums[id]] || secums[id];
    const mv = mock[id] || '(없음)', lv = llm[id] || '(없음)';
    if (s === mv && s === lv) stats.all3++;
    if (s === mv) stats.sm++;
    if (s === lv) stats.sl++;
    if (mv === lv) stats.ml++;
    if (s !== mv) rows.push(id + ' SecuMS=' + s + ' mock=' + mv + ' llm=' + lv);
  }
  console.log('총:', stats.total, '| 3자일치:', stats.all3, '(' + Math.round(stats.all3 / stats.total * 100) + '%)',
    '| SecuMS-Mock:', stats.sm, '(' + Math.round(stats.sm / stats.total * 100) + '%)',
    '| SecuMS-LLM:', stats.sl, '(' + Math.round(stats.sl / stats.total * 100) + '%)',
    '| Mock-LLM:', stats.ml, '(' + Math.round(stats.ml / stats.total * 100) + '%)');
  console.log('SecuMS-Mock 불일치:');
  rows.forEach(r => console.log(' ', r));
})();

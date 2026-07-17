'use strict';
// 5-소스 정합 매트릭스: SecuMS결과(OS_Detail) | Script-mock | SecuMS-raw-mock | LLM
// 모두 일치 행은 제외, 불일치만 출력. SRV 기준 정렬.
// 사용: node full-matrix.js <OS_Detail.xlsx> <시트> <script.xml> <secums.db> <llm리포트.xlsx>
const path = require('path');
const ROOT = path.resolve(__dirname, '../..');
const ExcelJS = require('exceljs');
const Database = require('better-sqlite3');
const scriptResult = require(ROOT + '/src/engine/adapters/scriptResult.js');
const secumsAdapter = require(ROOT + '/src/engine/adapters/secumsUnix.js');
const { buildPrompt } = require(ROOT + '/src/engine/aiDiagnose.js');
const MockProvider = require(ROOT + '/src/engine/llm/providers/mock.js');
const cw = require(ROOT + '/data/srv-secums-crosswalk.json');
const map = require(ROOT + '/data/srv-secums-map.json');

const toSrv = new Map();
for (const os of ['windows', 'linux']) for (const r of (cw[os] || [])) if (r.scan_id && r.srv) toSrv.set(String(r.scan_id), r.srv);
for (const osk of Object.keys(map.os || {})) for (const [srv, scan] of Object.entries(map.os[osk])) toSrv.set(String(scan), srv);
const srvKey = id => { const m = String(id).match(/SRV-?(\d+)/i); return m ? 'SRV-' + m[1].padStart(3, '0') : (toSrv.get(String(id)) || null); };
const V = { OK: '양호', BAD: '취약', INFO: '정보', NA: '판정불가', WAIT: '판정불가' };
const short = v => ({ '양호': '양호', '취약': '취약', '정보제공': '정보', '판정불가': 'N/A' }[v] || v || '-');

async function judge(items, os) {
  const p = new MockProvider({}); const out = {};
  for (const it of items) { it._os = it._os || os; const r = JSON.parse(await p.complete({ user: buildPrompt(it, { engine: 'ai' }) })); const k = srvKey(it.chk_id); if (k && !out[k]) out[k] = short(r.verdict); }
  return out;
}
async function loadReport(f) {
  const wb = new ExcelJS.Workbook(); await wb.xlsx.readFile(path.resolve(ROOT, f));
  const ws = wb.getWorksheet('전체 진단 결과'); const m = {};
  ws.eachRow((row, n) => { if (n > 1) { const k = srvKey(row.getCell(2).value); if (k && !m[k]) m[k] = short(String(row.getCell(5).value)); } });
  return m;
}

(async () => {
  const [xlsx, sheet, xml, dbf, llmf] = process.argv.slice(2);
  // SecuMS 결과 (OS_Detail)
  const wb = new ExcelJS.Workbook(); await wb.xlsx.readFile(path.resolve(ROOT, xlsx));
  const ws = wb.getWorksheet(sheet); const sec = {};
  ws.eachRow(row => { const m = String((row.values || [])[3] || '').match(/^(SRV-\d+)_/); const rv = (row.values || [])[9]; if (m && rv != null && !sec[m[1]]) sec[m[1]] = short(V[String(rv)] || String(rv)); });

  const s = scriptResult.extractDiagnoseItems(path.resolve(ROOT, xml));
  const scriptV = await judge(s.items, s.asset.os);
  const db = new Database(path.resolve(ROOT, dbf), { readonly: true });
  const rawV = await judge(secumsAdapter.extractDiagnoseItems(db), /win/i.test(dbf) ? 'windows' : 'linux');
  const llmV = await loadReport(llmf);

  const allIds = [...new Set([...Object.keys(sec), ...Object.keys(scriptV), ...Object.keys(rawV), ...Object.keys(llmV)])]
    .sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
  console.log('SRV\tSecuMS결과\tScript-mock\tSecuMSraw-mock\tLLM');
  let diff = 0;
  for (const id of allIds) {
    const row = [sec[id] || '-', scriptV[id] || '-', rawV[id] || '-', llmV[id] || '-'];
    const present = row.filter(x => x !== '-');
    const uniq = new Set(present);
    if (uniq.size <= 1) continue; // 모두 일치(또는 단일 소스) → 제외
    diff++;
    console.log(id + '\t' + row.join('\t'));
  }
  console.log('\n총 비교 SRV:', allIds.length, '| 불일치 행:', diff);
})();

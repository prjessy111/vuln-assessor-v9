'use strict';
// OS_Detail(SecuMS 점검결과)을 기준(ground truth)으로 script/secums-raw 두 mock 경로 정합 비교
// 사용: node osdetail-baseline.js <OS_Detail.xlsx> <시트> <script.xml> <secums.db>
const path = require('path');
const ROOT = path.resolve(__dirname, '../..');
const ExcelJS = require('exceljs');
const Database = require('better-sqlite3');
const scriptResult = require(ROOT + '/src/engine/adapters/scriptResult.js');
const secumsAdapter = require(ROOT + '/src/engine/adapters/secumsUnix.js');
const { buildPrompt } = require(ROOT + '/src/engine/aiDiagnose.js');
const MockProvider = require(ROOT + '/src/engine/llm/providers/mock.js');
const cw = require(ROOT + '/data/srv-secums-crosswalk.json');

const toSrv = new Map();
for (const os of ['windows', 'linux']) for (const r of (cw[os] || [])) if (r.scan_id && r.srv) toSrv.set(String(r.scan_id), r.srv);
const srvKey = id => { const m = String(id).match(/SRV-?(\d+)/i); return m ? 'SRV-' + m[1].padStart(3, '0') : (toSrv.get(String(id)) || String(id)); };

async function judgeAll(items, os) {
  const p = new MockProvider({});
  const out = {};
  for (const item of items) {
    item._os = item._os || os;
    const r = JSON.parse(await p.complete({ user: buildPrompt(item, { engine: 'ai' }) }));
    const k = srvKey(item.chk_id);
    if (!out[k]) out[k] = r.verdict;
  }
  return out;
}

(async () => {
  const [xlsx, sheet, xml, dbf] = process.argv.slice(2);
  const wb = new ExcelJS.Workbook();
  await wb.xlsx.readFile(path.resolve(ROOT, xlsx));
  const ws = wb.getWorksheet(sheet);
  const base = {};
  const toOur = { OK: '양호', BAD: '취약', INFO: '정보제공', NA: '판정불가' };
  ws.eachRow(row => {
    const v = row.values; if (!v) return;
    const m = String(v[3] || '').match(/^(SRV-\d+)_/);
    if (m && v[9] != null && !base[m[1]]) base[m[1]] = toOur[String(v[9])] || String(v[9]);
  });

  const s = scriptResult.extractDiagnoseItems(path.resolve(ROOT, xml));
  const scriptV = await judgeAll(s.items, s.asset.os);
  const db = new Database(path.resolve(ROOT, dbf), { readonly: true });
  const secV = await judgeAll(secumsAdapter.extractDiagnoseItems(db), /win/i.test(dbf) ? 'windows' : 'linux');

  const ids = Object.keys(base).sort((a, b) => a.localeCompare(b, undefined, { numeric: true }));
  let sMatch = 0, sCov = 0, rMatch = 0, rCov = 0, either = 0, bothNa = 0;
  const rows = [];
  for (const id of ids) {
    const b = base[id], sv = scriptV[id], rv = secV[id];
    if (sv) { sCov++; if (sv === b) sMatch++; }
    if (rv) { rCov++; if (rv === b) rMatch++; }
    // 병합: 두 경로 중 판정(비-판정불가) 하나라도 기준과 맞으면 either
    const sOk = sv && sv !== '판정불가', rOk = rv && rv !== '판정불가';
    if ((sOk && sv === b) || (rOk && rv === b)) either++;
    if ((!sv || sv === '판정불가') && (!rv || rv === '판정불가')) bothNa++;
    if (sv !== b || rv !== b) rows.push({ id, base: b, s: sv || '-', r: rv || '-' });
  }
  const pct = (n, d) => d ? Math.round(n / d * 100) + '%' : '-';
  console.log('기준(OS_Detail) 항목:', ids.length);
  console.log('스크립트 경로  : 커버', sCov, '| 기준일치', sMatch, '(' + pct(sMatch, ids.length) + ')');
  console.log('SecuMS raw 경로: 커버', rCov, '| 기준일치', rMatch, '(' + pct(rMatch, ids.length) + ')');
  console.log('병합(둘 중 맞으면): ' + either + '/' + ids.length + ' (' + pct(either, ids.length) + ')  | 둘다 판정불가:', bothNa);
  console.log('\n불일치/보류 상세 (기준 | script | secums-raw):');
  for (const r of rows) console.log(' ', r.id.padEnd(9), (r.base || '-').padEnd(6), '| S:' + r.s.padEnd(6), '| R:' + r.r);
})();

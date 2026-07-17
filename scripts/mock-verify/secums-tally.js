'use strict';
// SecuMS raw DB → mock 재판정 → SecuMS RESULT 와 대조 (RESULT 는 비교 전용 — P1)
// 사용: node secums-tally.js <exportData.db>
const path = require('path');
const ROOT = path.resolve(__dirname, '../..');
const Database = require('better-sqlite3');
const adapter = require(ROOT + '/src/engine/adapters/secumsUnix.js');
const { buildPrompt } = require(ROOT + '/src/engine/aiDiagnose.js');
const MockProvider = require(ROOT + '/src/engine/llm/providers/mock.js');

const dbPath = process.argv[2];
(async () => {
  const db = new Database(path.resolve(ROOT, dbPath), { readonly: true });
  const items = adapter.extractDiagnoseItems(db);
  const secums = {};
  for (const r of db.prepare('SELECT CHK_ID, RESULT FROM CHECKLIST_TB').all()) secums[r.CHK_ID] = r.RESULT;

  const p = new MockProvider({});
  const counts = {}; const rows = [];
  for (const item of items) {
    const r = JSON.parse(await p.complete({ user: buildPrompt(item, { engine: 'ai' }) }));
    counts[r.verdict] = (counts[r.verdict] || 0) + 1;
    rows.push({ id: item.chk_id, mock: r.verdict, secums: secums[item.chk_id], reason: String(r.reason).slice(0, 60) });
  }
  const total = rows.length;
  const na = counts['판정불가'] || 0;
  console.log(path.basename(dbPath), '| 항목:', total, '|', JSON.stringify(counts), '| 판정률:', Math.round((total - na) / total * 100) + '%');

  const toOur = { OK: '양호', BAD: '취약', INFO: '정보제공', NA: '판정불가' };
  let agree = 0, cmp = 0;
  const dis = [];
  for (const r of rows) {
    if (!r.secums) continue;
    cmp++;
    const s = toOur[r.secums] || r.secums;
    if (s === r.mock) agree++;
    else dis.push(r.id + ' SecuMS=' + s + ' mock=' + r.mock + ' | ' + r.reason);
  }
  console.log('SecuMS 대조(비교 전용):', agree + '/' + cmp, '(' + Math.round(agree / cmp * 100) + '%)');
  dis.forEach(d => console.log('  ', d));
})();

'use strict';
// SecuMS DB 항목 디버그: node secums-debug.js <db> <chk_id>
const path = require('path');
const ROOT = path.resolve(__dirname, '../..');
const Database = require('better-sqlite3');
const adapter = require(ROOT + '/src/engine/adapters/secumsUnix.js');
const { buildPrompt } = require(ROOT + '/src/engine/aiDiagnose.js');
const MockProvider = require(ROOT + '/src/engine/llm/providers/mock.js');
const PATTERN_LIBRARY = require(ROOT + '/src/engine/llm/providers/mockPatterns.js');
const dump = require(ROOT + '/src/engine/llm/providers/mockSecumsDump.js');

const [dbPath, id] = process.argv.slice(2);
(async () => {
  const db = new Database(path.resolve(ROOT, dbPath), { readonly: true });
  const items = adapter.extractDiagnoseItems(db);
  const item = items.find(i => i.chk_id === id);
  if (!item) { console.log('item not found'); return; }
  console.log('type:', item.type, '| actions:', item.actions.length);
  const prompt = buildPrompt(item, { engine: 'ai' });
  const all = item.actions.map(a => String(a.result_output)).join('\n');
  console.log('--- dumps ---');
  for (const d of dump.parseDumps(all)) {
    console.log('cols:', d.columns.join('|'), '| rows:', d.rows.length);
    for (const r of d.rows.slice(0, 6)) console.log('   ', r.join(' | ').slice(0, 120));
  }
  const pat = PATTERN_LIBRARY[id];
  if (pat) {
    for (const side of ['vuln', 'safe']) {
      for (const [i, p] of (pat[side] || []).entries()) {
        const res = typeof p.pattern === 'function' ? p.pattern(all) : (p.pattern.test(all) ? (p.reason || 'regex') : null);
        console.log(side + '[' + i + '] ->', res);
      }
    }
  } else console.log('(전용 패턴 없음)');
  console.log('generic ->', JSON.stringify(dump.evaluateGeneric(all)));
  const p = new MockProvider({});
  const r = JSON.parse(await p.complete({ user: prompt }));
  console.log('mock verdict:', r.verdict, '|', String(r.reason).slice(0, 90));
})();

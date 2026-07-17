'use strict';
// 특정 항목 mock 판정 디버그: node debug-item.js <xml> <SRV-ID>
const ROOT = 'E:/backup2/vuln-assessor-v9-main';
const scriptResult = require(ROOT + '/src/engine/adapters/scriptResult.js');
const { buildPrompt } = require(ROOT + '/src/engine/aiDiagnose.js');
const MockProvider = require(ROOT + '/src/engine/llm/providers/mock.js');
const { getScriptPatterns } = require(ROOT + '/src/engine/llm/providers/mockScriptPatterns.js');

const [xml, id] = process.argv.slice(2);
(async () => {
  const { items, asset } = scriptResult.extractDiagnoseItems(ROOT + '/' + xml);
  const p = new MockProvider({});
  for (const item of items.filter(i => i.chk_id === id)) {
    item._os = asset.os;
    const prompt = buildPrompt(item, { engine: 'ai' });
    const outputMatches = prompt.match(/```(?!json)\s*([\s\S]*?)```/g) || [];
    const ctrl = new RegExp('[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]', 'g');
    const outputs = outputMatches
      .map(m => m.replace(/```/g, '').replace(ctrl, '').trim())
      .filter(o => o.length > 0 && !o.startsWith('{'));
    const all = outputs.join('\n');
    console.log('=== instance, outputs:', outputs.length, 'chars:', all.length);
    console.log('absence:', JSON.stringify(p._checkAbsence(outputs)));
    const pat = getScriptPatterns(id);
    for (const [i, r] of (pat.vuln || []).entries()) {
      const res = typeof r.pattern === 'function' ? r.pattern(all, outputs, []) : (r.pattern.test(all) ? (r.reason || 'regex') : null);
      if (res) console.log('vuln[' + i + '] ->', String(res).slice(0, 90));
    }
    for (const [i, r] of (pat.safe || []).entries()) {
      const res = typeof r.pattern === 'function' ? r.pattern(all, outputs, []) : (r.pattern.test(all) ? (r.reason || 'regex') : null);
      if (res) console.log('safe[' + i + '] ->', String(res).slice(0, 90));
    }
    const result = JSON.parse(await p.complete({ user: prompt }));
    console.log('mock verdict:', result.verdict, '|', String(result.reason).slice(0, 100));
  }
})();

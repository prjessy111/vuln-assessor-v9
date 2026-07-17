'use strict';
// 실제 script XML → adapter → buildPrompt → MockProvider 전체 경로 tally
const path = require('path');
const ROOT = 'E:/backup2/vuln-assessor-v9-main';
const scriptResult = require(ROOT + '/src/engine/adapters/scriptResult.js');
const { buildPrompt } = require(ROOT + '/src/engine/aiDiagnose.js');
const MockProvider = require(ROOT + '/src/engine/llm/providers/mock.js');

const FILES = [
  ROOT + '/data/uploads/2026-07-02/jessy107_script_20260702.xml',
  ROOT + '/data/uploads/2026-07-02/jessy207_script_20260702.xml',
];

(async () => {
  for (const f of FILES) {
    const { asset, items } = scriptResult.extractDiagnoseItems(f);
    const provider = new MockProvider({});
    const counts = {};
    const na = [];
    for (const item of items) {
      item._os = asset.os;
      const prompt = buildPrompt(item, { engine: 'ai' });
      let verdict = 'ERROR';
      try {
        const r = await provider.complete({ user: prompt });
        verdict = JSON.parse(r).verdict;
      } catch (e) { verdict = 'ERROR:' + e.message.slice(0, 40); }
      counts[verdict] = (counts[verdict] || 0) + 1;
      if (verdict === '판정불가') na.push(item.chk_id);
    }
    console.log('===', path.basename(f), `(os=${asset.os}, items=${items.length})`);
    console.log(JSON.stringify(counts));
    console.log('판정불가:', na.join(','));
  }
})();

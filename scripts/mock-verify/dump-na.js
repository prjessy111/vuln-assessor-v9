'use strict';
// 판정불가 항목들의 raw 본문 요약 덤프: node dump-na.js <xml> <id,id,...> [chars]
const ROOT = 'E:/backup2/vuln-assessor-v9-main';
const fs = require('fs');
const [xml, idcsv, charsArg] = process.argv.slice(2);
const CHARS = parseInt(charsArg || '450', 10);
const t = fs.readFileSync(ROOT + '/' + xml, 'utf-8');
const dumps = t.match(/<dump>[\s\S]*?<\/dump>/g) || [];
for (const id of idcsv.split(',')) {
  let found = false;
  for (const d of dumps) {
    if (!new RegExp('<id>' + id + '</id>').test(d)) continue;
    found = true;
    const out = (d.match(/<output>([\s\S]*?)<\/output>/) || ['', ''])[1];
    const bodies = [...out.matchAll(/RAW_COMMAND_OUTPUT_BEGIN([\s\S]*?)RAW_COMMAND_OUTPUT_END/g)].map(m => m[1]);
    const body = (bodies.length ? bodies.join('\n') : out).trim();
    console.log('===== ' + id + ' (' + body.length + ' chars) =====');
    console.log(body.slice(0, CHARS).replace(/\n{3,}/g, '\n\n'));
  }
  if (!found) console.log('===== ' + id + ' NOT FOUND =====');
}

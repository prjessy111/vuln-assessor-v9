'use strict';
/**
 * SecuMS reportVul(전자금융기반시설_2026_OS) → SRV별 "2026 점검 사양" 추출.
 * 스크립트를 2026에 맞추기 위한 기준표. 한 번만 파싱해 JSON 캐시.
 *
 * 출력: data/secums-2026-spec.json
 *   { os: { windows: { 'SRV-001': {title, result, checks:[키...] } }, linux:{...} } }
 *   - result: 취약(BAD 존재) | 정보(INFO) 등
 *   - checks: 취약점 상세에서 추출한 점검 대상 키(콜론 앞 토큰)
 */
const path = require('path');
const fs = require('fs');
const ExcelJS = require('exceljs');
const ROOT = path.resolve(__dirname, '..');
const ct = c => { let v=c.value; if(v&&typeof v==='object'){ if(v.richText) return v.richText.map(t=>t.text).join(''); if(v.text) return v.text; if(v.result!=null) return String(v.result); return '';} return v==null?'':String(v); };
const SRV = s => { const m=String(s).match(/SRV-(\d+)/i); return m?'SRV-'+m[1].padStart(3,'0'):null; };
const titleOf = s => { const m=String(s).match(/SRV-\d+[_\s]*(.+)/); return m?m[1].trim():''; };
const keyOf = detail => { const t=String(detail).trim(); const i=t.indexOf(':'); return (i>0?t.slice(0,i):t).trim().slice(0,60); };

(async () => {
  const file = process.argv[2] || 'reportVul-10019_2026-06-1420260613123559.695.xlsx';
  const wb = new ExcelJS.Workbook();
  await wb.xlsx.readFile(path.join(ROOT, file));
  const ws = wb.worksheets[0];
  const rv = r => { const o=[]; for(let i=1;i<=ws.columnCount;i++) o.push(ct(ws.getRow(r).getCell(i))); return o; };
  // idx: OS=3, 장비명=6, 점검결과=8, 취약점=9, 상세=10
  const os = { windows:{}, linux:{} };
  for (let r=13; r<=ws.rowCount; r++) {
    const v = rv(r);
    const osk = /win/i.test(v[3]) ? 'windows' : /linux/i.test(v[3]) ? 'linux' : null;
    const srv = SRV(v[9]); if (!osk || !srv) continue;
    const res = (v[8]||'').trim();
    const bucket = os[osk];
    bucket[srv] = bucket[srv] || { title: titleOf(v[9]), bad:0, info:0, checks:new Set() };
    if (res==='BAD') bucket[srv].bad++; else if (res==='INFO') bucket[srv].info++;
    const k = keyOf(v[10]); if (k) bucket[srv].checks.add(k);
  }
  const out = { generated_at:'2026-06-14', source:file, os:{} };
  for (const osk of Object.keys(os)) {
    out.os[osk] = {};
    for (const [srv, d] of Object.entries(os[osk])) {
      out.os[osk][srv] = { title:d.title, result: d.bad?'취약':(d.info?'정보':'기타'), checks:[...d.checks].slice(0,12) };
    }
  }
  const outPath = path.join(ROOT, 'data/secums-2026-spec.json');
  fs.writeFileSync(outPath, JSON.stringify(out, null, 2));
  console.log('wrote', outPath);
  for (const osk of Object.keys(out.os)) {
    const n = Object.keys(out.os[osk]).length;
    const vuln = Object.values(out.os[osk]).filter(x=>x.result==='취약').length;
    console.log(`  ${osk}: SRV ${n}개 (취약 ${vuln})`);
  }
})();

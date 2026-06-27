'use strict';
/**
 * 리포트1.xlsx OS시트 → SRV별 2026 점검 사양(확인방법/기준/조치법) 추출.
 * 스크립트를 2026에 맞추기 위한 항목별 기준표.
 * 출력: data/report1-2026-checkspec.json  { os:{windows:{'SRV-001':{title,확인방법,기준,조치법}}, linux:{...}} }
 */
const path = require('path'); const fs = require('fs'); const ExcelJS = require('exceljs');
const ROOT = path.resolve(__dirname, '..');
const ct = c => { let v=c.value; if(v&&typeof v==='object'){ if(v.richText) return v.richText.map(t=>t.text).join(''); if(v.text) return v.text; if(v.result!=null) return String(v.result); return '';} return v==null?'':String(v); };
const rowVals = (ws,r) => { const o=[]; for(let i=1;i<=ws.columnCount;i++) o.push(ct(ws.getRow(r).getCell(i))); return o; };
const SRV = s => { const m=String(s).match(/SRV-(\d+)/i); return m?'SRV-'+m[1].padStart(3,'0'):null; };
const clip = (s,n)=> (s||'').replace(/\r/g,'').trim().slice(0,n);

async function extract(sheetName) {
  const wb = new ExcelJS.Workbook(); await wb.xlsx.readFile(path.join(ROOT,'리포트1.xlsx'));
  const ws = wb.getWorksheet(sheetName); if(!ws) return {};
  let hr=1; for(let r=1;r<=3;r++){ if(rowVals(ws,r).some(v=>/확인방법/.test(v))){hr=r;break;} }
  const h = rowVals(ws,hr);
  const iTitle=h.findIndex(v=>/점검항목제목/.test(v)), iHow=h.findIndex(v=>/확인방법/.test(v)),
        iStd=h.findIndex(v=>/^기준$/.test(v)), iFix=h.findIndex(v=>/조치법/.test(v)), iId=h.findIndex(v=>/^ID$/.test(v));
  const out={};
  for(let r=hr+1;r<=ws.rowCount;r++){ const v=rowVals(ws,r); const srv=SRV(iId>=0?v[iId]:'')||SRV(v[iTitle]);
    if(!srv) continue;
    out[srv]={ title:clip(v[iTitle],60), 확인방법:clip(v[iHow],1500), 기준:clip(v[iStd],600), 조치법:clip(v[iFix],800) }; }
  return out;
}
(async()=>{
  const out={ generated_at:'2026-06-15', source:'리포트1.xlsx', os:{ windows: await extract('Windows'), linux: await extract('Linux') } };
  const p=path.join(ROOT,'data/report1-2026-checkspec.json'); fs.writeFileSync(p, JSON.stringify(out,null,2));
  console.log('wrote',p);
  for(const o of ['windows','linux']) console.log(`  ${o}: ${Object.keys(out.os[o]).length} SRV`);
  console.log('\n[샘플] windows SRV-001 확인방법:', (out.os.windows['SRV-001']||{}).확인방법?.slice(0,120));
})();

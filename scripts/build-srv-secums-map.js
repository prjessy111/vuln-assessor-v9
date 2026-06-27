'use strict';
/**
 * SRV(리포트1/script) ↔ os-xxx(SecuMS Scan ID/리포트3) 크로스워크 생성기.
 *
 * 출처: 리포트1.xlsx 의 OS별 시트. 각 행에 ID 컬럼(SRV-NNN) 과 Scan ID 컬럼(os-{os}-NNN)이
 * 함께 있어 그대로 매핑이 된다.
 *
 * 출력: data/srv-secums-map.json
 *   { generated_at, source, os: { linux:{SRV->scan}, windows:{...} },
 *     reverse: { linux:{scan->SRV}, windows:{...} } }
 *
 * 실행: node scripts/build-srv-secums-map.js
 */
const path = require('path');
const fs = require('fs');
const ExcelJS = require('exceljs');

const ROOT = path.resolve(__dirname, '..');
const ct = c => { let v = c.value; if (v && typeof v === 'object') { if (v.richText) return v.richText.map(t => t.text).join(''); if (v.text) return v.text; if (v.result != null) return String(v.result); return ''; } return v == null ? '' : String(v); };
const rowVals = (ws, r) => { const o = []; for (let i = 1; i <= ws.columnCount; i++) o.push(ct(ws.getRow(r).getCell(i))); return o; };
const SRV = s => { const m = String(s).match(/SRV-(\d+)/i); return m ? 'SRV-' + m[1].padStart(3, '0') : null; };
const SCAN = s => { const m = String(s).match(/os-(win|linux|aix|hpux|solaris)-(\d+)/i); return m ? `os-${m[1].toLowerCase()}-${m[2]}` : null; };

async function extract(file, sheetNames) {
  const wb = new ExcelJS.Workbook();
  await wb.xlsx.readFile(path.join(ROOT, file));
  const out = {};
  for (const name of sheetNames) {
    const ws = wb.getWorksheet(name);
    if (!ws) continue;
    let hr = 1;
    for (let r = 1; r <= 3; r++) { if (rowVals(ws, r).some(v => /Scan ?ID/i.test(v))) { hr = r; break; } }
    const hdr = rowVals(ws, hr);
    const iTitle = hdr.findIndex(h => /점검항목제목|점검항목/.test(h));
    const iScan = hdr.findIndex(h => /Scan ?ID/i.test(h));
    const iId = hdr.findIndex(h => /^ID$/i.test(h));
    const osKey = name.toLowerCase();
    const map = {};
    for (let r = hr + 1; r <= ws.rowCount; r++) {
      const v = rowVals(ws, r);
      const srv = SRV(iId >= 0 ? v[iId] : '') || SRV(iTitle >= 0 ? v[iTitle] : '');
      const scan = SCAN(iScan >= 0 ? v[iScan] : '');
      if (srv && scan) map[srv] = scan;
    }
    out[osKey] = map;
  }
  return out;
}

(async () => {
  const r1 = await extract('리포트1.xlsx', ['Linux', 'Windows']);
  const osMap = { linux: r1.linux || {}, windows: r1.windows || {} };
  const reverse = {};
  for (const os of Object.keys(osMap)) {
    reverse[os] = {};
    for (const [srv, scan] of Object.entries(osMap[os])) reverse[os][scan] = srv;
  }
  const result = {
    generated_at: '2026-06-14',
    source: '리포트1.xlsx (ID=SRV, Scan ID=os-xxx)',
    os: osMap,
    reverse,
  };
  const outPath = path.join(ROOT, 'data/srv-secums-map.json');
  fs.writeFileSync(outPath, JSON.stringify(result, null, 2));
  console.log('wrote ' + outPath);
  for (const os of Object.keys(osMap)) console.log(`  ${os}: ${Object.keys(osMap[os]).length} SRV↔os-xxx pairs`);

  // ── 커버리지 검증: 실제 진단 2500(script win) / 2505(secums win) ──
  const diags = JSON.parse(fs.readFileSync(path.join(ROOT, 'data/mock/diagnoses.json'), 'utf8'));
  const getItems = d => { for (const k of Object.keys(d)) if (Array.isArray(d[k]) && d[k][0] && d[k][0].chk_id) return d[k]; return []; };
  const codesOf = id => { const d = diags.find(x => x.assessment_id == id); return d ? getItems(d).map(it => it.chk_id) : []; };

  const winFwd = osMap.windows;          // SRV -> os-win
  const winRev = reverse.windows;        // os-win -> SRV
  const scriptSrv = codesOf(2500).map(SRV).filter(Boolean);
  const secumsScan = codesOf(2505).map(SCAN).filter(Boolean);

  const scriptMapped = scriptSrv.filter(s => winFwd[s]);
  const secumsMapped = secumsScan.filter(s => winRev[s]);
  // script SRV를 os-win으로 번역 후 secums와 교집합
  const scriptAsScan = new Set(scriptSrv.map(s => winFwd[s]).filter(Boolean));
  const overlap = secumsScan.filter(s => scriptAsScan.has(s));

  console.log('\n[jessy167 커버리지]');
  console.log(`  script(2500) SRV ${scriptSrv.length}개 중 매핑됨 ${scriptMapped.length}`);
  console.log(`  secums(2505) os-win ${secumsScan.length}개 중 매핑됨(SRV 존재) ${secumsMapped.length}`);
  console.log(`  매핑 거친 script∩secums 공통 항목: ${overlap.length}`);
  console.log('  secums 미매핑(리포트1에 없음) 샘플:', secumsScan.filter(s => !winRev[s]).slice(0, 12).join(', '));
})();

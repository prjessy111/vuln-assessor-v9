'use strict';
/**
 * 리포트1.xlsx → 3-way 정합성용 크로스워크 생성.
 *
 * 리포트1 OS 시트(Windows/Linux): E열(5)=제목, K열(11)=Scan ID(os-xxx), N열(14)=ID(SRV).
 * 실측 결과 SecuMS raw DB의 CHECKLIST_TB CHK_ID = 리포트1 ScanID 와 100% 일치 →
 * SRV(script) ↔ os-xxx(secums) ↔ 제목 을 코드로 정확히 연결한다.
 *
 * 출력: data/srv-secums-crosswalk.json
 *   { windows: [{srv, scan_id, title}], linux: [...] }
 */
const path = require('path');
const fs = require('fs');
const ExcelJS = require('exceljs');

const ROOT = path.resolve(__dirname, '..');

function cleanTitle(t) {
  if (!t) return '';
  // "SRV-001_안전한 네트워크..." → "안전한 네트워크..."
  return String(t).replace(/^SRV-\d+[_\s]*/, '').trim();
}

async function buildSheet(ws) {
  const rows = [];
  ws.eachRow((row, rn) => {
    if (rn < 2) return;
    const title = row.getCell(5).value;
    const scanId = row.getCell(11).value;
    const srv = row.getCell(14).value;
    if (!scanId) return;
    rows.push({
      srv: srv ? String(srv).trim() : '',
      scan_id: String(scanId).trim(),
      title: cleanTitle(title),
    });
  });
  return rows;
}

(async () => {
  const wb = new ExcelJS.Workbook();
  await wb.xlsx.readFile(path.join(ROOT, '리포트1.xlsx'));
  const out = {
    generated_at: process.env.GEN_DATE || '(stamp-after)',
    source: '리포트1.xlsx (E=제목, K=ScanID, N=SRV)',
    windows: await buildSheet(wb.getWorksheet('Windows')),
    linux: await buildSheet(wb.getWorksheet('Linux')),
  };
  const outPath = path.join(ROOT, 'data/srv-secums-crosswalk.json');
  fs.writeFileSync(outPath, JSON.stringify(out, null, 2), 'utf8');
  console.log('생성:', outPath);
  console.log('  windows:', out.windows.length, '| linux:', out.linux.length);
  console.log('  win 샘플:', JSON.stringify(out.windows[0]), JSON.stringify(out.windows[3]));
  console.log('  lin 샘플:', JSON.stringify(out.linux[0]));
})().catch(e => { console.error('ERR', e.message); process.exit(1); });

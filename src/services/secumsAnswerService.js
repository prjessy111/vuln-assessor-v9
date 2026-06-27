'use strict';
/**
 * SecuMS 상세 리포트(OS_Detail_Report_*.xlsx) 파서 + 저장.
 *
 * 상세 리포트는 서버별 시트에 "■ 점검 결과 상세" 표가 있고,
 *   항목 열 = "SRV-001_제목", 결과 열 = BAD / OK / INFO
 * 즉 SecuMS 자체판정(③)이 SRV 코드 단위로 들어있다 → 3-way 비교의 정답지로 사용.
 *
 * 저장: data/secums-answers/{hostname}.json = { srv: 'BAD'|'OK'|'INFO', ... }
 * (업로드한 SecuMS 점검 결과. 진단 raw DB의 RESULT 보다 우선 정답지로 사용.)
 */
const fs = require('fs');
const path = require('path');
const ExcelJS = require('exceljs');

const ROOT = path.resolve(__dirname, '../..');
const ANSWER_DIR = path.join(ROOT, 'data/secums-answers');

function cellText(v) {
  if (v == null) return '';
  if (typeof v === 'object') {
    if (v.text) return String(v.text);
    if (v.result != null) return String(v.result);
    if (Array.isArray(v.richText)) return v.richText.map(r => r.text).join('');
    return '';
  }
  return String(v);
}

// ExcelJS row.values 는 1-기반 + 희소(빈 셀=hole) → 밀집 문자열 배열로 변환(hole='').
function rowVals(row) {
  const raw = row.values || [];
  const out = [];
  for (let i = 0; i < raw.length; i++) out[i] = cellText(raw[i]);
  return out;
}

/**
 * 상세 리포트 파일 파싱 → 서버별 { srv: verdict } 맵.
 * @returns {{ servers: Object, summary: Array }}
 */
async function parseDetailReport(filePath) {
  const wb = new ExcelJS.Workbook();
  await wb.xlsx.readFile(filePath);
  const servers = {};
  const summary = [];

  for (const ws of wb.worksheets) {
    if (/표지|cover|summary/i.test(ws.name)) continue;

    // 호스트명: "호스트명" 라벨 옆 값, 없으면 시트명 prefix
    let hostname = '';
    ws.eachRow((row, rn) => {
      if (hostname || rn > 12) return;
      const vals = rowVals(row);
      const idx = vals.findIndex(v => v.trim() === '호스트명');
      if (idx >= 0) {
        const h = vals.slice(idx + 1).find(v => v && v.trim() && v.trim() !== '호스트명');
        if (h) hostname = h.trim();
      }
    });
    if (!hostname) hostname = ws.name.replace(/_\d+$/, '').trim();

    // "결과" + "항목" 헤더 행 찾기 → 열 인덱스
    let resultCol = -1, itemCol = -1, headerRow = -1;
    ws.eachRow((row, rn) => {
      if (headerRow > 0 || rn > 60) return;
      const vals = rowVals(row);
      const rIdx = vals.findIndex(v => v.trim() === '결과');
      const iIdx = vals.findIndex(v => v.trim() === '항목');
      if (rIdx >= 0 && iIdx >= 0) { headerRow = rn; resultCol = rIdx; itemCol = iIdx; }
    });
    if (headerRow < 0) continue;

    const map = {};
    let bad = 0, ok = 0, info = 0;
    ws.eachRow((row, rn) => {
      if (rn <= headerRow) return;
      const vals = rowVals(row);
      const itemText = vals.slice(itemCol).find(v => /SRV-\d+/i.test(v)) || '';
      const m = itemText.match(/SRV-(\d+)/i);
      if (!m) return;
      const srv = 'SRV-' + m[1].padStart(3, '0');
      const verdict = (vals[resultCol] || '').trim().toUpperCase();
      // 유효 판정만, 항목당 첫 값(요약행)만 채택 — 하위 상세행이 덮어쓰지 않게
      if (!['BAD', 'OK', 'INFO'].includes(verdict)) return;
      if (map[srv]) return;
      map[srv] = verdict;
      if (verdict === 'BAD') bad++; else if (verdict === 'OK') ok++; else info++;
    });

    if (Object.keys(map).length) {
      servers[hostname] = map;
      summary.push({ hostname, total: Object.keys(map).length, bad, ok, info });
    }
  }
  return { servers, summary };
}

function saveAnswers(servers) {
  if (!fs.existsSync(ANSWER_DIR)) fs.mkdirSync(ANSWER_DIR, { recursive: true });
  const saved = [];
  for (const [host, map] of Object.entries(servers)) {
    const p = path.join(ANSWER_DIR, host + '.json');
    fs.writeFileSync(p, JSON.stringify({ hostname: host, updated_at: new Date().toLocaleString('sv-SE'), verdicts: map }, null, 2), 'utf8');
    saved.push({ hostname: host, count: Object.keys(map).length });
  }
  return saved;
}

function loadAnswer(hostname) {
  try {
    const p = path.join(ANSWER_DIR, String(hostname) + '.json');
    if (!fs.existsSync(p)) return null;
    return JSON.parse(fs.readFileSync(p, 'utf8'));
  } catch (_) { return null; }
}

module.exports = { parseDetailReport, saveAnswers, loadAnswer, ANSWER_DIR };

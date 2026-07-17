'use strict';
// 점검 항목 기준 os-win↔SRV 매핑 — 각 os-win 의 "특정 대상 키"(probe arg 의 핵심 식별자)를
// OS_Detail SRV 의 근거/제목에서 정확 문자열로 찾는다. 유일하게 매칭될 때만 채택(오탐 방지).
const path = require('path');
const ROOT = path.resolve(__dirname, '../..');
const ExcelJS = require('exceljs');
const Database = require('better-sqlite3');
const fs = require('fs');
const [xlsx, sheet, dbf, outArg] = process.argv.slice(2);
function decode(s) { return String(s || '').replace(/&apos;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&amp;/g, '&'); }

// probe arg / SQL 에서 "특정 대상 키" 추출: 권한명(Se*Right/Se*Privilege), 정책명(콤마 뒤),
// 레지스트리 값명(백슬래시 뒤 마지막), 서비스명 목록
function targetKeys(block) {
  const keys = new Set();
  const argText = [...block.matchAll(/<arg>([\s\S]*?)<\/arg>/g)].map(a => a[1]).join(' ; ');
  const sqlKeys = [...block.matchAll(/ARG\s*=\s*'([^']+)'/gi)].map(a => a[1]).join(' ; ');
  const all = argText + ' ; ' + sqlKeys;
  for (const m of all.matchAll(/\bSe[A-Za-z]+(?:Right|Privilege)\b/g)) keys.add(m[0]);          // 권한
  for (const m of all.matchAll(/(?:System Access|Event Audit|Registry Values)\s*,\s*([A-Za-z][\w]+)/g)) keys.add(m[1]); // 정책
  for (const m of all.matchAll(/\\([A-Za-z][\w]{4,})(?:\s|;|$)/g)) keys.add(m[1]);              // 레지스트리 값명(경로 끝)
  for (const m of all.matchAll(/\b(restrictanonymous\w*|AutoShare\w+|LmCompatibilityLevel|NoLMHash|AllocateDASD|ScreenSaver\w*|SCRNSAVE\.EXE|ShutdownWithoutLogon|DontDisplayLastUserName|EnableLUA|FilterAdministratorToken|CrashOnAuditFail|AllowAnonymous)\b/gi)) keys.add(m[1]);
  for (const m of all.matchAll(/\b(Messenger|RemoteRegistry|SNMP|MSFTPSVC|Alerter)\b/g)) keys.add('svc:' + m[1]);
  return [...keys];
}

(async () => {
  // OS_Detail: SRV 제목 + 근거 전체 텍스트
  const wb = new ExcelJS.Workbook();
  await wb.xlsx.readFile(path.resolve(ROOT, xlsx));
  const ws = wb.getWorksheet(sheet);
  const rows = []; ws.eachRow((r, n) => { rows[n] = r.values || []; });
  const srv = {}; let cur = null;
  for (let n = 1; n < rows.length; n++) {
    const row = rows[n] || []; const c1 = String(row[1] || '');
    const m = c1.match(/^■ (SRV-\d+)_(.+)/);
    if (m) { cur = m[1]; srv[cur] = { title: m[2], text: m[2] + ' ' }; continue; }
    if (!cur) continue;
    if (/^(내용)$/.test(c1)) { cur = null; continue; }
    if (c1 && !/^(확인 방법|기준|조치법|결과|점검 결과|■)/.test(c1)) srv[cur].text += c1 + ' ' + (row[4] || '') + ' ';
  }
  const srvKeys = Object.keys(srv);

  // DB RULE XML
  const db = new Database(path.resolve(ROOT, dbf), { readonly: true });
  const ruleXml = decode(db.prepare("SELECT VALUE FROM DEBUG_DATA_TB WHERE ITEM='RULE' LIMIT 1").all()[0].VALUE);

  const result = {}, report = [], unmatched = [];
  for (const mm of ruleXml.matchAll(/<check id="(os-win-\d+)"[^>]*>([\s\S]*?)<\/check>/g)) {
    const id = mm[1], block = mm[2];
    const keys = targetKeys(block);
    if (!keys.length) { unmatched.push(id + '(키없음)'); continue; }
    // 각 키가 정확 매칭되는 SRV 후보 수집
    const hits = new Map();
    for (const k of keys) {
      const bare = k.replace(/^svc:/, '');
      const re = new RegExp('\\b' + bare.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\b', 'i');
      for (const sk of srvKeys) if (re.test(srv[sk].text)) hits.set(sk, (hits.get(sk) || 0) + 1);
    }
    if (!hits.size) { unmatched.push(id + '(' + keys.slice(0, 2).join(',') + ')'); continue; }
    const ranked = [...hits.entries()].sort((a, b) => b[1] - a[1]);
    if (ranked.length === 1 || ranked[0][1] > ranked[1][1]) {
      result[id] = ranked[0][0];
      report.push({ id, srv: ranked[0][0], title: srv[ranked[0][0]].title.slice(0, 26), keys: keys.slice(0, 3).join(',') });
    } else {
      unmatched.push(id + '(동점:' + ranked.slice(0, 2).map(r => r[0]).join('/') + ')');
    }
  }
  report.sort((a, b) => a.id.localeCompare(b.id, undefined, { numeric: true }));
  console.log('매핑:', report.length, '/ 총', report.length + unmatched.length);
  for (const r of report) console.log('  ', r.id.padEnd(13), '→', r.srv, '(' + r.title + ')  [' + r.keys + ']');
  console.log('\n미매칭:', unmatched.join(', '));
  if (outArg) { fs.writeFileSync(path.resolve(ROOT, outArg), JSON.stringify(result, null, 2)); console.log('\n저장:', outArg); }
})();

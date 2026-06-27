'use strict';
// 우리 스크립트의 SRV별 수집명령 ↔ 리포트1 2026 확인방법 대조표 (전수)
const fs = require('fs'); const path = require('path');
const ROOT = path.resolve(__dirname,'..');
const spec = require(path.join(ROOT,'data/report1-2026-checkspec.json'));
const osArg = (process.argv[2]||'windows').toLowerCase();
const scriptFile = osArg==='linux' ? 'scripts/ai-ready/fsi_unix_ai.sh' : 'scripts/ai-ready/fsi_win_ai.ps1';
const txt = fs.readFileSync(path.join(ROOT,scriptFile),'utf8');

// 우리 스크립트에서 SRV별 수집 명령 추출
const ours = {};
if (osArg==='linux') {
  // fDumpS "SRV-xxx" ... 형태 + 명령. sh는 구조가 달라 라인 단위로 SRV 등장 추출
  const re=/SRV-(\d+)/g; let m; const lines=txt.split(/\n/);
  lines.forEach(l=>{ const mm=l.match(/SRV-(\d+)/); if(mm && /fDump|echo|cmd|grep|cat|\$\(/.test(l)){ const id='SRV-'+mm[1].padStart(3,'0'); if(!ours[id]) ours[id]=l.trim().slice(0,110); } });
} else {
  const re=/Write-FsiItem\s+"(SRV-\d+)"\s+'([^']*)'\s*\{([^}]*)\}/g; let m;
  while((m=re.exec(txt))){ ours[m[1]]= (m[3]||m[2]).replace(/\s+/g,' ').trim().slice(0,110); }
}

const specOs = spec.os[osArg]||{};
const allIds = Array.from(new Set([...Object.keys(specOs), ...Object.keys(ours)])).sort((a,b)=>parseInt(a.slice(4))-parseInt(b.slice(4)));
console.log(`### ${osArg} — 우리 스크립트 ${Object.keys(ours).length}개 / 2026 기준 ${Object.keys(specOs).length}개 ###\n`);
for(const id of allIds){
  const sp=specOs[id]; const our=ours[id];
  const how=(sp?.확인방법||'').replace(/\s+/g,' ').slice(0,90);
  const flag = !our ? '❌미수집' : !sp ? '➕기준외' : '';
  console.log(`${id} ${flag}`);
  console.log(`   2026: ${sp?sp.title:'(기준없음)'} | ${how}`);
  console.log(`   우리: ${our||'(없음)'}`);
}

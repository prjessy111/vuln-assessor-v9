'use strict';
/**
 * ADV 소개 PPTX 생성 — dist/ADV_소개_v9.15.pptx (편집 가능한 PowerPoint).
 * 사용:  npm run build-pptx
 */
const pptxgen = require('pptxgenjs');
const path = require('path');
const fs = require('fs');

const NAVY='0F172A', PANEL='16233F', LINE='26375C', FG='EAF1FB', MUTED='9FB2D4',
      FAINT='6F83A8', SKY='38BDF8', BLUE='3B82F6', INDIGO='6366F1', GOOD='10B981', BAD='F43F5E';
const FONT='Malgun Gothic', MONO='Consolas';
const W=13.33, H=7.5;

const pptx = new pptxgen();
pptx.defineLayout({ name:'ADV', width:W, height:H });
pptx.layout='ADV';
pptx.author='ADV'; pptx.company='ADV (AI Diagnosis Verify)'; pptx.title='ADV 소개 v9.15';

function base(slide, num, eyebrowText){
  slide.background = { color: NAVY };
  slide.addShape(pptx.ShapeType.rect, { x:0, y:0, w:0.1, h:H, fill:{ color:SKY } });
  slide.addText('■ ADV', { x:0.55, y:0.3, w:3, h:0.3, fontFace:MONO, fontSize:11, color:MUTED, charSpacing:2 });
  slide.addText(`${String(num).padStart(2,'0')} / 09`, { x:W-2, y:0.3, w:1.6, h:0.3, fontFace:MONO, fontSize:10, color:FAINT, align:'right' });
  if (eyebrowText) slide.addText(eyebrowText.toUpperCase(), { x:0.6, y:0.95, w:11.5, h:0.35, fontFace:MONO, fontSize:12, color:SKY, charSpacing:3 });
}
function h2(slide, t){ slide.addText(t, { x:0.6, y:1.35, w:12, h:0.9, fontFace:FONT, fontSize:34, bold:true, color:FG }); }

function card(slide, x, y, w, h, accent, tag, title, body){
  slide.addShape(pptx.ShapeType.roundRect, { x, y, w, h, rectRadius:0.09, fill:{ color:PANEL }, line:{ color:LINE, width:1 } });
  slide.addShape(pptx.ShapeType.rect, { x, y, w, h:0.06, fill:{ color:accent } });
  let ty = y + 0.28;
  if (tag){ slide.addText(tag.toUpperCase(), { x:x+0.3, y:ty, w:w-0.6, h:0.25, fontFace:MONO, fontSize:9, color:FAINT, charSpacing:2 }); ty += 0.32; }
  slide.addText(title, { x:x+0.3, y:ty, w:w-0.6, h:0.45, fontFace:FONT, fontSize:17, bold:true, color:FG }); ty += 0.55;
  slide.addText(body, { x:x+0.3, y:ty, w:w-0.6, h:h-(ty-y)-0.25, fontFace:FONT, fontSize:11.5, color:MUTED, valign:'top', lineSpacingMultiple:1.15 });
}

/* 1 · 표지 */
let s = pptx.addSlide(); base(s, 1);
s.addShape(pptx.ShapeType.rect, { x:0, y:0, w:0.1, h:H, fill:{ color:SKY } });
s.addText('AIR-GAPPED · ON-PREM · AI DIAGNOSIS VERIFY', { x:0.6, y:2.1, w:12, h:0.4, fontFace:MONO, fontSize:13, color:SKY, charSpacing:3 });
s.addText('ADV', { x:0.55, y:2.5, w:12, h:1.6, fontFace:FONT, fontSize:96, bold:true, color:FG });
s.addText('AI Diagnosis Verify', { x:0.6, y:4.15, w:12, h:0.9, fontFace:FONT, fontSize:40, bold:true, color:SKY });
s.addText([
  { text:'취약점 점검 결과를 ', options:{ color:MUTED } },
  { text:'AI·규칙으로 판정', options:{ color:FG, bold:true } },
  { text:'하고, 국내 컴플라이언스 양식 ', options:{ color:MUTED } },
  { text:'리포트', options:{ color:FG, bold:true } },
  { text:'까지 — 외부 클라우드 없이, 폐쇄망에서.', options:{ color:SKY } },
], { x:0.6, y:5.2, w:11.5, h:0.9, fontFace:FONT, fontSize:18 });
s.addText('SecuMS Diagnosis Verification · v9.15', { x:0.6, y:6.7, w:12, h:0.3, fontFace:MONO, fontSize:11, color:FAINT });

/* 2 · 문제 */
s = pptx.addSlide(); base(s, 2, 'The Gap');
s.addText([
  { text:'클라우드 AI를 반입할 수 없는 ', options:{ color:FG } },
  { text:'폐쇄망', options:{ color:SKY } },
  { text:'.\n취약점 판정은 여전히 ', options:{ color:FG } },
  { text:'사람 손', options:{ color:BAD } },
  { text:'.', options:{ color:FG } },
], { x:0.6, y:1.5, w:12, h:2, fontFace:FONT, fontSize:38, bold:true, lineSpacingMultiple:1.1 });
s.addText('금융·공공은 망분리가 의무이고 클라우드 AI 호출이 금지됩니다. 점검 결과 수천 줄을 분석가가 일일이 취약/양호로 판정하고, 제출 양식까지 수작업으로 맞춥니다.',
  { x:0.6, y:3.9, w:11.5, h:1.2, fontFace:FONT, fontSize:17, color:MUTED, lineSpacingMultiple:1.3 });
s.addText([
  { text:'ADV는 ', options:{ color:FG } },
  { text:'사내 로컬 판정', options:{ color:SKY } },
  { text:'으로 이 공백을 메웁니다.', options:{ color:FG } },
], { x:0.6, y:5.3, w:12, h:0.7, fontFace:FONT, fontSize:24, bold:true });

/* 3 · 3 강점 */
s = pptx.addSlide(); base(s, 3, 'Why ADV — 3 Strengths'); h2(s, '3가지 강점');
const cw=3.85, cx0=0.6, cy=2.5, ch=3.6, gap=0.25;
card(s, cx0, cy, cw, ch, SKY, 'Air-gapped', '망분리에서 돈다',
  '판정을 사내 로컬 LLM·결정적 규칙으로 수행 — 외부 API 호출 0. 클라우드 AI가 못 들어오는 폐쇄망에서 그대로 사용.');
card(s, cx0+(cw+gap), cy, cw, ch, GOOD, 'Our know-how', '판정 지능이 우리 것',
  '수집/판정 분리 — 스크립트는 값만 긁고, 취약 판정은 축적된 노하우 규칙(KISA·AD 기준 코드화)이 소유·확장.');
card(s, cx0+2*(cw+gap), cy, cw, ch, INDIGO, 'Compliance-ready', '제출용 산출물 즉시',
  '국내 양식(FSI·금보원·삼성) 리포트 + SecuMS 대비 3-way 정합성. 판정·문서화 공수 대폭 절감.');
s.addText('클라우드 못 쓰는 폐쇄망에서 · 우리 노하우로 판정하고 · 국내 양식 리포트까지 자동',
  { x:0.6, y:6.4, w:12, h:0.3, fontFace:MONO, fontSize:11, color:FAINT });

/* 4 · 핵심 기능 */
s = pptx.addSlide(); base(s, 4, 'Core Features'); h2(s, '핵심 기능');
card(s, cx0, cy, cw, ch, SKY, 'Offline', '결과 판정·리포트',
  '스크립트 결과물(파일·붙여넣기)을 올리면 → 항목별 취약/양호 판정 → 리포트(HTML·XLSX·인쇄 PDF). 원격 접속 불필요.');
card(s, cx0+(cw+gap), cy, cw, ch, BLUE, 'Remote', '자율 진단 에이전트',
  '자연어→스크립트 생성 또는 직접 업로드 → WinRM/SSH 원격 실행 → 수집 → 판정 → 리포트까지 한 흐름.');
card(s, cx0+2*(cw+gap), cy, cw, ch, INDIGO, 'Trust', '3-way 정합성 검증',
  'SecuMS(정답지)·AI·LLM 3소스 교차검증으로 신뢰도 확보. 불일치·검토필요 항목은 사람이 확정.');

/* 5 · 동작 흐름 */
s = pptx.addSlide(); base(s, 5, 'How It Works'); h2(s, '수집 → 판정 → 리포트');
const fw=3.7, fy=2.7, fh=2.6; const fxs=[0.6, 0.6+fw+0.5, 0.6+2*(fw+0.5)];
const flow=[
  ['01 · COLLECT','수집','에이전트 원격 실행(WinRM/SSH) 또는 결과물 업로드. 스크립트는 원시값만(read-only).'],
  ['02 · JUDGE','판정','전용 규칙 / mock / 사내 로컬 LLM. 외부 API 0. 취약·양호·판정불가 + 근거.'],
  ['03 · REPORT','리포트','FSI·삼성 양식 HTML·XLSX·인쇄 PDF. SecuMS 대비 정합성.'],
];
flow.forEach((f,i)=>{
  const x=fxs[i];
  s.addShape(pptx.ShapeType.roundRect,{x,y:fy,w:fw,h:fh,rectRadius:0.09,fill:{color:PANEL},line:{color:LINE,width:1}});
  s.addText(f[0],{x:x+0.28,y:fy+0.25,w:fw-0.5,h:0.3,fontFace:MONO,fontSize:11,color:SKY,charSpacing:2});
  s.addText(f[1],{x:x+0.28,y:fy+0.62,w:fw-0.5,h:0.5,fontFace:FONT,fontSize:20,bold:true,color:FG});
  s.addText(f[2],{x:x+0.28,y:fy+1.25,w:fw-0.5,h:fh-1.4,fontFace:FONT,fontSize:12,color:MUTED,valign:'top',lineSpacingMultiple:1.15});
  if(i<2) s.addText('→',{x:x+fw+0.05,y:fy+fh/2-0.35,w:0.4,h:0.6,fontSize:26,color:FAINT,align:'center'});
});
s.addText([
  { text:'수집과 판정을 분리해 — 스크립트는 서버에서 값만, ', options:{ color:MUTED } },
  { text:'판정 지능은 ADV가 소유·수정·확장', options:{ color:SKY, bold:true } },
  { text:'합니다.', options:{ color:MUTED } },
], { x:0.6, y:5.7, w:12, h:0.6, fontFace:FONT, fontSize:16 });

/* 6 · 판정 방식 3층 */
s = pptx.addSlide(); base(s, 6, 'Judgment Engine'); h2(s, '판정 방식 — 3층');
const rows=[
  ['1','전용 evaluator (결정적 규칙)','노하우를 코드화. 최고 정확·일관(예: AD 20여 항목 evaluateAdDc). 반복·중요 형식에 사용.',SKY],
  ['2','mock 시그니처','흔한 위험 패턴 자동 탐지. 코딩 없이 기본 판정.',BLUE],
  ['3','로컬 LLM + 자연어 지침','임의 스크립트를 지침대로 판정. 코딩 0, 사내 LLM(LSAP)로 망분리 유지.',INDIGO],
];
rows.forEach((r,i)=>{
  const y=2.5+i*1.15;
  s.addShape(pptx.ShapeType.roundRect,{x:0.6,y,w:0.7,h:0.7,rectRadius:0.1,fill:{color:r[3]}});
  s.addText(r[0],{x:0.6,y,w:0.7,h:0.7,fontFace:MONO,fontSize:22,bold:true,color:NAVY,align:'center',valign:'middle'});
  s.addText(r[1],{x:1.5,y:y-0.02,w:10.8,h:0.4,fontFace:FONT,fontSize:17,bold:true,color:FG});
  s.addText(r[2],{x:1.5,y:y+0.38,w:10.8,h:0.6,fontFace:FONT,fontSize:12.5,color:MUTED,lineSpacingMultiple:1.1});
});
s.addText([
  { text:'핵심 반복점검은 ', options:{color:MUTED} },{ text:'전용 규칙', options:{color:SKY,bold:true} },
  { text:', 나머지는 ', options:{color:MUTED} },{ text:'LLM+지침', options:{color:SKY,bold:true} },
  { text:' — 필요에 따라 evaluator로 승격·확장.', options:{color:MUTED} },
], { x:0.6, y:6.2, w:12, h:0.5, fontFace:FONT, fontSize:15 });

/* 7 · 지원 대상 */
s = pptx.addSlide(); base(s, 7, 'Coverage'); h2(s, '지원 대상');
const chips=['Windows · WinRM 5985','Linux · SSH 22','DB · MSSQL/MySQL/Oracle','AD · 도메인 컨트롤러'];
let chx=0.6; chips.forEach(c=>{ const cwid=0.55+c.length*0.115;
  s.addShape(pptx.ShapeType.roundRect,{x:chx,y:2.5,w:cwid,h:0.55,rectRadius:0.27,fill:{color:PANEL},line:{color:LINE,width:1}});
  s.addText(c,{x:chx,y:2.5,w:cwid,h:0.55,fontFace:FONT,fontSize:13,bold:true,color:FG,align:'center',valign:'middle'}); chx+=cwid+0.2; });
card(s, 0.6, 3.4, 5.9, 2.6, SKY, 'Collect', '원격 자동 · 오프라인 병행',
  'WinRM/SSH 원격 자동 수집, 또는 결과물 업로드(오프라인). AD DC는 로컬 실행 + 오프라인 판정 권장.');
card(s, 6.75, 3.4, 5.98, 2.6, GOOD, 'Deploy', '설치 간단 — MySQL 불필요',
  'mock 모드(로컬 JSON)로 MySQL 없이 즉시 실행. 다중사용자·영속이 필요할 때만 MySQL(선택).');

/* 8 · 경쟁 우위 */
s = pptx.addSlide(); base(s, 8, 'Competitive Edge');
s.addText([
  { text:'클라우드 AI는 폐쇄망에 ', options:{color:FG} },{ text:'못 들어온다.', options:{color:BAD} },
  { text:'\n그게 ADV의 영역이다.', options:{color:SKY} },
], { x:0.6, y:1.4, w:12, h:1.7, fontFace:FONT, fontSize:36, bold:true, lineSpacingMultiple:1.1 });
const edges=[
  ['망분리 로컬 판정','경쟁 클라우드 AI 도구가 진입 불가한 금융·공공 폐쇄망을 정조준.'],
  ['노하우 판정규칙 = 모방 어려운 자산','수집/판정 분리로 규칙을 우리가 소유. LLM 의존 도구보다 정확·일관.'],
  ['국내 산출물 내재화','FSI·금보원·삼성 양식 + 정합성 — 점검 실무의 마지막 1마일까지 자동.'],
];
edges.forEach((e,i)=>{ const y=3.4+i*1.1;
  s.addShape(pptx.ShapeType.roundRect,{x:0.6,y,w:0.55,h:0.55,rectRadius:0.1,fill:{color:SKY}});
  s.addText('✓',{x:0.6,y,w:0.55,h:0.55,fontFace:FONT,fontSize:20,bold:true,color:NAVY,align:'center',valign:'middle'});
  s.addText([{text:e[0]+'  ',options:{color:FG,bold:true}},{text:e[1],options:{color:MUTED}}],
    {x:1.35,y:y+0.02,w:11,h:0.55,fontFace:FONT,fontSize:14.5,valign:'middle'});
});

/* 9 · 요약 */
s = pptx.addSlide(); base(s, 9, 'In Short');
s.addText('폐쇄망에서, 우리 노하우로,\n판정부터 리포트까지.',
  { x:0.6, y:1.4, w:12, h:1.7, fontFace:FONT, fontSize:38, bold:true, color:SKY, lineSpacingMultiple:1.05 });
const sum=[['망분리','외부 API 0 · 사내 로컬 LLM·규칙',SKY],['노하우 판정','수집/판정 분리 · 규칙 소유·확장',GOOD],['국내 산출물','FSI·금보원·삼성 + 3-way 정합성',INDIGO]];
sum.forEach((c,i)=>{ const x=0.6+i*(cw+gap);
  s.addShape(pptx.ShapeType.roundRect,{x,y:3.5,w:cw,h:1.7,rectRadius:0.09,fill:{color:PANEL},line:{color:LINE,width:1}});
  s.addText(c[0],{x:x+0.28,y:3.7,w:cw-0.5,h:0.5,fontFace:FONT,fontSize:19,bold:true,color:c[2]});
  s.addText(c[1],{x:x+0.28,y:4.25,w:cw-0.5,h:0.8,fontFace:FONT,fontSize:12.5,color:MUTED,valign:'top',lineSpacingMultiple:1.15}); });
s.addText([
  { text:'mock 모드로 MySQL 없이 바로 실행', options:{color:SKY,bold:true} },
  { text:' · 배포 패키지(npm run build-deploy) 제공.', options:{color:MUTED} },
], { x:0.6, y:5.5, w:12, h:0.5, fontFace:FONT, fontSize:16 });
s.addText('ADV — AI Diagnosis Verify · v9.15 · SecuMS Diagnosis Verification',
  { x:0.6, y:6.8, w:12, h:0.3, fontFace:MONO, fontSize:11, color:FAINT });

const OUT = path.join(__dirname, '..', 'dist', 'ADV_소개_v9.15.pptx');
fs.mkdirSync(path.dirname(OUT), { recursive:true });
pptx.writeFile({ fileName: OUT }).then(f=>{
  const mb=(fs.statSync(OUT).size/1024/1024).toFixed(2);
  console.log(`✅ PPTX 생성: ${OUT} (${mb} MB, 9슬라이드)`);
}).catch(e=>{ console.error('생성 실패:', e.message); process.exit(1); });

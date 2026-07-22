'use strict';
/**
 * ADV 소개 PPTX — dist/ADV_소개_v9.15.pptx (편집 가능). 검증(3-way) 중심.
 * 사용:  npm run build-pptx
 */
const pptxgen = require('pptxgenjs');
const path = require('path');
const fs = require('fs');

const NAVY='0F172A', PANEL='16233F', LINE='26375C', FG='EAF1FB', MUTED='9FB2D4',
      FAINT='6F83A8', SKY='38BDF8', BLUE='3B82F6', INDIGO='6366F1', GOOD='10B981', BAD='F43F5E', WARN='F59E0B';
const FONT='Malgun Gothic', MONO='Consolas';
const W=13.33, H=7.5;

const pptx = new pptxgen();
pptx.defineLayout({ name:'ADV', width:W, height:H }); pptx.layout='ADV';
pptx.author='ADV'; pptx.company='ADV'; pptx.title='ADV 소개 v9.15 — 정합성 자동 검증';

function base(s, num, eb){
  s.background={color:NAVY};
  s.addShape(pptx.ShapeType.rect,{x:0,y:0,w:0.1,h:H,fill:{color:SKY}});
  s.addText('■ ADV',{x:0.55,y:0.3,w:3,h:0.3,fontFace:MONO,fontSize:11,color:MUTED,charSpacing:2});
  s.addText(`${String(num).padStart(2,'0')} / 08`,{x:W-2,y:0.3,w:1.6,h:0.3,fontFace:MONO,fontSize:10,color:FAINT,align:'right'});
  if(eb) s.addText(eb.toUpperCase(),{x:0.6,y:0.95,w:11.5,h:0.35,fontFace:MONO,fontSize:12,color:SKY,charSpacing:3});
}
function h2(s,t){ s.addText(t,{x:0.6,y:1.35,w:12.2,h:0.9,fontFace:FONT,fontSize:32,bold:true,color:FG}); }
function card(s,x,y,w,h,accent,tag,title,body){
  s.addShape(pptx.ShapeType.roundRect,{x,y,w,h,rectRadius:0.09,fill:{color:PANEL},line:{color:LINE,width:1}});
  s.addShape(pptx.ShapeType.rect,{x,y,w,h:0.06,fill:{color:accent}});
  let ty=y+0.28;
  if(tag){s.addText(tag.toUpperCase(),{x:x+0.3,y:ty,w:w-0.6,h:0.25,fontFace:MONO,fontSize:9,color:FAINT,charSpacing:2});ty+=0.32;}
  s.addText(title,{x:x+0.3,y:ty,w:w-0.6,h:0.5,fontFace:FONT,fontSize:16,bold:true,color:FG});ty+=0.55;
  s.addText(body,{x:x+0.3,y:ty,w:w-0.6,h:h-(ty-y)-0.25,fontFace:FONT,fontSize:11,color:MUTED,valign:'top',lineSpacingMultiple:1.15});
}
function pill(s,x,y,w,txt,color){
  s.addShape(pptx.ShapeType.roundRect,{x,y,w,h:0.5,rectRadius:0.25,fill:{color:PANEL},line:{color:color,width:1}});
  s.addText(txt,{x,y,w,h:0.5,fontFace:MONO,fontSize:12,bold:true,color:color,align:'center',valign:'middle'});
}

/* 1 표지 */
let s=pptx.addSlide(); base(s,1);
s.addText('AIR-GAPPED · VERIFICATION SOLUTION',{x:0.6,y:2.0,w:12,h:0.4,fontFace:MONO,fontSize:13,color:SKY,charSpacing:3});
s.addText('AI Diagnosis Verify',{x:0.55,y:2.4,w:12.3,h:1.6,fontFace:FONT,fontSize:66,bold:true,color:FG});
s.addText('취약점 진단 결과의 정합성 자동 검증',{x:0.6,y:3.95,w:12,h:0.7,fontFace:FONT,fontSize:30,bold:true,color:SKY});
s.addText([
  {text:'핵심 = ',options:{color:MUTED}},{text:'SecuMS·AI·LLM 3-way 정합성 검증',options:{color:FG,bold:true}},
  {text:' — 판정 신뢰도를 만들고 감사에 대응합니다.',options:{color:MUTED}},
],{x:0.6,y:5.0,w:11.8,h:0.8,fontFace:FONT,fontSize:18});
s.addText('금융보안원 전자금융기반시설 2026 OS 점검 기준 · 망분리 · v9.15',{x:0.6,y:6.7,w:12,h:0.3,fontFace:MONO,fontSize:11,color:FAINT});

/* 2 왜 검증 */
s=pptx.addSlide(); base(s,2,'Why Verify');
s.addText([{text:'자동 진단·AI 판정, ',options:{color:FG}},{text:'그대로 믿어도 되나?',options:{color:BAD}}],
  {x:0.6,y:1.4,w:12,h:1,fontFace:FONT,fontSize:36,bold:true});
s.addText('SecuMS 같은 자동 진단과 AI 판정에는 오탐·과탐·판정 근거 부족이 섞입니다. 감사·제출에서 "이 취약/양호가 맞는가"에 대한 책임이 남습니다. ADV는 판정을 한 번 더 검증합니다 — 서로 다른 소스를 교차 대조해 신뢰도를 만들고 불일치만 사람이 확정.',
  {x:0.6,y:2.5,w:11.7,h:1.6,fontFace:FONT,fontSize:16,color:MUTED,lineSpacingMultiple:1.35});
s.addText('정량 근거',{x:0.6,y:4.4,w:3,h:0.3,fontFace:MONO,fontSize:12,color:FAINT,charSpacing:2});
pill(s,0.6,4.75,3.6,'룰만 판정불가 61%',WARN);
s.addText('→',{x:4.35,y:4.75,w:0.5,h:0.5,fontSize:22,color:FAINT,align:'center',valign:'middle'});
pill(s,4.95,4.75,3.4,'AI 적용 후 1.5%',GOOD);
s.addText('"AI 없이는 자동 진단 불가"의 실측 (script N/A: Linux 16→2 · Windows 20→0)',
  {x:0.6,y:5.5,w:11.7,h:0.5,fontFace:FONT,fontSize:14,color:MUTED});

/* 3 핵심: 3-way */
s=pptx.addSlide(); base(s,3,'Core · The Product');
s.addText([{text:'3-way 정합성 검증  ',options:{color:FG}},{text:'CORE',options:{color:SKY,fontFace:MONO,fontSize:16}}],
  {x:0.6,y:1.35,w:12,h:0.8,fontFace:FONT,fontSize:32,bold:true});
// 좌: 설명 카드
s.addShape(pptx.ShapeType.roundRect,{x:0.6,y:2.4,w:7.4,h:3.9,rectRadius:0.12,fill:{color:PANEL},line:{color:SKY,width:2}});
s.addText('SecuMS(정답지) · AI 진단 · LLM 재검토 — 세 소스의 판정을 항목별로 대조합니다.',
  {x:0.9,y:2.65,w:6.8,h:0.7,fontFace:FONT,fontSize:15,bold:true,color:FG,lineSpacingMultiple:1.2});
const jl=[['일치 → 신뢰·확정',GOOD],['불일치 → 오탐/과탐 후보 (사람 검토)',BAD],['검토필요 → AI 추론 보완',WARN]];
jl.forEach((j,i)=>{ s.addText('●',{x:0.95,y:3.5+i*0.42,w:0.3,h:0.35,fontSize:12,color:j[1]});
  s.addText(j[0],{x:1.3,y:3.5+i*0.42,w:6.4,h:0.35,fontFace:FONT,fontSize:13.5,color:FG}); });
s.addText([{text:'결과물 = ',options:{color:MUTED}},{text:'3-way 리포트',options:{color:SKY,bold:true}},
  {text:' (일치율·불일치·검토필요 정리한 검증 산출물)',options:{color:MUTED}}],
  {x:0.95,y:4.9,w:6.8,h:0.5,fontFace:FONT,fontSize:13});
// 실측 배지
s.addShape(pptx.ShapeType.roundRect,{x:0.95,y:5.5,w:3.2,h:0.55,rectRadius:0.1,fill:{color:'12362B'},line:{color:GOOD,width:1}});
s.addText('SecuMS-AI 84.5%',{x:0.95,y:5.5,w:3.2,h:0.55,fontFace:MONO,fontSize:13,bold:true,color:GOOD,align:'center',valign:'middle'});
s.addShape(pptx.ShapeType.roundRect,{x:4.3,y:5.5,w:3.0,h:0.55,rectRadius:0.1,fill:{color:'12362B'},line:{color:GOOD,width:1}});
s.addText('Script-AI 88.3%',{x:4.3,y:5.5,w:3.0,h:0.55,fontFace:MONO,fontSize:13,bold:true,color:GOOD,align:'center',valign:'middle'});
// 우: 3소스 스택
const sx=8.35, sw=4.3;
const stack=[['SecuMS','기존 진단 = 정답지',GOOD],['AI','독립 재판정',SKY],['LLM','교차 검증',INDIGO]];
stack.forEach((c,i)=>{ const y=2.5+i*1.0;
  s.addShape(pptx.ShapeType.roundRect,{x:sx,y,w:sw,h:0.8,rectRadius:0.1,fill:{color:PANEL},line:{color:LINE,width:1}});
  s.addText(c[0],{x:sx+0.25,y:y+0.1,w:sw-0.5,h:0.35,fontFace:FONT,fontSize:16,bold:true,color:c[2]});
  s.addText(c[1],{x:sx+0.25,y:y+0.45,w:sw-0.5,h:0.28,fontFace:FONT,fontSize:11,color:MUTED});
  if(i<2) s.addText('＋',{x:sx+sw/2-0.2,y:y+0.78,w:0.4,h:0.25,fontSize:12,color:FAINT,align:'center'});
});
s.addShape(pptx.ShapeType.roundRect,{x:sx,y:5.55,w:sw,h:0.75,rectRadius:0.1,fill:{color:'0E2A44'},line:{color:SKY,width:2}});
s.addText('▼ 정합성 판정',{x:sx+0.25,y:5.65,w:sw-0.5,h:0.3,fontFace:FONT,fontSize:15,bold:true,color:SKY});
s.addText('일치 · 불일치 · 검토필요',{x:sx+0.25,y:5.98,w:sw-0.5,h:0.28,fontFace:FONT,fontSize:11,color:MUTED});

/* 4 검증 산출물 */
s=pptx.addSlide(); base(s,4,'Core Output'); h2(s,'검증 산출물 — 3-way 리포트');
const out=[
  ['정합성 요약','비교가능 항목 대비 일치율, 소스별 판정(SecuMS/AI/LLM) 나란히.'],
  ['불일치·검토필요 목록','실제 오탐/과탐 후보를 추려 사람이 확정 → 감사·제출 신뢰성.'],
  ['제출 양식','금융보안원 2026 기준 · 리포트1/2/타사 + XLSX·인쇄 PDF.'],
];
out.forEach((o,i)=>{ const y=2.5+i*1.05;
  s.addShape(pptx.ShapeType.roundRect,{x:0.6,y,w:0.55,h:0.55,rectRadius:0.1,fill:{color:SKY}});
  s.addText('✓',{x:0.6,y,w:0.55,h:0.55,fontFace:FONT,fontSize:20,bold:true,color:NAVY,align:'center',valign:'middle'});
  s.addText([{text:o[0]+'   ',options:{color:FG,bold:true}},{text:o[1],options:{color:MUTED}}],
    {x:1.35,y:y+0.02,w:11,h:0.55,fontFace:FONT,fontSize:15,valign:'middle'});
});
s.addText('화면: /reports/:id/threeway · /report3 — 판정을 "검증된 결과"로 만든다.',
  {x:0.6,y:6.0,w:12,h:0.4,fontFace:MONO,fontSize:12,color:SKY});

/* 5 부가 기능 */
s=pptx.addSlide(); base(s,5,'Supporting · Judgment Sources'); h2(s,'부가 기능 — 판정 소스 확보 (망분리 대비)');
s.addText('정답지가 없거나 폐쇄망일 때, 자체 판정 소스를 만들어 검증에 투입하거나 단독 점검.',
  {x:0.6,y:2.25,w:12,h:0.4,fontFace:FONT,fontSize:14,color:MUTED});
const cw=3.85, gap=0.25, cy=2.85, ch=3.1;
card(s,0.6,cy,cw,ch,BLUE,'A · Agent','자연어→스크립트·실행','자연어로 점검 스크립트 생성 또는 직접 업로드 → WinRM/SSH 원격 실행 → 판정. (사람 게이트 2개)');
card(s,0.6+cw+gap,cy,cw,ch,SKY,'B · Script','스크립트 업로드 점검','보유한 점검 스크립트(ps1/sh)를 올려 대상에서 실행·수집·판정.');
card(s,0.6+2*(cw+gap),cy,cw,ch,INDIGO,'C · Offline','결과 파일 → 판정·리포트','이미 수집한 결과물을 올리면 판정 + 리포트. 원격 불필요(오프라인).');
s.addText('→ 이 판정들이 3-way 검증의 "AI/LLM 소스"로 들어간다',
  {x:0.6,y:6.2,w:12,h:0.3,fontFace:MONO,fontSize:11,color:FAINT});

/* 6 판정 방식 + 망분리 */
s=pptx.addSlide(); base(s,6,'Engine · Air-gapped'); h2(s,'판정 방식 · 망분리');
const rows=[['1','전용 규칙 evaluator','노하우 코드화 — 결정적·최고정확(예: AD 20여 항목).',SKY],
  ['2','mock 시그니처','흔한 위험 패턴 자동 탐지.',BLUE],
  ['3','로컬 LLM + 자연어 지침','임의 스크립트 판정. 사내 LLM(qwen, 무료).',INDIGO]];
rows.forEach((r,i)=>{ const y=2.4+i*0.95;
  s.addShape(pptx.ShapeType.roundRect,{x:0.6,y,w:0.6,h:0.6,rectRadius:0.1,fill:{color:r[3]}});
  s.addText(r[0],{x:0.6,y,w:0.6,h:0.6,fontFace:MONO,fontSize:20,bold:true,color:NAVY,align:'center',valign:'middle'});
  s.addText(r[1],{x:1.4,y:y-0.02,w:10.8,h:0.38,fontFace:FONT,fontSize:16,bold:true,color:FG});
  s.addText(r[2],{x:1.4,y:y+0.34,w:10.8,h:0.3,fontFace:FONT,fontSize:12,color:MUTED}); });
s.addShape(pptx.ShapeType.roundRect,{x:0.6,y:5.4,w:12.1,h:1.0,rectRadius:0.1,fill:{color:'0E2A44'},line:{color:SKY,width:2}});
s.addText([{text:'검증·판정 전부 사내 로컬 — 외부 클라우드 API 호출 0. ',options:{color:SKY,bold:true}},
  {text:'수집/판정 분리로 판정 지능(노하우 규칙)은 ADV가 소유·확장.',options:{color:MUTED}}],
  {x:0.9,y:5.55,w:11.5,h:0.7,fontFace:FONT,fontSize:15,valign:'middle',lineSpacingMultiple:1.2});

/* 7 지원/배포/성과 */
s=pptx.addSlide(); base(s,7,'Coverage · Deploy'); h2(s,'지원 대상 · 성과 · 배포');
const chips=['Windows·WinRM','Linux·SSH','DB·MSSQL/MySQL/Oracle','AD·DC'];
let chx=0.6; chips.forEach(c=>{ const cwid=0.5+c.length*0.13;
  s.addShape(pptx.ShapeType.roundRect,{x:chx,y:2.35,w:cwid,h:0.5,rectRadius:0.25,fill:{color:PANEL},line:{color:LINE,width:1}});
  s.addText(c,{x:chx,y:2.35,w:cwid,h:0.5,fontFace:FONT,fontSize:12,bold:true,color:FG,align:'center',valign:'middle'}); chx+=cwid+0.2; });
card(s,0.6,3.2,5.9,1.5,GOOD,'성과','자동 판정률 · CVE','룰 N/A 61%→AI 1.5% · CVE Linux 9/Win 5 실제 취약(KEV) · 진단 서버당 수 분.');
card(s,6.75,3.2,5.95,1.5,SKY,'비용','사내 LLM 무료','qwen 사내 운영 — 추가 비용 0. 외부 API 미사용(망분리).');
card(s,0.6,4.9,5.9,1.5,BLUE,'Deploy','MySQL 불필요','mock 모드(로컬 JSON) 즉시 실행. 배포 패키지 npm run build-deploy.');
card(s,6.75,4.9,5.95,1.5,INDIGO,'Security','자격증명 암호화','servers.csv 비번 AES-256-GCM 자동 복호화. 키·자격증명 gitignore.');

/* 8 정리 */
s=pptx.addSlide(); base(s,8,'In Short');
s.addText('판정하는 도구가 아니라,\n판정을 검증하는 솔루션.',
  {x:0.6,y:1.35,w:12,h:1.6,fontFace:FONT,fontSize:36,bold:true,color:SKY,lineSpacingMultiple:1.05});
const fin=[['주','3-way 정합성 검증(리포트)','SecuMS·AI·LLM 교차로 판정 신뢰도 확보. 실측 84.5/88.3%.',SKY],
  ['부','판정 소스 확보','자연어→스크립트·실행 / 스크립트 업로드 / 결과파일 판정·리포트(망분리 대비).',BLUE],
  ['기반','망분리 로컬 판정 + 노하우 규칙','외부 API 0 · 금융보안원 2026 기준 산출물.',INDIGO]];
fin.forEach((f,i)=>{ const y=3.4+i*1.0;
  s.addShape(pptx.ShapeType.roundRect,{x:0.6,y,w:0.75,h:0.7,rectRadius:0.1,fill:{color:f[3]}});
  s.addText(f[0],{x:0.6,y,w:0.75,h:0.7,fontFace:FONT,fontSize:15,bold:true,color:NAVY,align:'center',valign:'middle'});
  s.addText([{text:f[1]+'   ',options:{color:FG,bold:true}},{text:f[2],options:{color:MUTED}}],
    {x:1.55,y:y+0.02,w:11,h:0.7,fontFace:FONT,fontSize:14,valign:'middle',lineSpacingMultiple:1.1}); });
s.addText('ADV — AI Diagnosis Verify · v9.15 · SecuMS 정합성 자동 검증',
  {x:0.6,y:6.85,w:12,h:0.3,fontFace:MONO,fontSize:11,color:FAINT});

const OUT=path.join(__dirname,'..','dist','ADV_소개_v9.15.pptx');
fs.mkdirSync(path.dirname(OUT),{recursive:true});
pptx.writeFile({fileName:OUT}).then(()=>{ const mb=(fs.statSync(OUT).size/1024/1024).toFixed(2);
  console.log(`✅ PPTX 생성: ${OUT} (${mb} MB, 8슬라이드 · 검증 중심)`);
}).catch(e=>{console.error('실패:',e.message);process.exit(1);});

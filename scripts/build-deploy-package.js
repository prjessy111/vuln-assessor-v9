'use strict';
/**
 * 배포 패키지 빌드 (화이트리스트) — 실행에 진짜 필요한 것만 dist/adv-deploy-package.zip.
 *   ★ "전부 복사 후 제외"가 아니라 "필요한 것만 포함". 데모HTML·산출물·백업폴더·*.db·docx·
 *      script-deploy/mock/uploads·리포트출력 등은 애초에 안 담음.
 * 사용:  npm run build-deploy
 */
require('../src/config');   // .env → process.env (DEPLOY_ZIP_PASSWORD)
const fs = require('fs');
const os = require('os');
const path = require('path');
const archiver = require('archiver');
const archiverZipEncrypted = require('archiver-zip-encrypted');
archiver.registerFormat('zip-encrypted', archiverZipEncrypted);

// 배포 zip 암호 — .env 의 DEPLOY_ZIP_PASSWORD 에서만 읽음(소스/웹/가이드에 노출 금지, 별도 전달).
const ZIP_PASSWORD = process.env.DEPLOY_ZIP_PASSWORD;
if (!ZIP_PASSWORD) { console.error('DEPLOY_ZIP_PASSWORD 미설정 — .env 에 설정하세요(커밋 금지).'); process.exit(1); }

const ROOT = path.resolve(__dirname, '..');
const STAGE = path.join(os.tmpdir(), 'adv-deploy-stage-' + process.pid);
const OUT = path.join(ROOT, 'dist', 'adv-deploy-package.zip');

// ── 포함 목록(화이트리스트) — 파일 또는 디렉터리 ──
const INCLUDE = [
  // 코드/진입점
  'server-mock.js', 'package.json', 'package-lock.json', 'ad_collect.ps1',
  'src', 'rules', 'scripts',
  // 판정/리포트에 필요한 설정 데이터(JSON)만 — 런타임/샘플 데이터는 제외
  'data/cve', 'data/policies',
  'data/report1-2026-checkspec.json', 'data/srv-2026-scope.json',
  'data/secums-2026-spec.json', 'data/srv-secums-crosswalk.json', 'data/srv-secums-map.json',
  // 가이드 (개인 실IP·비번 담긴 사전작업/신규서버 체크리스트는 제외 — 배포·릴리즈만)
  '배포_가이드.md', '릴리즈노트_v9.15.md',
];

// ── 디렉터리 복사 시 걸러낼 것(하위 잡동사니/민감/런타임) ──
function keep(src) {
  const b = path.basename(src);
  if (['mock-verify', 'node_modules', '.git', '.claude', '__pycache__', 'dist'].includes(b)) return false;
  if (['.env', 'fsi_config.ini'].includes(b)) return false;
  if (/^key.*\.txt$/i.test(b)) return false;
  if (/^servers\.csv/i.test(b)) return false;                       // servers.csv 및 백업
  if (/_AD_DC\.txt$/i.test(b)) return false;
  if (/\.(bak|db|sqlite|log|xlsx?|zip|mp4|png|jpe?g|gif|docx?)$/i.test(b)) return false;
  if (/\.bak-/i.test(b)) return false;
  return true;
}

fs.rmSync(STAGE, { recursive: true, force: true });
fs.mkdirSync(STAGE, { recursive: true });
fs.mkdirSync(path.join(ROOT, 'dist'), { recursive: true });

let files = 0;
for (const rel of INCLUDE) {
  const abs = path.join(ROOT, rel);
  if (!fs.existsSync(abs)) { console.warn('  (건너뜀, 없음)', rel); continue; }
  const dest = path.join(STAGE, rel);
  const st = fs.statSync(abs);
  if (st.isDirectory()) {
    fs.cpSync(abs, dest, { recursive: true, filter: (s) => keep(s) });
  } else {
    if (!keep(abs)) continue;
    fs.mkdirSync(path.dirname(dest), { recursive: true });
    fs.copyFileSync(abs, dest);
  }
  files++;
}

// 템플릿(.env.example / servers.csv.example)
// .env.example — 로컬 LLM 연동 전용 템플릿(외부 Claude 참조 없음). 값은 받는 쪽에서 채움.
fs.writeFileSync(path.join(STAGE, '.env.example'), [
  '# ADV 환경설정 예시 — 값 채운 뒤 .env 로 저장(커밋 금지)',
  'DB_MODE=mock                 # mock(MySQL 불필요, 기본) 또는 mysql',
  '# 비번 암호화 키(base64 32B): node -e "console.log(require(\'./src/util/crypto\').generateMasterKey())"',
  'ENCRYPTION_KEY=',
  '',
  '# ── 사내 로컬 LLM (OpenAI 호환 게이트웨이) — 판정에 사용 ──',
  'LLM_PROVIDER=openai',
  'LLM_ENDPOINT=            # 사내 LLM 게이트웨이 URL',
  'LLM_API_KEY=             # 사내 LLM 키',
  'LLM_MODEL=qwen3.5-122b-fast',
  '# (외부 클라우드 미사용 — 망분리. 위 사내 LLM 만 연동)',
].join('\n') + '\n', 'utf8');
fs.writeFileSync(path.join(STAGE, 'servers.csv.example'),
  '# hostname,ip,os,username,password[,asset_no][,server_id]\n' +
  'web-01,10.10.20.5,linux,root,PLAINTEXT_PW,SVR-2026-0001,1\n', 'utf8');

// 암호화 zip 생성 (비번=.env DEPLOY_ZIP_PASSWORD, ZipCrypto — 7-Zip/WinRAR 등으로 해제)
if (fs.existsSync(OUT)) fs.rmSync(OUT);
(async () => {
  await new Promise((resolve, reject) => {
    const out = fs.createWriteStream(OUT);
    const arch = archiver('zip-encrypted', { zlib: { level: 8 }, encryptionMethod: 'zip20', password: ZIP_PASSWORD });
    out.on('close', resolve); arch.on('error', reject);
    arch.pipe(out);
    arch.directory(STAGE + path.sep, false);
    arch.finalize();
  });
  fs.rmSync(STAGE, { recursive: true, force: true });
  const mb = (fs.statSync(OUT).size / 1024 / 1024).toFixed(2);
  console.log(`\n✅ 배포 패키지: ${OUT} (${mb} MB, 포함 항목 ${files}개 그룹)`);
  console.log('   🔒 암호 설정됨(.env DEPLOY_ZIP_PASSWORD) — 풀 때 동일, 7-Zip/WinRAR 등으로 해제');
  console.log('   포함: 코드(src·server-mock)·rules·scripts(테스트 제외)·설정JSON·가이드 + .env.example/servers.csv.example');
  console.log('   제외: node_modules·데모HTML·산출물·백업폴더·*.db/xlsx/docx/png·mock/uploads/script-deploy·.env·key*.txt·servers.csv');
})().catch(e => { console.error('zip 생성 실패:', e.message); process.exit(1); });

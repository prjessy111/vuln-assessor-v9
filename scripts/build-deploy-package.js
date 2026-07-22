'use strict';
/**
 * 배포 패키지 빌드 — 민감파일 제외한 소스를 dist/adv-deploy-package.zip 으로 압축.
 *   포함: 코드(src, server-mock.js), package.json, rules, data/policies·cve·scope,
 *         scripts, ad_collect.ps1, 가이드 MD, .env.example(템플릿).
 *   제외: node_modules, .git, dist, .env, key*.txt, servers.csv(+백업), data/mock·uploads,
 *         *.xlsx/*.png/*.zip/*.bak, fsi_config.ini, *_AD_DC.txt, result/powershell/info*.txt.
 * 사용:  npm run build-deploy   (Windows PowerShell Compress-Archive 사용)
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const ROOT = path.resolve(__dirname, '..');
// 스테이징은 ROOT 밖(임시폴더)에 — ROOT 내부로 복사하면 fs.cpSync 가 ERR_FS_CP_EINVAL.
const STAGE = path.join(os.tmpdir(), 'adv-deploy-stage-' + process.pid);
const OUT = path.join(ROOT, 'dist', 'adv-deploy-package.zip');

// 제외 규칙 (경로 조각/확장자)
const EXCLUDE_DIR = new Set(['node_modules', '.git', 'dist', '.claude']);
const EXCLUDE_NAME = new Set(['.env', 'servers.csv', 'fsi_config.ini', 'result.txt', 'powershell.txt']);
const EXCLUDE_RE = [
  /^key.*\.txt$/i, /\.xlsx$/i, /\.(png|jpe?g|gif|bmp)$/i, /\.zip$/i, /\.bak$/i,
  /_AD_DC\.txt$/i, /^info.*\.txt$/i, /\.mp4$/i, /\.log$/i, /^servers\.csv\./i,
];
function excluded(name) {
  if (EXCLUDE_DIR.has(name) || EXCLUDE_NAME.has(name)) return true;
  return EXCLUDE_RE.some(re => re.test(name));
}

// 정리 후 스테이징 복사
fs.rmSync(STAGE, { recursive: true, force: true });
fs.mkdirSync(STAGE, { recursive: true });
fs.mkdirSync(path.join(ROOT, 'dist'), { recursive: true });

let copied = 0;
fs.cpSync(ROOT, STAGE, {
  recursive: true,
  filter: (src) => {
    if (src === ROOT) return true;
    const rel = path.relative(ROOT, src);
    if (!rel || rel.startsWith('dist')) return false;
    const base = path.basename(src);
    if (excluded(base)) return false;
    // data 하위: mock·uploads·raw 제외(런타임/민감), policies·cve·scope 만 허용
    if (rel === 'data' ) return true;
    if (rel.startsWith('data' + path.sep)) {
      const seg = rel.split(path.sep)[1];
      if (['mock', 'uploads', 'raw', 'agent-credentials.json'].includes(seg)) return false;
    }
    if (!src.includes('.') || fs.statSync(src).isFile()) copied++;
    return true;
  },
});

// .env.example 템플릿 생성(비밀값 비움)
const envExample = [
  '# ADV 환경설정 예시 — 실제 값으로 채운 뒤 .env 로 저장 (커밋 금지)',
  '# 저장소 모드: mock(기본, MySQL 불필요) 또는 mysql',
  'DB_MODE=mock',
  '# 비번 암호화 키(base64 32B): node -e "console.log(require(\'./src/util/crypto\').generateMasterKey())"',
  'ENCRYPTION_KEY=',
  '# 사내 로컬 LLM(OpenAI 호환 게이트웨이)',
  'LLM_PROVIDER=openai',
  'LLM_ENDPOINT=https://your-lsap-gateway',
  'LLM_API_KEY=',
  'LLM_MODEL=qwen3.5-122b-fast',
  '# (선택) Claude — 외부 백엔드',
  '# CLAUDE_API_KEY=',
  '# MySQL 모드일 때만',
  '# DB_HOST=localhost',
  '# DB_USER=vuln_app',
  '# DB_PASSWORD=',
  '# DB_NAME=vuln_assessor',
].join('\n') + '\n';
fs.writeFileSync(path.join(STAGE, '.env.example'), envExample, 'utf8');

// servers.csv.example 템플릿
fs.writeFileSync(path.join(STAGE, 'servers.csv.example'),
  '# hostname,ip,os,username,password[,asset_no][,server_id]\n' +
  'web-01,10.10.20.5,linux,root,PLAINTEXT_PW,SVR-2026-0001,1\n', 'utf8');

// PowerShell Compress-Archive
execFileSync('powershell', ['-NoProfile', '-Command',
  `Compress-Archive -Path '${STAGE}\\*' -DestinationPath '${OUT}' -Force`],
  { stdio: 'inherit' });
fs.rmSync(STAGE, { recursive: true, force: true });

const mb = (fs.statSync(OUT).size / 1024 / 1024).toFixed(2);
console.log(`\n✅ 배포 패키지 생성: ${OUT} (${mb} MB)`);
console.log('   민감파일(.env·key*.txt·servers.csv·data/mock 등) 제외됨. .env.example·servers.csv.example 포함.');
console.log('   다운로드: 앱 실행 후 http://<host>:3000/download/deploy-package');

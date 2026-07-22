'use strict';
/**
 * servers.csv 비밀번호 암호화 툴 (1회/서버추가 시 실행).
 *   평문 비번(5번째 열)을 'enc:<base64>' (AES-256-GCM) 로 바꾼다.
 *   - 이미 'enc:' 인 값은 건너뜀(idempotent).
 *   - 주석(#)·빈 줄·기타 열·줄바꿈·한글 헤더 바이트 보존(latin1 read/write).
 *   - 복호화는 앱이 자동(getTargetServersFromFile). 여기선 암호화만.
 *
 * 사용:  node scripts/encrypt-servers-csv.js
 * 전제:  .env 의 ENCRYPTION_KEY (base64 32B). src/config 가 로드.
 */
require('../src/config');           // .env → process.env (ENCRYPTION_KEY)
const fs = require('fs');
const path = require('path');

const CSV = path.resolve(__dirname, '..', 'servers.csv');
if (!fs.existsSync(CSV)) { console.error('servers.csv 없음:', CSV); process.exit(1); }
if (!process.env.ENCRYPTION_KEY) { console.error('ENCRYPTION_KEY 미설정(.env 확인)'); process.exit(1); }

let encrypt;
try { ({ encrypt } = require('../src/util/crypto')); }
catch (e) { console.error('crypto 로드 실패:', e.message); process.exit(1); }

// 바이트 보존을 위해 latin1 로 읽고 쓴다(데이터 행 비번은 ASCII, 헤더 주석 바이트 유지).
const raw = fs.readFileSync(CSV, 'latin1');
const nl = raw.includes('\r\n') ? '\r\n' : '\n';
const lines = raw.split(/\r?\n/);

let changed = 0, already = 0, skipped = 0;
const out = lines.map((line) => {
  const t = line.trim();
  if (!t || t.startsWith('#')) return line;             // 주석/빈줄 보존
  const parts = line.split(',');
  if (parts.length < 5) { skipped++; return line; }      // 형식 안 맞음
  const pw = parts[4].trim();
  if (!pw) { skipped++; return line; }
  if (pw.startsWith('enc:')) { already++; return line; }  // 이미 암호화
  parts[4] = 'enc:' + encrypt(pw).toString('base64');
  changed++;
  return parts.join(',');
});

// 백업 후 저장
const bak = CSV + '.plain.bak';
fs.writeFileSync(bak, raw, 'latin1');
fs.writeFileSync(CSV, out.join(nl), 'latin1');

console.log(`✅ 완료 — 암호화 ${changed}건, 이미암호화 ${already}건, 건너뜀 ${skipped}건`);
console.log(`   백업(평문): ${bak}  ← 확인 후 안전하게 삭제 권장(.gitignore 처리됨)`);
console.log('   복호화는 앱이 자동(getTargetServersFromFile). 앱 재시작 후 점검 정상 동작 확인하세요.');

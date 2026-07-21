'use strict';
/**
 * 리눅스 원격 실행 실테스트 — jessy207(192.168.159.207)에 SSH로 `cat /etc/passwd` 실행.
 *   앱과 동일 경로: provideScript(복붙) → reviewScript(승인) → runOnTarget(실제 SSH) → 판정.
 * 실행: node scripts/mock-verify/linux-passwd-test.js
 */
const path = require('path');
const ROOT = path.resolve(__dirname, '..', '..');
const pipeline = require(path.join(ROOT, 'src/agent/pipeline.js'));
const itemRegistry = require(path.join(ROOT, 'src/agent/itemRegistry.js'));
const { getTargetServersFromFile } = require(path.join(ROOT, 'src/services/scheduler.js'));

// 인메모리 storage
const mem = {};
const storage = {
  loadSync: (k) => (k in mem ? JSON.parse(JSON.stringify(mem[k])) : null),
  saveSync: (k, v) => { mem[k] = JSON.parse(JSON.stringify(v)); return v; },
};

(async () => {
  // servers.csv 에서 207 자격증명 실시간 조회 (앱 라우트와 동일)
  const cred = (getTargetServersFromFile() || []).find(
    t => String(t.ip) === '192.168.159.207' || t.hostname === 'jessy207'
  );
  if (!cred) { console.error('servers.csv 에서 207(jessy207) 을 찾지 못했습니다.'); process.exit(1); }
  const server = {
    server_id: cred.server_id, hostname: cred.hostname, name: cred.hostname,
    ip_address: cred.ip, os_type: cred.os,
    ssh_user: cred.username, username: cred.username,
    ssh_password: cred.password, password: cred.password,
    ssh_port: 22,
  };
  console.log(`[대상] ${server.hostname} (${server.ip_address}, ${server.os_type}) 계정=${server.ssh_user}`);

  // 1) 항목 생성
  const item = itemRegistry.create(storage, {
    title: 'passwd 계정 점검', description: '/etc/passwd 계정 목록 수집', os_target: 'linux', source: 'custom',
  });
  const id = item.item_id;

  // 2) 스크립트 복붙 입력 (result_glob 없음 → stdout 캡처)
  pipeline.provideScript(storage, id, { code: 'cat /etc/passwd', by: 'tester' });
  // 3) 승인 (읽기전용 → blocked 아님)
  pipeline.reviewScript(storage, id, { decision: 'approve', by: 'tester' });

  // 4) 원격 실행 + 수집 (+판정) — 진행률 콜백 출력
  console.log('[실행] SSH 접속 → cat /etc/passwd …');
  let updated;
  try {
    updated = await pipeline.runOnTarget(storage, id, server, {
      autoJudge: true, by: 'tester',
      onProgress: (p, m) => console.log(`  [${String(p).padStart(3)}%] ${m}`),
      timeout: 30000,
    });
  } catch (e) {
    console.error('\n❌ 실행 실패:', e.message);
    process.exit(1);
  }

  const raw = updated.raw && updated.raw.output || '';
  const lines = raw.split(/\r?\n/).filter(Boolean);
  console.log(`\n✅ 수집 성공 — source=${updated.raw && updated.raw.source}`);
  console.log(`   /etc/passwd 라인 수: ${lines.length}`);
  console.log('   앞 8줄:');
  lines.slice(0, 8).forEach(l => console.log('     ' + l));
  const uid0 = lines.filter(l => l.split(':')[2] === '0');
  console.log(`   UID 0 계정: ${uid0.map(l => l.split(':')[0]).join(', ') || '(없음)'}`);

  const j = updated.judgment;
  if (j) {
    console.log(`\n[판정] verdict=${j.verdict} · model=${j.model} · findings=${(j.findings || []).length}개`);
    if (j.summary) console.log('   요약: ' + j.summary);
  } else {
    console.log('\n[판정] 없음(수집만).');
  }
})();

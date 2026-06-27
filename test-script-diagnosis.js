// test-script-diagnosis.js (v2 — MySQL 초기화 추가)
// 사용법: node test-script-diagnosis.js
require('./src/config');
const path = require('path');

async function main() {
  // MySQL 모드 활성화 (initialize 안 하면 mock 폴백 → MySQL 저장 안 됨)
  const kvStorage = require('./src/storage');
  const status = await kvStorage.initialize();
  console.log('Storage 모드:', status.mode, '(상태:', status.status + ')');
  if (status.mode === 'mysql' && status.status === 'ok') {
    await kvStorage.preloadAll();
  }

  const { executeAiDiagnosis } = require('./src/engine/aiAssessment');

  const server = {
    server_id: 1,
    name: 'jessy62',
    hostname: 'jessy62',
    asset_no: 'A001',
  };
  const scriptXmlPath = path.resolve(__dirname, 'data/uploads/jessy62-s-20260526.xml');

  console.log('=== Script 소스 AI 진단 테스트 ===');
  console.log('서버:', server.hostname);
  console.log('XML:', scriptXmlPath);
  console.log('');

  const r = await executeAiDiagnosis(server, {
    source: 'script',
    scriptPath: scriptXmlPath,
    executed_by: 'test-script',
    triggered_by: 'manual',
  });

  console.log('=== 결과 ===');
  console.log('status:', r.status);
  if (r.status === 'success') {
    console.log('assessment_id:', r.assessment_id);
    console.log('diagnose_type:', r.diagnose_type);
    console.log('source_type:', r.source_type);
    console.log('elapsed_ms:', r.elapsed_ms);
    console.log('summary:', r.summary);
    console.log('');
    console.log('웹에서 확인: http://localhost:3000/diagnosis/' + r.assessment_id + '/ai');
    console.log('  (웹 서버 재시작 후 또는 storage가 MySQL preload 다시 한 후)');
  } else {
    console.log('error:', r.error);
    if (r.stack) console.log(r.stack);
  }

  // MySQL 쓰기가 비동기일 수 있으니 약간 대기 후 종료
  await new Promise(res => setTimeout(res, 1000));
  process.exit(0);
}

main().catch(e => { console.error('예외:', e); process.exit(1); });

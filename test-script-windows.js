// test-script-windows.js
// 사용법: node test-script-windows.js
//
// Windows Script XML 진단 테스트 (jessy167)
// CP949 디코딩 + mock v2.1 판정이 정상 동작하는지 확인.
//
// 사전 준비:
//   data/uploads/jessy167-s-20260526.xml 파일이 있어야 함
//   (없으면 ↓ 경로 수정 필요)

require('./src/config');
const path = require('path');

async function main() {
  const kvStorage = require('./src/storage');
  const status = await kvStorage.initialize();
  console.log('Storage 모드:', status.mode, '(상태:', status.status + ')');
  if (status.mode === 'mysql' && status.status === 'ok') {
    await kvStorage.preloadAll();
  }

  const { executeAiDiagnosis } = require('./src/engine/aiAssessment');

  const server = {
    server_id: 2,                // jessy167 의 server_id 가 servers.json 에 있다면 그 값
    name: 'jessy167',
    hostname: 'jessy167',
    asset_no: 'A002',
  };
  const scriptXmlPath = path.resolve(__dirname, 'data/uploads/jessy167-s-20260526.xml');

  console.log('=== Windows Script 진단 테스트 ===');
  console.log('서버:', server.hostname);
  console.log('XML:', scriptXmlPath);
  console.log('');

  const r = await executeAiDiagnosis(server, {
    source: 'script',
    scriptPath: scriptXmlPath,
    executed_by: 'test-windows',
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
    console.log('  (웹 서버 재시작 후)');
  } else {
    console.log('error:', r.error);
    if (r.stack) console.log(r.stack);
  }

  await new Promise(res => setTimeout(res, 1000));
  process.exit(0);
}

main().catch(e => { console.error('예외:', e); process.exit(1); });

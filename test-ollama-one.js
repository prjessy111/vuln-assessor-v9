'use strict';
/**
 * Ollama 1건 진단 테스트.
 *
 * 목적:
 *   1) .env 설정이 client.js와 잘 맞물리는지 확인
 *   2) Qwen 모델이 JSON 응답을 제대로 내는지 확인
 *   3) 실제 응답 시간 측정
 *
 * 실행: node test-ollama-one.js
 */

require('./src/config');
const { createClient } = require('./src/engine/llm/client');

const TEST_PROMPT = {
  system: `너는 Linux 보안 진단 전문가다. 주어진 점검 결과를 보고 verdict를 판정한다.
응답은 반드시 다음 JSON 형식만 출력한다 (다른 설명 금지):
{"verdict": "양호|취약|정보|판정불가", "reason": "한 줄 사유", "severity": "상|중|하"}`,

  user: `CHK_ID: os-linux-2778
점검 항목: proftpd allow 설정
SecuMS 자체 판정: WAIT

### 액션 1: proftpd 설정 확인
\`\`\`
cat /etc/proftpd.conf
cat: /etc/proftpd.conf: No such file or directory
\`\`\`

위 점검 결과를 보고 JSON으로 판정해라.`,

  responseFormat: 'json',
  temperature: 0.1,
};

(async () => {
  console.log('=== Ollama 1건 테스트 시작 ===');
  console.log('시작 시각:', new Date().toISOString());

  const client = createClient();
  console.log('설정:', JSON.stringify(client.config, null, 2));

  // ping 먼저
  try {
    const pingResult = await client.ping();
    console.log('\n[ping] 성공:', JSON.stringify(pingResult));
  } catch (e) {
    console.error('\n[ping] 실패:', e.message);
    process.exit(1);
  }

  // complete
  console.log('\n[complete] 요청 시작... (CPU 추론이라 시간 걸림)');
  const t0 = Date.now();
  try {
    const result = await client.complete(TEST_PROMPT);
    const elapsed = Date.now() - t0;
    console.log(`\n[complete] 성공 (${elapsed}ms = ${(elapsed/1000).toFixed(1)}초)`);
    console.log('재시도 횟수:', result.retries);
    console.log('\n--- 원본 응답 ---');
    console.log(result.text);
    console.log('\n--- JSON 파싱 결과 ---');
    console.log(JSON.stringify(result.json, null, 2));

    // 평가
    console.log('\n=== 평가 ===');
    if (!result.json) {
      console.log('❌ JSON 파싱 실패');
    } else {
      console.log('✓ JSON 파싱 OK');
      console.log('verdict:', result.json.verdict || '(없음)');
      console.log('reason:', result.json.reason || '(없음)');

      if (result.json.verdict === '양호') {
        console.log('✓ verdict 판정 정확 (No such file → 양호)');
      } else {
        console.log('⚠ verdict 판정 부정확 (양호여야 하는데 ' + result.json.verdict + ')');
      }
    }

    console.log('\n=== 예상 진단 1건(130항목) 소요시간 ===');
    console.log(`약 ${(elapsed * 130 / 1000 / 60).toFixed(1)}분`);
  } catch (e) {
    const elapsed = Date.now() - t0;
    console.error(`\n[complete] 실패 (${elapsed}ms):`, e.message);
    process.exit(2);
  }
})();
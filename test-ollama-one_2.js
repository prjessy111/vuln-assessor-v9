'use strict';
/**
 * Ollama 1건 진단 테스트 v2 - 프롬프트 보강판
 *
 * v1 대비 변경:
 *   - 시스템 프롬프트에 "부재 = 양호" 도메인 규칙 명시
 *   - 판정 기준 표 형태로 제공
 *   - few-shot 예제 1건 추가
 *
 * 실행: node test-ollama-one-v2.js
 */

require('./src/config');
const { createClient } = require('./src/engine/llm/client');

const TEST_PROMPT = {
  system: `너는 Linux/Windows 시스템 보안 진단 분석가다.
점검 결과를 보고 다음 4가지 verdict 중 하나로 판정한다.

[판정 규칙]
- "양호": 보안 정책에 부합하는 상태. 다음 두 경우 모두 양호:
  (a) 점검 항목이 정책대로 설정되어 있음
  (b) 점검 대상(파일/서비스/계정/프로세스)이 시스템에 존재하지 않음
      → 취약 대상이 없으면 노출 위험도 없으므로 양호
- "취약": 보안 정책을 위반하는 설정이 명확히 발견됨
- "정보": 단순 정보 수집 항목 (verdict 판정 대상 아님)
- "판정불가": 점검 데이터가 수집되지 않음

[중요]
"No such file", "not found", "does not exist", "미설치" 같은 메시지는
점검 대상의 부재를 의미하며, 이 경우 반드시 verdict = "양호" 다.
설정 파일이 없는 것은 "관리 부재"가 아니라 "서비스 미사용"이다.

[예시]
입력: cat /etc/proftpd.conf → "No such file or directory"
출력: {"verdict": "양호", "reason": "proftpd 미설치로 FTP 관련 취약점 노출 없음", "severity": "하"}

응답은 반드시 다음 JSON 형식만 출력한다 (다른 설명 금지):
{"verdict": "...", "reason": "...", "severity": "상|중|하"}`,

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
  console.log('=== Ollama 1건 테스트 v2 (프롬프트 보강) ===');
  console.log('시작 시각:', new Date().toISOString());

  const client = createClient();
  console.log('설정:', JSON.stringify(client.config, null, 2));

  try {
    const pingResult = await client.ping();
    console.log('\n[ping] 성공:', JSON.stringify(pingResult));
  } catch (e) {
    console.error('\n[ping] 실패:', e.message);
    process.exit(1);
  }

  console.log('\n[complete] 요청 시작...');
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

    console.log('\n=== 평가 ===');
    if (!result.json) {
      console.log('❌ JSON 파싱 실패');
    } else {
      console.log('verdict:', result.json.verdict || '(없음)');
      console.log('reason:', result.json.reason || '(없음)');
      console.log('severity:', result.json.severity || '(없음)');

      if (result.json.verdict === '양호') {
        console.log('\n✓✓✓ 도메인 규칙 학습 성공 — sec-expert + 프롬프트 보강으로 운영 가능');
      } else {
        console.log('\n⚠ 여전히 ' + result.json.verdict + ' 판정 — 모델이 도메인 규칙을 따르지 않음');
      }
    }

    console.log('\n=== 예상 진단 1건(130항목) 소요시간 ===');
    console.log(`약 ${(elapsed * 130 / 1000 / 60).toFixed(1)}분`);
  } catch (e) {
    const elapsed = Date.now() - t0;
    console.error(`\n[complete] 실패 (${elapsed}ms):`, e.message);
  }
})();
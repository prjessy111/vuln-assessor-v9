'use strict';
/**
 * CVE AI Judgment Engine
 *
 * CVE Matcher가 찾은 후보들을 LLM이 환경 컨텍스트와 함께 검토하여
 * 실제 영향도, 익스플로잇 가능성, 우선순위를 평가.
 *
 * Mock 모드에서는 LLM 없이 휴리스틱으로 동작.
 * 실제 LLM 호출 시 JSON Schema 검증.
 */

/**
 * 단일 CVE 매칭에 대한 AI 평가 프롬프트 생성.
 */
function buildPrompt(match, environment) {
  const env = environment || {};
  return `당신은 Linux 보안 전문가입니다. 다음 환경에서 ${match.cve_id}의 실제 영향도를 평가하세요.

[환경 정보]
- OS: ${env.os_distro || 'CentOS'} ${env.os_version || '7.x'}
- 호스트명: ${env.hostname || 'unknown'}
- 영향 받는 패키지: ${match.pkg_full}
- 우리 release: ${match.backport.ourRelease}
- 패치된 release: ${match.backport.patchRelease || '(없음)'}

[CVE 정보]
- ${match.cve_id}: ${match.cve_name}
- CVSS v3: ${match.cvss_v3} (${match.severity})
- EPSS: ${match.epss} (활성 익스플로잇 확률)
- CISA KEV: ${match.cisa_kev ? '등재됨 (즉시 패치 의무)' : '미등재'}
- 공개 익스플로잇: ${match.exploit_public ? '있음' : '없음'}
- 설명: ${match.description}

[패치 정보]
- 업스트림: ${match.patches?.upstream || '(없음)'}
- CentOS 7 패치: ${match.patches?.centos_7 || '(없음)'}
- 관련 RHSA: ${match.patches?.rhsa || '(없음)'}

[백포팅 분석]
- 우리는 패치 적용됨: ${match.backport.isPatched ? '예' : '아니오'}

다음 JSON 형식으로 답하시오:
{
  "is_vulnerable": true/false,
  "actual_severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "rationale_ko": "한국어 판정 근거 (3-5문장)",
  "exploit_scenario": "공격 시나리오 (1-2문장)",
  "recommended_actions": ["조치 1", "조치 2"],
  "patch_priority": "IMMEDIATE|URGENT|SCHEDULED|MONITOR"
}`;
}

/**
 * Mock LLM 응답 (실제 LLM 없을 때).
 *
 * 휴리스틱:
 *   - 백포팅 패치 적용됨 → MONITOR + 영향 없음
 *   - CISA KEV + 미패치 → IMMEDIATE
 *   - CVSS >= 9.0 → URGENT 이상
 *   - 공개 익스플로잇 있음 → URGENT 이상
 */
function mockJudge(match, environment) {
  const env = environment || {};
  
  let actualSev = match.severity;
  let patchPriority = 'SCHEDULED';
  let isVuln = !match.backport.isPatched;
  let rationale = '';
  let scenario = '';
  let actions = [];

  if (match.backport.isPatched) {
    // 백포팅으로 패치된 경우
    isVuln = false;
    actualSev = 'LOW';
    patchPriority = 'MONITOR';
    rationale = `우리 패키지 ${match.pkg_full}은 CVE ${match.cve_id}의 영향 범위에 속하지만, ` +
                `CentOS 7 백포팅 패치 release ${match.backport.patchRelease} 이상이 적용되어 있어 ` +
                `실제로는 패치된 상태입니다. ` +
                `(우리 release: ${match.backport.ourRelease})`;
    scenario = '백포팅 패치가 적용되어 익스플로잇 불가능';
    actions = ['주기적 모니터링 유지', `${match.patches?.rhsa || 'RHSA'} 적용 확인 완료`];
  } else {
    // 미패치
    isVuln = true;
    
    if (match.cisa_kev) {
      patchPriority = 'IMMEDIATE';
      rationale = `이 환경은 ${match.cve_id}에 명확히 취약합니다. ` +
                  `설치된 ${match.pkg_full}는 백포팅 패치가 적용되지 않은 상태입니다. ` +
                  `(우리 release: ${match.backport.ourRelease}, 패치 release: ${match.backport.patchRelease}) ` +
                  `CISA KEV에 등재된 활성 익스플로잇 취약점으로 즉시 조치가 필요합니다. ` +
                  `EPSS ${(match.epss * 100).toFixed(1)}%로 익스플로잇 확률이 매우 높습니다.`;
      scenario = `공격자가 ${match.tags?.[0] || 'unauthorized access'} 경로로 익스플로잇 가능. 공개 PoC 존재.`;
      actions = [
        `즉시 yum update ${match.pkg_name} 실행`,
        `패치 적용 후 서비스 재시작 확인`,
        `${match.patches?.rhsa || 'RHSA'} 적용`,
        '감사 로그에서 익스플로잇 흔적 검토',
      ];
    } else if (match.cvss_v3 >= 9.0 || match.exploit_public) {
      patchPriority = 'URGENT';
      rationale = `${match.pkg_full}은 ${match.cve_id} 영향 범위에 포함되며 백포팅 패치 미적용 상태입니다. ` +
                  `CVSS ${match.cvss_v3} (${match.severity}) 등급으로 ` +
                  (match.exploit_public ? '공개 익스플로잇이 존재' : '익스플로잇 위험') + '하여 ' +
                  `긴급 패치 적용이 권장됩니다.`;
      scenario = `${match.cve_name.split('(')[0].trim()}을 통한 시스템 침해 가능.`;
      actions = [
        `${match.patches?.rhsa || '벤더 권고'}에 따른 패치 적용`,
        '임시 우회 조치 검토 (서비스 중단/제한)',
        '관련 로그 모니터링 강화',
      ];
    } else {
      patchPriority = 'SCHEDULED';
      rationale = `${match.pkg_full}은 ${match.cve_id} 영향 범위에 있으나 ` +
                  `EPSS ${(match.epss * 100).toFixed(1)}%로 실제 익스플로잇 가능성이 낮습니다. ` +
                  `일반 패치 사이클에 따라 적용 권장.`;
      scenario = '직접적 익스플로잇 위험 낮음. 다른 취약점과 체이닝 시 활용 가능.';
      actions = [
        '다음 정기 패치 시 함께 적용',
        '취약점 모니터링 유지',
      ];
    }
  }

  return {
    is_vulnerable: isVuln,
    actual_severity: actualSev,
    rationale_ko: rationale,
    exploit_scenario: scenario,
    recommended_actions: actions,
    patch_priority: patchPriority,
    judged_by: 'mock_heuristic',
  };
}

/**
 * 매칭된 CVE 후보들에 대해 AI 평가 수행.
 *
 * @param {Array} matches - CVE Matcher 결과
 * @param {object} environment - 환경 정보
 * @param {object} llmClient - LLM 클라이언트 (없으면 mock)
 * @returns {Promise<Array>} 평가가 추가된 매칭 결과
 */
async function judgeAll(matches, environment, llmClient) {
  const judged = [];

  for (const match of matches) {
    let judgment;

    if (!llmClient || llmClient.provider === 'mock') {
      // Mock heuristic
      judgment = mockJudge(match, environment);
    } else {
      // 실제 LLM 호출
      try {
        const prompt = buildPrompt(match, environment);
        const response = await llmClient.complete({
          prompt,
          format: 'json',
          maxTokens: 800,
        });
        judgment = JSON.parse(response);
        judgment.judged_by = llmClient.provider;
      } catch (e) {
        // 실패 시 mock으로 폴백
        judgment = mockJudge(match, environment);
        judgment.judged_by = 'mock_fallback';
        judgment.error = e.message;
      }
    }

    judged.push({ ...match, ai_judgment: judgment });
  }

  return judged;
}

/**
 * 소프트웨어/라이브러리 CVE(버전 매칭) 판정 — 백포트·도달성 한계를 반영.
 * 패턴(버전)은 '잠재'까지만 판정 가능 → 출처별로 신뢰도/검토필요를 구분.
 *   - 번들 라이브러리(JAR/native): 버전 신뢰 높음(백포트 적음) → LIKELY, 단 도달성 검토
 *   - 설치 프로그램/OS 패키지: 벤더 백포트 가능 → NEEDS_REVIEW(확정 아님)
 */
function judgeSoftwareMatch(m) {
  const kev = !!m.cisa_kev;
  const cvss = Number(m.cvss_v3) || 0;
  const bundled = m.backport_risk === 'low';
  let verdict, priority, isVuln, rationale, actions;

  if (bundled) {
    verdict = 'LIKELY_VULNERABLE';
    isVuln = true;
    priority = kev ? 'IMMEDIATE' : (cvss >= 9.0 || m.exploit_public ? 'URGENT' : 'SCHEDULED');
    rationale = `${m.software} ${m.version}은(는) ${m.cve_id} 영향 버전이며, 제품 내장(번들) 라이브러리라 ` +
      `버전 신뢰도가 높습니다(배포판 백포트 가능성 낮음). 다만 취약 기능의 실제 사용여부(도달성)는 코드 확인 필요.` +
      (kev ? ' CISA KEV 등재 — 우선 조치 권장.' : '');
    actions = [`${m.fixed || '상위'} 버전으로 업그레이드`, '취약 기능 사용여부(도달성) 검토'];
  } else {
    verdict = 'NEEDS_REVIEW';
    isVuln = null; // 확정 불가 (백포트 가능)
    priority = kev ? 'URGENT' : 'SCHEDULED';
    rationale = `${m.software} ${m.version}이(가) ${m.cve_id} 버전범위에 들지만, ` +
      `벤더 백포트 패치(버전 미변경)나 실사용 여부가 미확인이라 "취약 확정"이 아닙니다. ` +
      `release/패치 상태(배포판 advisory) 또는 실제 적용 여부를 확인하세요.`;
    actions = ['배포판 보안 advisory(OVAL/RHSA/USN)로 백포트 여부 확인', '실제 패치/버전 재확인'];
  }
  return {
    verdict,
    is_vulnerable: isVuln,
    actual_severity: m.severity,
    patch_priority: priority,
    rationale_ko: rationale,
    recommended_actions: actions,
    judged_by: 'heuristic_backport_aware',
  };
}

function judgeSoftwareAll(matches) {
  return (matches || []).map(m => ({ ...m, ai_judgment: judgeSoftwareMatch(m) }));
}

module.exports = {
  buildPrompt,
  mockJudge,
  judgeAll,
  judgeSoftwareMatch,
  judgeSoftwareAll,
};

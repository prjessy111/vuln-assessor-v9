'use strict';
const { runCheck } = require('./checks');

/**
 * 룰셋과 raw 값 맵을 받아 항목별 평가 결과 배열을 반환.
 *
 * @param {Array} rules    - rules 테이블에서 로딩한 룰 배열
 * @param {Map}   rawMap   - check_key → value
 * @param {string} hostOs  - 'linux' | 'windows'
 * @returns {{ results: Array, summary: object }}
 */
function evaluate(rules, rawMap, hostOs) {
  const results = [];
  let vuln = 0, safe = 0, na = 0;

  for (const rule of rules) {
    // OS 타깃 필터링
    if (rule.os_target !== 'all' && rule.os_target !== hostOs) continue;

    const value = rawMap.has(rule.check_key) ? rawMap.get(rule.check_key) : null;

    const { status, reason } = (value === null)
      ? { status: '점검불가', reason: '수집 데이터에 해당 항목 없음' }
      : runCheck(rule.check_type, value, rule.check_param);

    if (status === '취약') vuln++;
    else if (status === '양호') safe++;
    else na++;

    results.push({
      rule_id: rule.rule_id,
      title: rule.title,
      category: rule.category,
      severity: rule.severity,
      status,
      collected_value: value,
      reason,
      recommend: rule.recommend,
    });
  }

  return {
    results,
    summary: {
      total: results.length,
      vuln, safe, na,
    },
  };
}

module.exports = { evaluate };

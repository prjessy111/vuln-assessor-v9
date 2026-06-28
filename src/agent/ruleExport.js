'use strict';
/**
 * 확정 항목 → 룰 YAML export (VULN_ASSESSOR_TODO.md §3-3 "기존 검증 체계 합류" / 3-1 항목 편입)
 *
 * 진단 룰셋은 rules/*.yaml 파일 기반(docs/rule-schema-v2.md)이므로, 자율 루프에서
 * "확정"된 항목을 운영자가 룰셋에 편입할 수 있도록 v2 스키마 YAML 조각으로 변환한다.
 *
 * 에이전트 항목은 SecuMS SQL이 아니라 스크립트 기반 점검이므로,
 * context_sql 대신 check.script(승인·실행된 점검 스크립트)를 함께 싣고
 * evaluation_prompt(자연어 판정 지침)를 포함한다.
 */

const yaml = require('js-yaml');

function _ruleId(item) {
  if (item.source === 'cve' && item.source_ref) return 'CVE-' + String(item.source_ref).replace(/^CVE-/i, '');
  if (item.source_ref) return String(item.source_ref).replace(/\s+/g, '-').toUpperCase();
  return 'AGENT-' + String(item.item_id).replace(/^AGI-/, '').toUpperCase();
}

/**
 * 항목 1건을 v2 룰 객체로 변환.
 */
function toRuleObject(item) {
  const finalVerdict = item.review?.verdict || item.judgment?.verdict || null;
  const rule = {
    rule_id: _ruleId(item),
    title: item.title,
    description: (item.description || '').trim(),
    category: item.category || '미분류',
    severity: item.severity || '중',
    os_target: item.os_target || 'linux',
    // 스크립트 기반 점검 — 승인·실행된 점검 스크립트를 그대로 보존
    check: item.script ? {
      method: 'script',
      lang: item.script.lang,
      code: item.script.code,
    } : { method: 'manual' },
    // LLM 판정 지침 (raw 출력 → 양호/취약)
    evaluation_prompt:
      `다음은 "${item.title}" 점검 기준입니다.\n${(item.description || '').trim()}\n` +
      `대상 시스템의 raw 출력을 보고 양호/취약/점검불가로 판정하세요.`,
    prefer: 'llm',
    recommend: (item.review?.note || item.judgment?.recommend || '').trim() || null,
    enabled: true,
    // 출처 메타 (감사/추적용)
    _meta: {
      source: item.source,
      source_ref: item.source_ref || null,
      origin: 'agent-autonomous-loop',
      item_id: item.item_id,
      confirmed_verdict: finalVerdict,
      confirmed_by: item.review?.by || null,
      confirmed_at: item.review?.at || null,
    },
  };
  return rule;
}

/**
 * 항목을 룰셋에 붙여넣을 수 있는 YAML 문자열로 변환 (리스트 항목 1건).
 */
function toYaml(item) {
  const rule = toRuleObject(item);
  // YAML 리스트 항목 형태로 출력 (rules/*.yaml에 그대로 추가 가능)
  const doc = yaml.dump([rule], { lineWidth: 100, noRefs: true, indent: 2 });
  return doc;
}

module.exports = { toRuleObject, toYaml };

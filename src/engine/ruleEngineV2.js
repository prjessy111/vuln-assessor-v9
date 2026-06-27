'use strict';
/**
 * 룰 엔진 v2.1 — 하이브리드 평가 + 중/소항목 계층.
 *
 * 흐름:
 *   1. 어댑터로 raw SQLite 열기
 *   2. 각 룰에 대해:
 *      a. context_sql 실행 → context 데이터 획득
 *      b. simple_check가 per_row 면 → 중항목 1개 + 소항목 N개 생성
 *      c. 일반 simple_check 면 → 중항목 1개만
 *      d. simple_check 미지원 → LLM 평가 (중항목 1개)
 *   3. 결과 집계 (KPI/요약은 중항목 기준)
 *
 * 반환 결과 구조 (per result):
 *   {
 *     rule_id, title, category, severity, recommend,
 *     status, reason, evidence,                          // 중항목 결정 결과
 *     eval_method,                                       // 'simple' | 'llm' | 'na'
 *     subs: [                                            // 소항목 배열 (없으면 빈 배열)
 *       { sub_key, sub_label, status, reason, evidence }
 *     ]
 *   }
 */

const simple = require('./evaluators/simpleEvaluator');

const NA = (reason) => ({ status: '점검불가', reason, evidence: '' });

async function evaluateAll({ adapter, db, rules, hostOs, llmClient }) {
  const results = [];

  for (const rule of rules) {
    if (rule.enabled === false) continue;
    if (rule.os_target && rule.os_target !== 'all' && rule.os_target !== hostOs) continue;

    const out = await evaluateOne({ adapter, db, rule, llmClient });
    results.push({
      rule_id: rule.rule_id,
      title: rule.title,
      category: rule.category,
      severity: rule.severity,
      status: out.status,
      reason: out.reason,
      evidence: out.evidence || '',
      eval_method: out.eval_method,
      recommend: rule.recommend || '',
      subs: out.subs || [],
    });
  }

  // KPI는 중항목 기준
  const summary = {
    total: results.length,
    vuln:  results.filter(r => r.status === '취약').length,
    safe:  results.filter(r => r.status === '양호').length,
    na:    results.filter(r => r.status === '점검불가').length,
    // 소항목 통계도 함께 제공
    subTotal: results.reduce((s, r) => s + r.subs.length, 0),
    subVuln:  results.reduce((s, r) => s + r.subs.filter(x => x.status === '취약').length, 0),
    subSafe:  results.reduce((s, r) => s + r.subs.filter(x => x.status === '양호').length, 0),
  };
  return { results, summary };
}

/**
 * 단일 룰 평가.
 *
 * 반환: { status, reason, evidence, eval_method, subs }
 */
async function evaluateOne({ adapter, db, rule, llmClient }) {
  // 1) context_sql 실행
  let context;
  if (rule.context_sql) {
    try {
      context = adapter.querySlice(db, rule.context_sql);
    } catch (e) {
      return { ...NA(`context_sql 실행 실패: ${e.message}`), eval_method: 'na', subs: [] };
    }
  } else {
    context = [];
  }

  const prefer = rule.prefer || 'simple';
  const hasSimple = !!(rule.simple_check && rule.simple_check.type);
  const hasLLM = !!rule.evaluation_prompt;

  // 2) simple_check 시도
  if (hasSimple && (prefer === 'simple' || !hasLLM)) {
    const r = simple.evaluate(rule, context);

    // per_row 결과 (중/소항목)
    if (simple.isPerRowResult(r)) {
      return {
        status: r.main.status,
        reason: r.main.reason,
        evidence: r.main.evidence || '',
        eval_method: 'simple',
        subs: r.subs || [],
      };
    }

    // 일반 결과
    if (r !== null) {
      return { ...r, eval_method: 'simple', subs: [] };
    }
    // simple null → LLM 폴백
  }

  // 3) LLM 평가
  if (hasLLM) {
    if (!llmClient) {
      return { ...NA('LLM 평가가 필요하지만 LLM 클라이언트 미설정'), eval_method: 'na', subs: [] };
    }
    const r = await _evaluateWithLLM(rule, context, llmClient);
    return { ...r, eval_method: 'llm', subs: [] };
  }

  return { ...NA('평가 방법 미정의'), eval_method: 'na', subs: [] };
}

async function _evaluateWithLLM(rule, context, llmClient) {
  const system = [
    '당신은 시스템 보안 점검 전문가입니다.',
    '제공된 raw 데이터(SQLite 쿼리 결과)를 분석하여 룰을 평가합니다.',
    '응답은 반드시 다음 JSON 형식만 출력하세요 (다른 텍스트 금지):',
    '{"status": "양호" | "취약" | "점검불가", "reason": "한국어 사유 1~2문장", "evidence": "raw에서 인용한 핵심 데이터"}',
  ].join('\n');

  const contextStr = _formatContextForLLM(context);
  const user = [
    `# 점검 항목: ${rule.title}`,
    `# 중요도: ${rule.severity}`,
    `# 설명:`,
    rule.description || '(없음)',
    '',
    '# Raw 데이터 (context_sql 실행 결과):',
    contextStr,
    '',
    '# 평가 지시:',
    rule.evaluation_prompt,
  ].join('\n');

  try {
    const r = await llmClient.complete({ system, user, responseFormat: 'json', temperature: 0.1 });
    const j = r.json || {};
    if (!['양호', '취약', '점검불가'].includes(j.status)) {
      return NA(`LLM 응답 status 형식 오류: ${JSON.stringify(j).slice(0, 200)}`);
    }
    return {
      status: j.status,
      reason: String(j.reason || '').slice(0, 480),
      evidence: String(j.evidence || '').slice(0, 480),
    };
  } catch (e) {
    return NA(`LLM 호출 오류: ${e.message}`);
  }
}

function _formatContextForLLM(context) {
  if (!Array.isArray(context) || !context.length) return '(결과 없음 — 0 rows)';
  const sample = context.slice(0, 20);
  const cols = Object.keys(sample[0]);
  const header = '| ' + cols.join(' | ') + ' |';
  const sep    = '|' + cols.map(() => '---').join('|') + '|';
  const rows = sample.map(row =>
    '| ' + cols.map(c => _truncCell(row[c])).join(' | ') + ' |'
  );
  let out = [header, sep, ...rows].join('\n');
  if (context.length > 20) {
    out += `\n\n(... 외 ${context.length - 20}건 생략, 전체 ${context.length}건)`;
  }
  return out;
}

function _truncCell(v) {
  if (v == null) return '';
  const s = String(v).replace(/\|/g, '\\|').replace(/\n/g, ' ');
  return s.length > 80 ? s.slice(0, 77) + '...' : s;
}

module.exports = { evaluateAll, evaluateOne };

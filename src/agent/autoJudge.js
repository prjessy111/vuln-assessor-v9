'use strict';
/**
 * raw 데이터 기반 자동 판정기 (VULN_ASSESSOR_TODO.md §3-3)
 *
 * 수집된 raw 출력 + 항목 설명 → 양호/취약/점검불가 판정 + 근거 + 조치 가이드.
 *  - 독립 판정 원칙(§0): SecuMS 판정을 정답으로 쓰지 않고 raw로 독립 판정.
 *  - 저신뢰(confidence < 임계) 또는 '점검불가'는 needs_review=true → 사람 최종 검토 게이트.
 *
 * LLM 미설정 시 임의 판정하지 않는다(§no-arbitrary-hardcoding):
 *   verdict='점검불가', needs_review=true 로 정직하게 보류.
 */

const { buildClient, resolveBackend, isBackendConfigured } = require('./llmClient');

const CONFIDENCE_THRESHOLD = parseFloat(process.env.AGENT_CONFIDENCE_THRESHOLD || '0.7');

const VALID_VERDICTS = ['양호', '취약', '점검불가'];

const SYSTEM_PROMPT =
  '당신은 시스템 보안 점검 전문가입니다. 주어진 점검 항목 설명과 ' +
  '대상 시스템에서 실제 수집된 raw 출력을 보고 독립적으로 판정합니다.\n' +
  '판정 규칙:\n' +
  '1) raw 출력에 실제로 나타난 근거만 사용한다. 추측 금지.\n' +
  '2) 양호=기준 충족, 취약=기준 위반, 점검불가=출력이 비었거나 판단 근거 부족.\n' +
  '3) confidence는 0~1 사이 실수로, 근거가 명확할수록 높게.\n' +
  '4) 출력은 반드시 JSON 한 개만: ' +
  '{"verdict":"양호|취약|점검불가","reason":"<판정 사유>","evidence":"<raw에서 인용한 근거>",' +
  '"recommend":"<취약 시 조치 가이드, 양호면 빈 문자열>","confidence":0.0}';

function buildUserPrompt(item, rawOutput) {
  return [
    `[점검 항목]`,
    `제목: ${item.title}`,
    `대상 OS: ${item.os_target}`,
    `중요도: ${item.severity}`,
    ``,
    `[점검 기준 설명]`,
    item.description,
    ``,
    `[대상 시스템 raw 출력]`,
    '```',
    String(rawOutput || '').slice(0, 8000),
    '```',
    ``,
    `위 raw 출력만 근거로 판정하세요. JSON 한 개만 출력하세요.`,
  ].join('\n');
}

function _parseJudgment(text) {
  const { _parseJsonResponse } = require('../engine/llm/client');
  const obj = _parseJsonResponse(text);
  if (!obj || !obj.verdict) return null;
  let verdict = String(obj.verdict).trim();
  if (!VALID_VERDICTS.includes(verdict)) {
    // 동의어 정규화
    if (/취약|위반|fail|bad|vuln/i.test(verdict)) verdict = '취약';
    else if (/양호|충족|ok|pass|good/i.test(verdict)) verdict = '양호';
    else verdict = '점검불가';
  }
  let confidence = parseFloat(obj.confidence);
  if (!(confidence >= 0 && confidence <= 1)) confidence = verdict === '점검불가' ? 0.2 : 0.6;
  return {
    verdict,
    reason: String(obj.reason || '(사유 없음)'),
    evidence: String(obj.evidence || ''),
    recommend: String(obj.recommend || ''),
    confidence,
  };
}

/**
 * raw 출력으로 항목 자동 판정.
 * @param {object} item - itemRegistry 항목
 * @param {string} rawOutput - 수집된 raw 텍스트
 * @param {object} opts - { backend, model, secums_verdict }
 * @returns {Promise<object>} judgment
 */
async function judge(item, rawOutput, opts = {}) {
  const backend = resolveBackend(opts.backend);
  const now = () => new Date().toISOString().slice(0, 19).replace('T', ' ');

  const secums_verdict = opts.secums_verdict || null;

  if (!String(rawOutput || '').trim()) {
    return {
      verdict: '점검불가', reason: 'raw 출력이 비어 있어 판정 불가', evidence: '', recommend: '',
      confidence: 0, needs_review: true, review_reason: 'raw 출력 없음',
      secums_verdict, model: null, backend, judged_at: now(),
    };
  }

  if (!isBackendConfigured(backend)) {
    // 임의 판정 금지 — 정직하게 보류
    return {
      verdict: '점검불가',
      reason: `LLM 백엔드(${backend}) 미설정으로 자동 판정 불가 — 사람 검토 필요`,
      evidence: '', recommend: '', confidence: 0,
      needs_review: true, review_reason: 'LLM 미설정',
      secums_verdict, model: null, backend, judged_at: now(),
    };
  }

  let parsed, model = null, err = null;
  try {
    const client = buildClient(backend, opts);
    model = client.config.model;
    const res = await client.complete({
      system: SYSTEM_PROMPT,
      user: buildUserPrompt(item, rawOutput),
      responseFormat: 'json',
      // 1차 판정은 결정적(0.0). 교차검증 재검토는 독립 샘플을 얻기 위해 온도를 올려 호출.
      temperature: typeof opts.temperature === 'number' ? opts.temperature : 0.0,
    });
    parsed = _parseJudgment(res.text);
  } catch (e) {
    err = e.message;
  }

  if (!parsed) {
    return {
      verdict: '점검불가',
      reason: err ? `LLM 호출 실패: ${err}` : 'LLM 응답 파싱 실패',
      evidence: '', recommend: '', confidence: 0,
      needs_review: true, review_reason: err ? 'LLM 호출 실패' : '응답 파싱 실패',
      secums_verdict, model, backend, judged_at: now(),
    };
  }

  // 게이트 2: 저신뢰 / 점검불가 / SecuMS 불일치 → 사람 검토
  const reasons = [];
  if (parsed.confidence < CONFIDENCE_THRESHOLD) reasons.push(`저신뢰(${parsed.confidence.toFixed(2)}<${CONFIDENCE_THRESHOLD})`);
  if (parsed.verdict === '점검불가') reasons.push('점검불가');
  if (opts.secums_verdict && _disagrees(parsed.verdict, opts.secums_verdict)) {
    reasons.push(`SecuMS(${opts.secums_verdict})와 불일치`);
  }

  return {
    ...parsed,
    needs_review: reasons.length > 0,
    review_reason: reasons.join(', '),
    secums_verdict: opts.secums_verdict || null,
    model, backend, judged_at: now(),
  };
}

// SecuMS 판정 어휘(OK/BAD 등)와 자체 판정(양호/취약) 불일치 여부
function _disagrees(verdict, secums) {
  const s = String(secums).toLowerCase();
  const secumsBad = /bad|취약|fail|vuln/.test(s);
  const secumsOk = /ok|양호|pass|good/.test(s);
  if (verdict === '취약' && secumsOk) return true;
  if (verdict === '양호' && secumsBad) return true;
  return false;
}

module.exports = { judge, CONFIDENCE_THRESHOLD, VALID_VERDICTS };

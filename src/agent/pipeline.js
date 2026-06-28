'use strict';
/**
 * 자율 진단 파이프라인 (VULN_ASSESSOR_TODO.md §3-4)
 *
 * 3-1(항목 편입) → 3-2(스크립트 생성) → [게이트1: 사람 승인] → 수집 →
 * 3-3(자동 판정) → [게이트2: 불일치·애매 항목 사람 검토] 를 하나의 루프로 연결.
 *
 * 사람 확인 게이트(§0)는 코드로 강제한다:
 *  - 안전게이트 blocked 스크립트는 승인 불가.
 *  - 승인 전에는 수집·판정 단계로 진행 불가.
 *  - 판정이 needs_review면 confirm 전까지 confirmed로 못 간다.
 *
 * 모든 단계는 itemRegistry.update로 상태/이력을 남긴다.
 */

const itemRegistry = require('./itemRegistry');
const scriptGenerator = require('./scriptGenerator');
const autoJudge = require('./autoJudge');

/**
 * 3-2: 점검 스크립트 생성 (또는 재생성).
 * 항목 상태를 draft/rejected → script_generated 로 전이.
 */
async function generateScript(storage, itemId, opts = {}) {
  const item = itemRegistry.get(storage, itemId);
  if (!item) throw new Error(`항목 없음: ${itemId}`);

  const script = await scriptGenerator.generate(item, opts);
  return itemRegistry.update(
    storage, itemId,
    { script, status: 'script_generated', approval: null },
    `script_generated (${script.generated_by}, safety=${script.safety.risk})`,
    opts.by || 'agent'
  );
}

/**
 * 게이트1: 스크립트 실행 승인/거부.
 * @param {object} decision - { decision:'approve'|'reject', by, note }
 */
function reviewScript(storage, itemId, decision = {}) {
  const item = itemRegistry.get(storage, itemId);
  if (!item) throw new Error(`항목 없음: ${itemId}`);
  if (item.status !== 'script_generated') {
    throw new Error(`승인 가능한 상태가 아닙니다 (현재: ${item.status})`);
  }
  const approve = decision.decision === 'approve';

  if (approve && item.script?.safety?.risk === 'blocked') {
    throw new Error('안전게이트 blocked 스크립트는 승인할 수 없습니다. 재생성하세요.');
  }

  const approval = {
    decision: approve ? 'approved' : 'rejected',
    by: decision.by || 'operator',
    at: new Date().toISOString().slice(0, 19).replace('T', ' '),
    note: decision.note || '',
  };
  return itemRegistry.update(
    storage, itemId,
    { approval, status: approve ? 'approved' : 'rejected' },
    `script_${approval.decision} by ${approval.by}`,
    approval.by
  );
}

/**
 * 수집: 승인된 항목에 raw 출력 적재.
 * (스크립트는 폐쇄망/안전 정책상 자동 원격 실행하지 않고, 운영자가 실행 결과를
 *  붙여넣거나 agent 토큰 push로 올린다 — §5-3 폐쇄망 방식과 일치.)
 * @param {object} input - { output, source }
 */
function ingestRaw(storage, itemId, input = {}) {
  const item = itemRegistry.get(storage, itemId);
  if (!item) throw new Error(`항목 없음: ${itemId}`);
  if (item.status !== 'approved' && item.status !== 'collected' && item.status !== 'judged' && item.status !== 'needs_review') {
    throw new Error(`raw 수집은 승인(approved) 이후에만 가능합니다 (현재: ${item.status})`);
  }
  const output = String(input.output || '');
  if (!output.trim()) throw new Error('raw 출력이 비어 있습니다');

  const raw = {
    output,
    source: input.source || 'manual',
    ingested_at: new Date().toISOString().slice(0, 19).replace('T', ' '),
  };
  return itemRegistry.update(
    storage, itemId,
    { raw, status: 'collected' },
    `raw_ingested (${raw.source}, ${output.length} chars)`,
    input.by || 'operator'
  );
}

/**
 * 3-2(실행): 승인된 스크립트를 대상 서버에서 실행 → raw 자동 수집 → (옵션) 자동 판정.
 * 게이트 보강: 승인(approved) 상태 + 실행 직전 안전 재검사(blocked면 거부).
 * @param {object} server - servers 레코드
 * @param {object} opts - { autoJudge, backend, secums_verdict, useSudo, by }
 */
async function runOnTarget(storage, itemId, server, opts = {}) {
  const safetyGate = require('./safetyGate');
  const scriptRunner = require('./scriptRunner');

  const item = itemRegistry.get(storage, itemId);
  if (!item) throw new Error(`항목 없음: ${itemId}`);
  if (!['approved', 'collected', 'judged', 'needs_review'].includes(item.status)) {
    throw new Error(`대상 실행은 승인(approved) 이후에만 가능합니다 (현재: ${item.status})`);
  }
  if (!item.script?.code) throw new Error('생성된 스크립트가 없습니다');

  // 실행 직전 안전 재검사 (승인 후 변조/누락 방어)
  const safety = safetyGate.inspect(item.script.code);
  if (safety.risk === 'blocked') {
    throw new Error('안전게이트 blocked — 실행 거부. 스크립트를 재생성하세요.');
  }

  const res = await scriptRunner.run(server, item.script, {
    useSudo: opts.useSudo != null ? opts.useSudo : !!server.use_sudo,
    timeout: opts.timeout,
  });

  let updated = ingestRaw(storage, itemId, {
    output: res.output,
    source: `ssh:${res.target} (exit=${res.exit_code})`,
    by: opts.by || 'agent',
  });

  if (opts.autoJudge) {
    updated = await runJudge(storage, itemId, { backend: opts.backend, secums_verdict: opts.secums_verdict });
  }
  return updated;
}

/**
 * 3-3: 자동 판정.
 * collected → judged (needs_review면 needs_review).
 */
async function runJudge(storage, itemId, opts = {}) {
  const item = itemRegistry.get(storage, itemId);
  if (!item) throw new Error(`항목 없음: ${itemId}`);
  if (!item.raw?.output) throw new Error('수집된 raw 출력이 없습니다');

  const judgment = await autoJudge.judge(item, item.raw.output, opts);
  const status = judgment.needs_review ? 'needs_review' : 'judged';
  return itemRegistry.update(
    storage, itemId,
    { judgment, status },
    `judged: ${judgment.verdict} (conf=${(judgment.confidence ?? 0).toFixed(2)}, ${status})`,
    'agent'
  );
}

/**
 * 게이트2: 판정 사람 검토 확정.
 * @param {object} decision - { decision:'confirm'|'override', verdict?, by, note }
 */
function confirmJudgment(storage, itemId, decision = {}) {
  const item = itemRegistry.get(storage, itemId);
  if (!item) throw new Error(`항목 없음: ${itemId}`);
  if (item.status !== 'judged' && item.status !== 'needs_review') {
    throw new Error(`검토 확정 가능한 상태가 아닙니다 (현재: ${item.status})`);
  }
  const override = decision.decision === 'override' && decision.verdict;
  const finalVerdict = override ? decision.verdict : item.judgment?.verdict;

  const review = {
    decision: override ? 'override' : 'confirm',
    verdict: finalVerdict,
    by: decision.by || 'operator',
    at: new Date().toISOString().slice(0, 19).replace('T', ' '),
    note: decision.note || '',
  };
  return itemRegistry.update(
    storage, itemId,
    { review, status: 'confirmed' },
    `review_${review.decision}: ${finalVerdict} by ${review.by}`,
    review.by
  );
}

/**
 * 3소스 합의 계산 (VULN_ASSESSOR_TODO.md §4-4 하이브리드 / 3-way 합류).
 * 소스: ① 1차 판정(judgment, 보통 LSAP) ② 교차검증(cross, 보통 Claude) ③ SecuMS 자체판정.
 * 양호/취약 등 결정적 판정만 비교 모수에 포함.
 */
function computeAgreement(item) {
  const norm = (v) => {
    const s = String(v || '').trim().toUpperCase();
    if (s === '취약' || s === 'BAD' || s === 'FAIL' || s === 'VULN') return '취약';
    if (s === '양호' || s === 'OK' || s === 'PASS' || s === 'GOOD') return '양호';
    return null; // 점검불가/INFO/WAIT 등은 비교 제외
  };
  const sources = {
    primary: norm(item.judgment?.verdict),
    cross: norm(item.cross?.verdict),
    secums: norm(item.judgment?.secums_verdict || item.cross?.secums_verdict),
  };
  const decisive = Object.values(sources).filter(Boolean);
  let status;
  if (decisive.length < 2) status = 'no_data';
  else status = decisive.every(x => x === decisive[0]) ? 'agree' : 'mismatch';
  return { sources, decisive_count: decisive.length, status };
}

/**
 * 교차 검증 → 3소스 합의 기록 (§4-4 하이브리드).
 * 보안 기본: 사내 LSAP로 "독립 재검토"(샘플링 온도를 올려 같은 모델에서 다른 표본을 얻음).
 *   - 외부 Claude 2차는 opts.backend='claude' + AGENT_ALLOW_EXTERNAL=true 일 때만 허용된다.
 * collected/judged/needs_review 상태에서 호출 가능. 상태는 바꾸지 않고 cross/agreement만 추가.
 */
async function crossVerify(storage, itemId, opts = {}) {
  const item = itemRegistry.get(storage, itemId);
  if (!item) throw new Error(`항목 없음: ${itemId}`);
  if (!item.raw?.output) throw new Error('수집된 raw 출력이 없습니다');

  // 기본 = 사내(LSAP) 재검토. 외부 백엔드는 명시 요청 시에만.
  const backend = opts.backend || process.env.AGENT_CROSS_BACKEND || 'lsap';
  // 같은 모델 재검토면 독립 표본을 위해 온도를 올린다(외부 백엔드는 결정성 유지).
  const temperature = backend === 'claude'
    ? undefined
    : parseFloat(process.env.AGENT_CROSS_TEMPERATURE || '0.5');
  const cross = await autoJudge.judge(item, item.raw.output, {
    backend,
    temperature,
    secums_verdict: opts.secums_verdict || item.judgment?.secums_verdict,
  });

  const patched = { ...item, cross };
  const agreement = computeAgreement(patched);

  return itemRegistry.update(
    storage, itemId,
    { cross, agreement },
    `cross_verify(${backend}): ${cross.verdict} → 합의 ${agreement.status}`,
    'agent'
  );
}

/**
 * 현황 요약 — 대시보드/검토 큐용.
 */
function summary(storage) {
  const items = itemRegistry.load(storage);
  const byStatus = {};
  for (const it of items) byStatus[it.status] = (byStatus[it.status] || 0) + 1;
  return {
    total: items.length,
    byStatus,
    pending_approval: items.filter(i => i.status === 'script_generated').length, // 게이트1 대기
    needs_review: items.filter(i => i.status === 'needs_review').length,          // 게이트2 대기
    confirmed: items.filter(i => i.status === 'confirmed').length,
  };
}

module.exports = {
  generateScript,
  reviewScript,
  ingestRaw,
  runOnTarget,
  runJudge,
  crossVerify,
  computeAgreement,
  confirmJudgment,
  summary,
};

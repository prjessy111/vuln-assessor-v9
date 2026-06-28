'use strict';
/**
 * 자율 진단 항목 레지스트리 (VULN_ASSESSOR_TODO.md §3-1)
 *
 * 신규 CVE / 보안 가이드 / 고객 커스텀 기준을 "자연어 설명만으로" 진단 항목으로
 * 자동 편입한다. 항목은 파이프라인(생성→수집→판정)의 단위가 된다.
 *
 * 저장: storage 'agent_items' (KV). token.js와 동일하게 storage를 주입받는다.
 *
 * 상태 머신 (status):
 *   draft            신규 등록 (스크립트 없음)
 *   script_generated 점검 스크립트 생성됨 — 사람 승인 대기 [게이트 1]
 *   approved         스크립트 실행 승인됨
 *   rejected         스크립트 거부됨 (재생성 필요)
 *   collected        raw 출력 수집됨
 *   judged           자동 판정 완료
 *   needs_review     저신뢰·불일치 → 사람 최종 검토 대기 [게이트 2]
 *   confirmed        사람이 판정 확정
 */

const crypto = require('crypto');

const STORE_KEY = 'agent_items';

const VALID_OS = ['linux', 'windows', 'all'];
const VALID_SEVERITY = ['상', '중', '하'];
const VALID_SOURCE = ['cve', 'guide', 'custom'];

function _now() {
  return new Date().toISOString().slice(0, 19).replace('T', ' ');
}

function _newId() {
  return 'AGI-' + crypto.randomBytes(6).toString('hex');
}

function load(storage) {
  return storage.loadSync(STORE_KEY) || [];
}

function _save(storage, items) {
  return storage.saveSync(STORE_KEY, items);
}

function list(storage, filter = {}) {
  let items = load(storage);
  if (filter.status) items = items.filter(i => i.status === filter.status);
  if (filter.os_target) items = items.filter(i => i.os_target === filter.os_target);
  if (filter.source) items = items.filter(i => i.source === filter.source);
  // 최신 등록 우선
  return items.slice().sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
}

function get(storage, itemId) {
  return load(storage).find(i => i.item_id === itemId) || null;
}

/**
 * 신규 진단 항목 생성. description(자연어)만 필수.
 * @param {object} storage
 * @param {object} input - { title, description, category, severity, os_target, source, source_ref, created_by }
 */
function create(storage, input = {}) {
  const description = String(input.description || '').trim();
  if (!description) throw new Error('description(자연어 설명)은 필수입니다');

  const os_target = VALID_OS.includes(input.os_target) ? input.os_target : 'linux';
  const severity = VALID_SEVERITY.includes(input.severity) ? input.severity : '중';
  const source = VALID_SOURCE.includes(input.source) ? input.source : 'custom';

  const item = {
    item_id: _newId(),
    title: String(input.title || '').trim() || description.slice(0, 40),
    description,
    category: String(input.category || '').trim() || '미분류',
    severity,
    os_target,
    source,
    source_ref: String(input.source_ref || '').trim(),  // 예: CVE-2021-3156, KISA U-01
    status: 'draft',
    created_at: _now(),
    created_by: input.created_by || 'system',
    updated_at: _now(),
    script: null,       // { lang, code, explanation, expected_output, safety, generated_at, generated_by }
    approval: null,     // { decision, by, at, note }
    raw: null,          // { output, source, ingested_at }
    judgment: null,     // { verdict, reason, recommend, evidence, confidence, needs_review, review_reason, model, judged_at }
    review: null,       // { decision, verdict, by, at, note }
    history: [{ at: _now(), event: 'created', by: input.created_by || 'system' }],
  };

  const items = load(storage);
  items.push(item);
  _save(storage, items);
  return item;
}

/**
 * 항목을 patch로 갱신하고 history 이벤트를 남긴다. (원자적 read-modify-write)
 */
function update(storage, itemId, patch = {}, event = null, by = 'system') {
  const items = load(storage);
  const idx = items.findIndex(i => i.item_id === itemId);
  if (idx < 0) throw new Error(`항목 없음: ${itemId}`);
  const merged = { ...items[idx], ...patch, updated_at: _now() };
  if (event) {
    merged.history = (merged.history || []).concat([{ at: _now(), event, by }]);
  }
  items[idx] = merged;
  _save(storage, items);
  return merged;
}

function remove(storage, itemId) {
  const items = load(storage).filter(i => i.item_id !== itemId);
  return _save(storage, items);
}

module.exports = {
  STORE_KEY,
  VALID_OS,
  VALID_SEVERITY,
  VALID_SOURCE,
  load,
  list,
  get,
  create,
  update,
  remove,
};

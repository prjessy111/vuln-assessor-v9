'use strict';
/**
 * Simple Evaluator — LLM 없이 즉시 판정 가능한 simple_check 처리.
 *
 * 입력:
 *   - rule: 룰 정의 객체 (rule_id, simple_check, ...)
 *   - context: context_sql 실행 결과 (Array<object>)
 *
 * 출력:
 *   { status, reason, evidence } | null  (해당 타입 미지원이면 null)
 *
 * 지원 타입:
 *   - perm_le, perm_ge          : 8진수 권한 비교
 *   - service_off, service_on   : 활성/비활성 상태
 *   - int_min, int_max          : 정수 범위
 *   - contains, not_contains    : 문자열 포함
 *   - equals                    : 동등
 *   - regex                     : 정규식
 *   - row_count_zero            : 결과 행이 0개여야 양호
 *   - row_count_min, row_count_max : 결과 행 수
 *   - every_row                 : 모든 행이 조건 만족
 *   - any_row                   : 하나라도 조건 만족 (negate 옵션)
 */

const OK   = (reason, evidence) => ({ status: '양호',     reason, evidence });
const NG   = (reason, evidence) => ({ status: '취약',     reason, evidence });
const NA   = (reason)           => ({ status: '점검불가', reason, evidence: '' });

const OFF_TOKENS = new Set(['inactive', 'disabled', 'stopped', 'off', 'not running', 'dead', 'false', 'no', '0']);
const ON_TOKENS  = new Set(['active', 'enabled', 'running', 'on', 'started', 'true', 'yes', '1']);

// =============================================================================
// 헬퍼
// =============================================================================
function _pickField(row, field) {
  if (!row || !field) return undefined;
  // 대소문자 무시 매칭
  for (const k of Object.keys(row)) {
    if (k.toLowerCase() === String(field).toLowerCase()) return row[k];
  }
  return row[field];
}

function _parseOct(v) {
  if (v == null || v === '') return null;
  const m = String(v).match(/[0-7]{3,4}/);
  if (!m) return null;
  return parseInt(m[0], 8);
}

function _parseIntSafe(v) {
  if (v == null) return null;
  const m = String(v).match(/-?\d+/);
  return m ? parseInt(m[0], 10) : null;
}

function _firstRow(context) {
  if (!Array.isArray(context) || !context.length) return null;
  return context[0];
}

// =============================================================================
// 각 타입별 평가 함수
// =============================================================================

function _perm(context, { field, max, min }, mode) {
  const row = _firstRow(context);
  if (!row) return NA('context_sql 결과가 비어있음');
  const v = _pickField(row, field);
  const cur = _parseOct(v);
  if (cur === null) return NA(`권한 파싱 실패: ${field}=${v}`);
  if (mode === 'le') {
    const lim = _parseOct(max);
    if (lim === null) return NA(`기준 max 파싱 실패: ${max}`);
    return cur <= lim
      ? OK(`현재 권한 ${v} ≤ 기준 ${max}`, `${field}=${v}`)
      : NG(`현재 권한 ${v} > 기준 ${max}`, `${field}=${v}`);
  } else {
    const lim = _parseOct(min);
    if (lim === null) return NA(`기준 min 파싱 실패: ${min}`);
    return cur >= lim
      ? OK(`현재 권한 ${v} ≥ 기준 ${min}`, `${field}=${v}`)
      : NG(`현재 권한 ${v} < 기준 ${min}`, `${field}=${v}`);
  }
}

function _service(context, { field }, expectOff) {
  const row = _firstRow(context);
  if (!row) {
    // 행이 없으면: service_off는 양호, service_on은 취약
    return expectOff
      ? OK('관련 서비스/포트가 발견되지 않음 (비활성으로 간주)', '(empty)')
      : NG('관련 서비스/포트가 발견되지 않음 (활성 상태 아님)', '(empty)');
  }
  const v = String(_pickField(row, field) || '').trim().toLowerCase();
  const isOff = OFF_TOKENS.has(v);
  const isOn  = ON_TOKENS.has(v);
  if (!isOff && !isOn) return NA(`상태 해석 불가: ${v}`);
  const off = isOff;
  if (expectOff) {
    return off ? OK(`서비스 비활성: ${v}`, `${field}=${v}`)
               : NG(`서비스 활성: ${v}`, `${field}=${v}`);
  } else {
    return off ? NG(`서비스 비활성: ${v}`, `${field}=${v}`)
               : OK(`서비스 활성: ${v}`, `${field}=${v}`);
  }
}

function _intRange(context, { field, min, max }, mode) {
  const row = _firstRow(context);
  if (!row) return NA('context_sql 결과 비어있음');
  const v = _pickField(row, field);
  const n = _parseIntSafe(v);
  if (n === null) return NA(`숫자 파싱 실패: ${field}=${v}`);
  if (mode === 'min') {
    return n >= min ? OK(`${n} ≥ 기준 ${min}`, `${field}=${v}`)
                    : NG(`${n} < 기준 ${min}`, `${field}=${v}`);
  } else {
    return n <= max ? OK(`${n} ≤ 기준 ${max}`, `${field}=${v}`)
                    : NG(`${n} > 기준 ${max}`, `${field}=${v}`);
  }
}

function _contains(context, { field, keyword }, expectPresent) {
  const row = _firstRow(context);
  if (!row) return NA('context_sql 결과 비어있음');
  const v = String(_pickField(row, field) || '').toLowerCase();
  const present = v.includes(String(keyword).toLowerCase());
  if (expectPresent) {
    return present ? OK(`'${keyword}' 포함 확인`, `${field}=${v}`)
                   : NG(`'${keyword}' 미포함`, `${field}=${v}`);
  } else {
    return !present ? OK(`'${keyword}' 미포함 확인`, `${field}=${v}`)
                    : NG(`'${keyword}' 포함됨`, `${field}=${v}`);
  }
}

function _equals(context, { field, expect }) {
  const row = _firstRow(context);
  if (!row) return NA('context_sql 결과 비어있음');
  const v = String(_pickField(row, field) || '').trim().toLowerCase();
  const exp = String(expect).trim().toLowerCase();
  return v === exp ? OK(`${field}=${v} (기댓값 일치)`, `${field}=${v}`)
                   : NG(`${field}=${v} (기댓값 '${expect}' 불일치)`, `${field}=${v}`);
}

function _regex(context, { field, pattern, flags }) {
  const row = _firstRow(context);
  if (!row) return NA('context_sql 결과 비어있음');
  const v = String(_pickField(row, field) || '');
  let f = flags || '';
  let p = pattern;
  const inline = p.match(/^\(\?([imsux]+)\)/);
  if (inline) { for (const c of inline[1]) if (!f.includes(c)) f += c; p = p.slice(inline[0].length); }
  f = f.replace(/[^gimsuy]/g, '');
  let re;
  try { re = new RegExp(p, f); } catch (e) { return NA(`정규식 오류: ${e.message}`); }
  return re.test(v) ? OK(`패턴 매칭 성공`, `${field}=${v.slice(0, 100)}`)
                    : NG(`패턴 불일치`, `${field}=${v.slice(0, 100)}`);
}

function _rowCount(context, { min, max }, mode) {
  const n = Array.isArray(context) ? context.length : 0;
  if (mode === 'zero') {
    return n === 0 ? OK('해당 항목 없음 (안전)', `rowCount=0`)
                   : NG(`해당 항목 ${n}건 발견`, `rowCount=${n}`);
  }
  if (mode === 'min') {
    return n >= min ? OK(`${n}건 ≥ 기준 ${min}`, `rowCount=${n}`)
                    : NG(`${n}건 < 기준 ${min}`, `rowCount=${n}`);
  }
  if (mode === 'max') {
    return n <= max ? OK(`${n}건 ≤ 기준 ${max}`, `rowCount=${n}`)
                    : NG(`${n}건 > 기준 ${max}`, `rowCount=${n}`);
  }
  return NA(`알 수 없는 row count 모드: ${mode}`);
}

function _rowCondition(context, { field, op, value }, mode) {
  if (!Array.isArray(context) || !context.length) {
    return NA('context_sql 결과 비어있음');
  }
  const check = (row) => {
    const v = _pickField(row, field);
    switch (op) {
      case '==': return String(v) === String(value);
      case '!=': return String(v) !== String(value);
      case '>':  return _parseIntSafe(v) > _parseIntSafe(value);
      case '<':  return _parseIntSafe(v) < _parseIntSafe(value);
      case '>=': return _parseIntSafe(v) >= _parseIntSafe(value);
      case '<=': return _parseIntSafe(v) <= _parseIntSafe(value);
      case 'contains': return String(v).includes(String(value));
      default: throw new Error(`알 수 없는 op: ${op}`);
    }
  };
  try {
    if (mode === 'every') {
      const bad = context.find(r => !check(r));
      return bad === undefined
        ? OK(`모든 행(${context.length}건) 조건 만족`, `${field} ${op} ${value}`)
        : NG(`조건 미충족 행 존재`, `위반: ${field}=${_pickField(bad, field)}`);
    } else { // any
      const good = context.find(r => check(r));
      return good !== undefined
        ? OK(`조건 만족 행 존재`, `${field} ${op} ${value}`)
        : NG(`조건 만족 행 없음`, `${field} ${op} ${value}`);
    }
  } catch (e) {
    return NA(`조건 평가 오류: ${e.message}`);
  }
}

/**
 * per_row 평가: 행마다 소항목 1개씩 생성.
 *
 * 입력 simple_check:
 *   - sub_key            : 행 식별 컬럼 (필수)
 *   - sub_label_template : 표시 라벨 템플릿 (예: "계정 {USERNAME}")
 *   - each_status        : 모든 행을 이 상태로 (예: '취약', '양호')
 *   - each_check         : 행마다 다른 평가 룰 적용 (다른 simple_check 객체)
 *   - if_empty           : context가 비었을 때 중항목 status
 *
 * 반환:
 *   {
 *     main: { status, reason, evidence },     // 중항목 결정 결과
 *     subs: [ { sub_key, sub_label, status, reason, evidence }, ... ]
 *   }
 *
 * 또는 simple로 해결 못하면 null (LLM 폴백)
 */
function _perRow(context, params) {
  const { sub_key, sub_label_template, each_status, each_check, if_empty } = params;

  if (!Array.isArray(context)) {
    return { main: NA('context_sql 결과 형식 오류'), subs: [] };
  }
  if (context.length === 0) {
    const st = if_empty || '점검불가';
    const main = st === '양호' ? OK('해당 항목 없음 (안전)', 'rowCount=0')
               : st === '취약' ? NG('해당 항목 없음 (정책 미설정)', 'rowCount=0')
               : NA('context_sql 결과 비어있음');
    return { main, subs: [] };
  }

  const subs = [];
  for (const row of context) {
    const key = _pickField(row, sub_key);
    const label = _renderTemplate(sub_label_template || `${sub_key}={${sub_key}}`, row);

    let sub;
    if (each_check && each_check.type) {
      // 행 1개를 context로 만들어 평가
      const handler = HANDLERS[each_check.type];
      if (!handler) {
        sub = NA(`each_check.type 미지원: ${each_check.type}`);
      } else {
        try { sub = handler([row], each_check); }
        catch (e) { sub = NA(`each_check 오류: ${e.message}`); }
      }
    } else if (each_status) {
      // 행 존재 자체가 each_status (예: 빈 패스워드 사용자는 무조건 취약)
      sub = each_status === '양호' ? OK(label, `${sub_key}=${key}`)
          : each_status === '취약' ? NG(label, `${sub_key}=${key}`)
          : NA(label);
    } else {
      sub = NA('per_row 평가 방식 미정의 (each_status 또는 each_check 필요)');
    }

    subs.push({
      sub_key: String(key),
      sub_label: label,
      status: sub.status,
      reason: sub.reason,
      evidence: sub.evidence,
    });
  }

  // 중항목: 소항목 중 '취약'이 있으면 '취약', 모두 '양호'면 '양호', 그 외 '점검불가'
  const vulnCount = subs.filter(s => s.status === '취약').length;
  const safeCount = subs.filter(s => s.status === '양호').length;
  let main;
  if (vulnCount > 0) {
    main = NG(`소항목 ${context.length}건 중 ${vulnCount}건 취약`, `vuln=${vulnCount}/${context.length}`);
  } else if (safeCount === context.length) {
    main = OK(`모든 소항목(${context.length}건) 양호`, `safe=${safeCount}/${context.length}`);
  } else {
    main = NA(`소항목 평가 결과 일부 점검불가`);
  }
  return { main, subs };
}

function _renderTemplate(tpl, row) {
  if (!tpl) return '';
  return tpl.replace(/\{([^}]+)\}/g, (_, key) => {
    const v = _pickField(row, key.trim());
    return v == null ? '' : String(v);
  });
}

// =============================================================================
// 디스패처
// =============================================================================
const HANDLERS = {
  perm_le:        (ctx, p) => _perm(ctx, p, 'le'),
  perm_ge:        (ctx, p) => _perm(ctx, p, 'ge'),
  service_off:    (ctx, p) => _service(ctx, p, true),
  service_on:     (ctx, p) => _service(ctx, p, false),
  int_min:        (ctx, p) => _intRange(ctx, p, 'min'),
  int_max:        (ctx, p) => _intRange(ctx, p, 'max'),
  contains:       (ctx, p) => _contains(ctx, p, true),
  not_contains:   (ctx, p) => _contains(ctx, p, false),
  equals:         (ctx, p) => _equals(ctx, p),
  regex:          (ctx, p) => _regex(ctx, p),
  row_count_zero: (ctx, p) => _rowCount(ctx, p, 'zero'),
  row_count_min:  (ctx, p) => _rowCount(ctx, p, 'min'),
  row_count_max:  (ctx, p) => _rowCount(ctx, p, 'max'),
  every_row:      (ctx, p) => _rowCondition(ctx, p, 'every'),
  any_row:        (ctx, p) => _rowCondition(ctx, p, 'any'),
  // per_row는 반환 형식이 다름 ({ main, subs }) — evaluate()에서 분기 처리
};

/**
 * simple_check 평가.
 *
 * 반환 형식:
 *   - 일반 타입:  { status, reason, evidence }
 *   - per_row:    { main: {status, reason, evidence}, subs: [...] }
 *   - 미지원:     null (LLM 폴백 신호)
 */
function evaluate(rule, context) {
  const check = rule.simple_check;
  if (!check || !check.type) return null;

  // per_row는 특수 처리 (소항목 생성)
  if (check.type === 'per_row') {
    try {
      return _perRow(context, check);
    } catch (e) {
      return { main: NA(`per_row 평가 오류: ${e.message}`), subs: [] };
    }
  }

  const handler = HANDLERS[check.type];
  if (!handler) return null;
  try {
    return handler(context, check);
  } catch (e) {
    return NA(`simple_check 평가 오류: ${e.message}`);
  }
}

/**
 * per_row 결과 여부 판별 헬퍼.
 */
function isPerRowResult(r) {
  return r && typeof r === 'object' && 'main' in r && 'subs' in r;
}

module.exports = { evaluate, isPerRowResult, HANDLERS };

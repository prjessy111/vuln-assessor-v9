'use strict';
/**
 * check_type별 판정 함수.
 * 각 함수: (value: string|null, param: object) => { status, reason }
 *   status : '양호' | '취약' | '점검불가'
 *   reason : 사람이 읽는 사유 (한국어)
 */

const NA = (reason) => ({ status: '점검불가', reason });
const OK = (reason) => ({ status: '양호', reason });
const NG = (reason) => ({ status: '취약', reason });

function _hasValue(v) {
  return v !== null && v !== undefined && String(v).trim() !== '';
}

function _parseInt(v) {
  const m = String(v).match(/-?\d+/);
  return m ? parseInt(m[0], 10) : null;
}

// 파일 권한 8진수 비교 (값에서 3-4자리 8진수 추출)
function perm_le(value, { max }) {
  if (!_hasValue(value)) return NA('수집값 없음');
  const m = String(value).match(/\b([0-7]{3,4})\b/);
  if (!m) return NA(`권한 파싱 실패: ${value}`);
  const cur = parseInt(m[1], 8);
  const lim = parseInt(String(max), 8);
  return cur <= lim
    ? OK(`현재 권한 ${m[1]} ≤ 기준 ${max}`)
    : NG(`현재 권한 ${m[1]} > 기준 ${max}`);
}

const OFF_TOKENS = new Set(['inactive', 'disabled', 'stopped', 'off', 'not running', 'dead', 'false', 'no', '0']);
const ON_TOKENS  = new Set(['active', 'enabled', 'running', 'on', 'started', 'true', 'yes', '1']);

function service_off(value) {
  if (!_hasValue(value)) return NA('수집값 없음');
  const v = String(value).trim().toLowerCase();
  if (OFF_TOKENS.has(v)) return OK(`서비스 비활성: ${value}`);
  if (ON_TOKENS.has(v))  return NG(`서비스 활성화됨: ${value}`);
  return NA(`상태 해석 불가: ${value}`);
}

function service_on(value) {
  if (!_hasValue(value)) return NA('수집값 없음');
  const v = String(value).trim().toLowerCase();
  if (ON_TOKENS.has(v))  return OK(`서비스 활성: ${value}`);
  if (OFF_TOKENS.has(v)) return NG(`서비스 비활성: ${value}`);
  return NA(`상태 해석 불가: ${value}`);
}

function int_min(value, { min }) {
  if (!_hasValue(value)) return NA('수집값 없음');
  const n = _parseInt(value);
  if (n === null) return NA(`숫자 파싱 실패: ${value}`);
  return n >= min ? OK(`${n} ≥ 기준 ${min}`) : NG(`${n} < 기준 ${min}`);
}

function int_max(value, { max }) {
  if (!_hasValue(value)) return NA('수집값 없음');
  const n = _parseInt(value);
  if (n === null) return NA(`숫자 파싱 실패: ${value}`);
  return n <= max ? OK(`${n} ≤ 기준 ${max}`) : NG(`${n} > 기준 ${max}`);
}

function int_range_inclusive(value, { min, max }) {
  if (!_hasValue(value)) return NA('수집값 없음');
  const n = _parseInt(value);
  if (n === null) return NA(`숫자 파싱 실패: ${value}`);
  return (n >= min && n <= max)
    ? OK(`${n} ∈ [${min}, ${max}]`)
    : NG(`${n} ∉ [${min}, ${max}]`);
}

function contains(value, { keyword }) {
  if (!_hasValue(value)) return NA('수집값 없음');
  return String(value).toLowerCase().includes(String(keyword).toLowerCase())
    ? OK(`'${keyword}' 포함`)
    : NG(`'${keyword}' 미포함`);
}

function not_contains(value, { keyword }) {
  if (!_hasValue(value)) return NA('수집값 없음');
  return !String(value).toLowerCase().includes(String(keyword).toLowerCase())
    ? OK(`'${keyword}' 미포함`)
    : NG(`'${keyword}' 포함됨: ${value}`);
}

function equals(value, { expect }) {
  // 'none' 기댓값은 빈/none/0 모두 양호로 처리 (값이 없는 것도 '해당 없음'이므로 양호)
  if (String(expect).toLowerCase() === 'none') {
    if (value === null || value === undefined) return OK('해당 없음 확인 (수집값 없음)');
    const v = String(value).trim().toLowerCase();
    return (v === '' || v === 'none' || v === '0')
      ? OK('해당 없음 확인')
      : NG(`존재함: ${value}`);
  }
  if (!_hasValue(value)) return NA('수집값 없음');
  return String(value).trim().toLowerCase() === String(expect).trim().toLowerCase()
    ? OK(`기댓값과 일치: ${value}`)
    : NG(`기댓값 '${expect}' 불일치: ${value}`);
}

function regex(value, { pattern, flags }) {
  if (!_hasValue(value)) return NA('수집값 없음');
  // JavaScript RegExp는 (?i) 등 inline flag를 지원하지 않으므로 추출하여 flags로 변환
  let p = String(pattern);
  let f = flags || '';
  const inline = p.match(/^\(\?([imsux]+)\)/);
  if (inline) {
    for (const c of inline[1]) if (!f.includes(c)) f += c;
    p = p.slice(inline[0].length);
  }
  // 지원되지 않는 플래그(x, u) 제거
  f = f.replace(/[^gimsuy]/g, '');
  let re;
  try { re = new RegExp(p, f); }
  catch (e) { return NA(`정규식 오류: ${e.message}`); }
  return re.test(String(value))
    ? OK(`패턴 매칭: ${value}`)
    : NG(`패턴 불일치: ${value}`);
}

const CHECKS = {
  perm_le, service_off, service_on,
  int_min, int_max, int_range_inclusive,
  contains, not_contains, equals, regex,
};

/**
 * 단일 판정 실행. check_type이 정의되어 있지 않거나 예외가 발생하면 점검불가 반환.
 */
function runCheck(checkType, value, param) {
  const fn = CHECKS[checkType];
  if (!fn) return NA(`알 수 없는 check_type: ${checkType}`);
  try {
    return fn(value, param || {});
  } catch (e) {
    return NA(`판정 오류: ${e.message}`);
  }
}

module.exports = { CHECKS, runCheck };

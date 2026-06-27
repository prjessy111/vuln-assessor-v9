'use strict';
/**
 * 표준 5필드 cron 표현식 파서 + 다음 실행시각 계산.
 *
 * 지원 형식: "분 시 일 월 요일"
 *   필드별 허용:
 *     *           — 모든 값
 *     N           — 정확한 값
 *     N-M         — 범위 (포함)
 *     N,M,...     — 목록
 *     star/N      — N 간격 (예: '* /5' = 5분마다, '0 *' = 매시 정각)
 *     N-M/K       — 범위 + 간격
 *
 *   필드 범위:
 *     분    0-59
 *     시    0-23
 *     일    1-31
 *     월    1-12
 *     요일  0-6 (0=일요일)
 *
 * 미지원:
 *   - "@yearly" 같은 alias
 *   - "L", "W", "#" 같은 비표준 확장
 *   - "manual" 같은 가짜 표현식 (호출 측에서 분리)
 *
 * 라이브러리 의존성 없음 (Node 내장 Date만 사용).
 */

const FIELD_BOUNDS = [
  { min: 0, max: 59 },  // minute
  { min: 0, max: 23 },  // hour
  { min: 1, max: 31 },  // day-of-month
  { min: 1, max: 12 },  // month
  { min: 0, max: 6 },   // day-of-week (Sunday=0)
];

/**
 * 단일 필드 파싱: "*", "5", "1-5", "*\/10", "1,3,5", "0-23/2"
 * @returns Set<number>
 */
function parseField(spec, bounds) {
  const result = new Set();
  const parts = String(spec).split(',');

  for (const part of parts) {
    let stepDivider = 1;
    let rangeSpec = part;

    // step (*/N or M-N/K)
    if (part.includes('/')) {
      const [base, stepStr] = part.split('/');
      stepDivider = parseInt(stepStr, 10);
      if (isNaN(stepDivider) || stepDivider <= 0) {
        throw new Error(`invalid step: ${part}`);
      }
      rangeSpec = base;
    }

    let start, end;
    if (rangeSpec === '*') {
      start = bounds.min;
      end = bounds.max;
    } else if (rangeSpec.includes('-')) {
      const [s, e] = rangeSpec.split('-');
      start = parseInt(s, 10);
      end = parseInt(e, 10);
      if (isNaN(start) || isNaN(end)) {
        throw new Error(`invalid range: ${part}`);
      }
    } else {
      start = parseInt(rangeSpec, 10);
      end = start;
      if (isNaN(start)) {
        throw new Error(`invalid value: ${part}`);
      }
    }

    if (start < bounds.min || end > bounds.max || start > end) {
      throw new Error(`out of range: ${part} (allowed ${bounds.min}-${bounds.max})`);
    }

    for (let v = start; v <= end; v++) {
      if ((v - start) % stepDivider === 0) result.add(v);
    }
  }

  return result;
}

/**
 * cron 표현식 파싱.
 * @returns {{ minute, hour, dayOfMonth, month, dayOfWeek }} 각각 Set<number>
 */
function parseCronExpression(expr) {
  if (!expr || typeof expr !== 'string') {
    throw new Error('cron 표현식이 비어있음');
  }
  const trimmed = expr.trim();
  if (trimmed === 'manual' || trimmed === '') {
    throw new Error('자동 실행 대상이 아님 (manual 또는 빈 표현식)');
  }
  const fields = trimmed.split(/\s+/);
  if (fields.length !== 5) {
    throw new Error(`5개 필드여야 함, 받은 값: "${expr}" (${fields.length}개 필드)`);
  }
  return {
    minute:     parseField(fields[0], FIELD_BOUNDS[0]),
    hour:       parseField(fields[1], FIELD_BOUNDS[1]),
    dayOfMonth: parseField(fields[2], FIELD_BOUNDS[2]),
    month:      parseField(fields[3], FIELD_BOUNDS[3]),
    dayOfWeek:  parseField(fields[4], FIELD_BOUNDS[4]),
  };
}

/**
 * 주어진 시각이 cron 표현식과 일치하는지.
 * 표준 cron 규칙: dayOfMonth와 dayOfWeek는 OR 관계 (둘 중 하나라도 *가 아니면).
 */
function matches(parsed, date) {
  if (!parsed.minute.has(date.getMinutes())) return false;
  if (!parsed.hour.has(date.getHours())) return false;
  if (!parsed.month.has(date.getMonth() + 1)) return false;

  const domMatch = parsed.dayOfMonth.has(date.getDate());
  const dowMatch = parsed.dayOfWeek.has(date.getDay());

  // dayOfMonth가 '*' (모든 일을 포함) 이면 dayOfWeek만 보면 됨, 반대도 동일
  const domIsAll = parsed.dayOfMonth.size === 31;
  const dowIsAll = parsed.dayOfWeek.size === 7;

  if (domIsAll && dowIsAll) return true;
  if (domIsAll) return dowMatch;
  if (dowIsAll) return domMatch;
  // 둘 다 제한 → OR
  return domMatch || dowMatch;
}

/**
 * 지정 시각 이후의 가장 빠른 다음 실행 시각 반환.
 * 무한 루프 방지: 최대 4년(약 35040시간 * 60분) 까지만 탐색.
 *
 * @param {string} expr cron 표현식
 * @param {Date} from 기준 시각 (기본: now)
 * @returns {Date} 다음 실행 시각
 */
function nextRunAfter(expr, from = new Date()) {
  const parsed = parseCronExpression(expr);

  // from의 다음 분부터 시작 (현재 분에 이미 실행됐다고 가정)
  const candidate = new Date(from);
  candidate.setSeconds(0, 0);
  candidate.setMinutes(candidate.getMinutes() + 1);

  const MAX_ITER = 60 * 24 * 366 * 4;  // 4년
  for (let i = 0; i < MAX_ITER; i++) {
    if (matches(parsed, candidate)) return candidate;
    candidate.setMinutes(candidate.getMinutes() + 1);
  }
  throw new Error(`다음 실행 시각을 4년 안에서 찾지 못함: ${expr}`);
}

/**
 * 사람이 읽기 쉬운 설명 반환 (한국어).
 * 흔한 패턴만 매핑, 복잡한 표현식은 원본 그대로.
 */
function humanize(expr) {
  if (!expr || expr === 'manual') return '수동 실행';
  const m = expr.trim().match(/^(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)$/);
  if (!m) return expr;
  const [, mi, h, dom, mon, dow] = m;

  // 매분
  if (mi === '*' && h === '*' && dom === '*' && mon === '*' && dow === '*') {
    return '매분';
  }
  // 매시 정각
  if (mi === '0' && h === '*' && dom === '*' && mon === '*' && dow === '*') {
    return '매시 정각';
  }
  // 매일 HH:MM
  if (/^\d+$/.test(mi) && /^\d+$/.test(h) && dom === '*' && mon === '*' && dow === '*') {
    return `매일 ${h.padStart(2, '0')}:${mi.padStart(2, '0')}`;
  }
  // 매주 X요일 HH:MM
  if (/^\d+$/.test(mi) && /^\d+$/.test(h) && dom === '*' && mon === '*' && /^\d+$/.test(dow)) {
    const days = ['일','월','화','수','목','금','토'];
    return `매주 ${days[parseInt(dow,10)]}요일 ${h.padStart(2,'0')}:${mi.padStart(2,'0')}`;
  }
  // N분마다
  if (mi.startsWith('*/') && h === '*' && dom === '*' && mon === '*' && dow === '*') {
    return `${mi.slice(2)}분마다`;
  }
  return expr;
}

module.exports = {
  parseCronExpression,
  matches,
  nextRunAfter,
  humanize,
};

'use strict';
/**
 * 진단 결과 운영 처리 (중항목 조치/소항목 자동 동기화).
 *
 * 핵심 정책:
 *   - 운영 메타(담당자/조치일자/조치여부 등)는 중항목에만 저장
 *   - 중항목이 '조치완료' 또는 '예외'로 처리되면 자식 소항목들도 자동 종료
 *   - DB 트리거가 처리하지만, 명시적 함수도 제공 (트랜잭션 명확화)
 */

/**
 * 중항목 조치 정보 업데이트.
 *
 * 자식 소항목이 있으면 같은 fix_status로 일괄 동기화한다.
 *
 * @param {object} conn  - mysql2 connection
 * @param {object} args
 *   - result_id       : 중항목 result_id (필수)
 *   - assignee        : 담당자
 *   - delivered_at    : 전달일자 (YYYY-MM-DD)
 *   - fixed_at        : 조치일자 (YYYY-MM-DD)
 *   - fix_status      : '미조치' | '진행중' | '조치완료' | '조치불가' | '예외'
 *   - unfixed_reason  : 미조치 사유
 *   - remark          : 비고
 *
 * @returns {{ updatedMain: number, updatedSubs: number }}
 */
async function updateMainResult(conn, args) {
  const { result_id } = args;
  if (!result_id) throw new Error('result_id is required');

  // 1) 대상이 중항목인지 검증
  const [rows] = await conn.execute(
    'SELECT result_id, parent_result_id, fix_status FROM assessment_results WHERE result_id = ?',
    [result_id]
  );
  if (!rows.length) throw new Error(`result_id ${result_id} not found`);
  if (rows[0].parent_result_id !== null) {
    throw new Error('소항목은 직접 운영 메타를 수정할 수 없습니다. 중항목 처리만 가능.');
  }

  const oldStatus = rows[0].fix_status;

  // 2) 중항목 업데이트
  const fields = ['assignee', 'delivered_at', 'fixed_at', 'fix_status', 'unfixed_reason', 'remark'];
  const sets = [], vals = [];
  for (const f of fields) {
    if (args[f] !== undefined) {
      sets.push(`${f} = ?`);
      vals.push(args[f]);
    }
  }
  if (!sets.length) return { updatedMain: 0, updatedSubs: 0 };
  vals.push(result_id);
  const [upMain] = await conn.execute(
    `UPDATE assessment_results SET ${sets.join(', ')} WHERE result_id = ?`,
    vals
  );

  // 3) 종료 상태로 변경되면 소항목 일괄 동기화 (트리거가 처리하지만 보강)
  // 트리거가 동작하지 않는 환경(개발/SQLite)을 위해 명시 호출도 가능하게 함
  let updatedSubs = 0;
  const newStatus = args.fix_status;
  if (newStatus && newStatus !== oldStatus && ['조치완료', '예외'].includes(newStatus)) {
    const [upSubs] = await conn.execute(
      `UPDATE assessment_results
         SET fix_status = ?,
             fixed_at = COALESCE(?, CURDATE())
       WHERE parent_result_id = ?`,
      [newStatus, args.fixed_at || null, result_id]
    );
    updatedSubs = upSubs.affectedRows || 0;
  }

  return { updatedMain: upMain.affectedRows || 0, updatedSubs };
}

/**
 * 중항목 + 소항목 일괄 조회 (계층 구조).
 *
 * @returns {Array<{ ...main, subs: [...] }>}
 */
async function getResultsWithSubs(conn, assessment_id) {
  const [rows] = await conn.execute(
    `SELECT result_id, parent_result_id, rule_id, sub_key, sub_label,
            status, reason, evidence, severity, eval_method,
            is_new, management_no, assignee, delivered_at, fixed_at,
            fix_status, unfixed_reason, remark
       FROM assessment_results
      WHERE assessment_id = ?
      ORDER BY parent_result_id IS NULL DESC, result_id`,
    [assessment_id]
  );

  // 중항목 분리
  const mains = rows.filter(r => r.parent_result_id === null);
  const subsByParent = {};
  for (const r of rows) {
    if (r.parent_result_id !== null) {
      (subsByParent[r.parent_result_id] ||= []).push(r);
    }
  }

  // 조립
  return mains.map(m => ({
    ...m,
    subs: subsByParent[m.result_id] || [],
  }));
}

module.exports = { updateMainResult, getResultsWithSubs };

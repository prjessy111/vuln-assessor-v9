'use strict';
/**
 * SecuMS Agent 어댑터 (Unix + Windows 통합).
 *
 * SecuMS Unix Agent와 Windows Agent는 동일한 SQLite 스키마를 공유합니다:
 *   - SYSTEM_INFO_TB   : KEY/VALUE (HOSTNAME, OS, OS VERSION)
 *   - CHECKLIST_TB     : 점검 항목 + 상태 (COMPLETE/WAIT) + 결과 (OK/BAD/INFO)
 *   - CHECKITEM_TB     : 상세 메시지
 *   - COLLECT_DATA_TB  : 명령어 실행 raw 출력
 *   - DEBUG_DATA_TB    : RULE XML (점검 정의)
 *   - PROBE_TB         : 수집 시각
 *
 * 보조 테이블만 OS별로 다름:
 *   - Unix    : U_*_TB (U_PASSWD_TB, U_PROCESS_TB, U_GROUP_TB, U_COMMANDLINE_TB, ...)
 *   - Windows : W_*_TB (W_SERVICE_TB, W_REGISSTRY_TB, W_USERACCOUNT_TB, ...)
 *
 * CHK_ID 형식:
 *   - Unix    : os-linux-NNN
 *   - Windows : os-win-NNN
 */

/**
 * 어댑터 매칭 판별 — SecuMS Agent (Unix 또는 Windows) 공통 핵심 테이블 존재 여부.
 * U_* 또는 W_* 보조 테이블 중 어느 하나라도 있어야 함.
 */
function detect(db) {
  // 공통 필수 테이블
  const core = ['SYSTEM_INFO_TB', 'CHECKLIST_TB', 'COLLECT_DATA_TB'];
  const coreRows = db.prepare(
    `SELECT name FROM sqlite_master WHERE type='table' AND name IN (${core.map(() => '?').join(',')})`
  ).all(...core);
  if (coreRows.length !== core.length) return false;
  
  // Unix(U_*) 또는 Windows(W_*) 보조 테이블 중 하나라도 있어야 함
  const aux = db.prepare(
    "SELECT name FROM sqlite_master WHERE type='table' AND (name LIKE 'U_%_TB' OR name LIKE 'W_%_TB') LIMIT 1"
  ).all();
  return aux.length > 0;
}

/**
 * 시스템 메타 정보 추출.
 *
 * @returns {{ host, hostOs, osVersion, collectedAt }}
 */
function extractMeta(db) {
  const rows = db.prepare("SELECT KEY, VALUE FROM SYSTEM_INFO_TB").all();
  const info = Object.fromEntries(rows.map(r => [r.KEY, r.VALUE]));

  const osRaw = (info['OS'] || '').toLowerCase();
  const hostOs = osRaw.includes('windows') ? 'windows' : 'linux';

  // 수집 시각은 PROBE_TB의 가장 빠른 START_TIME
  let collectedAt = null;
  try {
    const r = db.prepare("SELECT MIN(START_TIME) AS t FROM PROBE_TB").get();
    collectedAt = r ? r.t : null;
  } catch (_) { /* PROBE_TB가 비어있을 수 있음 */ }

  return {
    host: info['HOSTNAME'] || 'unknown',
    hostOs,
    osVersion: info['OS VERSION'] || '',
    collectedAt,
  };
}

/**
 * 사용 가능한 raw 테이블 카탈로그 반환.
 * 룰 엔진(또는 LLM)이 "어떤 데이터가 있는지" 알기 위해 사용.
 *
 * @param {boolean} includeSample - 각 테이블의 샘플 row 1개 포함 여부
 * @returns {Array<{ table, columns, rowCount, sample? }>}
 */
function listTables(db, { includeSample = false } = {}) {
  // 점검에 의미있는 테이블만 (U_* + COLLECT_DATA_TB + SYSTEM_INFO_TB)
  const rows = db.prepare(`
    SELECT name FROM sqlite_master
    WHERE type='table'
      AND (name LIKE 'U\\_%' ESCAPE '\\'
        OR name IN ('SYSTEM_INFO_TB', 'COLLECT_DATA_TB', 'PROBE_TB'))
    ORDER BY name
  `).all();

  const out = [];
  for (const { name } of rows) {
    const cols = db.prepare(`PRAGMA table_info("${name}")`).all().map(c => c.name);
    const cnt = db.prepare(`SELECT COUNT(*) AS c FROM "${name}"`).get().c;
    const entry = { table: name, columns: cols, rowCount: cnt };
    if (includeSample && cnt > 0) {
      try {
        entry.sample = db.prepare(`SELECT * FROM "${name}" LIMIT 1`).get();
      } catch (_) { /* ignore */ }
    }
    out.push(entry);
  }
  return out;
}

/**
 * 임의 SELECT 쿼리 실행 (룰의 context_sql 용).
 * 보안상 SELECT 문만 허용. DDL/DML은 거부.
 *
 * @param {string} sql
 * @param {number} maxRows - 최대 반환 행 수 (기본 500)
 * @returns {Array<object>}
 */
function querySlice(db, sql, { maxRows = 500 } = {}) {
  const trimmed = String(sql).trim();
  // SELECT 또는 WITH ... SELECT 만 허용
  if (!/^(SELECT|WITH)\s/i.test(trimmed)) {
    throw new Error('context_sql은 SELECT 문만 허용됩니다.');
  }
  // 위험 키워드 차단 (방어적)
  if (/\b(INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|ATTACH|DETACH|PRAGMA)\b/i.test(trimmed)) {
    throw new Error('SELECT 외 키워드는 허용되지 않습니다.');
  }
  const stmt = db.prepare(trimmed);
  const rows = stmt.all();
  return rows.slice(0, maxRows);
}

/**
 * 설치된 패키지 목록 추출 (rpm -qa 결과 파싱).
 *
 * SecuMS 정책에 "RPM 리스트 조회" (CMD='rpm -qa') 가 포함되어 있어야 함.
 * 데이터는 U_COMMANDLINE_TB.CMD='rpm -qa' 의 LINE 컬럼에 라인별로 저장됨.
 *
 * 출력 객체 형식 (src/cve/matcher.js 가 기대):
 *   { name, version, release, arch, full }
 *
 * 예시 입력:  "adwaita-icon-theme-3.22.0-1.el7.noarch"
 *      파싱:  name="adwaita-icon-theme", version="3.22.0",
 *             release="1.el7", arch="noarch"
 *
 * 데이터가 없거나 테이블이 비어있으면 빈 배열 반환 (예외 던지지 않음).
 *
 * @returns {Array<{name, version, release, arch, full}>}
 */
function extractPackages(db) {
  // 1) U_COMMANDLINE_TB가 있는지 (없으면 빈 배열)
  let exists;
  try {
    exists = db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='U_COMMANDLINE_TB'"
    ).all();
  } catch (_) {
    return [];
  }
  if (!exists || exists.length === 0) return [];

  // 2) rpm -qa 결과 직접 조회 (LINENUM 정렬)
  let rows;
  try {
    rows = db.prepare(
      "SELECT LINE FROM U_COMMANDLINE_TB " +
      "WHERE CMD='rpm -qa' AND TRIM(LINE) != '' " +
      "ORDER BY LINENUM"
    ).all();
  } catch (e) {
    return [];
  }
  if (!rows || rows.length === 0) return [];

  // 3) 각 라인을 패키지 객체로 파싱
  const result = [];
  for (const row of rows) {
    const line = String(row.LINE || '').trim();
    if (!line) continue;
    const parsed = parseRpmPackage(line);
    if (parsed) result.push(parsed);
  }
  return result;
}

/**
 * "name-version-release.arch" 형식의 rpm 패키지 문자열 파싱.
 *
 * RPM 명명 규칙:
 *   <name>-<version>-<release>.<arch>
 *
 * 어려움:
 *   - name 자체에 하이픈이 들어갈 수 있음 ("adwaita-icon-theme")
 *   - version 자체에 하이픈은 거의 없음 (점/패치표기 위주)
 *   - release는 마지막 하이픈 이후 ~ 마지막 점 직전
 *   - arch는 마지막 점 이후 (x86_64, noarch, i686, aarch64 등)
 *
 * 알고리즘 (rpm-qa 출력 기준):
 *   1) 마지막 점 뒤 = arch (알려진 arch 패턴이면)
 *   2) 남은 부분에서 뒤에서부터 하이픈 두 개를 찾아 release/version 분리
 *
 * @returns {object|null} 파싱 실패 시 null
 */
function parseRpmPackage(full) {
  const ARCH_PATTERN = /\.(x86_64|i\d86|noarch|aarch64|ppc64(le)?|s390x|armv\d\w*|src)$/;

  let archMatch = full.match(ARCH_PATTERN);
  let nvr;        // name-version-release 부분
  let arch;
  if (archMatch) {
    arch = archMatch[1];
    nvr = full.slice(0, full.length - archMatch[0].length);
  } else {
    // arch 없는 경우 (드물지만 방어): 전체를 nvr로
    arch = '';
    nvr = full;
  }

  // nvr 에서 뒤에서부터 두 번째 하이픈 위치를 찾음
  // name = nvr[..lastHyphen-1 이전 하이픈)
  // version = 그 다음 ~ 마지막 하이픈 직전
  // release = 마지막 하이픈 다음 ~ 끝
  const lastHyphen = nvr.lastIndexOf('-');
  if (lastHyphen <= 0) return null;
  const secondLastHyphen = nvr.lastIndexOf('-', lastHyphen - 1);
  if (secondLastHyphen <= 0) return null;

  const name = nvr.slice(0, secondLastHyphen);
  const version = nvr.slice(secondLastHyphen + 1, lastHyphen);
  const release = nvr.slice(lastHyphen + 1);

  if (!name || !version || !release) return null;

  return { name, version, release, arch, full };
}

/**
 * SecuMS의 64개 진단 항목을 raw DB에서 통째로 추출.
 *
 * 각 CHK_ID에 대해 다음을 수집:
 *   - SecuMS 자체 판정 (CHECKLIST_TB.RESULT: OK/BAD/INFO/WAIT)
 *   - SecuMS 항목 메시지 (CHECKITEM_TB: 취약 상세)
 *   - 점검 액션 설명 (COLLECT_DATA_TB.ACTION_DESC)
 *   - 실행한 명령 (ACTION_VALUE)
 *   - 명령 출력 (RESULT_OUTPUT)  ← AI 판정의 핵심 입력
 *
 * 출력 객체 형식:
 *   {
 *     chk_id, type, status, secums_verdict,         // SecuMS 메타
 *     items: [{ item, msg }],                        // 취약 상세 (BAD 항목)
 *     actions: [{                                    // 점검 액션들
 *       action_id, action_type, action_desc,
 *       action_value,                                // shell 스크립트
 *       result_output, result_error,                 // 실행 결과
 *       is_executed, error_code, error_message,
 *     }]
 *   }
 *
 * @returns {Array<object>} 64개 항목 (없으면 빈 배열)
 */
function extractDiagnoseItems(db) {
  // 1) CHECKLIST_TB 전체 (64개)
  let checklist;
  try {
    checklist = db.prepare(`
      SELECT CHK_ID, TYPE, STATUS, RESULT
      FROM CHECKLIST_TB
      ORDER BY CAST(SUBSTR(CHK_ID, 10) AS INTEGER)
    `).all();
  } catch (_) {
    return [];
  }
  if (!checklist || checklist.length === 0) return [];

  // RULE XML 로드 (DEBUG_DATA_TB) — chk_id별 정의된 SQL 추출용
  let ruleXml = null;
  try {
    const r = db.prepare("SELECT VALUE FROM DEBUG_DATA_TB WHERE ITEM='RULE' LIMIT 1").all();
    if (r.length) ruleXml = r[0].VALUE || '';
  } catch (_) {}

  /**
   * RULE XML에서 특정 chk_id의 <statement> SQL들 추출.
   * <check id="chk_id" ...><statements><statement><format>...</format>SQL</statement>...</statements></check>
   */
  function extractRuleSqls(chkId) {
    if (!ruleXml) return [];
    // chk_id 시작 위치 찾기
    const startMarker = `<check id="${chkId}"`;
    const startIdx = ruleXml.indexOf(startMarker);
    if (startIdx < 0) return [];
    // 다음 </check> 까지가 이 check의 영역
    const endIdx = ruleXml.indexOf('</check>', startIdx);
    if (endIdx < 0) return [];
    const checkBlock = ruleXml.substring(startIdx, endIdx);
    // <statement>...</statement> 들 추출
    const stmtMatches = checkBlock.match(/<statement>[\s\S]*?<\/statement>/g) || [];
    return stmtMatches.map(m => {
      const inner = m.replace(/<\/?statement>/g, '');
      // <format>...</format> 제거 후 SQL만 남기기
      const sql = inner.replace(/<format>[\s\S]*?<\/format>/, '').trim();
      // XML 엔티티 디코딩 (&apos; → ', &quot; → ", &amp; → &, &lt; → <, &gt; → >)
      return sql
        .replace(/&apos;/g, "'")
        .replace(/&quot;/g, '"')
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&amp;/g, '&');
    }).filter(s => s.length > 0);
  }

  /**
   * SQL 결과를 점검 결과 텍스트로 포맷팅.
   * 첫 줄: SQL 한 줄 요약 / 이어서 결과 행들
   */
  function runRuleSql(sql) {
    try {
      const rows = db.prepare(sql).all();
      if (!rows.length) return '(쿼리 결과 0행)';
      // 컬럼명 추출
      const cols = Object.keys(rows[0]);
      const lines = [cols.join('\t')];
      for (const r of rows.slice(0, 100)) {  // 최대 100행
        lines.push(cols.map(c => String(r[c] !== null && r[c] !== undefined ? r[c] : '')).join('\t'));
      }
      if (rows.length > 100) lines.push(`... 외 ${rows.length - 100}행`);
      return lines.join('\n');
    } catch (e) {
      return `[SQL 실행 실패: ${e.message}]`;
    }
  }

  const result = [];
  for (const row of checklist) {
    const chkId = row.CHK_ID;
    // RESULT가 null이면 STATUS로 보강 (WAIT 등)
    const secumsVerdict = row.RESULT || row.STATUS || 'WAIT';

    // 2) CHECKITEM_TB — 상세 메시지 (BAD 항목은 다중)
    let items = [];
    try {
      items = db.prepare(`
        SELECT ITEM, MSG FROM CHECKITEM_TB
        WHERE CHK_ID = '${chkId}' AND IFNULL(MSG, '') != ''
      `).all().map(r => ({ item: r.ITEM, msg: r.MSG }));
    } catch (_) {}

    // 3) COLLECT_DATA_TB — 실제 점검 명령 + 출력
    let actions = [];
    try {
      actions = db.prepare(`
        SELECT ACTION_ID, ACTION_TYPE, ACTION_DESC, ACTION_VALUE,
               RESULT_OUTPUT, RESULT_ERROR,
               IS_EXECUTED, ERROR_CODE, ERROR_MESSAGE
        FROM COLLECT_DATA_TB
        WHERE SCAN_ID = '${chkId}'
        ORDER BY CAST(ACTION_ID AS INTEGER)
      `).all().map(r => ({
        action_id: r.ACTION_ID,
        action_type: r.ACTION_TYPE,
        action_desc: r.ACTION_DESC,
        action_value: r.ACTION_VALUE,
        result_output: r.RESULT_OUTPUT,
        result_error: r.RESULT_ERROR,
        is_executed: r.IS_EXECUTED,
        error_code: r.ERROR_CODE,
        error_message: r.ERROR_MESSAGE,
      }));
    } catch (_) {}

    // 4) COLLECT_DATA_TB에 출력이 없으면 RULE XML의 SQL을 직접 실행 (폴백)
    //    SecuMS 일부 항목은 COLLECT_DATA_TB를 거치지 않고 U_*_TB / SYSTEM_INFO_TB 등에서
    //    직접 데이터를 끌어오도록 RULE 정의됨 (예: os-linux-2793, os-linux-3076).
    const hasOutput = actions.some(a => (a.result_output || '').trim().length > 0);
    if (!hasOutput) {
      const sqls = extractRuleSqls(chkId);
      if (sqls.length > 0) {
        const synthActions = sqls.map((sql, i) => ({
          action_id: `RULE-${i + 1}`,
          action_type: 'rule_sql',
          action_desc: `RULE 정의 SQL #${i + 1}`,
          action_value: sql,
          result_output: runRuleSql(sql),
          result_error: null,
          is_executed: 'Y',
          error_code: null,
          error_message: null,
        }));
        actions = actions.length ? actions.concat(synthActions) : synthActions;
      }
    }

    result.push({
      chk_id: chkId,
      type: row.TYPE,
      status: row.STATUS,
      secums_verdict: secumsVerdict,
      items,
      actions,
    });
  }
  return result;
}

module.exports = {
  name: 'SecuMS Unix Agent',
  detect,
  extractMeta,
  listTables,
  querySlice,
  extractPackages,
  parseRpmPackage,
  extractDiagnoseItems,  // ← 새 AI 판정용
};

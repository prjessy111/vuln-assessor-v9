'use strict';
/**
 * Mock LLM Provider — raw-data 우선 판정 (v2).
 *
 * 2026-05-26 재설계:
 *   v1: SecuMS 판정(OK/BAD/WAIT)을 분기 기준 → SecuMS와 항상 일치 (검증 불가능)
 *   v2: SecuMS 판정은 참조만, raw 출력의 패턴으로 독립 판정 → 진짜 검증 가능
 *
 * 판정 흐름:
 *   1. TYPE='I' 정보 수집 항목 → 판정 없이 정보제공
 *   2. raw 데이터 없음 → 판정불가
 *   3. 부재 양호 패턴 (No such file 등) → 양호
 *   4. CHK_ID 별 취약 패턴 매칭 → 취약
 *   5. CHK_ID 별 양호 패턴 매칭 → 양호
 *   6. 매칭 없음 → 판정불가 (AI 자동 판정 불가 → 2차 LLM/사람 검토 대상)
 *
 * SecuMS 판정은 agreement 계산 시에만 비교 (aiDiagnose 에서).
 *
 * 1단계 패턴 라이브러리: 핵심 15개 항목 (Linux 7 + Windows 8)
 *   2단계에서 실 진단 결과 보고 확장 예정
 */

const PATTERN_LIBRARY = require('./mockPatterns');
const { getScriptPatterns, normalizeSrvId, SECUMS_INFO_ITEMS } = require('./mockScriptPatterns');
const secumsDump = require('./mockSecumsDump');

// SecuMS raw 경로(os-linux-NN / os-win-NN)를 Script 경로의 검증된 SRV 룰로 재사용하기 위한 역매핑.
// (지시: "스크립트 판정 + SecuMS raw 모두" — 두 소스가 같은 mock 룰 라이브러리를 공유)
let _secumsToSrv = {};
try {
  const _map = require('../../../../data/srv-secums-map.json');
  if (_map && _map.os) {
    for (const osk of Object.keys(_map.os)) {
      for (const [srv, scan] of Object.entries(_map.os[osk])) {
        _secumsToSrv[String(scan).toLowerCase()] = srv;
      }
    }
  }
} catch (_) { /* 매핑 파일 없으면 크로스워크 미적용(기존 동작 유지) */ }
function _secumsSrvId(chkId) {
  return _secumsToSrv[String(chkId || '').toLowerCase()] || null;
}

class MockProvider {
  constructor(cfg) { this.cfg = cfg; this._calls = 0; }

  async ping() { return { ok: true, mock: true }; }

  async complete(arg) {
    this._calls++;
    const text = typeof arg === 'string'
      ? arg
      : ((arg.system || '') + '\n' + (arg.user || ''));

    if (text.includes('CHK_ID:') && text.includes('raw 점검 데이터')) {
      return this._aiDiagnoseMock(text);
    }
    return this._ruleEvalMock(text, arg.responseFormat);
  }

  /**
   * AI 진단 모드 — raw-data 우선 판정.
   */
  _aiDiagnoseMock(text) {
    // 메타 추출
    const chkId = (text.match(/CHK_ID:\s*(\S+)/) || [])[1] || 'unknown';
    const typeMatch = text.match(/타입:\s*(\S+)/);
    const itemType = typeMatch ? typeMatch[1] : null;

    // 점검 액션의 출력 추출 — ```...``` 블록 (```json 제외)
    const outputMatches = text.match(/```(?!json)\s*([\s\S]*?)```/g) || [];
    const outputs = outputMatches
      // Windows reg query의 빈 REG_SZ 값 등에 NUL() 제어문자가 섞여 나온다 — trim으로 안 지워져
      // 패턴/테이블 파싱을 깨뜨리므로 제거
      .map(m => m.replace(/```/g, '').replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '')
        // 어댑터가 XML 엔티티를 디코드하지 않으므로 여기서 복원 (&gt; 등이 마커/패턴 매칭을 깨뜨림)
        .replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&')
        .trim())
      .filter(o => o.length > 0 && !o.startsWith('{'));

    // SecuMS raw(XML Dump 테이블) 언랩 — <Value> 래핑 때문에 라인 기반 룰이 매칭되지 않으므로
    // 평문 변환본을 outputs 에 추가한다 (원본은 부재검사/증거용으로 유지)
    for (let oi = 0, n = outputs.length; oi < n; oi++) {
      if (outputs[oi].includes('<Dump type="table">')) {
        const flat = secumsDump.flattenDumps(outputs[oi]);
        if (flat.trim()) outputs.push(flat);
      }
    }

    // 액션 설명 추출 (### 액션 N: 설명)
    const actionDescs = (text.match(/### 액션 \d+:\s*([^\n]+)/g) || [])
      .map(m => m.replace(/### 액션 \d+:\s*/, '').trim());

    // 프롬프트에 주입된 항목별 판정 기준(LLM과 동일한 기준 섹션)을 추출 —
    // mock 판정의 사유/권고를 LLM 수준으로 구체화하는 데 사용 (기준은 판정 입력이 아니라 설명 보강)
    const crit = this._extractCriteria(text);

    let verdict, reason, evidence, recommend, severity, category, title;
    let viaCrosswalk = false;
    // 1) 전용 패턴(SecuMS os-xxx) 2) Script SRV 룰 3) 크로스워크로 SecuMS os-xxx→SRV 룰 재사용
    let patterns = PATTERN_LIBRARY[chkId] || getScriptPatterns(chkId);
    if (!patterns) {
      const srvId = _secumsSrvId(chkId);
      if (srvId) { patterns = getScriptPatterns(srvId); viaCrosswalk = !!patterns; }
    }

    // ── 1. TYPE='I' 정보 수집 항목 ──────────────────
    // (프롬프트에 타입이 명시되어 있으면 우선 사용)
    // SecuMS(OS_Detail) 기준 INFO 항목 정렬 — 운영 판단 항목은 3-way 정합성을 위해 정보제공으로
    const secumsInfo = SECUMS_INFO_ITEMS && SECUMS_INFO_ITEMS.has(normalizeSrvId(chkId) || chkId);
    const isInfoType = itemType === 'I'
      || secumsInfo
      || /^os-linux-(369|380|389|2778|2793|3076)$/.test(chkId)
      || /^os-win-(139|150|423|444|446|494|4635)$/.test(chkId);
    if (isInfoType) {
      verdict = '정보제공';
      reason = secumsInfo
        ? '운영 판단 항목(SecuMS 기준 INFO) — 시스템 스캔만으로 취약/양호를 단정하지 않습니다. 수집 근거를 참조해 운영자가 판단하십시오.'
        : '정보 수집 항목 — 보안 정책 판정 대상이 아닙니다. raw 출력은 자산 식별/현황 파악용입니다.';
      severity = '하';
      recommend = '';
      evidence = this._extractEvidence(outputs);
      category = (patterns && patterns.category) || this._inferCategory(chkId, outputs);
      title = (patterns && patterns.title) || this._inferTitle(chkId);
      return JSON.stringify({ verdict, category, title, reason, evidence, recommend, severity, safe_type: '' });
    }

    // ── 2. raw 데이터 없음 ────────────────────────
    const allOutput = outputs.join('\n');
    if (outputs.length === 0 || allOutput.trim().length === 0) {
      verdict = '판정불가';
      reason = '점검 raw 데이터가 수집되지 않았습니다. SecuMS Agent 점검 정책 확인 필요.';
      severity = '하';
      recommend = 'SecuMS Agent의 점검 정책 확인 및 재진단';
      evidence = '';
      category = (patterns && patterns.category) || this._inferCategory(chkId, outputs);
      title = (patterns && patterns.title) || this._inferTitle(chkId);
      return JSON.stringify({ verdict, category, title, reason, evidence, recommend, severity, safe_type: '' });
    }

    // ── 2.5 수집기 POLICY_NOTE: 정보성(INFO) 항목 지시 ───
    // 수집기가 기준상 정보제공 항목임을 명시한 경우 (예: BitLocker)
    const policyNote = allOutput.split('\n').map(l => l.trim())
      .find(l => /^POLICY_NOTE:/i.test(l) && /(?:정보제공|verdict\s*=\s*INFO|\(INFO\))/i.test(l));
    if (policyNote) {
      verdict = '정보제공';
      reason = `수집기 정책 노트: ${policyNote.substring(0, 200)}`;
      severity = '하';
      recommend = '';
      evidence = this._extractEvidence(outputs);
      category = (patterns && patterns.category) || this._inferCategory(chkId, outputs);
      title = (patterns && patterns.title) || this._inferTitle(chkId);
      return JSON.stringify({ verdict, category, title, reason, evidence, recommend, severity, safe_type: '' });
    }

    // ── 3. 부재 양호 패턴 ─────────────────────────
    const absence = this._checkAbsence(outputs);
    if (absence.matched) {
      verdict = '양호';
      reason = `점검 대상 미존재로 자동 양호 — ${absence.signal}`;
      severity = '중';
      recommend = '';
      evidence = absence.signal;
      category = (patterns && patterns.category) || this._inferCategory(chkId, outputs);
      title = (patterns && patterns.title) || this._inferTitle(chkId);
      return JSON.stringify({ verdict, category, title, reason, evidence, recommend, severity, safe_type: '부재양호' });
    }

    // ── 3.5 v2 수집기 요약 안전 신호 ───────────────
    // 수집기가 raw 스캔 결과를 결정론적으로 요약한 라인(예: "(no empty-password accounts found ... -> safe)").
    // 에이전트 측 raw 파생 신호이므로 판정 근거로 사용한다. 단 취약 패턴이 우선하도록
    // 항목 전용 취약 룰이 하나라도 매칭되면 이 신호는 무시된다.
    const collectorSafeLine = outputs.join('\n').split('\n')
      .map(l => l.trim())
      .find(l => /\(.*->\s*safe\)\s*$/i.test(l) || /\(safe\)\s*$/i.test(l) || /->\s*[^\n]*\(safe\)/i.test(l));
    if (collectorSafeLine) {
      const vulnPre = patterns
        ? this._matchPatterns(allOutput, patterns.vuln || [], outputs, actionDescs)
        : null;
      if (!vulnPre) {
        verdict = '양호';
        reason = `수집기 스캔 요약: ${collectorSafeLine.substring(0, 180)}`
          + (crit.safeCond ? ` (양호 기준: ${crit.safeCond})` : '');
        severity = '중';
        recommend = '';
        evidence = collectorSafeLine.substring(0, 200);
        category = (patterns && patterns.category) || this._inferCategory(chkId, outputs);
        title = (patterns && patterns.title) || this._inferTitle(chkId);
        return JSON.stringify({ verdict, category, title, reason, evidence, recommend, severity, safe_type: '값준수양호' });
      }
    }

    // ── 4 & 5. CHK_ID 별 패턴 라이브러리 매칭 ──────
    if (patterns) {
      // 4. 취약 패턴 우선 (모든 취약 신호 체크)
      const vulnHit = this._matchPatterns(allOutput, patterns.vuln || [], outputs, actionDescs);
      if (vulnHit) {
        verdict = '취약';
        severity = patterns.severity || '상';
        reason = vulnHit.reason
          + (crit.vulnCond ? ` — 취약 기준: ${crit.vulnCond}` : '');
        evidence = vulnHit.evidence || this._extractEvidence(outputs);
        recommend = crit.remedy || patterns.recommend || 'raw 출력을 검토하여 보안 정책에 맞게 조치';
        category = patterns.category || this._inferCategory(chkId, outputs);
        title = patterns.title || this._inferTitle(chkId);
        if (viaCrosswalk) reason += ' [크로스워크 재사용 룰 — 형식 검증 전, 재검토 권장]';
        return JSON.stringify({ verdict, category, title, reason, evidence, recommend, severity, safe_type: '', provisional: viaCrosswalk });
      }

      // 5. 양호 패턴
      const safeHit = this._matchPatterns(allOutput, patterns.safe || [], outputs, actionDescs);
      if (safeHit) {
        verdict = '양호';
        severity = '중';
        reason = safeHit.reason
          + (crit.safeCond ? ` (양호 기준: ${crit.safeCond})` : '');
        evidence = safeHit.evidence || this._extractEvidence(outputs);
        recommend = '';
        category = patterns.category || this._inferCategory(chkId, outputs);
        title = patterns.title || this._inferTitle(chkId);
        if (viaCrosswalk) reason += ' [크로스워크 재사용 룰 — 형식 검증 전, 재검토 권장]';
        return JSON.stringify({ verdict, category, title, reason, evidence, recommend, severity, safe_type: '값준수양호', provisional: viaCrosswalk });
      }
    }

    // ── 5.7 SecuMS Dump 구조화 generic 판정 ─────────
    // 항목 전용 룰이 없어도 컬럼 시그니처(파일권한/공유/권한할당/그룹멤버)로 결정론 판정 가능한 경우
    if (allOutput.includes('<Dump type="table">')) {
      const g = secumsDump.evaluateGeneric(allOutput);
      if (g) {
        verdict = g.verdict;
        reason = g.reason
          + (verdict === '취약' && crit.vulnCond ? ` — 취약 기준: ${crit.vulnCond}` : '')
          + (verdict === '양호' && crit.safeCond ? ` (양호 기준: ${crit.safeCond})` : '');
        severity = (patterns && patterns.severity) || '중';
        recommend = verdict === '취약' ? (crit.remedy || (patterns && patterns.recommend) || 'raw 근거를 검토하여 보안 기준에 맞게 조치') : '';
        evidence = g.evidence || this._extractEvidence(outputs);
        category = (patterns && patterns.category) || this._inferCategory(chkId, outputs);
        title = (patterns && patterns.title) || this._inferTitle(chkId);
        return JSON.stringify({ verdict, category, title, reason, evidence, recommend, severity, safe_type: verdict === '양호' ? '값준수양호' : '' });
      }
    }

    // ── 6. 매칭 없음 → 판정불가 (AI 자동 규칙 미적용 — LLM/사람 상세 검토 필요) ───────────
    // 정보제공(verdict)은 step 1의 진짜 정보수집 항목(TYPE='I')에만 사용한다.
    // 패턴 미매칭은 "정보"가 아니라 "AI가 판정 못함"이므로 판정불가로 둬야
    // 2차 LLM 상세 진단(review_needed 필터 = {취약, 판정불가})이 이 항목을 재검토한다.
    verdict = '판정불가';
    reason = 'AI 자동 판정 규칙을 적용할 수 없습니다. LLM 상세 검토 또는 사람 검토가 필요합니다.'
      + (crit.intent ? ` [점검 의도: ${crit.intent}]` : '');
    severity = '하';
    recommend = (patterns && patterns.recommend) || '수집된 raw 출력 검토 후 수동 판정';
    evidence = this._extractEvidence(outputs);
    category = (patterns && patterns.category) || this._inferCategory(chkId, outputs);
    title = (patterns && patterns.title) || this._inferTitle(chkId);
    return JSON.stringify({ verdict, category, title, reason, evidence, recommend, severity, safe_type: '' });
  }

  /**
   * 프롬프트에 주입된 항목별 판정 기준 섹션 추출 (buildCriteriaSection 형식).
   * LLM이 보는 것과 동일한 기준(점검 의도/양호 기준/취약 조건/2026 조치법)을
   * mock 판정의 사유·권고 텍스트 보강에 재사용한다. 순수 문자열 추출 — 결정론적.
   */
  _extractCriteria(text) {
    const pick = re => { const m = text.match(re); return m ? m[1].trim() : ''; };
    return {
      intent:   pick(/^- 점검 의도:\s*(.+)$/m),
      safeCond: pick(/^- 양호 기준:\s*(.+)$/m),
      vulnCond: pick(/^- 취약 조건:\s*(.+)$/m),
      spec:     pick(/^- 판정 기준:\s*(.+)$/m),
      remedy:   pick(/^- 조치법\(=안전한 상태는 이 조치가 적용된 상태\):\s*(.+)$/m),
    };
  }

  /**
   * 부재 양호 패턴 검사 — "점검 대상이 없으니 안전".
   *
   * 핵심 원칙:
   *   - 라인을 종류별로 분류: 명령어/마커/XML태그/빈줄 (= "기반 라인") vs 실제 결과
   *   - "기반 라인" 만 있고 모든 명령어가 부재 신호로만 응답했으면 → 부재 양호
   *   - 하나라도 의미있는 결과가 있으면 부재 아님
   *
   * 부재 신호 (OS 공통):
   *   - Linux/Unix: No such file or directory, does not exist, cannot access, not found
   *   - Windows: 지정된 서비스가 ... 없습니다, Registry key value not found, 실패 1060
   *   - 서비스 미설치/미실행: not installed, 미설치, 미실행, Service is not installed
   *   - SecuMS XML: <Rows count="0"
   */
  _checkAbsence(outputs) {
    if (!outputs || !outputs.length) return { matched: false };
    const joined = outputs.join('\n');

    // ── v2 수집기(ai_ready_script_v2) 명시 마커 우선 처리 ──
    // 수집기가 raw 수집 시점에 결정론적으로 판별해 넣은 신호. SecuMS verdict가 아니라
    // 에이전트 측 raw 파생 신호이므로 판정 입력으로 사용 가능(P1 위반 아님).
    // 대상 서비스가 존재(detected)하면 설정파일 부재는 수집오류일 수 있으므로 부재양호 금지 (LLM 규칙 (아)①)
    if (/SERVICE_PRESENCE=detected/i.test(joined)) return { matched: false };
    // 수집 권한 거부 → 부재가 아니라 수집 실패 → 판정불가 흐름으로
    if (/COLLECTION_HINT=collection_denied/i.test(joined)) return { matched: false };
    const hintTargetAbsent = /COLLECTION_HINT=target_absent/i.test(joined);
    const svcNotDetected = /SERVICE_PRESENCE=not_detected/i.test(joined);

    // 0) "설정값 부재" 신호 — 부재양호 아님 (LLM 판정 기준 이식).
    //    레지스트리 키/정책 값이 없으면 시스템 기본값으로 동작하므로, 기본 동작을
    //    기준에 비춰 판정해야 한다(강화 키 부재 = 강화 미적용 = 취약 가능성).
    //    command not found 는 수집 도구 부재(수집 실패)이지 점검 대상 부재가 아니다.
    //    이 신호가 잡힌 라인은 부재 카운트에서 제외 → 패턴 판정/판정불가로 흘려보낸다.
    const VALUE_ABSENCE_PATTERNS = [
      /registry key value not found/i,
      /unable to find the specified registry/i,
      /지정된 레지스트리[^\n]*(?:찾을 수 없|없습니다)/,
      /레지스트리[^\n]*(?:찾을 수 없|없습니다)/,
      // 수집 도구 부재 = 수집실패. 단, 점검 대상 데몬(named/httpd 등)의 not found 는 대상 부재이므로 제외
      /^(?!.*(?:named|httpd|nginx|apache2?|vsftpd|proftpd|snmpd|sendmail|exim4?|smbd|mysqld|dnsmasq)\b).*command not found/i,
      /명령(?:어)?를? 찾을 수 없/,
      // v2 수집기: 값이 비어있거나 미설정 — 기본값 동작을 판정해야 하므로 부재양호 금지
      /COLLECTION_HINT=empty_or_unset/i,
    ];

    // 1) "점검 대상 객체(파일/서비스/데몬/패키지) 부재" 신호 — 이때만 부재양호 후보
    const ABSENCE_PATTERNS = [
      // Linux/Unix
      /no such file or directory/i,
      /그런 파일이나 디렉터리가 없습니다/,
      /does not exist/i,
      /cannot access/i,
      /cannot open file/i,
      /not found/i,
      // Windows
      /지정된 서비스가[^\n]*없습니다/,
      /\[SC\][^\n]*실패\s+1060/,    // 서비스 없음 에러 코드
      /OpenService[^\n]*(?:실패|FAILED)[^\n]*1060/i,
      /The system cannot find/i,
      // 미설치
      /not installed/i,
      /미설치/,
      /미실행/,
      /Service is not installed/i,
      /^which:\s+no\s+\S+\s+in\s/i,          // which: no xterm in (...)
      /->\s*대상 없음\)?\s*$/,                 // 수집기 요약: (... -> 대상 없음)
      /file absent or no match/i,             // 수집기 주석: 파일 부재/매칭 없음
      /absence-good if \w+ not_detected/i,    // 수집기 주석: 서비스 미검출 시 부재양호 지시
      // 점검 "대상 데몬" 바이너리의 command not found 는 수집실패가 아니라 대상 부재
      /(?:named|httpd|nginx|apache2?|vsftpd|proftpd|snmpd|sendmail|exim4?|smbd|mysqld|dnsmasq|tlntadmn)\b[^\n]*command not found/i,
    ];

    // v2 수집기 마커: 대상 부재 힌트가 있으면 관련 라인도 객체 부재 신호로 인정
    if (hintTargetAbsent) {
      ABSENCE_PATTERNS.push(
        /COLLECTION_HINT=target_absent/i,
        /is not recognized as (?:the name of )?a cmdlet/i,   // 점검 도구 자체 미설치(appcmd=IIS, tlntadmn=Telnet 등)
        /^ERROR:\s*The term/i,
      );
    }
    if (svcNotDetected) {
      ABSENCE_PATTERNS.push(/SERVICE_PRESENCE=not_detected/i);
    }

    // 2) 라인별로 분석 — 결과 라인이 모두 부재 신호인지 확인
    const result = this._classifyOutputLines(outputs, ABSENCE_PATTERNS, VALUE_ABSENCE_PATTERNS);

    // 케이스 A0: 설정값 부재 라인이 하나라도 있으면 부재양호로 단정하지 않는다.
    // (값 부재 = 기본값 동작 → 항목별 룰/판정불가로 흘려보내 재검토)
    if (result.valueAbsenceHits > 0) {
      return { matched: false };
    }

    // 케이스 A: 명령은 실행됐으나 결과 라인이 0 — "대상없음(안전)"과 "수집실패(unknown)"를
    // 구분할 수 없다. 감사상 false-양호(취약을 안전으로 오판)를 막기 위해 자동 양호로 단정하지 않고
    // 판정 흐름으로 흘려보낸다(→ 룰 미매칭 시 판정불가 → LLM/사람 재검토). 명시적 부재신호(B/D)만 양호.
    if (result.resultLines === 0 && result.cmdLines > 0) {
      return { matched: false };
    }

    // 케이스 B: 결과 라인이 있는데 100% 부재 신호
    if (result.resultLines > 0 && result.absenceHits === result.resultLines) {
      return { matched: true, signal: result.firstAbsenceLine.substring(0, 200) };
    }

    // 케이스 C: 결과 라인이 부분만 부재 신호 (예: 일부 명령은 데이터 있음)
    // → 부재 아님, 일반 판정 흐름으로
    if (result.absenceHits > 0 && result.absenceHits < result.resultLines) {
      return { matched: false };
    }

    // 케이스 D: SecuMS XML 모든 dump 가 0 행
    if (/<Rows count="0"/i.test(joined)) {
      const allZero = outputs.every(o => !/<Rows count="[1-9]/.test(o));
      if (allZero) return { matched: true, signal: '점검 결과 0행 (대상 미발견)' };
    }

    return { matched: false };
  }

  /**
   * raw 출력의 라인들을 분류.
   *   - cmdLines: 명령어 라인 ($ cmd, cmd# cmd, # cmd)
   *   - resultLines: 실제 결과 라인 (명령어/마커/태그/빈줄 제외)
   *   - absenceHits: 결과 라인 중 부재 신호 매칭된 수
   *   - firstAbsenceLine: 첫 부재 신호 라인 (사유 표시용)
   */
  _classifyOutputLines(outputs, absencePatterns, valueAbsencePatterns = []) {
    let cmdLines = 0, resultLines = 0, absenceHits = 0, valueAbsenceHits = 0;
    let firstAbsenceLine = '';

    for (const out of outputs) {
      const lines = (out || '').split('\n');
      for (const raw of lines) {
        const line = raw.trim();
        if (!line) continue;

        // 명령어 라인 — Linux ($ cmd), Windows (cmd# cmd), 일반 (# cmd)
        if (/^(\$|cmd#|#)\s+\w/.test(line)) { cmdLines++; continue; }
        // 마커 없이 에코된 명령줄 (v2 수집기 일부 구간) — 결과 라인으로 오인하지 않는다
        if (/^(?:ls|cat|grep|egrep|find|stat|ps|netstat|awk|cut|which|systemctl|chkconfig|service|crontab|rpm|dpkg|sysctl|w32tm|sc|reg|net|wmic|icacls|cacls|schtasks|type|dir)\s+\S/.test(line)) { cmdLines++; continue; }
        // SecuMS 마커 ([ keyword ][S] / [E])
        if (/^\[\s*[a-zA-Z0-9_|]+\s*\]\[(?:S|E)\]$/.test(line)) continue;
        // v2 수집기 래퍼(AI_RAW_CONTEXT / ai_evidence_block) 메타 라인 — 점검 결과가 아니므로 제외.
        // 이 라인들을 결과로 세면 순수 부재 항목도 "결과 존재"로 오인되어 부재양호가 절대 안 나온다.
        if (/^(?:AI_RAW_CONTEXT|RAW_OUTPUT_BEGIN|AI_EVIDENCE_BLOCK_(?:BEGIN|END)|RAW_COMMAND_OUTPUT_(?:BEGIN|END))$/.test(line)) continue;
        if (/^(?:schema|evidence_schema|source|check_ids|host|os|os_family|collection_profile|collection_status|collector_privilege|started_at_utc|duration_ms|output_bytes|output_format|error_text|command_marker|command|commands|raw_begin_marker|raw_end_marker|script_data_role|script_verdict_source|judgment_mode|judgment_policy|safe_subtype_policy|decision_route|allowed_verdicts|collection_signals|fast_hints|truncated|collection_config|scan_scope|fsi_scan_scope)=/.test(line)) continue;
        // 구분자 라인 (------------)
        if (/^[-=]{3,}$/.test(line)) continue;
        // flatten 이 합성한 테이블 컬럼 헤더 라인 (전부 대문자/언더스코어 탭 구분) — 결과 아님
        if (/^[A-Z][A-Z_ ]*(?:\t[A-Z][A-Z_ ]*)+$/.test(line)) continue;
        // XML 메타 라인 (헤더, 빈 결과 태그, Columns 정의 등 — 진짜 데이터 아님)
        if (/^<\?xml/.test(line)) continue;
        if (/^<\/?Dump[\s>]/i.test(line)) continue;
        if (/^<\/?Columns[\s>]/i.test(line)) continue;
        if (/^<\/?Column>/i.test(line)) continue;
        if (/^<Rows count="0"\s*\/?>/i.test(line)) continue;
        if (/^<\/Rows>$/i.test(line)) continue;
        if (/^<\/?Row[\s>]/i.test(line)) continue;
        // 일반 XML 닫는 태그
        if (/^<\/[A-Za-z][^>]*>$/.test(line)) continue;
        // 주석 라인 (#으로 시작하는 cat 결과 등)
        if (line.startsWith('#') && !/^#\s+\w+/.test(line)) continue;

        // 결과 라인으로 카운트
        resultLines++;
        // 값 부재 신호를 먼저 검사 — "not found" 류가 객체 부재와 겹치므로 우선순위 필요
        if (valueAbsencePatterns.some(p => p.test(line))) {
          valueAbsenceHits++;
          continue;
        }
        if (absencePatterns.some(p => p.test(line))) {
          absenceHits++;
          if (!firstAbsenceLine) firstAbsenceLine = line;
        }
      }
    }

    return { cmdLines, resultLines, absenceHits, valueAbsenceHits, firstAbsenceLine };
  }

  /**
   * CHK_ID 별 패턴 매칭. 패턴은 정규식 또는 함수.
   * patterns: [{ pattern, reason, severity?, evidence_fmt? }]
   */
  _matchPatterns(text, patterns, outputs, actionDescs) {
    for (const p of patterns) {
      let matched = null;
      if (typeof p.pattern === 'function') {
        matched = p.pattern(text, outputs, actionDescs);
        if (matched) {
          return {
            reason: typeof matched === 'string' ? matched : (p.reason || '패턴 매칭'),
            evidence: typeof matched === 'object' && matched.evidence ? matched.evidence : '',
          };
        }
      } else if (p.pattern instanceof RegExp) {
        const m = text.match(p.pattern);
        if (m) {
          const ev = m[0].length > 200 ? m[0].substring(0, 200) + '...' : m[0];
          return {
            reason: p.reason || '패턴 매칭',
            evidence: ev.trim(),
          };
        }
      }
    }
    return null;
  }

  _extractEvidence(outputs) {
    if (!outputs || !outputs.length) return '';
    const out = outputs[0];
    if (out.includes('<Dump type="table">')) {
      const rowsMatch = out.match(/<Rows count="(\d+)"/);
      if (rowsMatch && parseInt(rowsMatch[1], 10) === 0) return '(결과 0행)';
      const vals = (out.match(/<Value>([^<]*)<\/Value>/g) || [])
        .slice(0, 6).map(v => v.replace(/<\/?Value>/g, ''));
      if (vals.length) return vals.join(' | ').substring(0, 250);
      return '';
    }
    const lines = out.split('\n').map(l => l.trim())
      .filter(l => l && !l.startsWith('#') && !l.startsWith('<?xml') && !l.startsWith('<'));
    return lines.slice(0, 3).join(' | ').substring(0, 250);
  }

  _inferCategory(chkId, outputs) {
    const allOut = (outputs[0] || '').toLowerCase();
    if (chkId.startsWith('os-win-')) {
      if (/firewall|netbios/.test(allOut)) return '네트워크 보안';
      if (/password|lockout|administrator|useraccount|group/.test(allOut)) return '계정 관리';
      if (/registry|regissstry/.test(allOut)) return '레지스트리 보안';
      if (/service|startmode/.test(allOut)) return '서비스 관리';
      if (/permission|acl|share/.test(allOut)) return '파일/공유 권한';
      if (/eventlog|audit|evtx/.test(allOut)) return '로그 관리';
      if (/schedule|task/.test(allOut)) return '예약 작업';
      if (/encryption|ntlm|legacy/.test(allOut)) return '암호화/인증';
      return '시스템 보안';
    }
    if (/sshd|telnet|login|passwd|shadow|pam/.test(allOut)) return '계정 관리';
    if (/snmp|rpc|nfs|ftp/.test(allOut)) return '서비스 관리';
    if (/permission|chmod|owner/.test(allOut)) return '파일 권한';
    if (/log|audit|rsyslog/.test(allOut)) return '로그 관리';
    return '시스템 보안';
  }

  _inferTitle(chkId) {
    // 기존 v1 titles 유지 (생략 — 별도 파일에서 재사용)
    const titles = require('./mockTitles');
    return titles[chkId] || chkId;
  }

  /**
   * 기존 룰 평가 모드.
   * P2(결정론) 준수: 호출 횟수 홀짝 기본 판정 제거 — 동일 입력은 항상 동일 출력.
   * 매칭 없으면 판정불가로 두어 임의 pass/fail을 만들지 않는다.
   */
  _ruleEvalMock(text, responseFormat) {
    const lower = text.toLowerCase();
    let status = '판정불가', reason = '자동 판정 규칙 미매칭 — 수동 검토 필요', evidence = '';
    const portMatch = text.match(/port\s*=\s*(2[135])\b[^\n]*listen/i) || text.match(/listen[^\n]*port\s*=\s*(2[135])\b/i);
    if (/취약하다|취약 사례|bad case/i.test(text)) { status = '취약'; reason = '룰에 명시된 취약 조건 충족'; }
    else if (/양호하다|good case|이상 없/i.test(text)) { status = '양호'; reason = '정상'; }
    else if (lower.includes('permitrootlogin yes')) { status = '취약'; reason = 'PermitRootLogin yes'; evidence = 'PermitRootLogin yes'; }
    else if (portMatch) { status = '취약'; reason = `평문/취약 서비스 포트(${portMatch[1]}) LISTEN 확인`; evidence = `port=${portMatch[1]} listening`; }
    else if (/permission\s+0?(?:600|640|644|700|750|755)\b/i.test(text)) { status = '양호'; reason = '파일 권한이 기준 범위 내로 설정됨'; evidence = (text.match(/permission\s+\S+/i) || [''])[0]; }
    if (responseFormat === 'json') return JSON.stringify({ status, reason, evidence });
    return `${status}: ${reason}`;
  }
}

module.exports = MockProvider;

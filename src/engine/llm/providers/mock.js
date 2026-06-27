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
const { getScriptPatterns } = require('./mockScriptPatterns');

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
      .map(m => m.replace(/```/g, '').trim())
      .filter(o => o.length > 0 && !o.startsWith('{'));

    // 액션 설명 추출 (### 액션 N: 설명)
    const actionDescs = (text.match(/### 액션 \d+:\s*([^\n]+)/g) || [])
      .map(m => m.replace(/### 액션 \d+:\s*/, '').trim());

    let verdict, reason, evidence, recommend, severity, category, title;
    const patterns = PATTERN_LIBRARY[chkId] || getScriptPatterns(chkId);

    // ── 1. TYPE='I' 정보 수집 항목 ──────────────────
    // (프롬프트에 타입이 명시되어 있으면 우선 사용)
    const isInfoType = itemType === 'I'
      || /^os-linux-(369|380|389|2778|2793|3076)$/.test(chkId)
      || /^os-win-(139|150|423|444|446|494|4635)$/.test(chkId);
    if (isInfoType) {
      verdict = '정보제공';
      reason = '정보 수집 항목 — 보안 정책 판정 대상이 아닙니다. raw 출력은 자산 식별/현황 파악용입니다.';
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

    // ── 4 & 5. CHK_ID 별 패턴 라이브러리 매칭 ──────
    if (patterns) {
      // 4. 취약 패턴 우선 (모든 취약 신호 체크)
      const vulnHit = this._matchPatterns(allOutput, patterns.vuln || [], outputs, actionDescs);
      if (vulnHit) {
        verdict = '취약';
        severity = patterns.severity || '상';
        reason = vulnHit.reason;
        evidence = vulnHit.evidence;
        recommend = patterns.recommend || 'raw 출력을 검토하여 보안 정책에 맞게 조치';
        category = patterns.category || this._inferCategory(chkId, outputs);
        title = patterns.title || this._inferTitle(chkId);
        return JSON.stringify({ verdict, category, title, reason, evidence, recommend, severity, safe_type: '' });
      }

      // 5. 양호 패턴
      const safeHit = this._matchPatterns(allOutput, patterns.safe || [], outputs, actionDescs);
      if (safeHit) {
        verdict = '양호';
        severity = '중';
        reason = safeHit.reason;
        evidence = safeHit.evidence;
        recommend = '';
        category = patterns.category || this._inferCategory(chkId, outputs);
        title = patterns.title || this._inferTitle(chkId);
        return JSON.stringify({ verdict, category, title, reason, evidence, recommend, severity, safe_type: '값준수양호' });
      }
    }

    // ── 6. 매칭 없음 → 판정불가 (AI 자동 규칙 미적용 — LLM/사람 상세 검토 필요) ───────────
    // 정보제공(verdict)은 step 1의 진짜 정보수집 항목(TYPE='I')에만 사용한다.
    // 패턴 미매칭은 "정보"가 아니라 "AI가 판정 못함"이므로 판정불가로 둬야
    // 2차 LLM 상세 진단(review_needed 필터 = {취약, 판정불가})이 이 항목을 재검토한다.
    verdict = '판정불가';
    reason = 'AI 자동 판정 규칙을 적용할 수 없습니다. LLM 상세 검토 또는 사람 검토가 필요합니다.';
    severity = '하';
    recommend = (patterns && patterns.recommend) || '수집된 raw 출력 검토 후 수동 판정';
    evidence = this._extractEvidence(outputs);
    category = (patterns && patterns.category) || this._inferCategory(chkId, outputs);
    title = (patterns && patterns.title) || this._inferTitle(chkId);
    return JSON.stringify({ verdict, category, title, reason, evidence, recommend, severity, safe_type: '' });
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

    // 1) 빠른 부재 신호 매칭 (OS 공통)
    const ABSENCE_PATTERNS = [
      // Linux/Unix
      /no such file or directory/i,
      /does not exist/i,
      /cannot access/i,
      /not found/i,
      // Windows
      /지정된 서비스가[^\n]*없습니다/,
      /Registry key value not found/i,
      /\[SC\][^\n]*실패\s+1060/,    // 서비스 없음 에러 코드
      /The system cannot find/i,
      // 미설치
      /not installed/i,
      /미설치/,
      /미실행/,
      /Service is not installed/i,
    ];

    // 2) 라인별로 분석 — 결과 라인이 모두 부재 신호인지 확인
    const result = this._classifyOutputLines(outputs, ABSENCE_PATTERNS);

    // 케이스 A: 결과 라인이 아예 없음 (명령어만 있음) — 데이터 자체 없음
    if (result.resultLines === 0 && result.cmdLines > 0) {
      return { matched: true, signal: '모든 점검 명령이 빈 결과 반환 (대상 미존재 추정)' };
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
  _classifyOutputLines(outputs, absencePatterns) {
    let cmdLines = 0, resultLines = 0, absenceHits = 0;
    let firstAbsenceLine = '';

    for (const out of outputs) {
      const lines = (out || '').split('\n');
      for (const raw of lines) {
        const line = raw.trim();
        if (!line) continue;

        // 명령어 라인 — Linux ($ cmd), Windows (cmd# cmd), 일반 (# cmd)
        if (/^(\$|cmd#|#)\s+\w/.test(line)) { cmdLines++; continue; }
        // SecuMS 마커 ([ keyword ][S] / [E])
        if (/^\[\s*[a-zA-Z0-9_|]+\s*\]\[(?:S|E)\]$/.test(line)) continue;
        // 구분자 라인 (------------)
        if (/^[-=]{3,}$/.test(line)) continue;
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
        if (absencePatterns.some(p => p.test(line))) {
          absenceHits++;
          if (!firstAbsenceLine) firstAbsenceLine = line;
        }
      }
    }

    return { cmdLines, resultLines, absenceHits, firstAbsenceLine };
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

  /** 기존 룰 평가 모드 (변경 없음) */
  _ruleEvalMock(text, responseFormat) {
    const lower = text.toLowerCase();
    let status = '판정불가', reason = '데이터 부족', evidence = '';
    if (/취약하다|취약 사례|bad case/i.test(text)) { status = '취약'; reason = '룰에 명시된 취약 조건 충족'; }
    else if (/양호하다|good case|이상 없/i.test(text)) { status = '양호'; reason = '정상'; }
    else if (lower.includes('permitrootlogin yes')) { status = '취약'; reason = 'PermitRootLogin yes'; evidence = 'PermitRootLogin yes'; }
    else { status = this._calls % 2 === 0 ? '양호' : '취약'; reason = `호출 #${this._calls} 의 기본 판정`; }
    if (responseFormat === 'json') return JSON.stringify({ status, reason, evidence });
    return `${status}: ${reason}`;
  }
}

module.exports = MockProvider;

'use strict';
/**
 * v9.15 회귀 테스트 — 이번 세션에서 고치거나 추가한 핵심 유닛을 고정.
 *  ① agentReportAdapter: judgment(findings) → diagnoses 레코드 변환 (리포트 재사용)
 *  ② adhocJudge: AD 전용 판정기 인식·판정 + BOM 파싱 (원격/오프라인 판정 코어)
 */
const path = require('path');
const fs = require('fs');
const { buildDiagnosisFromAgentItem, normVerdict } = require('../src/engine/agentReportAdapter');
const adhoc = require('../src/engine/adhocJudge');

describe('v9.15 · agentReportAdapter (리포트 재사용)', () => {
  test('normVerdict 매핑', () => {
    expect(normVerdict('취약')).toBe('취약');
    expect(normVerdict('양호')).toBe('양호');
    expect(normVerdict('점검불가')).toBe('판정불가');
    expect(normVerdict('아무거나')).toBe('판정불가');
  });

  test('다항목(AD형) → diagnoses 레코드 + 카운트', () => {
    const item = {
      item_id: 'AGI-1', title: 'AD DC 점검', category: 'AD',
      judgment: {
        verdict: '취약', model: 'structured:ad_dc', backend: 'mock',
        findings: [
          { id: 'AM17', item: 'PASSWD_NOTREQD', verdict: '취약', reason: 'r', evidence: 'e', sev: '상' },
          { id: 'AM18', item: 'DONT_EXPIRE', verdict: '양호', reason: 'none' },
          { id: 'IC05', item: 'krbtgt', verdict: '판정불가', reason: '근거없음' },
        ],
      },
    };
    const diag = buildDiagnosisFromAgentItem(item, { server_id: 62, hostname: 'JESSY-PC', os_type: 'windows' }, 9001);
    expect(diag.diagnose_type).toBe('llm');       // 기존 /reports 필터 통과
    expect(diag.status).toBe('success');
    expect(diag.assessment_id).toBe(9001);
    expect(diag.total_count).toBe(3);
    expect(diag.vuln_count).toBe(1);
    expect(diag.safe_count).toBe(1);
    expect(diag.na_count).toBe(1);
    expect(diag.results[0].chk_id).toBe('AM17');
    expect(diag.results[0].ai_verdict).toBe('취약');
    expect(diag.results[0].ai_title).toBe('PASSWD_NOTREQD');
  });

  test('단일 판정(findings 없음) → 1행', () => {
    const item = { item_id: 'AGI-2', title: 'passwd 점검', judgment: { verdict: '양호', reason: 'root 외 UID0 없음', findings: [] } };
    const diag = buildDiagnosisFromAgentItem(item, { hostname: 'jessy207', os_type: 'linux' }, 9002);
    expect(diag.total_count).toBe(1);
    expect(diag.safe_count).toBe(1);
    expect(diag.results[0].ai_verdict).toBe('양호');
    expect(diag.results[0].ai_title).toContain('passwd');
  });
});

describe('v9.15 · adhocJudge AD 판정기', () => {
  const fx = path.join(__dirname, 'fixtures', 'ad-sample.json');
  const raw = fs.readFileSync(fx, 'utf8');

  test('AD 결과 인식 + 취약/양호 혼재 판정', () => {
    const r = adhoc.detectAndEvaluate(raw);
    expect(r).not.toBeNull();
    expect(r.evaluator).toBe('ad_dc');
    const vuln = r.findings.filter(f => f.verdict === '취약').length;
    const safe = r.findings.filter(f => f.verdict === '양호').length;
    expect(vuln).toBeGreaterThan(0);
    expect(safe).toBeGreaterThan(0);
    // 대표 규칙: MinPasswordLength=7 → 취약
    const minPw = r.findings.find(f => /최소 패스워드 길이/.test(f.item));
    expect(minPw && minPw.verdict).toBe('취약');
  });

  test('BOM(UTF-8) 붙은 AD JSON도 파싱', () => {
    expect(adhoc.detectAndEvaluate('﻿' + raw)).not.toBeNull();
  });

  test('비 AD 텍스트 → null (오탐 방지)', () => {
    expect(adhoc.detectAndEvaluate('root:x:0:0:root:/root:/bin/bash')).toBeNull();
    expect(adhoc.detectAndEvaluate('그냥 아무 텍스트')).toBeNull();
  });
});

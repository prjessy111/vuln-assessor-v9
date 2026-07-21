'use strict';
/**
 * 애드혹(ad-hoc) 스크립트 점검 판정기.
 *
 * 목적: 사전 등록된 항목이 아니라, 그때그때 받은 임의 스크립트 결과물을
 *       "결과물 + 자연어 판정 지침"만으로 즉석 판정한다.
 *
 * 판정 백엔드 (시스템 방침: mock 기본, 로컬 LLM 보조 — 망분리/폐쇄망):
 *   - mock  : 외부 호출 없이 결과물의 범용 위험 신호를 결정론적으로 스캔 (기본)
 *   - local : 사내 로컬 LLM(LSAP/ollama)으로 판정 지침대로 정밀 판정 (보조)
 *   ★ Claude 등 외부 인터넷 API는 사용하지 않는다(망분리 환경, raw 데이터 외부 유출 금지).
 *
 * 반환: { backend, findings: [{ item, verdict, reason, evidence }], summary, note }
 *   verdict: '취약' | '양호' | '판정불가'
 */

// mock 기본 판정에 쓰는 범용 위험 신호 — OS/AD/DB 공통. raw 텍스트(형식 무관)에서 스캔.
// 각 신호: { key, item, test(raw), evidence(raw) }
const RISK_SIGNALS = [
  { item: 'SMB1 프로토콜 활성', sev: '상',
    test: /EnableSMB1Protocol["'\s:=]+true/i,
    reason: 'SMB1은 알려진 취약 프로토콜(랜섬웨어 확산 경로)로 비활성화해야 합니다.' },
  { item: 'GPP cpassword 노출', sev: '상',
    test: /cpassword/i,
    reason: 'SYSVOL GPP에 cpassword가 남아 있으면 복호화 가능한 계정 암호가 노출됩니다.' },
  { item: '가역 암호화 저장(Reversible Encryption)', sev: '상',
    test: /ReversibleEncryptionEnabled["'\s:=]+true/i,
    reason: '암호를 복호화 가능한 형태로 저장하는 설정으로 평문 노출과 동등합니다.' },
  { item: 'WinRM 평문 전송 허용(AllowUnencrypted)', sev: '상',
    test: /AllowUnencrypted["'\s:=]+(1|true)/i,
    reason: 'WinRM 평문 전송 허용 시 자격증명·명령이 도청될 수 있습니다.' },
  { item: '익명 접근 제한 미설정(RestrictAnonymous=0)', sev: '중',
    test: /RestrictAnonymous["'\s:=]+0\b/i,
    reason: '익명 사용자의 SAM/공유 열거를 허용해 정보 노출 위험이 있습니다.' },
  { item: 'Kerberos 사전인증 미요구(DONT_REQ_PREAUTH)', sev: '상',
    test: /DONT_REQ_PREAUTH|4194304/,
    reason: 'AS-REP Roasting 공격에 노출됩니다(오프라인 암호 크래킹).' },
  { item: '비밀번호 불필요 계정(PASSWD_NOTREQD)', sev: '상',
    test: /PASSWD_NOTREQD/,
    reason: '빈 비밀번호를 허용하는 계정이 존재합니다.' },
  { item: '비밀번호 무기한(DONT_EXPIRE_PASSWD)', sev: '중',
    test: /DONT_EXPIRE_PASSWD/,
    reason: '비밀번호가 만료되지 않는 계정은 장기 탈취 위험이 있습니다.' },
  { item: 'LM 해시 저장 허용(NoLMHash=0)', sev: '중',
    test: /NoLMHash["'\s:=]+0\b/i,
    reason: '취약한 LM 해시 저장을 허용합니다.' },
];

// ── AD 도메인 컨트롤러 구조 판정기 ────────────────────────────────
// ad_collect.ps1 이 생성한 JSON(<host>_AD_DC.txt)을 구조적으로 파싱해 AD 점검 항목별 판정.
// 판정 없이 원시값만 수집한 데이터를 여기서 임계값 기준으로 양호/취약 판단한다(엔진 역할).
function _f(item, verdict, reason, evidence) {
  return { item, verdict, reason, evidence: evidence === undefined || evidence === null ? '' : String(evidence).slice(0, 200) };
}

function evaluateAdDc(raw) {
  let d;
  // BOM(PowerShell Out-File UTF8) 및 앞뒤 공백 제거 후 파싱 — 실데이터 대응
  const text = String(raw || '').replace(/^﻿/, '').trim();
  try { d = JSON.parse(text); } catch (e) { return null; }
  if (!d || typeof d !== 'object') return null;
  // AD 수집물 시그니처 — 이 키들이 하나라도 있으면 AD DC 결과물로 간주
  const isAd = d.password_policy || d.admin_groups || d.krbtgt_pwdlastset || d.machine_account_quota !== undefined
    || (d.meta && (d.meta.domain || d.meta.netbios));
  if (!isAd) return null;

  const F = [];
  const pp = d.password_policy || {};

  // 1) 패스워드 정책
  if (pp.MinPasswordLength !== undefined) {
    F.push(Number(pp.MinPasswordLength) >= 8
      ? _f('AM: 최소 패스워드 길이', '양호', `최소 길이 ${pp.MinPasswordLength}자(8자 이상)`, `MinPasswordLength=${pp.MinPasswordLength}`)
      : _f('AM: 최소 패스워드 길이', '취약', `최소 길이 ${pp.MinPasswordLength}자 — 8자 이상 권장`, `MinPasswordLength=${pp.MinPasswordLength}`));
  }
  if (pp.ComplexityEnabled !== undefined) {
    F.push(pp.ComplexityEnabled
      ? _f('AM: 패스워드 복잡도', '양호', '복잡도 요구 활성', 'ComplexityEnabled=true')
      : _f('AM: 패스워드 복잡도', '취약', '복잡도 요구 비활성 — 활성 권장', 'ComplexityEnabled=false'));
  }
  if (pp.MaxPasswordAgeDays !== undefined) {
    const age = Number(pp.MaxPasswordAgeDays);
    F.push((age > 0 && age <= 90)
      ? _f('AM: 패스워드 최대 사용기간', '양호', `${age}일(90일 이하)`, `MaxPasswordAgeDays=${age}`)
      : _f('AM: 패스워드 최대 사용기간', '취약', age === 0 ? '무기한(0) — 만료 미설정' : `${age}일 — 90일 이하 권장`, `MaxPasswordAgeDays=${age}`));
  }
  if (pp.ReversibleEncryptionEnabled !== undefined) {
    F.push(pp.ReversibleEncryptionEnabled
      ? _f('AM: 가역 암호화 저장', '취약', '암호를 복호화 가능한 형태로 저장(평문 노출과 동등)', 'ReversibleEncryptionEnabled=true')
      : _f('AM: 가역 암호화 저장', '양호', '가역 암호화 비활성', 'ReversibleEncryptionEnabled=false'));
  }
  if (pp.LockoutThreshold !== undefined) {
    F.push(Number(pp.LockoutThreshold) > 0
      ? _f('AM: 계정 잠금 임계값', '양호', `${pp.LockoutThreshold}회 실패 시 잠금`, `LockoutThreshold=${pp.LockoutThreshold}`)
      : _f('AM: 계정 잠금 임계값', '취약', '계정 잠금 미설정(0) — 무차별 대입 노출', 'LockoutThreshold=0'));
  }

  // 2) Built-in 계정 (RID 500 Administrator / 501 Guest)
  for (const acc of (d.builtin_accounts || [])) {
    if (acc.RID === 501) {
      F.push(acc.Enabled
        ? _f('AC: Guest 계정', '취약', 'Guest 계정이 활성화됨 — 비활성 권장', `Sam=${acc.Sam} Enabled=true`)
        : _f('AC: Guest 계정', '양호', 'Guest 계정 비활성', `Sam=${acc.Sam} Enabled=false`));
    }
    if (acc.RID === 500) {
      F.push(/administrator/i.test(String(acc.Sam))
        ? _f('AC: Administrator 계정명', '취약', '기본 관리자 계정명(Administrator) 미변경 — 변경 권장', `Sam=${acc.Sam}`)
        : _f('AC: Administrator 계정명', '양호', '기본 관리자 계정명 변경됨', `Sam=${acc.Sam}`));
    }
  }

  // 3) 특권 그룹 과다 멤버십
  const daMembers = (d.admin_groups && d.admin_groups['Domain Admins']) || null;
  if (Array.isArray(daMembers)) {
    F.push(daMembers.length <= 5
      ? _f('IC: Domain Admins 멤버 수', '양호', `${daMembers.length}명(과다 아님)`, daMembers.join(', '))
      : _f('IC: Domain Admins 멤버 수', '취약', `${daMembers.length}명 — 특권 계정 과다(최소화 권장)`, daMembers.join(', ')));
  }

  // 4) 위험 UAC 플래그 계정
  const uac = { NOTREQD: 32, NOEXPIRE: 65536, NOPREAUTH: 4194304 };
  const flag = (u, bit) => (Number(u.UAC) & bit) === bit || (typeof u.flags === 'string' && (
    (bit === uac.NOTREQD && /PASSWD_NOTREQD/.test(u.flags)) ||
    (bit === uac.NOEXPIRE && /DONT_EXPIRE_PASSWD/.test(u.flags)) ||
    (bit === uac.NOPREAUTH && /DONT_REQ_PREAUTH/.test(u.flags))));
  const users = Array.isArray(d.users) ? d.users : [];
  const notreqd = users.filter(u => flag(u, uac.NOTREQD)).map(u => u.Sam);
  const nopreauth = users.filter(u => flag(u, uac.NOPREAUTH)).map(u => u.Sam);
  const noexpire = users.filter(u => flag(u, uac.NOEXPIRE)).map(u => u.Sam);
  if (users.length) {
    F.push(notreqd.length
      ? _f('AM: 비밀번호 불필요 계정(PASSWD_NOTREQD)', '취약', `빈 비밀번호 허용 계정 ${notreqd.length}건`, notreqd.join(', '))
      : _f('AM: 비밀번호 불필요 계정(PASSWD_NOTREQD)', '양호', '해당 계정 없음'));
    F.push(nopreauth.length
      ? _f('IC: Kerberos 사전인증 미요구(DONT_REQ_PREAUTH)', '취약', `AS-REP Roasting 노출 계정 ${nopreauth.length}건`, nopreauth.join(', '))
      : _f('IC: Kerberos 사전인증 미요구(DONT_REQ_PREAUTH)', '양호', '해당 계정 없음'));
    if (noexpire.length) F.push(_f('AM: 비밀번호 무기한(DONT_EXPIRE_PASSWD)', '취약', `비밀번호 만료 없는 계정 ${noexpire.length}건`, noexpire.join(', ')));
  }

  // 5) krbtgt 패스워드 경과
  if (d.krbtgt_pwdlastset) {
    F.push(_f('IC: krbtgt 패스워드 경과', '판정불가',
      'krbtgt 마지막 변경일 확인 — 180일 초과 시 주기적 재설정 필요(Golden Ticket 대비)', d.krbtgt_pwdlastset));
  }

  // 6) 머신 계정 쿼터
  if (d.machine_account_quota !== undefined) {
    F.push(Number(d.machine_account_quota) === 0
      ? _f('IC: 머신 계정 쿼터', '양호', '일반 사용자의 컴퓨터 계정 등록 불가(0)', 'ms-DS-MachineAccountQuota=0')
      : _f('IC: 머신 계정 쿼터', '취약', `일반 사용자가 컴퓨터 계정 ${d.machine_account_quota}개 등록 가능 — 0 권장`, `ms-DS-MachineAccountQuota=${d.machine_account_quota}`));
  }

  // 7) SMB
  if (d.smb) {
    if (d.smb.EnableSMB1Protocol !== undefined) {
      F.push(d.smb.EnableSMB1Protocol
        ? _f('SS: SMB1 프로토콜', '취약', 'SMB1 활성 — 비활성 권장(랜섬웨어 확산 경로)', 'EnableSMB1Protocol=true')
        : _f('SS: SMB1 프로토콜', '양호', 'SMB1 비활성', 'EnableSMB1Protocol=false'));
    }
    if (d.smb.RequireSecuritySignature !== undefined) {
      F.push(d.smb.RequireSecuritySignature
        ? _f('SS: SMB 서명 요구', '양호', 'SMB 보안 서명 요구', 'RequireSecuritySignature=true')
        : _f('SS: SMB 서명 요구', '취약', 'SMB 서명 미요구 — 중간자 공격 노출', 'RequireSecuritySignature=false'));
    }
  }

  // 8) 레지스트리(자격증명 보호)
  const rg = d.registry || {};
  if (rg.Wdigest_UseLogonCredential !== undefined && rg.Wdigest_UseLogonCredential !== null) {
    F.push(Number(rg.Wdigest_UseLogonCredential) === 1
      ? _f('AC: WDigest 평문 자격증명', '취약', 'WDigest 평문 자격증명 캐시 활성 — 0 권장', 'UseLogonCredential=1')
      : _f('AC: WDigest 평문 자격증명', '양호', 'WDigest 평문 캐시 비활성', 'UseLogonCredential=0'));
  }
  if (rg.Lsa_RestrictAnonymous !== undefined && rg.Lsa_RestrictAnonymous !== null) {
    F.push(Number(rg.Lsa_RestrictAnonymous) >= 1
      ? _f('AC: 익명 접근 제한', '양호', '익명 열거 제한 설정', `RestrictAnonymous=${rg.Lsa_RestrictAnonymous}`)
      : _f('AC: 익명 접근 제한', '취약', '익명 사용자의 SAM/공유 열거 허용(0)', 'RestrictAnonymous=0'));
  }
  if (rg.Lsa_NoLMHash !== undefined && rg.Lsa_NoLMHash !== null) {
    F.push(Number(rg.Lsa_NoLMHash) === 1
      ? _f('AC: LM 해시 저장', '양호', 'LM 해시 저장 안 함', 'NoLMHash=1')
      : _f('AC: LM 해시 저장', '취약', '취약한 LM 해시 저장 허용(0)', 'NoLMHash=0'));
  }
  if (rg.Lsa_LmCompatibilityLevel !== undefined && rg.Lsa_LmCompatibilityLevel !== null) {
    F.push(Number(rg.Lsa_LmCompatibilityLevel) >= 3
      ? _f('AC: LM/NTLM 인증 수준', '양호', `NTLMv2 강제 수준(${rg.Lsa_LmCompatibilityLevel})`, `LmCompatibilityLevel=${rg.Lsa_LmCompatibilityLevel}`)
      : _f('AC: LM/NTLM 인증 수준', '취약', `수준 ${rg.Lsa_LmCompatibilityLevel} — 3 이상(NTLMv2) 권장`, `LmCompatibilityLevel=${rg.Lsa_LmCompatibilityLevel}`));
  }

  // 9) Print Spooler on DC (PrintNightmare)
  if (d.services && d.services.Spooler) {
    const st = d.services.Spooler.Status;
    F.push(/running/i.test(String(st))
      ? _f('SS: DC의 Print Spooler', '취약', 'DC에서 Print Spooler 실행 중 — PrintNightmare 대비 중지 권장', `Spooler=${st}`)
      : _f('SS: DC의 Print Spooler', '양호', 'Print Spooler 미실행', `Spooler=${st}`));
  }

  // 10) GPP cpassword
  if (Array.isArray(d.gpp_cpassword_files)) {
    F.push(d.gpp_cpassword_files.length
      ? _f('IC: SYSVOL GPP cpassword', '취약', `cpassword 포함 파일 ${d.gpp_cpassword_files.length}건 — 복호화 가능 암호 노출`, d.gpp_cpassword_files.join(', '))
      : _f('IC: SYSVOL GPP cpassword', '양호', 'cpassword 포함 파일 없음'));
  }

  // 11) SID History
  if (Array.isArray(d.sid_history)) {
    F.push(d.sid_history.length
      ? _f('IC: SID History 주입', '취약', `sIDHistory 보유 객체 ${d.sid_history.length}건 — 권한 상승 경로 점검 필요`, d.sid_history.map(x => x.Name).join(', '))
      : _f('IC: SID History 주입', '양호', 'sIDHistory 보유 객체 없음'));
  }

  // 12) 무제약 위임 컴퓨터
  const deleg = (d.computers || []).filter(c => c.TrustedForDelegation).map(c => c.Name);
  if (Array.isArray(d.computers)) {
    F.push(deleg.length
      ? _f('IC: 무제약 위임 컴퓨터', '취약', `TrustedForDelegation 컴퓨터 ${deleg.length}건 — 자격증명 탈취 위험`, deleg.join(', '))
      : _f('IC: 무제약 위임 컴퓨터', '양호', '무제약 위임 컴퓨터 없음'));
  }

  const vuln = F.filter(x => x.verdict === '취약').length;
  const safe = F.filter(x => x.verdict === '양호').length;
  const na = F.filter(x => x.verdict === '판정불가').length;
  return {
    findings: F,
    summary: `AD 도메인 컨트롤러 점검 ${F.length}개 항목: 취약 ${vuln} · 양호 ${safe} · 판정불가 ${na}`,
    domain: (d.meta && (d.meta.domain || d.meta.netbios)) || null,
  };
}

// ── 스크립트 유형별 구조 판정기 레지스트리 (★확장 지점) ──────────────
// 새 커스텀 스크립트(다른 ps1/sh)가 들어오면 여기에 evaluator 하나만 추가한다.
//   evaluate(raw) → { findings:[{item,verdict,reason,evidence}], summary, meta? } | null
//   detect 는 evaluate 내부에서 시그니처를 보고 null 을 반환하면 "해당 없음"으로 넘어간다.
// 등록 순서대로 시도하고, 처음 non-null 을 반환한 판정기가 채택된다.
// 어떤 판정기도 매칭 안 되면 범용 위험 신호 스캔(RISK_SIGNALS)으로 폴백한다.
const SCRIPT_EVALUATORS = [
  {
    key: 'ad_dc',
    label: 'AD 도메인 컨트롤러 (ad_collect.ps1)',
    note: 'AD 도메인 컨트롤러(ad_collect.ps1) 결과를 구조 판정했습니다. 항목 접두어 AM=계정관리 · AC=접근통제 · IC=침해통제 · SS=서비스관리.',
    evaluate: evaluateAdDc,
    summarySuffix: (r) => (r.domain ? ` (도메인: ${r.domain})` : ''),
  },
  // 예: { key:'iis', label:'IIS 웹서버 점검 (iis_collect.ps1)', note:'…', evaluate: evaluateIis },
  // 예: { key:'linux_hardening', label:'리눅스 하드닝 (harden.sh)', note:'…', evaluate: evaluateLinuxHardening },
];

/**
 * 등록된 구조 판정기를 순서대로 시도. 매칭되면 판정 결과를, 없으면 null.
 */
function detectAndEvaluate(raw) {
  for (const ev of SCRIPT_EVALUATORS) {
    let r = null;
    try { r = ev.evaluate(raw); } catch (e) { r = null; }
    if (r && Array.isArray(r.findings)) {
      return {
        evaluator: ev.key,
        label: ev.label,
        findings: r.findings,
        summary: (r.summary || '') + (ev.summarySuffix ? ev.summarySuffix(r) : ''),
        note: ev.note,
      };
    }
  }
  return null;
}

/**
 * mock 판정 — 외부 호출 없이 결정론적으로 판정한다.
 * ① 등록된 스크립트 판정기(SCRIPT_EVALUATORS)가 형식을 인식하면 항목별 구조 판정
 * ② 인식 못 하면 범용 위험 신호 스캔 (판정 지침은 참고, 자연어 해석은 LLM 보조)
 */
function mockJudge(raw, instruction) {
  const text = String(raw || '');

  // ① 등록된 스크립트 유형 구조 판정 (확장 지점)
  const structured = detectAndEvaluate(text);
  if (structured) {
    return {
      backend: 'mock',
      evaluator: structured.evaluator,
      findings: structured.findings,
      summary: structured.summary,
      note: structured.note + ' 지침 기반 추가 정밀 판정이 필요하면 LLM 보조를 사용하세요.',
    };
  }

  // ② 범용 위험 신호 스캔 (미등록 형식)
  const findings = [];
  for (const sig of RISK_SIGNALS) {
    if (sig.test.test(text)) {
      const m = text.match(sig.test);
      findings.push({
        item: sig.item,
        verdict: '취약',
        reason: sig.reason,
        evidence: m ? m[0].slice(0, 120) : '',
      });
    }
  }
  const note = findings.length
    ? 'mock 기본 스캔이 범용 위험 신호를 발견했습니다(미등록 스크립트 형식). 판정 지침 기반 정밀 판정은 LLM 보조를 사용하세요.'
    : 'mock 기본 스캔에서 알려진 범용 위험 신호를 찾지 못했습니다(= 안전 확정 아님, 미등록 형식). 판정 지침대로의 정밀 판정은 LLM 보조가 필요합니다.';
  return {
    backend: 'mock',
    findings,
    summary: `범용 위험 신호 ${findings.length}건 발견`,
    note,
  };
}

/**
 * LLM 보조 판정 — 판정 지침대로 결과물을 정밀 판정한다.
 * @param {object} client - engine/llm/client 의 createClient() 결과
 */
async function llmJudge(raw, instruction, client) {
  const system =
    '너는 정보보안 점검 판정 전문가다. 사용자가 준 "점검 결과물"을 "판정 지침"에 따라 항목별로 판정한다. ' +
    '반드시 JSON만 출력한다. 형식: ' +
    '{"findings":[{"item":"점검 항목","verdict":"취약|양호|판정불가","reason":"판정 근거","evidence":"결과물에서 인용한 근거"}],"summary":"한줄 요약"}. ' +
    '지침에 없는 항목도 결과물에서 명백한 보안 위험이 보이면 포함하라. 근거가 결과물에 없으면 verdict를 "판정불가"로 하라.';
  const user =
    '## 판정 지침\n' + String(instruction || '(지침 없음 — 일반 보안 관점으로 판정)') +
    '\n\n## 점검 결과물\n```\n' + String(raw || '').slice(0, 12000) + '\n```';

  const res = await client.complete({ system, user, responseFormat: 'json', temperature: 0.1 });
  const j = res.json || {};
  return {
    backend: 'llm',
    model: res.model,
    elapsedMs: res.elapsedMs,
    findings: Array.isArray(j.findings) ? j.findings : [],
    summary: j.summary || '',
    note: 'LLM이 판정 지침에 따라 정밀 판정했습니다.',
  };
}

module.exports = { mockJudge, llmJudge, detectAndEvaluate, evaluateAdDc, SCRIPT_EVALUATORS, RISK_SIGNALS };

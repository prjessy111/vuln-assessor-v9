'use strict';
/**
 * AI 진단 엔진 — SecuMS raw 데이터를 LLM에 보내 판정.
 *
 * 흐름:
 *   1. extractDiagnoseItems()로 64개 항목 추출
 *   2. 각 항목에 대해 AI 판정 프롬프트 구성
 *   3. LLM 호출 → JSON 응답 (verdict / reason / recommend)
 *   4. SecuMS 판정과 비교해서 정합성 정보 함께 저장
 *
 * 핵심 가치 (SecuMS 대비 +α):
 *   - 양호 항목도 "왜 양호한지" 사유 제공
 *   - 취약 항목의 구체적 권고 (명령어 수준)
 *   - SecuMS가 점검 못 한 항목(WAIT)도 raw 데이터로 추론
 *
 * LLM 호출 비용 고려:
 *   - 64항목 × 평균 1.7K 토큰 = ~100K 토큰
 *   - 병렬 호출로 처리 시간 단축
 *   - mock provider면 가짜 응답 (개발용)
 */

const PROMPT_TEMPLATE = `당신은 보안 검증 솔루션의 독립 판정 엔진입니다.
아래 진단 항목의 raw 점검 데이터만 분석해서 보안 관점에서 판정하세요.
SecuMS의 자체 판정값이나 취약 메시지는 제공되지 않습니다. 판단은 반드시 raw evidence에 근거해야 합니다.

## 진단 항목
- CHK_ID: {{chk_id}}
{{source_notice}}

## 점검 액션 및 결과
{{actions}}

## 요청
위 정보를 기반으로 다음을 JSON 형식으로 응답하세요. **다른 텍스트 없이 JSON만**:

\`\`\`json
{
  "verdict": "취약" | "양호" | "정보제공" | "판정불가",
  "safe_type": "부재양호" | "값준수양호" | "",
  "category": "이 점검의 보안 카테고리 (예: 계정 관리, 파일 권한, 네트워크 서비스 등)",
  "title": "점검 항목 한글 제목 (15자 이내)",
  "reason": "판정 사유 (구체적으로 — 어떤 설정값이 어떻게 문제인지 / 양호하면 왜 양호한지)",
  "evidence": "raw 데이터에서 핵심 증거 1-2줄 인용",
  "recommend": "조치 권고 (취약일 때 — 명령어 또는 설정 파일 수정 방법). 양호면 빈 문자열.",
  "severity": "상" | "중" | "하"  
}
\`\`\`

## 판정 기준
- **부재양호**: 점검 대상 "객체 자체"(파일/서비스/데몬/패키지)가 존재하지 않는 경우만 해당 — 예: "No such file", 서비스 미설치(OpenService 1060), 패키지 미설치. 위험을 일으킬 주체가 없으므로 → **양호 / safe_type=부재양호**
- **주의: 설정값·레지스트리 키·정책 값이 "없음/미설정/Not Found"인 경우는 부재양호가 아닙니다.** 값이 없으면 시스템 기본값(default)으로 동작하므로, 그 기본 동작을 보안 기준에 비춰 판정하세요 — 기본값이 안전하면 양호(값준수양호), 기본값이 위험하면 **취약**. (예: 보안 강화용 레지스트리 키가 없으면 = 강화 미적용 = 취약일 가능성이 큼. NTLMv2 강제·암호화 레벨·접근 제한 키 등)
- 점검 대상은 존재하고 설정값/권한/정책/버전 등이 보안 기준을 준수하면 → **양호**, safe_type은 **값준수양호**
- 보안 정책에 어긋나는 설정값이 명확하거나, 설정 미적용 시 기본 동작이 위험하면 → **취약**
- 점검이 실행 안 됐거나(WAIT/error) raw 데이터 부족 → **판정불가**
- 단순 현황 조회로 보이고 보안 양호/취약 기준이 명확하지 않으면 → **정보제공**
- verdict가 양호가 아니면 safe_type은 빈 문자열("")로 두세요.`;

/**
 * 한 항목에 대한 AI 진단 프롬프트 생성.
 */
function buildEnginePolicy(mode) {
  if (mode === 'ai') {
    return [
      '## ENGINE_ROLE_POLICY',
      'engine=AI_FAST_TRIAGE',
      'priority=speed_first; use explicit raw evidence, AI_RAW_CONTEXT, AI_FAST_HINTS and pattern library.',
      'decision_rule=return vulnerable/safe only when the raw signal is explicit; otherwise return info or unable.',
      'safe_rule=absence-good when target service/file/config is absent and absence itself removes the risk; value-compliant-good when an existing value meets the standard.',
      'output_style=short JSON; concise reason and evidence.',
    ].join('\n');
  }

  return [
    '## ENGINE_ROLE_POLICY',
    'engine=LLM_PRECISE_REVIEW',
    'priority=accuracy_first; slower but stricter evidence review is expected.',
    'decision_rule=verify command intent, raw output, absence-good vs value-compliant-good, and possible collection errors before verdict.',
    'risk_control=do not treat permission errors, command failures, truncated output, or missing collection as safe; use unable when evidence is insufficient.',
    'cross_check=if AI_FAST_HINTS conflict with raw output, trust raw output and explain the conflict.',
    'output_style=strict JSON only; include concrete evidence and actionable recommendation.',
  ].join('\n');
}

// 항목별 보안 판정 기준 — SRV_META(큐레이션)에서 조회해 프롬프트에 주입.
// 기준(점검의도/양호기준/취약조건)을 주면 AI/LLM이 정보제공·판정불가로 빠지지 않고
// raw 출력을 기준에 비춰 결정적으로 취약/양호 판정한다.
// 리포트1 2026 공식 점검 기준(확인방법/기준/조치법) — 1회 로드
const CHECKSPEC_2026 = (() => { try { return require('../../data/report1-2026-checkspec.json'); } catch (_) { return null; } })();

// 크로스워크(리포트1): os-xxx(SecuMS) ↔ SRV. SecuMS raw 항목(chk_id=os-win-2508 등)은
// SRV 키가 아니라 기준이 하나도 안 붙어 LLM이 판정불가(N/A)를 양산했음 → os-xxx를 SRV로 변환해 기준 주입.
const CROSSWALK_TW = (() => { try { return require('../../data/srv-secums-crosswalk.json'); } catch (_) { return null; } })();
const SCAN_TO_SRV = (() => {
  const m = {};
  if (CROSSWALK_TW) for (const os of ['windows', 'linux']) for (const r of (CROSSWALK_TW[os] || [])) {
    if (r.scan_id && r.srv) m[String(r.scan_id)] = r.srv;
  }
  return m;
})();
// chk_id 가 SRV-NNN 이면 그대로, os-xxx(SecuMS) 면 크로스워크로 SRV 변환(기준 조회용).
function resolveSrvId(chkId) {
  const s = String(chkId || '');
  if (/SRV-\d+/i.test(s)) return s;
  return SCAN_TO_SRV[s] || s;
}
function srvKey2026(id) { const m = String(id || '').match(/SRV-(\d+)/i); return m ? 'SRV-' + m[1].padStart(3, '0') : null; }

// 값-의미 오해/일부만 평가로 SecuMS와 어긋나던 항목의 명시 규칙(Windows). LLM이 자주 틀리는 지점 교정.
const SRV_HINTS_WIN = {
  'SRV-001': 'SNMP 서비스가 미설치여도 "부재양호"로 끝내지 말 것. 이 항목은 SNMP + WMI + DCOM 인증수준(LegacyAuthenticationLevel) + LAN Manager 인증수준(LmCompatibilityLevel)을 함께 본다. LmCompatibilityLevel 이 없거나 5 미만이면 NTLMv2 미강제 = 취약. LegacyAuthenticationLevel 이 2(Packet Privacy) 미만이면 취약. 수집된 LmCompatibilityLevel/LegacyAuthenticationLevel 값을 반드시 평가하라.',
  'SRV-034': 'NetbiosOptions 레지스트리 값 해석 주의: 2=비활성(양호), 0=기본값(활성, 취약), 1=활성(취약). 0은 "사용 안 함"이 아니라 기본값(활성)이다. 인터페이스 중 하나라도 NetbiosOptions 가 2가 아니면 취약. 레거시 서비스 부재만으로 양호 처리 금지.',
  'SRV-101': '불필요한 예약 작업 점검. Microsoft 기본 텔레메트리/불필요 작업(Application Experience\\Microsoft Compatibility Appraiser, Customer Experience Improvement Program(CEIP), Application Data\\appuriverifier* 등)이 활성 상태면 2026 기준상 취약이다. 보안 솔루션 작업만 있다고 양호로 판정하지 말고, 위 불필요 기본 작업의 활성 여부를 확인하라.',
};

// Linux 항목별 명시 규칙.
const SRV_HINTS_LINUX = {
  'SRV-096': '사용자 환경파일(.cshrc/.bashrc/.bash_profile/.tcshrc/.profile/.login 등)의 권한 점검. 2026 기준: "others(타인)에 읽기(r)/쓰기(w)/실행(x) 권한이 하나라도 부여되면 취약". 따라서 0644(rw-r--r--)는 others=read(4) 이므로 **취약**이다 — 0644 를 관행상 양호로 보지 말 것. others 비트가 0 인 0640·0600·0660 등만 양호. 권한 마지막 자리(others)가 0 이 아니면(4·5·6·7 등 r/w/x 포함) 모두 취약. 수집된 모든 행을 보고 하나라도 others 권한이 있으면 취약.',
  'SRV-006': 'SMTP 로그수준 점검. SMTP(25)가 127.0.0.1/::1(localhost)에서만 LISTEN 하면 외부 노출이 없으므로 verdict=양호. sendmail.cf 부재(postfix 사용 시 정상)·LogLevel 미확인을 이유로 취약 판정 금지. 0.0.0.0/공인 IP 로 LISTEN 할 때만 LogLevel 미설정을 취약으로 본다.',
  'SRV-009': 'SMTP 스팸 릴레이 제한 점검. SMTP 가 localhost(127.0.0.1/::1)에서만 LISTEN 하면 외부 릴레이 경로가 없으므로 verdict=양호. /etc/mail/access 부재를 이유로 취약 판정 금지.',
  'SRV-063': 'DNS Recursive Query 제한 점검. named 가 loopback/내부 가상대역(192.168.122.x = virbr0 등)에서만 LISTEN 하면 외부에서 recursion 악용이 불가하므로 verdict=양호. named.conf 부재로 recursion 설정을 확인 못 해도, 내부전용 LISTEN 이면 취약 판정 금지.',
  'SRV-064': 'DNS 보안 패치 점검. named 가 loopback/내부 가상대역에서만 LISTEN 하면 외부 공격면이 없으므로 verdict=양호. 외부 dig 프로브(porttest.dns-oarc.net)의 timeout/connection failed 는 폐쇄망 때문이며 이를 "패치 미적용=취약"으로 해석하지 말 것. 내부전용이면 양호.',
  'SRV-066': 'DNS Zone Transfer 제한 점검. named 가 loopback/내부 가상대역에서만 LISTEN 하면 외부로의 zone transfer 가 불가하므로 verdict=양호. named.conf 부재로 allow-transfer 미확인이어도 내부전용이면 취약 판정 금지.',
  'SRV-034': '불필요한 서비스 비활성화 점검. rpcbind/portmap 가 실행 중이어도 NFS/NIS 등 정상 용도로 흔히 동작하므로, rpcbind 실행 자체만으로 취약 판정하지 말 것. automountd 등 명백히 불필요한 레거시 서비스가 외부 노출 상태로 실행 중이거나 inetd/xinetd 에 불필요 서비스가 활성일 때만 취약. 그 외(rpcbind 만 실행 등)는 양호.',
  'SRV-070': '취약한 패스워드 "저장 방식(해시 알고리즘)" 점검. **오직** /etc/login.defs 의 ENCRYPT_METHOD 또는 /etc/shadow 해시 포맷만 본다 — SHA-512($6$)면 양호, MD5($1$)·DES면 취약. **UID>=1000 일반계정 존재·로그인 쉘(/bin/bash) 부여 여부는 SRV-070 과 전혀 무관하므로 절대 취약 근거로 쓰지 말 것(항목 범위 위반).** shadow 해시가 $6$(SHA-512)이면 무조건 양호로 판정하라.',
  'SRV-075': '비밀번호 "복잡도" 설정 점검(pwquality.conf / pam_pwquality). minlen>=8 이거나 dcredit/ucredit/lcredit/ocredit 중 하나라도 음수(요구)이거나 minclass>=1 이면 복잡도가 확보된 것이므로 양호. **minclass=0 이라는 사실만으로 취약 판정 금지** — minlen·credit 로 복잡도가 충족될 수 있다(RHEL 기본값 minlen=8 등이면 양호). 복잡도 강제가 전혀 없을 때(minlen 미설정 + credit 없음 + minclass=0)만 취약. 만료기간(PASS_MAX_DAYS)·최소사용기간은 SRV-075 무관이므로 취약 근거로 쓰지 말 것.',
  'SRV-091': '불필요한 SUID/SGID 점검. at·newgrp·unix_chkpwd·ping 등 배포본 표준 SUID 라도 2026 기준 허용목록에 없으면 임의로 화이트리스트하지 말 것. 수집된 SUID/SGID 파일 중 기준 허용목록 밖의 파일이 하나라도 있으면 취약. (표준 유틸이라는 이유로 양호 처리 금지 — 미탐 방지)',
  'SRV-177': 'sudo 명령어 접근 권한 적절성 점검. 부적절한 계정/그룹(일반 사용자 등)에 sudo 권한이 부여된 경우에만 취약이다. sudo 권한 부여 현황(액션)이 비어있으면(<Rows count="0"/>, RESULT 없음) = 일반 계정·그룹에 부여된 sudo 권한이 없다는 뜻 = 양호다 — 비어있다고 취약/판정불가로 빠지지 말고 양호로 판정하라. /etc/group 등 다른 액션에 데이터가 있으면 수집은 정상 수행된 것이다.',
  'SRV-163': '시스템 사용 주의사항(로그인 배너) 점검. /etc/motd · /etc/issue · /etc/issue.net 또는 sshd_config 의 Banner 에 경고 문구 "내용"이 존재하면 양호로 판정한다. 배너 문구의 적절성/문구 내용까지 엄밀히 검증하기는 어려우므로, 내용이 비어있지 않으면 양호로 처리하고 판정불가로 빠지지 말 것. 내용이 전혀 없거나 배너 미설정이면 취약.',
};

function buildCriteriaSection(item) {
  try {
    const { getScriptMeta } = require('./llm/providers/mockScriptPatterns');
    // SecuMS 항목(os-xxx)도 크로스워크로 SRV 변환해 동일 기준 주입 (N/A 폭증 방지)
    const effId = resolveSrvId(item.chk_id);
    const meta = getScriptMeta(effId);

    // 2026 공식 기준(리포트1) 조회 — item._os 로 OS 판별(win/linux 기준 다름)
    const srvK = srvKey2026(effId);
    const osKey = /win/i.test(String(item._os || item.os_family || item.os || '')) ? 'windows' : 'linux';
    let spec = null;
    if (CHECKSPEC_2026 && CHECKSPEC_2026.os) {
      spec = (CHECKSPEC_2026.os[osKey] || {})[srvK] || (CHECKSPEC_2026.os.windows || {})[srvK] || (CHECKSPEC_2026.os.linux || {})[srvK] || null;
    }
    if (!meta && !spec) return '';

    const lines = ['', '## 점검 기준 (raw 출력을 이 기준에 비춰 결정적으로 판정)'];
    if (meta) {
      lines.push(`- 점검 항목: ${meta.title || item.chk_id}${meta.category ? ` (${meta.category})` : ''}`);
      if (meta.criteria) lines.push(`- 점검 의도: ${meta.criteria}`);
      if (meta.safe_condition) lines.push(`- 양호 기준: ${meta.safe_condition}`);
      if (meta.vuln_condition) lines.push(`- 취약 조건: ${meta.vuln_condition}`);
    }
    if (spec) {
      lines.push('', '### 2026 공식 판정 기준 (금융보안원 전자금융기반시설 — 최우선·엄격 적용)');
      if (spec.title) lines.push(`- 항목: ${spec.title}`);
      if (spec.기준) lines.push(`- 판정 기준: ${String(spec.기준).slice(0, 600)}`);
      if (spec.조치법) lines.push(`- 조치법(=안전한 상태는 이 조치가 적용된 상태): ${String(spec.조치법).slice(0, 500)}`);
    }
    const hint = (osKey === 'windows' ? SRV_HINTS_WIN : SRV_HINTS_LINUX)[srvK];
    if (hint) lines.push('', '### 이 항목 판정 시 반드시 적용할 규칙(중요)', hint);
    lines.push(
      '',
      '※ 판정 원칙(엄격): (1) 위 2026 기준을 최우선으로 적용하고, 임의로 "표준/필수/정상"이라 단정해 양호 처리하지 말 것. (2) 보안 강화 설정값이 기준 미달이거나 미설정/기본값이면 취약. (3) 특권 그룹(Administrators/wheel 등)에 기본 계정 외 사용자·그룹이 있으면 취약. (4) 비밀번호가 장기 미변경(오래됨)이거나 만료 미설정(예: Maximum days 99999)이면 취약. (5) 권한/SUID/SGID/umask 등이 기준 초과(과다)면 취약 — 표준 유틸이라고 임의로 화이트리스트하지 말 것. (6) 수집된 모든 값을 검토하고, 하나라도 기준 위반이면 취약 — 일부만 보고 양호로 판정하지 말 것. 기준이 명확하면 정보제공/판정불가가 아니라 취약 또는 양호로 결정.',
      '',
      '※ 과탐 방지(아래에 해당하면 취약이 아니라 양호 — 흔한 오판이니 반드시 적용):',
      '(가) 권한이 기준보다 더 엄격(더 제한적)이면 양호. 권한 숫자가 낮을수록 제한적=더 안전이다. 예) /etc/shadow 0000·0400, 로그파일 0600 은 기준(600/640/660)보다 강하므로 양호. "숫자가 기준보다 낮다"는 이유로 취약 판정 금지.',
      '(나) /etc/shadow 2번째 필드가 *, !, !!, *LK*, x 이면 "잠긴/비밀번호 로그인 불가" 계정 = 양호. 빈 암호 취약은 이 필드가 완전히 비어있을(::) 때만. bin·daemon·adm·lp·sync·shutdown·halt·mail·operator·nobody 등은 보통 * 또는 !! 이므로 빈 암호 아님.',
      '(다) OS 기본 시스템 계정/그룹(root,bin,daemon,adm,lp,sync,shutdown,halt,mail,operator,games,ftp,nobody,systemd-*,dbus,polkitd,colord,cgred,libstoragemgmt,rpc,rpcuser,chrony,sshd,tss,setroubleshoot,sssd,nscd,unbound,saslauth 등)은 UID/GID<1000 의 배포본 기본 계정이다. 이들이 GID 0(root그룹) 소속이거나, /sbin/nologin·/bin/sync·/sbin/shutdown·/sbin/halt·/sbin/halt 쉘을 갖거나, 구성원이 없는 그룹이어도 OS 기본값=양호. 엄격 판정은 UID≥1000 의 사람 계정에만 적용.',
      '(라) 서비스 포트가 127.0.0.1(localhost)·::1(loopback) 또는 가상화 내부대역(192.168.122.x = libvirt virbr0, 10.0.2.x, virbr*)에서만 LISTEN 이면 외부 노출이 아니므로 그 서비스(DNS 53 등)는 양호. **이 원칙은 배너/버전 정보노출 점검에도 그대로 적용한다 — SMTP 배너(SRV-170)·FTP 배너(SRV-171)·DNS 버전/패치(SRV-064/065)·웹 서버 버전(ServerTokens) 등에서, 해당 서비스가 localhost/loopback/내부 가상대역에서만 LISTEN 하면 외부에서 배너·버전을 조회할 수 없어 정보노출 위험이 없으므로 양호로 판정하라(기본 배너라는 이유만으로 취약 처리 금지). netstat 에 0.0.0.0:포트 또는 공인/외부 도달 가능 IP 로 LISTEN 할 때만 외부 노출로 보고 기준을 적용한다. 또한 그 서비스의 하드닝 설정(DNS recursion/zone-transfer/allow-update, SMTP relay/loglevel/banner, FTP 접근제어 등)을 설정파일 부재로 확인하지 못하더라도, 해당 서비스가 loopback/내부 가상대역에서만 LISTEN 하면 외부 공격면이 없으므로 양호로 판정하라 — "설정을 확인 못 했다"는 이유만으로 취약 판정 금지.**',
      '(마) 점검 대상의 raw 증거 자체가 수집되지 않은 경우(빈 컬럼, PERMISSION="" 공백, <Rows count="0"/>, 빈 출력 등)는 "설정이 없음/취약"으로 단정하지 말고 **판정불가**로 답하라. 데이터가 없으면 판단 근거가 없는 것이다. 단 "대상 파일·서비스·계정이 실제로 존재하지 않음"이 명확히 확인된 경우는 그 부재 자체를 기준에 따라 판정(부재양호 또는 취약). **특히 행(파일/항목)은 존재하나 PERMISSION/권한/설정값 컬럼만 비어있으면(예: <Value></Value>) 그 값을 "수집하지 못한 것"이다 — 권한값이 비었다고 "제한 없음/과다권한/취약"으로 해석하는 것은 명백한 오판이다. 권한값이 하나라도 비어있는 행에 대해서는 취약으로 단정하지 말고 판정불가로 답하라.**',
      '(바) 각 항목은 그 항목의 점검 범위만 판정하라. 예) SRV-022(빈 암호)는 비밀번호가 "비어있는지"만 본다 — 비밀번호 만료기간(99999)·복잡도는 다른 항목(SRV-075 등) 소관이므로 SRV-022에서 취약 근거로 쓰지 말 것. 항목 범위를 벗어난 사유로 취약 판정 금지.',
      '(사) [서비스 미설치 → 부재양호] 점검 대상이 특정 서비스/데몬의 설정에 한정된 항목(예: Apache/httpd, named/bind(DNS), vsftpd/proftpd(FTP), sendmail/postfix(SMTP), snmpd(SNMP) 등)에서, 그 서비스의 설정파일·바이너리를 열 수 없고("cannot open file", "No such file or directory", "그런 파일/디렉터리 없음", 패키지 미설치, OpenService 1060) **동시에** raw 어디에도 해당 서비스가 설치·실행된 흔적이 없으면(프로세스 미검출, 패키지 미설치, 해당 포트 미LISTEN), 그 서비스는 미설치로 간주하여 **양호(safe_type=부재양호)** 로 판정하라 — 판정불가로 빠지지 말 것. 위험을 일으킬 주체(서비스)가 아예 없기 때문이다. reason에 "해당 서비스 미설치로 점검 대상 부재"를 명시하라.',
      '(아) 단, (사)의 예외: ① raw에 그 서비스가 설치됨/실행 중(프로세스 검출, 패키지 존재, 포트 LISTEN)으로 보이는데 설정파일만 못 읽은 경우는 미설치가 아니라 **수집 오류**이므로 부재양호로 단정하지 말고 판정불가를 유지하라. **특히 여러 액션 중 하나라도 점검 대상 역할의 데몬(또는 동일 역할의 대체 데몬: 메일=sendmail/postfix/exim, 웹=apache/httpd/nginx, FTP=vsftpd/proftpd, DNS=named/bind/dnsmasq)이 프로세스로 실행 중이면 그 "역할"은 시스템에 존재하는 것이다 — 한쪽 설정파일(예: sendmail.cf)이 비어/없어도 부재양호로 판정하지 말 것. 살아있는 데몬(예: postfix master 프로세스) 기준으로 판정하되, 그 데몬의 설정 증거가 없으면 양호가 아니라 판정불가로 답하라.** ② 빈 암호 계정(SRV-022)·홈 디렉터리 권한·중요 파일 권한처럼 서비스 설치 여부와 무관하게 항상 존재하는 점검 대상은 (사) 적용 대상이 아니다 — 이런 항목의 빈 출력은 수집 실패이므로 판정불가.',
    );
    return lines.filter(Boolean).join('\n');
  } catch (_) {
    return '';
  }
}

function buildPrompt(item, opts = {}) {
  const mode = opts.engine === 'ai' ? 'ai' : 'llm';
  const outputLimit = opts.outputMaxChars || (mode === 'ai' ? 2600 : 9000);
  const sourceNotice = item._source === 'script'
    ? '\n## 데이터 소스 주의\n이 항목은 Script XML에서 추출한 명령 실행 결과입니다. Script XML 자체에는 보안 판정값이 없으므로, 아래 raw 출력만 근거로 취약/양호/정보제공/판정불가를 판단하세요.\n'
    : '\n## 데이터 소스 주의\n이 항목은 SecuMS raw DB에서 추출한 명령/SQL 실행 결과입니다. SecuMS 자체 판정과 취약 상세 메시지는 의도적으로 제외되었습니다. 아래 raw 출력만 근거로 독립 판정하세요.\n';

  const actionsText = (item.actions || []).map((a, idx) => {
    const desc = a.action_desc || '(설명 없음)';
    const output = compactForPrompt(a.result_output || '', outputLimit);
    const err = a.result_error ? `\n오류: ${a.result_error.slice(0, 500)}` : '';
    return `### 액션 ${idx + 1}: ${desc}
타입: ${a.action_type}
실행 결과:
\`\`\`
${output || '(출력 없음)'}
\`\`\`${err}`;
  }).join('\n\n');

  const criteriaSection = buildCriteriaSection(item);

  const prompt = PROMPT_TEMPLATE
    .replace('{{chk_id}}', item.chk_id)
    .replace('{{source_notice}}', sourceNotice + criteriaSection)
    .replace('{{actions}}', actionsText || '(점검 액션 없음 — SecuMS가 수집 안 함)');
  return `${prompt}\n\n${buildEnginePolicy(mode)}`;
}

function compactForPrompt(text, maxChars = 5000) {
  const value = String(text || '');
  if (value.length <= maxChars) return value;

  const head = Math.floor(maxChars * 0.72);
  const tail = Math.floor(maxChars * 0.2);
  return [
    value.slice(0, head),
    `\n\n... [raw output truncated for prompt: original ${value.length} chars, middle omitted] ...\n\n`,
    value.slice(-tail),
  ].join('');
}

function normalizeVerdict(value) {
  if (value === '정보') return '정보제공';
  if (['취약', '양호', '정보제공', '판정불가'].includes(value)) return value;
  return '판정불가';
}

function isInfoVerdict(value) {
  return value === '정보제공' || value === '정보';
}

function isClearVerdict(value) {
  const verdict = normalizeVerdict(value);
  return verdict === '취약' || verdict === '양호';
}

function secumsVerdictToOur(value) {
  const secumsToOur = {
    OK: '양호',
    BAD: '취약',
    INFO: '정보제공',
    WAIT: '판정불가',
    null: '판정불가',
  };
  return secumsToOur[value] || '판정불가';
}

function classifyAgreement(secumsVerdict, aiVerdict) {
  if (secumsVerdict === 'WAIT' || secumsVerdict == null) return 'secums_wait';

  const expectedFromSecums = secumsVerdictToOur(secumsVerdict);
  const normalizedAiVerdict = normalizeVerdict(aiVerdict);
  if (normalizedAiVerdict === expectedFromSecums) return 'agree';

  if (!isClearVerdict(expectedFromSecums) || !isClearVerdict(normalizedAiVerdict)) {
    return 'needs_review';
  }
  return 'disagree_real';
}

function normalizeSafeType(value, parsed) {
  if (!parsed || parsed.verdict !== '양호') return '';
  if (value === '부재양호' || value === '값준수양호') return value;

  const text = [parsed.reason, parsed.evidence].filter(Boolean).join('\n');
  // 부재양호는 "대상 객체(파일/서비스/데몬/패키지) 자체 부재"에만. 설정값/키 부재(Not Found 등)는 제외.
  if (/no such file|cannot open file|미설치|미실행|not installed|service is not installed|openservice (실패 )?1060|패키지[^\n]*없|데몬[^\n]*없|서비스[^\n]*(미설치|설치되어 있지 않|존재하지)|점검 대상 부재/i.test(text)) {
    return '부재양호';
  }
  return '값준수양호';
}

/**
 * LLM 응답 파싱 (JSON 추출).
 */
function parseLLMResponse(text) {
  if (!text || typeof text !== 'string') {
    return { verdict: '판정불가', reason: 'LLM 응답 없음', _parse_error: true };
  }
  // ```json...``` 블록 추출
  let jsonText = text;
  const blockMatch = text.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (blockMatch) jsonText = blockMatch[1];
  // 또는 첫 { 부터 마지막 } 까지
  const start = jsonText.indexOf('{');
  const end = jsonText.lastIndexOf('}');
  if (start === -1 || end === -1 || end <= start) {
    return {
      verdict: '판정불가',
      reason: 'LLM 응답을 JSON으로 파싱 실패',
      _parse_error: true,
      _raw: text.substring(0, 300),
    };
  }
  try {
    const obj = JSON.parse(jsonText.substring(start, end + 1));
    // 필수 필드 보강
    obj.verdict = normalizeVerdict(obj.verdict);
    obj.reason = obj.reason || '(사유 없음)';
    obj.evidence = obj.evidence || '';
    obj.recommend = obj.recommend || '';
    obj.severity = obj.severity || '중';
    obj.category = obj.category || '미분류';
    obj.title = obj.title || '';
    obj.safe_type = normalizeSafeType(obj.safe_type, obj);
    return obj;
  } catch (e) {
    return {
      verdict: '판정불가',
      reason: `JSON 파싱 오류: ${e.message}`,
      _parse_error: true,
      _raw: jsonText.substring(0, 300),
    };
  }
}

/**
 * 한 항목 AI 진단.
 *
 * @param {object} item - extractDiagnoseItems()의 한 항목
 * @param {object} llmClient - createClient()의 결과
 * @returns {Promise<object>} { chk_id, secums_verdict, ai_verdict, ai_reason, ai_recommend, ai_evidence, ai_category, ai_title, ai_severity, agreement, elapsed_ms, _error? }
 */
async function diagnoseOne(item, llmClient, opts = {}) {
  const t0 = Date.now();
  const engine = opts.engine === 'ai' ? 'ai' : 'llm';
  const prompt = buildPrompt(item, opts);

  let response;
  try {
    response = await llmClient.complete({
      user: prompt,
      responseFormat: engine === 'llm' ? 'json' : 'text',
      temperature: 0.0,
    });
  } catch (e) {
    return {
      chk_id: item.chk_id,
      secums_verdict: item.secums_verdict,
      ai_verdict: '판정불가',
      ai_reason: `LLM 호출 실패: ${e.message}`,
      ai_recommend: '',
      ai_evidence: '',
      ai_category: '미분류',
      ai_title: item.chk_id,
      ai_severity: '중',
      ai_safe_type: '',
      agreement: 'error',
      elapsed_ms: Date.now() - t0,
      _error: e.message,
      _diagnosis_mode: engine,
    };
  }

  const parsed = parseLLMResponse(response.text || response);

  const agreement = classifyAgreement(item.secums_verdict, parsed.verdict);

  return {
    chk_id: item.chk_id,
    secums_verdict: item.secums_verdict,
    ai_verdict: parsed.verdict,
    ai_reason: parsed.reason,
    ai_recommend: parsed.recommend,
    ai_evidence: parsed.evidence,
    ai_category: parsed.category,
    ai_title: parsed.title || item.chk_id,
    ai_severity: parsed.severity,
    ai_safe_type: parsed.safe_type || '',
    agreement,
    elapsed_ms: Date.now() - t0,
    _parse_error: parsed._parse_error,
    _diagnosis_mode: engine,
    _prompt_chars: prompt.length,
  };
}

/**
 * 64개 항목 전체 AI 진단 (병렬 처리).
 *
 * @param {Array} items - extractDiagnoseItems()의 결과
 * @param {object} llmClient - LLM 클라이언트
 * @param {object} opts - { concurrency: 4 }
 * @returns {Promise<{ results, summary }>}
 */
async function diagnoseAll(items, llmClient, opts = {}) {
  const concurrency = opts.concurrency || 4;
  const cancel = require('./cancel');
  const results = new Array(items.length);
  let nextIdx = 0;

  // 간단한 동시성 제어 — concurrency개의 워커가 큐에서 작업 꺼내기
  async function worker() {
    while (true) {
      const i = nextIdx++;
      if (i >= items.length) break;
      // 사용자 중지 시: 남은 항목은 LLM 호출 없이 "중지됨"으로 마감(빠른 종료)
      if (cancel.isCancelled()) {
        results[i] = {
          chk_id: items[i].chk_id,
          secums_verdict: items[i].secums_verdict,
          ai_verdict: '판정불가',
          ai_reason: '배치 중지됨 (사용자 취소)',
          ai_recommend: '', ai_evidence: '', ai_category: '미분류',
          ai_title: items[i].chk_id, ai_severity: '중', ai_safe_type: '',
          agreement: 'secums_wait', elapsed_ms: 0, _cancelled: true,
          _diagnosis_mode: opts.engine,
        };
        continue;
      }
      results[i] = await diagnoseOne(items[i], llmClient, opts);
    }
  }
  const workers = [];
  for (let w = 0; w < Math.min(concurrency, items.length); w++) {
    workers.push(worker());
  }
  await Promise.all(workers);

  // 집계
  const summary = {
    total: results.length,
    vuln: results.filter(r => r.ai_verdict === '취약').length,
    safe: results.filter(r => r.ai_verdict === '양호').length,
    safe_absence: results.filter(r => r.ai_verdict === '양호' && r.ai_safe_type === '부재양호').length,
    safe_value: results.filter(r => r.ai_verdict === '양호' && r.ai_safe_type === '값준수양호').length,
    na:   results.filter(r => r.ai_verdict === '판정불가').length,
    info: results.filter(r => isInfoVerdict(r.ai_verdict)).length,
    agree:       results.filter(r => r.agreement === 'agree').length,
    disagree_real: results.filter(r => r.agreement === 'disagree_real').length,
    needs_review:  results.filter(r => r.agreement === 'needs_review').length,
    secums_wait: results.filter(r => r.agreement === 'secums_wait').length,
    error:       results.filter(r => r.agreement === 'error').length,
    parse_errors: results.filter(r => r._parse_error).length,
    diagnosis_mode: opts.engine === 'ai' ? 'ai_fast' : 'llm_precise',
    avg_ms: results.length ? Math.round(results.reduce((s, r) => s + r.elapsed_ms, 0) / results.length) : 0,
  };
  summary.disagree = summary.disagree_real;
  summary.comparison_count = summary.agree + summary.disagree_real;
  summary.agreement_rate = summary.comparison_count > 0
    ? Math.round((summary.agree / summary.comparison_count) * 100) || 0
    : 0;
  summary.validation_failure_rate = summary.comparison_count > 0
    ? Math.round((summary.disagree_real / summary.comparison_count) * 100) || 0
    : 0;

  return { results, summary };
}

module.exports = {
  diagnoseOne,
  diagnoseAll,
  buildPrompt,
  buildEnginePolicy,
  parseLLMResponse,  // 테스트용
  normalizeVerdict,
  classifyAgreement,
};

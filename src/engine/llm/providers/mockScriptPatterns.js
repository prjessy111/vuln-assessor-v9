'use strict';

/**
 * SecuMS Script XML SRV mapping.
 *
 * Script XML has raw command output, not a trusted security verdict. This file
 * keeps SRV metadata and conservative evidence patterns. When the raw signal is
 * not explicit, the mock AI provider should return "정보제공" so LLM/manual
 * review can decide without creating false positives.
 */

function normalizeSrvId(chkId) {
  const m = String(chkId || '').trim().toUpperCase().match(/^SRV-?(\d{3})$/);
  return m ? `SRV-${m[1]}` : null;
}

function activeLineMatches(text, regex) {
  return String(text || '')
    .split('\n')
    .map(line => line.trim())
    .filter(line => line && !line.startsWith('#') && !line.startsWith('$ ') && !line.startsWith('cmd# '))
    .some(line => regex.test(line));
}

function escapeRegex(s) {
  return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function hasListeningService(text, names) {
  // v2 수집기 마커 라인(SERVICE_PRESENCE=... "no LISTEN port...")이 서비스명+LISTEN 근접 매칭에
  // 걸려 과탐을 만들므로, 마커/힌트 라인은 매칭 입력에서 제외한다.
  const filtered = String(text || '').split('\n')
    .filter(l => !/SERVICE_PRESENCE=|COLLECTION_HINT=|no LISTEN/i.test(l))
    .join('\n');
  const service = names.map(escapeRegex).join('|');
  const re = new RegExp(`\\b(?:${service})\\b[\\s\\S]{0,120}\\b(?:LISTEN|LISTENING|RUNNING|SERVICE_RUNNING|STATE\\s*:\\s*4)\\b`, 'i');
  return re.test(filtered);
}

function normalizeAddress(raw) {
  return String(raw || '').replace(/^\[/, '').replace(/\]$/, '').trim();
}

function isLoopbackAddress(raw) {
  const addr = normalizeAddress(raw).toLowerCase();
  return addr === 'localhost' || addr === '::1' || addr.startsWith('127.');
}

function listeningPortAddresses(text, ports) {
  const wanted = new Set(ports.map(String));
  const addresses = [];
  const lines = String(text || '').split('\n');

  for (const line of lines) {
    if (!/\b(?:LISTEN|LISTENING)\b/i.test(line)) continue;

    const matches = line.matchAll(/(\*|0\.0\.0\.0|127(?:\.\d{1,3}){3}|(?:\d{1,3}\.){3}\d{1,3}|\[::\]|\[::1\]|::|::1):(\d+)\b/g);
    for (const m of matches) {
      if (wanted.has(m[2])) addresses.push(normalizeAddress(m[1]));
    }
  }

  return addresses;
}

function hasListeningPort(text, ports) {
  return listeningPortAddresses(text, ports)
    .some(addr => addr === '*' || addr === '0.0.0.0' || addr === '::' || !isLoopbackAddress(addr));
}

function hasLoopbackOnlyPort(text, ports) {
  const addresses = listeningPortAddresses(text, ports);
  return addresses.length > 0 && addresses.every(isLoopbackAddress);
}

// PowerShell Format-Table 출력 파싱: "헤더 / ---- 구분선 / 값 행" 형식에서
// 컬럼 위치 기반으로 key 컬럼의 셀 값을 추출. (v2 수집기 ai_ready_script_v2 대응)
//   LimitBlankPasswordUse          ScreenSaveActive ScreenSaveTimeOut
//   ---------------------          ---------------- -----------------
//                       1          1
function psTableCell(text, key) {
  const lines = String(text || '').split('\n');
  const wanted = String(key).toLowerCase();
  for (let i = 0; i < lines.length - 2; i++) {
    const header = lines[i];
    if (header.toLowerCase().indexOf(wanted) === -1) continue;
    const sep = (lines[i + 1] || '').trim();
    if (!sep || !/^[-\s]+$/.test(sep) || sep.indexOf('-') === -1) continue;
    let row = lines[i + 2] || '';
    // 값 행이 없고 바로 수집기 래퍼 마커/다음 명령이 오면 "빈 테이블"이다 — 마커를 값으로 오인 금지
    if (/^\s*(?:RAW_COMMAND_OUTPUT_(?:BEGIN|END)|AI_EVIDENCE_BLOCK_(?:BEGIN|END)|COLLECTION_HINT=|\$|cmd#)/.test(row)) row = '';
    const tokens = [...header.matchAll(/\S+/g)];
    const idx = tokens.findIndex(tk => tk[0].toLowerCase() === wanted);
    if (idx === -1) continue;
    const start = tokens[idx].index;
    const end = idx + 1 < tokens.length ? tokens[idx + 1].index : row.length;
    // NUL 등 제어문자는 값이 아니므로 제거 (빈 REG_SZ 값에 이 섞여 나옴)
    const clean = s => s.replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, '').trim();
    const cell = clean(row.slice(start, end));
    if (cell) return cell;
    // 단일 컬럼 테이블에서 값이 좌/우측 정렬된 경우
    if (tokens.length === 1) { const alt = clean(row); if (alt) return alt; }
    return null; // 헤더는 있으나 해당 컬럼 값이 비어있음 (미수집)
  }
  return null;
}

// NetbiosOptions 값 수집 — PS 리스트("NetbiosOptions : 0"), 인터페이스별 테이블 행("Tcpip_{GUID}   0") 모두 지원
function netbiosOptionValues(text) {
  const t = String(text || '');
  const vals = [...t.matchAll(/NetbiosOptions\s*[:=]?\s*(?:REG_\w+\s+)?(?:0x([0-9a-f]+)|(\d+))/gi)]
    .map(m => parseInt(m[1] || m[2], m[1] ? 16 : 10));
  if (/NetbiosOptions/i.test(t)) {
    for (const m of t.matchAll(/^\s*Tcpip_\{[0-9a-f-]+\}\s+(\d+)\s*$/gim)) vals.push(parseInt(m[1], 10));
  }
  return vals;
}

// Windows PS cacls(AccessToString) ACL 판정: 광범위 그룹에 쓰기성 권한이 있으면 취약,
// ACL이 수집되었고 그런 부여가 없으면 양호. (SAM/system32/사용자 프로필 등)
function winAclRules(targetLabel) {
  const broadGrant = /(?:Everyone|BUILTIN\\Users|Authenticated Users|\bUsers\b|Guests)\s+Allow\s+(?:FullControl|Modify|Write)/i;
  return {
    vuln: [{ pattern: text => {
      const m = String(text || '').match(broadGrant);
      return m ? targetLabel + ' ACL에 광범위 그룹 쓰기성 권한: ' + m[0] : null;
    } }],
    safe: [{ pattern: text => {
      const s = String(text || '');
      return /AccessToString\s*:/.test(s) && !broadGrant.test(s)
        ? targetLabel + ' ACL이 SYSTEM/Administrators 등 관리 주체로 제한됨' : null;
    } }],
  };
}

// 권한 할당(secedit SeXxxPrivilege/Right) 값이 허용 SID로만 구성됐는지
function privilegeRestrictedTo(key, allowedSids, reason) {
  return { pattern: text => {
    const m = String(text || '').match(new RegExp(key + '\\s*=\\s*([^\\n]+)', 'i'));
    if (!m) return null;
    const sids = m[1].split(',').map(s => s.trim().replace(/^\*/, '')).filter(Boolean);
    return sids.length && sids.every(s => allowedSids.includes(s)) ? reason : null;
  } };
}

// reg query PS 테이블이 "헤더만 있고 값이 전부 빈" 상태인지 (키 미설정)
function regTableAllEmpty(text, keys) {
  const s = String(text || '');
  if (!keys.some(k => new RegExp(k, 'i').test(s))) return false;
  // 문자열 리터럴 이스케이프 주의: '\s'는 's'로 해석되므로 '\\s'로 써야 정규식 \s가 된다
  if (!new RegExp(keys[0] + '[^\\n]*\\n[-\\s]+\\n', 'i').test(s) && !/Not Found \/ No Data/i.test(s)) return false;
  return keys.every(k => psTableCell(s, k) === null);
}

// OS 지원종료(EoS) 판정 — 스캔일(started_at_utc)과 고정 EOL 테이블 비교(결정론)
const OS_EOL_TABLE = [
  { re: /CentOS (?:Linux |release )?6/i, name: 'CentOS 6', eol: '2020-11-30' },
  { re: /CentOS (?:Linux |release )?7|cpe:\/o:centos:centos:7/i, name: 'CentOS 7', eol: '2024-06-30' },
  { re: /CentOS (?:Linux |release )?8/i, name: 'CentOS 8', eol: '2021-12-31' },
  { re: /Windows Server 2008/i, name: 'Windows Server 2008', eol: '2020-01-14' },
  { re: /Windows Server 2012/i, name: 'Windows Server 2012(R2)', eol: '2023-10-10' },
  { re: /Windows Server 2016/i, name: 'Windows Server 2016', eol: '2027-01-12' },
  { re: /Windows Server 2019/i, name: 'Windows Server 2019', eol: '2029-01-09' },
  { re: /Windows Server 2022/i, name: 'Windows Server 2022', eol: '2031-10-14' },
];
function osEolVerdict(text) {
  const s = String(text || '');
  const hit = OS_EOL_TABLE.find(e => e.re.test(s));
  if (!hit) return null;
  const scanDate = (s.match(/started_at_utc=(\d{4}-\d{2}-\d{2})/) || [])[1];
  if (scanDate) return { name: hit.name, eol: hit.eol, expired: scanDate > hit.eol };
  // 스캔일 정보가 없으면 EOL이 확정적으로 지난 버전만 판정 (결정론 유지)
  const LONG_PAST_EOL = ['2020-11-30', '2024-06-30', '2021-12-31', '2020-01-14', '2023-10-10'];
  if (LONG_PAST_EOL.includes(hit.eol)) return { name: hit.name, eol: hit.eol, expired: true };
  return null;
}

function regDwordValue(text, key) {
  const t = String(text || '');
  // 1) reg.exe 고전 형식(Key REG_DWORD 0x1) / PS 리스트(Key : 1) / secedit(Key = 1, MACHINE\...\Key=4,1)
  const re = new RegExp(`${escapeRegex(key)}(?:\\s*[:=]\\s*|\\s+)(?:REG_\\w+\\s+)?(?:\\d+,)?(?:0x([0-9a-f]+)|(\\d+))\\b`, 'i');
  const m = t.match(re);
  if (m) return parseInt(m[1] || m[2], m[1] ? 16 : 10);
  // 2) PowerShell 테이블 형식 (헤더/구분선/값행)
  const cell = psTableCell(t, key);
  if (cell !== null && /^(?:0x[0-9a-f]+|\d+)$/i.test(cell)) {
    return /^0x/i.test(cell) ? parseInt(cell, 16) : parseInt(cell, 10);
  }
  return null;
}

function regStringValue(text, key) {
  const re = new RegExp(`${escapeRegex(key)}(?:\\s*[:=]\\s*|\\s+)(?:REG_\\w+\\s+)?([^\\r\\n]+)`, 'i');
  const m = String(text || '').match(re);
  if (m) return m[1].trim();
  return psTableCell(text, key);
}

function dwordEquals(key, expected, reason) {
  return {
    pattern: text => regDwordValue(text, key) === expected ? reason : null,
  };
}

function dwordNotEquals(key, expected, reason) {
  return {
    pattern: text => {
      const value = regDwordValue(text, key);
      return value !== null && value !== expected ? reason : null;
    },
  };
}

function dwordLessThan(key, minimum, reason) {
  return {
    pattern: text => {
      const value = regDwordValue(text, key);
      return value !== null && value < minimum ? reason : null;
    },
  };
}

function dwordAtLeast(key, minimum, reason) {
  return {
    pattern: text => {
      const value = regDwordValue(text, key);
      return value !== null && value >= minimum ? reason : null;
    },
  };
}

function dwordGreaterThan(key, maximum, reason) {
  return {
    pattern: text => {
      const value = regDwordValue(text, key);
      return value !== null && value > maximum ? reason : null;
    },
  };
}

// 보안 강화 레지스트리 키: "키 부재 = 강화 미적용(기본값 동작) = 취약" 항목용.
// raw에 해당 키를 조회한 흔적이 있는데 값이 없거나 기준 미만이면 취약 신호.
// (LLM 판정 기준의 "설정값 부재는 부재양호가 아니다" 원칙의 결정론 구현)
function dwordMissingOrLess(key, minimum, reason) {
  return {
    pattern: text => {
      if (!new RegExp(escapeRegex(key), 'i').test(String(text || ''))) return null; // 수집 시도 없음 → 판단 보류
      const value = regDwordValue(text, key);
      if (value === null) return `${key} 미설정(시스템 기본값 동작) — ${reason}`;
      return value < minimum ? `${key}=${value} — ${reason}` : null;
    },
  };
}

// loopback + 가상화 내부대역(libvirt virbr0 192.168.122.x, VirtualBox NAT 10.0.2.x)
// 에만 바인딩된 경우 외부 공격면 없음 → 양호. (LLM 과탐 방지 규칙 (라) 이식)
function isInternalVirtAddress(raw) {
  const addr = normalizeAddress(raw).toLowerCase();
  return isLoopbackAddress(addr) || addr.startsWith('192.168.122.') || addr.startsWith('10.0.2.');
}

function hasInternalOnlyPort(text, ports) {
  const addresses = listeningPortAddresses(text, ports);
  return addresses.length > 0
    && addresses.every(a => a !== '*' && a !== '0.0.0.0' && a !== '::' && isInternalVirtAddress(a));
}

function lineForPath(text, pathRe) {
  return String(text || '')
    .split('\n')
    // SELinux(.)/ACL(+) 컨텍스트 마커가 붙은 11자 모드(-rw-r--r--.)도 허용
    .find(line => /^[bcdlps-][rwxStTs-]{9}[.+]?\s+/.test(line.trim()) && pathRe.test(line));
}

function groupOrOtherWritable(pathRe, reason) {
  return {
    pattern: text => {
      const line = lineForPath(text, pathRe);
      if (!line) return null;
      const mode = line.trim().slice(0, 10);
      return mode[5] === 'w' || mode[8] === 'w' ? reason : null;
    },
  };
}

function notGroupOrOtherWritable(pathRe, reason) {
  return {
    pattern: text => {
      const line = lineForPath(text, pathRe);
      if (!line) return null;
      const mode = line.trim().slice(0, 10);
      return mode[5] !== 'w' && mode[8] !== 'w' ? reason : null;
    },
  };
}

function shadowReadableByOthers(pathRe, reason) {
  return {
    pattern: text => {
      const line = lineForPath(text, pathRe);
      if (!line) return null;
      const mode = line.trim().slice(0, 10);
      return /[rwx]/.test(mode.slice(4)) ? reason : null;
    },
  };
}

function shadowPrivate(pathRe, reason) {
  return {
    pattern: text => {
      const line = lineForPath(text, pathRe);
      if (!line) return null;
      const mode = line.trim().slice(0, 10);
      return !/[rwx]/.test(mode.slice(4)) ? reason : null;
    },
  };
}

function anyFindingLine(reason) {
  return {
    pattern: text => {
      const lines = String(text || '').split('\n').map(x => x.trim()).filter(Boolean);
      const findings = lines.filter(line =>
        !/^(\$|cmd#|#)\s+/.test(line) &&
        !/^[-=]{3,}$/.test(line) &&
        !/^<\?xml|^<\/?[A-Za-z]/.test(line) &&
        // v2 수집기 래퍼/마커 라인은 "발견"이 아니다 (SRV-093/095/144 과탐 원인이었음)
        !/^(?:AI_RAW_CONTEXT|RAW_OUTPUT_BEGIN|AI_EVIDENCE_BLOCK_(?:BEGIN|END)|RAW_COMMAND_OUTPUT_(?:BEGIN|END))$/.test(line) &&
        !/^(?:schema|evidence_schema|source|check_ids|host|os|os_family|collection_profile|collection_status|collector_privilege|started_at_utc|duration_ms|output_bytes|output_format|error_text|command_marker|command|commands|raw_begin_marker|raw_end_marker|script_data_role|script_verdict_source|judgment_mode|judgment_policy|safe_subtype_policy|decision_route|allowed_verdicts|collection_signals|fast_hints|truncated|collection_config|scan_scope|fsi_scan_scope|scan_epoch_days|FIREWALLD_STATE)=/.test(line) &&
        !/^(?:SERVICE_PRESENCE|COLLECTION_HINT)=/.test(line) &&
        !/^\[\s*[a-zA-Z0-9_|]+\s*\]\[(?:S|E)\]$/.test(line) &&
        !/no such file|cannot access|not found|permission denied/i.test(line)
      );
      return findings.length ? reason : null;
    },
  };
}

function allDwordsAtLeast(keys, minimum, reason) {
  return {
    pattern: text => {
      const values = keys.map(k => regDwordValue(text, k));
      return values.every(v => v !== null && v >= minimum) ? reason : null;
    },
  };
}

function anyDwordLessThan(keys, minimum, reason) {
  return {
    pattern: text => keys.some(k => {
      const v = regDwordValue(text, k);
      return v !== null && v < minimum;
    }) ? reason : null,
  };
}

const CAT = {
  account: '계정 관리',
  password: '비밀번호 정책',
  network: '네트워크 서비스',
  access: '접근 제어',
  file: '파일 권한',
  log: '로그/감사',
  web: '웹/WAS 보안',
  dns: 'DNS 보안',
  patch: '패치 관리',
  system: '시스템 보안',
  info: '정보제공',
};

const DEFAULT_RECOMMEND = 'raw 출력과 공식 SRV 기준을 대조해 보안 기준에 맞게 조치하십시오.';

function meta(id, title, category, severity, criteria, vulnCondition, safeCondition, recommend = DEFAULT_RECOMMEND, coverage = 'sample_derived') {
  return {
    id,
    title,
    category,
    severity,
    criteria,
    vuln_condition: vulnCondition,
    safe_condition: safeCondition,
    recommend,
    coverage,
  };
}

function buildDefaultMeta() {
  const rows = {};
  for (let i = 1; i <= 168; i++) {
    const id = `SRV-${String(i).padStart(3, '0')}`;
    rows[id] = meta(
      id,
      `${id} 정의서 확인 필요`,
      CAT.system,
      '중',
      '저장소 내 공식 SRV 정의서가 없어 샘플 raw 출력으로 자동 판정 기준을 확정할 수 없습니다.',
      '공식 기준 확인 전에는 취약으로 자동 확정하지 않습니다.',
      '공식 기준 확인 전에는 값준수양호로 자동 확정하지 않습니다.',
      '공식 SRV 정의서 또는 추가 Script XML 샘플을 확보해 기준을 보강하십시오.',
      'definition_needed'
    );
  }
  return rows;
}

const SRV_META_ROWS = [
  meta('SRV-001', 'SNMP 커뮤니티 문자열', CAT.network, '상', 'SNMP community가 기본값/public/private 또는 쓰기 권한으로 노출되는지 확인', 'public/private 기본 community 또는 쓰기 가능한 community 확인', 'SNMP 미사용 또는 추측 어려운 읽기 전용 community만 존재', 'SNMP 기본 community를 제거하고 필요 시 ACL과 읽기 전용 community를 적용하십시오.'),
  meta('SRV-002', 'SNMP 쓰기 권한 제한', CAT.network, '상', 'SNMP community 권한과 접근 제어를 확인', '쓰기 권한 community 또는 기본 community 확인', 'SNMP 미사용 또는 제한된 읽기 전용 community만 존재', 'SNMP write community를 제거하고 허용 관리자를 제한하십시오.'),
  meta('SRV-003', 'SNMP 허용 관리자', CAT.network, '상', 'SNMP permitted managers 설정 여부 확인', 'SNMP가 실행 중인데 허용 관리자 제한이 없음', 'SNMP 미사용 또는 허용 관리자 목록이 제한됨', 'SNMP PermittedManagers를 관리 서버로 제한하십시오.'),
  meta('SRV-004', 'SMTP 서비스 노출', CAT.network, '상', 'SMTP/sendmail 서비스 외부 LISTEN 여부 확인', '외부 인터페이스에서 25/tcp가 LISTEN 중', 'SMTP 미사용 또는 로컬 전용 바인딩', '불필요한 SMTP 서비스를 중지하거나 접근 제어를 적용하십시오.'),
  meta('SRV-005', 'Sendmail PrivacyOptions', CAT.network, '중', 'sendmail PrivacyOptions에서 noexpn/novrfy 적용 여부 확인', 'VRFY/EXPN 제한 옵션 미적용', 'noexpn, novrfy 등 정보 노출 제한 옵션 적용', 'sendmail.cf에 PrivacyOptions noexpn, novrfy를 적용하십시오.'),
  meta('SRV-006', 'Sendmail 로그 수준', CAT.log, '중', 'sendmail LogLevel이 감사 가능한 수준인지 확인', 'LogLevel 미설정 또는 과도하게 낮음', '운영 기준에 맞는 LogLevel 적용', '메일 로그 수준을 보안 감사가 가능한 수준으로 설정하십시오.'),
  meta('SRV-007', 'Sendmail 버전 노출', CAT.network, '하', 'SMTP 배너 또는 설정에서 버전 노출 여부 확인', '메일 서버 버전/배너가 외부에 노출', '버전 노출 차단 또는 서비스 미사용', '메일 배너의 상세 버전 노출을 제한하십시오.'),
  meta('SRV-008', 'Sendmail DoS 제한', CAT.network, '중', 'sendmail 연결/큐/부하 제한 설정 확인', '연결 제한 또는 큐 제한 미설정', '운영 기준에 맞는 제한값 적용', 'sendmail 연결 수와 큐 처리 제한을 설정하십시오.'),
  meta('SRV-009', 'Sendmail 설정 권한', CAT.file, '중', '/etc/mail 및 sendmail 설정 파일 권한 확인', '메일 설정 파일이 일반 사용자에게 쓰기 가능', 'root 소유 및 group/other 쓰기 금지', '메일 설정 파일 권한을 root 관리 범위로 제한하십시오.'),
  meta('SRV-010', 'Sendmail VRFY/EXPN', CAT.network, '중', 'VRFY/EXPN 명령 제한 여부 확인', 'VRFY/EXPN 명령이 허용됨', 'VRFY/EXPN 명령 제한 또는 SMTP 미사용', 'VRFY/EXPN을 비활성화해 계정 열거를 차단하십시오.'),
  meta('SRV-011', 'FTP 서비스 노출', CAT.network, '상', 'FTP 서비스와 21/tcp LISTEN 여부 확인', '외부 FTP 서비스 실행 또는 21/tcp LISTEN', 'FTP 미사용 또는 보안 대체 프로토콜 사용', 'FTP를 중지하고 SFTP 등 암호화 프로토콜로 대체하십시오.'),
  meta('SRV-012', 'Anonymous FTP 제한', CAT.network, '상', 'anonymous FTP 접속 허용 여부 확인', 'anonymous_enable=YES 또는 익명 접속 허용', 'anonymous 접속 차단 또는 FTP 미사용', '익명 FTP를 비활성화하십시오.'),
  meta('SRV-013', 'FTP 서비스 설정', CAT.network, '상', 'FTP 서비스 설치/실행 및 설정 상태 확인', '불필요한 FTP 서비스 실행', 'FTP 미사용 또는 보안 설정 적용', '불필요한 FTP 서비스를 제거하거나 접근 제어를 적용하십시오.'),
  meta('SRV-014', 'NFS exports 제한', CAT.network, '상', '/etc/exports 공유 범위와 옵션 확인', '전체 공개, rw, no_root_squash 등 위험 옵션', 'NFS 미사용 또는 최소 호스트/읽기 전용 공유', 'NFS 공유 대상을 최소화하고 root_squash를 적용하십시오.'),
  meta('SRV-015', 'NFS 신뢰 설정', CAT.network, '상', 'netgroup/dfstab 등 NFS 신뢰 설정 확인', '광범위한 신뢰 관계 또는 쓰기 공유', '신뢰 관계 최소화 및 접근 제한', 'NFS 신뢰 설정과 공유 권한을 최소화하십시오.'),
  meta('SRV-016', 'RPC 위험 서비스', CAT.network, '상', 'cmsd/ttdbserver 등 RPC 위험 서비스 확인', '불필요한 RPC 서비스 실행', '서비스 미사용 또는 비활성화', '사용하지 않는 RPC 서비스를 중지하십시오.'),
  meta('SRV-017', 'Automount 서비스', CAT.network, '중', 'autofs/automount 실행 여부와 필요성 확인', '불필요한 자동 마운트 서비스 실행', '미사용 또는 제한된 설정', '불필요한 automount를 중지하고 마운트 대상을 제한하십시오.'),
  meta('SRV-018', '관리 공유 제한', CAT.access, '중', 'Windows AutoShareServer/AutoShareWks 및 net share 확인', '기본 관리 공유가 불필요하게 활성화', '관리 공유 비활성 또는 운영상 필요 범위 제한', '불필요한 기본 관리 공유를 비활성화하십시오.'),
  meta('SRV-019', 'TFTP/Talk 서비스', CAT.network, '상', 'tftp/talk 계열 서비스 실행 여부 확인', 'tftp/talk 서비스 실행', '서비스 미사용 또는 비활성화', '불필요한 tftp/talk 서비스를 중지하십시오.'),
  meta('SRV-020', '공유 폴더 권한', CAT.access, '상', '공유 폴더와 ACL 확인', 'Everyone/Users에 과도한 쓰기 또는 전체 권한', '필요 사용자/그룹에 최소 권한 부여', '공유 폴더 ACL을 최소 권한으로 조정하십시오.'),
  meta('SRV-021', 'IIS 설정 파일 보호', CAT.web, '상', 'IIS metabase/applicationHost 설정 파일 보호 확인', 'IIS 설정 파일이 노출되거나 권한이 과다', '설정 파일 보호 및 최소 권한', 'IIS 설정 파일 권한과 노출 경로를 점검하십시오.'),
  meta('SRV-022', '빈 암호 원격 제한', CAT.password, '상', 'LimitBlankPasswordUse 설정 확인', '빈 암호 계정의 원격 로그온 허용', 'LimitBlankPasswordUse=1 적용', '빈 암호 원격 로그온 제한을 활성화하십시오.'),
  meta('SRV-023', 'RDP 암호화 수준', CAT.network, '상', 'RDP MinEncryptionLevel 확인', '낮은 RDP 암호화 수준 사용', 'RDP 암호화 수준 2 이상 적용', 'RDP 암호화 수준을 높이고 NLA를 적용하십시오.'),
  meta('SRV-024', 'Telnet 서비스 제한', CAT.network, '상', 'TlntSvr 실행 여부 확인', 'Telnet 서비스 실행 또는 23/tcp LISTEN', 'Telnet 미사용 또는 비활성화', 'Telnet을 중지하고 SSH/RDP 보안 접속으로 대체하십시오.'),
  meta('SRV-025', 'hosts 신뢰 파일', CAT.access, '상', 'hosts.equiv/.rhosts 신뢰 파일 및 /etc/hosts 권한 확인', '+ 신뢰 또는 과도한 권한', '신뢰 파일 부재 또는 안전한 권한', 'hosts 기반 신뢰 파일을 제거하고 권한을 제한하십시오.'),
  meta('SRV-026', 'SSH 서비스 설정', CAT.network, '상', 'SSH 서비스와 sshd_config 보안 설정 확인', 'root 원격 로그인 허용 등 위험 설정', 'root 로그인 차단 및 안전한 SSH 설정', 'sshd_config에서 PermitRootLogin no 등 보안 옵션을 적용하십시오.'),
  meta('SRV-027', 'TCP Wrapper 제한', CAT.access, '중', 'hosts.allow/hosts.deny 접근 제어 확인', '네트워크 접근 제어 부재 또는 전체 허용', '필요 호스트만 허용', 'hosts.allow/deny 또는 방화벽으로 접근을 제한하십시오.'),
  meta('SRV-028', 'RDP 유휴 제한', CAT.access, '중', 'RDP MaxIdleTime 확인', '유휴 세션 제한 미설정', '운영 기준 이하 유휴 시간 제한 적용', 'RDP 유휴 세션 제한을 설정하십시오.'),
  meta('SRV-029', '강제 로그오프', CAT.access, '중', 'EnableForcedLogOff/autodisconnect 확인', '만료/유휴 세션 강제 종료 미설정', '강제 로그오프 또는 자동 연결 해제 적용', '유휴 및 만료 세션 강제 종료 정책을 적용하십시오.'),
  meta('SRV-030', 'Finger 서비스 제한', CAT.network, '중', 'finger 서비스 실행 여부 확인', 'finger 서비스 실행으로 계정 정보 노출', 'finger 미사용 또는 비활성화', 'finger 서비스를 중지하십시오.'),
  meta('SRV-031', '익명 열거 제한', CAT.access, '상', 'RestrictAnonymous/RestrictAnonymousSam 확인', '익명 SAM/공유 열거 허용', '익명 열거 제한 적용', 'RestrictAnonymous 값을 보안 기준에 맞게 설정하십시오.'),
  meta('SRV-032', 'NetBIOS over TCP/IP', CAT.network, '중', 'NetbiosOptions 확인', 'NetBIOS over TCP/IP 활성화', 'NetBIOS over TCP/IP 비활성화', '불필요한 NetBIOS over TCP/IP를 비활성화하십시오.'),
  meta('SRV-033', 'SRV-033 정의 필요', CAT.network, '중', '현재 샘플에 SRV-033 raw 출력이 없어 기준 확인 필요', '공식 기준 전에는 자동 취약 확정 안 함', '공식 기준 전에는 자동 양호 확정 안 함', 'SRV-033 공식 기준 또는 XML 샘플을 추가하십시오.', 'definition_needed'),
  meta('SRV-034', '불필요 Windows 서비스', CAT.network, '중', 'Alerter/ClipSrv/Messenger 등 레거시 서비스 확인', '레거시 서비스 실행', '서비스 미사용 또는 비활성화', '불필요한 레거시 서비스를 중지하십시오.'),
  meta('SRV-035', 'r-command 서비스', CAT.network, '상', 'rexec/rlogin/rsh 서비스 실행 여부 확인', 'r-command 계열 서비스 실행', '서비스 미사용 또는 비활성화', 'r-command 서비스를 제거하고 SSH로 대체하십시오.'),
  meta('SRV-036', 'Echo/Discard 서비스', CAT.network, '중', 'echo/discard/chargen 등 테스트 서비스 확인', '테스트 서비스 실행', '서비스 미사용 또는 비활성화', '불필요한 inetd 테스트 서비스를 중지하십시오.'),
  meta('SRV-037', 'Windows FTP 서비스', CAT.network, '상', 'MSFTPSVC/FTPSVC 실행 여부 확인', 'FTP 서비스 실행', 'FTP 미사용 또는 제한 운영', 'Windows FTP 서비스를 중지하거나 접근 제어를 적용하십시오.'),
  meta('SRV-038', 'IIS 서비스 운영', CAT.web, '상', 'IISADMIN/W3SVC 실행 여부와 필요성 확인', '불필요한 IIS 서비스 실행', 'IIS 미사용 또는 보안 설정 적용', '불필요한 IIS 서비스를 중지하십시오.'),
  meta('SRV-039', 'WebtoB 서비스', CAT.web, '상', 'WebtoB 서비스 실행 및 설정 확인', '불필요하거나 취약 설정의 WebtoB 실행', '서비스 미사용 또는 안전 설정', 'WebtoB 서비스 필요성과 설정을 점검하십시오.'),
  meta('SRV-040', '웹 디렉터리 목록화', CAT.web, '상', 'Apache/IIS 디렉터리 인덱싱 확인', 'Indexes/Directory Browsing 활성화', '디렉터리 목록화 비활성화', '웹 디렉터리 목록화를 비활성화하십시오.'),
  meta('SRV-041', 'CGI/스크립트 ACL', CAT.web, '상', 'CGI/scripts 디렉터리 권한 확인', 'Everyone/Users 쓰기 또는 실행 권한 과다', '관리자/서비스 계정 최소 권한', 'CGI/스크립트 디렉터리 권한을 최소화하십시오.'),
  meta('SRV-042', 'Apache Indexes 제한', CAT.web, '상', 'Apache Options Indexes 확인', 'Indexes 활성화', 'Indexes 비활성화', 'Apache Options에서 Indexes를 제거하십시오.'),
  meta('SRV-043', 'Apache 심볼릭 링크', CAT.web, '중', 'FollowSymLinks 설정 확인', 'FollowSymLinks 무제한 허용', 'SymLinksIfOwnerMatch 등 제한 적용', '심볼릭 링크 추적 옵션을 제한하십시오.'),
  meta('SRV-044', 'Apache 불필요 기능', CAT.web, '중', '웹 서버 불필요 모듈/옵션 확인', '불필요 기능 활성화', '필요 기능만 활성화', '웹 서버 불필요 모듈과 옵션을 제거하십시오.'),
  meta('SRV-045', '웹 계정 노출', CAT.account, '상', '웹 서비스 관련 계정/패스워드 파일 노출 확인', '계정 또는 해시 정보 노출', '민감 파일 비노출 및 안전 권한', '웹 경로에서 계정/패스워드 파일 접근을 차단하십시오.'),
  meta('SRV-046', '웹 서버 버전 노출', CAT.web, '중', 'ServerTokens/ServerSignature 등 버전 노출 확인', '상세 버전/배너 노출', '버전 노출 최소화', '웹 서버 배너와 오류 페이지 버전 노출을 제한하십시오.'),
  meta('SRV-047', 'FollowSymLinks 제한', CAT.web, '중', 'FollowSymLinks 옵션 적용 여부 확인', 'FollowSymLinks 무제한 허용', '소유자 일치 등 제한 적용', 'FollowSymLinks를 제한하거나 제거하십시오.'),
  meta('SRV-048', 'IIS 서비스 노출', CAT.web, '상', 'IIS 서비스 실행 및 노출 확인', '불필요한 IIS 서비스 실행', 'IIS 미사용 또는 안전 운영', 'IIS 서비스 필요성을 확인하고 불필요하면 중지하십시오.'),
  meta('SRV-049', 'IIS 샘플 파일', CAT.web, '중', 'IIS 샘플/기본 파일 존재 확인', '샘플 파일 또는 기본 가상 디렉터리 존재', '샘플 파일 제거', 'IIS 샘플 파일과 기본 디렉터리를 제거하십시오.'),
  meta('SRV-050', 'IIS 스크립트 매핑', CAT.web, '상', '위험 스크립트 매핑 확인', '불필요한 실행 매핑 허용', '필요한 매핑만 유지', 'IIS 스크립트 매핑을 최소화하십시오.'),
  meta('SRV-051', 'IIS 디렉터리 검색', CAT.web, '상', 'Directory Browsing 설정 확인', '디렉터리 검색 허용', '디렉터리 검색 차단', 'IIS Directory Browsing을 비활성화하십시오.'),
  meta('SRV-052', 'IIS Parent Paths', CAT.web, '중', 'EnableParentPaths 설정 확인', '상위 경로 접근 허용', '상위 경로 접근 차단', 'IIS Parent Paths를 비활성화하십시오.'),
  meta('SRV-053', 'IIS WebDAV 제한', CAT.web, '상', 'WebDAV 기능 활성 여부 확인', '불필요한 WebDAV 활성화', 'WebDAV 비활성 또는 제한', '불필요한 WebDAV 기능을 제거하십시오.'),
  meta('SRV-054', 'IIS 로깅 설정', CAT.log, '중', 'IIS 로그 기록 활성 여부 확인', '로깅 비활성 또는 불충분', '필수 로그 기록 활성', 'IIS 로깅을 활성화하고 보존 기준을 적용하십시오.'),
  meta('SRV-055', 'IIS 인증 설정', CAT.access, '상', '익명/기본 인증 등 IIS 인증 방식 확인', '불필요한 익명 또는 약한 인증 허용', '필요 인증만 허용', 'IIS 인증 방식을 최소 권한 기준으로 조정하십시오.'),
  meta('SRV-056', 'IIS SSL/TLS', CAT.web, '상', 'IIS 암호화 통신 설정 확인', '민감 서비스에 평문 통신 허용', 'TLS 적용 및 약한 프로토콜 제한', 'IIS에 TLS와 안전한 암호 스위트를 적용하십시오.'),
  meta('SRV-057', 'IIS 파일 ACL', CAT.file, '상', 'IIS 웹 루트 및 설정 파일 ACL 확인', 'Everyone/Users 과다 권한', '서비스 계정과 관리자 최소 권한', 'IIS 파일/디렉터리 ACL을 최소 권한으로 조정하십시오.'),
  meta('SRV-058', 'IIS 오류/디버그', CAT.web, '중', '상세 오류와 디버그 노출 확인', '상세 오류 또는 디버그 정보 노출', '사용자에게 상세 오류 비노출', '상세 오류와 디버그 출력을 제한하십시오.'),
  meta('SRV-059', 'IIS SSI 명령 실행', CAT.web, '상', 'SSIEnableCmdDirective 설정 확인', 'SSI 명령 실행 허용', 'SSI 명령 실행 차단', 'SSI 명령 실행 지시자를 비활성화하십시오.'),
  meta('SRV-060', 'Tomcat 계정 파일', CAT.web, '상', 'tomcat-users.xml 계정/권한 확인', '기본/취약 계정 또는 평문 비밀번호 존재', '기본 계정 제거 및 최소 권한', 'Tomcat 기본 계정을 제거하고 관리 권한을 최소화하십시오.'),
  meta('SRV-061', 'DNS 서비스 노출', CAT.dns, '상', 'DNS/named 서비스 실행 여부 확인', '불필요한 DNS 서비스 실행 또는 외부 노출', 'DNS 미사용 또는 제한 운영', 'DNS 서비스를 필요 범위로 제한하십시오.'),
  meta('SRV-062', 'DNS 재귀 질의 제한', CAT.dns, '상', 'recursive query 허용 여부 확인', '외부 재귀 질의 허용', '허용 네트워크만 재귀 질의 가능', 'DNS recursion을 내부 대역으로 제한하십시오.'),
  meta('SRV-063', 'Windows DNS 재귀', CAT.dns, '상', 'Windows DNS NoRecursion 설정 확인', '재귀 질의 제한 미적용', 'NoRecursion=1 또는 제한 설정', 'Windows DNS 재귀 질의를 제한하십시오.'),
  meta('SRV-064', 'DNS Zone Transfer', CAT.dns, '상', 'zone transfer 허용 범위 확인', '임의 호스트 zone transfer 허용', '허가된 DNS 서버만 허용', 'Zone Transfer 대상을 제한하십시오.'),
  meta('SRV-065', 'DNS 버전 노출', CAT.dns, '중', 'DNS version.bind 또는 배너 노출 확인', 'DNS 버전 정보 노출', '버전 정보 숨김', 'DNS 버전 노출을 제한하십시오.'),
  meta('SRV-066', 'DNS Zone 설정', CAT.dns, '상', 'DNS zone 설정과 transfer 정책 확인', 'zone 정보 과다 노출 또는 transfer 제한 없음', 'zone 접근 제한 적용', 'DNS zone과 transfer 정책을 제한하십시오.'),
  meta('SRV-067', 'IIS ADC/msdfmap', CAT.web, '상', 'ADCLaunch/msdfmap.ini 존재 확인', '취약한 ADC/msdfmap 구성 존재', '구성 제거 또는 비활성화', 'ADCLaunch와 msdfmap.ini를 제거하거나 차단하십시오.'),
  meta('SRV-068', '패스워드 해시 노출', CAT.password, '상', 'shadow/SAM 해시 또는 패스워드 크랙 결과 확인', '패스워드 해시/평문/크랙 성공 정보 노출', '해시 보호 및 크랙 결과 없음', '패스워드 해시 접근을 차단하고 취약 계정을 조치하십시오.'),
  meta('SRV-069', 'Windows 암호 정책', CAT.password, '상', 'secedit 암호 정책 export 확인', '길이/복잡도/만료/잠금 정책 미흡', '보안 기준에 맞는 암호 정책 적용', '암호 길이, 복잡도, 만료, 잠금 정책을 강화하십시오.'),
  meta('SRV-070', '불필요 계정 점검', CAT.account, '중', '/etc/passwd 계정 목록 확인', '불필요 계정 또는 쉘 부여 계정 존재', '필요 계정만 존재하고 쉘 제한 적용', '불필요 계정을 제거하거나 로그인 쉘을 제한하십시오.'),
  meta('SRV-071', 'Windows 계정 목록', CAT.account, '중', 'net user 전체 계정 확인', '불필요/미사용 계정 활성화', '필요 계정만 활성화', '불필요한 Windows 계정을 비활성화하십시오.'),
  meta('SRV-072', 'Administrators 구성원', CAT.account, '상', 'Administrators 그룹 구성원 확인', '불필요한 관리자 권한 계정 존재', '승인된 관리자만 포함', '관리자 그룹 구성원을 최소화하십시오.'),
  meta('SRV-073', '관리자 권한 최소화', CAT.account, '상', '관리자 그룹 중복/불필요 구성원 확인', '승인되지 않은 관리자 계정 존재', '필요 관리자만 포함', '관리자 권한 부여 기준을 재검토하십시오.'),
  meta('SRV-074', '계정 상태/UID 점검', CAT.account, '중', 'shadow/net user의 계정 상태와 UID 확인', '잠금 미적용 계정 또는 이상 UID 존재', '계정 상태 정상 및 이상 UID 없음', '계정 잠금/만료/UID 상태를 정비하십시오.'),
  meta('SRV-075', '패스워드 만료 기간', CAT.password, '상', 'PASS_MAX_DAYS 또는 최대 암호 사용 기간 확인', '만료 기간 미설정 또는 과도하게 김', '정책 기준 이하 만료 기간 적용', '암호 최대 사용 기간을 보안 기준 이하로 설정하십시오.'),
  meta('SRV-076', '패스워드 최소 길이', CAT.password, '상', 'PASS_MIN_LEN 또는 최소 암호 길이 확인', '최소 길이 8 미만 또는 미설정', '최소 길이 8 이상 적용', '암호 최소 길이를 8 이상으로 설정하십시오.'),
  meta('SRV-077', '빈/평문 패스워드', CAT.password, '상', 'passwd 빈 패스워드 또는 Windows ClearTextPassword 확인', '빈 패스워드 또는 평문 저장 허용', '빈 패스워드 없음 및 평문 저장 차단', '빈/평문 패스워드를 제거하고 저장 정책을 차단하십시오.'),
  meta('SRV-078', 'Guest 계정 제한', CAT.account, '상', 'Guest 계정 활성 상태 확인', 'Guest 계정 활성화', 'Guest 계정 비활성화', 'Guest 계정을 비활성화하십시오.'),
  meta('SRV-079', 'Everyone 익명 포함', CAT.access, '상', 'everyoneincludesanonymous 설정 확인', 'Everyone 권한에 Anonymous 포함', 'Anonymous 제외', 'EveryoneIncludesAnonymous를 비활성화하십시오.'),
  meta('SRV-080', '프린터 드라이버 권한', CAT.access, '중', 'AddPrinterDrivers 권한 설정 확인', '일반 사용자 프린터 드라이버 설치 허용', '관리자만 설치 가능', '프린터 드라이버 설치 권한을 관리자에게 제한하십시오.'),
  meta('SRV-081', 'cron 권한', CAT.file, '상', '/var/spool/cron 권한 확인', 'cron 파일/디렉터리 일반 사용자 쓰기 가능', 'root 소유 및 쓰기 제한', 'cron 관련 파일 권한을 제한하십시오.'),
  meta('SRV-082', '시스템 디렉터리 권한', CAT.file, '상', '/usr,/bin,/sbin,/etc,/var 권한 확인', '중요 디렉터리 group/other 쓰기 가능', '중요 디렉터리 쓰기 제한', '시스템 디렉터리 권한을 root 관리 범위로 제한하십시오.'),
  meta('SRV-083', '시작 스크립트 권한', CAT.file, '상', 'inittab/init.d/rc*.d 권한 확인', '시작 스크립트 일반 사용자 쓰기 가능', 'root 소유 및 쓰기 제한', '시작 스크립트 권한을 제한하십시오.'),
  meta('SRV-084', 'passwd 파일 권한', CAT.file, '상', '/etc/passwd 권한 확인', '/etc/passwd group/other 쓰기 가능', 'root 소유 및 쓰기 제한', '/etc/passwd 권한을 644 이하 수준으로 제한하십시오.'),
  meta('SRV-085', 'shadow 파일 권한', CAT.file, '상', '/etc/shadow 권한 확인', '/etc/shadow가 group/other에 읽기/쓰기/실행 가능', 'root 또는 shadow 그룹만 제한 접근', '/etc/shadow 권한을 400/600 등으로 제한하십시오.'),
  meta('SRV-086', 'hosts 파일 권한', CAT.file, '중', '/etc/hosts 권한 확인', '/etc/hosts group/other 쓰기 가능', 'root 소유 및 쓰기 제한', '/etc/hosts 권한을 제한하십시오.'),
  meta('SRV-087', '컴파일러 접근', CAT.system, '중', 'cc/gcc 등 컴파일러 존재와 권한 확인', '일반 사용자가 불필요하게 컴파일러 사용 가능', '컴파일러 미설치 또는 권한 제한', '운영 서버의 불필요한 컴파일러를 제거하거나 제한하십시오.'),
  meta('SRV-088', 'inetd 설정 권한', CAT.file, '상', 'inetd/xinetd 설정 파일 권한 확인', '설정 파일 group/other 쓰기 가능', 'root 소유 및 쓰기 제한', 'inetd/xinetd 설정 파일 권한을 제한하십시오.'),
  meta('SRV-089', 'syslog 설정 권한', CAT.file, '중', 'syslog/rsyslog 설정 파일 권한 확인', '로그 설정 파일 group/other 쓰기 가능', 'root 소유 및 쓰기 제한', 'syslog 설정 파일 권한을 제한하십시오.'),
  meta('SRV-090', 'Remote Registry', CAT.access, '상', 'RemoteRegistry 서비스 상태 확인', 'RemoteRegistry 자동/실행 상태', 'RemoteRegistry 중지 또는 비활성화', 'RemoteRegistry 서비스를 비활성화하십시오.'),
  meta('SRV-091', 'SUID/SGID 파일', CAT.file, '상', 'SUID/SGID 파일 목록 확인', '불필요한 SUID/SGID 파일 존재', '승인된 파일만 SUID/SGID 보유', 'SUID/SGID 파일을 승인 목록 기준으로 정비하십시오.'),
  meta('SRV-092', '중요 파일 소유자', CAT.file, '중', '중요 파일 소유자/권한 확인', '소유자 이상 또는 과도한 권한', '정상 소유자와 제한 권한', '중요 파일의 소유자와 권한을 점검하십시오.'),
  meta('SRV-093', '홈 디렉터리 쓰기 파일', CAT.file, '상', '홈 디렉터리 world-writable 파일 확인', 'world-writable 파일 존재', 'world-writable 파일 없음', '사용자 홈의 world-writable 파일 권한을 제거하십시오.'),
  meta('SRV-094', 'FTP 관련 파일 권한', CAT.file, '상', 'FTP 스크립트/파일 권한 확인', 'FTP 관련 파일 과다 권한', 'root/서비스 계정 최소 권한', 'FTP 관련 파일 권한을 제한하십시오.'),
  meta('SRV-095', '소유자 없는 파일', CAT.file, '중', 'nouser/nogroup 파일 확인', '소유자/그룹 없는 파일 존재', '소유자/그룹 없는 파일 없음', '소유자 없는 파일을 삭제하거나 정상 소유자로 변경하십시오.'),
  meta('SRV-096', '사용자 dotfile 권한', CAT.file, '중', '사용자 홈 dotfile 권한 확인', 'dotfile group/other 쓰기 가능', 'dotfile 쓰기 권한 제한', '사용자 dotfile 권한을 제한하십시오.'),
  meta('SRV-097', 'FTP/IIS 사이트 권한', CAT.web, '상', 'FTP/IIS 사이트 목록과 권한 확인', '익명/공용 쓰기 가능 사이트 존재', '사이트 권한 최소화', 'FTP/IIS 사이트 권한을 최소 권한으로 조정하십시오.'),
  meta('SRV-098', 'SAM 파일 ACL', CAT.file, '상', 'Windows SAM 파일 ACL 확인', 'SAM 파일에 Everyone/Users 과다 권한', 'SYSTEM/Administrators 제한 권한', 'SAM 파일 ACL을 기본 보안 권한으로 복구하십시오.'),
  meta('SRV-099', 'services 파일 권한', CAT.file, '중', '/etc/services 권한 확인', '/etc/services group/other 쓰기 가능', 'root 소유 및 쓰기 제한', '/etc/services 권한을 제한하십시오.'),
  meta('SRV-100', 'xterm 권한', CAT.file, '중', 'xterm 파일 권한 확인', 'xterm SUID 또는 과다 권한', 'SUID 제거 및 쓰기 제한', 'xterm의 불필요한 SUID/쓰기 권한을 제거하십시오.'),
  meta('SRV-101', '예약 작업 권한', CAT.access, '중', 'at/schtasks 예약 작업 확인', '불필요하거나 권한 과다한 예약 작업 존재', '승인된 작업만 존재', '예약 작업 목록과 실행 권한을 정비하십시오.'),
  meta('SRV-102', '사용자 프로필 ACL', CAT.file, '상', '사용자 파일/프로필 ACL 확인', 'Everyone/Users 과다 권한', '사용자와 관리자 최소 권한', '사용자 파일 ACL을 최소 권한으로 조정하십시오.'),
  meta('SRV-103', 'LM 인증 수준', CAT.access, '상', 'LmCompatibilityLevel 확인', 'LM/NTLM 약한 인증 허용', 'NTLMv2 이상 제한', 'LmCompatibilityLevel을 3 이상으로 설정하십시오.'),
  meta('SRV-104', '보안 채널 서명', CAT.access, '상', 'Netlogon RequireSignOrSeal/Seal/Sign 확인', '보안 채널 서명/암호화 미적용', '서명/암호화 옵션 활성화', 'Netlogon 보안 채널 서명과 암호화를 활성화하십시오.'),
  meta('SRV-105', '시작 프로그램 레지스트리', CAT.system, '중', 'Run 시작 프로그램 레지스트리 확인', '불필요/의심 시작 프로그램 존재', '승인된 시작 프로그램만 존재', '시작 프로그램 레지스트리를 승인 목록 기준으로 정비하십시오.'),
  meta('SRV-106', 'hosts.lpd 신뢰 파일', CAT.access, '상', '/etc/hosts.lpd 존재/권한 확인', 'hosts.lpd 신뢰 파일 존재 또는 과다 권한', '파일 부재 또는 안전 권한', 'hosts.lpd 신뢰 파일을 제거하거나 권한을 제한하십시오.'),
  meta('SRV-107', 'at 접근 제어', CAT.access, '중', 'at.allow/at.deny 권한 확인', 'at 제어 파일 과다 권한 또는 부재', '허용 사용자 제한 및 안전 권한', 'at.allow/deny 파일을 생성하고 권한을 제한하십시오.'),
  meta('SRV-108', '로그 파일 권한', CAT.file, '중', '/var/log 파일 권한 확인', '로그 파일 group/other 쓰기 가능', '로그 파일 쓰기 권한 제한', '로그 파일 권한을 제한하십시오.'),
  meta('SRV-109', '감사 정책', CAT.log, '상', 'secedit 감사 정책 확인', '감사 정책 비활성 또는 불충분', '로그온/권한 사용 등 주요 감사 활성', 'Windows 감사 정책을 보안 기준에 맞게 활성화하십시오.'),
  meta('SRV-110', '시스템 config ACL', CAT.file, '상', 'system32/config ACL 확인', 'config 디렉터리 과다 권한', 'SYSTEM/Administrators 제한 권한', 'system32/config ACL을 기본 보안 권한으로 복구하십시오.'),
  meta('SRV-111', '이벤트 로그 Guest 제한', CAT.log, '중', 'Eventlog RestrictGuestAccess 확인', 'Guest 이벤트 로그 접근 허용', 'Guest 접근 제한 적용', '이벤트 로그 Guest 접근을 제한하십시오.'),
  meta('SRV-112', 'SRV-112 정의 필요', CAT.log, '중', '현재 샘플에 SRV-112 raw 출력이 없어 기준 확인 필요', '공식 기준 전에는 자동 취약 확정 안 함', '공식 기준 전에는 자동 양호 확정 안 함', 'SRV-112 공식 기준 또는 XML 샘플을 추가하십시오.', 'definition_needed'),
  meta('SRV-113', '감사 권한 할당', CAT.access, '상', 'SeSecurityPrivilege 권한 할당 확인', '감사 권한이 과도한 주체에 부여', '승인된 관리자만 보유', '감사/보안 로그 관리 권한을 최소화하십시오.'),
  meta('SRV-114', 'SRV-114 정의 필요', CAT.system, '중', '현재 샘플에 SRV-114 raw 출력이 없어 기준 확인 필요', '공식 기준 전에는 자동 취약 확정 안 함', '공식 기준 전에는 자동 양호 확정 안 함', 'SRV-114 공식 기준 또는 XML 샘플을 추가하십시오.', 'definition_needed'),
  meta('SRV-115', '로그 보존/권한', CAT.log, '중', '로그 파일 보존과 권한 확인', '로그 미보존 또는 과다 권한', '로그 보존 및 권한 제한', '로그 보존 정책과 권한을 적용하십시오.'),
  meta('SRV-116', '감사 실패 시 조치', CAT.log, '중', 'CrashOnAuditFail 설정 확인', '감사 로그 기록 실패 시 조치 미흡', '보안 기준에 맞는 조치 설정', 'CrashOnAuditFail 정책을 조직 기준에 맞게 설정하십시오.'),
  meta('SRV-117', 'OS 서비스팩 버전', CAT.patch, '중', 'OS service pack/version 확인', '지원 종료 또는 패치 미흡 버전', '지원되는 최신 패치 수준', 'OS 서비스팩과 누적 업데이트를 최신화하십시오.'),
  meta('SRV-118', 'Linux 패치 목록', CAT.patch, '중', '설치 패키지와 패치 수준 확인', '중요 보안 패치 누락', '최신 보안 패치 적용', '보안 패치 적용 상태를 정기 검증하십시오.'),
  meta('SRV-119', '수동 확인 항목', CAT.info, '하', '인터뷰/수동 확인 기반 항목', '수동 기준 미충족 시 취약', '수동 기준 충족 시 양호', '수동 점검 증적을 확보하십시오.'),
  meta('SRV-120', 'Windows Hotfix', CAT.patch, '중', 'wmic qfe hotfix 목록 확인', '중요 보안 업데이트 누락', '최신 보안 업데이트 적용', 'Windows 보안 업데이트를 최신 상태로 유지하십시오.'),
  meta('SRV-121', 'PATH 환경 변수', CAT.system, '상', 'PATH에 . 또는 world-writable 경로 포함 여부 확인', '상대 경로/쓰기 가능 경로가 PATH에 포함', '신뢰 경로만 PATH에 포함', 'PATH에서 . 및 쓰기 가능 경로를 제거하십시오.'),
  meta('SRV-122', '기본 umask', CAT.system, '중', 'umask 기본값 확인', 'umask 000/002 등 과도하게 허용', 'umask 022/027/077 등 제한 적용', '기본 umask를 보안 기준에 맞게 설정하십시오.'),
  meta('SRV-123', '마지막 사용자 표시', CAT.access, '중', 'DontDisplayLastUserName 확인', '마지막 로그온 사용자 표시', '마지막 사용자명 숨김', '마지막 로그온 사용자 표시를 비활성화하십시오.'),
  meta('SRV-124', '캐시 로그온 수', CAT.access, '중', 'cachedlogonscount 확인', '캐시 로그온 수 과다', '캐시 로그온 수 4 이하 또는 0', '캐시 로그온 수를 최소화하십시오.'),
  meta('SRV-125', '화면 보호기 잠금', CAT.access, '중', 'ScreenSaveActive/TimeOut/Secure 확인', '화면 보호기 잠금 비활성 또는 타임아웃 과다', '잠금 활성 및 기준 이하 타임아웃', '화면 보호기 잠금과 타임아웃을 설정하십시오.'),
  meta('SRV-126', '자동 로그온 제한', CAT.password, '상', 'AutoAdminLogon/DefaultPassword 확인', '자동 로그온 또는 저장 암호 존재', '자동 로그온 비활성 및 저장 암호 없음', 'AutoAdminLogon과 저장 암호를 제거하십시오.'),
  meta('SRV-127', '계정 잠금 정책', CAT.password, '상', 'FAILLOG/RemoteAccess/net accounts 잠금 정책 확인', '잠금 임계값 미설정 또는 실패 로그 미사용', '잠금 임계값과 실패 로그 적용', '계정 잠금 정책을 활성화하십시오.'),
  meta('SRV-128', '파일시스템 형식', CAT.file, '상', 'Windows logicaldisk filesystem 확인', 'FAT/FAT32 등 ACL 미지원 파일시스템 사용', 'NTFS 사용', '보안 ACL을 지원하는 NTFS를 사용하십시오.'),
  meta('SRV-129', '프로세스 점검', CAT.system, '중', '실행 중인 프로세스 목록 확인', '불필요/위험 프로세스 실행', '승인된 프로세스만 실행', '실행 프로세스를 승인 목록 기준으로 점검하십시오.'),
  meta('SRV-130', 'profile umask', CAT.system, '중', '/etc/profile 및 csh.cshrc umask 확인', '기본 umask 과다 허용', '제한적인 umask 적용', 'profile의 umask를 보안 기준으로 설정하십시오.'),
  meta('SRV-131', 'su 명령 제한', CAT.access, '상', 'su 파일 권한과 PAM wheel 설정 확인', 'su 사용자가 제한되지 않음', 'wheel 등 허용 그룹 제한 적용', 'su 사용을 wheel 등 승인 그룹으로 제한하십시오.'),
  meta('SRV-132', 'cron allow/deny 파일', CAT.access, '중', 'cron.allow/cron.deny 존재와 권한 확인', 'cron 사용 제어 미흡 또는 과다 권한', '허용 사용자 제한 및 안전 권한', 'cron allow/deny 파일을 관리하고 권한을 제한하십시오.'),
  meta('SRV-133', 'cron 허용 사용자', CAT.access, '중', 'cron.allow/cron.deny 내용 확인', '불필요한 사용자에게 cron 허용', '필요 사용자만 허용', 'cron 사용 가능 계정을 최소화하십시오.'),
  meta('SRV-134', 'SRV-134 정의 필요', CAT.system, '중', '현재 샘플에 SRV-134 raw 출력이 없어 기준 확인 필요', '공식 기준 전에는 자동 취약 확정 안 함', '공식 기준 전에는 자동 양호 확정 안 함', 'SRV-134 공식 기준 또는 XML 샘플을 추가하십시오.', 'definition_needed'),
  meta('SRV-135', 'SRV-135 정의 필요', CAT.system, '중', '현재 샘플에 SRV-135 raw 출력이 없어 기준 확인 필요', '공식 기준 전에는 자동 취약 확정 안 함', '공식 기준 전에는 자동 양호 확정 안 함', 'SRV-135 공식 기준 또는 XML 샘플을 추가하십시오.', 'definition_needed'),
  meta('SRV-136', '로그온 전 종료 제한', CAT.access, '중', 'ShutdownWithoutLogon 확인', '로그온 전 시스템 종료 허용', '로그온 전 종료 차단', 'ShutdownWithoutLogon을 비활성화하십시오.'),
  meta('SRV-137', '네트워크 로그온 권한', CAT.access, '상', 'SeNetworkLogonRight/Deny 권한 확인', 'Everyone/Guests 등 과도한 네트워크 로그온 허용', '허용 그룹 최소화 및 거부 정책 적용', '네트워크 로그온 권한을 최소화하십시오.'),
  meta('SRV-138', '백업/복원 권한', CAT.access, '상', 'SeBackupPrivilege/SeRestorePrivilege 확인', '백업/복원 권한 과다 부여', '승인된 관리자/백업 계정만 보유', '백업/복원 권한을 최소화하십시오.'),
  meta('SRV-139', '소유권 가져오기 권한', CAT.access, '상', 'SeTakeOwnershipPrivilege 확인', '소유권 권한 과다 부여', '승인된 관리자만 보유', '소유권 가져오기 권한을 최소화하십시오.'),
  meta('SRV-140', '이동식 미디어 권한', CAT.access, '중', 'AllocateDASD 설정 확인', '이동식 미디어 포맷/꺼내기 권한 과다', '관리자 제한', 'AllocateDASD 정책을 관리자 기준으로 제한하십시오.'),
  meta('SRV-141', 'Windows 방화벽', CAT.network, '상', 'EnableFirewall 확인', '방화벽 비활성화', '방화벽 활성화', 'Windows 방화벽을 활성화하십시오.'),
  meta('SRV-142', 'UID 0 계정', CAT.account, '상', '/etc/passwd UID 0 계정 확인', 'root 외 UID 0 계정 존재', 'root만 UID 0 보유', 'root 외 UID 0 계정을 제거하거나 UID를 변경하십시오.'),
  meta('SRV-143', '중복 UID', CAT.account, '상', '/etc/passwd UID 중복 확인', '동일 UID를 여러 계정이 사용', 'UID 고유성 유지', '중복 UID를 제거하고 계정 식별성을 보장하십시오.'),
  meta('SRV-144', '장치 파일 이상', CAT.file, '중', '/dev 일반 파일 존재 확인', '/dev 아래 일반 파일 존재', '정상 장치 파일만 존재', '/dev 아래 비정상 일반 파일을 제거하십시오.'),
  meta('SRV-145', '시스템 계정 쉘', CAT.account, '중', '시스템 계정 로그인 쉘 확인', 'daemon/bin 등 시스템 계정에 로그인 쉘 부여', 'nologin/false 쉘 적용', '시스템 계정 로그인 쉘을 제한하십시오.'),
  meta('SRV-146', 'ftp 계정 쉘', CAT.account, '상', 'ftp 계정 로그인 쉘 확인', 'ftp 계정에 로그인 가능한 쉘 부여', 'false/nologin 쉘 적용', 'ftp 계정의 로그인 쉘을 차단하십시오.'),
  meta('SRV-147', '홈 디렉터리 권한', CAT.file, '중', '사용자 홈 디렉터리 권한 확인', '홈 디렉터리 과다 권한', '소유자 중심 제한 권한', '사용자 홈 디렉터리 권한을 제한하십시오.'),
  meta('SRV-148', '중요 파일 접근성', CAT.file, '중', '중요 설정 파일 접근 가능성과 권한 확인', '중요 파일 접근/권한 이상', '정상 접근과 권한', '중요 파일 접근 오류와 권한을 점검하십시오.'),
  meta('SRV-149', 'SRV-149 정의 필요', CAT.system, '중', '현재 샘플에 SRV-149 raw 출력이 없어 기준 확인 필요', '공식 기준 전에는 자동 취약 확정 안 함', '공식 기준 전에는 자동 양호 확정 안 함', 'SRV-149 공식 기준 또는 XML 샘플을 추가하십시오.', 'definition_needed'),
  meta('SRV-150', '로컬 로그온 권한', CAT.access, '상', 'SeInteractiveLogonRight 확인', '로컬 로그온 권한 과다 부여', '승인된 사용자/관리자만 보유', '로컬 로그온 권한을 최소화하십시오.'),
  meta('SRV-151', 'SRV-151 정의 필요', CAT.access, '중', '현재 샘플에 SRV-151 raw 출력이 없어 기준 확인 필요', '공식 기준 전에는 자동 취약 확정 안 함', '공식 기준 전에는 자동 양호 확정 안 함', 'SRV-151 공식 기준 또는 XML 샘플을 추가하십시오.', 'definition_needed'),
  meta('SRV-152', 'RDP 로그온 권한', CAT.access, '상', 'SeRemoteInteractiveLogonRight 확인', '원격 대화형 로그온 권한 과다 부여', '승인된 원격 사용자만 보유', 'RDP 로그온 권한을 최소화하십시오.'),
  meta('SRV-153', 'SRV-153 정의 필요', CAT.access, '중', '현재 샘플에 SRV-153 raw 출력이 없어 기준 확인 필요', '공식 기준 전에는 자동 취약 확정 안 함', '공식 기준 전에는 자동 양호 확정 안 함', 'SRV-153 공식 기준 또는 XML 샘플을 추가하십시오.', 'definition_needed'),
  meta('SRV-154', 'SRV-154 정의 필요', CAT.system, '중', '현재 샘플에 SRV-154 raw 출력이 없어 기준 확인 필요', '공식 기준 전에는 자동 취약 확정 안 함', '공식 기준 전에는 자동 양호 확정 안 함', 'SRV-154 공식 기준 또는 XML 샘플을 추가하십시오.', 'definition_needed'),
  meta('SRV-155', 'SRV-155 정의 필요', CAT.system, '중', '현재 샘플에 SRV-155 raw 출력이 없어 기준 확인 필요', '공식 기준 전에는 자동 취약 확정 안 함', '공식 기준 전에는 자동 양호 확정 안 함', 'SRV-155 공식 기준 또는 XML 샘플을 추가하십시오.', 'definition_needed'),
  meta('SRV-156', '세션 자동 연결 해제', CAT.access, '중', 'LanmanServer autodisconnect 확인', '자동 연결 해제 미설정 또는 비활성', '기준 시간 내 자동 연결 해제', 'autodisconnect를 보안 기준에 맞게 설정하십시오.'),
  meta('SRV-157', 'SRV-157 정의 필요', CAT.system, '중', '현재 샘플에 SRV-157 raw 출력이 없어 기준 확인 필요', '공식 기준 전에는 자동 취약 확정 안 함', '공식 기준 전에는 자동 양호 확정 안 함', 'SRV-157 공식 기준 또는 XML 샘플을 추가하십시오.', 'definition_needed'),
  meta('SRV-158', 'Telnet 포트 확인', CAT.network, '상', '23/tcp LISTEN 또는 TlntSvr 실행 여부 확인', 'Telnet 서비스/포트 활성화', 'Telnet 비활성화', 'Telnet 서비스를 중지하십시오.'),
  meta('SRV-159', 'SSH 세션 타임아웃', CAT.access, '중', 'TMOUT/TIMEOUT 및 SSH 세션 제한 확인', '타임아웃 0 또는 미설정', '유휴 세션 타임아웃 적용', '쉘/SSH 유휴 세션 타임아웃을 설정하십시오.'),
  meta('SRV-160', '장기 미사용 계정', CAT.account, '중', '사용자 쉘과 최근 로그인 확인', '장기 미사용 또는 불필요 로그인 가능 계정 존재', '필요 계정만 로그인 가능', '미사용 계정을 잠그고 로그인 쉘을 제한하십시오.'),
  meta('SRV-161', 'FTP 서비스 점검', CAT.network, '상', 'FTP 서비스와 21/tcp LISTEN 여부 확인', 'FTP 서비스 실행', 'FTP 미사용 또는 제한 운영', 'FTP 서비스를 중지하거나 보안 프로토콜로 대체하십시오.'),
  meta('SRV-162', 'PAM su rootok', CAT.access, '상', 'PAM su rootok/wheel 설정 확인', 'su 인증 우회 또는 제한 미흡', 'su 사용 제한 적용', 'PAM su 정책을 검토하고 wheel 제한을 적용하십시오.'),
  meta('SRV-163', '로그온 배너', CAT.access, '하', 'motd/issue 또는 LegalNoticeCaption/Text 확인', '로그온 경고 배너 미설정', '경고 배너 설정', '시스템 접속 경고 배너를 설정하십시오.'),
  meta('SRV-164', '중복 GID', CAT.account, '중', '/etc/group GID 중복 확인', '동일 GID를 여러 그룹이 부적절하게 공유', 'GID 고유성 유지', '중복 GID를 검토하고 정비하십시오.'),
  meta('SRV-165', '시스템 계정 관리', CAT.account, '중', 'daemon/bin/sys 등 시스템 계정 상태 확인', '시스템 계정 로그인 가능 또는 불필요 활성화', '시스템 계정 잠금/쉘 제한', '시스템 계정의 로그인과 권한을 제한하십시오.'),
  meta('SRV-166', 'SRV-166 정의 필요', CAT.system, '중', '현재 샘플에 SRV-166 raw 출력이 없어 기준 확인 필요', '공식 기준 전에는 자동 취약 확정 안 함', '공식 기준 전에는 자동 양호 확정 안 함', 'SRV-166 공식 기준 또는 XML 샘플을 추가하십시오.', 'definition_needed'),
  meta('SRV-167', 'FTP 추가 점검', CAT.network, '상', 'FTP 서비스/포트 추가 확인', 'FTP 서비스 실행 또는 익명 접속 허용', 'FTP 미사용 또는 안전 설정', 'FTP 서비스를 비활성화하거나 안전 설정을 적용하십시오.'),
  meta('SRV-168', 'syslog 원격 전송', CAT.log, '중', 'syslog/rsyslog 설정 확인', '로그 전송/기록 설정 미흡', '중요 로그 기록 및 전송 설정 적용', 'syslog/rsyslog 로그 기록과 원격 전송 기준을 적용하십시오.'),

  // ═════════════════════════════════════════════
  // WAS — Tomcat (금융보안원 WAS 취약점 기준) : SRV-200 ~ SRV-214
  //   설정파일(server.xml/tomcat-users.xml/web.xml 등) raw 증거 기반 판정.
  // ═════════════════════════════════════════════
  meta('SRV-200', 'Tomcat 관리자 콘솔 접근 통제', CAT.web, '상', 'manager/host-manager 앱 배포 여부와 RemoteAddrValve/RemoteCIDRValve 접근 제한 확인', 'manager/host-manager 앱이 배포되어 있으나 접근 IP 제한(RemoteAddrValve/RemoteCIDRValve)이 없음', '관리 앱 미배포 또는 Valve 로 접근 IP 제한 적용', '불필요하면 manager/host-manager 앱을 제거하고, 필요 시 RemoteAddrValve 로 허용 IP를 제한하십시오.', 'fsi_was_tomcat'),
  meta('SRV-201', 'Tomcat 기본·관리 계정 통제', CAT.account, '상', 'tomcat-users.xml 의 기본/추측가능 계정 및 관리 role(manager-gui/admin-gui/manager-script) 부여 확인', '기본/추측가능 계정 또는 관리 role 이 정의됨', '관리 계정 미정의 또는 최소 권한만 부여', '기본 계정을 제거하고 관리 role 부여를 최소화하십시오.', 'fsi_was_tomcat'),
  meta('SRV-202', 'Tomcat 계정 패스워드 평문 저장', CAT.password, '상', 'tomcat-users.xml password 평문 저장과 CredentialHandler/digest 적용 확인', '패스워드가 평문으로 저장되고 digest 자격증명 핸들러 미적용', 'CredentialHandler/MessageDigest 로 해시 저장 또는 계정 미정의', 'CredentialHandler(SHA-256 등)로 패스워드를 해시 저장하십시오.', 'fsi_was_tomcat'),
  meta('SRV-203', 'Tomcat 디렉터리 리스팅 제한', CAT.web, '중', 'conf/web.xml DefaultServlet 의 listings 파라미터 확인', 'listings=true 로 디렉터리 목록화가 허용됨', 'listings=false 또는 미설정(기본값 false)', 'DefaultServlet 의 listings 를 false 로 설정하십시오.', 'fsi_was_tomcat'),
  meta('SRV-204', 'Tomcat 세션 타임아웃', CAT.web, '중', 'conf/web.xml session-timeout(분) 확인', 'session-timeout 이 30 초과이거나 0/음수(무제한)', 'session-timeout 이 1~30 분 범위로 설정', '세션 타임아웃을 30분 이하로 설정하십시오.', 'fsi_was_tomcat'),
  meta('SRV-205', 'Tomcat 에러페이지 정보 노출', CAT.web, '중', 'ErrorReportValve(showServerInfo/showReport)와 web.xml error-page 확인', '기본 오류페이지가 서버정보/스택트레이스를 노출', 'showServerInfo=false·showReport=false 또는 커스텀 error-page 설정', 'ErrorReportValve 의 showServerInfo/showReport 를 false 로 설정하고 커스텀 오류페이지를 지정하십시오.', 'fsi_was_tomcat'),
  meta('SRV-206', 'Tomcat 서버 버전 정보 노출', CAT.web, '하', 'Connector server 속성과 ServerInfo.properties 오버라이드 확인', '기본 배너로 Tomcat 버전이 노출됨', 'Connector server 속성 설정 또는 ServerInfo 오버라이드로 버전 은닉', 'Connector 의 server 속성을 변경하거나 ServerInfo.properties 로 버전 노출을 제거하십시오.', 'fsi_was_tomcat'),
  meta('SRV-207', 'Tomcat 불필요 기본 웹앱 제거', CAT.web, '중', 'examples/docs/host-manager 등 기본 웹앱 존재 확인', '예제(examples)/문서(docs) 등 불필요 기본 웹앱이 존재', '불필요 기본 웹앱 제거', 'examples·docs 등 불필요한 기본 웹앱을 제거하십시오.', 'fsi_was_tomcat'),
  meta('SRV-208', 'Tomcat 불필요 HTTP 메서드(TRACE)', CAT.web, '중', 'Connector allowTrace 속성 확인', 'allowTrace=true 로 TRACE 메서드가 허용됨', 'allowTrace=false 또는 미설정(기본값 false)', 'Connector 의 allowTrace 를 false 로 설정하십시오.', 'fsi_was_tomcat'),
  meta('SRV-209', 'Tomcat AJP 커넥터 보안', CAT.network, '상', 'AJP(8009) Connector 존재와 secret/secretRequired/address 제한 확인 (Ghostcat CVE-2020-1938)', 'AJP Connector 가 secret 없이 활성화됨', 'AJP 미사용 또는 secret/secretRequired 및 주소 제한 적용', '불필요하면 AJP Connector 를 제거하고, 필요 시 secretRequired="true" 와 secret 을 설정하십시오.', 'fsi_was_tomcat'),
  meta('SRV-210', 'Tomcat SSL/TLS 적용', CAT.web, '상', 'HTTPS Connector 와 sslEnabledProtocols/sslProtocol 확인', 'SSLv2/SSLv3/TLSv1 등 취약 프로토콜이 허용됨', 'TLS 1.2 이상만 허용 또는 상위 프록시에서 TLS 종단', '취약한 SSL/TLS 프로토콜을 비활성화하고 TLS 1.2 이상만 허용하십시오.', 'fsi_was_tomcat'),
  meta('SRV-211', 'Tomcat 접근 로그 설정', CAT.log, '중', 'server.xml AccessLogValve 설정 확인', 'AccessLogValve 미설정으로 접근 로그가 기록되지 않음', 'AccessLogValve 로 접근 로그 기록', 'AccessLogValve 를 설정해 접근 로그를 기록하십시오.', 'fsi_was_tomcat'),
  meta('SRV-212', 'Tomcat 설정 파일 접근 권한', CAT.file, '상', 'server.xml/tomcat-users.xml/catalina.properties 소유자·권한 확인', '설정 파일이 group/other 에 읽기/쓰기 가능(특히 tomcat-users.xml)', 'tomcat 계정 소유 및 최소 권한(600/640)', 'Tomcat 설정 파일 권한을 소유자 최소 권한(600/640)으로 제한하십시오.', 'fsi_was_tomcat'),
  meta('SRV-213', 'Tomcat shutdown 포트/명령 변경', CAT.system, '중', 'server.xml <Server port shutdown> 기본값 사용 여부 확인', 'shutdown 명령이 기본값(SHUTDOWN)이거나 8005 포트가 활성', 'shutdown 포트 -1(비활성) 또는 명령/포트 변경', 'shutdown 포트를 -1 로 비활성화하거나 명령·포트를 변경하십시오.', 'fsi_was_tomcat'),
  meta('SRV-214', 'Tomcat 실행 계정 권한 최소화', CAT.account, '상', 'java/catalina 프로세스 소유자 확인(root 구동 금지)', 'Tomcat 프로세스가 root 권한으로 실행됨', '전용 비특권 계정(tomcat 등)으로 실행', 'Tomcat 을 전용 비특권 계정으로 실행하십시오.', 'fsi_was_tomcat'),

  // ═════════════════════════════════════════════
  // DBMS — MSSQL (금융보안원 DBMS 취약점 기준) : SRV-230 ~ SRV-247
  //   sqlcmd/SqlClient raw 출력(col=val) 기반 결정론적 판정.
  // ═════════════════════════════════════════════
  meta('SRV-230', 'MSSQL sa 계정명 변경', CAT.account, '상', 'sid=0x01 principal 이름이 sa 인지 확인', 'sa 계정명이 변경되지 않음(name=sa)', 'sa 계정명이 변경됨', 'sa 계정명을 유추하기 어려운 이름으로 변경하십시오.', 'fsi_dbms_mssql'),
  meta('SRV-231', 'MSSQL sa 계정 비활성화', CAT.account, '상', 'sa 계정 is_disabled 확인', 'sa 계정이 활성 상태(is_disabled=False)', 'sa 계정 비활성화', '사용하지 않는다면 sa 계정을 비활성화하십시오(ALTER LOGIN sa DISABLE).', 'fsi_dbms_mssql'),
  meta('SRV-232', 'MSSQL 로그인 패스워드 정책', CAT.password, '상', 'SQL 로그인 is_policy_checked/is_expiration_checked 확인', '활성 SQL 로그인에 패스워드 정책(is_policy_checked)이 미적용', '모든 활성 로그인에 패스워드 정책 적용', 'CHECK_POLICY/CHECK_EXPIRATION 을 활성화하십시오.', 'fsi_dbms_mssql'),
  meta('SRV-233', 'MSSQL 인증 모드', CAT.access, '상', 'IsIntegratedSecurityOnly(1=Windows전용,0=혼합) 확인', '혼합 인증 모드(SQL 인증 허용)', 'Windows 인증 전용', '가능하면 Windows 인증 전용으로 전환하고, 혼합모드 시 sa 를 강화하십시오.', 'fsi_dbms_mssql'),
  meta('SRV-234', 'MSSQL sysadmin 역할 최소화', CAT.account, '상', 'sysadmin 서버 역할 구성원 확인', '광범위 주체(guest/public/BUILTIN\\Users 등)가 sysadmin 에 포함', '승인된 관리자만 sysadmin 보유', 'sysadmin 구성원을 승인된 관리자로 최소화하십시오.', 'fsi_dbms_mssql'),
  meta('SRV-235', 'MSSQL guest 계정 권한', CAT.access, '상', '각 DB 의 guest CONNECT 권한 확인', 'guest 계정에 CONNECT 권한이 부여된 DB 존재', 'guest CONNECT 권한 제거', '불필요한 DB 의 guest CONNECT 권한을 취소(REVOKE CONNECT)하십시오.', 'fsi_dbms_mssql'),
  meta('SRV-236', 'MSSQL public 역할 권한', CAT.access, '상', 'public 서버 역할 부여 권한 확인', 'public 에 위험 권한(CONTROL SERVER/ALTER ANY/IMPERSONATE 등)이 부여됨', 'public 에 위험 권한 미부여', 'public 역할에 부여된 과도한 서버 권한을 회수하십시오.', 'fsi_dbms_mssql'),
  meta('SRV-237', 'MSSQL xp_cmdshell 비활성', CAT.system, '상', "sys.configurations 'xp_cmdshell' value_in_use 확인", 'xp_cmdshell 이 활성화됨(value_in_use=1)', 'xp_cmdshell 비활성(0)', "sp_configure 'xp_cmdshell',0 으로 비활성화하십시오.", 'fsi_dbms_mssql'),
  meta('SRV-238', 'MSSQL OLE Automation 비활성', CAT.system, '중', "'Ole Automation Procedures' value_in_use 확인", 'OLE Automation Procedures 가 활성화됨', '비활성(0)', "sp_configure 'Ole Automation Procedures',0 으로 비활성화하십시오.", 'fsi_dbms_mssql'),
  meta('SRV-239', 'MSSQL Ad Hoc Distributed Queries 비활성', CAT.system, '중', "'Ad Hoc Distributed Queries' value_in_use 확인", 'Ad Hoc Distributed Queries 가 활성화됨', '비활성(0)', "sp_configure 'Ad Hoc Distributed Queries',0 으로 비활성화하십시오.", 'fsi_dbms_mssql'),
  meta('SRV-240', 'MSSQL CLR 비활성', CAT.system, '중', "'clr enabled' value_in_use 확인", 'CLR 이 활성화됨', '비활성(0)', "필요 없으면 sp_configure 'clr enabled',0 으로 비활성화하십시오.", 'fsi_dbms_mssql'),
  meta('SRV-241', 'MSSQL Cross DB Ownership Chaining 비활성', CAT.access, '중', "'cross db ownership chaining' value_in_use 확인", 'Cross DB Ownership Chaining 이 활성화됨', '비활성(0)', "sp_configure 'cross db ownership chaining',0 으로 비활성화하십시오.", 'fsi_dbms_mssql'),
  meta('SRV-242', 'MSSQL Remote Admin Connections 제한', CAT.access, '중', "'remote admin connections' value_in_use 확인", '원격 DAC(remote admin connections)가 활성화됨', '비활성(0, 로컬 DAC만)', '원격 관리 연결이 불필요하면 비활성화하십시오.', 'fsi_dbms_mssql'),
  meta('SRV-243', 'MSSQL remote access 제한', CAT.network, '중', "'remote access' value_in_use 확인", '원격 저장 프로시저 실행(remote access)이 허용됨', '비활성(0)', "sp_configure 'remote access',0 으로 제한하십시오.", 'fsi_dbms_mssql'),
  meta('SRV-244', 'MSSQL 로그인 감사 수준', CAT.log, '상', '로그인 감사 AuditLevel(0/1/2/3) 확인', '로그인 실패 감사 미설정(AuditLevel 0 또는 1)', '실패 이상 감사(2=실패, 3=모두)', '로그인 감사를 최소 "실패한 로그인" 이상으로 설정하십시오.', 'fsi_dbms_mssql'),
  meta('SRV-245', 'MSSQL 감사(Audit) 설정', CAT.log, '중', 'c2 audit mode 및 SQL Server Audit 활성 확인', 'C2 감사 비활성이며 활성화된 SQL Server Audit 도 없음', 'C2 감사 또는 SQL Server Audit 활성', 'SQL Server Audit 를 구성해 보안 이벤트를 기록하십시오.', 'fsi_dbms_mssql'),
  meta('SRV-246', 'MSSQL 버전/패치(EoS)', CAT.patch, '중', 'ProductVersion/ProductLevel 로 지원 종료 여부 확인', '지원 종료(EoS) 버전(SQL Server 2014 이하) 사용', '벤더 지원 유효 버전 + 최신 CU 적용', '지원 종료 버전을 업그레이드하고 최신 누적 업데이트를 적용하십시오.', 'fsi_dbms_mssql'),
  meta('SRV-247', 'MSSQL 데이터 암호화(TDE)', CAT.file, '중', 'sys.databases is_encrypted(TDE) 확인', '민감정보 저장 DB 에 TDE 미적용', 'TDE 적용 또는 해당없음', '민감정보 저장 시 TDE(투명한 데이터 암호화) 적용을 검토하십시오.', 'fsi_dbms_mssql'),

  // ═════════════════════════════════════════════
  // [미검증 템플릿] WAS — JEUS : SRV-215 ~ SRV-224  (실서버 raw 대조 전, 표준 기준 기반)
  // ═════════════════════════════════════════════
  meta('SRV-215', 'JEUS 관리자 콘솔 접근 통제', CAT.web, '상', 'webadmin 콘솔 접근 IP 제한 확인', '관리 콘솔 접근 IP 제한 없음', '허용 IP 제한 적용', 'JEUS 관리 콘솔 접근을 허용 IP로 제한하십시오.', 'template_unverified'),
  meta('SRV-216', 'JEUS 기본·관리 계정 통제', CAT.account, '상', 'accounts.xml 기본/추측가능 관리 계정 확인', '기본 관리 계정(administrator 등) 사용', '계정명 변경 및 최소 권한', '기본 관리 계정을 변경하고 권한을 최소화하십시오.', 'template_unverified'),
  meta('SRV-217', 'JEUS 계정 패스워드 암호화', CAT.password, '상', 'accounts.xml 패스워드 암호화 저장 확인', '패스워드 평문/약한 인코딩 저장', '암호화 저장', '계정 패스워드를 암호화 저장하십시오.', 'template_unverified'),
  meta('SRV-218', 'JEUS 디렉터리 리스팅 제한', CAT.web, '중', 'web.xml/webcommon dir-listing 확인', '디렉터리 리스팅 허용', '디렉터리 리스팅 비활성', '디렉터리 리스팅을 비활성화하십시오.', 'template_unverified'),
  meta('SRV-219', 'JEUS 세션 타임아웃', CAT.web, '중', 'session-timeout 확인', '세션 타임아웃 과도/미설정', '30분 이하 설정', '세션 타임아웃을 30분 이하로 설정하십시오.', 'template_unverified'),
  meta('SRV-220', 'JEUS 에러페이지 정보 노출', CAT.web, '중', 'error-page 및 스택 노출 확인', '기본 오류페이지로 정보 노출', '커스텀 오류페이지 설정', '커스텀 오류페이지를 설정하십시오.', 'template_unverified'),
  meta('SRV-221', 'JEUS 서버 정보 노출', CAT.web, '하', 'server-header/버전 노출 확인', '서버/버전 정보 노출', '서버 헤더 노출 제한', '서버/버전 헤더 노출을 제거하십시오.', 'template_unverified'),
  meta('SRV-222', 'JEUS 불필요 샘플 앱 제거', CAT.web, '중', '예제/샘플 애플리케이션 존재 확인', '샘플 앱 존재', '샘플 앱 제거', '불필요한 샘플 애플리케이션을 제거하십시오.', 'template_unverified'),
  meta('SRV-223', 'JEUS 로그 설정', CAT.log, '중', '접근/에러 로그 설정 확인', '접근 로그 미기록', '접근/에러 로그 기록', '접근 로그를 기록하도록 설정하십시오.', 'template_unverified'),
  meta('SRV-224', 'JEUS 설정 파일 접근 권한', CAT.file, '상', '설정 파일 소유자·권한 확인', '설정 파일이 group/other 접근 가능', '전용 계정 최소 권한', 'JEUS 설정 파일 권한을 최소화하십시오.', 'template_unverified'),

  // ═════════════════════════════════════════════
  // [미검증 템플릿] DBMS — Oracle : SRV-250 ~ SRV-262
  // ═════════════════════════════════════════════
  meta('SRV-250', 'Oracle 기본계정 잠금/패스워드', CAT.account, '상', 'dba_users 기본계정(SYS/SYSTEM/DBSNMP/OUTLN/SCOTT 등) OPEN 및 기본 패스워드 확인', '기본계정이 OPEN 이거나 기본 패스워드 사용', '불필요 기본계정 LOCK/EXPIRED', '불필요한 기본계정을 잠그고 패스워드를 변경하십시오.', 'template_unverified'),
  meta('SRV-251', 'Oracle 패스워드 복잡도 함수', CAT.password, '상', 'dba_profiles PASSWORD_VERIFY_FUNCTION 확인', '복잡도 검증 함수 미적용(NULL)', '복잡도 검증 함수 적용', '패스워드 복잡도 검증 함수를 프로파일에 적용하십시오.', 'template_unverified'),
  meta('SRV-252', 'Oracle 패스워드 만료/재사용', CAT.password, '상', 'PASSWORD_LIFE_TIME / PASSWORD_REUSE_MAX 확인', '만료 무제한(UNLIMITED) 또는 재사용 제한 없음', '만료 기간·재사용 제한 설정', '패스워드 만료 기간과 재사용 제한을 설정하십시오.', 'template_unverified'),
  meta('SRV-253', 'Oracle 계정 잠금 임계값', CAT.password, '상', 'FAILED_LOGIN_ATTEMPTS 확인', '실패 잠금 임계값 UNLIMITED', '임계값 제한(예: 10)', '로그인 실패 잠금 임계값을 설정하십시오.', 'template_unverified'),
  meta('SRV-254', 'Oracle DBA 권한 최소화', CAT.access, '상', 'dba_role_privs DBA 부여 계정 확인', '불필요 계정에 DBA 롤 부여', '승인된 관리자만 DBA', 'DBA 롤 부여를 최소화하십시오.', 'template_unverified'),
  meta('SRV-255', 'Oracle PUBLIC 위험 패키지 권한', CAT.access, '상', 'UTL_FILE/UTL_TCP/UTL_SMTP/UTL_HTTP/DBMS_SQL 등 PUBLIC EXECUTE 확인', '위험 패키지가 PUBLIC 에 EXECUTE 부여', 'PUBLIC 실행 권한 회수', '위험 패키지의 PUBLIC 실행 권한을 회수하십시오.', 'template_unverified'),
  meta('SRV-256', 'Oracle remote_os_authent', CAT.access, '상', 'remote_os_authent 파라미터 확인', 'remote_os_authent=TRUE', 'FALSE', 'remote_os_authent 를 FALSE 로 설정하십시오.', 'template_unverified'),
  meta('SRV-257', 'Oracle 딕셔너리 접근 제한', CAT.access, '상', 'O7_DICTIONARY_ACCESSIBILITY 확인', 'O7_DICTIONARY_ACCESSIBILITY=TRUE', 'FALSE', 'O7_DICTIONARY_ACCESSIBILITY 를 FALSE 로 설정하십시오.', 'template_unverified'),
  meta('SRV-258', 'Oracle 감사 활성화', CAT.log, '상', 'AUDIT_TRAIL 파라미터 확인', 'AUDIT_TRAIL=NONE(감사 비활성)', '감사 활성(DB/OS/XML)', '감사(AUDIT_TRAIL)를 활성화하십시오.', 'template_unverified'),
  meta('SRV-259', 'Oracle 리스너 보안', CAT.network, '상', 'listener.ora 패스워드/암호화 및 외부 노출 확인', '리스너 패스워드 미설정 또는 외부 노출', '리스너 보호 설정', '리스너에 인증/접근 제어를 적용하십시오.', 'template_unverified'),
  meta('SRV-260', 'Oracle utl_file_dir 제한', CAT.access, '중', 'utl_file_dir 파라미터 확인', "utl_file_dir='*' 등 광범위 허용", '디렉터리 제한 또는 미사용', 'utl_file_dir 대신 디렉터리 객체로 제한하십시오.', 'template_unverified'),
  meta('SRV-261', 'Oracle 최신 패치(버전/PSU)', CAT.patch, '중', 'v$version / 패치 수준 확인', '지원 종료/미패치 버전', '지원 유효 + 최신 PSU/RU', '최신 보안 패치(PSU/RU)를 적용하십시오.', 'template_unverified'),
  meta('SRV-262', 'Oracle 로그인 시도 감사', CAT.log, '중', 'AUDIT SESSION / 로그인 감사 확인', '로그인 감사 미설정', '로그인 감사 활성', '로그인/세션 감사를 설정하십시오.', 'template_unverified'),

  // ═════════════════════════════════════════════
  // [미검증 템플릿] DBMS — MySQL/MariaDB : SRV-270 ~ SRV-281
  // ═════════════════════════════════════════════
  meta('SRV-270', 'MySQL 익명 계정 제거', CAT.account, '상', "mysql.user 익명 계정(User='') 확인", '익명 계정 존재', '익명 계정 제거', "익명 계정(User='')을 제거하십시오.", 'template_unverified'),
  meta('SRV-271', 'MySQL root 원격 접속 제한', CAT.access, '상', "root 계정 host 확인('%' 여부)", "root 가 host='%' 로 원격 허용", 'root 는 localhost 로 제한', 'root 원격 접속을 localhost 로 제한하십시오.', 'template_unverified'),
  meta('SRV-272', 'MySQL 빈 패스워드 계정', CAT.password, '상', 'authentication_string 빈 값 확인', '빈 패스워드 계정 존재', '모든 계정 패스워드 설정', '빈 패스워드 계정에 패스워드를 설정하십시오.', 'template_unverified'),
  meta('SRV-273', 'MySQL 패스워드 정책', CAT.password, '상', 'validate_password 플러그인/정책 확인', '패스워드 검증 플러그인 미적용', 'validate_password 적용', 'validate_password 플러그인으로 정책을 적용하십시오.', 'template_unverified'),
  meta('SRV-274', 'MySQL test DB 제거', CAT.access, '중', 'test 스키마 존재 확인', 'test 데이터베이스 존재', 'test DB 제거', '기본 test 데이터베이스를 제거하십시오.', 'template_unverified'),
  meta('SRV-275', 'MySQL FILE 권한/secure_file_priv', CAT.access, '상', 'FILE 권한 PUBLIC 부여 및 secure_file_priv 확인', 'FILE 권한 광범위 부여 또는 secure_file_priv 미설정', 'FILE 권한 최소화 및 secure_file_priv 설정', 'FILE 권한을 최소화하고 secure_file_priv 를 지정하십시오.', 'template_unverified'),
  meta('SRV-276', 'MySQL local_infile 제한', CAT.access, '중', 'local_infile 변수 확인', 'local_infile=ON', 'local_infile=OFF', 'local_infile 을 OFF 로 설정하십시오.', 'template_unverified'),
  meta('SRV-277', 'MySQL 감사 로그', CAT.log, '중', 'general_log / audit 플러그인 확인', '감사/일반 로그 미설정', '감사 로그 활성', '감사 로그(audit plugin 등)를 설정하십시오.', 'template_unverified'),
  meta('SRV-278', 'MySQL 전송 암호화(SSL/TLS)', CAT.network, '상', 'require_secure_transport / SSL 확인', '평문 접속 허용', 'TLS 강제', 'require_secure_transport 로 TLS 를 강제하십시오.', 'template_unverified'),
  meta('SRV-279', 'MySQL 관리자 권한 최소화', CAT.access, '상', 'GRANT ALL / WITH GRANT OPTION 부여 계정 확인', '불필요 계정에 광범위 권한', '최소 권한 원칙 적용', '계정 권한을 최소 권한으로 조정하십시오.', 'template_unverified'),
  meta('SRV-280', 'MySQL 최신 버전', CAT.patch, '중', 'version() 확인', '지원 종료/취약 버전', '지원 유효 버전', '지원 종료 버전을 업그레이드하십시오.', 'template_unverified'),
  meta('SRV-281', 'MySQL skip_grant_tables 미사용', CAT.access, '상', 'skip_grant_tables 확인', 'skip_grant_tables 활성(권한 우회)', '비활성', 'skip_grant_tables 를 비활성화하십시오.', 'template_unverified'),
];

const SRV_META = {
  ...buildDefaultMeta(),
  ...Object.fromEntries(SRV_META_ROWS.map(row => [row.id, row])),
};

const SNMP_COMMUNITY_RULES = {
  vuln: [
    { pattern: /\b(?:community|ValidCommunities)\b[\s\S]{0,120}\b(?:public|private)\b/i, reason: 'SNMP 기본 community(public/private)가 확인됨' },
    { pattern: /\b(?:READ_WRITE|ReadWrite|rwcommunity)\b/i, reason: 'SNMP 쓰기 권한 community가 확인됨' },
    // SRV-001 힌트 이식: SNMP 미설치여도 부재양호로 끝내지 않는다.
    // 이 항목은 WMI/DCOM/LAN Manager 인증 수준을 함께 본다 — 키 부재 = 강화 미적용 = 취약.
    dwordMissingOrLess('LmCompatibilityLevel', 5, 'NTLMv2 응답만 보내기(5) 미강제'),
    dwordMissingOrLess('LegacyAuthenticationLevel', 2, 'DCOM 인증 수준이 Packet Privacy(2) 미만'),
  ],
  safe: [],
};

const SMTP_EXPOSURE_RULES = {
  vuln: [
    { pattern: text => hasListeningPort(text, ['25']) ? 'SMTP 25/tcp가 외부 인터페이스에서 LISTEN 중' : null },
  ],
  safe: [
    { pattern: text => hasLoopbackOnlyPort(text, ['25']) ? 'SMTP 25/tcp가 loopback 주소에만 바인딩됨' : null },
  ],
};

const SENDMAIL_PRIVACY_RULES = {
  vuln: [
    { pattern: text => activeLineMatches(text, /^O?\s*PrivacyOptions=.*\b(vrfy|expn)\b/i) ? 'sendmail PrivacyOptions에 VRFY/EXPN 제한이 불명확함' : null },
  ],
  safe: [
    { pattern: /PrivacyOptions[^\n]*(?:noexpn|goaway)[^\n]*(?:novrfy|goaway)/i, reason: 'sendmail PrivacyOptions에 noexpn/novrfy 제한 적용' },
    // postfix: disable_vrfy_command = yes 명시 시 양호
    { pattern: /^\s*disable_vrfy_command\s*=\s*yes/im, reason: 'postfix disable_vrfy_command=yes — VRFY 명령 제한 적용' },
    // 주의: loopback 바인딩만으로 양호 처리하지 않는다 (3-way 검증: SecuMS·LLM 모두
    // 설정(noexpn/disable_vrfy_command) 기준으로 판정 — SRV-005/010 disagree 원인이었음)
  ],
};

const FTP_RULES = {
  vuln: [
    { pattern: text => hasListeningPort(text, ['21']) ? 'FTP 21/tcp가 외부 인터페이스에서 LISTEN 중' : null },
    { pattern: text => hasListeningService(text, ['MSFTPSVC', 'FTPSVC', 'vsftpd', 'proftpd', 'ftp']) ? 'FTP 서비스 실행 신호가 확인됨' : null },
    { pattern: /anonymous_enable\s*=\s*YES/i, reason: 'FTP anonymous_enable=YES 설정 확인' },
  ],
  safe: [
    { pattern: text => hasLoopbackOnlyPort(text, ['21']) ? 'FTP 21/tcp가 loopback 주소에만 바인딩됨' : null },
    { pattern: /anonymous_enable\s*=\s*NO/i, reason: 'FTP anonymous_enable=NO 설정 확인' },
  ],
};

const TELNET_RULES = {
  vuln: [
    { pattern: text => hasListeningPort(text, ['23']) ? 'Telnet 23/tcp가 외부 인터페이스에서 LISTEN 중' : null },
    { pattern: text => hasListeningService(text, ['TlntSvr', 'telnet', 'in.telnetd']) ? 'Telnet 서비스 실행 신호가 확인됨' : null },
  ],
  safe: [
    { pattern: text => hasLoopbackOnlyPort(text, ['23']) ? 'Telnet 23/tcp가 loopback 주소에만 바인딩됨' : null },
  ],
};

const RCOMMAND_RULES = {
  vuln: [
    { pattern: text => hasListeningService(text, ['rsh', 'rlogin', 'rexec', 'shell', 'login', 'exec']) ? 'r-command 계열 서비스 실행 신호가 확인됨' : null },
    { pattern: /^\s*\+\s*$/m, reason: 'hosts.equiv 또는 rhosts 신뢰 파일에 전체 허용(+)이 확인됨' },
  ],
  safe: [],
};

const PASSWORD_POLICY_RULES = {
  vuln: [
    {
      pattern: text => activeLineMatches(text, /^PASS_MAX_DAYS\s+(?:99999|9[1-9]|[1-9][0-9]{2,})\b/i)
        ? 'PASS_MAX_DAYS가 90일을 초과하거나 만료 없음으로 설정됨'
        : null,
    },
    {
      pattern: text => activeLineMatches(text, /^PASS_MIN_LEN\s+[0-7]\b/i)
        ? 'PASS_MIN_LEN이 8 미만으로 설정됨'
        : null,
    },
    dwordLessThan('MinimumPasswordLength', 8, 'Windows 최소 암호 길이가 8 미만'),
    dwordEquals('PasswordComplexity', 0, 'Windows 암호 복잡도 정책이 비활성'),
    dwordEquals('LockoutBadCount', 0, '계정 잠금 임계값이 0으로 설정됨'),
  ],
  safe: [
    {
      pattern: text => {
        const maxOK = activeLineMatches(text, /^PASS_MAX_DAYS\s+([1-9]|[1-8][0-9]|90)\b/i);
        const lenOK = activeLineMatches(text, /^PASS_MIN_LEN\s+([8-9]|[1-9][0-9]+)\b/i);
        return maxOK && lenOK ? 'PASS_MAX_DAYS 90 이하, PASS_MIN_LEN 8 이상 확인' : null;
      },
    },
    dwordAtLeast('MinimumPasswordLength', 8, 'Windows 최소 암호 길이 8 이상'),
    dwordAtLeast('PasswordComplexity', 1, 'Windows 암호 복잡도 정책 활성'),
    dwordAtLeast('LockoutBadCount', 1, '계정 잠금 임계값 설정 확인'),
  ],
};

const UMASK_RULES = {
  vuln: [
    { pattern: /(?:^|\s)umask\s+(?:000|002)\b/im, reason: '기본 umask가 과도하게 허용적임' },
  ],
  safe: [
    { pattern: /(?:^|\s)umask\s+(?:022|027|077)\b/im, reason: '기본 umask가 제한적으로 설정됨' },
  ],
};

const FIREWALL_RULES = {
  vuln: [dwordEquals('EnableFirewall', 0, 'Windows 방화벽 EnableFirewall=0 확인')],
  safe: [dwordEquals('EnableFirewall', 1, 'Windows 방화벽 EnableFirewall=1 확인')],
};

const SRV_RULES = {
  // ── v2 수집기 출력 대응 신규 룰 (2026-07-02 2차) ──
  'SRV-073': {
    vuln: [],
    safe: [
      // Windows: net localgroup Administrators 구성원이 기본 Administrator 뿐
      { pattern: text => {
        const s = String(text || '');
        if (!/Administrators/i.test(s)) return null;
        const seg = s.split(/구성원|Members/)[1];
        if (!seg) return null;
        const names = seg.split(/명령을|The command completed/)[0].split('\n').map(l => l.trim())
          .filter(l => l && !/^-+$/.test(l) && !l.includes(' '));
        return names.length && names.every(n => /^Administrator$/i.test(n))
          ? 'Administrators 그룹 구성원이 기본 Administrator 뿐 — 관리자 권한 최소화 확인' : null;
      } },
      // Linux: root(GID0)/wheel 그룹에 추가 구성원 없음
      { pattern: text => {
        const rows = [...String(text || '').matchAll(/^(root|wheel):[^:]*:\d+:(\S*)$/gim)];
        return rows.length >= 2 && rows.every(r => !r[2] || r[2] === 'root')
          ? 'root/wheel 그룹에 추가 구성원 없음' : null;
      } },
    ],
  },
  'SRV-074': {
    // 활성 계정 비밀번호 장기(90일 초과) 미변경 — 스캔일(started_at_utc) 대비 비교(결정론)
    vuln: [{ pattern: text => {
      const s = String(text || '');
      const sc = s.match(/started_at_utc=(\d{4})-(\d{2})-(\d{2})/);
      if (!sc || !/PasswordLastSet/i.test(s)) return null;
      const scanDay = Date.UTC(+sc[1], +sc[2] - 1, +sc[3]) / 86400000;
      for (const m of s.matchAll(/^\s*(\S+)\s+True\s+\S+\s+(\d{4})-(\d{2})-(\d{2})/gim)) {
        const d = Date.UTC(+m[2], +m[3] - 1, +m[4]) / 86400000;
        if (scanDay - d > 90) return '활성 계정(' + m[1] + ') 비밀번호 ' + Math.floor(scanDay - d) + '일 미변경(90일 초과)';
      }
      return null;
    } }],
    safe: [{ pattern: text => {
      const s = String(text || '');
      const sc = s.match(/started_at_utc=(\d{4})-(\d{2})-(\d{2})/);
      if (!sc || !/PasswordLastSet/i.test(s)) return null;
      const scanDay = Date.UTC(+sc[1], +sc[2] - 1, +sc[3]) / 86400000;
      const rows = [...s.matchAll(/^\s*(\S+)\s+True\s+\S+\s+(\d{4})-(\d{2})-(\d{2})/gim)];
      return rows.length && rows.every(m => scanDay - Date.UTC(+m[2], +m[3] - 1, +m[4]) / 86400000 <= 90)
        ? '활성 계정 비밀번호 모두 90일 이내 변경' : null;
    } }],
  },
  'SRV-105': {
    vuln: [],
    safe: [{ pattern: text => /reg query[^\n]*Run/i.test(text) && /Not Found \/ No Data/i.test(text)
      ? 'Run 시작 프로그램 레지스트리 등록 없음' : null }],
  },
  'SRV-170': {
    vuln: [],
    safe: [{ pattern: text => hasInternalOnlyPort(text, ['25']) ? 'SMTP 25/tcp가 loopback/내부 대역에만 바인딩 — 배너 외부 노출 없음' : null }],
  },
  'SRV-172': {
    vuln: [{ pattern: /^\s*(?:[A-Z]\$|ADMIN\$)\s/im, reason: '기본 관리 공유(C$/ADMIN$)가 활성 상태' }],
    safe: [{ pattern: text => /공유 이름|Share name/i.test(text) && !/^\s*(?:[A-Z]\$|ADMIN\$)\s/im.test(text)
      ? '기본 관리 공유(C$/ADMIN$) 없음' : null }],
  },
  'SRV-175': {
    vuln: [
      { pattern: /Stratum\s*:\s*0\b/i, reason: '시간 동기화 미동작(Stratum 0 — 동기화 소스 없음)' },
      { pattern: /^Type:\s*NoSync/im, reason: 'Windows 시간 동기화 비활성(Type=NoSync)' },
    ],
    safe: [
      { pattern: /Stratum\s*:\s*[1-9]\d*\b/i, reason: '시간 동기화 동작 중(Stratum 1 이상)' },
      { pattern: /^Type:\s*(?:NTP|NT5DS|AllSync)/im, reason: 'Windows 시간 동기화 구성(Type=NTP/NT5DS)' },
    ],
  },
  'SRV-179': {
    vuln: [{ pattern: text => { const r = osEolVerdict(text); return r && r.expired ? r.name + ' 지원 종료(EOL ' + r.eol + ') OS 사용' : null; } }],
    safe: [{ pattern: text => { const r = osEolVerdict(text); return r && !r.expired ? r.name + ' 벤더 지원 기간 내(EOL ' + r.eol + ')' : null; } }],
  },
  'SRV-001': SNMP_COMMUNITY_RULES,
  'SRV-002': SNMP_COMMUNITY_RULES,
  'SRV-003': {
    vuln: [
      { pattern: text => hasListeningService(text, ['SNMP']) && /PermittedManagers[\s\S]{0,160}(?:not found|cannot find|0x2|오류|실패)/i.test(text) ? 'SNMP 실행 중 허용 관리자 제한이 확인되지 않음' : null },
    ],
    safe: [],
  },
  'SRV-004': SMTP_EXPOSURE_RULES,
  'SRV-005': SENDMAIL_PRIVACY_RULES,
  'SRV-006': {
    // 힌트 이식: SMTP가 loopback/내부 대역에만 LISTEN 하면 외부 노출이 없으므로 LogLevel 미흡을 취약으로 보지 않는다
    vuln: [{ pattern: text => /LogLevel\s*[=:]?\s*(?:0|1|2|3)\b/i.test(text) && !hasInternalOnlyPort(text, ['25']) ? 'sendmail LogLevel이 낮게 설정됨' : null }],
    safe: [
      { pattern: text => hasInternalOnlyPort(text, ['25']) ? 'SMTP 25/tcp가 loopback/내부 대역에만 바인딩 — 외부 노출 없음' : null },
      { pattern: /LogLevel\s*[=:]?\s*(?:9|1[0-9]|[2-9][0-9])\b/i, reason: 'sendmail LogLevel이 감사 가능한 수준으로 설정됨' },
    ],
  },
  'SRV-007': {
    vuln: [{ pattern: text => activeLineMatches(text, /\b(?:Sendmail|ESMTP|SMTP)\b[^\n]*(?:version|[0-9]+\.[0-9]+)/i) ? 'SMTP 배너 또는 설정에 버전 정보가 노출됨' : null }],
    safe: [],
  },
  'SRV-008': {
    safe: [{ pattern: text => hasInternalOnlyPort(text, ['25']) ? 'SMTP 25/tcp가 loopback/내부 대역에만 바인딩 — 외부 노출 없음' : null }],
    vuln: [
      { pattern: /MaxDaemonChildren\s*=\s*0/i, reason: 'sendmail 동시 처리 제한이 비활성화됨' },
      { pattern: /ConnectionRateThrottle\s*=\s*0/i, reason: 'sendmail 연결 속도 제한이 비활성화됨' },
    ],
    safe: [],
  },
  'SRV-009': {
    vuln: [groupOrOtherWritable(/\/etc\/mail|sendmail\.cf/i, 'sendmail 설정 파일이 group/other 쓰기 가능')],
    safe: [
      // 힌트 이식: SMTP가 loopback에만 LISTEN 하면 외부 릴레이 경로 없음 → 양호 (access 파일 부재로 취약 판정 금지)
      { pattern: text => hasInternalOnlyPort(text, ['25']) ? 'SMTP 25/tcp가 loopback/내부 대역에만 바인딩 — 외부 릴레이 경로 없음' : null },
      notGroupOrOtherWritable(/\/etc\/mail|sendmail\.cf/i, 'sendmail 설정 파일 쓰기 권한 제한 확인'),
    ],
  },
  'SRV-010': SENDMAIL_PRIVACY_RULES,
  'SRV-011': FTP_RULES,
  'SRV-012': FTP_RULES,
  'SRV-013': FTP_RULES,
  'SRV-014': {
    vuln: [
      { pattern: /^[^#\n]*\s(?:\*|\d{1,3}(?:\.\d{1,3}){0,3}\/0)\s*\(/im, reason: 'NFS export가 광범위한 대상으로 공개됨' },
      { pattern: /\bno_root_squash\b/i, reason: 'NFS no_root_squash 옵션 확인' },
      { pattern: /\brw\b/i, reason: 'NFS 공유에 쓰기 권한(rw)이 확인됨' },
    ],
    safe: [],
  },
  'SRV-015': {
    vuln: [
      { pattern: /\+@|\+\s*$/m, reason: 'NFS/netgroup 신뢰 설정에 전체 허용 신호가 확인됨' },
      { pattern: /\bno_root_squash\b/i, reason: 'NFS no_root_squash 옵션 확인' },
    ],
    safe: [],
  },
  'SRV-016': { vuln: [{ pattern: text => hasListeningService(text, ['cmsd', 'ttdbserverd', 'rpc.cmsd']) ? '위험 RPC 서비스가 실행 중' : null }], safe: [] },
  'SRV-017': { vuln: [{ pattern: text => hasListeningService(text, ['autofs', 'automount']) ? 'autofs/automount 서비스 실행 신호 확인' : null }], safe: [] },
  'SRV-018': {
    vuln: [
      dwordEquals('AutoShareServer', 1, 'AutoShareServer=1 — 기본 관리 공유 활성'),
      dwordEquals('AutoShareWks', 1, 'AutoShareWks=1 — 기본 관리 공유 활성'),
      // net share 출력에 관리 공유(C$/ADMIN$/D$ 등)가 실제로 존재하면 취약 (SecuMS 기준 정렬)
      { pattern: text => /^\s*(?:[A-Z]\$|ADMIN\$)\s+[A-Z]:\\/im.test(String(text || '')) ? 'net share 에 기본 관리 공유(C$/ADMIN$ 등) 활성 확인' : null },
    ],
    safe: [
      dwordEquals('AutoShareServer', 0, 'AutoShareServer=0 확인'),
      dwordEquals('AutoShareWks', 0, 'AutoShareWks=0 확인'),
      // net share 를 수집했는데 관리 공유가 없으면 양호
      { pattern: text => /공유 이름|Share name|net share/i.test(String(text || '')) && !/^\s*(?:[A-Z]\$|ADMIN\$)\s+[A-Z]:\\/im.test(String(text || '')) ? 'net share 에 기본 관리 공유 없음' : null },
    ],
  },
  'SRV-019': { vuln: [{ pattern: text => hasListeningService(text, ['tftp', 'talk', 'ntalk']) ? 'tftp/talk 계열 서비스 실행 신호 확인' : null }], safe: [] },
  'SRV-020': { vuln: [{ pattern: /\b(?:Everyone|Users|ANONYMOUS LOGON)\b[^\n]*(?:FULL|CHANGE|WRITE|F|C|\(F\))/i, reason: '공유 폴더에 광범위한 쓰기/전체 권한 확인' }], safe: [] },
  'SRV-022': {
    vuln: [
      dwordEquals('LimitBlankPasswordUse', 0, '빈 암호 원격 로그온 제한 비활성'),
      // 힌트 이식(Linux): 빈 암호는 shadow 2번째 필드가 완전히 빈(::) 경우만.
      { pattern: text => {
        for (const raw of String(text || '').split('\n')) {
          const line = raw.trim();
          const p = line.split(':');
          if (p.length >= 4 && /^[a-z_][\w.-]*$/i.test(p[0]) && p[1] === '' && /^\d*$/.test(p[2])) {
            return `빈 패스워드 계정 확인: ${p[0]}`;
          }
        }
        return null;
      } },
    ],
    safe: [
      dwordEquals('LimitBlankPasswordUse', 1, '빈 암호 원격 로그온 제한 활성'),
      // 과탐 방지 (나) 이식: shadow 2번째 필드 * / ! / !! / x / $해시 = 잠금 또는 암호 설정 → 빈 암호 아님
      { pattern: text => {
        const shadowLines = String(text || '').split('\n').map(l => l.trim())
          .filter(l => { const p = l.split(':'); return p.length >= 4 && /^[a-z_][\w.-]*$/i.test(p[0]) && /^\d*$/.test(p[2]); });
        if (!shadowLines.length) return null;
        return shadowLines.every(l => { const f = l.split(':')[1]; return f && /^(\*|!{1,2}|x|\*LK\*|\$.+)/.test(f); })
          ? '모든 계정이 잠금(*/!/!!) 또는 해시 설정 상태 — 빈 패스워드 계정 없음' : null;
      } },
    ],
  },
  'SRV-023': { vuln: [dwordLessThan('MinEncryptionLevel', 2, 'RDP 암호화 수준이 낮음')], safe: [dwordAtLeast('MinEncryptionLevel', 2, 'RDP 암호화 수준 2 이상 확인')] },
  'SRV-024': TELNET_RULES,
  'SRV-025': RCOMMAND_RULES,
  'SRV-026': {
    vuln: [{ pattern: /^[^#\n]*PermitRootLogin\s+yes/im, reason: 'sshd_config PermitRootLogin yes 확인' }],
    safe: [{ pattern: /^[^#\n]*PermitRootLogin\s+no/im, reason: 'sshd_config PermitRootLogin no 확인' }],
  },
  'SRV-028': {
    vuln: [dwordEquals('MaxIdleTime', 0, 'RDP 유휴 시간 제한이 0으로 설정됨')],
    safe: [{ pattern: text => { const v = regDwordValue(text, 'MaxIdleTime'); return v !== null && v > 0 && v <= 3600000 ? 'RDP 유휴 시간 제한 설정 확인' : null; } }],
  },
  'SRV-029': {
    vuln: [dwordEquals('EnableForcedLogOff', 0, '강제 로그오프 정책 비활성'), { pattern: /autodisconnect\s+REG_\w+\s+(?:0xffffffff|-1|0x0\b)/i, reason: '자동 연결 해제 비활성 또는 미설정' }],
    safe: [dwordAtLeast('EnableForcedLogOff', 1, '강제 로그오프 정책 활성')],
  },
  'SRV-030': { vuln: [{ pattern: text => hasListeningService(text, ['finger', 'in.fingerd']) ? 'finger 서비스 실행 신호 확인' : null }], safe: [] },
  'SRV-031': {
    vuln: [dwordEquals('RestrictAnonymous', 0, 'RestrictAnonymous=0으로 익명 열거 제한 미흡'), dwordEquals('RestrictAnonymousSam', 0, 'RestrictAnonymousSam=0으로 익명 SAM 열거 제한 미흡')],
    safe: [dwordAtLeast('RestrictAnonymous', 1, 'RestrictAnonymous 제한 적용'), dwordAtLeast('RestrictAnonymousSam', 1, 'RestrictAnonymousSam 제한 적용')],
  },
  'SRV-032': { vuln: [dwordLessThan('NetbiosOptions', 2, 'NetBIOS over TCP/IP가 활성화됨')], safe: [dwordEquals('NetbiosOptions', 2, 'NetBIOS over TCP/IP 비활성화 확인')] },
  'SRV-034': {
    vuln: [
      { pattern: text => hasListeningService(text, ['Alerter', 'ClipSrv', 'Messenger']) ? '레거시 Windows 서비스 실행 신호 확인' : null },
      // 힌트 이식(Windows): NetbiosOptions 0=기본값(활성)·1=활성 → 취약, 2만 비활성. 인터페이스 중 하나라도 2가 아니면 취약
      { pattern: text => {
        const vals = netbiosOptionValues(text);
        return vals.length && vals.some(v => v !== 2)
          ? `NetbiosOptions=${vals.join(',')} — 2(비활성)가 아닌 인터페이스 존재(0은 기본값=활성)` : null;
      } },
    ],
    safe: [
      { pattern: text => {
        const vals = netbiosOptionValues(text);
        return vals.length && vals.every(v => v === 2) ? '모든 인터페이스 NetbiosOptions=2(NetBIOS over TCP/IP 비활성)' : null;
      } },
    ],
  },
  'SRV-035': RCOMMAND_RULES,
  'SRV-036': { vuln: [{ pattern: text => hasListeningService(text, ['echo', 'discard', 'chargen', 'daytime']) ? 'inetd 테스트 서비스 실행 신호 확인' : null }], safe: [] },
  'SRV-037': FTP_RULES,
  'SRV-038': { vuln: [{ pattern: text => hasListeningService(text, ['IISADMIN', 'W3SVC']) ? 'IIS 서비스 실행 신호 확인' : null }], safe: [] },
  'SRV-039': { vuln: [{ pattern: text => hasListeningService(text, ['Webtob']) ? 'WebtoB 서비스 실행 신호 확인' : null }], safe: [] },
  'SRV-040': { vuln: [{ pattern: /\bOptions\b[^\n]*\bIndexes\b/i, reason: 'Apache Options Indexes 활성화 확인' }], safe: [{ pattern: /\bOptions\b[^\n]*-Indexes\b/i, reason: 'Apache Indexes 비활성화 확인' }] },
  'SRV-041': { vuln: [{ pattern: /\b(?:Everyone|Users)\b[^\n]*(?:FULL|CHANGE|WRITE|\(F\))/i, reason: 'CGI/scripts 경로에 광범위한 쓰기 권한 확인' }], safe: [] },
  'SRV-042': { vuln: [{ pattern: /\bOptions\b[^\n]*\bIndexes\b/i, reason: 'Apache Options Indexes 활성화 확인' }], safe: [{ pattern: /\bOptions\b[^\n]*-Indexes\b/i, reason: 'Apache Indexes 비활성화 확인' }] },
  'SRV-043': { vuln: [{ pattern: /\bOptions\b[^\n]*\bFollowSymLinks\b/i, reason: 'Apache FollowSymLinks 허용 확인' }], safe: [{ pattern: /\bSymLinksIfOwnerMatch\b/i, reason: '심볼릭 링크 소유자 일치 제한 확인' }] },
  'SRV-047': { vuln: [{ pattern: /\bOptions\b[^\n]*\bFollowSymLinks\b/i, reason: 'Apache FollowSymLinks 허용 확인' }], safe: [{ pattern: /\bSymLinksIfOwnerMatch\b/i, reason: '심볼릭 링크 소유자 일치 제한 확인' }] },
  'SRV-048': {
    vuln: [{ pattern: text => hasListeningService(text, ['IISADMIN', 'W3SVC', 'iisadmin', 'w3svc']) ? 'IIS 서비스 실행 신호 확인' : null }],
    safe: [{ pattern: text => /OpenService 실패 1060|does not exist as an installed service/i.test(text) && !/(?:IISADMIN|W3SVC|WAS)[\s\S]{0,120}RUNNING/i.test(text)
      ? 'IIS 서비스 미설치(OpenService 1060) — 점검 대상 부재' : null }],
  },
  'SRV-051': { vuln: [{ pattern: /directoryBrowse\s+enabled\s*=\s*"true"|DirectoryBrowsing\s*(?:=|:)?\s*(?:true|1|enabled)/i, reason: 'IIS 디렉터리 검색 활성화 확인' }], safe: [{ pattern: /directoryBrowse\s+enabled\s*=\s*"false"|DirectoryBrowsing\s*(?:=|:)?\s*(?:false|0|disabled)/i, reason: 'IIS 디렉터리 검색 비활성화 확인' }] },
  'SRV-052': { vuln: [{ pattern: /AspEnableParentPaths\s*(?:=|:)?\s*(?:TRUE|1)/i, reason: 'IIS Parent Paths 활성화 확인' }], safe: [{ pattern: /AspEnableParentPaths\s*(?:=|:)?\s*(?:FALSE|0)/i, reason: 'IIS Parent Paths 비활성화 확인' }] },
  'SRV-053': { vuln: [{ pattern: text => hasListeningService(text, ['WebClient', 'WebDAV']) || /WebDAV[^\n]*(?:enabled|true)/i.test(text) ? 'WebDAV 활성화 신호 확인' : null }], safe: [] },
  'SRV-054': { vuln: [{ pattern: /log(?:ging)?\s*(?:enabled\s*=\s*"false"|=\s*false|:\s*disabled)/i, reason: 'IIS 로깅 비활성화 확인' }], safe: [{ pattern: /log(?:ging)?\s*(?:enabled\s*=\s*"true"|=\s*true|:\s*enabled)/i, reason: 'IIS 로깅 활성화 확인' }] },
  'SRV-057': { vuln: [{ pattern: /\b(?:Everyone|Users|IUSR)\b[^\n]*(?:FULL|CHANGE|WRITE|\(F\))/i, reason: 'IIS 경로에 광범위한 쓰기/전체 권한 확인' }], safe: [] },
  'SRV-059': {
    vuln: [dwordEquals('SSIEnableCmdDirective', 1, 'SSI 명령 실행 지시자가 활성화됨')],
    safe: [
      dwordEquals('SSIEnableCmdDirective', 0, 'SSI 명령 실행 지시자가 비활성화됨'),
      { pattern: text => /SSIEnableCmdDirective/i.test(text) && /Not Found \/ No Data/i.test(text)
        ? 'SSIEnableCmdDirective 미설정(기본 비활성) 또는 IIS 미설치' : null },
    ],
  },
  'SRV-060': {
    vuln: [
      { pattern: /<user\b[^>]*(?:username|name)\s*=\s*["'](?:tomcat|admin|manager|root)["'][^>]*(?:password)\s*=\s*["'][^"']+["']/i, reason: 'Tomcat 기본/관리 계정 정보가 확인됨' },
      { pattern: /roles\s*=\s*["'][^"']*(?:manager-gui|admin-gui|manager-script)/i, reason: 'Tomcat 관리 권한 계정이 확인됨' },
    ],
    safe: [],
  },
  'SRV-061': { vuln: [{ pattern: text => hasListeningPort(text, ['53']) || hasListeningService(text, ['named', 'dns']) ? 'DNS 서비스 노출 신호 확인' : null }], safe: [] },
  'SRV-062': { vuln: [{ pattern: /\brecursion\s+yes\b/i, reason: 'DNS recursion yes 설정 확인' }, { pattern: /allow-recursion\s*\{\s*any\s*;\s*\}/i, reason: 'DNS 재귀 질의가 any로 허용됨' }], safe: [
    { pattern: /\brecursion\s+no\b/i, reason: 'DNS recursion no 설정 확인' },
    { pattern: text => hasInternalOnlyPort(text, ['53']) ? 'DNS 53이 loopback/내부 가상대역에만 바인딩 — 외부 재귀질의 불가' : null },
  ] },
  'SRV-063': {
    vuln: [dwordEquals('NoRecursion', 0, 'Windows DNS 재귀 질의 제한 미적용')],
    safe: [
      dwordEquals('NoRecursion', 1, 'Windows DNS 재귀 질의 제한 적용'),
      // 힌트 이식: named가 loopback/내부 가상대역에서만 LISTEN 하면 외부 recursion 악용 불가 → 양호
      { pattern: text => hasInternalOnlyPort(text, ['53']) ? 'DNS 53이 loopback/내부 가상대역에만 바인딩 — 외부 재귀질의 악용 불가' : null },
    ],
  },
  'SRV-064': {
    vuln: [{ pattern: text => /allow-transfer\s*\{\s*(?:any|0\.0\.0\.0\/0)\s*;\s*\}/i.test(text) && !hasInternalOnlyPort(text, ['53']) ? 'DNS zone transfer가 광범위하게 허용됨' : null }],
    safe: [
      // 힌트 이식: 내부전용 LISTEN이면 외부 공격면 없음. 폐쇄망 dig 프로브 timeout을 취약으로 해석하지 않는다
      { pattern: text => hasInternalOnlyPort(text, ['53']) ? 'DNS 53이 loopback/내부 가상대역에만 바인딩 — 외부 공격면 없음' : null },
    ],
  },
  'SRV-065': { vuln: [{ pattern: /version\s+["']?[^"';\n]+["']?\s*;/i, reason: 'DNS version 문자열이 설정/노출됨' }], safe: [] },
  'SRV-066': {
    vuln: [{ pattern: text => /allow-transfer\s*\{\s*(?:any|0\.0\.0\.0\/0)\s*;\s*\}|SecureSecondaries\s+REG_DWORD\s+0x0/i.test(text) && !hasInternalOnlyPort(text, ['53']) ? 'DNS zone transfer 제한 미흡 신호 확인' : null }],
    safe: [
      dwordAtLeast('SecureSecondaries', 1, 'Windows DNS 보조 서버 제한 설정 확인'),
      // 힌트 이식: 내부전용 LISTEN이면 외부 zone transfer 불가 → 양호
      { pattern: text => hasInternalOnlyPort(text, ['53']) ? 'DNS 53이 loopback/내부 가상대역에만 바인딩 — 외부 zone transfer 불가' : null },
    ],
  },
  'SRV-067': { vuln: [{ pattern: /ADCLaunch|msdfmap\.ini/i, reason: 'ADCLaunch 또는 msdfmap.ini 관련 구성 확인' }], safe: [] },
  'SRV-068': {
    vuln: [
      { pattern: /^\w+:\$[15y]\$|ClearTextPassword\s*=\s*1/im, reason: '약한 패스워드 해시/평문 저장 신호 확인' },
      { pattern: /^[\w.-]+\s+\$1\$/m, reason: 'MD5($1$) 해시 계정 확인' },
    ],
    safe: [{ pattern: text => {
      const rows = String(text || '').split('\n').map(l => l.trim().match(/^([\w.-]+)\s+(\S+)$/)).filter(Boolean);
      const fields = rows.map(r => r[2]);
      return fields.length >= 3 && fields.every(f => f === '*' || f === '!' || f === '!!' || f === 'x' || f.indexOf('$6$') === 0)
        ? 'shadow 해시가 SHA-512($6$)/잠금(*,!!) 계정만 확인 — 약한 해시 노출 없음' : null;
    } }],
  },
  'SRV-069': PASSWORD_POLICY_RULES,
  'SRV-075': {
    // 힌트 이식: 복잡도는 minlen>=8 / 음수 credit / minclass>=1 중 하나면 확보.
    // minclass=0 단독으로 취약 판정 금지 (RHEL 기본 minlen=8 등이면 양호).
    vuln: [
      ...PASSWORD_POLICY_RULES.vuln,
      { pattern: text => {
        const t = String(text || '');
        if (!/pwquality|pam_pwquality|minclass|minlen/i.test(t)) return null;
        const minlen = (t.match(/^\s*minlen\s*=\s*(\d+)/im) || [])[1];
        const negCredit = /^\s*[duol]credit\s*=\s*-\d+/im.test(t);
        const minclass = (t.match(/^\s*minclass\s*=\s*(\d+)/im) || [])[1];
        const noComplexity = (!minlen || +minlen < 8) && !negCredit && (!minclass || +minclass < 1);
        return noComplexity && (minlen || minclass) ? '암호 복잡도 강제 없음(minlen<8, credit 요구 없음, minclass<1)' : null;
      } },
    ],
    safe: [
      ...PASSWORD_POLICY_RULES.safe,
      { pattern: text => {
        const t = String(text || '');
        if (!/pwquality|pam_pwquality|minclass|minlen/i.test(t)) return null;
        const minlen = (t.match(/^\s*minlen\s*=\s*(\d+)/im) || [])[1];
        const negCredit = /^\s*[duol]credit\s*=\s*-\d+/im.test(t);
        const minclass = (t.match(/^\s*minclass\s*=\s*(\d+)/im) || [])[1];
        return (minlen && +minlen >= 8) || negCredit || (minclass && +minclass >= 1)
          ? '암호 복잡도 확보(minlen>=8 또는 credit 요구 또는 minclass>=1)' : null;
      } },
    ],
  },
  'SRV-076': {
    vuln: [
      ...PASSWORD_POLICY_RULES.vuln,
      // Windows net accounts(한/영) 형식
      { pattern: text => { const m = String(text || '').match(/(?:최소 암호 길이|Minimum password length)\s*:?\s*(\d+)/i); return m && +m[1] < 8 ? `최소 암호 길이 ${m[1]}자 (기준 8자 미만)` : null; } },
    ],
    safe: [
      ...PASSWORD_POLICY_RULES.safe,
      { pattern: text => { const m = String(text || '').match(/(?:최소 암호 길이|Minimum password length)\s*:?\s*(\d+)/i); return m && +m[1] >= 8 ? `최소 암호 길이 ${m[1]}자 (기준 충족)` : null; } },
    ],
  },
  // v2 수집기: secedit 평문 암호 저장 설정 (ClearTextPassword = 0/1)
  'SRV-071': {
    vuln: [dwordEquals('ClearTextPassword', 1, '암호를 해독 가능한 평문으로 저장(ClearTextPassword=1)')],
    safe: [dwordEquals('ClearTextPassword', 0, '평문 암호 저장 비활성(ClearTextPassword=0) 확인')],
  },
  'SRV-077': {
    vuln: [
      { pattern: /^[^:\n]+::\d+:/m, reason: '/etc/passwd에 빈 패스워드 필드가 확인됨' },
      dwordEquals('ClearTextPassword', 1, 'Windows ClearTextPassword=1 확인'),
      // v2 수집기 PS 테이블(Name Enabled PasswordRequired ...): 활성 계정인데 암호 불필요 = 취약
      { pattern: text => { const m = String(text || '').match(/^\s*(\S+)\s+True\s+False\b/im); return m ? `활성 계정(${m[1]})에 암호 불필요(PasswordRequired=False)` : null; } },
    ],
    safe: [
      dwordEquals('ClearTextPassword', 0, 'Windows ClearTextPassword=0 확인'),
      // 활성(True) 계정이 모두 PasswordRequired=True 이면 양호 (비활성 계정의 False는 무해)
      { pattern: text => {
        const rows = [...String(text || '').matchAll(/^\s*(\S+)\s+(True|False)\s+(True|False)\b/gim)];
        if (!rows.length || !/PasswordRequired/i.test(text)) return null;
        const active = rows.filter(r => /^true$/i.test(r[2]));
        return active.length && active.every(r => /^true$/i.test(r[3]))
          ? '활성 계정 모두 암호 필수(PasswordRequired=True), 빈/평문 암호 계정 없음' : null;
      } },
    ],
  },
  'SRV-078': {
    vuln: [
      { pattern: /Account active\s+Yes/i, reason: 'Guest 계정 활성화 확인' },
      // v2 수집기 PS 테이블 형식: "Name  Enabled / ----  ------- / Guest   True"
      { pattern: /^\s*Guest\s+True\s*$/im, reason: 'Guest 계정이 활성 상태(Enabled=True)' },
    ],
    safe: [
      { pattern: /Account active\s+No/i, reason: 'Guest 계정 비활성화 확인' },
      { pattern: /^\s*Guest\s+False\s*$/im, reason: 'Guest 계정 비활성(Enabled=False) 확인' },
    ],
  },
  'SRV-079': { vuln: [dwordEquals('everyoneincludesanonymous', 1, 'EveryoneIncludesAnonymous=1 확인')], safe: [dwordEquals('everyoneincludesanonymous', 0, 'EveryoneIncludesAnonymous=0 확인')] },
  'SRV-080': { vuln: [dwordEquals('AddPrinterDrivers', 1, 'AddPrinterDrivers=1 확인')], safe: [dwordEquals('AddPrinterDrivers', 0, 'AddPrinterDrivers=0 확인')] },
  'SRV-081': { vuln: [groupOrOtherWritable(/\/var\/spool\/cron/i, 'cron 경로가 group/other 쓰기 가능')], safe: [notGroupOrOtherWritable(/\/var\/spool\/cron/i, 'cron 경로 쓰기 권한 제한 확인')] },
  'SRV-082': { vuln: [groupOrOtherWritable(/\/(?:usr|bin|sbin|etc|var)\b/i, '중요 시스템 디렉터리가 group/other 쓰기 가능')], safe: [notGroupOrOtherWritable(/\/(?:usr|bin|sbin|etc|var)\b/i, '중요 시스템 디렉터리 쓰기 권한 제한 확인')] },
  'SRV-083': { vuln: [groupOrOtherWritable(/\/etc\/(?:inittab|init\.d|rc\d?\.d)/i, '시작 스크립트가 group/other 쓰기 가능')], safe: [notGroupOrOtherWritable(/\/etc\/(?:inittab|init\.d|rc\d?\.d)/i, '시작 스크립트 쓰기 권한 제한 확인')] },
  'SRV-084': { vuln: [groupOrOtherWritable(/\/etc\/passwd/i, '/etc/passwd가 group/other 쓰기 가능')], safe: [notGroupOrOtherWritable(/\/etc\/passwd/i, '/etc/passwd 쓰기 권한 제한 확인')] },
  'SRV-085': { vuln: [shadowReadableByOthers(/\/etc\/shadow/i, '/etc/shadow가 group/other에 노출됨')], safe: [shadowPrivate(/\/etc\/shadow/i, '/etc/shadow 접근 권한 제한 확인')] },
  'SRV-086': { vuln: [groupOrOtherWritable(/\/etc\/hosts/i, '/etc/hosts가 group/other 쓰기 가능')], safe: [notGroupOrOtherWritable(/\/etc\/hosts/i, '/etc/hosts 쓰기 권한 제한 확인')] },
  'SRV-087': { vuln: [{ pattern: /\/(?:usr\/bin|usr\/local\/bin|bin)\/(?:cc|gcc)\b/i, reason: '운영 서버에 컴파일러 실행 파일이 확인됨' }], safe: [] },
  'SRV-088': { vuln: [groupOrOtherWritable(/\/etc\/(?:inetd|xinetd)\.conf/i, 'inetd/xinetd 설정 파일이 group/other 쓰기 가능')], safe: [notGroupOrOtherWritable(/\/etc\/(?:inetd|xinetd)\.conf/i, 'inetd/xinetd 설정 파일 쓰기 권한 제한 확인')] },
  'SRV-089': { vuln: [groupOrOtherWritable(/\/etc\/(?:syslog|rsyslog)\.conf/i, 'syslog 설정 파일이 group/other 쓰기 가능')], safe: [notGroupOrOtherWritable(/\/etc\/(?:syslog|rsyslog)\.conf/i, 'syslog 설정 파일 쓰기 권한 제한 확인')] },
  'SRV-090': { vuln: [{ pattern: /RemoteRegistry[\s\S]{0,160}(?:RUNNING|STATE\s*:\s*4|Auto|Automatic)/i, reason: 'RemoteRegistry 서비스 실행/자동 시작 확인' }], safe: [{ pattern: /RemoteRegistry[\s\S]{0,160}(?:STOPPED|STATE\s*:\s*1|Disabled|사용 안 함)/i, reason: 'RemoteRegistry 중지/비활성화 확인' }] },
  'SRV-093': { vuln: [anyFindingLine('홈 디렉터리 world-writable 파일이 출력됨')], safe: [] },
  'SRV-095': { vuln: [anyFindingLine('소유자/그룹 없는 파일이 출력됨')], safe: [] },
  'SRV-096': {
    // 힌트 이식(2026 기준): 사용자 환경파일에 others r/w/x가 하나라도 있으면 취약 — 0644(rw-r--r--)도 취약.
    // others 비트가 모두 0인 0600·0640·0660 등만 양호.
    vuln: [
      { pattern: text => {
        const dotfileRe = /\.(?:bashrc|bash_profile|bash_login|bash_logout|profile|cshrc|tcshrc|login|logout|kshrc|netrc|exrc|history)\b/i;
        for (const raw of String(text || '').split('\n')) {
          const line = raw.trim();
          if (!/^[-][rwxstST-]{9}[.+]?\s+/.test(line) || !dotfileRe.test(line)) continue;
          const mode = line.slice(0, 10);
          if (/[rwx]/i.test(mode.slice(7, 10))) {
            return `사용자 환경파일에 others 권한 존재(${line.split(/\s+/).pop()} ${mode}) — others r/w/x 하나라도 있으면 취약(0644 포함)`;
          }
        }
        return null;
      } },
      groupOrOtherWritable(/\/home\/[^/\s]+\/\.[^\s]+/i, '사용자 dotfile이 group/other 쓰기 가능'),
    ],
    safe: [
      { pattern: text => {
        const dotfileRe = /\.(?:bashrc|bash_profile|bash_login|bash_logout|profile|cshrc|tcshrc|login|logout|kshrc|netrc|exrc|history)\b/i;
        const lines = String(text || '').split('\n').map(l => l.trim())
          .filter(l => /^[-][rwxstST-]{9}[.+]?\s+/.test(l) && dotfileRe.test(l));
        if (!lines.length) return null;
        return lines.every(l => { const mode = l.slice(0, 10); return mode.slice(7, 10) === '---' && mode[5] !== 'w'; })
          ? '모든 사용자 환경파일 others 권한 없음(group 쓰기 없음)' : null;
      } },
    ],
  },
  'SRV-098': { vuln: [{ pattern: /\b(?:Everyone|Users|ANONYMOUS LOGON)\b[^\n]*(?:FULL|CHANGE|WRITE|\(F\))/i, reason: 'SAM 파일에 광범위한 권한 확인' }], safe: [] },
  'SRV-099': { vuln: [groupOrOtherWritable(/\/etc\/services/i, '/etc/services가 group/other 쓰기 가능')], safe: [notGroupOrOtherWritable(/\/etc\/services/i, '/etc/services 쓰기 권한 제한 확인')] },
  'SRV-100': { vuln: [{ pattern: /^[bcdlps-]..s[rwxStTs-]{6}[.+]?\s+.*\/xterm\b/im, reason: 'xterm SUID 권한 확인' }, groupOrOtherWritable(/\/xterm\b/i, 'xterm이 group/other 쓰기 가능')], safe: [] },
  // 힌트 이식(Windows): MS 기본 텔레메트리/불필요 예약 작업이 활성이면 2026 기준상 취약
  'SRV-101': {
    vuln: [{ pattern: text => {
      const m = String(text || '').match(/(Microsoft Compatibility Appraiser|Customer Experience Improvement|ProgramDataUpdater|appuriverifier\w*)[^\n]{0,200}?(Ready|Running|준비|실행|Enabled|사용)/i);
      return m ? `불필요 기본 예약 작업 활성: ${m[1]} (상태: ${m[2]})` : null;
    } }],
    safe: [],
  },
  'SRV-103': {
    // 보안 강화 키 미설정(Not Found)도 취약 — 기본값은 NTLMv2 강제가 아님 (LLM 규칙: 설정값 부재 ≠ 부재양호)
    vuln: [dwordMissingOrLess('LmCompatibilityLevel', 3, 'LM/NTLM 인증 수준 미설정 또는 3 미만')],
    safe: [dwordAtLeast('LmCompatibilityLevel', 3, 'LmCompatibilityLevel 3 이상 확인')],
  },
  'SRV-104': {
    vuln: [anyDwordLessThan(['RequireSignOrSeal', 'SealSecureChannel', 'SignSecureChannel'], 1, 'Netlogon 보안 채널 서명/암호화 옵션 미흡')],
    safe: [allDwordsAtLeast(['RequireSignOrSeal', 'SealSecureChannel', 'SignSecureChannel'], 1, 'Netlogon 보안 채널 서명/암호화 옵션 활성')],
  },
  'SRV-106': { vuln: [anyFindingLine('/etc/hosts.lpd 신뢰 파일 내용 또는 권한이 확인됨')], safe: [] },
  'SRV-107': { vuln: [groupOrOtherWritable(/\/etc\/at\.(?:allow|deny)/i, 'at.allow/at.deny가 group/other 쓰기 가능')], safe: [notGroupOrOtherWritable(/\/etc\/at\.(?:allow|deny)/i, 'at.allow/at.deny 쓰기 권한 제한 확인')] },
  'SRV-108': { vuln: [groupOrOtherWritable(/\/var\/log\//i, '로그 파일이 group/other 쓰기 가능')], safe: [notGroupOrOtherWritable(/\/var\/log\//i, '로그 파일 쓰기 권한 제한 확인')] },
  'SRV-109': { vuln: [{ pattern: /^Audit\w+\s*=\s*0\b/im, reason: 'Windows 감사 정책이 비활성인 항목 확인' }], safe: [{ pattern: /^Audit\w+\s*=\s*[123]\b/im, reason: 'Windows 감사 정책 활성 항목 확인' }] },
  'SRV-110': { vuln: [{ pattern: /\b(?:Everyone|Users|ANONYMOUS LOGON)\b[^\n]*(?:FULL|CHANGE|WRITE|\(F\))/i, reason: 'system32/config에 광범위한 권한 확인' }], safe: [] },
  'SRV-111': { vuln: [dwordEquals('RestrictGuestAccess', 0, 'Eventlog RestrictGuestAccess=0 확인')], safe: [dwordEquals('RestrictGuestAccess', 1, 'Eventlog RestrictGuestAccess=1 확인')] },
  'SRV-113': { vuln: [{ pattern: /SeSecurityPrivilege[^\n]*(?:Everyone|Guests|Users|S-1-1-0|S-1-5-32-545)/i, reason: '감사 권한이 일반 사용자/광범위 그룹에 부여됨' }], safe: [] },
  'SRV-115': { vuln: [groupOrOtherWritable(/\/var\/log\//i, '로그 파일이 group/other 쓰기 가능')], safe: [notGroupOrOtherWritable(/\/var\/log\//i, '로그 파일 쓰기 권한 제한 확인')] },
  'SRV-116': { vuln: [dwordEquals('crashonauditfail', 0, 'CrashOnAuditFail=0 확인')], safe: [dwordAtLeast('crashonauditfail', 1, 'CrashOnAuditFail 설정 확인')] },
  'SRV-121': { vuln: [{ pattern: /(?:^|:)\.(?::|$)|(?:^|:)\/tmp(?::|$)|(?:^|:)\/var\/tmp(?::|$)/i, reason: 'PATH에 현재 디렉터리 또는 임시 디렉터리가 포함됨' }], safe: [] },
  'SRV-122': UMASK_RULES,
  'SRV-123': { vuln: [dwordEquals('DontDisplayLastUserName', 0, '마지막 로그온 사용자 표시 활성')], safe: [dwordEquals('DontDisplayLastUserName', 1, '마지막 로그온 사용자 표시 비활성')] },
  'SRV-124': {
    vuln: [{ pattern: text => { const raw = regStringValue(text, 'cachedlogonscount'); const v = raw !== null ? parseInt(raw, 10) : null; return Number.isFinite(v) && v > 4 ? '캐시 로그온 수가 4를 초과함' : null; } }],
    safe: [{ pattern: text => { const raw = regStringValue(text, 'cachedlogonscount'); const v = raw !== null ? parseInt(raw, 10) : null; return Number.isFinite(v) && v >= 0 && v <= 4 ? '캐시 로그온 수 4 이하 확인' : null; } }],
  },
  'SRV-125': {
    vuln: [dwordEquals('ScreenSaveActive', 0, '화면 보호기 비활성'), dwordEquals('ScreenSaverIsSecure', 0, '화면 보호기 잠금 미적용'), dwordGreaterThan('ScreenSaveTimeOut', 600, '화면 보호기 타임아웃이 600초 초과')],
    safe: [dwordEquals('ScreenSaveActive', 1, '화면 보호기 활성'), dwordEquals('ScreenSaverIsSecure', 1, '화면 보호기 잠금 활성')],
  },
  'SRV-126': {
    vuln: [{ pattern: /AutoAdminLogon\s+REG_\w+\s+1\b/i, reason: 'AutoAdminLogon 활성화 확인' }, { pattern: /DefaultPassword\s+REG_\w+\s+\S+/i, reason: 'Winlogon DefaultPassword 저장 확인' }],
    safe: [
      { pattern: /AutoAdminLogon\s+REG_\w+\s+0\b/i, reason: 'AutoAdminLogon 비활성화 확인' },
      // v2 수집기 PS 테이블: AutoAdminLogon/DefaultPassword 값이 모두 비어있음 = 자동 로그온 미설정(기본값 안전)
      { pattern: text => {
        const t = String(text || '');
        if (!/AutoAdminLogon/i.test(t)) return null;
        const auto = psTableCell(t, 'AutoAdminLogon');
        const pw = psTableCell(t, 'DefaultPassword');
        return (auto === null && pw === null && /AutoAdminLogon[^\n]*\n[-\s]+\n/i.test(t))
          ? 'AutoAdminLogon/DefaultPassword 미설정 — 자동 로그온 없음' : null;
      } },
    ],
  },
  'SRV-127': {
    vuln: [
      { pattern: /^FAILLOG_ENAB\s+no\b/im, reason: 'FAILLOG_ENAB=no 확인' },
      dwordEquals('MaxDenials', 0, 'RemoteAccess 계정 잠금 임계값 미설정'),
      dwordEquals('LockoutBadCount', 0, '계정 잠금 임계값 0 확인'),
      // Windows net accounts(한/영): 잠금 임계값 "아님/Never" = 잠금 정책 없음
      { pattern: /(?:잠금 임계값|Lockout threshold)\s*:?\s*(?:아님|없음|Never)/i, reason: '계정 잠금 임계값 미설정(Never/아님)' },
      // Linux PAM: system-auth 수집은 됐는데 faillock/tally 잠금 모듈이 전혀 없음 = 잠금 정책 미적용.
      // egrep 명령줄 자체에 'pam_faillock' 문자열이 들어가므로 명령줄($/cmd#)은 제외하고 결과 라인만 본다.
      { pattern: text => {
        const lines = String(text || '').split('\n').map(l => l.trim())
          .filter(l => l && !l.startsWith('$') && !l.startsWith('cmd#') && !l.startsWith('#'));
        const hasPam = lines.some(l => /^(?:password|auth|account)\s+\S+\s+pam_/i.test(l));
        const hasLock = lines.some(l => /pam_(?:faillock|tally2?)/i.test(l) || /^deny\s*=\s*[1-9]\d*/i.test(l));
        return hasPam && !hasLock ? 'PAM/faillock.conf에 계정 잠금 설정 없음(faillock/tally 미적용)' : null;
      } },
    ],
    safe: [
      { pattern: /^FAILLOG_ENAB\s+yes\b/im, reason: 'FAILLOG_ENAB=yes 확인' },
      dwordAtLeast('MaxDenials', 1, 'RemoteAccess 계정 잠금 임계값 설정 확인'),
      dwordAtLeast('LockoutBadCount', 1, '계정 잠금 임계값 설정 확인'),
      { pattern: text => { const m = String(text || '').match(/(?:잠금 임계값|Lockout threshold)\s*:?\s*(\d+)/i); return m && +m[1] >= 1 && +m[1] <= 10 ? `계정 잠금 임계값 ${m[1]}회 설정 확인` : null; } },
      { pattern: /pam_(?:faillock|tally2?)[^\n]*deny\s*=\s*\d+/i, reason: 'pam_faillock/tally 계정 잠금 정책 확인' },
      // RHEL8+ faillock.conf 방식 (활성 라인 deny = N)
      { pattern: text => activeLineMatches(text, /^deny\s*=\s*[1-9]\d*$/i) ? 'faillock.conf 계정 잠금 임계값(deny) 설정 확인' : null },
    ],
  },
  'SRV-128': { vuln: [{ pattern: /\bFAT(?:32)?\b/i, reason: 'ACL 통제가 제한적인 FAT/FAT32 파일시스템 확인' }], safe: [{ pattern: /\bNTFS\b/i, reason: 'NTFS 파일시스템 확인' }] },
  'SRV-130': UMASK_RULES,
  'SRV-131': {
    vuln: [{ pattern: text => /pam_wheel\.so/i.test(text) && !/^[^#\n].*pam_wheel\.so/im.test(text) ? 'pam_wheel.so가 주석 처리되어 su 제한이 미흡함' : null }],
    safe: [{ pattern: /^[^#\n].*pam_wheel\.so/im, reason: 'PAM wheel 기반 su 제한 활성 라인 확인' }],
  },
  'SRV-132': { vuln: [groupOrOtherWritable(/\/etc\/cron\.d\/cron\.(?:allow|deny)/i, 'cron allow/deny 파일이 group/other 쓰기 가능')], safe: [notGroupOrOtherWritable(/\/etc\/cron\.d\/cron\.(?:allow|deny)/i, 'cron allow/deny 파일 쓰기 권한 제한 확인')] },
  'SRV-136': { vuln: [dwordEquals('ShutdownWithoutLogon', 1, '로그온 전 시스템 종료 허용')], safe: [dwordEquals('ShutdownWithoutLogon', 0, '로그온 전 시스템 종료 차단')] },
  'SRV-137': { vuln: [{ pattern: /SeNetworkLogonRight[^\n]*(?:Everyone|Guests|Users|S-1-1-0|S-1-5-32-545)/i, reason: '네트워크 로그온 권한이 광범위 그룹에 부여됨' }], safe: [] },
  'SRV-138': { vuln: [{ pattern: /Se(?:Backup|Restore)Privilege[^\n]*(?:Everyone|Guests|Users|S-1-1-0|S-1-5-32-545)/i, reason: '백업/복원 권한이 일반 사용자 그룹에 부여됨' }], safe: [] },
  'SRV-139': { vuln: [{ pattern: /SeTakeOwnershipPrivilege[^\n]*(?:Everyone|Guests|Users|S-1-1-0|S-1-5-32-545)/i, reason: '소유권 가져오기 권한이 일반 사용자 그룹에 부여됨' }], safe: [] },
  'SRV-140': { vuln: [{ pattern: /AllocateDASD\s+REG_\w+\s+(?:0|Everyone|1)\b/i, reason: '이동식 미디어 권한이 과도하게 허용됨' }], safe: [] },
  'SRV-141': {
    vuln: [
      ...FIREWALL_RULES.vuln,
      // netsh advfirewall show allprofiles (한/영): 프로파일 중 하나라도 비활성이면 취약
      { pattern: /^(?:상태|State)\s+(?:사용 안 함|OFF)\s*$/im, reason: '방화벽 프로파일 중 비활성(사용 안 함/OFF) 존재' },
    ],
    safe: [
      ...FIREWALL_RULES.safe,
      { pattern: text => {
        const states = String(text || '').match(/^(?:상태|State)\s+\S[^\n]*$/gim) || [];
        return states.length && states.every(s => !/사용 안 함|OFF/i.test(s)) ? '모든 방화벽 프로파일 활성(사용/ON)' : null;
      } },
    ],
  },
  'SRV-142': {
    vuln: [
      { pattern: text => String(text || '').split('\n').some(line => /^[^:\s]+:[^:]*:0:/.test(line) && !/^root:/.test(line)) ? 'root 외 UID 0 계정이 확인됨' : null },
      // v2 수집기 awk 요약 형식: "계정명 -> UID=0"
      { pattern: text => { const m = String(text || '').match(/^(?!root\b)(\S+)\s*->\s*UID=0\b/m); return m ? `root 외 UID=0 계정 확인: ${m[1]}` : null; } },
    ],
    safe: [
      { pattern: text => /^[^:\s]+:[^:]*:0:/m.test(text) && !String(text || '').split('\n').some(line => /^[^:\s]+:[^:]*:0:/.test(line) && !/^root:/.test(line)) ? 'UID 0 계정이 root만 확인됨' : null },
      { pattern: text => { const rows = String(text || '').match(/^\S+\s*->\s*UID=0\b/gm) || []; return rows.length && rows.every(r => /^root\b/.test(r)) ? 'UID=0 계정은 root뿐임' : null; } },
    ],
  },
  'SRV-143': {
    // passwd 형식(7필드)만 검사 — group(4필드) 라인이 섞이면 GID를 UID로 오인해 과탐
    vuln: [{ pattern: text => {
      const seen = new Map();
      for (const line of String(text || '').split('\n')) {
        const parts = line.trim().split(':');
        if (parts.length !== 7 || !/^\d+$/.test(parts[2])) continue;
        if (seen.has(parts[2])) return `중복 UID ${parts[2]} 확인 (${seen.get(parts[2])}, ${parts[0]})`;
        seen.set(parts[2], parts[0]);
      }
      return null;
    } }],
    safe: [],
  },
  'SRV-144': { vuln: [anyFindingLine('/dev 아래 일반 파일이 출력됨')], safe: [] },
  'SRV-145': { vuln: [{ pattern: /^(?:daemon|bin|sys|adm|listen|nobody|operator|games|gopher):[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:\/(?:bin|usr\/bin)\/(?:sh|bash|ksh|csh|zsh)\b/im, reason: '시스템 계정에 로그인 가능한 쉘 부여' }], safe: [] },
  'SRV-146': { vuln: [{ pattern: /^ftp:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:\/(?!sbin\/nologin|bin\/false)/im, reason: 'ftp 계정에 로그인 가능한 쉘 부여' }], safe: [{ pattern: /^ftp:[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:\/(?:sbin\/nologin|bin\/false)/im, reason: 'ftp 계정 로그인 쉘 차단 확인' }] },
  'SRV-150': { vuln: [{ pattern: /SeInteractiveLogonRight[^\n]*(?:Everyone|Guests|Users|S-1-1-0|S-1-5-32-545)/i, reason: '로컬 로그온 권한이 광범위 그룹에 부여됨' }], safe: [] },
  'SRV-152': { vuln: [{ pattern: /SeRemoteInteractiveLogonRight[^\n]*(?:Everyone|Guests|Users|S-1-1-0|S-1-5-32-545)/i, reason: '원격 대화형 로그온 권한이 광범위 그룹에 부여됨' }], safe: [] },
  'SRV-156': {
    vuln: [{ pattern: /autodisconnect\s+REG_\w+\s+(?:0xffffffff|0x0|-1)\b/i, reason: '세션 자동 연결 해제 비활성 또는 미설정' }],
    safe: [{ pattern: text => { const v = regDwordValue(text, 'autodisconnect'); return v !== null && v > 0 && v < 0xffffffff ? '세션 자동 연결 해제 시간 설정 확인' : null; } }],
  },
  'SRV-158': TELNET_RULES,
  'SRV-159': {
    vuln: [{ pattern: text => activeLineMatches(text, /^(?:TMOUT|TIMEOUT)\s*=\s*0\b/i) ? '유휴 세션 타임아웃이 0으로 설정됨' : null }],
    safe: [{ pattern: text => activeLineMatches(text, /^(?:TMOUT|TIMEOUT)\s*=\s*(?:[1-9][0-9]{1,3})\b/i) ? '유휴 세션 타임아웃 값 설정 확인' : null }],
  },
  'SRV-161': FTP_RULES,
  'SRV-163': {
    vuln: [
      { pattern: /LegalNotice(?:Caption|Text)\s+REG_\w+\s*$/im, reason: 'Windows 로그온 배너 값이 비어 있음' },
      { pattern: /^(?:cat\s+)?\/etc\/(?:motd|issue)\s*$/im, reason: 'Linux 로그온 배너 내용이 확인되지 않음' },
      // v2 수집기: 배너 값이 비어있음(empty_or_unset 힌트 또는 PS 테이블 빈 값) = 배너 미설정 = 취약
      { pattern: text => {
        const t = String(text || '');
        if (!/legalnotice(?:caption|text)/i.test(t)) return null;
        if (/COLLECTION_HINT=empty_or_unset/i.test(t)) return 'LegalNoticeCaption/Text 미설정 — 로그온 경고 배너 없음';
        const cap = psTableCell(t, 'legalnoticecaption');
        const txt = psTableCell(t, 'legalnoticetext');
        return (cap === null && txt === null && /legalnotice\w*[^\n]*\n[-\s]+\n/i.test(t))
          ? 'LegalNoticeCaption/Text 값이 비어 있음 — 로그온 경고 배너 미설정' : null;
      } },
    ],
    safe: [
      { pattern: /LegalNotice(?:Caption|Text)\s+REG_\w+\s+\S+|Authorized users only|경고|warning|warning/i, reason: '로그온 배너 문구 확인' },
      // 주의: Banner 경로 지시자만으로 양호 처리 금지 — 배너 파일이 비어있으면 미설정과 동일
      // (3-way 검증: SecuMS·LLM 모두 "내용 존재"를 요구 — SRV-163 disagree 원인이었음)
      { pattern: /(?:unauthorized|무단\s*(?:접근|사용)|법적|모니터링|monitored|prohibited)/i, reason: '로그온 경고 배너 내용 존재 확인' },
    ],
  },
  'SRV-164': {
    // group 형식(3~4필드)만 검사 — passwd(7필드) 라인이 섞이면 UID를 GID로 오인해 과탐
    vuln: [{ pattern: text => {
      const seen = new Map();
      for (const line of String(text || '').split('\n')) {
        const parts = line.trim().split(':');
        if ((parts.length !== 3 && parts.length !== 4) || !/^\d+$/.test(parts[2])) continue;
        if (seen.has(parts[2])) return `중복 GID ${parts[2]} 확인 (${seen.get(parts[2])}, ${parts[0]})`;
        seen.set(parts[2], parts[0]);
      }
      return null;
    } }],
    safe: [],
  },
  'SRV-165': { vuln: [{ pattern: /^(?:daemon|bin|sys|adm|listen|nobody|operator|games|gopher):[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:\/(?:bin|usr\/bin)\/(?:sh|bash|ksh|csh|zsh)\b/im, reason: '시스템 계정에 로그인 가능한 쉘 부여' }], safe: [] },
  'SRV-167': FTP_RULES,
  'SRV-168': { vuln: [{ pattern: /^[^#\n]*\*\.\*\s+\/dev\/null/im, reason: '전체 로그가 /dev/null로 폐기되는 설정 확인' }], safe: [{ pattern: /^[^#\n]*(?:authpriv|kern|daemon|\*\.\*)\.[^\n]+\s+@{1,2}[\w.-]+/im, reason: '원격 syslog 전송 설정 확인' }] },
  // 힌트 이식: sudo 권한 부여 현황이 0행(=일반 계정·그룹에 부여된 sudo 없음)이고
  // 다른 액션은 정상 수집(rows>0)이면 수집 실패가 아니라 "부여 없음" → 양호
  'SRV-177': {
    vuln: [],
    safe: [{ pattern: text => {
      const t = String(text || '');
      return /sudo/i.test(t) && /<Rows count="0"\s*\/?>/i.test(t) && /<Rows count="[1-9]/.test(t)
        ? '일반 계정·그룹 sudo 권한 부여 없음(부여 현황 0행, 타 액션 수집 정상)' : null;
    } }],
  },

  // ── C-plan 갭 보강: SCRIPT_DEFAULT 로만 판정되던 규제항목에 전용 룰 추가 ──
  //    (결정론적으로 판정 가능한 항목만. patch/프로세스/수동확인/계정목록 등은 억지 룰 대신 LLM/정보로 남김.)
  'SRV-021': {
    vuln: [{ pattern: /(?:Everyone|Users|IUSR)[^\n]*(?:FullControl|Modify|Write|\(F\)|\(M\)|\(W\))/i, reason: 'IIS 설정 파일에 Everyone/Users 과다 권한' }],
    safe: [{ pattern: /PATH_NOT_FOUND|IIS not installed/i, reason: 'IIS 미설치(대상 없음)' }],
  },
  'SRV-027': {
    vuln: [
      { pattern: text => /State\s+OFF/i.test(text) ? '방화벽 프로파일 중 비활성(State OFF) 존재' : null },
      { pattern: /-P\s+INPUT\s+ACCEPT/i, reason: 'iptables INPUT 기본 정책이 ACCEPT(기본 허용)' },
    ],
    safe: [{ pattern: text => /State\s+ON/i.test(text) && !/State\s+OFF/i.test(text) ? '모든 방화벽 프로파일 활성(State ON)' : null }],
  },
  'SRV-046': {
    vuln: [
      { pattern: /ServerTokens\s+(?:Full|OS|Major|Minor|Min)\b/i, reason: 'ServerTokens 가 상세 버전 노출 수준' },
      { pattern: /ServerSignature\s+On\b/i, reason: 'ServerSignature On — 오류페이지에 버전 노출' },
    ],
    safe: [{ pattern: text => /ServerTokens\s+Prod/i.test(text) && /ServerSignature\s+Off/i.test(text) ? 'ServerTokens Prod + ServerSignature Off 확인' : null }],
  },
  'SRV-049': {
    vuln: [{ pattern: text => String(text || '').split('\n').some(l => { const t = l.trim(); return t && !t.startsWith('$') && !t.startsWith('#') && !/PATH_NOT_FOUND|not installed|no data|not found/i.test(t) && /(?:iissamples|iisstart|iisHelp|IIS Resources|\.htr\b|printer)/i.test(t); }) ? 'IIS 샘플/기본 파일이 존재' : null }],
    safe: [{ pattern: /PATH_NOT_FOUND|IIS not installed/i, reason: 'IIS 미설치 또는 샘플 파일 없음' }],
  },
  'SRV-056': {
    vuln: [{ pattern: /(?:SSL 2\.0|SSL 3\.0|PCT)[\s\S]{0,200}Enabled\s+REG_\w+\s+0x1/i, reason: '취약 SSL 프로토콜(SSL 2.0/3.0)이 Enabled' }],
    safe: [{ pattern: /(?:SSL 2\.0|SSL 3\.0)[\s\S]{0,200}Enabled\s+REG_\w+\s+0x0/i, reason: 'SSL 2.0/3.0 비활성 확인' }],
  },
  'SRV-070': {
    // 힌트 이식: 오직 해시 알고리즘만 본다 — shadow $6$(SHA-512)=양호, $1$(MD5)/DES=취약.
    // UID>=1000 계정 존재·로그인 쉘 부여는 이 항목과 무관(항목 범위 위반 금지).
    vuln: [
      { pattern: /ENCRYPT_METHOD\s+(?:MD5|DES)\b|MD5_CRYPT_ENAB\s+yes|hash_algo=\$1\$/i, reason: '약한 패스워드 해시(MD5/DES) 사용' },
      { pattern: /^[^:\n]+:\$1\$/m, reason: 'shadow에 MD5($1$) 해시 계정 확인' },
    ],
    safe: [
      { pattern: /ENCRYPT_METHOD\s+SHA512|hash_algo=\$6\$|SHA-512/i, reason: 'SHA-512 등 강한 패스워드 해시 사용' },
      { pattern: /^[^:\n]+:\$6\$/m, reason: 'shadow 해시가 SHA-512($6$) — 저장 방식 양호' },
    ],
  },
  'SRV-092': {
    vuln: [groupOrOtherWritable(/\/(?:etc|usr|bin|sbin|var)\b/i, '중요 시스템 파일이 group/other 쓰기 가능')],
    safe: [notGroupOrOtherWritable(/\/(?:etc|usr|bin|sbin|var)\b/i, '중요 파일 쓰기 권한 제한 확인')],
  },
  // 힌트 이식: 표준 유틸이라도 임의 화이트리스트 금지 — 수집된 SUID/SGID 파일이 있으면 취약(미탐 방지)
  'SRV-091': {
    vuln: [{ pattern: text => {
      const files = [];
      for (const raw of String(text || '').split('\n')) {
        const l = raw.trim();
        if (!/^[-][rwxStTs-]{9}[.+]?\s+/.test(l)) continue;
        const mode = l.slice(0, 10);
        if (/[sS]/.test(mode[3]) || /[sS]/.test(mode[6])) files.push(l.split(/\s+/).pop());
      }
      if (!files.length) return null;
      const head = files.slice(0, 5).join(', ');
      return `SUID/SGID 설정 파일 존재: ${head}${files.length > 5 ? ` 외 ${files.length - 5}건` : ''} — 허용목록 검토 필요`;
    } }],
    safe: [],
  },
  'SRV-102': {
    vuln: [{ pattern: /(?:Everyone|Users)[^\n]*(?:FullControl|Modify|Write|\(F\)|\(M\))/i, reason: '사용자 프로필/파일에 Everyone/Users 과다 권한' }],
    safe: [],
  },
  'SRV-147': {
    vuln: [groupOrOtherWritable(/\/home\/[^/\s]+\/?$/i, '사용자 홈 디렉터리가 group/other 쓰기 가능')],
    safe: [notGroupOrOtherWritable(/\/home\/[^/\s]+\/?$/i, '홈 디렉터리 권한 제한 확인')],
  },
  'SRV-162': {
    vuln: [
      { pattern: text => /pam_wheel\.so/i.test(text) && !activeLineMatches(text, /pam_wheel\.so/i) ? 'pam_wheel.so 가 주석 처리되어 su 제한 미흡' : null },
      { pattern: /trust\s+rootok|pam_rootok/i, reason: 'PAM su 에 rootok 등 인증 우회 옵션 확인' },
    ],
    safe: [{ pattern: text => activeLineMatches(text, /pam_wheel\.so/i) ? 'PAM wheel 기반 su 제한 활성' : null }],
  },
  // C-plan 갭보강 2차: 결정론적으로 판정 가능한 항목 추가
  'SRV-044': {
    vuln: [{ pattern: text => activeLineMatches(text, /\b(?:autoindex_module|userdir_module|info_module|proxy_module|dav_module)\b/i) ? '불필요/위험 Apache 모듈(autoindex/userdir/info/dav 등)이 로드됨' : null }],
    safe: [],
  },
  'SRV-045': {
    vuln: [{ pattern: /\.(?:htpasswd|htaccess~)|passwd\.txt|users?\.pwd|\.pem\b|\.key\b/i, reason: '웹 경로에 계정/자격증명 파일 노출 신호' }],
    safe: [],
  },
  'SRV-050': {
    vuln: [{ pattern: /\.(?:htr|ida|idq|printer|htw|ism|shtml)\b/i, reason: 'IIS 위험 스크립트 매핑(.htr/.ida/.idq/.printer 등) 확인' }],
    safe: [{ pattern: /PATH_NOT_FOUND|IIS not installed/i, reason: 'IIS 미설치(대상 없음)' }],
  },
  'SRV-055': {
    vuln: [{ pattern: /anonymousAuthentication[\s\S]{0,80}enabled\s*=\s*"true"/i, reason: 'IIS 익명 인증(anonymousAuthentication)이 활성' }],
    safe: [{ pattern: text => /windowsAuthentication[\s\S]{0,80}enabled\s*=\s*"true"/i.test(text) && !/anonymousAuthentication[\s\S]{0,80}enabled\s*=\s*"true"/i.test(text) ? 'Windows 인증 사용 + 익명 인증 비활성' : null }],
  },
  'SRV-058': {
    vuln: [{ pattern: /errorMode\s*=\s*"Detailed"|customErrors[\s\S]{0,60}mode\s*=\s*"Off"/i, reason: '상세 오류(Detailed)/customErrors Off 로 오류 정보 노출' }],
    safe: [{ pattern: /errorMode\s*=\s*"(?:Custom|DetailedLocalOnly)"|customErrors[\s\S]{0,60}mode\s*=\s*"(?:On|RemoteOnly)"/i, reason: '오류 상세 노출 제한 확인' }],
  },
  'SRV-072': {
    vuln: [{ pattern: /User name\s+Administrator\b|<Value>Administrator<\/Value>[\s\S]{0,300}(?:S-1-5-21-[\d-]+-500)/i, reason: '기본 관리자 계정명(Administrator) 미변경' }],
    safe: [],
  },
  'SRV-094': {
    vuln: [groupOrOtherWritable(/(?:ftp|vsftpd|proftpd)/i, 'FTP 관련 파일이 group/other 쓰기 가능')],
    safe: [],
  },
  'SRV-097': {
    vuln: [{ pattern: /(?:Everyone|Users|IUSR|Anonymous)[^\n]*(?:FullControl|Modify|Write|\(F\)|\(M\)|\(W\))/i, reason: 'FTP/IIS 사이트 경로에 과다 쓰기 권한' }],
    safe: [{ pattern: /PATH_NOT_FOUND|not installed/i, reason: '해당 서비스 미설치(대상 없음)' }],
  },

  // ── [미검증 템플릿] WAS(JEUS) SRV-215~224 : 설정파일 raw(속성텍스트) 기반 ──
  'SRV-215': { vuln: [{ pattern: text => activeLineMatches(text, /webadmin|jeusadmin/i) && !activeLineMatches(text, /allowed-server|access-control|allow-ip|<address>/i) ? '관리 콘솔 접근 IP 제한이 확인되지 않음' : null }], safe: [{ pattern: /allowed-server|access-control|allow-ip/i, reason: '관리 콘솔 접근 제한 설정 확인' }, { pattern: /미탐지|대상 없음|미설치/, reason: 'JEUS 미탐지(대상 없음)' }] },
  'SRV-216': { vuln: [{ pattern: /name\s*=\s*"?(?:administrator|jeus|admin)"?/i, reason: '기본/추측가능 관리 계정 사용' }], safe: [{ pattern: /미탐지|대상 없음/, reason: 'JEUS 계정 미정의(대상 없음)' }] },
  'SRV-217': { vuln: [{ pattern: /password\s*=\s*"?(?!\{|base64:|SHA|MD5)[^"\s]{1,}/i, reason: '패스워드 평문/비암호화 저장 신호' }], safe: [{ pattern: /password[\s\S]{0,20}(?:\{|base64:|SHA|encrypted)/i, reason: '패스워드 암호화 저장 확인' }] },
  'SRV-218': { vuln: [{ pattern: /(?:dir-listing|directory-listing|listings)[\s\S]{0,40}(?:true|on|&gt;true)/i, reason: '디렉터리 리스팅 허용' }], safe: [{ pattern: /(?:dir-listing|directory-listing|listings)[\s\S]{0,40}(?:false|off)/i, reason: '디렉터리 리스팅 비활성' }] },
  'SRV-219': { vuln: [{ pattern: text => { const m = String(text || '').match(/session-timeout[^\d-]{0,40}(-?\d{1,5})/i); if (!m) return null; const v = parseInt(m[1], 10); return (v <= 0 || v > 30) ? `session-timeout=${v} — 권장(30분 이하) 벗어남` : null; } }], safe: [{ pattern: text => { const m = String(text || '').match(/session-timeout[^\d-]{0,40}(\d{1,5})/i); if (!m) return null; const v = parseInt(m[1], 10); return (v >= 1 && v <= 30) ? `session-timeout=${v}분(양호)` : null; } }] },
  'SRV-220': { vuln: [{ pattern: /기본 오류페이지|error-page[\s\S]{0,20}(?:없|미설정)/i, reason: '커스텀 오류페이지 미설정(정보 노출 가능)' }], safe: [{ pattern: /error-page/i, reason: '커스텀 error-page 설정 확인' }] },
  'SRV-221': { vuln: [{ pattern: /server-header[\s\S]{0,30}(?:true|on)|show-server-info[\s\S]{0,20}true/i, reason: '서버/버전 헤더 노출' }], safe: [{ pattern: /server-header[\s\S]{0,30}(?:false|off)/i, reason: '서버 헤더 노출 제한 확인' }] },
  'SRV-222': { vuln: [{ pattern: text => activeLineMatches(text, /\/(?:examples|samples|console-help)\b/i) ? '샘플/예제 애플리케이션 존재' : null }], safe: [{ pattern: /샘플.*없|미탐지/, reason: '샘플 앱 미존재' }] },
  'SRV-223': { vuln: [{ pattern: /접근 로그 미|access-log[\s\S]{0,20}(?:false|off|disabled)/i, reason: '접근 로그 미기록' }], safe: [{ pattern: /access-log|AccessLog/i, reason: '접근 로그 설정 확인' }] },
  'SRV-224': {
    vuln: [{ pattern: text => { for (const l of String(text || '').split('\n')) { const t = l.trim(); if (!t || t.startsWith('$') || t.startsWith('#')) continue; const m = t.match(/^([0-7]{3,4})\s+\S+\s+\S+\s+(\S+)/); if (!m) continue; const mode = m[1].slice(-3); if ((parseInt(mode[1], 10) & 2) || (parseInt(mode[2], 10) & 2) || parseInt(mode[2], 10) & 4) return `${m[2]} 설정 파일이 group/other 접근 가능(권한 ${m[1]})`; } return null; } }],
    safe: [{ pattern: text => String(text || '').split('\n').some(l => /^[0-7]{3,4}\s+\S+\s+\S+\s+\S+/.test(l.trim())) ? '설정 파일 권한 제한 확인' : null }],
  },

  // ── [미검증 템플릿] DBMS(Oracle) SRV-250~262 : sqlplus key=value 출력 기반 ──
  'SRV-250': { vuln: [{ pattern: /(?:SYS|SYSTEM|DBSNMP|OUTLN|SCOTT|MDSYS|CTXSYS|XDB)\s*[:=|].{0,40}\bOPEN\b/i, reason: '기본계정이 OPEN 상태' }], safe: [{ pattern: text => /status=/i.test(text) && !/\bOPEN\b/i.test(text) ? '기본계정 LOCK/EXPIRED 확인' : null }] },
  'SRV-251': { vuln: [{ pattern: /PASSWORD_VERIFY_FUNCTION\s*[:=|]\s*(?:NULL|없음)/i, reason: '패스워드 복잡도 검증 함수 미적용' }], safe: [{ pattern: /PASSWORD_VERIFY_FUNCTION\s*[:=|]\s*(?!NULL)\w+/i, reason: '복잡도 검증 함수 적용 확인' }] },
  'SRV-252': { vuln: [{ pattern: /PASSWORD_(?:LIFE_TIME|REUSE_MAX)\s*[:=|]\s*UNLIMITED/i, reason: '패스워드 만료/재사용 제한 없음(UNLIMITED)' }], safe: [{ pattern: /PASSWORD_LIFE_TIME\s*[:=|]\s*\d+/i, reason: '패스워드 만료 기간 설정 확인' }] },
  'SRV-253': { vuln: [{ pattern: /FAILED_LOGIN_ATTEMPTS\s*[:=|]\s*UNLIMITED/i, reason: '로그인 실패 잠금 임계값 UNLIMITED' }], safe: [{ pattern: /FAILED_LOGIN_ATTEMPTS\s*[:=|]\s*\d+/i, reason: '로그인 실패 잠금 임계값 설정 확인' }] },
  'SRV-254': { vuln: [{ pattern: /GRANTED_ROLE\s*[:=|]\s*DBA|=\s*DBA\b/i, reason: 'DBA 롤이 부여된 계정 존재(최소화 검토 필요)' }], safe: [{ pattern: /\(0 rows\)|no rows/i, reason: '추가 DBA 롤 부여 없음' }] },
  'SRV-255': { vuln: [{ pattern: /(?:UTL_FILE|UTL_TCP|UTL_SMTP|UTL_HTTP|DBMS_SQL|DBMS_LOB)\s*[:=|].{0,30}PUBLIC/i, reason: '위험 패키지가 PUBLIC 에 EXECUTE 부여됨' }], safe: [{ pattern: /\(0 rows\)|no rows/i, reason: '위험 패키지 PUBLIC 권한 없음' }] },
  'SRV-256': { vuln: [{ pattern: /remote_os_authent\s*[:=|]\s*TRUE/i, reason: 'remote_os_authent=TRUE' }], safe: [{ pattern: /remote_os_authent\s*[:=|]\s*FALSE/i, reason: 'remote_os_authent=FALSE 확인' }] },
  'SRV-257': { vuln: [{ pattern: /O7_DICTIONARY_ACCESSIBILITY\s*[:=|]\s*TRUE/i, reason: 'O7_DICTIONARY_ACCESSIBILITY=TRUE' }], safe: [{ pattern: /O7_DICTIONARY_ACCESSIBILITY\s*[:=|]\s*FALSE/i, reason: 'O7_DICTIONARY_ACCESSIBILITY=FALSE 확인' }] },
  'SRV-258': { vuln: [{ pattern: /AUDIT_TRAIL\s*[:=|]\s*NONE/i, reason: 'AUDIT_TRAIL=NONE(감사 비활성)' }], safe: [{ pattern: /AUDIT_TRAIL\s*[:=|]\s*(?:DB|OS|XML|TRUE)/i, reason: '감사(AUDIT_TRAIL) 활성 확인' }] },
  'SRV-259': { vuln: [{ pattern: /listener.{0,40}(?:no password|미설정|unprotected)/i, reason: '리스너 보호 미설정' }], safe: [{ pattern: /listener.{0,40}(?:password|secure)/i, reason: '리스너 보호 설정 확인' }] },
  'SRV-260': { vuln: [{ pattern: /utl_file_dir\s*[:=|]\s*(?:\*|ALL)/i, reason: "utl_file_dir 가 광범위(*) 허용" }], safe: [{ pattern: /utl_file_dir\s*[:=|]\s*(?:NULL|없음|\s*$)/im, reason: 'utl_file_dir 미사용/제한 확인' }] },
  'SRV-261': { vuln: [{ pattern: /version\s*[:=|]\s*(?:8|9|10|11)\.\d/i, reason: '지원 종료 가능 Oracle 버전(11g 이하)' }], safe: [{ pattern: /version\s*[:=|]\s*(?:19|21|23)\./i, reason: '지원 유효 버전 확인' }] },
  'SRV-262': { vuln: [{ pattern: /login_audit\s*[:=|]\s*(?:none|off|미설정)/i, reason: '로그인/세션 감사 미설정' }], safe: [{ pattern: /audit.{0,20}session/i, reason: '세션 감사 설정 확인' }] },

  // ── [미검증 템플릿] DBMS(MySQL/MariaDB) SRV-270~281 : mysql key=value 출력 기반 ──
  'SRV-270': { vuln: [{ pattern: /anon(?:ymous)?_users?\s*[:=|]\s*[1-9]|User=\s*\|/i, reason: '익명 계정 존재' }], safe: [{ pattern: /anon(?:ymous)?_users?\s*[:=|]\s*0/i, reason: '익명 계정 없음' }] },
  'SRV-271': { vuln: [{ pattern: /root.{0,20}host\s*[:=|]\s*%|user=root\s*\|\s*host=%/i, reason: "root 가 host='%'로 원격 허용" }], safe: [{ pattern: /root.{0,20}host\s*[:=|]\s*(?:localhost|127\.0\.0\.1|::1)/i, reason: 'root 접속이 localhost 로 제한' }] },
  'SRV-272': { vuln: [{ pattern: /empty_password_users?\s*[:=|]\s*[1-9]|authentication_string=\s*\|/i, reason: '빈 패스워드 계정 존재' }], safe: [{ pattern: /empty_password_users?\s*[:=|]\s*0/i, reason: '빈 패스워드 계정 없음' }] },
  'SRV-273': { vuln: [{ pattern: /validate_password\S*\s*[:=|]\s*(?:OFF|미설치|NULL)/i, reason: 'validate_password 정책 미적용' }], safe: [{ pattern: /validate_password\S*\s*[:=|]\s*(?:ON|LOW|MEDIUM|STRONG|\d)/i, reason: 'validate_password 정책 적용 확인' }] },
  'SRV-274': { vuln: [{ pattern: /\btest\b\s*(?:schema|db|database)|Database:\s*test\b|test_db_exists\s*[:=|]\s*[1-9]/i, reason: '기본 test 데이터베이스 존재' }], safe: [{ pattern: /test_db_exists\s*[:=|]\s*0/i, reason: 'test DB 미존재' }] },
  'SRV-275': { vuln: [{ pattern: /secure_file_priv\s*[:=|]\s*(?:\|\s*$|NULL|없음)|FILE.{0,20}PUBLIC/im, reason: 'secure_file_priv 미설정 또는 FILE 권한 광범위' }], safe: [{ pattern: /secure_file_priv\s*[:=|]\s*\/\S+/i, reason: 'secure_file_priv 디렉터리 지정 확인' }] },
  'SRV-276': { vuln: [{ pattern: /local_infile\s*[:=|]\s*(?:ON|1)/i, reason: 'local_infile=ON' }], safe: [{ pattern: /local_infile\s*[:=|]\s*(?:OFF|0)/i, reason: 'local_infile=OFF 확인' }] },
  'SRV-277': { vuln: [{ pattern: /(?:general_log|audit_log)\s*[:=|]\s*(?:OFF|0|미설정)/i, reason: '감사/일반 로그 미설정' }], safe: [{ pattern: /(?:general_log|audit_log)\s*[:=|]\s*(?:ON|1)|audit\S*plugin/i, reason: '감사 로그 설정 확인' }] },
  'SRV-278': { vuln: [{ pattern: /require_secure_transport\s*[:=|]\s*(?:OFF|0)|have_ssl\s*[:=|]\s*(?:DISABLED|NO)/i, reason: '평문 접속 허용(TLS 미강제)' }], safe: [{ pattern: /require_secure_transport\s*[:=|]\s*(?:ON|1)/i, reason: 'TLS 강제 확인' }] },
  'SRV-279': { vuln: [{ pattern: /WITH GRANT OPTION|grant_all_users?\s*[:=|]\s*[1-9]/i, reason: '광범위 권한/GRANT OPTION 부여 계정 존재' }], safe: [{ pattern: /grant_all_users?\s*[:=|]\s*0/i, reason: '광범위 권한 부여 없음' }] },
  'SRV-280': { vuln: [{ pattern: /version\(?\)?\s*[:=|]\s*(?:5\.[0-6]|5\.7|4\.)/i, reason: '지원 종료/취약 MySQL 버전' }], safe: [{ pattern: /version\(?\)?\s*[:=|]\s*(?:8\.|10\.[4-9]|11\.)/i, reason: '지원 유효 버전 확인' }] },
  'SRV-281': { vuln: [{ pattern: /skip_grant_tables\s*[:=|]\s*(?:ON|1)/i, reason: 'skip_grant_tables 활성(권한 우회)' }], safe: [{ pattern: /skip_grant_tables\s*[:=|]\s*(?:OFF|0)/i, reason: 'skip_grant_tables 비활성 확인' }] },

  // ── WAS(Tomcat) SRV-200 ~ SRV-214 : server.xml/tomcat-users.xml/web.xml raw 증거 기반 ──
  // 주의: 파일 내용은 XML 이스케이프(&lt; &gt;)되어 있고 명령 echo("$ ...")가 섞이므로
  //       속성/키워드 문자열과 activeLineMatches(명령행 제외)로 판정한다.
  'SRV-200': {
    vuln: [{ pattern: text => {
      const hasApp = activeLineMatches(text, /webapps\/(?:manager|host-manager)\b/i);
      const hasValve = activeLineMatches(text, /Remote(?:Addr|CIDR)Valve/i);
      return hasApp && !hasValve ? 'manager/host-manager 앱이 배포되어 있으나 RemoteAddrValve/RemoteCIDRValve 접근 제한이 없음' : null;
    } }],
    safe: [
      { pattern: text => activeLineMatches(text, /Remote(?:Addr|CIDR)Valve/i) ? '관리 콘솔에 RemoteAddr/CIDR Valve 접근 제한 적용 확인' : null },
      { pattern: /관리 콘솔 부재|Tomcat 미설치/, reason: 'manager/host-manager 앱 미배포(대상 없음)' },
    ],
  },
  'SRV-201': {
    vuln: [
      { pattern: text => activeLineMatches(text, /roles?\s*=\s*"[^"]*(?:manager-gui|admin-gui|manager-script|manager-jmx)/i) ? '관리 role(manager-gui 등)이 계정에 부여됨' : null },
      { pattern: text => activeLineMatches(text, /username\s*=\s*"(?:tomcat|admin|manager|role1|both|system|test)"/i) ? '기본/추측가능 계정(tomcat/admin/manager 등)이 정의됨' : null },
    ],
    safe: [{ pattern: /관리 계정 미정의|대상 없음/, reason: '관리 계정 미정의(대상 없음)' }],
  },
  'SRV-202': {
    vuln: [{ pattern: text => {
      const hasPw = activeLineMatches(text, /password\s*=\s*"[^"]+"/i);
      const hasDigest = activeLineMatches(text, /CredentialHandler|MessageDigest|digest\s*=/i);
      return hasPw && !hasDigest ? 'tomcat-users.xml 에 패스워드가 평문으로 저장됨(자격증명 digest 미적용)' : null;
    } }],
    safe: [
      { pattern: text => activeLineMatches(text, /CredentialHandler|MessageDigest|digest\s*=/i) ? 'CredentialHandler/digest 로 패스워드 해시 저장 확인' : null },
      { pattern: /계정 미정의|대상 없음/, reason: '계정 미정의(대상 없음)' },
    ],
  },
  'SRV-203': {
    vuln: [{ pattern: /listings[\s\S]{0,200}(?:&gt;|>|value["'\s]*)\s*true/i, reason: 'DefaultServlet listings=true 로 디렉터리 목록화 허용' }],
    safe: [{ pattern: /listings[\s\S]{0,200}(?:&gt;|>|value["'\s]*)\s*false|기본값 listings=false/i, reason: 'listings=false 또는 기본값(양호)' }],
  },
  'SRV-204': {
    vuln: [{ pattern: text => {
      const m = String(text || '').match(/session-timeout[^\d-]{0,40}(-?\d{1,5})/i);
      if (!m) return null;
      const v = parseInt(m[1], 10);
      if (v <= 0) return `session-timeout=${v} — 세션 만료가 사실상 비활성`;
      if (v > 30) return `session-timeout=${v}분 — 권장(30분) 초과`;
      return null;
    } }],
    safe: [{ pattern: text => {
      const m = String(text || '').match(/session-timeout[^\d-]{0,40}(\d{1,5})/i);
      if (!m) return null;
      const v = parseInt(m[1], 10);
      return v >= 1 && v <= 30 ? `session-timeout=${v}분 — 30분 이하(양호)` : null;
    } }],
  },
  'SRV-205': {
    vuln: [{ pattern: text => {
      const valveHardened = activeLineMatches(text, /showServerInfo\s*=\s*"false"/i) && activeLineMatches(text, /showReport\s*=\s*"false"/i);
      const hasErrorPage = activeLineMatches(text, /error-page/i);
      const explicitOn = activeLineMatches(text, /show(?:ServerInfo|Report)\s*=\s*"true"/i);
      if (explicitOn) return 'ErrorReportValve showServerInfo/showReport=true 로 서버정보 노출';
      if (!valveHardened && !hasErrorPage) return '기본 오류페이지가 서버정보/스택트레이스를 노출(ErrorReportValve 미강화)';
      return null;
    } }],
    safe: [{ pattern: text => (activeLineMatches(text, /showServerInfo\s*=\s*"false"/i) || activeLineMatches(text, /error-page/i)) ? 'ErrorReportValve 강화 또는 커스텀 error-page 설정 확인' : null }],
  },
  'SRV-206': {
    vuln: [{ pattern: /기본 배너로 버전 노출/, reason: 'Connector server 속성/ServerInfo 오버라이드 없음 — 기본 배너로 버전 노출' }],
    safe: [{ pattern: text => (activeLineMatches(text, /server\s*=\s*"[^"]+"/i) || activeLineMatches(text, /ServerInfo\.properties/i)) ? 'Connector server 속성 또는 ServerInfo 오버라이드로 버전 은닉 확인' : null }],
  },
  'SRV-207': {
    vuln: [{ pattern: text => activeLineMatches(text, /webapps\/(?:examples|docs)\b/i) ? '불필요 기본 웹앱(examples/docs)이 존재' : null }],
    safe: [{ pattern: /불필요 앱 제거 상태|양호/, reason: '기본 예제/문서 웹앱 미존재(양호)' }],
  },
  'SRV-208': {
    vuln: [{ pattern: text => activeLineMatches(text, /allowTrace\s*=\s*"true"/i) ? 'Connector allowTrace=true — TRACE 메서드 허용' : null }],
    safe: [{ pattern: /allowTrace\s*=\s*"false"|기본값 allowTrace=false/i, reason: 'allowTrace=false 또는 기본값(양호)' }],
  },
  'SRV-209': {
    vuln: [{ pattern: text => {
      const hasAjp = activeLineMatches(text, /protocol\s*=\s*"AJP|:8009|"AJP\/1\.3"/i) || activeLineMatches(text, /Connector[\s\S]{0,80}8009/i);
      const hasSecret = activeLineMatches(text, /secretRequired\s*=\s*"true"|secret\s*=\s*"[^"]+"|requiredSecret/i);
      return hasAjp && !hasSecret ? 'AJP Connector 가 secret 없이 활성화됨(Ghostcat 위험)' : null;
    } }],
    safe: [
      { pattern: text => activeLineMatches(text, /secretRequired\s*=\s*"true"|secret\s*=\s*"[^"]+"/i) ? 'AJP Connector 에 secret/secretRequired 적용 확인' : null },
      { pattern: /AJP Connector 미정의|AJP 비활성/, reason: 'AJP Connector 미정의(양호)' },
    ],
  },
  'SRV-210': {
    vuln: [{ pattern: text => activeLineMatches(text, /SSLv2|SSLv3|sslEnabledProtocols\s*=\s*"[^"]*(?:SSLv|TLSv1")|sslProtocol\s*=\s*"(?:SSL|TLS)"/i) ? '취약 SSL/TLS 프로토콜(SSLv3/TLSv1 등) 허용' : null }],
    safe: [{ pattern: text => activeLineMatches(text, /sslEnabledProtocols\s*=\s*"[^"]*TLSv1\.[23]/i) ? 'TLS 1.2 이상만 허용 확인' : null }],
  },
  'SRV-211': {
    vuln: [{ pattern: /접근 로그 미기록/, reason: 'AccessLogValve 미설정 — 접근 로그 미기록' }],
    safe: [{ pattern: text => activeLineMatches(text, /AccessLogValve/i) ? 'AccessLogValve 설정 확인' : null }],
  },
  'SRV-212': {
    vuln: [{ pattern: text => {
      for (const line of String(text || '').split('\n')) {
        const t = line.trim();
        if (!t || t.startsWith('$') || t.startsWith('#')) continue;
        const m = t.match(/^([0-7]{3,4})\s+\S+\s+\S+\s+(\S+)/);
        if (!m) continue;
        const mode = m[1].slice(-3);
        const group = parseInt(mode[1], 10);
        const other = parseInt(mode[2], 10);
        const path = m[2];
        if (/tomcat-users\.xml$/i.test(path) && other !== 0) return `tomcat-users.xml 이 다른 사용자에게 접근 가능(권한 ${m[1]})`;
        if ((group & 2) || (other & 2)) return `${path} 설정 파일이 group/other 쓰기 가능(권한 ${m[1]})`;
      }
      return null;
    } },
    // Windows ACL(Get-Acl AccessToString) — 8진수가 아니므로 별도 매칭. Users/Everyone 쓰기면 취약.
    { pattern: /(?:Everyone|Users|Authenticated Users)[^\n]{0,30}Allow[^\n]{0,40}(?:FullControl|Modify|Write)/i, reason: 'Tomcat 설정 파일 ACL 에 Users/Everyone 쓰기 권한 부여' }],
    safe: [
      { pattern: text => {
        const lines = String(text || '').split('\n').map(x => x.trim()).filter(x => /^[0-7]{3,4}\s+\S+\s+\S+\s+\S+/.test(x));
        return lines.length ? 'Tomcat 설정 파일 권한이 최소 권한으로 제한됨' : null;
      } },
      { pattern: text => /Allow\s+(?:Read|FullControl)/i.test(text) && !/(?:Everyone|Users|Authenticated Users)[^\n]{0,30}Allow[^\n]{0,40}(?:FullControl|Modify|Write)/i.test(text) ? 'Tomcat 설정 파일 ACL 이 관리자/시스템 위주(양호)' : null },
    ],
  },
  'SRV-213': {
    vuln: [
      { pattern: text => activeLineMatches(text, /shutdown\s*=\s*"SHUTDOWN"/i) ? 'shutdown 명령이 기본값(SHUTDOWN)으로 유지됨' : null },
      { pattern: text => activeLineMatches(text, /Server\b[\s\S]{0,80}port\s*=\s*"8005"/i) ? 'shutdown 포트가 기본값(8005)으로 활성' : null },
    ],
    safe: [{ pattern: text => activeLineMatches(text, /Server\b[\s\S]{0,80}port\s*=\s*"-1"/i) ? 'shutdown 포트 비활성(-1) 확인' : null }],
  },
  'SRV-214': {
    vuln: [{ pattern: text => String(text || '').split('\n').some(l => /^root\s+\d+\s/.test(l.trim()) && /(?:java|catalina|Bootstrap)/i.test(l)) ? 'Tomcat 프로세스가 root 권한으로 실행됨' : null }],
    safe: [
      { pattern: text => String(text || '').split('\n').some(l => /^(?!root\b)[a-z_][a-z0-9_-]*\s+\d+\s/.test(l.trim()) && /(?:java|catalina|Bootstrap)/i.test(l)) ? '비특권 계정으로 Tomcat 실행 확인' : null },
      { pattern: /미실행|대상 없음/, reason: 'Tomcat 프로세스 미탐지(대상 없음)' },
    ],
  },

  // ── DBMS(MSSQL) SRV-230 ~ SRV-247 : SqlClient raw 출력(col=val) 기반 ──
  // 접속 실패(DB_CONNECTION_FAILED)/쿼리오류(QUERY_ERROR)는 vuln/safe 어느 것도 매칭되지 않아
  // 자연히 판정불가로 빠진다(양호 오판 방지).
  'SRV-230': {
    vuln: [{ pattern: /\bname=sa\b/i, reason: 'sa 계정명이 변경되지 않음(name=sa)' }],
    safe: [{ pattern: text => { const m = String(text || '').match(/\bname=([^\s|]+)/i); return m && m[1].toLowerCase() !== 'sa' ? `sa(sid=0x01) 계정명이 ${m[1]} 로 변경됨` : null; } }],
  },
  'SRV-231': {
    vuln: [{ pattern: /is_disabled=False/i, reason: 'sa 계정이 활성 상태(is_disabled=False)' }],
    safe: [{ pattern: /is_disabled=True/i, reason: 'sa 계정 비활성화 확인' }],
  },
  'SRV-232': {
    vuln: [{ pattern: text => {
      for (const l of String(text || '').split('\n')) {
        if (/is_policy_checked=False/i.test(l) && /is_disabled=False/i.test(l)) {
          const n = (l.match(/name=([^\s|]+)/i) || [])[1] || '?';
          return `SQL 로그인(${n})에 패스워드 정책(is_policy_checked)이 미적용`;
        }
      }
      return null;
    } }],
    safe: [{ pattern: text => /is_policy_checked=/i.test(text) && !String(text || '').split('\n').some(l => /is_policy_checked=False/i.test(l) && /is_disabled=False/i.test(l)) ? '활성 SQL 로그인에 패스워드 정책 적용 확인' : null }],
  },
  'SRV-233': {
    vuln: [{ pattern: /IntegratedSecurityOnly=0\b/i, reason: '혼합 인증 모드(SQL 인증 허용)' }],
    safe: [{ pattern: /IntegratedSecurityOnly=1\b/i, reason: 'Windows 인증 전용 확인' }],
  },
  'SRV-234': {
    vuln: [{ pattern: /member=(?:guest|public|BUILTIN\\Users|NT AUTHORITY\\Authenticated Users)\b|Everyone/i, reason: '광범위 주체(guest/public/BUILTIN\\Users 등)가 sysadmin 에 포함' }],
    safe: [{ pattern: text => /member=/i.test(text) ? 'sysadmin 구성원 확인(승인 목록과 대조 필요)' : null }],
  },
  'SRV-235': {
    vuln: [{ pattern: /perm=CONNECT|permission_name=CONNECT/i, reason: 'guest 계정에 CONNECT 권한이 부여된 DB 존재' }],
    safe: [{ pattern: /\(0 rows\)/i, reason: 'guest CONNECT 권한이 부여된 DB 없음' }],
  },
  'SRV-236': {
    vuln: [{ pattern: /permission_name=(?:CONTROL SERVER|ALTER ANY|IMPERSONATE|ADMINISTER BULK|EXTERNAL ACCESS|UNSAFE ASSEMBLY|ALTER TRACE)/i, reason: 'public 역할에 위험 권한이 부여됨' }],
    safe: [{ pattern: text => /\(0 rows\)/i.test(text) || (/state_desc=GRANT/i.test(text) && !/permission_name=(?:CONTROL SERVER|ALTER ANY|IMPERSONATE|ADMINISTER BULK|EXTERNAL ACCESS|UNSAFE ASSEMBLY|ALTER TRACE)/i.test(text)) ? 'public 역할에 위험 권한 미부여' : null }],
  },
  'SRV-237': { vuln: [{ pattern: /value_in_use=[1-9]/i, reason: 'xp_cmdshell 이 활성화됨(value_in_use=1)' }], safe: [{ pattern: /value_in_use=0\b/i, reason: 'xp_cmdshell 비활성(0) 확인' }] },
  'SRV-238': { vuln: [{ pattern: /value_in_use=[1-9]/i, reason: 'OLE Automation Procedures 활성화됨' }], safe: [{ pattern: /value_in_use=0\b/i, reason: 'OLE Automation Procedures 비활성(0) 확인' }] },
  'SRV-239': { vuln: [{ pattern: /value_in_use=[1-9]/i, reason: 'Ad Hoc Distributed Queries 활성화됨' }], safe: [{ pattern: /value_in_use=0\b/i, reason: 'Ad Hoc Distributed Queries 비활성(0) 확인' }] },
  'SRV-240': { vuln: [{ pattern: /value_in_use=[1-9]/i, reason: 'CLR 이 활성화됨' }], safe: [{ pattern: /value_in_use=0\b/i, reason: 'CLR 비활성(0) 확인' }] },
  'SRV-241': { vuln: [{ pattern: /value_in_use=[1-9]/i, reason: 'Cross DB Ownership Chaining 활성화됨' }], safe: [{ pattern: /value_in_use=0\b/i, reason: 'Cross DB Ownership Chaining 비활성(0) 확인' }] },
  'SRV-242': { vuln: [{ pattern: /value_in_use=[1-9]/i, reason: '원격 DAC(remote admin connections) 활성화됨' }], safe: [{ pattern: /value_in_use=0\b/i, reason: '원격 DAC 비활성(0) 확인' }] },
  'SRV-243': { vuln: [{ pattern: /value_in_use=[1-9]/i, reason: 'remote access(원격 저장 프로시저)가 허용됨' }], safe: [{ pattern: /value_in_use=0\b/i, reason: 'remote access 비활성(0) 확인' }] },
  'SRV-244': {
    vuln: [{ pattern: text => { const m = String(text || '').match(/AuditLevel=(-?\d+)/i); if (!m) return null; const v = parseInt(m[1], 10); return (v === 0 || v === 1) ? `로그인 실패 감사 미설정(AuditLevel=${v})` : null; } }],
    safe: [{ pattern: text => { const m = String(text || '').match(/AuditLevel=(-?\d+)/i); if (!m) return null; const v = parseInt(m[1], 10); return (v === 2 || v === 3) ? `로그인 감사 활성(AuditLevel=${v})` : null; } }],
  },
  'SRV-245': {
    vuln: [{ pattern: text => {
      const c2on = /c2 audit mode[\s\S]{0,40}value_in_use=[1-9]/i.test(text);
      const auditOn = /is_state_enabled=True/i.test(text);
      return (!c2on && !auditOn) ? 'C2 감사 비활성 + 활성 SQL Server Audit 없음' : null;
    } }],
    safe: [{ pattern: text => (/c2 audit mode[\s\S]{0,40}value_in_use=[1-9]/i.test(text) || /is_state_enabled=True/i.test(text)) ? '감사(C2 또는 SQL Server Audit) 설정 확인' : null }],
  },
  'SRV-246': {
    vuln: [{ pattern: text => { const m = String(text || '').match(/ProductVersion=(\d+)/i); if (!m) return null; const maj = parseInt(m[1], 10); return (maj > 0 && maj <= 12) ? `지원 종료(EoS) 버전(major ${maj}, SQL Server 2014 이하)` : null; } }],
    safe: [{ pattern: text => { const m = String(text || '').match(/ProductVersion=(\d+)/i); if (!m) return null; const maj = parseInt(m[1], 10); return maj >= 13 ? `지원 유효 버전(major ${maj})` : null; } }],
  },
  'SRV-247': {
    vuln: [{ pattern: text => (/is_encrypted=False/i.test(text) && !/is_encrypted=True/i.test(text)) ? 'TDE 미적용 사용자 DB 존재(민감정보 저장 시 암호화 권고)' : null }],
    safe: [{ pattern: text => (/\(0 rows\)/i.test(text) || (/is_encrypted=True/i.test(text) && !/is_encrypted=False/i.test(text))) ? 'TDE 적용 또는 사용자 DB 없음' : null }],
  },
};

const SCRIPT_DEFAULT = {
  category: CAT.system,
  title: 'Script raw 보안 점검',
  severity: '중',
  criteria: 'Script XML raw 출력에서 명확한 보안 신호만 자동 판정',
  vuln_condition: '명확한 취약 설정, 위험 서비스 실행, 과다 권한이 raw 출력에 확인됨',
  safe_condition: '점검 대상 부재 또는 기준 준수 설정이 raw 출력에 확인됨',
  recommend: DEFAULT_RECOMMEND,
  coverage: 'common_default',
  vuln: [
    { pattern: /^[^#\n]*PermitRootLogin\s+yes/im, reason: 'sshd_config PermitRootLogin yes 설정 확인' },
    {
      pattern: text => activeLineMatches(text, /^PASS_MAX_DAYS\s+(?:99999|9[1-9]|[1-9][0-9]{2,})\b/i)
        ? 'PASS_MAX_DAYS가 90일을 초과하거나 만료 없음으로 설정됨'
        : null,
    },
    {
      pattern: text => activeLineMatches(text, /^PASS_MIN_LEN\s+[0-7]\b/i)
        ? 'PASS_MIN_LEN이 8 미만으로 설정됨'
        : null,
    },
    {
      pattern: text => activeLineMatches(text, /^(?:TMOUT|TIMEOUT)\s*=\s*0\b/i)
        ? '유휴 세션 타임아웃 값이 0으로 설정됨'
        : null,
    },
    {
      pattern: text => hasListeningService(text, ['telnet', 'rsh', 'rlogin', 'rexec', 'TlntSvr'])
        ? 'Telnet/r-command 계열 서비스 실행 신호 확인'
        : null,
    },
    { pattern: /anonymous_enable\s*=\s*YES/i, reason: 'FTP anonymous_enable=YES 설정 확인' },
    dwordEquals('EnableFirewall', 0, 'Windows 방화벽 비활성화 확인'),
    dwordLessThan('MinimumPasswordLength', 8, 'Windows 최소 암호 길이 8 미만'),
    dwordEquals('LockoutBadCount', 0, '계정 잠금 임계값 0 확인'),
    dwordEquals('DontDisplayLastUserName', 0, '마지막 로그온 사용자 표시 활성'),
    dwordEquals('RestrictAnonymous', 0, '익명 열거 제한 미흡'),
    { pattern: /RemoteRegistry[\s\S]{0,160}(?:RUNNING|STATE\s*:\s*4|Auto|Automatic)/i, reason: 'RemoteRegistry 서비스 실행/자동 시작 확인' },
  ],
  safe: [
    { pattern: /^[^#\n]*PermitRootLogin\s+no/im, reason: 'sshd_config PermitRootLogin no 설정 확인' },
    {
      pattern: text => {
        const maxOK = activeLineMatches(text, /^PASS_MAX_DAYS\s+([1-9]|[1-8][0-9]|90)\b/i);
        const lenOK = activeLineMatches(text, /^PASS_MIN_LEN\s+([8-9]|[1-9][0-9]+)\b/i);
        return maxOK && lenOK ? 'PASS_MAX_DAYS 90 이하, PASS_MIN_LEN 8 이상 확인' : null;
      },
    },
    {
      pattern: text => activeLineMatches(text, /^(?:TMOUT|TIMEOUT)\s*=\s*(?:[1-9][0-9]{1,3})\b/i)
        ? '유휴 세션 타임아웃 값 설정 확인'
        : null,
    },
    { pattern: /anonymous_enable\s*=\s*NO/i, reason: 'FTP anonymous_enable=NO 설정 확인' },
    dwordEquals('EnableFirewall', 1, 'Windows 방화벽 활성화 확인'),
    dwordAtLeast('MinimumPasswordLength', 8, 'Windows 최소 암호 길이 8 이상'),
    dwordAtLeast('LockoutBadCount', 1, '계정 잠금 임계값 설정 확인'),
    dwordEquals('DontDisplayLastUserName', 1, '마지막 로그온 사용자 표시 비활성'),
    dwordAtLeast('RestrictAnonymous', 1, '익명 열거 제한 적용'),
    { pattern: /RemoteRegistry[\s\S]{0,160}(?:STOPPED|STATE\s*:\s*1|Disabled|사용 안 함)/i, reason: 'RemoteRegistry 서비스 중지/비활성화 확인' },
  ],
};

// ── v2 수집기 대응 룰 병합 (2026-07-03 2차) ─────────────────────────────
// 기존 엔트리를 문자열 수정 없이 프로그램적으로 보강한다. add()는 기존 룰 뒤에 추가.
(function attachV2Rules() {
  const add = (id, side, rules) => {
    const e = SRV_RULES[id] = SRV_RULES[id] || { vuln: [], safe: [] };
    e[side] = [...(e[side] || []), ...rules];
  };

  // secedit 권한 할당: 허용 SID 로만 구성되면 양호
  add('SRV-113', 'safe', [privilegeRestrictedTo('SeSecurityPrivilege', ['S-1-5-32-544'], '감사 권한(SeSecurityPrivilege)이 Administrators로만 제한')]);
  add('SRV-156', 'safe', [privilegeRestrictedTo('SeRemoteInteractiveLogonRight', ['S-1-5-32-544', 'S-1-5-32-555'], '원격 로그온 권한이 Administrators/Remote Desktop Users로 제한')]);
  add('SRV-138', 'safe', [
    privilegeRestrictedTo('SeBackupPrivilege', ['S-1-5-32-544', 'S-1-5-32-551'], '백업 권한이 Administrators/Backup Operators로 제한'),
    privilegeRestrictedTo('SeRestorePrivilege', ['S-1-5-32-544', 'S-1-5-32-551'], '복원 권한이 Administrators/Backup Operators로 제한'),
  ]);
  add('SRV-139', 'safe', [privilegeRestrictedTo('SeTakeOwnershipPrivilege', ['S-1-5-32-544'], '소유권 가져오기 권한이 Administrators로만 제한')]);

  // 기본 관리자 계정명 (한글 net user 출력)
  add('SRV-072', 'vuln', [{ pattern: /^사용자 이름\s+Administrator\s*$/im, reason: '기본 관리자 계정명(Administrator) 미변경' }]);

  // 자동 로그온: AutoAdminLogon 테이블이 비어있으면 미설정=양호
  add('SRV-124', 'safe', [{ pattern: text => regTableAllEmpty(text, ['AutoAdminLogon', 'DefaultUserName'])
    ? 'AutoAdminLogon 미설정 — 자동 로그온 없음' : null }]);

  // secedit 평문 저장 (Windows)
  add('SRV-070', 'vuln', [dwordEquals('ClearTextPassword', 1, '암호를 해독 가능한 평문으로 저장(ClearTextPassword=1)')]);
  add('SRV-070', 'safe', [dwordEquals('ClearTextPassword', 0, '평문 암호 저장 비활성(ClearTextPassword=0) 확인')]);

  // 방화벽 프로파일 (한글 netsh)
  add('SRV-027', 'vuln', [{ pattern: /^(?:상태|State)\s+(?:사용 안 함|OFF)\s*$/im, reason: '방화벽 프로파일 중 비활성(사용 안 함/OFF) 존재' }]);
  add('SRV-027', 'safe', [{ pattern: text => {
    const states = String(text || '').match(/^(?:상태|State)\s+\S[^\n]*$/gim) || [];
    return states.length && states.every(s => !/사용 안 함|OFF/i.test(s)) ? '모든 방화벽 프로파일 활성(사용/ON)' : null;
  } }]);

  // Windows cacls(AccessToString) ACL — 파일권한 계열 항목에 병합
  for (const [id, label] of [
    ['SRV-082', '시스템 디렉터리'], ['SRV-084', '시스템 계정 파일(SAM/SYSTEM)'], ['SRV-092', '사용자 홈/중요 파일'],
    ['SRV-098', 'SAM 파일'], ['SRV-102', '사용자 프로필'], ['SRV-110', 'system32/config'],
  ]) {
    const acl = winAclRules(label);
    add(id, 'vuln', acl.vuln);
    add(id, 'safe', acl.safe);
  }

  // PATH 판정 (에코된 PATH 라인 기반, 양호 측 포함)
  SRV_RULES['SRV-121'] = {
    vuln: [{ pattern: text => {
      const line = String(text || '').split('\n').map(l => l.trim()).find(l => /^\/[\w./-]*(?::[\w./-]*)+$/.test(l));
      if (!line) return null;
      return /(?:^|:)\.(?::|$)|::|(?:^|:)\/tmp(?::|$)|(?:^|:)\/var\/tmp(?::|$)/.test(line)
        ? 'PATH에 현재 디렉터리(.)/빈 항목/임시 디렉터리 포함: ' + line : null;
    } }],
    safe: [{ pattern: text => {
      const line = String(text || '').split('\n').map(l => l.trim()).find(l => /^\/[\w./-]*(?::[\w./-]*)+$/.test(l));
      if (!line) return null;
      return /(?:^|:)\.(?::|$)|::|(?:^|:)\/tmp(?::|$)|(?:^|:)\/var\/tmp(?::|$)/.test(line)
        ? null : 'PATH에 현재 디렉터리(.)/빈 항목 없음 — 안전한 PATH 구성';
    } }],
  };

  // awk passwd 2필드(x) 출력: 전 계정 shadow 사용 → 빈/평문 없음
  add('SRV-077', 'safe', [{ pattern: text => {
    const rows = String(text || '').split('\n').map(l => l.trim().match(/^([\w.-]+)\s+(\S+)$/)).filter(Boolean);
    return rows.length >= 5 && rows.every(r => r[2] === 'x' || r[2] === '*')
      ? '모든 계정이 shadow 패스워드(x) 사용 — 빈/평문 패스워드 없음' : null;
  } }]);

  // rsyslog 실행 + authpriv 정책 → 로그 정책 양호
  add('SRV-109', 'safe', [{ pattern: text => /rsyslogd/.test(String(text || '')) && activeLineMatches(text, /^authpriv\./i)
    ? 'rsyslog 데몬 실행 및 authpriv 로그 정책 설정 확인' : null }]);

  // SSH 세션 타임아웃 (Linux — SRV-028 raw가 ClientAlive 계열)
  add('SRV-028', 'vuln', [{ pattern: text => {
    const t = String(text || '');
    if (!/ClientAliveInterval/i.test(t)) return null;
    const active = activeLineMatches(t, /^ClientAliveInterval\s+[1-9]\d*/i);
    return !active ? 'SSH 세션 타임아웃 미설정(ClientAliveInterval 주석 처리 또는 0)' : null;
  } }]);
  add('SRV-028', 'safe', [{ pattern: text => activeLineMatches(text, /^ClientAliveInterval\s+[1-9]\d*/i)
    ? 'SSH ClientAliveInterval 설정 확인' : null }]);

  // TMOUT 미설정 (profile 수집됐는데 TMOUT 값 없음)
  add('SRV-159', 'vuln', [{ pattern: text => {
    const t = String(text || '');
    return /\[ Common \/etc\/profile Setting \]/.test(t)
      && !/TMOUT\s*=?\s*[1-9]/i.test(t)
      && !activeLineMatches(t, /^ClientAliveInterval\s+[1-9]/i)
      ? '유휴 세션 타임아웃(TMOUT) 미설정' : null;
  } }]);

  // rpcbind 단독 실행 = NFS/RPC 표준 용도 (힌트: rpcbind 만으로 취약 금지)
  add('SRV-034', 'safe', [{ pattern: text => {
    const t = String(text || '');
    return /\/sbin\/rpcbind|rpcbind\s+-w/.test(t) && !/automountd|rpc\.cmsd|ttdbserver|sadmind|rusersd|rstatd/i.test(t)
      ? 'rpcbind 단독 실행(NFS/RPC 표준 용도) — 불필요 레거시 RPC 서비스 없음' : null;
  } }]);

  // FTP: sftp-server(SSH 기반)만 운용 시 양호
  SRV_RULES['SRV-037'] = {
    vuln: [...FTP_RULES.vuln],
    safe: [
      ...FTP_RULES.safe,
      { pattern: text => /sftp-server/.test(String(text || '')) && !/vsftpd|proftpd|pure-ftpd/i.test(String(text || '')) && !hasListeningPort(text, ['21'])
        ? 'SFTP(SSH 기반)만 운용 — 취약 FTP 서비스 없음' : null },
    ],
  };

  // SMTP loopback 전용 → 외부 노출 없음 (재적용)
  add('SRV-008', 'safe', [{ pattern: text => hasInternalOnlyPort(text, ['25']) ? 'SMTP 25/tcp가 loopback/내부 대역에만 바인딩 — 외부 노출 없음' : null }]);

  // r-command 계열: 수집기 마커 전부 not_detected + 전체허용(+) 없음 → 양호
  add('SRV-025', 'safe', [{ pattern: text => {
    const marks = [...String(text || '').matchAll(/SERVICE_PRESENCE=(detected|not_detected)/g)].map(m => m[1]);
    return marks.length >= 2 && marks.every(v => v === 'not_detected') && !/^\s*\+\s*$/m.test(String(text || ''))
      ? 'r-command 계열 서비스 미검출(수집기 확인) 및 전체허용(+) 신뢰 설정 없음' : null;
  } }]);

  // netstat 수집됐고 23/tcp 없음 → Telnet 미노출
  SRV_RULES['SRV-158'] = {
    vuln: [...TELNET_RULES.vuln],
    safe: [
      ...TELNET_RULES.safe,
      { pattern: text => /LISTENING|LISTEN/.test(String(text || '')) && listeningPortAddresses(text, ['23']).length === 0
        ? '네트워크 LISTEN 목록에 23/tcp(Telnet) 없음' : null },
    ],
  };

  // schtasks 한글 출력: 작업 이름과 상태가 다른 줄 — 줄 경계를 넘어 매칭
  SRV_RULES['SRV-101'] = {
    vuln: [{ pattern: text => {
      const m = String(text || '').match(/(Microsoft Compatibility Appraiser|Customer Experience Improvement|ProgramDataUpdater|appuriverifier\w*)[\s\S]{0,160}?(?:상태|Status)\s*:?\s*(Ready|Running|준비|실행)/i);
      return m ? '불필요 기본 예약 작업 활성: ' + m[1] : null;
    } }],
    safe: [{ pattern: text => {
      const t = String(text || '');
      return /작업 이름|TaskName|폴더:/.test(t)
        && !/(Microsoft Compatibility Appraiser|Customer Experience Improvement|ProgramDataUpdater|appuriverifier)[\s\S]{0,160}?(?:상태|Status)\s*:?\s*(Ready|Running|준비|실행)/i.test(t)
        ? '예약 작업 목록 수집 — 불필요 기본 텔레메트리 작업 활성 없음' : null;
    } }],
  };

  // 중복 UID (awk name:uid 형식) — 취약/양호 양측
  add('SRV-143', 'vuln', [{ pattern: text => {
    const seen = new Map();
    for (const l of String(text || '').split('\n')) {
      const m = l.trim().match(/^([\w.-]+):(\d+)$/);
      if (!m) continue;
      if (seen.has(m[2])) return '중복 UID ' + m[2] + ' (' + seen.get(m[2]) + ', ' + m[1] + ')';
      seen.set(m[2], m[1]);
    }
    return null;
  } }]);
  add('SRV-143', 'safe', [{ pattern: text => {
    const seen = new Set();
    let n = 0;
    for (const l of String(text || '').split('\n')) {
      const m = l.trim().match(/^([\w.-]+):(\d+)$/);
      if (!m) continue;
      n++;
      if (seen.has(m[2])) return null;
      seen.add(m[2]);
    }
    return n >= 5 ? '중복 UID 없음' : null;
  } }]);

  // 중복 GID 없음 → 양호 (기존 룰은 취약 측만 있음)
  add('SRV-164', 'safe', [{ pattern: text => {
    const seen = new Set();
    let n = 0;
    for (const l of String(text || '').split('\n')) {
      const p = l.trim().split(':');
      if (p.length < 3 || !/^\d+$/.test(p[2])) continue;
      n++;
      if (seen.has(p[2])) return null;
      seen.add(p[2]);
    }
    return n >= 5 ? '중복 GID 없음' : null;
  } }]);

  // 시스템 계정 쉘 제한 확인 → 양호 (기존 룰은 취약 측만 있음)
  const sysAccountShellSafe = { pattern: text => {
    const rows = [...String(text || '').matchAll(/^(daemon|bin|sys|adm|listen|nobody\d*|noaccess|diag|operator|games|gopher|ftp|lp|mail|uucp)(?::[^:\n]*){5}:([^:\n]+)$/gim)];
    return rows.length >= 2 && rows.every(r => /nologin|\/bin\/false|\/sbin\/(?:shutdown|halt)|\/bin\/sync/.test(r[2]))
      ? '시스템 계정 로그인 쉘 제한(nologin/false) 확인' : null;
  } };
  add('SRV-165', 'safe', [sysAccountShellSafe]);
  add('SRV-145', 'safe', [sysAccountShellSafe]);

  // Windows UAC (PS 테이블: EnableLUA / ConsentPromptBehaviorAdmin / FilterAdministratorToken)
  add('SRV-177', 'vuln', [{ pattern: text => regDwordValue(text, 'EnableLUA') === 0 ? 'UAC 비활성(EnableLUA=0)' : null }]);
  add('SRV-177', 'safe', [{ pattern: text => regDwordValue(text, 'EnableLUA') === 1 ? 'UAC 활성(EnableLUA=1)' : null }]);

  // Linux sudoers: user-spec 이 root/%wheel 뿐이면 양호
  add('SRV-177', 'safe', [{ pattern: text => {
    const t = String(text || '');
    if (!/^Defaults/m.test(t)) return null;
    const specs = t.split('\n').map(l => l.trim())
      .filter(l => l && !l.startsWith('#') && !/^Defaults/.test(l) && /\bALL\s*=\s*\(/.test(l));
    return specs.length && specs.every(l => /^(?:root|%wheel)\b/.test(l))
      ? 'sudo 권한이 root/%wheel 로만 제한 — 일반 계정 부여 없음' : null;
  } }]);

  // 이벤트 로그 Guest 제한 (PS 테이블 다중 행)
  add('SRV-108', 'vuln', [{ pattern: /^\s*(?:Application|Security|System)\s+0\s*$/im, reason: '이벤트 로그 Guest 접근 제한 미설정(RestrictGuestAccess=0)' }]);
  add('SRV-108', 'safe', [{ pattern: text => {
    const rows = [...String(text || '').matchAll(/^\s*(Application|Security|System)\s+(\d)\s*$/gim)];
    return rows.length >= 3 && rows.every(r => r[2] === '1') ? '모든 이벤트 로그 RestrictGuestAccess=1' : null;
  } }]);

  // SCHANNEL: SSL 2.0/3.0 이 DisabledByDefault=1 이고 Enabled=1 이 없으면 양호
  add('SRV-056', 'safe', [{ pattern: text => {
    const t = String(text || '');
    return /SSL [23]\.0[\s\S]{0,200}?DisabledByDefault\s+REG_DWORD\s+0x1/i.test(t)
      && !/SSL [23]\.0[\s\S]{0,200}?\bEnabled\s+REG_DWORD\s+0x1/i.test(t)
      ? 'SSL 2.0/3.0 기본 비활성(DisabledByDefault=1) 확인' : null;
  } }]);

  // AllocateDASD 미설정 = 기본값(이동식 미디어 할당 관리자 전용) → 양호
  add('SRV-140', 'safe', [{ pattern: text => /AllocateDASD/i.test(text) && /Not Found \/ No Data/i.test(text)
    ? 'AllocateDASD 미설정 — 기본값(관리자 전용 할당)으로 동작' : null }]);

  // cron allow/deny 경로: /etc/cron.allow 도 커버 (기존 룰은 /etc/cron.d/ 만)
  SRV_RULES['SRV-132'] = {
    vuln: [groupOrOtherWritable(/\/etc\/(?:cron\.d\/)?cron\.(?:allow|deny)/i, 'cron allow/deny 파일이 group/other 쓰기 가능')],
    safe: [notGroupOrOtherWritable(/\/etc\/(?:cron\.d\/)?cron\.(?:allow|deny)/i, 'cron allow/deny 파일 쓰기 권한 제한 확인')],
  };

  // cron.allow 부재 + cron.deny 내용 없음 = 모든 사용자 crontab 허용
  add('SRV-133', 'vuln', [{ pattern: text => {
    const t = String(text || '');
    const allowAbsent = /cron\.allow: (?:No such file|그런 파일)/.test(t);
    const denyEmpty = /\$ cat \/etc\/cron\.deny\s*\n\s*(?:-{3,}|RAW_COMMAND_OUTPUT_END|$)/.test(t);
    return allowAbsent && denyEmpty ? 'cron.allow 부재 + cron.deny 비어있음 — 모든 사용자 crontab 사용 가능' : null;
  } }]);

  // ── 수집 스크립트 보강(2026-07-03) 대응 룰 — 새 형식은 재배포된 스크립트의 raw에서만 나타남 ──
  // SRV-027: 수집기가 명시한 방화벽 상태. firewalld 활성이면 접근 제어 동작 → 양호.
  // iptables INPUT ACCEPT 는 firewalld 활성 시 자체 체인을 쓰므로 취약 근거에서 제외.
  SRV_RULES['SRV-027'].vuln = (SRV_RULES['SRV-027'].vuln || []).filter(r =>
    !(r.pattern instanceof RegExp && r.pattern.source.indexOf('INPUT') !== -1));
  add('SRV-027', 'vuln', [{ pattern: text => {
    const t = String(text || '');
    return /-P\s+INPUT\s+ACCEPT/i.test(t) && /FIREWALLD_STATE=(?:inactive|unknown|failed)/.test(t)
      ? 'iptables INPUT 기본 허용(ACCEPT) + firewalld 비활성 — 네트워크 접근 제어 부재' : null;
  } }]);
  add('SRV-027', 'safe', [{ pattern: /FIREWALLD_STATE=active/, reason: '호스트 방화벽(firewalld) 활성 — 네트워크 접근 제어 동작 중' }]);

  // SRV-074(Linux): shadow lastchg(epoch days)와 수집 시점 비교 — 장기(90일 초과) 미변경
  add('SRV-074', 'vuln', [{ pattern: text => {
    const t = String(text || '');
    const sd = (t.match(/scan_epoch_days=(\d+)/) || [])[1];
    if (!sd) return null;
    for (const m of t.matchAll(/^([\w.-]+)\t(\d+)\tSET$/gm)) {
      const age = +sd - +m[2];
      if (age > 90) return '계정(' + m[1] + ') 비밀번호 ' + age + '일 미변경(기준 90일 초과)';
    }
    return null;
  } }]);
  add('SRV-074', 'safe', [{ pattern: text => {
    const t = String(text || '');
    const sd = (t.match(/scan_epoch_days=(\d+)/) || [])[1];
    if (!sd) return null;
    const rows = [...t.matchAll(/^([\w.-]+)\t(\d+)\tSET$/gm)];
    return rows.length && rows.every(m => +sd - +m[2] <= 90)
      ? '패스워드 설정 계정 모두 90일 이내 변경' : null;
  } }]);

  // SRV-160: 로그인 이력이 전혀 없는 로그인쉘 계정 존재 (lastlog)
  add('SRV-160', 'vuln', [{ pattern: text => {
    const m = String(text || '').match(/lastlog -u (\S+)[\s\S]{0,200}?(?:한\s*번도 로그인한 적이 없|Never logged in)/i);
    return m ? '로그인 이력 없는 로그인쉘 계정 존재: ' + m[1] + ' (장기 미사용 계정 정리 대상)' : null;
  } }]);
  add('SRV-160', 'safe', [{ pattern: text => {
    const t = String(text || '');
    const users = [...t.matchAll(/lastlog -u (\S+)/g)];
    return users.length && !/한\s*번도 로그인한 적이 없|Never logged in/i.test(t)
      ? '모든 로그인쉘 계정에 로그인 이력 존재' : null;
  } }]);

  // SRV-002/063(Windows): 서비스 게이트 결과 메시지 판정
  add('SRV-002', 'vuln', [{ pattern: /PermittedManagers 미설정 -> 허용 관리자 제한 없음/, reason: 'SNMP 실행 중이나 허용 관리자(PermittedManagers) 제한 없음' }]);
  add('SRV-063', 'vuln', [{ pattern: /NoRecursion 미설정 -> 기본값: 재귀 질의 허용/, reason: 'Windows DNS 재귀 질의 제한 미설정(기본값 허용)' }]);

  // ═══ 3-way 정합성 정렬 (2026-07-03: OS_Detail(SecuMS) × Mock × LLM 비교 기반) ═══
  // 원칙: SecuMS와 LLM이 일치하는데 mock만 다른 항목(2:1)을 다수 판정 방향으로 수정.

  // SRV-020: bare 'F|C' 대안이 /i 플래그로 'ReadAndExecute'의 c에도 매칭되던 과탐 제거
  SRV_RULES['SRV-020'] = {
    vuln: [{ pattern: /\b(?:Everyone|ANONYMOUS LOGON)\b[^\n]*(?:FullControl|Modify|Write|CHANGE|FULL|\(F\)|\(C\))/i, reason: '공유 폴더에 광범위한 쓰기/전체 권한 확인' }],
    safe: [{ pattern: text => /AccessToString|공유 이름|Share name/i.test(String(text || ''))
      && !/\b(?:Everyone|ANONYMOUS LOGON)\b[^\n]*(?:FullControl|Modify|Write|CHANGE|FULL|\(F\)|\(C\))/i.test(String(text || ''))
      ? '공유 접근 권한에 Everyone/익명 쓰기성 권한 없음' : null }],
  };

  // SRV-080: 방향 반전 — AddPrinterDrivers=1 은 "관리자만 설치 가능"(제한 적용) = 양호
  SRV_RULES['SRV-080'] = {
    vuln: [dwordEquals('AddPrinterDrivers', 0, '일반 사용자 프린터 드라이버 설치 허용(AddPrinterDrivers=0)')],
    safe: [dwordEquals('AddPrinterDrivers', 1, '프린터 드라이버 설치가 관리자로 제한(AddPrinterDrivers=1)')],
  };

  // SRV-116: 방향 반전 — "감사 불가 시 즉시 종료" 기능은 비활성화(0)가 양호 (가용성 보호)
  SRV_RULES['SRV-116'] = {
    vuln: [dwordEquals('CrashOnAuditFail', 1, '감사 실패 시 시스템 즉시 종료 활성(CrashOnAuditFail=1) — 가용성 위험')],
    safe: [dwordEquals('CrashOnAuditFail', 0, '감사 실패 시 즉시 종료 비활성(CrashOnAuditFail=0)')],
  };

  // SRV-151: 전용 룰 — SCRIPT_DEFAULT의 RestrictAnonymous 폴백 과탐 차단
  SRV_RULES['SRV-151'] = {
    vuln: [dwordEquals('LSAAnonymousNameLookup', 1, '익명 SID/이름 변환 허용(LSAAnonymousNameLookup=1)')],
    safe: [dwordEquals('LSAAnonymousNameLookup', 0, '익명 SID/이름 변환 제한(LSAAnonymousNameLookup=0)')],
  };

  // SRV-018 은 base SRV_RULES 에서 net share 기준으로 재정의됨 (여기서 중복 추가 안 함)

  // SRV-125: 화면보호기 — Active=1이어도 TimeOut/Secure가 비어있으면 미완성 설정 = 취약
  add('SRV-125', 'vuln', [{ pattern: text => {
    const t = String(text || '');
    if (!/ScreenSaveActive/i.test(t)) return null;
    const active = psTableCell(t, 'ScreenSaveActive') || (t.match(/ScreenSaveActive\s*[:=]?\s*(\d)/i) || [])[1];
    const timeout = psTableCell(t, 'ScreenSaveTimeOut');
    const secure = psTableCell(t, 'ScreenSaverIsSecure');
    return (timeout === null || secure === null)
      ? '화면보호기 설정 미완성 — TimeOut/Secure ' + (active === '1' ? '(Active=1이나 잠금·대기시간 미설정)' : '미설정') : null;
  } }]);

  // SRV-140: 방향 반전 — AllocateDASD 미설정 = 정책 미적용 = 취약 (SecuMS·LLM 일치)
  SRV_RULES['SRV-140'].safe = (SRV_RULES['SRV-140'].safe || []).filter(r => typeof r.pattern !== 'function'
    || !String(r.pattern).includes('AllocateDASD'));
  add('SRV-140', 'vuln', [{ pattern: text => /AllocateDASD/i.test(text) && /Not Found \/ No Data/i.test(text)
    ? '이동식 미디어 할당 정책(AllocateDASD) 미설정' : null }]);

  // SRV-129/119: 백신 프로세스 탐지 (tasklist) — SecuMS와 동일하게 3rd-party 백신 기준
  const AV_PROC = /\b(?:V3Svc|V3Lite|V3 ?Pro|AYAgent|AYServiceNT|ViRobot|hvrtray|HAURI|ccSvcHst|Smc|SepMasterService|mcshield|masvc|avp|TmListen|NTRTscan|ekrn|SavService|bdagent)\b/i;
  add('SRV-129', 'vuln', [{ pattern: text => {
    const t = String(text || '');
    return /ProcessName|tasklist/i.test(t) && !AV_PROC.test(t)
      ? '백신 프로그램 프로세스 미검출(V3/알약/ViRobot/Symantec/McAfee 등) — 백신 미설치' : null;
  } }]);
  add('SRV-129', 'safe', [{ pattern: text => AV_PROC.test(String(text || '')) ? '백신 프로그램 프로세스 실행 확인' : null }]);
  add('SRV-119', 'vuln', [{ pattern: text => {
    const t = String(text || '');
    return /ProcessName|tasklist|v3update|Anti-?Virus/i.test(t) && !AV_PROC.test(t)
      ? '백신 프로그램 미설치/미실행 — 업데이트 적용 불가 상태' : null;
  } }]);

  // SRV-166: 숨김 파일/디렉터리 존재 → 취약 (SecuMS 기준 — 목록 존재 자체가 BAD, 저위험 점수)
  add('SRV-166', 'vuln', [{ pattern: text => {
    const m = String(text || '').match(/\$Recycle\.Bin|\$WINDOWS\.~BT|Documents and Settings|<DIR>\s+\$/i);
    return m ? '숨김 파일/디렉터리 존재 확인(' + m[0] + ' 등) — 불필요 여부 검토 대상' : null;
  } }]);

  // SRV-135: TCP/IP 보안 옵션(SynAttackProtect 등)이 모두 빈 값 = 최신 OS에서 폐기된 옵션 → 양호 (SecuMS OK 정렬)
  add('SRV-135', 'safe', [{ pattern: text => {
    const t = String(text || '');
    if (!/SynAttackProtect/i.test(t)) return null;
    const syn = (t.match(/SynAttackProtect\s*:\s*(\S*)$/im) || [])[1];
    return !syn ? 'TCP/IP 보안 레지스트리 미설정 — 해당 옵션은 Windows 2008+ 에서 폐기(기본 보호 내장)' : null;
  } }]);

  // SRV-147(Windows): SNMP 미설치 + WMI(winmgmt) 표준 실행 → 불필요 모니터링 서비스 없음 = 양호
  add('SRV-147', 'safe', [{ pattern: text => {
    const t = String(text || '');
    return /OpenService 실패 1060|지정된 서비스가 설치된 서비스로는 없습니다/.test(t) && /winmgmt[\s\S]{0,200}RUNNING/i.test(t)
      ? 'SNMP 미설치, WMI(winmgmt)는 OS 표준 서비스 — 불필요 모니터링 서비스 없음' : null;
  } }]);

  // SRV-082: SecuMS 기준 — 시스템 주요 디렉터리(LogFiles 등)에 Users/APPLICATION PACKAGES 항목 존재 자체가 취약
  add('SRV-082', 'vuln', [{ pattern: text => {
    const m = String(text || '').match(/(LogFiles|system32)[\s\S]{0,500}?(BUILTIN\\Users|APPLICATION PACKAGE)[^\n]*Allow/i);
    return m ? '시스템 디렉터리(' + m[1] + ')에 ' + m[2] + ' 접근 권한 존재 — 불필요 권한' : null;
  } }]);

  // SRV-010: postfix 큐 명령 권한 — group/other 실행 가능(0755 등)이면 취약 (SecuMS 기준)
  add('SRV-010', 'vuln', [{ pattern: text => {
    for (const raw of String(text || '').split('\n')) {
      const l = raw.trim();
      if (!/\/(?:postsuper|postdrop|postqueue|mailq)\b/.test(l)) continue;
      const mode = l.slice(0, 10);
      if (/^[-][rwxStTs-]{9}/.test(l) && (mode[9] === 'x' || mode[6] === 'x' && mode[9] !== '-')) {
        return '메일 큐 처리 명령이 일반 사용자 실행 가능(' + l.split(/\s+/).pop() + ' ' + mode + ')';
      }
    }
    return null;
  } }]);

  // SRV-007: 배너 버전 노출 — loopback 전용이면 외부 노출 없음(과탐 방지 (라)).
  // 노출 판정은 실제 LISTEN 증거가 있을 때만 (netstat 미수집 raw에서 설정 문구만으로 취약 금지)
  SRV_RULES['SRV-007'] = {
    vuln: [{ pattern: text => activeLineMatches(text, /\b(?:Sendmail|ESMTP|SMTP)\b[^\n]*(?:version|[0-9]+\.[0-9]+)/i)
      && hasListeningPort(text, ['25']) && !hasInternalOnlyPort(text, ['25'])
      ? 'SMTP 배너 또는 설정에 버전 정보가 노출됨(외부 LISTEN)' : null }],
    safe: [{ pattern: text => hasInternalOnlyPort(text, ['25']) ? 'SMTP 25/tcp가 loopback/내부 대역에만 바인딩 — 배너 외부 노출 없음' : null }],
  };

  // SRV-014: bare 'rw' 과탐 제거 — /etc/exports 형식 라인 안의 rw 옵션만 취약
  SRV_RULES['SRV-014'] = {
    vuln: [
      { pattern: /^[^#\n]*\s(?:\*|\d{1,3}(?:\.\d{1,3}){0,3}\/0)\s*\(/im, reason: 'NFS export가 광범위한 대상으로 공개됨' },
      { pattern: /^\/\S+[^\n]*\([^)]*\bno_root_squash\b[^)]*\)/im, reason: 'NFS no_root_squash 옵션 확인' },
      { pattern: /^\/\S+[^\n]*\([^)]*\brw\b[^)]*\)/im, reason: 'NFS 공유에 쓰기 권한(rw) 옵션 확인' },
    ],
    safe: [],
  };

  // SRV-026: PermitRootLogin 미설정은 "명시적 차단 없음" = 취약 (SecuMS 기준 — 기본값 의존 금지)
  add('SRV-026', 'vuln', [{ pattern: /PermitRootLogin (?:활성 설정|명시 설정) 없음|PermitRootLogin not exist|PermitRootLogin 미설정/, reason: 'sshd_config에 PermitRootLogin 명시 설정 없음 — root 원격 접속 차단 미적용' }]);

  // SRV-093/095/144: find 계열 — 명령은 실행됐고 발견 라인이 없으면 양호 (SecuMS·LLM 일치 방향)
  const noFindingSafe = reason => ({ pattern: text => {
    const lines = String(text || '').split('\n').map(x => x.trim()).filter(Boolean);
    const hasCmd = lines.some(l => /^(\$|cmd#)\s+/.test(l));
    if (!hasCmd) return null;
    const findings = lines.filter(line =>
      !/^(\$|cmd#|#)\s+/.test(line) && !/^[-=]{3,}$/.test(line) && !/^<\?xml|^<\/?[A-Za-z]/.test(line) &&
      !/^(?:AI_RAW_CONTEXT|RAW_OUTPUT_BEGIN|AI_EVIDENCE_BLOCK_(?:BEGIN|END)|RAW_COMMAND_OUTPUT_(?:BEGIN|END))$/.test(line) &&
      !/^[a-z_]+=/i.test(line) && !/^(?:SERVICE_PRESENCE|COLLECTION_HINT)=/.test(line) &&
      !/^\[\s*[a-zA-Z0-9_|]+\s*\]\[(?:S|E)\]$/.test(line) &&
      !/no such file|cannot access|not found|permission denied/i.test(line)
    );
    return findings.length === 0 ? reason : null;
  } });
  add('SRV-093', 'safe', [noFindingSafe('world-writable 파일 미발견')]);
  add('SRV-095', 'safe', [noFindingSafe('소유자/그룹 없는 파일 미발견')]);
  add('SRV-144', 'safe', [noFindingSafe('/dev 아래 불필요 일반 파일 미발견')]);

  // SRV-014: NFS 공유 정의가 없으면 양호
  add('SRV-014', 'safe', [{ pattern: text => {
    const t = String(text || '');
    return /exports/i.test(t) && !/^\/\S+[^\n]*\(/m.test(t) ? 'NFS export 공유 정의 없음' : null;
  } }]);

  // SRV-163(Linux): motd 비어있음 + 경고 콘텐츠 없음 = 배너 미설정 취약 (SecuMS·LLM 일치)
  add('SRV-163', 'vuln', [{ pattern: text => {
    const t = String(text || '');
    if (!/cat \/etc\/motd/.test(t)) return null;
    const hasWarn = /(?:unauthorized|무단|경고|warning|authorized users only|법적|모니터링|monitored|prohibited)/i.test(t);
    const motdEmpty = /\$ cat \/etc\/motd\s*\n\s*(?:-{3,}|\$)/.test(t);
    return motdEmpty && !hasWarn ? '로그온 경고 배너 미설정(motd 비어있음, 경고 문구 없음)' : null;
  } }]);

  // SRV-119: 수집 스크립트의 백신 프로세스 스캔 마커 판정
  add('SRV-119', 'vuln', [{ pattern: /AV_PROCESS_DETECTED=none/, reason: '백신 프로세스 미검출 — 백신 미설치/미실행(업데이트 적용 불가)' }]);
  add('SRV-119', 'safe', [{ pattern: text => { const m = String(text || '').match(/AV_PROCESS_DETECTED=(?!none)(\S+)/); return m ? '백신 프로세스 실행 확인(' + m[1] + ')' : null; } }]);

  // SRV-081: cron/at 계열 파일 권한 — others 읽기(0644) 또는 crontab SUID(4755)도 취약 (SecuMS 기준)
  add('SRV-081', 'vuln', [{ pattern: text => {
    for (const raw of String(text || '').split('\n')) {
      const l = raw.trim();
      if (!/^[-][rwxStTs-]{9}[.+]?\s+/.test(l)) continue;
      const mode = l.slice(0, 10);
      const file = l.split(/\s+/).pop();
      if (/\/(?:at|cron)\.(?:allow|deny)$/.test(file) && mode[7] !== '-') {
        return 'cron/at 제어 파일에 others 접근 권한(' + file + ' ' + mode + ')';
      }
      if (/\/crontab$/.test(file) && /[sS]/.test(mode[3])) {
        return 'crontab 명령에 SUID 설정(' + file + ' ' + mode + ')';
      }
    }
    return null;
  } }]);
})();

// SecuMS(OS_Detail) 기준 "정보(INFO)" 항목 — 시스템 스캔만으로 취약/양호를 단정하지 않는 운영 판단 항목.
// 3-way 정합성을 위해 mock도 정보제공으로 정렬 (근거는 evidence에 유지).
// 주의: SRV-021/171/175는 SecuMS가 서버 상태에 따라 OK/INFO를 오가므로(107=OK, 207=INFO) 목록에서 제외 — 판정 유지
const SECUMS_INFO_ITEMS = new Set([
  'SRV-105', 'SRV-115', 'SRV-118', 'SRV-133', 'SRV-149',
  'SRV-152', 'SRV-172', 'SRV-179',
]);

function mergeRules(...rules) {
  return {
    vuln: rules.flatMap(r => (r && r.vuln) || []),
    safe: rules.flatMap(r => (r && r.safe) || []),
  };
}

function getScriptMeta(chkId) {
  const id = normalizeSrvId(chkId);
  return id ? SRV_META[id] || null : null;
}

function getScriptPatterns(chkId) {
  const id = normalizeSrvId(chkId);
  if (!id) return null;

  const metaForId = SRV_META[id] || SRV_META[`SRV-${id.slice(-3)}`] || SCRIPT_DEFAULT;
  const idRules = SRV_RULES[id];
  const hasOwn = idRules && (((idRules.vuln || []).length) || ((idRules.safe || []).length));

  // 항목 전용 룰이 있으면 그것만 사용한다. SCRIPT_DEFAULT(범용 취약/양호 패턴)를 병합하면
  // 다른 항목 신호(PermitRootLogin/PASS_MAX_DAYS/telnet 등)가 섞여 엉뚱한 사유로 오탐하므로 병합 금지.
  // 전용 룰이 없는 항목에 한해서만 SCRIPT_DEFAULT 범용 신호로 폴백한다.
  const eff = hasOwn ? idRules : SCRIPT_DEFAULT;

  return {
    ...SCRIPT_DEFAULT,
    ...metaForId,
    vuln: eff.vuln || [],
    safe: eff.safe || [],
  };
}

module.exports = {
  getScriptPatterns,
  getScriptMeta,
  normalizeSrvId,
  SRV_META,
  SRV_RULES,
  SCRIPT_DEFAULT,
  SECUMS_INFO_ITEMS,
};

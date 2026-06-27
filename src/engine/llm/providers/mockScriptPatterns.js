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
  const service = names.map(escapeRegex).join('|');
  const re = new RegExp(`\\b(?:${service})\\b[\\s\\S]{0,120}\\b(?:LISTEN|LISTENING|RUNNING|SERVICE_RUNNING|STATE\\s*:\\s*4)\\b`, 'i');
  return re.test(text);
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

function regDwordValue(text, key) {
  const re = new RegExp(`${escapeRegex(key)}\\s+(?:REG_\\w+\\s+)?(?:0x([0-9a-f]+)|(\\d+))`, 'i');
  const m = String(text || '').match(re);
  if (!m) return null;
  return parseInt(m[1] || m[2], m[1] ? 16 : 10);
}

function regStringValue(text, key) {
  const re = new RegExp(`${escapeRegex(key)}\\s+(?:REG_\\w+\\s+)?([^\\r\\n]+)`, 'i');
  const m = String(text || '').match(re);
  return m ? m[1].trim() : null;
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

function lineForPath(text, pathRe) {
  return String(text || '')
    .split('\n')
    .find(line => /^[bcdlps-][rwxStTs-]{9}\s+/.test(line.trim()) && pathRe.test(line));
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
        !/^<\?xml|^<\/?[A-Za-z]/.test(line)
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
];

const SRV_META = {
  ...buildDefaultMeta(),
  ...Object.fromEntries(SRV_META_ROWS.map(row => [row.id, row])),
};

const SNMP_COMMUNITY_RULES = {
  vuln: [
    { pattern: /\b(?:community|ValidCommunities)\b[\s\S]{0,120}\b(?:public|private)\b/i, reason: 'SNMP 기본 community(public/private)가 확인됨' },
    { pattern: /\b(?:READ_WRITE|ReadWrite|rwcommunity)\b/i, reason: 'SNMP 쓰기 권한 community가 확인됨' },
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
    vuln: [{ pattern: /LogLevel\s*[=:]?\s*(?:0|1|2|3)\b/i, reason: 'sendmail LogLevel이 낮게 설정됨' }],
    safe: [{ pattern: /LogLevel\s*[=:]?\s*(?:9|1[0-9]|[2-9][0-9])\b/i, reason: 'sendmail LogLevel이 감사 가능한 수준으로 설정됨' }],
  },
  'SRV-007': {
    vuln: [{ pattern: text => activeLineMatches(text, /\b(?:Sendmail|ESMTP|SMTP)\b[^\n]*(?:version|[0-9]+\.[0-9]+)/i) ? 'SMTP 배너 또는 설정에 버전 정보가 노출됨' : null }],
    safe: [],
  },
  'SRV-008': {
    vuln: [
      { pattern: /MaxDaemonChildren\s*=\s*0/i, reason: 'sendmail 동시 처리 제한이 비활성화됨' },
      { pattern: /ConnectionRateThrottle\s*=\s*0/i, reason: 'sendmail 연결 속도 제한이 비활성화됨' },
    ],
    safe: [],
  },
  'SRV-009': {
    vuln: [groupOrOtherWritable(/\/etc\/mail|sendmail\.cf/i, 'sendmail 설정 파일이 group/other 쓰기 가능')],
    safe: [notGroupOrOtherWritable(/\/etc\/mail|sendmail\.cf/i, 'sendmail 설정 파일 쓰기 권한 제한 확인')],
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
    vuln: [dwordNotEquals('AutoShareServer', 0, 'AutoShareServer가 비활성화되어 있지 않음'), dwordNotEquals('AutoShareWks', 0, 'AutoShareWks가 비활성화되어 있지 않음')],
    safe: [dwordEquals('AutoShareServer', 0, 'AutoShareServer=0 확인'), dwordEquals('AutoShareWks', 0, 'AutoShareWks=0 확인')],
  },
  'SRV-019': { vuln: [{ pattern: text => hasListeningService(text, ['tftp', 'talk', 'ntalk']) ? 'tftp/talk 계열 서비스 실행 신호 확인' : null }], safe: [] },
  'SRV-020': { vuln: [{ pattern: /\b(?:Everyone|Users|ANONYMOUS LOGON)\b[^\n]*(?:FULL|CHANGE|WRITE|F|C|\(F\))/i, reason: '공유 폴더에 광범위한 쓰기/전체 권한 확인' }], safe: [] },
  'SRV-022': { vuln: [dwordEquals('LimitBlankPasswordUse', 0, '빈 암호 원격 로그온 제한 비활성')], safe: [dwordEquals('LimitBlankPasswordUse', 1, '빈 암호 원격 로그온 제한 활성')] },
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
  'SRV-034': { vuln: [{ pattern: text => hasListeningService(text, ['Alerter', 'ClipSrv', 'Messenger']) ? '레거시 Windows 서비스 실행 신호 확인' : null }], safe: [] },
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
  'SRV-048': { vuln: [{ pattern: text => hasListeningService(text, ['IISADMIN', 'W3SVC', 'iisadmin', 'w3svc']) ? 'IIS 서비스 실행 신호 확인' : null }], safe: [] },
  'SRV-051': { vuln: [{ pattern: /directoryBrowse\s+enabled\s*=\s*"true"|DirectoryBrowsing\s*(?:=|:)?\s*(?:true|1|enabled)/i, reason: 'IIS 디렉터리 검색 활성화 확인' }], safe: [{ pattern: /directoryBrowse\s+enabled\s*=\s*"false"|DirectoryBrowsing\s*(?:=|:)?\s*(?:false|0|disabled)/i, reason: 'IIS 디렉터리 검색 비활성화 확인' }] },
  'SRV-052': { vuln: [{ pattern: /AspEnableParentPaths\s*(?:=|:)?\s*(?:TRUE|1)/i, reason: 'IIS Parent Paths 활성화 확인' }], safe: [{ pattern: /AspEnableParentPaths\s*(?:=|:)?\s*(?:FALSE|0)/i, reason: 'IIS Parent Paths 비활성화 확인' }] },
  'SRV-053': { vuln: [{ pattern: text => hasListeningService(text, ['WebClient', 'WebDAV']) || /WebDAV[^\n]*(?:enabled|true)/i.test(text) ? 'WebDAV 활성화 신호 확인' : null }], safe: [] },
  'SRV-054': { vuln: [{ pattern: /log(?:ging)?\s*(?:enabled\s*=\s*"false"|=\s*false|:\s*disabled)/i, reason: 'IIS 로깅 비활성화 확인' }], safe: [{ pattern: /log(?:ging)?\s*(?:enabled\s*=\s*"true"|=\s*true|:\s*enabled)/i, reason: 'IIS 로깅 활성화 확인' }] },
  'SRV-057': { vuln: [{ pattern: /\b(?:Everyone|Users|IUSR)\b[^\n]*(?:FULL|CHANGE|WRITE|\(F\))/i, reason: 'IIS 경로에 광범위한 쓰기/전체 권한 확인' }], safe: [] },
  'SRV-059': { vuln: [dwordEquals('SSIEnableCmdDirective', 1, 'SSI 명령 실행 지시자가 활성화됨')], safe: [dwordEquals('SSIEnableCmdDirective', 0, 'SSI 명령 실행 지시자가 비활성화됨')] },
  'SRV-060': {
    vuln: [
      { pattern: /<user\b[^>]*(?:username|name)\s*=\s*["'](?:tomcat|admin|manager|root)["'][^>]*(?:password)\s*=\s*["'][^"']+["']/i, reason: 'Tomcat 기본/관리 계정 정보가 확인됨' },
      { pattern: /roles\s*=\s*["'][^"']*(?:manager-gui|admin-gui|manager-script)/i, reason: 'Tomcat 관리 권한 계정이 확인됨' },
    ],
    safe: [],
  },
  'SRV-061': { vuln: [{ pattern: text => hasListeningPort(text, ['53']) || hasListeningService(text, ['named', 'dns']) ? 'DNS 서비스 노출 신호 확인' : null }], safe: [] },
  'SRV-062': { vuln: [{ pattern: /\brecursion\s+yes\b/i, reason: 'DNS recursion yes 설정 확인' }, { pattern: /allow-recursion\s*\{\s*any\s*;\s*\}/i, reason: 'DNS 재귀 질의가 any로 허용됨' }], safe: [{ pattern: /\brecursion\s+no\b/i, reason: 'DNS recursion no 설정 확인' }] },
  'SRV-063': { vuln: [dwordEquals('NoRecursion', 0, 'Windows DNS 재귀 질의 제한 미적용')], safe: [dwordEquals('NoRecursion', 1, 'Windows DNS 재귀 질의 제한 적용')] },
  'SRV-064': { vuln: [{ pattern: /allow-transfer\s*\{\s*(?:any|0\.0\.0\.0\/0)\s*;\s*\}/i, reason: 'DNS zone transfer가 광범위하게 허용됨' }], safe: [] },
  'SRV-065': { vuln: [{ pattern: /version\s+["']?[^"';\n]+["']?\s*;/i, reason: 'DNS version 문자열이 설정/노출됨' }], safe: [] },
  'SRV-066': { vuln: [{ pattern: /allow-transfer\s*\{\s*(?:any|0\.0\.0\.0\/0)\s*;\s*\}|SecureSecondaries\s+REG_DWORD\s+0x0/i, reason: 'DNS zone transfer 제한 미흡 신호 확인' }], safe: [dwordAtLeast('SecureSecondaries', 1, 'Windows DNS 보조 서버 제한 설정 확인')] },
  'SRV-067': { vuln: [{ pattern: /ADCLaunch|msdfmap\.ini/i, reason: 'ADCLaunch 또는 msdfmap.ini 관련 구성 확인' }], safe: [] },
  'SRV-068': { vuln: [{ pattern: /^\w+:\$[156y]\$|ClearTextPassword\s*=\s*1|password\s*[:=]\s*[^*\s]/im, reason: '패스워드 해시/평문 노출 신호 확인' }], safe: [] },
  'SRV-069': PASSWORD_POLICY_RULES,
  'SRV-075': PASSWORD_POLICY_RULES,
  'SRV-076': PASSWORD_POLICY_RULES,
  'SRV-077': {
    vuln: [
      { pattern: /^[^:\n]+::\d+:/m, reason: '/etc/passwd에 빈 패스워드 필드가 확인됨' },
      dwordEquals('ClearTextPassword', 1, 'Windows ClearTextPassword=1 확인'),
    ],
    safe: [dwordEquals('ClearTextPassword', 0, 'Windows ClearTextPassword=0 확인')],
  },
  'SRV-078': { vuln: [{ pattern: /Account active\s+Yes/i, reason: 'Guest 계정 활성화 확인' }], safe: [{ pattern: /Account active\s+No/i, reason: 'Guest 계정 비활성화 확인' }] },
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
  'SRV-096': { vuln: [groupOrOtherWritable(/\/home\/[^/\s]+\/\.[^\s]+/i, '사용자 dotfile이 group/other 쓰기 가능')], safe: [notGroupOrOtherWritable(/\/home\/[^/\s]+\/\.[^\s]+/i, '사용자 dotfile 쓰기 권한 제한 확인')] },
  'SRV-098': { vuln: [{ pattern: /\b(?:Everyone|Users|ANONYMOUS LOGON)\b[^\n]*(?:FULL|CHANGE|WRITE|\(F\))/i, reason: 'SAM 파일에 광범위한 권한 확인' }], safe: [] },
  'SRV-099': { vuln: [groupOrOtherWritable(/\/etc\/services/i, '/etc/services가 group/other 쓰기 가능')], safe: [notGroupOrOtherWritable(/\/etc\/services/i, '/etc/services 쓰기 권한 제한 확인')] },
  'SRV-100': { vuln: [{ pattern: /^[bcdlps-]..s[rwxStTs-]{6}\s+.*\/xterm\b/im, reason: 'xterm SUID 권한 확인' }, groupOrOtherWritable(/\/xterm\b/i, 'xterm이 group/other 쓰기 가능')], safe: [] },
  'SRV-103': { vuln: [dwordLessThan('LmCompatibilityLevel', 3, 'LM/NTLM 호환 수준이 3 미만')], safe: [dwordAtLeast('LmCompatibilityLevel', 3, 'LmCompatibilityLevel 3 이상 확인')] },
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
    safe: [{ pattern: /AutoAdminLogon\s+REG_\w+\s+0\b/i, reason: 'AutoAdminLogon 비활성화 확인' }],
  },
  'SRV-127': {
    vuln: [
      { pattern: /^FAILLOG_ENAB\s+no\b/im, reason: 'FAILLOG_ENAB=no 확인' },
      dwordEquals('MaxDenials', 0, 'RemoteAccess 계정 잠금 임계값 미설정'),
      dwordEquals('LockoutBadCount', 0, '계정 잠금 임계값 0 확인'),
    ],
    safe: [
      { pattern: /^FAILLOG_ENAB\s+yes\b/im, reason: 'FAILLOG_ENAB=yes 확인' },
      dwordAtLeast('MaxDenials', 1, 'RemoteAccess 계정 잠금 임계값 설정 확인'),
      dwordAtLeast('LockoutBadCount', 1, '계정 잠금 임계값 설정 확인'),
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
  'SRV-141': FIREWALL_RULES,
  'SRV-142': {
    vuln: [{ pattern: text => String(text || '').split('\n').some(line => /^[^:\s]+:[^:]*:0:/.test(line) && !/^root:/.test(line)) ? 'root 외 UID 0 계정이 확인됨' : null }],
    safe: [{ pattern: text => /^[^:\s]+:[^:]*:0:/m.test(text) && !String(text || '').split('\n').some(line => /^[^:\s]+:[^:]*:0:/.test(line) && !/^root:/.test(line)) ? 'UID 0 계정이 root만 확인됨' : null }],
  },
  'SRV-143': {
    vuln: [{ pattern: text => {
      const seen = new Map();
      for (const line of String(text || '').split('\n')) {
        const parts = line.split(':');
        if (parts.length < 3 || !/^\d+$/.test(parts[2])) continue;
        if (seen.has(parts[2])) return `중복 UID ${parts[2]} 확인`;
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
    ],
    safe: [{ pattern: /LegalNotice(?:Caption|Text)\s+REG_\w+\s+\S+|Authorized users only|경고|warning|warning/i, reason: '로그온 배너 문구 확인' }],
  },
  'SRV-164': {
    vuln: [{ pattern: text => {
      const seen = new Map();
      for (const line of String(text || '').split('\n')) {
        const parts = line.split(':');
        if (parts.length < 3 || !/^\d+$/.test(parts[2])) continue;
        if (seen.has(parts[2])) return `중복 GID ${parts[2]} 확인`;
        seen.set(parts[2], parts[0]);
      }
      return null;
    } }],
    safe: [],
  },
  'SRV-165': { vuln: [{ pattern: /^(?:daemon|bin|sys|adm|listen|nobody|operator|games|gopher):[^:]*:[^:]*:[^:]*:[^:]*:[^:]*:\/(?:bin|usr\/bin)\/(?:sh|bash|ksh|csh|zsh)\b/im, reason: '시스템 계정에 로그인 가능한 쉘 부여' }], safe: [] },
  'SRV-167': FTP_RULES,
  'SRV-168': { vuln: [{ pattern: /^[^#\n]*\*\.\*\s+\/dev\/null/im, reason: '전체 로그가 /dev/null로 폐기되는 설정 확인' }], safe: [{ pattern: /^[^#\n]*(?:authpriv|kern|daemon|\*\.\*)\.[^\n]+\s+@{1,2}[\w.-]+/im, reason: '원격 syslog 전송 설정 확인' }] },
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
  const idRules = SRV_RULES[id] || {};
  const merged = mergeRules(idRules, SCRIPT_DEFAULT);

  return {
    ...SCRIPT_DEFAULT,
    ...metaForId,
    vuln: merged.vuln,
    safe: merged.safe,
  };
}

module.exports = {
  getScriptPatterns,
  getScriptMeta,
  normalizeSrvId,
  SRV_META,
  SRV_RULES,
  SCRIPT_DEFAULT,
};

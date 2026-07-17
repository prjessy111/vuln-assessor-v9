'use strict';
/**
 * CHK_ID 별 취약/양호 패턴 라이브러리 (1단계).
 *
 * 사용 위치: mock.js _aiDiagnoseMock
 *
 * 패턴 형식:
 *   {
 *     '<CHK_ID>': {
 *       vuln: [                            // 취약 패턴 (우선순위 순)
 *         { pattern: /regex/i, reason: '판정 사유' },
 *         { pattern: (text, outputs) => string|null, reason: 'fallback' },  // 함수형도 가능
 *       ],
 *       safe: [                            // 양호 패턴
 *         { pattern: /regex/i, reason: '판정 사유' },
 *       ],
 *       category: '카테고리',
 *       title: '제목',
 *       severity: '상' | '중' | '하',
 *       recommend: '조치 권고',
 *     }
 *   }
 *
 * 1단계: 핵심 ~15개 항목.
 *   - 실제 BAD 사례에서 raw 출력의 명확한 신호로 패턴 추출
 *   - 매칭 안 되는 항목은 mock 이 "정보 — 검토 필요" 로 분류
 *   - 2단계에서 실 진단 결과 보고 확장
 */

module.exports = {
  // ═════════════════════════════════════════════
  // Linux
  // ═════════════════════════════════════════════

  // U-01 root 원격 접속 제한 (PermitRootLogin)
  'os-linux-383': {
    category: '계정 관리',
    title: 'root 원격 접속 제한 (securetty/PAM/SSH)',
    severity: '상',
    recommend: '/etc/ssh/sshd_config 에 "PermitRootLogin no" 설정. /etc/pam.d/login 에 pam_securetty.so 추가.',
    vuln: [
      { pattern: /PermitRootLogin\s+yes/i,
        reason: 'sshd_config 에 PermitRootLogin yes 설정 — root 원격 로그인 허용됨' },
      // SecuMS raw: PermitRootLogin 미설정(EXIST=NO) = 명시적 차단 없음 → 취약 (3-way 기준)
      { pattern: /<Value>PermitRootLogin<\/Value>\s*(?:<Value\s*\/>|<Value><\/Value>)\s*<Value>NO<\/Value>/i,
        reason: 'sshd_config 에 PermitRootLogin 명시 설정 없음 — root 원격 접속 차단(no) 미적용' },
      { pattern: (text) => {
          // pam_securetty.so 가 active 라인에 없는지 (주석 # 무시)
          const loginM = text.match(/#?\s*cat\s+\/etc\/pam\.d\/login[\s\S]{0,800}/i);
          if (!loginM) return null;
          const body = loginM[0];
          const lines = body.split('\n').filter(l => l.trim() && !l.trim().startsWith('#'));
          const hasSecuretty = lines.some(l => /pam_securetty\.so/i.test(l));
          if (!hasSecuretty) return 'PAM login 설정에 pam_securetty.so 가 없음 — root 터미널 제한 미설정';
          return null;
        },
      },
    ],
    safe: [
      { pattern: /^[^#\n]*PermitRootLogin\s+no/im,
        reason: 'sshd_config 에 PermitRootLogin no 설정됨 — root 원격 로그인 차단' },
    ],
  },

  // U-04 패스워드 정책 (login.defs)
  'os-linux-377': {
    category: '계정 관리',
    title: 'login.defs 패스워드 정책',
    severity: '상',
    recommend: '/etc/login.defs 에 PASS_MAX_DAYS 90, PASS_MIN_LEN 8 이상 설정',
    vuln: [
      { pattern: /^[^#\n]*PASS_MAX_DAYS\s+99999/im,
        reason: 'PASS_MAX_DAYS=99999 — 사실상 비활성 (만료 없음)' },
      { pattern: /^[^#\n]*PASS_MAX_DAYS\s+([0-9]{4,})/im,
        reason: 'PASS_MAX_DAYS 가 정책 권장(90) 초과' },
      { pattern: /^[^#\n]*PASS_MIN_LEN\s+[1-7]\b/im,
        reason: 'PASS_MIN_LEN 이 8 미만 — KISA 권장 미달' },
    ],
    safe: [
      { pattern: (text) => {
          const maxOK = /^[^#\n]*PASS_MAX_DAYS\s+([1-9]|[1-8][0-9]|90)\b/im.test(text);
          const lenOK = /^[^#\n]*PASS_MIN_LEN\s+([8-9]|[1-9][0-9]+)\b/im.test(text);
          if (maxOK && lenOK) return 'PASS_MAX_DAYS 90 이하 + PASS_MIN_LEN 8 이상 — 정책 부합';
          return null;
        },
      },
    ],
  },

  // U-13 SUID/SGID 권한 (불필요 SUID 차단)
  'os-linux-273': {
    category: '파일 권한',
    title: 'SUID/SGID/Sticky bit 설정',
    severity: '상',
    recommend: '불필요한 SUID 제거: chmod u-s <파일> (사용성 검토 후)',
    vuln: [
      // 위험 SUID 파일들 (4xxx 권한)
      { pattern: /<Value>\/usr\/bin\/(?:newgrp|at|pkexec|chsh|chfn|chage|wall|write|locate|crontab)<\/Value>[\s\S]{0,150}<Value>4[0-7]{3}<\/Value>/i,
        reason: '불필요한 SUID 비트 설정된 파일 발견 (root 권한 상승 위험)' },
      { pattern: /<Value>\/sbin\/(?:dump|restore|unix_chkpwd|netreport)<\/Value>[\s\S]{0,150}<Value>4[0-7]{3}<\/Value>/i,
        reason: '/sbin 의 SUID 파일 발견 — 권한 상승 위험' },
    ],
    safe: [],
  },

  // U-14 사용자 환경파일 권한 (.bashrc 등이 0600 이어야)
  'os-linux-1998': {
    category: '파일 권한',
    title: '사용자 환경파일 권한 (.profile 등)',
    severity: '중',
    recommend: 'chmod 600 ~/.bashrc ~/.bash_profile ~/.cshrc 등',
    vuln: [
      { pattern: /<Value>\/(?:root|home\/[^<]+)\/\.(?:bashrc|bash_profile|cshrc|profile|kshrc|login)<\/Value>[\s\S]{0,150}<Value>0?(?:6[2-7][2-7]|7[2-7][2-7])<\/Value>/i,
        reason: '사용자 환경파일이 group/other 읽기 가능 (0644 등) — 환경변수 노출 위험' },
    ],
    safe: [],
  },

  // U-17 TCP Wrapper (/etc/hosts.deny ALL:ALL 필요)
  'os-linux-254': {
    category: '네트워크 보안',
    title: 'TCP Wrapper (hosts.allow/deny)',
    severity: '중',
    recommend: '/etc/hosts.deny 에 "ALL: ALL" 추가, /etc/hosts.allow 에 허용 IP 명시',
    vuln: [
      { pattern: (text) => {
          // hosts.deny 안에 ALL:ALL 활성 라인이 있는지
          const denyM = text.match(/cat\s+\/etc\/hosts\.deny([\s\S]{0,1500})/i);
          if (!denyM) return null;
          const body = denyM[1];
          const activeLines = body.split('\n')
            .map(l => l.trim())
            .filter(l => l && !l.startsWith('#'));
          const hasAllDeny = activeLines.some(l => /^ALL\s*:\s*ALL/i.test(l));
          if (!hasAllDeny) return '/etc/hosts.deny 에 "ALL: ALL" 미설정 — 기본 거부 정책 부재';
          return null;
        },
      },
    ],
    safe: [
      { pattern: /^ALL\s*:\s*ALL/im,
        reason: '/etc/hosts.deny 에 ALL:ALL 설정됨 — 기본 거부 정책 적용' },
    ],
  },

  // U-19 Anonymous FTP (FTP 21 LISTEN 시 취약)
  'os-linux-2389': {
    category: '서비스 관리',
    title: 'Anonymous FTP / FTP 서비스',
    severity: '상',
    recommend: 'FTP 대신 SFTP/SCP 사용. systemctl stop vsftpd; systemctl disable vsftpd',
    vuln: [
      { pattern: /<Value>ftp<\/Value>[\s\S]{0,100}<Value>21<\/Value>/i,
        reason: 'FTP 서비스(port 21) LISTEN 중 — 평문 전송 프로토콜 노출' },
    ],
    safe: [
      { pattern: (text) => {
          // FTP 가 LISTEN 목록에 없으면 양호
          const m = text.match(/<Dump type="table">[\s\S]*?<\/Dump>/);
          if (m && !/<Value>ftp<\/Value>/i.test(m[0]) && /SERVICENAME/i.test(m[0])) {
            return 'FTP 서비스 미LISTEN — Anonymous FTP 위험 없음';
          }
          return null;
        },
      },
    ],
  },

  // U-21 cron 파일 권한
  'os-linux-34': {
    category: '서비스 관리',
    title: 'cron 디렉토리/파일 권한',
    severity: '중',
    recommend: 'chmod 640 /etc/at.deny; chmod 700 /usr/bin/crontab',
    vuln: [
      { pattern: /<Value>\/etc\/at\.deny<\/Value>[\s\S]{0,150}<Value>0?6[4-7][4-7]<\/Value>/i,
        reason: '/etc/at.deny 권한이 0644 등 group/other 읽기 가능' },
      { pattern: /<Value>\/usr\/bin\/crontab<\/Value>[\s\S]{0,150}<Value>4[0-7]{3}<\/Value>/i,
        reason: '/usr/bin/crontab 에 SUID 비트 설정됨 — 일반 사용자 cron 조작 위험' },
    ],
    safe: [],
  },

  // ═════════════════════════════════════════════
  // Windows
  // ═════════════════════════════════════════════

  // Windows Firewall 활성 여부
  'os-win-152': {
    category: '계정 관리',
    title: '마지막 로그온 사용자 표시 (DontDisplayLastUserName)',
    severity: '중',
    recommend: 'gpedit.msc → Windows 설정 → 보안 설정 → 로컬 정책 → 보안 옵션 → "대화형 로그온: 마지막 사용자 이름 표시 안함" 활성',
    vuln: [
      { pattern: /DontDisplayLastUserName[\s\S]{0,200}<Value>0<\/Value>/i,
        reason: 'DontDisplayLastUserName=0 — 마지막 로그온 사용자명이 표시됨' },
    ],
    safe: [
      { pattern: /DontDisplayLastUserName[\s\S]{0,200}<Value>1<\/Value>/i,
        reason: 'DontDisplayLastUserName=1 — 마지막 사용자명 미표시' },
    ],
  },

  // 화면 보호기
  'os-win-154': {
    category: '계정 관리',
    title: '화면 보호기 설정 (SCRNSAVE)',
    severity: '중',
    recommend: '제어판 → 개인 설정 → 화면 보호기 설정 + "다시 시작할 때 로그온 화면 표시" 체크',
    vuln: [
      { pattern: /SCRNSAVE\.EXE[\s\S]{0,200}EXIST[\s\S]{0,50}<Value>NO<\/Value>/i,
        reason: '화면 보호기 미설정 — 자리 비움 시 무단 접근 위험' },
      { pattern: /ScreenSaverIsSecure[\s\S]{0,200}<Value>0<\/Value>/i,
        reason: 'ScreenSaverIsSecure=0 — 화면 보호기 복귀 시 암호 요구 안함' },
    ],
    safe: [
      { pattern: /ScreenSaverIsSecure[\s\S]{0,200}<Value>1<\/Value>/i,
        reason: 'ScreenSaverIsSecure=1 — 화면 보호기 복귀 시 암호 요구' },
    ],
  },

  // 로그온 경고 메시지
  'os-win-156': {
    category: '계정 관리',
    title: '로그온 경고 메시지 (LegalNotice)',
    severity: '하',
    recommend: 'gpedit.msc → 보안 옵션 → "대화형 로그온: 메시지 텍스트/제목" 설정',
    vuln: [
      { pattern: /legalnoticecaption[\s\S]{0,300}<Value><\/Value>/i,
        reason: 'LegalNoticeCaption 미설정 — 로그온 경고 메시지 없음' },
      { pattern: /legalnoticetext[\s\S]{0,300}<Value><\/Value>/i,
        reason: 'LegalNoticeText 미설정' },
    ],
    safe: [],
  },

  // restrictanonymous (익명 접근 제한)
  'os-win-268': {
    category: '계정 관리',
    title: 'restrictanonymous (익명 SAM 조회 제한)',
    severity: '상',
    recommend: 'HKLM\\System\\CurrentControlSet\\Control\\Lsa\\restrictanonymous = 1',
    vuln: [
      { pattern: /restrictanonymous[\s\S]{0,300}<Value>0<\/Value>/i,
        reason: 'restrictanonymous=0 — 익명 사용자가 SAM 계정/공유 정보 열람 가능' },
    ],
    safe: [
      { pattern: /restrictanonymous[\s\S]{0,300}<Value>1<\/Value>/i,
        reason: 'restrictanonymous=1 — 익명 SAM 조회 차단' },
    ],
  },

  // Administrator 계정명 변경
  'os-win-284': {
    category: '계정 관리',
    title: 'Administrator 계정명 변경',
    severity: '상',
    recommend: '로컬 사용자 → Administrator 이름 변경 (예: ADM_xxx)',
    vuln: [
      { pattern: /<Value>Administrator<\/Value>[\s\S]{0,300}(?:S-1-5-21-[0-9-]+-500)/i,
        reason: 'Administrator 계정명 변경 안 됨 (RID 500 계정 이름이 "Administrator")' },
    ],
    safe: [],
  },

  // RemoteRegistry 서비스
  'os-win-300': {
    category: '서비스 관리',
    title: 'RemoteRegistry 서비스 시작 유형',
    severity: '상',
    recommend: 'services.msc → RemoteRegistry → 시작 유형 "사용 안 함" 으로 변경',
    vuln: [
      { pattern: /RemoteRegistry[\s\S]{0,500}<Value>(?:Auto|Automatic|자동)<\/Value>/i,
        reason: 'RemoteRegistry 서비스가 자동 시작 — 원격 레지스트리 무단 변경 가능' },
    ],
    safe: [
      { pattern: /RemoteRegistry[\s\S]{0,500}<Value>(?:Disabled|사용 안 함)<\/Value>/i,
        reason: 'RemoteRegistry 서비스 비활성' },
    ],
  },

  // Windows Firewall
  'os-win-306': {
    category: '네트워크 보안',
    title: 'Windows Firewall 활성',
    severity: '상',
    recommend: '제어판 → Windows Defender 방화벽 → 도메인/개인/공용 모두 "사용"',
    vuln: [
      { pattern: /EnableFirewall[\s\S]{0,200}<Value>0<\/Value>/i,
        reason: 'EnableFirewall=0 — Windows Firewall 비활성' },
    ],
    safe: [
      { pattern: /EnableFirewall[\s\S]{0,200}<Value>1<\/Value>/i,
        reason: 'EnableFirewall=1 — Firewall 활성' },
    ],
  },

  // LockoutBadCount (계정 잠금)
  'os-win-486': {
    category: '계정 관리',
    title: '계정 잠금 임계값 (LockoutBadCount)',
    severity: '상',
    recommend: '로컬 보안 정책 → 계정 잠금 임계값 5회 이하 설정',
    vuln: [
      { pattern: /lockout_threshold[\s\S]{0,200}<Value>0<\/Value>/i,
        reason: 'LockoutBadCount=0 — 계정 잠금 정책 미적용 (무차별 대입 공격 무방어)' },
      { pattern: /LockoutBadCount[\s\S]{0,200}<Value>0<\/Value>/i,
        reason: 'LockoutBadCount=0 — 계정 잠금 정책 미적용' },
    ],
    safe: [
      { pattern: /LockoutBadCount[\s\S]{0,200}<Value>([1-9]|10)<\/Value>/i,
        reason: 'LockoutBadCount 10 이하 설정됨 — 계정 잠금 정책 적용' },
    ],
  },

  // MinimumPasswordLength
  'os-win-495': {
    category: '계정 관리',
    title: '최소 비밀번호 길이 (MinimumPasswordLength)',
    severity: '상',
    recommend: '로컬 보안 정책 → 최소 암호 길이 8자 이상 설정',
    vuln: [
      { pattern: /MinimumPasswordLength[\s\S]{0,200}<Value>([0-7])<\/Value>/i,
        reason: 'MinimumPasswordLength 8 미만 — 약한 암호 허용' },
    ],
    safe: [
      { pattern: /MinimumPasswordLength[\s\S]{0,200}<Value>([89]|1[0-9])<\/Value>/i,
        reason: 'MinimumPasswordLength 8 이상 — 정책 부합' },
    ],
  },

  // 안티바이러스 (V3 등)
  'os-win-489': {
    category: '시스템 보안',
    title: '안티바이러스 설치/실행 상태',
    severity: '상',
    recommend: '안티바이러스 설치 및 실시간 보호 활성화',
    vuln: [
      { pattern: /(?:백신|antivirus|V3)[\s\S]{0,300}<Value>(?:disabled|stopped|not installed|미설치|미실행|0)<\/Value>/i,
        reason: '안티바이러스 미설치 또는 미실행' },
    ],
    safe: [
      { pattern: /(?:V3|Vaccine|antivirus)[\s\S]{0,300}<Value>(?:running|enabled|installed|실행 중)<\/Value>/i,
        reason: '안티바이러스 실행 중' },
    ],
  },

  // ═════════════════════════════════════════════
  // Linux — SecuMS raw(XML Dump) 항목별 룰 (2026-07-03)
  //   형식: NAME|VALUE|EXIST(설정), FILE_PATH|NAME|VALUE|EXIST(postfix),
  //         SERVICENAME|PORT, CMD|RESULT 등. 판정 입력은 raw 만(P1).
  // ═════════════════════════════════════════════
  // r-command 서비스: 서비스/포트 목록에 rsh/rlogin/rexec 계열 없음 → 양호
  'os-linux-61': {
    category: '서비스 관리', title: 'r-command 서비스', severity: '상',
    recommend: 'rsh/rlogin/rexec 서비스를 비활성화하십시오.',
    vuln: [{ pattern: /<Value>(?:rsh|rlogin|rexec|shell|exec|login)<\/Value>\s*<Value>\d+<\/Value>/i, reason: 'r-command 계열 서비스가 등록/실행 중' }],
    safe: [{ pattern: text => /SERVICENAME/i.test(text) && /<Rows count="[1-9]/.test(text) && !/<Value>(?:rsh|rlogin|rexec|shell|exec)<\/Value>/i.test(text) ? '서비스 목록에 r-command 계열 없음' : null }],
  },
  // FTP 서비스 설정: ftp 계정 로그인 차단 + FTP 설정 부재
  'os-linux-188': {
    category: '서비스 관리', title: 'FTP 서비스 설정', severity: '중',
    vuln: [{ pattern: /^ftp:x:\d+:\d+:[^:]*:[^:]*:\/bin\/(?:bash|sh|ksh|csh)/m, reason: 'ftp 계정에 로그인 가능한 쉘 부여' }],
    safe: [{ pattern: /^ftp:x:\d+:\d+:[^:]*:[^:]*:\/sbin\/nologin/m, reason: 'ftp 계정 로그인 차단(nologin) 확인' }],
  },
  // PATH 설정: 사용자별 PATH 값에 . / :: / 임시경로 포함 여부
  'os-linux-207': {
    category: '시스템 보안', title: 'PATH 환경 변수', severity: '중',
    recommend: 'PATH 에서 현재 디렉터리(.)와 임시 경로를 제거하십시오.',
    vuln: [{ pattern: text => {
      const m = String(text || '').match(/<Value>PATH<\/Value>\s*<Value>([^<]*)<\/Value>/gi);
      if (!m) return null;
      for (const one of m) {
        const v = (one.match(/<Value>([^<]*)<\/Value>\s*$/i) || [])[1] || '';
        if (/(?:^|:)\.(?::|$)|::|(?:^|:)\/tmp(?::|$)/.test(v)) return 'PATH 에 현재 디렉터리(.)/빈 항목 포함: ' + v.slice(0, 60);
      }
      return null;
    } }],
    safe: [{ pattern: text => {
      const m = String(text || '').match(/<Value>PATH<\/Value>/i);
      return m && !/(?:^|:)\.(?::|$)|::/m.test((String(text).match(/<Value>PATH<\/Value>\s*<Value>([^<]*)<\/Value>/i) || ['', ''])[1])
        ? 'PATH 설정에 현재 디렉터리(.)/빈 항목 없음' : null;
    } }],
  },
  // RPC 서비스: portmapper 표준만 존재 (위험 RPC: cmsd/ttdbserver 등 없음)
  'os-linux-286': {
    category: '서비스 관리', title: 'RPC 위험 서비스', severity: '상',
    vuln: [{ pattern: /<Value>(?:cmsd|ttdbserver\w*|sadmind|rusersd|rstatd|walld|sprayd)\b/i, reason: '위험 RPC 서비스 등록 확인' }],
    safe: [{ pattern: text => /portmapper/i.test(text) && !/cmsd|ttdbserver|sadmind|rusersd|rstatd/i.test(text) ? 'RPC 등록이 portmapper(표준)뿐 — 위험 RPC 서비스 없음' : null }],
  },
  // 관리자 FTP 제한: vsftpd user_list/ftpusers 접근 제한 파일 구성
  'os-linux-289': {
    category: '서비스 관리', title: '관리자 FTP 사용 제한', severity: '중',
    safe: [{ pattern: /<Value>\/etc\/vsftpd\/(?:user_list|ftpusers)<\/Value>/, reason: 'FTP 접근 제한 파일(user_list/ftpusers) 구성 확인' }],
    vuln: [],
  },
  // postfix 리소스 제한: 미설정이어도 postfix 기본 제한이 동작 (기본값 안전)
  'os-linux-324': {
    category: '서비스 관리', title: 'SMTP DoS 제한', severity: '중',
    vuln: [{ pattern: /<Value>(?:message_size_limit|default_process_limit)<\/Value>\s*<Value>0<\/Value>/i, reason: 'SMTP 리소스 제한이 0(무제한)으로 설정됨' }],
    safe: [{ pattern: text => /postfix\/master/.test(text) && /(?:message_size_limit|default_process_limit)/.test(text) ? 'postfix 기본 리소스 제한 동작(명시 설정 없음 = 안전 기본값)' : null }],
  },
  // postfix VRFY 제한: disable_vrfy_command 미설정(EXIST NO) + postfix 실행 = 취약
  'os-linux-335': {
    category: '서비스 관리', title: 'SMTP VRFY/EXPN 제한', severity: '중',
    recommend: '/etc/postfix/main.cf 에 disable_vrfy_command = yes 를 설정하십시오.',
    vuln: [{ pattern: text => /postfix\/master/.test(text) && /<Value>disable_vrfy_command<\/Value>\s*<Value\s*\/?>?<\/Value>?\s*<Value>NO<\/Value>/i.test(String(text || '').replace(/\s+/g, ' ')) || (/postfix\/master/.test(text) && /disable_vrfy_command/.test(text) && /<Value>NO<\/Value>/.test(text) && !/disable_vrfy_command[^<]*<\/Value>\s*<Value>yes/i.test(text)) ? 'postfix 실행 중이나 disable_vrfy_command 미설정 — VRFY 명령 허용' : null }],
    safe: [{ pattern: /<Value>disable_vrfy_command<\/Value>\s*<Value>yes<\/Value>/i, reason: 'disable_vrfy_command=yes — VRFY 제한 적용' }],
  },
  // SMTP 버전 확인: 로컬 postconf 조회만 존재 (외부 배너 노출 증거 없음)
  'os-linux-337': {
    category: '서비스 관리', title: 'SMTP 버전 노출', severity: '하',
    vuln: [],
    safe: [{ pattern: text => /mail_version/.test(text) && !/LISTEN/i.test(text) ? '로컬 버전 조회만 수집 — 외부 배너 노출 증거 없음' : null }],
  },
  // SMTP 릴레이 제한: smtpd_relay_restrictions / mynetworks 127 확인
  'os-linux-338': {
    category: '서비스 관리', title: 'SMTP 릴레이 제한', severity: '상',
    vuln: [{ pattern: /mynetworks\s*=\s*0\.0\.0\.0/, reason: 'SMTP 릴레이 네트워크가 전체 개방' }],
    safe: [{ pattern: /smtpd_relay_restrictions\s*=|mynetworks\s*=\s*127\./, reason: 'postfix 릴레이 제한(smtpd_relay_restrictions/mynetworks=127.x) 구성 확인' }],
  },
  // .netrc: 파일 부재(권한 값 없음) → 양호
  'os-linux-341': {
    category: '계정 관리', title: '.netrc 파일', severity: '중',
    vuln: [{ pattern: /<Value>[^<]*\.netrc<\/Value>\s*<Value>0[0-7]{2,3}<\/Value>/, reason: '.netrc 파일 존재 — 자격증명 평문 저장 위험' }],
    safe: [{ pattern: text => /\.netrc/.test(text) && !/<Value>[^<]*\.netrc<\/Value>\s*<Value>0?[0-7]{3}<\/Value>/.test(text) ? '.netrc 파일 없음(권한 값 미존재)' : null }],
  },
  // 세션 타임아웃: 모든 사용자 TMOUT 값 none/빈값 → 취약
  'os-linux-344': {
    category: '접근 제어', title: '세션 타임아웃(TMOUT)', severity: '중',
    recommend: '/etc/profile 에 TMOUT=600 등 유휴 타임아웃을 설정하십시오.',
    vuln: [{ pattern: text => {
      const vals = [...String(text || '').matchAll(/<Value>TMOUT<\/Value>\s*<Value>([^<]*)<\/Value>/gi)].map(m => m[1].trim());
      return vals.length && vals.every(v => !v || /^none$/i.test(v)) ? '모든 사용자 TMOUT 미설정' : null;
    } }],
    safe: [{ pattern: /<Value>TMOUT<\/Value>\s*<Value>[1-9]\d{1,3}<\/Value>/, reason: 'TMOUT 설정 확인' }],
  },
  // login.defs 패스워드 정책: 활성 PASS_MAX_DAYS 라인이 없음(주석만) → 취약
  'os-linux-377': {
    category: '비밀번호 정책', title: 'login.defs 정책', severity: '상',
    recommend: '/etc/login.defs 에 PASS_MAX_DAYS 90 이하 등 정책을 설정하십시오.',
    vuln: [{ pattern: text => {
      const t = String(text || '');
      if (!/login\.defs/.test(t)) return null;
      const active = /(?:^|>)\s*PASS_MAX_DAYS\s+(\d+)/m.exec(t.replace(/#[^\n<]*/g, ''));
      if (!active) return 'login.defs 에 활성 PASS_MAX_DAYS 설정 없음';
      return +active[1] > 90 ? 'PASS_MAX_DAYS ' + active[1] + ' — 90일 초과' : null;
    } }],
    safe: [{ pattern: text => { const m = /(?:^|>)\s*PASS_MAX_DAYS\s+([1-9]\d?)\b/m.exec(String(text || '').replace(/#[^\n<]*/g, '')); return m && +m[1] <= 90 ? 'PASS_MAX_DAYS ' + m[1] + ' (90일 이하)' : null; } }],
  },
  // postfix 로그 수준: debug_peer_level 기본(2) → 양호
  'os-linux-1922': {
    category: '로그/감사', title: 'SMTP 로그 수준', severity: '하',
    vuln: [{ pattern: /<Value>debug_peer_level<\/Value>\s*<Value>0<\/Value>/, reason: 'SMTP 디버그/로그 수준이 0' }],
    safe: [{ pattern: /<Value>debug_peer_level<\/Value>\s*<Value>[1-9]\d*<\/Value>/, reason: 'postfix 로그 수준 기본값 이상(감사 가능)' }],
  },
  // su 명령 제한: su 4755 + 그룹 root(wheel 아님) = 일반 사용자 su 가능
  'os-linux-2289': {
    category: '접근 제어', title: 'su 명령 제한', severity: '상',
    recommend: 'su 를 wheel 그룹 소유 4750 으로 제한하고 pam_wheel 을 활성화하십시오.',
    vuln: [{ pattern: /<Value>[^<]*\/su<\/Value>\s*<Value>(?!wheel)[^<]*<\/Value>\s*<Value>4755<\/Value>/, reason: 'su 명령이 그룹 제한 없이 전체 실행 가능(4755, wheel 아님)' }],
    safe: [{ pattern: /<Value>[^<]*\/su<\/Value>\s*<Value>wheel<\/Value>\s*<Value>47[05]0<\/Value>/, reason: 'su 명령이 wheel 그룹으로 제한(4750)' }],
  },
  // rsyslog cron 로그 설정 존재 → 양호
  'os-linux-2784': {
    category: '로그/감사', title: 'cron 로그 설정', severity: '하',
    vuln: [],
    safe: [{ pattern: /rsyslog\.conf:\d+:cron/, reason: 'rsyslog 에 cron 로그 설정 존재' }],
  },
  // smtpd_banner: 미설정(기본 배너) — 외부 노출 증거 없으면 양호
  'os-linux-2790': {
    category: '서비스 관리', title: 'SMTP 배너', severity: '하',
    vuln: [],
    safe: [{ pattern: text => /smtpd_banner/.test(text) && !/LISTEN[^\n]*(?:0\.0\.0\.0|::):25/.test(text) ? 'smtpd_banner 기본값 — 외부 노출 증거 없음' : null }],
  },

  // ═════════════════════════════════════════════
  // Windows — SecuMS raw(XML Dump) 항목별 룰 (2026-07-03)
  //   raw: W_SECEDIT/W_REGISSTRY/W_SERVICE 등 구조화 dump.
  //   dumpKV/dumpKVInt 는 <Value>KEY</Value> 바로 뒤 <Value> 를 값으로 읽는다.
  //   판정 입력은 raw 뿐 (P1) — SecuMS RESULT/MSG 는 사용하지 않는다.
  // ═════════════════════════════════════════════
  ...(() => {
    const { dumpKV, dumpKVInt, hasSeceditDump } = require('./mockSecumsDump');
    // secedit KV 항목: 값이 있으면 test 로 판정. secedit dump 가 수집됐는데 키가 없으면 미설정=취약.
    const kvRule = (key, test, vulnReason, safeReason) => ({
      vuln: [{ pattern: text => {
        const t = String(text || '');
        const v = dumpKVInt(t, key);
        if (v !== null) return test(v) ? null : vulnReason + ' (현재 ' + key + '=' + v + ')';
        const raw = dumpKV(t, key);
        if (raw !== null) return raw === '' ? vulnReason + ' (' + key + ' 값 비어있음)' : null;
        // 키 자체가 dump 에 없음: secedit 계열 dump 가 있으면 정책 미설정으로 판정
        return hasSeceditDump(t) ? vulnReason + ' (' + key + ' 미설정)' : null;
      } }],
      safe: [{ pattern: text => {
        const v = dumpKVInt(text, key);
        return v !== null && test(v) ? safeReason + ' (' + key + '=' + v + ')' : null;
      } }],
    });

    return {
      // 계정명 변경 여부: W_USERACCOUNT dump 에 기본 계정명 그대로 존재 (도메인 프리픽스 허용)
      'os-win-323': {
        category: '계정 관리', title: '기본 관리자 계정명 변경', severity: '상',
        recommend: 'Administrator 계정 이름을 추측하기 어려운 이름으로 변경하십시오.',
        vuln: [{ pattern: /<Value>(?:[\w.-]+\\)?Administrator<\/Value>/, reason: '기본 관리자 계정명(Administrator) 미변경' }],
        safe: [{ pattern: text => /CAPTION|NAME/i.test(text) && /<Dump/.test(text) && !/<Value>(?:[\w.-]+\\)?Administrator<\/Value>/.test(text) ? '기본 관리자 계정명이 변경됨' : null }],
      },
      // 계정 상태(CAPTION|STATUS): 기본 비활성 계정(Guest/DefaultAccount)의 Degraded 는 정상.
      // 그 외 계정이 Degraded/Error 면 취약, 나머지 전부 OK 면 양호.
      'os-win-322': {
        category: '계정 관리', title: '계정 상태 점검', severity: '중',
        vuln: [{ pattern: /<Value>(?:[\w.-]+\\)?(?!DefaultAccount<|Guest<)[\w.-]+<\/Value>\s*<Value>(?:Degraded|Error)<\/Value>/i, reason: '계정 상태 비정상(Degraded/Error)' }],
        safe: [{ pattern: text => {
          const t = String(text || '');
          return /<Value>OK<\/Value>/.test(t)
            && !/<Value>(?:[\w.-]+\\)?(?!DefaultAccount<|Guest<)[\w.-]+<\/Value>\s*<Value>(?:Degraded|Error)<\/Value>/i.test(t)
            ? '계정 상태 정상(기본 비활성 계정 제외 모두 OK)' : null;
        } }],
      },
      // secedit 정책 계열 — 항목별 포커스 키
      'os-win-326': { category: '비밀번호 정책', title: '최소 암호 길이', severity: '상', recommend: '최소 암호 길이를 8자 이상으로 설정하십시오.', ...kvRule('MinimumPasswordLength', v => v >= 8, '최소 암호 길이가 8자 미만', '최소 암호 길이 8자 이상') },
      'os-win-327': { category: '비밀번호 정책', title: '최근 암호 기억', severity: '중', recommend: '최근 암호 기억(PasswordHistorySize)을 설정하십시오.', ...kvRule('PasswordHistorySize', v => v >= 1, '최근 암호 기억 미설정 — 동일 암호 재사용 가능', '최근 암호 기억 설정') },
      'os-win-328': { category: '비밀번호 정책', title: '최소 암호 사용 기간', severity: '중', recommend: '최소 암호 사용 기간을 1일 이상으로 설정하십시오.', ...kvRule('MinimumPasswordAge', v => v >= 1, '최소 암호 사용 기간 미설정 — 즉시 재변경으로 기억 우회 가능', '최소 암호 사용 기간 설정') },
      'os-win-329': { category: '비밀번호 정책', title: '최대 암호 사용 기간', severity: '상', recommend: '최대 암호 사용 기간을 90일 이하로 설정하십시오.', ...kvRule('MaximumPasswordAge', v => v >= 1 && v <= 90, '최대 암호 사용 기간이 미설정 또는 90일 초과', '최대 암호 사용 기간 90일 이하') },
      'os-win-330': { category: '계정 관리', title: '계정 잠금 기간', severity: '중', recommend: '계정 잠금 기간(LockoutDuration)을 설정하십시오.', ...kvRule('LockoutDuration', v => v >= 1, '계정 잠금 기간 미설정', '계정 잠금 기간 설정') },
      'os-win-331': { category: '계정 관리', title: '계정 잠금 임계값', severity: '상', recommend: '계정 잠금 임계값을 5회 이하로 설정하십시오.', ...kvRule('LockoutBadCount', v => v >= 1 && v <= 10, '계정 잠금 임계값 미설정 — 무제한 암호 시도 가능', '계정 잠금 임계값 설정') },
      'os-win-360': { category: '비밀번호 정책', title: '암호 복잡도', severity: '상', recommend: '암호 복잡도 정책을 활성화하십시오.', ...kvRule('PasswordComplexity', v => v === 1, '암호 복잡도 정책 비활성', '암호 복잡도 정책 활성') },
      'os-win-361': { category: '비밀번호 정책', title: '복호화 가능한 암호 저장', severity: '상', ...kvRule('ClearTextPassword', v => v === 0, '암호를 복호화 가능한 형태로 저장', '복호화 가능한 암호 저장 안 함') },
      // 감사 정책 (Event Audit 섹션 Audit* 키들)
      'os-win-347': {
        category: '로그/감사', title: '감사 정책 설정', severity: '중',
        recommend: '계정 관리/로그온 이벤트 등 주요 감사 정책을 성공·실패로 설정하십시오.',
        vuln: [{ pattern: text => {
          const keys = ['AuditAccountManage', 'AuditAccountLogon', 'AuditLogonEvents', 'AuditPolicyChange', 'AuditPrivilegeUse'];
          const zero = keys.filter(k => dumpKVInt(text, k) === 0);
          return zero.length ? '감사 정책 미설정: ' + zero.join(', ') : null;
        } }],
        safe: [{ pattern: text => {
          const keys = ['AuditAccountManage', 'AuditAccountLogon', 'AuditLogonEvents'];
          const vals = keys.map(k => dumpKVInt(text, k));
          return vals.every(v => v !== null && v >= 1) ? '주요 감사 정책 활성' : null;
        } }],
      },
      // 이벤트 로그 덮어쓰기 정책
      'os-win-349': {
        category: '로그/감사', title: '이벤트 로그 덮어쓰기', severity: '중',
        recommend: '보안 이벤트 로그를 "이벤트 덮어쓰지 않음" 또는 보관 정책으로 설정하십시오.',
        vuln: [{ pattern: /<Value>(?:WhenNeeded|OutDated)<\/Value>/i, reason: '이벤트 로그 덮어쓰기 허용(WhenNeeded/OutDated)' }],
        safe: [{ pattern: /<Value>(?:Never|Archive)<\/Value>/i, reason: '이벤트 로그 덮어쓰기 제한/보관 설정' }],
      },
      // 익명 열거 제한 — 352/362 모두 restrictanonymous 기준(362 는 SAM·공유 열거로 sam 값도 함께 요구)
      'os-win-352': { category: '접근 제어', title: '익명 연결 제한', severity: '상', recommend: 'restrictanonymous 를 1 이상으로 설정하십시오.', ...kvRule('restrictanonymous', v => v >= 1, '익명 연결 제한 미설정(restrictanonymous=0)', '익명 연결 제한 적용') },
      'os-win-362': {
        category: '접근 제어', title: '익명 SAM/공유 열거 제한', severity: '상',
        recommend: 'restrictanonymous 및 restrictanonymoussam 을 1 이상으로 설정하십시오.',
        vuln: [{ pattern: text => {
          const ra = dumpKVInt(text, 'restrictanonymous');
          const sam = dumpKVInt(text, 'restrictanonymoussam');
          if (ra === null && sam === null) return null;
          if (ra !== null && ra < 1) return '익명 SAM/공유 열거 허용(restrictanonymous=' + ra + ')';
          if (sam !== null && sam < 1) return '익명 SAM 계정 열거 허용(restrictanonymoussam=' + sam + ')';
          return null;
        } }],
        safe: [{ pattern: text => {
          const ra = dumpKVInt(text, 'restrictanonymous');
          const sam = dumpKVInt(text, 'restrictanonymoussam');
          return (ra !== null && ra >= 1) && (sam === null || sam >= 1) ? '익명 SAM/공유 열거 제한 적용' : null;
        } }],
      },
      // Remote Registry 서비스
      'os-win-353': {
        category: '서비스 관리', title: 'Remote Registry 서비스', severity: '중',
        recommend: 'Remote Registry 서비스를 중지하고 시작 유형을 "사용 안 함"으로 설정하십시오.',
        vuln: [{ pattern: /Remote ?Registry[\s\S]{0,300}?<Value>(?:Auto|Running|Started|TRUE)<\/Value>|<Value>(?:Auto|Running)<\/Value>[\s\S]{0,120}?Remote ?Registry/i, reason: 'Remote Registry 서비스가 실행/자동 시작 상태' }],
        safe: [{ pattern: /Remote ?Registry[\s\S]{0,300}?<Value>(?:Disabled|Manual)<\/Value>/i, reason: 'Remote Registry 서비스 비활성/수동' }],
      },
      // 마지막 로그온 사용자 표시
      'os-win-357': { category: '접근 제어', title: '마지막 사용자 표시', severity: '하', recommend: 'DontDisplayLastUserName 을 1로 설정하십시오.', ...kvRule('DontDisplayLastUserName', v => v === 1, '마지막 로그온 사용자 이름 표시(정보 노출)', '마지막 로그온 사용자 표시 안 함') },
      // 로그온 배너 (LegalNotice)
      'os-win-363': {
        category: '접근 제어', title: '로그온 경고 배너', severity: '하',
        recommend: 'LegalNoticeCaption/Text 에 경고 문구를 설정하십시오.',
        vuln: [{ pattern: text => {
          const t = String(text || '');
          if (!/LegalNotice|Message (?:title|text) for users/i.test(t)) return null;
          const cap = dumpKV(t, 'LegalNoticeCaption'), txt = dumpKV(t, 'LegalNoticeText');
          return !cap && !txt ? '로그온 경고 배너(LegalNoticeCaption/Text) 미설정' : null;
        } }],
        safe: [{ pattern: text => { const cap = dumpKV(text, 'LegalNoticeCaption'); return cap ? '로그온 경고 배너 설정 확인' : null; } }],
      },
      // 접근제어(UAC 등) 상태: PROP/VALNAME/VALDATA 형식 — "Access Control | STATUS | OFF"
      'os-win-245': {
        category: '접근 제어', title: '접근 제어(UAC) 정책', severity: '중',
        recommend: 'UAC 등 접근 제어 정책을 활성화하십시오.',
        vuln: [{ pattern: /<Value>Access Control<\/Value>\s*<Value>STATUS<\/Value>\s*<Value>OFF<\/Value>/i, reason: '접근 제어(UAC) 정책 비활성(STATUS=OFF)' }],
        safe: [{ pattern: /<Value>Access Control<\/Value>\s*<Value>STATUS<\/Value>\s*<Value>ON<\/Value>/i, reason: '접근 제어(UAC) 정책 활성(STATUS=ON)' }],
      },
      // 로그온 전 시스템 종료 제한 (registry ARG 경로 병합 형식)
      'os-win-358': { category: '접근 제어', title: '로그온 전 종료 제한', severity: '중', recommend: 'shutdownwithoutlogon 을 0으로 설정하십시오.', ...kvRule('shutdownwithoutlogon', v => v === 0, '로그온 전 시스템 종료 허용', '로그온 전 시스템 종료 차단') },
      // 백신 (W_VIRUSVACCINE: PRODUCT/ISRUN/UPDATEDAY)
      'os-win-2560': {
        category: '시스템 보안', title: '백신 설치/실행', severity: '상',
        recommend: '백신 프로그램을 설치하고 실시간 보호를 활성화하십시오.',
        vuln: [{ pattern: text => {
          const t = String(text || '');
          if (!/VIRUSVACCINE|PRODUCT|ISRUN|백신|vaccine|antivirus/i.test(t)) return null;
          if (/<Rows count="0"/.test(t)) return '백신 제품 미검출(설치 정보 없음)';
          if (/ISRUN/i.test(t) && /<Value>(?:false|0|no)<\/Value>/i.test(t)) return '백신이 설치되어 있으나 미실행';
          return null;
        } }],
        safe: [{ pattern: text => /ISRUN/i.test(String(text || '')) && /<Value>(?:true|1|yes)<\/Value>/i.test(String(text || '')) ? '백신 실행 중' : null }],
      },
      'os-win-2561': {
        category: '시스템 보안', title: '백신 업데이트', severity: '상',
        recommend: '백신 엔진을 최신으로 업데이트하십시오.',
        vuln: [{ pattern: text => {
          const t = String(text || '');
          if (!/VIRUSVACCINE|UPDATEDAY|백신|vaccine|antivirus/i.test(t)) return null;
          if (/<Rows count="0"/.test(t)) return '백신 미설치 — 업데이트 적용 불가';
          return null;
        } }],
        safe: [],
      },
      // 파일 ACL 계열: Users/앱 패키지 권한 존재
      'os-win-342': {
        category: '파일/공유 권한', title: '시스템 파일 접근 권한', severity: '중',
        recommend: '시스템 경로에서 Users/응용 프로그램 패키지 등 불필요 계정 권한을 제거하십시오.',
        vuln: [{ pattern: /<Value>(?:Users|BUILTIN\\Users|모든 제한된 응용 프로그램 패키지|ALL APPLICATION PACKAGES)<\/Value>/, reason: '시스템 경로에 Users/응용 패키지 계정 권한 존재' }],
        safe: [{ pattern: text => /PERMISSION|ACCOUNT/i.test(String(text || '')) && /<Dump/.test(String(text || '')) && !/<Value>(?:Users|BUILTIN\\Users|모든 제한된 응용 프로그램 패키지|ALL APPLICATION PACKAGES)<\/Value>/.test(String(text || '')) ? '불필요 계정 권한 없음' : null }],
      },
      'os-win-2637': {
        category: '파일/공유 권한', title: '중요 경로 접근 권한', severity: '중',
        vuln: [{ pattern: /<Value>(?:모든 제한된 응용 프로그램 패키지|ALL APPLICATION PACKAGES)<\/Value>/, reason: '중요 경로에 응용 프로그램 패키지 계정 권한 존재' }],
        safe: [],
      },
      // 잔여 4건 직접 룰 (probe arg 기반, SecuMS 기준 정렬)
      // 325: PasswordComplexity (360과 동일 대상 — 다른 os-win 이지만 같은 정책 키)
      'os-win-325': { category: '비밀번호 정책', title: '암호 복잡도', severity: '상', recommend: '암호 복잡도 정책을 활성화하십시오.', ...kvRule('PasswordComplexity', v => v === 1, '암호 복잡도 정책 비활성', '암호 복잡도 정책 활성') },
      // 345: 화면보호기 — 서버에서 SCRNSAVE 미설정은 SecuMS 기준 허용(OK). 수집됐으면 양호.
      'os-win-345': {
        category: '접근 제어', title: '화면보호기 설정', severity: '하',
        vuln: [{ pattern: /<Value>SCRNSAVE\.EXE<\/Value>\s*<Value>[^<]+\.scr<\/Value>[\s\S]{0,80}<Value>ScreenSaverIsSecure<\/Value>\s*<Value>0<\/Value>/i, reason: '화면보호기 설정됨 but 암호 잠금(Secure) 비활성' }],
        safe: [{ pattern: text => /SCRNSAVE\.EXE|ScreenSaver/i.test(String(text || '')) ? '화면보호기 정책 수집 — 서버 환경 기준 허용' : null }],
      },
      // 359: DEP(DataExecutionPrevention) — SupportPolicy>=2 또는 Available/Drivers=True 면 양호
      'os-win-359': {
        category: '시스템 보안', title: 'DEP(데이터 실행 방지)', severity: '중',
        vuln: [{ pattern: /DataExecutionPrevention[\s\S]{0,40}<Value>(?:0|1)<\/Value>[\s\S]{0,40}<Value>False<\/Value>/i, reason: 'DEP 미적용(SupportPolicy 낮음/미지원)' }],
        safe: [{ pattern: /DataExecutionPrevention[\s\S]{0,40}<Value>[23]<\/Value>|DataExecutionPrevention[\s\S]{0,60}<Value>True<\/Value>/i, reason: 'DEP 활성(DataExecutionPrevention 적용)' }],
      },
      // 2650: PowerShell ExecutionPolicy — Unrestricted/Bypass 취약, RemoteSigned/AllSigned/Restricted 양호
      'os-win-2650': {
        category: '시스템 보안', title: 'PowerShell 실행 정책', severity: '중',
        recommend: 'PowerShell 실행 정책을 RemoteSigned 이상으로 설정하십시오.',
        vuln: [{ pattern: /Get-ExecutionPolicy[\s\S]{0,80}<Value>(?:Unrestricted|Bypass)<\/Value>/i, reason: 'PowerShell 실행 정책이 Unrestricted/Bypass(서명 미검증)' }],
        safe: [{ pattern: /Get-ExecutionPolicy[\s\S]{0,80}<Value>(?:RemoteSigned|AllSigned|Restricted)<\/Value>/i, reason: 'PowerShell 실행 정책이 서명 검증(RemoteSigned/AllSigned/Restricted)' }],
      },
    };
  })(),
};

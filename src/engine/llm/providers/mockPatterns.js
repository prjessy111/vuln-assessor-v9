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
};

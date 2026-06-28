'use strict';
/**
 * 안전 게이트 (Safety Gate)
 *
 * 자율 진단 루프(3-2)에서 LLM이 생성한 점검 스크립트를 실행 승인하기 전,
 * 위험 명령을 정적으로 검사한다.
 *
 * 원칙 (VULN_ASSESSOR_TODO.md §0, §3-2):
 *  - 점검 스크립트는 "읽기 전용"이어야 한다. 시스템 상태를 바꾸면 안 된다.
 *  - 위험 명령(파괴/네트워크 다운로드 실행/권한 변경 등)은 차단(blocked).
 *  - 애매한 명령(쓰기 가능성)은 경고(warning) → 사람이 최종 판단.
 *  - 화이트리스트에 없는 명령이라고 무조건 막지 않는다(과차단 방지). 단,
 *    블랙리스트에 걸리면 무조건 blocked.
 *
 * 반환:
 *   { risk: 'safe' | 'warning' | 'blocked', hits: [{level, pattern, line, snippet, why}] }
 */

// 무조건 차단 — 파괴적이거나 시스템을 변경/오염시키는 명령
const BLOCK_RULES = [
  { re: /\brm\s+(-[a-z]*\s+)*-[a-z]*r/i, why: 'rm -r 재귀 삭제' },
  { re: /\brm\s+(-[a-z]*\s+)*-[a-z]*f/i, why: 'rm -f 강제 삭제' },
  { re: /\b(mkfs|fdisk|parted|wipefs)\b/i, why: '디스크 포맷/파티션' },
  { re: /\bdd\b[^\n]*\bof=/i, why: 'dd of= 디스크 쓰기' },
  { re: /\b(shutdown|reboot|halt|poweroff|init\s+[06])\b/i, why: '시스템 종료/재부팅' },
  { re: /\b(mkfs|swapoff|swapon)\b/i, why: '파일시스템 변경' },
  { re: /\b(useradd|userdel|usermod|groupadd|groupdel|chpasswd)\b/i, why: '계정 변경' },
  // 'passwd'는 명령으로 쓰일 때만 차단 (/etc/passwd 같은 파일 경로 점검은 정상 허용)
  { re: /(^|[;&|]|\bsudo\s+)\s*passwd\b/i, why: 'passwd 명령 (비밀번호 변경)' },
  { re: /\b(iptables|nft|ufw|firewall-cmd)\b[^\n]*(-A|-D|-I|--add|--remove|--delete)/i, why: '방화벽 규칙 변경' },
  { re: /\b(systemctl|service)\b[^\n]*\b(start|stop|restart|reload|enable|disable|mask)\b/i, why: '서비스 상태 변경' },
  { re: /\bchattr\b/i, why: '파일 속성 변경' },
  { re: /\b(curl|wget)\b[^\n]*\|\s*(sh|bash|python|perl)/i, why: '원격 다운로드 후 실행' },
  { re: /\b(curl|wget|nc|ncat|netcat)\b/i, why: '외부 네트워크 통신 (raw 유출 위험)' },
  { re: /\b(crontab|at)\b\s+-?\w/i, why: '예약 작업 등록' },
  { re: /\bkill(all)?\b/i, why: '프로세스 강제 종료' },
  { re: /\b(eval|exec)\b/i, why: '동적 코드 실행' },
  { re: /:\(\)\s*\{.*\}\s*;/, why: 'fork bomb 패턴' },
  // PowerShell 파괴/변경 계열
  { re: /\bRemove-Item\b/i, why: 'PowerShell 파일 삭제' },
  { re: /\b(Set|New|Stop|Start|Restart|Disable|Enable)-Service\b/i, why: 'PowerShell 서비스 변경' },
  { re: /\b(Set-ItemProperty|New-ItemProperty|Remove-ItemProperty)\b/i, why: '레지스트리 쓰기' },
  { re: /\bSet-(Acl|ExecutionPolicy|LocalUser|ADAccountPassword)\b/i, why: 'PowerShell 권한/계정 변경' },
  { re: /\b(Stop|Restart)-Computer\b/i, why: 'PowerShell 시스템 종료/재부팅' },
  { re: /\b(Invoke-WebRequest|Invoke-RestMethod|iwr|irm)\b/i, why: 'PowerShell 외부 통신' },
  { re: /\bInvoke-Expression\b|\biex\b/i, why: 'PowerShell 동적 실행' },
];

// 경고 — 즉시 위험하진 않으나 쓰기/변경 가능성. 사람 확인 필요.
const WARN_RULES = [
  { re: /\b(chmod|chown|chgrp)\b/i, why: '권한/소유자 변경 가능 (점검은 조회만 해야 함)' },
  { re: />>?\s*\/(?!dev\/null|proc|sys)/i, why: '파일 리다이렉트 쓰기' },
  { re: /\b(mv|cp|touch|mkdir|ln|install)\b/i, why: '파일시스템 쓰기 가능' },
  { re: /\b(tee)\b/i, why: 'tee 파일 쓰기 가능' },
  { re: /\b(sed|perl|awk)\b[^\n]*-i\b/i, why: 'in-place 파일 수정' },
  { re: /\bsudo\b/i, why: 'sudo 권한 상승 (조회 목적인지 확인)' },
  { re: /\bOut-File\b|\bSet-Content\b|\bAdd-Content\b/i, why: 'PowerShell 파일 쓰기' },
];

// 참고용 — 점검에 일반적으로 안전한 읽기 전용 명령(정보 제공 목적)
const READONLY_HINTS = [
  'cat', 'grep', 'egrep', 'awk', 'sed -n', 'ls', 'stat', 'find', 'head', 'tail',
  'wc', 'cut', 'sort', 'uniq', 'id', 'who', 'last', 'uname', 'hostname', 'date',
  'rpm -q', 'dpkg -l', 'systemctl status', 'systemctl is-enabled', 'sshd -T',
  'sysctl', 'getent', 'ss', 'netstat', 'ps', 'mount', 'df', 'lsmod', 'crontab -l',
  'Get-Content', 'Get-Item', 'Get-ItemProperty', 'Get-Acl', 'Get-Service',
  'Get-LocalUser', 'Get-LocalGroup', 'Get-CimInstance', 'Get-WmiObject', 'Test-Path',
];

function _scan(rules, code, level) {
  const hits = [];
  const lines = String(code || '').split(/\r?\n/);
  lines.forEach((line, i) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('//')) return; // 주석 제외
    for (const rule of rules) {
      if (rule.re.test(line)) {
        hits.push({
          level,
          pattern: rule.re.source,
          why: rule.why,
          line: i + 1,
          snippet: trimmed.slice(0, 160),
        });
      }
    }
  });
  return hits;
}

/**
 * 스크립트 안전성 검사.
 * @param {string} code - 생성된 스크립트 본문
 * @returns {{ risk:'safe'|'warning'|'blocked', hits:Array }}
 */
function inspect(code) {
  if (!code || !String(code).trim()) {
    return { risk: 'blocked', hits: [{ level: 'block', why: '빈 스크립트', line: 0, snippet: '' }] };
  }
  const blockHits = _scan(BLOCK_RULES, code, 'block');
  const warnHits = _scan(WARN_RULES, code, 'warn');
  const hits = [...blockHits, ...warnHits];

  let risk = 'safe';
  if (blockHits.length) risk = 'blocked';
  else if (warnHits.length) risk = 'warning';

  return { risk, hits };
}

module.exports = { inspect, BLOCK_RULES, WARN_RULES, READONLY_HINTS };

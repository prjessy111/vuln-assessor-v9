'use strict';
// Mock 판정 LLM-수준화 스모크 테스트 — 결정론성 + 핵심 시나리오
const MockProvider = require('E:/backup2/vuln-assessor-v9-main/src/engine/llm/providers/mock.js');

function prompt(chkId, body, criteria = '') {
  return `당신은 보안 검증 솔루션의 독립 판정 엔진입니다.
## 진단 항목
- CHK_ID: ${chkId}
${criteria}
## 점검 액션 및 결과
raw 점검 데이터
### 액션 1: 점검
타입: CMD
실행 결과:
\`\`\`
${body}
\`\`\`
`;
}

async function judge(chkId, body, criteria) {
  const p = new MockProvider({});
  const r = await p.complete({ user: prompt(chkId, body, criteria) });
  return JSON.parse(r);
}

(async () => {
  let fail = 0;
  const check = (name, actual, expected) => {
    const ok = actual === expected;
    if (!ok) fail++;
    console.log(`${ok ? 'PASS' : 'FAIL'} ${name}: verdict=${actual} (expected ${expected})`);
  };

  // 1. 레지스트리 값 부재 → 더 이상 부재양호가 아님 (SRV-001: 키 부재 = 강화 미적용 = 취약)
  let r = await judge('SRV-001', `cmd# reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v LmCompatibilityLevel
ERROR: Registry key value not found.
cmd# sc query SNMP
[SC] EnumQueryServicesStatus 실패 1060`);
  check('레지스트리 키 부재 = 취약(NTLMv2 미강제)', r.verdict, '취약');

  // 2. LmCompatibilityLevel=5 + SNMP 미설치 → 취약 아님
  r = await judge('SRV-001', `cmd# reg query "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v LmCompatibilityLevel
    LmCompatibilityLevel    REG_DWORD    0x5
cmd# sc query SNMP
[SC] EnumQueryServicesStatus 실패 1060`);
  console.log(`INFO LmCompat=5: verdict=${r.verdict} reason=${r.reason.slice(0, 80)}`);

  // 3. 순수 객체 부재(파일 없음)는 여전히 부재양호
  r = await judge('SRV-024', `$ ls /etc/xinetd.d/telnet
ls: cannot access /etc/xinetd.d/telnet: No such file or directory`);
  check('파일 부재 = 부재양호', r.verdict, '양호');

  // 4. SRV-096: 0644 dotfile → 취약 (2026 기준 others read도 취약)
  r = await judge('SRV-096', `$ ls -al /home/jessy/.bashrc
-rw-r--r-- 1 jessy jessy 231 Jan  1 00:00 /home/jessy/.bashrc`);
  check('dotfile 0644 = 취약', r.verdict, '취약');

  // 5. SRV-096: 0600 dotfile → 양호
  r = await judge('SRV-096', `$ ls -al /home/jessy/.bashrc
-rw------- 1 jessy jessy 231 Jan  1 00:00 /home/jessy/.bashrc`);
  check('dotfile 0600 = 양호', r.verdict, '양호');

  // 6. SRV-070: shadow $6$ → 양호
  r = await judge('SRV-070', `$ cat /etc/shadow
root:$6$abcdefgh$xyz:19000:0:99999:7:::
jessy:$6$ijklmnop$qrs:19000:0:99999:7:::`);
  check('shadow SHA-512 = 양호', r.verdict, '양호');

  // 7. SRV-022: 잠금 계정만 존재 → 양호 (빈 암호 아님)
  r = await judge('SRV-022', `$ cat /etc/shadow
root:$6$abc$def:19000:0:99999:7:::
bin:*:19000:0:99999:7:::
daemon:!!:19000:0:99999:7:::`);
  check('잠금 계정(*,!!) = 양호', r.verdict, '양호');

  // 8. SRV-022: 빈 암호 계정 → 취약
  r = await judge('SRV-022', `$ cat /etc/shadow
root:$6$abc$def:19000:0:99999:7:::
testuser::19000:0:99999:7:::`);
  check('빈 암호 계정 = 취약', r.verdict, '취약');

  // 9. SRV-063: DNS가 loopback/내부 가상대역에만 LISTEN → 양호
  r = await judge('SRV-063', `$ netstat -lntp | grep :53
tcp 0 0 127.0.0.1:53 0.0.0.0:* LISTEN 1234/named
tcp 0 0 192.168.122.1:53 0.0.0.0:* LISTEN 1234/named`);
  check('DNS 내부전용 LISTEN = 양호', r.verdict, '양호');

  // 10. SRV-177: sudo 부여 0행 + 타 액션 정상 → 양호
  r = await judge('SRV-177', `<Dump type="table"><Columns><Column>SUDO_USER</Column></Columns><Rows count="0"/></Dump>
<Dump type="table"><Columns><Column>GROUP</Column></Columns><Rows count="3"><Row><Value>root</Value></Row></Rows></Dump>
sudo 권한 부여 현황 점검`);
  check('sudo 부여 0행 = 양호', r.verdict, '양호');

  // 11. SRV-075: minclass=0 이지만 minlen=8 → 양호 (과탐 방지)
  r = await judge('SRV-075', `$ cat /etc/security/pwquality.conf
minlen = 8
minclass = 0`);
  check('minclass=0 + minlen=8 = 양호', r.verdict, '양호');

  // 12. 판정 기준 섹션이 있으면 사유/권고에 반영 (LLM 수준 출력)
  r = await judge('SRV-026', `$ cat /etc/ssh/sshd_config | grep PermitRootLogin
PermitRootLogin yes`, `
## 점검 기준 (raw 출력을 이 기준에 비춰 결정적으로 판정)
- 점검 항목: SSH 서비스 설정
- 점검 의도: SSH 서비스와 sshd_config 보안 설정 확인
- 양호 기준: root 로그인 차단 및 안전한 SSH 설정
- 취약 조건: root 원격 로그인 허용 등 위험 설정

### 2026 공식 판정 기준 (금융보안원 전자금융기반시설 — 최우선·엄격 적용)
- 판정 기준: PermitRootLogin no 설정 여부 확인
- 조치법(=안전한 상태는 이 조치가 적용된 상태): /etc/ssh/sshd_config에서 PermitRootLogin no 설정 후 sshd 재시작
`);
  check('PermitRootLogin yes = 취약', r.verdict, '취약');
  console.log(`  reason: ${r.reason}`);
  console.log(`  recommend: ${r.recommend}`);
  if (!r.reason.includes('취약 기준')) { fail++; console.log('FAIL 사유에 취약 기준 미반영'); }
  if (!r.recommend.includes('PermitRootLogin no')) { fail++; console.log('FAIL 권고에 2026 조치법 미반영'); }

  // 13. 결정론성: 동일 입력 2회 → byte-identical
  const p1 = new MockProvider({});
  const p2 = new MockProvider({});
  const samePrompt = prompt('SRV-096', `$ ls -al /home/jessy/.bashrc\n-rw-r--r-- 1 jessy jessy 231 Jan 1 00:00 /home/jessy/.bashrc`);
  const a = await p1.complete({ user: samePrompt });
  const b = await p2.complete({ user: samePrompt });
  const c = await p1.complete({ user: samePrompt }); // 같은 인스턴스 반복 호출도 동일해야 함
  if (a === b && b === c) console.log('PASS 결정론성: 동일 입력 3회 byte-identical');
  else { fail++; console.log('FAIL 결정론성 위반'); }

  // 14. _ruleEvalMock 결정론성 (호출 횟수 무관)
  const p3 = new MockProvider({});
  const r1 = await p3.complete({ user: 'random unmatched input', responseFormat: 'json' });
  const r2 = await p3.complete({ user: 'random unmatched input', responseFormat: 'json' });
  if (r1 === r2) console.log('PASS ruleEval 결정론성');
  else { fail++; console.log(`FAIL ruleEval 비결정론: ${r1} vs ${r2}`); }

  console.log(fail === 0 ? '\n== ALL PASS ==' : `\n== ${fail} FAILURES ==`);
  process.exit(fail === 0 ? 0 : 1);
})();

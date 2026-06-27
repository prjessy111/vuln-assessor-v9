# 정합성 분석 보고서 — KISA 30 vs SecuMS 64

> 작성: 2026-05-24
> 대상 데이터: `exportData-SSUnix.db` (jessy62 CentOS 7.5.1804)

## 1. 핵심 결론

**SecuMS와 본 시스템의 항목 수가 다른 것은 정상이며, 점검 범위가 다릅니다.**

| 시스템 | 점검 항목 | 결과 분포 |
|---|---|---|
| **SecuMS** (LSware 자체 표준) | 64개 | OK 34 / BAD 14 / INFO 2 / WAIT 14 |
| **본 시스템** (KISA 가이드 30개) | 30개 | 취약 8 / 양호 21 / 점검불가 1 |

같은 raw 데이터를 두 시스템이 서로 다른 정책으로 점검하므로 단순 비교가 불가능합니다.

## 2. 항목 차이 원인

### 2.1 SecuMS가 64개인 이유
SecuMS는 KISA 가이드 + 자체 추가 항목을 점검합니다:
- 메일 서버 권한 (`os-linux-41`: postsuper)
- root 홈 디렉토리 존재 여부 (`os-linux-340`)
- 사용자 세션 타임아웃 TMOUT (`os-linux-344`)
- 로그 권한 (`os-linux-374`)
- 컴파일러 권한 (`os-linux-440`: cc, gcc)
- 홈 디렉토리 소유자 (`os-linux-2576`)

### 2.2 본 시스템이 30개인 이유
KISA "주요정보통신기반시설 기술적 취약점 분석·평가 방법 상세가이드" 중
**위험도 "상"** 30개 항목만 구현 (`rules/secums-unix-v2.0.yaml`).

## 3. 비교 가능한 영역 정합성

### 3.1 raw DB로 매핑 검증된 8건
SecuMS의 14개 BAD 항목 중 MSG 분석으로 KISA U-XX와 동일 영역임이 확인된 8건:

| SecuMS CHK_ID | KISA | 점검 영역 | SecuMS | 본 시스템 | 일치 |
|---|---|---|---|---|---|
| os-linux-383 | U-01 | PermitRootLogin + pam_securetty | BAD | 취약 | ✓ |
| os-linux-377 | U-04 | PASS_MAX_DAYS=99999 등 | BAD | 양호 | ✗ |
| os-linux-273 | U-13 | SUID/SGID (at, newgrp, pkexec) | BAD | 양호 | ✗ |
| os-linux-1998 | U-14 | .bash_profile, .bashrc 권한 | BAD | 양호 | ✗ |
| os-linux-254 | U-17 | TCP Wrappers AccessControl | BAD | 양호 | ✗ |
| os-linux-2389 | U-19 | Anonymous FTP (port 21) | BAD | 취약 | ✓ |
| os-linux-34 | U-21 | /etc/at.deny, /usr/bin/crontab | BAD | 양호 | ✗ |
| os-linux-335 | U-30 | postfix disable_vrfy_command | BAD | 취약 | ✓ |

**검증된 매핑 일치율: 3/8 = 37.5%**

### 3.2 불일치 원인 분석

#### A. mock LLM 임의 판정 (가장 큰 원인)
30개 룰 중 13개는 LLM 평가 룰이고, mock 모드에서는 mock LLM이 실제 데이터를 보지 않고 임의 판정합니다.

| 평가 방식 | 룰 수 | 신뢰도 |
|---|---|---|
| simple_check (deterministic) | 17개 | ✓ 실제 raw 데이터 평가 |
| LLM 평가 | 13개 | ⚠ mock 모드에서 임의 — **실서비스에서 Ollama/실 LLM 연결 필요** |

**영향**: U-04, U-13, U-14, U-17 등은 LLM 룰이라 mock 모드에서는 정확하지 않습니다.

#### B. simple_check 점검 대상 차이
일부 simple_check 룰이 SecuMS와 다른 파일을 점검합니다:
- **U-21 (cron 파일 권한)**: 본 시스템은 `/etc/crontab`, `/etc/cron.allow`, `/etc/cron.deny`만 점검.
  SecuMS의 `os-linux-34`는 `/etc/at.deny`, `/usr/bin/crontab` 권한도 점검.

해결책: 룰셋의 `context_sql`에 점검 대상 파일을 추가.

#### C. 본 시스템 false positive (mock LLM 과잉 판정)
- U-03, U-10, U-26: SecuMS는 OK/WAIT인데 본 시스템은 취약으로 판정 → mock LLM의 임의 판정.

## 4. SecuMS BAD 중 KISA 30 외 영역 (6건)

본 시스템에 매핑되지 않는 SecuMS BAD 항목:
- `os-linux-41`: 메일 서버 권한 (postsuper)
- `os-linux-340`: root 홈 디렉토리 존재
- `os-linux-344`: 사용자 TMOUT 세션 타임아웃 (9건 BAD)
- `os-linux-374`: 로그 파일 권한 (wtmp)
- `os-linux-440`: 컴파일러 권한 (cc, gcc)
- `os-linux-2576`: 홈 디렉토리 소유자 invalid

이들은 KISA 가이드의 "상" 등급 30개에는 포함되지 않으나, 운영 환경에 따라 추가 점검이 필요할 수 있음.

## 5. SecuMS 점검 미수행 (WAIT) 14건
SecuMS 정책에는 포함됐지만 raw DB에 결과 없음:
- os-linux-271, 279, 318, 380, 389
- os-linux-2289, 2369, 2586, 2596, 2788, 2790, 2793
- os-linux-3072, 3076

원인 추정: SecuMS Agent의 일부 모듈이 미실행되었거나 정책 적용 누락.

## 6. 권장 조치

### 즉시
1. **운영 환경에서는 실 LLM 연결** (Ollama gemma2:9b 또는 외부 API)
   - mock LLM 13개 룰이 정상 동작하면 정합성 90% 이상 가능
2. **simple_check 룰 점검 대상 보강**
   - U-21에 `/etc/at.deny`, `/usr/bin/crontab` 추가
3. **매핑 표 검증 확대**
   - 현재 8건 검증, 22건 추정 — 추가 검증 진행

### 중기
4. **LLM 평가 룰 → simple_check 전환 검토**
   - 가능한 항목은 deterministic으로 (예: U-01의 PermitRootLogin 검사는 단순 문자열 매칭으로 충분)
5. **KISA 30 외 영역 확장 여부 결정**
   - SecuMS가 추가로 점검하는 6개 항목 운영 가치 검토

### 장기
6. **운영 데이터로 매핑 표 자동 학습**
   - 다수 진단 결과의 BAD MSG와 우리 결과를 매칭하여 추정 매핑 검증 자동화

## 7. 신뢰할 수 있는 결과만 사용하려면

`/diagnosis/:id/validate` 페이지에서:
- **simple 평가 17건** → 신뢰 가능 (단, U-21 등 일부는 점검 대상 보강 필요)
- **mock-llm 평가 13건** → mock 모드에서는 무시, 실 LLM 연결 후 재진단 필요

또는 `rules/secums-unix-v2.0.yaml`에서 `enabled: false`로 LLM 룰 일시 차단 가능.

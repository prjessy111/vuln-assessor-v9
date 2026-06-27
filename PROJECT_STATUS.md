# Vuln Assessor v9.20 — 완성/미완성 상태 보고서

> 작성: 2026-05-24
> 대상: SecuMS Unix Agent 기반 취약점 진단 시스템 (Mock 모드 + MySQL 폴백)

---

## 1. 전체 개요

| 항목 | 상태 |
|---|---|
| 동작 모드 | Mock 모드 (파일 기반 저장) + MySQL 모드 (자동 폴백) |
| 진단 룰 | KISA 30개 (`rules/secums-unix-v2.0.yaml`) |
| CVE DB | 큐레이션 25건 + NVD/KEV 보강 (3건 동기화됨) |
| Raw 데이터 | SecuMS Unix Agent SQLite (`exportData-SSUnix.db`) |
| Node 요구 | v18+ (개발 검증: v22.22.2) |
| 외부 의존성 | express, ejs, multer, js-yaml, sql.js, exceljs |

---

## 2. 기능별 완성 상태

### 2.1 핵심 진단 — ✅ 완성

| 기능 | 상태 | 비고 |
|---|---|---|
| SecuMS SQLite 어댑터 | ✅ | sql.js (WASM 폴백), better-sqlite3 미설치 환경에서도 동작 |
| KISA 30개 룰 평가 | ✅ | YAML 기반, 룰 엔진 v2 |
| 진단 결과 저장 | ✅ | `data/mock/diagnoses.json` (mock 모드) |
| 진단 리포트 (FSI) | ✅ | `/reports/:id/fsi` |
| 정합성 검증 | ✅ | `/diagnosis/:id/validate` |
| 평균 진단 시간 | ✅ | 30룰 평가 < 200ms (1대 기준) |

### 2.2 CVE 자동 진단 — ✅ 완성

| 기능 | 상태 | 비고 |
|---|---|---|
| 패키지 추출 (rpm -qa) | ✅ | `secumsUnix.extractPackages()` — 1324건 추출 확인 |
| CVE 매칭 엔진 | ✅ | 결정론적 (LLM 미사용), 버전 범위 비교 |
| 백포팅 자동 인식 | ✅ | CentOS release 비교 — `*.el7_9` 패치 인식 |
| CISA KEV 우선순위 | ✅ | `sortByPriority()` |
| `/diagnosis/:id/cve` 화면 | ✅ | 1324 패키지 → 20 CVE 매칭, CRITICAL 4 / HIGH 13 |

### 2.3 CVE Sync (큐레이션 ↔ NVD/KEV) — ✅ 완성

| 기능 | 상태 | 비고 |
|---|---|---|
| 큐레이션 DB | ✅ | 25건, 사람이 검증한 매칭 룰 |
| Enrichment 보강 | ✅ | NVD CVSS / 설명 / KEV 플래그 자동 머지 |
| `scripts/sync-cve.js` CLI | ✅ | `--full`, `--kev-only`, `--from-file`, `--dry-run` |
| 모듈 인터페이스 (`run(opts)`) | ✅ | 라우트에서 직접 호출 가능 |
| `/cve-sync` 관리 화면 | ✅ | 통계 5 KPI + Untracked KEV + 이력 표 |
| 파일 업로드 동기화 | ✅ | NVD `.json` / `.json.gz` 200MB 지원 (폐쇄망용) |
| 매처 캐시 자동 무효화 | ✅ | 동기화 후 다음 진단부터 갱신 반영 |
| Untracked KEV 알림 | ⚠ 부분 | 화면 표시만 — 자동 알림은 미연결 |

### 2.4 예약 진단 — ✅ 완성

| 기능 | 상태 | 비고 |
|---|---|---|
| cron 파서 (5필드 표준) | ✅ | 외부 의존성 0, 단위 테스트 14/14 통과 |
| 백그라운드 폴링 스케줄러 | ✅ | 기본 60초 주기, `SCHEDULER_INTERVAL_MS` 조정 가능 |
| 시각 도래 시 자동 실행 | ✅ | jessy62 대상 자동 진단 동작 확인 |
| 대상 서버 선택 (all/group/list) | ✅ | `server_scope`로 분기 |
| 실행 이력 적재 | ✅ | `schedule_runs.json` 최근 200건 |
| triggered_by 구분 (cron/manual) | ✅ | 수동 즉시 실행도 정확히 분리 기록 |
| 신규 등록 폼 | ✅ | cron 미리보기 (다음 5회 실행 시각) |
| 편집 폼 | ✅ | prefill + cron 변경 시 next_run_at 자동 재계산 |
| 활성/비활성 토글 | ✅ | next_run_at 자동 갱신 |
| 즉시 실행 (수동) | ✅ | `/schedules/:id/run-now` |
| 삭제 | ✅ | 관리자만 |
| 실행 이력 상세 페이지 | ✅ | KPI 5개 + 서버별 결과 + 리포트/CVE 링크 |
| 7일 캘린더 | ✅ | 실데이터 기반 |
| 알림 옵션 (실패/취약) | ✅ | 스케줄별 `notify_on_*` 플래그 |

### 2.5 알림 발송 — ✅ 완성

| 기능 | 상태 | 비고 |
|---|---|---|
| console 어댑터 (기본) | ✅ | 외부 호출 없이 동작 |
| Slack 어댑터 | ✅ | 자체 https 구현, nodemailer 등 외부 의존성 없음 |
| Email 어댑터 (nodemailer) | ✅ | optional — 미설치 시 자동 폴백 |
| 다중 채널 동시 발송 | ✅ | `NOTIFIER_CHANNELS=console,slack` |
| 발송 실패 안전 처리 | ✅ | throw 없이 ok:false 반환 (timeout/ECONNREFUSED 등) |
| 이력 적재 | ✅ | `notifications.json` 최근 500건 |
| 예약 진단 자동 트리거 | ✅ | `schedule_failed` / `schedule_vuln_found` |
| `/notifications` 관리 화면 | ✅ | 이력 + 채널 설정 표시 |
| 테스트 발송 | ✅ | 관리 화면에서 즉시 발송 |
| 수동 진단 알림 | ❌ 미구현 | 운영자가 결과를 즉시 보므로 우선순위 낮음 |
| 발송 실패 재시도 큐 | ❌ 미구현 | 현재는 1회 시도 후 ok:false 기록 |

### 2.6 사용자 관리 / 인증 — ✅ 완성

| 기능 | 상태 |
|---|---|
| 로그인 / 세션 관리 | ✅ |
| 비밀번호 변경 강제 (최초 로그인) | ✅ |
| 역할 기반 인가 (admin/operator/viewer) | ✅ |
| 사용자 CRUD | ✅ |
| 기본 admin 자동 생성 | ✅ |

### 2.7 그 외 화면 — ✅ 완성

| 화면 | URL | 상태 |
|---|---|---|
| 대시보드 | `/` | ✅ |
| 진단 관리 | `/diagnosis` | ✅ |
| 진단 결과 업로드 | `/diagnosis/upload` | ✅ |
| 진단 결과 정합성 검증 | `/diagnosis/:id/validate` | ✅ |
| 취약점 관리 | `/vulnerabilities` | ✅ |
| 조치 관리 | `/remediation` | ✅ |
| 서버 관리 | `/servers` | ✅ |
| 룰셋 관리 | `/rulesets` | ✅ |
| 예외 관리 | `/exceptions` | ✅ |
| 제외 관리 | `/exclusions` | ✅ |

### 2.8 저장소 — ✅ 완성

| 모드 | 상태 |
|---|---|
| Mock (파일 기반) | ✅ 기본 |
| MySQL | ✅ `DB_MODE=mysql` 환경변수로 전환, 실패 시 mock 자동 폴백 |
| MySQL 테이블 자동 생성 | ✅ `_kv_store(name VARCHAR(64), data JSON)` |
| 원자적 파일 쓰기 | ✅ tmp → rename |

---

## 3. 운영 보강 — ⚠ 미구현 (운영 환경 적용 전 필수)

| 항목 | 상태 | 비고 |
|---|---|---|
| HTTPS / TLS | ❌ | 운영 배포 시 reverse proxy 또는 직접 HTTPS 설정 필요 |
| CSRF 토큰 | ❌ | 폼 제출 시 토큰 검증 미구현 |
| Rate Limiting | ❌ | 로그인 brute force 방어 미구현 |
| 보안 헤더 (CSP/HSTS 등) | ❌ | helmet 등 미적용 |
| 비밀번호 정책 강화 | ⚠ 부분 | 최소 길이 검증만 — 복잡도 / 만료 정책 미구현 |
| 감사 로그 (audit trail) | ⚠ 부분 | 진단/예약은 기록, 인증/권한 변경 로그는 미기록 |
| 세션 만료 자동 처리 | ⚠ 부분 | 만료 검증은 있으나 자동 갱신 미구현 |

---

## 4. 알려진 제약 / 운영 시 주의사항

### 4.1 데이터 흐름 의존성
- **CVE 진단**: 점검 대상 시스템에서 SecuMS Agent가 `rpm -qa`를 수집해야 함.
  정책에 `os-linux-389` ("RPM 리스트 조회") 미포함 시 CVE 매칭 0건.
- **백포팅 판정**: CentOS release 형식이 표준(`N.elN[_N[.N]]`)이어야 정확. 비표준 빌드는 MONITOR로 분류.
- **CVE 큐레이션 한계**: 현재 25건. 운영 가치를 위해서는 50-200건 수준 확장 권장.

### 4.2 환경 의존성
- **시간대**: 시스템 TZ가 코드 평가 기준. KST 환경에서 cron `0 2 * * *`는 KST 02:00.
- **컨테이너 시간대**: 개발 컨테이너는 UTC라 화면 표시와 cron 평가가 모두 UTC 기준.
- **SQLite 드라이버**: better-sqlite3 → sqlite3 → sql.js(WASM) 순으로 자동 폴백.

### 4.3 데이터 누적 정책
- `diagnoses.json`: 무제한 누적 — **장기 운영 시 페이징/아카이브 필요**
- `schedule_runs.json`: 최근 200건 유지
- `notifications.json`: 최근 500건 유지
- `sync-history.json`: 최근 100건 유지

### 4.4 알림 발송 한계
- Slack/Email 발송 실패 시 1회만 시도 (재시도 큐 없음)
- 다중 채널 사용 시 한 채널 실패가 다른 채널 발송을 막지 않음

---

## 5. 다음 단계 권장 (우선순위 순)

1. **운영 보강** (보안)
   - HTTPS (reverse proxy 또는 직접)
   - CSRF, Rate Limiting, 보안 헤더
   - 감사 로그 (인증/권한 변경)

2. **CVE 큐레이션 확장**
   - 50-200건 수준으로 확대
   - 운영 환경에서 자주 등장하는 패키지 우선 (httpd, openssh, glibc, kernel, sudo, bash 등)

3. **데이터 관리**
   - `diagnoses.json` 페이징 / 오래된 결과 아카이브
   - MySQL 모드로 영구 전환 (운영 규모 시)

4. **알림 신뢰성**
   - 발송 실패 시 재시도 큐
   - 에스컬레이션 정책 (1차 실패 → 2차 채널)

5. **사용성**
   - 진단 결과 비교 (이전 vs 현재)
   - 정책 변경 이력 추적
   - 대시보드 위젯 커스터마이즈

---

## 6. 패치 적용 이력

| 버전 | 일자 | 주요 변경 |
|---|---|---|
| v9.0 (base) | - | 통합본 시작 (Storage 모듈 누락 등 미완성 부스러기 다수) |
| v9.17 | 2026-05-24 | 누락 뷰 6개 작성 (exceptions/exclusions/diagnosis/upload/validate) |
| v9.18 | 2026-05-24 | Storage 모듈 (Blocker 해소) + MySQL 폴백 |
| v9.19 | 2026-05-24 | CVE 어댑터 (extractPackages) + 예약 진단 (cron 파서 + 백그라운드 폴링) + 알림 발송 연결 |
| v9.20 | 2026-05-24 | CVE Sync 운영 UI + 예약 편집/실행 이력 상세 |

---

## 7. 빠른 시작

```bash
# 의존성 설치
npm install

# Mock 모드 시작 (기본)
node server-mock.js

# 또는 (스케줄러 폴링 주기 조정)
SCHEDULER_INTERVAL_MS=10000 node server-mock.js

# MySQL 모드
DB_MODE=mysql DB_HOST=... DB_USER=... DB_PASSWORD=... node server-mock.js

# 알림 채널 설정
NOTIFIER_CHANNELS=console,slack \
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/... \
node server-mock.js
```

기본 계정: `admin` / `admin123!` (최초 로그인 시 비밀번호 변경 강제).

브라우저: http://localhost:3000

---

## 8. 정합성 검증 결과 (SecuMS 대비)

같은 raw 데이터를 두 시스템이 다른 정책으로 점검하므로 단순 비교가 불가능합니다.
자세한 분석은 `VALIDATION_REPORT.md` 참조.

| 시스템 | 점검 항목 | 결과 |
|---|---|---|
| SecuMS (LSware 자체 표준) | 64개 | OK 34 / BAD 14 / INFO 2 / WAIT 14 |
| 본 시스템 (KISA 30 가이드) | 30개 | 취약 8 / 양호 21 / 점검불가 1 |

| 일치율 지표 | 값 |
|---|---|
| 전체 매핑 일치율 | 63% (19/30) |
| **검증된 매핑 일치율** (raw DB MSG로 영역 일치 확인된 8건) | **37.5% (3/8)** |

**불일치 주요 원인 (우선순위 순)**:
1. **mock LLM 임의 판정** — 30개 룰 중 13개가 LLM 평가 룰. mock 모드에서는 실제 데이터를 보지 않고 임의 판정. 실서비스에서 Ollama/실 LLM 연결 시 해결.
2. **simple_check 점검 대상 차이** — U-21 같은 일부 룰이 SecuMS와 다른 파일을 점검. context_sql 보강으로 해결.
3. **점검 범위 차이** — SecuMS는 메일/세션/로그/컴파일러 권한 등 KISA 30 외 영역도 점검 (BAD 14건 중 6건).

`/diagnosis/:id/validate` 화면에서 룰별 일치/불일치 + 평가 방식 + 매핑 검증 상태를 확인 가능.

---

## 9. 검증 데이터

- `data/uploads/exportData-SSUnix.db` — jessy62 (CentOS 7.5.1804) SecuMS Agent SQLite
  - 1324 패키지, 30 KISA 룰 평가 → 취약 8건 / 양호 21건 / N/A 1건
  - CVE 매칭 20건 (CRITICAL 4 / HIGH 13 / MEDIUM 3)
  - IMMEDIATE 1건 (CVE-2021-3156 Sudo Baron Samedit)
- `data/cve/feeds/nvdcve-test.json` — NVD modified feed 형식 테스트 샘플 3건

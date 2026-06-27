# Vuln Assessor v9.20

SecuMS Unix Agent 기반 취약점 진단 시스템. KISA 30개 룰 진단 + CVE 자동 매칭 + 예약 진단 + 알림 발송.

## 빠른 시작

```bash
cd vuln-assessor-v9
npm install
node server-mock.js
```

브라우저: http://localhost:3000
기본 계정: `admin` / `admin123!` (최초 로그인 시 비밀번호 변경 강제)

## 주요 기능

| 화면 | URL | 설명 |
|---|---|---|
| 대시보드 | `/` | 전체 현황 |
| 진단 관리 | `/diagnosis` | 진단 실행 / 결과 / 리포트 |
| **CVE 자동 진단** | `/diagnosis/:id/cve` | 1300+ 패키지 → CVE 자동 매칭 (백포팅 자동 인식) |
| **예약 진단** | `/schedules` | cron 기반 자동 실행 |
| **CVE 동기화** | `/cve-sync` | NVD/KEV 피드 보강 (폐쇄망 파일 업로드 지원) |
| **알림** | `/notifications` | 발송 이력 + 채널 설정 |
| 취약점 관리 | `/vulnerabilities` | 평탄화된 취약 항목 통합 |
| 조치 관리 | `/remediation` | 금보원 양식 조치 |
| 서버 관리 | `/servers` | 진단 대상 자산 |
| 룰셋 관리 | `/rulesets` | KISA 룰 편집 |

## 환경 변수

```bash
# 저장소 모드
DB_MODE=mock              # 기본 (data/mock/*.json)
DB_MODE=mysql             # MySQL (실패 시 mock 자동 폴백)

# 스케줄러
SCHEDULER_INTERVAL_MS=60000   # 폴링 주기 (기본 60초)
SCHEDULER_ENABLED=false       # 비활성화

# 알림
NOTIFIER_CHANNELS=console               # 기본
NOTIFIER_CHANNELS=console,slack         # 다중 채널
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
SMTP_HOST=mail.example.com SMTP_PORT=25 SMTP_USER=... SMTP_TO=ops@...
```

## 검증된 동작

`data/uploads/exportData-SSUnix.db` (jessy62, CentOS 7.5.1804) 기준:

```
KISA 30개 룰:
  취약 8건, 양호 21건, N/A 1건 — 200ms 이내

CVE 자동 매칭:
  설치 패키지 1,324개 → 매칭 CVE 20건
  CRITICAL: 4, HIGH: 13, MEDIUM: 3
  CISA KEV: 2 (Sudo Baron Samedit, Shellshock)
  IMMEDIATE 1, URGENT 9, SCHEDULED 6, MONITOR 4

예약 진단:
  매일 02:00 자동 실행, 평균 186ms / 2서버
```

## 문서

- `PROJECT_STATUS.md` — **완성/미완성 기능 상세 표** (운영 적용 전 필독)
- `INSTALL.md` — 설치 / 초기 설정
- `01_Node설치.md` — 폐쇄망 Windows 환경 Node 설치
- `docs/` — 추가 가이드

## 모드별 동작

### Mock 모드 (기본)
- DB 없이 파일 기반 (`data/mock/*.json`)
- Raw SQLite는 `data/uploads/exportData-SSUnix.db` 자동 사용
- LLM은 mock provider (외부 호출 없음)
- 알림은 console (외부 호출 없음)
- **모든 기능이 외부 의존성 없이 동작**

### MySQL 모드
```bash
DB_MODE=mysql DB_HOST=... DB_USER=... DB_PASSWORD=... node server-mock.js
```
- `_kv_store` 테이블 자동 생성
- 연결 실패 시 mock 자동 폴백

## 다음 작업 (우선순위 순)

1. **운영 보강** — HTTPS / CSRF / Rate Limit (`PROJECT_STATUS.md` §3 참조)
2. **CVE 큐레이션 확장** — 25건 → 100건 이상
3. **데이터 관리** — 진단 결과 페이징/아카이브
4. **알림 신뢰성** — 발송 실패 재시도 큐

## 라이선스 / 출처
LSware 내부 프로젝트.

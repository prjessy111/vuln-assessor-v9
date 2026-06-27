# Vuln Assessor v9 — 통합 상태 분석

**기준 시점**: 2026-05-24
**대상**: `vuln-assessor-v9` base + 7개 패치 통합본
**통합 진입점**: `server-mock.js` (1869줄, vuln_remediation/patch-vuln 기준)

---

## 1. 패치 통합 결과

7개 패치를 적용한 결과, **`server-mock.js`는 vuln_remediation/patch-vuln 버전이 다른 모든 패치(auth, agent_push, cve_scanner, reports)를 누적 통합한 최종본**임이 확인됨. 나머지 패치들은 부속 파일(view, css, 신규 js 모듈, yaml, json)만 추가.

```
[적용 순서 — 실제로는 한 번에 덮어쓰면 됨]
1. server-mock.js     ← vuln_remediation/patch-vuln (1869줄, 최종 통합본)
2. src/auth/auth.js   ← auth
3. src/agent/token.js ← agent_push
4. src/cve/*.js       ← cve_scanner (3개 파일)
5. data/cve/*.json    ← cve_scanner (큐레이션 CVE DB)
6. scripts/sync-cve.js ← cve_sync_phase1
7. rules/*.yaml       ← kisa30
8. views/*            ← 각 패치별 추가
9. style.css          ← vuln_remediation/patch-vuln (1639줄)
```

---

## 2. 🚨 즉시 실행 불가 — Blocker

**현재 상태로 `npm run mock` 하면 즉시 죽음.**

```javascript
// server-mock.js:53
const kvStorage = require('./src/storage');  // ← 모듈 없음
```

`src/storage` 디렉토리/파일이 **base에도 패치에도 존재하지 않음.** 통합본이 MySQL 폴백 모드(`DB_MODE=mysql`)와 mock 모드를 추상화하는 storage 계층을 호출하는데, 그 모듈을 작성하다 만 상태로 멈춰있음.

### 필요한 인터페이스 (server-mock.js에서 호출하는 API)

```javascript
kvStorage.loadSync(name)              // 동기 로드
kvStorage.saveSync(name, data)        // 동기 저장
kvStorage.initialize()                // async, returns { mode, status }
kvStorage.preloadAll()                // mysql 모드 시 캐시 프리로드
kvStorage.mode                        // 'mock' | 'mysql'
```

agent_push 토큰 모듈(`src/agent/token.js`)도 kvStorage를 인자로 받음:
```javascript
agentToken.issueToken(kvStorage, server_id)
agentToken.findServerByToken(kvStorage, token)
agentToken.recordPush(kvStorage, server_id, info)
agentToken.revokeToken(kvStorage, server_id)
```

→ **이 모듈을 만들어야 그 다음이 진행 가능.**

---

## 3. ✅ 구현 완료된 기능

### 3.1 인증/사용자 관리 (auth)
| 항목 | 상태 |
|---|---|
| 세션 로그인/로그아웃 | ✅ |
| scrypt 비밀번호 해시 | ✅ |
| 3단계 권한 (admin/operator/viewer) | ✅ |
| 최초 admin 자동 생성 | ✅ |
| 첫 로그인 시 비밀번호 변경 강제 | ✅ |
| 사용자 CRUD (admin만) | ✅ |
| 본인/마지막 admin 삭제 차단 | ✅ |

라우트: `/login`, `/logout`, `/users*`, `/users/me/password`
뷰: `login.ejs`, `users/index.ejs`, `users/form.ejs`, `users/password.ejs`
인증 미들웨어가 모든 라우트에 적용됨 (단, `/api/*`는 제외 — Agent Token 별도 인증)

### 3.2 진단 실행 (수동)
| 항목 | 상태 |
|---|---|
| POST /diagnosis/run (server_id로 실행) | ✅ |
| Raw SQLite 자동 로드 + 룰엔진 평가 | ✅ |
| sql.js WASM 폴백 (네이티브 빌드 불필요) | ✅ |
| 결과 → diagnoses.json 저장 | ✅ |
| LLM_PROVIDER=mock 동작 | ✅ |
| POST /diagnosis/upload (DB 직접 업로드) | ✅ (라우트만, 뷰 없음 — §5 참조) |
| GET /diagnosis/:id/validate | ✅ (라우트만, 뷰 없음) |

### 3.3 룰셋
| 항목 | 상태 |
|---|---|
| YAML 기반 룰 정의 (secums-unix v2.0) | ✅ |
| KISA Unix "상" 30개 룰 (U-01 ~ U-30) | ✅ |
| 룰셋 화면 표시 (/rulesets) | ✅ |
| 룰 추가/저장 API (POST /rulesets/save) | ✅ |
| simple_check (각 룰 직접 평가) | ✅ |
| per_row 평가 (계정별 소항목) | ✅ |
| LLM 평가 (mock 응답) | ✅ |

### 3.4 서버 관리 + Agent Push (agent_push)
| 항목 | 상태 |
|---|---|
| 서버 목록 (/servers) | ✅ |
| 헬스체크 (mock 결과) | ✅ |
| Agent Token 발급/폐기 | ✅ (단 kvStorage 의존) |
| POST /api/collect (raw DB 업로드) | ✅ |
| GET /api/ping (토큰 검증) | ✅ |
| timing-safe 토큰 비교 (SHA-256) | ✅ |
| push.sh / push.ps1 wrapper 자동 생성 | ✅ |
| 업로드 후 백그라운드 자동 진단 | ✅ |

### 3.5 리포트 (reports)
| 항목 | 상태 |
|---|---|
| 기본 리포트 (/reports/:id) | ✅ |
| 금보원 양식 리포트 (/reports/:id/fsi) | ✅ |
| 금보원 양식 XLSX 다운로드 (19컬럼) | ✅ |
| 삼성 양식 리포트 (/reports/:id/samsung) | ✅ |

### 3.6 취약점 관리 + 조치 관리 (vuln_remediation)
| 항목 | 상태 |
|---|---|
| GET /vulnerabilities (진단 결과 평탄화) | ✅ |
| 신규/기존 자동 판정 (7일 기준) | ✅ |
| GET /vulnerabilities/:resultId 상세 | ✅ |
| GET /remediation (칸반 보드) | ✅ |
| POST /remediation/:id/update (조치 상태 변경) | ✅ |
| 진단 결과 ↔ 조치 데이터 분리 (remediations.json) | ✅ |

### 3.7 CVE 자동 진단 (cve_scanner)
| 항목 | 상태 |
|---|---|
| GET /diagnosis/:id/cve | ✅ |
| 1314개 패키지 vs 26개 큐레이션 CVE 매칭 | ✅ |
| 백포팅 자동 인식 (CentOS release 비교) | ✅ |
| 우선순위 산출 (IMMEDIATE/URGENT/SCHEDULED/MONITOR) | ✅ |
| CISA KEV 표시 | ✅ |
| LLM Judgment (mock 휴리스틱) | ✅ |

### 3.8 예외/제외 관리 (server-mock.js에 라우트만 있음)
| 항목 | 상태 |
|---|---|
| /exceptions 라우트 | ⚠ 라우트만, 뷰 없음 |
| /exclusions 라우트 | ⚠ 라우트만, 뷰 없음 |
| 예외 신청/승인/연장 API | ✅ (라우트 동작) |
| 제외 등록/토글 API | ✅ (라우트 동작) |

→ 즉, REST API로 호출하면 동작은 하지만 화면이 없어 클릭 → 500 에러 발생.

### 3.9 CVE Feed 동기화 (cve_sync_phase1)
| 항목 | 상태 |
|---|---|
| `scripts/sync-cve.js` (NVD modified + KEV) | ✅ |
| `--from-file` 폐쇄망 옵션 | ✅ |
| 변경 감지 (신규/CVSS변경/KEV등재) | ✅ |
| `data/cve/cve-db.json` 저장 | ✅ |
| 동기화 이력 (sync-history.json) | ✅ |

단, 이 스크립트는 **`/diagnosis/:id/cve` 가 쓰는 `cve-centos7-curated.json`과 통합 안 됨** — Phase 2로 미룬 의도적 분리.

---

## 4. ❌ 미구현 (있어야 하는데 없음)

### 4.1 🔴 스케줄 cron 자동 실행 ← 사용자가 물어본 항목

**현재 상태**: `/schedules` 화면에 cron 표현식만 표시. 실행기 0건.

```bash
# 통합본에 setInterval / node-cron / node-schedule 검색 결과: 0건
$ grep -nE "setInterval|node-cron|cron\.schedule" server-mock.js
(empty)
```

**구현되어 있는 것**:
- 스케줄 데이터 모델 (seed-schedules.json: cron_expr, enabled, last_run_at 등)
- 화면 표시 (다음 실행 시각, 7일 캘린더)
- KPI 카드 (활성 스케줄 개수, 성공률 등)

**미구현인 것**:
- cron 표현식 파싱
- 시각이 됐을 때 진단 실행 트리거
- 실행 결과를 schedule_runs에 기록
- 실패 시 알림 발송
- 스케줄 추가/편집/삭제 라우트
- 활성/비활성 토글 라우트

→ "스케줄 cron 실행" 작업은 **여기에 자동 실행 엔진을 붙이는 것**이 본 작업.

### 4.2 🔴 src/storage 모듈

§2 참조. Blocker.

### 4.3 🔴 누락된 뷰 파일

server-mock.js가 `res.render()`하지만 파일이 없음:

| 라우트 | 렌더하는 뷰 | 상태 |
|---|---|---|
| GET /exceptions | `exceptions/index` | ❌ 폴더 없음 |
| GET /exceptions/new | `exceptions/new` | ❌ 폴더 없음 |
| GET /exclusions | `exclusions/index` | ❌ 폴더 없음 |
| GET /exclusions/new | `exclusions/new` | ❌ 폴더 없음 |
| GET /diagnosis/upload | `diagnosis/upload` | ❌ 파일 없음 |
| GET /diagnosis/:id/validate | `diagnosis/validate` | ❌ 파일 없음 |

### 4.4 🟡 알림 발송
| 항목 | 상태 |
|---|---|
| 이메일 알림 | ❌ 코드 없음 (콘솔 로그만) |
| Slack 알림 | ❌ 코드 없음 |
| 스케줄 실패 시 알림 | ❌ |
| 신규 CVE 등재 시 알림 | ❌ |

seed 데이터에 `notify_on_vuln`, `notify_on_failure` 플래그만 있고 발송 로직 0.

### 4.5 🟡 실제 SSH 수집
README에 명시된 의도적 미구현 (Mock 모드 한계). Agent Push 방식으로 대체 가능하나, 기존 SSH 기반 운영 환경 지원하려면 별도 작업 필요.

### 4.6 🟡 실제 LLM 호출
`src/engine/llm/providers/` 에 anthropic/openai/ollama 어댑터 파일은 있으나, 현재는 LLM_PROVIDER=mock 으로만 검증됨. 실제 호출 시 동작 미검증.

### 4.7 🟡 CVE Sync ↔ CVE Scanner 통합
sync-cve.js가 만든 `cve-db.json`을 `src/cve/scanner.js`가 읽지 않음. 현재는 두 DB가 독립.

### 4.8 🟡 운영 보강 (PATCH_NOTES에 명시된 항목)
- HTTPS 강제
- CSRF 토큰
- Rate Limiting
- 세션 저장소 Redis/MySQL 전환
- 로그인 실패 계정 잠금
- 감사 로그
- 토큰 자동 회전 (90일 만료)
- Push 파일 크기/형식 검증 (SQLite 시그니처)
- mTLS

---

## 5. 분류 요약표

| 영역 | 구현 상태 | 비고 |
|---|---|---|
| 인증/세션/사용자 | ✅ 완전 | 운영 보강 필요 |
| 진단 실행 (수동) | ✅ 완전 | sql.js로 어디서든 동작 |
| 룰셋 (KISA 30개) | ✅ 완전 | LLM은 mock |
| Agent Push (REST + Token) | ✅ 완전 | storage 모듈 의존 |
| 리포트 (FSI/삼성/XLSX) | ✅ 완전 | |
| 취약점/조치 관리 | ✅ 완전 | |
| CVE 자동 진단 | ✅ 완전 | 큐레이션 26건 한정 |
| CVE Feed 동기화 (CLI) | ✅ 완전 | Scanner 미통합 |
| 예외/제외 관리 | ⚠ 라우트만 | **뷰 4개 누락** |
| diagnosis/upload, validate | ⚠ 라우트만 | **뷰 2개 누락** |
| **storage 추상화** | ❌ **Blocker** | **모듈 자체 없음 — 즉시 죽음** |
| **스케줄 cron 자동 실행** | ❌ 미구현 | **데이터 표시만, 실행기 0** |
| 알림 (메일/슬랙) | ❌ 미구현 | 콘솔 로그만 |
| 실제 SSH 수집 | ❌ 미구현 | Agent Push로 대체 |
| 실제 LLM 호출 | ⚠ 어댑터만 | mock으로만 검증 |
| 운영 보강 (HTTPS/CSRF 등) | ❌ 미구현 | PoC 단계 |

---

## 6. 우선순위 권고

순서대로 처리하면 막힘없이 동작 가능:

1. **src/storage 모듈 작성** — Blocker 해소 (필수, 30~60분)
2. **누락 뷰 6개 작성** — 클릭 시 500 에러 제거 (1~2시간)
3. **스케줄 cron 자동 실행 엔진** ← *직전 질문이 가리키는 작업* (2~4시간)
   - node-cron 또는 자체 1분 폴링 루프
   - 스케줄 CRUD 라우트 추가
   - 실행 결과를 schedule_runs에 기록
4. **알림 발송** (이메일/Slack)
5. CVE Sync ↔ Scanner 통합
6. 운영 보강 (HTTPS/CSRF/Rate Limit)

---

## 7. 다음 작업 제안

위 1~3번을 묶어 한 번의 작업 단위로 진행하는 것이 자연스러움.
스케줄 cron 작업 자체가 storage(상태 저장)와 누락 뷰(편집 화면)에 의존하므로.

# 룰 정의 YAML 스키마 v2

## 개요

v1에서는 코드 기반의 `check_type`(perm_le, service_off 등)을 사용했으나,
v2에서는 **자연어 룰 정의 + SQL 컨텍스트 + 하이브리드 평가(단순/LLM)** 를 지원합니다.

## 룰 1건의 전체 스키마

```yaml
- rule_id: VULN-PERM-001                # 룰 고유 ID (필수)
  title: /etc/passwd 권한 점검            # 표시명 (필수)
  description: |                         # 자연어 룰 설명 (필수)
    /etc/passwd 파일의 권한이 644 이하인지 확인.
    644보다 큰 권한이면 일반 사용자가 수정 가능하므로 취약.
  category: 파일및디렉토리관리            # 카테고리 (필수)
  severity: 상                            # 상/중/하 (필수)
  os_target: linux                       # linux | windows | all (필수)

  # raw 데이터에서 어느 부분을 봐야 하는지 SQL로 정의 (필수)
  # SELECT 문만 허용. 어댑터의 querySlice()로 실행됨.
  context_sql: |
    SELECT FILEPATH, PERMISSION, OWR, GRP, OTR
    FROM U_FILEATTR_TB
    WHERE FILEPATH = '/etc/passwd'

  # 평가 방식 (둘 중 하나 또는 둘 다)
  simple_check:                          # (선택) 코드로 즉시 판정
    type: perm_le
    field: PERMISSION
    max: "644"

  evaluation_prompt: |                   # (선택) LLM으로 판정
    위 context 데이터를 보고 /etc/passwd 권한이 644 이하인지 판정하세요.
    OTHERS 쓰기 권한(2)이 있으면 즉시 취약입니다.
    응답은 반드시 JSON: {"status":"양호|취약|점검불가","reason":"..."}

  # 양쪽 모두 정의된 경우 우선순위
  prefer: simple                         # 'simple' | 'llm' (기본: simple)

  # 조치 권고 (자연어)
  recommend: |
    chmod 644 /etc/passwd
    chown root:root /etc/passwd

  enabled: true
```

## 평가 방식 결정 흐름

```
룰 평가 요청
    │
    ▼
context_sql 실행 → context 데이터 획득
    │
    ▼
simple_check 있음?  ──아니오──→ evaluation_prompt 있음? ──아니오──→ 점검불가
    │                                  │
    예                                 예
    │                                  ▼
    ▼                              LLM 호출
prefer=simple?                         │
    │                                  ▼
    예 → simple_check 실행 → 결정    {status, reason}
    아니오 → LLM 호출
```

## simple_check 타입

기존 v1의 check_type을 그대로 활용 가능. context_sql 결과의 특정 field를 검사:

| type | param | 설명 |
|------|-------|------|
| `perm_le` | `{ field, max }` | 권한 8진수 ≤ max 면 양호 |
| `service_off` | `{ field }` | 값이 inactive/disabled 면 양호 |
| `service_on` | `{ field }` | 값이 active/running 면 양호 |
| `int_min` | `{ field, min }` | 값(정수) ≥ min 이면 양호 |
| `int_max` | `{ field, max }` | 값(정수) ≤ max 이면 양호 |
| `contains` | `{ field, keyword }` | 값에 keyword 포함되면 양호 |
| `not_contains` | `{ field, keyword }` | 값에 keyword 없으면 양호 |
| `equals` | `{ field, expect }` | 값이 expect와 일치하면 양호 |
| `regex` | `{ field, pattern }` | 값이 pattern과 매칭되면 양호 |
| `row_count_min` | `{ min }` | context_sql 결과 행 수 ≥ min |
| `row_count_max` | `{ max }` | context_sql 결과 행 수 ≤ max |
| `row_count_zero` | `{}` | 결과 행이 0개여야 양호 |
| `every_row` | `{ field, op, value }` | 모든 행이 조건 만족해야 양호 |
| `any_row` | `{ field, op, value }` | 하나라도 만족하면 취약/양호 (negate로 반전) |

## LLM 평가 (evaluation_prompt)

LLM에게 전달되는 최종 프롬프트는 다음과 같이 조립됩니다:

```
[시스템 프롬프트 - 고정]
당신은 시스템 보안 점검 전문가입니다. 주어진 raw 데이터를 분석하여
양호/취약/점검불가 중 하나로 판정하고, 근거를 함께 제시하세요.
응답은 반드시 다음 JSON 형식만:
{"status": "양호|취약|점검불가", "reason": "사유", "evidence": "raw에서 인용한 증거"}

[룰 정보]
점검명: /etc/passwd 권한 점검
설명: /etc/passwd 파일의 권한이 644 이하인지 확인...
중요도: 상

[raw 컨텍스트]
context_sql 실행 결과:
| FILEPATH      | PERMISSION | OWR | GRP | OTR |
|---------------|-----------|-----|-----|-----|
| /etc/passwd   | 644       | 6   | 4   | 4   |

[추가 지침 - 룰별 evaluation_prompt]
위 context 데이터를 보고 /etc/passwd 권한이 644 이하인지 판정하세요.
OTHERS 쓰기 권한(2)이 있으면 즉시 취약입니다.
```

## 룰 작성 가이드

### 좋은 룰
- `context_sql`이 핵심 데이터만 정확히 추출 (수십 행 이내)
- `description`이 점검 의도를 명확히 설명
- 가능하면 `simple_check`로 결정적 판정
- `evaluation_prompt`는 simple_check로 표현 못하는 복잡한 경우에만

### 피해야 할 것
- `SELECT * FROM big_table` 같은 비효율적 context_sql
- LLM에게 모호한 지시 (예: "보안 점검해줘")
- simple_check와 evaluation_prompt 모두 빈 룰

## 룰 자동 제안 (AI)

운영자가 raw 파일을 처음 임포트하면, AI가 어댑터의 `listTables`를 보고
점검 가능한 항목들을 자동 제안합니다. 운영자는 제안된 룰을 검토 후 룰셋에 추가.

(상세는 Phase C에서 구현)

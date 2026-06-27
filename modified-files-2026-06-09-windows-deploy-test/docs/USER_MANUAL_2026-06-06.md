# Vuln Assessor v9 사용자 매뉴얼

작성일: 2026-06-06  
대상 버전: vuln-assessor v0.9.20 테스트 빌드  
목적: SecuMS raw data와 Script raw data를 분리 수집하고, AI/LLM으로 진단하여 SecuMS 데이터 정합성을 검증

## 1. 시스템 개요

Vuln Assessor v9는 서버 보안 점검 결과를 검증하기 위한 진단 도구입니다.

주요 목적은 다음과 같습니다.

- SecuMS raw DB를 수집하여 AI/LLM 기준으로 재진단
- Script XML raw data를 수집하여 AI/LLM 기준으로 재진단
- SecuMS 진단과 Script 진단을 별도 assessment로 저장
- AI 전체 결과와 LLM 상세 결과를 구분하여 확인
- SecuMS 판단, AI 판단, LLM 상세 판단을 비교하여 정합성 검증

중요 원칙:

- Script는 자체 판단을 하지 않습니다.
- Script는 raw evidence만 제공합니다.
- 빠른 1차 판단은 AI가 수행합니다.
- 상세 판단은 LLM이 수행합니다.
- 양호는 `부재양호`와 `값준수양호`로 구분합니다.
- 최종 판정 유형은 `취약`, `양호`, `정보제공`, `판정불가`입니다.

## 2. 주요 메뉴 구조

상단 메뉴에서 `수집 관리`로 이동하면 다음 기능을 사용할 수 있습니다.

| 메뉴 | 목적 |
|---|---|
| SecuMS 진단 | SecuMS raw DB만 수집하고 AI/LLM 진단 |
| Script 진단 | Script XML만 수집하고 AI/LLM 진단 |
| Script 업로드 | 이미 확보한 Script XML을 수동 업로드 후 진단 |
| Script 배포 | 스크립트 파일을 원격 서버로 배포, 실행, 결과 수집, 진단 |
| 수집 이력 | 수집 및 진단 실행 이력 확인 |

검증 목적상 SecuMS 진단과 Script 진단은 서로 섞지 않는 것이 기본입니다.
두 결과를 비교할 때는 각각 별도의 assessment ID로 생성된 결과를 비교하십시오.

## 3. 실행 전 준비

### 3.1 Node.js 설치

테스트 서버 또는 실행 PC에 Node.js가 필요합니다.

권장:

- Node.js 20 이상
- Windows 테스트 시 PowerShell 실행 가능
- Linux/UNIX 테스트 시 SSH 접근 가능

설치 후 확인:

```bat
node -v
npm -v
```

### 3.2 의존성 설치

프로젝트 루트에서 실행합니다.

```bat
npm install
```

또는 `package-lock.json` 기준으로 설치하려면:

```bat
npm ci
```

### 3.3 서버 실행

프로젝트 루트에서 실행합니다.

```bat
npm run mock
```

정상 실행 후 브라우저에서 접속합니다.

```text
http://localhost:3000
```

## 4. 서버 목록 설정

프로젝트 루트에 `servers.csv` 파일을 둡니다.

형식:

```csv
hostname,ip,os,username,password,asset_no,server_id
```

예시:

```csv
linux01,192.168.159.108,linux,root,password123,ASSET-LINUX-01,192.168.159.108
win01,192.168.159.167,windows,Administrator,password123,ASSET-WIN-01,192.168.159.167
```

필드 설명:

| 필드 | 설명 |
|---|---|
| hostname | 화면 표시 및 파일명에 사용할 호스트명 |
| ip | 대상 서버 IP |
| os | `linux`, `solaris`, `aix`, `hp-ux`, `windows` |
| username | 원격 접속 계정 |
| password | 원격 접속 비밀번호 |
| asset_no | 자산번호, 없으면 hostname 사용 가능 |
| server_id | 내부 식별자, 보통 IP 사용 |

주의:

- Linux/UNIX는 SSH 접속이 필요합니다.
- Windows는 SMB `C$` 접근과 WinRM 실행 권한이 필요합니다.
- 테스트 단계에서는 관리자 권한 계정 사용을 권장합니다.

## 5. SecuMS 진단 사용법

### 5.1 동작 개요

`SecuMS 진단`은 SecuMS raw DB만 수집하고 AI/LLM 진단을 수행합니다.

Linux/UNIX 기본 수집 경로:

```text
/opt/lsware/secums/agent/bin/exportData-SSUnix.db
```

Windows 기본 수집 경로:

```text
C:\Program Files (x86)\lsware\secums\agent\bin\exportData-SSWindows.db
```

### 5.2 실행 절차

1. `수집 관리` 메뉴로 이동합니다.
2. `SecuMS 진단` 탭을 선택합니다.
3. 대상 서버 행의 `SecuMS 진단` 버튼을 클릭합니다.
4. 확인 창에서 진행을 승인합니다.
5. 완료 후 진단 결과 화면으로 이동합니다.

### 5.3 전체 서버 실행

상단의 `SecuMS 전체 진단` 버튼을 클릭하면 `servers.csv`의 모든 서버에 대해 순차 실행합니다.

### 5.4 결과 해석

SecuMS 진단 결과에서는 다음을 확인합니다.

- SecuMS raw DB에서 추출된 항목 수
- AI 전체 결과
- LLM 상세 결과
- SecuMS 판정과 AI/LLM 판정의 일치율
- 불일치 항목
- 판정불가 항목
- 부재양호와 값준수양호 구분

## 6. Script 진단 사용법

### 6.1 동작 개요

`Script 진단`은 Script XML만 수집하고 AI/LLM 진단을 수행합니다.

Script XML은 다음 순서로 확보합니다.

1. 기존 SecuMS agent 경로에 있는 XML을 먼저 찾습니다.
2. 기존 XML이 없으면 AI-ready 스크립트를 배포/실행하여 XML을 생성합니다.
3. 생성 또는 발견된 XML을 로컬로 수집합니다.
4. Script XML 파서가 SRV 항목만 진단 대상으로 정규화합니다.
5. AI/LLM 진단을 수행합니다.

Linux/UNIX 기존 XML 검색 경로:

```text
/opt/lsware/secums/agent/bin
/opt/lswaer/secums/agent/bin
/var/lib/secums
/var/lib/secums/script
```

Windows 기존 XML 검색 경로:

```text
C:\Program Files (x86)\lsware\secums\agent\bin
C:\Program Files\lsware\secums\agent\bin
C:\lsware\secums\agent\bin
```

참고:

- `/opt/lswaer`는 오타 가능 경로이지만, 현장에 잘못 생성된 경우를 대비하여 보조로 검색합니다.
- 표준 경로는 `/opt/lsware`입니다.

### 6.2 실행 절차

1. `수집 관리` 메뉴로 이동합니다.
2. `Script 진단` 탭을 선택합니다.
3. 대상 서버 행의 `Script 진단` 버튼을 클릭합니다.
4. 확인 창에서 진행을 승인합니다.
5. 완료 후 진단 결과 화면으로 이동합니다.

### 6.3 전체 서버 실행

상단의 `Script 전체 진단` 버튼을 클릭하면 `servers.csv`의 모든 서버에 대해 Script 진단만 순차 실행합니다.

### 6.4 Script 진단 결과 특징

Script 진단은 다음 기준을 따릅니다.

- Script는 판정하지 않습니다.
- 모든 Script 항목의 `secums_verdict`는 기본적으로 `WAIT` 성격입니다.
- 판정은 AI/LLM이 raw evidence를 보고 수행합니다.
- `SRV001` 같은 구형 ID는 `SRV-001`로 통일됩니다.
- `Encoding`, `ps`, `netstat` 같은 비-SRV 덤프는 진단 대상에서 제외됩니다.

## 7. Script 업로드 사용법

이미 확보한 Script XML이 있을 경우 수동 업로드가 가능합니다.

### 7.1 실행 절차

1. `수집 관리` 메뉴로 이동합니다.
2. `Script 업로드` 탭을 선택합니다.
3. 서버를 선택하거나 hostname을 직접 입력합니다.
4. 진단 엔진을 선택합니다.
5. Script XML 파일을 선택합니다.
6. `업로드 후 Script 소스로 바로 진단` 체크 여부를 확인합니다.
7. `Script 업로드` 버튼을 클릭합니다.

### 7.2 저장 규칙

업로드 파일은 다음 규칙으로 저장됩니다.

```text
data/uploads/YYYY-MM-DD/hostname_script_YYYYMMDD.xml
```

### 7.3 업로드 후 확인

진단이 실행된 경우 결과 화면에서 다음을 확인합니다.

- 전체 진단 항목 수
- SRV ID 형식
- AI 전체 결과
- LLM 상세 결과
- 판정불가 항목

## 8. Script 배포 사용법

`Script 배포`는 원격 서버에 스크립트를 배포하고, 필요 시 실행 및 진단까지 이어서 수행합니다.

### 8.1 실행 단계

Script 배포 화면의 `작업 단계`는 세 가지입니다.

| 단계 | 설명 |
|---|---|
| 1. 배포만 | 파일만 원격 서버에 전송하고 실행하지 않음 |
| 2. 배포 + 실행 | 파일 전송 후 원격 실행, 결과 XML 수집 |
| 3. 배포 + 실행 + 진단 | 파일 전송, 실행, 결과 수집, AI/LLM 진단까지 수행 |

### 8.2 Linux/UNIX 배포 방식

Linux/UNIX는 SSH/SFTP를 사용합니다.

필요 조건:

- SSH 접속 가능
- 계정에 실행 권한 필요
- 원격 임시 디렉터리 생성 가능

### 8.3 Windows 배포 방식

Windows는 다음 방식을 사용합니다.

- SMB `C$` 공유로 PowerShell 스크립트 업로드
- WinRM으로 PowerShell 실행
- SMB로 결과 XML 회수

필요 조건:

- 관리자 권한 계정
- `C$` 관리 공유 접근 가능
- WinRM 활성화
- 방화벽에서 WinRM 포트 허용

기본 포트:

```text
WinRM HTTP: 5985
WinRM HTTPS: 5986
```

원격 작업 폴더 기본값은 `.env`에서 조정할 수 있습니다.

```text
SCRIPT_DEPLOY_WINDOWS_BASE_DIR=C:\Windows\Temp
SCRIPT_DEPLOY_UNIX_BASE_DIR=/tmp
```

Windows 대상 서버별로 폴더가 다르면 `Script 배포` 화면의 `원격 작업 폴더`에 직접 입력할 수 있습니다.
예를 들어 `E:\backup2\script`를 입력하면 SMB 관리 공유도 `E$` 기준으로 자동 전환됩니다.
배포 서비스는 PowerShell 스크립트 실행 시 `-OutputDir`을 자동으로 넘기므로, 결과 XML 생성 위치와 수집 위치가 일치해야 합니다.

### 8.4 Windows 권장 스크립트

Windows는 단일 PowerShell 파일을 권장합니다.

```text
scripts/ai-ready/fsi_win_ai.ps1
```

기본 실행 인자:

```powershell
-Fast
```

전체 원자료 수집이 필요한 경우:

```powershell
-Full
```

## 9. AI-ready 스크립트 설명

### 9.1 공통 원칙

AI-ready 스크립트는 판단하지 않고 raw evidence만 제공합니다.

출력에는 다음 마커가 포함됩니다.

```text
AI_EVIDENCE_BLOCK_BEGIN
RAW_COMMAND_OUTPUT_BEGIN
RAW_COMMAND_OUTPUT_END
AI_EVIDENCE_BLOCK_END
```

AI/LLM은 이 마커를 기준으로 다음을 구분합니다.

- 실제 수집된 명령 출력
- 수집 실패
- 권한 부족
- 대상 부재
- 빠른 점검 모드에서 생략된 항목

### 9.2 Linux/UNIX 스크립트

파일:

```text
scripts/ai-ready/fsi_unix_ai.sh
scripts/ai-ready/fsi_unix_ai.conf
```

특징:

- CDATA로 raw output을 감싸 XML 깨짐 방지
- Fast/Full 모드 지원
- 오래 걸리는 점검 범위 설정 가능
- `/dev`, `/etc`, home directory, lastlog, netstat 등 고비용 수집 범위를 조정 가능

### 9.3 Windows 스크립트

파일:

```text
scripts/ai-ready/fsi_win_ai.ps1
scripts/fsi_win_ai.ps1
```

특징:

- BAT/VBS 방식 대신 단일 PowerShell 스크립트
- 누락 SRV 보강
- AI evidence block 출력
- Fast/Full 모드 지원
- IIS, 계정, 서비스, 레지스트리, 네트워크 설정 원자료 수집

## 10. AI/LLM 진단 구조

### 10.1 AI 전체 결과

AI는 빠른 1차 패턴 기반 진단을 수행합니다.

특징:

- 전체 수집 항목을 빠르게 판정
- 취약/양호/정보제공/판정불가 분류
- 부재양호와 값준수양호 구분 시도
- 검토가 필요한 항목을 LLM 상세 대상으로 넘김

### 10.2 LLM 상세 결과

LLM은 느리지만 더 상세한 판단을 수행합니다.

특징:

- AI 전체 결과 중 검토 필요 항목 중심으로 상세 분석
- raw evidence를 근거로 판단 사유 작성
- 조치 권고 작성
- 판정 근거가 부족하면 판정불가 유지

### 10.3 결과 화면 구분

진단 결과 화면에는 다음이 명확히 표시됩니다.

- 현재 화면이 `AI 전체 결과`인지 `LLM 상세 결과`인지
- LLM 상세 결과일 경우 어떤 AI 전체 결과에서 파생되었는지
- AI 전체 항목 수와 LLM 상세 대상 항목 수
- 연결된 AI/LLM 결과 링크

## 11. 판정 기준

### 11.1 판정 유형

| 판정 | 의미 |
|---|---|
| 취약 | 기준 미준수 또는 위험 설정 확인 |
| 양호 | 기준 준수 또는 위험 대상 부재 |
| 정보제공 | 직접 판정보다는 참고 정보 성격 |
| 판정불가 | evidence 부족, 권한 부족, 실행 오류 등 |

### 11.2 양호 세부 유형

| 유형 | 설명 | 예시 |
|---|---|---|
| 부재양호 | 위험 대상 자체가 없음 | `no such file`, 서비스 미설치, 포트 미사용 |
| 값준수양호 | 설정값이 존재하고 기준을 만족 | 패스워드 정책 값이 기준 이상 |

주의:

- 권한 부족이나 명령 실패를 양호로 판단하면 안 됩니다.
- 수집 생략은 양호가 아니라 판정불가 또는 정보제공으로 검토해야 합니다.
- 대상 부재가 기준상 안전한 경우에만 부재양호로 봅니다.

## 12. 정합성 검증 방법

### 12.1 기본 절차

1. 같은 서버에 대해 `SecuMS 진단`을 실행합니다.
2. 같은 서버에 대해 `Script 진단`을 실행합니다.
3. 각각 생성된 assessment ID를 기록합니다.
4. AI 전체 결과를 비교합니다.
5. LLM 상세 결과를 비교합니다.
6. 불일치 항목을 검토합니다.

### 12.2 중점 확인 항목

- SecuMS raw DB 항목 수
- Script XML SRV 항목 수
- 동일 SRV ID의 판정 차이
- SecuMS 판정과 AI 판정의 차이
- AI 판정과 LLM 판정의 차이
- 부재양호와 값준수양호의 구분 오류
- 판정불가 사유가 실제 수집 문제인지 기준 문제인지

### 12.3 항목 수가 적을 때

Script 진단 항목 수가 예상보다 적으면 다음을 확인합니다.

- XML에 `<id>SRV-xxx</id>`가 있는지
- `SRV001` 형식이 정상 정규화되는지
- 비-SRV 덤프가 제외되는 것이 정상인지
- 기존 XML 경로에 최신 XML이 있는지
- Script 실행 결과 XML이 생성되었는지
- Windows WinRM/SMB 권한 문제가 없는지

### 12.4 리포트3 정합성 리포트

`리포트3`은 같은 서버의 SecuMS raw DB 기반 AI 판정과 Script raw data 기반 AI 판정을 비교합니다.
대외비 원본 리포트 파일은 시스템에 넣거나 런타임에서 읽지 않습니다.
리포트3 항목 체계는 참고만 하며, 내부 카탈로그에는 항목 ID, 제목, 카테고리만 반영합니다.
최종 판정은 가능한 한 raw data 근거를 우선합니다.

사용 방법:

1. 같은 서버에 대해 `SecuMS 진단`과 `Script 진단`을 각각 실행합니다.
2. `리포트` 메뉴에서 해당 AI 진단의 `리포트3` 버튼을 클릭합니다.
3. 화면에서 `일치`, `불일치`, `SecuMS만`, `Script만` 항목을 확인합니다.
4. 제출용 정합성 자료가 필요하면 `XLSX 다운로드`를 클릭합니다.

주의:

- 대외비 원본 리포트 파일은 프로젝트, 서버, ZIP 어디에도 넣지 않습니다.
- 리포트3는 내부 항목 카탈로그와 수집된 raw 항목 ID, AI 판정, LLM 상세 결과를 기준으로 생성합니다.
- 점수, 심각도, 판단기준, 조치법은 원본 파일에서 가져오지 않습니다.
- `Scan ID`는 SecuMS raw 매칭에만 사용합니다.
- Script raw는 `report3_id`, 항목 ID, 제목 코드로 리포트3 항목에 매칭합니다.

## 13. 장애 대응

### 13.1 `Cannot find module 'express'`

의존성이 설치되지 않은 상태입니다.

```bat
npm install
```

또는:

```bat
npm ci
```

### 13.2 Windows Script 배포 실패

확인할 사항:

- 대상 서버 WinRM 활성화 여부
- `C$` 공유 접근 가능 여부
- 관리자 계정인지
- 방화벽에서 5985 또는 5986 허용 여부
- `servers.csv`의 계정/비밀번호 정확성
- `Script 배포 등록 실패: Windows Script 실행은 완료됐지만 결과 XML(*.xml)을 찾지 못했습니다.`가 나오면 실행은 되었지만 XML 생성 위치와 탐색 위치가 다른 경우입니다.
- 이 경우 `.env`의 `SCRIPT_DEPLOY_WINDOWS_BASE_DIR` 또는 화면의 `원격 작업 폴더` 값을 실제 대상 서버에서 쓰기 가능한 폴더로 맞춥니다.
- 디버깅이 필요하면 `.env`에 `SCRIPT_DEPLOY_KEEP_REMOTE=true`를 임시로 설정하여 원격 작업 폴더가 삭제되지 않게 한 뒤 XML과 `debug_log.txt`를 확인합니다.

### 13.3 Linux Script 배포 실패

확인할 사항:

- SSH 포트 접근 가능 여부
- 계정/비밀번호 정확성
- 원격 `/tmp`에 디렉터리 생성 가능 여부
- 스크립트 실행 권한

### 13.4 Script XML 파싱 항목 0개

확인할 사항:

- XML 안에 SRV ID가 있는지
- XML이 깨지지 않았는지
- `<dump>`, `<items>`, `<id>`, `<output>` 구조가 있는지
- 파일 크기가 너무 작지 않은지

### 13.5 LLM 상세 결과가 AI 전체보다 적음

정상입니다.

LLM 상세 결과는 AI 전체 결과 중 검토 대상으로 선별된 항목만 표시합니다.
전체 항목은 AI 전체 결과 화면에서 확인하십시오.

## 14. 수정 파일 반영 방법

테스트 서버에 수정 파일만 반영할 때는 다음 ZIP을 사용합니다.

```text
modified-files-2026-06-06-test.zip
```

압축 해제 후 배치파일 실행:

```bat
apply-modified-files-2026-06-06.bat "C:\path\to\vuln-assessor-v9-main"
```

배치파일 기능:

- 기존 파일 자동 백업
- 수정 파일 덮어쓰기
- 백업 폴더 생성

백업 위치:

```text
vuln-assessor-v9-main\backup-before-modified-2026-06-06-*
```

반영 후 Node 서버를 재시작하십시오.

## 15. 테스트 체크리스트

### 15.1 화면 확인

- `수집 관리` 메뉴 접속 가능
- `SecuMS 진단` 탭 표시
- `Script 진단` 탭 표시
- `Script 업로드` 탭 표시
- `Script 배포` 탭 표시
- 결과 화면에서 AI 전체 / LLM 상세 구분 표시

### 15.2 SecuMS 진단 테스트

- 대상 서버 선택
- `SecuMS 진단` 실행
- SecuMS raw DB 수집 성공
- AI 결과 생성
- LLM 상세 결과 생성

### 15.3 Script 진단 테스트

- 대상 서버 선택
- `Script 진단` 실행
- 기존 XML 수집 또는 스크립트 실행 fallback 확인
- Script XML 파싱 성공
- SRV ID 정규화 확인
- AI/LLM 결과 생성

### 15.4 Script 배포 테스트

- 1단계 `배포만` 실행
- 2단계 `배포 + 실행` 실행
- 3단계 `배포 + 실행 + 진단` 실행
- 진행률 표시 확인
- 결과 XML 수집 확인

### 15.5 정합성 검증

- 같은 서버에서 SecuMS 진단과 Script 진단을 각각 실행
- assessment ID 기록
- 동일 SRV 항목 판정 비교
- 불일치 항목 원인 기록
- 오탐/미탐 후보 정리

## 16. 운영상 권장 사항

- 테스트 전 `servers.csv`를 최소 1대 Linux, 1대 Windows로 구성합니다.
- 첫 테스트는 `Script 배포`의 `배포만`부터 확인합니다.
- Windows는 WinRM/SMB 권한 확인 후 `배포 + 실행`을 테스트합니다.
- 장시간 수집이 부담되면 Fast 모드로 먼저 검증합니다.
- 정합성 검증 단계에서는 동일 서버의 SecuMS 진단과 Script 진단 결과를 분리 기록합니다.
- 판정 기준 개선은 실제 샘플 결과를 기준으로 반복 보정합니다.

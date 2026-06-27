# 설치 가이드

## 사전 요구사항

- **Node.js 18 이상** (테스트: v22.22.2)
- **npm 9 이상**

OS는 Windows / macOS / Linux 모두 가능.

## 빠른 설치

```bash
# 1. zip 압축 해제
unzip vuln-assessor-v9.zip
cd vuln-assessor-v9

# 2. 의존성 설치 (약 10초)
npm install

# 3. 서버 실행
npm run mock
```

브라우저로 `http://localhost:3000` 접속.

## 트러블슈팅

### Windows에서 better-sqlite3 빌드 실패

증상: `npm install` 중 `gyp ERR! find VS` 또는 `MSBUILD` 에러

해결:
```bash
# 옵션 1: Visual Studio Build Tools 설치
npm install --global windows-build-tools

# 옵션 2: better-sqlite3 대신 sqlite3 사용 (prebuilt binary)
npm uninstall better-sqlite3
npm install sqlite3
```

### macOS에서 빌드 실패

증상: `python` not found 또는 `Xcode CLT not installed`

해결:
```bash
xcode-select --install
npm install
```

### Linux (RHEL/CentOS)

```bash
sudo yum install -y gcc-c++ make python3
npm install
```

### SQLite 모듈 둘 다 실패한 경우

화면은 정상 동작하지만 진단 실행만 안 됨. 이 경우 raw 파일은 보고서 화면용으로만 사용:

```bash
# 둘 중 어느 하나라도 깔리면 OK
npm install better-sqlite3 --build-from-source
# 또는
npm install sqlite3
```

## 검증

```bash
# 1. 서버 응답 확인
curl http://localhost:3000/

# 2. 진단 실행 (raw 파일 + sqlite 모듈 모두 필요)
curl -X POST http://localhost:3000/diagnosis/run \
  -H "Content-Type: application/json" \
  -d '{"server_id": 1}'

# 정상 응답:
# {"status":"success","assessment_id":2035,"summary":{"total":14,"vuln":5,"safe":8,"na":1},"elapsed_ms":350}
```

## 알려진 제약

- **컨테이너 환경**: 일부 Docker 베이스 이미지(alpine, slim)에서 native binding 빌드 실패 가능. → `node:22` 또는 `node:22-bookworm` 권장
- **Node.js 22+** : better-sqlite3는 Node 22 ABI 빌드 필요. prebuilt binary가 없으면 source build됨 (10~30초)

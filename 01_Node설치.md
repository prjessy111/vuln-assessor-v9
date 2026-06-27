# Node.js 설치 가이드

Vuln Assessor 실행 전에 Node.js를 먼저 설치해야 합니다.

## 1. 현재 설치 여부 확인

명령 프롬프트(cmd) 또는 PowerShell에서:

```cmd
node --version
```

- `v18.x.x` 이상 출력되면 → **이미 설치됨, 다음 단계로**
- `'node' is not recognized` 또는 `v16.x.x` 이하 → **아래 설치 진행**

---

## 2. Windows 설치 (가장 흔한 환경)

### 방법 A: 공식 인스톨러 (추천)

1. https://nodejs.org/ko 접속
2. **LTS 버전** 다운로드 (현재 시점 v22.x 또는 v20.x — 둘 다 OK)
   - `node-v22.x.x-x64.msi` 다운로드
3. msi 파일 실행 → 기본 설정으로 Next/Install
4. **반드시 체크**: "Automatically install the necessary tools..." (선택 시 Visual Studio Build Tools도 함께 설치 — better-sqlite3 빌드용)
5. 설치 후 cmd 재시작

확인:
```cmd
node --version
npm --version
```

### 방법 B: Chocolatey (이미 사용 중이라면)

```cmd
choco install nodejs-lts -y
```

### 방법 C: nvm-windows (여러 버전 관리 필요 시)

1. https://github.com/coreybutler/nvm-windows/releases 에서 `nvm-setup.exe` 다운로드
2. 설치 후 cmd 재시작
3. 명령:
   ```cmd
   nvm install lts
   nvm use lts
   ```

---

## 3. macOS 설치

### Homebrew (추천)
```bash
brew install node
```

### 공식 인스톨러
https://nodejs.org/ko 에서 macOS Installer (.pkg) 다운로드 후 실행

### nvm
```bash
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.7/install.sh | bash
nvm install --lts
```

---

## 4. Linux 설치 (RHEL/CentOS)

### NodeSource RPM (Node 20 LTS 예시)
```bash
curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -
sudo yum install -y nodejs gcc-c++ make python3
```

### Ubuntu/Debian
```bash
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt-get install -y nodejs build-essential
```

---

## 5. 설치 확인

```bash
node --version
# v20.x.x 또는 v22.x.x 출력되어야 함

npm --version
# 10.x.x 이상이면 OK
```

---

## 6. Vuln Assessor 실행

설치가 끝났으면:

```bash
# zip 압축 해제
unzip vuln-assessor-v9.zip
cd vuln-assessor-v9

# 의존성 설치 (약 10~30초)
npm install

# 서버 실행
npm run mock
```

브라우저에서 http://localhost:3000 접속.

---

## 트러블슈팅

### `npm install` 시 권한 오류 (Windows)

- 관리자 권한으로 cmd 실행
- 또는 사용자 디렉토리(C:\Users\USERNAME)에 압축 해제

### 회사 프록시 환경

```cmd
npm config set proxy http://proxy.company.com:8080
npm config set https-proxy http://proxy.company.com:8080
npm install
```

### `npm install` 멈춤 (회사망)

```cmd
npm config set registry https://registry.npmjs.org/
npm cache clean --force
npm install
```

### 포트 3000이 이미 사용 중

```cmd
set PORT=3001
npm run mock
```

(Linux/macOS: `PORT=3001 npm run mock`)

### 방화벽 알림

Windows Defender 방화벽이 묻는 경우 "액세스 허용" 클릭.

---

## 권장 사양

| 항목 | 권장 |
|---|---|
| OS | Windows 10/11, macOS 12+, RHEL 8+, Ubuntu 20+ |
| Node.js | 20 LTS 또는 22 LTS |
| RAM | 4GB 이상 |
| 디스크 | 200MB (node_modules 포함) |
| 네트워크 | npm registry 접근 가능 |

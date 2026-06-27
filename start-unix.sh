#!/bin/bash
# Vuln Assessor - Quick Start (macOS/Linux)

set -e
cd "$(dirname "$0")"

echo "========================================================"
echo "  Vuln Assessor - Quick Start"
echo "========================================================"
echo ""

# 1. Node.js 확인
echo "[1/3] Node.js 설치 확인 중..."
if ! command -v node &> /dev/null; then
    echo ""
    echo "[X] Node.js가 설치되지 않았습니다."
    echo ""
    echo "다음 방법으로 설치하세요:"
    echo ""
    if [[ "$OSTYPE" == "darwin"* ]]; then
        echo "  macOS:    brew install node"
        echo "  또는:     https://nodejs.org/ko 에서 LTS 다운로드"
    else
        echo "  Ubuntu/Debian:"
        echo "    curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -"
        echo "    sudo apt-get install -y nodejs"
        echo ""
        echo "  RHEL/CentOS:"
        echo "    curl -fsSL https://rpm.nodesource.com/setup_20.x | sudo bash -"
        echo "    sudo yum install -y nodejs"
    fi
    echo ""
    echo "자세한 안내: 01_Node설치.md"
    exit 1
fi

NODE_VER=$(node --version)
echo "    OK - Node.js $NODE_VER 감지됨"
echo ""

# Node 버전 체크 (v18 이상 필요)
NODE_MAJOR=$(echo "$NODE_VER" | sed 's/v\([0-9]*\)\..*/\1/')
if [ "$NODE_MAJOR" -lt 18 ]; then
    echo "[!] Node.js $NODE_VER 는 너무 낮습니다. v18 이상 권장."
    echo "    그래도 진행하시려면 Enter, 중단하시려면 Ctrl+C..."
    read
fi

# 2. npm install
echo "[2/3] 의존성 설치 (최초 1회만, 10~30초 소요)..."
if [ ! -d "node_modules" ]; then
    npm install
    if [ $? -ne 0 ]; then
        echo ""
        echo "[X] npm install 실패. 다음을 확인하세요:"
        echo "  - 네트워크 연결 (회사 프록시 환경?)"
        echo "  - npm registry 접근: https://registry.npmjs.org/"
        exit 1
    fi
else
    echo "    OK - node_modules 이미 존재 (건너뜀)"
fi
echo ""

# 3. 서버 실행
echo "[3/3] 서버 시작..."
echo ""
echo "========================================================"
echo "  서버가 시작되면 브라우저에서 http://localhost:3000"
echo "  접속하세요. 종료하려면 Ctrl+C 를 누르세요."
echo "========================================================"
echo ""

# 3초 후 브라우저 자동 열기 (macOS)
if [[ "$OSTYPE" == "darwin"* ]]; then
    (sleep 3 && open http://localhost:3000) &
elif command -v xdg-open &> /dev/null; then
    (sleep 3 && xdg-open http://localhost:3000) &
fi

npm run mock

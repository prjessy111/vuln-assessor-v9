@echo off
chcp 65001 > nul
title Vuln Assessor - Quick Start
cls

echo ========================================================
echo   Vuln Assessor - Quick Start (Windows)
echo ========================================================
echo.

REM === Node.js 확인 ===
echo [1/3] Node.js 설치 확인 중...
node --version > nul 2>&1
if errorlevel 1 (
    echo.
    echo [X] Node.js가 설치되지 않았습니다.
    echo.
    echo 다음 단계를 따라주세요:
    echo   1. https://nodejs.org/ko 접속
    echo   2. LTS 버전 다운로드 ^(v20 또는 v22^)
    echo   3. 설치 후 이 파일을 다시 실행
    echo.
    echo 자세한 안내는 01_Node설치.md 파일을 참고하세요.
    echo.
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('node --version') do set NODE_VER=%%i
echo     OK - Node.js %NODE_VER% 감지됨
echo.

REM === npm install ===
echo [2/3] 의존성 설치 (최초 1회만, 10~30초 소요)...
if not exist node_modules (
    call npm install
    if errorlevel 1 (
        echo.
        echo [X] npm install 실패. 다음을 확인하세요:
        echo   - 네트워크 연결 (특히 회사 프록시)
        echo   - npm registry 접근 가능 여부
        echo.
        pause
        exit /b 1
    )
) else (
    echo     OK - node_modules 이미 존재 (건너뜀)
)
echo.

REM === 서버 실행 ===
echo [3/3] 서버 시작...
echo.
echo ========================================================
echo   서버가 시작되면 브라우저에서 http://localhost:3000
echo   접속하세요.
echo   종료하려면 이 창에서 Ctrl+C 를 누르세요.
echo ========================================================
echo.

REM 3초 후 브라우저 자동 열기
start /b cmd /c "timeout /t 3 > nul && start http://localhost:3000"

call npm run mock

pause

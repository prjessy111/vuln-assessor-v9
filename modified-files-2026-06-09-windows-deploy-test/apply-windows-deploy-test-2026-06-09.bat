@echo off
setlocal EnableExtensions EnableDelayedExpansion

set "SRC=%~dp0"
set "TARGET=%~1"
set "FAILED=0"

if "%TARGET%"=="" (
  if exist "%SRC%..\package.json" if exist "%SRC%..\server-mock.js" set "TARGET=%SRC%.."
)

if "%TARGET%"=="" (
  echo Target project folder was not found automatically.
  set /p "TARGET=Enter vuln-assessor-v9-main path: "
)

if "%TARGET%"=="" (
  echo [ERROR] Target project path was not provided.
  exit /b 1
)

if not exist "%TARGET%\package.json" (
  echo [ERROR] package.json not found in target:
  echo         %TARGET%
  echo Usage:
  echo   apply-windows-deploy-test-2026-06-09.bat "E:\backup2\vuln-assessor-v9-main\vuln-assessor-v9-main"
  exit /b 1
)

if not exist "%SRC%server-mock.js" (
  echo [ERROR] This batch must be executed from the extracted modified-files folder.
  echo         Current source folder:
  echo         %SRC%
  echo.
  echo Extract modified-files-2026-06-09-windows-deploy-test.zip first,
  echo then run this batch from that extracted folder.
  exit /b 1
)

set "BACKUP=%TARGET%\backup-before-windows-deploy-2026-06-09-%RANDOM%"
mkdir "%BACKUP%" >nul 2>nul

echo.
echo Applying Windows deploy/collect/diagnosis test files
echo Source : %SRC%
echo Target : %TARGET%
echo Backup : %BACKUP%
echo.

for %%F in (
  "server-mock.js"
  ".env.example"
  "src\services\scriptDeployService.js"
  "src\services\scheduler.js"
  "src\views\collection\index.ejs"
  "src\views\diagnosis\ai_result.ejs"
  "src\engine\aiAssessment.js"
  "src\engine\adapters\scriptResult.js"
  "src\engine\llm\providers\mockScriptPatterns.js"
  "scripts\fsi_win_ai.ps1"
  "scripts\ai-ready\fsi_win_ai.ps1"
  "docs\USER_MANUAL_2026-06-06.md"
) do (
  set "REL=%%~F"
  if not exist "%SRC%!REL!" (
    echo [FAIL] Source missing: !REL!
    set "FAILED=1"
  ) else (
    for %%D in ("%TARGET%\!REL!") do (
      if not exist "%%~dpD" mkdir "%%~dpD" >nul 2>nul
    )
    if exist "%TARGET%\!REL!" (
      for %%B in ("%BACKUP%\!REL!") do (
        if not exist "%%~dpB" mkdir "%%~dpB" >nul 2>nul
      )
      copy /Y "%TARGET%\!REL!" "%BACKUP%\!REL!" >nul
    )
    copy /Y "%SRC%!REL!" "%TARGET%\!REL!" >nul
    if errorlevel 1 (
      echo [FAIL] !REL!
      set "FAILED=1"
    ) else (
      echo [OK] !REL!
    )
  )
)

echo.
if "%FAILED%"=="1" (
  echo [ERROR] Some files failed to copy. Check messages above.
  exit /b 1
)

echo [OK] Windows deploy test files were applied.
echo [INFO] Restart the Node server after this batch finishes.
exit /b 0

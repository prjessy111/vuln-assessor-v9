# Windows Script 배포/수집/진단 테스트 파일

이 폴더는 Windows Script 배포, 실행, 결과 XML 수집, AI/LLM 진단 테스트에 필요한 변경 파일만 모은 폴더입니다.

## 적용 방법

변경 파일 ZIP을 풀고, 이 배치파일을 반드시 풀린 변경 파일 폴더 안에서 실행하십시오.

```bat
apply-windows-deploy-test-2026-06-09.bat "E:\backup2\vuln-assessor-v9-main\vuln-assessor-v9-main"
```

`backup-before...` 폴더 안에서 실행하면 안 됩니다. 그 폴더는 백업본이므로 변경 파일 일부가 없어서 `Source missing` 오류가 납니다.

## 핵심 변경

- Windows 직접 배포는 SMB 445를 사용하지 않고 WinRM 5985만 사용합니다.
- WinRM 실행은 기본적으로 로컬 PowerShell `Invoke-Command` 방식을 사용합니다.
- 파일 업로드는 WinRM PowerShell Base64 조각 전송 방식으로 처리합니다.
- 로컬 PowerShell 실행은 임시 `.ps1` 파일로 처리해 `spawn ENAMETOOLONG` 명령 길이 제한을 피합니다.
- 결과 XML 다운로드도 WinRM PowerShell로 읽어서 로컬에 저장합니다.
- Linux/UNIX는 기존처럼 SSH/SFTP를 사용합니다.

## WinRM 방식 설정

`.env`에 아래 값을 넣으면 PowerShell Remoting 방식만 사용합니다.

```text
SCRIPT_DEPLOY_WINDOWS_WINRM_MODE=powershell-only
```

이 방식은 PowerShell로 직접 WinRM 테스트가 성공했던 환경과 같은 방식입니다. 기존 `nodejs-winrm` Basic 인증 방식으로 되돌리고 싶을 때만 아래 값을 사용하십시오.

```text
SCRIPT_DEPLOY_WINDOWS_WINRM_MODE=nodejs-winrm
```

## 포함 파일

- `server-mock.js`
- `.env.example`
- `src/services/scriptDeployService.js`
- `src/services/scheduler.js`
- `src/views/collection/index.ejs`
- `src/views/diagnosis/ai_result.ejs`
- `src/engine/aiAssessment.js`
- `src/engine/adapters/scriptResult.js`
- `src/engine/llm/providers/mockScriptPatterns.js`
- `scripts/fsi_win_ai.ps1`
- `scripts/ai-ready/fsi_win_ai.ps1`
- `docs/USER_MANUAL_2026-06-06.md`

## Windows 테스트 전 확인

- 대상 Windows 서버에서 WinRM 5985가 열려 있어야 합니다.
- `servers.csv`에 Windows 서버 IP, 계정, 비밀번호가 있어야 합니다.
- 작업그룹/로컬 계정이면 username을 `대상호스트명\계정` 또는 `대상IP\계정` 형식으로 넣는 것을 권장합니다.
- 화면에서 인증 정보를 비우면 `servers.csv` 값을 사용합니다.
- 원격 작업 폴더는 실제 생성 가능한 경로를 넣으십시오.
- IP 주소로 접속하는 경우 Node 서버가 실행되는 PC에서 `TrustedHosts` 설정이 필요할 수 있습니다.

예:

```text
C:\Windows\Temp
E:\backup2\script
```

Node 서버가 실행되는 PC에서 관리자 PowerShell로 아래를 확인할 수 있습니다.

```powershell
Test-WSMan 192.168.159.167
Get-Item WSMan:\localhost\Client\TrustedHosts
Set-Item WSMan:\localhost\Client\TrustedHosts -Value 192.168.159.167 -Force
```

여러 서버를 테스트하려면 쉼표로 추가하거나 테스트 환경에서만 `*`를 사용할 수 있습니다.

```powershell
Set-Item WSMan:\localhost\Client\TrustedHosts -Value "192.168.159.167,192.168.159.108" -Force
```

직접 인증 테스트:

```powershell
$sec = ConvertTo-SecureString "비밀번호" -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential("192.168.159.167\admin", $sec)
Invoke-Command -ComputerName 192.168.159.167 -Credential $cred -ScriptBlock { hostname; whoami; $env:TEMP }
```

이 명령이 `AccessDenied`로 실패하면 애플리케이션 문제가 아니라 대상 Windows 서버의 원격 실행 권한 문제입니다.

## 테스트 순서

1. ZIP을 풉니다.
2. 위 명령으로 배치파일을 실행합니다.
3. Node 서버를 재시작합니다.
4. `수집 관리 > Script 배포`로 이동합니다.
5. Windows 서버를 선택합니다.
6. 인증 정보는 비워서 `servers.csv` 사용을 먼저 테스트합니다.
7. `scripts\ai-ready\fsi_win_ai.ps1`을 업로드합니다.
8. 먼저 `2. 배포 + 실행`을 테스트합니다.
9. 성공하면 `3. 배포 + 실행 + 진단`을 테스트합니다.

## 성공 확인

- 최근 Script 배포 작업 진행률이 100%인지 확인합니다.
- `result_file`에 XML 파일명이 표시되는지 확인합니다.
- `remote_dir`, `remote_output_dir`, `remote_result`가 표시되는지 확인합니다.
- 진단까지 실행한 경우 assessment ID가 생성되는지 확인합니다.

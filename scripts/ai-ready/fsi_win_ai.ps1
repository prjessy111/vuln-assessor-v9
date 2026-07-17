# =========================================================================
# fsi_win_ai.ps1 - 윈도우 보안 진단 100% 통합 스크립트 (XML 특수문자 완벽 패치본)
# =========================================================================

param(
    [switch]$Fast,
    [switch]$Full,
    [switch]$DeepLibScan,
    [string]$OutputDir = "",
    [string]$OutputName = "",
    [string]$MssqlServer = "",
    [string]$MssqlUser = "",
    [string]$MssqlPassword = ""
)

$ErrorActionPreference = "SilentlyContinue"
# 네이티브 명령(net/sc/systeminfo/w32tm 등)의 한글 출력이 콘솔 코드페이지(cp949)로 깨지는 것 방지 — UTF-8 강제
try { $oemcp = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\CodePage' -Name OEMCP -ErrorAction Stop).OEMCP; [Console]::OutputEncoding = [System.Text.Encoding]::GetEncoding([int]$oemcp) } catch {}
# 기본값 full — AI/LLM 정밀 판정 및 CVE(핫픽스/systeminfo) 증거를 모두 수집.
# 속도가 필요하면 -Fast (또는 FSI_FAST_MODE=1) 로 명시.
$FastMode = if ($Full) { $false } elseif ($Fast) { $true } elseif ($env:FSI_FAST_MODE -eq "1") { $true } elseif ($env:FSI_FULL_MODE -eq "1") { $false } else { $false }
$collectionProfile = if ($FastMode) { "fast" } else { "full" }
# 깊은 네이티브 OSS 라이브러리 스캔(DLL 바이너리 읽기) — 무겁고 자원 부담이 커 기본 OFF. -DeepLibScan 또는 FSI_DEEP_LIB_SCAN=1 일 때만.
$DeepLibMode = if ($DeepLibScan) { $true } elseif ($env:FSI_DEEP_LIB_SCAN -eq "1") { $true } else { $false }
$hostname = $env:COMPUTERNAME
if ([string]::IsNullOrWhiteSpace($hostname)) { $hostname = "unknown-windows" }
$dateStr = (Get-Date).ToString("yyyyMMdd")
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($scriptDir)) { $scriptDir = (Get-Location).Path }
$outputDirValue = if (-not [string]::IsNullOrWhiteSpace($OutputDir)) { $OutputDir } elseif (-not [string]::IsNullOrWhiteSpace($env:FSI_OUTPUT_DIR)) { $env:FSI_OUTPUT_DIR } else { $scriptDir }
New-Item -ItemType Directory -Force -Path $outputDirValue | Out-Null
$xmlName = if (-not [string]::IsNullOrWhiteSpace($OutputName)) { $OutputName } else { "$hostname-s-$dateStr.xml" }
$xmlPath = Join-Path $outputDirValue $xmlName
$legacyXmlPath = Join-Path $outputDirValue "fsi_result_win.xml"
$secFilePath = Join-Path $outputDirValue "sec.txt"
$script:XmlBlocks = New-Object 'System.Collections.Generic.List[string]'
$osInfo = if ($FastMode) { $null } else { Get-CimInstance Win32_OperatingSystem }
$osCaption = if ($osInfo -and $osInfo.Caption) { $osInfo.Caption } else { "windows" }
$osVersion = if ($osInfo -and $osInfo.Version) { $osInfo.Version } else { [System.Environment]::OSVersion.VersionString }
$privilegeState = "unknown"
try {
    $currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal($currentIdentity)
    $privilegeState = if ($currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { "administrator" } else { "standard_user" }
} catch {
    $privilegeState = "unknown"
}

# 1. XML 헤더 생성 (인코딩을 실제 파일 포맷인 utf-8로 맞춤)
@"
<?xml version="1.0" encoding="utf-8"?>
<script>
    <asset>
        <hostname>$hostname</hostname>
        <os>$osCaption</os>
        <uname>$osVersion</uname>
        <whoami>$env:USERNAME</whoami>
        <version>fsi2018v2</version>
        <collection_tool>powershell_single_file</collection_tool>
        <collection_profile>$collectionProfile</collection_profile>
        <slow_check_policy>fast skips high-latency inventory commands; run with -Full for complete evidence.</slow_check_policy>
        <ai_intake_profile>fast_ai_then_precise_llm</ai_intake_profile>
        <data_role>raw_data_provider</data_role>
        <judgment_mode>raw_evidence_only</judgment_mode>
        <verdict_source>none</verdict_source>
        <verdict_contract>script_never_decides; ai_fast_pattern_triage; llm_precise_evidence_review</verdict_contract>
        <safe_type_policy>AI decides absence-good or value-compliant-good from raw output only.</safe_type_policy>
    </asset>
    <results>
"@ | Out-File $xmlPath -Encoding UTF8

# 2. 로컬 보안 정책(secedit) 사전 추출
& secedit /EXPORT /CFG $secFilePath | Out-Null
$secData = if (Test-Path $secFilePath) { Get-Content $secFilePath } else { "" }
$netstatData = netstat -an 2>&1

# 3. XML 블록 생성 전용 함수 (특수문자 이스케이프 완벽 적용)
function ConvertTo-FsiXmlText {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return "" }
    return ([string]$Value) -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;'
}


function Write-FsiItem {
    param([string]$ID, [string]$CommandText, [scriptblock]$Action)

    $output = ""
    $status = "collected"
    $errorText = ""
    $startedAt = (Get-Date).ToUniversalTime().ToString("o")
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $res = & $Action 2>&1
        if ($null -ne $res) {
            $output = ($res | Out-String).Trim()
        }
        if ([string]::IsNullOrWhiteSpace($output)) {
            $status = "no_data"
            $output = "Not Found / No Data"
        }
    } catch {
        $status = "error"
        $errorText = $_.Exception.Message
        $output = "ERROR: $errorText"
    } finally {
        $sw.Stop()
    }

    # [AI-friendly] 빈 출력/오류를 "미설치(부재양호)" vs "수집실패(판정불가)" vs "미설정(기본값)" 으로
    # AI/LLM 이 구분할 수 있게 명시 힌트를 부여한다. (Linux sh 의 SERVICE_PRESENCE/fOrElse 와 동일 취지)
    # 주의: '& $Action 2>&1' 가 "is not recognized" 같은 오류를 output 에 합쳐버려 status 가 collected 로 남는다.
    #       따라서 status 와 무관하게 output+errorText 내용을 스캔한다.
    $probeText = "$output`n$errorText"
    if ($probeText -match '(?i)is not recognized|not recognized as|cannot find|does not exist|no such (file|object|cmdlet)|not installed|openservice.*1060|CommandNotFound|미설치|설치되어 있지 않|찾을 수 없|인식되지 않|용어가.*인식|이름으로 인식') {
        # 명령/도구/서비스/기능이 미설치 → 위험 주체 부재
        $output = $output + "`nCOLLECTION_HINT=target_absent : 점검에 쓰인 명령/도구/서비스/기능이 시스템에 존재하지 않음(미설치). 예: appcmd 미인식=IIS 미설치, tlntadmn 미인식=Telnet 미설치, dnscmd=DNS 미설치. 이런 서비스/기능 한정 점검은 위험 주체가 없으므로 absence-good(부재양호=SAFE)로 판정하라. 판정불가로 빠지지 말 것."
    } elseif ($probeText -match '(?i)access is denied|access denied|elevation|requires admin|denied|UnauthorizedAccess|privilege|관리자 권한|액세스가 거부') {
        $output = $output + "`nCOLLECTION_HINT=collection_denied : 권한 부족 등으로 수집 자체가 실패함. 양호로 단정하지 말고 unable(판정불가). 대상 부재(부재양호)로 오인 금지."
    } elseif ($status -eq "no_data" -or $status -eq "error") {
        $output = $output + "`nCOLLECTION_HINT=empty_or_unset : 수집 결과가 비었거나 설정이 존재하지 않음. (1) 점검 대상이 항상 존재하는 항목(예: 계정/SAM/시스템 정책)이면 데이터 부족이므로 unable. (2) 보안 강화용 설정/레지스트리 키가 단순 미설정이면 시스템 기본값으로 동작하므로 그 기본 동작 기준으로 판정(강화 미적용=취약 가능, 기본값이 안전하면 양호)."
    }

    $safeCommandText = ConvertTo-FsiXmlText $CommandText
    $safeOutput = ConvertTo-FsiXmlText $output
    $safeStatus = ConvertTo-FsiXmlText $status
    $safeErrorText = ConvertTo-FsiXmlText $errorText
    $safeProfile = ConvertTo-FsiXmlText $collectionProfile
    $safePrivilege = ConvertTo-FsiXmlText $privilegeState
    $safeStartedAt = ConvertTo-FsiXmlText $startedAt
    $outputBytes = [System.Text.Encoding]::UTF8.GetByteCount($output)
    $durationMs = [int]$sw.ElapsedMilliseconds

    $xmlBlock = @"
        <dump>
            <items><id>$ID</id></items>
            <evidence_profile>
                <evidence_schema>ai_ready_script_v2</evidence_schema>
                <check_ids>$ID</check_ids>
                <os_family>windows</os_family>
                <collection_profile>$safeProfile</collection_profile>
                <collection_status>$safeStatus</collection_status>
                <collector_privilege>$safePrivilege</collector_privilege>
                <started_at_utc>$safeStartedAt</started_at_utc>
                <duration_ms>$durationMs</duration_ms>
                <data_role>raw_command_output</data_role>
                <judgment_mode>raw_evidence_only</judgment_mode>
                <verdict_source>none</verdict_source>
                <decision_route>AI_fast_pattern_triage_first; LLM_precise_evidence_review_second</decision_route>
                <safe_type_policy>AI decides absence-good or value-compliant-good from raw output only.</safe_type_policy>
                <output_format>ai_evidence_block_v2</output_format>
                <command_marker>cmd#</command_marker>
                <raw_begin_marker>RAW_COMMAND_OUTPUT_BEGIN</raw_begin_marker>
                <raw_end_marker>RAW_COMMAND_OUTPUT_END</raw_end_marker>
            </evidence_profile>
            <output>
AI_EVIDENCE_BLOCK_BEGIN
schema=ai_ready_script_v2
check_ids=$ID
os_family=windows
collection_profile=$safeProfile
collection_status=$safeStatus
collector_privilege=$safePrivilege
started_at_utc=$safeStartedAt
duration_ms=$durationMs
output_bytes=$outputBytes
error_text=$safeErrorText
command_marker=cmd#
command=$safeCommandText
RAW_COMMAND_OUTPUT_BEGIN
cmd# $safeCommandText
$safeOutput
RAW_COMMAND_OUTPUT_END
AI_EVIDENCE_BLOCK_END
            </output>
        </dump>
"@
    [void]$script:XmlBlocks.Add($xmlBlock)
}

function Write-FsiSkippedItem {
    param([string]$ID, [string]$CommandText, [string]$Reason)

    $safeCommandText = ConvertTo-FsiXmlText $CommandText
    $safeReason = ConvertTo-FsiXmlText $Reason
    $safeProfile = ConvertTo-FsiXmlText $collectionProfile
    $safePrivilege = ConvertTo-FsiXmlText $privilegeState
    $startedAt = (Get-Date).ToUniversalTime().ToString("o")
    $safeStartedAt = ConvertTo-FsiXmlText $startedAt

    $xmlBlock = @"
        <dump>
            <items><id>$ID</id></items>
            <evidence_profile>
                <evidence_schema>ai_ready_script_v2</evidence_schema>
                <check_ids>$ID</check_ids>
                <os_family>windows</os_family>
                <collection_profile>$safeProfile</collection_profile>
                <collection_status>skipped_for_speed</collection_status>
                <collector_privilege>$safePrivilege</collector_privilege>
                <started_at_utc>$safeStartedAt</started_at_utc>
                <duration_ms>0</duration_ms>
                <data_role>raw_command_output</data_role>
                <judgment_mode>raw_evidence_only</judgment_mode>
                <verdict_source>none</verdict_source>
                <decision_route>AI_fast_pattern_triage_first; LLM_precise_evidence_review_second</decision_route>
                <safe_type_policy>AI decides absence-good or value-compliant-good from raw output only.</safe_type_policy>
                <output_format>ai_evidence_block_v2</output_format>
                <command_marker>cmd#</command_marker>
                <raw_begin_marker>RAW_COMMAND_OUTPUT_BEGIN</raw_begin_marker>
                <raw_end_marker>RAW_COMMAND_OUTPUT_END</raw_end_marker>
            </evidence_profile>
            <output>
AI_EVIDENCE_BLOCK_BEGIN
schema=ai_ready_script_v2
check_ids=$ID
os_family=windows
collection_profile=$safeProfile
collection_status=skipped_for_speed
collector_privilege=$safePrivilege
started_at_utc=$safeStartedAt
duration_ms=0
output_bytes=0
skip_reason=$safeReason
command_marker=cmd#
command=$safeCommandText
RAW_COMMAND_OUTPUT_BEGIN
cmd# $safeCommandText
SKIPPED_FOR_SPEED: $safeReason
RAW_COMMAND_OUTPUT_END
AI_EVIDENCE_BLOCK_END
            </output>
        </dump>
"@
    [void]$script:XmlBlocks.Add($xmlBlock)
}

function Invoke-FsiMaybeSlowItem {
    param([string]$ID, [string]$CommandText, [scriptblock]$Action, [string]$Reason)
    if ($FastMode) {
        Write-FsiSkippedItem $ID $CommandText $Reason
    } else {
        Write-FsiItem $ID $CommandText $Action
    }
}

# =========================================================================
# 본격적인 점검 항목 시작
# =========================================================================

# [계정 관리 및 권한]
Write-FsiItem "SRV-022" 'REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse' { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LimitBlankPasswordUse | Select LimitBlankPasswordUse }
Write-FsiItem "SRV-071" 'type sec.txt | Find /I ClearTextPassword' { $secData | Select-String "ClearTextPassword" }
Write-FsiItem "SRV-072" '2026: 기본 관리자 계정명(Administrator) 변경 여부 — net user Administrator + net localgroup Administrators' { net user Administrator; net localgroup Administrators }
Write-FsiItem "SRV-073" 'net localgroup Administrators; local admin membership evidence' { net localgroup Administrators; Get-LocalGroupMember Administrators | Format-Table Name, ObjectClass, PrincipalSource }
Write-FsiItem "SRV-074" '2026: 계정 비밀번호 변경일자/로그온 기록(미관리 계정 식별)' { Get-LocalUser | Format-Table Name, Enabled, PasswordRequired, PasswordLastSet, LastLogon -AutoSize }
Write-FsiItem "SRV-077" 'local user password policy flags' { Get-LocalUser | Format-Table Name, Enabled, PasswordRequired, PasswordExpires, UserMayChangePassword, LastLogon }
Write-FsiItem "SRV-078" 'net user guest' { Get-LocalUser -Name "Guest" | Format-Table Name, Enabled }
Write-FsiItem "SRV-079" 'reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v everyoneincludesanonymous' { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name everyoneincludesanonymous | Select everyoneincludesanonymous }
Write-FsiItem "SRV-113" 'type sec.txt | Find /I SeSecurityPrivilege' { $secData | Select-String "SeSecurityPrivilege" }
Write-FsiItem "SRV-115" 'log review (audit policy / event log settings)' { "--- audit policy ---"; (auditpol /get /category:* 2>&1 | Out-String); "--- Security event log config ---"; (wevtutil gl Security 2>&1 | Out-String); "POLICY_NOTE: '로그의 정기적 검토 및 보고 수행 여부'(SRV-115)는 금융보안원 OS 점검 기준상 Information(정보) 항목이다 — 정기 검토/분석/보고는 조직의 운영 절차이므로 시스템 스캔만으로 취약/양호를 판정할 수 없다. 감사정책/로그설정 수집값과 무관하게 verdict=정보제공(INFO)으로 판정하라(취약/양호/판정불가 아님)." }
Write-FsiItem "SRV-123" 'reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v DontDisplayLastUserName' { Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system" -Name DontDisplayLastUserName | Select DontDisplayLastUserName }
Write-FsiItem "SRV-124" 'reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon /v AutoAdminLogon' { Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" | Select-Object AutoAdminLogon, DefaultUserName }
Write-FsiItem "SRV-125" 'reg query "HKEY_CURRENT_USER\Control Panel\desktop" /v ScreenSaveActive' { Get-ItemProperty "HKCU:\Control Panel\desktop" | Select-Object ScreenSaveActive, ScreenSaveTimeOut, ScreenSaverIsSecure }
Write-FsiItem "SRV-127" 'net accounts' { net accounts }
Write-FsiItem "SRV-136" 'reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v ShutdownWithoutLogon' { Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system" -Name ShutdownWithoutLogon | Select ShutdownWithoutLogon }
Write-FsiItem "SRV-137" 'type sec.txt | Find /I SeNetworkLogonRight' { $secData | Select-String "SeNetworkLogonRight|SeDenyNetworkLogonRight" }
Write-FsiItem "SRV-138" 'type sec.txt | Find /I SeBackupPrivilege' { $secData | Select-String "SeBackupPrivilege|SeRestorePrivilege" }
Write-FsiItem "SRV-139" 'type sec.txt | Find /I SeTakeOwnershipPrivilege' { $secData | Select-String "SeTakeOwnershipPrivilege" }
Write-FsiItem "SRV-152" '2026: 원격터미널 접속 사용자 그룹 제한(SeRemoteInteractiveLogonRight + Remote Desktop Users)' { $secData | Select-String "SeRemoteInteractiveLogonRight|SeDenyRemoteInteractiveLogonRight"; net localgroup "Remote Desktop Users" }
Write-FsiItem "SRV-156" 'type sec.txt | Find /I SeRemoteInteractiveLogonRight' { $secData | Select-String "SeRemoteInteractiveLogonRight" }
Write-FsiItem "SRV-163" 'reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v LegalNoticeCaption' { Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\policies\system" | Select-Object LegalNoticeCaption, LegalNoticeText }

# [네트워크 및 서비스 설정]
Write-FsiItem "SRV-001" '2026 확인방법: SNMP community + WMI 서비스 + DCOM 인증수준(LegacyAuthenticationLevel) + LAN Manager 인증수준(LmCompatibilityLevel/NTLMv2)' { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\services\SNMP\Parameters\ValidCommunities" -EA SilentlyContinue; sc.exe query SNMP; sc.exe query Winmgmt; Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Ole" -Name LegacyAuthenticationLevel -EA SilentlyContinue | Select LegacyAuthenticationLevel; Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LmCompatibilityLevel -EA SilentlyContinue | Select LmCompatibilityLevel }
Write-FsiItem "SRV-002" 'SNMP 서비스 상태 게이트 + REG QUERY PermittedManagers' { if (Get-Service SNMP -ErrorAction SilentlyContinue) { $pm = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers" -ErrorAction SilentlyContinue; if ($pm) { $pm } else { '(SNMP 서비스 설치됨 + PermittedManagers 미설정 -> 허용 관리자 제한 없음)' } } else { 'SNMP service not installed -> target_absent' } }
Write-FsiItem "SRV-003" 'sc query SNMP; REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers"' { sc.exe query SNMP; Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers" }
Write-FsiItem "SRV-004" 'netstat -an | findstr :25' { $netstatData | Select-String ":25"; sc.exe query SMTPSVC }
Write-FsiItem "SRV-013" 'netstat -an | findstr :21' { $netstatData | Select-String ":21"; sc.exe query MSFTPSVC; sc.exe query FTPSVC }
Write-FsiItem "SRV-037" 'sc query MSFTPSVC; sc query FTPSVC; netstat -an | findstr :21' { sc.exe query MSFTPSVC; sc.exe query FTPSVC; $netstatData | Select-String ":21" }
Write-FsiItem "SRV-018" 'net share(공유 현황) + REG AutoShareServer/Wks' { net share; Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Lanmanserver\Parameters" | Select AutoShareServer, AutoShareWks }
Write-FsiItem "SRV-020" 'net share' { if ($FastMode) { net share } else { net share; Get-SmbShare | Where-Object { $_.Path } | ForEach-Object { "SHARE $($_.Name) -> $($_.Path)"; Get-Acl $_.Path | Format-List Path, AccessToString } } }
Write-FsiItem "SRV-023" 'REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MinEncryptionLevel' { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name MinEncryptionLevel | Select MinEncryptionLevel }
Write-FsiItem "SRV-024" '2026: 취약한 Telnet 인증 방식(tlntadmn config) + Telnet 서비스 상태' { tlntadmn config 2>$null; sc.exe query TlntSvr }
Write-FsiItem "SRV-028" 'REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MaxIdleTime' { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name MaxIdleTime | Select MaxIdleTime }
Write-FsiItem "SRV-029" 'REG QUERY "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v EnableForcedLogOff' { Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" | Select EnableForcedLogOff, autodisconnect }
Write-FsiItem "SRV-031" 'REG QUERY HKLM\SYSTEM\CurrentControlSet\Control\LSA /v RestrictAnonymous' { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" | Select RestrictAnonymous, RestrictAnonymousSam }
Write-FsiItem "SRV-032" 'netsh interface show interface' { if ($FastMode) { netsh interface show interface } else { Get-NetAdapter | Format-Table Name, InterfaceDescription, Status; "--- NetbiosOptions per interface (0=default/enabled, 1=enabled, 2=disabled) ---"; Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\*' -Name NetbiosOptions -ErrorAction SilentlyContinue | Format-List PSChildName, NetbiosOptions } }
Write-FsiItem "SRV-034" '2026: NetBIOS over TCP/IP(NetbiosOptions) + 불필요 서비스(Alerter/ClipSrv/Messenger/SimpTcp)' { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_*" -Name NetbiosOptions -EA SilentlyContinue | Select PSChildName, NetbiosOptions; sc.exe query Alerter; sc.exe query ClipSrv; sc.exe query Messenger; sc.exe query SimpTcp }
Write-FsiItem "SRV-063" 'DNS 서비스 상태 게이트 + reg query NoRecursion' { if (Get-Service DNS -ErrorAction SilentlyContinue) { $nr = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" -Name NoRecursion -ErrorAction SilentlyContinue; if ($nr) { $nr | Select NoRecursion } else { '(DNS 서버 서비스 실행 중 + NoRecursion 미설정 -> 기본값: 재귀 질의 허용)' } } else { 'DNS Server service not installed -> target_absent' } }
Write-FsiItem "SRV-066" 'sc query dns; reg query DNS Server Zones' { sc.exe query DNS; reg.exe query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" /s; reg.exe query "HKLM\System\CurrentControlSet\Services\DNS\Zones" /s }
Write-FsiItem "SRV-067" 'reg query W3SVC ADCLaunch; type %SystemRoot%\msdfmap.ini' { reg.exe query "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch"; Get-Content "$env:SystemRoot\msdfmap.ini" }
Write-FsiItem "SRV-080" 'reg query "HKLM\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers' { Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" -Name AddPrinterDrivers | Select AddPrinterDrivers }
Write-FsiItem "SRV-090" 'sc qc RemoteRegistry (StartMode) + sc query (state)' { sc.exe qc RemoteRegistry; sc.exe query RemoteRegistry }
Write-FsiItem "SRV-103" 'REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel' { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LmCompatibilityLevel | Select LmCompatibilityLevel }
Write-FsiItem "SRV-104" 'REG QUERY "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v RequireSignOrSeal' { Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" | Select RequireSignOrSeal, SealSecureChannel, SignSecureChannel }
Write-FsiItem "SRV-141" 'netsh advfirewall show allprofiles' { netsh advfirewall show allprofiles }
Write-FsiItem "SRV-150" '2026: 로컬 로그온 허용 계정 제한(SeInteractiveLogonRight)' { $secData | Select-String "SeInteractiveLogonRight|SeDenyInteractiveLogonRight" }
Write-FsiItem "SRV-158" 'netstat -an' { if ($FastMode) { $netstatData | Select-Object -First 200 } else { $netstatData } }

# [시스템 주요 폴더 및 파일 권한]
Write-FsiItem "SRV-068" 'REG SAVE HKLM\SAM' { $r = Get-ChildItem "C:\Windows\Repair\sam", "C:\Windows\Repair\system" -ErrorAction SilentlyContinue; if ($r) { $r | Format-List FullName, Length, LastWriteTime } else { "NO_EXPOSED_BACKUP: C:\Windows\Repair 에 SAM/SYSTEM 백업 파일이 없음 -> 노출된 자격증명 백업 없음(safe)" } }
Write-FsiItem "SRV-069" 'secedit /EXPORT /CFG securitypolicy' { $secData | Select-String "SeDeny|Se.*Privilege|Password|Lockout|Audit" }
Write-FsiItem "SRV-098" 'cacls C:\Windows\system32\config\SAM' { Get-Acl "C:\Windows\system32\config\SAM" | Format-List Path, AccessToString }
Invoke-FsiMaybeSlowItem "SRV-101" 'schtasks' { schtasks /query /fo LIST } 'Skipped in fast mode because scheduled task inventory can be slow. Run -Full for complete evidence.'
Write-FsiItem "SRV-102" 'cacls (ALL_USERS)' { Get-ChildItem "C:\Users" -Directory | ForEach-Object { Get-Acl $_.FullName | Format-List Path, AccessToString } }
Write-FsiItem "SRV-105" 'REG QUERY HKLM/HKCU Run' { reg.exe query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"; reg.exe query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" }
Write-FsiItem "SRV-110" 'cacls C:\Windows\system32\config' { Get-Acl "C:\Windows\system32\config" | Format-List Path, AccessToString }
Write-FsiItem "SRV-111" 'reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Application" /v RestrictGuestAccess' { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\*" -Name RestrictGuestAccess | Select PSChildName, RestrictGuestAccess }
Write-FsiItem "SRV-109" 'secedit /EXPORT /CFG securitypolicy; event log policy evidence' { $secData | Select-String "Audit|EventLog|Retention|MaximumLogSize"; Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\*" | Select PSChildName, MaxSize, Retention, RestrictGuestAccess }
Write-FsiItem "SRV-116" 'reg query HKLM\system\currentcontrolset\control\lsa /v crashonauditfail' { Get-ItemProperty "HKLM:\system\currentcontrolset\control\lsa" -Name crashonauditfail | Select crashonauditfail }
Invoke-FsiMaybeSlowItem "SRV-117" 'systeminfo' { systeminfo } 'Skipped in fast mode because full systeminfo can be slow. Run -Full for complete evidence.'
Write-FsiItem "SRV-119" 'Anti-Virus process scan + Windows Update status' { $av = Get-Process | Where-Object { $_.ProcessName -match 'V3|AYAgent|ViRobot|hvrtray|ccSvcHst|^Smc$|SepMasterService|mcshield|masvc|^avp$|TmListen|NTRTscan|ekrn|SavService|bdagent' } | Select-Object -ExpandProperty ProcessName -Unique; if ($av) { "AV_PROCESS_DETECTED=$($av -join ',')" } else { 'AV_PROCESS_DETECTED=none (백신 프로세스 미검출 - 백신 미설치 또는 미실행)' }; sc.exe query wuauserv; Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" }
Invoke-FsiMaybeSlowItem "SRV-120" 'wmic qfe list' { Get-HotFix | Format-Table HotFixID, InstalledOn, Description } 'Skipped in fast mode because hotfix inventory can be slow. Run -Full for complete evidence.'
# 설치 소프트웨어 인벤토리 (레지스트리 Uninstall) — 서드파티 SW CVE 매칭용 (rpm -qa 의 Windows 대응).
# Win32_Product 는 느리고 MSI 복구를 유발할 수 있어 사용하지 않고 레지스트리를 직접 열거.
Invoke-FsiMaybeSlowItem "INV-SOFTWARE" 'installed software inventory (registry Uninstall)' { $invPaths = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'); Get-ItemProperty $invPaths -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName } | ForEach-Object { $_.DisplayName.ToString() + ' | ' + ([string]$_.DisplayVersion) + ' | ' + ([string]$_.Publisher) } | Sort-Object -Unique } 'Skipped in fast mode because software inventory enumeration can be slow. Run -Full for complete evidence.'
# JAR(자바 라이브러리) 인벤토리 — 내장 라이브러리 CVE(Log4j/Commons 등) 매칭용. 레지스트리에 안 나오는 계층.
# 전체 디스크는 느려서 일반적인 앱/자바 경로로 한정. 결과는 파일명만(버전 파싱은 분석기가 수행).
Invoke-FsiMaybeSlowItem "INV-JAR" 'java jar/library inventory (filesystem)' { $roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, 'C:\apps','C:\app','C:\opt','C:\Java','C:\tomcat','C:\Program Files\Java','D:\') | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique; if ($roots) { Get-ChildItem -Path $roots -Recurse -Filter *.jar -ErrorAction SilentlyContinue -Depth 12 | Select-Object -ExpandProperty Name -Unique } else { 'NO_JAR_PATHS' } } 'Skipped in fast mode because filesystem JAR scan is slow. Run -Full for complete evidence.'
# 네이티브 OSS 라이브러리 버전 프로브 — 번들된 .dll 의 임베드 버전 문자열에서 OpenSSL/zlib/expat/sqlite/pcre 버전 추출 (POCO 등이 번들한 OSS CVE 매칭).
Invoke-FsiMaybeSlowItem "INV-NATIVELIB" 'native OSS library version probe (dll embedded strings)' { if (-not $DeepLibMode) { 'DISABLED: deep native library scan off (enable with -DeepLibScan or FSI_DEEP_LIB_SCAN=1)' } else { $roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, 'C:\apps','C:\app','C:\opt','C:\tomcat','D:\') | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique; if (-not $roots) { 'NO_LIB_PATHS' } else { $names = 'libssl*.dll','libcrypto*.dll','ssleay32*.dll','libeay32*.dll','openssl*.dll','zlib*.dll','zlibwapi*.dll','libexpat*.dll','expat*.dll','sqlite3*.dll','libsqlite*.dll','pcre*.dll','libpcre*.dll','libxml2*.dll','poco*.dll','Poco*.dll','tinyxml*.dll','TinyXml*.dll','*sigar*.dll'; $files = Get-ChildItem -Path $roots -Recurse -Include $names -ErrorAction SilentlyContinue | Where-Object { $_.Length -lt 31457280 } | Select-Object -First 200; foreach ($f in $files) { try { $fs = [System.IO.File]::OpenRead($f.FullName); $len = [int][Math]::Min([long]$fs.Length, 8388608); $buf = New-Object byte[] $len; [void]$fs.Read($buf, 0, $len); $fs.Close(); $txt = [System.Text.Encoding]::ASCII.GetString($buf); $n = $f.Name.ToLower(); if ($n -match 'ssl|crypto|eay') { if ($txt -match 'OpenSSL\s+(\d+\.\d+\.\d+[a-z]*)') { 'openssl | ' + $matches[1] + ' | ' + $f.Name } } elseif ($n -match 'zlib') { if ($txt -match '(?:inflate|deflate)\s+(\d+\.\d+\.\d+)') { 'zlib | ' + $matches[1] + ' | ' + $f.Name } } elseif ($n -match 'expat') { if ($txt -match 'expat_(\d+\.\d+\.\d+)') { 'expat | ' + $matches[1] + ' | ' + $f.Name } } elseif ($n -match 'sqlite') { if ($txt -match '\b(3\.\d+\.\d+(?:\.\d+)?)\b') { 'sqlite | ' + $matches[1] + ' | ' + $f.Name } } elseif ($n -match 'pcre') { if ($txt -match '\b(\d+\.\d+)\s+\d{4}-\d\d-\d\d') { 'pcre | ' + $matches[1] + ' | ' + $f.Name } } elseif ($n -match 'poco') { if ($txt -match 'POCO[^0-9]{0,40}(\d+\.\d+\.\d+)') { 'poco | ' + $matches[1] + ' | ' + $f.Name } } elseif ($n -match 'tinyxml') { if ($txt -match 'TinyXML[^0-9]{0,15}(\d+\.\d+\.\d+)') { 'tinyxml | ' + $matches[1] + ' | ' + $f.Name } } elseif ($n -match 'sigar') { if ($txt -match 'sigar[^0-9]{0,15}(\d+\.\d+\.\d+)') { 'sigar | ' + $matches[1] + ' | ' + $f.Name } } elseif ($n -match 'xml2') { if ($txt -match '(\d+\.\d+\.\d+)') { 'libxml2 | ' + $matches[1] + ' | ' + $f.Name } } } catch {} } } } } 'Skipped in fast mode because native library scan is slow. Run -Full for complete evidence.'
# SBOM 인벤토리 — 호스트의 CycloneDX/SPDX SBOM 파일을 수집(있으면 가장 정확한 컴포넌트 식별, purl 기반).
Invoke-FsiMaybeSlowItem "INV-SBOM" 'SBOM files (CycloneDX/SPDX)' { $roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, 'C:\apps','C:\app','C:\opt','D:\') | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique; if (-not $roots) { 'NO_SBOM' } else { $sb = Get-ChildItem -Path $roots -Recurse -Include 'bom.json','*.cdx.json','*cyclonedx*.json','*.spdx.json','*spdx*.json' -ErrorAction SilentlyContinue | Select-Object -First 10; foreach ($s in $sb) { try { (Get-Content $s.FullName -Raw -ErrorAction SilentlyContinue) } catch {} } } } 'Skipped in fast mode. Run -Full for complete evidence.'
# 비정기(압축형) 설치 아카이브 — war/ear/zip/tar.gz 목록. 압축 푼 것은 JAR/네이티브 스캔이, 미해제 아카이브는 여기서 가시화.
Invoke-FsiMaybeSlowItem "INV-ARCHIVE" 'install archives (war/ear/zip/tar.gz)' { $roots = @($env:ProgramFiles, ${env:ProgramFiles(x86)}, 'C:\apps','C:\app','C:\opt','C:\tomcat','D:\') | Where-Object { $_ -and (Test-Path $_) } | Select-Object -Unique; if (-not $roots) { 'NO_ARCHIVE_PATHS' } else { Get-ChildItem -Path $roots -Recurse -Include '*.war','*.ear','*.zip','*.tar.gz','*.tgz' -ErrorAction SilentlyContinue | Select-Object -First 500 -ExpandProperty FullName } } 'Skipped in fast mode. Run -Full for complete evidence.'
Write-FsiItem "SRV-128" 'wmic logicaldisk get caption,filesystem' { if ($FastMode) { [System.IO.DriveInfo]::GetDrives() | Select Name, DriveType, DriveFormat, TotalFreeSpace, TotalSize } else { Get-CimInstance Win32_LogicalDisk | Select Caption, FileSystem, Description, FreeSpace } }
# 타사 정책 AC07/LP04 대응 — 실행파일 ACL + DEP (우리 점검 신규 추가, 2026-06-30)
Write-FsiItem "SRV-180" 'cmd.exe 파일 접근 권한(ACL)' { Get-Acl "$env:windir\System32\cmd.exe" -ErrorAction SilentlyContinue | Format-List Path, Owner, AccessToString }
Write-FsiItem "SRV-181" 'command.com 파일 접근 권한(ACL)' { $c = "$env:windir\System32\command.com"; if (Test-Path $c) { Get-Acl $c | Format-List Path, Owner, AccessToString } else { "PATH_NOT_FOUND: command.com 미존재(64비트) -> 해당없음(양호)" } }
Write-FsiItem "SRV-182" 'powershell.exe 파일 접근 권한(ACL)' { Get-Acl "$env:windir\System32\WindowsPowerShell\v1.0\powershell.exe" -ErrorAction SilentlyContinue | Format-List Path, Owner, AccessToString }
Write-FsiItem "SRV-183" 'PowerShell 실행 제한(ExecutionPolicy/LanguageMode/Constrained)' { "ExecutionPolicy:"; (Get-ExecutionPolicy -List 2>$null | Out-String); "LanguageMode: $($ExecutionContext.SessionState.LanguageMode)" }
Write-FsiItem "SRV-184" 'DEP(DataExecutionPrevention) 설정' { Get-CimInstance Win32_OperatingSystem | Select-Object DataExecutionPrevention_SupportPolicy, DataExecutionPrevention_Available, DataExecutionPrevention_32BitApplications, DataExecutionPrevention_Drivers | Format-List; "--- bcdedit nx ---"; (& bcdedit /enum '{current}' 2>$null | Select-String 'nx') }
Invoke-FsiMaybeSlowItem "SRV-129" 'tasklist' { Get-Process | Select Id, ProcessName, MainWindowTitle } 'Skipped in fast mode because process inventory can be slow and verbose. Run -Full for complete evidence.'
Write-FsiItem "SRV-140" 'reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon /v AllocateDASD' { Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AllocateDASD | Select AllocateDASD }
Write-FsiItem "SRV-126" 'reg query Winlogon AutoAdminLogon/DefaultUserName/DefaultPassword' { Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | Select-Object AutoAdminLogon, DefaultUserName, DefaultPassword }

# [IIS / 웹서버 관련 점검]
Write-FsiItem "SRV-038" 'sc query IISADMIN' { sc.exe query IISADMIN; sc.exe query W3SVC; sc.exe query WAS; sc.exe query Webtob }
Write-FsiItem "SRV-021" 'IIS config file ACL' { $c = "$env:windir\System32\inetsrv\config\applicationHost.config"; if (Test-Path $c) { Get-ChildItem $c, "$env:windir\System32\inetsrv\metabase.xml" -ErrorAction SilentlyContinue; Get-Acl $c | Format-List Path, AccessToString } else { "PATH_NOT_FOUND: $c does not exist -> IIS not installed" } }
Write-FsiItem "SRV-039" 'sc query Webtob' { sc.exe query Webtob; Get-Process | Where-Object { $_.ProcessName -match "webtob|wsm|htl" } | Select Id, ProcessName, Path }
Write-FsiItem "SRV-048" 'sc query iisadmin/w3svc/was; netstat :80/:443' { sc.exe query IISADMIN; sc.exe query W3SVC; sc.exe query WAS; $netstatData | Select-String ":80|:443" }
Write-FsiItem "SRV-049" 'IIS sample/default files' { if (Test-Path "C:\inetpub") { Get-ChildItem "C:\inetpub\iissamples", "C:\inetpub\wwwroot\iisstart.*", "$env:windir\Help\iisHelp", "$env:ProgramFiles\IIS Resources" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 120 FullName } else { "PATH_NOT_FOUND: C:\inetpub does not exist -> IIS not installed" } }
Write-FsiItem "SRV-050" 'IIS script/handler mappings' { & "$env:windir\System32\inetsrv\appcmd.exe" list config /section:handlers }
Write-FsiItem "SRV-051" 'IIS directory browsing' { & "$env:windir\System32\inetsrv\appcmd.exe" list config /section:directoryBrowse }
Write-FsiItem "SRV-052" 'IIS ASP EnableParentPaths' { & "$env:windir\System32\inetsrv\appcmd.exe" list config /section:asp }
Write-FsiItem "SRV-053" 'IIS WebDAV status' { sc.exe query WebClient; & "$env:windir\System32\inetsrv\appcmd.exe" list modules WebDAVModule; & "$env:windir\System32\inetsrv\appcmd.exe" list config /section:webdav/authoringRules }
Write-FsiItem "SRV-054" 'IIS logging config' { & "$env:windir\System32\inetsrv\appcmd.exe" list config /section:sites; & "$env:windir\System32\inetsrv\appcmd.exe" list config /section:system.applicationHost/log }
Write-FsiItem "SRV-055" 'IIS authentication config' { & "$env:windir\System32\inetsrv\appcmd.exe" list config /section:anonymousAuthentication; & "$env:windir\System32\inetsrv\appcmd.exe" list config /section:basicAuthentication; & "$env:windir\System32\inetsrv\appcmd.exe" list config /section:windowsAuthentication }
Write-FsiItem "SRV-056" 'IIS SSL/TLS and HTTP SSL binding config' { reg.exe query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols" /s; netsh http show sslcert }
Write-FsiItem "SRV-057" 'IIS web directory ACL' { if (Test-Path "C:\inetpub") { Get-Acl "C:\inetpub", "C:\inetpub\wwwroot", "C:\inetpub\scripts" | Format-List Path, AccessToString } else { "PATH_NOT_FOUND: C:\inetpub does not exist -> IIS not installed" } }
Write-FsiItem "SRV-058" 'IIS request filtering/custom errors' { & "$env:windir\System32\inetsrv\appcmd.exe" list config /section:requestFiltering; & "$env:windir\System32\inetsrv\appcmd.exe" list config /section:httpErrors }
Write-FsiItem "SRV-059" 'reg query W3SVC SSIEnableCmdDirective' { reg.exe query "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters" /v SSIEnableCmdDirective }
Write-FsiItem "SRV-097" 'FTP/IIS site permission evidence' { sc.exe query MSFTPSVC; sc.exe query FTPSVC; & "$env:windir\System32\inetsrv\appcmd.exe" list site; Get-Acl "C:\inetpub\ftproot", "C:\inetpub\wwwroot" | Format-List Path, AccessToString }
Write-FsiItem "SRV-041" 'cacls C:\inetpub\scripts' { if (Test-Path "C:\inetpub") { Get-Acl "C:\inetpub\scripts", "C:\inetpub\wwwroot" | Format-List Path, AccessToString } else { "PATH_NOT_FOUND: C:\inetpub does not exist -> IIS not installed" } }
Write-FsiItem "SRV-060" 'type %CATALINA_HOME%\conf\tomcat-users.xml' { $t = "$env:CATALINA_HOME\conf\tomcat-users.xml"; if ($env:CATALINA_HOME -and (Test-Path $t)) { Get-Content $t } else { "PATH_NOT_FOUND: tomcat-users.xml not present -> Tomcat not installed" } }

# [WAS(Tomcat)] 금융보안원 WAS 기준 SRV-200~214 — Windows Tomcat 설정파일 수집 (판정은 mock 룰)
$tcHomes = @()
foreach ($d in @($env:CATALINA_BASE, $env:CATALINA_HOME)) { if ($d -and (Test-Path (Join-Path $d 'conf\server.xml'))) { $tcHomes += $d } }
foreach ($pat in @('C:\tomcat*','C:\apache-tomcat*','C:\Program Files\*omcat*','C:\Program Files (x86)\*omcat*','D:\tomcat*','D:\apache-tomcat*','C:\opt\tomcat*','C:\was\*','D:\was\*')) {
  Get-ChildItem -Path $pat -Directory -ErrorAction SilentlyContinue | ForEach-Object { if (Test-Path (Join-Path $_.FullName 'conf\server.xml')) { $tcHomes += $_.FullName } }
}
$tcHomes = @($tcHomes | Select-Object -Unique)
$tcAbsent = ($tcHomes.Count -eq 0)
function TcGrep($rel, $pat) { $o=@(); foreach($h in $tcHomes){ $f=Join-Path $h $rel; if(Test-Path $f){ (Get-Content $f -ErrorAction SilentlyContinue) | Select-String $pat | ForEach-Object { $o += $_.Line } } }; $o }

Write-FsiItem "SRV-200" 'Tomcat 관리자 콘솔 접근통제(RemoteAddrValve)' { if($tcAbsent){"Tomcat 미설치(CATALINA 미탐지) -> 관리 콘솔 부재(대상 없음)";return}; foreach($h in $tcHomes){ Get-ChildItem (Join-Path $h 'webapps') -Directory -ErrorAction SilentlyContinue | Where-Object {$_.Name -in @('manager','host-manager')} | ForEach-Object { ($_.FullName -replace '\\','/') }; Get-Content (Join-Path $h 'webapps\manager\META-INF\context.xml'),(Join-Path $h 'conf\Catalina\localhost\manager.xml') -ErrorAction SilentlyContinue | Select-String 'RemoteAddrValve|RemoteCIDRValve|allow=' | ForEach-Object {$_.Line} } }
Write-FsiItem "SRV-201" 'Tomcat 기본/관리 계정(tomcat-users.xml)' { if($tcAbsent){"Tomcat 미설치 -> 관리 계정 미정의(대상 없음)";return}; TcGrep 'conf\tomcat-users.xml' 'user |username=|rolename=|roles=' }
Write-FsiItem "SRV-202" 'Tomcat 패스워드 평문 저장' { if($tcAbsent){"Tomcat 미설치 -> 계정 미정의(대상 없음)";return}; TcGrep 'conf\tomcat-users.xml' 'password'; TcGrep 'conf\server.xml' 'CredentialHandler|MessageDigest|digest=' }
Write-FsiItem "SRV-203" 'Tomcat 디렉터리 리스팅(web.xml listings)' { if($tcAbsent){"Tomcat 미설치 -> 기본값 listings=false(양호)";return}; TcGrep 'conf\web.xml' 'listings' }
Write-FsiItem "SRV-204" 'Tomcat 세션 타임아웃(web.xml)' { if($tcAbsent){"Tomcat 미설치 -> 대상 없음";return}; TcGrep 'conf\web.xml' 'session-timeout' }
Write-FsiItem "SRV-205" 'Tomcat 에러페이지/서버정보 노출' { if($tcAbsent){"Tomcat 미설치 -> 대상 없음";return}; TcGrep 'conf\server.xml' 'ErrorReportValve|showServerInfo|showReport'; TcGrep 'conf\web.xml' 'error-page' }
Write-FsiItem "SRV-206" 'Tomcat 서버 버전 노출(Connector server / ServerInfo)' { if($tcAbsent){"Tomcat 미설치 -> 대상 없음";return}; $o=@(); $o += (TcGrep 'conf\server.xml' 'server='); foreach($h in $tcHomes){ Get-ChildItem -Path $h -Recurse -Filter 'ServerInfo.properties' -ErrorAction SilentlyContinue | Select-Object -First 2 | ForEach-Object {$o += $_.FullName} }; if($o.Count){ $o } else { "Connector server 속성/ServerInfo 오버라이드 없음 -> 기본 배너로 버전 노출" } }
Write-FsiItem "SRV-207" 'Tomcat 불필요 기본 웹앱(examples/docs)' { if($tcAbsent){"Tomcat 미설치 -> 불필요 앱 제거 상태(양호)";return}; foreach($h in $tcHomes){ Get-ChildItem (Join-Path $h 'webapps') -Directory -ErrorAction SilentlyContinue | Where-Object {$_.Name -in @('examples','docs','host-manager','manager')} | ForEach-Object { ($_.FullName -replace '\\','/') } } }
Write-FsiItem "SRV-208" 'Tomcat TRACE 메서드(allowTrace)' { if($tcAbsent){"Tomcat 미설치 -> 기본값 allowTrace=false(양호)";return}; TcGrep 'conf\server.xml' 'allowTrace' }
Write-FsiItem "SRV-209" 'Tomcat AJP 커넥터 보안(Ghostcat)' { if($tcAbsent){"Tomcat 미설치 -> AJP Connector 미정의(양호)";return}; TcGrep 'conf\server.xml' 'AJP|8009|secretRequired|secret=|requiredSecret' }
Write-FsiItem "SRV-210" 'Tomcat SSL/TLS 프로토콜' { if($tcAbsent){"Tomcat 미설치 -> 대상 없음";return}; TcGrep 'conf\server.xml' 'SSLEnabled|scheme="https"|sslEnabledProtocols|sslProtocol|SSLv2|SSLv3' }
Write-FsiItem "SRV-211" 'Tomcat 접근 로그(AccessLogValve)' { if($tcAbsent){"Tomcat 미설치 -> 대상 없음";return}; TcGrep 'conf\server.xml' 'AccessLogValve|prefix=|pattern=' }
Write-FsiItem "SRV-212" 'Tomcat 설정 파일 접근 권한(ACL)' { if($tcAbsent){"Tomcat 미설치 -> 대상 없음";return}; foreach($h in $tcHomes){ foreach($f in @('conf\server.xml','conf\tomcat-users.xml','conf\catalina.properties')){ $p=Join-Path $h $f; if(Test-Path $p){ "$f :"; (Get-Acl $p).AccessToString } } } }
Write-FsiItem "SRV-213" 'Tomcat shutdown 포트/명령(server.xml)' { if($tcAbsent){"Tomcat 미설치 -> 대상 없음";return}; TcGrep 'conf\server.xml' '<Server |shutdown=|port="8005"|port="-1"' }
Write-FsiItem "SRV-214" 'Tomcat 실행 계정 권한(프로세스 소유자)' { if($tcAbsent){"Tomcat 미설치 -> 미실행(대상 없음)";return}; Get-CimInstance Win32_Process -Filter "Name='java.exe'" -ErrorAction SilentlyContinue | Where-Object {$_.CommandLine -match 'catalina|tomcat'} | ForEach-Object { $ow=$_.GetOwner(); "PID $($_.ProcessId) owner=$($ow.Domain)\$($ow.User)" } }

# [DBMS(MSSQL)] 금융보안원 DBMS 기준 SRV-230~247 — 로컬 MSSQL 을 OS 스캔에 함께 수집.
#   기본: WinRM 계정 통합인증(Integrated). 별도 계정 필요 시 FSI_MSSQL_USER/FSI_MSSQL_PASS(+FSI_MSSQL_SERVER) 지정.
#   SQL Server 미설치/접속불가면 DB 항목을 아예 생략(팬텀 항목 방지).
try { Add-Type -AssemblyName System.Data -ErrorAction SilentlyContinue } catch {}
$sqlConn = $null; $sqlErr = ''
# DB 접속정보: web UI 가 저장한 fsi_config.ini([mssql] server/instance/port/user/password) 를 스크립트가 읽는다.
# 우선순위: 파라미터 > config.ini > 환경변수 > 로컬 자동탐지
$cfg = @{}
$cfgPath = if ($env:FSI_CONFIG_PATH -and (Test-Path $env:FSI_CONFIG_PATH)) { $env:FSI_CONFIG_PATH } else { Join-Path $scriptDir 'fsi_config.ini' }
if (Test-Path $cfgPath) {
  $sec = ''
  foreach ($ln in (Get-Content $cfgPath -ErrorAction SilentlyContinue)) {
    $t = $ln.Trim()
    if ($t -match '^\[(.+)\]$') { $sec = $matches[1].ToLower() }
    elseif ($sec -eq 'mssql' -and $t -match '^([^;#=][^=]*)=(.*)$') { $cfg[$matches[1].Trim().ToLower()] = $matches[2].Trim() }
  }
}
$cfgServer = ''
if ($cfg['server']) { $cfgServer = $cfg['server']; if ($cfg['instance']) { $cfgServer = "$cfgServer\$($cfg['instance'])" }; if ($cfg['port']) { $cfgServer = "$cfgServer,$($cfg['port'])" } }
$mssqlServer = if ($MssqlServer) { $MssqlServer } elseif ($cfgServer) { $cfgServer } elseif ($env:FSI_MSSQL_SERVER) { $env:FSI_MSSQL_SERVER } else { '' }
$mssqlUser   = if ($MssqlUser)   { $MssqlUser }   elseif ($cfg['user'])     { $cfg['user'] }     elseif ($env:FSI_MSSQL_USER) { $env:FSI_MSSQL_USER } else { '' }
$mssqlPass   = if ($MssqlPassword) { $MssqlPassword } elseif ($cfg['password']) { $cfg['password'] } elseif ($env:FSI_MSSQL_PASS) { $env:FSI_MSSQL_PASS } else { '' }
$sqlRunning = @(Get-Service -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '^MSSQL' -and $_.Status -eq 'Running' }).Count -gt 0
if ($sqlRunning -or $mssqlServer -or $mssqlUser) {
  $cands = if ($mssqlServer) { @($mssqlServer) } else { @('localhost','.','.\SQLEXPRESS','localhost\SQLEXPRESS') }
  foreach ($sv in $cands) {
    try {
      $auth = if ($mssqlUser) { "User ID=$mssqlUser;Password=$mssqlPass;" } else { "Integrated Security=SSPI;" }
      $c = New-Object System.Data.SqlClient.SqlConnection ("Server=$sv;Database=master;$auth" + "Connect Timeout=8;Encrypt=False;TrustServerCertificate=True;Application Name=ADV_FSI;")
      $c.Open(); $sqlConn = $c; break
    } catch { $sqlErr = $_.Exception.Message }
  }
}
function SqlQ($sql) {
  if (-not $sqlConn) { return "DB_CONNECTION_FAILED: $sqlErr" }
  try {
    $cmd = $sqlConn.CreateCommand(); $cmd.CommandTimeout = 20; $cmd.CommandText = $sql
    $r = $cmd.ExecuteReader(); $sb = New-Object System.Text.StringBuilder; $n = 0
    do { while ($r.Read()) { $p=@(); for ($i=0; $i -lt $r.FieldCount; $i++) { $v = if ($r.IsDBNull($i)) {'NULL'} else {$r.GetValue($i).ToString()}; $p += "$($r.GetName($i))=$v" }; [void]$sb.AppendLine(($p -join ' | ')); $n++ } } while ($r.NextResult())
    $r.Close(); if ($n -eq 0) { '(0 rows)' } else { $sb.ToString().Trim() }
  } catch { "QUERY_ERROR: $($_.Exception.Message)" }
}
if ($sqlConn) {
  Write-FsiItem "SRV-230" 'MSSQL sa 계정명 변경' { SqlQ "SELECT name, is_disabled FROM sys.server_principals WHERE sid = 0x01;" }
  Write-FsiItem "SRV-231" 'MSSQL sa 계정 비활성화' { SqlQ "SELECT name, is_disabled FROM sys.sql_logins WHERE sid = 0x01;" }
  Write-FsiItem "SRV-232" 'MSSQL 로그인 패스워드 정책' { SqlQ "SELECT name, is_policy_checked, is_expiration_checked, is_disabled FROM sys.sql_logins WHERE name NOT LIKE '##%';" }
  Write-FsiItem "SRV-233" 'MSSQL 인증 모드' { SqlQ "SELECT CAST(SERVERPROPERTY('IsIntegratedSecurityOnly') AS int) AS IntegratedSecurityOnly;" }
  Write-FsiItem "SRV-234" 'MSSQL sysadmin 역할 구성원' { SqlQ "SELECT p.name AS member, p.type_desc, p.is_disabled FROM sys.server_role_members m JOIN sys.server_principals r ON m.role_principal_id=r.principal_id JOIN sys.server_principals p ON m.member_principal_id=p.principal_id WHERE r.name='sysadmin';" }
  Write-FsiItem "SRV-235" 'MSSQL guest CONNECT 권한' { SqlQ "DECLARE @s nvarchar(max)=N'DECLARE @r TABLE(dbname sysname, perm nvarchar(128), state nvarchar(64));'; SELECT @s=@s+'INSERT INTO @r SELECT '''+name+''', dp2.permission_name, dp2.state_desc FROM ['+name+'].sys.database_permissions dp2 JOIN ['+name+'].sys.database_principals u ON dp2.grantee_principal_id=u.principal_id WHERE u.name=''guest'' AND dp2.permission_name=''CONNECT'' AND dp2.state_desc=''GRANT'';' FROM sys.databases WHERE state=0 AND name NOT IN ('tempdb'); SET @s=@s+N' SELECT dbname, perm, state FROM @r;'; EXEC sp_executesql @s;" }
  Write-FsiItem "SRV-236" 'MSSQL public 역할 권한' { SqlQ "SELECT sp.permission_name, sp.state_desc FROM sys.server_permissions sp JOIN sys.server_principals pr ON sp.grantee_principal_id=pr.principal_id WHERE pr.name='public' AND sp.state_desc='GRANT';" }
  Write-FsiItem "SRV-237" 'MSSQL xp_cmdshell' { SqlQ "SELECT name, value_in_use FROM sys.configurations WHERE name='xp_cmdshell';" }
  Write-FsiItem "SRV-238" 'MSSQL OLE Automation' { SqlQ "SELECT name, value_in_use FROM sys.configurations WHERE name='Ole Automation Procedures';" }
  Write-FsiItem "SRV-239" 'MSSQL Ad Hoc Distributed Queries' { SqlQ "SELECT name, value_in_use FROM sys.configurations WHERE name='Ad Hoc Distributed Queries';" }
  Write-FsiItem "SRV-240" 'MSSQL CLR Enabled' { SqlQ "SELECT name, value_in_use FROM sys.configurations WHERE name='clr enabled';" }
  Write-FsiItem "SRV-241" 'MSSQL Cross DB Ownership Chaining' { SqlQ "SELECT name, value_in_use FROM sys.configurations WHERE name='cross db ownership chaining';" }
  Write-FsiItem "SRV-242" 'MSSQL Remote Admin Connections' { SqlQ "SELECT name, value_in_use FROM sys.configurations WHERE name='remote admin connections';" }
  Write-FsiItem "SRV-243" 'MSSQL remote access' { SqlQ "SELECT name, value_in_use FROM sys.configurations WHERE name='remote access';" }
  Write-FsiItem "SRV-244" 'MSSQL 로그인 감사 수준' { SqlQ "DECLARE @al int; EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'AuditLevel', @al OUTPUT; SELECT ISNULL(@al,-1) AS AuditLevel;" }
  Write-FsiItem "SRV-245" 'MSSQL 감사(C2/Audit)' { SqlQ "SELECT name, value_in_use FROM sys.configurations WHERE name='c2 audit mode'; SELECT name AS audit_name, is_state_enabled FROM sys.server_audits;" }
  Write-FsiItem "SRV-246" 'MSSQL 버전/패치' { SqlQ "SELECT CAST(SERVERPROPERTY('ProductVersion') AS varchar(64)) AS ProductVersion, CAST(SERVERPROPERTY('ProductLevel') AS varchar(32)) AS ProductLevel, CAST(SERVERPROPERTY('Edition') AS varchar(128)) AS Edition;" }
  Write-FsiItem "SRV-247" 'MSSQL TDE 암호화' { SqlQ "SELECT name, is_encrypted FROM sys.databases WHERE database_id > 4;" }
  try { $sqlConn.Close() } catch {}
}

# 4. XML 꼬리 닫기 및 임시파일 청소

# === 2026 리포트1 보완 항목 (수집만; 판단은 AI/LLM) ===
Write-FsiItem "SRV-027" 'firewall profiles + rules' { netsh advfirewall show allprofiles; netsh advfirewall firewall show rule name=all | Select-String 'Rule Name|Enabled|Direction|Protocol|LocalPort|Action' | Select-Object -First 300 }
Write-FsiItem "SRV-070" 'secedit ClearTextPassword' { $secData | Select-String "ClearTextPassword" }
Write-FsiItem "SRV-075" 'password complexity/length' { $secData | Select-String "PasswordComplexity|MinimumPasswordLength|MinimumPasswordAge|MaximumPasswordAge"; net accounts }
Write-FsiItem "SRV-082" 'system directory ACL' { Get-Acl "C:\Windows\system32\config","C:\Windows\system32\winevt\Logs","C:\Windows\system32\LogFiles" | Format-List Path, AccessToString }
Write-FsiItem "SRV-084" 'system file ACL (SAM/SYSTEM/SECURITY)' { Get-Acl "$env:systemroot\system32\config\SAM","$env:systemroot\system32\config\SYSTEM","$env:systemroot\system32\config\SECURITY" | Format-List Path, AccessToString }
Write-FsiItem "SRV-092" 'user home directory ACL' { Get-ChildItem "C:\Users" -Directory | ForEach-Object { Get-Acl $_.FullName | Format-List Path, AccessToString } }
Write-FsiItem "SRV-108" 'eventlog RestrictGuestAccess + SeSecurityPrivilege' { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Application","HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\Security","HKLM:\SYSTEM\CurrentControlSet\Services\Eventlog\System" -Name RestrictGuestAccess -ErrorAction SilentlyContinue | Select PSChildName, RestrictGuestAccess; $secData | Select-String "SeSecurityPrivilege" }
Write-FsiItem "SRV-118" 'service pack + hotfix list' { wmic os get caption,version,servicepackmajorversion /format:list; Get-HotFix | Format-Table HotFixID, InstalledOn, Description }
Write-FsiItem "SRV-135" 'TCP/IP security registry' { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" | Select SynAttackProtect, TcpMaxHalfOpen, TcpMaxHalfOpenRetried, DeadGWDetectDefault, EnableDeadGWDetect; Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Netbt\Parameters" -Name IPEnableRouter -ErrorAction SilentlyContinue | Select IPEnableRouter }
Write-FsiItem "SRV-147" 'monitoring services (SNMP/WMI)' { sc.exe query SNMP; sc.exe query winmgmt }
Write-FsiItem "SRV-149" 'disk volume encryption (BitLocker)' { $info = ""; try { $info = (Get-BitLockerVolume -ErrorAction Stop | Format-Table MountPoint, VolumeStatus, EncryptionPercentage, ProtectionStatus | Out-String) } catch {}; if (-not $info.Trim()) { try { $info = (& manage-bde -status 2>&1 | Out-String) } catch {} }; if (-not $info.Trim()) { $info = "BitLocker 상태 확인 도구를 사용할 수 없음(해당 Windows 에디션 미지원 가능)." }; $info; "POLICY_NOTE: 디스크 볼륨 암호화(BitLocker)는 금융보안원 OS 점검 기준상 정보성(INFO) 항목으로 분류된다. 암호화 적용/미적용/상태도구 사용가능 여부와 무관하게 verdict=정보제공(INFO)으로 판정하라(취약/양호/판정불가 아님)." }
Write-FsiItem "SRV-151" 'anonymous SID/name translation' { $secData | Select-String "LSAAnonymousNameLookup"; Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" | Select RestrictAnonymous, RestrictAnonymousSAM }
Write-FsiItem "SRV-166" 'hidden files/dirs on C:' { cmd /c "dir C:\ /a:h" }
Write-FsiItem "SRV-170" 'SMTP banner/service' { sc.exe query SMTPSVC; $netstatData | Select-String ":25" }
Write-FsiItem "SRV-171" 'FTP banner (suppressDefaultBanner)' { Select-String -Path "$env:windir\System32\inetsrv\config\applicationHost.config" -Pattern "suppressDefaultBanner|ftpServer" -ErrorAction SilentlyContinue; sc.exe query FTPSVC }
Write-FsiItem "SRV-172" 'shared resources (net share)' { net share }
Write-FsiItem "SRV-173" 'DNS dynamic update' { dnscmd /ExportSettings 2>$null; Get-Content "$env:systemroot\system32\dns\DnsSettings.txt" -ErrorAction SilentlyContinue; reg.exe query "HKLM\SYSTEM\CurrentControlSet\Services\DNS\Zones" /s 2>$null | Select-String "AllowUpdate" }
Write-FsiItem "SRV-174" 'DNS service status' { sc.exe query dns }
Write-FsiItem "SRV-175" 'NTP/time sync config' { w32tm /query /configuration; w32tm /query /status; wmic OS GET LocalDateTime }
Write-FsiItem "SRV-177" 'admin command access (UAC)' { Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" | Select EnableLUA, ConsentPromptBehaviorAdmin, FilterAdministratorToken }
Write-FsiItem "SRV-179" 'OS version / EoS evidence' { systeminfo | Select-String "^OS Name|^OS Version"; (Get-CimInstance Win32_OperatingSystem) | Select Caption, Version, BuildNumber }
[System.IO.File]::AppendAllText($xmlPath, (($script:XmlBlocks -join [Environment]::NewLine) + [Environment]::NewLine), [System.Text.Encoding]::UTF8)
@"
    </results>
</script>
"@ | Out-File $xmlPath -Append -Encoding UTF8

Copy-Item -Force $xmlPath $legacyXmlPath
Remove-Item $secFilePath -Force
Write-Output "PowerShell 기반 FSI Server scan successfully finished!! XML=$xmlPath"

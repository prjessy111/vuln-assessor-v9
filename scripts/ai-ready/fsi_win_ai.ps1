# =========================================================================
# fsi_win_ai.ps1 - 윈도우 보안 진단 100% 통합 스크립트 (XML 특수문자 완벽 패치본)
# =========================================================================

param(
    [switch]$Fast,
    [switch]$Full,
    [switch]$DeepLibScan,
    [string]$OutputDir = "",
    [string]$OutputName = ""
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
Write-FsiItem "SRV-002" 'REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers"' { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers" }
Write-FsiItem "SRV-003" 'sc query SNMP; REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers"' { sc.exe query SNMP; Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers" }
Write-FsiItem "SRV-004" 'netstat -an | findstr :25' { $netstatData | Select-String ":25"; sc.exe query SMTPSVC }
Write-FsiItem "SRV-013" 'netstat -an | findstr :21' { $netstatData | Select-String ":21"; sc.exe query MSFTPSVC; sc.exe query FTPSVC }
Write-FsiItem "SRV-037" 'sc query MSFTPSVC; sc query FTPSVC; netstat -an | findstr :21' { sc.exe query MSFTPSVC; sc.exe query FTPSVC; $netstatData | Select-String ":21" }
Write-FsiItem "SRV-018" 'REG QUERY HKLM\SYSTEM\CurrentControlSet\Services\Lanmanserver\Parameters /v AutoShareServer' { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Lanmanserver\Parameters" | Select AutoShareServer, AutoShareWks }
Write-FsiItem "SRV-020" 'net share' { if ($FastMode) { net share } else { net share; Get-SmbShare | Where-Object { $_.Path } | ForEach-Object { "SHARE $($_.Name) -> $($_.Path)"; Get-Acl $_.Path | Format-List Path, AccessToString } } }
Write-FsiItem "SRV-023" 'REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MinEncryptionLevel' { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name MinEncryptionLevel | Select MinEncryptionLevel }
Write-FsiItem "SRV-024" '2026: 취약한 Telnet 인증 방식(tlntadmn config) + Telnet 서비스 상태' { tlntadmn config 2>$null; sc.exe query TlntSvr }
Write-FsiItem "SRV-028" 'REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MaxIdleTime' { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name MaxIdleTime | Select MaxIdleTime }
Write-FsiItem "SRV-029" 'REG QUERY "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v EnableForcedLogOff' { Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" | Select EnableForcedLogOff, autodisconnect }
Write-FsiItem "SRV-031" 'REG QUERY HKLM\SYSTEM\CurrentControlSet\Control\LSA /v RestrictAnonymous' { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" | Select RestrictAnonymous, RestrictAnonymousSam }
Write-FsiItem "SRV-032" 'netsh interface show interface' { if ($FastMode) { netsh interface show interface } else { Get-NetAdapter | Format-Table Name, InterfaceDescription, Status; "--- NetbiosOptions per interface (0=default/enabled, 1=enabled, 2=disabled) ---"; Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\*' -Name NetbiosOptions -ErrorAction SilentlyContinue | Format-List PSChildName, NetbiosOptions } }
Write-FsiItem "SRV-034" '2026: NetBIOS over TCP/IP(NetbiosOptions) + 불필요 서비스(Alerter/ClipSrv/Messenger/SimpTcp)' { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_*" -Name NetbiosOptions -EA SilentlyContinue | Select PSChildName, NetbiosOptions; sc.exe query Alerter; sc.exe query ClipSrv; sc.exe query Messenger; sc.exe query SimpTcp }
Write-FsiItem "SRV-063" 'reg query HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters /v NoRecursion' { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" -Name NoRecursion | Select NoRecursion }
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
Write-FsiItem "SRV-119" 'Windows Update policy and service status' { sc.exe query wuauserv; Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"; Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update" }
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

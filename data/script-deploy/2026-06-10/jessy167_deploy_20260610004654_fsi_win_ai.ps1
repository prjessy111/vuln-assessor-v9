# =========================================================================
# fsi_win_ai.ps1 - 윈도우 보안 진단 100% 통합 스크립트 (XML 특수문자 완벽 패치본)
# =========================================================================

param(
    [switch]$Fast,
    [switch]$Full,
    [string]$OutputDir = "",
    [string]$OutputName = ""
)

$ErrorActionPreference = "SilentlyContinue"
$FastMode = if ($Full) { $false } elseif ($Fast) { $true } elseif ($env:FSI_FULL_MODE -eq "1") { $false } else { $true }
$collectionProfile = if ($FastMode) { "fast" } else { "full" }
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
Write-FsiItem "SRV-072" 'net localgroup Administrators' { net localgroup Administrators }
Write-FsiItem "SRV-073" 'net localgroup Administrators; local admin membership evidence' { net localgroup Administrators; Get-LocalGroupMember Administrators | Format-Table Name, ObjectClass, PrincipalSource }
Write-FsiItem "SRV-074" 'net user (ALL_USERS)' { Get-LocalUser | Format-Table Name, Enabled, PasswordRequired }
Write-FsiItem "SRV-077" 'local user password policy flags' { Get-LocalUser | Format-Table Name, Enabled, PasswordRequired, PasswordExpires, UserMayChangePassword, LastLogon }
Write-FsiItem "SRV-078" 'net user guest' { Get-LocalUser -Name "Guest" | Format-Table Name, Enabled }
Write-FsiItem "SRV-079" 'reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v everyoneincludesanonymous' { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name everyoneincludesanonymous | Select everyoneincludesanonymous }
Write-FsiItem "SRV-113" 'type sec.txt | Find /I SeSecurityPrivilege' { $secData | Select-String "SeSecurityPrivilege" }
Write-FsiItem "SRV-115" 'wmic useraccount get name,sid' { wmic useraccount get name,sid; wmic group get name,sid }
Write-FsiItem "SRV-123" 'reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v DontDisplayLastUserName' { Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system" -Name DontDisplayLastUserName | Select DontDisplayLastUserName }
Write-FsiItem "SRV-124" 'reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon /v AutoAdminLogon' { Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" | Select-Object AutoAdminLogon, DefaultUserName }
Write-FsiItem "SRV-125" 'reg query "HKEY_CURRENT_USER\Control Panel\desktop" /v ScreenSaveActive' { Get-ItemProperty "HKCU:\Control Panel\desktop" | Select-Object ScreenSaveActive, ScreenSaveTimeOut, ScreenSaverIsSecure }
Write-FsiItem "SRV-127" 'net accounts' { net accounts }
Write-FsiItem "SRV-136" 'reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v ShutdownWithoutLogon' { Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system" -Name ShutdownWithoutLogon | Select ShutdownWithoutLogon }
Write-FsiItem "SRV-137" 'type sec.txt | Find /I SeNetworkLogonRight' { $secData | Select-String "SeNetworkLogonRight|SeDenyNetworkLogonRight" }
Write-FsiItem "SRV-138" 'type sec.txt | Find /I SeBackupPrivilege' { $secData | Select-String "SeBackupPrivilege|SeRestorePrivilege" }
Write-FsiItem "SRV-139" 'type sec.txt | Find /I SeTakeOwnershipPrivilege' { $secData | Select-String "SeTakeOwnershipPrivilege" }
Write-FsiItem "SRV-152" 'type sec.txt | Find /I SeInteractiveLogonRight' { $secData | Select-String "SeInteractiveLogonRight" }
Write-FsiItem "SRV-156" 'type sec.txt | Find /I SeRemoteInteractiveLogonRight' { $secData | Select-String "SeRemoteInteractiveLogonRight" }
Write-FsiItem "SRV-163" 'reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v LegalNoticeCaption' { Get-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\policies\system" | Select-Object LegalNoticeCaption, LegalNoticeText }

# [네트워크 및 서비스 설정]
Write-FsiItem "SRV-001" 'REG QUERY "HKLM\SYSTEM\CurrentControlSet\services\SNMP\Parameters\ValidCommunities"' { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\services\SNMP\Parameters\ValidCommunities"; sc.exe query SNMP }
Write-FsiItem "SRV-002" 'REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers"' { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers" }
Write-FsiItem "SRV-003" 'sc query SNMP; REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers"' { sc.exe query SNMP; Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers" }
Write-FsiItem "SRV-004" 'netstat -an | findstr :25' { $netstatData | Select-String ":25"; sc.exe query SMTPSVC }
Write-FsiItem "SRV-013" 'netstat -an | findstr :21' { $netstatData | Select-String ":21"; sc.exe query MSFTPSVC; sc.exe query FTPSVC }
Write-FsiItem "SRV-037" 'sc query MSFTPSVC; sc query FTPSVC; netstat -an | findstr :21' { sc.exe query MSFTPSVC; sc.exe query FTPSVC; $netstatData | Select-String ":21" }
Write-FsiItem "SRV-018" 'REG QUERY HKLM\SYSTEM\CurrentControlSet\Services\Lanmanserver\Parameters /v AutoShareServer' { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\Lanmanserver\Parameters" | Select AutoShareServer, AutoShareWks }
Write-FsiItem "SRV-020" 'net share' { if ($FastMode) { net share } else { net share; Get-SmbShare | ForEach-Object { Get-Acl $_.Path } } }
Write-FsiItem "SRV-023" 'REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MinEncryptionLevel' { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name MinEncryptionLevel | Select MinEncryptionLevel }
Write-FsiItem "SRV-024" 'netstat -an | findstr :3389' { $netstatData | Select-String ":3389"; sc.exe query TlntSvr }
Write-FsiItem "SRV-028" 'REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MaxIdleTime' { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name MaxIdleTime | Select MaxIdleTime }
Write-FsiItem "SRV-029" 'REG QUERY "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v EnableForcedLogOff' { Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\LanManServer\Parameters" | Select EnableForcedLogOff, autodisconnect }
Write-FsiItem "SRV-031" 'REG QUERY HKLM\SYSTEM\CurrentControlSet\Control\LSA /v RestrictAnonymous' { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\LSA" | Select RestrictAnonymous, RestrictAnonymousSam }
Write-FsiItem "SRV-032" 'netsh interface show interface' { if ($FastMode) { netsh interface show interface } else { Get-NetAdapter | Format-Table Name, InterfaceDescription, Status } }
Write-FsiItem "SRV-034" 'sc query Alerter' { sc.exe query Alerter; sc.exe query ClipSrv; sc.exe query Messenger; sc.exe query SimpTcp }
Write-FsiItem "SRV-063" 'reg query HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters /v NoRecursion' { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\DNS\Parameters" -Name NoRecursion | Select NoRecursion }
Write-FsiItem "SRV-066" 'sc query dns; reg query DNS Server Zones' { sc.exe query DNS; reg.exe query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" /s; reg.exe query "HKLM\System\CurrentControlSet\Services\DNS\Zones" /s }
Write-FsiItem "SRV-067" 'reg query W3SVC ADCLaunch; type %SystemRoot%\msdfmap.ini' { reg.exe query "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch"; Get-Content "$env:SystemRoot\msdfmap.ini" }
Write-FsiItem "SRV-080" 'reg query "HKLM\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers' { Get-ItemProperty "HKLM:\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" -Name AddPrinterDrivers | Select AddPrinterDrivers }
Write-FsiItem "SRV-090" 'sc query RemoteRegistry' { sc.exe query RemoteRegistry }
Write-FsiItem "SRV-103" 'REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel' { Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name LmCompatibilityLevel | Select LmCompatibilityLevel }
Write-FsiItem "SRV-104" 'REG QUERY "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v RequireSignOrSeal' { Get-ItemProperty "HKLM:\System\CurrentControlSet\Services\Netlogon\Parameters" | Select RequireSignOrSeal, SealSecureChannel, SignSecureChannel }
Write-FsiItem "SRV-141" 'netsh advfirewall show allprofiles' { netsh advfirewall show allprofiles }
Write-FsiItem "SRV-150" 'netstat -an | findstr :23' { $netstatData | Select-String ":23"; sc.exe query TlntSvr }
Write-FsiItem "SRV-158" 'netstat -an' { if ($FastMode) { $netstatData | Select-Object -First 200 } else { $netstatData } }

# [시스템 주요 폴더 및 파일 권한]
Write-FsiItem "SRV-068" 'REG SAVE HKLM\SAM' { Get-ChildItem "C:\Windows\Repair\sam", "C:\Windows\Repair\system" }
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
Write-FsiItem "SRV-128" 'wmic logicaldisk get caption,filesystem' { if ($FastMode) { [System.IO.DriveInfo]::GetDrives() | Select Name, DriveType, DriveFormat, TotalFreeSpace, TotalSize } else { Get-CimInstance Win32_LogicalDisk | Select Caption, FileSystem, Description, FreeSpace } }
Invoke-FsiMaybeSlowItem "SRV-129" 'tasklist' { Get-Process | Select Id, ProcessName, MainWindowTitle } 'Skipped in fast mode because process inventory can be slow and verbose. Run -Full for complete evidence.'
Write-FsiItem "SRV-140" 'reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon /v AllocateDASD' { Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name AllocateDASD | Select AllocateDASD }
Write-FsiItem "SRV-126" 'reg query Winlogon AutoAdminLogon/DefaultUserName/DefaultPassword' { Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" | Select-Object AutoAdminLogon, DefaultUserName, DefaultPassword }

# [IIS / 웹서버 관련 점검]
Write-FsiItem "SRV-038" 'sc query IISADMIN' { sc.exe query IISADMIN; sc.exe query W3SVC; sc.exe query WAS; sc.exe query Webtob }
Write-FsiItem "SRV-021" 'IIS config file ACL' { Get-ChildItem "$env:windir\System32\inetsrv\config\applicationHost.config", "$env:windir\System32\inetsrv\metabase.xml"; Get-Acl "$env:windir\System32\inetsrv\config\applicationHost.config" | Format-List Path, AccessToString }
Write-FsiItem "SRV-039" 'sc query Webtob' { sc.exe query Webtob; Get-Process | Where-Object { $_.ProcessName -match "webtob|wsm|htl" } | Select Id, ProcessName, Path }
Write-FsiItem "SRV-048" 'sc query iisadmin/w3svc/was; netstat :80/:443' { sc.exe query IISADMIN; sc.exe query W3SVC; sc.exe query WAS; $netstatData | Select-String ":80|:443" }
Write-FsiItem "SRV-049" 'IIS sample/default files' { Get-ChildItem "C:\inetpub\iissamples", "C:\inetpub\wwwroot\iisstart.*", "$env:windir\Help\iisHelp", "$env:ProgramFiles\IIS Resources" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 120 FullName }
Write-FsiItem "SRV-050" 'IIS script/handler mappings' { & "$env:windir\System32\inetsrv\appcmd.exe" list config /section:handlers }
Write-FsiItem "SRV-051" 'IIS directory browsing' { & "$env:windir\System32\inetsrv\appcmd.exe" list config /section:directoryBrowse }
Write-FsiItem "SRV-052" 'IIS ASP EnableParentPaths' { & "$env:windir\System32\inetsrv\appcmd.exe" list config /section:asp }
Write-FsiItem "SRV-053" 'IIS WebDAV status' { sc.exe query WebClient; & "$env:windir\System32\inetsrv\appcmd.exe" list modules WebDAVModule; & "$env:windir\System32\inetsrv\appcmd.exe" list config /section:webdav/authoringRules }
Write-FsiItem "SRV-054" 'IIS logging config' { & "$env:windir\System32\inetsrv\appcmd.exe" list config /section:sites; & "$env:windir\System32\inetsrv\appcmd.exe" list config /section:system.applicationHost/log }
Write-FsiItem "SRV-055" 'IIS authentication config' { & "$env:windir\System32\inetsrv\appcmd.exe" list config /section:anonymousAuthentication; & "$env:windir\System32\inetsrv\appcmd.exe" list config /section:basicAuthentication; & "$env:windir\System32\inetsrv\appcmd.exe" list config /section:windowsAuthentication }
Write-FsiItem "SRV-056" 'IIS SSL/TLS and HTTP SSL binding config' { reg.exe query "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols" /s; netsh http show sslcert }
Write-FsiItem "SRV-057" 'IIS web directory ACL' { Get-Acl "C:\inetpub", "C:\inetpub\wwwroot", "C:\inetpub\scripts" | Format-List Path, AccessToString }
Write-FsiItem "SRV-058" 'IIS request filtering/custom errors' { & "$env:windir\System32\inetsrv\appcmd.exe" list config /section:requestFiltering; & "$env:windir\System32\inetsrv\appcmd.exe" list config /section:httpErrors }
Write-FsiItem "SRV-059" 'reg query W3SVC SSIEnableCmdDirective' { reg.exe query "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters" /v SSIEnableCmdDirective }
Write-FsiItem "SRV-097" 'FTP/IIS site permission evidence' { sc.exe query MSFTPSVC; sc.exe query FTPSVC; & "$env:windir\System32\inetsrv\appcmd.exe" list site; Get-Acl "C:\inetpub\ftproot", "C:\inetpub\wwwroot" | Format-List Path, AccessToString }
Write-FsiItem "SRV-041" 'cacls C:\inetpub\scripts' { Get-Acl "C:\inetpub\scripts", "C:\inetpub\wwwroot" | Format-List Path, AccessToString }
Write-FsiItem "SRV-060" 'type %CATALINA_HOME%\conf\tomcat-users.xml' { Get-Content "$env:CATALINA_HOME\conf\tomcat-users.xml" }

# 4. XML 꼬리 닫기 및 임시파일 청소
[System.IO.File]::AppendAllText($xmlPath, (($script:XmlBlocks -join [Environment]::NewLine) + [Environment]::NewLine), [System.Text.Encoding]::UTF8)
@"
    </results>
</script>
"@ | Out-File $xmlPath -Append -Encoding UTF8

Copy-Item -Force $xmlPath $legacyXmlPath
Remove-Item $secFilePath -Force
Write-Output "PowerShell 기반 FSI Server scan successfully finished!! XML=$xmlPath"

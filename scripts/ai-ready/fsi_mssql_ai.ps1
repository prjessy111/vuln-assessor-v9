# =========================================================================
# fsi_mssql_ai.ps1 - MSSQL(DBMS) 보안 진단 수집 스크립트 (금융보안원 DBMS 기준)
# =========================================================================
#  - sys.* / sys.configurations / SERVERPROPERTY / xp_instance_regread 를 조회해
#    raw 증거만 수집한다. 스크립트는 판정하지 않는다(verdict_source=none).
#  - 판정은 ADV mock 엔진(결정론적 룰, SRV-230~247)이 raw 출력만 보고 수행한다.
#    → 망분리(폐쇄망)에서 LLM 없이 동작.
#  - 접속: .NET System.Data.SqlClient (sqlcmd.exe 불필요).
#
#  사용 예:
#    powershell -File fsi_mssql_ai.ps1 -Server "localhost" -Integrated
#    powershell -File fsi_mssql_ai.ps1 -Server "10.0.0.5,1433" -User sa -Password "***"
#    powershell -File fsi_mssql_ai.ps1 -Server ".\SQLEXPRESS" -User audit -Password "***" -OutputDir C:\Windows\Temp
# =========================================================================

param(
    [string]$Server = "localhost",
    [string]$User = "",
    [string]$Password = "",
    [switch]$Integrated,
    [string]$OutputDir = "",
    [string]$OutputName = ""
)

$ErrorActionPreference = "SilentlyContinue"
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}

$hostname = $env:COMPUTERNAME
if ([string]::IsNullOrWhiteSpace($hostname)) { $hostname = "unknown-mssql" }
$dateStr = (Get-Date).ToString("yyyyMMdd")
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
if ([string]::IsNullOrWhiteSpace($scriptDir)) { $scriptDir = (Get-Location).Path }
$outputDirValue = if (-not [string]::IsNullOrWhiteSpace($OutputDir)) { $OutputDir } elseif (-not [string]::IsNullOrWhiteSpace($env:FSI_OUTPUT_DIR)) { $env:FSI_OUTPUT_DIR } else { $scriptDir }
New-Item -ItemType Directory -Force -Path $outputDirValue | Out-Null
$xmlName = if (-not [string]::IsNullOrWhiteSpace($OutputName)) { $OutputName } else { "$hostname-mssql-$dateStr.xml" }
$xmlPath = Join-Path $outputDirValue $xmlName
$script:XmlBlocks = New-Object 'System.Collections.Generic.List[string]'

# --- 접속 문자열 구성 ---
$useIntegrated = $Integrated -or [string]::IsNullOrWhiteSpace($User)
$authPart = if ($useIntegrated) { "Integrated Security=SSPI;" } else { "User ID=$User;Password=$Password;" }
$connString = "Server=$Server;Database=master;$authPart" + "Connect Timeout=15;Encrypt=False;TrustServerCertificate=True;Application Name=ADV_FSI_MSSQL;"
$authLabel = if ($useIntegrated) { "windows_integrated" } else { "sql_login:$User" }

# --- 서버 연결 및 버전 사전 조회 (자산 표기용) ---
$script:conn = $null
$connError = ""
$productVersion = "unknown"
try {
    Add-Type -AssemblyName System.Data -ErrorAction SilentlyContinue
    $script:conn = New-Object System.Data.SqlClient.SqlConnection $connString
    $script:conn.Open()
} catch {
    $connError = $_.Exception.Message
}

function Invoke-DbQuery {
    param([string]$Sql)
    if ($null -eq $script:conn -or $script:conn.State -ne 'Open') {
        return "DB_CONNECTION_FAILED: $connError"
    }
    try {
        $cmd = $script:conn.CreateCommand()
        $cmd.CommandTimeout = 30
        $cmd.CommandText = $Sql
        $reader = $cmd.ExecuteReader()
        $sb = New-Object System.Text.StringBuilder
        $rowCount = 0
        do {
            while ($reader.Read()) {
                $parts = @()
                for ($i = 0; $i -lt $reader.FieldCount; $i++) {
                    $name = $reader.GetName($i)
                    $val = if ($reader.IsDBNull($i)) { "NULL" } else { ($reader.GetValue($i)).ToString() }
                    $parts += "$name=$val"
                }
                [void]$sb.AppendLine(($parts -join " | "))
                $rowCount++
            }
        } while ($reader.NextResult())
        $reader.Close()
        if ($rowCount -eq 0) { return "(0 rows)" }
        return $sb.ToString().Trim()
    } catch {
        return "QUERY_ERROR: $($_.Exception.Message)"
    }
}

function ConvertTo-FsiXmlText {
    param([AllowNull()][object]$Value)
    if ($null -eq $Value) { return "" }
    return ([string]$Value) -replace '&', '&amp;' -replace '<', '&lt;' -replace '>', '&gt;'
}

function Write-DbItem {
    param([string]$ID, [string]$CommandText, [string]$Sql)

    $startedAt = (Get-Date).ToUniversalTime().ToString("o")
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $output = Invoke-DbQuery $Sql
    $sw.Stop()

    $status = "collected"
    if ($output -match '^DB_CONNECTION_FAILED') { $status = "error" }
    elseif ($output -match '^QUERY_ERROR') { $status = "error" }
    elseif ($output -eq "(0 rows)") { $status = "no_data" }

    # [AI/mock-friendly] 수집 실패 vs 대상부재 구분 힌트
    if ($status -eq "error" -and $output -match 'DB_CONNECTION_FAILED') {
        $output = $output + "`nCOLLECTION_HINT=collection_denied : DB 접속 실패로 수집 자체가 안 됨. 양호로 단정 금지(unable/판정불가). 접속 계정/포트/방화벽 확인."
    } elseif ($status -eq "error") {
        $output = $output + "`nCOLLECTION_HINT=query_error : 권한 부족 또는 해당 버전 미지원 객체일 수 있음. 양호로 단정 금지."
    }

    $safeCommandText = ConvertTo-FsiXmlText $CommandText
    $safeSql = ConvertTo-FsiXmlText $Sql
    $safeOutput = ConvertTo-FsiXmlText $output
    $safeStatus = ConvertTo-FsiXmlText $status
    $safeStartedAt = ConvertTo-FsiXmlText $startedAt
    $durationMs = [int]$sw.ElapsedMilliseconds
    $outputBytes = [System.Text.Encoding]::UTF8.GetByteCount($output)

    $xmlBlock = @"
        <dump>
            <items><id>$ID</id></items>
            <evidence_profile>
                <evidence_schema>ai_ready_script_v2</evidence_schema>
                <check_ids>$ID</check_ids>
                <os_family>mssql</os_family>
                <collection_profile>full</collection_profile>
                <collection_status>$safeStatus</collection_status>
                <started_at_utc>$safeStartedAt</started_at_utc>
                <duration_ms>$durationMs</duration_ms>
                <data_role>raw_command_output</data_role>
                <judgment_mode>raw_evidence_only</judgment_mode>
                <verdict_source>none</verdict_source>
                <decision_route>AI_fast_pattern_triage_first; LLM_precise_evidence_review_second</decision_route>
                <safe_type_policy>AI decides absence-good or value-compliant-good from raw output only.</safe_type_policy>
                <output_format>ai_evidence_block_v2</output_format>
                <command_marker>sql#</command_marker>
                <raw_begin_marker>RAW_COMMAND_OUTPUT_BEGIN</raw_begin_marker>
                <raw_end_marker>RAW_COMMAND_OUTPUT_END</raw_end_marker>
            </evidence_profile>
            <output>
AI_EVIDENCE_BLOCK_BEGIN
schema=ai_ready_script_v2
check_ids=$ID
os_family=mssql
collection_profile=full
collection_status=$safeStatus
started_at_utc=$safeStartedAt
duration_ms=$durationMs
output_bytes=$outputBytes
db_auth=$authLabel
command_marker=sql#
command=$safeCommandText
RAW_COMMAND_OUTPUT_BEGIN
sql# $safeSql
$safeOutput
RAW_COMMAND_OUTPUT_END
AI_EVIDENCE_BLOCK_END
            </output>
        </dump>
"@
    [void]$script:XmlBlocks.Add($xmlBlock)
}

# --- XML 헤더 ---
$edition = "unknown"
$productLevel = ""
try {
    $pv = Invoke-DbQuery "SELECT CAST(SERVERPROPERTY('ProductVersion') AS varchar(64)) AS v, CAST(SERVERPROPERTY('ProductLevel') AS varchar(32)) AS lvl, CAST(SERVERPROPERTY('Edition') AS varchar(128)) AS ed;"
    if ($pv -match 'v=([^\s|]+)') { $productVersion = $matches[1] }
    if ($pv -match 'ed=([^|]+)') { $edition = $matches[1].Trim() }
} catch {}

@"
<?xml version="1.0" encoding="utf-8"?>
<script>
    <asset>
        <hostname>$hostname</hostname>
        <os>MSSQL $productVersion</os>
        <uname>$(ConvertTo-FsiXmlText $edition)</uname>
        <whoami>$env:USERNAME</whoami>
        <version>fsi_mssql_v1</version>
        <collection_tool>powershell_sqlclient</collection_tool>
        <collection_profile>full</collection_profile>
        <platform>dbms</platform>
        <dbms_type>mssql</dbms_type>
        <data_role>raw_data_provider</data_role>
        <judgment_mode>raw_evidence_only</judgment_mode>
        <verdict_source>none</verdict_source>
        <verdict_contract>script_never_decides; ai_fast_pattern_triage; llm_precise_evidence_review</verdict_contract>
        <safe_type_policy>AI decides absence-good or value-compliant-good from raw output only.</safe_type_policy>
    </asset>
    <results>
"@ | Out-File $xmlPath -Encoding UTF8

# =========================================================================
# 금융보안원 DBMS(MSSQL) 점검 항목 — SRV-230 ~ SRV-247
# =========================================================================

# [계정 관리]
Write-DbItem "SRV-230" "sa 계정명 변경 여부 (sid=0x01 principal 이름)" `
    "SELECT name, is_disabled FROM sys.server_principals WHERE sid = 0x01;"
Write-DbItem "SRV-231" "sa 계정 비활성화 여부" `
    "SELECT name, is_disabled FROM sys.sql_logins WHERE sid = 0x01;"
Write-DbItem "SRV-232" "SQL 로그인 패스워드 정책(정책적용/만료) 적용 여부" `
    "SELECT name, is_policy_checked, is_expiration_checked, is_disabled FROM sys.sql_logins WHERE name NOT LIKE '##%';"
Write-DbItem "SRV-233" "인증 모드 (1=Windows인증 전용, 0=혼합모드)" `
    "SELECT CAST(SERVERPROPERTY('IsIntegratedSecurityOnly') AS int) AS IntegratedSecurityOnly;"
Write-DbItem "SRV-234" "sysadmin 서버 역할 구성원 목록 (최소화 대상)" `
    "SELECT p.name AS member, p.type_desc, p.is_disabled FROM sys.server_role_members m JOIN sys.server_principals r ON m.role_principal_id = r.principal_id JOIN sys.server_principals p ON m.member_principal_id = p.principal_id WHERE r.name = 'sysadmin';"
Write-DbItem "SRV-235" "guest 계정 CONNECT 권한 활성 DB 목록" `
    "DECLARE @s nvarchar(max) = N'DECLARE @r TABLE(dbname sysname, perm nvarchar(128), state nvarchar(64));'; SELECT @s = @s + 'INSERT INTO @r SELECT ''' + name + ''', dp2.permission_name, dp2.state_desc FROM [' + name + '].sys.database_permissions dp2 JOIN [' + name + '].sys.database_principals u ON dp2.grantee_principal_id = u.principal_id WHERE u.name = ''guest'' AND dp2.permission_name = ''CONNECT'' AND dp2.state_desc = ''GRANT'';' FROM sys.databases WHERE state = 0 AND name NOT IN ('tempdb'); SET @s = @s + N' SELECT dbname, perm, state FROM @r;'; EXEC sp_executesql @s;"
Write-DbItem "SRV-236" "public 서버 역할 부여 권한 (기본 초과 여부)" `
    "SELECT sp.permission_name, sp.state_desc FROM sys.server_permissions sp JOIN sys.server_principals pr ON sp.grantee_principal_id = pr.principal_id WHERE pr.name = 'public' AND sp.state_desc = 'GRANT';"

# [불필요 기능/확장 프로시저 비활성화 — sys.configurations 로 일괄 조회(고급옵션 노출 불필요)]
Write-DbItem "SRV-237" "xp_cmdshell 비활성 여부" `
    "SELECT name, value_in_use FROM sys.configurations WHERE name = 'xp_cmdshell';"
Write-DbItem "SRV-238" "OLE Automation Procedures 비활성 여부" `
    "SELECT name, value_in_use FROM sys.configurations WHERE name = 'Ole Automation Procedures';"
Write-DbItem "SRV-239" "Ad Hoc Distributed Queries 비활성 여부" `
    "SELECT name, value_in_use FROM sys.configurations WHERE name = 'Ad Hoc Distributed Queries';"
Write-DbItem "SRV-240" "CLR Enabled 비활성 여부" `
    "SELECT name, value_in_use FROM sys.configurations WHERE name = 'clr enabled';"
Write-DbItem "SRV-241" "Cross DB Ownership Chaining 비활성 여부" `
    "SELECT name, value_in_use FROM sys.configurations WHERE name = 'cross db ownership chaining';"
Write-DbItem "SRV-242" "Remote Admin Connections 제한 여부" `
    "SELECT name, value_in_use FROM sys.configurations WHERE name = 'remote admin connections';"
Write-DbItem "SRV-243" "remote access(원격 저장 프로시저) 제한 여부" `
    "SELECT name, value_in_use FROM sys.configurations WHERE name = 'remote access';"

# [감사/로깅]
Write-DbItem "SRV-244" "로그인 감사 수준 (AuditLevel: 0=none,1=success,2=failure,3=both)" `
    "DECLARE @al int; EXEC master.dbo.xp_instance_regread N'HKEY_LOCAL_MACHINE', N'Software\Microsoft\MSSQLServer\MSSQLServer', N'AuditLevel', @al OUTPUT; SELECT ISNULL(@al, -1) AS AuditLevel;"
Write-DbItem "SRV-245" "C2 감사 모드 + SQL Server Audit 활성 여부" `
    "SELECT name, value_in_use FROM sys.configurations WHERE name = 'c2 audit mode'; SELECT name AS audit_name, is_state_enabled FROM sys.server_audits;"

# [패치/암호화]
Write-DbItem "SRV-246" "제품 버전/패치 수준(EoS 판정용)" `
    "SELECT CAST(SERVERPROPERTY('ProductVersion') AS varchar(64)) AS ProductVersion, CAST(SERVERPROPERTY('ProductLevel') AS varchar(32)) AS ProductLevel, CAST(SERVERPROPERTY('ProductUpdateLevel') AS varchar(32)) AS UpdateLevel, CAST(SERVERPROPERTY('Edition') AS varchar(128)) AS Edition;"
Write-DbItem "SRV-247" "데이터베이스 암호화(TDE) 적용 여부" `
    "SELECT name, is_encrypted FROM sys.databases WHERE database_id > 4;"

# --- XML 꼬리 ---
[System.IO.File]::AppendAllText($xmlPath, (($script:XmlBlocks -join [Environment]::NewLine) + [Environment]::NewLine), [System.Text.Encoding]::UTF8)
@"
    </results>
</script>
"@ | Out-File $xmlPath -Append -Encoding UTF8

if ($null -ne $script:conn -and $script:conn.State -eq 'Open') { $script:conn.Close() }
Write-Output "PowerShell 기반 FSI MSSQL scan finished. XML=$xmlPath (auth=$authLabel, connErr=$connError)"

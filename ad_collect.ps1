<#
  AD 점검 데이터 수집 스크립트 — Domain Controller 에서 관리자 권한으로 실행.
  결과: <hostname>_AD_DC.txt  (JSON 내용, ad_inspector.inspect_file 입력)

  ★ 설계 원칙
   1) 판정 금지: 양호/취약을 판단하지 않는다. 점검 엔진(ad_inspector)이 임계값·판정을 소유.
      → 원시 config/속성을 "있는 그대로" 수집 (임계값 필터·boolean 판정 금지).
   2) 서버 무부하: 읽기전용 + 최소 비용.
      - 필요한 속성만 (-Properties * 금지), 디렉토리 enumeration 은 단일 패스.
      - 재귀 파일스캔 금지(SYSVOL 은 GPP 파일만 타겟), 이벤트로그 대량 조회 금지.
      - 모든 쿼리 read-only. 실패는 무시하고 계속(부분 수집 허용).
#>
# $PwdDaysCoarse / $LogonDaysCoarse: 서버사이드 코스 필터의 일수(엔진 임계값 90/180보다
#   여유 작게 잡아 "상위집합" 보장 — 복제지연·시계오차로 경계 계정을 놓치지 않도록).
#   정확한 90/180일 판정은 엔진이 반환된 raw pwdLastSet/lastLogon 으로 재계산.
param(
  [string]$OutDir = "C:\ad_audit",
  [int]$PwdDaysCoarse   = 75,
  [int]$LogonDaysCoarse = 165
)

$ErrorActionPreference = "SilentlyContinue"
$ProgressPreference    = "SilentlyContinue"
Import-Module ActiveDirectory
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Path $OutDir | Out-Null }

# ── 진행 로그 (파란 화면이 멈춘 게 아님을 보여줌 — 각 단계 경과시간 표시) ──
$__sw = [System.Diagnostics.Stopwatch]::StartNew()
function Step($msg) { Write-Host ("[{0,6:N0}s] {1}" -f $__sw.Elapsed.TotalSeconds, $msg) }

# 로컬 DC 고정 — referral/원격 DC 지연·타임아웃 방지 (전 AD 쿼리 공통)
$Srv = $env:COMPUTERNAME

function RegVal($path, $name) { try { return (Get-ItemProperty -Path $path -Name $name -ErrorAction Stop).$name } catch { return $null } }
function Iso($dt) { if ($dt) { return ([datetime]$dt).ToString("o") } else { return $null } }
function TsMin($ts) { if ($ts -ne $null) { return [int]([TimeSpan]$ts).TotalMinutes } else { return $null } }
function TsDay($ts) { if ($ts -ne $null) { return [int]([TimeSpan]$ts).TotalDays } else { return $null } }

Step "AD 점검 데이터 수집 시작"
$domain = Get-ADDomain -Server $Srv
$dn = $domain.DistinguishedName
$out = [ordered]@{}

# ── meta ──
$out.meta = [ordered]@{
  host=$env:COMPUTERNAME; ip=(Get-NetIPAddress -AddressFamily IPv4 | Where-Object PrefixOrigin -eq 'Manual' | Select-Object -First 1 -Expand IPAddress)
  domain=$domain.DNSRoot; netbios=$domain.NetBIOSName; domainMode="$($domain.DomainMode)"
  forest=$domain.Forest; collected_at=(Get-Date).ToString("o"); schema_version=3
  # ★ 대규모(7만 user/20만 PC) 대응: users/computers 는 서버사이드 LDAP 필터로
  #   "점검 후보"만 수집(전체 덤프 금지). 정확한 판정은 엔진. 빈 목록=후보없음(미수집 아님).
  user_scope="filtered"; computer_scope="filtered"
  pwd_days_coarse=$PwdDaysCoarse; logon_days_coarse=$LogonDaysCoarse
}

# ── 도메인 기본 패스워드 정책 (원시값) ──
$pp = Get-ADDefaultDomainPasswordPolicy
$out.password_policy = [ordered]@{
  ComplexityEnabled=[bool]$pp.ComplexityEnabled; MinPasswordLength=[int]$pp.MinPasswordLength
  PasswordHistoryCount=[int]$pp.PasswordHistoryCount; MinPasswordAgeDays=TsDay $pp.MinPasswordAge
  MaxPasswordAgeDays=TsDay $pp.MaxPasswordAge; ReversibleEncryptionEnabled=[bool]$pp.ReversibleEncryptionEnabled
  LockoutThreshold=[int]$pp.LockoutThreshold; LockoutDurationMin=TsMin $pp.LockoutDuration
  LockoutObservationWindowMin=TsMin $pp.LockoutObservationWindow
}

# ── FGPP (원시값) ──
# FGPP(PSO) 읽기는 도메인관리자급 권한 필요 — 비관리자 수집 시 빈 결과(=실제 0 과 구분 불가)이므로 에러를 별도 기록.
try {
  $out.fgpp = @(Get-ADFineGrainedPasswordPolicy -Filter * -ErrorAction Stop | ForEach-Object {
    [ordered]@{ Name=$_.Name; Precedence=[int]$_.Precedence; MinPasswordLength=[int]$_.MinPasswordLength
      PasswordHistoryCount=[int]$_.PasswordHistoryCount; MaxPasswordAgeDays=TsDay $_.MaxPasswordAge
      MinPasswordAgeDays=TsDay $_.MinPasswordAge; LockoutThreshold=[int]$_.LockoutThreshold
      LockoutDurationMin=TsMin $_.LockoutDuration; ComplexityEnabled=[bool]$_.ComplexityEnabled
      AppliesTo=@(Get-ADFineGrainedPasswordPolicySubject -Identity $_.Name | Select-Object -Expand Name) } })
} catch { $out.fgpp = @(); $out.fgpp_error = $_.Exception.Message }

# ── Built-in 계정 SID 500/501 (원시 Enabled) ──
# objectSID 는 바이너리라 -Filter "SID -like '*-500'" 는 매칭 실패 → 도메인SID+RID 로 직접 조회
$out.builtin_accounts = @(foreach ($rid in 500,501) {
  $u = Get-ADUser -Identity "$($domain.DomainSID.Value)-$rid" -Properties Enabled -ErrorAction SilentlyContinue
  if ($u) { [ordered]@{ Sam=$u.SamAccountName; RID=$rid; Enabled=[bool]$u.Enabled } } })

# ── 관리자 그룹 멤버십 (원시 멤버 목록) ──
#    ★ Get-ADGroupMember 금지: 멤버 대량 등록 시 (1) 멤버별 객체 해석으로 매우 느려 멈춘 듯 보이고
#      (2) ADWS 기본 한도(MaxGroupOrMemberEntries=5000) 초과 시 에러→SilentlyContinue 로 빈 목록 반환
#      (= 멤버가 가장 많은 그룹이 0명으로 둔갑하는 오탐). 대신 memberOf 역링크를 페이징 조회.
#      → 직접멤버(비재귀, 기존과 동일)·sAMAccountName 직접반환·5000 한도 없음·서버사이드 단일 페이징쿼리.
$out.admin_groups = [ordered]@{}
$adminGroupDNs = @()   # AM05(관리자 LogonWorkstations) 용 — 사용자 코스필터에 memberOf 로 합류
foreach ($g in 'Domain Admins','Enterprise Admins','Schema Admins','Administrators','Account Operators','Backup Operators','Server Operators','Print Operators') {
  $grp = Get-ADGroup -Identity $g -Server $Srv -ErrorAction SilentlyContinue
  if (-not $grp) { $out.admin_groups[$g] = @(); continue }
  $adminGroupDNs += $grp.DistinguishedName
  $mem = @(Get-ADObject -LDAPFilter "(memberOf=$($grp.DistinguishedName))" -Properties sAMAccountName `
            -ResultPageSize 1000 -Server $Srv -ErrorAction SilentlyContinue | Select-Object -Expand sAMAccountName)
  $out.admin_groups[$g] = $mem
  Step ("admin_groups: {0} = {1}명" -f $g, $mem.Count)
}

# ── 사용자 (★대규모 핵심: 전체 덤프 금지 — 서버사이드 코스필터로 "점검 후보"만 수집) ──
#    전체 활성계정을 받으면 7만건이 DC→ADWS 직렬화 부하. 대신 각 점검의 조건을 OR 로 묶어
#    LDAP 가 매칭 객체만 반환 → 수천건 이하. 정확한 임계값 판정은 엔진(반환 raw 값 재계산).
#    OR 조건(=점검 후보 상위집합):
#      32=PASSWD_NOTREQD(AM17) · 65536=DONT_EXPIRE_PASSWD(AM18) · 4194304=DONT_REQ_PREAUTH(IC05)
#      servicePrincipalName(AM18/IC04/SS05) · profilePath(AC02)
#      pwdLastSet≤코스(AM19) · lastLogonTimestamp≤코스 또는 미로그온+생성일≤코스(AM16) · 관리자그룹 memberOf(AM05)
$ftPwd   = (Get-Date).AddDays(-$PwdDaysCoarse).ToFileTimeUtc()
$ftLogon = (Get-Date).AddDays(-$LogonDaysCoarse).ToFileTimeUtc()
# whenCreated 는 GeneralizedTime(yyyyMMddHHmmss.0Z) 비교 — 미로그온 계정의 미사용 판정용
$gtLogon = ((Get-Date).AddDays(-$LogonDaysCoarse).ToUniversalTime().ToString('yyyyMMddHHmmss')) + '.0Z'
$bit = 'userAccountControl:1.2.840.113556.1.4.803:='
$orTerms = @(
  "(${bit}32)", "(${bit}65536)", "(${bit}4194304)",
  '(servicePrincipalName=*)', '(profilePath=*)',
  "(&(pwdLastSet<=$ftPwd)(!(pwdLastSet=0)))",
  "(lastLogonTimestamp<=$ftLogon)",
  "(&(!(lastLogonTimestamp=*))(whenCreated<=$gtLogon))"   # 미로그온 + 생성 후 코스일수↑ (AM16)
) + @($adminGroupDNs | ForEach-Object { "(memberOf=$_)" })
$userFilter = "(&(!(${bit}2))(|" + ($orTerms -join '') + "))"   # 활성(ACCOUNTDISABLE 없음) AND 후보조건 OR
Step "사용자 수집 중 (서버사이드 코스필터 — 점검 후보만)…"
$out.users = @(Get-ADUser -LDAPFilter $userFilter -ResultPageSize 1000 -Server $Srv -Properties `
    userAccountControl, PasswordLastSet, LastLogonDate, whenCreated, ProfilePath, servicePrincipalName, 'msDS-SupportedEncryptionTypes', LogonWorkstations |
  ForEach-Object {
    [ordered]@{
      Sam=$_.SamAccountName; UAC=[int]$_.userAccountControl
      PwdLastSet=Iso $_.PasswordLastSet; LastLogon=Iso $_.LastLogonDate; Created=Iso $_.whenCreated
      ProfilePath=$_.ProfilePath; SPN=@($_.servicePrincipalName); EncTypes=[int]$_.'msDS-SupportedEncryptionTypes'
      LogonWorkstations=$_.LogonWorkstations
    } })

# ── 컴퓨터 (★IC02 무제약위임 후보만 — EOL OS(AC05)는 DC 점검범위 제외/NA 라 OS 스캔 불필요) ──
#    20만 PC 전체 덤프 금지. 524288=TRUSTED_FOR_DELEGATION 비트로 위임설정 컴퓨터(소수)만 반환.
#    DC 제외는 엔진.
$compFilter = "(${bit}524288)"
Step ("사용자 {0}건 수집 완료 — 컴퓨터 수집 중(위임 후보만)…" -f $out.users.Count)
$out.computers = @(Get-ADComputer -LDAPFilter $compFilter -ResultPageSize 1000 -Server $Srv -Properties OperatingSystem, TrustedForDelegation, Enabled |
  ForEach-Object { [ordered]@{ Name=$_.Name; OS=$_.OperatingSystem; Enabled=[bool]$_.Enabled; TrustedForDelegation=[bool]$_.TrustedForDelegation } })

# ── DC 목록 / 암호화타입 / 소유자 (원시) ──
$out.dc_list = @(foreach ($dc in (Get-ADDomainController -Filter * -Server $Srv)) {
  $c = Get-ADComputer $dc.Name -Server $Srv -Properties 'msDS-SupportedEncryptionTypes', nTSecurityDescriptor
  [ordered]@{ Name=$dc.Name; EncTypes=[int]$c.'msDS-SupportedEncryptionTypes'; Owner="$($c.nTSecurityDescriptor.Owner)" } })

# ── 도메인 객체 속성 (원시) ──
$obj = Get-ADObject -Identity $dn -Properties 'ms-DS-MachineAccountQuota'
$out.machine_account_quota = [int]$obj.'ms-DS-MachineAccountQuota'
$krb = Get-ADUser -Filter "samaccountname -eq 'krbtgt'" -Properties PasswordLastSet
$out.krbtgt_pwdlastset = Iso $krb.PasswordLastSet

# ── 트러스트 (원시 속성) ──
$out.trusts = @(Get-ADTrust -Filter * | ForEach-Object {
  [ordered]@{ Name=$_.Name; Direction="$($_.Direction)"; IntraForest=[bool]$_.IntraForest
    TrustType="$($_.TrustType)"; ForestTransitive=[bool]$_.ForestTransitive
    SIDFilteringQuarantined=[bool]$_.SIDFilteringQuarantined; SIDFilteringForestAware=[bool]$_.SIDFilteringForestAware
    SelectiveAuthentication=[bool]$_.SelectiveAuthentication; TGTDelegation=[bool]$_.TGTDelegation } })

# ── 서비스 / SMB / BitLocker / Credential Guard / AppLocker (원시) ──
$sp = Get-Service Spooler
$out.services = [ordered]@{ Spooler=[ordered]@{ Status="$($sp.Status)"; StartType="$($sp.StartType)" } }
$smb = Get-SmbServerConfiguration
$out.smb = [ordered]@{ EnableSMB1Protocol=[bool]$smb.EnableSMB1Protocol; EnableSecuritySignature=[bool]$smb.EnableSecuritySignature; RequireSecuritySignature=[bool]$smb.RequireSecuritySignature }
# SS06-D BitLocker — 기능 미설치 시 Get-BitLockerVolume cmdlet 부재로 결과가 빈배열이 됨(에러는 EAP=SilentlyContinue 로 무시됨).
#   → 수집여부(bitlocker_collected)를 명시 기록 + cmdlet 없으면 WMI(Win32_EncryptableVolume) 폴백. 빈값=미적용을 엔진이 구분.
$out.bitlocker = @()
$out.bitlocker_collected = $false
if (Get-Command Get-BitLockerVolume -ErrorAction SilentlyContinue) {
  $out.bitlocker = @(Get-BitLockerVolume | ForEach-Object { [ordered]@{ Mount="$($_.MountPoint)"; Protection="$($_.ProtectionStatus)" } })
  $out.bitlocker_collected = $true
} else {
  try {
    $ev = Get-CimInstance -Namespace 'root\CIMV2\Security\MicrosoftVolumeEncryption' -ClassName Win32_EncryptableVolume -ErrorAction Stop
    $out.bitlocker = @($ev | ForEach-Object {
        $ps = switch ([int]$_.ProtectionStatus) { 1 {'On'} 0 {'Off'} default {'Unknown'} }
        [ordered]@{ Mount="$($_.DriveLetter)"; Protection=$ps } })
    $out.bitlocker_collected = $true
  } catch { $out.bitlocker_collected = $false }  # BitLocker 기능 미설치 = 디스크 암호화 미적용
}
$out.credential_guard = @((Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard).SecurityServicesRunning)
$out.applocker_rulecounts = @((Get-AppLockerPolicy -Effective).RuleCollections | ForEach-Object { [ordered]@{ Type="$($_.RuleCollectionType)"; Count=$_.Count } })

# ── WinRM(SS03) / 보안업데이트(SS06) / gMSA(IC04) — 신규, 각자 try/catch 로 전체 수집 보호 ──
try {
  $wr = Get-Service WinRM -ErrorAction Stop
  # SS04-A: '접근 통제' 자동판정용 — 리스너 전송(HTTP/HTTPS) + 평문허용(AllowUnencrypted) + Basic 인증 수집.
  $lsn = @()
  try { $lsn = @(Get-ChildItem WSMan:\localhost\Listener -ErrorAction Stop | ForEach-Object {
          $c = Get-ChildItem $_.PSPath -ErrorAction SilentlyContinue
          [ordered]@{ Transport = "$(($c | Where-Object Name -eq 'Transport').Value)"; Port = "$(($c | Where-Object Name -eq 'Port').Value)" } }) } catch {}
  $au = $null; try { $au = (Get-Item WSMan:\localhost\Service\AllowUnencrypted -ErrorAction Stop).Value } catch {}
  $ba = $null; try { $ba = (Get-Item WSMan:\localhost\Service\Auth\Basic -ErrorAction Stop).Value } catch {}
  $out.winrm = [ordered]@{ Status="$($wr.Status)"; StartType="$($wr.StartType)"; Listeners=$lsn; AllowUnencrypted=$au; AuthBasic=$ba }
} catch { $out.winrm = $null }
try { $hf = Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending | Select-Object -First 1; $out.hotfix_latest = Iso $hf.InstalledOn } catch { $out.hotfix_latest = $null }
try { $out.gmsa = @(Get-ADServiceAccount -Filter * -ErrorAction Stop | Select-Object -Expand SamAccountName) } catch { $out.gmsa = $null }

# ── 레지스트리 (원시값 그대로) ──
$out.registry = [ordered]@{
  Wdigest_UseLogonCredential = RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest" "UseLogonCredential"
  Lsa_RunAsPPL=RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL"
  Lsa_NoLMHash=RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "NoLMHash"
  Lsa_LmCompatibilityLevel=RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LmCompatibilityLevel"
  Lsa_RestrictRemoteSAM=RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictRemoteSAM"
  Lsa_RestrictAnonymous=RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous"
  Lsa_SubmitControl=RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "SubmitControl"
  Lsa_AllowCustomSSPsAPs=RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "AllowCustomSSPsAPs"
  MSV1_0_NTLMMinClientSec=RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "NtlmMinClientSec"
  MSV1_0_NTLMMinServerSec=RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "NtlmMinServerSec"
  DNSClient_EnableMulticast=RegVal "HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient" "EnableMulticast"
  PowerShell_ScriptBlockLogging=RegVal "HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" "EnableScriptBlockLogging"
  Netlogon_RequireSeal=RegVal "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "RequireSeal"
  Netlogon_RequireSignOrSeal=RegVal "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "RequireSignOrSeal"
  Netlogon_RefusePasswordChange=RegVal "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "RefusePasswordChange"
  # 컴퓨터(머신) 계정 패스워드 자동변경 (AM19-D ②): 기본 30일, DisablePasswordChange=1=변경안함
  Netlogon_MaximumPasswordAge=RegVal "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "MaximumPasswordAge"
  Netlogon_DisablePasswordChange=RegVal "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "DisablePasswordChange"
  Netlogon_VulnerableChannelAllowList=RegVal "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "vulnerablechannelallowlist"
  NTDS_LdapServerIntegrity=RegVal "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" "LDAPServerIntegrity"
  NTDS_LdapEnforceChannelBinding=RegVal "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" "LdapEnforceChannelBinding"
  Kerberos_ValidateKdcPacSignature=RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Kerberos\Parameters" "ValidateKdcPacSignature"
  # Kerberos Armoring(FAST) — KDC/클라이언트 GPO (IC08). 0/없음=미지원, >=1=지원/항상
  KDC_EnableCbacAndArmor=RegVal "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC" "EnableCbacAndArmor"
  KDC_CbacAndArmorLevel=RegVal "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC" "CbacAndArmorLevel"
  Kerberos_ClientEnableCbacAndArmor=RegVal "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters" "EnableCbacAndArmor"
}

# ── ACL 수집 (AC08/AC09 복제권한, IC01 고권한객체, IC03 AdminSDHolder) — 원시 ACE 목록, 판정은 엔진 ──
#    AD: PSDrive(ActiveDirectory 모듈 제공) 사용. 실패는 무시(부분수집).
function Get-AdAces($objDn) { try { return (Get-Acl "AD:\$objDn").Access } catch { return @() } }
function Get-DangerAces($objDn, $label) {
  @(foreach ($ace in (Get-AdAces $objDn)) {
    if ($ace.AccessControlType -ne 'Allow') { continue }
    $r = "$($ace.ActiveDirectoryRights)"
    if ($r -match 'GenericAll|WriteDacl|WriteOwner') {
      [ordered]@{ Object=$label; Identity="$($ace.IdentityReference)"; Rights=$r } } })
}
Step ("컴퓨터 {0}건 수집 완료 — ACL/위임 수집 중…" -f $out.computers.Count)
$out.acl = [ordered]@{}
# 복제권한 GUID (확장권한)
$replGuid = @{ '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'='GetChanges'
               '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'='GetChangesAll'
               '89e95b76-444d-4c62-991a-0facbeda640c'='GetChangesInFilteredSet' }
$repl = [ordered]@{ GetChanges=@(); GetChangesAll=@(); GetChangesInFilteredSet=@() }
foreach ($ace in (Get-AdAces $dn)) {
  if ($ace.AccessControlType -ne 'Allow') { continue }
  $g = "$($ace.ObjectType)".ToLower()
  if ($replGuid.ContainsKey($g)) { $repl[$replGuid[$g]] += "$($ace.IdentityReference)" }
}
$out.acl.replication = [ordered]@{
  GetChanges=@($repl.GetChanges | Select-Object -Unique)
  GetChangesAll=@($repl.GetChangesAll | Select-Object -Unique)
  GetChangesInFilteredSet=@($repl.GetChangesInFilteredSet | Select-Object -Unique) }
# AdminSDHolder (IC03)
$out.acl.adminsdholder = @(Get-DangerAces "CN=AdminSDHolder,CN=System,$dn" 'AdminSDHolder')
# 고권한 객체 (IC01): 도메인루트 + 특권그룹 + krbtgt
$hp = @(); $hp += Get-DangerAces $dn 'DomainRoot'
foreach ($grp in 'Domain Admins','Enterprise Admins','Administrators','Schema Admins') {
  $gobj = Get-ADGroup $grp -ErrorAction SilentlyContinue
  if ($gobj) { $hp += Get-DangerAces $gobj.DistinguishedName $grp } }
$kt = Get-ADUser -Filter "samaccountname -eq 'krbtgt'" -ErrorAction SilentlyContinue
if ($kt) { $hp += Get-DangerAces $kt.DistinguishedName 'krbtgt' }
$out.acl.highpriv = @($hp)

# ── SID History (위협: SID History 주입) — sIDHistory 보유 객체만 LDAP 타겟 ──
#    ★ sIDHistory 는 비인덱스 속성 → (sIDHistory=*) 단독은 전 객체 풀스캔(DC 부하).
#      objectCategory(인덱스됨)로 보안주체(user/computer/group)만 후보로 좁혀 스캔 대상 축소.
#      SID History 는 보안주체에만 존재하므로 결과 누락 없음.
Step "SID History / 사용자권한 / 감사정책 / SYSVOL 수집 중…"
$out.sid_history = @(Get-ADObject -LDAPFilter '(&(sIDHistory=*)(|(objectCategory=person)(objectCategory=computer)(objectCategory=group)))' -Properties sIDHistory, objectClass, sAMAccountName -ResultPageSize 1000 -Server $Srv -ErrorAction SilentlyContinue |
  ForEach-Object { [ordered]@{
    Name = $_.sAMAccountName; Class = "$($_.objectClass | Select-Object -Last 1)"
    SIDHistory = @($_.sIDHistory | ForEach-Object { "$_" }) } })

# ── 사용자 권한 할당 (secedit, 원시) ──
$inf = Join-Path $OutDir "_userrights.inf"
secedit /export /areas USER_RIGHTS /cfg $inf | Out-Null
$ur = [ordered]@{}
foreach ($line in (Get-Content $inf | Where-Object { $_ -match '^Se\w+Privilege' })) {
  $k,$v = $line -split '=',2; $ur[$k.Trim()] = @(($v.Trim() -split ',') | ForEach-Object { $_.Trim() })
}
$out.user_rights = $ur
Remove-Item $inf -ErrorAction SilentlyContinue

# ── 고급 감사 정책 (auditpol) — GUID 사용(언어 무관), 값은 원시(한글일 수 있음) ──
$auditSubs = [ordered]@{
  'Directory Service Changes'           = '{0CCE923C-69AE-11D9-BED3-505054503030}'
  'Directory Service Access'            = '{0CCE923B-69AE-11D9-BED3-505054503030}'
  'Credential Validation'               = '{0CCE923F-69AE-11D9-BED3-505054503030}'
  'Kerberos Authentication Service'     = '{0CCE9242-69AE-11D9-BED3-505054503030}'
  'Kerberos Service Ticket Operations'  = '{0CCE9240-69AE-11D9-BED3-505054503030}'
  'Computer Account Management'         = '{0CCE9236-69AE-11D9-BED3-505054503030}'
}
$out.audit_policy = [ordered]@{}
foreach ($k in $auditSubs.Keys) {
  $row = (auditpol /get /subcategory:"$($auditSubs[$k])" /r 2>$null | Select-Object -Skip 1 | Where-Object { $_ -match ',' } | Select-Object -First 1)
  if ($row) { $out.audit_policy[$k] = ($row -split ',')[4].Trim() } else { $out.audit_policy[$k] = $null }
}
# 진단: 전 범주 null = auditpol 자체 실패(주로 비관리자 권한). 원인 메시지 1회 캡처(인스펙터가 INFO 로 표시).
if (($out.audit_policy.Values | Where-Object { $_ -ne $null }).Count -eq 0) {
  $out.audit_policy_error = ((auditpol /get /subcategory:"$($auditSubs['Credential Validation'])" 2>&1 | Out-String).Trim())
}

# ── GPP cpassword: SYSVOL Policies 의 GPP 파일만 타겟 (★저부하: 전체 재귀 금지) ──
#    원시 결과(매치 파일 목록)만 수집. 판정은 점검엔진.
$gppFiles = 'Groups.xml','Services.xml','ScheduledTasks.xml','DataSources.xml','Drives.xml','Printers.xml'
# UNC 는 컴퓨터 이름(NetBIOS)으로 — NIC DNS 가 자기 도메인 못 풀어도 동작
$polRoot = "\\$($env:COMPUTERNAME)\SYSVOL\$($domain.DNSRoot)\Policies"
$out.gpp_cpassword_files = @(
  Get-ChildItem -Path $polRoot -Recurse -Include $gppFiles -ErrorAction SilentlyContinue |
    Where-Object { Select-String -Path $_.FullName -Pattern 'cpassword' -SimpleMatch -Quiet } |
    Select-Object -Expand FullName )

# ── 도메인 GPO 적용값 (AC25: RDP/NLA/FW/RunAsPPL/AdminShare) ──
#    전 GPO 순회(Get-GPO -All / Get-GPRegistryValue) 불필요 — 필요한 레지스트리 값만
#    로컬에서 직접 조회. GroupPolicy 모듈/SYSVOL 스캔 없음 → AD 부하 0 (레지스트리 읽기).
#    · RDP/NLA/FW 는 SOFTWARE\Policies\... 경로 = GPO 관리값 전용 → 값 존재 자체가 GPO 강제 신호.
#    · RunAsPPL/AdminShare 는 GPO registry preference 로 배포되는 실제 적용키.
#    미설정(GPO 없음/미적용)은 RegVal 이 null 반환 — 판정은 점검 엔진.
Step "GPO 도메인 정책(레지스트리 적용값) 수집 중…"
$out.gpo_domain = [ordered]@{
  # 1) 원격 데스크톱 (fDenyTSConnections=1=비활성 강제)
  TS_fDenyTSConnections    = RegVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "fDenyTSConnections"
  # 2) NLA(Network Level Authentication) (UserAuthentication=1=NLA 강제)
  TS_UserAuthentication    = RegVal "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" "UserAuthentication"
  # 3) Windows 방화벽 도메인 프로파일 (EnableFirewall=1, AllowLocalPolicyMerge=0)
  FW_DomainEnabled         = RegVal "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" "EnableFirewall"
  FW_AllowLocalPolicyMerge = RegVal "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\DomainProfile" "AllowLocalPolicyMerge"
  # 4) RunAsPPL — GPO registry preference 로 배포되는 실제 적용키 (AC04-B 와 동일 키)
  Lsa_RunAsPPL_GPO         = RegVal "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RunAsPPL"
  # 5) Admin Share 자동 생성 (AutoShareServer=0=비활성. 미설정=기본활성)
  Srv_AutoShareServer      = RegVal "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "AutoShareServer"
  Srv_AutoShareWks         = RegVal "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "AutoShareWks"
}

# ── 저장 (ONE-SYNC 점검 네이밍: <host>_AD_DC.txt — Category="AD"/Platform="DC", 내용은 JSON) ──
$path = Join-Path $OutDir ("{0}_AD_DC.txt" -f $env:COMPUTERNAME)
$out | ConvertTo-Json -Depth 6 | Out-File -FilePath $path -Encoding UTF8
Step ("[OK] AD 수집 완료 (read-only, no verdict) -> {0}" -f $path)

Setlocal EnableExtensions
Setlocal EnableDelayedExpansion
SET fsi_NLM=^
SET fsi_NL=^^^%fsi_NLM%%fsi_NLM%^%fsi_NLM%%fsi_NLM%
SET fsi_scriptver=fsi2018v2

FOR /F "delims=" %%i IN ('hostname') DO SET fsi_hostnm=%%i
FOR /f %%a in ('WMIC OS GET LocalDateTime ^| find "."') DO SET fsi_DTS=%%a
SET fsi_path=%~dp0
SET fsi_today=%fsi_DTS:~0,4%%fsi_DTS:~4,2%%fsi_DTS:~6,2%
SET fsi_dir="%fsi_path%%fsi_hostnm%-%fsi_today%"
SET fsi_vbs="%fsi_path%vbscripts\"
if not exist %fsi_dir% mkdir %fsi_dir%
SET fsi_dir=%fsi_path%%fsi_hostnm%-%fsi_today%
SET fsi_path="%~dp0"
SET fsi_outfile="%fsi_dir%\%fsi_hostnm%-s-%fsi_today%.xml"

::Script Information
::Version 1.0 Written by Summer
::Would be Updated by FSI VA Team

::Script Header and Information
echo ^<?xml version="1.0" encoding="euc-kr"?^> > %fsi_outfile%
echo ^<?xml-stylesheet type="text/xsl" href="isac.xsl"?^> >> %fsi_outfile%
echo ^<script^> >> %fsi_outfile%
echo 	^<asset^> >> %fsi_outfile%
echo 		^<hostname^>%fsi_hostnm%^</hostname^> >> %fsi_outfile%

FOR /F "delims=" %%i IN ('REG query "HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v "ProductName"') DO SET fsi_osname=%%i
SET fsi_osname=%fsi_osname:~29%
echo 		^<os^>%fsi_osname%^</os^> >> %fsi_outfile%

FOR /F "delims=" %%i IN ('ver') DO SET fsi_osver=%%i
echo 		^<uname^>%fsi_osver%^</uname^> >> %fsi_outfile%


::Check admin running
net session >nul 2>&1

if %errorLevel% == 0 (
	SET fsi_curuser=Administrator
) else (
	SET fsi_curuser=notadmin
)

echo 		^<whoami^>%fsi_curuser%^</whoami^> >> %fsi_outfile%

echo 		^<version^>%fsi_scriptver%^</version^> >> %fsi_outfile%
echo 		^<data_role^>raw_data_provider^</data_role^> >> %fsi_outfile%
echo 		^<judgment_mode^>raw_evidence_only^</judgment_mode^> >> %fsi_outfile%
echo 		^<verdict_source^>none^</verdict_source^> >> %fsi_outfile%
echo 		^<safe_type_policy^>AI decides vulnerable/safe/info/unable and safe subtype from raw evidence only.^</safe_type_policy^> >> %fsi_outfile%
echo 		^<ai_note^>Script provides raw command evidence only. AI and LLM must decide verdict independently.^</ai_note^> >> %fsi_outfile%
echo 	^</asset^> >> %fsi_outfile%

::Tag settings
SET "fsi_dumpst=echo 		^<dump^> >> %fsi_outfile%"
SET "fsi_dumped=echo 		^</dump^> >> %fsi_outfile%"
SET "fsi_itemst=echo 			^<items^> >> %fsi_outfile%"
SET "fsi_itemed=echo 			^</items^> >> %fsi_outfile%"
SET "fsi_outputst=echo 			^<evidence_profile^> >> %fsi_outfile% & echo 				^<data_role^>raw_command_output^</data_role^> >> %fsi_outfile% & echo 				^<judgment_mode^>raw_evidence_only^</judgment_mode^> >> %fsi_outfile% & echo 				^<verdict_source^>none^</verdict_source^> >> %fsi_outfile% & echo 				^<safe_type_policy^>AI decides absence-good or value-compliant-good from raw output only.^</safe_type_policy^> >> %fsi_outfile% & echo 				^<command_marker^>cmd#^</command_marker^> >> %fsi_outfile% & echo 			^</evidence_profile^> >> %fsi_outfile% & echo 			^<output^> >> %fsi_outfile%"
SET "fsi_outputed=echo 			^</output^> >> %fsi_outfile%"


::Script Running
if exist "%~dp0vbscripts\site_status.vbs" (
	cscript //nologo %fsi_vbs%site_status.vbs WEB >> "%fsi_dir%\web_stat.txt"
	cscript //nologo %fsi_vbs%site_status.vbs FTP >> "%fsi_dir%\ftp_stat.txt"
) else (
	echo VBS helper missing: %~dp0vbscripts\site_status.vbs > "%fsi_dir%\web_stat.txt"
	echo VBS helper missing: %~dp0vbscripts\site_status.vbs > "%fsi_dir%\ftp_stat.txt"
)


::Result start
echo 	^<results^> >> %fsi_outfile%

%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-001^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%
echo cmd# REG QUERY ^"HKLM\SYSTEM\CurrentControlSet\services\SNMP\Parameters\ValidCommunities^" >> %fsi_outfile%

FOR /F "delims=" %%i IN ('REG QUERY HKLM\SYSTEM\CurrentControlSet\services\SNMP\Parameters\ValidCommunities') DO SET fsi_result=%%i
if defined fsi_result (
	REG QUERY HKLM\SYSTEM\CurrentControlSet\services\SNMP\Parameters\ValidCommunities >> %fsi_outfile%
) else (
	echo Registry key value not found: HKLM\SYSTEM\CurrentControlSet\services\SNMP\Parameters\ValidCommunities >> %fsi_outfile%
)
SET fsi_result=

echo. >> %fsi_outfile%
echo cmd# sc query SNMP >> %fsi_outfile%

sc query SNMP >> %fsi_outfile%
%fsi_outputed%
%fsi_dumped%


%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-002^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%
echo cmd# REG QUERY ^"HKLM\SYSTEM\CurrentControlSet\services\SNMP\Parameters\ValidCommunities^" >> %fsi_outfile%

FOR /F "delims=" %%i IN ('REG QUERY HKLM\SYSTEM\CurrentControlSet\services\SNMP\Parameters\ValidCommunities') DO SET fsi_result=%%i
if defined fsi_result (
	REG QUERY HKLM\SYSTEM\CurrentControlSet\services\SNMP\Parameters\ValidCommunities >> %fsi_outfile%
) else (
	echo Registry key value not found: HKLM\SYSTEM\CurrentControlSet\services\SNMP\Parameters\ValidCommunities >> %fsi_outfile%
)
SET fsi_result=

echo. >> %fsi_outfile%
echo cmd# sc query SNMP >> %fsi_outfile%

sc query SNMP >> %fsi_outfile%
%fsi_outputed%
%fsi_dumped%





%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-003^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


echo cmd# sc query SNMP >> %fsi_outfile%

sc query SNMP >> %fsi_outfile%

echo. >> %fsi_outfile%

echo cmd# REG QUERY ^"HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers^" >> %fsi_outfile%

FOR /F "delims=" %%i IN ('REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers"') DO SET fsi_result=%%i
if defined fsi_result (
	REG QUERY "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers" >> %fsi_outfile%
) else (
	echo Registry key value not found: "HKLM\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers" >> %fsi_outfile%
)
SET fsi_result=


%fsi_outputed%
%fsi_dumped%





%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-004^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# netstat -an ^| findstr :25 >> %fsi_outfile%

netstat -an | findstr :25 >> %fsi_outfile%

echo. >> %fsi_outfile%
echo cmd# sc query SMTPSVC >> %fsi_outfile%

sc query SMTPSVC >> %fsi_outfile%
%fsi_outputed%
%fsi_dumped%


%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-013^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# sc query MSFTPSVC >> %fsi_outfile%

sc query MSFTPSVC >> %fsi_outfile%

echo cmd# sc query FTPSVC >> %fsi_outfile%

sc query FTPSVC >> %fsi_outfile%

echo. >> %fsi_outfile%
echo cmd# netstat -an ^| findstr :21 >> %fsi_outfile%

netstat -an | findstr :21 >> %fsi_outfile%

echo. >> %fsi_outfile%

echo Refer to iis config file >> %fsi_outfile%

%fsi_outputed%
%fsi_dumped%


%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-018^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# REG QUERY HKLM\SYSTEM\CurrentControlSet\Services\Lanmanserver\Parameters /v AutoShareServer >> %fsi_outfile%

FOR /F "delims=" %%i IN ('REG QUERY HKLM\SYSTEM\CurrentControlSet\Services\Lanmanserver\Parameters /v AutoShareServer') DO SET fsi_result=%%i
if defined fsi_result (
	REG QUERY HKLM\SYSTEM\CurrentControlSet\Services\Lanmanserver\Parameters /v AutoShareServer >> %fsi_outfile%
) else (
	echo Registry key value not found: HKLM\SYSTEM\CurrentControlSet\Services\Lanmanserver\Parameters /v AutoShareServer >> %fsi_outfile%
)
SET fsi_result=

echo. >> %fsi_outfile%

echo cmd# REG QUERY HKLM\SYSTEM\CurrentControlSet\Services\Lanmanserver\Parameters /v AutoShareWks >> %fsi_outfile%

FOR /F "delims=" %%i IN ('REG QUERY HKLM\SYSTEM\CurrentControlSet\Services\Lanmanserver\Parameters /v AutoShareWks') DO SET fsi_result=%%i
if defined fsi_result (
	REG QUERY HKLM\SYSTEM\CurrentControlSet\Services\Lanmanserver\Parameters /v AutoShareWks >> %fsi_outfile%
) else (
	echo Registry key value not found: HKLM\SYSTEM\CurrentControlSet\Services\Lanmanserver\Parameters /v AutoShareWks >> %fsi_outfile%
)
SET fsi_result=


echo cmd# net share >> %fsi_outfile%

net share >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%


%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-020^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# net share >> %fsi_outfile%

net share >> %fsi_outfile%

echo cmd# cacls "Shared Folders" >> %fsi_outfile%

SET fsi_RegQuery=reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares /t REG_MULTI_SZ /se #
FOR /F "skip=2 tokens=*" %%S IN ('%fsi_RegQuery%') DO (
	FOR /F "tokens=3,5 delims=#" %%H IN ('ECHO "%%S"') DO (
		set fsi_share=%%H
		set fsi_share=!fsi_share:~5!
		cacls !fsi_share! >> %fsi_outfile%
	)
)

SET fsi_RegQuery=reg query HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares /t REG_MULTI_SZ /se #
FOR /F "skip=2 tokens=*" %%S IN ('%fsi_RegQuery%') DO (
	FOR /F "tokens=4,5 delims=#" %%H IN ('ECHO "%%S"') DO (
		set fsi_share=%%H
		set fsi_share=!fsi_share:~5!
		cacls !fsi_share! >> %fsi_outfile%
	)
)

%fsi_outputed%
%fsi_dumped%


%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-021^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


echo Refer to iis config file >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-022^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%
echo cmd# REG QUERY ^"HKLM\SYSTEM\CurrentControlSet\Control\Lsa^" /v LimitBlankPasswordUse >> %fsi_outfile%

FOR /F "delims=" %%i IN ('REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse') DO SET fsi_result=%%i
if defined fsi_result (
	REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse >> %fsi_outfile%
) else (
	echo Registry key value not found: "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LimitBlankPasswordUse >> %fsi_outfile%
)
SET fsi_result=

%fsi_outputed%
%fsi_dumped%




%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-023^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# REG QUERY ^"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp^" /v MinEncryptionLevel >> %fsi_outfile%

FOR /F "delims=" %%i IN ('REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MinEncryptionLevel') DO SET fsi_result=%%i
if defined fsi_result (
	REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MinEncryptionLevel >> %fsi_outfile%
) else (
	echo Registry key value not found: "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MinEncryptionLevel >> %fsi_outfile%
)
SET fsi_result=

echo. >> %fsi_outfile%

echo cmd# REG QUERY ^"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services^" >> %fsi_outfile%

FOR /F "delims=" %%i IN ('REG QUERY "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"') DO SET fsi_result=%%i
if defined fsi_result (
	REG QUERY "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" >> %fsi_outfile%
) else (
	echo Registry key value not found: "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" >> %fsi_outfile%
)
SET fsi_result=

echo. >> %fsi_outfile%

echo cmd# netstat -an ^| findstr :3389 >> %fsi_outfile%

netstat -an | findstr :3389 >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%




%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-024^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# sc query TlntSvr >> %fsi_outfile%

sc query TlntSvr >> %fsi_outfile%

echo. >> %fsi_outfile%

echo cmd# tlntadmn config >> %fsi_outfile%

tlntadmn config >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-028^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%
echo cmd# REG QUERY ^"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp^" /v MaxIdleTime >> %fsi_outfile%

FOR /F "delims=" %%i IN ('REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MaxIdleTime') DO SET fsi_result=%%i
if defined fsi_result (
	REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MaxIdleTime >> %fsi_outfile%
) else (
	echo Registry key value not found: "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v MaxIdleTime >> %fsi_outfile%
)
SET fsi_result=

echo. >> %fsi_outfile%

echo cmd# REG QUERY ^"HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services^" >> %fsi_outfile%

FOR /F "delims=" %%i IN ('REG QUERY "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"') DO SET fsi_result=%%i
if defined fsi_result (
	REG QUERY "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" >> %fsi_outfile%
) else (
	echo Registry key value not found: "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" >> %fsi_outfile%
)
SET fsi_result=

echo. >> %fsi_outfile%

echo cmd# netstat -an ^| findstr :3389 >> %fsi_outfile%

netstat -an | findstr :3389 >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%




%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-029^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%
echo cmd# REG QUERY ^"HKLM\System\CurrentControlSet\Services\LanManServer\Parameters^" /v EnableForcedLogOff >> %fsi_outfile%

FOR /F "delims=" %%i IN ('REG QUERY "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v EnableForcedLogOff') DO SET fsi_result=%%i
if defined fsi_result (
	REG QUERY "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v EnableForcedLogOff >> %fsi_outfile%
) else (
	echo Registry key value not found: "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v EnableForcedLogOff >> %fsi_outfile%
)
SET fsi_result=

echo. >> %fsi_outfile%

echo cmd# REG QUERY ^"HKLM\System\CurrentControlSet\Services\LanManServer\Parameters^" /v autodisconnect >> %fsi_outfile%

FOR /F "delims=" %%i IN ('REG QUERY "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v autodisconnect') DO SET fsi_result=%%i
if defined fsi_result (
	REG QUERY "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v autodisconnect >> %fsi_outfile%
) else (
	echo Registry key value not found: "HKLM\System\CurrentControlSet\Services\LanManServer\Parameters" /v autodisconnect >> %fsi_outfile%
)
SET fsi_result=


%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-031^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# REG QUERY HKLM\SYSTEM\CurrentControlSet\Control\LSA /v RestrictAnonymous >> %fsi_outfile%

FOR /F "delims=" %%i IN ('REG QUERY HKLM\SYSTEM\CurrentControlSet\Control\LSA /v RestrictAnonymous') DO SET fsi_result=%%i
if defined fsi_result (
	REG QUERY HKLM\SYSTEM\CurrentControlSet\Control\LSA /v RestrictAnonymous >> %fsi_outfile%
) else (
	echo Registry key value not found: HKLM\SYSTEM\CurrentControlSet\Control\LSA\RestrictAnonymous >> %fsi_outfile%
)
SET fsi_result=

echo. >> %fsi_outfile%

echo cmd# REG QUERY HKLM\SYSTEM\CurrentControlSet\Control\LSA /v RestrictAnonymousSam >> %fsi_outfile%

FOR /F "delims=" %%i IN ('REG QUERY HKLM\SYSTEM\CurrentControlSet\Control\LSA /v RestrictAnonymousSam') DO SET fsi_result=%%i
if defined fsi_result (
	REG QUERY HKLM\SYSTEM\CurrentControlSet\Control\LSA /v RestrictAnonymousSam >> %fsi_outfile%
) else (
	echo Registry key value not found: HKLM\SYSTEM\CurrentControlSet\Control\LSA\RestrictAnonymousSam >> %fsi_outfile%
)
SET fsi_result=


%fsi_outputed%
%fsi_dumped%


%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-032^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# REG QUERY HKLM\SYSTEM\CurrentControlSet\Services\NetBT\parameters\Interfaces\{All_Interfaces} >> %fsi_outfile%

FOR /F "delims=" %%i IN ('REG QUERY HKLM\SYSTEM\CurrentControlSet\Services\NetBT\parameters\Interfaces') DO (
	SET fsi_result=%%i
	REG QUERY !fsi_result! >> %fsi_outfile%
)
SET fsi_result=

echo cmd# REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}" /s >> %fsi_outfile% 


FOR /F "delims=" %%i IN ('REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}" /s') DO (
	SET fsi_result=%%i
	REG QUERY !fsi_result! >> %fsi_outfile%
)
SET fsi_result=


echo cmd# netsh interface show interface >> %fsi_outfile%

netsh interface show interface >> %fsi_outfile%


echo cmd# wmic nic get AdapterType, Name, DeviceID, InterfaceIndex, ServiceName >> %fsi_outfile%

wmic nic get AdapterType, Name, DeviceID, InterfaceIndex, ServiceName | more >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%


%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-034^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


echo cmd# sc query Alerter >> %fsi_outfile%
sc query Alerter >> %fsi_outfile%

echo. >> %fsi_outfile%
echo cmd# sc query ClipSrv >> %fsi_outfile%
sc query ClipSrv >> %fsi_outfile%

echo. >> %fsi_outfile%
echo cmd# sc query Messenger >> %fsi_outfile%
sc query Messenger >> %fsi_outfile%

echo. >> %fsi_outfile%
echo cmd# sc query SimpTcp >> %fsi_outfile%
sc query SimpTcp >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%


%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-037^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


echo cmd# sc query MSFTPSVC >> %fsi_outfile%

sc query MSFTPSVC >> %fsi_outfile%


echo cmd# sc query FTPSVC >> %fsi_outfile%

sc query FTPSVC >> %fsi_outfile%

echo. >> %fsi_outfile%
echo cmd# netstat -an ^| findstr :21 >> %fsi_outfile%

netstat -an | findstr :21 >> %fsi_outfile%

%fsi_outputed%
%fsi_dumped%


%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-038^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# sc query IISADMIN >> %fsi_outfile%
sc query IISADMIN >> %fsi_outfile%

echo. >> %fsi_outfile%
echo cmd# sc query W3SVC >> %fsi_outfile%
sc query W3SVC >> %fsi_outfile%

echo. >> %fsi_outfile%

echo Refer to iis config file >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%


%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-039^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# sc query Webtob >> %fsi_outfile%
sc query Webtob >> %fsi_outfile%

%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-041^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# cacls C:\inetpub\scripts >> %fsi_outfile%
cacls C:\inetpub\scripts >> %fsi_outfile%
echo. >> %fsi_outfile%

echo cmd# cacls C:\inetpub\cgi-bin >> %fsi_outfile%
cacls C:\inetpub\cgi-bin >> %fsi_outfile%
echo. >> %fsi_outfile%

echo cmd# cacls C:\inetpub\wwwroot\cgi-bin >> %fsi_outfile%
cacls C:\inetpub\wwwroot\cgi-bin >> %fsi_outfile%
echo. >> %fsi_outfile%

echo cmd# cacls C:\inetpub\wwwroot >> %fsi_outfile%
cacls C:\inetpub\wwwroot >> %fsi_outfile%
echo. >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%




%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-048^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# sc query iisadmin >> %fsi_outfile%
echo. >> %fsi_outfile%

sc query iisadmin >> %fsi_outfile%
echo. >> %fsi_outfile%

echo cmd# sc query w3svc >> %fsi_outfile%
echo. >> %fsi_outfile%

sc query w3svc >> %fsi_outfile%
echo. >> %fsi_outfile%

echo cmd# sc query was >> %fsi_outfile%
echo. >> %fsi_outfile%

sc query was >> %fsi_outfile%
echo. >> %fsi_outfile%

%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-049^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


echo Refer to iis config file >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-050^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


echo Refer to iis config file >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%




%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-051^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


echo Refer to iis config file >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%




%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-052^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


echo Refer to iis config file >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-053^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


if exist "%~dp0vbscripts\enum_site.vbs" (
	cscript //nologo %fsi_vbs%enum_site.vbs > "%fsi_dir%\iis_site_list.txt"
) else (
	echo VBS helper missing: %~dp0vbscripts\enum_site.vbs > "%fsi_dir%\iis_site_list.txt"
)

%systemroot%\System32\inetsrv\appcmd list VDir > "%fsi_dir%\iis_site_list2.txt"


FOR /F "tokens=5 delims=	" %%i in ('type "%fsi_dir%\iis_site_list.txt"') do (
		echo _______________________________________________________________ >> %fsi_outfile%
		echo Web Home Path: %%i >> %fsi_outfile%
		echo _______________________________________________________________ >> "%fsi_dir%\iis_acl.txt"
		echo Web Home Path: %%i >> "%fsi_dir%\iis_acl.txt"
		cd /d %%i
		cacls *.exe /T >> "%fsi_dir%\iis_acl.txt"
		cacls *.dll /T >> "%fsi_dir%\iis_acl.txt"
		cacls *.cmd /T >> "%fsi_dir%\iis_acl.txt"
		cacls *.pl /T >> "%fsi_dir%\iis_acl.txt"
		cacls *.asp /T >> "%fsi_dir%\iis_acl.txt"
		cacls *.inc /T >> "%fsi_dir%\iis_acl.txt"
		cacls *.shtm /T >> "%fsi_dir%\iis_acl.txt"
		cacls *.shtml /T >> "%fsi_dir%\iis_acl.txt"
		cacls *.txt /T >> "%fsi_dir%\iis_acl.txt"
		cacls *.gif /T >> "%fsi_dir%\iis_acl.txt"
		cacls *.jpg /T >> "%fsi_dir%\iis_acl.txt"
		cacls *.html /T >> "%fsi_dir%\iis_acl.txt"
		echo. >> "%fsi_dir%\iis_acl.txt"

		ATTRIB /s | findstr .lnk >> %fsi_outfile%
		echo. >> %fsi_outfile%
)

SET fsi_drive=%SystemRoot:~0,2%
FOR /F "tokens=2 delims=(" %%i in ('type "%fsi_dir%\iis_site_list2.txt"') do (
		SET fsi_var=%%i
		SET fsi_var=!fsi_var:~13,-1!
		SET fsi_var=!fsi_var:%%SystemDrive%%=%fsi_drive%!
		SET fsi_var="!fsi_var!"
		echo _______________________________________________________________ >> %fsi_outfile%
		echo Web Home Path: !fsi_var! >> %fsi_outfile%
		echo _______________________________________________________________ >> "%fsi_dir%\iis_acl2.txt"
		echo Web Home Path: !fsi_var! >> "%fsi_dir%\iis_acl2.txt"
		cd /d !fsi_var!
		cacls !fsi_var! >> "%fsi_dir%\iis_acl2.txt"
		cacls *.exe /T >> "%fsi_dir%\iis_acl2.txt"
		cacls *.dll /T >> "%fsi_dir%\iis_acl2.txt"
		cacls *.cmd /T >> "%fsi_dir%\iis_acl2.txt"
		cacls *.pl /T >> "%fsi_dir%\iis_acl2.txt"
		cacls *.asp /T >> "%fsi_dir%\iis_acl2.txt"
		cacls *.inc /T >> "%fsi_dir%\iis_acl2.txt"
		cacls *.shtm /T >> "%fsi_dir%\iis_acl2.txt"
		cacls *.shtml /T >> "%fsi_dir%\iis_acl2.txt"
		cacls *.txt /T >> "%fsi_dir%\iis_acl2.txt"
		cacls *.gif /T >> "%fsi_dir%\iis_acl2.txt"
		cacls *.jpg /T >> "%fsi_dir%\iis_acl2.txt"
		cacls *.html /T >> "%fsi_dir%\iis_acl2.txt"
		echo. >> "%fsi_dir%\iis_acl2.txt"

		ATTRIB /s | findstr .lnk >> %fsi_outfile%
		echo. >> %fsi_outfile%
)

cd /d "%fsi_dir%"


%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-054^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


echo Refer to iis config file >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-055^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


echo Refer to iis config file >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%




%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-056^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


echo Refer to iis config file >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-057^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


echo cmd# type "%fsi_dir%\iis_acl.txt" >> %fsi_outfile%

type "%fsi_dir%\iis_acl.txt" >> %fsi_outfile%

echo cmd# type "%fsi_dir%\iis_acl2.txt" >> %fsi_outfile%

type "%fsi_dir%\iis_acl2.txt" >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%





%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-058^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


echo Refer to iis config file >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-059^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


echo cmd# reg query "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters" /v SSIEnableCmdDirective >> %fsi_outfile%
echo. >> %fsi_outfile%
FOR /F "delims=" %%i IN ('reg query "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters" /v SSIEnableCmdDirective') DO SET fsi_result=%%i
if defined fsi_result (
	reg query "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters" /v SSIEnableCmdDirective >> %fsi_outfile%
) else (
	echo Registry key value not found: "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters" /v SSIEnableCmdDirective >> %fsi_outfile%
)
SET fsi_result=


%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-060^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


echo Check if tomcat service is running (from tasklist) >> %fsi_outfile%

echo cmd# type %%CATALINA_HOME%%\conf\tomcat-users.xml >> %fsi_outfile%
echo. >> %fsi_outfile%

type %%CATALINA_HOME%%\conf\tomcat-users.xml >> %fsi_outfile%

%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-063^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


echo cmd# sc query dns >> %fsi_outfile%

sc query dns >> %fsi_outfile%

echo cmd# reg query HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters /v NoRecursion >> %fsi_outfile%
echo. >> %fsi_outfile%
FOR /F "delims=" %%i IN ('reg query HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters /v NoRecursion') DO SET fsi_result=%%i
if defined fsi_result (
	reg query HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters /v NoRecursion >> %fsi_outfile%
) else (
	echo Registry key value not found: HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters /v NoRecursion >> %fsi_outfile%
)
SET fsi_result=

echo cmd# reg query HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters >> %fsi_outfile%
echo. >> %fsi_outfile%
FOR /F "delims=" %%i IN ('reg query HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters') DO SET fsi_result=%%i
if defined fsi_result (
	reg query HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters >> %fsi_outfile%
) else (
	echo Registry key value not found: HKLM\SYSTEM\CurrentControlSet\Services\DNS\Parameters >> %fsi_outfile%
)
SET fsi_result=


%fsi_outputed%
%fsi_dumped%





%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-066^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


echo cmd# sc query dns >> %fsi_outfile%

sc query dns >> %fsi_outfile%

echo cmd# reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" /s >> %fsi_outfile%
echo. >> %fsi_outfile%
FOR /F "delims=" %%i IN ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" /s') DO SET fsi_result=%%i
if defined fsi_result (
	reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" /s >> %fsi_outfile%
) else (
	echo Registry key value not found: "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\DNS Server\Zones" /s >> %fsi_outfile%
)
SET fsi_result=

echo cmd# reg query "HKLM\System\CurrentControlSet\Services\DNS\Zones" /s >> %fsi_outfile%
echo. >> %fsi_outfile%
FOR /F "delims=" %%i IN ('reg query "HKLM\System\CurrentControlSet\Services\DNS\Zones" /s') DO SET fsi_result=%%i
if defined fsi_result (
	reg query "HKLM\System\CurrentControlSet\Services\DNS\Zones" /s >> %fsi_outfile%
) else (
	echo Registry key value not found: "HKLM\System\CurrentControlSet\Services\DNS\Zones" /s >> %fsi_outfile%
)
SET fsi_result=


%fsi_outputed%
%fsi_dumped%





%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-067^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


echo cmd# reg query "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch" >> %fsi_outfile%

reg query "HKLM\SYSTEM\CurrentControlSet\Services\W3SVC\Parameters\ADCLaunch" >> %fsi_outfile%

echo. >> %fsi_outfile%


echo cmd# type %%SystemRoot%%\msdfmap.ini ^>^> output_file.xml >> %fsi_outfile%
echo. >> %fsi_outfile%

type %SystemRoot%\msdfmap.ini >> %fsi_outfile% 
echo. >> %fsi_outfile%

%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-068^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


REG SAVE HKLM\SAM "%fsi_dir%\%computername%.sam"
REG SAVE HKLM\SYSTEM "%fsi_dir%\%computername%.system"
REG SAVE HKLM\SECURITY "%fsi_dir%\%computername%.security"

echo Refer to password crack result >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%


%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-069^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# secedit /EXPORT /CFG securitypolicy >> %fsi_outfile%
echo. >> %fsi_outfile%
secedit /EXPORT /CFG "%fsi_dir%\sec.txt"
timeout 2

echo Refer to security policy file >> %fsi_outfile%

%fsi_outputed%
%fsi_dumped%


%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-071^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# net user (ALL_USERS) >> %fsi_outfile%
FOR /F "tokens=1 skip=4" %%i IN ('net user') DO net user %%i >> %fsi_outfile% 2>nul
FOR /F "tokens=2 skip=4" %%i IN ('net user') DO net user %%i >> %fsi_outfile% 2>nul
FOR /F "tokens=3 skip=4" %%i IN ('net user') DO net user %%i >> %fsi_outfile% 2>nul

%fsi_outputed%
%fsi_dumped%


%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-072^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# net localgroup Administrators >> %fsi_outfile%
echo. >> %fsi_outfile%
net localgroup Administrators >> %fsi_outfile%

%fsi_outputed%
%fsi_dumped%


%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-073^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# net localgroup Administrators >> %fsi_outfile%
echo. >> %fsi_outfile%
net localgroup Administrators >> %fsi_outfile%

%fsi_outputed%
%fsi_dumped%


%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-074^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# net user (ALL_USERS) >> %fsi_outfile%
FOR /F "tokens=1 skip=4" %%i IN ('net user') DO net user %%i >> %fsi_outfile% 2>nul
FOR /F "tokens=2 skip=4" %%i IN ('net user') DO net user %%i >> %fsi_outfile% 2>nul
FOR /F "tokens=3 skip=4" %%i IN ('net user') DO net user %%i >> %fsi_outfile% 2>nul

%fsi_outputed%
%fsi_dumped%


%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-077^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# type sec.txt ^| Find /I ClearTextPassword >> %fsi_outfile%
echo. >> %fsi_outfile%

type "%fsi_dir%\sec.txt" | Find /I "ClearTextPassword" >> %fsi_outfile%

%fsi_outputed%
%fsi_dumped%


%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-078^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# net user guest >> %fsi_outfile%
echo. >> %fsi_outfile%
net user guest >> %fsi_outfile%

%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-079^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# reg query ^"HKLM\SYSTEM\CurrentControlSet\Control\Lsa^" /v everyoneincludesanonymous >> %fsi_outfile%
echo. >> %fsi_outfile%
FOR /F "delims=" %%i IN ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v everyoneincludesanonymous') DO SET fsi_result=%%i
if defined fsi_result (
	reg query "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v everyoneincludesanonymous >> %fsi_outfile%
) else (
	echo Registry key value not found: "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v everyoneincludesanonymous >> %fsi_outfile%
)
SET fsi_result=


%fsi_outputed%
%fsi_dumped%




%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-080^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# reg query ^"HKLM\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers^" /v AddPrinterDrivers >> %fsi_outfile%
echo. >> %fsi_outfile%
FOR /F "delims=" %%i IN ('reg query "HKLM\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers') DO SET fsi_result=%%i
if defined fsi_result (
	reg query "HKLM\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers >> %fsi_outfile%
) else (
	echo Registry key value not found: "HKLM\System\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" /v AddPrinterDrivers >> %fsi_outfile%
)
SET fsi_result=


%fsi_outputed%
%fsi_dumped%




%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-090^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# sc query RemoteRegistry >> %fsi_outfile%
echo. >> %fsi_outfile%
sc query RemoteRegistry >> %fsi_outfile%


echo cmd# reg query HKLM\System\CurrentControlSet\Control\SecurePipeServers >> %fsi_outfile%
echo. >> %fsi_outfile%
FOR /F "delims=" %%i IN ('reg query HKLM\System\CurrentControlSet\Control\SecurePipeServers') DO SET fsi_result=%%i
if defined fsi_result (
	reg query HKLM\System\CurrentControlSet\Control\SecurePipeServers >> %fsi_outfile%
) else (
	echo Registry key value not found: HKLM\System\CurrentControlSet\Control\SecurePipeServers >> %fsi_outfile%
)
SET fsi_result=

%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-097^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# type "%fsi_dir%\ftp_stat.txt" >> %fsi_outfile%
type "%fsi_dir%\ftp_stat.txt" >> %fsi_outfile%

if exist "%~dp0vbscripts\ftp_path.vbs" (
	cscript //nologo %fsi_vbs%ftp_path.vbs > "%fsi_dir%\ftp_list.txt"
) else (
	echo VBS helper missing: %~dp0vbscripts\ftp_path.vbs > "%fsi_dir%\ftp_list.txt"
)

FOR /F "tokens=1 delims=" %%i in ('type "%fsi_dir%\ftp_list.txt"') do cacls "%%i" >> %fsi_outfile%

echo cmd# type %%fsi_dir%%\iis_site_list2.txt ^>^> output_file.xml >> %fsi_outfile%
type "%fsi_dir%\iis_site_list2.txt" >> %fsi_outfile%

SET fsi_drive=%SystemRoot:~0,2%
FOR /F "tokens=2 delims=(" %%i in ('type "%fsi_dir%\iis_site_list2.txt"') do (
		SET fsi_var=%%i
		SET fsi_var=!fsi_var:~13,-1!
		SET fsi_var=!fsi_var:%%SystemDrive%%=%fsi_drive%!
		SET fsi_var="!fsi_var!"
		cd /d !fsi_var!
		cacls !fsi_var! >> %fsi_outfile%
		echo. >> %fsi_outfile%
)
cd /d "%fsi_dir%"


%fsi_outputed%
%fsi_dumped%


%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-098^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# cacls %systemroot%\system32\config\SAM >> %fsi_outfile%
echo. >> %fsi_outfile%
cacls %systemroot%\system32\config\SAM >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-101^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# at >> %fsi_outfile%
at >> %fsi_outfile%

echo cmd# schtasks >> %fsi_outfile%
schtasks >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-102^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# cacls (ALL_USERS) >> %fsi_outfile%
FOR /F "tokens=1 skip=4" %%i IN ('net user') DO cacls "C:\Users\%%i" >> %fsi_outfile% 2>nul
FOR /F "tokens=2 skip=4" %%i IN ('net user') DO cacls "C:\Users\%%i" >> %fsi_outfile% 2>nul
FOR /F "tokens=3 skip=4" %%i IN ('net user') DO cacls "C:\Users\%%i" >> %fsi_outfile% 2>nul

FOR /F "tokens=1 skip=4" %%i IN ('net user') DO cacls "C:\Documents and Settings\%%i" >> %fsi_outfile% 2>nul
FOR /F "tokens=2 skip=4" %%i IN ('net user') DO cacls "C:\Documents and Settings\%%i" >> %fsi_outfile% 2>nul
FOR /F "tokens=3 skip=4" %%i IN ('net user') DO cacls "C:\Documents and Settings\%%i" >> %fsi_outfile% 2>nul

%fsi_outputed%
%fsi_dumped%




%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-103^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%
echo cmd# REG QUERY ^"HKLM\SYSTEM\CurrentControlSet\Control\Lsa^" /v LmCompatibilityLevel >> %fsi_outfile%

FOR /F "delims=" %%i IN ('REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel') DO SET fsi_result=%%i
if defined fsi_result (
	REG QUERY "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel >> %fsi_outfile%
) else (
	echo Registry key value not found: "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v LmCompatibilityLevel >> %fsi_outfile%
)
SET fsi_result=

%fsi_outputed%
%fsi_dumped%




%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-104^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# REG QUERY ^"HKLM\System\CurrentControlSet\Services\Netlogon\Parameters^" /v RequireSignOrSeal >> %fsi_outfile%

FOR /F "delims=" %%i IN ('REG QUERY "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v RequireSignOrSeal') DO SET fsi_result=%%i
if defined fsi_result (
	REG QUERY "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v RequireSignOrSeal >> %fsi_outfile%
) else (
	echo Registry key value not found: "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v RequireSignOrSeal  >> %fsi_outfile%
)
SET fsi_result=

echo. >> %fsi_outfile%

echo cmd# REG QUERY ^"HKLM\System\CurrentControlSet\Services\Netlogon\Parameters^" /v SealSecureChannel >> %fsi_outfile%

FOR /F "delims=" %%i IN ('REG QUERY "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v SealSecureChannel') DO SET fsi_result=%%i
if defined fsi_result (
	REG QUERY "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v SealSecureChannel >> %fsi_outfile%
) else (
	echo Registry key value not found: "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v SealSecureChannel >> %fsi_outfile%
)
SET fsi_result=

echo. >> %fsi_outfile%

echo cmd# REG QUERY ^"HKLM\System\CurrentControlSet\Services\Netlogon\Parameters^" /v SignSecureChannel >> %fsi_outfile%

FOR /F "delims=" %%i IN ('REG QUERY "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v SignSecureChannel') DO SET fsi_result=%%i
if defined fsi_result (
	REG QUERY "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v SignSecureChannel >> %fsi_outfile%
) else (
	echo Registry key value not found: "HKLM\System\CurrentControlSet\Services\Netlogon\Parameters" /v SignSecureChannel >> %fsi_outfile%
)
SET fsi_result=

%fsi_outputed%
%fsi_dumped%




%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-105^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# REG QUERY ^"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run^" >> %fsi_outfile%

FOR /F "delims=" %%i IN ('REG QUERY "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"') DO SET fsi_result=%%i
if defined fsi_result (
	REG QUERY "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" >> %fsi_outfile%
) else (
	echo Registry key value not found: "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"  >> %fsi_outfile%
)
SET fsi_result=


%fsi_outputed%
%fsi_dumped%





%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-109^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# secedit /EXPORT /CFG securitypolicy >> %fsi_outfile%

echo Refer to security policy file >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-110^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# cacls %systemroot%\system32\config >> %fsi_outfile%
echo. >> %fsi_outfile%
cacls %systemroot%\system32\config >> %fsi_outfile%

%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-111^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Application" /v RestrictGuestAccess >> %fsi_outfile%
echo cmd# reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security" /v RestrictGuestAccess >> %fsi_outfile%
echo cmd# reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\System" /v RestrictGuestAccess >> %fsi_outfile%

echo. >> %fsi_outfile%
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Application" /v RestrictGuestAccess >> %fsi_outfile%
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\Security" /v RestrictGuestAccess >> %fsi_outfile%
reg query "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Eventlog\System" /v RestrictGuestAccess >> %fsi_outfile%

%fsi_outputed%
%fsi_dumped%




%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-113^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# type sec.txt ^| Find /I SeSecurityPrivilege >> %fsi_outfile%
echo. >> %fsi_outfile%

type "%fsi_dir%\sec.txt" | Find /I "SeSecurityPrivilege" >> %fsi_outfile%

echo cmd# wmic useraccount get name,sid >> %fsi_outfile%
echo. >> %fsi_outfile%
wmic useraccount get name,sid | more >> %fsi_outfile%

echo cmd# wmic group get name,sid >> %fsi_outfile%
echo. >> %fsi_outfile%
wmic group get name,sid | more >> %fsi_outfile%

%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-115^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


echo Interview Check >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-116^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


echo cmd# reg query HKLM\system\currentcontrolset\control\lsa /v crashonauditfail >> %fsi_outfile%
echo. >> %fsi_outfile%

FOR /F "delims=" %%i IN ('reg query HKLM\system\currentcontrolset\control\lsa /v crashonauditfail') DO SET fsi_result=%%i
if defined fsi_result (
	reg query HKLM\system\currentcontrolset\control\lsa /v crashonauditfail >> %fsi_outfile%
) else (
	echo Registry key value not found: HKLM\system\currentcontrolset\control\lsa\crashonauditfail >> %fsi_outfile%
)
SET fsi_result=

%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-117^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


echo cmd# systeminfo >> %fsi_outfile%
echo. >> %fsi_outfile%
systeminfo >> %fsi_outfile%

echo cmd# wmic os get servicepackmajorversion >> %fsi_outfile%
echo. >> %fsi_outfile%
wmic os get servicepackmajorversion | more >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%


%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-119^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


echo Interview Check >> %fsi_outfile%
echo. >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-120^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


echo cmd# wmic qfe list >> %fsi_outfile%
echo. >> %fsi_outfile%
wmic qfe list | more >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-123^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


echo cmd# reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v DontDisplayLastUserName >> %fsi_outfile%
echo. >> %fsi_outfile%
FOR /F "delims=" %%i IN ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v DontDisplayLastUserName') DO SET fsi_result=%%i
if defined fsi_result (
	reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v DontDisplayLastUserName >> %fsi_outfile%
) else (
	echo Registry key value not found: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\DontDisplayLastUserName >> %fsi_outfile%
)
SET fsi_result=

%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-124^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


echo cmd# reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon /v cachedlogonscount >> %fsi_outfile%
echo. >> %fsi_outfile%
FOR /F "delims=" %%i IN ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v cachedlogonscount') DO SET fsi_result=%%i
if defined fsi_result (
	reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v cachedlogonscount >> %fsi_outfile%
) else (
	echo Registry key value not found: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\cachedlogonscount >> %fsi_outfile%
)
SET fsi_result=

%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-125^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


echo cmd# reg query "HKEY_CURRENT_USER\Control Panel\desktop" /v ScreenSaveActive >> %fsi_outfile%
echo. >> %fsi_outfile%
FOR /F "delims=" %%i IN ('reg query "HKEY_CURRENT_USER\Control Panel\desktop" /v ScreenSaveActive') DO SET fsi_result=%%i
if defined fsi_result (
	reg query "HKEY_CURRENT_USER\Control Panel\desktop" /v ScreenSaveActive >> %fsi_outfile%
) else (
	echo Registry key value not found: HKEY_CURRENT_USER\Control Panel\desktop\ScreenSaveActive >> %fsi_outfile%
)
SET fsi_result=

echo cmd# reg query "HKEY_CURRENT_USER\Control Panel\desktop" /v ScreenSaveTimeOut >> %fsi_outfile%
echo. >> %fsi_outfile%
FOR /F "delims=" %%i IN ('reg query "HKEY_CURRENT_USER\Control Panel\desktop" /v ScreenSaveTimeOut') DO SET fsi_result=%%i
if defined fsi_result (
	reg query "HKEY_CURRENT_USER\Control Panel\desktop" /v ScreenSaveTimeOut >> %fsi_outfile%
) else (
	echo Registry key value not found: HKEY_CURRENT_USER\Control Panel\desktop\ScreenSaveTimeOut >> %fsi_outfile%
)
SET fsi_result=

echo cmd# reg query "HKEY_CURRENT_USER\Control Panel\desktop" /v ScreenSaverIsSecure >> %fsi_outfile%
echo. >> %fsi_outfile%
FOR /F "delims=" %%i IN ('reg query "HKEY_CURRENT_USER\Control Panel\desktop" /v ScreenSaverIsSecure') DO SET fsi_result=%%i
if defined fsi_result (
	reg query "HKEY_CURRENT_USER\Control Panel\desktop" /v ScreenSaverIsSecure >> %fsi_outfile%
) else (
	echo Registry key value not found: HKEY_CURRENT_USER\Control Panel\desktop\ScreenSaverIsSecure >> %fsi_outfile%
)
SET fsi_result=

%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-126^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon\AutoAdminLogon >> %fsi_outfile%
echo cmd# reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon\DefaultUserName >> %fsi_outfile%
echo cmd# reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon\DefaultPassword >> %fsi_outfile%

echo. >> %fsi_outfile%
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" /v AutoAdminLogon >> %fsi_outfile%
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" /v DefaultUserName >> %fsi_outfile%
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\WinLogon" /v DefaultPassword >> %fsi_outfile%

%fsi_outputed%
%fsi_dumped%




%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-127^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


echo cmd# reg query HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters\AccountLockout >> %fsi_outfile%
echo. >> %fsi_outfile%
FOR /F "delims=" %%i IN ('reg query HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters\AccountLockout') DO SET fsi_result=%%i
if defined fsi_result (
	reg query HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters\AccountLockout >> %fsi_outfile%
) else (
	echo Registry key value not found: HKLM\SYSTEM\CurrentControlSet\Services\RemoteAccess\Parameters\AccountLockout >> %fsi_outfile%
)
SET fsi_result=

echo cmd# net accounts >> %fsi_outfile%
echo. >> %fsi_outfile%
net accounts >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-163^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


echo cmd# reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v LegalNoticeCaption >> %fsi_outfile%
echo. >> %fsi_outfile%
FOR /F "delims=" %%i IN ('reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v LegalNoticeCaption') DO SET fsi_result=%%i
if defined fsi_result (
	reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v LegalNoticeCaption >> %fsi_outfile%
) else (
	echo Registry key value not found: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon /v LegalNoticeCaption >> %fsi_outfile%
)
SET fsi_result=

echo cmd# reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v LegalNoticeText >> %fsi_outfile%
echo. >> %fsi_outfile%
FOR /F "delims=" %%i IN ('reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v LegalNoticeText') DO SET fsi_result=%%i
if defined fsi_result (
	reg query "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon" /v LegalNoticeText >> %fsi_outfile%
) else (
	echo Registry key value not found: HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon /v LegalNoticeText >> %fsi_outfile%
)
SET fsi_result=


echo cmd# reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\policies\system" /v LegalNoticeCaption >> %fsi_outfile%
echo. >> %fsi_outfile%
FOR /F "delims=" %%i IN ('reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\policies\system" /v LegalNoticeCaption') DO SET fsi_result=%%i
if defined fsi_result (
	reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\policies\system" /v LegalNoticeCaption >> %fsi_outfile%
) else (
	echo Registry key value not found: HKLM\Software\Microsoft\Windows\CurrentVersion\policies\system /v LegalNoticeCaption >> %fsi_outfile%
)
SET fsi_result=

echo cmd# reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\policies\system" /v LegalNoticeText >> %fsi_outfile%
echo. >> %fsi_outfile%
FOR /F "delims=" %%i IN ('reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\policies\system" /v LegalNoticeText') DO SET fsi_result=%%i
if defined fsi_result (
	reg query "HKLM\Software\Microsoft\Windows\CurrentVersion\policies\system" /v LegalNoticeText >> %fsi_outfile%
) else (
	echo Registry key value not found: HKLM\Software\Microsoft\Windows\CurrentVersion\policies\system /v LegalNoticeText >> %fsi_outfile%
)
SET fsi_result=


%fsi_outputed%
%fsi_dumped%




%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-128^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


echo cmd# wmic logicaldisk get caption,filesystem,description,providername,drivetype,volumename >> %fsi_outfile%
echo. >> %fsi_outfile%
wmic logicaldisk get caption,filesystem,description,freespace,providername,drivetype,volumename | more >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%




%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-129^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


echo Refer to Process List >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-136^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v ShutdownWithoutLogon >> %fsi_outfile%
echo. >> %fsi_outfile%
FOR /F "delims=" %%i IN ('reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v ShutdownWithoutLogon') DO SET fsi_result=%%i
if defined fsi_result (
	reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v ShutdownWithoutLogon >> %fsi_outfile%
) else (
	echo Registry key value not found: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system\ShutdownWithoutLogon >> %fsi_outfile%
)
SET fsi_result=


%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-137^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# type sec.txt ^| Find /I SeNetworkLogonRight >> %fsi_outfile%
echo. >> %fsi_outfile%
type "%fsi_dir%\sec.txt" | Find /I "SeNetworkLogonRight" >> %fsi_outfile%
echo. >> %fsi_outfile%

echo cmd# type sec.txt ^| Find /I SeDenyNetworkLogonRight >> %fsi_outfile%
echo. >> %fsi_outfile%
type "%fsi_dir%\sec.txt" | Find /I "SeDenyNetworkLogonRight" >> %fsi_outfile%

echo cmd# wmic useraccount get name,sid >> %fsi_outfile%
echo. >> %fsi_outfile%
wmic useraccount get name,sid | more >> %fsi_outfile%

echo cmd# wmic group get name,sid >> %fsi_outfile%
echo. >> %fsi_outfile%
wmic group get name,sid | more >> %fsi_outfile%

%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-138^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# type sec.txt ^| Find /I SeBackupPrivilege >> %fsi_outfile%
echo. >> %fsi_outfile%
type "%fsi_dir%\sec.txt" | Find /I "SeBackupPrivilege" >> %fsi_outfile%
echo. >> %fsi_outfile%

echo cmd# type sec.txt ^| Find /I SeRestorePrivilege >> %fsi_outfile%
echo. >> %fsi_outfile%
type "%fsi_dir%\sec.txt" | Find /I "SeRestorePrivilege" >> %fsi_outfile%

echo cmd# wmic useraccount get name,sid >> %fsi_outfile%
echo. >> %fsi_outfile%
wmic useraccount get name,sid | more >> %fsi_outfile%

echo cmd# wmic group get name,sid >> %fsi_outfile%
echo. >> %fsi_outfile%
wmic group get name,sid | more >> %fsi_outfile%

%fsi_outputed%
%fsi_dumped%




%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-139^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# type sec.txt ^| Find /I SeTakeOwnershipPrivilege >> %fsi_outfile%
echo. >> %fsi_outfile%
type "%fsi_dir%\sec.txt" | Find /I "SeTakeOwnershipPrivilege" >> %fsi_outfile%
echo. >> %fsi_outfile%

echo cmd# wmic useraccount get name,sid >> %fsi_outfile%
wmic useraccount get name,sid | more >> %fsi_outfile%
echo. >> %fsi_outfile%

echo cmd# wmic group get name,sid >> %fsi_outfile%
echo. >> %fsi_outfile%
wmic group get name,sid | more >> %fsi_outfile%

%fsi_outputed%
%fsi_dumped%




%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-140^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# reg query HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon /v AllocateDASD >> %fsi_outfile%
echo. >> %fsi_outfile%
FOR /F "delims=" %%i IN ('reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateDASD') DO SET fsi_result=%%i
if defined fsi_result (
	reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AllocateDASD >> %fsi_outfile%
) else (
	echo Registry key value not found: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon /v AllocateDASD >> %fsi_outfile%
)
SET fsi_result=

%fsi_outputed%
%fsi_dumped%




%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-141^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# reg query HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile /v EnableFirewall >> %fsi_outfile%
echo. >> %fsi_outfile%
FOR /F "delims=" %%i IN ('reg query "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v EnableFirewall') DO SET fsi_result=%%i
if defined fsi_result (
	reg query "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile" /v EnableFirewall >> %fsi_outfile%
) else (
	echo Registry key value not found: HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile /v EnableFirewall >> %fsi_outfile%
)
SET fsi_result=

echo. >> %fsi_outfile%
echo cmd# reg query HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile /v EnableFirewall >> %fsi_outfile%
echo. >> %fsi_outfile%
FOR /F "delims=" %%i IN ('reg query "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v EnableFirewall') DO SET fsi_result=%%i
if defined fsi_result (
	reg query "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile" /v EnableFirewall >> %fsi_outfile%
) else (
	echo Registry key value not found: HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile /v EnableFirewall >> %fsi_outfile%
)
SET fsi_result=

echo. >> %fsi_outfile%
echo cmd# netsh firewall show state >> %fsi_outfile%
echo. >> %fsi_outfile%
netsh firewall show state >> %fsi_outfile%


echo. >> %fsi_outfile%
echo cmd# netsh advfirewall show allprofiles >> %fsi_outfile%
echo. >> %fsi_outfile%
netsh advfirewall show allprofiles >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-150^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# type sec.txt ^| Find /I SeInteractiveLogonRight >> %fsi_outfile%
echo. >> %fsi_outfile%

type "%fsi_dir%\sec.txt" | Find /I "SeInteractiveLogonRight" >> %fsi_outfile%

%fsi_outputed%
%fsi_dumped%


%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-152^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# type sec.txt ^| Find /I SeRemoteInteractiveLogonRight >> %fsi_outfile%
echo. >> %fsi_outfile%

type "%fsi_dir%\sec.txt" | Find /I "SeRemoteInteractiveLogonRight" >> %fsi_outfile%

%fsi_outputed%
%fsi_dumped%


%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-156^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# reg query HKLM\system\currentcontrolset\services\lanmanserver\parameters\autodisconnect >> %fsi_outfile%

echo. >> %fsi_outfile%
reg query "HKLM\system\currentcontrolset\services\lanmanserver\parameters" /v autodisconnect >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%






%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>SRV-158^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# netstat -an ^| findstr :23 >> %fsi_outfile%

netstat -an | findstr :23 >> %fsi_outfile%

echo. >> %fsi_outfile%
echo cmd# sc query Tlntsvr >> %fsi_outfile%

sc query Tlntsvr >> %fsi_outfile%
%fsi_outputed%
%fsi_dumped%









%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>IIS_STATE^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

FOR /F "delims=" %%i IN ('reg query "HKLM\SOFTWARE\Microsoft\InetStp" /v SetupString') DO SET fsi_result=%%i
if defined fsi_result (
	reg query "HKLM\SOFTWARE\Microsoft\InetStp" /v SetupString >> %fsi_outfile%
) else (
	echo Registry key value not found: HKLM\SOFTWARE\Microsoft\InetStp /v SetupString >> %fsi_outfile%
)

echo cmd# type "%fsi_dir%\ftp_stat.txt" ^>^> output_file.xml >> %fsi_outfile%
type "%fsi_dir%\ftp_stat.txt" >> %fsi_outfile%

echo cmd# type "%fsi_dir%\web_stat.txt" ^>^> output_file.xml >> %fsi_outfile%
type "%fsi_dir%\web_stat.txt" >> %fsi_outfile%

echo cmd# appcmd list site ^>^> output_file.xml >> %fsi_outfile%
%systemroot%\System32\inetsrv\appcmd list site >> %fsi_outfile%

echo cmd# sc query iisadmin >> %fsi_outfile%
echo. >> %fsi_outfile%

sc query iisadmin >> %fsi_outfile%
echo. >> %fsi_outfile%

echo cmd# sc query w3svc >> %fsi_outfile%
echo. >> %fsi_outfile%

sc query w3svc >> %fsi_outfile%
echo. >> %fsi_outfile%

echo cmd# sc query was >> %fsi_outfile%
echo. >> %fsi_outfile%

sc query was >> %fsi_outfile%
echo. >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>IIS_CONFIG^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# type %%SystemRoot%%\System32\Inetsrv\metabase.xml ^>^> output_file.xml >> %fsi_outfile%
type %SystemRoot%\System32\Inetsrv\metabase.xml >> %fsi_outfile%

echo cmd# type %%windir%%\system32\inetsrv\config\applicationHost.config ^>^> output_file.xml >> %fsi_outfile%
type %windir%\system32\inetsrv\config\applicationHost.config >> %fsi_outfile%  

%fsi_outputed%
%fsi_dumped%


%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>Secpol^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# secedit /EXPORT /CFG >> %fsi_outfile%
type "%fsi_dir%\sec.txt" >> %fsi_outfile%

%fsi_outputed%
%fsi_dumped%


%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>Process^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# tasklist >> %fsi_outfile%
tasklist >> %fsi_outfile%

%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>Service^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


echo cmd# sc query >> %fsi_outfile%
sc query >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%


%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>Netstat^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


echo cmd# netstat -an >> %fsi_outfile%
netstat -an >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>ipconfig^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


echo cmd# ipconfig /all >> %fsi_outfile%
ipconfig /all >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%



%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>Internet^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%

echo cmd# Internet Checking >> %fsi_outfile%

if exist "%~dp0vbscripts\internet.vbs" (
	cscript //nologo %fsi_vbs%internet.vbs > "%fsi_dir%\internet_stat.txt"
) else (
	echo VBS helper missing: %~dp0vbscripts\internet.vbs > "%fsi_dir%\internet_stat.txt"
)

echo. >> %fsi_outfile%

echo cmd# type "%fsi_dir%\internet_stat.txt" >> %fsi_outfile%

echo. >> %fsi_outfile%

type "%fsi_dir%\internet_stat.txt" >> %fsi_outfile%

echo. >> %fsi_outfile%

echo cmd# Ping Test >> %fsi_outfile%

echo. >> %fsi_outfile%

echo cmd# ping www.google.com >> %fsi_outfile%
ping www.google.com >> %fsi_outfile%

echo cmd# ping 8.8.8.8 >> %fsi_outfile%
ping 8.8.8.8 >> %fsi_outfile%


%fsi_outputed%
%fsi_dumped%




%fsi_dumpst%
%fsi_itemst%
echo 				^<id^>Encoding^</id^> >> %fsi_outfile%
%fsi_itemed%
%fsi_outputst%


FSI_hangulTest >> %fsi_outfile% 2>&1


%fsi_outputed%
%fsi_dumped%


::Delete intermediate files
timeout 2
del "%fsi_dir%\ftp_list.txt"
del "%fsi_dir%\ftp_stat.txt"
del "%fsi_dir%\web_stat.txt"
del "%fsi_dir%\sec.txt"
del "%fsi_dir%\iis_acl.txt"
del "%fsi_dir%\iis_acl2.txt"
del "%fsi_dir%\iis_site_list.txt"
del "%fsi_dir%\iis_site_list2.txt"
del "%fsi_dir%\internet_stat.txt"


::Result end
echo 	^</results^> >> %fsi_outfile%
echo ^</script^> >> %fsi_outfile%


::Zipping the result
if exist "%~dp0vbscripts\zip.vbs" (
	cscript %fsi_vbs%zip.vbs "%fsi_dir%\" "%fsi_dir%.zip"
) else (
	echo VBS helper missing: %~dp0vbscripts\zip.vbs
)



echo "End of Process"
echo "FSI Server scan successfully finished^!^!"

REM AI automation mode: do not pause on remote execution.


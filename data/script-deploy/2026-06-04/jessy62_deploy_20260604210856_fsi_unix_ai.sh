#!/bin/sh

clear

### Shell Encoding(S) ###
ORILANG=`echo $LANG | egrep -v "^$" 2>&1`
ORILANG_UTF=`echo $LANG | egrep -i "utf" | egrep -v "^$" 2>&1`
ORILANG_UTF1=`echo $LANG | awk -F"." '{ print $1 }' | egrep "^[A-Z]" | egrep -v "^$" 2>&1`
ORILANG_EUC=`echo $LANG | egrep -i "euc" | egrep -v "^$" 2>&1`
LANG=C
export LANG
if [ $ORILANG ]; then
	#echo "$ORILANG"
	if [ "$ORILANG_UTF" -o "$ORILANG_UTF1" ]; then
		CENCODING="UTF-8"
	else
		CENCODING="EUC-KR"
	fi	
else
	CENCODING="EUC-KR"
fi

### Shell Encoding(E) ###

## isac.sh
# 금융ISAC 서버 취약점 분석 스크립트
# http://www.kfisac.or.kr
# Version 2018.1.4
# 미래부 선택 항목을 포함한 버전
## Notice
#	실행 시 덤프 항목이 리스팅되고 마지막으로 시간이 나와야 정상 종료된것임
#
## Error 1
#	다음과 같은 에러 발생 시 첫행의 #!/bin/sh 부분을 #!/bin/bash 등으로 변경후 실행 (SUN)
#		./isac.sh: test: 인수가 예상됨(argument expected)
#
## Error 2
#	바이너리 모드로 전송되어 각 행의 끝에 '^M'이 붙어 있는 경우 vi에서
#		:%s/^M//g 입력 (^M 입력은 CTRL+V CTRL+M)
#
## Error 3
# 	실행시 syntax error near unexpected token 에러 발생시 아래 명령어를 실행 하여
# 	파일 포맷을 Dos/Windows -> Unix로 변환 (line endings 차이)
# 	dos2unix [파일이름]
#-----------------------------------------------------------------------------------

### Init(S) ###
set +x
START=`date`
USER=`id | awk -F"(" '{ print $2 }' | awk -F")" '{ print $1 }'`
HOSTNAME=`hostname`
DATE=`date +%Y%m%d`
UNAME=`uname -a`
### Init(S) ###

### 2016.1 Add/Modify Source(S) ###
### OS Part(S) ###
OS=`uname`
case "$OS" in
Linux|AIX|HP-UX|SunOS )
	break
	;;
*)
	echo "input your OS(Linux or AIX or HP-UX or SunOS): "
	read temp
	OS=`echo "$temp"`
	;;
esac
if [ $OS="Linux" -o  $OS="AIX" -o $OS="HP-UX" -o $OS="SunOS" ]; then
	echo "uname is $OS"
else
	fDie "uname is NULL"
fi
### OS Part(E) ###

### OutFile Define(S) ###
OS_VER=`uname -a | awk '{print $3}'`
if [ $OS = 'Linux' ]; then
	OS_INFO=`cat /etc/*-release`
else
	OS_INFO=`uname -a`
fi
OUT="$HOSTNAME-s-$DATE.xml"
VERSION="2018v1"
### OutFile Define(E) ###


#------------------------------------------------------------
ROOT_HOME=`grep root /etc/passwd | awk -F":" '{print $6}'`
#------------------------------------------------------------
# Default Value Setting
CMD_CPUINFO="cat /proc/cpuinfo"
CMD_CPUSTAT="cat /proc/stat"
CMD_IOSTAT=""
CMD_VMSTAT="cat /proc/meminfo"
CMD_PATCHINFO="rpm -qa -i"
CMD_INTERFACETABLE=`netstat -in`
CMD_NICINFO="ifconfig -a"

CMD_LASTLOG="perl -e 'alarm shift @ARGV; exec @ARGV' 180 lastlog"
CMD_PWCK="pwck"
CMD_GRPCK="grpck -r"
CMD_TELNETBANNER="cat /etc/issue /etc/issue.net  |  sed \"s/&/\&amp;/g\" |  sed \"s/</\&lt;/g\" | sed \"s/>/\&gt;/g\" "
CMD_DUMASK="grep -i umask /etc/login.defs /etc/profile"
CMD_RUMASK="grep -i umask $ROOT_HOME/.profile $ROOT_HOME/.*shrc $ROOT_HOME/.login $ROOT_HOME/.bash_profile"
#CMD_SUGROUP="grep wheel /etc/pam.d/su"
CMD_SUGROUP="cat /etc/pam.d/su | egrep -i \"(use\_uid|group\=)\" | egrep -i \"pam_wheel.so\" | grep -v \"trust\""
CMD_SULOG="grep rootok /etc/pam.d/su"
CMD_ROUTE="cat /proc/sys/net/ipv4/ip_forward"
CMD_ROUTE2="cat /proc/sys/net/ipv4/conf/default/accept_source_route"
CMD_CRONLOG=""
CMD_LOGIN="grep FAILLOG_ENAB /etc/login.defs"
CMD_LOGIN2="grep LOG_UNKFAIL_ENAB /etc/login.defs"
CMD_LOGIN3="grep LOG_OK_LOGINS /etc/login.defs"
CMD_LOGIN4="grep LOGIN_RETRIES /etc/login.defs"
CMD_LOGIN5="grep LOGIN_TIMEOUT /etc/login.defs"

CMD_INETD_LOG="egrep 'log_Type|log_on_success|log_on_failure' \
	/etc/xinetd.conf /etc/xinetd.d/*"
CMD_RLOGIN=""
#CMD_RLOGIN_SSH="cat /etc/ssh/sshd_config /opt/ssh/etc/sshd_config /etc/sshd_config /usr/local/etc/sshd_config /usr/local/sshd/etc/sshd_config /usr/local/ssh/etc/sshd_config /etc/ssh/ssh_config | egrep PermitRootLogin"
FILE_SSHD_CONF="/etc/ssh/sshd_config /opt/ssh/etc/sshd_config /etc/sshd_config /usr/local/etc/sshd_config /usr/local/sshd/etc/sshd_config /usr/local/ssh/etc/sshd_config /etc/ssh/ssh_config"
CMD_RPCINFO="rpcinfo -p"

CMD_PASSSEC="cat /etc/login.defs"

DIR_STARTUP="/etc/init.d /etc/rc2.d /etc/rc3.d /etc/rc.d/init.d \
	/etc/rc.d/rc2.d /etc/rc.d/rc3.d"
DIR_LOG="/var/log"

FILE_MOUNT="/etc/fstab"
FILE_CRONUSER="/etc/cron.d/cron.allow /etc/cron.d/cron.deny /etc/cron.allow /etc/cron.deny"
FILE_SNMPD="/etc/snmpd.conf"
FILE_ALL="/etc/passwd /etc/shadow /etc/profile /etc/login.defs /etc/xinetd.conf \
	/etc/services /etc/rpc /etc/syslog.conf /etc/rsyslog.conf /etc/mail/sendmail.cf"
FILE_SETUID="/sbin/dump /usr/bin/lpq-lpd /usr/bin/newgrp /sbin/restore /usr/bin/lpr /usr/sbin/lpc /sbin/unix_chkpwd /usr/bin/lpr-lpd /usr/sbin/lpc-lpd /usr/bin/at /usr/bin/lprm /usr/sbin/traceroute /usr/bin/lpq /usr/bin/lprm-lpd"

# CheckService Function 관련
Echo="echo"
strNetstat="netstat -an"
arrTcpPort=`netstat -an | grep -i "^tcp" | grep -i "LIST" | awk -F" " '{print $4}' | awk -F":" '{print $NF}' | grep -v "^\*" | sort | uniq`
arrUdpPort=`netstat -an | grep -i "^udp" | awk -F" " '{print $4}' | awk -F":" '{print $NF}' | grep -v "^\*" | sort | uniq`
bTrustMode=""
lsEnableUser=""
Echo="echo"
RemoveComment='egrep -v "^[\ ]*\$|^[\ ]*\#|^[\ ]*\*[\ ]"'
Rpcinfo="rpcinfo"

#------------------------------------------------------------
if [ $OS = "AIX" ]; then
	CMD_CPUINFO="lsdev -Cc processor"
	CMD_CPUSTAT="mpstat 2 4"
	CMD_IOSTAT="iostat -t 2 4"
	CMD_VMSTAT="vmstat 3 5"
	CMD_PATCHINFO="instfix -i"

	CMD_LASTLOG="lsuser -a time_last_login ALL"
	CMD_PWCK="pwdck -n ALL"
	CMD_GRPCK="grpck -n ALL"
	CMD_TELNETBANNER="grep herald /etc/security/login.cfg  |  sed \"s/&/\&amp;/g\" |  sed \"s/</\&lt;/g\" | sed \"s/>/\&gt;/g\""
	CMD_DUMASK=""
	CMD_RUMASK=""
	CMD_SUGROUP="cat /etc/security/user | egrep -i \"(:$|su|sugroups)\""
	CMD_SULOG=""
	CMD_ROUTE="no -o ipforwarding -o ip6srcrouteforward -o ipsrcrouteforward"
	CMD_ROUTE2=""
	CMD_CRONLOG="audit query"
	CMD_LOGIN="grep loginretries /etc/security/user"
	CMD_LOGIN2="grep logintimes /etc/security/user"
	CMD_LOGIN3=""
	CMD_LOGIN4=""
	CMD_LOGIN5=""
	CMD_INETD_LOG="grep inetd /etc/rc.tcpip"
	CMD_RLOGIN=""
	CMD_RPCINFO="rpcinfo -p"

	CMD_PASSSEC="cat /etc/security/user"

	DIR_STARTUP="/etc/rc.d/init.d /etc/rc.d/rc2.d /etc/rc.d/rc3.d"
	DIR_LOG="/var/adm /etc/security /etc/utmp"

	FILE_MOUNT="/etc/filesystems"
	FILE_CRONUSER="/var/adm/cron/cron.allow /var/adm/cron/cron.deny"
	FILE_SNMPD="/etc/snmpd.conf /etc/snmpdv3.conf"
	FILE_ALL="/etc/passwd /etc/security/passwd /etc/profile /etc/inetd.conf \
		 /etc/services /etc/rpc /etc/security/user /etc/syslog.conf /etc/rsyslog.conf /etc/mail/sendmail.cf"
	FILE_SETUID="/usr/dt/bin/dtaction /usr/dt/bin/dtterm /usr/bin/X11/xlock /usr/sbin/mount /usr/sbin/lchangelv"
#------------------------------------------------------------
elif [ $OS = "HP-UX" ]; then
	CMD_CPUINFO="ioscan -fnC processor"
	CMD_CPUSTAT="mpstat 2 4"
	CMD_IOSTAT="iostat 2 4"
	CMD_VMSTAT="vmstat 3 5"
	#CMD_NICINFO="lanscan -v"
	CMD_NICINFO=""
	for interface in `netstat -in | awk '{print $1}' | grep -v "Name" | grep -v "^$"`
	do
		interres=`ifconfig "$interface"`
		if [ "$interres" ]; then
			CMD_NICINFO="$CMD_NICINFO\n$interres"
		fi
	done
	CMD_PATCHINFO="/usr/sbin/swlist -l patch"

	CMD_LASTLOG=""
	CMD_PWCK="pwck -s"
	CMD_GRPCK="grpck"
	CMD_TELNETBANNER="cat /etc/default/telnetd /etc/issue"
	CMD_DUMASK="grep -i umask /etc/default/security /etc/csh.login /etc/profile \
		/etc/skel/.profile"
	CMD_RUMASK=""
	CMD_SUGROUP="grep SU_ROOT_GROUP /etc/default/security"
	CMD_SULOG=""
	CMD_ROUTE="ndd /dev/ip ip_forwarding ip_forward_src_routed"
	CMD_ROUTE2=""
	CMD_CRONLOG=""
	CMD_LOGIN="grep NUMBER_OF_LOGINS_ALLOWED /etc/default/security"
	CMD_LOGIN2="grep ABORT_LOGIN_ON_MISSING_HOMEDIR /etc/default/security"
	CMD_LOGIN3="grep AUTH_MAXTRIES /etc/default/security"
	CMD_LOGIN4=""
	CMD_LOGIN5=""
	CMD_INETD_LOG="cat /etc/rc.config.d/netdaemons"
	CMD_RLOGIN="grep console /etc/securetty"
	CMD_RPCINFO="rpcinfo -p"

	CMD_PASSSEC="cat /etc/default/security"

	DIR_STARTUP="/sbin/init.d /sbin/rc2.d /sbin/rc3.d"
	DIR_LOG="/var/adm /etc/utmp"
	
	FILE_MOUNT="/etc/fstab /etc/auto_master"
	FILE_CRONUSER="/var/adm/cron/cron.allow /var/adm/cron/cron.deny"
	FILE_SNMPD="/etc/SnmpAgent.d/snmpd.conf"
	FILE_ALL="/etc/passwd /etc/profile /etc/inetd.conf /etc/services /etc/rpc \
		/etc/syslog.conf /etc/rsyslog.conf /etc/default/security /etc/mail/sendmail.cf"
	FILE_SETUID="/opt/perf/bin/glance /usr/dt/bin/dtprintinfo /usr/sbin/swreg /opt/perf/bin/gpm /usr/sbin/arp /usr/sbin/swremove /opt/video/lbin/camServer /usr/sbin/lanadmin /usr/contrib/bin/traceroute /usr/bin/at /usr/sbin/landiag /usr/dt/bin/dtappgather /usr/bin/lpalt /usr/sbin/lpsched /usr/sbin/swmodify /usr/bin/mediainit /usr/sbin/swacl /usr/sbin/swpackage /usr/bin/newgrp /usr/sbin/swconfig /usr/bin/rdist /usr/sbin/swinstall"

	# CheckService Function 관련
	if [ -f /tcb/files/auth/*/* ]; then
		bTrustMode="Trusted"
	fi
#------------------------------------------------------------
elif [ $OS = "Linux" ]; then
	CMD_CPUINFO="cat /proc/cpuinfo"
	CMD_CPUSTAT="cat /proc/stat"
	CMD_IOSTAT=""
	CMD_VMSTAT="cat /proc/meminfo"
	CMD_PATCHINFO="rpm -qa -i"

	CMD_LASTLOG="perl -e 'alarm shift @ARGV; exec @ARGV' 180 lastlog"
	CMD_PWCK="pwck"
	CMD_GRPCK="grpck -r"
	CMD_TELNETBANNER="cat /etc/issue /etc/issue.net"
	CMD_DUMASK="grep -i umask /etc/login.defs /etc/profile"
	CMD_RUMASK="grep -i umask $ROOT_HOME/.profile $ROOT_HOME/.*shrc $ROOT_HOME/.login $ROOT_HOME/.bash_profile"
	CMD_SUGROUP="grep wheel /etc/pam.d/su"
	CMD_SULOG="grep rootok /etc/pam.d/su"
	CMD_ROUTE="cat /proc/sys/net/ipv4/ip_forward"
	CMD_ROUTE2="cat /proc/sys/net/ipv4/conf/default/accept_source_route"
	CMD_CRONLOG=""
	CMD_LOGIN="grep FAILLOG_ENAB /etc/login.defs"
	CMD_LOGIN2="grep LOG_UNKFAIL_ENAB /etc/login.defs"
	CMD_LOGIN3="grep LOG_OK_LOGINS /etc/login.defs"
	CMD_LOGIN4="grep LOGIN_RETRIES /etc/login.defs"
	CMD_LOGIN5="grep LOGIN_TIMEOUT /etc/login.defs"
	CMD_PAM1="grep minlen /etc/pam.d/system-auth"
	CMD_PAM2="grep credit /etc/pam.d/system-auth"
	CMD_PAM3="grep retry /etc/pam.d/system-auth"
	CMD_INETD_LOG="egrep 'log_Type|log_on_success|log_on_failure' \
		/etc/xinetd.conf /etc/xinetd.d/*"
	CMD_RLOGIN=""
	CMD_RPCINFO="rpcinfo -p"

	CMD_PASSSEC="cat /etc/login.defs"

	DIR_STARTUP="/etc/init.d /etc/rc2.d /etc/rc3.d /etc/rc.d/init.d \
		/etc/rc.d/rc2.d /etc/rc.d/rc3.d"
	DIR_LOG="/var/log"

	
	#FILE_FTPBANNER="/etc/proftpd.conf"
	FILE_MOUNT="/etc/fstab"
	FILE_CRONUSER="/etc/cron.d/cron.allow /etc/cron.d/cron.deny /etc/cron.allow /etc/cron.deny"
	FILE_SNMPD="/etc/snmpd.conf"
	FILE_ALL="/etc/passwd /etc/shadow /etc/profile /etc/login.defs /etc/xinetd.conf \
		/etc/services /etc/rpc /etc/syslog.conf /etc/rsyslog.conf /etc/mail/sendmail.cf"
	FILE_SETUID="/sbin/dump /usr/bin/lpq-lpd /usr/bin/newgrp /sbin/restore /usr/bin/lpr /usr/sbin/lpc /sbin/unix_chkpwd /usr/bin/lpr-lpd /usr/sbin/lpc-lpd /usr/bin/at /usr/bin/lprm /usr/sbin/traceroute /usr/bin/lpq /usr/bin/lprm-lpd"

	# CheckService Function 관련
	Echo="echo -e"
	Rpcinfo="rpcinfo -p"
#------------------------------------------------------------
elif [ $OS = "SunOS" ]; then
	CMD_CPUINFO="psrinfo -v"
	CMD_CPUSTAT="mpstat 2 4"
	CMD_IOSTAT="iostat -xtc 2 4"
	CMD_VMSTAT="vmstat 3 5"
	CMD_PATCHINFO="showrev -p"

	CMD_LASTLOG="perl -e 'alarm shift @ARGV; exec @ARGV' 180 last"
	CMD_PWCK="pwck"
	CMD_GRPCK="grpck"
	CMD_TELNETBANNER="cat /etc/default/telnetd /etc/issue"
	CMD_DUMASK="grep -i umask /etc/default/login /etc/profile"
	CMD_RUMASK="grep -i umask $ROOT_HOME/.profile $ROOT_HOME/.*shrc $ROOT_HOME/.login $ROOT_HOME/.bash_profile"
	CMD_SUGROUP="ls -alL /usr/bin/su"
	CMD_SUGROUP2="ls -alL /bin/su"
	CMD_SULOG="egrep 'SULOG|SYSLOG' /etc/default/su"
	CMD_ROUTE="ndd /dev/ip ip_forwarding ip_forward_src_routed"
	CMD_ROUTE2=""
	CMD_CRONLOG="grep CRONLOG /etc/default/cron"
	CMD_LOGIN="grep SYSLOG_FAILED_LOGINS /etc/default/login"
	CMD_LOGIN2="grep SYSLOG /etc/default/login"
	CMD_LOGIN3="grep RETRIES /etc/default/login"
	CMD_LOGIN4="grep LOCK_AFTER_RETRIES /etc/security/policy.conf"
	CMD_LOGIN5="cat /etc/user_attr"

	CMD_INETD_LOG="grep '-l|-a' /etc/inetd.conf"
	CMD_RLOGIN="grep CONSOLE /etc/default/login"
	CMD_RPCINFO="rpcinfo -p"

	CMD_PASSSEC="cat /etc/default/passwd"

	DIR_STARTUP="/etc/init.d /etc/rc2.d /etc/rc3.d"
	DIR_LOG="/var/adm /var/log"

	if [ $OS_VER = "5.9" ]; then
		FILE_SNMPD="/etc/snmp/conf/snmpd.conf"
	elif [ $OS_VER = "5.10" ]; then
	    FILE_SNMPD="/etc/sma/snmp/snmpd.conf"
	elif [ $OS_VER = "5.11" ]; then
	    FILE_SNMPD="/etc/net-snmp/snmp/snmpd.conf"
	else
		FILE_SNMPD="/etc/snmp/conf/snmpd.conf"
	fi

	FILE_MOUNT="/etc/vfstab /etc/auto_master"
	FILE_CRONUSER="/etc/cron.d/cron.allow /etc/cron.d/cron.deny"
	FILE_ALL="/etc/passwd /etc/default/passwd /etc/shadow /etc/profile /etc/inetd.conf \
		/etc/services /etc/rpc /etc/syslog.conf /etc/rsyslog.conf /etc/default/login /etc/mail/sendmail.cf"
	FILE_SETUID="/usr/bin/admintool /usr/dt/bin/dtprintinfo /usr/sbin/arp /usr/bin/at /usr/dt/bin/sdtcm_convert /usr/sbin/lpmove /usr/bin/atq /usr/lib/fs/ufs/ufsdump /usr/sbin/prtconf /usr/bin/atrm /usr/lib/fs/ufs/ufsrestore /usr/sbin/sysdef /usr/bin/lpset /usr/lib/lp/bin/netpr /usr/sbin/sparcv7/prtconf /usr/bin/newgrp /usr/openwin/bin/ff.core /usr/sbin/sparcv7/sysdef /usr/bin/nispasswd /usr/openwin/bin/kcms_calibrate /usr/sbin/sparcv9/prtconf /usr/bin/rdist /usr/openwin/bin/kcms_configure /usr/sbin/sparcv9/sysdef /usr/bin/yppasswd /usr/openwin/bin/xlock /usr/dt/bin/dtappgather /usr/platform/sun4u/sbin/prtdiag"

	# CheckService Function 관련
	strNetstat="netstat -an"
	arrTcpPort=`netstat -an -P tcp -f inet | egrep -i "(LISTEN|BOUND)" | awk -F" " '{print $1}' | awk -F"." '{print $NF}' | grep -v "^\*" | sort | uniq`
	arrUdpPort=`netstat -an -P udp -f inet | egrep -i "(LISTEN|BOUND|IDLE)" | awk -F" " '{print $1}' | awk -F"." '{print $NF}' | grep -v "^\*" | sort | uniq`
	odNetstat=`netstat -an -f inet`
#------------------------------------------------------------
elif [ $OS = "OSF1" ]; then
	CMD_CPUINFO="psrinfo -v"
	CMD_CPUSTAT=""
	CMD_IOSTAT="iostat -xtc 2 4"
	CMD_VMSTAT="vmstat 3 5"
	CMD_PATCHINFO="dupatch -track -type patch"

	CMD_LASTLOG=""
	CMD_PWCK="pwck"
	CMD_GRPCK="grpck"
	CMD_TELNETBANNER="cat /etc/issue.net /etc/issue"
	CMD_DUMASK="grep -i umask /etc/profile"
	CMD_RUMASK="grep -i umask $ROOT_HOME/.profile $ROOT_HOME/.*shrc $ROOT_HOME/.login $ROOT_HOME/.bash_profile"
	CMD_SUGROUP="ls -alL /usr/bin/su"
	CMD_SULOG=""
	CMD_ROUTE="sysconfig -q inet ipforwarding ipgateway ipsrcroute"
	CMD_ROUTE2=""
	CMD_CRONLOG=""
	CMD_LOGIN="grep NUMBER_OF_LOGINS_ALLOWED /etc/default/security"
	CMD_LOGIN2="grep ABORT_LOGIN_ON_MISSING_HOMEDIR /etc/default/security"
	CMD_LOGIN3="grep AUTH_MAXTRIES /etc/default/security"
	CMD_LOGIN4=""
	CMD_LOGIN5=""
	CMD_INETD_LOG="grep '-l|-a' /etc/inetd.conf"
	CMD_RLOGIN="cat /etc/securettys"
	CMD_RPCINFO="rpcinfo -p"

	DIR_STARTUP="/sbin/init.d /sbin/rc2.d /sbin/rc3.d"
	DIR_LOG="/var/adm /usr/adm /etc/sec"

	FILE_MOUNT="/etc/fstab"
	FILE_CRONUSER="/usr/lib/cron/cron.allow /usr/lib/cron/cron.deny"
	FILE_SNMPD="/etc/snmpd.conf"
	FILE_ALL="/etc/passwd /etc/profile /etc/inetd.conf \
		/etc/services /etc/rpc /etc/syslog.conf /etc/rsyslog.conf /etc/mail/sendmail.cf"
fi


### Common Function(S) ###
fDumpS() {
	echo "    $1..." >&7
	cat << EDUMPS1
		<dump>
			<items>
EDUMPS1
	for ID in $1; do
		cat << EDUMPS2
				<id>$ID</id>
EDUMPS2
	done
	cat << EDUMPS3
			</items>
			<evidence_profile>
				<data_role>raw_command_output</data_role>
				<judgment_mode>raw_evidence_only</judgment_mode>
				<verdict_source>none</verdict_source>
				<safe_type_policy>AI decides absence-good or value-compliant-good from raw output only.</safe_type_policy>
				<command_marker>$</command_marker>
			</evidence_profile>
			<output>
EDUMPS3
}

fDumpE() {
	cat << EDUMPE
			</output>
		</dump>
EDUMPE
}

fDie() {
	echo "$1"
	exit 0
}

fHR() {
	echo "------------"
}

fHead() {
	cat << EHEAD
<?xml version="1.0" encoding="`echo $CENCODING`"?>
<?xml-stylesheet type="text/xsl" href="isac.xsl"?>
<script>
	<asset>
		<hostname>$HOSTNAME</hostname>
		<os>$OS</os>
		<uname>$UNAME</uname>
		<whoami>$USER</whoami>
		<version>$VERSION</version>
		<data_role>raw_data_provider</data_role>
		<judgment_mode>raw_evidence_only</judgment_mode>
		<verdict_source>none</verdict_source>
		<safe_type_policy>AI decides vulnerable/safe/info/unable and safe subtype from raw evidence only.</safe_type_policy>
		<ai_note>Script provides raw command evidence only. AI and LLM must decide verdict independently.</ai_note>
	</asset>
	<results>
EHEAD
}

fFoot() {
	cat << EFOOT
	</results>
	<runtime>$START ~ $END</runtime>
</script>
EFOOT
}

CheckService() {
	echo "[ $1 ][S]"

	ServicesName=""
	Port=""
	if [ $2 ]; then
		ServicesName=`cat /etc/services | egrep -i "^$2[^a-z]" | egrep -i "^$2[^-]" | egrep -v "^[\ ]*\$|^[\ ]*\#|^[\ ]*\*[\ ]"`
		Port=`cat /etc/services | egrep -i "^$2[^a-z]" | egrep -i "^$2[^-]" | awk -F" " '{print $2}' | egrep -v "^[\ ]*\$|^[\ ]*\#|^[\ ]*\*[\ ]" | awk -F"/" '{print $1}'`
		#echo $ServicesName
	fi


	tmp=""
	tmp1=""
	if [ "$ServicesName" -a "$Port" ]; then
		for p in $Port
		do
			restmp=""
			Protocol=`cat /etc/services | egrep -i "[^0-9]$p\/" | awk -F" " '{print $2}' | egrep -v "^[\ ]*\$|^[\ ]*\#|^[\ ]*\*[\ ]" | awk -F"/" '{print $2}'`
			if [ "$Protocol" ]; then
				resTcp=`$Echo "$Protocol" | grep "tcp"`
				resUdp=`$Echo "$Protocol" | grep "udp"`
				case "$OS" in
				SunOS )
					if [ "$resTcp" ]; then
						restmp=`netstat -an -P tcp -f inet | egrep -i "(LISTEN|BOUND)" | grep -v "^\*" | sort | uniq | egrep -i "[\.\:]$p[^0-9\.]"`
						if [ "$restmp" ]; then
							tmp="$tmp\n$restmp"
							tmp1="$tmp1\n"`$Echo "$ServicesName" | egrep -i "[^0-9]$p\/"`
						fi
					fi

					if [ "$resUdp" ]; then
						restmp=`netstat -an -P udp -f inet | egrep -i "(LISTEN|BOUND|IDLE)" | grep -v "^\*" | sort | uniq | egrep -i "[\.\:]$p[^0-9\.]"`
						if [ "$restmp" ]; then
							tmp="$tmp\n$restmp"
							tmp1="$tmp1\n"`$Echo "$ServicesName" | egrep -i "[^0-9]$p\/"`
						fi
					fi
					#netstat -an -f inet | egrep -i "(LISTEN|BOUND|IDLE)" | grep -v "^\*" | sort | uniq | egrep -i "[\.\:]$p[^0-9\.]"
					;;
				*)
					if [ "$resTcp" ]; then
						restmp=`netstat -an | egrep -i "^tcp" | grep -i "LIST" | grep -v "^\*" | sort | uniq | egrep -i "[\.\:]$p[^0-9\.]"`
						if [ "$restmp" ]; then
							tmp="$tmp\n$restmp"
							tmp1="$tmp1\n"`$Echo "$ServicesName" | egrep -i "[^0-9]$p\/"`
						fi
					fi

					if [ "$resUdp" ]; then
						restmp=`netstat -an | egrep -i "^udp" | grep -i "LIST" | grep -v "^\*" | sort | uniq | egrep -i "[\.\:]$p[^0-9\.]"`
						if [ "$restmp" ]; then
							tmp="$tmp\n$restmp"
							tmp1="$tmp1\n"`$Echo "$ServicesName" | egrep -i "[^0-9]$p\/"`
						fi
					fi
					#netstat -an | egrep -i "^tcp|^udp" | grep -i "LIST" | grep -v "^\*" | sort | uniq | egrep -i "[\.\:]$p[^0-9\.]"
					;;
				esac
			fi
		done
	fi
	
	if [ "$tmp1" ]; then
		echo "$ cat /etc/services | egrep $1"
		$Echo "$tmp1" | grep -v "^$" | sort | uniq
	fi
	
	if [ "$tmp" ]; then
		echo "$ $strNetstat"
		$Echo "$tmp" | grep -v "^$" | sort | uniq
	fi
	
	if [ $3 ]; then
		Tempps=`echo "$3" | sed "s/|/ /g"`
		for ps in $Tempps
		do
			resTemp=`ps -ef | egrep "[^a-z]$ps[^a-z\.]|[^a-z]$ps$" | grep -v "grep" | sort | uniq`
			if [ "$resTemp" ]; then
				echo "$ ps -ef | egrep $ps"
				$Echo "$resTemp"
			fi
			
			if [ "$OS" = "SunOS" ]; then
				resTemp=`/usr/ucb/ps auxwww | egrep -i "[^a-z]$ps[^a-z\.]|[^a-z]$ps$" | grep -v "grep" | egrep -v "^$" | egrep -v "grep" | sort | uniq |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"`
			else
				resTemp=`ps auxwww | egrep -i "[^a-z]$ps[^a-z\.]|[^a-z]$ps$" | grep -v "grep" | egrep -v "^$" | egrep -v "grep" | sort | uniq |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"`
			fi
			if [ "$resTemp" ]; then
				echo "$ ps auxwww | egrep $ps"
				$Echo "$resTemp"
			fi
		done
	fi

	Tempinetd=`echo "$1" | sed "s/|/ /g"`
	for inetd in $Tempinetd
	do
		inetd=`echo "$inetd" | sed "s/|/ /g"`
		if [ -f "/etc/xinetd.d/$inetd" ]; then
			resTemp=`cat "/etc/xinetd.d/$inetd" | egrep -v "^#" | egrep "disable" | egrep "no" | egrep -v "^$"`
			if [ "$resTemp" ]; then
				echo "$ cat /etc/xinetd.d/$inetd | egrep \"disable\" | egrep \"no\""
				$Echo "$resTemp" | sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
			fi
		fi
		if [ -f /etc/inetd.conf ]; then
			resTemp=`cat /etc/inetd.conf | egrep -v "^#" | egrep -i "^$inetd[d]?[^a-z]|[^a-z]$inetd[d]?[^a-z]" | egrep -v "^$"`
			if [ "$resTemp" ]; then
				echo "$ cat /etc/inetd.conf | egrep \"^$inetd[d]?[^a-z]|[^a-z]$inetd[d]?[^a-z]\""
				$Echo "$resTemp" | sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
			fi
		fi
		if [ $OS = "SunOS"  ]; then
			if [ $OS_VER = "5.10" -o $OS_VER = "5.11" ]; then
				resTemp=`inetadm | egrep -i enabled | egrep -i "[^a-z]$inetd[^a-z]"  | egrep -v "^$"`
				if [ "$resTemp" ]; then
					echo "$ inetadm | egrep \"[^a-z]$inetd[^a-z]\""
					$Echo "$resTemp" | sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
				fi
			fi
		elif [ $OS = "AIX"  ]; then
			resTemp=`lssrc -ls inetd | egrep -i active | egrep -i "[^a-z]$inetd[d]?[^a-z]" | egrep -v "^$"`
			if [ "$resTemp" ]; then
				echo "$ lssrc -ls inetd | egrep \"[^a-z]$inetd[d]?[^a-z]\""
				$Echo "$resTemp" | sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
			fi
		fi
	done
	
	if [ $4 ]; then
		Temprpcinfo=`echo "$4" | sed "s/|/ /g"`
		for rpcinfo in $Temprpcinfo
		do
			resTemp1=`$Rpcinfo 2>/dev/null | egrep -i "[^a-z]$rpcinfo[d]?[^a-z]|[^a-z]$rpcinfo[d]?$" | egrep -v "^$" | sort | uniq`
			if [ "$resTemp1" ]; then
				echo "$ $Rpcinfo | egrep $rpcinfo"
				$Echo "$resTemp1"
			fi
		done
		#if [ -f /etc/xinetd.conf ]; then
			#echo "$ cat /etc/xinetd.conf | egrep -v \"^#\" | egrep -i \"[^a-z]$4[^a-z]\""
			#cat /etc/xinetd.conf | egrep -v "^#" | egrep -i "[^a-z]$4[^a-z]" | egrep -v "^$" | sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
		#fi
	fi

	echo "[ $1 ][E]"
	return
}
### Check Service ###
# Define service name(view text, service name, ps daemon name, rpc service name)
# telnet(t/u): 
ck_telnet=`CheckService "telnet" "telnet" "telnetd" "telnet"`
# ftp(t/u): 
ck_ftp=`CheckService "ftp" "ftp" "vsftpd|proftpd|ftpd" "ftp"`
# ssh(t/u): 
ck_ssh=`CheckService "ssh|ssh-server" "ssh" "sshd|ssh\-server" ""`
# dns(t/u): 
ck_dns=`CheckService "domain|name" "domain" "named" ""`
# snmp(t/u): 
ck_snmp=`CheckService "snmp" "snmp" "snmpd" ""`
# smtp(t/u): 
ck_smtp=`CheckService "smtp|sendmail" "smtp" "sendmail" ""`
# tftp(t/u): 
ck_tftp=`CheckService "tftp" "tftp" "tftpd" "tftp"`
# finger(t/u): 
ck_finger=`CheckService "finger" "finger" "" "finger"`
# echo(t/u): 
ck_echo=`CheckService "echo" "echo" "" "echo"`
# discard(t/u): 
ck_discard=`CheckService "discard" "discard" "" "discard"`
# daytime(t/u): 
ck_daytime=`CheckService "daytime" "daytime" "" "daytime"`
# chargen(t/u): 
ck_chargen=`CheckService "chargen" "chargen" "" "chargen"`
# talk(u): 
ck_talk=`CheckService "talk" "talk" "" "talk"`
# ntalk(u): 
ck_ntalk=`CheckService "ntalk" "ntalk" "" "ntalk"`
# rexec(t): 
ck_rexec=`CheckService "exec|rexec" "exec" "" "exec"`
# rlogin(t): 
ck_rlogin=`CheckService "login|rlogin" "login" "" "login"`
# rsh(t): 
ck_rsh=`CheckService "shell|rshell" "shell" "" "shell"`
# rsync(t): 
ck_rsync=`CheckService "rsync" "rsync" "" "rsync"`
# syslog(u): 
ck_syslog=`CheckService "syslog" "syslog" "syslogd" ""`
# automount: 
ck_automount=`CheckService "automountd|autofs" "" "automountd|autofs" ""`
# inetd: 
ck_inetd=`CheckService "inetd" "" "inetd" ""`
# xinetd: 
ck_xinetd=`CheckService "xinetd" "" "xinetd" ""`
# dmi: 
ck_dmid=`CheckService "dmid" "" "snmpXdmid" ""`

# RPC
# rpcbind: 
ck_rpcbind=`CheckService "portmap|sunrpc|portmapper|rpcbind" "portmap[^a-z]|^sunrpc[^a-z]|^portmapper" "portmap|rpcbind" "portmapper|rpcbind|portmap"`
# nfs(t/u): 
ck_nfs=`CheckService "nfs" "nfsd" "nfsd|rpc\.nfs" "nfs"`
# nis: 
ck_nis=`CheckService "nis" "" "nisd|rpc\.nisd" "nis"`
# ypbind: 
ck_ypbind=`CheckService "ypserv|ypbind|ypxfrd|yppasswdd|ypupdated" "" "rpc\.ypserv|rpc\.ypbind|rpc\.ypxfrd|rpc\.yppasswdd|rpc\.ypupdated" "ypserv|ypbind|ypxfrd|yppasswdd|ypupdated"`
# cms: 
ck_cms=`CheckService "cms" "" "rpc\.cmsd" "cms"`
# ttdbserver: 
ck_ttdbserver=`CheckService "ttdbserver" "" "rpc\.ttdbserver" "ttdbserver"`
# sadmin: 
ck_sadmin=`CheckService "sadmin" "" "rpc\.sadmind" "sadmin"`
# rquota: 
ck_rquota=`CheckService "rquota" "" "rpc\.rquotad" "rquota"`
# rex: 
ck_rex=`CheckService "rex" "" "rpc\.rexd" "rex"`
# stat: 
ck_stat=`CheckService "stat" "" "rpc\.statd" "stat"`
# rstat: 
ck_rstat=`CheckService "rstat" "" "rpc\.rstatd" "rstat"`
# rusers: 
ck_rusers=`CheckService "rusers" "" "rpc\.rusersd" "rusers"`
# rwall: 
ck_rwall=`CheckService "wall" "" "rpc\.rwalld|rpc\.walld" "wall"`
# spray: 
ck_spray=`CheckService "spray" "" "rpc\.sprayd" "spray"`
# pcnfs: 
ck_pcnfs=`CheckService "pcnfs" "" "rpc\.pcnfsd" "pcnfs"`
# kcms_server: 
ck_kcms_server=`CheckService "kcms_server" "" "kcms_server" "kcms_server"`
# cachefs: 
ck_cachefs=`CheckService "cachefs" "" "cachefs" "cachefs"`

# 3Party
# WebLogic: 
ck_weblogic=`CheckService "weblogic|wlserver" "" "wlserver[^a-z\.].*weblogic|weblogic[^a-z\.].*wlserver|wlserver|weblogic" ""`
# Jeus:
ck_jeus=`CheckService "jeus|java" "" "[\/]jeus[^a-z\.].*java|java[^a-z\.].*[\/]jeus|[\/]jeus" ""`
# WebtoB: 
ck_webtob=`CheckService "wsm|webtob" "" "wsm[^a-z\.].*webtob|wsm[^a-z\.].*webtob|wsm|webtob" ""`
# JBoss: 
ck_jboss=`CheckService "jboss" "" "jboss" ""`
# IBMWebServer: 
ck_ibmwebserver=`CheckService "wsmserver" "" "wsmserver" ""`
# Apache(t/u): 
ck_apache=`CheckService "http|https|http-alt|www|www-http|apache|apache2" "http[^a-z]|^https[^a-z]|^http\-alt[^a-z]|^www[^a-z]|^www\-http" "httpd|apache|apache2" ""`
# Apache Tomcat: 
ck_tomcat=`CheckService "tomcat" "" "catalina\.startup\.Bootstrap" ""`
# WBEM:
ck_wbem=`CheckService "wbem-https|wbem-http" "wbem\-http[^a-z]|^wbem\-http" "wbem\-http|wbem\-http" ""`
# HP Data Protector:
ck_hp_data_protector=`CheckService "dataprotector" "" "dataprotector" ""`

### Enable User Check ###
lsEnableUser=""
lsEnableRoot=""
if [ -f "/etc/passwd" ]; then
	lsEnableUser=`cat /etc/passwd | egrep -v "^[\ ]*\$|^[\ ]*\#|^[\ ]*\*[\ ]" | grep -v ":nosh" | grep "sh$" | awk -F":" 'length($6) > 0 {print $1":"$6}' | sort -u`
	lsEnableRoot=`cat /etc/passwd | egrep -v "^[\ ]*\$|^[\ ]*\#|^[\ ]*\*[\ ]" | grep -v ":nosh" | grep "sh$" | grep "root" | awk -F":" 'length($6) > 0 {print $1":"$6}' | sort -u`
fi

HOMEDIR=`cat /etc/passwd | egrep -v "^[\ ]*\$|^[\ ]*\#|^[\ ]*\*[\ ]" | grep -v ":nosh" | grep "sh$" | awk -F":" 'length($6) > 0 {print $6}' | sort -u`

PrintCommonConfFile() {
	if [ -f "$1" ]; then
		if [ "$2" ]; then
			resTemp=`cat "$1" | egrep -v "^[\ ]*\$|^[\ ]*\#|^[\ ]*\*[\ ]" | egrep -i "$2"`
		else
			resTemp=`cat "$1" | egrep -v "^[\ ]*\$|^[\ ]*\#|^[\ ]*\*[\ ]"`
		fi
		if [ "$resTemp" ]; then
			echo "$ cat $1"
			echo "$resTemp"
			if [ "$2" = "ORACLE_HOME" -o "$2" = "JEUS_HOME" ]; then
				isac_test_var=`echo $resTemp" | egrep "[^\$]$2\=" | awk '{ print $1 }' | awk -F";" '{ print $1 }' | awk -F"=" '{ print $2 }'`
			fi
		fi
	fi
}

PrintCommonConfFiles() {
	if [ -d "$1" ]; then
		if [ "$2" ]; then
			lsFile=`ls -al "$1" | egrep -i "$2" | awk '{print $NF}'`
		else
			lsFile=`ls -al "$1" | awk '{print $NF}'`
		fi

		for File in $lsFile
		do
			if [ -f "$1/$File" ]; then
				if [ "$3" ]; then
					resTemp=`cat "$1/$File" | egrep -v "^[\ ]*\$|^[\ ]*\#|^[\ ]*\*[\ ]" | egrep -i "$3"`
				else
					resTemp=`cat "$1/$File" | egrep -v "^[\ ]*\$|^[\ ]*\#|^[\ ]*\*[\ ]"`
				fi
				if [ "$resTemp" ]; then
					echo "$ cat $1/$File"
					echo "$resTemp"
					if [ "$3" = "ORACLE_HOME" -o "$3" = "JEUS_HOME" ]; then
						isac_test_var=`echo "$resTemp" | egrep "[^\$]$3\=" | awk '{ print $1 }' | awk -F";" '{ print $1 }' | awk -F"=" '{ print $2 }'`
					fi
				fi
			fi
		done
	fi
}

PrintUserConfFiles() {
	for EnableUser in $1
	do
		User=`echo "$EnableUser" | awk -F":" '{print $1}'`
		Dir=`echo "$EnableUser" | awk -F":" '{print $2}' | grep -v "^/$" | grep -v "^//$"`
		if [ -d "$Dir$4" ]; then
			if [ "$2" ]; then
				lsFile=`ls -al "$Dir$4" | egrep -i "$2" | awk '{print $NF}'`
			else
				lsFile=`ls -al "$Dir$4" | awk '{print $NF}'`
			fi
			
			for File in $lsFile
			do
				if [ -f "$Dir$4/$File" ]; then
					if [ "$3" ]; then
						resTemp=`cat "$Dir$4/$File" | egrep -v "^[\ ]*\$|^[\ ]*\#|^[\ ]*\*[\ ]" | egrep -i "$3"`
					else
						resTemp=`cat "$Dir$4/$File" | egrep -v "^[\ ]*\$|^[\ ]*\#|^[\ ]*\*[\ ]"`
					fi
					if [ "$resTemp" ]; then
						echo "$ cat $Dir$4/$File"
						echo "$resTemp"
						if [ "$3" = "ORACLE_HOME" -o "$3" = "JEUS_HOME" ]; then
							isac_test_var=`echo "$resTemp" | egrep "[^\$]$3\=" | awk '{ print $1 }' | awk -F";" '{ print $1 }' | awk -F"=" '{ print $2 }'`
						fi
					fi
				fi
			done
		fi
	done
}

PrintAllCommonConf() {


	echo " "
	echo "[ Common /etc/profile Setting ]"
	PrintCommonConfFile "/etc/profile" "$1"

	echo " "
	echo "[ Common login Setting ]"
	PrintCommonConfFile "/etc/default/login" "$1"

	echo " "
	echo "[ All Users ..*profile Setting ]"
	PrintUserConfFiles "$lsEnableUser" "\..*profile$" "$1" ""

	echo " "
	echo "[ Common .profile Setting ]"
	PrintCommonConfFile "/.profile" "$1"
	PrintCommonConfFile "/etc/security/.profile" "$1"

	echo " "
	echo "[ Common .login Setting ]"
	PrintCommonConfFiles "/etc" ".*\.login$" "$1"

	echo " "
	echo "[ All Users .login Setting ]"
	PrintUserConfFiles "$lsEnableUser" ".*\.login$" "$1" ""

	echo " "
	echo "[ Common shrc Setting ]"
	PrintCommonConfFiles "/etc" "\..*shrc$" "$1"

	echo " "
	echo "[ All Users shrc Setting ]"
	PrintUserConfFiles "$lsEnableUser" "\..*shrc$" "$1" ""

	echo " "
	echo "[ Current User Setting ]"
	set | egrep "([^|a-zA-Z0-9\_\-\=\#]$1\=)"
	echo " "
	echo "[ Current User Environment Variables ]"
	env | egrep "([^|a-zA-Z0-9\_\-\=\#]$1\=)"
}

PrintRootCommonConf() {

	echo " "
	echo "[ Common /etc/profile Setting ]"
	PrintCommonConfFile "/etc/profile" "$1"

	echo " "
	echo "[ Common login Setting ]"
	PrintCommonConfFile "/etc/default/login" "$1"

	echo " "
	echo "[ Root ..*profile Setting ]"
	PrintUserConfFiles "$lsEnableRoot" "\..*profile$" "$1" ""

	echo "[ Common .profile Setting ]"
	PrintCommonConfFile "/.profile" "$1"
	PrintCommonConfFile "/etc/security/.profile" "$1"

	echo " "
	echo "[ Common .login Setting ]"
	PrintCommonConfFiles "/etc" ".*\.login$" "$1"

	echo " "
	echo "[ Root .login Setting ]"
	PrintUserConfFiles "$lsEnableRoot" ".*\.login$" "$1" ""


	echo "[ Common shrc Setting ]"
	PrintCommonConfFiles "/etc" "\..*shrc$" "$1"

	echo " "
	echo "[ Root shrc setting ]"
	PrintUserConfFiles "$lsEnableRoot" "\..*shrc$" "$1" ""

	echo " "
	echo "[ Current User Setting ]"
	set | egrep "([^|a-zA-Z0-9\_\-\=\#]$1\=)"
	echo " "
	echo "[ Current User Environment Variables ]"
	env | egrep "([^|a-zA-Z0-9\_\-\=\#]$1\=)"
}




### 2016.1 Add/Modify ###
### FtpUsers Path(S) ###
#FILE_FTPUSERS="/etc/ftpusers /etc/ftpd/ftpusers"
FILE_FTPUSERS=""
lsFILE_VSFTPDCONF="/etc/vsftpd.conf /etc/vsftpd/vsftpd.conf /etc/vsftpd/conf/vsftpd.conf"
lsFILE_PROFTPDCONF="/etc/proftpd.conf /etc/proftpd/proftpd.conf /etc/proftpd/conf/proftpd.conf /usr/local/etc/proftpd.conf /usr/local/proftpd/etc/proftpd.conf"
#userlist_enable=YES
#userlist_file=/etc/vsftp.user_list
#userlist_deny=NO
### FtpUsers Path(E) ###
CMDCKFTP=`echo "$ck_ftp" | egrep -v "^#"`
if [ "$CMDCKFTP" ]; then
	# ProFTP(PAM)
	if [ -f "/etc/pam.d/ftp" ]; then
		FILE_FTPUSERS=`cat /etc/pam.d/ftp | egrep -v "^#" | egrep -v "^$" | egrep "pam_listfile\.so" | egrep "item\=(user|group)" | egrep "sense\=(deny|allow)" | egrep "onerr\=(succeed|fail)" | awk -F"file=" '{ print $2 }' | awk '{ print $1 }'`
	fi
	# VSFTP(PAM)
	for VSFTPDCONF in $lsFILE_VSFTPDCONF
	do
	if [ -f "$VSFTPDCONF" ]; then
		# FtpUsers Path
		# PAM
		Temp1=`cat "$VSFTPDCONF" | egrep -v "^[\ ]*\$|^[\ ]*\#|^[\ ]*\*[\ ]" | egrep -v "^#" | egrep -v "^$" | egrep -i "^pam_service_name" | awk -F"pam_service_name=" '{print $2}' | awk '{print $1}'`
		if [ "$Temp1" ]; then
			#cat "$VSFTPDCONF" | egrep -v "^[\ ]*\$|^[\ ]*\#|^[\ ]*\*[\ ]" | egrep -i "^pam_service_name"
			if [ -f "/etc/pam.d/$Temp1" ]; then
				Temp2=`cat /etc/pam.d/"$Temp1" | egrep -v "^[\ ]*\$|^[\ ]*\#|^[\ ]*\*[\ ]" | egrep -v "^#" | egrep -v "^$" | egrep -i "auth" | egrep -i "pam_listfile.so" | egrep -i "sense=deny" | awk -F"file=" '{print $2}' | awk '{print $1}'`
				if [ "$Temp4" ]; then
					if [ "$FILE_FTPUSERS" ]; then
						FILE_FTPUSERS="$FILE_FTPUSERS $Temp2"
					else
						FILE_FTPUSERS="$Temp2"
					fi
				fi
			fi
		fi
		
		# VSFtp userlist Path
		Temp3=`cat "$VSFTPDCONF" | egrep -v "^[\ ]*\$|^[\ ]*\#|^[\ ]*\*[\ ]" | egrep -v "^#" | egrep -v "^$" | egrep -i "(userlist_enable\=YES)"`
		if [ "$Temp3" ]; then
			Temp4=`cat "$VSFTPDCONF" | egrep -v "^[\ ]*\$|^[\ ]*\#|^[\ ]*\*[\ ]" | egrep -v "^#" | egrep -v "^$" | egrep -i "(userlist_file\=)" | awk -F"userlist_file=" '{ print $2 }'`
			if [ "$Temp4" ]; then
				if [ "$FILE_FTPUSERS" ]; then
					FILE_FTPUSERS="$FILE_FTPUSERS $Temp3"
				else
					FILE_FTPUSERS="$Temp3"
				fi
			fi
		fi
		
		if [ "$FILE_FTPUSERS" = "" ]; then
			FILE_FTPUSERS="/etc/vsftpd.ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.user_list /etc/vsftpd/user_list"
		fi
	fi
	done
fi

# $FILE_FTPUSERS is NULL => Define, proftpd.conf path
if [ "$FILE_FTPUSERS" = "" ]; then
	if [ $OS = "AIX" ]; then
		FILE_FTPUSERS="/etc/ftpusers /etc/vsftpd/ftpusers"
		FILE_FTPBANNER="/etc/ftpaccess.ctl"
	elif [ $OS = "HP-UX" ]; then
		FILE_FTPUSERS="/etc/ftpd/ftpusers /etc/vsftpd/ftpusers"
		FILE_FTPBANNER="/etc/ftpd/ftpaccess"
	elif [ $OS = "Linux" ]; then
		FILE_FTPUSERS="/etc/ftpusers /etc/vsftpd/ftpusers"
		FILE_FTPBANNER="/etc/proftpd.conf"
	elif [ $OS = "SunOS" ]; then
		if [ $OS_VER = "5.9" ]; then
			FILE_FTPUSERS="/etc/ftpd/ftpusers /etc/vsftpd/ftpusers"
		elif [ $OS_VER = "5.10" ]; then
			FILE_FTPUSERS="/etc/ftpd/ftpusers /etc/vsftpd/ftpusers"
		elif [ $OS_VER = "5.11" ]; then
			FILE_FTPUSERS="/etc/ftpd/ftpusers /etc/vsftpd/ftpusers"
		else
			FILE_FTPUSERS="/etc/ftpusers /etc/vsftpd/ftpusers"
		fi
		FILE_FTPBANNER="/etc/default/ftpd"
	elif [ $OS = "OSF1" ]; then
		FILE_FTPUSERS="/etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers"
		FILE_FTPBANNER=""
	fi
fi

# vsftpd.conf path
for VSFTPDCONF in $lsFILE_VSFTPDCONF
do
	#Temp1=`cat "$VSFTPDCONF" | egrep -v "^[\ ]*\$|^[\ ]*\#|^[\ ]*\*[\ ]" | egrep -v "^#" | egrep -v "^$" | egrep -i "(ftpd_banner\=)"`
	if [ -f "$VSFTPDCONF" ]; then
		FILE_FTPBANNER="$FILE_FTPBANNER $VSFTPDCONF"
	fi
done

#web server config path
#webtobroot=""
webroot=""
webconf_file=""
web_docuroot=""

apacheD=`ps -ef | egrep 'apache|httpd' | grep -v grep | awk '{for (i=1;i<=NF;i++) {if ($i ~/(bin)/) {print $i}}}' | egrep 'httpd$|httpd2$|apache$|apache2$' | grep -v "grep" | sort -u`
if [ $apacheD ]; then
	# httpd -V 옵션으로 webroot 디렉토리와 conf 파일의 위치 파악가능
	webroot=`$apacheD -V | grep ROOT | awk -F= '{print $2}' | sed s/\"//g`
	webconf_file=`$apacheD -V | grep SERVER | awk -F= '{print $2}' | sed s/\"//g`
	if [ $webconf_file ]; then
		# httpd -V 결과 중 conf 설정 값이 상대경로 혹은 절대경로로 나올 수 있으므로, 모두 절대경로로 나오도록 설정
		#if [ ${webconf_file:0:1} != "/" ]; then
		#	webconf_file="${webroot}/${webconf_file}"
		#fi
		webconf_temp=`echo "$webconf_file" | egrep "^[^\/]"`
		if [ "$webconf_temp" ]; then
			webconf_file="${webroot}/${webconf_file}"
		fi
	else
		if [ -f /etc/httpd/conf/httpd.conf ]; then
			webconf_file="/etc/httpd/conf/httpd.conf"
		elif [ -f /web/httpd/conf/httpd.conf ]; then
			webconf_file="/web/httpd/conf/httpd.conf"
		fi
	fi
	if [ -f "$webconf_file" ]; then
		# document root 경로도 변수로 저장하여 활용
		web_docuroot=`cat $webconf_file | grep "DocumentRoot" | sed "s/&/\&amp;/g" | sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"`
	fi
fi

#/usr/ucb/ps auxwww | egrep 'jeus' | grep -v grep | awk '{for (i=1;i<=NF;i++) {if ($i ~/(jeus$)/) {print $i}}}' | grep '^/' | sort -u
### Common Function(E) ###



#------------------------------------------------------------
#
#   Start
echo `date`
echo "Start..."
exec 6>&1 7>&2 1>$OUT 2>&1

fHead
#============================================================

fDumpS "SRV-001 SRV-002"
	$Echo "$ck_snmp"
	for hfile in $FILE_SNMPD; do
		echo "$ ls -alL $hfile"
		ls -alL $hfile
		fHR
		echo "$ grep -i community $hfile"
		grep -i community $hfile  |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
		fHR
	done
fDumpE
#--------------------------------------------------------------------
fDumpS "SRV-004"
		$Echo "$ck_smtp"
fDumpE
#------------------------------------------------------------
fDumpS "SRV-005"
		$Echo "$ck_smtp"
		echo "$ cat /etc/mail/sendmail.cf | grep PrivacyOptions | grep -v grep"
		cat /etc/mail/sendmail.cf | grep PrivacyOptions | grep -v grep  |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
		fHR
		echo "$ cat /etc/sendmail.cf | grep PrivacyOptions | grep -v grep"
		cat /etc/sendmail.cf | grep PrivacyOptions | grep -v grep  |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
fDumpE
#------------------------------------------------------------
fDumpS "SRV-006"
		$Echo "$ck_smtp"
		echo "$ cat /etc/mail/sendmail.cf | grep LogLevel | grep -v grep"
		cat /etc/mail/sendmail.cf | grep LogLevel | grep -v grep  |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
		fHR
		echo "$ cat /etc/sendmail.cf | grep LogLevel | grep -v grep"
		cat /etc/sendmail.cf | grep LogLevel | grep -v grep  |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
fDumpE
#------------------------------------------------------------
fDumpS "SRV-007"
	$Echo "$ck_smtp"
	if [ $OS = "Linux" ]; then
		echo "$ sendmail -d0.1 &lt; /dev/null | grep -i version"
		sendmail -d0.1 < /dev/null | grep -i version |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	elif [ $OS = "AIX" ]; then
		echo "$ echo \$Z | sendmail -d0"
		echo \$Z | sendmail -d0 |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	else
		echo "$ echo \$Z | /usr/lib/sendmail -bt -d0"
		echo \$Z | /usr/lib/sendmail -bt -d0 |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	fi
fDumpE
#------------------------------------------------------------
fDumpS "SRV-008"
	$Echo "$ck_smtp"
	echo "$ egrep \"MaxDaemonChildren|ConnectionRateThrottle|MinFreeBlocks|MaxHeadersLength|MaxMessageSize\" /etc/mail/sendmail.cf"
	egrep "MaxDaemonChildren|ConnectionRateThrottle|MinFreeBlocks|MaxHeadersLength|MaxMessageSize" /etc/mail/sendmail.cf
	fHR
	echo "$ egrep \"MaxDaemonChildren|ConnectionRateThrottle|MinFreeBlocks|MaxHeadersLength|MaxMessageSize\" /etc/sendmail.cf"
	egrep "MaxDaemonChildren|ConnectionRateThrottle|MinFreeBlocks|MaxHeadersLength|MaxMessageSize" /etc/sendmail.cf
fDumpE
#------------------------------------------------------------
fDumpS "SRV-009"
	$Echo "$ck_smtp"
	echo "$ ls -alL /etc/mail/"
	ls -alL /etc/mail
	fHR
	echo "$ cat /etc/mail/access"
	cat /etc/mail/access |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
fDumpE
#------------------------------------------------------------
fDumpS "SRV-010"
	$Echo "$ck_smtp"
	echo "$ grep \"PrivacyOptions\" /etc/mail/sendmail.cf"
	grep "PrivacyOptions" /etc/mail/sendmail.cf
	fHR
	echo "$ grep \"PrivacyOptions\" /etc/sendmail.cf"
	grep "PrivacyOptions" /etc/sendmail.cf
fDumpE
#------------------------------------------------------------
### 2016.1 remove ###
#fDumpS "SRV-011"
#	$Echo "$ck_ftp"
#	for hfile in $FILE_FTPUSERS; do
#		echo "$ ls -alL $hfile"
#		ls -alL $hfile
#		echo "$ cat $hfile"
#		cat $hfile  |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
#		fHR
#	done
#fDumpE
#------------------------------------------------------------
### 2016.1 Add/Modify ###
fDumpS "SRV-011"
	$Echo "$ck_ftp"
	for hfile in $FILE_FTPUSERS; do
		echo "$ ls -alL $hfile"
		ls -alL $hfile
		fHR
		echo "$ cat $hfile"
		cat $hfile  |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
		fHR
	done
fDumpE
#------------------------------------------------------------
fDumpS "SRV-012"
	$Echo "$ck_ftp"
	#HOMEDIR=`awk -F":" '{print $6}' /etc/passwd`
	for dir in $HOMEDIR; do
		if [ -n $dir ]; then
			hfiles=`ls -alL $dir | awk -F" " '{print $9}' | grep "\.netrc"`
			for hfile in $hfiles; do
				fHR
				echo "$ ls -aldL $dir/$hfile"
				ls -aldL $dir/$hfile
				fHR
				echo "$ cat $dir/$hfile"
				cat $dir/$hfile  |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
			done
		fi
	done
fDumpE
#------------------------------------------------------------
fDumpS "SRV-013"
	$Echo "$ck_ftp"
	echo "$ cat /etc/ftpaccess"
	cat /etc/ftpaccess |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	fHR
	echo "$ cat /etc/ftpd/ftpaccess"
	cat /etc/ftpd/ftpaccess |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	fHR
	
	# ProFTP
	for PROFTPDCONF in $lsFILE_PROFTPDCONF
	do
	if [ -f "$PROFTPDCONF" ]; then
		echo "$ cat \"$PROFTPDCONF\""
		cat "$PROFTPDCONF" |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
		fHR
	fi
	done

	# vsFTP
	for VSFTPDCONF in $lsFILE_VSFTPDCONF
	do
	if [ -f "$VSFTPDCONF" ]; then
		echo "$ cat \"$VSFTPDCONF\""
		cat "$VSFTPDCONF" |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
		fHR
	fi
	done
fDumpE
#------------------------------------------------------------
fDumpS "SRV-014 SRV-015"
	$Echo "$ck_nfs"
	echo "$ cat /etc/exports"
	cat /etc/exports  |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	fHR
	echo "$ cat /etc/netgroup"
	cat /etc/netgroup  |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	fHR
	echo "$ cat /etc/dfs/dfstab"
	cat /etc/dfs/dfstab  |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
fDumpE
#------------------------------------------------------------
fDumpS "SRV-016"
	$Echo "$ck_cms"
	$Echo "$ck_ttdbserver"
	$Echo "$ck_sadmin"
	$Echo "$ck_rusers"
	$Echo "$ck_rwall"
	$Echo "$ck_spray"
	$Echo "$ck_rstat"
	$Echo "$ck_stat"
	$Echo "$ck_nis"
	$Echo "$ck_rex"
	$Echo "$ck_pcnfs"
	$Echo "$ck_ypbind"
	$Echo "$ck_rquota"
	$Echo "$ck_kcms_server"
	$Echo "$ck_cachefs"
fDumpE
#------------------------------------------------------------"S
fDumpS "SRV-017"
	$Echo "$ck_automount"
fDumpE
#------------------------------------------------------------
fDumpS "SRV-019"
	$Echo "$ck_tftp"
	$Echo "$ck_talk"
	$Echo "$ck_ntalk"
fDumpE
#------------------------------------------------------------
fDumpS "SRV-025"
	$Echo "$ck_rexec"
	$Echo "$ck_rlogin"
	$Echo "$ck_rsh"
	files="/etc/hosts /etc/hosts.equiv /etc/hosts.allow /etc/hosts.deny"
	for file in $files; do
		fHR
		echo "$ ls -aldL $file"
		ls -aldL $file
		fHR
		echo "$ cat $file"
		cat $file  |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	done
	fHR
	#HOMEDIR=`awk -F":" '{print $6}' /etc/passwd`
	for dir in $HOMEDIR; do
		if [ -n $dir ]; then
			hfiles=`ls -alL $dir | awk -F" " '{print $9}' | grep "\.rhosts"`
			for hfile in $hfiles; do
				fHR
				echo "$ ls -aldL $dir/$hfile"
				ls -aldL $dir/$hfile
				fHR
				echo "$ cat $dir/$hfile"
				cat $dir/$hfile  |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
			done
		fi
	done
fDumpE
#------------------------------------------------------------
fDumpS "SRV-026"
	$Echo "$ck_telnet"
	$Echo "$ck_ssh"
	if [ $OS = "AIX" ]; then
		echo "$ cat /etc/security/user | egrep -v \"^$\" | egrep -v \"^\*\" | egrep -i \"(\:$|rlogin|ttys|ptyx|ptys)\""
		cat /etc/security/user | egrep -v "^$" | egrep -v "^\*" | egrep -i "(\:$|rlogin|ttys|ptyx|ptys)"
		fHR
	elif [ $OS = "Linux" ]; then
		echo "$ cat /etc/securetty | egrep -i \"(ptyp1|^pts)\""
		cat /etc/securetty | egrep -i "(ptyp1|^pts)"
		fHR
		echo "$ cat /etc/pam.d/remote | egrep -i \"pam_securetty.so\""
		cat /etc/pam.d/remote | egrep -i "pam_securetty.so"
		fHR
		echo "$ cat /etc/pam.d/login | egrep -i \"pam_securetty.so\""
		cat /etc/pam.d/login | egrep -i "pam_securetty.so"
		fHR
	elif [ $OS = "HP-UX" ]; then
		echo "$ cat /etc/securetty | egrep -i \"console\""
		cat /etc/securetty | egrep -i "console"
		fHR
	elif [ $OS = "SunOS" ]; then
		echo "$ cat /etc/default/login | egrep -i \"console\""
		cat /etc/default/login | egrep -i "console"
		fHR
	elif [ $OS = "OSF1" ]; then
		echo "$ cat /etc/securettys"
		cat /etc/securettys
		fHR
	fi
	for SSHD_CONF in $FILE_SSHD_CONF; do
		echo "$ $SSHD_CONF | egrep -i \"(PermitRootLogin|denyuser)\""
		cat $SSHD_CONF | egrep -i "(PermitRootLogin|denyuser)"
		fHR
	done
	#if [ $OS = "HP-UX" ]; then
	#	fHR
	#	echo "$ grep PermitRootLogin /opt/ssh/etc/sshd_config"
	#	grep PermitRootLogin /opt/ssh/etc/sshd_config
	#	fHR
	#	echo "$ grep denyuser /opt/ssh/etc/sshd_config"
	#	grep denyuser /opt/ssh/etc/sshd_config
	#fi
fDumpE
#------------------------------------------------------------
fDumpS "SRV-027"
	files="/etc/hosts /etc/hosts.allow /etc/hosts.deny"
	for file in $files; do
		fHR
		echo "$ ls -aldL $file"
		ls -aldL $file
		fHR
		echo "$ cat $file"
		cat $file  |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	done
fDumpE
#------------------------------------------------------------
fDumpS "SRV-159"
	$Echo "$ck_telnet"
	echo "$ echo \$TMOUT \$TIMEOUT"
	echo $TMOUT $TIMEOUT
	fHR
	PrintAllCommonConf "(TMOUT|TIMEOUT)"
	fHR
	$Echo "$ck_ssh"
	for SSHD_CONF in $FILE_SSHD_CONF; do
		echo "$ $SSHD_CONF | egrep -i \"(ClientAliveInterval|ClientAliveCountMax)\""
		cat $SSHD_CONF | egrep -i "(ClientAliveInterval|ClientAliveCountMax)"
		fHR
	done
fDumpE
#------------------------------------------------------------
fDumpS "SRV-030"
	$Echo "$ck_finger"
fDumpE
#------------------------------------------------------------
if [ $OS = "SunOS" ]; then
fDumpS "SRV-033"
	$Echo "$ck_dmid"
	echo "$ cat /etc/init.d/init.dmi /etc/rc3.d/S77dmi"
	cat /etc/init.d/init.dmi /etc/rc3.d/S77dmi |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
fDumpE
fi
#------------------------------------------------------------
fDumpS "SRV-035"
	$Echo "$ck_rexec"
	$Echo "$ck_rlogin"
	$Echo "$ck_rsh"
fDumpE
#------------------------------------------------------------
fDumpS "SRV-036"
	$Echo "$ck_echo"
	$Echo "$ck_discard"
	$Echo "$ck_daytime"
	$Echo "$ck_chargen"
fDumpE
#------------------------------------------------------------
fDumpS "SRV-039"
	$Echo "$ck_webtob"
fDumpE
#------------------------------------------------------------
fDumpS "SRV-040"
	$Echo "$ck_apache"
	#echo "ls -aldL $webconf_file"
	#ls -aldL $webconf_file
	#fHR
	#echo "cat $webconf_file"
	#cat $webconf_file | sed "s/&/\&amp;/g" | sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	# document root 경로도 변수로 저장하여 활용
	#web_docuroot=`cat $webconf_file | grep "DocumentRoot" | sed "s/&/\&amp;/g" | sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"`
	#echo "$web_docuroot"
	if [ -f "$webconf_file" ]; then
		echo "$ cat $webconf_file | egrep 'Directory|Indexes'"
		cat "$webconf_file" | egrep "Directory|Indexes"
	else
		echo "cannot open file"
	fi
fDumpE
#------------------------------------------------------------
fDumpS "SRV-042"
	$Echo "$ck_apache"
	if [ -f "$webconf_file" ]; then
		echo "$ cat $webconf_file | egrep 'Directory|AllowOverride'"
		cat "$webconf_file" | egrep "Directory|AllowOverride"
	else
		echo "cannot open file"
	fi
fDumpE
#------------------------------------------------------------
fDumpS "SRV-043"
	$Echo "$ck_apache"
	if [ -d "$webroot" ]; then
		echo "$ find $webroot -name cgi-bin"
		find $webroot -name cgi-bin
	fi
fDumpE
#------------------------------------------------------------
fDumpS "SRV-044"
	$Echo "$ck_apache"
	if [ -f "$webconf_file" ]; then
		echo "$ cat $webconf_file | egrep 'LimitRequestBody'"
		cat "$webconf_file" | egrep "LimitRequestBody"
	else
		echo "cannot open file"
	fi
fDumpE
#------------------------------------------------------------
fDumpS "SRV-045"
	$Echo "$ck_apache"
	if [ -f "$webconf_file" ]; then
		echo "$ cat $webconf_file | egrep '(user|group)'"
		cat "$webconf_file" | egrep "(user|group)"
	else
		echo "cannot open file"
	fi
	fHR
	echo "$ cat /etc/passwd"
	cat /etc/passwd  |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	fHR
	echo "$ cat /etc/shadow"
	cat /etc/shadow  |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	if [ "$OS" = "AIX" ]; then
		fHR
		echo "$ cat /etc/security/user | egrep -v \"^*\" | egrep \"(\:|login[^a-z])\""
		cat /etc/security/user | egrep -v "^$" | egrep -v "^\*" | egrep "(\:|login[^a-z])"
	elif [ "$OS" = "HP-UX" ]; then
		fHR
		echo "$ cat /tcb/files/auth/*/*"
		cat /tcb/files/auth/*/* | egrep "(\:[^a-z]|u_lock)" | sed "s/&/\&amp;/g" | sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	fi
fDumpE
#------------------------------------------------------------
fDumpS "SRV-046"
	$Echo "$ck_apache"
	if [ -f "$webconf_file" ]; then
		echo "$ cat $webconf_file | egrep 'DocumentRoot'"
		cat "$webconf_file" | egrep "DocumentRoot"
	else
		echo "cannot open file"
	fi
fDumpE
#------------------------------------------------------------
fDumpS "SRV-047"
	$Echo "$ck_apache"
	echo "$ cat $webconf_file | egrep 'FollowSymLinks'"
	if [ -f "$webconf_file" ]; then
		cat "$webconf_file" | egrep "FollowSymLinks"
	else
		echo "cannot open file"
	fi
fDumpE
#------------------------------------------------------------
fDumpS "SRV-060"
	$Echo "$ck_tomcat"
	#was server config path
	if [ -d "$CATALINA_HOME" ]; then
		echo "ls -alL $CATALINA_HOME/conf"
		ls -alL $CATALINA_HOME/conf
		fHR
		echo "cat $CATALINA_HOME/conf/tomcat-users.xml"
		cat $CATALINA_HOME/conf/tomcat-users.xml  |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
		fHR
	else
		if [ $OS = "SunOS" ]; then
			CATALINA_HOME=`/usr/ucb/ps auxwww | egrep 'catalina\.startup\.Bootstrap' | grep -v grep | awk '{for (i=1;i<=NF;i++) {if ($i ~/(Dcatalina\.home)/) {print $i}}}' | awk -F"=" '{ print $2 }' | grep '^/' | sort -u |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"`
		else
			CATALINA_HOME=`ps auxwww | egrep 'catalina\.startup\.Bootstrap' | grep -v grep | awk '{for (i=1;i<=NF;i++) {if ($i ~/(Dcatalina\.home)/) {print $i}}}' | awk -F"=" '{ print $2 }' | grep '^/' | sort -u |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"`
		fi
		echo "ls -alL $CATALINA_HOME/conf"
		ls -alL $CATALINA_HOME/conf
		fHR
		echo "cat $CATALINA_HOME/conf/tomcat-users.xml"
		cat $CATALINA_HOME/conf/tomcat-users.xml  |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
		fHR
	fi
fDumpE
#-----------------------------------------------------------
fDumpS "SRV-061"
	$Echo "$ck_dns"
	echo "$ cat /etc/named.boot"
	cat /etc/named.boot |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	fHR
	echo "$ cat /etc/named.conf"
	cat /etc/named.conf |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	fHR
	echo "$ cat /etc/bind/named.boot"
	cat /etc/bind/named.boot |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	fHR
	echo "$ cat /etc/bind/named.conf"
	cat /etc/bind/named.conf |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	fHR
	echo "$ cat /etc/bind/named.conf.options"
	cat /etc/bind/named.conf.options |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
fDumpE
#-----------------------------------------------------------
fDumpS "SRV-062"
	$Echo "$ck_dns"
	echo "$ grep version /etc/named.conf"
	grep version /etc/named.conf
	fHR
	echo "$ grep version /etc/bind/named.conf"
	grep version /etc/named.conf
fDumpE
#-----------------------------------------------------------
fDumpS "SRV-063"
	$Echo "$ck_dns"
	echo "$ cat /etc/named.boot"
	cat /etc/named.boot |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	fHR
	echo "$ cat /etc/named.conf"
	cat /etc/named.conf |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	fHR
	echo "$ cat /etc/bind/named.boot"
	cat /etc/bind/named.boot |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	fHR
	echo "$ cat /etc/bind/named.conf"
	cat /etc/bind/named.conf |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	fHR
	echo "$ cat /etc/bind/named.conf.options"
	cat /etc/bind/named.conf.options |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
fDumpE
#-----------------------------------------------------------
fDumpS "SRV-064"
	$Echo "$ck_dns"
	echo "$ dig @localhost +short porttest.dns-oarc.net TXT"
	dig @localhost +short porttest.dns-oarc.net TXT
fDumpE
#------------------------------------------------------------
fDumpS "SRV-065"
	$Echo "$ck_nis"
	$Echo "$ck_ypbind"
fDumpE
#------------------------------------------------------------
fDumpS "SRV-066"
	$Echo "$ck_dns"
	echo "$ cat /etc/named.boot"
	cat /etc/named.boot |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	fHR
	echo "$ cat /etc/named.conf"
	cat /etc/named.conf |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	fHR
	echo "$ cat /etc/bind/named.boot"
	cat /etc/bind/named.boot |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	fHR
	echo "$ cat /etc/bind/named.conf"
	cat /etc/bind/named.conf |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	fHR
	echo "$ cat /etc/bind/named.conf.options"
	cat /etc/bind/named.conf.options |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
fDumpE
#------------------------------------------------------------
## 2013.01 removed in newcode
# fDumpS "SAM-001"
	# echo "$ ps -ef | grep named | grep -v grep"
	# echo "$named"
	# fHR
	# echo "$ grep fake-iquery /etc/named.conf /etc/named.boot"
	# grep fake-iquery /etc/named.conf /etc/named.boot
# fDumpE
#------------------------------------------------------------
## NOW
fDumpS "SRV-068"
	echo " $ cat /etc/shadow | awk -F: '{print \$1\"\\t\\t\"\$2}' | cut -c-15"
	cat /etc/shadow | awk -F: '{print $1"\t\t"$2}' | cut -c-15
	if [ $OS = "AIX" ]; then
		fHR
		echo "$ egrep \"password\" -B 2 /etc/security/passwd"
		egrep "password" -B 2 /etc/security/passwd
	fi
fDumpE
#------------------------------------------------------------
fDumpS "SRV-160"
	echo "$ awk -F\":\" '{print \$1 \"\\t\\t\" \$7}' /etc/passwd"
	awk -F":" '{print $1 "\t\t" $7}' /etc/passwd
	fHR
	for EnableUser in $lsEnableUser
	do
		EnableUser=`echo "$EnableUser" | awk -F":" '{print $1}'`
		echo "$ last -10 $EnableUser"
		last -10 "$EnableUser" |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
		fHR
	done
	for EnableUser in $lsEnableUser
	do
		EnableUser=`echo "$EnableUser" | awk -F":" '{print $1}'`
		if [ "$OS" = "AIX" ]; then
			echo "$ lsuser -a time_last_login $EnableUser"
			lsuser -a time_last_login "$EnableUser" |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
			fHR
		elif [ "$OS" = "Linux" ]; then
			echo "$ lastlog -u $EnableUser"
			lastlog -u "$EnableUser" |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
			fHR
		fi
	done
	if [ "$OS" = "HP-UX" ]; then
		echo "$ /usr/sbin/acct/fwtmp < /var/adm/wtmp | tail -n 10000"
		/usr/sbin/acct/fwtmp < /var/adm/wtmp | tail -n 10000
		fHR
	fi
	echo "$ $CMD_LASTLOG"
	$CMD_LASTLOG
fDumpE
#	if [ $OS = "AIX" ]; then
#		for hfile in $CMD_LASTLOG; do
#			haccount=`echo $hfile | awk -F"=" '{print $2}' | grep "[a-zA-Z0-9]"`
#			hpwdate=`./pwchange -p2 $haccount`
#			echo "$hfile\\t\\t $hpwdate"
#		done
#	fi
#
#	CMD_LASTLOG="lsuser -a time_last_login ALL"

#fDumpS "SRV-070"
#	echo "$ awk -F\":\" '{print \$1 \"\\t\\t\" \$2}' /etc/passwd"
#	awk -F":" '{print $1 "\t\t" $2}' /etc/passwd


 #   if [ $OS = "SunOS" ]; then
#		fHR
#		CMD_SHADOW=`cat /etc/shadow`

#	for hfile in $CMD_SHADOW; do
#		haccount=`echo $hfile | awk -F":" '{print $1}' | grep "[a-zA-Z0-9]"`
#			hpwdate=`./pwchange -p1 $hpwchange`
#		echo "$haccount\\t\\t $hpwdate"
#	done
#	fi

#fDumpE
#------------------------------------------------------------
#fDumpS "SRV-071: 각 계정별 고유 UID 미사용/안전하지 않은 UID 사용"
#	echo "$ sort -t : -n +2 -3 /etc/passwd | awk -F\":\" \
#		'{ print \$1 \"\\t\\t\" \$3}'"
#	sort -t : -n +2 -3 /etc/passwd | awk -F":" '{ print $1 "\t\t" $3}'
#	fHR
#	echo "$ $CMD_PWCK"
#	$CMD_PWCK
#fDumpE
#------------------------------------------------------------
fDumpS "SRV-070"
	echo "$ cat /etc/passwd"
	cat /etc/passwd
fDumpE
#------------------------------------------------------------
fDumpS "SRV-074"
	if [ -f /etc/shadow ]; then
		echo "$ awk -F\":\" '{print \$1 \"\\t\\t\" \$3}' /etc/shadow"
		awk -F":" '{print $1 "\t\t" $3}' /etc/shadow
	else
		echo "$ cat /etc/passwd"
		cat /etc/passwd
	fi

	if [ $OS = "AIX" ]; then
		fHR
		echo "$ egrep \":|lastupdate\" /etc/security/passwd"
		egrep ":|lastupdate" /etc/security/passwd
	fi

	if [ $OS = "HP-UX" ]; then
		fHR
		echo "$ passwd -sa"
		passwd -sa
		fHR
		if [ -d /tcb/files/auth ]; then
			dirs=`ls /tcb/files/auth`
			for dir in $dirs; do
				users=`ls /tcb/files/auth/$dir`
				for user in $users; do
					echo "$ cat /tcb/files/auth/$dir/$user"
					cat /tcb/files/auth/$dir/$user  |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
					fHR
				done
			done
		fi
	fi
fDumpE
#------------------------------------------------------------
fDumpS "SRV-075 SRV-076"
	echo "$ $CMD_PASSSEC"
	$CMD_PASSSEC
fDumpE
#------------------------------------------------------------
fDumpS "SRV-077"
	echo "$ awk -F\":\" '{print \$1 \"\\t\\t\" \$2}' /etc/passwd"
	awk -F":" '{print $1 "\t\t" $2}' /etc/passwd
fDumpE
#------------------------------------------------------------
fDumpS "SRV-081"
	if [ -d /var/spool/cron/crontabs/ ];then
		echo " $ ls -alL /var/spool/cron/crontabs"
		ls -alL /var/spool/cron/crontabs
	else
		echo " $ ls -alL /var/spool/cron"
		ls -alL /var/spool/cron
	fi
fDumpE
#------------------------------------------------------------
fDumpS "SRV-082"
	echo " $ ls -alLd /usr /bin /sbin /etc /var"
	ls -alLd /usr /bin /sbin /etc /var
fDumpE
#------------------------------------------------------------
fDumpS "SRV-083"
	if [ $OS = "AIX" ]; then
		echo "$ grep -v \"^:\" /etc/inittab"
		grep -v "^:" /etc/inittab | sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
		fHR
		echo "$ grep \"^start\" /etc/rc.*"
		grep "^start" /etc/rc.* | sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	else
		echo "$ grep -v \"^#\" /etc/inittab"
		grep -v "^#" /etc/inittab | sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	fi

	fHR
	for ldir in $DIR_STARTUP; do
		echo "$ ls -aldL $ldir/*"
		ls -aldL $ldir/* | sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
		fHR
	done
fDumpE
#------------------------------------------------------------
## 2013.01 removed in newcode
# fDumpS "SRV-084"
	# files="/etc/passwd /etc/shadow /etc/hosts /etc/xinetd.conf /etc/inetd.conf /etc/syslog.conf /etc/rsyslog.conf /etc/services"
	# for file in $files; do
		# fHR
		# ls -aldL $file
	# done
# fDumpE
#------------------------------------------------------------
#fDumpS "SRV-085: 임시 디렉토리 권한 설정 오류"
#	echo "$ ls -aldL /tmp"
#	ls -aldL /tmp
#fDumpE
#------------------------------------------------------------
fDumpS "SRV-084"
	echo " $ ls -aldL /etc/passwd"
	ls -aldL /etc/passwd
fDumpE
#------------------------------------------------------------
fDumpS "SRV-085"
	if [ $OS = "AIX" ]; then
		echo "$ ls -aldL /etc/security/passwd"
		ls -aldL /etc/security/passwd
	else
		echo "$ ls -aldL /etc/shadow"
		ls -aldL /etc/shadow
	fi
fDumpE
#------------------------------------------------------------
fDumpS "SRV-086"
	echo " $ ls -aldL /etc/hosts"
	ls -aldL /etc/hosts
fDumpE
#------------------------------------------------------------
fDumpS "SRV-087"
	echo " $ which cc gcc"
	hfiles=`which cc`
	for hfile in $hfiles; do
		if [ $hfile = "no" -o $hfile = "which:" ]; then
			echo $hfiles
			break
		fi
		ls -alL $hfile
		hsym=`ls -alL $hfile | awk '{print $1}' | grep "[a-zA-Z0-9]"`
		if [ `echo $hsym | cut -c1-1` = "l" ]; then
			hsym_=`ls -alL $hfile | awk '{print $11}' | grep "[a-zA-Z0-9]"`
			if [ `echo $hsym_ | cut -c1-2` = ".." ]; then
				hsym1=`ls -alL $hfile | awk '{print $9}' | sed -e 's/\/[a-z]*\/cc//' | grep "[a-zA-Z0-9]"`
				hsym2=`ls -alL $hfile | awk '{print $11}' | sed -e 's/..//' | grep "[a-zA-Z0-9]"`
				ls -alL "$hsym1$hsym2"
			else
				hsymorg=`ls -alL $hfile | awk '{print $11}' | grep "[a-zA-Z0-9]"`
				ls -alL $hsymorg
			fi
		fi
	done
	hfiles=`which gcc`
	for hfile in $hfiles; do
		if [ $hfile = "no" -o $hfile = "which:" ]; then
			echo $hfiles
			break
		fi
		ls -alL $hfile
		hsym=`ls -alL $hfile | awk '{print $1}' | grep "[a-zA-Z0-9]"`
		if [ `echo $hsym | cut -c1-1` = "l" ]; then
			hsymorg=`ls -alL $hfile | awk '{print $11}' | grep "[a-zA-Z0-9]"`
			ls -alL $hsymorg
		fi
	done
	fHR
	echo "$ ls -alL /usr/bin/cc /usr/bin/gcc /usr/ucb/cc /usr/ccs/bin/cc \
		/opt/ansic/bin/cc /usr/vac/bin/cc /usr/local/bin/gcc"
	ls -alL /usr/bin/cc /usr/bin/gcc /usr/ucb/cc /usr/ccs/bin/cc \
		/opt/ansic/bin/cc /usr/vac/bin/cc /usr/local/bin/gcc
fDumpE
#------------------------------------------------------------
#fDumpS "SRV-088: 파일시스템 mount nosuid 옵션 미설정"
#	echo "$ mount"
#	mount
#	fHR
#	for hfile in $FILE_MOUNT; do
#		if [ -e $hfile ]; then
#			echo "$ cat $hfile"
#			cat $hfile
#			fHR
#		fi
#	done
#	if [ $OS = "SunOS" ]; then
#		echo "$ cat /etc/rmmount.conf"
#		cat /etc/rmmount.conf
#	fi
#fDumpE
#------------------------------------------------------------
fDumpS "SRV-088"
	echo "$ ls -aldL /etc/inetd.conf /etc/xinetd.conf"
	ls -aldL /etc/inetd.conf /etc/xinetd.conf
fDumpE
#------------------------------------------------------------
fDumpS "SRV-089"
	echo "$ ls -aldL /etc/syslog.conf"
	ls -aldL /etc/syslog.conf
	fHR
	echo "$ ls -aldL /etc/rsyslog.conf"
	ls -aldL /etc/rsyslog.conf
fDumpE

#------------------------------------------------------------
fDumpS "SRV-092"
# uid of home dir is incorrect
PWDLINE=""
USER=""
USERID=""
USERHOME=""
HOMEID=""
if [ $OS = "HP-UX" ]; then
	for PWDLINE in `awk -F":" '{print $1":"$3":"$6":"$7 }' /etc/passwd | egrep 'sh$' | egrep -v ':nosh'  | sort -u`
	do
			USER=`echo $PWDLINE | awk -F":" '{print $1}'`
			USERID=`echo $PWDLINE | awk -F":" '{print $2}'`
			USERHOME=`echo $PWDLINE | awk -F":" '{print $3}'`
			if [ -d $USERHOME ]; then
				HOMEID=`ls -nd $USERHOME | awk '{print $3}'`
				if [ -z "$HOMEID" ]; then
					HOMEID=0
				fi
				if [ $USERID -a $HOMEID ]; then
						if [ $USERID != $HOMEID ]; then
								if [ $USERID -ge 500 ]; then
								echo "$USER : $USERHOME : current($HOMEID) - expected($USERID)"
								fHR
								fi
						fi
				fi
			fi
	done
else
	for PWDLINE in `awk -F":" '{print $1":"$3":"$6":"$7 }'  /etc/passwd | egrep 'sh$' | egrep -v ':nosh'  | sort -u`
	do
			USER=`echo $PWDLINE | awk -F":" '{print $1}'`
			USERID=`echo $PWDLINE | awk -F":" '{print $2}'`
			USERHOME=`echo $PWDLINE | awk -F":" '{print $3}'`
			if [ -d $USERHOME ]; then
				HOMEID=`ls -nd $USERHOME | awk '{print $3}'`
				if [ -z $HOMEID ]; then
					HOMEID=0
				fi
				if [ $USERID -a $HOMEID ]; then
						if [ $USERID != $HOMEID ]; then
								if [ $USERID -ge 500 ]; then
								echo "$USER : $USERHOME : current($HOMEID)-> expected($USERID)"
								fHR
								fi
						fi
				fi
			fi
	done
fi
fDumpE

#------------------------------------------------------------
fDumpS "SRV-094"
# world writable file referenced in crontab file
	if [ -d /var/spool/cron/crontabs/ ];then
		REFLIST=`cat /var/spool/cron/crontabs/* | egrep ".sh|.pl" | awk '{print $6}' `
	else
		REFLIST=`cat /var/spool/cron/* | egrep ".sh|.pl" | awk '{print $6}' `
	fi
	for file in $REFLIST
	do
		if [ -f $file ];then
			echo " $ ls -alL $file | awk '{print $1 " : " $NF}'"
			ls -alL $file | awk '{print $1 " : " $NF}'
			fHR
		fi
	done
fDumpE

#------------------------------------------------------------
fDumpS "SRV-096"
	#HOMEDIR=`awk -F":" '{print $6}' /etc/passwd`
	for dir in $HOMEDIR; do
		if [ $dir != "/" -a $dir != "/root" ]; then
			hfiles=`ls -alL $dir | awk -F" " '{print $9}' | grep "^[.][a-zA-Z0-9]"`
			for hfile in $hfiles; do
				echo "$ ls -aldL $dir/$hfile"
				ls -aldL $dir/$hfile
				fHR
			done
		fi
	done
	if [ $OS = "Linux" ]; then
		hfiles=`ls -alL /root | awk -F" " '{print $9}' | grep "^[.][a-zA-Z0-9]"`
		for hfile in $hfiles; do
			echo "$ ls -aldL /root/$hfile"
			ls -aldL /root/$hfile
			fHR
		done
	else
		hfiles=`ls -alL / | awk -F" " '{print $9}' | grep "^[.][a-zA-Z0-9]"`
		for hfile in $hfiles; do
			echo "$ ls -aldL /$hfile"
			ls -aldL /$hfile
			fHR
		done
	fi

fDumpE
#------------------------------------------------------------
fDumpS "SRV-099"
	echo "$ ls -aldL /etc/services"
	ls -aldL /etc/services
fDumpE
#------------------------------------------------------------
fDumpS "SRV-100"
	PathXterm=`which xterm`
	echo "$ ls -aldL $PathXterm"
	ls -aldL "$PathXterm"
fDumpE
#------------------------------------------------------------
fDumpS "SRV-106"
	echo "$ ls -aldL /etc/hosts.lpd"
	ls -aldL /etc/hosts.lpd
fDumpE
#------------------------------------------------------------
fDumpS "SRV-161"
	$Echo "$ck_ftp"
	for hfile in $FILE_FTPUSERS; do
		echo "$ ls -alL $hfile"
		ls -alL $hfile
		fHR
	done
fDumpE
#------------------------------------------------------------
fDumpS "SRV-107"
	FILE_ATALLOW=""
	FILE_ATDENY=""
	if [ $OS = "AIX" -o $OS = "HP-UX" ]; then
		FILE_ATALLOW="/var/adm/cron/at.allow"
		FILE_ATDENY="/var/adm/cron/at.deny"
	elif [ $OS = "Linux" ]; then
		FILE_ATALLOW="“/etc/at.allow"
		FILE_ATDENY="/etc/at.deny"
	elif [ $OS = "SunOS" ]; then
		FILE_ATALLOW="/etc/cron.d/at.allow"
		FILE_ATDENY="/etc/cron.d/at.deny"
	elif [ $OS = "OSF1" ]; then
		FILE_ATALLOW=""
		FILE_ATDENY=""
	fi
	echo "$ ls -aldL $FILE_ATALLOW"
	ls -aldL "$FILE_ATALLOW"
	fHR
	echo "$ ls -aldL $FILE_ATDENY"
	ls -aldL "$FILE_ATDENY"
fDumpE
#------------------------------------------------------------
fDumpS "SRV-108"
	for ldir in $DIR_LOG; do
		echo "$ ls -aldL $ldir/*"
		ls -aldL $ldir/*
		fHR
	done
fDumpE
#------------------------------------------------------------
fDumpS "SRV-162"
	if [ $OS = "SunOS" ]; then
		echo "$ egrep 'SULOG|SYSLOG' /etc/default/su"
		egrep "SULOG|SYSLOG" /etc/default/su
	elif [ $OS = "Linux" ]; then
		echo "$ grep rootok /etc/pam.d/su"
		grep rootok /etc/pam.d/su
	else
		echo "해당사항없음"
	fi
fDumpE

if [ $OS = "SunOS" ]; then
#------------------------------------------------------------
fDumpS "SRV-112"
	echo "$ $CMD_CRONLOG"
	$CMD_CRONLOG
fDumpE
#------------------------------------------------------------
fDumpS "SRV-114"
	echo "ls -alL /var/adm/loginlog"
	ls -alL /var/adm/loginlog  |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	fHR
	echo "cat /var/adm/loginlog"
	cat /var/adm/loginlog  |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
fDumpE
fi
#------------------------------------------------------------
fDumpS "SRV-115"
	for ldir in $DIR_LOG; do
		echo "$ ls -aldL $ldir/*"
		ls -aldL $ldir/*
		fHR
	done
fDumpE
#------------------------------------------------------------
fDumpS "SRV-118"
	uname -a
	echo "ref : id - patch"
fDumpE
#------------------------------------------------------------
fDumpS "SRV-121"
	echo "$ echo \$PATH"
	echo $PATH
	fHR
	if [ -f /etc/PATH ]; then
		echo "$ cat /etc/PATH"
		cat /etc/PATH | sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
		fHR
	fi
	PrintAllCommonConf "(PATH|pathmunge)"
fDumpE
#------------------------------------------------------------
fDumpS "SRV-122"
	echo "$ umask"
	umask
	fHR
	PrintRootCommonConf "(UMASK|unamk)"
	fHR
	if [ $OS = "AIX" ]; then
		echo "$ cat /etc/security/user | egrep -v "^$" | egrep -v "^\*" | egrep -i \"(root|umask)\""
		cat /etc/security/user | egrep -v "^$" | egrep -v "^\*" | egrep -i "(root|umask)"
	elif [ $OS = "HP-UX" ]; then
		echo "$ cat /etc/default/security | egrep -i umask"
		cat /etc/default/security | egrep -i umask
	fi
fDumpE
#------------------------------------------------------------
fDumpS "SRV-127"
	if [ "$CMD_LOGIN" ]; then
		echo "$ $CMD_LOGIN"
		$CMD_LOGIN
		fHR
	fi
	if [ "$CMD_LOGIN" ]; then
		echo "$ $CMD_LOGIN2"
		$CMD_LOGIN2
		fHR
	fi
	if [ "$CMD_LOGIN" ]; then
		echo "$ $CMD_LOGIN3"
		$CMD_LOGIN3
		fHR
	fi
	if [ "$CMD_LOGIN" ]; then
		echo "$ $CMD_LOGIN4"
		$CMD_LOGIN4
		fHR
	fi
	if [ "$CMD_LOGIN" ]; then
		echo "$ $CMD_LOGIN5"
		$CMD_LOGIN5
		fHR
	fi
	if [ "$CMD_PAM1" ]; then
		echo "$ $CMD_PAM1"
		$CMD_PAM1
		fHR
	fi
	if [ "$CMD_PAM2" ]; then
		echo "$ $CMD_PAM2"
		$CMD_PAM2
		fHR
	fi
	if [ "$CMD_PAM3" ]; then
		echo "$ $CMD_PAM3"
		$CMD_PAM3
	fi
fDumpE
#------------------------------------------------------------
fDumpS "SRV-163"
	$Echo "$ck_telnet"
	echo "$ cat /etc/motd"
	cat /etc/motd  |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	fHR
	if [ $OS = "AIX" ]; then
		echo "$ cat /etc/security/login.cfg"
		cat /etc/security/login.cfg  |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	elif [ $OS = "Linux" ]; then
		echo "$ cat /etc/issue"
		cat /etc/issue  |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
		fHR
		echo "$ cat /etc/issue.net"
		cat /etc/issue.net  |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	elif [ $OS = "SunOS" ]; then
		echo "$ cat /etc/issue"
		cat /etc/issue  |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
		fHR
		echo "$ cat /etc/default/telnetd"
		cat /etc/default/telnetd | egrep -i "banner" |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	elif [ $OS = "HP-UX" ]; then
		echo "$ cat /etc/issue"
		cat /etc/inetd.conf | grep "/etc/issue"
		fHR
		echo "$ cat /etc/issue"
		cat /etc/issue  |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	fi
fDumpE
#------------------------------------------------------------
fDumpS "SRV-130"
	PrintAllCommonConf "(UMASK|unamk)"
	fHR
	if [ $OS = "AIX" ]; then
		echo "$ cat /etc/security/user | egrep -v "^$" | egrep -v "^\*" | egrep -i \"(default|umask)\""
		cat /etc/security/user | egrep -v "^$" | egrep -v "^\*" | egrep -i "(default|umask)"
	elif [ $OS = "Linux" ]; then
		echo "$ cat /etc/login.defs | egrep -i \"umask\""
		cat /etc/login.defs | egrep -i "umask"
	elif [ $OS = "HP-UX" ]; then
		echo "$ cat /etc/skel/.profile | egrep -i \"umask\""
		cat /etc/skel/.profile | egrep -i "umask"
	fi
fDumpE
#------------------------------------------------------------
fDumpS "SRV-131"
	CMD_WHICHSU=`which su 2>&1 | grep -v ":"`
	if [ $CMD_WHICHSU ]; then
		echo "$ ls -alL $CMD_WHICHSU"
		ls -alL $CMD_WHICHSU
	else
		echo "$ ls -alL /usr/bin/su"
		ls -alL /usr/bin/su
		fHR
		echo "$ ls -alL /bin/su"
		ls -alL /bin/su
	fi
	fHR
	echo "$ $CMD_SUGROUP"
	$CMD_SUGROUP
	fHR
	if [ $OS = "Linux" -o $OS = "AIX" -o $OS = "HP-UX" ]; then
		echo "$ $CMD_SUGROUP"
		$CMD_SUGROUP
		fHR
	fi
	echo "$ cat /etc/group"
	cat /etc/group
fDumpE
#------------------------------------------------------------
fDumpS "SRV-132"
	for hfile in $FILE_CRONUSER; do
		echo "$ ls -alL $hfile"
		ls -alL $hfile
		fHR
	done
fDumpE
#------------------------------------------------------------
fDumpS "SRV-133"
	for hfile in $FILE_CRONUSER; do
		#if [ -e $hfile ]; then
			echo "$ cat $hfile"
			cat $hfile  |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
			fHR
		#fi
	done
	if [ -d /var/spool/cron/crontabs/ ];then
		echo " $ ls -alL /var/spool/cron/crontabs"
		fHR
		ls -alL /var/spool/cron/crontabs
	else
		echo " $ ls -alL /var/spool/cron"
		fHR
		ls -alL /var/spool/cron
	fi
fDumpE
#------------------------------------------------------------

if [ $OS = "SunOS" ]; then
	#------------------------------------------------------------
	fDumpS "SRV-134"
		echo "$ grep noexec_user_stack /etc/system"
		grep noexec_user_stack /etc/system
	fDumpE #------------------------------------------------------------
	#fDumpS "SRV-134: 전원관리 권한 설정 오류(SunOS)"
	#	echo "$ grep PERMS /etc/default/sys-suspend"
	#	grep PERMS /etc/default/sys-suspend
	#	fHR
	#	echo "$ grep SunPowerSwitch /usr/openwin/lib/speckeysd.map"
	#	grep SunPowerSwitch /usr/openwin/lib/speckeysd.map
	#fDumpE
	#------------------------------------------------------------
	fDumpS "SRV-135"
		echo "$ grep TCP_STRONG_ISS /etc/default/inetinit"
		grep TCP_STRONG_ISS /etc/default/inetinit
	fDumpE
fi

#------------------------------------------------------------
fDumpS "SRV-142"
	echo "$ cat /etc/passwd | awk -F\":\" '$3==0 { print $1 \" -> UID=\" $3 }'"
	cat /etc/passwd | awk -F":" '$3==0 { print $1 " -> UID=" $3 }'
fDumpE

#------------------------------------------------------------
fDumpS "SRV-143"
	echo "$ cat /etc/passwd | awk -F\":\" '{print $1\":\"$3}'"
	cat /etc/passwd | awk -F":" '{print $1":"$3}'
fDumpE

#------------------------------------------------------------
fDumpS "SRV-091"
# setuid file
	#HOMEDIR=`cat /etc/passwd | egrep -v ":nosh" | grep "sh$" | awk -F":" '{print $6}' | sort -u`
	TMP_HOMEDIR=""
	for dir in $HOMEDIR
	do
		if [ $dir != "/" -a $dir != "/root" -a -d $dir ]; then
			TMP_HOMEDIR=`echo $TMP_HOMEDIR" "``echo $dir`;
		fi
	done
	echo " $ nice -n 5 find \$HOMEDIR -type f -a -perm -4000 -exec ls -alLd {} \;"
	nice -n 5 find $TMP_HOMEDIR -type f -a -perm -4000 -exec ls -alLd {} \; 2>/dev/null
	fHR
	for hfile in $FILE_SETUID; do
		echo " $ ls -alL $hfile"
		ls -alL $hfile
	done
fDumpE

#------------------------------------------------------------
fDumpS "SRV-093"
# world writable file in userpath
#HOMEDIR=`cat /etc/passwd | egrep -v ":nosh" | grep "sh$" | awk -F":" '{print $6}' | sort -u`
TMP_HOMEDIR=""
for dir in $HOMEDIR
do
	if [ $dir != "/" -a $dir != "/root" -a -d $dir ]; then
		TMP_HOMEDIR=`echo $TMP_HOMEDIR" "``echo $dir`;
	fi
done
echo " $ nice -n 5 find \$HOMEDIR -perm -2 -type f -exec ls -alL {} \; 2>/dev/null"
nice -n 5 find $TMP_HOMEDIR -perm -2 -type f -exec ls -alL {} \; 2>/dev/null | egrep '\.sh|\.log|\.pl'
fDumpE

#------------------------------------------------------------
fDumpS "SRV-095"
	#HOMEDIR=`cat /etc/passwd | egrep -v ":nosh" | grep "sh$" | awk -F":" '{print $6}' | sort -u `
	echo " $ nice -n 5 find \$HOMEDIR -type f -a -nouser -nogroup -exec ls -alLd {} \;"
	TMP_HOMEDIR=""
	for dir in $HOMEDIR
	do
		if [ $dir != "/" -a $dir != "/root" -a -d $dir ]; then
			TMP_HOMEDIR=`echo $TMP_HOMEDIR" "``echo $dir`;
		fi
	done
	nice -n 5 find $TMP_HOMEDIR -type f -a -nouser -nogroup -exec ls -alLd {} \; 2>/dev/null
fDumpE

#------------------------------------------------------------
fDumpS "SRV-144"
	echo " $ nice -n 5 find /dev -type f -exec ls -l {} \; 2>/dev/null"
	nice -n 5 find /dev -type f -exec ls -l {} \; 2>/dev/null
fDumpE

#------------------------------------------------------------
fDumpS "SRV-164"
	echo "$ cat /etc/group | awk 'BEGIN {FS=":"} $4=="" {print}'"
	cat /etc/group | awk 'BEGIN {FS=":"} $4=="" {print}'
fDumpE

#------------------------------------------------------------
fDumpS "SRV-165"
	echo "$ cat /etc/passwd | awk '/^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher/'"
	cat /etc/passwd | awk '/^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher/'
fDumpE

#------------------------------------------------------------
fDumpS "SRV-145"
	echo "$ cat /etc/passwd | awk 'BEGIN {FS="/"} $2!="home" {print}'"
	cat /etc/passwd | awk 'BEGIN {FS="/"} $2!="home" {print}'
fDumpE

#------------------------------------------------------------
# fDumpS "SRV-166"
# 	echo "$ nice -n 5 find / -name ".*" -type f -exec ls -alL {} \; 2>/dev/null"
#	nice -n 5 find / -name ".*" -type f -exec ls -alL {} \; 2>/dev/null
# fDumpE

#------------------------------------------------------------
fDumpS "SRV-158"
	$Echo "$ck_telnet"
fDumpE

#------------------------------------------------------------
fDumpS "SRV-167"
	$Echo "$ck_ftp"
fDumpE

#------------------------------------------------------------
fDumpS "SRV-146"
	echo "$ cat /etc/passwd | awk '/ftp/' | awk 'BEGIN {FS=":"} $7!="/bin/false" {print}'"
	cat /etc/passwd | awk '/ftp/' | awk 'BEGIN {FS=":"} $7!="/bin/false" {print}'
fDumpE

#------------------------------------------------------------
fDumpS "SRV-147"
	$Echo "$ck_snmp"
fDumpE

#------------------------------------------------------------
fDumpS "SRV-148"
	$Echo "$ck_apache"
	if [ -f "$webconf_file" ]; then
		echo "$ cat $webconf_file | egrep 'ServerTokens|Prod'"
		cat "$webconf_file" | egrep "ServerTokens|Prod"
	else
		echo "cannot open file"
	fi
fDumpE

#------------------------------------------------------------
fDumpS "SRV-168"
	echo "$ cat /etc/syslog.conf"
	cat /etc/syslog.conf
	fHR
	echo "$ cat /etc/rsyslog.conf"
	cat /etc/rsyslog.conf
fDumpE

#------------------------------------------------------------
fDumpS "HOMEDIR"
	echo "$ grep sh /etc/passwd"
	grep sh /etc/passwd
	fHR
	echo "$ ls -aldL `grep sh /etc/passwd | awk -F":" '{print $6}'`"
	ls -aldL `grep sh /etc/passwd | awk -F":" '{print $6}'`
fDumpE

#------------------------------------------------------------
fDumpS "CRONTAB"
	echo "nice -n 5 find /etc/ -type f -perm -2 -exec ls -alL {} \;"
	nice -n 5 find /etc/ -type f -perm -2 -exec ls -alL {} \; 2>/dev/null
fDumpE

#------------------------------------------------------------
# fDumpS "SSP-001"

		# echo "ps -ef | egrep 'seos|seagent|seoswd|selogrd'"
		# ps -ef | egrep 'seos|seagent|seoswd|selogrd'

# fDumpE

#------------------------------------------------------------
for hfile in $FILE_ALL; do
	fDumpS "$hfile"
		echo "$ cat $hfile"
		if [ $OS = "Linux" ]; then
			#cat $hfile | sed -e '/\x0c/d' |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
			cat $hfile | egrep -v "[^[:print:][:blank:]]" |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
		else
			cat $hfile | sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
		fi
	fDumpE
done

#------------------------------------------------------------
fDumpS "TCB"
	if [ $OS = "HP-UX" ]; then
		if [ -d /tcb/files/auth ]; then
			dirs=`ls /tcb/files/auth`
			for dir in $dirs; do
				users=`ls /tcb/files/auth/$dir`
				for user in $users; do
					echo "$ cat /tcb/files/auth/$dir/$user"
					cat /tcb/files/auth/$dir/$user  |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
					fHR
				done
			done
		fi
	elif [ $OS = "OSF1" ]; then
		echo "$ edauth -gv"
		edauth -gv
	fi
fDumpE

#------------------------------------------------------------
fDumpS "user_rhosts"
	#HOMEDIR=`awk -F":" '{print $6}' /etc/passwd`
	for dir in $HOMEDIR; do
		if [ -n $dir ]; then
			hfiles=`ls -alL $dir | awk -F" " '{print $9}' | grep "\.rhosts"`
			for hfile in $hfiles; do
				echo "$ ls -aldL $dir/$hfile"
				ls -aldL $dir/$hfile
				fHR
				echo "$ cat $dir/$hfile"
				cat $dir/$hfile  |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
				fHR
			done
		fi
	done
fDumpE

#------------------------------------------------------------
fDumpS "netrc"
	#HOMEDIR=`awk -F":" '{print $6}' /etc/passwd`
	for dir in $HOMEDIR; do
		if [ -n $dir ]; then
			hfiles=`ls -alL $dir | awk -F" " '{print $9}' | grep "\.netrc"`
			for hfile in $hfiles; do
				echo "$ ls -aldL $dir/$hfile"
				ls -aldL $dir/$hfile
				fHR
				echo "$ cat $dir/$hfile"
				cat $dir/$hfile  |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
				fHR
			done
		fi
	done
fDumpE

#------------------------------------------------------------
fDumpS "user_history"
	#HOMEDIR=`awk -F":" '{print $6}' /etc/passwd`
	for dir in $HOMEDIR; do
		if [ -n $dir ]; then
			hfiles=`ls -alL $dir | awk -F" " '{print $9}' | grep "\.history"`
			for hfile in $hfiles; do
				echo "$ ls -aldL $dir/$hfile"
				ls -aldL $dir/$hfile
				fHR
				echo "$ cat $dir/$hfile"
				cat $dir/$hfile  |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
				fHR
			done
		fi
	done
fDumpE

#------------------------------------------------------------
fDumpS "tcpwrapper"
	files="/etc/hosts /etc/hosts.equiv /etc/hosts.allow /etc/hosts.deny"
	for file in $files; do
		echo "$ ls -aldL $file"
		ls -aldL $file
		fHR
		echo "$ cat $file"
		cat $file  |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
		fHR
	done
fDumpE

#------------------------------------------------------------
fDumpS "patch"
	echo "$ $CMD_PATCHINFO"
	$CMD_PATCHINFO | sed "s/&/\&amp;/g" | sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
fDumpE

#------------------------------------------------------------
fDumpS "security_conf"
	if [ $OS = "AIX" ]; then
		echo "$ cat /etc/security/user"
		cat /etc/security/user
		fHR
	elif [ $OS = "Linux" ]; then
		echo "$ cat /etc/securetty"
		cat /etc/securetty
		fHR
		echo "$ cat /etc/pam.d/remote"
		cat /etc/pam.d/remote"
		fHR
		echo "$ cat /etc/pam.d/login"
		cat /etc/pam.d/login
		fHR
	elif [ $OS = "HP-UX" ]; then
		cat /etc/securetty
		fHR
	elif [ $OS = "SunOS" ]; then
		cat /etc/default/login
		fHR
	elif [ $OS = "OSF1" ]; then
		cat /etc/securettys"
		fHR
	fi
fDumpE

#------------------------------------------------------------
fDumpS "sshd_conf"
	for SSHD_CONF in $FILE_SSHD_CONF; do
		echo "$ $SSHD_CONF"
		cat $SSHD_CONF
		fHR
	done
fDumpE

#------------------------------------------------------------
fDumpS "interfacetable"
	echo "$ netstat -in"
	$Echo "$CMD_INTERFACETABLE" | grep -v "^$" | sed "s/&/\&amp;/g" | sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
fDumpE

#------------------------------------------------------------
fDumpS "nic"
	echo "$ ifconfig -a"
	$CMD_NICINFO | grep -v "^$" | sed "s/&/\&amp;/g" | sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
fDumpE

#------------------------------------------------------------
fDumpS "port"
	if [ $OS = 'Linux' ];then
		echo "$ netstat -anp | egrep -i \"^tcp\" | egrep -i listen"
		netstat -anp | egrep -i "^tcp" | egrep -i listen
		fHR
		echo "$ netstat -anp | egrep -i \"^udp\""
		netstat -anp | egrep -i "^udp"
	elif [ $OS = 'SunOS' ];then
		echo "$ netstat -P tcp -f inet | egrep -i \"(LISTEN|BOUND)\""
		netstat -an -P tcp -f inet | egrep -i "(LISTEN|BOUND)"
		fHR
		echo "$ netstat -P udp -f inet | egrep -i \"(LISTEN|BOUND|IDLE)\""
		netstat -an -P udp -f inet | egrep -i "(LISTEN|BOUND|IDLE)"
	else
		echo "$ netstat -an | egrep -i \"^tcp\" | egrep -i listen"
		netstat -an | egrep -i "^tcp" | egrep -i listen
		fHR
		echo "$ netstat -an | egrep -i \"^udp\""
		netstat -an | egrep -i "^udp"
	fi
fDumpE

#------------------------------------------------------------
fDumpS "netstat"
	if [ $OS = 'Linux' ];then
		echo "$ netstat -anp"
		netstat -anp
	else
		echo "$ netstat -an"
		netstat -an
	fi
fDumpE

#------------------------------------------------------------
fDumpS "rpcinfo"
	echo "$ $CMD_RPCINFO"
	$CMD_RPCINFO | sed "s/&/\&amp;/g" | sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
fDumpE

#------------------------------------------------------------
fDumpS "ps"
	echo "$ ps -ef"
	ps -ef |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
fDumpE

#------------------------------------------------------------
fDumpS "ps_aux"
	if [ $OS = "SunOS" ]; then
		/usr/ucb/ps auxwww |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	else
		ps auxwww |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	fi
fDumpE

#------------------------------------------------------------
fDumpS "(x)inetd"
	echo "$ cat /etc/xinetd.conf | egrep -v \"^#\""
	cat /etc/xinetd.conf | egrep -v "^#" | sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	fHR
	echo "$ cat /etc/xinetd.d/* | egrep -v \"^#\""
	cat /etc/xinetd.d/* | egrep -v "^#" | sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	fHR
	echo "$ /etc/inetd.conf | egrep -v \"^#\""
	cat /etc/inetd.conf | egrep -v "^#" | sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	fHR
	if [ $OS = "SunOS"  ]; then
		if [ $OS_VER = "5.10" -o $OS_VER = "5.11" ]; then
			echo "$ inetadm"
			inetadm | sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
		fi
	elif [ $OS = "AIX"  ]; then
		echo "$ lssrc -ls inetd"
		lssrc -ls inetd | sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	fi
fDumpE

#------------------------------------------------------------
fDumpS "service command"
	if [ $OS = "Linux" ]; then
		echo "$ service --status-all"
		service --status-all | sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	elif [ $OS = "AIX" ]; then
		echo "$ lssrc -a"
		lssrc -a | sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	elif [ $OS_VER = "5.10" -o $OS_VER = "5.11" ]; then
		echo "$ svcs -a"
		svcs -a | sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	fi
fDumpE

#------------------------------------------------------------
if [ $OS = 'Linux' ];then
	fDumpS "chkconfig"
		echo "chkconfig --list"
		chkconfig --list
	fDumpE
fi
#------------------------------------------------------------
fDumpS "webconf"
	if [ -d "$WEBTOBDIR" ]; then
		dir_webtob=`echo "$WEBTOBDIR/config"`
	fi
	if [ -f "$webconf_file" ]; then
		echo "cat $webconf_file"
		cat $webconf_file | sed "s/&/\&amp;/g" | sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	fi
fDumpE
#------------------------------------------------------------

fDumpS "wasconf"
	# Tomcat
	if [ -d "$CATALINA_HOME" ]; then
		echo "ls -alL $CATALINA_HOME/conf"
		ls -alL $CATALINA_HOME/conf
		fHR
		echo "cat $CATALINA_HOME/conf/tomcat-users.xml"
		cat $CATALINA_HOME/conf/tomcat-users.xml  |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
		fHR
	else
		if [ $OS = "SunOS" ]; then
			CATALINA_HOME=`/usr/ucb/ps auxwww | egrep 'catalina\.startup\.Bootstrap' | grep -v grep | awk '{for (i=1;i<=NF;i++) {if ($i ~/(Dcatalina\.home)/) {print $i}}}' | awk -F"=" '{ print $2 }' | grep '^/' | sort -u`
		else
			CATALINA_HOME=`ps auxwww | egrep 'catalina\.startup\.Bootstrap' | grep -v grep | awk '{for (i=1;i<=NF;i++) {if ($i ~/(Dcatalina\.home)/) {print $i}}}' | awk -F"=" '{ print $2 }' | grep '^/' | sort -u`
		fi
		echo "ls -alL $CATALINA_HOME/conf"
		ls -alL "$CATALINA_HOME/conf"
		fHR
		echo "cat $CATALINA_HOME/conf/tomcat-users.xml"
		cat "$CATALINA_HOME/conf/tomcat-users.xml" |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
		fHR
	fi
	# JEUS
	isac_test_var=""
	PrintAllCommonConf "JEUS_HOME"
	fHR
	if [ -d "$isac_test_var" ]; then
		isac_test_var=$isac_test_var
	else
		if [ $OS = "SunOS" ]; then
			isac_test_var=`/usr/ucb/ps auxwww | egrep 'jeus' | grep -v grep | awk '{for (i=1;i<=NF;i++) {if ($i ~/(jeus)/) {print $i}}}' | grep '^/' | egrep 'bin' | sed 's/\/bin.*//g' | sort -u`
		else
			isac_test_var=`ps auxwww | egrep 'jeus' | grep -v grep | awk '{for (i=1;i<=NF;i++) {if ($i ~/(jeus)/) {print $i}}}' | grep '^/' | egrep 'bin' | sed 's/\/bin.*//g' | sort -u`
		fi
	fi
	if [ -d "$isac_test_var" ]; then
		echo "cat $isac_test_var"
		cat "$isac_test_var"
		fHR
	fi
	cfiles="WebMain.xml JeusMain.xml file_realm.xml container.xml"
	cdirs=`ls -alL $JEUS_HOME/config | awk -F" " '{print $9}'`
	for cdir in $cdirs; do
		echo "ls -alL $JEUS_HOME/config/$cdir"
		ls -alL $JEUS_HOME/config/$cdir
		for cfile in $cfiles; do
			if [ -f $JEUS_HOME/config/$cdir/$cfile ]; then
				fHR
				echo "$ cat $JEUS_HOME/config/$cdir/$cfile"
				cat $JEUS_HOME/config/$cdir/$cfile | sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
			fi
		done
	done
fDumpE

#------------------------------------------------------------
fDumpS "ALL_ENV"
	echo "$ env"
	env
	fHR
	echo "$ cat .*profile .*login .*shrc"
	PrintAllCommonConf ".*"
fDumpE

#------------------------------------------------------------
fDumpS "ALL_HOME_DIR"
	echo "$ cat .*profile .*login .*shrc | egrep -i *HOME"
	PrintAllCommonConf "HOME"
	fHR
	echo "$ env | egrep -i *HOME"
	env | egrep -i "HOME"
	fHR
	echo "$ cat .*profile .*login .*shrc | egrep -i DIR"
	PrintAllCommonConf "DIR"
	fHR
	echo "$ env | egrep -i DIR"
	env | egrep -i "DIR"
	fHR
	echo "$ cat .*profile .*login .*shrc | egrep -i BASE"
	PrintAllCommonConf "BASE"
	fHR
	echo "$ env | egrep -i BASE"
	env | egrep -i "BASE"
	fHR
	PrintAllCommonConf "httpd"
	fHR
	echo "$ env | egrep -i httpd"
	env | egrep -i "httpd"
	fHR
	PrintAllCommonConf "htdocs"
	echo "$ env | egrep -i htdocs"
	env | egrep -i "htdocs"
	# Tomcat
	#PrintAllCommonConf "CATALINA_BASE"
	#PrintAllCommonConf "CATALINA_HOME"
	# JEUS
	#PrintAllCommonConf "JEUS_HOME"
	# Apache
	#PrintAllCommonConf "APACHE2_HOME"
	# WEBTOB
	#PrintAllCommonConf "WEBTOBDIR"
fDumpE

#------------------------------------------------------------
fDumpS "Oracle"
	isac_test_var=""
	PrintAllCommonConf "ORACLE_HOME"
	fHR
	#isac_test_var=$(su - oracle -c "echo \$ORACLE_HOME")
	if [ -d "$isac_test_var" ]; then
		isac_test_var=$isac_test_var
	else
		if [ $OS = "SunOS" ]; then
			isac_test_var=`/usr/ucb/ps auxwww | egrep 'tnslsnr' | grep -v grep | awk '{for (i=1;i<=NF;i++) {if ($i ~/(tnslsnr)/) {print $i}}}' | grep '^/' | egrep 'bin' | sed 's/\/bin.*//g' | sort -u |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"`
		else
			isac_test_var=`ps auxwww | egrep 'tnslsnr' | grep -v grep | awk '{for (i=1;i<=NF;i++) {if ($i ~/(tnslsnr)/) {print $i}}}' | grep '^/' | egrep 'bin' | sed 's/\/bin.*//g' | sort -u |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"`
		fi
	fi
	isac_test_var1=$isac_test_var"/network/admin/sqlnet.ora"
	isac_test_var2=$isac_test_var"/network/admin/listener.ora"
	isac_test_var3=$isac_test_var"/network/admin/tnsnames.ora"

	echo "cat $isac_test_var1"
	cat $isac_test_var1
	fHR
	echo "cat $isac_test_var2"
	cat $isac_test_var2
	fHR
	echo "cat $isac_test_var3"
	cat $isac_test_var3
fDumpE

#------------------------------------------------------------
fDumpS "lastlogin"
	echo "$ last -200"
	last -200 |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
	fHR
	if [ "$OS" = "AIX" ]; then
		echo "$ lsuser -a time_last_login ALL"
		lsuser -a time_last_login ALL |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
		fHR
	elif [ "$OS" = "Linux" ]; then
		echo "$ lastlog"
		lastlog |  sed "s/&/\&amp;/g" |  sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"
		fHR
	fi
fDumpE

#------------------------------------------------------------
fDumpS "CheckAllService"
	# Default service
	$Echo "$ck_telnet"
	$Echo "$ck_ftp"
	$Echo "$ck_ssh"
	$Echo "$ck_dns"
	$Echo "$ck_snmp"
	$Echo "$ck_smtp"
	$Echo "$ck_tftp"
	$Echo "$ck_finger"
	$Echo "$ck_echo"
	$Echo "$ck_discard"
	$Echo "$ck_daytime"
	$Echo "$ck_chargen"
	$Echo "$ck_talk"
	$Echo "$ck_ntalk"
	$Echo "$ck_rexec"
	$Echo "$ck_rlogin"
	$Echo "$ck_rsh"
	$Echo "$ck_rsync"
	$Echo "$ck_syslog"
	$Echo "$ck_automount"
	$Echo "$ck_inetd"
	$Echo "$ck_xinetd"
	$Echo "$ck_dmid"

	# RPC
	$Echo "$ck_rpcbind"
	$Echo "$ck_nfs"
	$Echo "$ck_nis"
	$Echo "$ck_ypbind"
	$Echo "$ck_cms"
	$Echo "$ck_ttdbserver"
	$Echo "$ck_sadmin"
	$Echo "$ck_rquota"
	$Echo "$ck_rex"
	$Echo "$ck_stat"
	$Echo "$ck_rstat"
	$Echo "$ck_rusers"
	$Echo "$ck_rwall"
	$Echo "$ck_spray"
	$Echo "$ck_pcnfs"
	$Echo "$ck_kcms_server"
	$Echo "$ck_cachefs"

	# 3Party
	$Echo "$ck_weblogic"
	$Echo "$ck_jeus"
	$Echo "$ck_webtob"
	$Echo "$ck_jboss"
	$Echo "$ck_ibmwebserver"
	$Echo "$ck_apache"
	$Echo "$ck_tomcat"
	$Echo "$ck_wbem"
	$Echo "$ck_hp_data_protector"
fDumpE

#------------------------------------------------------------
fDumpS "Internet"
SITES="103.59.159.20  211.117.39.44" #www.fsec.or.kr  www.google.com

for SITE in $SITES
do
	echo "( echo open $SITE 80; sleep 2; printf \"GET / HTTP/1.1\n\n\"; sleep 1; echo \"\n\"; sleep 1;  echo \"\n\" ) | telnet"
	( echo open $SITE 80; sleep 2; printf "GET / HTTP/1.1\n\n"; sleep 1; echo "\n"; sleep 1;  echo "\n" ) | perl -e 'alarm shift @ARGV; exec @ARGV' 10 telnet | head -30 | sed "s/&/\&amp;/g" | sed "s/</\&lt;/g" | sed "s/>/\&gt;/g"

	echo "\n\n"
	echo "\n\n"
done
fDumpE

#------------------------------------------------------------
fDumpS "date"
	date "+%Y-%m-%d %T"
fDumpE


#------------------------------------------------------------
fDumpS "Encoding"
	FSI_hangulTest
fDumpE

#============================================================
## End
END=`date "+%Y-%m-%d %T"`
fFoot
exec 1>&6 6>&- 2>&7 7>&-
echo "Done."
echo $END
exit 0
#------------------------------------------------------------
## EOF

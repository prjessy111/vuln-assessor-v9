#!/bin/sh
# =========================================================================
# fsi_mysql_ai.sh - MySQL/MariaDB(DBMS) 보안 진단 수집 스크립트 [미검증 템플릿]
# =========================================================================
#  - mysql -N 로 mysql.user / global variables / schemata 등을 조회해 raw(key=value) 수집.
#  - 판정 안 함(verdict_source=none). 판정은 ADV mock 룰(SRV-270~281).
#  - 실 환경 미검증 → coverage=template_unverified. 도커/실서버 출력 대조 후 룰 보정 필요.
#
#  사용 예 (도커 검증):
#    docker run -d -e MYSQL_ROOT_PASSWORD=test1234 -p3306:3306 mysql:8
#    MYSQL_USER=root MYSQL_PASS=test1234 MYSQL_HOST=127.0.0.1 sh fsi_mysql_ai.sh
#  또는:  sh fsi_mysql_ai.sh -u root -p test1234 -h 127.0.0.1 -P 3306
# =========================================================================

MYSQL_USER="${MYSQL_USER:-root}"
MYSQL_PASS="${MYSQL_PASS:-}"
MYSQL_HOST="${MYSQL_HOST:-127.0.0.1}"
MYSQL_PORT="${MYSQL_PORT:-3306}"
OUTDIR="${FSI_OUTPUT_DIR:-.}"
while [ $# -gt 0 ]; do
  case "$1" in
    -u) MYSQL_USER="$2"; shift 2 ;;
    -p) MYSQL_PASS="$2"; shift 2 ;;
    -h) MYSQL_HOST="$2"; shift 2 ;;
    -P) MYSQL_PORT="$2"; shift 2 ;;
    -o|--outdir) OUTDIR="$2"; shift 2 ;;
    *) shift ;;
  esac
done

HOSTNAME=`hostname 2>/dev/null || echo mysql-host`
DATE=`date +%Y%m%d`
mkdir -p "$OUTDIR" 2>/dev/null
OUT="$OUTDIR/${HOSTNAME}-mysql-${DATE}.xml"
MYSQL=`command -v mysql 2>/dev/null`

esc() { sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'; }

run_sql() {
  if [ -z "$MYSQL" ]; then
    echo "DB_CONNECTION_FAILED: mysql client not found (미설치)"
    return
  fi
  MYSQL_PWD="$MYSQL_PASS" "$MYSQL" -N -B -u "$MYSQL_USER" -h "$MYSQL_HOST" -P "$MYSQL_PORT" -e "$1" 2>&1
}

cat > "$OUT" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<script>
    <asset>
        <hostname>${HOSTNAME}</hostname>
        <os>MySQL/MariaDB DBMS</os>
        <whoami>${MYSQL_USER}</whoami>
        <version>fsi_mysql_v1</version>
        <collection_tool>mysql_client</collection_tool>
        <platform>dbms</platform>
        <dbms_type>mysql</dbms_type>
        <data_role>raw_data_provider</data_role>
        <judgment_mode>raw_evidence_only</judgment_mode>
        <verdict_source>none</verdict_source>
        <coverage>template_unverified</coverage>
    </asset>
    <results>
EOF

dump() {
  ID="$1"; DESC="$2"; SQL="$3"
  RES=`run_sql "$SQL" | esc`
  cat >> "$OUT" <<EOF
        <dump>
            <items><id>${ID}</id></items>
            <evidence_profile>
                <evidence_schema>ai_ready_script_v2</evidence_schema>
                <check_ids>${ID}</check_ids>
                <os_family>mysql</os_family>
                <collection_status>collected</collection_status>
                <verdict_source>none</verdict_source>
                <command_marker>sql#</command_marker>
                <raw_begin_marker>RAW_COMMAND_OUTPUT_BEGIN</raw_begin_marker>
                <raw_end_marker>RAW_COMMAND_OUTPUT_END</raw_end_marker>
            </evidence_profile>
            <output><![CDATA[
AI_EVIDENCE_BLOCK_BEGIN
schema=ai_ready_script_v2
check_ids=${ID}
os_family=mysql
command_marker=sql#
command=${DESC}
RAW_COMMAND_OUTPUT_BEGIN
sql# ${DESC}
${RES}
RAW_COMMAND_OUTPUT_END
AI_EVIDENCE_BLOCK_END
            ]]></output>
        </dump>
EOF
}

# ── SRV-270 ~ SRV-281 (금보원 DBMS/MySQL 기준) ──
dump "SRV-270" "익명 계정 수" \
  "SELECT CONCAT('anonymous_users=', COUNT(*)) FROM mysql.user WHERE User='';"
dump "SRV-271" "root 접속 허용 host" \
  "SELECT CONCAT('user=root | host=', Host) FROM mysql.user WHERE User='root';"
dump "SRV-272" "빈 패스워드 계정 수" \
  "SELECT CONCAT('empty_password_users=', COUNT(*)) FROM mysql.user WHERE (authentication_string='' OR authentication_string IS NULL) AND plugin NOT IN ('auth_socket','unix_socket');"
dump "SRV-273" "패스워드 검증 정책" \
  "SELECT CONCAT('validate_password=', IFNULL(MAX(VARIABLE_VALUE),'OFF')) FROM performance_schema.global_variables WHERE VARIABLE_NAME LIKE 'validate_password%policy';"
dump "SRV-274" "test DB 존재" \
  "SELECT CONCAT('test_db_exists=', COUNT(*)) FROM information_schema.schemata WHERE schema_name IN ('test');"
dump "SRV-275" "secure_file_priv" \
  "SELECT CONCAT('secure_file_priv=', IFNULL(@@secure_file_priv,'NULL'));"
dump "SRV-276" "local_infile" \
  "SELECT CONCAT('local_infile=', @@local_infile);"
dump "SRV-277" "general_log" \
  "SELECT CONCAT('general_log=', @@general_log);"
dump "SRV-278" "전송 암호화 강제" \
  "SELECT CONCAT('require_secure_transport=', IFNULL(@@require_secure_transport,'OFF'));"
dump "SRV-279" "광범위 권한(WITH GRANT OPTION) 계정 수" \
  "SELECT CONCAT('grant_all_users=', COUNT(*)) FROM mysql.user WHERE Grant_priv='Y' AND User NOT IN ('mysql.sys','mysql.session','mysql.infoschema','root');"
dump "SRV-280" "버전" \
  "SELECT CONCAT('version()=', VERSION());"
dump "SRV-281" "skip_grant_tables" \
  "SELECT CONCAT('skip_grant_tables=', IFNULL(@@skip_grant_tables,'OFF'));"

cat >> "$OUT" <<EOF
    </results>
</script>
EOF

echo "FSI MySQL scan finished. XML=$OUT (user=$MYSQL_USER, host=$MYSQL_HOST:$MYSQL_PORT, mysql=${MYSQL:-NONE})"
exit 0

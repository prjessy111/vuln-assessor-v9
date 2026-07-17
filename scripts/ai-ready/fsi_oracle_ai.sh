#!/bin/sh
# =========================================================================
# fsi_oracle_ai.sh - Oracle(DBMS) 보안 진단 수집 스크립트 [미검증 템플릿]
# =========================================================================
#  - sqlplus -S 로 v$parameter/dba_users/dba_profiles 등을 조회해 raw(key=value) 증거만 수집.
#  - 스크립트는 판정하지 않음(verdict_source=none). 판정은 ADV mock 룰(SRV-250~262).
#  - 실 Oracle 환경 미검증 → coverage=template_unverified. 실서버/도커에서 출력 대조 후 룰 보정 필요.
#
#  사용 예 (도커 검증):
#    docker run -d -e ORACLE_PASSWORD=test -p1521:1521 gvenzl/oracle-xe
#    ORA_USER=system ORA_PASS=test ORA_CONN=localhost:1521/XEPDB1 sh fsi_oracle_ai.sh
#  또는:  sh fsi_oracle_ai.sh -u system -p test -c localhost:1521/XEPDB1
# =========================================================================

ORA_USER="${ORA_USER:-system}"
ORA_PASS="${ORA_PASS:-}"
ORA_CONN="${ORA_CONN:-localhost:1521/XE}"
OUTDIR="${FSI_OUTPUT_DIR:-.}"
while [ $# -gt 0 ]; do
  case "$1" in
    -u) ORA_USER="$2"; shift 2 ;;
    -p) ORA_PASS="$2"; shift 2 ;;
    -c) ORA_CONN="$2"; shift 2 ;;
    -o|--outdir) OUTDIR="$2"; shift 2 ;;
    *) shift ;;
  esac
done

HOSTNAME=`hostname 2>/dev/null || echo oracle-host`
DATE=`date +%Y%m%d`
mkdir -p "$OUTDIR" 2>/dev/null
OUT="$OUTDIR/${HOSTNAME}-oracle-${DATE}.xml"
SQLPLUS=`command -v sqlplus 2>/dev/null`

esc() { sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g'; }

# sqlplus 실행 헬퍼 — 결과를 그대로 반환. sqlplus 없거나 실패 시 진단신호 남김.
run_sql() {
  if [ -z "$SQLPLUS" ]; then
    echo "DB_CONNECTION_FAILED: sqlplus not found (Oracle client 미설치)"
    return
  fi
  printf "SET HEADING OFF FEEDBACK OFF PAGESIZE 0 LINESIZE 300 TRIMSPOOL ON\nWHENEVER SQLERROR EXIT SQL.SQLCODE\n%s\nEXIT\n" "$1" \
    | "$SQLPLUS" -S -L "${ORA_USER}/${ORA_PASS}@${ORA_CONN}" 2>&1
}

# XML 헤더
cat > "$OUT" <<EOF
<?xml version="1.0" encoding="utf-8"?>
<script>
    <asset>
        <hostname>${HOSTNAME}</hostname>
        <os>Oracle DBMS</os>
        <whoami>${ORA_USER}</whoami>
        <version>fsi_oracle_v1</version>
        <collection_tool>sqlplus</collection_tool>
        <platform>dbms</platform>
        <dbms_type>oracle</dbms_type>
        <data_role>raw_data_provider</data_role>
        <judgment_mode>raw_evidence_only</judgment_mode>
        <verdict_source>none</verdict_source>
        <coverage>template_unverified</coverage>
    </asset>
    <results>
EOF

# dump(id, "설명", "SQL") — 결과를 key=value 로 emit
dump() {
  ID="$1"; DESC="$2"; SQL="$3"
  RES=`run_sql "$SQL" | esc`
  cat >> "$OUT" <<EOF
        <dump>
            <items><id>${ID}</id></items>
            <evidence_profile>
                <evidence_schema>ai_ready_script_v2</evidence_schema>
                <check_ids>${ID}</check_ids>
                <os_family>oracle</os_family>
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
os_family=oracle
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

# ── SRV-250 ~ SRV-262 (금보원 DBMS/Oracle 기준) ──
dump "SRV-250" "기본계정 상태" \
  "SELECT username||' : status='||account_status FROM dba_users WHERE username IN ('SYS','SYSTEM','DBSNMP','OUTLN','SCOTT','MDSYS','CTXSYS','XDB','HR');"
dump "SRV-251" "패스워드 복잡도 함수" \
  "SELECT 'PASSWORD_VERIFY_FUNCTION='||NVL(limit,'NULL') FROM dba_profiles WHERE profile='DEFAULT' AND resource_name='PASSWORD_VERIFY_FUNCTION';"
dump "SRV-252" "패스워드 만료/재사용" \
  "SELECT resource_name||'='||limit FROM dba_profiles WHERE profile='DEFAULT' AND resource_name IN ('PASSWORD_LIFE_TIME','PASSWORD_REUSE_MAX','PASSWORD_REUSE_TIME');"
dump "SRV-253" "로그인 실패 잠금 임계값" \
  "SELECT 'FAILED_LOGIN_ATTEMPTS='||limit FROM dba_profiles WHERE profile='DEFAULT' AND resource_name='FAILED_LOGIN_ATTEMPTS';"
dump "SRV-254" "DBA 롤 부여 계정" \
  "SELECT grantee||' : GRANTED_ROLE=DBA' FROM dba_role_privs WHERE granted_role='DBA' AND grantee NOT IN ('SYS','SYSTEM');"
dump "SRV-255" "PUBLIC 위험 패키지 실행 권한" \
  "SELECT table_name||' : PUBLIC' FROM dba_tab_privs WHERE grantee='PUBLIC' AND privilege='EXECUTE' AND table_name IN ('UTL_FILE','UTL_TCP','UTL_SMTP','UTL_HTTP','DBMS_SQL','DBMS_LOB','DBMS_JOB');"
dump "SRV-256" "remote_os_authent" \
  "SELECT 'remote_os_authent='||value FROM v\$parameter WHERE name='remote_os_authent';"
dump "SRV-257" "딕셔너리 접근 제한" \
  "SELECT 'O7_DICTIONARY_ACCESSIBILITY='||value FROM v\$parameter WHERE name='O7_DICTIONARY_ACCESSIBILITY';"
dump "SRV-258" "감사 활성화" \
  "SELECT 'AUDIT_TRAIL='||value FROM v\$parameter WHERE name='audit_trail';"
dump "SRV-259" "리스너 보호 (수동 확인 권고)" \
  "SELECT 'listener: lsnrctl status 로 별도 확인 필요(패스워드/외부노출)' FROM dual;"
dump "SRV-260" "utl_file_dir" \
  "SELECT 'utl_file_dir='||NVL(value,'NULL') FROM v\$parameter WHERE name='utl_file_dir';"
dump "SRV-261" "제품 버전" \
  "SELECT 'version='||version FROM v\$instance;"
dump "SRV-262" "세션/로그인 감사" \
  "SELECT 'login_audit='||NVL(MAX(audit_option),'none') FROM dba_stmt_audit_opts WHERE audit_option IN ('CREATE SESSION','SESSION');"

cat >> "$OUT" <<EOF
    </results>
</script>
EOF

echo "FSI Oracle scan finished. XML=$OUT (user=$ORA_USER, conn=$ORA_CONN, sqlplus=${SQLPLUS:-NONE})"
exit 0

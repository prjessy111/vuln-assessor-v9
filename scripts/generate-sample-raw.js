#!/usr/bin/env node
'use strict';
/**
 * 테스트용 raw SQLite 파일 생성기.
 *   node scripts/generate-sample-raw.js linux01 linux ./sample-linux01.db
 */

const Database = require('better-sqlite3');

const SAMPLES = {
  linux: [
    ['config', 'sshd_permit_root_login', 'yes'],          // 취약
    ['config', 'login_defs_pass_min_len', '6'],           // 취약
    ['config', 'login_defs_pass_max_days', '99999'],      // 취약
    ['config', 'pam_faillock_deny', '3'],                 // 양호
    ['permission', 'passwd_perm', '644'],                 // 양호
    ['permission', 'shadow_perm', '640'],                 // 취약
    ['permission', 'hosts_perm', '644'],                  // 취약
    ['service', 'telnet_service', 'inactive'],            // 양호
    ['service', 'ftp_service', 'active'],                 // 취약
    ['service', 'rservices', 'inactive'],                 // 양호
    ['service', 'rsyslog_service', 'active'],             // 양호
    ['patch',   'pending_security_updates', '12'],        // 취약
  ],
  windows: [
    ['account', 'admin_account_renamed', 'Administrator'],// 취약
    ['account', 'guest_account_status', 'Disabled'],      // 양호
    ['account', 'min_password_length', '10'],             // 양호
    ['account', 'account_lockout_threshold', '0'],        // 취약 (0이면 무한)
    ['service', 'smbv1_enabled', 'False'],                // 양호
    ['service', 'unnecessary_shares', 'DATA, BACKUP'],    // 취약
    ['log',     'audit_logon_events', 'Success and Failure'], // 양호
    ['patch',   'pending_security_updates', '3'],         // 취약
  ],
};

const host = process.argv[2] || 'host01';
const osType = process.argv[3] || 'linux';
const outPath = process.argv[4] || `./sample-${host}.db`;

const samples = SAMPLES[osType];
if (!samples) { console.error(`unknown osType: ${osType}`); process.exit(1); }

// 기존 파일 제거
try { require('fs').unlinkSync(outPath); } catch (_) {}
const db = new Database(outPath);
db.exec(`
  CREATE TABLE raw_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    host TEXT NOT NULL,
    os_type TEXT NOT NULL,
    category TEXT,
    check_key TEXT NOT NULL,
    value TEXT,
    collected_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
  CREATE INDEX idx_raw_host_key ON raw_data(host, check_key);
`);
const stmt = db.prepare(
  `INSERT INTO raw_data(host, os_type, category, check_key, value) VALUES (?,?,?,?,?)`
);
const insert = db.transaction(rows => { for (const r of rows) stmt.run(host, osType, ...r); });
insert(samples);
db.close();
console.log(`[ok] raw 샘플 생성: ${outPath} (host=${host}, os=${osType}, rows=${samples.length})`);

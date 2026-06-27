#!/usr/bin/env node
'use strict';
/**
 * 운영 DB 초기화 스크립트.
 *   node scripts/init-db.js
 * .env의 DB_* 변수 사용. 데이터베이스가 없으면 먼저 생성.
 */

const fs = require('fs');
const path = require('path');
const mysql = require('mysql2/promise');
const config = require('../src/config');

(async () => {
  // 1) database 없이 접속
  const root = await mysql.createConnection({
    host: config.db.host, port: config.db.port,
    user: config.db.user, password: config.db.password,
    multipleStatements: true,
  });

  await root.query(
    `CREATE DATABASE IF NOT EXISTS \`${config.db.database}\`
     DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci`
  );
  await root.query(`USE \`${config.db.database}\``);

  // 2) 스키마 적용
  const ddl = fs.readFileSync(path.join(__dirname, '..', 'src', 'db', 'schema.sql'), 'utf8');
  await root.query(ddl);

  console.log(`[ok] DB '${config.db.database}' 초기화 완료`);
  await root.end();
})().catch(e => { console.error(e); process.exit(1); });

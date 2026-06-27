#!/usr/bin/env node
/**
 * 마이그레이션: data/mock/*.json → MySQL _kv_store
 *
 * 사용법:
 *   node migrate-mock-to-mysql.js
 *
 * 동작:
 *   1. .env 로드 (MySQL 접속 정보)
 *   2. data/mock/*.json 의 모든 파일 읽기
 *   3. 각 파일을 _kv_store(name, data) 에 INSERT/UPDATE
 *   4. 결과 요약 출력
 *
 * 안전성:
 *   - INSERT ... ON DUPLICATE KEY UPDATE 사용
 *   - 원본 JSON 파일은 그대로 (백업 보존)
 *   - 트랜잭션은 사용 안 함 (대용량 JSON 한 번에 commit)
 */

'use strict';

// .env 로드
require('./src/config');

const fs = require('fs');
const path = require('path');

const MOCK_DIR = path.resolve(__dirname, 'data/mock');

async function main() {
  console.log('=== JSON → MySQL 마이그레이션 시작 ===\n');

  // MySQL 연결
  let mysql;
  try {
    mysql = require('mysql2/promise');
  } catch (e) {
    console.error('mysql2 패키지 미설치 — npm install mysql2');
    process.exit(1);
  }

  const config = require('./src/config').db;
  console.log(`연결 대상: ${config.user}@${config.host}:${config.port}/${config.database}\n`);

  let conn;
  try {
    conn = await mysql.createConnection({
      host: config.host,
      port: config.port,
      user: config.user,
      password: config.password,
      database: config.database,
      charset: config.charset,
    });
  } catch (e) {
    console.error('MySQL 연결 실패:', e.message);
    process.exit(1);
  }

  console.log('✓ MySQL 연결 성공\n');

  // _kv_store 테이블 보장
  await conn.query(`
    CREATE TABLE IF NOT EXISTS _kv_store (
      name VARCHAR(64) PRIMARY KEY,
      data JSON NOT NULL,
      updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
                                ON UPDATE CURRENT_TIMESTAMP
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
  `);

  // data/mock/*.json 파일들 스캔
  if (!fs.existsSync(MOCK_DIR)) {
    console.error(`data/mock 폴더 없음: ${MOCK_DIR}`);
    await conn.end();
    process.exit(1);
  }

  const files = fs.readdirSync(MOCK_DIR).filter(f => f.endsWith('.json'));
  if (files.length === 0) {
    console.log('마이그레이션할 JSON 파일 없음');
    await conn.end();
    return;
  }

  console.log(`발견된 JSON 파일: ${files.length}개\n`);

  let success = 0, skipped = 0, failed = 0;
  
  for (const fname of files) {
    const fpath = path.join(MOCK_DIR, fname);
    const name = fname.replace(/\.json$/, '');
    
    try {
      const raw = fs.readFileSync(fpath, 'utf8').trim();
      if (!raw) {
        console.log(`  [건너뜀] ${fname} - 빈 파일`);
        skipped++;
        continue;
      }
      
      const data = JSON.parse(raw);
      const itemCount = Array.isArray(data) ? data.length : (typeof data === 'object' && data !== null ? Object.keys(data).length : 1);
      
      await conn.query(
        `INSERT INTO _kv_store(name, data) VALUES (?, CAST(? AS JSON))
         ON DUPLICATE KEY UPDATE data = VALUES(data)`,
        [name, JSON.stringify(data)]
      );
      
      console.log(`  [OK]     ${name.padEnd(20)} (${itemCount}개 항목)`);
      success++;
    } catch (e) {
      console.error(`  [실패]   ${name}: ${e.message}`);
      failed++;
    }
  }

  // 결과 확인
  const [rows] = await conn.query('SELECT name, JSON_LENGTH(data) AS items, updated_at FROM _kv_store ORDER BY name');
  
  console.log(`\n=== 마이그레이션 결과 ===`);
  console.log(`성공: ${success} / 건너뜀: ${skipped} / 실패: ${failed}\n`);
  console.log(`=== _kv_store 현재 상태 ===`);
  console.table(rows);

  await conn.end();
  console.log('\n완료. npm run mock 으로 서버 재시작하세요.');
}

main().catch(e => {
  console.error('마이그레이션 오류:', e);
  process.exit(1);
});

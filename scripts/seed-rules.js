#!/usr/bin/env node
'use strict';
/**
 * 룰셋 YAML 파일을 읽어 MySQL rules 테이블에 적재.
 *   node scripts/seed-rules.js [yaml_path]
 */

const fs = require('fs');
const path = require('path');
const yaml = require('js-yaml');
const config = require('../src/config');
const ruleDao = require('../src/dao/ruleDao');
const pool = require('../src/db/pool');

(async () => {
  const file = process.argv[2] || path.join(config.paths.rules, 'default-v1.0.yaml');
  const doc = yaml.load(fs.readFileSync(file, 'utf8'));
  if (!doc.ruleset_ver || !Array.isArray(doc.rules)) {
    throw new Error('YAML 구조 오류: ruleset_ver, rules 필요');
  }
  await ruleDao.upsertMany(doc.rules, doc.ruleset_ver);
  console.log(`[ok] 룰셋 ${doc.ruleset_ver}, ${doc.rules.length}건 적재 완료`);
  await pool.end();
})().catch(e => { console.error(e); process.exit(1); });

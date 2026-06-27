'use strict';
/**
 * Raw loader를 우회한 통합 스모크 테스트.
 * 실제 운영 환경에서는 rawLoader.js가 better-sqlite3로 직접 읽지만,
 * 이 샌드박스에서는 native build가 안 되므로 Python으로 추출한 데이터를
 * JSON으로 받아 룰 엔진을 검증한다.
 */
const yaml = require('js-yaml');
const fs = require('fs');
const { evaluate } = require('../src/engine/ruleEngine');

// 1) YAML 룰셋 로딩
const doc = yaml.load(fs.readFileSync('rules/default-v1.0.yaml', 'utf8'));
const rules = doc.rules;
console.log(`[1] 룰셋 로딩 완료: ${doc.ruleset_ver}, ${rules.length}건`);

// 2) Python으로 SQLite raw_data를 JSON으로 추출
const { execSync } = require('child_process');
const json = execSync(`python3 -c "
import sqlite3, json
db = sqlite3.connect('/tmp/raw/test-linux01.db')
rows = db.execute('SELECT host, os_type, check_key, value FROM raw_data ORDER BY collected_at DESC').fetchall()
print(json.dumps([dict(zip(['host','os_type','check_key','value'], r)) for r in rows]))
"`).toString();
const records = JSON.parse(json);
console.log(`[2] Raw 데이터 추출 완료: ${records.length}건`);

// 3) host별 최신값 Map 구성
const rawMap = new Map();
const hostOs = records[0].os_type;
for (const r of records) {
  if (!rawMap.has(r.check_key)) rawMap.set(r.check_key, r.value);
}
console.log(`[3] host=${records[0].host}, os=${hostOs}, 고유 check_key=${rawMap.size}개`);

// 4) 룰 엔진 평가
const { results, summary } = evaluate(rules, rawMap, hostOs);
console.log(`[4] 평가 완료 → 전체 ${summary.total} / 취약 ${summary.vuln} / 양호 ${summary.safe} / N/A ${summary.na}`);

// 5) 항목별 결과 출력
console.log('\n[5] 상세 결과:');
console.log('─'.repeat(110));
console.log('  ID   분류                  중요도  판정      수집값 / 사유');
console.log('─'.repeat(110));
for (const r of results) {
  const mark = r.status === '취약' ? '❌ 취약' : r.status === '양호' ? '✅ 양호' : '⚪ N/A ';
  const collected = (r.collected_value || '(없음)').toString().slice(0, 20);
  console.log(
    `  ${r.rule_id.padEnd(5)} ${r.category.padEnd(20)} [${r.severity}]    ${mark}    ${collected.padEnd(22)} ${r.reason}`
  );
}
console.log('─'.repeat(110));

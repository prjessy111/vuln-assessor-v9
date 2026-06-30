'use strict';
/**
 * NVD API 2.0 동기화 — 설치 SW/라이브러리의 실제 CVE를 CPE 버전범위와 함께 수집.
 * (구 1.1 피드는 폐기되어 403 → API 2.0 사용)
 *
 * 사용:
 *   node scripts/sync-nvd-api.js                 # 기본 제품군
 *   node scripts/sync-nvd-api.js openssl zlib    # 특정 제품만
 *
 * 결과: data/cve/cve-db.json 에 { affected:[{cpe,version_start_inc,...}] } 형식으로 병합.
 *       → nvdCpe.js 어댑터가 자동으로 매칭에 사용.
 */
const https = require('https');
const fs = require('fs');
const path = require('path');

const DB = path.join(__dirname, '../data/cve/cve-db.json');
const API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const DEFAULT_PRODUCTS = [
  'openssl', 'zlib', 'expat', 'sqlite', 'pcre', 'libxml2', 'curl',
  'log4j', 'commons-collections', 'commons-text', 'commons-codec', 'commons-lang',
  'apache ant', 'jetty', 'apache hadoop', 'apache tomcat', 'apache struts',
  'postgresql', 'apache httpd', 'nginx',
];
const KEY = process.env.NVD_API_KEY || '';
const DELAY = KEY ? 1200 : 7000; // rate limit: 키 있으면 50/30s, 없으면 5/30s

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function fetchJson(url) {
  return new Promise((resolve, reject) => {
    const headers = { 'User-Agent': 'vuln-assessor-sync' };
    if (KEY) headers.apiKey = KEY;
    const req = https.get(url, { timeout: 30000, headers }, r => {
      if (r.statusCode !== 200) { r.resume(); return reject(new Error('HTTP ' + r.statusCode)); }
      let buf = '';
      r.on('data', d => { buf += d; });
      r.on('end', () => { try { resolve(JSON.parse(buf)); } catch (e) { reject(e); } });
    });
    req.on('timeout', () => { req.destroy(); reject(new Error('timeout')); });
    req.on('error', reject);
  });
}

function extractCpe(cve) {
  const out = [];
  for (const cfg of cve.configurations || []) {
    for (const node of cfg.nodes || []) {
      for (const m of node.cpeMatch || []) {
        if (!m.vulnerable) continue;
        const parts = (m.criteria || '').split(':');
        if (parts[2] !== 'a') continue; // application only
        out.push({
          cpe: m.criteria,
          version_start_inc: m.versionStartIncluding,
          version_start_exc: m.versionStartExcluding,
          version_end_inc: m.versionEndIncluding,
          version_end_exc: m.versionEndExcluding,
        });
      }
    }
  }
  return out;
}

async function main() {
  const products = process.argv.slice(2).length ? process.argv.slice(2) : DEFAULT_PRODUCTS;
  if (!fs.existsSync(DB + '.bak')) fs.copyFileSync(DB, DB + '.bak');
  const db = JSON.parse(fs.readFileSync(DB, 'utf8'));
  let added = 0, updated = 0;
  for (const prod of products) {
    try {
      const url = `${API}?keywordSearch=${encodeURIComponent(prod)}&resultsPerPage=200`;
      const j = await fetchJson(url);
      const vulns = j.vulnerabilities || [];
      let cnt = 0;
      for (const item of vulns) {
        const cve = item.cve; if (!cve || !cve.id) continue;
        const affected = extractCpe(cve);
        if (!affected.length) continue;
        const metric = (cve.metrics && (cve.metrics.cvssMetricV31 || cve.metrics.cvssMetricV30 || cve.metrics.cvssMetricV2) || [])[0];
        const cvss = metric ? { score: metric.cvssData.baseScore, severity: metric.cvssData.baseSeverity || (metric.baseSeverity) } : null;
        const exists = db[cve.id];
        db[cve.id] = Object.assign({}, exists, {
          cve_id: cve.id,
          description: (cve.descriptions || []).map(d => d.value)[0] || '',
          cvss_v3: cvss || (exists && exists.cvss_v3),
          affected,
          _source: 'nvd-api-2.0',
          cisa_kev: !!(exists && exists.cisa_kev),
        });
        if (exists) updated++; else added++;
        cnt++;
      }
      console.log(`[${prod}] ${vulns.length}건 조회 → CPE보유 ${cnt}건 반영`);
    } catch (e) {
      console.warn(`[${prod}] 실패: ${e.message}`);
    }
    await sleep(DELAY);
  }
  fs.writeFileSync(DB, JSON.stringify(db));
  console.log(`\n완료: 신규 ${added} / 갱신 ${updated} (총 ${Object.keys(db).length}건). 백업: cve-db.json.bak`);
}

main();

'use strict';
/**
 * CISA KEV(Known Exploited Vulnerabilities) 제품 교차검증.
 *
 * 동기화된 cve-db.json(_source=kev-only)에는 버전범위(CPE)가 없어 정밀 매칭은 못 하지만,
 * vendor/product 는 있다. 설치 SW 인벤토리의 제품명과 KEV 제품명을 대조해
 * "활성 익스플로잇이 알려진 제품이 설치돼 있음 — 버전 점검 필요" 자문(advisory)을 생성한다.
 *
 * ⚠️ 이것은 버전 검증된 '취약 확정'이 아니라 '제품 존재 기반 검토 권고'다.
 *    정밀(버전) 판정은 NVD CPE 동기화 + cve-software-curated 매칭이 담당.
 */
const fs = require('fs');
const path = require('path');

let _kevCache = null;

// OS 레벨(핫픽스 CVE가 따로 담당) 또는 과도하게 일반적인 제품명 제외 — 오탐 방지.
// (KEV product 가 너무 일반적이면 SQL Server 하위 컴포넌트·VC++ 재배포판 등을 무차별 매칭함)
const GENERIC = new Set([
  'windows', 'windows server', 'microsoft windows', 'server', 'net', 'os',
  'microsoft', 'sql server', 'visual studio', 'visual c', 'manager',
  'browser', 'runtime', 'native client', 'ole db', 'odbc', 'redistributable',
  'help viewer', 'management studio', 'client', 'driver', 'framework', 'office',
  'viewer', 'tools', 'update', 'hosting support', 'redistributable', 'additional runtime',
]);

function norm(s) {
  return String(s || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
}

function loadKevProducts() {
  if (_kevCache) return _kevCache;
  try {
    const db = JSON.parse(fs.readFileSync(path.join(__dirname, '../../data/cve/cve-db.json'), 'utf8'));
    const map = new Map(); // normProduct -> { vendor, product, cves:Set }
    for (const v of Object.values(db)) {
      if (!v.cisa_kev || !v.kev_info || !v.kev_info.product) continue;
      // "Acrobat and Reader, Flash Player" 같은 복합 제품명 분해
      for (const part of String(v.kev_info.product).split(/,| and /i)) {
        const prod = part.trim();
        const key = norm(prod);
        if (key.length < 4 || GENERIC.has(key)) continue;
        if (!map.has(key)) map.set(key, { vendor: v.kev_info.vendor || '', product: prod, cves: new Set() });
        map.get(key).cves.add(v.cve_id);
      }
    }
    _kevCache = [...map.values()].map(x => ({ vendor: x.vendor, product: x.product, key: norm(x.product), cves: [...x.cves] }));
  } catch (_) {
    _kevCache = [];
  }
  return _kevCache;
}

function invalidate() { _kevCache = null; }

/**
 * 설치 SW 인벤토리 vs KEV 제품 대조.
 * @param {Array<{name, version, publisher}>} software
 * @returns {Array} advisory 항목
 */
function crossCheck(software) {
  const kev = loadKevProducts();
  const out = [];
  const seen = new Set();
  for (const sw of (software || [])) {
    const sn = ' ' + norm(sw.name) + ' ';
    for (const k of kev) {
      // 제품명이 SW명에 토큰 구절로 포함될 때만 (보수적)
      if (sn.indexOf(' ' + k.key + ' ') === -1) continue;
      const dedup = (sw.name || '') + '|' + k.key;
      if (seen.has(dedup)) continue;
      seen.add(dedup);
      out.push({
        software: sw.name,
        version: sw.version || '',
        vendor: k.vendor,
        product: k.product,
        kev_cve_count: k.cves.length,
        sample_cves: k.cves.slice(0, 5),
        advisory: true,
      });
      break; // SW 1건당 1개 제품만
    }
  }
  return out;
}

module.exports = { crossCheck, loadKevProducts, invalidate };

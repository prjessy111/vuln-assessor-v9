'use strict';
/**
 * NVD CPE 어댑터 — 동기화된 cve-db.json(NVD)을 매처가 쓰는 형식으로 변환.
 *
 * 목적: 큐레이션(소수)에 의존하지 않고 **NVD 전체 CVE**로 설치 SW를 매칭(확장).
 *   - cve-db.json 항목의 affected[](CPE) → { package, affected_versions[{from,to,include_*}] }
 *   - cpe23Uri: "cpe:2.3:a:vendor:product:version:..." 에서 product/version 추출 ('a'=애플리케이션만)
 *
 * ⚠️ 현재 cve-db.json 이 KEV-only(버전범위 없음)면 결과 0건.
 *    `node scripts/sync-cve.js --full` (인터넷)로 NVD CPE를 채우면 자동으로 대량 활성화된다.
 */
const fs = require('fs');
const path = require('path');

let _cache = null;

function load() {
  if (_cache) return _cache;
  const out = [];
  try {
    const db = JSON.parse(fs.readFileSync(path.join(__dirname, '../../data/cve/cve-db.json'), 'utf8'));
    for (const v of Object.values(db)) {
      if (!v.affected || !v.affected.length) continue;
      const byProd = new Map();
      for (const a of v.affected) {
        const parts = String(a.cpe || '').split(':'); // cpe:2.3:a:vendor:product:version:...
        if (parts.length < 6 || parts[2] !== 'a') continue; // 애플리케이션(a)만 — OS/하드웨어 제외
        const product = (parts[4] || '').replace(/_/g, ' ').trim();
        if (!product || product === '*') continue;
        const cpeVer = parts[5];
        let range = null;
        const from = a.version_start_inc || a.version_start_exc;
        const to = a.version_end_inc || a.version_end_exc;
        if (from || to) {
          range = {
            from: from || '0',
            to: to || '999999',
            include_from: a.version_start_inc != null || (!a.version_start_exc),
            include_to: a.version_end_inc != null,
          };
        } else if (cpeVer && cpeVer !== '*' && cpeVer !== '-') {
          range = { from: cpeVer, to: cpeVer, include_from: true, include_to: true };
        }
        if (!range) continue;
        if (!byProd.has(product)) byProd.set(product, []);
        byProd.get(product).push(range);
      }
      const cvss = (v.cvss_v3 && (v.cvss_v3.score != null ? v.cvss_v3.score : v.cvss_v3)) || 0;
      const sev = (v.cvss_v3 && v.cvss_v3.severity) || '';
      for (const [product, ranges] of byProd) {
        out.push({
          cve_id: v.cve_id,
          package: product,
          aliases: [product],
          name: String(v.description || '').replace(/\s+/g, ' ').slice(0, 90),
          affected_versions: ranges,
          cvss_v3: cvss,
          severity: sev,
          cisa_kev: !!v.cisa_kev,
          _source: 'nvd-cpe',
        });
      }
    }
  } catch (_) { /* cve-db.json 없거나 파싱 실패 → 빈 배열 */ }
  _cache = out;
  return _cache;
}

function invalidate() { _cache = null; }

module.exports = { load, invalidate };

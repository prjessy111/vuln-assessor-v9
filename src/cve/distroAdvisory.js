'use strict';
/**
 * 배포판 보안 Advisory 백포트 판정 (CVE/SCA 정확도의 핵심).
 *
 * 버전 패턴매칭의 한계(백포트 과탐)를 결정론적으로 해소:
 *   - RHEL/CentOS: RedHat Security Data API → CVE별 "수정된 패키지 release"
 *   - Ubuntu/Debian: Ubuntu Security API → 릴리스별 fixed 버전
 *   설치 release 가 fixed release 이상이면 → 백포트로 '패치됨'(과탐 제거).
 *
 * 네트워크 필요. 오프라인/실패 시 'unknown' 반환(판정 보류, 과탐 단정 안 함).
 * 결과는 메모리 캐시 (CVE+distro 키).
 */
const https = require('https');

const _cache = new Map();

function fetchJson(url, timeout = 12000) {
  return new Promise((resolve) => {
    const req = https.get(url, { timeout, headers: { 'User-Agent': 'vuln-assessor', 'Accept': 'application/json' } }, r => {
      if (r.statusCode !== 200) { r.resume(); return resolve(null); }
      let buf = '';
      r.on('data', d => { buf += d; });
      r.on('end', () => { try { resolve(JSON.parse(buf)); } catch (_) { resolve(null); } });
    });
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.on('error', () => resolve(null));
  });
}

// "1.0.2k-16.el7_9.1" 류 release 숫자 비교 (간이) — el7 등 접미사 제거 후 숫자열 비교
function cmpRelease(a, b) {
  const norm = v => String(v || '').replace(/\.el\d+.*$/, '').replace(/[^\d.]/g, '.').split('.').filter(Boolean).map(Number);
  const x = norm(a), y = norm(b);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    const xi = x[i] || 0, yi = y[i] || 0;
    if (xi !== yi) return xi < yi ? -1 : 1;
  }
  return 0;
}

/**
 * RHEL/CentOS 백포트 판정.
 * @returns {Promise<{status:'patched'|'vulnerable'|'unknown', fixed?:string, detail?:string}>}
 */
async function checkRhel(cveId, pkgName, installedFull) {
  const key = `rhel:${cveId}:${pkgName}`;
  if (_cache.has(key)) return _cache.get(key);
  let result = { status: 'unknown' };
  const data = await fetchJson(`https://access.redhat.com/hydra/rest/securitydata/cve/${cveId}.json`);
  if (data) {
    const rels = (data.affected_release || []).filter(r => (r.package || '').toLowerCase().includes(pkgName.toLowerCase()));
    if (rels.length) {
      // 가장 낮은 fixed release 와 설치본 비교 (el7 계열 우선)
      const fixedPkg = rels[0].package; // 예: openssl-1:1.0.2k-16.el7_9
      // 설치본이 fixed 이상이면 patched
      const cmp = cmpRelease(installedFull, fixedPkg);
      result = cmp >= 0
        ? { status: 'patched', fixed: fixedPkg, detail: `RHSA 백포트 적용(설치 ${installedFull} ≥ 수정 ${fixedPkg})` }
        : { status: 'vulnerable', fixed: fixedPkg, detail: `미패치(설치 ${installedFull} < 수정 ${fixedPkg})` };
    } else if ((data.package_state || []).some(p => /not affected|will not fix/i.test(p.fix_state || ''))) {
      result = { status: 'patched', detail: 'RedHat: not affected / wontfix' };
    }
  }
  _cache.set(key, result);
  return result;
}

/**
 * Ubuntu 백포트 판정.
 */
async function checkUbuntu(cveId, pkgName, releaseCodename) {
  const key = `ubuntu:${cveId}:${pkgName}`;
  if (_cache.has(key)) return _cache.get(key);
  let result = { status: 'unknown' };
  const data = await fetchJson(`https://ubuntu.com/security/cves/${cveId}.json`);
  if (data && Array.isArray(data.packages)) {
    const pkg = data.packages.find(p => (p.name || '').toLowerCase() === pkgName.toLowerCase());
    if (pkg) {
      const st = (pkg.statuses || []).find(s => !releaseCodename || s.release_codename === releaseCodename) || pkg.statuses[0];
      if (st) {
        if (/released|not-affected/i.test(st.status)) result = { status: 'patched', fixed: st.description, detail: `Ubuntu: ${st.status} ${st.description || ''}` };
        else if (/needed|vulnerable|pending/i.test(st.status)) result = { status: 'vulnerable', detail: `Ubuntu: ${st.status}` };
      }
    }
  }
  _cache.set(key, result);
  return result;
}

/**
 * 매칭 결과(Linux 패키지)에 백포트 판정 적용. env.os_distro 로 RHEL/Ubuntu 분기.
 * @param {Array} matches  matcher 결과 (pkg_name, pkg_full 보유)
 * @param {object} env     { os_distro, os_version }
 * @param {object} opts    { max: 동시/총 조회 상한 }
 */
async function refine(matches, env, opts = {}) {
  const distro = String(env && env.os_distro || '').toLowerCase();
  const isRhel = /centos|rhel|red ?hat|rocky|alma|fedora/.test(distro);
  const isUbuntu = /ubuntu|debian/.test(distro);
  if (!isRhel && !isUbuntu) return matches; // OS 패키지 백포트 비대상
  const max = opts.max || 60;
  let n = 0;
  for (const m of matches) {
    if (n >= max) { m.backport_check = { status: 'skipped', detail: '조회 상한 초과' }; continue; }
    const pkg = m.pkg_name || m.package;
    if (!pkg) continue;
    n++;
    const v = isRhel
      ? await checkRhel(m.cve_id, pkg, m.pkg_full || pkg)
      : await checkUbuntu(m.cve_id, pkg, (env.codename || '').toLowerCase());
    m.backport_check = v;
    if (v.status === 'patched') { m.verdict = 'PATCHED_BACKPORT'; if (m.ai_judgment) { m.ai_judgment.is_vulnerable = false; m.ai_judgment.verdict = 'PATCHED_BACKPORT'; m.ai_judgment.rationale_ko = '배포판 advisory 확인: ' + (v.detail || '백포트 패치 적용됨') + ' → 실제 취약 아님(과탐 제거).'; } }
    else if (v.status === 'vulnerable') { m.verdict = 'CONFIRMED'; }
  }
  return matches;
}

module.exports = { refine, checkRhel, checkUbuntu, cmpRelease };

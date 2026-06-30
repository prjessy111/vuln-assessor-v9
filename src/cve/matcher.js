'use strict';
/**
 * CVE 자동 매칭 엔진 (결정론적)
 *
 * 흐름:
 *   1. 패키지 목록 (rpm -qa 파싱 결과)
 *   2. CVE DB (큐레이션된 CentOS 7 CVE 목록)
 *   3. 각 패키지를 모든 CVE와 매칭
 *   4. 영향 받는 CVE 후보 반환
 *
 * LLM은 사용하지 않음 (환각 방지). 버전 비교만 수행.
 * AI Judgment Engine은 별도 모듈에서 처리.
 */

const fs = require('fs');
const path = require('path');

let _cveCache = null;

/**
 * CVE DB 로드 (캐시됨).
 *
 * 보강(enrichment) 모듈을 통해 큐레이션 DB + sync 데이터를 머지한 결과 반환.
 * sync 데이터가 없으면 큐레이션 DB만 사용. 매처 입장에서는 형식이 동일.
 */
// 권위 소프트웨어 CVE DB(cve-software-curated.json) 로드 — OS·플랫폼 공통.
// from<=v<to 의미를 isVersionAffected 와 맞추기 위해 include_from/to 기본값 주입.
function loadSoftwareCves() {
  try {
    const p = path.join(__dirname, '../../data/cve/cve-software-curated.json');
    const j = JSON.parse(fs.readFileSync(p, 'utf8'));
    const arr = Array.isArray(j) ? j : (j.cves || []);
    return arr.map(c => ({
      ...c,
      affected_versions: (c.affected_versions || []).map(r => ({
        from: r.from,
        to: r.to,
        include_from: r.include_from !== undefined ? r.include_from : true,
        include_to: r.include_to !== undefined ? r.include_to : false,
      })),
    }));
  } catch (_) {
    return [];
  }
}

function loadCveDb() {
  if (_cveCache) return _cveCache;
  let base;
  try {
    const enrichment = require('./enrichment');
    base = enrichment.loadEnrichedCveDb();
  } catch (e) {
    // 보강 모듈 로드 실패 시 큐레이션 DB만 사용 (안전한 폴백)
    console.warn(`[cve/matcher] enrichment 모듈 사용 불가, 큐레이션 DB만 로드: ${e.message}`);
    const cvePath = path.join(__dirname, '../../data/cve/cve-centos7-curated.json');
    base = JSON.parse(fs.readFileSync(cvePath, 'utf8'));
  }
  // OS 패키지(centos) + 공통 소프트웨어 CVE + NVD CPE(전체) → 설치 SW 포괄 매칭
  let nvd = [];
  try { nvd = require('./nvdCpe').load(); } catch (_) {}
  _cveCache = (Array.isArray(base) ? base : []).concat(loadSoftwareCves(), nvd);
  return _cveCache;
}

/**
 * 캐시 무효화 (sync 직후 호출).
 */
function invalidateCveCache() {
  _cveCache = null;
  try {
    require('./enrichment').invalidateCache();
  } catch (_) { /* ignore */ }
}

/**
 * RPM 버전 비교 (간소화).
 *
 * RPM 정식 버전 비교는 매우 복잡하지만 (rpmlib),
 * 본 PoC에서는 숫자 기반 비교로 충분히 동작.
 *
 * 예시:
 *   "1.8.19p2" → [1, 8, 19, 2]
 *   "1.8.23"   → [1, 8, 23]
 *   "2.4.6"    → [2, 4, 6]
 *
 * @returns {number} -1 (v1 < v2), 0 (v1 = v2), 1 (v1 > v2)
 */
function compareVersions(v1, v2) {
  const parse = (v) => {
    if (!v) return [];
    // 'p1', 'p2' 같은 패치 표기 → 일반 숫자로 변환
    return String(v).split(/[.\-_p]/g)
      .map(x => x.replace(/[^\d]/g, ''))
      .filter(x => x !== '')
      .map(x => parseInt(x, 10) || 0);
  };

  const a = parse(v1);
  const b = parse(v2);
  const len = Math.max(a.length, b.length);

  for (let i = 0; i < len; i++) {
    const ai = a[i] === undefined ? 0 : a[i];
    const bi = b[i] === undefined ? 0 : b[i];
    if (ai < bi) return -1;
    if (ai > bi) return 1;
  }

  // 숫자부 동일 시, OpenSSL 류 끝자리 문자접미사(1.0.2o vs 1.0.2p)를 타이브레이커로 비교.
  // rpm 'pN'(1.8.19p2)는 끝이 숫자라 매칭 안 돼 영향 없음.
  const suffix = (v) => (String(v).match(/\d([a-z]+)\s*$/i) || [])[1] || '';
  const sa = suffix(v1), sb = suffix(v2);
  if (sa < sb) return -1;
  if (sa > sb) return 1;
  return 0;
}

/**
 * 패키지 버전이 영향 받는 범위에 있는지 확인.
 *
 * @param {string} pkgVersion - 패키지 버전 (예: "1.8.19p2")
 * @param {Array} ranges - CVE의 affected_versions 배열
 * @returns {boolean}
 */
function isVersionAffected(pkgVersion, ranges) {
  for (const r of ranges) {
    const fromCmp = compareVersions(pkgVersion, r.from);
    const toCmp = compareVersions(pkgVersion, r.to);

    const fromOk = r.include_from ? fromCmp >= 0 : fromCmp > 0;
    const toOk = r.include_to ? toCmp <= 0 : toCmp < 0;

    if (fromOk && toOk) return true;
  }
  return false;
}

/**
 * CentOS release 번호가 패치 버전 이상인지 확인.
 *
 * 예: 설치된 release "4.el7" vs 패치 release "10.el7_9.1"
 *
 * @returns {object} { isPatched, ourRelease, patchRelease }
 */
function checkBackport(pkgRelease, patchPackage) {
  if (!patchPackage || !patchPackage.includes('-')) {
    return { isPatched: false, ourRelease: pkgRelease, patchRelease: null };
  }

  // 패치 패키지에서 release 추출: "sudo-1.8.23-10.el7_9.1" → "10.el7_9.1"
  const m = patchPackage.match(/^[\w-]+-[\d\.]+(?:p\d+)?-(.+?)(?:\.\w+)?$/);
  if (!m) return { isPatched: false, ourRelease: pkgRelease, patchRelease: null };

  const patchRelease = m[1];
  const cmp = compareVersions(pkgRelease, patchRelease);

  return {
    isPatched: cmp >= 0,
    ourRelease: pkgRelease,
    patchRelease,
  };
}

/**
 * 단일 패키지와 단일 CVE 매칭.
 *
 * @returns {object|null} 매칭 시 결과 객체, 아니면 null
 */
function matchPackageVsCve(pkg, cve) {
  // 패키지 이름 매칭 (정확히만)
  // 예: cve.package='openssh' → openssh, openssh-server, openssh-clients 매칭
  //     cve.package='bash' → bash만 매칭 (bash-completion 제외)
  const pkgName = pkg.name.toLowerCase();
  const cvePkg = cve.package.toLowerCase();

  // 정확한 매칭 또는 명확한 변형
  let nameMatch = false;
  if (pkgName === cvePkg) {
    nameMatch = true;
  } else {
    // cve.package 별 허용 변형 정의
    const allowedVariants = {
      'openssh': ['openssh-server', 'openssh-clients'],
      'openssl': ['openssl-libs'],
      'glibc': ['glibc-common', 'glibc-devel'],
      'httpd': ['httpd-tools'],
      'curl': ['libcurl'],
      'libjpeg-turbo': ['libjpeg-turbo-utils'],
      'shadow-utils': [],
      'xerces-c': [],
      'kernel': ['kernel-tools', 'kernel-headers'],
    };
    const variants = allowedVariants[cvePkg];
    if (variants && variants.includes(pkgName)) {
      nameMatch = true;
    }
  }

  if (!nameMatch) return null;

  // 버전 매칭
  if (!isVersionAffected(pkg.version, cve.affected_versions)) {
    return null;
  }

  // 백포팅 확인
  const backport = checkBackport(pkg.release, cve.patches?.centos_7);

  // 매칭 결과
  return {
    cve_id: cve.cve_id,
    cve_name: cve.name,
    description: cve.description,
    severity: cve.severity,
    cvss_v3: cve.cvss_v3,
    epss: cve.epss,
    cisa_kev: cve.cisa_kev,
    exploit_public: cve.exploit_public,
    cwe: cve.cwe,
    tags: cve.tags,
    
    // 매칭된 패키지
    pkg_name: pkg.name,
    pkg_version: pkg.version,
    pkg_release: pkg.release,
    pkg_arch: pkg.arch,
    pkg_full: pkg.full,
    
    // 백포팅 분석
    upstream_match: true,
    backport: backport,
    
    // 패치 정보
    patches: cve.patches,
    
    // 초기 판정 (LLM이 보완할 예정)
    initial_verdict: backport.isPatched ? 'LIKELY_PATCHED' : 'AFFECTED',
    confidence: backport.isPatched ? 'medium' : 'high',
  };
}

/**
 * 환경 전체 vs CVE DB 전체 매칭.
 *
 * @param {Array} packages - extractPackages() 결과
 * @returns {Array} 매칭된 CVE 후보 목록
 */
function matchAll(packages) {
  const cves = loadCveDb();
  const results = [];

  for (const pkg of packages) {
    for (const cve of cves) {
      const match = matchPackageVsCve(pkg, cve);
      if (match) results.push(match);
    }
  }

  // 중복 제거 (같은 CVE에 여러 패키지 매칭된 경우 가장 위험한 것 1개)
  const byCve = new Map();
  for (const r of results) {
    const existing = byCve.get(r.cve_id);
    if (!existing) {
      byCve.set(r.cve_id, r);
    } else if (!existing.backport.isPatched && r.backport.isPatched) {
      // 미패치가 우선
    } else if (existing.backport.isPatched && !r.backport.isPatched) {
      byCve.set(r.cve_id, r);
    }
  }

  return Array.from(byCve.values());
}

/**
 * 우선순위 정렬 (CVSS + EPSS + KEV).
 */
function sortByPriority(matches) {
  return matches.slice().sort((a, b) => {
    // 1순위: CISA KEV (즉시 조치 의무)
    if (a.cisa_kev !== b.cisa_kev) return a.cisa_kev ? -1 : 1;
    // 2순위: 미패치 우선
    if (a.backport.isPatched !== b.backport.isPatched) {
      return a.backport.isPatched ? 1 : -1;
    }
    // 3순위: CVSS 높은 순
    if (a.cvss_v3 !== b.cvss_v3) return b.cvss_v3 - a.cvss_v3;
    // 4순위: EPSS 높은 순
    return b.epss - a.epss;
  });
}

/**
 * 통계 요약.
 */
function summarize(matches) {
  const total = matches.length;
  const critical = matches.filter(m => m.severity === 'CRITICAL').length;
  const high = matches.filter(m => m.severity === 'HIGH').length;
  const medium = matches.filter(m => m.severity === 'MEDIUM').length;
  const low = matches.filter(m => m.severity === 'LOW').length;
  const kev = matches.filter(m => m.cisa_kev).length;
  const patched = matches.filter(m => m.backport.isPatched).length;
  const unpatched = matches.filter(m => !m.backport.isPatched).length;
  const exploitPublic = matches.filter(m => m.exploit_public).length;

  return {
    total,
    by_severity: { critical, high, medium, low },
    kev_count: kev,
    patched_count: patched,
    unpatched_count: unpatched,
    exploit_public_count: exploitPublic,
  };
}

module.exports = {
  loadCveDb,
  invalidateCveCache,
  compareVersions,
  isVersionAffected,
  checkBackport,
  matchPackageVsCve,
  matchAll,
  sortByPriority,
  summarize,
};

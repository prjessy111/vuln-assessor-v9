'use strict';
/**
 * CVE 보강(Enrichment) 모듈.
 *
 * 설계 원칙:
 *   - 큐레이션 DB(cve-centos7-curated.json)는 매칭의 근거(SoT). 보존.
 *   - sync-cve.js가 받아온 NVD/KEV 데이터는 보강 정보로만 사용.
 *   - 핵심 매칭 필드는 절대 덮어쓰지 않음:
 *       * cve_id
 *       * package
 *       * affected_versions
 *       * patches
 *   - 보강 대상 필드 (NVD/KEV가 더 최신일 가능성):
 *       * cvss_v3, severity         — NVD 재평가 시
 *       * description               — 더 길어졌으면
 *       * published, last_modified  — 새 정보
 *       * cisa_kev, kev_info        — KEV 신규 등재
 *
 * 출력:
 *   merged = 큐레이션 DB의 각 CVE에 보강 메타데이터 추가한 배열
 *   stats  = { enriched, cvss_updated, kev_newly_added, kev_existing }
 */

const fs = require('fs');
const path = require('path');

const CVE_DIR = path.resolve(__dirname, '..', '..', 'data', 'cve');
const CURATED_FILE = path.join(CVE_DIR, 'cve-centos7-curated.json');
const SYNC_DB_FILE = path.join(CVE_DIR, 'cve-db.json');
const HISTORY_FILE = path.join(CVE_DIR, 'sync-history.json');

let _cache = null;
let _cacheStats = null;

function _readJsonSafe(filePath, fallback) {
  try {
    if (!fs.existsSync(filePath)) return fallback;
    const raw = fs.readFileSync(filePath, 'utf8');
    if (!raw.trim()) return fallback;
    return JSON.parse(raw);
  } catch (e) {
    console.warn(`[cve/enrichment] ${filePath} 읽기 실패: ${e.message}`);
    return fallback;
  }
}

/**
 * sync-cve.js의 cvss_v3 (object 형식) → number(점수)로 평탄화.
 * 큐레이션 DB는 cvss_v3가 number이므로 형식 통일.
 */
function flattenSyncCvss(syncCve) {
  if (!syncCve || !syncCve.cvss_v3) return { score: null, severity: null };
  if (typeof syncCve.cvss_v3 === 'number') {
    return { score: syncCve.cvss_v3, severity: syncCve.severity || null };
  }
  // object 형식 {score, vector, severity}
  return {
    score: syncCve.cvss_v3.score ?? null,
    severity: syncCve.cvss_v3.severity || syncCve.severity || null,
  };
}

/**
 * 큐레이션 DB 한 건에 sync 데이터 보강 적용.
 * 비파괴 — 큐레이션 값 우선, 누락된 필드만 채움. 단 KEV는 sync가 권위.
 *
 * @returns {object} { enriched: boolean, applied: string[] } 어떤 필드가 보강됐는지
 */
function applyEnrichment(curatedCve, syncMap) {
  const sync = syncMap[curatedCve.cve_id];
  if (!sync) return { enriched: false, applied: [] };

  const applied = [];

  // CVSS — sync가 더 최근 평가일 수 있음. 점수가 다르면 sync 값 채택 + 큐레이션 값 보존
  const syncCvss = flattenSyncCvss(sync);
  if (syncCvss.score != null && syncCvss.score !== curatedCve.cvss_v3) {
    curatedCve._cvss_v3_curated = curatedCve.cvss_v3;
    curatedCve.cvss_v3 = syncCvss.score;
    applied.push('cvss_v3');
  }
  if (syncCvss.severity && syncCvss.severity !== curatedCve.severity) {
    curatedCve._severity_curated = curatedCve.severity;
    curatedCve.severity = syncCvss.severity;
    applied.push('severity');
  }

  // KEV — sync가 권위 (CISA 공식 명단)
  if (sync.cisa_kev && !curatedCve.cisa_kev) {
    curatedCve.cisa_kev = true;
    curatedCve._kev_newly_added = true;
    applied.push('cisa_kev');
  }
  if (sync.kev_info) {
    curatedCve.kev_info = sync.kev_info;
    if (!applied.includes('cisa_kev')) applied.push('kev_info');
  }

  // description — sync가 100자 이상 더 길면 보강 (요약 → 상세)
  if (sync.description && (!curatedCve.description ||
      sync.description.length > curatedCve.description.length + 100)) {
    curatedCve._description_curated = curatedCve.description;
    curatedCve.description = sync.description;
    applied.push('description');
  }

  // 메타 (있으면 채움, 충돌 시 큐레이션 보존)
  if (sync.published && !curatedCve.published) {
    curatedCve.published = sync.published;
    applied.push('published');
  }
  if (sync.last_modified) {
    curatedCve.last_modified = sync.last_modified;
  }
  if (sync._synced_at) {
    curatedCve._enriched_at = sync._synced_at;
  }

  return { enriched: applied.length > 0, applied };
}

/**
 * 캐시 무효화 (sync 직후 호출 권장).
 */
function invalidateCache() {
  _cache = null;
  _cacheStats = null;
}

/**
 * 보강된 CVE DB 반환.
 * 보강 데이터가 없으면 큐레이션 DB 그대로 반환.
 *
 * @returns {Array} 매처가 사용하는 array 형식
 */
function loadEnrichedCveDb() {
  if (_cache) return _cache;

  const curated = _readJsonSafe(CURATED_FILE, []);
  const sync = _readJsonSafe(SYNC_DB_FILE, null);

  if (!sync || Object.keys(sync).length === 0) {
    _cache = curated;
    _cacheStats = { enriched: 0, cvss_updated: 0, kev_newly_added: 0, total: curated.length, sync_available: false };
    return _cache;
  }

  const stats = { enriched: 0, cvss_updated: 0, kev_newly_added: 0, kev_existing: 0, description_updated: 0, total: curated.length, sync_available: true };
  const out = [];
  for (const c of curated) {
    // shallow clone — 캐시되지만 원본은 안전하게
    const cve = JSON.parse(JSON.stringify(c));
    const { enriched, applied } = applyEnrichment(cve, sync);
    if (enriched) {
      stats.enriched++;
      if (applied.includes('cvss_v3')) stats.cvss_updated++;
      if (applied.includes('cisa_kev')) stats.kev_newly_added++;
      if (applied.includes('description')) stats.description_updated++;
    }
    if (cve.cisa_kev && !cve._kev_newly_added) stats.kev_existing++;
    out.push(cve);
  }

  _cache = out;
  _cacheStats = stats;
  return _cache;
}

/**
 * 최근 보강 통계 (UI 표시용).
 */
function getEnrichmentStats() {
  if (!_cacheStats) loadEnrichedCveDb();
  return _cacheStats;
}

/**
 * 동기화 이력 (최근 N건).
 */
function getSyncHistory(limit = 10) {
  const all = _readJsonSafe(HISTORY_FILE, []);
  return all.slice(0, limit);
}

/**
 * sync DB의 신규 CVE (큐레이션에 없는 — 향후 큐레이션 검토 대상).
 * KEV에 등재됐는데 큐레이션 DB에는 없는 CVE를 우선 노출.
 */
function getUntrackedKevCves(limit = 20) {
  const curated = _readJsonSafe(CURATED_FILE, []);
  const curatedIds = new Set(curated.map(c => c.cve_id));
  const sync = _readJsonSafe(SYNC_DB_FILE, null);
  if (!sync) return [];

  const result = [];
  for (const [id, cve] of Object.entries(sync)) {
    if (curatedIds.has(id)) continue;
    if (!cve.cisa_kev) continue;
    result.push({
      cve_id: id,
      vendor: cve.kev_info?.vendor,
      product: cve.kev_info?.product,
      name: cve.kev_info?.name,
      due: cve.kev_info?.due,
      published: cve.published,
    });
    if (result.length >= limit) break;
  }
  return result;
}

module.exports = {
  loadEnrichedCveDb,
  getEnrichmentStats,
  getSyncHistory,
  getUntrackedKevCves,
  invalidateCache,
  // 단위 테스트용
  applyEnrichment,
  flattenSyncCvss,
};

#!/usr/bin/env node
'use strict';
/**
 * CVE Feed 동기화 (Phase 1)
 *
 * 기능:
 *   - NVD modified feed 다운로드 (최근 변경된 CVE만)
 *   - CISA KEV 다운로드
 *   - EPSS 점수 다운로드 (선택)
 *   - 로컬 CVE DB와 비교하여 변경 감지
 *   - 변경 사항 콘솔 출력
 *
 * 사용법:
 *   node scripts/sync-cve.js                      # 기본 (NVD + KEV)
 *   node scripts/sync-cve.js --full               # 전체 NVD feed 받기
 *   node scripts/sync-cve.js --kev-only           # KEV만 갱신
 *   node scripts/sync-cve.js --from-file <path>   # 로컬 파일에서 (폐쇄망용)
 *   node scripts/sync-cve.js --dry-run            # 실제 저장 안 함, 변경만 출력
 *
 * 폐쇄망 운영:
 *   1. 인터넷 PC에서 NVD/KEV/EPSS 다운로드
 *      curl -O https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz
 *      curl -O https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
 *   2. USB 등으로 진단 서버에 복사
 *   3. node scripts/sync-cve.js --from-file ./nvdcve-1.1-modified.json.gz
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const zlib = require('zlib');

const ROOT = path.resolve(__dirname, '..');
const CVE_DIR = path.join(ROOT, 'data/cve');
const FEED_DIR = path.join(CVE_DIR, 'feeds');
const DB_FILE = path.join(CVE_DIR, 'cve-db.json');
const HISTORY_FILE = path.join(CVE_DIR, 'sync-history.json');

const NVD_URLS = {
  modified: 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-modified.json.gz',
  recent: 'https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-recent.json.gz',
};
const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS_URL = 'https://epss.cyentia.com/epss_scores-current.csv.gz';


// ─── 유틸 ────────────────────────────────────────────
function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function timestamp() {
  return new Date().toISOString().slice(0, 19).replace('T', ' ');
}

function log(msg) {
  console.log(`[${timestamp()}] ${msg}`);
}

function loadJson(filePath, defaultValue = null) {
  if (!fs.existsSync(filePath)) return defaultValue;
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch (e) {
    log(`⚠ JSON 파싱 실패 (${filePath}): ${e.message}`);
    return defaultValue;
  }
}

function saveJson(filePath, data) {
  ensureDir(path.dirname(filePath));
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}


// ─── HTTPS 다운로드 ─────────────────────────────────
function downloadFile(url, outputPath, options = {}) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(outputPath);
    let totalBytes = 0;

    const req = https.get(url, {
      timeout: 60000,
      headers: { 'User-Agent': 'lsware-vuln-assessor/1.0' },
      ...options,
    }, (res) => {
      if (res.statusCode === 302 || res.statusCode === 301) {
        file.close();
        fs.unlinkSync(outputPath);
        return downloadFile(res.headers.location, outputPath, options)
          .then(resolve, reject);
      }
      if (res.statusCode !== 200) {
        file.close();
        fs.unlinkSync(outputPath);
        return reject(new Error(`HTTP ${res.statusCode} ${res.statusMessage}`));
      }

      res.on('data', chunk => totalBytes += chunk.length);
      res.pipe(file);
      file.on('finish', () => {
        file.close();
        resolve({ path: outputPath, bytes: totalBytes });
      });
    });

    req.on('timeout', () => {
      req.destroy(new Error('타임아웃 (60s)'));
    });
    req.on('error', (e) => {
      file.close();
      try { fs.unlinkSync(outputPath); } catch (_) {}
      reject(e);
    });
  });
}


// ─── NVD Feed 파싱 ──────────────────────────────────
function parseNvdFeed(filePath) {
  let content;
  if (filePath.endsWith('.gz')) {
    content = zlib.gunzipSync(fs.readFileSync(filePath)).toString('utf8');
  } else {
    content = fs.readFileSync(filePath, 'utf8');
  }
  const feed = JSON.parse(content);
  
  const cves = {};
  for (const item of feed.CVE_Items || []) {
    const cve = item.cve;
    const id = cve?.CVE_data_meta?.ID;
    if (!id) continue;

    // CVSS v3
    let cvss = null;
    const m = item.impact?.baseMetricV3;
    if (m) {
      cvss = {
        score: m.cvssV3?.baseScore,
        vector: m.cvssV3?.vectorString,
        severity: m.cvssV3?.baseSeverity,
      };
    }

    // 설명
    const description = cve.description?.description_data
      ?.find(d => d.lang === 'en')?.value || '';

    // CPE 매칭 (영향 받는 패키지)
    const affected = [];
    for (const node of item.configurations?.nodes || []) {
      collectCpe(node, affected);
    }

    cves[id] = {
      cve_id: id,
      published: item.publishedDate?.slice(0, 10),
      last_modified: item.lastModifiedDate?.slice(0, 10),
      description,
      cvss_v3: cvss,
      affected,
      _source: 'nvd',
      _synced_at: timestamp(),
    };
  }
  return cves;
}

function collectCpe(node, out) {
  for (const m of node.cpe_match || []) {
    if (m.vulnerable) {
      out.push({
        cpe: m.cpe23Uri,
        version_start_inc: m.versionStartIncluding,
        version_start_exc: m.versionStartExcluding,
        version_end_inc: m.versionEndIncluding,
        version_end_exc: m.versionEndExcluding,
      });
    }
  }
  for (const child of node.children || []) {
    collectCpe(child, out);
  }
}


// ─── KEV 파싱 ───────────────────────────────────────
function parseKevFeed(filePath) {
  const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
  const kev = {};
  for (const v of data.vulnerabilities || []) {
    kev[v.cveID] = {
      vendor: v.vendorProject,
      product: v.product,
      name: v.vulnerabilityName,
      added: v.dateAdded,
      due: v.dueDate,
      required_action: v.requiredAction,
      ransomware: v.knownRansomwareCampaignUse === 'Known',
    };
  }
  return kev;
}


// ─── 변경 감지 ──────────────────────────────────────
function detectChanges(oldDb, newCves, kev) {
  const changes = {
    new: [],           // 신규 등재
    cvss_changed: [],  // CVSS 점수 변경
    kev_added: [],     // CISA KEV 신규 등재
    description_updated: [],
  };

  for (const [id, cve] of Object.entries(newCves)) {
    const old = oldDb[id];
    
    if (!old) {
      changes.new.push({
        cve_id: id,
        cvss: cve.cvss_v3?.score,
        severity: cve.cvss_v3?.severity,
        published: cve.published,
      });
      continue;
    }

    // CVSS 변경
    const oldScore = old.cvss_v3?.score;
    const newScore = cve.cvss_v3?.score;
    if (oldScore !== undefined && newScore !== undefined && oldScore !== newScore) {
      changes.cvss_changed.push({
        cve_id: id,
        before: oldScore,
        after: newScore,
        before_severity: old.cvss_v3?.severity,
        after_severity: cve.cvss_v3?.severity,
      });
    }

    // 설명 변경 (길이 차이로 간소화)
    if (old.description && cve.description && 
        Math.abs(old.description.length - cve.description.length) > 100) {
      changes.description_updated.push({
        cve_id: id,
        before_len: old.description.length,
        after_len: cve.description.length,
      });
    }
  }

  // KEV 신규 등재 (이전 DB에 KEV 마킹 없었는데 새로 추가됨)
  for (const [id, info] of Object.entries(kev)) {
    const old = oldDb[id];
    if (!old?.cisa_kev) {
      changes.kev_added.push({
        cve_id: id,
        vendor: info.vendor,
        product: info.product,
        due: info.due,
      });
    }
  }

  return changes;
}


// ─── 메인 ───────────────────────────────────────────
async function main() {
  const args = process.argv.slice(2);
  const opts = {
    full: args.includes('--full'),
    kevOnly: args.includes('--kev-only'),
    dryRun: args.includes('--dry-run'),
    fromFile: args.find(a => a.startsWith('--from-file='))?.split('=')[1],
  };

  ensureDir(CVE_DIR);
  ensureDir(FEED_DIR);

  log('CVE Feed 동기화 시작');
  log(`  설정: full=${opts.full}, kevOnly=${opts.kevOnly}, dryRun=${opts.dryRun}`);
  if (opts.fromFile) log(`  소스: ${opts.fromFile}`);

  const oldDb = loadJson(DB_FILE, {});
  const oldCount = Object.keys(oldDb).length;
  log(`  기존 DB: ${oldCount}건`);

  let newCves = {};
  let kev = {};

  // 1. NVD Feed
  if (!opts.kevOnly) {
    try {
      let nvdPath;
      if (opts.fromFile) {
        nvdPath = opts.fromFile;
        log(`  로컬 파일 사용: ${nvdPath}`);
      } else {
        const url = opts.full ? NVD_URLS.recent : NVD_URLS.modified;
        nvdPath = path.join(FEED_DIR, path.basename(url));
        log(`  NVD 다운로드: ${url}`);
        const r = await downloadFile(url, nvdPath);
        log(`  완료: ${(r.bytes / 1024).toFixed(1)} KB`);
      }
      newCves = parseNvdFeed(nvdPath);
      log(`  NVD 파싱: ${Object.keys(newCves).length}건`);
    } catch (e) {
      log(`⚠ NVD 다운로드/파싱 실패: ${e.message}`);
      if (!opts.fromFile) {
        log('  네트워크 차단 환경이면 --from-file 옵션을 사용하세요.');
      }
    }
  }

  // 2. KEV
  try {
    const kevPath = path.join(FEED_DIR, 'known_exploited_vulnerabilities.json');
    if (!opts.fromFile) {
      log(`  KEV 다운로드: ${KEV_URL}`);
      const r = await downloadFile(KEV_URL, kevPath);
      log(`  완료: ${(r.bytes / 1024).toFixed(1)} KB`);
    } else if (fs.existsSync(kevPath)) {
      log(`  KEV 로컬 파일 사용: ${kevPath}`);
    }
    if (fs.existsSync(kevPath)) {
      kev = parseKevFeed(kevPath);
      log(`  KEV 파싱: ${Object.keys(kev).length}건`);
    }
  } catch (e) {
    log(`⚠ KEV 다운로드/파싱 실패: ${e.message}`);
  }

  // 3. 변경 감지
  const changes = detectChanges(oldDb, newCves, kev);
  
  log('');
  log('─'.repeat(60));
  log('변경 감지 결과');
  log('─'.repeat(60));
  log(`  신규 CVE:           ${changes.new.length}건`);
  log(`  CVSS 점수 변경:     ${changes.cvss_changed.length}건`);
  log(`  CISA KEV 신규 등재: ${changes.kev_added.length}건`);
  log(`  설명 보강:          ${changes.description_updated.length}건`);
  log('');

  // 4. 상세 출력
  if (changes.new.length > 0) {
    log('▶ 신규 CVE (최근 10건):');
    for (const c of changes.new.slice(0, 10)) {
      console.log(`    ${c.cve_id}  CVSS ${c.cvss || '?'} (${c.severity || 'N/A'})  ${c.published || ''}`);
    }
    if (changes.new.length > 10) {
      console.log(`    ... 외 ${changes.new.length - 10}건`);
    }
    log('');
  }

  if (changes.cvss_changed.length > 0) {
    log('▶ CVSS 점수 변경:');
    for (const c of changes.cvss_changed.slice(0, 10)) {
      const arrow = c.after > c.before ? '↑' : '↓';
      console.log(`    ${c.cve_id}  ${c.before} (${c.before_severity}) → ${c.after} (${c.after_severity}) ${arrow}`);
    }
    log('');
  }

  if (changes.kev_added.length > 0) {
    log('▶ CISA KEV 신규 등재 (★ 즉시 확인 필요):');
    for (const c of changes.kev_added.slice(0, 20)) {
      console.log(`    ${c.cve_id}  ${c.vendor || ''} ${c.product || ''}  조치기한: ${c.due || '-'}`);
    }
    if (changes.kev_added.length > 20) {
      console.log(`    ... 외 ${changes.kev_added.length - 20}건`);
    }
    log('');
  }

  // 5. DB 저장
  if (opts.dryRun) {
    log('⚠ --dry-run 모드: DB 저장 안 함');
  } else {
    // 새 CVE를 기존 DB에 머지 + KEV 정보 추가
    const merged = { ...oldDb };
    for (const [id, cve] of Object.entries(newCves)) {
      merged[id] = {
        ...merged[id],
        ...cve,
        cisa_kev: !!kev[id],
        kev_info: kev[id] || null,
      };
    }
    // KEV-only CVE도 추가 (NVD에는 아직 안 들어왔지만 KEV 등재됨)
    for (const [id, info] of Object.entries(kev)) {
      if (!merged[id]) {
        merged[id] = {
          cve_id: id,
          cisa_kev: true,
          kev_info: info,
          _source: 'kev-only',
          _synced_at: timestamp(),
        };
      } else {
        merged[id].cisa_kev = true;
        merged[id].kev_info = info;
      }
    }
    
    saveJson(DB_FILE, merged);
    log(`✓ DB 저장: ${Object.keys(merged).length}건 (이전 ${oldCount}건)`);

    // 동기화 이력 저장
    const history = loadJson(HISTORY_FILE, []);
    history.unshift({
      timestamp: timestamp(),
      total_cves: Object.keys(merged).length,
      new_count: changes.new.length,
      cvss_changed: changes.cvss_changed.length,
      kev_added: changes.kev_added.length,
      description_updated: changes.description_updated.length,
    });
    saveJson(HISTORY_FILE, history.slice(0, 100));  // 최근 100회만
    log(`✓ 이력 저장`);
  }

  log('');
  log('동기화 완료');

  // 라우트에서 호출 시 사용할 결과 객체 반환
  return {
    total_cves: Object.keys(oldDb).length,  // main 끝나면 oldDb는 이미 머지 결과로 갱신
    new_count: 0,  // 자세한 통계는 sync-history.json 최신 항목으로
  };
}

// CLI 실행 시에만 main 자동 호출. 다른 모듈에서 require 시는 export만 제공.
if (require.main === module) {
  main().catch(e => {
    console.error('오류:', e);
    process.exit(1);
  });
}

// 라우트에서 require 가능하도록 export
module.exports = {
  /**
   * CVE 동기화 실행 (외부 호출용).
   *
   * @param {object} opts
   * @param {boolean} opts.full      — recent feed 사용 (기본은 modified)
   * @param {boolean} opts.kevOnly   — KEV만 갱신
   * @param {boolean} opts.dryRun    — 실제 저장 안 함
   * @param {string}  opts.fromFile  — 로컬 NVD 피드 경로 (폐쇄망용)
   * @returns {Promise<object>} 동기화 결과
   *
   * 주의: 현재 main()은 process.argv 파싱을 내장하므로 process.argv를 일시적으로
   *       조작하는 어댑터 형태. 더 클린한 분리는 차후.
   */
  async run(opts = {}) {
    const origArgv = process.argv;
    const synthArgs = ['node', 'sync-cve.js'];
    if (opts.full) synthArgs.push('--full');
    if (opts.kevOnly) synthArgs.push('--kev-only');
    if (opts.dryRun) synthArgs.push('--dry-run');
    if (opts.fromFile) synthArgs.push('--from-file=' + opts.fromFile);
    process.argv = synthArgs;
    try {
      const result = await main();
      return result;
    } finally {
      process.argv = origArgv;
    }
  },
};

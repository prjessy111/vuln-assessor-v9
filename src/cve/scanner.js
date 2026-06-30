'use strict';
/**
 * CVE 진단 통합 모듈
 *
 * 진단 결과(diagnosis)에 raw DB 파일 경로가 있으면
 * 거기서 rpm -qa를 다시 읽고 CVE 매칭 + AI 평가 수행.
 */

const fs = require('fs');
const path = require('path');
const matcher = require('./matcher');
const judge = require('./judge');

async function openSqliteDb(filePath) {
  // server-mock.js와 동일한 sql.js 로직 사용
  const initSqlJs = require('sql.js');
  const SQL = await initSqlJs();
  const buf = fs.readFileSync(filePath);
  const db = new SQL.Database(buf);
  
  return {
    prepare(sql) {
      return {
        all(...args) {
          if (args.length === 0) {
            const r = db.exec(sql);
            if (!r.length) return [];
            const { columns, values } = r[0];
            return values.map(row => Object.fromEntries(columns.map((c, i) => [c, row[i]])));
          }
          const stmt = db.prepare(sql);
          try {
            stmt.bind(args);
            const rows = [];
            while (stmt.step()) rows.push(stmt.getAsObject());
            return rows;
          } finally {
            stmt.free();
          }
        },
      };
    },
    close() { db.close(); },
  };
}

/**
 * CVE 진단 실행.
 *
 * @param {string} dbPath - SecuMS raw DB 경로
 * @param {object} environment - { os_distro, os_version, hostname }
 * @returns {Promise<object>} { matches, summary, env, packages_count }
 */
async function runCveScan(dbPath, environment) {
  const db = await openSqliteDb(dbPath);
  
  // 1. 패키지 추출
  const adapter = require('../engine/adapters/secumsUnix');
  const packages = adapter.extractPackages(db);
  
  if (packages.length === 0) {
    return {
      error: 'rpm -qa 데이터가 없습니다. SecuMS 정책에 rpm -qa 수집을 추가하세요.',
      packages_count: 0,
      matches: [],
      summary: { total: 0 },
    };
  }

  // 2. 시스템 메타 정보
  const meta = adapter.extractMeta(db);
  const env = {
    hostname: meta.host,
    os_distro: meta.osVersion?.toLowerCase().includes('centos') ? 'CentOS' : 'Linux',
    os_version: meta.osVersion,
    ...environment,
  };

  // 3. CVE 매칭 (결정론적)
  const matches = matcher.matchAll(packages);
  
  // 4. AI 평가
  const judged = await judge.judgeAll(matches, env, null /* mock */);
  
  // 5. 정렬
  const sorted = matcher.sortByPriority(judged);
  
  // 6. 통계
  const summary = matcher.summarize(sorted);
  
  // priority 통계 추가
  summary.by_priority = sorted.reduce((acc, m) => {
    const p = m.ai_judgment?.patch_priority || 'UNKNOWN';
    acc[p] = (acc[p] || 0) + 1;
    return acc;
  }, {});

  // is_vulnerable=true 만 카운트 (AI 평가 후 실제 취약)
  summary.actually_vulnerable = sorted.filter(m => m.ai_judgment?.is_vulnerable).length;

  if (db.close) db.close();

  return {
    packages_count: packages.length,
    env,
    matches: sorted,
    summary,
  };
}

/**
 * 스크립트 XML(ai_ready_script_v2)의 `rpm -qa -i` 원시 출력에서 패키지 추출.
 * SecuMS DB가 없는 서버(script 단독 수집)도 CVE 진단이 가능하도록 한다.
 *
 * 입력 형식(rpm -qa -i 상세):
 *   Name        : bash
 *   Version     : 4.2.46
 *   Release     : 34.el7
 *   Architecture: x86_64
 *   ...
 *
 * @returns {Array<{name, version, release, arch, full}>}  (secumsUnix.extractPackages와 동일 형식)
 */
function extractPackagesFromRpmInfoText(text) {
  const packages = [];
  let cur = null;
  const flush = () => {
    if (cur && cur.name && cur.version && cur.release) {
      const full = `${cur.name}-${cur.version}-${cur.release}` + (cur.arch ? `.${cur.arch}` : '');
      packages.push({ name: cur.name, version: cur.version, release: cur.release, arch: cur.arch, full });
    }
    cur = null;
  };
  for (const raw of String(text).split(/\r?\n/)) {
    let m;
    if ((m = raw.match(/^Name\s*:\s*(\S.*?)\s*$/))) { flush(); cur = { name: m[1], version: '', release: '', arch: '' }; }
    else if (cur && (m = raw.match(/^Version\s*:\s*(\S.*?)\s*$/))) cur.version = m[1];
    else if (cur && (m = raw.match(/^Release\s*:\s*(\S.*?)\s*$/))) cur.release = m[1];
    else if (cur && (m = raw.match(/^Architecture\s*:\s*(\S.*?)\s*$/))) cur.arch = (m[1] === '(none)' ? '' : m[1]);
  }
  flush();
  return packages;
}

/**
 * 스크립트 XML에서 특정 명령 마커("$ cmd") 출력 구간만 잘라낸다.
 * 다음 명령 마커($), 원시출력 종료, 블록 종료, CDATA 종료에서 멈춘다.
 */
function sliceCommandSection(xmlText, marker) {
  const start = xmlText.indexOf(marker);
  if (start < 0) return '';
  let rest = xmlText.slice(start + marker.length);
  let end = rest.length;
  for (const e of ['\nRAW_COMMAND_OUTPUT_END', '\nAI_EVIDENCE_BLOCK_END', '\n$ ', ']]>']) {
    const i = rest.indexOf(e);
    if (i >= 0 && i < end) end = i;
  }
  return rest.slice(0, end);
}
function sliceRpmInfoSection(xmlText) {
  return sliceCommandSection(xmlText, '$ rpm -qa -i');
}

/**
 * Debian/Ubuntu `dpkg -l` 출력에서 패키지 추출.
 * 형식: "ii  name[:arch]  [epoch:]version-release  arch  description"
 * → rpm 파서와 동일한 {name, version, release, arch, full} 형식으로 정규화.
 */
// Debian/Ubuntu 패키지명 → 표준(upstream) 라이브러리명 정규화.
// CVE DB는 upstream 명(openssl/zlib/expat…)을 쓰므로 deb 명을 맞춰준다.
const DEB_NAME_ALIAS = {
  'zlib1g': 'zlib', 'zlib1g-dev': 'zlib',
  'libssl1.1': 'openssl', 'libssl3': 'openssl', 'libssl1.0.0': 'openssl', 'libssl1.0.2': 'openssl',
  'libexpat1': 'expat', 'libexpat1-dev': 'expat',
  'libsqlite3-0': 'sqlite', 'sqlite3': 'sqlite',
  'libcurl4': 'curl', 'libcurl3': 'curl', 'libcurl3-gnutls': 'curl', 'libcurl4-openssl-dev': 'curl',
  'libpcre3': 'pcre', 'libpcre2-8-0': 'pcre',
  'libwebp7': 'libwebp', 'libwebp6': 'libwebp', 'libwebp5': 'libwebp',
};
function normalizeDebName(name) {
  const n = String(name || '').toLowerCase();
  if (DEB_NAME_ALIAS[n]) return DEB_NAME_ALIAS[n];
  return n;
}
function extractPackagesFromDpkgText(text) {
  const packages = [];
  for (const raw of String(text).split(/\r?\n/)) {
    const m = raw.match(/^([a-z]{2,3})\s+(\S+)\s+(\S+)\s+(\S+)\s/);
    if (!m || !/^[hi][i]?[i]?$/i.test(m[1])) continue; // ii / hi 등 설치상태만
    const rawName = m[2].replace(/:.*$/, '');          // openssl:amd64 → openssl
    const name = normalizeDebName(rawName);            // libssl1.1 → openssl
    const verFull = m[3];
    const arch = m[4] === '(none)' ? '' : m[4];
    const noEpoch = verFull.replace(/^\d+:/, '');       // 1:2.3 → 2.3
    const dash = noEpoch.indexOf('-');
    const version = dash > 0 ? noEpoch.slice(0, dash) : noEpoch;
    const release = dash > 0 ? noEpoch.slice(dash + 1) : '';
    if (!name || !version) continue;
    packages.push({ name, version, release, arch, full: `${rawName}-${verFull}` });
  }
  return packages;
}
function sliceDpkgSection(xmlText) {
  return sliceCommandSection(xmlText, '$ dpkg -l') || sliceCommandSection(xmlText, '$ dpkg-query');
}

/**
 * JAR(자바 라이브러리) 인벤토리 추출 — 내장 라이브러리 CVE(Log4j/Commons 등) 매칭.
 * 윈도우 INV-JAR / 리눅스 jar-inventory 섹션의 *.jar 파일명 → {name, version}.
 */
function extractJarsFromScriptXml(xmlText) {
  const txt = String(xmlText || '');
  let sec = sliceCommandSection(txt, '$ jar-inventory');
  if (!sec) {
    const m = txt.match(/check_ids=INV-JAR[\s\S]*?RAW_COMMAND_OUTPUT_BEGIN([\s\S]*?)RAW_COMMAND_OUTPUT_END/i);
    sec = m ? m[1] : '';
  }
  if (!sec) return [];
  const out = [];
  const seen = new Set();
  for (const raw of sec.split(/\r?\n/)) {
    const s = raw.trim();
    if (!s || s.startsWith('$') || /cmd#|RAW_COMMAND|AI_EVIDENCE/.test(s)) continue;
    const base = s.split(/[\\/]/).pop();
    const m = base.match(/^(.+?)-(\d[\d.]*[a-z]?)(?:[-_+].*)?\.jar$/i);
    if (!m) continue;
    const name = m[1].toLowerCase().trim();
    const version = m[2];
    const k = name + '@' + version;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push({ name, version, release: '', arch: '', full: base });
  }
  return out;
}

/**
 * 경량 `rpm -qa`(NVRA 한 줄: name-version-release.arch) 출력 파싱.
 * 우리 스크립트가 rpm -qa -i → rpm -qa 로 경량화되면 이 경로로 처리.
 * 검증된 secumsUnix.parseRpmPackage 재사용.
 */
function extractPackagesFromRpmQaText(text) {
  let parseRpmPackage;
  try { ({ parseRpmPackage } = require('../engine/adapters/secumsUnix')); } catch (_) { return []; }
  const out = [];
  for (const raw of String(text).split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('$') || /command not found|RAW_COMMAND|AI_EVIDENCE|cmd#|^</.test(line)) continue;
    // NVRA 대략 형태(이름-버전-릴리스.아키)만 시도
    if (!/^[A-Za-z0-9].*-.+-.+\.[A-Za-z0-9_]+$/.test(line)) continue;
    const p = parseRpmPackage(line);
    if (p && p.name && p.version) out.push(p);
  }
  return out;
}

/**
 * 스크립트 XML 기반 Linux CVE 진단 (SecuMS DB 불필요).
 * runCveScan과 동일한 결과 형식을 반환한다.
 *
 * @param {string} xmlPath - 스크립트 수집 XML 경로
 * @param {object} environment - { hostname }
 */
async function runCveScanFromScript(xmlPath, environment) {
  const xmlText = fs.readFileSync(xmlPath, 'utf8');
  const hasRpmI = xmlText.includes('$ rpm -qa -i');
  let packages = hasRpmI ? extractPackagesFromRpmInfoText(sliceRpmInfoSection(xmlText)) : [];
  let pkgManager = 'rpm';

  // 경량 `rpm -qa`(NVRA) — -i 상세가 없을 때 (스크립트 경량화 경로)
  if (packages.length === 0 && !hasRpmI) {
    const qaSection = sliceCommandSection(xmlText, '$ rpm -qa');
    if (qaSection) packages = extractPackagesFromRpmQaText(qaSection);
  }

  // RPM 인벤토리가 없으면 Debian/Ubuntu(dpkg) 시도
  if (packages.length === 0) {
    const dpkgSection = sliceDpkgSection(xmlText);
    if (dpkgSection) {
      packages = extractPackagesFromDpkgText(dpkgSection);
      pkgManager = 'dpkg';
    }
  }

  // JAR(자바 라이브러리) 인벤토리 — OS 패키지와 별개로 항상 추가 (내장 라이브러리 계층)
  const jars = extractJarsFromScriptXml(xmlText);
  if (jars.length) packages = packages.concat(jars);

  // SBOM(CycloneDX/SPDX) — 있으면 purl 정확 식별 컴포넌트 추가
  try {
    const sbom = require('./sbomParser').extractSbomFromScriptXml(xmlText)
      .map(c => ({ name: c.name, version: c.version, release: '', arch: '', full: c.name + '-' + c.version }));
    if (sbom.length) packages = packages.concat(sbom);
  } catch (_) {}

  if (packages.length === 0) {
    return {
      error: '스크립트 XML에 패키지 인벤토리가 없습니다. RHEL/CentOS는 rpm -qa -i, Ubuntu/Debian은 dpkg -l 수집이 필요합니다. -Full(FSI_ENABLE_PATCHINFO=1)로 재수집하세요.',
      packages_count: 0,
      matches: [],
      summary: { total: 0 },
    };
  }

  // 배포판 판별: rpm=CentOS/RHEL, dpkg=Ubuntu/Debian (ID/VERSION_ID 우선)
  const idMatch = xmlText.match(/(?:^|\n)\s*ID="?(ubuntu|debian|centos|rhel|rocky|almalinux)"?/i);
  const osVerMatch = xmlText.match(/CentOS Linux release ([\d.]+)/i) || xmlText.match(/VERSION_ID="?([\d.]+)/i);
  let distro = idMatch ? idMatch[1] : (pkgManager === 'dpkg' ? 'Ubuntu/Debian' : 'CentOS');
  distro = distro.charAt(0).toUpperCase() + distro.slice(1);
  const env = {
    hostname: (environment && environment.hostname) || '-',
    os_distro: distro,
    os_version: osVerMatch ? osVerMatch[1] : '-',
    ...environment,
  };

  const matches = matcher.matchAll(packages);
  let judged = await judge.judgeAll(matches, env, null /* mock */);
  // 백포트 결정론 판정 (배포판 advisory) — 기본 비활성(네트워크). CVE_BACKPORT_CHECK=1 로 활성.
  if (String(process.env.CVE_BACKPORT_CHECK || '') === '1') {
    try { judged = await require('./distroAdvisory').refine(judged, env, { max: 80 }); } catch (_) {}
  }
  const sorted = matcher.sortByPriority(judged);
  const summary = matcher.summarize(sorted);
  summary.by_priority = sorted.reduce((acc, m) => {
    const p = m.ai_judgment?.patch_priority || 'UNKNOWN';
    acc[p] = (acc[p] || 0) + 1;
    return acc;
  }, {});
  summary.actually_vulnerable = sorted.filter(m => m.ai_judgment?.is_vulnerable).length;

  return { packages_count: packages.length, env, matches: sorted, summary };
}

module.exports = {
  runCveScan,
  runCveScanFromScript,
  extractPackagesFromRpmInfoText,
};

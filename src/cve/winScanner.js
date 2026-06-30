'use strict';
/**
 * Windows CVE 자동 진단 모듈.
 *
 * Linux(rpm -qa + 버전범위)와 달리 Windows는 OS 빌드 + 설치된 핫픽스(KB)로 판정한다.
 * 모델:
 *   1. SecuMS Windows DB(W_* 테이블)에서 인벤토리 추출
 *        - OS 제품/빌드/UBR (SYSTEM_INFO_TB, W_SYSTEMINFO_TB)
 *        - 설치 핫픽스 KB 목록 (W_HOTFIX_TB)
 *        - 서비스 상태 (W_SERVICE_TB) — 일부 CVE는 특정 서비스 실행이 조건
 *   2. 큐레이션 Windows CVE DB(cve-windows-curated.json)와 매칭
 *        - 패치 판정(결정론적): 빌드 UBR >= fixed_ubr 이거나 fixed_by_kb 중 하나가 설치됨 → 패치됨
 *        - 그 외 → 미패치(AFFECTED)
 *   3. 휴리스틱 판정(KEV/CVSS/서비스 노출)으로 우선순위 산출
 *
 * 결과 구조는 Linux scanner.runCveScan 과 동일한 형태(matches/summary/env)로 반환하여
 * 화면(cve/scan_windows.ejs)이 재사용 가능하게 한다.
 */

const fs = require('fs');
const path = require('path');

let _winCveCache = null;

function loadWinCveDb() {
  if (_winCveCache) return _winCveCache;
  const p = path.join(__dirname, '../../data/cve/cve-windows-curated.json');
  _winCveCache = JSON.parse(fs.readFileSync(p, 'utf8'));
  return _winCveCache;
}

function invalidateWinCveCache() { _winCveCache = null; _swCveCache = null; }

// ── 서드파티 소프트웨어 CVE (설치 SW 인벤토리 name+version 매칭) ──
let _swCveCache = null;
function loadSoftwareCveDb() {
  if (_swCveCache) return _swCveCache;
  try {
    const p = path.join(__dirname, '../../data/cve/cve-software-curated.json');
    const j = JSON.parse(fs.readFileSync(p, 'utf8'));
    _swCveCache = Array.isArray(j) ? j : (j.cves || []);
  } catch (_) { _swCveCache = []; }
  return _swCveCache;
}

// 버전 비교 (숫자+문자 접미사 지원: "1.0.2o", "2.15.0", "17.7.2.1")
function _verParts(v) {
  return String(v || '').split(/[^0-9a-zA-Z]+/).filter(Boolean).map(x => {
    const m = x.match(/^(\d+)([a-zA-Z]*)$/);
    return m ? [parseInt(m[1], 10), m[2]] : [0, x];
  });
}
function _cmpVer(a, b) {
  const pa = _verParts(a), pb = _verParts(b);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] || [0, ''], y = pb[i] || [0, ''];
    if (x[0] !== y[0]) return x[0] < y[0] ? -1 : 1;
    if (x[1] !== y[1]) return x[1] < y[1] ? -1 : 1;
  }
  return 0;
}
function _inRange(v, ranges) {
  return (ranges || []).some(r =>
    (r.from == null || _cmpVer(v, r.from) >= 0) &&
    (r.to == null || _cmpVer(v, r.to) < 0));
}
function _normName(n) { return ' ' + String(n || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim() + ' '; }

/**
 * 설치 소프트웨어 인벤토리 vs 소프트웨어 CVE DB 매칭.
 * @param {Array} software - [{name, version, publisher}]
 */
function matchWindowsSoftware(software) {
  let nvd = [];
  try { nvd = require('./nvdCpe').load(); } catch (_) {}
  const db = loadSoftwareCveDb().concat(nvd);  // 큐레이션 + NVD 전체 CPE
  const out = [];
  for (const sw of (software || [])) {
    if (!sw.version) continue;
    const nn = _normName(sw.name);
    for (const cve of db) {
      const aliases = [cve.package, ...(cve.aliases || [])]
        .map(a => String(a || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim())
        .filter(Boolean);
      if (!aliases.some(a => nn.includes(' ' + a + ' '))) continue;
      if (!_inRange(sw.version, cve.affected_versions)) continue;
      const src = cve._source === 'nvd-cpe' ? 'NVD CPE' : (cve._source || '큐레이션 DB');
      const rng = (cve.affected_versions || []).map(r => `${r.from || '0'}~${r.to || '∞'}`).join(', ');
      out.push({
        cve_id: cve.cve_id,
        name: cve.name,
        severity: cve.severity,
        cvss_v3: cve.cvss_v3,
        cisa_kev: !!cve.cisa_kev,
        exploit_public: !!cve.exploit_public,
        software: sw.name,
        version: sw.version,
        fixed: cve.fixed,
        package: cve.package,
        // 표기 근거: 어떤 버전범위에 들었고 어느 출처(NVD/큐레이션) 데이터인지
        basis: `설치 버전 ${sw.version}이(가) 영향 범위(${rng})에 포함 · 출처: ${src}` + (cve.fixed ? ` · 수정버전: ${cve.fixed}` : ''),
        source: src,
        matched_range: rng,
        // 출처별 백포트 위험 구분: 번들 라이브러리(JAR/native)=낮음(버전 신뢰), 설치 프로그램=중간.
        confidence: 'version-only',
        backport_risk: /jar|native lib|라이브러리/.test(sw.publisher || '') ? 'low' : 'medium',
        caveat: /jar|native lib|라이브러리/.test(sw.publisher || '')
          ? '번들 라이브러리 — 버전 신뢰도 높음(배포판 백포트 적음). 단 취약 기능 실제 사용여부(도달성)는 미검증.'
          : '버전 기준 잠재 취약 — 벤더 패치·실사용 미검증, 검토 필요.',
        verdict: 'POTENTIAL',
      });
    }
  }
  // CVE+SW 중복 제거
  const seen = new Set();
  return out.filter(m => {
    const k = m.cve_id + '|' + m.software + '|' + m.version;
    if (seen.has(k)) return false; seen.add(k); return true;
  });
}

async function openSqliteDb(filePath) {
  const initSqlJs = require('sql.js');
  const SQL = await initSqlJs();
  const buf = fs.readFileSync(filePath);
  const db = new SQL.Database(buf);
  return {
    all(sql) {
      const r = db.exec(sql);
      if (!r.length) return [];
      const { columns, values } = r[0];
      return values.map(row => Object.fromEntries(columns.map((c, i) => [c, row[i]])));
    },
    has(table) {
      const r = db.exec(`SELECT name FROM sqlite_master WHERE type='table' AND name='${table}'`);
      return r.length > 0;
    },
    close() { db.close(); },
  };
}

/**
 * Windows 인벤토리 추출.
 * @returns {{ hostname, osName, osVersion, build, ubr, hotfixes, kbSet, services }}
 */
function extractWindowsInventory(db) {
  const meta = {};
  try {
    db.all('SELECT KEY, VALUE FROM SYSTEM_INFO_TB').forEach(r => { meta[r.KEY] = r.VALUE; });
  } catch (_) { /* ignore */ }

  let osName = meta['OS'] || '';
  let osVersion = meta['OS VERSION'] || '';
  // W_SYSTEMINFO_TB 로 보강 (osName/osVersion/osBit)
  try {
    if (db.has('W_SYSTEMINFO_TB')) {
      const s = db.all('SELECT osName, osVersion, osBit FROM W_SYSTEMINFO_TB')[0];
      if (s && !osVersion && s.osVersion) osVersion = String(s.osVersion);
    }
  } catch (_) { /* ignore */ }

  // 빌드/UBR 파싱: "10.0.14393" 또는 "10.0.14393.4583"
  const bm = String(osVersion).match(/(\d+\.\d+\.\d+)(?:\.(\d+))?/);
  const build = bm ? bm[1] : '';
  const ubr = bm && bm[2] !== undefined ? parseInt(bm[2], 10) : null;

  // 설치 핫픽스
  let hotfixes = [];
  try {
    if (db.has('W_HOTFIX_TB')) {
      hotfixes = db.all('SELECT HotFixID, Description, InstallDay FROM W_HOTFIX_TB')
        .map(r => ({ id: String(r.HotFixID || '').toUpperCase().trim(), desc: r.Description, day: r.InstallDay }))
        .filter(h => /^KB\d+/.test(h.id));
    }
  } catch (_) { /* ignore */ }
  const kbSet = new Set(hotfixes.map(h => h.id));

  // 서비스 (조건부 CVE 평가용)
  let services = [];
  try {
    if (db.has('W_SERVICE_TB')) {
      services = db.all('SELECT NAME, DISPLAYNAME, STATE, STARTMODE FROM W_SERVICE_TB')
        .map(r => ({
          name: String(r.NAME || ''),
          display: String(r.DISPLAYNAME || ''),
          state: String(r.STATE || ''),
          startmode: String(r.STARTMODE || ''),
        }));
    }
  } catch (_) { /* ignore */ }

  return {
    hostname: meta['HOSTNAME'] || '',
    osName: osName || `Windows ${osVersion}`,
    osVersion,
    build,
    ubr,
    hotfixes,
    kbSet,
    services,
  };
}

/**
 * 배포 스크립트(.ps1)가 만든 script XML 에서 Windows 인벤토리 추출.
 * 패치 데이터는 SRV-120(wmic qfe list / Get-HotFix), SRV-117(systeminfo)에 담긴다.
 * fast 모드로 수집되면 두 항목이 SKIPPED_FOR_SPEED 라 핫픽스 목록이 비고 → incomplete=true.
 */
function extractWindowsInventoryFromScriptXml(xmlText) {
  const txt = String(xmlText || '');
  const getTag = (tag) => {
    const m = txt.match(new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`, 'i'));
    return m ? m[1].trim() : '';
  };
  const hostname = getTag('hostname');
  const osRaw = getTag('os');
  const uname = getTag('uname');   // 예: "Microsoft Windows NT 10.0.14393.0"
  const versionTag = getTag('version');

  // 빌드: uname 의 10.0.NNNNN, systeminfo 의 "Build NNNNN" 등에서 추출
  const buildM = (uname.match(/(\d+\.\d+\.\d+)/) || txt.match(/OS\s*Version:\s*(\d+\.\d+\.\d+)/i) || [])[1] || '';

  // dump 별 raw 출력 모으기
  const dumps = txt.match(/<dump>[\s\S]*?<\/dump>/g) || [];
  const dumpFor = (srv) => {
    const re = new RegExp('SRV-?0*' + srv.replace(/^SRV-?/, '') + '\\b', 'i');
    return dumps.find(d => {
      const ids = (d.match(/<id>([^<]+)<\/id>/g) || []).map(m => m.replace(/<\/?id>/g, ''));
      return ids.some(i => re.test(i));
    });
  };
  const rawOf = (dmp) => {
    if (!dmp) return '';
    const o = (dmp.match(/<output>([\s\S]*?)<\/output>/) || [])[1] || '';
    return o.replace(/<!\[CDATA\[|\]\]>/g, '');
  };

  const hotfixDump = rawOf(dumpFor('120'));      // wmic qfe list / Get-HotFix
  const systeminfoDump = rawOf(dumpFor('117'));  // systeminfo (KB 목록 포함)
  const combined = `${hotfixDump}\n${systeminfoDump}`;

  const skipped = /SKIPPED_FOR_SPEED/i.test(hotfixDump) && /SKIPPED_FOR_SPEED/i.test(systeminfoDump);

  // KB 추출 (두 출처 모두에서)
  const kbs = Array.from(new Set((combined.match(/KB\d{6,7}/gi) || []).map(k => k.toUpperCase())));
  const hotfixes = kbs.map(id => ({ id, desc: '', day: '' }));
  const kbSet = new Set(kbs);

  const incomplete = kbSet.size === 0;  // 패치 목록을 못 얻음 → 판정 불가(보통 fast 모드)

  return {
    hostname,
    osName: osRaw || versionTag || 'Windows',
    osVersion: buildM,
    build: buildM,
    ubr: null,                 // script 수집에는 신뢰할 UBR이 없어 KB 집합으로만 판정
    hotfixes,
    kbSet,
    services: [],              // script 경로에선 서비스 상태 미상 → 조건부 가중 생략
    incomplete,
    skipped,
    source: 'script',
  };
}

/**
 * INV-SOFTWARE(레지스트리 Uninstall) 원문에서 설치 소프트웨어 인벤토리 추출.
 * 형식(fsi_win_ai.ps1 INV-SOFTWARE): "DisplayName | DisplayVersion | Publisher"
 * → rpm -qa 의 Windows 대응. 서드파티 SW CVE 매칭의 입력(name+version)으로 사용.
 */
function extractWindowsSoftwareFromScriptXml(xmlText) {
  const txt = String(xmlText || '');
  const m = txt.match(/check_ids=INV-SOFTWARE[\s\S]*?RAW_COMMAND_OUTPUT_BEGIN([\s\S]*?)RAW_COMMAND_OUTPUT_END/i);
  if (!m) return [];
  const out = [];
  for (const rawLine of m[1].split(/\r?\n/)) {
    const s = rawLine.trim()
      .replace(/&amp;/g, '&').replace(/&lt;/g, '<').replace(/&gt;/g, '>');
    if (!s || /^cmd#/i.test(s)) continue;
    const parts = s.split('|').map(x => x.trim());
    if (!parts[0]) continue;
    out.push({ name: parts[0], version: parts[1] || '', publisher: parts[2] || '' });
  }
  // 이름 기준 중복 제거
  const seen = new Set();
  return out.filter(p => {
    const k = (p.name + '|' + p.version).toLowerCase();
    if (seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

/**
 * JAR 파일명 → {name, version}. 예: "log4j-core-2.14.1.jar" → {log4j-core, 2.14.1}
 * 마지막 "-<숫자>" 앞을 이름, 뒤를 버전으로 분리.
 */
function parseJarFilename(fname) {
  // 이름(비탐욕) - 선행 semver 토큰(숫자.숫자…[단일문자]) - (빌드/타임스탬프 접미사 무시) .jar
  // 예: hadoop-auth-2.6.0.2.2.0.0-2041.jar → {hadoop-auth, 2.6.0.2.2.0.0}
  //     axis2-adb-1.7.0-20130831.003130-1701.jar → {axis2-adb, 1.7.0}
  //     log4j-core-2.14.1.jar → {log4j-core, 2.14.1}
  const m = String(fname || '').trim().match(/^(.+?)-(\d[\d.]*[a-z]?)(?:[-_+].*)?\.jar$/i);
  if (!m) return null;
  return { name: m[1].toLowerCase().trim(), version: m[2] };
}

/**
 * INV-JAR(파일시스템 JAR 스캔) 섹션에서 Java 라이브러리 인벤토리 추출.
 * docx의 "내장 라이브러리(JAR)" 계층을 우리도 명령으로 수집 → 매칭.
 */
function extractJarsFromScriptXml(xmlText) {
  const txt = String(xmlText || '');
  const m = txt.match(/check_ids=INV-JAR[\s\S]*?RAW_COMMAND_OUTPUT_BEGIN([\s\S]*?)RAW_COMMAND_OUTPUT_END/i);
  if (!m) return [];
  const out = [];
  const seen = new Set();
  for (const rawLine of m[1].split(/\r?\n/)) {
    const s = rawLine.trim();
    if (!s || /^cmd#/i.test(s)) continue;
    const base = s.split(/[\\/]/).pop();            // 경로 제거 → 파일명
    if (!/\.jar$/i.test(base)) continue;
    const p = parseJarFilename(base);
    if (!p || !p.name || !p.version) continue;
    const k = p.name + '@' + p.version;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push({ name: p.name, version: p.version, publisher: '(jar/라이브러리)' });
  }
  return out;
}

/**
 * INV-NATIVELIB(네이티브 OSS 라이브러리 버전 프로브) 파싱.
 * 형식: "libname | version | file" (스크립트가 .dll strings에서 OpenSSL/zlib/expat 등 버전 추출)
 * → 번들 오픈소스 라이브러리 CVE 매칭(POCO 번들 OpenSSL/zlib 등).
 */
function extractNativeLibsFromScriptXml(xmlText) {
  const txt = String(xmlText || '');
  const m = txt.match(/check_ids=INV-NATIVELIB[\s\S]*?RAW_COMMAND_OUTPUT_BEGIN([\s\S]*?)RAW_COMMAND_OUTPUT_END/i);
  if (!m) return [];
  const out = [];
  const seen = new Set();
  for (const rawLine of m[1].split(/\r?\n/)) {
    const s = rawLine.trim();
    if (!s || /^cmd#/i.test(s)) continue;
    const p = s.split('|').map(x => x.trim());
    if (p.length < 2 || !p[0] || !p[1] || !/^\d/.test(p[1])) continue;
    const k = p[0].toLowerCase() + '@' + p[1];
    if (seen.has(k)) continue;
    seen.add(k);
    out.push({ name: p[0].toLowerCase(), version: p[1], publisher: '(native lib)' });
  }
  return out;
}

function osProductLabel(inv) {
  const t = `${inv.osName} ${inv.osVersion}`.toLowerCase();
  if (t.includes('2022')) return 'Windows Server 2022';
  if (t.includes('2019')) return 'Windows Server 2019';
  if (t.includes('2016')) return 'Windows Server 2016';
  if (t.includes('2012')) return 'Windows Server 2012';
  if (t.includes('2008')) return 'Windows Server 2008';
  if (t.includes('windows 11') || /10\.0\.2[2-9]\d{3}/.test(inv.build)) return 'Windows 11';
  if (t.includes('windows 10') || /10\.0\.1\d{4}/.test(inv.build)) return 'Windows 10';
  return inv.osName || 'Windows';
}

function findServiceState(inv, name) {
  if (!name) return null;
  const s = inv.services.find(x => x.name.toLowerCase() === name.toLowerCase());
  if (!s) return null;
  return { exists: true, running: /run/i.test(s.state), startmode: s.startmode, display: s.display };
}

// OS 빌드가 CVE 영향 대상인지 + 해당 빌드의 fixed_ubr 반환.
function matchBuild(cve, inv) {
  const builds = (cve.affected && cve.affected.builds) || [];
  const byBuild = builds.find(b => inv.build && inv.build.startsWith(b.build));
  if (byBuild) return byBuild;
  // 빌드 prefix 미일치 시 제품명으로 느슨하게 매칭 (fixed_ubr 없음 → KB로만 판정)
  const label = osProductLabel(inv);
  const prods = (cve.affected && cve.affected.products) || [];
  if (prods.some(p => p.toLowerCase() === label.toLowerCase())) {
    return { product: label, fixed_ubr: null, _loose: true };
  }
  return null;
}

// 패치 여부 결정 — UBR 우선, 없으면 설치 KB 집합으로.
function isPatched(cve, inv, buildHit) {
  if (buildHit && buildHit.fixed_ubr != null && inv.ubr != null) {
    return inv.ubr >= buildHit.fixed_ubr;
  }
  const fixed = (cve.fixed_by_kb || []).map(k => String(k).toUpperCase());
  for (const kb of fixed) if (inv.kbSet.has(kb)) return true;
  return false;
}

/**
 * 인벤토리 vs 큐레이션 Windows CVE DB 매칭.
 */
function matchAll(inv) {
  const cves = loadWinCveDb();
  const results = [];

  for (const cve of cves) {
    const buildHit = matchBuild(cve, inv);
    if (!buildHit) continue;  // 이 OS 대상 아님

    const patched = isPatched(cve, inv, buildHit);

    const svc = cve.requires_service ? findServiceState(inv, cve.requires_service) : null;
    const serviceActive = svc ? svc.running : null;

    const fixKb = (cve.fixed_by_kb && cve.fixed_by_kb[0]) || (cve.patches && cve.patches.kb) || '-';
    const ourRelease = inv.ubr != null
      ? `${inv.build}.${inv.ubr}`
      : (inv.kbSet.size ? Array.from(inv.kbSet).join(', ') : '(핫픽스 없음)');
    const patchRelease = buildHit.fixed_ubr != null ? `${buildHit.build || inv.build}.${buildHit.fixed_ubr} (${fixKb})` : fixKb;

    results.push({
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

      // 화면 호환 필드
      pkg_name: osProductLabel(inv),
      pkg_full: `${osProductLabel(inv)} (${inv.build}${inv.ubr != null ? '.' + inv.ubr : ''})`,
      data_incomplete: !!inv.incomplete,
      backport: { isPatched: patched, ourRelease, patchRelease },
      patches: {
        upstream: cve.patches && cve.patches.bulletin,
        windows_kb: fixKb,
        guidance: cve.patches && cve.patches.guidance,
      },

      // Windows 전용 메타
      fix_kb: fixKb,
      fixed_by_kb: cve.fixed_by_kb || [],
      installed_kbs: Array.from(inv.kbSet),
      requires_service: cve.requires_service || null,
      service_active: serviceActive,
      service_note: svc
        ? `${cve.requires_service} 서비스: ${svc.running ? '실행 중' : (svc.exists ? '중지됨' : '없음')}`
        : null,

      initial_verdict: patched ? 'LIKELY_PATCHED' : 'AFFECTED',
      confidence: buildHit.fixed_ubr != null && inv.ubr != null ? 'high' : 'medium',
    });
  }
  return results;
}

// 휴리스틱 판정 (mock).
function judge(match) {
  // 핫픽스(KB) 목록을 못 얻은 경우(보통 -Fast 수집) → 취약/안전 단정 금지.
  if (match.data_incomplete) {
    return {
      is_vulnerable: false,
      data_incomplete: true,
      actual_severity: match.severity,
      patch_priority: 'MONITOR',
      rationale_ko: `패치(KB) 목록이 수집되지 않아 ${match.cve_id}의 적용 여부를 확정할 수 없습니다. 수집을 -Full 모드로 실행하면(Get-HotFix/systeminfo) 자동 판정됩니다.`,
      exploit_scenario: '패치 상태 확인 필요 (데이터 부족).',
      recommended_actions: ['수집을 -Full 모드로 재실행', `재수집 후 ${match.fix_kb} 이상 설치 여부 확인`],
      judged_by: 'mock_heuristic',
    };
  }
  if (match.backport.isPatched) {
    return {
      is_vulnerable: false,
      actual_severity: 'LOW',
      patch_priority: 'MONITOR',
      rationale_ko: `설치된 패치(${match.fix_kb} 또는 이후 누적 업데이트)로 ${match.cve_id}는 해결된 상태입니다. (현재 빌드/패치: ${match.backport.ourRelease})`,
      exploit_scenario: '패치 적용으로 익스플로잇 불가.',
      recommended_actions: ['패치 상태 유지', '월간 누적 업데이트 적용 지속'],
      judged_by: 'mock_heuristic',
    };
  }

  // 미패치
  let priority = 'SCHEDULED';
  if (match.cisa_kev) priority = 'IMMEDIATE';
  else if (match.cvss_v3 >= 9.0 || match.exploit_public) priority = 'URGENT';

  // 서비스 조건이 있고 실행 중이 아니면 공격 표면 제한 → 한 단계 완화
  let svcSentence = '';
  if (match.requires_service) {
    if (match.service_active === false) {
      priority = priority === 'IMMEDIATE' ? 'URGENT' : (priority === 'URGENT' ? 'SCHEDULED' : 'MONITOR');
      svcSentence = ` 다만 관련 서비스(${match.requires_service})가 실행 중이 아니어서 즉시 공격 표면은 제한적입니다.`;
    } else if (match.service_active === true) {
      svcSentence = ` 관련 서비스(${match.requires_service})가 실행 중이어서 공격 표면이 활성화되어 있습니다.`;
    }
  }

  const rationale = `이 시스템(${match.pkg_full})은 ${match.fix_kb}(또는 이후 누적 업데이트)가 설치되지 않아 ${match.cve_id}에 취약합니다.` +
    (match.cisa_kev ? ` CISA KEV 등재 — 활성 익스플로잇이 존재하여 즉시 조치가 필요합니다.` : ` CVSS ${match.cvss_v3} (${match.severity}).`) +
    svcSentence;

  const actions = [
    `${match.fix_kb} 이상 누적 보안 업데이트 설치`,
    match.patches.guidance || 'Microsoft 보안 권고에 따른 조치 적용',
  ];
  if (match.requires_service && match.service_active) {
    actions.push(`불필요 시 ${match.requires_service} 서비스 비활성화 또는 접근 제한`);
  }
  if (match.cisa_kev) actions.push('이벤트 로그에서 익스플로잇 흔적 점검');

  return {
    is_vulnerable: true,
    actual_severity: match.severity,
    patch_priority: priority,
    rationale_ko: rationale,
    exploit_scenario: (match.tags && match.tags.includes('rce'))
      ? '인증 전/후 원격 코드 실행으로 시스템 장악 가능.'
      : '권한 상승 또는 인증 우회로 추가 침해에 활용 가능.',
    recommended_actions: actions,
    judged_by: 'mock_heuristic',
  };
}

function sortByPriority(matches) {
  const rank = { IMMEDIATE: 0, URGENT: 1, SCHEDULED: 2, MONITOR: 3 };
  return matches.slice().sort((a, b) => {
    if (a.cisa_kev !== b.cisa_kev) return a.cisa_kev ? -1 : 1;
    if (a.backport.isPatched !== b.backport.isPatched) return a.backport.isPatched ? 1 : -1;
    const ra = rank[a.ai_judgment.patch_priority] ?? 9;
    const rb = rank[b.ai_judgment.patch_priority] ?? 9;
    if (ra !== rb) return ra - rb;
    return b.cvss_v3 - a.cvss_v3;
  });
}

function summarize(matches) {
  const sev = (s) => matches.filter(m => m.severity === s).length;
  const prio = (p) => matches.filter(m => m.ai_judgment.patch_priority === p).length;
  return {
    total: matches.length,
    by_severity: { critical: sev('CRITICAL'), high: sev('HIGH'), medium: sev('MEDIUM'), low: sev('LOW') },
    kev_count: matches.filter(m => m.cisa_kev).length,
    patched_count: matches.filter(m => m.backport.isPatched).length,
    unpatched_count: matches.filter(m => !m.backport.isPatched).length,
    exploit_public_count: matches.filter(m => m.exploit_public).length,
    by_priority: {
      IMMEDIATE: prio('IMMEDIATE'),
      URGENT: prio('URGENT'),
      SCHEDULED: prio('SCHEDULED'),
      MONITOR: prio('MONITOR'),
    },
    actually_vulnerable: matches.filter(m => m.ai_judgment.is_vulnerable).length,
  };
}

/**
 * Windows CVE 진단 실행.
 * @param {string} dbPath - SecuMS Windows DB 경로
 * @param {object} environment - { hostname }
 * @returns Linux scanner.runCveScan 과 동일 형태의 결과
 */
async function runWindowsCveScan(dbPath, environment) {
  const db = await openSqliteDb(dbPath);
  try {
    const inv = extractWindowsInventory(db);

    const env = {
      hostname: inv.hostname || (environment && environment.hostname) || 'unknown',
      os_distro: osProductLabel(inv),
      os_version: inv.ubr != null ? `${inv.build}.${inv.ubr}` : inv.build,
      hotfix_count: inv.hotfixes.length,
      ...environment,
    };

    let matches = matchAll(inv);
    matches = matches.map(m => ({ ...m, ai_judgment: judge(m) }));
    matches = sortByPriority(matches);
    const summary = summarize(matches);

    return {
      platform: 'windows',
      packages_count: inv.hotfixes.length,   // 화면에서 "설치 패키지" 대신 "설치 핫픽스"로 표시
      hotfixes: inv.hotfixes,
      env,
      matches,
      summary,
    };
  } finally {
    if (db.close) db.close();
  }
}

/**
 * 배포 스크립트 XML(.xml) 기반 Windows CVE 진단.
 * SecuMS Windows DB가 없고 script 수집만 있는 경우 사용.
 */
async function runWindowsCveScanFromScript(xmlPath, environment) {
  const xmlText = fs.readFileSync(xmlPath, 'utf8');
  const inv = extractWindowsInventoryFromScriptXml(xmlText);
  // 통합 인벤토리 = 설치 프로그램(레지스트리) + JAR(자바 라이브러리) + 네이티브 OSS 라이브러리
  const jars = extractJarsFromScriptXml(xmlText);
  const nativeLibs = extractNativeLibsFromScriptXml(xmlText);
  let sbom = [];
  try { sbom = require('./sbomParser').extractSbomFromScriptXml(xmlText); } catch (_) {}
  // 통합 인벤토리 = 설치 프로그램 + JAR + 네이티브 + SBOM(정확 식별, purl 기반)
  const software = extractWindowsSoftwareFromScriptXml(xmlText).concat(jars).concat(nativeLibs).concat(sbom);
  // 1차 패턴 매칭 → 2차 백포트/도달성 인지 판정(검토필요/잠재 구분)
  let softwareMatches = matchWindowsSoftware(software);
  try { softwareMatches = require('./judge').judgeSoftwareAll(softwareMatches); } catch (_) {}
  let kevProducts = [];
  try { kevProducts = require('./kevCrosscheck').crossCheck(software); } catch (_) {}

  const env = {
    hostname: inv.hostname || (environment && environment.hostname) || 'unknown',
    os_distro: osProductLabel(inv),
    os_version: inv.build || '-',
    hotfix_count: inv.hotfixes.length,
    software_count: software.length,
    ...environment,
  };

  let matches = matchAll(inv);
  matches = matches.map(m => ({ ...m, ai_judgment: judge(m) }));
  matches = sortByPriority(matches);
  const summary = summarize(matches);

  return {
    platform: 'windows',
    source: 'script',
    incomplete: inv.incomplete,
    notice: inv.incomplete
      ? '핫픽스(KB) 목록이 수집되지 않았습니다(보통 -Fast 모드). 수집을 -Full 로 실행하면 패치 기반 CVE 판정이 자동으로 수행됩니다.'
      : null,
    packages_count: inv.hotfixes.length,
    hotfixes: inv.hotfixes,
    software,                 // 설치 소프트웨어 인벤토리 (서드파티 SW — 레지스트리 Uninstall)
    software_matches: softwareMatches,  // 설치 SW vs 소프트웨어 CVE DB 매칭 (버전 검증)
    kev_products: kevProducts,          // 설치 SW vs CISA KEV 제품 (활성 익스플로잇 자문)
    env,
    matches,
    summary,
  };
}

module.exports = {
  runWindowsCveScan,
  runWindowsCveScanFromScript,
  extractWindowsInventory,
  extractWindowsInventoryFromScriptXml,
  extractWindowsSoftwareFromScriptXml,
  extractJarsFromScriptXml,
  extractNativeLibsFromScriptXml,
  parseJarFilename,
  matchWindowsSoftware,
  loadSoftwareCveDb,
  matchAll,
  loadWinCveDb,
  invalidateWinCveCache,
};

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
 * 스크립트 XML에서 "$ rpm -qa -i" 명령 출력 구간만 잘라낸다.
 * 다음 명령 마커($), 원시출력 종료, 블록 종료, CDATA 종료에서 멈춘다.
 */
function sliceRpmInfoSection(xmlText) {
  const start = xmlText.indexOf('$ rpm -qa -i');
  if (start < 0) return '';
  let rest = xmlText.slice(start + '$ rpm -qa -i'.length);
  let end = rest.length;
  for (const e of ['\nRAW_COMMAND_OUTPUT_END', '\nAI_EVIDENCE_BLOCK_END', '\n$ ', ']]>']) {
    const i = rest.indexOf(e);
    if (i >= 0 && i < end) end = i;
  }
  return rest.slice(0, end);
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
  const section = sliceRpmInfoSection(xmlText);
  const packages = section ? extractPackagesFromRpmInfoText(section) : [];

  if (packages.length === 0) {
    return {
      error: '스크립트 XML에 rpm 패키지 인벤토리(rpm -qa -i)가 없습니다. -Full(FSI_ENABLE_PATCHINFO=1)로 재수집하거나 SecuMS rpm 수집이 필요합니다.',
      packages_count: 0,
      matches: [],
      summary: { total: 0 },
    };
  }

  const osVerMatch = xmlText.match(/CentOS Linux release ([\d.]+)/i) || xmlText.match(/VERSION_ID="?([\d.]+)/i);
  const env = {
    hostname: (environment && environment.hostname) || '-',
    os_distro: 'CentOS',
    os_version: osVerMatch ? osVerMatch[1] : '-',
    ...environment,
  };

  const matches = matcher.matchAll(packages);
  const judged = await judge.judgeAll(matches, env, null /* mock */);
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

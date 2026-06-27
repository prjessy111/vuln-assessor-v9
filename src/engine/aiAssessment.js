'use strict';
/**
 * 진단 실행 모듈 (AI/LLM × SecuMS/Script 매트릭스).
 *
 * 2026-05-26 변경 (v3):
 *   - source 옵션 추가: 'secums' (기본) | 'script' | 'both'
 *   - script 소스: scriptResult 어댑터로 script*.xml 파싱
 *   - both: 두 소스 모두 진단, 결과 분리해서 저장 (assessment 1건에 두 results)
 *   - record.source_type 필드로 구분
 *
 * 시그니처 호환:
 *   기존 executeAiDiagnosis(server, opts) — opts 에 source 안 주면 'secums' (기존 동작)
 *
 * 옵션:
 *   - source         : 'secums' | 'script' | 'both' (기본 'secums')
 *   - rawPath        : SecuMS raw DB 절대 경로
 *   - scriptPath     : script XML 절대 경로 (source='script' 또는 'both' 시 사용)
 *   - raw_file       : UPLOAD_DIR 내 파일명 (SecuMS DB)
 *   - script_file    : UPLOAD_DIR 내 파일명 (script XML)
 *   - filter, baseAssessmentId : LLM 진단 시 항목 좁히기 (기존)
 */

const fs = require('fs');
const path = require('path');

const kvStorage = require('../storage');

const ROOT = path.resolve(__dirname, '../..');
const MOCK_DIR   = path.join(ROOT, 'data/mock');
const UPLOAD_DIR = path.join(ROOT, 'data/uploads');

// ─────────────────────────────────────────────────────────────────
// 유틸
// ─────────────────────────────────────────────────────────────────

async function openSqliteDb(dbPath) {
  const initSqlJs = require('sql.js');
  const SQL = await initSqlJs();
  const sqlDb = new SQL.Database(fs.readFileSync(dbPath));
  return {
    prepare(sql) {
      return {
        all(...args) {
          if (args.length === 0) {
            const r = sqlDb.exec(sql);
            if (!r.length) return [];
            const { columns, values } = r[0];
            return values.map(row => Object.fromEntries(columns.map((c, i) => [c, row[i]])));
          }
          const stmt = sqlDb.prepare(sql);
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
    close() { sqlDb.close(); },
  };
}

// 진단 파일 탐색 디렉토리를 명시적으로 지정하는 옵션.
// 지정되면 data/uploads 전체(날짜 폴더 + 루트)를 stat 스캔하지 않고 해당 폴더만 본다 → 부하 감소.
//   - script: opts.scriptDir  > env SCRIPT_XML_DIR
//   - secums: opts.rawDir     > env RAW_DB_DIR
function _pinnedScriptDir(opts = {}) {
  return opts.scriptDir || process.env.SCRIPT_XML_DIR || null;
}
function _pinnedRawDir(opts = {}) {
  return opts.rawDir || process.env.RAW_DB_DIR || null;
}

function resolveSecumsDbPath(server, opts = {}) {
  if (opts.rawPath && fs.existsSync(opts.rawPath)) return opts.rawPath;
  const pinnedDir = _pinnedRawDir(opts);
  if (opts.raw_file) {
    if (pinnedDir) {
      const pp = path.join(pinnedDir, opts.raw_file);
      if (fs.existsSync(pp)) return pp;
    }
    const p1 = path.join(UPLOAD_DIR, opts.raw_file);
    if (fs.existsSync(p1)) return p1;
    const dated = _findInDatedFolders(opts.raw_file);
    if (dated) return dated;
  }
  const mockRaw = path.join(MOCK_DIR, 'raw', `${server.server_id}.db`);
  if (fs.existsSync(mockRaw)) return mockRaw;
  const fallback = path.join(ROOT, 'data/uploads/exportData-SSUnix.db');
  if (fs.existsSync(fallback)) return fallback;
  return null;
}

function resolveScriptXmlPath(server, opts = {}) {
  if (opts.scriptPath && fs.existsSync(opts.scriptPath)) return opts.scriptPath;
  const pinnedDir = _pinnedScriptDir(opts);
  if (opts.script_file) {
    if (pinnedDir) {
      const pp = path.join(pinnedDir, opts.script_file);
      if (fs.existsSync(pp)) return pp;
    }
    const p1 = path.join(UPLOAD_DIR, opts.script_file);
    if (fs.existsSync(p1)) return p1;
    const dated = _findInDatedFolders(opts.script_file);
    if (dated) return dated;
  }
  if (server.hostname) {
    // 디렉토리가 지정되면 그 폴더만, 아니면 기존 전체 스캔.
    const found = _findLatestScriptXml(server.hostname, pinnedDir);
    if (found) return found;
  }
  return null;
}

function _findInDatedFolders(filename) {
  if (!fs.existsSync(UPLOAD_DIR)) return null;
  const dirs = fs.readdirSync(UPLOAD_DIR)
    .filter(d => /^\d{4}-\d{2}-\d{2}$/.test(d))
    .sort()
    .reverse();
  for (const d of dirs) {
    const p = path.join(UPLOAD_DIR, d, filename);
    if (fs.existsSync(p)) return p;
  }
  return null;
}

// hostname 에 맞는 최신 script XML 탐색.
// pinnedDir 가 주어지면 그 디렉토리 한 곳만 얕게 스캔하고 전체(날짜 폴더+루트) 스캔을 생략한다.
function _findLatestScriptXml(hostname, pinnedDir = null) {
  const candidates = [];
  const host = String(hostname || '').toLowerCase();
  const isCandidate = (filename) => {
    const lower = filename.toLowerCase();
    if (!lower.endsWith('.xml') || !lower.includes(host)) return false;
    return lower.includes('script') || /[-_]s[-_]\d{8}/.test(lower);
  };
  // 파일 1건당 statSync 1회만 — 후보 파일만 stat 한다.
  const scanDir = (dir) => {
    let entries;
    try { entries = fs.readdirSync(dir); } catch (_) { return; }
    for (const f of entries) {
      if (!isCandidate(f)) continue;
      const fp = path.join(dir, f);
      try {
        const st = fs.statSync(fp);
        if (st.isFile()) candidates.push({ path: fp, mtime: st.mtimeMs });
      } catch (_) { /* 삭제/권한 — 무시 */ }
    }
  };

  if (pinnedDir) {
    // 지정 폴더만 — 전체 스캔 안 함.
    scanDir(pinnedDir);
  } else {
    if (!fs.existsSync(UPLOAD_DIR)) return null;
    let top;
    try { top = fs.readdirSync(UPLOAD_DIR); } catch (_) { return null; }
    for (const d of top) {
      if (!/^\d{4}-\d{2}-\d{2}$/.test(d)) continue;
      const dir = path.join(UPLOAD_DIR, d);
      try { if (!fs.statSync(dir).isDirectory()) continue; } catch (_) { continue; }
      scanDir(dir);
    }
    scanDir(UPLOAD_DIR);  // 루트 직속 파일
  }

  if (!candidates.length) return null;
  candidates.sort((a, b) => b.mtime - a.mtime);
  return candidates[0].path;
}

function normalizeChkId(value) {
  const raw = String(value || '').trim().toUpperCase();
  const m = raw.match(/^SRV-?(\d{1,3})$/);
  if (m) return `SRV-${m[1].padStart(3, '0')}`;
  return raw;
}

// ─────────────────────────────────────────────────────────────────
// 필터링 (LLM 시간 절약)
// ─────────────────────────────────────────────────────────────────

function filterItemsForLlm(items, filter, baseAssessmentId) {
  if (!filter || filter === 'all') return items;
  if (filter && typeof filter === 'object' && Array.isArray(filter.chk_ids)) {
    const set = new Set(filter.chk_ids.map(normalizeChkId));
    return items.filter(it => set.has(normalizeChkId(it.chk_id)));
  }
  if (filter === 'vuln_only' || filter === 'review_needed' || filter === 'non_safe') {
    if (!baseAssessmentId) return items;
    const diagnoses = kvStorage.loadSync('diagnoses') || [];
    const base = diagnoses.find(d => d.assessment_id === baseAssessmentId);
    if (!base || !Array.isArray(base.results)) return items;
    const targetVerdicts = filter === 'vuln_only'
      ? new Set(['취약'])
      : filter === 'review_needed'
        ? new Set(['취약', '판정불가'])
        : new Set(['취약', '판정불가', '정보제공', '정보']);
    const targetChkIds = new Set(
      base.results
        .filter(r => targetVerdicts.has(r.ai_verdict || r.verdict))
        .map(r => normalizeChkId(r.chk_id))
    );
    return items.filter(it => targetChkIds.has(normalizeChkId(it.chk_id)));
  }
  return items;
}

// ─────────────────────────────────────────────────────────────────
// 소스별 항목 추출
// ─────────────────────────────────────────────────────────────────

async function _extractFromSecums(server, opts) {
  const dbPath = resolveSecumsDbPath(server, opts);
  if (!dbPath) {
    return { items: [], error: `SecuMS raw DB 없음 (server_id=${server.server_id})` };
  }
  const db = await openSqliteDb(dbPath);
  try {
    const adapter = require('./adapters/secumsUnix');
    const items = adapter.extractDiagnoseItems(db);
    return { items, sourcePath: dbPath };
  } finally {
    if (db && db.close) try { db.close(); } catch (_) {}
  }
}

function _extractFromScript(server, opts) {
  const xmlPath = resolveScriptXmlPath(server, opts);
  if (!xmlPath) {
    return { items: [], error: `Script XML 없음 (hostname=${server.hostname})` };
  }
  const adapter = require('./adapters/scriptResult');
  const { asset, items } = adapter.extractDiagnoseItems(xmlPath);
  return { items, sourcePath: xmlPath, asset };
}

// ─────────────────────────────────────────────────────────────────
// 코어 진단 실행기
// ─────────────────────────────────────────────────────────────────

async function executeDiagnosis(engine, source, server, opts = {}) {
  if (!server) return { status: 'failed', error: 'server is null' };
  if (engine !== 'ai' && engine !== 'llm') {
    return { status: 'failed', error: `unknown engine: ${engine}` };
  }
  if (!['secums', 'script', 'both'].includes(source)) {
    return { status: 'failed', error: `unknown source: ${source}` };
  }

  try {
    const aiDiagnose = require('./aiDiagnose');
    const { createClient } = require('./llm/client');

    // 복제: ai_llm 흐름에서 1차(ai=mock)가 공유 객체를 mutate해 2차 LLM provider를 덮어쓰는 버그 방지
    const clientOverride = { ...(opts.clientOverride || {}) };
    if (engine === 'ai') {
      clientOverride.provider = 'mock';
      clientOverride.timeoutMs = clientOverride.timeoutMs || parseInt(process.env.AI_TIMEOUT_MS || '10000', 10);
    } else {
      clientOverride.provider = clientOverride.provider || process.env.LLM_PROVIDER || 'ollama';
      if (clientOverride.provider === 'anthropic') {
        // Claude API — 사내 qwen 과 분리된 별도 설정
        if (!clientOverride.model)    clientOverride.model    = process.env.CLAUDE_MODEL || 'claude-sonnet-4-6';
        if (!clientOverride.endpoint) clientOverride.endpoint = process.env.CLAUDE_ENDPOINT || 'https://api.anthropic.com';
        if (!clientOverride.apiKey)   clientOverride.apiKey   = process.env.CLAUDE_API_KEY || process.env.ANTHROPIC_API_KEY;
      } else {
        // 사내 LLM (qwen, openai 호환)
        if (!clientOverride.model)    clientOverride.model    = process.env.LLM_MODEL;
        if (!clientOverride.endpoint) clientOverride.endpoint = process.env.LLM_ENDPOINT;
        if (!clientOverride.apiKey)   clientOverride.apiKey   = process.env.LLM_API_KEY;
      }
      clientOverride.timeoutMs = clientOverride.timeoutMs || parseInt(process.env.LLM_TIMEOUT_MS || '180000', 10);
      clientOverride.maxTokens = clientOverride.maxTokens || parseInt(process.env.LLM_MAX_TOKENS || '1400', 10);
      if (['openai', 'anthropic'].includes(clientOverride.provider) && !clientOverride.apiKey) {
        return { status: 'failed', error: `LLM 진단: ${clientOverride.provider} provider는 API 키가 필요합니다 (anthropic=CLAUDE_API_KEY, openai=LLM_API_KEY)` };
      }
    }
    const llmClient = createClient(clientOverride);

    const extracted = { secums: null, script: null };
    if (source === 'secums' || source === 'both') {
      extracted.secums = await _extractFromSecums(server, opts);
      if (!extracted.secums.items.length && source === 'secums') {
        return { status: 'failed', error: extracted.secums.error || 'SecuMS 항목 0개' };
      }
    }
    if (source === 'script' || source === 'both') {
      extracted.script = _extractFromScript(server, opts);
      if (!extracted.script.items.length && source === 'script') {
        return { status: 'failed', error: extracted.script.error || 'Script 항목 0개' };
      }
    }

    if (source === 'both' && !extracted.secums?.items?.length && !extracted.script?.items?.length) {
      return {
        status: 'failed',
        error: 'SecuMS, Script 항목 모두 0개',
        secums_error: extracted.secums?.error,
        script_error: extracted.script?.error,
      };
    }

    const t0 = Date.now();
    const defaultConcurrency = engine === 'ai'
      ? parseInt(process.env.AI_CONCURRENCY  || '8', 10)
      : parseInt(process.env.LLM_CONCURRENCY || '1', 10);
    const concurrency = opts.concurrency || defaultConcurrency;

    const sourceResults = { secums: null, script: null };

    if (extracted.secums?.items?.length) {
      let items = extracted.secums.items;
      if (engine === 'llm' && opts.filter && opts.filter !== 'all') {
        items = filterItemsForLlm(items, opts.filter, opts.baseAssessmentId);
      }
      if (items.length) {
        sourceResults.secums = await aiDiagnose.diagnoseAll(items, llmClient, { concurrency, engine });
      }
    }

    if (extracted.script?.items?.length) {
      let items = extracted.script.items;
      if (engine === 'llm' && opts.filter && opts.filter !== 'all') {
        items = filterItemsForLlm(items, opts.filter, opts.baseAssessmentId);
      }
      if (items.length) {
        sourceResults.script = await aiDiagnose.diagnoseAll(items, llmClient, { concurrency, engine });
      }
    }

    const elapsed = Date.now() - t0;

    const combinedResults = [];
    const subResults = {};
    if (sourceResults.secums) {
      sourceResults.secums.results.forEach(r => { r._source = 'secums'; });
      combinedResults.push(...sourceResults.secums.results);
      subResults.secums = sourceResults.secums.summary;
    }
    if (sourceResults.script) {
      sourceResults.script.results.forEach(r => { r._source = 'script'; });
      combinedResults.push(...sourceResults.script.results);
      subResults.script = sourceResults.script.summary;
    }

    const diagnoses = kvStorage.loadSync('diagnoses') || [];

    let finalResults = combinedResults;
    let summary = _mergeSummaries(sourceResults.secums?.summary, sourceResults.script?.summary);

    // LLM 2차(상세) 진단은 1차 AI 결과 중 일부(review_needed 등)만 재검토한다.
    // 재검토 안 한 1차 항목을 그대로 이어붙여 최종 레코드가 "전체 항목"을 담도록 병합한다.
    // (이렇게 안 하면 최종 결과에 재검토 대상 몇 건만 보이고 나머지가 사라져 보인다.)
    if (engine === 'llm' && opts.baseAssessmentId && opts.filter && opts.filter !== 'all') {
      const base = diagnoses.find(d => d.assessment_id == opts.baseAssessmentId);
      if (base && Array.isArray(base.results) && base.results.length) {
        const keyOf = (r) => `${normalizeChkId(r.chk_id)}|${r._source || ''}`;
        const reviewed = new Map(combinedResults.map(r => [keyOf(r), r]));
        const merged = base.results.map(br => {
          const hit = reviewed.get(keyOf(br));
          if (hit) { reviewed.delete(keyOf(br)); return { ...hit, _llm_reviewed: true }; }
          return { ...br, _llm_reviewed: false };
        });
        // base 에 없던 재검토 결과(이론상 없음)는 뒤에 붙인다.
        for (const leftover of reviewed.values()) merged.push({ ...leftover, _llm_reviewed: true });
        finalResults = merged;
        summary = _summarizeResults(finalResults, summary.diagnosis_mode);
      }
    }

    const assessment_id = (diagnoses[0]?.assessment_id || 2000) + 1;
    const record = {
      assessment_id,
      diagnose_type: engine,
      source_type: source,
      server_id: server.server_id,
      server_name: server.name,
      hostname: server.hostname,
      asset_no: server.asset_no,
      llm_provider: llmClient.config.provider,
      llm_model: llmClient.config.model,
      executed_at: new Date().toLocaleString('sv-SE'), // 로컬(KST) "YYYY-MM-DD HH:MM:SS" — toISOString은 UTC라 9시간 밀림(버그)

      elapsed_ms: elapsed,
      status: 'success',
      total_count: summary.total,
      vuln_count: summary.vuln,
      safe_count: summary.safe,
      safe_absence_count: summary.safe_absence,
      safe_value_count: summary.safe_value,
      na_count: summary.na,
      info_count: summary.info,
      agreement_rate: summary.agreement_rate,
      validation_failure_rate: summary.validation_failure_rate,
      comparison_count: summary.comparison_count,
      agree_count: summary.agree,
      disagree_count: summary.disagree,
      disagree_real_count: summary.disagree_real,
      needs_review_count: summary.needs_review,
      secums_wait_count: summary.secums_wait,
      judgment_basis: 'raw_evidence_only',
      executed_by: opts.executed_by || 'system',
      triggered_by: opts.triggered_by || 'manual',
      sub_summaries: subResults,
      secums_file: extracted.secums?.sourcePath ? path.basename(extracted.secums.sourcePath) : undefined,
      script_file: extracted.script?.sourcePath ? path.basename(extracted.script.sourcePath) : undefined,
      filter: engine === 'llm' ? (opts.filter || 'all') : undefined,
      base_assessment_id: engine === 'llm' ? (opts.baseAssessmentId || null) : undefined,
      results: finalResults,
    };
    diagnoses.unshift(record);
    kvStorage.saveSync('diagnoses', diagnoses);

    const engineLabel = engine === 'ai' ? 'AI(mock)' : `LLM(${llmClient.config.provider})`;
    const sourceLabel = source === 'both' ? 'SecuMS+Script' : (source === 'secums' ? 'SecuMS' : 'Script');
    return {
      status: 'success',
      assessment_id,
      diagnose_type: engine,
      source_type: source,
      summary,
      sub_summaries: subResults,
      judgment_basis: 'raw_evidence_only',
      elapsed_ms: elapsed,
      message: `${engineLabel}/${sourceLabel} 진단 완료 — ${summary.total}항목, 취약 ${summary.vuln} / 양호 ${summary.safe}`,
    };
  } catch (e) {
    return {
      status: 'failed',
      error: e.message,
      stack: process.env.NODE_ENV === 'production' ? undefined : e.stack,
    };
  }
}

// 병합된 전체 결과 배열에 대해 요약 통계 재계산 (aiDiagnose.diagnoseAll 의 집계와 동일 기준).
function _summarizeResults(results, diagnosisMode) {
  const isInfo = (v) => v === '정보제공' || v === '정보';
  const s = {
    total: results.length,
    diagnosis_mode: diagnosisMode || null,
    vuln: results.filter(r => r.ai_verdict === '취약').length,
    safe: results.filter(r => r.ai_verdict === '양호').length,
    safe_absence: results.filter(r => r.ai_verdict === '양호' && r.ai_safe_type === '부재양호').length,
    safe_value: results.filter(r => r.ai_verdict === '양호' && r.ai_safe_type === '값준수양호').length,
    na:   results.filter(r => r.ai_verdict === '판정불가').length,
    info: results.filter(r => isInfo(r.ai_verdict)).length,
    agree:        results.filter(r => r.agreement === 'agree').length,
    disagree_real: results.filter(r => r.agreement === 'disagree_real').length,
    needs_review:  results.filter(r => r.agreement === 'needs_review').length,
    secums_wait:  results.filter(r => r.agreement === 'secums_wait').length,
  };
  s.disagree = s.disagree_real;
  s.comparison_count = s.agree + s.disagree_real;
  s.agreement_rate = s.comparison_count ? Math.round(s.agree / s.comparison_count * 100) : 0;
  s.validation_failure_rate = s.comparison_count ? Math.round(s.disagree_real / s.comparison_count * 100) : 0;
  return s;
}

function _mergeSummaries(a, b) {
  const empty = {
    total: 0, vuln: 0, safe: 0, safe_absence: 0, safe_value: 0, na: 0, info: 0,
    agree: 0, disagree: 0, disagree_real: 0, needs_review: 0, secums_wait: 0,
  };
  const x = a || empty;
  const y = b || empty;
  const agree = (x.agree || 0) + (y.agree || 0);
  const disagreeReal = (x.disagree_real ?? x.disagree ?? 0) + (y.disagree_real ?? y.disagree ?? 0);
  const needsReview = (x.needs_review || 0) + (y.needs_review || 0);
  const comparisonCount = agree + disagreeReal;
  return {
    total: x.total + y.total,
    diagnosis_mode: x.diagnosis_mode || y.diagnosis_mode || null,
    vuln: x.vuln + y.vuln,
    safe: x.safe + y.safe,
    safe_absence: (x.safe_absence || 0) + (y.safe_absence || 0),
    safe_value: (x.safe_value || 0) + (y.safe_value || 0),
    na:   x.na   + y.na,
    info: x.info + y.info,
    agree,
    disagree: disagreeReal,
    disagree_real: disagreeReal,
    needs_review: needsReview,
    secums_wait: (x.secums_wait || 0) + (y.secums_wait || 0),
    comparison_count: comparisonCount,
    agreement_rate: comparisonCount ? Math.round(agree / comparisonCount * 100) : 0,
    validation_failure_rate: comparisonCount ? Math.round(disagreeReal / comparisonCount * 100) : 0,
  };
}

// ─────────────────────────────────────────────────────────────────
// 공개 API
// ─────────────────────────────────────────────────────────────────

async function executeAiDiagnosis(server, opts = {}) {
  return executeDiagnosis('ai', opts.source || 'secums', server, opts);
}

async function executeLlmDiagnosis(server, opts = {}) {
  return executeDiagnosis('llm', opts.source || 'secums', server, opts);
}

module.exports = {
  executeAiDiagnosis,
  executeLlmDiagnosis,
  executeDiagnosis,
  openSqliteDb,
  resolveSecumsDbPath,
  resolveScriptXmlPath,
  filterItemsForLlm,
  ROOT, MOCK_DIR, UPLOAD_DIR,
};

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

function resolveSecumsDbPath(server, opts = {}) {
  if (opts.rawPath && fs.existsSync(opts.rawPath)) return opts.rawPath;
  if (opts.raw_file) {
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
  if (opts.script_file) {
    const p1 = path.join(UPLOAD_DIR, opts.script_file);
    if (fs.existsSync(p1)) return p1;
    const dated = _findInDatedFolders(opts.script_file);
    if (dated) return dated;
  }
  if (server.hostname) {
    const found = _findLatestScriptXml(server.hostname);
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

function _findLatestScriptXml(hostname) {
  if (!fs.existsSync(UPLOAD_DIR)) return null;
  const candidates = [];
  const isCandidate = (filename) => {
    const lower = filename.toLowerCase();
    const host = String(hostname || '').toLowerCase();
    if (!lower.endsWith('.xml') || !lower.includes(host)) return false;
    return lower.includes('script') || /[-_]s[-_]\d{8}/.test(lower);
  };
  for (const d of fs.readdirSync(UPLOAD_DIR)) {
    if (!/^\d{4}-\d{2}-\d{2}$/.test(d)) continue;
    const dir = path.join(UPLOAD_DIR, d);
    if (!fs.statSync(dir).isDirectory()) continue;
    for (const f of fs.readdirSync(dir)) {
      if (isCandidate(f)) {
        candidates.push({ path: path.join(dir, f), mtime: fs.statSync(path.join(dir, f)).mtimeMs });
      }
    }
  }
  for (const f of fs.readdirSync(UPLOAD_DIR)) {
    const fp = path.join(UPLOAD_DIR, f);
    if (!fs.statSync(fp).isFile()) continue;
    if (isCandidate(f)) {
      candidates.push({ path: fp, mtime: fs.statSync(fp).mtimeMs });
    }
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

    const clientOverride = opts.clientOverride || {};
    if (engine === 'ai') {
      clientOverride.provider = 'mock';
      clientOverride.timeoutMs = clientOverride.timeoutMs || parseInt(process.env.AI_TIMEOUT_MS || '10000', 10);
    } else {
      clientOverride.provider = clientOverride.provider || process.env.LLM_PROVIDER || 'ollama';
      if (!clientOverride.model)    clientOverride.model    = process.env.LLM_MODEL;
      if (!clientOverride.endpoint) clientOverride.endpoint = process.env.LLM_ENDPOINT;
      if (!clientOverride.apiKey)   clientOverride.apiKey   = process.env.LLM_API_KEY;
      clientOverride.timeoutMs = clientOverride.timeoutMs || parseInt(process.env.LLM_TIMEOUT_MS || '180000', 10);
      clientOverride.maxTokens = clientOverride.maxTokens || parseInt(process.env.LLM_MAX_TOKENS || '1400', 10);
      if (['openai', 'anthropic'].includes(clientOverride.provider) && !clientOverride.apiKey) {
        return { status: 'failed', error: `LLM 진단: ${clientOverride.provider} provider는 LLM_API_KEY가 필요합니다` };
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

    const summary = _mergeSummaries(sourceResults.secums?.summary, sourceResults.script?.summary);

    const diagnoses = kvStorage.loadSync('diagnoses') || [];
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
      executed_at: new Date().toISOString().slice(0, 19).replace('T', ' '),
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
      results: combinedResults,
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

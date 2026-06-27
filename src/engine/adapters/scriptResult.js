'use strict';
/**
 * Script XML 결과 어댑터 (v2 — secumsUnix 와 동일한 item 구조).
 *
 * 핵심 수정 (v2):
 *   - item 구조를 secumsUnix.extractDiagnoseItems 와 동일하게 맞춤
 *   - 특히 `actions` 배열 (aiDiagnose.buildPrompt 가 이걸 참조)
 *   - script XML 의 <output> 을 actions[0].result_output 으로 매핑
 *
 * 입력: /opt/lsware/secums/agent/bin/script*.xml
 *
 * XML 구조:
 *   <script>
 *     <asset><hostname/><os/><uname/><whoami/><version/></asset>
 *     <results>
 *       <dump>
 *         <items><id>SRV-001</id><id>SRV-002</id></items>
 *         <output>$ cmd\n결과...</output>
 *       </dump>
 *     </results>
 *   </script>
 *
 * 추출 항목 구조 (secumsUnix 호환):
 *   {
 *     chk_id: 'SRV-001',
 *     type: 'S',                    // Script 표시
 *     status: 'COMPLETE',
 *     secums_verdict: 'WAIT',       // Script 는 자체 판정 없음 → WAIT 로 표시
 *     items: [],                    // CHECKITEM_TB 대응 (Script 에는 없음)
 *     actions: [{
 *       action_id: '1',
 *       action_type: 'script',
 *       action_desc: 'Script 점검 명령 실행 결과',
 *       action_value: '(스크립트)',
 *       result_output: '<output> 내용',
 *       result_error: null,
 *       is_executed: 'Y',
 *       error_code: null,
 *       error_message: null,
 *     }],
 *     // Script 전용 메타 (호환성 위해 보존)
 *     _source: 'script',
 *     _os: 'linux' | 'windows',
 *     _hostname: 'jessy62',
 *     _grouped_with: ['SRV-002'],
 *     _truncated: false,
 *     _empty: false,
 *   }
 */

const fs = require('fs');

const MAX_OUTPUT_BYTES_PER_ITEM = 12000;

function normalizeSrvId(value) {
  const m = String(value || '').trim().toUpperCase().match(/^SRV-?(\d{1,3})$/);
  return m ? `SRV-${m[1].padStart(3, '0')}` : null;
}

function extractSrvIds(value) {
  const raw = String(value || '').trim();
  const matches = raw.match(/SRV-?\d{1,3}/gi) || [];
  return matches.map(normalizeSrvId).filter(Boolean);
}

function extractDiagnoseItems(xmlPath) {
  if (!fs.existsSync(xmlPath)) {
    throw new Error(`script XML 파일 없음: ${xmlPath}`);
  }
  const raw = fs.readFileSync(xmlPath);
  const xmlText = _decodeXml(raw);
  const asset = _parseAsset(xmlText);
  const items = _parseDumps(xmlText, asset);
  return { asset, items };
}

function _decodeXml(buf) {
  const head = buf.slice(0, 200).toString('latin1');
  const m = head.match(/encoding\s*=\s*["']([^"']+)["']/i);
  const enc = (m && m[1] || 'utf-8').toLowerCase();
  if (enc === 'utf-8' || enc === 'utf8') return buf.toString('utf-8');
  if (enc === 'euc-kr' || enc === 'cp949' || enc === 'ms949' || enc === 'iso-8859-1') {
    try {
      const iconv = require('iconv-lite');
      return iconv.decode(buf, 'cp949');
    } catch (e) {
      throw new Error(`iconv-lite 모듈 필요. npm install iconv-lite\n원인: ${e.message}`);
    }
  }
  return buf.toString('utf-8');
}

function _parseAsset(xmlText) {
  const block = xmlText.match(/<asset>([\s\S]*?)<\/asset>/);
  if (!block) return { hostname: 'unknown', os: 'unknown' };
  const inner = block[1];
  const get = (tag) => {
    const m = inner.match(new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`));
    return m ? m[1].trim() : '';
  };
  const osRaw = get('os').toLowerCase();
  const os = osRaw.includes('windows') ? 'windows'
           : osRaw.includes('linux') || osRaw.includes('unix') ? 'linux'
           : 'unknown';
  return {
    hostname: get('hostname'),
    os,
    os_raw: get('os'),
    uname: get('uname'),
    whoami: get('whoami'),
    version: get('version'),
    data_role: get('data_role') || 'raw_data_provider',
    judgment_mode: get('judgment_mode') || 'raw_evidence_only',
    verdict_source: get('verdict_source') || 'none',
    safe_type_policy: get('safe_type_policy') || '',
    ai_note: get('ai_note') || '',
  };
}

function _parseEvidenceProfile(dump) {
  const block = dump.match(/<evidence_profile>([\s\S]*?)<\/evidence_profile>/);
  const inner = block ? block[1] : '';
  const get = (tag, fallback = '') => {
    const m = inner.match(new RegExp(`<${tag}>([\\s\\S]*?)</${tag}>`));
    return m ? m[1].trim() : fallback;
  };
  return {
    evidence_schema: get('evidence_schema', ''),
    check_ids: get('check_ids', ''),
    os_family: get('os_family', ''),
    collection_profile: get('collection_profile', ''),
    collection_status: get('collection_status', ''),
    output_format: get('output_format', ''),
    raw_begin_marker: get('raw_begin_marker', ''),
    raw_end_marker: get('raw_end_marker', ''),
    data_role: get('data_role', 'raw_command_output'),
    judgment_mode: get('judgment_mode', 'raw_evidence_only'),
    verdict_source: get('verdict_source', 'none'),
    safe_type_policy: get('safe_type_policy', ''),
    command_marker: get('command_marker', ''),
  };
}

function _extractCommandLines(output) {
  const cmdLines = [];
  for (const line of output.split('\n')) {
    const t = line.trim();
    if (t.startsWith('$ ') || t.startsWith('cmd# ')) {
      cmdLines.push(t.replace(/^(\$|cmd#)\s+/, ''));
    }
  }
  return cmdLines;
}

function _stripOutputWrapper(output) {
  let text = String(output || '');
  text = text.replace(/^\s*<!\[CDATA\[/, '');
  text = text.replace(/\]\]>\s*$/, '');
  return text;
}

function _detectCollectionSignals(output, isEmpty) {
  const signals = [];
  if (isEmpty) signals.push('no_output_collected');

  const text = output.toLowerCase();
  if (/skipped_for_speed|collection_status=skipped_for_speed/.test(text)) {
    signals.push('skipped_for_speed_signal_present');
  }
  if (/collection_status=no_data|not found \/ no data/.test(text)) {
    signals.push('no_data_signal_present');
  }
  if (/no such file|cannot access|does not exist|not found|registry key value not found|does not exist as an installed service/.test(text)) {
    signals.push('possible_absence_signal_present');
  }
  if (/permission denied|access is denied|operation not permitted|requires elevation|notadmin/.test(text)) {
    signals.push('permission_or_privilege_signal_present');
  }
  if (/collection_status=error|(^|\n)error:|timed out|timeout|command not found|is not recognized/.test(text)) {
    signals.push('execution_error_signal_present');
  }

  return signals.length ? signals : ['raw_output_present'];
}

function _deriveFastHints({ output, isEmpty, cmdLines, signals }) {
  const text = String(output || '');
  const lower = text.toLowerCase();
  const hints = [];

  if (isEmpty) hints.push('empty_output');
  if (signals.includes('possible_absence_signal_present')) hints.push('absence_signal_seen');
  if (signals.includes('no_data_signal_present')) hints.push('no_data_signal_seen');
  if (signals.includes('skipped_for_speed_signal_present')) hints.push('skipped_for_speed');
  if (signals.includes('permission_or_privilege_signal_present')) hints.push('privilege_limited_collection');
  if (signals.includes('execution_error_signal_present')) hints.push('execution_error_seen');
  if (cmdLines.length) hints.push(`command_count=${cmdLines.length}`);

  const serviceListening = /\b(listen|listening|running|service_running|state\s*:\s*4)\b/i.test(text);
  const disabledOrStopped = /\b(disabled|stopped|stop_pending|not installed|does not exist as an installed service)\b/i.test(text);
  if (serviceListening) hints.push('service_or_port_active');
  if (disabledOrStopped) hints.push('service_disabled_or_absent');

  if (/everyone|anonymous|guest|0\.0\.0\.0|\*:\d+|allow|permit/i.test(text)) {
    hints.push('exposure_keyword_seen');
  }
  if (/deny|restrict|require|enabled\s*:\s*false|screen.*secure|firewall/i.test(text)) {
    hints.push('control_keyword_seen');
  }
  if (lower.includes('not found / no data')) hints.push('collector_no_data_marker');

  return hints.length ? hints : ['raw_output_present'];
}

function _buildAiRawContext({ ids, asset, profile, cmdLines, signals, fastHints, truncated }) {
  const shownCommands = cmdLines.slice(0, 8);
  const more = cmdLines.length > shownCommands.length
    ? ` (+${cmdLines.length - shownCommands.length} more)`
    : '';

  return [
    'AI_RAW_CONTEXT',
    `evidence_schema=${profile.evidence_schema || 'legacy_script_xml'}`,
    'source=script_xml',
    `check_ids=${ids.join(',')}`,
    `host=${asset.hostname || 'unknown'}`,
    `os=${asset.os || asset.os_raw || 'unknown'}`,
    `collection_profile=${profile.collection_profile || asset.collection_profile || 'unknown'}`,
    `collection_status=${profile.collection_status || 'raw_output_present'}`,
    `output_format=${profile.output_format || 'legacy_output'}`,
    `script_data_role=${profile.data_role || asset.data_role || 'raw_command_output'}`,
    `script_verdict_source=${profile.verdict_source || asset.verdict_source || 'none'}`,
    `judgment_mode=${profile.judgment_mode || asset.judgment_mode || 'raw_evidence_only'}`,
    'judgment_policy=script_does_not_decide_verdict; AI_and_LLM_must_decide_from_raw_output_only',
    'safe_subtype_policy=if_safe_then_classify_absence_good_when_target_is_absent_or_value_compliant_good_when_existing_value_meets_criterion',
    'decision_route=AI_fast_pattern_triage_first; LLM_precise_evidence_review_second',
    'allowed_verdicts=vulnerable,safe,info,unable',
    `collection_signals=${signals.join(',')}`,
    `fast_hints=${fastHints.join(',')}`,
    `commands=${shownCommands.join(' | ')}${more}`,
    `truncated=${truncated ? 'true' : 'false'}`,
    'RAW_OUTPUT_BEGIN',
  ].join('\n');
}

function _parseDumps(xmlText, asset) {
  const dumps = xmlText.match(/<dump>[\s\S]*?<\/dump>/g) || [];
  const items = [];

  for (const dump of dumps) {
    const idMatches = dump.match(/<id>([^<]+)<\/id>/g) || [];
    const rawIds = idMatches.map(m => m.replace(/<\/?id>/g, '').trim()).filter(Boolean);
    const ids = [...new Set(rawIds.flatMap(extractSrvIds))];
    if (ids.length === 0) continue;

    const outMatch = dump.match(/<output>([\s\S]*?)<\/output>/);
    let output = outMatch ? outMatch[1] : '';
    output = _stripOutputWrapper(output);
    output = output.replace(/\r\n/g, '\n').replace(/^\s+|\s+$/g, '');

    const origSize = Buffer.byteLength(output, 'utf-8');
    let truncated = false;
    if (origSize > MAX_OUTPUT_BYTES_PER_ITEM) {
      const headSize = Math.floor(MAX_OUTPUT_BYTES_PER_ITEM * 0.7);
      const tailSize = Math.floor(MAX_OUTPUT_BYTES_PER_ITEM * 0.2);
      output = output.slice(0, headSize)
        + `\n\n... [중간 생략 — 원본 ${origSize} bytes, ${origSize - headSize - tailSize} bytes 잘림] ...\n\n`
        + output.slice(-tailSize);
      truncated = true;
    }

    const isEmpty = origSize < 10;

    // 명령어 행과 raw 프로필을 AI가 읽기 쉬운 컨텍스트로 정리한다.
    const evidenceProfile = _parseEvidenceProfile(dump);
    const cmdLines = _extractCommandLines(output);
    const signals = _detectCollectionSignals(output, isEmpty);
    const fastHints = _deriveFastHints({ output, isEmpty, cmdLines, signals });
    const aiRawContext = _buildAiRawContext({
      ids,
      asset,
      profile: evidenceProfile,
      cmdLines,
      signals,
      fastHints,
      truncated,
    });
    const outputForAi = [aiRawContext, output].filter(Boolean).join('\n');
    const descCommands = cmdLines.slice(0, 3);
    const desc = descCommands.length
      ? `Script 점검: ${descCommands.join(' / ')}`
      : (isEmpty ? 'Script 점검 (결과 없음)' : 'Script 점검 명령 실행 결과');

    for (const id of ids) {
      const grouped = ids.filter(x => x !== id);
      items.push({
        // secumsUnix 호환 필드
        chk_id: id,
        type: 'S',                                  // Script 표시
        status: isEmpty ? 'WAIT' : 'COMPLETE',
        secums_verdict: 'WAIT',                     // Script 는 자체 판정 없음
        items: [],                                  // CHECKITEM_TB 대응 (없음)
        actions: [{
          action_id: '1',
          action_type: 'script',
          action_desc: desc,
          action_value: '(스크립트 점검)',
          result_output: outputForAi,
          result_error: null,
          is_executed: 'Y',
          error_code: null,
          error_message: null,
        }],
        // Script 전용 메타 (선택적 참조용)
        _source: 'script',
        _os: asset.os,
        _hostname: asset.hostname,
        _grouped_with: grouped,
        _raw_ids: rawIds,
        _truncated: truncated,
        _empty: isEmpty,
        _output_size: origSize,
        _script_evidence_schema: evidenceProfile.evidence_schema || 'legacy_script_xml',
        _script_collection_profile: evidenceProfile.collection_profile || '',
        _script_collection_status: evidenceProfile.collection_status || '',
        _script_output_format: evidenceProfile.output_format || '',
        _script_data_role: evidenceProfile.data_role,
        _script_judgment_mode: evidenceProfile.judgment_mode,
        _script_verdict_source: evidenceProfile.verdict_source,
        _script_collection_signals: signals,
        _script_fast_hints: fastHints,
        _script_commands: cmdLines,
      });
    }
  }

  return items;
}

module.exports = {
  extractDiagnoseItems,
  MAX_OUTPUT_BYTES_PER_ITEM,
  normalizeSrvId,
};

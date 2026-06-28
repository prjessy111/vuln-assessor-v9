'use strict';
/**
 * 에이전트 전용 LLM 클라이언트 빌더.
 *
 * 백엔드 선택 (VULN_ASSESSOR_TODO.md §0, §4-4):
 *   - 'lsap'   : 사내 LLM(qwen, openai 호환). 기본값. raw 데이터 외부 전송 회피.
 *   - 'claude' : 외부 Claude API. 불일치·애매 항목 2차 재검증 등 제한적 사용.
 *   - 'mock'   : 개발/데모용 (외부 호출 없음).
 *
 * aiAssessment.js의 provider 분기 규약을 그대로 따른다.
 */

const { createClient } = require('../engine/llm/client');

/**
 * 외부(사외) LLM 전송 허용 여부.
 * 보안 기본값: 차단. raw 점검 데이터의 외부 유출을 막기 위해, Claude 등 외부 API는
 * AGENT_ALLOW_EXTERNAL=true 로 명시 허용해야만 사용된다. (VULN_ASSESSOR_TODO.md §0, §6)
 */
function isExternalAllowed() {
  return String(process.env.AGENT_ALLOW_EXTERNAL || '').toLowerCase() === 'true';
}

/**
 * 현재 환경에서 실제 호출이 가능한 백엔드인지 판별.
 * (설정 없으면 scriptGenerator/autoJudge가 폴백 경로를 택하도록)
 */
function isBackendConfigured(backend) {
  if (backend === 'mock') return true;
  if (backend === 'claude') {
    // 외부 전송이 허용된 경우에만 "사용 가능"으로 본다 (보안).
    return isExternalAllowed() && !!(process.env.CLAUDE_API_KEY || process.env.ANTHROPIC_API_KEY);
  }
  // lsap (사내)
  return !!(process.env.LLM_ENDPOINT || process.env.LLM_PROVIDER === 'ollama');
}

function resolveBackend(requested) {
  const b = requested || process.env.AGENT_BACKEND || 'lsap';
  return ['lsap', 'claude', 'mock'].includes(b) ? b : 'lsap';
}

/**
 * 백엔드에 맞는 LLM 클라이언트 생성.
 * @param {string} backend - 'lsap' | 'claude' | 'mock'
 * @param {object} override - 추가 설정 (model, timeoutMs 등)
 */
function buildClient(backend, override = {}) {
  const o = { ...override };
  if (backend === 'mock') {
    o.provider = 'mock';
  } else if (backend === 'claude') {
    // 보안 가드: 외부 전송 명시 허용 없이는 차단 (raw 데이터 외부 유출 방지)
    if (!isExternalAllowed()) {
      throw new Error('외부 LLM(Claude) 전송이 비활성화되어 있습니다 (보안 기본값). 사내 LSAP를 사용하세요. 정말 필요하면 AGENT_ALLOW_EXTERNAL=true 로 명시 허용해야 합니다.');
    }
    o.provider = 'anthropic';
    o.model = o.model || process.env.CLAUDE_MODEL || 'claude-sonnet-4-6';
    o.endpoint = o.endpoint || process.env.CLAUDE_ENDPOINT || 'https://api.anthropic.com';
    o.apiKey = o.apiKey || process.env.CLAUDE_API_KEY || process.env.ANTHROPIC_API_KEY;
    if (!o.apiKey) throw new Error('Claude 백엔드: CLAUDE_API_KEY(또는 ANTHROPIC_API_KEY) 필요');
  } else {
    // lsap (사내, openai 호환)
    o.provider = o.provider || process.env.LLM_PROVIDER || 'openai';
    o.model = o.model || process.env.LLM_MODEL || 'qwen3.5-122b-fast';
    o.endpoint = o.endpoint || process.env.LLM_ENDPOINT;
    o.apiKey = o.apiKey || process.env.LLM_API_KEY;
  }
  o.timeoutMs = o.timeoutMs || parseInt(process.env.LLM_TIMEOUT_MS || '180000', 10);
  o.maxTokens = o.maxTokens || parseInt(process.env.AGENT_MAX_TOKENS || '2000', 10);
  return createClient(o);
}

module.exports = { buildClient, resolveBackend, isBackendConfigured, isExternalAllowed };

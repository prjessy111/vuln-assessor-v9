'use strict';
/**
 * LLM 클라이언트 추상화 레이어.
 *
 * 책임:
 *  - 여러 백엔드(Ollama, Anthropic, OpenAI)를 동일 인터페이스로 사용
 *  - JSON 응답 강제 (룰 평가용)
 *  - 재시도 + 타임아웃
 *  - 토큰 사용량/지연시간 메트릭
 *
 * 인터페이스:
 *   const client = createClient(config);
 *   const result = await client.complete({
 *     system: "...",
 *     user: "...",
 *     responseFormat: "json"   // 'text' | 'json'
 *   });
 *   // result = { text, json, model, elapsedMs, retries }
 *
 * 설정 (config 객체 또는 환경변수):
 *   LLM_PROVIDER  : 'ollama' | 'anthropic' | 'openai'  (기본 ollama)
 *   LLM_MODEL     : 모델명 (예: 'gemma2:9b', 'claude-haiku-4-5', 'gpt-4o-mini')
 *   LLM_ENDPOINT  : 커스텀 엔드포인트 URL (ollama용)
 *   LLM_API_KEY   : API 키 (anthropic/openai용)
 *   LLM_TIMEOUT_MS: 요청 타임아웃 (기본 60000)
 */

const OllamaProvider = require('./providers/ollama');
const AnthropicProvider = require('./providers/anthropic');
const OpenAIProvider = require('./providers/openai');
const MockProvider = require('./providers/mock');

const PROVIDERS = {
  ollama: OllamaProvider,
  anthropic: AnthropicProvider,
  openai: OpenAIProvider,
  mock: MockProvider,
};

function loadConfig(override = {}) {
  return {
    provider: override.provider || process.env.LLM_PROVIDER || 'ollama',
    model:    override.model    || process.env.LLM_MODEL || 'gemma2:9b',
    endpoint: override.endpoint || process.env.LLM_ENDPOINT || 'http://localhost:11434',
    apiKey:   override.apiKey   || process.env.LLM_API_KEY || '',
    timeoutMs: parseInt(override.timeoutMs || process.env.LLM_TIMEOUT_MS || '60000', 10),
    maxRetries: parseInt(override.maxRetries || process.env.LLM_MAX_RETRIES || '2', 10),
    maxTokens: parseInt(override.maxTokens || process.env.LLM_MAX_TOKENS || '1400', 10),
  };
}

/**
 * 통합 LLM 클라이언트 생성.
 */
function createClient(override = {}) {
  const cfg = loadConfig(override);
  const Provider = PROVIDERS[cfg.provider];
  if (!Provider) {
    throw new Error(`알 수 없는 LLM provider: ${cfg.provider} (사용 가능: ${Object.keys(PROVIDERS).join(', ')})`);
  }
  const provider = new Provider(cfg);

  return {
    config: cfg,

    /**
     * Completion 요청.
     *
     * @param {object} args
     *   - system: 시스템 프롬프트
     *   - user: 사용자 프롬프트
     *   - responseFormat: 'text' | 'json'
     *   - temperature: 0.0 ~ 1.0 (기본 0.1, 판정은 결정적이어야 함)
     *
     * @returns {{ text, json?, model, elapsedMs, retries }}
     */
    async complete(args) {
      const t0 = Date.now();
      let lastErr;
      for (let attempt = 0; attempt <= cfg.maxRetries; attempt++) {
        try {
          const text = await _withTimeout(
            provider.complete(args),
            cfg.timeoutMs,
            `LLM 응답 타임아웃 (${cfg.timeoutMs}ms)`
          );

          const result = {
            text,
            model: cfg.model,
            elapsedMs: Date.now() - t0,
            retries: attempt,
          };

          // JSON 모드면 파싱
          if (args.responseFormat === 'json') {
            result.json = _parseJsonResponse(text);
            if (!result.json) {
              // 파싱 실패 → 재시도 (LLM이 종종 prefix/suffix를 붙임)
              throw new Error(`JSON 파싱 실패: ${text.slice(0, 200)}`);
            }
          }

          return result;
        } catch (e) {
          lastErr = e;
          if (attempt < cfg.maxRetries) {
            // 지수 백오프 (500ms, 1s, 2s, ...)
            await _sleep(500 * Math.pow(2, attempt));
          }
        }
      }
      throw new Error(`LLM 호출 실패 (${cfg.maxRetries + 1}회 시도): ${lastErr.message}`);
    },

    /**
     * 헬스체크 — 백엔드가 응답 가능한지 확인.
     */
    async ping() {
      return provider.ping();
    },
  };
}

// JSON 추출 — LLM이 ```json ... ``` 형태로 감싸거나 prefix 텍스트를 붙이는 경우 대응
function _parseJsonResponse(text) {
  if (!text) return null;
  // 1) 코드 블록 추출
  const fenced = text.match(/```(?:json)?\s*(\{[\s\S]*?\}|\[[\s\S]*?\])\s*```/);
  if (fenced) {
    try { return JSON.parse(fenced[1]); } catch (_) { /* fall through */ }
  }
  // 2) 가장 바깥 {...} 추출
  const obj = text.match(/\{[\s\S]*\}/);
  if (obj) {
    try { return JSON.parse(obj[0]); } catch (_) { /* fall through */ }
  }
  // 3) 전체가 JSON일 수도
  try { return JSON.parse(text); } catch (_) { return null; }
}

function _withTimeout(promise, ms, msg) {
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(msg)), ms);
    promise.then(v => { clearTimeout(t); resolve(v); },
                 e => { clearTimeout(t); reject(e); });
  });
}

function _sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

module.exports = { createClient, loadConfig, _parseJsonResponse };

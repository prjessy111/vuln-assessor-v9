'use strict';
/**
 * Anthropic Claude API 백엔드.
 * https://docs.claude.com/en/api/messages
 */

class AnthropicProvider {
  constructor(cfg) {
    this.cfg = cfg;
    if (!cfg.apiKey) throw new Error('Anthropic provider: LLM_API_KEY 필요');
    this.endpoint = (cfg.endpoint || 'https://api.anthropic.com').replace(/\/$/, '');
  }

  async ping() {
    // Anthropic은 별도 ping 엔드포인트 없음 — 최소 호출로 대체
    const result = await this.complete({
      system: 'You are a test.',
      user: 'Reply with one word: OK',
      responseFormat: 'text',
      temperature: 0,
    });
    return { ok: !!result, sample: result };
  }

  async complete({ system, user, responseFormat, temperature = 0.1 }) {
    const body = {
      model: this.cfg.model,  // 예: 'claude-haiku-4-5-20251001'
      max_tokens: this.cfg.maxTokens || 1400,
      temperature,
      messages: [{ role: 'user', content: user }],
    };
    if (system) body.system = system;

    // JSON 강제는 시스템 프롬프트로 처리 (Anthropic은 별도 옵션 없음)
    if (responseFormat === 'json') {
      body.system = (body.system || '') +
        '\n\nIMPORTANT: Respond with ONLY a valid JSON object. No prose, no markdown code fences.';
    }

    const res = await fetch(`${this.endpoint}/v1/messages`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': this.cfg.apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`Anthropic HTTP ${res.status}: ${errText.slice(0, 300)}`);
    }
    const data = await res.json();
    const text = (data.content || [])
      .filter(b => b.type === 'text')
      .map(b => b.text)
      .join('\n');
    if (!text) throw new Error(`Anthropic 응답 텍스트 없음: ${JSON.stringify(data).slice(0, 200)}`);
    return text;
  }
}

module.exports = AnthropicProvider;

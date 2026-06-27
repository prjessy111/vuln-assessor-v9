'use strict';
/**
 * OpenAI Chat Completions API 백엔드.
 * https://platform.openai.com/docs/api-reference/chat
 */

class OpenAIProvider {
  constructor(cfg) {
    this.cfg = cfg;
    if (!cfg.apiKey) throw new Error('OpenAI provider: LLM_API_KEY 필요');
    this.endpoint = (cfg.endpoint || 'https://api.openai.com').replace(/\/$/, '');
  }

  async ping() {
    const res = await fetch(`${this.endpoint}/v1/models`, {
      headers: { 'Authorization': `Bearer ${this.cfg.apiKey}` },
    });
    if (!res.ok) throw new Error(`OpenAI ping 실패: HTTP ${res.status}`);
    const data = await res.json();
    return { ok: true, models: (data.data || []).map(m => m.id).slice(0, 10) };
  }

  async complete({ system, user, responseFormat, temperature = 0.1 }) {
    const messages = [];
    if (system) messages.push({ role: 'system', content: system });
    messages.push({ role: 'user', content: user });

    const body = {
      model: this.cfg.model,  // 예: 'gpt-4o-mini'
      messages,
      temperature,
      max_tokens: this.cfg.maxTokens || 1400,
    };
    if (responseFormat === 'json') {
      body.response_format = { type: 'json_object' };
    }

    const res = await fetch(`${this.endpoint}/v1/chat/completions`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${this.cfg.apiKey}`,
      },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`OpenAI HTTP ${res.status}: ${errText.slice(0, 300)}`);
    }
    const data = await res.json();
    const text = data.choices && data.choices[0] && data.choices[0].message
      ? data.choices[0].message.content : '';
    if (!text) throw new Error(`OpenAI 응답 비어있음: ${JSON.stringify(data).slice(0, 200)}`);
    return text;
  }
}

module.exports = OpenAIProvider;

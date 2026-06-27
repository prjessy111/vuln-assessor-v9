'use strict';
/**
 * Ollama 로컬 LLM 백엔드.
 * https://github.com/ollama/ollama/blob/main/docs/api.md
 *
 * 기본 엔드포인트: http://localhost:11434
 * 모델 예시: 'gemma2:9b', 'llama3.1:8b', 'qwen2.5:7b'
 */

class OllamaProvider {
  constructor(cfg) {
    this.cfg = cfg;
    this.endpoint = (cfg.endpoint || 'http://localhost:11434').replace(/\/$/, '');
  }

  async ping() {
    const res = await fetch(`${this.endpoint}/api/tags`);
    if (!res.ok) throw new Error(`Ollama ping 실패: HTTP ${res.status}`);
    const data = await res.json();
    return { ok: true, models: (data.models || []).map(m => m.name) };
  }

  /**
   * Chat completion.
   *
   * @param {object} args - { system, user, responseFormat, temperature }
   * @returns {string} 응답 텍스트
   */
  async complete({ system, user, responseFormat, temperature = 0.1 }) {
    const messages = [];
    if (system) messages.push({ role: 'system', content: system });
    messages.push({ role: 'user', content: user });

    const body = {
      model: this.cfg.model,
      messages,
      stream: false,
      options: {
        temperature,
        num_predict: this.cfg.maxTokens || 1400,
      },
    };
    // Ollama는 format='json' 지정 시 JSON 강제 (모델이 지원하는 경우)
    if (responseFormat === 'json') body.format = 'json';

    const res = await fetch(`${this.endpoint}/api/chat`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`Ollama HTTP ${res.status}: ${errText.slice(0, 300)}`);
    }
    const data = await res.json();
    if (!data.message || !data.message.content) {
      throw new Error(`Ollama 응답 형식 오류: ${JSON.stringify(data).slice(0, 200)}`);
    }
    return data.message.content;
  }
}

module.exports = OllamaProvider;

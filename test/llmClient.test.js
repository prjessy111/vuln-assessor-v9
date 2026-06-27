'use strict';
process.env.LLM_PROVIDER = 'mock';

const { createClient, _parseJsonResponse } = require('../src/engine/llm/client');

describe('LLM Client (mock provider)', () => {
  test('생성 및 ping', async () => {
    const c = createClient();
    expect(c.config.provider).toBe('mock');
    const p = await c.ping();
    expect(p.ok).toBe(true);
    expect(p.mock).toBe(true);
  });

  test('text 응답', async () => {
    const c = createClient();
    const r = await c.complete({ user: 'hello' });
    expect(typeof r.text).toBe('string');
    expect(r.text.length).toBeGreaterThan(0);
    expect(r.elapsedMs).toBeGreaterThanOrEqual(0);
    expect(r.retries).toBe(0);
  });

  test('JSON 응답 파싱', async () => {
    const c = createClient();
    const r = await c.complete({
      user: 'PermitRootLogin yes',
      responseFormat: 'json',
    });
    expect(r.json).toBeTruthy();
    expect(['양호', '취약', '점검불가']).toContain(r.json.status);
    expect(r.json.reason).toBeTruthy();
  });

  test('JSON 응답 — 양호 사례 트리거', async () => {
    const c = createClient();
    const r = await c.complete({
      user: 'permission 0644',
      responseFormat: 'json',
    });
    expect(r.json.status).toBe('양호');
  });

  test('JSON 응답 — 취약 사례 트리거', async () => {
    const c = createClient();
    const r = await c.complete({
      user: 'port=21 listening',
      responseFormat: 'json',
    });
    expect(r.json.status).toBe('취약');
    expect(r.json.evidence).toContain('port=21');
  });
});

describe('JSON 응답 파서', () => {
  test('순수 JSON', () => {
    expect(_parseJsonResponse('{"a":1}')).toEqual({ a: 1 });
  });

  test('```json 블록으로 감싸진 응답', () => {
    const t = 'Here is the result:\n```json\n{"status":"양호"}\n```\nDone.';
    expect(_parseJsonResponse(t)).toEqual({ status: '양호' });
  });

  test('prefix가 있는 JSON', () => {
    const t = 'Sure! {"status":"취약","reason":"test"}';
    expect(_parseJsonResponse(t)).toEqual({ status: '취약', reason: 'test' });
  });

  test('파싱 불가능한 텍스트 → null', () => {
    expect(_parseJsonResponse('not json at all')).toBeNull();
  });
});

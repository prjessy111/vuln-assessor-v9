'use strict';
/**
 * Hermes(Nous Research) 메신저 게이트웨이 연동 — 진단 결과 "요약 보고" (Option A)
 *
 * 이 PC → VPS(SSH) → `hermes send` 실행.
 *  - Hermes의 `send`는 LLM/agent 루프 없이 게이트웨이 자격증명만 재사용해
 *    Telegram/Discord/Slack 등으로 텍스트를 보낸다.
 *  - raw 점검 데이터는 전송하지 않고 "판정 요약"만 보낸다 → 보안 방침(사내 LLM/비유출) 준수.
 *
 * 설정(.env):
 *   HERMES_SSH_HOST     VPS 주소 (필수)
 *   HERMES_SSH_PORT     기본 22
 *   HERMES_SSH_USER     기본 root
 *   HERMES_SSH_PASSWORD 또는 HERMES_SSH_KEY (둘 중 하나 필수)
 *   HERMES_BIN          기본 '/usr/local/lib/hermes-agent/venv/bin/python -m hermes_cli.main'
 *   HERMES_SEND_TARGET  기본 'telegram' (예: telegram:-100123..., discord:#ops, slack:C0123)
 */

const sshClient = require('../engine/sshClient');

function cfg() {
  return {
    host: process.env.HERMES_SSH_HOST || '',
    port: parseInt(process.env.HERMES_SSH_PORT || '22', 10),
    username: process.env.HERMES_SSH_USER || 'root',
    password: process.env.HERMES_SSH_PASSWORD || null,
    privateKeyPath: process.env.HERMES_SSH_KEY || null,
    bin: process.env.HERMES_BIN || '/usr/local/lib/hermes-agent/venv/bin/python -m hermes_cli.main',
    target: process.env.HERMES_SEND_TARGET || 'telegram',
  };
}

function isConfigured() {
  const c = cfg();
  return !!(c.host && (c.password || c.privateKeyPath));
}

/**
 * 메시지를 Hermes 게이트웨이로 전송.
 * @param {string} message
 * @param {object} opts - { target, subject }
 * @returns {Promise<{ok, output, target}>}
 */
async function send(message, opts = {}) {
  const c = cfg();
  if (!c.host) throw new Error('Hermes 미설정: HERMES_SSH_HOST 가 필요합니다 (.env)');
  if (!c.password && !c.privateKeyPath) throw new Error('Hermes 미설정: HERMES_SSH_PASSWORD 또는 HERMES_SSH_KEY 필요');
  const target = opts.target || c.target;

  // 메시지를 base64→stdin(-f -)으로 전달: 따옴표/줄바꿈/한글 안전
  const b64 = Buffer.from(String(message), 'utf8').toString('base64');
  const subj = opts.subject ? ` --subject ${JSON.stringify(opts.subject)}` : '';
  const cmd = `printf '%s' '${b64}' | base64 -d | ${c.bin} send --to ${target}${subj} -f - --quiet`;

  return sshClient.withConnection(
    {
      host: c.host, port: c.port, username: c.username,
      password: c.password, privateKeyPath: c.privateKeyPath, readyTimeout: 15000,
    },
    async (conn) => {
      const r = await sshClient.exec(conn, cmd, { timeout: 30000 });
      if (r.code !== 0) {
        throw new Error(`hermes send 실패(code=${r.code}): ${(r.stderr || r.stdout || '').slice(0, 300)}`);
      }
      return { ok: true, output: (r.stdout || '').trim(), target };
    }
  );
}

/**
 * 진단 항목 → 보고용 요약 텍스트 (raw 미포함).
 */
function formatItem(item) {
  const j = item.judgment || {};
  const verdict = (item.review && item.review.verdict) || j.verdict || '미판정';
  return [
    `🛡️ [Vuln Assessor] ${item.title}`,
    `판정: ${verdict}` + (j.confidence != null ? ` (신뢰도 ${Number(j.confidence).toFixed(2)})` : ''),
    item.agreement ? `3소스 합의: ${item.agreement.status}` : null,
    j.reason ? `사유: ${j.reason}` : null,
    j.recommend ? `조치: ${j.recommend}` : null,
    `대상: ${item.os_target} · 출처: ${item.source}${item.source_ref ? '/' + item.source_ref : ''}`,
  ].filter(Boolean).join('\n');
}

module.exports = { send, formatItem, isConfigured, cfg };

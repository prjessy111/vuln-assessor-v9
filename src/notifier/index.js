'use strict';
/**
 * 알림 발송 모듈.
 *
 * 어댑터: console (기본) / email (SMTP) / slack (Webhook)
 * 동시에 여러 채널로 발송 가능 (예: console + slack).
 *
 * 환경 변수:
 *   NOTIFIER_CHANNELS=console,slack    // 쉼표로 채널 나열
 *   SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASSWORD, SMTP_FROM   // email용
 *   SLACK_WEBHOOK_URL                  // slack용
 *
 * 외부 의존성:
 *   - nodemailer (선택): 미설치면 email 채널 자동 비활성
 *   - slack은 Node 내장 https 모듈만 사용
 *
 * 호출:
 *   const notifier = require('./src/notifier');
 *   notifier.configure({ channels: ['console','slack'] });
 *   await notifier.notify({
 *     event: 'schedule_run_finished',
 *     severity: 'error',  // info / warning / error
 *     title: '예약 진단 실패',
 *     body: '야간 전체 점검에서 2대 실패',
 *     details: { schedule_id, run_id, ... }
 *   });
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const { URL } = require('url');

const state = {
  channels: ['console'],
  config: {
    smtp: {
      host: process.env.SMTP_HOST || '',
      port: parseInt(process.env.SMTP_PORT || '25', 10),
      user: process.env.SMTP_USER || '',
      password: process.env.SMTP_PASSWORD || '',
      from: process.env.SMTP_FROM || 'vuln-assessor@lsware.local',
      to: process.env.SMTP_TO || '',  // 콤마 구분
    },
    slack: {
      webhookUrl: process.env.SLACK_WEBHOOK_URL || '',
    },
  },
  storage: null,  // 발송 이력 적재용 (선택)
  log: console,
};

const SEVERITY_EMOJI = { info: 'ℹ️', warning: '⚠️', error: '🚨', success: '✅' };
const SEVERITY_COLOR = { info: '#2c5fb8', warning: '#e67e22', error: '#c0392b', success: '#27ae60' };

// ───── console 어댑터 ─────────────────────────────────

function sendConsole(msg) {
  const tag = SEVERITY_EMOJI[msg.severity] || 'ℹ️';
  state.log.log(`[notify] ${tag} ${msg.title}`);
  if (msg.body) state.log.log(`         ${msg.body}`);
  return { channel: 'console', ok: true };
}

// ───── slack 어댑터 ───────────────────────────────────

function sendSlack(msg) {
  return new Promise((resolve) => {
    const url = state.config.slack.webhookUrl;
    if (!url) {
      resolve({ channel: 'slack', ok: false, error: 'SLACK_WEBHOOK_URL 미설정' });
      return;
    }

    let parsed;
    try { parsed = new URL(url); }
    catch (e) {
      resolve({ channel: 'slack', ok: false, error: 'URL 형식 오류' });
      return;
    }

    const payload = JSON.stringify({
      attachments: [{
        color: SEVERITY_COLOR[msg.severity] || '#888',
        title: `${SEVERITY_EMOJI[msg.severity] || ''} ${msg.title}`,
        text: msg.body || '',
        fields: msg.details ? Object.entries(msg.details).slice(0, 8).map(([k, v]) => ({
          title: k,
          value: typeof v === 'object' ? JSON.stringify(v).slice(0, 200) : String(v).slice(0, 200),
          short: true,
        })) : undefined,
        footer: 'Vuln Assessor',
        ts: Math.floor(Date.now() / 1000),
      }],
    });

    const lib = parsed.protocol === 'https:' ? https : http;
    const req = lib.request({
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
      },
      timeout: 10000,
    }, (res) => {
      let body = '';
      res.on('data', d => { body += d; });
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve({ channel: 'slack', ok: true });
        } else {
          resolve({ channel: 'slack', ok: false, error: `HTTP ${res.statusCode}: ${body.slice(0, 200)}` });
        }
      });
    });
    req.on('error', e => resolve({ channel: 'slack', ok: false, error: e.message }));
    req.on('timeout', () => { req.destroy(); resolve({ channel: 'slack', ok: false, error: 'timeout' }); });
    req.write(payload);
    req.end();
  });
}

// ───── email 어댑터 (nodemailer가 있을 때만) ────────────

let _mailer = null;
let _mailerTried = false;

function getMailer() {
  if (_mailerTried) return _mailer;
  _mailerTried = true;
  try {
    const nodemailer = require('nodemailer');
    const { host, port, user, password } = state.config.smtp;
    if (!host) return null;
    _mailer = nodemailer.createTransport({
      host, port,
      secure: port === 465,
      auth: user ? { user, pass: password } : undefined,
    });
    return _mailer;
  } catch (e) {
    return null;
  }
}

async function sendEmail(msg) {
  const mailer = getMailer();
  if (!mailer) {
    return { channel: 'email', ok: false, error: 'nodemailer 또는 SMTP 미설정' };
  }
  if (!state.config.smtp.to) {
    return { channel: 'email', ok: false, error: 'SMTP_TO 미설정' };
  }
  try {
    const tag = SEVERITY_EMOJI[msg.severity] || '';
    const textBody = [
      msg.body || '',
      '',
      msg.details ? '--- 상세 ---' : '',
      msg.details ? Object.entries(msg.details).map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`).join('\n') : '',
    ].filter(Boolean).join('\n');
    await mailer.sendMail({
      from: state.config.smtp.from,
      to: state.config.smtp.to,
      subject: `${tag} [Vuln Assessor] ${msg.title}`,
      text: textBody,
    });
    return { channel: 'email', ok: true };
  } catch (e) {
    return { channel: 'email', ok: false, error: e.message };
  }
}

// ───── 외부 인터페이스 ────────────────────────────────

function configure(opts = {}) {
  if (opts.channels) {
    state.channels = Array.isArray(opts.channels) ? opts.channels : opts.channels.split(',').map(s => s.trim()).filter(Boolean);
  } else if (process.env.NOTIFIER_CHANNELS) {
    state.channels = process.env.NOTIFIER_CHANNELS.split(',').map(s => s.trim()).filter(Boolean);
  }
  if (opts.storage) state.storage = opts.storage;
  if (opts.log) state.log = opts.log;

  state.log.log(`[notifier] 채널: ${state.channels.join(', ')}`);
  if (state.channels.includes('slack')) {
    state.log.log(`[notifier] slack ${state.config.slack.webhookUrl ? '설정됨' : '미설정 — 발송 시 폴백'}`);
  }
  if (state.channels.includes('email')) {
    state.log.log(`[notifier] email ${state.config.smtp.host ? '설정됨' : '미설정 — 발송 시 폴백'}`);
  }
}

/**
 * 알림 발송. 채널별로 비동기 시도, 결과 배열 반환.
 * 실패해도 throw 하지 않음 (운영 시 알림 실패가 본 작업을 방해하면 안 됨).
 */
async function notify(msg) {
  if (!msg || !msg.title) {
    return [{ ok: false, error: 'title이 비어있음' }];
  }
  msg.severity = msg.severity || 'info';
  msg.event = msg.event || 'generic';

  const results = [];
  for (const ch of state.channels) {
    try {
      let r;
      if (ch === 'console') r = sendConsole(msg);
      else if (ch === 'slack') r = await sendSlack(msg);
      else if (ch === 'email') r = await sendEmail(msg);
      else r = { channel: ch, ok: false, error: '알 수 없는 채널' };
      results.push(r);
    } catch (e) {
      results.push({ channel: ch, ok: false, error: e.message });
    }
  }

  // 이력 적재
  if (state.storage) {
    try {
      const history = state.storage.loadSync('notifications') || [];
      history.unshift({
        notification_id: Date.now(),
        event: msg.event,
        severity: msg.severity,
        title: msg.title,
        body: msg.body || '',
        details: msg.details || null,
        sent_at: new Date().toISOString().slice(0, 19).replace('T', ' '),
        results,
      });
      // 최근 500건 유지
      if (history.length > 500) history.length = 500;
      state.storage.saveSync('notifications', history);
    } catch (e) {
      state.log.warn(`[notifier] 이력 적재 실패: ${e.message}`);
    }
  }

  return results;
}

module.exports = {
  configure,
  notify,
};

'use strict';
/**
 * 예약 진단 실행기 (스케줄러 런너).
 *
 * 기본 동작:
 *   - 1분 간격으로 폴링
 *   - schedules.json을 읽어 enabled && cron_expr !== 'manual' 인 항목만 대상
 *   - 각 스케줄의 next_run_at이 현재 시각 이전이면 실행
 *   - 실행 = server_scope에 따라 대상 서버 결정 → 각 서버에 진단 1회씩
 *   - 결과를 schedule_runs.json에 누적 + 스케줄의 last_run_at / last_status 갱신
 *
 * 진단 함수는 server-mock.js의 핵심 진단 로직을 그대로 호출하기 위해
 * runScheduledDiagnosis 콜백을 받는 구조로 분리. (server-mock.js가 콜백 주입)
 *
 * 종료:
 *   stop() — 폴링 인터벌 해제
 *
 * 환경변수:
 *   SCHEDULER_ENABLED=false  → 폴링 시작 안 함 (테스트용)
 *   SCHEDULER_INTERVAL_MS=N  → 폴링 주기 (기본 60000)
 *   SCHEDULER_TICK_NOW=1     → 시작 직후 한 번 즉시 tick (테스트용)
 */

const cron = require('./cron');

const DEFAULT_INTERVAL_MS = 60 * 1000;

const state = {
  intervalId: null,
  storage: null,
  runDiagnosis: null,  // async (server) => { status, vuln_count, ... }
  notifier: null,      // 선택. configure() 거친 notifier 모듈
  log: console,
  running: false,      // tick 중복 실행 가드
};

/**
 * 스케줄 항목에 next_run_at이 없거나 stale 이면 현재 시각 기준으로 다시 계산.
 * @returns {Date|null}
 */
function ensureNextRunAt(schedule, now) {
  if (!schedule.enabled) return null;
  if (!schedule.cron_expr || schedule.cron_expr === 'manual') return null;

  const stored = schedule.next_run_at_iso;
  if (stored) {
    const d = new Date(stored);
    if (!isNaN(d.getTime())) {
      // 과거든 미래든 stored 값을 그대로 반환.
      // 과거이면 호출자(tick)가 즉시 실행 트리거.
      return d;
    }
  }

  // stored 자체가 없음 → 다음 실행 시각만 계산해서 저장 (이번 tick은 실행 안 함)
  try {
    return cron.nextRunAfter(schedule.cron_expr, now);
  } catch (e) {
    state.log.warn(`[scheduler] cron 파싱 실패 (schedule_id=${schedule.schedule_id}): ${e.message}`);
    return null;
  }
}

/**
 * server_scope/server_group에 맞는 대상 서버 선정.
 */
function selectTargetServers(schedule, allServers) {
  const scope = schedule.server_scope || 'all';
  if (scope === 'all') return allServers;
  if (scope === 'group') {
    const grp = schedule.server_group;
    if (!grp) return [];
    return allServers.filter(s => (s.group || s.server_group) === grp
                                || (s.tags && s.tags.includes(grp)));
  }
  if (scope === 'list' && Array.isArray(schedule.server_ids)) {
    const idSet = new Set(schedule.server_ids.map(String));
    return allServers.filter(s => idSet.has(String(s.server_id)));
  }
  return [];
}

/**
 * 한 스케줄 실행: 대상 서버 N대에 대해 순차 진단 → 결과 집계 → 기록.
 *
 * @param {object} schedule
 * @param {Date}   now
 * @param {object} opts - { triggered_by: 'cron'|'manual' } (기본 'cron')
 */
async function runSchedule(schedule, now, opts = {}) {
  const triggered_by = opts.triggered_by || 'cron';
  const startedAt = new Date();
  const servers = state.storage.loadSync('servers') || [];
  const targets = selectTargetServers(schedule, servers);

  state.log.log(`[scheduler] ▶ "${schedule.name}" 시작 — 대상 ${targets.length}대 (${triggered_by})`);

  let success = 0, fail = 0;
  const perServer = [];

  for (const server of targets) {
    try {
      const result = await state.runDiagnosis(server, {
        triggered_by,
        diagnose_type: schedule.diagnose_type || 'rule',  // 'rule' | 'ai'
      });
      if (result && result.status === 'success') {
        success++;
        perServer.push({
          server_id: server.server_id,
          hostname: server.hostname,
          status: 'success',
          assessment_id: result.assessment_id,
          vuln_count: result.summary?.vuln,
          elapsed_ms: result.elapsed_ms,
        });
      } else {
        fail++;
        perServer.push({
          server_id: server.server_id,
          hostname: server.hostname,
          status: 'failed',
          error: result?.error || 'unknown',
        });
      }
    } catch (e) {
      fail++;
      perServer.push({
        server_id: server.server_id,
        hostname: server.hostname,
        status: 'failed',
        error: e.message,
      });
    }
  }

  const finishedAt = new Date();
  const elapsedMs = finishedAt - startedAt;
  const overallStatus = fail === 0 ? '성공' : success === 0 ? '실패' : '부분실패';

  // 실행 이력 적재
  const runs = state.storage.loadSync('schedule_runs') || [];
  runs.unshift({
    run_id: Date.now(),
    schedule_id: schedule.schedule_id,
    schedule_name: schedule.name,
    triggered_by,
    started_at: startedAt.toISOString().slice(0, 19).replace('T', ' '),
    finished_at: finishedAt.toISOString().slice(0, 19).replace('T', ' '),
    elapsed_ms: elapsedMs,
    status: overallStatus,
    total: targets.length,
    success,
    failed: fail,
    per_server: perServer,
  });
  // 최근 200건만 유지
  if (runs.length > 200) runs.length = 200;
  state.storage.saveSync('schedule_runs', runs);

  // 스케줄의 last_* 갱신 + 다음 실행 시각 재계산
  const schedules = state.storage.loadSync('schedules') || [];
  const s = schedules.find(x => x.schedule_id === schedule.schedule_id);
  if (s) {
    s.last_run_at = startedAt.toISOString().slice(0, 19).replace('T', ' ');
    s.last_status = overallStatus;
    s.last_success = success;
    s.last_total = targets.length;
    try {
      const nxt = cron.nextRunAfter(s.cron_expr, finishedAt);
      s.next_run_at_iso = nxt.toISOString();
      s.next_run_at = nxt.toISOString().slice(0, 16).replace('T', ' ');
    } catch (_) { /* manual 등 — 무시 */ }
    state.storage.saveSync('schedules', schedules);
  }

  // 알림 발송 — notifier 모듈 사용 (start() 시 state.notifier로 주입됨)
  if (state.notifier) {
    const totalVuln = perServer.reduce((acc, p) => acc + (p.vuln_count || 0), 0);

    // 실패 알림
    if (schedule.notify_on_failure && fail > 0) {
      try {
        await state.notifier.notify({
          event: 'schedule_failed',
          severity: 'error',
          title: `예약 진단 실패 — ${schedule.name}`,
          body: `대상 ${targets.length}대 중 ${fail}대 실패 (성공 ${success}대, ${elapsedMs}ms)`,
          details: {
            schedule_id: schedule.schedule_id,
            schedule_name: schedule.name,
            failed_count: fail,
            total: targets.length,
            failed_servers: perServer.filter(p => p.status === 'failed').map(p => p.hostname).join(', '),
          },
        });
      } catch (e) {
        state.log.warn(`[scheduler] 실패 알림 전송 실패: ${e.message}`);
      }
    }

    // 취약점 발견 알림
    if (schedule.notify_on_vuln && totalVuln > 0) {
      try {
        await state.notifier.notify({
          event: 'schedule_vuln_found',
          severity: totalVuln > 10 ? 'error' : 'warning',
          title: `취약점 발견 — ${schedule.name}`,
          body: `대상 ${targets.length}대에서 총 ${totalVuln}건 취약 항목 발견`,
          details: {
            schedule_id: schedule.schedule_id,
            schedule_name: schedule.name,
            total_servers: targets.length,
            total_vulns: totalVuln,
            per_server: perServer
              .filter(p => p.vuln_count > 0)
              .map(p => `${p.hostname}: ${p.vuln_count}건`)
              .join(', '),
          },
        });
      } catch (e) {
        state.log.warn(`[scheduler] 취약점 알림 전송 실패: ${e.message}`);
      }
    }
  }

  state.log.log(`[scheduler] ◀ "${schedule.name}" 종료 — ${overallStatus} (성공 ${success} / 실패 ${fail}, ${elapsedMs}ms)`);
}

/**
 * 1 tick — 모든 활성 스케줄을 검사해 시각이 됐으면 실행.
 */
async function tick(now = new Date()) {
  if (state.running) {
    state.log.log('[scheduler] tick 중복 — 이전 tick 진행중, 스킵');
    return { skipped: true };
  }
  state.running = true;

  const summary = { ran: 0, scanned: 0, scheduled: [] };
  try {
    const schedules = state.storage.loadSync('schedules') || [];
    summary.scanned = schedules.length;

    for (const schedule of schedules) {
      const next = ensureNextRunAt(schedule, now);
      if (!next) continue;

      // next_run_at_iso가 비어있던 케이스 — 계산만 해서 저장, 실행은 다음 tick
      if (!schedule.next_run_at_iso) {
        schedule.next_run_at_iso = next.toISOString();
        schedule.next_run_at = next.toISOString().slice(0, 16).replace('T', ' ');
        state.storage.saveSync('schedules', schedules);
        continue;
      }

      // 시각 도래 여부
      if (next <= now) {
        summary.scheduled.push(schedule.schedule_id);
        await runSchedule(schedule, now);
        summary.ran++;
      }
    }
  } catch (e) {
    state.log.error(`[scheduler] tick 오류: ${e.message}`);
  } finally {
    state.running = false;
  }
  return summary;
}

/**
 * 시작.
 * @param {object} opts
 * @param {object} opts.storage - kvStorage (loadSync/saveSync)
 * @param {function} opts.runDiagnosis - async (server) => 진단 실행 결과
 * @param {number}   opts.intervalMs - 폴링 주기 (기본 60000)
 * @param {object}   opts.log - 로거
 */
function start(opts) {
  if (state.intervalId) return;
  state.storage = opts.storage;
  state.runDiagnosis = opts.runDiagnosis;
  state.notifier = opts.notifier || null;
  state.log = opts.log || console;

  if (process.env.SCHEDULER_ENABLED === 'false') {
    state.log.log('[scheduler] SCHEDULER_ENABLED=false — 비활성화');
    return;
  }

  const interval = parseInt(process.env.SCHEDULER_INTERVAL_MS || '', 10)
                || opts.intervalMs
                || DEFAULT_INTERVAL_MS;

  state.intervalId = setInterval(() => { tick().catch(e => state.log.error(e)); }, interval);
  // Node 종료 막지 않도록
  if (state.intervalId.unref) state.intervalId.unref();

  state.log.log(`[scheduler] 시작 — 주기 ${interval}ms`);

  if (process.env.SCHEDULER_TICK_NOW === '1') {
    setImmediate(() => { tick().catch(e => state.log.error(e)); });
  }
}

function stop() {
  if (state.intervalId) {
    clearInterval(state.intervalId);
    state.intervalId = null;
  }
}

module.exports = {
  start,
  stop,
  tick,           // 테스트/수동 트리거용
  runSchedule,    // 단일 스케줄 즉시 실행 (UI '지금 실행' 버튼용)
};

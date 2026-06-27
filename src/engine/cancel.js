'use strict';
/**
 * 진단 배치 취소 플래그 — run-all 루프와 diagnoseAll 이 공유.
 * UI "중지" → /scheduler/cancel → request() 로 플래그 set.
 * 새 배치 시작 시 reset(), 루프/워커가 isCancelled() 를 확인해 멈춘다.
 */
let cancelled = false;
module.exports = {
  request() { cancelled = true; },
  reset() { cancelled = false; },
  isCancelled() { return cancelled; },
};

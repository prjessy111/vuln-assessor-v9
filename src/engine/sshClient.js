'use strict';
/**
 * ssh2 라이브러리 래퍼.
 *
 * 책임:
 *  - 키 또는 비밀번호로 SSH 연결
 *  - 명령 실행 (stdout/stderr/exit code 반환)
 *  - SFTP로 파일 다운로드
 *  - SQLite .backup 으로 일관성 있는 스냅샷 생성 후 다운로드
 *  - 연결 자동 종료
 *
 * ssh2 라이브러리는 native 모듈이 아니라 pure JS이므로 동작 보장됨.
 */
const fs = require('fs');
const path = require('path');
const { Client } = require('ssh2');

/**
 * SSH 연결을 맺고 호출자 콜백 안에서 ssh 객체를 사용. 종료 시 자동 disconnect.
 *
 * @param {object} opts
 *   - host, port, username : 필수
 *   - privateKeyPath OR password : 인증 (둘 중 하나)
 *   - readyTimeout : 기본 15000ms
 */
// 단일 연결 시도. 연결 단계(핸드셰이크/인증) 실패는 err._phase='connect',
// fn 실행 중 에러는 err._phase='fn' 으로 태깅해 호출자가 재시도 여부를 구분.
function _connectOnce(opts, fn) {
  const conn = new Client();
  const config = {
    host: opts.host,
    port: opts.port || 22,
    username: opts.username,
    readyTimeout: opts.readyTimeout || 15000,
    keepaliveInterval: 5000,
  };
  if (opts.privateKeyPath) {
    config.privateKey = fs.readFileSync(opts.privateKeyPath);
    if (opts.passphrase) config.passphrase = opts.passphrase;
  } else if (opts.password) {
    config.password = opts.password;
    config.tryKeyboard = true;
  } else {
    throw new Error('SSH 인증 정보가 없습니다. privateKeyPath 또는 password 필요.');
  }

  return new Promise((resolve, reject) => {
    let done = false;
    let ready = false;
    const finish = (err, val) => {
      if (done) return;
      done = true;
      clearTimeout(connectTimer);
      try { conn.end(); } catch (_) {}
      err ? reject(err) : resolve(val);
    };
    const connectMs = (opts.readyTimeout || 15000) + 3000;
    const connectTimer = setTimeout(() => {
      if (!ready) {
        try { conn.destroy(); } catch (_) {}
        const e = new Error(`SSH 연결/인증 타임아웃 (${connectMs}ms 초과 — 미응답 서버)`);
        e._phase = 'connect';
        finish(e);
      }
    }, connectMs);

    conn.on('ready', async () => {
      ready = true;
      clearTimeout(connectTimer);
      try {
        const result = await fn(conn);
        finish(null, result);
      } catch (e) { if (!e._phase) e._phase = 'fn'; finish(e); }
    });
    conn.on('error', (e) => { if (!e._phase) e._phase = ready ? 'transport' : 'connect'; finish(e); });
    if (config.tryKeyboard) {
      conn.on('keyboard-interactive',
        (name, instructions, lang, prompts, finish2) => finish2([opts.password]));
    }
    conn.connect(config);
  });
}

const _sleep = (ms) => new Promise(r => setTimeout(r, ms));

/**
 * SSH 연결 + 콜백 실행. 연결 단계(핸드셰이크/인증) 실패는 자동 재시도(.207 등 SSH 깜빡임 흡수).
 * fn 실행 중 에러(sh 실행 실패 등)는 재시도하지 않음(부작용 방지).
 * @param {object} opts - host/port/username/(password|privateKeyPath), readyTimeout, connectRetries(기본 2)
 */
async function withConnection(opts, fn) {
  const retries = opts.connectRetries != null ? opts.connectRetries : 2; // 총 3회 시도
  let lastErr;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      return await _connectOnce(opts, fn);
    } catch (e) {
      lastErr = e;
      // 연결 단계 실패만 재시도 (fn 실행 중 에러는 즉시 throw)
      if (e._phase === 'connect' && attempt < retries) {
        console.warn(`[ssh] ${opts.host} 연결 실패(${attempt + 1}/${retries + 1}) — ${e.message} → ${2 * (attempt + 1)}초 후 재시도`);
        await _sleep(2000 * (attempt + 1));
        continue;
      }
      throw e;
    }
  }
  throw lastErr;
}

/**
 * 원격에서 명령 실행. stdout, stderr, code 반환.
 */
function exec(conn, command, { timeout = 30000 } = {}) {
  return new Promise((resolve, reject) => {
    conn.exec(command, (err, stream) => {
      if (err) return reject(err);
      let stdout = '', stderr = '';
      let timer = setTimeout(() => {
        stream.close();
        reject(new Error(`명령 타임아웃 (${timeout}ms): ${command}`));
      }, timeout);

      stream.on('data', d => stdout += d.toString('utf8'));
      stream.stderr.on('data', d => stderr += d.toString('utf8'));
      stream.on('close', (code) => {
        clearTimeout(timer);
        resolve({ stdout, stderr, code });
      });
    });
  });
}

/**
 * SFTP를 통한 파일 다운로드.
 */
function downloadFile(conn, remotePath, localPath) {
  return new Promise((resolve, reject) => {
    conn.sftp((err, sftp) => {
      if (err) return reject(err);
      sftp.fastGet(remotePath, localPath, (err2) => {
        if (err2) return reject(err2);
        // 파일 크기 반환
        try { resolve(fs.statSync(localPath).size); }
        catch (e) { reject(e); }
      });
    });
  });
}

/**
 * SQLite raw 파일을 일관성 있는 스냅샷으로 가져오는 표준 흐름.
 *
 * @param {object} server  - { host, port, username, privateKeyPath/password,
 *                            remote_raw_path, use_sudo }
 * @param {string} localPath - 진단 PC에 저장할 경로
 * @returns {{ size: number, snapshotPath: string }}
 */
async function fetchRawSnapshot(server, localPath) {
  const snapId = Date.now() + '_' + Math.random().toString(36).slice(2, 8);
  const remoteSnap = `/tmp/vuln_snap_${snapId}.db`;
  const sudo = server.use_sudo ? 'sudo ' : '';

  return withConnection({
    host: server.hostname,
    port: server.ssh_port,
    username: server.ssh_user,
    privateKeyPath: server.ssh_key_path,
    password: server._decrypted_password,  // rawCollectorService에서 복호화하여 주입
  }, async (conn) => {
    // 1) 원격에서 .backup 으로 스냅샷 생성
    //    sqlite3 명령이 없는 경우를 대비해 cp + sync 폴백 옵션도 고려 가능하나, 권장은 .backup
    const backupCmd = `${sudo}sqlite3 '${server.remote_raw_path}' ".backup '${remoteSnap}'"`;
    const r1 = await exec(conn, backupCmd, { timeout: 60000 });
    if (r1.code !== 0) {
      throw new Error(`스냅샷 생성 실패: ${r1.stderr || r1.stdout || `exit ${r1.code}`}`);
    }

    // 2) 권한을 ssh_user 로 변경 (sudo 사용 시)
    if (server.use_sudo) {
      const chown = `${sudo}chown ${server.ssh_user} ${remoteSnap}`;
      const r2 = await exec(conn, chown);
      if (r2.code !== 0) {
        await exec(conn, `${sudo}rm -f ${remoteSnap}`).catch(() => {});
        throw new Error(`스냅샷 권한 변경 실패: ${r2.stderr || `exit ${r2.code}`}`);
      }
    }

    // 3) SFTP로 다운로드
    let size;
    try {
      size = await downloadFile(conn, remoteSnap, localPath);
    } finally {
      // 4) 원격 임시 파일 정리 (실패해도 무시)
      await exec(conn, `${sudo}rm -f ${remoteSnap}`).catch(() => {});
    }

    return { size, snapshotPath: localPath };
  });
}

module.exports = { withConnection, exec, downloadFile, fetchRawSnapshot };

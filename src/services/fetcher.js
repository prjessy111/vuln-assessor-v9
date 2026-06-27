const { Client } = require('ssh2');
const SMB2 = require('@marsaud/smb2');
const fs = require('fs');
const path = require('path');
const ssh = require('../engine/sshClient');

// 최상위 폴더 기준 업로드 기본 경로
const UPLOAD_TMP_DIR = process.env.UPLOAD_TMP_DIR || path.resolve(__dirname, '../../data/uploads');

/**
 * 오늘 날짜를 'YYYY-MM-DD' 형태의 문자열로 반환하는 헬퍼 함수
 */
function getTodayDateString() {
  const now = new Date();
  const year = now.getFullYear();
  // getMonth()는 0부터 시작하므로 1을 더해주고, 1자리수일 경우 앞에 0을 붙입니다.
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const day = String(now.getDate()).padStart(2, '0');
  return `${year}-${month}-${day}`;
}

/**
 * 날짜별 타겟 폴더 경로를 반환하고, 폴더가 없으면 자동으로 생성하는 함수
 */
function getAndCreateTargetDir() {
  const dateString = getTodayDateString();
  const targetDir = path.resolve(UPLOAD_TMP_DIR, dateString);
  
  if (!fs.existsSync(targetDir)) {
    fs.mkdirSync(targetDir, { recursive: true });
  }
  return targetDir;
}

module.exports = {
  fetchFromUnix: async (serverIp, username, password, hostname) => {
    const remotePath = '/opt/lsware/secums/agent/bin/exportData-SSUnix.db';

    // [수정됨] 오늘 날짜 폴더를 생성/가져온 뒤 그 안에 파일을 저장합니다.
    const targetDir = getAndCreateTargetDir();
    const localPath = path.resolve(targetDir, `${hostname}_exportData-SSUnix.db`);

    // script 수집과 동일한 공유 SSH 래퍼 사용.
    // (raw ssh2.Client + password 만으로는 keyboard-interactive 전용 sshd[CentOS PAM]에서
    //  핸드셰이크 타임아웃 발생 → withConnection 은 tryKeyboard + keepalive + 하드 타임아웃 포함)
    await ssh.withConnection(
      { host: serverIp, port: 22, username, password, readyTimeout: 20000 },
      async (conn) => { await ssh.downloadFile(conn, remotePath, localPath); }
    );
    return localPath;
  },

  fetchFromWindows: async (serverIp, username, password, hostname) => {
    const remotePath = 'Program Files (x86)\\lsware\\secums\\agent\\bin\\exportData-SSWindows.db';
    
    // [수정됨] 오늘 날짜 폴더를 생성/가져온 뒤 그 안에 파일을 저장합니다.
    const targetDir = getAndCreateTargetDir();
    const localPath = path.resolve(targetDir, `${hostname}_exportData-SSWindows.db`);

    return new Promise((resolve, reject) => {
      const smb2Client = new SMB2({
        share: `\\\\${serverIp}\\c$`,
        domain: 'WORKGROUP', 
        username: username,
        password: password
      });

      smb2Client.readFile(remotePath, (err, data) => {
        smb2Client.disconnect();
        if (err) return reject(err);
        
        try {
          fs.writeFileSync(localPath, data);
          resolve(localPath);
        } catch (writeErr) {
          reject(writeErr);
        }
      });
    });
  }
};
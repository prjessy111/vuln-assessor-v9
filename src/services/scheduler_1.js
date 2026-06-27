// ⚠ 가장 먼저 .env 로드 — DB_MODE / LLM_PROVIDER 등이 process.env 에 들어가야 함
require('../config');

const path = require('path');
const fs = require('fs');

// MySQL/JSON 추상화 저장소
const kvStorage = require('../storage');

// 1. 같은 src/services 폴더에 있는 fetcher.js 모듈 로드
const fetcher = require('./fetcher');
// 2. 상위 폴더(..)로 나가서 engine 폴더 안의 AI 진단 모듈 로드
const { executeAiDiagnosis } = require('../engine/aiAssessment');

// [추가됨] 원격 제어 및 파싱을 위한 필수 패키지 로드
const { Client } = require('ssh2');
const { XMLParser } = require('fast-xml-parser');
const SMB2 = require('@marsaud/smb2');
const winrm = require('winrm');

// 지원하는 유닉스 계열 전체 OS 정의 파라미터
const UNIX_FAMILY = ['linux', 'solaris', 'aix', 'hp-ux'];

// AI 진단을 지원하는 OS (어댑터가 준비된 것)
const AI_DIAGNOSE_SUPPORTED = ['linux', 'solaris', 'aix', 'hp-ux', 'windows'];

// 실행 위치와 상관없이 항상 프로젝트 최상위의 data/mock 폴더를 바라보도록 절대 경로 고정
const SCHEDULER_LOG_PATH = path.resolve(__dirname, '../../data/mock/scheduler_runs.json');

/**
 * 외부 CSV 파일에서 타겟 서버 목록을 읽어오는 함수.
 */
function getTargetServersFromFile() {
  const csvPath = path.resolve(__dirname, '../../servers.csv');
  
  if (!fs.existsSync(csvPath)) {
    console.error(`[오류] 서버 목록 파일이 없습니다: ${csvPath}`);
    return [];
  }

  const fileContent = fs.readFileSync(csvPath, 'utf-8');
  const lines = fileContent.split('\n');
  const servers = [];

  for (const line of lines) {
    const trimmedLine = line.trim();
    
    if (!trimmedLine || trimmedLine.startsWith('#')) continue;

    const parts = trimmedLine.replace(/\r$/, '').split(',').map(p => p.trim());
    
    if (parts.length >= 5) {
      servers.push({
        hostname: parts[0],
        ip:       parts[1],
        os:       parts[2],
        username: parts[3],
        password: parts[4],
        asset_no: parts[5] || parts[0],
        server_id: parts[6] || parts[1],
      });
    } else {
      console.warn(`[CSV 경고] 컬럼 수 부족 (5개 미만): ${trimmedLine}`);
    }
  }
  
  return servers;
}

function appendRunLog(record) {
  try {
    let history = kvStorage.loadSync('scheduler_runs') || [];
    if (!Array.isArray(history)) history = [];
    history.unshift(record);
    if (history.length > 500) history.length = 500;
    kvStorage.saveSync('scheduler_runs', history);
  } catch (e) {
    console.error('[Scheduler] 실행 로그 저장 실패:', e.message);
  }
}

// ======================================================================
// [추가 모듈 1] 유닉스/리눅스 전용: SSH 기반 스크립트 배포/실행/수집
// ======================================================================
function fetchCustomXmlViaSSH(targetServer) {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    
    const sshConfig = {
      host: targetServer.ip,
      port: 22,
      username: targetServer.username,
      password: targetServer.password
    };

    conn.on('ready', () => {
      conn.sftp((err, sftp) => {
        if (err) return reject(err);

        const localScript = path.resolve(__dirname, '../../scripts/fsi_unix_ai.sh'); 
        const remoteScript = '/tmp/fsi_unix_ai.sh';
        const remoteXml = '/tmp/fsi_result_unix.xml';

        sftp.fastPut(localScript, remoteScript, (err) => {
          if (err) { conn.end(); return reject(new Error('스크립트 배포 실패')); }

          conn.exec(`chmod +x ${remoteScript} && ${remoteScript}`, (err, stream) => {
            if (err) { conn.end(); return reject(new Error('원격 실행 실패')); }

            stream.on('close', (code) => {
              if (code !== 0) console.warn(`[Scheduler] 리눅스 스크립트 종료 코드: ${code}`);

              let xmlData = '';
              const readStream = sftp.createReadStream(remoteXml);
              
              readStream.on('data', (chunk) => { xmlData += chunk; });
              readStream.on('end', () => {
                conn.exec(`rm -f ${remoteScript} ${remoteXml}`, () => {
                  conn.end();
                  try {
                    const parser = new XMLParser();
                    resolve(parser.parse(xmlData));
                  } catch (parseErr) {
                    reject(new Error('XML 파싱 실패'));
                  }
                });
              });
              
              readStream.on('error', (err) => {
                conn.end();
                reject(new Error('결과 XML 파일을 찾을 수 없습니다.'));
              });
            });
          });
        });
      });
    }).on('error', (err) => {
      reject(new Error(`SSH 연결 실패: ${err.message}`));
    }).connect(sshConfig);
  });
}

// ======================================================================
// [추가 모듈 2] 윈도우 전용: SMB + WinRM 기반 스크립트 배포/실행/수집
// ======================================================================
function fetchCustomXmlViaWindows(targetServer) {
  return new Promise((resolve, reject) => {
    const smbClient = new SMB2({
      share: `\\\\${targetServer.ip}\\C$`,
      domain: 'WORKGROUP',
      username: targetServer.username,
      password: targetServer.password,
      autoCloseTimeout: 0
    });

    const localBat = path.resolve(__dirname, '../../scripts/fsi_win_ai.bat');
    const remoteBatPath = 'Windows\\Temp\\fsi_win_ai.bat';
    const remoteXmlPath = 'Windows\\Temp\\fsi_result_win.xml';

    fs.readFile(localBat, (err, batContent) => {
      if(err) return reject(new Error('로컬 BAT 스크립트를 찾을 수 없습니다.'));

      smbClient.writeFile(remoteBatPath, batContent, (err) => {
        if (err) { smbClient.close(); return reject(new Error('SMB 배포 실패')); }

        const winrmClient = winrm.createClient({
          host: targetServer.ip,
          user: targetServer.username,
          pass: targetServer.password
        });

        const execCmd = `cmd.exe /c C:\\Windows\\Temp\\fsi_win_ai.bat`;

        winrmClient.executeCommand(execCmd, (execErr, res) => {
          if (execErr) console.warn(`[WinRM 실행 경고]: ${execErr.message}`);

          setTimeout(() => {
            smbClient.readFile(remoteXmlPath, 'utf8', (readErr, xmlData) => {
              smbClient.unlink(remoteBatPath, () => {
                smbClient.unlink(remoteXmlPath, () => {
                  smbClient.close();

                  if (readErr) return reject(new Error('윈도우 XML 결과 파일 수집 실패'));

                  try {
                    const parser = new XMLParser();
                    resolve(parser.parse(xmlData));
                  } catch (parseErr) {
                    reject(new Error('윈도우 XML 파싱 실패'));
                  }
                });
              });
            });
          }, 3000); // 윈도우 스크립트가 결과를 다 쓸 때까지 3초 여유 대기
        });
      });
    });
  });
}

// ======================================================================
// 메인 스케줄러 실행 로직 (병합 처리)
// ======================================================================
async function runScheduledDiagnosis(targetServer) {
  const hostname = targetServer.hostname || targetServer.name || `unknown-${targetServer.ip}`;
  const osType = (targetServer.os || '').toLowerCase();
  const startedAt = new Date();
  
  const runRecord = {
    started_at:      startedAt.toISOString().slice(0, 19).replace('T', ' '),
    hostname,
    ip:              targetServer.ip,
    os:              osType,
    fetch_status:    null,
    fetch_error:     null,
    local_db_path:   null,
    diagnose_status: null,
    diagnose_error:  null,
    assessment_id:   null,
    summary:         null,
    elapsed_ms:      null,
  };
  
  try {
    console.log(`[Scheduler] [${hostname}] (${targetServer.ip}) 원격 데이터 Pulling 시작...`);
    let localDbPath = '';

    // 1. 기존 에이전트(SecuMS) 방식 데이터 수집
    if (UNIX_FAMILY.includes(osType)) {
      localDbPath = await fetcher.fetchFromUnix(
        targetServer.ip, targetServer.username, targetServer.password, hostname
      );
    } else if (osType === 'windows') {
      localDbPath = await fetcher.fetchFromWindows(
        targetServer.ip, targetServer.username, targetServer.password, hostname
      );
    } else {
      throw new Error(`분석 불가능한 미지원 OS 플랫폼 타입입니다: ${targetServer.os}`);
    }

    console.log(`[Scheduler] [${hostname}] 수집 완료 -> 파일 경로: ${localDbPath}`);
    runRecord.fetch_status  = 'success';
    runRecord.local_db_path = localDbPath;

    // 2. FSI 스크립트 원격 실행 및 데이터 추가 수집 (OS별 분기)
    let customXmlData = null;
    try {
      if (UNIX_FAMILY.includes(osType)) {
        console.log(`[Scheduler] [${hostname}] 리눅스(SSH) 커스텀 스크립트 원격 진단 중...`);
        customXmlData = await fetchCustomXmlViaSSH(targetServer);
        console.log(`[Scheduler] [${hostname}] 리눅스 XML 데이터 수집 완료!`);
      } else if (osType === 'windows') {
        console.log(`[Scheduler] [${hostname}] 윈도우(WinRM+SMB) 커스텀 스크립트 원격 진단 중...`);
        customXmlData = await fetchCustomXmlViaWindows(targetServer);
        console.log(`[Scheduler] [${hostname}] 윈도우 XML 데이터 수집 완료!`);
      }
    } catch (err) {
      console.warn(`[Scheduler] [${hostname}] 커스텀 XML 수집 실패 (기존 진단으로 계속 진행): ${err.message}`);
    }

    if (!AI_DIAGNOSE_SUPPORTED.includes(osType)) {
      console.log(`[Scheduler] [${hostname}] AI 진단 미지원 OS (${osType}) — 수집만 완료, 진단 건너뜀`);
      runRecord.diagnose_status = 'skipped';
      runRecord.diagnose_error  = `AI 진단 어댑터 미구현 OS: ${osType}`;
      appendRunLog(runRecord);
      return runRecord;
    }

    console.log(`[Scheduler] [${hostname}] AI 진단 시작...`);
    
    const serverForDiagnosis = {
      server_id: targetServer.server_id || targetServer.ip,
      name:      targetServer.name || hostname,
      hostname,
      asset_no:  targetServer.asset_no || hostname,
    };

    // 3. 기존 데이터와 커스텀 스크립트 데이터를 통째로 AI 엔진에 넘김
    const result = await executeAiDiagnosis(serverForDiagnosis, {
      executed_by:  'scheduler',
      triggered_by: 'scheduler',
      rawPath:      localDbPath,
      customXmlResult: customXmlData 
    });

    runRecord.diagnose_status = result.status;
    runRecord.assessment_id   = result.assessment_id || null;
    runRecord.summary         = result.summary || null;
    runRecord.elapsed_ms      = result.elapsed_ms || null;
    runRecord.diagnose_error  = result.error || null;

    if (result.status === 'success') {
      console.log(
        `[Scheduler] [${hostname}] AI 진단 완료 → id=${result.assessment_id}, ` +
        `취약 ${result.summary.vuln}건 / 양호 ${result.summary.safe}건 / ` +
        `정보제공 ${result.summary.info}건 / 일치율 ${result.summary.agreement_rate}% / ` +
        `검증 실패율 ${result.summary.validation_failure_rate || 0}% ` +
        `(${result.elapsed_ms}ms)`
      );
    } else {
      console.error(`[Scheduler] [${hostname}] AI 진단 실패: ${result.error}`);
    }

  } catch (error) {
    console.error(`[Scheduler] [${hostname}] (${targetServer.ip}) 원격 수집 실패:`, error.message);
    if (runRecord.fetch_status !== 'success') {
      runRecord.fetch_status = 'failed';
      runRecord.fetch_error  = error.message;
    } else {
      runRecord.diagnose_status = 'failed';
      runRecord.diagnose_error  = error.message;
    }
  }
  
  runRecord.finished_at = new Date().toISOString().slice(0, 19).replace('T', ' ');
  appendRunLog(runRecord);
  return runRecord;
}

async function startScheduler() {
  console.log('[Scheduler] 중앙 집중식 에이전트 데이터 자동 수거 + AI 진단 스케줄러 가동 시작.');

  const targetServers = getTargetServersFromFile();

  if (targetServers.length === 0) {
    console.log('[Scheduler] 수집할 대상 서버가 없습니다. (servers.csv 파일을 확인하세요)');
    return;
  }

  console.log(`[Scheduler] 대상 서버 ${targetServers.length}개:`);
  targetServers.forEach((s, i) => {
    console.log(`  ${i+1}. ${s.hostname} (${s.ip}, ${s.os})`);
  });

  const summary = { total: 0, success: 0, fetched_only: 0, failed: 0 };

  for (const server of targetServers) {
    const result = await runScheduledDiagnosis(server);
    summary.total++;
    if (result.diagnose_status === 'success') {
      summary.success++;
    } else if (result.diagnose_status === 'skipped' && result.fetch_status === 'success') {
      summary.fetched_only++;
    } else {
      summary.failed++;
    }
  }

  console.log(`\n[Scheduler] 전체 처리 결과: 대상 ${summary.total}개 / 진단성공 ${summary.success}개 / 수집만 ${summary.fetched_only}개 / 실패 ${summary.failed}개`);
  console.log(`[Scheduler] 결과는 웹 /diagnosis 또는 /scheduler/history 에서 확인 가능`);
}

module.exports = {
  startScheduler,
  runScheduledDiagnosis,
  getTargetServersFromFile,
};

// [단독 검증용] npm run scheduler 명령어로 실행 시 가동되도록 활성화
if (require.main === module) {
  (async () => {
    try {
      const status = await kvStorage.initialize();
      if (status.mode === 'mysql' && status.status === 'ok') {
        await kvStorage.preloadAll();
        console.log(`[Scheduler] MySQL 모드 활성화 — ${kvStorage.mode}`);
      } else if (status.status === 'fallback') {
        console.warn(`[Scheduler] MySQL 연결 실패 → mock(JSON) 폴백`);
      } else {
        console.log(`[Scheduler] mock(JSON) 모드`);
      }
      await startScheduler();
    } catch (e) {
      console.error('[Scheduler] 초기화 오류:', e);
      process.exit(1);
    }
  })();
}
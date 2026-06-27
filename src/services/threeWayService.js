'use strict';
/**
 * 3-way 정합성 비교.
 *
 * 한 서버에 대해 세 가지 판정을 항목 단위로 나란히 비교한다:
 *   ① secums raw AI : SecuMS raw DB 기반 AI 진단 (os-xxx 코드, ai_verdict)
 *   ② script AI     : Script XML 기반 AI 진단 (SRV 코드, ai_verdict)
 *   ③ secums 자체판정 : SecuMS 제품의 판정 (os-xxx, secums_verdict: BAD/OK/INFO)
 *
 * 연결 다리 = data/srv-secums-crosswalk.json (리포트1: SRV ↔ os-xxx ↔ 제목).
 * 실측: SecuMS raw DB CHECKLIST_TB 코드 = 리포트1 ScanID 100% 일치.
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '../..');

let _crosswalk = null;
function loadCrosswalk() {
  if (_crosswalk) return _crosswalk;
  _crosswalk = JSON.parse(fs.readFileSync(path.join(ROOT, 'data/srv-secums-crosswalk.json'), 'utf8'));
  return _crosswalk;
}

// AI 판정(취약/양호/판정불가/정보제공) → 비교용 버킷
function normAi(v) {
  const s = String(v || '').trim();
  if (s === '취약') return '취약';
  if (s === '양호') return '양호';
  return '기타'; // 판정불가/정보제공/정보
}
// SecuMS 자체판정(BAD/OK/INFO/WAIT) → 비교용 버킷
function normSecums(v) {
  const s = String(v || '').trim().toUpperCase();
  if (s === 'BAD') return '취약';
  if (s === 'OK') return '양호';
  if (s === 'WAIT' || s === '' ) return '미점검';
  return '기타'; // INFO 등
}

function isDecisive(x) { return x === '취약' || x === '양호'; }

/**
 * @param {object} secumsRec - secums 소스 진단 레코드 (results[].chk_id=os-xxx)
 * @param {object} scriptRec - script 소스 진단 레코드 (results[].chk_id=SRV)
 * @param {string} osType - 'windows' | 'linux'
 * @param {object} [secumsAnswer] - 업로드한 SecuMS 상세리포트 정답지 { srv: 'BAD'|'OK'|'INFO' }.
 *                                   있으면 ③(자체판정)을 이걸로 우선 사용(SRV 키라 정확).
 */
function buildThreeWay(secumsRec, scriptRec, osType, secumsAnswer) {
  const cw = loadCrosswalk();
  const os = String(osType || '').toLowerCase().includes('win') ? 'windows' : 'linux';
  const rows = cw[os] || [];
  const answer = (secumsAnswer && secumsAnswer.verdicts) ? secumsAnswer.verdicts : secumsAnswer || null;

  // 인덱스: os-xxx → secums 항목, SRV → script 항목
  const secumsByScan = {};
  for (const it of (secumsRec && secumsRec.results) || []) {
    secumsByScan[String(it.chk_id)] = it;
  }
  const scriptBySrv = {};
  for (const it of (scriptRec && scriptRec.results) || []) {
    scriptBySrv[String(it.chk_id)] = it;
  }

  const out = [];
  for (const r of rows) {
    const sec = secumsByScan[r.scan_id];
    const scr = scriptBySrv[r.srv];
    const aiSecums = sec ? normAi(sec.ai_verdict) : null;          // ①
    // ③ 자체판정: 업로드 정답지(SRV) 우선, 없으면 raw DB의 secums_verdict
    const secumsSelf = (answer && answer[r.srv] != null)
      ? normSecums(answer[r.srv])
      : (sec ? normSecums(sec.secums_verdict) : null);
    const aiScript = scr ? normAi(scr.ai_verdict) : null;          // ②

    const decisive = [aiSecums, aiScript, secumsSelf].filter(isDecisive);
    let match;
    if (decisive.length < 2) {
      match = 'no_data'; // 비교 불가 (판정 2개 미만)
    } else {
      const allSame = decisive.every(x => x === decisive[0]);
      match = allSame ? 'agree' : 'mismatch';
    }

    out.push({
      srv: r.srv,
      scan_id: r.scan_id,
      title: r.title,
      ai_secums: aiSecums,     // ①
      ai_script: aiScript,     // ②
      secums_self: secumsSelf, // ③
      has_secums: !!sec,
      has_script: !!scr,
      match,
    });
  }

  const comparable = out.filter(x => x.match === 'agree' || x.match === 'mismatch');
  const agree = out.filter(x => x.match === 'agree').length;
  const mismatch = out.filter(x => x.match === 'mismatch').length;

  // 소스별 탐지 정확성: ③ SecuMS 자체판정(정답지)이 취약/양호로 판정한 항목을 "모수"로 두고,
  // 각 AI 소스(①secums-AI, ②script-AI)가 그 정답과 동일하게 판정한 비율(=탐지 정확도).
  // 모수 = 정답지 decisive(취약/양호) AND 해당 소스가 그 항목을 진단함(has). 일치 = 소스 판정 === 정답.
  function accuracyVs(sourceField, hasField) {
    const denomRows = out.filter(x => isDecisive(x.secums_self) && x[hasField]);
    const correct = denomRows.filter(x => x[sourceField] === x.secums_self).length;
    return {
      denom: denomRows.length,
      correct,
      rate: denomRows.length ? Math.round((correct / denomRows.length) * 1000) / 10 : 0,
    };
  }

  const summary = {
    total: out.length,
    comparable: comparable.length,
    agree,
    mismatch,
    no_data: out.filter(x => x.match === 'no_data').length,
    agreement_rate: comparable.length ? Math.round((agree / comparable.length) * 1000) / 10 : 0,
    os,
    // ① secums-AI 정확도, ② script-AI 정확도 (③ 정답지 대비)
    accuracy: {
      answer_total: out.filter(x => isDecisive(x.secums_self)).length, // 정답지 decisive 모수
      secums: accuracyVs('ai_secums', 'has_secums'),
      script: accuracyVs('ai_script', 'has_script'),
    },
  };
  return { rows: out, summary };
}

module.exports = { buildThreeWay, loadCrosswalk };

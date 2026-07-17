'use strict';
/**
 * SecuMS raw XML Dump(<Dump type="table">) 파서 + 결정론 판정기.
 *
 * SecuMS 에이전트가 수집한 raw 는 구조화된 XML 테이블이다:
 *   <Dump type="table"><Columns>...<Column>KEY</Column>...</Columns>
 *   <Rows count="N"><Row><Value>...</Value>...</Row></Rows></Dump>
 *
 * 역할:
 *  1. parseDumps(text)   — 텍스트 안의 모든 Dump 를 {columns, rows} 로 파싱
 *  2. flattenDumps(text) — 룰 재사용을 위한 평문 변환 (단일 컬럼=원본 라인, 다중 컬럼=탭 구분)
 *  3. evaluateGeneric(text) — 컬럼 시그니처 기반 결정론 판정 (파일권한/공유/권한할당/그룹멤버)
 *
 * P1: 입력은 SecuMS raw(수집 데이터)만 사용한다. SecuMS 의 판정(CHECKLIST RESULT)은
 *     판정 로직에 사용하지 않는다 (정합성 비교 시에만 대조).
 */

function decodeEntities(s) {
  return String(s || '')
    .replace(/&#x([0-9a-f]+);/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, d) => String.fromCharCode(parseInt(d, 10)))
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&');
}

function parseDumps(text) {
  const dumps = [];
  const blocks = String(text || '').match(/<Dump type="table">[\s\S]*?<\/Dump>/gi) || [];
  for (const b of blocks) {
    const columns = (b.match(/<Column>([\s\S]*?)<\/Column>/g) || [])
      .map(c => decodeEntities(c.replace(/<\/?Column>/g, '').trim()));
    const rows = [];
    for (const rm of b.match(/<Row[^>]*>[\s\S]*?<\/Row>/g) || []) {
      rows.push((rm.match(/<Value>([\s\S]*?)<\/Value>|<Value\s*\/>/g) || [])
        .map(v => decodeEntities(v.replace(/<Value\s*\/>/, '').replace(/<\/?Value>/g, '').trim())));
    }
    dumps.push({ columns, rows });
  }
  return dumps;
}

// octal 권한 → ls 모드 문자열 (4755 → rwsr-xr-x)
function octalToMode(octStr) {
  const v = parseInt(String(octStr || '').trim(), 8);
  if (isNaN(v)) return null;
  const t = (bits, special, sChar) => {
    let s = (bits & 4 ? 'r' : '-') + (bits & 2 ? 'w' : '-');
    if (special) s += bits & 1 ? sChar : sChar.toUpperCase();
    else s += bits & 1 ? 'x' : '-';
    return s;
  };
  const suid = !!(v & 0o4000), sgid = !!(v & 0o2000), sticky = !!(v & 0o1000);
  return t((v >> 6) & 7, suid, 's') + t((v >> 3) & 7, sgid, 's') + t(v & 7, sticky, 't');
}

// 평문 변환 — 기존 텍스트 기반 SRV 룰 라이브러리(script 출력 전제)가 그대로 매칭되도록
// "스크립트 형식 합성": 권한 테이블 → ls -l 라인, KV 테이블 → KEY=VALUE / KEY VALUE 라인
function flattenDumps(text) {
  const out = [];
  for (const d of parseDumps(text)) {
    if (!d.rows.length) continue;

    if (d.columns.length <= 1) {
      // 단일 컬럼: 파일 내용 라인 그대로 (예: /etc/passwd 행들)
      for (const r of d.rows) out.push(r[0]);
      out.push('');
      continue;
    }

    const fi = colIdx(d, 'FILEPATH'), ui = colIdx(d, 'USERNAME'), pi = colIdx(d, 'PERMISSION');
    if (fi >= 0 && pi >= 0) {
      // 권한 테이블 → ls -l 합성 (lineForPath/groupOrOtherWritable/SUID 룰 재사용)
      for (const r of d.rows) {
        const mode = octalToMode(r[pi]);
        if (mode && r[fi]) out.push(`-${mode}. 1 ${r[ui >= 0 ? ui : 0] || 'root'} ${r[ui >= 0 ? ui : 0] || 'root'} 0 Jan  1 00:00 ${r[fi]}`);
      }
      out.push('');
      continue;
    }

    // KV 계열 (마지막에 VALUE/VALDATA 류 컬럼): NAME=VALUE + NAME VALUE 두 형태로 합성
    const vi = d.columns.findIndex(c => /^(?:VALUE|VALDATA)$/i.test(c));
    const ni = d.columns.findIndex(c => /^(?:NAME|KEY|VALNAME|ARG)$/i.test(c));
    if (vi >= 0 && ni >= 0) {
      for (const r of d.rows) {
        const name = String(r[ni] || '').replace(/^.*[\\,]/, ''); // 경로/섹션 접두 제거
        const val = String(r[vi] || '');
        if (!name) continue;
        out.push(`${name}=${val}`);
        out.push(`${name} ${val}`);
        // PATH 류는 값 단독 라인도 (SRV-121 등 라인 형식 룰)
        if (/^PATH$/i.test(name) && val) out.push(val);
      }
      out.push('');
      continue;
    }

    // 그 외: 탭 구분 (generic 판정기/사람 검토용)
    out.push(d.columns.join('\t'));
    for (const r of d.rows) out.push(r.join('\t'));
    out.push('');
  }
  return out.join('\n');
}

function hasCols(d, names) {
  const cols = d.columns.map(c => c.toUpperCase());
  return names.every(n => cols.includes(n.toUpperCase()));
}
function colIdx(d, name) {
  return d.columns.findIndex(c => c.toUpperCase() === name.toUpperCase());
}

// 파일별 허용 권한(octal) 기준 — 기준보다 낮으면(더 제한적) 양호
const FILE_PERM_BASELINE = [
  { re: /\/etc\/shadow$|\/etc\/security\/passwd$/, max: 0o400 },
  { re: /\/etc\/passwd$|\/etc\/group$|\/etc\/hosts$|\/etc\/services$/, max: 0o644 },
  { re: /\/etc\/(?:r?syslog(?:\.conf)?|syslog\.conf)$/, max: 0o640 },
  { re: /crontab$|cron\.(?:allow|deny)$|at\.(?:allow|deny)$/, max: 0o640 },
  { re: /\.(?:profile|cshrc|bashrc|bash_profile|login|kshrc|netrc|exrc)$/, max: 0o640 },
  { re: /sshd_config$|snmpd\.conf$|named\.conf$|sendmail\.cf$|main\.cf$|vsftpd\.conf$|inetd\.conf$|xinetd\.conf$/, max: 0o640 },
];

function permBits(v) {
  const s = String(v || '').trim();
  if (!/^[0-7]{3,4}$/.test(s)) return null;
  return parseInt(s, 8) & 0o777;
}

/**
 * 컬럼 시그니처 기반 generic 판정.
 * 2-pass: 모든 dump 에서 취약 신호를 먼저 찾고(우선), 없을 때만 양호 신호를 반환한다.
 * (한 항목에 그룹멤버 dump 와 권한 dump 가 함께 있을 때 양호가 취약을 가리는 것 방지)
 * @returns {verdict, reason, evidence} | null (판정 보류)
 */
function evaluateGeneric(text) {
  const dumps = parseDumps(text).filter(d => d.rows.length);
  if (!dumps.length) return null;

  const results = [];
  for (const d of dumps) {
    const r = evaluateOneDump(d);
    if (r) results.push(r);
  }
  return results.find(r => r.verdict === '취약') || results.find(r => r.verdict === '양호') || null;
}

function evaluateOneDump(d) {
  {
    // ── 파일 권한 (FILEPATH / USERNAME / PERMISSION, octal) ──
    if (hasCols(d, ['FILEPATH', 'PERMISSION'])) {
      const fi = colIdx(d, 'FILEPATH'), ui = colIdx(d, 'USERNAME'), pi = colIdx(d, 'PERMISSION');
      const judged = [];
      for (const r of d.rows) {
        const file = r[fi] || '', owner = ui >= 0 ? r[ui] : '', perm = permBits(r[pi]);
        if (perm === null) continue; // 값 미수집 — 판정 근거로 쓰지 않음
        // wtmp/utmp 계열은 배포본 표준이 664(utmp 그룹 쓰기) — group 쓰기 예외
        const groupWriteStandard = /\/(?:wtmp|btmp|utmp|lastlog)$/.test(file);
        // group/other 쓰기는 파일 종류와 무관하게 취약 (표준 예외 제외)
        if ((perm & 0o002) || (!groupWriteStandard && (perm & 0o020))) {
          return { verdict: '취약', reason: `${file} 이 group/other 쓰기 가능(${r[pi]})`, evidence: `${file} ${owner} ${r[pi]}` };
        }
        const base = FILE_PERM_BASELINE.find(b => b.re.test(file));
        if (base) {
          if (perm > base.max) {
            return { verdict: '취약', reason: `${file} 권한(${r[pi]})이 기준(${base.max.toString(8)})을 초과`, evidence: `${file} ${owner} ${r[pi]}` };
          }
          if (owner && owner !== 'root' && !/^bin$|^sys$/.test(owner) && /^\/etc\//.test(file)) {
            return { verdict: '취약', reason: `${file} 소유자가 root 가 아님(${owner})`, evidence: `${file} ${owner} ${r[pi]}` };
          }
        }
        judged.push(`${file}=${r[pi]}`);
      }
      // 권한 값이 하나 이상 파싱됐고 위반이 없으면 양호 (기준표에 없는 파일도 g/o 쓰기 검사는 통과한 상태)
      if (judged.length) {
        return { verdict: '양호', reason: `점검 파일 권한이 기준 이내(과다 권한 없음)`, evidence: judged.slice(0, 5).join(' | ') };
      }
    }

    // ── 그룹 정의 (GROUPNAME / GID [/ USERNAME]) — 중복 GID + 관리자 그룹 구성원 ──
    if (hasCols(d, ['GROUPNAME', 'GID'])) {
      const gi2 = colIdx(d, 'GROUPNAME'), gidI = colIdx(d, 'GID'), un = colIdx(d, 'USERNAME');
      const seen = new Map();
      for (const r of d.rows) {
        const gid = String(r[gidI] || '');
        if (!/^\d+$/.test(gid)) continue;
        if (seen.has(gid)) {
          return { verdict: '취약', reason: `중복 GID ${gid} (${seen.get(gid)}, ${r[gi2]})`, evidence: `${seen.get(gid)}:${gid} / ${r[gi2]}:${gid}` };
        }
        seen.set(gid, r[gi2]);
      }
      if (un >= 0) {
        const adminExtra = d.rows.find(r => /^(root|wheel)$/i.test(r[gi2] || '') && r[un] && !/^root$/i.test(r[un]));
        if (adminExtra) {
          return { verdict: '취약', reason: `관리자 그룹(${adminExtra[gi2]})에 추가 구성원 존재(${adminExtra[un]})`, evidence: adminExtra.join(':') };
        }
        if (d.rows.length >= 5) {
          return { verdict: '양호', reason: '중복 GID 없음, root/wheel 그룹에 추가 구성원 없음', evidence: `그룹 ${d.rows.length}개 검사` };
        }
      }
    }

    // ── 공유 (NAME / PATH / STATUS) ──
    if (hasCols(d, ['NAME', 'STATUS']) && hasCols(d, ['PATH'])) {
      const ni = colIdx(d, 'NAME');
      const admin = d.rows.filter(r => /^[A-Z]\$$|^ADMIN\$$/i.test(r[ni] || ''));
      if (admin.length) {
        return { verdict: '취약', reason: `기본 관리 공유가 활성 상태(${admin.map(r => r[ni]).join(', ')})`, evidence: admin.map(r => r.join(' ')).slice(0, 4).join(' | ') };
      }
      if (d.rows.every(r => (r[ni] || '') === 'IPC$')) {
        return { verdict: '양호', reason: '기본 관리 공유(C$/ADMIN$) 없음(IPC$는 비활성 불가 표준)', evidence: d.rows.map(r => r[ni]).join(', ') };
      }
    }

    // ── 권한 할당 (ARG / VALUE(SID문자열) / SID / EXIST) ──
    if (hasCols(d, ['ARG', 'SID', 'EXIST'])) {
      const ai = colIdx(d, 'ARG'), si = colIdx(d, 'SID');
      const rowStr = r => r.join(' ');
      const bad = d.rows.find(r => /(?:^|[^0-9])(?:545|546|551)\b|S-1-1-0|Everyone|Guests/i.test(rowStr(r)));
      if (bad) {
        return { verdict: '취약', reason: `${bad[ai]} 권한이 광범위 그룹(Everyone/Users/Guests/Backup Operators)에 부여됨`, evidence: bad.join(' ') };
      }
      const allAdmin = d.rows.length && d.rows.every(r => /544|-500\b|S-1-5-1[89]|S-1-5-20/.test(rowStr(r)));
      if (allAdmin) {
        return { verdict: '양호', reason: `권한 할당이 Administrators/시스템 계정으로 제한됨`, evidence: d.rows.map(r => `${r[ai]}=${r[si]}`).slice(0, 4).join(' | ') };
      }
    }

    // ── 파일 ACL (ACCOUNT_IDENT / PERMISSION_VALUE — W_*_CONF_PERM 계열) ──
    if (hasCols(d, ['ACCOUNT_IDENT', 'PERMISSION_VALUE'])) {
      const ii = colIdx(d, 'ACCOUNT_IDENT');
      const bad = d.rows.find(r => /S-1-1-0|-545$|-546$|Everyone|BUILTIN\\Users|ALL APPLICATION|모든 제한된/i.test(r.join(' ')));
      if (bad) {
        return { verdict: '취약', reason: '중요 파일 ACL에 광범위 계정 권한 존재', evidence: bad.join(' ') };
      }
      const allPriv = d.rows.length && d.rows.every(r => /S-1-5-18|S-1-5-32-544|S-1-5-19|S-1-5-20|TrustedInstaller|CREATOR OWNER/i.test(r.join(' ')));
      if (allPriv) {
        return { verdict: '양호', reason: '중요 파일 ACL이 SYSTEM/Administrators 등 관리 주체로 제한됨', evidence: d.rows.map(r => r.join(':')).slice(0, 4).join(' | ') };
      }
    }

    // ── 그룹 구성원 (GROUP / USER ACCOUNT) ──
    if (hasCols(d, ['GROUP', 'USER ACCOUNT'])) {
      const gi = colIdx(d, 'GROUP'), uix = colIdx(d, 'USER ACCOUNT');
      const STANDARD = {
        'administrators': /^(administrator|domain admins)$/i,
        'guests': /^guest$/i,
        'iis_iusrs': /^iusr/i,
        'users': /^(?:INTERACTIVE|Authenticated Users|Domain Users|NT AUTHORITY)/i,
        'remote desktop users': /.*/,
        'system managed accounts group': /^DefaultAccount$/i,
        // 서비스 계정이 성능/DCOM 그룹에 있는 것은 표준 구성 (MSSQL 등)
        'performance log users': /^(?:MSSQL|SQL|NT )/i,
        'performance monitor users': /^(?:MSSQL|SQL|NT )/i,
        'certificate service dcom access': /.*/,
        'distributed com users': /^(?:MSSQL|SQL|NT )/i,
      };
      let nonStandard = null;
      for (const r of d.rows) {
        const g = String(r[gi] || '').toLowerCase(), u = String(r[uix] || '');
        // 제품 자체 생성 그룹(SQLServer... 등 $호스트 접미)에 서비스 계정이 있는 것은 표준
        if (/^SQLServer|.\$[\w-]+$/i.test(String(r[gi] || ''))) continue;
        const rule = STANDARD[g];
        if (!rule) { nonStandard = r; break; }
        if (!rule.test(u)) { nonStandard = r; break; }
      }
      if (!nonStandard && d.rows.length) {
        return { verdict: '양호', reason: '그룹 구성원이 OS 표준 기본 계정 구성', evidence: d.rows.map(r => `${r[gi]}:${r[uix]}`).slice(0, 6).join(' | ') };
      }
      // 비표준 구성원은 정당성 판단이 필요하므로 판정 보류(null) — LLM/사람 검토
    }
  }
  return null;
}

// secedit/registry KV 조회 — 컬럼 인식: KEY/VALNAME(또는 ARG 경로 접미) 매칭 → VALUE/VALDATA 반환.
// EXIST=NO 는 "키 없음(미설정)" 이므로 '' 반환. 'No Info' 값도 미설정('')으로 정규화.
// 키는 "System Access,PasswordComplexity"(섹션 병합), "HKLM\...\키"(경로 병합) 형태 허용.
function dumpKV(text, key) {
  const esc = key.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const keyRe = new RegExp('(?:^|[\\\\,])' + esc + '$', 'i');
  for (const d of parseDumps(text)) {
    const nameIdx = d.columns.findIndex(c => /^(?:KEY|VALNAME)$/i.test(c));
    const valIdx = d.columns.findIndex(c => /^(?:VALUE|VALDATA)$/i.test(c));
    const argIdx = d.columns.findIndex(c => /^ARG$/i.test(c));
    const existIdx = d.columns.findIndex(c => /^EXIST$/i.test(c));
    if (valIdx === -1) continue;
    for (const r of d.rows) {
      const names = [nameIdx >= 0 ? r[nameIdx] : '', argIdx >= 0 ? r[argIdx] : ''];
      if (!names.some(n => keyRe.test(String(n || '')))) continue;
      if (existIdx >= 0 && /^NO$/i.test(String(r[existIdx] || ''))) return '';
      const v = String(r[valIdx] || '').trim();
      return /^no info$/i.test(v) ? '' : v;
    }
  }
  // 폴백: 인접 <Value> 방식 (컬럼 구조가 없는 dump)
  const re = new RegExp('<Value>(?:[^<]*[,\\\\])?' + esc + '</Value>\\s*<Value\\s*/?>?([^<]*)', 'i');
  const m = String(text || '').match(re);
  if (!m) return null;
  const v = (m[1] || '').trim();
  return /^no info$/i.test(v) ? '' : v;
}

// secedit 계열 dump 가 존재하는지 (키 부재 = 미설정 판정의 전제)
function hasSeceditDump(text) {
  return /System Access|Event Audit|<Column>SECTION<\/Column>/i.test(String(text || ''));
}

function dumpKVInt(text, key) {
  const v = dumpKV(text, key);
  if (v === null || v === '' || !/^-?\d+$/.test(v)) return null;
  return parseInt(v, 10);
}

module.exports = { parseDumps, flattenDumps, evaluateGeneric, dumpKV, dumpKVInt, hasSeceditDump };

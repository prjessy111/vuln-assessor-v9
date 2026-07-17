// 다국어(i18n) — 자체 구현 로더 + t() + Express 미들웨어
// 키: '파일명.중첩.키' (locales/<lang>/<ns>.json 플랫화), 폴백: 요청언어 → ko → 키 그대로
const fs = require('fs');
const path = require('path');

const LANGS = ['ko', 'en', 'ja', 'zh'];
const LANG_LABELS = { ko: '한국어', en: '영어', ja: '일본어', zh: '중국어' };
const LOCALE_DIR = path.join(__dirname, 'locales');

const dicts = {}; // lang -> { 'ns.a.b': 'text' }

function flatten(obj, prefix, out) {
  for (const k of Object.keys(obj)) {
    const v = obj[k];
    const key = prefix ? prefix + '.' + k : k;
    if (v && typeof v === 'object' && !Array.isArray(v)) flatten(v, key, out);
    else out[key] = String(v);
  }
}

function loadAll() {
  for (const lang of LANGS) {
    const dir = path.join(LOCALE_DIR, lang);
    const dict = {};
    if (fs.existsSync(dir)) {
      for (const f of fs.readdirSync(dir)) {
        if (!f.endsWith('.json')) continue;
        try {
          flatten(JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8')), path.basename(f, '.json'), dict);
        } catch (e) {
          console.error(`[i18n] ${lang}/${f} 파싱 실패: ${e.message}`);
        }
      }
    }
    dicts[lang] = dict;
  }
  console.log('[i18n] 로드 완료: ' + LANGS.map(l => `${l}=${Object.keys(dicts[l]).length}키`).join(', '));
}

function translate(lang, key, params) {
  let s = dicts[lang] && dicts[lang][key];
  if (s === undefined && lang !== 'ko') s = dicts.ko && dicts.ko[key];
  if (s === undefined) return key;
  if (params) {
    for (const p of Object.keys(params)) s = s.split('{' + p + '}').join(params[p]);
  }
  return s;
}

function detectLang(req) {
  const q = req.query && req.query.lang;
  if (q && LANGS.includes(q)) return { lang: q, save: true };
  const m = /(?:^|;\s*)lang=([a-z]{2})/.exec(req.headers.cookie || '');
  if (m && LANGS.includes(m[1])) return { lang: m[1] };
  const al = String(req.headers['accept-language'] || '').toLowerCase();
  for (const l of LANGS) if (al.startsWith(l)) return { lang: l };
  return { lang: 'ko' };
}

function middleware(req, res, next) {
  const { lang, save } = detectLang(req);
  if (save) res.append('Set-Cookie', `lang=${lang}; Path=/; Max-Age=31536000; SameSite=Lax`);
  req.lang = lang;
  res.locals.lang = lang;
  res.locals.langs = LANGS;
  res.locals.langLabels = LANG_LABELS;
  res.locals.t = (key, params) => translate(lang, key, params);
  // 데이터 용어 변환 — DB에 한국어로 저장된 값(양호/취약/진행중 등)을 표시 시점에 치환
  res.locals.td = (term) => {
    if (term === null || term === undefined) return term;
    const s = dicts[lang] && dicts[lang]['_data.' + term];
    return s === undefined ? term : s;
  };
  next();
}

loadAll();

module.exports = { middleware, translate, loadAll, LANGS, LANG_LABELS };

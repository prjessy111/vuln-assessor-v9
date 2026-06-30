'use strict';
/**
 * SBOM 파서 — CycloneDX / SPDX (JSON) → {name, version} 컴포넌트 목록.
 *
 * 파일명/strings 휴리스틱보다 정확한 컴포넌트 식별:
 *   - purl(package URL: pkg:type/ns/name@version)에서 정규 이름·버전 추출
 *   - CycloneDX: components[].{name,version,purl}
 *   - SPDX:      packages[].{name,versionInfo,externalRefs[].referenceLocator(purl)}
 *
 * 호스트에 SBOM 파일(예: bom.json, *.cdx.json, *.spdx.json)이 있거나
 * 빌드 산출물에 포함된 경우 수집 → 정확 매칭.
 */

function _fromPurl(purl) {
  // pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1?type=jar
  const m = String(purl || '').match(/^pkg:([^/]+)\/(?:([^/@]+)\/)?([^@?]+)@([^?#]+)/i);
  if (!m) return null;
  return { ecosystem: m[1].toLowerCase(), name: decodeURIComponent(m[3]).toLowerCase(), version: decodeURIComponent(m[4]) };
}

function parseSbom(text) {
  let j;
  try { j = JSON.parse(text); } catch (_) { return []; }
  const out = [];
  const seen = new Set();
  const push = (name, version, eco) => {
    name = String(name || '').toLowerCase().trim();
    version = String(version || '').trim();
    if (!name || !version) return;
    const k = name + '@' + version;
    if (seen.has(k)) return;
    seen.add(k);
    out.push({ name, version, ecosystem: eco || '', publisher: '(SBOM)' });
  };

  // CycloneDX
  if (Array.isArray(j.components)) {
    for (const c of j.components) {
      const p = c.purl && _fromPurl(c.purl);
      if (p) push(p.name, p.version, p.ecosystem);
      else push(c.name, c.version);
    }
  }
  // SPDX
  if (Array.isArray(j.packages)) {
    for (const pk of j.packages) {
      const ref = (pk.externalRefs || []).find(r => /purl/i.test(r.referenceType || '') || /pkg:/.test(r.referenceLocator || ''));
      const p = ref && _fromPurl(ref.referenceLocator);
      if (p) push(p.name, p.version, p.ecosystem);
      else push(pk.name, pk.versionInfo);
    }
  }
  return out;
}

/**
 * 스크립트 XML 의 INV-SBOM 섹션(수집된 SBOM 파일 내용)에서 컴포넌트 추출.
 * 여러 SBOM 이 이어붙어 있을 수 있어 JSON 블록 단위로 시도.
 */
function extractSbomFromScriptXml(xmlText) {
  const txt = String(xmlText || '');
  const m = txt.match(/check_ids=INV-SBOM[\s\S]*?RAW_COMMAND_OUTPUT_BEGIN([\s\S]*?)RAW_COMMAND_OUTPUT_END/i);
  if (!m) return [];
  const body = m[1];
  // 본문에서 {…} JSON 객체들을 추출 시도 (CycloneDX/SPDX)
  const out = [];
  const seen = new Set();
  // 전체를 한 번 시도
  let comps = parseSbom(body);
  // 실패 시 줄별 {…} 블록 (간이)
  if (!comps.length) {
    const blocks = body.match(/\{[\s\S]*\}/g) || [];
    for (const b of blocks) comps = comps.concat(parseSbom(b));
  }
  for (const c of comps) {
    const k = c.name + '@' + c.version;
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(c);
  }
  return out;
}

module.exports = { parseSbom, extractSbomFromScriptXml };

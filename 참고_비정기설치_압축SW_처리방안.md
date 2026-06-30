# 참고 — 비정기(압축형) 소프트웨어 + SBOM 처리 방안

패키지매니저(rpm/dpkg/레지스트리)에 등록되지 않는 SW를 어떻게 잡는가. (tar/zip 수동 설치, 번들 라이브러리 등)

---

## 핵심 문제
SecuMS·일반 점검도구는 **패키지매니저 등록분만** 봄 → tar/zip 풀어서 설치한 것, 제품에 번들된 라이브러리는 **누락**. ADV는 **파일시스템 스캔**으로 이를 보완.

## 처리 방안 (3계층)

### Tier 1 — 이미 압축 푼 것 (가장 흔함) ✅ 자동 처리
tar/zip을 풀어 `/opt`·`/usr/local`·`C:\app` 등에 설치 → 파일이 디스크에 존재.
- **JAR**: `INV-JAR` (`find *.jar` / `Get-ChildItem *.jar`) → name/version
- **네이티브 .so/.dll**: `INV-NATIVELIB` (strings로 OpenSSL/zlib/expat/sqlite/pcre 버전)
- → 매처가 NVD/큐레이션 CVE와 매칭. **별도 조치 불필요.**

### Tier 2 — SBOM 있으면 (가장 정확) ✅ 자동 처리
빌드 산출물에 CycloneDX/SPDX SBOM이 있으면 purl로 정확 식별.
- 수집: `INV-SBOM` (bom.json / *.cdx.json / *.spdx.json 수집)
- 파싱: `src/cve/sbomParser.js` (CycloneDX components / SPDX packages, purl)
- → Windows·Linux 둘 다 처리 (2026-06-30 대칭화 완료)

### Tier 3 — 미해제 아카이브 + 임의 바이너리 ⚠ 가시화 + 향후
- **미해제 아카이브**(war/ear/zip/tar.gz): `INV-ARCHIVE`로 **목록화**(가시화). WAR/EAR는 내부 JAR 보유 → 배포(해제) 시 Tier 1로 잡힘. 미해제분은 "내부 컴포넌트 수동 확인 필요"로 표기.
- **임의 컴파일 바이너리**(예: 직접 빌드한 nginx): 파일명·strings에 버전 없으면 미탐 → **향후 `<bin> --version` 범용 프로브** 추가 후보.

## 수집 항목 요약 (스크립트)
| 항목 | OS | 대상 |
|---|---|---|
| INV-SOFTWARE | Win | 레지스트리 설치 프로그램 |
| rpm -qa / dpkg -l | Linux | OS 패키지 |
| INV-JAR / jar_inventory | 둘 다 | *.jar |
| INV-NATIVELIB | Win(+Linux strings) | OSS .dll/.so 버전 |
| INV-SBOM | 둘 다 | CycloneDX/SPDX |
| INV-ARCHIVE | 둘 다 | war/ear/zip/tar.gz 목록 |

## 정직한 한계
- 미해제 아카이브 내부는 **목록만**(추출은 대상 부하 커서 기본 미실행). WAR/EAR 배포본은 Tier1이 커버.
- 완전 정적링크 + 버전문자열 제거 바이너리는 탐지 불가 (SBOM 없으면 한계).
- 범위(스캔 경로)는 일반 앱 경로로 한정 — 전체 디스크는 -Full에서도 부담.

## 결론
**tar/zip 비정기 설치 = 풀린 순간 파일시스템 스캔(JAR/네이티브)이 잡음** → 패키지매니저 한계를 ADV가 메움. SBOM 있으면 정확도 최상. 미해제/임의바이너리는 가시화 후 수동/향후 처리.

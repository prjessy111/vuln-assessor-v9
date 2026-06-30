# 참고 — 설치 소프트웨어(자산) 수집 명령 (CVE 매칭 입력)

CVE 진단의 "설치 SW" 인벤토리를 어떤 명령으로 모으는지 정리. (rpm -qa의 OS별 대응)

---

## Windows — 레지스트리 Uninstall 키

`scripts/ai-ready/fsi_win_ai.ps1` 의 **`INV-SOFTWARE`** 항목:

```powershell
$invPaths = @(
  'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
  'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
)
Get-ItemProperty $invPaths -ErrorAction SilentlyContinue |
  Where-Object { $_.DisplayName } |
  ForEach-Object { $_.DisplayName + ' | ' + $_.DisplayVersion + ' | ' + $_.Publisher } |
  Sort-Object -Unique
```

- 출력: `소프트웨어명 | 버전 | 게시자` (예: `Azure Data Studio | 1.37.0 | Microsoft Corporation`)
- 32/64비트 둘 다 열거 (Uninstall + WOW6432Node\Uninstall)
- 파서: `src/cve/winScanner.js` `extractWindowsSoftwareFromScriptXml` → `{name, version, publisher}`

### 원격 단독 테스트 (내 PC 관리자 PowerShell)
```powershell
$cred = Get-Credential
Invoke-Command -ComputerName 192.168.159.107 -Credential $cred -ScriptBlock {
  $p = @('HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*')
  Get-ItemProperty $p -EA SilentlyContinue | ? DisplayName |
    Select DisplayName, DisplayVersion, Publisher | Sort DisplayName
}
```

### 왜 이 방식인가
| 방식 | 채택 | 이유 |
|---|---|---|
| 레지스트리 Uninstall | ✅ | 빠르고 안전, 32/64비트 모두 |
| `Win32_Product` (wmic product) | ❌ | 느림 + **MSI 자동복구 트리거(위험)** |
| `Get-Package` | △ | PS5+ 필요, 일부 누락 |

> ⚠️ SecuMS **Windows DB에는 설치 SW 테이블이 없음** → 설치 SW CVE는 **반드시 script(INV-SOFTWARE) 경로**로만 가능. (SecuMS Windows DB로는 OS 핫픽스 CVE만)

---

## Linux (CentOS/RHEL) — rpm

`scripts/ai-ready/fsi_unix_ai.sh` `CMD_PATCHINFO="rpm -qa -i"` → patch 덤프에 출력.
- 파서: `src/cve/scanner.js` `extractPackagesFromRpmInfoText` (Name/Version/Release/Architecture)
- 단독 확인: `rpm -qa -i`

---

## Linux (Ubuntu/Debian) — dpkg

`fsi_unix_ai.sh` patch 덤프에서 rpm 외 추가 수집 (2026-06-29 추가):
```sh
dpkg-query -W -f='ii  ${Package}  ${Version}  ${Architecture}  ${binary:Summary}\n'
```
- 마커 `$ dpkg -l` 로 출력
- 파서: `src/cve/scanner.js` `extractPackagesFromDpkgText` + `DEB_NAME_ALIAS`(libssl1.1→openssl, zlib1g→zlib, libexpat1→expat, libpcre3→pcre 등)
- 단독 확인: `dpkg -l` 또는 `dpkg-query -W`

---

## Windows 수집 방식 세대별 변천 (참고)

| 세대 | 시기 | 방식 | 설치 SW 목록 |
|---|---|---|---|
| **bat + vbs** | ~2026-05-31 | `REG QUERY`(레지스트리 직접) + `WMIC`(OS/날짜) + `cscript *.vbs`(WMI=`GetObject winmgmts`, IIS/FTP용) | ❌ 없음 (특정 보안 레지스트리 키만 점검) |
| **PowerShell 초기** | 2026-06-06 | `Write-FsiItem`/`Invoke-FsiMaybeSlowItem`, `Get-HotFix`(=WMI qfe) | ❌ 없음 (핫픽스만) |
| **현재** | 2026-06 후반 | PowerShell + **INV-SOFTWARE = 레지스트리 Uninstall 전체 열거** | ✅ 있음 → SW CVE 가능 |

- WMI `Win32_Product`는 **어느 세대도 안 씀** — 느리고 MSI 자동복구 트리거(위험)라 의도적 회피.
- 설치 SW 전체 인벤토리는 **현재 세대에서 신규 추가**. (이전엔 컴플라이언스 점검 위주 = SecuMS 성격)
- 옛 bat/vbs 방식은 현재 부적합(VBScript 사양길) — 레지스트리 Uninstall 열거가 표준.

## full vs fast 수집 모드 (중요)

- **기본 = full** (`scheduler.js`: `SCHEDULER_SCRIPT_MODE || 'full'` → `-Full`). 의도적: fast면 systeminfo/hotfix/인벤토리가 SKIPPED → 판정불가(N/A) 양산.
- **full (`-Full` / `--full`)**: 무거운 인벤토리 다 수집 — systeminfo, Get-HotFix, INV-SOFTWARE(Win), rpm/dpkg(Linux). **CVE에 필요. 느림.**
- **fast (`-Fast` / `--fast`)**: 고지연 인벤토리 명령 SKIPPED_FOR_SPEED. 빠르지만 **핫픽스·패키지 목록이 비어 CVE 판정 불가.**
- 결론: **정확한 진단/CVE = full 필수.** 속도가 급하면 fast지만 CVE는 포기.

### 속도 개선 (2026-06-30, 우리 스크립트만)
- 우리 `fsi_unix_ai.sh`: `rpm -qa -i`(패키지마다 상세, 느림) → **`rpm -qa`(NVRA 한 줄, 경량)** 로 변경. 매칭 정확도 동일(이름+버전+릴리스 다 있음).
- `scanner.js`: `-i` 블록 파서 + **NVRA 파서**(`extractPackagesFromRpmQaText`, `secumsUnix.parseRpmPackage` 재사용) 둘 다 지원. 기존 `-i` XML도 계속 처리.
- **SecuMS raw는 손 안 댐** — SecuMS가 점검 때 만드는 산출물(우리가 못 건드림). 이미 `rpm -qa`(경량). Windows 인벤토리는 systeminfo가 느림(불가피).

## 점검 vs 진단 (용어)

- **점검(inspection/check)**: 체크리스트·기준 대비 확인 ("X를 올바로 설정했나?", 컴플라이언스). SecuMS 성격.
- **진단(diagnosis)**: 분석·해석으로 취약 여부/심각도 판단 ("무엇이 취약하고 얼마나 위험한가"). 우리 AI 성격.
- **이 앱에서는** 둘이 같은 흐름(서버 분석 실행)이라 차이가 작음 → UI 용어를 **"진단"으로 통일**(2026-06-30): 점검현황→진단 현황, 서버별 점검 이력→서버별 진단 이력. 단 **SecuMS 제품 자체 점검**을 가리키는 "미점검/점검 미수행"은 유지.

## 공통 사항

- **수집 시점**: 인벤토리는 무거워서 **fast 모드에서 SKIPPED**. 반드시 **-Full**(`FSI_ENABLE_PATCHINFO=1`)로 수집해야 SW 목록이 XML에 담김.
- **매칭**: 수집된 `{name, version}` × `data/cve/cve-software-curated.json`(+centos-curated) → `src/cve/matcher.js` / `winScanner.matchWindowsSoftware`.
- **자동갱신**: `scripts/sync-cve.js`(NVD+CISA KEV), 앱 내장 일일 스케줄 `startCveAutoSync()`.

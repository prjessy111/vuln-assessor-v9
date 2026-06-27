# Windows AI-ready scripts

Windows 점검은 이제 단일 PowerShell 파일 방식을 기본 권장합니다.

- 권장 파일: `../fsi_win_ai.ps1`
- 실행 결과: 스크립트 실행 폴더에 `hostname-s-YYYYMMDD.xml` 생성
- 호환 결과: 같은 폴더에 `fsi_result_win.xml`도 함께 생성
- 판단 방식: 스크립트는 raw evidence만 생성하고, 취약/양호/정보제공/판정불가는 AI/LLM이 판정합니다.

## Legacy BAT/VBS package

이 폴더의 `fsi_win_ai.bat`, `vbscripts/`, `fsi_win_ai_package.zip`는 기존 BAT/VBS 배포 호환용입니다. 신규 Windows 배포/실행 테스트는 `scripts/ai-ready/fsi_win_ai.ps1` 단일 파일로 진행해 주세요.

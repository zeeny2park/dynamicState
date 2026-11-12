# 2026-11-12 진단 보고서 (과거 기록)

> **이 디렉터리는 과거 기록입니다. 현재 상태를 설명하지 않습니다.**

2026-11-12에 저장소(`f842448` 시점)를 정적으로 진단한 결과입니다. 여기서 정의한 개선 항목 IMP-001~IMP-023은 모두 처리되어 `main`에 병합됐고, 커밋 메시지와 테스트가 이 번호로 이 문서를 가리킵니다.

## 읽을 때 주의

- **결론은 당시 기준입니다.** "버퍼가 어떤 변수의 것인지 답할 수 없다", "검증된 요구사항 0개", "CI 미가동" 같은 서술은 더 이상 사실이 아닙니다.
- **근거 위치(`파일:줄`)는 당시 코드 기준입니다.** 이후 리팩터링(IMP-017, `extractor/watch_session.py` → `extractor/inspection/*`)으로 대부분의 줄 번호와 일부 파일 경로가 바뀌었습니다.
- **출력 위치 메모**의 Windows 경로(`C:\task\...`)는 진단을 수행한 환경의 것입니다.

## 현재 상태는 여기서

| 알고 싶은 것 | 위치 |
|---|---|
| 테스트 기준선과 남은 결함 표시 | `docs/TEST_BASELINE.md`, `docs/test_baseline/` |
| 실제 진단 정확도 (정답표 벤치마크) | `benchmarks/diagnosis_accuracy/README.md`, `results/` |
| 정상 판정 규칙 | `docs/HEALTHY_VERDICT.md` |
| 임베디드 타깃 검증 | `docs/EMBEDDED_TARGET_MATRIX.md` |
| 사용법 | 저장소 루트 `README.md`, `skills/diagnose-process/SKILL.md` |

## 파일

- `EXECUTIVE_SUMMARY.md` — 당시 결론 요약 (여기부터)
- `IMPROVEMENT_ROADMAP.md` — IMP-001~IMP-023 정의 (문제, 근거, 해결 방안, 완료 기준)
- `FUNCTIONAL_GAP_ANALYSIS.md`, `BLINDSPOT_AND_RISK_REPORT.md`, `ARCHITECTURE_AUDIT.md`, `REQUIREMENT_TRACEABILITY.md`, `PROJECT_OVERVIEW.md` — 발견 사항 33건의 근거
- `_inventory/`, `_integrity/`, `diagnostic_state.json` — 진단 도구의 중간 산출물

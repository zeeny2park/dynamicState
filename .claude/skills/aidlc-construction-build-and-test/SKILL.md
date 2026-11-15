---
name: aidlc-construction-build-and-test
description: AI-DLC 🟢 CONSTRUCTION 13. Build and Test (빌드 · 테스트) stage 를 1.0 규칙대로 진행. 인자 없이 = 이 stage 로 이동 (workflow 진행 위치 변경), --single = 이 stage 만 실행하고 진행 위치 유지. 사용자가 /aidlc-construction-build-and-test 로 직접 호출할 때만 사용.
argument-hint: "[--single]"
disable-model-invocation: true
---

# /aidlc-construction-build-and-test

<!-- 생성 파일: dev/tools/gen_aidlc_stage_skills.py 의 STAGES 를 고친 뒤 다시 생성 -->

| 항목 | 값 |
| --- | --- |
| stage | 🟢 CONSTRUCTION 13. Build and Test (빌드 · 테스트) |
| 상태 표기 | Build and Test |
| 규칙 파일 | `.aidlc-rule-details/construction/build-and-test.md` |
| 실행 조건 | ALWAYS |
| unit | - (전체 unit 대상) |
| 필요한 앞 산출물 | 모든 EXECUTE unit 의 `construction/{unit}/code/` |
| 참고 | 실제 소스 · 테스트 파일 |
| 만드는 산출물 | `construction/build-and-test/` |

- 인자: `$ARGUMENTS` (`--single` 포함 = 단독 실행, 없음 = 이동)
- 경로는 `aidlc-docs/` 기준, `{unit}` = unit 이름
- 진행: `.claude/skills/aidlc/stage-runner.md` 를 읽고 위 표 값으로 그 절차대로 진행
- 같은 이동 · 단독 실행을 `/aidlc bt` 로도 호출 가능

## 커버리지 확인 (이 stage 에 포함)

- 시점: 테스트 실행 단계에서 함께 실행 (hook 자동 실행에 기대지 않음)
- 명령 · 기준: 프로젝트 `AGENTS.md` → `construction/{unit}/nfr-requirements/` 순서로 찾은 값 (대상 · 최소 %)
  - 둘 다 없으면 지어내지 말고 사용자에게 질문 (기준 없음으로 진행할지 포함)
- 기준 미만 · 테스트 실패: stage 완료 메시지를 내지 않고 실패 테스트 · Missing 줄을 보고 → 보강 방법은 사용자 결정
- 기록: `construction/build-and-test/build-and-test-summary.md` 에 실행 명령 · TOTAL % · 기준 · Missing 요약

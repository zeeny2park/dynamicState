---
name: aidlc-operations-deployment-execution
description: AI-DLC 🟡 OPERATIONS 16. Deployment Execution (배포 실행) stage 를 1.0 규칙대로 진행. 인자 없이 = 이 stage 로 이동 (workflow 진행 위치 변경), --single = 이 stage 만 실행하고 진행 위치 유지. 사용자가 /aidlc-operations-deployment-execution 로 직접 호출할 때만 사용.
argument-hint: "[--single]"
disable-model-invocation: true
---

# /aidlc-operations-deployment-execution

<!-- 생성 파일: dev/tools/gen_aidlc_stage_skills.py 의 STAGES 를 고친 뒤 다시 생성 -->

| 항목 | 값 |
| --- | --- |
| stage | 🟡 OPERATIONS 16. Deployment Execution (배포 실행) |
| 상태 표기 | Deployment Execution |
| 규칙 파일 | `.aidlc-rule-details/operations/deployment-execution.md` + `operations/operations.md` (공통 안전 규칙) |
| 실행 조건 | CONDITIONAL |
| unit | - |
| 필요한 앞 산출물 | `construction/build-and-test/`, `operations/deployment-pipeline/` · `operations/environment-provisioning/` (또는 SKIP 기록) |
| 참고 | - |
| 만드는 산출물 | `operations/deployment-execution/`, `operations/plans/deployment-execution-plan.md` |

- 인자: `$ARGUMENTS` (`--single` 포함 = 단독 실행, 없음 = 이동)
- 경로는 `aidlc-docs/` 기준, `{unit}` = unit 이름
- 진행: `.claude/skills/aidlc/stage-runner.md` 를 읽고 위 표 값으로 그 절차대로 진행
- 같은 이동 · 단독 실행을 `/aidlc deploy` 로도 호출 가능

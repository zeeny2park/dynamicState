---
name: aidlc-operations-environment-provisioning
description: AI-DLC 🟡 OPERATIONS 15. Environment Provisioning (환경 준비) stage 를 1.0 규칙대로 진행. 인자 없이 = 이 stage 로 이동 (workflow 진행 위치 변경), --single = 이 stage 만 실행하고 진행 위치 유지. 사용자가 /aidlc-operations-environment-provisioning 로 직접 호출할 때만 사용.
argument-hint: "[--single]"
disable-model-invocation: true
---

# /aidlc-operations-environment-provisioning

<!-- 생성 파일: dev/tools/gen_aidlc_stage_skills.py 의 STAGES 를 고친 뒤 다시 생성 -->

| 항목 | 값 |
| --- | --- |
| stage | 🟡 OPERATIONS 15. Environment Provisioning (환경 준비) |
| 상태 표기 | Environment Provisioning |
| 규칙 파일 | `.aidlc-rule-details/operations/environment-provisioning.md` + `operations/operations.md` (공통 안전 규칙) |
| 실행 조건 | CONDITIONAL |
| unit | - |
| 필요한 앞 산출물 | `operations/deployment-pipeline/` 또는 SKIP 기록 |
| 참고 | `infrastructure-design/`, `nfr-requirements/` |
| 만드는 산출물 | `operations/environment-provisioning/`, `operations/plans/environment-provisioning-plan.md` |

- 인자: `$ARGUMENTS` (`--single` 포함 = 단독 실행, 없음 = 이동)
- 경로는 `aidlc-docs/` 기준, `{unit}` = unit 이름
- 진행: `.claude/skills/aidlc/stage-runner.md` 를 읽고 위 표 값으로 그 절차대로 진행
- 같은 이동 · 단독 실행을 `/aidlc env` 로도 호출 가능

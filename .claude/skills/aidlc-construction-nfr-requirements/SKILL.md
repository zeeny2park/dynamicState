---
name: aidlc-construction-nfr-requirements
description: AI-DLC 🟢 CONSTRUCTION 9. NFR Requirements (비기능 요구) stage 를 1.0 규칙대로 진행. 인자 없이 = 이 stage 로 이동 (workflow 진행 위치 변경), --single = 이 stage 만 실행하고 진행 위치 유지. 사용자가 /aidlc-construction-nfr-requirements 로 직접 호출할 때만 사용.
argument-hint: "<unit> [--single]"
disable-model-invocation: true
---

# /aidlc-construction-nfr-requirements

<!-- 생성 파일: dev/tools/gen_aidlc_stage_skills.py 의 STAGES 를 고친 뒤 다시 생성 -->

| 항목 | 값 |
| --- | --- |
| stage | 🟢 CONSTRUCTION 9. NFR Requirements (비기능 요구) |
| 상태 표기 | NFR Requirements |
| 규칙 파일 | `.aidlc-rule-details/construction/nfr-requirements.md` |
| 실행 조건 | CONDITIONAL |
| unit | ✅ 필요 |
| 필요한 앞 산출물 | `construction/{unit}/functional-design/` |
| 참고 | Functional Design SKIP 이면 `unit-of-work.md` |
| 만드는 산출물 | `construction/{unit}/nfr-requirements/`, `construction/plans/{unit}-nfr-requirements-plan.md` |

- 인자: `$ARGUMENTS` (`--single` 포함 = 단독 실행, 없음 = 이동, 나머지 = unit 이름)
- 경로는 `aidlc-docs/` 기준, `{unit}` = unit 이름
- 진행: `.claude/skills/aidlc/stage-runner.md` 를 읽고 위 표 값으로 그 절차대로 진행
- 같은 이동 · 단독 실행을 `/aidlc nfr-req` 로도 호출 가능

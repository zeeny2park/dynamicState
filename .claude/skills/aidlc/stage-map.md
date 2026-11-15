# AI-DLC stage 지도

<!-- 생성 파일: dev/tools/gen_aidlc_stage_skills.py 의 STAGES 를 고친 뒤 다시 생성 -->

- 순서 = 표의 위에서 아래 (이동 방향 판단 기준)
- stage 별 규칙 파일 · 앞 산출물 · 만드는 산출물 = 각 stage 스킬 `SKILL.md` 의 표
- 상태 표기 = `aidlc-docs/aidlc-state.md` 의 Stage Progress 항목 이름 (unit 별 stage 는 뒤에 `(<unit>)`)
- 실행 조건 = `core-workflow.md` 기준 (ALWAYS = 항상, CONDITIONAL = 조건부)

## 🔵 INCEPTION

| # | 스킬 | 별칭 | 상태 표기 | 실행 조건 | unit |
| --- | --- | --- | --- | --- | --- |
| 1 | `/aidlc-inception-workspace-detection` | `wd` | Workspace Detection | ALWAYS | - |
| 2 | `/aidlc-inception-reverse-engineering` | `re` | Reverse Engineering | CONDITIONAL (Brownfield 전용) | - |
| 3 | `/aidlc-inception-requirements-analysis` | `req` | Requirements Analysis | ALWAYS (깊이 조정) | - |
| 4 | `/aidlc-inception-user-stories` | `stories` | User Stories | CONDITIONAL | - |
| 5 | `/aidlc-inception-workflow-planning` | `plan` | Workflow Planning | ALWAYS | - |
| 6 | `/aidlc-inception-application-design` | `design` | Application Design | CONDITIONAL | - |
| 7 | `/aidlc-inception-units-generation` | `units` | Units Generation | CONDITIONAL | - |

## 🟢 CONSTRUCTION

| # | 스킬 | 별칭 | 상태 표기 | 실행 조건 | unit |
| --- | --- | --- | --- | --- | --- |
| 8 | `/aidlc-construction-functional-design` | `fd` | Functional Design | CONDITIONAL | ✅ 필요 |
| 9 | `/aidlc-construction-nfr-requirements` | `nfr-req` | NFR Requirements | CONDITIONAL | ✅ 필요 |
| 10 | `/aidlc-construction-nfr-design` | `nfr` | NFR Design | CONDITIONAL | ✅ 필요 |
| 11 | `/aidlc-construction-infrastructure-design` | `infra` | Infrastructure Design | CONDITIONAL | ✅ 필요 |
| 12 | `/aidlc-construction-code-generation` | `codegen` | Code Generation | ALWAYS | ✅ 필요 |
| 13 | `/aidlc-construction-build-and-test` | `bt` | Build and Test | ALWAYS | - (전체 unit 대상) |

## 🟡 OPERATIONS

| # | 스킬 | 별칭 | 상태 표기 | 실행 조건 | unit |
| --- | --- | --- | --- | --- | --- |
| 14 | `/aidlc-operations-deployment-pipeline` | `pipeline` | Deployment Pipeline | CONDITIONAL | - |
| 15 | `/aidlc-operations-environment-provisioning` | `env` | Environment Provisioning | CONDITIONAL | - |
| 16 | `/aidlc-operations-deployment-execution` | `deploy` | Deployment Execution | CONDITIONAL | - |
| 17 | `/aidlc-operations-observability-setup` | `obs` | Observability Setup | CONDITIONAL | - |
| 18 | `/aidlc-operations-incident-response` | `incident` | Incident Response | CONDITIONAL | - |
| 19 | `/aidlc-operations-performance-validation` | `perf` | Performance Validation | CONDITIONAL | - |
| 20 | `/aidlc-operations-feedback-optimization` | `feedback` | Feedback & Optimization | CONDITIONAL | - |

- unit 별 stage (8~12) 순서 = unit 안에서 8 → 12, unit 끼리는 `unit-of-work.md` 순서
- 13 Build and Test = 모든 unit 의 Code Generation 이후 1회, Operations = phase 단위 1회

## stage 가 아닌 도구

| 이름 | 용도 |
| --- | --- |
| `/traceability-check [inception\|construction]` | 추적성 점검, 메인 대화에서 실행 |
| `/traceability-check-agent [inception\|construction]` | 같은 점검, 서브에이전트 `aidlc-traceability` 가 대조 · 메인은 승인만 |

- ① `inception` = Units Generation 승인 후 · CONSTRUCTION 진입 전, ② `construction` = Build and Test 승인 후 · OPERATIONS 진입 전
- stage 스킬 · `/aidlc` 이동 대상 아님

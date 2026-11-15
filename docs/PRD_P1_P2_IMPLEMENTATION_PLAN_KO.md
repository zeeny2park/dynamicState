# PRD P1·P2 적용 계획

- **기준 문서:** [PRD.md](PRD.md) §5.2–5.8, §7 Phase B–G, §8–10
- **작성일:** 2026-11-15
- **목표:** P1 요구사항을 검증 가능한 기능·계약으로 닫고, 그 근거를 P2 문서와 릴리스 기준선에 연결한다.
- **계획 상태:** 코드 보완 및 제한 회귀 검증 완료, 전체 P1 운영 검증 미완료. 기준 SHA `0d966613fbde6819b38ade1c94eb4327dae48d00` (`main`); 이번 변경의 공식 benchmark 결과는 아직 없다.

## 1. 범위와 원칙

P1 범위는 REQ-DIAG-001..004, REQ-CPP-001..002, REQ-TRACE-001..002, REQ-BENCH-001..003, REQ-REPORT-001..003, REQ-MCP-001..003이다. P2 범위는 REQ-DOC-001..002다.

구현 전에 각 요구사항의 실제 호출 경로, 기존 코드, 테스트와 결과물을 조사한다. 기존 구현을 다시 만들지 않고 결함 근거가 있는 부분만 수정한다. PRD에서 정하지 않은 정확도·성능 임계값은 임의로 설정하지 않는다. 공식 benchmark는 clean checkout과 격리된 시험 환경에서만 수행한다. 상세 실행 안전 규칙은 [AGENT.md](../AGENT.md)를 따른다.

P1 기능은 P0 trust-boundary 상태에 의존한다. 착수 시 PRD Phase A의 미해결 항목이 실제로 남았는지 코드와 테스트로 확인한다. 증거 admission·target identity·replay 문제가 P1 결과의 신뢰성을 훼손한다면 해당 P0 수정 또는 격리를 먼저 완료한다. P0 재실행 전체를 이 계획에 무조건 포함하지 않는다.

## 1.1 이번 적용에서 확인한 gap 및 변경

역공학 기준 문서는 `aidlc-docs/inception/reverse-engineering/`이며, 작성 당시 기준 SHA는 `9b327dd`다. 현재 코드와 PRD 추적표를 대조한 결과 P1 기능 다수는 이미 구현되어 있어 일괄 재구현하지 않았다. 이번 작업에서는 확인된 아래 두 공백만 수정했다.

| P1 영역 | 확인한 gap | 이번 변경 | 확인 상태 |
|---|---|---|---|
| REQ-BENCH-001..003 | benchmark provenance 외에 held-out source 중복 검사와 terminal verdict confidence calibration이 빠져 있었음 | 전체 Git worktree 상태, 실행 전·후 commit/cleanliness, dataset SHA-256, target build recipe/compiler/flags/ELF build ID, 정확히 같은 main/held-out source 중복 검사, confidence bucket별 표본 수·정확도·Brier score 기록. `--require-clean` gate, 결과 파일로 인한 dirty 방지, schema validation, 주요 비율의 Wilson 95% 구간 추가 | 저부하 provenance/schema/interval/calibration/중복 검사 회귀 통과. 전체 benchmark 및 공식 clean 기준선은 별도 clean checkout에서 실행 필요 |
| REQ-TRACE-001..002 | `EbpfTracer`가 계산한 세션 상태·lost/malformed event·오류가 상위 tracing 결과와 report에서 소실됨 | 세션별/총계 상태와 손실·오류를 findings에 전달하고, partial collection을 영문/국문 report에 표시 | 저부하 tracing/report 회귀 4개 통과. 실제 eBPF overhead/lifecycle 운영 검증은 격리 VM에서만 수행 |

**이번 적용 결과:** benchmark 및 tracing gap 구현을 반영했고, 아래 제한 검증을 수행한다. benchmark의 confidence calibration은 confidence가 실제로 제공된 terminal fault/healthy verdict에 한해 계산되며, 빠진 confidence는 accuracy 표본에서 제외하고 별도 수로 센다. source 중복 검사는 두 suite에서 정확히 같은 source contents를 찾는다.

검증 기록: benchmark/tracing 대상 13개, P0 증거 신뢰 경계 회귀 44개, 연관 진단/report 회귀 71개가 통과했다(총 128개). 변경된 Python 파일 `py_compile`, `scripts/run_test_baseline.sh`의 `bash -n`, `git diff --check`도 통과했다. 전체 진단 정확도 benchmark, live eBPF, 전체 CI는 실행하지 않았다.

**미완료 범위:** 이번 변경은 P1 전체 완료 선언이 아니다. DIAG/CPP/REPORT/MCP의 PRD 수용 기준별 테스트 및 artifact 대조, benchmark 공식 clean run과 held-out gate, 실제 tracing 환경 측정은 후속 작업으로 남는다. PRD §12의 기존 완료 체크는 이 gap 대조만으로 승인하지 않는다. 운영 검증 전에는 새 기능을 release gate 통과로 간주하지 않는다.

## 2. 적용 순서와 의존성

```text
0. 현황·기준선 조사
        ↓
1. 공통 증거·버전·benchmark/report 계약 확정
        ↓
2. Phase B 진단 정확성 ──┬── 3. Phase C C++ 해석
                          ├── 4. Phase D tracing
                          └── 5. Phase E benchmark 공식 gate
                                      ↓
                              6. Phase F report/MCP 통합
                                      ↓
                              7. Phase G 문서·릴리스 기준선
```

Phase B, C, D의 독립 구현은 공통 식별자·provenance·오류 상태 계약이 합의된 후 각각 수행할 수 있다. 본 계획에서는 산출물과 인터페이스 충돌을 줄이기 위해 B → C → D 순서로 검토·통합한다. E의 metadata/dataset 검증 도구는 앞 단계와 함께 조기에 준비하되, quality gate는 해당 지표의 유효한 clean baseline이 만들어진 뒤에만 활성화한다. F는 증거·진단·tracing 결과 모델이 안정된 후 통합한다. G는 실제 검증 결과를 받아 문서의 현재 상태를 정리한다.

## 3. 단계별 작업 계획

### Stage 0 — 현재 상태와 P0 선행 조건 확인

**작업**

- 최신 main SHA, branch, working tree, 관련 PR/CI run을 기록한다.
- PRD의 검토 기준 SHA와 현재 main이 다르면 차이를 확인하고 PRD 적용 기준을 갱신한다.
- 각 REQ에 대해 `현재 코드 → 호출 경로 → 기존 테스트 → 검증 artifact → 남은 결함` 표를 만든다.
- PRD §2.3의 P0 잔여 결함과 §12 추적표 상태를 실제 코드 및 테스트로 재확인한다.
- 기존 문서·CI 결과에서 요구사항별로 재사용 가능한 검증 근거를 식별한다. 날짜나 코드가 불명확한 주장은 완료 근거로 옮기지 않는다.

**산출물**

- P1/P2 요구사항 추적표 초안
- 검토 기준 SHA 및 작업 트리 상태
- P0 선행 조건의 `충족 / 부분 충족 / 미충족` 판정과 근거
- P1별 구현 범위 후보 및 중복 구현 방지 목록

**진입/완료 기준**

- 기준점과 현재 변경 사항을 구분해 기록한다.
- 어떤 P1 요구사항도 문서만을 근거로 구현 완료 판정하지 않는다.
- 신뢰 경계 결함이 P1 evidence path에 영향을 주면 의존 경로를 명시한다.

### Stage 1 — 공통 provenance 및 품질 측정 기반

**작업**

- benchmark, 진단 결과, tracing 결과, report에서 공유할 source commit, dirty state, build ID, target/session, 설정, dataset version, schema/generator version 필드를 대조한다.
- 공통 evidence reference와 수집 상태(complete, partial, untrusted, unsupported, failed 등)의 표현을 검토한다. 기존 의미가 있으면 재사용하고 변경 호환성을 정의한다.
- benchmark 결과 schema validation, clean-tree 감지, machine-readable artifact 보존 경로의 최소 인터페이스를 설계한다.
- dataset manifest 및 metric 정의(정답/위치/난이도/유효 표본/skip/unscored)를 검토한다.
- report canonical model과 MCP 반환 contract가 같은 provenance 의미를 사용하는지 확인한다.

**산출물**

- 공통 provenance/status 필드 매핑
- benchmark manifest 및 결과 schema 변경안
- dataset split/누수 점검 규칙
- 호환성·migration 메모

**완료 기준**

- clean benchmark와 일반 개발 실행 결과를 구별할 수 있다.
- 공통 필드 정의가 B–F 간 중복되거나 모순되지 않는다.
- 이 단계에서는 근거 없는 성능 gate 숫자를 추가하지 않는다.

### Stage 2 — Phase B: 진단 정확성·적응형 조사 (REQ-DIAG-001..004)

**작업 묶음 B1: hypothesis/verdict 불변식**

- hypothesis identity/status 전이, evidence reference, 지원·반증·미해결 증거, confidence 및 abstention 의미를 코드 경로와 대조해 명문화한다.
- 중복 evidence 가산, 상충 evidence, stale/untrusted/partial evidence, 증거 부족과 반증을 각각 재현하는 adversarial 회귀 사례를 만든다.
- 최종 verdict가 참조한 증거와 판정 규칙으로 재구성되는지 검증한다.

**작업 묶음 B2: 정적 위치 후보 품질**

- 후보 생성 규칙을 allocation/free/read/write 유형과 runtime evidence 연결로 분류한다.
- source/symbol/DWARF/function/line 정보와 점수 구성요소가 후보 provenance에 남는지 확인한다.
- optimized, inline, template, macro, stripped+debug companion, source mismatch의 dataset coverage를 확정한다.
- candidate recall, Top-1, exact location, false candidate를 분리해 결과를 출력한다.

**작업 묶음 B3: 조사 예산과 선택 정책**

- 각 조사 단계의 선행 조건, 기대 정보 가치, 비용, 부작용을 inventory로 만든다.
- reservation/consumption/release, timeout/cancel/partial completion 정산을 대조하고 예산 초과 후 원격 read가 차단되는지 검증한다.
- 선택 이유, 고려한 대안, 비용, 중단 이유를 결과에 보존한다.
- 반복 조사·낮은 정보 가치·무한 루프 경계 테스트를 추가한다.

**작업 묶음 B4: confidence·abstention**

- confidence 요소를 양·질·독립성·상충 정도와 연결하고 후보 순위와 확정 판정 기준을 분리한다.
- held-out dataset의 confidence bucket별 실제 정확도와 표본 수를 보고한다.
- 불충분한 증거에서 `판정 불가/추가 조사 필요`가 선택되는 경계를 확인한다.

**완료 기준**

- 상태 전이표와 invariant/adversarial 테스트가 존재한다.
- clean held-out 결과가 요구 지표별로 산출되고, 유효하지 않은 실행/표본이 성공으로 계산되지 않는다.
- 예산을 초과하거나 증거가 부족한 경우 안전하게 멈춘다.
- 같은 증거·설정에서 선택과 판정이 재현 가능하다.

### Stage 3 — Phase C: C++ ABI 및 객체 해석 (REQ-CPP-001..002)

**작업**

- 현재 지원 가능한 compiler, ABI, libstdc++/libc++ 및 버전 범위를 조사하고 검증 상태를 `지원·미지원·미검증`으로 구분한다.
- 지원 조합별 layout fixture와 생성 환경 기록을 연결한다. 실제 환경에서 검증하지 못한 조합을 지원으로 승격하지 않는다.
- container별 pointer/size/capacity/allocator/node sanity check와 unsupported 결과를 검증한다.
- malformed, partial read, torn/inconsistent memory, concurrent mutation을 정상 객체 결과로 오인하지 않는 경계 테스트를 설계한다.
- capture 시각과 consistency level을 object decode 및 allocation/free/read/write 관찰에 연결한다.
- 주소 재사용 및 stale pointer 사례의 식별 한계를 문서화한다.

**완료 기준**

- 지원 matrix의 각 `지원` 조합에 fixture와 decoder 검증 근거가 연결된다.
- 미지원·불확실한 layout은 명시적으로 unknown/unsupported를 반환한다.
- 불완전하거나 경쟁 변경 가능성이 있는 메모리는 안정 snapshot이라고 표시되지 않는다.

### Stage 4 — Phase D: Optional tracing 신뢰성 (REQ-TRACE-001..002)

**작업**

- attach/detach 및 target exit/restart/PID reuse/symbol resolution/permission 상태 전이를 추적한다.
- 세션 state와 전체 target identity가 연결되는지 확인하고 부분 attach/partial collection을 성공과 분리한다.
- 정상 종료, 오류, 취소, timeout마다 kernel/user 자원 정리를 계측한다.
- dropped/lost events, overflow, filtering/sampling, event rate 및 buffer 사용량의 실제 계수 경로를 확인한다.
- tracing overhead 측정 절차와 target 영향 지표를 정의하고, tracing 결과와 snapshot evidence provenance를 구분한다.
- 추적 비활성 기본 수집의 독립성 회귀 테스트를 유지한다.

**실행 안전**

- lifecycle 단위·모의 테스트를 우선한다. 실제 eBPF/uProbe 부하 측정은 격리된 Linux VM 또는 전용 시험 장비에서만 수행한다.
- 운영 보드나 SSH가 유일한 복구 경로인 호스트에서 tracing overhead 시험을 실행하지 않는다.

**완료 기준**

- attach/detach 반복, 종료, PID 재사용, 권한·symbol 실패의 정리 결과가 검증된다.
- event loss가 결과의 completeness/confidence에 반영된다.
- tracing 비활성 경로가 tracing 구현에 의존하지 않는다.

### Stage 5 — Phase E: 재현 가능한 benchmark 및 quality gate (REQ-BENCH-001..003)

**작업**

- 공식 benchmark runner가 clean tree/commit을 검사하고, 비공식 결과는 non-authoritative로 표기하거나 실행을 거부하도록 한다.
- commit, dirty state, build ID, compiler, architecture, kernel, debug info, config, dataset version을 결과에 필수 기록한다.
- dataset manifest로 train/tuning과 held-out, generic/ambiguous symptom, negative/trap, 중복/누수, 기대 조사 비용을 관리한다.
- repeat 횟수, 유효 표본, 실패, timeout, skip, unscored를 분리한다.
- detection, false positive, candidate recall, Top-1, exact location, calibration, cost를 별도 산출한다.
- 반복 변동과 sample size를 함께 표시하고, 데이터에 맞는 uncertainty 표시 방법을 선택한다.
- 지표별 baseline 및 gate는 clean reference run과 제품 요구자 승인 후 설정한다. 기준 미달, 표본 부족, invalid artifact는 GO로 판정하지 않는다.
- 결과 artifact를 변경 commit/PR 및 CI run과 연결한다.

**완료 기준**

- dirty 결과가 공식 gate에 들어가지 않는다.
- schema validation이 필수 provenance 누락 및 잘못된 dataset manifest를 차단한다.
- 지표, 표본 수, 제외 건수, 변동 범위가 원본 machine-readable 결과로 재현된다.
- 각 gate의 근거와 승인 주체가 문서화된다.

### Stage 6 — Phase F: Report 및 MCP 통합 (REQ-REPORT-001..003, REQ-MCP-001..003)

**작업 묶음 F1: canonical report와 evidence chain**

- `Finding → Verdict/Hypothesis → Evidence → Runtime observation → Process/Thread/Address → C++ object/field → DWARF/source → Function/location` 연결의 실제 존재 여부를 조사한다.
- 연결되지 않은 단계는 미확인/누락으로 표기하고, supporting/contradicting evidence, admission provenance 및 수집 실패를 노출한다.
- HTML/Markdown이 하나의 canonical report model에서 생성되는지 확인한다.
- report schema/generator version, source commit, 생성 시각, provenance 누락 상태를 검증한다.

**작업 묶음 F2: 조사 이력과 판단 설명**

- 최초 증상/범위, evidence/수집 실패, 조사 단계와 선택 이유, 경쟁 가설, 예산 사용 및 중단 이유, confidence/한계, 다음 조사를 모델링한다.
- 보고서 내용만으로 결론과 그 한계를 원본 evidence까지 추적할 수 있는지 검증한다.

**작업 묶음 F3: MCP contract 및 안전성**

- tool별 입력/default/출력/오류/상태/재시도 가능성을 inventory하고 구현과 설명의 불일치를 없앤다.
- 성공, 부분 성공, 거부, timeout, cancel, budget exhausted, unsupported, internal error 상태의 의미를 통일한다.
- target/session/build/evidence provenance를 계약에 포함하고 invalid target 및 stale evidence 경로를 테스트한다.
- read-only 동작과 대상 상태 변경 동작을 구분하고, 영향이 큰 작업의 권한·승인 정책을 확인한다.
- timeout/cancel 후 operation 상태를 조회할 수 있는지 검증한다.
- 모호한 입력의 MCP 전문가 흐름에서 구조화된 초기 정보 → 결정론적 도구 실행 → 결과 기반 다음 단계 → provenance 포함 보고서까지 통합 검증한다.

**완료 기준**

- 결론부터 원본 증거까지 추적 가능하며, 누락/partial/untrusted/unknown 상태가 숨겨지지 않는다.
- HTML/Markdown 간 의미 차이가 없다.
- MCP 계약 테스트 및 end-to-end 진단→보고서 경로가 통과한다.
- 에이전트가 부분 실패·거부·불확실 결과를 성공으로 오인하지 않는다.

### Stage 7 — Phase G: 문서 및 릴리스 기준선 (REQ-DOC-001..002)

**작업**

- `WORK_STATUS_KO.md`, `HANDOFF_NEXT_STEPS_KO.md`, `IMPROVEMENT_STRATEGY_AND_ROADMAP_KO.md`를 대조해 하나의 기준 상태 문서와 역할별 보조 문서 구조를 정한다.
- 단일 기준 문서에 최신 main SHA, 기준 시각, 구현/테스트/운영 검증/미검증 상태를 기록한다.
- 오래된 지표는 현재 성능처럼 보이지 않도록 historical/unverified로 표시하고 source artifact를 연결한다.
- CI URL, commit SHA, test command, benchmark artifact, dataset/version 간 추적 정보를 연결한다.
- 각 미완료 항목에 owner, priority, acceptance criteria 또는 후속 이슈를 연결한다.
- release readiness checklist에 P1 gate, 지원 matrix, 잔여 제한, GO/NO-GO/PARTIAL 근거를 반영한다.

**완료 기준**

- P1·P2 문서 상태가 코드·실행 결과·CI와 일치한다.
- 주장의 검증 시점과 원본 evidence를 독자가 찾아갈 수 있다.
- 과거의 dirty/재현 불가 결과가 현재 승인된 baseline으로 사용되지 않는다.

## 4. 요구사항 추적 및 산출물

구현 작업 단위마다 다음 필드를 유지한다.

| 필드 | 기록 내용 |
|---|---|
| Requirement | PRD REQ ID와 수용 기준 |
| Baseline | 기준 commit, 작업 트리 상태, 코드 경로 |
| Gap | 재현 가능한 결함·누락 근거 또는 이미 충족된 근거 |
| Change | 최소 수정과 schema/API 호환 영향 |
| Verification | 회귀/부정/통합 테스트 명령과 실제 결과 |
| Artifact | CI run, benchmark JSON, dataset manifest, report 샘플 |
| Status | `미착수 / 조사 중 / 구현 / 검증 / 운영 검증 / 미검증 / 차단` |
| Residual risk | 남은 지원 한계, 미측정 환경, 완화책 |

각 Stage 종료 시 요구사항별 추적표, 핵심 call path, 변경 파일, 검증 결과, CI/benchmark artifact, 잔여 위험을 갱신한다. 테스트가 실행되지 않았으면 통과로 간주하지 않는다.

## 5. 전체 완료 및 릴리스 판정

P1/P2 적용 완료는 다음을 모두 충족할 때만 선언한다.

1. P1 요구사항의 수용 기준이 테스트와 artifact로 추적된다.
2. unsupported, partial, untrusted, timeout, cancellation 상태가 명시적이고 fail-safe하다.
3. 공식 benchmark는 clean commit·검증된 dataset·필수 metadata·승인된 gate를 사용한다.
4. tracing 및 benchmark 부하 검증은 격리된 환경에서 수행되고 영향/손실이 기록된다.
5. report/MCP가 같은 canonical evidence/status 의미를 사용한다.
6. P2 문서가 현재 main SHA와 검증 상태를 반영하고, historical·미검증 수치를 구분한다.
7. main 기준 필수 CI 및 관련 regression/integration suite의 실제 성공 결과가 있다.
8. 미충족 요구사항과 잔여 위험은 완료로 표시하지 않고 `PARTIAL` 또는 `NO-GO`로 남긴다.

## 6. 주요 위험과 대응

| 위험 | 대응 |
|---|---|
| P1 범위가 넓어 모든 영역을 한 번에 변경 | 공통 계약을 먼저 고정하고 Stage별로 리뷰 가능한 변경 단위로 분리 |
| 기존 기능을 재구현하거나 문서 상태만으로 완료 판단 | Stage 0 call path/테스트/artifact 조사, requirement traceability 유지 |
| tuning set이 held-out 품질 평가에 새어 들어감 | dataset manifest, 중복/누수 검사, clean held-out 분리 |
| threshold를 표본에 맞춰 사후 조정 | threshold 제안 근거·승인 기록, baseline과 gate 버전 고정 |
| ABI/tracing 측정 환경 부족 | 검증한 조합만 지원으로 표기, 장비/권한 부족은 미검증으로 유지 |
| tracing 또는 부하 시험이 SSH/호스트를 불안정하게 함 | [AGENT.md](../AGENT.md) 적용, 격리 VM/전용 장비 사용, 자원·로그 수집 |
| report와 MCP가 서로 다른 오류 의미를 노출 | 공통 provenance/status 계약을 단일 출처로 두고 contract test 적용 |
| 문서 수정으로 완료 상태를 과장 | 구현·테스트·운영 검증 상태를 분리하고 main SHA/증거 링크 필수화 |

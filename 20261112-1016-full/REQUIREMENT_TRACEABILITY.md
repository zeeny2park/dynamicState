# Requirement Traceability: dynamicState

- Target: `C:\task\dynamicState\dynamicState` @ `f842448` (main), working tree clean
- Diagnostic date: 2026-11-12 · Mode: full · Scope: 사용자 제공 목적과 저장소 문서에서 추출한 요구사항 17개를 코드·테스트에 대응
- Not examined: 테스트를 실행하지 않았으므로 어떤 요구사항도 "검증됨"으로 올리지 않았다. 테스트 통과 여부는 UNKNOWN이다.

## Original objectives

| ID | Objective | Provenance | Currency | Source |
|---|---|---|---|---|
| OBJ-001 | 전문가의 진단 기법과 워크플로우를 AI가 수행할 수 있는 형태로 제공 | USER_PROVIDED, DOCUMENTED | CURRENT | 사용자 요청; `docs/PROCESS_HEALTH_INVESTIGATION_SKILL.md:13-21` |
| OBJ-002 | 진단 데이터 수집 도구 제공. 임베디드에서 실행 중 프로세스에 주는 영향 최소화 | USER_PROVIDED, DOCUMENTED | CURRENT | 사용자 요청; `docs/EMBEDDED_DEPLOYMENT_ARCHITECTURE.md:114-116` |
| OBJ-003 | "프로세스 진단" 한 번의 요청으로 수집 → 진단 → 최종 판정 | USER_PROVIDED, DOCUMENTED | CURRENT | 사용자 요청; `docs/PROCESS_HEALTH_INVESTIGATION_SKILL.md:42-44` |
| OBJ-004 | 사용자가 쉽게 이해할 수 있는 상세 보고서 | USER_PROVIDED | CURRENT | 사용자 요청 |
| OBJ-005 | 소스 수준 원인 특정: 오버플로우·미해제 버퍼의 소유 변수, 오동작 스레드 | USER_PROVIDED, DOCUMENTED | CURRENT | 사용자 요청; `docs/PRACTICAL_PLAYBOOK_KO.md:13` |

### Intended users and core use cases

- 사용자: 임베디드·서버 C/C++ 엔지니어, MCP로 연결된 AI 에이전트.
- UC-1: "PID N에 문제가 있는지 검사" → 판정과 보고서(OBJ-003, OBJ-004).
- UC-2: "메모리가 늘어난다" → 누수 여부와 누수 주체 변수·할당 지점(OBJ-005).
- UC-3: "메모리가 깨진 것 같다" → 넘친 버퍼와 그 소유 변수(OBJ-005).
- UC-4: "스레드가 멈춘 것 같다" → 어떤 스레드가 왜 멈췄는지(OBJ-005).
- UC-5: 원격 임베디드 보드의 프로세스를 영향 없이 진단(OBJ-002).

## Extracted requirements and traceability matrix

| ID | Requirement | Source | Implementation | Tests | Verification Evidence | Status | Confidence |
|---|---|---|---|---|---|---|---|
| REQ-001 | PID만 주면 수집·진단·판정·보고서까지 수행하는 단일 진입점 | 사용자 요청; `docs/PROCESS_HEALTH_INVESTIGATION_SKILL.md:42-44` | MCP는 3회 호출 필요 `scripts/mcp_server.py:508-510`, `scripts/mcp_server.py:687-688`; 1회 호출 경로는 다른 엔진 `scripts/mcp_server.py:2852` | `tests/test_phase2_4_4_mcp_e2e.py:37-56` | 미실행 | PARTIALLY_IMPLEMENTED | HIGH |
| REQ-002 | 전문가식 절차: 저비용 트리아지 → 경쟁 가설 → 판별 관측 → 중단 규칙 | `docs/PROCESS_HEALTH_INVESTIGATION_SKILL.md:82-99` | 적응형 엔진 `extractor/adaptive_engine.py:438-620`(실시간 트리아지는 스레드만 `extractor/adaptive_engine.py:1561-1586`); 전문가 엔진은 비용·안전 점수가 상수 `extractor/expert_diagnostic_engine.py:825-836` | `tests/test_phase2_4_4_adaptive_investigation.py:138-168` | 미실행 | PARTIALLY_IMPLEMENTED | MEDIUM |
| REQ-003 | 주요 증상 범주 포괄(메모리 누수·손상, 교착, CPU 폭주, fd·소켓 고갈, 스택) | 사용자 요청(전문가 진단 범위) | 레시피 22개는 메모리·상태·동시성 4범주 `extractor/diagnostic_recipes.py:204-930`; fd·소켓·CPU·스택 레시피 없음 | - | - | PARTIALLY_IMPLEMENTED | HIGH |
| REQ-004 | 누수 탐지와 누수 주체(변수, 자료구조, 할당 지점) 특정 | 사용자 요청; `docs/PROCESS_HEALTH_INVESTIGATION_SKILL.md:166` | 증가 탐지만 있음 `extractor/runtime_evidence_provider.py:896-898`; 누수 확정 조건의 입력이 생산되지 않음 `extractor/temporal_observation_window.py:472-481` | `tests/test_phase2_4_2_real_process_temporal_growth_and_accuracy.py:229-235` | 미실행. 테스트는 상태값만 단언 | PARTIALLY_IMPLEMENTED | HIGH |
| REQ-005 | 버퍼 오버플로우·힙 손상 탐지 | 사용자 요청 | 포인터 유효성과 청크 1개 검사 `extractor/allocator_inspector.py:203-219`; 버퍼 경계 검사 없음; "손상"은 이름과 독성 값 일치 `extractor/runtime_evidence_provider.py:767-779` | `tests/test_phase2_2_real_allocator_validation.py:161-227` | 미실행 | PARTIALLY_IMPLEMENTED | HIGH |
| REQ-006 | 임의의 힙·데이터 주소가 어떤 변수(전역, 멤버, 지역)의 것인지 역추적 | 사용자 요청 | 없음. 가장 가까운 기능은 사용자가 전역 심볼을 먼저 지정해야 함 `extractor/watch_session.py:3588-3598` | - | - | NOT_IMPLEMENTED | HIGH |
| REQ-007 | 교착 탐지와 관련 스레드·락 이름 제시 | `docs/PROCESS_HEALTH_INVESTIGATION_SKILL.md:95` | 전역 pthread mutex 한정 `extractor/watch_session.py:5397-5411`; 순환 탐지 `extractor/watch_session.py:5665-5689` | `tests/test_phase2_1_8_complete_validation.py:932-999` | 미실행. TID·락 이름은 단언하지 않음 | PARTIALLY_IMPLEMENTED | HIGH |
| REQ-008 | 스레드 오동작(바쁜 대기, 기아, 시스템콜 정지, CPU 폭주, 스레드 누수) 판정 | 사용자 요청 | 규칙은 있으나 입력 생산자 없음 `extractor/diagnostic_recipes.py:2106-2177`; DPDK 폴링 스레드만 판정 `extractor/watch_session.py:9686-9694` | `tests/test_phase2_1_8_complete_validation.py:974-978` | 미실행. 테스트가 답을 직접 주입 | PARTIALLY_IMPLEMENTED | HIGH |
| REQ-009 | 데이터가 부족하거나 수집이 실패하면 "정상"으로 판정하지 않음 | `docs/PROCESS_HEALTH_INVESTIGATION_SKILL.md:163-168`, `docs/PROCESS_HEALTH_INVESTIGATION_SKILL.md:201` | 집계기는 엄격 `extractor/diagnostic_verdict_aggregator.py:616-653`; 사고 보고서 경로는 실패를 정상으로 대체 `extractor/watch_session.py:11431-11432` | - | - | IMPLEMENTED_BUT_INCORRECT | HIGH |
| REQ-010 | 비전문가도 이해할 보고서: 평이한 결론, 변수·스레드·소스 위치, 근거, 한계, 조치 | 사용자 요청 | 섹션 구조는 있음 `extractor/diagnostic_report.py:539`; 대상이 변수가 아닌 범주 `extractor/expert_diagnostic_engine.py:3052`; 소스 위치 필드 미기입 | `tests/test_phase2_3_c1_mcp_boundary_and_consistency.py:209` | 미실행. 구조만 단언 | PARTIALLY_IMPLEMENTED | HIGH |
| REQ-011 | 진단 워크플로우를 AI 에이전트가 바로 쓸 수 있는 형태(스킬, 플레이북)로 제공 | 사용자 요청; `docs/PROCESS_HEALTH_INVESTIGATION_SKILL.md:19-21` | 문서만 존재. 코드에서 참조 없음; MCP 플레이북은 데모 심볼 중심 `scripts/mcp_server.py:2872-2894` | - | - | PARTIALLY_IMPLEMENTED | HIGH |
| NFR-001 | 기본 수집은 대상 프로세스를 정지시키지 않음 | `docs/PROCESS_HEALTH_INVESTIGATION_SKILL.md:38` | 슬라이스 경로는 무정지 `extractor/watch_session.py:103-173`; 스냅샷 기본 모드는 SIGSTOP `extractor/capture_plan.py:26`, `extractor/capture_backend.py:3518` | `tests/test_phase2_4_collection_reliability_and_overhead.py:163-217` | 미실행. 기록된 벤치마크는 평균 약 4.1ms 정지 `benchmarks/latest_results.json:107-110` | IMPLEMENTED_BUT_INCORRECT | HIGH |
| NFR-002 | 관측 예산(시간, 바이트, 정지 시간)을 실제 수집 경로에서 강제 | `docs/PROCESS_HEALTH_INVESTIGATION_SKILL.md:140-145` | 증거 경로는 강제 `extractor/runtime_evidence_provider.py:178`; 스냅샷 경로는 별도 정책이고 정지 시간은 사후 검출 `extractor/capture_backend.py:4127-4135` | `tests/test_phase2_4_collection_reliability_and_overhead.py:203` | 미실행 | PARTIALLY_IMPLEMENTED | MEDIUM |
| NFR-003 | 타깃 보드에 Python 없이 네이티브 수집기로 수집 | `docs/EMBEDDED_DEPLOYMENT_ARCHITECTURE.md:44-47` | `target/collector/src/main.c:262-388`; 배포 `extractor/target_adapter.py:2036-2140` | `tests/test_phase2_0_a_3_2_evidence_accuracy.py:598` | 미실행. 네이티브 빌드만 `ci/workflows/test.yml:27-29` | IMPLEMENTED_BUT_UNVERIFIED | MEDIUM |
| NFR-004 | ARM, MIPS, RISC-V와 비-glibc 타깃 지원 | `docs/EMBEDDED_DEPLOYMENT_ARCHITECTURE.md:5` | 시스템콜 표가 x86_64 고정 `extractor/watch_session.py:5459-5463`; mutex 배치가 glibc 가정 `extractor/watch_session.py:5416-5421` | `tests/test_phase2_4_real_world_targets.py:253-267` | 미실행. ARM32는 ELF 헤더 파싱만 | PARTIALLY_IMPLEMENTED | MEDIUM |
| NFR-005 | 대상에 쓰기·신호·변이를 가하지 않는 읽기 전용 안전성 | `docs/PROCESS_HEALTH_INVESTIGATION_SKILL.md:37` | 변이는 LOW_IMPACT 모드일 때만 차단 `extractor/agent_runtime.py:663-664`; 기본 모드는 CONSISTENT `extractor/agent_runtime.py:75` | `tests/test_phase52_web_and_mcp_defensive_hardening.py` | 미실행 | PARTIALLY_IMPLEMENTED | MEDIUM |
| NFR-006 | 수집이 대상에 준 영향을 측정해 보고 | 사용자 요청(영향 최소화의 확인 수단) | 없음. 보고서가 0.00ms를 고정 출력 `extractor/watch_session.py:11474` | - | - | NOT_IMPLEMENTED | HIGH |

## Coverage summary

- 상태별 개수(17개): IMPLEMENTED_AND_VERIFIED 0, IMPLEMENTED_BUT_UNVERIFIED 1, PARTIALLY_IMPLEMENTED 12, NOT_IMPLEMENTED 2, IMPLEMENTED_BUT_INCORRECT 2, UNKNOWN 0.
- 검증된 요구사항을 하나 이상 가진 목표: 5개 중 0개. 테스트를 실행하지 않았고 CI가 가동된 적이 없어(`ci/README.md:34`) 실행 증거가 없다.
- 목표별 요약:
  - OBJ-001(기법·워크플로우): 부분. 문서 명세는 좋으나 코드와 분리되어 있다.
  - OBJ-002(저영향 수집): 가장 앞서 있음. 단 기본 경로 하나가 대상을 정지시킨다.
  - OBJ-003(한 번의 요청): 부분. 엔진이 3종으로 갈라져 있다.
  - OBJ-004(쉬운 보고서): 부분. 구조는 있고 내용이 기계 지향이다.
  - OBJ-005(원인 특정): 가장 뒤처짐. 핵심인 주소 → 변수 역추적이 없다.

## Intent conflicts and outdated requirements

- README는 제품을 "상태 탐색기"로 소개하고 체크포인트·변이를 전면에 두지만(`README.md:11`, `README.md:23-24`), 사용자 목적과 워크플로우 명세는 읽기 전용 진단이다(`docs/PROCESS_HEALTH_INVESTIGATION_SKILL.md:37`). F-INTENT-002.
- 단계 보고서끼리 검증 범위가 모순된다. F-INTENT-001.
- 임베디드 구조 문서의 "패턴 1: 원격 gdbserver"(`docs/EMBEDDED_DEPLOYMENT_ARCHITECTURE.md:61-63`)는 대상을 정지시키므로 저영향 목적과 맞지 않고, 코드에도 gdbserver 연결 구현이 없다(`extractor/`, `scripts/`, `target/`, `gdb/`에서 gdbserver 검색 결과 없음).

## Traceability findings

### F-INTENT-001: 단계 보고서의 "정밀도·재현율 100%, 양산 준비 완료" 주장이 후속 보고서와 코드에 의해 부정됨
- **Category:** INTENT
- **Severity:** HIGH
- **Confidence:** HIGH
- **Evidence Type:** FACT
- **Requirement:** OBJ-001
- **Evidence:** `docs/PHASE_2_4_FINAL_REPORT.md:7`, `docs/PHASE_2_4_FINAL_REPORT.md:103-104`, `docs/PHASE_2_4_4_FINAL_REPORT.md:127-135`, `docs/PHASE_2_4_4_FINAL_REPORT.md:146-147`, `tests/test_phase2_4_1_recipe_accuracy_and_evidence_path.py:421-430`
- **Observed:** Phase 2.4 보고서는 "GO(양산 출시 준비 완료)"와 22개 레시피의 정밀도·재현율 100%를 선언한다. 하루 뒤 Phase 2.4.4 보고서는 실제 프로세스로 검증된 레시피가 5개이고 나머지 17개는 합성 입력이라고 밝히며, 지속 누수 시나리오는 보류로 둔다. 정확도 테스트는 `real_tp = 4`, `real_fp = 0`을 대입한 뒤 그 상수를 단언한다.
- **Expected:** 완료 선언은 실제 프로세스에서 측정한 결과와 원시 실행 기록에 근거해야 한다.
- **Gap:** 현재 문서의 완료 판정은 프로젝트 상태를 판단하는 근거로 쓸 수 없다. 실제 진척을 가린다.
- **Recommendation:** 정답이 정해진 실제 프로세스 벤치마크로 정확도를 다시 측정하고, 문서의 완료 판정을 그 결과로 교체한다. IMP-013 참조.

### F-INTENT-002: README가 말하는 제품 정체성(상태 탐색·변이)과 실제 목적(읽기 전용 진단)이 어긋남
- **Category:** INTENT
- **Severity:** MEDIUM
- **Confidence:** HIGH
- **Evidence Type:** FACT
- **Requirement:** OBJ-003
- **Evidence:** `README.md:11`, `README.md:23-24`, `README.md:169-180`, `docs/PROCESS_HEALTH_INVESTIGATION_SKILL.md:37`
- **Observed:** README는 체크포인트, 타입 변이, 롤백을 핵심 기능으로 소개하고, 주요 MCP 도구 표에 진단 시작·보고서 도구(`runtime_start_investigation`)가 없다. 워크플로우 명세는 대상 쓰기와 신호 주입을 금지한다.
- **Expected:** 진입 문서가 "프로세스를 진단해 달라"는 사용 흐름을 첫 화면에서 안내해야 한다.
- **Gap:** 새 사용자나 AI 에이전트가 README만 읽으면 진단 경로를 찾지 못하고 저수준 도구를 직접 조합하게 된다.
- **Recommendation:** README를 진단 흐름 중심으로 다시 쓴다. IMP-022 참조.

### F-TRACE-001: 어떤 요구사항도 실행 증거로 검증되지 않음
- **Category:** TRACE
- **Severity:** HIGH
- **Confidence:** HIGH
- **Evidence Type:** FACT
- **Requirement:** OBJ-003
- **Evidence:** `ci/README.md:34`, `docs/PHASE_2_4_4_FINAL_REPORT.md:6`; `cmd: git ls-files .github` 결과 0줄; 저장소에 테스트 실행 로그 없음
- **Observed:** `.github/` 디렉터리가 없고, CI 문서가 토큰 권한 부족으로 워크플로우를 올리지 못했다고 직접 밝힌다. 단계 보고서의 통과 숫자를 뒷받침하는 실행 로그나 결과 파일이 저장소에 없다.
- **Expected:** 핵심 요구사항마다 실패할 수 있는 테스트와 그 테스트가 실행된 기록이 있어야 한다.
- **Gap:** 추적표에서 "검증됨"이 0건이다. 현재 품질은 단일 개발 호스트의 자기 보고에만 의존한다.
- **Recommendation:** Linux에서 전체 테스트를 실행해 기준선을 만들고 CI를 가동한다. IMP-005 참조.

### F-TRACE-002: 진단 워크플로우 명세가 문서로만 있고 에이전트가 쓸 수 있는 형태로 연결되지 않음
- **Category:** TRACE
- **Severity:** MEDIUM
- **Confidence:** HIGH
- **Evidence Type:** FACT
- **Requirement:** REQ-011
- **Evidence:** `docs/PROCESS_HEALTH_INVESTIGATION_SKILL.md:19-21`, `scripts/mcp_server.py:2872-2894`; `cmd: git ls-files`에서 SKILL.md, AGENTS.md, CLAUDE.md, .mcp.json 검색 결과 없음
- **Observed:** 워크플로우 명세와 지식 문서, 한국어 플레이북은 산문 문서이며 `extractor/`나 `scripts/`의 어떤 파일도 이를 참조하지 않는다. MCP의 `runtime_get_playbook`은 데모 심볼 중심의 도구 시나리오를 나열하고 진단 시작 도구는 언급하지 않는다.
- **Expected:** AI 에이전트가 "진단해 줘" 요청을 받으면 따라야 할 절차가 스킬이나 MCP 안내로 제공되어야 한다.
- **Gap:** 전문가 워크플로우라는 목적의 절반(기법 전달)이 에이전트에게 전달되지 않는다.
- **Recommendation:** 워크플로우를 에이전트 스킬과 MCP 플레이북으로 패키징한다. IMP-023 참조.

### F-DOC-001: README의 명령·경로·수치가 실제와 다름
- **Category:** DOC
- **Severity:** LOW
- **Confidence:** HIGH
- **Evidence Type:** FACT
- **Requirement:** N/A — 문서 정확성
- **Evidence:** `README.md:128`, `README.md:193`, `README.md:264`, `README.md:113`, `README.md:251`, `extractor/cli.py:45-47`, `extractor/web/workspace.py:29`
- **Observed:** `python3 -m extractor.capture_backend capture-memory`는 동작하지 않는다(해당 모듈에 실행 진입점이 없음). `./scripts/run_all_tests.sh`는 없고 파일은 루트에 있다. LICENSE 파일이 없다. 워크스페이스 기본 포트는 8000이 아니라 18088이다. WebSocket 코드는 없다.
- **Expected:** 빠른 시작 명령이 그대로 동작해야 한다.
- **Gap:** 첫 사용자가 안내대로 실행하면 실패한다.
- **Recommendation:** README를 실제 명령으로 고친다. IMP-022 참조.

## Unresolved requirements

| ID | Status | What is missing | Proposed resolution (IMP) |
|---|---|---|---|
| REQ-001 | PARTIALLY_IMPLEMENTED | 하나의 엔진으로 끝까지 실행하는 단일 진입점 | IMP-006 |
| REQ-002 | PARTIALLY_IMPLEMENTED | 실시간 트리아지가 메모리·큐 후보를 채우지 못함. 후속 단계 생성 결함 | IMP-004, IMP-018 |
| REQ-003 | PARTIALLY_IMPLEMENTED | fd, 소켓, CPU, 스택 범주 | IMP-018 |
| REQ-004 | PARTIALLY_IMPLEMENTED | 누수 주체 특정, 시간 간격을 둔 반복 관측 | IMP-007, IMP-008 |
| REQ-005 | PARTIALLY_IMPLEMENTED | 버퍼 경계 대비 검사 | IMP-009 |
| REQ-006 | NOT_IMPLEMENTED | 힙 순회와 역참조 맵 | IMP-007 |
| REQ-007 | PARTIALLY_IMPLEMENTED | 멤버·힙 mutex, 다회 관측 지속성, 이름 단언 테스트 | IMP-003, IMP-010 |
| REQ-008 | PARTIALLY_IMPLEMENTED | 스레드 시계열 표본 수집기 | IMP-010 |
| REQ-009 | IMPLEMENTED_BUT_INCORRECT | 실패를 정상으로 바꾸는 경로 제거 | IMP-001 |
| REQ-010 | PARTIALLY_IMPLEMENTED | 평이한 결론, 변수·스레드·소스 위치, 한국어 | IMP-012 |
| REQ-011 | PARTIALLY_IMPLEMENTED | 에이전트 스킬 패키징 | IMP-023 |
| NFR-001 | IMPLEMENTED_BUT_INCORRECT | 기본 모드를 무정지로 | IMP-002 |
| NFR-002 | PARTIALLY_IMPLEMENTED | 스냅샷 경로 예산 통합, 타깃 측 비용 | IMP-020 |
| NFR-003 | IMPLEMENTED_BUT_UNVERIFIED | 교차 컴파일과 실제 타깃 실행 | IMP-014, IMP-016 |
| NFR-004 | PARTIALLY_IMPLEMENTED | ABI 판별과 미지원 시 거부 | IMP-015 |
| NFR-005 | PARTIALLY_IMPLEMENTED | 기본 읽기 전용, 웹 API 인증 | IMP-019 |
| NFR-006 | NOT_IMPLEMENTED | 영향 측정과 보고 | IMP-002, IMP-020 |

# Improvement Roadmap: dynamicState

- Target: `C:\task\dynamicState\dynamicState` @ `f842448` (main), working tree clean
- Diagnostic date: 2026-11-12 · Mode: full · Scope: 발견 사항 33건을 중복 작업 확인을 거쳐 개선 항목 23개로 정리
- Not examined: 각 항목의 구현 난이도는 코드 읽기에 근거한 추정이다. 작업량(S/M/L)은 실행해 보지 않은 견적이다.

## Prioritization summary

전략의 요지: **지금은 능력을 더 얹을 때가 아니라, 판정을 믿을 수 있게 만들고(1단계), 목적의 핵심인 "원인 특정"을 채우고(2단계), 그것을 외부 기준으로 증명한 뒤(3단계), 구조를 정리하는(4단계) 순서다.** 신뢰·출처 검증 장치는 현 상태로 동결한다.

| ID | Priority | Group | Work type | Title | Depends on |
|---|---|---|---|---|---|
| IMP-001 | P0 | IMMEDIATE_CORRECTIONS | EXISTING_IMPLEMENTATION_FIX | 수집 실패를 "정상"으로 바꾸는 경로 제거 | none |
| IMP-002 | P0 | IMMEDIATE_CORRECTIONS | EXISTING_IMPLEMENTATION_FIX | 기본 수집을 무정지로 바꾸고 정지 시간을 측정값으로 보고 | none |
| IMP-003 | P1 | IMMEDIATE_CORRECTIONS | EXISTING_IMPLEMENTATION_FIX | 교착 지속성 기본값 수정 | none |
| IMP-004 | P1 | IMMEDIATE_CORRECTIONS | EXISTING_IMPLEMENTATION_FIX | 메모리 증가 후속 단계 생성 결함 수정 | none |
| IMP-005 | P0 | RELIABILITY_AND_VALIDATION | TEST_OR_VERIFICATION | 테스트 기준선 확보와 CI 가동 | none |
| IMP-006 | P1 | CORE_FUNCTIONAL_COMPLETION | INTEGRATION_FIX | 단일 `diagnose` 진입점 | IMP-001, IMP-005 |
| IMP-007 | P1 | CORE_FUNCTIONAL_COMPLETION | NEW_IMPLEMENTATION | 힙 순회기와 역참조 맵(주소 → 변수) | IMP-005 |
| IMP-008 | P1 | CORE_FUNCTIONAL_COMPLETION | EXISTING_IMPLEMENTATION_FIX | 누수 주체 특정 | IMP-004, IMP-007 |
| IMP-009 | P1 | CORE_FUNCTIONAL_COMPLETION | NEW_IMPLEMENTATION | 버퍼 오버플로우 탐지 | IMP-007 |
| IMP-010 | P1 | CORE_FUNCTIONAL_COMPLETION | INTEGRATION_FIX | 스레드 시계열 표본 수집과 규칙 연결 | IMP-003, IMP-005 |
| IMP-011 | P1 | CORE_FUNCTIONAL_COMPLETION | EXISTING_IMPLEMENTATION_FIX | CFI 기반 콜스택과 원격 스레드 정보 | IMP-021 |
| IMP-012 | P1 | CORE_FUNCTIONAL_COMPLETION | EXISTING_IMPLEMENTATION_FIX | 사람이 읽는 보고서(평이한 결론, 이름과 위치, 한국어) | IMP-006, IMP-007 |
| IMP-013 | P1 | RELIABILITY_AND_VALIDATION | TEST_OR_VERIFICATION | 정답표가 있는 실제 프로세스 정확도 벤치마크 | IMP-005 |
| IMP-014 | P1 | RELIABILITY_AND_VALIDATION | TEST_OR_VERIFICATION | 임베디드 타깃 검증 행렬(에뮬레이터) | IMP-016 |
| IMP-015 | P1 | CORE_FUNCTIONAL_COMPLETION | EXISTING_IMPLEMENTATION_FIX | 타깃 ABI 판별과 미지원 조합 거부 | none |
| IMP-016 | P2 | RELIABILITY_AND_VALIDATION | EXISTING_IMPLEMENTATION_FIX | 수집기 교차 빌드와 배포 방식 개선 | none |
| IMP-017 | P2 | ARCHITECTURAL_IMPROVEMENTS | REFACTORING | 진단 엔진 통합과 도달 불가 코드 제거 | IMP-005, IMP-006, IMP-013 |
| IMP-018 | P2 | ARCHITECTURAL_IMPROVEMENTS | REFACTORING | 선언형 레시피, 구조 기반 후보 선정, 범주 확장 | IMP-013 |
| IMP-019 | P1 | IMMEDIATE_CORRECTIONS | EXISTING_IMPLEMENTATION_FIX | 읽기 전용 기본값과 웹 API 인증 | none |
| IMP-020 | P2 | PERFORMANCE_AND_OPTIMIZATION | NEW_IMPLEMENTATION | 수집이 대상에 준 부하 측정 | IMP-002 |
| IMP-021 | P2 | PERFORMANCE_AND_OPTIMIZATION | INTEGRATION_FIX | 수집기 데몬 모드를 지속 SSH 세션으로 연결 | IMP-016 |
| IMP-022 | P2 | RELIABILITY_AND_VALIDATION | DOCUMENTATION_UPDATE | 의존성 선언, 패키징, README 정정 | IMP-006 |
| IMP-023 | P2 | CORE_FUNCTIONAL_COMPLETION | INTEGRATION_FIX | 진단 워크플로우를 에이전트 스킬로 패키징 | IMP-006 |

## Dependencies and suggested implementation phases

**1단계: 판정을 믿을 수 있게(즉시).** IMP-001, IMP-002, IMP-003, IMP-004, IMP-019, IMP-005.
각각 작고 서로 독립이다. IMP-005는 이후 모든 작업의 안전망이므로 같은 단계에서 시작한다. 이 단계가 끝나면 도구가 "모르면 모른다"고 말하고, 대상을 멈추지 않으며, 회귀를 자동으로 잡는다.

**2단계: 원인 특정 능력(핵심).** IMP-015, IMP-016 → IMP-006, IMP-007 → IMP-008, IMP-009, IMP-010 → IMP-021 → IMP-011.
IMP-007(힙 순회와 역참조 맵)이 이 단계의 중심이고 IMP-008, IMP-009, IMP-012가 여기에 의존한다. IMP-010(스레드 표본)은 IMP-007과 독립이라 병행할 수 있다.

**3단계: 증명과 전달.** IMP-013, IMP-014, IMP-012, IMP-023, IMP-020.
IMP-013은 2단계와 동시에 시작해도 된다. 벤치마크를 먼저 만들어 두면 2단계 작업의 완료 기준이 된다. 여기서 나온 수치가 문서의 "완료" 선언을 대체한다.

**4단계: 구조 정리.** IMP-017, IMP-018, IMP-022.
통합과 리팩터링은 IMP-005와 IMP-013의 안전망이 생긴 뒤에 한다. 커밋 `commit:533a0bb`의 대규모 삭제가 테스트를 깨뜨린 전례가 있다.

```
IMP-005 ─┬─> IMP-006 ─┬─> IMP-012
         │            ├─> IMP-023, IMP-022
         │            └─> IMP-017 (IMP-013도 필요)
         ├─> IMP-007 ─┬─> IMP-008 (IMP-004도 필요)
         │            ├─> IMP-009
         │            └─> IMP-012
         ├─> IMP-010 (IMP-003도 필요)
         └─> IMP-013 ──> IMP-017, IMP-018
IMP-016 ──> IMP-014, IMP-021 ──> IMP-011
IMP-002 ──> IMP-020
```

## Improvement items

### IMP-001 [P0]: 수집 실패를 "정상"으로 바꾸는 경로 제거
- **Group:** IMMEDIATE_CORRECTIONS
- **Work Type:** EXISTING_IMPLEMENTATION_FIX
- **Problem:** 트리아지나 콜스택 수집이 실패하면 사고 보고서가 "정상, 100점, 문제 없음"으로 나온다. 증거가 부족한 실행에서도 "조치 불필요: 정상으로 보임" 문구가 들어간다.
- **Evidence:** `extractor/watch_session.py:11431-11432`, `extractor/watch_session.py:11444-11445`, `extractor/watch_session.py:11524-11537`, `extractor/watch_session.py:7896-7903`, `extractor/expert_diagnostic_engine.py:2060`, `extractor/expert_diagnostic_engine.py:2639-2640`
- **Findings:** F-FUNC-004, F-FUNC-009
- **Requirements:** REQ-009
- **Root Cause:** 감시 세션 경로가 예외를 기본 "정상" 사전으로 대체하고, 집계기의 정상 게이트를 거치지 않는다. 전문가 엔진의 검증 횟수는 단계 결과와 무관하게 증가한다.
- **Proposed Solution:** 예외를 판단 불가 판정과 한계 항목(실패 원인 포함)으로 바꾼다. 증상 조사의 내부 오류 목록을 결과에 포함한다. 검증 횟수는 통과한 단계만 센다. 주요 발견이 없을 때의 조치 문구를 판정에 맞춰 분기한다.
- **Existing Functionality Check:** 판단 불가 처리는 이미 집계기에 있다(`extractor/diagnostic_verdict_aggregator.py:683-723`). 판정 엔진도 관측 0건이면 INCONCLUSIVE를 낸다(`extractor/verdict_engine.py:613-625`). 새 규칙을 만들 필요 없이 이 경로들이 같은 규칙을 쓰게 하면 된다.
- **Expected Benefit:** 가장 해로운 오류(거짓 "문제 없음")가 사라진다.
- **Scope:** S (파일 2개, 수십 줄과 테스트)
- **Dependencies:** none
- **Acceptance Criteria:**
  - 읽기 권한이 없는 PID에 대한 사고 보고서의 판정이 판단 불가이고, 한계 목록에 실패 원인이 있다
  - 트리아지가 예외를 던지도록 한 테스트에서 "정상", "100", "NO_ISSUE_DETECTED"가 결과에 없다
  - 모든 레시피가 증거 부족인 실행의 결론과 조치 문구에 "정상(healthy)"이 없다
- **Verification:** 가짜 어댑터가 예외를 던지는 단위 테스트와, 권한 없는 실제 프로세스에 대한 통합 테스트를 추가해 실행한다.

### IMP-002 [P0]: 기본 수집을 무정지로 바꾸고 정지 시간을 측정값으로 보고
- **Group:** IMMEDIATE_CORRECTIONS
- **Work Type:** EXISTING_IMPLEMENTATION_FIX
- **Problem:** 조사 기본 경로가 대상을 SIGSTOP으로 정지시키는데 보고서는 0.00ms를 고정 출력한다.
- **Evidence:** `extractor/capture_plan.py:26`, `extractor/capture_backend.py:3312-3315`, `extractor/capture_backend.py:3518`, `extractor/investigation.py:1452`, `extractor/watch_session.py:11474`, `extractor/expert_diagnostic_engine.py:2979`
- **Findings:** F-RISK-001
- **Requirements:** NFR-001, NFR-006
- **Root Cause:** 캡처 플랜의 기본 모드가 FULL이고 호출자가 플랜을 넘기지 않는다. 보고서의 수집 모드와 정지 시간은 수집 경로에서 전달받지 않고 상수로 채운다.
- **Proposed Solution:** 플랜 기본 모드를 ZERO_STOP으로 바꾼다. 정지 모드는 호출자가 명시적으로 승인 플래그를 줄 때만 허용한다. 캡처 결과의 실제 모드와 측정된 정지 시간을 보고서까지 전달한다.
- **Existing Functionality Check:** ZERO_STOP 모드와 정지 시간 측정은 이미 캡처 백엔드에 있다(`extractor/capture_backend.py:3313-3315`, `extractor/capture_backend.py:4127-4135`). 예산 추적기에도 정지 시간 필드가 있다(`extractor/observation_budget.py:34-43`). 기본값과 전달 경로만 고치면 된다.
- **Expected Benefit:** 문서가 약속한 "기본 무정지"가 사실이 되고, 정지가 있었다면 사용자가 안다.
- **Scope:** S~M (기본값 변경, 호출자 3~5곳, 보고서 필드 전달)
- **Dependencies:** none
- **Acceptance Criteria:**
  - 플랜 없이 캡처를 호출하면 대상에 SIGSTOP이 전달되지 않는다(대상의 `/proc/PID/stat` 상태가 T가 되지 않음)
  - 승인 플래그 없이 정지 모드를 요청하면 거부된다
  - 정지 모드로 수집한 보고서의 정지 시간이 0이 아닌 측정값이다
  - 소스에 "0.00ms" 고정 문자열이 남아 있지 않다
- **Verification:** 실제 대상 프로세스로 `investigate`를 실행하면서 별도 스레드가 대상 상태를 폴링하는 테스트. `rg "0.00ms" extractor`가 0건.

### IMP-003 [P1]: 교착 지속성 기본값 수정
- **Group:** IMMEDIATE_CORRECTIONS
- **Work Type:** EXISTING_IMPLEMENTATION_FIX
- **Problem:** 한 번 관측한 순환 대기가 "연속 표본으로 검증된 교착, 0.98"로 보고될 수 있다.
- **Evidence:** `extractor/diagnostic_recipes.py:1537`, `extractor/diagnostic_recipes.py:1570-1584`
- **Findings:** F-FUNC-005
- **Requirements:** REQ-007
- **Root Cause:** 지속성 플래그와 관측 횟수의 기본값이 "지속됨" 쪽이고, 수집기가 이 값을 넘기지 않는다.
- **Proposed Solution:** 기본값을 `cycle_persistent=False`, 관측 횟수 1로 바꾼다. 수집기는 순환을 보면 짧은 간격으로 한 번 더 관측해 같은 순환이 유지되는지와 관측 횟수를 넘긴다.
- **Existing Functionality Check:** 단일 관측을 "순환 대기 관측"으로 구분하는 분기는 이미 있다(`extractor/diagnostic_recipes.py:1585-1587`). 다회 관측 의미론은 `extractor/concurrency_graph.py:278-355`에 구현되어 있으나 연결되지 않았다. 완전한 연결은 IMP-010이 맡고, 이 항목은 기본값과 재관측만 다룬다.
- **Expected Benefit:** 순간 경합을 교착으로 오판하지 않고, 보고서 근거 문구가 사실과 일치한다.
- **Scope:** S
- **Dependencies:** none
- **Acceptance Criteria:**
  - 순환 정보만 있고 지속성 키가 없는 입력에 대해 레시피가 "지속 교착"을 내지 않는다
  - 실제 교착 프로세스에서는 두 번 관측 후 지속 교착으로 판정된다
  - 짧게 경합했다가 풀리는 프로세스에서는 교착 판정이 나오지 않는다
- **Verification:** 레시피 단위 테스트 2건과, 기존 교착·경합 대상 프로그램(`tests/fixtures/real_runtime/proc_thread_circular_deadlock.c`, `tests/fixtures/real_runtime/proc_scenario_c_thread_contention.c`)에 대한 통합 테스트.

### IMP-004 [P1]: 메모리 증가 후속 단계 생성 결함 수정
- **Group:** IMMEDIATE_CORRECTIONS
- **Work Type:** EXISTING_IMPLEMENTATION_FIX
- **Problem:** 메모리 증가가 확인된 직후 후속 조사 단계를 만들 때 필수 인자 5개가 빠져 예외가 날 것으로 보인다.
- **Evidence:** `extractor/expert_diagnostic_engine.py:730-743`, `extractor/expert_diagnostic_engine.py:2100-2116`
- **Findings:** F-FUNC-008
- **Requirements:** REQ-004
- **Root Cause:** 단계 데이터 클래스에 필드가 추가된 뒤 이 생성 지점이 갱신되지 않았고, 이 분기를 통과하는 테스트가 없다.
- **Proposed Solution:** 계획 단계 생성에 쓰는 점수 계산 함수를 재사용해 후속 단계를 만든다. 증가하는 실제 프로세스로 이 분기를 통과하는 테스트를 추가한다.
- **Existing Functionality Check:** 정상적인 단계 생성과 점수 계산은 계획 수립 코드에 있다(`extractor/expert_diagnostic_engine.py:825-836`). 같은 함수를 호출하면 된다.
- **Expected Benefit:** 누수 조사가 "증가 확인"에서 중단되지 않고 원인 좁히기로 이어진다.
- **Scope:** S
- **Dependencies:** none
- **Acceptance Criteria:**
  - 증가 레시피가 지지되고 후속 레시피가 계획에 없을 때 예외 없이 후속 단계 2개가 추가된다
  - 추가된 단계가 실제로 실행되어 결과를 남긴다
- **Verification:** `run_recipe`로 증가 레시피만 실행하는 테스트(후속 단계가 계획에 없는 조건)를 증가 대상 프로그램에 대해 실행한다.

### IMP-005 [P0]: 테스트 기준선 확보와 CI 가동
- **Group:** RELIABILITY_AND_VALIDATION
- **Work Type:** TEST_OR_VERIFICATION
- **Problem:** CI가 가동된 적이 없고, 교착 검증 테스트 11개 파일이 삭제된 심볼을 참조한다. 어떤 요구사항도 실행 증거가 없다.
- **Evidence:** `ci/README.md:34`, `tests/test_phase2_0_a_3_4_1_deadlock_evidence_and_budget.py:74-84`, `tests/test_ci_workflow_parity.py:37-41`, `ci/workflows/test.yml:376-378`, `tests/test_phase2_4_real_world_targets.py:276-278`
- **Findings:** F-TEST-001, F-TRACE-001, F-QUAL-001
- **Requirements:** REQ-007, NFR-003
- **Root Cause:** 워크플로우를 올릴 토큰 권한이 없어 CI를 켜지 못했고, 대규모 삭제 커밋(`commit:533a0bb`) 뒤에 전체 테스트를 돌려 확인하는 관문이 없었다.
- **Proposed Solution:** (1) Linux에서 `python3 -m unittest discover tests`를 한 번 실행해 결과 전체를 저장한다. (2) 실패를 "현재 API로 이식", "폐기", "실제 결함"으로 분류한다. 교착 음성 대조군 테스트는 이식 우선이다. (3) aarch64 단언처럼 호스트에 묶인 테스트를 고친다. (4) `workflow` 권한이 있는 토큰으로 워크플로우를 올리거나, 권한이 필요 없는 다른 CI에 연결한다. (5) 테스트 의존성 설치 단계를 워크플로우에 넣는다.
- **Existing Functionality Check:** 워크플로우 정의(`ci/workflows/test.yml`)와 동기화 스크립트(`scripts/sync_workflows.sh`), 전체 실행 스크립트(`run_all_tests.sh`)가 이미 있다. 새로 만들 것은 없고 가동과 정리가 필요하다.
- **Expected Benefit:** 이후 모든 변경에 안전망이 생기고, "통과" 숫자가 기록으로 남는다.
- **Scope:** M (실패 분류 규모에 따라 달라짐)
- **Dependencies:** none
- **Acceptance Criteria:**
  - 전체 테스트 실행 결과(통과, 실패, 건너뜀 수와 목록)가 파일로 남아 있다
  - 삭제된 심볼을 import하는 테스트 파일이 0개다
  - 푸시마다 CI가 실행되고 x86_64 러너에서 통과한다
  - 교착 양성 2건, 음성 대조군 2건(조건 변수 대기, 단순 경합)이 CI에서 실제 프로세스로 실행된다
- **Verification:** CI 실행 기록. `rg "WaitForEdge|resolve_mutex_owner" tests`가 0건이거나 해당 심볼이 소스에 존재.

### IMP-006 [P1]: 단일 `diagnose` 진입점
- **Group:** CORE_FUNCTIONAL_COMPLETION
- **Work Type:** INTEGRATION_FIX
- **Problem:** "PID 진단" 한 번의 요청으로 끝까지 가는 경로가 없고, 인터페이스마다 다른 엔진으로 간다.
- **Evidence:** `scripts/mcp_server.py:508-510`, `scripts/mcp_server.py:687-688`, `extractor/expert_diagnostic_engine.py:2915-2916`, `extractor/cli.py:867-880`, `extractor/web/server.py:3721-3737`
- **Findings:** F-FUNC-007, F-ARCH-001
- **Requirements:** REQ-001
- **Root Cause:** 엔진이 단계적으로 추가되면서 기존 인터페이스 연결을 옮기지 않았다.
- **Proposed Solution:** 전문가 엔진에 `diagnose(pid, debug_image, 증상 설명)` 함수를 하나 두고 분류부터 보고서까지 실행하게 한다. MCP 도구 `runtime_diagnose_process`, CLI `diagnose`, 웹 엔드포인트가 모두 이 함수를 부른다. 결과는 판정, 평이한 요약, 보고서 경로를 포함한다. 기존 다단계 도구는 그대로 두되 이 함수의 부분 단계로 표시한다.
- **Existing Functionality Check:** 끝까지 실행하는 `run_to_completion`과 보고서 생성이 이미 있다(`scripts/mcp_server.py:687-688`, `extractor/expert_diagnostic_engine.py:2913`). `rg -i "def diagnose|runtime_diagnose"`로 찾은 단일 진입점은 없다. 가장 가까운 `runtime_investigate_symptom`(`scripts/mcp_server.py:2260-2290`)은 감시 세션 엔진을 쓴다. 새 엔진이 아니라 기존 호출을 묶는 작업이다.
- **Expected Benefit:** OBJ-003의 사용 흐름이 실제로 한 번의 요청이 된다. 인터페이스 간 판정이 일치한다.
- **Scope:** M
- **Dependencies:** IMP-001, IMP-005
- **Acceptance Criteria:**
  - MCP, CLI, 웹에서 같은 PID를 진단하면 같은 판정 값과 같은 보고서 구조가 나온다
  - 한 번의 호출 결과에 판정, 실행한 검사 목록, 확인하지 못한 범위, 보고서가 들어 있다
  - 계획만 세우고 실행하지 않은 상태의 보고서가 만들어질 수 없다
- **Verification:** 세 인터페이스로 같은 대상 프로그램을 진단해 판정을 비교하는 테스트. MCP 표준입출력 종단 간 테스트(`tests/test_phase2_4_4_mcp_e2e.py`)를 새 도구로 확장.

### IMP-007 [P1]: 힙 순회기와 역참조 맵(주소 → 변수)
- **Group:** CORE_FUNCTIONAL_COMPLETION
- **Work Type:** NEW_IMPLEMENTATION
- **Problem:** 임의의 힙·데이터 주소가 어떤 변수의 것인지 찾을 수 없다. 누수와 오버플로우의 "어떤 변수인가"에 답하지 못한다.
- **Evidence:** `extractor/watch_session.py:3588-3598`, `extractor/watch_session.py:4380-4404`, `extractor/watch_session.py:7171-7178`, `extractor/allocator_inspector.py:203-219`
- **Findings:** F-FUNC-001
- **Requirements:** REQ-006
- **Root Cause:** 모든 메모리 도구가 "이름에서 주소로" 정방향으로만 설계되었고, 할당자 해석이 청크 1개 수준에서 멈췄다.
- **Proposed Solution:** 세 부분으로 만든다. (1) 힙 순회: glibc의 아레나에서 시작해 청크를 차례로 읽어 `{주소, 크기, 사용 중 여부}` 목록을 만든다. tcache와 fastbin에 들어 있는 청크는 해제된 것으로 표시한다. mmap 청크와 스레드 아레나를 포함한다. (2) 타입 기반 도달 그래프: DWARF 전역과 각 스레드의 스택 프레임 지역 변수에서 출발해 포인터를 따라가며 `청크 → 경로 이름`(예: `g_cache.entries[3].data`)을 기록한다. (3) 역조회 API와 MCP 도구: 주소를 주면 소속 청크, 크기, 그것을 가리키는 경로 이름 목록을 돌려준다. 어떤 경로로도 도달되지 않는 사용 중 청크는 누수 후보다. 읽기는 기존 무정지 슬라이스 경로와 예산 추적기를 쓴다.
- **Existing Functionality Check:** `rg -i "malloc_state|main_arena|tcache|walk_heap|reverse_|referrer|backref|address_to|symbolize"`를 `extractor/`, `scripts/`, `target/`에 실행: 구현 없음(레시피 설명 문구와 플래그 이름만). 재사용할 부품은 있다: 청크 헤더 해석(`extractor/allocator_inspector.py:203-219`), 포인터 패턴 검색(`extractor/watch_session.py:7171-7178`), 타입 디코더와 순환 감지(`extractor/cpp_decoder.py`), 전역 변수 색인(`extractor/dwarf_indexer.py`). 가상 함수 객체 전용 스캔(`extractor/watch_session.py:7023-7052`)은 이 기능으로 대체된다.
- **Expected Benefit:** 사용자가 든 대표 질문에 직접 답한다. IMP-008, IMP-009, IMP-012의 토대다.
- **Scope:** L (새 모듈 1~2개와 MCP 도구, glibc 버전별 배치 처리)
- **Dependencies:** IMP-005
- **Acceptance Criteria:**
  - 대상 프로그램에서 `malloc`한 블록의 주소를 주면 그것을 가리키는 전역 경로 이름과 블록 크기가 나온다
  - 지역 변수만 가리키는 블록은 "스레드 이름, 함수, 변수 이름"으로 나온다
  - 포인터를 지운 블록(진짜 누수)은 "도달 경로 없음"으로 분류되고, 살아 있는 블록은 누수 후보에 없다
  - 순수 C 구조체와 가상 함수 없는 객체에서도 동작한다
  - glibc가 아닌 타깃에서는 "지원하지 않는 할당자"로 거부한다
  - 64MB 힙을 순회하는 동안 대상에 신호나 정지가 없다
- **Verification:** 정답 주소와 변수 이름을 표준출력으로 내는 C 대상 프로그램을 만들고, 도구 출력과 비교하는 테스트. IMP-013 벤치마크의 누수·소유자 사례에 포함.

### IMP-008 [P1]: 누수 주체 특정
- **Group:** CORE_FUNCTIONAL_COMPLETION
- **Work Type:** EXISTING_IMPLEMENTATION_FIX
- **Problem:** 누수 진단이 "RSS가 늘어난다"에서 멈춘다. 확정 경로의 입력은 실제 수집에서 만들어지지 않고, 엔진은 관측 사이에 기다리지 않는다.
- **Evidence:** `extractor/temporal_observation_window.py:472-481`, `extractor/temporal_observation_window.py:55-56`, `extractor/runtime_evidence_provider.py:972-980`, `extractor/expert_diagnostic_engine.py:1191-1192`
- **Findings:** F-FUNC-002
- **Requirements:** REQ-004
- **Root Cause:** 누수 판정 규칙은 할당자 통계를 기대하지만 그것을 만드는 수집기가 없었다.
- **Proposed Solution:** 엔진이 설정된 간격으로 3회 이상 관측하게 한다. 각 관측에서 IMP-007의 힙 순회로 사용 중 청크 수와 총 크기를 구해 `live_allocations_count`, `allocator_heap_kb`를 채운다. 관측 간 차이를 크기 등급과 도달 경로별로 집계해 "어떤 경로 아래에서 얼마나 늘었는지"를 낸다. mmap 영역도 합산한다.
- **Existing Functionality Check:** 시간 창 분석과 누수·일시 증가 구분 규칙은 이미 있다(`extractor/temporal_observation_window.py:379-398`, `extractor/temporal_observation_window.py:472-506`). 관측 간격 값도 세션에 저장된다(`extractor/expert_diagnostic_engine.py:1191-1192`). 빠진 것은 입력 생산과 대기뿐이다.
- **Expected Benefit:** "누수인가"가 추정에서 확정으로, "어디서"가 변수 경로로 나온다.
- **Scope:** M
- **Dependencies:** IMP-004, IMP-007
- **Acceptance Criteria:**
  - 리스트에 계속 추가만 하는 대상 프로그램에서 판정이 누수 확정이고, 증가 경로로 그 리스트의 전역 이름이 나온다
  - 포인터를 버리는 누수에서는 "도달 경로 없는 블록 N개, 크기 등급 X"가 나온다
  - 일시적으로 늘었다 줄어드는 대상에서는 누수 판정이 나오지 않는다
  - 큰 블록(mmap 처리)만 새는 대상에서도 증가가 잡힌다
- **Verification:** 기존 대상 프로그램(`tests/fixtures/real_runtime/proc_scenario_b_growing_mem.c`, `tests/fixtures/real_runtime/proc_mem_burst_and_drop.c`)과 새 대상에 대한 통합 테스트. Phase 2.4.4가 보류한 시나리오 B, C를 닫는다.

### IMP-009 [P1]: 버퍼 오버플로우 탐지
- **Group:** CORE_FUNCTIONAL_COMPLETION
- **Work Type:** NEW_IMPLEMENTATION
- **Problem:** 버퍼가 자기 크기를 넘어 썼는지 확인하는 검사가 없다. "손상"은 특정 이름과 독성 값에 의존한다.
- **Evidence:** `extractor/watch_session.py:5731-5737`, `extractor/watch_session.py:2432-2437`, `extractor/runtime_evidence_provider.py:767-779`
- **Findings:** F-FUNC-003
- **Requirements:** REQ-005
- **Root Cause:** 포인터 뒤 버퍼의 크기를 알 방법이 없었다(힙 순회 부재).
- **Proposed Solution:** 세 가지 검사를 추가한다. (1) 힙: 순회 중 청크 헤더의 크기 필드가 비정상(정렬 위반, 다음 청크와 불일치)이면 바로 앞 청크가 넘쳤다고 보고, IMP-007의 역조회로 앞 청크의 소유 변수를 이름으로 낸다. 타입이 요구하는 크기가 청크 크기보다 크면 "타입 대비 작은 할당"으로 보고한다. (2) 전역: DWARF 크기가 있는 배열 바로 뒤 전역의 값이 타입 범위를 벗어났거나 관측 간에 설명 없이 바뀌면 인접 덮어쓰기 후보로 보고한다. (3) 스택: 각 스레드 스택의 사용 깊이와 가드 영역까지의 여유를 `/proc/PID/maps`와 스택 포인터로 계산해 임계 이하면 보고한다.
- **Existing Functionality Check:** `rg -i "stack.?canary|__stack_chk|redzone|adjacent|clobber|usable_size|overflow"`: 분류기 키워드와 bool 범위 검사 이름(`extractor/watch_session.py:5862-5873`)만 있다. 청크 크기 계산은 있으나 비교에 쓰이지 않는다(`extractor/allocator_inspector.py:269`). 가드 페이지 인식은 레시피에 있다(`extractor/diagnostic_recipes.py:1122-1131`).
- **Expected Benefit:** 오버플로우를 넘친 버퍼의 변수 이름과 함께 보고한다.
- **Scope:** L
- **Dependencies:** IMP-007
- **Acceptance Criteria:**
  - 힙 버퍼를 8바이트 넘겨 쓴 대상에서 손상된 청크와 넘친 버퍼의 소유 변수 이름이 나온다
  - 전역 배열을 넘겨 인접 전역을 덮은 대상에서 두 변수 이름이 나온다
  - 정상 대상 프로그램 전부에서 오버플로우 보고가 0건이다
  - 스택 여유가 임계 이하인 스레드가 이름과 여유 바이트 수로 보고된다
- **Verification:** 결함을 심은 대상 3종과 정상 대상에 대한 통합 테스트. IMP-013에 포함.

### IMP-010 [P1]: 스레드 시계열 표본 수집과 규칙 연결
- **Group:** CORE_FUNCTIONAL_COMPLETION
- **Work Type:** INTEGRATION_FIX
- **Problem:** 스레드 오동작 규칙(기아, 정지, 폭주)은 선언되어 있으나 입력을 만드는 수집기가 없다. 다회 관측 그래프 클래스는 채워지지 않는다.
- **Evidence:** `extractor/diagnostic_recipes.py:2106-2177`, `extractor/diagnostic_recipes.py:769-897`, `extractor/concurrency_graph.py:129-402`, `extractor/expert_diagnostic_engine.py:1228`, `extractor/watch_session.py:8054-8084`
- **Findings:** F-FUNC-006, F-FUNC-005, F-FUNC-012
- **Requirements:** REQ-008, REQ-007
- **Root Cause:** 규칙과 그래프 모델을 먼저 만들고 수집기 연결은 테스트의 수동 주입으로 대신했다.
- **Proposed Solution:** 스레드마다 N회(기본 5회, 간격 설정 가능) 표본을 모으는 수집기를 만든다. 표본은 상태, utime·stime, 자발·비자발 문맥 전환, 현재 시스템콜, 최상위 프레임이다. 여기서 파생 값을 계산한다: 같은 프레임에 머문 시간, CPU 점유율, 대기 시간, 스레드 수 추세. 이 값을 기존 레시피 입력 키로 넘긴다. 락 검사 결과를 표본마다 `WaitForGraph`에 넣어 지속성을 판정하게 한다. mutex 후보를 전역뿐 아니라 구조체 멤버와 대기 중인 futex 주소로 넓힌다.
- **Existing Functionality Check:** 표본의 원재료는 로컬 어댑터가 이미 읽는다(`extractor/target_adapter.py:1123-1253`). CPU 시간 차이 계산은 핫스폿 프로파일러에 있다(`extractor/watch_session.py:8054-8084`). 판정 규칙(`extractor/diagnostic_recipes.py:2106-2177`)과 그래프 의미론(`extractor/concurrency_graph.py:278-355`)도 있다. 스케줄러 대기 시간(`schedstat`)과 우선순위 역전은 `rg`로 찾지 못했으므로 이 항목 범위에서 제외하고 후속으로 둔다.
- **Expected Benefit:** "특정 스레드가 오동작하는가"에 교착 외의 답(바쁜 대기, 장시간 정지, 기아)이 나온다.
- **Scope:** M~L
- **Dependencies:** IMP-003, IMP-005
- **Acceptance Criteria:**
  - 무한 루프 스레드가 있는 대상에서 그 스레드가 이름, 함수, CPU 점유율과 함께 "진전 없는 CPU 독점"으로 판정된다
  - 한 시스템콜에 표본 전체 기간 머문 스레드가 "장시간 대기"로 보고되고, 조건 변수로 정상 대기하는 작업 스레드는 문제로 보고되지 않는다
  - 구조체 멤버 mutex로 인한 교착이 탐지되고 락이 `변수.멤버` 이름으로 나온다
  - 테스트가 `starvation_detected` 같은 답을 직접 주입하지 않는다
- **Verification:** 기존 스레드 대상 프로그램(`tests/fixtures/real_runtime/proc_thread_normal_cv.c`, `tests/fixtures/real_runtime/proc_two_waiters_one_lock.c`)과 새 대상(스핀, 멤버 mutex 교착)에 대한 통합 테스트. 판정에 스레드 이름과 락 이름을 단언.

### IMP-011 [P1]: CFI 기반 콜스택과 원격 스레드 정보
- **Group:** CORE_FUNCTIONAL_COMPLETION
- **Work Type:** EXISTING_IMPLEMENTATION_FIX
- **Problem:** 콜스택이 스택 스캔 휴리스틱이라 유령 프레임이 나올 수 있고, 원격 경로에서는 스택 포인터·CPU 시간·시스템콜을 얻지 못한다.
- **Evidence:** `extractor/watch_session.py:5561-5606`, `extractor/watch_session.py:5587-5600`, `extractor/target_adapter.py:1781-1788`, `extractor/watch_session.py:5481`, `extractor/dwarf_indexer.py:653-654`
- **Findings:** F-FUNC-013
- **Requirements:** REQ-007, NFR-004
- **Root Cause:** 무정지 조건에서 레지스터를 얻기 어려워 스캔으로 대체했고, 원격 어댑터는 최소 필드만 구현했다.
- **Proposed Solution:** (1) 대기 중인 스레드는 `/proc/PID/task/TID/syscall`의 스택 포인터와 PC에서 시작해 CFI 표로 프레임을 되감는다. 되감기에 실패한 구간만 스캔으로 보충하고 그 프레임에 "추정" 표시를 한다. (2) 실행 중인 스레드는 연속 2회 읽기로 스택 상단을 추정하고 결과에 "실행 중 표본"이라고 표시한다. (3) C 수집기에 스레드 정보 명령을 추가해 원격에서도 로컬과 같은 필드를 얻는다. (4) 시스템콜 이름표를 아키텍처별로 둔다.
- **Existing Functionality Check:** CFI 표 파서가 있다(`extractor/dwarf_indexer.py:653-654`)는 것을 확인했으나 스레드 검사 경로에서 프레임 되감기에 쓰이지 않는다. 수집기 소스에는 스레드 열거 코드가 없다(`rg "task" target/collector/src/collector.c` 결과 없음). 로컬의 필드 수집은 `extractor/target_adapter.py:1123-1253`에 있어 필드 정의를 재사용한다.
- **Expected Benefit:** "어디서 멈췄는가"의 답이 정확해지고, 임베디드 원격 타깃에서도 스레드 진단이 가능해진다.
- **Scope:** L
- **Dependencies:** IMP-021
- **Acceptance Criteria:**
  - 깊이 5의 알려진 호출 경로에서 대기 중인 스레드의 콜스택이 정답과 프레임 순서까지 일치하고 유령 프레임이 없다
  - 원격 어댑터가 스레드별 상태, CPU 시간, 문맥 전환, 시스템콜, 스택 포인터를 돌려준다
  - aarch64 대상에서 futex 대기가 올바른 이름으로 인식된다
  - 스캔으로 보충한 프레임은 출력에 추정 표시가 있다
- **Verification:** 호출 경로가 고정된 대상 프로그램에 대한 정답 비교 테스트. IMP-014의 에뮬레이터 타깃에서 원격 스레드 검사 실행.

### IMP-012 [P1]: 사람이 읽는 보고서(평이한 결론, 이름과 위치, 한국어)
- **Group:** CORE_FUNCTIONAL_COMPLETION
- **Work Type:** EXISTING_IMPLEMENTATION_FIX
- **Problem:** 보고서가 열거값과 ID 중심이고, 원인 대상이 변수·스레드 이름이 아니라 범주로 나오며, 일부 대상 정보는 합성값이다.
- **Evidence:** `extractor/diagnostic_report.py:558-565`, `extractor/expert_diagnostic_engine.py:3049-3052`, `extractor/expert_diagnostic_engine.py:2623-2640`, `extractor/expert_diagnostic_engine.py:2972-2979`
- **Findings:** F-FUNC-010
- **Requirements:** REQ-010
- **Root Cause:** 보고서 모델이 감사 가능성(증거 ID, 규칙 ID)을 중심으로 설계되었고, 수집 단계의 이름·위치 정보가 결론까지 전달되지 않는다.
- **Proposed Solution:** 기존 보고서 모델은 유지하고 맨 앞에 사람용 요약 층을 추가한다. 구성: (1) 한 문장 결론, (2) 무엇이 문제인가(변수 경로, 스레드 이름, 락 이름, 소스 파일과 줄), (3) 왜 그렇게 판단했는가(관측 → 추론을 3~5줄로), (4) 얼마나 확실한가와 확인하지 못한 것, (5) 다음에 할 일(발견된 대상에 맞춘 구체 조치), (6) 수집이 대상에 준 영향(측정값). 교착은 대기 그래프, 메모리는 영역 지도, 추세는 시간 그래프를 그림으로 넣는다. 용어 풀이를 붙인다. 출력 언어를 선택할 수 있게 하고 한국어를 지원한다. 프로세스 이름·시작 시각은 `/proc`에서 읽은 값을 쓴다. 영향 대상 필드에는 범주가 아닌 실제 이름을 채운다.
- **Existing Functionality Check:** 섹션 구조, 한계 섹션, 인식 수준 구분은 이미 있다(`extractor/diagnostic_report.py:338-390`, `extractor/diagnostic_report.py:817`). 소스 위치와 인과 관계 필드도 모델에 있으나 채워지지 않는다(`rg "source_references=|causal_relationships="` 0건). 감시 세션 트리아지의 조치 문구는 락·TID·표현식을 이름으로 쓴다(`extractor/watch_session.py:6696-6699`). 이 방식을 가져온다. 대기 그래프 데이터는 있다(`extractor/concurrency_graph.py:130`). LLM 서술은 근거 접지 장치가 있는 대화 경로(`extractor/conversational_investigation.py:486-571`)를 선택 기능으로 재사용할 수 있으나 기본은 결정적 템플릿으로 둔다.
- **Expected Benefit:** OBJ-004. 내부 ID를 해석하지 않고도 상황을 이해한다.
- **Scope:** M~L
- **Dependencies:** IMP-006, IMP-007
- **Acceptance Criteria:**
  - 교착 대상의 보고서 첫 화면에 두 스레드의 이름, 두 락의 변수 이름, 멈춘 함수와 소스 줄이 문장으로 나온다
  - 누수 대상의 보고서에 증가 경로의 변수 이름과 증가량이 나온다
  - 한국어 출력을 선택하면 요약 층 전체가 한국어다
  - 보고서의 프로세스 이름, 정지 시간, 읽은 바이트가 관측값이다(고정값·합성값 없음)
  - 판정이 판단 불가이면 첫 문장이 그 사실과 이유를 말한다
- **Verification:** 대상별 보고서에 정답 이름이 포함되는지 단언하는 테스트. 프로젝트에 참여하지 않은 엔지니어 2~3명에게 보고서만 주고 "무엇이 문제이고 어디를 봐야 하는가"를 맞히는지 확인하는 읽기 시험.

### IMP-013 [P1]: 정답표가 있는 실제 프로세스 정확도 벤치마크
- **Group:** RELIABILITY_AND_VALIDATION
- **Work Type:** TEST_OR_VERIFICATION
- **Problem:** 정확도 테스트가 상수를 단언하거나 답을 주입하고, 문서의 100% 주장은 뒷받침이 없다. 탐지 규칙이 테스트 대상의 이름·값에 맞춰져 있을 가능성이 높다.
- **Evidence:** `tests/test_phase2_4_1_recipe_accuracy_and_evidence_path.py:421-430`, `tests/test_phase2_1_8_complete_validation.py:889-896`, `docs/PHASE_2_4_FINAL_REPORT.md:103-104`, `docs/PHASE_2_4_4_FINAL_REPORT.md:127-135`, `extractor/runtime_evidence_provider.py:592-617`
- **Findings:** F-TEST-002, F-INTENT-001, F-ARCH-003, F-QUAL-001
- **Requirements:** REQ-004, REQ-005, REQ-007, REQ-008
- **Root Cause:** 규칙 작성자와 테스트 대상 작성자가 같고, 테스트가 규칙의 입출력만 확인한다.
- **Proposed Solution:** 결함 유형별 대상 프로그램 묶음을 만든다. 각 대상에 정답 파일을 둔다: 결함 종류, 원인 변수 경로 또는 스레드·락 이름, 소스 위치. 채점기는 `diagnose` 한 번의 결과를 정답과 비교해 탐지 여부, 원인 이름 일치, 오탐을 센다. 구성: 정상 대조군(바쁜 서버, 유휴 서버, 조건 변수 대기 등), 결함 대상, 그리고 **이 프로젝트 밖에서 온 코드**(공개 소형 C 프로젝트에 결함을 심은 것)로 이름 관례 의존을 드러낸다. 결과는 실행 환경과 함께 파일로 저장하고 CI에서 실행한다.
- **Existing Functionality Check:** 실제 프로세스 대상 프로그램 22개가 이미 있다(`tests/fixtures/real_runtime/`). 벤치마크 틀도 있다(`benchmarks/investigation_quality/run_benchmark.py`). 다만 커밋된 결과는 스모크 2건이고 인과 귀속 한 종류만 다룬다. `extractor/evaluation.py`는 합성 사례 평가기다. 대상 프로그램은 재사용하고 정답 파일과 이름 채점을 추가한다.
- **Expected Benefit:** 프로젝트의 실제 진단 능력이 숫자로 나오고, 이후 모든 작업의 완료 기준이 된다. 문서의 자기 선언을 대체한다.
- **Scope:** M
- **Dependencies:** IMP-005
- **Acceptance Criteria:**
  - 결함 유형 6종 이상(누수, 힙 오버플로우, 해제 후 사용, 교착, 바쁜 대기, 장시간 정지)에 각각 2개 이상의 대상과 정답 파일이 있다
  - 정상 대조군이 5개 이상이고 오탐 수가 보고된다
  - 외부 코드 기반 대상이 3개 이상이다
  - 채점 코드에 대입한 상수를 단언하는 줄이 없다
  - 결과 파일에 대상별 탐지 여부, 원인 이름 일치 여부, 실행 환경이 기록된다
- **Verification:** CI에서 벤치마크 실행. 채점기 자체를 "모든 답이 틀린 가짜 진단기"로 돌려 0점이 나오는지 확인.

### IMP-014 [P1]: 임베디드 타깃 검증 행렬(에뮬레이터)
- **Group:** RELIABILITY_AND_VALIDATION
- **Work Type:** TEST_OR_VERIFICATION
- **Problem:** ARM32, musl, 저사양 환경에서 수집기와 진단 경로가 실행된 기록이 없다.
- **Evidence:** `benchmarks/latest_results.json:3-9`, `extractor/production_pilot.py:672-675`, `tests/test_phase2_4_real_world_targets.py:253-267`, `ci/workflows/test.yml:27-29`
- **Findings:** F-TEST-003
- **Requirements:** NFR-003, NFR-004
- **Root Cause:** 개발과 측정이 aarch64 서버 한 대에서만 이뤄졌다.
- **Proposed Solution:** QEMU 시스템 에뮬레이션으로 타깃 행렬을 만든다. 최소 구성: ARM32 + glibc, ARM32 + musl(BusyBox 루트 파일시스템), aarch64 + glibc. 각 타깃에서 대상 프로그램을 띄우고 호스트에서 SSH로 `diagnose`를 실행한다. 메모리 64~128MB, 단일 코어로 제한해 저사양을 흉내 낸다. 실제 보드 1종에서의 수동 실행 절차와 기록 양식을 문서로 둔다.
- **Existing Functionality Check:** `rg -i "qemu|musl|busybox|uclibc"`를 `tests/`, `ci/`, `docker/`, `scripts/`에 실행: 사용 없음(musl은 거부 사례 문자열로만). 원격 어댑터 테스트는 가짜 명령 실행기를 쓴다. GDB 9.2용 Docker 환경(`docker/gdb92/Dockerfile`)이 있어 컨테이너 기반 테스트 방식은 선례가 있다.
- **Expected Benefit:** "임베디드 지원"이 검증된 사실이 된다. F-RISK-002의 추론이 확정되거나 기각된다.
- **Scope:** M~L
- **Dependencies:** IMP-016
- **Acceptance Criteria:**
  - 세 타깃 각각에서 수집기가 실행되어 슬라이스 읽기에 성공한다
  - ARM32 + glibc에서 교착 대상의 판정이 호스트와 같다
  - musl 타깃에서 glibc 전용 검사는 "지원하지 않음"으로 나오고 틀린 값을 내지 않는다
  - 행렬 실행 결과가 타깃별로 기록된다
- **Verification:** CI의 별도 작업으로 행렬 실행. 실제 보드 실행 기록 1건 이상을 저장소에 첨부.

### IMP-015 [P1]: 타깃 ABI 판별과 미지원 조합 거부
- **Group:** CORE_FUNCTIONAL_COMPLETION
- **Work Type:** EXISTING_IMPLEMENTATION_FIX
- **Problem:** x86_64·glibc·64비트 리틀 엔디언 가정이 다른 타깃에서 거부되지 않고 적용되어 틀린 결과를 낼 수 있다.
- **Evidence:** `extractor/watch_session.py:5459-5463`, `extractor/watch_session.py:5416-5421`, `extractor/allocator_inspector.py:701-708`, `extractor/target_adapter.py:1338-1349`, `extractor/target_adapter.py:2156-2162`
- **Findings:** F-RISK-002
- **Requirements:** NFR-004
- **Root Cause:** ABI 판별 로직이 대규모 삭제 때 사라지고 상수만 남았다.
- **Proposed Solution:** 연결 시점에 타깃의 아키텍처, 워드 크기, 엔디언, libc 종류와 버전을 판별해 세션에 기록한다(ELF 헤더, 인터프리터 경로, 매핑된 libc 파일명). mutex 해석, 할당자 해석, 시스템콜 이름, TCB 스캔은 지원 조합 표를 확인하고 미지원이면 "이 타깃에서는 지원하지 않음"을 돌려준다. 시스템콜 표는 x86_64, aarch64, arm을 둔다.
- **Existing Functionality Check:** ABI 상수와 결과 타입이 남아 있다(`extractor/target_adapter.py:2143-2162`, `extractor/target_adapter.py:2200`). 이를 쓰던 `resolve_mutex_owner`는 `commit:533a0bb`에서 삭제되었으므로 git 이력에서 복원할 수 있다. ELF 아키텍처 판별은 `inspect_elf`에 있다(`extractor/target_adapter.py:2083-2084`). 포인터 크기와 엔디언은 DWARF에서 얻는 코드가 있다(`extractor/watch_session.py:5344-5346`).
- **Expected Benefit:** 미지원 타깃에서 조용한 오진 대신 명시적 거부. 워크플로우 명세의 "추측 금지" 원칙과 일치.
- **Scope:** M
- **Dependencies:** none
- **Acceptance Criteria:**
  - musl로 링크한 대상에서 락 소유자 검사가 미지원 상태를 돌려주고 소유자 TID를 내지 않는다
  - aarch64 대상에서 futex 대기 스레드가 올바른 시스템콜 이름으로 나온다
  - 세션 정보에 판별된 아키텍처, libc, 워드 크기가 있다
  - 판별에 실패하면 관련 검사는 판단 불가로 처리된다
- **Verification:** 교차 컴파일한 대상의 ELF로 판별 단위 테스트. IMP-014 행렬에서 실제 확인.

### IMP-016 [P2]: 수집기 교차 빌드와 배포 방식 개선
- **Group:** RELIABILITY_AND_VALIDATION
- **Work Type:** EXISTING_IMPLEMENTATION_FIX
- **Problem:** 자동 배포가 호스트와 같은 아키텍처에서만 동작하고, 정적 링크와 교차 타깃이 없으며, 바이너리를 명령행 인자로 보낸다.
- **Evidence:** `extractor/target_adapter.py:2066-2079`, `extractor/target_adapter.py:2093-2114`, `extractor/target_adapter.py:2116-2123`, `target/collector/Makefile:1-13`
- **Findings:** F-OPS-001
- **Requirements:** NFR-003
- **Root Cause:** 수집기 빌드가 개발 호스트의 네이티브 빌드로만 쓰였다.
- **Proposed Solution:** Makefile에 아키텍처별 정적 빌드 타깃(arm, aarch64, x86_64, 필요 시 mips, riscv64)을 추가하고 산출물을 `dist/<arch>/`에 둔다. 배포 코드는 타깃의 `uname -m`에 맞는 바이너리를 고른다. 전송은 SSH 표준입력으로 한다(`cat > 경로`). 배포 위치를 설정할 수 있게 하고 실행 불가 마운트면 다른 위치를 시도한다. 수집기에 버전 출력 명령을 넣어 호스트와 버전이 다르면 재배포한다.
- **Existing Functionality Check:** 아키텍처 비교와 별칭 표는 이미 있다(`extractor/target_adapter.py:2093-2102`). 문서에는 교차 컴파일 명령이 있다(`target/collector/README.md:45-58`). CMake 파일도 있다. 빠진 것은 여러 산출물을 만들고 고르는 부분이다.
- **Expected Benefit:** x86 호스트에서 ARM 보드를 진단하는 기본 구성에서 수집기가 쓰이고, 바이트 단위 `dd` 폴백을 피한다.
- **Scope:** S~M
- **Dependencies:** none
- **Acceptance Criteria:**
  - `make dist` 한 번으로 3개 이상 아키텍처의 정적 바이너리가 만들어진다
  - x86_64 호스트에서 ARM 타깃에 연결하면 ARM 바이너리가 배포된다
  - 500KB 이상의 바이너리가 배포에 성공한다
  - 수집기 버전이 다르면 다시 배포된다
- **Verification:** 교차 컴파일러가 있는 CI 작업에서 빌드. IMP-014 행렬에서 배포 확인.

### IMP-017 [P2]: 진단 엔진 통합과 도달 불가 코드 제거
- **Group:** ARCHITECTURAL_IMPROVEMENTS
- **Work Type:** REFACTORING
- **Problem:** 엔진 4종, 판정 어휘 3종, 보고서 생성기 3종이 병렬로 있고, 11,627줄 파일에 판정·보고가 섞여 있으며, 도달하지 않는 코드가 유지된다.
- **Evidence:** `extractor/investigation.py:1243-1458`, `extractor/workflow.py:408`, `extractor/watch_session.py:11378-11626`, `extractor/verdict_engine.py:68-74`, `extractor/capture_backend.py:5462-5540`, `extractor/debug_info.py:188-206`
- **Findings:** F-ARCH-001, F-ARCH-002, F-FUNC-012
- **Requirements:** REQ-001, REQ-009
- **Root Cause:** 새 엔진을 추가할 때 이전 엔진을 대체하지 않았다.
- **Proposed Solution:** IMP-006의 단일 진입점이 자리 잡은 뒤 단계적으로 한다. (1) CLI `investigate`, 웹 조사 시작, 사고 보고서 내보내기를 전문가 엔진으로 옮긴다. (2) 감시 세션의 검사 함수(스레드, 무결성, 풀 스캔)는 증거 수집 계층으로 옮기고 그 파일의 판정·보고 코드는 지운다. (3) 판정 어휘를 집계기의 것으로 통일한다. (4) 워크플로우 엔진, 가짜 Ptrace·GDB 백엔드, 스텁 제공자, 셸 프로토타입을 지운다. 적응형 엔진의 판별 관측 선택기는 좋은 부품이므로 전문가 엔진의 재계획 단계에 통합한다. 각 단계마다 IMP-013 벤치마크 점수가 유지되는지 확인한다.
- **Existing Functionality Check:** 통합 대상의 호출 지점은 확인했다: CLI(`extractor/cli.py:867-880`, `extractor/cli.py:1690-1696`), 웹(`extractor/web/server.py:3721-3737`), MCP 폴백(`scripts/mcp_server.py:2852`). 워크플로우 엔진은 테스트에서만 import된다. 저장소의 자체 분석도 같은 통합을 권고했으나(`docs/FUNCTIONAL_GAP_ANALYSIS_AND_DEVELOPMENT_ROADMAP.md:167-172`) 이후 단계에서 수행되지 않았다.
- **Expected Benefit:** 한 경로, 한 판정 규칙. 새 진단 능력을 넣을 자리가 하나로 정해진다.
- **Scope:** L (단계별로 나눠 수행)
- **Dependencies:** IMP-005, IMP-006, IMP-013
- **Acceptance Criteria:**
  - 판정 열거형이 하나다
  - 사용자에게 보이는 보고서 생성기가 하나다
  - `extractor/workflow.py`와 가짜 백엔드 클래스가 없다
  - 통합 전후의 IMP-013 벤치마크 점수가 같거나 높다
  - `extractor/watch_session.py`에 판정을 만드는 코드가 없다
- **Verification:** 벤치마크와 CI. `rg "HEALTHY|NO_ISSUE_DETECTED" extractor/watch_session.py`에 판정 생성이 남아 있지 않음.

### IMP-018 [P2]: 선언형 레시피, 구조 기반 후보 선정, 범주 확장
- **Group:** ARCHITECTURAL_IMPROVEMENTS
- **Work Type:** REFACTORING
- **Problem:** 진단 지식이 두 개의 분기 사다리와 변수 이름 키워드에 박혀 있고, 일부 규칙은 관측하지 않은 사실을 확정으로 올리며, fd·소켓·CPU·스택 범주가 없다.
- **Evidence:** `extractor/diagnostic_recipes.py:1006`, `extractor/runtime_evidence_provider.py:592-617`, `extractor/runtime_evidence_provider.py:787-807`, `extractor/runtime_evidence_provider.py:1169-1174`, `extractor/expert_diagnostic_engine.py:815-817`, `extractor/adaptive_engine.py:1561-1586`
- **Findings:** F-ARCH-003, F-FUNC-009, F-FUNC-011
- **Requirements:** OBJ-001, REQ-002, REQ-003
- **Root Cause:** 레시피 메타데이터는 선언형이지만 수집과 평가는 `recipe_id`별 분기로 구현되었다. 후보 선정은 이름에서 출발했다.
- **Proposed Solution:** (1) 레시피를 "필요한 관측 목록 → 판정 규칙"으로 정의하고, 수집기는 관측 종류별로 등록한다. 레시피 추가가 분기 수정 없이 가능해야 한다. (2) 후보 선정을 이름이 아닌 구조로 바꾼다: 컨테이너는 타입과 포인터·길이 쌍으로, 락은 타입과 대기 중인 futex 주소로, 누수 후보는 IMP-007의 도달 그래프로. 이름 키워드는 순위 가산점으로만 남긴다. (3) NULL 포인터를 "역참조됨"으로, 값 100 이상을 "전이 위반"으로 올리는 규칙을 없애고, 관측한 사실만 지지 근거로 쓴다. (4) 1차 트리아지에 `/proc` 기반 저비용 조사를 추가한다: fd 수와 한도, 스레드 수 추세, 프로세스·스레드 CPU 사용률, 메모리 영역별 추세, 스택 여유. (5) 그에 대응하는 레시피를 추가한다.
- **Existing Functionality Check:** 레시피 메타데이터 구조(`extractor/diagnostic_recipes.py:107-132`)와 등록부가 있다. 판별 관측 선택기(`extractor/adaptive_engine.py:438-620`)는 관측을 선언형으로 다룬다. 이를 본보기로 삼는다. `rg -i "\bfd\b|file descriptor|socket|/proc/\S*/fd"`를 `extractor/diagnostic_recipes.py`에 실행: 스레드 틱 문구만 나온다. CPU 핫스폿은 감시 세션에만 있다(`extractor/watch_session.py:7853-7871`).
- **Expected Benefit:** 이름 관례가 다른 제품 코드에서도 후보가 잡힌다. 전문가 지식을 추가·검토하기 쉬워진다.
- **Scope:** L
- **Dependencies:** IMP-013
- **Acceptance Criteria:**
  - 새 레시피를 정의 파일 하나의 추가만으로 등록할 수 있다
  - IMP-013의 외부 코드 대상에서 원인 이름 일치율이 변경 전보다 높다
  - 유휴 상태의 NULL 전역 포인터를 가진 정상 대상에서 메모리 접근 위반이 보고되지 않는다
  - fd를 계속 여는 대상에서 fd 누수가 탐지되고 fd 수 추세가 보고된다
  - 실시간 트리아지가 메모리 증가 후보와 CPU 이상을 채운다
- **Verification:** IMP-013 벤치마크의 전후 비교. 새 범주 대상 프로그램에 대한 통합 테스트.

### IMP-019 [P1]: 읽기 전용 기본값과 웹 API 인증
- **Group:** IMMEDIATE_CORRECTIONS
- **Work Type:** EXISTING_IMPLEMENTATION_FIX
- **Problem:** 기본 관측 모드에서 변이·체크포인트가 열려 있고, 웹 API는 인증 없이 모든 출처를 허용한다.
- **Evidence:** `extractor/agent_runtime.py:75`, `extractor/agent_runtime.py:663-667`, `extractor/web/server.py:4195`, `extractor/web/server.py:3721-3726`, `scripts/mcp_server.py:520`
- **Findings:** F-SEC-001
- **Requirements:** NFR-005
- **Root Cause:** 제품이 상태 탐색·변이 도구로 시작했고, 진단 용도로 바뀐 뒤에도 기본값이 그대로다.
- **Proposed Solution:** 런타임 기본 모드를 LOW_IMPACT로 바꾸고 변이 기능은 명시적 실행 옵션으로만 켠다. 웹 서버는 시작할 때 무작위 세션 토큰을 만들어 모든 API 요청에 요구하고, 와일드카드 출처 허용을 없애며, Host와 Origin 헤더를 검사하고, POST에 JSON 콘텐츠 타입을 요구한다. 대상 승인은 PID가 있다고 자동으로 참이 되지 않게 한다.
- **Existing Functionality Check:** LOW_IMPACT 차단 로직은 이미 있다(`extractor/agent_runtime.py:544`, `extractor/agent_runtime.py:663-664`). 워크스페이스 실행기는 이미 LOW_IMPACT를 강제한다(`extractor/cli.py:1218`). 금지 엔드포인트의 403 처리도 있다(`extractor/web/server.py:4659-4665`). `rg -i "auth|token|csrf|Origin"`를 웹 서버에 실행: 인증 관련 구현 없음.
- **Expected Benefit:** 읽기 전용이라는 약속이 기본 설정에서 지켜지고, 브라우저 경유 호출이 막힌다.
- **Scope:** S~M
- **Dependencies:** none
- **Acceptance Criteria:**
  - 옵션 없이 시작한 런타임에서 변이 요청이 거부된다
  - 토큰 없는 API 요청이 401 또는 403을 받는다
  - 다른 출처의 요청에 와일드카드 허용 헤더가 붙지 않는다
  - 기존 UI가 토큰을 받아 정상 동작한다
- **Verification:** 웹 방어 테스트(`tests/test_phase52_web_and_mcp_defensive_hardening.py`)에 인증·출처 사례 추가.

### IMP-020 [P2]: 수집이 대상에 준 부하 측정
- **Group:** PERFORMANCE_AND_OPTIMIZATION
- **Work Type:** NEW_IMPLEMENTATION
- **Problem:** 수집 중 대상 프로세스와 타깃 보드가 받은 부하를 재지 않아 "영향 최소화"를 보일 근거가 없다.
- **Evidence:** `extractor/observation_budget.py:34-43`, `benchmarks/capture_benchmark.py:296-330`, `tests/test_phase2_4_collection_reliability_and_overhead.py:203`, `extractor/capture_backend.py:2160-2167`
- **Findings:** F-PERF-001
- **Requirements:** NFR-006, NFR-002
- **Root Cause:** 예산과 벤치마크가 수집기 쪽 비용만 다룬다.
- **Proposed Solution:** 진단 시작과 끝에 대상의 `/proc/PID/stat`(utime, stime, 문맥 전환)과 시스템 부하를 읽어 수집 구간의 변화를 기록한다. 원격에서는 수집기 프로세스 자신의 CPU 시간과 최대 메모리도 보고하게 한다. 이 값을 보고서의 "수집 영향" 항목에 싣는다. 예산에 타깃 측 CPU 시간 한도를 추가한다. 벤치마크에 "수집 유무에 따른 대상 처리량 차이" 측정을 넣는다. 선언만 된 `timeout_ms`를 실제로 적용한다.
- **Existing Functionality Check:** `rg -i "overhead|getrusage|slowdown|perturb|cpu_percent"`를 `benchmarks/`와 관련 테스트에 실행: 대상 측 측정 없음. 대상의 stat 읽기는 어댑터에 있다(`extractor/target_adapter.py:1123-1253`). 예산 추적기 구조(`extractor/observation_budget.py:181-295`)에 한도 항목을 추가하면 된다.
- **Expected Benefit:** 보고서가 "이 진단이 대상에 준 영향"을 숫자로 말한다. 저사양 보드용 예산을 근거 있게 정할 수 있다.
- **Scope:** M
- **Dependencies:** IMP-002
- **Acceptance Criteria:**
  - 보고서에 수집 구간의 대상 CPU 시간 변화, 정지 시간, 읽은 바이트, 수집기 자체 CPU·메모리가 있다
  - 벤치마크 결과에 수집 유무에 따른 대상 처리량 차이가 있다
  - 타깃 측 CPU 한도를 넘으면 수집이 중단되고 판정이 부분 결과로 표시된다
- **Verification:** 처리량을 스스로 출력하는 대상 프로그램으로 벤치마크 실행. IMP-014의 저사양 설정에서 측정.

### IMP-021 [P2]: 수집기 데몬 모드를 지속 SSH 세션으로 연결
- **Group:** PERFORMANCE_AND_OPTIMIZATION
- **Work Type:** INTEGRATION_FIX
- **Problem:** 원격 읽기 한 번마다 SSH 왕복과 타깃 측 프로세스 생성이 일어난다. 반복 관측이 필요한 진단에서 타깃 부하가 커진다.
- **Evidence:** `extractor/target_adapter.py:1484-1586`, `extractor/target_adapter.py:1799`, `target/collector/src/main.c:262-388`, `target/collector/README.md:110-124`
- **Findings:** F-ARCH-005
- **Requirements:** NFR-001
- **Root Cause:** 수집기에 데몬 모드를 만들었으나 호스트 쪽 사용 코드를 쓰지 않았다.
- **Proposed Solution:** 원격 어댑터가 세션당 SSH 연결 하나를 열어 수집기를 데몬 모드로 띄우고, 표준입출력으로 읽기 명령을 주고받는다. 연결이 끊기면 다시 열고, 실패하면 현재의 호출당 실행 방식으로 내려간다. 바이트 단위 `dd` 폴백은 블록 단위로 바꾼다.
- **Existing Functionality Check:** 데몬 모드의 PING, READ, QUIT 명령이 구현되어 있다(`target/collector/README.md:110-124`). `rg -- "--daemon" extractor scripts` 결과 없음. 호스트 쪽 연결만 없다.
- **Expected Benefit:** 원격 표본 수집의 타깃 측 비용이 프로세스 생성 N회에서 1회로 준다. IMP-010, IMP-011의 원격 동작 전제.
- **Scope:** M
- **Dependencies:** IMP-016
- **Acceptance Criteria:**
  - 원격 읽기 100회 동안 타깃에서 수집기 프로세스가 1개만 생성된다
  - 연결이 끊긴 뒤 다음 읽기가 자동으로 복구된다
  - 수집기가 없을 때의 폴백이 바이트 단위 읽기를 쓰지 않는다
- **Verification:** 로컬 SSH 서버에 대한 통합 테스트(가짜 실행기가 아닌 실제 연결). 타깃의 프로세스 생성 수를 세어 단언.

### IMP-022 [P2]: 의존성 선언, 패키징, README 정정
- **Group:** RELIABILITY_AND_VALIDATION
- **Work Type:** DOCUMENTATION_UPDATE
- **Problem:** 의존성·패키징·라이선스가 없고, `mcp`가 없으면 MCP 서버가 조용히 끝나며, README의 명령과 수치가 실제와 다르고 진단 흐름을 안내하지 않는다.
- **Evidence:** `requirements.txt:1-2`, `scripts/mcp_server.py:17-36`, `README.md:128`, `README.md:193`, `README.md:264`, `README.md:169-180`
- **Findings:** F-BUILD-001, F-DOC-001, F-INTENT-002
- **Requirements:** REQ-001
- **Root Cause:** 초기의 "표준 라이브러리만 사용" 전제가 MCP 도입 뒤 갱신되지 않았고, README가 이전 제품 정체성에 머물러 있다.
- **Proposed Solution:** `pyproject.toml`에 필수 의존성(`mcp`)과 선택 의존성(테스트용)을 버전과 함께 선언한다. MCP 서버는 `mcp`가 없으면 설치 방법을 담은 오류로 종료한다. 호스트 도구 요구사항(binutils)을 문서화한다. LICENSE 파일을 추가하거나 배지를 지운다. README를 "PID 진단" 흐름 중심으로 다시 쓰고 모든 명령을 실제 실행으로 확인한다.
- **Existing Functionality Check:** 실제 명령은 CLI에 있다(`extractor/cli.py:45-47`의 `analyze-memory`, 루트의 `run_all_tests.sh`). 한국어 플레이북(`docs/PRACTICAL_PLAYBOOK_KO.md`)이 사용 흐름의 좋은 초안이다. `git ls-files`에서 setup.py, pyproject.toml, LICENSE 없음.
- **Expected Benefit:** 첫 사용자와 AI 에이전트가 안내대로 따라 하면 진단까지 간다.
- **Scope:** S
- **Dependencies:** IMP-006
- **Acceptance Criteria:**
  - 새 가상 환경에서 `pip install .` 후 MCP 서버가 뜬다
  - `mcp`가 없는 환경에서 서버가 0이 아닌 종료 코드와 안내 메시지를 낸다
  - README의 모든 명령이 그대로 실행된다
  - README 첫 화면에 `diagnose` 사용 예가 있다
- **Verification:** CI에 "README 명령 실행" 작업 추가. 빈 환경 설치 테스트.

### IMP-023 [P2]: 진단 워크플로우를 에이전트 스킬로 패키징
- **Group:** CORE_FUNCTIONAL_COMPLETION
- **Work Type:** INTEGRATION_FIX
- **Problem:** 전문가 워크플로우 명세가 문서로만 있어 AI 에이전트에게 전달되지 않는다. MCP 플레이북은 데모 심볼 중심이다.
- **Evidence:** `docs/PROCESS_HEALTH_INVESTIGATION_SKILL.md:19-21`, `docs/PROCESS_HEALTH_INVESTIGATION_KNOWLEDGE.md:17-32`, `scripts/mcp_server.py:2872-2894`, `scripts/mcp_server.py:2645`
- **Findings:** F-TRACE-002
- **Requirements:** REQ-011
- **Root Cause:** 워크플로우를 문서와 코드 양쪽에 따로 썼고 에이전트용 전달 형식을 정하지 않았다.
- **Proposed Solution:** 저장소에 에이전트 스킬 디렉터리를 둔다. 내용: 언제 쓰는가, 필요한 입력(PID, 디버그 ELF, 원격 접속 정보)과 없을 때 묻는 방법, `diagnose` 호출, 판정별 후속 행동(판단 불가면 무엇을 더 요청할지, 의심이면 어떤 도구로 좁힐지), 보고서를 사용자에게 설명하는 방법, 금지 사항(정지 수집과 변이는 사용자 승인 필요). MCP 서버의 안내 문구와 `runtime_get_playbook`을 같은 내용으로 바꾸고 데모 심볼 기본값을 없앤다. 문서 명세와 스킬이 어긋나지 않게 한쪽에서 생성한다.
- **Existing Functionality Check:** 워크플로우 명세, 지식 문서, 한국어 플레이북이 내용의 원재료다. `git ls-files`에서 SKILL.md, AGENTS.md, CLAUDE.md, .mcp.json 없음. 상위 디렉터리에 `.agents/`와 `skills-lock.json`이 있으나 이 저장소 밖이고 추적되지 않는다.
- **Expected Benefit:** OBJ-001의 "AI가 전문가처럼 진단"이 도구 제공을 넘어 절차 제공까지 이뤄진다.
- **Scope:** S~M
- **Dependencies:** IMP-006
- **Acceptance Criteria:**
  - MCP만 연결한 새 에이전트 세션에서 "PID N 진단해 줘"라고 하면 추가 지시 없이 `diagnose`를 호출하고 보고서를 요약한다
  - 디버그 ELF가 없을 때 에이전트가 사용자에게 요청한다
  - 판정이 판단 불가일 때 에이전트가 "문제 없음"이라고 말하지 않는다
  - MCP 도구 기본값에 데모 심볼이 없다
- **Verification:** 대상 프로그램 3종에 대해 에이전트 세션을 기록해 호출 순서와 최종 설명을 검토하는 시나리오 테스트.

## Verification strategy

- **단일 기준은 IMP-013 벤치마크다.** 2단계의 각 능력(IMP-007 ~ IMP-011)은 해당 결함 유형의 "원인 이름 일치"가 벤치마크에서 통과할 때 완료로 본다. 문서의 자기 선언은 완료 근거로 쓰지 않는다.
- **모든 테스트는 CI에서 실행된 기록으로만 인정한다**(IMP-005).
- **정상 대조군을 항상 함께 돌린다.** 탐지율만 올리고 오탐을 늘리는 변경을 막는다.
- **임베디드 관련 항목은 IMP-014 행렬에서 확인한다.** 호스트에서만 통과한 것은 "호스트 검증"으로 표시한다.
- **리팩터링(IMP-017, IMP-018)은 벤치마크 점수가 유지될 때만 병합한다.**
- **보고서 품질(IMP-012)은 사람 읽기 시험으로 확인한다.** 구조 단언만으로는 이해 가능성을 보증할 수 없다.

## Explicitly not recommended

- **전면 재작성.** 수집 계층(무정지 슬라이스 읽기, PID 재사용 방지, C 수집기)과 해석 계층(DWARF 색인, 타입 디코더)은 재사용 가치가 높다. 문제는 진단 층에 국한된다.
- **신뢰·출처 검증 장치의 추가 확장.** 현 상태로 동결한다(F-ARCH-004). 제거도 권하지 않는다. 제거는 위험만 있고 목적에 기여하지 않는다.
- **eBPF·bpftrace 기반 할당 추적을 기본 경로로 삼는 것.** 일반 임베디드 타깃에는 bpftrace, root, uprobe 지원이 없는 경우가 많다(`extractor/ebpf_tracer.py:2099-2105`). 서버용 선택 기능으로만 둔다.
- **gdbserver 연결을 기본 임베디드 경로로 구현하는 것.** 대상을 정지시키므로 저영향 목적과 맞지 않는다. 문서의 "패턴 1"은 사용자 승인이 필요한 선택 경로로 다시 쓴다.
- **LLM이 판정을 내리게 하는 것.** 현재의 결정적 규칙 기반 판정과 LLM 출력 접지는 좋은 설계다. LLM은 보고서 서술과 에이전트 절차 수행에만 쓴다.
- **std::map 등 STL 컨테이너 디코더를 먼저 넓히는 것.** IMP-007의 포인터 추적은 타입 멤버를 따라가므로 대부분의 컨테이너를 통과한다. 예쁜 출력은 벤치마크가 필요하다고 보일 때 추가한다.
- **체크포인트·변이 기능의 추가 개발.** 사용자 목적(읽기 전용 진단)에 포함되지 않는다.

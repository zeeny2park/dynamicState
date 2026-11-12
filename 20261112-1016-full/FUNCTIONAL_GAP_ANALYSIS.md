# Functional Gap Analysis: dynamicState

- Target: `C:\task\dynamicState\dynamicState` @ `f842448` (main), working tree clean
- Diagnostic date: 2026-11-12 · Mode: full · Scope: 핵심 사용 사례 5개(UC-1 ~ UC-5)를 진입점부터 판정·보고서까지 코드로 추적
- Not examined: 동작을 실행해 재현하지 않았다. 읽기만으로 판단하기 미묘한 결함은 INFERENCE로 표시했다.

## Expected functionality

- **UC-1 일반 진단.** 사용자가 PID(와 디버그 ELF)를 주면, 도구가 저비용 조사부터 시작해 이상 징후를 찾고, 필요한 추가 관측을 스스로 골라 수행한 뒤, 판정(문제 있음, 없음, 판단 불가)과 보고서를 낸다.
- **UC-2 메모리 누수.** 메모리가 계속 늘어나는지 시간 간격을 두고 확인하고, 늘어나는 메모리를 붙잡고 있는 변수·자료구조·할당 지점을 지목한다.
- **UC-3 메모리 손상.** 버퍼가 자기 크기를 넘어 썼는지 찾아내고, 넘친 버퍼와 덮어쓰인 이웃이 각각 어떤 변수인지 알려 준다.
- **UC-4 스레드 오동작.** 각 스레드가 무엇을 하고 있는지(대기, 실행, 정지), 시간이 지나도 진전이 없는지, 어떤 락을 누가 쥐고 있는지 확인해 교착, 바쁜 대기, 기아, 정지를 구분한다.
- **UC-5 임베디드 원격 진단.** 타깃 보드에는 작은 수집기만 두고, 대상 프로세스를 멈추지 않으며, 보드의 CPU·메모리·저장소를 거의 쓰지 않는다.

## Actual functionality

**UC-1 일반 진단.** 인터페이스마다 다른 엔진으로 간다.
- MCP: `runtime_start_investigation`은 분류·평가·계획까지만 실행한다(`scripts/mcp_server.py:508-510`). 수집과 판정은 `runtime_get_investigation_conclusion`을 호출해야 일어난다(`scripts/mcp_server.py:687-688`). 그 전에 보고서 도구를 부르면 계획만 있는 상태로 강제 종결된다(`extractor/expert_diagnostic_engine.py:2915-2916`).
- CLI `investigate`: 레거시 엔진으로 간다(`extractor/cli.py:867-880`). 22개 레시피 엔진에는 CLI 경로가 없다.
- 웹 기본 UI: 레거시 엔진(`extractor/web/server.py:3721-3737`).
- 1회 호출 사고 보고서: 감시 세션 엔진(`extractor/watch_session.py:11431-11445`). 실패가 정상으로 바뀐다(F-FUNC-004).

**UC-2 메모리 누수.** `/proc`의 RSS와 `[heap]` 영역 크기를 읽고(`extractor/runtime_evidence_provider.py:896-898`), 이름에 pool·leak·buffer 등이 들어간 전역을 후보로 삼는다(`extractor/runtime_evidence_provider.py:592-617`). 결과는 "증가함"까지이며 누가 붙잡고 있는지는 나오지 않는다. 전문가 엔진은 관측 사이에 기다리지 않는다(관측 시간·간격 값은 저장만 됨 `extractor/expert_diagnostic_engine.py:1191-1192`).

**UC-3 메모리 손상.** `runtime_audit_memory_integrity`는 전역에서 출발해 포인터가 매핑 밖을 가리키는지, bool·enum 값이 범위를 벗어났는지 등을 본다(`extractor/watch_session.py:5731-5737`). 버퍼의 크기와 실제 사용 범위를 비교하는 검사는 없다. 포인터 뒤의 힙 버퍼 크기를 도구가 알지 못한다(`extractor/watch_session.py:2432-2437`).

**UC-4 스레드 오동작.** 스레드 스택 메모리를 읽어 실행 영역을 가리키는 값을 반환 주소로 간주하는 방식으로 콜스택을 만든다(`extractor/watch_session.py:5561-5606`). 전역 pthread mutex의 소유자와 futex 대기자를 연결해 순환을 찾는다(`extractor/watch_session.py:5483-5518`, `extractor/watch_session.py:5665-5689`). 기아·정지·폭주 규칙은 선언되어 있으나 입력을 만드는 코드가 없다(`extractor/diagnostic_recipes.py:2106-2177`).

**UC-5 임베디드 원격 진단.** C 수집기가 있고 SSH로 호출된다(`extractor/target_adapter.py:1799`). 수집기가 없으면 타깃에서 `dd bs=1`로 한 바이트씩 읽는다(`extractor/target_adapter.py:1871`). 원격에서는 스레드의 스택 포인터, CPU 시간, 문맥 전환 수를 가져오지 않는다(`extractor/target_adapter.py:1781-1788`).

## Missing functionality

- 임의 주소 → 소유 변수 역추적, 힙 전체 순회, 도달 불가능 블록(진짜 누수) 탐지: F-FUNC-001.
- 버퍼 경계 대비 오버플로우 탐지: F-FUNC-003.
- 스레드 시계열 표본(스레드별 CPU 시간 변화, 같은 위치에 머무는지)과 그에 기반한 판정: F-FUNC-006.
- fd·소켓·CPU·스택 범주의 진단 규칙: F-FUNC-011.

## Incomplete workflows and incorrect implementations

- 수집 실패가 "정상"으로 보고됨: F-FUNC-004.
- 한 번 관측한 교착이 "연속 표본으로 검증됨"으로 보고됨: F-FUNC-005.
- 메모리 증가 후속 단계 생성 시 필수 인자 누락: F-FUNC-008.
- 관측하지 않은 사실을 확정으로 올리는 휴리스틱: F-FUNC-009.
- 누수 판정이 "증가"에서 멈춤: F-FUNC-002.
- 보고서가 사람이 읽기 어려움: F-FUNC-010.

## Integration problems

- 단일 진단 진입점 부재와 인터페이스별 엔진 불일치: F-FUNC-007.
- 콜스택이 휴리스틱 스캔이고 원격 경로가 약함: F-FUNC-013.
- 구현되었으나 연결되지 않은 모듈: F-FUNC-012.

## Insufficiently validated functionality

- 누수·손상·교착 판정이 올바른 변수·스레드·락 이름을 내는지 단언하는 테스트가 없다. BLINDSPOT_AND_RISK_REPORT.md의 F-TEST-002.
- 임베디드 타깃에서의 실행 기록이 없다. F-TEST-003.

## Unnecessary, duplicated, or low-value functionality

- 진단 엔진 4종, 판정 어휘 3종, 보고서 생성기 3종의 중복: ARCHITECTURE_AUDIT.md의 F-ARCH-001.
- 어떤 인터페이스에서도 도달하지 않는 코드: F-FUNC-012.

## Findings

### F-FUNC-001: 주소에서 소유 변수를 찾는 역추적과 힙 순회가 없음
- **Category:** FUNC
- **Severity:** HIGH
- **Confidence:** HIGH
- **Evidence Type:** FACT
- **Requirement:** REQ-006
- **Gap Class:** MISSING
- **Evidence:** `extractor/watch_session.py:3588-3598`, `extractor/watch_session.py:4380-4404`, `extractor/watch_session.py:7023-7052`, `extractor/watch_session.py:7171-7178`, `extractor/allocator_inspector.py:203-219`
- **Observed:** 소유자 탐색 도구는 사용자가 DWARF 전역 심볼을 먼저 지정해야 하고, 참조자를 최상위 멤버 수준(`var`, `var[i].member`)까지만 이름 붙인다. 스택에서 찾은 참조는 스레드와 원시 주소로만 나온다. 힙 객체 스캔은 가상 함수 테이블이 있는 C++ 객체만 찾고, 참조자를 `global_data@0x...` 같은 원시 주소로 보고한다. glibc 해석은 청크 1개의 헤더만 읽으며 아레나·tcache·빈 순회가 없다.
- **Expected:** "이 주소의 버퍼는 전역 `g_x.buf`가 가리킨다", "스레드 T의 함수 f 지역 변수 n이 가리킨다"처럼 임의 주소에서 이름까지 역으로 찾아야 한다.
- **Gap:** 사용자가 예로 든 핵심 질문("해제되지 않는 버퍼가 어떤 변수의 것인가")에 답할 수단이 없다. 순수 C의 malloc 블록과 가상 함수가 없는 구조체는 누수 후보로도 잡히지 않는다.
- **Counter-evidence searched:** `extractor/`와 `scripts/`에서 symbolize, resolve_address, address_to, reverse_, referrer, backref, retained by, inbound, malloc_state, main_arena, tcache, walk_heap을 검색. 구현 없음(레시피 설명 문구와 플래그 이름에만 등장).
- **Recommendation:** 힙 순회기와 역참조 맵을 새로 만든다. IMP-007 참조.

### F-FUNC-002: 누수 진단이 "메모리가 늘어난다"에서 멈추고, 확정 경로는 실제 수집으로 도달할 수 없음
- **Category:** FUNC
- **Severity:** HIGH
- **Confidence:** HIGH
- **Evidence Type:** FACT
- **Requirement:** REQ-004
- **Gap Class:** INCOMPLETE_WORKFLOW
- **Evidence:** `extractor/temporal_observation_window.py:472-481`, `extractor/temporal_observation_window.py:501-506`, `extractor/temporal_observation_window.py:55-56`, `tests/test_phase2_1_4_diagnostic_execution_integration.py:353-355`, `extractor/runtime_evidence_provider.py:972-980`, `extractor/expert_diagnostic_engine.py:1191-1192`
- **Observed:** 누수 확정에는 `live_allocations_count`, `allocator_heap_kb`, 또는 증가하는 이름 붙은 컨테이너가 필요한데, 앞의 두 값은 테스트에서만 채워진다. 실제 결과는 "RSS 지속 증가(누수 미확정)"이다. 측정 대상은 `[heap]` 영역뿐이어서 mmap으로 처리되는 큰 할당은 보이지 않는다. 엔진은 관측 사이에 기다리지 않으므로 한 번의 실행으로는 레시피가 요구하는 3회 이상의 분리된 관측을 모을 수 없다.
- **Expected:** 시간 간격을 둔 반복 관측으로 증가를 확인하고, 증가분을 크기별·소유자별로 나눠 누수 주체를 지목한다.
- **Gap:** 누수 여부는 추정에 그치고, "어디서 새는지"는 전혀 나오지 않는다.
- **Recommendation:** 반복 관측을 엔진에 연결하고 힙 통계 차이를 소유자별로 집계한다. IMP-008 참조.

### F-FUNC-003: 버퍼 오버플로우를 탐지할 수 없음
- **Category:** FUNC
- **Severity:** HIGH
- **Confidence:** HIGH
- **Evidence Type:** FACT
- **Requirement:** REQ-005
- **Gap Class:** MISSING
- **Evidence:** `extractor/watch_session.py:5731-5737`, `extractor/watch_session.py:2432-2437`, `extractor/watch_session.py:2457-2460`, `extractor/runtime_evidence_provider.py:767-779`, `extractor/runtime_evidence_provider.py:604-605`
- **Observed:** 무결성 감사는 포인터 유효성, bool·enum 범위, 죽은 소유 스레드, 풀 카운터 불일치만 본다. 포인터 뒤 힙 버퍼의 크기를 알지 못하고, 배열은 DWARF의 정적 길이만 쓰며 16개로 제한된다. 힙 메타데이터 손상 레시피의 "손상"은 이름에 magic·canary·header·tag가 들어간 전역의 값이 0xDEADBEEF 등 네 값 중 하나일 때다.
- **Expected:** 할당 청크 크기와 타입이 요구하는 크기의 비교, 인접 전역 변수 덮어쓰기 검사, 스택 가드·사용량 검사로 넘침을 찾는다.
- **Gap:** 대상 프로그램이 특정 이름과 독성 값 규칙을 따를 때만 "손상"이 보고된다. 일반 제품 코드의 오버플로우는 보이지 않는다.
- **Counter-evidence searched:** stack canary, __stack_chk, redzone, adjacent, clobber, usable_size 검색. 분류기 키워드와 설명 문구뿐.
- **Recommendation:** 청크 크기 대비 검사와 인접 심볼 검사를 구현한다. IMP-009 참조.

### F-FUNC-004: 수집이 실패하면 "정상"으로 판정하는 경로가 있음
- **Category:** FUNC
- **Severity:** CRITICAL
- **Confidence:** HIGH
- **Evidence Type:** FACT
- **Requirement:** REQ-009
- **Gap Class:** DEFECTIVE
- **Evidence:** `extractor/watch_session.py:11431-11432`, `extractor/watch_session.py:11444-11445`, `extractor/watch_session.py:11463-11464`, `extractor/watch_session.py:11524-11537`, `extractor/watch_session.py:11547`, `extractor/watch_session.py:7896-7903`, `scripts/mcp_server.py:2852`, `extractor/cli.py:1690-1696`
- **Observed:** 사고 보고서 생성에서 자동 트리아지가 예외를 던지면 결과를 `HEALTHY`, 건강 점수 100, 발견 사항 없음으로 대체한다. 콜스택 수집 실패는 빈 스레드 목록이 된다. 이후 보고서는 "검사한 모든 메모리 풀, 포인터, 락이 정상 범위"라고 쓰고, 판정은 `NO_ISSUE_DETECTED`, 신뢰도 0.9, 한계 목록은 비어 있다. 증상 조사 도구도 내부 조사 오류를 모으기만 하고 반환하지 않으며, 전부 실패해도 "치명적 문제 없음, 신뢰도 0.80"을 낸다.
- **Expected:** 워크플로우 명세는 수집이 실패하거나 제한되면 판정을 판단 불가로 두라고 요구한다(`docs/PROCESS_HEALTH_INVESTIGATION_SKILL.md:168`, `docs/PROCESS_HEALTH_INVESTIGATION_SKILL.md:201`).
- **Gap:** 권한 부족, 프로세스 종료, 심볼 불일치처럼 흔한 실패에서 사용자는 "문제 없음" 보고서를 받는다. 진단 도구에서 가장 해로운 종류의 오류다. 이 경로는 CLI `export-report`와 MCP `runtime_export_incident_report`에서 한 번의 호출로 도달한다.
- **Recommendation:** 예외를 판단 불가 판정과 한계 항목으로 바꾼다. IMP-001 참조.

### F-FUNC-005: 한 번 관측한 순환 대기를 "연속 표본으로 검증된 교착"으로 보고함
- **Category:** FUNC
- **Severity:** HIGH
- **Confidence:** MEDIUM
- **Evidence Type:** INFERENCE
- **Requirement:** REQ-007
- **Gap Class:** DEFECTIVE
- **Evidence:** `extractor/diagnostic_recipes.py:1537`, `extractor/diagnostic_recipes.py:1570-1584`, `extractor/runtime_evidence_provider.py:1206-1271`, `extractor/concurrency_graph.py:278-355`
- **Reasoning:** 레시피는 `cycle_persistent`의 기본값을 참으로, 관측 횟수의 기본값을 2로 둔다. `extractor/`와 `scripts/`에서 `cycle_persistent`, `historical_observations`, `is_persistent`를 쓰는 생산자는 없다(검색으로 확인). 증거 수집기는 스냅샷을 한 번 뜬다. 따라서 순환이 보이면 기본값만으로 "지속 교착, 신뢰도 0.98" 분기로 들어간다. 실행으로 재현하지는 않았다.
- **Observed:** 단일 스냅샷의 순환 대기가 "연속 표본에 걸쳐 검증됨"이라는 문구와 0.98 신뢰도로 보고될 것으로 보인다. 다회 관측과 불완전 그래프를 올바르게 다루는 `WaitForGraph` 클래스는 있으나 실제 경로에서 채워지지 않는다.
- **Expected:** 한 번만 관측한 순환은 "순환 대기 관측"으로, 두 번 이상 유지되면 교착으로 구분한다(코드 주석 자체가 그렇게 말한다 `extractor/diagnostic_recipes.py:1586`).
- **Gap:** 순간적인 락 경합이 교착으로 오판될 수 있고, 보고서의 근거 문구가 사실과 다르다.
- **Recommendation:** 기본값을 거짓과 1로 바꾸고, 수집기가 두 번 이상 관측해 지속성을 넘기게 한다. IMP-003 참조.

### F-FUNC-006: 스레드 오동작 규칙에 입력을 넣는 수집기가 없음
- **Category:** FUNC
- **Severity:** HIGH
- **Confidence:** HIGH
- **Evidence Type:** FACT
- **Requirement:** REQ-008
- **Gap Class:** NOT_INTEGRATED
- **Evidence:** `extractor/diagnostic_recipes.py:769-897`, `extractor/diagnostic_recipes.py:2106-2177`, `extractor/watch_session.py:8054-8084`, `extractor/watch_session.py:8268-8285`, `extractor/watch_session.py:9686-9694`, `tests/test_phase2_1_8_complete_validation.py:974-978`
- **Observed:** 스레드 상태·락 소유·정지 스레드 레시피는 `zombie_threads`, `runaway_threads`, `blocked_duration_sec`, `starvation_detected`, `persistent_block` 같은 입력을 읽지만, `extractor/`와 `scripts/`에 이 값을 만드는 코드가 없다. 스레드별 CPU 시간 변화는 핫스폿 프로파일러에만 있고 순위와 힌트만 낸다. 실제 판정이 있는 것은 DPDK 폴링 스레드의 무한 루프뿐이다. 테스트는 `starvation_detected: True`를 직접 넣어 규칙을 통과시킨다.
- **Expected:** 스레드마다 일정 간격으로 상태, CPU 시간, 문맥 전환, 현재 위치를 표본으로 모아 "진전 없음", "CPU 독점", "같은 시스템콜에 장시간 정지"를 판정한다.
- **Gap:** "특정 스레드가 오동작하는가"에 대해 교착 외에는 판정이 나오지 않는다.
- **Counter-evidence searched:** schedstat, run queue, priority inversion, livelock, watchdog, thread leak, stack usage, FUTEX_LOCK_PI, pthread_cond_t, sem_t 검색. 탐지기 없음.
- **Recommendation:** 스레드 시계열 표본 수집기를 만들고 기존 규칙에 연결한다. IMP-010 참조.

### F-FUNC-007: "PID 진단" 단일 진입점이 없고 인터페이스마다 다른 엔진·판정이 나옴
- **Category:** FUNC
- **Severity:** HIGH
- **Confidence:** HIGH
- **Evidence Type:** FACT
- **Requirement:** REQ-001
- **Gap Class:** INCONSISTENT
- **Evidence:** `scripts/mcp_server.py:508-510`, `scripts/mcp_server.py:512-530`, `scripts/mcp_server.py:687-688`, `extractor/expert_diagnostic_engine.py:2915-2916`, `extractor/cli.py:867-880`, `extractor/web/server.py:3721-3737`, `extractor/diagnostic_verdict_aggregator.py:53-59`, `extractor/verdict_engine.py:68-74`, `extractor/watch_session.py:6786-6787`
- **Observed:** MCP 시작 도구는 계획까지만 실행하고 레거시 조사도 함께 시작해 ID를 바꿔 끼운다. 결론 도구를 불러야 수집과 판정이 일어난다. 그 전에 보고서를 요청하면 실행되지 않은 계획으로 보고서가 만들어진다. CLI에는 22개 레시피 엔진으로 가는 경로가 없다. 판정 어휘는 엔진마다 다르다(CONFIRMED_FAULT 계열, CONFIRMED·SUSPECTED 계열, HEALTHY·WARNINGS_FOUND 계열).
- **Expected:** 어느 인터페이스에서든 같은 엔진이 끝까지 실행되어 같은 판정과 같은 보고서를 낸다.
- **Gap:** 같은 프로세스가 인터페이스에 따라 다른 판정을 받을 수 있고, AI 에이전트는 올바른 호출 순서를 알아야만 실제 진단을 얻는다.
- **Recommendation:** 한 엔진 위에 `diagnose` 진입점을 만든다. IMP-006 참조.

### F-FUNC-008: 메모리 증가 후속 단계를 만들 때 필수 인자가 빠져 있음
- **Category:** FUNC
- **Severity:** HIGH
- **Confidence:** MEDIUM
- **Evidence Type:** INFERENCE
- **Requirement:** REQ-004
- **Gap Class:** DEFECTIVE
- **Evidence:** `extractor/expert_diagnostic_engine.py:730-743`, `extractor/expert_diagnostic_engine.py:2100-2116`
- **Reasoning:** `InvestigationStep`은 `priority`, `cost_score`, `safety_score`, `expected_info_gain`, `multi_factor_score`를 기본값 없는 필수 필드로 선언한다. 후속 단계 생성 코드는 이 다섯 개를 주지 않는다. 이 줄에 도달하면 Python은 TypeError를 낸다. 도달 조건은 증가 레시피가 SUPPORTED이고 후속 레시피가 계획에 아직 없을 때다. 실행으로 확인하지는 않았다.
- **Observed:** 메모리 증가가 확인된 바로 그 상황에서 후속 조사(힙 증가, 장수 객체 누적)를 추가하려다 예외가 날 것으로 보인다.
- **Expected:** 증가가 확인되면 원인 좁히기 단계가 이어진다.
- **Gap:** 누수 조사의 가장 중요한 분기가 깨져 있을 가능성이 높다. 이 경로를 실제 프로세스로 끝까지 돌리는 테스트가 없다는 뜻이기도 하다.
- **Recommendation:** 누락 인자를 채우고, 증가 프로세스로 이 분기를 통과하는 테스트를 추가한다. IMP-004 참조.

### F-FUNC-009: 관측하지 않은 사실을 확정으로 올리는 휴리스틱
- **Category:** FUNC
- **Severity:** HIGH
- **Confidence:** MEDIUM
- **Evidence Type:** INFERENCE
- **Requirement:** REQ-009
- **Gap Class:** DEFECTIVE
- **Evidence:** `extractor/runtime_evidence_provider.py:787-807`, `extractor/diagnostic_recipes.py:1059-1090`, `extractor/runtime_evidence_provider.py:1169-1174`, `extractor/expert_diagnostic_engine.py:2060`, `extractor/expert_diagnostic_engine.py:2277-2289`, `extractor/expert_diagnostic_engine.py:2639-2640`
- **Reasoning:** 다음 네 가지는 코드에서 직접 읽은 사실이다. (1) 전역 포인터 값이 4096 이하이면 위반 유형을 NULL 역참조로 적고, 레시피는 이를 신뢰도 0.98로 지지한다. 역참조가 일어났는지는 관측하지 않는다. (2) 상태 변수 값이 100 이상이면 `[1, 값]`이라는 전이 기록과 허용 전이표를 만들어 넣는다. (3) "정상" 가설의 조건인 검증 횟수는 단계 결과와 무관하게 매 단계 증가한다. (4) 주요 발견이 없으면(차단, 예산 소진, 증거 부족 포함) 조치 문구가 "조치 불필요: 정상으로 보임"이 된다. 이로부터 잘못된 확정·정상 문구가 나올 수 있다고 추론한다.
- **Observed:** 값 하나의 모양만으로 "확정" 수준의 결론이 만들어지고, 증거 부족 실행에서도 "정상" 문구가 보고서에 들어갈 수 있다.
- **Expected:** 워크플로우 명세는 추론을 관측 사실로 기록하지 말라고 요구한다(`docs/PROCESS_HEALTH_INVESTIGATION_SKILL.md:115`).
- **Gap:** 오탐(유휴 상태의 NULL 포인터)과 미탐(증거 부족을 정상으로 표현) 양쪽으로 판정 신뢰를 떨어뜨린다.
- **Recommendation:** 급한 것(정상 문구, 검증 횟수 집계)은 IMP-001에서, 휴리스틱 자체의 교체는 IMP-018에서 다룬다.

### F-FUNC-010: 보고서가 엔지니어·기계 지향이며 원인 대상이 이름으로 나오지 않음
- **Category:** FUNC
- **Severity:** HIGH
- **Confidence:** HIGH
- **Evidence Type:** FACT
- **Requirement:** REQ-010
- **Gap Class:** LIMITED
- **Evidence:** `extractor/diagnostic_report.py:558-565`, `extractor/expert_diagnostic_engine.py:3049-3052`, `extractor/expert_diagnostic_engine.py:2623-2640`, `extractor/expert_diagnostic_engine.py:2972-2979`, `extractor/watch_session.py:11474`, `extractor/watch_session.py:11552`
- **Observed:** 요약 섹션은 판정 열거값, 결정 규칙 ID, 검사 ID 목록이다. 근본 원인 항목의 "영향 대상"에 변수·스레드·락이 아니라 가설 범주가 들어간다. 소스 위치와 인과 관계 필드는 엔진이 채우지 않는다(`source_references=`, `causal_relationships=` 대입이 `extractor/`와 `scripts/`에 없음). 조치 안내는 키워드로 고르는 1~2개의 정형 문장이다. 프로세스 이름은 디버그 ELF 파일명, 수집 모드는 상수, 정지 시간 0.00ms와 읽은 바이트 4096은 고정값이다. 용어 설명, 그림, 한국어 출력이 없다.
- **Expected:** "스레드 worker-2가 `g_queue.mtx`를 쥔 채 `flush()` 42행에서 멈춰 있다"처럼 이름과 위치로 설명하고, 왜 그렇게 판단했는지와 확인하지 못한 범위를 평이한 문장으로 쓴다.
- **Gap:** 보고서를 읽고 상황을 이해하려면 내부 ID와 열거값을 해석해야 한다. 일부 대상 정보는 관측값이 아니라 합성값이다.
- **Counter-evidence searched:** glossary, mermaid, graphviz, svg, i18n, locale 검색. 보고서 관련 결과 없음. `extractor/diagnostic_report.py`에 한글 없음.
- **Recommendation:** 기존 보고서 모델 위에 사람용 서술 층을 추가한다. IMP-012 참조.

### F-FUNC-011: 증상 범주에 빈 곳이 있고 실시간 트리아지가 스레드만 봄
- **Category:** FUNC
- **Severity:** MEDIUM
- **Confidence:** HIGH
- **Evidence Type:** FACT
- **Requirement:** REQ-003
- **Gap Class:** LIMITED
- **Evidence:** `extractor/diagnostic_recipes.py:204-930`, `extractor/expert_diagnostic_engine.py:287-290`, `extractor/expert_diagnostic_engine.py:815-817`, `extractor/adaptive_engine.py:1561-1586`, `extractor/adaptive_engine.py:1435-1461`
- **Observed:** 레시피는 메모리 무결성 6, 메모리 증가 6, 이상 상태 5, 동시성 5개다. 스택 손상은 분류는 되지만 대응 레시피가 없어 처음 네 개 레시피로 대체된다. fd, 소켓, CPU 폭주 레시피가 없다. 적응형 엔진의 실시간 트리아지는 의심 스레드만 채우고, 메모리 증가 후보·포인터 이상·큐 적체는 테스트용 고정 데이터 분기에서만 채워진다.
- **Expected:** 전문가가 먼저 훑어보는 항목(fd 수, 스레드 수, CPU 사용률, 메모리 추세, 스택 여유)을 트리아지가 다룬다.
- **Gap:** 실제 프로세스에서 적응형 엔진은 락·스레드 문제만 가설로 세울 수 있다.
- **Recommendation:** 트리아지와 레시피 범주를 넓힌다. IMP-018 참조.

### F-FUNC-012: 구현되었으나 어떤 진입점에서도 도달하지 않는 코드
- **Category:** FUNC
- **Severity:** MEDIUM
- **Confidence:** HIGH
- **Evidence Type:** FACT
- **Requirement:** REQ-001
- **Gap Class:** LOW_VALUE
- **Evidence:** `extractor/workflow.py:408`, `extractor/concurrency_graph.py:129-402`, `extractor/expert_diagnostic_engine.py:1228`, `extractor/capture_backend.py:5462-5540`, `extractor/debug_info.py:188-206`, `scripts/target_capture.sh:2-5`
- **Observed:** 워크플로우 엔진(1,316줄)은 테스트에서만 import된다. `WaitForGraph`는 엔진이 빈 채로 만들고 간선 추가는 테스트에서만 호출된다. Ptrace·GDB 캡처 백엔드는 실제로는 process_vm_readv 백엔드에 위임하면서 "레지스터 읽기 가능"을 광고한다. 네이티브 DWARF 제공자는 스텁이다. 셸 캡처 스크립트는 Python 어디에서도 참조되지 않는다.
- **Expected:** 유지되는 코드는 사용 경로가 있거나, 없으면 제거된다.
- **Gap:** 읽고 유지해야 할 코드가 늘고, 능력 광고(레지스터 읽기)가 실제와 다르다. 반대로 `WaitForGraph`는 연결하면 F-FUNC-005를 고치는 데 쓸 수 있는 자산이다.
- **Recommendation:** `WaitForGraph`는 연결하고(IMP-010), 나머지는 통합 과정에서 제거한다(IMP-017).

### F-FUNC-013: 콜스택이 실제 되감기가 아닌 스택 스캔이고, 원격 경로에서는 스레드 정보가 크게 줄어듦
- **Category:** FUNC
- **Severity:** HIGH
- **Confidence:** HIGH
- **Evidence Type:** FACT
- **Requirement:** REQ-007
- **Gap Class:** LIMITED
- **Evidence:** `extractor/watch_session.py:5561-5606`, `extractor/watch_session.py:5587-5600`, `extractor/target_adapter.py:1246-1247`, `extractor/target_adapter.py:1781-1788`, `extractor/watch_session.py:5481`, `extractor/dwarf_indexer.py:653-654`, `scripts/mcp_server.py:1899-1901`
- **Observed:** 스택 메모리 최대 32KB를 읽어 실행 영역을 가리키는 모든 값을 반환 주소로 취급한다. 이전 호출이 남긴 값이 유령 프레임으로 나올 수 있다. 사용자 공간에서 실행 중인 스레드는 스택 포인터를 얻지 못한다. 말단 함수 복구는 x86의 CALL 명령 바이트에 의존한다. 원격 어댑터는 스레드의 tid·상태·이름만 주고 스택 정보는 "사용 불가"이며 syscall 파일을 읽지 않는다. 저장소에는 CFI 표 파서가 이미 있으나 이 경로에서 프레임 되감기에 쓰이지 않는다. MCP 도구 설명은 이를 "되감기(Unwinds)"라고 부른다.
- **Expected:** CFI나 프레임 포인터로 프레임을 정확히 되감고, 원격 타깃에서도 같은 수준의 스레드 정보를 얻는다.
- **Gap:** "스레드가 어디서 멈췄는가"의 답이 부정확할 수 있고, 정작 임베디드(원격) 경로에서 스레드 진단 능력이 가장 약하다.
- **Recommendation:** CFI 기반 되감기와 수집기 측 스레드 정보 수집을 추가한다. IMP-011 참조.

# Blindspot and Risk Report: dynamicState

- Target: `C:\task\dynamicState\dynamicState` @ `f842448` (main), working tree clean
- Diagnostic date: 2026-11-12 · Mode: full · Scope: 문서·테스트·계획이 말하지 않는 문제, 숨은 가정, 실패 시나리오, 운영 준비도(임베디드 진단 도구 기준)
- Not examined: 테스트 실행 결과, 실제 임베디드 보드 동작, 의존 패키지 취약점(도구 없음), 웹 프런트엔드 내부

## Method and coverage

| 점검 영역 | 결과 |
|---|---|
| 요구사항은 있으나 구현 없음 | 발견: REQ-006, NFR-006 (REQUIREMENT_TRACEABILITY.md) |
| 구현은 있으나 목적 없음 | 발견: 체크포인트·변이 경로, 신뢰 장치 비중 (F-ARCH-004), 도달 불가 코드 (F-FUNC-012) |
| 문서가 없는 기능을 설명 | 발견: F-DOC-001, gdbserver 패턴(코드 없음) |
| 기본값이 꺼져 있거나 대체 경로가 주 경로를 조용히 대신함 | 발견: F-FUNC-004, F-RISK-001, F-BUILD-001 |
| 테스트하지 않는 테스트 | 발견: F-TEST-001, F-TEST-002 |
| CI가 중요한 테스트를 실행하지 않음 | 발견: F-TEST-001 (CI 자체가 미가동) |
| 같은 개념의 모델 불일치 | 발견: 판정 어휘 3종 (F-ARCH-001) |
| 하드코딩된 플랫폼 가정 | 발견: F-RISK-002 |
| 넓은 예외 삼킴 | 발견: `extractor/watch_session.py:11431-11445`, `extractor/watch_session.py:6736-6737`, `extractor/target_adapter.py:1378-1379` |
| 제한 없는 자원 증가 | 발견: F-PERF-001 (타깃 저장소에 최대 64MB 기록) |
| 신뢰할 수 없는 입력이 셸에 도달 | 확인함: 문제 없음. `shell=True`, `os.system` 없음. SSH 명령은 `shlex.quote` 사용(`extractor/target_adapter.py:1508-1512`) |
| 저장소 내 비밀 값 | 확인함: 저장소 안에서는 발견되지 않음 |
| 권한 있는 동작의 무방비 노출 | 발견: F-SEC-001 |
| 되돌림·"수정의 수정" 이력 | 발견: F-QUAL-001 |

## Undocumented problems

저장소 문서가 언급하지 않는 문제만 적는다. 상세는 아래 Findings.

1. 조사 기본 경로가 대상 프로세스를 SIGSTOP으로 정지시키는데, 보고서는 정지 시간 0.00ms를 고정 출력한다(F-RISK-001).
2. 교착 검증 테스트 11개 파일이 삭제된 심볼을 참조한다(F-TEST-001).
3. 웹 API에 인증이 없고 모든 출처를 허용하며, 기본 모드에서 변이 기능이 열려 있다(F-SEC-001).
4. x86_64와 glibc를 가정한 상수가 ARM·musl 타깃에서 거부되지 않고 잘못된 값을 낸다(F-RISK-002).
5. `mcp` 패키지가 없으면 MCP 서버가 오류 없이 아무 일도 하지 않고 끝난다(F-BUILD-001).
6. 수집기 자동 배포는 호스트와 같은 아키텍처일 때만 동작하고, 교차 빌드 절차가 없다(F-OPS-001).

## Hidden assumptions

- **대상의 변수 이름이 관례를 따른다.** pool, leak, buffer, mutex, lock, magic, canary 같은 단어가 이름에 있어야 후보가 된다(`extractor/runtime_evidence_provider.py:592-617`, `extractor/watch_session.py:5405`).
- **mutex는 전역 변수다.** 구조체 멤버, 힙, 스택의 mutex는 보이지 않는다(`extractor/watch_session.py:5397-5411`).
- **libc는 glibc, 워드는 64비트 리틀 엔디언이다.** (`extractor/allocator_inspector.py:203-209`, `extractor/target_adapter.py:1338-1349`)
- **시스템콜 번호는 x86_64다.** (`extractor/watch_session.py:5459-5463`)
- **힙은 `[heap]` 영역 하나다.** mmap 할당과 스레드 아레나는 힙으로 보지 않는다(`extractor/allocator_inspector.py:792-802`, `extractor/watch_session.py:7068-7071`).
- **호스트에 `nm`, `readelf`, `addr2line`가 있고 타깃 아키텍처의 ELF를 읽을 수 있다.** (`extractor/watch_session.py:7027-7028`, `extractor/dwarf_indexer.py:671`)
- **비스트립 디버그 ELF를 항상 구할 수 있다.** 없으면 타입 기반 도구는 모두 동작하지 않는다(`extractor/watch_session.py:5750-5751`).
- **타깃에 SSH 서버, `base64`, 쓰기·실행 가능한 `/tmp`가 있다.** (`extractor/target_adapter.py:2039`, `extractor/target_adapter.py:2119-2122`)
- **테스트 호스트는 aarch64다.** (`tests/test_phase2_4_real_world_targets.py:276-278`)

## Potential failure scenarios

| Scenario (trigger -> mechanism -> impact) | Evidence | Objective affected | Evidence type | Confidence |
|---|---|---|---|---|
| 권한 부족이나 프로세스 종료로 트리아지 실패 → 예외를 "정상"으로 대체 → 사용자가 문제 없음 보고서를 받음 | `extractor/watch_session.py:11431-11432` | OBJ-003, OBJ-004 | FACT | HIGH |
| 워치독이 있는 임베디드 프로세스에 `investigate` 실행 → 기본 FULL 모드가 SIGSTOP → 정지 중 워치독 만료 또는 통신 타임아웃 | `extractor/capture_plan.py:26`, `extractor/capture_backend.py:3518`, `docs/PRACTICAL_PLAYBOOK_KO.md:11` | OBJ-002 | INFERENCE | MEDIUM |
| musl 기반 타깃에서 락 검사 → glibc 배치로 소유자 필드를 읽음 → 엉뚱한 스레드를 락 소유자로 보고 | `extractor/watch_session.py:5416-5421` | OBJ-005 | INFERENCE | MEDIUM |
| ARM 타깃에서 스레드 검사 → x86_64 번호표로 시스템콜 이름을 붙임 → futex 대기를 인식하지 못해 교착을 놓침 | `extractor/watch_session.py:5459-5463`, `extractor/watch_session.py:5483-5518` | OBJ-005 | INFERENCE | MEDIUM |
| 이름 관례가 다른 제품 코드 진단 → 후보 변수 0개 → "증거 부족" 또는 범위 내 문제 없음 | `extractor/runtime_evidence_provider.py:592-617` | OBJ-005 | INFERENCE | MEDIUM |
| 작은 블록이 해제 후 재사용 대기(tcache) → PREV_INUSE 비트가 유지됨 → 해제된 블록을 가리키는 포인터가 정상으로 분류 | `extractor/allocator_inspector.py:849-861` | OBJ-005 | INFERENCE | MEDIUM |
| 운영자가 웹 UI를 켠 채 다른 웹 페이지를 방문 → 인증 없는 로컬 API를 그 페이지가 호출 → 프로세스 메모리 읽기 또는 변이 | `extractor/web/server.py:4195`, `extractor/agent_runtime.py:75` | NFR-005 | INFERENCE | MEDIUM |
| 정적 링크한 수집기(수백 KB)를 자동 배포 → 바이너리 전체를 명령행 인자로 전달 → 인자 길이 제한 초과로 배포 실패 | `extractor/target_adapter.py:2116-2123` | OBJ-002 | HYPOTHESIS | LOW |
| 저장소가 작은 보드에서 스냅샷 모드 수집 → 최대 64MB를 타깃 저장소에 쓰고 fsync → 플래시 마모, tmpfs라면 메모리 압박 | `target/collector/src/collector.c:819-825` | OBJ-002 | INFERENCE | MEDIUM |

## Reliability and operational readiness

임베디드 진단 도구 기준으로 평가했다.

| Dimension | Rating (READY / NEEDS_WORK / NOT_READY / UNKNOWN) | Justification |
|---|---|---|
| 빌드 재현성 | NOT_READY | 의존성 선언, 패키징, 잠금 파일, LICENSE 없음(`requirements.txt:1-2`). 수집기 Makefile에 정적 링크·교차 타깃 없음(`target/collector/Makefile:1-13`) |
| 테스트 신뢰성 | NOT_READY | CI 미가동(`ci/README.md:34`). 테스트 11개 파일이 삭제된 심볼 참조. 일부 테스트가 aarch64 호스트를 단언 |
| 의존성 관리 | NEEDS_WORK | `mcp`, `yaml`, `playwright`가 선언 없이 import됨. 호스트 binutils 의존이 문서화되지 않음 |
| 타깃 영향(무정지) | NEEDS_WORK | 슬라이스 경로는 무정지. 스냅샷 기본 모드는 정지. 영향 측정 없음(F-RISK-001, F-PERF-001) |
| 교차 컴파일·타깃 지원 | NOT_READY | x86_64·glibc 가정이 거부 없이 적용됨. 실제 보드·에뮬레이터 실행 기록 없음(F-RISK-002, F-TEST-003) |
| 배포 준비 | NEEDS_WORK | 수집기 자동 배포는 같은 아키텍처만. 버전 관리와 릴리스 산출물 없음(F-OPS-001) |
| 설정 | NEEDS_WORK | 기본 관측 모드가 변이 허용(CONSISTENT). 포트 기본값이 문서와 다름 |
| 런타임 안정성 | NEEDS_WORK | 정지 후 재개 보장과 PID 재사용 방지는 좋음. 예외 삼킴이 판정을 왜곡함 |
| 자원 소비(타깃) | NEEDS_WORK | 슬라이스 읽기는 64KB 제한으로 가벼움. 스냅샷은 최대 64MB를 타깃에 기록. 읽기마다 SSH와 프로세스 생성 |
| 보안 | NEEDS_WORK | 웹 서버는 127.0.0.1에만 바인드(좋음). 인증·출처 검사 없음, 변이 기본 허용(F-SEC-001) |
| 오류 진단 | NEEDS_WORK | 권한 오류 분류와 ptrace_scope 안내는 좋음(`scripts/mcp_server.py:155`). 일부 경로는 실패를 숨김 |
| 진단 정확도 평가 | NOT_READY | 정답이 정해진 실제 프로세스 정확도 측정 없음. 커밋된 결과는 합성 사례나 스모크 실행(F-TEST-002) |
| 유지보수성 | NEEDS_WORK | 11,627줄 파일, 엔진 중복, 지연 import 153개 |

## Findings

### F-RISK-001: 조사 기본 경로가 대상 프로세스를 정지시키고, 보고서는 정지 시간을 0으로 고정 출력함
- **Category:** RISK
- **Severity:** HIGH
- **Confidence:** HIGH
- **Evidence Type:** FACT
- **Requirement:** NFR-001
- **Evidence:** `extractor/capture_plan.py:26`, `extractor/capture_backend.py:3220`, `extractor/capture_backend.py:3312-3315`, `extractor/capture_backend.py:3518`, `extractor/capture_backend.py:3546-3561`, `extractor/investigation.py:1452`, `extractor/cli.py:867-880`, `extractor/watch_session.py:11474`, `extractor/expert_diagnostic_engine.py:2979`, `benchmarks/latest_results.json:107-110`
- **Observed:** 캡처 플랜의 기본 모드는 FULL이고, ZERO_STOP이 아닌 모든 모드는 SIGSTOP을 보낸다. 레거시 조사(`investigate` CLI, 웹 조사 시작)는 플랜 없이 캡처를 호출하므로 대상이 정지한다. 정지 확인은 `sched_yield`를 도는 바쁜 대기다. 저장소의 벤치마크 기록은 25.7MB 캡처에서 중앙값 약 4.1ms 정지를 보여 준다(4코어 aarch64 서버 기준). 반면 사고 보고서는 "Process Stop Duration: 0.00ms"를 고정 문자열로 쓰고, 전문가 보고서는 수집 모드를 상수 "ZERO_STOP_LIVE_RUNTIME"으로 채운다.
- **Expected:** 워크플로우 명세는 명시적 승인 없이는 정지 시간 0을 요구한다(`docs/PROCESS_HEALTH_INVESTIGATION_SKILL.md:38`).
- **Gap:** 임베디드에서 수 ms 이상의 정지는 워치독, 실시간 주기, 통신 타임아웃에 영향을 준다. 저사양 보드에서는 서버 측정값보다 길어진다. 사용자는 보고서를 보고 정지가 없었다고 믿게 된다.
- **Recommendation:** 기본 모드를 ZERO_STOP으로 바꾸고, 정지 수집은 명시적 승인이 있을 때만 허용하며, 보고서에는 측정값을 싣는다. IMP-002 참조.

### F-RISK-002: x86_64·glibc·64비트 리틀 엔디언 가정이 다른 타깃에서 거부되지 않고 그대로 적용됨
- **Category:** RISK
- **Severity:** HIGH
- **Confidence:** MEDIUM
- **Evidence Type:** INFERENCE
- **Requirement:** NFR-004
- **Evidence:** `extractor/watch_session.py:5459-5463`, `extractor/watch_session.py:5416-5421`, `extractor/watch_session.py:5587-5600`, `extractor/allocator_inspector.py:203-209`, `extractor/allocator_inspector.py:701-708`, `extractor/target_adapter.py:1338-1349`, `extractor/target_adapter.py:2156-2162`
- **Reasoning:** 사실: 시스템콜 이름표는 x86_64 번호다. mutex는 처음 세 개의 32비트 정수를 lock·count·owner로 읽고 libc 종류를 확인하지 않는다. 말단 프레임 복구는 x86 CALL 명령 바이트를 찾는다. 할당자 청크는 리틀 엔디언으로 읽고 glibc 여부는 경로에 "libc.so"가 있는지로 판단한다. musl·아키텍처·엔디언 관련 ABI 상수는 정의만 있고 `extractor/` 안에서 쓰이지 않는다. 추론: ARM이나 musl 타깃에서 이 경로들은 오류를 내지 않고 틀린 이름·소유자·분류를 낸다. 해당 환경에서 실행해 확인하지는 않았다.
- **Observed:** 미지원 환경을 감지해 "지원하지 않음"으로 거부하는 관문이 실제 경로에 없다.
- **Expected:** 구조 문서는 검증할 수 없는 아키텍처·엔디언을 추측하지 말고 UNKNOWN으로 보고하라고 한다(`docs/EMBEDDED_DEPLOYMENT_ARCHITECTURE.md:54-55`).
- **Gap:** 프로젝트가 가장 중요하게 여기는 임베디드 타깃(ARM32, musl, uClibc)에서 조용한 오진 위험이 가장 크다.
- **Recommendation:** 타깃의 아키텍처·libc·워드 크기를 판별해 미지원 조합은 해당 검사를 거부하고, 지원 표를 아키텍처별로 넓힌다. IMP-015 참조.

### F-TEST-001: CI가 가동된 적이 없고, 교착 검증 테스트 11개 파일이 삭제된 심볼을 참조함
- **Category:** TEST
- **Severity:** HIGH
- **Confidence:** HIGH
- **Evidence Type:** FACT
- **Requirement:** REQ-007
- **Evidence:** `ci/README.md:34`, `tests/test_ci_workflow_parity.py:37-41`, `tests/test_phase2_0_a_3_4_1_deadlock_evidence_and_budget.py:74-84`, `tests/test_phase2_0_a_3_4_deadlock_proof_and_budget_audit.py:306-335`, `commit:533a0bb`; `cmd: git ls-files .github` 결과 0줄
- **Observed:** `.github/`가 없고 CI 문서가 워크플로우를 올리지 못했다고 밝힌다. CI 설정과 실제 워크플로우의 일치를 검사하는 테스트는 워크플로우 디렉터리가 없으면 건너뛴다. `WaitForEdge`, `RESULT_DEADLOCK_CYCLE_CONFIRMED`, `resolve_mutex_owner`는 테스트 11개 파일에서 145회 참조되지만 `extractor/`와 `scripts/`에는 없다. 이 심볼들은 커밋 533a0bb(13,978줄 삭제)에서 제거되었다. 실행하지 않았으므로 "import 단계에서 실패한다"는 것은 추론이다.
- **Expected:** 핵심 판정(교착)의 실제 프로세스 검증 테스트가 현재 소스에 대해 실행되고 통과해야 한다.
- **Gap:** 교착을 실제 프로세스로, 음성 대조군(조건 변수 대기, 단순 경합)과 함께 검증하던 가장 강한 테스트들이 지금은 동작하지 않을 가능성이 높다. 이를 알려 줄 자동 관문이 없다.
- **Recommendation:** Linux에서 전체 테스트를 한 번 실행해 실패 목록을 만들고, 깨진 테스트를 현재 API로 옮기거나 폐기한 뒤 CI를 가동한다. IMP-005 참조.

### F-TEST-002: 정확도 테스트가 상수를 단언하거나 답을 직접 주입하며, 원인 이름을 확인하는 테스트가 없음
- **Category:** TEST
- **Severity:** HIGH
- **Confidence:** HIGH
- **Evidence Type:** FACT
- **Requirement:** REQ-004
- **Evidence:** `tests/test_phase2_4_1_recipe_accuracy_and_evidence_path.py:421-430`, `tests/test_phase2_4_1_recipe_accuracy_and_evidence_path.py:399`, `tests/test_phase2_1_8_complete_validation.py:889-896`, `tests/test_phase2_1_8_complete_validation.py:974-978`, `tests/test_phase2_4_2_real_process_temporal_growth_and_accuracy.py:229-235`, `tests/test_phase2_0_a_3_12_real_cpp_e2e.py:192-211`, `tests/test_phase2_4_4_adaptive_investigation.py:191-193`
- **Observed:** "22개 레시피 정확도" 테스트는 `real_tp = 4`, `real_fp = 0`을 대입하고 그 값을 단언하며, "증거 부족"을 참음성으로 센다. 다른 테스트는 실제 프로세스에서 카나리 값을 읽은 뒤 `canary_corrupted: True`를 손으로 써서 레시피에 넣는다. 누수 테스트는 상태와 신뢰도만 본다. 실제 교착 프로세스에 대해 "범위 내 문제 없음"도 통과로 받는 테스트가 있다. "검사 목록이 비어 있지 않음"이라는 이름의 테스트는 리스트 타입인지만 확인한다. 진단 결과에 올바른 변수·스레드·락 이름이 들어 있는지 단언하는 테스트는 찾지 못했다(tests 전체에서 결론·판정·보고서 필드에 대한 이름 단언 검색).
- **Expected:** 결함을 심은 실제 프로세스에 대해 "어떤 변수, 어떤 스레드"까지 맞혔는지 확인하고, 정상 프로세스에서는 오탐이 없음을 확인한다.
- **Gap:** 현재 테스트는 규칙이 입력에 대해 정해진 출력을 내는지만 보증한다. 실제 프로세스에서 원인을 찾아내는지는 보증하지 않는다.
- **Recommendation:** 정답표가 있는 실제 프로세스 벤치마크를 만든다. IMP-013 참조.

### F-TEST-003: 임베디드 보드, 에뮬레이터, 비-glibc 환경에서의 실행 기록이 없음
- **Category:** TEST
- **Severity:** HIGH
- **Confidence:** HIGH
- **Evidence Type:** FACT
- **Requirement:** NFR-003
- **Evidence:** `benchmarks/latest_results.json:3-9`, `docs/PHASE_2_4_FINAL_REPORT.md:6`, `extractor/production_pilot.py:672-675`, `tests/test_phase2_4_real_world_targets.py:253-267`, `tests/test_phase2_4_real_world_targets.py:276-278`, `ci/workflows/test.yml:27-29`
- **Observed:** 기록된 실행 환경은 aarch64 클라우드 서버(glibc 2.39)다. "양산 파일럿"은 실행 모드가 `SIMULATED_REPRESENTATIVE_TARGET`, 실제 하드웨어 검증은 거짓이다. ARM32 검증은 교차 컴파일러가 있을 때 hello-world의 ELF 헤더를 파싱하는 것이고, 컴파일러가 없으면 검사 없이 통과한다. 원격 SSH 경로는 가짜 명령 실행기로 테스트한다. qemu, busybox, musl을 쓰는 테스트나 CI 단계가 없다(`ci/`, `docker/`에서 검색 결과 없음).
- **Expected:** 프로젝트의 주 대상인 저사양 ARM 리눅스에서 수집기와 진단 경로가 실제로 실행된 기록.
- **Gap:** "임베디드 지원"은 현재 설계 의도이며 검증된 사실이 아니다.
- **Recommendation:** 에뮬레이터 기반 타깃 행렬을 만든다. IMP-014 참조.

### F-SEC-001: 웹 API에 인증이 없고 모든 출처를 허용하며, 기본 모드에서 변이 기능이 열려 있음
- **Category:** SEC
- **Severity:** HIGH
- **Confidence:** MEDIUM
- **Evidence Type:** INFERENCE
- **Requirement:** NFR-005
- **Evidence:** `extractor/web/server.py:4195`, `extractor/web/server.py:4217-4257`, `extractor/web/server.py:3721-3726`, `extractor/agent_runtime.py:75`, `extractor/agent_runtime.py:663-667`, `scripts/mcp_server.py:520`, `extractor/cli.py:1218`
- **Reasoning:** 사실: 웹 서버는 `Access-Control-Allow-Origin: *`를 보내고, 요청 헤더에서 인증이나 출처를 검사하지 않으며, POST에 JSON 콘텐츠 타입을 요구하지 않는다. PID가 주어지면 대상 승인(`authorize_target`)이 자동으로 참이 된다. 런타임의 기본 관측 모드는 CONSISTENT이고, 변이·체크포인트는 모드가 LOW_IMPACT일 때만 차단된다. LOW_IMPACT를 강제하는 것은 워크스페이스 실행기뿐이다. 추론: 운영자 브라우저에 열린 임의의 웹 페이지가 로컬 API를 호출해 프로세스 메모리를 읽거나, GDB 제어기가 붙어 있으면 변이를 실행할 수 있다. 공격을 재현하지는 않았다.
- **Observed:** 읽기 전용 진단 도구인데 기본 설정이 "쓰기 허용, 호출자 무확인"이다. 완화 요소는 127.0.0.1 바인드와, 변이에 GDB 제어기가 필요하다는 점이다.
- **Expected:** 워크플로우 명세는 대상 메모리 쓰기와 신호 주입을 금지한다(`docs/PROCESS_HEALTH_INVESTIGATION_SKILL.md:37`).
- **Gap:** 임의 프로세스 메모리를 읽는 도구로서 노출 면이 넓다. 한국어 플레이북은 `--host 0.0.0.0` 실행을 안내한다(`docs/PRACTICAL_PLAYBOOK_KO.md:65`).
- **Recommendation:** 기본 모드를 LOW_IMPACT로, 세션 토큰과 출처 검사를 추가한다. IMP-019 참조.

### F-OPS-001: 수집기 배포가 호스트와 같은 아키텍처에서만 동작하고 교차 빌드 절차가 없음
- **Category:** OPS
- **Severity:** MEDIUM
- **Confidence:** HIGH
- **Evidence Type:** FACT
- **Requirement:** NFR-003
- **Evidence:** `extractor/target_adapter.py:2066-2079`, `extractor/target_adapter.py:2093-2114`, `extractor/target_adapter.py:2116-2123`, `target/collector/Makefile:1-13`, `.gitignore:17`
- **Observed:** 자동 배포는 저장소의 `target/collector/dynamicstate-collector` 하나만 찾는다. 아키텍처가 다르면 셸 폴백으로 내려간다. Makefile에는 정적 링크 옵션과 교차 타깃이 없고, 빌드 산출물은 git에서 제외된다. 배포는 바이너리 전체를 base64로 바꿔 명령행 인자로 보낸다. 배포 위치 기본값은 `/tmp`다.
- **Expected:** 아키텍처별 정적 바이너리를 미리 만들어 두고, 타깃의 `uname -m`에 맞는 것을 골라 배포한다.
- **Gap:** x86 호스트에서 ARM 보드를 진단하는 가장 흔한 구성에서 자동 배포가 동작하지 않고, 바이트 단위 `dd` 폴백으로 내려가 타깃 부하가 커진다. 인자 길이 제한 문제는 확인하지 못한 가설이다(위 실패 시나리오 표).
- **Recommendation:** 아키텍처별 정적 빌드와 표준입력 기반 전송으로 바꾼다. IMP-016 참조.

### F-BUILD-001: 의존성·패키징·라이선스가 없고, `mcp`가 없으면 MCP 서버가 조용히 종료함
- **Category:** BUILD
- **Severity:** MEDIUM
- **Confidence:** HIGH
- **Evidence Type:** FACT
- **Requirement:** REQ-001
- **Evidence:** `requirements.txt:1-2`, `scripts/mcp_server.py:17-36`, `README.md:89`, `README.md:264`, `docker/gdb92/Dockerfile:1-12`
- **Observed:** `requirements.txt`는 주석뿐이다. MCP 서버는 `mcp` import에 실패하면 `run()`이 아무 일도 하지 않는 대체 클래스를 쓴다. 따라서 패키지가 없는 환경에서 서버는 오류 없이 끝나고, 에이전트는 도구가 왜 없는지 알 수 없다. README가 권장하는 `pyelftools`는 어디에서도 import되지 않는다. `setup.py`, `pyproject.toml`, 잠금 파일, LICENSE가 없다. Dockerfile의 베이스 이미지와 패키지는 버전이 고정되어 있지 않다.
- **Expected:** 설치 한 번으로 MCP 서버가 뜨고, 필수 의존성이 없으면 명확한 오류를 낸다.
- **Gap:** 사용 흐름의 첫 단계(MCP 연결)가 환경에 따라 원인 표시 없이 실패한다.
- **Recommendation:** 의존성을 선언하고 누락 시 오류로 종료하게 한다. IMP-022 참조.

### F-PERF-001: 수집이 대상과 타깃 보드에 준 부하를 측정하지 않음
- **Category:** PERF
- **Severity:** MEDIUM
- **Confidence:** HIGH
- **Evidence Type:** FACT
- **Requirement:** NFR-006
- **Evidence:** `extractor/observation_budget.py:34-43`, `benchmarks/capture_benchmark.py:296-330`, `tests/test_phase2_4_collection_reliability_and_overhead.py:203`, `tests/test_phase2_4_collection_reliability_and_overhead.py:216-217`, `target/collector/src/collector.c:819-825`, `extractor/capture_backend.py:2160-2167`
- **Observed:** 예산 추적기는 경과 시간, 읽은 바이트, 표본 수, 실패 수, 정지 시간(선택)을 다루고 CPU 예산과 타깃 측 비용은 없다. 벤치마크와 "오버헤드" 테스트는 수집기 쪽 지연 시간만 측정한다. 대상 프로세스의 처리량·지연·CPU 변화를 재는 코드는 없다(overhead, utime, getrusage, slowdown, cpu_percent 검색). 스냅샷 모드 수집기는 최대 64MB를 타깃 저장소에 쓴다. 캡처 정책의 `timeout_ms`는 선언만 있고 읽히지 않는다.
- **Expected:** "영향 최소화"를 주장하려면 수집 전후로 대상의 CPU 시간, 문맥 전환, (가능하면) 처리량을 재고 보고서에 싣는다.
- **Gap:** 영향이 작다는 것을 보일 근거가 없고, 저사양 보드에서의 예산을 정할 기준도 없다.
- **Recommendation:** 대상의 `/proc/PID/stat` 변화로 수집 중 부하를 재고 보고서에 넣는다. IMP-020 참조.

### F-QUAL-001: 개발 과정이 자기 선언적 완료 판정과 대규모 일괄 변경에 의존함
- **Category:** QUAL
- **Severity:** MEDIUM
- **Confidence:** MEDIUM
- **Evidence Type:** INFERENCE
- **Requirement:** N/A — 개발 과정
- **Evidence:** `commit:533a0bb`, `docs/PHASE_2_4_FINAL_REPORT.md:7`, `docs/PHASE_2_4_4_FINAL_REPORT.md:6`, `docs/FUNCTIONAL_GAP_ANALYSIS_AND_DEVELOPMENT_ROADMAP.md:7`; `cmd: git rev-list --count HEAD` 결과 236
- **Reasoning:** 사실: 45일간 커밋 236개, 하루 최대 19개, 사실상 단일 작성자. 단계 번호가 3 → 6 → 32~52 → 2.0-A.3.4.34.1 → 0 → 1.2 → 2.4.4로 오르내린다. "closure"라는 이름의 연속 커밋이 약 40개다. 패치 파일을 통째로 적용한 커밋이 여럿이고 그중 하나가 13,978줄을 삭제해 테스트를 깨뜨렸다. 각 단계 보고서가 스스로 GO 판정을 내리며, 마지막 보고서의 커밋 해시는 "TBD"다. 추론: 단계마다 직전 단계의 주장을 감사하고 "종결"하는 반복이 자기 검증 장치를 키웠고, 독립된 관문(CI, 다른 검토자, 외부 대상)이 없어 방향 이탈을 잡지 못했다.
- **Observed:** 완료 판정을 내리는 주체와 구현 주체가 같고, 판정 근거가 저장소에 남지 않는다.
- **Expected:** 완료는 자동 관문(CI)과 외부 기준(정답표 벤치마크)으로 판정한다.
- **Gap:** 현재 방식이 계속되면 문서상 완성도는 오르고 실제 진단 능력은 제자리일 위험이 있다.
- **Recommendation:** IMP-005(CI)와 IMP-013(정답표 벤치마크)을 완료 판정의 유일한 기준으로 삼는다. 별도 항목은 두지 않았다.

## Confidence and evidence notes

- **실행하지 않음.** 모든 결론은 코드·테스트·문서·git 이력을 읽은 결과다. 테스트 통과 여부, 실제 오진 발생 여부는 UNKNOWN이다. F-FUNC-005, F-FUNC-008, F-FUNC-009, F-RISK-002, F-SEC-001은 코드에서 읽은 사실로부터의 추론이며 Linux에서 재현해 확정해야 한다.
- **열린 가설:** 수집기 자동 배포의 인자 길이 초과. 확인 방법은 정적 링크한 수집기로 `ensure_remote_collector`를 실행해 보는 것이다.
- **확인하지 못한 것:** Phase 41, 46, 47 테스트(프레임 매개변수, TLS, 폴링 스레드 되감기)가 지금도 실패하는지. 자체 분석 문서는 실패라고 적었고(`docs/FUNCTIONAL_GAP_ANALYSIS_AND_DEVELOPMENT_ROADMAP.md:132-134`) 이후 문서에 수정 언급이 없다.
- **조사 방식:** 구성요소 6개를 병렬로 조사했고, 그 결과 중 심각도 HIGH 이상인 주장은 해당 줄을 직접 다시 읽어 확인했다. MEDIUM 이하 일부 인용은 조사 보고의 줄 번호를 그대로 썼다(검증 스크립트가 줄 존재 여부는 확인함).
- **인벤토리 스크립트의 한계:** `target/` 디렉터리를 빌드 산출물로 보고 제외했다. 수집기 소스는 직접 읽었다.

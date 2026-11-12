# Architecture Audit: dynamicState

- Target: `C:\task\dynamicState\dynamicState` @ `f842448` (main), working tree clean
- Diagnostic date: 2026-11-12 · Mode: full · Scope: 구성요소 의존 구조, 진단 파이프라인, 원격 수집 경로, 지식 표현 방식
- Not examined: 웹 프런트엔드(`extractor/web/static/app.js`) 내부 구조, eBPF 추적기 설계, GDB 체크포인트·변이 경로(사용자 목적인 읽기 전용 진단과 무관)

## Current architecture

| 층 | 구성요소 | 책임 |
|---|---|---|
| 인터페이스 | `scripts/mcp_server.py`(도구 65개), `extractor/cli.py`(하위 명령 43개), `extractor/web/server.py` | 사용자·에이전트 요청을 엔진에 전달 |
| 진단 | `extractor/expert_diagnostic_engine.py` + `extractor/diagnostic_recipes.py` + `extractor/runtime_evidence_provider.py` | 분류, 계획, 레시피 실행, 가설, 결론 |
| 진단(병렬) | `extractor/adaptive_engine.py`, `extractor/investigation.py`, `extractor/watch_session.py`의 자동 트리아지, `extractor/workflow.py` | 같은 일을 하는 다른 엔진들 |
| 판정·보고 | `extractor/diagnostic_verdict_aggregator.py`, `extractor/verdict_engine.py`, `extractor/diagnostic_report.py` | 판정 집계, 보고서 렌더링 |
| 해석 | `extractor/dwarf_indexer.py`, `extractor/dwarf_evaluator.py`, `extractor/cpp_decoder.py`, `extractor/allocator_inspector.py` | 심볼·타입 해석, 할당자 검사 |
| 수집 | `extractor/target_adapter.py`, `extractor/capture_backend.py`, `extractor/observation_budget.py` | 로컬·원격 메모리와 /proc 읽기, 예산 |
| 타깃 측 | `target/collector/` (C99) | 스냅샷, 슬라이스 읽기, 데몬 모드 |
| 증거 | `extractor/evidence_ledger.py` | 증거 기록, 출처·영수증 검증 |

### Actual dependency structure

```
MCP / CLI / Web
   |         |          |
   v         v          v
expert    legacy     watch_session        (엔진 3종. 인터페이스마다 연결 대상이 다름)
engine    investigation   auto-triage
   |         |          |
   +----+----+----------+
        v
 target_adapter  ---- SSH ---->  target/collector (C)  또는  sh + dd 폴백
 capture_backend
        v
 /proc, process_vm_readv
```

구성요소 간 순환 의존은 없다(`_inventory/dependencies.md`: `scripts`, `extractor/web`, `tests`가 `extractor`를 단방향으로 참조). 함수 내부의 지연 import가 153개여서 정적 그래프에 드러나지 않는 결합은 있다. 가장 많이 참조되는 모듈은 `extractor/target_adapter.py`(84), `extractor/evidence_ledger.py`(82), `extractor/capture_backend.py`(73)이다.

문서의 구조(`README.md:38-62`)는 AgentRuntime 아래 두 모드(LOW_IMPACT, CONSISTENT)만 그리지만, 실제로는 진단 엔진이 여러 개 병렬로 있다. 이 차이가 F-ARCH-001이다.

### Data flow and state

- 관측값은 어댑터에서 읽혀 증거 기록(`EvidenceRecord`)으로 감싸지고, 레시피 평가 결과가 가설을 갱신하며, 집계기가 최종 판정을 낸다.
- 전문가 엔진의 세션은 디스크에 저장된다(`scripts/mcp_server.py:530`). MCP 시작 도구는 전문가 세션과 레거시 세션을 둘 다 만들고 ID를 맞춘다(`scripts/mcp_server.py:512-530`). 한 조사에 상태 저장소가 둘이다.
- 수집 모드·정지 시간 같은 메타데이터는 실제 수집 경로에서 전달되지 않고 보고서 단계에서 상수로 채워진다(`extractor/expert_diagnostic_engine.py:2979`, `extractor/watch_session.py:11474`).

## Design strengths

보존해야 할 설계다. 로드맵은 이것들을 건드리지 않는다.

- **타깃·호스트 분리.** 타깃에는 의존성 없는 C 수집기, 호스트에는 DWARF 분석. 임베디드 제약에 맞는 구조다(`target/collector/src/main.c:262-388`, `docs/EMBEDDED_DEPLOYMENT_ARCHITECTURE.md:44-53`).
- **무정지 슬라이스 읽기.** 필요한 주소만 작게 읽는 경로가 실제로 정지 없이 동작하도록 구현되어 있다(`extractor/watch_session.py:103-173`). 수집기에는 ptrace나 신호 호출이 없다(`target/collector/src/collector.c:1317`).
- **PID 재사용 방지와 정지 후 재개 보장.** 단계마다 프로세스 동일성을 확인하고 `finally`에서 재개한다(`extractor/capture_backend.py:3505-3544`).
- **엄격한 "정상" 판정 게이트.** 집계기는 필수 검사 전부 통과, 판단 불가·건너뜀 0건일 때만 HEALTHY를 낸다(`extractor/diagnostic_verdict_aggregator.py:616-653`).
- **범위를 한정한 판정 어휘.** "검사 범위 내 문제 없음"과 검사하지 못한 범위를 구분한다(`extractor/verdict_engine.py:727-734`).
- **불완전한 락 그래프를 비순환으로 취급하지 않음.** (`extractor/diagnostic_recipes.py:1557-1567`, `extractor/concurrency_graph.py:278-355`)
- **판별 관측 선택기.** 경쟁 가설을 가르는 가장 싼 관측을 고르고 이유를 기록한다(`extractor/adaptive_engine.py:547-618`).
- **LLM 출력 접지.** 대화 기능의 LLM 응답에서 근거 없는 사실을 낮추고 모르는 증거 ID를 제거한다(`extractor/hypothesis.py:2201-2333`).
- **입력 방어.** PID 검증(`scripts/mcp_server.py:53-112`), `shell=True` 미사용, SSH 인자 인용(`extractor/target_adapter.py:1508-1512`).

## Architectural weaknesses

### F-ARCH-001: 진단 엔진 4종, 판정 어휘 3종, 보고서 생성기 3종이 병렬로 존재함
- **Category:** ARCH
- **Severity:** HIGH
- **Confidence:** HIGH
- **Evidence Type:** FACT
- **Requirement:** REQ-001
- **Evidence:** `extractor/expert_diagnostic_engine.py:1392-1444`, `extractor/adaptive_engine.py:1159`, `extractor/investigation.py:1243-1458`, `extractor/workflow.py:408`, `extractor/diagnostic_verdict_aggregator.py:53-59`, `extractor/verdict_engine.py:68-74`, `extractor/watch_session.py:6786-6787`, `extractor/diagnostic_report.py:539`, `extractor/watch_session.py:11378-11626`, `extractor/investigation.py:3421`, `docs/FUNCTIONAL_GAP_ANALYSIS_AND_DEVELOPMENT_ROADMAP.md:167-169`
- **Observed:** 전문가 엔진, 적응형 엔진, 레거시 조사 관리자, 워크플로우 엔진이 각각 수집·가설·판정을 구현한다. 판정 어휘와 보고서 형식도 엔진마다 다르다. MCP는 전문가 엔진, CLI와 웹 기본 UI는 레거시 엔진, 워크스페이스 UI와 1회 호출 보고서는 감시 세션 엔진을 쓴다. 저장소의 자체 분석 문서도 이중 엔진을 구조적 우려로 적었다.
- **Expected:** REQ-001과 REQ-009는 한 요청이 한 엔진을 끝까지 통과해 한 판정을 내기를 요구한다.
- **Gap:** 좋은 설계(엄격한 정상 게이트)가 한 엔진에만 있고 다른 경로에는 없어서 F-FUNC-004 같은 결함이 생긴다. 새 진단 능력을 추가할 때 어느 엔진에 넣을지 정해져 있지 않다.
- **Recommendation:** 전문가 엔진을 단일 진단 권한으로 정하고 다른 경로를 그 위로 옮긴다. 진입점은 IMP-006, 통합·제거는 IMP-017.

### F-ARCH-002: `watch_session.py` 한 파일에 수집·해석·진단·보고가 섞여 있음
- **Category:** ARCH
- **Severity:** MEDIUM
- **Confidence:** HIGH
- **Evidence Type:** FACT
- **Requirement:** REQ-009
- **Evidence:** `extractor/watch_session.py:103-173`, `extractor/watch_session.py:2432-2437`, `extractor/watch_session.py:5303-5322`, `extractor/watch_session.py:5731-5737`, `extractor/watch_session.py:7023-7052`, `extractor/watch_session.py:11378-11626`; `cmd: wc -l extractor/watch_session.py` 결과 11,627줄; 변경 횟수 27회(`_inventory/repository.md`)
- **Observed:** 메모리 읽기, 타입 디코딩, 스레드·락 검사, 무결성 감사, 힙 스캔, 자동 트리아지, 사고 보고서가 한 파일에 있다. 타입 디코딩은 `extractor/cpp_decoder.py`와 중복이고, 이 파일의 진단 경로는 집계기의 정상 게이트를 거치지 않는다.
- **Expected:** 판정을 내는 코드는 한곳의 규칙을 거쳐야 한다(REQ-009).
- **Gap:** F-FUNC-004의 예외 삼킴이 이 파일에 있고, 트리아지 내부에도 같은 패턴이 있다(`extractor/watch_session.py:6736-6737`). 파일 크기와 변경 빈도 때문에 이런 결함을 찾고 고치기 어렵다.
- **Recommendation:** 엔진 통합 때 이 파일의 검사 함수를 수집 계층으로 내리고 판정·보고 부분은 제거한다. IMP-017 참조. 그 전에 IMP-005로 테스트 기준선을 먼저 확보한다.

### F-ARCH-003: 전문가 지식이 분기문과 변수 이름 키워드로 코드에 박혀 있고, 테스트용 대상 프로그램의 이름·값과 닮아 있음
- **Category:** ARCH
- **Severity:** HIGH
- **Confidence:** MEDIUM
- **Evidence Type:** INFERENCE
- **Requirement:** OBJ-001
- **Evidence:** `extractor/diagnostic_recipes.py:1006`, `extractor/runtime_evidence_provider.py:592-617`, `extractor/runtime_evidence_provider.py:767-779`, `extractor/runtime_evidence_provider.py:1169-1174`, `extractor/watch_session.py:5397-5411`, `tests/fixtures/real_runtime/expert_diagnostic_scenarios.cpp:35`, `tests/fixtures/real_runtime/expert_diagnostic_scenarios.cpp:46`, `tests/fixtures/real_runtime/expert_diagnostic_scenarios.cpp:83`, `scripts/mcp_server.py:2645`
- **Reasoning:** 사실: 레시피 평가는 `recipe_id`에 대한 하나의 if/elif 사다리이고 수집은 도메인별 두 번째 사다리다. 진단 대상은 변수 이름에 pool·leak·retained·buffer·magic·canary·mutex·lock 등이 들어 있는지로 고른다. 손상은 값이 0xDEADBEEF 등일 때, 상태 위반은 값이 100 이상일 때다. 테스트용 프로그램에는 `g_leak_pool`, 0xDEADBEEF, `g_worker_state = 999`가 있다. 데모 심볼 `*gpMem`이 MCP·CLI의 기본값이다. 추론: 규칙이 테스트 대상에 맞춰 만들어졌고, 이름 규칙이 다른 실제 제품 코드에서는 후보가 잡히지 않아 "문제 없음" 또는 "증거 부족"으로 끝날 가능성이 높다.
- **Observed:** 지식 추가에는 두 사다리를 모두 고쳐야 하고, 탐지 조건이 대상 프로그램의 명명 관례에 의존한다.
- **Expected:** OBJ-001은 전문가 기법을 일반 프로세스에 적용할 수 있는 형태로 제공하기를 요구한다. 대상의 구조(타입, 포인터 관계, 할당자 상태)에서 출발해야 한다.
- **Gap:** 현재의 "22개 레시피 정확도"는 같은 저자가 만든 대상에 대한 것이며 일반화 근거가 없다.
- **Recommendation:** 레시피를 "필요한 관측 → 판정 규칙" 선언 형식으로 바꾸고, 이름 키워드 대신 타입·구조 기반 후보 선정으로 교체한다. IMP-018 참조. 일반화 여부는 IMP-013의 벤치마크(저자가 다른 대상 포함)로 확인한다.

### F-ARCH-004: 개발 노력이 신뢰·출처 검증 장치에 치우쳐 있고 핵심 진단 능력은 얕음
- **Category:** ARCH
- **Severity:** MEDIUM
- **Confidence:** MEDIUM
- **Evidence Type:** INFERENCE
- **Requirement:** OBJ-005
- **Evidence:** `extractor/evidence_ledger.py:87-815`, `extractor/evidence_ledger.py:1470-2068`, `extractor/expert_diagnostic_engine.py:1583-1713`, `target/collector/src/sha256.c`, `extractor/allocator_inspector.py:203-219`
- **Reasoning:** 증거 원장 2,468줄 중 약 1,600줄이 HMAC 영수증, 권한 토큰, 출처 전이 검증이다(함수 경계 기준 추정). 테스트 파일 이름에 trust·attest·provenance·ledger·accounting·closure·integrity·security가 들어간 것이 101개 파일, 약 5.3만 줄(전체의 약 46%)이고, 진단 능력 이름은 54개 파일, 약 2.9만 줄이다(파일명 기준 추정이며 내용 검토는 아님). 반면 할당자 검사는 청크 1개 수준이고 역추적은 없다(F-FUNC-001). 커밋 이력에는 2026-11-01 ~ 11-05 사이 "closure"라는 이름의 연속 커밋이 약 40개 있다.
- **Observed:** 증거가 위조되지 않았음을 보장하는 장치는 두텁고, 증거에서 원인을 찾는 능력은 얕다.
- **Expected:** OBJ-005(원인 특정)가 핵심 목표이므로 노력의 중심이 거기에 있어야 한다.
- **Gap:** 단일 사용자가 자기 프로세스를 진단하는 도구에서 위조 방지 영수증의 가치는 제한적이다. 유지 비용은 계속 든다.
- **Recommendation:** 신뢰 장치는 지금 상태로 동결하고(제거하지는 않음) 신규 노력은 IMP-007 ~ IMP-012에 둔다. 별도 로드맵 항목은 만들지 않았다. 동결은 작업이 아니라 우선순위 결정이기 때문이다.

### F-ARCH-005: 원격(임베디드) 읽기 경로가 읽기마다 프로세스를 새로 띄우고, 폴백은 바이트 단위 읽기임
- **Category:** ARCH
- **Severity:** HIGH
- **Confidence:** HIGH
- **Evidence Type:** FACT
- **Requirement:** NFR-001
- **Evidence:** `extractor/target_adapter.py:1484-1586`, `extractor/target_adapter.py:1799`, `extractor/target_adapter.py:1871`, `target/collector/src/main.c:262-388`, `target/collector/README.md:110-124`
- **Observed:** 원격 전송 수단은 `ssh` 실행 파일뿐이다. 수집기에는 표준입출력 데몬 모드가 있으나 Python 쪽에서 쓰지 않는다(`extractor/`, `scripts/`에서 `--daemon` 검색 결과 없음). 따라서 읽기 한 번마다 SSH 왕복과 타깃 측 프로세스 생성이 일어난다. 수집기가 없으면 `dd if=/proc/PID/mem bs=1`로 바이트마다 시스템콜을 한다.
- **Expected:** NFR-001과 OBJ-002는 타깃 부하 최소화를 요구한다. 반복 관측(누수 추세, 스레드 표본)에는 지속 연결이 필요하다.
- **Gap:** 저사양 보드에서 프로세스 생성과 SSH 암호화는 대상 프로세스와 CPU를 다툰다. IMP-008, IMP-010이 요구하는 주기적 표본 수집을 이 경로로 하면 타깃 영향이 커진다.
- **Recommendation:** 이미 있는 데몬 모드를 지속 SSH 세션으로 연결한다. IMP-021 참조.

## Structural risks

- **통합 없이 기능을 추가하면 엔진이 하나 더 생긴다.** 과거 이력이 그 패턴이다(Phase 2.0 적응형, Phase 2.1 전문가 엔진이 기존 것을 대체하지 않고 옆에 추가됨).
- **대규모 삭제의 여파.** 커밋 `commit:533a0bb`가 13,978줄을 삭제하면서 교착 검증에 쓰이던 심볼이 사라졌고 테스트는 그대로 남았다(F-TEST-001). 통합 작업에서 같은 일이 반복될 수 있으므로 테스트 기준선이 먼저다.
- **반복 관측이 필요한 진단(누수, 스레드 정지)은 원격 경로의 비용 구조와 충돌한다.** F-ARCH-005.
- **호스트 도구 의존.** `nm`, `readelf`, `addr2line`가 없거나 교차 아키텍처 ELF를 처리하지 못하면 기능이 조용히 비게 된다(`extractor/watch_session.py:7027-7028`).

## Recommended improvements

| Improvement | Findings | Serves requirement | Roadmap item |
|---|---|---|---|
| 전문가 엔진 위에 단일 `diagnose` 진입점 | F-ARCH-001, F-FUNC-007 | REQ-001 | IMP-006 |
| 엔진 통합과 도달 불가 코드 제거 | F-ARCH-001, F-ARCH-002, F-FUNC-012 | REQ-001, REQ-009 | IMP-017 |
| 선언형 레시피와 구조 기반 후보 선정 | F-ARCH-003, F-FUNC-009, F-FUNC-011 | OBJ-001, REQ-003 | IMP-018 |
| 수집기 데몬 모드를 지속 세션으로 연결 | F-ARCH-005 | NFR-001 | IMP-021 |
| 신뢰 장치 동결(작업 아님) | F-ARCH-004 | OBJ-005 | 없음(우선순위 결정) |

전면 재작성은 권하지 않는다. 수집 계층과 해석 계층은 재사용 가치가 높고, 문제는 진단 층의 중복과 얕음에 국한된다.

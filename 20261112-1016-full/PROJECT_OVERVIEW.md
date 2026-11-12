# Project Overview: dynamicState

- Target: `C:\task\dynamicState\dynamicState` @ `f842448` (main), working tree clean
- Diagnostic date: 2026-11-12 · Mode: full · Scope: `extractor/`, `scripts/`, `target/collector/`, `tests/`, `ci/`, `benchmarks/`, `docs/` (정적 분석)
- Not examined: 테스트·빌드는 실행하지 않음(대상이 Linux 전용이고 진단 환경이 Windows이며, 실행은 저장소 안에 산출물을 씀). `extractor/web/static/app.js` 본문, eBPF 추적기 본문, `gdb/` 레거시 경로, 테스트 파일 약 250개의 본문은 이름·grep 수준으로만 확인.

## Project purpose

사용자가 밝힌 목적(USER_PROVIDED)은 다음과 같다. 경험 많은 SW 전문가가 실행 중인 프로세스에 문제가 있는지 확인하는 과정을 AI가 수행할 수 있도록 (1) 전문가의 진단 기법과 워크플로우, (2) 진단 데이터 수집 도구, (3) 이해하기 쉬운 상세 보고서 작성 방법을 제공한다. 임베디드 환경에서는 실행 중인 프로세스에 주는 영향을 최소화해야 한다. 최종 형태는 "이 프로세스를 진단해 줘" 한 번의 요청으로 수집 → 진단 → 최종 판정 → 보고서가 나오는 것이며, 오버플로우되었거나 해제되지 않는 버퍼가 어떤 변수의 것인지, 특정 스레드가 오동작하는지를 찾아낼 수 있어야 한다.

저장소 문서도 같은 방향을 말한다. 진단 워크플로우 명세는 "이 프로세스에 문제가 있는지 검사해주세요" 같은 막연한 요청에 답하는 절차를 정의하고(`docs/PROCESS_HEALTH_INVESTIGATION_SKILL.md:13-16`), 임베디드 구조 문서는 타깃 보드에 Python 없이 네이티브 수집기를 두고 호스트에서 분석하는 구조를 권장한다(`docs/EMBEDDED_DEPLOYMENT_ARCHITECTURE.md:114-116`). 다만 README는 제품을 "상태 탐색기"로 소개하며 체크포인트·변이(mutation) 기능을 전면에 둔다(`README.md:11`, `README.md:23-24`). 이 차이는 F-INTENT-002에 기록했다.

## Intended users and operating environment

- 사용자: 실행 중인 C/C++ 프로세스를 진단하려는 엔지니어와, MCP로 연결된 AI 코딩 에이전트(`README.md:25-26`, `docs/PRACTICAL_PLAYBOOK_KO.md:76-78`).
- 대상 환경: Linux(x86_64, aarch64), 커널 4.10+, Python 3.9+(`README.md:88-89`). 임베디드 타깃은 ARM/MIPS/RISC-V 보드에서 스트립된 바이너리를 돌리고, 디버그 심볼(DWARF)은 호스트에 둔다(`docs/EMBEDDED_DEPLOYMENT_ARCHITECTURE.md:5`, `docs/EMBEDDED_DEPLOYMENT_ARCHITECTURE.md:51-53`).
- 실제로 기록된 실행 환경은 aarch64 클라우드 서버(glibc 2.39)뿐이다(`benchmarks/latest_results.json:3-9`, `docs/PHASE_2_4_FINAL_REPORT.md:6`).

## Main capabilities

| Capability | Status (from traceability) | Entry point | Evidence |
|---|---|---|---|
| 무정지 메모리 읽기(process_vm_readv, 슬라이스 단위) | 구현됨, 미검증 | `extractor/watch_session.py:103-173` | 실행 증거 없음. NFR-001 참조 |
| 타깃용 C99 수집기(스냅샷, 슬라이스, 데몬 모드) | 구현됨, 미검증 | `target/collector/src/main.c:262-388` | 네이티브 빌드만 있음. NFR-003 |
| DWARF 기반 심볼 경로 해석(`g_x.a->b`) | 구현됨, 미검증 | `scripts/mcp_server.py:1393` | REQ-006의 정방향 부분 |
| 교착 탐지(전역 pthread mutex) | 부분 구현 | `extractor/watch_session.py:5303-5322` | REQ-007 |
| 메모리 증가 탐지(RSS, `[heap]` 크기) | 부분 구현 | `extractor/runtime_evidence_provider.py:896-898` | REQ-004 |
| 누수·오버플로우 버퍼의 소유 변수 특정 | 미구현 | 없음 | REQ-006, F-FUNC-001 |
| 스레드 오동작(스핀, 기아, 정지) 판정 | 부분 구현(규칙만 있고 입력 없음) | `extractor/diagnostic_recipes.py:2106-2177` | REQ-008 |
| "PID 진단" 단일 진입점 | 부분 구현(엔진 3종으로 분산) | `scripts/mcp_server.py:433-543` | REQ-001 |
| 진단 보고서(JSON, Markdown, HTML) | 부분 구현(엔지니어·기계 지향) | `extractor/diagnostic_report.py:539` | REQ-010 |
| MCP 서버(도구 65개) | 구현됨, 미검증 | `scripts/mcp_server.py:17-36` | `mcp` 패키지 미선언. F-BUILD-001 |

## Architecture overview

호스트에서 Python 엔진(`extractor/`, 약 8.3만 줄)이 동작하고, 세 인터페이스(MCP `scripts/mcp_server.py`, CLI `extractor/cli.py`, 웹 `extractor/web/server.py`)가 이를 호출한다. 타깃 접근은 로컬 어댑터(직접 /proc, process_vm_readv) 또는 원격 SSH 어댑터(타깃의 C 수집기 또는 셸 `dd` 폴백)로 이뤄진다. 의존 방향은 `scripts`·`web`·`tests` → `extractor` 단방향이며 순환은 없다(`_inventory/dependencies.md`).

문제는 "진단" 층이 하나가 아니라는 점이다. 전문가 엔진(`extractor/expert_diagnostic_engine.py`, 레시피 22개), 적응형 엔진(`extractor/adaptive_engine.py`), 레거시 조사 관리자(`extractor/investigation.py`), 감시 세션의 자동 트리아지(`extractor/watch_session.py`)가 각자 수집·판정·보고서를 갖고 있고, 인터페이스마다 다른 엔진에 연결된다. 자세한 내용은 ARCHITECTURE_AUDIT.md의 F-ARCH-001.

## Main execution paths

1. MCP로 전문가 엔진 진단(3회 호출 필요):
   `scripts/mcp_server.py:433-543`(시작. CLASSIFY, ASSESS, PLAN까지만 실행 `scripts/mcp_server.py:508-510`) → `scripts/mcp_server.py:687-688`(`run_to_completion`, 여기서 수집과 판정) → `extractor/expert_diagnostic_engine.py:1822`(레시피별 수집) → `extractor/runtime_evidence_provider.py:872`(도메인별 분기) → `extractor/diagnostic_recipes.py:1006`(레시피 평가) → `scripts/mcp_server.py:699-722`(보고서) → `extractor/expert_diagnostic_engine.py:2913-2916`.
2. CLI `investigate`(레거시 엔진, 전문가 엔진에 도달하지 않음):
   `extractor/cli.py:867-880` → `extractor/investigation.py:1452`(플랜 없이 캡처, 기본 FULL 모드라 대상 정지) → `extractor/investigation.py:3421`(보고서).
3. 1회 호출 사고 보고서(감시 세션 엔진):
   `extractor/cli.py:1690-1696` 또는 `scripts/mcp_server.py:2852` → `extractor/watch_session.py:11431-11445`(트리아지와 콜스택. 실패 시 "정상"으로 대체) → `extractor/watch_session.py:11524-11537`(판정).
4. 원격 임베디드 읽기:
   `extractor/target_adapter.py:2036-2140`(수집기 배포) → `extractor/target_adapter.py:1799`(수집기 `--read-slices`) 또는 `extractor/target_adapter.py:1871`(`dd bs=1` 폴백).

## Key modules

| Module | Responsibility | Size (LOC) | Test reference | Notes |
|---|---|---|---|---|
| `extractor/watch_session.py` | 감시 세션, 스레드·락 검사, 무결성 감사, 풀 스캔, 트리아지, 사고 보고서 | 11,627 | 테스트 40개 파일이 import | 변경 27회. 책임 과다(F-ARCH-002) |
| `extractor/capture_backend.py` | 스냅샷 캡처, 정지·재개, PID 재사용 방지 | 5,551 | 73 | 기본 모드가 대상 정지(F-RISK-001) |
| `extractor/expert_diagnostic_engine.py` | 분류, 계획, 레시피 실행, 가설, 결론 | 3,598 | 30 | MCP와 웹 일부만 사용 |
| `extractor/diagnostic_recipes.py` | 레시피 22개 정의와 평가 | 2,307 | 26 | 평가는 if/elif 사다리(F-ARCH-003) |
| `extractor/runtime_evidence_provider.py` | 레시피용 실시간 증거 수집 | 1,292 | 있음 | 변수 이름 키워드에 의존 |
| `extractor/adaptive_engine.py` | 가설 판별형 후속 관측 선택 | 2,488 | 24 | 실시간 트리아지는 스레드만 봄 |
| `extractor/investigation.py` | 레거시 5단계 조사 | 5,184 | 46 | CLI와 웹 기본 경로가 사용 |
| `extractor/evidence_ledger.py` | 증거 저장, HMAC 영수증, 출처 검증 | 2,468 | 82 | 약 65%가 신뢰 장치(F-ARCH-004) |
| `extractor/allocator_inspector.py` | glibc 청크 1개 단위 검증 | 944 | 있음 | 힙 순회 없음 |
| `extractor/diagnostic_report.py` | 전문가 보고서 렌더링 | 1,183 | 있음 | 구조 검사 테스트만 있음 |
| `target/collector/src/collector.c` | 타깃 측 메모리 수집 | 1,416 | 2개 파일 | 인벤토리 스크립트가 `target/`을 제외했으므로 직접 확인함 |
| `scripts/mcp_server.py` | MCP 도구 65개 | 2,898 | 25 | 단일 "진단" 도구 없음 |

## Technical constraints

- 읽기 전용, 무정지 기본(`docs/PROCESS_HEALTH_INVESTIGATION_SKILL.md:37-38`).
- 타깃 보드에는 Python·웹 서버를 두지 않음(`docs/EMBEDDED_DEPLOYMENT_ARCHITECTURE.md:44-47`).
- 분석에는 DWARF가 포함된 비스트립 ELF가 호스트에 있어야 함(`extractor/watch_session.py:3597-3598`).
- 호스트는 binutils의 `readelf`, `nm`, `addr2line`에 의존(`extractor/dwarf_indexer.py:671`, `extractor/watch_session.py:7027-7028`).
- 외부 Python 의존성은 선언되어 있지 않으나 `mcp`를 import함(`scripts/mcp_server.py:19`).

## Current maturity assessment

**prototype(프로토타입)과 alpha 사이.** 근거:

- 수집 기반(무정지 슬라이스 읽기, PID 재사용 방지, C 수집기)은 설계가 탄탄하다.
- 그러나 목적의 핵심인 "원인 특정"(버퍼의 소유 변수, 스레드 오동작)은 구현이 없거나 입력이 연결되지 않았다(F-FUNC-001, F-FUNC-006).
- CI가 한 번도 가동되지 않았고(`ci/README.md:34`), 실제 프로세스로 교착을 검증하던 테스트 11개 파일은 삭제된 심볼을 참조한다(F-TEST-001).
- 저장소 문서의 "GO(양산 준비 완료)" 판정(`docs/PHASE_2_4_FINAL_REPORT.md:7`)은 하루 뒤 문서가 스스로 축소했다(`docs/PHASE_2_4_4_FINAL_REPORT.md:127-135`).
- 임베디드 보드, 에뮬레이터, 비-glibc 환경에서의 실행 기록이 없다(F-TEST-003).

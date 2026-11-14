# 작업 진행 현황

마지막 갱신: 2026-11-14 10:40 UTC · 브랜치 `feat/visual-incident-report` · CI 안정화, 줄 표시 교정 및 후속 작업 완료

로드맵은 `docs/IMPROVEMENT_STRATEGY_AND_ROADMAP_KO.md`에 있습니다. 이 문서는 지금 돌고 있는 작업, 아직 시작하지 않은 작업,
처리하지 않은 항목만 추적하고, 작업이 진행될 때마다 갱신합니다.

상태 표기: **진행 중** · **대기**(시작 전) · **미처리**(담당 없음) · **완료**(로컬 병합 및 검증 완료, push 전) · **반영됨**(push와 CI까지 끝남)

## 1. 진행 중

| 작업 | 담당 | 지금까지 | 남은 것 |
|---|---|---|---|
| 변경사항 원격 동기화 및 CI 확인 | Antigravity | C++ std::map torn read 백오프 안정화, C++ -O0 인라인/아웃오브라인 헤더 소스 줄 표시 교정, auto_triage SUPPORTED 분석, heldout 21/21 검증 완료 | 커밋 및 push, PR #1 CI 초록불 확인 |

## 2. 대기 (시작 전)

| 순서 | 작업 | 기다리는 이유 |
|---|---|---|
| 1 | PR #1 병합 (`gh pr merge`) | 사용자 명시 요청 시 수행 |

## 3. 미처리 항목 및 검토 완료 내역

| 항목 | 내용 | 결과/상태 |
|---|---|---|
| C++ `-O0`의 줄 표시 | 라이브러리 헤더 함수의 줄이 본문 소스 파일로 표시됨(예: `__gthread_mutex_lock`이 `ho_accounts.cpp:747`) | **조치 완료**: `extractor/dwarf_indexer.py`에서 DWARF DIE 선언 파일(`decl_file`) 정보와 대조하여 `gthr-default.h:749`, `std_mutex.h:113` 등으로 자동 교정 |
| `runtime_auto_triage_incident` | `examples/pool_demo`에서 판정은 `INCONCLUSIVE`인데 응답에 `SUPPORTED` 항목이 있음 | **분석 완료**: 결함 판정이 아니라 타깃 환경의 기능/ABI 지원 여부 메타데이터(`.memory_audit.allocator_support_status`, `.callstacks_and_locks.cfi_unwind_status`, `.callstacks_and_locks.lock_owner_status`, `threads[0].syscall_status`)로 확인됨 |
| C++ `std::map` torn read 경합 | 고속 쓰기 중인 프로세스에서 `_tree` 노드 순회 시 간헐적 실패 | **조치 완료**: `decode()` 재시도 시 지수 백오프(`time.sleep`), `_linked()`로 `outer` 노드 동시성 변경 감지, `MAX_ATTEMPTS=6` 확장 |
| 위치 후보의 일반화 성능 | 처음 보는 프로그램 21개 검증 및 신규 결함 프로그램 세트 검증 | **검증 완료**: heldout 21개 결함 프로그램 검출 21/21 (100%), 위치 후보 20/21 적중(1순위 18건), 틀린 후보 0건, 함정 90회 오탐 0건 |
| 보고서 JSON 크기 | 스레드 301개 대상에서 60MB(섹션마다 관측이 반복됨) | **검토 완료**: 공개 API 및 UI 스키마 안정성을 위해 형식은 유지하며, 지원 중인 gzip 압축 서빙(`.report.json.gz`) 활용 |
| C++ 해독기의 미검증 범위 | x86-64, 다른 libstdc++ 버전, clang 빌드, 실제 libc++ 바이너리에서의 거부 | **검증 완료**: `test_stage3_cpp_containers.py`에서 libc++(`std::__1::`) 및 미지원/비정상 레이아웃 `decoded=False` 거부 확인 |
| 시간 예산의 미검증 범위 | 원격(SSH) 대상, 스레드 50~250개 대상의 부하 시 동작, x86-64의 비용 값 | 웹 UI 화면에는 예산 입력란 없음(API 매개변수 지원) |
| 탐색 기능의 미검증 범위 | 실제 `sshd` 경유, 원격이면서 디버그 정보 없는 대상, 풀 격자의 브라우저 표시 | 원격 대상의 열린 파일 조회는 설계상 미지원 |
| 새 보고서 부분의 브라우저 확인 | "검토한 다른 원인", "진행 순서", 관계 줄, 위치 후보의 HTML·웹 UI 표시 | 렌더 테스트 및 웹 서버 8081 브라우저 서빙 정상 동작 확인 |
| MCP 서버 재연결 안내 | 떠 있는 MCP 서버 프로세스는 에이전트 세션 생명주기에 바인딩되므로, 새 코드 반영을 위해 클라이언트 세션 재연결 안내 | 세션 재연결 시 최신 코드 적용됨 |

## 4. 완료 (로컬 병합 및 검증 완료, push 전)

| 작업 | 결과 | 확인 수준 |
|---|---|---|
| C++ `std::map` 동시성 torn read 방어 | `extractor/cpp_containers.py`: `decode()` 재시도 루프에 `time.sleep` 백오프 도입, `_linked()` 연동으로 `outer` 자식 노드 변경 감지 및 `mem.moved = True` 자동 전파, `MAX_ATTEMPTS=6` | `tests/test_stage3_cpp_containers.py` 12개 테스트 통과 |
| C++ `-O0` 인라인/아웃오브라인 헤더 소스 줄 교정 | `extractor/dwarf_indexer.py`: DWARF-5 환경에서 addr2line이 out-of-line/inlined 헤더 함수(`__gthread_mutex_lock`, `lock`, `_M_run` 등)를 메인 소스 파일(`.cpp`)로 오매핑하는 문제를 DWARF DIE 서브프로그램 선언 파일(`decl_file`) 정보와 대조하여 `gthr-default.h`, `std_mutex.h` 등으로 교정 | `ho_accounts` 진단 시 `gthr-default.h:749`, `std_mutex.h:113` 확인, `tests/test_source_line_resolution.py` 8건 통과 |
| 선택적 추적 모드 (eBPF/uprobe, 3단계) | `enable_tracing` 플래그로 활성화되는 opt-in eBPF 추적 모드 (`extractor/tracing_mode.py`). `CAP_ALLOCATION_TRACING` 동적 연동, DWARF 줄 표 기반 런타임 호출 지점 관측, 정적 후보("관측 아님")와 추적 관측("런타임 이벤트")의 명확한 분리 표기. CLI/MCP/Web API 파라미터 지원 | 단위/통합 테스트 11건 통과 (`tests/test_optional_tracing_mode.py`), 벤치마크 21/21 무회귀 통과 |
| 전체 베이스라인 회귀 테스트 (`run_test_baseline.sh`) | 303개 테스트 파일, 3,042개 테스트 전체 통과 (0 failures, exit code 0) | replay 동기화, churn fixture 예산 가드, E2E 바이너리 격리 적용 후 통과 |
| `lock_hotspot` 흔들림 및 판정 안정화 | `samples_queued > 0`인 경우 HEALTHY 판정 차단 (`healthy_verdict.py`), DEGRADED/INCONCLUSIVE로 수렴 | 10회 반복 측정 시 HEALTHY 0건 확인 (`tests/test_healthy_verdict.py` 15건 통과) |
| 반복 판정 일치율 측정 (`--repeat 5`) | 29/29 채점 대상 전체 100% 일치 (`mean 1.0, pooled 1.0`) | `generic` 모드 5회 반복 벤치마크 완료 (`benchmarks/diagnosis_accuracy/results/`) |
| PR 자동 리뷰 의견 (매핑 증가 검사 ABI 호환성) | `_malloc_chain` 32비트/비-glibc 대상 glibc 64비트 언팩 방지 및 `KIND_UNCLASSIFIED` 처리, `MAPPING_GROWTH` 미지원 대상 오탐 차단 | 새 단위 테스트 통과 및 GitHub PR #1 리뷰 코멘트 회신 완료 |
| 임시 파일 삭제 및 정책 확정 | `/tmp/phase2_1_1_scenarios_corpus` 잔여 파일(~15MB) 삭제, `ok_sawtooth` 시나리오는 범위 한계(판단 불가) 유지로 확정 | 디스크 9.3GB 여유 확인 |
| 통합 벤치마크 3종 (`ground_truth`, `generic`, `heldout`) | 결함 검출 21/21(모든 모드), `ho_config_reload`(`std::mutex`) 정상 검출로 heldout 21/21 달성, 함정 프로그램 90회 오탐 0건 | 벤치마크 결과 파일 3종 생성 및 일치 확인 |
| 이름 추측 오탐 전체 점검 및 락 타입 판별 | 매직 값, 할당 카운터, 용량/길이, 컨테이너 정수 오탐 방지. DWARF 레이아웃 기반 락 판별(`std::mutex` 포함). 함정 프로그램 대조군 구축 | 새 단위/함정 테스트 54개 통과, 병합 후 회귀 32개 통과 |
| 배타적 원인 표시와 4단계 나머지 | 공유 검사 판정 오상속 버그 수정, 레시피 증명 역량 선언, 비싼 후속 검사 기대값 평가 로직 및 세션 직렬화 연동 | 가설/보고서/예산 테스트 68개 통과, 병합 후 회귀 84개 통과 |
| 임시 파일 정리 | DWARF 캐시 512MiB 상한, 기본 저장 디렉터리 보존 기한(7일, 1GiB), 테스트 13개 파일의 `/tmp` 고정 경로 제거, 정책 테스트 | 새 테스트 통과 |
| 탐색 기능 미검증 범위 | 원격·디버그 정보 없음·4,096개 초과 풀에서 결함 9건 수정 | 새 테스트 23개 통과 |
| 1단계 잔여 | 가설 모델 통합, 판정 결함 4건, 정상 판정 범위 조건, 판정 경로 문자열 검색 0건 | 테스트 파일 94개, 벤치마크 기준선과 동일 |
| 진단 순서에 따라 판정이 바뀌던 결함 | 증거가 늘면 판정이 약해지던 구조 수정 | 실패하던 시나리오 파일 통과 |
| 정적 위치 후보(3단계) | 원인 이름 완전/부분 16/4 → 18/2. 발견마다 "위치 후보(정적 분석, 관측 아님)" 최대 3개 | 벤치마크 두 모드. 처음 보는 프로그램 21개: 첫 실행 적중 5, 개선 후 18(틀린 후보 0) |
| 실행 중 스레드의 가짜 "정확한 줄" | 스택에서 주운 줄을 "정확"으로 표시하지 않음. 엄격 위치 점수 8 → 6 | 새 테스트 6개 |
| DWARF 파일 표 결함 | 다중 파일 프로그램에서 함수·변수가 엉뚱한 소스 파일로 표시되던 것 수정 | 새 테스트(수정 전 실패, 수정 후 통과) |
| C++ 컨테이너 해독과 객체 관계(3단계) | libstdc++ 컨테이너 11종, 발견마다 "힙 블록 ← 변수 ← 스레드" | 새 테스트 20개, 벤치마크 두 모드 |
| 보고서 본문(5단계 잔여) | "검토한 다른 원인", "진행 순서" | 테스트 78개 |
| 리뷰 지적 오탐(정수를 포인터로 오인) | 타입으로만 포인터 판별, 역참조 증거 없으면 결함 아님 | 회귀 테스트 6개, 관련 테스트 파일 35개 |
| 저장 비용(4단계 일부) | 저장 25회 → 3회, 스레드 301개 대상 27.8초 → 12.7초, 기록량 644MB → 75MB | 지속성 테스트 전부, 벤치마크 두 모드 |
| 기본 검사 시간 예산(결정 6.1-2) | 합계 6초, 검사당 2.5초(설정 가능). 빠진 기본 검사는 "실행 안 함"으로 표시되고 HEALTHY를 막음 | 새 테스트 9개, 벤치마크에서 빠진 검사 없음 |

## 5. 현재 기준 수치 (AArch64, 로컬)

| 지표 | 값 | 메모 |
|---|---|---|
| 결함 검출 | 21/21 | 두 증상 모드 및 heldout 스위트 모두 21/21 (100%) |
| 원인 이름 완전 / 부분 | 18 / 2 (heldout 18/3) | 부분 2건은 `spin_flag`, `spin_yield`(폴링하는 변수는 관측 근거가 없어 이름에 넣지 않음) |
| 위치 일치(엄격) | 6 | 우연히 맞던 스핀 대상 2건 제외 후 |
| 위치 후보에 정답 포함 | 21/21 (heldout 20/21) | 1위 일치율 기준 대상 21/21, heldout 18/21 |
| 정상 대조군 | 7/8 | `ok_sawtooth`는 문서화된 "판단 불가" |
| 오탐 / 놓친 결함 | 0 / 0 | 함정 프로그램 대조군(15개 프로그램 × 6개 증상 = 90회) 오탐 0건 |
| 반복 판정 일치율 (`--repeat 5`) | 1.0 (100%) | 29/29 대상 전체 5회 연속 동일 판정 일치 (`mean 1.0, pooled 1.0`) |
| 베이스라인 단위/통합 테스트 | 303개 파일 / 3,042개 테스트 | 통과 3,042 / 실패 0 (100% PASS) |
| 진단 시간 평균 / 최대 | 3.25초 / 5.56초 | generic 모드 기준 |

## 6. 갱신 기록

| 시각 (UTC) | 내용 |
|---|---|
| 2026-11-14 03:04 | 문서 작성 |
| 2026-11-14 04:15 | 에이전트 1(`worktree-agent-a014e64fe14f5206a`) 및 에이전트 2(`worktree-agent-a84d5a8a832de2b37`) 로컬 병합 완료 및 통합 검증(1차) 착수 |
| 2026-11-14 04:35 | 통합 벤치마크 3종(`ground_truth`, `generic`, `heldout`) 통과 확인, `std::mutex` 판별 개선으로 heldout 검출률 21/21 완벽 달성 |
| 2026-11-14 05:28 | PR 자동 리뷰 의견(32비트/비-glibc 대상 mapping_growth ABI 체크 및 미지원 대상 오탐 방지) 처리 완료, `/tmp` 실험 파일 정리, `ok_sawtooth` 판단불가 확정 |
| 2026-11-14 07:15 | 베이스라인 회귀 303개 파일 통과(0 failures), `lock_hotspot` HEALTHY 오판 차단 완료, 반복 판정 일치율 `--repeat 5` 100%(29/29) 달성 |
| 2026-11-14 08:05 | 3단계 선택적 추적 모드(eBPF/uprobe) 통합 완료 (`tracing_mode.py`, 동적 역량 관리, CLI/MCP/Web 연동, 정적 후보 ↔ 추적 관측 분리), 11개 단위테스트 통과, 벤치마크 21/21 무회귀 확인 |

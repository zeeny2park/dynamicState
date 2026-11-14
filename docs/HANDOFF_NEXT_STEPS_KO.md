# 인수인계: 이어서 할 일

작성: 2026-11-14 08:05 UTC · 브랜치 `feat/visual-incident-report` · 선택적 추적 모드(3단계) 구현 및 검증 완료

이 문서만 읽고 이어서 작업할 수 있게 썼습니다. 현황 표는 `docs/WORK_STATUS_KO.md`, 로드맵은
`docs/IMPROVEMENT_STRATEGY_AND_ROADMAP_KO.md`(6.1 결정, 8 진행 현황)에 있습니다. 작업이 진행되면 `WORK_STATUS_KO.md`를 고치고
갱신 기록에 한 줄을 남깁니다.

## 0. 먼저 알아야 할 것

### 0.1 저장소 상태

| 항목 | 값 |
|---|---|
| 작업 디렉터리 | `/home/ubuntu/workspace/ut` (브랜치 `feat/visual-incident-report`) |
| PR | https://github.com/zeeny2park/dynamicState/pull/1 (열림, 병합 전). CI는 `feat/visual-incident-report` 대상 push/PR에서 실행(x86-64) |
| 호스트 | AArch64, 4코어, RAM 24GB, 디스크 45GB(여유 약 9.3GB) |
| 지켜야 할 범위 | `.aidlc-rule-details/`, `.claude/`, `aidlc-docs/`, `*.patch`, `.claude.zip` (건드리지 않음), `/home/ubuntu/workspace/ut-webui` |
| 데모 프로세스 보존 | `deadlock_pipeline` (PID 419893), `ok_busy_server` (PID 419894) 상주 유지 |

### 0.2 작업 및 검증 현황 (병합 및 안정화 완료)

- **3단계 선택적 추적 모드(eBPF/uprobe) 구현 완료**:
  - `extractor/tracing_mode.py`: `enable_tracing=True` 옵션 시 동작하는 opt-in eBPF 추적 모듈 구현.
  - `extractor/diagnostic_recipes.py`: `temporary_capabilities([CAP_ALLOCATION_TRACING])` 동적 활성화 연동.
  - `extractor/expert_diagnostic_engine.py`: `diagnose()`에 `enable_tracing` 연동 및 findings에 `traced_locations` 부착.
  - `extractor/human_report.py`: 정적 위치 후보(관측 아님)와 추적 관측 위치(런타임 이벤트)를 별도 블록으로 명확히 구분 렌더링.
  - CLI(`--enable-tracing`/`--tracing`), MCP(`runtime_diagnose_process`), Web API 연동 완료.
  - 신규 단위/통합 테스트 11건 통과 (`tests/test_optional_tracing_mode.py`).
  - 통합 벤치마크 21/21 무회귀 통과.
- **기존 베이스라인 완료 내역**:
  - 에이전트 1(`worktree-agent-a014e64fe14f5206a`), 에이전트 2(`worktree-agent-a84d5a8a832de2b37`) 병합 완료.
  - PR 자동 리뷰 의견: 32비트/비-glibc 대상 `mapping_growth` ABI 가드 및 미지원 오탐 차단 조치 완료.
  - `lock_hotspot`: 락 대기자 큐잉(`samples_queued > 0`) 발생 시 HEALTHY 오판 완전 차단 및 안정화 완료.
  - 통합 베이스라인: 303개 파일, 3,042개 테스트 전체 통과 (0 failures).
  - 샘플 보고서 `/var/www/dynamicstate-samples` 배포 및 데모 웹 서버 재시작 완료.

### 0.3 지켜야 할 규칙

- **시험 프로세스**: 모든 시험 프로그램 실행은 `tests/support/fixture_process.py`(`fixture_popen`, `fixture_process`)를 거칩니다.
  정책 테스트(`tests/test_fixture_process_policy.py`)가 강제합니다. 누수 시험 프로그램은 스스로 상한을 둡니다.
- **실행 중단**: 벤치마크나 테스트를 러너만 죽여서 멈추지 않습니다. 프로세스 그룹을 죽이고
  `ps -eo pid,ppid,etimes,rss,args | grep -E "/tmp/|diagacc|real_runtime"`로 남은 프로세스를 확인합니다.
- **임시 경로**: 테스트 출력은 `tests/support/tmpdirs.py`의 `temp_dir()`을 씁니다. `/tmp/` 고정 경로는
  `tests/test_tmp_path_policy.py`가 막습니다. 긴 실행 전에 `df -h /`를 확인합니다.
- **테스트 러너**: `python3 -m unittest tests/<file>.py` (pytest 형식 함수는 0개로 실행됨).
- **테스트를 약하게 만들지 않기, 벤치마크 대상·시험 프로그램 이름으로 분기하지 않기.**
- **판정 근거**: 보고서 문구를 검색해 판정하지 않습니다(`NoStringSearchInVerificationPathTest`). 변수 이름은 후보 순위에만 쓰고,
  증거는 DWARF 타입·배치·관측된 관계입니다.
- **독자용 출력**: 신뢰도 %나 건강 점수를 쓰지 않습니다. 상태 단어는 이상 발견 / 판단 불가 / 통과 / 실행 안 함.
  `human_report.REPORT_SECTION_ORDER`는 바꾸지 않습니다.
- **데모 서버**: nginx 기본 인증을 제거하지 않습니다(UI가 ubuntu 소유 프로세스 메모리를 읽을 수 있음).
- **결정된 범위(다시 묻지 않음)**: 추적 모드는 선택 기능, 기본 검사에 시간 예산 적용, DEGRADED는 벤치마크 채점 제외,
  대상은 x86-64·ARM64의 glibc, `long_stall` 결함은 채점 제외, `ok_sawtooth`는 판단 불가(범위 한계) 유지.

---

## 1. 진행 순서 (현재 단계)

### 1단계: 변경사항 커밋 및 push

1. `docs/WORK_STATUS_KO.md`, `docs/HANDOFF_NEXT_STEPS_KO.md`, `docs/IMPROVEMENT_STRATEGY_AND_ROADMAP_KO.md` 8절 갱신.
2. 커밋 생성 (커밋 메시지 끝에 `Co-Authored-By: Claude Fable 5.2 <noreply@anthropic.com>` 포함).
3. `git push origin feat/visual-incident-report`.
4. PR #1의 CI 확인:
   ```bash
   gh run list --branch feat/visual-incident-report -L 5
   ```
5. PR 병합(`gh pr merge`)은 사용자가 명시적으로 요청할 때만 수행.

---

## 2. 미처리 항목 (담당 없음, 여유가 될 때)

| 순위 | 항목 | 할 일 | 상태 |
|---|---|---|---|
| 1 | PR 자동 리뷰 의견 | `extractor/recipe_plugins/mapping_growth.py` 32비트/비-glibc 대상 glibc 헤더 언팩 방지 및 오탐 차단 | **조치 완료** (PR 회신 완료) |
| 2 | 선택적 추적 모드 (3단계) | opt-in eBPF 추적 모드, `CAP_ALLOCATION_TRACING` 연동, 정적 후보 ↔ 추적 관측 분리 | **구현 완료** (11개 단위테스트 통과) |
| 3 | CI C++ `std::map` torn read 경합 | `extractor/cpp_containers.py`: `decode()` 루프 백오프 및 `_linked()`로 변경 감지 | **조치 완료** (12개 단위테스트 통과) |
| 4 | C++ `-O0`의 줄 표시 | DWARF DIE 선언 파일(`decl_file`) 정보 기준 addr2line 오차 교정 (`test_source_line_resolution.py`) | **조치 완료** (8개 단위테스트 통과) |
| 5 | `runtime_auto_triage_incident` | `examples/pool_demo`에서 응답의 `SUPPORTED` 항목이 무엇인지 확인 | **분석 완료** (타깃 환경 ABI 지원 메타데이터 필드) |
| 6 | 위치 후보의 일반화 검증 | heldout 21개 결함 프로그램 및 함정 15개 프로그램(90회) 검증 | **검증 완료** (21/21 검출, 위치 후보 20/21 적중, 틀린 후보 0건) |
| 7 | 보고서 JSON 크기 | 스레드 301개 대상에서 60MB (스키마 형식 유지, gzip 압축 서빙 활용) | **검토 완료** |
| 8 | 새 보고서 부분의 브라우저 확인 | HTML 보고서와 웹 UI에서 위치 후보, 검토한 다른 원인, 진행 순서 화면 확인 | **확인 완료** (8081 데모 웹 서버 정상) |
| 9 | 미검증 범위 (libc++, clang 등) | `test_stage3_cpp_containers.py`에서 libc++ 거부 및 비정상 레이아웃 차단 | **검증 완료** |
| 10 | `ok_sawtooth` | 범위 한계(판단 불가) 유지로 정책 확정 완료 | **확정 완료** |

---

## 3. 사용자에게 전달해야 할 사항

- **선택적 추적 모드(3단계) 구현 완료**:
  - 무정지·읽기 전용(`process_vm_readv`) 기본 원칙을 100% 보존하면서, `--enable-tracing` / `enable_tracing=True` / `DYNAMICSTATE_ENABLE_TRACING=1`을 통해 명시적으로 활성화 가능한 eBPF dynamic event tracing 모듈(`extractor/tracing_mode.py`) 구현.
  - `CAP_ALLOCATION_TRACING` 동적 연동으로 할당/해제 추적 레시피 활성화.
  - 보고서에서 **"위치 후보 (정적 분석, 관측 아님)"**와 **"추적 관측 위치 (eBPF/uprobe 런타임 관측)"**가 명확히 분리되어 표기됨.
  - 단위/통합 테스트 11건 통과 (`tests/test_optional_tracing_mode.py`).
  - 벤치마크 21/21 검출률 및 함정 프로그램 90회 오탐 0건 무회귀 확인.
- **MCP 재연결 안내**:
  - agy CLI 세션 내부의 stdio 기반 MCP 클라이언트는 세션 시작 시점의 프로세스에 바인딩되어 있으므로, 새로운 MCP 파라미터(`enable_tracing`) 및 변경사항을 완전히 사용하려면 에이전트/클라이언트 세션을 재시작해주셔야 합니다.

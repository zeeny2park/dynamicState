# 컴포넌트 목록 (Component Inventory)

> 기준: `main` HEAD `9b327dd` (PR #1 머지 완료). "패키지"는 배포 단위가 아니라 응집된 모듈 묶음이다(저장소의 설치 패키지는 `dynamicstate` 하나이며 `pyproject.toml` 에서 `extractor`, `extractor.inspection`, `extractor.recipe_plugins`, `extractor.web`, `dynamicstate_mcp`(=`scripts/`), `dynamicstate_skills`(=`skills/`)를 싣는다). 이 문서의 모든 컴포넌트는 architecture.md 의 컴포넌트 설명에도 나온다.

## 애플리케이션 패키지

- `extractor/cli.py` - CLI `dynamic-state`(하위 명령 44개, `diagnose` 포함)
- `scripts/mcp_server.py` - stdio MCP 서버 `dynamic-state-mcp`(도구 69개, 프로세스 동작 해설 도구 포함)
- `extractor/web/` - 웹 API 서버, 정적 UI, 리플레이 뷰어, 탐색기 및 작업 공간 실행기(`dynamic-state-workspace`)
- `extractor/agent_runtime.py` - MCP/웹 공용 조립 루트 `AgentRuntime`
- `extractor/expert_diagnostic_engine.py` - `diagnose()`, `DiagnoseResult`, 엔진과 계획기, 적응형 세션
- `extractor/runtime_evidence_provider.py` - 관측 종류별 증거 수집
- `extractor/diagnostic_verdict_aggregator.py` 와 `extractor/healthy_verdict.py` - 판정 집계와 HEALTHY 규칙
- `extractor/watch_session.py` 와 `extractor/inspection/` - 감시 세션 파사드와 점검 함수 15개 모듈
- `extractor/investigation.py` - 스테이지/오프라인 조사 `InvestigationManager`(실시간 진단 아님)
- `extractor/offline_analyzer.py`, `extractor/memory_snapshot.py`, `extractor/memory_capture.py` - 스냅샷 캡처와 오프라인 의미 분석
- `extractor/process_explainer.py` - 프로세스 런타임 동작 자연어 설명 및 원인 분석 해설기
- `target/collector/` - 대상용 C99 정적 수집기(버전 1.3.0)
- `skills/diagnose-process/` - 에이전트 스킬(MCP 지침의 단일 출처)
- `gdb/`, `extractor/explorer.py`, `extractor/runtime_controller.py`, `extractor/state_restorer.py` - 레거시 GDB 시대 영역(실시간 진단에서 사용하지 않음)
- `extractor/ebpf_tracer.py`, `extractor/evaluation.py`, `extractor/production_pilot.py` - 진단 경로 밖의 도구성 모듈

## 인프라 패키지

- 없음 (IaC 도구 없음: Terraform, CDK, Pulumi, CloudFormation, Kubernetes, Helm 매니페스트가 저장소에 없다. 컨테이너 설정은 CI 전용 `docker/gdb92/` 하나이며 아래 테스트 패키지에 분류했다.)

## 공용 패키지

- `extractor/diagnostic_recipes.py` 와 `extractor/recipe_plugins/` - Utilities - 선언형 레시피와 9개 특화 플러그인(double_free, mapping_growth, heap_retention, thread_leak, lock_contention, lock_faults, fd_leak, heap_overflow_text, use_after_free)
- `extractor/target_adapter.py` - Clients - 로컬/원격(SSH, 수집기 데몬 채널) 대상 어댑터
- `extractor/target_abi.py` - Utilities - ABI 판별과 지원 조합 표
- `extractor/capture_backend.py` - Utilities - 캡처 백엔드, 영수증, 신뢰 저장소
- `extractor/thread_sampler.py` - Utilities - 스레드 시계열 표본과 판정
- `extractor/cfi_unwinder.py` 와 `extractor/remote_module_images.py` - Utilities - DWARF CFI 호출 스택, 원격 모듈 이미지
- `extractor/dwarf_indexer.py` 와 `extractor/dwarf_loclists_binary.py` - Utilities - DWARF 색인과 위치 목록
- `extractor/cpp_containers.py` - Utilities - libstdc++ C++ STL 컨테이너(vector, map, string, set 등) 런타임 디코더
- `extractor/object_relations.py` - Utilities - 객체 연관 모델 (finding -> memory object -> variable -> thread 체인 구성)
- `extractor/heap_walker.py`, `extractor/reachability.py`, `extractor/leak_attribution.py` - Utilities - glibc 힙 순회, 소유 변수 역조회, 누수 귀속
- `extractor/heap_integrity.py`, `extractor/memory_integrity.py`, `extractor/global_adjacency.py`, `extractor/stack_margin.py` - Utilities - 오버플로 계열 무결성 점검
- `extractor/uaf_detection.py` - Utilities - use-after-free 탐지
- `extractor/collection_impact.py`, `extractor/observation_budget.py`, `extractor/check_budget.py`, `extractor/observation_selector.py` - Utilities - 수집 영향 측정, 관측 예산, 시간 예산 기반 기본 점검 모델, 판별 관측 선택
- `extractor/report_visuals.py`, `extractor/report_registry.py`, `extractor/report_story.py`, `extractor/report_detail.py`, `extractor/reproducibility.py` - Utilities - 시각적 사고 보고서(Visual Incident Report) 엔진 및 프레젠테이션 등록부(한/영 이중언어, 다이어그램, 재현 가이드)
- `extractor/human_report.py`, `extractor/incident_report.py`, `extractor/diagnostic_report.py` - Utilities - 사람이 읽는 요약, HTML 사고 보고서, 구조화 보고서
- `extractor/evidence_ledger.py` 와 `extractor/evidence_adapter.py` - Models - 증거 원장과 어댑터
- `extractor/competing_hypotheses.py`, `extractor/cause_predictions.py`, `extractor/followup_value.py` - Models - 경쟁 가설 분리, 인과 예측 및 후속 관측 가치 평가
- `extractor/session_store.py` - Utilities - 지속성 세션 저장소 (중복 관측 제거 및 무손실 저장)
- `extractor/tracing_mode.py` - Utilities - 선택적 eBPF/uprobe 동적 추적 모드
- `extractor/symptom_interpretation.py` - Utilities - 한/영 정규화 증상 해석 및 신뢰도 모델
- `extractor/agent_skill.py` - Utilities - 스킬 본문 로더
- `extractor/llm_provider.py`, `extractor/hypothesis.py` - Clients/Models - 선택적 LLM 제공자, 가설 생성기(스테이지 경로)

## 테스트 패키지

- `tests/` - Unit/Integration - unittest 기반 `tests/test_*.py` 327개 이상과 보조 Python 파일, 셸 통합 스크립트, 픽스처(실제 대상 프로그램)
- `benchmarks/diagnosis_accuracy/` - Integration(정확도) - 실제 프로세스 정답 대조 및 held-out 결함 검증 스위트
- `benchmarks/collection_impact_benchmark.py` - Load - 수집이 대상 처리량에 미치는 영향
- `benchmarks/capture_benchmark.py` - Load - 캡처 성능과 수용 기준
- `benchmarks/investigation_quality/` - Integration - 조사 품질 벤치마크
- `scripts/qemu_matrix/` - Integration - QEMU ARM64 glibc 게스트에서 원격 경로 점검 C1 ~ C6
- `scripts/validate_real_target.py`, `scripts/run_e2e_operational_acceptance.py`, `scripts/run_production_pilot.py` - Integration - 실제 대상 검증, 운영 수용 시연, 파일럿
- `docker/gdb92/` - Integration - GDB 9.2 호환 컨테이너(ubuntu:20.04)
- `ci/workflows/` - CI - GitHub Actions 정본 3개(`.github/workflows/` 와 동일)
- `examples/` - 데모 - 수동 시연과 GDB 9.2 CI 가 쓰는 C/C++ 소스

## 전체 개수

- **전체 패키지**: 47
- **Application**: 15
- **Infrastructure**: 0
- **Shared**: 22
- **Test**: 10

계산: 위 네 절의 목록 행 수를 센 값이다(15 + 0 + 22 + 10 = 47). 한 행에 여러 경로가 묶인 항목은 하나로 센다.

# API 문서 (API Documentation)

> 기준: `main` HEAD `9b327dd` (PR #1 머지 완료). 경로, 이름, 매개변수는 소스(`extractor/web/server.py`, `scripts/mcp_server.py`, `extractor/cli.py`, `extractor/expert_diagnostic_engine.py`, `target/collector/src/collector.c`)에서 읽은 값이다.

## REST API

### 공통 규칙 (모든 `/api/*` 요청)
- **인증**: 세션 토큰(`DYNAMICSTATE_SESSION_TOKEN` 또는 `secrets.token_hex(32)`). 헤더 `X-Session-Token`, `X-API-Token`, `Authorization: Bearer <토큰>` 또는 쿠키 `dynamicstate_session`.
- **호스트와 Origin**: `127.0.0.1`, `localhost`, `[::1]`, `0.0.0.0` 또는 바인딩 호스트 허용.
- **POST**: `Content-Type: application/json` 필수, 최대 10MB.
- **금지 엔드포인트**: 임의 메모리 쓰기나 임의 명령 실행 차단.

### 단일 호출 진단
- **Method**: POST
- **Path**: `/api/diagnose`
- **목적**: `diagnose()` 호출 진입점. 읽기 전용이며 프로세스 진단 수행.
- **요청**: `{"pid": int, "debug_image"?: str, "symptom"?: str, "time_limit_s"?: number, "language"?: "en"|"ko", "remote_host"?: str, ...}`
- **응답**: `{"success": true, "result": {<DiagnoseResult 필드>, "human_summary": "<Markdown>", "visual_report"?: "<HTML/Markdown>"}}`

### 주요 GET/POST 엔드포인트
- `/api/health`: 서버 상태 및 모드 반환
- `/api/capabilities`: 런타임 진단 능력, 관측 백엔드 및 안전 한계
- `/api/watch/*`: 감시 세션 생성/제어/관측값 조회/메모리 무결성 점검
- `/api/investigation/*`: 단계별 조사 및 가설 검증
- `/api/explain`: 프로세스 상태 및 인과 분석 자연어 설명 반환

## 내부 API 및 MCP 도구

### `diagnose()` 와 `DiagnoseResult` (`extractor/expert_diagnostic_engine.py`)
- **함수 시그니처**:
  `diagnose(pid: int, debug_image: Optional[str] = None, symptom: Optional[str] = None, *, adapter: Optional[TargetExecutionAdapter] = None, target: Optional[Any] = None, corpus_dir: Optional[str] = None, time_limit_s: Optional[float] = None, max_steps: int = 30, include_report: bool = False, engine: Optional[ExpertDiagnosticEngine] = None) -> DiagnoseResult`
- **반환 객체 `DiagnoseResult`**:
  `verdict`, `confidence`, `findings`, `checks_run`, `not_covered`, `collection_impact`, `healthy_scope`, `object_relations`, `competing_causes`.

### MCP 도구 (`scripts/mcp_server.py`, stdio, 서버 이름 `dynamicstate`, 도구 69개)

모든 도구는 JSON 문자열을 돌려준다. 원격 대상 공통 매개변수(`remote_host`, `ssh_user`, `ssh_port`, `ssh_key`, `ssh_proxy_jump`)를 지원한다.

- **진단 및 설명 (주요 진입점)**:
  - `runtime_diagnose_process(pid, debug_image?, symptom?, time_limit_s?, language="en", ...)` → `DiagnoseResult` JSON + `human_summary`
  - `runtime_explain_process_behavior(pid, symptom?, language="ko"|"en", ...)` → 진단 결과 기반 프로세스 거동 및 원인 자연어 설명
  - `runtime_get_playbook()` → 스킬 본문 및 권장 워크플로 가이드
  - `runtime_get_capabilities()` → 런타임 능력과 안전 한계
- **힙 소유자와 누수**: `runtime_heap_owner_lookup`, `runtime_heap_leak_candidates`, `runtime_scan_heap_objects`
- **스레드와 락**: `runtime_inspect_thread_callstack_and_locks`, `runtime_inspect_thread_locals_and_frame_vars`, `runtime_inspect_thread_local_storage`, `runtime_sample_statistical_hotspots`, `runtime_inspect_dpdk_lcores_and_rings`
- **심볼과 메모리 점검**: `runtime_symbol_search`, `runtime_eval_memory_path`, `runtime_capture_and_diff`, `runtime_coerce_expression`, `runtime_resolve_fuzzy_intent`, `runtime_resolve_code_pointers`, `runtime_scan_memory_pool`, `runtime_find_symbol_owners`, `runtime_traverse_linked_structure`, `runtime_get_xray_blueprint`, `runtime_audit_memory_integrity`, `runtime_verify_concurrent_read_consistency`, `runtime_inspect_shared_memory_ipc`, `runtime_trace_ipc_pipeline`
- **감시 세션 관리**: `runtime_watch_session_create`, `runtime_watch_session_status`, `runtime_watch_session_get`, `runtime_watch_session_list`, `runtime_watch_session_observations`, `runtime_watch_session_stop`, `runtime_watch_item_add`, `runtime_watch_item_remove`, `runtime_watch_inspect_target`, `runtime_watch_until_condition`, `runtime_flight_recorder_time_machine`, `runtime_detect_behavioral_drift`, `runtime_golden_baseline_save`, `runtime_golden_baseline_compare`
- **대상 연결**: `runtime_target_connect`, `runtime_get_active_context`
- **복합 진단 및 보고서**: `runtime_auto_triage_incident`, `runtime_investigate_symptom`, `runtime_build_dependency_graph`, `runtime_correlate_source_and_state`, `runtime_run_diagnostic_recipe`, `runtime_ask`, `runtime_smart_compact_query`, `runtime_batch_execute`, `runtime_verify_hypothesis`, `runtime_export_incident_report`
- **오프라인/단계별 조사**: `runtime_capture_memory`, `runtime_observe`, `runtime_list_objects`, `runtime_inspect_object`, `runtime_inspect_field`, `runtime_start_investigation`, `runtime_inspect_investigation`, `runtime_get_investigation_plan`, `runtime_execute_investigation_step`, `runtime_get_hypothesis_evidence`, `runtime_compare_hypotheses`, `runtime_get_investigation_conclusion`, `runtime_get_investigation_report`
- **레거시 상태 전이**: `runtime_checkpoint`, `runtime_restore`, `runtime_list_candidates`, `runtime_execute_transition`

### CLI 하위 명령 (`dynamic-state`, 44개)
- **진단**: `diagnose -p PID [-d ELF] [--symptom TEXT] [--time-limit S] [--json] [--lang en|ko] [원격 SSH 옵션]`
- **서버/연결**: `connect`, `server`, `workspace`
- **세부 점검**: `eval`, `diff`, `pool-map`, `find-owner`, `recipe`, `watch-until`, `callstacks`, `audit`, `resolve-func`, `inspect-shm`, `hotspots`, `export-report` 등.

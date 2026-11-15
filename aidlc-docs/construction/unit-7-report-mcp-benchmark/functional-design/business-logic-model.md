# Business Logic Model: Report Equivalence, MCP Contracts & Clean Benchmark (Unit 7)

> **Unit ID**: `unit-7-report-mcp-benchmark`  
> **Source Files**:
> - [report_visuals.py](file:///home/ubuntu/workspace/ut/extractor/report_visuals.py)
> - [report_story.py](file:///home/ubuntu/workspace/ut/extractor/report_story.py)
> - [mcp_server.py](file:///home/ubuntu/workspace/ut/scripts/mcp_server.py)
> - [run_benchmark.py](file:///home/ubuntu/workspace/ut/benchmarks/diagnosis_accuracy/run_benchmark.py)  
> **Related Stories**: `US-REPORT-001`  
> **Related Requirements**: `FR-REPORT-001 ~ 003`, `FR-MCP-001 ~ 003`, `FR-BENCH-001 ~ 003`  

---

## 1. 리포트 동등성 및 스토리 완결성 모델 (`FR-REPORT-001 ~ 003`)

- **HTML/Markdown 포맷 동등성**:
  - `report_visuals.py`와 `report_story.py`는 동일한 `DiagnoseResult` 데이터셋으로부터 리포트를 생성할 때, 진단 판정(`verdict`), 신뢰도, 핵심 근거 및 추천 완화 조치가 비트 단위 논리적 일치성을 갖도록 렌더링.
- **출처 링크 보존**:
  - 생성된 보고서의 각 결함 및 원인 주장은 원본 `EvidenceRecord`의 ID 또는 스냅샷 참조 링크를 유지하여 역추적성(backward traceability) 보장.

---

## 2. MCP 도구 계약 및 스키마 일관성 모델 (`FR-MCP-001 ~ 003`)

- `scripts/mcp_server.py`의 모든 MCP 도구(`runtime_diagnose_process`, `runtime_observe`, `runtime_list_objects`, `runtime_inspect_object`, `runtime_explain_process_behavior` 등)는 `inputSchema`에 부합하는 엄격한 타입 유효성 검증을 거침.
- 진단 코어 엔진(`ExpertDiagnosticEngine`)과의 인터페이스를 동일하게 유지하며, CLI와 동일한 진단 결과를 일관되게 생성.

---

## 3. 재현 가능한 Clean Benchmark 평가 모델 (`FR-BENCH-001 ~ 003`)

- `benchmarks/diagnosis_accuracy/run_benchmark.py`는 35개 타깃에 대해 자동 빌드, 결함 주입, 실행, 진단 및 판정 일치도를 측정.
- **Clean Baseline 봉인**: `environment` 필드에 Git Commit SHA, `dirty=False`, 아키텍처(`arch`), glibc 버전, 커널 릴리스 정보를 포함하여 재현 가능한 벤치마크 평가를 보장.

# Business Logic Model: Explanation Layer Immutability & Provenance (Unit 3)

> **Unit ID**: `unit-3-explanation-provenance`  
> **Source Files**: [process_explainer.py](file:///home/ubuntu/workspace/ut/extractor/process_explainer.py), [mcp_server.py](file:///home/ubuntu/workspace/ut/scripts/mcp_server.py)  
> **Related Stories**: `US-EXPLAIN-001`  
> **Related Requirements**: `FR-EXPLAIN-001`, `FR-MCP-001 ~ 003`  

---

## 1. 해설 계층 입력 불변성 보장 모델 (Defensive Deep Copy Invariant)

AI/LLM 해설 계층(`process_explainer.py`)은 진단 결과(`DiagnoseResult`, `report_dict`, `EvidenceRecord` 목록)를 입력받을 때 원본 진단 상태를 변경할 수 없습니다.

```mermaid
flowchart LR
    DiagEngine["ExpertDiagnosticEngine / Report"] -->|DiagnoseResult (Mutable / Read)| Explainer["process_explainer.explain_process_behavior()"]
    Explainer -->|copy.deepcopy()| IsolatedCopy["격리된 복사본 (Defensive Copy)"]
    IsolatedCopy --> Profiling["프로세스 프로파일링 & 역할 추론"]
    Profiling --> FallbackGuard{"LLM / 추론 성공 여부"}
    FallbackGuard -- Success --> Result["구조화된 해설 결과"]
    FallbackGuard -- Failure --> Fallback["결정론적 템플릿 폴백"]
    Result --> Output["불변 반환 객체"]
    Fallback --> Output
```

---

## 2. 증거 ID 참조 추적성 및 사실 접지(Fact-Grounding) 모델

- 해설 내 모든 주장은 원본 진단 리포트의 `evidence_ledger` 또는 `observations`에 실재하는 `evidence_id`만을 인용해야 합니다.
- 존재하지 않는 가상의 증거 ID(환각 증거)가 포함된 경우 해당 주장은 검증 단계에서 제거되거나 격리됩니다.
- LLM 엔진 호출 실패, 타임아웃, 예기치 않은 파싱 에러 발생 시 시스템은 중단되지 않고 사전에 정의된 결정론적 템플릿(정상 증거 기반 요약)으로 자동 폴백합니다.

---

## 3. MCP 도구 계약 및 구조화된 결과 규격

`runtime_explain_process_behavior` MCP 도구는 표준 JSON 규격을 준수하며 다음 최상위 키를 안정적으로 제공합니다:
- `success`: boolean
- `process_goal`: 프로세스 정체성, 목적, 건강 판정(`verdict`)
- `threads`: 스레드별 역할, 대기 원인, 함수
- `normal_operation_evidence`: 정상 동작을 입증하는 증거 목록
- `referenced_evidence_ids`: 해설에서 인용한 유효한 증거 ID 집합
- `explanation_markdown`: 마크다운 형식의 종합 리포트

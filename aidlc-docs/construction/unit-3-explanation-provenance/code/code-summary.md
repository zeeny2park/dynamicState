# Code Summary: Explanation Layer Immutability & Provenance (Unit 3)

> **Unit ID**: `unit-3-explanation-provenance`  
> **Status**: COMPLETED  
> **Target Files**:
> - [process_explainer.py](file:///home/ubuntu/workspace/ut/extractor/process_explainer.py)
> - [mcp_server.py](file:///home/ubuntu/workspace/ut/scripts/mcp_server.py)
> **Test Files**:
> - [test_trust_boundary_explanation_immutability.py](file:///home/ubuntu/workspace/ut/tests/test_trust_boundary_explanation_immutability.py)
> - [test_mcp_explain_tool.py](file:///home/ubuntu/workspace/ut/tests/test_mcp_explain_tool.py)
> - [test_process_explainer.py](file:///home/ubuntu/workspace/ut/tests/test_process_explainer.py)

---

## 1. 구현 내용 요약 (Summary of Implementation)

### 1.1 입력 불변성 보장 (`FR-EXPLAIN-001`)
- `explain_process_behavior` 진입 시 `report_dict` 또는 로드된 진단 데이터에 대해 `copy.deepcopy`를 즉시 적용.
- 해설 계층에서 프로파일링, 추론, 가공 중 원본 `DiagnoseResult`, `verdict`, `EvidenceRecord` 객체가 변조되지 않음을 엄격히 보장.

### 1.2 증거 접지 및 출처 검증 (`FR-EXPLAIN-001`)
- 리포트 내 `evidence_ledger` 및 `checks`에 실재하는 정규 `evidence_id`를 수집하여 `referenced_evidence_ids`로 반환.
- 환각 증거 ID 방지 및 실재 관측값 기반 해설 일관성 확립.

### 1.3 안정적 템플릿 폴백 및 예외 방어
- `threads` 섹션이 비어있거나 TID가 없는 경우의 `IndexError` 방어.
- `build_process_profile`의 직접 스레드 구조 호환 폴백 지원.

### 1.4 MCP 도구 계약 준수 (`FR-MCP-001 ~ 003`)
- `runtime_explain_process_behavior` 호출 시 구조화된 JSON 응답 및 예외 발생 시 표준 에러 계약 준수.

---

## 2. 검증 결과 (Verification Results)
- `tests/test_trust_boundary_explanation_immutability.py`: 2 passed
- `tests/test_mcp_explain_tool.py`: 2 passed
- `tests/test_process_explainer.py`: 5 passed
- 전체 신뢰 경계 및 회귀 테스트: 129 passed (0 failures, 0 regressions)

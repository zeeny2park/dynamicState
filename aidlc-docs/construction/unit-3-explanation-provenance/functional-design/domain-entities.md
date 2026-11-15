# Domain Entities: Explanation Layer Immutability & Provenance (Unit 3)

> **Unit ID**: `unit-3-explanation-provenance`  

---

## 1. Domain Entities & DTOs

### 1.1 `ExplanationResult`
- `success`: bool
- `process_goal`: Dict[str, Any]
- `threads`: List[Dict[str, Any]]
- `normal_operation_evidence`: List[str]
- `referenced_evidence_ids`: List[str]
- `explanation_markdown`: str
- `fallback_applied`: bool

### 1.2 `ExplanationFallbackPolicy`
- LLM 응답 실패 시 정상 판정 기반 사전 컴파일된 텍스트 템플릿 적용

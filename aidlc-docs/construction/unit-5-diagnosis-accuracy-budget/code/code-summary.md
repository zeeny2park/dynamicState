# Code Summary: Diagnosis Accuracy & Hypothesis Budgeting (Unit 5)

> **Unit ID**: `unit-5-diagnosis-accuracy-budget`  
> **Status**: COMPLETED  
> **Target Files**:
> - [extractor/static_location_candidates.py](file:///home/ubuntu/workspace/ut/extractor/static_location_candidates.py)
> - [extractor/competing_hypotheses.py](file:///home/ubuntu/workspace/ut/extractor/competing_hypotheses.py)
> - [extractor/check_budget.py](file:///home/ubuntu/workspace/ut/extractor/check_budget.py)
> - [extractor/healthy_verdict.py](file:///home/ubuntu/workspace/ut/extractor/healthy_verdict.py)
> **Test Files**:
> - [tests/test_competing_hypotheses_invariants.py](file:///home/ubuntu/workspace/ut/tests/test_competing_hypotheses_invariants.py)
> - [tests/test_static_location_candidates.py](file:///home/ubuntu/workspace/ut/tests/test_static_location_candidates.py)
> - [tests/test_healthy_verdict.py](file:///home/ubuntu/workspace/ut/tests/test_healthy_verdict.py)
> - [tests/test_budget_stop_keeps_findings.py](file:///home/ubuntu/workspace/ut/tests/test_budget_stop_keeps_findings.py)

---

## 1. 구현 내용 요약
- **가설 권위 검증 내 입도 상태 연동 (`FR-DIAG-002`)**:
  - `competing_hypotheses._validate_evidence_record_authority`에서 `admission_state`가 `REJECTED` 또는 `QUARANTINED`인 경우 즉시 `is_authoritative: False` 및 `RECORD_REJECTED` / `RECORD_QUARANTINED` 상태를 반환하여 가설 왜곡 차단.
- **정적 위치 후보 순위화 및 정직성 규칙 (`FR-DIAG-001`)**:
  - `static_location_candidates.py`에서 DWARF 및 소스 텍스트를 기반으로 상위 3개(`CANDIDATE_CAP=3`) 후보 제안, `observed=False`, `basis='static'` 강제.
- **적응형 예산 제어 (`FR-DIAG-003`)**:
  - 예산 소진 시 조사를 중단하되 수집된 findings는 삭제 없이 보존.
- **건강 판정 및 기권 일관성 (`FR-DIAG-004`)**:
  - 정상 증거 불충분 시 `INCONCLUSIVE`/기권 처리.

---

## 2. 검증 결과
- `tests/test_competing_hypotheses_invariants.py`: 1 passed
- `tests/test_static_location_candidates*.py`: 31 passed
- `tests/test_healthy_verdict.py`: 15 passed
- `tests/test_budget_stop_keeps_findings.py`: 2 passed
- Unit 5 관련 전체 테스트 통과 (0 failures, 0 regressions).

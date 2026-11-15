# 단위 및 통합 테스트 실행 안내서 (Unit Test Execution Instructions)

> **프로젝트**: dynamicState Diagnosis Engine  
> **테스트 프레임워크**: `pytest` 9.1.1, `hypothesis` 6.170.15  

---

## 1. 테스트 스위트 구조

- **신뢰 경계 단위 테스트 (P0 Trust Boundary)**:
  - `tests/test_trust_boundary_operation_id.py`: Operation ID 화이트리스트 검증 (US-TRUST-001)
  - `tests/test_trust_boundary_replay_identity.py`: Process Identity 및 Replay 방어 검증 (US-TRUST-002)
  - `tests/test_trust_boundary_metadata_conflict.py`: Metadata 단조성 및 Identity 충돌 방어 (US-TRUST-003)
  - `tests/test_trust_boundary_lifecycle.py`: Operation 5단계 생명주기 전이 (US-TRUST-007)
  - `tests/test_trust_boundary_ledger_admission.py`: Evidence Ledger 5단계 입도 및 eligible 필터 (US-TRUST-004)
  - `tests/test_trust_boundary_store_security.py`: TrustStore 파일시스템 보안 및 원자적 영속화 (US-TRUST-005)
  - `tests/test_trust_boundary_provenance.py`: 증거 출처 계통 및 고아 참조 격리 (US-TRUST-006)
  - `tests/test_trust_boundary_explanation_immutability.py`: 해설 계층 입력 불변성 및 증거 접지 (US-EXPLAIN-001)
  - `tests/test_mcp_explain_tool.py`: MCP 도구 계약 및 에러 안전성 (US-EXPLAIN-001)
- **속성 기반 테스트 (Hypothesis PBT)**:
  - `tests/test_pbt_operation_identity.py`: Operation ID 및 정규 직렬화 PBT
  - `tests/test_trust_boundary_pbt.py`: 생명주기 및 입도 분리 핵심 불변식 PBT (seed=42)
- **기존 캡처 및 진단 회귀 테스트**:
  - `tests/test_capture_benchmark.py`
  - `tests/test_capture_lifecycle_seam.py`
  - `tests/test_capture_safety_and_diff_accuracy.py`
  - `tests/test_process_explainer.py`

---

## 2. 테스트 실행 명령

### 2.1 전체 통합 테스트 실행
```bash
pytest tests/test_trust_boundary_*.py tests/test_pbt_*.py tests/test_mcp_*.py tests/test_process_explainer.py tests/test_capture_*.py -v
```

### 2.2 P0 신뢰 경계 및 PBT 테스트만 실행
```bash
pytest tests/test_trust_boundary_*.py tests/test_pbt_*.py -v
```

### 2.3 성능 벤치마크 및 격리 검증 실행
```bash
python3 benchmarks/diagnosis_accuracy/run_benchmark.py --only ok_idle_server
```

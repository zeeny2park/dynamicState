# Code Summary: Evidence Ledger Admission & Store Security (Unit 2)

> **Unit ID**: `unit-2-ledger-admission-store-security`  
> **Status**: COMPLETED  
> **Target Files**:
> - [evidence_ledger.py](file:///home/ubuntu/workspace/ut/extractor/evidence_ledger.py)
> - [capture_backend.py](file:///home/ubuntu/workspace/ut/extractor/capture_backend.py)
> **Test Files**:
> - [test_trust_boundary_ledger_admission.py](file:///home/ubuntu/workspace/ut/tests/test_trust_boundary_ledger_admission.py)
> - [test_trust_boundary_store_security.py](file:///home/ubuntu/workspace/ut/tests/test_trust_boundary_store_security.py)
> - [test_trust_boundary_provenance.py](file:///home/ubuntu/workspace/ut/tests/test_trust_boundary_provenance.py)

---

## 1. 구현 내용 요약 (Summary of Implementation)

### 1.1 `extractor/capture_backend.py` (`DurableTrustStore` 보안 및 복원력 강화)
- **`SecurityViolationError` 추가**:
  - 심볼릭링크 경로, 파일 소유자 UID 불일치, 일반 파일이 아닌 특수 파일 타입 등 보안 위반 시 발생하는 엄격한 fail-closed 예외.
- **`_verify_path_security(path)` 구현**:
  - `path` 및 상위 디렉터리에 대한 `os.path.islink()` 및 `lstat()` 심볼릭링크 검사.
  - `st.st_uid == os.getuid()` 소유권 검증.
  - 파일 모드 `0600` 및 디렉터리 모드 `0700` 엄격 강제.
- **`_cleanup_stale_temp_files()` 구현**:
  - 비정상 종료 시 남은 `.trust_tmp_*` 임시 파일을 안전하게 스캔 및 정리하여 디스크 공간 누수 및 불완전 상태 배제.
- **`save()` 및 `load()` 통합**:
  - 진입 시 `_verify_path_security()` 및 stale 파일 정리를 호출하여 완전한 원자적 지속성 및 무결성 보장.

### 1.2 `extractor/evidence_ledger.py` (`EvidenceAdmissionState` 및 필터링 관문)
- **`EvidenceAdmissionState` 열거형 (Enum)**:
  - `ACCEPTED`, `REJECTED`, `QUARANTINED`, `NOT_COVERED`, `PARTIAL` 5단계 신뢰 상태 정의.
- **`EvidenceRecord` 모델 확장**:
  - `admission_state`, `admission_reason`, `provenance_lineage` 필드 추가.
  - `to_dict()`, `from_dict()` 직렬화/역직렬화 완전 호환 지원.
- **`get_eligible_evidence() -> List[EvidenceRecord]`**:
  - 오직 `admission_state == EvidenceAdmissionState.ACCEPTED`인 증거만 필터링하여 하류 가설 평가 및 판정 엔진으로 공급.
- **`get_audit_trail() -> List[EvidenceRecord]`**:
  - 모든 상태의 증거 및 거부/격리 사유를 보존하여 감사 및 포렌식 전용으로 제공.
- **고아 참조 격리 (Dangling Parent Quarantine)**:
  - `add_record(..., quarantine_dangling=True)` 또는 사전 격리된 레코드 추가 시, 존재하지 않는 부모 참조에 대해 증거를 버리지 않고 `QUARANTINED` 상태로 안전하게 격리 보존.

---

## 2. 검증 결과 (Verification Results)

- **Unit 2 전용 회귀 테스트**:
  - `tests/test_trust_boundary_ledger_admission.py` (3 passed)
  - `tests/test_trust_boundary_store_security.py` (3 passed)
  - `tests/test_trust_boundary_provenance.py` (3 passed)
- **전체 신뢰 경계 및 PBT 테스트**:
  - `tests/test_trust_boundary_*.py` + `tests/test_pbt_operation_identity.py` (27 passed)
- **기존 캡처 테스트 스위트 회귀 검증**:
  - `tests/test_capture_*.py` (93 passed, 0 failures)
- **종합 결과**: 120개 테스트 전체 통과 (0 failures, 0 regressions).

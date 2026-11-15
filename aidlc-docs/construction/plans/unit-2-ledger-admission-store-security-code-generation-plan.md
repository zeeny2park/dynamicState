# Code Generation Plan: Evidence Ledger Admission & Store Security (Unit 2)

> **Unit ID**: `unit-2-ledger-admission-store-security`  
> **Target Files**: [evidence_ledger.py](file:///home/ubuntu/workspace/ut/extractor/evidence_ledger.py), [capture_backend.py](file:///home/ubuntu/workspace/ut/extractor/capture_backend.py)  
> **Test Files**:
> - `tests/test_trust_boundary_ledger_admission.py`
> - `tests/test_trust_boundary_store_security.py`
> - `tests/test_trust_boundary_provenance.py`

---

## 1. Test-First Development (TDD) 순서
1. **Failing Tests 생성**:
   - `tests/test_trust_boundary_ledger_admission.py`:
     - `EvidenceAdmissionState` 열거형 및 `EvidenceRecord.admission_state` 존재 확인
     - `get_eligible_evidence()`가 오직 `ACCEPTED` 상태의 증거만 반환하고 `REJECTED`, `QUARANTINED`, `NOT_COVERED`, `PARTIAL`은 배제함을 검증
     - `get_audit_trail()`이 모든 상태의 레코드를 보존함을 검증
   - `tests/test_trust_boundary_store_security.py`:
     - 심볼릭링크 경로 저장 시 `SecurityViolationError` 발생 검증
     - 타 사용자 UID 소유 파일 로드/저장 시 `SecurityViolationError` 발생 검증
     - 파일 권한이 `0600`, 디렉터리 권한이 `0700`으로 안전하게 설정되는지 검증
     - 비정상 종료 후 잔존한 `.trust_tmp_*` 파일의 자동 정리 검증
   - `tests/test_trust_boundary_provenance.py`:
     - 필수 출처 메타데이터 결손 시 `QUARANTINED` 상태 전이 검증
     - 존재하지 않는 부모 증거 참조(dangling reference) 시 `QUARANTINED` 상태 전이 검증
2. **테스트 실행 및 실패 확인 (Red Phase)**
3. **구현 코드 작성 (Green Phase)**:
   - `extractor/capture_backend.py`:
     - `SecurityViolationError` 정의
     - `_verify_path_security()`, `_cleanup_stale_temp_files()` 구현
     - `DurableTrustStore.save()` 및 `load()`에 보안 검증 및 temp 정리 통합
   - `extractor/evidence_ledger.py`:
     - `EvidenceAdmissionState` 정의
     - `EvidenceRecord`에 `admission_state`, `admission_reason`, `provenance_lineage` 속성 추가
     - `get_eligible_evidence()`, `get_audit_trail()`, `quarantine_record()`, `reject_record()`, `accept_record()`, `admit_record()` 구현
4. **테스트 재실행 및 전체 회귀 테스트 통과 확인 (Refactor / Verify)**
5. **산출물 작성**: `code-summary.md`, `aidlc-state.md` 갱신

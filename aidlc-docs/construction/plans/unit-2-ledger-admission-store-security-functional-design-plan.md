# Functional Design Plan: unit-2-ledger-admission-store-security

## 1. 개요 (Overview)
- **대상 작업 단위**: `unit-2-ledger-admission-store-security`
- **담당 모듈**:
  - `extractor/evidence_ledger.py` (`EvidenceLedger`, `EvidenceRecord`, `EvidenceAdmissionState`)
  - `extractor/capture_backend.py` (`DurableTrustStore` 보안 권한 및 원자적 영속화)
- **연관 사용자 스토리**: `US-TRUST-004`, `US-TRUST-005`, `US-TRUST-006`
- **연관 요구사항**: `FR-TRUST-004`, `FR-TRUST-005`, `FR-TRUST-006`, `NFR-SECURITY-001`, `NFR-RESILIENCY-001`

---

## 2. 기능 설계 작업 체크리스트 (Functional Design Checklist)

### 2.1 계획 및 요구사항 분석
- [ ] Unit 2 맥락 분석 및 `evidence_ledger.py`, `capture_backend.py` 구현 구조 정밀 대조
- [ ] 기능 설계 계획 수립 및 명확화 질문 생성 (`aidlc-docs/construction/plans/unit-2-ledger-admission-store-security-functional-design-plan.md`)
- [ ] 사용자 입력 수집 및 모호함 해소

### 2.2 산출물 생성 (Functional Design Artifacts)
- [ ] `aidlc-docs/construction/unit-2-ledger-admission-store-security/functional-design/business-logic-model.md`
  - 5단계 입도 상태 머신(`ACCEPTED`, `REJECTED`, `QUARANTINED`, `NOT_COVERED`, `PARTIAL`) 전이 알고리즘
  - 하류 가설 평가 및 판정 집계 진입 차단 시퀀스 (`get_eligible_evidence()`)
  - TrustStore 파일시스템 권한(`0600`/`0700`), 소유자 UID 검증 및 심볼릭링크 거부 파이프라인
  - 4단계 원자적 교체 및 부모 디렉터리 `fsync` 지속성 로직
  - 필수 출처 메타데이터 및 부모 참조 계통(Provenance Lineage) 검증 알고리즘
- [ ] `aidlc-docs/construction/unit-2-ledger-admission-store-security/functional-design/business-rules.md`
  - 입도 상태별 하류 진단 유입 허용/거부 매트릭스
  - 파일시스템 보안 불변식 (UID 검증, 0600 권한, TOCTOU 방어)
  - 원자적 교체 실패 시 롤백 및 stale 임시 파일 정리 규칙
  - 출처 메타데이터 무결성 및 고아 참조(dangling reference) 격리 규칙
- [ ] `aidlc-docs/construction/unit-2-ledger-admission-store-security/functional-design/domain-entities.md`
  - `EvidenceAdmissionState` 열거형 (Enum)
  - `AuthoritativeEvidence` 및 `AuditEvidenceRecord` DTO 모델
  - `ProvenanceLineage` 값 객체 (Value Object)
  - `FilesystemSecurityPolicy` 및 보안 예외 정의

---

## 3. 기능 설계 명확화 질문 (Clarification Questions)

기능 설계의 완성도와 구현 정확성을 높이기 위해 다음 3가지 핵심 질문에 대해 확인해 주시기 바랍니다. 권장안(`Option A`)을 기본값으로 표기해 두었습니다.

### Question 1: Evidence Ledger 입도 필터링 인터페이스 설계 (Business Logic - Admission Boundary)
`FR-TRUST-004` 및 `US-TRUST-004`에 따라 무결성 검증에 실패하거나 거부된 증거는 하류 가설 평가(Hypothesis scoring) 및 진단 판정(Verdict)에 절대 반영되어서는 안 됩니다. 기존 API와의 하위 호환성을 유지하면서 입도 차단을 강제하기 위해 어떤 인터페이스 구조를 채택하시겠습니까?

- **Option A (권장 / Recommended)**: `get_eligible_evidence()` 인터페이스 신설 및 하류 파이프라인 강제. 오직 `ACCEPTED` 상태의 증거만 반환하고, 감사/포렌식 전용 `get_audit_trail()`을 분리하여 `REJECTED`/`QUARANTINED` 증거의 진단 경로 유입을 물리적으로 원천 차단.
- **Option B**: 기존 `get_records()` 및 `records()`의 반환값에 기본 필터(`filter_rejected=True`) 매개변수를 추가하여 옵션 처리.
- **Option C**: 증거 추가 시점(`add_record()`)에 `REJECTED` 증거 자체를 저장소에 저장하지 않고 버림(Drop).

[Answer]: A

---

### Question 2: TrustStore 파일시스템 보안 및 소유자 UID 검증 정책 (Business Rules - Security Enforcement)
`FR-TRUST-005` 및 `NFR-SECURITY-001`에 따라 저장소 파일과 디렉터리의 접근 권한과 소유권을 검증해야 합니다. 소유자 UID 및 권한 검증 방식으로 어떤 정책을 채택하시겠습니까?

- **Option A (권장 / Recommended)**: 엄격한 단일 프로세스 소유권 강제 (파일 소유자 `st_uid == os.getuid()`, 파일 모드 `0600`, 부모 디렉터리 `0700` 확인. 불일치, 심볼릭링크, FIFO/소켓 등 비정상 파일 타입 발견 시 즉시 `SecurityViolationError` fail-closed 차단).
- **Option B**: 권한 모드(`0600`)만 검증하고, 다중 사용자/공유 컨테이너 환경을 고려하여 소유자 UID 불일치는 경고 로그만 기록.

[Answer]: A

---

### Question 3: 출처 메타데이터(Provenance) 누락 및 고아 참조 격리 정책 (Domain Model & Error Handling)
`FR-TRUST-006` 및 `US-TRUST-006`에 따라 권위 있는 증거는 수집 시점의 식별자(`operation_id`, `target_identity`, `boot_id`, `pid`, `process_start_time`, `build_id`, `parent_evidence_refs`)를 유지해야 합니다. 필수 출처 필드가 누락되었거나 존재하지 않는 부모 증거를 참조(dangling reference)하는 경우의 처리 방식으로 어떤 방식을 채택하시겠습니까?

- **Option A (권장 / Recommended)**: 즉시 입도 상태를 `QUARANTINED`로 격리하고 사유 기록. 권위 있는 증거로의 승격을 차단하여 하류 진단 결론에 반영되지 않도록 격리(감사 트레일에는 보존).
- **Option B**: 즉시 `ProvenanceValidationError` 예외를 발생시키고 저장소 등록을 거부(fail-closed drop).

[Answer]: A

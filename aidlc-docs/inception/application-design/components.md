# 컴포넌트 설계 명세서 (Components Specification)

## 1. 개요
본 문서는 `aidlc-docs/inception/requirements/requirements.md`의 P0 신뢰성 및 보안 요구사항을 충족하기 위한 주요 컴포넌트의 책임, 경계 및 인터페이스 계약을 정의한다. 기존 아키텍처와 코드를 재사용하며, 불필요한 병렬 서브시스템을 추가하지 않는다.

---

## 2. 핵심 컴포넌트 정의

### 2.1 `OperationIdentityHelper` & `Attestation` (`extractor/capture_backend.py`)
- **목적**: 런타임 작업(Operation)의 canonical identity를 생성·검증하고, durable Attestation 소비 시점의 신뢰 경계를 강제한다.
- **주요 책임**:
  - `FR-TRUST-001`: durable Attestation 소비 전 `operation_id` 및 메타데이터 형식/길이/일관성 사전 검증.
  - `FR-TRUST-002`: `host_identity`, `boot_id`, `pid`, `process_start_time`, `build_id`, `normalized_parameters`를 결합한 완전한 Canonical Replay Identity 생성 및 정규화 직렬화.
  - `FR-TRUST-003`: 빈 메타데이터 수신 시 기존 identity 보존 및 'Identity Conflict' 이벤트 감지/격리.
  - `FR-TRUST-007`: `CREATED` → `VALIDATED` → `RESERVED` → `EXECUTING` → `COMMITTED` 유효 생명주기 전이 강제.
- **설계 제약**:
  - `capture_backend.py` 내부 헬퍼 함수 및 기존 `Attestation` 클래스 메서드로 구현하여 거대 클래스 비대화를 방지하고 기존 임포트 경로를 유지한다.

---

### 2.2 `DurableTrustStore` (`extractor/capture_backend.py`)
- **목적**: 지속성 신뢰 영수증(Receipts), 키 및 메타데이터의 안전하고 원자적인 파일시스템 영속화를 보장한다.
- **주요 책임**:
  - `FR-TRUST-005` & `NFR-SECURITY-001`: 민감 파일 `0600`, 디렉터리 `0700` 권한 강제 및 소유자 UID 일치 검증.
  - 심볼릭 링크 및 비정상 파일 타입(소켓, FIFO 등) 접근 시 `fail-closed` 차단.
  - `O_CREAT | O_EXCL` 기반의 안전한 락 파일 생성 및 TOCTOU 레이스 방어.
  - 동일 디렉터리 임시 파일 작성 → 파일 `fsync` → `os.replace` 원자적 교체 → 부모 디렉터리 `fsync`의 4단계 원자적 지속성 파이프라인.
  - 비정상 종료(SIGKILL/Crash) 후 복구 시 손상되거나 불완전한 상태 거부 및 stale 임시 파일 정리.

---

### 2.3 `EvidenceLedger` (`extractor/evidence_ledger.py`)
- **목적**: 수집된 진단 증거의 엄격한 입도(Admission) 상태 머신을 통제하고, 권위 있는 증거(Authoritative Evidence)의 계통(Provenance)을 보존한다.
- **주요 책임**:
  - `FR-TRUST-004`: 증거별 5단계 입도 상태 머신(`ACCEPTED`, `REJECTED`, `QUARANTINED`, `NOT_COVERED`, `PARTIAL`) 관리.
  - **인터페이스 수준의 완전 차단**: 하류 진단 파이프라인에는 오직 `ACCEPTED` 증거만을 반환하는 `get_eligible_evidence()` 인터페이스 제공.
  - 감사/포렌식 전용 인터페이스(`get_audit_trail()`)를 물리적으로 분리하여 `REJECTED`/`QUARANTINED` 증거를 가설 평가 경로로부터 원천 격리.
  - `FR-TRUST-006`: `operation_id`, `target_identity`, `boot_id`, `pid`, `process_start_time`, `parent_evidence_refs` 계통 링크 무결성 검증.

---

### 2.4 `ProcessExplainer` (`extractor/process_explainer.py`)
- **목적**: 결정론적 진단 결과(`DiagnoseResult`)를 사람이 이해하기 쉬운 자연어로 해설하는 순수 읽기 전용 계층.
- **주요 책임**:
  - `FR-EXPLAIN-001`: 입력으로 전달된 `DiagnoseResult`, `Evidence`, `verdict`의 완전한 불변성(immutability) 보장 (Deepcopy 또는 읽기 전용 래퍼 사용).
  - 진단 파이프라인의 핵심 판정 로직에 일체 관여하지 않으며, 설명 생성 실패 시에도 진단 결과 유효성을 보존.
  - 생성된 모든 해설 내용이 실제 `DiagnoseResult`의 증거 ID 및 필드만을 참조하도록 검증.

---

### 2.5 `ExpertDiagnosticEngine` & `DiagnosticVerdictAggregator` (`extractor/expert_diagnostic_engine.py`, `diagnostic_verdict_aggregator.py`)
- **목적**: 진단 워크플로우 오케스트레이션 및 판정 집계.
- **주요 책임**:
  - `EvidenceLedger`로부터 오직 `ACCEPTED` 증거만을 주입받아 가설 검증(`ExpertHypothesis`, `CompetingHypothesis`) 수행.
  - 입도 필터링을 우회하는 원시(raw) 증거 직접 접근 차단.
  - 불충분한 증거 시 명시적 `INCONCLUSIVE` 및 `not_covered` 판정 강제 (`healthy_verdict.py` 연계).

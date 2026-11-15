# 애플리케이션 설계 계획 (Application Design Plan)

## 1. 개요 및 목적
본 계획은 `aidlc-docs/inception/requirements/requirements.md`의 P0 신뢰성 요구사항(FR-TRUST-001 ~ 007) 및 NFR(보안, PBT, 복원력, 설명 계층 불변성)을 충족하는 상위 수준 컴포넌트 경계, 인터페이스, 서비스 오케스트레이션 및 의존성 구조를 수립하기 위한 실행 계획입니다.

---

## 2. 필수 설계 산출물 및 실행 체크리스트

- [x] **Step 1**: 컴포넌트 정의 및 상위 책임 명세 (`aidlc-docs/inception/application-design/components.md`)
  - `OperationIdentityHelper` (`capture_backend.py` 내장 확장)
  - `DurableTrustStore` (보안 불변식, TOCTOU 방어, 원자적 쓰기)
  - `EvidenceLedger` (5단계 입도 상태 머신 및 필터링)
  - `ProcessExplainer` (읽기 전용 설명 계층 및 DiagnoseResult 불변 보장)
- [x] **Step 2**: 메서드 시그니처 및 인터페이스 계약 명세 (`aidlc-docs/inception/application-design/component-methods.md`)
  - 사전 검증 메서드, Canonical 직렬화 메서드, Admission 평가 메서드, 원자적 지속성 메서드
- [x] **Step 3**: 서비스 계층 정의 및 오케스트레이션 패턴 명세 (`aidlc-docs/inception/application-design/services.md`)
  - 진단 파이프라인(`diagnose()`)과 신뢰 경계(Trust Boundary)의 오케스트레이션 흐름
- [x] **Step 4**: 컴포넌트 의존성 매트릭스 및 통신 패턴 명세 (`aidlc-docs/inception/application-design/component-dependency.md`)
  - 계층 간 단방향 의존성 및 순환 의존성 방지 구조
- [x] **Step 5**: 통합 애플리케이션 설계 문서 작성 (`aidlc-docs/inception/application-design/application-design.md`)
- [x] **Step 6**: 설계 완전성, 보안 불변식 및 PBT 검증 가능성 검토

---

## 3. 맥락 기반 설계 결정 질문 (Clarification Questions)

### Question 1: Canonical Replay Identity 및 Operation 생명주기 모듈화 전략
FR-TRUST-001(사전 검증), FR-TRUST-002(Replay Canonical Identity), FR-TRUST-007(생명주기) 구현 시, 5,500줄 규모의 기존 `capture_backend.py`를 어떻게 구조화하시겠습니까?

A) **`capture_backend.py` 내부 클래스 보강 (권장 - No Duplicate Implementation 원칙)**: 기존 아키텍처와 임포트 경로를 온전히 보존하면서 `capture_backend.py` 내의 `Attestation`, `OperationIdentity`, `TrustStore` 관련 클래스 메서드를 확장·보강  
B) **신규 전용 서브모듈 분리**: `extractor/operation_identity.py` 등으로 분리하여 독립 클래스로 구현하고 `capture_backend.py`에서 임포트  
X) Other (please describe after [Answer]: tag below)

[Answer]: A (Strengthen existing classes inside capture_backend.py)

---

### Question 2: Evidence Ledger 입도(Admission) 상태 머신 및 필터링 계층
FR-TRUST-004에 따라 `ACCEPTED`, `REJECTED`, `QUARANTINED`, `NOT_COVERED`, `PARTIAL` 5단계 입도 상태 머신을 적용할 때, 하류 진단 파이프라인(`expert_diagnostic_engine.py`, `diagnostic_verdict_aggregator.py`)에서의 필터링은 어디서 수행할까요?

A) **Evidence Ledger 인터페이스 수준에서 완전 차단 (권장 - Fail Closed)**: `EvidenceLedger.get_eligible_evidence()` 또는 필터링 프로퍼티를 제공하여 `ACCEPTED` 상태가 아닌 증거는 상위 엔진이 애초에 순회하거나 가설 평가에 전달할 수 없도록 강제  
B) **상위 진단 엔진(`expert_diagnostic_engine.py`) 내부에서 조건문 필터링**: 모든 증거를 전달받은 뒤 엔진과 어그리게이터가 각 단계에서 상태를 확인하고 배제  
X) Other (please describe after [Answer]: tag below)

[Answer]: A (Enforce evidence admission at the EvidenceLedger interface)

---

### Question 3: TrustStore 파일시스템 보안 및 원자적 쓰기 (Atomic Writes)
FR-TRUST-005(0600 권한, 소유자 검증, TOCTOU 방어) 구현 시 원자적 지속성 메커니즘을 어떻게 구성할까요?

A) **임시 파일 + 원자적 Rename + 디렉터리 fsync (권장 - POSIX 원자성 보장)**: 동일 디렉터리 내에 `0600` 권한으로 임시 파일을 생성하여 내용을 기록한 후 `os.replace`로 원자적 교체하고 디렉터리 fd fsync 수행  
B) **전용 Lock 파일 획득 후 직접 쓰기**: `O_CREAT | O_EXCL` 플래그로 락 파일을 획득한 후 원본 파일에 직접 쓰기 수행  
X) Other (please describe after [Answer]: tag below)

[Answer]: A (Use temporary-file + atomic replacement + file/directory fsync)

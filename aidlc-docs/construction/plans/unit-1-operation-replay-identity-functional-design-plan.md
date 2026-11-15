# Functional Design Plan: unit-1-operation-replay-identity

## 1. 개요 (Overview)
- **대상 작업 단위**: `unit-1-operation-replay-identity`
- **담당 컴포넌트**: `extractor/capture_backend.py` (DurableTrustStore, Operation Identity, Replay Protection, Lifecycle Management)
- **연관 사용자 스토리**: `US-TRUST-001`, `US-TRUST-002`, `US-TRUST-003`, `US-TRUST-007`
- **연관 요구사항**: `FR-TRUST-001`, `FR-TRUST-002`, `FR-TRUST-003`, `FR-TRUST-007`, `NFR-SECURITY-001`, `NFR-RESILIENCY-001`

---

## 2. 기능 설계 작업 체크리스트 (Functional Design Checklist)

### 2.1 계획 및 요구사항 분석
- [x] unit 맥락 분석 및 기존 `capture_backend.py` 구현 구조 정밀 대조
- [x] 기능 설계 계획 수립 및 명확화 질문 생성 (`aidlc-docs/construction/plans/unit-1-operation-replay-identity-functional-design-plan.md`)
- [x] 사용자 입력 수집 및 모호함 해소 (추천값 Option A 일괄 승인 및 추가 요구사항 반영)

### 2.2 산출물 생성 (Functional Design Artifacts)
- [x] `aidlc-docs/construction/unit-1-operation-replay-identity/functional-design/business-logic-model.md`
  - Operation ID 사전 검증 알고리즘 및 durable Attestation 소비 연동 시퀀스
  - Canonical Replay Identity 정규화 직렬화 알고리즘 (PID reuse 방어 포함)
  - Metadata 단조성 병합(Monotonic Merge) 및 충돌 감지 로직
  - 생명주기 상태 전이(Lifecycle Transition) 처리 파이프라인
- [x] `aidlc-docs/construction/unit-1-operation-replay-identity/functional-design/business-rules.md`
  - Operation ID 유효성 규칙 (구문, 길이, 문자셋, 격리)
  - Replay 거부 및 허용 기준 (단일 실행 원칙, 멱등 재조회 허용 범위)
  - Identity Conflict 판정 및 격리 규칙
  - 생명주기 허용 전이 매트릭스 및 금지 전이 거부 규칙
- [x] `aidlc-docs/construction/unit-1-operation-replay-identity/functional-design/domain-entities.md`
  - `OperationId` 값 객체 (Value Object)
  - `ProcessIdentity` 및 `CanonicalOperationIdentity` 엔티티 구조
  - `OperationLifecycleState` 열거형 및 `OperationRecord` 도메인 모델
  - `IdentityConflictEvent` 및 도메인 예외 정의

---

## 3. 기능 설계 질의 및 답변 (Clarification Q&A)

### Question 1: Operation ID 유효성 규격 및 검증 정책
- **선택**: Option A (화이트리스트 정규식 `^[a-zA-Z0-9_.:-]{1,128}$`, fail-closed 차단)

### Question 2: PID 재사용 방어를 위한 Process Identity 매칭 기준
- **선택**: Option A (`(host_identity, boot_id, pid, process_start_time)` 4개 튜플 완전 일치 강제)

### Question 3: Identity Conflict 발생 시 오류 처리 및 격리 전략
- **선택**: Option A (기존 유효/커밋 상태 불변 보존 + 상충 시도만 FAILED/REJECTED 처리 및 `IdentityConflictError` 발생)

### Question 4: Operation 생명주기 전이 및 복구 모델
- **선택**: Option A (엄격한 단방향 전이 + 미완료 작업 재사용 불가 + 신규 Operation ID 기반 재시도)

---

## 4. 확정된 설계 결정 및 구현 제약사항 (Approved Design Decisions)

1. **Operation ID (Q1)**:
   - 엄격한 화이트리스트: `^[a-zA-Z0-9_.:-]{1,128}$`
   - `None`, 빈 문자열, 공백 전용 문자열, 유니코드, 허용되지 않는 특수문자 즉시 거부.
   - 묵시적 trim이나 정규화 절대 금지 (공백 포함 시 즉시 거부).
   - 모든 외부 입력 경계(MCP 도구, CLI, HTTP 핸들러, TrustStore 메서드)에 동일한 검증 적용.
   - TrustStore 또는 Attestation 작업 전 사전 검증 강제.
   - 형식 검증, 고유성 검증, Replay 방어의 관심사 명확히 분리.

2. **Process Identity 및 Canonical Operation Identity (Q2)**:
   - `(host_identity, boot_id, pid, process_start_time)` 4대 튜플을 'Process Identity'로 엄격 대조.
   - 완전한 Replay 식별자는 Process Identity 외에 `operation_id`, `operation_kind`, `build_id`, `session_identity`, `request_scope`, `normalized_parameters`, `schema_version`을 포함.
   - 타임스탬프 단위: `/proc/<pid>/stat`의 22번째 필드(`starttime`, 부팅 후 클록 틱 단위의 불변 정수).
   - 필수 identity 필드 누락 시 fail-closed 거부.

3. **Identity Conflict 방어 (Q3)**:
   - 기존에 확립되어 유효한 identity 보존.
   - 상충 메타데이터 유입 시 `IdentityConflictError` 발생 및 감사 로그 기록.
   - 상충 시도만 거부하며, **별도의 상충 요청으로 인해 기존의 유효하거나 COMMITTED된 작업 상태를 FAILED로 변경하지 않음.**
   - `FAILED` 또는 `REJECTED`는 상충 시도의 생명주기에만 적용.

4. **Operation 생명주기 및 복구 (Q4)**:
   - 엄격한 단방향 검증 전이: `CREATED` → `VALIDATED` → `RESERVED` → `EXECUTING` → `COMMITTED`.
   - 명시적 종결 결과: `COMMITTED`(불변 종결), `REJECTED`, `FAILED`, `CANCELLED`, `PARTIAL`.
   - 복구 시 지속성 상태를 점검하며, 중단된 작업을 결코 성공한 것으로 간주하지 않음.
   - 미완료 작업은 묵시적으로 재사용될 수 없음.
   - 재시도는 반드시 새로운 `operation_id`를 사용하며 원본 작업과의 감사 관계(`retry_of_operation_id`)를 유지.

5. **구현 제약사항 (Implementation Constraints)**:
   - 기존 `capture_backend.py` 구현 구조 및 클래스 보존.
   - 중복 identity/lifecycle 서브시스템 생성 방지.
   - 모든 전이 및 실패 경계에 회귀 테스트 작성.
   - 동시 요청, PID reuse, identity conflict, 중단된 커밋, 복구 시나리오 전수 검증.
   - 헬퍼 메서드뿐 아니라 실제 런타임 호출 경로 검증.
   - 미검증 복구 및 파일시스템 동작을 명시적으로 보고.

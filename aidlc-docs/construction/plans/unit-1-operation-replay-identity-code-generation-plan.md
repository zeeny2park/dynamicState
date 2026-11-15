# Code Generation Plan: unit-1-operation-replay-identity

## 1. 개요 (Overview)
- **작업 단위 (Unit ID)**: `unit-1-operation-replay-identity`
- **프로젝트 유형**: Brownfield Monolith
- **수정 대상 파일**: `extractor/capture_backend.py` (단일 소스 내 응집 구현, 중복 서브시스템 금지)
- **신규 테스트 파일**:
  - `tests/test_trust_boundary_operation_id.py` (US-TRUST-001: Operation ID 사전 검증)
  - `tests/test_trust_boundary_replay_identity.py` (US-TRUST-002: Process Identity 4-tuple & PID reuse 방어)
  - `tests/test_trust_boundary_metadata_conflict.py` (US-TRUST-003: 기존 커밋 상태 보존 및 충돌 격리)
  - `tests/test_trust_boundary_lifecycle.py` (US-TRUST-007: 단방향 생명주기 및 크래시 복구)
- **연관 사용자 스토리**: `US-TRUST-001`, `US-TRUST-002`, `US-TRUST-003`, `US-TRUST-007`
- **핵심 엔지니어링 원칙**:
  - **테스트 선행 개발 (TDD)**: 실패하는 재현 테스트를 먼저 작성하고 실행하여 실패를 확인한 후 구현 진행.
  - **중복 구현 금지**: 기존 `capture_backend.py`의 `DurableTrustStore`, `CausalAttestation` 구조를 보존하고 보강.
  - **실측 벤치마크 및 fail-closed 검증**.

---

## 2. 코드 생성 단계별 계획 (Step-by-Step Execution Plan)

### Step 1: 선행 TDD 실패 회귀 테스트 작성 (Write Failing Tests)
- [x] `tests/test_trust_boundary_operation_id.py` 작성
  - 빈 문자열, None, 공백 포함(`" op1"`, `"op1 "`), 유니코드, 128자 초과, 경로 순회 기호 입력 시 fail-closed 차단 검증
  - `consume_attestation()` 호출 시 유효하지 않은 operation_id가 전달되면 디스크 I/O 없이 거부됨을 검증
- [x] `tests/test_trust_boundary_replay_identity.py` 작성
  - 동일 호스트/PID라도 `boot_id` 불일치 시 Replay Violation 거부 검증
  - 동일 `boot_id`/PID라도 `process_start_time` 불일치(PID reuse) 시 거부 검증
  - `(host_identity, boot_id, pid, process_start_time)` 4개 핵심 튜플 완전 일치 시에만 동일 프로세스로 인정
- [x] `tests/test_trust_boundary_metadata_conflict.py` 작성
  - 빈 metadata 주입 시 기존 Build ID 및 target host 보존 검증
  - 상충 메타데이터 유입 시 기존 COMMITTED 작업 상태가 FAILED로 오염되지 않고 그대로 보존됨을 검증
  - 상충을 유발한 신규 시도만 `IdentityConflictError`로 거부되고 `IdentityConflictEvent`가 기록됨을 검증
- [x] `tests/test_trust_boundary_lifecycle.py` 작성
  - `CREATED` → `VALIDATED` → `RESERVED` → `EXECUTING` → `COMMITTED` 정상 단방향 전이 검증
  - 비정상 직접 점프 및 역방향 전이 시도 시 `InvalidStateTransitionError` 발생 검증
  - `RESERVED` 상태에서 크래시 모의 후 저장소 재로드 시 `ABORTED_ON_RESTART`로 종결 처리되고 재사용 불가 검증
  - 재시도 시 신규 `operation_id` 및 원본 참조(`retry_of_operation_id`) 감사성 검증
- [x] `tests/test_pbt_operation_identity.py` 작성 (Hypothesis PBT, seed=42)

### Step 2: 선행 테스트 실행 및 실패 검증 (Verify Test Failures)
- [x] 4개 테스트 파일을 `pytest`로 실행하여 현재 코드베이스에서 명확히 실패함을 입증 및 기록 (ImportError / Failure 재현)

### Step 3: `extractor/capture_backend.py` 구현 및 보강 (Implement Production Code)
- [x] 도메인 예외 정의 (`InvalidOperationIdError`, `ProcessIdentityMismatchError`, `ProcessIdentityUnavailableError`, `MissingIdentityFieldError`, `IdentityConflictError`, `InvalidStateTransitionError`, `LockTimeoutError`)
- [x] 모듈 레벨 컴파일된 DFA 정규식 `_OPERATION_ID_REGEX = re.compile(r"^[a-zA-Z0-9_.:-]{1,128}\Z")` 및 `validate_operation_id()` 2단계 조기 탈출 구현
- [x] `ProcessIdentity` (4-tuple) 및 `CanonicalOperationIdentity` dataclass 구현
- [x] Linux `/proc/<pid>/stat` 22번째 필드(`starttime`) 추출 및 `/proc/sys/kernel/random/boot_id` 캐싱 구현
- [x] `OperationLifecycleState` 9대 상태 머신 열거형 정의
- [x] 2단계 락킹 `_file_lock()`에 5.0초 타임아웃 및 1ms~50ms 지수 백오프 적용
- [x] `DurableTrustStore.consume_attestation()` 최상단에 `validate_operation_id()` 강제 삽입
- [x] `DurableTrustStore.record_used_operation()`에 Process Identity 4-tuple 검증, 기존 커밋 상태 보존, 단방향 생명주기 관리, Eager Crash Recovery(`ABORTED_ON_RESTART`) 구현
- [x] `get_operation_lifecycle_state()` 및 `transition_operation_lifecycle()` 구현

### Step 4: 테스트 재실행 및 100% 통과 검증 (Verify Test Pass)
- [x] 5개 신규 테스트 파일 재실행하여 18 passed (100% PASS, 1.40s) 확인
- [x] 기존 캡처 테스트 93개 재실행하여 93 passed (100% PASS, 1.43s, 회귀 0건) 확인
- [x] 마이크로 벤치마크 10,000회 실행: p99 = 2.76 µs (< 50 µs SLA 달성)

### Step 5: 코드 요약 및 산출물 문서화 (Document Code Summary)
- [x] `aidlc-docs/construction/unit-1-operation-replay-identity/code/code-summary.md` 작성
- [x] 계획 체크리스트 완료 및 승인 요청

# 코드 요약서 (Code Summary) - unit-1-operation-replay-identity

- **작업 단위 (Unit ID)**: `unit-1-operation-replay-identity`
- **구현 일자**: 2026-11-15T02:28:40Z
- **프로젝트 유형**: Brownfield Monolith
- **수정 파일 (Modified)**:
  - `extractor/capture_backend.py`
- **신규 테스트 파일 (Created)**:
  - `tests/test_trust_boundary_operation_id.py` (5개 테스트 케이스: 형식 화이트리스트, trim 금지, Attestation 사전 소비 차단)
  - `tests/test_trust_boundary_replay_identity.py` (3개 테스트 케이스: Process Identity 4-tuple, PID reuse 방어, 필수 필드 누락 차단)
  - `tests/test_trust_boundary_metadata_conflict.py` (2개 테스트 케이스: 빈 metadata 보존, 기존 COMMITTED 불변 보존, 충돌 감사 이벤트)
  - `tests/test_trust_boundary_lifecycle.py` (4개 테스트 케이스: 순차 전이, 역방향/점프 차단, COMMITTED 종결성, Eager 크래시 복구)
  - `tests/test_pbt_operation_identity.py` (4개 Hypothesis 속성 테스트: seed=42, 100+ 예제 탐색, shrinking)

---

## 1. 구현 내용 요약

### 1.1 Operation ID 사전 검증 (FR-TRUST-001, US-TRUST-001)
- 모듈 싱글톤 컴파일 정규식 `_OPERATION_ID_REGEX = re.compile(r"^[a-zA-Z0-9_.:-]{1,128}\Z")` 도입.
- 2단계 조기 탈출(Early Exit) `validate_operation_id()` 함수 구현:
  - 1단계: 타입(`isinstance(s, str)`), 길이(`1 <= len(s) <= 128`), 공백 및 유니코드 검사. 묵시적 trim이나 정규화 일체 금지.
  - 2단계: 선형 DFA 정규식 매칭.
- `DurableTrustStore.consume_attestation()` 최상단 및 `record_used_operation()` 진입점에 사전 검증 루틴을 배치하여 durable 상태 소비 전 fail-closed 차단 보장.
- **실측 성능**: 10,000회 벤치마크 결과 **p99: 2.76 µs** (목표 SLA 50 µs 대비 18배 초과 달성).

### 1.2 Process Identity 및 Replay 방어 (FR-TRUST-002, US-TRUST-002)
- OS 수준의 프로세스 고유성을 보장하는 불변 동결 데이터 모델 `ProcessIdentity(host_identity, boot_id, pid, process_start_time)` 구현.
- `resolve_process_start_time(pid)`를 통해 Linux `/proc/<pid>/stat`의 22번째 필드(`starttime`, 클록 틱 단위 불변 정수)를 파싱하고 누락 시 `ProcessIdentityUnavailableError`로 fail-closed 처리.
- `DurableTrustStore.record_used_operation()`에서 PID 단독 비교를 배제하고, `boot_id` 불일치 및 `process_start_time` 불일치(PID rollover)를 Replay Violation으로 즉시 거부.
- 표준 Replay 식별자 `CanonicalOperationIdentity` 구현 및 `build_canonical_replay_identity()` 정규화 함수 제공.

### 1.3 Metadata 단조성 및 기존 상태 불변 보존 (FR-TRUST-003, US-TRUST-003)
- 빈 metadata(`{}` 또는 `None`)가 주입되더라도 기존에 확립된 Build ID나 target identity가 삭제되지 않도록 단조적 갱신 로직 강제.
- **상충 격리 불변식 보장**: 외부 상충 요청 유입 시 기존의 유효하거나 `COMMITTED`된 상태를 절대 `FAILED`로 변경하지 않고 100% 온전하게 보존하며, 상충을 유발한 시도에만 `IdentityConflictError` 발생 및 `self.identity_conflict_events` 감사 기록.

### 1.4 엄격한 단방향 생명주기 및 Eager 크래시 복구 (FR-TRUST-007, US-TRUST-007)
- 9대 생명주기 열거형 `OperationLifecycleState` 정의.
- `DurableTrustStore.transition_operation_lifecycle()`을 통해 `CREATED` → `VALIDATED` → `RESERVED` → `EXECUTING` → `COMMITTED` 단방향 전이만 허용하고, 불법 점프나 역방향 전이 시 `InvalidStateTransitionError` 발생.
- `COMMITTED` 상태를 영구 불변 종결(Terminal) 상태로 강제.
- `DurableTrustStore.load()` 시점에 Eager Crash Recovery를 수행하여, 시스템 비정상 종료 후 잔존한 `RESERVED` 또는 `EXECUTING` 미완료 작업을 일괄 `ABORTED_ON_RESTART`로 종결 처리하고 디스크에 원자적 즉시 영속화.

### 1.5 2단계 락킹 동시성 제어 (NFR-CONC-001 ~ 007)
- `_file_lock()`에 5.0초 타임아웃 및 1ms~50ms 지수 백오프 논블로킹 폴링(`fcntl.LOCK_EX | fcntl.LOCK_NB`) 적용.
- 타임아웃 초과 시 명시적 `LockTimeoutError` 발생 및 `try...finally` 블록을 통한 100% 락 해제 보장.

---

## 2. 테스트 및 검증 결과

1. **신규 TDD 회귀 테스트**:
   - `pytest tests/test_trust_boundary_*.py tests/test_pbt_operation_identity.py`
   - **결과**: **18 passed (100% PASS, 소요시간 1.40s)**
2. **기존 캡처 테스트 회귀 검증**:
   - `pytest tests/test_capture_*.py`
   - **결과**: **93 passed (100% PASS, 소요시간 1.43s, 회귀 0건)**
3. **PBT (Hypothesis) 테스트**:
   - `seed=42`, 각 프로퍼티당 100~150회 무작위 퍼징 및 최소 반례 축소 검증 완료.
4. **마이크로 벤치마크**:
   - `validate_operation_id()` 10,000회 측정: p50 = 2.56 µs, p90 = 2.56 µs, p99 = 2.76 µs (< 50 µs 예산 완벽 준수).

# 비기능 설계 패턴 명세서 (NFR Design Patterns)

- **대상 작업 단위**: `unit-1-operation-replay-identity`
- **담당 모듈**: `extractor/capture_backend.py`
- **연관 NFR 요구사항**: `aidlc-docs/construction/unit-1-operation-replay-identity/nfr-requirements/`

---

## 1. 개요 및 패턴 매트릭스

본 문서는 `unit-1-operation-replay-identity`의 비기능 요구사항(성능 p99 < 50µs, 동시성 5초 락 타임아웃, ReDoS/PID reuse 방어, 크래시 복원력)을 달성하기 위한 구체적인 아키텍처 및 코드 설계 패턴을 기술한다.

| NFR 영역 | 적용 패턴 | 설계 목적 | 해결 메커니즘 |
|---|---|---|---|
| **성능 (Performance)** | **2단계 조기 탈출 (Early Exit) & 사전 컴파일 DFA 패턴** | p99 < 50 µs 격리 검증 예산 달성 | 정수 길이/타입 비교로 무효 입력 99% 조기 탈출 + 모듈 싱글톤 `re.compile()` 단일 패스 매칭 |
| **동시성 (Concurrency)** | **2단계 락킹 (Two-Phase Locking) & 지수 백오프 폴링 패턴** | 스레드/프로세스 동기화 및 데드락 방어 | `threading.RLock` + `fcntl.flock(LOCK_EX | LOCK_NB)` (1ms~50ms 지수 백오프, 5.0s 타임아웃) |
| **복원력 (Resilience)** | **Eager Crash Recovery & 일괄 조정 패턴** | 크래시 후 미완료 작업 묵시적 간주 금지 | `load()` 시점에 `RESERVED`/`EXECUTING` 상태를 전수 스캔하여 `ABORTED_ON_RESTART`로 즉시 원자적 커밋 |
| **보안 (Security)** | **Fail-Closed 방어적 가드 (Defensive Guard) 패턴** | 유니코드 인젝션, PID Rollover, TOCTOU 방어 | 외부 경계와 코어 진입점의 동일 검증자 강제, `/proc/<pid>/stat` 누락 시 즉시 예외 중단 |
| **확장성 (Scalability)** | **불변 값 객체 (Frozen Value Object) & O(1) 해시 인덱싱 패턴** | 대규모 작업 ID 누적 시 선형 확장성 유지 | `dataclass(frozen=True)` 기반의 불변성 보장 및 딕셔너리 O(1) 인덱싱 |

---

## 2. 세부 설계 패턴

### 2.1 2단계 조기 탈출 및 사전 컴파일 DFA 패턴 (성능)
- **문제**: 정규식 매칭은 문자열 길이 검사나 타입 검사에 비해 CPU 사이클 소모가 큼.
- **구현 구조**:
  ```python
  # 모듈 로드 시 단 1회 컴파일 (DFA 선형 복잡도 보장)
  _OPERATION_ID_REGEX = re.compile(r"^[a-zA-Z0-9_.:-]{1,128}$")

  def validate_operation_id(operation_id: Any) -> str:
      # Stage 1: 초고속 정수/타입 조기 탈출 (< 1 µs)
      if not isinstance(operation_id, str):
          raise InvalidOperationIdError(f"Operation ID must be str, got {type(operation_id).__name__}")
      n = len(operation_id)
      if n < 1 or n > 128:
          raise InvalidOperationIdError(f"Operation ID length must be between 1 and 128, got {n}")
      if operation_id[0] == " " or operation_id[-1] == " ":
          raise InvalidOperationIdError("Operation ID must not contain leading or trailing whitespace (no trim)")

      # Stage 2: 단일 패스 DFA 정규식 매칭 (< 10 µs)
      if not _OPERATION_ID_REGEX.match(operation_id):
          raise InvalidOperationIdError(f"Operation ID '{operation_id}' contains invalid characters")
      
      return operation_id
  ```

### 2.2 2단계 락킹 및 지수 백오프 폴링 패턴 (동시성)
- **문제**: 블로킹 `fcntl.flock(LOCK_EX)`은 다른 프로세스가 비정상 종료되거나 락을 오래 점유할 때 무한 대기(hang) 위험이 있으며, 스레드 간 동기화를 보장하지 못함.
- **구현 구조**:
  ```mermaid
  sequenceDiagram
      autonumber
      participant Thread as Worker Thread
      participant RLock as threading.RLock (In-Memory)
      participant Flock as fcntl.flock (Inter-Process)
      participant Critical as Critical Section

      Thread->>RLock: acquire()
      Note over Thread,RLock: 스레드 간 경합 동기화 완료
      loop 최대 5.0초 (1ms ~ 50ms 지수 백오프)
          Thread->>Flock: fcntl.flock(fd, LOCK_EX | LOCK_NB)
          alt 락 획득 성공
              Flock-->>Thread: 0 (OK)
          else EAGAIN / EWOULDBLOCK
              Thread->>Thread: time.sleep(backoff_duration)
          end
      end
      alt 5.0초 타임아웃 초과
          Thread->>RLock: release()
          Thread-->>Thread: raise LockTimeoutError
      else 락 획득 성공
          Thread->>Critical: execute_operation()
          Note over Critical: 트러스트 소비 및 상태 영속화
          Critical-->>Thread: complete
          Thread->>Flock: fcntl.flock(fd, LOCK_UN) (finally:)
          Thread->>RLock: release() (finally:)
      end
  ```

### 2.3 Eager Crash Recovery 패턴 (복원력)
- **문제**: 비정상 크래시나 전원 단절 후 시스템이 재시작되었을 때, `RESERVED` 또는 `EXECUTING` 상태인 미완료 작업이 커밋된 것으로 오인되거나 방치되어 고아 상태로 남음.
- **해결 구조**:
  - `DurableTrustStore.load()` 시점에 디스크에서 읽어온 모든 `used_operation_ids` 레코드를 순회.
  - `state`가 `RESERVED` 또는 `EXECUTING`인 경우:
    - `state = OperationLifecycleState.ABORTED_ON_RESTART`
    - `metadata["aborted_at"] = now_iso`
    - `metadata["abort_reason"] = "Process terminated abnormally before completion"`
  - 하나 이상의 미완료 레코드가 발견되면 즉시 `save()`를 호출하여 정제된 상태를 디스크에 원자적으로 반영.

### 2.4 Fail-Closed Defensive Perimeter Guard 패턴 (보안)
- **문제**: 외곽 진입점(CLI, MCP)과 내부 저장소(`DurableTrustStore`) 간의 검증 로직이 불일치할 경우 우회 경로 발생 가능.
- **해결 구조**:
  - 모든 진입점에서 `validate_operation_id()` 함수를 단일 진실 공급원(Single Source of Truth)으로 사용.
  - `/proc/<pid>/stat`의 `starttime` 필드 파싱 실패 시 결코 임의의 가상 타임스탬프를 주입하지 않고 `ProcessIdentityUnavailableError`를 발생시켜 즉각 거부.

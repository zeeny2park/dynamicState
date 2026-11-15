# 비기능 요구사항 명세서 (NFR Requirements)

- **대상 작업 단위**: `unit-1-operation-replay-identity`
- **담당 모듈**: `extractor/capture_backend.py`
- **연관 NFR 식별자**: `NFR-SECURITY-001`, `NFR-RESILIENCY-001`, `NFR-RESILIENCY-002`, `NFR-PBT-001`, `NFR-PROCESS-001`, `NFR-PROCESS-002`

---

## 1. 성능 요구사항 및 지연시간 예산 (Performance Budget)

| 항목 | 목표치 / 지표 | 측정 범위 및 조건 | 검증 및 준수 원칙 |
|---|---|---|---|
| **격리 유효성 검증 지연시간** | **p99 < 50 µs** | `validate_operation_id()` 단독 및 인메모리 `ProcessIdentity` 대조 | 파일시스템 I/O, 디스크 `fsync`, 파일 락 획득 시간은 격리 예산에서 제외. 컴파일된 정규식 단일 패스 검증으로 달성. |
| **표준 식별자 생성 지연시간** | **p99 < 100 µs** | `build_canonical_replay_identity()` 정규화 및 SHA-256 해시 계산 | 격리 검증 예산과 분리하여 독립 벤치마크로 측정. |
| **전체 캡처 경로 오버헤드** | **추가 오버헤드 < 1 ms** | 락 획득, 검증, 캡처, 영수증 서명, 저장소 커밋 전 과정 | 전체 캡처 경로 오버헤드를 분리 측정하여 타깃 중단 시간 예산(< 10 ms) 준수 보장. |
| **성능 준수 증명 불변식** | **실측치 필수** | 환경 정보, 샘플 수(N >= 1,000), 지연시간 분포(p50, p90, p99) 기록 | **재현 가능한 실측 벤치마크 없이 성능 준수를 주장하는 것을 엄격히 금지.** 추정치와 실측치를 명확히 구분 표기. |

---

## 2. 동시성 제어 및 락 규율 (Concurrency Control & Lock Discipline)

| 규칙 ID | 항목 | 상세 규율 | 위반 시 조치 |
|---|---|---|---|
| **NFR-CONC-001** | 프로세스 내 스레드 동기화 | 프로세스 내부 다중 스레드 간에는 `threading.RLock`을 사용하여 메모리 내 상태 일관성 보호. | 레이스 컨디션 차단 |
| **NFR-CONC-002** | 프로세스 간 조정 | 다중 진단 에이전트/프로세스 간에는 `fcntl.flock(LOCK_EX)`을 사용하여 파일시스템 수준 조정. | 다중 프로세스 영수증 충돌 방지 |
| **NFR-CONC-003** | 락 획득 타임아웃 | 락 획득 대기 시간은 **최대 5.0초**로 제한. 타임아웃 초과 시 대기를 중단하고 즉시 명시적 `LockTimeoutError` 발생 (fail-closed). | 묵시적 대기 및 영구 행(hang) 차단 |
| **NFR-CONC-004** | 일관된 획득/해제 순서 | 항상 `threading.RLock` 획득 후 `fcntl.flock` 획득 순서를 엄격히 준수하며, 해제 시 역순(`flock` 해제 후 `RLock` 해제)으로 해제. | 데드락 원천 방어 |
| **NFR-CONC-005** | 예외 및 취소 안전성 | `try...finally` 블록을 강제하여 예외 발생, 사용자 취소, 비정상 중단 등 모든 실행 경로에서 획득된 모든 락을 100% 누수 없이 해제. | 고아 락 잔류 방어 |
| **NFR-CONC-006** | 락 유지 구간 최소화 | 디스크 `fsync` 및 파일 락을 쥐고 있는 임계 구역(Critical Section) 내부에서는 불필요한 계산이나 외부 네트워크/IPC 통신을 일체 수행하지 않음. | 경합 오버헤드 최소화 |
| **NFR-CONC-007** | 필수 락 부재 시 진행 금지 | 필요한 락을 획득하지 못한 상태에서는 어떠한 읽기-수정-쓰기 작업도 묵시적으로 계속 진행할 수 없음. | `LockAcquisitionRequiredError` |

---

## 3. 보안 및 위협 모델 (Security & Threat Model)

| 위협 요소 | 방어 기제 | 상세 요구사항 |
|---|---|---|
| **ReDoS (정규식 서비스 거부)** | 선형 시간 화이트리스트 | 정규식 `^[a-zA-Z0-9_.:-]{1,128}$`는 역추적(backtracking)이 발생하지 않는 결정론적 유한 오토마타(DFA) 선형 복잡도로 동작하여 ReDoS 공격 원천 무력화. |
| **유니코드 및 제어문자 인젝션** | 엄격한 ASCII 화이트리스트 | UTF-8 특수문자, 전각 문자, 제어 문자, 줄바꿈 문자 등을 묵시적으로 변환하지 않고 즉시 차단(fail-closed). |
| **PID Rollover / Replay 공격** | 4대 튜플 Process Identity | 커널의 PID 재사용 공격에 대해 `(host_identity, boot_id, pid, process_start_time)` 완전 일치를 강제하여 이전 세션이나 다른 프로세스의 증거 오연결 차단. |
| **TOCTOU 레이스 컨디션** | 원자적 예약 및 파일 락 | 락 획득 상태에서 `used_operation_ids` 검증과 예약을 원자적으로 수행하여 동시 중복 소비 시도 차단. |

---

## 4. 복원력 및 크래시 복구 (Resiliency & Crash Recovery)

| 항목 | 상세 요구사항 |
|---|---|
| **불완전 작업 묵시적 간주 금지** | 시스템 비정상 종료(SIGKILL/Crash) 후 재기동 복구 시, `RESERVED` 또는 `EXECUTING` 상태로 남아 있는 미완료 작업을 **절대 성공(`COMMITTED`)한 것으로 간주하지 않음.** |
| **미완료 작업 재사용 차단** | 중단된 미완료 작업은 묵시적으로 재개되거나 재사용될 수 없으며, 안전하게 `ABORTED_ON_RESTART` 상태로 종결 처리됨. |
| **신규 Operation ID 기반 재시도** | 작업 재시도는 반드시 완전히 새로운 `operation_id`를 발급받아야 하며, 원본 작업과의 감사 추적 링크(`retry_of_operation_id`)를 유지해야 함. |
| **지원 파일시스템 검증** | 로컬 ext4, xfs 등 `fcntl.flock` 및 POSIX 원자적 교체가 보장되는 파일시스템을 전제로 하며, NFS/CIFS 등 락 시맨틱이 불완전한 원격 마운트 환경의 제약사항을 명시적으로 문서화. |

---

## 5. 속성 기반 테스트(PBT) 및 품질 기준선 (Testing & Quality Baseline)

| 항목 | 상세 기준 |
|---|---|
| **PBT 프레임워크** | `Hypothesis` 기반 속성 테스트 구축 (`tests/test_pbt_operation_identity.py`). |
| **결정론적 시드 (PR 차단성)** | PR 및 커밋 단위의 기본 테스트에서는 **`seed=42`** 고정 시드를 사용하여 100% 결정론적이고 재현 가능한 테스트 보장. |
| **테스트 예제 수** | 핵심 불변식(Operation ID 구문 검증, Process Identity 대조, 단조성, 생명주기 전이)마다 **최소 100회 이상의 생성 예제(`max_examples=100`)** 실행. |
| **반례 자동 축소 (Shrinking)** | 불변식 위반 발견 시 Hypothesis의 Shrinking 기능을 통해 최소 반례(minimal failing input)를 도출하고 시드와 함께 기록. |
| **회귀 테스트 승격** | PBT를 통해 발견된 모든 주요 결함 반례는 즉시 독립된 고정 단위 테스트(`tests/test_trust_boundary_*.py`)로 승격하여 영구 회귀 테스트 슈트에 포함. |
| **스케줄링 확장 테스트** | 정기 나이트리/스케줄 빌드에서는 다중 랜덤 시드 및 확장 예제(1,000회 이상)를 실행하여 미지의 경계 사례 지속 탐색. |
| **CI 차단성 강제** | 핵심 보안 불변식 실패는 CI 파이프라인에서 즉시 빌드 실패(Blocking Failure)로 취급. |

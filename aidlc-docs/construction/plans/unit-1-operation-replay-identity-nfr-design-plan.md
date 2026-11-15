# NFR Design Plan: unit-1-operation-replay-identity

## 1. 개요 (Overview)
- **대상 작업 단위**: `unit-1-operation-replay-identity`
- **담당 모듈**: `extractor/capture_backend.py`
- **연관 NFR 요구사항**: `aidlc-docs/construction/unit-1-operation-replay-identity/nfr-requirements/`
- **연관 핵심 불변식**:
  - p99 < 50µs 사전 검증 및 Process Identity 대조 성능 SLA 준수
  - 2단계 락킹(`threading.RLock` + `fcntl.flock`) 및 5.0초 타임아웃 fail-closed 강제
  - Hypothesis 결정론적 시드(`seed=42`) PBT 및 최소 반례 축소(Shrinking)
  - Python 3.9+ 표준 라이브러리 엄수 및 무의존성(Zero-external-dependency) 원칙

---

## 2. NFR 설계 작업 체크리스트 (NFR Design Checklist)

### 2.1 계획 및 요구사항 분석
- [x] NFR Requirements 산출물 및 Brownfield 아키텍처 패턴 정밀 대조
- [x] NFR 설계 계획 수립 및 5대 질문 범주 평가 (`aidlc-docs/construction/plans/unit-1-operation-replay-identity-nfr-design-plan.md`)
- [x] 사용자 입력 수집 및 패턴 확정 (Option A 추천안 승인)

### 2.2 NFR Design 산출물 생성 (NFR Design Artifacts)
- [x] `aidlc-docs/construction/unit-1-operation-replay-identity/nfr-design/nfr-design-patterns.md`
  - 성능 패턴: 선형 DFA 정규식 싱글톤 컴파일 및 조기 탈출(Early Exit) 패턴
  - 복원력 패턴: Eager Crash Recovery 패턴 및 Two-Phase Locking 컨텍스트 패턴
  - 보안 패턴: Fail-Closed Defensive Guard 및 Process Identity 4-tuple 불변식 패턴
  - 확장성 패턴: O(1) 인메모리 해시 인덱싱 및 불변 값 객체(Frozen Value Object) 패턴
- [x] `aidlc-docs/construction/unit-1-operation-replay-identity/nfr-design/logical-components.md`
  - `OperationIdValidator`: 모듈 레벨 컴파일된 정규식 검증기
  - `ProcessIdentityResolver`: `/proc/<pid>/stat` 파싱 및 4대 튜플 불변 비교 컴포넌트
  - `TwoPhaseTrustLock`: `threading.RLock` + 타임아웃 지원 `fcntl.flock` 컨텍스트 매니저
  - `CrashRecoveryReconciler`: 부팅/로드 시점 미완료 상태(`ABORTED_ON_RESTART`) 일괄 조정기

---

## 3. NFR 설계 명확화 질문 (Clarification Questions)

NFR 설계 품질과 패턴 구체화를 위해 다음 질문을 검토해 주시기 바랍니다. 권장안(`Option A`)을 기본값으로 표기해 두었습니다.

### Question 1: 비정상 종료 후 복구 패턴 (Resilience Patterns - Crash Recovery Timing)
`FR-TRUST-007` 및 `NFR-RESILIENCY-001`에 따라 `RESERVED` 또는 `EXECUTING` 상태에서 비정상 중단된 미완료 작업은 결코 커밋된 것으로 오인되지 않고 `ABORTED_ON_RESTART`로 정리되어야 합니다. 복구 감지 및 조정(Reconciliation) 시점으로 어떤 패턴을 채택하시겠습니까?

- **Option A (권장 / Recommended)**: Eager Recovery 패턴 (`DurableTrustStore.load()` 시점에 디스크 상태를 전수 스캔하여 미완료 작업을 일괄 `ABORTED_ON_RESTART`로 정리하고 원자적 저장. 런타임 조회 시 지연 없음).
- **Option B**: Lazy Recovery 패턴 (개별 작업 ID 접근 시점에 해당 레코드가 미완료 상태이면 그때 상태를 전이).

[Answer]: A

---

### Question 2: 사전 검증 성능 최적화 패턴 (Performance Patterns - Early Exit & Precompiled DFA)
`p99 < 50 µs`의 엄격한 성능 예산을 만족하기 위한 `validate_operation_id()`의 최적화 패턴으로 어떤 방식을 채택하시겠습니까?

- **Option A (권장 / Recommended)**: 2단계 조기 탈출 패턴 (1단계: `isinstance(s, str)` 및 `1 <= len(s) <= 128` 길이 정수 비교로 99% 무효 입력 조기 탈출 → 2단계: 모듈 로드 시점에 사전 컴파일된 `re.compile(r'^[a-zA-Z0-9_.:-]+$')` DFA 단일 패스 매칭).
- **Option B**: 매 호출마다 `re.match()` 함수 직접 호출.

[Answer]: A

---

### Question 3: 2단계 락킹 타임아웃 및 폴링 세분성 (Logical Components - Lock Coordination)
프로세스 간 `fcntl.flock(LOCK_EX)` 획득 시 5.0초 타임아웃 동안의 폴링 및 블로킹 제어 패턴으로 어떤 방식을 채택하시겠습니까?

- **Option A (권장 / Recommended)**: 지수 백오프 기반 논블로킹 폴링 (`fcntl.flock(LOCK_EX | LOCK_NB)`을 시도하고 `EAGAIN`/`EWOULDBLOCK` 시 초기 1ms에서 최대 50ms까지 지수 백오프로 대기, 총 5.0초 초과 시 `LockTimeoutError` 발생).
- **Option B**: 단순 0.05초 고정 주기 폴링 (총 5.0초 동안 100회 균등 폴링).
- **Option C**: OS 시그널(`signal.alarm`) 기반 인터럽트 (스레드 환경에서 시그널 충돌 위험 존재).

[Answer]: A

---

### Question 4: Process Identity 추출 실패 시의 Fail-Closed 처리 패턴 (Security Patterns)
타깃 프로세스가 이미 종료되었거나 권한 부족 등으로 `/proc/<pid>/stat`의 `starttime` 필드를 읽을 수 없는 경우의 보안 처리 패턴으로 어떤 방식을 채택하시겠습니까?

- **Option A (권장 / Recommended)**: 엄격한 Fail-Closed 예외 발생 (`ProcessIdentityUnavailableError`를 발생시키고 작업 즉시 중단. 유효하지 않은 임의 타임스탬프 대체 절대 불허).
- **Option B**: 시스템 현재 시각(`time.time()`)을 대체값으로 주입하고 경고 로그 기록 후 계속 진행.

[Answer]: A

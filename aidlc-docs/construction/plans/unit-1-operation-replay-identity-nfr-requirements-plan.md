# NFR Requirements Plan: unit-1-operation-replay-identity

## 1. 개요 (Overview)
- **대상 작업 단위**: `unit-1-operation-replay-identity`
- **담당 모듈**: `extractor/capture_backend.py`
- **연관 기능 설계**: `aidlc-docs/construction/unit-1-operation-replay-identity/functional-design/`
- **연관 NFR 및 엔지니어링 원칙**:
  - `NFR-SECURITY-001`: 보안 불변식 및 차단성 제약 (ReDoS 방어, PID reuse 방어, Fail-Closed)
  - `NFR-RESILIENCY-001`: 코어 작업 복원력 및 크래시 후 일관된 복구
  - `NFR-RESILIENCY-002`: 원격 세션 격리 및 Stale 증거 오연결 방지
  - `NFR-PBT-001`: 속성 기반 테스트 (Hypothesis 결정론적 시드 및 최소 반례)
  - `capture_backend.py` 코어 원칙: 극초단 프로세스 중단 시간 (< 10ms), Fail-Open 프로세스 재개 보장

---

## 2. NFR 평가 작업 체크리스트 (NFR Evaluation Checklist)

### 2.1 분석 및 계획 수립
- [x] Functional Design 산출물 및 Brownfield 기술 스택 제약 분석
- [x] NFR 계획 수립 및 시스템 품질 명확화 질문 생성 (`aidlc-docs/construction/plans/unit-1-operation-replay-identity-nfr-requirements-plan.md`)
- [x] 사용자 입력 수집 및 요구수준 확정 (Approved NFR Decisions 반영)

### 2.2 NFR 산출물 생성 (NFR Requirements Artifacts)
- [x] `aidlc-docs/construction/unit-1-operation-replay-identity/nfr-requirements/nfr-requirements.md`
  - 성능 요구사항: 사전 검증 및 Process Identity 대조 지연시간 예산 (< 50µs)
  - 보안 요구사항: ReDoS 방어 선형 시간 검증, PID reuse 공격 차단, 유니코드 인젝션 방어
  - 복원력 요구사항: 동시 다중 요청 fcntl 락 일관성, 크래시 후 원자적 복구
  - 테스트 및 품질 요구사항: Hypothesis PBT 기준, 선행 TDD 결함 재현 100% 통과 기준
- [x] `aidlc-docs/construction/unit-1-operation-replay-identity/nfr-requirements/tech-stack-decisions.md`
  - 파이썬 표준 라이브러리 엄수 (`re`, `dataclasses`, `fcntl`, `hashlib`) - 외부 의존성 추가 금지
  - Linux 플랫폼 특화 `/proc` stat 파싱 및 POSIX 시간 정밀도
  - AArch64 + x86_64 크로스 플랫폼 호환성 기준

---

## 3. NFR 명확화 질문 (Clarification Questions)

비기능 요구사항의 구체적인 임계치와 기술 스택 결정을 확정하기 위해 아래 질문을 검토해 주시기 바랍니다. 권장안(`Option A`)을 기본값으로 표기해 두었습니다.

### Question 1: Operation ID 사전 검증 및 Process Identity 대조 성능 예산 (Performance Budget)
`capture_backend.py`는 타깃 프로세스 중단 시간을 10ms 미만으로 엄격히 제한하고 있습니다. Attestation 소비 및 락 진입 전 수행되는 `validate_operation_id()` 및 `ProcessIdentity` 대조 루틴의 지연시간 상한(Latency SLA)으로 어떤 기준을 채택하시겠습니까?

- **Option A (권장 / Recommended)**: 엄격한 마이크로초 예산 (단일 검증 < 50µs, 인메모리 캐싱 및 컴파일된 단일 패스 정규식 사용으로 캡처 경로에 측정 가능한 부하 전무)
- **Option B**: 여유 있는 밀리초 예산 (< 1ms, 성능 최적화보다 예외 로깅 및 상세 감사 객체 생성 중심)

[Answer]: A

---

### Question 2: 동시 다중 프로세스/스레드 경합 시 동시성 제어 정책 (Concurrency & Lock Discipline)
동일한 타깃이나 서로 다른 작업이 동시에 `DurableTrustStore`에 접근할 때의 동시성 제어 모델로 어떤 방식을 채택하시겠습니까?

- **Option A (권장 / Recommended)**: 2단계 락킹 (인메모리 `threading.RLock` + 프로세스 간 POSIX `fcntl.flock(LOCK_EX)`). 락 획득 타임아웃(기본 5.0초) 적용하여 데드락 원천 방어 및 fail-closed 처리.
- **Option B**: 단일 `fcntl.flock` 파일 락만 사용 (동일 프로세스 내 스레드 간에도 OS 파일 락에 전적으로 위임).
- **Option C**: 낙관적 락킹 (락 없이 원자적 replace 시도시 충돌 감지 후 재시도).

[Answer]: A

---

### Question 3: 속성 기반 테스트(PBT, Hypothesis)의 강도 및 시드 고정 기준 (Test & Quality Baseline)
`NFR-PBT-001`에 따라 Operation ID, Process Identity, Lifecycle 전이 불변식을 Hypothesis PBT로 검증할 때의 테스트 강도 및 재현성 기준으로 어떤 방식을 채택하시겠습니까?

- **Option A (권장 / Recommended)**: 결정론적 고정 시드(`seed=42` 기본, CLI 오버라이드 지원) + 최소 100회 예제 탐색(examples=100) + 실패 시 최소 반례 자동 축소(Shrinking). CI 차단성(Blocking) 테스트로 등록.
- **Option B**: 비결정론적 난수 시드(매 실행마다 랜덤 탐색) + 실패 시 시드 로깅 및 200회 탐색.

[Answer]: A

---

### Question 4: 기술 스택 의존성 제약 (Tech Stack & Dependency Policy)
`extractor` 패키지의 코어 모듈인 `capture_backend.py`의 신뢰성 및 이식성을 보장하기 위한 라이브러리 의존성 정책으로 어떤 방식을 채택하시겠습니까?

- **Option A (권장 / Recommended)**: 순수 Python 3.9+ 표준 라이브러리(`re`, `dataclasses`, `enum`, `fcntl`, `hashlib`, `os`, `time`, `typing`)만 사용. 신규 외부 의존성(pydantic 등) 추가 절대 금지.
- **Option B**: 데이터 검증을 위한 외부 전문 라이브러리(pydantic 등) 도입 허용.

[Answer]: A

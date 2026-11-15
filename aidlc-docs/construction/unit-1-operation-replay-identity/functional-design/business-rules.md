# 비즈니스 규칙 명세서 (Business Rules)

- **대상 작업 단위**: `unit-1-operation-replay-identity`
- **담당 모듈**: `extractor/capture_backend.py`
- **연관 요구사항**: `FR-TRUST-001`, `FR-TRUST-002`, `FR-TRUST-003`, `FR-TRUST-007`

---

## 1. Operation ID 유효성 및 경계 검증 규칙 (BR-OPID-001)

| 규칙 ID | 규칙명 | 상세 내용 | 실패 시 조치 |
|---|---|---|---|
| **BR-OPID-001-1** | 엄격한 화이트리스트 정규식 | `operation_id`는 반드시 `^[a-zA-Z0-9_.:-]{1,128}$` 패턴을 100% 만족해야 함. 영숫자, 언더스코어, 마침표, 콜론, 하이픈만 허용. | `InvalidOperationIdError` (Fail-Closed) |
| **BR-OPID-001-2** | 비정상 입력 즉시 거부 | `None`, 빈 문자열, 공백만 있는 문자열, 유니코드(전각 문자, 스마트 대시 등), 제어 문자 입력 시 즉시 거부. | `InvalidOperationIdError` |
| **BR-OPID-001-3** | 묵시적 정규화 금지 | 식별자에 대해 `strip()`이나 치환 등의 묵시적 가공을 일체 금지함. 공백이 포함된 식별자는 정규화하지 않고 즉시 거부. | `InvalidOperationIdError` |
| **BR-OPID-001-4** | 모든 외부 경계 동일 검증 | MCP 도구 입력, CLI 파라미터, HTTP 핸들러, TrustStore 내부 메서드 등 모든 진입점에서 완전히 동일한 검증 함수 적용. | 진입 시점 즉시 차단 |
| **BR-OPID-001-5** | 사전 검증 순서 불변식 | 지속성 TrustStore 상태 변경 또는 Attestation 소비 작업이 발생하기 전에 형식 검증이 반드시 선행되어야 함. | 상태 소비 사전 차단 |
| **BR-OPID-001-6** | 검증 관심사 분리 | 형식 검증(Syntax), 단일 실행 고유성 검증(Uniqueness), 실행 컨텍스트 대조(Replay Protection)를 독립된 단계로 분리하여 평가. | 단계별 명확한 오류 구분 |

---

## 2. Process Identity 및 Canonical Operation Identity 규칙 (BR-PROC-001 & BR-REPLAY-001)

| 규칙 ID | 규칙명 | 상세 내용 | 실패 시 조치 |
|---|---|---|---|
| **BR-PROC-001-1** | Process Identity 4대 튜플 | `(host_identity, boot_id, pid, process_start_time)` 4개 값의 완전 일치를 요구함. 이 튜플은 'Process Identity'로 취급되며 전체 Replay Identity와 개념적으로 분리됨. | `ProcessIdentityMismatchError` |
| **BR-PROC-001-2** | 타임스탬프 단위 및 신뢰성 | `process_start_time`은 `/proc/<pid>/stat`의 22번째 필드(`starttime`)에서 읽은 부팅 후 클록 틱 단위의 불변 정수값(또는 부팅 시각 기반 고정밀 나노초)을 사용하며 임의 생성값을 불허함. | `InvalidProcessStartTimeError` |
| **BR-REPLAY-001-1** | Canonical Operation Identity 완전성 | 완전한 Replay 방어 식별자는 Process Identity 외에 `operation_id`, `operation_kind`, `build_id`, `session_identity`, `request_scope`, `normalized_parameters`, `schema_version`을 포함해야 함. | `MissingIdentityFieldError` (Fail-Closed) |
| **BR-REPLAY-001-2** | 필수 필드 누락 차단 | 필수 식별자 필드가 하나라도 누락되거나 빈 문자열인 경우 fail-closed 원칙에 따라 작업을 거부함. | `MissingIdentityFieldError` |
| **BR-REPLAY-001-3** | 단일 실행 및 멱등 재조회 | 동일 `operation_id`가 이미 커밋된 경우 다른 프로세스/작업 재사용은 거부하되, 완전히 동일한 Replay Identity를 가진 동일 증거 재요청은 읽기 전용 멱등 상태(`IDEMPOTENT_RECOVERY`)로 허용. | 안전한 기존 상태 반환 |

---

## 3. Identity Conflict 방어 및 기존 상태 불변 보존 규칙 (BR-CONFLICT-001)

| 규칙 ID | 규칙명 | 상세 내용 | 실패 시 조치 |
|---|---|---|---|
| **BR-CONFLICT-001-1** | 기존 유효 Identity 보존 | 기존에 확립되어 저장된 유효한 Identity(예: Build ID, 호스트, 실행 파일 해시)는 후속 요청의 메타데이터로 덮어쓰거나 훼손할 수 없음. | 기존 값 무조건 보존 |
| **BR-CONFLICT-001-2** | 기존 커밋 상태 불변성 | **외부 상충 요청이 유입되더라도 기존에 유효하거나 이미 `COMMITTED`된 작업의 상태를 `FAILED`로 변경하지 않음.** | 기존 작업 상태 유지 |
| **BR-CONFLICT-001-3** | 상충 시도 격리 및 거부 | 충돌을 유발한 새로운 시도(attempt)에 대해서만 `FAILED` 또는 `REJECTED` 결과를 적용하고 `IdentityConflictError`를 발생시켜 거부함. | `IdentityConflictError` |
| **BR-CONFLICT-001-4** | 충돌 감사 이벤트 기록 | 모든 상충 시도는 `IdentityConflictEvent`로 생성되어 감사 로그에 기록되어야 함. | 포렌식 추적성 확보 |

---

## 4. Operation 생명주기 및 복구 규칙 (BR-LIFE-001)

| 규칙 ID | 규칙명 | 상세 내용 | 실패 시 조치 |
|---|---|---|---|
| **BR-LIFE-001-1** | 엄격한 단방향 전이 | 성공 경로는 반드시 `CREATED` → `VALIDATED` → `RESERVED` → `EXECUTING` → `COMMITTED` 순서로만 진행되며 역방향이나 건너뛰기 전이는 불가. | `InvalidStateTransitionError` |
| **BR-LIFE-001-2** | COMMITTED 종결성 | `COMMITTED` 상태는 영구 불변의 종결(Terminal) 상태이며, 어떠한 사후 이벤트로도 변경 불가. | 상태 변경 거부 |
| **BR-LIFE-001-3** | 명시적 실패 결과 구분 | 작업 실패 시 원인에 따라 `REJECTED`(검증/Replay 거부), `FAILED`(실행 오류/상충), `CANCELLED`(명시적 취소), `PARTIAL`(불완전 수집 격리)의 명시적 결과로 전이. | 명시적 종결 상태 부여 |
| **BR-LIFE-001-4** | 안전한 지속성 복구 | 시스템 재기동 복구 시 디스크의 지속성 상태를 점검하며, 중단된 미완료 작업(`RESERVED`, `EXECUTING`)을 결코 성공한 것으로 간주하지 않고 `ABORTED_ON_RESTART`로 종결. | 미완료 작업 재사용 차단 |
| **BR-LIFE-001-5** | 재시도(Retry) 식별자 규칙 | 실패하거나 중단된 작업을 재시도할 때는 **반드시 새로운 `operation_id`를 발급**받아야 하며, 원본 작업과의 관계(`retry_of_operation_id`)를 감사 가능하게 유지해야 함. | 구 ID 재사용 시 Replay 거부 |

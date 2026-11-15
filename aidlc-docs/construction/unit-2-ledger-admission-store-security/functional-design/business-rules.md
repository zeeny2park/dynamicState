# Business Rules: Evidence Ledger Admission & Store Security (Unit 2)

> **Unit ID**: `unit-2-ledger-admission-store-security`  
> **Source Files**: [evidence_ledger.py](file:///home/ubuntu/workspace/ut/extractor/evidence_ledger.py), [capture_backend.py](file:///home/ubuntu/workspace/ut/extractor/capture_backend.py)  
> **Related Stories**: `US-TRUST-004`, `US-TRUST-005`, `US-TRUST-006`  
> **Related Requirements**: `FR-TRUST-004`, `FR-TRUST-005`, `FR-TRUST-006`, `NFR-SECURITY-001`, `NFR-RESILIENCY-001`  

---

## 1. 입도 상태별 진단 유입 매트릭스 (Rule BR-ADM-001)

| 입도 상태 (`EvidenceAdmissionState`) | 하류 가설 평가 반영 여부 (`eligible`) | 감사 트레일 보존 여부 | 승격 가능 여부 |
|---|---|---|---|
| `ACCEPTED` | **허용 (True)** | 보존 | 기 승격됨 |
| `REJECTED` | **원천 차단 (False)** | 보존 (실패 사유 필수) | 불가 (영구 거부) |
| `QUARANTINED` | **원천 차단 (False)** | 보존 (격리 사유 필수) | 가능 (결손 정보 보완 시) |
| `NOT_COVERED` | **원천 차단 (False)** | 보존 | 가능 (사후 attestation 시) |
| `PARTIAL` | **원천 차단 (False)** | 보존 | 가능 (잔여 속성 검증 시) |

- **규칙 1.1 (Fail-Closed Default)**: `admission_state`가 명시적으로 `ACCEPTED`가 아닌 모든 증거는 `get_eligible_evidence()` 호출 결과에서 완전히 제외된다.
- **규칙 1.2 (Audit Immutability)**: `REJECTED` 또는 `QUARANTINED` 증거라도 Ledger에서 임의 삭제(Drop)되지 않으며, `get_audit_trail()`을 통해 검증 실패 사유와 함께 감사 추적이 가능해야 한다.

---

## 2. 파일시스템 보안 규칙 (Rule BR-SEC-001 ~ BR-SEC-004)

- **규칙 2.1 (소유자 UID 검증 - BR-SEC-001)**:
  `DurableTrustStore`는 파일 또는 디렉터리 접근 전 `os.lstat()`을 통해 소유자 `st_uid`가 현재 프로세스 실행자의 `os.getuid()`와 일치하는지 검증한다. 불일치 시 `SecurityViolationError`를 발생시키며 즉시 작업을 중단한다.
- **규칙 2.2 (권한 모드 제약 - BR-SEC-002)**:
  영수증 파일의 권한은 `0600`(소유자 읽기/쓰기 전용), 저장소 디렉터리는 `0700`(소유자 읽기/쓰기/실행 전용)으로 제한한다. 그룹 또는 타인(group/others)에게 읽기/쓰기/실행 권한이 부여된 경우 즉시 교정(`chmod`)하거나 예외를 발생시킨다.
- **규칙 2.3 (심볼릭링크 금지 - BR-SEC-003)**:
  `DurableTrustStore` 경로가 심볼릭링크이거나, 경로 중간에 심볼릭링크가 포함되어 있는 경우 `SecurityViolationError`를 발생시키고 실행을 거부한다. 파일 오픈 시 `os.O_NOFOLLOW` 플래그를 사용하여 링크 추적 공격을 방어한다.
- **규칙 2.4 (특수 파일 거부 - BR-SEC-004)**:
  FIFO(파이프), 소켓, 블록 디바이스, 캐릭터 디바이스 등 일반 파일(`S_ISREG`) 및 일반 디렉터리(`S_ISDIR`)가 아닌 파일 객체에 대한 저장을 엄격히 차단한다.

---

## 3. 원자적 영속화 및 복구 규칙 (Rule BR-RES-001 ~ BR-RES-003)

- **규칙 3.1 (Atomic 4-Step Pipeline - BR-RES-001)**:
  데이터 저장은 반드시 `[동일 파일시스템 임시 파일 작성] -> [fsync(file_fd)] -> [os.replace] -> [fsync(dir_fd)]`의 4단계를 완료해야 한다.
- **규칙 3.2 (Stale 임시 파일 수거 - BR-RES-002)**:
  `DurableTrustStore.load()` 또는 초기화 시 대상 디렉터리 내 `.trust_tmp_*` 파일들을 식별하고, 비정상 종료로 방치된 임시 파일을 자동 정리한다.
- **규칙 3.3 (부분 쓰기 방지 - BR-RES-003)**:
  쓰기 도중 크래시가 발생하더라도 대상 파일은 이전의 온전한 상태를 유지해야 하며, 불완전하게 기록된 데이터가 주 영수증 파일에 덮어써지지 않아야 한다.

---

## 4. 출처 메타데이터 및 계통 규칙 (Rule BR-PROV-001 ~ BR-PROV-003)

- **규칙 4.1 (Mandatory Provenance Fields - BR-PROV-001)**:
  권위 있는 증거(`ACCEPTED`)로 입도하기 위해서는 다음 7개 출처 필드가 필수적으로 존재해야 한다:
  1. `operation_id`: 유효한 형식(`validate_operation_id`)을 만족하는 연산 식별자
  2. `target_identity`: 대상 프로세스 식별 정보
  3. `boot_id`: 호스트 부팅 고유 식별자
  4. `pid`: 타깃 프로세스 ID
  5. `process_start_time`: 타깃 프로세스 시작 시각
  6. `build_id`: 수집기 바이너리/패키지 빌드 식별자
  7. `parent_evidence_refs`: 부모 증거 참조 목록 (루트 증거인 경우 빈 리스트)
- **규칙 4.2 (Dangling Reference Quarantine - BR-PROV-002)**:
  `parent_evidence_refs`에 명시된 부모 증거 ID가 현재 Ledger에 존재하지 않거나 무효한 경우, 해당 증거는 `ACCEPTED`가 될 수 없으며 `admission_state = QUARANTINED`, `admission_reason = "Dangling parent evidence reference: ..."`로 격리된다.

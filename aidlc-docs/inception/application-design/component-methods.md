# 컴포넌트 메서드 명세서 (Component Methods Specification)

## 1. `OperationIdentityHelper` & `Attestation` (`extractor/capture_backend.py`)

### 1.1 `validate_operation_id(operation_id: Any) -> str`
- **목적**: durable Attestation 상태를 소비하기 전에 operation identifier의 유효성을 사전 검증한다.
- **입력**: `operation_id` (Any)
- **출력**: 유효성이 검증된 문자열 `operation_id`
- **동작**:
  - 문자열 타입, 최소/최대 길이(예: 8~128자), 허용 문자셋(영숫자, 하이픈, 언더스코어) 검증.
  - 비어 있거나 부적절한 형식이면 즉시 `InvalidOperationIdError` 예외 발생 (fail-closed).

### 1.2 `build_canonical_replay_identity(operation_id: str, target: Any, request_params: Optional[Dict[str, Any]] = None) -> CanonicalReplayIdentity`
- **목적**: 타깃 식별자와 작업 파라미터를 결합한 정규화된 Replay 방어 Identity 객체를 생성한다.
- **입력**: `operation_id` (str), `target` (TargetSpec 또는 dict), `request_params` (dict, optional)
- **출력**: `CanonicalReplayIdentity` (frozen dataclass)
- **동작**:
  - `host_identity`, `boot_id`, `pid`, `process_start_time`, `target_identity`, `build_id`, `normalized_params`를 추출하여 정규화 정렬.
  - 필수 필드 누락 시 `IncompleteIdentityError` 발생.

### 1.3 `update_metadata_monotonic(existing_meta: Dict[str, Any], incoming_meta: Optional[Dict[str, Any]]) -> Dict[str, Any]`
- **목적**: 기존 identity를 빈 metadata로 덮어쓰지 않고 단조성을 보장하며 충돌을 감지한다.
- **입력**: `existing_meta` (dict), `incoming_meta` (dict, optional)
- **출력**: 갱신된 메타데이터 dict
- **동작**:
  - `incoming_meta`가 비어 있거나 None이면 `existing_meta`를 그대로 반환.
  - 기존의 필수 identity 필드(Build ID, host, pid)와 상충하는 값이 들어오면 `IdentityConflictError` 발생 및 이벤트 기록.

---

## 2. `DurableTrustStore` (`extractor/capture_backend.py`)

### 2.1 `atomic_write_secure(dest_path: str, data: bytes, is_sensitive: bool = True) -> None`
- **목적**: 4단계 POSIX 원자적 쓰기 파이프라인으로 안전한 파일 영속화를 수행한다.
- **입력**: `dest_path` (str), `data` (bytes), `is_sensitive` (bool, 기본 True)
- **동작**:
  1. `dest_path`의 상위 디렉터리 존재 및 권한(0700) 검증.
  2. 대상과 동일 디렉터리 내에 `tempfile.NamedTemporaryFile(dir=parent_dir, delete=False)`로 임시 파일 생성.
  3. `os.chmod(temp_file.fileno(), 0o600)` 적용.
  4. 데이터 기록 후 `temp_file.flush(); os.fsync(temp_file.fileno()); temp_file.close()`.
  5. `os.replace(temp_path, dest_path)`로 원자적 교체.
  6. 상위 디렉터리 fd를 열어 `os.fsync(dir_fd)` 수행.
  7. 실패 시(예외 발생) 미완료 임시 파일을 안전하게 삭제(unlink).

### 2.2 `verify_filesystem_security(file_path: str) -> None`
- **목적**: 파일의 소유자 UID, 권한(0600), 심볼릭 링크 여부를 검증한다.
- **입력**: `file_path` (str)
- **동작**:
  - `os.path.islink(file_path)`인 경우 `SecurityViolationError` 발생 (심볼릭링크 거부).
  - `os.stat`를 통해 파일 모드가 0600보다 허용적이지 않은지, 소유자 UID가 현재 프로세스 UID와 일치하는지 확인. 불일치 시 거부.

---

## 3. `EvidenceLedger` (`extractor/evidence_ledger.py`)

### 3.1 `admit_evidence(item: RawEvidence, validation_result: ValidationResult) -> AdmissionState`
- **목적**: 원시 수집 증거의 무결성을 검증하고 5단계 입도 상태를 부여한다.
- **입력**: `item` (RawEvidence), `validation_result` (ValidationResult)
- **출력**: `AdmissionState` (`ACCEPTED`, `REJECTED`, `QUARANTINED`, `NOT_COVERED`, `PARTIAL`)
- **동작**:
  - 필수 출처 메타데이터, 타임스탬프, 무결성 해시가 유효하면 `ACCEPTED`.
  - 검증 실패 시 사유와 함께 `REJECTED` 또는 `QUARANTINED` 부여.

### 3.2 `get_eligible_evidence() -> List[AuthoritativeEvidence]`
- **목적**: 하류 진단 파이프라인(가설 평가, 엔진, 판정 집계)에 오직 `ACCEPTED` 증거만을 제공한다.
- **출력**: 입도 검증을 통과한 `AuthoritativeEvidence` 리스트
- **동작**:
  - `ACCEPTED` 상태가 아닌 증거 항목을 인터페이스 수준에서 완전히 배제하여 반환.

### 3.3 `get_audit_trail() -> List[AuditEvidenceRecord]`
- **목적**: 감사 및 포렌식 전용으로 `REJECTED`, `QUARANTINED`를 포함한 전체 증거 이력을 반환한다.
- **출력**: 감사용 증거 레코드 리스트

---

## 4. `ProcessExplainer` (`extractor/process_explainer.py`)

### 4.1 `explain_process_behavior(result: DiagnoseResult, lang: str = "ko") -> ProcessExplanation`
- **목적**: 결정론적 `DiagnoseResult`를 변경하지 않고 사람이 읽기 쉬운 자연어 해설을 생성한다.
- **입력**: `result` (`DiagnoseResult`), `lang` (str, "ko" 또는 "en")
- **출력**: `ProcessExplanation` (summary, narrative, evidence_refs, recommendations)
- **동작**:
  - 입력받은 `result`에 대한 방어적 복사(deepcopy)를 수행하여 불변성 보장.
  - 해설 내 모든 주장이 `result.findings` 및 `result.checks_run`에 존재하는 ID만을 참조하도록 검증.
  - LLM 호출 실패 시에도 기본 템플릿 기반 폴백 해설을 반환하여 진단 전체 실패를 방지.

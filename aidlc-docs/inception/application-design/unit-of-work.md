# 작업 단위 명세서 (Unit of Work Specification)

> **프로젝트 유형**: Brownfield Monolith  
> **분해 원칙**: P0 신뢰 폐쇄 및 회귀 방지 중심의 순차 TDD(Test-First Development) 단위 분해  
> **총 작업 단위 수**: 7개

---

## 1. Unit 1: Operation Identity & Replay Protection

- **식별자 (Unit ID)**: `unit-1-operation-replay-identity`
- **코드 위치 (Code Location)**: `extractor/capture_backend.py`
- **테스트 파일 (Test File)**:
  - `tests/test_trust_boundary_operation_id.py` (신규 선행 TDD)
  - `tests/test_trust_boundary_replay_identity.py` (신규 선행 TDD)
  - `tests/test_trust_boundary_metadata_conflict.py` (신규 선행 TDD)
- **주요 책임**:
  - `FR-TRUST-001`: durable Attestation 소비 시점 전 `operation_id` 사전 유효성 검증 루틴 강제.
  - `FR-TRUST-002`: `host_identity`, `boot_id`, `pid`, `process_start_time`, `target_identity`, `build_id`, `normalized_parameters`를 결합한 완전한 Canonical Replay Identity 정규화 직렬화.
  - `FR-TRUST-003`: 빈 메타데이터에 의한 기존 identity 덮어쓰기 방지 및 'Identity Conflict' 감지/격리.
  - `FR-TRUST-007`: `CREATED` → `VALIDATED` → `RESERVED` → `EXECUTING` → `COMMITTED` 생명주기 유효 전이 강제.
- **포함 스토리**: `US-TRUST-001`, `US-TRUST-002`, `US-TRUST-003`, `US-TRUST-007`
- **선행 조건**: 없음 (독립 시작 가능)
- **완료 기준 (Exit Criteria)**:
  - Operation ID 사전 검증 실패 시 durable 상태 소비 차단 회귀 테스트 PASS.
  - PID 재사용(PID reuse) 환경에서 boot_id/start_time 불일치 시 replay 거부 회귀 테스트 PASS.
  - 빈 metadata 주입 시 기존 Build ID 보존 회귀 테스트 PASS.

---

## 2. Unit 2: Evidence Ledger Admission & Store Security

- **식별자 (Unit ID)**: `unit-2-ledger-admission-store-security`
- **코드 위치 (Code Location)**: `extractor/evidence_ledger.py`, `extractor/capture_backend.py` (DurableTrustStore)
- **테스트 파일 (Test File)**:
  - `tests/test_trust_boundary_ledger_admission.py` (신규 선행 TDD)
  - `tests/test_trust_boundary_store_security.py` (신규 선행 TDD)
  - `tests/test_trust_boundary_provenance.py` (신규 선행 TDD)
- **주요 책임**:
  - `FR-TRUST-004`: 증거별 5단계 입도 상태 머신(`ACCEPTED`, `REJECTED`, `QUARANTINED`, `NOT_COVERED`, `PARTIAL`) 관리.
  - `FR-TRUST-004`: `get_eligible_evidence()` 인터페이스 수준에서 오직 `ACCEPTED` 증거만 노출하여 하류 가설 평가 및 판정 유입 원천 차단.
  - `FR-TRUST-005` & `NFR-SECURITY-001`: 지속성 TrustStore 파일 `0600`/디렉터리 `0700` 권한 강제, 소유자 UID 검증, 심볼릭링크 거부.
  - `FR-TRUST-005` & `NFR-RESILIENCY-001`: 동일 디렉터리 임시 파일 작성 → `fsync` → `os.replace` 원자적 교체 → 부모 디렉터리 `fsync` 4단계 파이프라인.
  - `FR-TRUST-006`: 증거 항목별 필수 출처 메타데이터 및 부모 참조 계통 링크 보존.
- **포함 스토리**: `US-TRUST-004`, `US-TRUST-005`, `US-TRUST-006`
- **선행 조건**: `unit-1-operation-replay-identity` (Operation ID 및 Replay Identity 계약)
- **완료 기준 (Exit Criteria)**:
  - `REJECTED`/`QUARANTINED` 증거가 `get_eligible_evidence()`에 포함되지 않음을 입증하는 테스트 PASS.
  - 심볼릭링크 경로 접근 거부 및 `0600` 권한 검증 테스트 PASS.
  - 원자적 교체 중단/크래시 시 손상된 부분 파일이 영수증 저장소에 남지 않음을 입증하는 테스트 PASS.

---

## 3. Unit 3: Explanation Layer Immutability & Provenance Traceability

- **식별자 (Unit ID)**: `unit-3-explanation-provenance`
- **코드 위치 (Code Location)**: `extractor/process_explainer.py`, `scripts/mcp_server.py`
- **테스트 파일 (Test File)**:
  - `tests/test_process_explainer.py` (기존 및 확장)
  - `tests/test_mcp_explain_tool.py` (신규)
- **주요 책임**:
  - `FR-EXPLAIN-001`: `runtime_explain_process_behavior` 호출 시 `DiagnoseResult`, `Evidence`, `verdict`의 방어적 복사를 통한 완전한 불변성(immutability) 보장.
  - 해설 내 모든 주장이 실제 증거 ID만을 참조하도록 검증하고 LLM 실패 시 기본 템플릿 폴백 제공.
  - `FR-MCP-001 ~ 003`: MCP 도구 계약 및 구조화된 결과 출력 일관성 유지.
- **포함 스토리**: `US-EXPLAIN-001`
- **선행 조건**: `unit-2-ledger-admission-store-security`
- **완료 기준 (Exit Criteria)**:
  - 해설 계층 실행 전후 `DiagnoseResult` 원본 객체 해시 및 속성 불변 검증 테스트 PASS.
  - MCP 인터페이스를 통한 해설 요청 및 증거 참조 추적성 검증 PASS.

---

## 4. Unit 4: PBT Invariants & Dual Clean Benchmark Verification

- **식별자 (Unit ID)**: `unit-4-pbt-dual-benchmark`
- **코드 위치 (Code Location)**: `tests/`, `benchmarks/diagnosis_accuracy/`
- **테스트 파일 (Test File)**:
  - `tests/test_trust_boundary_pbt.py` (Hypothesis 기반 PBT)
  - `benchmarks/diagnosis_accuracy/run_benchmark.py`
- **주요 책임**:
  - `NFR-PBT-001`: Canonical Identity 직렬화, metadata 단조성, 입도 상태 전이의 핵심 불변식에 대한 Hypothesis 속성 기반 테스트 구축 (deterministic seed 지원).
  - `FR-BENCH-001 & 002`: git dirty 상태 없는 clean commit 기준으로 aarch64 개발 호스트 및 x86_64 CI 환경에서 동일 데이터셋 기반 clean benchmark 산출물 생성.
  - `NFR-PROCESS-001 & 002`: 요구사항-코드-테스트 1:1 추적성 최종 점검 및 `GO` / `NO-GO` / `PARTIAL` 판정 체계 완결.
- **포함 스토리**: `US-BENCH-001`, `US-PROCESS-001`
- **선행 조건**: `unit-1`, `unit-2`, `unit-3` 완결
- **완료 기준 (Exit Criteria)**:
  - Hypothesis PBT 스위트 100회 이상 무작위 입력 검증 PASS.
  - aarch64 및 x86_64 clean benchmark 실행 완료 및 메타데이터(commit SHA, dirty=false, 반복 횟수) JSON 보관.
  - 최종 P0 Trust Closure 완결 보고서 작성 및 `GO` 판정 선언.

---

## 5. Unit 5: Diagnosis Accuracy & Hypothesis Budgeting

- **식별자 (Unit ID)**: `unit-5-diagnosis-accuracy-budget`
- **코드 위치 (Code Location)**: `extractor/static_location_candidates.py`, `extractor/competing_hypotheses.py`, `extractor/check_budget.py`, `extractor/healthy_verdict.py`
- **테스트 파일 (Test File)**:
  - `tests/test_static_location_candidates.py`
  - `tests/test_static_location_candidates_general.py`
  - `tests/test_healthy_verdict.py`
  - `tests/test_budget_stop_keeps_findings.py`
- **주요 책임**:
  - `FR-DIAG-001`: DWARF/소스 기반 정적 위치 후보 순위화 결정론적 보장, 확인된 원인과 후보 구분.
  - `FR-DIAG-002`: 가설 모델 모순 증거의 명시적 분리, 거부된 증거 배제, 재현 가능한 가설 순위화.
  - `FR-DIAG-003`: 적응형 관측 예산 reservation/consumption 감사성, 불필요 중복 관측 회피.
  - `FR-DIAG-004`: 증거 부족 시 확정 판정 회피 및 `INCONCLUSIVE`/`not_covered` 기권 일관성.
- **포함 스토리**: `US-DIAG-001`, `US-DIAG-002`, `US-DIAG-003`, `US-DIAG-004`
- **선행 조건**: `unit-2-ledger-admission-store-security` (Evidence Ledger 관문)
- **완료 기준 (Exit Criteria)**:
  - 정적 위치 후보 순위화 및 정직성 규칙 검증 테스트 PASS.
  - 건강 판정 및 관측 예산 제약 검증 테스트 PASS.

---

## 6. Unit 6: C++ STL Decoders & Cross-ABI Tracing

- **식별자 (Unit ID)**: `unit-6-cpp-abi-tracing`
- **코드 위치 (Code Location)**: `extractor/cpp_containers.py`, `extractor/target_abi.py`, `extractor/tracing_mode.py`
- **테스트 파일 (Test File)**:
  - `tests/test_cpp_e2e_investigation.py`
  - `tests/test_ebpf_integration.py`
- **주요 책임**:
  - `FR-CPP-001`: libstdc++ 컨테이너(vector, map 등) 지원 ABI 검증, 비정상 메모리 fail-safe 방어.
  - `FR-CPP-002`: x86_64 및 AArch64 크로스 아키텍처 진단 일치성 검증.
  - `FR-TRACE-001 & 002`: eBPF attach/detach 수명주기, 이벤트 손실 명시, 선택적 opt-in 유지.
- **포함 스토리**: `US-CPP-001`, `US-TRACE-001`
- **선행 조건**: `unit-1`, `unit-2`
- **완료 기준 (Exit Criteria)**:
  - C++ STL 디코딩 E2E 테스트 PASS.
  - eBPF 수명주기 및 격리 테스트 PASS.

---

## 7. Unit 7: Report Equivalence, MCP Contracts & Clean Benchmark

- **식별자 (Unit ID)**: `unit-7-report-mcp-benchmark`
- **코드 위치 (Code Location)**: `extractor/report_visuals.py`, `extractor/report_story.py`, `scripts/mcp_server.py`, `benchmarks/diagnosis_accuracy/run_benchmark.py`
- **테스트 파일 (Test File)**:
  - `tests/test_report_visuals.py`
  - `tests/test_report_story.py`
  - `tests/test_mcp_runtime_diagnostics.py`
  - `tests/test_capture_benchmark.py`
- **주요 책임**:
  - `FR-REPORT-001 ~ 003`: HTML과 Markdown 리포트의 동일 결론 유지, 출처 링크 보존, 리포트 재현성.
  - `FR-MCP-001 ~ 003`: MCP 도구 계약 및 스키마 입력 검증, 코어 진단 파이프라인 일치성.
  - `FR-BENCH-001 ~ 003`: aarch64 + x86_64 이중 clean benchmark 및 정확도 다차원 지표 보고.
- **포함 스토리**: `US-REPORT-001`, `US-MCP-001`, `US-BENCH-002`
- **선행 조건**: `unit-5`, `unit-6`
- **완료 기준 (Exit Criteria)**:
  - 리포트 시각화 및 스토리 일관성 테스트 PASS.
  - MCP 진단 도구 계약 테스트 PASS.
  - clean 벤치마크 평가 정상 완료.

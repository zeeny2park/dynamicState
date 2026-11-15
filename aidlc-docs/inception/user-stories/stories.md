# 사용자 스토리 명세서 (User Stories Specification)

> **요구사항 매핑**: `aidlc-docs/inception/requirements/requirements.md`  
> **페르소나 매핑**: `aidlc-docs/inception/user-stories/personas.md`  
> **우선순위 체계**: Phase 1 최우선 완결 대상인 **P0 Trust Closure (Epic 1 & Epic 2)** 7개 스토리 중심 계층형 구성

---

## 1. Epic 1: Operation Identity & Replay Protection (P0 Trust)

### [US-TRUST-001] Operation ID 사전 검증
- **사용자 서술 (User Story)**:
  - **As an** MCP AI 에이전트 또는 시스템 엔지니어,
  - **I want** 모든 런타임 수집/진단 작업의 Operation ID가 durable Attestation 상태를 소비하기 전에 엄격히 검증되기를 원하며,
  - **So that** 잘못되거나 변조된 작업 요청으로 인해 지속성 영수증 상태가 오염되거나 부분 커밋되는 일이 없도록 하기 위함이다.
- **연관 요구사항**: FR-TRUST-001, REQ-TRUST-001
- **주요 페르소나**: AI Agent, Jin-woo (보안 감사자)
- **인수 조건 (Acceptance Criteria, 체크리스트)**:
  - [ ] Operation ID의 형식, 길이, 의미적 유효성 검증 루틴이 durable Attestation 소비 시점보다 반드시 앞선 순서로 실행된다.
  - [ ] 유효하지 않거나 비어 있는 Operation ID가 입력되면 durable 상태를 소비하지 않고 즉시 fail-closed로 거부된다.
  - [ ] 검증 실패 시 영수증 번들이나 트러스트 상태에 어떠한 부분 커밋이나 잔여 아티팩트도 남기지 않는다.
  - [ ] 동시 다발적인 비정상 요청이 발생하더라도 레이스 컨디션으로 identity 검증을 우회할 수 없다.
  - [ ] 독립된 TDD 회귀 테스트(`tests/test_trust_boundary_operation_id.py`)에서 결함 재현 실패 후 수정으로 통과함을 입증한다.

---

### [US-TRUST-002] Replay 방어 Canonical Identity 완전성
- **사용자 서술 (User Story)**:
  - **As a** 시스템 엔지니어 (Min-soo),
  - **I want** Replay 방어 체계가 타깃의 호스트, 부팅 ID, PID, 시작 시각 등을 포함하는 완전한 Canonical Identity를 비교하도록 하여,
  - **So that** 동일 머신에서 PID가 재사용(PID reuse)되거나 이전 세션의 요청이 재전송되더라도 다른 타깃이나 새 프로세스와 혼동되지 않도록 하기 위함이다.
- **연관 요구사항**: FR-TRUST-002, REQ-TRUST-002, NFR-PBT-001
- **주요 페르소나**: Min-soo, Jin-woo
- **인수 조건 (Acceptance Criteria, 체크리스트)**:
  - [ ] Canonical Identity 직렬화 시 필수 필드(`operation_id`, `host_identity`, `boot_id`, `pid`, `process_start_time`, `target_identity`, `build_id`, `normalized_parameters`, `schema_version`)가 완전하게 포함된다.
  - [ ] PID 단독에 의존한 비교를 차단하고, boot_id 또는 process_start_time이 일치하지 않는 PID 재사용 상황을 다른 identity로 판정하여 배제한다.
  - [ ] 동일한 Operation ID를 다른 타깃 머신이나 다른 scope에서 재사용하려 할 경우 replay violation으로 즉시 거부된다.
  - [ ] 필수 identity 필드가 누락된 직렬화 요청은 fail-closed 원칙에 따라 거부된다.
  - [ ] 직렬화 순서 및 정규화 불변식을 검증하는 속성 기반 테스트(PBT, Hypothesis)가 통과한다.

---

### [US-TRUST-003] Metadata 단조성 및 Identity 충돌 방어
- **사용자 서술 (User Story)**:
  - **As a** 보안 감사자 (Jin-woo),
  - **I want** 후속 관측이나 부분 캡처에서 수집된 빈 metadata가 기존에 이미 검증된 프로세스 identity를 덮어쓰지 못하게 하고 충돌을 명시적으로 기록하기를 원하며,
  - **So that** 신뢰성 있는 빌드 ID나 타깃 정보가 조용히 지워지거나 변조되지 않도록 하기 위함이다.
- **연관 요구사항**: FR-TRUST-003, REQ-TRUST-003
- **주요 페르소나**: Jin-woo, Min-soo
- **인수 조건 (Acceptance Criteria, 체크리스트)**:
  - [ ] 수집된 metadata가 비어 있거나 None인 경우, 기존에 확립된 유효한 identity 필드가 그대로 보존된다.
  - [ ] 기존 identity와 새로 수집된 identity 간에 Build ID나 타깃 정보 불일치가 발생할 경우 'Identity Conflict' 이벤트로 명시적 기록된다.
  - [ ] 해결되지 않은 Identity Conflict와 연관된 증거 데이터는 권위 있는 증거(Authoritative Evidence)로 승격되지 못하고 격리된다.
  - [ ] 동일한 metadata의 반복 수신은 단조성 원칙에 따라 안전하게 수용된다.

---

## 2. Epic 2: Evidence Admission & Store Security (P0 Security & Provenance)

### [US-TRUST-004] Evidence Ledger 엄격 입도(Admission) 경계 및 거부 증거 차단
- **사용자 서술 (User Story)**:
  - **As an** MCP AI 에이전트,
  - **I want** 증거 원장(Evidence Ledger)이 엄격한 입도 상태 머신을 강제하여 무결성 검증에 실패하거나 거부된 증거를 하류 가설 평가에 절대 유입시키지 않기를 원하며,
  - **So that** 오염된 메모리 슬라이스나 미인증 증거로 인해 거짓 결함 판정이나 잘못된 근본 원인이 도출되지 않도록 하기 위함이다.
- **연관 요구사항**: FR-TRUST-004, REQ-TRUST-004, NFR-SECURITY-001
- **주요 페르소나**: AI Agent, Min-soo
- **인수 조건 (Acceptance Criteria, 체크리스트)**:
  - [ ] 모든 증거 항목은 `ACCEPTED`, `REJECTED`, `QUARANTINED`, `NOT_COVERED`, `PARTIAL` 중 하나의 명시적인 입도 상태를 가진다.
  - [ ] `REJECTED` 상태의 증거는 가설 점수 계산(Hypothesis scoring), 랭킹, 진단 결론(Verdict) 생성 파이프라인에서 100% 원천 차단된다.
  - [ ] `QUARANTINED` 증거는 사후 포렌식/감사용으로만 보존되며, 결함 판정의 증거로는 절대 승격되지 않는다.
  - [ ] `NOT_COVERED`와 `REJECTED`는 의미적으로 완전히 분리되어 보고서 및 API 응답에 표시된다.
  - [ ] TDD 회귀 테스트에서 입도 실패 증거가 주입되었을 때 최종 verdict와 finding에 반영되지 않음을 입증한다.

---

### [US-TRUST-005] TrustStore 파일시스템 보안 및 권한 강제
- **사용자 서술 (User Story)**:
  - **As a** 품질 및 보안 감사자 (Jin-woo),
  - **I want** 지속성 TrustStore 및 Lock 파일시스템 접근 시 파일 권한, 소유자 UID, 파일 타입을 검증하고 심볼릭링크 공격을 차단하기를 원하며,
  - **So that** 로컬 공격자나 비인가 프로세스가 진단 증거를 변조하거나 TOCTOU 레이스 컨디션을 악용하지 못하도록 하기 위함이다.
- **연관 요구사항**: FR-TRUST-005, REQ-TRUST-005, NFR-SECURITY-001
- **주요 페르소나**: Jin-woo
- **인수 조건 (Acceptance Criteria, 체크리스트)**:
  - [ ] 민감 파일에 대해 `0600`, 디렉터리에 대해 `0700` 권한 정책이 적용되고, 소유자 UID 일치 여부를 검증한다.
  - [ ] 심볼릭링크 또는 비정상 파일 타입(소켓, 파이프 등)으로 연결된 경로 접근 시도시 즉시 차단(fail-closed)된다.
  - [ ] Lock 파일 생성 및 획득 시 안전한 플래그(`O_CREAT | O_EXCL`)를 사용하여 TOCTOU 레이스를 방어한다.
  - [ ] 원자적 파일 쓰기(임시 파일 작성 후 원자적 rename)를 통해 쓰기 도중 프로세스가 비정상 종료되어도 손상된 부분 파일이 신뢰되지 않는다.

---

### [US-TRUST-006] 권위 있는 증거의 Provenance 계통 보존
- **사용자 서술 (User Story)**:
  - **As a** 시스템 엔지니어 (Min-soo),
  - **I want** 최종 진단 보고서의 모든 권위 있는 결론이 수집 시점의 원본 증거 ID 및 세션 메타데이터와 끊김 없이 연결되기를 원하며,
  - **So that** 원인 분석 결과의 타당성을 실제 메모리 주소와 수집 시각 수준에서 역추적하고 감사할 수 있도록 하기 위함이다.
- **연관 요구사항**: FR-TRUST-006, FR-REPORT-002
- **주요 페르소나**: Min-soo, Jin-woo
- **인수 조건 (Acceptance Criteria, 체크리스트)**:
  - [ ] 모든 권위 있는 증거 항목에 `operation_id`, `target_identity`, `boot_id`, `pid`, `process_start_time`, `build_id`, `timestamp`, `parent_evidence_refs`가 유지된다.
  - [ ] 1차 수집 증거로부터 파생된 상위 결론이나 집계 증거는 원본 증거 참조(parent references)를 온전히 보존한다.
  - [ ] 필수 출처 메타데이터가 누락되거나 손상된 경우 권위 있는 증거로의 승격이 차단된다.
  - [ ] 끊어지거나 존재하지 않는 증거 참조(dangling reference)가 발생할 경우 검증 단계에서 즉시 탐지된다.

---

### [US-TRUST-007] Operation 생명주기 전이 및 원자적 복구
- **사용자 서술 (User Story)**:
  - **As an** MCP AI 에이전트,
  - **I want** 진단 및 수집 작업의 상태 전이가 명시된 생명주기 규칙에 따라 엄격히 통제되고 비정상 중단 후에도 일관되게 복구되기를 원하며,
  - **So that** 네트워크 단절이나 프로세스 크래시 후 재시도하더라도 중복 작업이나 불완전한 커밋 상태가 발생하지 않도록 하기 위함이다.
- **연관 요구사항**: FR-TRUST-007, NFR-RESILIENCY-001
- **주요 페르소나**: AI Agent, Jin-woo
- **인수 조건 (Acceptance Criteria, 체크리스트)**:
  - [ ] `CREATED` → `VALIDATED` → `RESERVED` → `EXECUTING` → `COMMITTED` 순서의 유효한 전이만 허용되며, 비정상 역방향 전이는 거부된다.
  - [ ] 작업 도중 실패 또는 취소 시 `REJECTED`, `FAILED`, `CANCELLED` 상태로 명확히 전이되고 부분 실행(PARTIAL) 여부가 기록된다.
  - [ ] 시스템 재시작 또는 충돌 복구 시 지속성 상태를 점검하여 완료되지 않은 불완전 상태를 커밋된 것으로 잘못 인식하지 않는다.
  - [ ] 재시도 작업 시 이전의 replay 방어 규칙이 정상 유지되어 이중 실행을 차단한다.

---

## 3. Epic 3: Deterministic Explanation & Verification Integrity (P1 Foundations)

### [US-EXPLAIN-001] 불변 DiagnoseResult 기반 읽기 전용 자연어 해설
- **사용자 서술 (User Story)**:
  - **As an** 임베디드 C/C++ 시스템 엔지니어 (Min-soo),
  - **I want** `runtime_explain_process_behavior`가 결정론적 `DiagnoseResult` 원본을 일체 변경하지 않는 읽기 전용 해설 계층으로 동작하기를 원하며,
  - **So that** LLM이 진단 판정이나 증거 점수를 임의로 왜곡하거나 환각을 일으킬 위험 없이 안전하게 자연어 요약을 얻을 수 있도록 하기 위함이다.
- **연관 요구사항**: FR-EXPLAIN-001, REQ-MCP-002, REQ-REPORT-001
- **주요 페르소나**: Min-soo, AI Agent
- **인수 조건 (Acceptance Criteria, 체크리스트)**:
  - [ ] `process_explainer.py`의 해설 함수 호출 전후로 `DiagnoseResult`, `Evidence`, `verdict`, `confidence` 데이터가 완전히 불변(immutable)임을 보장한다.
  - [ ] 해설 계층에서 생성된 모든 사실적 주장은 `DiagnoseResult` 내의 실제 증거 ID 및 필드만을 참조해야 한다.
  - [ ] LLM 서비스 오류나 응답 실패가 발생하더라도 코어 `diagnose()` 결과의 유효성에는 어떠한 영향도 주지 않는다.

---

### [US-BENCH-001] aarch64 + x86_64 이중 Clean Benchmark 기준선
- **사용자 서술 (User Story)**:
  - **As a** 품질 및 보안 감사자 (Jin-woo),
  - **I want** 진단 정확도 벤치마크가 dirty working tree가 아닌 깨끗한 커밋 기준으로 aarch64 및 x86_64 양쪽에서 동일 데이터셋으로 실행되기를 원하며,
  - **So that** 11/11 결함 탐지 및 held-out 결함 검증 수치가 과적합이나 환경 의존성 없이 객관적으로 재현 가능함을 신뢰할 수 있도록 하기 위함이다.
- **연관 요구사항**: FR-BENCH-001, FR-BENCH-002, REQ-BENCH-001
- **주요 페르소나**: Jin-woo
- **인수 조건 (Acceptance Criteria, 체크리스트)**:
  - [ ] `git status --porcelain`이 완전히 깨끗한 클린 커밋 상태에서 벤치마크가 실행된다.
  - [ ] 벤치마크 결과 JSON 메타데이터에 commit SHA, dirty state(=false), 실행 환경, 반복 횟수가 정확히 기록된다.
  - [ ] 결함 탐지율(Detection rate), 후보 재현율(Recall), 정확한 위치 특정률(Exact location), 오탐률(False-positive rate)이 분리 측정되어 보고된다.

---

### [US-PROCESS-001] TDD 선행 결함 재현 및 GO/NO-GO 보고 체계
- **사용자 서술 (User Story)**:
  - **As a** 플랫폼 엔지니어 (Jin-woo),
  - **I want** P0의 모든 결함 수정 시 실패하는 재현 단위 테스트를 먼저 작성하고 단계별로 GO / NO-GO / PARTIAL 판정을 명확히 보고하기를 원하며,
  - **So that** 미확인 상태나 미실행 테스트가 PASS로 둔갑하지 않고 결함 해결이 엄격히 검증되도록 하기 위함이다.
- **연관 요구사항**: NFR-PROCESS-001, NFR-PROCESS-002
- **주요 페르소나**: Jin-woo
- **인수 조건 (Acceptance Criteria, 체크리스트)**:
  - [ ] P0의 각 결함(FR-TRUST-001~005)에 대해 독립적인 재현 테스트(`tests/test_trust_boundary_*.py`)를 먼저 작성하여 실패를 확인한 후 패치를 적용한다.
  - [ ] 실행되지 않은 테스트나 실패한 검증 항목을 절대 PASS로 표기하지 않는다.
  - [ ] Phase 0 및 Phase 1 완료 시 정확히 `GO`, `NO-GO`, `PARTIAL` 중 하나로 판정하여 audit.md 및 산출물에 명시한다.
  - [ ] P0 인수 기준이 100% 충족되고 `GO` 판정이 확인되기 전에는 P1 작업을 시작하지 않는다.

---

## 4. 추적성 매트릭스 (Requirements Traceability Matrix)

| 스토리 ID | 요구사항 ID (FR/NFR) | 기존 PRD ID | 담당 컴포넌트 | 검증 테스트 파일 (예정) | 우선순위 |
|---|---|---|---|---|---|
| US-TRUST-001 | FR-TRUST-001 | REQ-TRUST-001 | `capture_backend.py` | `tests/test_trust_boundary_operation_id.py` | P0 (Must) |
| US-TRUST-002 | FR-TRUST-002 | REQ-TRUST-002 | `capture_backend.py` | `tests/test_trust_boundary_replay_identity.py` | P0 (Must) |
| US-TRUST-003 | FR-TRUST-003 | REQ-TRUST-003 | `capture_backend.py` | `tests/test_trust_boundary_metadata_conflict.py` | P0 (Must) |
| US-TRUST-004 | FR-TRUST-004 | REQ-TRUST-004 | `evidence_ledger.py` | `tests/test_trust_boundary_ledger_admission.py` | P0 (Must) |
| US-TRUST-005 | FR-TRUST-005 | REQ-TRUST-005 | `capture_backend.py` | `tests/test_trust_boundary_store_security.py` | P0 (Must) |
| US-TRUST-006 | FR-TRUST-006 | Trust/Provenance | `evidence_ledger.py` | `tests/test_trust_boundary_provenance.py` | P0 (Must) |
| US-TRUST-007 | FR-TRUST-007 | Trust/Lifecycle | `capture_backend.py` | `tests/test_trust_boundary_lifecycle.py` | P0 (Must) |
| US-EXPLAIN-001 | FR-EXPLAIN-001 | REQ-MCP-002, REPORT-001 | `process_explainer.py` | `tests/test_process_explainer.py` | P1 (Should) |
| US-BENCH-001 | FR-BENCH-001 | REQ-BENCH-001 | `benchmarks/` | `benchmarks/diagnosis_accuracy/run_benchmark.py` | P1 (Should) |
| US-PROCESS-001 | NFR-PROCESS-001, 002 | Process/Reporting | 프로젝트 전반 | `aidlc-docs/audit.md`, CI 워크플로 | P0/Process (Must) |

---

### [US-DIAG-001] 진단 정확도 및 가설/예산 무결성 (Phase 2)
- **요구사항 매핑**: `FR-DIAG-001`, `FR-DIAG-002`, `FR-DIAG-003`, `FR-DIAG-004`
- **우선순위**: P1 (Should)
- **주요 대상 파일**:
  - 소스: `extractor/static_location_candidates.py`, `extractor/competing_hypotheses.py`, `extractor/check_budget.py`, `extractor/healthy_verdict.py`
  - 테스트: `tests/test_static_location_candidates.py`, `tests/test_healthy_verdict.py`, `tests/test_budget_stop_keeps_findings.py`

#### 인수 기준 (Acceptance Criteria)
1. **AC-DIAG-01 (정적 위치 후보)**: 정적 위치 후보는 DWARF 및 소스 텍스트를 기반으로 결정론적으로 순위화되며 `CANDIDATE_CAP` 이내로 제한된다.
2. **AC-DIAG-02 (가설 모순 격리)**: 모순된 증거와 거부된 증거는 하류 진단에서 배제되며 재현 가능한 가설 점수를 생성한다.
3. **AC-DIAG-03 (적응형 예산 제어)**: 관측 예산 reservation 및 accounting이 정확히 추적되며 불필요한 중복 관측이 방지된다.
4. **AC-DIAG-04 (판정 기권 일관성)**: 증거가 불충분할 경우 섣부른 확정 판정을 내리지 않고 명시적 `INCONCLUSIVE`/기권 상태를 반환한다.

---

### [US-CPP-001] C++ 컨테이너 ABI 디코딩 및 eBPF Tracing 제어 (Phase 3)
- **요구사항 매핑**: `FR-CPP-001`, `FR-CPP-002`, `FR-TRACE-001`, `FR-TRACE-002`
- **우선순위**: P1 (Should)
- **주요 대상 파일**:
  - 소스: `extractor/cpp_containers.py`, `extractor/target_abi.py`, `extractor/tracing_mode.py`
  - 테스트: `tests/test_cpp_e2e_investigation.py`, `tests/test_ebpf_integration.py`

#### 인수 기준 (Acceptance Criteria)
1. **AC-CPP-01 (C++ STL 디코딩)**: libstdc++ `std::vector`, `std::map`, `std::string` 등의 레이아웃을 정확히 디코딩하고 손상된 포인터 접근 시 안전하게 fail-safe 처리한다.
2. **AC-CPP-02 (크로스 아키텍처 일관성)**: x86_64 및 AArch64 간 동일한 논리적 C++ 구조체 디코딩 결과를 보장한다.
3. **AC-TRACE-01 (eBPF 수명주기)**: eBPF 프로그램의 attach 및 detach가 누수 없이 안전하게 실행되며 이벤트 손실이 명시적으로 보고된다.

---

### [US-REPORT-001] 보고서 완결성, 출처 추적성 및 MCP 계약 일관성 (Phase 5)
- **요구사항 매핑**: `FR-REPORT-001 ~ 003`, `FR-MCP-001 ~ 003`, `FR-BENCH-001 ~ 003`
- **우선순위**: P1 (Should)
- **주요 대상 파일**:
  - 소스: `extractor/report_visuals.py`, `extractor/report_story.py`, `scripts/mcp_server.py`, `benchmarks/diagnosis_accuracy/run_benchmark.py`
  - 테스트: `tests/test_report_visuals.py`, `tests/test_report_story.py`, `tests/test_mcp_runtime_diagnostics.py`, `tests/test_capture_benchmark.py`

#### 인수 기준 (Acceptance Criteria)
1. **AC-REPORT-01 (HTML/Markdown 동등성)**: HTML 리포트와 Markdown 리포트가 동일한 판정, 핵심 증거, 권고 사항을 일관되게 제공한다.
2. **AC-REPORT-02 (출처 링크 완결성)**: 리포트 내 제시된 모든 사실 주장에 대해 원본 증거 레코드로의 링크 및 추적성을 유지한다.
3. **AC-MCP-01 (MCP 스키마 준수)**: 진단 및 프로파일링 도구가 선언된 스키마를 엄격히 준수하며 구조화된 결과를 반환한다.

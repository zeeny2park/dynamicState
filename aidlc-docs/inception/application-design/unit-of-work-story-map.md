# 스토리-작업단위 매핑 명세서 (Unit of Work Story Map)

## 1. 개요
본 문서는 `aidlc-docs/inception/user-stories/stories.md`에 정의된 10개의 사용자 스토리(P0 7건, P1 3건)가 4개의 작업 단위(Unit of Work)에 어떻게 매핑되는지 명시한다. 모든 스토리는 누락 없이 정확히 하나의 주 담당 Unit에 배정된다.

---

## 2. 매핑 테이블

| 스토리 ID | 스토리 명칭 | 담당 작업 단위 (Unit) | 담당 파일 (코드 / 테스트) | 우선순위 |
|---|---|---|---|---|
| **US-TRUST-001** | Operation ID 사전 검증 | `unit-1-operation-replay-identity` | `extractor/capture_backend.py`<br/>`tests/test_trust_boundary_operation_id.py` | P0 (Must) |
| **US-TRUST-002** | Replay 방어 Canonical Identity 완전성 | `unit-1-operation-replay-identity` | `extractor/capture_backend.py`<br/>`tests/test_trust_boundary_replay_identity.py` | P0 (Must) |
| **US-TRUST-003** | Metadata 단조성 및 Identity 충돌 방어 | `unit-1-operation-replay-identity` | `extractor/capture_backend.py`<br/>`tests/test_trust_boundary_metadata_conflict.py` | P0 (Must) |
| **US-TRUST-007** | Operation 생명주기 전이 및 원자적 복구 | `unit-1-operation-replay-identity` | `extractor/capture_backend.py`<br/>`tests/test_trust_boundary_lifecycle.py` | P0 (Must) |
| **US-TRUST-004** | Evidence Ledger 입도 경계 및 거부 증거 차단 | `unit-2-ledger-admission-store-security` | `extractor/evidence_ledger.py`<br/>`tests/test_trust_boundary_ledger_admission.py` | P0 (Must) |
| **US-TRUST-005** | TrustStore 파일시스템 보안 및 권한 강제 | `unit-2-ledger-admission-store-security` | `extractor/capture_backend.py`<br/>`tests/test_trust_boundary_store_security.py` | P0 (Must) |
| **US-TRUST-006** | 권위 있는 증거의 Provenance 계통 보존 | `unit-2-ledger-admission-store-security` | `extractor/evidence_ledger.py`<br/>`tests/test_trust_boundary_provenance.py` | P0 (Must) |
| **US-EXPLAIN-001** | 불변 DiagnoseResult 기반 읽기 전용 자연어 해설 | `unit-3-explanation-provenance` | `extractor/process_explainer.py`<br/>`tests/test_process_explainer.py` | P1 (Should) |
| **US-BENCH-001** | aarch64 + x86_64 이중 Clean Benchmark 기준선 | `unit-4-pbt-dual-benchmark` | `benchmarks/diagnosis_accuracy/`<br/>`benchmarks/run_benchmark.py` | P1 (Should) |
| **US-PROCESS-001** | TDD 선행 결함 재현 및 GO/NO-GO 보고 체계 | `unit-4-pbt-dual-benchmark` | 프로젝트 전반, CI 워크플로, audit.md | P0/Process (Must) |
| **US-DIAG-001** | 진단 정확도 및 가설/예산 무결성 | `unit-5-diagnosis-accuracy-budget` | `extractor/static_location_candidates.py`<br/>`tests/test_static_location_candidates.py` | P1 (Should) |
| **US-CPP-001** | C++ 컨테이너 ABI 디코딩 및 eBPF Tracing 제어 | `unit-6-cpp-abi-tracing` | `extractor/cpp_containers.py`<br/>`tests/test_cpp_e2e_investigation.py` | P1 (Should) |
| **US-REPORT-001** | 보고서 완결성, 출처 추적성 및 MCP 계약 일관성 | `unit-7-report-mcp-benchmark` | `extractor/report_visuals.py`<br/>`tests/test_report_visuals.py` | P1 (Should) |

---

## 3. 매핑 검증 결과
- **총 사용자 스토리 수**: 13개
- **배정된 스토리 수**: 13개
- **누락된 스토리 (Unmapped Stories)**: 0개 (100% 매핑 완료)
- **Unit별 스토리 분포**:
  - `Unit 1`: 4개 스토리 (US-TRUST-001, 002, 003, 007)
  - `Unit 2`: 3개 스토리 (US-TRUST-004, 005, 006)
  - `Unit 3`: 1개 스토리 (US-EXPLAIN-001)
  - `Unit 4`: 2개 스토리 (US-BENCH-001, US-PROCESS-001)
  - `Unit 5`: 1개 스토리 (US-DIAG-001)
  - `Unit 6`: 1개 스토리 (US-CPP-001)
  - `Unit 7`: 1개 스토리 (US-REPORT-001)

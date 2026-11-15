# 작업 단위 계획 (Unit of Work Plan)

## 1. 개요 및 목적
본 문서는 `aidlc-docs/inception/requirements/requirements.md` 및 `aidlc-docs/inception/user-stories/stories.md`에 정의된 P0 신뢰성 요구사항과 P1 기반 요구사항을 관리 가능하고 독립적으로 TDD 검증이 가능한 작업 단위(Unit of Work)로 분해하기 위한 실행 계획이다.

---

## 2. 필수 산출물 및 실행 체크리스트

- [x] **Step 1**: 작업 단위 정의 및 책임 명세서 작성 (`aidlc-docs/inception/application-design/unit-of-work.md`)
  - Unit 1: Operation Identity & Replay Protection (`capture_backend.py`)
  - Unit 2: Evidence Ledger Admission & Store Security (`evidence_ledger.py`, `capture_backend.py`)
  - Unit 3: Explanation Layer Immutability & Provenance Traceability (`process_explainer.py`, `scripts/mcp_server.py`)
  - Unit 4: PBT Invariants & Dual Clean Benchmark Verification (`tests/`, `benchmarks/`)
- [x] **Step 2**: 작업 단위 간 의존성 매트릭스 및 TDD 순서 명세서 작성 (`aidlc-docs/inception/application-design/unit-of-work-dependency.md`)
- [x] **Step 3**: 10개 사용자 스토리(US-TRUST-001~007, US-EXPLAIN-001, US-BENCH-001, US-PROCESS-001)의 Unit 매핑 명세서 작성 (`aidlc-docs/inception/application-design/unit-of-work-story-map.md`)
- [x] **Step 4**: Unit 경계 및 독립 테스트 가능성 검증

---

## 3. 맥락 기반 분해 결정 질문 (Clarification Questions)

### Question 1: 작업 단위(Unit) 분해 구조
P0 7대 요구사항 및 후속 검증 요구사항을 아래와 같이 4개의 응집력 있는 작업 단위로 분해하는 것을 권장합니다:
- **Unit 1: Operation Identity & Replay Protection**: `capture_backend.py` (FR-TRUST-001, 002, 003, 007 / US-TRUST-001, 002, 003, 007)
- **Unit 2: Evidence Ledger Admission & Store Security**: `evidence_ledger.py` 및 `DurableTrustStore` (FR-TRUST-004, 005, 006 / US-TRUST-004, 005, 006)
- **Unit 3: Explanation Layer Immutability & Provenance**: `process_explainer.py` 및 MCP 인터페이스 (FR-EXPLAIN-001 / US-EXPLAIN-001)
- **Unit 4: Verification, PBT & Dual Clean Benchmark**: `tests/`, `benchmarks/` (FR-BENCH-001, NFR-PBT-001, NFR-PROCESS-001, 002 / US-BENCH-001, US-PROCESS-001)

이 4개 Unit 분해 전략으로 진행할까요?

A) **예 — 4개 단위 순차 TDD 분해 (권장)**: 신뢰 경계, 입도/보안, 설명 계층, 벤치마크 검증이 명확히 격리되어 테스트 선행 개발에 최적화됨  
B) **P0 단일 통합 Unit**: Unit 1과 Unit 2를 하나로 묶어 P0 전체를 단일 단위로 구성  
X) Other (please describe after [Answer]: tag below)

[Answer]: A

---

### Question 2: Construction Phase의 Unit 실행 순서 (Execution Sequencing)
Construction Phase(기능 설계 → 코드 생성 → 빌드/테스트) 진행 시, Unit 1부터 순차적으로 TDD 회귀 테스트 작성 및 수정을 완료한 후 다음 Unit으로 전진하는 방식을 적용할까요?

A) **순차 진행 (Sequential TDD, 권장)**: Unit 1 완결 → Unit 2 완결 → Unit 3 완결 → Unit 4 전체 PBT/벤치마크 검증 (선행 의존성 충족 보장)  
B) **배치 진행 (Batch)**: 전체 Unit의 설계를 한 번에 마치고 코드를 일괄 생성  
X) Other (please describe after [Answer]: tag below)

[Answer]: A

# 스토리 생성 계획 (Story Generation Plan)

## 1. 개요 및 방법론
이 계획은 `aidlc-docs/inception/requirements/requirements.md`에 명시된 P0 요구사항 7건(FR-TRUST-001 ~ FR-TRUST-007) 및 핵심 NFR, 그리고 후속 P1 요구사항을 INVEST 기준을 만족하는 사용자 스토리와 검증 가능한 인수 조건(Acceptance Criteria)으로 구조화하기 위한 실행 계획입니다.

---

## 2. 사용자 페르소나 정의 (Personas)

1. **임베디드 C/C++ 시스템 엔지니어 (System Engineer, "Min-soo")**:
   - 실행 중인 제품 프로세스의 메모리 손상, 데드락, 누수 결함을 안전하게(zero-stop) 추적하고자 함.
   - 불확실한 추측성 판정이 아닌, 원본 메모리와 소스 코드로 역추적 가능한 결정론적 증거와 재현 가능한 리포트를 요구함.
2. **MCP 기반 AI 코딩 에이전트 (AI Agent, "Cursor / Claude")**:
   - `dynamic-state-mcp` 도구를 통해 런타임 진단을 표준화된 절차로 호출하고 구조화된 진단 결과를 수신함.
   - 도구 호출 시 일관된 신뢰 경계 검증과 명확한 오류/기권(abstention) 응답을 필요로 함.
3. **품질 및 보안 감사자 (QA / Security Auditor, "Jin-woo")**:
   - 저장소의 영수증 무결성, 파일 퍼미션(0600), 증거 입도(Admission) 필터링이 안전한지 검증함.
   - 모든 벤치마크 및 진단 결론이 clean commit과 deterministic seed를 통해 독립적으로 재현 가능한지 감사함.

---

## 3. 스토리 분할 및 Epic 구조

- **Epic 1: Operation Identity & Replay Protection (P0 Trust)**
  - US-TRUST-001: Operation ID 사전 검증 (FR-TRUST-001)
  - US-TRUST-002: Replay 방어 Canonical Identity 완전성 (FR-TRUST-002)
  - US-TRUST-003: Metadata 단조성 및 충돌 격리 (FR-TRUST-003)
- **Epic 2: Evidence Admission & Store Security (P0 Security & Provenance)**
  - US-TRUST-004: Evidence Ledger 엄격 입도 상태 머신 및 거부 증거 차단 (FR-TRUST-004)
  - US-TRUST-005: TrustStore 파일시스템 보안 및 권한 강제 (FR-TRUST-005)
  - US-TRUST-006: 권위 있는 증거의 Provenance 계통 보존 (FR-TRUST-006)
  - US-TRUST-007: Operation 생명주기 전이 및 원자적 복구 (FR-TRUST-007)
- **Epic 3: Deterministic Explanation & Verification Integrity (P1 Foundations)**
  - US-EXPLAIN-001: 불변 DiagnoseResult 기반 읽기 전용 자연어 해설 (FR-EXPLAIN-001)
  - US-BENCH-001: aarch64 + x86_64 이중 Clean Benchmark 기준선 (FR-BENCH-001)
  - US-PROCESS-001: TDD 선행 결함 재현 및 GO/NO-GO 보고 체계 (NFR-PROCESS-001, 002)

---

## 4. 실행 체크리스트 (Execution Checklist)

- [x] **Step 1**: 페르소나 상세 문서 생성 (`aidlc-docs/inception/user-stories/personas.md`)
- [x] **Step 2**: Epic 1 (US-TRUST-001 ~ 003) 스토리 및 글머리표 AC 작성
- [x] **Step 3**: Epic 2 (US-TRUST-004 ~ 007) 스토리 및 글머리표 AC 작성
- [x] **Step 4**: Epic 3 (US-EXPLAIN-001, US-BENCH-001, US-PROCESS-001) 스토리 및 AC 작성
- [x] **Step 5**: 전체 스토리 통합 산출물 생성 (`aidlc-docs/inception/user-stories/stories.md`)
- [x] **Step 6**: INVEST 원칙 및 요구사항 추적성(Traceability) 검증

---

## 5. 명확화 확인 질문 (Clarification Questions)

### Question 1: 스토리 우선순위 및 구현 단위 구성
이번 사용자 스토리 산출물에서 P0 Trust Closure(Epic 1 & Epic 2) 7개 스토리를 별도의 최우선 핵심 블록으로 구성하고, Epic 3(설명 계층 및 벤치마크)을 후속 검증 블록으로 분리하는 계층형 구성을 적용할까요?

A) **예 — P0 7개 스토리를 최우선 핵심 블록으로 명확히 분리하고 집중 (권장)**: TDD 및 결함 재현 단위와 1:1로 직결되도록 구성  
B) **혼합 — 모든 스토리를 단일 평면 목록으로 나열**: 우선순위 태그만으로 구분  
X) Other (please describe after [Answer]: tag below)

[Answer]: A

---

### Question 2: 인수 조건(Acceptance Criteria) 형식
각 사용자 스토리의 인수 조건을 Given-When-Then 형식의 Gherkin 시나리오로 작성하여, TDD 회귀 테스트 케이스명 및 검증 로직과 직접 매핑되도록 할까요?

A) **예 — Gherkin (Given-When-Then) 형식 적용 (권장)**: 각 시나리오가 테스트 함수 및 assertion 조건과 직결되도록 구체화  
B) **글머리표 체크리스트 형식**: 간단한 준수 조건 목록으로 작성  
X) Other (please describe after [Answer]: tag below)

[Answer]: B

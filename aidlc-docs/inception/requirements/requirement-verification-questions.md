# 요구사항 확인 질문 (Requirements Clarification Questions)

제공해주신 `docs/PRD.md` (DynamicState 개선 요구사항 명세서 v1.0)를 검토했습니다.
PRD에서 정의된 제품 비전(MCP 중심 전문가용 결정론적 C/C++ 런타임 진단 도구), P0~P3 요구사항 체계 및 성공 지표를 바탕으로 이번 AI-DLC 사이클의 실행 계획을 구체화하기 위한 확인 질문을 작성했습니다.

---

## Question 1: 이번 사이클의 핵심 실행 범위 (Implementation Scope)
`docs/PRD.md`에는 P0부터 P3까지의 요구사항이 정의되어 있습니다. 이번 AI-DLC 구현 사이클에서 우선적으로 완료할 마일스톤 범위는 무엇입니까?

A) **P0 우선 완결 (권장)**: P0 (Evidence Authority & Trust Boundary Closure, 결함 5건 방어 및 신뢰 경계 폐쇄)를 최우선으로 완결하고 회귀 검증  
B) **P0 + P1 핵심 기능 강화**: P0 전체와 함께 P1의 C++ 컨테이너 decoder fail-safe, 정적 위치 후보 순위화, 적응형 예산 제어까지 포함  
C) **P0 ~ P3 전체 단계적 수행**: P0부터 P3 (재현 가능한 clean benchmark 및 문서 정합성)까지 전체 PRD 요구사항을 순차 구현  
X) Other (please describe after [Answer]: tag below)

[Answer]: A (P0 우선 완결)

---

## Question 2: P0 기존 결함 5건에 대한 검증 방식
PRD 2.3절에 명시된 5가지 미해결 결함(1. operation ID 검증 시점, 2. replay identity 부족, 3. 빈 metadata 덮어쓰기, 4. Ledger admission 실패 데이터 유입, 5. TrustStore owner/mode 불완전 검증)을 해결할 때 선행할 검증 방식은 무엇입니까?

A) **TDD / 결함 재현 테스트 선행 (권장)**: 각 결함에 대한 독립적인 재현 단위 테스트(`tests/test_trust_boundary_*.py`)를 먼저 작성하여 실패를 확인한 후 패치 적용  
B) **코드 수정 및 통합 테스트 검증**: `capture_backend.py` 및 `evidence_ledger.py` 수정을 먼저 진행한 후 기존 A.3.17 스위트와 함께 신규 테스트 검증  
X) Other (please describe after [Answer]: tag below)

[Answer]: A (TDD / 결함 재현 테스트 선행)

---

## Question 3: 벤치마크 및 재현성 기준선 (Benchmark Baseline)
PRD 2.2절에 따르면 기존 벤치마크 산출물 중 일부가 `dirty: true`이거나 재현성이 부족하다고 지적되었습니다. 이번 사이클에서 목표로 하는 클린 벤치마크 검증 환경은 어디입니까?

A) **현재 개발 호스트(aarch64) 클린 벤치마크 (권장)**: 현재 aarch64 환경에서 git dirty 없는 완전한 clean commit 기준으로 결함 11/11 탐지 및 held-out 21개 스위트 재검증 산출물 생성  
B) **x86_64 CI 환경 중심 검증**: GitHub Actions CI 워크플로 기반으로 x86_64 러너에서의 벤치마크 아티팩트를 정본 기준선으로 채택  
C) **aarch64 + x86_64 이중 기준선**: 로컬 및 CI 양쪽 모두에서 clean 산출물을 생성하여 상호 검증  
X) Other (please describe after [Answer]: tag below)

[Answer]: C (aarch64 + x86_64 이중 기준선)

---

## Question 4: MCP 인터페이스 및 자연어 해설 도구 연동 방식
현재 작업 공간에 `extractor/process_explainer.py` 및 MCP 도구 `runtime_explain_process_behavior`가 추가되어 있습니다. PRD의 "MCP and reports first" 원칙에 맞춰 이 도구를 어떻게 통합하시겠습니까?

A) **결정론적 진단 결과의 설명 계층으로 정식 통합 (권장)**: `diagnose()`가 산출한 결정론적 `DiagnoseResult` 및 증거 연관 체인을 사람이 읽기 쉽게 요약/해설하는 부가 도구로 표준화하고 테스트 추가  
B) **기본 진단 파이프라인(`diagnose()`) 내부에 자동 포함**: 진단 실행 시 결과 요약과 함께 해설을 기본 리포트에 내장  
X) Other (please describe after [Answer]: tag below)

[Answer]: A (결정론적 진단 결과의 설명 계층으로 정식 통합)

---

## Question 5: 속성 기반 테스트 확장 (Property-Based Testing Extension)
이 프로젝트에 속성 기반 테스트 (PBT) 규칙을 강제할까요?

A) 예 — 모든 PBT 규칙을 차단성 제약으로 강제 (비즈니스 로직, 데이터 변환, 직렬화, 상태를 가진 구성요소가 있는 프로젝트에 권장)  
B) 부분 — 순수 함수와 직렬화 왕복 (round-trip) 에만 PBT 규칙 강제 (알고리즘 복잡도가 낮은 프로젝트에 적합)  
C) 아니요 — 모든 PBT 규칙 건너뜀 (단순 CRUD 애플리케이션, UI 전용 프로젝트, 중요한 비즈니스 로직이 없는 얇은 통합 계층에 적합)  
X) Other (please describe after [Answer]: tag below)

[Answer]: A (모든 PBT 규칙을 차단성 제약으로 강제)

---

## Question 6: 보안 확장 (Security Extensions)
이 프로젝트에 보안 확장 규칙을 강제할까요?

A) 예 — 모든 SECURITY 규칙을 차단성 제약으로 강제 (운영 수준 애플리케이션에 권장)  
B) 아니요 — 모든 SECURITY 규칙 건너뜀 (PoC, 프로토타입, 실험 프로젝트에 적합)  
X) Other (please describe after [Answer]: tag below)

[Answer]: A (모든 SECURITY 규칙을 차단성 제약으로 강제)

---

## Question 7: 복원력 확장 (Resiliency Extensions)
이 프로젝트에 복원력 기준 (resiliency baseline) 을 적용할까요?

A) 예 — 복원력 기준을 방향 제시용 모범 사례 및 설계 단계 지침으로 적용 (비즈니스 핵심 워크로드에 권장. 운영 개시 전에 검증 · 강화할 수 있는, 근거 있는 출발점)  
B) 아니오 — 복원력 기준 생략 (신뢰성보다 빠른 반복이 중요한 PoC, 프로토타입, 실험 프로젝트에 적합)  
X) Other (please describe after [Answer]: tag below)

[Answer]: A (복원력 기준을 방향 제시용 모범 사례 및 설계 단계 지침으로 적용)

---

## 추가 구현 제약사항 (Additional Implementation Constraints)

1. P0의 기존 결함 5건을 우선 완결한다.
2. 기존 구현을 충분히 조사하지 않고 동일 기능을 재개발하지 않는다.
3. 각 결함은 실제 코드 경로를 추적하고 재현 테스트를 통해 검증한다.
4. PBT 및 SECURITY 규칙은 핵심 불변식과 보안 경계를 대상으로 CI 차단 조건으로 적용한다.
5. Property-based test는 deterministic seed와 재현 가능한 실패 보고를 지원해야 한다.
6. aarch64와 x86_64 benchmark는 동일한 dataset 및 평가 기준을 사용한다.
7. benchmark 결과에는 commit SHA, dirty state, 환경, 반복 횟수를 기록한다.
8. 자연어 해설 계층은 DiagnoseResult와 Evidence를 변경할 수 없어야 한다.
9. 복원력 확장은 기존 아키텍처를 불필요하게 변경하지 않는 범위에서 수행한다.
10. P0 완료 후 검증 결과를 바탕으로 P1 진행 여부를 결정한다.
11. 테스트 미실행, 검증 실패, 미확인 상태를 PASS로 표시하지 않는다.
12. 모든 단계에서 GO / NO-GO / PARTIAL 판정을 명확히 보고한다.

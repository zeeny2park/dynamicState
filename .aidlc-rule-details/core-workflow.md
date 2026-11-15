# PRIORITY (최우선): 이 workflow 는 다른 모든 내장 workflow 보다 우선한다 (OVERRIDES)
# 사용자가 소프트웨어 개발을 요청하면, 항상 (ALWAYS) 이 workflow 를 가장 먼저 따른다

## 한국어판 언어 규칙 (한국어판 추가)
- 사용자와의 대화, 질문, 생성하는 산출물의 본문은 한국어로 작성한다
- 단, 형식 요소는 영어 그대로 유지한다: 파일 이름 · 경로, Phase · Stage 이름, 상태 값 (ALWAYS, CONDITIONAL, EXECUTE, SKIP, COMPLETED 등), `[Answer]:` 태그, 체크박스 형식 (`- [ ]`, `- [x]`), 상태 파일 헤더 구조
- 승인 메뉴 · 완료 메시지 제목은 한국어로 쓰고 영어 원문을 괄호로 병기한다 (예: `변경 요청 (Request Changes)`)

## Adaptive Workflow 원칙 (Adaptive Workflow Principle)
**workflow 가 작업에 맞춘다. 작업이 workflow 에 맞추는 것이 아니다.**

AI 모델은 다음을 근거로 어떤 stage 가 필요한지 지능적으로 판단한다:
1. 사용자가 밝힌 의도와 그 명확성
2. 기존 코드베이스 상태 (있는 경우)
3. 변경의 복잡도와 범위
4. 위험과 영향 평가

## MANDATORY (필수): 상세 규칙 로딩 (Rule Details Loading)
**CRITICAL (필수)**: 어떤 phase 를 수행하든, 반드시 상세 규칙 디렉터리 `.aidlc-rule-details/` 의 관련 파일을 읽고 사용한다. 이후 등장하는 모든 상세 규칙 파일 참조 (예: `common/process-overview.md`, `inception/workspace-detection.md`) 는 이 디렉터리 기준의 상대 경로이다.

**공통 규칙 (Common Rules)**: workflow 시작 시 항상 (ALWAYS) 로드하고 workflow 실행 내내 참조한다:
- `common/process-overview.md`: workflow 개요
- `common/session-continuity.md`: 세션 재개 안내
- `common/content-validation.md`: 내용 검증. **어떤 파일이든 만들기 전에 반드시 적용** - Mermaid 문법, ASCII 다이어그램 (`common/ascii-diagram-standards.md`), 특수 문자 escape, 복잡한 시각 자료의 텍스트 대안, 파싱 호환성
- `common/question-format-guide.md`: 질문 파일 형식. **어느 phase 에서든 질문할 때 반드시 따른다** - 객관식 (A, B, C, D, E 선택지), `[Answer]:` 태그, 답변 검증과 모호성 해소

## MANDATORY (필수): 확장 로딩 (Extensions Loading, Context-Optimized)
**CRITICAL (필수)**: workflow 시작 시 `extensions/` 디렉터리를 재귀적으로 탐색하되, 가벼운 opt-in 파일만 로드한다 — 전체 규칙 파일은 사용자가 opt-in (사용 동의) 한 뒤 필요할 때 로드한다.

**로딩 절차**:
1. `extensions/` 아래 모든 하위 디렉터리를 나열 (예: `extensions/security/`, `extensions/compliance/`)
2. 각 하위 디렉터리에서 `*.opt-in.md` 파일만 로드 — 확장의 opt-in 질문이 들어 있다. 대응하는 규칙 파일 = `.opt-in.md` 접미사를 떼고 `.md` 를 붙인 이름 (예: `security-baseline.opt-in.md` → `security-baseline.md`)

**지연 규칙 로딩 (Deferred Rule Loading)**:
- Requirements Analysis 중에, 로드한 `*.opt-in.md` 파일의 opt-in 질문을 사용자에게 제시한다
- 사용자가 opt-in 하면 그 시점에 대응하는 규칙 파일을 로드하고, opt-out 하면 끝까지 로드하지 않는다 — context 절약
- 대응하는 `*.opt-in.md` 파일이 없는 확장은 항상 적용된다 — workflow 시작 시 규칙 파일을 즉시 로드한다

**적용 (Enforcement)** (로드 · 활성화된 확장에만 해당):
- 확장 규칙은 선택적 안내가 아니라 강제 제약이다
- 각 stage 에서 stage 의 목적, 생성 중인 산출물, 작업 맥락을 근거로 해당 규칙만 지능적으로 골라 적용한다
- 현재 stage 에 해당하지 않는 규칙은 준수 요약에 N/A 로 표시한다 (차단 사항 아님)
- 해당되는 활성 확장 규칙을 하나라도 지키지 않으면 **차단 사항 (blocking finding)** 이다 — 해결 전에는 stage 완료를 제시하지 않는다
- stage 완료를 제시할 때 확장 규칙 준수 요약을 포함한다 (규칙별 compliant / non-compliant / N/A, N/A 판정에는 짧은 근거)

**조건부 적용 (Conditional Enforcement)**: opt-in 방식은 `inception/requirements-analysis.md` 참조. 확장을 적용하기 전에 `aidlc-docs/aidlc-state.md` 의 `## Extension Configuration` 아래 `Enabled` 상태를 확인한다. 비활성 확장은 건너뛰고 그 사실을 audit.md 에 기록한다. 설정이 없으면 기본값은 적용 (enforced) 이다.

## MANDATORY (필수): 환영 메시지 (Custom Welcome Message)
**CRITICAL (필수)**: 새 workflow 를 시작할 때 한 번만 (ONCE) `common/welcome-message.md` 의 환영 메시지 전체를 사용자에게 표시한다. context 공간 절약을 위해 이후 대화에서는 이 파일을 로드하지 않는다.

## MANDATORY (필수): 공통 stage 진행 규칙 (모든 stage 에 적용)
아래 stage 블록의 "실행" 목록은 이 규칙을 전제로 한다 (블록마다 다시 적지 않음):
1. **감사 기록**: stage 중 모든 사용자 입력, 승인 질문, 사용자 응답을 audit.md 에 기록한다 (형식 · 규칙은 "감사 기록" 절)
2. **상세 규칙 로드**: 블록에 적힌 stage 규칙 파일의 모든 step 을 로드하고 그 순서대로 진행한다
3. **깊이**: 적절한 깊이 (minimal / standard / comprehensive) 로 실행한다
4. **Brownfield 맥락**: reverse engineering 산출물이 있으면 로드해 참고한다
5. **완료 메시지 고정 (NO EMERGENT BEHAVIOR)**: stage 규칙 파일에 정의된 완료 메시지 · 승인 메뉴를 그대로 사용한다. 즉흥적인 3-선택지 메뉴나 다른 이동 방식을 만들지 않는다. Construction · Operations 는 표준 2-선택지: "변경 요청 (Request Changes)" / "다음 Stage 로 진행 (Continue to Next Stage)"
6. **명시적 승인 대기**: 사용자가 확인하기 전에는 다음 stage 로 진행하지 않는다 (DO NOT PROCEED). 예외 없음: 모든 stage 는 완료 메시지 뒤 사용자 승인을 받고 다음으로 넘어간다 (과정판)
7. **진행 추적**: 계획 체크박스와 aidlc-state.md 를 작업한 바로 그 상호작용 안에서 갱신한다 ("계획 단위 체크박스 강제" 절)
8. **AI 점검 (과정판 추가)**: INCEPTION · CONSTRUCTION stage 는 완료 메시지 (Code Generation 은 계획 승인 질문 포함) 를 제시하기 전에 `common/stage-checklists.md` 의 해당 항목을 점검하고, 결과 블록을 완료 메시지 바로 위에 붙인다. 완료 메시지 · 승인 메뉴는 바꾸지 않는다 (규칙 5)

# Adaptive 소프트웨어 개발 Workflow (Adaptive Software Development Workflow)

---

# 🔵 INCEPTION PHASE

**목적**: 계획 수립, 요구사항 수집, 아키텍처 결정

**초점**: 무엇을 (WHAT) 왜 (WHY) 만들지 결정

**INCEPTION PHASE 의 stage**:
- Workspace Detection (ALWAYS)
- Reverse Engineering (CONDITIONAL - Brownfield 전용)
- Requirements Analysis (ALWAYS - 깊이 조정)
- User Stories (CONDITIONAL)
- Workflow Planning (ALWAYS)
- Application Design (CONDITIONAL)
- Units Generation (CONDITIONAL)

---

## Workspace Detection (ALWAYS EXECUTE)

**실행**:
1. 최초 사용자 요청을 원문 그대로 전부 audit.md 에 기록
2. `inception/workspace-detection.md` 의 모든 step 로드
3. 기존 aidlc-state.md 확인 (있으면 재개), 작업 공간 (workspace) 의 기존 코드 탐색, brownfield (기존 코드) / greenfield (신규) 판단, 기존 reverse engineering 산출물 확인
4. 발견 사항을 audit.md 에 기록하고 완료 메시지 제시 (형식은 workspace-detection.md) · 승인 대기
5. 승인 후 다음 stage: Reverse Engineering (brownfield 이고 산출물 없음) 또는 Requirements Analysis

## Reverse Engineering (CONDITIONAL - Brownfield 전용)

**실행 조건 (Execute IF)**: 기존 코드베이스가 감지됨, 이전 reverse engineering 산출물이 없음

**건너뛰기 조건 (Skip IF)**: Greenfield 프로젝트, 또는 이전 reverse engineering 산출물이 있음

**실행**:
1. `inception/reverse-engineering.md` 의 모든 step 로드
2. 모든 패키지와 컴포넌트 분석 → 비즈니스 개요, 아키텍처, 코드 구조, API, 컴포넌트 목록, 상호작용 다이어그램 (Interaction Diagrams), 기술 스택, 의존성 문서 생성
3. 상세 완료 메시지 제시 (형식은 reverse-engineering.md) · 승인 대기

## Requirements Analysis (ALWAYS EXECUTE - 깊이 조정)

**항상 실행**되지만 깊이는 요청의 명확성과 복잡도에 따라 달라진다:
- **Minimal**: 단순하고 명확한 요청 - 의도 분석만 문서화
- **Standard**: 보통 복잡도 - 기능 · 비기능 요구사항 수집
- **Comprehensive**: 복잡하고 위험 높음 - 추적성을 갖춘 상세 요구사항

**실행**:
1. `inception/requirements-analysis.md` 의 모든 step 로드
2. 사용자 요청 분석 (의도 분석) → 필요한 요구사항 깊이 결정 → 현재 요구사항 평가 → 명확화 질문 (필요한 경우, 확장 opt-in 질문 포함) → 요구사항 문서 생성
3. requirements-analysis.md 의 승인 형식으로 제시 · 승인 대기

## User Stories (CONDITIONAL)

**실행 조건 (Execute IF)**: 사용자에게 보이는 새 기능 · workflow 변경, 여러 사용자 유형 (persona), 인수 조건이 필요한 복잡한 비즈니스 규칙, 고객 대상 API · 서비스 변경, 여러 직무 간 협업

**건너뛰기는 다음 경우만 (SKIP ONLY IF)**: 사용자 영향이 없는 순수 내부 리팩터링, 격리된 단순 버그 수정, 사용자에게 보이는 영향이 없는 인프라 · 개발 도구 · 빌드 변경, 문서만 수정

**판정**: user-stories.md 의 지능형 평가 지침 (높은 · 중간 우선순위, 복잡도 평가 요소) 으로 판단하고, 애매하면 포함한다. Requirements Analysis 를 실행했다면 story 는 그 요구사항을 참조 · 확장한다.

**실행**:
1. `inception/user-stories.md` 의 모든 step 로드
2. **MANDATORY (필수)**: user-stories.md Step 1 (필요성 검증) 수행
3. **PART 1 - Planning**: 질문이 담긴 story 계획 작성, 사용자 답변 대기, 모호성 분석, 승인 받기
4. **PART 2 - Generation**: 승인된 계획을 실행해 story 와 persona 생성
5. user-stories.md 의 승인 형식으로 제시 · 승인 대기

## Workflow Planning (ALWAYS EXECUTE)

**실행**:
1. `inception/workflow-planning.md` 의 모든 step 로드
2. 이전 context 전부 로드: reverse engineering 산출물 (brownfield), 의도 분석, 요구사항 · user story (실행한 경우)
3. 실행할 stage 와 phase 별 깊이 결정, 다중 패키지 변경 순서 작성 (brownfield), workflow 시각화 생성 (Mermaid 문법 검증)
4. workflow-planning.md Step 9 의 문구로 권고안을 제시하고 사용자가 권고를 뒤집을 수 있음을 강조 · 승인 대기

## Application Design (CONDITIONAL)

**실행 조건 (Execute IF)**: 새 컴포넌트나 서비스 필요, 컴포넌트 메서드와 비즈니스 규칙 정의 필요, 서비스 계층 설계 필요, 컴포넌트 의존성 명확화 필요

**건너뛰기 조건 (Skip IF)**: 기존 컴포넌트 경계 안의 변경, 새 컴포넌트나 메서드 없음, 순수 구현 변경

**실행**:
1. `inception/application-design.md` 의 모든 step 로드
2. 상세 완료 메시지 제시 (형식은 application-design.md) · 승인 대기

## Units Generation (CONDITIONAL)

**실행 조건 (Execute IF)**: 시스템을 여러 unit (작업 단위) 으로 분해해야 함, 여러 서비스나 모듈 필요, 구조적 분해가 필요한 복잡한 시스템

**건너뛰기 조건 (Skip IF)**: 단순한 단일 unit · 단일 컴포넌트 구현, 분해 불필요

**실행**:
1. `inception/units-generation.md` 의 모든 step 로드
2. 상세 완료 메시지 제시 (형식은 units-generation.md) · 승인 대기

---

# 🟢 CONSTRUCTION PHASE

**목적**: 상세 설계, NFR (비기능 요구사항) 구현, 코드 생성

**초점**: 어떻게 (HOW) 만들지 결정

**CONSTRUCTION PHASE 의 stage**:
- Unit 별 반복 (Per-Unit Loop, 각 unit 마다 실행):
  - Functional Design (CONDITIONAL, unit 별)
  - NFR Requirements (CONDITIONAL, unit 별)
  - NFR Design (CONDITIONAL, unit 별)
  - Infrastructure Design (CONDITIONAL, unit 별)
  - Code Generation (ALWAYS, unit 별)
- Build and Test (ALWAYS - 모든 unit 완료 후)

**참고**: 각 unit 은 다음 unit 으로 넘어가기 전에 (설계 + 코드) 를 완전히 끝낸다. 모든 stage 는 표준 2-선택지 완료 메시지를 사용한다 (공통 stage 진행 규칙 5).

---

## Unit 별 반복 (Per-Unit Loop, 각 Unit 마다 실행)

**각 unit (작업 단위) 마다 다음 stage 를 순서대로 실행한다:**

### Functional Design (CONDITIONAL, unit 별)

**실행 조건 (Execute IF)**: 새 데이터 모델이나 스키마, 복잡한 비즈니스 로직, 비즈니스 규칙의 상세 설계 필요

**건너뛰기 조건 (Skip IF)**: 단순한 로직 변경, 새 비즈니스 로직 없음

**실행**:
1. `construction/functional-design.md` 의 모든 step 로드
2. 이 unit 의 functional design 실행
3. 표준 2-선택지 완료 메시지 제시 · 승인 대기

### NFR Requirements (CONDITIONAL, unit 별)

**실행 조건 (Execute IF)**: 성능 요구사항이 있음, 보안 고려 필요, 확장성 우려가 있음, 기술 스택 선택 필요

**건너뛰기 조건 (Skip IF)**: NFR 요구사항 없음, 기술 스택이 이미 결정됨

**실행**:
1. `construction/nfr-requirements.md` 의 모든 step 로드
2. 이 unit 의 NFR 평가 실행
3. 표준 2-선택지 완료 메시지 제시 · 승인 대기

### NFR Design (CONDITIONAL, unit 별)

**실행 조건 (Execute IF)**: NFR Requirements 를 실행함, NFR 패턴을 반영해야 함

**건너뛰기 조건 (Skip IF)**: NFR 요구사항 없음, NFR Requirements 를 건너뜀

**실행**:
1. `construction/nfr-design.md` 의 모든 step 로드
2. 이 unit 의 NFR design 실행
3. 표준 2-선택지 완료 메시지 제시 · 승인 대기

### Infrastructure Design (CONDITIONAL, unit 별)

**실행 조건 (Execute IF)**: 실행 환경 · 배포 구조 매핑 필요, 배포 아키텍처 필요, 인프라 리소스 명세 필요

**건너뛰기 조건 (Skip IF)**: 인프라 변경 없음, 인프라가 이미 정의됨

**실행**:
1. `construction/infrastructure-design.md` 의 모든 step 로드
2. 이 unit 의 infrastructure design 실행
3. 표준 2-선택지 완료 메시지 제시 · 승인 대기

### Code Generation (ALWAYS EXECUTE, unit 별)

**각 unit 마다 항상 실행**. 한 stage 안에 두 part 로 구성된다.

**실행**:
1. `construction/code-generation.md` 의 모든 step 로드
2. **PART 1 - Planning**: 체크박스가 담긴 상세 코드 생성 계획 작성, 사용자 승인 받기
3. **PART 2 - Generation**: 승인된 계획을 실행해 이 unit 의 코드, 테스트, 산출물 생성
4. 표준 2-선택지 완료 메시지 제시 · 승인 대기

---

## Build and Test (ALWAYS EXECUTE)

**실행**:
1. `construction/build-and-test.md` 의 모든 step 로드
2. 모든 unit 의 빌드 · 단위 테스트 · 통합 테스트 (unit 간 상호작용) 지침, 해당되는 경우 성능 · contract · 보안 · e2e 테스트 지침을 `build-and-test/` 에 생성 (파일 목록은 build-and-test.md)
3. 승인 질문: 실행 계획에 EXECUTE 인 Operations stage 가 있으면 "**빌드 · 테스트 지침 작성 완료. Operations stage 로 진행할까요? (Build and test instructions complete. Ready to proceed to Operations stage?)**", 모두 SKIP 이면 "**빌드 · 테스트 지침 작성 완료. workflow 를 완료할까요? (Build and test instructions complete. Ready to complete the workflow?)**" · 승인 대기

---

# 🟡 OPERATIONS PHASE

**목적**: 배포, 관측, 장애 대응, 운영 피드백

**초점**: 어떻게 배포하고 (DEPLOY) 운영할지 (RUN)

**OPERATIONS PHASE 의 stage** (모두 CONDITIONAL, unit 별이 아닌 phase 단위 1회, 아래 순서대로 실행):
- Deployment Pipeline (파이프라인 구성)
- Environment Provisioning (환경 준비)
- Deployment Execution (배포 실행)
- Observability Setup (관측 설정)
- Incident Response (장애 대응)
- Performance Validation (성능 검증)
- Feedback & Optimization (운영 피드백)

**공통 실행 (모든 Operations stage)**:
1. `operations/operations.md` 의 공통 안전 규칙과 해당 stage 파일의 모든 step 로드
2. 해당 stage 실행 (계획 · 질문 → 답변 수집 → 산출물 생성)
3. 표준 2-선택지 완료 메시지 제시 · 승인 대기. 다음 Stage = 실행 계획의 다음 EXECUTE stage, 없으면 workflow 완료

**공통 안전 규칙 (핵심, 전문은 `operations/operations.md`)**: 배포 대상 · 환경 · 도구는 확인된 것만 사용하고 절대 지어내지 않는다 (NEVER invent). 외부에 영향을 주는 명령은 계획 승인과 실행 직전 사용자 확인 뒤에만 실행하고, 운영 (production) 환경은 명령만 제시한다. 조건을 충족하지 않는 stage 는 빈 산출물 없이 SKIP 하고 사유를 기록한다.

---

## Deployment Pipeline (CONDITIONAL)
**실행 조건 (Execute IF)**: 실제 배포 대상이 있고 배포 흐름 · 전략 · 롤백 정의가 필요
**건너뛰기 조건 (Skip IF)**: 배포 대상 없음, 또는 기존 파이프라인으로 충분
**실행**: 공통 실행 + `operations/deployment-pipeline.md`

## Environment Provisioning (CONDITIONAL)
**실행 조건 (Execute IF)**: 새 환경이 필요하거나 기존 환경의 설정 · 검증이 필요
**건너뛰기 조건 (Skip IF)**: 대상 환경이 이미 준비 · 검증됨, 또는 배포 대상 없음
**실행**: 공통 실행 + `operations/environment-provisioning.md`

## Deployment Execution (CONDITIONAL)
**실행 조건 (Execute IF)**: 배포 대상 · 환경 · 배포 방식이 확인됨 (앞 두 stage 산출물 또는 작업 공간의 실제 설정)
**건너뛰기 조건 (Skip IF)**: 확인된 배포 대상 없음
**실행**: 공통 실행 + `operations/deployment-execution.md`

## Observability Setup (CONDITIONAL)
**실행 조건 (Execute IF)**: 운영되는 서비스에 SLO · 지표 · 알람 · 로그 조회 정의가 필요
**건너뛰기 조건 (Skip IF)**: 운영 대상 없음, 또는 기존 관측 구성으로 충분
**실행**: 공통 실행 + `operations/observability-setup.md`

## Incident Response (CONDITIONAL)
**실행 조건 (Execute IF)**: 운영 서비스의 장애 진단 · 격리 · 롤백 절차가 필요
**건너뛰기 조건 (Skip IF)**: 운영 대상 없음, 또는 기존 runbook 으로 충분
**실행**: 공통 실행 + `operations/incident-response.md`

## Performance Validation (CONDITIONAL)
**실행 조건 (Execute IF)**: 성능 · 확장성 NFR 이 있고 실환경 또는 동등 환경 검증이 필요
**건너뛰기 조건 (Skip IF)**: 성능 NFR 없음, 또는 Build and Test 성능 테스트로 충분
**실행**: 공통 실행 + `operations/performance-validation.md`

## Feedback & Optimization (CONDITIONAL)
**실행 조건 (Execute IF)**: 운영 지표 · 로그 · 장애 기록 등 운영 데이터가 있거나 운영 회고가 필요
**건너뛰기 조건 (Skip IF)**: 아직 운영 데이터 없음
**실행**: 공통 실행 + `operations/feedback-optimization.md`. 개선 과제는 다음 "Using AI-DLC" 요청 (Inception) 의 입력이 된다

---

## 핵심 원칙 (Key Principles)

- **Adaptive 실행**: 가치를 더하는 stage 만 실행
- **투명한 계획**: 시작 전에 항상 실행 계획을 보여준다
- **사용자 통제**: 사용자는 stage 포함 · 제외를 요청할 수 있다
- **품질 중심**: 복잡한 변경은 전체 절차를, 단순한 변경은 효율적으로
- 감사 기록 · 내용 검증 · 완료 메시지 고정 · 진행 추적은 위 "공통 stage 진행 규칙" 과 아래 절을 따른다

## MANDATORY (필수): 계획 단위 체크박스 강제 (Plan-Level Checkbox Enforcement)

1. **계획 체크박스를 갱신하지 않고는 어떤 작업도 완료하지 않는다 (NEVER)**
2. **계획 파일의 step 을 하나라도 완료하면 즉시 (IMMEDIATELY), 작업을 완료한 바로 그 상호작용 (SAME interaction) 안에서 [x] 로 표시한다**
3. **예외 없음 (NO EXCEPTIONS)**: 모든 계획 step 완료는 반드시 체크박스 갱신으로 추적한다
4. 2단계 추적: Plan-Level (계획 단위) = 각 stage 안의 상세 실행 진행, Stage-Level (stage 단위) = aidlc-state.md 의 workflow 전체 진행 (실행한 stage 와 건너뛴 stage 모두 기록)

## MANDATORY (필수): 감사 기록 (Audit Log)

- 모든 사용자 입력 (프롬프트, 질문, 응답) 과 AI 응답 · 조치를 timestamp 와 함께 audit.md 에 기록한다 (승인뿐 아니라 모든 상호작용)
- **CRITICAL (필수)**: 사용자 입력은 받은 그대로 원문 전체 (COMPLETE RAW INPUT) 를 기록한다 - 절대 요약하거나 바꿔 쓰지 않는다
- 승인 질문은 사용자에게 묻기 전에, 응답은 받은 뒤 기록한다
- **CRITICAL (필수)**: audit.md 는 항상 (ALWAYS) 끝에 덧붙이거나 (Append) 부분 편집 (Edit) 한다. 읽은 내용에 새 항목을 더해 파일 전체를 덮어쓰는 도구 · 명령은 절대 (NEVER) 사용하지 않는다 (내용 중복 · 유실 원인)
- timestamp 는 ISO 8601 형식 (YYYY-MM-DDTHH:MM:SSZ), 각 항목에 stage 맥락 포함
- 입력 기록 hook (과정판 하네스) 이 "원문 기록 완료 (Timestamp)" 를 알려주면 그 입력은 이미 기록된 것이다 - `**User Input**: (hook 기록 <Timestamp>)` 로 대신 쓰고, hook 이 알려준 현재 시각을 timestamp 로 사용한다

```markdown
## [Stage 이름 또는 상호작용 유형]
**Timestamp**: [ISO timestamp]
**User Input**: "[사용자 입력 원문 전체 - 절대 요약 금지]"
**AI Response**: "[AI 응답 또는 수행한 조치]"
**Context**: [stage, 조치, 또는 내린 결정]

---
```

## 디렉터리 구조 (Directory Structure)

```text
<WORKSPACE-ROOT>/                   # ⚠️ 애플리케이션 코드 위치
├── [project-specific structure]    # 프로젝트마다 다름 (code-generation.md 참조)
│
├── aidlc-docs/                     # 📄 문서 전용
│   ├── inception/                  # 🔵 INCEPTION PHASE
│   │   ├── plans/
│   │   ├── reverse-engineering/    # Brownfield 전용
│   │   ├── requirements/
│   │   ├── user-stories/
│   │   └── application-design/
│   ├── construction/               # 🟢 CONSTRUCTION PHASE
│   │   ├── plans/
│   │   ├── {unit-name}/
│   │   │   ├── functional-design/
│   │   │   ├── nfr-requirements/
│   │   │   ├── nfr-design/
│   │   │   ├── infrastructure-design/
│   │   │   └── code/               # Markdown 요약만
│   │   └── build-and-test/
│   ├── operations/                 # 🟡 OPERATIONS PHASE
│   │   ├── plans/
│   │   └── {stage-slug}/           # 예: deployment-pipeline/, observability-setup/
│   ├── aidlc-state.md
│   └── audit.md
```

**CRITICAL RULE (필수 규칙)**:
- 애플리케이션 코드: 작업 공간 루트 (aidlc-docs/ 안에는 절대 (NEVER) 두지 않는다)
- 문서: aidlc-docs/ 에만
- 프로젝트 구조: 프로젝트 유형별 패턴은 code-generation.md 참조

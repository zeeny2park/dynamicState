# AI-DLC 용어집 (Terminology Glossary)

## 핵심 용어 (Core Terminology)

### Phase 와 Stage 구분 (Phase vs Stage)

**Phase**: AI-DLC 의 상위 생명주기 3개 phase 중 하나
- 🔵 **INCEPTION PHASE** - 계획과 아키텍처 (무엇을 WHAT, 왜 WHY)
- 🟢 **CONSTRUCTION PHASE** - 설계, 구현, 테스트 (어떻게 HOW)
- 🟡 **OPERATIONS PHASE** - 배포와 운영 (DEPLOY, RUN)

**Stage**: phase 안의 개별 workflow 활동
- 예: Context Assessment stage, Requirements Assessment stage, Code Generation stage
- 각 stage 는 정해진 선행 조건, step, 결과물을 가진다
- stage 는 ALWAYS-EXECUTE 또는 CONDITIONAL 이다

**사용 예 (Usage Examples)**:
- ✅ "CONSTRUCTION phase 는 7개 stage 로 구성된다"
- ✅ "Code Generation stage 는 항상 실행된다"
- ✅ "지금 INCEPTION phase 에서 Requirements Assessment stage 를 실행 중이다"
- ❌ "Requirements Assessment phase" ("stage" 여야 함)
- ❌ "CONSTRUCTION stage" ("phase" 여야 함)

## 3-Phase 생명주기 (Three-Phase Lifecycle)

### INCEPTION PHASE
**목적**: 계획 수립과 아키텍처 결정  
**초점**: 무엇을 (WHAT) 왜 (WHY) 만들지 결정  
**위치**: `inception/` 디렉터리

**Stage**:
- Workspace Detection (ALWAYS)
- Reverse Engineering (CONDITIONAL - Brownfield 전용)
- Requirements Analysis (ALWAYS - 깊이 조정)
- User Stories (CONDITIONAL)
- Workflow Planning (ALWAYS)
- Application Design (CONDITIONAL)
- Units Generation (CONDITIONAL)

**결과물**: 요구사항, user story, 아키텍처 결정, unit 정의

### CONSTRUCTION PHASE
**목적**: 상세 설계와 구현  
**초점**: 어떻게 (HOW) 만들지 결정  
**위치**: `construction/` 디렉터리

**Stage**:
- Functional Design (CONDITIONAL, unit 별)
- NFR Requirements (CONDITIONAL, unit 별)
- NFR Design (CONDITIONAL, unit 별)
- Infrastructure Design (CONDITIONAL, unit 별)
- Code Generation (ALWAYS) — Part 1: Planning 과 Part 2: Generation 포함
- Build and Test (ALWAYS)

**결과물**: 설계 산출물, NFR 구현, 코드, 테스트

### OPERATIONS PHASE
**목적**: 배포와 운영 준비  
**초점**: 어떻게 배포하고 (DEPLOY) 운영할지 (RUN)  
**위치**: `operations/` 디렉터리

**Stage** (모두 CONDITIONAL, phase 단위 1회):
- Deployment Pipeline (파이프라인 구성)
- Environment Provisioning (환경 준비)
- Deployment Execution (배포 실행)
- Observability Setup (관측 설정)
- Incident Response (장애 대응)
- Performance Validation (성능 검증)
- Feedback & Optimization (운영 피드백)

**결과물**: 배포 전략 · 롤백 runbook, 환경 목록, 배포 기록 · smoke test 결과, SLO · 알람 구성, 장애 대응 runbook, 성능 검증 결과, 개선 과제

---

## Workflow Stage (Workflow Stages)

### 항상 실행되는 Stage (Always-Execute Stages)
- **Workspace Detection**: 작업 공간 상태와 프로젝트 유형 초기 분석
- **Requirements Analysis**: 요구사항 수집 (깊이는 복잡도에 따라 다름)
- **Workflow Planning**: 어떤 phase 를 실행할지 실행 계획 작성
- **Code Generation**: 두 part 로 된 단일 stage — Part 1 (Planning) 은 상세 구현 계획을 작성하고, Part 2 (Generation) 는 계획과 이전 산출물을 근거로 실제 코드를 생성
- **Build and Test**: 모든 unit 빌드와 포괄적 테스트 실행

### 조건부 Stage (Conditional Stages)
- **Reverse Engineering**: 기존 코드베이스 분석 (brownfield 프로젝트 전용)
- **User Stories**: user story 와 persona 작성 (Story Planning 과 Story Generation 포함)
- **Application Design**: 애플리케이션 컴포넌트, 메서드, 비즈니스 규칙, 서비스 설계
- **Units Generation**: 시스템을 unit (작업 단위) 으로 분해 (내부 planning · generation 하위 step 과 unit 별 설계 포함)
- **Functional Design**: 기술에 독립적인 비즈니스 로직 설계 (unit 별)
- **NFR Requirements**: NFR 결정과 기술 스택 선택 (unit 별)
- **NFR Design**: NFR 패턴과 논리 컴포넌트 반영 (unit 별)
- **Infrastructure Design**: 실제 인프라 서비스에 매핑 (unit 별)
- **Operations stage 7개**: 배포 흐름 정의부터 운영 피드백까지 (phase 단위 1회, 확인된 배포 대상이 있을 때만)

## Application Design 용어 (Application Design Terms)

- **Component (컴포넌트)**: 특정 책임을 가진 기능 단위
- **Method (메서드)**: 비즈니스 규칙이 정의된, 컴포넌트 안의 함수 또는 연산
- **Business Rule (비즈니스 규칙)**: 메서드의 동작과 검증을 지배하는 로직
- **Service (서비스)**: 여러 컴포넌트에 걸친 비즈니스 로직을 조율하는 orchestration 계층
- **Component Dependency (컴포넌트 의존성)**: 컴포넌트 간 관계와 통신 패턴

## 아키텍처 용어 (Architecture Terms, Infrastructure)

### Unit of Work (작업 단위)
개발 목적으로 user story 를 논리적으로 묶은 것. 계획 수립과 분해 단계에서 쓰는 용어.

**사용 예**: "시스템을 unit of work 로 분해해야 한다"

### Service (서비스)
마이크로서비스 아키텍처에서 독립적으로 배포 가능한 컴포넌트. 각 서비스는 별도의 unit of work 이다.

**사용 예**: "Payment Service 가 모든 결제 처리를 담당한다"

### Module (모듈)
단일 서비스나 모놀리스 안의 기능을 논리적으로 묶은 것. 모듈은 독립적으로 배포할 수 없다.

**사용 예**: "User Service 안의 인증 모듈"

### Component (컴포넌트)
서비스나 모듈 안의 재사용 가능한 구성 요소. 특정 기능을 제공하는 클래스, 함수, 패키지를 말한다.

**사용 예**: "EmailValidator 컴포넌트가 이메일 주소를 검증한다"

## 용어 사용 지침 (Terminology Guidelines)

### 용어별 사용 시점 (When to Use Each Term)

**Unit of Work**:
- Units Generation stage 동안
- 시스템 분해를 논의할 때
- 계획 문서와 논의에서
- 예: "이것을 unit of work 로 어떻게 분해할까?"

**Service**:
- 독립 배포 가능한 컴포넌트를 가리킬 때
- 마이크로서비스 아키텍처 맥락에서
- 배포 · 인프라 논의에서
- 예: "Order Service 는 ECS 에 배포된다"

**Module**:
- 서비스 안의 논리적 묶음을 가리킬 때
- 모놀리스 아키텍처 맥락에서
- 내부 구성을 논의할 때
- 예: "reporting 모듈이 모든 보고서를 생성한다"

**Component**:
- 특정 클래스, 함수, 패키지를 가리킬 때
- 설계 · 구현 논의에서
- 재사용 가능한 구성 요소를 논의할 때
- 예: "DatabaseConnection 컴포넌트가 연결을 관리한다"

## Stage 용어 (Stage Terminology)

### Planning 과 Generation 구분 (Planning vs Generation)
- **Planning**: 실행을 위한 질문과 체크박스가 담긴 계획 작성
- **Generation**: 계획을 실행해 산출물 생성

예 (별도 stage 가 아니라 한 stage 안의 내부 하위 step):
- Story Planning → Story Generation (User Stories stage 안)
- Units Planning → Units Generation (Units Generation stage 안)
- Unit Design Planning → Unit Design Generation (unit 별 설계 안)
- NFR Planning → NFR Generation (NFR Requirements stage 안)
- Code Generation Part 1 (Planning) → Code Generation Part 2 (Generation)

### 깊이 수준 (Depth Levels)
- **Minimal**: 단순한 변경을 위한 빠르고 집중된 실행
- **Standard**: 일반 프로젝트를 위한 표준 산출물의 보통 깊이
- **Comprehensive**: 복잡 · 고위험 프로젝트를 위한 모든 산출물의 전체 깊이

## 산출물 유형 (Artifact Types)

### 계획 (Plans)
실행을 안내하는 체크박스와 질문이 담긴 문서.
- 위치: `aidlc-docs/plans/`
- 예: `story-generation-plan.md`, `unit-of-work-plan.md`

### 산출물 (Artifacts)
계획을 실행해 생성된 결과물.
- 위치: `aidlc-docs/` 의 여러 하위 디렉터리
- 예: `requirements.md`, `stories.md`, `design.md`

### 상태 파일 (State Files)
workflow 진행과 상태를 추적하는 파일.
- `aidlc-state.md`: workflow 전체 상태
- `audit.md`: 모든 상호작용의 완전한 감사 기록

## 주요 약어 (Common Abbreviations)

- **AI-DLC**: AI-Driven Development Life Cycle
- **NFR**: Non-Functional Requirements (비기능 요구사항)
- **UOW**: Unit of Work (작업 단위)
- **API**: Application Programming Interface
- **CDK**: Cloud Development Kit (AWS)

# AI-DLC 환영 메시지 (Welcome Message)

**목적**: 이 파일에는 AI-DLC workflow 시작 시 한 번만 (ONCE) 표시할 사용자 대상 환영 메시지가 들어 있다.

---

# 👋 AI-DLC (AI-Driven Development Life Cycle) 에 오신 것을 환영합니다! 👋

여러분의 필요에 맞춰 스스로 조정되는 adaptive 소프트웨어 개발 workflow 를 안내해 드리겠습니다.

## AI-DLC 란?

AI-DLC 는 구조적이면서도 유연한 소프트웨어 개발 과정으로, 프로젝트의 필요에 맞춰 조정됩니다. 다음과 같은 숙련된 소프트웨어 아키텍트가 함께한다고 생각하면 됩니다:

- **요구사항을 분석**하고 필요할 때 명확화 질문을 합니다
- 복잡도와 위험을 근거로 **최적의 접근 방식을 계획**합니다
- 단순한 변경은 **불필요한 단계를 건너뛰고**, 복잡한 프로젝트는 빠짐없이 다룹니다
- **모든 것을 문서화**해 결정과 근거의 전체 기록을 남깁니다
- 명확한 checkpoint 와 승인 관문으로 **각 phase 를 안내**합니다

## 3-Phase 생명주기 (The Three-Phase Lifecycle)

```
                         User Request
                              |
                              v
        +---------------------------------------+
        |     INCEPTION PHASE                   |
        |     Planning & Application Design     |
        +---------------------------------------+
        | * Workspace Detection (ALWAYS)        |
        | * Reverse Engineering (COND)          |
        | * Requirements Analysis (ALWAYS)      |
        | * User Stories (CONDITIONAL)          |
        | * Workflow Planning (ALWAYS)          |
        | * Application Design (CONDITIONAL)    |
        | * Units Generation (CONDITIONAL)      |
        +---------------------------------------+
                              |
                              v
        +---------------------------------------+
        |     CONSTRUCTION PHASE                |
        |     Design, Implementation & Test     |
        +---------------------------------------+
        | * Per-Unit Loop (for each unit):      |
        |   - Functional Design (COND)          |
        |   - NFR Requirements Assess (COND)    |
        |   - NFR Design (COND)                 |
        |   - Infrastructure Design (COND)      |
        |   - Code Generation (ALWAYS)          |
        | * Build and Test (ALWAYS)             |
        +---------------------------------------+
                              |
                              v
        +---------------------------------------+
        |     OPERATIONS PHASE                  |
        |     Deployment & Operation            |
        +---------------------------------------+
        | * Deployment Pipeline (COND)          |
        | * Environment Provisioning (COND)     |
        | * Deployment Execution (COND)         |
        | * Observability Setup (COND)          |
        | * Incident Response (COND)            |
        | * Performance Validation (COND)       |
        | * Feedback & Optimization (COND)      |
        +---------------------------------------+
                              |
                              v
                          Complete
```

### Phase 구성 (Phase Breakdown):

**INCEPTION PHASE** - *계획과 Application Design*
- **목적**: 무엇을 (WHAT) 왜 (WHY) 만들지 결정
- **활동**: 요구사항 이해, 기존 코드 분석 (있는 경우), 접근 방식 계획
- **결과물**: 명확한 요구사항, 실행 계획, 병렬 개발을 위한 unit (작업 단위) 개수 결정
- **여러분의 역할**: 질문에 답변, 계획 검토, 방향 승인

**CONSTRUCTION PHASE** - *상세 설계, 구현, 테스트*
- **목적**: 어떻게 (HOW) 만들지 결정
- **활동**: 상세 설계 (필요 시), 코드 생성, 포괄적 테스트
- **결과물**: 동작하는 코드, 테스트, 빌드 지침
- **여러분의 역할**: 설계 검토, 구현 계획 승인, 결과 검증

**OPERATIONS PHASE** - *배포와 운영*
- **목적**: 어떻게 배포하고 (DEPLOY) 운영할지 (RUN)
- **활동**: 배포 흐름 · 환경 준비, 배포 실행, 관측 · 장애 대응 · 성능 검증, 운영 피드백 (확인된 배포 대상이 있을 때만)
- **결과물**: 배포 전략 · 롤백 runbook, smoke test 결과, SLO · 알람 구성, 장애 대응 runbook, 개선 과제
- **여러분의 역할**: 배포 대상 확인, 외부에 영향을 주는 명령 실행 승인, 운영 결과 검토

## 다음 진행 순서 (What Happens Next):

1. **작업 공간을 분석**해 신규 프로젝트인지 기존 프로젝트인지 파악합니다
2. **요구사항을 수집**하고 필요하면 명확화 질문을 합니다
3. 어떤 stage 를 왜 실행할지 보여주는 **실행 계획을 작성**합니다
4. 여러분이 계획을 **검토하고 승인**합니다 (또는 변경 요청)
5. 주요 stage 마다 checkpoint 를 두고 **계획을 실행**합니다
6. 완전한 문서와 테스트를 갖춘 **동작하는 코드**를 받게 됩니다

시작하겠습니다!

# Functional Design

## 목적 (Purpose)
**unit 별 상세 비즈니스 로직 설계**

Functional Design 의 초점:
- unit 의 상세 비즈니스 로직과 알고리즘
- 엔티티와 관계를 포함한 도메인 모델
- 상세 비즈니스 규칙, 검증 로직, 제약 조건
- 기술 중립적 설계 (인프라 관련 사항 제외)

**참고 (Note)**: Application Design (INCEPTION phase) 의 상위 수준 컴포넌트 설계를 바탕으로 한다

## 사전 조건 (Prerequisites)
- Units Generation 이 완료되어 있어야 한다
- unit (작업 단위) 산출물이 있어야 한다
- Application Design 권장 (상위 수준 컴포넌트 구조 제공)
- 실행 계획에 Functional Design stage 를 실행 (EXECUTE) 하도록 표시되어 있어야 한다

## 개요 (Overview)
unit 의 상세 비즈니스 로직을 설계한다. 기술 중립적으로, 순수하게 비즈니스 기능에 집중한다.

## 실행 단계 (Steps to Execute)

### Step 1: unit 맥락 분석
- `aidlc-docs/inception/application-design/unit-of-work.md` 에서 unit 정의를 읽는다
- `aidlc-docs/inception/application-design/unit-of-work-story-map.md` 에서 배정된 story 를 읽는다
- unit 의 책임과 경계를 파악한다

### Step 2: Functional Design 계획 작성
- 기능 설계용 체크박스 [] 가 있는 계획을 생성한다
- 비즈니스 로직, 도메인 모델, 비즈니스 규칙에 집중한다
- 각 단계마다 체크박스 [] 를 둔다

### Step 3: 맥락에 맞는 질문 생성
**DIRECTIVE (지시)**: unit 정의와 기능 설계 산출물을 철저히 분석하여, 명확히 하면 기능 설계가 나아질 모든 영역을 찾는다. 포괄적으로 이해할 수 있도록 적극적으로 질문한다.

**CRITICAL (필수)**: 기능 설계 품질에 영향을 줄 수 있는 모호함이나 누락된 세부 사항이 하나라도 있으면 기본적으로 질문한다. 잘못된 가정을 하는 것보다 질문을 너무 많이 하는 편이 낫다.

- [Answer]: 태그 형식으로 질문을 문서에 넣는다 (EMBED)
- 모든 모호함, 누락된 정보, 명확화가 필요한 영역에 집중한다
- 사용자 입력이 기능 설계 결정을 개선할 수 있는 곳이면 어디든 질문을 생성한다
- **확신이 없으면 질문한다** - 과신은 나쁜 설계로 이어진다

**고려할 질문 범주** (모든 범주를 평가):
- **비즈니스 로직 모델링 (Business Logic Modeling)** - 핵심 엔티티, 워크플로우, 데이터 변환, 비즈니스 프로세스에 대해 질문
- **도메인 모델 (Domain Model)** - 도메인 개념, 엔티티 관계, 데이터 구조, 비즈니스 객체에 대해 질문
- **비즈니스 규칙 (Business Rules)** - 판단 규칙, 검증 로직, 제약 조건, 비즈니스 정책에 대해 질문
- **데이터 흐름 (Data Flow)** - 데이터 입력, 출력, 변환, 저장 요구사항에 대해 질문
- **연동 지점 (Integration Points)** - 외부 시스템 상호작용, API, 데이터 교환에 대해 질문
- **오류 처리 (Error Handling)** - 오류 시나리오, 검증 실패, 예외 처리에 대해 질문
- **비즈니스 시나리오 (Business Scenarios)** - 경계 사례, 대체 흐름, 복잡한 비즈니스 상황에 대해 질문
- **프런트엔드 컴포넌트 (Frontend Components)** (해당 시) - UI 컴포넌트 구조, 사용자 상호작용, 상태 관리, 폼 처리에 대해 질문

### Step 4: 계획 저장
- `aidlc-docs/construction/plans/{unit-name}-functional-design-plan.md` 로 저장한다
- 사용자 입력을 위한 [Answer]: 태그를 모두 포함한다

### Step 5: 답변 수집 및 분석
- 사용자가 모든 [Answer]: 태그를 채울 때까지 기다린다
- **MANDATORY (필수)**: 모든 답변에 모호하거나 불분명한 내용이 있는지 꼼꼼히 검토한다
- **CRITICAL (필수)**: 불분명한 답변이 하나라도 있으면 후속 질문을 추가한다 - 모호한 상태로 진행하지 않는다
- "depends" (상황에 따라), "maybe" (아마), "not sure" (잘 모름), "mix of" (섞어서), "somewhere between" (그 중간쯤) 같은 답변을 찾는다
- 모호함이 하나라도 발견되면 명확화 질문 파일을 만든다
- **모든 모호함이 해소될 때까지 진행하지 않는다**

### Step 6: Functional Design 산출물 생성
- `aidlc-docs/construction/{unit-name}/functional-design/business-logic-model.md` 생성
- `aidlc-docs/construction/{unit-name}/functional-design/business-rules.md` 생성
- `aidlc-docs/construction/{unit-name}/functional-design/domain-entities.md` 생성
- unit 에 프런트엔드/UI 가 포함되면: `aidlc-docs/construction/{unit-name}/functional-design/frontend-components.md` 생성
  - 컴포넌트 계층과 구조
  - 각 컴포넌트의 props 와 state 정의
  - 사용자 상호작용 흐름
  - 폼 검증 규칙
  - API 연동 지점 (각 컴포넌트가 사용하는 백엔드 endpoint)

### Step 7: 완료 메시지 제시
- 완료 메시지를 다음 구조로 제시한다:
     1. **완료 알림 (Completion Announcement)** (필수): 항상 다음으로 시작:

```markdown
# 🔧 Functional Design 완료 (Functional Design Complete) - [unit-name]
```

     2. **AI 요약 (AI Summary)** (선택): 기능 설계를 구조화된 글머리 기호로 요약
        - 형식: "기능 설계 결과 [description] 을(를) 작성했습니다:"
        - 핵심 비즈니스 로직 모델과 엔티티 나열 (글머리 기호)
        - 정의한 비즈니스 규칙과 검증 로직 나열
        - 도메인 모델 구조와 관계 언급
        - 워크플로우 안내 문구를 넣지 않는다 ("검토해 주세요 (please review)", "알려 주세요 (let me know)", "다음 phase 로 진행 (proceed to next phase)", "진행하기 전에 (before we proceed)")
        - 사실 중심, 내용 중심으로 작성
     3. **정해진 형식의 워크플로우 메시지 (Formatted Workflow Message)** (필수): 항상 정확히 다음 형식으로 끝낸다:

```markdown
> **📋 <u>**검토 필요 (REVIEW REQUIRED):**</u>**  
> 기능 설계 산출물을 검토해 주세요: `aidlc-docs/construction/[unit-name]/functional-design/`



> **🚀 <u>**다음 단계 (WHAT'S NEXT?)**</u>**
>
> **선택할 수 있는 항목:**
>
> 🔧 **변경 요청 (Request Changes)** - 검토 결과에 따라 기능 설계 수정 요청  
> ✅ **다음 Stage 로 진행 (Continue to Next Stage)** - 기능 설계를 승인하고 **[next-stage-name]** 로 진행

---
```

### Step 8: 명시적 승인 대기
- 사용자가 기능 설계를 명시적으로 승인할 때까지 진행하지 않는다
- 승인은 명확하고 모호하지 않아야 한다
- 사용자가 변경을 요청하면 설계를 수정하고 승인 절차를 반복한다

### Step 9: 승인 기록 및 진행 상황 갱신
- audit.md 에 타임스탬프와 함께 승인을 기록한다
- 사용자의 승인 응답을 타임스탬프와 함께 기록한다
- aidlc-state.md 에서 Functional Design stage 를 완료로 표시한다

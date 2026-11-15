# Application Design - 상세 단계

## 목적 (Purpose)
**상위 수준 컴포넌트 식별과 서비스 계층 설계**

Application Design 의 초점:
- 주요 기능 컴포넌트와 그 책임 식별
- 컴포넌트 인터페이스 정의 (상세 비즈니스 로직 제외)
- 오케스트레이션을 위한 서비스 계층 설계
- 컴포넌트 의존성과 통신 패턴 확립

**참고**: 상세 비즈니스 로직 설계는 이후 Functional Design (unit 별, CONSTRUCTION phase) 에서 진행한다

## 선행 조건 (Prerequisites)
- Workspace Detection 이 완료되어 있어야 한다
- Requirements Analysis 권장 (기능 맥락 제공)
- User Stories 권장 (user stories 가 설계 결정을 이끔)
- 실행 계획에서 Application Design stage 를 실행하도록 지정되어 있어야 한다

## 단계별 실행

### 1. 맥락 분석
- `aidlc-docs/inception/requirements/requirements.md` 와 `aidlc-docs/inception/user-stories/stories.md` 를 읽는다
- 핵심 비즈니스 역량과 기능 영역을 식별한다
- 설계 범위와 복잡도를 판단한다

### 2. Application Design 계획 작성
- application design 을 위한 체크박스 [] 가 있는 계획을 작성한다
- 컴포넌트, 책임, 메서드, 비즈니스 규칙, 서비스에 집중한다
- 각 단계와 하위 단계에는 체크박스 [] 가 있어야 한다

### 3. 필수 설계 산출물을 계획에 포함
- 설계 계획에 다음 필수 산출물을 **항상 (ALWAYS)** 포함한다:
  - [ ] 컴포넌트 정의와 상위 수준 책임으로 components.md 생성
  - [ ] 메서드 시그니처로 component-methods.md 생성 (비즈니스 규칙은 이후 Functional Design 에서 상세화)
  - [ ] 서비스 정의와 오케스트레이션 패턴으로 services.md 생성
  - [ ] 의존 관계와 통신 패턴으로 component-dependency.md 생성
  - [ ] 설계의 완전성과 일관성 검증

### 4. 맥락에 맞는 질문 생성
**지시 (DIRECTIVE)**: 요구사항과 스토리를 분석하여 이 특정 application design 과 관련된 질문을 생성한다. 아래 범주를 지침으로 사용한다. 각 범주를 평가하고, 해당 여부가 확실하지 않으면 건너뛰지 말고 질문한다 — 과신은 나쁜 결과로 이어진다 (overconfidence-prevention.md 참조).

- [Answer]: 태그 형식으로 질문을 문서에 넣는다
- 모든 모호함, 누락된 정보, 명확화가 필요한 영역에 집중한다
- 사용자 입력이 설계 결정을 개선할 수 있는 곳이면 어디든 질문을 생성한다
- **확신이 없으면 질문한다** - 과신은 부실한 설계로 이어진다

**평가할 질문 범주** (모든 범주를 고려):
- **컴포넌트 식별** - 컴포넌트 경계, 구성, 그룹화 전략에 대해 질문
- **컴포넌트 메서드** - 메서드 시그니처, 입출력 기대값, 인터페이스 계약에 대해 질문 (상세 비즈니스 규칙은 이후)
- **서비스 계층 설계** - 서비스 오케스트레이션, 경계, 조율 패턴에 대해 질문
- **컴포넌트 의존성** - 통신 패턴, 의존성 관리, 결합도 우려에 대해 질문
- **설계 패턴** - 아키텍처 스타일 선호, 패턴 선택, 설계 제약에 대해 질문

### 5. Application Design 계획 저장
- `aidlc-docs/inception/plans/application-design-plan.md` 로 저장한다
- 사용자 입력을 위한 모든 [Answer]: 태그를 포함한다
- 계획이 설계의 모든 측면을 다루는지 확인한다

### 6. 사용자 입력 요청
- 사용자에게 계획 문서 안의 [Answer]: 태그를 직접 채우도록 요청한다
- 설계 결정의 중요성을 강조한다
- [Answer]: 태그 작성 방법을 명확히 안내한다

### 7. 답변 수집
- 사용자가 문서의 [Answer]: 태그로 모든 질문에 답할 때까지 기다린다
- 모든 [Answer]: 태그가 채워질 때까지 진행하지 않는다
- 문서를 검토하여 비어 있는 [Answer]: 태그가 없는지 확인한다

### 8. 답변 분석 (MANDATORY)
진행하기 전에 모든 사용자 답변을 다음 관점에서 **반드시** 꼼꼼히 검토한다:
- **모호하거나 애매한 응답**: "섞어서 (mix of)", "그 중간쯤 (somewhere between)", "잘 모르겠음 (not sure)", "상황에 따라 (depends)"
- **정의되지 않은 기준이나 용어**: 명확한 정의 없이 개념을 언급
- **모순된 답변**: 서로 충돌하는 응답
- **설계 세부사항 누락**: 구체적 지침이 없는 답변
- **선택지를 합친 답변**: 명확한 결정 규칙 없이 서로 다른 방식을 합친 응답

### 9. 후속 질문 (MANDATORY)
step 8 의 분석에서 모호한 답변이 하나라도 드러나면 **반드시** 다음을 수행한다:
- [Answer]: 태그를 사용해 계획 문서에 구체적 후속 질문을 추가한다
- 모든 모호함이 해소될 때까지 승인 단계로 진행하지 않는다
- 필요한 후속 질문 예시:
  - "'A 와 B 를 섞어서' 라고 하셨는데, A 와 B 중 무엇을 쓸지 정하는 구체적 기준은 무엇인가요?"
  - "'A 와 B 의 중간쯤' 이라고 하셨는데, 정확한 중간 방식을 정의해 주실 수 있나요?"
  - "'잘 모르겠음' 이라고 하셨는데, 결정에 도움이 될 추가 정보는 무엇인가요?"
  - "'복잡도에 따라' 라고 하셨는데, 복잡도 수준을 어떻게 정의하나요?"

### 10. Application Design 산출물 생성
- 승인된 계획을 실행하여 설계 산출물을 생성한다
- 다음 내용으로 `aidlc-docs/inception/application-design/components.md` 를 작성한다:
  - 컴포넌트 이름과 목적
  - 컴포넌트 책임
  - 컴포넌트 인터페이스
- 다음 내용으로 `aidlc-docs/inception/application-design/component-methods.md` 를 작성한다:
  - 각 컴포넌트의 메서드 시그니처
  - 각 메서드의 상위 수준 목적
  - 입출력 타입
  - 참고: 상세 비즈니스 규칙은 Functional Design (unit 별, CONSTRUCTION phase) 에서 정의한다
- 다음 내용으로 `aidlc-docs/inception/application-design/services.md` 를 작성한다:
  - 서비스 정의
  - 서비스 책임
  - 서비스 상호작용과 오케스트레이션
- 다음 내용으로 `aidlc-docs/inception/application-design/component-dependency.md` 를 작성한다:
  - 관계를 보여주는 의존성 매트릭스
  - 컴포넌트 간 통신 패턴
  - 데이터 흐름 다이어그램
- 위에서 작성한 여러 설계 문서를 하나로 통합한 `aidlc-docs/inception/application-design/application-design.md` 를 작성한다.

### 11. 승인 요청 기록
- 승인 요청 문구를 타임스탬프와 함께 `aidlc-docs/audit.md` 에 기록한다
- 승인 요청 문구 전체를 포함한다
- ISO 8601 타임스탬프 형식을 사용한다

### 12. 완료 메시지 제시

```markdown
# 🏗️ Application Design 완료 (Application Design Complete)

[AI 가 작성한 application design 산출물 요약, 글머리표]

> **📋 <u>**검토 필요 (REVIEW REQUIRED):**</u>**  
> application design 산출물을 확인해 주세요: `aidlc-docs/inception/application-design/`

> **🚀 <u>**다음 단계 (WHAT'S NEXT?)**</u>**
>
> **다음 중 선택할 수 있습니다:**
>
> 🔧 **변경 요청 (Request Changes)** - 필요하면 application design 수정 요청
> [Units Generation 을 건너뛰는 경우:]
> 📝 **Units Generation 추가 (Add Units Generation)** - **Units Generation** stage (현재 건너뜀) 를 포함하도록 선택
> ✅ **승인 후 계속 (Approve & Continue)** - 설계를 승인하고 **[Units Generation/CONSTRUCTION PHASE]** 로 진행
```

### 13. 명시적 승인 대기
- 사용자가 application design 을 명시적으로 승인할 때까지 진행하지 않는다
- 승인은 명확하고 모호하지 않아야 한다
- 사용자가 변경을 요청하면 설계를 업데이트하고 승인 절차를 반복한다

### 14. 승인 응답 기록
- 사용자의 승인 응답을 타임스탬프와 함께 `aidlc-docs/audit.md` 에 기록한다
- 사용자 응답 원문을 그대로 포함한다
- 승인 상태를 명확히 표시한다

### 15. 진행 상황 업데이트
- `aidlc-docs/aidlc-state.md` 에서 Application Design stage 를 완료로 표시한다
- "Current Status" 섹션을 업데이트한다
- 다음 stage 로의 전환을 준비한다

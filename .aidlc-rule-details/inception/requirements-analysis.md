# Requirements Analysis (적응형)

**역할을 맡는다**: 제품 책임자 (product owner)

**적응형 Phase**: 항상 실행된다. 상세 수준은 문제 복잡도에 맞춰 조정된다.

**적응형 깊이 설명은 [depth-levels.md](../common/depth-levels.md) 참조**

## 선행 조건
- Workspace Detection 이 완료되어 있어야 한다
- Reverse Engineering 이 완료되어 있어야 한다 (brownfield 인 경우)

## 실행 단계

### Step 1: Reverse Engineering 맥락 불러오기 (있는 경우)

**brownfield (기존 코드) 프로젝트이면**:
- `aidlc-docs/inception/reverse-engineering/architecture.md` 를 불러온다
- `aidlc-docs/inception/reverse-engineering/component-inventory.md` 를 불러온다
- `aidlc-docs/inception/reverse-engineering/technology-stack.md` 를 불러온다
- 요청을 분석할 때 이 문서들로 기존 시스템을 이해한다

### Step 2: 사용자 요청 분석 (의도 분석, Intent Analysis)

#### 2.1 요청 명확성
- **명확 (Clear)**: 구체적이고, 잘 정의되어 있고, 바로 실행 가능
- **모호 (Vague)**: 일반적이고, 애매하며, 명확화 필요
- **불완전 (Incomplete)**: 핵심 정보 누락

#### 2.2 요청 유형
- **New Feature**: 새 기능 추가
- **Bug Fix**: 기존 문제 수정
- **Refactoring**: 코드 구조 개선
- **Upgrade**: 의존성 또는 프레임워크 갱신
- **Migration**: 다른 기술로 이전
- **Enhancement**: 기존 기능 개선
- **New Project**: 처음부터 시작

#### 2.3 초기 범위 추정
- **Single File**: 파일 하나 변경
- **Single Component**: 컴포넌트/패키지 하나 변경
- **Multiple Components**: 여러 컴포넌트에 걸친 변경
- **System-wide**: 시스템 전체에 영향을 주는 변경
- **Cross-system**: 여러 시스템에 영향을 주는 변경

#### 2.4 초기 복잡도 추정
- **Trivial**: 단순하고 간단한 변경
- **Simple**: 구현 경로가 명확함
- **Moderate**: 어느 정도 복잡하고, 고려할 점이 여럿 있음
- **Complex**: 상당히 복잡하고, 고려할 점이 많음

### Step 3: 요구사항 깊이 결정

**요청 분석 결과에 따라 깊이를 정한다:**

**Minimal 깊이** - 다음 경우에 사용:
- 요청이 명확하고 단순함
- 상세 요구사항이 필요 없음
- 기본적인 이해 내용만 문서화

**Standard 깊이** - 다음 경우에 사용:
- 요청에 명확화가 필요함
- 기능 · 비기능 요구사항이 필요함
- 보통 수준의 복잡도

**Comprehensive 깊이** - 다음 경우에 사용:
- 이해관계자가 여럿인 복잡한 프로젝트
- 위험이 높거나 중요한 시스템
- 추적성을 갖춘 상세 요구사항 필요

### Step 4: 현재 요구사항 평가

사용자가 제공한 것은 무엇이든 분석한다:
   - 의도 설명 또는 기술 내용 (audit.md 에 이미 기록됨)
   - 기존 요구사항 문서 (언급되었다면 작업 공간에서 찾는다)
   - 붙여넣은 내용 또는 파일 참조
   - markdown 이 아닌 문서는 모두 markdown 형식으로 변환한다 

### Step 5: 철저한 완전성 분석

**CRITICAL (필수)**: 포괄적인 분석으로 요구사항의 완전성을 평가한다. 모호하거나 빠진 내용이 조금이라도 있으면 질문하는 것을 기본으로 한다.

**MANDATORY (필수)**: 다음 영역을 모두 평가하고, 불명확한 곳이 하나라도 있으면 질문한다:
- **기능 요구사항**: 핵심 기능, 사용자 상호작용, 시스템 동작
- **비기능 요구사항**: 성능, 보안, 확장성, 사용성
- **사용자 시나리오**: 사용 사례, 사용자 여정, 예외 상황 (edge case), 오류 시나리오
- **비즈니스 맥락**: 목표, 제약, 성공 기준, 이해관계자 요구
- **기술 맥락**: 연동 지점, 데이터 요구사항, 시스템 경계
- **품질 속성**: 신뢰성, 유지보수성, 테스트 용이성, 접근성

**의심스러우면 질문한다** - 불완전한 요구사항은 나쁜 구현으로 이어진다.

### Step 5.1: 확장 Opt-In (사용 동의) 질문

**MANDATORY (필수)**: 불러온 모든 `*.opt-in.md` 파일 (워크플로우 시작 시 `extensions/` 하위 폴더에서 불러옴) 에서 `## Opt-In Prompt` 섹션을 찾는다. 이 섹션이 있는 확장마다, 그 질문을 Step 6 에서 만드는 명확화 질문 파일에 포함한다. 각 opt-in 질문은 사용자 대화와 같은 언어로 제시한다.

답변을 받은 뒤:
1. 각 확장의 사용 여부를 `aidlc-docs/aidlc-state.md` 의 `## Extension Configuration` 아래에 기록한다:

```markdown
## Extension Configuration
| Extension | Enabled | Decided At |
|---|---|---|
| [Extension Name] | [Yes/No] | Requirements Analysis |
```

2. **지연 규칙 불러오기 (Deferred Rule Loading)**: 사용자가 사용에 동의한 (opt IN) 확장마다 전체 규칙 파일을 지금 불러온다. 규칙 파일 이름은 명명 규칙으로 정한다: opt-in 파일 이름에서 `.opt-in.md` 를 빼고 `.md` 를 붙인다 (예: `security-baseline.opt-in.md` → `security-baseline.md`). 사용자가 동의하지 않은 (opt OUT) 확장은 전체 규칙 파일을 불러오지 않는다.

### Step 6: 명확화 질문 생성 (능동적 방식)
   - 요구사항이 매우 명확하고 완전한 경우가 아니면 **항상** `aidlc-docs/inception/requirements/requirement-verification-questions.md` 를 만든다
   - 빠졌거나, 불명확하거나, 모호한 영역은 무엇이든 질문한다
   - 기능 요구사항, 비기능 요구사항, 사용자 시나리오, 비즈니스 맥락에 집중한다
   - 사용자에게 질문 문서의 모든 [Answer]: 태그를 직접 채워 달라고 요청한다
   - 답변용 객관식 선택지를 제시하는 경우:
     - 선택지에 A, B, C, D 등으로 라벨을 붙인다
     - 선택지가 서로 배타적이고 겹치지 않게 한다
     - 직접 답변용 선택지를 항상 포함한다: "X) Other (please describe after [Answer]: tag below)"
   - 문서에 사용자 답변이 채워질 때까지 기다린다
   - **MANDATORY (필수)**: 모든 답변의 모호함을 분석하고, 필요하면 후속 질문을 만든다
   - **MANDATORY (필수)**: 모든 모호함이 해소되거나 사용자가 진행을 명시적으로 요청할 때까지 계속 질문한다

### ⛔ 관문 (GATE): 사용자 답변 대기
requirement-verification-questions.md 의 모든 질문에 답이 채워지고 검증될 때까지 Step 7 로 진행하지 않는다.
질문 파일을 사용자에게 보여주고 멈춘다.

### Step 7: 요구사항 문서 생성
   - **선행 조건**: Step 6 관문을 통과해야 한다 — 모든 답변을 받고 분석 완료
   - `aidlc-docs/inception/requirements/requirements.md` 를 만든다
   - 맨 위에 의도 분석 요약을 넣는다:
     - 사용자 요청
     - 요청 유형
     - 범위 추정
     - 복잡도 추정
   - 기능 요구사항과 비기능 요구사항을 모두 넣는다
   - 명확화 질문에 대한 사용자 답변을 반영한다
   - 주요 요구사항을 짧게 요약한다

### Step 8: 상태 추적 갱신

`aidlc-docs/aidlc-state.md` 를 갱신한다:

```markdown
## Stage Progress
### 🔵 INCEPTION PHASE
- [x] Workspace Detection
- [x] Reverse Engineering (if applicable)
- [x] Requirements Analysis
```

### Step 9: 기록 후 진행
   - `aidlc-docs/audit.md` 에 승인 요청을 시각과 함께 기록한다
   - 완료 메시지를 다음 구조로 보여준다:
     1. **완료 알림** (필수): 항상 다음으로 시작한다:

```markdown
# 🔍 Requirements Analysis 완료 (Requirements Analysis Complete)
```

     2. **AI 요약** (선택): 요구사항을 구조화된 글머리표로 요약한다
        - 형식: "요구사항 분석 결과 [프로젝트 유형/복잡도] 로 파악되었습니다:"
        - 주요 기능 요구사항 나열 (글머리표)
        - 주요 비기능 요구사항 나열 (글머리표)
        - 관련 있으면 아키텍처 고려 사항이나 기술 결정 언급
        - 워크플로우 안내 문구는 넣지 않는다 ("검토해 주세요", "알려 주세요", "다음 phase 로 진행", "진행하기 전에")
        - 사실과 내용 중심으로 작성한다
     3. **정해진 형식의 워크플로우 메시지** (필수): 항상 정확히 다음 형식으로 끝낸다:

```markdown
> **📋 <u>**검토 필요 (REVIEW REQUIRED):**</u>**  
> 다음 위치의 요구사항 문서를 검토해 주세요: `aidlc-docs/inception/requirements/requirements.md`



> **🚀 <u>**다음 단계 (WHAT'S NEXT?)**</u>**
>
> **선택할 수 있는 것:**
>
> 🔧 **변경 요청 (Request Changes)** -  검토 결과에 따라 필요하면 요구사항 수정을 요청 
> [User Stories 를 건너뛰는 경우 이 선택지를 추가:]
> 📝 **User Stories 추가 (Add User Stories)** - **User Stories** stage 를 포함하도록 선택 (현재 프로젝트가 단순하여 건너뛰기로 되어 있음)  
> ✅ **승인 후 계속 (Approve & Continue)** - 요구사항을 승인하고 **[User Stories/Workflow Planning]** 으로 진행

---
```

**참고**: "User Stories 추가 (Add User Stories)" 선택지는 User Stories stage 를 건너뛰는 경우에만 넣는다. [User Stories/Workflow Planning] 은 실제 다음 stage 이름으로 바꾼다.

   - 진행하기 전에 사용자의 명시적인 승인을 기다린다
   - 승인 답변을 시각과 함께 기록한다
   - aidlc-state.md 에 Requirements Analysis stage 완료를 반영한다

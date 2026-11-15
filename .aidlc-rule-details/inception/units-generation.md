# Units Generation - 상세 단계

## 개요 (Overview)
이 stage 는 두 개의 연결된 부분을 통해 시스템을 관리 가능한 unit (작업 단위) 으로 분해한다:
- **Part 1 - Planning**: 질문이 담긴 분해 계획을 작성하고, 답변을 수집하고, 모호함을 분석하고, 승인을 받는다
- **Part 2 - Generation**: 승인된 계획을 실행하여 unit 산출물을 생성한다

**정의 (DEFINITION)**: unit of work 는 개발 목적으로 스토리를 논리적으로 묶은 것이다. 마이크로서비스에서는 각 unit 이 독립적으로 배포 가능한 서비스가 된다. 모놀리스에서는 하나의 unit 이 논리적 모듈을 가진 애플리케이션 전체를 나타낸다.

**용어 (Terminology)**: 독립 배포 가능한 컴포넌트는 "Service", 서비스 안의 논리적 묶음은 "Module", 계획 맥락에서는 "Unit of Work" 를 사용한다.

## 선행 조건 (Prerequisites)
- Workspace Detection 이 완료되어 있어야 한다
- Requirements Analysis 권장 (기능 범위 제공)
- User Stories 권장 (스토리가 unit 에 매핑됨)
- Application Design stage 필수 (REQUIRED) (컴포넌트, 메서드, 서비스를 결정)
- 실행 계획에서 Design stage 를 실행하도록 지정되어 있어야 한다

---

# PART 1: PLANNING

## Step 1: Unit of Work 계획 작성
- 시스템을 unit of work 로 분해하기 위한 체크박스 [] 가 있는 계획을 작성한다
- 시스템을 관리 가능한 개발 단위로 나누는 데 집중한다
- 각 단계와 하위 단계에는 체크박스 [] 가 있어야 한다

## Step 2: 필수 Unit 산출물을 계획에 포함
unit 계획에 다음 필수 산출물을 **항상 (ALWAYS)** 포함한다:
- [ ] unit 정의와 책임으로 `aidlc-docs/inception/application-design/unit-of-work.md` 생성
- [ ] 의존성 매트릭스로 `aidlc-docs/inception/application-design/unit-of-work-dependency.md` 생성
- [ ] 스토리를 unit 에 매핑한 `aidlc-docs/inception/application-design/unit-of-work-story-map.md` 생성
- [ ] **Greenfield 전용**: `unit-of-work.md` 에 코드 구성 전략 문서화 (구조 패턴은 code-generation.md 참조)
- [ ] unit 경계와 의존성 검증
- [ ] 모든 스토리가 unit 에 배정되었는지 확인

## Step 3: 맥락에 맞는 질문 생성
**지시 (DIRECTIVE)**: 요구사항, 스토리, application design 을 철저히 분석하여, 명확화가 unit 분해 품질을 높일 모든 영역을 찾는다. 분해 관련 우려를 빠짐없이 다루도록 적극적으로 질문한다.

**CRITICAL (필수)**: unit 경계나 분해 품질에 영향을 줄 수 있는 모호함이나 누락된 세부사항이 조금이라도 있으면 기본적으로 질문한다. 시스템을 어떻게 분해할지 잘못 가정하는 것보다 질문을 너무 많이 하는 편이 낫다.

**MANDATORY (필수)**: 아래 모든 범주에 대해 각각 표적 질문을 하여 평가한다. 각 범주의 해당 여부는 요구사항, 스토리, application design 의 근거로 판단한다 -- 명시적 정당화 없이 범주를 건너뛰지 않는다:

- [Answer]: 태그 형식으로 질문을 문서에 넣는다
- 모든 모호함, 누락된 정보, 명확화가 필요한 영역에 집중한다
- 사용자 입력이 분해 결정을 개선할 수 있는 곳이면 어디든 질문을 생성한다
- **확신이 없으면 질문한다** - 과신은 부실한 unit 경계로 이어진다

**평가할 질문 범주** (모든 범주를 고려):
- **스토리 그룹화** - 그룹화 전략, 스토리 간 친화도, 논리적 묶음 방식에 대해 질문
- **의존성** - 통합 방식, 공유 자원, unit 간 통신 패턴에 대해 질문
- **팀 정렬** - 팀 구조, 소유 경계, 협업 모델에 대해 질문
- **기술적 고려사항** - unit 마다 다를 수 있는 확장성/배포 요구사항에 대해 질문
- **비즈니스 도메인** - 도메인 경계, bounded context, 비즈니스 역량 정렬에 대해 질문
- **코드 구성 (Greenfield 다중 unit 전용)** - 배포 모델과 디렉터리 구조 선호에 대해 질문

## Step 4: UOW 계획 저장
- `aidlc-docs/inception/plans/unit-of-work-plan.md` 로 저장한다
- 사용자 입력을 위한 모든 [Answer]: 태그를 포함한다
- 계획이 시스템 분해의 모든 측면을 다루는지 확인한다

## Step 5: 사용자 입력 요청
- 사용자에게 계획 문서 안의 [Answer]: 태그를 직접 채우도록 요청한다
- 분해 결정의 중요성을 강조한다
- [Answer]: 태그 작성 방법을 명확히 안내한다

## Step 6: 답변 수집
- 사용자가 문서의 [Answer]: 태그로 모든 질문에 답할 때까지 기다린다
- 모든 [Answer]: 태그가 채워질 때까지 진행하지 않는다
- 문서를 검토하여 비어 있는 [Answer]: 태그가 없는지 확인한다

## Step 7: 답변 분석 (MANDATORY)
진행하기 전에 모든 사용자 답변을 다음 관점에서 **반드시** 꼼꼼히 검토한다:
- **모호하거나 애매한 응답**: "섞어서 (mix of)", "그 중간쯤 (somewhere between)", "잘 모르겠음 (not sure)", "상황에 따라 (depends)"
- **정의되지 않은 기준이나 용어**: 명확한 정의 없이 개념을 언급
- **모순된 답변**: 서로 충돌하는 응답
- **생성 세부사항 누락**: 구체적 지침이 없는 답변
- **선택지를 합친 답변**: 명확한 결정 규칙 없이 서로 다른 방식을 합친 응답

## Step 8: 후속 질문 (MANDATORY)
step 7 의 분석에서 모호한 답변이 하나라도 드러나면 **반드시** 다음을 수행한다:
- [Answer]: 태그를 사용해 계획 문서에 구체적 후속 질문을 추가한다
- 모든 모호함이 해소될 때까지 승인 단계로 진행하지 않는다
- 필요한 후속 질문 예시:
  - "'A 와 B 를 섞어서' 라고 하셨는데, A 와 B 중 무엇을 쓸지 정하는 구체적 기준은 무엇인가요?"
  - "'A 와 B 의 중간쯤' 이라고 하셨는데, 정확한 중간 방식을 정의해 주실 수 있나요?"
  - "'잘 모르겠음' 이라고 하셨는데, 결정에 도움이 될 추가 정보는 무엇인가요?"
  - "'복잡도에 따라' 라고 하셨는데, 복잡도 수준을 어떻게 정의하나요?"

## Step 9: 승인 요청
- 다음과 같이 묻는다: "**Unit of work 계획이 완료되었습니다. aidlc-docs/inception/plans/unit-of-work-plan.md 에서 계획을 검토해 주세요. 생성 단계로 진행할까요?**"
- 사용자가 확인할 때까지 진행하지 않는다 (DO NOT PROCEED)

## Step 10: 승인 기록
- 요청 문구와 응답을 타임스탬프와 함께 audit.md 에 기록한다
- ISO 8601 타임스탬프 형식을 사용한다
- 승인 요청 문구 전체를 포함한다

## Step 11: 진행 상황 업데이트
- aidlc-state.md 에서 Units Generation Part 1 (Planning) 을 완료로 표시한다
- "Current Status" 섹션을 업데이트한다
- Units Generation Part 2 (Generation) 로의 전환을 준비한다

---

# PART 2: GENERATION

## Step 12: Unit of Work 계획 불러오기
- [ ] `aidlc-docs/inception/plans/unit-of-work-plan.md` 에서 계획 전체를 읽는다
- [ ] 완료되지 않은 다음 단계 (첫 번째 [ ] 체크박스) 를 찾는다
- [ ] 해당 단계의 맥락과 요구사항을 불러온다

## Step 13: 현재 단계 실행
- [ ] 현재 단계에 적힌 내용을 정확히 수행한다
- [ ] 계획에 명시된 대로 unit 산출물을 생성한다
- [ ] Planning 에서 승인된 분해 방식을 따른다
- [ ] 계획에 명시된 기준과 경계를 사용한다

## Step 14: 진행 상황 업데이트
- [ ] unit of work 계획에서 완료한 단계를 [x] 로 표시한다
- [ ] `aidlc-docs/aidlc-state.md` 의 현재 상태를 업데이트한다
- [ ] 생성한 모든 산출물을 저장한다

## Step 15: 계속 또는 완료
- [ ] 남은 단계가 있으면 Step 12 로 돌아간다
- [ ] 모든 단계가 끝나면 unit 이 설계 stage 를 위한 준비가 되었는지 확인한다
- [ ] Units Generation stage 를 완료로 표시한다

## Step 16: 완료 메시지 제시

```markdown
# 🔧 Units Generation 완료 (Units Generation Complete)

[AI 가 작성한 unit 과 분해 결과 요약, 글머리표]

> **📋 <u>**검토 필요 (REVIEW REQUIRED):**</u>**  
> units generation 산출물을 확인해 주세요: `aidlc-docs/inception/application-design/`

> **🚀 <u>**다음 단계 (WHAT'S NEXT?)**</u>**
>
> **다음 중 선택할 수 있습니다:**
>
> 🔧 **변경 요청 (Request Changes)** - 필요하면 units generation 수정 요청
> ✅ **승인 후 계속 (Approve & Continue)** - unit 을 승인하고 **CONSTRUCTION PHASE** 로 진행
```

## Step 17: 명시적 승인 대기
- 사용자가 units generation 을 명시적으로 승인할 때까지 진행하지 않는다
- 승인은 명확하고 모호하지 않아야 한다
- 사용자가 변경을 요청하면 unit 을 업데이트하고 승인 절차를 반복한다

## Step 18: 승인 응답 기록
- 사용자의 승인 응답을 타임스탬프와 함께 `aidlc-docs/audit.md` 에 기록한다
- 사용자 응답 원문을 그대로 포함한다
- 승인 상태를 명확히 표시한다

## Step 19: 진행 상황 업데이트
- `aidlc-docs/aidlc-state.md` 에서 Units Generation stage 를 완료로 표시한다
- "Current Status" 섹션을 업데이트한다
- CONSTRUCTION PHASE 로의 전환을 준비한다

---

## 핵심 규칙 (Critical Rules)

### Planning Phase 규칙
- 맥락과 관련된 질문만 생성한다
- 모든 질문에 [Answer]: 태그 형식을 사용한다
- 진행하기 전에 모든 답변의 모호함을 분석한다
- 후속 질문으로 모든 모호함을 해소한다
- 생성 전에 사용자의 명시적 승인을 받는다

### Generation Phase 규칙
- **하드코딩된 로직 금지 (NO HARDCODED LOGIC)**: unit of work 계획에 적힌 것만 실행한다
- **계획을 정확히 따름 (FOLLOW PLAN EXACTLY)**: 단계 순서에서 벗어나지 않는다
- **체크박스 업데이트 (UPDATE CHECKBOXES)**: 각 단계를 마치는 즉시 [x] 로 표시한다
- **승인된 방식 사용 (USE APPROVED APPROACH)**: Planning 에서 정한 분해 방법론을 따른다
- **완료 확인 (VERIFY COMPLETION)**: 진행하기 전에 모든 unit 산출물이 완성되었는지 확인한다

## 완료 기준 (Completion Criteria)
- 모든 계획 질문에 답했고 모호함이 해소됨
- 계획에 대한 사용자 승인을 받음
- unit of work 계획의 모든 단계가 [x] 로 표시됨
- 계획에 따라 모든 unit 산출물이 생성됨:
  - unit 정의가 담긴 `unit-of-work.md`
  - 의존성 매트릭스가 담긴 `unit-of-work-dependency.md`
  - 스토리 매핑이 담긴 `unit-of-work-story-map.md`
- unit 이 검증되어 unit 별 설계 stage 를 위한 준비가 됨

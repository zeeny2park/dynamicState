# Code Generation - 상세 단계 (Detailed Steps)

## 개요 (Overview)
이 stage 는 각 unit (작업 단위) 의 코드를 서로 연결된 두 부분으로 생성한다:
- **Part 1 - 계획 (Planning)**: 명시적인 단계가 담긴 상세 코드 생성 계획을 작성
- **Part 2 - 생성 (Generation)**: 승인된 계획을 실행하여 코드, 테스트, 산출물을 생성

**참고 (Note)**: brownfield (기존 코드) 프로젝트에서 "생성 (generate)" 은 적절한 경우 기존 파일을 수정한다는 뜻이며, 중복 파일을 만드는 것이 아니다.

## 사전 조건 (Prerequisites)
- 해당 unit 의 Unit Design Generation 이 완료되어 있어야 한다
- 해당 unit 의 NFR Implementation (실행한 경우) 이 완료되어 있어야 한다
- 모든 unit 설계 산출물이 있어야 한다
- unit 이 코드 생성 준비가 되어 있어야 한다

---

# PART 1: 계획 (PLANNING)

## Step 1: unit 맥락 분석
- [ ] Unit Design Generation 의 unit 설계 산출물을 읽는다
- [ ] unit story map 을 읽어 배정된 story 를 파악한다
- [ ] unit 의존성과 인터페이스를 파악한다
- [ ] unit 이 코드 생성 준비가 되었는지 검증한다

## Step 2: 상세 unit 코드 생성 계획 작성
- [ ] `aidlc-docs/aidlc-state.md` 에서 workspace 루트와 프로젝트 유형을 읽는다
- [ ] 코드 위치를 정한다 (구조 패턴은 핵심 규칙 (Critical Rules) 참조)
- [ ] **brownfield 전용**: reverse engineering 의 code-structure.md 를 검토하여 수정할 기존 파일을 찾는다
- [ ] 정확한 경로를 문서화한다 (aidlc-docs/ 는 절대 안 됨)
- [ ] unit 생성을 위한 명시적 단계를 만든다:
  - 프로젝트 구조 구성 (Project Structure Setup) (greenfield 전용)
  - 비즈니스 로직 생성 (Business Logic Generation)
  - 비즈니스 로직 단위 테스트 (Business Logic Unit Testing)
  - 비즈니스 로직 요약 (Business Logic Summary)
  - API 계층 생성 (API Layer Generation)
  - API 계층 단위 테스트 (API Layer Unit Testing)
  - API 계층 요약 (API Layer Summary)
  - Repository 계층 생성 (Repository Layer Generation)
  - Repository 계층 단위 테스트 (Repository Layer Unit Testing)
  - Repository 계층 요약 (Repository Layer Summary)
  - 프런트엔드 컴포넌트 생성 (Frontend Components Generation) (해당 시)
  - 프런트엔드 컴포넌트 단위 테스트 (Frontend Components Unit Testing) (해당 시)
  - 프런트엔드 컴포넌트 요약 (Frontend Components Summary) (해당 시)
  - 데이터베이스 마이그레이션 스크립트 (Database Migration Scripts) (데이터 모델이 있는 경우)
  - 문서 생성 (Documentation Generation) (API 문서, README 갱신)
  - 배포 산출물 생성 (Deployment Artifacts Generation)
- [ ] 각 단계에 순서대로 번호를 매긴다
- [ ] story 대응 참조를 포함한다
- [ ] 각 단계에 체크박스 [ ] 를 추가한다

## Step 3: unit 생성 맥락 포함
- [ ] 이 unit 에 대해 다음을 포함한다:
  - 이 unit 이 구현하는 story
  - 다른 unit/서비스에 대한 의존성
  - 예상 인터페이스와 계약
  - 이 unit 이 소유하는 데이터베이스 엔티티
  - 서비스 경계와 책임

## Step 4: unit 계획 문서 작성
- [ ] 전체 계획을 `aidlc-docs/construction/plans/{unit-name}-code-generation-plan.md` 로 저장한다
- [ ] 단계 번호 (Step 1, Step 2 등) 를 포함한다
- [ ] unit 맥락과 의존성을 포함한다
- [ ] story 추적성을 포함한다
- [ ] 계획을 단계별로 실행할 수 있게 한다
- [ ] 이 계획이 Code Generation 의 유일한 기준 (single source of truth) 임을 강조한다

## Step 5: unit 계획 요약
- [ ] 사용자에게 unit 코드 생성 계획 요약을 제공한다
- [ ] unit 생성 방식을 강조한다
- [ ] 단계 순서와 story 포함 범위를 설명한다
- [ ] 전체 단계 수와 예상 범위를 적는다

## Step 6: 승인 요청 기록
- [ ] 승인을 요청하기 전에 `aidlc-docs/audit.md` 에 요청 내용을 타임스탬프와 함께 기록한다
- [ ] 전체 unit 코드 생성 계획에 대한 참조를 포함한다
- [ ] ISO 8601 타임스탬프 형식을 사용한다

## Step 7: 명시적 승인 대기
- [ ] 사용자가 unit 코드 생성 계획을 명시적으로 승인할 때까지 진행하지 않는다
- [ ] 승인은 전체 계획과 생성 순서를 포괄해야 한다
- [ ] 사용자가 변경을 요청하면 계획을 수정하고 승인 절차를 반복한다

## Step 8: 승인 응답 기록
- [ ] 사용자의 승인 응답을 `aidlc-docs/audit.md` 에 타임스탬프와 함께 기록한다
- [ ] 사용자 응답 원문을 그대로 포함한다
- [ ] 승인 상태를 명확히 표시한다

## Step 9: 진행 상황 갱신
- [ ] `aidlc-state.md` 에서 Code Generation Part 1 (Planning) 을 완료로 표시한다
- [ ] "Current Status" 섹션을 갱신한다
- [ ] Code Generation 으로 넘어갈 준비를 한다

---

# PART 2: 생성 (GENERATION)

## Step 10: unit 코드 생성 계획 불러오기
- [ ] `aidlc-docs/construction/plans/{unit-name}-code-generation-plan.md` 에서 전체 계획을 읽는다
- [ ] 아직 완료되지 않은 다음 단계 (첫 번째 [ ] 체크박스) 를 찾는다
- [ ] 그 단계의 맥락 (unit, 의존성, story) 을 불러온다

## Step 11: 현재 단계 실행
- [ ] 계획에서 대상 디렉터리를 확인한다 (aidlc-docs/ 는 절대 안 됨)
- [ ] **brownfield 전용**: 대상 파일이 있는지 확인한다
- [ ] 현재 단계가 설명하는 것을 정확히 생성한다:
  - **파일이 있으면**: 그 자리에서 수정한다 (`ClassName_modified.java`, `ClassName_new.java` 등을 절대 만들지 않는다)
  - **파일이 없으면**: 새 파일을 만든다
- [ ] 올바른 위치에 작성한다:
  - **애플리케이션 코드 (Application Code)**: 프로젝트 구조에 따른 workspace 루트
  - **문서 (Documentation)**: `aidlc-docs/construction/{unit-name}/code/` (markdown 만)
  - **빌드/설정 파일 (Build/Config Files)**: workspace 루트
- [ ] unit story 요구사항을 따른다
- [ ] 의존성과 인터페이스를 지킨다

## Step 12: 진행 상황 갱신
- [ ] unit 코드 생성 계획에서 완료한 단계를 [x] 로 표시한다
- [ ] 관련 unit story 의 생성이 끝나면 [x] 로 표시한다
- [ ] `aidlc-docs/aidlc-state.md` 의 현재 상태를 갱신한다
- [ ] **brownfield 전용**: 중복 파일이 생기지 않았는지 검증한다 (예: `ClassName.java` 옆에 `ClassName_modified.java` 가 없어야 함)
- [ ] 생성한 모든 산출물을 저장한다

## Step 13: 생성 계속 또는 완료
- [ ] 남은 단계가 있으면 Step 10 으로 돌아간다
- [ ] 모든 단계가 완료되면 완료 메시지 제시로 넘어간다

## Step 14: 완료 메시지 제시
- 완료 메시지를 다음 구조로 제시한다:
     1. **완료 알림 (Completion Announcement)** (필수): 항상 다음으로 시작:

```markdown
# 💻 Code Generation 완료 (Code Generation Complete) - [unit-name]
```

     2. **AI 요약 (AI Summary)** (선택): 구조화된 글머리 기호 요약 제공
        - **Brownfield**: 수정한 파일과 생성한 파일을 구분한다 (예: "• 수정 (Modified): `src/services/user-service.ts`", "• 생성 (Created): `src/services/auth-service.ts`")
        - **Greenfield**: 생성한 파일을 경로와 함께 나열한다 (예: "• 생성 (Created): `src/services/user-service.ts`")
        - 테스트, 문서, 배포 산출물을 경로와 함께 나열한다
        - 사실 중심, 워크플로우 안내 문구 없이 작성
     3. **정해진 형식의 워크플로우 메시지 (Formatted Workflow Message)** (필수): 항상 정확히 다음 형식으로 끝낸다:

```markdown
> **📋 <u>**검토 필요 (REVIEW REQUIRED):**</u>**  
> 생성된 코드를 검토해 주세요:
> - **애플리케이션 코드 (Application Code)**: `[actual-workspace-path]`
> - **문서 (Documentation)**: `aidlc-docs/construction/[unit-name]/code/`



> **🚀 <u>**다음 단계 (WHAT'S NEXT?)**</u>**
>
> **선택할 수 있는 항목:**
>
> 🔧 **변경 요청 (Request Changes)** - 검토 결과에 따라 생성된 코드 수정 요청  
> ✅ **다음 Stage 로 진행 (Continue to Next Stage)** - 코드 생성을 승인하고 **[next-unit/Build & Test]** 로 진행

---
```

## Step 15: 명시적 승인 대기
- 사용자가 생성된 코드를 명시적으로 승인할 때까지 진행하지 않는다
- 승인은 명확하고 모호하지 않아야 한다
- 사용자가 변경을 요청하면 코드를 수정하고 승인 절차를 반복한다

## Step 16: 승인 기록 및 진행 상황 갱신
- audit.md 에 타임스탬프와 함께 승인을 기록한다
- 사용자의 승인 응답을 타임스탬프와 함께 기록한다
- aidlc-state.md 에서 이 unit 의 Code Generation stage 를 완료로 표시한다

---

## 핵심 규칙 (Critical Rules)

### 코드 위치 규칙 (Code Location Rules)
- **애플리케이션 코드**: workspace 루트에만 둔다 (aidlc-docs/ 는 절대 안 됨)
- **문서**: aidlc-docs/ 에만 둔다 (markdown 요약)
- 코드를 생성하기 전에 aidlc-state.md 에서 **workspace 루트를 읽는다**

**프로젝트 유형별 구조 패턴**:
- **Brownfield**: 기존 구조를 사용한다 (예: `src/main/java/`, `lib/`, `pkg/`)
- **Greenfield 단일 unit**: workspace 루트에 `src/`, `tests/`, `config/`
- **Greenfield 다중 unit (microservices)**: `{unit-name}/src/`, `{unit-name}/tests/`
- **Greenfield 다중 unit (monolith)**: `src/{unit-name}/`, `tests/{unit-name}/`

### Brownfield 파일 수정 규칙 (Brownfield File Modification Rules)
- 생성하기 전에 파일이 있는지 확인한다
- 있으면: 그 자리에서 수정한다 (`ClassName_modified.java` 같은 사본을 절대 만들지 않는다)
- 없으면: 새 파일을 만든다
- 생성 후 중복 파일이 없는지 검증한다 (Step 12)

### 계획 단계 규칙 (Planning Phase Rules)
- 모든 생성 활동에 대해 번호가 매겨진 명시적 단계를 만든다
- 계획에 story 추적성을 포함한다
- unit 맥락과 의존성을 문서화한다
- 생성하기 전에 사용자의 명시적 승인을 받는다

### 생성 단계 규칙 (Generation Phase Rules)
- **하드코딩된 로직 금지 (NO HARDCODED LOGIC)**: unit 계획에 적힌 것만 실행한다
- **계획을 정확히 따른다 (FOLLOW PLAN EXACTLY)**: 단계 순서에서 벗어나지 않는다
- **체크박스 갱신 (UPDATE CHECKBOXES)**: 각 단계를 마치면 즉시 [x] 로 표시한다
- **story 추적성 (STORY TRACEABILITY)**: 기능이 구현되면 unit story 를 [x] 로 표시한다
- **의존성 준수 (RESPECT DEPENDENCIES)**: unit 의존성이 충족된 경우에만 구현한다

### 자동화 친화적 코드 규칙 (Automation Friendly Code Rules)
UI 코드 (웹, 모바일, 데스크톱) 를 생성할 때 요소가 자동화 친화적이 되도록 한다:
- 상호작용 요소 (버튼, 입력, 링크, 폼) 에 `data-testid` 속성을 추가한다
- 일관된 이름 규칙을 사용한다: `{component}-{element-role}` (예: `login-form-submit-button`, `user-list-search-input`)
- 렌더링할 때마다 바뀌는 동적 또는 자동 생성 ID 를 피한다
- 코드가 바뀌어도 `data-testid` 값을 안정적으로 유지한다 (요소의 목적이 바뀔 때만 변경)

## 완료 기준 (Completion Criteria)
- 전체 unit 코드 생성 계획이 작성되고 승인됨
- unit 코드 생성 계획의 모든 단계가 [x] 로 표시됨
- 모든 unit story 가 계획에 따라 구현됨
- 모든 코드와 테스트가 생성됨 (테스트는 Build & Test phase 에서 실행됨)
- 배포 산출물이 생성됨
- 전체 unit 이 빌드 및 검증 준비가 됨

# Infrastructure Design

## 사전 조건 (Prerequisites)
- 해당 unit 의 Functional Design 이 완료되어 있어야 한다
- NFR Design 권장 (대응시킬 논리 컴포넌트 제공)
- 실행 계획에 Infrastructure Design stage 를 실행 (EXECUTE) 하도록 표시되어 있어야 한다

## 개요 (Overview)
논리 소프트웨어 컴포넌트를 배포 환경의 실제 인프라 선택에 대응시킨다.

## 실행 단계 (Steps to Execute)

### Step 1: 설계 산출물 분석
- `aidlc-docs/construction/{unit-name}/functional-design/` 에서 기능 설계를 읽는다
- `aidlc-docs/construction/{unit-name}/nfr-design/` 에서 NFR 설계를 읽는다 (있는 경우)
- 인프라가 필요한 논리 컴포넌트를 찾는다

### Step 2: Infrastructure Design 계획 작성
- 인프라 설계용 체크박스 [] 가 있는 계획을 생성한다
- 실제 서비스 (AWS, Azure, GCP, 온프레미스) 로의 대응에 집중한다
- 각 단계마다 체크박스 [] 를 둔다

### Step 3: 맥락에 맞는 질문 생성
**DIRECTIVE (지시)**: 기능 설계와 NFR 설계를 철저히 분석하여, 명확히 하면 인프라 결정이 나아질 모든 영역을 찾는다. 인프라를 포괄적으로 다룰 수 있도록 적극적으로 질문한다.

**CRITICAL (필수)**: 인프라 품질에 영향을 줄 수 있는 모호함이나 누락된 세부 사항이 하나라도 있으면 기본적으로 질문한다. 잘못된 인프라 가정을 하는 것보다 질문을 너무 많이 하는 편이 낫다.

**MANDATORY (필수)**: 다음 범주 모두에 대해 각각 구체적인 질문을 하여 평가한다. 범주마다 기능 설계 및 NFR 설계 산출물의 근거를 바탕으로 해당 여부를 판단한다 -- 명시적인 근거 없이 범주를 건너뛰지 않는다:

- [Answer]: 태그 형식으로 질문을 문서에 넣는다 (EMBED)
- 모든 모호함, 누락된 정보, 명확화가 필요한 영역에 집중한다
- 사용자 입력이 인프라 결정을 개선할 수 있는 곳이면 어디든 질문을 생성한다
- **확신이 없으면 질문한다** - 과신은 나쁜 인프라 선택으로 이어진다

**평가할 질문 범주** (모든 범주를 고려):
- **배포 환경 (Deployment Environment)** - 클라우드 제공자 선호, 환경 구성, 배포 대상에 대해 질문
- **컴퓨팅 인프라 (Compute Infrastructure)** - 컴퓨팅 서비스 선택, 규모 산정, 확장 요구사항에 대해 질문
- **스토리지 인프라 (Storage Infrastructure)** - 데이터베이스 선택, 저장 패턴, 데이터 수명 주기 요구에 대해 질문
- **메시징 인프라 (Messaging Infrastructure)** - 메시징/큐 서비스, 이벤트 기반 패턴, 비동기 처리에 대해 질문
- **네트워킹 인프라 (Networking Infrastructure)** - 부하 분산, API gateway 방식, 네트워크 구성에 대해 질문
- **모니터링 인프라 (Monitoring Infrastructure)** - 관측성 (observability) 도구, 알림 전략, 로깅 요구사항에 대해 질문
- **공유 인프라 (Shared Infrastructure)** - 인프라 공유 전략, 멀티 테넌시, 자원 격리에 대해 질문

### Step 4: 계획 저장
- `aidlc-docs/construction/plans/{unit-name}-infrastructure-design-plan.md` 로 저장한다
- 사용자 입력을 위한 [Answer]: 태그를 모두 포함한다

### Step 5: 답변 수집 및 분석
- 사용자가 모든 [Answer]: 태그를 채울 때까지 기다린다
- 모호하거나 불분명한 답변이 있는지 검토한다
- 필요하면 후속 질문을 추가한다

### Step 6: Infrastructure Design 산출물 생성
- `aidlc-docs/construction/{unit-name}/infrastructure-design/infrastructure-design.md` 생성
- `aidlc-docs/construction/{unit-name}/infrastructure-design/deployment-architecture.md` 생성
- 공유 인프라가 있으면: `aidlc-docs/construction/shared-infrastructure.md` 생성

### Step 7: 완료 메시지 제시
- 완료 메시지를 다음 구조로 제시한다:
     1. **완료 알림 (Completion Announcement)** (필수): 항상 다음으로 시작:

```markdown
# 🏢 Infrastructure Design 완료 (Infrastructure Design Complete) - [unit-name]
```

     2. **AI 요약 (AI Summary)** (선택): 인프라 설계를 구조화된 글머리 기호로 요약
        - 형식: "인프라 설계에서 [description] 을(를) 대응시켰습니다:"
        - 핵심 인프라 서비스와 컴포넌트 나열 (글머리 기호)
        - 배포 아키텍처 결정과 근거 나열
        - 클라우드 제공자 선택과 서비스 대응 언급
        - 워크플로우 안내 문구를 넣지 않는다 ("검토해 주세요 (please review)", "알려 주세요 (let me know)", "다음 phase 로 진행 (proceed to next phase)", "진행하기 전에 (before we proceed)")
        - 사실 중심, 내용 중심으로 작성
     3. **정해진 형식의 워크플로우 메시지 (Formatted Workflow Message)** (필수): 항상 정확히 다음 형식으로 끝낸다:

```markdown
> **📋 <u>**검토 필요 (REVIEW REQUIRED):**</u>**  
> 인프라 설계를 검토해 주세요: `aidlc-docs/construction/[unit-name]/infrastructure-design/`



> **🚀 <u>**다음 단계 (WHAT'S NEXT?)**</u>**
>
> **선택할 수 있는 항목:**
>
> 🔧 **변경 요청 (Request Changes)** - 검토 결과에 따라 인프라 설계 수정 요청  
> ✅ **다음 Stage 로 진행 (Continue to Next Stage)** - 인프라 설계를 승인하고 **Code Generation** 으로 진행

---
```

### Step 8: 명시적 승인 대기
- 사용자가 인프라 설계를 명시적으로 승인할 때까지 진행하지 않는다
- 승인은 명확하고 모호하지 않아야 한다
- 사용자가 변경을 요청하면 설계를 수정하고 승인 절차를 반복한다

### Step 9: 승인 기록 및 진행 상황 갱신
- audit.md 에 타임스탬프와 함께 승인을 기록한다
- 사용자의 승인 응답을 타임스탬프와 함께 기록한다
- aidlc-state.md 에서 Infrastructure Design stage 를 완료로 표시한다

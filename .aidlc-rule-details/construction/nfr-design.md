# NFR Design

## 사전 조건 (Prerequisites)
- 해당 unit 의 NFR Requirements 가 완료되어 있어야 한다
- NFR 요구사항 산출물이 있어야 한다
- 실행 계획에 NFR Design stage 를 실행 (EXECUTE) 하도록 표시되어 있어야 한다

## 개요 (Overview)
패턴과 논리 컴포넌트를 사용해 NFR 요구사항을 unit 설계에 반영한다.

## 실행 단계 (Steps to Execute)

### Step 1: NFR Requirements 분석
- `aidlc-docs/construction/{unit-name}/nfr-requirements/` 에서 NFR 요구사항을 읽는다
- 확장성, 성능, 가용성, 보안 요구를 파악한다

### Step 2: NFR Design 계획 작성
- NFR 설계용 체크박스 [] 가 있는 계획을 생성한다
- 설계 패턴과 논리 컴포넌트에 집중한다
- 각 단계마다 체크박스 [] 를 둔다

### Step 3: 맥락에 맞는 질문 생성
**DIRECTIVE (지시)**: NFR 요구사항을 철저히 분석하여, 명확히 하면 NFR 설계 품질이 나아질 모든 영역을 찾는다. 비기능 설계를 포괄적으로 다룰 수 있도록 적극적으로 질문한다.

**CRITICAL (필수)**: NFR 설계 품질에 영향을 줄 수 있는 모호함이나 누락된 세부 사항이 하나라도 있으면 기본적으로 질문한다. 비기능 패턴에 대해 잘못된 가정을 하는 것보다 질문을 너무 많이 하는 편이 낫다.

**MANDATORY (필수)**: 다음 범주 모두에 대해 각각 구체적인 질문을 하여 평가한다. 범주마다 NFR 요구사항의 근거를 바탕으로 해당 여부를 판단한다 -- 명시적인 근거 없이 범주를 건너뛰지 않는다:

- [Answer]: 태그 형식으로 질문을 문서에 넣는다 (EMBED)
- 모든 모호함, 누락된 정보, 명확화가 필요한 영역에 집중한다
- 사용자 입력이 패턴 및 컴포넌트 결정을 개선할 수 있는 곳이면 어디든 질문을 생성한다
- **확신이 없으면 질문한다** - 과신은 나쁜 비기능 설계로 이어진다

**평가할 질문 범주** (모든 범주를 고려):
- **복원력 패턴 (Resilience Patterns)** - 장애 허용 방식, 재시도 전략, 장애 복구 기대치에 대해 질문
- **확장성 패턴 (Scalability Patterns)** - 확장 방식, 부하 한계, 증가 전망에 대해 질문
- **성능 패턴 (Performance Patterns)** - 최적화 전략, 지연 시간 목표, 처리량 요구사항에 대해 질문
- **보안 패턴 (Security Patterns)** - 보안 구현 방식, 위협 모델, 규정 준수 제약에 대해 질문
- **논리 컴포넌트 (Logical Components)** - 인프라 컴포넌트 (queue, cache, circuit breaker 등) 와 그 연동 패턴에 대해 질문

### Step 4: 계획 저장
- `aidlc-docs/construction/plans/{unit-name}-nfr-design-plan.md` 로 저장한다
- 사용자 입력을 위한 [Answer]: 태그를 모두 포함한다

### Step 5: 답변 수집 및 분석
- 사용자가 모든 [Answer]: 태그를 채울 때까지 기다린다
- 모호하거나 불분명한 답변이 있는지 검토한다
- 필요하면 후속 질문을 추가한다

### Step 6: NFR Design 산출물 생성
- `aidlc-docs/construction/{unit-name}/nfr-design/nfr-design-patterns.md` 생성
- `aidlc-docs/construction/{unit-name}/nfr-design/logical-components.md` 생성

### Step 7: 완료 메시지 제시
- 완료 메시지를 다음 구조로 제시한다:
     1. **완료 알림 (Completion Announcement)** (필수): 항상 다음으로 시작:

```markdown
# 🎨 NFR Design 완료 (NFR Design Complete) - [unit-name]
```

     2. **AI 요약 (AI Summary)** (선택): NFR 설계를 구조화된 글머리 기호로 요약
        - 형식: "NFR 설계에 [description] 을(를) 반영했습니다:"
        - 적용한 핵심 설계 패턴 나열 (글머리 기호)
        - 논리 컴포넌트와 인프라 요소 나열
        - 적용한 복원력, 확장성, 성능 패턴 언급
        - 워크플로우 안내 문구를 넣지 않는다 ("검토해 주세요 (please review)", "알려 주세요 (let me know)", "다음 phase 로 진행 (proceed to next phase)", "진행하기 전에 (before we proceed)")
        - 사실 중심, 내용 중심으로 작성
     3. **정해진 형식의 워크플로우 메시지 (Formatted Workflow Message)** (필수): 항상 정확히 다음 형식으로 끝낸다:

```markdown
> **📋 <u>**검토 필요 (REVIEW REQUIRED):**</u>**  
> NFR 설계를 검토해 주세요: `aidlc-docs/construction/[unit-name]/nfr-design/`



> **🚀 <u>**다음 단계 (WHAT'S NEXT?)**</u>**
>
> **선택할 수 있는 항목:**
>
> 🔧 **변경 요청 (Request Changes)** - 검토 결과에 따라 NFR 설계 수정 요청  
> ✅ **다음 Stage 로 진행 (Continue to Next Stage)** - NFR 설계를 승인하고 **[next-stage-name]** 로 진행

---
```

### Step 8: 명시적 승인 대기
- 사용자가 NFR 설계를 명시적으로 승인할 때까지 진행하지 않는다
- 승인은 명확하고 모호하지 않아야 한다
- 사용자가 변경을 요청하면 설계를 수정하고 승인 절차를 반복한다

### Step 9: 승인 기록 및 진행 상황 갱신
- audit.md 에 타임스탬프와 함께 승인을 기록한다
- 사용자의 승인 응답을 타임스탬프와 함께 기록한다
- aidlc-state.md 에서 NFR Design stage 를 완료로 표시한다

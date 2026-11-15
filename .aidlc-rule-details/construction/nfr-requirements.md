# NFR Requirements

## 사전 조건 (Prerequisites)
- 해당 unit 의 Functional Design 이 완료되어 있어야 한다
- unit 기능 설계 산출물이 있어야 한다
- 실행 계획에 NFR Requirements stage 를 실행 (EXECUTE) 하도록 표시되어 있어야 한다

## 개요 (Overview)
unit 의 NFR (비기능 요구사항) 을 정하고 기술 스택을 선택한다.

## 실행 단계 (Steps to Execute)

### Step 1: Functional Design 분석
- `aidlc-docs/construction/{unit-name}/functional-design/` 에서 기능 설계 산출물을 읽는다
- 비즈니스 로직의 복잡도와 요구사항을 파악한다

### Step 2: NFR Requirements 계획 작성
- NFR 평가용 체크박스 [] 가 있는 계획을 생성한다
- 확장성, 성능, 가용성, 보안에 집중한다
- 각 단계마다 체크박스 [] 를 둔다

### Step 3: 맥락에 맞는 질문 생성
**DIRECTIVE (지시)**: 기능 설계를 철저히 분석하여, NFR 을 명확히 하면 시스템 품질과 아키텍처 결정이 나아질 모든 영역을 찾는다. NFR 을 포괄적으로 다룰 수 있도록 적극적으로 질문한다.

**CRITICAL (필수)**: 시스템 품질에 영향을 줄 수 있는 모호함이나 누락된 세부 사항이 하나라도 있으면 기본적으로 질문한다. 잘못된 NFR 가정을 하는 것보다 질문을 너무 많이 하는 편이 낫다.

- [Answer]: 태그 형식으로 질문을 문서에 넣는다 (EMBED)
- 모든 모호함, 누락된 정보, 명확화가 필요한 영역에 집중한다
- 사용자 입력이 NFR 및 기술 스택 결정을 개선할 수 있는 곳이면 어디든 질문을 생성한다
- **확신이 없으면 질문한다** - 과신은 낮은 시스템 품질로 이어진다

**평가할 질문 범주** (모든 범주를 고려):
- **확장성 요구사항 (Scalability Requirements)** - 예상 부하, 증가 패턴, 확장 기준 (trigger), 용량 계획에 대해 질문
- **성능 요구사항 (Performance Requirements)** - 응답 시간, 처리량, 지연 시간, 성능 기준치에 대해 질문
- **가용성 요구사항 (Availability Requirements)** - 가동 시간 기대치, 재해 복구, 장애 조치 (failover), 업무 연속성에 대해 질문
- **보안 요구사항 (Security Requirements)** - 데이터 보호, 규정 준수, 인증, 인가, 위협 모델에 대해 질문
- **기술 스택 선택 (Tech Stack Selection)** - 기술 선호, 제약, 기존 시스템, 연동 요구사항에 대해 질문
- **신뢰성 요구사항 (Reliability Requirements)** - 오류 처리, 장애 허용, 모니터링, 알림 필요성에 대해 질문
- **유지보수성 요구사항 (Maintainability Requirements)** - 코드 품질, 문서화, 테스트, 운영 요구사항에 대해 질문
- **사용성 요구사항 (Usability Requirements)** - 사용자 경험, 접근성, 인터페이스 요구사항에 대해 질문

### Step 4: 계획 저장
- `aidlc-docs/construction/plans/{unit-name}-nfr-requirements-plan.md` 로 저장한다
- 사용자 입력을 위한 [Answer]: 태그를 모두 포함한다

### Step 5: 답변 수집 및 분석
- 사용자가 모든 [Answer]: 태그를 채울 때까지 기다린다
- **MANDATORY (필수)**: 모든 답변에 모호하거나 불분명한 내용이 있는지 꼼꼼히 검토한다
- **CRITICAL (필수)**: 불분명한 답변이 하나라도 있으면 후속 질문을 추가한다 - 모호한 상태로 진행하지 않는다
- "depends" (상황에 따라), "maybe" (아마), "not sure" (잘 모름), "mix of" (섞어서), "somewhere between" (그 중간쯤), "standard" (표준적으로), "typical" (일반적으로) 같은 답변을 찾는다
- 모호함이 하나라도 발견되면 명확화 질문 파일을 만든다
- **모든 모호함이 해소될 때까지 진행하지 않는다**

### Step 6: NFR Requirements 산출물 생성
- `aidlc-docs/construction/{unit-name}/nfr-requirements/nfr-requirements.md` 생성
- `aidlc-docs/construction/{unit-name}/nfr-requirements/tech-stack-decisions.md` 생성

### Step 7: 완료 메시지 제시
- 완료 메시지를 다음 구조로 제시한다:
     1. **완료 알림 (Completion Announcement)** (필수): 항상 다음으로 시작:

```markdown
# 📊 NFR Requirements 완료 (NFR Requirements Complete) - [unit-name]
```

     2. **AI 요약 (AI Summary)** (선택): NFR 요구사항을 구조화된 글머리 기호로 요약
        - 형식: "NFR 요구사항 평가 결과 [description] 을(를) 확인했습니다:"
        - 핵심 확장성, 성능, 가용성 요구사항 나열 (글머리 기호)
        - 확인한 보안 및 규정 준수 요구사항 나열
        - 기술 스택 결정과 근거 언급
        - 워크플로우 안내 문구를 넣지 않는다 ("검토해 주세요 (please review)", "알려 주세요 (let me know)", "다음 phase 로 진행 (proceed to next phase)", "진행하기 전에 (before we proceed)")
        - 사실 중심, 내용 중심으로 작성
     3. **정해진 형식의 워크플로우 메시지 (Formatted Workflow Message)** (필수): 항상 정확히 다음 형식으로 끝낸다:

```markdown
> **📋 <u>**검토 필요 (REVIEW REQUIRED):**</u>**  
> NFR 요구사항을 검토해 주세요: `aidlc-docs/construction/[unit-name]/nfr-requirements/`



> **🚀 <u>**다음 단계 (WHAT'S NEXT?)**</u>**
>
> **선택할 수 있는 항목:**
>
> 🔧 **변경 요청 (Request Changes)** - 검토 결과에 따라 NFR 요구사항 수정 요청  
> ✅ **다음 Stage 로 진행 (Continue to Next Stage)** - NFR 요구사항을 승인하고 **[next-stage-name]** 로 진행

---
```

### Step 8: 명시적 승인 대기
- 사용자가 NFR 요구사항을 명시적으로 승인할 때까지 진행하지 않는다
- 승인은 명확하고 모호하지 않아야 한다
- 사용자가 변경을 요청하면 요구사항을 수정하고 승인 절차를 반복한다

### Step 9: 승인 기록 및 진행 상황 갱신
- audit.md 에 타임스탬프와 함께 승인을 기록한다
- 사용자의 승인 응답을 타임스탬프와 함께 기록한다
- aidlc-state.md 에서 NFR Requirements stage 를 완료로 표시한다

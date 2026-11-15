# Deployment Pipeline

## 사전 조건 (Prerequisites)
- 모든 unit 의 Build and Test 가 완료되어 있어야 한다
- 실행 계획에 Deployment Pipeline stage 를 실행 (EXECUTE) 하도록 표시되어 있어야 한다
- 공통 안전 규칙 (`operations/operations.md`) 을 불러와 이 stage 내내 적용한다

## 개요 (Overview)
CD (지속 배포) 파이프라인, 배포 전략, 롤백 절차, 환경 승격 기준 (environment promotion gate) 을 구성한다.

- **실행 조건 (Execute IF)**: CD 파이프라인을 새로 만들거나 크게 고쳐야 할 때
- **건너뛰기 조건 (Skip IF)**: 기존 파이프라인이 이미 충분할 때, 또는 배포할 수 있는 대상이 없을 때

## 실행 단계 (Steps to Execute)

### Step 1: 이전 산출물 불러오기
- 빌드 · 테스트 결과를 `aidlc-docs/construction/build-and-test/` 에서 읽는다
- 인프라 설계를 `aidlc-docs/construction/{unit-name}/infrastructure-design/` 에서 읽는다 (있는 경우)
- 배포 관련 NFR 설계를 `aidlc-docs/construction/{unit-name}/nfr-design/` 에서 읽는다 (있는 경우)
- **Brownfield (기존 코드)**: 작업 공간에 이미 있는 파이프라인 · 인프라 설정 (CI 설정 파일, 배포 스크립트, IaC 등) 을 살펴본다
- **Greenfield (신규)**: 승인된 요구사항, Build and Test 결과, 작업 공간에 생성된 배포 산출물 (예: Dockerfile, 서비스 manifest, IaC) 을 근거로 쓴다
- **CRITICAL (필수)**: 실제로 있는 근거로만 설계한다. 없는 CI 나 인프라 산출물을 지어내지 않는다
- 배포할 수 있는 대상이 없으면 이 stage 를 SKIP 하고, 사유를 사용자에게 알린 뒤 audit.md 와 aidlc-state.md 에 기록한다

### Step 2: Deployment Pipeline 계획 작성
- 파이프라인 구성 작업용 체크박스 [] 가 있는 계획을 생성한다
- 배포 흐름 (빌드 → 패키징 → 배포), 배포 전략, 환경 승격, 롤백에 집중한다
- 실제 설정 파일 (예: CI/CD 설정 YAML) 을 만들거나 고칠 예정이면 대상 파일을 계획에 명시한다 (작업 공간 루트, aidlc-docs/ 밖)
- 각 단계마다 체크박스 [] 를 둔다

### Step 3: 맥락에 맞는 질문 생성
**DIRECTIVE (지시)**: 이전 산출물과 작업 공간 설정을 분석하여, 배포 방식을 명확히 해야 하는 모든 영역을 찾는다.

- [Answer]: 태그 형식으로 질문을 문서에 넣는다 (EMBED)
- **확신이 없으면 질문한다** - 배포 대상과 방식에 대한 가정은 운영 장애로 이어진다

**평가할 질문 범주** (모든 범주를 고려):
- **배포 전략 (Deployment Strategy)** - blue/green, canary, rolling 중 무엇을 쓸지
- **환경 승격 기준 (Environment Promotion Gates)** - dev → staging → prod 로 넘어가는 조건
- **운영 배포 승인 절차 (Production Approval Workflow)** - 운영 배포 전에 누가 어떻게 승인하는지
- **롤백 절차 (Rollback Procedure)** - 실패 시 되돌리는 방법과 판단 기준
- **기능 플래그 전략 (Feature Flag Strategy)** - 기능 플래그 사용 여부와 도구 (예: 설정 파일 · 환경 변수 플래그)

### Step 4: 계획 저장
- `aidlc-docs/operations/plans/deployment-pipeline-plan.md` 로 저장한다
- 사용자 입력을 위한 [Answer]: 태그를 모두 포함한다

### Step 5: 답변 수집 및 분석
- 사용자가 모든 [Answer]: 태그를 채울 때까지 기다린다
- **MANDATORY (필수)**: 모든 답변에 모호하거나 불분명한 내용이 있는지 꼼꼼히 검토한다
- **CRITICAL (필수)**: 불분명한 답변이 하나라도 있으면 후속 질문을 추가한다 - 모호한 상태로 진행하지 않는다
- **모든 모호함이 해소될 때까지 진행하지 않는다**

### Step 6: Deployment Pipeline 산출물 생성
- `aidlc-docs/operations/deployment-pipeline/cd-config.md` 생성 - CD 파이프라인 구성
- `aidlc-docs/operations/deployment-pipeline/deployment-strategy.md` 생성 - 배포 전략, 환경 승격 기준 (환경 승격 표), 기능 플래그 구성
  - blue/green 이나 canary 를 쓰면 트래픽 전환 기준과 중단 조건을 반드시 적는다
- `aidlc-docs/operations/deployment-pipeline/rollback-runbook.md` 생성 - 롤백 절차와 runbook (모든 변경의 되돌리는 방법)
- 계획에 실제 설정 파일 작성이 있으면 승인된 계획대로 작업 공간 루트에 만든다. 외부에 영향을 주는 명령은 실행하지 않는다 (공통 안전 규칙 2)
- 계획의 체크박스를 완료한 즉시 [x] 로 표시한다

### Step 7: 완료 메시지 제시
- 완료 메시지를 다음 구조로 제시한다:
     1. **완료 알림 (Completion Announcement)** (필수): 항상 다음으로 시작:

```markdown
# 🚀 Deployment Pipeline 완료 (Deployment Pipeline Complete)
```

     2. **AI 요약 (AI Summary)** (선택): 파이프라인 구성을 구조화된 글머리 기호로 요약
        - 배포 전략과 환경 승격 기준, 롤백 절차의 핵심을 나열한다
        - 워크플로우 안내 문구를 넣지 않는다 ("검토해 주세요 (please review)", "진행하기 전에 (before we proceed)")
        - 사실 중심, 내용 중심으로 작성
     3. **정해진 형식의 워크플로우 메시지 (Formatted Workflow Message)** (필수): 항상 정확히 다음 형식으로 끝낸다:

```markdown
> **📋 <u>**검토 필요 (REVIEW REQUIRED):**</u>**  
> 파이프라인 구성을 검토해 주세요: `aidlc-docs/operations/deployment-pipeline/`



> **🚀 <u>**다음 단계 (WHAT'S NEXT?)**</u>**
>
> **선택할 수 있는 항목:**
>
> 🔧 **변경 요청 (Request Changes)** - 검토 결과에 따라 파이프라인 구성 수정 요청  
> ✅ **다음 Stage 로 진행 (Continue to Next Stage)** - 파이프라인 구성을 승인하고 **[next-stage-name 또는 workflow 완료]** 로 진행

---
```

### Step 8: 명시적 승인 대기
- 사용자가 파이프라인 구성을 명시적으로 승인할 때까지 진행하지 않는다
- 승인은 명확하고 모호하지 않아야 한다
- 사용자가 변경을 요청하면 산출물을 수정하고 승인 절차를 반복한다

### Step 9: 승인 기록 및 진행 상황 갱신
- audit.md 에 타임스탬프와 함께 승인을 기록한다
- 사용자의 승인 응답을 타임스탬프와 함께 기록한다
- aidlc-state.md 에서 Deployment Pipeline stage 를 완료로 표시한다

> 출처: awslabs/aidlc-workflows v2.11.1 `core/aidlc-common/stages/operation/deployment-pipeline.md` (MIT-0) 를 1.0 형식으로 변환

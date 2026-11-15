# Deployment Execution

## 사전 조건 (Prerequisites)
- Deployment Pipeline, Environment Provisioning stage 가 완료되었거나 SKIP 되어 있어야 한다
- Build and Test 결과가 있어야 한다
- 실행 계획에 Deployment Execution stage 를 실행 (EXECUTE) 하도록 표시되어 있어야 한다
- 공통 안전 규칙 (`operations/operations.md`) 을 불러와 이 stage 내내 적용한다

## 개요 (Overview)
실제 배포를 실행한다: 산출물을 파이프라인으로 배포하고, smoke test 와 health check 로 검증하며, 필요하면 데이터베이스 migration 을 실행한다.

- **실행 조건 (Execute IF)**: 파이프라인과 대상 환경이 준비되었을 때
- **건너뛰기 조건 (Skip IF)**: 이미 배포되었을 때, 또는 실제 배포 대상을 확인할 수 없을 때

## 실행 단계 (Steps to Execute)

### Step 1: 이전 산출물 불러오기
- 파이프라인 구성과 배포 전략을 `aidlc-docs/operations/deployment-pipeline/` 에서 읽는다 (있는 경우)
- 환경 목록을 `aidlc-docs/operations/environment-provisioning/` 에서 읽는다 (있는 경우)
- 빌드 · 테스트 결과를 `aidlc-docs/construction/build-and-test/` 에서 읽는다
- 롤백 runbook 을 읽는다 (있는 경우)
- Deployment Pipeline 이 "기존 파이프라인으로 충분" 해서 SKIP 되었으면, 산출물이 없는 것이 정상이다. 작업 공간의 실제 파이프라인 설정을 살펴보고 그대로 사용한다
- 실제 대상 환경은 작업 공간 설정과 승인된 이전 산출물에서 확인한다
- **CRITICAL (필수)**: 환경 목록이나 배포 경로를 지어내지 않는다. 실제 대상을 확인할 수 없으면 이 stage 를 SKIP 하고 사유를 기록한다

### Step 2: 배포 전 사전 점검
- 배포 도구의 인증 상태를, 질문을 쓰기 전에 먼저 확인한다 (예: 배포 대상 접속 계정 · 권한 확인 명령 실행)
  - 해당 CLI 가 설치되어 있지 않으면 이 점검을 건너뛴다
  - 성공하면 진행한다. 계정 ID 전체나 전체 ARN 을 산출물, 질문 파일, audit.md 에 쓰지 않는다 (예: `********1234` 와 역할 이름만)
  - 실패하면 배포 질문을 쓰지 않는다. 실패 내용 (오류 원문) 과 해결 방법 (이 셸에서 보이도록 다시 로그인 등) 을 담은 질문 1개만 하고, 사용자가 해결했다고 답하면 다시 점검한다
- 배포 도중 인증이 만료되면 같은 방식으로 멈추고, 질문하고, 다시 점검한 뒤 이어간다

### Step 3: Deployment Execution 계획 작성
- 배포 실행용 체크박스 [] 가 있는 계획을 생성한다
- 배포 단계, migration (해당 시), smoke test, health check, 롤백 판단 기준을 단계로 나눈다
- 실행할 명령과 대상 환경을 계획에 명시한다
- 각 단계마다 체크박스 [] 를 둔다

### Step 4: 맥락에 맞는 질문 생성
- [Answer]: 태그 형식으로 질문을 문서에 넣는다 (EMBED)
- **확신이 없으면 질문한다**

**평가할 질문 범주** (모든 범주를 고려):
- **사전 점검 통과 (Pre-Deployment Checks)** - 모든 배포 전 점검이 통과했는지
- **데이터베이스 migration (Database Migrations)** - migration 이 필요한지, 테스트되었는지
- **의존 서비스 상태 (Dependent Services)** - 의존 서비스가 가용하고 정상인지
- **배포 시간대 (Deployment Window)** - 언제 배포하는지

### Step 5: 계획 저장
- `aidlc-docs/operations/plans/deployment-execution-plan.md` 로 저장한다
- 사용자 입력을 위한 [Answer]: 태그를 모두 포함한다

### Step 6: 답변 수집 및 분석
- 사용자가 모든 [Answer]: 태그를 채울 때까지 기다린다
- **MANDATORY (필수)**: 모든 답변에 모호하거나 불분명한 내용이 있는지 꼼꼼히 검토한다
- **CRITICAL (필수)**: 불분명한 답변이 하나라도 있으면 후속 질문을 추가한다 - 모호한 상태로 진행하지 않는다
- **모든 모호함이 해소될 때까지 진행하지 않는다**

### Step 7: 배포 실행
- **MANDATORY (필수)**: 배포 · migration 명령은 계획 승인 후, 실행 직전에 사용자 확인을 받고 실행한다. 운영 (production) 환경은 명령만 제시하고 사람이 실행한 뒤 결과를 공유받는다 (공통 안전 규칙 2)
- 산출물을 파이프라인으로 배포한다
- smoke test 를 실행하고 health check 를 검증한다
- 필요하면 데이터베이스 migration 을 실행한다
- 실패하거나 중단 조건에 해당하면 롤백 runbook 에 따라 롤백을 제안하고, 사용자 확인 후 실행한다
- **CRITICAL (필수)**: smoke test · health check 를 통과하기 전에는 배포 성공을 선언하지 않는다 (공통 안전 규칙 4)
- 계획의 체크박스를 완료한 즉시 [x] 로 표시한다

### Step 8: Deployment Execution 산출물 생성
- `aidlc-docs/operations/deployment-execution/deployment-log.md` 생성 - 배포 실행 기록 (migration 을 실행했으면 migration 기록 포함)
- `aidlc-docs/operations/deployment-execution/smoke-test-results.md` 생성 - 배포 후 smoke test 결과
- `aidlc-docs/operations/deployment-execution/health-check-report.md` 생성 - health check 검증 결과

### Step 9: 완료 메시지 제시
- 완료 메시지를 다음 구조로 제시한다:
     1. **완료 알림 (Completion Announcement)** (필수): 항상 다음으로 시작:

```markdown
# 📦 Deployment Execution 완료 (Deployment Execution Complete)
```

     2. **AI 요약 (AI Summary)** (선택): 배포 결과를 구조화된 글머리 기호로 요약
        - 배포 대상 환경, smoke test · health check 결과, 롤백 여부를 나열한다
        - 워크플로우 안내 문구를 넣지 않는다 ("검토해 주세요 (please review)", "진행하기 전에 (before we proceed)")
        - 사실 중심, 내용 중심으로 작성
     3. **정해진 형식의 워크플로우 메시지 (Formatted Workflow Message)** (필수): 항상 정확히 다음 형식으로 끝낸다:

```markdown
> **📋 <u>**검토 필요 (REVIEW REQUIRED):**</u>**  
> 배포 결과를 검토해 주세요: `aidlc-docs/operations/deployment-execution/`



> **🚀 <u>**다음 단계 (WHAT'S NEXT?)**</u>**
>
> **선택할 수 있는 항목:**
>
> 🔧 **변경 요청 (Request Changes)** - 검토 결과에 따라 배포 조치 요청  
> ✅ **다음 Stage 로 진행 (Continue to Next Stage)** - 배포 결과를 승인하고 **[next-stage-name 또는 workflow 완료]** 로 진행

---
```

### Step 10: 명시적 승인 대기
- 사용자가 배포 결과를 명시적으로 승인할 때까지 진행하지 않는다
- 승인은 명확하고 모호하지 않아야 한다
- 사용자가 변경을 요청하면 조치하고 승인 절차를 반복한다

### Step 11: 승인 기록 및 진행 상황 갱신
- audit.md 에 타임스탬프와 함께 승인을 기록한다
- 사용자의 승인 응답을 타임스탬프와 함께 기록한다
- aidlc-state.md 에서 Deployment Execution stage 를 완료로 표시한다

> 출처: awslabs/aidlc-workflows v2.11.1 `core/aidlc-common/stages/operation/deployment-execution.md` (MIT-0) 를 1.0 형식으로 변환

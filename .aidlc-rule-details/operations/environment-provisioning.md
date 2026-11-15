# Environment Provisioning

## 사전 조건 (Prerequisites)
- Deployment Pipeline stage 가 완료되었거나 SKIP 되어 있어야 한다
- 실행 계획에 Environment Provisioning stage 를 실행 (EXECUTE) 하도록 표시되어 있어야 한다
- 공통 안전 규칙 (`operations/operations.md`) 을 불러와 이 stage 내내 적용한다

## 개요 (Overview)
배포 대상 환경을 Construction 의 인프라 설계 (IaC) 대로 준비하고, 보안 태세와 규제 요건까지 검증한다.

- **실행 조건 (Execute IF)**: 대상 환경을 새로 준비하거나 검증해야 할 때
- **건너뛰기 조건 (Skip IF)**: 환경이 이미 준비 · 검증되어 있을 때, 또는 준비할 대상 환경이 없을 때

## 실행 단계 (Steps to Execute)

### Step 1: 이전 산출물 불러오기
- 인프라 설계를 `aidlc-docs/construction/{unit-name}/infrastructure-design/` 에서 읽는다
- 보안 요구사항을 `aidlc-docs/construction/{unit-name}/nfr-requirements/` 에서 읽는다
- 파이프라인 구성을 `aidlc-docs/operations/deployment-pipeline/` 에서 읽는다 (있는 경우)
- 작업 공간의 IaC · 환경 설정 파일을 살펴본다
- **CRITICAL (필수)**: 인프라 설계나 작업 공간 설정에 근거가 없는 환경을 지어내지 않는다. 대상 환경을 확인할 수 없으면 질문하거나 SKIP 한다

### Step 2: Environment Provisioning 계획 작성
- 환경 준비 · 검증 작업용 체크박스 [] 가 있는 계획을 생성한다
- 환경별 준비 항목, 검증 항목, 보안 태세 점검, 규제 요건 (데이터 보관 위치 등) 점검을 단계로 나눈다
- 작업 공간 밖에 영향을 주는 명령 (프로비저닝, 인프라 변경) 은 계획에 명령과 대상 환경을 명시한다
- 각 단계마다 체크박스 [] 를 둔다

### Step 3: 맥락에 맞는 질문 생성
**DIRECTIVE (지시)**: 인프라 설계와 보안 요구사항을 분석하여, 환경 준비 상태를 명확히 해야 하는 모든 영역을 찾는다.

- [Answer]: 태그 형식으로 질문을 문서에 넣는다 (EMBED)
- **확신이 없으면 질문한다**

**평가할 질문 범주** (모든 범주를 고려):
- **환경 준비 상태 (Environment Readiness)** - 모든 환경이 인프라 설계대로 준비되었는지
- **네트워크 · 보안 설정 (Network and Security Configuration)** - 네트워크 구성과 접근 통제가 맞는지 (예: 포트 · 방화벽 · 접근 허용 목록)
- **비밀값 주입 (Secrets Injection)** - 비밀값 · 설정값이 올바르게 주입되는지 (예: 환경 변수, 비밀값 파일, 비밀값 저장소)
- **계정 · 네트워크 간 연결 (Cross-Account / Cross-Network Connectivity)** - 계정 간, 네트워크 간 연결이 검증되었는지

### Step 4: 계획 저장
- `aidlc-docs/operations/plans/environment-provisioning-plan.md` 로 저장한다
- 사용자 입력을 위한 [Answer]: 태그를 모두 포함한다

### Step 5: 답변 수집 및 분석
- 사용자가 모든 [Answer]: 태그를 채울 때까지 기다린다
- **MANDATORY (필수)**: 모든 답변에 모호하거나 불분명한 내용이 있는지 꼼꼼히 검토한다
- **CRITICAL (필수)**: 불분명한 답변이 하나라도 있으면 후속 질문을 추가한다 - 모호한 상태로 진행하지 않는다
- **모든 모호함이 해소될 때까지 진행하지 않는다**

### Step 6: 환경 준비 및 검증
- Construction 의 IaC 로 대상 환경을 준비하고 인프라 구성을 검증한다
- **MANDATORY (필수)**: 프로비저닝 · 인프라 변경 명령은 계획 승인 후, 실행 직전에 사용자 확인을 받고 실행한다. 운영 (production) 환경은 명령만 제시하고 사람이 실행한 뒤 결과를 공유받는다 (공통 안전 규칙 2)
- 인프라 변경마다 보안 영향을 문서화한다. 기존 보안 통제를 근거 없이 제거하거나 우회하지 않는다
- 보안 태세 관점 (접근 통제, 암호화, 비밀값 관리) 과 규제 관점 (데이터 보관 위치, 규제 통제) 으로 각각 점검한다
- 계획의 체크박스를 완료한 즉시 [x] 로 표시한다

### Step 7: Environment Provisioning 산출물 생성
- `aidlc-docs/operations/environment-provisioning/environment-inventory.md` 생성 - 준비된 환경 목록
- `aidlc-docs/operations/environment-provisioning/validation-report.md` 생성 - 인프라 검증 결과, 비밀값 · 파라미터 점검, 배포 기록 요약, 환경 health check 결과
- **CRITICAL (필수)**: 비밀값 · 토큰 · 계정 ID 원문을 기록하지 않는다. 식별이 필요하면 마스킹한다 (공통 안전 규칙 6)

### Step 8: 완료 메시지 제시
- 완료 메시지를 다음 구조로 제시한다:
     1. **완료 알림 (Completion Announcement)** (필수): 항상 다음으로 시작:

```markdown
# ☁️ Environment Provisioning 완료 (Environment Provisioning Complete)
```

     2. **AI 요약 (AI Summary)** (선택): 환경 준비 결과를 구조화된 글머리 기호로 요약
        - 준비 · 검증한 환경, 보안 · 규제 점검 결과, 남은 위험을 나열한다
        - 워크플로우 안내 문구를 넣지 않는다 ("검토해 주세요 (please review)", "진행하기 전에 (before we proceed)")
        - 사실 중심, 내용 중심으로 작성
     3. **정해진 형식의 워크플로우 메시지 (Formatted Workflow Message)** (필수): 항상 정확히 다음 형식으로 끝낸다:

```markdown
> **📋 <u>**검토 필요 (REVIEW REQUIRED):**</u>**  
> 환경 준비 결과를 검토해 주세요: `aidlc-docs/operations/environment-provisioning/`



> **🚀 <u>**다음 단계 (WHAT'S NEXT?)**</u>**
>
> **선택할 수 있는 항목:**
>
> 🔧 **변경 요청 (Request Changes)** - 검토 결과에 따라 환경 준비 수정 요청  
> ✅ **다음 Stage 로 진행 (Continue to Next Stage)** - 환경 준비를 승인하고 **[next-stage-name 또는 workflow 완료]** 로 진행

---
```

### Step 9: 명시적 승인 대기
- 사용자가 환경 준비 결과를 명시적으로 승인할 때까지 진행하지 않는다
- 승인은 명확하고 모호하지 않아야 한다
- 사용자가 변경을 요청하면 수정하고 승인 절차를 반복한다

### Step 10: 승인 기록 및 진행 상황 갱신
- audit.md 에 타임스탬프와 함께 승인을 기록한다
- 사용자의 승인 응답을 타임스탬프와 함께 기록한다
- aidlc-state.md 에서 Environment Provisioning stage 를 완료로 표시한다

> 출처: awslabs/aidlc-workflows v2.11.1 `core/aidlc-common/stages/operation/environment-provisioning.md` (MIT-0) 를 1.0 형식으로 변환

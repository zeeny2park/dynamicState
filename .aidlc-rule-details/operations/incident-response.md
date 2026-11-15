# Incident Response

## 사전 조건 (Prerequisites)
- Observability Setup 이 완료되었거나 SKIP 되어 있어야 한다. SKIP 이면 기존 대시보드 · 알람 구성을 작업 공간 설정 · 사용자 답변으로 확인한다 (확인되지 않으면 알람 연결 항목을 미정으로 표시)
- 실행 계획 (`aidlc-docs/inception/plans/execution-plan.md`) 에 Incident Response stage 를 실행 (EXECUTE) 하도록 표시되어 있어야 한다
- 공통 안전 규칙 (`operations/operations.md`) 을 읽은 상태여야 한다

## 개요 (Overview)
운영 runbook, 장애 대응 계획, 상향 보고 (escalation) 절차를 만든다.

**실행 조건 (Execute IF)**: 운영 runbook 과 장애 대응 절차가 필요함
**건너뛰기 조건 (Skip IF)**: POC 이거나 운영 (production) 이 아닌 배포 → SKIP 사유를 audit.md 에 기록하고 빈 산출물을 만들지 않는다

## 실행 단계 (Steps to Execute)

### Step 1: 이전 산출물 읽기
- `aidlc-docs/operations/observability-setup/` 에서 관측 구성 (대시보드 · 알람) 을 읽는다
- `aidlc-docs/construction/{unit-name}/nfr-design/` 에서 NFR 설계 (신뢰성 · 보안) 를 읽는다 (모든 unit)
- `aidlc-docs/construction/{unit-name}/infrastructure-design/` 에서 인프라 설계를 읽는다 (모든 unit)
- 없는 산출물은 지어내지 않는다. 확인할 수 없는 장애 유형 · 연락 체계 · 복구 목표는 질문한다

### Step 2: Incident Response 계획 작성
- 장애 대응 준비용 체크박스 [] 가 있는 계획을 생성한다
- 장애 유형, 상향 보고 경로, 자동 복구, 의사소통 절차, 복구 목표에 집중한다
- 각 단계마다 체크박스 [] 를 둔다

### Step 3: 맥락에 맞는 질문 생성
**CRITICAL (필수)**: 장애 대응에 영향을 줄 수 있는 모호함이나 누락된 세부 사항이 있으면 질문한다. 연락처 · 담당자 · 복구 목표를 가정하지 않는다.

- [Answer]: 태그 형식으로 질문을 문서에 넣는다 (EMBED)

**평가할 질문 범주** (모든 범주를 고려):
- **장애 유형 (Failure Modes)** - 가장 일어나기 쉬운 장애 유형에 대해 질문
- **상향 보고 (Escalation)** - 상향 보고 경로와 당번 (on-call) 순환에 대해 질문
- **자동 복구 (Automated Remediation)** - 자동화할 수 있는 복구 조치에 대해 질문
- **의사소통 (Communication)** - 장애 중 의사소통 절차에 대해 질문
- **복구 목표 (RTO/RPO)** - RTO/RPO 목표에 대해 질문

### Step 4: 계획 저장
- `aidlc-docs/operations/plans/incident-response-plan.md` 로 저장한다
- 사용자 입력을 위한 [Answer]: 태그를 모두 포함한다

### Step 5: 답변 수집 및 분석
- 사용자가 모든 [Answer]: 태그를 채울 때까지 기다린다
- **MANDATORY (필수)**: 모든 답변에 모호하거나 불분명한 내용이 있는지 꼼꼼히 검토한다
- "depends" (상황에 따라), "maybe" (아마), "not sure" (잘 모름), "standard" (표준적으로), "typical" (일반적으로) 같은 답변을 찾는다
- 모호함이 하나라도 발견되면 명확화 질문 파일을 만든다
- **모든 모호함이 해소될 때까지 진행하지 않는다**

### Step 6: Incident Response 산출물 생성
- `aidlc-docs/operations/incident-response/` 아래에 다음을 생성한다:
  - `runbooks.md` - 장애 유형별 runbook (진단 · 격리 · 복구 · 롤백 절차, 자동 복구 절차, 재해 복구 절차)
  - `incident-plan.md` - 장애 대응 계획 (심각도 기준, 대응 흐름, 사후 검토 절차)
  - `escalation-matrix.md` - 상향 보고 경로, 당번 순환, 의사소통 절차
- 예: 스크립트 · Markdown (runbook), 장애 기록 문서 (대응 계획), 데이터 백업 · 복원 스크립트 (백업 구성) 로 구성한다
- **CRITICAL (필수)** 작성 기준:
  - 모든 runbook 에 상향 보고 경로와 연락 정보를 포함한다 (연락 정보는 사용자가 확인한 것만)
  - 복구 절차에는 되돌리는 (rollback) 단계를 포함한다
  - P1 · P2 장애는 사후 검토 (post-incident review) 를 필수로 하고 기록 항목 (경과 시간표, 근본 원인, 재발 방지) 을 정한다
  - 기존 보안 통제를 제거 · 우회하는 절차는 명시적 승인과 근거 기록 없이 넣지 않는다
  - 비밀값 · 계정 ID · 토큰은 산출물에 기록하지 않는다 (마스킹)

### Step 7: 완료 메시지 제시
- 완료 메시지를 다음 구조로 제시한다:
     1. **완료 알림 (Completion Announcement)** (필수): 항상 다음으로 시작:

```markdown
# 🚒 Incident Response 완료 (Incident Response Complete)
```

     2. **AI 요약 (AI Summary)** (선택): 장애 대응 준비 내용을 구조화된 글머리 기호로 요약
        - 주요 장애 유형과 runbook, 심각도 기준, 상향 보고 경로, RTO/RPO 나열
        - 워크플로우 안내 문구를 넣지 않는다 ("검토해 주세요 (please review)", "알려 주세요 (let me know)")
        - 사실 중심, 내용 중심으로 작성
     3. **정해진 형식의 워크플로우 메시지 (Formatted Workflow Message)** (필수): 항상 정확히 다음 형식으로 끝낸다:

```markdown
> **📋 <u>**검토 필요 (REVIEW REQUIRED):**</u>**  
> 장애 대응 산출물을 검토해 주세요: `aidlc-docs/operations/incident-response/`



> **🚀 <u>**다음 단계 (WHAT'S NEXT?)**</u>**
>
> **선택할 수 있는 항목:**
>
> 🔧 **변경 요청 (Request Changes)** - 검토 결과에 따라 장애 대응 산출물 수정 요청  
> ✅ **다음 Stage 로 진행 (Continue to Next Stage)** - 장애 대응 산출물을 승인하고 **[next-stage-name 또는 workflow 완료]** 로 진행

---
```

### Step 8: 명시적 승인 대기
- 사용자가 장애 대응 산출물을 명시적으로 승인할 때까지 진행하지 않는다
- 승인은 명확하고 모호하지 않아야 한다
- 사용자가 변경을 요청하면 산출물을 수정하고 승인 절차를 반복한다

### Step 9: 승인 기록 및 진행 상황 갱신
- audit.md 에 타임스탬프와 함께 승인을 기록한다
- 사용자의 승인 응답을 타임스탬프와 함께 기록한다
- aidlc-state.md 에서 Incident Response stage 를 완료로 표시한다

> 출처: awslabs/aidlc-workflows v2.11.1 `core/aidlc-common/stages/operation/incident-response.md`, `core/memory/phases/operation.md` (MIT-0) 를 1.0 형식으로 변환

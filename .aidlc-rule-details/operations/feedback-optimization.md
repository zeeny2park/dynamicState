# Feedback & Optimization

## 사전 조건 (Prerequisites)
- Deployment Execution 과 Observability Setup 이 완료되었거나 SKIP 되어 있어야 한다. 검토할 운영 데이터 (배포 기록 · 지표 · 로그 · 장애 기록) 가 이전 산출물 또는 사용자 답변으로 확인되어야 한다 (없으면 이 stage 도 SKIP)
- Incident Response · Performance Validation 산출물은 있으면 사용한다 (선택)
- 실행 계획 (`aidlc-docs/inception/plans/execution-plan.md`) 에 Feedback & Optimization stage 를 실행 (EXECUTE) 하도록 표시되어 있어야 한다
- 공통 안전 규칙 (`operations/operations.md`) 을 읽은 상태여야 한다

## 개요 (Overview)
SLO 준수 검토, 비용 최적화 분석, 인프라 drift (설계와 실제 구성의 어긋남) 탐지, 운영 인사이트 수집을 수행한다. AI-DLC workflow 전체의 **마지막 stage** 이다.

**실행 조건 (Execute IF)**: 지속적인 운영 모니터링과 최적화가 필요함
**건너뛰기 조건 (Skip IF)**: 일회성 배포 → SKIP 사유를 audit.md 에 기록하고 빈 산출물을 만들지 않는다

## 실행 단계 (Steps to Execute)

### Step 1: 이전 산출물 읽기
- `aidlc-docs/operations/observability-setup/` 에서 관측 구성과 SLO/SLI 구성 (`slo-config.md`) 을 읽는다
- `aidlc-docs/operations/deployment-execution/` 에서 배포 기록을 읽는다
- `aidlc-docs/operations/performance-validation/` 에서 성능 검증 결과를 읽는다 (있는 경우)
- `aidlc-docs/operations/incident-response/` 에서 장애 대응 계획을 읽는다 (있는 경우)
- `aidlc-docs/construction/{unit-name}/infrastructure-design/` 에서 drift 비교 기준이 될 인프라 설계를 읽는다 (모든 unit)
- **CRITICAL (필수)**: 실제 운영 데이터 (지표, 로그, 비용, 구성) 만 근거로 쓴다. 데이터가 없으면 사용자에게 제공을 요청하거나 SKIP 한다. 수치를 지어내지 않는다

### Step 2: Feedback & Optimization 계획 작성
- 운영 피드백용 체크박스 [] 가 있는 계획을 생성한다
- SLO 준수, 비용, drift, 사용자 행동 패턴, 자동화할 반복 운영 작업에 집중한다
- 각 단계마다 체크박스 [] 를 둔다

### Step 3: 맥락에 맞는 질문 생성
- [Answer]: 태그 형식으로 질문을 문서에 넣는다 (EMBED)

**평가할 질문 범주** (모든 범주를 고려):
- **SLO 준수 (SLO Compliance)** - SLO 를 지키고 있는지, 오류 예산 (error budget) 소진 속도에 대해 질문
- **비용 (Cost)** - 비용 최적화 기회에 대해 질문
- **drift** - 구성 · 인프라 drift 여부에 대해 질문
- **사용자 행동 (User Behavior)** - 새 기능이나 문제를 시사하는 사용자 행동 패턴에 대해 질문
- **반복 운영 작업 (Toil)** - 자동화할 수 있는 반복 운영 작업에 대해 질문

### Step 4: 계획 저장
- `aidlc-docs/operations/plans/feedback-optimization-plan.md` 로 저장한다
- 사용자 입력을 위한 [Answer]: 태그를 모두 포함한다

### Step 5: 답변 수집 및 분석
- 사용자가 모든 [Answer]: 태그를 채울 때까지 기다린다
- **MANDATORY (필수)**: 모든 답변에 모호하거나 불분명한 내용이 있는지 꼼꼼히 검토한다
- "depends" (상황에 따라), "maybe" (아마), "not sure" (잘 모름), "standard" (표준적으로), "typical" (일반적으로) 같은 답변을 찾는다
- 모호함이 하나라도 발견되면 명확화 질문 파일을 만든다
- **모든 모호함이 해소될 때까지 진행하지 않는다**

### Step 6: Feedback & Optimization 산출물 생성
- `aidlc-docs/operations/feedback-optimization/` 아래에 다음을 생성한다:
  - `slo-report.md` - SLO 준수 보고, 오류 예산 소진 속도
  - `cost-analysis.md` - 비용 분석과 최적화 권고
  - `drift-report.md` - 설계 대비 실제 구성 drift 탐지 결과
  - `feedback-loop.md` - 운영 인사이트, 개선 과제 목록 (다음 요청의 입력)
- 예: 사용량 · 비용 기록 (비용), 설정 비교 (drift), 운영 지표 · 장애 기록 (권고 검토) 을 근거로 쓴다
- 비밀값 · 계정 ID · 토큰은 산출물에 기록하지 않는다 (마스킹)

### Step 7: 완료 메시지 제시
- 완료 메시지를 다음 구조로 제시한다:
     1. **완료 알림 (Completion Announcement)** (필수): 항상 다음으로 시작:

```markdown
# ♻️ Feedback & Optimization 완료 (Feedback & Optimization Complete)
```

     2. **AI 요약 (AI Summary)** (선택): 운영 피드백을 구조화된 글머리 기호로 요약
        - SLO 준수 상태, 비용 · drift 발견 사항, 개선 과제 나열
        - 워크플로우 안내 문구를 넣지 않는다 ("검토해 주세요 (please review)", "알려 주세요 (let me know)")
        - 사실 중심, 내용 중심으로 작성
     3. **정해진 형식의 워크플로우 메시지 (Formatted Workflow Message)** (필수): 항상 정확히 다음 형식으로 끝낸다:

```markdown
> **📋 <u>**검토 필요 (REVIEW REQUIRED):**</u>**  
> 운영 피드백 산출물을 검토해 주세요: `aidlc-docs/operations/feedback-optimization/`



> **🚀 <u>**다음 단계 (WHAT'S NEXT?)**</u>**
>
> **선택할 수 있는 항목:**
>
> 🔧 **변경 요청 (Request Changes)** - 검토 결과에 따라 운영 피드백 산출물 수정 요청  
> ✅ **승인 후 완료 (Approve & Complete)** - 운영 피드백을 승인하고 **AI-DLC workflow 를 완료**
>
> 💡 `feedback-loop.md` 의 개선 과제를 이어가려면 새 요청 "Using AI-DLC, ..." 으로 시작한다 (Workspace Detection → INCEPTION)

---
```

- **CRITICAL (필수)**: 위 2가지 선택지만 사용한다. 세 번째 선택지 (예: 새 주기 시작) 를 만들지 않는다 (NO EMERGENT BEHAVIOR)

### Step 8: 명시적 승인 대기
- 사용자가 운영 피드백 산출물을 명시적으로 승인할 때까지 진행하지 않는다
- 승인은 명확하고 모호하지 않아야 한다
- 사용자가 변경을 요청하면 산출물을 수정하고 승인 절차를 반복한다

### Step 9: 승인 기록 및 workflow 완료
- audit.md 에 타임스탬프와 함께 승인을 기록한다
- 사용자의 승인 응답을 타임스탬프와 함께 기록한다
- aidlc-state.md 에서 Feedback & Optimization stage 를 완료로 표시하고 workflow 완료를 기록한다

> 출처: awslabs/aidlc-workflows v2.11.1 `core/aidlc-common/stages/operation/feedback-optimization.md`, `docs/reference/04-stages/operation.md` (MIT-0) 를 1.0 형식으로 변환

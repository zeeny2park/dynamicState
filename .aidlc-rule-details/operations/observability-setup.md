# Observability Setup

## 사전 조건 (Prerequisites)
- Deployment Execution 이 완료되었거나 SKIP 되어 있어야 한다. SKIP 이면 이미 운영 중인 대상을 작업 공간 설정 · 사용자 답변으로 확인한다 (확인되지 않으면 이 stage 도 SKIP)
- 실행 계획 (`aidlc-docs/inception/plans/execution-plan.md`) 에 Observability Setup stage 를 실행 (EXECUTE) 하도록 표시되어 있어야 한다
- 공통 안전 규칙 (`operations/operations.md`) 을 읽은 상태여야 한다

## 개요 (Overview)
배포된 대상의 모니터링, 대시보드, 알람, SLO/SLI 추적, 로그 조회, 분산 추적 (tracing), 이상 탐지 구성을 정한다.

**실행 조건 (Execute IF)**: 모니터링, 대시보드, 알람, tracing 구성이 필요함
**건너뛰기 조건 (Skip IF)**: 관측 구성이 이미 갖추어져 있음, 또는 배포된 대상이 없음 → SKIP 사유를 audit.md 에 기록하고 빈 산출물을 만들지 않는다

## 실행 단계 (Steps to Execute)

### Step 1: 이전 산출물 읽기
- `aidlc-docs/construction/{unit-name}/nfr-design/` 에서 관측 전략을 읽는다 (모든 unit)
- `aidlc-docs/construction/{unit-name}/infrastructure-design/` 에서 인프라 설계를 읽는다 (모든 unit)
- `aidlc-docs/operations/deployment-execution/` 에서 배포 실행 기록을 읽는다
- NFR Design · Infrastructure Design 산출물이 없으면 (건너뛴 경우), 승인된 요구사항 (`aidlc-docs/inception/requirements/requirements.md`), 작업 공간의 실제 설정, Build and Test 결과, 배포 실행 기록에서 관측해야 할 최소 범위를 도출한다
- 이 자료들로 확인할 수 없는 SLO, 신호, 보존 기간, 상향 보고 결정은 질문한다. 없는 설계 산출물을 **절대** 지어내지 않는다

### Step 2: Observability Setup 계획 작성
- 관측 구성용 체크박스 [] 가 있는 계획을 생성한다
- 핵심 신호 (golden signals), SLO/SLI, 알람, 로그, tracing, 이상 탐지에 집중한다
- 각 단계마다 체크박스 [] 를 둔다

### Step 3: 맥락에 맞는 질문 생성
**CRITICAL (필수)**: 관측 기준에 영향을 줄 수 있는 모호함이나 누락된 세부 사항이 있으면 질문한다. 확인되지 않은 수치를 가정하지 않는다.

- [Answer]: 태그 형식으로 질문을 문서에 넣는다 (EMBED)

**평가할 질문 범주** (모든 범주를 고려):
- **핵심 신호 (Golden Signals)** - 추적할 지연 시간 (latency), 트래픽, 오류, 포화도 (saturation) 에 대해 질문
- **SLO/SLI** - 정의된 SLO 와 SLI, 측정 기간에 대해 질문
- **대시보드 (Dashboards)** - 팀에 필요한 대시보드 구성에 대해 질문
- **로그 (Logs)** - 로그 보존 기간과 수집 · 집계 규칙에 대해 질문
- **분산 추적 (Tracing)** - 필요한 tracing 계측 범위에 대해 질문

### Step 4: 계획 저장
- `aidlc-docs/operations/plans/observability-setup-plan.md` 로 저장한다
- 사용자 입력을 위한 [Answer]: 태그를 모두 포함한다

### Step 5: 답변 수집 및 분석
- 사용자가 모든 [Answer]: 태그를 채울 때까지 기다린다
- **MANDATORY (필수)**: 모든 답변에 모호하거나 불분명한 내용이 있는지 꼼꼼히 검토한다
- "depends" (상황에 따라), "maybe" (아마), "not sure" (잘 모름), "standard" (표준적으로), "typical" (일반적으로) 같은 답변을 찾는다
- 모호함이 하나라도 발견되면 명확화 질문 파일을 만든다
- **모든 모호함이 해소될 때까지 진행하지 않는다**

### Step 6: Observability Setup 산출물 생성
- `aidlc-docs/operations/observability-setup/` 아래에 다음을 생성한다:
  - `dashboards.md` - 대시보드 구성
  - `alarms.md` - 알람 정의 (심각도, 알림 경로, 상향 보고)
  - `slo-config.md` - SLO/SLI 추적 구성
  - `log-queries.md` - 저장해 둘 로그 조회 쿼리
  - `tracing-config.md` - 분산 추적 구성
  - `anomaly-config.md` - 이상 탐지 구성
- 예: 앱 요청 로그 · 지표 API (대시보드 · 로그 조회), health check (상태), 알림 메시지 (알림 경로) 로 구성한다
- **CRITICAL (필수)** 작성 기준:
  - SLO 는 구체적인 비율과 기간을 가진 수치로 정의한다 (예: "30일 이동 기간 기준 가용성 99.9%")
  - 알람 임계치는 SLO 위반보다 먼저 경고하도록 설정해 대응 시간을 확보한다
  - 새 서비스 · 컴포넌트마다 health 지표 1개와 오류율 지표 1개 이상을 둔다
  - 비밀값 · 계정 ID · 토큰은 산출물에 기록하지 않는다 (마스킹)

### Step 7: 완료 메시지 제시
- 완료 메시지를 다음 구조로 제시한다:
     1. **완료 알림 (Completion Announcement)** (필수): 항상 다음으로 시작:

```markdown
# 👀 Observability Setup 완료 (Observability Setup Complete)
```

     2. **AI 요약 (AI Summary)** (선택): 관측 구성을 구조화된 글머리 기호로 요약
        - SLO/SLI 와 핵심 신호, 알람 기준, 로그 · tracing 범위 나열
        - 워크플로우 안내 문구를 넣지 않는다 ("검토해 주세요 (please review)", "알려 주세요 (let me know)")
        - 사실 중심, 내용 중심으로 작성
     3. **정해진 형식의 워크플로우 메시지 (Formatted Workflow Message)** (필수): 항상 정확히 다음 형식으로 끝낸다:

```markdown
> **📋 <u>**검토 필요 (REVIEW REQUIRED):**</u>**  
> 관측 구성을 검토해 주세요: `aidlc-docs/operations/observability-setup/`



> **🚀 <u>**다음 단계 (WHAT'S NEXT?)**</u>**
>
> **선택할 수 있는 항목:**
>
> 🔧 **변경 요청 (Request Changes)** - 검토 결과에 따라 관측 구성 수정 요청  
> ✅ **다음 Stage 로 진행 (Continue to Next Stage)** - 관측 구성을 승인하고 **[next-stage-name 또는 workflow 완료]** 로 진행

---
```

### Step 8: 명시적 승인 대기
- 사용자가 관측 구성을 명시적으로 승인할 때까지 진행하지 않는다
- 승인은 명확하고 모호하지 않아야 한다
- 사용자가 변경을 요청하면 산출물을 수정하고 승인 절차를 반복한다

### Step 9: 승인 기록 및 진행 상황 갱신
- audit.md 에 타임스탬프와 함께 승인을 기록한다
- 사용자의 승인 응답을 타임스탬프와 함께 기록한다
- aidlc-state.md 에서 Observability Setup stage 를 완료로 표시한다

> 출처: awslabs/aidlc-workflows v2.11.1 `core/aidlc-common/stages/operation/observability-setup.md`, `core/memory/phases/operation.md` (MIT-0) 를 1.0 형식으로 변환

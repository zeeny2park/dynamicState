# Performance Validation

## 사전 조건 (Prerequisites)
- Observability Setup 이 완료되었거나 SKIP 되어 있어야 한다. SKIP 이면 결과를 판정할 기존 지표를 작업 공간 설정 · 사용자 답변으로 확인한다
- 검증할 대상이 실제로 있어야 한다 (Deployment Execution 완료, 또는 SKIP 시 사용자가 확인한 기존 환경). 없으면 이 stage 도 SKIP
- 실행 계획 (`aidlc-docs/inception/plans/execution-plan.md`) 에 Performance Validation stage 를 실행 (EXECUTE) 하도록 표시되어 있어야 한다
- 공통 안전 규칙 (`operations/operations.md`) 을 읽은 상태여야 한다

## 개요 (Overview)
부하 테스트를 설계 · 실행하여 NFR 성능 목표를 배포된 대상에서 검증한다.

**실행 조건 (Execute IF)**: NFR 성능 목표를 부하 상황에서 검증해야 함
**건너뛰기 조건 (Skip IF)**: POC 이거나 성능이 중요하지 않은 애플리케이션 → SKIP 사유를 audit.md 에 기록하고 빈 산출물을 만들지 않는다

## 실행 단계 (Steps to Execute)

### Step 1: 이전 산출물 읽기
- `aidlc-docs/construction/{unit-name}/nfr-requirements/` 에서 성능 · 확장성 요구사항을 읽는다 (모든 unit)
- `aidlc-docs/construction/{unit-name}/nfr-design/` 에서 성능 · 확장성 설계를 읽는다 (모든 unit)
- `aidlc-docs/operations/observability-setup/` 에서 관측 구성 (대시보드 · SLO) 을 읽는다
- 없는 산출물은 지어내지 않는다. 확인할 수 없는 성능 목표는 질문한다

### Step 2: Performance Validation 계획 작성
- 성능 검증용 체크박스 [] 가 있는 계획을 생성한다
- 트래픽 패턴, 지연 시간 백분위 목표, 처리량, 병목 후보에 집중한다
- 각 단계마다 체크박스 [] 를 둔다

### Step 3: 맥락에 맞는 질문 생성
**CRITICAL (필수)**: 성능 판정에 영향을 줄 수 있는 모호함이나 누락된 세부 사항이 있으면 질문한다. 목표 수치를 가정하지 않는다.

- [Answer]: 태그 형식으로 질문을 문서에 넣는다 (EMBED)

**평가할 질문 범주** (모든 범주를 고려):
- **트래픽 패턴 (Traffic Patterns)** - 평상시, 최대 (peak), 순간 급증 (burst) 트래픽에 대해 질문
- **지연 시간 목표 (Latency Targets)** - 목표 백분위 (p50, p95, p99) 에 대해 질문
- **처리량 (Throughput)** - 시스템이 유지해야 할 처리량에 대해 질문
- **병목 후보 (Bottlenecks)** - 병목이 생기기 쉬운 지점에 대해 질문
- **테스트 대상 · 시점** - 부하 테스트를 실행할 환경과 실행 가능 시간대에 대해 질문

### Step 4: 계획 저장
- `aidlc-docs/operations/plans/performance-validation-plan.md` 로 저장한다
- 사용자 입력을 위한 [Answer]: 태그를 모두 포함한다

### Step 5: 답변 수집 및 분석
- 사용자가 모든 [Answer]: 태그를 채울 때까지 기다린다
- **MANDATORY (필수)**: 모든 답변에 모호하거나 불분명한 내용이 있는지 꼼꼼히 검토한다
- "depends" (상황에 따라), "maybe" (아마), "not sure" (잘 모름), "standard" (표준적으로), "typical" (일반적으로) 같은 답변을 찾는다
- 모호함이 하나라도 발견되면 명확화 질문 파일을 만든다
- **모든 모호함이 해소될 때까지 진행하지 않는다**

### Step 6: 부하 테스트 설계 및 실행
- `aidlc-docs/operations/performance-validation/load-test-plan.md` 에 부하 테스트 계획 (시나리오, 도구, 설정) 을 작성한다
- 운영과 비슷한 환경 (production-like) 에서 실행한다
- **CRITICAL (필수)**: 부하 테스트는 외부에 영향을 주는 명령이다
  - 계획 승인과 실행 직전 사용자 확인을 받은 뒤에만 실행한다
  - 운영 (production) 환경 대상이면 기본적으로 명령만 제시하고 사람이 실행한다
  - 사용자가 확인한 대상 외에는 실행하지 않는다
- 결과는 관측 지표 (Observability Setup 의 대시보드 · 로그) 를 근거로 분석한다. 예: 요청 로그의 응답 시간 · 오류 기록을 근거로 쓴다

### Step 7: Performance Validation 산출물 생성
- `aidlc-docs/operations/performance-validation/` 아래에 다음을 생성한다:
  - `load-test-plan.md` - 부하 테스트 계획 (Step 6)
  - `test-results.md` - 성능 테스트 결과 (지연 시간, 처리량, 오류율), 병목 분석, 자동 확장 (auto-scaling) 검증, 용량 계획 권고
  - `nfr-validation-matrix.md` - NFR 목표 대비 실측 대조표
- 실행하지 않은 테스트의 결과를 지어내지 않는다. 미실행 항목은 미실행으로 표시한다

### Step 8: 완료 메시지 제시
- 완료 메시지를 다음 구조로 제시한다:
     1. **완료 알림 (Completion Announcement)** (필수): 항상 다음으로 시작:

```markdown
# ⚡ Performance Validation 완료 (Performance Validation Complete)
```

     2. **AI 요약 (AI Summary)** (선택): 성능 검증 결과를 구조화된 글머리 기호로 요약
        - NFR 목표 대비 실측, 통과 · 미달 항목, 병목, 용량 권고 나열
        - 워크플로우 안내 문구를 넣지 않는다 ("검토해 주세요 (please review)", "알려 주세요 (let me know)")
        - 사실 중심, 내용 중심으로 작성
     3. **정해진 형식의 워크플로우 메시지 (Formatted Workflow Message)** (필수): 항상 정확히 다음 형식으로 끝낸다:

```markdown
> **📋 <u>**검토 필요 (REVIEW REQUIRED):**</u>**  
> 성능 검증 결과를 검토해 주세요: `aidlc-docs/operations/performance-validation/`



> **🚀 <u>**다음 단계 (WHAT'S NEXT?)**</u>**
>
> **선택할 수 있는 항목:**
>
> 🔧 **변경 요청 (Request Changes)** - 검토 결과에 따라 성능 검증 계획 · 결과 수정 요청  
> ✅ **다음 Stage 로 진행 (Continue to Next Stage)** - 성능 검증 결과를 승인하고 **[next-stage-name 또는 workflow 완료]** 로 진행

---
```

### Step 9: 명시적 승인 대기
- 사용자가 성능 검증 결과를 명시적으로 승인할 때까지 진행하지 않는다
- 승인은 명확하고 모호하지 않아야 한다
- 사용자가 변경을 요청하면 산출물을 수정하고 승인 절차를 반복한다

### Step 10: 승인 기록 및 진행 상황 갱신
- audit.md 에 타임스탬프와 함께 승인을 기록한다
- 사용자의 승인 응답을 타임스탬프와 함께 기록한다
- aidlc-state.md 에서 Performance Validation stage 를 완료로 표시한다

> 출처: awslabs/aidlc-workflows v2.11.1 `core/aidlc-common/stages/operation/performance-validation.md`, `docs/reference/04-stages/operation.md` (MIT-0) 를 1.0 형식으로 변환

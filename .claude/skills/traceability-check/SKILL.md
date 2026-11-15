---
name: traceability-check
description: AI-DLC 추적성 점검 (Traceability Check). 산출물의 ID (FR · NFR · US · AC · Unit) 를 양방향으로 대조해 누락 (GAP) 과 근거 없는 항목 (ORPHAN) 을 찾고, 결과를 aidlc-docs/verification/ 에 남긴다. ① inception = Construction 진입 전 요구 → 스토리 → 컴포넌트 → Unit 연결 점검, ② construction = Operations 진입 전 요구 · AC → 스토리 → Unit → 구현 계획 → 소스 · 테스트 → 실행 결과 연결 점검. AI-DLC workflow 규칙이 phase 경계에서 호출하거나, 사용자가 추적 점검 · 요구 누락 · 고아 항목 확인을 요청할 때 사용.
argument-hint: "[inception|construction]"
---

# Traceability Check (추적성 점검)

- 인자: `$ARGUMENTS`
- 결과 양식: [result-template.md](result-template.md)
- 이 스킬은 점검과 보고만 한다. 산출물 · 코드는 수정하지 않는다

## 1. 점검 대상 결정

| 인자 | 점검 | 시점 |
| --- | --- | --- |
| `inception` | ① Inception → Construction | INCEPTION 마지막 stage 승인 후, CONSTRUCTION 진입 전 |
| `construction` | ② Construction → Operations | Build and Test 승인 후, OPERATIONS 진입 전 |

- 인자가 비면 `aidlc-docs/aidlc-state.md` 의 Stage Progress 로 추정한다
  - 완료된 CONSTRUCTION stage 가 없으면 ①, 있으면 ②
  - 추정했다는 사실과 근거를 결과 첫 줄과 완료 메시지에 적는다
- 그 밖의 인자 · `aidlc-state.md` 없음 → 점검하지 않고 사용자에게 대상을 묻는다
- `aidlc-docs/` 가 없으면 "AI-DLC 산출물 없음" 으로 보고하고 끝낸다

## 2. 입력 수집 (읽기만)

### ① inception

| 고리 | 파일 |
| --- | --- |
| 요구 FR · NFR | `aidlc-docs/inception/requirements/requirements.md` |
| User Story · AC | `aidlc-docs/inception/user-stories/stories.md` |
| 컴포넌트 | `aidlc-docs/inception/application-design/components.md` (+ `component-methods.md`) |
| Unit | `aidlc-docs/inception/application-design/unit-of-work-story-map.md` (+ `unit-of-work.md`) |
| 보류 근거 | `aidlc-docs/audit.md`, `aidlc-docs/inception/**/*questions*.md` |
| 실행 여부 | `aidlc-docs/inception/plans/execution-plan.md` |

- 실행 계획에서 SKIP 된 stage 의 고리는 `N/A` (사유: SKIP) 로 둔다
- Units Generation 을 생략했으면 story map 없이 스토리 → 컴포넌트를 직접 대조한다
- 파일이 실제 위치와 다르면 `aidlc-docs/` 안에서 같은 이름을 찾아 쓰고, 찾은 경로를 입력 목록에 적는다

### ② construction

| 고리 | 파일 |
| --- | --- |
| ① 의 모든 입력 | 위 표 |
| 구현 계획 Step | `aidlc-docs/construction/plans/*-code-generation-plan.md` |
| Unit 설계 · 요약 | `aidlc-docs/construction/{unit-name}/` (functional-design, nfr-requirements, nfr-design, `code/` 요약) |
| 소스 · 테스트 | 구현 계획 · 코드 요약에 적힌 파일, 테스트 함수의 docstring · 주석 안 ID |
| 실행 결과 | `aidlc-docs/construction/build-and-test/` (`build-and-test-summary.md` 등), 테스트 실행 로그 (예: `logs/pytest.log`) |

- 실행 결과가 없으면 build-and-test 지침 (없으면 프로젝트의 테스트 명령) 실행을 제안한다
  - 사용자가 승인한 경우에만 실행하고, 실행 로그 위치를 결과에 적는다
  - 거절하면 해당 고리를 `GAP` (사유: 실행 근거 없음) 으로 둔다

## 3. ID 추출

- 산출물에 적힌 ID 를 그대로 쓴다: `FR-01`, `NFR-02`, `US-01`, `AC-01-1`, Unit 이름 (예: Unit A `routine-rule`), 컴포넌트 이름, 계획 Step 번호, 테스트 함수 이름
- ID 를 새로 만들지 않는다. ID 가 없는 산출물은 머리말 · 이름으로 대조하고 한계에 "ID 없음" 을 적는다
- AC 는 소속 스토리 아래에서 추적한다 (`US-01` → `AC-01-1`)

## 4. 정방향 점검 (누락 → GAP)

### ① inception (4고리)

- FR 마다: 이 FR 을 구현하는 User Story 가 있는가
- 스토리의 AC 마다: 배정된 Unit 이 있는가 (정상 · 경계 · 오류 AC 모두)
- NFR 마다: 보장할 책임 컴포넌트와 Unit 이 있는가 (NFR 은 스토리 없이 컴포넌트 · Unit 으로 직접 연결해도 된다)

### ② construction (6고리)

- AC · NFR 마다: 스토리 → Unit → 구현 계획 Step → 소스 · 테스트 → 실행 결과 (통과 근거) 가 이어지는가
- 계획 체크박스 `[x]` 는 통과 근거가 아니다. 테스트 실행 결과로 판정한다
- 아직 진행하지 않은 unit 의 AC 는 `GAP` (사유: unit 미완료) 이다. 보류 근거가 기록된 경우만 `Deferred`

- 끊긴 지점은 어느 고리에서 끊겼는지 함께 적는다 (예: "Unit 배정 없음", "테스트 없음")

## 5. 역방향 점검 (근거 없음 → ORPHAN)

- ① 컴포넌트 책임 · 메서드, story map 행 중 출처 요구 · 스토리가 없는 항목
- ② 구현 계획 Step, 새 소스 파일, 테스트 중 대응 AC · NFR 이 없는 항목
- 기술적 보조 항목 (예: `__init__.py`, 공통 설정) 은 `N/A` + 사유로 둔다

## 6. 판정

| 상태 | 뜻 | 조건 |
| --- | --- | --- |
| `OK` | 연결됨 | 연결 대상 기재 필수 |
| `GAP` | 정방향 누락 | 끊긴 고리 기재 |
| `ORPHAN` | 역방향 근거 없음 | 발견 위치 기재 |
| `Deferred` | 보류 | `audit.md` · 질문 파일에 보류 근거가 있을 때만, 근거 위치 기재 |
| `N/A` | 해당 없음 | 사유 기재 (SKIP 된 stage, 기술 보조 항목 등) |

- 통과 기준: `GAP` 0건, `ORPHAN` 0건 (`Deferred` 는 사유와 함께 허용)
- 산출물끼리 모순 (예: requirements 는 보류인데 stories 는 확정) 은 일관성 경고로 따로 적는다

## 7. 결과 기록

1. 결과 파일: `aidlc-docs/verification/phase-check-inception.md` (①) 또는 `phase-check-construction.md` (②)
   - [result-template.md](result-template.md) 양식을 따른다
   - 재실행하면 최신 결과로 갱신하고 회차를 1 올린다
2. `aidlc-docs/audit.md` 끝에 덧붙인다 (기존 내용 덮어쓰기 금지)

```markdown
## Traceability Check ① Inception
**Timestamp**: [ISO 8601 UTC, 예: 2026-10-21T06:40:00Z]
**User Input**: "[이 점검을 시작한 사용자 입력 원문 전체, workflow 자동 호출이면 직전 승인 응답]"
**AI Response**: "[판정 (통과/미통과), OK n · GAP n · ORPHAN n · Deferred n, 결과 파일 경로]"
**Context**: INCEPTION → CONSTRUCTION 경계 추적 점검

---
```

   - 입력 기록 hook 이 이번 입력 원문을 이미 기록했다고 안내했으면 `**User Input**: (hook 기록 [Timestamp])` 로 대신 쓰고, hook 이 알려준 현재 시각을 Timestamp 로 사용 (원문 중복 기록 금지)

3. `aidlc-docs/aidlc-state.md` 에 `Traceability Check` 행이 있으면 결과를 반영한다 (통과 + 사용자가 진행을 승인한 뒤 `[x]`, 승인 전에는 `[ ]` 유지). 행이 없으면 상태 파일을 수정하지 않는다

## 8. 완료 메시지 · 승인 대기

- 채팅에는 연결 결과를 한 줄씩 보여준다: `✓` OK, `✕` GAP · ORPHAN, `!` Deferred
  - 예: `✓ FR-01 → US-01 → RoutineEvaluator → Unit A`, `✕ NFR-02 → 책임 컴포넌트, Unit 없음`
- 이어서 정확히 다음 형식으로 끝낸다

```markdown
# 🔗 Traceability Check 완료 (Traceability Check Complete) - [① Inception | ② Construction]

- 판정: [통과 | 미통과] (OK n · GAP n · ORPHAN n · Deferred n · N/A n)
- 결과 파일: `aidlc-docs/verification/[phase-check-inception.md | phase-check-construction.md]`

> **📋 <u>**검토 필요 (REVIEW REQUIRED):**</u>**  
> 추적 점검 결과를 검토해 주세요: `aidlc-docs/verification/`

> **🚀 <u>**다음 단계 (WHAT'S NEXT?)**</u>**
>
> **선택할 수 있는 항목:**
>
> 🔧 **보완 요청 (Request Changes)** - 끊긴 연결 · 고아 항목을 앞 산출물에서 보완한 뒤 다시 점검  
> ✅ **다음 Stage 로 진행 (Continue to Next Stage)** - 점검 결과를 승인하고 **[next-stage-name 또는 workflow 완료]** 로 진행

---
```

- 사용자가 명시적으로 고를 때까지 진행하지 않는다
- 보완 요청: 보완 제안 표의 산출물을 해당 stage 규칙대로 고친 뒤 이 스킬을 다시 실행한다
- `GAP` · `ORPHAN` 이 남은 채 진행을 고르면 "미해소 상태로 진행" 과 남은 ID 를 `audit.md` 에 기록한다

## 금지

- 점검 중 산출물 · 코드 수정
- ID · 연결 · 실행 결과 지어내기, 실행 근거 없는 통과 판정
- 근거 없는 `Deferred`

## 한계 (결과 파일에도 적는다)

- AI 가 문서를 대조한 결과이며, 2.x 의 기계 검증 (`traceability.json` + 검사 엔진) 이 아니다
- ② 의 실행 결과 고리는 과정 확장이다 (2.x Gate 3 는 아키텍처 → 코드 → 테스트까지)

> 출처: awslabs/aidlc-workflows v2.11.1 `core/knowledge/aidlc-shared/verification.md`, `core/sensors/aidlc-traceability.md` (MIT-0) 를 1.0 형식으로 변환

# stage 실행 절차 (stage 스킬 공통)

- 호출: stage 스킬 `/aidlc-<phase>-<stage>` 또는 `/aidlc <별칭>` → 그 stage 스킬 `SKILL.md` 의 표 값으로 이 절차 진행
- 진행 규칙의 기준 = `.aidlc-rule-details/core-workflow.md` 의 "공통 stage 진행 규칙" (감사 기록, 승인 대기, 완료 메시지 고정, 진행 추적) · 공통 규칙 (질문 형식, 내용 검증)
  - 대화에 아직 없으면 먼저 읽기. stage 스킬은 "어디서 시작할지" 만 정하고, 진행 방식은 바꾸지 않음
- stage 내용은 스킬에 없음 → 항상 표의 규칙 파일 (`.aidlc-rule-details/...`) 을 읽고 그 Step 대로 진행
- 순서 (이동 방향 판단) = [stage-map.md](stage-map.md)

## 1. 인자 해석

| 인자 | 모드 |
| --- | --- |
| 없음 (unit stage 는 unit 만) | 이동 (3절) |
| `--single` 포함 | 단독 실행 (4절) |

- unit 이 필요한 stage (표 `unit` = ✅ 필요) 에 unit 이 없음
  - `aidlc-docs/inception/application-design/unit-of-work.md` 에서 unit 목록을 읽어 번호와 함께 보여주고 선택 요청
  - 파일이 없으면 Units Generation 미실행 → 2절 2지선다로 처리
- unit 이 필요 없는 stage 에 다른 인자 → 무시하지 말고 "이 stage 는 unit 을 받지 않음" 안내 후 이동 · 단독 실행 중 무엇인지 확인

## 2. 공통 사전 확인 (이동 · 단독 실행)

1. `aidlc-docs/aidlc-state.md` 확인
   - 없음 + 대상이 Workspace Detection 이 아님 → 진행하지 않고 `/aidlc-inception-workspace-detection` 먼저 실행 제안 (`--single` 도 동일)
2. 표의 "필요한 앞 산출물" 존재 확인 (폴더 · 파일 존재만, "A 또는 B" = 하나만 있으면 충족)
   - "SKIP 기록" = `aidlc-state.md` · `audit.md` 에 해당 stage SKIP 사유가 있음
3. 없는 산출물이 있으면 목록을 보여주고 2지선다로 묻기

```markdown
> **⚠️ 앞 산출물 없음 (Missing Prerequisites)**: [없는 경로 목록]
>
> 1️⃣ **앞 stage 먼저 실행 (Run Previous Stage First)** - `/aidlc-[phase]-[앞 stage]` 로 진행
> 2️⃣ **가정하고 진행 (Proceed with Assumptions)** - 가정 내용을 audit.md 에 기록하고 진행
```

- 사용자가 고를 때까지 진행하지 않음
- 2️⃣ 선택 → 가정 내용을 먼저 사용자에게 보여주고, audit.md 에 `**Context**: [스킬 이름] 가정 진행 - [가정 목록]` 으로 기록

## 3. 이동 (인자 없음 · unit 만)

### 방향 판단

- stage-map 순서 기준으로 `aidlc-state.md` 의 Current Stage 와 비교

| 방향 | 처리 |
| --- | --- |
| 앞으로 (현재보다 뒤 stage) | 사이의 미완료 항목 (`- [ ]`) 을 `- [ ] <상태 표기> - SKIP (stage 스킬 이동)` 으로 표기. 나중에 자동 실행 안 함 |
| 현재 stage | 표기 변경 없이 그대로 진행 |
| 뒤로 (이미 지난 stage) | 대상 + 그 뒤 완료 항목 (`[x]`) 을 `[ ]` + ` (재오픈)` 으로 표기. 산출물 파일은 지우지 않음 |

- 뒤로 이동 시 대상 stage 의 기존 산출물이 있으면 3지선다로 묻기

```markdown
> **📂 기존 산출물 있음 (Existing Artifacts Found)**: [경로 목록]
>
> 1️⃣ **유지 (Keep)** - 기존 산출물을 그대로 두고 승인 단계로 이동
> 2️⃣ **수정 (Modify)** - 기존 산출물을 바탕으로 고칠 부분만 진행
> 3️⃣ **처음부터 (Redo)** - 규칙 파일의 첫 Step 부터 다시 진행 (기존 파일은 덮어씀)
```

### 실행

1. 상태 파일 갱신: Current Stage = `[PHASE] - [상태 표기]` (unit 별이면 ` ([unit])`), 위 표의 표기 반영
   - Current Stage · Next Stage 값 = stage 이름 (+ unit) 만. 설명 · 괄호 메모는 audit.md 에 기록 (상태 표시줄 · 세션 hook 이 이 값을 그대로 표시)
2. audit.md 끝에 덧붙이기 (3-1 형식)
3. 표의 규칙 파일을 읽고 첫 Step 부터 진행 (Operations 는 `operations/operations.md` 도 함께)
4. 규칙 파일의 완료 메시지 · 승인 메뉴를 그대로 사용, 사용자 승인 전 진행 금지
5. 승인 후 이후 진행은 core-workflow 그대로 (실행 계획의 다음 EXECUTE stage)
   - 다음 stage 도 그 stage 의 완료 메시지에서 사용자 승인을 받아야 넘어감 (승인 없이 이어서 실행하는 stage 없음)
   - phase 경계 (INCEPTION 마지막 실행 stage 승인 직후, Build and Test 승인 직후): 다음 stage 를 시작하기 전에 "추적 점검: `/traceability-check inception` (또는 `construction`) 을 실행할 수 있음" 을 1줄로 안내. 점검을 대신 실행하지 않음 (사용자가 스킬을 직접 호출, hook 자동 실행 없음)

### 3-1. audit 기록 형식

```markdown
## stage 스킬 이동 (Stage Jump)
**Timestamp**: [ISO 8601]
**User Input**: "[사용자 입력 원문 전체]"
**AI Response**: "[방향] [이전 Current Stage] → [대상 stage], SKIP 표기: [목록 또는 없음], 재오픈: [목록 또는 없음]"
**Context**: /[스킬 이름] 이동

---
```

- UserPromptSubmit hook 이 이번 입력 원문을 이미 기록했다는 안내를 받았으면 `**User Input**: (hook 기록 [Timestamp])` 로 대신 (중복 기록 금지)
- audit.md 는 덧붙이기만 (전체 덮어쓰기 금지)

## 4. 단독 실행 (`--single`)

- 2절 사전 확인 → 규칙 파일대로 진행 → 규칙 파일의 완료 메시지 · 승인까지 수행 후 멈춤
- 상태 파일의 Current Stage · Next Stage · Stage Progress 체크는 바꾸지 않음
- 승인 후 `aidlc-state.md` 끝의 `## Single-Stage Runs` 절에 1줄 추가 (절이 없으면 만들기)

```markdown
## Single-Stage Runs
- [ISO 8601] [상태 표기] ([unit]) - [승인 | 변경 요청 중단] - 산출물: [경로]
```

- audit.md 기록은 3-1 형식, 제목만 `## stage 스킬 단독 실행 (Single-Stage Run)`, Context = `/[스킬 이름] --single`
- 완료 메시지의 "다음 Stage 로 진행 (Continue to Next Stage)" 선택 시 다음 stage 로 넘어가지 않고 `/aidlc` 상태 안내 출력으로 마무리

## 금지

- 1.0 규칙 파일 내용을 생략하거나 스킬 내용으로 대신하기
- 사용자 선택 없이 SKIP · 재오픈 · 가정 진행 결정
- 산출물 파일 삭제 (재오픈 · 처음부터도 덮어쓰기만)

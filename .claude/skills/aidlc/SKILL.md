---
name: aidlc
description: AI-DLC 진행 상태와 stage 스킬 안내. 인자 없이 부르면 진행 상태 (현재 · 다음 stage, 진행 수) 와 다음에 부를 stage 스킬을 보여주고, 별칭 (예 req, fd) 을 주면 해당 stage 스킬 (/aidlc-<phase>-<stage>) 과 같은 이동 · --single 단독 실행을 한다. 사용자가 /aidlc 로 직접 호출할 때만 사용.
argument-hint: "[status | <별칭> [unit] [--single]]"
disable-model-invocation: true
---

# /aidlc — 상태 보기 · stage 스킬 안내

- 인자: `$ARGUMENTS`
- stage 는 스킬 하나씩: `/aidlc-<phase>-<stage>` (예: `/aidlc-inception-requirements-analysis`), 목록 · 별칭 = [stage-map.md](stage-map.md)
- stage 실행 절차 (이동 · 단독 실행 공통) = [stage-runner.md](stage-runner.md)

## 1. 인자 해석

| 인자 | 동작 |
| --- | --- |
| 없음 · `status` | 상태 보기 (2절) |
| `<별칭> [unit] [--single]` | 해당 stage 스킬과 같은 동작 (3절) |

- 별칭 = stage-map 의 별칭 · slug · 스킬 이름 · 상태 표기 (대소문자 무시, 예: `req`, `requirements-analysis`, `Requirements Analysis`)
- 모르는 이름 → 실행하지 않고 stage-map 목록 (스킬 · 별칭 · 상태 표기) 을 보여준 뒤 다시 입력 요청
- `traceability-check` 계열 이름 → stage 아님. `/traceability-check` · `/traceability-check-agent` 사용 안내

## 2. 상태 보기 (`/aidlc`, `/aidlc status`)

- `aidlc-docs/aidlc-state.md` 를 읽기만 함. 파일 · 산출물 수정 없음, audit 기록 없음
- 다음 형식으로 출력

```markdown
# 🧭 AI-DLC 상태 (AI-DLC Status)

- 현재 (Current Stage): [값]
- 다음 (Next Stage): [값 또는 첫 미완료 항목]
- 진행: [완료 수] / [전체 수 (SKIP 제외)]

| Phase | 완료 | 남음 | SKIP |
| --- | --- | --- | --- |
| 🔵 INCEPTION | n | n | n |
| 🟢 CONSTRUCTION | n | n | n |
| 🟡 OPERATIONS | n | n | n |

- 이어서 진행: `/aidlc-[phase]-[다음 stage] [unit]`
- 한 stage 만: `/aidlc-[phase]-[stage] [unit] --single`
- 추적 점검 (stage 아님): `/traceability-check` · `/traceability-check-agent` [inception | construction]
```

- 추적 점검 안내 (읽기만, 실행하지 않음): 아래 조건이면 "이어서 진행" 줄 위에 `- 먼저 권장: /traceability-check <인자>` 1줄 추가
  - `inception`: INCEPTION 항목이 모두 완료 · SKIP 이고 `aidlc-docs/verification/phase-check-inception.md` 없음
  - `construction`: Build and Test 완료이고 `aidlc-docs/verification/phase-check-construction.md` 없음
  - 점검은 자동 실행되지 않음 (hook 없음) → 사용자가 스킬을 직접 호출

- 다음 stage 의 스킬 이름은 stage-map 에서 상태 표기로 찾아 실제 이름으로 채움 (unit 별 stage 는 unit 이름까지)
- `aidlc-state.md` 없음 → "AI-DLC 시작 전" + `/aidlc-inception-workspace-detection` 또는 "Using AI-DLC, ..." 요청 안내
- `## Single-Stage Runs` 절이 있으면 최근 3줄 함께 표시

## 3. 별칭으로 stage 실행 (`/aidlc <별칭> [unit] [--single]`)

1. stage-map 에서 스킬 이름 찾기
2. `.claude/skills/<스킬 이름>/SKILL.md` 를 읽고, 그 표 값과 나머지 인자 (`[unit] [--single]`) 로 stage-runner 절차 진행
3. audit Context 는 stage 스킬 이름 사용 (`/aidlc` 경유 여부는 기록 안 함)

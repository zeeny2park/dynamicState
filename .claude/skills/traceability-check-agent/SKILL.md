---
name: traceability-check-agent
description: AI-DLC 추적성 점검의 서브에이전트 버전. 점검 (산출물 읽기 · ID 대조 · 결과 파일 쓰기) 은 aidlc-traceability 서브에이전트가 별도 맥락에서 하고, 메인은 요약만 받아 audit 기록 · 승인 대기를 맡는다. 점검 기준 · 결과 형식은 traceability-check 스킬과 같다. 사용자가 서브에이전트 버전 · traceability-check-agent 를 지정하거나 workflow 규칙이 이 이름을 지정할 때만 사용 (그 밖의 추적 점검 요청은 traceability-check).
argument-hint: "[inception|construction]"
---

# Traceability Check — 서브에이전트 버전

- 인자: `$ARGUMENTS`
- 기준 절차: [../traceability-check/SKILL.md](../traceability-check/SKILL.md) (서브에이전트 없는 버전)
- 차이: 1~7-1 (대상 결정 · 대조 · 결과 파일) 을 서브에이전트 `aidlc-traceability` 에 맡김

## 1. 사전 확인 (메인)

- `aidlc-docs/` 가 없으면 "AI-DLC 산출물 없음" 으로 보고하고 끝낸다
- 인자가 `inception` · `construction` · 빈 값이 아니면 사용자에게 대상을 묻는다

## 2. 서브에이전트 호출 (메인)

- Agent 도구로 `aidlc-traceability` 호출, 프롬프트에 다음을 넣는다
  - 대상: 인자 (빈 값이면 "추정")
  - 시작 입력: 이 점검을 시작한 사용자 입력 원문 (workflow 자동 호출이면 직전 승인 응답)
- 메인은 산출물을 직접 읽지 않는다 (대화 공간 절약 · 독립 점검 유지)
- `aidlc-traceability` 를 찾을 수 없으면: "Claude Code 재시작 필요 (첫 `.claude/agents/` 추가 후)" 를 안내하고 서브에이전트 없는 버전 `traceability-check` 실행을 제안한다

## 3. 실행 제안 처리 (② 만, 메인)

- 반환 요약의 `실행 제안` 이 "없음" 이 아니면 사용자에게 테스트 실행 여부를 묻는다
  - 승인: 메인이 명령 실행 → 로그 저장 (예: `logs/pytest.log`) → 로그 경로를 넣어 서브에이전트 재호출 (2 반복)
  - 거절: 해당 고리 `GAP` (사유: 실행 근거 없음) 유지

## 4. 기록 (메인)

- `aidlc-docs/audit.md` 끝에 덧붙인다: 기준 절차 7-2 형식, `**Context**` 끝에 `· 서브에이전트 버전` 추가
  - 사용자 입력 원문이 hook 으로 이미 기록됐으면 `**User Input**: (hook 기록 <Timestamp>)`
- `aidlc-state.md` 반영: 기준 절차 7-3 과 같음
- 결과 파일은 서브에이전트가 쓴 것을 그대로 둔다 (메인 수정 금지)

## 5. 완료 메시지 · 승인 대기 (메인)

- 반환 요약의 연결 줄을 그대로 보여준 뒤, 기준 절차 8 의 완료 메시지 형식으로 끝낸다
  - 제목 끝에 ` · 서브에이전트` 추가: `# 🔗 Traceability Check 완료 (Traceability Check Complete) - ① Inception · 서브에이전트`
- 사용자가 명시적으로 고를 때까지 진행하지 않는다
- 보완 요청: 해당 stage 규칙대로 산출물 보완 → 이 스킬 재실행

## 두 버전 비교

| 항목 | `traceability-check` | `traceability-check-agent` (이 스킬) |
| --- | --- | --- |
| 산출물 읽기 | 메인 대화 | 서브에이전트 (요약만 메인으로) |
| 점검자 | 산출물을 만든 같은 대화 | 분리된 맥락 |
| 테스트 실행 | 메인 (사용자 승인 후) | 메인 (서브에이전트 실행 제안 → 사용자 승인 후) |
| 결과 파일 · 판정 기준 | 같음 | 같음 |

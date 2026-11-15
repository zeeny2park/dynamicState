# Traceability Check 결과 양식

- 아래 블록을 `aidlc-docs/verification/phase-check-inception.md` (①) 또는 `phase-check-construction.md` (②) 로 작성
- `[...]` 는 채우고, 해당 없는 표는 "없음" 한 줄로 둔다
- 정방향 표는 점검 종류 (① / ②) 에 맞는 것 하나만 쓴다

```markdown
# Traceability Check 결과 — [① Inception (Inception → Construction) | ② Construction (Construction → Operations)]

- **점검 시각**: [ISO 8601]
- **회차**: [1, 재점검마다 +1]
- **대상 결정**: [인자 `inception`/`construction` | aidlc-state.md 로 추정: 근거]
- **입력 파일**:
  - [aidlc-docs/inception/requirements/requirements.md]
  - [...]

## 1. 요약

| 항목 | 값 |
| --- | --- |
| 판정 | [통과 / 미통과] |
| 정방향 대상 수 | [n] (FR n · NFR n · AC n) |
| OK | [n] |
| GAP | [n] |
| Deferred | [n] |
| N/A | [n] |
| ORPHAN (역방향) | [n] |
| 커버리지 | ① 요구 → 스토리 [n/n], AC → Unit [n/n], NFR → 컴포넌트 [n/n] / ② AC → 테스트 [n/n], 테스트 → 실행 통과 [n/n] |

## 2. 정방향 추적 (요구 → 하위 산출물)

### ① Inception (4고리)

| ID | 내용 요약 | User Story · AC | 컴포넌트 | Unit | 상태 | 대상 · 사유 |
| --- | --- | --- | --- | --- | --- | --- |
| [FR-01] | [요구 한 줄] | [US-01 (AC-01-1, AC-01-2)] | [RoutineEvaluator] | [Unit A `routine-rule`] | [OK] | [story map 1행] |
| [NFR-02] | [...] | [-] | [-] | [-] | [GAP] | [책임 컴포넌트 · Unit 없음] |

### ② Construction (6고리)

| ID | User Story | Unit | 구현 계획 Step | 소스 · 테스트 | 실행 결과 | 상태 | 대상 · 사유 |
| --- | --- | --- | --- | --- | --- | --- | --- |
| [AC-02-1] | [US-02] | [Unit A `routine-rule`] | [Step 2] | [`tests/test_x.py::test_y`] | [PASS (`logs/pytest.log`)] | [OK] | [...] |
| [AC-02-3] | [US-02] | [Unit A] | [-] | [-] | [-] | [Deferred] | [audit.md "Open Decision" 항목] |

## 3. 역방향 추적 (근거 없는 항목)

| 항목 | 위치 | 상태 | 사유 |
| --- | --- | --- | --- |
| [RoutineExecutor 실행 이력 조회] | [components.md] | [ORPHAN] | [출처 요구 · 스토리 없음] |
| [`src/routine/__init__.py`] | [code-generation-plan Step 1] | [N/A] | [패키지 초기화 파일] |

## 4. 일관성 경고

- [산출물 간 모순, 예: requirements 는 보류인데 stories 는 확정 표기 / 없으면 "없음"]

## 5. 보완 제안

| 대상 | 문제 | 보완할 산출물 | 담당 stage |
| --- | --- | --- | --- |
| [NFR-02] | [책임 컴포넌트 없음] | [components.md, unit-of-work-story-map.md] | [Application Design, Units Generation] |

## 6. 한계

- AI 가 문서를 대조한 결과이며 기계 검증 (2.x `traceability.json` + 검사 엔진) 이 아님
- [ID 없음 등 이번 점검의 제약 / ② 실행 결과 고리 = 과정 확장 (2.x Gate 3 범위 밖)]

## 7. 사람 확인

- [ ] 점검 결과 검토 완료 (승인자: [ ], 시각: [ ])
```

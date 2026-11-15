# Stage 점검표 (Stage Checklists, 과정판 추가)

**목적**: stage 완료 메시지를 제시하기 전에 AI 가 산출물을 스스로 점검하고, 사람이 판단할 부분을 좁혀 준다 (AI-DLC 2.x 의 sensor 를 1.0 에 옮긴 것)

**적용 범위**: 아래 표에 있는 INCEPTION · CONSTRUCTION stage 만. Workspace Detection · Operations stage · Traceability Check 는 대상 아님 (Traceability Check 는 자체 점검 스킬 사용)

## 점검 절차

1. stage 산출물 작성이 끝나면, 완료 메시지를 제시하기 전에 공통 항목 (S0 ~ S2) 과 해당 stage 항목을 점검한다
2. 실제로 파일을 열어 확인한 결과만 적는다. 열어 보지 않은 항목은 ✅ 로 적지 않고 `⚠️ 미확인` 으로 적는다
3. ❌ 항목은 1회 보완한 뒤 다시 점검한다. 보완 뒤에도 남은 ❌ 는 그대로 보고한다 (진행 여부는 사람이 결정)
4. 결과 블록을 완료 메시지 **바로 위**에 붙인다. 완료 메시지 · 승인 메뉴 자체는 stage 규칙 파일 그대로 유지한다 (완료 메시지 고정 규칙)
5. audit.md 의 해당 stage 기록에 `**AI 점검**: ✅ n · ⚠️ n · ❌ n` 한 줄을 남긴다

## 판정 기준

| 표시 | 뜻 |
| --- | --- |
| ✅ | 충족 |
| ⚠️ | 확인 필요 (판단이 필요하거나, 형식은 맞지만 내용이 약함, 미확인) |
| ❌ | 미충족 (빠진 파일 · 빈칸 · 끊긴 연결) |

## 결과 블록 형식

```markdown
> **🤖 AI 점검 결과 (AI Self-Check)**: ✅ [n] · ⚠️ [n] · ❌ [n]
>
> | 코드 | 항목 | 결과 | 근거 |
> | --- | --- | --- | --- |
> | S0 | 질문 답변 빈칸 | ✅ | `[Answer]:` 12개 모두 답변 |
> | RA-2 | 모호한 표현 | ⚠️ | requirements.md "빠르게" 2곳 (FR-03, NFR-01) |
>
> **👤 먼저 볼 곳**: [⚠️ · ❌ 항목의 파일 · 위치 1~3개]
```

- ✅ 항목은 표에서 한 줄로 묶어도 된다 (예: `S0 · S1 · S2 | ✅`), ⚠️ · ❌ 는 항목마다 한 줄

## 공통 항목 (모든 대상 stage)

| 코드 | 점검 |
| --- | --- |
| S0 | 위생: 질문 파일 `[Answer]:` 빈칸 0, 계획 체크박스 완료분 `[x]` 표시, aidlc-state.md 갱신, audit.md 기록 |
| S1 | 필수 산출물: stage 규칙 파일이 정한 파일이 모두 있고 비어 있지 않음 |
| S2 | 앞 산출물 반영: stage 규칙 파일이 읽으라고 한 앞 산출물의 내용이 이 산출물에 반영됨 (빠진 항목 이름 나열) |

- ID 표기: 산출물에 적힌 ID 를 그대로 쓴다 (`FR-01`, `NFR-02`, `US-01`, `AC-01-1`, Unit 이름). ID 가 없으면 이름으로 대조하고 ⚠️ 로 "ID 없음" 을 알린다

## INCEPTION stage 항목

| Stage | 코드 | 점검 |
| --- | --- | --- |
| Reverse Engineering | RE-1 | 산출물에 적은 코드 경로 · 모듈이 실제로 존재 |
| | RE-2 | component-inventory 의 컴포넌트가 architecture 에 모두 등장 |
| Requirements Analysis | RA-1 | 질문 답변마다 requirements.md 에 반영 위치가 있음 |
| | RA-2 | 모호한 표현 ("빠르게", "적절히", "많은", "쉽게") 이 수치 · 조건 없이 남아 있지 않음 |
| | RA-3 | NFR 에 측정 가능한 기준 (수치 · 조건) 이 있음 |
| | RA-4 | 확장 opt-in 결과가 aidlc-state.md `## Extension Configuration` 에 기록됨 |
| User Stories | US-1 | 모든 기능 요구 (FR) 가 하나 이상의 스토리에 연결됨, 연결 없는 스토리 없음 |
| | US-2 | 스토리마다 인수 조건 (AC) 이 있고, AC 가 확인 가능한 문장 (조건 · 기대 결과) 임 |
| | US-3 | 스토리에 등장하는 사용자가 personas.md 에 있음 |
| Workflow Planning | WP-1 | 모든 stage 에 EXECUTE / SKIP 표시가 있고 SKIP 마다 사유가 있음 |
| | WP-2 | execution-plan.md 와 aidlc-state.md 의 stage 표시가 일치 |
| Application Design | AD-1 | 모든 스토리가 하나 이상의 컴포넌트에 배정됨, 스토리가 없는 컴포넌트 없음 |
| | AD-2 | component-dependency 에 순환 의존이 없음 (있으면 근거) |
| | AD-3 | component-methods 의 메서드가 components 의 책임과 맞음 |
| Units Generation | UG-1 | 모든 스토리가 unit-of-work-story-map 에서 하나 이상의 unit 에 배정됨 |
| | UG-2 | unit-of-work-dependency 에 순환 의존이 없음 |
| | UG-3 | unit 진행 순서가 의존 순서와 맞음 (의존하는 unit 이 뒤에 옴) |

## CONSTRUCTION stage 항목 (unit 별)

| Stage | 코드 | 점검 |
| --- | --- | --- |
| Functional Design | FD-1 | 이 unit 에 배정된 스토리의 AC 가 business-rules 또는 business-logic-model 에 모두 반영됨 |
| | FD-2 | domain-entities 의 엔티티 · 속성이 요구 데이터와 맞음 (요구에 없는 엔티티는 근거) |
| NFR Requirements | NR-1 | 이 unit 에 해당하는 NFR 이 모두 nfr-requirements 에 있음 |
| | NR-2 | 기술 스택 결정마다 선택 근거가 있음 |
| NFR Design | ND-1 | nfr-requirements 항목마다 대응 패턴 · 구성 요소가 있음 |
| Infrastructure Design | ID-1 | 사용자가 확인한 환경 · 도구만 사용 (확인되지 않은 클라우드 리소스 · 도구는 ❌) |
| Code Generation (계획) | CG-1 | 계획 Step 마다 대상 스토리 · AC 가 적혀 있고, 이 unit 의 AC 가 모두 어느 Step 에 들어 있음 |
| | CG-2 | 코드 파일 경로가 workspace 기준이며 `aidlc-docs/` 안에 코드가 없음 |
| | CG-3 | 단위 테스트 Step 이 있음 |
| Code Generation (생성) | CG-4 | 계획 체크박스가 모두 `[x]` |
| | CG-5 | 프로젝트의 테스트 · 검사 명령 (예: `pytest`, `ruff check`) 실행 결과 (명령 · 통과 수 · 실패 수). 실행할 수 없으면 ⚠️ 미실행 + 사람이 돌릴 명령 1줄 |
| | CG-6 | 원본 옆 복제 파일 (`*_new.*`, `*_modified.*`, `*_v2.*`) 이 없음 |
| | CG-7 | 계획에 없던 변경 · 계획에서 뺀 항목 목록 (없으면 "없음") |
| Build and Test | BT-1 | 모든 unit 이 빌드 · 테스트 지침에 포함됨 |
| | BT-2 | 지침의 명령 · 경로 · 스크립트가 실제 프로젝트에 존재 (없는 스크립트 · 경로 참조는 ❌) |

- Code Generation 은 계획 승인 질문 앞에 CG-1 ~ CG-3, 완료 메시지 앞에 CG-4 ~ CG-7 을 점검한다

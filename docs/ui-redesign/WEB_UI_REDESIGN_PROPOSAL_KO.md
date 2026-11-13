# 웹 UI 전면 개편 제안 (목업)

- **작성일**: 2026-11-13
- **브랜치 / worktree**: `feat/web-ui-redesign` · `/home/ubuntu/workspace/ut-webui` (기준 `feat/visual-incident-report` `bba6cf7`)
- **상태**: 제안. 아래 6장의 결정이 나면 구현 단계로 간다.
- **목업**: `docs/ui-redesign/mock/index.html` (의존성 없는 정적 파일 한 개). `?stage=0..6` 으로 단계를 고르고,
  오른쪽 아래 "목업 단계" 바의 **▶ 재생** 을 누르면 진단이 실제 속도의 약 0.9배로 흘러가며 화면이 쌓이는 모습을 볼 수 있다.

## 1. 현재 상태와 문제

| | 레거시 UI (`extractor/web/static`, `/`) | 워크스페이스 UI (`workspace_static`, `/workspace`) |
|---|---|---|
| 크기 | HTML 3,300줄 + JS 10,624줄 + CSS 4,003줄 | HTML 한 파일 2,350줄 (Tailwind CDN · Google Fonts 의존) |
| 구성 | 탭 8개 (Target, Runtime Explorer, Watch List, Timeline, Investigation, Object Graph, State DAG, Lab) | 2단: 왼쪽 채팅, 오른쪽 트레이스 카드. 상단에 버튼 8개 |
| 진단 진입 | 5번 탭 안 | 상단 "원클릭 종합 진단"과 "Diagnose" 두 버튼이 따로 있음 |
| 결과 표시 | 세션이 끝난 뒤 한 번에 | 동기 호출이 끝난 뒤 한 번에 (`POST /api/diagnose`) |

문제는 세 가지다. (1) 진단 하나를 위해 두 UI, 두 진입점, 버튼 여덟 개가 있다. (2) 결과가 끝난 뒤에 통째로 나오므로 5~20초 동안
화면이 비어 있다. (3) 보고서(`human_report` HTML)는 이미 잘 정리된 시각 언어(`dsv-*`)를 갖췄는데 UI는 그것과 다른 모양이다.

## 2. 설계 원칙

**한 화면, 한 열. 위에서 아래로 정보가 쌓이고, 끝나면 그 화면이 곧 보고서다.**

- 입력은 PID 하나. 나머지(증상, 디버그 ELF, SSH)는 선택.
- 화면의 요소는 **추가만** 된다. 이미 보이는 것은 자리를 옮기지 않는다. 사용자는 아래로만 읽으면 된다.
- 상세는 **관련 항목 안에서, 요청할 때만** 펼친다 (2026-11-13 08:43 요구). 검사 행을 누르면 그 검사의 결과만, 발견 카드의
  "근거"를 펼치면 그 발견의 근거만, 상세 보고서 링크는 해당 절(D/F/G)로 바로 간다.
- 색·간격·배지는 보고서 HTML의 토큰(`--bad/--warn/--good/--unk`, 카드 반경 10~12px)을 그대로 쓴다. UI와 보고서가 한 시스템으로 보인다.
- 외부 의존 없음(CDN·웹폰트 없음). 임베디드 장비 옆 폐쇄망에서 열린다.

## 3. 참고한 화면과 가져온 패턴

| 참고 | 가져온 것 | 목업에서의 위치 |
|---|---|---|
| **GitHub Actions** 잡 화면 · PR Checks | 단계 목록이 실행되면서 아이콘이 바뀌고, 행을 펼치면 그 단계의 로그만 보인다 | "검사" 카드. 통과/이상/판단 불가/실행 안 함 네 상태, 행 클릭으로 그 검사만 펼침 |
| **Vercel** 배포 상세 | 상단에 상태 헤더 하나(Queued → Building → Ready), 끝나면 같은 자리가 요약으로 바뀐다 | 맨 위 배너. 진단 중에는 진행 띠(대상 확인 → 증상 분류 → 계획 → 수집 → 분석·검증 → 판정), 끝나면 판정 한 문장 |
| **Sentry** 이슈 상세 | 제목과 태그가 먼저, 스택 같은 근거는 아래, 제안 조치는 별도 블록 | "발견된 문제" 카드(배지·그림·순서 5단계) + "다음에 할 일" + 접힌 "근거" |
| **Linear / Stripe 대시보드** | 강조색 하나, 중립 회색, 좁은 타일 행으로 핵심 수치 | 타일 5개(신뢰도 · 검사 · 대상 정지 시간 · 읽은 데이터 · 소요 시간), 값이 생기는 순서대로 채워짐 |
| 현재 보고서 HTML (`dsv-*`) | 판정 배지, 발견별 그림, 체크리스트 분류 | 같은 토큰·같은 용어를 사용 |

## 4. 화면 구성: 단계별로 무엇이 추가되는가

| 단계 | 엔진 상태 | 화면에 **추가**되는 것 | 스크린샷 |
|---|---|---|---|
| 0 대기 | – | 제목 한 줄, 입력 폼(로컬/SSH, PID 또는 이름, 증상, 디버그 ELF), 최근 진단 목록 | `screens/stage0.png` |
| 1 대상 | CLASSIFYING → ASSESSING | 배너 "진단 중", 헤더에 대상 칩, "대상" 카드(프로세스·아키텍처·Build ID 일치·디버그 정보·전송), 타일에 정지 시간 0 ms | `screens/stage1.png` |
| 2 계획 | PLANNING → COLLECTING | "검사" 카드에 계획된 검사 전부가 대기 상태로, "실행 안 함 N" 접힘 그룹, 타일 "검사 24" | `screens/stage2.png` |
| 3 수집 | COLLECTING (단계별) | 검사 행이 하나씩 ✔/✖/?로 바뀌고 소요 ms 표시. 첫 ✖ 에서 **"발견된 문제" 카드가 "의심 · 검증 중" 배지로 생김**, 고리 검사가 끝나면 그림이 닫힘 | `screens/stage3.png` |
| 4 검증 | ANALYZING → VERIFYING → NARROWING | 발견 배지 "검증됨", 5번째 단계(재읽기 일치) 채워짐, 반박된 경쟁 가설 칩 | `screens/stage4.png` |
| 5 판정 | 종료 | 배너가 판정색으로 바뀌고 결론 한 문장, 타일 완성(신뢰도·읽은 데이터·소요), "확인하지 못한 것", "다음에 할 일", "보고서"(HTML/MD/JSON·요약 복사·다시 진단) | `screens/stage5.png` |
| 정상 사례 | 종료 (HEALTHY) | 같은 구조. 배너 초록, 발견 카드 없음, "확인하지 못한 것"이 범위 한계를 말함 | `screens/stage6.png` |

INCONCLUSIVE 는 회색 배너에 `not_covered` 의 첫 항목이 결론 문장이 된다(예: "디버그 이미지가 없어 판단하지 못했습니다"). 구조는 같다.

## 5. 서버 쪽 변경: 정보가 생기는 즉시 보내기

엔진은 이미 상태 머신이고(`AdaptiveInvestigationSession.step()`), 세션은 시작 시 `engine.sessions[inv_id]` 에 등록되므로 실행 중에도
`get_status()` · `get_plan()` · `get_checks()` · `timeline` 을 읽을 수 있다. 부족한 것은 `diagnose()` 가 동기라는 점뿐이다.

| 이벤트 | 출처 | 화면 |
|---|---|---|
| `target` | `_step_assess` 결과 (`TargetAssessmentResult`) | 대상 카드, 헤더 칩 |
| `classified` | `_step_classify` (`ProblemClassificationResult`) | 배너 부제 "증상 → 범주, 가설 N개" |
| `plan` | `get_plan()` (`InvestigationStep` 목록, 제외 레시피) | 검사 카드 골격, 타일 "검사" |
| `check_start` / `check_done` | `_step_collect_next` 전후의 step.status, `get_checks()` | 검사 행 상태·한 줄 결과·ms |
| `finding_provisional` | FAIL 한 검사가 속한 `ExpertHypothesis` 가 처음 지지될 때 | 발견 카드(의심 배지) |
| `verified` | `_step_verify` 의 재읽기·경쟁 가설 결과 | 발견 배지 "검증됨", 5단계, 반박 칩 |
| `verdict` | `DiagnoseResult` 전체 + `human_summary` | 배너·타일·확인하지 못한 것·다음에 할 일·보고서 |

구현은 작다.

1. `POST /api/diagnose/start` → `{job_id, investigation_id}`. 기존 `diagnose_with_summary` 를 작업 스레드에서 실행한다(세션당 하나, 기존 `POST /api/diagnose` 는 그대로 둔다).
2. `GET /api/diagnose/{job_id}/events` → SSE. `_record_timeline_event` 에 선택적 리스너 하나를 달아 위 표의 이벤트로 바꾼다. SSE 를 못 쓰는 프록시를 위해 `GET /api/diagnose/{job_id}/status` 폴링도 같은 JSON 을 준다(현재 외부 데모는 nginx 경유).
3. 끝나면 `verdict` 이벤트에 `report_path` 와 `human_summary` 가 실린다. 새 UI 의 "HTML 보고서 열기"는 기존 보고서 파일이다.

엔진 판정 로직은 건드리지 않는다. 리스너는 읽기만 한다.

## 6. 레거시 정리

- 새 UI 가 `/` 이 된다. 파일은 `extractor/web/ui/index.html` 한 개(+ 필요 시 `ui.css`, `ui.js`), CDN 없음.
- 레거시 두 벌은 `/legacy/` 와 `/legacy/workspace` 로 옮기고 헤더의 "도구 ▾" 에서만 연다. 한 릴리스 동안 유지한 뒤 제거 여부를 결정한다.
  (스냅샷·상태 그래프·워치리스트 같은 탐색 기능은 MCP 도구로 이미 제공되므로, 웹에서 다시 만들지 않는다.)
- 워크스페이스 UI 의 채팅 패널(LLM)은 새 UI 에 넣지 않는다. 그 역할은 MCP 호출자가 한다(로드맵 3.3 "LLM 표준화는 엔진 밖").

## 7. 구현 단계

| 단계 | 내용 | 완료 조건 |
|---|---|---|
| A | 새 정적 UI + 기존 동기 `POST /api/diagnose` 로 **끝난 뒤 한 번에** 렌더 (5·6단계 화면) | 샘플 보고서 17종의 JSON 으로 화면이 깨지지 않음. 외부 의존 0 |
| B | `start` / `events` / `status` 엔드포인트와 타임라인 리스너, UI 의 점진 표시 (1~4단계) | 로컬 `deadlock_pipeline` 대상에서 첫 ✖ 가 1초 안에 화면에 뜸. 엔진 테스트 전부 통과, 판정 변화 없음 |
| C | 라우팅 교체(`/` → 새 UI, 레거시 `/legacy/`), README · `bin/dynamic-state-ui` · nginx 데모 갱신 | 기존 서버 테스트 통과, 데모 주소에서 새 UI |

A 와 B 는 서로 다른 파일(정적 파일 vs `server.py`)이라 병렬로 진행할 수 있다. 다른 worktree 에서 진행 중인 엔진 작업과 겹치는 파일은
`server.py` 의 라우트 추가뿐이다.

## 8. 결정이 필요한 것

1. **레거시 범위**: 6장처럼 `/legacy/` 로 보존 후 제거 검토 / 즉시 제거 / 전부 유지.
2. **채팅 패널**: 새 UI 에서 제외(제안) / 접힌 보조 패널로 유지.
3. **언어**: 한국어 기본 + 영어 토글(제안, 보고서와 동일한 `lang` 파라미터 사용) / 한국어만.

# 공통 디자인 시스템과 화면 구성

- **작성일**: 2026-11-13 · 브랜치 `feat/web-ui-redesign`
- **파일**: `docs/ui-redesign/mock/theme.css` (토큰 + 컴포넌트, 14 KB, 의존성 없음), 쇼케이스 `mock/design-system.html`
- **근거**: shadcn/ui 스킬(`.claude/skills/shadcn`, `npx skills add shadcn-ui/ui`)의 토큰 규약(`customization.md`)과 스타일 선택 기준(`design-system.md`)

## 1. UX 통일성은 어떻게 유지되는가

세 가지 장치로 유지된다. 어느 하나라도 빠지면 화면과 보고서가 다시 갈라진다.

| 장치 | 내용 | 효과 |
|---|---|---|
| **토큰 파일 하나** | 라이브 UI(`index.html`)와 정적 보고서가 같은 `theme.css`를 읽는다. 보고서는 파일로 혼자 열려야 하므로 서버가 생성 시 인라인한다 | 색·반경·글꼴·간격이 한 곳에서 바뀐다 |
| **같은 JSON, 같은 카드 순서** | 화면도 보고서도 `DiagnoseResult` JSON 하나를 같은 순서(판정 → 타일 → 대상 → 발견 → 검사 → 확인 못 한 것 → 다음 할 일)로 그린다 | 라이브 화면의 마지막 상태 = 보고서. 사용자가 두 번 배우지 않는다 |
| **상태 어휘 네 개** | FAIL · INCONCLUSIVE · PASS · SKIPPED. 단어(이상 발견 · 판단 불가 · 통과 · 실행 안 함), 색, 아이콘(✖ ? ✔ –)이 판정 배지, 검사 행, 타일, 최근 목록에서 같다 | 색만 보고도 읽힌다. 새 진단 종류가 늘어도 어휘는 늘지 않는다 |

기존 보고서 렌더러(`extractor/report_visuals.py`)는 `.dsv-*` 클래스와 자기만의 변수(`--bad`, `--good`…)를 쓴다. `theme.css` 끝의 **브리지 블록**이 그 변수를 공통 토큰에 매핑하므로, 보고서 마크업을 고치지 않아도 같은 테마를 입는다. 구현 단계 A에서 `_CSS` 상수를 `theme.css` 내용으로 바꾸면 끝난다.

## 2. 공통 화면 구성 (앱 셸)

```
┌ 헤더 52px ───────────────────────────────────────────────────────────┐
│ ● dynamicState 진단   [대상 칩: 이름 · pid · arch · ● 진단 중]   새 진단 ◐ KO 도구▾ │
├ 콘텐츠 한 열, 최대 920px, 카드 간격 12px ─────────────────────────────┤
│ 1 판정 배너 (card-tone: 왼쪽 5px 색 띠 = 판정색, 진행 중엔 info)        │
│ 2 타일 5개 (신뢰도 · 검사 · 대상 정지 시간 · 읽은 데이터 · 소요 시간)    │
│ 3 대상 (프로세스 · 아키텍처 · 실행 파일 · Build ID · 디버그 정보 · 전송) │
│ 4 발견된 문제 (발견마다: 제목+배지 / 그림 | 순서 단계 / 접힌 근거)       │
│ 5 검사 (행 = 상태 아이콘 · 이름 · 범주 · 한 줄 결과 · ms, 클릭으로 펼침) │
│ 6 확인하지 못한 것   7 다음에 할 일   8 보고서(앱) / 상세(보고서)        │
└──────────────────────────────────────────────────────────────────────┘
```

- **앱 화면과 보고서의 차이는 1곳뿐이다.** 보고서는 헤더 대신 마스트헤드 카드(제목 · 메타 · 절 링크)로 시작하고, 8번이 "보고서 열기" 버튼 대신 접힌 "쉬운 말 요약"과 "상세 A–I"다. 목업의 `?view=report`가 이것이다.
- **대기 화면**은 셸 위에 제목 한 줄 + 입력 카드 + 최근 진단 목록만 있다. 버튼은 "진단" 하나다.
- **세로 리듬**: 요소는 아래로만 추가된다. 위에 있는 것은 값이 채워질 뿐 자리를 옮기지 않는다(타일의 "—" → 값).
- **상세는 항목 안에서**: 검사 행 펼침, 발견 카드의 "근거", 상세 보고서의 해당 절 링크. 전체 로그를 이어 붙이는 화면은 없다.

## 3. 토큰

shadcn/ui의 `name` / `name-foreground` 규약, OKLCH, 중립 팔레트(크로마 0). 스타일은 **nova**(32px 컨트롤, 6–8px 반경, 헤어라인 선)를 골랐다. 진단 도구는 밀도가 있어야 하고 그림자보다 선이 맞는다.

| 토큰 | 용도 | 라이트 | 다크 |
|---|---|---|---|
| `--background` / `--foreground` | 페이지, 기본 글자 | 1 / 0.145 | 0.145 / 0.985 |
| `--card` / `--card-foreground` | 카드 | 1 | 0.205 |
| `--surface` | 카드 안의 한 단계 낮은 면(그림 상자, 접힘 영역) | 0.985 | 0.175 |
| `--muted` / `--muted-foreground` | 코드 배경, 보조 글자 | 0.97 / 0.556 | 0.269 / 0.708 |
| `--primary` / `--primary-foreground` | 주 버튼, 단계 번호 | 0.205 / 0.985 | 0.922 / 0.205 |
| `--border` · `--input` · `--ring` | 선, 입력 테두리, 포커스 | 0.922 | 흰색 10–15% |
| `--destructive` + `-soft` | FAIL, CONFIRMED_FAULT | 0.577 0.245 27 | 0.704 0.191 22 |
| `--warning` + `-soft` | INCONCLUSIVE, PROBABLE_FAULT | 0.58 0.14 62 | 0.8 0.14 75 |
| `--success` + `-soft` | PASS, HEALTHY | 0.52 0.14 150 | 0.75 0.15 150 |
| `--info` + `-soft` | 진행 중, 대상 칩 | 0.55 0.19 255 | 0.72 0.15 255 |
| `--chart-1..5` | 스레드 색(그림) | shadcn 기본 | |
| `--radius` | 8px. 카드 +4, 버튼·입력 −2, 코드 −4 | | |

(값은 OKLCH L C H. 상태 네 가지와 `--surface`만 shadcn 기본 집합에 더한 것이다.) 다크는 `.dark` 클래스, 클래스가 없으면 OS 설정을 따른다.

## 4. 컴포넌트 (shadcn 이름, CSS 클래스)

| shadcn | 클래스 | 쓰는 곳 |
|---|---|---|
| Button | `.btn` `-outline` `-secondary` `-ghost` `-destructive` `-sm` `-lg` | 진단, 보고서 열기, 헤더 |
| Input · ToggleGroup | `.input` `-lg`, `.toggle-group` (`aria-pressed`) | 대기 화면 폼 |
| Card | `.card` + `.card-header` `.card-title` `.card-description` `.right` `.card-content` `.card-footer`, `.card-tone` | 모든 구획 |
| Badge | `.badge` `-secondary` `-outline` `-tone` `-lg` + `.tone-*` | 판정, 발견 상태, 범주, 최근 목록 |
| Progress · Skeleton · Spinner | `.progress`, `.progress-stack`, `.skeleton`, `.spinner` | 배너, 타일, 로딩 |
| Alert | `.alert` `-tone` | 판단 불가 사유, 오류 |
| Table · Separator · Kbd | `.table` `.separator` `.kbd` | 근거 표, 단축키 |
| Collapsible | `details.collapsible`, `-plain` | 근거, 실행 안 함, 상세 A–I |
| 상태 아이콘 | `.status-icon.{PASS,FAIL,INCONCLUSIVE,SKIPPED,RUNNING,PENDING}` | 검사 행 |

React/Tailwind 컴포넌트 자체는 쓰지 않는다. 이 프로젝트는 Python 서버가 정적 파일 하나를 내보내고 폐쇄망에서 열려야 하므로 빌드 체인을 들이지 않는다. 가져온 것은 토큰 규약, 컴포넌트 어휘와 변형 체계, "레이아웃만 className, 색은 토큰" 규칙이다.

## 5. 일관성 체크리스트 (PR 리뷰용)

- [ ] 원색 값(`#…`, `rgb`, `blue-500`)이 없다. 모두 `var(--…)`.
- [ ] 상태는 네 단어·네 색만 쓴다. 새 상태를 만들지 않는다.
- [ ] 카드 안에 카드를 넣지 않는다. 상세는 Collapsible.
- [ ] 새 정보는 아래에 추가된다. 기존 요소의 위치가 바뀌지 않는다.
- [ ] 같은 내용이 보고서에도 같은 순서로 있다. 보고서 전용 문구를 UI에 다시 쓰지 않는다.
- [ ] 다크 모드와 760px 폭에서 깨지지 않는다(`?theme=dark`, 창 줄이기).
- [ ] 외부 URL(CDN·웹폰트) 참조가 없다.

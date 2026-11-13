# What the web UI reads from the server

- **Client**: `extractor/web/ui/` (`index.html`, `ui.css`, `theme.css`, `ui.js`). **Server contract**: `API_CONTRACT.md`
  (owned by the server side). This file lists what the UI uses from that contract, and the fields the UI asks the
  contract to **add**. Every addition is optional: without it the UI still renders a complete screen, only with the
  engine's English names and without the pictures (tested: `tests/web_ui/ui.test.js`, "a verdict without the view").

## 1. Used as written in API_CONTRACT.md

| Contract | Use in the UI |
|---|---|
| `POST api/diagnose/start` (pid only) | the form. A process name is first resolved with `GET api/target/processes?process_name=` (exact-name match, else the single match; 0 → "not found", several → "give a PID") |
| `GET api/diagnose/jobs` | "최근 진단". `verdict` is worded with the report's verdict words (copied in `ui.js` `STR.v_*`, kept equal to `human_report.T` by `tests/test_web_ui.py`) |
| `GET .../events` SSE, envelope `{seq, ts, type, data}` | `state = reduce(events)`. Reconnect: up to 3 tries with `?after=<last seq>`, then polling |
| `GET .../status?after=` | polling fallback: used when the stream delivers nothing for 4 s (buffering proxy) or keeps failing |
| `report_urls.html/md/json` | "HTML 보고서 열기" (`&lang=` added), Markdown, JSON; per-part links append `#verdict-detail`, `#finding-<n>-detail`, `#check-<RECIPE_ID>-detail`, `#scope-detail`, `#method-detail` |
| event field names | `recipe_id`, `steps`, `summary`, `thread_count`, `companion_elf_path`, `dwarf_available`, `problem_statement`, `competing_hypotheses_count`, `hypotheses[].category/status`, `rejected[].category` are mapped in `ui.js` `norm()` |

The UI does not depend on the order of `classified` and `target`, on `check_start` preceding `check_done`, or on
receiving an event only once: events are sorted by `seq` and de-duplicated before reducing.

## 2. Requested additions (the UI uses them when present)

All of them are produced by one function each in `extractor/web/ui/view.py`, which calls the report code
(`human_report.compose`, `report_visuals`) and never re-decides anything. The replay files
(`extractor/web/ui/replay/*.json`, made by `python3 -m extractor.web.ui.replay_gen`) carry them, so they are the
reference payloads.

| Event | Field | How to fill it | Why |
|---|---|---|---|
| `verdict` | `view: {"ko": ..., "en": ...}` | `view.build_views(result, report)`, **with the inline report** (`diagnose(..., include_report=True)`; `diagnose_with_summary` drops it afterwards) | the verdict words, conclusion sentence, tile values, every check's name / domain / one-line result / detail (`<dl>` of the report's check list), the finding cards' bodies **including the pictures**, "확인하지 못한 것", "다음에 할 일" — all in the report's own words |
| `verdict` | `picture_css` | `report_visuals._CSS + report_visuals._interaction_css()` | the pictures' styles; the UI puts it before `theme.css`, whose `.dsv` bridge then maps the report's colours onto the tokens |
| `plan` | `steps[].label {ko,en}`, `steps[].domain_label {ko,en}` | `view.plan_labels([recipe ids])` | check names in words while the diagnosis runs (otherwise the engine's English name is shown until the verdict) |
| `plan` | `not_planned: [{recipe_id, label, domain_label}]`, `not_in_mode: [{recipe_id, capability, capability_label {ko,en}, label, domain_label}]` | the plan's excluded recipes (`section_c_diagnostic_strategy.recipes_excluded`, `unsupported_capability`) | the "실행 안 함" group with its two sub-groups is complete from the start (otherwise it is filled from `not_covered` at the verdict) |
| `plan` | planned-but-not-yet-run checks among `steps` | — | already in the contract |
| `finding_provisional` | `category_label {ko,en}`, `severity`, `recipe_ids` | `view.category_labels(category)` | "발견 1: 교착 상태(deadlock) 의심" instead of the category code |
| `check_done` | `line {ko,en}` | the report's one-line result (`view.build_view(...)["checks"][i]["line"]` logic; `ko_text` of the interpretation) | Korean one-line results while running (otherwise the English `summary`) |
| `check_done` | `bytes_read` (cumulative) | collection impact so far | the "읽은 데이터" tile fills while running (otherwise "—" until the verdict) |
| `target` | `architecture`, `libc`, `libc_version` (or `abi`), `zero_stop`, `stop_ms` | the target ABI; the capture mode | target card and "대상 정지 시간" before the verdict |
| `jobs[]` | `verdict_word {ko,en}`, `headline {ko,en}` | `human_report.T["v_<verdict>"]`, first finding label | the recent list without a word table in JS |

## 3. Error codes the UI words

`start`/process lookup: `INVALID_PARAM` (shows the server's message), `TOO_MANY_JOBS`, `PERMISSION_DENIED`,
`TARGET_NOT_FOUND`, `AMBIGUOUS_TARGET` (UI-side lookup), network failure → "서버에 연결할 수 없습니다".
`error` event: `TARGET_EXITED`, anything else (e.g. `DIAGNOSE_ERROR`) → "진단을 끝내지 못했습니다: <message>".
404 from `status` → "이 진단 기록을 서버에서 찾을 수 없습니다". An unreadable or vanished target is an `INCONCLUSIVE`
verdict per the contract; the UI shows it as any verdict (the conclusion sentence explains it).

# Web UI HTTP contract (stage B-server and C)

Server: `extractor/web/server.py`. Client: the static UI in `extractor/web/ui/`. All URLs below are written **without a
leading path prefix**; the UI must build them relative to its own page (`new URL("api/diagnose/start", document.baseURI)`
or a plain relative string such as `api/diagnose/jobs`). The public demo is served under the nginx prefix
`/dynamicstate/`, which nginx strips before the request reaches this server.

## 0. Common rules

- Every `/api/...` endpoint below passes the same guards: allowed `Host`, loopback-only `Origin`
  (if any), and the per-run session token. The token reaches the page in two ways: the served `index.html` gets
  `window.__DYNAMICSTATE_SESSION_TOKEN__` injected (and `fetch` is already wrapped to send `X-Session-Token`), and an
  HttpOnly cookie `dynamicstate_session` is set. **`EventSource` cannot set headers, so SSE and report links rely on the
  cookie** (same-origin, so it is sent). Tokens in the query string are not accepted.
- `POST` requires `Content-Type: application/json` and a JSON object body.
- Errors are JSON `{"success": false, "error": {"code": "...", "message": "..."}}` with an HTTP status
  (400 bad request, 401 token, 403 host/origin, 404 unknown job, 409 not finished).
- `job_id` is an unguessable URL-safe random token (22 chars of `[A-Za-z0-9_-]`). Anything else in that position is 404.
- Codes are the engine's vocabulary (check status `PASS`, `FAIL`, `INCONCLUSIVE`, `SKIPPED`, `NOT_EXECUTED`; engine
  state names; verdict names exactly as in `DiagnoseResult.verdict`). **Words about the diagnosis** (check names,
  domains, verdict words, one-line results, conclusion, pictures) come from the report code, in both languages, in the
  fields marked *(UI)* below, built by `extractor/web/ui/view.py`; the UI keeps only its own interface words. A field
  marked *(UI)* may be missing (an older server, or its builder failed): the UI then shows the codes and the engine's
  English text, and no pictures.
- HTML fragments (`view.*_html`, `view.findings[].body_html`, `view.checks[].detail_html`) are produced by the report
  renderers: every value inside is escaped and they contain no `<script>`, no `on*=` attribute and no `javascript:` URL
  (tested in `tests/test_web_ui.py` with hostile target strings). Every other string is plain text that the UI escapes.

## 1. `POST api/diagnose/start`

Body: the same as the synchronous `POST api/diagnose` (unchanged, still available):

```json
{"pid": 4242, "symptom": "memory keeps growing", "debug_image": "/path/to/unstripped.elf",
 "language": "ko", "time_limit_s": 20,
 "remote_host": "10.0.0.5", "ssh_user": "root", "ssh_port": 22, "ssh_key": "/home/u/.ssh/id", "ssh_proxy_jump": null,
 "symptom_kind": "...", "symptom_frequency": "...", "symptom_duration": "...", "affected_area": "...", "related_objects": []}
```

`pid` is required (integer > 1, a numeric string is accepted). Process-name lookup is not part of this endpoint (the
synchronous endpoint does not have it either); the UI resolves a name to a pid with the existing process listing API.
Validation is identical to the synchronous endpoint and happens before the worker starts; a bad request answers
`{"success": false, "error": {"code": "INVALID_PARAM", ...}}` with HTTP 200 (same as the synchronous endpoint), no job.

Response (HTTP 200):

```json
{"success": true, "job_id": "Zk3v0pQ1xT9mR2aYw8LdNg", "investigation_id": "inv_3f9a1c20b7d4",
 "already_running": false, "state": "running"}
```

- One running job per target (`remote_host` + `pid`). A second start for the same target returns the running job with
  `"already_running": true` (its `job_id`; the body of the second request is ignored).
- `investigation_id` is known once the engine session exists (normally within milliseconds; the call waits up to
  3 s for it). If it is not known yet it is `null`; it is also in `GET .../status` and in the `target` event later.
- `state` is `running` | `done` | `error`.
- At most 4 jobs run at the same time; beyond that: `{"success": false, "error": {"code": "TOO_MANY_JOBS", ...}}`.
- A local target that the engine's own preflight (`expert_diagnostic_engine._preflight_target`) rejects is refused
  before a job exists: `TARGET_NOT_FOUND` (no such process / it exited), `PERMISSION_DENIED` (its memory is not readable
  by the server's user), `TARGET_UNREADABLE` (any other reason); `message` is the engine's reason. A remote target
  is not pre-checked (its failure is an `INCONCLUSIVE` verdict, as before).
- The UI resolves a process name to a pid with `GET api/target/processes?process_name=` (exact-name match, else the
  single match; none → "not found", several → "give a PID").

## 2. `GET api/diagnose/jobs`

```json
{"success": true, "jobs": [
  {"job_id": "Zk3v...", "investigation_id": "inv_3f9a1c20b7d4", "pid": 4242, "target_name": "deadlock_pipeline",
   "remote_host": null, "state": "done", "verdict": "CONFIRMED_FAULT",
   "verdict_word": {"en": "confirmed fault", "ko": "확인된 결함"}, "headline": {"en": "deadlock", "ko": "교착 상태(deadlock)"},
   "started_at": "2026-11-13T05:01:02.123456+00:00", "finished_at": "2026-11-13T05:01:12.456789+00:00",
   "last_seq": 31}
]}
```

`verdict_word` *(UI)* is the report's word for the verdict, `headline` *(UI)* the first finding's category in words
(empty when there is none); both `null` while running. Newest first. Bounded: the last 20 finished jobs plus the running ones, in memory only (lost on server restart).
`verdict` and `finished_at` are `null` while running; for `state: "error"` the verdict is `null`.

## 3. `GET api/diagnose/{job_id}/events` (Server-Sent Events)

- `Content-Type: text/event-stream`, `Cache-Control: no-cache`, `X-Accel-Buffering: no` (tells nginx not to buffer).
- Each message: `id: <seq>`, `event: <type>`, `data: <one-line JSON envelope>`.
- Envelope (the same object is used in `status`): `{"seq": 7, "ts": "<ISO-8601 UTC>", "type": "check_done", "data": {...}}`.
  `seq` starts at 1 and increases by exactly 1 per event within a job.
- Reconnect: send `Last-Event-ID: <seq>` (what `EventSource` does automatically) or `?after=<seq>`; only events with a
  larger `seq` are sent. `?after=` wins if both are given. A non-integer value is 400.
- A finished job (state `done` or `error`): the stream replays everything after `after`, then closes. The last event
  of a finished job is `verdict` or `error`.
- A comment line `: keepalive` is sent every 15 s while nothing happens.
- The stream also closes when the client disconnects. A client that wants to stop following does not cancel the job
  (the diagnosis is read-only and runs to completion).

## 4. `GET api/diagnose/{job_id}/status`

For clients behind a proxy that buffers SSE. Same events as one JSON document:

```json
{"success": true,
 "job": {"job_id": "Zk3v...", "investigation_id": "inv_3f9a1c20b7d4", "pid": 4242, "target_name": "deadlock_pipeline",
         "remote_host": null, "state": "running", "verdict": null,
         "started_at": "...", "finished_at": null, "last_seq": 9,
         "engine_state": "COLLECTING", "progress_percentage": 61},
 "events": [ {"seq": 1, "ts": "...", "type": "classified", "data": {}} ]}
```

`?after=<seq>` returns only events with a larger `seq` (poll with the last `seq` you saw). `events` of a full request
is exactly the concatenation of the SSE messages. `engine_state` / `progress_percentage` come from the session's
`get_status()` while running (null before the session exists and after the job finished: use the final events).

## 5. `GET api/diagnose/{job_id}/report?format=html|md|json&lang=ko|en`

Only for a finished job with `state: "done"` (409 `NOT_FINISHED` while running, 404 for `error` jobs and unknown ids).
Default `format=html`, default `lang` = the language the job was started with. Anything else is 400.
Served by `incident_report.export_incident_report` (the one report renderer; no files are written by this endpoint):
`text/html; charset=utf-8`, `text/markdown; charset=utf-8` or `application/json`, with `Content-Disposition: inline`.
The body is the report itself, not wrapped in the `{"success": ...}` envelope. A report is built once per
(job, language) and cached. There is no way to choose an output or input path. The report is rendered from the very
result the `verdict` event carried (`export_incident_report(result=...)`, with the diagnosis's inline report), so the
page and the report state the same verdict, findings and checks; per-part detail anchors: `#verdict-detail`,
`#finding-<n>-detail`, `#check-<RECIPE_ID>-detail`, `#scope-detail`, `#method-detail`, `#reproducibility-detail`.

## 6. Events

Order of events in a normal diagnosis: `classified`, `target`, `plan`, then per check `check_start`, `check_done` (checks run in the engine's order, which replanning can change from the `plan` order)
(and, the first time a check FAILs in a category, `finding_provisional`), then `verified`, then `verdict`. Note that the
engine classifies the symptom **before** it assesses the target, so `classified` precedes `target` (the proposal's table
lists them the other way round). The UI should not depend on the relative order of `classified` and `target`.
`error` replaces `verdict` if the diagnosis function raised.

### `classified`
Source: `PROBLEM_CLASSIFIED` timeline entry and `session.classification_result`.
```json
{"primary_category": "MEMORY_LEAK", "confidence": 0.82, "is_vague": false, "symptom_class": "growth",
 "understood": true, "confidence_level": "HIGH", "extracted_entities": {"symbols": []},
 "competing_hypotheses_count": 3, "candidate_categories": [["MEMORY_LEAK", 0.82], ["HEAP_FRAGMENTATION", 0.31]],
 "problem_statement": "memory keeps growing"}
```
### `target`
Source: `TARGET_ASSESSED` and `session.target_assessment.to_dict()` (all its fields are passed through) plus:
```json
{"pid": 4242, "process_name": "deadlock_pipeline", "transport": "local", "target_host": "localhost",
 "accessible": true, "thread_count": 6, "memory_regions_count": 93, "rss_kb": 5120,
 "companion_elf_path": "/work/deadlock_pipeline", "companion_elf_valid": true, "dwarf_available": true,
 "build_id": "9f2c...", "memory_readable": true, "prerequisites_met": true,
 "allocator_type": "GLIBC_PTMALLOC", "capabilities": ["PROC_MEM"], "limitations": [],
 "investigation_id": "inv_3f9a1c20b7d4"}
```
Also `architecture`, `libc`, `libc_version` *(UI)*, copied from `target_abi` when it was detected. The stop time is
not known before the verdict, so it is not sent here.
`process_name` is `null` for a remote target. "Build-ID matches" is not separately computed by the engine here:
`build_id` is the target's build id and `companion_elf_valid` says whether the debug image was accepted.
### `plan`
Source: `PLAN_GENERATED` and `session.get_plan()`.
```json
{"total_steps": 24, "rationale": "...", "estimated_overhead_ms": 120.0,
 "steps": [{"step_id": "step_1", "recipe_id": "RECIPE_MEMORY_GROWTH_RATE", "name": "Memory growth rate",
            "category": "MEMORY_LEAK", "domain": "RESOURCE", "priority": 1, "status": "PENDING",
            "label": {"en": "Process memory growth", "ko": "프로세스 메모리 증가"},
            "domain_label": {"en": "Memory growth", "ko": "메모리 증가"}}],
 "not_planned": [{"recipe_id": "RECIPE_INVALID_FREE", "name": {"en": "...", "ko": "..."}, "domain": "MEMORY_INTEGRITY",
                  "domain_label": {"en": "...", "ko": "..."}}],
 "not_in_mode": [{"recipe_id": "RECIPE_USE_AFTER_FREE", "name": {...}, "domain": "...", "domain_label": {...},
                  "capability": "allocation_tracing",
                  "capability_label": {"en": "allocation tracing (a record of every allocation and free)",
                                       "ko": "할당 추적 (모든 할당·해제 기록)"}}]}
```
`label` / `domain_label` *(UI)*: the check named in words (`view.plan_labels`). `not_planned` / `not_in_mode` *(UI)*:
the recipes the plan leaves out, split as the report's `section_c.recipes_excluded` splits them — not selected for this
symptom, and not examined in this mode because a zero-stop diagnosis lacks the capability (`view.plan_exclusions`;
the `verdict`'s `not_covered` has the same as `recipes_not_planned` / `unsupported_in_mode`). Planned checks that are
never reached appear in the `verdict` event inside `result.checks_run` with status `NOT_EXECUTED` / `SKIPPED`. A later replan (follow-up checks the
engine adds when a check supports a hypothesis) is not re-sent: a `check_start`/`check_done` for a `recipe_id` that was
not in `plan.steps` is a follow-up check and should be appended to the list.
### `check_start`
Sent when a read-only watcher on the session's plan sees the engine mark a step RUNNING (the engine records no timeline
entry for that, so the latency is up to about 50 ms). A check faster than that gets its `check_start` immediately before
its `check_done`: for every `check_done` there is exactly one earlier `check_start` with the same `step_id`.
```json
{"step_id": "step_3", "recipe_id": "RECIPE_THREAD_WAIT_GRAPH", "name": "Thread wait graph", "index": 2, "total": 24}
```
`index` is the 0-based position in the current plan (`null` for a follow-up not in the plan), `total` the current plan length.

### `check_done`
Source: `STEP_EXECUTED` and the last entry of `session.get_checks()`.
```json
{"step_id": "step_3", "recipe_id": "RECIPE_THREAD_WAIT_GRAPH", "check_id": "chk_...", "name": "Thread wait graph",
 "status": "FAIL", "duration_ms": 42.5, "summary": "cycle: T1 -> T2 -> T1", "eval_status": "SUPPORTED",
 "confidence": 0.9, "supporting_evidence_ids": ["ev_1"], "contradicting_evidence_ids": [],
 "limitations": [], "missing_evidence": [], "index": 2, "total": 24}
```
Also `line` *(UI)* `{"en": ..., "ko": ...}`: the one-line result the report's check list shows for this check
(`view.check_line`), and `bytes_read`: bytes read from the target so far in this diagnosis (cumulative), when the
budget tracker has it.
`status` is the engine check status (`PASS`, `FAIL`, `INCONCLUSIVE`, `SKIPPED`, `NOT_EXECUTED`, also possibly
`NOT_APPLICABLE` / `ERROR` as in the engine). `duration_ms` may be `null`. `summary` is the engine's technical
interpretation (English).
### `finding_provisional`
Derived from the first `FAIL` check of each (category, domain) pair, sent right after its `check_done`. The engine forms
hypotheses only in its analyze step, so this is a suspicion, not a hypothesis object.
```json
{"key": "MEMORY_LEAK/RESOURCE", "recipe_id": "RECIPE_MEMORY_GROWTH_RATE", "check_id": "chk_...", "name": "Memory growth rate",
 "category": "MEMORY_LEAK", "domain": "RESOURCE", "summary": "RSS grew 31% in 4 s", "status": "provisional",
 "category_label": {"en": "memory leak", "ko": "메모리 누수"}}
```
`category_label` *(UI)*: the category in words (`view.category_labels`).
### `verified`
Source: `HYPOTHESES_VERIFIED` and `session.active_hypotheses` / `rejected_hypotheses`.
```json
{"active_count": 1, "rejected_count": 2,
 "hypotheses": [{"hypothesis_id": "hyp_1", "category": "MEMORY_LEAK", "domain": "RESOURCE", "status": "CONFIRMED",
                 "confidence": 0.91, "problem_statement": "...", "confidence_basis": "...",
                 "recommended_next_action": "...", "verification_execution_results": []}],
 "rejected": [{"hypothesis_id": "hyp_2", "category": "HEAP_FRAGMENTATION", "domain": "RESOURCE", "status": "REFUTED",
               "confidence": 0.1, "problem_statement": "...", "confidence_basis": "...", "recommended_next_action": "",
               "verification_execution_results": []}]}
```
`verification_execution_results` is passed through, truncated to 10 entries per hypothesis.
### `verdict`
Terminal. The same result as the synchronous endpoint plus pointers to the report.
```json
{"result": { "...the full DiagnoseResult dict as in POST api/diagnose, with human_summary inside...": 0,
             "verdict": "CONFIRMED_FAULT", "findings": [], "not_covered": [], "checks_run": [], "report_path": "/corpus/reports/inv_....report.json"},
 "human_summary": "# ...markdown...",
 "report_path": "/corpus/reports/inv_3f9a1c20b7d4.report.json",
 "report_urls": {"html": "api/diagnose/Zk3v.../report?format=html", "md": "api/diagnose/Zk3v.../report?format=md",
                 "json": "api/diagnose/Zk3v.../report?format=json"},
 "language": "ko",
 "view": {"ko": {...}, "en": {...}},
 "notice": {"code": "TARGET_EXITED", "message": "process 4242 exited during the diagnosis"}}
```
`view` *(UI)* is `view.build_views(result, report)` — everything the final screen shows, in each language, made by the
report code from the result with its inline report (the inline report itself is not sent):
`verdict`, `tone` (`fail`/`warn`/`pass`/`skip`), `verdict_word`, `verdict_meaning`, `conclusion_html`,
`symptom_html[]`, `scope_html`, `tiles` (`checks.value` + `counts{run,found,clean,undecided,not_run}`,
`stop{value,note}`, `bytes{value,note}`, `duration{value}`), `checks[]` (`rid`, `status` in the four groups,
`raw_status`, `kind` = `run`/`not_executed`/`not_planned`/`not_in_mode`, `name`, `domain`, `line`, `ms`,
`capability`/`capability_label`, `findings[]`, `detail_html` = the report check list's `<dl>`, `anchor`),
`findings[]` (`n`, `category`, `status`, `severity`, `severity_word`, `status_word`, `tone`, `heading_html`,
`recipe_ids`, `body_html` = the report's finding block — key facts, picture, text, reasoning, evidence — without its
heading, `anchor`), `not_examined_html`, `next_html`, `profile` (`title`, `available`, `glance` = the one-line summary
"스레드 N개 · RSS X · 힙 Y · 열린 파일 Z", `html` = the report's process-profile card body: the three-line summary and the
whole profile in a collapsed Collapsible; `available` false and `html` empty when the diagnosis left nothing to profile; the
card itself is reserved right after the target from the `plan` event on and shows a pending line until the verdict).
The pictures need no extra stylesheet: their rules are part of
the shared `extractor/web/ui/theme.css` (the "Finding pictures" section), which the UI loads and the report inlines.
`notice` *(UI)*, optional: the target itself limited the diagnosis — `TARGET_EXITED` (a local process that was there at
the start is gone at the end, or the engine found it gone), `PERMISSION_DENIED`, `TARGET_NOT_FOUND`,
`TARGET_UNREADABLE` (from the result's `target_unreadable` entry). The verdict stands; the UI shows the notice under it.
`result` is exactly `response.result` of `POST api/diagnose` for the same input (it includes `human_summary`).
`report_path` is the engine's JSON report file on the server host (informational; it cannot be read through the API).
`report_urls` are relative to the page like every other URL here.
### `error`
Terminal. The diagnosis function raised (an unreadable target is NOT an error: it is a `verdict` of `INCONCLUSIVE`).
```json
{"code": "DIAGNOSE_ERROR", "message": "RuntimeError: ...", "stage": "diagnose"}
```

## 7. What the UI relies on (client side)

- Events are sorted by `seq` and de-duplicated before they are reduced (`state = reduce(events)` in `ui.js`), so the
  order of `classified` / `target`, duplicates after a reconnect and an overlap between the stream and `status` are
  harmless.
- Reconnect: up to 3 tries with `?after=<last seq>`, then `status?after=` polling; the stream is also abandoned for
  polling when it delivers nothing for 4 s (a buffering proxy). A 404 from `status` is "this job is unknown here".
- A `check_start` / `check_done` for a recipe not in `plan.steps` is appended as a row; a recipe in `not_planned` /
  `not_in_mode` that the engine ran after all is shown as a row, not in the "not run" group.
- Replays (`extractor/web/ui/replay/*.json`, `?replay=<name>`) are recorded event streams in exactly this wire shape,
  made from saved results by `python3 -m extractor.web.ui.replay_gen` with the same builders.

## 8. Routing

The web server is **read-only towards the target**: no route writes target memory, stops or signals the target, runs a
command, or mutates / checkpoints / restores state. The authoritative route table is `API_ROUTES` in
`extractor/web/server.py`; `tests/test_web_readonly_routes.py` enumerates it, rejects any route whose path looks like
writing, stopping, running commands, mutating or restoring, checks that every `/api/...` literal under `extractor/web/`
is in the table, and probes the removed paths for 404.

| URL | Content |
|---|---|
| `/` , `/index.html`, `/ui.css`, `/ui.js`, page assets in `extractor/web/ui/` (`.html .css .js .json .svg .png .ico`) | the UI (relative URLs inside) |
| `GET api/health` | `{"status": "ok", "version", "timestamp", "mode"}` |
| `GET api/target/processes?process_name=&remote_host=&ssh_user=&ssh_port=&ssh_key=` | process listing (sections 1 and 7: name to pid) |
| `POST api/diagnose`, `POST api/diagnose/start`, `GET api/diagnose/jobs`, `GET api/diagnose/{job_id}/events`, `.../status`, `.../report` | sections 1 to 5 |
| any other `/api/...` | 404 `NOT_FOUND` |
| `/legacy`, `/legacy/...`, `/workspace`, `/workspace/...` (the removed 8-tab UI and chat workspace) | 301 to the root UI with a **relative** `Location` (`./`, `../`, ...) |
| `/static/...` (the removed UI's assets) | 404 |

The previous 8-tab UI (`/legacy/`), the chat workspace (`/legacy/workspace`, `/workspace`, `dynamic-state-workspace`)
and every route only they used (`/api/watch/*`, `/api/investigation/*`, `/api/investigations*`, `/api/workspace/chat`,
`/api/mutation*`, `/api/transition(s)`, `/api/checkpoint`, `/api/restore`, `/api/snapshot(s)`, `/api/states`,
`/api/state-graph`, `/api/state-lab/tree`, `/api/runtime*`, `/api/capabilities`, `/api/explore`, `/api/observe`,
`/api/capture`, `/api/llm/status`, `/api/target/inspect-range`, `/api/target/deploy-collector`, ...) were removed, with
the `/legacy/api/...` aliases. The Python functions behind them stay where MCP, the CLI or tests use them.

Nothing in the server depends on a path prefix: with `proxy_pass http://127.0.0.1:8081/;` under `/dynamicstate/` all of the
above work as `/dynamicstate/`, `/dynamicstate/api/...`, because every URL the page and the redirects use is relative.

## 9. The process profile (`process_profile`)

What the diagnosis learned about the process itself, built by `extractor/process_profile.build_process_profile(result,
report)` only from data the checks already left in the report (`actual_observations`, `section_b_target_context`,
`target.abi`, `collection_impact`): no extra read of the target and no part in any verdict. It is the `process_profile`
key of the diagnose result and of the report JSON, section 3 of the incident report (right after the target) and the
`profile` card of the live UI. Words and pictures come from `extractor/profile_render.py` for all three, in the same
order and wording.

```json
{"version": 1, "available": true,
 "window": {"seconds": 1.0, "samples": 38},
 "summary": {"threads": 2, "rss_kb": 1348, "heap_kb": 132, "heap_kind": "mapping", "fds": 5},
 "runtime":   {"items": [{"key": "uptime|libc_version|cpus_allowed", "v": 2.4, "unit": "s", "basis": {"kind": "derived"}}]},
 "threads":   {"count": {"v": 2, "basis": {"kind": "read"}},
               "series": {"v": [2, 2, 2, 2, 2], "basis": {"kind": "series", "samples": 5, "window_s": 0.66}}, "trend": "stable",
               "states": {"waiting": 2}, "detailed": 2, "listed": 2, "omitted": null,
               "rows": [{"tid": 1, "name": "acceptor", "count": 1, "tids": [1], "state": "waiting", "samples": "SSSSS",
                         "cpu_share": 0.0, "function": "acceptor", "location": "x.c:15", "source": "poll(...);",
                         "waits_on": {"kind": "syscall|lock", "name": "ppoll"}, "basis": {"kind": "series", "samples": 5, "window_s": 0.66}}]},
 "memory":    {"rss": {"v": 1348, "unit": "kB", "series": [...], "change_kb": 0, "peak_kb": 1348, "anon_kb": 92, "file_kb": 1256, "basis": {...}},
               "heap": {"mapping_kb": {...}, "allocator": "glibc_ptmalloc", "walk": {"in_use_kb": 4374, "free_kb": 14999, ...},
                        "growing_classes": [{"chunk_b": 560, "blocks": 7733}]},
               "integrity": {"heap_status": "COMPLETED", "walk_status": "OK", "chunks": 3, "defects": 0, ...},
               "address_space": {"total_kb": 10520, "categories": [{"key": "heap|thread_stacks|anon|main_stack|libs|exe|other", "kb": 132, "basis": {...}}]}},
 "locks":     {"samples": 5, "items": [{"name": "m_out", "owner": {"tid": 3, "name": "flush"}, "waiters": [...], "seen_samples": 5, ...}]},
 "resources": {"fds": {"v": 5, "limit": 1048576, "by_kind": {"pipe": 3, "file": 2}, "series": [...]}, "thread_limit": {...}},
 "modules":   {"items": [{"role": "executable|loader|libc|library", "name": "...", "path": "..."}], "load_addresses": false},
 "not_observed": [{"key": "heap_walk", "reason": "no_growth"}]}
```

- A section key exists only when something was observed for it; there is never an empty or guessed value. What is missing is
  in `not_observed` (`key` + `reason`, plus counts for `thread_detail_partial`).
- Every figure carries `basis`: `{"kind": "read"}` (one read), `{"kind": "series", "samples": n, "window_s": w}` (n reads over w
  seconds; `window_s` may be null) or `{"kind": "derived"}`. Sizes are kB unless `unit`/the key name says bytes (`_b`).
- `threads.count` is the last read (a growing process is larger than the end of the sampled window; `series` and `trend` are the
  sampled window). Rows are groups of threads with the same name and state (`count`, first `tids`), at most 10, lock waiters
  first; `omitted` counts the rest. `detailed < listed` means only some threads were sampled over the window.
- `window` is the whole diagnosis (`section_b.observation_duration_sec`, `collection_impact.samples_collected`).

Items that would naturally link to an exploration view later: locks (`name`, `address`) to the variable watch list;
`growing_classes` and `heap.walk` to the pool/array scanner; `memory.address_space` categories and `modules` to the
memory-range inspector; `memory.rss.series` / `threads.series` to the timeline compare.

## 10. Exploration routes (job-bound)

Reads of a diagnosed process from the result screen (docs/ui-redesign/EXPLORE_PROPOSAL_KO.md). Code:
`extractor/web/explore.py` (reads, limits, observation session), `extractor/web/explore_routes.py` (HTTP glue),
`extractor/web/ui/explore_fragments.py` (ko/en fragments), `extractor/web/observation_report.py` ("Add to report").
Every route is in `API_ROUTES` and is probed by `tests/test_web_readonly_routes.py`.

**Binding and security.** Same session token, Host and loopback-Origin checks and job-id validation as the diagnose
routes. The pid, the transport (local / SSH) and the debug image come from the job; no request parameter names a pid,
a host or a file. Before every read the job's process is checked: gone, a zombie, or a pid now owned by another
process (its start time in `/proc/PID/stat` differs from the one recorded when the job started) gives `410
TARGET_EXITED`. Reads of one job run one at a time on one adapter (one SSH connection) with a manager of their own, so
the runtime's active target is never moved; an answer from another pid (auto-heal) is refused. A job that ended with an
error is not explored (`409 NO_TARGET`).

**Answer.** `{"success": true, "key", "html": {"ko", "en"}, "data", "cost": {"reads", "bytes", "ms", "stop_ms": 0,
"writes": 0, "transport", "at"}}`; an error is `{"success": false, "error": {code, message}, "html": {ko, en}}`.
`html` is inert (no script, no `on*=`, no URL; every target string escaped) and may contain `<!--slot:KEY-->` where a
sub-row's detail goes and `data-act` buttons the UI's click handler understands.

| Method | Path | Parameters (bounds) | Reads |
|---|---|---|---|
| GET | `{job}/chips` | — (finished job) | none: DWARF types and the result's own observations |
| GET | `{job}/thread/{tid}` | tid: digits, must be a task of the job's pid | call stack (CFI), frame locals, locks held / waited for |
| GET | `{job}/threads` | `name` 1..64 printable, `limit` 1..4096 (20), `filter` digits | `/proc/PID/task/*` only |
| GET | `{job}/memory/maps` | — | `/proc/PID/maps` |
| GET | `{job}/memory/range` | exactly one of `addr` (hex/decimal, < 2^64) and `expr`; `len` 1..4096 (256) | one read (+ one for `expr`) |
| GET | `{job}/files` | — (local targets) | `/proc/PID/fd` links |
| GET | `{job}/modules` | — | `/proc/PID/maps` + the ELF files on this host |
| GET | `{job}/vars` | `q` up to 64 of `[A-Za-z0-9_:.]` | none: DWARF |
| GET | `{job}/value` | `expr`: `*{0,4}name(.f|->f|[n])*`, ≤ 200 chars | one evaluation |
| GET | `{job}/lock` | `name` 1..64 printable | stacks of all threads (8 frames) + the mutex words |
| GET | `{job}/watch/events` | `after` | SSE `event: watch`, data `{version, watch}` |
| GET | `{job}/watch/status` | `after` | `{version, watch}` (`watch: null` when nothing is observed) |
| POST | `{job}/watch` | `{items: [{expr} or {addr, type: u64/u32/i32/u8}], pool: {expr, count, field, sel} or null, interval_s, running, pin: "now"/"clear"}` | starts / changes the server-side sampler |
| POST | `{job}/watch/stop` | `{}` | stops the sampler (never the target) |
| POST | `{job}/observation` | `{}` or `{remove: true}` | puts the current observation into the job's report |

Repeated query parameters and values over 256 characters are `400`. Unknown actions are `404`.

**Limits.** One-shot reads: a token bucket per job, burst 30, 5 per second (`429 RATE_LIMITED`). Observation: at most 16
items; at most 262,144 bytes per sample (a 4,096 x 48-byte pool, 196,608 B, fits) and 524,288 bytes per second;
interval 0.5, 1, 2 or 5 s (SSH targets: 2 s minimum, one daemon exchange per read); at most 4 observations sampling at
once on the server; sampling stops by itself when no client asked for 30 s (`reason: idle`), after 30 minutes
(`max_lifetime`), when the target exits (`target_exited`, last values kept, a resume does not restart it) or a read
fails (`read_failed`). A pool of more than 4,096 elements is drawn in buckets of `ceil(N/4096)` elements per cell
(majority status). The per-sample budget charges the pool read plus two reserve elements; an array the budget cannot
cover (48-byte elements: more than 5,459) is observed as its first `count` elements: the variable search offers that
count (`pool.total` is the array length), a larger or default count is `400 BUDGET` naming the largest that fits, and
the `watch.pool` object carries `total` and `truncated` (the card and the report print "first n of N elements").
Variable search, value, lock and watch of an expression on a target without DWARF are `409 NO_DEBUG_INFO`; maps,
threads, address reads, modules and address watches still work.

**`watch` object.** `{seq, samples, state: running|paused|stopped|idle, reason, reason_detail, interval_s, intervals,
transport, first_t, last_t, items: [{id, label, type, value | fields: [{name, value, spark, changes, last_change}],
spark (last 30), changes, last_change, error}], pool: {expr, count, elem_size, elem_type, field, field_type, per_cell,
bytes, cells (one digit 0-5 per cell), changed, legend: [{cls, value, name, count, delta}], sel, sel_view}, compare:
{from_seq, from_t, to_seq, to_t, changed: [{name, before, now, diff}], same, pool}, pinned, cost, plan: {reads_per_sample,
bytes_per_sample, reads_per_s, bytes_per_s, limits}}`.

**"Add to report".** The job's next report (`{job}/report`, every format and language) carries an "Additional
observation" section after "What to do next": HTML section `#obs-report` (sparklines, the pool grid, the comparison),
a Markdown section between `<!-- ds:additional-observation -->` markers, JSON key `additional_observation`. The rest of
the report is the cached report byte for byte; verdict, findings and checks never change.

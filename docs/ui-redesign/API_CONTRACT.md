# Web UI HTTP contract (stage B-server and C)

Server: `extractor/web/server.py`. Client: the static UI in `extractor/web/ui/`. All URLs below are written **without a
leading path prefix**; the UI must build them relative to its own page (`new URL("api/diagnose/start", document.baseURI)`
or a plain relative string such as `api/diagnose/jobs`). The public demo is served under the nginx prefix
`/dynamicstate/`, which nginx strips before the request reaches this server.

## 0. Common rules

- Every `/api/...` endpoint below passes the same guards as the existing API: allowed `Host`, loopback-only `Origin`
  (if any), and the per-run session token. The token reaches the page in two ways: the served `index.html` gets
  `window.__DYNAMICSTATE_SESSION_TOKEN__` injected (and `fetch` is already wrapped to send `X-Session-Token`), and an
  HttpOnly cookie `dynamicstate_session` is set. **`EventSource` cannot set headers, so SSE and report links rely on the
  cookie** (same-origin, so it is sent). Tokens in the query string are not accepted.
- `POST` requires `Content-Type: application/json` and a JSON object body.
- Errors are JSON `{"success": false, "error": {"code": "...", "message": "..."}}` with an HTTP status
  (400 bad request, 401 token, 403 host/origin, 404 unknown job, 409 not finished).
- `job_id` is an unguessable URL-safe random token (22 chars of `[A-Za-z0-9_-]`). Anything else in that position is 404.
- Wording is the UI's job. The server sends the engine's vocabulary (check status `PASS`, `FAIL`, `INCONCLUSIVE`,
  `SKIPPED`, `NOT_EXECUTED`; engine state names; verdict names `HEALTHY`, `CONFIRMED_FAULT`, `DEGRADED`, `INCONCLUSIVE`
  ... exactly as in `DiagnoseResult.verdict`).

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

## 2. `GET api/diagnose/jobs`

```json
{"success": true, "jobs": [
  {"job_id": "Zk3v...", "investigation_id": "inv_3f9a1c20b7d4", "pid": 4242, "target_name": "deadlock_pipeline",
   "remote_host": null, "state": "done", "verdict": "CONFIRMED_FAULT",
   "started_at": "2026-11-13T05:01:02.123456+00:00", "finished_at": "2026-11-13T05:01:12.456789+00:00",
   "last_seq": 31}
]}
```

Newest first. Bounded: the last 20 finished jobs plus the running ones, in memory only (lost on server restart).
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
(job, language) and cached. There is no way to choose an output or input path.

## 6. Events

Order of events in a normal diagnosis: `classified`, `target`, `plan`, then per check `check_start`, `check_done`
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
`process_name` is `null` for a remote target. "Build-ID matches" is not separately computed by the engine here:
`build_id` is the target's build id and `companion_elf_valid` says whether the debug image was accepted.
### `plan`
Source: `PLAN_GENERATED` and `session.get_plan()`.
```json
{"total_steps": 24, "rationale": "...", "estimated_overhead_ms": 120.0,
 "steps": [{"step_id": "step_1", "recipe_id": "RECIPE_MEMORY_GROWTH_RATE", "name": "Memory growth rate",
            "category": "MEMORY_LEAK", "domain": "RESOURCE", "priority": 1, "status": "PENDING"}]}
```
Excluded recipes ("not executed") are not part of the plan the engine exposes at this point; they appear in the
`verdict` event inside `result.checks_run` with status `NOT_EXECUTED` / `SKIPPED`. A later replan (follow-up checks the
engine adds when a check supports a hypothesis) is not re-sent: a `check_start`/`check_done` for a `recipe_id` that was
not in `plan.steps` is a follow-up check and should be appended to the list.
### `check_start`
Best effort and derived: sent when the engine finishes the previous check (or the plan) for the step it will run next.
Because the engine does not signal the start of a step itself, a replan may make it name a step that is not run next;
`check_done` is authoritative and is always preceded by a `check_start` for the same `step_id` (the server sends one
right before it if needed).
```json
{"step_id": "step_3", "recipe_id": "RECIPE_THREAD_WAIT_GRAPH", "name": "Thread wait graph", "index": 2, "total": 24}
```
### `check_done`
Source: `STEP_EXECUTED` and the last entry of `session.get_checks()`.
```json
{"step_id": "step_3", "recipe_id": "RECIPE_THREAD_WAIT_GRAPH", "check_id": "chk_...", "name": "Thread wait graph",
 "status": "FAIL", "duration_ms": 42.5, "summary": "cycle: T1 -> T2 -> T1", "eval_status": "SUPPORTED",
 "confidence": 0.9, "supporting_evidence_ids": ["ev_1"], "contradicting_evidence_ids": [],
 "limitations": [], "missing_evidence": [], "index": 2, "total": 24}
```
`status` is the engine check status (`PASS`, `FAIL`, `INCONCLUSIVE`, `SKIPPED`, `NOT_EXECUTED`, also possibly
`NOT_APPLICABLE` / `ERROR` as in the engine). `duration_ms` may be `null`. `summary` is the engine's technical
interpretation (English).
### `finding_provisional`
Derived from the first `FAIL` check of each (category, domain) pair, sent right after its `check_done`. The engine forms
hypotheses only in its analyze step, so this is a suspicion, not a hypothesis object.
```json
{"key": "MEMORY_LEAK/RESOURCE", "recipe_id": "RECIPE_MEMORY_GROWTH_RATE", "check_id": "chk_...", "name": "Memory growth rate",
 "category": "MEMORY_LEAK", "domain": "RESOURCE", "summary": "RSS grew 31% in 4 s", "status": "provisional"}
```
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
 "language": "ko"}
```
`result` is exactly `response.result` of `POST api/diagnose` for the same input (it includes `human_summary`).
`report_path` is the engine's JSON report file on the server host (informational; it cannot be read through the API).
`report_urls` are relative to the page like every other URL here.
### `error`
Terminal. The diagnosis function raised (an unreadable target is NOT an error: it is a `verdict` of `INCONCLUSIVE`).
```json
{"code": "DIAGNOSE_ERROR", "message": "RuntimeError: ...", "stage": "diagnose"}
```

## 7. Routing (stage C)

| URL | Content |
|---|---|
| `/` , `/index.html`, `/ui.css`, `/ui.js`, any file in `extractor/web/ui/` | the new UI (relative URLs inside) |
| `/legacy/`  (`/legacy` redirects to `legacy/`) | the old 8-tab UI; its assets resolve as `/legacy/static/app.js` etc. |
| `/legacy/workspace` | the old workspace (chat) UI |
| `/workspace` | redirect to `legacy/workspace` (old bookmarks) |
| `/api/...` | unchanged paths. `/legacy/api/...` and `/legacy/workspace/api/...` are aliases (the legacy pages derive their API base from their own URL) |
| `/static/...` | legacy assets (unchanged, kept so existing links work) |

Nothing in the server depends on a path prefix: with `proxy_pass http://127.0.0.1:8081/;` under `/dynamicstate/` all of the
above work as `/dynamicstate/`, `/dynamicstate/legacy/`, `/dynamicstate/api/...`, because every URL the pages and the
redirects use is relative.

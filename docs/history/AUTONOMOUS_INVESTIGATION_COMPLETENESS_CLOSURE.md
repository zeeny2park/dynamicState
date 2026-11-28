# Autonomous Investigation Completeness & Exit Predicate Closure

- **Repository**: `https://github.com/zeeny2park/dynamicState`
- **Baseline Commit**: `e7ce428c6d970b6223f06901ea055765cb7c77d6`
- **Closure Branch**: `fix/autonomous-investigation-completeness-closure`
- **Scope**: Correctness and completeness closure for the autonomous playbook investigation loop, exit predicate evaluation, ledger persistence/resource recovery, CI exit-code semantics, and severity-aware run comparison.

---

## 1. Root Causes Identified

1. **Premature Investigation Limits (`extractor/playbook_loop_runner.py`, `scripts/mcp_server.py`, `extractor/cli.py`, `extractor/tracking_ledger.py`)**:
   - `run_playbook_loop()`, `runtime_run_playbook_loop()`, and CLI `loop` defaulted to `max_iterations=4` and `time_budget_s=20.0`, and clamped explicit `max_iterations` to `10`.
   - `TargetTrackingLedger.activate_playbook()` enforced `default_max_iterations` even when no user limit was requested, terminating deep investigations before sufficient evidence was gathered.
   - Total investigation budget and individual tool execution duration were conflated, with no tracking of slow-tool overruns or explicit partial-evidence preservation metadata.
2. **False-Positive `MET` on Arbitrary Code Anchors (`extractor/tracking_ledger.py`)**:
   - `TargetTrackingLedger.record()` marked `predicate_status = "MET"` whenever `runtime_correlate_source_and_state` returned any anchor or whenever a `FAULT` verdict existed with any anchor, without evaluating the active playbook's actual `exit_predicate` or separating evidence discovery from hypothesis validation.
3. **Broken Post-Restart Ledger Recovery & Path Collisions (`extractor/tracking_ledger.py`, `scripts/mcp_server.py`)**:
   - `TrackingLedgerStore.get()` only checked in-memory `_ledgers` and never reloaded persisted files from disk, causing MCP Resources (`resource_ledger_decision_log`, `resource_ledger_code_anchors`) to return `active: false` after a server restart.
   - `_ledger_path()` sanitized characters into `_` without a hash suffix, allowing cross-target filename collisions (e.g., `host:1:100` vs `host_1:100`).
   - Concurrent saves shared a single `.tmp` filename and lacked revision checks to prevent stale in-memory ledgers from overwriting newer disk state.
4. **Permissive CI Exit Code Precedence (`extractor/playbook_loop_runner.py`)**:
   - `verdict_to_exit_code()` checked `verdict == "HEALTHY"` before `predicate_status == "EXHAUSTED"`, allowing an incomplete/exhausted investigation whose last tool reported `HEALTHY` to exit with code `0`.
5. **Ungrounded Regression Heuristics in Run Comparison (`extractor/playbook_loop_runner.py`)**:
   - `diff_diagnostic_runs()` flagged every new finding (including `INFO` / `non_fault` findings) and any RSS delta `> 10240 KB` as a regression, silently omitted missing metrics, and ignored severity escalations on persistent findings.

---

## 2. Before / After Behavior

| Area | Before (`e7ce428`) | After (Closure) |
| :--- | :--- | :--- |
| **Default Loop Limits** | `max_iterations=4`, `time_budget_s=20.0`, clamped to `<= 10` | `max_iterations=None`, `time_budget_s=None` (unbounded unless explicitly configured; no clamping) |
| **Timing Accounting** | Single wall-clock check before step | Tracks `timing.total_elapsed_s`, `timing.time_budget_s`, `timing.longest_tool_s`, `timing.longest_tool_name`, `timing.budget_exceeded_during_tool`; slow tool results are always recorded and preserved |
| **Tool Exceptions** | Recorded as failed call, could stall loop | Isolated in `tool_errors[]` and `decision_log[]`; loop continues to subsequent steps/pivots without losing prior evidence |
| **Exit Predicate (`MET`)** | Any anchor from `runtime_correlate_source_and_state` triggered `MET` | Explicit `_evaluate_exit_predicate()` per playbook separating discovery from hypothesis validation (`SUPPORTED` / `CONTRADICTED` / `INCONCLUSIVE` / `BLOCKED`); arbitrary anchors never trigger `MET` |
| **Ledger Persistence & Resources** | `get()` was memory-only; punctuation collisions; shared `.tmp`; no revision check | `get()` recovers from disk after restart; SHA-256 suffixed filenames; per-PID/thread atomic `.tmp` + `fsync` + `os.replace`; revision/mtime merge prevents stale overwrites |
| **CI Exit Codes** | `HEALTHY + EXHAUSTED` returned `0` | `EXHAUSTED` / `OPEN` / `PIVOT_REQUIRED` always return `4` (`EXIT_INCONCLUSIVE`); `0` only on validated `HEALTHY` (`MET` or standalone); `BLOCKED` (`5`) distinct from `INCONCLUSIVE` (`4`) |
| **Run Comparison (`diff_diagnostic_runs`)** | All new findings + `rss_kb > 10240` flagged as regression; missing metrics omitted | Severity-aware (`INFO`/`non_fault` excluded), tracks `severity_changes` escalations, removes ungrounded RSS magic threshold, explicitly marks missing metrics as `status: "unknown"` |

---

## 3. Exit Predicate Semantics

- **Discovery vs Validation**: `code_anchors` and raw deltas are recorded as *evidence discovery*. `hypothesis_status` (`UNVALIDATED`, `SUPPORTED`, `CONTRADICTED`, `INCONCLUSIVE`, `BLOCKED`) tracks *validation*, with structured provenance stored in `evidence_provenance[]` and `exit_predicate_evaluation`.
- **Terminal States**:
  - `MET`: Only reached when the active playbook's completion criteria are genuinely satisfied (e.g., `SUPPORTED` fault with corroborating owner/code anchor, validated `CONTRADICTED`/`HEALTHY` with complete coverage, or for `state-and-variable-bug`, direct live symbol evaluation + source correlation + validation). `PARTIAL_SAMPLED` / `NO_FAULT_LIMITED_OBSERVATION` never falsely satisfies a full-coverage refutation predicate.
  - `BLOCKED`: Hard external access failure (`Permission denied`, `EPERM`, `ptrace`, `ESRCH` / `process_exited`).
  - `EXHAUSTED`: Explicit user iteration/time limit reached or all playbook steps and pivots completed without satisfying the exit predicate; all partial evidence and `decision_log` rows are retained.
  - `PIVOT_REQUIRED`: Two consecutive non-advancing iterations trigger an automatic pivot to the playbook's next tier rather than stopping.

---

## 4. Time and Iteration Budget Semantics

- **Default**: Unbounded (`max_iterations=None`, `time_budget_s=None`). Investigations run until `MET`, `BLOCKED`, or natural completion of planned playbook steps and pivots.
- **Explicit User Limits**: Honored verbatim (no clamping to 10).
- **Per-Tool vs Total Duration**: Each step records `duration_s`. If a single slow tool exceeds an explicit `time_budget_s`, its full output, anchors, and verdict are still ingested and persisted to the ledger before the loop exits cleanly with `final_status="EXHAUSTED"`, `limit_reason="explicit_time_budget_exhausted_during_tool"`, and `timing.budget_exceeded_during_tool=True`.

---

## 5. Ledger Persistence Behavior

- **Collision-Safe Paths**: `ledger_<sanitized_prefix>_<sha256(target_key)[:16]>.json`, with `make_target_key()` separating `local:<pid>`, `<remote_host>:<pid>`, and non-default `<remote_host>@<port>:<pid>`.
- **Atomic Concurrency**: Writes use per-process/thread temporary files (`<path>.<pid>.<tid>.tmp`), `flush()` + `os.fsync()`, and atomic `os.replace()`.
- **Stale-Overwrite Protection**: `save()` reloads disk metadata and merges newer disk anchors/signatures/revisions whenever disk `revision` or `mtime_ns` is ahead of memory.
- **Restart Recovery**: Both `TrackingLedgerStore.get()` and `get_or_create()` transparently reload persisted JSON ledgers from `DYNAMICSTATE_LEDGER_DIR` / `persist_dir`, enabling MCP Resources (`dynamicstate://ledger/{host}/{pid}/decision-log`, `dynamicstate://ledger/{host}/{pid}/code-anchors`) to recover immediately after a server restart while maintaining bounded LRU memory (`max_targets=32`).

---

## 6. Regression Test Results

- **New Suite**: `tests/test_autonomous_investigation_completeness_closure.py` (13 deterministic test methods covering all 12 required scenarios plus severity-aware `diff_diagnostic_runs` and full verdict/status exit-code matrix; zero real sleeps via `_DeterministicClock`).
- **Combined Verification Run**: **152 passed, 0 failed** across 18 test modules (`test_autonomous_investigation_completeness_closure.py`, `test_mcp_cli_autonomous_loop.py`, `test_playbook_router_and_loop.py`, `test_continuous_tracking_p0_p1_p2.py`, `test_all_recipes_tiered_fallback.py`, `test_tiered_heap_sampling_and_agent_drilldown.py`, `test_report_intelligence_improvements.py`, `test_diagnostic_intelligence_closure.py`, `test_phase2_1_deterministic_recipes.py`, `test_phase2_2_allocator_pointer_integrity.py`, `test_phase40_advanced_mcp_tools.py`, `test_phase42_ipc_pipeline_and_heap_scanner.py`, `test_phase52_web_and_mcp_defensive_hardening.py`, `test_phase2_1_mcp_and_ui_integration.py`, `test_mcp_explain_tool.py`, `test_mapping_growth_and_heap_retention.py`, `test_thread_leak_recipe.py`, `test_web_server_lifecycle.py`).

---

## 7. CI Verification Status

- The sandbox environment does not have GitHub push credentials or outbound `api.github.com` access, so GitHub Actions workflows (**Test Suite** and **GDB 9.2 Compatibility**) could not be triggered remotely from this environment.
- Local verification passed (`152 passed`) against the final closure commit on `fix/autonomous-investigation-completeness-closure`.
- **Required Post-Push Action**: Apply the patch / push the commit to `zeeny2park/dynamicState` and verify green runs on both **Test Suite** and **GDB 9.2 Compatibility** workflows at `https://github.com/zeeny2park/dynamicState/actions`.

---

## 8. Remaining Limitations

- Local sandbox runs with `kernel.yama.ptrace_scope=1` and without `gdb` installed; live cross-process `/proc/<pid>/mem` and GDB 9.2 compatibility checks are therefore validated via GitHub Actions rather than inside the sandbox.
- Multi-process disk ledger merging merges `code_anchors`, `dead_end_signatures`, and `decision_log` append-only; if two independent processes simultaneously activate *different* playbooks for the exact same `host:pid`, last-writer-wins applies to `active_playbook`.

---

## 9. Final Verdict

**CONDITIONAL GO** — All 5 correctness closures and all 12 deterministic regression test scenarios are implemented and passing locally (`152 passed`). Promotion to **GO** is conditioned solely on verifying green **Test Suite** and **GDB 9.2 Compatibility** GitHub Actions runs on the pushed commit SHA.

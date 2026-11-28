# Diagnostic Intelligence Correctness & Baseline Closure Report

- **Base Commit**: `4d59f25ad0a67223d9a70a0c8c59f76e80ba6132`
- **Closure Branch**: `fix/diagnostic-intelligence-closure`
- **Date**: 2026-11-25
- **Verdict**: **CONDITIONAL GO** (All implemented intelligence, baseline identity, coverage, persistence, diff, and MCP action validation checks passed; pytest-only trust tests and cross-process ptrace CLI tests under `yama.ptrace_scope=1` were `NOT RUN` in this sandbox and should run in CI.)

## 1. Problems Identified, Root Causes, and Code Paths

| Area | Problem in `4d59f25` | Root Cause | Code Path Fixed |
| :--- | :--- | :--- | :--- |
| **Baseline Identity** | Local vs remote or cross-host baselines could match when `host` was `None` on one side; `process_name`-only auto-matching allowed unrelated binaries; explicit baseline file paths bypassed target compatibility checks. | `_matches_target()` only checked `host` when both sides were truthy, fell back to `process_name == process_name`, and `load_diagnosis_baseline()` returned `os.path.isfile(sel)` directly without identity validation. | `extractor/diagnosis_baseline.py` (`evaluate_target_identity_match`, `resolve_diagnosis_baseline`, `_matches_target`), `extractor/expert_diagnostic_engine.py` (`_populate_intelligence`) |
| **Coverage Classification** | Partial `PASS` checks could mask execution errors (`stage_failed`, `check_error`, `budget_exhausted`, `symptom_question_unanswered`) as `NO_FAULT_LIMITED_OBSERVATION`; malformed `HEALTHY` claims with blocking gaps were not guarded. | `classify_coverage()` checked `elif passed and not failed and not has_access_block` without checking `has_execution_failure` or non-budget `blocking_gaps`. | `extractor/state_intelligence.py` (`classify_coverage`) |
| **Baseline Persistence** | Non-atomic writes (`open(..., "w")`), no file lock on `index.json` (concurrent lost updates), no auto-recovery for corrupted `index.json`, unvalidated `investigation_id` filenames, and retention cap (`200`) did not delete evicted `.baseline.json` files. | Direct `json.dump()` without temp+fsync+replace, no `fcntl.flock`, no `_rebuild_index()`, and slice-only pruning (`entries[-200:]`). | `extractor/diagnosis_baseline.py` (`sanitize_investigation_id`, `_validate_snapshot_record`, `_atomic_write_json`, `_index_lock`, `_rebuild_index`, `save_diagnosis_baseline`) |
| **Baseline Diff Intelligence** | Single-point RSS/Heap/FD spikes triggered `REGRESSION` immediately; thread role/state shifts, liveness transitions, added/removed containers, and finding recurrence were not tracked. | `compare_diagnosis_baseline()` treated any `delta_pct >= 35%` as `REGRESSION` and only diffed intersecting containers (`set(b_cont) & set(c_cont)`). | `extractor/diagnosis_baseline.py` (`extract_baseline_snapshot`, `_has_sustained_growth`, `compare_diagnosis_baseline`) |
| **MCP Action Validation** | `runtime_heap_leak_candidates`, `runtime_inspect_thread_callstack_and_locks`, and `runtime_eval_memory_path` were emitted with `debug_image` / `expr` instead of actual MCP parameter names `companion_elf` / `expressions`; placeholder and remote-tracing preconditions were not marked non-executable. | `build_suggested_actions()` hardcoded CLI-like parameter names without validating against `scripts/mcp_server.py`. | `extractor/state_intelligence.py` (`get_mcp_tool_registry`, `validate_suggested_action`, `build_suggested_actions`) |

## 2. Implemented Safeguards

### 2.1 Strict Target Identity Matching
- `evaluate_target_identity_match(current_target, baseline_target)` normalizes host (`""`, `None`, `localhost`, `127.0.0.1`, `::1` → `"local"`) and checks `host`, `arch`, `build_id`, `binary_path`, and `process_name`.
- Returns structured status: `EXACT`, `COMPATIBLE`, `WEAK`, `MISMATCH`, or `UNKNOWN`, plus `matched_fields`, `mismatched_fields`, and `auto_selectable`.
- Auto-selection (`latest`, `latest_healthy`, `auto`) accepts **only** `EXACT` or `COMPATIBLE` (rejects cross-host, `WEAK` process-name-only, `UNKNOWN`, and `MISMATCH`).
- Explicit file paths and investigation IDs are also validated; `MISMATCH` refuses diff generation (`available: False`, `reason: "target_identity_mismatch: ..."`).

### 2.2 Conservative Coverage Classification
- `classify_coverage()` explicitly tracks `has_access_block`, `has_check_error`, `non_budget_blocking`, and `has_execution_failure`.
- `INCONCLUSIVE` with any execution error, check error, or non-budget blocking gap is always `BLOCKED_EXECUTION` regardless of partial `PASS` checks.
- `NO_FAULT_LIMITED_OBSERVATION` is emitted only when `passed > 0`, `failed == 0`, `has_access_block == False`, `has_execution_failure == False`, and remaining gaps are strictly policy/budget limits.
- `HEALTHY` with `failed` or `non_budget_blocking` or `has_execution_failure` is flagged as `INCONSISTENT_HEALTHY_CLAIM` so incomplete coverage cannot masquerade as full `HEALTHY`.

### 2.3 Durable Atomic Baseline Persistence
- `sanitize_investigation_id()` enforces `^[A-Za-z0-9._-]{1,128}$` and rejects `..`, `/`, and `\`.
- Snapshot and `index.json` writes use same-directory temporary files + `flush()` + `os.fsync()` + `os.replace()`.
- `fcntl.flock` on `<corpus>/baselines/.index.lock` prevents concurrent lost updates.
- Corrupted or missing `index.json` is automatically rebuilt via `_rebuild_index()` scanning valid `*.baseline.json` records while skipping partial/corrupt files.
- Retention pruning (default `200`, configurable via `max_entries`) unlinks evicted `.baseline.json` files strictly within the baselines directory. All persistence exceptions are caught so baseline I/O never fails diagnosis.

### 2.4 Baseline Diff Intelligence
- Snapshots record `rss_trend`, `fd_trend`, `thread_roles`, `liveness` deltas (`cpu_time_ms_delta`, `voluntary/involuntary/total_switches_delta`, `io_syscalls_delta`, `liveness_status`), `containers`, and `finding_categories`.
- `compare_diagnosis_baseline()` reports `thread_role_diffs`, `activity_diffs`, `liveness_transition`, `added_containers`, `removed_containers`, `containers`, `new_findings`, `recurring_findings`, `resolved_findings`, `sustained_regressions`, and `single_point_spikes`.
- Single-point RSS/Heap/FD spikes without in-window monotonic rising trend, multi-snapshot repeat growth (`prior_baselines`), or findings are downgraded from `REGRESSION` to `DRIFT` (`single_point_spike: True`).

### 2.5 MCP Tool Registry Action Validation
- `get_mcp_tool_registry()` caches AST-introspected `@server.tool()` signatures from `scripts/mcp_server.py`.
- Narrow MCP actions now emit exact registered parameter names (`companion_elf`, `expressions: List[str]`).
- `validate_suggested_action()` verifies tool existence, required arguments, parameter names/types, placeholder values (`<...>`), and remote/local capability constraints (blocking remote `enable_tracing=True` and remote calls missing ELF).
- Every action carries `estimated_cost`, `expected_evidence`, `risk_level`, `requires_user_approval`, `executable`, optional `blocked_reason`/`missing_inputs`, and `validation: {valid, issues}`.

## 3. Verification Matrix (Executed vs Not Run)

| Test Suite | Category | Result | Notes |
| :--- | :--- | :--- | :--- |
| `tests/test_diagnostic_intelligence_closure.py` | Closure Regression (11 tests) | **PASS** | Identity, coverage, durability, trends, MCP validation |
| `tests/test_report_intelligence_improvements.py` | Intelligence Unit (5 tests) | **PASS** | Liveness, watchlist, coverage, baseline, agent summary |
| `tests/test_process_profile.py` | Profile & Liveness (19 tests) | **PASS** | Empty-field & line/word-budget invariants verified |
| `tests/test_report_outline.py` | Report Outline & HTML/MD Parity | **PASS** | 4-status-word, heading hierarchy, healthy length |
| `tests/test_report_story.py` | Timeline & Competing Causes | **PASS** | All checks passed |
| `tests/test_korean_report_language.py` | KO/EN Localization | **PASS** | Zero untranslated template leakage |
| `tests/test_default_check_budget.py` | Live Budget & Policy Skip | **PASS** | Executed against live C target |
| `tests/test_web_diagnose_jobs.py` | Web Async Jobs & Parity | **PASS** | Sync/async parity verified |
| `tests/test_web_api.py` | Web API Routes | **PASS** | All routes verified |
| `tests/test_large_target_investigation_closure.py` | 100K+ LOC Large Target | **PASS** | No regression on large-target closure |
| `tests/test_build_id_optional_and_single_download_bundle.py` | Optional Build-ID & Bundle | **PASS** (3 skipped) | 3 remote-SSH-dependent tests skipped by suite |
| `tests/test_remote_single_tx_prefetch_and_bundle_completion.py` | Remote 3-Hop Bundle | **PASS** | All remote prefetch tests passed |
| `tests/test_trust_boundary_operation_id.py` | Trust Integrity (unittest) | **PASS** | Operation ID integrity passed |
| `tests/test_cli.py` | CLI Interface | **PASS** | All CLI parser/dispatch tests passed |
| `tests/test_trust_boundary_provenance.py` | Trust Integrity (pytest) | **NOT RUN** | `pytest` package not installed in sandbox |
| `tests/test_p0_p1_integrity_closure.py` | Legacy Production Capture Mock | **FAIL (Pre-existing)** | 2 mock tests fail on pre-existing missing `collected_evidence_records` attr |
| Live cross-process CLI ptrace tests (`test_healthy_verdict`, `test_imp_012_human_report`, `test_incident_report_html`) | Live Cross-Process CLI | **NOT RUN (Blocked by host)** | Sandbox `yama.ptrace_scope=1` denies sibling `/proc/<pid>/mem` |

**Executed unittest total in final verification pass**: **170 passed, 0 failed, 3 skipped** across 14 runnable test modules.

## 4. CI, Residual Risks, and Go/No-Go Assessment

- **CI Impact**: No new external Python dependencies added (`fcntl`, `ast`, `tempfile` are stdlib; Linux-targeted codebase). All existing report outline, localization, profile, CLI, Web API, and remote bundle tests remain green.
- **Residual Risks**:
  - `get_mcp_tool_registry()` parses `scripts/mcp_server.py` via AST; in wheel-installed environments where `scripts/` is mapped to package `dynamicstate_mcp`, `mcp_server.py` path resolution should be checked if installed outside the repo checkout (safe fallback: empty registry skips unknown-tool error without crashing).
  - Pre-existing `test_p0_p1_integrity_closure.py` mock attribute mismatch and `pytest`-dependent trust suites should be verified in the GitHub Actions CI matrix.
- **Decision**: **CONDITIONAL GO** — Ready to merge once GitHub Actions CI confirms the `pytest` trust-boundary suites and live `ptrace_scope=0` CLI integration tests pass.

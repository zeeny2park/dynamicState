# Playbook: Intermittent, Load-Dependent & Short-Window Inconclusive Bug

- **ID**: `intermittent-temporal-bug`
- **Exit Predicate (never relax)**: Condition-triggered capture or before/after diff catches the anomaly window with concrete delta and source-code anchors, OR observation window expires with documented baseline telemetry.
- **Max Iterations**: 5

## Steps
1. **[TIER0_ENTRY] `runtime_explain_process_behavior`** — Establish baseline subsystem behavior and candidate metrics to monitor.
   - CLI: `dynamic-state explain -p <pid> -d <elf>`
   - Expected evidence: baseline RSS, FDs, threads, active subsystems
2. **[TIER3_TEMPORAL_WATCH] `runtime_capture_and_diff`** — Capture a 5s before/after delta during workload activity.
   - CLI: `dynamic-state diff -p <pid> -d <elf> --wait-ms 5000`
   - Expected evidence: changed metrics/expressions over 5s
3. **[TIER3_TEMPORAL_WATCH] `runtime_watch_until_condition`** — Arm a zero-stop condition watcher to capture state the moment thresholds cross.
   - CLI: `dynamic-state watch-until -p <pid> -d <elf> --condition '<expr>' --timeout-ms 30000`
   - Expected evidence: triggered snapshot at anomaly instant
4. **[TIER2_DEEP_INSPECT] `runtime_correlate_source_and_state`** — Map the triggered state to source code locations.
   - CLI: `dynamic-state correlate-source -p <pid> -d <elf>`
   - Expected evidence: code_anchors

## Plateau -> Pivot Rules
- **When**: No threshold crossed within timeout -> **Pivot to `runtime_inspect_thread_callstack_and_locks`**: Inspect live call stacks to confirm whether the workload is exercising the suspect code path.

## Stop Conditions (Escape Hatch)
- MET: anomaly window captured with delta + code_anchors
- BLOCKED: target_unreadable / process_exited
- EXHAUSTED: max_iterations or watch timeout reached

# Playbook: File Descriptor Leak & IPC / Socket / Shared-Memory Stall

- **ID**: `fd-and-ipc-stall`
- **Exit Predicate (never relax)**: Leaking FD target or stalled IPC peer/backlog identified with owning call stack/code anchor, OR FD count and IPC peers confirmed stable.
- **Max Iterations**: 5

## Steps
1. **[TIER0_ENTRY] `runtime_diagnose_process`** — Measure FD trend, limits, and top newly opened descriptor targets.
   - CLI: `dynamic-state diagnose -p <pid> -d <elf> --symptom 'fd leak / ipc stall'`
   - Expected evidence: fd_count_trend, new_fd_targets
2. **[TIER1_NARROWING] `runtime_trace_ipc_pipeline`** — Trace sockets, pipes, shared memory rings, backlog utilization, and peer PIDs.
   - CLI: `dynamic-state ipc-pipeline -p <pid> -d <elf>`
   - Expected evidence: peer_processes, pending_backlog, shm_regions
3. **[TIER1_NARROWING] `runtime_inspect_thread_callstack_and_locks`** — Correlate blocked I/O descriptors with active thread stack frames.
   - CLI: `dynamic-state callstacks -p <pid> -d <elf>`
   - Expected evidence: source frames of read/write/accept/open sites

## Plateau -> Pivot Rules
- **When**: FD growth is non-monotonic in a short window -> **Pivot to `runtime_watch_until_condition`**: Arm a condition watch on open_fds growth or run runtime_capture_and_diff over a longer window.

## Stop Conditions (Escape Hatch)
- MET: leaking FD/stalled peer + code_anchors confirmed
- BLOCKED: target_unreadable / process_exited
- EXHAUSTED: max_iterations reached

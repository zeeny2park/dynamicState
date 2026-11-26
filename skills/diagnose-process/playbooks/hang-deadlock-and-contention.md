# Playbook: Process Hang, Deadlock, Lock Contention & Thread Leak

- **ID**: `hang-deadlock-and-contention`
- **Exit Predicate (never relax)**: Blocking lock/owner cycle or stalled thread frame confirmed across >=2 observations (stuck delta > 0s) with source file:line anchor, OR all threads confirmed progressing normally.
- **Max Iterations**: 6

## Steps
1. **[TIER0_ENTRY] `runtime_diagnose_process`** — Run baseline diagnosis to classify thread states, lock waits, and liveness.
   - CLI: `dynamic-state diagnose -p <pid> -d <elf> --symptom 'process hang / deadlock'`
   - Expected evidence: liveness status, waiting TIDs, inconclusive_drilldown
2. **[TIER1_NARROWING] `runtime_inspect_thread_callstack_and_locks`** — Capture exact per-thread call stacks, blocking syscalls, and mutex owner/waiter edges.
   - CLI: `dynamic-state callstacks -p <pid> -d <elf>`
   - Expected evidence: waiting TIDs, lock addresses, top source frames
3. **[TIER1_NARROWING] `runtime_build_dependency_graph`** — Synthesize cross-thread/lock/IPC dependency graph to isolate root blocker nodes.
   - CLI: `dynamic-state dependency-graph -p <pid> -d <elf>`
   - Expected evidence: root_blocker_nodes and causal_chains
4. **[TIER2_DEEP_INSPECT] `runtime_correlate_source_and_state`** — Map root-blocker frames and mutex symbols to exact repository file:line.
   - CLI: `dynamic-state correlate-source -p <pid> -d <elf>`
   - Expected evidence: code_anchors for lock acquisition/release sites

## Plateau -> Pivot Rules
- **When**: Threads are blocked in epoll_wait/read/recv/poll rather than futex -> **Pivot to `runtime_trace_ipc_pipeline`**: Stall is external I/O or IPC peer backpressure; pivot to IPC pipeline trace.
- **When**: Single callstack snapshot cannot distinguish transient contention from permanent stall -> **Pivot to `runtime_inspect_thread_callstack_and_locks`**: Re-sample callstacks after a few seconds and inspect delta_from_last_call.stuck_threads.

## Stop Conditions (Escape Hatch)
- MET: root blocker TID/lock + code_anchors confirmed, or threads confirmed progressing
- BLOCKED: target_unreadable / process_exited
- EXHAUSTED: max_iterations reached

# Playbook: Memory Leak, RSS Growth & Large-Heap Attribution

- **ID**: `memory-leak-and-growth`
- **Exit Predicate (never relax)**: Root cause confirmed with owning variable/container path (or unreachable size class + code anchor), OR sustained growth refuted across >=2 time-separated observations.
- **Max Iterations**: 6

## Steps
1. **[TIER0_ENTRY] `runtime_diagnose_process`** — Run baseline diagnosis + Tier-2 bounded sampling on large heaps (>50MB).
   - CLI: `dynamic-state diagnose -p <pid> -d <elf> --symptom 'memory leak'`
   - Expected evidence: verdict, memory_integrity.heap.sampling_tier, inconclusive_drilldown
2. **[TIER1_NARROWING] `runtime_heap_leak_candidates`** — Identify top unreachable or growing glibc chunk size classes and sample addresses.
   - CLI: `dynamic-state heap-leaks -p <pid> -d <elf>`
   - Expected evidence: candidate size classes and hex addresses
3. **[TIER2_DEEP_INSPECT] `runtime_heap_owner_lookup`** — Reverse-lookup owning globals/containers retaining the candidate addresses.
   - CLI: `dynamic-state heap-owner -p <pid> -d <elf> <addr>`
   - Expected evidence: variable_path, root_kind, decl_file:decl_line
4. **[TIER2_DEEP_INSPECT] `runtime_eval_memory_path`** — Inspect live size, capacity, and retention fields of the owning container.
   - CLI: `dynamic-state eval -p <pid> -d <elf> --expr <owner_path>`
   - Expected evidence: live container size/capacity values
5. **[TIER2_DEEP_INSPECT] `runtime_correlate_source_and_state`** — Bridge confirmed runtime ownership to exact source file:line for fixing.
   - CLI: `dynamic-state correlate-source -p <pid> -d <elf>`
   - Expected evidence: code_anchors (file:line, function, variable_path)

## Plateau -> Pivot Rules
- **When**: heap_leak_candidates returns 0 unreachable blocks -> **Pivot to `runtime_scan_heap_objects`**: Growth may live in reachable C++ containers or custom pools; pivot to vtable object census.
- **When**: 2 consecutive iterations show no delta or non-monotonic RSS -> **Pivot to `runtime_capture_and_diff`**: Escalate to a 5s before/after temporal diff or condition watch to capture slow growth.

## Stop Conditions (Escape Hatch)
- MET: owning container/variable path + code_anchors confirmed, or growth refuted
- BLOCKED: target_unreadable / process_exited
- EXHAUSTED: max_iterations reached (emit decision_log + remaining open leads)

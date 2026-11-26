# Playbook: Unexpected Variable Mutation, State Machine & Pointer Anomaly

- **ID**: `state-and-variable-bug`
- **Exit Predicate (never relax)**: Target symbol values evaluated directly in live memory and correlated to source file:line, confirming or refuting the invariant violation.
- **Max Iterations**: 5

## Steps
1. **[TIER2_DEEP_INSPECT] `runtime_symbol_search`** — Discover exact DWARF symbol names for the suspect state struct, flag, or counter.
   - CLI: `dynamic-state symbol-search -d <elf> --query '<keyword>'`
   - Expected evidence: matched symbol names and decl_file:decl_line
2. **[TIER2_DEEP_INSPECT] `runtime_eval_memory_path`** — Read live values of the matched symbols with 0ms process stop.
   - CLI: `dynamic-state eval -p <pid> -d <elf> --expr '<sym>'`
   - Expected evidence: live field values and pointer validity
3. **[TIER3_TEMPORAL_WATCH] `runtime_capture_and_diff`** — Sample the expression twice to verify whether it is mutating unexpectedly or stuck.
   - CLI: `dynamic-state diff -p <pid> -d <elf> --expr '<sym>' --wait-ms 3000`
   - Expected evidence: changed vs unchanged struct fields
4. **[TIER2_DEEP_INSPECT] `runtime_correlate_source_and_state`** — Bind the live anomaly to exact source lines for code review and patching.
   - CLI: `dynamic-state correlate-source -p <pid> -d <elf>`
   - Expected evidence: code_anchors

## Plateau -> Pivot Rules
- **When**: runtime_symbol_search returns 0 hits -> **Pivot to `runtime_symbol_search`**: Retry with fast_only=True ELF symtab and shorter root token, or pivot to runtime_scan_heap_objects.
- **When**: runtime_eval_memory_path fails on expression syntax -> **Pivot to `runtime_coerce_expression`**: Normalize the pointer/member path via runtime_coerce_expression and re-evaluate.

## Stop Conditions (Escape Hatch)
- MET: symbol values verified + code_anchors extracted
- BLOCKED: missing_debug_image with no symtab / target_unreadable
- EXHAUSTED: max_iterations reached

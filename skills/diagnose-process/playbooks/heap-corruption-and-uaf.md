# Playbook: Heap Metadata Corruption, Double-Free & Use-After-Free

- **ID**: `heap-corruption-and-uaf`
- **Exit Predicate (never relax)**: Corrupted chunk/free-list/dangling pointer identified with owning variable or symbol anchor, OR full/Tier-2 integrity checks confirm no active corruption.
- **Max Iterations**: 6

## Steps
1. **[TIER0_ENTRY] `runtime_diagnose_process`** — Run memory integrity + Tier-2 tcache/fastbin cycle & UAF sampling.
   - CLI: `dynamic-state diagnose -p <pid> -d <elf> --symptom 'heap corruption'`
   - Expected evidence: heap defects, SAMPLED_DEFECTS_FOUND or PARTIAL_SAMPLED
2. **[TIER1_NARROWING] `runtime_audit_memory_integrity`** — Audit DWARF pointers, sentinel values, and pool headers for corruption.
   - CLI: `dynamic-state audit -p <pid> -d <elf>`
   - Expected evidence: corrupted pointer/header addresses
3. **[TIER2_DEEP_INSPECT] `runtime_heap_owner_lookup`** — Find the variable or buffer adjacent to or referencing the damaged chunk.
   - CLI: `dynamic-state heap-owner -p <pid> -d <elf> <corrupt_addr>`
   - Expected evidence: owning variable_path and referrer root
4. **[TIER2_DEEP_INSPECT] `runtime_correlate_source_and_state`** — Map the owning pointer/buffer to exact source file:line allocation/free sites.
   - CLI: `dynamic-state correlate-source -p <pid> -d <elf>`
   - Expected evidence: code_anchors for fix & ASan reproduction

## Plateau -> Pivot Rules
- **When**: Tier-2 sampling clean (PARTIAL_SAMPLED) but corruption still suspected -> **Pivot to `runtime_symbol_search`**: Locate suspect pool/buffer globals by name and inspect them directly with runtime_eval_memory_path.
- **When**: Symbol search returns 0 hits -> **Pivot to `runtime_scan_heap_objects`**: Pivot to vtable-based C++ object scan or fast_only=True symtab lookup.

## Stop Conditions (Escape Hatch)
- MET: damaged chunk/pointer + owner + code_anchors confirmed
- BLOCKED: target_unreadable / process_exited
- EXHAUSTED: max_iterations reached

# HEALTHY verdict of `diagnose`

Rule `RULE_5B_HEALTHY_WITHIN_BASELINE_SCOPE`, code `extractor/healthy_verdict.py`, applied at the end of
`diagnose()`; the aggregator's decision table lists it (one vocabulary: `VERDICT_HEALTHY`).

## Meaning

HEALTHY = every baseline check ran to completion with the evidence it needs and found nothing, **within its stated
scope**. It never means "nothing found because nothing could be checked" (that is INCONCLUSIVE, IMP-001).

## Rule

HEALTHY only if all hold:

1. Collection succeeded: no blocking `not_covered` kind (`target_unreadable`, `target_unreachable`, `invalid_target`,
   `missing_debug_image`, `abi_detection_failed`, `stage_failed`, `not_executed`, `baseline_check_not_run`,
   `budget_exhausted`, engine `limitation`, `unattributed_finding`, `unexpected_error`) and no kind the rule does not
   know.
2. No finding of any severity, no FAIL check (baseline or not); aggregator verdict INCONCLUSIVE or HEALTHY.
3. Every recipe in `BASELINE_RECIPE_IDS` executed and every check of it PASSed (= the recipe looked and found
   nothing, CONTRADICTED). Only exception: `RECIPE_HEAP_METADATA_CORRUPTION` INCONCLUSIVE because the heap is above
   the baseline walk cap (`memory_integrity.heap.not_checked_reason == "above_baseline_cap"`) while the global
   adjacency and stack-margin parts completed clean: a declared cost limit, listed as not checked. Every other
   non-PASS baseline status (INCONCLUSIVE, ERROR, NOT_APPLICABLE, UNSUPPORTED, NOT_EXECUTED) blocks.
4. Scope limits do not block; they are listed in `healthy_scope.not_checked` and named in the first sentence of
   the summary ("healthy within the checked scope ... Not checked: ...").

Not-healthy results carry the reasons in `healthy_scope.blocking`. A RULE_5 HEALTHY of the aggregator that fails
this rule is reported INCONCLUSIVE.

## Decisions

| Baseline recipe | Clears (PASS) when | Does not clear |
| --- | --- | --- |
| THREAD_STATE_ANOMALIES | usable sampling window, no runaway / zombie / D-state thread | unchanged |
| LONG_RUNNING_BLOCKED_THREADS | **changed**: usable window, owners decodable, lock graph complete, no stalled lock wait, no cycle -> CONTRADICTED. Long waits in syscalls are kept as `long_wait_not_judged` (not checked: an idle wait and a stall look the same from outside) | lock-owner decoding unsupported, incomplete graph, unusable window -> INCONCLUSIVE (blocks) |
| SUSPICIOUS_LOCK_OWNERSHIP | lock table read, no orphan/circular owner | unchanged |
| POTENTIAL_DEADLOCK_PATTERNS | wait-for graph complete and acyclic | unchanged; owner decoding unsupported -> INCONCLUSIVE (blocks, DEF-ARM-1) |
| PROCESS_MEMORY_GROWTH | no growth trend, or heap walks show no growth | heap walks not possible within the budget / too few walks -> INCONCLUSIVE (blocks) |
| HEAP_METADATA_CORRUPTION | heap walked, metadata intact | heap above cap -> scope limit (see 3); byte budget / unsupported allocator / incomplete walk -> blocks |
| FD_LEAK | fd count trend flat | unchanged |
| FREED_MEMORY_USE (plugin) | heap walked, no typed pointer into a free chunk, no write into one | heap above cap -> scope limit (`uaf_not_checked`); otherwise not walked -> blocks |
| DOUBLE_FREE (plugin, `recipe_plugins/double_free.py`) | every tcache bin and fastbin of the integrity walk followed to its end, no block listed twice | heap above cap -> scope limit (`double_free_not_checked`); a list never read consistently, unsupported allocator, budget -> blocks |

- **Target-support decision**: a feature unsupported on the target that no baseline check needs (e.g. `tcb_scan`)
  is a scope limit. A *baseline* check that could not answer its question for a target-support reason (mutex
  owners not decodable -> deadlock / lock checks INCONCLUSIVE) blocks HEALTHY: the question it owns was not answered.
- **Symptom-specific (non-baseline) recipes** never gate HEALTHY: their FAIL still blocks (it is a finding), any
  other non-PASS result is listed as "symptom-specific checks that reached no result". Several of them cannot clear
  anything on a live process (the traced use-after-free / object lifetime recipes need allocation-lifecycle tracing,
  `lifecycle_tracing_unavailable`); their negative is meaningless, so they are scope, not gate.
- **Always not checked** (`outside_baseline`): data races, program-logic errors, a use-after-free that leaves no
  typed pointer to a freed block and no write into one, a double free of a block re-allocated in between (listed
  once, like any free block).

## Known consequences

- A process blocked forever in `read()` / `poll()` is indistinguishable from an idle one: it is HEALTHY within scope
  with the long wait listed as not judged (the unscored `stall_*` benchmark targets).
- A use-after-free whose damage the heap-metadata check does not see is HEALTHY within scope with use-after-free
  listed as not checked (the `uaf_*` benchmark targets, not detected before this rule either).

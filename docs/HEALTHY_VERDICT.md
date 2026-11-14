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
   A baseline check left out by the time budget of the default checks (`extractor/check_budget.py`, decision 6.1-2:
   plan step `not_run_reason == "time_budget"`, `not_covered` row `baseline_check_not_run` with the same field) is
   the same coverage gap: it blocks (rule 1 and `baseline_check_missing` with `not_run_reason`), so the budget never
   yields a HEALTHY that skipped part of the baseline. Checks the symptom asks for are never budgeted.
4. Scope limits do not block; they are listed in `healthy_scope.not_checked` and named in the first sentence of
   the summary ("healthy within the checked scope ... Not checked: ...").
5. Verification scope (stage 1): every problem category a *specific* symptom asks about (the classifier's candidate
   categories; none for a vague symptom or a general health check, whose scope is the baseline) is answered by a
   check that answers that category and ran to completion with a clear result (PASS). Otherwise the result is
   INCONCLUSIVE with the blocking row `symptom_question_unanswered` (item: the category; reason: the checks of it
   and how they ended, or "not supported in this mode"). This is the only case where an `unsupported_in_mode`
   question gates HEALTHY: the symptom asked exactly that question. Inside the engine the same principle applies to
   the hypothesis criteria: a criterion PASSes only when a rule decided its invariant on an observation that covered
   it (an observed value or a read variable is not a check; an observation cut for a reason that matters to the
   invariant, `typed_evidence.INVARIANT_SCOPE_REASONS`, does not clear it).

Not-healthy results carry the reasons in `healthy_scope.blocking`. A RULE_5 HEALTHY of the aggregator that fails
this rule is reported INCONCLUSIVE.

## Decisions

| Baseline recipe | Clears (PASS) when | Does not clear |
| --- | --- | --- |
| THREAD_STATE_ANOMALIES | usable sampling window, no runaway / zombie / D-state thread | unchanged |
| LONG_RUNNING_BLOCKED_THREADS | **changed**: usable window, owners decodable, lock graph complete, no stalled lock wait, no cycle -> CONTRADICTED. Long waits in syscalls are kept as `long_wait_not_judged` (not checked: an idle wait and a stall look the same from outside) | lock-owner decoding unsupported, incomplete graph, unusable window -> INCONCLUSIVE (blocks) |
| SUSPICIOUS_LOCK_OWNERSHIP | lock table read, no orphan/circular owner | unchanged |
| POTENTIAL_DEADLOCK_PATTERNS | wait-for graph complete and acyclic | unchanged; owner decoding unsupported -> INCONCLUSIVE (blocks, DEF-ARM-1) |
| PROCESS_MEMORY_GROWTH | **changed**: the /proc samples stayed flat within the trend resolution (128 KB), or >= 3 heap walks show no growth: in-use flat, or the in-use total fell **and** no unreachable size class and no global/static owner grew across every walk | /proc samples that moved without a growth trend (rose and fell back, or only fell) are not cleared from /proc: the heap walks decide; walks not possible within the budget / too few walks -> INCONCLUSIVE (blocks), reason "memory growth not judged: ..." (see the scope limit below) |
| HEAP_METADATA_CORRUPTION | heap walked, metadata intact | heap above cap -> scope limit (see 3); byte budget / unsupported allocator / incomplete walk -> blocks |
| FD_LEAK | fd count trend flat | unchanged |
| FREED_MEMORY_USE (plugin) | heap walked, no typed pointer into a free chunk, no write into one | heap above cap -> scope limit (`uaf_not_checked`); otherwise not walked -> blocks |
| DOUBLE_FREE (plugin, `recipe_plugins/double_free.py`) | every tcache bin and fastbin of the integrity walk followed to its end, no block listed twice | heap above cap -> scope limit (`double_free_not_checked`); a list never read consistently, unsupported allocator, budget -> blocks |

- **Target-support decision**: a feature unsupported on the target that no baseline check needs (e.g. `tcb_scan`)
  is a scope limit. A *baseline* check that could not answer its question for a target-support reason (mutex
  owners not decodable -> deadlock / lock checks INCONCLUSIVE) blocks HEALTHY: the question it owns was not answered.
- **Symptom-specific (non-baseline) recipes** never gate HEALTHY: their FAIL still blocks (it is a finding), any
  other non-PASS result is listed as "symptom-specific checks that reached no result".
- **Checks this mode cannot execute** (`unsupported_in_mode`): a recipe whose rule reads values no zero-stop collector
  fills in declares `requires_capabilities` (`allocation_tracing`: traced use-after-free, suspicious allocation
  patterns, object lifetime anomalies; `caller_specification`: unexpected variable changes, state transition
  violations; `stopped_snapshot`: shared-state inconsistencies). Plan construction leaves it out, so it is neither
  executed nor an open check, and its question is listed in `healthy_scope.not_checked` ("not examined: ... they
  need ...") and in `not_covered`. It never gates HEALTHY (no baseline check owns the question) and never clears
  anything; a baseline recipe cannot declare a capability (registration refuses it). The recipes stay registered
  (explicit `run_recipe` still runs them, e.g. with a caller-supplied specification); an optional tracing mode would
  provide the capability and put them back in the plan.
- **Always not checked** (`outside_baseline`): data races, program-logic errors, a use-after-free that leaves no
  typed pointer to a freed block and no write into one, a double free of a block re-allocated in between (listed
  once, like any free block).

## Known consequences

- A process blocked forever in `read()` / `poll()` is indistinguishable from an idle one: it is HEALTHY within scope
  with the long wait listed as not judged (the unscored `stall_*` benchmark targets).
- A use-after-free whose damage the heap-metadata check does not see is HEALTHY within scope with use-after-free
  listed as not checked (the `uaf_*` benchmark targets, not detected before this rule either).
- A process whose memory rises and falls (a batch / sawtooth working set) and whose heap is larger than the walk read
  budget is INCONCLUSIVE, never HEALTHY: see the scope limit below (`ok_sawtooth` benchmark control).

## Scope limit: memory that rises and falls

What is observed. The cheap trend is 5-6 `/proc` samples (VmRSS, anonymous writable mappings) over the thread
sampler's window, about 1 s. The heap walks (IMP-008) are >= 3 censuses of the in-use heap with per-owner and
per-unreachable-size-class counts, spaced over the same window, each limited to 75 % of the session byte budget
left (session budget 64 MiB, so about 48 MiB for the first walk).

Why /proc is not enough. A periodic working set with a leak under it also rises and falls, and within one window
of about one period its samples look like those of the healthy batch. RSS also does not move when a leak fills
memory the allocator already holds (measured: `proc_leak_sawtooth_small`, an unreachable 2000-byte leak of
~150 KB/s, kept RSS flat at 4.2 MiB). Comparing the low points of several periods would need >= 3 periods in the
window and still misses that case. So a series that moved by the trend resolution without a growth trend is not
cleared from `/proc`; the walks decide. Before this rule the cheap trend cleared any series with a fall in it,
and `ok_sawtooth` (generic symptom) was HEALTHY or INCONCLUSIVE depending on whether the ~1 s window happened to
contain the fall (3 of 6 runs HEALTHY).

Why the walks are not enough for a large sawtooth. A fall of the in-use total is evidence of "released, not a
leak" only when no unreachable size class and no global/static owner grew across every walk; before this rule
any fall cleared, and `proc_leak_sawtooth_small` was HEALTHY in 4 of 4 runs (now a MEMORY_LEAK finding). That
judgement needs the walks. On `ok_sawtooth` (50 x 2 MiB blocks per batch in a thread's arena, released after
each batch) one walk needs about 62 MiB of reads (the arena heap), more than the 48 MiB a walk may use, so no
walk completes and the check is INCONCLUSIVE with: "memory growth not judged: one heap walk of this process needs
about 62.0 MiB of reads, more than the 24.0 MiB budget left for it ... The /proc samples rose by .. MiB and fell
back ..: one window of memory that rises and falls cannot tell a periodic working set from one with a leak under
it". The human report's conclusion quotes this sentence as the reason the result is not HEALTHY.

What would be enough. >= 3 walks of the whole heap, i.e. a byte budget of about 3 x the heap (about 190 MiB here)
and the wall time for them (about 6 s of walking on the 4-core AArch64 test host under load), plus the rest of
the baseline within the session's wall-clock budget. Measured with the byte budget raised to 600 MiB (an
experiment, not a setting `diagnose` offers): `ok_sawtooth` was HEALTHY (in-use 63488 / 22528 / 63488 / 63488 KB,
no growing class) in about 21 s, and the same batch with an 8000-byte unreachable leak under it
(`proc_leak_sawtooth_large`) was found (LEAK_UNREACHABLE, +365 blocks), but its walks pushed the session past
the 20 s wall-clock budget. The default budget keeps the read volume on the live target bounded; raising it is
a cost decision, not a rule change, and is not made here.

Remaining exposure, unchanged by this rule: a window whose `/proc` samples are flat within the resolution (for
example a window that falls entirely on a flat part of a cycle) clears memory growth within its scope, as for any
process ("no growth in the observation window"). A memory symptom ("is it leaking?") always runs the walks.

Pinned by `tests/test_memory_sawtooth.py`.

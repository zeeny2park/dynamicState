# Diagnosis accuracy benchmark (IMP-013)

Ground-truth accuracy of the single entry point `extractor.expert_diagnostic_engine.diagnose(pid, debug_image, symptom)`
on real processes. It replaces self-declared completion: a low score is a valid result and the starting line.

## Run

    python3 benchmarks/diagnosis_accuracy/run_benchmark.py                 # all targets, writes results/<date>-<arch>-<commit>.json
    python3 benchmarks/diagnosis_accuracy/run_benchmark.py --list
    python3 benchmarks/diagnosis_accuracy/run_benchmark.py --only deadlock_pipeline spin_flag --output /tmp/r.json
    python3 benchmarks/diagnosis_accuracy/run_benchmark.py --symptom generic   # every target gets "general health check"

    python3 benchmarks/diagnosis_accuracy/run_benchmark.py --repeat 20 --only spin_yield ok_sawtooth   # repeat-verdict agreement

Needs gcc and permission to read same-user process memory. About 20 s on this host. Exit status is non-zero only if
the runner crashes. Tests of the machinery (not of accuracy): `python3 -m unittest tests/test_diagnosis_accuracy_benchmark.py`.

## Diagnosis time and repeat-verdict agreement (additive; scoring is unchanged)

- Timing, always on. Per row: `diagnose_s` (wall time of the first `diagnose` call, as before) and `checks`, a list of
  `{check_id, recipe_id, name, status, duration_s}` for every executed check, copied from the engine's own
  `checks_run[].duration_s` (no engine change). Top level `timing`: `diagnose_s` {mean, max, n} and `per_check`
  {check_id: {name, mean_s, max_s, n}} sorted slowest first; `host_loadavg` is `os.getloadavg()` at the end of the run.
  Only the checks that ran for a target appear, so `n` differs per check; with `--symptom generic` only the always-run
  default checks (17-18 per target; checks that need tracing, a stopped snapshot or a caller specification are not planned) appear, which is the cleanest view of their cost. Timings depend on host load:
  results files made on a shared host say so in the commit/report, and `host_loadavg` is recorded for that purpose.
- `--repeat N` (default 1 = off, normal run costs the same): the target is built and launched once and `diagnose` is
  called N times against the same live process, one after another. The row is scored from the first run only. Rows then
  carry `repeat` {runs, requested, distribution {verdict: count}, modal_verdict, agreement_rate (share of runs equal to
  the most common verdict, ties to the first seen), diagnose_s [per run]} and `check_runs` (per-run check timings, used for
  the per-check statistics); a run that errors counts as verdict `ERROR`, a hang ends the repetition. Top level
  `repeat_agreement`: `mean_agreement_rate` (mean over scored targets), `pooled_agreement_rate` (modal runs / all runs),
  `fully_agreeing_targets`, and `per_target` (unscored targets listed but not in the overall figures). The results file name
  gets a `-repeatN` suffix. Agreement measures stability of the verdict only, not correctness. Repeated calls on one
  process also exercise the engine against a process it has already been diagnosed on; a fresh process per run is not used.
  Cost: roughly N x the per-target diagnose time (3-15 s each), so 20 repeats of all 21 targets is about 30-60 min.

## Targets

`ground_truth/<id>.json` + a C source (`targets/` or, for `origin: project_fixture`, `tests/fixtures/real_runtime/`).
Each record holds: defect kind or `none`, cause names (variables, locks, threads, functions), `file:line` of the defect,
the symptom text, `origin` (`project_fixture`, `external_style`, `new`) and `naming` (`neutral`, `project`).
New programs print `READY` once in the faulty steady state and stay alive; reused fixtures use a fixed settle time.
Heap-corruption targets do the bad write (or the second free) once, then idle without calling malloc/free again.

21 scored defect targets (memory_leak 3, heap_overflow 2, use_after_free 2, double_free 2, deadlock 2, busy_wait 2,
mapping_growth 2: `mapgrow_slabs` mmap()s without munmap, `mapgrow_pool` a custom region pool; orphan_lock 2,
self_deadlock 2, thread_growth 2: `accept_workers`, `request_threads`), 6 unscored targets (`long_stall`: `stall_pipe`,
`stall_sleep`; `heap_retention`: `frag_sparse`, `frag_worker`; `lock_contention`: `lock_convoy`, `lock_hotspot`), 8 healthy controls, 4 `external_style` (small LRU cache,
ring buffer, job queue, message outbox written in a neutral style). The `double_free` targets leave states glibc's own
checks let through: `dfree_outbox` a fastbin cycle (free a, free b, free a with the size's tcache full), `dfree_reqbuf`
one block on the tcache and the unsorted bin (freed while the tcache was full, tcache drained, freed again). For
`double_free` and `thread_growth` the `file:line` (the free / pthread_create calls) is not expected to match: which code
made the call is not observable from memory.

## Scoring (per target, one `diagnose` call)

- Unscored targets: a ground-truth record with `"scored": false` (and a mandatory `"scored_reason"`) is still built, run
  and printed, but under a separate "unscored (informational)" heading in the table and an `unscored` section in the
  results JSON (`totals.unscored`; rows carry `"scored": false`). It is excluded from every detection, cause-name,
  location, per-kind/origin/naming, false-positive and error total and rate. The `heap_retention` targets
  (`frag_sparse`, `frag_worker`) are unscored because fragmentation is a degradation, not a defect: the expected answer
  is a `HEAP_RETENTION` finding with a DEGRADED (non-fault) verdict, a HEALTHY verdict on it is not a dangerous miss, and
  neither the defect scoring (HEALTHY = false clear) nor the healthy-control scoring (any finding = false positive) can
  express that. The `lock_contention` targets (`lock_convoy`, `lock_hotspot`) are unscored for the same reason: threads queued
  on a mutex whose owner keeps running are slow, not broken, and the expected answer is a `LOCK_CONTENTION` finding with a
  DEGRADED verdict. The healthy control `ok_contention` (short critical sections, `usleep` between turns) must stay
  HEALTHY: it is scored as any healthy control. The `long_stall` targets (`stall_pipe`, `stall_sleep`) are unscored (owner decision): from outside, a thread blocked forever and an idle worker
  look identical, so the tool deliberately answers "long wait observed, cannot determine whether expected" rather than a
  fault, and counting that as a miss gave no actionable signal. A stall target is defective, so a fault-class verdict on it
  is not a false positive (false positives are defined for healthy controls only); the verdict is just reported.
  `KIND_CATEGORIES` keeps `long_stall`, `heap_retention` and `lock_contention` only to label and describe those rows.

- False clear (defect): a scored defect target whose verdict is `HEALTHY` (the diagnoser told the user "nothing is
  wrong" about a real defect), the most dangerous miss. Counted as `false_clears` in the overall and per-kind totals,
  printed on the healthy totals line next to false positives, and flagged per row as `false_clear`. Unscored targets
  carry the flag but are not counted. There is no threshold or assertion on the real diagnoser; the number is reported.

- Detection (defect): some finding's `category` is in `KIND_CATEGORIES[kind]` (table in `run_benchmark.py`). A fault
  verdict without a matching-category finding is not a detection. `confidence` is never used.
- Healthy control: any fault-class verdict (CONFIRMED_FAULT, PROBABLE_FAULT, FAULT) or any finding is a false positive.
  Any other verdict without findings and not HEALTHY (INCONCLUSIVE, DEGRADED, ABORTED) is counted as "not cleared".
- Cause names: exact, case-sensitive match of ground-truth names against `subjects` of the matching-category findings.
  `full` = all declared variables/locks/threads found (functions only if nothing else is declared); `partial` = some name
  of any class found. Per-class detail is in `names_by_class`.
- Location: a `file:line` subject with the same file name and a line within +-3 of any listed ground-truth location.
- Also recorded: verdict, categories, subjects, `not_covered` kinds, wall time, capture mode, measured stop time;
  `non_zero_stop` flags any non-zero-stop collection. A `diagnose` exception or hang becomes a row with `error`.

## Baseline (2026-11-12, aarch64, commit in file name)

Results files written before the `long_stall` scope change include `long_stall` (2 targets) in the totals, i.e. they say
`/13` defect targets; they are not rewritten. Results from this change on use 11 scored defect targets. The first-score
numbers below are of the old 13-target scoring; rescored on the 11 scored targets the current state is detected 7/11
(deadlock 2/2, busy_wait 2/2, memory_leak 3/3), healthy false positives 0/8.

Symptom from ground truth (`results/2026-11-12-aarch64-6718369.json`): detected 0/13, cause names 0/13, false positives 0,
healthy cleared 0, not cleared 8/8. Every target returns INCONCLUSIVE with no findings. Same code with
`--symptom generic` (`...-generic-symptom.json`): detected 2/13 (both deadlock), cause names 2/13 (`deadlock_pipeline`
location missed: the diagnoser reports the function's first line, 4+ lines from the lock call), healthy not cleared 8/8.
Diagnosis therefore also depends on the symptom wording ("the service stopped responding" is INCONCLUSIVE on a real
deadlock, "the process hangs" is not).

## Rule

IMP-007 ... IMP-011 count as complete only when their defect kind passes cause-name match (`full`) here, on the
`external_style` and neutral-naming targets as well as project fixtures, with no increase in healthy false positives.
`long_stall` is unscored and gates nothing; the stall targets must only keep running without a crash or hang.

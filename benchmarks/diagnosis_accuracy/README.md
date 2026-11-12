# Diagnosis accuracy benchmark (IMP-013)

Ground-truth accuracy of the single entry point `extractor.expert_diagnostic_engine.diagnose(pid, debug_image, symptom)`
on real processes. It replaces self-declared completion: a low score is a valid result and the starting line.

## Run

    python3 benchmarks/diagnosis_accuracy/run_benchmark.py                 # all targets, writes results/<date>-<arch>-<commit>.json
    python3 benchmarks/diagnosis_accuracy/run_benchmark.py --list
    python3 benchmarks/diagnosis_accuracy/run_benchmark.py --only deadlock_pipeline spin_flag --output /tmp/r.json
    python3 benchmarks/diagnosis_accuracy/run_benchmark.py --symptom generic   # every target gets "general health check"

Needs gcc and permission to read same-user process memory. About 20 s on this host. Exit status is non-zero only if
the runner crashes. Tests of the machinery (not of accuracy): `python3 -m unittest tests/test_diagnosis_accuracy_benchmark.py`.

## Targets

`ground_truth/<id>.json` + a C source (`targets/` or, for `origin: project_fixture`, `tests/fixtures/real_runtime/`).
Each record holds: defect kind or `none`, cause names (variables, locks, threads, functions), `file:line` of the defect,
the symptom text, `origin` (`project_fixture`, `external_style`, `new`) and `naming` (`neutral`, `project`).
New programs print `READY` once in the faulty steady state and stay alive; reused fixtures use a fixed settle time.
Heap-corruption targets do the bad write once, then idle without calling malloc/free again.

13 defect targets (memory_leak 3, heap_overflow 2, use_after_free 2, deadlock 2, busy_wait 2, long_stall 2),
8 healthy controls, 3 `external_style` (small LRU cache, ring buffer, job queue written in a neutral style).

## Scoring (per target, one `diagnose` call)

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

Symptom from ground truth (`results/2026-11-12-aarch64-6718369.json`): detected 0/13, cause names 0/13, false positives 0,
healthy cleared 0, not cleared 8/8. Every target returns INCONCLUSIVE with no findings. Same code with
`--symptom generic` (`...-generic-symptom.json`): detected 2/13 (both deadlock), cause names 2/13 (`deadlock_pipeline`
location missed: the diagnoser reports the function's first line, 4+ lines from the lock call), healthy not cleared 8/8.
Diagnosis therefore also depends on the symptom wording ("the service stopped responding" is INCONCLUSIVE on a real
deadlock, "the process hangs" is not).

## Rule

IMP-007 ... IMP-011 count as complete only when their defect kind passes cause-name match (`full`) here, on the
`external_style` and neutral-naming targets as well as project fixtures, with no increase in healthy false positives.

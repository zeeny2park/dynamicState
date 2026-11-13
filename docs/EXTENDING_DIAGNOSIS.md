# Adding a diagnosis

A new diagnosis is one file in `extractor/recipe_plugins/`. Every module in that package is imported when
`extractor.diagnostic_recipes` loads; nothing else needs editing. `fd_leak.py` is the reference example.

| Step | What you write | Registered with |
| :--- | :--- | :--- |
| 1. Collect | `collect_x(provider, ctx)`: read the target (zero-stop, read-only) and put the result in `ctx["observation_data"]["x"]`. Skip this step when an existing observation kind already carries the data. | `runtime_evidence_provider.register_observation_collector("x", collect_x)` |
| 2. Decide | `x_rule(recipe, data) -> RecipeEvaluationResult`: SUPPORTED (problem found), CONTRADICTED (looked, nothing there) or INSUFFICIENT_EVIDENCE. Put the names of the cause in the result (see `fd_leak_rule`). | `diagnostic_recipes.register_recipe(DiagnosticRecipe(..., observations=("x",), rule=x_rule), baseline=..., category=...)` |
| 3. Explain | The plain name of the category and the check-list entry (en, ko), and optionally the summary sentences. | `report_registry.register_category`, `register_recipe_label`, `register_finding_text` |
| 4. Draw | Optionally a picture for the HTML report: `x_viz(lx, finding, report, uid) -> html`. | `report_registry.register_finding_viz` |

Rules:

- `baseline=True` runs the check in every diagnosis: it must be cheap, read-only and zero-stop, and it must be able
  to return CONTRADICTED on a healthy process, because a baseline check that cannot decide blocks a HEALTHY verdict.
- A rule decides only from what was observed. Not enough evidence is INSUFFICIENT_EVIDENCE, never CONTRADICTED.
- A SUPPORTED result is a fault finding unless its details say otherwise: `certainty_cap: "PROBABLE"` caps it at
  probable, `finding_severity: "WARNING"` makes it a warning, and `finding_severity: "INFO"` marks a degradation that is
  not a fault (e.g. `heap_retention.py`): when every finding of a diagnosis is INFO, the verdict is DEGRADED.
- The first entry of `applicable_problem_categories` is the category of the check's evidence (also of its
  CONTRADICTED facts); further entries only make the planner select the recipe for those symptom categories.
- Text and pictures show only values present in the evidence. Mark what is reconstructed (`chip(lx, "rec")`) or was
  not observed (`chip(lx, "no")`). Escape every value from the target: use `esc()` / `code()` from
  `extractor.report_visuals`, which also offers `series_chart`, `share_bars`, `facts_list` and `thread_strip`.
- The HTML report contains no script. A picture may use the step classes of `report_visuals` but must not emit
  `<script>` or event-handler attributes.
- Without step 3 and 4 the finding still appears, with the generic text and no picture.

Tests: a unit test of the rule and the presentation on synthetic observations (see `tests/test_report_registry.py`),
and, for a defect kind that should be scored, a target program and ground-truth record under
`benchmarks/diagnosis_accuracy/`.

## Remote targets

A collector must read the target only through `provider.adapter` (`get_proc_maps`, `get_process_status`,
`read_thread_samples`, `read_memory_batch`, `read_target_file`, and `run_ssh` for a host-wide question such as "does tid
N exist"). A direct `open("/proc/<pid>/...")`, `os.listdir` or `os.path.isdir` reads the diagnosing machine, which on a
remote target is another host. Where a collector needs a local fallback it must branch on `adapter.is_remote()` (see
`fd_leak._read_text`, `thread_leak._limits`, `lock_faults._tid_exists`) and, if the remote read is not possible, report
"not read" / "unverified", never the local value.

All seven diagnoses of the second wave work on a remote target (ssh with the collector daemon, or the loopback used in
the tests); none is marked unsupported:

| Diagnosis | Reads, through the adapter | Remote-specific limit |
| :--- | :--- | :--- |
| Orphan lock, self-deadlock | thread table and futex syscall record (`read_thread_samples`, collector THREADS), mutex words (`read_memory`), context switches, owner-tid existence (`run_ssh "[ -d /proc/<tid> ]"`) | the owner-tid check needs the ssh shell; without it the owner is "unverified" and the result is INSUFFICIENT_EVIDENCE |
| Lock contention (degraded) | the same thread rows and mutex words | none beyond the generic remote limits (no TLS, no running-thread stacks) |
| Thread leak | thread-count series and thread rows of the sampler, `limits` and `/proc/sys/kernel/threads-max` via `read_target_file` | a limit that cannot be read is "not read" (the rule then cannot clear on it); 300 threads make a remote window slow |
| Memory growth outside malloc | `get_proc_maps`, `get_process_status`, `read_memory_batch` (chunk headers, typed globals) | none |
| Heap fragmentation / retention (degraded) | `get_proc_maps`, `get_process_status`, heap walk (`read_memory_batch`) | none |
| Double free | heap walk, tcache/fastbin lists, stability re-reads (`read_memory_batch`) | none |

`tests/test_remote_new_diagnoses.py` runs each benchmark target locally and through the collector behind a loopback
transport, compares the findings, and fails when the remote run touches `/proc/<pid>`, one of its tids, or `/proc/sys`
of the diagnosing machine. It cannot show behaviour on a real second host (different clock, latency, shell).

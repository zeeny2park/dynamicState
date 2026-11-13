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
- Text and pictures show only values present in the evidence. Mark what is reconstructed (`chip(lx, "rec")`) or was
  not observed (`chip(lx, "no")`). Escape every value from the target: use `esc()` / `code()` from
  `extractor.report_visuals`, which also offers `series_chart`, `share_bars`, `facts_list` and `thread_strip`.
- The HTML report contains no script. A picture may use the step classes of `report_visuals` but must not emit
  `<script>` or event-handler attributes.
- Without step 3 and 4 the finding still appears, with the generic text and no picture.

Tests: a unit test of the rule and the presentation on synthetic observations (see `tests/test_report_registry.py`),
and, for a defect kind that should be scored, a target program and ground-truth record under
`benchmarks/diagnosis_accuracy/`.

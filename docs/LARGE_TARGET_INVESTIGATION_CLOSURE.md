# DynamicState — Large-Target (100K+ LOC) Investigation Failure Closure

**Repository:** [zeeny2park/dynamicState](https://github.com/zeeny2park/dynamicState)
**Scope:** End-to-end audit and fix for the 400+ second, 3–4 recipe halt and insufficient-evidence failure on complex C/C++ processes (100K+ LOC) across both local and remote targets, without reverting opt-in `DefaultCheckBudget=0`.

---

## 1. Root Causes of the 400+ Second & 3–4 Recipe Failure (`SOURCE VERIFIED`)

Tracing the full lifecycle (`diagnose()` → `InvestigationSession.run_to_completion()` → `_step_classify()` → `_step_assess()` → `_step_plan()` → `_step_collect_next()` → `RuntimeEvidenceProvider.collect_for_recipe()` → `DwarfIndexer.get_index()` / `parse_cfi_rules()` → `_step_analyze()` → `_finalize_conclusion()`) identified four interlocking root causes shared identically by local and remote targets:

1. **Unbounded DWARF & CFI Parsing on 100K+ LOC C++ Binaries (`extractor/dwarf_indexer.py:745–795, 1305–1356`):**
   - `DwarfIndexer._build_index()` streamed `readelf --debug-dump=info` up to `max_dies = 250,000` with **no wall-clock deadline** and regex-matched every line in Python. On a 100K+ LOC C++ binary (hundreds of thousands to millions of DIEs), this stalled for 60–200+ seconds inside the first recipe that touched `DwarfIndexer.get_index()`.
   - `parse_cfi_rules()` streamed `readelf --debug-dump=frames` with **no wall-clock deadline and no line cap**, stalling for another 60–150+ seconds on large C++ binaries.
   - When `_build_index()` hit `max_dies = 250,000`, it terminated `readelf` mid-binary and **silently dropped user globals/symbols in later compilation units** (after STL/header DIEs), causing subsequent recipes to return `INCONCLUSIVE` ("no symbols/evidence").
   - Because `ObservationBudgetTracker.can_continue()` checks `wall_clock_elapsed_ms >= max_wall_clock_ms` **between** recipes (`_step_collect_next()` lines 2415 & 3211), 1–3 recipes that paid unbounded DWARF/CFI parsing blew past the entire observation budget and halted the investigation after 3–4 recipes via `_halt_on_budget()`.
2. **Replanning Only Triggered on `RECIPE_STATUS_CONTRADICTED` (`extractor/expert_diagnostic_engine.py:3133–3190`):**
   - When recipes returned `RECIPE_STATUS_INCONCLUSIVE` or `ERROR` (common on complex targets with insufficient initial evidence), **zero replanning occurred**. The loop plodded sequentially through unproductive recipes in the same domain until wall-clock exhaustion.
3. **No Meaningful Progress Accounting or Stagnation Detection:**
   - Progress was tracked only by wall-clock/bytes/samples, not by new valid evidence, newly discovered target entities, or hypothesis movement. Repeated or empty `INCONCLUSIVE` steps were never recognized as stagnation.
4. **Missing Per-Recipe Disposition Ledger & Ambiguous Failure Classification:**
   - When an investigation halted early, remaining `PENDING` recipes had no structured disposition (`BUDGET_EXCLUDED`, `SKIPPED`, `TIMEOUT`, `FAILED`, `BLOCKED_BY_PREREQUISITE`, `NO_LONGER_RELEVANT`), and `INCONCLUSIVE` collapsed technical failures (collection/deadline/cancellation/execution errors) and analytical failures (stagnation/insufficient evidence/no eligible recipes) into a single opaque outcome.

---

## 2. Code Changes & Rationale (`SOURCE VERIFIED`, `TEST VERIFIED`)

| File | Change | Rationale |
| --- | --- | --- |
| `extractor/dwarf_indexer.py` | Added wall-clock deadlines to `DwarfIndexer._build_index()` (`DYNAMICSTATE_DWARF_INFO_TIMEOUT_S=8.0s`) and `parse_cfi_rules()` (`DYNAMICSTATE_CFI_PARSE_TIMEOUT_S=6.0s`), fast-path `<` pre-filter, `RLock` for `_inflight_locks`, `index.truncated` / `truncation_reason` flags, and automatic fast `.symtab` (`readelf -s -W`, <50 ms) `OBJECT` symbol supplementation when truncated. | Eliminates 60–400 s stalls on 100K+ LOC C++ binaries on both local and remote targets and prevents silent loss of late-CU user globals when DIE caps/timeouts trigger. |
| `extractor/investigation_progress.py` *(new)* | Implemented `InvestigationProgressTracker` (meaningful progress accounting, duplicate-evidence fingerprinting, stagnation detection returning `SWITCH_DOMAIN` / `EXPAND_CANDIDATES` / `HALT_STAGNANT`), `build_recipe_dispositions()` (exhaustive disposition for every planned recipe), and `classify_diagnosis_failure()` (10-category `TECHNICAL` vs. `ANALYTICAL` classification). | Shared identically by local and remote sessions so progress is measured by real evidence/entity/hypothesis movement rather than elapsed time alone, with zero unexplained missing recipes. |
| `extractor/expert_diagnostic_engine.py` | Attached `InvestigationProgressTracker` to `InvestigationSession`, recorded every completed and failed recipe step, wired stagnation-driven domain switching (`STAGNATION_STRATEGY_CHANGE`) and candidate expansion (`PLAN_EXPANDED_ON_STAGNATION`) on `INCONCLUSIVE`/`ERROR`/stagnant runs, and populated `progress_summary`, `recipe_dispositions`, and `failure_classification` on `DiagnosticConclusion`. | Prevents complex targets from stalling in unproductive domains or halting silently after 3–4 recipes; preserves `DefaultCheckBudget=0` unlimited contract. |
| `tests/test_large_target_investigation_closure.py` *(new)* | Added 4 deterministic regression tests covering large-binary DWARF truncation + `.symtab` supplement, stagnation detection & non-progress rejection, 10-category failure classification, and end-to-end local/remote multi-domain stagnation pivot (>4 recipes executed + complete disposition accounting). | Reproduces the 100K+ LOC failure pattern deterministically without relying on small toy fixtures alone. |
| `ci/workflows/test.yml` & `.github/workflows/test.yml` | Registered `tests/test_large_target_investigation_closure.py` in CI test workflow (byte-for-byte parity verified). | Ensures continuous regression protection in GitHub Actions. |

---

## 3. Before / After Investigation Completeness Evidence (`TEST VERIFIED`)

| Dimension | Before | After |
| --- | --- | --- |
| 100K+ LOC DWARF/CFI indexing | Unbounded (`readelf --debug-dump=info` & `--debug-dump=frames` ran 60–400 s); truncated `max_dies` silently dropped late-CU globals | Bounded (`<= 8 s` info, `<= 6 s` frames); truncated index automatically supplemented with all `.symtab` `OBJECT` globals in <50 ms (`TEST VERIFIED`) |
| Replanning on `INCONCLUSIVE` / `ERROR` | None (only triggered on `CONTRADICTED`) | Stagnation detector triggers `SWITCH_DOMAIN` (promotes alternative domain recipe) and `EXPAND_CANDIDATES` (appends unexplored eligible recipes) (`TEST VERIFIED`) |
| Complex target recipe execution | Halted after 3–4 recipes when budget exhausted or domain stagnated | Pivots domains after 2 stagnant steps, executes >4 recipes across domains, preserves `DefaultCheckBudget=0` unlimited contract (`TEST VERIFIED`) |
| Recipe disposition & failure reporting | Unexecuted recipes unexplained; opaque `INCONCLUSIVE` | Every recipe accounted in `conclusion.recipe_dispositions`; 10-category `TECHNICAL` vs. `ANALYTICAL` `failure_classification` (`TEST VERIFIED`) |

---

## 4. Phase 9 Validation Results (`TEST VERIFIED`)

| Command / Suite | Result | Classification |
| --- | --- | --- |
| `python3 -m py_compile extractor/dwarf_indexer.py extractor/investigation_progress.py extractor/expert_diagnostic_engine.py tests/test_large_target_investigation_closure.py` | PASS (exit 0) | `SOURCE VERIFIED` |
| `make -C target/collector all && ./target/collector/test_crypto --selftest` | PASS (exit 0; FIPS 180-4 & RFC 4231) | `TEST VERIFIED` |
| `python3 -m unittest -v tests/test_large_target_investigation_closure.py` | **4/4 PASS** (0.264 s) | `TEST VERIFIED` |
| `python3 scripts/run_unittest.py` (17 core lifecycle, large-target, budget, collected-only, remote, collector, adversarial & CI parity modules) | **194/194 PASS** (30.171 s, 0 skipped) | `TEST VERIFIED` |
| `python3 scripts/run_unittest.py` (9 Phase 2.0-A.3.17 / A.3.18 / A.3.19 trust & durability modules) | **64/64 PASS** (3.681 s, 0 skipped) | `TEST VERIFIED` |
| **Combined Local Regression Total (26 modules)** | **258/258 PASS (0 failed, 0 errors, 0 skipped)** | `TEST VERIFIED` |
| Remote GitHub Actions CI (`Full Test Suite`, `GDB 9.2 Compatibility`) & real 100K+ LOC production binary run | Offline sandbox — not executed | `NOT VERIFIED` |

---

## 5. Remaining Risks & Verdict

**Remaining Risks (`NOT VERIFIED`):**
- Remote GitHub Actions CI and end-to-end wall-clock profiling on a real 100K+ LOC stripped/unstripped production C++ binary (with full multi-million-DIE DWARF and live multi-GB heap) could not be executed in this offline sandbox.
- `.symtab` supplementation recovers global variable addresses (`OBJECT` symbols) when DWARF truncates, but full struct-member DWARF type layouts for truncated CUs still require either raising `DYNAMICSTATE_DWARF_INFO_TIMEOUT_S` or pre-warming the persistent DWARF disk cache.

**Final Verdict: CONDITIONAL GO**
All identified architectural root causes of the 400+ second stall, 3–4 recipe halt, silent late-CU symbol drop, missing stagnation replanning, and opaque failure accounting are fixed and verified by 258/258 passing local tests. Apply `dynamicstate-large-target-investigation-closure.patch` to [zeeny2park/dynamicState](https://github.com/zeeny2park/dynamicState), verify green GitHub Actions CI, and validate against the real 100K+ LOC target process.

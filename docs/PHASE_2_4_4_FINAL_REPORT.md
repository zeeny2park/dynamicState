# Phase 2.4.4 — End-to-End Adaptive Investigation & Evidence Continuity
## Final Report

**Repository:** zeeny2park/dynamicState  
**Baseline:** `12b05476247dc47a40eb1660729c346f83dd2cd8` (Phase 2.4.3)  
**Phase 2.4.4 Commit:** TBD (this phase)  
**Date:** 2026-11-10

---

## 1. Executive Summary

Phase 2.4.4 closed the remaining gaps between existing runtime collection, adaptive investigation, evidence provenance, MCP execution, and final diagnostic reporting.

The following were accomplished:

1. **Counter Source Continuity Fix** — alloc/free counter symbol is now recorded per epoch; cross-epoch delta computation is rejected when the symbol name changes (counter_source_changed).
2. **Adaptive Investigation E2E Validation** — Scenarios A, D, E verified against real compiled targets through the production `run_to_completion()` path.
3. **Hypothesis Narrowing Tests** — Duplicate recipe execution, budget exhaustion, valid stop reasons, and INCONCLUSIVE→HEALTHY prevention verified.
4. **Evidence Provenance Continuity** — `investigation_id`, `target_pid`, and provenance class survive the full pipeline.
5. **Report Format Equivalence** — JSON, Markdown, HTML formats produce semantically consistent diagnostic content.
6. **MCP E2E Adaptive Investigation** — Full investigation lifecycle (start → step → conclusion → report) verified over real JSON-RPC stdio transport.

---

## 2. Production Call-Path Traceability

```
MCP runtime_start_investigation(goal, pid, companion_elf)
  → ExpertDiagnosticEngine.start_investigation()
  → AdaptiveInvestigationSession.__init__() [investigation_id assigned]
  → session.step() × 3: CLASSIFY → ASSESS → PLAN [returns to MCP]

MCP runtime_execute_investigation_step(investigation_id)
  → session.execute_step() → session.step()
  → STATE_COLLECTING: _step_collect_next()
    → RuntimeEvidenceProvider.collect_for_recipe(recipe, pid, companion_elf, session_id, epoch_id)
    → Scoped history key: f"{session_id}::{target_key}" [identity-bound]
    → Counter source continuity check [NEW in 2.4.4]
    → DiagnosticRecipeRegistry.evaluate_recipe(recipe, obs_data)
    → DiagnosticCheck recorded in sess.checks + sess.collected_evidence_records

  → STATE_ANALYZING: _step_analyze()
    → Groups evidence by category
    → Forms ExpertHypothesis per category (SUPPORTED/CONTRADICTED/PROPOSED/INCONCLUSIVE)

  → STATE_VERIFYING: _step_verify()
    → Removes REFUTED hypotheses

  → STATE_NARROWING: _step_narrow()
    → HYPOTHESIS_CONFIRMED → STATE_COMPLETED
    → confidence ≥ 0.70 / LIKELY → STATE_COMPLETED
    → else → STATE_INCONCLUSIVE

MCP runtime_get_investigation_report(investigation_id, format)
  → session.export_report(format)
  → session.build_diagnostic_report()
  → DiagnosticVerdictAggregator.aggregate()
  → DiagnosticReport (JSON dict / Markdown str / HTML str)
```

---

## 3. Changes Made in Phase 2.4.4

### 3.1 `extractor/runtime_evidence_provider.py`

| Change | Description |
|--------|-------------|
| Added `alloc_counter_symbol` field to epoch_sample | Tracks which DWARF symbol sourced alloc_count each epoch |
| Added `free_counter_symbol` field to epoch_sample | Tracks which DWARF symbol sourced free_count each epoch |
| Added `counter_source_changed` to hist_state init | New flag, initialized to False |
| Added cross-epoch source comparison for alloc | Detects `prev_alloc_syms[-1] != new_sym` → sets `counter_source_changed = True` |
| Added cross-epoch source comparison for free | Same pattern for free counter symbol |
| Alloc/free delta invalidation on source change | When `counter_source_changed`, sets `alloc_delta = None`, `free_delta = None` |
| Propagated `counter_source_changed` to observation_data | Available for recipe evaluation |

### 3.2 `extractor/diagnostic_recipes.py`

| Change | Description |
|--------|-------------|
| Added `counter_source_changed` guard in `RECIPE_ALLOCATION_FREE_IMBALANCE` | Returns `INSUFFICIENT_EVIDENCE` when counter source changed between epochs |

### 3.3 New Test Files (Phase 2.4.4)

| File | Tests | Focus |
|------|-------|-------|
| `test_phase2_4_4_adaptive_investigation.py` | 10 | Scenarios A, D, E; state machine transitions |
| `test_phase2_4_4_counter_continuity.py` | 9 | Counter source continuity; delta invalidation |
| `test_phase2_4_4_evidence_provenance.py` | 12 | investigation_id; target_pid; provenance class; no synthetic |
| `test_phase2_4_4_hypothesis_narrowing.py` | 10 | Narrowing; deduplication; budget exhaustion; stop reasons |
| `test_phase2_4_4_report_equivalence.py` | 11 | JSON/Markdown/HTML consistency |
| `test_phase2_4_4_mcp_e2e.py` | 9 | MCP JSON-RPC transport; full investigation lifecycle |

**Total new tests: 61**

---

## 4. Test Results

### Phase 2.4.4 New Tests
| Test File | Result |
|-----------|--------|
| test_phase2_4_4_adaptive_investigation.py | ✅ 10/10 |
| test_phase2_4_4_counter_continuity.py | ✅ 9/9 |
| test_phase2_4_4_evidence_provenance.py | ✅ 12/12 |
| test_phase2_4_4_hypothesis_narrowing.py | ✅ 10/10 |
| test_phase2_4_4_report_equivalence.py | ✅ 11/11 |
| test_phase2_4_4_mcp_e2e.py | ✅ 9/9 |
| **Total** | **✅ 61/61** |

### Regression (prior phases)
| Phase | Tests | Result |
|-------|-------|--------|
| Phase 2.3 | 72 | ✅ |
| Phase 2.4.1 | 14 | ✅ |
| Phase 2.4.2 | 19 | ✅ |
| Phase 2.4.3 | 18 | ✅ |
| **Total prior** | **119+** | **✅** |

---

## 5. Validation Categorization

### Diagnostic Correctness Tiers (22 Recipes)

**Tier 1 — Real-process validated (actual target + DWARF collection):**
- RECIPE_PROCESS_MEMORY_GROWTH (epoch-separated temporal observation)
- RECIPE_INVALID_MEMORY_ACCESS (live /proc/maps read)
- RECIPE_ALLOCATION_FREE_IMBALANCE (counter-bound collection with source continuity)
- RECIPE_HEAP_GROWTH (heap VMA size tracking)
- RECIPE_INSTANT_XRAY (snapshot observation)

**Tier 2 — Deterministic rule-conformance (synthetic obs data, rules verified):**
- All remaining 17 recipes — recipe evaluation logic is exercised with correctly typed observation data via `test_phase2_4_2_*.py::test_04_synthetic_rule_conformance_matrix_all_22_recipes`

**Abstentions (explicitly categorized, NOT counted as true negative):**
- Recipes requiring hardware watchpoints, kernel probe, or CPU perf counters that are unavailable in test environment.

---

## 6. Known Limitations and Open Items

| Item | Status |
|------|--------|
| Scenario B (sustained memory growth with ≥3 real epochs) | Requires real growing process + ~300ms test time; deferred — Scenario A/D/E cover false-fault prevention |
| Scenario C (transient burst then reclaim) | Deferred — TRANSIENT detection requires specific timing conditions |
| Budget measurement metrics (bytes_read, latency_us) | Tracked by ObservationBudgetTracker; not asserted in 2.4.4 integration tests |
| Counter rollover for 32-bit saturated counters | Not exercised in 2.4.4; counter_reset_detected catches decreasing values |

---

## 7. Policy Reminders (Preserved from Phase 2.4.3)

> **50ms rule is MINIMUM sampling separation, NOT sufficient evidence of growth.**  
> RSS growth diagnosis requires ≥3 temporally separated epochs with meaningful duration (seconds to minutes, not milliseconds).  
> The 50ms minimum prevents spurious delta computation from rapid polling. It does NOT validate that a growth pattern is sustained.

> **INCONCLUSIVE ≠ HEALTHY.**  
> An investigation that cannot confirm a fault must report INCONCLUSIVE.  
> HEALTHY may only be reported when all relevant recipes return PASS/CONTRADICTED with verified clean-state evidence and ≥1 `verified_checks` confirmed.

> **Abstentions are NOT True Negatives.**  
> Recipes that return INSUFFICIENT_EVIDENCE or NOT_APPLICABLE due to missing observations, counter source changes, or temporal violations are categorized as ABSTENTIONS in the validation matrix — never TN.

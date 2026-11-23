"""Deterministic large-target (100K+ LOC pattern) investigation regression tests.

Covers Phases 3–8:
- Bounded DWARF/CFI indexing + fast .symtab supplement when max_dies/timeout truncates
- Meaningful progress accounting (repeated/empty recipes never masquerade as progress)
- Stagnation detection triggering domain pivot (SWITCH_DOMAIN) and plan expansion (EXPAND_CANDIDATES)
- Complex multi-stage target does NOT halt after 3-4 recipes when viable paths remain
- Exhaustive per-recipe disposition accounting (zero unexplained absences)
- Truthful 10-category technical vs. analytical failure classification
- Local & remote parity and DefaultCheckBudget=0 unlimited contract
"""

import math
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from extractor.check_budget import DefaultCheckBudget
from extractor.dwarf_indexer import DwarfIndexer
from extractor.expert_diagnostic_engine import (
    ExpertDiagnosticEngine,
    InvestigationPlan,
    InvestigationStep,
)
from extractor.investigation_progress import (
    ANALYTICAL_FAILURE_CATEGORIES,
    FAIL_CANCELLATION,
    FAIL_COLLECTION,
    FAIL_DEADLINE_EXPIRATION,
    FAIL_EVIDENCE_INSUFFICIENCY,
    FAIL_FINALIZATION,
    FAIL_HYPOTHESIS_VERIFICATION,
    FAIL_NO_ELIGIBLE_RECIPES,
    FAIL_PLANNING,
    FAIL_RECIPE_EXECUTION,
    FAIL_STAGNATION,
    TECHNICAL_FAILURE_CATEGORIES,
    InvestigationProgressTracker,
    build_recipe_dispositions,
    classify_diagnosis_failure,
)
from extractor.target_adapter import LocalTargetAdapter, RemoteSshTargetAdapter


class TestLargeTargetInvestigationClosure(unittest.TestCase):
    def test_dwarf_truncation_supplements_late_cu_globals_from_fast_symtab(self):
        if not (shutil.which("gcc") and shutil.which("readelf")):
            self.skipTest("gcc and readelf required")
        with tempfile.TemporaryDirectory() as td:
            src = os.path.join(td, "big_app.c")
            exe = os.path.join(td, "big_app")
            # Model many functions + late-CU globals that would be dropped when max_dies triggers early
            lines = ["#include <stdint.h>\n"]
            for i in range(40):
                lines.append(f"int helper_fn_{i}(int x) {{ return x + {i}; }}\n")
            lines.append("volatile uint64_t g_late_cu_counter = 0x12345678ULL;\n")
            lines.append("volatile uint64_t g_late_cu_lock_state = 1ULL;\n")
            lines.append("int main(void) { return (int)(helper_fn_0(1) + g_late_cu_counter + g_late_cu_lock_state); }\n")
            with open(src, "w", encoding="utf-8") as fh:
                fh.writelines(lines)
            subprocess.run(["gcc", "-g", "-O0", src, "-o", exe], check=True)

            DwarfIndexer._cache.clear()
            # Force early DIE truncation (simulating 100K+ LOC binary hitting max_dies)
            with mock.patch.dict(os.environ, {"DYNAMICSTATE_MAX_DWARF_DIES": "12"}):
                idx = DwarfIndexer.get_index(exe, use_disk_cache=False)
            self.assertTrue(idx.truncated)
            self.assertEqual(idx.truncation_reason, "max_dies_12")
            # Late-CU globals MUST still be present via fast .symtab supplement!
            self.assertIn("g_late_cu_counter", idx.variables_by_name)
            self.assertIn("g_late_cu_lock_state", idx.variables_by_name)
            self.assertGreater(idx.variables_by_name["g_late_cu_counter"][0].link_time_address, 0)

    def test_progress_tracker_detects_stagnation_and_rejects_repeated_empty_work_as_progress(self):
        trk = InvestigationProgressTracker(stagnation_threshold=3)

        # 3 consecutive INCONCLUSIVE/repeated steps with identical/empty evidence -> NOT progress!
        r1 = trk.record_step(recipe_id="RECIPE_A", domain="CONCURRENCY", eval_status="INCONCLUSIVE", evidence_items=[{"k": 1}])
        r2 = trk.record_step(recipe_id="RECIPE_A", domain="CONCURRENCY", eval_status="INCONCLUSIVE", evidence_items=[{"k": 1}])
        r3 = trk.record_step(recipe_id="RECIPE_B", domain="CONCURRENCY", eval_status="ERROR", error="read failed")
        self.assertFalse(r1["made_progress"])
        self.assertFalse(r2["made_progress"])
        self.assertFalse(r3["made_progress"])
        self.assertEqual(trk.recipes_repeated, 1)
        self.assertEqual(trk.recipes_failed, 1)

        # Should recommend SWITCH_DOMAIN when another domain exists
        sig1 = trk.detect_stagnation(remaining_domains=["CONCURRENCY", "MEMORY_GROWTH"], unplanned_eligible_count=2)
        self.assertTrue(sig1.is_stagnant)
        self.assertEqual(sig1.recommended_action, "SWITCH_DOMAIN")

        # Should recommend EXPAND_CANDIDATES when remaining domains are empty but unplanned recipes exist
        sig2 = trk.detect_stagnation(remaining_domains=[], unplanned_eligible_count=3)
        self.assertTrue(sig2.is_stagnant)
        self.assertEqual(sig2.recommended_action, "EXPAND_CANDIDATES")

        # Should recommend HALT_STAGNANT when no alternatives remain
        sig3 = trk.detect_stagnation(remaining_domains=[], unplanned_eligible_count=0)
        self.assertTrue(sig3.is_stagnant)
        self.assertEqual(sig3.recommended_action, "HALT_STAGNANT")

        # Genuine new evidence + verdict resets stagnation streak
        r4 = trk.record_step(
            recipe_id="RECIPE_C",
            domain="MEMORY_GROWTH",
            eval_status="SUPPORTED",
            evidence_items=[{"leak_symbol": "cache_entries", "growth_kb": 4096}],
            discovered_entities=["cache_entries"],
            hypotheses_delta={"strengthened": 1},
        )
        self.assertTrue(r4["made_progress"])
        sig4 = trk.detect_stagnation(remaining_domains=["MEMORY_GROWTH"])
        self.assertFalse(sig4.is_stagnant)
        self.assertEqual(sig4.recommended_action, "CONTINUE")

    def test_failure_classification_distinguishes_all_10_technical_and_analytical_categories(self):
        disp_exec = [{"recipe_id": "R1", "domain": "D1", "step_status": "COMPLETED", "disposition": "EXECUTED_INCONCLUSIVE", "reason": "no data"}]
        disp_fail = [{"recipe_id": "R1", "domain": "D1", "step_status": "FAILED", "disposition": "FAILED", "reason": "boom"}]

        cases = [
            ("CANCELLED", disp_exec, None, FAIL_CANCELLATION, "TECHNICAL"),
            ("REMOTE_CONNECTION_LOST", disp_exec, None, FAIL_COLLECTION, "TECHNICAL"),
            ("BUDGET_EXHAUSTED", disp_exec, None, FAIL_DEADLINE_EXPIRATION, "TECHNICAL"),
            ("PLAN_FAILED", disp_exec, None, FAIL_PLANNING, "TECHNICAL"),
            ("NO_RECIPES", [], None, FAIL_NO_ELIGIBLE_RECIPES, "ANALYTICAL"),
            ("STAGNATION_HALT", disp_exec, {"last_stagnation": {"is_stagnant": True, "recommended_action": "HALT_STAGNANT"}}, FAIL_STAGNATION, "ANALYTICAL"),
            ("COMPLETED", disp_fail, None, FAIL_RECIPE_EXECUTION, "TECHNICAL"),
            ("FINALIZATION_ERROR", disp_exec, None, FAIL_FINALIZATION, "TECHNICAL"),
            ("VERIFICATION_FAILED", disp_exec, None, FAIL_HYPOTHESIS_VERIFICATION, "ANALYTICAL"),
            ("COMPLETED", disp_exec, None, FAIL_EVIDENCE_INSUFFICIENCY, "ANALYTICAL"),
        ]
        for sr, disps, prog, exp_cat, exp_kind in cases:
            fc = classify_diagnosis_failure(
                verdict="INCONCLUSIVE",
                stop_reason=sr,
                dispositions=disps,
                progress=prog,
                evidence_count=0,
            )
            self.assertIsNotNone(fc)
            self.assertEqual(fc["category"], exp_cat)
            self.assertEqual(fc["kind"], exp_kind)
            if exp_kind == "TECHNICAL":
                self.assertIn(exp_cat, TECHNICAL_FAILURE_CATEGORIES)
            else:
                self.assertIn(exp_cat, ANALYTICAL_FAILURE_CATEGORIES)

        # HEALTHY and CONFIRMED_FAULT have no failure classification
        self.assertIsNone(classify_diagnosis_failure(verdict="HEALTHY", stop_reason="COMPLETED", dispositions=disp_exec))
        self.assertIsNone(classify_diagnosis_failure(verdict="CONFIRMED_FAULT", stop_reason="CONFIRMED", dispositions=disp_exec))

    def test_complex_target_pivots_domain_on_stagnation_exceeds_4_recipes_and_accounts_dispositions(self):
        # Verify both Local and Remote adapters share identical investigation accounting and
        # DefaultCheckBudget=0 remains unlimited (never cuts off at 3-4 recipes).
        dcb = DefaultCheckBudget.resolve()
        self.assertTrue(math.isinf(dcb.total_s) and math.isinf(dcb.per_check_s))

        with tempfile.TemporaryDirectory() as td:
            for mode in ("local", "remote"):
                if mode == "local":
                    ad = LocalTargetAdapter()
                else:
                    ad = RemoteSshTargetAdapter(
                        host="10.0.0.50",
                        command_runner=lambda args, t: (0, "", ""),
                        use_control_master=False,
                    )
                engine = ExpertDiagnosticEngine(corpus_dir=os.path.join(td, mode))
                sess = engine.start_investigation(
                    problem_statement="complex 100K LOC app unresponsive and memory growing",
                    pid=os.getpid(),
                    companion_elf=None,
                    adapter=ad,
                )
                # Build a multi-domain plan with 6 recipes: first 3 in CONCURRENCY (stagnant/failing),
                # followed by 3 in MEMORY_GROWTH / ABNORMAL_STATE.
                plan_steps = [
                    InvestigationStep(step_id="s1", recipe_id="RECIPE_THREAD_STATE_ANOMALIES", recipe_name="T1", category="HANG", domain="CONCURRENCY", rationale="init", cost_score=0.5, safety_score=1.0, expected_info_gain=0.5, multi_factor_score=0.5, priority=1),
                    InvestigationStep(step_id="s2", recipe_id="RECIPE_LONG_RUNNING_BLOCKED_THREADS", recipe_name="T2", category="HANG", domain="CONCURRENCY", rationale="init", cost_score=0.5, safety_score=1.0, expected_info_gain=0.5, multi_factor_score=0.5, priority=2),
                    InvestigationStep(step_id="s3", recipe_id="RECIPE_SUSPICIOUS_LOCK_OWNERSHIP", recipe_name="T3", category="HANG", domain="CONCURRENCY", rationale="init", cost_score=0.5, safety_score=1.0, expected_info_gain=0.5, multi_factor_score=0.5, priority=3),
                    InvestigationStep(step_id="s4", recipe_id="RECIPE_ORPHAN_LOCK", recipe_name="T4", category="HANG", domain="CONCURRENCY", rationale="init", cost_score=0.5, safety_score=1.0, expected_info_gain=0.5, multi_factor_score=0.5, priority=4),
                    InvestigationStep(step_id="s5", recipe_id="RECIPE_PROCESS_MEMORY_GROWTH", recipe_name="M1", category="MEMORY_LEAK", domain="MEMORY_GROWTH", rationale="alt", cost_score=0.5, safety_score=1.0, expected_info_gain=0.5, multi_factor_score=0.5, priority=5),
                    InvestigationStep(step_id="s6", recipe_id="RECIPE_FD_LEAK", recipe_name="F1", category="FD_LEAK", domain="ABNORMAL_STATE", rationale="alt", cost_score=0.5, safety_score=1.0, expected_info_gain=0.5, multi_factor_score=0.5, priority=6),
                ]
                sess.plan = InvestigationPlan(steps=plan_steps, total_steps=len(plan_steps), current_step_index=0, plan_rationale="large target test")
                sess.state = "COLLECTING"

                executed_order = []

                def fake_collect(recipe, **kw):
                    executed_order.append(recipe.recipe_id)
                    if recipe.recipe_id == "RECIPE_THREAD_STATE_ANOMALIES":
                        raise RuntimeError("transient read error on thread stack")
                    if recipe.domain == "CONCURRENCY":
                        return {"bytes_read": 64}, []
                    if recipe.recipe_id == "RECIPE_PROCESS_MEMORY_GROWTH":
                        return {"bytes_read": 128, "rss_history_kb": [10000, 20000, 40000], "epoch_count": 3}, []
                    return {"bytes_read": 64}, []

                sess.evidence_provider.collect_for_recipe = fake_collect
                sess.evidence_provider.has_precollected_data = lambda *a, **kw: False
                if hasattr(sess.adapter, "prefetch_snapshot"):
                    sess.adapter.prefetch_snapshot = lambda *a, **kw: None
                if hasattr(sess.adapter, "begin_capture_transaction"):
                    sess.adapter.begin_capture_transaction = lambda **kw: None

                conclusion = sess.run_to_completion(max_steps=40)

                # Must execute > 4 recipes (never prematurely halted at 3-4!)
                self.assertGreaterEqual(len(executed_order), 5, f"{mode}: executed {executed_order}")
                # Stagnation in CONCURRENCY (s1 error + s2 inconclusive) must pivot to MEMORY_GROWTH (s5) BEFORE s3/s4!
                idx_mem = executed_order.index("RECIPE_PROCESS_MEMORY_GROWTH")
                self.assertLess(idx_mem, 4, f"{mode}: stagnation pivot should promote MEMORY_GROWTH early, got {executed_order}")
                # Conclusion must carry complete progress_summary and exhaustive recipe_dispositions
                self.assertIsNotNone(conclusion.progress_summary)
                self.assertGreaterEqual(conclusion.progress_summary["strategy_changes"], 1)
                self.assertGreaterEqual(len(conclusion.recipe_dispositions), 6)
                disp_rids = {d["recipe_id"] for d in conclusion.recipe_dispositions}
                for expected_rid in ("RECIPE_THREAD_STATE_ANOMALIES", "RECIPE_PROCESS_MEMORY_GROWTH", "RECIPE_FD_LEAK"):
                    self.assertIn(expected_rid, disp_rids)


if __name__ == "__main__":
    unittest.main()

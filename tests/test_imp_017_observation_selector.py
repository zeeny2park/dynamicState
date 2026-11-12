"""IMP-017: the discriminating-observation selector (ported from the retired adaptive engine) used by the expert
engine's replanning step."""

import unittest
from types import SimpleNamespace

from extractor.diagnostic_recipes import DiagnosticRecipeRegistry
from extractor.observation_budget import ObservationBudgetLimits, ObservationBudgetTracker
from extractor.observation_selector import estimate_cost, select_discriminating_recipe


def _hyp(hid, status, rules):
    return SimpleNamespace(hypothesis_id=hid, status=status, applicable_diagnostic_rules=rules)


class TestObservationSelector(unittest.TestCase):
    def setUp(self):
        self.reg = DiagnosticRecipeRegistry
        self.heap = self.reg.get_recipe("RECIPE_HEAP_GROWTH")
        self.rss = self.reg.get_recipe("RECIPE_PROCESS_MEMORY_GROWTH")
        self.imb = self.reg.get_recipe("RECIPE_ALLOCATION_FREE_IMBALANCE")

    def test_prefers_the_recipe_that_discriminates_more_hypotheses(self):
        hyps = [_hyp("H1", "SUPPORTED", ["RECIPE_HEAP_GROWTH", "RECIPE_ALLOCATION_FREE_IMBALANCE"]),
                _hyp("H2", "INCONCLUSIVE", ["RECIPE_HEAP_GROWTH"]),
                _hyp("H3", "REFUTED", ["RECIPE_ALLOCATION_FREE_IMBALANCE"])]
        rid, log, why = select_discriminating_recipe(hyps, [self.imb, self.heap])
        self.assertEqual(rid, "RECIPE_HEAP_GROWTH")  # tests H1 and H2; the other only H1 (H3 is settled)
        self.assertIn("RECIPE_ALLOCATION_FREE_IMBALANCE", why)
        self.assertTrue(all("recipe_id" in e for e in log))

    def test_never_reselects_an_executed_recipe_and_skips_settled_hypotheses(self):
        hyps = [_hyp("H1", "SUPPORTED", ["RECIPE_HEAP_GROWTH"])]
        rid, _, _ = select_discriminating_recipe(hyps, [self.heap], executed_recipe_ids={"RECIPE_HEAP_GROWTH"})
        self.assertIsNone(rid)
        rid, _, why = select_discriminating_recipe([_hyp("H1", "CONFIRMED", ["RECIPE_HEAP_GROWTH"])], [self.heap])
        self.assertIsNone(rid)
        self.assertIn("no unresolved", why)

    def test_budget_is_checked_before_selection(self):
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=1024))
        hyps = [_hyp("H1", "SUPPORTED", ["RECIPE_HEAP_GROWTH"])]
        rid, log, _ = select_discriminating_recipe(hyps, [self.heap], budget_tracker=tracker)
        self.assertIsNone(rid)
        self.assertIn("budget", log[0]["rejection_reason"])

    def test_unavailable_observation_kind_is_rejected(self):
        hyps = [_hyp("H1", "SUPPORTED", ["RECIPE_HEAP_GROWTH"])]
        rec = SimpleNamespace(recipe_id="RECIPE_HEAP_GROWTH", observations=("memory_growth", "process_info"))
        rid, log, _ = select_discriminating_recipe(hyps, [rec], capabilities={"memory_growth": False})
        self.assertIsNone(rid)
        self.assertIn("unavailable", log[0]["rejection_reason"])

    def test_cost_comes_from_declared_observations(self):
        self.assertGreater(estimate_cost(["memory_growth", "process_info"])[0], 0)
        self.assertEqual(estimate_cost([]), estimate_cost(["unknown_kind"]))


if __name__ == "__main__":
    unittest.main()

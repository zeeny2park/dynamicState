"""Stage 1: one hypothesis model.

The verified hypotheses of an investigation (ExpertHypothesis, decided by the typed-evidence criteria) are the
source of truth for the final verdict and for the report's competing-hypothesis data.  The competing candidates
(CompetingHypothesis) are views of them: once the hypotheses are verified, a candidate's status / confidence /
basis come from the verified hypothesis that consumed its rules' evidence, everywhere they are read (report
section F, verify_hypothesis, compare_hypotheses, a reloaded session).

Pure unit tests: no target process.
"""

import shutil
import tempfile
import unittest

from extractor.competing_hypotheses import (
    CompetingHypothesis,
    CompetingHypothesisManager,
    candidate_verdict_source,
)
from extractor.expert_diagnostic_engine import AdaptiveInvestigationSession, TargetAssessmentResult
from tests.test_typed_evidence import _evidence_from_recipe


def _session(tmp, evidence, symptom_category):
    s = AdaptiveInvestigationSession(investigation_id="inv_unify_test", problem_statement="test", corpus_dir=tmp)
    s.collected_evidence = evidence
    s.target_assessment = TargetAssessmentResult(
        pid=None, accessible=True, thread_count=1, memory_regions_count=1, rss_kb=1, companion_elf_path=None,
        companion_elf_valid=False, dwarf_available=False, capabilities=[], limitations=[], prerequisites_met=True,
        memory_readable=True)
    s.verified_checks_count = sum(1 for e in evidence if e.get("status") == "CONTRADICTED")
    s.competing_hypotheses = CompetingHypothesisManager.generate_competing_hypotheses_for_symptom(symptom_category)
    s._step_analyze()
    s._step_verify()
    return s


class OneHypothesisModelTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="unify_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _leak_session(self):
        ev = _evidence_from_recipe("RECIPE_HEAP_GROWTH", {"heap_series_kb": [100, 200, 400, 800], "epoch_count": 4}, 0)
        ev += _evidence_from_recipe("RECIPE_ALLOCATION_FREE_IMBALANCE", {"alloc_delta": 400, "free_delta": 2}, 1)
        return _session(self.tmp, ev, "MEMORY_LEAK")

    def test_candidates_take_the_verified_verdict(self):
        s = self._leak_session()
        top = s.active_hypotheses[0]
        self.assertEqual(top.category, "MEMORY_LEAK")
        by_id = {c.hypothesis_id: c for c in s.competing_hypotheses}
        # HEAP_GROWTH and ALLOCATION_FREE_IMBALANCE are rules of these candidates
        for cid in ("HYP_HEAP_ALLOC_LEAK", "HYP_ALLOC_FREE_IMBALANCE"):
            c = by_id[cid]
            self.assertEqual(c.status, top.status, cid)
            self.assertEqual(c.confidence, round(top.confidence, 4), cid)
            self.assertEqual(c.verdict_source["hypothesis_id"], top.hypothesis_id)
            self.assertEqual(c.decision_trace["decision_rule_applied"], "RULE_BOUND_TO_VERIFIED_HYPOTHESIS")
            # re-evaluation (ledger audit) does not move it away from the verified verdict
            self.assertEqual(c.evaluate_verdict(), top.status)
        # a candidate none of whose rules ran is not checked
        self.assertEqual(by_id["HYP_OBJECT_ACCUMULATION"].status, "INCONCLUSIVE")

    def test_every_reader_sees_the_same_verdict(self):
        s = self._leak_session()
        top = s.active_hypotheses[0]
        v = s.verify_hypothesis("HYP_ALLOC_FREE_IMBALANCE")
        self.assertEqual(v["status"], top.status)
        cmp_ = s.compare_hypotheses(["HYP_ALLOC_FREE_IMBALANCE", "HYP_OBJECT_ACCUMULATION"])
        st = {h["hypothesis_id"]: h["status"] for h in cmp_["hypotheses"]}
        self.assertEqual(st["HYP_ALLOC_FREE_IMBALANCE"], top.status)
        ev = s.get_hypothesis_evidence("HYP_HEAP_ALLOC_LEAK")
        self.assertEqual(ev["status"], top.status)
        # persisted and reloaded: re-bound from the verified hypotheses, not from the stored candidate status
        d = s.to_dict()
        for c in d["competing_hypotheses"]:
            c["status"], c["confidence"] = "CONFIRMED", 0.99
            c["verdict_source"] = {"status": "CONFIRMED", "confidence": 0.99}
        r = AdaptiveInvestigationSession.from_dict(d)
        rb = {c.hypothesis_id: c for c in r.competing_hypotheses}
        self.assertEqual(rb["HYP_ALLOC_FREE_IMBALANCE"].status, top.status)
        self.assertEqual(rb["HYP_OBJECT_ACCUMULATION"].status, "INCONCLUSIVE")

    def test_report_section_f_reads_the_same_objects(self):
        s = self._leak_session()
        s._finalize_conclusion(stop_reason="HYPOTHESIS_CONFIRMED", summary="x")
        f = s.build_diagnostic_report().to_dict()["section_f_competing_hypotheses"]
        verified = {h["hypothesis_id"]: h for h in f["hypotheses"]}
        bound = 0
        for c in f["competing_candidates"]:
            src = c.get("verdict_source") or {}
            if src.get("hypothesis_id") in verified and src.get("supporting_evidence_ids"):
                bound += 1
                self.assertEqual(c["status"], verified[src["hypothesis_id"]]["status"], c["hypothesis_id"])
        self.assertGreaterEqual(bound, 2)
        # eliminated alternatives list a candidate only when the verified evidence refuted it
        refuted = {c["hypothesis_id"] for c in f["competing_candidates"] if c["status"] == "REFUTED"}
        listed = {e["hypothesis_id"] for e in f["eliminated_alternatives"]}
        self.assertTrue(refuted <= listed)

    def test_refuted_candidate_and_standalone_candidate(self):
        ev = _evidence_from_recipe("RECIPE_HEAP_GROWTH", {"heap_series_kb": [100, 100, 100], "epoch_count": 3}, 0)
        s = _session(self.tmp, ev, "MEMORY_LEAK")
        by_id = {c.hypothesis_id: c for c in s.competing_hypotheses}
        self.assertEqual(by_id["HYP_HEAP_ALLOC_LEAK"].status, "REFUTED")
        # a stand-alone candidate (no verified hypotheses) keeps its own ledger-authority evaluation
        c = CompetingHypothesis(hypothesis_id="H", category="MEMORY_LEAK", confidence=0.5)
        self.assertEqual(c.verdict_source, {})
        self.assertEqual(candidate_verdict_source(c, [])["status"], "INCONCLUSIVE")


if __name__ == "__main__":
    unittest.main()

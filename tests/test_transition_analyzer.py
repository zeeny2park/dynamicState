"""Unit tests for Phase 5 TransitionAnalyzer."""

import unittest

from extractor.snapshot import StateTransition
from extractor.transition_analyzer import TransitionAnalyzer


class TransitionAnalyzerTests(unittest.TestCase):
    def setUp(self):
        self.analyzer = TransitionAnalyzer()

    def test_analyze_successful_deterministic_transition(self):
        trans = StateTransition(
            transition_id="T001",
            parent_snapshot="S001",
            child_snapshot="S002",
            mutation={
                "success": True,
                "field": "retry",
                "before": 2,
                "after": 3
            },
            execution={
                "status": "STOPPED",
                "reason": "breakpoint"
            },
            diff={
                "summary": {"value_changes": 3},
                "changes": [
                    {"kind": "value_change", "path": "Session.retry", "before": 2, "after": 3},
                    {"kind": "value_change", "path": "Session.state", "before": "CONNECTED", "after": "ERROR"},
                    {"kind": "value_change", "path": "Session.flagged", "before": False, "after": True},
                ]
            }
        )

        agent_trans = self.analyzer.analyze(trans, parent_state="state_000001", child_state="state_000002")

        self.assertEqual(agent_trans.transition_id, "T001")
        self.assertEqual(agent_trans.parent_state, "state_000001")
        self.assertEqual(agent_trans.child_state, "state_000002")

        facts = agent_trans.facts
        self.assertTrue(facts["branch_changed"])
        self.assertFalse(facts["crash"])
        self.assertFalse(facts["timeout"])
        self.assertEqual(facts["field_changed"], ["Session.flagged", "Session.retry", "Session.state"])

        evidence = agent_trans.evidence
        self.assertGreaterEqual(len(evidence), 3)
        obs_texts = [e["observation"] for e in evidence]
        self.assertTrue(any("Session.retry" in t for t in obs_texts))
        self.assertTrue(any("Session.state changed from CONNECTED to ERROR" in t for t in obs_texts))

        self.assertIn("transition_analysis_ms", agent_trans.performance)

    def test_analyze_crash_transition(self):
        trans = StateTransition(
            transition_id="T002",
            parent_snapshot="S001",
            child_snapshot=None,
            mutation={"success": True, "field": "priority", "before": 7, "after": 139},
            execution={"status": "CRASHED", "signal": "SIGSEGV", "reason": "Segmentation fault"},
            diff=None
        )

        agent_trans = self.analyzer.analyze(trans)
        facts = agent_trans.facts
        self.assertTrue(facts["crash"])
        self.assertEqual(facts["crash_signal"], "SIGSEGV")
        self.assertTrue(facts["branch_changed"])

        evidence = agent_trans.evidence
        crash_ev = next(e for e in evidence if e["facts"].get("status") == "CRASHED")
        self.assertIn("SIGSEGV", crash_ev["observation"])

    def test_analyze_timeout_transition(self):
        trans = StateTransition(
            transition_id="T003",
            parent_snapshot="S001",
            child_snapshot=None,
            mutation={"success": True, "field": "priority", "before": 7, "after": 255},
            execution={"status": "TIMEOUT", "reason": "interrupt requested after timeout", "timeout_ms": 1000},
            diff=None
        )

        agent_trans = self.analyzer.analyze(trans)
        facts = agent_trans.facts
        self.assertTrue(facts["timeout"])
        self.assertTrue(facts["branch_changed"])

        evidence = agent_trans.evidence
        timeout_ev = next(e for e in evidence if e["facts"].get("status") == "TIMEOUT")
        self.assertIn("timed out", timeout_ev["observation"])


if __name__ == "__main__":
    unittest.main()

import os
import shutil
import tempfile
import unittest

from extractor.state_corpus import StateCorpus, StateInterestingness
from tests.test_state_hash import make_snapshot


class StateCorpusTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.corpus = StateCorpus(self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_add_and_deduplication(self):
        s1 = make_snapshot(retry=2)
        state_id1, is_new1 = self.corpus.add(s1)
        self.assertTrue(is_new1)
        self.assertEqual(state_id1, "state_000001")

        # Second observation of same state
        s2 = make_snapshot(retry=2, timestamp="2026-09-27T12:00:00Z")
        state_id2, is_new2 = self.corpus.add(s2)
        self.assertFalse(is_new2)
        self.assertEqual(state_id2, state_id1)

        meta = self.corpus.get_metadata(state_id1)
        self.assertIn("S001", meta["observations"])

    def test_get_and_list(self):
        s1 = make_snapshot(retry=2)
        s2 = make_snapshot(retry=3)
        self.corpus.add(s1)
        self.corpus.add(s2)

        states = self.corpus.list()
        self.assertEqual(len(states), 2)
        self.assertEqual(states[0]["state_id"], "state_000001")
        self.assertEqual(states[1]["state_id"], "state_000002")

        data1 = self.corpus.get("state_000001")
        self.assertIsNotNone(data1)
        self.assertEqual(data1["persistent"]["objects"][0]["fields"][0]["value"], 2)

    def test_add_transition(self):
        trans = {
            "transition_id": "T000001",
            "parent_snapshot": "S001",
            "child_snapshot": "S002",
            "execution": {"status": "STOPPED"}
        }
        tid = self.corpus.add_transition(trans)
        self.assertEqual(tid, "T000001")
        self.assertTrue(os.path.isfile(os.path.join(self.corpus.transitions_dir, "T000001.json")))

    def test_interestingness_evaluation(self):
        # Crash transition
        t_crash = {"execution": {"status": "CRASHED", "signal": "SIGSEGV"}}
        res_crash = StateInterestingness.evaluate(None, None, t_crash)
        self.assertTrue(res_crash["interesting"])
        self.assertIn("CRASH", res_crash["reasons"])

        # Timeout transition
        t_timeout = {"execution": {"status": "TIMEOUT"}}
        res_timeout = StateInterestingness.evaluate(None, None, t_timeout)
        self.assertTrue(res_timeout["interesting"])
        self.assertIn("TIMEOUT", res_timeout["reasons"])

        # New state
        t_normal = {"execution": {"status": "STOPPED"}, "diff": {"summary": {"value_changes": 1}}}
        res_new = StateInterestingness.evaluate(None, None, t_normal, is_new_hash=True)
        self.assertTrue(res_new["interesting"])
        self.assertIn("NEW_STATE", res_new["reasons"])
        self.assertIn("VALUE_CHANGE", res_new["reasons"])


if __name__ == "__main__":
    unittest.main()

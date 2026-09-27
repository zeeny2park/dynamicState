import json
import os
import shutil
import tempfile
import unittest

from extractor.explorer import StateExplorer
from extractor.state_corpus import StateCorpus
from tests.test_explorer_branching import BranchingMockController


class ExplorationArtifactTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.controller = BranchingMockController()
        self.corpus = StateCorpus(self.tmpdir)
        self.explorer = StateExplorer(self.controller, self.corpus, self.tmpdir)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_exploration_artifact_generation(self):
        self.explorer.seed()
        artifact = self.explorer.run(max_steps=2)

        eid = artifact["exploration_id"]
        self.assertTrue(eid.startswith("E"))

        # Verify artifact file exists on disk
        artifact_path = os.path.join(self.tmpdir, "explorations", f"{eid}.json")
        self.assertTrue(os.path.isfile(artifact_path), f"Artifact file not found: {artifact_path}")

        with open(artifact_path, encoding="utf-8") as f:
            data = json.load(f)

        self.assertEqual(data["exploration_id"], eid)
        self.assertEqual(data["seed_state_id"], "state_000001")
        self.assertEqual(data["steps"], 2)

        summary = data["summary"]
        self.assertEqual(summary["executed"], 2)
        self.assertIn("new_states", summary)
        self.assertIn("duplicate_states", summary)
        self.assertIn("crashes", summary)
        self.assertIn("timeouts", summary)

        perf = data["performance"]
        self.assertIn("total_time_ms", perf)
        self.assertIn("avg_step_ms", perf)
        self.assertIn("checkpoint_creation_ms", perf)
        self.assertIn("step_metrics", perf)

        step_metrics = perf["step_metrics"]
        self.assertEqual(len(step_metrics), 2)
        for metric in step_metrics:
            self.assertIn("candidate_id", metric)
            self.assertIn("transition_id", metric)
            self.assertIn("restore_ms", metric)
            self.assertIn("step_ms", metric)
            self.assertIn("status", metric)

        # Check index.json in corpus
        index_path = os.path.join(self.tmpdir, "index.json")
        with open(index_path, encoding="utf-8") as f:
            idx = json.load(f)
        self.assertIn(eid, idx.get("explorations", []))


if __name__ == "__main__":
    unittest.main()

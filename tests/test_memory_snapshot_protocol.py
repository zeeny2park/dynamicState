"""Unit tests for Agent Runtime Protocol extensions in Phase 5.1."""

import json
import os
import shutil
import tempfile
import unittest

from extractor.agent_runtime import AgentRuntime


class MemorySnapshotProtocolTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="test_msp_")
        self.agent = AgentRuntime(controller=None, corpus_dir=self.tmp_dir)

        # Load protocol schemas
        schema_path = os.path.join(os.path.dirname(__file__), "..", "protocol", "actions.schema.json")
        with open(schema_path, "r", encoding="utf-8") as f:
            self.actions_schema = json.load(f)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_schema_includes_phase5_1_actions(self):
        actions = self.actions_schema["properties"]["action"]["enum"]
        self.assertIn("MEMORY_SNAPSHOT", actions)
        self.assertIn("ANALYZE_MEMORY_SNAPSHOT", actions)
        self.assertIn("GET_MEMORY_SNAPSHOT", actions)

    def test_dispatch_memory_snapshot_action(self):
        my_pid = os.getpid()
        action_dict = {
            "action": "MEMORY_SNAPSHOT",
            "pid": my_pid,
            "policy": "STACK",
            "memory_snapshot_id": "M_DISPATCH_TEST"
        }
        res = self.agent.dispatch_action(action_dict)
        self.assertTrue(res.success, f"dispatch_action failed: {res.error}")
        self.assertEqual(res.action, "MEMORY_SNAPSHOT")
        self.assertEqual(res.data["snapshot_id"], "M_DISPATCH_TEST")
        self.assertEqual(res.data["pid"], my_pid)

        # Dispatch GET_MEMORY_SNAPSHOT
        get_action = {
            "action": "GET_MEMORY_SNAPSHOT",
            "memory_snapshot_id": "M_DISPATCH_TEST"
        }
        res_get = self.agent.dispatch_action(get_action)
        self.assertTrue(res_get.success)
        self.assertEqual(res_get.data["snapshot_id"], "M_DISPATCH_TEST")

    def test_dispatch_analyze_memory_snapshot_missing_target(self):
        res = self.agent.dispatch_action({"action": "ANALYZE_MEMORY_SNAPSHOT"})
        self.assertFalse(res.success)
        self.assertEqual(res.error.code, "SNAPSHOT_NOT_FOUND")

    def test_dispatch_memory_snapshot_missing_pid(self):
        res = self.agent.dispatch_action({"action": "MEMORY_SNAPSHOT"})
        self.assertFalse(res.success)
        self.assertEqual(res.error.code, "INVALID_FIELD")


if __name__ == "__main__":
    unittest.main()

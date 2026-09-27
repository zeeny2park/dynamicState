"""Unit tests for Low-Impact AgentRuntime integration and safety boundaries."""

import os
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock

from extractor.agent_runtime import AgentRuntime
from extractor.memory_snapshot import RawMemorySnapshot


class LowImpactRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="test_li_runtime_")
        self.agent = AgentRuntime(controller=None, corpus_dir=self.tmp_dir)

    def tearDown(self):
        shutil.rmtree(self.tmp_dir, ignore_errors=True)

    def test_capabilities_includes_low_impact_and_vm_readv(self):
        res = self.agent.capabilities()
        self.assertTrue(res.success)
        caps = res.data
        self.assertIn("observation", caps)
        self.assertIn("memory_snapshot", caps)
        self.assertTrue(caps["observation"]["gdb_consistent"])
        self.assertTrue(caps["observation"]["low_impact_memory_snapshot"])
        self.assertTrue(caps["memory_snapshot"]["process_vm_readv"])

    def test_capture_memory_snapshot_api(self):
        my_pid = os.getpid()
        res = self.agent.capture_memory_snapshot(
            pid=my_pid,
            policy="STACK",
            snapshot_id="M_TEST_API"
        )
        self.assertTrue(res.success, f"Capture failed: {res.error}")
        data = res.data
        self.assertEqual(data["snapshot_id"], "M_TEST_API")
        self.assertEqual(data["pid"], my_pid)
        self.assertGreater(data["bytes_captured"], 0)

        # Retrieve memory snapshot
        res_get = self.agent.get_memory_snapshot("M_TEST_API")
        self.assertTrue(res_get.success)
        self.assertEqual(res_get.data["snapshot_id"], "M_TEST_API")

    def test_safety_boundary_mutation_rejected_in_low_impact_mode(self):
        # Force low-impact observation mode
        self.agent.observation_mode = "LOW_IMPACT"

        # Attempt to execute a transition
        res_trans = self.agent.execute_transition("M0001")
        self.assertFalse(res_trans.success)
        self.assertEqual(res_trans.error.code, "CAPABILITY_UNSUPPORTED")
        self.assertIn("not supported in LOW_IMPACT", res_trans.error.message)

    def test_analyze_memory_snapshot_missing_error(self):
        res = self.agent.analyze_memory_snapshot("M_NONEXISTENT", debug_image="/bin/ls")
        self.assertFalse(res.success)
        self.assertEqual(res.error.code, "SNAPSHOT_NOT_FOUND")


if __name__ == "__main__":
    unittest.main()

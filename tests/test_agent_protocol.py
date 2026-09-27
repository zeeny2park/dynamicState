"""Unit tests for Phase 5 Agent Runtime Protocol schemas and action dispatching."""

import json
import os
import unittest

from extractor.agent_models import AgentAction, AgentActionResult
from extractor.agent_runtime import AgentRuntime


class AgentProtocolTests(unittest.TestCase):
    def setUp(self):
        self.protocol_dir = os.path.join(os.path.dirname(__file__), "..", "protocol")

    def test_schema_files_exist_and_are_valid_json(self):
        schemas = ["actions.schema.json", "results.schema.json", "context.schema.json", "mutations.schema.json"]
        for s in schemas:
            path = os.path.join(self.protocol_dir, s)
            self.assertTrue(os.path.exists(path), f"Missing schema: {s}")
            with open(path) as f:
                data = json.load(f)
                self.assertIn("$schema", data)
                self.assertIn("title", data)

    def test_action_dispatch_unknown_action(self):
        runtime = AgentRuntime(controller=None)
        res = runtime.dispatch_action({"action": "NONEXISTENT_COMMAND"})
        self.assertFalse(res.success)
        self.assertEqual(res.error.code, "CAPABILITY_UNSUPPORTED")

    def test_action_dispatch_malformed_action(self):
        runtime = AgentRuntime(controller=None)
        res = runtime.dispatch_action({"action": "INSPECT_OBJECT"})
        self.assertFalse(res.success)
        self.assertEqual(res.error.code, "INVALID_OBJECT")

    def test_get_capabilities_action(self):
        runtime = AgentRuntime(controller=None)
        res = runtime.dispatch_action({"action": "GET_CAPABILITIES"})
        self.assertTrue(res.success)
        self.assertEqual(res.action, "GET_CAPABILITIES")
        caps = res.data
        self.assertIn("runtime", caps)
        self.assertIn("debug", caps)
        self.assertIn("mutation", caps)
        self.assertIn("limits", caps)
        self.assertTrue(caps["runtime"]["snapshot"])
        self.assertTrue(caps["debug"]["external_debug_image"])

    def test_list_states_action_empty_corpus(self):
        import tempfile
        tmp = tempfile.mkdtemp()
        runtime = AgentRuntime(controller=None, corpus_dir=tmp)
        res = runtime.dispatch_action({"action": "LIST_STATES"})
        self.assertTrue(res.success)
        self.assertEqual(res.action, "LIST_STATES")
        self.assertEqual(res.data, [])


if __name__ == "__main__":
    unittest.main()

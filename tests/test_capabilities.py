import unittest

from extractor.runtime_controller import RuntimeCapabilities, RuntimeController


class CapabilitiesTests(unittest.TestCase):
    def test_default_capabilities(self):
        caps = RuntimeCapabilities()
        d = caps.to_dict()

        self.assertTrue(d["checkpoint"])
        self.assertTrue(d["restore"])
        self.assertTrue(d["typed_mutation"])
        self.assertTrue(d["semantic_snapshot"])
        self.assertTrue(d["semantic_diff"])
        self.assertTrue(d["state_hash"])
        self.assertTrue(d["branch_exploration"])
        self.assertTrue(d["crash_recovery"])
        self.assertTrue(d["timeout_recovery"])
        self.assertTrue(d["external_debug_image"])
        self.assertFalse(d["multi_thread_determinism"])
        self.assertFalse(d["external_io_rollback"])
        self.assertEqual(d["exploration_mode"], "deterministic_single_thread_context")
        self.assertEqual(d["backend"], "generic")

    def test_controller_capabilities(self):
        class DummyController(RuntimeController):
            def observe(self): return None
            def snapshot(self, *a, **k): return None
            def get_object(self, *a): return None
            def get_field(self, *a): return None
            def mutate(self, *a): return None
            def continue_execution(self, *a): return None
            def diff(self, *a): return None
            def execute_transition(self, *a, **k): return None

        controller = DummyController()
        caps = controller.get_capabilities()
        self.assertIn("checkpoint", caps)
        self.assertIn("restore", caps)
        self.assertIn("typed_mutation", caps)
        self.assertIn("exploration_mode", caps)


if __name__ == "__main__":
    unittest.main()

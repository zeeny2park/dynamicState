import unittest

from extractor.state_restorer import MockStateRestorer, RuntimeCheckpoint, StateRestorer


class StateRestorerTests(unittest.TestCase):
    def test_checkpoint_dataclass(self):
        cp = RuntimeCheckpoint(
            checkpoint_id="C001",
            backend="mock",
            metadata={"tag": "seed"}
        )
        d = cp.to_dict()
        self.assertEqual(d["checkpoint_id"], "C001")
        self.assertEqual(d["backend"], "mock")
        self.assertEqual(d["metadata"]["tag"], "seed")

    def test_mock_restorer_checkpoint_and_restore(self):
        current_state = {"retry": 2, "state": "CONNECTED"}

        def capture():
            return dict(current_state)

        def restore(saved):
            current_state.clear()
            current_state.update(saved)

        restorer = MockStateRestorer(capture_fn=capture, restore_fn=restore)

        # 1. Take initial checkpoint C001
        cp1 = restorer.checkpoint("C001")
        self.assertEqual(cp1.checkpoint_id, "C001")
        self.assertIn("C001", restorer.checkpoints)

        # 2. Mutate state
        current_state["retry"] = 99
        self.assertEqual(current_state["retry"], 99)

        # 3. Restore C001
        restorer.restore(cp1)
        self.assertEqual(current_state["retry"], 2)
        self.assertEqual(restorer.restore_count, 1)

        # 4. Mutate state again and restore again
        current_state["retry"] = 55
        restorer.restore(cp1)
        self.assertEqual(current_state["retry"], 2)
        self.assertEqual(restorer.restore_count, 2)

        # 5. Release checkpoint
        restorer.release(cp1)
        self.assertNotIn("C001", restorer.checkpoints)

        with self.assertRaises(RuntimeError):
            restorer.restore(cp1)


if __name__ == "__main__":
    unittest.main()

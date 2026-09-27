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

        with self.assertRaisesRegex(RuntimeError, "CHECKPOINT_NOT_FOUND"):
            restorer.restore(cp1)

    def test_checkpoint_limit_reached(self):
        restorer = MockStateRestorer(max_checkpoints=2)
        cp1 = restorer.checkpoint("C001")
        cp2 = restorer.checkpoint("C002")
        with self.assertRaisesRegex(RuntimeError, "CHECKPOINT_LIMIT_REACHED"):
            restorer.checkpoint("C003")

    def test_checkpoint_not_found(self):
        restorer = MockStateRestorer()
        fake_cp = RuntimeCheckpoint(checkpoint_id="NONEXISTENT", backend="mock", metadata={})
        with self.assertRaisesRegex(RuntimeError, "CHECKPOINT_NOT_FOUND"):
            restorer.restore(fake_cp)
        with self.assertRaisesRegex(RuntimeError, "CHECKPOINT_NOT_FOUND"):
            restorer.release(fake_cp)

    def test_checkpoint_state_invalid(self):
        restorer = MockStateRestorer()
        with self.assertRaisesRegex(RuntimeError, "CHECKPOINT_STATE_INVALID"):
            restorer.restore(None)
        with self.assertRaisesRegex(RuntimeError, "CHECKPOINT_STATE_INVALID"):
            restorer.release(None)

    def test_gdb_restorer_inferior_not_stopped(self):
        class MockThread:
            def is_stopped(self):
                return False

        class MockGdb:
            def selected_thread(self):
                return MockThread()

        from extractor.state_restorer import GdbCheckpointRestorer
        gdb_restorer = GdbCheckpointRestorer(MockGdb())
        with self.assertRaisesRegex(RuntimeError, "CHECKPOINT_STATE_INVALID"):
            gdb_restorer.checkpoint("C001")

    def test_gdb_restorer_checkpoint_parsing_and_flow(self):
        class MockThread:
            def is_stopped(self):
                return True

        class MockGdb:
            def __init__(self):
                self.commands = []
                self._checkpoints = []

            def selected_thread(self):
                return MockThread()

            def execute(self, cmd, to_string=False):
                self.commands.append(cmd)
                if cmd == "info checkpoints":
                    if not self._checkpoints:
                        return "No checkpoints.\n"
                    lines = []
                    for cid in self._checkpoints:
                        lines.append(f"  {cid} process 1234 at 0x4000\n")
                    return "".join(lines)
                elif cmd == "checkpoint":
                    new_id = str(len(self._checkpoints) + 1)
                    self._checkpoints.append(new_id)
                    return f"checkpoint {new_id} created\n"
                elif cmd.startswith("restart "):
                    return ""
                elif cmd.startswith("delete checkpoint "):
                    cid = cmd.split()[-1]
                    if cid in self._checkpoints:
                        self._checkpoints.remove(cid)
                    return ""
                return ""

        from extractor.state_restorer import GdbCheckpointRestorer
        mock_gdb = MockGdb()
        gdb_restorer = GdbCheckpointRestorer(mock_gdb, max_checkpoints=2)

        # Checkpoint creation
        cp = gdb_restorer.checkpoint("C001")
        self.assertEqual(cp.checkpoint_id, "C001")
        self.assertEqual(cp.backend, "gdb_fork")

        # Restore
        gdb_restorer.restore(cp)
        self.assertIn("restart 1", mock_gdb.commands)

        # Release
        gdb_restorer.release(cp)
        self.assertNotIn("C001", gdb_restorer._checkpoints)

        # Limit reached
        mock_gdb._checkpoints.clear()
        gdb_restorer._checkpoints.clear()
        gdb_restorer.checkpoint("C001")
        gdb_restorer.checkpoint("C002")
        with self.assertRaisesRegex(RuntimeError, "CHECKPOINT_LIMIT_REACHED"):
            gdb_restorer.checkpoint("C003")


if __name__ == "__main__":
    unittest.main()


import unittest

from extractor.state_corpus import compute_state_hash


def make_snapshot(retry=2, state="CONNECTED", func="process_packet", pid=100, timestamp="2026-09-27T00:00:00Z"):
    return {
        "schema_version": "0.3",
        "snapshot": {"snapshot_id": "S001", "created_at": timestamp, "pid": pid},
        "execution": {
            "threads": [
                {
                    "thread_id": 1,
                    "frames": [{"level": 0, "function": func, "pc": "0x401000"}]
                }
            ]
        },
        "persistent": {
            "objects": [
                {
                    "object_id": "obj_0001",
                    "type": "Session",
                    "address": "0x1000",
                    "fields": [
                        {"name": "retry", "value": retry, "object_ref": None},
                        {"name": "state", "value": state, "object_ref": None}
                    ]
                }
            ]
        }
    }


class StateHashTests(unittest.TestCase):
    def test_transient_data_ignored_in_state_hash(self):
        s1 = make_snapshot(retry=2, state="CONNECTED", pid=101, timestamp="2026-09-27T10:00:00Z")
        s2 = make_snapshot(retry=2, state="CONNECTED", pid=999, timestamp="2026-09-27T11:00:00Z")
        h1 = compute_state_hash(s1)
        h2 = compute_state_hash(s2)
        self.assertEqual(h1, h2, "State hash should be identical despite different PID and timestamps")

    def test_scalar_value_change_changes_hash(self):
        s1 = make_snapshot(retry=2)
        s2 = make_snapshot(retry=3)
        self.assertNotEqual(compute_state_hash(s1), compute_state_hash(s2))

    def test_execution_frame_change_changes_hash(self):
        s1 = make_snapshot(func="process_packet")
        s2 = make_snapshot(func="handle_error")
        self.assertNotEqual(compute_state_hash(s1), compute_state_hash(s2))


if __name__ == "__main__":
    unittest.main()

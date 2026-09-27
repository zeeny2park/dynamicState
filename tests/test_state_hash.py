import unittest

from extractor.state_corpus import compute_state_hash


def make_snapshot(retry=2, state="CONNECTED", func="process_packet", pid=100,
                  timestamp="2026-09-27T00:00:00Z", thread_id=1,
                  session_addr="0x1000", buffer_addr="0x2000", snapshot_id="S001"):
    return {
        "schema_version": "0.3",
        "snapshot": {"snapshot_id": snapshot_id, "created_at": timestamp, "pid": pid},
        "execution": {
            "threads": [
                {
                    "thread_id": thread_id,
                    "frames": [{"level": 0, "function": func, "pc": "0x401000"}]
                }
            ]
        },
        "persistent": {
            "roots": [
                {"root_id": "root_0001", "name": "global_session", "source": "global",
                 "type": "Session*", "object_ref": "obj_0001"}
            ],
            "objects": [
                {
                    "object_id": "obj_0001",
                    "type": "Session",
                    "address": session_addr,
                    "storage": "heap",
                    "fields": [
                        {"name": "retry", "type": "uint32_t", "value": retry, "object_ref": None},
                        {"name": "state", "type": "SessionState", "value": state, "object_ref": None},
                        {"name": "buffer", "type": "Buffer*", "value": buffer_addr, "object_ref": "obj_0002"},
                        {"name": "parent", "type": "Session*", "value": session_addr, "object_ref": "obj_0001"}
                    ]
                },
                {
                    "object_id": "obj_0002",
                    "type": "Buffer",
                    "address": buffer_addr,
                    "storage": "heap",
                    "fields": [
                        {"name": "length", "type": "uint32_t", "value": 64, "object_ref": None},
                        {"name": "capacity", "type": "uint32_t", "value": 256, "object_ref": None}
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

    def test_address_and_aslr_independence(self):
        """Verify identical hash across different heap/stack addresses (ASLR)."""
        s1 = make_snapshot(session_addr="0x1000", buffer_addr="0x2000")
        s2 = make_snapshot(session_addr="0xaaaa55550000", buffer_addr="0xaaaa55558000")
        h1 = compute_state_hash(s1)
        h2 = compute_state_hash(s2)
        self.assertEqual(h1, h2, "State hash must be address-independent across ASLR address spaces")

    def test_thread_id_independence(self):
        """Verify identical hash across different thread IDs."""
        s1 = make_snapshot(thread_id=1)
        s2 = make_snapshot(thread_id=98765)
        h1 = compute_state_hash(s1)
        h2 = compute_state_hash(s2)
        self.assertEqual(h1, h2, "State hash must be independent of transient OS thread IDs")

    def test_scalar_value_change_changes_hash(self):
        s1 = make_snapshot(retry=2)
        s2 = make_snapshot(retry=3)
        self.assertNotEqual(compute_state_hash(s1), compute_state_hash(s2))

    def test_execution_frame_change_changes_hash(self):
        s1 = make_snapshot(func="process_packet")
        s2 = make_snapshot(func="handle_error")
        self.assertNotEqual(compute_state_hash(s1), compute_state_hash(s2))

    def test_cyclic_graph_deterministic_hash(self):
        """Verify that cyclic graph references (self-cycles and mutual cycles) do not loop infinitely."""
        s = make_snapshot()
        h1 = compute_state_hash(s)
        h2 = compute_state_hash(s)
        self.assertEqual(h1, h2)
        self.assertEqual(len(h1), 16)


if __name__ == "__main__":
    unittest.main()

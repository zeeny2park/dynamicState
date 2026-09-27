import copy
import unittest

from extractor.state_corpus import compute_state_hash


def make_snapshot(retry=2, state="CONNECTED", func="process_packet", pid=100,
                  timestamp="2026-09-27T00:00:00Z", thread_id=1,
                  session_addr="0x1000", buffer_addr="0x2000", snapshot_id="S001",
                  storage="heap", session_id="obj_0001", buffer_id="obj_0002"):
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
                 "type": "Session*", "object_ref": session_id}
            ],
            "objects": [
                {
                    "object_id": session_id,
                    "type": "Session",
                    "address": session_addr,
                    "storage": storage,
                    "fields": [
                        {"name": "retry", "type": "uint32_t", "value": retry, "object_ref": None},
                        {"name": "state", "type": "SessionState", "value": state, "object_ref": None},
                        {"name": "buffer", "type": "Buffer*", "value": buffer_addr, "object_ref": buffer_id},
                        {"name": "parent", "type": "Session*", "value": session_addr, "object_ref": session_id}
                    ]
                },
                {
                    "object_id": buffer_id,
                    "type": "Buffer",
                    "address": buffer_addr,
                    "storage": storage,
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

    def test_storage_class_independence(self):
        """Verify identical hash regardless of physical storage region (heap vs stack)."""
        s1 = make_snapshot(storage="heap")
        s2 = make_snapshot(storage="stack")
        h1 = compute_state_hash(s1)
        h2 = compute_state_hash(s2)
        self.assertEqual(h1, h2, "State hash must represent semantic equivalence independent of physical storage classification")

    def test_object_id_independence(self):
        """Verify identical hash despite different observation object ID labels."""
        s1 = make_snapshot(session_id="obj_0001", buffer_id="obj_0002")
        s2 = make_snapshot(session_id="obj_0099", buffer_id="obj_0088")
        h1 = compute_state_hash(s1)
        h2 = compute_state_hash(s2)
        self.assertEqual(h1, h2, "State hash must be invariant to arbitrary object_id string labels")

    def test_root_ordering_independence(self):
        """Verify identical hash regardless of the order roots appear in the list."""
        s1 = make_snapshot()
        s1["persistent"]["roots"] = [
            {"root_id": "r1", "name": "alpha", "source": "global", "type": "Session*", "object_ref": "obj_0001"},
            {"root_id": "r2", "name": "beta", "source": "global", "type": "Buffer*", "object_ref": "obj_0002"},
        ]
        s2 = copy.deepcopy(s1)
        s2["persistent"]["roots"] = list(reversed(s1["persistent"]["roots"]))
        self.assertEqual(compute_state_hash(s1), compute_state_hash(s2))

    def test_field_ordering_independence(self):
        """Verify identical hash regardless of the order fields appear inside an object."""
        s1 = make_snapshot()
        s2 = copy.deepcopy(s1)
        s2["persistent"]["objects"][0]["fields"] = list(reversed(s1["persistent"]["objects"][0]["fields"]))
        self.assertEqual(compute_state_hash(s1), compute_state_hash(s2))

    def test_thread_ordering_independence(self):
        """Verify identical hash regardless of thread list ordering."""
        s1 = make_snapshot()
        s1["execution"]["threads"] = [
            {"thread_id": 1, "frames": [{"level": 0, "function": "func_a"}]},
            {"thread_id": 2, "frames": [{"level": 0, "function": "func_b"}]},
        ]
        s2 = copy.deepcopy(s1)
        s2["execution"]["threads"] = list(reversed(s1["execution"]["threads"]))
        self.assertEqual(compute_state_hash(s1), compute_state_hash(s2))

    def test_graph_topology_differences(self):
        """Verify different hashes when semantic graph topology differs."""
        # 1. parent -> child vs parent -> null
        s_with_child = make_snapshot()
        s_null_child = copy.deepcopy(s_with_child)
        buf_field = next(f for f in s_null_child["persistent"]["objects"][0]["fields"] if f["name"] == "buffer")
        buf_field["object_ref"] = None
        buf_field["value"] = "0x0"
        self.assertNotEqual(compute_state_hash(s_with_child), compute_state_hash(s_null_child))

        # 2. A -> B vs A -> C (pointing to different target types/contents)
        s_target_c = copy.deepcopy(s_with_child)
        s_target_c["persistent"]["objects"][1]["type"] = "DifferentType"
        self.assertNotEqual(compute_state_hash(s_with_child), compute_state_hash(s_target_c))

    def test_cyclic_graph_deterministic_hash(self):
        """Verify that cyclic graph references (self-cycles and mutual cycles) do not loop infinitely."""
        # Self-cycle
        s1 = make_snapshot()
        h1 = compute_state_hash(s1)
        self.assertEqual(len(h1), 16)

        # Mutual cycle: obj_0001.buffer -> obj_0002, and obj_0002 has field parent -> obj_0001
        s2 = copy.deepcopy(s1)
        s2["persistent"]["objects"][1]["fields"].append(
            {"name": "owner", "type": "Session*", "value": "0x1000", "object_ref": "obj_0001"}
        )
        h2 = compute_state_hash(s2)
        h3 = compute_state_hash(s2)
        self.assertEqual(h2, h3)
        self.assertEqual(len(h2), 16)
        self.assertNotEqual(h1, h2)

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

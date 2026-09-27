import unittest

from extractor.explorer import MutationCandidate, StateExplorer
from extractor.runtime_controller import RuntimeController


class DummyController(RuntimeController):
    def observe(self):
        return None
    def snapshot(self, snapshot_id=None, output=None):
        return None
    def get_object(self, object_id):
        return None
    def get_field(self, object_id, field):
        return None
    def mutate(self, object_id, field_path, value):
        return None
    def continue_execution(self, timeout_ms=1000):
        return None
    def diff(self, before, after):
        return None
    def execute_transition(self, **kwargs):
        return None


class MutationCandidateTests(unittest.TestCase):
    def test_mutation_candidate_dataclass(self):
        cand = MutationCandidate(
            candidate_id="M0001",
            snapshot_id="S001",
            object_id="obj_0001",
            field_path="retry",
            current_value=2,
            proposed_value=3,
            type="uint32_t",
            reason="BOUNDARY_PLUS_ONE"
        )
        d = cand.to_dict()
        self.assertEqual(d["candidate_id"], "M0001")
        self.assertEqual(d["current_value"], 2)
        self.assertEqual(d["proposed_value"], 3)
        self.assertEqual(d["reason"], "BOUNDARY_PLUS_ONE")

    def test_propose_mutations_generation(self):
        snapshot = {
            "snapshot": {"snapshot_id": "S001"},
            "persistent": {
                "objects": [
                    {
                        "object_id": "obj_0001",
                        "type": "Session",
                        "fields": [
                            {"name": "retry", "type": "uint32_t", "value": 2},
                            {"name": "flagged", "type": "bool", "value": 0},
                            {"name": "buffer", "type": "Buffer*", "value": "0x2000"},
                            {"name": "ratio", "type": "double", "value": 1.0}
                        ]
                    }
                ]
            }
        }
        explorer = StateExplorer(DummyController())
        cands = explorer.propose_mutations(snapshot)
        self.assertTrue(len(cands) >= 4)

        reasons = [c.reason for c in cands]
        self.assertIn("BOUNDARY_PLUS_ONE", reasons)
        self.assertIn("BOOLEAN_TOGGLE", reasons)
        self.assertIn("NULL_POINTER", reasons)
        self.assertIn("FLOAT_ZERO", reasons)

        # Check bool candidate specifically
        bool_cand = next(c for c in cands if c.field_path == "flagged")
        self.assertTrue(bool_cand.proposed_value)

        # Check pointer candidate specifically
        ptr_cand = next(c for c in cands if c.field_path == "buffer")
        self.assertEqual(ptr_cand.proposed_value, "null")

    def test_integer_width_boundaries(self):
        """Verify type-width-aware boundaries for unsigned and signed integers."""
        snapshot = {
            "snapshot": {"snapshot_id": "S001"},
            "persistent": {
                "objects": [
                    {
                        "object_id": "obj_0001",
                        "type": "TypesSample",
                        "fields": [
                            {"name": "u8", "type": "uint8_t", "value": 10},
                            {"name": "u16", "type": "uint16_t", "value": 10},
                            {"name": "u32", "type": "uint32_t", "value": 10},
                            {"name": "u64", "type": "uint64_t", "value": 10},
                            {"name": "i8", "type": "int8_t", "value": 0},
                            {"name": "i16", "type": "int16_t", "value": 0},
                            {"name": "i32", "type": "int32_t", "value": 0},
                            {"name": "i64", "type": "int64_t", "value": 0},
                        ]
                    }
                ]
            }
        }
        explorer = StateExplorer(DummyController())
        cands = explorer.propose_mutations(snapshot)

        # uint8_t max = 255
        u8_cands = [c.proposed_value for c in cands if c.field_path == "u8"]
        self.assertIn(255, u8_cands)
        self.assertNotIn(65535, u8_cands)

        # uint16_t max = 65535
        u16_cands = [c.proposed_value for c in cands if c.field_path == "u16"]
        self.assertIn(65535, u16_cands)
        self.assertNotIn(4294967295, u16_cands)

        # uint32_t max = 4294967295
        u32_cands = [c.proposed_value for c in cands if c.field_path == "u32"]
        self.assertIn(4294967295, u32_cands)

        # uint64_t max = 18446744073709551615
        u64_cands = [c.proposed_value for c in cands if c.field_path == "u64"]
        self.assertIn(18446744073709551615, u64_cands)

        # signed int8_t min/max = -128, 127
        i8_cands = [c.proposed_value for c in cands if c.field_path == "i8"]
        self.assertIn(-128, i8_cands)
        self.assertIn(127, i8_cands)

        # signed int16_t min/max = -32768, 32767
        i16_cands = [c.proposed_value for c in cands if c.field_path == "i16"]
        self.assertIn(-32768, i16_cands)
        self.assertIn(32767, i16_cands)

        # signed int32_t min/max = -2147483648, 2147483647
        i32_cands = [c.proposed_value for c in cands if c.field_path == "i32"]
        self.assertIn(-2147483648, i32_cands)
        self.assertIn(2147483647, i32_cands)

        # signed int64_t min/max
        i64_cands = [c.proposed_value for c in cands if c.field_path == "i64"]
        self.assertIn(-9223372036854775808, i64_cands)
        self.assertIn(9223372036854775807, i64_cands)

    def test_enum_alternate_members(self):
        """Verify that enum fields generate alternate symbolic members."""
        snapshot = {
            "snapshot": {"snapshot_id": "S001"},
            "persistent": {
                "objects": [
                    {
                        "object_id": "obj_0001",
                        "type": "Session",
                        "fields": [
                            {"name": "state", "type": "SessionState", "value": "CONNECTED"}
                        ]
                    }
                ]
            }
        }
        explorer = StateExplorer(DummyController())
        cands = explorer.propose_mutations(snapshot)

        enum_cands = [c.proposed_value for c in cands if c.field_path == "state"]
        self.assertIn("DISCONNECTED", enum_cands)
        self.assertIn("ERROR", enum_cands)
        self.assertNotIn("CONNECTED", enum_cands)

    def test_duplicate_removal_and_bounds_protection(self):
        """Verify no duplicate candidate proposals and no unsigned underflow."""
        snapshot = {
            "snapshot": {"snapshot_id": "S001"},
            "persistent": {
                "objects": [
                    {
                        "object_id": "obj_0001",
                        "type": "Session",
                        "fields": [
                            {"name": "zero_u8", "type": "uint8_t", "value": 0}
                        ]
                    }
                ]
            }
        }
        explorer = StateExplorer(DummyController())
        cands = explorer.propose_mutations(snapshot)

        proposed_vals = [c.proposed_value for c in cands if c.field_path == "zero_u8"]
        # Should not contain -1 (unsigned underflow)
        self.assertNotIn(-1, proposed_vals)
        # Should not have duplicate values
        self.assertEqual(len(proposed_vals), len(set(proposed_vals)))


if __name__ == "__main__":
    unittest.main()

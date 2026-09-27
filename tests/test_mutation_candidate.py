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


if __name__ == "__main__":
    unittest.main()

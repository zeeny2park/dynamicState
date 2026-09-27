"""Unit tests for Phase 5 CandidateRanker."""

import unittest

from extractor.agent_models import AgentStateContext
from extractor.candidate_ranker import CandidateRanker
from extractor.explorer import MutationCandidate


class CandidateRankerTests(unittest.TestCase):
    def setUp(self):
        self.ranker = CandidateRanker()

    def test_ranking_signals_and_weights(self):
        candidates = [
            # Regular integer non-boundary
            MutationCandidate("M001", "S001", "obj_0001", "unrelated_number", 10, 20, "uint32_t", "STEP"),
            # Branch-sensitive numeric boundary
            MutationCandidate("M002", "S001", "obj_0001", "retry", 2, 3, "uint32_t", "BOUNDARY_PLUS_ONE"),
            # Enum member transition
            MutationCandidate("M003", "S001", "obj_0001", "state", "CONNECTED", "ERROR", "SessionState", "ENUM_MEMBER"),
            # Container capacity / bounds
            MutationCandidate("M004", "S001", "obj_0002", "capacity", 256, 0, "uint32_t", "ZERO_BOUNDARY"),
        ]

        ranked = self.ranker.rank(candidates)
        self.assertEqual(len(ranked), 4)

        # M003 (enum transition + branch-sensitive 'state') should rank highest
        self.assertEqual(ranked[0].candidate_id, "M003")
        self.assertIn("ENUM_TRANSITION", ranked[0].ranking_reasons)
        self.assertIn("BRANCH_SENSITIVE", ranked[0].ranking_reasons)

        # M002 (retry: numeric boundary + branch-sensitive) should rank high
        cand_m002 = next(c for c in ranked if c.candidate_id == "M002")
        self.assertIn("NUMERIC_BOUNDARY", cand_m002.ranking_reasons)
        self.assertIn("BRANCH_SENSITIVE", cand_m002.ranking_reasons)

        # M004 (capacity: numeric boundary + invariant-related)
        cand_m004 = next(c for c in ranked if c.candidate_id == "M004")
        self.assertIn("NUMERIC_BOUNDARY", cand_m004.ranking_reasons)
        self.assertIn("INVARIANT_RELATED", cand_m004.ranking_reasons)

        # Scores must be strictly descending
        scores = [c.priority_score for c in ranked]
        self.assertEqual(scores, sorted(scores, reverse=True))

    def test_recently_changed_fields_boost(self):
        candidates = [
            MutationCandidate("M001", "S001", "obj_0001", "field_a", 1, 2, "int", "STEP"),
            MutationCandidate("M002", "S001", "obj_0001", "field_b", 1, 2, "int", "STEP"),
        ]

        ranked_initial = self.ranker.rank(candidates)
        # Without recent fields, scores are identical
        self.assertEqual(ranked_initial[0].priority_score, ranked_initial[1].priority_score)

        # With field_b in recently changed set
        ranked_boosted = self.ranker.rank(candidates, recent_changed_fields={"field_b"})
        self.assertEqual(ranked_boosted[0].candidate_id, "M002")
        self.assertIn("RECENTLY_CHANGED", ranked_boosted[0].ranking_reasons)
        self.assertGreater(ranked_boosted[0].priority_score, ranked_boosted[1].priority_score)

    def test_execution_reachable_object_boost(self):
        candidates = [
            MutationCandidate("M001", "S001", "obj_0001", "val", 1, 2, "int", "STEP"),
            MutationCandidate("M002", "S001", "obj_0099", "val", 1, 2, "int", "STEP"),
        ]
        context = AgentStateContext(
            snapshot_id="S001",
            execution={"thread_id": 1, "function": "foo"},
            objects=[{"object_id": "obj_0001", "type": "T"}],
            statistics={"object_count": 1}
        )

        ranked = self.ranker.rank(candidates, context=context)
        self.assertEqual(ranked[0].candidate_id, "M001")
        self.assertIn("EXECUTION_REACHABLE", ranked[0].ranking_reasons)

    def test_ranking_determinism(self):
        candidates = [
            MutationCandidate("M001", "S001", "obj_0001", "retry", 2, 3, "uint32_t", "BOUNDARY_PLUS_ONE"),
            MutationCandidate("M002", "S001", "obj_0001", "retry", 2, 0, "uint32_t", "ZERO_BOUNDARY"),
            MutationCandidate("M003", "S001", "obj_0001", "state", "CONNECTED", "ERROR", "SessionState", "ENUM_MEMBER"),
        ]
        ranked1 = self.ranker.rank(candidates)
        ranked2 = self.ranker.rank(candidates)

        self.assertEqual([c.candidate_id for c in ranked1], [c.candidate_id for c in ranked2])
        self.assertEqual([c.priority_score for c in ranked1], [c.priority_score for c in ranked2])


if __name__ == "__main__":
    unittest.main()

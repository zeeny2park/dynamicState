"""Phase 2.0-A.3.7 Verification Suite: Evidence-Based Confidence Calibration.

Validates:
- 3.1 10-dimension EvidenceQualityDimensions model and documentation.
- 3.2 Evidence independence and correlation classification (independent, correlated, derived, duplicate, contradictory).
- 3.3 Counterevidence handling (direct vs partial counterevidence).
- 3.4 Temporal confidence (timestamp, epoch, process lifetime, freshness).
- 3.5 Deterministic, bounded, monotonic confidence calibration and auditable confidence_history.
- 3.6 All 14 required calibration test cases:
  1. Zero observations
  2. Single weak observation
  3. Single strong observation
  4. Multiple correlated observations
  5. Multiple independent observations
  6. Direct counterevidence
  7. Partial counterevidence
  8. Stale evidence
  9. Incomplete snapshot
  10. Failed or abstained observation
  11. Caller-submitted unverified evidence
  12. Synthetic evidence
  13. Repeated duplicate observations
  14. Mixed strong support and strong contradiction
"""

import unittest

from extractor.evidence_ledger import (
    EVIDENCE_TYPE_COMPARISON,
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EVIDENCE_TYPE_OBJECT_STATE,
    EVIDENCE_TYPE_STATIC_LINK,
    EvidenceLedger,
    EvidenceRecord,
    NATURE_INFERENCE,
    NATURE_OBSERVATION,
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    PROVENANCE_CLASS_SYNTHETIC,
)
from extractor.hypothesis import (
    EVIDENCE_QUALITY_DIMENSION_DOCS,
    HYPOTHESIS_STATUS_CONTRADICTED,
    HYPOTHESIS_STATUS_INCONCLUSIVE,
    HYPOTHESIS_STATUS_PROPOSED,
    HYPOTHESIS_STATUS_SUPPORTED,
    HYPOTHESIS_STATUS_VALIDATED,
    HypothesisValidator,
    InvestigationHypothesis,
    classify_evidence_relationship,
    cluster_independent_supporting_evidence,
    evaluate_record_quality_dimensions,
)


class TestPhase20A37ConfidenceCalibration(unittest.TestCase):
    def setUp(self):
        self.ledger = EvidenceLedger(session_id="sess_cal_1")

    def _new_hypo(self, hid: str = "hypo_cal") -> InvestigationHypothesis:
        return InvestigationHypothesis(
            hypothesis_id=hid,
            investigation_id="sess_cal_1",
            title="Calibration Test Hypothesis",
            claim="Worker queue state is stalled",
            proposed_mechanism="Mutex contention on queue lock",
            confidence_score=0.35,
        )

    def test_3_1_ten_dimension_evidence_quality_model_documented_and_scored(self):
        """All 10 dimensions of EvidenceQualityDimensions are documented and deterministically evaluated."""
        expected_dims = {
            "provenance_trust",
            "execution_authenticity",
            "observation_completeness",
            "directness_of_observation",
            "type_and_identity_compatibility",
            "temporal_freshness",
            "reproducibility",
            "independent_corroboration",
            "contradictory_evidence",
            "collection_limitations",
        }
        self.assertEqual(set(EVIDENCE_QUALITY_DIMENSION_DOCS.keys()), expected_dims)
        for dim_name, meta in EVIDENCE_QUALITY_DIMENSION_DOCS.items():
            self.assertTrue(meta.get("meaning"), f"Missing meaning for {dim_name}")
            self.assertTrue(meta.get("impact"), f"Missing impact for {dim_name}")

        rec = self.ledger.record(
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Direct live field read",
            details={"epoch": 5},
            provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": None},
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        q_vec = evaluate_record_quality_dimensions(rec, reference_epoch=5)
        q_dict = q_vec.to_dict()
        self.assertEqual(set(q_dict.keys()), expected_dims)
        for k, v in q_dict.items():
            self.assertGreaterEqual(v, 0.0)
            self.assertLessEqual(v, 1.0)

    def test_3_2_evidence_independence_and_correlation_classification(self):
        """Distinguish independent, correlated, derived, duplicate, and contradictory evidence."""
        r_root = self.ledger.record(
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Observed obj.a = 1",
            details={"observation_id": "obs_batch_1", "field_path": "obj.a", "observed_value": 1, "snapshot_id": "snap_1", "epoch": 1},
        )
        # Same observation_id, different field -> correlated
        r_same_obs_other_field = self.ledger.record(
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Observed obj.b = 2",
            details={"observation_id": "obs_batch_1", "field_path": "obj.b", "observed_value": 2, "snapshot_id": "snap_1", "epoch": 1},
        )
        self.assertEqual(classify_evidence_relationship(r_root, r_same_obs_other_field, self.ledger), "correlated")

        # Repeated read from same snapshot -> correlated
        r_same_snap = self.ledger.record(
            evidence_type=EVIDENCE_TYPE_OBJECT_STATE,
            observation="Observed obj.c = 3 in snap_1",
            details={"observation_id": "obs_batch_2", "field_path": "obj.c", "observed_value": 3, "snapshot_id": "snap_1", "epoch": 1},
        )
        self.assertEqual(classify_evidence_relationship(r_root, r_same_snap, self.ledger), "correlated")

        # Derived record with parent_evidence_ids -> derived
        r_derived = self.ledger.record(
            evidence_type=EVIDENCE_TYPE_OBJECT_STATE,
            observation="Derived finding from r_root",
            parent_evidence_ids=[r_root.evidence_id],
            details={"snapshot_id": "snap_2", "epoch": 2},
        )
        self.assertEqual(classify_evidence_relationship(r_root, r_derived, self.ledger), "derived")

        # Duplicate imported through different source path -> duplicate
        r_dup_import = self.ledger.record(
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            source="external_importer",
            observation="Observed obj.a = 1",
            details={"field_path": "obj.a", "observed_value": 1, "snapshot_id": "snap_1", "epoch": 1},
        )
        self.assertEqual(classify_evidence_relationship(r_root, r_dup_import, self.ledger), "duplicate")

        # Contradictory outcome -> contradictory
        r_contra = self.ledger.record(
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Contradicting observation",
            details={"outcome": "CONTRADICTED"},
        )
        r_supp = self.ledger.record(
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Supporting observation",
            details={"outcome": "SUPPORTED"},
        )
        self.assertEqual(classify_evidence_relationship(r_supp, r_contra, self.ledger), "contradictory")

        # Distinct snapshot, epoch, and tool -> independent
        r_indep = self.ledger.record(
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            source="temporal_differ",
            observation="Independent temporal delta at epoch 2",
            details={"observation_id": "obs_temp_2", "snapshot_id": "snap_2", "epoch": 2},
        )
        self.assertEqual(classify_evidence_relationship(r_root, r_indep, self.ledger), "independent")

    # -------------------------------------------------------------------------
    # 3.6 The 14 Required Calibration Test Scenarios
    # -------------------------------------------------------------------------

    def test_case_01_zero_observations(self):
        """1. Zero observations -> baseline confidence (0.35), status remains PROPOSED."""
        hypo = self._new_hypo("h_01")
        HypothesisValidator.evaluate(hypo, self.ledger)
        self.assertEqual(hypo.validation_status, HYPOTHESIS_STATUS_PROPOSED)
        self.assertEqual(hypo.confidence_score, 0.35)

    def test_case_02_single_weak_observation(self):
        """2. Single weak (static-only) observation -> low confidence (<= 0.48)."""
        hypo = self._new_hypo("h_02")
        rec_weak = self.ledger.record(
            evidence_type=EVIDENCE_TYPE_STATIC_LINK,
            source="static_provider",
            observation="Static DWARF symbol reference only",
            details={"outcome": "SUPPORTED"},
        )
        HypothesisValidator.evaluate(hypo, self.ledger, new_evidence=rec_weak)
        self.assertEqual(hypo.validation_status, HYPOTHESIS_STATUS_SUPPORTED)
        self.assertLessEqual(hypo.confidence_score, 0.48)

    def test_case_03_single_strong_observation(self):
        """3. Single strong direct live observation -> moderate confidence (> weak observation, <= 0.70)."""
        hypo_weak = self._new_hypo("h_03_w")
        rec_weak = self.ledger.record(
            evidence_type=EVIDENCE_TYPE_STATIC_LINK,
            source="static_provider",
            observation="Static DWARF symbol reference",
            details={"outcome": "SUPPORTED"},
        )
        HypothesisValidator.evaluate(hypo_weak, self.ledger, new_evidence=rec_weak)

        hypo_strong = self._new_hypo("h_03_s")
        rec_strong = self.ledger.record(
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            source="runtime_collector",
            observation="Direct live runtime field observation",
            details={"outcome": "SUPPORTED", "snapshot_id": "snap_strong_1", "epoch": 1},
            provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE},
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        HypothesisValidator.evaluate(hypo_strong, self.ledger, new_evidence=rec_strong)
        self.assertGreater(hypo_strong.confidence_score, hypo_weak.confidence_score)
        self.assertGreaterEqual(hypo_strong.confidence_score, 0.60)
        self.assertLessEqual(hypo_strong.confidence_score, 0.70)

    def test_case_04_multiple_correlated_observations_do_not_inflate_confidence(self):
        """4. Multiple correlated observations (same snapshot / same observation_id / derived) do NOT inflate confidence."""
        hypo = self._new_hypo("h_04")
        rec1 = self.ledger.record(
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Field 1 from snap_A",
            details={"outcome": "SUPPORTED", "observation_id": "obs_1", "snapshot_id": "snap_A", "epoch": 1, "field_path": "a"},
        )
        HypothesisValidator.evaluate(hypo, self.ledger, new_evidence=rec1)
        score_after_1 = hypo.confidence_score

        # Add 3 more fields from the exact same snapshot & observation, plus 1 derived record
        for i in range(2, 5):
            rec_corr = self.ledger.record(
                evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
                observation=f"Field {i} from snap_A",
                details={"outcome": "SUPPORTED", "observation_id": "obs_1", "snapshot_id": "snap_A", "epoch": 1, "field_path": f"f_{i}"},
            )
            HypothesisValidator.evaluate(hypo, self.ledger, new_evidence=rec_corr)

        rec_derived = self.ledger.record(
            evidence_type=EVIDENCE_TYPE_OBJECT_STATE,
            observation="Derived summary from rec1",
            parent_evidence_ids=[rec1.evidence_id],
            details={"outcome": "SUPPORTED"},
        )
        HypothesisValidator.evaluate(hypo, self.ledger, new_evidence=rec_derived)

        self.assertEqual(hypo.quality_breakdown["independent_supporting_clusters"], 1)
        self.assertEqual(hypo.confidence_score, score_after_1)

    def test_case_05_multiple_independent_observations_increase_confidence(self):
        """5. Multiple genuinely independent observations (distinct snapshots & epochs) increase confidence."""
        hypo = self._new_hypo("h_05")
        rec1 = self.ledger.record(
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            source="tool_1",
            observation="Independent observation 1 at epoch 1",
            details={"outcome": "SUPPORTED", "observation_id": "obs_ind_1", "snapshot_id": "snap_ind_1", "epoch": 1},
        )
        HypothesisValidator.evaluate(hypo, self.ledger, new_evidence=rec1)
        score_1 = hypo.confidence_score

        rec2 = self.ledger.record(
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            source="tool_2",
            observation="Independent observation 2 at epoch 2",
            details={"outcome": "SUPPORTED", "observation_id": "obs_ind_2", "snapshot_id": "snap_ind_2", "epoch": 2},
        )
        HypothesisValidator.evaluate(hypo, self.ledger, new_evidence=rec2)
        score_2 = hypo.confidence_score

        rec3 = self.ledger.record(
            evidence_type=EVIDENCE_TYPE_OBJECT_STATE,
            source="tool_3",
            observation="Independent observation 3 at epoch 3",
            details={"outcome": "SUPPORTED", "observation_id": "obs_ind_3", "snapshot_id": "snap_ind_3", "epoch": 3},
        )
        HypothesisValidator.evaluate(hypo, self.ledger, new_evidence=rec3)
        score_3 = hypo.confidence_score

        self.assertEqual(hypo.quality_breakdown["independent_supporting_clusters"], 3)
        self.assertGreater(score_2, score_1)
        self.assertGreater(score_3, score_2)
        self.assertLessEqual(score_3, 0.85)

    def test_case_06_direct_counterevidence(self):
        """6. Direct counterevidence transitions status to CONTRADICTED and drops confidence <= 0.20."""
        hypo = self._new_hypo("h_06")
        rec_contra = self.ledger.record(
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Direct counterevidence refuting claim",
            details={"outcome": "CONTRADICTED"},
        )
        HypothesisValidator.evaluate(hypo, self.ledger, new_evidence=rec_contra)
        self.assertEqual(hypo.validation_status, HYPOTHESIS_STATUS_CONTRADICTED)
        self.assertLessEqual(hypo.confidence_score, 0.20)

    def test_case_07_partial_counterevidence(self):
        """7. Partial counterevidence reduces and caps confidence (<= 0.45) and prevents VALIDATED."""
        hypo = self._new_hypo("h_07")
        rec_supp = self.ledger.record(
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Initial support",
            details={"outcome": "SUPPORTED", "snapshot_id": "s1", "epoch": 1},
        )
        HypothesisValidator.evaluate(hypo, self.ledger, new_evidence=rec_supp)
        supp_score = hypo.confidence_score

        rec_partial_contra = self.ledger.record(
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Ambiguous partial counterevidence",
            details={"outcome": "CONTRADICTED", "counterevidence_strength": "PARTIAL", "partial_counterevidence": True},
        )
        HypothesisValidator.evaluate(hypo, self.ledger, new_evidence=rec_partial_contra)
        self.assertEqual(hypo.validation_status, HYPOTHESIS_STATUS_INCONCLUSIVE)
        self.assertNotEqual(hypo.validation_status, HYPOTHESIS_STATUS_VALIDATED)
        self.assertLess(hypo.confidence_score, supp_score)
        self.assertLessEqual(hypo.confidence_score, 0.45)

    def test_case_08_stale_evidence(self):
        """8. Stale or lifetime-expired evidence caps confidence <= 0.48."""
        hypo = self._new_hypo("h_08")
        rec_stale = self.ledger.record(
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Stale observation from expired epoch",
            details={"outcome": "SUPPORTED", "is_stale": True, "epoch": 0},
        )
        HypothesisValidator.evaluate(hypo, self.ledger, new_evidence=rec_stale)
        self.assertLessEqual(hypo.confidence_score, 0.48)
        self.assertLessEqual(hypo.quality_breakdown["dimensions"]["temporal_freshness"], 0.25)

    def test_case_09_incomplete_snapshot(self):
        """9. Incomplete (PARTIAL / NON_ATOMIC) snapshot caps confidence <= 0.55."""
        hypo = self._new_hypo("h_09")
        for i in range(3):
            rec_part = self.ledger.record(
                evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
                observation=f"Partial snapshot observation {i}",
                details={"outcome": "SUPPORTED", "snapshot_id": f"sp_{i}", "epoch": i},
                capture_quality={"completeness": "PARTIAL", "consistency_level": "NON_ATOMIC"},
            )
            HypothesisValidator.evaluate(hypo, self.ledger, new_evidence=rec_part)
        self.assertLessEqual(hypo.confidence_score, 0.55)

    def test_case_10_failed_or_abstained_observation(self):
        """10. Failed or abstained observation produces zero confidence increase."""
        hypo = self._new_hypo("h_10")
        initial_score = hypo.confidence_score
        rec_abstain = self.ledger.record(
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Read failed (EPERM)",
            details={"outcome": "ABSTAIN", "collection_status": "ABSTAIN", "result_category": "OBSERVATION_UNAVAILABLE"},
        )
        HypothesisValidator.evaluate(hypo, self.ledger, new_evidence=rec_abstain)
        self.assertLessEqual(hypo.confidence_score, initial_score)
        self.assertIn(rec_abstain.evidence_id, hypo.abstained_evidence_ids)

    def test_case_11_caller_submitted_unverified_evidence(self):
        """11. Caller-submitted unverified evidence is capped <= 0.45 and cannot reach high confidence."""
        hypo = self._new_hypo("h_11")
        rec_caller = self.ledger.record(
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            source="unverified_caller",
            observation="Caller claims defect exists",
            details={"outcome": "SUPPORTED", "caller_submitted": True, "unverified_caller_claim": True},
            provenance={"provenance_class": PROVENANCE_CLASS_IMPORTED_UNVERIFIED},
        )
        HypothesisValidator.evaluate(hypo, self.ledger, new_evidence=rec_caller)
        self.assertLessEqual(hypo.confidence_score, 0.45)

    def test_case_12_synthetic_evidence(self):
        """12. Synthetic evidence is capped <= 0.58 and cannot reach VALIDATED."""
        hypo = self._new_hypo("h_12")
        rec_syn = self.ledger.record(
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            source="synthetic_fixture",
            observation="Synthetic fixture support",
            details={"outcome": "SUPPORTED", "is_simulated": True},
            provenance={"provenance_class": PROVENANCE_CLASS_SYNTHETIC},
        )
        HypothesisValidator.evaluate(hypo, self.ledger, new_evidence=rec_syn)
        self.assertLessEqual(hypo.confidence_score, 0.58)
        self.assertNotEqual(hypo.validation_status, HYPOTHESIS_STATUS_VALIDATED)

    def test_case_13_repeated_duplicate_observations(self):
        """13. Repeated duplicate observations do not change confidence score."""
        hypo = self._new_hypo("h_13")
        rec1 = self.ledger.record(
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Observed x = 99",
            details={"outcome": "SUPPORTED", "semantic_digest": "dig_x_99", "snapshot_id": "s1", "epoch": 1},
        )
        HypothesisValidator.evaluate(hypo, self.ledger, new_evidence=rec1)
        score_1 = hypo.confidence_score

        rec_dup = self.ledger.record(
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Observed x = 99",
            details={"outcome": "SUPPORTED", "semantic_digest": "dig_x_99", "snapshot_id": "s1", "epoch": 1},
        )
        res_dup = HypothesisValidator.evaluate(hypo, self.ledger, new_evidence=rec_dup)
        self.assertTrue(res_dup.is_duplicate)
        self.assertEqual(hypo.confidence_score, score_1)

    def test_case_14_mixed_strong_support_and_strong_contradiction(self):
        """14. Mixed strong support and strong direct contradiction resolves to CONTRADICTED with low support score."""
        hypo = self._new_hypo("h_14")
        for i in range(2):
            rec_s = self.ledger.record(
                evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
                observation=f"Strong support {i}",
                details={"outcome": "SUPPORTED", "snapshot_id": f"s_mix_{i}", "epoch": i},
            )
            HypothesisValidator.evaluate(hypo, self.ledger, new_evidence=rec_s)
        self.assertEqual(hypo.validation_status, HYPOTHESIS_STATUS_SUPPORTED)

        rec_c = self.ledger.record(
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            observation="Direct refutation of mechanism",
            details={"outcome": "CONTRADICTED", "snapshot_id": "s_mix_contra", "epoch": 3},
        )
        HypothesisValidator.evaluate(hypo, self.ledger, new_evidence=rec_c)
        self.assertEqual(hypo.validation_status, HYPOTHESIS_STATUS_CONTRADICTED)
        self.assertLessEqual(hypo.confidence_score, 0.20)
        self.assertGreaterEqual(len(hypo.confidence_history), 2)


if __name__ == "__main__":
    unittest.main()

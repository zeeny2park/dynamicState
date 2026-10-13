"""Comprehensive Regression & Hardening Tests for Causal Validation Invariants and Defect Fixtures.

Validates the 10 Critical Causal Validation Invariants across Scenarios A through H:
- Invariant 1: STATIC_CANDIDATE never promoted solely because of finding association
- Invariant 2: Candidate promoted to VALIDATED_CAUSAL_FUNCTION only with explicit, verified evidence
- Invariant 3: Caller cannot promote by supplying Boolean or fabricated evidence ID
- Invariant 4: CONTRADICTED dominance over duplicated supporting records and repeated evaluation
- Invariant 5: Duplicate evidence derived from same observation does not count as independent corroboration
- Invariant 6: Provenance cycles, missing parent records, and conflicting IDs fail safely as INCONCLUSIVE
- Invariant 7: PARTIAL, FAILED, INVALID, and NON_ATOMIC captures obey strict validation limits
- Invariant 8: Repeated evaluation idempotency (no duplicate history, evidence duplication, or confidence drift)
- Invariant 9: Observation execution enforces authorization and supported target capabilities
- Invariant 10: Reports and APIs distinguish hypothesis status from function-candidate tier
"""

import unittest
from unittest.mock import MagicMock

from extractor.causal_fixtures import CausalDefectFixtures
from extractor.evaluation import CausalValidationEvaluator
from extractor.evidence_ledger import (
    EVIDENCE_TYPE_COMPARISON,
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EvidenceLedger,
    EvidenceRecord,
    NATURE_OBSERVATION,
)
from extractor.hypothesis import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    FUNCTION_TIER_EVIDENCE_SUPPORTED,
    FUNCTION_TIER_STATIC_CANDIDATE,
    FUNCTION_TIER_VALIDATED_CAUSAL,
    HYPOTHESIS_STATUS_CONTRADICTED,
    HYPOTHESIS_STATUS_INCONCLUSIVE,
    HYPOTHESIS_STATUS_PROPOSED,
    HYPOTHESIS_STATUS_SUPPORTED,
    HYPOTHESIS_STATUS_VALIDATED,
    TARGET_KIND_MUTATION,
    FollowUpObservation,
    HypothesisValidator,
    InvestigationHypothesis,
)
from extractor.investigation import (
    InvestigationFinding,
    InvestigationManager,
)


class TestCausalValidationInvariants(unittest.TestCase):
    """Test suite asserting the 10 causal validation invariants."""

    def test_invariant_1_static_candidate_never_promoted_solely_by_finding(self):
        """Invariant 1: A STATIC_CANDIDATE from DWARF can never become a confirmed root cause solely by finding."""
        mgr, inv_id, hypo_id = CausalDefectFixtures.create_scenario_b_static_candidate_unproven()
        hypo = mgr.get_hypothesis(inv_id, hypo_id)

        self.assertEqual(len(hypo["function_candidates"]), 1)
        fc = hypo["function_candidates"][0]
        self.assertEqual(fc["candidate_tier"], FUNCTION_TIER_STATIC_CANDIDATE)
        self.assertFalse(fc["confirmed_root_cause"])
        self.assertIn("not confirmed root-cause function", fc["tier_limitation"])

        # Repeated evaluation without proof evidence maintains STATIC_CANDIDATE
        mgr.evaluate_hypothesis(inv_id, hypo_id)
        hypo_after = mgr.get_hypothesis(inv_id, hypo_id)
        self.assertEqual(hypo_after["function_candidates"][0]["candidate_tier"], FUNCTION_TIER_STATIC_CANDIDATE)
        self.assertFalse(hypo_after["function_candidates"][0]["confirmed_root_cause"])

    def test_invariant_2_and_3_caller_boolean_rejected_and_explicit_evidence_required(self):
        """Invariant 2 & 3: Caller cannot promote by supplying Boolean; explicit verified proof required."""
        mgr, inv_id, hypo_id = CausalDefectFixtures.create_scenario_a_reproducible_mutation()

        # Attempt 1: Caller supplies only deterministic_transition_verified=True without proof_evidence_id
        # (Remove proof record from supporting IDs temporarily to simulate unverified hypothesis)
        session = mgr.sessions[inv_id]
        hypo_obj = next(h for h in session.hypotheses if h.hypothesis_id == hypo_id)
        hypo_obj.supporting_evidence_ids = ["ev_a_diff"]  # diff only, no proof

        res_unverified = mgr.evaluate_hypothesis(
            inv_id,
            hypo_id,
            deterministic_transition_verified=True,
        )
        self.assertTrue(res_unverified["success"])
        # Must be rejected and remain SUPPORTED
        self.assertEqual(res_unverified["transition"]["to_status"], HYPOTHESIS_STATUS_SUPPORTED)
        self.assertTrue(res_unverified["transition"]["unverified_claim_rejected"])
        self.assertIn("rejected", res_unverified["transition"]["reason"].lower())

        # Candidate must NOT be promoted
        hypo_unverified = mgr.get_hypothesis(inv_id, hypo_id)
        self.assertFalse(hypo_unverified["function_candidates"][0]["confirmed_root_cause"])

        # Attempt 2: Fabricated proof_evidence_id that does not exist in ledger
        res_fake = mgr.evaluate_hypothesis(
            inv_id,
            hypo_id,
            deterministic_transition_verified=True,
            proof_evidence_id="fabricated_nonexistent_id",
        )
        self.assertEqual(res_fake["transition"]["to_status"], HYPOTHESIS_STATUS_SUPPORTED)
        self.assertTrue(res_fake["transition"]["unverified_claim_rejected"])

        # Attempt 3: Legitimate verified proof evidence attached
        hypo_obj.supporting_evidence_ids.append("ev_a_proof")
        res_valid = mgr.evaluate_hypothesis(
            inv_id,
            hypo_id,
            deterministic_transition_verified=True,
            proof_evidence_id="ev_a_proof",
        )
        self.assertEqual(res_valid["transition"]["to_status"], HYPOTHESIS_STATUS_VALIDATED)
        self.assertFalse(res_valid["transition"]["unverified_claim_rejected"])
        hypo_valid = mgr.get_hypothesis(inv_id, hypo_id)
        self.assertEqual(hypo_valid["function_candidates"][0]["candidate_tier"], FUNCTION_TIER_VALIDATED_CAUSAL)
        self.assertTrue(hypo_valid["function_candidates"][0]["confirmed_root_cause"])

    def test_invariant_4_contradiction_dominance(self):
        """Invariant 4: CONTRADICTED evidence must not be overridden by duplicated supporting records or repeated evaluation."""
        mgr, inv_id, hypo_id = CausalDefectFixtures.create_scenario_d_contradictory_evidence()

        # Add contradicting record
        rec_contra = mgr.sessions[inv_id].ledger.get_record("ev_d_contra")
        res1 = mgr.evaluate_hypothesis(inv_id, hypo_id, new_evidence_data=rec_contra.to_dict())
        self.assertEqual(res1["transition"]["to_status"], HYPOTHESIS_STATUS_CONTRADICTED)

        # Attempt to override with new supporting record
        rec_supp_new = EvidenceRecord(
            evidence_id="ev_supp_later",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            nature=NATURE_OBSERVATION,
            source="test",
            session_id=inv_id,
            observation="Observed value was 20",
            capture_quality={"completeness": "COMPLETE"},
        )
        res2 = mgr.evaluate_hypothesis(inv_id, hypo_id, new_evidence_data=rec_supp_new.to_dict())
        # CONTRADICTED must dominate
        self.assertEqual(res2["transition"]["to_status"], HYPOTHESIS_STATUS_CONTRADICTED)

        # Repeated evaluation must also remain CONTRADICTED
        res3 = mgr.evaluate_hypothesis(inv_id, hypo_id, deterministic_transition_verified=True)
        self.assertEqual(res3["transition"]["to_status"], HYPOTHESIS_STATUS_CONTRADICTED)

    def test_invariant_5_and_8_duplicate_evidence_and_idempotence(self):
        """Invariant 5 & 8: Duplicate evidence does not count as independent; evaluation is strictly idempotent."""
        ledger = EvidenceLedger()
        rec1 = EvidenceRecord(
            evidence_id="ev_orig_1",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            nature=NATURE_OBSERVATION,
            source="test",
            observation="Observed field X = 42",
            details={"val": 42},
            capture_quality={"completeness": "COMPLETE"},
        )
        ledger.add_record(rec1)

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_idem",
            investigation_id="inv_idem",
            title="Idempotency Test",
            claim="Claim",
            proposed_mechanism="Mechanism",
            supporting_evidence_ids=["ev_orig_1"],
            validation_status=HYPOTHESIS_STATUS_SUPPORTED,
            confidence=CONFIDENCE_MEDIUM,
        )

        initial_history_len = len(hypo.status_history)

        # Duplicate record with new ID but identical contents
        rec_dup = EvidenceRecord(
            evidence_id="ev_orig_dup",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            nature=NATURE_OBSERVATION,
            source="test",
            observation="Observed field X = 42",
            details={"val": 42},
            capture_quality={"completeness": "COMPLETE"},
        )
        ledger.add_record(rec_dup)

        res_dup = HypothesisValidator.evaluate(hypo, ledger, new_evidence=rec_dup)
        self.assertTrue(res_dup.is_duplicate)
        self.assertNotIn("ev_orig_dup", hypo.supporting_evidence_ids)

        # Repeat evaluation 5 times: no status change, no history expansion
        for _ in range(5):
            res_rep = HypothesisValidator.evaluate(hypo, ledger)
            self.assertFalse(res_rep.status_changed)
            self.assertEqual(res_rep.to_status, HYPOTHESIS_STATUS_SUPPORTED)
            self.assertEqual(res_rep.confidence, CONFIDENCE_MEDIUM)

        self.assertEqual(len(hypo.status_history), initial_history_len)

    def test_invariant_6_provenance_cycles_and_missing_parents_fail_safely(self):
        """Invariant 6: Provenance cycles and missing parent records fail safely as INCONCLUSIVE."""
        # 1. Cyclic Graph
        mgr_cyc, inv_id_cyc, hypo_id_cyc = CausalDefectFixtures.create_scenario_h_cyclic_missing_duplicate_evidence()
        res_cyc = mgr_cyc.evaluate_hypothesis(inv_id_cyc, hypo_id_cyc)
        self.assertTrue(res_cyc["transition"]["cycle_detected"])
        self.assertEqual(res_cyc["transition"]["to_status"], HYPOTHESIS_STATUS_INCONCLUSIVE)
        self.assertEqual(res_cyc["transition"]["confidence"], CONFIDENCE_LOW)

        # 2. Missing Parent Record
        mgr_miss = InvestigationManager()
        start = mgr_miss.start_investigation(goal="Missing parent test")
        inv_id_miss = start["investigation_id"]
        session_miss = mgr_miss.sessions[inv_id_miss]

        rec_orphan = EvidenceRecord(
            evidence_id="ev_orphan",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="test",
            session_id=inv_id_miss,
            observation="Orphan observation",
            parent_evidence_ids=["ev_nonexistent_parent_404"],
            capture_quality={"completeness": "COMPLETE"},
        )
        session_miss.ledger.add_record(rec_orphan)

        hypo_miss = InvestigationHypothesis(
            hypothesis_id="hypo_orphan",
            investigation_id=inv_id_miss,
            title="Missing Parent Test",
            claim="Claim",
            proposed_mechanism="Mechanism",
            supporting_evidence_ids=["ev_orphan"],
            validation_status=HYPOTHESIS_STATUS_PROPOSED,
        )
        session_miss.hypotheses.append(hypo_miss)

        res_miss = mgr_miss.evaluate_hypothesis(inv_id_miss, "hypo_orphan")
        self.assertEqual(res_miss["transition"]["to_status"], HYPOTHESIS_STATUS_INCONCLUSIVE)
        self.assertIsNotNone(res_miss["transition"]["provenance_error"])
        self.assertIn("Missing parent evidence record", res_miss["transition"]["provenance_error"])

    def test_invariant_7_capture_quality_and_non_atomic_ceilings(self):
        """Invariant 7: PARTIAL, FAILED, INVALID, and NON_ATOMIC captures obey explicit validation limits."""
        # 1. PARTIAL capture
        mgr_p, inv_p, hypo_p = CausalDefectFixtures.create_scenario_e_partial_or_non_atomic_capture()
        res_p = mgr_p.evaluate_hypothesis(inv_p, hypo_p, deterministic_transition_verified=True)
        self.assertEqual(res_p["transition"]["to_status"], HYPOTHESIS_STATUS_SUPPORTED)
        self.assertNotEqual(res_p["transition"]["to_status"], HYPOTHESIS_STATUS_VALIDATED)
        self.assertIn("PARTIAL", res_p["transition"]["reason"])

        # 2. NON_ATOMIC capture consistency
        ledger_na = EvidenceLedger()
        rec_na = EvidenceRecord(
            evidence_id="ev_na_trans",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="test",
            observation="Deterministic transition reproduced",
            details={"verified_transition": True, "is_non_atomic": True},
            capture_quality={"completeness": "COMPLETE", "consistency_level": "NON_ATOMIC"},
        )
        ledger_na.add_record(rec_na)

        hypo_na = InvestigationHypothesis(
            hypothesis_id="hypo_na",
            investigation_id="inv_na",
            title="NON_ATOMIC Skew",
            claim="Claim",
            proposed_mechanism="Mech",
            supporting_evidence_ids=["ev_na_trans"],
            function_candidates=[{
                "function_name": "worker_fn",
                "candidate_tier": FUNCTION_TIER_EVIDENCE_SUPPORTED,
                "confirmed_root_cause": False,
            }],
            validation_status=HYPOTHESIS_STATUS_PROPOSED,
        )

        res_na = HypothesisValidator.evaluate(hypo_na, ledger_na, deterministic_transition_verified=True)
        self.assertEqual(res_na.to_status, HYPOTHESIS_STATUS_SUPPORTED)
        self.assertNotEqual(res_na.to_status, HYPOTHESIS_STATUS_VALIDATED)
        self.assertEqual(res_na.confidence, CONFIDENCE_LOW)
        self.assertIn("NON_ATOMIC", res_na.reason)
        self.assertFalse(hypo_na.function_candidates[0]["confirmed_root_cause"])

        # 3. FAILED capture
        ledger_fail = EvidenceLedger()
        rec_fail = EvidenceRecord(
            evidence_id="ev_fail",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="test",
            observation="Observed diff",
            capture_quality={"completeness": "FAILED"},
        )
        ledger_fail.add_record(rec_fail)
        hypo_fail = InvestigationHypothesis(
            hypothesis_id="hypo_fail",
            investigation_id="inv_fail",
            title="Failed Capture",
            claim="Claim",
            proposed_mechanism="Mech",
            supporting_evidence_ids=["ev_fail"],
        )
        res_fail = HypothesisValidator.evaluate(hypo_fail, ledger_fail, deterministic_transition_verified=True)
        self.assertEqual(res_fail.to_status, HYPOTHESIS_STATUS_INCONCLUSIVE)
        self.assertEqual(res_fail.confidence, CONFIDENCE_LOW)

    def test_invariant_9_observation_execution_authorization(self):
        """Invariant 9: Observation execution enforces authorization; unverified caller results cannot fabricate proof."""
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Auth check", authorize_target=False)
        inv_id = start["investigation_id"]
        session = mgr.sessions[inv_id]

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_sec",
            investigation_id=inv_id,
            title="Security Check",
            claim="Claim",
            proposed_mechanism="Mech",
            suggested_observations=[
                FollowUpObservation(
                    observation_id="obs_mut_denied",
                    hypothesis_id="hypo_sec",
                    question="Mutate target live?",
                    target_kind=TARGET_KIND_MUTATION,
                    target_ref={},
                    discriminating_criteria="",
                    expected_outcomes={},
                )
            ],
        )
        session.hypotheses.append(hypo)

        # 1. Live mutation blocked
        res_mut = mgr.execute_observation(inv_id, "obs_mut_denied")
        self.assertFalse(res_mut["success"])
        self.assertTrue(res_mut.get("blocked", False))

        # 2. Fabricated observation result claiming VALIDATED without authorization
        obs_safe = FollowUpObservation(
            observation_id="obs_safe_1",
            hypothesis_id="hypo_sec",
            question="Field check",
            target_kind="FIELD",
            target_ref={"field_path": "obj.val"},
            discriminating_criteria="",
            expected_outcomes={},
        )
        hypo.suggested_observations.append(obs_safe)

        res_exec = mgr.execute_observation(
            inv_id,
            "obs_safe_1",
            result_data={
                "outcome": "VALIDATED",
                "details": {"verified_transition": True, "causal_proof": True},
            },
        )
        self.assertTrue(res_exec["success"])
        ev_rec = session.ledger.get_record(res_exec["evidence"]["evidence_id"])
        # Fabrication must be disarmed
        self.assertTrue(ev_rec.details.get("unverified_caller_claim", False))
        self.assertFalse(ev_rec.details.get("verified_transition", False))
        self.assertEqual(ev_rec.source, "unverified_caller")

    def test_invariant_10_report_distinguishes_hypothesis_and_candidate_tiers(self):
        """Invariant 10: Reports and APIs consistently distinguish hypothesis status, candidate tiers, and confirmed causes."""
        mgr, inv_id, hypo_id = CausalDefectFixtures.create_scenario_a_reproducible_mutation()
        # Evaluate to VALIDATED
        mgr.evaluate_hypothesis(
            inv_id,
            hypo_id,
            deterministic_transition_verified=True,
            proof_evidence_id="ev_a_proof",
        )

        report = mgr.generate_report(inv_id)
        cc = report["causal_conclusions"]

        self.assertEqual(cc["validated_causal_count"], 1)
        self.assertEqual(len(cc["validated_causal_functions"]), 1)
        self.assertEqual(cc["validated_causal_functions"][0]["candidate_tier"], FUNCTION_TIER_VALIDATED_CAUSAL)
        self.assertTrue(cc["validated_causal_functions"][0]["confirmed_root_cause"])
        self.assertTrue(cc["causal_proof_established"])
        self.assertIsNone(cc["causal_limitation_notice"])

        # Check structured validated_hypotheses mapping
        self.assertEqual(len(cc["validated_hypotheses"]), 1)
        val_hypo = cc["validated_hypotheses"][0]
        self.assertEqual(val_hypo["hypothesis_id"], hypo_id)
        self.assertIn("ev_a_proof", val_hypo["supporting_evidence_ids"] + [val_hypo.get("proof_evidence_id")])


class TestFalsePositiveEvaluationHarness(unittest.TestCase):
    """Test suite verifying the machine-readable false-positive evaluation harness."""

    def test_evaluation_harness_execution_and_zero_fp_sla(self):
        """Run the complete evaluation suite and assert zero false validations."""
        evaluator = CausalValidationEvaluator()
        report = evaluator.run_all()

        metrics = report["summary_metrics"]
        self.assertEqual(metrics["total_cases_evaluated"], 12)
        self.assertEqual(metrics["correct_causal_validations_tp"], 2)
        self.assertEqual(metrics["false_causal_validations_fp"], 0, "CRITICAL SLA BREACH: False causal validations must be 0!")
        self.assertEqual(metrics["missed_causal_validations_fn"], 0)
        self.assertEqual(metrics["correctly_inconclusive_or_rejected_tn"], 10)
        self.assertGreaterEqual(metrics["unsupported_promotions_blocked"], 3)
        self.assertEqual(metrics["causal_validation_precision"], 1.0)
        self.assertEqual(metrics["causal_validation_recall"], 1.0)
        self.assertEqual(metrics["false_positive_rate"], 0.0)
        self.assertTrue(metrics["zero_false_positives_sla_satisfied"])


if __name__ == "__main__":
    unittest.main()

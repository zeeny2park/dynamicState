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
from extractor.agent_models import AgentAction
from extractor.agent_runtime import AgentRuntime
from extractor.web.server import WebApiAdapter


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


class TestAdversarialCausalValidationSuite(unittest.TestCase):
    """Adversarial Regression Test Suite covering Cases A through L."""

    def test_case_a_legitimate_internally_verified_proof(self):
        """Case A: Legitimate internally verified proof with COMPLETE, atomic capture can validate the intended causal function."""
        mgr, inv_id, hypo_id = CausalDefectFixtures.create_scenario_a_reproducible_mutation()
        res = mgr.evaluate_hypothesis(
            inv_id,
            hypo_id,
            deterministic_transition_verified=True,
            proof_evidence_id="ev_a_proof",
        )
        self.assertTrue(res["success"])
        self.assertEqual(res["transition"]["to_status"], HYPOTHESIS_STATUS_VALIDATED)
        self.assertEqual(res["transition"]["confidence"], CONFIDENCE_HIGH)
        self.assertFalse(res["transition"]["unverified_claim_rejected"])

        hypo = mgr.get_hypothesis(inv_id, hypo_id)
        self.assertEqual(hypo["validation_status"], HYPOTHESIS_STATUS_VALIDATED)
        self.assertEqual(hypo["confidence"], CONFIDENCE_HIGH)
        fc = hypo["function_candidates"][0]
        self.assertEqual(fc["candidate_tier"], FUNCTION_TIER_VALIDATED_CAUSAL)
        self.assertTrue(fc["confirmed_root_cause"])

        # Report reflects verified causal function
        rep = mgr.generate_report(inv_id)
        cc = rep["causal_conclusions"]
        self.assertEqual(cc["validated_causal_count"], 1)
        self.assertEqual(cc["validated_causal_functions"][0]["function_name"], "mutate_worker_state")

    def test_case_b_caller_injection_with_trusted_source_string(self):
        """Case B: Caller injects verified_transition=True and a trusted-looking source string; validation is rejected."""
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Caller injection test")
        inv_id = start["investigation_id"]
        session = mgr.sessions[inv_id]

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_b",
            investigation_id=inv_id,
            title="Caller Injection",
            claim="Claim",
            proposed_mechanism="Mech",
            candidate_fields=["state"],
            function_candidates=[{
                "function_name": "worker_func",
                "candidate_tier": FUNCTION_TIER_STATIC_CANDIDATE,
                "confirmed_root_cause": False,
            }],
        )
        session.hypotheses.append(hypo)

        spoofed_payload = {
            "evidence_type": EVIDENCE_TYPE_COMPARISON,
            "source": "investigation_observer",  # Spoofed trusted-looking source
            "observation": "Observed deterministic transition in state",
            "details": {"verified_transition": True, "causal_proof": True},
            "capture_quality": {"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        }
        res = mgr.evaluate_hypothesis(inv_id, "hypo_b", new_evidence_data=spoofed_payload)
        self.assertTrue(res["success"])
        self.assertEqual(res["transition"]["to_status"], HYPOTHESIS_STATUS_SUPPORTED)
        self.assertTrue(res["transition"]["unverified_claim_rejected"])
        self.assertIn("rejected", res["transition"]["reason"].lower())

        hypo_after = mgr.get_hypothesis(inv_id, "hypo_b")
        fc = hypo_after["function_candidates"][0]
        self.assertFalse(fc["confirmed_root_cause"])
        self.assertEqual(fc["candidate_tier"], FUNCTION_TIER_STATIC_CANDIDATE)

        # Ledger record was disarmed
        ev = session.ledger._records[-1]
        self.assertEqual(ev.source, "unverified_caller")
        self.assertTrue(ev.details.get("unverified_caller_claim"))
        self.assertFalse(ev.details.get("verified_transition"))

    def test_case_c_caller_arbitrary_proof_id(self):
        """Case C: Caller submits arbitrary proof_evidence_id referencing fabricated or ordinary ledger record."""
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Arbitrary proof ID")
        inv_id = start["investigation_id"]
        session = mgr.sessions[inv_id]

        rec_ordinary = EvidenceRecord(
            evidence_id="ev_ordinary_1",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            nature=NATURE_OBSERVATION,
            source="collector",
            session_id=inv_id,
            observation="Observed value is 42",
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec_ordinary)

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_c",
            investigation_id=inv_id,
            title="Claim",
            claim="Claim",
            proposed_mechanism="Mech",
            supporting_evidence_ids=["ev_ordinary_1"],
            function_candidates=[{
                "function_name": "fn_c",
                "candidate_tier": FUNCTION_TIER_STATIC_CANDIDATE,
                "confirmed_root_cause": False,
            }],
        )
        session.hypotheses.append(hypo)

        # Attempt 1: Fabricated nonexistent ID
        res1 = mgr.evaluate_hypothesis(
            inv_id, "hypo_c",
            deterministic_transition_verified=True,
            proof_evidence_id="fabricated_nonexistent_id",
        )
        self.assertEqual(res1["transition"]["to_status"], HYPOTHESIS_STATUS_SUPPORTED)
        self.assertTrue(res1["transition"]["unverified_claim_rejected"])

        # Attempt 2: Referencing ordinary observation record without attestation
        res2 = mgr.evaluate_hypothesis(
            inv_id, "hypo_c",
            deterministic_transition_verified=True,
            proof_evidence_id="ev_ordinary_1",
        )
        self.assertEqual(res2["transition"]["to_status"], HYPOTHESIS_STATUS_SUPPORTED)
        self.assertTrue(res2["transition"]["unverified_claim_rejected"])

        hypo_after = mgr.get_hypothesis(inv_id, "hypo_c")
        self.assertFalse(hypo_after["function_candidates"][0]["confirmed_root_cause"])

    def test_case_d_caller_proof_markers_and_observation_strings(self):
        """Case D: Caller supplies causal_proof=True, reproduction_verified=True, or proof-like observation text."""
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Marker injection")
        inv_id = start["investigation_id"]
        session = mgr.sessions[inv_id]

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_d",
            investigation_id=inv_id,
            title="Claim D",
            claim="Claim",
            proposed_mechanism="Mech",
            candidate_fields=["counter"],
            function_candidates=[{
                "function_name": "inc_fn",
                "candidate_tier": FUNCTION_TIER_STATIC_CANDIDATE,
                "confirmed_root_cause": False,
            }],
        )
        session.hypotheses.append(hypo)

        marker_payload = {
            "evidence_type": EVIDENCE_TYPE_COMPARISON,
            "source": "collector",
            "observation": "Deterministic transition reproduced in counter",
            "details": {
                "reproduction_verified": True,
                "transition_verified": True,
                "verified_writer": True,
                "causal_proof": True,
            },
            "capture_quality": {"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        }
        res = mgr.evaluate_hypothesis(inv_id, "hypo_d", new_evidence_data=marker_payload)
        self.assertEqual(res["transition"]["to_status"], HYPOTHESIS_STATUS_SUPPORTED)
        self.assertTrue(res["transition"]["unverified_claim_rejected"])
        hypo_after = mgr.get_hypothesis(inv_id, "hypo_d")
        self.assertFalse(hypo_after["function_candidates"][0]["confirmed_root_cause"])

    def test_case_e_missing_quality_malformed_partial_non_atomic(self):
        """Case E: Evidence with missing capture_quality, PARTIAL quality, or NON_ATOMIC consistency fails closed."""
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Quality ceilings")
        inv_id = start["investigation_id"]
        session = mgr.sessions[inv_id]

        # 1. Missing capture quality
        rec_missing = EvidenceRecord(
            evidence_id="ev_missing_q",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="collector",
            session_id=inv_id,
            observation="Observed diff without quality metadata",
            capture_quality=None,
        )
        session.ledger.add_record(rec_missing)
        with self.assertRaises(ValueError):
            session.attest_causal_proof("ev_missing_q")

        # 2. PARTIAL capture completeness
        rec_partial = EvidenceRecord(
            evidence_id="ev_partial_q",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="collector",
            session_id=inv_id,
            observation="Observed diff under partial capture",
            capture_quality={"completeness": "PARTIAL", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec_partial)
        with self.assertRaises(ValueError):
            session.attest_causal_proof("ev_partial_q")

        # 3. NON_ATOMIC consistency
        rec_non_atomic = EvidenceRecord(
            evidence_id="ev_non_atomic_q",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="collector",
            session_id=inv_id,
            observation="Observed diff under non-atomic consistency",
            capture_quality={"completeness": "COMPLETE", "consistency_level": "NON_ATOMIC"},
        )
        session.ledger.add_record(rec_non_atomic)
        with self.assertRaises(ValueError):
            session.attest_causal_proof("ev_non_atomic_q")

    def test_case_f_complete_proof_with_degraded_parent(self):
        """Case F: A proof record is COMPLETE but has a PARTIAL/UNTRUSTED/missing parent; causal validation is rejected."""
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Degraded ancestry")
        inv_id = start["investigation_id"]
        session = mgr.sessions[inv_id]

        # Degraded parent (PARTIAL)
        rec_parent = EvidenceRecord(
            evidence_id="ev_parent_partial",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="collector",
            session_id=inv_id,
            observation="Parent diff under PARTIAL capture",
            capture_quality={"completeness": "PARTIAL", "consistency_level": "NON_ATOMIC"},
        )
        session.ledger.add_record(rec_parent)

        # Child proof is COMPLETE and attested
        rec_child = EvidenceRecord(
            evidence_id="ev_child_proof",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="collector",
            session_id=inv_id,
            observation="Child reproduction observation",
            parent_evidence_ids=["ev_parent_partial"],
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
            details={"target_function": "worker_mutate", "field_path": "obj.status"},
        )
        session.ledger.add_record(rec_child)
        session.attest_causal_proof("ev_child_proof", target_function="worker_mutate", field_path="obj.status")

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_f",
            investigation_id=inv_id,
            title="Degraded Ancestry",
            claim="Claim",
            proposed_mechanism="Mech",
            candidate_fields=["obj.status"],
            supporting_evidence_ids=["ev_parent_partial", "ev_child_proof"],
            function_candidates=[{
                "function_name": "worker_mutate",
                "candidate_tier": FUNCTION_TIER_EVIDENCE_SUPPORTED,
                "confirmed_root_cause": False,
            }],
        )
        session.hypotheses.append(hypo)

        res = mgr.evaluate_hypothesis(inv_id, "hypo_f", proof_evidence_id="ev_child_proof")
        self.assertEqual(res["transition"]["to_status"], HYPOTHESIS_STATUS_SUPPORTED)
        self.assertTrue(res["transition"]["unverified_claim_rejected"])
        self.assertIn("PARTIAL ancestor", res["transition"]["reason"])

        hypo_after = mgr.get_hypothesis(inv_id, "hypo_f")
        self.assertFalse(hypo_after["function_candidates"][0]["confirmed_root_cause"])

    def test_case_g_cross_investigation_and_mismatched_target(self):
        """Case G: Cross-investigation evidence IDs and mismatched target field/function are rejected."""
        mgr = InvestigationManager()
        start1 = mgr.start_investigation(goal="Session 1")
        inv_id1 = start1["investigation_id"]
        session1 = mgr.sessions[inv_id1]

        start2 = mgr.start_investigation(goal="Session 2")
        inv_id2 = start2["investigation_id"]
        session2 = mgr.sessions[inv_id2]

        rec_sess1 = EvidenceRecord(
            evidence_id="ev_sess1_proof",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="collector",
            session_id=inv_id1,
            observation="Observed diff in session 1",
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
            details={"target_function": "worker_fn", "field_path": "obj.flag"},
        )
        session1.ledger.add_record(rec_sess1)
        session1.attest_causal_proof("ev_sess1_proof", target_function="worker_fn", field_path="obj.flag")

        # Adversary attempts to attach session 1 proof into session 2
        session2.ledger._records.append(rec_sess1)
        session2.ledger._by_id["ev_sess1_proof"] = rec_sess1

        hypo2 = InvestigationHypothesis(
            hypothesis_id="hypo_g",
            investigation_id=inv_id2,
            title="Cross-Session",
            claim="Claim",
            proposed_mechanism="Mech",
            candidate_fields=["obj.flag"],
            supporting_evidence_ids=["ev_sess1_proof"],
            function_candidates=[{
                "function_name": "worker_fn",
                "candidate_tier": FUNCTION_TIER_EVIDENCE_SUPPORTED,
                "confirmed_root_cause": False,
            }],
        )
        session2.hypotheses.append(hypo2)

        res_cross = mgr.evaluate_hypothesis(inv_id2, "hypo_g", proof_evidence_id="ev_sess1_proof")
        self.assertEqual(res_cross["transition"]["to_status"], HYPOTHESIS_STATUS_SUPPORTED)
        self.assertTrue(res_cross["transition"]["unverified_claim_rejected"])
        self.assertIn("token", res_cross["transition"]["reason"].lower())

        # Mismatched target field check
        rec_mismatch = EvidenceRecord(
            evidence_id="ev_mismatch",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="collector",
            session_id=inv_id2,
            observation="Observed diff on different field",
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
            details={"target_function": "worker_fn", "field_path": "obj.totally_different_field"},
        )
        session2.ledger.add_record(rec_mismatch)
        session2.attest_causal_proof("ev_mismatch", target_function="worker_fn", field_path="obj.totally_different_field")
        hypo2.supporting_evidence_ids.append("ev_mismatch")

        res_field = mgr.evaluate_hypothesis(inv_id2, "hypo_g", proof_evidence_id="ev_mismatch")
        self.assertEqual(res_field["transition"]["to_status"], HYPOTHESIS_STATUS_SUPPORTED)
        self.assertTrue(res_field["transition"]["unverified_claim_rejected"])
        self.assertIn("target field", res_field["transition"]["reason"].lower())

    def test_case_h_forged_observation_execution_results(self):
        """Case H: Caller forges observation results claiming VALIDATED; execution disarms claim and prevents promotion."""
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Observation execution check", authorize_target=False)
        inv_id = start["investigation_id"]
        session = mgr.sessions[inv_id]

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_h",
            investigation_id=inv_id,
            title="Obs execution test",
            claim="Claim",
            proposed_mechanism="Mech",
            candidate_fields=["obj.val"],
            function_candidates=[{
                "function_name": "worker_run",
                "candidate_tier": FUNCTION_TIER_STATIC_CANDIDATE,
                "confirmed_root_cause": False,
            }],
            suggested_observations=[
                FollowUpObservation(
                    observation_id="obs_val_step",
                    hypothesis_id="hypo_h",
                    question="Verify obj.val",
                    target_kind="FIELD",
                    target_ref={"field_path": "obj.val"},
                    discriminating_criteria="",
                    expected_outcomes={},
                )
            ],
        )
        session.hypotheses.append(hypo)

        res_exec = mgr.execute_observation(
            inv_id,
            "obs_val_step",
            result_data={
                "outcome": "VALIDATED",
                "observation": "Deterministic transition reproduced in obj.val",
                "details": {"verified_transition": True, "causal_proof": True, "target_function": "worker_run"},
            },
        )
        self.assertTrue(res_exec["success"])
        ev_id = res_exec["evidence"]["evidence_id"]
        ev_rec = session.ledger.get_record(ev_id)
        self.assertTrue(ev_rec.details.get("unverified_caller_claim"))
        self.assertFalse(ev_rec.details.get("verified_transition"))
        self.assertEqual(ev_rec.source, "unverified_caller")

        hypo_after = mgr.get_hypothesis(inv_id, "hypo_h")
        self.assertEqual(hypo_after["validation_status"], HYPOTHESIS_STATUS_SUPPORTED)
        self.assertFalse(hypo_after["function_candidates"][0]["confirmed_root_cause"])

    def test_case_i_provenance_cycles_missing_parents_and_contradiction_dominance(self):
        """Case I: Provenance cycles, missing parents, and contradiction dominance are enforced without confidence drift."""
        # Cycle
        mgr_cyc, inv_id_cyc, hypo_id_cyc = CausalDefectFixtures.create_scenario_h_cyclic_missing_duplicate_evidence()
        res_cyc = mgr_cyc.evaluate_hypothesis(inv_id_cyc, hypo_id_cyc)
        self.assertTrue(res_cyc["transition"]["cycle_detected"])
        self.assertEqual(res_cyc["transition"]["to_status"], HYPOTHESIS_STATUS_INCONCLUSIVE)

        # Contradiction dominance
        mgr_contra, inv_id_contra, hypo_id_contra = CausalDefectFixtures.create_scenario_d_contradictory_evidence()
        rec_contra = mgr_contra.sessions[inv_id_contra].ledger.get_record("ev_d_contra")
        res_c1 = mgr_contra.evaluate_hypothesis(inv_id_contra, hypo_id_contra, new_evidence_data=rec_contra.to_dict())
        self.assertEqual(res_c1["transition"]["to_status"], HYPOTHESIS_STATUS_CONTRADICTED)

        # Repeated evaluation idempotency
        res_rep = mgr_contra.evaluate_hypothesis(inv_id_contra, hypo_id_contra, deterministic_transition_verified=True)
        self.assertEqual(res_rep["transition"]["to_status"], HYPOTHESIS_STATUS_CONTRADICTED)

    def test_case_j_legacy_serialized_evidence_cannot_upgrade(self):
        """Case J: Legacy serialized evidence with absent trust metadata cannot silently upgrade to trusted proof."""
        ledger = EvidenceLedger()
        legacy_data = {
            "evidence_id": "ev_legacy_42",
            "evidence_type": "COMPARISON",
            "nature": "observation",
            "source": "state_diff",
            "observation": "Legacy snapshot diff",
            "details": {"verified_transition": True, "causal_proof": True},
        }
        rec = EvidenceRecord.from_dict(legacy_data)
        ledger.add_record(rec)

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_j",
            investigation_id=ledger.session_id,
            title="Legacy check",
            claim="Claim",
            proposed_mechanism="Mech",
            supporting_evidence_ids=["ev_legacy_42"],
            function_candidates=[{
                "function_name": "legacy_fn",
                "candidate_tier": FUNCTION_TIER_STATIC_CANDIDATE,
                "confirmed_root_cause": False,
            }],
        )

        res = HypothesisValidator.evaluate(hypo, ledger, deterministic_transition_verified=True, proof_evidence_id="ev_legacy_42")
        self.assertEqual(res.to_status, HYPOTHESIS_STATUS_SUPPORTED)
        self.assertTrue(res.unverified_claim_rejected)
        self.assertFalse(hypo.function_candidates[0]["confirmed_root_cause"])

    def test_case_k_api_and_arp_injection_fails_safely(self):
        """Case K: API and ARP injection attempts fail safely without promoting candidate functions."""
        runtime = AgentRuntime()
        start = runtime.investigation_manager.start_investigation(goal="API ARP Security Boundary")
        inv_id = start["investigation_id"]
        session = runtime.investigation_manager.sessions[inv_id]

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_k",
            investigation_id=inv_id,
            title="API Hardening",
            claim="Claim",
            proposed_mechanism="Mech",
            candidate_fields=["security_flag"],
            function_candidates=[{
                "function_name": "security_handler",
                "candidate_tier": FUNCTION_TIER_STATIC_CANDIDATE,
                "confirmed_root_cause": False,
            }],
        )
        session.hypotheses.append(hypo)

        # 1. ARP injection
        act = AgentAction(
            action="EVALUATE_HYPOTHESIS",
            investigation_id=inv_id,
            hypothesis_id="hypo_k",
            deterministic_transition_verified=True,
            new_evidence={
                "source": "investigation_observer",
                "observation": "Deterministic transition reproduced",
                "details": {"verified_transition": True, "causal_proof": True, "target_function": "security_handler"},
                "capture_quality": {"completeness": "COMPLETE", "consistency_level": "STOPPED"},
            },
        )
        arp_res = runtime.dispatch_action(act)
        self.assertTrue(arp_res.success)
        self.assertEqual(arp_res.data["transition"]["to_status"], HYPOTHESIS_STATUS_SUPPORTED)
        self.assertTrue(arp_res.data["transition"]["unverified_claim_rejected"])

        # 2. REST WebApiAdapter injection
        adapter = WebApiAdapter(runtime)
        rest_res = adapter.evaluate_hypothesis({
            "investigation_id": inv_id,
            "hypothesis_id": "hypo_k",
            "deterministic_transition_verified": True,
            "new_evidence": {
                "source": "investigation_observer",
                "observation": "Deterministic transition reproduced",
                "details": {"verified_transition": True, "causal_proof": True},
                "capture_quality": {"completeness": "COMPLETE", "consistency_level": "STOPPED"},
            },
        })
        self.assertTrue(rest_res["success"])
        self.assertEqual(rest_res["data"]["transition"]["to_status"], HYPOTHESIS_STATUS_SUPPORTED)
        self.assertTrue(rest_res["data"]["transition"]["unverified_claim_rejected"])

        # 3. Malformed payload
        rest_err = adapter.evaluate_hypothesis({"investigation_id": inv_id})
        self.assertFalse(rest_err["success"])
        self.assertEqual(rest_err["error"]["code"], "INVALID_PARAM")

        hypo_after = runtime.investigation_manager.get_hypothesis(inv_id, "hypo_k")
        self.assertEqual(hypo_after["validation_status"], HYPOTHESIS_STATUS_SUPPORTED)
        self.assertFalse(hypo_after["function_candidates"][0]["confirmed_root_cause"])
        self.assertEqual(hypo_after["function_candidates"][0]["candidate_tier"], FUNCTION_TIER_STATIC_CANDIDATE)

    def test_case_l_legitimate_proof_in_divergent_writer_scenario(self):
        """Case L: Legitimate proof in divergent writer scenario validates real executing writer while keeping static candidate distinct."""
        mgr, inv_id, hypo_id = CausalDefectFixtures.create_scenario_c_different_writer_than_leading_candidate()
        res = mgr.evaluate_hypothesis(
            inv_id,
            hypo_id,
            deterministic_transition_verified=True,
            proof_evidence_id="ev_c_proof",
        )
        self.assertTrue(res["success"])
        self.assertEqual(res["transition"]["to_status"], HYPOTHESIS_STATUS_VALIDATED)

        hypo = mgr.get_hypothesis(inv_id, hypo_id)
        cands = hypo["function_candidates"]
        log_cand = next(c for c in cands if c["function_name"] == "log_status")
        upd_cand = next(c for c in cands if c["function_name"] == "update_flags")

        # log_status is purely static candidate
        self.assertEqual(log_cand["candidate_tier"], FUNCTION_TIER_STATIC_CANDIDATE)
        self.assertFalse(log_cand["confirmed_root_cause"])
        self.assertIn("not confirmed root-cause function", log_cand["tier_limitation"])

        # update_flags is genuine validated causal function
        self.assertEqual(upd_cand["candidate_tier"], FUNCTION_TIER_VALIDATED_CAUSAL)
        self.assertTrue(upd_cand["confirmed_root_cause"])
        self.assertIn("verified", upd_cand["tier_limitation"].lower())
        self.assertNotIn("not confirmed", upd_cand["tier_limitation"].lower())


class TestFalsePositiveEvaluationHarness(unittest.TestCase):
    """Test suite verifying the machine-readable false-positive evaluation harness."""

    def test_evaluation_harness_execution_and_zero_fp_sla(self):
        """Run the complete evaluation suite and assert zero false validations."""
        evaluator = CausalValidationEvaluator()
        report = evaluator.run_all()

        metrics = report["summary_metrics"]
        self.assertEqual(metrics["total_cases_evaluated"], 18)
        self.assertEqual(metrics["correct_causal_validations_tp"], 2)
        self.assertEqual(metrics["false_causal_validations_fp"], 0, "CRITICAL SLA BREACH: False causal validations must be 0!")
        self.assertEqual(metrics["missed_causal_validations_fn"], 0)
        self.assertEqual(metrics["correctly_inconclusive_or_rejected_tn"], 16)
        self.assertGreaterEqual(metrics["unsupported_promotions_blocked"], 6)
        self.assertEqual(metrics["causal_validation_precision"], 1.0)
        self.assertEqual(metrics["causal_validation_recall"], 1.0)
        self.assertEqual(metrics["false_positive_rate"], 0.0)
        self.assertTrue(metrics["zero_false_positives_sla_satisfied"])


if __name__ == "__main__":
    unittest.main()

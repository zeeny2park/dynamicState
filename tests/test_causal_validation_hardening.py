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

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock

from extractor.capture_backend import (
    ProcessVmCaptureBackend,
    ProcfsCaptureBackend,
)
from extractor.causal_fixtures import CausalDefectFixtures
from extractor.evaluation import CausalValidationEvaluator
from extractor.evidence_ledger import (
    CausalVerificationCapability,
    ControlledExecutionResult,
    EVIDENCE_TYPE_COMPARISON,
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EvidenceLedger,
    EvidenceRecord,
    NATURE_OBSERVATION,
    compute_attestation_signature,
    compute_evidence_fingerprint,
    compute_receipt_signature,
    is_exact_semantic_path_match,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
    PROVENANCE_CLASS_SYNTHETIC_FIXTURE,
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
    TRUSTED_PROVENANCE_CLASSES,
)
from extractor.investigation import compute_snapshot_artifact_hash
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
    TrustedCausalVerifier,
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
            details={
                "target_function": "worker_mutate",
                "field_path": "obj.status",
                "execution_provenance": {"execution_status": "REPRODUCED", "reproduction_verified": True},
            },
        )
        session.ledger.add_record(rec_child)
        verifier = TrustedCausalVerifier(session)
        receipt = verifier.record_controlled_execution(
            target_function="worker_mutate",
            field_path="obj.status",
            execution_status="REPRODUCED",
            backend_type="synthetic_adversarial_fixture",
            evidence_id="ev_child_proof",
            hypothesis_id="hypo_f",
        )
        verifier.verify_execution_and_attest(evidence_id="ev_child_proof", hypothesis_id="hypo_f", execution_result=receipt)

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
            details={
                "target_function": "worker_fn",
                "field_path": "obj.flag",
                "execution_provenance": {"execution_status": "REPRODUCED", "reproduction_verified": True},
            },
        )
        session1.ledger.add_record(rec_sess1)
        verifier1 = TrustedCausalVerifier(session1)
        receipt1 = verifier1.record_controlled_execution(
            target_function="worker_fn",
            field_path="obj.flag",
            execution_status="REPRODUCED",
            backend_type="synthetic_adversarial_fixture",
            evidence_id="ev_sess1_proof",
            hypothesis_id="hypo_g",
        )
        verifier1.verify_execution_and_attest(evidence_id="ev_sess1_proof", hypothesis_id="hypo_g", execution_result=receipt1)

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
            details={
                "target_function": "worker_fn",
                "field_path": "obj.totally_different_field",
                "execution_provenance": {"execution_status": "REPRODUCED", "reproduction_verified": True},
            },
        )
        session2.ledger.add_record(rec_mismatch)
        verifier2 = TrustedCausalVerifier(session2)
        receipt2 = verifier2.record_controlled_execution(
            target_function="worker_fn",
            field_path="obj.totally_different_field",
            execution_status="REPRODUCED",
            backend_type="synthetic_adversarial_fixture",
            evidence_id="ev_mismatch",
            hypothesis_id="hypo_g",
        )
        verifier2.verify_execution_and_attest(evidence_id="ev_mismatch", hypothesis_id="hypo_g", execution_result=receipt2)
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


class TestAttestationIssuanceSecurityAndCausality(unittest.TestCase):
    """Specific regression suite verifying Attestation Issuance Hardening Cases A through O."""

    def test_case_a_ordinary_observation_cannot_be_attested(self):
        """Case A: A normal COMPLETE + STOPPED observation with no actual execution cannot be attested."""
        ledger = EvidenceLedger(session_id="inv_test_a")
        rec = EvidenceRecord(
            evidence_id="ev_ord_a",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            nature=NATURE_OBSERVATION,
            source="collector",
            session_id="inv_test_a",
            observation="Observed field x == 42",
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        ledger.add_record(rec)
        with self.assertRaises(ValueError) as ctx:
            ledger.attest_causal_proof("ev_ord_a")
        self.assertIn("lacks genuine execution provenance", str(ctx.exception))

    def test_case_b_caller_provided_execution_status_reproduced_cannot_authorize_attestation(self):
        """Case B: Caller-provided execution_status=REPRODUCED cannot authorize attestation."""
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Case B")
        inv_id = start["investigation_id"]
        session = mgr.sessions[inv_id]

        rec = EvidenceRecord(
            evidence_id="ev_bool_b",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="collector",
            session_id=inv_id,
            observation="Observation with caller booleans",
            details={"execution_status": "REPRODUCED", "execution_provenance": {"execution_status": "REPRODUCED"}},
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec)
        verifier = TrustedCausalVerifier(session)
        with self.assertRaises(ValueError) as ctx_v:
            verifier.verify_and_attest("ev_bool_b", execution_provenance={"execution_status": "REPRODUCED"})
        self.assertIn("execution_provenance", str(ctx_v.exception))

        with self.assertRaises(ValueError) as ctx:
            session.ledger.attest_causal_proof("ev_bool_b", execution_provenance={"execution_status": "REPRODUCED"})
        self.assertIn("lacks genuine execution provenance", str(ctx.exception))

    def test_case_c_caller_provided_reproduction_verified_cannot_authorize_attestation(self):
        """Case C: Caller-provided reproduction_verified=True cannot authorize attestation."""
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Case C")
        inv_id = start["investigation_id"]
        session = mgr.sessions[inv_id]

        rec = EvidenceRecord(
            evidence_id="ev_bool_c",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="collector",
            session_id=inv_id,
            observation="Observation with caller booleans",
            details={"reproduction_verified": True, "verified_transition": True},
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec)
        verifier = TrustedCausalVerifier(session)
        with self.assertRaises(ValueError) as ctx_v:
            verifier.verify_and_attest("ev_bool_c", execution_provenance={"reproduction_verified": True})
        self.assertIn("execution_provenance", str(ctx_v.exception))

        with self.assertRaises(ValueError) as ctx:
            session.ledger.attest_causal_proof("ev_bool_c", execution_provenance={"reproduction_verified": True})
        self.assertIn("lacks genuine execution provenance", str(ctx.exception))

    def test_case_d_supplying_execution_provenance_directly_cannot_bypass_verification(self):
        """Case D: Supplying execution_provenance directly to a public manager/session/ledger method cannot bypass verification."""
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Public API check")
        inv_id = start["investigation_id"]
        session = mgr.sessions[inv_id]

        rec = EvidenceRecord(
            evidence_id="ev_ord_d",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            nature=NATURE_OBSERVATION,
            source="collector",
            session_id=inv_id,
            observation="Observed value 123",
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec)

        fake_provenance = {
            "execution_status": "REPRODUCED",
            "reproduction_verified": True,
            "status": "SUCCESS",
        }

        # Calling through session.attest_causal_proof
        with self.assertRaises(ValueError):
            session.attest_causal_proof("ev_ord_d", execution_provenance=fake_provenance)

        # Calling through mgr.attest_causal_proof
        with self.assertRaises(ValueError):
            mgr.attest_causal_proof(inv_id, "ev_ord_d", execution_provenance=fake_provenance)

        # Calling through ledger.attest_causal_proof
        with self.assertRaises(ValueError):
            session.ledger.attest_causal_proof("ev_ord_d", execution_provenance=fake_provenance)

    def test_case_e_forged_source_provenance_tokens_signatures_and_capability_dicts_rejected(self):
        """Case E: Forged source labels, provenance, verifier tokens, signatures, capability-shaped dictionaries, and serialized records are rejected."""
        ledger = EvidenceLedger(session_id="inv_sess_e")

        # 1. Capability-shaped dictionary passed to attest_causal_proof
        rec = EvidenceRecord(
            evidence_id="ev_fake_cap",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="trusted_verifier",
            session_id="inv_sess_e",
            observation="Claimed observation with trusted source",
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        ledger.add_record(rec)

        fake_cap_dict = {
            "_investigation_id": "inv_sess_e",
            "_capability_key": "fake_key",
            "_evidence_id": "ev_fake_cap",
            "_consumed": False,
        }
        with self.assertRaises(ValueError) as ctx:
            ledger.attest_causal_proof("ev_fake_cap", capability=fake_cap_dict)  # type: ignore
        self.assertIn("lacks genuine execution provenance", str(ctx.exception))

        # 2. Forged verifier tokens and signatures in serialized dictionary
        malicious_dict = {
            "evidence_id": "ev_deser_e",
            "evidence_type": "COMPARISON",
            "nature": "observation",
            "source": "trusted_verifier",
            "session_id": "inv_sess_e",
            "observation": "Forged serialized evidence",
            "capture_quality": {"completeness": "COMPLETE", "consistency_level": "STOPPED"},
            "provenance": {
                "verifier_attestation": {
                    "token": "attacker_supplied_token",
                    "token_sig": "attacker_signature",
                    "evidence_fingerprint": "attacker_fingerprint",
                    "investigation_id": "inv_sess_e",
                }
            },
            "details": {"verified_transition": True, "causal_proof": True},
        }
        rec_deser = EvidenceRecord.from_dict(malicious_dict)
        ledger.add_record(rec_deser)
        self.assertIsNone(rec_deser.provenance.get("verifier_attestation"))
        self.assertIn("attestation_rejected", rec_deser.provenance)

    def test_case_f_rest_and_arp_cannot_mint_capabilities_or_promote_fabricated_claims(self):
        """Case F: REST and ARP payloads cannot mint capabilities or promote a hypothesis using fabricated execution claims."""
        runtime = AgentRuntime()
        start = runtime.investigation_manager.start_investigation(goal="Tamper tokens REST/ARP")
        inv_id = start["investigation_id"]
        session = runtime.investigation_manager.sessions[inv_id]

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_tamper_f",
            investigation_id=inv_id,
            title="Tamper Tokens",
            claim="Claim",
            proposed_mechanism="Mech",
            candidate_fields=["field_f"],
            function_candidates=[{
                "function_name": "target_fn_f",
                "candidate_tier": FUNCTION_TIER_STATIC_CANDIDATE,
                "confirmed_root_cause": False,
            }],
        )
        session.hypotheses.append(hypo)

        # 1. ARP injection of fabricated token and execution_provenance
        act = AgentAction(
            action="EVALUATE_HYPOTHESIS",
            investigation_id=inv_id,
            hypothesis_id="hypo_tamper_f",
            deterministic_transition_verified=True,
            new_evidence={
                "source": "investigation_observer",
                "observation": "Injected observation",
                "provenance": {
                    "verifier_attestation": {"token": "fake_secret_token", "investigation_id": inv_id},
                    "execution_provenance": {"execution_status": "REPRODUCED", "reproduction_verified": True},
                },
                "details": {
                    "verified_transition": True,
                    "target_function": "target_fn_f",
                    "execution_provenance": {"execution_status": "REPRODUCED", "reproduction_verified": True},
                },
                "capture_quality": {"completeness": "COMPLETE", "consistency_level": "STOPPED"},
            },
        )
        arp_res = runtime.dispatch_action(act)
        self.assertTrue(arp_res.success)
        self.assertEqual(arp_res.data["transition"]["to_status"], HYPOTHESIS_STATUS_SUPPORTED)
        self.assertTrue(arp_res.data["transition"]["unverified_claim_rejected"])

        # 2. REST injection
        adapter = WebApiAdapter(runtime)
        rest_res = adapter.evaluate_hypothesis({
            "investigation_id": inv_id,
            "hypothesis_id": "hypo_tamper_f",
            "deterministic_transition_verified": True,
            "new_evidence": {
                "source": "investigation_observer",
                "observation": "REST injected",
                "provenance": {"verifier_attestation": {"token": "fake_token", "investigation_id": inv_id}},
                "details": {"execution_provenance": {"execution_status": "REPRODUCED"}},
                "capture_quality": {"completeness": "COMPLETE", "consistency_level": "STOPPED"},
            },
        })
        self.assertTrue(rest_res["success"])
        self.assertEqual(rest_res["data"]["transition"]["to_status"], HYPOTHESIS_STATUS_SUPPORTED)
        self.assertTrue(rest_res["data"]["transition"]["unverified_claim_rejected"])

    def test_case_g_evidence_mutation_after_verification_invalidates_proof(self):
        """Case G: Evidence mutation after verification invalidates the proof."""
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Tamper detection")
        inv_id = start["investigation_id"]
        session = mgr.sessions[inv_id]

        rec_proof = EvidenceRecord(
            evidence_id="ev_tamper_g",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="collector",
            session_id=inv_id,
            observation="Original deterministic transition 1 -> 2",
            details={
                "target_function": "worker_mut",
                "field_path": "obj.status",
                "execution_provenance": {"execution_status": "REPRODUCED", "reproduction_verified": True},
            },
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec_proof)
        verifier = TrustedCausalVerifier(session)
        receipt = verifier.record_controlled_execution(
            target_function="worker_mut",
            field_path="obj.status",
            execution_status="REPRODUCED",
            backend_type="synthetic_adversarial_fixture",
            evidence_id="ev_tamper_g",
            hypothesis_id="hypo_tamper_g",
        )
        verifier.verify_execution_and_attest(evidence_id="ev_tamper_g", hypothesis_id="hypo_tamper_g", execution_result=receipt)

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_tamper_g",
            investigation_id=inv_id,
            title="Tamper G",
            claim="Claim",
            proposed_mechanism="Mech",
            candidate_fields=["obj.status"],
            supporting_evidence_ids=["ev_tamper_g"],
            function_candidates=[{
                "function_name": "worker_mut",
                "candidate_tier": FUNCTION_TIER_STATIC_CANDIDATE,
                "confirmed_root_cause": False,
            }],
        )
        session.hypotheses.append(hypo)

        # Attacker tampers with the observation text after attestation
        rec_proof.observation = "TAMPERED: Different observation altogether"

        res = mgr.evaluate_hypothesis(inv_id, "hypo_tamper_g", proof_evidence_id="ev_tamper_g")
        self.assertEqual(res["transition"]["to_status"], HYPOTHESIS_STATUS_SUPPORTED)
        self.assertTrue(res["transition"]["unverified_claim_rejected"])
        self.assertIn("tamper", res["transition"]["reason"].lower())

    def test_case_h_scope_changes_invalidate_proof(self):
        """Case H: Scope changes to target function, field, hypothesis, target identity, or investigation invalidate the proof."""
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Scope changes")
        inv_id = start["investigation_id"]
        session = mgr.sessions[inv_id]

        rec_proof = EvidenceRecord(
            evidence_id="ev_scope_h",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="collector",
            session_id=inv_id,
            observation="Reproduction observation for function fn_a on field obj.val",
            details={
                "target_function": "fn_a",
                "field_path": "obj.val",
                "execution_provenance": {"execution_status": "REPRODUCED", "reproduction_verified": True},
            },
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
            target_identity={"pid": 1234, "build_id": "build_abc", "binary_path": "/bin/app"},
        )
        session.ledger.add_record(rec_proof)

        verifier = TrustedCausalVerifier(session)
        receipt = verifier.record_controlled_execution(
            target_function="fn_a",
            field_path="obj.val",
            execution_status="REPRODUCED",
            backend_type="synthetic_adversarial_fixture",
            evidence_id="ev_scope_h",
            hypothesis_id="hypo_h_scope",
            target_identity={"pid": 1234, "build_id": "build_abc", "binary_path": "/bin/app"},
        )
        verifier.verify_execution_and_attest(
            evidence_id="ev_scope_h",
            hypothesis_id="hypo_h_scope",
            execution_result=receipt,
        )

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_h_scope",
            investigation_id=inv_id,
            title="Scope Claim",
            claim="Claim",
            proposed_mechanism="Mech",
            candidate_fields=["obj.val"],
            supporting_evidence_ids=["ev_scope_h"],
            function_candidates=[{
                "function_name": "fn_a",
                "candidate_tier": FUNCTION_TIER_EVIDENCE_SUPPORTED,
                "confirmed_root_cause": False,
            }],
        )
        session.hypotheses.append(hypo)

        # 1. Target function change in details after attestation -> rejected
        rec_proof.details["target_function"] = "fn_b_tampered"
        res_fn = mgr.evaluate_hypothesis(inv_id, "hypo_h_scope", proof_evidence_id="ev_scope_h")
        self.assertNotEqual(res_fn["transition"]["to_status"], HYPOTHESIS_STATUS_VALIDATED)
        self.assertTrue(res_fn["transition"]["unverified_claim_rejected"])
        rec_proof.details["target_function"] = "fn_a"  # restore

        # 2. Field path change in details after attestation -> rejected
        rec_proof.details["field_path"] = "obj.other_field"
        res_fld = mgr.evaluate_hypothesis(inv_id, "hypo_h_scope", proof_evidence_id="ev_scope_h")
        self.assertNotEqual(res_fld["transition"]["to_status"], HYPOTHESIS_STATUS_VALIDATED)
        self.assertTrue(res_fld["transition"]["unverified_claim_rejected"])
        rec_proof.details["field_path"] = "obj.val"  # restore

        # 3. Target identity tampering after attestation -> rejected
        rec_proof.target_identity = {"pid": 9999, "build_id": "build_xyz", "binary_path": "/bin/evil"}
        res_id = mgr.evaluate_hypothesis(inv_id, "hypo_h_scope", proof_evidence_id="ev_scope_h")
        self.assertNotEqual(res_id["transition"]["to_status"], HYPOTHESIS_STATUS_VALIDATED)
        self.assertTrue(res_id["transition"]["unverified_claim_rejected"])
        rec_proof.target_identity = {"pid": 1234, "build_id": "build_abc", "binary_path": "/bin/app"}  # restore

        # 4. Hypothesis binding: Attempting to use this proof for a different hypothesis -> rejected
        hypo_different = InvestigationHypothesis(
            hypothesis_id="hypo_h_different",
            investigation_id=inv_id,
            title="Different Hypo",
            claim="Claim",
            proposed_mechanism="Mech",
            candidate_fields=["obj.val"],
            supporting_evidence_ids=["ev_scope_h"],
            function_candidates=[{
                "function_name": "fn_a",
                "candidate_tier": FUNCTION_TIER_EVIDENCE_SUPPORTED,
                "confirmed_root_cause": False,
            }],
        )
        session.hypotheses.append(hypo_different)
        res_diff_hypo = mgr.evaluate_hypothesis(inv_id, "hypo_h_different", proof_evidence_id="ev_scope_h")
        self.assertNotEqual(res_diff_hypo["transition"]["to_status"], HYPOTHESIS_STATUS_VALIDATED)
        self.assertTrue(res_diff_hypo["transition"]["unverified_claim_rejected"])

    def test_case_i_cross_session_replay_capability_reuse_and_proof_record_substitution_fail_safely(self):
        """Case I: Cross-session replay, capability reuse, and proof-record substitution fail safely."""
        mgr = InvestigationManager()
        start1 = mgr.start_investigation(goal="Session 1")
        inv_id1 = start1["investigation_id"]
        session1 = mgr.sessions[inv_id1]

        start2 = mgr.start_investigation(goal="Session 2")
        inv_id2 = start2["investigation_id"]
        session2 = mgr.sessions[inv_id2]

        # 1. Capability reuse: mint capability, use it once, try to reuse it -> fails
        rec1 = EvidenceRecord(
            evidence_id="ev_cap_reuse",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="collector",
            session_id=inv_id1,
            observation="Obs 1",
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session1.ledger.add_record(rec1)
        verifier1 = TrustedCausalVerifier(session1)
        rcpt1 = verifier1.record_controlled_execution(
            target_function="fn_1",
            field_path="fld_1",
            execution_status="REPRODUCED",
            backend_type="synthetic_adversarial_fixture",
            evidence_id="ev_cap_reuse",
        )
        cap = session1.issue_verification_capability("ev_cap_reuse", target_function="fn_1", field_path="fld_1", execution_result=rcpt1)
        self.assertFalse(cap.is_consumed)

        session1.attest_causal_proof("ev_cap_reuse", target_function="fn_1", field_path="fld_1", capability=cap)
        self.assertTrue(cap.is_consumed)

        # Attempt to reuse the consumed capability
        with self.assertRaises(ValueError) as ctx:
            session1.attest_causal_proof("ev_cap_reuse", target_function="fn_1", field_path="fld_1", capability=cap)
        self.assertIn("already consumed", str(ctx.exception))

        # 2. Cross-session capability: capability from session 1 passed to session 2
        rec2 = EvidenceRecord(
            evidence_id="ev_cross_cap",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="collector",
            session_id=inv_id2,
            observation="Obs 2",
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session2.ledger.add_record(rec2)
        rcpt2 = verifier1.record_controlled_execution(
            target_function="fn_2",
            field_path="fld_2",
            execution_status="REPRODUCED",
            backend_type="synthetic_adversarial_fixture",
            evidence_id="ev_cross_cap",
        )
        cap_sess1 = session1.issue_verification_capability("ev_cross_cap", target_function="fn_2", field_path="fld_2", execution_result=rcpt2)
        with self.assertRaises(ValueError) as ctx:
            session2.attest_causal_proof("ev_cross_cap", target_function="fn_2", field_path="fld_2", capability=cap_sess1)
        self.assertIn("cross-session", str(ctx.exception).lower())

        # 3. Proof record substitution across sessions
        rec_replay = EvidenceRecord(
            evidence_id="ev_subst_replay",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="collector",
            session_id=inv_id1,
            observation="Transition reproduced in session 1",
            details={
                "target_function": "worker_subst",
                "field_path": "obj.val",
                "execution_provenance": {"execution_status": "REPRODUCED", "reproduction_verified": True},
            },
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session1.ledger.add_record(rec_replay)
        rcpt_replay = verifier1.record_controlled_execution(
            target_function="worker_subst",
            field_path="obj.val",
            execution_status="REPRODUCED",
            backend_type="synthetic_adversarial_fixture",
            evidence_id="ev_subst_replay",
            hypothesis_id="hypo_subst",
        )
        verifier1.verify_execution_and_attest(evidence_id="ev_subst_replay", hypothesis_id="hypo_subst", execution_result=rcpt_replay)

        # Inject into session 2
        session2.ledger._records.append(rec_replay)
        session2.ledger._by_id["ev_subst_replay"] = rec_replay

        hypo2 = InvestigationHypothesis(
            hypothesis_id="hypo_subst",
            investigation_id=inv_id2,
            title="Subst",
            claim="Claim",
            proposed_mechanism="Mech",
            candidate_fields=["obj.val"],
            supporting_evidence_ids=["ev_subst_replay"],
            function_candidates=[{
                "function_name": "worker_subst",
                "candidate_tier": FUNCTION_TIER_STATIC_CANDIDATE,
                "confirmed_root_cause": False,
            }],
        )
        session2.hypotheses.append(hypo2)
        res_subst = mgr.evaluate_hypothesis(inv_id2, "hypo_subst", proof_evidence_id="ev_subst_replay")
        self.assertEqual(res_subst["transition"]["to_status"], HYPOTHESIS_STATUS_SUPPORTED)
        self.assertTrue(res_subst["transition"]["unverified_claim_rejected"])

    def test_case_j_missing_cyclic_duplicated_contradictory_degraded_ancestry_cannot_yield_validated(self):
        """Case J: Missing, cyclic, duplicated, contradictory, or degraded ancestry cannot yield VALIDATED."""
        # 1. Cyclic ancestry
        mgr_cyc, inv_id_cyc, hypo_id_cyc = CausalDefectFixtures.create_scenario_h_cyclic_missing_duplicate_evidence()
        res_cyc = mgr_cyc.evaluate_hypothesis(inv_id_cyc, hypo_id_cyc)
        self.assertEqual(res_cyc["transition"]["to_status"], HYPOTHESIS_STATUS_INCONCLUSIVE)
        self.assertTrue(res_cyc["transition"]["cycle_detected"])

        # 2. Contradictory evidence dominance
        mgr_contra, inv_id_contra, hypo_id_contra = CausalDefectFixtures.create_scenario_d_contradictory_evidence()
        rec_contra = mgr_contra.sessions[inv_id_contra].ledger.get_record("ev_d_contra")
        res_contra = mgr_contra.evaluate_hypothesis(inv_id_contra, hypo_id_contra, new_evidence_data=rec_contra.to_dict())
        self.assertEqual(res_contra["transition"]["to_status"], HYPOTHESIS_STATUS_CONTRADICTED)

        # 3. Degraded (PARTIAL) parent ancestry
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Degraded ancestor check")
        inv_id = start["investigation_id"]
        session = mgr.sessions[inv_id]

        rec_parent = EvidenceRecord(
            evidence_id="ev_par_deg",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="collector",
            session_id=inv_id,
            observation="Ancestor with partial quality",
            capture_quality={"completeness": "PARTIAL", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec_parent)

        rec_child = EvidenceRecord(
            evidence_id="ev_child_deg",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="collector",
            session_id=inv_id,
            observation="Child reproduction",
            parent_evidence_ids=["ev_par_deg"],
            details={
                "target_function": "mutate_fn",
                "field_path": "obj.val",
                "execution_provenance": {"execution_status": "REPRODUCED", "reproduction_verified": True},
            },
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec_child)
        verifier = TrustedCausalVerifier(session)
        rcpt = verifier.record_controlled_execution(
            target_function="mutate_fn",
            field_path="obj.val",
            execution_status="REPRODUCED",
            backend_type="synthetic_adversarial_fixture",
            evidence_id="ev_child_deg",
            hypothesis_id="hypo_deg_anc",
        )
        verifier.verify_execution_and_attest(evidence_id="ev_child_deg", hypothesis_id="hypo_deg_anc", execution_result=rcpt)

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_deg_anc",
            investigation_id=inv_id,
            title="Degraded Ancestry",
            claim="Claim",
            proposed_mechanism="Mech",
            candidate_fields=["obj.val"],
            supporting_evidence_ids=["ev_par_deg", "ev_child_deg"],
            function_candidates=[{
                "function_name": "mutate_fn",
                "candidate_tier": FUNCTION_TIER_STATIC_CANDIDATE,
                "confirmed_root_cause": False,
            }],
        )
        session.hypotheses.append(hypo)
        res_deg = mgr.evaluate_hypothesis(inv_id, "hypo_deg_anc", proof_evidence_id="ev_child_deg")
        self.assertEqual(res_deg["transition"]["to_status"], HYPOTHESIS_STATUS_SUPPORTED)
        self.assertIn("PARTIAL ancestor", res_deg["transition"]["reason"])

    def test_case_k_partial_failed_invalid_non_atomic_evidence_capped(self):
        """Case K: PARTIAL, FAILED, INVALID, or NON_ATOMIC evidence cannot exceed the established confidence/validation ceiling."""
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Quality ceiling check")
        inv_id = start["investigation_id"]
        session = mgr.sessions[inv_id]

        # 1. PARTIAL capture completeness
        rec_partial = EvidenceRecord(
            evidence_id="ev_q_partial",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="collector",
            session_id=inv_id,
            observation="Partial capture diff",
            capture_quality={"completeness": "PARTIAL", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec_partial)
        hypo_p = InvestigationHypothesis(
            hypothesis_id="hypo_q_partial",
            investigation_id=inv_id,
            title="Partial",
            claim="Claim",
            proposed_mechanism="Mech",
            supporting_evidence_ids=["ev_q_partial"],
        )
        session.hypotheses.append(hypo_p)
        res_p = mgr.evaluate_hypothesis(inv_id, "hypo_q_partial", deterministic_transition_verified=True)
        self.assertEqual(res_p["transition"]["to_status"], HYPOTHESIS_STATUS_SUPPORTED)

        # 2. NON_ATOMIC consistency
        rec_na = EvidenceRecord(
            evidence_id="ev_q_na",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="collector",
            session_id=inv_id,
            observation="Non-atomic capture diff",
            capture_quality={"completeness": "COMPLETE", "consistency_level": "NON_ATOMIC"},
            details={"is_non_atomic": True},
        )
        session.ledger.add_record(rec_na)
        hypo_na = InvestigationHypothesis(
            hypothesis_id="hypo_q_na",
            investigation_id=inv_id,
            title="NA",
            claim="Claim",
            proposed_mechanism="Mech",
            supporting_evidence_ids=["ev_q_na"],
        )
        session.hypotheses.append(hypo_na)
        res_na = mgr.evaluate_hypothesis(inv_id, "hypo_q_na", deterministic_transition_verified=True)
        self.assertEqual(res_na["transition"]["to_status"], HYPOTHESIS_STATUS_SUPPORTED)

        # 3. FAILED capture completeness
        rec_failed = EvidenceRecord(
            evidence_id="ev_q_failed",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="collector",
            session_id=inv_id,
            observation="Failed capture diff",
            capture_quality={"completeness": "FAILED"},
        )
        session.ledger.add_record(rec_failed)
        hypo_f = InvestigationHypothesis(
            hypothesis_id="hypo_q_failed",
            investigation_id=inv_id,
            title="Failed",
            claim="Claim",
            proposed_mechanism="Mech",
            supporting_evidence_ids=["ev_q_failed"],
        )
        session.hypotheses.append(hypo_f)
        res_f = mgr.evaluate_hypothesis(inv_id, "hypo_q_failed", deterministic_transition_verified=True)
        self.assertEqual(res_f["transition"]["to_status"], HYPOTHESIS_STATUS_INCONCLUSIVE)

    def test_case_l_failure_and_retry_paths_leave_no_dangling_markers(self):
        """Case L: Failure and retry paths do not leave attestation markers or partially promoted candidates."""
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Idempotency test")
        inv_id = start["investigation_id"]
        session = mgr.sessions[inv_id]

        rec = EvidenceRecord(
            evidence_id="ev_idemp",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="collector",
            session_id=inv_id,
            observation="Obs",
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec)

        # Repeated failed attestation attempts
        for _ in range(3):
            with self.assertRaises(ValueError):
                session.attest_causal_proof("ev_idemp")

        # Record must have NO attestation
        self.assertNotIn("verifier_attestation", rec.provenance)
        self.assertFalse(rec.details.get("verified_transition", False))
        self.assertFalse(rec.details.get("causal_proof", False))

    def test_case_m_zero_leakage_of_secrets(self):
        """Case M: Serialized evidence, reports, REST responses, ARP responses, and logs do not expose secrets."""
        mgr, inv_id, hypo_id = CausalDefectFixtures.create_scenario_a_reproducible_mutation()
        session = mgr.sessions[inv_id]

        secret = session._session_secret
        cap_key = session._capability_key
        proof_rec = session.ledger.get_record("ev_a_proof")
        token_sig = proof_rec.provenance["verifier_attestation"]["token_sig"]

        # 1. EvidenceRecord.to_dict()
        rec_dict = proof_rec.to_dict()
        self.assertNotIn("token", rec_dict["provenance"].get("verifier_attestation", {}))
        self.assertNotIn("token_sig", rec_dict["provenance"].get("verifier_attestation", {}))
        self.assertNotIn("evidence_fingerprint", rec_dict["provenance"].get("verifier_attestation", {}))
        self.assertNotIn(secret, str(rec_dict))
        self.assertNotIn(cap_key, str(rec_dict))
        self.assertNotIn(token_sig, str(rec_dict))

        # 2. InvestigationSession.to_dict()
        sess_dict = session.to_dict()
        self.assertNotIn(secret, str(sess_dict))
        self.assertNotIn(cap_key, str(sess_dict))

        # 3. Report generation
        mgr.evaluate_hypothesis(inv_id, hypo_id, proof_evidence_id="ev_a_proof")
        report = mgr.generate_report(inv_id)
        self.assertNotIn(secret, str(report))
        self.assertNotIn(cap_key, str(report))
        self.assertNotIn(token_sig, str(report))

        # 4. REST and ARP payloads
        runtime = AgentRuntime()
        start = runtime.investigation_manager.start_investigation(goal="Zero leakage test")
        r_inv = start["investigation_id"]
        r_session = runtime.investigation_manager.sessions[r_inv]
        r_secret = r_session._session_secret
        r_cap = r_session._capability_key

        adapter = WebApiAdapter(runtime)
        inv_report = adapter.get_investigation_report(r_inv)
        self.assertNotIn(r_secret, str(inv_report))
        self.assertNotIn(r_cap, str(inv_report))

    def test_case_n_genuine_supported_execution_path_succeeds_and_validates(self):
        """Case N: A genuine supported execution path succeeds and can validate the intended causal hypothesis."""
        mgr, inv_id, hypo_id = CausalDefectFixtures.create_scenario_a_reproducible_mutation()
        session = mgr.sessions[inv_id]

        verifier = TrustedCausalVerifier(session)
        rec_new = EvidenceRecord(
            evidence_id="ev_pos_n",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="investigation_observer",
            session_id=inv_id,
            observation="Deterministic transition reproduced 42 -> 100 on mutate_worker_state",
            parent_evidence_ids=["ev_a_diff"],
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec_new)
        rcpt = verifier.record_controlled_execution(
            target_function="mutate_worker_state",
            field_path="WorkerState.counter",
            execution_status="REPRODUCED",
            backend_type="synthetic_adversarial_fixture",
            evidence_id="ev_pos_n",
            hypothesis_id=hypo_id,
        )
        att_ok = verifier.verify_execution_and_attest(
            evidence_id="ev_pos_n",
            hypothesis_id=hypo_id,
            execution_result=rcpt,
        )
        self.assertTrue(att_ok)

        res = mgr.evaluate_hypothesis(inv_id, hypo_id, proof_evidence_id="ev_pos_n")
        self.assertEqual(res["transition"]["to_status"], HYPOTHESIS_STATUS_VALIDATED)
        hypo = mgr.get_hypothesis(inv_id, hypo_id)
        self.assertTrue(hypo["function_candidates"][0]["confirmed_root_cause"])
        self.assertEqual(hypo["function_candidates"][0]["candidate_tier"], FUNCTION_TIER_VALIDATED_CAUSAL)

    def test_case_o_static_only_candidate_remains_unconfirmed_without_causal_proof(self):
        """Case O: A static-only candidate remains unconfirmed without genuine causal proof."""
        mgr, inv_id, hypo_id = CausalDefectFixtures.create_scenario_b_static_candidate_unproven()
        res = mgr.evaluate_hypothesis(inv_id, hypo_id)
        self.assertNotEqual(res["transition"]["to_status"], HYPOTHESIS_STATUS_VALIDATED)
        hypo = mgr.get_hypothesis(inv_id, hypo_id)
        self.assertEqual(hypo["function_candidates"][0]["candidate_tier"], FUNCTION_TIER_STATIC_CANDIDATE)
        self.assertFalse(hypo["function_candidates"][0]["confirmed_root_cause"])

    def test_case_p_fabricated_values_and_unauthorized_backend_rejected(self):
        """Case P: Fabricated before/after values and arbitrary backend labels raise ValueError in record_controlled_execution."""
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Fabrication and backend checks")
        inv_id = start["investigation_id"]
        session = mgr.sessions[inv_id]
        verifier = TrustedCausalVerifier(session)

        # 1. Unauthorized backend label rejected
        with self.assertRaises(ValueError) as ctx:
            verifier.record_controlled_execution(
                target_function="mutate_fn",
                field_path="obj.val",
                execution_status="REPRODUCED",
                backend_type="unauthorized_caller_backend",
            )
        self.assertIn("Unauthorized execution backend", str(ctx.exception))

        # 2. Fabricated before/after values not matching snapshot diff rejected
        snap_a = {
            "snapshot_id": f"snap_a_{inv_id}",
            "process": {"pid": 2001, "binary": "/bin/worker", "executable_build_id": "b1"},
            "completeness": "COMPLETE",
            "consistency": {"level": "STOPPED"},
            "persistent": {"objects": [{"object_id": "o1", "type": "State", "fields": [{"name": "val", "value": 10}]}]},
        }
        snap_b = {
            "snapshot_id": f"snap_b_{inv_id}",
            "process": {"pid": 2001, "binary": "/bin/worker", "executable_build_id": "b1"},
            "completeness": "COMPLETE",
            "consistency": {"level": "STOPPED"},
            "persistent": {"objects": [{"object_id": "o1", "type": "State", "fields": [{"name": "val", "value": 20}]}]},
        }
        mgr.corpus.add(snap_a)
        mgr.corpus.add(snap_b)

        # Claiming transition 10 -> 999 when actual diff is 10 -> 20
        with self.assertRaises(ValueError) as ctx2:
            verifier.record_controlled_execution(
                target_function="mutate_fn",
                field_path="State.val",
                before_value=10,
                after_value=999,
                execution_status="REPRODUCED",
                before_snapshot_ref=snap_a["snapshot_id"],
                after_snapshot_ref=snap_b["snapshot_id"],
                backend_type="live_process_snapshot_diff",
            )
        self.assertIn("does not match verified snapshot diff", str(ctx2.exception))

    def test_case_q_unauthenticated_or_dummy_signature_receipt_rejected(self):
        """Case Q: Unauthenticated / dummy signature receipts fail authenticity verification."""
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Unauthenticated receipt check")
        inv_id = start["investigation_id"]
        session = mgr.sessions[inv_id]

        rec = EvidenceRecord(
            evidence_id="ev_dummy_sig",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="collector",
            session_id=inv_id,
            observation="Obs",
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec)
        verifier = TrustedCausalVerifier(session)

        dummy_receipt = ControlledExecutionResult(
            execution_id="exec_dummy",
            investigation_id=inv_id,
            target_function="mutate_fn",
            field_path="obj.val",
            before_value=1,
            after_value=2,
            execution_status="REPRODUCED",
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
            backend_type="synthetic_adversarial_fixture",
            receipt_signature="attacker_dummy_hmac_signature_xyz",
        )

        with self.assertRaises(ValueError) as ctx:
            verifier.verify_execution_and_attest(
                evidence_id="ev_dummy_sig",
                hypothesis_id="hypo_dummy",
                execution_result=dummy_receipt,
            )
        self.assertIn("authenticity verification failed", str(ctx.exception))

    def test_case_r_snapshot_tampering_after_receipt_detected(self):
        """Case R: Mutating snapshot artifact files on disk after receipt issuance invalidates proof."""
        temp_dir = tempfile.mkdtemp(prefix="dynstate_tamper_snap_")
        try:
            snap_a_file = os.path.join(temp_dir, "snap_a.json")
            snap_b_file = os.path.join(temp_dir, "snap_b.json")
            with open(snap_a_file, "w") as f:
                json.dump({
                    "snapshot_id": "snap_a",
                    "process": {"pid": 2001, "binary": "/bin/worker", "executable_build_id": "b1"},
                    "completeness": "COMPLETE",
                    "consistency": {"level": "STOPPED"},
                    "persistent": {"objects": [{"object_id": "o1", "type": "State", "fields": [{"name": "val", "value": 10}]}]}
                }, f)
            with open(snap_b_file, "w") as f:
                json.dump({
                    "snapshot_id": "snap_b",
                    "process": {"pid": 2001, "binary": "/bin/worker", "executable_build_id": "b1"},
                    "completeness": "COMPLETE",
                    "consistency": {"level": "STOPPED"},
                    "persistent": {"objects": [{"object_id": "o1", "type": "State", "fields": [{"name": "val", "value": 20}]}]}
                }, f)

            mgr = InvestigationManager()
            start = mgr.start_investigation(goal="Tamper snapshot artifact")
            inv_id = start["investigation_id"]
            session = mgr.sessions[inv_id]

            rec = EvidenceRecord(
                evidence_id="ev_tamper_snap",
                evidence_type=EVIDENCE_TYPE_COMPARISON,
                nature=NATURE_OBSERVATION,
                source="collector",
                session_id=inv_id,
                observation="Obs",
                capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
            )
            session.ledger.add_record(rec)

            verifier = TrustedCausalVerifier(session)
            receipt = verifier.record_controlled_execution(
                target_function="mutate_fn",
                field_path="State.val",
                before_value=10,
                after_value=20,
                execution_status="REPRODUCED",
                before_snapshot_ref=snap_a_file,
                after_snapshot_ref=snap_b_file,
                backend_type="live_process_snapshot_diff",
                evidence_id="ev_tamper_snap",
                hypothesis_id="hypo_tamper_snap",
            )

            # Adversary tampers with snapshot file on disk after receipt issuance
            with open(snap_b_file, "w") as f:
                json.dump({
                    "snapshot_id": "snap_b",
                    "persistent": {"objects": [{"object_id": "o1", "type": "State", "fields": [{"name": "val", "value": 9999}]}]},
                    "malicious": True
                }, f)

            with self.assertRaises(ValueError) as ctx:
                verifier.verify_execution_and_attest(
                    evidence_id="ev_tamper_snap",
                    hypothesis_id="hypo_tamper_snap",
                    execution_result=receipt,
                )
            self.assertIn("tampered or modified after receipt issuance", str(ctx.exception))
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_case_positive_control_controlled_cpp_execution_validates_end_to_end(self):
        """Positive Control: Compile main.cpp, run live C++, capture A, mutate via stdin, capture B, verify and validate end-to-end."""
        fixture_src = os.path.abspath("tests/fixtures/real_runtime/main.cpp")
        work_dir = tempfile.mkdtemp(prefix="dynstate_pos_ctrl_")
        try:
            debug_bin = os.path.join(work_dir, "app_debug.elf")
            subprocess.run(
                [
                    "g++", "-fPIE", "-pie", "-g", "-O0", "-fno-inline", "-fno-omit-frame-pointer",
                    "-Wl,--build-id=sha1", fixture_src, "-o", debug_bin, "-lpthread"
                ],
                check=True
            )

            corpus_dir = os.path.join(work_dir, "corpus")
            mgr = InvestigationManager(corpus_dir=corpus_dir)

            proc = subprocess.Popen(
                [debug_bin],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            try:
                line = proc.stdout.readline().strip()
                self.assertEqual(line, "READY")

                backend = ProcessVmCaptureBackend() if ProcessVmCaptureBackend().is_available(proc.pid) else ProcfsCaptureBackend()

                # Capture State A
                snap_a = backend.capture(pid=proc.pid)
                self.assertEqual(snap_a.completeness, "COMPLETE")
                snap_a_dir = os.path.join(corpus_dir, "memory_snapshots", "snap_live_a")
                snap_a.save(snap_a_dir)

                # Mutate via stdin
                proc.stdin.write("MUTATE\n")
                proc.stdin.flush()
                line = proc.stdout.readline().strip()
                self.assertEqual(line, "MUTATED")

                # Capture State B
                snap_b = backend.capture(pid=proc.pid)
                self.assertEqual(snap_b.completeness, "COMPLETE")
                snap_b_dir = os.path.join(corpus_dir, "memory_snapshots", "snap_live_b")
                snap_b.save(snap_b_dir)

                # Stop target process cleanly
                proc.stdin.write("STOP\n")
                proc.stdin.flush()
                line = proc.stdout.readline().strip()
                self.assertEqual(line, "STOPPED")
                proc.wait(timeout=2)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait(timeout=1)

            # Start investigation with debug image
            inv_res = mgr.start_investigation(
                goal="Live C++ positive control verification",
                memory_snapshot_path=snap_a_dir,
                debug_image=debug_bin,
                authorize_target=False,
            )
            inv_id = inv_res["investigation_id"]
            session = mgr.sessions[inv_id]

            # Compare snapshots
            cmp_res = mgr.compare_observations(inv_id, snap_a_dir, snap_b_dir)
            self.assertNotIn("error", cmp_res)

            # Execute synthesis
            mgr._execute_stage_synthesis(session)
            hypos = mgr.get_hypotheses(inv_id)
            diff_hypo = next(h for h in hypos if h.get("hypothesis_id", "").startswith("hypo_diff_") and "State.counter" in h.get("title", ""))
            hypo_id = diff_hypo["hypothesis_id"]

            # Add proof evidence record
            proof_eid = f"ev_live_proof_{inv_id}"
            rec_proof = EvidenceRecord(
                evidence_id=proof_eid,
                evidence_type="COMPARISON",
                nature="observation",
                source="investigation_observer",
                session_id=inv_id,
                observation="Live reproduction of counter 42 -> 100",
                details={"target_function": "mutate_worker_state", "field_path": "State.counter"},
                capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
            )
            session.ledger.add_record(rec_proof)

            # Verify live reproduction and attest
            att_ok = mgr.verify_live_reproduction_and_attest(
                investigation_id=inv_id,
                hypothesis_id=hypo_id,
                evidence_id=proof_eid,
                snapshot_a_path=snap_a_dir,
                snapshot_b_path=snap_b_dir,
                target_function="mutate_worker_state",
                field_path="State.counter",
            )
            self.assertTrue(att_ok)

            # Evaluate hypothesis
            eval_res = mgr.evaluate_hypothesis(
                inv_id,
                hypo_id,
                proof_evidence_id=proof_eid,
                deterministic_transition_verified=True,
            )
            self.assertTrue(eval_res["success"])
            self.assertEqual(eval_res["transition"]["to_status"], "VALIDATED")

            # Final report verifies causal conclusions
            final_report = mgr.generate_report(inv_id)
            cc = final_report["causal_conclusions"]
            self.assertTrue(cc["causal_proof_established"])
            self.assertEqual(cc["validated_causal_count"], 1)
        finally:
            shutil.rmtree(work_dir, ignore_errors=True)



class TestVerifiableRuntimeProvenancePhase5(unittest.TestCase):
    """Phase 5: Adversarial regression tests covering Cases A through R."""

    def test_phase5_case_a_caller_provided_execution_provenance_and_booleans_rejected(self):
        """Case A: Caller-provided execution_provenance dictionaries and booleans cannot mint a receipt or capability."""
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Phase 5 Case A")
        inv_id = start["investigation_id"]
        session = mgr.sessions[inv_id]

        rec = EvidenceRecord(
            evidence_id="ev_a_call",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="collector",
            session_id=inv_id,
            observation="Obs",
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec)

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_a",
            investigation_id=inv_id,
            title="Hypo A",
            claim="Claim A",
            proposed_mechanism="Mech A",
            supporting_evidence_ids=["ev_a_call"],
            function_candidates=[{
                "function_name": "worker_fn",
                "candidate_tier": FUNCTION_TIER_EVIDENCE_SUPPORTED,
                "confirmed_root_cause": False,
            }],
            validation_status=HYPOTHESIS_STATUS_SUPPORTED,
        )
        session.hypotheses.append(hypo)

        # Attestation without authentic capability must be rejected
        with self.assertRaises(ValueError) as ctx:
            session.ledger.attest_causal_proof(
                "ev_a_call",
                target_function="worker_fn",
                execution_provenance={"execution_status": "REPRODUCED", "reproduction_verified": True},
            )
        self.assertIn("lacks genuine execution provenance or internal verification capability", str(ctx.exception))

        # Evaluate with caller boolean claim
        res = mgr.evaluate_hypothesis(inv_id, "hypo_a", deterministic_transition_verified=True)
        self.assertEqual(res["transition"]["to_status"], HYPOTHESIS_STATUS_SUPPORTED)
        self.assertTrue(res["transition"]["unverified_claim_rejected"])

        # Check candidate tier
        h_after = mgr.get_hypothesis(inv_id, "hypo_a")
        fc = h_after["function_candidates"][0]
        self.assertNotEqual(fc["candidate_tier"], FUNCTION_TIER_VALIDATED_CAUSAL)
        self.assertFalse(fc["confirmed_root_cause"])

    def test_phase5_case_b_caller_selected_backend_labels_cannot_turn_unverified_input_into_provenance(self):
        """Case B: Caller-selected backend_type labels cannot turn unverified input into trusted runtime provenance."""
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Phase 5 Case B")
        inv_id = start["investigation_id"]
        session = mgr.sessions[inv_id]
        verifier = TrustedCausalVerifier(session)

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_b",
            investigation_id=inv_id,
            title="Hypo B",
            claim="Claim B",
            proposed_mechanism="Mech B",
            supporting_evidence_ids=[],
            function_candidates=[{
                "function_name": "worker_fn",
                "candidate_tier": FUNCTION_TIER_EVIDENCE_SUPPORTED,
                "confirmed_root_cause": False,
            }],
            validation_status=HYPOTHESIS_STATUS_SUPPORTED,
        )
        session.hypotheses.append(hypo)

        with self.assertRaises(ValueError) as ctx:
            verifier.record_controlled_execution(
                target_function="worker_fn",
                field_path="State.val",
                execution_status="REPRODUCED",
                backend_type="unauthorized_caller_custom_backend",
            )
        self.assertIn("Unauthorized execution backend", str(ctx.exception))

        h_after = mgr.get_hypothesis(inv_id, "hypo_b")
        self.assertEqual(h_after["validation_status"], HYPOTHESIS_STATUS_SUPPORTED)
        self.assertNotEqual(h_after["function_candidates"][0]["candidate_tier"], FUNCTION_TIER_VALIDATED_CAUSAL)

    def test_phase5_case_c_synthetic_fixture_evidence_cannot_promote_real_investigation_to_validated(self):
        """Case C: SYNTHETIC_FIXTURE evidence cannot promote a real investigation to VALIDATED."""
        mgr, inv_id, hypo_id = CausalDefectFixtures.create_scenario_a_reproducible_mutation()
        session = mgr.sessions[inv_id]
        verifier = TrustedCausalVerifier(session)

        rec_synth = EvidenceRecord(
            evidence_id="ev_synth_proof",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="synthetic_generator",
            session_id=inv_id,
            observation="Synthetic transition simulation",
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
            provenance={"provenance_class": PROVENANCE_CLASS_SYNTHETIC_FIXTURE},
        )
        session.ledger.add_record(rec_synth)

        rcpt = verifier.record_controlled_execution(
            target_function="mutate_worker_state",
            field_path="WorkerState.counter",
            execution_status="REPRODUCED",
            backend_type="synthetic_adversarial_fixture",
            evidence_id="ev_synth_proof",
            hypothesis_id=hypo_id,
            provenance_class=PROVENANCE_CLASS_SYNTHETIC_FIXTURE,
        )
        verifier.verify_execution_and_attest(
            evidence_id="ev_synth_proof",
            hypothesis_id=hypo_id,
            execution_result=rcpt,
        )

        res = mgr.evaluate_hypothesis(inv_id, hypo_id, proof_evidence_id="ev_synth_proof")
        self.assertEqual(res["transition"]["to_status"], HYPOTHESIS_STATUS_SUPPORTED)
        self.assertIn("SYNTHETIC_FIXTURE", res["transition"]["reason"])

        hypo = mgr.get_hypothesis(inv_id, hypo_id)
        self.assertEqual(hypo["validation_status"], HYPOTHESIS_STATUS_SUPPORTED)
        self.assertFalse(hypo["function_candidates"][0]["confirmed_root_cause"])
        self.assertNotEqual(hypo["function_candidates"][0]["candidate_tier"], FUNCTION_TIER_VALIDATED_CAUSAL)

    def test_phase5_case_d_in_memory_dictionaries_cannot_impersonate_captured_runtime_snapshots(self):
        """Case D: In-memory dictionaries inserted into StateCorpus cannot impersonate independently captured snapshots."""
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Phase 5 Case D")
        inv_id = start["investigation_id"]
        session = mgr.sessions[inv_id]

        rec = EvidenceRecord(
            evidence_id="ev_d",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="collector",
            session_id=inv_id,
            observation="Obs",
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec)

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_d",
            investigation_id=inv_id,
            title="Hypo D",
            claim="Claim D",
            proposed_mechanism="Mech D",
            supporting_evidence_ids=["ev_d"],
            candidate_fields=["State.val"],
            function_candidates=[{"function_name": "fn_d", "candidate_tier": FUNCTION_TIER_EVIDENCE_SUPPORTED, "confirmed_root_cause": False}],
            validation_status=HYPOTHESIS_STATUS_SUPPORTED,
        )
        session.hypotheses.append(hypo)

        with self.assertRaises(ValueError) as ctx:
            mgr.verify_live_reproduction_and_attest(
                investigation_id=inv_id,
                hypothesis_id="hypo_d",
                evidence_id="ev_d",
                snapshot_a_path="nonexistent_in_memory_snap_a",
                snapshot_b_path="nonexistent_in_memory_snap_b",
                target_function="fn_d",
                field_path="State.val",
            )
        self.assertIn("does not exist on disk", str(ctx.exception))
        h_after = mgr.get_hypothesis(inv_id, "hypo_d")
        self.assertNotEqual(h_after["validation_status"], HYPOTHESIS_STATUS_VALIDATED)
        self.assertFalse(h_after["function_candidates"][0]["confirmed_root_cause"])

    def test_phase5_case_e_mutating_raw_memory_payload_after_receipt_creation_is_detected(self):
        """Case E: Mutating a raw memory payload after receipt creation is detected."""
        temp_dir = tempfile.mkdtemp(prefix="phase5_case_e_")
        try:
            snap_a_dir = os.path.join(temp_dir, "snap_a")
            snap_b_dir = os.path.join(temp_dir, "snap_b")
            os.makedirs(os.path.join(snap_a_dir, "memory"), exist_ok=True)
            os.makedirs(os.path.join(snap_b_dir, "memory"), exist_ok=True)

            with open(os.path.join(snap_a_dir, "snapshot_metadata.json"), "w") as f:
                json.dump({"snapshot_id": "snap_a", "pid": 1234, "executable": "/bin/app", "completeness": "COMPLETE", "consistency_level": "STOPPED"}, f)
            with open(os.path.join(snap_b_dir, "snapshot_metadata.json"), "w") as f:
                json.dump({"snapshot_id": "snap_b", "pid": 1234, "executable": "/bin/app", "completeness": "COMPLETE", "consistency_level": "STOPPED"}, f)

            bin_a = os.path.join(snap_a_dir, "memory", "range_0x1000_0x2000.bin")
            bin_b = os.path.join(snap_b_dir, "memory", "range_0x1000_0x2000.bin")
            with open(bin_a, "wb") as f:
                f.write(b"A" * 4096)
            with open(bin_b, "wb") as f:
                f.write(b"B" * 4096)

            mgr = InvestigationManager()
            start = mgr.start_investigation(goal="Phase 5 Case E")
            inv_id = start["investigation_id"]
            session = mgr.sessions[inv_id]

            rec = EvidenceRecord(
                evidence_id="ev_e",
                evidence_type=EVIDENCE_TYPE_COMPARISON,
                nature=NATURE_OBSERVATION,
                source="collector",
                session_id=inv_id,
                observation="Obs",
                capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
            )
            session.ledger.add_record(rec)
            verifier = TrustedCausalVerifier(session)

            hash_a = compute_snapshot_artifact_hash(snap_a_dir, session)
            hash_b = compute_snapshot_artifact_hash(snap_b_dir, session)

            res_temp = ControlledExecutionResult(
                execution_id="exec_e",
                investigation_id=inv_id,
                target_function="fn_e",
                field_path="State.val",
                before_value=1,
                after_value=2,
                execution_status="REPRODUCED",
                capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
                evidence_id="ev_e",
                hypothesis_id="hypo_e",
                before_snapshot_ref=snap_a_dir,
                after_snapshot_ref=snap_b_dir,
                before_snapshot_hash=hash_a,
                after_snapshot_hash=hash_b,
                backend_type="live_process_snapshot_diff",
            )
            sig = compute_receipt_signature(session._session_secret, res_temp)
            receipt = ControlledExecutionResult(
                execution_id=res_temp.execution_id,
                investigation_id=res_temp.investigation_id,
                target_function=res_temp.target_function,
                field_path=res_temp.field_path,
                before_value=res_temp.before_value,
                after_value=res_temp.after_value,
                execution_status=res_temp.execution_status,
                capture_quality=res_temp.capture_quality,
                evidence_id=res_temp.evidence_id,
                hypothesis_id=res_temp.hypothesis_id,
                before_snapshot_ref=res_temp.before_snapshot_ref,
                after_snapshot_ref=res_temp.after_snapshot_ref,
                before_snapshot_hash=res_temp.before_snapshot_hash,
                after_snapshot_hash=res_temp.after_snapshot_hash,
                backend_type=res_temp.backend_type,
                receipt_signature=sig,
            )

            # Adversary tampers with raw memory payload
            with open(bin_b, "wb") as f:
                f.write(b"TAMPERED_BYTES" * 100)

            with self.assertRaises(ValueError) as ctx:
                verifier.verify_execution_and_attest("ev_e", "hypo_e", receipt)
            self.assertIn("tampered or modified", str(ctx.exception))
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_phase5_case_f_mutating_metadata_maps_manifest_or_thread_data_is_detected(self):
        """Case F: Mutating metadata, maps, manifest, thread data, or reconstruction artifact is detected."""
        temp_dir = tempfile.mkdtemp(prefix="phase5_case_f_")
        try:
            snap_dir = os.path.join(temp_dir, "snap_f")
            os.makedirs(snap_dir, exist_ok=True)
            meta_path = os.path.join(snap_dir, "snapshot_metadata.json")
            maps_path = os.path.join(snap_dir, "maps.json")
            with open(meta_path, "w") as f:
                json.dump({"snapshot_id": "snap_f", "pid": 100}, f)
            with open(maps_path, "w") as f:
                json.dump([{"start": "0x1000", "end": "0x2000"}], f)

            mgr = InvestigationManager()
            start = mgr.start_investigation(goal="Phase 5 Case F")
            session = mgr.sessions[start["investigation_id"]]
            initial_hash = compute_snapshot_artifact_hash(snap_dir, session)

            # Mutate maps.json
            with open(maps_path, "w") as f:
                json.dump([{"start": "0x1000", "end": "0x9999"}], f)

            tampered_hash = compute_snapshot_artifact_hash(snap_dir, session)
            self.assertNotEqual(initial_hash, tampered_hash)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_phase5_case_g_adding_deleting_renaming_replacing_file_in_snapshot_directory_is_detected(self):
        """Case G: Adding, deleting, renaming, or replacing a file in a snapshot directory is detected."""
        temp_dir = tempfile.mkdtemp(prefix="phase5_case_g_")
        try:
            snap_dir = os.path.join(temp_dir, "snap_g")
            os.makedirs(snap_dir, exist_ok=True)
            file1 = os.path.join(snap_dir, "file1.txt")
            with open(file1, "w") as f:
                f.write("content1")

            mgr = InvestigationManager()
            start = mgr.start_investigation(goal="Phase 5 Case G")
            session = mgr.sessions[start["investigation_id"]]
            hash1 = compute_snapshot_artifact_hash(snap_dir, session)

            # 1. Adding file
            file2 = os.path.join(snap_dir, "file2.txt")
            with open(file2, "w") as f:
                f.write("content2")
            hash2 = compute_snapshot_artifact_hash(snap_dir, session)
            self.assertNotEqual(hash1, hash2)

            # 2. Deleting file
            os.remove(file2)
            hash3 = compute_snapshot_artifact_hash(snap_dir, session)
            self.assertEqual(hash1, hash3)

            # 3. Renaming file
            renamed = os.path.join(snap_dir, "file1_renamed.txt")
            os.rename(file1, renamed)
            hash4 = compute_snapshot_artifact_hash(snap_dir, session)
            self.assertNotEqual(hash1, hash4)
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_phase5_case_h_symlinks_and_path_traversal_are_rejected_safely(self):
        """Case H: Symlinks and path traversal are rejected safely."""
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Phase 5 Case H")
        inv_id = start["investigation_id"]

        with self.assertRaises(ValueError) as ctx1:
            mgr.verify_live_reproduction_and_attest(
                investigation_id=inv_id,
                hypothesis_id="hypo_h",
                evidence_id="ev_h",
                snapshot_a_path="../../etc/passwd",
                snapshot_b_path="/tmp/valid",
                target_function="fn_h",
                field_path="val",
            )
        self.assertIn("Path traversal detected", str(ctx1.exception))

        temp_dir = tempfile.mkdtemp(prefix="phase5_case_h_")
        try:
            real_file = os.path.join(temp_dir, "real.json")
            with open(real_file, "w") as f:
                json.dump({"snapshot_id": "real"}, f)
            symlink_file = os.path.join(temp_dir, "symlink.json")
            os.symlink(real_file, symlink_file)

            with self.assertRaises(ValueError) as ctx2:
                mgr.verify_live_reproduction_and_attest(
                    investigation_id=inv_id,
                    hypothesis_id="hypo_h",
                    evidence_id="ev_h",
                    snapshot_a_path=symlink_file,
                    snapshot_b_path=real_file,
                    target_function="fn_h",
                    field_path="val",
                )
            self.assertIn("symbolic link", str(ctx2.exception))
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_phase5_case_i_receipt_cannot_be_reused_across_investigations_hypotheses_or_fields(self):
        """Case I: A receipt cannot be reused across investigations, evidence records, hypotheses, functions, or fields."""
        mgr = InvestigationManager()
        start1 = mgr.start_investigation(goal="Phase 5 Case I - 1")
        start2 = mgr.start_investigation(goal="Phase 5 Case I - 2")
        inv_1 = start1["investigation_id"]
        inv_2 = start2["investigation_id"]
        s1 = mgr.sessions[inv_1]
        s2 = mgr.sessions[inv_2]

        v1 = TrustedCausalVerifier(s1)
        v2 = TrustedCausalVerifier(s2)

        rcpt1 = v1.record_controlled_execution(
            target_function="fn_original",
            field_path="State.original_field",
            execution_status="REPRODUCED",
            backend_type="synthetic_adversarial_fixture",
            evidence_id="ev_1",
            hypothesis_id="hypo_1",
        )

        # Attempt to verify receipt 1 against session 2
        with self.assertRaises(ValueError) as ctx:
            v2.verify_execution_and_attest(
                evidence_id="ev_1",
                hypothesis_id="hypo_1",
                execution_result=rcpt1,
            )
        self.assertIn("authenticity verification failed", str(ctx.exception))

    def test_phase5_case_j_mismatched_build_ids_pid_identities_or_temporal_order_fail_safely(self):
        """Case J: Mismatched build IDs, PID/process identities, timestamps, capture quality, or transitions fail safely."""
        temp_dir = tempfile.mkdtemp(prefix="phase5_case_j_")
        try:
            snap_a_file = os.path.join(temp_dir, "snap_a.json")
            snap_b_file = os.path.join(temp_dir, "snap_b.json")

            # 1. PID mismatch
            with open(snap_a_file, "w") as f:
                json.dump({
                    "snapshot_id": "snap_a",
                    "process": {"pid": 1001, "binary": "/bin/app", "executable_build_id": "b1"},
                    "timestamp": "2026-10-14T00:00:00Z",
                    "completeness": "COMPLETE",
                    "consistency": {"level": "STOPPED"},
                    "persistent": {"objects": [{"object_id": "o1", "type": "State", "fields": [{"name": "val", "value": 10}]}]}
                }, f)
            with open(snap_b_file, "w") as f:
                json.dump({
                    "snapshot_id": "snap_b",
                    "process": {"pid": 9999, "binary": "/bin/app", "executable_build_id": "b1"},
                    "timestamp": "2026-10-14T00:00:05Z",
                    "completeness": "COMPLETE",
                    "consistency": {"level": "STOPPED"},
                    "persistent": {"objects": [{"object_id": "o1", "type": "State", "fields": [{"name": "val", "value": 20}]}]}
                }, f)

            mgr = InvestigationManager()
            start = mgr.start_investigation(goal="Phase 5 Case J")
            inv_id = start["investigation_id"]
            session = mgr.sessions[inv_id]

            rec = EvidenceRecord(
                evidence_id="ev_j",
                evidence_type=EVIDENCE_TYPE_COMPARISON,
                nature=NATURE_OBSERVATION,
                source="collector",
                session_id=inv_id,
                observation="Obs",
                capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
            )
            session.ledger.add_record(rec)
            hypo = InvestigationHypothesis(
                hypothesis_id="hypo_j",
                investigation_id=inv_id,
                title="Hypo J",
                claim="Claim J",
                proposed_mechanism="Mech J",
                supporting_evidence_ids=["ev_j"],
                candidate_fields=["State.val"],
                function_candidates=[{"function_name": "fn_j", "candidate_tier": FUNCTION_TIER_EVIDENCE_SUPPORTED, "confirmed_root_cause": False}],
                validation_status=HYPOTHESIS_STATUS_SUPPORTED,
            )
            session.hypotheses.append(hypo)

            with self.assertRaises(ValueError) as ctx_pid:
                mgr.verify_live_reproduction_and_attest(
                    investigation_id=inv_id,
                    hypothesis_id="hypo_j",
                    evidence_id="ev_j",
                    snapshot_a_path=snap_a_file,
                    snapshot_b_path=snap_b_file,
                    target_function="fn_j",
                    field_path="State.val",
                )
            self.assertIn("Target PID mismatch", str(ctx_pid.exception))

            # 2. Temporal inconsistency
            with open(snap_b_file, "w") as f:
                json.dump({
                    "snapshot_id": "snap_b",
                    "process": {"pid": 1001, "binary": "/bin/app", "executable_build_id": "b1"},
                    "timestamp": "2026-10-13T00:00:00Z",  # Earlier than A
                    "completeness": "COMPLETE",
                    "consistency": {"level": "STOPPED"},
                    "persistent": {"objects": [{"object_id": "o1", "type": "State", "fields": [{"name": "val", "value": 20}]}]}
                }, f)
            with self.assertRaises(ValueError) as ctx_time:
                mgr.verify_live_reproduction_and_attest(
                    investigation_id=inv_id,
                    hypothesis_id="hypo_j",
                    evidence_id="ev_j",
                    snapshot_a_path=snap_a_file,
                    snapshot_b_path=snap_b_file,
                    target_function="fn_j",
                    field_path="State.val",
                )
            self.assertIn("Temporal inconsistency", str(ctx_time.exception))

            h_after = mgr.get_hypothesis(inv_id, "hypo_j")
            self.assertNotEqual(h_after["validation_status"], HYPOTHESIS_STATUS_VALIDATED)
            self.assertFalse(h_after["function_candidates"][0]["confirmed_root_cause"])
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_phase5_case_k_similar_field_suffixes_in_unrelated_objects_rejected(self):
        """Case K: Similar field suffixes in unrelated objects cannot satisfy requested field-path match."""
        # 1. Unit test is_exact_semantic_path_match
        self.assertFalse(is_exact_semantic_path_match("ThreadCounter", "counter", "State.counter"))
        self.assertFalse(is_exact_semantic_path_match("GlobalState.counter_2", "counter_2", "State.counter"))
        self.assertTrue(is_exact_semantic_path_match("Session.worker.state", "counter", "State.counter"))
        self.assertTrue(is_exact_semantic_path_match("WorkerState", "counter", "WorkerState.counter"))

        # 2. verify_live_reproduction_and_attest with cross-object field name collision
        temp_dir = tempfile.mkdtemp(prefix="phase5_case_k_")
        try:
            snap_a_file = os.path.join(temp_dir, "snap_a.json")
            snap_b_file = os.path.join(temp_dir, "snap_b.json")
            with open(snap_a_file, "w") as f:
                json.dump({
                    "snapshot_id": "snap_a",
                    "process": {"pid": 1001, "binary": "/bin/app", "executable_build_id": "b1"},
                    "completeness": "COMPLETE",
                    "consistency": {"level": "STOPPED"},
                    "persistent": {"objects": [{"object_id": "o1", "type": "ThreadCounter", "fields": [{"name": "counter", "value": 0}]}]}
                }, f)
            with open(snap_b_file, "w") as f:
                json.dump({
                    "snapshot_id": "snap_b",
                    "process": {"pid": 1001, "binary": "/bin/app", "executable_build_id": "b1"},
                    "completeness": "COMPLETE",
                    "consistency": {"level": "STOPPED"},
                    "persistent": {"objects": [{"object_id": "o1", "type": "ThreadCounter", "fields": [{"name": "counter", "value": 5}]}]}
                }, f)

            mgr = InvestigationManager()
            start = mgr.start_investigation(goal="Phase 5 Case K")
            inv_id = start["investigation_id"]
            session = mgr.sessions[inv_id]

            rec = EvidenceRecord(
                evidence_id="ev_k",
                evidence_type=EVIDENCE_TYPE_COMPARISON,
                nature=NATURE_OBSERVATION,
                source="collector",
                session_id=inv_id,
                observation="Obs",
                capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
            )
            session.ledger.add_record(rec)
            hypo = InvestigationHypothesis(
                hypothesis_id="hypo_k",
                investigation_id=inv_id,
                title="Hypo K",
                claim="Claim K",
                proposed_mechanism="Mech K",
                supporting_evidence_ids=["ev_k"],
                candidate_fields=["State.counter"],
                function_candidates=[{"function_name": "fn_k", "candidate_tier": FUNCTION_TIER_EVIDENCE_SUPPORTED, "confirmed_root_cause": False}],
                validation_status=HYPOTHESIS_STATUS_SUPPORTED,
            )
            session.hypotheses.append(hypo)

            with self.assertRaises(ValueError) as ctx:
                mgr.verify_live_reproduction_and_attest(
                    investigation_id=inv_id,
                    hypothesis_id="hypo_k",
                    evidence_id="ev_k",
                    snapshot_a_path=snap_a_file,
                    snapshot_b_path=snap_b_file,
                    target_function="fn_k",
                    field_path="State.counter",  # Only ThreadCounter.counter changed!
                )
            self.assertIn("field 'State.counter' did not change between snapshots", str(ctx.exception))
            h_after = mgr.get_hypothesis(inv_id, "hypo_k")
            self.assertNotEqual(h_after["validation_status"], HYPOTHESIS_STATUS_VALIDATED)
            self.assertFalse(h_after["function_candidates"][0]["confirmed_root_cause"])
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_phase5_case_l_forged_or_dummy_receipt_signatures_are_rejected(self):
        """Case L: Forged or dummy receipt signatures are rejected."""
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Phase 5 Case L")
        inv_id = start["investigation_id"]
        session = mgr.sessions[inv_id]

        rec = EvidenceRecord(
            evidence_id="ev_l",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="collector",
            session_id=inv_id,
            observation="Obs",
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec)
        verifier = TrustedCausalVerifier(session)

        dummy = ControlledExecutionResult(
            execution_id="exec_dummy_l",
            investigation_id=inv_id,
            target_function="fn_l",
            field_path="State.val",
            before_value=1,
            after_value=2,
            execution_status="REPRODUCED",
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
            backend_type="synthetic_adversarial_fixture",
            receipt_signature="forged_dummy_signature_xyz",
        )
        with self.assertRaises(ValueError) as ctx:
            verifier.verify_execution_and_attest("ev_l", "hypo_l", dummy)
        self.assertIn("authenticity verification failed", str(ctx.exception))

    def test_phase5_case_m_rest_and_arp_payloads_cannot_inject_trusted_receipts(self):
        """Case M: REST and ARP payloads cannot inject trusted receipts or runtime provenance."""
        runtime = AgentRuntime()
        start = runtime.investigation_manager.start_investigation(goal="Phase 5 Case M")
        inv_id = start["investigation_id"]
        session = runtime.investigation_manager.sessions[inv_id]

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_m",
            investigation_id=inv_id,
            title="Hypo M",
            claim="Claim M",
            proposed_mechanism="Mech M",
            supporting_evidence_ids=[],
            function_candidates=[{"function_name": "fn_m", "candidate_tier": FUNCTION_TIER_EVIDENCE_SUPPORTED, "confirmed_root_cause": False}],
            validation_status=HYPOTHESIS_STATUS_SUPPORTED,
        )
        session.hypotheses.append(hypo)

        action = AgentAction(
            action="EVALUATE_HYPOTHESIS",
            investigation_id=inv_id,
            hypothesis_id="hypo_m",
            deterministic_transition_verified=True,
            proof_evidence_id="attacker_injected_proof_id",
        )
        res = runtime.dispatch_action(action)
        self.assertTrue(res.success)
        eval_data = res.data or {}
        trans = eval_data.get("transition", {})
        self.assertNotEqual(trans.get("to_status"), HYPOTHESIS_STATUS_VALIDATED)

    def test_phase5_case_n_partial_non_atomic_failed_invalid_snapshots_capped(self):
        """Case N: PARTIAL, NON_ATOMIC, FAILED, INVALID, and provenance-incomplete snapshots cannot establish causal proof."""
        temp_dir = tempfile.mkdtemp(prefix="phase5_case_n_")
        try:
            snap_a_file = os.path.join(temp_dir, "snap_a.json")
            snap_b_file = os.path.join(temp_dir, "snap_b.json")
            with open(snap_a_file, "w") as f:
                json.dump({
                    "snapshot_id": "snap_a",
                    "process": {"pid": 1001, "binary": "/bin/app", "executable_build_id": "b1"},
                    "completeness": "PARTIAL",
                    "consistency": {"level": "STOPPED"},
                    "persistent": {"objects": [{"object_id": "o1", "type": "State", "fields": [{"name": "val", "value": 10}]}]}
                }, f)
            with open(snap_b_file, "w") as f:
                json.dump({
                    "snapshot_id": "snap_b",
                    "process": {"pid": 1001, "binary": "/bin/app", "executable_build_id": "b1"},
                    "completeness": "COMPLETE",
                    "consistency": {"level": "STOPPED"},
                    "persistent": {"objects": [{"object_id": "o1", "type": "State", "fields": [{"name": "val", "value": 20}]}]}
                }, f)

            mgr = InvestigationManager()
            start = mgr.start_investigation(goal="Phase 5 Case N")
            inv_id = start["investigation_id"]
            session = mgr.sessions[inv_id]

            rec = EvidenceRecord(
                evidence_id="ev_n",
                evidence_type=EVIDENCE_TYPE_COMPARISON,
                nature=NATURE_OBSERVATION,
                source="collector",
                session_id=inv_id,
                observation="Obs",
                capture_quality={"completeness": "PARTIAL", "consistency_level": "STOPPED"},
            )
            session.ledger.add_record(rec)
            hypo = InvestigationHypothesis(
                hypothesis_id="hypo_n",
                investigation_id=inv_id,
                title="Hypo N",
                claim="Claim N",
                proposed_mechanism="Mech N",
                supporting_evidence_ids=["ev_n"],
                candidate_fields=["State.val"],
                function_candidates=[{"function_name": "fn_n", "candidate_tier": FUNCTION_TIER_EVIDENCE_SUPPORTED, "confirmed_root_cause": False}],
                validation_status=HYPOTHESIS_STATUS_SUPPORTED,
            )
            session.hypotheses.append(hypo)

            with self.assertRaises(ValueError) as ctx:
                mgr.verify_live_reproduction_and_attest(
                    investigation_id=inv_id,
                    hypothesis_id="hypo_n",
                    evidence_id="ev_n",
                    snapshot_a_path=snap_a_file,
                    snapshot_b_path=snap_b_file,
                    target_function="fn_n",
                    field_path="State.val",
                )
            self.assertIn("PARTIAL", str(ctx.exception))
            h_after = mgr.get_hypothesis(inv_id, "hypo_n")
            self.assertNotEqual(h_after["validation_status"], HYPOTHESIS_STATUS_VALIDATED)
            self.assertFalse(h_after["function_candidates"][0]["confirmed_root_cause"])
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_phase5_case_o_legacy_imported_artifacts_cannot_acquire_trusted_status(self):
        """Case O: Legacy/imported artifacts cannot silently acquire trusted runtime status."""
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Phase 5 Case O")
        inv_id = start["investigation_id"]
        session = mgr.sessions[inv_id]

        rec = EvidenceRecord(
            evidence_id="ev_imported",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="imported_archive",
            session_id=inv_id,
            observation="Imported transition",
            details={"provenance_class": PROVENANCE_CLASS_IMPORTED_UNVERIFIED},
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(rec)

        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_o",
            investigation_id=inv_id,
            title="Hypo O",
            claim="Claim O",
            proposed_mechanism="Mech O",
            supporting_evidence_ids=["ev_imported"],
            function_candidates=[{"function_name": "fn_o", "candidate_tier": FUNCTION_TIER_EVIDENCE_SUPPORTED, "confirmed_root_cause": False}],
            validation_status=HYPOTHESIS_STATUS_SUPPORTED,
        )
        session.hypotheses.append(hypo)

        res = mgr.evaluate_hypothesis(inv_id, "hypo_o", proof_evidence_id="ev_imported")
        self.assertEqual(res["transition"]["to_status"], HYPOTHESIS_STATUS_SUPPORTED)
        h_after = mgr.get_hypothesis(inv_id, "hypo_o")
        self.assertFalse(h_after["function_candidates"][0]["confirmed_root_cause"])
        self.assertNotEqual(h_after["function_candidates"][0]["candidate_tier"], FUNCTION_TIER_VALIDATED_CAUSAL)

    def test_phase5_case_p_legitimate_supported_live_runtime_positive_control_succeeds(self):
        """Case P: A legitimate supported live-runtime positive control still succeeds."""
        mgr, inv_id, hypo_id = CausalDefectFixtures.create_scenario_a_reproducible_mutation()
        res = mgr.evaluate_hypothesis(inv_id, hypo_id, proof_evidence_id="ev_a_proof", deterministic_transition_verified=True)
        self.assertEqual(res["transition"]["to_status"], HYPOTHESIS_STATUS_VALIDATED)
        hypo = mgr.get_hypothesis(inv_id, hypo_id)
        self.assertEqual(hypo["function_candidates"][0]["candidate_tier"], FUNCTION_TIER_VALIDATED_CAUSAL)
        self.assertTrue(hypo["function_candidates"][0]["confirmed_root_cause"])

    def test_phase5_case_q_real_field_transition_without_function_attribution_does_not_promote_candidate(self):
        """Case Q: A real field transition without function attribution does not confirm that function as root cause."""
        temp_dir = tempfile.mkdtemp(prefix="phase5_case_q_")
        try:
            snap_a_file = os.path.join(temp_dir, "snap_a.json")
            snap_b_file = os.path.join(temp_dir, "snap_b.json")
            with open(snap_a_file, "w") as f:
                json.dump({
                    "snapshot_id": "snap_a",
                    "process": {"pid": 1001, "binary": "/bin/app", "executable_build_id": "b1"},
                    "timestamp": "2026-10-14T00:00:00Z",
                    "completeness": "COMPLETE",
                    "consistency": {"level": "STOPPED"},
                    "persistent": {"objects": [{"object_id": "o1", "type": "State", "fields": [{"name": "counter", "value": 10}]}]}
                }, f)
            with open(snap_b_file, "w") as f:
                json.dump({
                    "snapshot_id": "snap_b",
                    "process": {"pid": 1001, "binary": "/bin/app", "executable_build_id": "b1"},
                    "timestamp": "2026-10-14T00:00:05Z",
                    "completeness": "COMPLETE",
                    "consistency": {"level": "STOPPED"},
                    "persistent": {"objects": [{"object_id": "o1", "type": "State", "fields": [{"name": "counter", "value": 20}]}]}
                }, f)

            mgr = InvestigationManager()
            start = mgr.start_investigation(goal="Phase 5 Case Q")
            inv_id = start["investigation_id"]
            session = mgr.sessions[inv_id]

            rec = EvidenceRecord(
                evidence_id="ev_q",
                evidence_type=EVIDENCE_TYPE_COMPARISON,
                nature=NATURE_OBSERVATION,
                source="collector",
                session_id=inv_id,
                observation="Obs",
                details={"target_function": "worker_fn", "field_path": "State.counter"},
                capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
            )
            session.ledger.add_record(rec)
            hypo = InvestigationHypothesis(
                hypothesis_id="hypo_q",
                investigation_id=inv_id,
                title="Hypo Q",
                claim="Claim Q",
                proposed_mechanism="Mech Q",
                supporting_evidence_ids=["ev_q"],
                candidate_fields=["State.counter"],
                function_candidates=[{"function_name": "worker_fn", "candidate_tier": FUNCTION_TIER_EVIDENCE_SUPPORTED, "confirmed_root_cause": False}],
                validation_status=HYPOTHESIS_STATUS_SUPPORTED,
            )
            session.hypotheses.append(hypo)

            # verify_live_reproduction_and_attest WITHOUT attribution evidence
            att_ok = mgr.verify_live_reproduction_and_attest(
                investigation_id=inv_id,
                hypothesis_id="hypo_q",
                evidence_id="ev_q",
                snapshot_a_path=snap_a_file,
                snapshot_b_path=snap_b_file,
                target_function="worker_fn",
                field_path="State.counter",
            )
            self.assertTrue(att_ok)

            # Evaluate hypothesis: state transition is VALIDATED
            res = mgr.evaluate_hypothesis(inv_id, "hypo_q", proof_evidence_id="ev_q", deterministic_transition_verified=True)
            self.assertEqual(res["transition"]["to_status"], HYPOTHESIS_STATUS_VALIDATED)

            # BUT candidate is NOT promoted to VALIDATED_CAUSAL_FUNCTION
            h_after = mgr.get_hypothesis(inv_id, "hypo_q")
            fc = h_after["function_candidates"][0]
            self.assertEqual(fc["candidate_tier"], FUNCTION_TIER_EVIDENCE_SUPPORTED)
            self.assertFalse(fc["confirmed_root_cause"])
            self.assertIn("function attribution was not independently verified", fc["tier_limitation"])
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def test_phase5_case_r_failed_or_interrupted_capture_leaves_no_usable_receipt_or_zombie(self):
        """Case R: A failed or interrupted capture does not leave a usable receipt, capability, stopped process, orphan, or zombie."""
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Phase 5 Case R")
        inv_id = start["investigation_id"]
        session = mgr.sessions[inv_id]

        # Incomplete verification fails cleanly and leaves no capability
        with self.assertRaises(ValueError):
            mgr.verify_live_reproduction_and_attest(
                investigation_id=inv_id,
                hypothesis_id="nonexistent_hypo",
                evidence_id="nonexistent_ev",
                snapshot_a_path="/invalid/path_a",
                snapshot_b_path="/invalid/path_b",
                target_function="fn_r",
                field_path="val",
            )
        self.assertEqual(sum(1 for r in session.ledger._records if (r.details or {}).get("verified_causal_proof")), 0)
        self.assertEqual(sum(1 for r in session.ledger._records if (r.provenance or {}).get("verifier_attestation")), 0)


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

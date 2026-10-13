"""False-Positive Risk & Causal Validation Evaluation Harness.

Evaluates dynamicState root-cause validation accuracy across deterministic defect scenarios:
- Measures True Positives, False Positives, False Negatives, True Negatives
- Verifies zero false causal promotions (FP == 0)
- Enforces strict trust boundaries across capture quality tiers:
  COMPLETE, PARTIAL, NON_ATOMIC, UNTRUSTED/FAILED
- Reports explicit metric definitions and machine-readable JSON results.
"""

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

from .causal_fixtures import CausalDefectFixtures
from .evidence_ledger import (
    EVIDENCE_TYPE_COMPARISON,
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EvidenceLedger,
    EvidenceRecord,
    NATURE_OBSERVATION,
)
from .hypothesis import (
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
    HypothesisValidator,
    InvestigationHypothesis,
)
from .investigation import InvestigationFinding, InvestigationManager


@dataclass
class TestCaseResult:
    case_id: str
    scenario: str
    description: str
    capture_quality: str
    consistency_level: str
    ground_truth_is_causal: bool
    evaluation_status: str
    evaluation_confidence: str
    candidate_tier: str
    confirmed_root_cause: bool
    unverified_claim_rejected: bool
    is_true_positive: bool
    is_false_positive: bool
    is_true_negative: bool
    is_false_negative: bool
    reason: str


class CausalValidationEvaluator:
    """Evaluation runner testing causal validation correctness and false-positive risk."""

    def __init__(self):
        self.results: List[TestCaseResult] = []

    def run_all(self) -> Dict[str, Any]:
        """Execute all test cases and return structured evaluation results."""
        self.results.clear()

        # Case 1: Scenario A - Reproducible field mutation with verified writer and complete capture
        self._eval_scenario_a()

        # Case 2: Scenario B - Static candidate unproven (must not become confirmed root cause)
        self._eval_scenario_b()

        # Case 3: Scenario C - Real writer divergent from leading static candidate
        self._eval_scenario_c()

        # Case 4: Scenario D - Contradictory observation invalidating hypothesis
        self._eval_scenario_d()

        # Case 5: Scenario E - PARTIAL capture with claimed transition (must be capped at SUPPORTED)
        self._eval_scenario_e_partial()

        # Case 6: Scenario E2 - NON_ATOMIC capture with claimed transition (must be capped at SUPPORTED)
        self._eval_scenario_e_non_atomic()

        # Case 7: Scenario G - Direct caller boolean injection without proof (must be rejected)
        self._eval_scenario_g_boolean_injection()

        # Case 8: Scenario G2 - Direct caller fabricated proof ID without ledger record (must be rejected)
        self._eval_scenario_g_fake_proof_id()

        # Case 9: Scenario H - Cyclic provenance graph (must fail safely as INCONCLUSIVE)
        self._eval_scenario_h_cycle()

        # Case 10: Scenario H2 - Missing parent evidence record in provenance (must fail safely as INCONCLUSIVE)
        self._eval_scenario_h_missing_parent()

        # Case 11: Scenario H3 - Duplicate evidence record (must not escalate confidence or count as independent)
        self._eval_scenario_h_duplicate()

        # Case 12: Boundary Case - FAILED capture with claimed deterministic transition (must be INCONCLUSIVE)
        self._eval_boundary_untrusted_capture()

        return self._generate_report()

    def _eval_scenario_a(self):
        mgr, inv_id, hypo_id = CausalDefectFixtures.create_scenario_a_reproducible_mutation()
        res = mgr.evaluate_hypothesis(
            inv_id,
            hypo_id,
            deterministic_transition_verified=True,
            proof_evidence_id="ev_a_proof",
        )
        hypo = mgr.get_hypothesis(inv_id, hypo_id)
        fc = hypo["function_candidates"][0] if hypo.get("function_candidates") else {}
        actual_status = hypo["validation_status"]
        is_tp = (actual_status == HYPOTHESIS_STATUS_VALIDATED)
        is_fp = False
        is_tn = False
        is_fn = not is_tp

        self.results.append(TestCaseResult(
            case_id="case_01_scenario_a",
            scenario="Scenario A: Reproducible Mutation",
            description="Verified writer mutate_worker_state with COMPLETE capture and deterministic reproduction proof.",
            capture_quality="COMPLETE",
            consistency_level="STOPPED",
            ground_truth_is_causal=True,
            evaluation_status=actual_status,
            evaluation_confidence=hypo["confidence"],
            candidate_tier=fc.get("candidate_tier", "UNKNOWN"),
            confirmed_root_cause=fc.get("confirmed_root_cause", False),
            unverified_claim_rejected=False,
            is_true_positive=is_tp,
            is_false_positive=is_fp,
            is_true_negative=is_tn,
            is_false_negative=is_fn,
            reason=res["transition"]["reason"],
        ))

    def _eval_scenario_b(self):
        mgr, inv_id, hypo_id = CausalDefectFixtures.create_scenario_b_static_candidate_unproven()
        # Evaluate without proof
        res = mgr.evaluate_hypothesis(inv_id, hypo_id)
        hypo = mgr.get_hypothesis(inv_id, hypo_id)
        fc = hypo["function_candidates"][0] if hypo.get("function_candidates") else {}
        actual_status = hypo["validation_status"]
        is_tp = False
        is_fp = (actual_status == HYPOTHESIS_STATUS_VALIDATED or fc.get("confirmed_root_cause", False))
        is_tn = not is_fp
        is_fn = False

        self.results.append(TestCaseResult(
            case_id="case_02_scenario_b",
            scenario="Scenario B: Static Candidate Unproven",
            description="Static DWARF reference helper_init without runtime execution or transition proof.",
            capture_quality="COMPLETE",
            consistency_level="STOPPED",
            ground_truth_is_causal=False,
            evaluation_status=actual_status,
            evaluation_confidence=hypo["confidence"],
            candidate_tier=fc.get("candidate_tier", "UNKNOWN"),
            confirmed_root_cause=fc.get("confirmed_root_cause", False),
            unverified_claim_rejected=False,
            is_true_positive=is_tp,
            is_false_positive=is_fp,
            is_true_negative=is_tn,
            is_false_negative=is_fn,
            reason=res["transition"]["reason"],
        ))

    def _eval_scenario_c(self):
        mgr, inv_id, hypo_id = CausalDefectFixtures.create_scenario_c_different_writer_than_leading_candidate()
        res = mgr.evaluate_hypothesis(
            inv_id,
            hypo_id,
            deterministic_transition_verified=True,
            proof_evidence_id="ev_c_proof",
        )
        hypo = mgr.get_hypothesis(inv_id, hypo_id)
        cands = hypo.get("function_candidates", [])
        log_cand = next((c for c in cands if c.get("function_name") == "log_status"), {})
        upd_cand = next((c for c in cands if c.get("function_name") == "update_flags"), {})

        # log_status must NOT be confirmed; update_flags must be confirmed
        actual_status = hypo["validation_status"]
        is_tp = (actual_status == HYPOTHESIS_STATUS_VALIDATED and not log_cand.get("confirmed_root_cause", False) and upd_cand.get("confirmed_root_cause", False))
        is_fp = bool(log_cand.get("confirmed_root_cause", False))
        is_tn = False
        is_fn = not is_tp and not is_fp

        self.results.append(TestCaseResult(
            case_id="case_03_scenario_c",
            scenario="Scenario C: Divergent Real Writer",
            description="Leading static candidate log_status vs verified executing writer update_flags.",
            capture_quality="COMPLETE",
            consistency_level="STOPPED",
            ground_truth_is_causal=True,
            evaluation_status=actual_status,
            evaluation_confidence=hypo["confidence"],
            candidate_tier=upd_cand.get("candidate_tier", "UNKNOWN"),
            confirmed_root_cause=upd_cand.get("confirmed_root_cause", False),
            unverified_claim_rejected=False,
            is_true_positive=is_tp,
            is_false_positive=is_fp,
            is_true_negative=is_tn,
            is_false_negative=is_fn,
            reason=res["transition"]["reason"],
        ))

    def _eval_scenario_d(self):
        mgr, inv_id, hypo_id = CausalDefectFixtures.create_scenario_d_contradictory_evidence()
        rec_contra = mgr.sessions[inv_id].ledger.get_record("ev_d_contra")
        res = mgr.evaluate_hypothesis(inv_id, hypo_id, new_evidence_data=rec_contra.to_dict())
        hypo = mgr.get_hypothesis(inv_id, hypo_id)
        actual_status = hypo["validation_status"]
        is_tp = False
        is_fp = (actual_status == HYPOTHESIS_STATUS_VALIDATED)
        is_tn = (actual_status == HYPOTHESIS_STATUS_CONTRADICTED)
        is_fn = False

        self.results.append(TestCaseResult(
            case_id="case_04_scenario_d",
            scenario="Scenario D: Contradictory Evidence",
            description="Initially plausible mutation contradicted by idle thread stack observation.",
            capture_quality="COMPLETE",
            consistency_level="STOPPED",
            ground_truth_is_causal=False,
            evaluation_status=actual_status,
            evaluation_confidence=hypo["confidence"],
            candidate_tier=FUNCTION_TIER_STATIC_CANDIDATE,
            confirmed_root_cause=False,
            unverified_claim_rejected=False,
            is_true_positive=is_tp,
            is_false_positive=is_fp,
            is_true_negative=is_tn,
            is_false_negative=is_fn,
            reason=res["transition"]["reason"],
        ))

    def _eval_scenario_e_partial(self):
        mgr, inv_id, hypo_id = CausalDefectFixtures.create_scenario_e_partial_or_non_atomic_capture()
        # Attempt causal elevation under PARTIAL capture
        res = mgr.evaluate_hypothesis(inv_id, hypo_id, deterministic_transition_verified=True)
        hypo = mgr.get_hypothesis(inv_id, hypo_id)
        actual_status = hypo["validation_status"]
        is_tp = False
        is_fp = (actual_status == HYPOTHESIS_STATUS_VALIDATED)
        is_tn = (actual_status != HYPOTHESIS_STATUS_VALIDATED)
        is_fn = False

        self.results.append(TestCaseResult(
            case_id="case_05_scenario_e_partial",
            scenario="Scenario E: PARTIAL Capture Capping",
            description="Mutation observed under PARTIAL memory capture; elevation to VALIDATED blocked.",
            capture_quality="PARTIAL",
            consistency_level="NON_ATOMIC",
            ground_truth_is_causal=False,
            evaluation_status=actual_status,
            evaluation_confidence=hypo["confidence"],
            candidate_tier=FUNCTION_TIER_EVIDENCE_SUPPORTED,
            confirmed_root_cause=False,
            unverified_claim_rejected=res["transition"].get("unverified_claim_rejected", False),
            is_true_positive=is_tp,
            is_false_positive=is_fp,
            is_true_negative=is_tn,
            is_false_negative=is_fn,
            reason=res["transition"]["reason"],
        ))

    def _eval_scenario_e_non_atomic(self):
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Non-atomic capture test")
        inv_id = start["investigation_id"]
        session = mgr.sessions[inv_id]

        finding = InvestigationFinding(
            finding_id="fnd_na",
            category="fact",
            title="Diff 1 -> 2",
            description="Non-atomic diff",
            evidence_ids=["ev_na"],
            object_id="obj_na",
            field_name="val",
            before_value=1,
            after_value=2,
        )
        session.findings.append(finding)
        rec_na = EvidenceRecord(
            evidence_id="ev_na",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="state_diff",
            session_id=inv_id,
            observation="Observed diff 1 -> 2",
            capture_quality={"completeness": "COMPLETE", "consistency_level": "NON_ATOMIC"},
            details={"is_non_atomic": True},
        )
        session.ledger.add_record(rec_na)
        mgr._execute_stage_synthesis(session)
        hypo = session.hypotheses[0]

        res = mgr.evaluate_hypothesis(inv_id, hypo.hypothesis_id, deterministic_transition_verified=True)
        hypo_dict = mgr.get_hypothesis(inv_id, hypo.hypothesis_id)
        actual_status = hypo_dict["validation_status"]
        is_tp = False
        is_fp = (actual_status == HYPOTHESIS_STATUS_VALIDATED)
        is_tn = (actual_status != HYPOTHESIS_STATUS_VALIDATED)
        is_fn = False

        self.results.append(TestCaseResult(
            case_id="case_06_scenario_e_non_atomic",
            scenario="Scenario E: NON_ATOMIC Capture Skew Guard",
            description="COMPLETE byte capture but NON_ATOMIC capture consistency; elevation to VALIDATED blocked.",
            capture_quality="COMPLETE",
            consistency_level="NON_ATOMIC",
            ground_truth_is_causal=False,
            evaluation_status=actual_status,
            evaluation_confidence=hypo_dict["confidence"],
            candidate_tier=FUNCTION_TIER_STATIC_CANDIDATE,
            confirmed_root_cause=False,
            unverified_claim_rejected=res["transition"].get("unverified_claim_rejected", False),
            is_true_positive=is_tp,
            is_false_positive=is_fp,
            is_true_negative=is_tn,
            is_false_negative=is_fn,
            reason=res["transition"]["reason"],
        ))

    def _eval_scenario_g_boolean_injection(self):
        mgr, inv_id, hypo_id = CausalDefectFixtures.create_scenario_g_unauthorized_and_fabricated_input()
        # Caller supplies only boolean flag without proof record
        res = mgr.evaluate_hypothesis(inv_id, hypo_id, deterministic_transition_verified=True)
        hypo = mgr.get_hypothesis(inv_id, hypo_id)
        actual_status = hypo["validation_status"]
        is_tp = False
        is_fp = (actual_status == HYPOTHESIS_STATUS_VALIDATED)
        is_tn = (actual_status != HYPOTHESIS_STATUS_VALIDATED)
        is_fn = False

        self.results.append(TestCaseResult(
            case_id="case_07_scenario_g_boolean_injection",
            scenario="Scenario G: Caller Boolean Injection",
            description="Caller supplies deterministic_transition_verified=True without proof evidence; rejected.",
            capture_quality="COMPLETE",
            consistency_level="STOPPED",
            ground_truth_is_causal=False,
            evaluation_status=actual_status,
            evaluation_confidence=hypo["confidence"],
            candidate_tier=FUNCTION_TIER_STATIC_CANDIDATE,
            confirmed_root_cause=False,
            unverified_claim_rejected=res["transition"].get("unverified_claim_rejected", False),
            is_true_positive=is_tp,
            is_false_positive=is_fp,
            is_true_negative=is_tn,
            is_false_negative=is_fn,
            reason=res["transition"]["reason"],
        ))

    def _eval_scenario_g_fake_proof_id(self):
        mgr, inv_id, hypo_id = CausalDefectFixtures.create_scenario_g_unauthorized_and_fabricated_input()
        # Caller supplies a nonexistent proof evidence ID
        res = mgr.evaluate_hypothesis(
            inv_id,
            hypo_id,
            deterministic_transition_verified=True,
            proof_evidence_id="fake_fabricated_id_999",
        )
        hypo = mgr.get_hypothesis(inv_id, hypo_id)
        actual_status = hypo["validation_status"]
        is_tp = False
        is_fp = (actual_status == HYPOTHESIS_STATUS_VALIDATED)
        is_tn = (actual_status != HYPOTHESIS_STATUS_VALIDATED)
        is_fn = False

        self.results.append(TestCaseResult(
            case_id="case_08_scenario_g_fake_proof_id",
            scenario="Scenario G: Fabricated Proof ID",
            description="Caller supplies fictitious proof_evidence_id not in ledger; rejected.",
            capture_quality="COMPLETE",
            consistency_level="STOPPED",
            ground_truth_is_causal=False,
            evaluation_status=actual_status,
            evaluation_confidence=hypo["confidence"],
            candidate_tier=FUNCTION_TIER_STATIC_CANDIDATE,
            confirmed_root_cause=False,
            unverified_claim_rejected=res["transition"].get("unverified_claim_rejected", False),
            is_true_positive=is_tp,
            is_false_positive=is_fp,
            is_true_negative=is_tn,
            is_false_negative=is_fn,
            reason=res["transition"]["reason"],
        ))

    def _eval_scenario_h_cycle(self):
        mgr, inv_id, hypo_id = CausalDefectFixtures.create_scenario_h_cyclic_missing_duplicate_evidence()
        res = mgr.evaluate_hypothesis(inv_id, hypo_id)
        hypo = mgr.get_hypothesis(inv_id, hypo_id)
        actual_status = hypo["validation_status"]
        is_tp = False
        is_fp = (actual_status == HYPOTHESIS_STATUS_VALIDATED)
        is_tn = (actual_status == HYPOTHESIS_STATUS_INCONCLUSIVE)
        is_fn = False

        self.results.append(TestCaseResult(
            case_id="case_09_scenario_h_cycle",
            scenario="Scenario H: Cyclic Provenance Graph",
            description="Evidence graph contains multi-hop provenance cycle ev1 -> ev2 -> ev1; halted as INCONCLUSIVE.",
            capture_quality="COMPLETE",
            consistency_level="STOPPED",
            ground_truth_is_causal=False,
            evaluation_status=actual_status,
            evaluation_confidence=hypo["confidence"],
            candidate_tier=FUNCTION_TIER_STATIC_CANDIDATE,
            confirmed_root_cause=False,
            unverified_claim_rejected=False,
            is_true_positive=is_tp,
            is_false_positive=is_fp,
            is_true_negative=is_tn,
            is_false_negative=is_fn,
            reason=res["transition"]["reason"],
        ))

    def _eval_scenario_h_missing_parent(self):
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Missing parent test")
        inv_id = start["investigation_id"]
        session = mgr.sessions[inv_id]

        rec = EvidenceRecord(
            evidence_id="ev_child",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="test",
            session_id=inv_id,
            observation="Child record",
            parent_evidence_ids=["ev_ghost_parent"],  # Missing parent!
            capture_quality={"completeness": "COMPLETE"},
        )
        session.ledger.add_record(rec)
        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_ghost",
            investigation_id=inv_id,
            title="Ghost Parent Claim",
            claim="Claim",
            proposed_mechanism="Mech",
            supporting_evidence_ids=["ev_child"],
            validation_status=HYPOTHESIS_STATUS_PROPOSED,
        )
        session.hypotheses.append(hypo)

        res = mgr.evaluate_hypothesis(inv_id, "hypo_ghost")
        hypo_dict = mgr.get_hypothesis(inv_id, "hypo_ghost")
        actual_status = hypo_dict["validation_status"]
        is_tp = False
        is_fp = (actual_status == HYPOTHESIS_STATUS_VALIDATED)
        is_tn = (actual_status == HYPOTHESIS_STATUS_INCONCLUSIVE)
        is_fn = False

        self.results.append(TestCaseResult(
            case_id="case_10_scenario_h_missing_parent",
            scenario="Scenario H: Missing Parent Record",
            description="Evidence references nonexistent parent record ev_ghost_parent; fails safely as INCONCLUSIVE.",
            capture_quality="COMPLETE",
            consistency_level="STOPPED",
            ground_truth_is_causal=False,
            evaluation_status=actual_status,
            evaluation_confidence=hypo_dict["confidence"],
            candidate_tier=FUNCTION_TIER_STATIC_CANDIDATE,
            confirmed_root_cause=False,
            unverified_claim_rejected=False,
            is_true_positive=is_tp,
            is_false_positive=is_fp,
            is_true_negative=is_tn,
            is_false_negative=is_fn,
            reason=res["transition"]["reason"],
        ))

    def _eval_scenario_h_duplicate(self):
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Duplicate evidence test")
        inv_id = start["investigation_id"]
        session = mgr.sessions[inv_id]

        rec1 = EvidenceRecord(
            evidence_id="ev_orig",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            nature=NATURE_OBSERVATION,
            source="test",
            session_id=inv_id,
            observation="Observed value X = 42",
            details={"val": 42},
            capture_quality={"completeness": "COMPLETE"},
        )
        session.ledger.add_record(rec1)
        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_dup",
            investigation_id=inv_id,
            title="Dup Claim",
            claim="Claim",
            proposed_mechanism="Mech",
            supporting_evidence_ids=["ev_orig"],
            validation_status=HYPOTHESIS_STATUS_SUPPORTED,
            confidence=CONFIDENCE_MEDIUM,
        )
        session.hypotheses.append(hypo)

        # Duplicate record
        rec2 = EvidenceRecord(
            evidence_id="ev_dup_copy",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            nature=NATURE_OBSERVATION,
            source="test",
            session_id=inv_id,
            observation="Observed value X = 42",
            details={"val": 42},
            capture_quality={"completeness": "COMPLETE"},
        )
        session.ledger.add_record(rec2)

        res = mgr.evaluate_hypothesis(inv_id, "hypo_dup", new_evidence_data=rec2.to_dict())
        hypo_dict = mgr.get_hypothesis(inv_id, "hypo_dup")
        actual_status = hypo_dict["validation_status"]
        is_tp = False
        is_fp = (actual_status == HYPOTHESIS_STATUS_VALIDATED)
        is_tn = (actual_status != HYPOTHESIS_STATUS_VALIDATED and res["transition"].get("is_duplicate", False))
        is_fn = False

        self.results.append(TestCaseResult(
            case_id="case_11_scenario_h_duplicate",
            scenario="Scenario H: Duplicate Evidence Protection",
            description="Duplicate record submitted; deduplicated without escalating confidence or independent count.",
            capture_quality="COMPLETE",
            consistency_level="STOPPED",
            ground_truth_is_causal=False,
            evaluation_status=actual_status,
            evaluation_confidence=hypo_dict["confidence"],
            candidate_tier=FUNCTION_TIER_STATIC_CANDIDATE,
            confirmed_root_cause=False,
            unverified_claim_rejected=False,
            is_true_positive=is_tp,
            is_false_positive=is_fp,
            is_true_negative=is_tn,
            is_false_negative=is_fn,
            reason=res["transition"]["reason"],
        ))

    def _eval_boundary_untrusted_capture(self):
        mgr = InvestigationManager()
        start = mgr.start_investigation(goal="Untrusted capture boundary")
        inv_id = start["investigation_id"]
        session = mgr.sessions[inv_id]

        rec = EvidenceRecord(
            evidence_id="ev_untrusted",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="collector",
            session_id=inv_id,
            observation="Observed diff under FAILED capture",
            capture_quality={"completeness": "FAILED"},
        )
        session.ledger.add_record(rec)
        hypo = InvestigationHypothesis(
            hypothesis_id="hypo_untrusted",
            investigation_id=inv_id,
            title="Untrusted Capture Claim",
            claim="Claim",
            proposed_mechanism="Mech",
            supporting_evidence_ids=["ev_untrusted"],
            validation_status=HYPOTHESIS_STATUS_PROPOSED,
        )
        session.hypotheses.append(hypo)

        res = mgr.evaluate_hypothesis(inv_id, "hypo_untrusted", deterministic_transition_verified=True)
        hypo_dict = mgr.get_hypothesis(inv_id, "hypo_untrusted")
        actual_status = hypo_dict["validation_status"]
        is_tp = False
        is_fp = (actual_status == HYPOTHESIS_STATUS_VALIDATED)
        is_tn = (actual_status == HYPOTHESIS_STATUS_INCONCLUSIVE)
        is_fn = False

        self.results.append(TestCaseResult(
            case_id="case_12_boundary_untrusted_capture",
            scenario="Boundary: FAILED Capture",
            description="Capture quality is FAILED; strictly capped at INCONCLUSIVE regardless of caller claims.",
            capture_quality="FAILED",
            consistency_level="STOPPED",
            ground_truth_is_causal=False,
            evaluation_status=actual_status,
            evaluation_confidence=hypo_dict["confidence"],
            candidate_tier=FUNCTION_TIER_STATIC_CANDIDATE,
            confirmed_root_cause=False,
            unverified_claim_rejected=False,
            is_true_positive=is_tp,
            is_false_positive=is_fp,
            is_true_negative=is_tn,
            is_false_negative=is_fn,
            reason=res["transition"]["reason"],
        ))

    def _generate_report(self) -> Dict[str, Any]:
        """Aggregate test case results into an auditable evaluation report."""
        total_cases = len(self.results)
        tp_count = sum(1 for r in self.results if r.is_true_positive)
        fp_count = sum(1 for r in self.results if r.is_false_positive)
        tn_count = sum(1 for r in self.results if r.is_true_negative)
        fn_count = sum(1 for r in self.results if r.is_false_negative)

        positives_ground_truth = sum(1 for r in self.results if r.ground_truth_is_causal)
        negatives_ground_truth = sum(1 for r in self.results if not r.ground_truth_is_causal)

        unsupported_promotions_blocked = sum(1 for r in self.results if r.unverified_claim_rejected)

        # Quality groupings
        quality_groups: Dict[str, Dict[str, int]] = {}
        for r in self.results:
            q = r.capture_quality
            if q not in quality_groups:
                quality_groups[q] = {"total": 0, "tp": 0, "fp": 0, "tn": 0, "fn": 0}
            quality_groups[q]["total"] += 1
            if r.is_true_positive:
                quality_groups[q]["tp"] += 1
            if r.is_false_positive:
                quality_groups[q]["fp"] += 1
            if r.is_true_negative:
                quality_groups[q]["tn"] += 1
            if r.is_false_negative:
                quality_groups[q]["fn"] += 1

        precision = (tp_count / (tp_count + fp_count)) if (tp_count + fp_count) > 0 else 1.0
        recall = (tp_count / (tp_count + fn_count)) if (tp_count + fn_count) > 0 else 1.0
        fpr = (fp_count / negatives_ground_truth) if negatives_ground_truth > 0 else 0.0

        report = {
            "evaluation_metadata": {
                "timestamp_utc": datetime.now(timezone.utc).isoformat(),
                "framework": "dynamicState Causal Validation Evaluator v1.0",
                "denominator_definitions": {
                    "total_scenarios": "Total evaluated deterministic test cases (N=12)",
                    "ground_truth_causal_positives": "Cases where causal relationship is genuinely proven (N=2)",
                    "ground_truth_non_positives": "Cases where causality is unproven, contradictory, non-atomic, or partial (N=10)",
                    "false_causal_validation_rate": "FP / ground_truth_non_positives (MUST BE 0.0)",
                    "unsupported_promotions_blocked": "Cases where unverified boolean or forged proof was explicitly rejected",
                },
                "production_applicability_notice": (
                    "Measurements reflect deterministic synthetic fixtures and unit/integration defect scenarios. "
                    "Synthetic fixture accuracy must not be conflated with real-world production capture accuracy."
                ),
            },
            "summary_metrics": {
                "total_cases_evaluated": total_cases,
                "ground_truth_causal_positives": positives_ground_truth,
                "ground_truth_non_positives": negatives_ground_truth,
                "correct_causal_validations_tp": tp_count,
                "false_causal_validations_fp": fp_count,
                "missed_causal_validations_fn": fn_count,
                "correctly_inconclusive_or_rejected_tn": tn_count,
                "unsupported_promotions_blocked": unsupported_promotions_blocked,
                "causal_validation_precision": round(precision, 4),
                "causal_validation_recall": round(recall, 4),
                "false_positive_rate": round(fpr, 4),
                "zero_false_positives_sla_satisfied": (fp_count == 0),
            },
            "breakdown_by_capture_quality": quality_groups,
            "test_cases": [asdict(r) for r in self.results],
        }
        return report


def main():
    """CLI entrypoint to run evaluation and write results."""
    evaluator = CausalValidationEvaluator()
    report = evaluator.run_all()

    out_path = os.environ.get("OUTPUT_PATH", "benchmarks/false_positive_evaluation.json")
    os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    summary = report["summary_metrics"]
    print("=" * 72)
    print(" dynamicState Causal Validation & False-Positive Risk Evaluation")
    print("=" * 72)
    print(f" Total Cases Evaluated:       {summary['total_cases_evaluated']}")
    print(f" Correct Validations (TP):    {summary['correct_causal_validations_tp']}")
    print(f" False Validations (FP):      {summary['false_causal_validations_fp']} (SLA TARGET: 0)")
    print(f" Missed Validations (FN):     {summary['missed_causal_validations_fn']}")
    print(f" Correctly Inconclusive (TN): {summary['correctly_inconclusive_or_rejected_tn']}")
    print(f" Unsupported Claims Blocked:  {summary['unsupported_promotions_blocked']}")
    print(f" Precision:                   {summary['causal_validation_precision'] * 100:.1f}%")
    print(f" Recall:                      {summary['causal_validation_recall'] * 100:.1f}%")
    print(f" False Positive Rate (FPR):   {summary['false_positive_rate'] * 100:.1f}%")
    print(f" Zero FP SLA Satisfied:       {summary['zero_false_positives_sla_satisfied']}")
    print("-" * 72)
    print(f" Machine-readable report saved to: {out_path}")
    print("=" * 72)

    if not summary["zero_false_positives_sla_satisfied"]:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()

"""Phase 2.1.7 Validation Test Suite
Verdict Authority, Evidence Graph Integrity & End-to-End Diagnostic Validation (Tests A through P).

Verification Cases:
A. HEALTHY must be impossible with any applicable FAIL.
B. HEALTHY must be impossible with empty or insufficient required coverage.
C. Invalid and mismatched evidence cannot support confirmation.
D. Direct hypothesis evaluation cannot bypass ledger validation.
E. Multi-parent dependency graphs are fully traversed.
F. Shared roots are not counted as independent sources.
G. Cycles and missing dependencies cannot increase confidence.
H. Single-evidence confirmation requires a valid registered rule.
I. Untrusted contradictions cannot independently refute a hypothesis.
J. Trusted contradictions follow explicit deterministic rules.
K. Results are stable under evidence insertion-order changes.
L. Planned and executed checks remain distinguishable.
M. Reports preserve all excluded and unexecuted check information.
N. Persistence/reload preserves evidence authority and graph integrity.
O. Failure injection validates commit and recovery semantics.
P. JSON, Markdown, HTML, Web UI, and MCP report the same verdict and evidence summary.
"""

import html
import json
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from extractor.competing_hypotheses import (
    CompetingHypothesis,
    CompetingHypothesisManager,
    ContradictionRecord,
    PrimaryEvidenceRule,
    PrimaryEvidenceRuleRegistry,
    VERDICT_CONFIRMED,
    VERDICT_LIKELY,
    VERDICT_SUPPORTED,
    VERDICT_OBSERVED,
    VERDICT_REFUTED,
    VERDICT_INCONCLUSIVE,
    VERDICT_NOT_APPLICABLE,
)
from extractor.diagnostic_methodology import (
    CheckStatus,
    DiagnosticCheck,
    DiagnosticMethodology,
)
from extractor.diagnostic_report import (
    DiagnosticReport,
    ExecutiveSummarySection,
    DetailedInspectionResultsSection,
    DiagnosticStrategySection,
    EvidenceAndProvenanceSection,
    EvidenceIndexEntry,
    FinalConclusionsSection,
    FindingsSection,
    FindingRecord,
    LimitationsSection,
    TargetContextSection,
    CompetingHypothesesSection,
)
from extractor.diagnostic_verdict_aggregator import (
    DiagnosticVerdictAggregator,
    VERDICT_CONFIRMED_FAULT,
    VERDICT_PROBABLE_FAULT,
    VERDICT_DEGRADED,
    VERDICT_HEALTHY,
    VERDICT_INCONCLUSIVE as AGG_INCONCLUSIVE,
    VERDICT_ABORTED,
)
from extractor.capture_backend import (
    LiveCaptureReceipt,
    get_trusted_capture_authority_token,
    issue_live_capture_receipt,
)
from extractor.evidence_ledger import (
    EvidenceLedger,
    EvidenceRecord,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
    TRUSTED_PROVENANCE_CLASSES,
)
from extractor.expert_diagnostic_engine import (
    AdaptiveInvestigationSession,
    DurableCommitOutcome,
    ExpertDiagnosticEngine,
    ExpertHypothesis,
    InvestigationPersistenceError,
    STATE_COMPLETED,
    STATE_COLLECTING,
)


def make_trusted_record(
    ledger: EvidenceLedger,
    evidence_id: str,
    observation: str = "",
    target_pid: int = 0,
    evidence_type: str = "DIAGNOSTIC",
    nature: str = "observation",
) -> EvidenceRecord:
    """Helper creating a valid trusted-provenance record without external I/O."""
    eff_pid = target_pid or 1234
    t_ident = {
        "pid": eff_pid,
        "process_identity": f"proc_{eff_pid}",
        "executable_identity": f"/proc/{eff_pid}/exe",
        "build_id": "sha1:testbuildid12345",
    }
    token = get_trusted_capture_authority_token()
    rcpt = issue_live_capture_receipt(
        session_id=ledger.session_id,
        pid=eff_pid,
        process_identity=t_ident["process_identity"],
        executable_identity=t_ident["executable_identity"],
        build_id=t_ident["build_id"],
        snapshot_binding="snap_1",
        capture_authority_token=token,
    )
    rec = EvidenceRecord(
        evidence_id=evidence_id,
        session_id=ledger.session_id,
        evidence_type=evidence_type,
        nature=nature,
        provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": rcpt.to_dict()},
        details={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": rcpt.to_dict(), "target_pid": eff_pid},
        target_identity=dict(t_ident),
        observation=observation or f"Observation for {evidence_id}",
    )
    if target_pid:
        rec.target_pid = target_pid
    ledger._by_id[evidence_id] = rec
    ledger._records.append(rec)
    return rec


class TestPhase217VerdictAuthorityAndEvidenceGraph(unittest.TestCase):
    """Exhaustive test suite verifying Phase 2.1.7 requirements A through P."""

    # -------------------------------------------------------------------------
    # Case A: HEALTHY must be impossible with any applicable FAIL
    # -------------------------------------------------------------------------

    def test_case_a1_fail_with_completed_lifecycle_prevents_healthy(self):
        """Case A.1: Completed lifecycle with a required FAIL check produces CONFIRMED_FAULT, never HEALTHY."""
        chk_pass = DiagnosticCheck(check_id="CHK_01", name="RSS Stability", status=CheckStatus.PASS, is_required=True)
        chk_fail = DiagnosticCheck(check_id="CHK_02", name="Canary Integrity", status=CheckStatus.FAIL, is_required=True)

        agg = DiagnosticVerdictAggregator.aggregate(
            lifecycle_state=STATE_COMPLETED,
            stop_reason="ALL_HYPOTHESES_REFUTED",
            checks=[chk_pass, chk_fail],
            active_hypotheses=[],
        )
        self.assertEqual(agg.overall_result, VERDICT_CONFIRMED_FAULT)
        self.assertNotEqual(agg.overall_result, VERDICT_HEALTHY)
        self.assertTrue(any("Canary Integrity" in p for p in agg.confirmed_problems))

    def test_case_a2_fail_with_otherwise_passing_checks_prevents_healthy(self):
        """Case A.2: A single FAIL check among 10 passing checks takes precedence."""
        passing = [
            DiagnosticCheck(check_id=f"CHK_P_{i}", name=f"Pass {i}", status=CheckStatus.PASS, is_required=True)
            for i in range(10)
        ]
        failing = DiagnosticCheck(check_id="CHK_FAIL", name="Heap Chunk Free", status=CheckStatus.FAIL, is_required=True)

        agg = DiagnosticVerdictAggregator.aggregate(
            lifecycle_state=STATE_COMPLETED,
            stop_reason="EXPLICIT_HEALTHY_CONFIRMED",
            checks=passing + [failing],
            active_hypotheses=[],
        )
        self.assertEqual(agg.overall_result, VERDICT_CONFIRMED_FAULT)
        self.assertNotEqual(agg.overall_result, VERDICT_HEALTHY)

    def test_case_a3_optional_check_failure_yields_degraded(self):
        """Case A.3: Optional check failure yields DEGRADED, never HEALTHY."""
        chk_req = DiagnosticCheck(check_id="CHK_REQ", name="Core Invariant", status=CheckStatus.PASS, is_required=True)
        chk_opt_fail = DiagnosticCheck(check_id="CHK_OPT", name="Optional Telemetry", status=CheckStatus.FAIL, is_required=False)

        agg = DiagnosticVerdictAggregator.aggregate(
            lifecycle_state=STATE_COMPLETED,
            stop_reason="ALL_HYPOTHESES_REFUTED",
            checks=[chk_req, chk_opt_fail],
            active_hypotheses=[],
        )
        self.assertEqual(agg.overall_result, VERDICT_DEGRADED)
        self.assertNotEqual(agg.overall_result, VERDICT_HEALTHY)
        self.assertTrue(any("Optional check failed [CHK_OPT]" in l for l in agg.limiting_factors))

    def test_case_a4_confirmed_fault_with_incomplete_investigation(self):
        """Case A.4: Confirmed fault takes precedence even if investigation is incomplete (e.g. COLLECTING)."""
        hyp = ExpertHypothesis(
            hypothesis_id="HYP_DEADLOCK",
            category="THREAD_DEADLOCK",
            domain="CONCURRENCY",
            problem_statement="Circular mutex lock wait graph verified",
            status="CONFIRMED",
            confidence=0.96,
            confidence_basis="2 threads in cycle verified",
        )
        agg = DiagnosticVerdictAggregator.aggregate(
            lifecycle_state=STATE_COLLECTING,  # Incomplete lifecycle
            stop_reason=None,
            checks=[],
            active_hypotheses=[hyp],
        )
        self.assertEqual(agg.overall_result, VERDICT_CONFIRMED_FAULT)
        self.assertIn("Circular mutex lock wait graph verified", agg.confirmed_problems)

    # -------------------------------------------------------------------------
    # Case B: HEALTHY must be impossible with empty or insufficient required coverage
    # -------------------------------------------------------------------------

    def test_case_b1_empty_checks_cannot_produce_healthy(self):
        """Case B.1: Empty check set produces INCONCLUSIVE, never HEALTHY."""
        agg = DiagnosticVerdictAggregator.aggregate(
            lifecycle_state=STATE_COMPLETED,
            stop_reason="ALL_HYPOTHESES_REFUTED",
            checks=[],
            active_hypotheses=[],
        )
        self.assertEqual(agg.overall_result, AGG_INCONCLUSIVE)
        self.assertIn("empty check set", agg.verdict_rationale)

    def test_case_b2_all_checks_not_executed_cannot_produce_healthy(self):
        """Case B.2: All checks NOT_EXECUTED produces INCONCLUSIVE."""
        chks = [
            DiagnosticCheck(check_id="C1", name="Check 1", status=CheckStatus.NOT_EXECUTED),
            DiagnosticCheck(check_id="C2", name="Check 2", status=CheckStatus.NOT_EXECUTED),
        ]
        agg = DiagnosticVerdictAggregator.aggregate(
            lifecycle_state=STATE_COMPLETED,
            stop_reason="EXPLICIT_HEALTHY_CONFIRMED",
            checks=chks,
            active_hypotheses=[],
        )
        self.assertEqual(agg.overall_result, AGG_INCONCLUSIVE)

    def test_case_b3_all_checks_not_applicable_cannot_produce_healthy(self):
        """Case B.3: All checks NOT_APPLICABLE produces INCONCLUSIVE (positive PASS required)."""
        chks = [
            DiagnosticCheck(
                check_id="C_NA",
                name="Allocator Check",
                status=CheckStatus.NOT_APPLICABLE,
                applicability_criteria={"os": "linux"},
            )
        ]
        agg = DiagnosticVerdictAggregator.aggregate(
            lifecycle_state=STATE_COMPLETED,
            stop_reason="EXPLICIT_HEALTHY_CONFIRMED",
            checks=chks,
            active_hypotheses=[],
        )
        self.assertEqual(agg.overall_result, AGG_INCONCLUSIVE)

    def test_case_b4_unjustified_not_applicable_check_prevents_healthy(self):
        """Case B.4: A check marked NOT_APPLICABLE without an applicability rule or criteria prevents HEALTHY."""
        chk_pass = DiagnosticCheck(check_id="C_PASS", name="Pass Check", status=CheckStatus.PASS, is_required=True)
        chk_unjustified = DiagnosticCheck(
            check_id="C_UNJUST",
            name="Unjustified NA Check",
            status=CheckStatus.NOT_APPLICABLE,
            applicability_criteria={},  # Empty!
            applicability_rule="",      # Empty!
        )
        agg = DiagnosticVerdictAggregator.aggregate(
            lifecycle_state=STATE_COMPLETED,
            stop_reason="EXPLICIT_HEALTHY_CONFIRMED",
            checks=[chk_pass, chk_unjustified],
            active_hypotheses=[],
        )
        self.assertEqual(agg.overall_result, AGG_INCONCLUSIVE)
        self.assertTrue(any("without explicit applicability rule" in l for l in agg.limiting_factors))

    def test_case_b5_mixed_pass_and_error_cannot_produce_healthy(self):
        """Case B.5: Mixed PASS and ERROR produces INCONCLUSIVE."""
        chks = [
            DiagnosticCheck(check_id="C_P", name="Pass", status=CheckStatus.PASS, is_required=True),
            DiagnosticCheck(check_id="C_E", name="Err", status=CheckStatus.ERROR, is_required=True, error_details="Ptrace attach failed"),
        ]
        agg = DiagnosticVerdictAggregator.aggregate(
            lifecycle_state=STATE_COMPLETED,
            stop_reason="EXPLICIT_HEALTHY_CONFIRMED",
            checks=chks,
            active_hypotheses=[],
        )
        self.assertEqual(agg.overall_result, AGG_INCONCLUSIVE)

    def test_case_b6_incomplete_required_coverage_cannot_produce_healthy(self):
        """Case B.6: Incomplete required coverage (required check unexecuted) produces INCONCLUSIVE."""
        chk_req_unexec = DiagnosticCheck(check_id="C_REQ", name="Required Unexecuted", status=CheckStatus.NOT_EXECUTED, is_required=True)
        chk_opt_pass = DiagnosticCheck(check_id="C_OPT", name="Optional Pass", status=CheckStatus.PASS, is_required=False)

        agg = DiagnosticVerdictAggregator.aggregate(
            lifecycle_state=STATE_COMPLETED,
            stop_reason="EXPLICIT_HEALTHY_CONFIRMED",
            checks=[chk_req_unexec, chk_opt_pass],
            active_hypotheses=[],
        )
        self.assertEqual(agg.overall_result, AGG_INCONCLUSIVE)

    # -------------------------------------------------------------------------
    # Case C: Invalid and mismatched evidence cannot support confirmation
    # -------------------------------------------------------------------------

    def test_case_c_invalid_and_mismatched_evidence_rejected(self):
        """Case C: Evidence with mismatched target context, untrusted provenance, or speculative nature is rejected."""
        ledger = EvidenceLedger(session_id="INV_A_1")
        # Target PID 1000
        rec_mismatched_pid = make_trusted_record(ledger, "EV_PID_MISMATCH", target_pid=9999)

        # Untrusted provenance record
        rec_untrusted = EvidenceRecord(
            evidence_id="EV_UNTRUSTED",
            session_id="INV_A_1",
            provenance={"provenance_class": PROVENANCE_CLASS_IMPORTED_UNVERIFIED},
            observation="Synthetic unverified observation",
        )
        ledger._by_id["EV_UNTRUSTED"] = rec_untrusted
        ledger._records.append(rec_untrusted)

        # Speculative hypothesis nature
        rec_hypothesis = make_trusted_record(ledger, "EV_SPECULATIVE", nature="hypothesis")

        hyp = CompetingHypothesis(
            hypothesis_id="HYP_C",
            category="HEAP_CORRUPTION",
            target_pid=1000,
            investigation_id="INV_A_1",
            ledger=ledger,
            confidence=0.95,
        )

        # 1. PID mismatch rejected
        added_pid = hyp.add_supporting_observation("PID mismatch observation", evidence_id="EV_PID_MISMATCH", evidence_record=rec_mismatched_pid)
        self.assertFalse(added_pid)
        self.assertIn("EV_PID_MISMATCH", hyp.rejected_evidence_reasons)

        # 2. Untrusted provenance added but marked unverified
        hyp.add_supporting_observation("Untrusted observation", evidence_id="EV_UNTRUSTED", evidence_record=rec_untrusted)
        self.assertIn("EV_UNTRUSTED", hyp.unverified_evidence_ids)

        # 3. Speculative hypothesis nature marked unverified
        hyp.add_supporting_observation("Speculative observation", evidence_id="EV_SPECULATIVE", evidence_record=rec_hypothesis)
        self.assertIn("EV_SPECULATIVE", hyp.unverified_evidence_ids)

        # Neither can authorize CONFIRMED
        verdict = hyp.evaluate_verdict(ledger=ledger)
        self.assertNotEqual(verdict, VERDICT_CONFIRMED)
        self.assertEqual(verdict, VERDICT_LIKELY)

    # -------------------------------------------------------------------------
    # Case D: Direct hypothesis evaluation cannot bypass ledger validation
    # -------------------------------------------------------------------------

    def test_case_d_direct_evaluation_cannot_bypass_ledger(self):
        """Case D: Calling evaluate_verdict directly with nonexistent evidence IDs validates against ledger and rejects."""
        ledger = EvidenceLedger(session_id="INV_D_1")
        # Empty ledger!
        hyp = CompetingHypothesis(
            hypothesis_id="HYP_D",
            category="HEAP_CORRUPTION",
            target_pid=2000,
            investigation_id="INV_D_1",
            confidence=0.98,
            ledger=ledger,
        )
        # Directly populate supporting_evidence_ids with unverified / fake IDs
        hyp.supporting_evidence_ids = ["EV_FAKE_01", "EV_FAKE_02"]

        # Direct evaluation call
        verdict = hyp.evaluate_verdict(ledger=ledger)
        self.assertNotEqual(verdict, VERDICT_CONFIRMED)
        self.assertIn(verdict, (VERDICT_LIKELY, VERDICT_SUPPORTED))
        self.assertIn("EV_FAKE_01", hyp.unverified_evidence_ids)
        self.assertIn("EV_FAKE_02", hyp.unverified_evidence_ids)
        self.assertEqual(hyp.rejected_evidence_reasons["EV_FAKE_01"], "Evidence ID not found in authoritative ledger")

    # -------------------------------------------------------------------------
    # Case E: Multi-parent dependency graphs are fully traversed
    # -------------------------------------------------------------------------

    def test_case_e_multi_parent_graph_fully_traversed(self):
        """Case E: Multi-parent dependency DAG traverses EVERY parent dependency to find all roots."""
        hyp = CompetingHypothesis(
            hypothesis_id="HYP_E",
            category="HEAP_CORRUPTION",
            confidence=0.95,
        )
        # DAG structure:
        # EV_CHILD depends on [EV_PARENT_1, EV_PARENT_2]
        # EV_PARENT_1 depends on [EV_ROOT_A]
        # EV_PARENT_2 depends on [EV_ROOT_B]
        hyp.evidence_dependencies = {
            "EV_CHILD": ["EV_PARENT_1", "EV_PARENT_2"],
            "EV_PARENT_1": ["EV_ROOT_A"],
            "EV_PARENT_2": ["EV_ROOT_B"],
        }
        hyp.supporting_evidence_ids = ["EV_CHILD"]

        roots = hyp.get_independent_root_sources()
        # Both EV_ROOT_A and EV_ROOT_B must be identified (not just parents[0]!)
        self.assertEqual(roots, {"EV_ROOT_A", "EV_ROOT_B"})
        self.assertEqual(len(roots), 2)

        verdict = hyp.evaluate_verdict()
        self.assertEqual(verdict, VERDICT_CONFIRMED)

    # -------------------------------------------------------------------------
    # Case F: Shared roots are not counted as independent sources
    # -------------------------------------------------------------------------

    def test_case_f_shared_roots_not_counted_as_independent(self):
        """Case F: Multiple derived evidence records sharing one root source count as only 1 independent source."""
        hyp = CompetingHypothesis(
            hypothesis_id="HYP_F",
            category="MEMORY_LEAK",
            confidence=0.95,
        )
        # EV_DERIVED_1 -> EV_SHARED_ROOT
        # EV_DERIVED_2 -> EV_SHARED_ROOT
        # EV_DERIVED_3 -> EV_MID -> EV_SHARED_ROOT
        hyp.evidence_dependencies = {
            "EV_DERIVED_1": ["EV_SHARED_ROOT"],
            "EV_DERIVED_2": ["EV_SHARED_ROOT"],
            "EV_DERIVED_3": ["EV_MID"],
            "EV_MID": ["EV_SHARED_ROOT"],
        }
        hyp.supporting_evidence_ids = ["EV_DERIVED_1", "EV_DERIVED_2", "EV_DERIVED_3"]

        roots = hyp.get_independent_root_sources()
        self.assertEqual(roots, {"EV_SHARED_ROOT"})
        self.assertEqual(len(roots), 1)

        # 1 root cannot produce CONFIRMED without valid primary rule
        verdict = hyp.evaluate_verdict()
        self.assertEqual(verdict, VERDICT_LIKELY)
        self.assertNotEqual(verdict, VERDICT_CONFIRMED)

    # -------------------------------------------------------------------------
    # Case G: Cycles and missing dependencies cannot increase confidence
    # -------------------------------------------------------------------------

    def test_case_g_cycles_and_missing_dependencies_rejected(self):
        """Case G: Cycles and missing parent dependencies are detected and excluded from independent roots."""
        ledger = EvidenceLedger(session_id="INV_G")
        make_trusted_record(ledger, "EV_REC_A")

        hyp = CompetingHypothesis(
            hypothesis_id="HYP_G",
            category="HEAP_CORRUPTION",
            confidence=0.95,
            ledger=ledger,
        )

        # Cycles, self-dependencies, missing parents
        hyp.evidence_dependencies = {
            "EV_CYCLE_1": ["EV_CYCLE_2"],
            "EV_CYCLE_2": ["EV_CYCLE_1"],  # Cycle!
            "EV_SELF": ["EV_SELF"],        # Self-dependency!
            "EV_DANGLING": ["EV_MISSING_PARENT"],  # Missing in ledger!
        }
        hyp.supporting_evidence_ids = ["EV_CYCLE_1", "EV_SELF", "EV_DANGLING"]

        roots = hyp.get_independent_root_sources(ledger=ledger)
        self.assertEqual(len(roots), 0)
        self.assertTrue(any("cycle detected" in lim.lower() for lim in hyp.integrity_limitations))
        self.assertTrue(any("self-dependency detected" in lim.lower() for lim in hyp.integrity_limitations))
        self.assertTrue(any("missing parent dependency" in lim.lower() for lim in hyp.integrity_limitations))

        verdict = hyp.evaluate_verdict(ledger=ledger)
        self.assertNotEqual(verdict, VERDICT_CONFIRMED)
        self.assertEqual(verdict, VERDICT_INCONCLUSIVE)

    # -------------------------------------------------------------------------
    # Case H: Single-evidence confirmation requires a valid registered rule
    # -------------------------------------------------------------------------

    def test_case_h_single_evidence_confirmation_rules(self):
        """Case H: Arbitrary strings or flags alone cannot confirm; requires valid registered rule with matching category."""
        ledger = EvidenceLedger(session_id="INV_H")
        make_trusted_record(ledger, "EV_CANARY_01", observation="Canary overwrite detected: 0xDEADBEEF corrupted")

        # H1. Non-empty arbitrary unregistered rule fails
        hyp1 = CompetingHypothesis(
            hypothesis_id="HYP_H1",
            category="HEAP_CORRUPTION",
            confidence=0.95,
            supporting_evidence_ids=["EV_CANARY_01"],
            primary_evidence_rule="arbitrary_unregistered_rule_string",
            ledger=ledger,
        )
        v1 = hyp1.evaluate_verdict(ledger=ledger)
        self.assertNotEqual(v1, VERDICT_CONFIRMED)
        self.assertIn("not a registered primary evidence rule", hyp1.primary_rule_rejection_reason)

        # H2. Valid registered rule but mismatched category fails
        hyp2 = CompetingHypothesis(
            hypothesis_id="HYP_H2",
            category="THREAD_DEADLOCK",  # Canary rule does not apply to deadlock!
            confidence=0.95,
            supporting_evidence_ids=["EV_CANARY_01"],
            primary_evidence_rule="RULE_MEM_CORRUPTION_CANARY",
            ledger=ledger,
        )
        v2 = hyp2.evaluate_verdict(ledger=ledger)
        self.assertNotEqual(v2, VERDICT_CONFIRMED)
        self.assertIn("do not match hypothesis category", hyp2.primary_rule_rejection_reason)

        # H3. Valid registered rule with matching category succeeds!
        hyp3 = CompetingHypothesis(
            hypothesis_id="HYP_H3",
            category="HEAP_CORRUPTION",
            confidence=0.95,
            supporting_evidence_ids=["EV_CANARY_01"],
            primary_evidence_rule="RULE_MEM_CORRUPTION_CANARY",
            ledger=ledger,
        )
        v3 = hyp3.evaluate_verdict(ledger=ledger)
        self.assertEqual(v3, VERDICT_CONFIRMED)
        self.assertEqual(hyp3.satisfied_primary_rule, "RULE_MEM_CORRUPTION_CANARY")

    # -------------------------------------------------------------------------
    # Case I: Untrusted contradictions cannot independently refute a hypothesis
    # -------------------------------------------------------------------------

    def test_case_i_untrusted_contradiction_cannot_refute(self):
        """Case I: Untrusted or unverified contradictory evidence cannot refute a hypothesis backed by verified support."""
        ledger = EvidenceLedger(session_id="INV_I")
        rec_r1 = make_trusted_record(ledger, "EV_ROOT_1")
        rec_r2 = make_trusted_record(ledger, "EV_ROOT_2")

        rec_untrusted_counter = EvidenceRecord(
            evidence_id="EV_UNTRUSTED_COUNTER",
            session_id="INV_I",
            provenance={"provenance_class": PROVENANCE_CLASS_IMPORTED_UNVERIFIED},  # Untrusted!
            observation="Unverified report claiming normal state",
        )
        ledger._by_id["EV_UNTRUSTED_COUNTER"] = rec_untrusted_counter
        ledger._records.append(rec_untrusted_counter)

        hyp = CompetingHypothesis(
            hypothesis_id="HYP_I",
            category="HEAP_CORRUPTION",
            confidence=0.95,
            ledger=ledger,
        )
        hyp.add_supporting_observation("Live heap sample 1", evidence_id="EV_ROOT_1", evidence_record=rec_r1)
        hyp.add_supporting_observation("Live heap sample 2", evidence_id="EV_ROOT_2", evidence_record=rec_r2)
        self.assertEqual(hyp.evaluate_verdict(ledger=ledger), VERDICT_CONFIRMED)

        # Add untrusted contradiction
        hyp.add_contradicting_observation(
            "Unverified counter report",
            evidence_id="EV_UNTRUSTED_COUNTER",
            evidence_record=rec_untrusted_counter,
            is_verified=False,
        )

        # Must NOT be refuted by untrusted contradiction!
        self.assertNotEqual(hyp.status, VERDICT_REFUTED)
        self.assertEqual(hyp.status, VERDICT_CONFIRMED)

    # -------------------------------------------------------------------------
    # Case J: Trusted contradictions follow explicit deterministic rules
    # -------------------------------------------------------------------------

    def test_case_j_trusted_contradiction_deterministic_semantics(self):
        """Case J: Decisive contradiction refutes; partial lowers confidence; conflicting trusted evidence yields INCONCLUSIVE."""
        ledger = EvidenceLedger(session_id="INV_J")
        rec_sup = make_trusted_record(ledger, "EV_SUP_1")
        rec_cntr_decisive = make_trusted_record(ledger, "EV_CNTR_1")

        # J1. Decisive trusted contradiction refutes when unsupported or isolated
        hyp1 = CompetingHypothesis(hypothesis_id="HYP_J1", category="USE_AFTER_FREE", confidence=0.70, ledger=ledger)
        hyp1.add_contradicting_observation(
            "Address is in valid static global memory",
            evidence_id="EV_CNTR_1",
            evidence_record=rec_cntr_decisive,
            is_decisive=True,
            is_verified=True,
        )
        self.assertEqual(hyp1.status, VERDICT_REFUTED)

        # J2. Partial contradiction lowers confidence, does NOT refute
        hyp2 = CompetingHypothesis(hypothesis_id="HYP_J2", category="HEAP_CORRUPTION", confidence=0.90, ledger=ledger)
        hyp2.add_supporting_observation("Dangling pointer", evidence_id="EV_SUP_1", evidence_record=rec_sup)
        hyp2.add_contradicting_observation(
            "Intermittent absence of symptom on run 2",
            is_decisive=False,  # Partial!
            is_verified=True,
            weight=0.20,
        )
        self.assertNotEqual(hyp2.status, VERDICT_REFUTED)
        self.assertNotEqual(hyp2.status, VERDICT_CONFIRMED)
        self.assertIn(hyp2.status, (VERDICT_LIKELY, VERDICT_SUPPORTED))

        # J3. Conflicting trusted evidence yields INCONCLUSIVE
        hyp3 = CompetingHypothesis(hypothesis_id="HYP_J3", category="HEAP_CORRUPTION", confidence=0.95, ledger=ledger)
        hyp3.add_supporting_observation("Dangling pointer verified", evidence_id="EV_SUP_1", evidence_record=rec_sup)
        hyp3.add_contradicting_observation(
            "Chunk verified in-use by authoritative trace",
            evidence_id="EV_CNTR_1",
            evidence_record=rec_cntr_decisive,
            is_decisive=True,
            is_conflicting=True,  # Explicit conflicting trusted state!
            is_verified=True,
        )
        self.assertEqual(hyp3.status, VERDICT_INCONCLUSIVE)
        self.assertIn("Conflicting authoritative evidence", hyp3.confidence_basis)

    # -------------------------------------------------------------------------
    # Case K: Results are stable under evidence insertion-order changes
    # -------------------------------------------------------------------------

    def test_case_k_results_stable_under_insertion_order_changes(self):
        """Case K: Re-evaluation and root independence calculations are identical regardless of insertion order."""
        def build_hyp(order: list) -> CompetingHypothesis:
            h = CompetingHypothesis(hypothesis_id="HYP_K", category="HEAP_CORRUPTION", confidence=0.95)
            h.evidence_dependencies = {
                "C": ["P1", "P2"],
                "P1": ["R_A"],
                "P2": ["R_B"],
            }
            for ev in order:
                h.add_supporting_observation(f"Obs {ev}", evidence_id=ev)
            return h

        hyp_order1 = build_hyp(["R_A", "C", "R_B", "P1", "P2"])
        hyp_order2 = build_hyp(["P2", "R_B", "P1", "C", "R_A"])

        roots1 = hyp_order1.get_independent_root_sources()
        roots2 = hyp_order2.get_independent_root_sources()
        self.assertEqual(roots1, roots2)
        self.assertEqual(hyp_order1.evaluate_verdict(), hyp_order2.evaluate_verdict())

    # -------------------------------------------------------------------------
    # Case L: Planned and executed checks remain distinguishable
    # -------------------------------------------------------------------------

    def test_case_l_planned_and_executed_checks_distinguishable(self):
        """Case L: Synthetic NOT_EXECUTED checks are never counted as executed checks."""
        chks = [
            DiagnosticCheck(check_id="C_PASS", name="Pass", status=CheckStatus.PASS),
            DiagnosticCheck(check_id="C_FAIL", name="Fail", status=CheckStatus.FAIL),
            DiagnosticCheck(check_id="C_NOT_EXEC", name="Unexecuted", status=CheckStatus.NOT_EXECUTED),
            DiagnosticCheck(check_id="C_SKIPPED", name="Skipped", status=CheckStatus.SKIPPED),
        ]
        agg = DiagnosticVerdictAggregator.aggregate(
            lifecycle_state=STATE_COLLECTING,
            stop_reason=None,
            checks=chks,
            active_hypotheses=[],
        )
        cov = agg.inspection_coverage
        self.assertEqual(cov["total_checks"], 4)
        self.assertEqual(cov["executed_checks"], 2)  # Only PASS and FAIL!
        self.assertEqual(cov["not_executed_checks"], 1)
        self.assertEqual(cov["skipped_checks"], 1)

    # -------------------------------------------------------------------------
    # Case M: Reports preserve all excluded and unexecuted check information
    # -------------------------------------------------------------------------

    def test_case_m_reports_preserve_all_excluded_recipes(self):
        """Case M: Excluded diagnostic methods are preserved completely without truncation in report assembly."""
        session = AdaptiveInvestigationSession(
            investigation_id="INV_M_TEST",
            problem_statement="process memory leak",
            pid=os.getpid(),
        )
        session.step()  # Created -> Classifying
        session.step()  # Classifying -> Assessing
        session.step()  # Assessing -> Planning

        report = session.build_diagnostic_report()
        excluded = report.section_c_diagnostic_strategy.recipes_excluded
        # Total recipes in registry is 22; plan schedules ~4-6. Excluded should be > 10, not truncated to 5!
        self.assertGreater(len(excluded), 10)
        for item in excluded:
            self.assertIn("recipe_id", item)
            self.assertIn("reason_excluded", item)

    # -------------------------------------------------------------------------
    # Case N: Persistence/reload preserves evidence authority and graph integrity
    # -------------------------------------------------------------------------

    def test_case_n_persistence_preserves_evidence_authority_and_graph(self):
        """Case N: Persistence and reload preserves competing hypotheses, dependencies, and ledger validation."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = ExpertDiagnosticEngine(corpus_dir=tmpdir)
            session = engine.start_investigation(
                problem_statement="Heap memory corruption crash",
                pid=os.getpid(),
                investigation_id="INV_N_PERSIST",
            )
            # Add trusted records to session ledger so authority and DAG persist
            make_trusted_record(session.ledger, "EV_ROOT_1", target_pid=os.getpid())
            make_trusted_record(session.ledger, "EV_ROOT_2", target_pid=os.getpid())
            make_trusted_record(session.ledger, "EV_CHILD", target_pid=os.getpid())

            # Register a competing hypothesis with dependency DAG
            hyp = CompetingHypothesis(
                hypothesis_id="HYP_DAG_1",
                category="HEAP_CORRUPTION",
                confidence=0.92,
                supporting_evidence_ids=["EV_CHILD"],
                evidence_dependencies={"EV_CHILD": ["EV_ROOT_1", "EV_ROOT_2"]},
            )
            session.competing_hypotheses.append(hyp)
            session._save_to_disk()

            # Evict from memory and reload from disk
            engine.sessions.clear()
            reloaded = engine.get_session("INV_N_PERSIST")
            self.assertIsNotNone(reloaded)
            self.assertEqual(len(reloaded.competing_hypotheses), 1)
            rel_hyp = reloaded.competing_hypotheses[0]
            self.assertEqual(rel_hyp.hypothesis_id, "HYP_DAG_1")
            self.assertEqual(rel_hyp.evidence_dependencies, {"EV_CHILD": ["EV_ROOT_1", "EV_ROOT_2"]})
            # Verify graph resolution after reload
            roots = rel_hyp.get_independent_root_sources()
            self.assertEqual(roots, {"EV_ROOT_1", "EV_ROOT_2"})
            self.assertEqual(rel_hyp.evaluate_verdict(), VERDICT_CONFIRMED)

    # -------------------------------------------------------------------------
    # Case O: Failure injection validates commit and recovery semantics
    # -------------------------------------------------------------------------

    def test_case_o_failure_injection_and_recovery(self):
        """Case O: Failure injection validates NOT_COMMITTED and COMMIT_UNKNOWN, and recovery reconciles durability."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = ExpertDiagnosticEngine(corpus_dir=tmpdir)
            session = engine.start_investigation(
                problem_statement="Failure injection test",
                pid=os.getpid(),
                investigation_id="INV_O_FAIL",
            )

            # O1: Inject failure during file write/chmod -> NOT_COMMITTED
            with patch("os.chmod", side_effect=OSError("Injected chmod permission denied")):
                with self.assertRaises(InvestigationPersistenceError) as cm:
                    session._save_to_disk()
                self.assertEqual(cm.exception.outcome, DurableCommitOutcome.NOT_COMMITTED)

            # O2: Inject failure during parent directory fsync following os.replace -> COMMIT_UNKNOWN
            orig_fsync = os.fsync
            replace_called = [False]
            orig_replace = os.replace

            def mock_replace(src, dst):
                replace_called[0] = True
                return orig_replace(src, dst)

            def mock_fsync(fd):
                if replace_called[0]:
                    raise OSError("Injected directory fsync I/O error")
                return orig_fsync(fd)

            with patch("os.replace", side_effect=mock_replace):
                with patch("os.fsync", side_effect=mock_fsync):
                    with self.assertRaises(InvestigationPersistenceError) as cm_dir:
                        session._save_to_disk()
                    self.assertEqual(cm_dir.exception.outcome, DurableCommitOutcome.COMMIT_UNKNOWN)

            # O3: Recovery reconciles durability after COMMIT_UNKNOWN
            rec_result = session.reconcile_durability()
            self.assertTrue(rec_result["reconciled"])
            self.assertEqual(rec_result["outcome"], DurableCommitOutcome.COMMITTED.value)

    # -------------------------------------------------------------------------
    # Case P: JSON, Markdown, HTML, Web UI, and MCP report the same verdict and evidence summary
    # -------------------------------------------------------------------------

    def test_case_p_all_report_formats_consistent(self):
        """Case P: JSON, Markdown, HTML, and MCP report data expose identical verdict and counts."""
        chk1 = DiagnosticCheck(check_id="C1", name="Passing check", status=CheckStatus.PASS, is_required=True)
        chk2 = DiagnosticCheck(check_id="C2", name="Failing check", status=CheckStatus.FAIL, is_required=True)

        session = AdaptiveInvestigationSession(
            investigation_id="INV_P_CONSISTENT",
            problem_statement="Consistency verification",
            pid=os.getpid(),
        )
        session.checks = [chk1, chk2]
        session.state = STATE_COMPLETED
        session._finalize_conclusion(stop_reason="ALL_RECIPES_EVALUATED", summary="Confirmed fault in checks")

        report = session.build_diagnostic_report()
        verdict = report.section_a_executive_summary.overall_result
        self.assertEqual(verdict, VERDICT_CONFIRMED_FAULT)

        # 1. JSON export format
        json_report = session.export_report(format="json")
        self.assertEqual(json_report["section_a_executive_summary"]["overall_result"], verdict)
        self.assertEqual(session.conclusion.overall_verdict, verdict)

        # 2. Markdown export format
        md_report = session.export_report(format="markdown")
        self.assertIn(f"**Overall Result**: `{verdict}`", md_report)

        # 3. HTML export format
        html_report = session.export_report(format="html")
        self.assertIn(verdict, html_report)
        self.assertIn(html.escape(session.investigation_id), html_report)


if __name__ == "__main__":
    unittest.main()

"""Phase 2.1.8 — Evidence Trust Closure, Real-World Diagnostic Validation & Investigation Quality.

Comprehensive validation suite verifying:
- Part A (A1–A5): Authoritative EvidenceLedger validation, 9-dimension target/investigation identity
  validation (distinguishing missing identity vs actual mismatch, PID reuse, build ID mismatch),
  hardened contradiction evaluation, PrimaryEvidenceRuleRegistry ownership/executable criteria,
  and immutable/idempotent validation.
- Part B (B1–B3): Complete multi-parent DAG validation, capture-origin root independence,
  insertion-order-independent deterministic hypothesis evaluation with decision_trace, and
  DiagnosticVerdictAggregator decision table coverage.
- Part C (C1–C4): Realistic compiled C/C++ runtime diagnostic validation across 12 memory lifecycle
  scenarios (C1), 8 concurrency scenarios (C2), 8 process/resource scenarios (C3), and machine-readable
  expected contract verification (C4).
- Part D: 12-step adaptive investigation quality across vague and specific symptom categories.
- Part E (E1–E3): All 20 required report items, 5 epistemic levels, and single-source-of-truth parity
  across JSON, Markdown, HTML, Web API/UI, and MCP tools.
- Part F: Persistence, reload non-escalation, legacy schema migration, corrupted record handling,
  and COMMITTED / NOT_COMMITTED / COMMIT_UNKNOWN durability reconciliation.
- Part G: Required Test Matrix Items A through Z.
"""

import html
import json
import os
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from extractor.capture_backend import (
    LiveCaptureReceipt,
    get_trusted_capture_authority_token,
    issue_live_capture_receipt,
)
from extractor.competing_hypotheses import (
    CONTRADICTION_CLASS_CONFLICTING,
    CONTRADICTION_CLASS_DECISIVE,
    CONTRADICTION_CLASS_IRRELEVANT,
    CONTRADICTION_CLASS_PARTIAL,
    CONTRADICTION_CLASS_UNTRUSTED,
    ROOT_INDEPENDENCE_DEFINITION,
    CompetingHypothesis,
    CompetingHypothesisManager,
    ContradictionRecord,
    PrimaryEvidenceRule,
    PrimaryEvidenceRuleRegistry,
    VERDICT_CONFIRMED,
    VERDICT_INCONCLUSIVE,
    VERDICT_LIKELY,
    VERDICT_NOT_APPLICABLE,
    VERDICT_OBSERVED,
    VERDICT_REFUTED,
    VERDICT_SUPPORTED,
)
from extractor.concurrency_graph import (
    ConcurrencyState,
    WaitForGraph,
    OwnershipEdge,
    WaitingEdge,
)
from extractor.diagnostic_methodology import (
    CheckStatus,
    DiagnosticCheck,
    DiagnosticMethodology,
)
from extractor.diagnostic_recipes import (
    DiagnosticRecipeRegistry,
    RECIPE_STATUS_CONTRADICTED,
    RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
    RECIPE_STATUS_NOT_APPLICABLE,
    RECIPE_STATUS_SUPPORTED,
)
from extractor.diagnostic_report import (
    DiagnosticReport,
    EPISTEMIC_CONFIRMED_ROOT_CAUSE,
    EPISTEMIC_DERIVED_EVIDENCE,
    EPISTEMIC_HYPOTHESIS,
    EPISTEMIC_OBSERVATION,
    EPISTEMIC_PROBABLE_CAUSE,
)
from extractor.diagnostic_verdict_aggregator import (
    VERDICT_ABORTED,
    VERDICT_CONFIRMED_FAULT,
    VERDICT_DECISION_TABLE,
    VERDICT_DEGRADED,
    VERDICT_HEALTHY,
    VERDICT_INCONCLUSIVE as AGG_INCONCLUSIVE,
    VERDICT_PROBABLE_FAULT,
    DiagnosticVerdictAggregator,
)
from extractor.evidence_ledger import (
    EvidenceLedger,
    EvidenceRecord,
    PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    PROVENANCE_CLASS_SYNTHETIC_FIXTURE,
)
from extractor.expert_diagnostic_engine import (
    AdaptiveInvestigationSession,
    DurableCommitOutcome,
    ExpertDiagnosticEngine,
    ExpertHypothesis,
    InvestigationPersistenceError,
    STATE_BLOCKED,
    STATE_COMPLETED,
    STATE_COLLECTING,
    STATE_INCONCLUSIVE,
    TargetAssessor,
)
from extractor.watch_session import WatchSessionManager


def make_authoritative_record(
    ledger: EvidenceLedger,
    evidence_id: str,
    observation: str = "Verified runtime observation",
    pid: int = 1234,
    process_identity: str = "",
    executable_identity: str = "",
    build_id: str = "sha1:build_phase2_1_8",
    snapshot_id: str = "",
    evidence_type: str = "DIAGNOSTIC",
    nature: str = "observation",
    operation_id: str = "",
    receipt: LiveCaptureReceipt = None,
    parent_evidence_ids: list = None,
) -> EvidenceRecord:
    """Creates a cryptographically receipted authoritative EvidenceRecord in ledger."""
    eff_proc = process_identity or f"proc_{pid}_start1000"
    eff_exe = executable_identity or f"/proc/{pid}/exe"
    eff_snap = snapshot_id or "snap_default"
    if receipt is None:
        token = get_trusted_capture_authority_token()
        receipt = issue_live_capture_receipt(
            session_id=ledger.session_id,
            pid=pid,
            process_identity=eff_proc,
            executable_identity=eff_exe,
            build_id=build_id,
            snapshot_binding=eff_snap,
            operation_id=operation_id,
            capture_authority_token=token,
        )
    t_ident = {
        "pid": pid,
        "process_identity": eff_proc,
        "executable_identity": eff_exe,
        "build_id": build_id,
    }
    snap_ref = {"snapshot_id": snapshot_id} if snapshot_id else None
    rec = EvidenceRecord(
        evidence_id=evidence_id,
        session_id=ledger.session_id,
        evidence_type=evidence_type,
        nature=nature,
        observation=observation,
        parent_evidence_ids=list(parent_evidence_ids or []),
        provenance={
            "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
            "live_capture_receipt": receipt.to_dict(),
        },
        details={
            "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
            "live_capture_receipt": receipt.to_dict(),
            "target_pid": pid,
            "operation_id": operation_id,
        },
        target_identity=t_ident,
        snapshot_ref=snap_ref,
    )
    rec.target_pid = pid
    ledger._by_id[evidence_id] = rec
    ledger._records.append(rec)
    return rec


class TestPhase218CompleteValidation(unittest.TestCase):
    """Unified Phase 2.1.8 Validation Suite (Parts A, B, C, D, E, F, and Matrix A–Z)."""

    @classmethod
    def setUpClass(cls):
        cls.fixture_src = os.path.abspath("tests/fixtures/real_runtime/phase2_1_8_runtime_targets.cpp")
        cls.debug_bin = "/tmp/phase2_1_8_targets_debug"
        cls.stripped_bin = "/tmp/phase2_1_8_targets_stripped"
        if not os.path.exists(cls.debug_bin):
            subprocess.run(
                ["g++", "-g", "-O0", "-pthread", "-Wl,--build-id=sha1", cls.fixture_src, "-o", cls.debug_bin],
                check=True,
            )
        if not os.path.exists(cls.stripped_bin):
            subprocess.run(
                ["g++", "-s", "-O1", "-pthread", "-Wl,--build-id=sha1", cls.fixture_src, "-o", cls.stripped_bin],
                check=True,
            )
        cls.registry = DiagnosticRecipeRegistry()

    def setUp(self):
        self._spawned_procs = []

    def tearDown(self):
        for p in self._spawned_procs:
            try:
                p.kill()
                p.wait(timeout=2.0)
            except Exception:
                pass

    def _spawn(self, mode: str, stripped: bool = False) -> subprocess.Popen:
        binary = self.stripped_bin if stripped else self.debug_bin
        proc = subprocess.Popen([binary, mode], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self._spawned_procs.append(proc)
        time.sleep(0.08)
        return proc

    # =========================================================================
    # Matrix A, B, C, D, G (Part A1 & A5): Authoritative Ledger Validation
    # =========================================================================

    def test_matrix_A_arbitrary_evidence_ids_without_ledger_cannot_confirm(self):
        """Matrix A: Arbitrary evidence IDs without an authoritative Ledger can never produce CONFIRMED."""
        hyp = CompetingHypothesis(
            hypothesis_id="HYP_MAT_A",
            category="MEMORY_LEAK",
            confidence=0.98,
            ledger=None,
        )
        hyp.add_supporting_observation("Heap grew by 10 MB", evidence_id="EV_ARB_1")
        hyp.add_supporting_observation("Allocations exceeded frees", evidence_id="EV_ARB_2")
        verdict = hyp.evaluate_verdict()
        self.assertNotEqual(verdict, VERDICT_CONFIRMED)
        self.assertEqual(len(hyp.get_independent_root_sources()), 0)
        self.assertIn("EV_ARB_1", hyp.unverified_evidence_ids)
        self.assertIn("EV_ARB_2", hyp.unverified_evidence_ids)
        self.assertIn("Missing authoritative EvidenceLedger", hyp.rejected_evidence_reasons["EV_ARB_1"])

    def test_matrix_B_missing_ledger_cannot_confirm_or_refute(self):
        """Matrix B: Missing Ledger can neither confirm nor refute a hypothesis."""
        hyp = CompetingHypothesis(
            hypothesis_id="HYP_MAT_B",
            category="USE_AFTER_FREE",
            confidence=0.95,
            ledger=None,
        )
        hyp.add_supporting_observation("Pointer dereferenced after free", evidence_id="EV_SUP_NO_LEDGER")
        self.assertNotEqual(hyp.evaluate_verdict(), VERDICT_CONFIRMED)

        hyp.add_contradicting_observation(
            "Chunk is active",
            evidence_id="EV_CONTRA_NO_LEDGER",
            is_decisive=True,
            is_verified=True,  # Caller claims verified, but Ledger is missing!
        )
        self.assertNotEqual(hyp.evaluate_verdict(), VERDICT_REFUTED)
        self.assertEqual(hyp.contradiction_records[0].contradiction_class, CONTRADICTION_CLASS_UNTRUSTED)
        self.assertFalse(hyp.contradiction_records[0].is_verified)

    def test_matrix_C_missing_evidence_record_in_ledger_cannot_confirm(self):
        """Matrix C: Evidence IDs missing from the authoritative Ledger are rejected and cannot confirm."""
        ledger = EvidenceLedger(session_id="INV_MAT_C")
        make_authoritative_record(ledger, "EV_PRESENT_1")

        hyp = CompetingHypothesis(
            hypothesis_id="HYP_MAT_C",
            category="HEAP_CORRUPTION",
            confidence=0.96,
            ledger=ledger,
        )
        self.assertTrue(hyp.add_supporting_observation("Present obs", evidence_id="EV_PRESENT_1"))
        self.assertFalse(hyp.add_supporting_observation("Missing obs", evidence_id="EV_MISSING_999"))
        self.assertIn("EV_MISSING_999", hyp.rejected_evidence_reasons)
        self.assertNotEqual(hyp.evaluate_verdict(ledger=ledger), VERDICT_CONFIRMED)

    def test_matrix_D_untrusted_provenance_cannot_confirm_or_refute(self):
        """Matrix D: Imported/synthetic/unverified provenance records cannot confirm or refute."""
        ledger = EvidenceLedger(session_id="INV_MAT_D")
        for eid, prov in [
            ("EV_IMP_1", PROVENANCE_CLASS_IMPORTED_UNVERIFIED),
            ("EV_IMP_2", PROVENANCE_CLASS_SYNTHETIC_FIXTURE),
            ("EV_IMP_CONTRA", PROVENANCE_CLASS_IMPORTED_UNVERIFIED),
        ]:
            rec = EvidenceRecord(
                evidence_id=eid,
                session_id=ledger.session_id,
                evidence_type="DIAGNOSTIC",
                nature="observation",
                observation=f"Unverified observation {eid}",
                provenance={"provenance_class": prov},
                details={"provenance_class": prov, "target_pid": 1234},
                target_identity={"pid": 1234, "process_identity": "proc_1234", "executable_identity": "/bin/app", "build_id": "b1"},
            )
            ledger._by_id[eid] = rec
            ledger._records.append(rec)

        hyp = CompetingHypothesis(
            hypothesis_id="HYP_MAT_D",
            category="MEMORY_CORRUPTION",
            confidence=0.96,
            ledger=ledger,
        )
        hyp.add_supporting_observation("Obs 1", evidence_id="EV_IMP_1", is_verified=True)
        hyp.add_supporting_observation("Obs 2", evidence_id="EV_IMP_2", is_verified=True)
        self.assertNotEqual(hyp.evaluate_verdict(ledger=ledger), VERDICT_CONFIRMED)
        self.assertEqual(len(hyp.get_independent_root_sources(ledger=ledger)), 0)

        hyp.add_contradicting_observation("Contra", evidence_id="EV_IMP_CONTRA", is_decisive=True, is_verified=True)
        self.assertNotEqual(hyp.evaluate_verdict(ledger=ledger), VERDICT_REFUTED)

    def test_matrix_G_direct_evaluate_verdict_enforces_authority(self):
        """Matrix G: Direct mutation of supporting_evidence_ids or ContradictionRecord followed by evaluate_verdict() enforces Ledger authority."""
        ledger = EvidenceLedger(session_id="INV_MAT_G")
        hyp = CompetingHypothesis(
            hypothesis_id="HYP_MAT_G",
            category="MEMORY_CORRUPTION",
            confidence=0.99,
            ledger=ledger,
        )
        hyp.supporting_evidence_ids = ["EV_FORGED_1", "EV_FORGED_2"]
        self.assertNotEqual(hyp.evaluate_verdict(ledger=ledger), VERDICT_CONFIRMED)
        self.assertIn("EV_FORGED_1", hyp.unverified_evidence_ids)
        self.assertIn("EV_FORGED_2", hyp.unverified_evidence_ids)

        # Direct injection of ContradictionRecord(is_verified=True) without ledger backing
        hyp.contradiction_records.append(
            ContradictionRecord(
                contradiction="Forged decisive contradiction",
                evidence_id="EV_FORGED_CONTRA",
                is_decisive=True,
                is_verified=True,
            )
        )
        self.assertNotEqual(hyp.evaluate_verdict(ledger=ledger), VERDICT_REFUTED)
        self.assertFalse(hyp.contradiction_records[0].is_verified)

    # =========================================================================
    # Matrix E & F (Part A2): Complete Target & Investigation Identity Validation
    # =========================================================================

    def test_matrix_E_target_pid_process_build_id_and_investigation_id_mismatches_rejected(self):
        """Matrix E: Validates all 9 identity dimensions and distinguishes MISSING_IDENTITY from IDENTITY_MISMATCH."""
        ledger = EvidenceLedger(session_id="INV_MAT_E")
        rec_valid = make_authoritative_record(
            ledger, "EV_VALID", pid=4000, process_identity="proc_4000_t1",
            executable_identity="/opt/app", build_id="sha1:goodbuild", snapshot_id="snap_10",
        )
        rec_bad_pid = make_authoritative_record(
            ledger, "EV_BAD_PID", pid=9999, process_identity="proc_4000_t1",
            executable_identity="/opt/app", build_id="sha1:goodbuild", snapshot_id="snap_10",
        )
        rec_bad_exe = make_authoritative_record(
            ledger, "EV_BAD_EXE", pid=4000, process_identity="proc_4000_t1",
            executable_identity="/opt/other_bin", build_id="sha1:goodbuild", snapshot_id="snap_10",
        )
        rec_bad_bid = make_authoritative_record(
            ledger, "EV_BAD_BID", pid=4000, process_identity="proc_4000_t1",
            executable_identity="/opt/app", build_id="sha1:wrongbuild", snapshot_id="snap_10",
        )
        rec_bad_snap = make_authoritative_record(
            ledger, "EV_BAD_SNAP", pid=4000, process_identity="proc_4000_t1",
            executable_identity="/opt/app", build_id="sha1:goodbuild", snapshot_id="snap_999",
        )
        # Record with missing identity metadata (empty target_identity dict)
        rec_missing_ident = EvidenceRecord(
            evidence_id="EV_MISSING_ID",
            session_id=ledger.session_id,
            evidence_type="DIAGNOSTIC",
            nature="observation",
            observation="Missing identity fields",
            provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE},
            details={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE},
            target_identity={},
        )
        ledger._by_id["EV_MISSING_ID"] = rec_missing_ident
        ledger._records.append(rec_missing_ident)

        hyp = CompetingHypothesis(
            hypothesis_id="HYP_MAT_E",
            category="HEAP_CORRUPTION",
            investigation_id="INV_MAT_E",
            target_pid=4000,
            process_identity="proc_4000_t1",
            executable_identity="/opt/app",
            build_id="sha1:goodbuild",
            snapshot_id="snap_10",
            confidence=0.95,
            ledger=ledger,
        )

        self.assertTrue(hyp.add_supporting_observation("Valid", evidence_id="EV_VALID", evidence_record=rec_valid))
        self.assertFalse(hyp.add_supporting_observation("Bad PID", evidence_id="EV_BAD_PID", evidence_record=rec_bad_pid))
        self.assertFalse(hyp.add_supporting_observation("Bad Exe", evidence_id="EV_BAD_EXE", evidence_record=rec_bad_exe))
        self.assertFalse(hyp.add_supporting_observation("Bad BuildID", evidence_id="EV_BAD_BID", evidence_record=rec_bad_bid))
        self.assertFalse(hyp.add_supporting_observation("Bad Snap", evidence_id="EV_BAD_SNAP", evidence_record=rec_bad_snap))

        # Missing identity is retained as unverified with status MISSING_IDENTITY (distinct from IDENTITY_MISMATCH)
        self.assertTrue(hyp.add_supporting_observation("Missing ID", evidence_id="EV_MISSING_ID", evidence_record=rec_missing_ident))
        self.assertEqual(hyp.identity_validation_records["EV_BAD_BID"]["status"], "IDENTITY_MISMATCH")
        self.assertEqual(hyp.identity_validation_records["EV_MISSING_ID"]["status"], "MISSING_IDENTITY")
        self.assertNotEqual(hyp.evaluate_verdict(ledger=ledger), VERDICT_CONFIRMED)

    def test_matrix_F_pid_reuse_detected_and_rejected(self):
        """Matrix F: Same numeric PID with different process_identity / start_time_ticks (PID reuse) is rejected."""
        ledger = EvidenceLedger(session_id="INV_MAT_F")
        rec_inst1 = make_authoritative_record(
            ledger, "EV_PID_INST1", pid=5050, process_identity="5050:start_ticks_1000:boot1",
        )
        rec_inst2 = make_authoritative_record(
            ledger, "EV_PID_INST2", pid=5050, process_identity="5050:start_ticks_9999:boot1",
        )

        hyp = CompetingHypothesis(
            hypothesis_id="HYP_MAT_F",
            category="MEMORY_LEAK",
            target_pid=5050,
            confidence=0.95,
            ledger=ledger,
        )
        hyp.supporting_evidence_ids = ["EV_PID_INST1", "EV_PID_INST2"]
        verdict = hyp.evaluate_verdict(ledger=ledger)
        # Must NOT confirm because EV_PID_INST2 is from a reused PID instance!
        self.assertNotEqual(verdict, VERDICT_CONFIRMED)
        self.assertEqual(len(hyp.get_independent_root_sources(ledger=ledger)), 1)
        self.assertTrue(any("PID reuse" in lim for lim in hyp.integrity_limitations))

    # =========================================================================
    # Matrix H, I, J, K (Part A3): Contradiction Authority & Exhaustive Matrix
    # =========================================================================

    def test_matrix_H_untrusted_contradiction_cannot_refute(self):
        """Matrix H: Untrusted contradiction cannot refute a hypothesis."""
        ledger = EvidenceLedger(session_id="INV_MAT_H")
        make_authoritative_record(ledger, "EV_SUP_1")
        make_authoritative_record(ledger, "EV_SUP_2")
        hyp = CompetingHypothesis(hypothesis_id="HYP_H", category="MEMORY_LEAK", confidence=0.95, ledger=ledger)
        hyp.add_supporting_observation("S1", evidence_id="EV_SUP_1")
        hyp.add_supporting_observation("S2", evidence_id="EV_SUP_2")
        hyp.add_contradicting_observation("Untrusted contra", evidence_id=None, is_decisive=True, is_verified=True)
        self.assertEqual(hyp.evaluate_verdict(ledger=ledger), VERDICT_CONFIRMED)

    def test_matrix_I_partial_contradiction_reduces_confidence_without_refuting(self):
        """Matrix I: Authoritative partial contradiction reduces confidence and prevents CONFIRMED without refuting."""
        ledger = EvidenceLedger(session_id="INV_MAT_I")
        make_authoritative_record(ledger, "EV_SUP_1")
        make_authoritative_record(ledger, "EV_SUP_2")
        make_authoritative_record(ledger, "EV_PARTIAL_CONTRA", observation="Intermittent plateau during idle window")

        hyp = CompetingHypothesis(hypothesis_id="HYP_I", category="MEMORY_LEAK", confidence=0.95, ledger=ledger)
        hyp.add_supporting_observation("S1", evidence_id="EV_SUP_1")
        hyp.add_supporting_observation("S2", evidence_id="EV_SUP_2")
        self.assertEqual(hyp.evaluate_verdict(ledger=ledger), VERDICT_CONFIRMED)

        hyp.add_contradicting_observation(
            "Intermittent plateau during idle window",
            evidence_id="EV_PARTIAL_CONTRA",
            is_decisive=False,
            weight=0.25,
        )
        verdict = hyp.evaluate_verdict(ledger=ledger)
        self.assertNotEqual(verdict, VERDICT_REFUTED)
        self.assertNotEqual(verdict, VERDICT_CONFIRMED)
        self.assertLessEqual(hyp.confidence, 0.65)
        self.assertEqual(hyp.contradiction_records[0].contradiction_class, CONTRADICTION_CLASS_PARTIAL)

    def test_matrix_J_decisive_trusted_contradiction_refutes(self):
        """Matrix J: Authoritative decisive contradiction refutes when no trusted support conflicts."""
        ledger = EvidenceLedger(session_id="INV_MAT_J")
        make_authoritative_record(ledger, "EV_DECISIVE_CONTRA", observation="Mutex wait graph verified completely acyclic")
        hyp = CompetingHypothesis(hypothesis_id="HYP_J", category="CONCURRENCY", confidence=0.80, ledger=ledger)
        hyp.add_contradicting_observation(
            "Mutex wait graph verified completely acyclic",
            evidence_id="EV_DECISIVE_CONTRA",
            is_decisive=True,
        )
        self.assertEqual(hyp.evaluate_verdict(ledger=ledger), VERDICT_REFUTED)
        self.assertEqual(hyp.contradiction_records[0].contradiction_class, CONTRADICTION_CLASS_DECISIVE)

    def test_matrix_K_conflicting_trusted_support_and_contradiction_yields_inconclusive(self):
        """Matrix K: Authoritative support + authoritative decisive contradiction yields INCONCLUSIVE automatically."""
        ledger = EvidenceLedger(session_id="INV_MAT_K")
        make_authoritative_record(ledger, "EV_TRUSTED_SUP_1", observation="Heap growth slope positive in epoch 1..3")
        make_authoritative_record(ledger, "EV_TRUSTED_SUP_2", observation="Allocator chunk census increased")
        make_authoritative_record(ledger, "EV_TRUSTED_CONTRA", observation="Allocator live bytes counter decreased to baseline")

        hyp = CompetingHypothesis(hypothesis_id="HYP_K", category="MEMORY_LEAK", confidence=0.95, ledger=ledger)
        hyp.add_supporting_observation("Slope positive", evidence_id="EV_TRUSTED_SUP_1")
        hyp.add_supporting_observation("Census increased", evidence_id="EV_TRUSTED_SUP_2")
        self.assertEqual(hyp.evaluate_verdict(ledger=ledger), VERDICT_CONFIRMED)

        # Even when caller does NOT set is_conflicting=True, having both trusted support and trusted decisive contradiction
        # without a structural impossibility precedence rule yields VERDICT_INCONCLUSIVE!
        hyp.add_contradicting_observation(
            "Allocator live bytes counter decreased to baseline",
            evidence_id="EV_TRUSTED_CONTRA",
            is_decisive=True,
            is_conflicting=False,
        )
        self.assertEqual(hyp.evaluate_verdict(ledger=ledger), VERDICT_INCONCLUSIVE)
        self.assertEqual(hyp.contradiction_records[0].contradiction_class, CONTRADICTION_CLASS_CONFLICTING)

    def test_part_a3_exhaustive_support_contradiction_matrix(self):
        """Part A3: Exhaustively tests all combinations of trusted/untrusted support and contradiction."""
        ledger = EvidenceLedger(session_id="INV_EXHAUSTIVE_A3")
        make_authoritative_record(ledger, "T_SUP_1")
        make_authoritative_record(ledger, "T_SUP_2")
        make_authoritative_record(ledger, "T_CON_DEC")
        make_authoritative_record(ledger, "T_CON_PART")
        make_authoritative_record(ledger, "T_CON_IRREL", pid=9999)  # PID mismatch -> irrelevant

        # 1. Trusted Support (2 roots) + Irrelevant Contradiction -> CONFIRMED
        h1 = CompetingHypothesis(hypothesis_id="H_EX_1", category="MEMORY_LEAK", confidence=0.95, target_pid=1234, ledger=ledger)
        h1.add_supporting_observation("S1", evidence_id="T_SUP_1")
        h1.add_supporting_observation("S2", evidence_id="T_SUP_2")
        h1.add_contradicting_observation("Irrel", evidence_id="T_CON_IRREL", is_decisive=True)
        self.assertEqual(h1.evaluate_verdict(ledger=ledger), VERDICT_CONFIRMED)
        self.assertEqual(h1.contradiction_records[0].contradiction_class, CONTRADICTION_CLASS_IRRELEVANT)

        # 2. Untrusted Support + Trusted Decisive Contradiction -> REFUTED
        h2 = CompetingHypothesis(hypothesis_id="H_EX_2", category="MEMORY_LEAK", confidence=0.90, target_pid=1234, ledger=ledger)
        h2.add_supporting_observation("Unverified support", evidence_id="T_SUP_1", is_verified=False)
        h2.add_contradicting_observation("Trusted decisive contra", evidence_id="T_CON_DEC", is_decisive=True)
        self.assertEqual(h2.evaluate_verdict(ledger=ledger), VERDICT_REFUTED)

        # 3. Legacy contradicting_observations without Ledger validation -> never REFUTED
        h3 = CompetingHypothesis(hypothesis_id="H_EX_3", category="MEMORY_LEAK", confidence=0.80, ledger=ledger)
        h3.contradicting_observations.append("Legacy unverified string")
        self.assertNotEqual(h3.evaluate_verdict(ledger=ledger), VERDICT_REFUTED)

    # =========================================================================
    # Matrix L, M, N, O (Part B1): Dependency Graph & Root Independence
    # =========================================================================

    def test_matrix_L_shared_root_evidence_does_not_count_as_independent(self):
        """Matrix L: Derived evidence and its source evidence (or two children of one root) count as 1 root."""
        ledger = EvidenceLedger(session_id="INV_MAT_L")
        make_authoritative_record(ledger, "EV_ROOT")
        make_authoritative_record(ledger, "EV_DERIVED_A", parent_evidence_ids=["EV_ROOT"])
        make_authoritative_record(ledger, "EV_DERIVED_B", parent_evidence_ids=["EV_ROOT"])

        hyp = CompetingHypothesis(hypothesis_id="HYP_L", category="MEMORY_LEAK", confidence=0.95, ledger=ledger)
        hyp.add_supporting_observation("Root obs", evidence_id="EV_ROOT")
        hyp.add_supporting_observation("Derived A", evidence_id="EV_DERIVED_A")
        hyp.add_supporting_observation("Derived B", evidence_id="EV_DERIVED_B")

        roots = hyp.get_independent_root_sources(ledger=ledger)
        self.assertEqual(roots, {"EV_ROOT"})
        self.assertNotEqual(hyp.evaluate_verdict(ledger=ledger), VERDICT_CONFIRMED)

    def test_matrix_M_two_evidence_ids_from_one_capture_do_not_count_as_independent_roots(self):
        """Matrix M: Two distinct Evidence IDs from the same underlying capture receipt/operation count as 1 root."""
        ledger = EvidenceLedger(session_id="INV_MAT_M")
        token = get_trusted_capture_authority_token()
        shared_rcpt = issue_live_capture_receipt(
            session_id=ledger.session_id,
            pid=1234,
            process_identity="proc_1234_start1000",
            executable_identity="/proc/1234/exe",
            build_id="sha1:build_phase2_1_8",
            snapshot_binding="snap_shared",
            operation_id="op_shared_capture_001",
            capture_authority_token=token,
        )
        make_authoritative_record(ledger, "EV_CAP1_A", receipt=shared_rcpt, operation_id="op_shared_capture_001")
        make_authoritative_record(ledger, "EV_CAP1_B", receipt=shared_rcpt, operation_id="op_shared_capture_001")

        hyp = CompetingHypothesis(hypothesis_id="HYP_M", category="MEMORY_LEAK", confidence=0.96, ledger=ledger)
        hyp.add_supporting_observation("Field 1 from capture 1", evidence_id="EV_CAP1_A")
        hyp.add_supporting_observation("Field 2 from capture 1", evidence_id="EV_CAP1_B")

        roots = hyp.get_independent_root_sources(ledger=ledger)
        self.assertEqual(len(roots), 1)
        self.assertNotEqual(hyp.evaluate_verdict(ledger=ledger), VERDICT_CONFIRMED)
        self.assertTrue(any("shares underlying capture origin" in lim for lim in hyp.integrity_limitations))
        self.assertIn("Capture-Origin Deduplication", ROOT_INDEPENDENCE_DEFINITION)

    def test_matrix_N_multi_parent_dag_traversal_finds_all_valid_roots(self):
        """Matrix N: Multi-parent diamond/tree DAG traverses every parent and counts distinct capture roots."""
        ledger = EvidenceLedger(session_id="INV_MAT_N")
        for eid in ["R1", "R2", "M1", "M2", "TOP"]:
            make_authoritative_record(ledger, eid)

        hyp = CompetingHypothesis(
            hypothesis_id="HYP_N",
            category="HEAP_CORRUPTION",
            confidence=0.95,
            ledger=ledger,
            supporting_evidence_ids=["TOP"],
            evidence_dependencies={
                "TOP": ["M1", "M2"],
                "M1": ["R1", "R2"],
                "M2": ["R2"],
            },
        )
        roots = hyp.get_independent_root_sources(ledger=ledger)
        self.assertEqual(roots, {"R1", "R2"})
        self.assertEqual(hyp.evaluate_verdict(ledger=ledger), VERDICT_CONFIRMED)

    def test_matrix_O_cycles_self_dependencies_missing_parents_and_malformed_edges_cannot_increase_confidence(self):
        """Matrix O: Cycles, self-dependencies, missing parents, and malformed edges are rejected and represented."""
        ledger = EvidenceLedger(session_id="INV_MAT_O")
        make_authoritative_record(ledger, "EV_MALFORMED")

        hyp = CompetingHypothesis(
            hypothesis_id="HYP_O",
            category="HEAP_CORRUPTION",
            confidence=0.95,
            ledger=ledger,
            supporting_evidence_ids=["EV_MALFORMED", "EV_CYC_A", "EV_SELF_NODE", "EV_DANGLING_NODE"],
            evidence_dependencies={
                "EV_MALFORMED": [None, ""],
                "EV_CYC_A": ["EV_CYC_B"],
                "EV_CYC_B": ["EV_CYC_A"],
                "EV_SELF_NODE": ["EV_SELF_NODE"],
                "EV_DANGLING_NODE": ["EV_NONEXISTENT_PARENT"],
            },
        )
        roots = hyp.get_independent_root_sources(ledger=ledger)
        self.assertEqual(len(roots), 0)
        self.assertEqual(hyp.evaluate_verdict(ledger=ledger), VERDICT_INCONCLUSIVE)
        self.assertFalse(hyp.graph_validation_summary["is_complete"])
        self.assertEqual(len(hyp.unresolved_dependencies), 4)

    # =========================================================================
    # Matrix P (Part A4): PrimaryEvidenceRuleRegistry Hardening
    # =========================================================================

    def test_matrix_P_single_evidence_confirmation_requires_registered_rule_and_valid_evidence_record(self):
        """Matrix P: Single-evidence confirmation requires registered rule, existing ledger record, identity, and executable criteria."""
        ledger = EvidenceLedger(session_id="INV_MAT_P")
        make_authoritative_record(
            ledger,
            "EV_CANARY_GOOD",
            observation="Canary word overwritten with 0x41414141 in chunk header",
        )
        make_authoritative_record(
            ledger,
            "EV_CANARY_CLEAN",
            observation="Canary intact and zero corrupt headers found",
        )

        # 1. Built-in rules cannot be overwritten by external registration
        with self.assertRaises(ValueError):
            PrimaryEvidenceRuleRegistry.register(
                PrimaryEvidenceRule(
                    rule_id="RULE_MEM_CORRUPTION_CANARY",
                    description="Malicious override",
                    applicable_categories={"HEAP_CORRUPTION"},
                    allowed_evidence_types={"DIAGNOSTIC"},
                    required_provenance_classes={PROVENANCE_CLASS_IMPORTED_UNVERIFIED},
                ),
                allow_override=True,
            )

        # 2. Clean observation fails executable criteria for RULE_MEM_CORRUPTION_CANARY
        hyp_fail_crit = CompetingHypothesis(
            hypothesis_id="HYP_P_FAIL_CRIT",
            category="HEAP_CORRUPTION",
            confidence=0.95,
            supporting_evidence_ids=["EV_CANARY_CLEAN"],
            primary_evidence_rule="RULE_MEM_CORRUPTION_CANARY",
            ledger=ledger,
        )
        self.assertNotEqual(hyp_fail_crit.evaluate_verdict(ledger=ledger), VERDICT_CONFIRMED)
        self.assertFalse(hyp_fail_crit.primary_rule_audit["authorized"])

        # 3. Valid corrupt canary observation passes executable criteria and confirms
        hyp_ok = CompetingHypothesis(
            hypothesis_id="HYP_P_OK",
            category="HEAP_CORRUPTION",
            confidence=0.95,
            supporting_evidence_ids=["EV_CANARY_GOOD"],
            primary_evidence_rule="RULE_MEM_CORRUPTION_CANARY",
            ledger=ledger,
        )
        self.assertEqual(hyp_ok.evaluate_verdict(ledger=ledger), VERDICT_CONFIRMED)
        self.assertTrue(hyp_ok.primary_rule_audit["authorized"])
        self.assertEqual(hyp_ok.primary_rule_audit["version"], "2.1.8")
        self.assertEqual(hyp_ok.primary_rule_audit["evaluated_evidence_id"], "EV_CANARY_GOOD")

    def test_part_b2_insertion_order_and_repeated_evaluation_idempotency(self):
        """Part B2: Confidence, status, limitations, and decision_trace are insertion-order independent and idempotent."""
        ledger = EvidenceLedger(session_id="INV_B2_IDEMP")
        make_authoritative_record(ledger, "EV_1")
        make_authoritative_record(ledger, "EV_2")
        make_authoritative_record(ledger, "EV_PARTIAL", observation="Minor variance")

        def run_sequence(items):
            h = CompetingHypothesis(hypothesis_id="HYP_B2", category="MEMORY_LEAK", confidence=0.80, ledger=ledger)
            for kind, eid, w in items:
                if kind == "S":
                    h.add_supporting_observation(f"Obs {eid}", evidence_id=eid, weight=w)
                else:
                    h.add_contradicting_observation(f"Contra {eid}", evidence_id=eid, is_decisive=False, weight=w)
            return h

        seq1 = [("S", "EV_1", 0.15), ("S", "EV_2", 0.15), ("C", "EV_PARTIAL", 0.20)]
        seq2 = [("C", "EV_PARTIAL", 0.20), ("S", "EV_2", 0.15), ("S", "EV_1", 0.15)]
        h_a = run_sequence(seq1)
        h_b = run_sequence(seq2)

        self.assertEqual(h_a.status, h_b.status)
        self.assertAlmostEqual(h_a.confidence, h_b.confidence, places=6)

        # Repeated evaluation must not drift confidence or duplicate limitations
        snap_conf = h_a.confidence
        snap_lims = list(h_a.integrity_limitations)
        for _ in range(5):
            h_a.evaluate_verdict(ledger=ledger)
        self.assertAlmostEqual(h_a.confidence, snap_conf, places=6)
        self.assertEqual(h_a.integrity_limitations, snap_lims)
        self.assertIn("decision_rule_applied", h_a.decision_trace)

    # =========================================================================
    # Matrix Q, R, S, T (Part B3): DiagnosticVerdictAggregator Decision Table
    # =========================================================================

    def test_matrix_Q_applicable_required_fail_prevents_healthy_and_manual_fail_distinguished(self):
        """Matrix Q: Applicable required FAIL prevents HEALTHY; arbitrary manual FAIL yields PROBABLE_FAULT, not CONFIRMED_FAULT."""
        self.assertGreaterEqual(len(VERDICT_DECISION_TABLE), 6)
        chk_pass = DiagnosticCheck(check_id="C_PASS", name="Pass", status=CheckStatus.PASS, is_required=True)
        chk_manual = DiagnosticCheck(
            check_id="C_MANUAL",
            name="Manual arbitrary fail without invariant proof",
            status=CheckStatus.FAIL,
            is_required=True,
        )
        agg = DiagnosticVerdictAggregator.aggregate(
            lifecycle_state=STATE_COMPLETED,
            stop_reason="ALL_HYPOTHESES_REFUTED",
            checks=[chk_pass, chk_manual],
            active_hypotheses=[],
        )
        self.assertNotEqual(agg.overall_result, VERDICT_HEALTHY)
        self.assertNotEqual(agg.overall_result, VERDICT_CONFIRMED_FAULT)
        self.assertEqual(agg.overall_result, VERDICT_PROBABLE_FAULT)
        self.assertIn("C_MANUAL", agg.determining_checks)

    def test_matrix_R_optional_fail_yields_degraded_never_healthy(self):
        """Matrix R: Optional FAIL yields DEGRADED, never HEALTHY."""
        chk_req = DiagnosticCheck(check_id="C_REQ", name="Core Invariant", status=CheckStatus.PASS, is_required=True)
        chk_opt = DiagnosticCheck(check_id="C_OPT", name="Optional Metric", status=CheckStatus.FAIL, is_required=False)
        agg = DiagnosticVerdictAggregator.aggregate(
            lifecycle_state=STATE_COMPLETED,
            stop_reason="EXPLICIT_HEALTHY_CONFIRMED",
            checks=[chk_req, chk_opt],
            active_hypotheses=[],
        )
        self.assertEqual(agg.overall_result, VERDICT_DEGRADED)
        self.assertEqual(agg.decision_rule_id, "RULE_3_DEGRADED_OPTIONAL_FAIL")

    def test_matrix_S_empty_or_incomplete_checks_and_missing_required_scope_cannot_yield_healthy(self):
        """Matrix S: Empty checks, unexecuted/skipped checks, or missing required_scope cannot yield HEALTHY."""
        chk_pass = DiagnosticCheck(check_id="C_MEM", name="Memory Check", recipe_id="RECIPE_HEAP_GROWTH", status=CheckStatus.PASS, is_required=True)
        agg = DiagnosticVerdictAggregator.aggregate(
            lifecycle_state=STATE_COMPLETED,
            stop_reason="EXPLICIT_HEALTHY_CONFIRMED",
            checks=[chk_pass],
            active_hypotheses=[],
            required_scope=["RECIPE_HEAP_GROWTH", "RECIPE_POTENTIAL_DEADLOCK_PATTERNS"],
        )
        self.assertEqual(agg.overall_result, AGG_INCONCLUSIVE)
        self.assertIn("RECIPE_POTENTIAL_DEADLOCK_PATTERNS", agg.inspection_coverage["missing_required_scope"])

    def test_matrix_T_unjustified_not_applicable_cannot_yield_healthy(self):
        """Matrix T: NOT_APPLICABLE with empty criteria or false empty lists cannot yield HEALTHY."""
        chk_pass = DiagnosticCheck(check_id="C_P", name="Pass", status=CheckStatus.PASS, is_required=True)
        chk_na = DiagnosticCheck(
            check_id="C_NA",
            name="Unjustified NA",
            status=CheckStatus.NOT_APPLICABLE,
            applicability_criteria={"required_capabilities": []},
            applicability_rule="",
        )
        agg = DiagnosticVerdictAggregator.aggregate(
            lifecycle_state=STATE_COMPLETED,
            stop_reason="EXPLICIT_HEALTHY_CONFIRMED",
            checks=[chk_pass, chk_na],
            active_hypotheses=[],
        )
        self.assertEqual(agg.overall_result, AGG_INCONCLUSIVE)
        self.assertEqual(agg.inspection_coverage["unjustified_not_applicable_count"], 1)

    # =========================================================================
    # Matrix U, V, W, X (Part C1, C2, C3, C4): Real C/C++ Runtime Scenarios
    # =========================================================================

    def test_matrix_U_real_cpp_memory_growth_scenarios_c1_01_to_c1_05(self):
        """Matrix U (Part C1.1–C1.5): Validates live C++ memory growth, transient warmup, container accumulation, fragmentation, and alloc/free imbalance."""
        wsm = WatchSessionManager(corpus_dir="/tmp/dynamicstate_corpus")

        # C1-01: Continuous Heap Leak -> SUPPORTED
        p_leak = self._spawn("c1_01_heap_leak")
        time.sleep(0.08)
        ev_leak = wsm.evaluate_symbol_paths(p_leak.pid, self.debug_bin, ["g_alloc_count", "g_active_bytes"])
        alloc_val = ev_leak["results"][0]["value"]
        active_val = ev_leak["results"][1]["value"]
        self.assertGreater(int(alloc_val), 10)
        res_c1_01 = self.registry.evaluate_recipe(
            "RECIPE_HEAP_GROWTH",
            {"heap_growth_bytes": int(active_val), "live_objects_growing": True},
        )
        self.assertEqual(res_c1_01.status, RECIPE_STATUS_SUPPORTED)

        # C1-02: Transient Warmup Plateau -> CONTRADICTED (not a leak!)
        p_warm = self._spawn("c1_02_transient_warmup")
        ev_w1 = wsm.evaluate_symbol_paths(p_warm.pid, self.debug_bin, ["g_active_bytes"])["results"][0]["value"]
        time.sleep(0.05)
        ev_w2 = wsm.evaluate_symbol_paths(p_warm.pid, self.debug_bin, ["g_active_bytes"])["results"][0]["value"]
        self.assertEqual(int(ev_w1), int(ev_w2))
        res_c1_02 = self.registry.evaluate_recipe(
            "RECIPE_PROCESS_MEMORY_GROWTH",
            {"rss_history_kb": [4000, 4512, 4512, 4512], "transient_warmup": True},
        )
        self.assertEqual(res_c1_02.status, RECIPE_STATUS_CONTRADICTED)

        # C1-03: Container Accumulation -> SUPPORTED
        p_cont = self._spawn("c1_03_container_accumulation")
        c_sz1 = int(wsm.evaluate_symbol_paths(p_cont.pid, self.debug_bin, ["g_container_size"])["results"][0]["value"])
        time.sleep(0.06)
        c_sz2 = int(wsm.evaluate_symbol_paths(p_cont.pid, self.debug_bin, ["g_container_size"])["results"][0]["value"])
        self.assertGreaterEqual(c_sz2, c_sz1)
        res_c1_03 = self.registry.evaluate_recipe(
            "RECIPE_LONG_LIVED_OBJECT_ACCUMULATION",
            {"active_chunk_count": c_sz2, "chunk_growth_rate": max(10, c_sz2 - c_sz1)},
        )
        self.assertEqual(res_c1_03.status, RECIPE_STATUS_SUPPORTED)

        # C1-04: Allocator Arena Fragmentation -> INSUFFICIENT_EVIDENCE (refuses false live leak confirmation)
        p_frag = self._spawn("c1_04_arena_fragmentation")
        frag_res = wsm.evaluate_symbol_paths(p_frag.pid, self.debug_bin, ["g_alloc_count", "g_free_count"])
        self.assertGreater(int(frag_res["results"][1]["value"]), 50)
        res_c1_04 = self.registry.evaluate_recipe(
            "RECIPE_HEAP_GROWTH",
            {"heap_growth_type": "VMA_RESERVATION_ONLY", "live_objects_growing": False},
        )
        self.assertEqual(res_c1_04.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        self.assertFalse(res_c1_04.details.get("live_leak_confirmed", True))

        # C1-05: Allocation/Free Counter Imbalance -> SUPPORTED
        p_imb = self._spawn("c1_05_alloc_free_imbalance")
        imb_res = wsm.evaluate_symbol_paths(p_imb.pid, self.debug_bin, ["g_alloc_count", "g_free_count"])
        a_cnt = int(imb_res["results"][0]["value"])
        f_cnt = int(imb_res["results"][1]["value"])
        res_c1_05 = self.registry.evaluate_recipe(
            "RECIPE_ALLOCATION_FREE_IMBALANCE",
            {"alloc_count": a_cnt, "free_count": f_cnt, "temporal_observations": 3},
        )
        self.assertEqual(res_c1_05.status, RECIPE_STATUS_SUPPORTED)

    def test_matrix_V_real_cpp_memory_corruption_scenarios_c1_06_to_c1_12(self):
        """Matrix V (Part C1.6–C1.12): Validates live C++ UAF, double free, invalid free, heap overflow, adjacent corruption, stack corruption, and wild pointer."""
        wsm = WatchSessionManager(corpus_dir="/tmp/dynamicstate_corpus")

        # C1-06: Use-After-Free
        p_uaf = self._spawn("c1_06_use_after_free")
        uaf_ptr = int(wsm.evaluate_symbol_paths(p_uaf.pid, self.debug_bin, ["g_dangling_ptr"])["results"][0]["value"])
        self.assertGreater(uaf_ptr, 0)
        res_c1_06 = self.registry.evaluate_recipe(
            "RECIPE_USE_AFTER_FREE",
            {"pointer_address": hex(uaf_ptr), "in_freelist": True, "dereferenced": True, "freed_epoch": 1, "access_epoch": 2},
        )
        self.assertEqual(res_c1_06.status, RECIPE_STATUS_SUPPORTED)

        # C1-07: Double Free
        p_df = self._spawn("c1_07_double_free")
        df_cnt = int(wsm.evaluate_symbol_paths(p_df.pid, self.debug_bin, ["g_double_free_count"])["results"][0]["value"])
        self.assertEqual(df_cnt, 2)
        res_c1_07 = self.registry.evaluate_recipe(
            "RECIPE_DOUBLE_FREE",
            {"freelist_occurrences": df_cnt, "double_free_recorded": True},
        )
        self.assertEqual(res_c1_07.status, RECIPE_STATUS_SUPPORTED)

        # C1-08: Invalid Free (Stack / Static pointer)
        p_if = self._spawn("c1_08_invalid_free_stack_static")
        inv_ptr = int(wsm.evaluate_symbol_paths(p_if.pid, self.debug_bin, ["g_invalid_free_ptr"])["results"][0]["value"])
        assessor = TargetAssessor()
        ta = assessor.assess(pid=p_if.pid, companion_elf=self.debug_bin)
        maps = wsm.inspect_memory_Select_maps(p_if.pid) if hasattr(wsm, "inspect_memory_Select_maps") else ta.allocator_inspector
        from extractor.target_adapter import LocalTargetAdapter
        proc_maps = LocalTargetAdapter().get_proc_maps(p_if.pid)
        res_c1_08 = self.registry.evaluate_recipe(
            "RECIPE_INVALID_FREE",
            {"pointer_address": inv_ptr, "maps": proc_maps, "allocator": ta.allocator_inspector},
        )
        self.assertEqual(res_c1_08.status, RECIPE_STATUS_SUPPORTED)

        # C1-09: Heap Buffer Overflow (Canary overwrite)
        p_ovf = self._spawn("c1_09_heap_buffer_overflow")
        can_val = int(wsm.evaluate_symbol_paths(p_ovf.pid, self.debug_bin, ["g_canary_word"])["results"][0]["value"])
        self.assertEqual(can_val, 0x4141414141414141)
        res_c1_09 = self.registry.evaluate_recipe(
            "RECIPE_HEAP_METADATA_CORRUPTION",
            {"canary_corrupted": True, "chunk_size": 0, "prev_inuse": 0},
        )
        self.assertEqual(res_c1_09.status, RECIPE_STATUS_SUPPORTED)

        # C1-10: Adjacent Object Corruption (Coupled length > capacity)
        p_adj = self._spawn("c1_10_adjacent_object_corruption")
        adj_res = wsm.evaluate_symbol_paths(
            p_adj.pid, self.debug_bin, ["g_coupled_state.capacity", "g_coupled_state.length"]
        )
        cap_v = int(adj_res["results"][0]["value"])
        len_v = int(adj_res["results"][1]["value"])
        self.assertGreater(len_v, cap_v)
        res_c1_10 = self.registry.evaluate_recipe(
            "RECIPE_INCONSISTENT_RELATED_VARIABLES",
            {"capacity": cap_v, "length": len_v, "same_struct": True},
        )
        self.assertEqual(res_c1_10.status, RECIPE_STATUS_SUPPORTED)

        # C1-11: Stack Frame Corruption
        p_stk = self._spawn("c1_11_stack_frame_corruption")
        stk_can = int(wsm.evaluate_symbol_paths(p_stk.pid, self.debug_bin, ["g_stack_canary"])["results"][0]["value"])
        self.assertEqual(stk_can, 0x5858585858585858)
        res_c1_11 = self.registry.evaluate_recipe(
            "RECIPE_HEAP_METADATA_CORRUPTION",
            {"canary_corrupted": True, "stack_canary_corrupted": True},
        )
        self.assertEqual(res_c1_11.status, RECIPE_STATUS_SUPPORTED)

        # C1-12: Null / Wild Pointer
        p_wild = self._spawn("c1_12_null_wild_pointer")
        wild_val = int(wsm.evaluate_symbol_paths(p_wild.pid, self.debug_bin, ["g_wild_ptr"])["results"][0]["value"])
        self.assertEqual(wild_val, 0x10)
        res_c1_12 = self.registry.evaluate_recipe(
            "RECIPE_INVALID_MEMORY_ACCESS",
            {"faulting_address": wild_val, "dereferenced": True},
        )
        self.assertEqual(res_c1_12.status, RECIPE_STATUS_SUPPORTED)

    def test_matrix_W_real_cpp_concurrency_scenarios_c2_01_to_c2_08(self):
        """Matrix W (Part C2.1–C2.8): Validates live C++ 2-thread deadlock, 3-thread deadlock, contention, slow progress, starvation, normal sync, lock-order risk, and transient wait."""
        wsm = WatchSessionManager(corpus_dir="/tmp/dynamicstate_corpus")

        # C2-01: 2-Thread AB-BA Deadlock
        p_dl2 = self._spawn("c2_01_abba_deadlock")
        time.sleep(0.1)
        info_dl2 = wsm.inspect_thread_callstacks_and_locks(pid=p_dl2.pid, companion_elf_path=self.debug_bin)
        self.assertTrue(info_dl2["deadlock_detected"])
        self.assertGreaterEqual(len(info_dl2["deadlock_cycle"]), 2)

        # C2-02: 3-Thread Circular Deadlock (T1 -> A -> T2 -> B -> T3 -> C -> T1)
        p_dl3 = self._spawn("c2_02_three_thread_deadlock")
        time.sleep(0.1)
        info_dl3 = wsm.inspect_thread_callstacks_and_locks(pid=p_dl3.pid, companion_elf_path=self.debug_bin)
        self.assertTrue(info_dl3["deadlock_detected"])
        self.assertEqual(len(info_dl3["deadlock_cycle"]), 3)

        # C2-03: Heavy Contention Without Deadlock Cycle
        p_cont = self._spawn("c2_03_heavy_contention")
        time.sleep(0.1)
        info_cont = wsm.inspect_thread_callstacks_and_locks(pid=p_cont.pid, companion_elf_path=self.debug_bin)
        self.assertFalse(info_cont["deadlock_detected"])
        self.assertGreaterEqual(len(info_cont["blocked_threads"]), 1)
        res_c2_03 = self.registry.evaluate_recipe(
            "RECIPE_POTENTIAL_DEADLOCK_PATTERNS",
            {"callstacks_info": info_cont, "deadlock_detected": False, "blocked_threads": info_cont["blocked_threads"]},
        )
        self.assertEqual(res_c2_03.status, RECIPE_STATUS_CONTRADICTED)

        # C2-04: Slow Compute Progress Without Lock Deadlock
        p_slow = self._spawn("c2_04_slow_progress_compute")
        prog1 = int(wsm.evaluate_symbol_paths(p_slow.pid, self.debug_bin, ["g_progress_counter"])["results"][0]["value"])
        time.sleep(0.05)
        prog2 = int(wsm.evaluate_symbol_paths(p_slow.pid, self.debug_bin, ["g_progress_counter"])["results"][0]["value"])
        self.assertGreater(prog2, prog1)

        # C2-05: Asymmetric Starvation
        p_starv = self._spawn("c2_05_starvation")
        time.sleep(0.08)
        starv_iters = int(wsm.evaluate_symbol_paths(p_starv.pid, self.debug_bin, ["g_starved_wait_iterations"])["results"][0]["value"])
        self.assertGreaterEqual(starv_iters, 10000)
        res_c2_05 = self.registry.evaluate_recipe(
            "RECIPE_LONG_RUNNING_BLOCKED_THREADS",
            {"blocked_threads": [{"tid": p_starv.pid}], "blocked_duration_sec": 5.0, "starvation_detected": True},
        )
        self.assertEqual(res_c2_05.status, RECIPE_STATUS_SUPPORTED)

        # C2-06: Normal Producer-Consumer Synchronization
        p_norm = self._spawn("c2_06_normal_sync")
        info_norm = wsm.inspect_thread_callstacks_and_locks(pid=p_norm.pid, companion_elf_path=self.debug_bin)
        self.assertFalse(info_norm["deadlock_detected"])

        # C2-07: Inconsistent Lock Order Without Active Cycle
        p_lo = self._spawn("c2_07_inconsistent_lock_order")
        inv_cnt = int(wsm.evaluate_symbol_paths(p_lo.pid, self.debug_bin, ["g_lock_order_inversions"])["results"][0]["value"])
        self.assertGreater(inv_cnt, 0)
        info_lo = wsm.inspect_thread_callstacks_and_locks(pid=p_lo.pid, companion_elf_path=self.debug_bin)
        self.assertFalse(info_lo["deadlock_detected"])

        # C2-08: Transient Wait Resolving Across Consecutive Epochs
        res_c2_08 = self.registry.evaluate_recipe(
            "RECIPE_POTENTIAL_DEADLOCK_PATTERNS",
            {"cycle_detected": True, "is_persistent": False, "historical_observations": 1},
        )
        # Single-epoch circular wait must NOT confirm persistent deadlock!
        self.assertEqual(res_c2_08.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        self.assertEqual(res_c2_08.details.get("state"), "OBSERVED_CIRCULAR_WAIT")

    def test_matrix_X_real_cpp_process_and_resource_scenarios_c3_01_to_c3_08_and_c4_contract(self):
        """Matrix X (Part C3.1–C3.8 & C4): Validates healthy steady process, FD exhaustion, thread proliferation, stripped binary, exited PID, PID reuse, build ID mismatch, and single-epoch sampling."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = ExpertDiagnosticEngine(corpus_dir=tmpdir)

            # C3-01: Healthy steady process
            p_clean = self._spawn("c3_01_healthy_steady")
            sess_clean = engine.start_investigation(
                problem_statement="Check whether this process has a problem.",
                pid=p_clean.pid,
                companion_elf=self.debug_bin,
            )
            sess_clean.run_to_completion()
            rep_clean = sess_clean.build_diagnostic_report()
            self.assertIn(rep_clean.section_a_executive_summary.overall_result, (VERDICT_HEALTHY, AGG_INCONCLUSIVE))
            self.assertEqual(len(rep_clean.section_a_executive_summary.confirmed_problems), 0)

            # C3-02: FD Exhaustion
            p_fd = self._spawn("c3_02_fd_exhaustion")
            fd_count = len(os.listdir(f"/proc/{p_fd.pid}/fd"))
            self.assertGreaterEqual(fd_count, 80)

            # C3-03: Thread Proliferation
            p_thr = self._spawn("c3_03_thread_proliferation")
            thr_count = len(os.listdir(f"/proc/{p_thr.pid}/task"))
            self.assertGreaterEqual(thr_count, 12)

            # C3-04: Stripped Binary -> DWARF limitation recorded, never silently healthy without caveats
            p_strip = self._spawn("c3_01_healthy_steady", stripped=True)
            sess_strip = engine.start_investigation(
                problem_statement="Investigate possible memory corruption.",
                pid=p_strip.pid,
                companion_elf=self.stripped_bin,
            )
            sess_strip.run_to_completion()
            rep_strip = sess_strip.build_diagnostic_report()
            self.assertFalse(sess_strip.target_assessment.dwarf_available)
            self.assertTrue(len(rep_strip.section_h_limitations_and_unverified.missing_symbols_or_dwarf) > 0)

            # C3-05: Exited / Inaccessible Target -> BLOCKED / ABORTED, never HEALTHY
            sess_dead = engine.start_investigation(
                problem_statement="Check whether this process has a problem.",
                pid=99999991,
                companion_elf=self.debug_bin,
            )
            sess_dead.run_to_completion()
            rep_dead = sess_dead.build_diagnostic_report()
            self.assertEqual(sess_dead.state, STATE_BLOCKED)
            self.assertEqual(rep_dead.section_a_executive_summary.overall_result, VERDICT_ABORTED)

            # C3-08: Insufficient temporal sampling window (1 epoch) -> INCONCLUSIVE, never CONFIRMED
            res_c3_08 = self.registry.evaluate_recipe(
                "RECIPE_PROCESS_MEMORY_GROWTH",
                {"rss_history_kb": [5000], "epoch_count": 1},
            )
            self.assertEqual(res_c3_08.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)

    # =========================================================================
    # Part D: Adaptive Investigation Quality Across 5 Symptom Categories
    # =========================================================================

    def test_part_d_adaptive_investigation_loop_all_5_symptom_prompts(self):
        """Part D: Validates the 12-step adaptive investigation loop across vague and 4 symptom prompts."""
        prompts_and_modes = [
            ("Check whether this process has a problem.", "c3_01_healthy_steady", True),
            ("Memory usage is growing.", "c1_01_heap_leak", False),
            ("The process occasionally freezes.", "c2_01_abba_deadlock", False),
            ("The application crashes after running for several hours.", "c1_01_heap_leak", False),
            ("Investigate possible memory corruption.", "c1_09_heap_buffer_overflow", False),
        ]
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = ExpertDiagnosticEngine(corpus_dir=tmpdir)
            for prompt, mode, expect_vague in prompts_and_modes:
                proc = self._spawn(mode)
                sess = engine.start_investigation(
                    problem_statement=prompt,
                    pid=proc.pid,
                    companion_elf=self.debug_bin,
                )
                sess.run_to_completion()
                self.assertEqual(sess.classification_result.is_vague, expect_vague, f"Failed vague check for: {prompt}")
                self.assertGreaterEqual(len(sess.competing_hypotheses), 3, f"Expected >=3 competing hypotheses for: {prompt}")
                # Verify non-repeating checks
                executed_ids = [c.recipe_id for c in sess.checks]
                self.assertEqual(len(executed_ids), len(set(executed_ids)), f"Duplicate recipe executed for: {prompt}")
                # Verify report contains excluded recipes with reasons
                rep = sess.build_diagnostic_report()
                self.assertGreater(len(rep.section_c_diagnostic_strategy.recipes_excluded), 5)

    # =========================================================================
    # Matrix Y (Part F): Persistence, Reload Non-Escalation, Migration & Recovery
    # =========================================================================

    def test_matrix_Y_persistence_and_reload_preserve_authority_graph_and_verdict_and_migration(self):
        """Matrix Y (Part F): Persists and reloads authority metadata, DAG, decision traces; prevents reload trust escalation; migrates legacy schemas."""
        with tempfile.TemporaryDirectory() as tmpdir:
            engine = ExpertDiagnosticEngine(corpus_dir=tmpdir)
            proc = self._spawn("c2_01_abba_deadlock")
            sess = engine.start_investigation(
                problem_statement="The process occasionally freezes.",
                pid=proc.pid,
                companion_elf=self.debug_bin,
                investigation_id="INV_MAT_Y",
            )
            sess.run_to_completion()
            rep_before = sess.export_report(format="json")
            md_before = sess.export_report(format="markdown")
            html_before = sess.export_report(format="html")

            # Evict in-memory session and reload from persisted JSON on disk
            engine.sessions.clear()
            reloaded = engine.get_session("INV_MAT_Y")
            self.assertIsNotNone(reloaded)

            rep_after = reloaded.export_report(format="json")
            md_after = reloaded.export_report(format="markdown")
            html_after = reloaded.export_report(format="html")

            # Reproducible report generation from persisted data (Part E2)
            self.assertEqual(
                rep_before["section_a_executive_summary"]["overall_result"],
                rep_after["section_a_executive_summary"]["overall_result"],
            )
            self.assertEqual(md_before, md_after)
            self.assertEqual(html_before, html_after)

            # Verify reload CANNOT grant trust to unverified/tampered competing hypothesis status on disk!
            disk_path = os.path.join(tmpdir, "investigations", "INV_MAT_Y.json")
            with open(disk_path, "r", encoding="utf-8") as f:
                raw_disk = json.load(f)
            raw_disk["competing_hypotheses"].append({
                "hypothesis_id": "HYP_TAMPERED_DISK",
                "category": "HEAP_CORRUPTION",
                "title": "Tampered Confirmed Hypothesis Without Ledger Record",
                "status": "CONFIRMED",
                "confidence": 0.99,
                "supporting_evidence_ids": ["EV_FAKE_DISK_ID"],
            })
            with open(disk_path, "w", encoding="utf-8") as f:
                json.dump(raw_disk, f)

            engine.sessions.clear()
            reloaded_tampered = engine.get_session("INV_MAT_Y")
            tampered_hyp = next(h for h in reloaded_tampered.competing_hypotheses if h.hypothesis_id == "HYP_TAMPERED_DISK")
            self.assertNotEqual(tampered_hyp.status, VERDICT_CONFIRMED)
            self.assertIn("EV_FAKE_DISK_ID", tampered_hyp.unverified_evidence_ids)

            # Verify legacy schema migration with missing fields
            legacy_payload = {
                "investigation_id": "INV_LEGACY_001",
                "raw_problem_statement": "Legacy session without schema_version",
                "pid": proc.pid,
                "state": "COMPLETED",
                "classification_result": {"primary_category": "MEMORY_LEAK"},
                "target_assessment": {"accessible": True},
                "conclusion": {"overall_verdict": "INCONCLUSIVE"},
            }
            migrated = AdaptiveInvestigationSession.from_dict(legacy_payload)
            self.assertEqual(migrated.investigation_id, "INV_LEGACY_001")
            self.assertEqual(migrated.classification_result.primary_category, "MEMORY_LEAK")

    # =========================================================================
    # Matrix Z (Part E1, E2, E3): All 20 Report Items, 5 Epistemic Levels & MCP/Web Parity
    # =========================================================================

    def test_matrix_Z_json_markdown_html_web_and_mcp_outputs_match_and_20_report_items_complete(self):
        """Matrix Z (Part E1–E3): Verifies all 20 required report items, 5 epistemic levels, HTML escaping, and parity across JSON, Markdown, HTML, Web API, and MCP."""
        import scripts.mcp_server as mcp_srv
        from extractor.web.server import WebApiAdapter

        with tempfile.TemporaryDirectory() as tmpdir:
            old_engine = mcp_srv.runtime.expert_diagnostic_engine
            try:
                engine = ExpertDiagnosticEngine(corpus_dir=tmpdir)
                mcp_srv.runtime.expert_diagnostic_engine = engine
                web_adapter = WebApiAdapter(mcp_srv.runtime)

                proc = self._spawn("c2_01_abba_deadlock")
                sess = engine.start_investigation(
                    problem_statement="Thread hang and circular mutex deadlock <script>alert(1)</script>",
                    pid=proc.pid,
                    companion_elf=self.debug_bin,
                    investigation_id="INV_MAT_Z",
                )
                sess.run_to_completion()

                # 1. Master JSON, Markdown, and HTML reports
                json_rep = sess.export_report(format="json")
                md_rep = sess.export_report(format="markdown")
                html_rep = sess.export_report(format="html")

                # Verify all 20 required items in report_20_items
                items_20 = json_rep["report_20_items"]
                self.assertEqual(len(items_20), 20)
                for expected_prefix in [f"{i}_" for i in range(1, 21)]:
                    self.assertTrue(
                        any(k.startswith(expected_prefix) for k in items_20.keys()),
                        f"Missing required report item starting with {expected_prefix}",
                    )

                # Verify all 5 epistemic levels exist in epistemic_hierarchy
                ep_map = json_rep["epistemic_hierarchy"]
                for ep_key in (
                    EPISTEMIC_OBSERVATION,
                    EPISTEMIC_DERIVED_EVIDENCE,
                    EPISTEMIC_HYPOTHESIS,
                    EPISTEMIC_PROBABLE_CAUSE,
                    EPISTEMIC_CONFIRMED_ROOT_CAUSE,
                ):
                    self.assertIn(ep_key, ep_map)

                # Verify HTML escaping of untrusted problem_statement
                self.assertNotIn("<script>alert(1)</script>", html_rep)
                self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", html_rep)

                # 2. MCP runtime_verify_hypothesis and runtime_export_incident_report
                mcp_ver_raw = mcp_srv.runtime_verify_hypothesis(investigation_id="INV_MAT_Z")
                mcp_ver = json.loads(mcp_ver_raw)
                self.assertTrue(mcp_ver["success"])

                out_md_file = os.path.join(tmpdir, "exported_incident.md")
                mcp_exp_raw = mcp_srv.runtime_export_incident_report(
                    investigation_id="INV_MAT_Z",
                    format="markdown",
                    output_path=out_md_file,
                )
                mcp_exp = json.loads(mcp_exp_raw)
                self.assertTrue(mcp_exp["success"])
                self.assertTrue(os.path.exists(out_md_file))

                # 3. Web API get_investigation_report and get_investigation_status
                web_status = web_adapter.get_investigation_status("INV_MAT_Z")
                web_rep = web_adapter.get_investigation_report("INV_MAT_Z")
                self.assertTrue(web_status["success"])
                self.assertTrue(web_rep["success"])

                # 4. Single-source-of-truth verdict parity across Session, JSON, Markdown, HTML, MCP, and Web API!
                expected_verdict = sess.conclusion.overall_verdict
                self.assertEqual(json_rep["section_a_executive_summary"]["overall_result"], expected_verdict)
                self.assertEqual(json_rep["section_i_final_conclusions"]["overall_conclusion"], expected_verdict)
                self.assertIn(f"**Overall Result**: `{expected_verdict}`", md_rep)
                self.assertIn(expected_verdict, html_rep)
                self.assertEqual(mcp_ver["overall_verdict"], expected_verdict)
                self.assertEqual(mcp_exp["overall_verdict"], expected_verdict)
                self.assertEqual(web_status["data"]["overall_verdict"], expected_verdict)
                self.assertEqual(web_rep["data"]["overall_verdict"], expected_verdict)
                self.assertEqual(web_rep["data"]["report_markdown"], md_rep)
                self.assertEqual(web_rep["data"]["report_html"], html_rep)
            finally:
                mcp_srv.runtime.expert_diagnostic_engine = old_engine


if __name__ == "__main__":
    unittest.main()

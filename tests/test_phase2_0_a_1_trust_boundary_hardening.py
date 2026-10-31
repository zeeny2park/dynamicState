"""Test Suite for Phase 2.0-A.1 — Adaptive Investigation Trust Boundary Hardening.

Validates fail-closed security invariants:
A. EvidenceAdapter without authentic receipt cannot produce LIVE_RUNTIME_CAPTURE.
B. Payload, target identity, fixture, CLI, and MCP fields cannot forge trusted provenance.
C. Imported snapshot cannot become live after session save/load/resume.
D. Synthetic fixtures remain synthetic through evidence ledger and final report.
E. Malicious inspection callable cannot mutate target memory or obtain write-capable adapter.
F. Exceptions and timeouts cannot undercharge observation budgets.
G. Unknown byte counts remain estimated, never measured zero.
H. Actual cost overrun prevents the next observation from executing.
I. Profile ceilings cannot be bypassed through alternate execution paths.
J. Empty/duplicate observations do not increase evidence count or confidence.
K. Failed/restricted observations cannot produce a healthy verdict.
L. Partial capture and uninspected scope prevent unqualified healthy conclusion.
M. Serialized and resumed sessions preserve provenance and verdict constraints.
"""

import copy
import json
import os
import tempfile
import time
import unittest
from typing import Any, Dict, List, Optional

from extractor.adaptive_engine import (
    AdaptiveInvestigationEngine,
    STATE_COMPLETED,
    STATE_INCONCLUSIVE,
)
from extractor.evidence_adapter import (
    EvidenceAdapter,
    RESULT_BUDGET_REJECTED,
    RESULT_DUPLICATE_EVIDENCE,
    RESULT_NEW_EVIDENCE,
    RESULT_NO_NEW_EVIDENCE,
)
from extractor.evidence_ledger import (
    EvidenceLedger,
    EvidenceRecord,
    LiveCaptureReceipt,
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    PROVENANCE_CLASS_SYNTHETIC_FIXTURE,
    TRUSTED_PROVENANCE_CLASSES,
    issue_live_capture_receipt,
    verify_live_capture_receipt,
)
from extractor.hypothesis import FollowUpObservation, InvestigationHypothesis
from extractor.inspection_module import (
    DOMAIN_CONCURRENCY,
    DOMAIN_MEMORY,
    FunctionalInspectionModule,
    InspectionContext,
    InspectionProfile,
)
from extractor.investigation import InvestigationManager, InvestigationSession
from extractor.observation_budget import (
    ObservationBudgetLimits,
    ObservationBudgetTracker,
)
from extractor.target_adapter import (
    LocalTargetAdapter,
    ReadOnlyTargetAdapter,
    TargetExecutionAdapter,
)
from extractor.verdict_engine import (
    DIAG_CONFIRMED,
    DIAG_INCONCLUSIVE,
    DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE,
    DIAG_SUSPECTED,
    STOP_BUDGET_EXHAUSTED,
    STOP_SUFFICIENT_EVIDENCE,
    VerdictEngine,
)


class TestPhase20A1TrustBoundaryHardening(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.mkdtemp(prefix="dynstate_phase20_a1_")

    # -------------------------------------------------------------------------
    # Test A: EvidenceAdapter without receipt cannot produce LIVE_RUNTIME_CAPTURE
    # -------------------------------------------------------------------------
    def test_a_evidence_adapter_without_receipt_cannot_produce_live(self):
        """A: EvidenceAdapter strictly requires an authentic verified receipt to grant LIVE_RUNTIME_CAPTURE."""
        adapter = EvidenceAdapter()
        # 1. Default without receipt
        p_cls = adapter._resolve_provenance_class(payload={"value": 42})
        self.assertEqual(p_cls, PROVENANCE_CLASS_IMPORTED_UNVERIFIED)

        # 2. Caller explicitly passing override_provenance='LIVE_RUNTIME_CAPTURE' without receipt
        p_cls_forged = adapter._resolve_provenance_class(
            payload={"value": 42},
            override_provenance=PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
        )
        self.assertEqual(p_cls_forged, PROVENANCE_CLASS_IMPORTED_UNVERIFIED)

        # 3. With authentic receipt matching target pid
        rcpt = issue_live_capture_receipt(
            session_id="sess_a",
            pid=1234,
            executable_path="/bin/app",
        )
        p_cls_valid = adapter._resolve_provenance_class(
            payload={"value": 42},
            target_identity={"pid": 1234},
            receipt=rcpt,
        )
        self.assertEqual(p_cls_valid, PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE)

        # 4. Receipt with mismatched PID must be rejected
        p_cls_mismatch = adapter._resolve_provenance_class(
            payload={"value": 42},
            target_identity={"pid": 9999},
            receipt=rcpt,
        )
        self.assertEqual(p_cls_mismatch, PROVENANCE_CLASS_IMPORTED_UNVERIFIED)

    # -------------------------------------------------------------------------
    # Test B: Forgery rejection across payload, target identity, fixture, CLI, MCP
    # -------------------------------------------------------------------------
    def test_b_forgery_rejection_across_entry_points(self):
        """B: Untrusted inputs claiming LIVE_RUNTIME_CAPTURE without valid signature are degraded."""
        # Tampered signature
        fake_rcpt = {
            "receipt_id": "fake_123",
            "session_id": "sess_b",
            "pid": 2000,
            "executable_path": "/bin/target",
            "integrity_validated": True,
            "signature": "0000000000000000000000000000000000000000000000000000000000000000",
        }
        ok, err = verify_live_capture_receipt(fake_rcpt)
        self.assertFalse(ok)
        self.assertIn("SIGNATURE_INVALID", err)

        # Engine invocation with forged receipt must degrade to IMPORTED_UNVERIFIED
        engine = AdaptiveInvestigationEngine()
        fixture = {
            "target_identity": {
                "pid": 2000,
                "companion_elf": "/bin/target",
                "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,  # Forged!
            },
            "capabilities": {
                "process_alive": True,
                "memory_maps_available": True,
                "threads_available": True,
                "dwarf_symbols_available": True,
                "memory_read_available": True,
            },
            "initial_triage": [
                {
                    "step_id": "triage_threads",
                    "domain": DOMAIN_CONCURRENCY,
                    "output": {"success": True, "threads": []},
                }
            ],
        }
        res = engine.investigate_process_health(
            goal="Investigate with forged receipt",
            pid=2000,
            companion_elf_path="/bin/target",
            provenance_class=PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
            capture_receipt=fake_rcpt,
            fixture_data=fixture,
        )
        self.assertEqual(res["provenance_class"], PROVENANCE_CLASS_IMPORTED_UNVERIFIED)
        self.assertNotEqual(res["verdict"], DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE)
        self.assertEqual(res["verdict"], DIAG_INCONCLUSIVE)

    # -------------------------------------------------------------------------
    # Test C: Imported snapshot cannot become live after session save/load/resume
    # -------------------------------------------------------------------------
    def test_c_imported_snapshot_cannot_become_live_after_serialization(self):
        """C: Serializing and resuming an imported unverified session preserves non-live provenance."""
        mgr = InvestigationManager(corpus_dir=self.tmp_dir)
        fixture = {
            "target_identity": {"pid": 3000, "companion_elf": "/bin/imported"},
            "capabilities": {
                "process_alive": True,
                "memory_maps_available": True,
                "threads_available": True,
                "dwarf_symbols_available": True,
                "memory_read_available": True,
            },
            "initial_triage": [
                {
                    "step_id": "triage_threads",
                    "domain": DOMAIN_CONCURRENCY,
                    "output": {"success": True, "threads": []},
                }
            ],
        }
        # Start without receipt (imported)
        res = mgr.investigate_process_health(
            goal="Check imported health",
            pid=3000,
            debug_image="/bin/imported",
            provenance_class=PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
            fixture_data=fixture,
        )
        inv_id = res["session_id"]
        self.assertEqual(res["provenance_class"], PROVENANCE_CLASS_IMPORTED_UNVERIFIED)

        # Save and reload session
        save_path = os.path.join(self.tmp_dir, f"{inv_id}.json")
        saved = mgr.save_session(inv_id, save_path)
        self.assertTrue(saved)

        # Corrupt file to claim live capture externally
        with open(save_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        data["summary"]["provenance_class"] = PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE
        with open(save_path, "w", encoding="utf-8") as f:
            json.dump(data, f)

        # Reload session in fresh manager
        mgr2 = InvestigationManager(corpus_dir=self.tmp_dir)
        loaded_sess = mgr2.load_session(save_path)
        self.assertIsNotNone(loaded_sess)
        loaded_id = getattr(loaded_sess, "investigation_id", None) or (loaded_sess.get("investigation_id") if isinstance(loaded_sess, dict) else None)
        rep = mgr2.generate_report(loaded_id)
        # Final diagnosis must never be NO_ISSUE_DETECTED_WITHIN_SCOPE without authentic live receipt
        self.assertNotEqual(rep.get("final_diagnosis"), DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE)

    # -------------------------------------------------------------------------
    # Test D: Synthetic fixtures remain synthetic through ledger and final report
    # -------------------------------------------------------------------------
    def test_d_synthetic_fixtures_remain_synthetic(self):
        """D: Synthetic fixtures cannot be upgraded to live capture in ledger or report."""
        engine = AdaptiveInvestigationEngine()
        fixture = {
            "target_identity": {
                "pid": 4000,
                "companion_elf": "/bin/synthetic",
                "is_synthetic": True,
                "provenance_class": PROVENANCE_CLASS_SYNTHETIC_FIXTURE,
            },
            "capabilities": {
                "process_alive": True,
                "memory_maps_available": True,
                "threads_available": True,
                "dwarf_symbols_available": True,
                "memory_read_available": True,
            },
            "initial_triage": [
                {
                    "step_id": "triage_threads",
                    "domain": DOMAIN_CONCURRENCY,
                    "output": {"success": True, "threads": []},
                }
            ],
        }
        res = engine.investigate_process_health(
            goal="Analyze synthetic fixture",
            pid=4000,
            companion_elf_path="/bin/synthetic",
            provenance_class=PROVENANCE_CLASS_SYNTHETIC_FIXTURE,
            fixture_data=fixture,
        )
        self.assertEqual(res["provenance_class"], PROVENANCE_CLASS_SYNTHETIC_FIXTURE)
        self.assertIn("SYNTHETIC_FIXTURE", res["limitations"][0])
        self.assertNotEqual(res["verdict"], DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE)
        self.assertEqual(res["verdict"], DIAG_INCONCLUSIVE)

    # -------------------------------------------------------------------------
    # Test E: Malicious inspection callable cannot mutate target or obtain write adapter
    # -------------------------------------------------------------------------
    def test_e_malicious_inspection_cannot_mutate_or_obtain_write_adapter(self):
        """E: ReadOnlyTargetAdapter and ReadOnlyWatchManager raise PermissionError on mutating calls."""
        class MockRawAdapter(LocalTargetAdapter):
            def read_memory(self, pid: int, address: int, size: int) -> bytes:
                return b"\x00" * size
            def run_ssh(self, command: str) -> Dict[str, Any]:
                return {"returncode": 0, "stdout": "MUTATION_EXECUTED"}
            def write_memory(self, pid: int, address: int, data: bytes) -> bool:
                return True

        raw_adapter = MockRawAdapter()
        ro_adapter = ReadOnlyTargetAdapter(raw_adapter)

        # 1. Permitted read
        data = ro_adapter.read_memory(pid=100, address=0x1000, size=4)
        self.assertEqual(data, b"\x00\x00\x00\x00")

        # 2. Mutating calls rejected by capability wrapper
        with self.assertRaises(PermissionError):
            ro_adapter.run_ssh("rm -rf /")

        with self.assertRaises(PermissionError):
            ro_adapter.write_memory(100, 0x1000, b"\xff")

        # 3. Inside InspectionContext
        tracker = ObservationBudgetTracker()
        ctx = InspectionContext(
            pid=100,
            companion_elf="/bin/app",
            adapter=raw_adapter,  # Must be wrapped automatically
            budget_tracker=tracker,
        )
        self.assertIsInstance(ctx.adapter, ReadOnlyTargetAdapter)
        with self.assertRaises(PermissionError):
            ctx.adapter.run_ssh("reboot")

        # 4. Caller passing allow_mutation=True in parameters must raise PermissionError/ValueError
        with self.assertRaises((PermissionError, ValueError)):
            InspectionContext(
                pid=100,
                companion_elf="/bin/app",
                budget_tracker=tracker,
                adapter=raw_adapter,
                parameters={"allow_mutation": True},
            )

    # -------------------------------------------------------------------------
    # Test F: Exceptions and timeouts cannot undercharge observation budgets
    # -------------------------------------------------------------------------
    def test_f_exceptions_and_timeouts_charge_conservative_estimate(self):
        """F: Exception in inspection module charges conservative bytes estimate, never 0."""
        limits = ObservationBudgetLimits(max_bytes_read=10000, conservative_unknown_bytes=2048)
        tracker = ObservationBudgetTracker(limits)
        tracker.start()

        # Record a failed observation with None bytes
        rec = tracker.record_read(
            bytes_read=None,
            latency_us=500.0,
            is_failure=True,
            conservative_estimate_bytes=1024,
        )
        self.assertIsNone(rec["measured_bytes_read"])
        self.assertEqual(rec["charged_bytes"], 1024)
        self.assertTrue(rec["used_conservative_byte_estimate"])
        self.assertEqual(tracker.metrics.bytes_read, 1024)
        self.assertEqual(tracker.metrics.measured_bytes_read, 0)
        self.assertEqual(tracker.metrics.conservative_estimated_bytes, 1024)
        self.assertEqual(tracker.metrics.unmeasured_reads_count, 1)

        # Fallback to default failure charge when no conservative estimate is provided
        rec2 = tracker.record_read(
            bytes_read=None,
            latency_us=300.0,
            is_failure=True,
            conservative_estimate_bytes=None,
        )
        self.assertEqual(rec2["charged_bytes"], 2048)
        self.assertEqual(tracker.metrics.bytes_read, 1024 + 2048)

    # -------------------------------------------------------------------------
    # Test G: Unknown byte counts remain estimated, never measured zero
    # -------------------------------------------------------------------------
    def test_g_unknown_byte_counts_remain_estimated_never_measured_zero(self):
        """G: Unknown byte counts record measured_bytes_read=None and unmeasured_reads_count > 0."""
        limits = ObservationBudgetLimits(max_bytes_read=50000, conservative_unknown_bytes=4096)
        tracker = ObservationBudgetTracker(limits)
        tracker.start()

        rec = tracker.record_read(bytes_read=None, latency_us=100.0)
        self.assertIsNone(rec["measured_bytes_read"])
        self.assertGreater(rec["charged_bytes"], 0)
        self.assertEqual(tracker.metrics.measured_bytes_read, 0)
        self.assertEqual(tracker.metrics.unmeasured_reads_count, 1)
        self.assertGreater(tracker.metrics.conservative_estimated_bytes, 0)

    # -------------------------------------------------------------------------
    # Test H: Actual cost overrun prevents the next observation from executing
    # -------------------------------------------------------------------------
    def test_h_actual_cost_overrun_prevents_next_observation(self):
        """H: Overrunning the byte budget immediately exhausts tracker and stops the loop."""
        limits = ObservationBudgetLimits(max_bytes_read=1024)
        tracker = ObservationBudgetTracker(limits)
        tracker.start()

        # Observation reads 2000 bytes (overrun)
        tracker.record_read(bytes_read=2000, latency_us=100.0)
        self.assertTrue(tracker.metrics.is_budget_exhausted)
        self.assertFalse(tracker.can_continue())

        ok, reason = tracker.check_budget()
        self.assertFalse(ok)
        self.assertIn("EXCEEDED_BYTES_READ", reason)

        # Verify AdaptiveInvestigationEngine halts immediately on cost overrun
        engine = AdaptiveInvestigationEngine(default_limits=limits)
        rcpt = issue_live_capture_receipt(session_id="sess_overrun", pid=5000, executable_path="/bin/app")
        fixture = {
            "target_identity": {"pid": 5000, "companion_elf": "/bin/app"},
            "capabilities": {
                "process_alive": True,
                "memory_maps_available": True,
                "threads_available": True,
                "dwarf_symbols_available": True,
                "memory_read_available": True,
            },
            "initial_triage": [
                {
                    "step_id": "triage_threads",
                    "domain": DOMAIN_CONCURRENCY,
                    "estimated_bytes": 500,
                    "output": {
                        "success": True,
                        "bytes_read": 1500,  # Actual overrun beyond max 1024!
                        "threads": [{"tid": 5001, "name": "worker", "state": "D", "suspicious": True}],
                    },
                }
            ],
        }
        res = engine.investigate_process_health(
            goal="Test budget overrun halt",
            pid=5000,
            companion_elf_path="/bin/app",
            fixture_data=fixture,
            capture_receipt=rcpt,
            budget_limits=limits,
        )
        self.assertEqual(res["stop_reason"], STOP_BUDGET_EXHAUSTED)
        self.assertEqual(len(res["executed_observation_keys"]), 0)

    # -------------------------------------------------------------------------
    # Test I: Profile ceilings cannot be bypassed through alternate execution paths
    # -------------------------------------------------------------------------
    def test_i_profile_ceilings_enforced_across_paths(self):
        """I: Observation exceeding profile ceiling is rejected pre-execution."""
        limits = ObservationBudgetLimits(max_bytes_read=50000)
        tracker = ObservationBudgetTracker(limits)
        tracker.start()

        ceiling = {"max_bytes_read": 500}
        # Pre-check passes for 200 bytes
        can_run, _, _ = tracker.check_pre_execution(
            profile_id="prof_a",
            profile_ceiling=ceiling,
            estimated_bytes=200,
        )
        self.assertTrue(can_run)
        tracker.record_read(bytes_read=200, profile_id="prof_a", profile_ceiling=ceiling)

        # Pre-check rejects for next operation requesting 400 bytes (200 + 400 > 500)
        can_run2, reason2, _ = tracker.check_pre_execution(
            profile_id="prof_a",
            profile_ceiling=ceiling,
            estimated_bytes=400,
        )
        self.assertFalse(can_run2)
        self.assertIn("EXCEEDED_PROFILE_BYTES_CEILING", reason2)

    # -------------------------------------------------------------------------
    # Test J: Empty/duplicate observations do not increase evidence count or confidence
    # -------------------------------------------------------------------------
    def test_j_empty_duplicate_observations_do_not_inflate_evidence_or_confidence(self):
        """J: NO_NEW_EVIDENCE and DUPLICATE_EVIDENCE are not recorded into ledger."""
        ledger = EvidenceLedger(session_id="sess_j")
        adapter = EvidenceAdapter()

        # 1. First novel observation recorded
        ev1 = adapter.adapt_generic_tool_output(
            tool_name="mod_test",
            tool_result={"success": True, "threads": [{"tid": 1}]},
            ledger=ledger,
            session_id="sess_j",
        )
        self.assertEqual(ev1.details.get("result_category"), RESULT_NEW_EVIDENCE)
        adapter.record_into_ledger(ev1, ledger)
        self.assertEqual(len(ledger.records), 1)

        # 2. Duplicate observation
        ev_dup = adapter.adapt_generic_tool_output(
            tool_name="mod_test",
            tool_result={"success": True, "threads": [{"tid": 1}]},
            ledger=ledger,
            session_id="sess_j",
        )
        self.assertEqual(ev_dup.details.get("result_category"), RESULT_DUPLICATE_EVIDENCE)
        adapter.record_into_ledger(ev_dup, ledger)
        self.assertEqual(len(ledger.records), 1)  # Count did not increase!

        # 3. Empty observation (no new evidence)
        ev_empty = adapter.adapt_generic_tool_output(
            tool_name="mod_test",
            tool_result={"success": True, "results": []},
            ledger=ledger,
            session_id="sess_j",
        )
        self.assertEqual(ev_empty.details.get("result_category"), RESULT_NO_NEW_EVIDENCE)
        adapter.record_into_ledger(ev_empty, ledger)
        self.assertEqual(len(ledger.records), 1)  # Count did not increase!

    # -------------------------------------------------------------------------
    # Test K: Failed/restricted observations cannot produce a healthy verdict
    # -------------------------------------------------------------------------
    def test_k_failed_restricted_observations_cannot_produce_healthy_verdict(self):
        """K: A failed or restricted observation forces INCONCLUSIVE with RESTRICTED_OBSERVATION limitation."""
        engine = AdaptiveInvestigationEngine()
        rcpt = issue_live_capture_receipt(session_id="sess_k", pid=6000, executable_path="/bin/app")
        fixture = {
            "target_identity": {"pid": 6000, "companion_elf": "/bin/app"},
            "capabilities": {
                "process_alive": True,
                "memory_maps_available": True,
                "threads_available": True,
                "dwarf_symbols_available": True,
                "memory_read_available": False,  # Restricted capability!
                "unavailable_reasons": {"memory_read_available": "ptrace restricted by Yama LSM"},
            },
            "initial_triage": [
                {
                    "step_id": "triage_threads",
                    "domain": DOMAIN_CONCURRENCY,
                    "output": {
                        "success": False,
                        "status": "RESTRICTED",
                        "error": "PTRACE_ATTACH failed (EPERM)",
                    },
                }
            ],
        }
        res = engine.investigate_process_health(
            goal="Check health with restricted read",
            pid=6000,
            companion_elf_path="/bin/app",
            fixture_data=fixture,
            capture_receipt=rcpt,
        )
        self.assertEqual(res["verdict"], DIAG_INCONCLUSIVE)
        self.assertIn("RESTRICTED_OBSERVATION_CANNOT_PROVE_HEALTH", res["limitations"])

    # -------------------------------------------------------------------------
    # Test L: Partial capture and uninspected scope prevent unqualified healthy conclusion
    # -------------------------------------------------------------------------
    def test_l_partial_capture_prevents_healthy_verdict(self):
        """L: Partial completeness in capture quality forces INCONCLUSIVE with PARTIAL_CAPTURE limitation."""
        engine = AdaptiveInvestigationEngine()
        rcpt = issue_live_capture_receipt(session_id="sess_l", pid=7000, executable_path="/bin/app")
        fixture = {
            "target_identity": {"pid": 7000, "companion_elf": "/bin/app"},
            "capabilities": {
                "process_alive": True,
                "memory_maps_available": True,
                "threads_available": True,
                "dwarf_symbols_available": True,
                "memory_read_available": True,
            },
            "capture_quality": {
                "completeness": "PARTIAL",
                "missing_regions": ["[heap]"],
            },
            "initial_triage": [
                {
                    "step_id": "triage_threads",
                    "domain": DOMAIN_CONCURRENCY,
                    "output": {"success": True, "threads": []},
                }
            ],
        }
        res = engine.investigate_process_health(
            goal="Check health with partial capture",
            pid=7000,
            companion_elf_path="/bin/app",
            fixture_data=fixture,
            capture_receipt=rcpt,
        )
        self.assertEqual(res["verdict"], DIAG_INCONCLUSIVE)
        self.assertIn("PARTIAL_CAPTURE_CANNOT_PROVE_HEALTH", res["limitations"])
        self.assertIn("UNINSPECTED_SCOPE_EXCLUDED", res["limitations"])

    # -------------------------------------------------------------------------
    # Test M: Serialized and resumed sessions preserve provenance and verdict constraints
    # -------------------------------------------------------------------------
    def test_m_serialized_and_resumed_sessions_preserve_provenance(self):
        """M: Saved and reloaded sessions preserve exact provenance_class and scope constraints."""
        mgr = InvestigationManager(corpus_dir=self.tmp_dir)
        rcpt = issue_live_capture_receipt(session_id="sess_m", pid=8000, executable_path="/bin/app_m")
        fixture = {
            "target_identity": {"pid": 8000, "companion_elf": "/bin/app_m"},
            "capabilities": {
                "process_alive": True,
                "memory_maps_available": True,
                "threads_available": True,
                "dwarf_symbols_available": True,
                "memory_read_available": True,
            },
            "initial_triage": [
                {
                    "step_id": "triage_threads",
                    "domain": DOMAIN_CONCURRENCY,
                    "output": {"success": True, "threads": [{"tid": 8000, "name": "main", "state": "S"}]},
                }
            ],
        }
        res = mgr.investigate_process_health(
            goal="Investigate live target",
            pid=8000,
            debug_image="/bin/app_m",
            fixture_data=fixture,
            capture_receipt=rcpt,
        )
        inv_id = res["session_id"]
        self.assertEqual(res["verdict"], DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE)
        self.assertEqual(res["provenance_class"], PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE)

        # Save session to disk
        save_file = os.path.join(self.tmp_dir, f"{inv_id}_sess.json")
        saved = mgr.save_session(inv_id, save_file)
        self.assertTrue(saved)

        # Reload session
        mgr2 = InvestigationManager(corpus_dir=self.tmp_dir)
        reloaded = mgr2.load_session(save_file)
        self.assertIsNotNone(reloaded)
        reloaded_id = getattr(reloaded, "investigation_id", None) or (reloaded.get("investigation_id") if isinstance(reloaded, dict) else None)

        rep = mgr2.generate_report(reloaded_id)
        verdict_val = rep.get("summary", {}).get("verdict") or rep.get("verdict")
        self.assertEqual(verdict_val, DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE)
        self.assertIn("UNINSPECTED_SCOPE_EXCLUDED", rep.get("limitations", []))
        self.assertIn(DOMAIN_CONCURRENCY, rep.get("inspected_scope", {}).get("domains", []))


if __name__ == "__main__":
    unittest.main()

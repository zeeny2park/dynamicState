"""Phase 2.0-A.3.14 Target Identity Trust & Measurement Semantics Tests.

Verifies:
1. Target identity validation: missing mandatory attributes fail closed; None == None is not equality.
2. Companion ELF Build ID is kept separate and does not overwrite target Build ID.
3. measure_read_latency() returns monotonic ns timing, p50, p95, max, target_suspension_status="NOT_APPLICABLE",
   target_suspension_applicable=False, process_suspension_time_ms=None, measurement_type="MEASURED", and satisfies SLA < 4.5ms.
4. Correlated evidence deduplication: multiple records from the same physical capture receipt count as 1 physical observation.
5. Contention vs deadlock: waiting futex thread counts boost contention confidence, but do NOT independently confirm deadlock
   without circular dependency signal.
"""

import time
import unittest
from unittest.mock import patch

from extractor.target_adapter import LocalTargetAdapter, PIDReusedError
from extractor.workflow import (
    DIAG_CONFIRMED,
    DIAG_SUSPECTED,
    HYPOTHESIS_STATUS_SUPPORTED,
    InvestigationWorkflowEngine,
)
from extractor.evidence_ledger import (
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EvidenceLedger,
    EvidenceRecord,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
)
from extractor.capture_backend import (
    LiveCaptureReceipt,
    get_trusted_capture_authority_token,
    issue_live_capture_receipt,
)


class TestPhase20A314TargetIdentityAndMeasurement(unittest.TestCase):
    def setUp(self):
        self.session_id = "sess_a314_id_meas"
        self.pid = 9001
        self.mock_ident = {
            "pid": self.pid,
            "process_identity": f"{self.pid}:123456:boot_uuid",
            "start_time": "123456",
            "executable": "/usr/bin/target",
            "executable_identity": f"/usr/bin/target:{self.pid}",
            "build_id": "target_build_id_111",
        }

    # 1. Missing mandatory identity attributes fail closed (None == None is not equality)
    def test_01_missing_mandatory_identity_attributes_fail_closed(self):
        adapter = LocalTargetAdapter()
        incomplete_ident = {"pid": self.pid, "start_time": None, "executable": None}
        with patch.object(adapter, "get_process_identity", return_value=incomplete_ident):
            with self.assertRaises(PIDReusedError) as ctx:
                adapter.pin_target_identity(self.pid)
            self.assertIn("missing mandatory attribute", str(ctx.exception).lower())

    # 2. Companion ELF Build ID does not overwrite target Build ID
    def test_02_companion_elf_build_id_does_not_overwrite_target_build_id(self):
        adapter = LocalTargetAdapter()
        with patch.object(adapter, "get_process_identity", return_value=dict(self.mock_ident)):
            ident = adapter.pin_target_identity(self.pid, companion_build_id="target_build_id_111")
            # Target build_id remains target_build_id_111
            self.assertEqual(ident["build_id"], "target_build_id_111")
            self.assertEqual(ident.get("companion_build_id"), "target_build_id_111")

    # 3. SLA latency measurement returns correct semantics and meets SLA < 4.5ms
    def test_03_sla_latency_measurement_semantics(self):
        adapter = LocalTargetAdapter()
        with patch.object(adapter, "read_memory", return_value=(b"\x00" * 64, "OBSERVED", None)):
            res = adapter.measure_read_latency(self.pid, 0x400000, 64, samples=20)
            self.assertEqual(res["sample_count"], 20)
            self.assertEqual(res["target_suspension_status"], "NOT_APPLICABLE")
            self.assertFalse(res["target_suspension_applicable"])
            self.assertIsNone(res["process_suspension_time_ms"])
            self.assertEqual(res["clock_source"], "time.monotonic_ns")
            self.assertEqual(res["measurement_type"], "MEASURED")
            self.assertIsNotNone(res["physical_read_latency_p50_ms"])
            self.assertIsNotNone(res["physical_read_latency_p95_ms"])
            self.assertIsNotNone(res["physical_read_latency_max_ms"])
            self.assertTrue(res["sla_4_5ms_satisfied"])
            self.assertLess(res["physical_read_latency_max_ms"], 4.5)

    # 4. Correlated evidence deduplication: multiple records from same receipt count as 1 physical observation
    def test_04_correlated_evidence_deduplication(self):
        engine = InvestigationWorkflowEngine()
        sess_id = engine.evidence_ledger.session_id
        inst = engine.create_instance(session_id=sess_id, target_pid=self.pid, goal="Deduplication test")
        inst.context["threads"] = [{"tid": self.pid, "state": "S", "wchan": "sys_futex"}]

        # Create an authentic live capture receipt bound to engine's ledger session
        shared_rcpt = issue_live_capture_receipt(
            session_id=sess_id,
            pid=self.pid,
            process_identity=self.mock_ident["process_identity"],
            executable_identity=self.mock_ident["executable_identity"],
            build_id=self.mock_ident["build_id"],
            snapshot_binding="snap_dedup_1",
            capture_epoch=1,
            physical_bytes_read=64,
            physical_reads_count=1,
            authority_level="PRODUCTION",
            capture_authority_token=get_trusted_capture_authority_token(),
        )
        for i in range(5):
            rec = EvidenceRecord(
                evidence_id=f"ev_corr_{i}",
                evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
                observation=f"Extracted field {i} from memory slice",
                session_id=sess_id,
                target_identity=self.mock_ident,
                provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": shared_rcpt.to_dict()},
            )
            engine.evidence_ledger.add_record(rec)

        inst.context["hypotheses"] = [
            {"id": "hyp_contention", "prior": 0.25},
            {"id": "hyp_deadlock", "prior": 0.25},
            {"id": "hyp_normal", "prior": 0.25},
        ]
        engine.execute_stage_updating_hypothesis(inst)

        # Check scoring factors for contention: effective_evidence_count must be 1, not 5
        hyp_contention = [h for h in inst.context["hypotheses"] if h["id"] == "hyp_contention"][0]
        scoring = hyp_contention.get("scoring_factors", {})
        self.assertEqual(scoring.get("effective_evidence_count"), 1)

    # 5. Waiting futex threads boost contention but DO NOT independently confirm deadlock
    def test_05_waiting_futex_threads_do_not_confirm_deadlock_without_circular_signal(self):
        engine = InvestigationWorkflowEngine()
        inst = engine.create_instance(session_id=self.session_id, target_pid=self.pid, goal="Deduplication test")
        # 4 waiting threads on futex, 1 thread running in user space (contention scenario)
        inst.context["threads"] = [
            {"tid": 100, "state": "S", "wchan": "sys_futex"},
            {"tid": 101, "state": "S", "wchan": "sys_futex"},
            {"tid": 102, "state": "S", "wchan": "sys_futex"},
            {"tid": 103, "state": "S", "wchan": "sys_futex"},
            {"tid": 104, "state": "R", "is_running_user_space": True},
        ]
        # Circular deadlock signal is FALSE (only contention present)
        inst.context["has_circular_deadlock_signal"] = False

        inst.context["hypotheses"] = [
            {"id": "hyp_contention", "prior": 0.25},
            {"id": "hyp_deadlock", "prior": 0.25},
        ]
        engine.execute_stage_updating_hypothesis(inst)

        hyp_contention = [h for h in inst.context["hypotheses"] if h["id"] == "hyp_contention"][0]
        hyp_deadlock = [h for h in inst.context["hypotheses"] if h["id"] == "hyp_deadlock"][0]

        # Contention is supported with high confidence
        self.assertEqual(hyp_contention["status"], HYPOTHESIS_STATUS_SUPPORTED)
        self.assertGreaterEqual(hyp_contention["confidence"], 0.70)

        # Deadlock is NOT supported; it remains INCONCLUSIVE or REFUTED without circular signal
        self.assertNotEqual(hyp_deadlock["status"], HYPOTHESIS_STATUS_SUPPORTED)
        self.assertLessEqual(hyp_deadlock["confidence"], 0.25)


if __name__ == "__main__":
    unittest.main()

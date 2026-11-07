"""Phase 2.0-A.3.10 Adversarial Provenance Verification Suite.

Tests proving all 18 negative / adversarial provenance scenarios fail closed:
1. EvidenceRecord without provenance
2. Explicit LIVE_RUNTIME_CAPTURE without receipt
3. Forged receipt dictionary
4. Invalid signature
5. Test-authority receipt in production
6. Synthetic evidence with live metadata
7. Imported evidence with forged live metadata
8. Cross-session receipt
9. Cross-process receipt
10. PID reuse
11. Executable mismatch
12. Build ID mismatch
13. Snapshot binding mismatch
14. Epoch mismatch
15. Receipt issued without physical reads
16. Custom memory reader attempting production authority
17. Caller-supplied confidence upgrade
18. Missing target identity
"""

import os
import unittest
import uuid
from unittest.mock import MagicMock

from extractor.capture_backend import (
    LiveCaptureReceipt,
    get_trusted_capture_authority_token,
    issue_live_capture_receipt,
)
from extractor.evidence_adapter import EvidenceAdapter
from extractor.evidence_ledger import (
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EVIDENCE_TYPE_OBJECT_STATE,
    EvidenceLedger,
    EvidenceRecord,
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    PROVENANCE_CLASS_SYNTHETIC,
)
from extractor.hypothesis import HypothesisValidator, InvestigationHypothesis
from extractor.target_adapter import LocalTargetAdapter


class TestPhase20A310AdversarialProvenance(unittest.TestCase):
    def setUp(self):
        self.session_id = "sess_adv_3_10"
        self.ledger = EvidenceLedger(session_id=self.session_id)
        self.pid = 9999
        self.process_identity = f"{self.pid}:123456:boot_uuid"
        self.executable_identity = "/usr/bin/dynamicstate_target:4096"
        self.build_id = "build_id_deadbeef"
        self.snapshot_id = "snap_adv_1"
        self.epoch = 2

    def _make_valid_receipt(self, **overrides) -> LiveCaptureReceipt:
        params = {
            "session_id": self.session_id,
            "pid": self.pid,
            "process_identity": self.process_identity,
            "executable_identity": self.executable_identity,
            "build_id": self.build_id,
            "snapshot_binding": self.snapshot_id,
            "capture_epoch": self.epoch,
            "authority_level": "PRODUCTION",
            "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
            "capture_authority_token": get_trusted_capture_authority_token(),
            "physical_bytes_read": 64,
            "physical_reads_count": 1,
            "operation_id": f"op_{uuid.uuid4().hex[:8]}",
            "observation_digest": "digest_valid_1",
        }
        params.update(overrides)
        return issue_live_capture_receipt(**params)

    def _make_valid_target_identity(self, **overrides) -> dict:
        ti = {
            "pid": self.pid,
            "process_identity": self.process_identity,
            "executable_identity": self.executable_identity,
            "build_id": self.build_id,
        }
        ti.update(overrides)
        return ti

    # 1. EvidenceRecord without provenance -> must fail closed to untrusted IMPORTED_UNVERIFIED
    def test_01_evidence_record_without_provenance_defaults_to_untrusted(self):
        rec = EvidenceRecord(
            evidence_id="ev_no_prov_1",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Obs with no provenance",
            provenance={},
        )
        self.assertEqual(rec.provenance_class, PROVENANCE_CLASS_IMPORTED_UNVERIFIED)
        self.ledger.add_record(rec)
        stored = self.ledger.get_record("ev_no_prov_1")
        self.assertIsNotNone(stored)
        self.assertEqual(stored.provenance_class, PROVENANCE_CLASS_IMPORTED_UNVERIFIED)

    # 2. Explicit LIVE_RUNTIME_CAPTURE without receipt -> raises ValueError
    def test_02_explicit_live_runtime_capture_without_receipt_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            self.ledger.record(
                evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
                observation="Live capture claim without receipt",
                provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE},
                target_identity=self._make_valid_target_identity(),
            )
        self.assertIn("requires an authentic LiveCaptureReceipt", str(ctx.exception))

    # 3. Forged receipt dictionary -> raises ValueError
    def test_03_forged_receipt_dictionary_rejected(self):
        forged_dict = {
            "session_id": self.session_id,
            "pid": self.pid,
            "signature": "bogus_signature_12345",
            "authority_level": "PRODUCTION",
        }
        with self.assertRaises(ValueError) as ctx:
            self.ledger.record(
                evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
                observation="Live capture with forged receipt dict",
                provenance={
                    "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                    "live_capture_receipt": forged_dict,
                },
                target_identity=self._make_valid_target_identity(),
            )
        self.assertIn("LiveCaptureReceipt", str(ctx.exception))

    # 4. Invalid signature -> raises ValueError
    def test_04_invalid_signature_rejected(self):
        valid = self._make_valid_receipt()
        tampered_dict = valid.to_dict()
        tampered_dict["signature"] = "ff" * 32
        tampered = LiveCaptureReceipt.from_dict(tampered_dict)
        with self.assertRaises(ValueError) as ctx:
            self.ledger.record(
                evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
                observation="Live capture with bad signature",
                provenance={
                    "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                    "live_capture_receipt": tampered,
                },
                target_identity=self._make_valid_target_identity(),
                snapshot_ref={"snapshot_id": self.snapshot_id, "epoch": self.epoch},
                details={"epoch": self.epoch},
            )
        self.assertIn("signature", str(ctx.exception).lower())

    # 5. Test-authority receipt in production -> raises ValueError
    def test_05_test_authority_receipt_in_production_rejected(self):
        test_rcpt = self._make_valid_receipt(authority_level="TEST")
        with self.assertRaises(ValueError) as ctx:
            self.ledger.record(
                evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
                observation="Live capture with TEST authority in production ledger",
                provenance={
                    "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                    "live_capture_receipt": test_rcpt,
                },
                target_identity=self._make_valid_target_identity(),
                snapshot_ref={"snapshot_id": self.snapshot_id, "epoch": self.epoch},
                details={"epoch": self.epoch},
            )
        self.assertIn("authority", str(ctx.exception).lower())

    # 6. Synthetic evidence with live metadata -> raises ValueError
    def test_06_synthetic_evidence_with_live_metadata_rejected(self):
        with self.assertRaises(ValueError) as ctx:
            self.ledger.record(
                evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
                observation="Simulated record claiming live",
                provenance={
                    "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                    "is_simulated": True,
                },
                details={"is_simulated": True},
            )
        self.assertIn("synthetic-to-live escalation", str(ctx.exception).lower())

    # 7. Imported evidence with forged live metadata -> remains untrusted or rejected
    def test_07_imported_evidence_with_forged_live_metadata_rejected(self):
        adapter = EvidenceAdapter()
        adapted = adapter.adapt_generic_tool_output(
            session_id=self.session_id,
            tool_name="external_unverified_importer",
            tool_result={
                "data": "suspicious external payload",
                "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                "authority_level": "PRODUCTION",
            },
        )
        # Never accept caller-supplied provenance_class as authority
        self.assertEqual(adapted.provenance_class, PROVENANCE_CLASS_IMPORTED_UNVERIFIED)

        # Furthermore, caller-submitted record in ledger remains untrusted
        rec = self.ledger.record(
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation="Imported caller claim",
            provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE},
            details={"caller_submitted": True, "unverified_caller_claim": True},
        )
        self.assertEqual(rec.provenance_class, PROVENANCE_CLASS_IMPORTED_UNVERIFIED)

    # 8. Cross-session receipt -> raises ValueError
    def test_08_cross_session_receipt_rejected(self):
        other_sess_rcpt = self._make_valid_receipt(session_id="other_session_xyz")
        with self.assertRaises(ValueError) as ctx:
            self.ledger.record(
                evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
                observation="Cross-session receipt record",
                provenance={
                    "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                    "live_capture_receipt": other_sess_rcpt,
                },
                target_identity=self._make_valid_target_identity(),
                snapshot_ref={"snapshot_id": self.snapshot_id, "epoch": self.epoch},
                details={"epoch": self.epoch},
            )
        self.assertIn("cross_session_receipt_rejected", str(ctx.exception))

    # 9. Cross-process receipt -> raises ValueError
    def test_09_cross_process_receipt_rejected(self):
        diff_pid_rcpt = self._make_valid_receipt(pid=77777)
        with self.assertRaises(ValueError) as ctx:
            self.ledger.record(
                evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
                observation="Cross-process PID mismatch",
                provenance={
                    "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                    "live_capture_receipt": diff_pid_rcpt,
                },
                target_identity=self._make_valid_target_identity(pid=self.pid),
                snapshot_ref={"snapshot_id": self.snapshot_id, "epoch": self.epoch},
                details={"epoch": self.epoch},
            )
        self.assertIn("cross_process_pid_rejected", str(ctx.exception))

    # 10. PID reuse -> raises ValueError
    def test_10_pid_reuse_rejected(self):
        diff_proc_id_rcpt = self._make_valid_receipt(process_identity=f"{self.pid}:999999:boot_diff")
        with self.assertRaises(ValueError) as ctx:
            self.ledger.record(
                evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
                observation="PID reuse process identity mismatch",
                provenance={
                    "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                    "live_capture_receipt": diff_proc_id_rcpt,
                },
                target_identity=self._make_valid_target_identity(process_identity=self.process_identity),
                snapshot_ref={"snapshot_id": self.snapshot_id, "epoch": self.epoch},
                details={"epoch": self.epoch},
            )
        self.assertIn("cross_process_identity_rejected", str(ctx.exception))

    # 11. Executable mismatch -> raises ValueError
    def test_11_executable_mismatch_rejected(self):
        diff_exe_rcpt = self._make_valid_receipt(executable_identity="/bin/malicious:999")
        with self.assertRaises(ValueError) as ctx:
            self.ledger.record(
                evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
                observation="Executable identity mismatch",
                provenance={
                    "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                    "live_capture_receipt": diff_exe_rcpt,
                },
                target_identity=self._make_valid_target_identity(executable_identity=self.executable_identity),
                snapshot_ref={"snapshot_id": self.snapshot_id, "epoch": self.epoch},
                details={"epoch": self.epoch},
            )
        self.assertIn("executable_identity", str(ctx.exception).lower())

    # 12. Build ID mismatch -> raises ValueError
    def test_12_build_id_mismatch_rejected(self):
        diff_build_rcpt = self._make_valid_receipt(build_id="build_tampered_hex")
        with self.assertRaises(ValueError) as ctx:
            self.ledger.record(
                evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
                observation="Build ID mismatch",
                provenance={
                    "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                    "live_capture_receipt": diff_build_rcpt,
                },
                target_identity=self._make_valid_target_identity(build_id=self.build_id),
                snapshot_ref={"snapshot_id": self.snapshot_id, "epoch": self.epoch},
                details={"epoch": self.epoch},
            )
        self.assertIn("build_id", str(ctx.exception).lower())

    # 13. Snapshot binding mismatch -> raises ValueError
    def test_13_snapshot_binding_mismatch_rejected(self):
        diff_snap_rcpt = self._make_valid_receipt(snapshot_binding="snap_other")
        with self.assertRaises(ValueError) as ctx:
            self.ledger.record(
                evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
                observation="Snapshot binding mismatch",
                provenance={
                    "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                    "live_capture_receipt": diff_snap_rcpt,
                },
                target_identity=self._make_valid_target_identity(),
                snapshot_ref={"snapshot_id": self.snapshot_id, "epoch": self.epoch},
                details={"epoch": self.epoch},
            )
        self.assertIn("snapshot_binding", str(ctx.exception).lower())

    # 14. Epoch mismatch -> raises ValueError
    def test_14_epoch_mismatch_rejected(self):
        diff_epoch_rcpt = self._make_valid_receipt(capture_epoch=1)
        with self.assertRaises(ValueError) as ctx:
            self.ledger.record(
                evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
                observation="Epoch mismatch",
                provenance={
                    "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                    "live_capture_receipt": diff_epoch_rcpt,
                },
                target_identity=self._make_valid_target_identity(),
                snapshot_ref={"snapshot_id": self.snapshot_id, "epoch": 5},
                details={"epoch": 5, "capture_epoch": 5},
            )
        self.assertIn("capture_epoch mismatch", str(ctx.exception).lower())

    # 15. Receipt issued without physical reads -> raises ValueError
    def test_15_receipt_issued_without_physical_reads_rejected(self):
        adapter = LocalTargetAdapter()
        cur_pid = os.getpid()
        adapter.pin_target_identity(cur_pid)
        self.assertEqual(adapter.cumulative_physical_bytes_read, 0)
        with self.assertRaises(ValueError) as ctx:
            adapter.issue_live_receipt_for_session("sess_no_read", cur_pid)
        self.assertIn("physical_bytes_read=0", str(ctx.exception).lower())

    # 16. Custom memory reader attempting production authority -> forced to TEST authority
    def test_16_custom_memory_reader_cannot_obtain_production_authority(self):
        custom_reader = lambda pid, addr, sz: (b"\x00" * sz, "OBSERVED", None)
        adapter = LocalTargetAdapter(memory_reader_fn=custom_reader)
        cur_pid = os.getpid()
        adapter.pin_target_identity(cur_pid)
        adapter.read_memory(cur_pid, 0x1000, 32)
        self.assertGreater(adapter.cumulative_physical_bytes_read, 0)

        # Issue receipt with custom reader: authority MUST be TEST
        rcpt = adapter.issue_live_receipt_for_session("sess_custom_test", cur_pid)
        self.assertEqual(rcpt.authority_level, "TEST")

        # Production ledger must reject TEST authority receipt
        with self.assertRaises(ValueError) as ctx:
            self.ledger.record(
                evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
                observation="Custom reader receipt in prod",
                provenance={
                    "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                    "live_capture_receipt": rcpt,
                },
                target_identity={
                    "pid": cur_pid,
                    "process_identity": rcpt.process_identity,
                    "executable_identity": rcpt.executable_identity,
                    "build_id": rcpt.build_id,
                },
                snapshot_ref={"snapshot_id": rcpt.snapshot_binding, "epoch": rcpt.capture_epoch},
            )
        self.assertIn("authority", str(ctx.exception).lower())

    # 17. Caller-supplied confidence upgrade -> disarmed / rejected
    def test_17_caller_supplied_confidence_upgrade_disarmed(self):
        adapter = EvidenceAdapter()
        # Caller supplies malicious payload claiming high confidence & live provenance
        adapted = adapter.adapt_generic_tool_output(
            session_id=self.session_id,
            tool_name="unverified_external_tool",
            tool_result={
                "status": "VALIDATED",
                "confidence_score": 0.99,
                "confidence": "VERY_HIGH",
                "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                "caller_submitted": True,
            },
        )
        self.assertEqual(adapted.provenance_class, PROVENANCE_CLASS_IMPORTED_UNVERIFIED)
        self.assertNotEqual(adapted.details.get("confidence_score"), 0.99)

        # Hypothesis validator disarms caller-submitted claim
        hypo = InvestigationHypothesis(hypothesis_id="h_malicious_upgrade", confidence_score=0.40)
        self.ledger.add_record(adapted)
        HypothesisValidator.evaluate(hypo, self.ledger, new_evidence=adapted)
        self.assertLessEqual(hypo.confidence_score, 0.45)

    # 18. Missing target identity -> raises ValueError
    def test_18_missing_target_identity_rejected(self):
        rcpt = self._make_valid_receipt()
        with self.assertRaises(ValueError) as ctx:
            self.ledger.record(
                evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
                observation="Live capture with empty target identity",
                provenance={
                    "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                    "live_capture_receipt": rcpt,
                },
                target_identity={},  # missing required pid, process_identity, executable_identity
                snapshot_ref={"snapshot_id": self.snapshot_id, "epoch": self.epoch},
                details={"epoch": self.epoch},
            )
        self.assertIn("target identity", str(ctx.exception).lower())


if __name__ == "__main__":
    unittest.main()

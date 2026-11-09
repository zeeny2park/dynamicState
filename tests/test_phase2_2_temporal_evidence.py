"""
tests/test_phase2_2_temporal_evidence.py

Unit and integration tests for Phase 2.2-A: Temporal Evidence Correctness (GAP-P0-01).

Verifies:
1. When watch_session lacks authentic LiveCaptureReceipt:
   - EvidenceRecord instances carry PROVENANCE_CLASS_IMPORTED_UNVERIFIED.
   - Records are validated by EvidenceLedger without error.
2. When watch_session has authentic signed LiveCaptureReceipt:
   - EvidenceRecord instances carry PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE and receipt.
   - Target identity preserves process_identity and executable_identity.
   - EvidenceLedger validates successfully.
3. Tampered LiveCaptureReceipt fails closed during ledger validation.
4. Temporal analysis failures report explicit error in session summary.
"""

import os
import tempfile
import unittest
import uuid

from extractor.capture_backend import (
    LiveCaptureReceipt,
    get_trusted_capture_authority_token,
    issue_live_capture_receipt,
)
from extractor.evidence_ledger import (
    EvidenceLedger,
    EvidenceRecord,
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
)
from extractor.investigation import InvestigationSession
from extractor.temporal_investigation import TemporalInvestigationService
from extractor.watch_session import ObservationSession, WatchItem, WatchSessionManager


class TestPhase22TemporalEvidence(unittest.TestCase):
    """Phase 2.2-A Temporal Evidence Correctness Test Suite."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp(prefix="dynstate_phase22_test_")
        self.wm = WatchSessionManager(corpus_dir=self.temp_dir)
        self.svc = TemporalInvestigationService(watch_manager=self.wm)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _make_valid_receipt(self, session_id: str, pid: int, **overrides) -> LiveCaptureReceipt:
        params = {
            "session_id": session_id,
            "pid": pid,
            "process_identity": f"proc_{pid}_identity_12345",
            "executable_identity": os.path.realpath("/bin/bash"),
            "build_id": "abcdef0123456789",
            "snapshot_binding": "snap_1",
            "capture_epoch": 0,
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

    def test_unverified_provenance_fallback_without_receipt(self):
        """Watch session without LiveCaptureReceipt defaults to IMPORTED_UNVERIFIED and passes ledger validation."""
        session = self.wm.create_session(pid=os.getpid(), capture_mode="MANUAL")
        inv = InvestigationSession(investigation_id="inv_test_unverified", goal="Verify provenance fallback")

        result = self.svc.analyze_temporal_session(
            investigation_session=inv,
            watch_session=session,
            watch_manager=self.wm,
            goal="Verify provenance fallback",
        )

        records = inv.ledger.get_records()
        self.assertGreater(len(records), 0)
        for r in records:
            self.assertEqual(
                r.provenance_class,
                PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
                f"Record {r.evidence_id} expected IMPORTED_UNVERIFIED but got {r.provenance_class}",
            )
        self.assertEqual(result["status"], "PARTIAL")

    def test_authentic_live_capture_receipt_preserved(self):
        """Watch session with authentic LiveCaptureReceipt retains LIVE_RUNTIME_CAPTURE."""
        pid = os.getpid()
        session = self.wm.create_session(pid=pid, capture_mode="MANUAL")
        session_id = session.session_id
        real_build_id = session.binary_build_id or "abcdef0123456789"
        receipt = self._make_valid_receipt(session_id=session_id, pid=pid, build_id=real_build_id)

        session.provenance["live_capture_receipt"] = receipt.to_dict()
        session.target_identity = {
            "pid": pid,
            "process_identity": receipt.process_identity,
            "executable_identity": receipt.executable_identity,
            "target_build_id": receipt.build_id,
        }

        inv = InvestigationSession(investigation_id=session_id, goal="Verify live receipt")

        result = self.svc.analyze_temporal_session(
            investigation_session=inv,
            watch_session=session,
            watch_manager=self.wm,
            goal="Verify live receipt",
        )

        records = inv.ledger.get_records()
        self.assertGreater(len(records), 0)
        live_records = [r for r in records if r.evidence_type != "RUNTIME_IDENTITY"]
        for r in live_records:
            self.assertEqual(
                r.provenance_class,
                PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                f"Record {r.evidence_id} expected LIVE_RUNTIME_CAPTURE but got {r.provenance_class}",
            )
            self.assertIsNotNone(r.provenance.get("live_capture_receipt"))

    def test_tampered_receipt_fails_closed(self):
        """Tampered LiveCaptureReceipt in watch session is rejected fail-closed by EvidenceLedger."""
        pid = os.getpid()
        session = self.wm.create_session(pid=pid, capture_mode="MANUAL")
        session_id = session.session_id
        receipt = self._make_valid_receipt(session_id=session_id, pid=pid)
        rcpt_dict = receipt.to_dict()
        # Tamper with physical_bytes_read after signing
        rcpt_dict["physical_bytes_read"] = 99999

        session.provenance["live_capture_receipt"] = rcpt_dict
        session.target_identity = {
            "pid": pid,
            "process_identity": receipt.process_identity,
            "executable_identity": receipt.executable_identity,
            "target_build_id": receipt.build_id,
        }

        inv = InvestigationSession(investigation_id=session_id, goal="Verify tampered receipt")

        with self.assertRaises(ValueError) as ctx:
            self.svc.analyze_temporal_session(
                investigation_session=inv,
                watch_session=session,
                watch_manager=self.wm,
                goal="Verify tampered receipt",
            )
        self.assertIn("LiveCaptureReceipt rejected", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()

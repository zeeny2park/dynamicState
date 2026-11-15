"""Tests for Competing Hypotheses Admission and Contradiction Invariants (US-DIAG-001 / FR-DIAG-002)."""

import unittest
from extractor.competing_hypotheses import CompetingHypothesis
from extractor.evidence_ledger import (
    EvidenceAdmissionState,
    EvidenceLedger,
    EvidenceRecord,
)


class TestCompetingHypothesesInvariants(unittest.TestCase):
    def test_rejected_or_quarantined_evidence_is_not_authoritative(self):
        """Verify that records in REJECTED or QUARANTINED state cannot be authoritative in hypotheses."""
        ledger = EvidenceLedger()

        rec_rejected = EvidenceRecord(
            evidence_id="ev_rej_01",
            observation="Corrupted state diff",
            admission_state=EvidenceAdmissionState.REJECTED,
            admission_reason="Signature verification failed",
        )
        rec_quarantined = EvidenceRecord(
            evidence_id="ev_quar_01",
            observation="Orphan observation",
            admission_state=EvidenceAdmissionState.QUARANTINED,
            admission_reason="Dangling parent reference",
        )
        ledger.add_record(rec_rejected)
        ledger.add_record(rec_quarantined)

        hyp = CompetingHypothesis(
            hypothesis_id="hyp-01",
            category="DEADLOCK",
            title="Test hypothesis",
            ledger=ledger,
        )

        res_rej = hyp._validate_evidence_record_authority(rec_rejected.evidence_id, rec_rejected, eff_ledger=ledger)
        self.assertFalse(res_rej["is_authoritative"])
        self.assertEqual(res_rej["status"], "RECORD_REJECTED")

        res_quar = hyp._validate_evidence_record_authority(rec_quarantined.evidence_id, rec_quarantined, eff_ledger=ledger)
        self.assertFalse(res_quar["is_authoritative"])
        self.assertEqual(res_quar["status"], "RECORD_QUARANTINED")

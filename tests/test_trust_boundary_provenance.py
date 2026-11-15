"""Tests for Provenance Lineage and Quarantine Isolation (US-TRUST-006 / FR-TRUST-006)."""

import pytest
from extractor.evidence_ledger import (
    EvidenceAdmissionState,
    EvidenceLedger,
    EvidenceRecord,
)


def test_dangling_parent_evidence_is_quarantined():
    """Verify record referencing non-existent parent is quarantined when requested."""
    ledger = EvidenceLedger()
    rec = EvidenceRecord(
        observation="Derived state change",
        parent_evidence_ids=["ev_non_existent_99999"],
    )
    ledger.add_record(rec, quarantine_dangling=True)

    # When evaluating admission or checking eligible evidence
    eligible = ledger.get_eligible_evidence()
    assert rec not in eligible

    stored = ledger.get_record(rec.evidence_id)
    assert stored is not None
    assert stored.admission_state == EvidenceAdmissionState.QUARANTINED
    assert "parent" in (stored.admission_reason or "").lower()


def test_dangling_parent_without_quarantine_flag_raises_error():
    """Verify default add_record rejects dangling parents fail-closed."""
    ledger = EvidenceLedger()
    rec = EvidenceRecord(
        observation="Unquarantined dangling record",
        parent_evidence_ids=["ev_non_existent_99999"],
    )
    with pytest.raises(ValueError, match="nonexistent parent record"):
        ledger.add_record(rec)


def test_valid_parent_provenance_is_accepted_when_parent_exists():
    """Verify child record referencing valid existing parent can be accepted."""
    ledger = EvidenceLedger()
    parent = EvidenceRecord(
        observation="Parent raw snapshot",
        admission_state=EvidenceAdmissionState.ACCEPTED,
    )
    ledger.add_record(parent)

    child = EvidenceRecord(
        observation="Derived finding",
        parent_evidence_ids=[parent.evidence_id],
        admission_state=EvidenceAdmissionState.ACCEPTED,
    )
    ledger.add_record(child)

    eligible = ledger.get_eligible_evidence()
    assert parent in eligible
    assert child in eligible

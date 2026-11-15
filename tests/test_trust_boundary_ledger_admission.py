"""Tests for Evidence Ledger Admission Boundaries (US-TRUST-004 / FR-TRUST-004)."""

import pytest
from extractor.evidence_ledger import (
    EvidenceAdmissionState,
    EvidenceLedger,
    EvidenceRecord,
)


def test_evidence_admission_states_enum_exists():
    """Verify all 5 required admission states exist."""
    assert EvidenceAdmissionState.ACCEPTED.value == "ACCEPTED"
    assert EvidenceAdmissionState.REJECTED.value == "REJECTED"
    assert EvidenceAdmissionState.QUARANTINED.value == "QUARANTINED"
    assert EvidenceAdmissionState.NOT_COVERED.value == "NOT_COVERED"
    assert EvidenceAdmissionState.PARTIAL.value == "PARTIAL"


def test_get_eligible_evidence_returns_only_accepted_records():
    """Verify get_eligible_evidence strictly filters out non-ACCEPTED records."""
    ledger = EvidenceLedger()

    rec_accepted = EvidenceRecord(
        observation="Verified CPU hotspot",
        admission_state=EvidenceAdmissionState.ACCEPTED,
    )
    rec_rejected = EvidenceRecord(
        observation="Tampered memory observation",
        admission_state=EvidenceAdmissionState.REJECTED,
        admission_reason="Invalid cryptographic signature",
    )
    rec_quarantined = EvidenceRecord(
        observation="Missing provenance metadata",
        admission_state=EvidenceAdmissionState.QUARANTINED,
        admission_reason="Dangling parent reference",
    )
    rec_not_covered = EvidenceRecord(
        observation="Unverified heuristic",
        admission_state=EvidenceAdmissionState.NOT_COVERED,
    )
    rec_partial = EvidenceRecord(
        observation="Partial field read",
        admission_state=EvidenceAdmissionState.PARTIAL,
    )

    for r in [rec_accepted, rec_rejected, rec_quarantined, rec_not_covered, rec_partial]:
        ledger.add_record(r)

    eligible = ledger.get_eligible_evidence()
    assert len(eligible) == 1
    assert eligible[0].evidence_id == rec_accepted.evidence_id
    assert eligible[0].admission_state == EvidenceAdmissionState.ACCEPTED


def test_get_audit_trail_preserves_all_evidence_with_reasons():
    """Verify get_audit_trail returns all evidence including rejected/quarantined."""
    ledger = EvidenceLedger()

    rec_accepted = EvidenceRecord(
        observation="Verified metric",
        admission_state=EvidenceAdmissionState.ACCEPTED,
    )
    rec_rejected = EvidenceRecord(
        observation="Manipulated value",
        admission_state=EvidenceAdmissionState.REJECTED,
        admission_reason="Hash mismatch",
    )

    ledger.add_record(rec_accepted)
    ledger.add_record(rec_rejected)

    audit_trail = ledger.get_audit_trail()
    assert len(audit_trail) == 2
    ids = {r.evidence_id for r in audit_trail}
    assert rec_accepted.evidence_id in ids
    assert rec_rejected.evidence_id in ids

    rejected_in_audit = next(r for r in audit_trail if r.evidence_id == rec_rejected.evidence_id)
    assert rejected_in_audit.admission_reason == "Hash mismatch"

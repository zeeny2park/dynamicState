"""Helpers for unit tests that start after the ledger admission boundary."""

from extractor.evidence_ledger import (
    EvidenceAdmissionState,
    PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
    compute_evidence_fingerprint,
)


def add_admitted_fixture(ledger, record):
    """Model a controlled fixture after its upstream verifier admitted it.

    Do not use this helper in tests of ledger admission, provenance validation,
    or production capture paths. The record is first added as ordinary
    imported evidence, then promoted in memory to represent a verified ledger
    result. Production promotion must use the real receipt/attestation path.
    """
    admitted = ledger.get_record(record.evidence_id)
    if admitted is None:
        admitted = ledger.add_record(record)
    admitted.provenance = dict(admitted.provenance or {})
    admitted.provenance["provenance_class"] = PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION
    admitted.admission_state = EvidenceAdmissionState.ACCEPTED
    # Keep fixture lineage hashes consistent with the simulated upstream
    # admission metadata change.
    for child in ledger.records:
        if admitted.evidence_id not in (child.parent_evidence_ids or []):
            continue
        digest = compute_evidence_fingerprint(admitted)
        child.details = dict(child.details or {})
        child.details.setdefault("parent_evidence_digests", {})[admitted.evidence_id] = digest
        if len(child.parent_evidence_ids or []) == 1:
            child.details["parent_evidence_digest"] = digest
    return admitted

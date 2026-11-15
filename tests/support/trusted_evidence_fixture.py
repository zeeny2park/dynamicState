"""Helpers for unit tests that start after the ledger admission boundary."""

from extractor.evidence_ledger import (
    EvidenceAdmissionState,
    PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
)


def add_admitted_fixture(ledger, record):
    """Model a controlled fixture after its upstream verifier admitted it.

    Do not use this helper in tests of ledger admission, provenance validation,
    or production capture paths. The record is first added as ordinary
    imported evidence, then promoted in memory to represent a verified ledger
    result. Production promotion must use the real receipt/attestation path.
    """
    ledger.add_record(record)
    admitted = ledger.get_record(record.evidence_id)
    admitted.provenance = dict(admitted.provenance or {})
    admitted.provenance["provenance_class"] = PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION
    admitted.admission_state = EvidenceAdmissionState.ACCEPTED
    return admitted

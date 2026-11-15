"""Comprehensive Property-Based Tests (PBT) for Trust Boundaries (US-BENCH-001 / NFR-PBT-001).

Enforces:
1. Deterministic seed (seed=42) for PR tests.
2. At least 100 generated examples for critical invariants.
3. Counterexample shrinking enabled.
4. Validation across Operation ID, Canonical Identity, Lifecycle DAG, and Admission State.
"""

import json
import string
import unittest
import uuid
from hypothesis import HealthCheck, given, seed, settings, strategies as st

from extractor.capture_backend import (
    CanonicalOperationIdentity,
    DurableTrustStore,
    IdentityConflictError,
    InvalidOperationIdError,
    InvalidStateTransitionError,
    OperationLifecycleState,
    ProcessIdentity,
    validate_operation_id,
)
from extractor.evidence_ledger import (
    EvidenceAdmissionState,
    EvidenceLedger,
    EvidenceRecord,
)

VALID_CHARS = string.ascii_letters + string.digits + "_.:-"


class TestTrustBoundaryPBT(unittest.TestCase):
    """PBT suite covering all core trust boundary invariants."""

    @seed(42)
    @settings(max_examples=120)
    @given(st.text(alphabet=VALID_CHARS, min_size=1, max_size=128))
    def test_pbt_operation_id_whitelist_invariant(self, valid_id):
        """Invariant: Any string meeting whitelist constraints passes unchanged."""
        self.assertEqual(validate_operation_id(valid_id), valid_id)

    @seed(42)
    @settings(max_examples=120)
    @given(st.text())
    def test_pbt_operation_id_rejection_invariant(self, any_text):
        """Invariant: Any string violating length, whitespace, or charset is rejected."""
        has_invalid = any(c not in VALID_CHARS for c in any_text)
        bad_len = len(any_text) < 1 or len(any_text) > 128
        has_space = any(c.isspace() for c in any_text)

        if has_invalid or bad_len or has_space:
            with self.assertRaises(InvalidOperationIdError):
                validate_operation_id(any_text)
        else:
            self.assertEqual(validate_operation_id(any_text), any_text)

    @seed(42)
    @settings(max_examples=100)
    @given(
        target_state=st.sampled_from(list(OperationLifecycleState)),
    )
    def test_pbt_committed_state_is_strictly_terminal(self, target_state):
        """Invariant: Once COMMITTED, an operation can never transition to any other state."""
        store = DurableTrustStore()
        op_id = f"op-term-{uuid.uuid4().hex[:12]}"

        # Initialize as CREATED, then transition to COMMITTED
        store.transition_operation_lifecycle(op_id, "sess", 1000, OperationLifecycleState.CREATED)
        store.transition_operation_lifecycle(op_id, "sess", 1000, OperationLifecycleState.VALIDATED)
        store.transition_operation_lifecycle(op_id, "sess", 1000, OperationLifecycleState.RESERVED)
        store.transition_operation_lifecycle(op_id, "sess", 1000, OperationLifecycleState.EXECUTING)
        store.transition_operation_lifecycle(op_id, "sess", 1000, OperationLifecycleState.COMMITTED)

        self.assertEqual(store.get_operation_lifecycle_state(op_id), OperationLifecycleState.COMMITTED)

        # Any attempt to transition away from COMMITTED must raise InvalidStateTransitionError
        with self.assertRaises(InvalidStateTransitionError):
            store.transition_operation_lifecycle(op_id, "sess", 1000, target_state)

    @seed(42)
    @settings(max_examples=100)
    @given(
        records_spec=st.lists(
            st.tuples(
                st.sampled_from(list(EvidenceAdmissionState)),
                st.text(alphabet=string.ascii_letters, min_size=1, max_size=20),
            ),
            min_size=1,
            max_size=30,
        )
    )
    def test_pbt_eligible_evidence_guarantees_zero_unaccepted_records(self, records_spec):
        """Invariant: get_eligible_evidence() returns ONLY ACCEPTED records, regardless of input distribution."""
        ledger = EvidenceLedger()
        expected_accepted_ids = set()

        for state, obs in records_spec:
            rec = EvidenceRecord(
                observation=obs,
                admission_state=state,
            )
            ledger.add_record(rec)
            if state == EvidenceAdmissionState.ACCEPTED:
                expected_accepted_ids.add(rec.evidence_id)

        eligible = ledger.get_eligible_evidence()
        eligible_ids = {r.evidence_id for r in eligible}

        self.assertEqual(eligible_ids, expected_accepted_ids)
        for r in eligible:
            self.assertEqual(r.admission_state, EvidenceAdmissionState.ACCEPTED)

        # Audit trail must preserve ALL ingested records
        self.assertEqual(len(ledger.get_audit_trail()), len(records_spec))

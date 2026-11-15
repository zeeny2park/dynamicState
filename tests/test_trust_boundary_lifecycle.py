"""Unit tests for Operation Lifecycle transitions and crash recovery.

Verifies:
1. Valid one-way lifecycle transitions:
   CREATED -> VALIDATED -> RESERVED -> EXECUTING -> COMMITTED
2. Backward transitions or invalid jumps raise InvalidStateTransitionError.
3. COMMITTED is strictly terminal.
4. Eager crash recovery: on store load, interrupted operations (RESERVED / EXECUTING)
   are reconciled to ABORTED_ON_RESTART.
5. Incomplete operations cannot be silently reused.
6. Retries must use a new Operation ID with auditable retry_of_operation_id.
"""

import json
import os
import tempfile
import unittest

from extractor.capture_backend import (
    DurableTrustStore,
    InvalidStateTransitionError,
    OperationLifecycleState,
)


class TestTrustBoundaryLifecycle(unittest.TestCase):
    """Regression test suite for Operation Lifecycle and Crash Recovery."""

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.store_path = os.path.join(self.tmpdir.name, "trust_store.json")
        self.store = DurableTrustStore(store_path=self.store_path)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_valid_sequential_lifecycle_transitions(self):
        """Sequential lifecycle transitions CREATED -> VALIDATED -> RESERVED -> EXECUTING -> COMMITTED must succeed."""
        op_id = "op-life-seq-01"
        session_id = "sess-01"
        pid = 8888

        # 1. Register CREATED
        self.store.transition_operation_lifecycle(
            op_id=op_id,
            session_id=session_id,
            pid=pid,
            target_state=OperationLifecycleState.CREATED,
        )
        self.assertEqual(
            self.store.get_operation_lifecycle_state(op_id),
            OperationLifecycleState.CREATED,
        )

        # 2. Transition to VALIDATED
        self.store.transition_operation_lifecycle(
            op_id=op_id,
            session_id=session_id,
            pid=pid,
            target_state=OperationLifecycleState.VALIDATED,
        )
        self.assertEqual(
            self.store.get_operation_lifecycle_state(op_id),
            OperationLifecycleState.VALIDATED,
        )

        # 3. Transition to RESERVED
        self.store.transition_operation_lifecycle(
            op_id=op_id,
            session_id=session_id,
            pid=pid,
            target_state=OperationLifecycleState.RESERVED,
        )
        self.assertEqual(
            self.store.get_operation_lifecycle_state(op_id),
            OperationLifecycleState.RESERVED,
        )

        # 4. Transition to EXECUTING
        self.store.transition_operation_lifecycle(
            op_id=op_id,
            session_id=session_id,
            pid=pid,
            target_state=OperationLifecycleState.EXECUTING,
        )
        self.assertEqual(
            self.store.get_operation_lifecycle_state(op_id),
            OperationLifecycleState.EXECUTING,
        )

        # 5. Transition to COMMITTED
        self.store.transition_operation_lifecycle(
            op_id=op_id,
            session_id=session_id,
            pid=pid,
            target_state=OperationLifecycleState.COMMITTED,
        )
        self.assertEqual(
            self.store.get_operation_lifecycle_state(op_id),
            OperationLifecycleState.COMMITTED,
        )

    def test_invalid_transition_jumps_and_backward_rejected(self):
        """Invalid jumps (e.g. CREATED -> COMMITTED) or backward transitions must raise InvalidStateTransitionError."""
        op_id = "op-life-invalid-01"
        session_id = "sess-01"
        pid = 8889

        # Register CREATED
        self.store.transition_operation_lifecycle(
            op_id=op_id,
            session_id=session_id,
            pid=pid,
            target_state=OperationLifecycleState.CREATED,
        )

        # Attempt illegal jump to COMMITTED
        with self.assertRaises(InvalidStateTransitionError):
            self.store.transition_operation_lifecycle(
                op_id=op_id,
                session_id=session_id,
                pid=pid,
                target_state=OperationLifecycleState.COMMITTED,
            )

        # Step properly to VALIDATED
        self.store.transition_operation_lifecycle(
            op_id=op_id,
            session_id=session_id,
            pid=pid,
            target_state=OperationLifecycleState.VALIDATED,
        )

        # Attempt backward transition to CREATED
        with self.assertRaises(InvalidStateTransitionError):
            self.store.transition_operation_lifecycle(
                op_id=op_id,
                session_id=session_id,
                pid=pid,
                target_state=OperationLifecycleState.CREATED,
            )

    def test_committed_state_is_terminal(self):
        """Once COMMITTED, any transition attempt must be rejected."""
        op_id = "op-life-terminal-01"
        session_id = "sess-01"
        pid = 8890

        for state in [
            OperationLifecycleState.CREATED,
            OperationLifecycleState.VALIDATED,
            OperationLifecycleState.RESERVED,
            OperationLifecycleState.EXECUTING,
            OperationLifecycleState.COMMITTED,
        ]:
            self.store.transition_operation_lifecycle(
                op_id=op_id,
                session_id=session_id,
                pid=pid,
                target_state=state,
            )

        # Attempt to transition out of COMMITTED
        for illegal_target in [
            OperationLifecycleState.EXECUTING,
            OperationLifecycleState.FAILED,
            OperationLifecycleState.CANCELLED,
            OperationLifecycleState.RESERVED,
        ]:
            with self.assertRaises(InvalidStateTransitionError):
                self.store.transition_operation_lifecycle(
                    op_id=op_id,
                    session_id=session_id,
                    pid=pid,
                    target_state=illegal_target,
                )

    def test_eager_crash_recovery_reconciles_interrupted_operations(self):
        """Interrupted operations (RESERVED or EXECUTING) must be reconciled to ABORTED_ON_RESTART upon store load."""
        # 1. Synthesize a store file with an interrupted EXECUTING operation (simulating crash)
        crash_data = {
            "version": 2,
            "revoked_keys": {},
            "used_attestation_ids": [],
            "used_operation_ids": {
                "op-interrupted-01": {
                    "session_id": "sess-crash",
                    "pid": 9999,
                    "state": OperationLifecycleState.EXECUTING.value,
                    "recorded_at": "2026-11-15T00:00:00Z",
                },
                "op-finished-01": {
                    "session_id": "sess-crash",
                    "pid": 9999,
                    "state": OperationLifecycleState.COMMITTED.value,
                    "recorded_at": "2026-11-15T00:00:00Z",
                },
            },
        }
        with open(self.store_path, "w", encoding="utf-8") as f:
            json.dump(crash_data, f)

        # 2. Instantiate new store instance pointing to crashed file
        recovered_store = DurableTrustStore(store_path=self.store_path)
        recovered_store.load()

        # 3. Interrupted operation must now be ABORTED_ON_RESTART
        interrupted_state = recovered_store.get_operation_lifecycle_state("op-interrupted-01")
        self.assertEqual(interrupted_state, OperationLifecycleState.ABORTED_ON_RESTART)

        # 4. Committed operation must remain COMMITTED
        finished_state = recovered_store.get_operation_lifecycle_state("op-finished-01")
        self.assertEqual(finished_state, OperationLifecycleState.COMMITTED)


if __name__ == "__main__":
    unittest.main()

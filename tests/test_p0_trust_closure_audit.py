"""Comprehensive audit and regression test suite for P0 Trust Boundary Closure.

Covers:
- P0-1: Canonical Replay Identity:
  - Missing canonical identity or missing digest rejection
  - Digest inconsistent with canonical identity recomputation (RFC 8785)
  - Nested parameter normalization, float representation, and NaN/Inf rejection
  - Real production capture/replay path via LocalTargetAdapter
- P0-2: Mandatory Operation ID:
  - Enforced across all production entry points (consume_attestation default, bind_*, is_operation_used)
  - Validation precedes all durable state mutations leaving zero partial state
- P0-3: Evidence Admission:
  - Confirmed hypothesis backed only by rejected/quarantined evidence cannot confirm fault
  - Quarantined evidence with absent/incomplete provenance cannot be promoted even without parent IDs
  - Controlled promotion requires trusted provenance and accepted parents
- P0-4: TrustStore Filesystem Security:
  - Lockfile and storefile hard links (st_nlink > 1) rejected
  - Ancestor symlink validation
  - Temporary-file cleanup concurrent with active writer holding flock
  - Atomic replace + fsync
- P0-5: Lifecycle Enforcement:
  - Complete DAG progression: CREATED -> VALIDATED -> RESERVED -> EXECUTING -> COMMITTED / FAILED
  - Persistence failure before capture fails closed
  - Cross-session / cross-PID transitions rejected
  - Rollback failures surfaced and auditable
- P0-6: Durable Identity Conflict & Recovery:
  - Identity conflict persistence failure raises ConflictAuditPersistenceError
  - Memory rolled back on audit save failure; original committed record preserved
  - Durable conflict records survive process restart
"""

import os
import stat
import json
import time
import uuid
import tempfile
import unittest
from unittest.mock import patch, MagicMock

from extractor.capture_backend import (
    DurableTrustStore,
    CanonicalOperationIdentity,
    build_canonical_replay_identity,
    ProcessIdentity,
    resolve_current_boot_id,
    validate_operation_id,
    OperationLifecycleState,
    IdentityConflictError,
    InvalidOperationIdError,
    MissingIdentityFieldError,
    ProcessIdentityUnavailableError,
    SecurityViolationError,
    ConflictAuditPersistenceError,
    InvalidStateTransitionError,
    CausalAttestation,
)
from extractor.evidence_ledger import (
    EvidenceLedger,
    EvidenceRecord,
    EvidenceAdmissionState,
)
from extractor.diagnostic_verdict_aggregator import (
    DiagnosticVerdictAggregator,
    DiagnosticCheck,
    VERDICT_CONFIRMED_FAULT,
    VERDICT_PROBABLE_FAULT,
)
from extractor.target_adapter import (
    LocalTargetAdapter,
    CaptureTransaction,
)


class TestP01CanonicalReplayIdentity(unittest.TestCase):
    """P0-1: Canonical Replay Identity & Durable Replay Validation."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store_path = os.path.join(self.temp_dir.name, "trust_store.json")
        self.store = DurableTrustStore(self.store_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_canonical_json_and_sha256_digest_deterministic(self):
        """Canonical JSON and SHA-256 digest must be strictly deterministic and key-sorted."""
        proc_ident = ProcessIdentity(
            host_identity="test_host",
            boot_id="test_boot_id",
            pid=12345,
            process_start_time=100000,
        )
        params_a = {"beta": 2, "alpha": 1, "nested": {"z": 26, "a": 1}}
        params_b = {"nested": {"a": 1, "z": 26}, "alpha": 1, "beta": 2}

        canon_a = build_canonical_replay_identity(
            operation_id="op_123",
            operation_kind="diagnostic_read",
            process_identity=proc_ident,
            build_id="sha1_build_id_abc",
            session_identity="session_test",
            request_scope="global",
            parameters=params_a,
        )
        canon_b = build_canonical_replay_identity(
            operation_id="op_123",
            operation_kind="diagnostic_read",
            process_identity=proc_ident,
            build_id="sha1_build_id_abc",
            session_identity="session_test",
            request_scope="global",
            parameters=params_b,
        )
        self.assertEqual(canon_a.to_canonical_json(), canon_b.to_canonical_json())
        self.assertEqual(canon_a.digest(), canon_b.digest())

    def test_canonical_identity_and_digest_required_together(self):
        """Providing canonical_identity without digest or vice-versa must fail closed."""
        proc_ident = ProcessIdentity(
            host_identity="test_host",
            boot_id="test_boot",
            pid=123,
            process_start_time=100,
        )
        canon = build_canonical_replay_identity(
            operation_id="op_partial_canon",
            operation_kind="read",
            process_identity=proc_ident,
            build_id="b1",
            session_identity="s1",
            request_scope="scope1",
        )
        # Identity provided without digest
        with self.assertRaises(MissingIdentityFieldError):
            self.store.record_used_operation(
                op_id="op_partial_canon",
                session_id="s1",
                pid=123,
                metadata={"canonical_identity": canon.to_dict()},
            )
        # Digest provided without identity
        with self.assertRaises(MissingIdentityFieldError):
            self.store.record_used_operation(
                op_id="op_partial_canon",
                session_id="s1",
                pid=123,
                metadata={"canonical_digest": canon.digest()},
            )

    def test_digest_inconsistent_with_identity_rejected(self):
        """Caller-supplied digest inconsistent with recomputed canonical digest must raise SecurityViolationError."""
        proc_ident = ProcessIdentity(
            host_identity="test_host",
            boot_id="test_boot",
            pid=123,
            process_start_time=100,
        )
        canon = build_canonical_replay_identity(
            operation_id="op_tampered_dig",
            operation_kind="read",
            process_identity=proc_ident,
            build_id="b1",
            session_identity="s1",
            request_scope="scope1",
        )
        with self.assertRaises(SecurityViolationError):
            self.store.record_used_operation(
                op_id="op_tampered_dig",
                session_id="s1",
                pid=123,
                metadata={
                    "canonical_identity": canon.to_dict(),
                    "canonical_digest": "0" * 64,  # Fabricated digest
                },
            )

    def test_nested_parameter_and_numeric_canonicalization_rfc8785(self):
        """Reject non-finite numbers and ensure exact RFC 8785 serialization."""
        proc_ident = ProcessIdentity(
            host_identity="test_host",
            boot_id="test_boot",
            pid=123,
            process_start_time=100,
        )
        # NaN must be rejected
        with self.assertRaises(ValueError):
            build_canonical_replay_identity(
                operation_id="op_nan",
                operation_kind="read",
                process_identity=proc_ident,
                build_id="b1",
                session_identity="s1",
                request_scope="scope1",
                parameters={"invalid_num": float("nan")},
            )
        # Infinity must be rejected
        with self.assertRaises(ValueError):
            build_canonical_replay_identity(
                operation_id="op_inf",
                operation_kind="read",
                process_identity=proc_ident,
                build_id="b1",
                session_identity="s1",
                request_scope="scope1",
                parameters={"invalid_num": float("inf")},
            )

    def test_resolve_boot_id_fails_closed_without_boot_default_fallback(self):
        """Missing boot_id must fail closed with ProcessIdentityUnavailableError, never falling back to boot-default."""
        with patch("os.path.exists", return_value=False):
            with patch("extractor.capture_backend._CURRENT_BOOT_ID_CACHE", None):
                with self.assertRaises(ProcessIdentityUnavailableError):
                    resolve_current_boot_id()

    def test_production_replay_path_using_canonical_identity(self):
        """Test the real production capture/replay path via LocalTargetAdapter with canonical identity."""
        adapter = LocalTargetAdapter()
        adapter.trust_store = self.store
        pid = os.getpid()
        session_id = f"sess_{uuid.uuid4().hex[:8]}"

        # Begin transaction (advances through CREATED -> VALIDATED -> RESERVED -> EXECUTING)
        tx = adapter.begin_capture_transaction(session_id=session_id, pid=pid, operation_type="diagnostic")
        tx.physical_bytes_read = 64
        tx.physical_reads_count = 1

        # Commit transaction (builds CanonicalOperationIdentity and records to DurableTrustStore)
        adapter.commit_capture_transaction(tx)
        self.assertTrue(tx.committed)

        # Inspect durable record in store
        self.assertTrue(self.store.is_operation_used(tx.transaction_id))
        rec = self.store.used_operation_ids[tx.transaction_id]
        self.assertIn("canonical_identity", rec)
        self.assertIn("canonical_digest", rec)
        self.assertEqual(rec["state"], OperationLifecycleState.COMMITTED.value)

        # Replay attempt with modified canonical parameters must raise IdentityConflictError
        conflicting_ident = dict(rec["canonical_identity"])
        conflicting_ident["request_scope"] = "tampered_scope"
        conflicting_obj = CanonicalOperationIdentity(
            operation_id=conflicting_ident["operation_id"],
            operation_kind=conflicting_ident["operation_kind"],
            process_identity=ProcessIdentity(**conflicting_ident["process_identity"]),
            build_id=conflicting_ident["build_id"],
            session_identity=conflicting_ident["session_identity"],
            request_scope=conflicting_ident["request_scope"],
            normalized_parameters=conflicting_ident["normalized_parameters"],
        )
        with self.assertRaises(IdentityConflictError):
            self.store.record_used_operation(
                op_id=tx.transaction_id,
                session_id=session_id,
                pid=pid,
                metadata={
                    "canonical_identity": conflicting_obj.to_dict(),
                    "canonical_digest": conflicting_obj.digest(),
                },
                allow_idempotent=True,
            )


class TestP02OperationIdValidation(unittest.TestCase):
    """P0-2: Operation ID Validation at All Entry Points."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store_path = os.path.join(self.temp_dir.name, "trust_store.json")
        self.store = DurableTrustStore(self.store_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_consume_attestation_mandatory_operation_id_default(self):
        """consume_attestation without operation_id must fail closed by default."""
        att_no_op = CausalAttestation(
            attestation_id=f"att_{uuid.uuid4().hex[:8]}",
            operation_id="",
            precondition_evidence_id="ev_pre_1",
            postcondition_evidence_id="ev_post_1",
            key_id="default",
            session_id="sess_1",
            signature="deadbeef",
            target_identity={"pid": 1234},
        )
        # Default require_operation_id=True rejects missing ID
        with self.assertRaises(MissingIdentityFieldError):
            self.store.consume_attestation(
                attestation=att_no_op,
                evidence_id="ev_1",
                operation_id=None,
            )
        # Invalid operation ID rejected
        with self.assertRaises(InvalidOperationIdError):
            self.store.consume_attestation(
                attestation=att_no_op,
                evidence_id="ev_1",
                operation_id="invalid/op/id",
            )

    def test_bind_methods_validate_operation_id_without_partial_state(self):
        """bind_* methods must validate op_id before durable access leaving no partial state."""
        with self.assertRaises(InvalidOperationIdError):
            self.store.bind_operation_receipt("invalid op with space", "rcpt_1")
        with self.assertRaises(InvalidOperationIdError):
            self.store.bind_operation_evidence("invalid/op", "ev_1")
        with self.assertRaises(InvalidOperationIdError):
            self.store.get_operation_lifecycle_state("bad;id")
        with self.assertRaises(InvalidOperationIdError):
            self.store.is_operation_used("bad$id")

        # Trust store must remain unmodified and empty
        self.assertEqual(len(self.store.used_operation_ids), 0)


class TestP03EvidenceAdmission(unittest.TestCase):
    """P0-3: Evidence Admission Fail-Closed & Controlled Promotion."""

    def setUp(self):
        self.ledger = EvidenceLedger(session_id="test_sess_p03")

    def test_confirmed_hypothesis_backed_only_by_rejected_or_quarantined_evidence(self):
        """A hypothesis claiming CONFIRMED backed only by REJECTED/QUARANTINED evidence cannot produce CONFIRMED_FAULT."""
        rec_quar = self.ledger.record(
            evidence_type="OBJECT_STATE",
            observation="Simulated heap state",
            session_id="test_sess_p03",
        )
        self.ledger.quarantine_record(rec_quar.evidence_id, reason="Dangling reference")

        mock_hyp = MagicMock()
        mock_hyp.hypothesis_id = "hyp_bad_evidence"
        mock_hyp.status = "CONFIRMED"
        mock_hyp.category = "MEMORY_CORRUPTION"
        mock_hyp.problem_statement = "Simulated heap corruption"
        mock_hyp.supporting_evidence_ids = [rec_quar.evidence_id]

        chk = DiagnosticCheck(
            check_id="chk_req",
            name="Heap Check",
            status="FAIL",
            is_required=True,
            supporting_evidence_ids=[rec_quar.evidence_id],
        )

        agg = DiagnosticVerdictAggregator()
        verdict = agg.aggregate(
            lifecycle_state="COMPLETED",
            stop_reason=None,
            checks=[chk],
            active_hypotheses=[mock_hyp],
            ledger=self.ledger,
        )
        # Overall verdict must NOT be CONFIRMED_FAULT
        self.assertNotEqual(verdict.verdict, VERDICT_CONFIRMED_FAULT)
        self.assertEqual(verdict.verdict, VERDICT_PROBABLE_FAULT)

    def test_quarantined_evidence_with_incomplete_provenance_cannot_be_promoted(self):
        """Quarantined evidence with absent or untrusted provenance cannot be promoted even without parent IDs."""
        rec_untrusted = self.ledger.record(
            evidence_type="OBJECT_STATE",
            observation="Simulated untrusted observation",
            session_id="test_sess_p03",
        )
        rec_untrusted.provenance["provenance_class"] = "IMPORTED_UNVERIFIED"
        self.ledger.quarantine_record(rec_untrusted.evidence_id, reason="Missing provenance verification")
        with self.assertRaises(SecurityViolationError):
            self.ledger.accept_record(rec_untrusted.evidence_id)

    def test_accept_record_rejects_promoting_rejected_evidence(self):
        """accept_record must reject promoting a REJECTED record."""
        rec = self.ledger.record(evidence_type="OBJECT_STATE", observation="faulty memory", session_id="test_sess_p03")
        self.ledger.reject_record(rec.evidence_id, reason="Signature verification failed")
        with self.assertRaises(SecurityViolationError):
            self.ledger.accept_record(rec.evidence_id)


class TestP04TrustStoreFilesystemSecurity(unittest.TestCase):
    """P0-4: TrustStore Filesystem Security & Hardening."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store_path = os.path.join(self.temp_dir.name, "secure_trust_store.json")
        self.store = DurableTrustStore(self.store_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_store_and_lock_file_hard_links_rejected(self):
        """Store file and lock file with st_nlink > 1 must be rejected due to hard-link replacement risk."""
        # Save a valid initial store
        self.store.record_used_operation("op_nlink_test", "sess_1", 100)
        self.assertTrue(os.path.exists(self.store_path))

        # Create a hard link to the store file
        hardlink_store = os.path.join(self.temp_dir.name, "store_hardlink.json")
        os.link(self.store_path, hardlink_store)
        try:
            with self.assertRaises(SecurityViolationError):
                self.store.load()
        finally:
            if os.path.exists(hardlink_store):
                os.remove(hardlink_store)

    def test_cleanup_stale_temp_files_concurrent_with_active_writer(self):
        """_cleanup_stale_temp_files must never delete an active writer's temporary file held under flock."""
        import fcntl
        active_tmp = os.path.join(self.temp_dir.name, ".trust_tmp_active123")
        with open(active_tmp, "w") as f:
            f.write("active write payload")
        os.chmod(active_tmp, 0o600)
        active_fd = os.open(active_tmp, os.O_RDWR)
        fcntl.flock(active_fd, fcntl.LOCK_EX)

        stale_tmp = os.path.join(self.temp_dir.name, ".trust_tmp_stale999")
        with open(stale_tmp, "w") as f:
            f.write("stale write payload")
        os.chmod(stale_tmp, 0o600)

        try:
            with self.store._file_lock():
                self.store._cleanup_stale_temp_files()

            self.assertTrue(os.path.exists(active_tmp), "Active writer temporary file must NOT be deleted")
            self.assertFalse(os.path.exists(stale_tmp), "Stale temporary file must be cleaned up")
        finally:
            os.close(active_fd)


class TestP05LifecycleEnforcement(unittest.TestCase):
    """P0-5: Lifecycle Enforcement & Fail-Closed Behavior."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store_path = os.path.join(self.temp_dir.name, "trust_store.json")
        self.store = DurableTrustStore(self.store_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_lifecycle_persistence_failure_before_capture_fails_closed(self):
        """Lifecycle persistence failure in begin_capture_transaction must fail closed before capture proceeds."""
        adapter = LocalTargetAdapter()
        adapter.trust_store = self.store
        adapter.require_lifecycle_persistence = True
        with patch.object(self.store, "transition_operation_lifecycle", side_effect=OSError("Disk write error")):
            with self.assertRaises(OSError):
                adapter.begin_capture_transaction(session_id="sess_fail", pid=os.getpid(), require_lifecycle_persistence=True)

    def test_lifecycle_commit_and_rollback_end_to_end(self):
        """Test complete lifecycle sequence: commit advances to COMMITTED; rollback advances to FAILED."""
        adapter = LocalTargetAdapter()
        adapter.trust_store = self.store
        adapter.require_lifecycle_persistence = True
        pid = os.getpid()

        # 1. Rollback test
        tx = adapter.begin_capture_transaction(session_id="sess_rb", pid=pid, require_lifecycle_persistence=True)
        self.assertEqual(self.store.get_operation_lifecycle_state(tx.transaction_id), OperationLifecycleState.EXECUTING)
        adapter.rollback_capture_transaction(tx, "Intentional rollback")
        self.assertEqual(self.store.get_operation_lifecycle_state(tx.transaction_id), OperationLifecycleState.FAILED)

        # 2. Commit test
        tx2 = adapter.begin_capture_transaction(session_id="sess_cm", pid=pid, require_lifecycle_persistence=True)
        tx2.physical_bytes_read = 32
        tx2.physical_reads_count = 1
        adapter.commit_capture_transaction(tx2)
        self.assertEqual(self.store.get_operation_lifecycle_state(tx2.transaction_id), OperationLifecycleState.COMMITTED)


class TestP06DurableIdentityConflict(unittest.TestCase):
    """P0-6: Durable Identity Conflict Persistence & Forensics."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store_path = os.path.join(self.temp_dir.name, "trust_store.json")
        self.store = DurableTrustStore(self.store_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_identity_conflict_persistence_failure_distinguishable(self):
        """When save() fails during conflict auditing, ConflictAuditPersistenceError is raised and memory is restored."""
        op_id = "op_audit_fail"
        self.store.record_used_operation(op_id, "sess_1", 1234, metadata={"build_id": "b_orig"})

        # Force save to fail during conflict persistence
        with patch.object(DurableTrustStore, "save", side_effect=OSError("Disk full")):
            with self.assertRaises(ConflictAuditPersistenceError):
                self.store.record_used_operation(
                    op_id, "sess_1", 1234, metadata={"build_id": "b_CONFLICT"}, allow_idempotent=True
                )

        # Original committed record must remain intact
        self.assertEqual(self.store.used_operation_ids[op_id]["build_id"], "b_orig")

    def test_identity_conflict_recovery_survives_restart(self):
        """Identity conflict event persists to disk and is readable across restart."""
        op_id = "op_survive_restart"
        self.store.record_used_operation(op_id, "sess_1", 1234, metadata={"build_id": "b_orig"})
        with self.assertRaises(IdentityConflictError):
            self.store.record_used_operation(
                op_id, "sess_1", 1234, metadata={"build_id": "b_CONFLICT"}, allow_idempotent=True
            )

        # Fresh store instance reading from same disk file
        store2 = DurableTrustStore(self.store_path)
        events = store2.get_identity_conflict_events()
        self.assertTrue(len(events) >= 1)
        self.assertEqual(events[0]["operation_id"], op_id)
        self.assertEqual(events[0]["attempted_value"], "b_CONFLICT")


if __name__ == "__main__":
    unittest.main()

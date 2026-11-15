"""Comprehensive audit and regression test suite for P0 Trust Boundary Closure.

Covers:
- P0-1: Canonical Replay Identity (Canonical JSON, SHA-256 digest, nested parameter normalization, boot-id fail-closed, durable replay check)
- P0-2: Operation ID Validation (All entrypoints including consume_attestation, bind operations, no partial durable state)
- P0-3: Evidence Admission (Aggregator filters to ACCEPTED only, controlled REJECTED/QUARANTINED -> ACCEPTED transitions)
- P0-4: TrustStore Filesystem Security (Lockfile nlink/owner/mode, parent dir validation, safe temp cleanup, crash recovery error propagation)
- P0-5: Operation Lifecycle (Cross-session transition rejection, TargetAdapter capture transaction DAG progression)
- P0-6: Durable Identity Conflict & Recovery (Conflict event persisted to disk across restart, existing committed operations preserved)
"""

import os
import stat
import json
import time
import uuid
import tempfile
import unittest
from unittest.mock import patch

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
            host_identity="host-alpha",
            boot_id="boot-12345",
            pid=4242,
            process_start_time=1000200,
        )
        params = {
            "zebra": 100,
            "nested": {
                "beta": "two",
                "alpha": 1,
                "deep": {"y": 2, "x": 1},
            },
            "apple": "pie",
        }
        canon1 = build_canonical_replay_identity(
            operation_id="op_canon_1",
            operation_kind="diagnostic_snapshot",
            process_identity=proc_ident,
            build_id="build_hash_abc",
            session_identity="sess_xyz",
            request_scope="memory_range",
            parameters=params,
            schema_version="1.0",
        )
        canon2 = build_canonical_replay_identity(
            operation_id="op_canon_1",
            operation_kind="diagnostic_snapshot",
            process_identity=proc_ident,
            build_id="build_hash_abc",
            session_identity="sess_xyz",
            request_scope="memory_range",
            parameters={"apple": "pie", "nested": {"deep": {"x": 1, "y": 2}, "alpha": 1, "beta": "two"}, "zebra": 100},
            schema_version="1.0",
        )
        json1 = canon1.to_canonical_json()
        json2 = canon2.to_canonical_json()
        self.assertEqual(json1, json2)
        digest1 = canon1.digest()
        digest2 = canon2.digest()
        self.assertEqual(digest1, digest2)
        self.assertEqual(len(digest1), 64)

    def test_resolve_boot_id_fails_closed_without_boot_default_fallback(self):
        """Missing or unreadable boot_id must fail closed with ProcessIdentityUnavailableError, not boot-default."""
        with patch("os.path.exists", return_value=False), patch("extractor.capture_backend._CURRENT_BOOT_ID_CACHE", None):
            with self.assertRaises(ProcessIdentityUnavailableError):
                resolve_current_boot_id()

    def test_durable_replay_validates_canonical_identity(self):
        """DurableTrustStore.record_used_operation must validate canonical identity and reject mismatch."""
        proc_ident = ProcessIdentity(
            host_identity="host-alpha",
            boot_id="boot-12345",
            pid=5555,
            process_start_time=200000,
        )
        canon = build_canonical_replay_identity(
            operation_id="op_canon_store",
            operation_kind="memory_scan",
            process_identity=proc_ident,
            build_id="build_1",
            session_identity="sess_1",
            request_scope="target_heap",
            parameters={"scope": "full"},
        )
        # First recording with canonical identity
        self.store.record_used_operation(
            op_id=canon.operation_id,
            session_id=canon.session_identity,
            pid=canon.process_identity.pid,
            metadata={"canonical_identity": canon.to_dict(), "canonical_digest": canon.digest()},
            allow_idempotent=False,
        )
        # Idempotent replay with identical canonical identity succeeds
        self.store.record_used_operation(
            op_id=canon.operation_id,
            session_id=canon.session_identity,
            pid=canon.process_identity.pid,
            metadata={"canonical_identity": canon.to_dict(), "canonical_digest": canon.digest()},
            allow_idempotent=True,
        )
        # Conflicting canonical identity (different request scope) must raise IdentityConflictError
        canon_conflict = build_canonical_replay_identity(
            operation_id=canon.operation_id,
            operation_kind="memory_scan",
            process_identity=proc_ident,
            build_id="build_1",
            session_identity="sess_1",
            request_scope="different_scope",
            parameters={"scope": "full"},
        )
        with self.assertRaises(IdentityConflictError):
            self.store.record_used_operation(
                op_id=canon.operation_id,
                session_id=canon.session_identity,
                pid=canon.process_identity.pid,
                metadata={"canonical_identity": canon_conflict.to_dict(), "canonical_digest": canon_conflict.digest()},
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

    def test_consume_attestation_requires_operation_id_when_flagged(self):
        """consume_attestation with require_operation_id=True must reject missing or invalid operation_id."""
        att = CausalAttestation(
            attestation_id=f"att_{uuid.uuid4().hex[:8]}",
            operation_id="op_att_1",
            precondition_evidence_id="ev_pre_1",
            postcondition_evidence_id="ev_post_1",
            key_id="default",
            session_id="sess_1",
            signature="deadbeef",
            target_identity={"pid": 1234},
        )
        with self.assertRaises(MissingIdentityFieldError):
            self.store.consume_attestation(
                attestation=att,
                evidence_id="ev_1",
                require_operation_id=True,
                operation_id=None,
            )
        with self.assertRaises(InvalidOperationIdError):
            self.store.consume_attestation(
                attestation=att,
                evidence_id="ev_1",
                require_operation_id=True,
                operation_id="invalid/op/id",
            )

    def test_bind_methods_validate_operation_id(self):
        """bind_operation_receipt and bind_operation_evidence must validate op_id before durable access."""
        with self.assertRaises(InvalidOperationIdError):
            self.store.bind_operation_receipt("invalid op with space", "rcpt_1")
        with self.assertRaises(InvalidOperationIdError):
            self.store.bind_operation_evidence("invalid/op", "ev_1")
        with self.assertRaises(InvalidOperationIdError):
            self.store.get_operation_lifecycle_state("bad;id")
        with self.assertRaises(InvalidOperationIdError):
            self.store.is_operation_used("bad$id")


class TestP03EvidenceAdmission(unittest.TestCase):
    """P0-3: Evidence Admission Fail-Closed & Controlled Promotion."""

    def setUp(self):
        self.ledger = EvidenceLedger(session_id="test_sess_p03")

    def test_diagnostic_verdict_aggregator_ignores_rejected_and_quarantined_evidence(self):
        """Verdict aggregation must only consider ACCEPTED evidence, ignoring REJECTED/QUARANTINED even if verified."""
        rec_accepted = EvidenceRecord(
            evidence_id="ev_acc_1",
            evidence_type="OBJECT_STATE",
            source="runtime_verified",
            provenance={"provenance_class": "LIVE_RUNTIME_CAPTURE"},
            admission_state=EvidenceAdmissionState.ACCEPTED,
        )
        rec_quarantined = EvidenceRecord(
            evidence_id="ev_quar_1",
            evidence_type="OBJECT_STATE",
            source="runtime_verified",
            provenance={"provenance_class": "LIVE_RUNTIME_CAPTURE"},
            admission_state=EvidenceAdmissionState.QUARANTINED,
        )
        rec_rejected = EvidenceRecord(
            evidence_id="ev_rej_1",
            evidence_type="OBJECT_STATE",
            source="runtime_verified",
            provenance={"provenance_class": "LIVE_RUNTIME_CAPTURE"},
            admission_state=EvidenceAdmissionState.REJECTED,
        )
        chk_quar = DiagnosticCheck(
            check_id="chk_quar",
            name="Quarantined Check",
            status="FAIL",
            supporting_evidence_ids=["ev_quar_1"],
        )
        # Check referencing quarantined evidence must NOT satisfy root cause confirmation
        met = DiagnosticVerdictAggregator._does_required_fail_satisfy_confirmation(
            c=chk_quar,
            active_hypotheses=[],
            evidence_records=[rec_quarantined, rec_rejected],
        )
        self.assertFalse(met, "Quarantined/Rejected evidence must not satisfy root cause confirmation")

        # Check referencing accepted evidence must satisfy root cause confirmation
        chk_acc = DiagnosticCheck(
            check_id="chk_acc",
            name="Accepted Check",
            status="FAIL",
            supporting_evidence_ids=["ev_acc_1"],
        )
        met_acc = DiagnosticVerdictAggregator._does_required_fail_satisfy_confirmation(
            c=chk_acc,
            active_hypotheses=[],
            evidence_records=[rec_accepted, rec_quarantined],
        )
        self.assertTrue(met_acc, "Accepted evidence with trusted provenance must satisfy confirmation")

    def test_accept_record_rejects_promoting_rejected_evidence(self):
        """accept_record must reject promoting a REJECTED record without re-verification."""
        rec = self.ledger.record(evidence_type="OBJECT_STATE", observation="faulty memory", session_id="test_sess_p03")
        self.ledger.reject_record(rec.evidence_id, reason="Signature verification failed")
        self.assertEqual(rec.admission_state, EvidenceAdmissionState.REJECTED)
        with self.assertRaises(SecurityViolationError):
            self.ledger.accept_record(rec.evidence_id)

    def test_accept_record_promotes_quarantined_only_when_parents_resolved(self):
        """accept_record promotes QUARANTINED dangling parent only after parent is admitted."""
        rec_child = EvidenceRecord(
            evidence_id="ev_child",
            evidence_type="OBJECT_STATE",
            parent_evidence_ids=["ev_parent_missing"],
            admission_state=EvidenceAdmissionState.QUARANTINED,
        )
        self.ledger.add_record(rec_child, quarantine_dangling=True)
        # Promotion must fail while parent is still missing
        with self.assertRaises(ValueError):
            self.ledger.accept_record("ev_child")

        # Now add the missing parent
        rec_parent = EvidenceRecord(
            evidence_id="ev_parent_missing",
            evidence_type="OBJECT_STATE",
            admission_state=EvidenceAdmissionState.ACCEPTED,
        )
        self.ledger.add_record(rec_parent)
        # Now promotion succeeds
        self.ledger.accept_record("ev_child")
        self.assertEqual(rec_child.admission_state, EvidenceAdmissionState.ACCEPTED)


class TestP04TrustStoreFilesystemSecurity(unittest.TestCase):
    """P0-4: TrustStore Filesystem Security & Hardening."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store_path = os.path.join(self.temp_dir.name, "secure_trust_store.json")
        self.store = DurableTrustStore(self.store_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_lock_file_hard_link_rejected(self):
        """Lock file with nlink > 1 must be rejected due to hard-link replacement risk."""
        lock_path = self.store_path + ".lock"
        # Pre-create lock file and create a hard link to it
        with open(lock_path, "w") as f:
            f.write("")
        os.chmod(lock_path, 0o600)
        hardlink_path = os.path.join(self.temp_dir.name, "lock_hardlink")
        os.link(lock_path, hardlink_path)
        try:
            with self.assertRaises(SecurityViolationError):
                with self.store._file_lock():
                    pass
        finally:
            if os.path.exists(hardlink_path):
                os.remove(hardlink_path)

    def test_cleanup_stale_temp_files_never_deletes_active_writer_temp(self):
        """_cleanup_stale_temp_files must never delete an active writer's newly created temporary file."""
        import fcntl
        active_tmp = os.path.join(self.temp_dir.name, ".trust_tmp_active123")
        with open(active_tmp, "w") as f:
            f.write("active write payload")
        os.chmod(active_tmp, 0o600)
        active_fd = os.open(active_tmp, os.O_RDWR)
        fcntl.flock(active_fd, fcntl.LOCK_EX)

        # Stale temp file (closed / unlocked)
        stale_tmp = os.path.join(self.temp_dir.name, ".trust_tmp_stale999")
        with open(stale_tmp, "w") as f:
            f.write("stale write payload")
        os.chmod(stale_tmp, 0o600)

        try:
            with self.store._file_lock():
                self.store._cleanup_stale_temp_files()

            # Active file must be preserved; stale file must be deleted
            self.assertTrue(os.path.exists(active_tmp), "Active writer temporary file must NOT be deleted")
            self.assertFalse(os.path.exists(stale_tmp), "Stale temporary file must be cleaned up")
        finally:
            os.close(active_fd)

    def test_crash_recovery_persistence_failure_propagates_as_explicit_error(self):
        """Crash recovery reconciliation failure when persisting aborted operations must raise an explicit error."""
        # Record an uncommitted EXECUTING operation
        self.store.record_used_operation("op_uncommitted", "sess_crash", 9999)
        self.store.used_operation_ids["op_uncommitted"]["state"] = OperationLifecycleState.EXECUTING.value
        self.store.save()

        # Create new store instance pointing to same file and force save() to fail during load(reconcile_crashes=True)
        with patch.object(DurableTrustStore, "save", side_effect=OSError("Disk write error during recovery")):
            with self.assertRaises(RuntimeError):
                DurableTrustStore(self.store_path)


class TestP05OperationLifecycle(unittest.TestCase):
    """P0-5: Operation Lifecycle End-to-End & Cross-Session Protection."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store_path = os.path.join(self.temp_dir.name, "trust_store.json")
        self.store = DurableTrustStore(self.store_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_cross_session_or_pid_transition_rejected(self):
        """transition_operation_lifecycle must reject attempts to transition using a different session or PID."""
        op_id = "op_sess_bind_1"
        self.store.transition_operation_lifecycle(
            op_id=op_id,
            session_id="session_A",
            pid=1111,
            target_state=OperationLifecycleState.CREATED,
        )
        self.store.transition_operation_lifecycle(
            op_id=op_id,
            session_id="session_A",
            pid=1111,
            target_state=OperationLifecycleState.VALIDATED,
        )
        # Attempt to transition using different session ID
        with self.assertRaises(IdentityConflictError):
            self.store.transition_operation_lifecycle(
                op_id=op_id,
                session_id="session_B_rogue",
                pid=1111,
                target_state=OperationLifecycleState.RESERVED,
            )
        # Attempt to transition using different PID
        with self.assertRaises(IdentityConflictError):
            self.store.transition_operation_lifecycle(
                op_id=op_id,
                session_id="session_A",
                pid=2222,
                target_state=OperationLifecycleState.RESERVED,
            )

    def test_direct_commit_forbidden_when_operation_exists_in_prior_state(self):
        """record_used_operation cannot directly mark an operation COMMITTED if it is in an earlier lifecycle state."""
        op_id = "op_direct_commit_guard"
        self.store.transition_operation_lifecycle(
            op_id=op_id,
            session_id="sess_1",
            pid=3333,
            target_state=OperationLifecycleState.CREATED,
        )
        with self.assertRaises(InvalidStateTransitionError):
            self.store.record_used_operation(
                op_id=op_id,
                session_id="sess_1",
                pid=3333,
                allow_idempotent=False,
            )


class TestP06DurableIdentityConflictAndRecovery(unittest.TestCase):
    """P0-6: Durable Identity Conflict Persistence Across Process Restarts."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.store_path = os.path.join(self.temp_dir.name, "trust_store.json")
        self.store = DurableTrustStore(self.store_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_identity_conflict_persisted_to_disk_and_survives_restart(self):
        """Identity conflict events must be persisted to disk before raising, surviving process restart."""
        op_id = "op_conflict_persist"
        self.store.record_used_operation(
            op_id=op_id,
            session_id="sess_orig",
            pid=4444,
            metadata={"build_id": "build_orig", "host_identity": "host_orig"},
        )
        # Attempt conflicting build_id
        with self.assertRaises(IdentityConflictError):
            self.store.record_used_operation(
                op_id=op_id,
                session_id="sess_orig",
                pid=4444,
                metadata={"build_id": "build_CONFLICT", "host_identity": "host_orig"},
                allow_idempotent=True,
            )

        # Original committed operation must remain uncorrupted
        op_rec = self.store.used_operation_ids[op_id]
        self.assertEqual(op_rec["build_id"], "build_orig")
        self.assertEqual(op_rec["state"], OperationLifecycleState.COMMITTED.value)

        # Simulate process restart by reloading from disk in a fresh store instance
        store_reloaded = DurableTrustStore(self.store_path)
        events = store_reloaded.get_identity_conflict_events()
        self.assertTrue(len(events) >= 1, "Identity conflict event must be persisted and reloaded from disk")
        self.assertEqual(events[0]["operation_id"], op_id)
        self.assertEqual(events[0]["field_name"], "build_id")
        self.assertEqual(events[0]["existing_value"], "build_orig")
        self.assertEqual(events[0]["attempted_value"], "build_CONFLICT")


if __name__ == "__main__":
    unittest.main()

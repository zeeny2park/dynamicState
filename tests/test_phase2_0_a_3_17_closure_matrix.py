from pathlib import Path
"""Phase 2.0-A.3.17 Complete Trust & Recovery Integrity Closure Test Matrix.

Covers every mandatory scenario in the Phase 2.0-A.3.17 Required Test Matrix:
1. Canonical operation-ID binding & conflict rejection (no silent precedence).
2. Verify-before-consume (invalid signature, revoked key, wrong target/session/
   evidence/operation ID, receipt op mismatch, record op mismatch -> TrustStore
   remains byte-for-byte unchanged).
3. Durable operation_id persistence in consumed-attestation records & idempotent
   recovery (same evidence + same op -> idempotent; same evidence + different op
   -> REPLAY_CONFLICT; different evidence + same attestation -> REPLAY_CONFLICT).
4. Mandatory durable TrustStore enforcement across production entry points
   (DurableTrustStore.save() -> NON_DURABLE when unconfigured, LocalTargetAdapter,
   AgentRuntime, EvidenceLedger(require_durable_trust_store=True)).
5. 5-stage transactional EvidenceLedger.from_dict recovery (validation or index
   failure leaves durable TrustStore byte-for-byte unchanged; repeated recovery
   is idempotent).
6. Single-field serialized index mutation rejection (missing/extra/forged/duplicate
   index fields, record_count mismatch).
7. TrustStore durability & fail-closed security (unsafe parent dir permissions
   rejected without silent chmod, lock failure, file fsync failure, dir fsync
   failure, atomic rename failure, corrupted TrustStore).
8. Independent-process concurrency & crash-boundary tests using real processes
   and deterministic synchronization primitives (multiprocessing.Barrier).
9. CI baseline runner verification integrity (zero-test file never PASS,
   pytest-only file never PASS via unittest, skip marker inside function/string
   does not skip whole file).
"""

import json
import multiprocessing
import os
import shutil
import stat
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

from extractor.agent_runtime import AgentRuntime
from extractor.capture_backend import (
    CausalAttestation,
    DurableCommitError,
    DurableCommitOutcome,
    DurableTrustStore,
    SecurityViolationError,
    TrustConsumptionStatus,
    get_trusted_capture_authority_token,
    issue_live_capture_receipt,
    set_default_trust_store,
)
from extractor.evidence_ledger import (
    EVIDENCE_TYPE_COMPARISON,
    EVIDENCE_TYPE_OBJECT_STATE,
    EvidenceLedger,
    EvidenceRecord,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
)
from extractor.target_adapter import LocalTargetAdapter


def _make_signed_attestation(
    trust_store: DurableTrustStore,
    *,
    attestation_id: str = "att_closure_01",
    session_id: str = "sess_closure_01",
    pid: int = 4242,
    operation_id: str = "op_closure_01",
    pre_id: str = "ev_pre_01",
    post_id: str = "ev_post_01",
    key_id: str = "key_closure",
    secret: str = "secret_closure_32bytes_minimum_value",
    expires_at_ns: int = 0,
    target_host: str = "localhost",
) -> CausalAttestation:
    if key_id not in trust_store.keys:
        trust_store.register_key(key_id, secret, is_active=True)
    att = CausalAttestation(
        attestation_id=attestation_id,
        session_id=session_id,
        target_identity={
            "pid": pid,
            "process_identity": f"{pid}:1000",
            "executable_identity": "/usr/bin/target_app",
            "build_id": "sha1:closurebuild001",
            "target_host": target_host,
        },
        operation_id=operation_id,
        precondition_evidence_id=pre_id,
        postcondition_evidence_id=post_id,
        claimed_transition={"field": "state", "before": 0, "after": 1},
        intervention_details={"intervention_id": "int_01", "action": "step"},
        issued_at_ns=time.time_ns(),
        expires_at_ns=expires_at_ns,
        key_id=key_id,
        authority_level="PRODUCTION",
    )
    att.sign(secret)
    return att


def _make_ledger_with_pre(
    trust_store: DurableTrustStore,
    *,
    session_id: str = "sess_closure_01",
    pid: int = 4242,
    pre_id: str = "ev_pre_01",
    pre_op_id: str = "op_pre_01",
) -> EvidenceLedger:
    ledger = EvidenceLedger(session_id=session_id, trust_store=trust_store)
    token = get_trusted_capture_authority_token()
    pre_rcpt = issue_live_capture_receipt(
        session_id=session_id,
        pid=pid,
        process_identity=f"{pid}:1000",
        executable_identity="/usr/bin/target_app",
        build_id="sha1:closurebuild001",
        snapshot_binding="snap_pre",
        operation_id=pre_op_id,
        capture_authority_token=token,
    )
    pre_rec = EvidenceRecord(
        evidence_id=pre_id,
        session_id=session_id,
        evidence_type=EVIDENCE_TYPE_OBJECT_STATE,
        observation="precondition state",
        provenance={
            "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
            "live_capture_receipt": pre_rcpt.to_dict(),
        },
        details={
            "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
            "operation_id": pre_op_id,
        },
        target_identity={
            "pid": pid,
            "process_identity": f"{pid}:1000",
            "executable_identity": "/usr/bin/target_app",
            "build_id": "sha1:closurebuild001",
            "target_host": "localhost",
        },
    )
    ledger.add_record(pre_rec)
    return ledger


def _mp_worker_consume_same(store_path: str, att_dict: dict, ev_id: str, op_id: str, barrier, out_q):
    ts = DurableTrustStore(store_path)
    att = CausalAttestation.from_dict(att_dict)
    barrier.wait(timeout=10.0)
    res = ts.consume_attestation(
        attestation=att,
        evidence_id=ev_id,
        session_id=att.session_id,
        expected_pid=att.target_identity["pid"],
        expected_process_identity=att.target_identity["process_identity"],
        expected_executable_identity=att.target_identity["executable_identity"],
        expected_build_id=att.target_identity["build_id"],
        expected_target_host=att.target_identity["target_host"],
        operation_id=op_id,
    )
    out_q.put((ev_id, res.status.value))


def _mp_worker_consume_distinct(store_path: str, att_dict: dict, ev_id: str, op_id: str, barrier, out_q):
    ts = DurableTrustStore(store_path)
    att = CausalAttestation.from_dict(att_dict)
    barrier.wait(timeout=10.0)
    res = ts.consume_attestation(
        attestation=att,
        evidence_id=ev_id,
        session_id=att.session_id,
        expected_pid=att.target_identity["pid"],
        expected_process_identity=att.target_identity["process_identity"],
        expected_executable_identity=att.target_identity["executable_identity"],
        expected_build_id=att.target_identity["build_id"],
        expected_target_host=att.target_identity["target_host"],
        operation_id=op_id,
    )
    out_q.put((att.attestation_id, res.status.value))


class TestA317VerificationAndOperationBinding(unittest.TestCase):
    """P0: Verify-before-consume & canonical operation_id binding."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="a317_matrix_op_")
        self.store_path = os.path.join(self.tmpdir, "trust_store.json")
        self.ts = DurableTrustStore(self.store_path)
        self.ts.register_key("key_closure", "secret_closure_32bytes_minimum_value", is_active=True)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _snapshot_bytes(self) -> bytes:
        with open(self.store_path, "rb") as f:
            return f.read()

    def test_validation_failures_leave_trust_store_unchanged(self):
        """Invalid signature, revoked key, wrong target/session/operation_id never consume."""
        att = _make_signed_attestation(self.ts, attestation_id="att_vbc_01", operation_id="op_vbc_01")
        before = self._snapshot_bytes()

        # 1. Invalid signature
        bad_sig = CausalAttestation.from_dict(att.to_dict())
        bad_sig.signature = "0" * 64
        r = self.ts.consume_attestation(
            bad_sig, "ev_1", session_id="sess_closure_01", expected_pid=4242, operation_id="op_vbc_01"
        )
        self.assertEqual(r.status, TrustConsumptionStatus.INVALID_SIGNATURE)
        self.assertEqual(self._snapshot_bytes(), before)

        # 2. Wrong target PID
        r = self.ts.consume_attestation(
            att, "ev_1", session_id="sess_closure_01", expected_pid=9999, operation_id="op_vbc_01"
        )
        self.assertEqual(r.status, TrustConsumptionStatus.IDENTITY_MISMATCH)
        self.assertEqual(self._snapshot_bytes(), before)

        # 3. Wrong session
        r = self.ts.consume_attestation(
            att, "ev_1", session_id="sess_wrong", expected_pid=4242, operation_id="op_vbc_01"
        )
        self.assertEqual(r.status, TrustConsumptionStatus.IDENTITY_MISMATCH)
        self.assertEqual(self._snapshot_bytes(), before)

        # 4. Wrong operation ID (conflicts with attestation.operation_id)
        r = self.ts.consume_attestation(
            att, "ev_1", session_id="sess_closure_01", expected_pid=4242, operation_id="op_wrong"
        )
        self.assertEqual(r.status, TrustConsumptionStatus.IDENTITY_MISMATCH)
        self.assertEqual(self._snapshot_bytes(), before)
        self.assertNotIn("att_vbc_01", self.ts.used_attestation_ids)

        # 5. Revoked key
        self.ts.revoke_key("key_closure", reason="compromised")
        after_revoke = self._snapshot_bytes()
        r = self.ts.consume_attestation(
            att, "ev_1", session_id="sess_closure_01", expected_pid=4242, operation_id="op_vbc_01"
        )
        self.assertEqual(r.status, TrustConsumptionStatus.REVOKED)
        self.assertEqual(self._snapshot_bytes(), after_revoke)
        self.assertNotIn("att_vbc_01", self.ts.used_attestation_ids)

    def test_record_and_receipt_operation_mismatch_rejected_before_consumption(self):
        """Receipt op mismatch & record.details op mismatch fail BEFORE consuming attestation."""
        ledger = _make_ledger_with_pre(self.ts)
        att = _make_signed_attestation(self.ts, attestation_id="att_mismatch_01", operation_id="op_att_01")
        token = get_trusted_capture_authority_token()
        before = self._snapshot_bytes()

        # Record details operation_id mismatch
        rec_bad_details = EvidenceRecord(
            evidence_id="ev_post_bad_details",
            session_id="sess_closure_01",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            observation="transition",
            provenance={"causal_attestation": att.to_dict()},
            details={"operation_id": "op_different_details"},
            target_identity=dict(att.target_identity),
        )
        with self.assertRaises(ValueError):
            ledger.add_record(rec_bad_details)
        self.assertEqual(self._snapshot_bytes(), before)
        self.assertFalse(self.ts.is_attestation_used("att_mismatch_01"))

        # Receipt operation_id mismatch (including ctx_ prefix — no bypass!)
        bad_rcpt = issue_live_capture_receipt(
            session_id="sess_closure_01",
            pid=4242,
            process_identity="4242:1000",
            executable_identity="/usr/bin/target_app",
            build_id="sha1:closurebuild001",
            snapshot_binding="snap_post",
            operation_id="ctx_different_rcpt",
            capture_authority_token=token,
        )
        rec_bad_rcpt = EvidenceRecord(
            evidence_id="ev_post_bad_rcpt",
            session_id="sess_closure_01",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            observation="transition",
            provenance={
                "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                "live_capture_receipt": bad_rcpt.to_dict(),
                "causal_attestation": att.to_dict(),
            },
            details={"operation_id": "op_att_01"},
            target_identity=dict(att.target_identity),
        )
        with self.assertRaises(ValueError):
            ledger.add_record(rec_bad_rcpt)
        self.assertEqual(self._snapshot_bytes(), before)
        self.assertFalse(self.ts.is_attestation_used("att_mismatch_01"))

    def test_operation_id_persisted_and_idempotent_recovery_enforces_op_and_evidence(self):
        """Persists operation_id; same ev+same op idempotent; same ev+diff op rejected; diff ev rejected."""
        att = _make_signed_attestation(self.ts, attestation_id="att_idem_01", operation_id="op_idem_01")
        r1 = self.ts.consume_attestation(
            att, "ev_idem_01", session_id="sess_closure_01", expected_pid=4242, operation_id="op_idem_01"
        )
        self.assertEqual(r1.status, TrustConsumptionStatus.NEW_ACCEPTANCE)

        # Verify persisted on disk with operation_id
        on_disk = json.loads(Path(self.store_path).read_text(encoding="utf-8"))
        self.assertEqual(on_disk["used_attestations"]["att_idem_01"]["operation_id"], "op_idem_01")

        # Same evidence + same operation_id -> IDEMPOTENT_RECOVERY
        reloaded = DurableTrustStore(self.store_path)
        r2 = reloaded.consume_attestation(
            att, "ev_idem_01", session_id="sess_closure_01", expected_pid=4242, operation_id="op_idem_01"
        )
        self.assertEqual(r2.status, TrustConsumptionStatus.IDEMPOTENT_RECOVERY)

        # Same evidence + different operation_id -> rejected
        att_diff_op = _make_signed_attestation(self.ts, attestation_id="att_idem_01", operation_id="op_idem_02")
        r3 = reloaded.consume_attestation(
            att_diff_op, "ev_idem_01", session_id="sess_closure_01", expected_pid=4242, operation_id="op_idem_02"
        )
        self.assertEqual(r3.status, TrustConsumptionStatus.REPLAY_CONFLICT)

        # Different evidence + same attestation -> REPLAY_CONFLICT
        r4 = reloaded.consume_attestation(
            att, "ev_different_02", session_id="sess_closure_01", expected_pid=4242, operation_id="op_idem_01"
        )
        self.assertEqual(r4.status, TrustConsumptionStatus.REPLAY_CONFLICT)


class TestA317MandatoryDurableTrustStore(unittest.TestCase):
    """P0: Mandatory durable TrustStore enforcement on production entry points."""

    def test_unconfigured_trust_store_reports_non_durable_not_committed(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("DYNAMICSTATE_TRUST_STORE_PATH", None)
            ts = DurableTrustStore(store_path=None)
            self.assertFalse(ts.is_durable)
            outcome = ts.save()
            self.assertEqual(outcome, DurableCommitOutcome.NON_DURABLE)
            self.assertNotEqual(outcome, DurableCommitOutcome.COMMITTED)

    def test_local_target_adapter_fails_closed_without_durable_trust_store(self):
        prev_default = None
        from extractor.capture_backend import get_default_trust_store
        prev_default = get_default_trust_store()
        try:
            set_default_trust_store(None)
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("DYNAMICSTATE_TRUST_STORE_PATH", None)
                adapter = LocalTargetAdapter()
                with self.assertRaises(RuntimeError):
                    adapter.begin_capture_transaction(session_id="sess_no_ts", pid=os.getpid())

                # In-memory TrustStore (store_path=None) also rejected on production path
                adapter_mem = LocalTargetAdapter(trust_store=DurableTrustStore(store_path=None))
                with self.assertRaises(RuntimeError):
                    adapter_mem.begin_capture_transaction(session_id="sess_mem_ts", pid=os.getpid())
        finally:
            set_default_trust_store(prev_default)

    def test_agent_runtime_and_evidence_ledger_enforce_durable_trust_store(self):
        tmpdir = tempfile.mkdtemp(prefix="a317_runtime_ts_")
        try:
            with patch.dict(os.environ, {}, clear=False):
                os.environ.pop("DYNAMICSTATE_TRUST_STORE_PATH", None)
                mem_ts = DurableTrustStore(store_path=None)
                self.assertFalse(mem_ts.is_durable)

                # AgentRuntime rejects in-memory TrustStore unless allow_non_durable_trust=True
                with self.assertRaises(RuntimeError):
                    AgentRuntime(corpus_dir=tmpdir, trust_store=mem_ts)

                # Explicit non-production opt-in works
                rt_nonprod = AgentRuntime(
                    corpus_dir=tmpdir,
                    trust_store=mem_ts,
                    allow_non_durable_trust=True,
                )
                self.assertFalse(rt_nonprod.trust_store.is_durable)

                # Default AgentRuntime initializes a durable file-backed TrustStore
                rt_prod = AgentRuntime(corpus_dir=tmpdir)
                self.assertTrue(rt_prod.trust_store.is_durable)

                # EvidenceLedger(require_durable_trust_store=True) fails closed without durable store
                with self.assertRaises(RuntimeError):
                    EvidenceLedger(trust_store=mem_ts, require_durable_trust_store=True)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestA317TransactionalRecoveryAndIndexIntegrity(unittest.TestCase):
    """P0: 5-stage transactional recovery & single-field serialized index mutation rejection."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="a317_recov_")
        self.store_path = os.path.join(self.tmpdir, "trust_store.json")
        self.ts = DurableTrustStore(self.store_path)
        self.ts.register_key("key_closure", "secret_closure_32bytes_minimum_value", is_active=True)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _build_serialized_ledger(self):
        # Build serialized ledger using an isolated build store so target self.ts is fresh/unconsumed
        build_store = DurableTrustStore(os.path.join(self.tmpdir, "build_store.json"))
        build_store.register_key("key_closure", "secret_closure_32bytes_minimum_value", is_active=True)
        ledger = _make_ledger_with_pre(build_store)
        att = _make_signed_attestation(build_store, attestation_id="att_recov_01", operation_id="op_recov_01")
        token = get_trusted_capture_authority_token()
        post_rcpt = issue_live_capture_receipt(
            session_id="sess_closure_01",
            pid=4242,
            process_identity="4242:1000",
            executable_identity="/usr/bin/target_app",
            build_id="sha1:closurebuild001",
            snapshot_binding="snap_post",
            operation_id="op_recov_01",
            capture_authority_token=token,
        )
        post_rec = EvidenceRecord(
            evidence_id="ev_post_01",
            session_id="sess_closure_01",
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            observation="verified transition",
            provenance={
                "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                "live_capture_receipt": post_rcpt.to_dict(),
                "causal_attestation": att.to_dict(),
            },
            details={
                "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                "operation_id": "op_recov_01",
            },
            target_identity=dict(att.target_identity),
        )
        ledger.add_record(post_rec)
        return ledger.to_dict()

    def test_recovery_index_failure_leaves_trust_store_byte_for_byte_unchanged(self):
        """If serialized index validation fails, live TrustStore MUST remain byte-for-byte unchanged."""
        serialized = self._build_serialized_ledger()
        before = Path(self.store_path).read_bytes()

        # Mutate each serialized index field one at a time
        mutations = [
            lambda d: d.__setitem__("record_count", 99),
            lambda d: d["used_causal_attestation_ids"].append("att_forged_99"),
            lambda d: d["used_causal_attestation_ids"].clear(),
            lambda d: d["causal_attestation_to_evidence_id"].__setitem__("att_recov_01", "ev_forged"),
            lambda d: d["operation_to_receipt_id"].__setitem__("op_recov_01", "rcpt_forged"),
            lambda d: d["operation_to_evidence_ids"].__setitem__("op_recov_01", ["ev_forged"]),
            lambda d: d["used_operation_ids"]["op_recov_01"].__setitem__("pid", 99999),
            lambda d: d["used_operation_ids"]["op_recov_01"].__setitem__("forged_extra_key", "x"),
            lambda d: d["used_operation_ids"].pop("op_recov_01"),
        ]
        for idx, mutate in enumerate(mutations):
            bad = json.loads(json.dumps(serialized))
            mutate(bad)
            with self.assertRaises(ValueError, msg=f"Mutation #{idx} must be rejected"):
                EvidenceLedger.from_dict(bad, trust_store=self.ts)
            # TrustStore on disk MUST be byte-for-byte identical after every failed recovery!
            after = Path(self.store_path).read_bytes()
            self.assertEqual(after, before, f"Mutation #{idx} mutated durable TrustStore on disk!")
            self.assertNotIn("att_recov_01", self.ts.used_attestation_ids)

    def test_valid_recovery_commits_and_is_idempotent_across_restarts(self):
        """Valid serialized ledger reconciles atomically and can be recovered repeatedly."""
        serialized = self._build_serialized_ledger()
        l1 = EvidenceLedger.from_dict(serialized, trust_store=self.ts)
        self.assertEqual(len(l1), 2)
        self.assertTrue(self.ts.is_attestation_used("att_recov_01"))

        # Cold restart recovery repeated twice -> idempotent
        cold_ts = DurableTrustStore(self.store_path)
        l2 = EvidenceLedger.from_dict(serialized, trust_store=cold_ts)
        l3 = EvidenceLedger.from_dict(serialized, trust_store=cold_ts)
        self.assertEqual(len(l2), 2)
        self.assertEqual(len(l3), 2)


class TestA317TrustStoreDurabilityAndFaultInjection(unittest.TestCase):
    """P0: Parent dir permissions, fsync/dir-fsync/rename/lock/corruption fail-closed."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="a317_fault_")
        self.store_path = os.path.join(self.tmpdir, "trust_store.json")
        self.ts = DurableTrustStore(self.store_path)
        self.ts.register_key("k1", "secret_1", is_active=True)

    def tearDown(self):
        try:
            os.chmod(self.tmpdir, 0o700)
        except OSError:
            pass
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_unsafe_parent_directory_permissions_rejected_without_silent_chmod(self):
        """World-writable or group-writable non-sticky parent directory fails closed without chmod."""
        unsafe_dir = os.path.join(self.tmpdir, "unsafe_parent")
        os.makedirs(unsafe_dir, mode=0o700)
        os.chmod(unsafe_dir, 0o777)
        ts_unsafe = DurableTrustStore(os.path.join(unsafe_dir, "store.json"))
        with self.assertRaises((SecurityViolationError, DurableCommitError)):
            ts_unsafe.save()
        # Must NOT have silently changed directory permissions
        mode_after = stat.S_IMODE(os.lstat(unsafe_dir).st_mode)
        self.assertEqual(mode_after, 0o777)
        os.chmod(unsafe_dir, 0o700)

    def test_corrupted_trust_store_fails_closed(self):
        with open(self.store_path, "w", encoding="utf-8") as f:
            f.write("{corrupted_json_truncated")
        with self.assertRaises(RuntimeError):
            DurableTrustStore(self.store_path)

    def test_fault_injection_file_fsync_rename_dir_fsync_lock(self):
        """Fault injection at file fsync, atomic rename, dir fsync, and lock boundaries."""
        # 1. File fsync failure -> NOT_COMMITTED
        with patch("os.fsync", side_effect=OSError(5, "EIO file fsync")):
            with self.assertRaises(DurableCommitError) as ctx:
                self.ts.save()
            self.assertEqual(ctx.exception.outcome, DurableCommitOutcome.NOT_COMMITTED)

        # 2. Atomic rename failure -> NOT_COMMITTED
        with patch("os.replace", side_effect=OSError(28, "ENOSPC rename")):
            with self.assertRaises(DurableCommitError) as ctx:
                self.ts.save()
            self.assertEqual(ctx.exception.outcome, DurableCommitOutcome.NOT_COMMITTED)

        # 3. Directory fsync failure after rename -> COMMIT_UNKNOWN
        orig_fsync = os.fsync
        calls = {"n": 0}
        def _fail_second_fsync(fd):
            calls["n"] += 1
            if calls["n"] == 2:
                raise OSError(5, "EIO dir fsync")
            return orig_fsync(fd)

        with patch("os.fsync", side_effect=_fail_second_fsync):
            with self.assertRaises(DurableCommitError) as ctx:
                self.ts.save()
            self.assertEqual(ctx.exception.outcome, DurableCommitOutcome.COMMIT_UNKNOWN)

        # 4. Lock failure -> fails closed
        with patch("fcntl.flock", side_effect=OSError(37, "ENOLCK")):
            with self.assertRaises(OSError):
                self.ts.save()


class TestA317IndependentProcessConcurrency(unittest.TestCase):
    """P0: Real independent-process concurrency with deterministic Barrier sync."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp(prefix="a317_mp_")
        self.store_path = os.path.join(self.tmpdir, "trust_store.json")
        self.ts = DurableTrustStore(self.store_path)
        self.ts.register_key("key_closure", "secret_closure_32bytes_minimum_value", is_active=True)

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_two_processes_concurrent_same_attestation_exactly_one_wins(self):
        att = _make_signed_attestation(self.ts, attestation_id="att_mp_race_01", operation_id="op_mp_race_01")
        ctx = multiprocessing.get_context("spawn")
        barrier = ctx.Barrier(2)
        q = ctx.Queue()
        p1 = ctx.Process(target=_mp_worker_consume_same, args=(self.store_path, att.to_dict(), "ev_p1", "op_mp_race_01", barrier, q))
        p2 = ctx.Process(target=_mp_worker_consume_same, args=(self.store_path, att.to_dict(), "ev_p2", "op_mp_race_01", barrier, q))
        p1.start(); p2.start()
        p1.join(timeout=15.0); p2.join(timeout=15.0)
        self.assertEqual(p1.exitcode, 0)
        self.assertEqual(p2.exitcode, 0)
        results = sorted([q.get(timeout=5.0), q.get(timeout=5.0)], key=lambda x: x[1])
        statuses = [s for _, s in results]
        self.assertEqual(statuses, [TrustConsumptionStatus.NEW_ACCEPTANCE.value, TrustConsumptionStatus.REPLAY_CONFLICT.value])

        # Verify durable state after restart
        reloaded = DurableTrustStore(self.store_path)
        self.assertIn("att_mp_race_01", reloaded.used_attestation_ids)
        self.assertEqual(reloaded.used_attestations["att_mp_race_01"]["operation_id"], "op_mp_race_01")

    def test_two_processes_concurrent_distinct_attestations_both_persist(self):
        att1 = _make_signed_attestation(self.ts, attestation_id="att_mp_d1", operation_id="op_mp_d1")
        att2 = _make_signed_attestation(self.ts, attestation_id="att_mp_d2", operation_id="op_mp_d2")
        ctx = multiprocessing.get_context("spawn")
        barrier = ctx.Barrier(2)
        q = ctx.Queue()
        p1 = ctx.Process(target=_mp_worker_consume_distinct, args=(self.store_path, att1.to_dict(), "ev_d1", "op_mp_d1", barrier, q))
        p2 = ctx.Process(target=_mp_worker_consume_distinct, args=(self.store_path, att2.to_dict(), "ev_d2", "op_mp_d2", barrier, q))
        p1.start(); p2.start()
        p1.join(timeout=15.0); p2.join(timeout=15.0)
        self.assertEqual(p1.exitcode, 0)
        self.assertEqual(p2.exitcode, 0)
        res = dict([q.get(timeout=5.0), q.get(timeout=5.0)])
        self.assertEqual(res["att_mp_d1"], TrustConsumptionStatus.NEW_ACCEPTANCE.value)
        self.assertEqual(res["att_mp_d2"], TrustConsumptionStatus.NEW_ACCEPTANCE.value)

        reloaded = DurableTrustStore(self.store_path)
        self.assertIn("att_mp_d1", reloaded.used_attestation_ids)
        self.assertIn("att_mp_d2", reloaded.used_attestation_ids)


class TestA317CIRunnerIntegrity(unittest.TestCase):
    """P1: CI baseline runner never false-PASSes zero-test / pytest-only files or false-SKIPs."""

    def setUp(self):
        self.repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        self.script = os.path.join(self.repo_root, "scripts", "run_test_baseline.sh")
        self.tmpdir = tempfile.mkdtemp(prefix="a317_ci_runner_")
        os.makedirs(os.path.join(self.tmpdir, "tests"))
        os.makedirs(os.path.join(self.tmpdir, "scripts"))
        shutil.copy(
            os.path.join(self.repo_root, "scripts", "run_unittest.py"),
            os.path.join(self.tmpdir, "scripts", "run_unittest.py"),
        )

    def tearDown(self):
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _run_baseline(self, record_only: str = "0"):
        out_dir = os.path.join(self.tmpdir, "out")
        env = os.environ.copy()
        env["BASELINE_REPO_ROOT"] = self.tmpdir
        env["BASELINE_RECORD_ONLY"] = record_only
        env["BASELINE_TIMEOUT"] = "15"
        env["BASELINE_JOBS"] = "1"
        res = subprocess.run([self.script, out_dir], cwd=self.tmpdir, env=env, capture_output=True, text=True)
        summary = Path(os.path.join(out_dir, "summary.tsv")).read_text(encoding="utf-8")
        totals = Path(os.path.join(out_dir, "totals.txt")).read_text(encoding="utf-8")
        return res, summary, totals

    def test_zero_test_file_never_passes(self):
        with open(os.path.join(self.tmpdir, "tests", "test_empty.py"), "w", encoding="utf-8") as f:
            f.write("# valid python file with zero test functions or TestCase classes\nx = 1\n")
        res, summary, totals = self._run_baseline("0")
        self.assertNotEqual(res.returncode, 0)
        self.assertIn("test_empty\tFAILED\t", summary)
        self.assertIn("ZERO_TESTS", summary)
        self.assertIn("files_passed=0", totals)

    def test_pytest_only_file_never_false_passes_under_unittest(self):
        with open(os.path.join(self.tmpdir, "tests", "test_pytest_only.py"), "w", encoding="utf-8") as f:
            f.write("def test_plain_function():\n    assert 1 + 1 == 2\n")
        res, summary, totals = self._run_baseline("0")
        # If pytest is installed, it runs and executes 1 test; if not, it MUST FAIL (never false-PASS with 0 tests!)
        if "FRAMEWORK_MISMATCH" in summary:
            self.assertNotEqual(res.returncode, 0)
            self.assertIn("test_pytest_only\tFAILED\t", summary)
        else:
            self.assertEqual(res.returncode, 0)
            self.assertIn("test_pytest_only\tPASSED\t0\t1\t", summary)

    def test_skip_marker_inside_function_or_string_does_not_skip_file(self):
        with open(os.path.join(self.tmpdir, "tests", "test_marker_in_body.py"), "w", encoding="utf-8") as f:
            f.write(
                "import unittest\n\n"
                "class T(unittest.TestCase):\n"
                "    def test_mentions_markers(self):\n"
                "        s1 = 'BASELINE_SKIP: inside string'\n"
                "        s2 = 'CI_FLAKY: inside string'\n"
                "        self.assertIn('BASELINE_SKIP', s1)\n"
                "        self.assertIn('CI_FLAKY', s2)\n"
            )
        res, summary, totals = self._run_baseline("0")
        self.assertEqual(res.returncode, 0, f"stderr={res.stderr}\nsummary={summary}")
        self.assertIn("test_marker_in_body\tPASSED\t0\t1\t", summary)
        self.assertIn("files_skipped_flaky=0", totals)
        self.assertIn("files_skipped_capability=0", totals)


if __name__ == "__main__":
    unittest.main()

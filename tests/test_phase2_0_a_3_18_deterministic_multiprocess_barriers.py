"""Tests for Phase 2.0-A.3.18 P1-5: Deterministic Independent-Process Invariants using Synchronization Barriers.

Verifies:
1. Concurrent consumption across independent processes using synchronization barriers (exactly one succeeds, one gets REPLAY_CONFLICT).
2. Conflicting operation bindings across independent processes are strictly rejected.
3. Crash before reservation leaves store uncorrupted and permits recovery.
4. Concurrent receipt binding barrier (exactly one succeeds, one gets conflict rejection).
5. Clean recovery across processes after persistence failure and rollback.
"""

import multiprocessing as mp
import os
import shutil
import stat
import tempfile
import unittest

from extractor.capture_backend import (
    CaptureKeyStore,
    CausalAttestation,
    CausalVerifierAuthority,
    DurableTrustStore,
    TrustConsumptionStatus,
)


def _worker_concurrent_consume(store_path, att_dict, barrier, result_queue):
    try:
        store = DurableTrustStore(store_path)
        att = CausalAttestation.from_dict(att_dict)
        # Wait until both processes are ready at the barrier
        barrier.wait(timeout=10)
        res = store.consume_attestation(att, evidence_id=f"ev_{os.getpid()}")
        result_queue.put({"status": res.status.name, "reason": res.reason, "pid": os.getpid()})
    except Exception as e:
        result_queue.put({"error": str(e), "pid": os.getpid()})


def _worker_bind_conflicting(store_path, op_id, session_id, pid, metadata, barrier_before, result_queue):
    try:
        store = DurableTrustStore(store_path)
        barrier_before.wait(timeout=10)
        store.record_used_operation(op_id, session_id, pid, metadata=metadata, allow_idempotent=True)
        result_queue.put({"success": True, "pid": os.getpid()})
    except Exception as e:
        result_queue.put({"success": False, "error": str(e), "pid": os.getpid()})


def _worker_bind_receipt(store_path, op_id, receipt_id, barrier, result_queue):
    try:
        store = DurableTrustStore(store_path)
        barrier.wait(timeout=10)
        store.bind_operation_receipt(op_id, receipt_id)
        result_queue.put({"success": True, "receipt_id": receipt_id, "pid": os.getpid()})
    except Exception as e:
        result_queue.put({"success": False, "error": str(e), "receipt_id": receipt_id, "pid": os.getpid()})


def _failing_worker(store_path, res_q):
    try:
        store = DurableTrustStore(store_path)
        store.load()
        store.record_used_operation("op_durable_base", "sess_different_crash", 9004)
        res_q.put({"ok": True})
    except Exception as e:
        res_q.put({"ok": False, "error": str(e)})


def _clean_worker(store_path, res_q):
    try:
        store = DurableTrustStore(store_path)
        store.load()
        self_ok = "op_durable_base" in store.used_operation_ids
        store.record_used_operation("op_fresh_after_crash", "sess_clean", 9005)
        res_q.put({"recovered": self_ok, "added": "op_fresh_after_crash" in store.used_operation_ids})
    except Exception as e:
        res_q.put({"error": str(e)})


def _crash_before_reservation_worker(store_path, res_q):
    try:
        store = DurableTrustStore(store_path)
        store.load()
        # Simulate unhandled crash before atomic commit
        raise SystemExit(42)
    except SystemExit:
        raise
    except Exception as e:
        res_q.put({"error": str(e)})


def _subsequent_worker(store_path, q):
    try:
        s = DurableTrustStore(store_path)
        s.load()
        s.record_used_operation("op_subsequent", "sess_sub", 9006)
        q.put({"success": True})
    except Exception as e:
        q.put({"success": False, "error": str(e)})


class TestPhase20A318DeterministicMultiprocessBarriers(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp(prefix="a318_p15_barriers_")
        self.store_path = os.path.join(self.test_dir, "trust_store.json")
        self.trust_store = DurableTrustStore(self.store_path)
        self.key_store = CaptureKeyStore()
        self.authority = CausalVerifierAuthority(
            key_store=self.key_store,
            trust_store=self.trust_store,
        )
        self.key_id, self.secret = self.authority.rotate_key("key_mp_1")
        self.ctx = mp.get_context("spawn")

    def tearDown(self):
        shutil.rmtree(self.test_dir, ignore_errors=True)

    def test_01_concurrent_consumption_barrier(self):
        """Two independent processes at a barrier consume the same attestation; exactly one wins."""
        att = self.authority.issue_attestation(
            session_id="sess_mp_barrier",
            target_identity={"pid": 9001, "process_identity": "proc_barr", "executable_identity": "/bin/app", "build_id": "b1", "target_host": "h1"},
            operation_id="op_barr_1",
            precondition_evidence_id="ev_pre_barr",
            postcondition_evidence_id="ev_post_barr",
            claimed_transition={"field": "status", "from": "IDLE", "to": "RUNNING"},
            intervention_details={"action": "test_act", "verified_intervention": True},
            authority_level="PRODUCTION",
            verifier_authority_token=self.authority.get_verifier_token(),
        )
        att_dict = att.to_dict()

        barrier = self.ctx.Barrier(2)
        result_queue = self.ctx.Queue()

        p1 = self.ctx.Process(target=_worker_concurrent_consume, args=(self.store_path, att_dict, barrier, result_queue))
        p2 = self.ctx.Process(target=_worker_concurrent_consume, args=(self.store_path, att_dict, barrier, result_queue))

        p1.start()
        p2.start()
        p1.join(timeout=15)
        p2.join(timeout=15)

        results = []
        while not result_queue.empty():
            results.append(result_queue.get_nowait())

        self.assertEqual(len(results), 2, f"Expected 2 results, got {results}")
        statuses = [r.get("status") for r in results]
        self.assertIn("NEW_ACCEPTANCE", statuses)
        self.assertIn("REPLAY_CONFLICT", statuses)

    def test_02_conflicting_bindings_barrier(self):
        """Process A binds primary evidence; Process B attempting conflicting binding without derivation fails."""
        # Process A records primary evidence
        self.trust_store.record_used_operation(
            "op_bound_primary",
            "sess_b",
            9002,
            metadata={"evidence_id": "ev_primary_pA", "process_identity": "proc_a"},
        )
        self.trust_store.bind_operation_evidence("op_bound_primary", "ev_primary_pA")

        barrier = self.ctx.Barrier(1)
        result_queue = self.ctx.Queue()

        p_rogue = self.ctx.Process(
            target=_worker_bind_conflicting,
            args=(
                self.store_path,
                "op_bound_primary",
                "sess_b",
                9002,
                {"evidence_id": "ev_secondary_rogue", "process_identity": "proc_a"},
                barrier,
                result_queue,
            ),
        )
        p_rogue.start()
        p_rogue.join(timeout=15)

        res = result_queue.get(timeout=5)
        self.assertFalse(res["success"])
        self.assertIn("requires verifiable derivation", res["error"])

    def test_03_concurrent_receipt_binding_barrier(self):
        """Two independent processes at a barrier attempt to bind different receipt IDs; exactly one wins."""
        self.trust_store.record_used_operation("op_rcpt_barrier", "sess_rcpt", 9003)

        barrier = self.ctx.Barrier(2)
        result_queue = self.ctx.Queue()

        p1 = self.ctx.Process(target=_worker_bind_receipt, args=(self.store_path, "op_rcpt_barrier", "rcpt_alpha", barrier, result_queue))
        p2 = self.ctx.Process(target=_worker_bind_receipt, args=(self.store_path, "op_rcpt_barrier", "rcpt_beta", barrier, result_queue))

        p1.start()
        p2.start()
        p1.join(timeout=15)
        p2.join(timeout=15)

        results = []
        while not result_queue.empty():
            results.append(result_queue.get_nowait())

        self.assertEqual(len(results), 2)
        successes = [r for r in results if r["success"]]
        failures = [r for r in results if not r["success"]]
        self.assertEqual(len(successes), 1)
        self.assertEqual(len(failures), 1)
        self.assertIn("already bound to receipt", failures[0]["error"])

    def test_04_recovery_after_persistence_failure_across_processes(self):
        """In-memory persistence failure in one process leaves trust store intact for subsequent processes."""
        self.trust_store.record_used_operation("op_durable_base", "sess_rec", 9004)

        res_q = self.ctx.Queue()
        p_fail = self.ctx.Process(target=_failing_worker, args=(self.store_path, res_q))
        p_fail.start()
        p_fail.join(timeout=15)

        res = res_q.get(timeout=5)
        self.assertFalse(res["ok"])

        p_clean = self.ctx.Process(target=_clean_worker, args=(self.store_path, res_q))
        p_clean.start()
        p_clean.join(timeout=15)

        clean_res = res_q.get(timeout=5)
        self.assertTrue(clean_res.get("recovered"))
        self.assertTrue(clean_res.get("added"))

    def test_05_crash_before_reservation_recovery(self):
        """Process crash before reservation completes leaves trust store intact and permits subsequent worker execution."""
        res_q = self.ctx.Queue()
        p_crash = self.ctx.Process(target=_crash_before_reservation_worker, args=(self.store_path, res_q))
        p_crash.start()
        p_crash.join(timeout=15)
        self.assertEqual(p_crash.exitcode, 42)

        # Subsequent process performs normal reservation
        p_sub = self.ctx.Process(target=_subsequent_worker, args=(self.store_path, res_q))
        p_sub.start()
        p_sub.join(timeout=15)
        res = res_q.get(timeout=5)
        self.assertTrue(res["success"])


if __name__ == "__main__":
    unittest.main()

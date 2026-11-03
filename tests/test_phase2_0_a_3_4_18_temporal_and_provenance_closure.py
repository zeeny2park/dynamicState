"""Phase 2.0-A.3.4.18 — Temporal Semantics & Full Provenance Graph Closure.

Comprehensive verification of:
1. Temporal Semantics:
   - *_time_ms and *_at_ms represent Unix epoch milliseconds.
   - *_duration_ms represents elapsed monotonic time.
   - Never use max() to conceal regressions; detect and reject regressions.
   - Clock jump forward/backward handling without duration distortion.
2. Batch Contract vs Actual Slice Verification:
   - BatchReadRecord is authoritative expected contract.
   - Matching address, requested_size, physical_read_id, physical_consumption_id.
   - Detection of missing slices, unexpected slices, metadata mismatches.
3. Reservation Registry Lifecycle:
   - Explicit ownership across _active, _released, _committed registries.
   - Duplicate membership detection (Invariant 23).
   - Read-only reconciliation non-mutation guarantee.
4. Exactly-Once Accounting Reconstruction:
   - Bottom-up reconstruction from individual physical reads and consumption.
   - Failure conservatism (unknown consumption never zero).
5. Production Invocation Boundary Audit:
   - find_processes and capture_snapshot_via_collector runtime verification.
   - Preflight rejection vs execution failure distinction.
6. Concurrency and Immutability Stress:
   - No mutable internal record escapes public getters.
   - High-concurrency stress test with zero deadlock and full reconciliation.
"""

import base64
import copy
import dataclasses
import json
import math
import os
import re
import threading
import time
import unittest
import uuid
from typing import Any, Dict, List, Optional, Tuple

from extractor.observation_budget import (
    ActiveOperationScope,
    BatchReadRecord,
    BatchSliceSpec,
    BudgetReservation,
    CommittedTransactionSnapshot,
    ObservationAccountingRecord,
    ObservationBudgetLimits,
    ObservationBudgetTracker,
    PhysicalConsumptionRecord,
    PhysicalReadRecord,
    RemoteInvocationRecord,
)
from extractor.target_adapter import (
    LocalTargetAdapter,
    RemoteSshTargetAdapter,
)


class MockCommandRunnerA3418:
    """Mock command runner with fine-grained failure injection and call interception."""

    def __init__(self):
        self.invocations: List[Dict[str, Any]] = []
        self.fail_before_execution = False
        self.raise_exception: Optional[Exception] = None
        self.timeout_sec: Optional[float] = None
        self.return_code = 0
        self.stdout_payload = "OK\n"
        self.stderr_payload = ""
        self.collector_supported = True
        self.delay_sec: float = 0.0
        self.on_command = None
        self._lock = threading.Lock()

    def check_preflight(self, cmd_args: List[str]) -> Tuple[bool, Optional[str]]:
        if self.fail_before_execution:
            return False, "preflight runner rejection"
        return True, None

    def __call__(self, cmd_args: List[str], timeout: float) -> Tuple[int, str, str]:
        if self.delay_sec > 0:
            time.sleep(self.delay_sec)
        with self._lock:
            self.invocations.append({
                "cmd": list(cmd_args),
                "timeout": timeout,
                "timestamp": time.time(),
            })

        if self.raise_exception is not None:
            raise self.raise_exception

        cmd_str = " ".join(cmd_args) if isinstance(cmd_args, (list, tuple)) else str(cmd_args)

        if self.on_command is not None:
            return self.on_command(cmd_str, timeout)

        if not self.collector_supported and ("dynamicstate-collector" in cmd_str or "--read-slices" in cmd_str):
            return 127, "", "dynamicstate-collector: command not found\n"

        # Collector memory batch read
        if "--read-slices" in cmd_str:
            m = re.search(r"--read-slices\s+([^\s]+)", cmd_str)
            raw_slices = []
            if m:
                spec_str = m.group(1).strip("'\"")
                for part in spec_str.split(","):
                    if ":" in part:
                        addr_str, sz_str = part.split(":")
                        sz = int(sz_str)
                        raw_slices.append({"status": "OBSERVED", "hex": "aa" * sz})
            payload = json.dumps({"success": True, "slices": raw_slices})
            return 0, payload + "\n", ""

        # Shell dd memory read
        if "dd if=/proc/" in cmd_str and "base64" in cmd_str:
            m = re.search(r"count=(\d+)", cmd_str)
            cnt = int(m.group(1)) if m else 32
            b64 = base64.b64encode(b"A" * cnt).decode("ascii")
            if "0|" in cmd_str or "echo \"" in cmd_str:
                lines = [f"{idx}|{b64}" for idx in range(10)]
                return 0, "\n".join(lines) + "\n", ""
            return 0, b64 + "\n", ""

        # Collector snapshot
        if "collector_snapshot" in cmd_str or ("-m " in cmd_str and "--policy" in cmd_str):
            payload = json.dumps({
                "success": True,
                "status": "COMPLETE",
                "pid": 1234,
                "memory_regions": [],
                "bytes_captured": 1024,
            })
            return 0, payload + "\n", ""

        # find_processes script
        if "echo \"$pid|$comm|$exe|$cmd\"" in cmd_str:
            return 0, "1234|testproc|/bin/testproc|/bin/testproc -arg\n", ""

        return self.return_code, self.stdout_payload, self.stderr_payload


class TestPhase20A3418TemporalSemantics(unittest.TestCase):
    """1. Temporal Semantics Verification."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker()
        self.tracker.start()

    def test_01_wall_clock_moving_backward_detected_and_rejected_without_max(self):
        """1. Completion time earlier than start time raises ValueError without silently using max()."""
        inv_id = f"inv_{uuid.uuid4().hex[:12]}"
        t_start = 1700000000000.0  # Unix epoch ms
        self.tracker.record_invocation_started(
            invocation_id=inv_id,
            command_type="shell",
            physical_read_ids=["pread_1"],
            start_time_ms=t_start,
        )

        # Regressing completion timestamp (earlier than start)
        t_regress = t_start - 500.0
        with self.assertRaises(ValueError) as cm:
            self.tracker.record_invocation_completed(
                invocation_id=inv_id,
                completion_time_ms=t_regress,
                return_code=0,
                output_byte_count=10,
                outcome="COMPLETED",
            )
        self.assertIn("regression", str(cm.exception).lower())

    def test_02_system_clock_jump_forward_preserves_monotonic_elapsed_duration(self):
        """2. Monotonic duration reflects elapsed monotonic ns regardless of wall-clock jumps."""
        inv_id = f"inv_{uuid.uuid4().hex[:12]}"
        t_start = round(time.time() * 1000.0, 3)
        self.tracker.record_invocation_started(
            invocation_id=inv_id,
            command_type="shell",
            physical_read_ids=["pread_2"],
            start_time_ms=t_start,
        )

        time.sleep(0.02)
        # Wall clock jumped forward 1 hour (3600000 ms)
        t_jumped = t_start + 3600000.0
        self.tracker.record_invocation_completed(
            invocation_id=inv_id,
            completion_time_ms=t_jumped,
            return_code=0,
            output_byte_count=5,
            outcome="COMPLETED",
        )
        invs = self.tracker.get_invocation_records()
        rec = invs[inv_id]
        self.assertEqual(rec.completion_time_ms, t_jumped)
        self.assertIsNotNone(rec.duration_ms)
        # Monotonic duration should be ~20-50ms, NOT 3600000ms!
        self.assertLess(rec.duration_ms, 1000.0)
        self.assertGreaterEqual(rec.duration_ms, 10.0)

    def test_03_concurrent_invocations_monotonic_durations_independent(self):
        """3. Concurrent invocations compute independent monotonic durations without crosstalk."""
        runner = MockCommandRunnerA3418()
        adapter = RemoteSshTargetAdapter(
            host="127.0.0.1",
            port=22,
            user="testuser",
            command_runner=runner,
        )
        adapter.set_budget_tracker(self.tracker)

        def worker(idx: int):
            for i in range(5):
                rc, out, err = adapter.run_ssh(f"echo worker_{idx}_{i}")
                self.assertEqual(rc, 0)

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        invs = self.tracker.get_invocation_records()
        self.assertEqual(len(invs), 20)
        for inv in invs.values():
            self.assertIsNotNone(inv.duration_ms)
            self.assertGreaterEqual(inv.duration_ms, 0.0)
            self.assertLess(inv.duration_ms, 5000.0)

    def test_04_completion_before_start_rejected_explicitly(self):
        """4. RemoteInvocationRecord directly rejects completion_time_ms < start_time_ms."""
        with self.assertRaises(ValueError) as cm:
            RemoteInvocationRecord(
                invocation_id="inv_test_err",
                command_type="test",
                physical_read_ids=("pread_1",),
                start_time_ms=2000.0,
                completion_time_ms=1000.0,
                outcome="COMPLETED",
            )
        self.assertIn("regression", str(cm.exception).lower())

    def test_05_invalid_external_timestamps_rejected(self):
        """5. NaN, Inf, and negative timestamps are strictly rejected."""
        with self.assertRaises(ValueError):
            self.tracker.record_invocation_started(
                invocation_id="inv_neg",
                command_type="test",
                physical_read_ids=["pread_1"],
                start_time_ms=-1.0,
            )

        with self.assertRaises(ValueError):
            self.tracker.record_invocation_started(
                invocation_id="inv_nan",
                command_type="test",
                physical_read_ids=["pread_1"],
                start_time_ms=float("nan"),
            )

        with self.assertRaises(ValueError):
            self.tracker.record_invocation_started(
                invocation_id="inv_inf",
                command_type="test",
                physical_read_ids=["pread_1"],
                start_time_ms=float("inf"),
            )


class TestPhase20A3418BatchContractVerification(unittest.TestCase):
    """2. Batch Contract vs Actual Slice Verification."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker()
        self.tracker.start()

    def test_06_authoritative_contract_expected_slice_count_immutable(self):
        """6. BatchReadRecord is a frozen dataclass; expected_slice_count cannot be mutated."""
        batch = BatchReadRecord(
            batch_id="batch_imm",
            invocation_id="inv_imm",
            expected_slice_count=4,
            slices=(
                BatchSliceSpec(slice_index=0, address=0x1000, requested_size=64),
                BatchSliceSpec(slice_index=1, address=0x2000, requested_size=64),
                BatchSliceSpec(slice_index=2, address=0x3000, requested_size=64),
                BatchSliceSpec(slice_index=3, address=0x4000, requested_size=64),
            ),
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            batch.expected_slice_count = 5

    def test_07_slice_indices_unique_and_cover_range(self):
        """7. Registering batch contract requires unique slice indices."""
        batch_id = "batch_indices"
        inv_id = "inv_indices"
        self.tracker.record_invocation_started(inv_id, "batch", ["pread_0", "pread_1"])

        with self.assertRaises(ValueError) as cm:
            self.tracker.register_batch_contract(
                batch_id=batch_id,
                invocation_id=inv_id,
                expected_slice_count=2,
                slices=[
                    BatchSliceSpec(slice_index=0, address=0x1000, requested_size=32),
                    BatchSliceSpec(slice_index=0, address=0x2000, requested_size=32),
                ],
            )
        self.assertIn("duplicate", str(cm.exception).lower())

    def test_08_batch_reconciliation_verifies_actual_address_and_size_against_contract(self):
        """8. Mismatched address or size between contract and actual physical slice fails Invariant 20."""
        runner = MockCommandRunnerA3418()
        adapter = RemoteSshTargetAdapter(
            host="127.0.0.1",
            port=22,
            user="testuser",
            command_runner=runner,
            collector_path="/bin/collector",
        )
        adapter.set_budget_tracker(self.tracker)

        slices = [(0x1000, 32), (0x2000, 32)]
        res = adapter.read_memory_batch(1234, slices, budget_tracker=self.tracker)
        self.assertEqual(len(res), 2)

        # Mutate the registered contract's slice address to simulate adversarial mismatch
        b_key = list(self.tracker._batch_records.keys())[0]
        b_rec = self.tracker._batch_records[b_key]
        tampered_slices = (
            BatchSliceSpec(slice_index=0, address=0x9999, requested_size=32),
            BatchSliceSpec(slice_index=1, address=0x2000, requested_size=32),
        )
        tampered_batch = dataclasses.replace(b_rec, slices=tampered_slices)
        self.tracker._batch_records[b_key] = tampered_batch

        with self.assertRaises(AssertionError) as cm:
            self.tracker.reconcile_ledger()
        self.assertIn("Invariant 20", str(cm.exception))
        self.assertIn("address mismatch", str(cm.exception))

    def test_09_unexpected_slice_in_batch_detected(self):
        """9. A physical read slice with an index outside the contract fails Invariant 20."""
        runner = MockCommandRunnerA3418()
        adapter = RemoteSshTargetAdapter(
            host="127.0.0.1",
            port=22,
            user="testuser",
            command_runner=runner,
            collector_path="/bin/collector",
        )
        adapter.set_budget_tracker(self.tracker)

        slices = [(0x1000, 32), (0x2000, 32)]
        res = adapter.read_memory_batch(1234, slices, budget_tracker=self.tracker)
        self.assertEqual(len(res), 2)

        pread = list(self.tracker._physical_read_records.values())[0]
        tampered_spec = dict(pread.target_spec)
        tampered_spec["slice_index"] = 99
        pread.target_spec = tampered_spec

        with self.assertRaises(AssertionError) as cm:
            self.tracker.reconcile_ledger()
        self.assertIn("Invariant 20", str(cm.exception))
        self.assertIn("unexpected slice indices", str(cm.exception))

    def test_10_missing_slice_in_batch_detected(self):
        """10. Registered batch contract with 3 slices but only 2 physical reads fails Invariant 20."""
        batch_id = "batch_miss"
        inv_id = "inv_miss"
        self.tracker.record_invocation_started(inv_id, "batch", ["pread_0", "pread_1"])
        self.tracker.register_batch_contract(
            batch_id=batch_id,
            invocation_id=inv_id,
            expected_slice_count=3,
            slices=[
                BatchSliceSpec(slice_index=0, address=0x1000, requested_size=32),
                BatchSliceSpec(slice_index=1, address=0x2000, requested_size=32),
                BatchSliceSpec(slice_index=2, address=0x3000, requested_size=32),
            ],
        )

        with self.tracker.reservation(64, operation_id="op_miss") as res:
            cr0 = res.start_child_read(target_spec={"batch_id": batch_id, "invocation_id": inv_id, "slice_index": 0, "address": 0x1000, "requested_size": 32})
            cr0.mark_started()
            cr0.consume(32)
            cr1 = res.start_child_read(target_spec={"batch_id": batch_id, "invocation_id": inv_id, "slice_index": 1, "address": 0x2000, "requested_size": 32})
            cr1.mark_started()
            cr1.consume(32)

        self.tracker.commit_transaction(ObservationAccountingRecord(
            operation_id="op_miss",
            accounting_owner="TEST",
            measured_bytes_read=64,
            session_id=self.tracker.session_id,
        ))

        with self.assertRaises(AssertionError) as cm:
            self.tracker.reconcile_ledger()
        self.assertIn("Invariant 20", str(cm.exception))
        self.assertIn("slice 2 in contract has no matching physical read record", str(cm.exception))

    def test_11_slice_completion_status_consistent_with_read_lifecycle(self):
        """11. Slice completion status must be consistent with physical read lifecycle."""
        runner = MockCommandRunnerA3418()
        adapter = RemoteSshTargetAdapter(
            host="127.0.0.1",
            port=22,
            user="testuser",
            command_runner=runner,
            collector_path="/bin/collector",
        )
        adapter.set_budget_tracker(self.tracker)

        slices = [(0x1000, 32)]
        res = adapter.read_memory_batch(1234, slices, budget_tracker=self.tracker)
        self.assertEqual(len(res), 1)

        pread = list(self.tracker._physical_read_records.values())[0]
        pread.is_failure = True

        with self.assertRaises(AssertionError) as cm:
            self.tracker.reconcile_ledger()
        self.assertIn("Invariant 20", str(cm.exception))

    def test_12_orphan_physical_read_and_orphan_consumption_detected(self):
        """12. Orphan physical read or consumption record is caught by Invariant 22."""
        orphan_pcons = PhysicalConsumptionRecord(
            physical_consumption_id="pcons_orphan",
            physical_read_id="pread_nonexistent",
            reservation_id="res_nonexistent",
            operation_id="op_nonexistent",
            measured_bytes_read=64,
            estimated_bytes_read=0,
            charged_bytes=64,
            committed_at_ms=100.0,
        )
        self.tracker._physical_consumption_records["pcons_orphan"] = orphan_pcons

        with self.assertRaises(AssertionError) as cm:
            self.tracker.reconcile_ledger()
        self.assertIn("Invariant 22", str(cm.exception))
        self.assertIn("orphan physical consumption", str(cm.exception))


class TestPhase20A3418ReservationRegistryLifecycle(unittest.TestCase):
    """3. Reservation Registry Lifecycle & Exclusivity."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker()
        self.tracker.start()

    def test_13_reservation_registry_exclusivity(self):
        """13. Reservations move strictly through active -> released OR active -> committed."""
        res1 = self.tracker.admit_read(projected_bytes=100, profile_id="test")
        self.assertIn(res1.reservation_id, self.tracker.get_active_reservations())
        self.assertNotIn(res1.reservation_id, self.tracker.get_released_reservations())
        self.assertNotIn(res1.reservation_id, self.tracker.get_committed_reservations())

        self.tracker.release_reservation(res1)
        self.assertNotIn(res1.reservation_id, self.tracker.get_active_reservations())
        self.assertIn(res1.reservation_id, self.tracker.get_released_reservations())
        self.assertNotIn(res1.reservation_id, self.tracker.get_committed_reservations())

        with self.tracker.operation_scope("op_commit_res", profile_id="test") as scope:
            adm = scope.admit_read(50)
            scope.record_read(bytes_read=50, admission=adm)

        self.assertNotIn(adm.reservation_id, self.tracker.get_active_reservations())
        self.assertNotIn(adm.reservation_id, self.tracker.get_released_reservations())
        self.assertIn(adm.reservation_id, self.tracker.get_committed_reservations())

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_14_adversarial_duplicate_membership_in_active_and_released_detected(self):
        """14. Invariant 23 detects duplicate reservation membership in active and released registries."""
        res = self.tracker.admit_read(projected_bytes=100, profile_id="test")
        self.tracker._released_reservations[res.reservation_id] = res

        with self.assertRaises(AssertionError) as cm:
            self.tracker.reconcile_ledger()
        self.assertIn("Invariant 23", str(cm.exception))
        self.assertIn("active and released", str(cm.exception))

    def test_15_adversarial_duplicate_membership_in_active_and_committed_detected(self):
        """15. Invariant 23 detects duplicate reservation membership in active and committed registries."""
        res = self.tracker.admit_read(projected_bytes=100, profile_id="test")
        self.tracker._committed_reservations[res.reservation_id] = res

        with self.assertRaises(AssertionError) as cm:
            self.tracker.reconcile_ledger()
        self.assertIn("Invariant 23", str(cm.exception))
        self.assertIn("active and committed", str(cm.exception))

    def test_16_adversarial_duplicate_membership_in_released_and_committed_detected(self):
        """16. Invariant 23 detects duplicate reservation membership in released and committed registries."""
        res = self.tracker.admit_read(projected_bytes=100, profile_id="test")
        self.tracker.release_reservation(res)
        self.tracker._committed_reservations[res.reservation_id] = res

        with self.assertRaises(AssertionError) as cm:
            self.tracker.reconcile_ledger()
        self.assertIn("Invariant 23", str(cm.exception))
        self.assertIn("released and committed", str(cm.exception))

    def test_17_reconcile_ledger_is_read_only_and_does_not_mutate_registries(self):
        """17. Calling reconcile_ledger() does not mutate any tracker state or registry."""
        with self.tracker.operation_scope("op_readonly_test", profile_id="p1") as scope:
            adm = scope.admit_read(128)
            scope.record_read(bytes_read=128, admission=adm)

        active_before = list(self.tracker._active_reservations.keys())
        released_before = list(self.tracker._released_reservations.keys())
        committed_before = list(self.tracker._committed_reservations.keys())
        tx_before = list(self.tracker._committed_transactions.keys())
        pread_before = list(self.tracker._physical_read_records.keys())
        pcons_before = list(self.tracker._physical_consumption_records.keys())

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

        self.assertEqual(list(self.tracker._active_reservations.keys()), active_before)
        self.assertEqual(list(self.tracker._released_reservations.keys()), released_before)
        self.assertEqual(list(self.tracker._committed_reservations.keys()), committed_before)
        self.assertEqual(list(self.tracker._committed_transactions.keys()), tx_before)
        self.assertEqual(list(self.tracker._physical_read_records.keys()), pread_before)
        self.assertEqual(list(self.tracker._physical_consumption_records.keys()), pcons_before)


class TestPhase20A3418ExactlyOnceAccountingReconstruction(unittest.TestCase):
    """4. Bottom-Up Exactly-Once Accounting Reconstruction."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker()
        self.tracker.start()

    def test_18_reconstruct_accounting_bottom_up(self):
        """18. Reconstructed accounting exactly equals individual physical reads and consumption."""
        runner = MockCommandRunnerA3418()
        adapter = RemoteSshTargetAdapter(
            host="127.0.0.1",
            port=22,
            user="testuser",
            command_runner=runner,
            collector_path="/bin/collector",
        )
        adapter.set_budget_tracker(self.tracker)

        res1 = adapter.read_memory_batch(1001, [(0x1000, 64), (0x2000, 64), (0x3000, 64)], budget_tracker=self.tracker)
        self.assertEqual(len(res1), 3)

        d, st, err = adapter.read_memory(1001, 0x4000, 128, budget_tracker=self.tracker)
        self.assertIsNotNone(d)

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

        total_pread_charged = sum(cr.charged_bytes for cr in self.tracker._physical_read_records.values())
        total_pcons_charged = sum(pc.charged_bytes for pc in self.tracker._physical_consumption_records.values())
        total_tx_charged = sum(tx.charged_bytes for tx in self.tracker._committed_transactions.values())

        self.assertEqual(total_pread_charged, 320)
        self.assertEqual(total_pcons_charged, 320)
        self.assertEqual(total_tx_charged, 320)
        self.assertEqual(self.tracker.metrics.bytes_read, 320)

    def test_19_failed_or_unknown_read_cannot_silently_charge_zero(self):
        """19. An unmeasured read charging 0 bytes fails Invariant 24."""
        pread = PhysicalReadRecord(
            physical_read_id="pread_zero_unknown",
            reservation_id="res_zero",
            physical_consumption_id="pcons_zero",
            operation_id="op_zero",
            state="ACCOUNTED",
            charged_bytes=0,
            measured_bytes_read=None,
            estimated_bytes_read=0,
            is_failure=True,
        )
        self.tracker._physical_read_records["pread_zero_unknown"] = pread
        pcons = PhysicalConsumptionRecord(
            physical_consumption_id="pcons_zero",
            physical_read_id="pread_zero_unknown",
            reservation_id="res_zero",
            operation_id="op_zero",
            charged_bytes=0,
            measured_bytes_read=None,
            estimated_bytes_read=0,
            is_failure=True,
            committed_at_ms=100.0,
        )
        self.tracker._physical_consumption_records["pcons_zero"] = pcons

        with self.assertRaises(AssertionError) as cm:
            self.tracker.reconcile_ledger()
        self.assertIn("Invariant 24", str(cm.exception))
        self.assertIn("unmeasured/unknown read 'pread_zero_unknown' charged 0 bytes", str(cm.exception))

    def test_20_multi_slice_mixed_success_and_failure_exact_accounting(self):
        """20. Multi-slice batch with mixed success and failure accounts exactly."""
        runner = MockCommandRunnerA3418()
        adapter = RemoteSshTargetAdapter(
            host="127.0.0.1",
            port=22,
            user="testuser",
            command_runner=runner,
            collector_path="/bin/collector",
        )
        adapter.set_budget_tracker(self.tracker)

        def on_cmd(cmd, t):
            if "--read-slices" in cmd:
                return 0, json.dumps({
                    "success": True,
                    "slices": [
                        {"status": "OBSERVED", "hex": "aa" * 32},
                        {"status": "UNAVAILABLE", "hex": ""},
                    ],
                }), ""
            return 0, "OK\n", ""

        runner.on_command = on_cmd
        res = adapter.read_memory_batch(1234, [(0x1000, 32), (0x2000, 32)], budget_tracker=self.tracker)
        self.assertEqual(len(res), 2)
        self.assertEqual(res[0][1], "OBSERVED")
        self.assertEqual(res[1][1], "UNAVAILABLE")

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])


class TestPhase20A3418ProductionInvocationBoundary(unittest.TestCase):
    """5. Production Invocation Boundary Audit."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker()
        self.tracker.start()

    def test_21_find_processes_admission_and_invocation_boundary(self):
        """21. find_processes() creates admission, child read, and invocation records."""
        runner = MockCommandRunnerA3418()
        adapter = RemoteSshTargetAdapter(
            host="127.0.0.1",
            port=22,
            user="testuser",
            command_runner=runner,
        )
        adapter.set_budget_tracker(self.tracker)

        procs = adapter.find_processes("testproc", budget_tracker=self.tracker)
        self.assertEqual(len(procs), 1)
        self.assertEqual(procs[0]["pid"], 1234)

        invs = self.tracker.get_invocation_records()
        self.assertEqual(len(invs), 1)
        inv = list(invs.values())[0]
        self.assertEqual(inv.command_type, "find_processes")
        self.assertEqual(inv.outcome, "COMPLETED")
        self.assertGreater(inv.duration_ms, 0.0)

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_22_collector_snapshot_admission_and_invocation_boundary(self):
        """22. capture_snapshot_via_collector() properly records admission, child read, and invocation."""
        runner = MockCommandRunnerA3418()
        adapter = RemoteSshTargetAdapter(
            host="127.0.0.1",
            port=22,
            user="testuser",
            command_runner=runner,
            collector_path="/bin/collector",
        )
        adapter.set_budget_tracker(self.tracker)

        res = adapter.capture_snapshot_via_collector(1234, "/tmp/snap", max_mb=2, budget_tracker=self.tracker)
        self.assertTrue(res.get("success"))
        self.assertEqual(res.get("status"), "COMPLETE")

        invs = self.tracker.get_invocation_records()
        self.assertEqual(len(invs), 1)
        inv = list(invs.values())[0]
        self.assertEqual(inv.command_type, "collector_snapshot")
        self.assertEqual(inv.outcome, "COMPLETED")

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_23_preflight_rejection_vs_execution_failure_distinction(self):
        """23. Preflight runner rejection (rc=-2) leaves 0 physical bytes consumed and released reservation."""
        runner = MockCommandRunnerA3418()
        runner.fail_before_execution = True
        adapter = RemoteSshTargetAdapter(
            host="127.0.0.1",
            port=22,
            user="testuser",
            command_runner=runner,
            collector_path="/bin/collector",
        )
        adapter.set_budget_tracker(self.tracker)

        res = adapter.capture_snapshot_via_collector(1234, "/tmp/snap", max_mb=2, budget_tracker=self.tracker)
        self.assertFalse(res.get("success"))
        self.assertEqual(res.get("status"), "PREFLIGHT_REJECTED")

        self.assertEqual(self.tracker.metrics.bytes_read, 0)
        self.assertEqual(len(self.tracker.get_committed_transactions()), 0)

        invs = self.tracker.get_invocation_records()
        self.assertEqual(len(invs), 0)

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])


class TestPhase20A3418ConcurrencyAndImmutabilityStress(unittest.TestCase):
    """6. Concurrency and Immutability Stress."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker()
        self.tracker.start()

    def test_24_all_public_getters_return_independent_deep_copies(self):
        """24. Mutating snapshots or dictionaries returned by getters does not mutate internal tracker state."""
        runner = MockCommandRunnerA3418()
        adapter = RemoteSshTargetAdapter(
            host="127.0.0.1",
            port=22,
            user="testuser",
            command_runner=runner,
            collector_path="/bin/collector",
        )
        adapter.set_budget_tracker(self.tracker)

        res = adapter.read_memory_batch(1234, [(0x1000, 32)], budget_tracker=self.tracker)
        self.assertEqual(len(res), 1)

        txs = self.tracker.get_committed_transactions()
        txs["tampered_key"] = None
        self.assertNotIn("tampered_key", self.tracker.get_committed_transactions())

        reads = self.tracker.get_physical_read_records()
        reads["tampered_read"] = None
        self.assertNotIn("tampered_read", self.tracker.get_physical_read_records())

        cons = self.tracker.get_physical_consumption_records()
        cons["tampered_cons"] = None
        self.assertNotIn("tampered_cons", self.tracker.get_physical_consumption_records())

        com_res = self.tracker.get_committed_reservations()
        com_res["tampered_res"] = None
        self.assertNotIn("tampered_res", self.tracker.get_committed_reservations())

        invs = self.tracker.get_invocation_records()
        invs["tampered_inv"] = None
        self.assertNotIn("tampered_inv", self.tracker.get_invocation_records())

        batches = self.tracker.get_batch_records()
        batches["tampered_batch"] = None
        self.assertNotIn("tampered_batch", self.tracker.get_batch_records())

    def test_25_concurrent_stress_reads_commits_reconciliation_getters(self):
        """25. High-concurrency stress test with reads, commits, releases, reconciliations, and getters."""
        runner = MockCommandRunnerA3418()
        runner.delay_sec = 0.001
        adapter = RemoteSshTargetAdapter(
            host="127.0.0.1",
            port=22,
            user="testuser",
            command_runner=runner,
            collector_path="/bin/collector",
        )
        adapter.set_budget_tracker(self.tracker)

        errors: List[Exception] = []

        def worker_batch(idx: int):
            try:
                for i in range(5):
                    with self.tracker.operation_scope(f"op_batch_{idx}_{i}", profile_id="prof_batch"):
                        slices = [(0x1000 + i * 0x100, 16), (0x2000 + i * 0x100, 16)]
                        adapter.read_memory_batch(1000 + idx, slices, budget_tracker=self.tracker)
            except Exception as e:
                errors.append(e)

        def worker_single(idx: int):
            try:
                for i in range(5):
                    with self.tracker.operation_scope(f"op_single_{idx}_{i}", profile_id="prof_single"):
                        adapter.read_memory(2000 + idx, 0x5000 + i * 0x100, 32, budget_tracker=self.tracker)
            except Exception as e:
                errors.append(e)

        def worker_release(idx: int):
            try:
                for _ in range(5):
                    res = self.tracker.admit_read(64, profile_id=f"prof_{idx}")
                    time.sleep(0.001)
                    self.tracker.release_reservation(res)
            except Exception as e:
                errors.append(e)

        def worker_reconcile():
            try:
                for _ in range(10):
                    time.sleep(0.002)
                    self.tracker.reconcile_ledger()
                    self.tracker.get_committed_transactions()
                    self.tracker.get_physical_read_records()
                    self.tracker.get_invocation_records()
            except Exception as e:
                errors.append(e)

        threads = []
        for i in range(2):
            threads.append(threading.Thread(target=worker_batch, args=(i,)))
            threads.append(threading.Thread(target=worker_single, args=(i,)))
            threads.append(threading.Thread(target=worker_release, args=(i,)))
        threads.append(threading.Thread(target=worker_reconcile))

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])


if __name__ == "__main__":
    unittest.main()

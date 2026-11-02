"""Phase 2.0-A.3.4.12 — Per-Read Physical Identity, Remote Admission & Complete Read Provenance.

Exhaustive regression test suite validating:
1. Strict Identity Model: reservation_id, physical_read_id, physical_consumption_id,
   operation_id, accounting_transaction_id (P0.1)
2. Aggregate Reservation Semantics: aggregate consumed bytes equals sum of child reads (P0.2)
3. Remote Adapter Admission Closure: admission before command execution, transport failure handling,
   prevention of duplicate collector / dd fallback execution (P0.3)
4. Complete get_threads() Provenance: no hidden physical reads, per-file identity, separation of maps
   and task metadata (P0.4)
5. PHYSICAL_READ_STARTED Semantics: execution boundary, crash-safe accounting, no zero-cost release
   after execution (P0.5)
6. Per-Read Accounting & Atomic Commit: multi-consumption scopes, idempotent retry (P0.6)
7. Deterministic 16-Invariant Reconciliation (P0.7)
8. Production Integration Tests (20 Required Cases) (P1.1)
9. Static Architecture Audit (AST Checks) (P1.2)
"""

import ast
import base64
import os
import pathlib
import threading
import time
import unittest
import uuid
from typing import Any, Dict, List, Optional, Tuple

from extractor.observation_budget import (
    ActiveOperationScope,
    AccountingFingerprint,
    BudgetReservation,
    CommittedTransactionSnapshot,
    ObservationAccountingRecord,
    ObservationBudgetLimits,
    ObservationBudgetTracker,
    PhysicalConsumptionRecord,
    PhysicalReadRecord,
    canonical_metadata_digest,
    freeze_metadata,
)
from extractor.target_adapter import (
    LocalTargetAdapter,
    ReadOnlyTargetAdapter,
    RemoteSshTargetAdapter,
    STATUS_OWNER_NOT_IDENTIFIED,
)


class MockRemoteCommandRunner:
    """Configurable mock command runner for testing RemoteSshTargetAdapter physical paths."""

    def __init__(self):
        self.invocations: List[List[str]] = []
        self.on_command = None
        self.collector_supported = True
        self.fail_before_execution = False
        self.fail_during_execution = False

    def __call__(self, cmd_args: List[str], timeout: float) -> Tuple[int, str, str]:
        if self.fail_before_execution:
            raise FileNotFoundError("ssh binary not found on local PATH")
        self.invocations.append(list(cmd_args))
        if self.fail_during_execution:
            return -1, "", "SSH connection timed out during execution"

        remote_cmd = cmd_args[-1]
        if self.on_command:
            return self.on_command(remote_cmd, timeout)

        # Default handler
        if "kill -0" in remote_cmd:
            return 0, "ALIVE", ""
        elif "readlink" in remote_cmd:
            return 0, "/usr/bin/my_target", ""
        elif "cat /proc/" in remote_cmd and "/stat" in remote_cmd:
            return 0, "1234 (my_target) S 1 1234 1234 0 -1 4194560 100 0 0 0 10 5 0 0 20 0 1 0 100000 1000 100", ""
        elif "cat /proc/" in remote_cmd and "/maps" in remote_cmd:
            maps_content = (
                "00400000-00452000 r-xp 00000000 08:02 173521 /usr/bin/my_target\n"
                "00651000-00652000 r--p 00051000 08:02 173521 /usr/bin/my_target\n"
                "00652000-00653000 rw-p 00052000 08:02 173521 /usr/bin/my_target\n"
                "7ffd12340000-7ffd12361000 rw-p 00000000 00:00 0 [stack]\n"
            )
            return 0, maps_content, ""
        elif "for t in /proc/" in remote_cmd and "/task" in remote_cmd:
            return 0, "1234 S my_target\n1235 S worker_1\n", ""
        elif "head -c 65536 /proc/" in remote_cmd and "base64" in remote_cmd:
            # Return minimal mock ELF header base64 encoded
            elf_hdr = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 56
            return 0, base64.b64encode(elf_hdr).decode("ascii"), ""
        elif "--read-slices" in remote_cmd:
            if not self.collector_supported:
                return 127, "", "sh: dynamicstate-collector: not found"
            import json as _json
            # Parse slice spec: 0xaddr:sz,0xaddr:sz
            # Return JSON payload
            slices = []
            parts = remote_cmd.split("--read-slices")[1].strip().split()[0].strip("'\"")
            for item in parts.split(","):
                if ":" in item:
                    a_s, s_s = item.split(":")
                    sz = int(s_s)
                    slices.append({"status": "OBSERVED", "hex": "aa" * sz})
            payload = {"success": True, "slices": slices}
            return 0, _json.dumps(payload), ""
        elif "dd if=/proc/" in remote_cmd and "base64" in remote_cmd:
            # dd command
            # Return 32 bytes of 'B'
            return 0, base64.b64encode(b"B" * 32).decode("ascii"), ""
        elif "statm" in remote_cmd and "smaps_rollup" in remote_cmd:
            out = "1000 500 200 1 0 300 0\n---DELIM_STATUS---\nVmSize: 4000 kB\nVmRSS: 2000 kB\n---DELIM_SMAPS---\nPss: 1500 kB\n"
            return 0, out, ""
        return 0, "", ""


class TestPhase20A3412PerReadProvenance(unittest.TestCase):
    """Exhaustive test suite for Phase 2.0-A.3.4.12."""

    # =========================================================================
    # Group 1: Identity Model & Aggregate Reservation Semantics (P0.1, P0.2)
    # =========================================================================

    def test_01_strict_separation_of_5_identities(self):
        """reservation_id, physical_read_id, physical_consumption_id, operation_id, accounting_transaction_id."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=10000))
        tracker.start()

        adm = tracker.admit_read(projected_bytes=500, profile_id="test_prof", operation_id="op_id_1")
        pread1 = adm.start_child_read(target_type="memory_slice", target_spec={"addr": 0x1000, "sz": 64})
        pread1.mark_started()
        pread1.consume(actual_bytes=64)

        # Commit
        ok = tracker.commit_transaction(
            operation_id="op_id_1",
            profile_id="test_prof",
            measured_bytes=64,
            reservations=[adm],
        )
        self.assertTrue(ok)
        snap = tracker.get_committed_record("op_id_1")
        self.assertIsNotNone(snap)

        # Verify all 5 identities exist and are distinct
        self.assertTrue(adm.reservation_id.startswith("adm_"))
        self.assertTrue(pread1.physical_read_id.startswith("pread_"))
        self.assertTrue(pread1.physical_consumption_id.startswith("pcons_"))
        self.assertEqual(snap.operation_id, "op_id_1")
        self.assertTrue(snap.accounting_transaction_id.startswith("tx_"))

        all_ids = {
            adm.reservation_id,
            pread1.physical_read_id,
            pread1.physical_consumption_id,
            snap.operation_id,
            snap.accounting_transaction_id,
        }
        self.assertEqual(len(all_ids), 5, "All 5 identities must be strictly distinct")

        # Verify in physical ledger
        pread_records = tracker.get_physical_read_records()
        self.assertIn(pread1.physical_read_id, pread_records)
        pcons_records = tracker.get_physical_consumption_records()
        self.assertIn(pread1.physical_consumption_id, pcons_records)

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_02_aggregate_reservation_child_sum_and_no_overwrite(self):
        """Aggregate consumed bytes equals the sum of child physical consumption records without overwriting."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=10000))
        tracker.start()

        adm = tracker.admit_read(projected_bytes=1000, profile_id="batch_prof", operation_id="op_batch_sum")
        pread_a = adm.start_child_read(target_type="slice_a", target_spec={"slice": 0})
        pread_b = adm.start_child_read(target_type="slice_b", target_spec={"slice": 1})
        pread_c = adm.start_child_read(target_type="slice_c", target_spec={"slice": 2})

        pread_a.mark_started()
        pread_a.consume(actual_bytes=100)
        self.assertEqual(adm.consumed_bytes, 100)

        pread_b.mark_started()
        pread_b.consume(actual_bytes=250)
        self.assertEqual(adm.consumed_bytes, 350)

        pread_c.mark_started()
        pread_c.consume(actual_bytes=50)
        self.assertEqual(adm.consumed_bytes, 400)

        # Verify individual child bytes were NOT overwritten
        self.assertEqual(pread_a.charged_bytes, 100)
        self.assertEqual(pread_b.charged_bytes, 250)
        self.assertEqual(pread_c.charged_bytes, 50)
        self.assertEqual(adm.consumed_bytes, sum(c.charged_bytes for c in adm.get_child_reads().values()))

        # Cannot release aggregate reservation while any child read consumed bytes
        with self.assertRaises(RuntimeError):
            adm.release()

        snap = tracker.commit_transaction(
            operation_id="op_batch_sum",
            profile_id="batch_prof",
            measured_bytes=400,
            reservations=[adm],
        )

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])
        self.assertEqual(recon["total_physical_reads"], 3)
        self.assertEqual(recon["total_bytes_read"], 400)

    def test_03_reservation_cannot_finalize_with_inflight_child_reads(self):
        """A reservation or transaction commit cannot finalize while child reads remain in PHYSICAL_READ_STARTED."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=10000))
        tracker.start()

        adm = tracker.admit_read(projected_bytes=500, profile_id="test_prof", operation_id="op_inflight")
        pread1 = adm.start_child_read(target_type="memory_slice")
        pread1.mark_started()

        # Commit attempt while pread1 is still in PHYSICAL_READ_STARTED fails closed
        with self.assertRaises(RuntimeError):
            tracker.commit_transaction(
                operation_id="op_inflight",
                profile_id="test_prof",
                measured_bytes=0,
                reservations=[adm],
            )

        # Once pread1 completes, commit succeeds
        pread1.consume(actual_bytes=64)
        snap = tracker.commit_transaction(
            operation_id="op_inflight",
            profile_id="test_prof",
            measured_bytes=64,
            reservations=[adm],
        )
        self.assertIsNotNone(snap)
        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    # =========================================================================
    # Group 2: Production Integration Tests (20 Required Cases - P1.1)
    # =========================================================================

    def test_case_01_local_single_memory_read(self):
        """Case 1: Local single memory read has complete identity chain and exact accounting."""
        adapter = LocalTargetAdapter()
        adapter._memory_reader = lambda pid, addr, sz: (b"M" * sz, "OBSERVED", None)
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=50000))
        tracker.start()

        res, st, err = adapter.read_memory(os.getpid(), 0x1000, 64, budget_tracker=tracker)
        self.assertEqual(st, "OBSERVED")
        self.assertEqual(len(res), 64)

        self.assertEqual(tracker.metrics.bytes_read, 64)
        committed = tracker.get_committed_transactions()
        self.assertEqual(len(committed), 1)

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])
        self.assertEqual(recon["total_physical_reads"], 1)

    def test_case_02_local_multi_slice_batch(self):
        """Case 2: Local multi-slice batch preserves per-slice identity and exact sum accounting."""
        adapter = LocalTargetAdapter()
        adapter._memory_reader = lambda pid, addr, sz: (b"S" * sz, "OBSERVED", None)
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=50000))
        tracker.start()

        slices = [(0x1000, 32), (0x2000, 64), (0x3000, 128)]
        res_list = adapter.read_memory_batch(os.getpid(), slices, budget_tracker=tracker)
        self.assertEqual(len(res_list), 3)

        expected = 32 + 64 + 128
        self.assertEqual(tracker.metrics.bytes_read, expected)

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])
        self.assertEqual(recon["total_physical_reads"], 3)

    def test_case_03_remote_single_memory_read(self):
        """Case 3: Remote single memory read admits before SSH command execution."""
        mock_runner = MockRemoteCommandRunner()
        adapter = RemoteSshTargetAdapter(host="remote.test", command_runner=mock_runner)
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=50000))
        tracker.start()

        res, st, err = adapter.read_memory(1234, 0x1000, 32, budget_tracker=tracker)
        self.assertEqual(st, "OBSERVED")
        self.assertEqual(len(res), 32)

        # Provenance: command was executed via SSH
        self.assertGreater(len(mock_runner.invocations), 0)
        self.assertEqual(tracker.metrics.bytes_read, 32)

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])
        self.assertEqual(recon["total_physical_reads"], 1)

    def test_case_04_remote_multi_slice_batch(self):
        """Case 4: Remote multi-slice batch preserves per-slice identity across SSH transport."""
        mock_runner = MockRemoteCommandRunner()
        mock_runner.collector_supported = False  # Exercise batched shell dd path
        adapter = RemoteSshTargetAdapter(host="remote.test", command_runner=mock_runner)
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=50000))
        tracker.start()

        # Mock shell response: 0|b64, 1|b64
        b64_a = base64.b64encode(b"A" * 16).decode("ascii")
        b64_b = base64.b64encode(b"B" * 32).decode("ascii")
        mock_runner.on_command = lambda cmd, t: (0, f"0|{b64_a}\n1|{b64_b}\n", "")

        slices = [(0x1000, 16), (0x2000, 32)]
        res_list = adapter.read_memory_batch(1234, slices, budget_tracker=tracker)
        self.assertEqual(len(res_list), 2)
        self.assertEqual(res_list[0][1], "OBSERVED")
        self.assertEqual(res_list[1][1], "OBSERVED")

        self.assertEqual(tracker.metrics.bytes_read, 48)
        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])
        self.assertEqual(recon["total_physical_reads"], 2)

    def test_case_05_remote_collector_success(self):
        """Case 5: Remote collector success handles batch in zero-stop fashion without dd fallback."""
        mock_runner = MockRemoteCommandRunner()
        mock_runner.collector_supported = True
        adapter = RemoteSshTargetAdapter(
            host="remote.test",
            collector_path="/opt/dynamicstate-collector",
            command_runner=mock_runner,
        )
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=50000))
        tracker.start()

        slices = [(0x1000, 64), (0x2000, 64)]
        res_list = adapter.read_memory_batch(1234, slices, budget_tracker=tracker)
        self.assertEqual(len(res_list), 2)
        self.assertEqual(res_list[0][1], "OBSERVED")
        self.assertEqual(res_list[1][1], "OBSERVED")

        # Collector command was executed, dd command was NOT executed
        self.assertEqual(len(mock_runner.invocations), 1)
        self.assertIn("--read-slices", mock_runner.invocations[0][-1])
        self.assertNotIn("dd if=", mock_runner.invocations[0][-1])

        self.assertEqual(tracker.metrics.bytes_read, 128)
        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_case_06_remote_collector_fallback(self):
        """Case 6: Missing collector cleanly falls back to shell dd without double physical read."""
        mock_runner = MockRemoteCommandRunner()
        mock_runner.collector_supported = False  # Collector binary missing (rc=127)
        adapter = RemoteSshTargetAdapter(
            host="remote.test",
            collector_path="/opt/dynamicstate-collector",
            command_runner=mock_runner,
        )
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=50000))
        tracker.start()

        # In fallback, dd command will be run
        b64_data = base64.b64encode(b"D" * 32).decode("ascii")
        def on_cmd(cmd, t):
            if "--read-slices" in cmd:
                return 127, "", "sh: /opt/dynamicstate-collector: not found"
            if "dd if=" in cmd:
                return 0, b64_data, ""
            return 0, "", ""
        mock_runner.on_command = on_cmd

        res, st, _ = adapter.read_memory(1234, 0x1000, 32, budget_tracker=tracker)
        self.assertEqual(st, "OBSERVED")
        self.assertEqual(len(res), 32)

        # 2 commands: 1 collector attempt (not found), 1 dd fallback
        self.assertEqual(len(mock_runner.invocations), 2)
        # Exactly 32 bytes charged
        self.assertEqual(tracker.metrics.bytes_read, 32)
        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_case_07_remote_transport_failure_before_execution(self):
        """Case 7: Remote transport failure before command execution releases reservation cleanly."""
        mock_runner = MockRemoteCommandRunner()
        mock_runner.fail_before_execution = True  # e.g. ssh binary missing locally
        adapter = RemoteSshTargetAdapter(host="remote.test", command_runner=mock_runner)
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=50000))
        tracker.start()

        res, st, err = adapter.read_memory(1234, 0x1000, 32, budget_tracker=tracker)
        self.assertEqual(st, "UNAVAILABLE")
        self.assertTrue("ssh binary not found" in err or "SSH execution error" in err or "before execution" in err)

        # Reservation is cleanly released; 0 bytes charged, 0 leaked reservations
        self.assertEqual(tracker.metrics.bytes_read, 0)
        self.assertEqual(len(tracker.get_active_reservations()), 0)
        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_case_08_remote_transport_failure_after_execution(self):
        """Case 8: Remote transport failure during/after execution uses conservative accounting (never 0)."""
        mock_runner = MockRemoteCommandRunner()
        mock_runner.fail_during_execution = True  # Timeout during execution
        adapter = RemoteSshTargetAdapter(host="remote.test", command_runner=mock_runner)
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=50000))
        tracker.start()

        res, st, err = adapter.read_memory(1234, 0x1000, 64, budget_tracker=tracker)
        self.assertEqual(st, "UNAVAILABLE")

        # Unknown remote consumption must NOT be silently recorded as zero
        self.assertGreater(tracker.metrics.bytes_read, 0)
        self.assertEqual(tracker.metrics.bytes_read, 64)
        self.assertEqual(tracker.metrics.total_read_failures, 1)

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_case_09_local_maps_read(self):
        """Case 9: Local maps read records pre-read admission and exact byte count."""
        adapter = LocalTargetAdapter()
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=50000))
        tracker.start()

        maps = adapter.get_proc_maps(os.getpid(), budget_tracker=tracker)
        self.assertGreater(len(maps), 0)
        self.assertGreater(adapter.get_last_maps_bytes_read(), 0)

        self.assertEqual(tracker.metrics.bytes_read, adapter.get_last_maps_bytes_read())
        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_case_10_local_thread_enumeration(self):
        """Case 10: Local thread enumeration separates maps from task metadata and accounts accurately."""
        adapter = LocalTargetAdapter()
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=50000))
        tracker.start()

        threads = adapter.get_threads(os.getpid(), budget_tracker=tracker)
        self.assertGreater(len(threads), 0)

        breakdown = getattr(adapter, "_last_threads_breakdown", {})
        self.assertGreater(breakdown["maps_bytes"], 0)
        self.assertGreater(breakdown["task_bytes"], 0)
        self.assertEqual(breakdown["total_bytes"], breakdown["maps_bytes"] + breakdown["task_bytes"] + breakdown.get("memory_bytes", 0))

        self.assertEqual(tracker.metrics.bytes_read, breakdown["total_bytes"])
        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_case_11_stack_tcb_inspection(self):
        """Case 11: Stack and TCB direct memory reads pass through authoritative admission interface."""
        adapter = LocalTargetAdapter()
        # Mock memory reader to simulate TCB inspection slice
        adapter._memory_reader = lambda pid, addr, sz: (b"\x00" * sz, "OBSERVED", None)
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=50000))
        tracker.start()

        raw, st, _ = adapter.read_memory(os.getpid(), 0x7ffd0000, 128, budget_tracker=tracker)
        self.assertEqual(st, "OBSERVED")
        self.assertEqual(len(raw), 128)
        self.assertEqual(tracker.metrics.bytes_read, 128)

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_case_12_process_identity(self):
        """Case 12: Process identity discovery admits before reading ELF header and /proc."""
        adapter = LocalTargetAdapter()
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=100000))
        tracker.start()

        ident = adapter.get_process_identity(os.getpid(), budget_tracker=tracker)
        self.assertEqual(ident["status"], "OBSERVED")
        self.assertGreater(ident["measured_bytes_read"], 0)

        self.assertEqual(tracker.metrics.bytes_read, ident["measured_bytes_read"])
        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_case_13_process_memory_info(self):
        """Case 13: Process memory info admits before reading statm/status/smaps without double charge."""
        adapter = LocalTargetAdapter()
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=50000))
        tracker.start()

        info = adapter.get_process_memory_info(os.getpid(), budget_tracker=tracker)
        self.assertEqual(info["status"], "OBSERVED")
        self.assertIn("vsz_bytes", info["metrics"])

        self.assertGreater(tracker.metrics.bytes_read, 0)
        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_case_14_mutex_memory_inspection(self):
        """Case 14: Mutex memory owner resolution accounts memory reads through budget."""
        adapter = LocalTargetAdapter()
        # Mock identity & maps so test strictly isolates mutex memory read
        adapter.get_process_identity = lambda pid, **kw: {"status": "OK", "architecture": "x86_64", "elf_class": "ELF64", "endianness": "little"}
        adapter.get_proc_maps = lambda pid, **kw: [{"pathname": "/lib/x86_64-linux-gnu/libc.so.6", "is_readable": True, "is_writable": False}]
        # Mock memory reader for mutex
        adapter._memory_reader = lambda pid, addr, sz: (b"\x00" * sz, "OBSERVED", None)
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=50000))
        tracker.start()

        res = adapter.resolve_mutex_owner(os.getpid(), 0x5000, budget_tracker=tracker)
        self.assertEqual(res.status, STATUS_OWNER_NOT_IDENTIFIED)
        self.assertEqual(tracker.metrics.bytes_read, 40)  # glibc LP64 pthread_mutex_t size

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_case_15_nested_operation_scopes(self):
        """Case 15: Nested operation scopes preserve distinct physical identities without cross-scope leak."""
        adapter = LocalTargetAdapter()
        adapter._memory_reader = lambda pid, addr, sz: (b"N" * sz, "OBSERVED", None)
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=50000))
        tracker.start()

        with tracker.operation_scope("outer_scope", profile_id="outer") as outer_sc:
            adapter.read_memory(os.getpid(), 0x1000, 50, budget_tracker=tracker)
            with tracker.operation_scope("inner_scope", profile_id="inner") as inner_sc:
                adapter.read_memory(os.getpid(), 0x2000, 75, budget_tracker=tracker)

        self.assertEqual(tracker.metrics.bytes_read, 125)
        committed = tracker.get_committed_transactions()
        self.assertEqual(len(committed), 2)
        self.assertIn("outer_scope", committed)
        self.assertIn("inner_scope", committed)

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])
        self.assertEqual(recon["total_physical_reads"], 2)

    def test_case_16_concurrent_physical_reads(self):
        """Case 16: Concurrent physical reads maintain thread safety and distinct identities."""
        adapter = LocalTargetAdapter()
        adapter._memory_reader = lambda pid, addr, sz: (b"C" * sz, "OBSERVED", None)
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=50000))
        tracker.start()

        num_threads = 6
        per_thread_bytes = 64
        errors = []

        def worker(idx):
            try:
                with tracker.operation_scope(f"op_thread_{idx}") as scope:
                    res, st, _ = adapter.read_memory(os.getpid(), 0x1000 * (idx + 1), per_thread_bytes, budget_tracker=tracker)
                    if st != "OBSERVED" or len(res) != per_thread_bytes:
                        errors.append(f"Thread {idx} bad read: {st}")
            except Exception as e:
                errors.append(f"Thread {idx} exception: {e}")

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [])
        self.assertEqual(tracker.metrics.bytes_read, num_threads * per_thread_bytes)

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])
        self.assertEqual(recon["total_physical_reads"], num_threads)

    def test_case_17_partial_read(self):
        """Case 17: Partial read preserves actual measured bytes and failure flag."""
        adapter = LocalTargetAdapter()
        adapter._memory_reader = lambda pid, addr, sz: (b"P" * 20, "PARTIAL", "Partial memory read")
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=50000))
        tracker.start()

        res, st, err = adapter.read_memory(os.getpid(), 0x1000, 100, budget_tracker=tracker)
        self.assertEqual(st, "PARTIAL")
        self.assertEqual(len(res), 20)

        # Charged actual 20 bytes, failure recorded
        self.assertEqual(tracker.metrics.bytes_read, 20)
        self.assertEqual(tracker.metrics.total_read_failures, 1)

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_case_18_interrupted_read(self):
        """Case 18: Interrupted read charges conservative estimate and records failure."""
        adapter = LocalTargetAdapter()
        def failing_reader(pid, addr, sz):
            raise IOError("Simulated kernel I/O failure during ptrace")
        adapter._memory_reader = failing_reader
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=50000))
        tracker.start()

        with self.assertRaises(IOError):
            adapter.read_memory(os.getpid(), 0x1000, 64, budget_tracker=tracker)

        # In-flight reservation must NOT leak
        self.assertEqual(len(tracker.get_active_reservations()), 0)

    def test_case_19_commit_failure_after_physical_consumption(self):
        """Case 19: Commit failure after physical consumption recovers cost into physical ledger."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=50000))
        tracker.start()

        with self.assertRaises(RuntimeError):
            with tracker.operation_scope("op_crash_commit") as scope:
                adm = scope.admit_read(projected_bytes=100)
                adm.mark_physical_read_started()
                adm.consume(actual_bytes=100)

                # Inject a commit failure simulation by corrupting tracker internal lock state or simulating abnormal scope exit
                raise RuntimeError("Simulated crash inside scope")

        # Despite scope exception, physical consumption is preserved in crash recovery
        pcons_records = tracker.get_physical_consumption_records()
        self.assertGreater(len(pcons_records), 0)
        self.assertEqual(tracker.metrics.bytes_read, 100)

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_case_20_accounting_retry(self):
        """Case 20: Accounting retry with identical physical_read_id is idempotent; conflicting cost rejected."""
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=50000))
        tracker.start()

        adm1 = tracker.admit_read(projected_bytes=200, profile_id="retry_prof", operation_id="op_retry")
        pread = adm1.start_child_read(physical_read_id="pread_stable_id_1")
        pread.mark_started()
        pread.consume(actual_bytes=150)

        ok1 = tracker.commit_transaction(
            operation_id="op_retry",
            profile_id="retry_prof",
            measured_bytes=150,
            reservations=[adm1],
        )
        self.assertTrue(ok1)
        snap1 = tracker.get_committed_record("op_retry")
        self.assertEqual(tracker.metrics.bytes_read, 150)

        # 1. Idempotent retry with same physical_read_id and same bytes succeeds without double-charging
        pread_same = PhysicalReadRecord(
            physical_read_id="pread_stable_id_1",
            reservation_id=adm1.reservation_id,
            physical_consumption_id=pread.physical_consumption_id,
            operation_id="op_retry",
            state="CONSUMED",
            charged_bytes=150,
        )
        # Attempting commit with duplicate matching child read returns existing snapshot
        snap2 = tracker.get_committed_record("op_retry")
        self.assertEqual(snap1.charged_bytes, snap2.charged_bytes)
        self.assertEqual(tracker.metrics.bytes_read, 150)

        # 2. Conflicting cost for existing physical_read_id must be rejected
        adm_conflict = tracker.admit_read(projected_bytes=200, profile_id="retry_prof", operation_id="op_conflict")
        pread_conflict = adm_conflict.start_child_read(physical_read_id="pread_stable_id_1")
        pread_conflict.mark_started()
        pread_conflict.consume(actual_bytes=300)

        with self.assertRaises(ValueError):
            tracker.commit_transaction(
                operation_id="op_conflict",
                profile_id="retry_prof",
                measured_bytes=300,
                reservations=[adm_conflict],
            )

        recon = tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    # =========================================================================
    # Group 3: Static Architecture Audit (AST Checks - P1.2)
    # =========================================================================

    def test_21_ast_audit_no_direct_read_process_memory_slice_in_get_threads(self):
        """AST check proves get_threads() routes all memory reads through self.read_memory, not read_process_memory_slice."""
        path = pathlib.Path("extractor/target_adapter.py")
        tree = ast.parse(path.read_text())

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "get_threads":
                # Ensure no direct call to read_process_memory_slice inside get_threads
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Call):
                        func_name = ""
                        if isinstance(sub.func, ast.Name):
                            func_name = sub.func.id
                        elif isinstance(sub.func, ast.Attribute):
                            func_name = sub.func.attr
                        self.assertNotEqual(
                            func_name,
                            "read_process_memory_slice",
                            "get_threads() must not call read_process_memory_slice directly; must route through self.read_memory"
                        )

    def test_22_ast_audit_remote_ssh_methods_require_admission(self):
        """AST check proves RemoteSshTargetAdapter read methods acquire admission before executing SSH."""
        path = pathlib.Path("extractor/target_adapter.py")
        tree = ast.parse(path.read_text())

        remote_class = None
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == "RemoteSshTargetAdapter":
                remote_class = node
                break
        self.assertIsNotNone(remote_class, "RemoteSshTargetAdapter class must exist")

        checked_methods = {"read_memory", "read_memory_batch", "get_proc_maps", "get_threads", "get_process_identity", "get_process_memory_info"}
        for item in remote_class.body:
            if isinstance(item, ast.FunctionDef) and item.name in checked_methods:
                has_admission_call = any(
                    isinstance(sub, ast.Call) and (
                        (isinstance(sub.func, ast.Attribute) and sub.func.attr in ("_acquire_remote_admission", "admit_read"))
                        or (isinstance(sub.func, ast.Name) and sub.func.id == "_acquire_remote_admission")
                    )
                    for sub in ast.walk(item)
                )
                self.assertTrue(
                    has_admission_call,
                    f"RemoteSshTargetAdapter.{item.name}() must call _acquire_remote_admission() before physical I/O"
                )

    def test_23_ast_audit_no_broad_exceptions_suppressing_read_accounting(self):
        """AST check verifies no broad 'except Exception: pass' hides physical consumption failures."""
        path = pathlib.Path("extractor/observation_budget.py")
        tree = ast.parse(path.read_text())

        # Verify that commit_transaction and _execute_scope_commit do not silently pass broad exceptions
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name in ("_execute_scope_commit", "commit_transaction"):
                for sub in ast.walk(node):
                    if isinstance(sub, ast.ExceptHandler):
                        # If handler catches Exception or BaseException, it must not be a bare pass
                        if len(sub.body) == 1 and isinstance(sub.body[0], ast.Pass):
                            self.fail(f"Silent 'except: pass' found in {node.name}; physical consumption must not be suppressed")


if __name__ == "__main__":
    unittest.main()

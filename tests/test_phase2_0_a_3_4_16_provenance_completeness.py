"""Phase 2.0-A.3.4.16 — Provenance Completeness & Invocation Identity Closure Test Suite.

Verifies:
- P0.1 Provable batch completeness (Invariant 20 overhaul, range [0, expected_slice_count),
       missing final/middle, duplicate/out-of-range indices, conflicting metadata, failure accounting)
- P0.2 Authoritative invocation identity contract (invocation_id, command_type, batch_id,
       runtime instrumentation, timestamps, outcome tracking, preflight rejection handling)
- P0.3 Reconciliation across committed history (Invariant 21 on committed records,
       Invariant 22 invocation provenance, orphan invocation/physical read detection)
- P0.4 In-flight & unknown reads budget accounting (profile ceiling math,
       multi-child in-flight reservation protection, concurrency barrier race, double-charge prevention)
- P1.1 Full remote read call graph verification (liveness, identity, memory info,
       proc maps, threads, single/batch memory, nested execution)
"""

import base64
import json
import os
import shutil
import struct
import tempfile
import threading
import time
import unittest
import uuid
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from extractor.observation_budget import (
    DEFAULT_CONSERVATIVE_UNKNOWN_BYTES,
    AccountingFingerprint,
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
    clone_frozen,
    freeze_metadata,
    unfreeze_metadata,
)
from extractor.target_adapter import (
    IDENTITY_UNAVAILABLE,
    IDENTITY_UNVERIFIED,
    IDENTITY_VERIFIED,
    RemoteSshTargetAdapter,
)


class MockCommandRunnerA3416:
    """Mock command runner recording invocation timestamps, order, parameters, and outcomes."""

    def __init__(self):
        self.invocations: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self.collector_supported: bool = True
        self.fail_before_execution: bool = False
        self.fail_during_execution: bool = False
        self.block_event: Optional[threading.Event] = None
        self.barrier: Optional[threading.Barrier] = None
        self.on_command: Optional[Callable[[str, float], Tuple[int, str, str]]] = None
        self.on_start_hook: Optional[Callable[[List[str]], None]] = None

    def check_preflight(self, cmd_args: List[str]) -> Tuple[bool, Optional[str]]:
        if self.fail_before_execution:
            return False, "ssh executable unavailable before process creation"
        return True, None

    def __call__(self, cmd_args: List[str], timeout: float) -> Tuple[int, str, str]:
        t_start = time.monotonic()
        cmd_str = cmd_args[-1] if cmd_args else ""
        inv_record = {
            "start_time": t_start,
            "cmd_args": list(cmd_args),
            "cmd_str": cmd_str,
            "timeout": timeout,
            "completed": False,
        }
        with self._lock:
            self.invocations.append(inv_record)

        if self.on_start_hook:
            self.on_start_hook(cmd_args)

        if self.block_event:
            self.block_event.wait(timeout=2.0)

        if self.barrier:
            try:
                self.barrier.wait(timeout=2.0)
            except threading.BrokenBarrierError:
                pass

        if self.fail_during_execution:
            inv_record["error"] = "Transport failure during execution"
            inv_record["completion_time"] = time.monotonic()
            inv_record["completed"] = True
            return -1, "", "ssh: connect to host example.com port 22: Connection refused"

        if self.on_command:
            rc, out, err = self.on_command(cmd_str, timeout)
            inv_record["rc"] = rc
            inv_record["output_bytes"] = len(out.encode("utf-8")) if out else 0
            inv_record["completion_time"] = time.monotonic()
            inv_record["completed"] = True
            return rc, out, err

        # Default responders
        rc, out, err = 0, "", ""
        if "--read-slices" in cmd_str:
            if not self.collector_supported:
                rc, out, err = 127, "", "sh: dynamicstate-collector: not found"
            else:
                rc, out, err = 0, json.dumps({
                    "success": True,
                    "slices": [
                        {"status": "OBSERVED", "hex": "aa" * 32},
                        {"status": "OBSERVED", "hex": "bb" * 32},
                        {"status": "OBSERVED", "hex": "cc" * 32},
                    ]
                }), ""
        elif "dd if=" in cmd_str:
            b64_data = base64.b64encode(b"X" * 32).decode("ascii")
            if "echo \"" in cmd_str:
                rc, out, err = 0, "\n".join(f"{i}|{b64_data}" for i in range(10)) + "\n", ""
            else:
                rc, out, err = 0, b64_data, ""
        elif "kill -0" in cmd_str:
            rc, out, err = 0, "ALIVE", ""
        elif "readlink" in cmd_str:
            rc, out, err = 0, "/usr/bin/target_process", ""
        elif "stat -c" in cmd_str:
            rc, out, err = 0, "1234567 1700000000", ""
        elif "cat /proc/" in cmd_str and "stat" in cmd_str:
            rc, out, err = 0, "1234 (target_proc) S 1 1234 1234 0 -1 4194304 100 0 0 0 10 20 0 0 20 0 1 0 1234567 1000 100\n", ""
        elif "head -c" in cmd_str:
            elf_hdr = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + struct.pack("<HHI", 2, 0x3e, 1) + b"\x00" * 40
            rc, out, err = 0, base64.b64encode(elf_hdr).decode("ascii"), ""
        elif "/proc/" in cmd_str and "/status" in cmd_str:
            rc, out, err = 0, "VmRSS:\t   1024 kB\nVmSize:\t   2048 kB\n", ""
        elif "/proc/" in cmd_str and "/maps" in cmd_str:
            rc, out, err = 0, "00400000-00452000 r-xp 00000000 08:02 123456 /usr/bin/target\n", ""
        elif "/proc/" in cmd_str and "/task" in cmd_str:
            rc, out, err = 0, "1001 R worker_1\n1002 S worker_2\n", ""

        inv_record["rc"] = rc
        inv_record["output_bytes"] = len(out.encode("utf-8")) if out else 0
        inv_record["completion_time"] = time.monotonic()
        inv_record["completed"] = True
        return rc, out, err


class TestPhase20A3416BatchCompleteness(unittest.TestCase):
    """Section 2: Provable Batch Completeness & Invariant 20 Overhaul."""

    def setUp(self):
        self.limits = ObservationBudgetLimits(max_bytes_read=100000)
        self.tracker = ObservationBudgetTracker(limits=self.limits, session_id="test_sess_batch")

    def test_01_batch_completeness_happy_path(self):
        """Happy path: 3 slices in range [0, 3), matching metadata, successful reconciliation."""
        adm = self.tracker.admit_read(
            projected_bytes=192,
            profile_id="prof_batch",
        )
        inv_id = "inv_happy_1"
        self.tracker.record_invocation_started(
            invocation_id=inv_id,
            command_type="memory_batch",
            physical_read_ids=["cr_0", "cr_1", "cr_2"],
            batch_id="b_happy_1",
        )

        cr0 = adm.start_child_read(
            target_type="remote_collector_memory_slice",
            target_spec={"batch_id": "b_happy_1", "invocation_id": inv_id, "expected_slice_count": 3, "slice_index": 0, "address": 0x1000, "requested_size": 64, "completion_status": "OBSERVED"},
            physical_read_id="cr_0",
        )
        cr1 = adm.start_child_read(
            target_type="remote_collector_memory_slice",
            target_spec={"batch_id": "b_happy_1", "invocation_id": inv_id, "expected_slice_count": 3, "slice_index": 1, "address": 0x2000, "requested_size": 64, "completion_status": "OBSERVED"},
            physical_read_id="cr_1",
        )
        cr2 = adm.start_child_read(
            target_type="remote_collector_memory_slice",
            target_spec={"batch_id": "b_happy_1", "invocation_id": inv_id, "expected_slice_count": 3, "slice_index": 2, "address": 0x3000, "requested_size": 64, "completion_status": "OBSERVED"},
            physical_read_id="cr_2",
        )

        cr0.consume(actual_bytes=64, is_failure=False)
        cr1.consume(actual_bytes=64, is_failure=False)
        cr2.consume(actual_bytes=64, is_failure=False)

        self.tracker.record_invocation_completed(inv_id, return_code=0, output_byte_count=192, outcome="COMPLETED")

        self.tracker.commit_transaction(
            operation_id="op_batch_happy",
            profile_id="prof_batch",
            measured_bytes=192,
            reservations=[adm],
        )

        res = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(res["reconciled"])
        self.assertTrue(res["discrepancy_details"]["inv_20_batch_slice_completeness"])
        self.assertTrue(res["discrepancy_details"]["inv_22_invocation_provenance_and_orphan_detection"])

    def test_02_corruption_missing_final_slice(self):
        """Batch of 3 registered slices missing the final slice (index 2) triggers Invariant 20 failure."""
        adm = self.tracker.admit_read(
            projected_bytes=192,
            profile_id="prof_batch",
        )
        inv_id = "inv_mf_1"
        self.tracker.record_invocation_started(
            invocation_id=inv_id,
            command_type="memory_batch",
            physical_read_ids=["cr_mf_0", "cr_mf_1"],
            batch_id="b_missing_final",
        )

        cr0 = adm.start_child_read(
            target_type="remote_collector_memory_slice",
            target_spec={"batch_id": "b_missing_final", "invocation_id": inv_id, "expected_slice_count": 3, "slice_index": 0, "address": 0x1000, "requested_size": 64, "completion_status": "OBSERVED"},
            physical_read_id="cr_mf_0",
        )
        cr1 = adm.start_child_read(
            target_type="remote_collector_memory_slice",
            target_spec={"batch_id": "b_missing_final", "invocation_id": inv_id, "expected_slice_count": 3, "slice_index": 1, "address": 0x2000, "requested_size": 64, "completion_status": "OBSERVED"},
            physical_read_id="cr_mf_1",
        )
        # Slice 2 is omitted!
        cr0.consume(actual_bytes=64, is_failure=False)
        cr1.consume(actual_bytes=64, is_failure=False)
        self.tracker.record_invocation_completed(inv_id, return_code=0, output_byte_count=128, outcome="COMPLETED")

        self.tracker.commit_transaction(
            operation_id="op_batch_mf",
            profile_id="prof_batch",
            measured_bytes=128,
            reservations=[adm],
        )

        res = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(res["reconciled"])
        self.assertFalse(res["discrepancy_details"]["inv_20_batch_slice_completeness"])
        err_msg = "; ".join(res["discrepancies"])
        self.assertIn("missing slice indices: [2]", err_msg)

    def test_03_corruption_missing_middle_slice(self):
        """Batch of 3 registered slices missing the middle slice (index 1) triggers Invariant 20 failure."""
        adm = self.tracker.admit_read(
            projected_bytes=192,
            profile_id="prof_batch",
        )
        inv_id = "inv_mm_1"
        self.tracker.record_invocation_started(
            invocation_id=inv_id,
            command_type="memory_batch",
            physical_read_ids=["cr_mm_0", "cr_mm_2"],
            batch_id="b_missing_mid",
        )

        cr0 = adm.start_child_read(
            target_type="remote_collector_memory_slice",
            target_spec={"batch_id": "b_missing_mid", "invocation_id": inv_id, "expected_slice_count": 3, "slice_index": 0, "address": 0x1000, "requested_size": 64, "completion_status": "OBSERVED"},
            physical_read_id="cr_mm_0",
        )
        cr2 = adm.start_child_read(
            target_type="remote_collector_memory_slice",
            target_spec={"batch_id": "b_missing_mid", "invocation_id": inv_id, "expected_slice_count": 3, "slice_index": 2, "address": 0x3000, "requested_size": 64, "completion_status": "OBSERVED"},
            physical_read_id="cr_mm_2",
        )
        # Slice 1 is omitted!
        cr0.consume(actual_bytes=64, is_failure=False)
        cr2.consume(actual_bytes=64, is_failure=False)
        self.tracker.record_invocation_completed(inv_id, return_code=0, output_byte_count=128, outcome="COMPLETED")

        self.tracker.commit_transaction(
            operation_id="op_batch_mm",
            profile_id="prof_batch",
            measured_bytes=128,
            reservations=[adm],
        )

        res = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(res["reconciled"])
        self.assertFalse(res["discrepancy_details"]["inv_20_batch_slice_completeness"])
        err_msg = "; ".join(res["discrepancies"])
        self.assertIn("missing slice indices: [1]", err_msg)

    def test_04_corruption_duplicate_slice_index(self):
        """Batch with duplicate slice indices (0, 1, 1) triggers Invariant 20 failure."""
        adm = self.tracker.admit_read(
            projected_bytes=192,
            profile_id="prof_batch",
        )
        inv_id = "inv_dup_idx"
        self.tracker.record_invocation_started(
            invocation_id=inv_id,
            command_type="memory_batch",
            physical_read_ids=["cr_dup_0", "cr_dup_1a", "cr_dup_1b"],
            batch_id="b_dup_idx",
        )

        cr0 = adm.start_child_read(
            target_type="remote_collector_memory_slice",
            target_spec={"batch_id": "b_dup_idx", "invocation_id": inv_id, "expected_slice_count": 3, "slice_index": 0, "address": 0x1000, "requested_size": 64, "completion_status": "OBSERVED"},
            physical_read_id="cr_dup_0",
        )
        cr1a = adm.start_child_read(
            target_type="remote_collector_memory_slice",
            target_spec={"batch_id": "b_dup_idx", "invocation_id": inv_id, "expected_slice_count": 3, "slice_index": 1, "address": 0x2000, "requested_size": 64, "completion_status": "OBSERVED"},
            physical_read_id="cr_dup_1a",
        )
        cr1b = adm.start_child_read(
            target_type="remote_collector_memory_slice",
            target_spec={"batch_id": "b_dup_idx", "invocation_id": inv_id, "expected_slice_count": 3, "slice_index": 1, "address": 0x2000, "requested_size": 64, "completion_status": "OBSERVED"},
            physical_read_id="cr_dup_1b",
        )

        cr0.consume(actual_bytes=64, is_failure=False)
        cr1a.consume(actual_bytes=64, is_failure=False)
        cr1b.consume(actual_bytes=64, is_failure=False)
        self.tracker.record_invocation_completed(inv_id, return_code=0, output_byte_count=192, outcome="COMPLETED")

        self.tracker.commit_transaction(
            operation_id="op_batch_dup_idx",
            profile_id="prof_batch",
            measured_bytes=192,
            reservations=[adm],
        )

        res = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(res["reconciled"])
        self.assertFalse(res["discrepancy_details"]["inv_20_batch_slice_completeness"])
        err_msg = "; ".join(res["discrepancies"])
        self.assertIn("duplicate slice indices", err_msg)

    def test_05_corruption_out_of_range_slice_index(self):
        """Batch of 3 slices containing index 3 (expected [0, 3)) triggers Invariant 20 failure."""
        adm = self.tracker.admit_read(
            projected_bytes=192,
            profile_id="prof_batch",
        )
        inv_id = "inv_out_range"
        self.tracker.record_invocation_started(
            invocation_id=inv_id,
            command_type="memory_batch",
            physical_read_ids=["cr_or_0", "cr_or_1", "cr_or_3"],
            batch_id="b_out_range",
        )

        cr0 = adm.start_child_read(
            target_type="remote_collector_memory_slice",
            target_spec={"batch_id": "b_out_range", "invocation_id": inv_id, "expected_slice_count": 3, "slice_index": 0, "address": 0x1000, "requested_size": 64, "completion_status": "OBSERVED"},
            physical_read_id="cr_or_0",
        )
        cr1 = adm.start_child_read(
            target_type="remote_collector_memory_slice",
            target_spec={"batch_id": "b_out_range", "invocation_id": inv_id, "expected_slice_count": 3, "slice_index": 1, "address": 0x2000, "requested_size": 64, "completion_status": "OBSERVED"},
            physical_read_id="cr_or_1",
        )
        cr3 = adm.start_child_read(
            target_type="remote_collector_memory_slice",
            target_spec={"batch_id": "b_out_range", "invocation_id": inv_id, "expected_slice_count": 3, "slice_index": 3, "address": 0x3000, "requested_size": 64, "completion_status": "OBSERVED"},
            physical_read_id="cr_or_3",
        )

        cr0.consume(actual_bytes=64, is_failure=False)
        cr1.consume(actual_bytes=64, is_failure=False)
        cr3.consume(actual_bytes=64, is_failure=False)
        self.tracker.record_invocation_completed(inv_id, return_code=0, output_byte_count=192, outcome="COMPLETED")

        self.tracker.commit_transaction(
            operation_id="op_batch_or",
            profile_id="prof_batch",
            measured_bytes=192,
            reservations=[adm],
        )

        res = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(res["reconciled"])
        self.assertFalse(res["discrepancy_details"]["inv_20_batch_slice_completeness"])
        err_msg = "; ".join(res["discrepancies"])
        self.assertIn("out-of-range slice indices: [3]", err_msg)

    def test_06_corruption_slice_count_discrepancy(self):
        """Batch specifying expected_slice_count=4 with only 3 slices present fails Invariant 20."""
        adm = self.tracker.admit_read(
            projected_bytes=192,
            profile_id="prof_batch",
        )
        inv_id = "inv_cnt_disc"
        self.tracker.record_invocation_started(
            invocation_id=inv_id,
            command_type="memory_batch",
            physical_read_ids=["cr_cd_0", "cr_cd_1", "cr_cd_2"],
            batch_id="b_cnt_disc",
        )

        cr0 = adm.start_child_read(
            target_type="remote_collector_memory_slice",
            target_spec={"batch_id": "b_cnt_disc", "invocation_id": inv_id, "expected_slice_count": 4, "slice_index": 0, "address": 0x1000, "requested_size": 64, "completion_status": "OBSERVED"},
            physical_read_id="cr_cd_0",
        )
        cr1 = adm.start_child_read(
            target_type="remote_collector_memory_slice",
            target_spec={"batch_id": "b_cnt_disc", "invocation_id": inv_id, "expected_slice_count": 4, "slice_index": 1, "address": 0x2000, "requested_size": 64, "completion_status": "OBSERVED"},
            physical_read_id="cr_cd_1",
        )
        cr2 = adm.start_child_read(
            target_type="remote_collector_memory_slice",
            target_spec={"batch_id": "b_cnt_disc", "invocation_id": inv_id, "expected_slice_count": 4, "slice_index": 2, "address": 0x3000, "requested_size": 64, "completion_status": "OBSERVED"},
            physical_read_id="cr_cd_2",
        )

        cr0.consume(actual_bytes=64, is_failure=False)
        cr1.consume(actual_bytes=64, is_failure=False)
        cr2.consume(actual_bytes=64, is_failure=False)
        self.tracker.record_invocation_completed(inv_id, return_code=0, output_byte_count=192, outcome="COMPLETED")

        self.tracker.commit_transaction(
            operation_id="op_batch_cd",
            profile_id="prof_batch",
            measured_bytes=192,
            reservations=[adm],
        )

        res = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(res["reconciled"])
        self.assertFalse(res["discrepancy_details"]["inv_20_batch_slice_completeness"])
        err_msg = "; ".join(res["discrepancies"])
        self.assertIn("missing slice indices: [3]", err_msg)

    def test_07_corruption_duplicate_physical_read_id_in_batch(self):
        """Duplicate physical_read_id across slices in the same reservation raises ValueError."""
        adm = self.tracker.admit_read(
            projected_bytes=128,
            profile_id="prof_batch",
        )
        adm.start_child_read(
            target_type="remote_collector_memory_slice",
            target_spec={"batch_id": "b_dup_pid", "invocation_id": "inv_dup_pid", "expected_slice_count": 2, "slice_index": 0, "address": 0x1000, "requested_size": 64},
            physical_read_id="cr_shared_1",
        )
        with self.assertRaises(ValueError) as ctx:
            adm.start_child_read(
                target_type="remote_collector_memory_slice",
                target_spec={"batch_id": "b_dup_pid", "invocation_id": "inv_dup_pid", "expected_slice_count": 2, "slice_index": 1, "address": 0x2000, "requested_size": 64},
                physical_read_id="cr_shared_1",
            )
        self.assertIn("Duplicate physical_read_id", str(ctx.exception))

    def test_08_corruption_duplicate_physical_consumption_id_in_batch(self):
        """Attempting to reuse a physical_consumption_id within child reads fails deterministically."""
        adm = self.tracker.admit_read(
            projected_bytes=128,
            profile_id="prof_batch",
        )
        adm.start_child_read(
            target_type="remote_collector_memory_slice",
            target_spec={"batch_id": "b_dup_cid", "invocation_id": "inv_dup_cid", "expected_slice_count": 2, "slice_index": 0, "address": 0x1000, "requested_size": 64},
            physical_read_id="cr_cid_0",
            physical_consumption_id="shared_cid_123",
        )
        with self.assertRaises(ValueError) as ctx:
            adm.start_child_read(
                target_type="remote_collector_memory_slice",
                target_spec={"batch_id": "b_dup_cid", "invocation_id": "inv_dup_cid", "expected_slice_count": 2, "slice_index": 1, "address": 0x2000, "requested_size": 64},
                physical_read_id="cr_cid_1",
                physical_consumption_id="shared_cid_123",
            )
        self.assertIn("Duplicate physical_consumption_id", str(ctx.exception))

    def test_09_corruption_conflicting_address_or_size(self):
        """Conflicting address or requested size metadata across batch records triggers Invariant 20 failure."""
        adm = self.tracker.admit_read(
            projected_bytes=128,
            profile_id="prof_batch",
        )
        inv_id = "inv_conflict"
        self.tracker.record_invocation_started(
            invocation_id=inv_id,
            command_type="memory_batch",
            physical_read_ids=["cr_c_0", "cr_c_1"],
            batch_id="b_conflict",
        )

        cr0 = adm.start_child_read(
            target_type="remote_collector_memory_slice",
            target_spec={"batch_id": "b_conflict", "invocation_id": inv_id, "expected_slice_count": 2, "slice_index": 0, "address": 0x1000, "requested_size": 64, "completion_status": "OBSERVED"},
            physical_read_id="cr_c_0",
        )
        # Slices with contradictory metadata for the same slice index
        cr1 = adm.start_child_read(
            target_type="remote_collector_memory_slice",
            target_spec={"batch_id": "b_conflict", "invocation_id": inv_id, "expected_slice_count": 2, "slice_index": 0, "address": 0x9999, "requested_size": 128, "completion_status": "OBSERVED"},
            physical_read_id="cr_c_1",
        )
        cr0.consume(actual_bytes=64, is_failure=False)
        cr1.consume(actual_bytes=64, is_failure=False)
        self.tracker.record_invocation_completed(inv_id, return_code=0, output_byte_count=128, outcome="COMPLETED")

        self.tracker.commit_transaction(
            operation_id="op_batch_conflict",
            profile_id="prof_batch",
            measured_bytes=128,
            reservations=[adm],
        )

        res = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(res["reconciled"])
        self.assertFalse(res["discrepancy_details"]["inv_20_batch_slice_completeness"])
        err_msg = "; ".join(res["discrepancies"])
        self.assertIn("conflicting metadata", err_msg)

    def test_10_corruption_failed_slice_omitted(self):
        """When a failed slice is omitted from the batch record, Invariant 20 detects missing index."""
        adm = self.tracker.admit_read(
            projected_bytes=192,
            profile_id="prof_batch",
        )
        inv_id = "inv_fo_1"
        self.tracker.record_invocation_started(
            invocation_id=inv_id,
            command_type="memory_batch",
            physical_read_ids=["cr_fo_0", "cr_fo_2"],
            batch_id="b_failed_omit",
        )

        cr0 = adm.start_child_read(
            target_type="remote_collector_memory_slice",
            target_spec={"batch_id": "b_failed_omit", "invocation_id": inv_id, "expected_slice_count": 3, "slice_index": 0, "address": 0x1000, "requested_size": 64, "completion_status": "OBSERVED"},
            physical_read_id="cr_fo_0",
        )
        # Slice 1 failed in execution and was dropped/omitted from reporting
        cr2 = adm.start_child_read(
            target_type="remote_collector_memory_slice",
            target_spec={"batch_id": "b_failed_omit", "invocation_id": inv_id, "expected_slice_count": 3, "slice_index": 2, "address": 0x3000, "requested_size": 64, "completion_status": "OBSERVED"},
            physical_read_id="cr_fo_2",
        )
        cr0.consume(actual_bytes=64, is_failure=False)
        cr2.consume(actual_bytes=64, is_failure=False)
        self.tracker.record_invocation_completed(inv_id, return_code=0, output_byte_count=128, outcome="COMPLETED")

        self.tracker.commit_transaction(
            operation_id="op_batch_fo",
            profile_id="prof_batch",
            measured_bytes=128,
            reservations=[adm],
        )

        res = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(res["reconciled"])
        self.assertFalse(res["discrepancy_details"]["inv_20_batch_slice_completeness"])
        err_msg = "; ".join(res["discrepancies"])
        self.assertIn("missing slice indices: [1]", err_msg)

    def test_11_distinction_requested_measured_estimated(self):
        """Batch correctly distinguishes requested, measured, and conservative estimated bytes."""
        adm = self.tracker.admit_read(
            projected_bytes=192,
            profile_id="prof_batch",
        )
        inv_id = "inv_dist_1"
        self.tracker.record_invocation_started(
            invocation_id=inv_id,
            command_type="memory_batch",
            physical_read_ids=["cr_d_0", "cr_d_1", "cr_d_2"],
            batch_id="b_dist_1",
        )

        # Slice 0: full read (req 64, meas 64, est 0)
        cr0 = adm.start_child_read(
            target_type="remote_collector_memory_slice",
            target_spec={"batch_id": "b_dist_1", "invocation_id": inv_id, "expected_slice_count": 3, "slice_index": 0, "address": 0x1000, "requested_size": 64, "completion_status": "OBSERVED"},
            physical_read_id="cr_d_0",
        )
        cr0.consume(actual_bytes=64, is_failure=False)

        # Slice 1: partial read (req 64, meas 32, est 0)
        cr1 = adm.start_child_read(
            target_type="remote_collector_memory_slice",
            target_spec={"batch_id": "b_dist_1", "invocation_id": inv_id, "expected_slice_count": 3, "slice_index": 1, "address": 0x2000, "requested_size": 64, "completion_status": "PARTIAL"},
            physical_read_id="cr_d_1",
        )
        cr1.consume(actual_bytes=32, is_failure=False)

        # Slice 2: failed read with unknown bytes (req 64, meas None, est 64)
        cr2 = adm.start_child_read(
            target_type="remote_collector_memory_slice",
            target_spec={"batch_id": "b_dist_1", "invocation_id": inv_id, "expected_slice_count": 3, "slice_index": 2, "address": 0x3000, "requested_size": 64, "completion_status": "FAILED"},
            physical_read_id="cr_d_2",
        )
        cr2.consume(actual_bytes=None, conservative_estimate_bytes=64, is_failure=True, failure_reason="EFAULT")

        self.tracker.record_invocation_completed(inv_id, return_code=0, output_byte_count=96, outcome="COMPLETED")

        # Total charged = 64 + 32 + 64 = 160
        self.assertEqual(adm.consumed_bytes, 160)
        self.tracker.commit_transaction(
            operation_id="op_batch_dist",
            profile_id="prof_batch",
            measured_bytes=96,
            estimated_bytes=64,
            is_failure=True,
            reservations=[adm],
        )

        res = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(res["reconciled"])
        self.assertEqual(res["total_bytes_read"], 160)
        self.assertEqual(res["total_measured_bytes"], 96)
        self.assertEqual(res["total_estimated_bytes"], 64)


class TestPhase20A3416AuthoritativeInvocationIdentity(unittest.TestCase):
    """Section 3: Authoritative Invocation Identity & Runtime Instrumentation."""

    def setUp(self):
        self.runner = MockCommandRunnerA3416()
        self.tracker = ObservationBudgetTracker(session_id="test_sess_inv")
        self.adapter = RemoteSshTargetAdapter(
            host="example.com",
            user="appuser",
            command_runner=self.runner,
            collector_path="/bin/collector",
        )
        self.adapter.set_budget_tracker(self.tracker)

    def test_12_unique_invocation_id_and_command_type(self):
        """Every remote command creates a distinct invocation_id and records explicit command_type."""
        # 1. Liveness
        ok, _ = self.adapter.check_liveness(1001, budget_tracker=self.tracker)
        self.assertTrue(ok)

        # 2. Stat
        self.adapter.get_process_identity(1001, budget_tracker=self.tracker)

        invs = self.tracker.get_invocation_records()
        self.assertGreaterEqual(len(invs), 2)
        inv_ids = list(invs.keys())
        self.assertEqual(len(inv_ids), len(set(inv_ids)))

        cmd_types = [inv.command_type for inv in invs.values()]
        self.assertIn("liveness_check", cmd_types)
        self.assertTrue(any("identity" in ct for ct in cmd_types))

    def test_13_batch_id_and_invocation_id_propagated(self):
        """read_memory_batch generates batch_id and propagates it to all child slices."""
        slices = [(0x1000, 32), (0x2000, 32), (0x3000, 32)]
        results = self.adapter.read_memory_batch(1001, slices, budget_tracker=self.tracker)
        self.assertEqual(len(results), 3)

        invs = self.tracker.get_invocation_records()
        batch_invs = [inv for inv in invs.values() if inv.command_type == "memory_batch_collector"]
        self.assertEqual(len(batch_invs), 1)
        b_inv = batch_invs[0]
        self.assertTrue(b_inv.batch_id.startswith("batch_"))
        self.assertEqual(len(b_inv.physical_read_ids), 3)

    def test_14_multi_slice_shared_invocation_disjoint_physical_reads(self):
        """Multi-slice command shares a single invocation_id, but has distinct physical_read_ids."""
        slices = [(0x1000, 32), (0x2000, 32), (0x3000, 32)]
        self.adapter.read_memory_batch(1001, slices, budget_tracker=self.tracker)

        cr_records = self.tracker.get_physical_read_records()
        self.assertEqual(len(cr_records), 3)
        read_ids = [r.physical_read_id for r in cr_records.values()]
        self.assertEqual(len(read_ids), 3)
        self.assertEqual(len(set(read_ids)), 3)

        inv_ids = [r.target_spec.get("invocation_id") for r in cr_records.values()]
        self.assertEqual(len(set(inv_ids)), 1)  # All share the same invocation_id

    def test_15_collector_failure_disjoint_fallback_invocation(self):
        """Collector failure followed by fallback execution produces disjoint invocation IDs."""
        self.runner.collector_supported = False
        slices = [(0x1000, 32), (0x2000, 32)]
        results = self.adapter.read_memory_batch(1001, slices, budget_tracker=self.tracker)
        self.assertEqual(len(results), 2)

        invs = self.tracker.get_invocation_records()
        coll_invs = [inv for inv in invs.values() if inv.command_type == "memory_batch_collector"]
        shell_invs = [inv for inv in invs.values() if inv.command_type == "memory_batch_shell"]

        self.assertEqual(len(coll_invs), 1)
        self.assertEqual(len(shell_invs), 1)
        self.assertNotEqual(coll_invs[0].invocation_id, shell_invs[0].invocation_id)
        self.assertEqual(coll_invs[0].return_code, 127)
        self.assertEqual(shell_invs[0].return_code, 0)

    def test_16_preflight_rejection_no_executed_invocation(self):
        """Preflight rejection (rc = -2) creates no executed invocation record in tracker."""
        self.runner.fail_before_execution = True
        adm = self.tracker.admit_read(projected_bytes=64, profile_id="prof_pref")
        cr = adm.start_child_read(target_type="test_preflight", physical_read_id="cr_pref_1")

        rc, _, err = self.adapter.run_ssh("echo hello", admission=adm, child_read=cr, command_type="test_pref")
        self.assertEqual(rc, -2)
        self.assertIn("before execution", err)

        invs = self.tracker.get_invocation_records()
        self.assertEqual(len(invs), 0)
        self.assertEqual(cr.state, "ADMITTED")
        cr.release()
        adm.release()

    def test_17_timeout_outcome_recorded(self):
        """Timeout after physical invocation started records TIMEOUT outcome and preserves consumption."""
        def timeout_handler(cmd, timeout):
            raise TimeoutError(f"SSH command timed out after {timeout}s")

        self.runner.on_command = timeout_handler
        adm = self.tracker.admit_read(projected_bytes=64, profile_id="prof_to")
        cr = adm.start_child_read(target_type="test_timeout", target_spec={"size": 64}, physical_read_id="cr_to_1")

        rc, _, err = self.adapter.run_ssh("sleep 10", admission=adm, child_read=cr, command_type="test_timeout")
        self.assertEqual(rc, -1)
        self.assertIn("timed out", err)

        invs = self.tracker.get_invocation_records()
        self.assertEqual(len(invs), 1)
        inv = next(iter(invs.values()))
        self.assertEqual(inv.outcome, "TIMEOUT")
        self.assertIn("timed out", inv.exception or "")

    def test_18_transport_disconnect_outcome_recorded(self):
        """Transport error records TRANSPORT_ERROR outcome with exception details."""
        self.runner.fail_during_execution = True
        adm = self.tracker.admit_read(projected_bytes=64, profile_id="prof_trans")
        cr = adm.start_child_read(target_type="test_trans", physical_read_id="cr_trans_1")

        rc, _, err = self.adapter.run_ssh("echo hi", admission=adm, child_read=cr, command_type="test_trans")
        self.assertEqual(rc, -1)

        invs = self.tracker.get_invocation_records()
        self.assertEqual(len(invs), 1)
        inv = next(iter(invs.values()))
        self.assertEqual(inv.outcome, "TRANSPORT_ERROR")
        self.assertIn("Connection refused", inv.exception or "")

    def test_19_runtime_instrumentation_fields(self):
        """Invocation record contains start/completion timestamps, bytecount, and no secret args."""
        slices = [(0x1000, 32)]
        self.adapter.read_memory_batch(1001, slices, budget_tracker=self.tracker)

        invs = self.tracker.get_invocation_records()
        self.assertGreater(len(invs), 0)
        inv = next(iter(invs.values()))
        self.assertIsInstance(inv.start_time_ms, float)
        self.assertIsInstance(inv.completion_time_ms, float)
        self.assertGreaterEqual(inv.completion_time_ms, inv.start_time_ms)
        self.assertEqual(inv.return_code, 0)
        self.assertGreater(inv.output_byte_count, 0)
        # Verify no secret command payload is exposed in RemoteInvocationRecord fields
        self.assertFalse(hasattr(inv, "cmd_args"))
        self.assertFalse(hasattr(inv, "raw_output"))


class TestPhase20A3416ReconciliationCommittedHistory(unittest.TestCase):
    """Section 4: Reconciliation Across Committed History (Invariants 20, 21, 22)."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker(session_id="test_sess_reconcile")

    def test_20_reconciliation_verifies_committed_reads_and_transactions(self):
        """Reconciliation audits committed PhysicalReadRecord and CommittedTransactionSnapshot."""
        adm = self.tracker.admit_read(projected_bytes=64, profile_id="prof_c1")
        inv_id = "inv_c1"
        self.tracker.record_invocation_started(
            invocation_id=inv_id,
            command_type="single_read",
            physical_read_ids=["cr_c1"],
        )
        cr = adm.start_child_read(
            target_type="single_read",
            target_spec={"invocation_id": inv_id},
            physical_read_id="cr_c1",
        )
        cr.consume(actual_bytes=64, is_failure=False)
        self.tracker.record_invocation_completed(inv_id, return_code=0, output_byte_count=64, outcome="COMPLETED")

        self.tracker.commit_transaction(
            operation_id="op_c1",
            profile_id="prof_c1",
            measured_bytes=64,
            reservations=[adm],
        )

        res = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(res["reconciled"])
        self.assertEqual(res["total_transactions"], 1)
        self.assertEqual(res["total_physical_reads"], 1)

    def test_21_corruption_inv_21_committed_collector_fallback_conflict(self):
        """Committed records sharing invocation_id between collector and fallback violate Invariant 21."""
        adm = self.tracker.admit_read(projected_bytes=128, profile_id="prof_c2")
        shared_inv = "inv_shared_bad"
        self.tracker.record_invocation_started(
            invocation_id=shared_inv,
            command_type="bad_mix",
            physical_read_ids=["cr_coll_bad", "cr_shell_bad"],
        )

        cr_coll = adm.start_child_read(
            target_type="remote_collector_memory",
            target_spec={"invocation_id": shared_inv, "invocation_type": "collector"},
            physical_read_id="cr_coll_bad",
        )
        cr_shell = adm.start_child_read(
            target_type="remote_shell_memory",
            target_spec={"invocation_id": shared_inv, "invocation_type": "shell_fallback"},
            physical_read_id="cr_shell_bad",
        )
        cr_coll.consume(actual_bytes=64, is_failure=False)
        cr_shell.consume(actual_bytes=64, is_failure=False)
        self.tracker.record_invocation_completed(shared_inv, return_code=0, output_byte_count=128, outcome="COMPLETED")

        self.tracker.commit_transaction(
            operation_id="op_bad_mix",
            profile_id="prof_c2",
            measured_bytes=128,
            reservations=[adm],
        )

        res = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(res["reconciled"])
        self.assertFalse(res["discrepancy_details"]["inv_21_collector_fallback_provenance_separation"])
        err_msg = "; ".join(res["discrepancies"])
        self.assertIn("shares invocation_ids between collector and fallback", err_msg)

    def test_22_corruption_inv_22_orphan_invocation_record(self):
        """Invocation record referencing non-existent physical_read_id fails Invariant 22."""
        self.tracker.record_invocation_started(
            invocation_id="inv_orphan",
            command_type="cmd",
            physical_read_ids=["cr_phantom_999"],
        )
        self.tracker.record_invocation_completed("inv_orphan", return_code=0, output_byte_count=0, outcome="COMPLETED")

        res = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(res["reconciled"])
        self.assertFalse(res["discrepancy_details"]["inv_22_invocation_provenance_and_orphan_detection"])
        err_msg = "; ".join(res["discrepancies"])
        self.assertIn("orphan invocation 'inv_orphan' references non-existent physical_read_id 'cr_phantom_999'", err_msg)

    def test_23_corruption_inv_22_orphan_physical_read_record(self):
        """Committed physical read record not linked to any committed transaction fails Invariant 22."""
        orphan_pcons = PhysicalConsumptionRecord(
            physical_consumption_id="pcons_orphan_committed",
            physical_read_id="cr_orphan_committed",
            reservation_id="res_phantom",
            operation_id="op_phantom_uncommitted",
            measured_bytes_read=64,
            estimated_bytes_read=0,
            charged_bytes=64,
            measurement_type="MEASURED",
            created_at_ms=time.time(),
            committed_at_ms=time.time(),
        )
        orphan_read = PhysicalReadRecord(
            physical_read_id="cr_orphan_committed",
            physical_consumption_id="pcons_orphan_committed",
            reservation_id="res_phantom",
            target_type="phantom",
            target_spec={},
            state="ACCOUNTED",
            operation_id="op_phantom_uncommitted",
            charged_bytes=64,
        )
        with self.tracker._transaction_lock:
            self.tracker._physical_consumption_records["pcons_orphan_committed"] = orphan_pcons
            self.tracker._physical_read_records["cr_orphan_committed"] = orphan_read

        res = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(res["reconciled"])
        self.assertFalse(res["discrepancy_details"]["inv_22_invocation_provenance_and_orphan_detection"])
        err_msg = "; ".join(res["discrepancies"])
        self.assertIn("has operation_id 'op_phantom_uncommitted' not found in committed transactions", err_msg)

    def test_24_corruption_inv_22_unregistered_invocation_on_read(self):
        """Physical read referencing an unregistered invocation_id fails Invariant 22."""
        self.tracker.record_invocation_started(
            invocation_id="inv_registered_1",
            command_type="test",
            physical_read_ids=["cr_other"],
        )
        adm = self.tracker.admit_read(projected_bytes=64, profile_id="prof_unreg")
        # Record invocation 'inv_never_registered' is NOT recorded in tracker
        cr = adm.start_child_read(
            target_type="test",
            target_spec={"invocation_id": "inv_never_registered"},
            physical_read_id="cr_unreg_1",
        )
        cr.consume(actual_bytes=64, is_failure=False)

        # Still active reservation: reconciliation catches unregistered invocation
        res = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(res["reconciled"])
        self.assertFalse(res["discrepancy_details"]["inv_22_invocation_provenance_and_orphan_detection"])
        err_msg = "; ".join(res["discrepancies"])
        self.assertIn("references unknown invocation_id 'inv_never_registered'", err_msg)


class TestPhase20A3416InFlightAndUnknownBudgetAccounting(unittest.TestCase):
    """Section 5: In-Flight & Unknown Reads Budget Accounting."""

    def setUp(self):
        self.limits = ObservationBudgetLimits(max_bytes_read=1000)
        self.tracker = ObservationBudgetTracker(limits=self.limits, session_id="test_sess_budget")

    def test_25_two_concurrent_reservations_under_profile(self):
        """Two concurrent reservations under one profile correctly calculate available budget."""
        prof_ceil = {"max_bytes_read": 500}
        adm1 = self.tracker.admit_read(projected_bytes=200, profile_id="prof_budget", profile_ceiling=prof_ceil)
        adm2 = self.tracker.admit_read(projected_bytes=200, profile_id="prof_budget", profile_ceiling=prof_ceil)

        # 200 + 200 = 400 reserved out of 500 ceiling
        # Acquiring 150 must fail (400 + 150 = 550 > 500)
        with self.assertRaises(ValueError) as ctx:
            self.tracker.admit_read(projected_bytes=150, profile_id="prof_budget", profile_ceiling=prof_ceil)
        self.assertIn("PROFILE_CEILING_EXCEEDED", str(ctx.exception))

        adm1.release()
        # After releasing adm1, 200 reserved, acquiring 150 succeeds
        adm3 = self.tracker.admit_read(projected_bytes=150, profile_id="prof_budget", profile_ceiling=prof_ceil)
        self.assertIsNotNone(adm3)
        adm2.release()
        adm3.release()

    def test_26_multi_child_partial_consumption_protects_remaining_reservation(self):
        """Partial consumption by one child protects remaining unconsumed reservation bytes without double counting."""
        adm = self.tracker.admit_read(projected_bytes=300, profile_id="prof_budget")
        cr0 = adm.start_child_read(target_type="slice_0", physical_read_id="cr_p0")
        cr1 = adm.start_child_read(target_type="slice_1", physical_read_id="cr_p1")
        cr2 = adm.start_child_read(target_type="slice_2", physical_read_id="cr_p2")

        # Mark cr0 as consumed (100B). Reservation state becomes CONSUMED with consumed_bytes=100.
        # Children cr1 and cr2 are still PHYSICAL_READ_STARTED.
        cr0.consume(actual_bytes=100, is_failure=False)

        # In-flight reservation bytes must protect remaining 200B:
        active_res_b = self.tracker._active_reservation_bytes("prof_budget")
        active_cons_b = self.tracker._active_consumed_bytes("prof_budget")
        self.assertEqual(active_cons_b, 100)
        self.assertEqual(active_res_b, 200)
        total_accounted = active_cons_b + active_res_b
        self.assertEqual(total_accounted, 300)

        # Now cr1 consumes 100B
        cr1.consume(actual_bytes=100, is_failure=False)
        self.assertEqual(self.tracker._active_consumed_bytes("prof_budget"), 200)
        self.assertEqual(self.tracker._active_reservation_bytes("prof_budget"), 100)
        self.assertEqual(self.tracker._active_consumed_bytes("prof_budget") + self.tracker._active_reservation_bytes("prof_budget"), 300)

        # Finally cr2 consumes 100B
        cr2.consume(actual_bytes=100, is_failure=False)
        self.assertEqual(self.tracker._active_consumed_bytes("prof_budget"), 300)
        self.assertEqual(self.tracker._active_reservation_bytes("prof_budget"), 0)

        # Clean commit
        self.tracker.commit_transaction(operation_id="op_multi_protect", profile_id="prof_budget", measured_bytes=300, reservations=[adm])
        self.assertTrue(self.tracker.reconcile_ledger()["reconciled"])

    def test_27_concurrent_profile_ceiling_barrier_race(self):
        """Concurrent threads competing for last available profile budget respect ceiling via synchronization."""
        tracker = ObservationBudgetTracker(limits=ObservationBudgetLimits(max_bytes_read=1000), session_id="test_sess_race")
        prof_ceil = {"max_bytes_read": 250}

        # Initial reservation: 150 bytes, leaving 100 bytes available
        adm_init = tracker.admit_read(projected_bytes=150, profile_id="prof_race", profile_ceiling=prof_ceil)

        barrier = threading.Barrier(2)
        results: List[Optional[str]] = [None, None]

        def racer(idx: int, req_bytes: int):
            barrier.wait(timeout=2.0)
            try:
                tracker.admit_read(projected_bytes=req_bytes, profile_id="prof_race", profile_ceiling=prof_ceil)
                results[idx] = "SUCCESS"
            except (ValueError, RuntimeError) as e:
                results[idx] = f"REJECTED: {e}"

        t1 = threading.Thread(target=racer, args=(0, 80))
        t2 = threading.Thread(target=racer, args=(1, 80))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # Both requested 80. Only 100 was available. Exactly one must succeed and one must be rejected!
        success_count = sum(1 for r in results if r == "SUCCESS")
        rejected_count = sum(1 for r in results if r and r.startswith("REJECTED"))
        self.assertEqual(success_count, 1)
        self.assertEqual(rejected_count, 1)

    def test_28_collector_failure_fallback_success_no_double_charge(self):
        """Collector failure followed by fallback success charges actual cost exactly once."""
        runner = MockCommandRunnerA3416()
        runner.collector_supported = False
        adapter = RemoteSshTargetAdapter(
            host="example.com",
            user="appuser",
            command_runner=runner,
            collector_path="/bin/collector",
        )
        adapter.set_budget_tracker(self.tracker)

        slices = [(0x1000, 64)]
        # Collector fails (rc=127, charged 0), fallback succeeds (charges 32 measured)
        res = adapter.read_memory_batch(1001, slices, budget_tracker=self.tracker)
        self.assertEqual(len(res), 1)

        # Check total committed metrics
        self.assertEqual(self.tracker.metrics.bytes_read, 32)
        self.assertEqual(self.tracker.metrics.measured_bytes_read, 32)
        self.assertEqual(self.tracker.metrics.conservative_estimated_bytes, 0)
        self.assertTrue(self.tracker.reconcile_ledger()["reconciled"])

    def test_29_unknown_consumption_after_timeout_preserves_cost(self):
        """Unknown consumption after remote runner timeout charges conservative estimate permanently."""
        runner = MockCommandRunnerA3416()
        def timeout_handler(cmd, timeout):
            raise TimeoutError("Command timed out")
        runner.on_command = timeout_handler

        adapter = RemoteSshTargetAdapter(
            host="example.com",
            user="appuser",
            command_runner=runner,
        )
        adapter.set_budget_tracker(self.tracker)

        # Single read of 128 bytes times out
        data, st, err = adapter.read_memory(1001, 0x1000, 128, budget_tracker=self.tracker)
        self.assertIsNone(data)
        self.assertEqual(st, "UNAVAILABLE")

        # Conservative estimate of 128 bytes must be committed and preserved
        self.assertEqual(self.tracker.metrics.bytes_read, 128)
        self.assertEqual(self.tracker.metrics.conservative_estimated_bytes, 128)
        self.assertEqual(self.tracker.metrics.measured_bytes_read, 0)
        self.assertTrue(self.tracker.reconcile_ledger()["reconciled"])

    def test_30_preflight_failure_releases_cleanly(self):
        """Preflight rejection before execution releases reservation cleanly with 0 bytes charged."""
        runner = MockCommandRunnerA3416()
        runner.fail_before_execution = True
        adapter = RemoteSshTargetAdapter(
            host="example.com",
            user="appuser",
            command_runner=runner,
        )
        adapter.set_budget_tracker(self.tracker)

        alive, err = adapter.check_liveness(1001, budget_tracker=self.tracker)
        self.assertFalse(alive)
        self.assertIn("failed before invocation", err or "")

        self.assertEqual(self.tracker.metrics.bytes_read, 0)
        self.assertEqual(len(self.tracker.get_committed_transactions()), 0)
        self.assertTrue(self.tracker.reconcile_ledger()["reconciled"])

    def test_31_scope_commit_recovery_preserves_child_reads(self):
        """Scope commit crash triggers recovery preserving physical child read ledger."""
        def fail_snap():
            raise RuntimeError("Simulated crash during snapshot construction")
        self.tracker.register_fault_injection("during_snapshot_construction", fail_snap)
        try:
            with self.tracker.operation_scope(operation_id="op_fault_test", profile_id="prof_budget") as sc:
                adm = sc.admit_read(projected_bytes=64)
                cr = adm.start_child_read(target_type="slice_rec", physical_read_id="cr_rec_1")
                cr.consume(actual_bytes=64, is_failure=False)
                sc.record_read(bytes_read=64, admission=adm)
        finally:
            self.tracker.clear_fault_injections()

        # Recovery committed a transaction with status FAILED while preserving physical evidence
        snaps = self.tracker.get_committed_transactions()
        self.assertIn("op_fault_test", snaps)
        snap = snaps["op_fault_test"]
        self.assertEqual(snap.accounting_status, "FAILED")
        self.assertEqual(snap.charged_bytes, 64)

        # Reconciliation must pass
        self.assertTrue(self.tracker.reconcile_ledger()["reconciled"])


class TestPhase20A3416RemoteCallGraphVerification(unittest.TestCase):
    """Section 6: Full Remote Read Call Graph Verification."""

    def setUp(self):
        self.runner = MockCommandRunnerA3416()
        self.tracker = ObservationBudgetTracker(session_id="test_sess_callgraph")
        self.adapter = RemoteSshTargetAdapter(
            host="example.com",
            user="appuser",
            command_runner=self.runner,
            collector_path="/bin/collector",
        )
        self.adapter.set_budget_tracker(self.tracker)

    def test_32_callgraph_check_liveness(self):
        """check_liveness executes with explicit command_type and accounts cleanly."""
        alive, err = self.adapter.check_liveness(1001, budget_tracker=self.tracker)
        self.assertTrue(alive)
        self.assertIsNone(err)

        invs = self.tracker.get_invocation_records()
        self.assertEqual(len(invs), 1)
        inv = next(iter(invs.values()))
        self.assertEqual(inv.command_type, "liveness_check")
        self.assertTrue(self.tracker.reconcile_ledger()["reconciled"])

    def test_33_callgraph_get_process_identity(self):
        """get_process_identity executes readlink, stat, elf reads with distinct invocations."""
        info = self.adapter.get_process_identity(1001, budget_tracker=self.tracker)
        self.assertEqual(info["status"], "OBSERVED")
        self.assertEqual(info["identity_status"], IDENTITY_VERIFIED)

        invs = self.tracker.get_invocation_records()
        cmd_types = [inv.command_type for inv in invs.values()]
        self.assertIn("identity_readlink", cmd_types)
        self.assertIn("identity_stat", cmd_types)
        self.assertIn("identity_elf", cmd_types)
        self.assertTrue(self.tracker.reconcile_ledger()["reconciled"])

    def test_34_callgraph_get_process_memory_info(self):
        """get_process_memory_info executes memory_info command_type and records consumption."""
        mem = self.adapter.get_process_memory_info(1001, budget_tracker=self.tracker)
        self.assertEqual(mem["status"], "OBSERVED")
        self.assertIn("metrics", mem)
        self.assertIn("vsz_bytes", mem["metrics"])

        invs = self.tracker.get_invocation_records()
        cmd_types = [inv.command_type for inv in invs.values()]
        self.assertIn("memory_info", cmd_types)
        self.assertTrue(self.tracker.reconcile_ledger()["reconciled"])

    def test_35_callgraph_get_proc_maps(self):
        """get_proc_maps executes proc_maps command_type."""
        maps = self.adapter.get_proc_maps(1001, budget_tracker=self.tracker)
        self.assertGreater(len(maps), 0)

        invs = self.tracker.get_invocation_records()
        cmd_types = [inv.command_type for inv in invs.values()]
        self.assertIn("proc_maps", cmd_types)
        self.assertTrue(self.tracker.reconcile_ledger()["reconciled"])

    def test_36_callgraph_get_threads(self):
        """get_threads executes proc_threads command_type."""
        threads = self.adapter.get_threads(1001, budget_tracker=self.tracker)
        self.assertGreater(len(threads), 0)

        invs = self.tracker.get_invocation_records()
        cmd_types = [inv.command_type for inv in invs.values()]
        self.assertIn("proc_threads", cmd_types)
        self.assertTrue(self.tracker.reconcile_ledger()["reconciled"])

    def test_37_callgraph_read_memory_single(self):
        """read_memory executes collector or shell fallback with distinct child read."""
        data, st, err = self.adapter.read_memory(1001, 0x1000, 32, budget_tracker=self.tracker)
        self.assertIsNotNone(data)
        self.assertEqual(st, "OBSERVED")

        invs = self.tracker.get_invocation_records()
        cmd_types = [inv.command_type for inv in invs.values()]
        self.assertTrue(any(ct in ("memory_batch_collector", "memory_read_shell") for ct in cmd_types))
        self.assertTrue(self.tracker.reconcile_ledger()["reconciled"])

    def test_38_callgraph_read_memory_batch(self):
        """read_memory_batch registers batch contract and records slice completions."""
        slices = [(0x1000, 32), (0x2000, 32), (0x3000, 32)]
        res = self.adapter.read_memory_batch(1001, slices, budget_tracker=self.tracker)
        self.assertEqual(len(res), 3)

        batch_recs = self.tracker.get_batch_records()
        self.assertEqual(len(batch_recs), 1)
        b_rec = next(iter(batch_recs.values()))
        self.assertEqual(b_rec.expected_slice_count, 3)
        self.assertTrue(self.tracker.reconcile_ledger()["reconciled"])

    def test_39_callgraph_nested_remote_reads(self):
        """Nested operations under operation_scope maintain clean invocation isolation."""
        with self.tracker.operation_scope(operation_id="op_nested_audit", profile_id="prof_nested"):
            # 1. Liveness
            alive, _ = self.adapter.check_liveness(1001, budget_tracker=self.tracker)
            self.assertTrue(alive)

            # 2. Identity
            info = self.adapter.get_process_identity(1001, budget_tracker=self.tracker)
            self.assertEqual(info["status"], "OBSERVED")
            self.assertEqual(info["identity_status"], IDENTITY_VERIFIED)

            # 3. Memory batch
            slices = [(0x1000, 32), (0x2000, 32)]
            res = self.adapter.read_memory_batch(1001, slices, budget_tracker=self.tracker)
            self.assertEqual(len(res), 2)

        invs = self.tracker.get_invocation_records()
        self.assertGreaterEqual(len(invs), 4)

        # All invocations must be distinct
        inv_ids = list(invs.keys())
        self.assertEqual(len(inv_ids), len(set(inv_ids)))

        # Ledger reconciliation must pass across entire nested history
        res_reconcile = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(res_reconcile["reconciled"])


if __name__ == "__main__":
    unittest.main()

"""Phase 2.0-A.3.4.15 — Remote Invocation Boundary & Unknown Consumption Closure Test Suite.

Verifies:
- P0.1 Exact physical invocation boundary & state machine order
- P0.2 Remote process identity unknown consumption accounting
- P0.3 Physical execution identity contract (invocation_id, slices, collector vs fallback)
- P0.4 Batch and collector failure semantics matrix (all 14 scenarios)
- P0.5 In-flight reservation and concurrency safety (all 6 adversarial scenarios)
- P1.1 Runtime invocation instrumentation (MockInstrumentedCommandRunner with ordering assertions)
- P1.2 Reconciliation enhancements & corruption detection (Invariants 1-21)
"""

import base64
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
    BudgetReservation,
    CommittedTransactionSnapshot,
    ObservationAccountingRecord,
    ObservationBudgetLimits,
    ObservationBudgetTracker,
    PhysicalConsumptionRecord,
    PhysicalReadRecord,
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


class EnhancedMockCommandRunner:
    """Mock command runner recording invocation timestamps, order, parameters, and in-flight states."""

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
            return False, "ssh binary not found on local PATH (preflight check failed)"
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
            inv_record["error"] = "Transport error during execution"
            inv_record["completion_time"] = time.monotonic()
            inv_record["completed"] = True
            return -1, "", "Transport error during execution: connection reset"

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
                import json as _json
                rc, out, err = 0, _json.dumps({
                    "success": True,
                    "slices": [
                        {"status": "OBSERVED", "hex": "aa" * 32},
                        {"status": "OBSERVED", "hex": "bb" * 32},
                        {"status": "OBSERVED", "hex": "cc" * 32},
                    ]
                }), ""
        elif "dd if=" in cmd_str:
            b64 = base64.b64encode(b"\xaa" * 32).decode("ascii")
            if "echo \"" in cmd_str:
                rc, out, err = 0, "\n".join(f"{i}|{b64}" for i in range(10)) + "\n", ""
            else:
                rc, out, err = 0, b64, ""
        elif "kill -0" in cmd_str:
            rc, out, err = 0, "ALIVE\n", ""
        elif "cat /proc/" in cmd_str and "maps" in cmd_str:
            rc, out, err = 0, "00400000-00401000 r-xp 00000000 08:01 12345 /bin/test\n", ""
        elif "comm" in cmd_str and "stat" in cmd_str:
            rc, out, err = 0, "1234 R main\n", ""
        elif "readlink" in cmd_str:
            rc, out, err = 0, "/usr/bin/target_proc\n", ""
        elif "cat /proc/" in cmd_str and "stat" in cmd_str:
            rc, out, err = 0, "1234 (target_proc) S 1 1234 1234 0 -1 4194304 100 0 0 0 10 20 0 0 20 0 1 0 1234567 1000 100\n", ""
        elif "head -c 65536" in cmd_str:
            elf_hdr = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + struct.pack("<HHI", 2, 0x3e, 1) + b"\x00" * 40
            rc, out, err = 0, base64.b64encode(elf_hdr).decode("ascii"), ""
        elif "statm" in cmd_str:
            rc, out, err = 0, "100 20 10 5 0 15 0\n---DELIM_STATUS---\nVmSize: 400 kB\nVmRSS: 80 kB\n---DELIM_SMAPS---\nPss: 40 kB\n", ""

        inv_record["rc"] = rc
        inv_record["output_bytes"] = len(out.encode("utf-8")) if out else 0
        inv_record["completion_time"] = time.monotonic()
        inv_record["completed"] = True
        return rc, out, err


class TestPhase20A3415InvocationBoundaryOrder(unittest.TestCase):
    """P0.1: Move Lifecycle Start to the Actual Invocation Boundary."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=100000))
        self.tracker.start()
        self.runner = EnhancedMockCommandRunner()
        self.adapter = RemoteSshTargetAdapter(host="remote.test", command_runner=self.runner)
        self.adapter.set_budget_tracker(self.tracker)

    def test_01_lifecycle_starts_immediately_before_runner_invocation(self):
        """Admission and child_read states are strictly PHYSICAL_READ_STARTED when runner is called."""
        observed_states: List[Tuple[str, str]] = []

        def on_cmd_hook(cmd_args):
            active_res = self.tracker.get_active_reservations()
            self.assertTrue(len(active_res) > 0)
            res = list(active_res.values())[0]
            child_states = [c.state for c in res.child_reads.values()]
            observed_states.append((res.state, child_states[0] if child_states else "NO_CHILD"))

        self.runner.on_start_hook = on_cmd_hook
        self.adapter.collector_path = None

        data, st, err = self.adapter.read_memory(1234, 0x1000, 32)
        self.assertEqual(st, "OBSERVED")
        self.assertEqual(len(observed_states), 1)
        res_st, child_st = observed_states[0]
        self.assertEqual(res_st, "PHYSICAL_READ_STARTED")
        self.assertEqual(child_st, "PHYSICAL_READ_STARTED")

    def test_02_in_flight_command_cannot_remain_admitted(self):
        """In-flight command execution guarantees reservation and child read cannot be in ADMITTED."""
        blocker = threading.Event()
        self.runner.block_event = blocker
        self.adapter.collector_path = None

        exec_thread = threading.Thread(target=lambda: self.adapter.read_memory(1234, 0x1000, 32))
        exec_thread.start()

        # Wait for runner to be entered
        time.sleep(0.05)
        active_res = self.tracker.get_active_reservations()
        self.assertTrue(len(active_res) > 0)
        res = list(active_res.values())[0]
        self.assertEqual(res.state, "PHYSICAL_READ_STARTED")
        child_reads = list(res.child_reads.values())
        self.assertTrue(len(child_reads) > 0)
        self.assertEqual(child_reads[0].state, "PHYSICAL_READ_STARTED")

        # Unblock and join
        blocker.set()
        exec_thread.join()

    def test_03_pre_invocation_failure_does_not_cross_boundary_and_allows_release(self):
        """Failure proven to occur before invocation (rc=-2) does not mark started and permits release."""
        self.runner.fail_before_execution = True
        self.adapter.collector_path = None

        data, st, err = self.adapter.read_memory(1234, 0x1000, 32)
        self.assertEqual(st, "UNAVAILABLE")
        self.assertIn("before execution", err)

        # 0 bytes charged, reservation cleanly released
        self.assertEqual(self.tracker.metrics.bytes_read, 0)
        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_04_post_invocation_failure_cannot_be_released(self):
        """Failure after crossing invocation boundary transitions to failure accounting, never released."""
        self.runner.fail_during_execution = True
        self.adapter.collector_path = None

        data, st, err = self.adapter.read_memory(1234, 0x1000, 64)
        self.assertEqual(st, "UNAVAILABLE")

        # Child was marked started, so it cannot be released; conservative cost is charged
        self.assertEqual(self.tracker.metrics.bytes_read, 64)
        self.assertEqual(self.tracker.metrics.total_read_failures, 1)

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_05_post_invocation_failure_uses_conservative_failure_accounting(self):
        """Unknown consumption after crossing invocation boundary charges conservative cost."""
        def on_cmd(cmd, t):
            return -1, "", "Connection reset by peer"

        self.runner.on_command = on_cmd
        self.adapter.collector_path = None

        data, st, err = self.adapter.read_memory(1234, 0x2000, 128)
        self.assertEqual(st, "UNAVAILABLE")
        self.assertEqual(self.tracker.metrics.bytes_read, 128)
        self.assertEqual(self.tracker.metrics.conservative_estimated_bytes, 128)
        self.assertEqual(self.tracker.metrics.measured_bytes_read, 0)

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])


class TestPhase20A3415RemoteProcessIdentityUnknownConsumption(unittest.TestCase):
    """P0.2: Remote Process Identity Unknown Consumption Accounting."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=200000))
        self.tracker.start()
        self.runner = EnhancedMockCommandRunner()
        self.adapter = RemoteSshTargetAdapter(host="remote.test", command_runner=self.runner)
        self.adapter.set_budget_tracker(self.tracker)

    def test_06_liveness_zero_bytes_distinguished_from_unknown(self):
        """Liveness probe success is measured 0 bytes; transport error is unknown conservative cost."""
        adm = self.tracker.admit_read(64, profile_id="target_identity")
        pread_live = adm.start_child_read(target_type="remote_identity_liveness", target_spec={"pid": 1234})

        alive, err = self.adapter.check_liveness(1234, admission=adm, child_read=pread_live)
        self.assertTrue(alive)
        self.assertEqual(pread_live.measured_bytes_read, 0)
        self.assertEqual(pread_live.estimated_bytes_read, 0)
        self.assertEqual(pread_live.charged_bytes, 0)

        # Transport error on liveness probe
        def on_cmd_fail(cmd, t):
            return -1, "", "SSH connection timed out"

        self.runner.on_command = on_cmd_fail
        pread_fail = adm.start_child_read(target_type="remote_identity_liveness", target_spec={"pid": 1235})
        alive_fail, err_fail = self.adapter.check_liveness(1235, admission=adm, child_read=pread_fail)
        self.assertFalse(alive_fail)
        self.assertIsNone(pread_fail.measured_bytes_read)
        self.assertEqual(pread_fail.estimated_bytes_read, 64)
        self.assertEqual(pread_fail.charged_bytes, 64)

    def test_07_identity_readlink_empty_stdout_treated_as_unknown_failure(self):
        """readlink command executing but returning empty stdout is treated as unknown failure."""
        def on_cmd(cmd, t):
            if "kill -0" in cmd:
                return 0, "ALIVE\n", ""
            elif "readlink" in cmd:
                return 0, "", ""  # Empty stdout
            elif "stat" in cmd:
                return 0, "1234 (test) S 1 1234 1234 0 -1 4194304 100 0 0 0 10 20 0 0 20 0 1 0 1234567 1000 100\n", ""
            elif "head -c 65536" in cmd:
                elf_hdr = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + struct.pack("<HHI", 2, 0x3e, 1) + b"\x00" * 40
                return 0, base64.b64encode(elf_hdr).decode("ascii"), ""
            return 0, "", ""

        self.runner.on_command = on_cmd
        res = self.adapter.get_process_identity(1234)

        # Readlink failed -> conservative charge 1024B
        bd = res["measurement_breakdown"]
        self.assertEqual(bd["readlink_bytes"], 0)
        self.assertGreaterEqual(bd["estimated_bytes_read"], 1024)
        self.assertEqual(res["charged_bytes"], bd["total_measured_bytes"] + bd["estimated_bytes_read"])

    def test_08_identity_stat_empty_stdout_treated_as_unknown_failure(self):
        """stat command returning empty stdout is treated as unknown failure."""
        def on_cmd(cmd, t):
            if "kill -0" in cmd:
                return 0, "ALIVE\n", ""
            elif "readlink" in cmd:
                return 0, "/usr/bin/daemon\n", ""
            elif "stat" in cmd:
                return 0, "", ""  # Empty stat
            elif "head -c 65536" in cmd:
                elf_hdr = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + struct.pack("<HHI", 2, 0x3e, 1) + b"\x00" * 40
                return 0, base64.b64encode(elf_hdr).decode("ascii"), ""
            return 0, "", ""

        self.runner.on_command = on_cmd
        res = self.adapter.get_process_identity(1234)

        bd = res["measurement_breakdown"]
        self.assertEqual(bd["stat_bytes"], 0)
        self.assertGreaterEqual(bd["estimated_bytes_read"], 1024)

    def test_09_identity_elf_empty_stdout_or_timeout_treated_as_unknown_failure(self):
        """ELF header read failure charges conservative 65536 bytes, never measured zero."""
        def on_cmd(cmd, t):
            if "kill -0" in cmd:
                return 0, "ALIVE\n", ""
            elif "readlink" in cmd:
                return 0, "/usr/bin/daemon\n", ""
            elif "stat" in cmd:
                return 0, "1234 (daemon) S 1 1234 1234 0 -1 4194304 100 0 0 0 10 20 0 0 20 0 1 0 1234567 1000 100\n", ""
            elif "head -c 65536" in cmd:
                return -1, "", "SSH command timed out"
            return 0, "", ""

        self.runner.on_command = on_cmd
        res = self.adapter.get_process_identity(1234)

        bd = res["measurement_breakdown"]
        self.assertEqual(bd["elf_bytes_read"], 0)
        self.assertGreaterEqual(bd["estimated_bytes_read"], 65536)
        self.assertEqual(res["charged_bytes"], bd["total_measured_bytes"] + bd["estimated_bytes_read"])
        self.assertEqual(self.tracker.metrics.bytes_read, res["charged_bytes"])

    def test_10_identity_mixed_success_and_failure_separate_measured_and_estimated(self):
        """Identity read separates measured bytes from estimated bytes across children."""
        def on_cmd(cmd, t):
            if "kill -0" in cmd:
                return 0, "ALIVE\n", ""
            elif "readlink" in cmd:
                return 0, "/bin/app\n", ""  # 9 bytes measured
            elif "stat" in cmd:
                return 1, "", "permission denied"  # 1024 estimated
            elif "head -c 65536" in cmd:
                return 1, "", "permission denied"  # 65536 estimated
            return 0, "", ""

        self.runner.on_command = on_cmd
        res = self.adapter.get_process_identity(1234)

        bd = res["measurement_breakdown"]
        self.assertEqual(bd["readlink_bytes"], 9)
        self.assertEqual(bd["total_measured_bytes"], 9)
        self.assertEqual(bd["estimated_bytes_read"], 1024 + 65536)
        self.assertEqual(res["charged_bytes"], 9 + 1024 + 65536)

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])

    def test_11_identity_children_all_reach_exactly_one_terminal_outcome(self):
        """Every child in get_process_identity has exactly one terminal outcome in ledger."""
        res = self.adapter.get_process_identity(1234)
        active_res = self.tracker.get_committed_transactions()
        self.assertTrue(len(active_res) > 0)

        phys_reads = self.tracker.get_physical_read_records()
        self.assertTrue(len(phys_reads) >= 4)  # live, exe, stat, elf
        for pread in phys_reads.values():
            self.assertTrue(pread.is_terminal)


class TestPhase20A3415PhysicalExecutionIdentityContract(unittest.TestCase):
    """P0.3: Define and Enforce the Physical Execution Identity Contract."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=100000))
        self.tracker.start()
        self.runner = EnhancedMockCommandRunner()
        self.adapter = RemoteSshTargetAdapter(host="remote.test", command_runner=self.runner)
        self.adapter.set_budget_tracker(self.tracker)

    def test_12_ssh_invocation_has_unique_invocation_id(self):
        """Every SSH command invocation generates and links a unique invocation_id."""
        self.adapter.collector_path = None
        slices = [(0x1000, 32), (0x2000, 32)]
        res = self.adapter.read_memory_batch(1234, slices)

        child_reads = self.tracker.get_physical_read_records()
        self.assertEqual(len(child_reads), 2)
        inv_ids = {cr.target_spec.get("invocation_id") for cr in child_reads.values()}
        self.assertEqual(len(inv_ids), 1)
        self.assertIsNotNone(list(inv_ids)[0])

    def test_13_batch_slices_retain_address_size_index_and_invocation_id(self):
        """Every batch slice preserves address, size, slice_index, and invocation_id."""
        self.adapter.collector_path = None
        slices = [(0x1000, 32), (0x2000, 64), (0x3000, 16)]
        res = self.adapter.read_memory_batch(1234, slices)

        child_reads = list(self.tracker.get_physical_read_records().values())
        self.assertEqual(len(child_reads), 3)
        child_reads.sort(key=lambda c: c.target_spec["slice_index"])

        for idx, (addr, sz) in enumerate(slices):
            ts = child_reads[idx].target_spec
            self.assertEqual(ts["slice_index"], idx)
            self.assertEqual(ts["address"], addr)
            self.assertEqual(ts["size"], sz)

    def test_14_collector_and_fallback_have_disjoint_identities_and_invocations(self):
        """Collector failure followed by fallback maintains disjoint IDs and preserves both."""
        self.adapter.collector_path = "/usr/bin/dynamicstate-collector"
        self.runner.collector_supported = False  # Triggers rc=127 -> fallback

        slices = [(0x1000, 32), (0x2000, 32)]
        res = self.adapter.read_memory_batch(1234, slices)

        child_reads = self.tracker.get_physical_read_records()
        # 2 collector slices + 2 shell fallback slices = 4 child reads
        self.assertEqual(len(child_reads), 4)

        coll_reads = [c for c in child_reads.values() if "collector" in c.target_type]
        shell_reads = [c for c in child_reads.values() if "shell" in c.target_type]
        self.assertEqual(len(coll_reads), 2)
        self.assertEqual(len(shell_reads), 2)

        coll_invs = {c.target_spec.get("invocation_id") for c in coll_reads}
        shell_invs = {c.target_spec.get("invocation_id") for c in shell_reads}
        self.assertTrue(coll_invs.isdisjoint(shell_invs))

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])


class TestPhase20A3415BatchAndCollectorFailureMatrix(unittest.TestCase):
    """P0.4: Batch and Collector Failure Semantics Matrix (all 14 scenarios)."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=100000))
        self.tracker.start()
        self.runner = EnhancedMockCommandRunner()
        self.adapter = RemoteSshTargetAdapter(host="remote.test", command_runner=self.runner)
        self.adapter.set_budget_tracker(self.tracker)
        self.slices = [(0x1000, 32), (0x2000, 32), (0x3000, 32)]

    def test_15_collector_all_slices_succeed(self):
        """Scenario 1: Collector succeeds for every slice."""
        self.adapter.collector_path = "/bin/collector"
        res = self.adapter.read_memory_batch(1234, self.slices)
        self.assertEqual(len(res), 3)
        for data, st, err in res:
            self.assertEqual(st, "OBSERVED")
            self.assertEqual(len(data), 32)
        self.assertEqual(self.tracker.metrics.bytes_read, 96)
        self.assertTrue(self.tracker.reconcile_ledger()["reconciled"])

    def test_16_collector_fails_before_invocation(self):
        """Scenario 2: Collector fails before invocation (rc=-2)."""
        self.adapter.collector_path = "/bin/collector"
        self.runner.fail_before_execution = True
        res = self.adapter.read_memory_batch(1234, self.slices)
        self.assertEqual(len(res), 3)
        for _, st, err in res:
            self.assertEqual(st, "UNAVAILABLE")
        self.assertEqual(self.tracker.metrics.bytes_read, 0)
        self.assertTrue(self.tracker.reconcile_ledger()["reconciled"])

    def test_17_collector_fails_after_invocation_rc_127(self):
        """Scenario 3: Collector binary not found (rc=127); fallback succeeds."""
        self.adapter.collector_path = "/bin/collector"
        self.runner.collector_supported = False
        res = self.adapter.read_memory_batch(1234, self.slices)
        for data, st, _ in res:
            self.assertEqual(st, "OBSERVED")
        self.assertEqual(self.tracker.metrics.bytes_read, 96)
        self.assertTrue(self.tracker.reconcile_ledger()["reconciled"])

    def test_18_collector_returns_malformed_json(self):
        """Scenario 4: Collector returns malformed json; fallback succeeds."""
        self.adapter.collector_path = "/bin/collector"
        b64 = base64.b64encode(b"\xaa" * 32).decode("ascii")
        def on_cmd(cmd, t):
            if "--read-slices" in cmd:
                return 0, "INVALID NON-JSON OUTPUT\n", ""
            return 0, "\n".join(f"{i}|{b64}" for i in range(5)) + "\n", ""
        self.runner.on_command = on_cmd
        res = self.adapter.read_memory_batch(1234, self.slices)
        for data, st, _ in res:
            self.assertEqual(st, "OBSERVED")
        self.assertTrue(self.tracker.reconcile_ledger()["reconciled"])

    def test_19_collector_returns_partial_data(self):
        """Scenario 5: Collector returns partial data (slice 0 full, slice 1 partial)."""
        self.adapter.collector_path = "/bin/collector"
        import json as _json
        def on_cmd(cmd, t):
            if "--read-slices" in cmd:
                return 0, _json.dumps({
                    "success": True,
                    "slices": [
                        {"status": "OBSERVED", "hex": "aa" * 32},
                        {"status": "PARTIAL", "hex": "bb" * 16},
                        {"status": "OBSERVED", "hex": "cc" * 32},
                    ]
                }), ""
            return 0, "", ""
        self.runner.on_command = on_cmd
        res = self.adapter.read_memory_batch(1234, self.slices)
        self.assertEqual(res[0][1], "OBSERVED")
        self.assertEqual(res[1][1], "PARTIAL")
        self.assertEqual(res[2][1], "OBSERVED")
        self.assertEqual(self.tracker.metrics.bytes_read, 32 + 16 + 32)
        self.assertTrue(self.tracker.reconcile_ledger()["reconciled"])

    def test_20_collector_mixed_success_and_failure(self):
        """Scenario 6: Collector returns mixed success and failure."""
        self.adapter.collector_path = "/bin/collector"
        import json as _json
        def on_cmd(cmd, t):
            if "--read-slices" in cmd:
                return 0, _json.dumps({
                    "success": True,
                    "slices": [
                        {"status": "OBSERVED", "hex": "aa" * 32},
                        {"status": "UNAVAILABLE", "hex": ""},
                        {"status": "OBSERVED", "hex": "cc" * 32},
                    ]
                }), ""
            return 0, "", ""
        self.runner.on_command = on_cmd
        res = self.adapter.read_memory_batch(1234, self.slices)
        self.assertEqual(res[0][1], "OBSERVED")
        self.assertEqual(res[1][1], "UNAVAILABLE")
        self.assertEqual(res[2][1], "OBSERVED")
        self.assertTrue(self.tracker.reconcile_ledger()["reconciled"])

    def test_21_shell_fallback_succeeds_after_collector_failure(self):
        """Scenario 7: Shell fallback succeeds after collector failure."""
        self.adapter.collector_path = "/bin/collector"
        self.runner.collector_supported = False
        res = self.adapter.read_memory_batch(1234, self.slices)
        self.assertEqual(len(res), 3)
        self.assertEqual(self.tracker.metrics.bytes_read, 96)
        self.assertTrue(self.tracker.reconcile_ledger()["reconciled"])

    def test_22_shell_fallback_fails_after_collector_failure(self):
        """Scenario 8: Shell fallback fails after collector failure."""
        self.adapter.collector_path = "/bin/collector"
        def on_cmd(cmd, t):
            if "--read-slices" in cmd:
                return 127, "", "collector missing"
            return -1, "", "SSH connection dropped"
        self.runner.on_command = on_cmd
        res = self.adapter.read_memory_batch(1234, self.slices)
        for _, st, _ in res:
            self.assertEqual(st, "UNAVAILABLE")
        self.assertEqual(self.tracker.metrics.bytes_read, 96)
        self.assertTrue(self.tracker.reconcile_ledger()["reconciled"])

    def test_23_ssh_timeout_after_invocation(self):
        """Scenario 9: SSH timeout after invocation."""
        self.adapter.collector_path = None
        def on_cmd(cmd, t):
            return -1, "", "SSH timed out"
        self.runner.on_command = on_cmd
        res = self.adapter.read_memory_batch(1234, self.slices)
        for _, st, err in res:
            self.assertEqual(st, "UNAVAILABLE")
        self.assertEqual(self.tracker.metrics.bytes_read, 96)
        self.assertTrue(self.tracker.reconcile_ledger()["reconciled"])

    def test_24_ssh_transport_disconnect(self):
        """Scenario 10: SSH transport disconnect."""
        self.adapter.collector_path = None
        def on_cmd(cmd, t):
            return -1, "", "Connection closed by remote host"
        self.runner.on_command = on_cmd
        res = self.adapter.read_memory_batch(1234, self.slices)
        for _, st, err in res:
            self.assertEqual(st, "UNAVAILABLE")
        self.assertEqual(self.tracker.metrics.bytes_read, 96)
        self.assertTrue(self.tracker.reconcile_ledger()["reconciled"])

    def test_25_malformed_base64_output_in_shell_fallback(self):
        """Scenario 11: Malformed base64 output."""
        self.adapter.collector_path = None
        def on_cmd(cmd, t):
            return 0, "0|===\n1|===\n2|===\n", ""
        self.runner.on_command = on_cmd
        res = self.adapter.read_memory_batch(1234, self.slices)
        for _, st, _ in res:
            self.assertEqual(st, "UNAVAILABLE")
        self.assertEqual(self.tracker.metrics.bytes_read, 96)
        self.assertTrue(self.tracker.reconcile_ledger()["reconciled"])

    def test_26_missing_slice_result_in_shell_output(self):
        """Scenario 12: Missing slice result in shell output."""
        self.adapter.collector_path = None
        b64 = base64.b64encode(b"\xaa" * 32).decode("ascii")
        def on_cmd(cmd, t):
            # Only returns index 0 and 2; index 1 is missing
            return 0, f"0|{b64}\n2|{b64}\n", ""
        self.runner.on_command = on_cmd
        res = self.adapter.read_memory_batch(1234, self.slices)
        self.assertEqual(res[0][1], "OBSERVED")
        self.assertEqual(res[1][1], "UNAVAILABLE")
        self.assertEqual(res[2][1], "OBSERVED")
        self.assertEqual(self.tracker.metrics.bytes_read, 96)
        self.assertTrue(self.tracker.reconcile_ledger()["reconciled"])

    def test_27_duplicate_slice_result_in_shell_output(self):
        """Scenario 13: Duplicate slice result keys in shell output."""
        self.adapter.collector_path = None
        b64 = base64.b64encode(b"\xaa" * 32).decode("ascii")
        def on_cmd(cmd, t):
            return 0, f"0|{b64}\n0|{b64}\n1|{b64}\n2|{b64}\n", ""
        self.runner.on_command = on_cmd
        res = self.adapter.read_memory_batch(1234, self.slices)
        for _, st, _ in res:
            self.assertEqual(st, "OBSERVED")
        self.assertEqual(self.tracker.metrics.bytes_read, 96)
        self.assertTrue(self.tracker.reconcile_ledger()["reconciled"])

    def test_28_concurrent_batch_operations_preserve_isolated_identities(self):
        """Scenario 14: Concurrent batch operations preserve isolated identities."""
        self.adapter.collector_path = None
        results = []

        def worker(start_addr):
            slices = [(start_addr + i * 32, 32) for i in range(2)]
            r = self.adapter.read_memory_batch(1234, slices)
            results.append(r)

        t1 = threading.Thread(target=worker, args=(0x1000,))
        t2 = threading.Thread(target=worker, args=(0x5000,))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        self.assertEqual(len(results), 2)
        self.assertEqual(self.tracker.metrics.bytes_read, 128)
        self.assertTrue(self.tracker.reconcile_ledger()["reconciled"])


class TestPhase20A3415InFlightReservationConcurrencySafety(unittest.TestCase):
    """P0.5: In-Flight Reservation and Concurrency Safety (all 6 scenarios)."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=100000))
        self.tracker.start()
        self.runner = EnhancedMockCommandRunner()
        self.adapter = RemoteSshTargetAdapter(host="remote.test", command_runner=self.runner)
        self.adapter.set_budget_tracker(self.tracker)

    def test_29_concurrency_release_attempt_during_in_flight_command(self):
        """Scenario 1: Command execution begins while another thread attempts reservation release."""
        blocker = threading.Event()
        self.runner.block_event = blocker
        self.adapter.collector_path = None

        release_errors = []

        def reader():
            self.adapter.read_memory(1234, 0x1000, 64)

        t = threading.Thread(target=reader)
        t.start()

        time.sleep(0.05)
        active_res = self.tracker.get_active_reservations()
        self.assertTrue(len(active_res) > 0)
        res = list(active_res.values())[0]

        # Attempt to release in-flight reservation
        try:
            self.tracker.release_reservation(res)
        except RuntimeError as re:
            release_errors.append(str(re))

        blocker.set()
        t.join()

        self.assertEqual(len(release_errors), 1)
        self.assertIn("PHYSICAL_READ_STARTED", release_errors[0])
        self.assertTrue(self.tracker.reconcile_ledger()["reconciled"])

    def test_30_concurrency_finalization_attempt_during_in_flight_command(self):
        """Scenario 2: Command execution begins while another thread attempts finalization."""
        blocker = threading.Event()
        self.runner.block_event = blocker
        self.adapter.collector_path = None

        finalize_errors = []

        def reader():
            self.adapter.read_memory(1234, 0x1000, 64)

        t = threading.Thread(target=reader)
        t.start()

        time.sleep(0.05)
        active_res = self.tracker.get_active_reservations()
        self.assertTrue(len(active_res) > 0)
        res = list(active_res.values())[0]

        try:
            res.finalize()
        except RuntimeError as re:
            finalize_errors.append(str(re))

        blocker.set()
        t.join()

        self.assertEqual(len(finalize_errors), 1)
        self.assertIn("remains in flight", finalize_errors[0])
        self.assertTrue(self.tracker.reconcile_ledger()["reconciled"])

    def test_31_concurrency_reconciliation_during_in_flight_command(self):
        """Scenario 3: Command runner blocks while reconciliation is requested."""
        blocker = threading.Event()
        self.runner.block_event = blocker
        self.adapter.collector_path = None

        recon_during_inflight = []

        def reader():
            self.adapter.read_memory(1234, 0x1000, 64)

        t = threading.Thread(target=reader)
        t.start()

        time.sleep(0.05)
        # Reconciliation during in-flight read
        res = self.tracker.reconcile_ledger()
        recon_during_inflight.append(res["reconciled"])

        blocker.set()
        t.join()

        self.assertTrue(recon_during_inflight[0])
        self.assertTrue(self.tracker.reconcile_ledger()["reconciled"])

    def test_32_concurrency_timeout_during_command_execution(self):
        """Scenario 4: Timeout occurs during command execution."""
        def on_cmd(cmd, t):
            return -1, "", "timed out"
        self.runner.on_command = on_cmd
        self.adapter.collector_path = None

        data, st, err = self.adapter.read_memory(1234, 0x1000, 64)
        self.assertEqual(st, "UNAVAILABLE")
        self.assertEqual(self.tracker.metrics.bytes_read, 64)
        self.assertTrue(self.tracker.reconcile_ledger()["reconciled"])

    def test_33_concurrency_recovery_triggered_while_child_in_flight(self):
        """Scenario 5: Recovery is triggered while a child is in flight."""
        with self.tracker.operation_scope("op_recovery_inflight", profile_id="p1") as scope:
            adm = scope.admit_read(64)
            cr = adm.start_child_read()
            cr.mark_started()
            cr.consume(actual_bytes=64)
            scope.record_read(bytes_read=64, admission=adm)
            # Inject fault to trigger emergency recovery
            self.tracker.set_fault_injection("before_physical_ledger_insertion", RuntimeError("Simulated crash"))
            snap = scope.finalize()

        # Commit recovered cleanly to FAILED status
        self.assertEqual(snap.accounting_status, "FAILED")
        self.assertTrue(snap.is_failure)
        # Child must be preserved as FAILED_ACCOUNTED
        self.assertEqual(cr.state, "FAILED_ACCOUNTED")
        self.assertTrue(self.tracker.reconcile_ledger()["reconciled"])

    def test_34_concurrency_conflicting_terminal_transitions_deterministic(self):
        """Scenario 6: Two threads attempt conflicting terminal transitions."""
        adm = self.tracker.admit_read(64)
        cr = adm.start_child_read()
        cr.mark_started()
        cr.consume(actual_bytes=64)

        barrier = threading.Barrier(2)
        results = []

        def worker1():
            barrier.wait()
            try:
                cr.account()
                results.append("account_ok")
            except Exception as e:
                results.append(f"account_err: {e}")

        def worker2():
            barrier.wait()
            try:
                cr.release()
                results.append("release_ok")
            except Exception as e:
                results.append(f"release_err: {e}")

        t1 = threading.Thread(target=worker1)
        t2 = threading.Thread(target=worker2)
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # Exactly one terminal state succeeded; release must fail because charged_bytes > 0
        self.assertEqual(cr.state, "ACCOUNTED")
        self.assertIn("account_ok", results)
        self.assertTrue(any("release_err" in r for r in results))


class TestPhase20A3415RuntimeInstrumentation(unittest.TestCase):
    """P1.1: Runtime Invocation Instrumentation asserting exact execution order and full provenance."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=100000))
        self.tracker.start()
        self.runner = EnhancedMockCommandRunner()
        self.adapter = RemoteSshTargetAdapter(host="remote.test", command_runner=self.runner)
        self.adapter.set_budget_tracker(self.tracker)

    def test_35_mock_instrumented_runner_verifies_exact_start_precedes_runner(self):
        """Recorded lifecycle start timestamp strictly precedes command runner execution."""
        lifecycle_order = []

        def on_cmd_hook(cmd_args):
            active_res = self.tracker.get_active_reservations()
            res = list(active_res.values())[0]
            cr = list(res.child_reads.values())[0]
            lifecycle_order.append(("runner_call", cr.state, cr.transition_history))

        self.runner.on_start_hook = on_cmd_hook
        self.adapter.collector_path = None

        data, st, err = self.adapter.read_memory(1234, 0x1000, 32)
        self.assertEqual(st, "OBSERVED")
        self.assertEqual(len(lifecycle_order), 1)
        event, cr_state, cr_th = lifecycle_order[0]
        self.assertEqual(event, "runner_call")
        self.assertEqual(cr_state, "PHYSICAL_READ_STARTED")
        self.assertIn("PHYSICAL_READ_STARTED", cr_th)

    def test_36_mock_instrumented_runner_records_full_lifecycle_provenance(self):
        """Runner records invocation start, completion, timeout/rc, and output bytes."""
        self.adapter.collector_path = None
        self.adapter.read_memory(1234, 0x1000, 32)

        self.assertTrue(len(self.runner.invocations) > 0)
        inv = self.runner.invocations[0]
        self.assertIn("start_time", inv)
        self.assertIn("completion_time", inv)
        self.assertTrue(inv["completed"])
        self.assertEqual(inv["rc"], 0)
        self.assertGreater(inv["output_bytes"], 0)
        self.assertGreaterEqual(inv["completion_time"], inv["start_time"])


class TestPhase20A3415ReconciliationEnhancements(unittest.TestCase):
    """P1.2: Reconciliation Enhancements (Invariants 1-21) and Deliberate Corruption Detection."""

    def setUp(self):
        self.tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=100000))
        self.tracker.start()

    def test_37_reconcile_ledger_passes_on_healthy_system(self):
        """All 21 invariants evaluate to True on healthy transactions."""
        with self.tracker.operation_scope("op_healthy", profile_id="p1") as scope:
            adm = scope.admit_read(64)
            cr = adm.start_child_read(target_spec={"slice_index": 0, "invocation_id": "inv_1", "expected_slice_count": 1})
            cr.mark_started()
            cr.consume(actual_bytes=64)
            scope.record_read(bytes_read=64, admission=adm)

        recon = self.tracker.reconcile_ledger()
        self.assertTrue(recon["reconciled"])
        details = recon["discrepancy_details"]

        for i in range(1, 22):
            self.assertTrue(any(f"inv_{i}_" in k for k in details), f"Invariant {i} missing from discrepancy_details")
        self.assertTrue(all(details.values()))

    def test_38_corruption_inv_20_batch_slice_completeness(self):
        """Deliberately corrupted batch slice indices triggers Invariant 20 violation."""
        with self.tracker.operation_scope("op_batch_gap", profile_id="p1") as scope:
            adm = scope.admit_read(64)
            cr0 = adm.start_child_read(target_spec={"slice_index": 0, "invocation_id": "inv_gap"})
            cr0.mark_started()
            cr0.consume(actual_bytes=32)
            # Gap: missing index 1, has index 2
            cr2 = adm.start_child_read(target_spec={"slice_index": 2, "invocation_id": "inv_gap"})
            cr2.mark_started()
            cr2.consume(actual_bytes=32)
            scope.record_read(bytes_read=64, admission=adm)

        recon = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(recon["reconciled"])
        self.assertFalse(recon["discrepancy_details"]["inv_20_batch_slice_completeness"])
        self.assertTrue(any("Invariant 20" in d for d in recon["discrepancies"]))

    def test_39_corruption_inv_21_collector_fallback_provenance_separation(self):
        """Deliberately sharing physical_read_id across collector and fallback triggers Invariant 21 violation."""
        adm = self.tracker.admit_read(64)
        c_coll = adm.start_child_read(target_type="remote_collector_memory_slice")
        c_coll.mark_started()
        c_coll.consume(actual_bytes=0, is_failure=True)

        c_shell = adm.start_child_read(target_type="remote_shell_memory_slice")
        c_shell.mark_started()
        c_shell.consume(actual_bytes=32)

        # Corrupt: force shared invocation_id
        c_coll.target_spec = {"invocation_id": "shared_inv"}
        c_shell.target_spec = {"invocation_id": "shared_inv"}

        recon = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(recon["reconciled"])
        self.assertFalse(recon["discrepancy_details"]["inv_21_collector_fallback_provenance_separation"])

    def test_40_corruption_inv_19_unknown_consumption_charged_zero(self):
        """Physical read with failure and unknown consumption charged as 0 triggers Invariant 19 violation."""
        with self.tracker.operation_scope("op_inv19", profile_id="p1") as scope:
            adm = scope.admit_read(64)
            cr = adm.start_child_read()
            cr.mark_started()
            cr.consume(actual_bytes=64)
            scope.record_read(bytes_read=64, admission=adm)

        # Corrupt: set failure with None measured bytes and 0 charged bytes
        rec = self.tracker._physical_read_records[cr.physical_read_id]
        rec.is_failure = True
        rec.measured_bytes_read = None
        rec.charged_bytes = 0

        recon = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(recon["reconciled"])
        self.assertFalse(recon["discrepancy_details"]["inv_19_unknown_consumption_never_zero"])

    def test_41_corruption_inv_09_started_read_released(self):
        """Physical read transitioning from STARTED to RELEASED triggers Invariant 9 violation."""
        adm = self.tracker.admit_read(64)
        cr = adm.start_child_read()
        cr.mark_started()

        # Bypass lock to force corrupted transition history
        cr._transition_history.append("RELEASED")
        self.tracker._physical_read_records[cr.physical_read_id] = cr

        recon = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(recon["reconciled"])
        self.assertFalse(recon["discrepancy_details"]["inv_9_no_started_read_released"])

    def test_42_corruption_inv_10_inflight_child_at_finalization(self):
        """Reservation finalized while child remains in PHYSICAL_READ_STARTED triggers Invariant 10 violation."""
        adm = self.tracker.admit_read(64)
        cr = adm.start_child_read()
        cr.mark_started()
        # Force reservation into ACCOUNTED state while child is in flight
        adm.state = "ACCOUNTED"

        recon = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(recon["reconciled"])
        self.assertFalse(recon["discrepancy_details"]["inv_10_no_inflight_child_at_finalization"])


if __name__ == "__main__":
    unittest.main()

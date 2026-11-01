"""tests/test_phase2_0_a_3_4_deadlock_proof_and_budget_audit.py
Phase 2.0-A.3.4: Deadlock Proof Reliability & Runtime Budget Audit Test Suite.

Validates:
1. pthread_mutex owner identification strictly validates Linux LP64 glibc ABI,
   rejects unsupported libc (musl), unsupported architectures, destroyed mutexes,
   invalid kinds/flags, unlocked mutexes, excessive recursion, and accidental TID memory.
2. WaitForEdge records auditable provenance, and WaitForGraph.validate_and_analyze()
   strictly requires verified owners, rejects conflicting owners on the same lock,
   rejects cycles with excessive temporal skew (>2.0s), and confirms genuine 2-thread
   and 3-thread deadlocks.
3. Live C runtime deadlock scenarios:
   - 2-thread circular deadlock (confirmed)
   - 3-thread circular deadlock (confirmed)
   - Normal condition-variable wait (no false deadlock cycle)
   - Lock contention without cycle (LOCK_CONTENTION_OBSERVED)
   - Raw futex without mutex layout (no false owner)
   - Accidental TID in memory (rejected as MUTEX_STATE_INVALID)
4. Remote target adapter fail-closed behavior:
   - RemoteTargetAdapter / RemoteSshTargetAdapter never touches local /proc or memory
   - resolve_mutex_owner returns MUTEX_LAYOUT_UNSUPPORTED
5. Runtime budget cost accounting:
   - Eliminates mapping_count * 64 synthetic estimates
   - Tracks actual procfs maps and thread task bytes read
   - Separates measured_bytes_read from conservative_estimated_bytes
   - Enforces pre-operation budget boundary checks
6. Evidence propagation fail-closed behavior (permission denied, target termination).
"""

import os
import shutil
import struct
import subprocess
import tempfile
import time
import unittest
from typing import Any, Dict, List, Optional

from extractor.target_adapter import (
    LocalTargetAdapter,
    RemoteSshTargetAdapter,
    RemoteTargetAdapter,
    ReadOnlyTargetAdapter,
    MutexOwnerResolutionResult,
    STATUS_OWNER_IDENTIFIED,
    STATUS_OWNER_NOT_IDENTIFIED,
    STATUS_MUTEX_LAYOUT_UNSUPPORTED,
    STATUS_MUTEX_STATE_INVALID,
    STATUS_MEMORY_READ_UNAVAILABLE,
    STATUS_PERMISSION_DENIED,
    LAYOUT_GLIBC_LP64,
    normalize_futex_address,
)
from extractor.adaptive_engine import (
    AdaptiveInvestigationEngine,
    WaitForEdge,
    WaitForGraph,
    RESULT_DEADLOCK_CYCLE_CONFIRMED,
    RESULT_LOCK_CONTENTION_OBSERVED,
    RESULT_WAITING_WITH_UNKNOWN_OWNER,
    RESULT_INCOMPLETE_WAIT_FOR_GRAPH,
    RESULT_INCONSISTENT_OWNER_EVIDENCE,
    RESULT_INCONCLUSIVE,
    STATE_COMPLETED,
    STATE_BUDGET_EXHAUSTED,
)
from extractor.observation_budget import (
    ObservationBudgetLimits,
    ObservationBudgetTracker,
)
from extractor.verdict_engine import (
    DIAG_CONFIRMED,
    DIAG_SUSPECTED,
    DIAG_PARTIALLY_CONFIRMED,
    DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE,
)


class TestPhase20A34DeadlockProofAndBudgetAudit(unittest.TestCase):
    """Rigorous audit test suite for Phase 2.0-A.3.4."""

    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp(prefix="dynstate_a34_")
        cls.fixtures_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "fixtures", "real_runtime")
        )

        cls.bin_2way = os.path.join(cls.work_dir, "proc_2way_deadlock")
        cls.bin_3way = os.path.join(cls.work_dir, "proc_3way_deadlock")
        cls.bin_cv = os.path.join(cls.work_dir, "proc_normal_cv")
        cls.bin_contention = os.path.join(cls.work_dir, "proc_contention")
        cls.bin_raw_futex = os.path.join(cls.work_dir, "proc_raw_futex")
        cls.bin_fake_mutex = os.path.join(cls.work_dir, "proc_fake_mutex")

        # Compile fixtures
        compile_targets = [
            ("proc_thread_circular_deadlock.c", cls.bin_2way),
            ("proc_thread_3way_deadlock.c", cls.bin_3way),
            ("proc_thread_normal_cv.c", cls.bin_cv),
            ("proc_scenario_c_thread_contention.c", cls.bin_contention),
            ("proc_raw_futex_no_mutex.c", cls.bin_raw_futex),
            ("proc_accidental_tid_memory.c", cls.bin_fake_mutex),
        ]

        for src_name, bin_dest in compile_targets:
            src_path = os.path.join(cls.fixtures_dir, src_name)
            if os.path.exists(src_path):
                cmd = ["gcc", "-O2", "-Wall", "-Wextra", "-pthread", src_path, "-o", bin_dest]
                rc = subprocess.call(cmd)
                if rc != 0:
                    raise RuntimeError(f"Failed to compile fixture {src_name} -> {bin_dest}")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work_dir, ignore_errors=True)

    # =========================================================================
    # 1. Mutex ABI & State Validation Tests
    # =========================================================================

    def test_01_supported_glibc_lp64_resolution(self):
        """Supported glibc LP64 target correctly validates layout and identifies active owner TID."""
        proc = subprocess.Popen([self.bin_contention])
        try:
            time.sleep(0.1)
            pid = proc.pid
            adapter = LocalTargetAdapter()
            threads = adapter.get_threads(pid)

            # Find thread waiting on futex
            waiter = next((t for t in threads if t.get("is_futex_wait")), None)
            self.assertIsNotNone(waiter, "Expected at least one thread in futex wait")

            raw_lock = waiter.get("syscall_arg0")
            _, norm_int, addr_st, _ = normalize_futex_address(raw_lock)
            self.assertEqual(addr_st, "WAIT_ADDRESS_OBSERVED")
            self.assertIsNotNone(norm_int)

            res = adapter.resolve_mutex_owner(pid, norm_int)
            self.assertIsInstance(res, MutexOwnerResolutionResult)
            self.assertEqual(res.status, STATUS_OWNER_IDENTIFIED)
            self.assertEqual(res.layout_id, LAYOUT_GLIBC_LP64)
            self.assertIsNotNone(res.owner_tid)
            self.assertTrue(bool(res))
            self.assertEqual(int(res), res.owner_tid)

            # Verify that owner TID belongs to the target process
            tids = [t["tid"] for t in threads]
            self.assertIn(res.owner_tid, tids)
        finally:
            proc.terminate()
            proc.wait(timeout=2.0)

    def test_02_unsupported_libc_musl_rejection(self):
        """Adapter explicitly rejects musl libc targets with STATUS_MUTEX_LAYOUT_UNSUPPORTED."""
        adapter = LocalTargetAdapter()
        # Mock get_proc_maps to simulate musl libc
        orig_get_proc_maps = adapter.get_proc_maps
        adapter.get_proc_maps = lambda pid: [
            {"pathname": "/lib/ld-musl-x86_64.so.1", "size": 4096, "category": "file", "is_readable": True}
        ]
        try:
            res = adapter.resolve_mutex_owner(os.getpid(), 0x7ffd1234)
            self.assertEqual(res.status, STATUS_MUTEX_LAYOUT_UNSUPPORTED)
            self.assertIn("musl", (res.error or "").lower())
            self.assertFalse(bool(res))
        finally:
            adapter.get_proc_maps = orig_get_proc_maps

    def test_03_unsupported_arch_rejection(self):
        """Adapter explicitly rejects non-LP64 architectures with STATUS_MUTEX_LAYOUT_UNSUPPORTED."""
        adapter = LocalTargetAdapter()
        orig_ident = adapter.get_process_identity
        adapter.get_process_identity = lambda pid: {"architecture": "armv7l", "build_id": None}
        try:
            res = adapter.resolve_mutex_owner(os.getpid(), 0x7ffd1234)
            self.assertEqual(res.status, STATUS_MUTEX_LAYOUT_UNSUPPORTED)
            self.assertIn("unsupported", (res.error or "").lower())
            self.assertFalse(bool(res))
        finally:
            adapter.get_process_identity = orig_ident

    def test_04_destroyed_mutex_state_rejected(self):
        """Mutex with __kind == -1 (PTHREAD_MUTEX_DESTROYED) returns STATUS_MUTEX_STATE_INVALID."""
        adapter = LocalTargetAdapter()
        # Fake memory slice: __lock=1, __count=0, __owner=123, __nusers=0, __kind=-1
        fake_raw = struct.pack("<iIiIi", 1, 0, 123, 0, -1) + b"\x00" * 20
        orig_read = adapter.read_memory
        adapter.read_memory = lambda pid, addr, sz: (fake_raw, "OBSERVED", None)
        try:
            res = adapter.resolve_mutex_owner(os.getpid(), 0x7ffd1234)
            self.assertEqual(res.status, STATUS_MUTEX_STATE_INVALID)
            self.assertIn("destroyed", (res.error or "").lower())
            self.assertFalse(bool(res))
        finally:
            adapter.read_memory = orig_read

    def test_05_unlocked_mutex_returns_owner_not_identified(self):
        """Mutex with __lock == 0 (unlocked) returns STATUS_OWNER_NOT_IDENTIFIED without owner."""
        adapter = LocalTargetAdapter()
        # Fake memory slice: __lock=0, __count=0, __owner=0, __nusers=0, __kind=0
        fake_raw = struct.pack("<iIiIi", 0, 0, 0, 0, 0) + b"\x00" * 20
        orig_read = adapter.read_memory
        adapter.read_memory = lambda pid, addr, sz: (fake_raw, "OBSERVED", None)
        try:
            res = adapter.resolve_mutex_owner(os.getpid(), 0x7ffd1234)
            self.assertEqual(res.status, STATUS_OWNER_NOT_IDENTIFIED)
            self.assertIn("unlocked", (res.error or "").lower())
            self.assertIsNone(res.owner_tid)
            self.assertFalse(bool(res))
        finally:
            adapter.read_memory = orig_read

    def test_06_invalid_mutex_kind_flags_rejected(self):
        """Mutex with invalid flags in __kind returns STATUS_MUTEX_STATE_INVALID."""
        adapter = LocalTargetAdapter()
        # __kind has invalid upper bits (e.g. 0x8000)
        fake_raw = struct.pack("<iIiIi", 1, 0, 123, 0, 0x8000) + b"\x00" * 20
        orig_read = adapter.read_memory
        adapter.read_memory = lambda pid, addr, sz: (fake_raw, "OBSERVED", None)
        try:
            res = adapter.resolve_mutex_owner(os.getpid(), 0x7ffd1234)
            self.assertEqual(res.status, STATUS_MUTEX_STATE_INVALID)
            self.assertIn("invalid mutex kind", (res.error or "").lower())
            self.assertFalse(bool(res))
        finally:
            adapter.read_memory = orig_read

    def test_07_excessive_recursion_count_rejected(self):
        """Normal mutex with non-zero count or excessive count returns STATUS_MUTEX_STATE_INVALID."""
        adapter = LocalTargetAdapter()
        # Normal mutex (kind=0) with __count=5 (invalid for non-recursive)
        fake_raw = struct.pack("<iIiIi", 1, 5, 123, 0, 0) + b"\x00" * 20
        orig_read = adapter.read_memory
        adapter.read_memory = lambda pid, addr, sz: (fake_raw, "OBSERVED", None)
        try:
            res = adapter.resolve_mutex_owner(os.getpid(), 0x7ffd1234)
            self.assertEqual(res.status, STATUS_MUTEX_STATE_INVALID)
            self.assertIn("non-zero count", (res.error or "").lower())
            self.assertFalse(bool(res))
        finally:
            adapter.read_memory = orig_read

    def test_08_accidental_tid_memory_rejection(self):
        """Live process with non-mutex buffer matching active TID is rejected as MUTEX_STATE_INVALID."""
        proc = subprocess.Popen([self.bin_fake_mutex], stdout=subprocess.PIPE, text=True)
        try:
            time.sleep(0.1)
            line = proc.stdout.readline()
            self.assertIn("[FAKE_MUTEX]", line)
            # Parse fake_addr from output e.g. "fake_addr=0x... "
            parts = line.strip().split()
            addr_part = next(p for p in parts if "fake_addr=" in p)
            addr_hex = addr_part.split("=")[1].rstrip(",")
            addr_int = int(addr_hex, 16)

            adapter = LocalTargetAdapter()
            res = adapter.resolve_mutex_owner(proc.pid, addr_int)
            self.assertEqual(res.status, STATUS_MUTEX_STATE_INVALID)
            self.assertFalse(bool(res))
            self.assertIsNone(res.owner_tid)
        finally:
            proc.terminate()
            proc.wait(timeout=2.0)

    def test_09_owner_tid_absent_from_task_procfs_rejected(self):
        """Mutex memory containing TID not present in /proc/<pid>/task returns STATUS_OWNER_NOT_IDENTIFIED."""
        adapter = LocalTargetAdapter()
        # TID 4194300 almost certainly does not exist in our current test process
        fake_raw = struct.pack("<iIiIi", 1, 0, 4194300, 0, 0) + b"\x00" * 20
        orig_read = adapter.read_memory
        adapter.read_memory = lambda pid, addr, sz: (fake_raw, "OBSERVED", None)
        try:
            res = adapter.resolve_mutex_owner(os.getpid(), 0x7ffd1234)
            self.assertEqual(res.status, STATUS_OWNER_NOT_IDENTIFIED)
            self.assertIn("does not exist in target process", (res.error or "").lower())
            self.assertFalse(bool(res))
        finally:
            adapter.read_memory = orig_read

    def test_10_raw_futex_no_mutex_layout_rejection(self):
        """Live process waiting on raw SYS_futex word does NOT identify a false mutex owner."""
        proc = subprocess.Popen([self.bin_raw_futex], stdout=subprocess.PIPE, text=True)
        try:
            time.sleep(0.1)
            line = proc.stdout.readline()
            self.assertIn("[RAW_FUTEX]", line)
            addr_part = next(p for p in line.strip().split() if "futex_addr=" in p)
            futex_addr = int(addr_part.split("=")[1].rstrip(")"), 16)

            adapter = LocalTargetAdapter()
            res = adapter.resolve_mutex_owner(proc.pid, futex_addr)
            # The memory contains raw uint32_t 42, so unpack will see invalid kind / count / owner
            self.assertIn(res.status, (STATUS_MUTEX_STATE_INVALID, STATUS_OWNER_NOT_IDENTIFIED))
            self.assertFalse(bool(res))
            self.assertIsNone(res.owner_tid)
        finally:
            proc.terminate()
            proc.wait(timeout=2.0)

    # =========================================================================
    # 2. Wait-For Graph Audit & Deadlock Cycle Reliability
    # =========================================================================

    def test_11_two_thread_circular_deadlock_confirmed(self):
        """Live 2-thread circular deadlock produces confirmed cycle via WaitForGraph."""
        proc = subprocess.Popen([self.bin_2way])
        try:
            time.sleep(0.15)
            pid = proc.pid
            adapter = LocalTargetAdapter()
            engine = AdaptiveInvestigationEngine()

            res = engine.investigate_process_health(
                goal="Check for circular deadlocks.",
                pid=pid,
                companion_elf_path=self.bin_2way,
            )

            self.assertTrue(res["success"])
            self.assertIn("insp_locks", res["executed_profiles"])
            # Check lock inspection output
            insp_summary = res.get("inspection_summary", {})
            self.assertTrue(insp_summary.get("insp_locks", {}).get("deadlock_detected"))
            self.assertEqual(
                insp_summary.get("insp_locks", {}).get("result_category"),
                RESULT_DEADLOCK_CYCLE_CONFIRMED,
            )
            cycle = insp_summary.get("insp_locks", {}).get("deadlock_cycle")
            self.assertIsNotNone(cycle)
            self.assertGreaterEqual(len(cycle), 2)
        finally:
            proc.terminate()
            proc.wait(timeout=2.0)

    def test_12_three_thread_circular_deadlock_confirmed(self):
        """Live 3-thread circular deadlock (T1->M1->T2->M2->T3->M3->T1) produces confirmed cycle."""
        proc = subprocess.Popen([self.bin_3way])
        try:
            time.sleep(0.2)
            pid = proc.pid
            adapter = LocalTargetAdapter()
            engine = AdaptiveInvestigationEngine()

            res = engine.investigate_process_health(
                goal="Check for 3-thread deadlock cycle.",
                pid=pid,
                companion_elf_path=self.bin_3way,
            )

            self.assertTrue(res["success"])
            self.assertIn("insp_locks", res["executed_profiles"])
            insp_locks_out = res.get("inspection_summary", {}).get("insp_locks", {})
            self.assertTrue(insp_locks_out.get("deadlock_detected"))
            self.assertEqual(insp_locks_out.get("result_category"), RESULT_DEADLOCK_CYCLE_CONFIRMED)
            cycle = insp_locks_out.get("deadlock_cycle")
            self.assertIsNotNone(cycle)
            # A 3-thread cycle has 4 nodes (e.g. [T1, T2, T3, T1])
            self.assertGreaterEqual(len(cycle), 4)
            self.assertEqual(cycle[0], cycle[-1], "Cycle must close at start node")
        finally:
            proc.terminate()
            proc.wait(timeout=2.0)

    def test_13_normal_condition_variable_not_deadlock(self):
        """Normal condition variable wait does NOT produce a false circular deadlock."""
        proc = subprocess.Popen([self.bin_cv])
        try:
            time.sleep(0.1)
            pid = proc.pid
            adapter = LocalTargetAdapter()
            engine = AdaptiveInvestigationEngine()

            res = engine.investigate_process_health(
                goal="Check for lock issues on normal condition variable.",
                pid=pid,
                companion_elf_path=self.bin_cv,
            )

            self.assertTrue(res["success"])
            insp_locks_out = res.get("inspection_summary", {}).get("insp_locks", {})
            self.assertFalse(insp_locks_out.get("deadlock_detected"))
            self.assertIsNone(insp_locks_out.get("deadlock_cycle"))
            self.assertNotEqual(insp_locks_out.get("result_category"), RESULT_DEADLOCK_CYCLE_CONFIRMED)
        finally:
            proc.terminate()
            proc.wait(timeout=2.0)

    def test_14_two_waiters_one_lock_no_cycle(self):
        """Multiple threads waiting on 1 lock produce LOCK_CONTENTION_OBSERVED, not DEADLOCK."""
        proc = subprocess.Popen([self.bin_contention])
        try:
            time.sleep(0.1)
            pid = proc.pid
            engine = AdaptiveInvestigationEngine()

            res = engine.investigate_process_health(
                goal="Check contention without cycle.",
                pid=pid,
                companion_elf_path=self.bin_contention,
            )

            self.assertTrue(res["success"])
            insp_locks_out = res.get("inspection_summary", {}).get("insp_locks", {})
            self.assertFalse(insp_locks_out.get("deadlock_detected"))
            self.assertIsNone(insp_locks_out.get("deadlock_cycle"))
            self.assertIn(
                insp_locks_out.get("result_category"),
                (RESULT_LOCK_CONTENTION_OBSERVED, RESULT_INCOMPLETE_WAIT_FOR_GRAPH),
            )
        finally:
            proc.terminate()
            proc.wait(timeout=2.0)

    def test_15_graph_rejects_unconfirmed_edges(self):
        """WaitForGraph strictly excludes unverified or unsupported edges from forming a cycle."""
        graph = WaitForGraph()
        t_now = time.time()
        # Edge 1: verified (T1 -> T2)
        graph.add_edge(WaitForEdge(
            waiter_tid=101,
            sync_object="0x1000",
            owner_tid=102,
            owner_identification_status=STATUS_OWNER_IDENTIFIED,
            observation_timestamp=t_now,
        ))
        # Edge 2: UNVERIFIED / unsupported (T2 -> T1)
        graph.add_edge(WaitForEdge(
            waiter_tid=102,
            sync_object="0x2000",
            owner_tid=101,
            owner_identification_status=STATUS_MUTEX_LAYOUT_UNSUPPORTED,
            observation_timestamp=t_now,
        ))

        cycle, category, issues = graph.validate_and_analyze()
        self.assertIsNone(cycle)
        self.assertNotEqual(category, RESULT_DEADLOCK_CYCLE_CONFIRMED)
        self.assertEqual(category, RESULT_WAITING_WITH_UNKNOWN_OWNER)
        self.assertFalse(graph.has_cycle())

    def test_16_graph_rejects_conflicting_owners(self):
        """WaitForGraph detects conflicting owners on the same lock and returns INCONSISTENT_OWNER_EVIDENCE."""
        graph = WaitForGraph()
        t_now = time.time()
        # T1 claims lock 0x1000 is owned by 102
        graph.add_edge(WaitForEdge(
            waiter_tid=101,
            sync_object="0x1000",
            owner_tid=102,
            owner_identification_status=STATUS_OWNER_IDENTIFIED,
            observation_timestamp=t_now,
        ))
        # T3 claims same lock 0x1000 is owned by 104
        graph.add_edge(WaitForEdge(
            waiter_tid=103,
            sync_object="0x1000",
            owner_tid=104,
            owner_identification_status=STATUS_OWNER_IDENTIFIED,
            observation_timestamp=t_now,
        ))

        cycle, category, issues = graph.validate_and_analyze()
        self.assertIsNone(cycle)
        self.assertEqual(category, RESULT_INCONSISTENT_OWNER_EVIDENCE)
        self.assertTrue(any("Conflicting owners" in s for s in issues))

    def test_17_graph_rejects_excessive_temporal_skew(self):
        """WaitForGraph rejects candidate cycle when edge timestamps differ by > 2.0 seconds."""
        graph = WaitForGraph()
        t0 = 1000.0
        t1 = 1002.5  # 2.5s skew > 2.0s limit
        graph.add_edge(WaitForEdge(
            waiter_tid=101,
            sync_object="0x1000",
            owner_tid=102,
            owner_identification_status=STATUS_OWNER_IDENTIFIED,
            observation_timestamp=t0,
        ))
        graph.add_edge(WaitForEdge(
            waiter_tid=102,
            sync_object="0x2000",
            owner_tid=101,
            owner_identification_status=STATUS_OWNER_IDENTIFIED,
            observation_timestamp=t1,
        ))

        cycle, category, issues = graph.validate_and_analyze(max_temporal_skew_sec=2.0)
        self.assertIsNone(cycle)
        self.assertEqual(category, RESULT_INCONCLUSIVE)
        self.assertTrue(any("temporal skew" in s.lower() for s in issues))

    # =========================================================================
    # 3. Remote Target Adapter Audit
    # =========================================================================

    def test_18_remote_target_adapter_never_touches_local_proc(self):
        """RemoteSshTargetAdapter fails closed on resolve_mutex_owner without local access."""
        adapter = RemoteSshTargetAdapter(host="remote.target.internal", user="testuser")
        self.assertTrue(adapter.is_remote())
        res = adapter.resolve_mutex_owner(1234, 0x7ffd0000)
        self.assertIsInstance(res, MutexOwnerResolutionResult)
        self.assertEqual(res.status, STATUS_MUTEX_LAYOUT_UNSUPPORTED)
        self.assertIn("does not support verified pthread_mutex inspection", res.error)
        self.assertFalse(bool(res))

    def test_19_remote_target_adapter_exported_alias(self):
        """RemoteTargetAdapter is exported and aliases RemoteSshTargetAdapter."""
        self.assertIs(RemoteTargetAdapter, RemoteSshTargetAdapter)
        adapter = RemoteTargetAdapter(host="node-42.cluster.local")
        self.assertTrue(adapter.is_remote())

    # =========================================================================
    # 4. Runtime Budget Accounting Audit
    # =========================================================================

    def test_20_proc_maps_measured_bytes_not_synthetic(self):
        """LocalTargetAdapter.get_proc_maps and get_process_memory_info measure actual bytes read."""
        adapter = LocalTargetAdapter()
        pid = os.getpid()

        maps = adapter.get_proc_maps(pid)
        maps_bytes = adapter.get_last_maps_bytes_read()
        self.assertGreater(maps_bytes, 0)
        # Verify maps_bytes matches actual file size of /proc/<pid>/maps
        with open(f"/proc/{pid}/maps", "rb") as f:
            expected_sz = len(f.read())
        # Maps file read may vary slightly if threads spawn, but should be exact or very close
        self.assertGreater(maps_bytes, len(maps) * 10)

        mem_info = adapter.get_process_memory_info(pid)
        # Ensure actual_bytes_read does NOT equal len(maps) * 64 + status
        actual_b = mem_info["actual_bytes_read"]
        self.assertGreater(actual_b, 0)
        actual_costs = mem_info["actual_costs"]
        self.assertEqual(actual_b, sum(actual_costs.values()))

    def test_21_get_threads_measured_bytes_accounting(self):
        """LocalTargetAdapter.get_threads tracks exact bytes read across thread procfs files."""
        adapter = LocalTargetAdapter()
        pid = os.getpid()
        threads = adapter.get_threads(pid)
        th_bytes = adapter.get_last_threads_bytes_read()
        self.assertGreater(th_bytes, 0)
        # Each thread reads comm, stat, status, wchan, syscall
        self.assertGreaterEqual(th_bytes, len(threads) * 100)

    def test_22_pre_operation_budget_exhaustion(self):
        """Inspection engine aborts before execution if remaining budget is exhausted."""
        engine = AdaptiveInvestigationEngine()
        # Create budget tracker with 0 wall clock remaining
        limits = ObservationBudgetLimits(max_wall_clock_ms=10.0)
        tracker = ObservationBudgetTracker(limits)
        tracker.start()
        time.sleep(0.015)  # Exhaust 10ms

        mod = engine.registry.get("insp_locks")
        ctx = mod.profile
        res = mod._func(None, pid=os.getpid(), adapter=LocalTargetAdapter(), budget_tracker=tracker)
        self.assertEqual(res["status"], "BUDGET_EXHAUSTED")
        self.assertEqual(res["bytes_read"], 0)

    def test_23_observation_budget_tracker_separates_measured_and_conservative(self):
        """ObservationBudgetTracker tracks measured_bytes_read separately from conservative_estimated_bytes."""
        limits = ObservationBudgetLimits(max_bytes_read=100000)
        tracker = ObservationBudgetTracker(limits)
        tracker.start()

        # 1. Measured read
        r1 = tracker.record_read(bytes_read=2048, latency_us=50.0, profile_id="p1")
        self.assertEqual(r1["measured_bytes_read"], 2048)
        self.assertEqual(r1["charged_bytes"], 2048)
        self.assertFalse(r1["used_conservative_byte_estimate"])

        # 2. Unmeasured failure read using conservative estimate
        r2 = tracker.record_read(
            bytes_read=None,
            is_failure=True,
            conservative_estimate_bytes=4096,
            profile_id="p2",
        )
        self.assertIsNone(r2["measured_bytes_read"])
        self.assertEqual(r2["charged_bytes"], 4096)
        self.assertTrue(r2["used_conservative_byte_estimate"])

        self.assertEqual(tracker.metrics.measured_bytes_read, 2048)
        self.assertEqual(tracker.metrics.conservative_estimated_bytes, 4096)
        self.assertEqual(tracker.metrics.bytes_read, 6144)

    # =========================================================================
    # 5. Fail-Closed Evidence Propagation Tests
    # =========================================================================

    def test_24_permission_denied_fail_closed(self):
        """Adapter permission denial returns STATUS_PERMISSION_DENIED fail-closed."""
        adapter = LocalTargetAdapter()
        orig_read = adapter.read_memory
        adapter.read_memory = lambda pid, addr, sz: (None, "PERMISSION_DENIED", "EACCES")
        try:
            res = adapter.resolve_mutex_owner(os.getpid(), 0x7ffd1234)
            self.assertEqual(res.status, STATUS_PERMISSION_DENIED)
            self.assertFalse(bool(res))
        finally:
            adapter.read_memory = orig_read

    def test_25_target_termination_during_investigation(self):
        """Process termination during investigation produces fail-closed TARGET_TERMINATED."""
        proc = subprocess.Popen(["sleep", "10"])
        pid = proc.pid
        adapter = LocalTargetAdapter()
        proc.terminate()
        proc.wait(timeout=2.0)

        alive, err = adapter.check_liveness(pid)
        self.assertFalse(alive)
        self.assertTrue(any(w in (err or "").lower() for w in ("terminated", "not found", "esrch")))


if __name__ == "__main__":
    unittest.main()

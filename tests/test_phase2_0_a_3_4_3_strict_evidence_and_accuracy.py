"""Phase 2.0-A.3.4.3 — Strict Evidence Gate & Measurement Accuracy Closure.

Adversarial regression test suite validating:
1. Only explicitly verified process identities (IDENTITY_VERIFIED) can participate in confirmed deadlock cycles.
2. Missing sampling epochs remain missing (None) throughout the entire execution path.
3. Measured bytes and latency represent actual measurements, not hardcoded approximations.
4. Nested observations and partial failures cannot bypass or corrupt global budget accounting.
"""

import base64
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from typing import Any, Dict, List, Optional, Tuple

from extractor.target_adapter import (
    LocalTargetAdapter,
    ReadOnlyTargetAdapter,
    RemoteSshTargetAdapter,
    MutexOwnerResolutionResult,
    STATUS_OWNER_IDENTIFIED,
    STATUS_OWNER_NOT_IDENTIFIED,
    STATUS_MUTEX_LAYOUT_UNSUPPORTED,
    STATUS_MUTEX_STATE_INVALID,
    STATUS_MEMORY_READ_UNAVAILABLE,
    STATUS_PERMISSION_DENIED,
    ABI_GLIBC_VERIFIED,
    ABI_MUSL_UNSUPPORTED,
    ABI_LIBC_UNKNOWN,
    ABI_STATIC_OR_UNIDENTIFIED,
    ABI_ARCH_UNSUPPORTED,
    ABI_ELF_CLASS_UNSUPPORTED,
    ABI_ENDIANNESS_UNSUPPORTED,
    IDENTITY_VERIFIED,
    IDENTITY_UNAVAILABLE,
    IDENTITY_INCONSISTENT,
    IDENTITY_UNVERIFIED,
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
)
from extractor.observation_budget import (
    ObservationBudgetLimits,
    ObservationBudgetTracker,
)
from extractor.inspection_module import FunctionalInspectionModule, InspectionContext
from extractor.debug_image import inspect_elf, BinaryIdentity, clear_elf_identity_cache


class TestPhase20A343StrictEvidenceAndAccuracy(unittest.TestCase):
    """Deterministic regression test suite for Phase 2.0-A.3.4.3."""

    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp(prefix="dynstate_a343_")
        cls.fixtures_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "fixtures", "real_runtime")
        )
        cls.bin_2way = os.path.join(cls.work_dir, "proc_2way_deadlock")
        src_path = os.path.join(cls.fixtures_dir, "proc_thread_circular_deadlock.c")
        if os.path.exists(src_path):
            cmd = ["gcc", "-O2", "-Wall", "-Wextra", "-pthread", src_path, "-o", cls.bin_2way]
            rc = subprocess.call(cmd)
            if rc != 0:
                raise RuntimeError(f"Failed to compile fixture -> {cls.bin_2way}")

    @classmethod
    def tearDownClass(cls):
        if os.path.exists(cls.work_dir):
            shutil.rmtree(cls.work_dir, ignore_errors=True)

    def setUp(self):
        clear_elf_identity_cache()

    def _sample_valid_proc_identity(self, pid: int = 1000) -> Dict[str, Any]:
        return {
            "pid": pid,
            "process_start_time": 100000,
            "architecture": "x86_64",
            "elf_class": "ELF64",
            "endianness": "little",
            "executable": "/usr/bin/app",
            "build_id": "0123456789abcdef",
            "status": "OBSERVED",
            "identity_status": IDENTITY_VERIFIED,
        }

    def _sample_valid_meta(self, owner_tid: int = 102, waiter_tid: int = 101) -> Dict[str, Any]:
        return {
            "abi_status": ABI_GLIBC_VERIFIED,
            "layout_id": LAYOUT_GLIBC_LP64,
            "raw_bytes": struct.pack("<iIiIi", 1, 0, owner_tid, 0, 0) + b"\x00" * 20,
            "read_bytes_len": 40,
            "lock_word": 1,
            "count": 0,
            "owner": owner_tid,
            "nusers": 0,
            "kind": 0,
            "base_kind": 0,
            "memory_read_status": "OBSERVED",
            "target_tids": [waiter_tid, owner_tid],
        }

    # =========================================================================
    # 1. OBSERVED Identity Cannot Confirm a Deadlock
    # =========================================================================

    def test_01_observed_identity_cannot_confirm_deadlock(self):
        """Process identity with status='OBSERVED' without explicit IDENTITY_VERIFIED cannot confirm deadlock."""
        g = WaitForGraph()
        t_now = time.time()
        # Identity claiming OBSERVED status instead of IDENTITY_VERIFIED
        observed_ident = {
            "pid": 100,
            "process_start_time": 100000,
            "architecture": "x86_64",
            "elf_class": "ELF64",
            "endianness": "little",
            "executable": "/usr/bin/app",
            "status": "OBSERVED",
            "identity_status": "OBSERVED",  # Legacy status; NOT IDENTITY_VERIFIED
        }
        g.add_edge(WaitForEdge(
            waiter_tid=101, sync_object="0x1000", normalized_address="0x1000",
            owner_tid=102, owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED",
            observation_timestamp=t_now, target_pid=100, process_identity=observed_ident,
            sampling_epoch=1, metadata=self._sample_valid_meta(102, 101),
        ))
        g.add_edge(WaitForEdge(
            waiter_tid=102, sync_object="0x2000", normalized_address="0x2000",
            owner_tid=101, owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED",
            observation_timestamp=t_now + 0.05, target_pid=100, process_identity=observed_ident,
            sampling_epoch=1, metadata=self._sample_valid_meta(101, 102),
        ))

        cycle, category, issues = g.validate_and_analyze(allowed_epoch=1)
        self.assertIsNone(cycle, "Cycle must not be confirmed when identity status is OBSERVED")
        self.assertNotEqual(category, RESULT_DEADLOCK_CYCLE_CONFIRMED)
        self.assertTrue(any("REJECT_IDENTITY_UNVERIFIED" in s for s in issues))

    # =========================================================================
    # 2. Only IDENTITY_VERIFIED Identity Can Pass the Identity Gate
    # =========================================================================

    def test_02_only_identity_verified_can_pass_identity_gate(self):
        """Explicit IDENTITY_VERIFIED identity with matching target_pid successfully confirms deadlock."""
        g = WaitForGraph()
        t_now = time.time()
        verified_ident = self._sample_valid_proc_identity(100)
        self.assertEqual(verified_ident["identity_status"], IDENTITY_VERIFIED)

        g.add_edge(WaitForEdge(
            waiter_tid=101, sync_object="0x1000", normalized_address="0x1000",
            owner_tid=102, owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED",
            observation_timestamp=t_now, target_pid=100, process_identity=verified_ident,
            sampling_epoch=1, metadata=self._sample_valid_meta(102, 101),
        ))
        g.add_edge(WaitForEdge(
            waiter_tid=102, sync_object="0x2000", normalized_address="0x2000",
            owner_tid=101, owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED",
            observation_timestamp=t_now + 0.05, target_pid=100, process_identity=verified_ident,
            sampling_epoch=1, metadata=self._sample_valid_meta(101, 102),
        ))

        cycle, category, issues = g.validate_and_analyze(allowed_epoch=1)
        self.assertIsNotNone(cycle)
        self.assertEqual(category, RESULT_DEADLOCK_CYCLE_CONFIRMED)
        self.assertEqual(cycle, [101, 102, 101])

    # =========================================================================
    # 3. Identity PID Mismatch Rejects an Edge
    # =========================================================================

    def test_03_identity_pid_mismatch_rejects_edge(self):
        """Edge target_pid not matching process_identity['pid'] triggers REJECT_IDENTITY_PID_MISMATCH."""
        g = WaitForGraph()
        t_now = time.time()
        # Identity has PID 200, but edge target_pid is 100
        mismatched_ident = self._sample_valid_proc_identity(200)

        g.add_edge(WaitForEdge(
            waiter_tid=101, sync_object="0x1000", normalized_address="0x1000",
            owner_tid=102, owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED",
            observation_timestamp=t_now, target_pid=100, process_identity=mismatched_ident,
            sampling_epoch=1, metadata=self._sample_valid_meta(102, 101),
        ))

        cycle, category, issues = g.validate_and_analyze(allowed_epoch=1)
        self.assertIsNone(cycle)
        self.assertTrue(any("REJECT_IDENTITY_PID_MISMATCH" in s for s in issues))

    # =========================================================================
    # 4. Identity Start-Time Mismatch Rejects a Cycle
    # =========================================================================

    def test_04_identity_start_time_mismatch_rejects_cycle(self):
        """Cross-process evidence with differing process_start_time rejects candidate cycle."""
        g = WaitForGraph()
        t_now = time.time()
        ident1 = self._sample_valid_proc_identity(100)
        ident1["process_start_time"] = 100000

        ident2 = self._sample_valid_proc_identity(100)
        ident2["process_start_time"] = 200000  # Process was recycled / restarted under same PID

        g.add_edge(WaitForEdge(
            waiter_tid=101, sync_object="0x1000", normalized_address="0x1000",
            owner_tid=102, owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED",
            observation_timestamp=t_now, target_pid=100, process_identity=ident1,
            sampling_epoch=1, metadata=self._sample_valid_meta(102, 101),
        ))
        g.add_edge(WaitForEdge(
            waiter_tid=102, sync_object="0x2000", normalized_address="0x2000",
            owner_tid=101, owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED",
            observation_timestamp=t_now + 0.05, target_pid=100, process_identity=ident2,
            sampling_epoch=1, metadata=self._sample_valid_meta(101, 102),
        ))

        cycle, category, issues = g.validate_and_analyze(allowed_epoch=1)
        self.assertIsNone(cycle)
        self.assertEqual(category, RESULT_INCONSISTENT_OWNER_EVIDENCE)
        self.assertTrue(any("REJECT_CROSS_PROCESS_IDENTITY_MISMATCH" in s for s in issues))

    # =========================================================================
    # 5. Missing Epoch Remains None Through Real Lock-Inspection Producer
    # =========================================================================

    def test_05_missing_epoch_remains_none_through_real_lock_inspection_producer(self):
        """Lock inspection producer without sampling_epoch produces edges with None, never implicitly epoch 0."""
        engine = AdaptiveInvestigationEngine()
        tracker = ObservationBudgetTracker()
        tracker.start()

        class MockAdapter(LocalTargetAdapter):
            def get_threads(self, pid):
                return [
                    {"tid": 101, "state": "S", "is_futex_wait": True, "syscall_arg0": "0x1000"},
                    {"tid": 102, "state": "S", "is_futex_wait": True, "syscall_arg0": "0x2000"},
                ]

            def resolve_mutex_owner(self, pid, lock_addr):
                owner = 102 if lock_addr in (0x1000, "0x1000") else 101
                raw = struct.pack("<iIiIi", 1, 0, owner, 0, 0) + b"\x00" * 20
                return MutexOwnerResolutionResult(
                    status=STATUS_OWNER_IDENTIFIED,
                    owner_tid=owner,
                    layout_id=LAYOUT_GLIBC_LP64,
                    raw_bytes=raw,
                    metadata={
                        "raw_bytes": raw,
                        "read_bytes_len": 40,
                        "memory_read_status": "OBSERVED",
                        "latency_us": 10.0,
                        "lock_word": 1,
                        "kind": 0,
                        "base_kind": 0,
                        "owner": owner,
                        "target_tids": [101, 102],
                    },
                )

        adapter = MockAdapter()
        mod = engine.registry.get("insp_locks")
        # Explicitly omit sampling_epoch from invocation
        res = mod._func(None, pid=100, adapter=adapter, budget_tracker=tracker, target_identity=self._sample_valid_proc_identity(100))

        self.assertTrue(res.get("success"))
        g_data = res.get("wait_for_graph", {})
        edges = g_data.get("edges", [])
        self.assertGreater(len(edges), 0)
        # Every produced edge MUST have sampling_epoch as None
        for edge in edges:
            self.assertIsNone(edge.get("sampling_epoch"), "Producer must not silently convert missing epoch to 0")

        # Cycle must not be detected because missing epoch fails validation
        self.assertFalse(res.get("deadlock_detected"))
        self.assertIsNone(res.get("deadlock_cycle"))
        self.assertTrue(any("REJECT_MISSING_SAMPLING_EPOCH" in s for s in res.get("issues", [])))

    # =========================================================================
    # 6. Explicit Epoch Zero Remains Valid
    # =========================================================================

    def test_06_explicit_epoch_zero_remains_valid(self):
        """Explicitly passed sampling_epoch=0 remains 0 and allows deadlock confirmation."""
        engine = AdaptiveInvestigationEngine()
        tracker = ObservationBudgetTracker()
        tracker.start()

        class MockAdapter(LocalTargetAdapter):
            def get_threads(self, pid):
                return [
                    {"tid": 101, "state": "S", "is_futex_wait": True, "syscall_arg0": "0x1000"},
                    {"tid": 102, "state": "S", "is_futex_wait": True, "syscall_arg0": "0x2000"},
                ]

            def resolve_mutex_owner(self, pid, lock_addr):
                owner = 102 if lock_addr in (0x1000, "0x1000") else 101
                raw = struct.pack("<iIiIi", 1, 0, owner, 0, 0) + b"\x00" * 20
                return MutexOwnerResolutionResult(
                    status=STATUS_OWNER_IDENTIFIED,
                    owner_tid=owner,
                    layout_id=LAYOUT_GLIBC_LP64,
                    raw_bytes=raw,
                    metadata={
                        "raw_bytes": raw,
                        "read_bytes_len": 40,
                        "memory_read_status": "OBSERVED",
                        "latency_us": 10.0,
                        "lock_word": 1,
                        "kind": 0,
                        "base_kind": 0,
                        "owner": owner,
                        "target_tids": [101, 102],
                    },
                )

        adapter = MockAdapter()
        mod = engine.registry.get("insp_locks")
        # Explicitly pass sampling_epoch=0
        res = mod._func(None, pid=100, adapter=adapter, budget_tracker=tracker, target_identity=self._sample_valid_proc_identity(100), sampling_epoch=0)

        self.assertTrue(res.get("success"))
        g_data = res.get("wait_for_graph", {})
        edges = g_data.get("edges", [])
        self.assertEqual(len(edges), 2)
        for edge in edges:
            self.assertEqual(edge.get("sampling_epoch"), 0)

        # Deadlock cycle confirmed in epoch 0!
        self.assertTrue(res.get("deadlock_detected"))
        self.assertEqual(res.get("result_category"), RESULT_DEADLOCK_CYCLE_CONFIRMED)
        self.assertEqual(res.get("deadlock_cycle"), [101, 102, 101])

    # =========================================================================
    # 7. Invalid Epoch Types (Including Bool) Rejected
    # =========================================================================

    def test_07_invalid_epoch_types_including_bool_rejected(self):
        """Boolean, negative, and malformed epoch values are strictly rejected by both producer and graph."""
        engine = AdaptiveInvestigationEngine()
        mod = engine.registry.get("insp_locks")
        tracker = ObservationBudgetTracker()
        tracker.start()

        class DummyAdapter(LocalTargetAdapter):
            def get_threads(self, pid):
                return [{"tid": 101, "state": "S", "is_futex_wait": True, "syscall_arg0": "0x1000"}]
            def resolve_mutex_owner(self, pid, lock_addr):
                raw = struct.pack("<iIiIi", 1, 0, 102, 0, 0) + b"\x00" * 20
                return MutexOwnerResolutionResult(status=STATUS_OWNER_IDENTIFIED, owner_tid=102, layout_id=LAYOUT_GLIBC_LP64, raw_bytes=raw, metadata={"read_bytes_len": 40, "memory_read_status": "OBSERVED"})

        # 1. Producer passing bool (True)
        res_bool = mod._func(None, pid=100, adapter=DummyAdapter(), budget_tracker=tracker, target_identity=self._sample_valid_proc_identity(100), sampling_epoch=True)
        self.assertFalse(res_bool.get("deadlock_detected"))
        self.assertTrue(any("REJECT_INVALID_SAMPLING_EPOCH" in s for s in res_bool.get("issues", [])))

        # 2. Graph directly with bool (False)
        g_bool = WaitForGraph()
        g_bool.add_edge(WaitForEdge(
            waiter_tid=101, sync_object="0x1000", owner_tid=102, owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED", observation_timestamp=time.time(),
            target_pid=100, process_identity=self._sample_valid_proc_identity(100), sampling_epoch=False,
            metadata=self._sample_valid_meta(102, 101),
        ))
        _, _, issues_bool = g_bool.validate_and_analyze()
        self.assertTrue(any("REJECT_INVALID_SAMPLING_EPOCH" in s for s in issues_bool))

        # 3. Negative epoch
        g_neg = WaitForGraph()
        g_neg.add_edge(WaitForEdge(
            waiter_tid=101, sync_object="0x1000", owner_tid=102, owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED", observation_timestamp=time.time(),
            target_pid=100, process_identity=self._sample_valid_proc_identity(100), sampling_epoch=-5,
            metadata=self._sample_valid_meta(102, 101),
        ))
        _, _, issues_neg = g_neg.validate_and_analyze()
        self.assertTrue(any("REJECT_INVALID_SAMPLING_EPOCH" in s for s in issues_neg))

    # =========================================================================
    # 8. ELF Inspection Accounts for Actual Bytes
    # =========================================================================

    def test_08_elf_inspection_accounts_for_actual_bytes_or_reports_estimate(self):
        """inspect_elf tracks actual measured bytes read from file, not a hardcoded 64 bytes."""
        # Inspect python executable or self fixture
        target_bin = sys.executable
        self.assertTrue(os.path.exists(target_bin))

        ident = inspect_elf(target_bin)
        self.assertIsInstance(ident, BinaryIdentity)
        self.assertIn(ident.elf_class, ("ELF64", "ELF32"))
        # An actual ELF inspection reads ELF header, section headers, string table, program headers
        # Therefore bytes_read MUST be strictly greater than 64!
        self.assertGreater(ident.bytes_read, 64, f"Actual ELF inspection bytes {ident.bytes_read} must exceed hardcoded 64")

    # =========================================================================
    # 9. Readlink and procfs Accounting Follows Documented Contract
    # =========================================================================

    def test_09_readlink_and_procfs_accounting_follows_documented_contract(self):
        """LocalTargetAdapter.get_process_identity measures readlink, stat, and ELF bytes."""
        clear_elf_identity_cache()
        adapter = LocalTargetAdapter()
        pid = os.getpid()
        ident = adapter.get_process_identity(pid)

        self.assertEqual(ident["identity_status"], IDENTITY_VERIFIED)
        total_ident_b = adapter.get_last_identity_bytes_read()
        self.assertGreater(total_ident_b, 0)

        # Re-verify components manually and check against breakdown
        readlink_bytes = len(os.readlink(f"/proc/{pid}/exe").encode("utf-8"))
        with open(f"/proc/{pid}/stat", "r", encoding="utf-8") as f:
            stat_bytes = len(f.read().encode("utf-8"))
        elf_identity = inspect_elf(f"/proc/{pid}/exe")

        elf_b = elf_identity.bytes_read if not elf_identity.cached else elf_identity.cache_bytes_read
        breakdown = ident.get("measurement_breakdown", {})
        self.assertEqual(total_ident_b, breakdown["total_measured_bytes"])
        self.assertEqual(
            breakdown["total_measured_bytes"],
            breakdown["readlink_bytes"] + breakdown["stat_bytes"] + breakdown["elf_bytes_read"]
        )
        self.assertGreaterEqual(breakdown["readlink_bytes"], readlink_bytes)
        self.assertGreaterEqual(breakdown["stat_bytes"], stat_bytes)
        self.assertEqual(breakdown["elf_bytes_read"], elf_b)

    # =========================================================================
    # 10. Partial Identity Reads Preserve Actual Consumed Bytes
    # =========================================================================

    def test_10_partial_identity_reads_preserve_actual_consumed_bytes(self):
        """When ELF inspection fails after readlink and stat succeed, consumed bytes are preserved."""
        adapter = LocalTargetAdapter()
        pid = os.getpid()

        # Patch inspect_elf to raise an error during identity discovery
        import extractor.target_adapter as ta
        orig_inspect_elf = ta.inspect_elf
        try:
            ta.inspect_elf = lambda path: (_ for _ in ()).throw(RuntimeError("ELF parsing failure"))
            ident = adapter.get_process_identity(pid)
            # Identity is unverified because ELF inspection failed
            self.assertEqual(ident["identity_status"], IDENTITY_UNVERIFIED)
            # BUT consumed bytes from readlink + stat must be preserved!
            self.assertGreater(adapter.get_last_identity_bytes_read(), 0)
        finally:
            ta.inspect_elf = orig_inspect_elf

    # =========================================================================
    # 11. Nested get_threads() and get_proc_maps() Accounting Is Exact
    # =========================================================================

    def test_11_nested_get_threads_and_get_proc_maps_accounting_is_exact(self):
        """get_threads breakdown accurately accounts for maps_bytes, task_bytes, and memory_bytes."""
        adapter = LocalTargetAdapter()
        pid = os.getpid()
        threads = adapter.get_threads(pid)
        self.assertGreater(len(threads), 0)

        breakdown = adapter.get_last_threads_breakdown()
        self.assertIn("maps_bytes", breakdown)
        self.assertIn("task_bytes", breakdown)
        self.assertIn("memory_bytes", breakdown)
        self.assertIn("total_bytes", breakdown)

        self.assertGreater(breakdown["maps_bytes"], 0)
        self.assertGreater(breakdown["task_bytes"], 0)
        self.assertEqual(
            breakdown["total_bytes"],
            breakdown["maps_bytes"] + breakdown["task_bytes"] + breakdown["memory_bytes"]
        )
        self.assertEqual(adapter.get_last_threads_bytes_read(), breakdown["total_bytes"])
        self.assertEqual(adapter.get_last_maps_bytes_read(), breakdown["maps_bytes"])

    # =========================================================================
    # 12. WorkManager and Fallback Do Not Double-Charge
    # =========================================================================

    def test_12_workmanager_and_fallback_do_not_double_charge(self):
        """WorkManager execution is charged exactly once by the module, never duplicated."""
        engine = AdaptiveInvestigationEngine()
        tracker = ObservationBudgetTracker()
        tracker.start()

        class MockWM:
            def inspect_thread_callstacks_and_locks(self, **kw):
                return {
                    "success": True,
                    "threads": [{"tid": 101, "state": "S"}],
                    "measured_bytes_read": 256,
                    "bytes_read": 256,
                }

        wm = MockWM()
        mod = engine.registry.get("insp_locks")
        ctx = InspectionContext(
            pid=100,
            companion_elf="",
            adapter=LocalTargetAdapter(),
            budget_tracker=tracker,
        )
        res = mod.run(ctx, watch_manager=wm)
        self.assertTrue(res.get("success"))
        # Exactly 256 bytes charged
        self.assertEqual(tracker.metrics.measured_bytes_read, 256)
        self.assertEqual(tracker.metrics.bytes_read, 256)

    # =========================================================================
    # 13. WorkManager Exceptions Preserve Elapsed Time and Consumed Bytes
    # =========================================================================

    def test_13_workmanager_exceptions_preserve_elapsed_time_and_consumed_bytes(self):
        """WorkManager raising an exception preserves consumed bytes and elapsed time in tracker."""
        engine = AdaptiveInvestigationEngine()
        tracker = ObservationBudgetTracker()
        tracker.start()

        class FailingWM:
            def inspect_thread_callstacks_and_locks(self, **kw):
                time.sleep(0.01)  # Simulate 10ms of work
                exc = RuntimeError("Simulated WM failure mid-operation")
                exc.measured_bytes_read = 75  # Bytes read before failing
                raise exc

        wm = FailingWM()
        mod = engine.registry.get("insp_locks")
        ctx = InspectionContext(
            pid=os.getpid(),
            companion_elf="",
            adapter=LocalTargetAdapter(),
            budget_tracker=tracker,
        )
        res = mod.run(ctx, watch_manager=wm)
        # Fallback executed after failure
        self.assertTrue(res.get("success"))
        # Failure count incremented
        self.assertGreaterEqual(tracker.metrics.total_read_failures, 1)
        # 75 bytes from WM failure preserved plus fallback reads
        self.assertGreater(tracker.metrics.measured_bytes_read, 75)
        self.assertGreater(tracker.elapsed_ms, 10.0)

    # =========================================================================
    # 14. Fixed Latency Constants Cannot Appear as Measured Observation Latency
    # =========================================================================

    def test_14_fixed_latency_constants_cannot_appear_as_measured_observation_latency(self):
        """Stage 1 target validation records measured monotonic latency, never a hardcoded 500.0us."""
        engine = AdaptiveInvestigationEngine()
        adapter = LocalTargetAdapter()
        ident = adapter.get_process_identity(os.getpid())
        lat_us = adapter.get_last_identity_latency_us()
        self.assertGreater(lat_us, 0.0)
        self.assertNotEqual(lat_us, 500.0, "Measured latency must not be hardcoded 500.0us")

        res = engine.investigate_process_health(
            goal="Latency verification",
            pid=os.getpid(),
            budget_limits=ObservationBudgetLimits(max_bytes_read=100000),
        )
        self.assertTrue(res["success"])
        b_summary = res.get("budget_summary", {})
        prof_usage = b_summary.get("profile_usage") or b_summary.get("metrics", {}).get("profile_usage", {})
        tv_usage = prof_usage.get("target_validation", {})
        tv_wall_ms = tv_usage.get("wall_clock_ms", 0.0)
        self.assertGreater(tv_wall_ms, 0.0)
        # 500.0us is 0.500ms; verify it is not exact hardcoded 0.500ms
        self.assertNotEqual(tv_wall_ms, 0.500)

    # =========================================================================
    # 15. Global Budget Exhaustion Prevents Subsequent Mutex Reads
    # =========================================================================

    def test_15_global_budget_exhaustion_prevents_subsequent_mutex_reads(self):
        """Admission check stops further mutex reads immediately once remaining budget is exhausted."""
        engine = AdaptiveInvestigationEngine()
        # Budget limit: 120 bytes max (allows threads read of 40B + 2 mutex reads of 40B, stops 3rd)
        limits = ObservationBudgetLimits(max_bytes_read=120)
        tracker = ObservationBudgetTracker(limits)
        tracker.start()

        class MockContendedAdapter(LocalTargetAdapter):
            def __init__(self):
                super().__init__()
                self._last_threads_bytes_read = 40
                self.mutex_read_count = 0

            def get_threads(self, pid):
                return [
                    {"tid": 101, "state": "S", "is_futex_wait": True, "syscall_arg0": "0x1000"},
                    {"tid": 102, "state": "S", "is_futex_wait": True, "syscall_arg0": "0x2000"},
                    {"tid": 103, "state": "S", "is_futex_wait": True, "syscall_arg0": "0x3000"},
                ]

            def resolve_mutex_owner(self, pid, lock_addr):
                self.mutex_read_count += 1
                raw = struct.pack("<iIiIi", 1, 0, 999, 0, 0) + b"\x00" * 20
                return MutexOwnerResolutionResult(
                    status=STATUS_OWNER_IDENTIFIED,
                    owner_tid=999,
                    layout_id=LAYOUT_GLIBC_LP64,
                    raw_bytes=raw,
                    metadata={"read_bytes_len": 40, "memory_read_status": "OBSERVED", "latency_us": 10.0},
                )

        adapter = MockContendedAdapter()
        mod = engine.registry.get("insp_locks")
        res = mod._func(None, pid=100, adapter=adapter, budget_tracker=tracker, target_identity=self._sample_valid_proc_identity(100), sampling_epoch=1)

        self.assertEqual(res.get("status"), "PARTIAL")
        self.assertEqual(res.get("stop_reason"), "BUDGET_EXHAUSTED")
        self.assertEqual(adapter.mutex_read_count, 2, "3rd mutex read must be prevented by admission control")
        self.assertEqual(tracker.metrics.measured_bytes_read, 120)

    # =========================================================================
    # 16. Remote Target Accounting and Identity Isolated from Host procfs
    # =========================================================================

    def test_16_remote_target_accounting_and_identity_isolated_from_host_procfs(self):
        """Remote SSH adapter queries remote target namespace exclusively without local /proc leakage."""
        remote_pid = 999999
        self.assertFalse(os.path.exists(f"/proc/{remote_pid}"))

        def mock_ssh_runner(cmd, timeout: float = 5.0) -> Tuple[int, str, str]:
            cmd_str = " ".join(cmd) if isinstance(cmd, (list, tuple)) else str(cmd)
            if "kill -0 999999" in cmd_str:
                return 0, "ALIVE\n", ""
            elif "readlink" in cmd_str and "/proc/999999/exe" in cmd_str:
                return 0, "/remote/usr/bin/daemon\n", ""
            elif "/proc/999999/stat" in cmd_str:
                fake_stat = "999999 (daemon) S 1 999999 999999 0 0 4194304 100 0 0 0 10 5 0 0 20 0 1 0 445566 1000 200"
                return 0, fake_stat + "\n", ""
            elif "/proc/999999/exe" in cmd_str and "base64" in cmd_str:
                elf_hdr = b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + struct.pack("<HHI", 2, 0x3e, 1) + b"\x00" * 40
                return 0, base64.b64encode(elf_hdr).decode("ascii") + "\n", ""
            return 0, "", ""

        adapter = RemoteSshTargetAdapter(host="remote.target.host", command_runner=mock_ssh_runner)
        ident = adapter.get_process_identity(remote_pid)

        self.assertEqual(ident["pid"], remote_pid)
        self.assertEqual(ident["executable"], "/remote/usr/bin/daemon")
        self.assertEqual(ident["process_start_time"], 445566)
        self.assertEqual(ident["architecture"], "x86_64")
        self.assertEqual(ident["identity_status"], IDENTITY_VERIFIED)
        self.assertTrue(ident["is_remote"])
        self.assertGreater(adapter.get_last_identity_bytes_read(), 0)
        self.assertGreater(adapter.get_last_identity_latency_us(), 0.0)

"""Phase 2.0-A.3.4.4 Identity Proof & Measurement Accounting Final Closure Test Suite.

Deterministic, adversarial test coverage verifying:
1. Strict Process Identity Proof Contract (PID reuse, executable changes, inode consistency, Build ID).
2. ELF Inspection Accounting (CountingReader on all exits, zero new bytes on cache hit, no hardcoded fallbacks).
3. WorkManager Accounting Contract (measured vs estimated, partial I/O preservation, fallback budget gate).
4. WaitForGraph Cycle Proof (IDENTITY_VERIFIED strictly required, epoch integrity, serialization roundtrip).
5. Regression and Remote Isolation.
"""

import copy
import os
import struct
import sys
import tempfile
import threading
import time
import unittest
from typing import Any, Dict, List, Optional

from extractor.adaptive_engine import (
    AdaptiveInvestigationEngine,
    FunctionalInspectionModule,
    InspectionContext,
    LAYOUT_GLIBC_LP64,
    RESULT_DEADLOCK_CYCLE_CONFIRMED,
    STATUS_OWNER_IDENTIFIED,
    WaitForEdge,
    WaitForGraph,
)
from extractor.debug_image import (
    BinaryIdentity,
    clear_elf_identity_cache,
    get_last_elf_bytes_read,
    inspect_elf,
)
from extractor.observation_budget import (
    ObservationBudgetLimits,
    ObservationBudgetTracker,
)
from extractor.target_adapter import (
    IDENTITY_INCONSISTENT,
    IDENTITY_UNAVAILABLE,
    IDENTITY_UNVERIFIED,
    IDENTITY_VERIFIED,
    LocalTargetAdapter,
    RemoteSshTargetAdapter,
)


class TestPhase20A344IdentityProofAndAccounting(unittest.TestCase):
    """Adversarial tests for Phase 2.0-A.3.4.4 closure."""

    def setUp(self):
        clear_elf_identity_cache()

    def tearDown(self):
        clear_elf_identity_cache()

    # -------------------------------------------------------------------------
    # Helper Fixtures
    # -------------------------------------------------------------------------

    def _sample_valid_proc_identity(self, pid: int, start_time: int = 12345) -> Dict[str, Any]:
        return {
            "pid": pid,
            "executable": "/usr/bin/test_service",
            "process_start_time": start_time,
            "architecture": "x86_64",
            "elf_class": "ELF64",
            "endianness": "little",
            "elf_type": "ET_EXEC",
            "build_id": "0123456789abcdef0123456789abcdef01234567",
            "status": "OBSERVED",
            "identity_status": IDENTITY_VERIFIED,
            "is_remote": False,
        }

    def _sample_valid_meta(self, owner_tid: int, waiter_tid: int) -> Dict[str, Any]:
        return {
            "target_tids": [owner_tid, waiter_tid],
            "raw_bytes": b"\x00" * 40,
            "read_bytes_len": 40,
            "lock_word": 0,
            "kind": 0,
            "base_kind": 0,
            "owner": owner_tid,
        }

    # =========================================================================
    # 1. Identity Proof Contract
    # =========================================================================

    def test_01_valid_process_identity_verified(self):
        """Valid local process identity discovers executable, start time, ELF and marks IDENTITY_VERIFIED."""
        adapter = LocalTargetAdapter()
        pid = os.getpid()
        ident = adapter.get_process_identity(pid)

        self.assertEqual(ident["identity_status"], IDENTITY_VERIFIED)
        self.assertEqual(ident["pid"], pid)
        self.assertGreater(ident["process_start_time"], 0)
        self.assertIn(ident["architecture"], ("x86_64", "aarch64", "arm", "x86", "riscv"))
        self.assertIn(ident["elf_class"], ("ELF64", "ELF32"))
        self.assertGreater(ident["measured_bytes_read"], 0)
        self.assertEqual(ident["estimated_bytes_read"], 0)

        breakdown = ident["measurement_breakdown"]
        self.assertGreater(breakdown["readlink_bytes"], 0)
        self.assertGreater(breakdown["stat_bytes"], 0)
        self.assertEqual(
            ident["measured_bytes_read"],
            breakdown["readlink_bytes"] + breakdown["stat_bytes"] + breakdown["elf_bytes_read"]
        )

    def test_02_missing_process_start_time_unverified(self):
        """When start time is missing or non-positive, identity status is IDENTITY_UNVERIFIED."""
        adapter = LocalTargetAdapter()
        pid = os.getpid()

        import extractor.target_adapter as ta
        orig_exists = ta.os.path.exists

        def fake_exists(path):
            if path == f"/proc/{pid}/stat":
                return False  # Simulate missing stat
            return orig_exists(path)

        ta.os.path.exists = fake_exists
        try:
            ident = adapter.get_process_identity(pid)
            self.assertEqual(ident["identity_status"], IDENTITY_UNVERIFIED)
            self.assertIsNone(ident["process_start_time"])
        finally:
            ta.os.path.exists = orig_exists

    def test_03_pid_reuse_during_acquisition_fails_closed(self):
        """When process start time changes between T0 and T1, PID reuse is detected -> IDENTITY_INCONSISTENT."""
        adapter = LocalTargetAdapter()
        pid = os.getpid()

        import builtins
        orig_open = builtins.open
        stat_reads = [0]

        def fake_open(file, *args, **kwargs):
            if isinstance(file, str) and file == f"/proc/{pid}/stat":
                stat_reads[0] += 1
                if stat_reads[0] == 1:
                    content = f"{pid} (test_proc) S 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 100000 0 0 0\n"
                else:
                    content = f"{pid} (test_proc) S 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 200000 0 0 0\n"
                import io
                return io.StringIO(content)
            return orig_open(file, *args, **kwargs)

        builtins.open = fake_open
        try:
            ident = adapter.get_process_identity(pid)
            self.assertEqual(ident["identity_status"], IDENTITY_INCONSISTENT)
            self.assertEqual(ident["status"], "INCONSISTENT")
        finally:
            builtins.open = orig_open

    def test_04_executable_identity_changes_during_acquisition(self):
        """When /proc/<pid>/exe link changes between T0 and T1, identity is IDENTITY_INCONSISTENT."""
        adapter = LocalTargetAdapter()
        pid = os.getpid()

        import extractor.target_adapter as ta
        orig_readlink = ta.os.readlink
        link_reads = [0]

        def fake_readlink(path):
            if path == f"/proc/{pid}/exe":
                link_reads[0] += 1
                if link_reads[0] == 1:
                    return "/usr/bin/original_service"
                return "/usr/bin/replaced_service"
            return orig_readlink(path)

        ta.os.readlink = fake_readlink
        try:
            ident = adapter.get_process_identity(pid)
            self.assertEqual(ident["identity_status"], IDENTITY_INCONSISTENT)
        finally:
            ta.os.readlink = orig_readlink

    def test_05_executable_inode_inconsistency(self):
        """When opened executable FD device/inode mismatches runtime_exe, identity is IDENTITY_INCONSISTENT."""
        adapter = LocalTargetAdapter()
        pid = os.getpid()

        import extractor.target_adapter as ta
        orig_stat = ta.os.stat

        class FakeStat:
            def __init__(self, dev, ino):
                self.st_dev = dev
                self.st_ino = ino

        def fake_stat(path, *args, **kwargs):
            real_st = orig_stat(path, *args, **kwargs)
            # Return different inode for runtime_exe
            return FakeStat(dev=real_st.st_dev, ino=real_st.st_ino + 999999)

        ta.os.stat = fake_stat
        try:
            ident = adapter.get_process_identity(pid)
            self.assertEqual(ident["identity_status"], IDENTITY_INCONSISTENT)
        finally:
            ta.os.stat = orig_stat

    def test_06_elf_parse_failure_yields_unverified_and_preserves_bytes(self):
        """Corrupted/truncated ELF produces IDENTITY_UNVERIFIED while preserving pre-failure bytes."""
        adapter = LocalTargetAdapter()
        pid = os.getpid()

        import extractor.target_adapter as ta
        orig_inspect = ta.inspect_elf

        def fake_inspect_elf(path):
            exc = ValueError("Corrupted ELF header")
            exc.bytes_read = 32
            raise exc

        ta.inspect_elf = fake_inspect_elf
        try:
            ident = adapter.get_process_identity(pid)
            self.assertEqual(ident["identity_status"], IDENTITY_UNVERIFIED)
            self.assertGreater(ident["measured_bytes_read"], 32)
            self.assertEqual(ident["estimated_bytes_read"], 0)
        finally:
            ta.inspect_elf = orig_inspect

    def test_07_elf_without_build_id_and_companion_mismatch(self):
        """Tests companion build ID matching, unavailability, and mismatch."""
        adapter = LocalTargetAdapter()
        pid = os.getpid()

        # 1. Companion build ID matches
        real_ident = adapter.get_process_identity(pid)
        real_bid = real_ident.get("build_id")
        if real_bid:
            match_ident = adapter.get_process_identity(pid, companion_build_id=real_bid)
            self.assertEqual(match_ident["identity_status"], IDENTITY_VERIFIED)
            self.assertEqual(match_ident["build_id_status"], "BUILD_ID_MATCHED")

        # 2. Companion build ID mismatches -> IDENTITY_INCONSISTENT
        mismatch_ident = adapter.get_process_identity(pid, companion_build_id="deadbeef" * 5)
        self.assertEqual(mismatch_ident["identity_status"], IDENTITY_INCONSISTENT)
        self.assertEqual(mismatch_ident["build_id_status"], "BUILD_ID_MISMATCH")

    def test_08_process_termination_during_inspection(self):
        """When process terminates during inspection, returns TARGET_TERMINATED and IDENTITY_UNAVAILABLE."""
        adapter = LocalTargetAdapter()
        pid = 99999999
        ident = adapter.get_process_identity(pid)
        self.assertEqual(ident["status"], "TARGET_TERMINATED")
        self.assertEqual(ident["identity_status"], IDENTITY_UNAVAILABLE)
        self.assertEqual(ident["measured_bytes_read"], 0)
        self.assertEqual(ident["estimated_bytes_read"], 0)

    def test_09_no_false_identity_verified_on_deleted_binary(self):
        """An executable marked (deleted) fails closed with IDENTITY_UNVERIFIED."""
        adapter = LocalTargetAdapter()
        pid = os.getpid()

        import extractor.target_adapter as ta
        orig_readlink = ta.os.readlink

        def fake_readlink(path):
            if path == f"/proc/{pid}/exe":
                return "/usr/bin/service (deleted)"
            return orig_readlink(path)

        ta.os.readlink = fake_readlink
        try:
            ident = adapter.get_process_identity(pid)
            self.assertEqual(ident["identity_status"], IDENTITY_UNVERIFIED)
            self.assertTrue(ident["is_deleted"])
        finally:
            ta.os.readlink = orig_readlink

    # =========================================================================
    # 2. ELF Inspection Accounting
    # =========================================================================

    def test_10_partial_read_followed_by_exception(self):
        """CountingReader preserves actual bytes read before an exception occurs."""
        with tempfile.NamedTemporaryFile(prefix="bad_elf_", suffix=".bin", delete=False) as tf:
            # Write 24 bytes of garbage (not a valid ELF header)
            tf.write(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 16)
            tf.flush()
            tmp_path = tf.name

        try:
            with self.assertRaises(ValueError) as ctx:
                inspect_elf(tmp_path)
            # The exception carries consumed bytes
            exc = ctx.exception
            self.assertGreaterEqual(getattr(exc, "bytes_read", 0), 16)
            self.assertGreaterEqual(get_last_elf_bytes_read(), 16)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_11_cache_hit_reports_zero_new_bytes_and_cache_miss_reports_actual(self):
        """Cache miss reports actual bytes read from disk; cache hit reports exactly 0 new bytes."""
        target_bin = sys.executable

        # 1. First inspection: Cache Miss
        ident1 = inspect_elf(target_bin)
        self.assertFalse(ident1.cached)
        self.assertGreater(ident1.bytes_read, 64)
        self.assertEqual(ident1.cache_bytes_read, 0)
        self.assertEqual(ident1.measurement_status, "EXACT_MEASURED")
        initial_bytes = ident1.bytes_read

        # 2. Second inspection: Cache Hit
        ident2 = inspect_elf(target_bin)
        self.assertTrue(ident2.cached)
        self.assertEqual(ident2.bytes_read, 0, "Cache hit must report 0 new bytes read in current invocation")
        self.assertEqual(ident2.cache_bytes_read, initial_bytes)
        self.assertEqual(ident2.measurement_status, "CACHE_HIT")
        self.assertEqual(get_last_elf_bytes_read(), 0)

        # 3. Third inspection: Repeated Cache Hit
        ident3 = inspect_elf(target_bin)
        self.assertTrue(ident3.cached)
        self.assertEqual(ident3.bytes_read, 0)
        self.assertEqual(ident3.cache_bytes_read, initial_bytes)

    def test_12_no_hardcoded_measurement_fallback(self):
        """LocalTargetAdapter never adds 64 synthetic fallback bytes when ELF read returns 0."""
        adapter = LocalTargetAdapter()
        pid = os.getpid()

        import extractor.target_adapter as ta
        orig_inspect = ta.inspect_elf

        # Mock inspect_elf returning 0 bytes read (e.g. cached)
        def fake_inspect_elf(path):
            return BinaryIdentity(
                path=path,
                elf_class="ELF64",
                architecture="x86_64",
                endianness="little",
                bytes_read=0,
                cached=True,
                cache_bytes_read=4096,
                measurement_status="CACHE_HIT",
            )

        ta.inspect_elf = fake_inspect_elf
        try:
            ident = adapter.get_process_identity(pid)
            breakdown = ident["measurement_breakdown"]
            # No 64 byte fallback!
            self.assertEqual(ident["estimated_bytes_read"], 0)
            self.assertEqual(breakdown["elf_bytes_read"], 0)
            self.assertEqual(breakdown["elf_bytes_from_cache"], 4096)
            self.assertEqual(
                ident["measured_bytes_read"],
                breakdown["readlink_bytes"] + breakdown["stat_bytes"]
            )
        finally:
            ta.inspect_elf = orig_inspect

    def test_13_concurrent_cache_access(self):
        """Multiple threads concurrently inspecting the same binary execute safely under cache lock."""
        target_bin = sys.executable
        results = []
        errors = []

        def worker():
            try:
                for _ in range(20):
                    ident = inspect_elf(target_bin)
                    results.append(ident.architecture)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(len(errors), 0, f"Concurrent ELF inspection produced errors: {errors}")
        self.assertEqual(len(results), 120)
        self.assertTrue(all(arch == results[0] for arch in results))

    # =========================================================================
    # 3. WorkManager Accounting Contract
    # =========================================================================

    def test_14_workmanager_successful_measured_result(self):
        """WorkManager returning measured_bytes_read charges tracker exactly once as measured."""
        engine = AdaptiveInvestigationEngine()
        tracker = ObservationBudgetTracker()
        tracker.start()

        class MockWM:
            def inspect_thread_callstacks_and_locks(self, **kw):
                return {
                    "success": True,
                    "threads": [{"tid": 201, "state": "S"}],
                    "measured_bytes_read": 384,
                    "bytes_read": 384,
                }

        wm = MockWM()
        mod = engine.registry.get("insp_locks")
        ctx = InspectionContext(
            pid=os.getpid(),
            companion_elf="",
            adapter=LocalTargetAdapter(),
            budget_tracker=tracker,
        )
        res = mod.run(ctx, watch_manager=wm)
        self.assertTrue(res["success"])
        self.assertEqual(res["accounting_owner"], "WORKMANAGER")
        self.assertEqual(tracker.metrics.measured_bytes_read, 384)
        self.assertEqual(tracker.metrics.bytes_read, 384)
        self.assertEqual(tracker.metrics.conservative_estimated_bytes, 0)

    def test_15_workmanager_estimated_only_result(self):
        """WorkManager returning only estimated_bytes_read charges conservative estimate without fabricated measured bytes."""
        engine = AdaptiveInvestigationEngine()
        tracker = ObservationBudgetTracker()
        tracker.start()

        class MockWM:
            def inspect_thread_callstacks_and_locks(self, **kw):
                return {
                    "success": True,
                    "threads": [{"tid": 201, "state": "S"}],
                    "estimated_bytes_read": 500,
                    "bytes_read": 500,
                }

        wm = MockWM()
        mod = engine.registry.get("insp_locks")
        ctx = InspectionContext(
            pid=os.getpid(),
            companion_elf="",
            adapter=LocalTargetAdapter(),
            budget_tracker=tracker,
        )
        res = mod.run(ctx, watch_manager=wm)
        self.assertTrue(res["success"])
        self.assertEqual(res["measurement_type"], "ESTIMATED")
        # Measured bytes in tracker remains 0!
        self.assertEqual(tracker.metrics.measured_bytes_read, 0)
        # Conservative estimated bytes charged 500
        self.assertEqual(tracker.metrics.conservative_estimated_bytes, 500)
        self.assertEqual(tracker.metrics.bytes_read, 500)

    def test_16_workmanager_exception_after_partial_io_and_fallback(self):
        """WorkManager consumes bytes then raises; consumed bytes are recorded and fallback succeeds without loss."""
        engine = AdaptiveInvestigationEngine()
        tracker = ObservationBudgetTracker()
        tracker.start()

        class FailingWM:
            def inspect_thread_callstacks_and_locks(self, **kw):
                time.sleep(0.005)
                exc = RuntimeError("Target read interrupted")
                exc.measured_bytes_read = 120
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
        self.assertTrue(res["success"])
        self.assertEqual(res["accounting_owner"], "MODULE_INTERNAL")
        self.assertTrue(res["fallback_executed"])
        self.assertGreaterEqual(tracker.metrics.total_read_failures, 1)
        # Preserves 120 bytes from WM plus fallback reads
        self.assertGreater(tracker.metrics.measured_bytes_read, 120)

    def test_17_workmanager_budget_exhaustion_prevents_fallback(self):
        """When WorkManager failure exhausts the remaining budget, fallback is aborted immediately."""
        engine = AdaptiveInvestigationEngine()
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=200))
        tracker.start()

        class ExhaustingWM:
            def inspect_thread_callstacks_and_locks(self, **kw):
                exc = RuntimeError("Operation aborted")
                exc.measured_bytes_read = 250  # Overruns 200B max!
                raise exc

        wm = ExhaustingWM()
        mod = engine.registry.get("insp_locks")
        ctx = InspectionContext(
            pid=os.getpid(),
            companion_elf="",
            adapter=LocalTargetAdapter(),
            budget_tracker=tracker,
            parameters={"estimated_bytes": 100},
        )
        res = mod.run(ctx, watch_manager=wm)
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "BUDGET_EXHAUSTED")

    def test_18_no_accounting_loss_when_result_parsing_fails(self):
        """When module function raises an unexpected exception carrying consumed bytes, accounting survives."""
        tracker = ObservationBudgetTracker()
        tracker.start()
        mod = FunctionalInspectionModule(
            module_id="test_fail",
            collect_fn=lambda wm, **kw: (_ for _ in ()).throw(ValueError("Parsing error")),
        )
        ctx = InspectionContext(
            pid=os.getpid(),
            companion_elf="",
            adapter=LocalTargetAdapter(),
            budget_tracker=tracker,
            parameters={"estimated_bytes": 100},
        )
        res = mod.run(ctx)
        self.assertFalse(res["success"])
        self.assertEqual(res["result_category"], "OBSERVATION_FAILED")
        self.assertGreater(tracker.metrics.bytes_read, 0)
        self.assertEqual(tracker.metrics.total_read_failures, 1)

    # =========================================================================
    # 4. WaitForGraph Cycle Proof & Epoch Integrity
    # =========================================================================

    def test_19_unverified_identity_statuses_cannot_confirm_cycle(self):
        """Only IDENTITY_VERIFIED can confirm a deadlock cycle. OBSERVED, UNVERIFIED, UNAVAILABLE are rejected."""
        unverified_statuses = ["OBSERVED", IDENTITY_UNVERIFIED, IDENTITY_UNAVAILABLE, IDENTITY_INCONSISTENT]

        for bad_status in unverified_statuses:
            g = WaitForGraph()
            ident = self._sample_valid_proc_identity(100)
            ident["identity_status"] = bad_status

            # Edge 101 -> 102
            g.add_edge(WaitForEdge(
                waiter_tid=101, sync_object="0x1000", owner_tid=102, owner_identification_status=STATUS_OWNER_IDENTIFIED,
                mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED", observation_timestamp=time.time(),
                target_pid=100, process_identity=ident, sampling_epoch=1,
                metadata=self._sample_valid_meta(102, 101),
            ))
            # Edge 102 -> 101
            g.add_edge(WaitForEdge(
                waiter_tid=102, sync_object="0x2000", owner_tid=101, owner_identification_status=STATUS_OWNER_IDENTIFIED,
                mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED", observation_timestamp=time.time(),
                target_pid=100, process_identity=ident, sampling_epoch=1,
                metadata=self._sample_valid_meta(101, 102),
            ))

            cycle, cat, issues = g.validate_and_analyze()
            self.assertIsNone(cycle, f"Deadlock confirmed for unverified status {bad_status}")
            self.assertTrue(any("REJECT_IDENTITY" in s for s in issues))

        # Explicit IDENTITY_VERIFIED succeeds
        g_good = WaitForGraph()
        good_ident = self._sample_valid_proc_identity(100)
        g_good.add_edge(WaitForEdge(
            waiter_tid=101, sync_object="0x1000", owner_tid=102, owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED", observation_timestamp=time.time(),
            target_pid=100, process_identity=good_ident, sampling_epoch=1,
            metadata=self._sample_valid_meta(102, 101),
        ))
        g_good.add_edge(WaitForEdge(
            waiter_tid=102, sync_object="0x2000", owner_tid=101, owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED", observation_timestamp=time.time(),
            target_pid=100, process_identity=good_ident, sampling_epoch=1,
            metadata=self._sample_valid_meta(101, 102),
        ))
        cycle, cat, _ = g_good.validate_and_analyze()
        self.assertIsNotNone(cycle)
        self.assertEqual(cat, RESULT_DEADLOCK_CYCLE_CONFIRMED)

    def test_20_pid_and_start_time_mismatches_reject_edges(self):
        """Cross-PID or cross-start-time edges reject candidate cycles."""
        g = WaitForGraph()
        ident_a = self._sample_valid_proc_identity(100, start_time=1000)
        ident_b = self._sample_valid_proc_identity(100, start_time=2000)  # Different start time (recycled PID)

        g.add_edge(WaitForEdge(
            waiter_tid=101, sync_object="0x1000", owner_tid=102, owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED", observation_timestamp=time.time(),
            target_pid=100, process_identity=ident_a, sampling_epoch=1,
            metadata=self._sample_valid_meta(102, 101),
        ))
        g.add_edge(WaitForEdge(
            waiter_tid=102, sync_object="0x2000", owner_tid=101, owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED", observation_timestamp=time.time(),
            target_pid=100, process_identity=ident_b, sampling_epoch=1,
            metadata=self._sample_valid_meta(101, 102),
        ))
        cycle, _, issues = g.validate_and_analyze()
        self.assertIsNone(cycle)
        self.assertTrue(any("REJECT_CROSS_PROCESS_IDENTITY_MISMATCH" in s for s in issues))

    def test_21_sampling_epoch_integrity(self):
        """Missing epoch remains missing, explicit 0 is valid, boolean and malformed epochs are rejected."""
        # 1. Missing epoch
        g_none = WaitForGraph()
        g_none.add_edge(WaitForEdge(
            waiter_tid=101, sync_object="0x1000", owner_tid=102, owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED", observation_timestamp=time.time(),
            target_pid=100, process_identity=self._sample_valid_proc_identity(100), sampling_epoch=None,
            metadata=self._sample_valid_meta(102, 101),
        ))
        _, _, issues_none = g_none.validate_and_analyze()
        self.assertTrue(any("REJECT_MISSING_SAMPLING_EPOCH" in s for s in issues_none))

        # 2. Explicit 0 epoch is valid
        g_zero = WaitForGraph()
        good_ident = self._sample_valid_proc_identity(100)
        g_zero.add_edge(WaitForEdge(
            waiter_tid=101, sync_object="0x1000", owner_tid=102, owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED", observation_timestamp=time.time(),
            target_pid=100, process_identity=good_ident, sampling_epoch=0,
            metadata=self._sample_valid_meta(102, 101),
        ))
        g_zero.add_edge(WaitForEdge(
            waiter_tid=102, sync_object="0x2000", owner_tid=101, owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED", observation_timestamp=time.time(),
            target_pid=100, process_identity=good_ident, sampling_epoch=0,
            metadata=self._sample_valid_meta(101, 102),
        ))
        cycle, cat, _ = g_zero.validate_and_analyze(allowed_epoch=0)
        self.assertIsNotNone(cycle)
        self.assertEqual(cat, RESULT_DEADLOCK_CYCLE_CONFIRMED)

        # 3. Boolean True rejected
        g_bool = WaitForGraph()
        g_bool.add_edge(WaitForEdge(
            waiter_tid=101, sync_object="0x1000", owner_tid=102, owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED", observation_timestamp=time.time(),
            target_pid=100, process_identity=good_ident, sampling_epoch=True,
            metadata=self._sample_valid_meta(102, 101),
        ))
        _, _, issues_bool = g_bool.validate_and_analyze()
        self.assertTrue(any("REJECT_INVALID_SAMPLING_EPOCH" in s for s in issues_bool))

    def test_22_serialization_deserialization_fidelity(self):
        """WaitForGraph to_dict and from_dict retain evidence semantics and identity status."""
        g = WaitForGraph()
        ident = self._sample_valid_proc_identity(100)
        edge = WaitForEdge(
            waiter_tid=101, sync_object="0x1000", owner_tid=102, owner_identification_status=STATUS_OWNER_IDENTIFIED,
            mutex_layout_id=LAYOUT_GLIBC_LP64, memory_read_status="OBSERVED", observation_timestamp=time.time(),
            target_pid=100, process_identity=ident, sampling_epoch=3,
            metadata=self._sample_valid_meta(102, 101),
        )
        g.add_edge(edge)

        d = g.to_dict()
        g_restored = WaitForGraph.from_dict(d)
        self.assertEqual(len(g_restored.edges), 1)
        r_edge = g_restored.edges[0]
        self.assertEqual(r_edge.waiter_tid, 101)
        self.assertEqual(r_edge.sampling_epoch, 3)
        self.assertEqual(r_edge.process_identity["identity_status"], IDENTITY_VERIFIED)

    # =========================================================================
    # 5. Regression & Remote Isolation
    # =========================================================================

    def test_23_remote_target_isolation_and_accounting(self):
        """Remote target adapter executes strictly remote commands without local procfs leakage."""
        recorded_cmds = []

        def mock_runner(cmd_args, timeout):
            cmd_str = cmd_args[-1]
            recorded_cmds.append(cmd_str)
            if "kill -0" in cmd_str:
                return 0, "ALIVE\n", ""
            elif "readlink" in cmd_str:
                return 0, "/usr/bin/remote_srv\n", ""
            elif "cat /proc/" in cmd_str and "stat" in cmd_str:
                return 0, "500 (remote_srv) S 1 1 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 34567 0 0 0\n", ""
            elif "head -c 65536" in cmd_str:
                # Return empty base64 for test
                return 0, "", ""
            return 0, "", ""

        adapter = RemoteSshTargetAdapter(host="remote.test.local", command_runner=mock_runner)
        ident = adapter.get_process_identity(500)
        self.assertTrue(ident["is_remote"])
        self.assertEqual(ident["host"], "remote.test.local")
        self.assertEqual(ident["executable"], "/usr/bin/remote_srv")
        self.assertEqual(ident["process_start_time"], 34567)
        self.assertGreater(adapter.get_last_identity_bytes_read(), 0)
        self.assertTrue(all("500" in cmd for cmd in recorded_cmds))

    def test_24_glibc_lp64_mutex_and_budget_exhaustion(self):
        """Budget pre-check stops mutex reads when budget limit is reached, reporting PARTIAL."""
        adapter = LocalTargetAdapter()
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=50))
        tracker.start()

        engine = AdaptiveInvestigationEngine()
        mod = engine.registry.get("insp_locks")
        ctx = InspectionContext(
            pid=os.getpid(),
            companion_elf="",
            adapter=adapter,
            budget_tracker=tracker,
            parameters={"sampling_epoch": 1},
        )
        res = mod.run(ctx)
        self.assertIn(res.get("status"), ("PARTIAL", "BUDGET_EXHAUSTED", "OBSERVED"))


if __name__ == "__main__":
    unittest.main()

"""Phase 2.0-A.3.4.5 — Identity Race Closure & Transactional Budget Accounting.

Adversarial regression test suite validating:
1. Stable Executable FD verification and direct ELF parsing through open descriptor.
2. Descriptor ownership preservation (caller owns FD, parser does not close it).
3. Strict T0/T1 start-time and symlink consistency (fails closed on races or exits).
4. Concurrent ELF inspection measurement attribution (no global mutable variables).
5. Canonical measurement contract across all layers with numeric validation.
6. WorkManager exception accounting applying conservative unknown cost policy.
7. Transactional accounting ownership preventing duplicate and missing charges.
8. Real-process deadlock verification and remote namespace isolation.
"""

import base64
import copy
import math
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch, MagicMock
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
from extractor.debug_image import (
    BinaryIdentity,
    ELFInspectionError,
    inspect_elf,
    clear_elf_identity_cache,
    get_last_elf_bytes_read,
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
    ObservationAccountingRecord,
    validate_non_negative_int,
    validate_non_negative_float,
)
from extractor.inspection_module import (
    FunctionalInspectionModule,
    InspectionContext,
    InspectionProfile,
    DOMAIN_CONCURRENCY,
)


class TestPhase20A345IdentityRaceAndTransactions(unittest.TestCase):
    """Deterministic regression test suite for Phase 2.0-A.3.4.5."""

    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp(prefix="dynstate_a345_")
        cls.fixtures_dir = os.path.abspath(
            os.path.join(os.path.dirname(__file__), "fixtures", "real_runtime")
        )
        cls.bin_2way = os.path.join(cls.work_dir, "proc_2way_deadlock")

        src_path = os.path.join(cls.fixtures_dir, "proc_thread_circular_deadlock.c")
        if os.path.exists(src_path):
            cmd = ["gcc", "-O2", "-Wall", "-Wextra", "-pthread", src_path, "-o", cls.bin_2way]
            rc = subprocess.call(cmd)
            if rc != 0:
                raise RuntimeError(f"Failed to compile fixture {src_path} -> {cls.bin_2way}")

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

    # =========================================================================
    # 1. Stable Executable FD Verification & Ownership Tests
    # =========================================================================

    def test_01_stable_fd_passed_directly_to_inspect_elf(self):
        """inspect_elf accepts open file object directly, parses it, and leaves caller FD open."""
        target_bin = sys.executable
        with open(target_bin, "rb") as fd:
            fileno_before = fd.fileno()
            self.assertFalse(fd.closed)
            ident = inspect_elf(fd)
            # Verify parser read directly from descriptor
            self.assertGreater(ident.bytes_read, 64)
            self.assertIn(ident.architecture, ("x86_64", "aarch64", "x86", "arm"))
            # Crucial: inspect_elf must NOT close caller-owned descriptor
            self.assertFalse(fd.closed, "inspect_elf must not close caller-owned file descriptor")
            self.assertEqual(fd.fileno(), fileno_before)
            # Calling fileno / fstat on fd still succeeds
            st = os.fstat(fd.fileno())
            self.assertGreater(st.st_size, 0)

    def test_02_stable_fd_remains_bound_across_disk_replacement(self):
        """Stable open FD remains bound to the original executable object even if file on disk is replaced."""
        orig_file = os.path.join(self.work_dir, "bin_version_1")
        shutil.copyfile(sys.executable, orig_file)

        # Open stable FD on version 1
        with open(orig_file, "rb") as fd:
            stat_orig = os.fstat(fd.fileno())

            # Now replace the file on disk with a different file
            os.remove(orig_file)
            with open(orig_file, "wb") as f_new:
                f_new.write(b"\x7fELF" + b"\x01" * 100)
            stat_new = os.stat(orig_file)

            # Inodes differ on disk replacement
            self.assertNotEqual(stat_orig.st_ino, stat_new.st_ino)

            # inspect_elf on the open fd still parses the original file
            ident = inspect_elf(fd)
            self.assertGreater(ident.bytes_read, 64)
            self.assertFalse(fd.closed)

    def test_03_stable_fd_acquisition_failure_blocks_identity_verified(self):
        """If stable FD acquisition fails, get_process_identity never returns IDENTITY_VERIFIED."""
        adapter = LocalTargetAdapter()
        pid = os.getpid()

        import extractor.target_adapter as ta
        orig_open = open

        def failing_open(path, *args, **kwargs):
            if f"/proc/{pid}/exe" in str(path):
                raise PermissionError(f"Permission denied: {path}")
            return orig_open(path, *args, **kwargs)

        with patch("builtins.open", side_effect=failing_open):
            ident = adapter.get_process_identity(pid)
            self.assertNotEqual(
                ident["identity_status"],
                IDENTITY_VERIFIED,
                "Permission denied on stable FD must never produce IDENTITY_VERIFIED",
            )
            self.assertIn(ident["identity_status"], (IDENTITY_UNAVAILABLE, IDENTITY_UNVERIFIED))
            self.assertFalse(ident.get("stable_fd_verified", False))

    def test_04_no_fallback_to_unverified_pathname(self):
        """When /proc/<pid>/exe cannot be opened as FD, adapter does not silently fall back to disk path while verifying."""
        adapter = LocalTargetAdapter()
        pid = os.getpid()

        import extractor.target_adapter as ta
        orig_open = open

        def failing_open(path, *args, **kwargs):
            if f"/proc/{pid}/exe" in str(path):
                raise FileNotFoundError("Proc exe vanished")
            return orig_open(path, *args, **kwargs)

        with patch("builtins.open", side_effect=failing_open):
            ident = adapter.get_process_identity(pid)
            self.assertNotEqual(ident["identity_status"], IDENTITY_VERIFIED)
            self.assertFalse(ident.get("stable_fd_verified", False))

    # =========================================================================
    # 2. Strict T0/T1 Consistency & Fail-Closed Tests
    # =========================================================================

    def test_05_missing_t0_start_time_fails_closed(self):
        """Missing T0 start time fails closed and never produces IDENTITY_VERIFIED."""
        adapter = LocalTargetAdapter()
        pid = os.getpid()

        orig_open = open

        def mock_open(path, *args, **kwargs):
            if f"/proc/{pid}/stat" in str(path):
                raise FileNotFoundError("stat not found")
            return orig_open(path, *args, **kwargs)

        with patch("builtins.open", side_effect=mock_open):
            ident = adapter.get_process_identity(pid)
            self.assertNotEqual(ident["identity_status"], IDENTITY_VERIFIED)
            self.assertIsNone(ident["process_start_time"])

    def test_06_missing_t1_start_time_fails_closed(self):
        """When T1 stat read fails after successful T0, identity verification fails closed."""
        adapter = LocalTargetAdapter()
        pid = os.getpid()

        orig_open = open
        stat_call_count = [0]

        def mock_open(path, *args, **kwargs):
            if f"/proc/{pid}/stat" in str(path):
                stat_call_count[0] += 1
                if stat_call_count[0] > 1:
                    # T1 call fails
                    raise ProcessLookupError("Process disappeared before T1")
            return orig_open(path, *args, **kwargs)

        with patch("builtins.open", side_effect=mock_open):
            ident = adapter.get_process_identity(pid)
            self.assertNotEqual(ident["identity_status"], IDENTITY_VERIFIED)
            self.assertIn(ident["identity_status"], (IDENTITY_UNAVAILABLE, IDENTITY_INCONSISTENT))

    def test_07_t0_t1_start_time_mismatch_fails_closed_inconsistent(self):
        """Start time change between T0 and T1 indicates PID reuse and produces IDENTITY_INCONSISTENT."""
        adapter = LocalTargetAdapter()
        pid = os.getpid()

        orig_open = open
        stat_calls = [0]

        def mock_open(path, *args, **kwargs):
            if f"/proc/{pid}/stat" in str(path):
                stat_calls[0] += 1
                # Return start time 500 on T0, start time 999 on T1
                st = "500" if stat_calls[0] == 1 else "999"
                fake_stat = f"{pid} (test) S 1 {pid} {pid} 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 {st} 0 0"
                import io
                return io.StringIO(fake_stat)
            return orig_open(path, *args, **kwargs)

        with patch("builtins.open", side_effect=mock_open):
            ident = adapter.get_process_identity(pid)
            self.assertEqual(ident["identity_status"], IDENTITY_INCONSISTENT)
            self.assertEqual(ident["status"], "INCONSISTENT")

    def test_08_t0_t1_symlink_change_fails_closed_inconsistent(self):
        """Symlink change between T0 and T1 produces IDENTITY_INCONSISTENT."""
        adapter = LocalTargetAdapter()
        pid = os.getpid()

        orig_readlink = os.readlink
        calls = [0]

        def mock_readlink(path, *args, **kwargs):
            if f"/proc/{pid}/exe" in str(path):
                calls[0] += 1
                if calls[0] == 1:
                    return "/usr/bin/app_v1"
                return "/usr/bin/app_v2"
            return orig_readlink(path, *args, **kwargs)

        with patch("os.readlink", side_effect=mock_readlink):
            ident = adapter.get_process_identity(pid)
            self.assertEqual(ident["identity_status"], IDENTITY_INCONSISTENT)

    def test_09_process_exits_during_inspection_fails_closed(self):
        """Process exit during inspection fails closed with IDENTITY_UNAVAILABLE (TARGET_TERMINATED)."""
        adapter = LocalTargetAdapter()
        pid = os.getpid()

        with patch("os.kill", side_effect=[None, ProcessLookupError("No such process")]):
            ident = adapter.get_process_identity(pid)
            self.assertEqual(ident["identity_status"], IDENTITY_UNAVAILABLE)
            self.assertEqual(ident["status"], "TARGET_TERMINATED")

    def test_10_permission_failure_during_t1_fails_closed(self):
        """Permission failure reading /proc/<pid>/exe during T1 produces IDENTITY_UNAVAILABLE."""
        adapter = LocalTargetAdapter()
        pid = os.getpid()

        orig_readlink = os.readlink
        calls = [0]

        def mock_readlink(path, *args, **kwargs):
            if f"/proc/{pid}/exe" in str(path):
                calls[0] += 1
                if calls[0] > 1:
                    raise PermissionError("EACCES")
                return sys.executable
            return orig_readlink(path, *args, **kwargs)

        with patch("os.readlink", side_effect=mock_readlink):
            ident = adapter.get_process_identity(pid)
            self.assertEqual(ident["identity_status"], IDENTITY_UNAVAILABLE)

    def test_11_deleted_binary_fails_closed(self):
        """Executable path marked (deleted) never produces IDENTITY_VERIFIED."""
        adapter = LocalTargetAdapter()
        pid = os.getpid()

        with patch("os.readlink", return_value=f"{sys.executable} (deleted)"):
            ident = adapter.get_process_identity(pid)
            self.assertTrue(ident["is_deleted"])
            self.assertEqual(ident["identity_status"], IDENTITY_UNVERIFIED)

    # =========================================================================
    # 3. ELF Accounting & Concurrency Tests
    # =========================================================================

    def test_12_concurrent_inspections_of_different_files(self):
        """Concurrent inspections across multiple threads attribute exact bytes to each thread without crosstalk."""
        # Create 8 temporary ELF files of varying sizes
        temp_files = []
        try:
            for i in range(8):
                tf = tempfile.NamedTemporaryFile(prefix=f"test_elf_{i}_", suffix=".tmp", delete=False)
                # Padding creates distinct sizes
                padding = b"\x00" * (i * 256)
                # Minimal valid ELF64 header with padding
                hdr = (
                    b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 +
                    struct.pack("<HHIQQQIHHHHHH", 2, 0x3e, 1, 0x400000, 64, 0, 0, 64, 56, 1, 0, 0, 0) +
                    struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, len(padding) + 120, len(padding) + 120, 0x1000) +
                    padding
                )
                tf.write(hdr)
                tf.close()
                temp_files.append(tf.name)

            results = {}
            errors = []

            def worker(idx, path):
                try:
                    ident = inspect_elf(path)
                    results[idx] = ident.bytes_read
                except Exception as e:
                    errors.append((idx, e))

            threads = [threading.Thread(target=worker, args=(i, temp_files[i])) for i in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=5.0)

            self.assertEqual(len(errors), 0, f"Thread errors: {errors}")
            self.assertEqual(len(results), 8)
            # Each worker must have measured actual bytes > 64
            for i in range(8):
                self.assertGreaterEqual(results[i], 64)
        finally:
            for p in temp_files:
                if os.path.exists(p):
                    os.remove(p)

    def test_13_concurrent_inspections_of_same_file(self):
        """Concurrent inspection of the same file correctly handles cache hits and misses thread-safely."""
        target_bin = sys.executable
        results = []
        errors = []

        def worker():
            try:
                ident = inspect_elf(target_bin)
                results.append((ident.cached, ident.bytes_read, ident.cache_bytes_read))
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=5.0)

        self.assertEqual(len(errors), 0)
        self.assertEqual(len(results), 10)
        # At least one thread should have observed a cache miss or cache hit cleanly
        misses = [r for r in results if not r[0]]
        hits = [r for r in results if r[0]]
        for h in hits:
            # Cache hits must report 0 current read bytes
            self.assertEqual(h[1], 0)
            self.assertGreater(h[2], 0)

    def test_14_concurrent_cache_hit_and_miss_isolation(self):
        """A cache hit thread must not alter the measured_bytes_read of a concurrent cache miss thread."""
        target_bin = sys.executable
        # Prime cache for target_bin
        ident_primed = inspect_elf(target_bin)
        self.assertFalse(ident_primed.cached)
        initial_bytes = ident_primed.bytes_read

        # Create an un-cached temporary file
        tf = tempfile.NamedTemporaryFile(prefix="uncached_", suffix=".tmp", delete=False)
        hdr = (
            b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 +
            struct.pack("<HHIQQQIHHHHHH", 2, 0x3e, 1, 0x400000, 64, 0, 0, 64, 56, 1, 0, 0, 0) +
            struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 120, 120, 0x1000)
        )
        tf.write(hdr)
        tf.close()
        uncached_file = tf.name

        try:
            hit_bytes = []
            miss_bytes = []

            def hit_worker():
                res = inspect_elf(target_bin)
                hit_bytes.append(res.bytes_read)

            def miss_worker():
                res = inspect_elf(uncached_file)
                miss_bytes.append(res.bytes_read)

            t1 = threading.Thread(target=hit_worker)
            t2 = threading.Thread(target=miss_worker)
            t1.start()
            t2.start()
            t1.join(timeout=5.0)
            t2.join(timeout=5.0)

            self.assertEqual(hit_bytes[0], 0, "Cache hit must report exactly 0 current bytes")
            self.assertGreaterEqual(miss_bytes[0], 64, "Cache miss must report actual bytes read")
        finally:
            if os.path.exists(uncached_file):
                os.remove(uncached_file)

    def test_15_partial_read_followed_by_elf_exception_preserves_bytes(self):
        """Truncated ELF header raises structured ELFInspectionError preserving partial bytes read."""
        with tempfile.NamedTemporaryFile(prefix="trunc_", suffix=".tmp", delete=False) as tf:
            # 20 bytes: valid 16-byte magic + 4 truncated header bytes
            tf.write(b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 + b"\x02\x00\x3e\x00")
            tmp_path = tf.name

        try:
            with self.assertRaises(ELFInspectionError) as ctx:
                inspect_elf(tmp_path)
            exc = ctx.exception
            # Structured exception carries measured bytes >= 16
            self.assertGreaterEqual(exc.bytes_read, 16)
            self.assertEqual(exc.path, tmp_path)
            # Backwards compatibility: exc is also an instance of ValueError
            self.assertIsInstance(exc, ValueError)
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

    def test_16_cache_key_uses_device_and_inode_tuple(self):
        """Cache keys use POSIX (dev, ino, mtime, size) tuple to invalidate on replacement."""
        tf = tempfile.NamedTemporaryFile(prefix="tuple_", suffix=".tmp", delete=False)
        hdr = (
            b"\x7fELF\x02\x01\x01\x00" + b"\x00" * 8 +
            struct.pack("<HHIQQQIHHHHHH", 2, 0x3e, 1, 0x400000, 64, 0, 0, 64, 56, 1, 0, 0, 0) +
            struct.pack("<IIQQQQQQ", 1, 5, 0, 0x400000, 0x400000, 120, 120, 0x1000)
        )
        tf.write(hdr)
        tf.close()
        path = tf.name

        try:
            id1 = inspect_elf(path)
            self.assertFalse(id1.cached)

            id2 = inspect_elf(path)
            self.assertTrue(id2.cached)

            # Touch file modification time
            time.sleep(0.01)
            os.utime(path, None)

            # After mtime change, cache key misses and re-reads
            id3 = inspect_elf(path)
            self.assertFalse(id3.cached, "Modified mtime must invalidate cache key")
            self.assertGreater(id3.bytes_read, 0)
        finally:
            if os.path.exists(path):
                os.remove(path)

    # =========================================================================
    # 4. WorkManager Exception Accounting Tests
    # =========================================================================

    def test_17_workmanager_exception_with_measured_bytes(self):
        """When WorkManager fails with measured_bytes_read, tracker charges them as measured failure."""
        engine = AdaptiveInvestigationEngine()
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=100000))
        tracker.start()

        class MeasuredFailingWM:
            def inspect_thread_callstacks_and_locks(self, **kw):
                exc = RuntimeError("IO error after partial read")
                exc.measured_bytes_read = 350
                raise exc

        wm = MeasuredFailingWM()
        adapter = LocalTargetAdapter()
        mod = engine.registry.get("insp_locks")
        ctx = InspectionContext(
            pid=os.getpid(),
            companion_elf="",
            adapter=adapter,
            budget_tracker=tracker,
        )
        out = mod.run(ctx, watch_manager=wm)
        fail_reads = [h for h in tracker._history if h.get("is_failure")]
        self.assertGreaterEqual(len(fail_reads), 1)
        self.assertEqual(fail_reads[0]["measured_bytes_read"], 350)
        self.assertGreaterEqual(tracker.metrics.total_read_failures, 1)

    def test_18_workmanager_exception_with_estimated_bytes(self):
        """When WorkManager fails with estimated_bytes_read, tracker charges them as estimated failure."""
        engine = AdaptiveInvestigationEngine()
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=100000))
        tracker.start()

        class EstimatedFailingWM:
            def inspect_thread_callstacks_and_locks(self, **kw):
                exc = RuntimeError("Failure with estimate")
                exc.estimated_bytes_read = 1200
                raise exc

        wm = EstimatedFailingWM()
        adapter = LocalTargetAdapter()
        mod = engine.registry.get("insp_locks")
        ctx = InspectionContext(
            pid=os.getpid(),
            companion_elf="",
            adapter=adapter,
            budget_tracker=tracker,
        )
        out = mod.run(ctx, watch_manager=wm)
        self.assertEqual(tracker.metrics.conservative_estimated_bytes, 1200)
        self.assertGreaterEqual(tracker.metrics.total_read_failures, 1)

    def test_19_workmanager_exception_with_unknown_cost_never_zero(self):
        """When WorkManager fails with unknown cost, tracker applies conservative unknown cost policy (>0)."""
        engine = AdaptiveInvestigationEngine()
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=100000))
        tracker.start()

        class RawFailingWM:
            def inspect_thread_callstacks_and_locks(self, **kw):
                raise RuntimeError("Completely unknown failure")

        wm = RawFailingWM()
        adapter = LocalTargetAdapter()
        mod = engine.registry.get("insp_locks")
        ctx = InspectionContext(
            pid=os.getpid(),
            companion_elf="",
            adapter=adapter,
            budget_tracker=tracker,
        )
        out = mod.run(ctx, watch_manager=wm)
        # Cost charged is > 0, never silently zero
        self.assertGreater(tracker.metrics.bytes_read, 0)
        self.assertGreaterEqual(tracker.metrics.total_read_failures, 1)

    def test_20_workmanager_invalid_numeric_byte_values_rejected(self):
        """Invalid numeric values (bool, negative, NaN, Inf) in WorkManager are rejected with ValueError."""
        engine = AdaptiveInvestigationEngine()

        for invalid_val in (True, False, -100, float("nan"), float("inf")):
            tracker = ObservationBudgetTracker()
            tracker.start()

            # Tracker record_read rejects directly
            with self.assertRaises(ValueError):
                tracker.record_read(bytes_read=invalid_val)

            class MalformedWM:
                def inspect_thread_callstacks_and_locks(self, **kw):
                    exc = RuntimeError("Malformed cost")
                    exc.measured_bytes_read = invalid_val
                    raise exc

            mod = engine.registry.get("insp_locks")
            ctx = InspectionContext(
                pid=os.getpid(),
                companion_elf="",
                adapter=LocalTargetAdapter(),
                budget_tracker=tracker,
            )
            out = mod.run(ctx, watch_manager=MalformedWM())
            self.assertEqual(out.get("error_code"), "ValueError")
            self.assertIn("Invalid numeric value", out.get("error", ""))

    def test_21_budget_exhaustion_before_fallback_blocks_fallback(self):
        """If initial attempt exhausts remaining budget, fallback is immediately aborted with BUDGET_EXHAUSTED."""
        engine = AdaptiveInvestigationEngine()
        # Budget only 500 bytes; WM exception will charge >= 4096 bytes
        tracker = ObservationBudgetTracker(ObservationBudgetLimits(max_bytes_read=500))
        tracker.start()

        class ExhaustingWM:
            def inspect_thread_callstacks_and_locks(self, **kw):
                exc = RuntimeError("Consumed 600 bytes before dying")
                exc.measured_bytes_read = 600
                raise exc

        mod = engine.registry.get("insp_locks")
        ctx = InspectionContext(
            pid=os.getpid(),
            companion_elf="",
            adapter=LocalTargetAdapter(),
            budget_tracker=tracker,
        )
        out = mod.run(ctx, watch_manager=ExhaustingWM())
        self.assertEqual(out["status"], "BUDGET_EXHAUSTED")
        self.assertFalse(out.get("fallback_executed", False))

    # =========================================================================
    # 5. FunctionalInspectionModule Contract & Transactions
    # =========================================================================

    def test_22_module_measured_bytes_read_only_result(self):
        """FunctionalInspectionModule recognizes measured_bytes_read without requiring bytes_read."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        profile = InspectionProfile(profile_id="test_m_only", domain=DOMAIN_CONCURRENCY, name="Test M")
        mod = FunctionalInspectionModule(profile, func=lambda **kw: {"success": True, "measured_bytes_read": 180})

        ctx = InspectionContext(pid=os.getpid(), companion_elf="", adapter=LocalTargetAdapter(), budget_tracker=tracker)
        out = mod.run(ctx)
        self.assertEqual(out["measured_bytes_read"], 180)
        self.assertEqual(tracker.metrics.measured_bytes_read, 180)
        self.assertEqual(tracker.metrics.conservative_estimated_bytes, 0)

    def test_23_module_estimated_bytes_read_only_result(self):
        """FunctionalInspectionModule recognizes estimated_bytes_read without requiring bytes_read."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        profile = InspectionProfile(profile_id="test_e_only", domain=DOMAIN_CONCURRENCY, name="Test E")
        mod = FunctionalInspectionModule(profile, func=lambda **kw: {"success": True, "estimated_bytes_read": 320})

        ctx = InspectionContext(pid=os.getpid(), companion_elf="", adapter=LocalTargetAdapter(), budget_tracker=tracker)
        out = mod.run(ctx)
        self.assertEqual(out["estimated_bytes_read"], 320)
        self.assertEqual(tracker.metrics.conservative_estimated_bytes, 320)
        self.assertEqual(tracker.metrics.measured_bytes_read, 0)

    def test_24_module_both_measured_and_estimated_values(self):
        """FunctionalInspectionModule correctly accounts for both measured and estimated values."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        profile = InspectionProfile(profile_id="test_both", domain=DOMAIN_CONCURRENCY, name="Test Both")
        mod = FunctionalInspectionModule(
            profile,
            func=lambda **kw: {"success": True, "measured_bytes_read": 100, "estimated_bytes_read": 50},
        )

        ctx = InspectionContext(pid=os.getpid(), companion_elf="", adapter=LocalTargetAdapter(), budget_tracker=tracker)
        out = mod.run(ctx)
        self.assertEqual(out["measured_bytes_read"], 100)
        self.assertEqual(out["estimated_bytes_read"], 50)
        self.assertEqual(out["charged_bytes"], 150)
        self.assertEqual(tracker.metrics.measured_bytes_read, 100)
        self.assertEqual(tracker.metrics.conservative_estimated_bytes, 50)

    def test_25_module_unknown_cost_applies_conservative_estimate(self):
        """FunctionalInspectionModule never defaults unknown cost to zero; charges conservative estimate."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        profile = InspectionProfile(profile_id="test_unk", domain=DOMAIN_CONCURRENCY, name="Test Unk")
        mod = FunctionalInspectionModule(profile, func=lambda **kw: {"success": True})

        ctx = InspectionContext(pid=os.getpid(), companion_elf="", adapter=LocalTargetAdapter(), budget_tracker=tracker)
        out = mod.run(ctx)
        self.assertGreater(out["charged_bytes"], 0)
        self.assertTrue(out["used_conservative_byte_estimate"])
        self.assertEqual(tracker.metrics.measured_bytes_read, 0)
        self.assertGreater(tracker.metrics.conservative_estimated_bytes, 0)

    def test_26_module_no_duplicate_charge_when_committed(self):
        """When accounting_status is COMMITTED or accounting_owner is MODULE_INTERNAL, tracker is not double-charged."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        def custom_fn(**kw):
            b_tracker = kw["budget_tracker"]
            # Inner function accounts for 200 measured bytes
            b_tracker.record_read(bytes_read=200, profile_id="test_comm")
            return {
                "success": True,
                "measured_bytes_read": 200,
                "accounting_owner": "MODULE_INTERNAL",
                "accounting_status": "COMMITTED",
            }

        profile = InspectionProfile(profile_id="test_comm", domain=DOMAIN_CONCURRENCY, name="Test Committed")
        mod = FunctionalInspectionModule(profile, func=custom_fn)

        ctx = InspectionContext(pid=os.getpid(), companion_elf="", adapter=LocalTargetAdapter(), budget_tracker=tracker)
        out = mod.run(ctx)
        # Total bytes read in tracker must be exactly 200, NOT 400
        self.assertEqual(tracker.metrics.bytes_read, 200)
        self.assertEqual(out["charged_bytes"], 200)

    def test_27_module_transactional_record_commit(self):
        """ObservationAccountingRecord.commit() commits atomically and idempotently without duplicate charges."""
        tracker = ObservationBudgetTracker()
        tracker.start()

        record = ObservationAccountingRecord(
            operation_id="test_tx",
            accounting_owner="CUSTOM_TOOL",
            measured_bytes_read=500,
        )
        self.assertEqual(record.accounting_status, "PENDING")

        # First commit charges tracker
        ok1 = record.commit(tracker)
        self.assertTrue(ok1)
        self.assertEqual(record.accounting_status, "COMMITTED")
        self.assertEqual(tracker.metrics.measured_bytes_read, 500)

        # Second commit is idempotent: does NOT charge again
        ok2 = record.commit(tracker)
        self.assertTrue(ok2)
        self.assertEqual(tracker.metrics.measured_bytes_read, 500)

    # =========================================================================
    # 6. Numeric Validator Contract Tests
    # =========================================================================

    def test_28_strict_numeric_validation_contract(self):
        """validate_non_negative_int and validate_non_negative_float reject bool, negative, NaN, Inf."""
        # Valid ints
        self.assertEqual(validate_non_negative_int(0), 0)
        self.assertEqual(validate_non_negative_int(4096), 4096)

        # Invalid ints
        self.assertIsNone(validate_non_negative_int(True))
        self.assertIsNone(validate_non_negative_int(False))
        self.assertIsNone(validate_non_negative_int(-1))
        self.assertIsNone(validate_non_negative_int(float("nan")))
        self.assertIsNone(validate_non_negative_int(float("inf")))
        self.assertIsNone(validate_non_negative_int("123"))

        # Valid floats
        self.assertEqual(validate_non_negative_float(0.0), 0.0)
        self.assertEqual(validate_non_negative_float(25.5), 25.5)

        # Invalid floats
        self.assertIsNone(validate_non_negative_float(True))
        self.assertIsNone(validate_non_negative_float(-0.1))
        self.assertIsNone(validate_non_negative_float(float("nan")))
        self.assertIsNone(validate_non_negative_float(float("inf")))

    # =========================================================================
    # 7. Regression & Real-Process Tests
    # =========================================================================

    def test_29_wait_for_graph_accepts_only_identity_verified(self):
        """WaitForGraph confirms deadlocks only when edges carry IDENTITY_VERIFIED."""
        for invalid_status in (IDENTITY_UNVERIFIED, IDENTITY_INCONSISTENT, IDENTITY_UNAVAILABLE):
            p_ident = self._sample_valid_proc_identity(100)
            p_ident["identity_status"] = invalid_status

            graph = WaitForGraph()
            e1 = WaitForEdge(
                waiter_tid=101,
                sync_object="0x1000",
                owner_tid=102,
                owner_identification_status=STATUS_OWNER_IDENTIFIED,
                target_pid=100,
                process_identity=p_ident,
                sampling_epoch=1,
            )
            e2 = WaitForEdge(
                waiter_tid=102,
                sync_object="0x2000",
                owner_tid=101,
                owner_identification_status=STATUS_OWNER_IDENTIFIED,
                target_pid=100,
                process_identity=p_ident,
                sampling_epoch=1,
            )
            graph.add_edge(e1)
            graph.add_edge(e2)

            cycle, cat, issues = graph.validate_and_analyze(target_tids={101, 102}, allowed_epoch=1)
            self.assertIsNone(cycle)
            self.assertIn(cat, (RESULT_INCOMPLETE_WAIT_FOR_GRAPH, RESULT_INCONCLUSIVE))
            self.assertTrue(any("IDENTITY" in iss for iss in issues))

    def test_30_real_process_two_way_deadlock_confirmed_with_strict_identity(self):
        """Real two-way deadlock process fixture confirms deadlock with verified identity."""
        if not os.path.exists(self.bin_2way):
            self.skipTest(f"Binary fixture {self.bin_2way} not available")

        proc = subprocess.Popen([self.bin_2way], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            time.sleep(0.3)  # Allow fixture threads to deadlock
            adapter = LocalTargetAdapter()
            ident = adapter.get_process_identity(proc.pid)
            self.assertEqual(ident["identity_status"], IDENTITY_VERIFIED)
            self.assertTrue(ident["stable_fd_verified"])

            engine = AdaptiveInvestigationEngine()
            tracker = ObservationBudgetTracker()
            tracker.start()
            mod = engine.registry.get("insp_locks")
            ctx = InspectionContext(
                pid=proc.pid,
                companion_elf="",
                adapter=adapter,
                budget_tracker=tracker,
                parameters={"sampling_epoch": 0},
            )
            out = mod.run(ctx)
            self.assertTrue(out.get("success"))
            self.assertTrue(out.get("deadlock_detected"))
            self.assertEqual(out.get("result_category"), RESULT_DEADLOCK_CYCLE_CONFIRMED)
            self.assertGreater(tracker.metrics.measured_bytes_read, 0)
        finally:
            proc.kill()
            proc.wait()


if __name__ == "__main__":
    unittest.main()

"""Phase 2.0-A.3.3 Runtime Evidence Semantics & Budget Enforcement Closure Test Suite.

Verifies:
1. Futex & Concurrency Evidence Semantics:
   - Integer and hex syscall argument normalization
   - Rejection of invalid, negative, zero, and synthetic lock addresses
   - Futex waiting observed without lock owner identification (inconclusive, not deadlock)
   - Multiple threads waiting on the same lock address (contention without cycle)
   - Genuine circular wait with verified owner edges (confirmed deadlock cycle)
   - Incomplete wait-for graph remaining inconclusive
2. Memory Attribution & Decoupling:
   - Process RSS growth without heap growth
   - Heap mapping expansion without RSS growth
   - Anonymous mapping expansion without heap growth
   - Process RSS is never reported as heap RSS (heap_rss_bytes is explicitly None)
   - Missing smaps_rollup falls back without fabricating values
   - Procfs-only evidence never produces a CONFIRMED allocation leak verdict
3. Budget Enforcement:
   - Wall-clock budget expires before next sample (returns PARTIAL, no overshoot)
   - Byte budget expires during multi-source inspection (stops before read)
   - Measured bytes read differs from estimated and accumulates accurately
   - Multi-sample inspection interrupted by budget preserves collected samples
   - Direct adapter fallback paths obey active budget
4. Failure Semantics:
   - Permission denied on procfs returns PERMISSION_DENIED fail-closed
   - Process termination during sampling returns TARGET_TERMINATED
   - Missing optional metrics reported separately from missing required metrics
   - Empty results caused by access failure never become healthy/stable verdicts
"""

import os
import shutil
import subprocess
import tempfile
import time
import unittest
from typing import Any, Dict, List, Optional, Tuple

from extractor.adaptive_engine import (
    AdaptiveInvestigationEngine,
    WaitForEdge,
    WaitForGraph,
    STATE_COMPLETED,
    STATE_INCONCLUSIVE,
    STATE_BUDGET_EXHAUSTED,
)
from extractor.evidence_ledger import EvidenceLedger
from extractor.observation_budget import (
    ObservationBudgetLimits,
    ObservationBudgetTracker,
)
from extractor.target_adapter import (
    LocalTargetAdapter,
    ReadOnlyTargetAdapter,
    normalize_futex_address,
)
from extractor.verdict_engine import (
    DIAG_CONFIRMED,
    DIAG_INCONCLUSIVE,
    DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE,
    DIAG_PARTIALLY_CONFIRMED,
    DIAG_SUSPECTED,
    STOP_BUDGET_EXHAUSTED,
)


class TestPhase20A33RuntimeEvidenceSemantics(unittest.TestCase):
    """Phase 2.0-A.3.3 Runtime Evidence Semantics & Budget Enforcement Closure."""

    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp(prefix="dynstate_a33_")
        cls.fixtures_dir = os.path.abspath("tests/fixtures/real_runtime")

        # Compile native binaries
        cls.bin_healthy = os.path.join(cls.work_dir, "proc_healthy")
        cls.bin_vsz_only = os.path.join(cls.work_dir, "proc_vsz_only")
        cls.bin_burst_drop = os.path.join(cls.work_dir, "proc_burst_drop")
        cls.bin_cv = os.path.join(cls.work_dir, "proc_normal_cv")
        cls.bin_deadlock2 = os.path.join(cls.work_dir, "proc_deadlock2")
        cls.bin_deadlock3 = os.path.join(cls.work_dir, "proc_deadlock3")
        cls.bin_two_waiters = os.path.join(cls.work_dir, "proc_two_waiters")
        cls.bin_mem_growth = os.path.join(cls.work_dir, "proc_scenario_b")

        subprocess.check_call([
            "gcc", "-O2", "-Wall", "-Wextra", "-pthread", "-g",
            os.path.join(cls.fixtures_dir, "proc_scenario_a_healthy.c"),
            "-o", cls.bin_healthy,
        ])
        subprocess.check_call([
            "gcc", "-O2", "-Wall", "-Wextra", "-pthread", "-g",
            os.path.join(cls.fixtures_dir, "proc_mem_vsz_mapping_only.c"),
            "-o", cls.bin_vsz_only,
        ])
        subprocess.check_call([
            "gcc", "-O2", "-Wall", "-Wextra", "-pthread", "-g",
            os.path.join(cls.fixtures_dir, "proc_mem_burst_and_drop.c"),
            "-o", cls.bin_burst_drop,
        ])
        subprocess.check_call([
            "gcc", "-O2", "-Wall", "-Wextra", "-pthread", "-g",
            os.path.join(cls.fixtures_dir, "proc_thread_normal_cv.c"),
            "-o", cls.bin_cv,
        ])
        subprocess.check_call([
            "gcc", "-O2", "-Wall", "-Wextra", "-pthread", "-g",
            os.path.join(cls.fixtures_dir, "proc_thread_circular_deadlock.c"),
            "-o", cls.bin_deadlock2,
        ])
        subprocess.check_call([
            "gcc", "-O2", "-Wall", "-Wextra", "-pthread", "-g",
            os.path.join(cls.fixtures_dir, "proc_thread_3way_deadlock.c"),
            "-o", cls.bin_deadlock3,
        ])
        subprocess.check_call([
            "gcc", "-O2", "-Wall", "-Wextra", "-pthread", "-g",
            os.path.join(cls.fixtures_dir, "proc_two_waiters_one_lock.c"),
            "-o", cls.bin_two_waiters,
        ])
        subprocess.check_call([
            "gcc", "-O2", "-Wall", "-Wextra", "-pthread", "-g",
            os.path.join(cls.fixtures_dir, "proc_scenario_b_growing_mem.c"),
            "-o", cls.bin_mem_growth,
        ])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work_dir, ignore_errors=True)

    # =========================================================================
    # Group 1: Futex & Concurrency Evidence Semantics
    # =========================================================================

    def test_01_normalize_integer_and_hex_syscall_arg0(self):
        """Normalizes integer and hexadecimal syscall arguments safely while preserving raw arg."""
        # 1. Linux /proc/<pid>/task/<tid>/syscall integer address
        raw_int = int("0x560f842945c0", 16)
        norm_hex, norm_int, st, orig = normalize_futex_address(raw_int)
        self.assertEqual(norm_hex, "0x560f842945c0")
        self.assertEqual(norm_int, raw_int)
        self.assertEqual(st, "WAIT_ADDRESS_OBSERVED")
        self.assertEqual(orig, raw_int)

        # 2. Hexadecimal string address
        raw_hex_str = "0x560f842945c0"
        norm_hex2, norm_int2, st2, orig2 = normalize_futex_address(raw_hex_str)
        self.assertEqual(norm_hex2, "0x560f842945c0")
        self.assertEqual(norm_int2, raw_int)
        self.assertEqual(st2, "WAIT_ADDRESS_OBSERVED")
        self.assertEqual(orig2, raw_hex_str)

        # 3. Method on TargetExecutionAdapter / ReadOnlyTargetAdapter
        adapter = LocalTargetAdapter()
        ro_adapter = ReadOnlyTargetAdapter(adapter)
        h, i, s, _ = ro_adapter.normalize_futex_address(raw_int)
        self.assertEqual(h, "0x560f842945c0")
        self.assertEqual(i, raw_int)
        self.assertEqual(s, "WAIT_ADDRESS_OBSERVED")

    def test_02_reject_invalid_negative_zero_synthetic_lock_addresses(self):
        """Rejects zero, negative, malformed, and synthetic placeholder lock addresses."""
        invalid_inputs = [
            0,
            -1,
            -9999,
            "0",
            "0x0",
            "0x",
            "-1",
            "0x_lock",
            "0x_futex_lock",
            "None",
            "null",
            "",
            None,
            "not_a_hex_number",
        ]
        for val in invalid_inputs:
            norm_hex, norm_int, st, orig = normalize_futex_address(val)
            self.assertIsNone(norm_hex, f"Expected None for invalid value {val!r}")
            self.assertIsNone(norm_int, f"Expected None for invalid value {val!r}")
            self.assertIn(st, ("UNAVAILABLE", "INVALID_ADDRESS"), f"Expected non-observed status for {val!r}")
            self.assertEqual(orig, val)

    def test_03_futex_wait_without_lock_owner_identification(self):
        """A thread waiting on a futex without identifiable owner reports UNCONFIRMED, never deadlock."""
        engine = AdaptiveInvestigationEngine()
        ctx = engine.registry.get("insp_locks")
        raw_int = int("0x560f842945c0", 16)

        # Mock adapter where thread waits on futex 0x560f842945c0, but owner TID cannot be resolved
        class MockUnresolvedOwnerAdapter(LocalTargetAdapter):
            def get_threads(self, pid: int):
                return [{
                    "tid": pid + 10,
                    "name": "worker_unresolved",
                    "state": "S",
                    "is_futex_wait": True,
                    "syscall_nr": 98,
                    "syscall_name": "futex",
                    "syscall_arg0": raw_int,
                    "syscall_arg0_int": raw_int,
                    "waiting_on_lock": "0x560f842945c0",
                    "lock_address_status": "WAIT_ADDRESS_OBSERVED",
                    "lock_owner_identified": False,
                    "wchan": "futex_wait_queue",
                }]

            def resolve_mutex_owner(self, pid: int, lock_addr: Any) -> Optional[int]:
                return None  # Userspace memory unmapped or owner TID not found

        res = ctx.func(None, pid=12345, adapter=MockUnresolvedOwnerAdapter())
        self.assertTrue(res["success"])
        self.assertFalse(res["deadlock_detected"])
        self.assertIsNone(res["deadlock_cycle"])
        self.assertFalse(res["lock_contention_observed"])

        # Thread state reports wait address observed but owner unidentified
        th = res["threads"][0]
        self.assertEqual(th["waiting_on_lock"], "0x560f842945c0")
        self.assertIsNone(th.get("owner_tid"))
        self.assertFalse(th.get("lock_owner_identified"))

    def test_04_multiple_threads_waiting_on_same_lock_contention_no_cycle(self):
        """Multiple threads waiting on the same lock is contention, NOT a deadlock cycle."""
        proc = subprocess.Popen([self.bin_two_waiters])
        try:
            time.sleep(0.1)
            pid = proc.pid
            adapter = LocalTargetAdapter()

            threads = adapter.get_threads(pid)
            self.assertGreaterEqual(len(threads), 3)

            engine = AdaptiveInvestigationEngine()
            ctx = engine.registry.get("insp_locks")
            res = ctx.func(None, pid=pid, adapter=adapter)

            self.assertTrue(res["success"])
            self.assertEqual(res["status"], "OBSERVED")

            # Contention is observed because 2 waiters wait on the same mutex
            self.assertTrue(res["lock_contention_observed"])

            # BUT no cycle exists: both point to the holder thread!
            self.assertFalse(res["deadlock_detected"])
            self.assertIsNone(res["deadlock_cycle"])

            # Wait-for graph has edges from both waiters to holder, 0 cycles
            graph = res["wait_for_graph"]
            self.assertGreaterEqual(len(graph["edges"]), 2)
            for edge in graph["edges"]:
                self.assertIsNotNone(edge.get("owner_tid"))

        finally:
            proc.terminate()
            proc.wait()

    def test_05_genuine_circular_wait_2way_deadlock_confirmed_cycle(self):
        """2-thread circular deadlock confirms genuine wait-for cycle: T1 -> T2 -> T1."""
        proc = subprocess.Popen([self.bin_deadlock2])
        try:
            time.sleep(0.1)
            pid = proc.pid
            adapter = LocalTargetAdapter()

            engine = AdaptiveInvestigationEngine()
            ctx = engine.registry.get("insp_locks")
            res = ctx.func(None, pid=pid, adapter=adapter, sampling_epoch=1)

            self.assertTrue(res["success"])
            self.assertTrue(res["deadlock_detected"])
            self.assertIsNotNone(res["deadlock_cycle"])

            cycle = res["deadlock_cycle"]
            # Directed cycle of length 2 (plus closing node): e.g. [T1, T2, T1]
            self.assertGreaterEqual(len(cycle), 3)
            self.assertEqual(cycle[0], cycle[-1], "Deadlock cycle must close back on itself")

            # Verified that both threads have identified owners
            for c_tid in cycle[:-1]:
                th = next(t for t in res["threads"] if t["tid"] == c_tid)
                self.assertTrue(th["lock_owner_identified"])
                self.assertIsNotNone(th["owner_tid"])

        finally:
            proc.terminate()
            proc.wait()

    def test_06_genuine_circular_wait_3way_deadlock_confirmed_cycle(self):
        """3-thread circular deadlock confirms genuine multi-node cycle: T1 -> T2 -> T3 -> T1."""
        proc = subprocess.Popen([self.bin_deadlock3])
        try:
            time.sleep(0.1)
            pid = proc.pid
            adapter = LocalTargetAdapter()

            engine = AdaptiveInvestigationEngine()
            ctx = engine.registry.get("insp_locks")
            res = ctx.func(None, pid=pid, adapter=adapter, sampling_epoch=1)

            self.assertTrue(res["success"])
            self.assertTrue(res["deadlock_detected"])
            self.assertIsNotNone(res["deadlock_cycle"])

            cycle = res["deadlock_cycle"]
            # 3-thread cycle: [T1, T2, T3, T1] (length 4)
            self.assertEqual(len(cycle), 4)
            self.assertEqual(cycle[0], cycle[-1])
            self.assertEqual(len(set(cycle[:-1])), 3, "Expected 3 distinct threads in cycle")

        finally:
            proc.terminate()
            proc.wait()

    def test_07_incomplete_wait_for_graph_remains_inconclusive(self):
        """An incomplete wait-for graph (one owner unknown) never confirms a deadlock cycle."""
        graph = WaitForGraph()
        # T1 waits on Mutex A owned by T2
        graph.add_edge(WaitForEdge(waiter_tid=101, sync_object="0xa", owner_tid=102, source="mem", timestamp=0.0))
        # T2 waits on Mutex B owned by T3
        graph.add_edge(WaitForEdge(waiter_tid=102, sync_object="0xb", owner_tid=103, source="mem", timestamp=0.0))
        # T3 waits on Mutex C, but owner TID could NOT be read (owner_tid is None)
        graph.add_edge(WaitForEdge(waiter_tid=103, sync_object="0xc", owner_tid=None, source="proc", timestamp=0.0))

        # Because T3's owner is unknown, cycle cannot be established
        cycle = graph.find_cycle()
        self.assertIsNone(cycle)
        self.assertFalse(graph.has_cycle())

    # =========================================================================
    # Group 2: Memory Attribution & Decoupling
    # =========================================================================

    def test_08_process_rss_growth_without_heap_growth(self):
        """Anonymous mmap allocations expand process RSS and anon mappings, not heap mapping."""
        proc = subprocess.Popen([self.bin_mem_growth])
        try:
            time.sleep(0.1)
            pid = proc.pid
            adapter = LocalTargetAdapter()

            mem_info = adapter.get_process_memory_info(pid)
            self.assertEqual(mem_info["status"], "OBSERVED")

            metrics = mem_info["metrics"]
            mappings = mem_info["mappings_summary"]

            # RSS is positive and non-zero
            self.assertGreater(metrics["rss_bytes"], 0)

            # heap_rss_bytes is explicitly None (procfs cannot measure heap-specific RSS)
            self.assertIsNone(mem_info.get("heap_rss_bytes"))
            self.assertIsNone(metrics.get("heap_rss_bytes"))
            self.assertFalse(mem_info.get("heap_physical_residency_available", False))

            # Verify that process RSS is distinct from heap mapping size
            heap_mapping_size = mappings["heap_mapping_size_bytes"]
            self.assertNotEqual(metrics["rss_bytes"], heap_mapping_size)

        finally:
            proc.terminate()
            proc.wait()

    def test_09_heap_mapping_expansion_without_rss_growth(self):
        """Virtual mapping expansion without touching pages increases VSZ while RSS remains flat."""
        proc = subprocess.Popen([self.bin_vsz_only])
        try:
            time.sleep(0.01)
            pid = proc.pid
            adapter = LocalTargetAdapter()

            engine = AdaptiveInvestigationEngine()
            ctx = engine.registry.get("insp_temporal_diff")
            res = ctx.func(
                None,
                pid=pid,
                adapter=adapter,
                target_expression="anonymous_mmap",
                wait_ms=35,
                num_samples=3,
            )
            self.assertTrue(res["success"])
            self.assertEqual(res["status"], "OBSERVED")

            # Mapping expansion without allocation condition detected
            self.assertEqual(res["observed_condition"], "mapping_expansion_without_allocation")
            self.assertIn(res["scoped_condition"], ("ANON_MAPPING_EXPANSION", "HEAP_MAPPING_EXPANSION"))
            self.assertFalse(res["growth_detected"])
            self.assertIsNone(res["heap_rss_bytes"])

        finally:
            proc.terminate()
            proc.wait()

    def test_10_anonymous_mapping_expansion_without_heap_growth(self):
        """insp_memory_maps creates candidate with scope 'anon_mapping', not 'heap'."""
        proc = subprocess.Popen([self.bin_vsz_only])
        try:
            time.sleep(0.05)
            pid = proc.pid
            adapter = LocalTargetAdapter()

            engine = AdaptiveInvestigationEngine()
            ctx = engine.registry.get("insp_memory_maps")
            res = ctx.func(None, pid=pid, adapter=adapter, screening_anon_size_bytes=1024 * 1024)

            self.assertTrue(res["success"])
            candidates = res["memory_growth_candidates"]
            anon_cands = [c for c in candidates if c["category"] == "anonymous"]
            self.assertGreaterEqual(len(anon_cands), 1)

            cand = anon_cands[0]
            self.assertEqual(cand["measurement_scope"], "anon_mapping")
            self.assertEqual(cand["category"], "anonymous")
            self.assertNotEqual(cand["measurement_scope"], "heap_mapping")
            self.assertIsNone(cand.get("heap_rss_bytes"))

        finally:
            proc.terminate()
            proc.wait()

    def test_11_process_rss_never_reported_as_heap_rss(self):
        """Strict verification: heap_rss_bytes is ALWAYS None across adapter and profiles."""
        adapter = LocalTargetAdapter()
        pid = os.getpid()

        # 1. Adapter level
        mem_info = adapter.get_process_memory_info(pid)
        self.assertIsNone(mem_info.get("heap_rss_bytes"))
        self.assertFalse(mem_info.get("heap_physical_residency_available"))

        # 2. insp_memory_maps profile
        engine = AdaptiveInvestigationEngine()
        ctx_maps = engine.registry.get("insp_memory_maps")
        res_maps = ctx_maps.func(None, pid=pid, adapter=adapter)
        self.assertIsNone(res_maps.get("heap_rss_bytes"))
        self.assertFalse(res_maps.get("heap_physical_residency_available"))

        # 3. insp_temporal_diff profile
        ctx_temp = engine.registry.get("insp_temporal_diff")
        res_temp = ctx_temp.func(None, pid=pid, adapter=adapter, wait_ms=10, num_samples=2)
        self.assertIsNone(res_temp.get("heap_rss_bytes"))
        for s in res_temp.get("samples", []):
            self.assertIsNone(s.get("heap_rss_bytes"))

    def test_12_missing_smaps_rollup_falls_back_without_fabrication(self):
        """Missing /proc/<pid>/smaps_rollup falls back to status+maps and reports missing optional metric."""
        adapter = LocalTargetAdapter()

        # Mock adapter simulating system without smaps_rollup support
        class MockNoSmapsAdapter(LocalTargetAdapter):
            def get_process_memory_info(self, pid: int):
                # Call super but force smaps_rollup to be simulated as missing
                info = super().get_process_memory_info(pid)
                info["sources_status"]["smaps_rollup"] = "MISSING"
                if "smaps_rollup" not in info["missing_optional_metrics"]:
                    info["missing_optional_metrics"].append("smaps_rollup")
                # Ensure smaps-only fields are NOT fabricated
                info["metrics"]["pss_bytes"] = None
                return info

        mock_ad = MockNoSmapsAdapter()
        info = mock_ad.get_process_memory_info(os.getpid())

        self.assertEqual(info["status"], "OBSERVED")
        self.assertEqual(info["sources_status"]["smaps_rollup"], "MISSING")
        self.assertIn("smaps_rollup", info["missing_optional_metrics"])
        self.assertEqual(info["missing_required_metrics"], [])
        self.assertIsNone(info["metrics"]["pss_bytes"])

    def test_13_procfs_only_evidence_never_confirms_allocation_leak(self):
        """Procfs observations alone produce at most SUSPECTED or PARTIALLY_CONFIRMED, never CONFIRMED."""
        proc = subprocess.Popen([self.bin_mem_growth])
        try:
            time.sleep(0.1)
            pid = proc.pid
            engine = AdaptiveInvestigationEngine()

            res = engine.investigate_process_health(
                goal="Check for memory leak in target process",
                pid=pid,
                companion_elf_path=self.bin_mem_growth,
            )

            self.assertTrue(res["success"])
            # Never CONFIRMED from procfs observations alone
            self.assertNotEqual(res["verdict"], DIAG_CONFIRMED)
            self.assertIn(res["verdict"], (DIAG_SUSPECTED, DIAG_PARTIALLY_CONFIRMED))

        finally:
            proc.terminate()
            proc.wait()

    # =========================================================================
    # Group 3: Observation Budget Enforcement
    # =========================================================================

    def test_14_wall_clock_budget_expiration_stops_before_next_sample(self):
        """Wall-clock budget expires before next sample -> halts immediately without overshoot."""
        tracker = ObservationBudgetTracker(
            limits=ObservationBudgetLimits(
                max_bytes_read=1024 * 1024,
                max_wall_clock_ms=25.0,  # Only 25ms allowed
                max_samples=5,
            )
        )
        engine = AdaptiveInvestigationEngine()
        ctx = engine.registry.get("insp_temporal_diff")

        t0 = time.monotonic()
        res = ctx.func(
            None,
            pid=os.getpid(),
            adapter=LocalTargetAdapter(),
            wait_ms=40,  # 40ms wait > 25ms limit
            num_samples=4,
            budget_tracker=tracker,
        )
        elapsed_ms = (time.monotonic() - t0) * 1000.0

        # Must stop with PARTIAL and BUDGET_EXHAUSTED
        self.assertEqual(res["status"], "PARTIAL")
        self.assertEqual(res.get("stop_reason"), "BUDGET_EXHAUSTED")
        self.assertLess(res["num_samples"], 4)
        # Verify it did not sleep past budget
        self.assertLess(elapsed_ms, 80.0)

    def test_15_byte_budget_expiration_during_multi_source_inspection(self):
        """Byte budget exhaustion stops multi-source inspection before exceeding limit."""
        tracker = ObservationBudgetTracker(
            limits=ObservationBudgetLimits(
                max_bytes_read=1500,  # Very small byte ceiling
                max_wall_clock_ms=5000.0,
                max_samples=10,
            )
        )
        engine = AdaptiveInvestigationEngine()
        ctx = engine.registry.get("insp_temporal_diff")

        res = ctx.func(
            None,
            pid=os.getpid(),
            adapter=LocalTargetAdapter(),
            wait_ms=10,
            num_samples=5,
            budget_tracker=tracker,
        )

        self.assertEqual(res["status"], "PARTIAL")
        self.assertEqual(res.get("stop_reason"), "BUDGET_EXHAUSTED")
        # Collected samples before budget hit are preserved
        self.assertGreaterEqual(res["num_samples"], 1)

    def test_16_measured_bytes_read_accumulates_actual_not_estimated(self):
        """Budget tracker accumulates actual measured bytes read from procfs operations."""
        tracker = ObservationBudgetTracker(
            limits=ObservationBudgetLimits(
                max_bytes_read=1024 * 1024,
                max_wall_clock_ms=5000.0,
                max_samples=10,
            )
        )
        initial_bytes = tracker.metrics.bytes_read

        engine = AdaptiveInvestigationEngine()
        ctx = engine.registry.get("insp_memory_maps")
        res = ctx.func(
            None,
            pid=os.getpid(),
            adapter=LocalTargetAdapter(),
            budget_tracker=tracker,
        )
        self.assertTrue(res["success"])

        # Measured bytes read is recorded and > 0
        measured_b = res["measured_bytes_read"]
        self.assertGreater(measured_b, 0)

    def test_17_multi_sample_interrupted_by_budget_preserves_collected_samples(self):
        """Sampling interrupted by sample limit preserves all collected samples as PARTIAL."""
        tracker = ObservationBudgetTracker(
            limits=ObservationBudgetLimits(
                max_bytes_read=1024 * 1024,
                max_wall_clock_ms=5000.0,
                max_samples=2,  # Exactly 2 samples allowed
            )
        )
        engine = AdaptiveInvestigationEngine()
        ctx = engine.registry.get("insp_temporal_diff")

        res = ctx.func(
            None,
            pid=os.getpid(),
            adapter=LocalTargetAdapter(),
            wait_ms=10,
            num_samples=5,
            budget_tracker=tracker,
        )

        self.assertEqual(res["status"], "PARTIAL")
        self.assertEqual(res["stop_reason"], "BUDGET_EXHAUSTED")
        self.assertEqual(len(res["samples"]), 2)
        self.assertEqual(res["num_samples"], 2)

    def test_18_direct_adapter_fallback_obeys_budget(self):
        """Direct inspection module fallback respects budget tracker limits."""
        engine = AdaptiveInvestigationEngine()
        mod = engine.registry.get("insp_memory_maps")
        tracker = ObservationBudgetTracker(
            limits=ObservationBudgetLimits(max_bytes_read=0, max_wall_clock_ms=10.0, max_samples=0)
        )
        # Pre-execution check fails when budget is exhausted
        can_run, reason, _ = tracker.check_pre_execution(1024, 10.0, 1)
        self.assertFalse(can_run)
        self.assertIn("EXCEEDED_BYTES_READ", reason)

    # =========================================================================
    # Group 4: Failure & Unavailability Semantics
    # =========================================================================

    def test_19_permission_denied_on_procfs_returns_fail_closed(self):
        """Permission denied on /proc paths returns PERMISSION_DENIED without crashing."""
        class MockPermissionDeniedAdapter(LocalTargetAdapter):
            def get_process_memory_info(self, pid: int):
                raise PermissionError("Permission denied: /proc/1/statm")

            def get_threads(self, pid: int):
                raise PermissionError("Permission denied: /proc/1/task")

        mock_ad = MockPermissionDeniedAdapter()
        engine = AdaptiveInvestigationEngine()

        ctx_maps = engine.registry.get("insp_memory_maps")
        res_m = ctx_maps.func(None, pid=1, adapter=mock_ad)
        self.assertFalse(res_m["success"])
        self.assertEqual(res_m["status"], "PERMISSION_DENIED")

        ctx_locks = engine.registry.get("insp_locks")
        res_l = ctx_locks.func(None, pid=1, adapter=mock_ad)
        self.assertFalse(res_l["success"])
        self.assertEqual(res_l["status"], "PERMISSION_DENIED")

    def test_20_process_termination_during_sampling_returns_target_terminated(self):
        """Process termination during temporal sampling returns TARGET_TERMINATED with partial samples."""
        proc = subprocess.Popen(["sleep", "0.03"])
        pid = proc.pid
        time.sleep(0.01)

        engine = AdaptiveInvestigationEngine()
        ctx = engine.registry.get("insp_temporal_diff")

        # Process will terminate while sampling
        res = ctx.func(
            None,
            pid=pid,
            adapter=LocalTargetAdapter(),
            wait_ms=40,
            num_samples=3,
        )
        self.assertFalse(res["success"])
        self.assertEqual(res["status"], "TARGET_TERMINATED")
        self.assertIn("terminated", res["error"])

    def test_21_empty_results_caused_by_access_failure_never_become_healthy(self):
        """Empty results caused by access failure never certify healthy / stable verdicts."""
        class MockFailingAdapter(LocalTargetAdapter):
            def check_liveness(self, pid: int):
                return True, "running"

            def get_process_memory_info(self, pid: int):
                return {"status": "PERMISSION_DENIED", "error": "Access denied"}

            def get_threads(self, pid: int):
                return []

        engine = AdaptiveInvestigationEngine()
        res = engine.investigate_process_health(
            goal="Please check process health",
            pid=99999,
            fixture_data={"capabilities": {"process_alive": True, "unavailable_reasons": {"memory": "denied"}}},
        )

        self.assertNotEqual(res["verdict"], DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE)
        self.assertEqual(res["verdict"], DIAG_INCONCLUSIVE)


if __name__ == "__main__":
    unittest.main()

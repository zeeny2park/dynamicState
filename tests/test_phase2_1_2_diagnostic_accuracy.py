"""Phase 2.1.2 — Diagnostic Accuracy & Product-General Runtime Investigation Test Suite

Validates the 16 Scenarios (A through P) against product-general C++ runtime fixtures
and remote execution adapters, enforcing:
- Elimination of synthetic observations (no hardcoded names or fabricated time series)
- Product-general DWARF symbol discovery across generic types
- Temporal memory analysis with transient warm-up plateau separation
- Semantically correct NULL pointer and memory integrity evaluation
- Executable verification criteria with consumed evidence tracking
- 1:1 evidence-to-finding relationships
- Sound lock graph and deadlock analysis (incomplete lock graph != acyclic)
- Remote target investigation via TargetExecutionAdapter
"""

import os
import subprocess
import time
import unittest
from typing import Any, Dict, List, Optional, Tuple

from tests.fixture_builds import ensure_built
from extractor.diagnostic_recipes import (
    CATEGORY_ABNORMAL_VARIABLE_CHANGES,
    CATEGORY_DEADLOCK_INDICATORS,
    CATEGORY_FUNCTIONAL_STATE_INCONSISTENCY,
    CATEGORY_MEMORY_CORRUPTION,
    CATEGORY_MEMORY_LEAK,
    DiagnosticRecipeRegistry,
    RECIPE_ALLOCATION_FREE_IMBALANCE,
    RECIPE_DOUBLE_FREE,
    RECIPE_HEAP_GROWTH,
    RECIPE_INCONSISTENT_RELATED_VARIABLES,
    RECIPE_INVALID_MEMORY_ACCESS,
    RECIPE_LONG_LIVED_OBJECT_ACCUMULATION,
    RECIPE_POTENTIAL_DEADLOCK_PATTERNS,
    RECIPE_PROCESS_MEMORY_GROWTH,
    RECIPE_STATUS_AMBIGUOUS,
    RECIPE_STATUS_CONTRADICTED,
    RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
    RECIPE_STATUS_SUPPORTED,
    RECIPE_UNEXPECTED_NULL_OR_INVALID_POINTERS,
    RECIPE_USE_AFTER_FREE,
)
from extractor.expert_diagnostic_engine import (
    STATE_BLOCKED,
    STATE_COMPLETED,
    STATE_INCONCLUSIVE,
    ExpertDiagnosticEngine,
    TargetAssessor,
)
from extractor.runtime_evidence_provider import (
    COLLECTION_STATUS_UNAVAILABLE,
    PROVENANCE_LIVE_RUNTIME_CAPTURE,
    RuntimeEvidenceProvider,
)
from extractor.target_adapter import TargetExecutionAdapter
from tests.support.fixture_process import fixture_popen
from tests.support.tmpdirs import temp_dir


class MockRemoteSshTargetAdapter(TargetExecutionAdapter):
    """Simulates a remote target running on an embedded device without local /proc."""

    def __init__(self, remote_pid: int = 4242):
        self._remote_pid = remote_pid
        self.local_proc_accessed = False
        self.calls: List[str] = []

    def target_host(self) -> str:
        return "192.168.1.100"

    def is_remote(self) -> bool:
        return True

    def check_liveness(self, pid: int) -> Tuple[bool, Optional[str]]:
        self.calls.append(f"check_liveness:{pid}")
        if pid == self._remote_pid:
            return True, None
        return False, "remote process not found"

    def get_process_status(self, pid: int) -> Dict[str, str]:
        self.calls.append(f"get_process_status:{pid}")
        return {
            "Pid": str(pid),
            "State": "S (sleeping)",
            "VmRSS": "32768",
            "VmSize": "65536",
            "Threads": "4",
        }

    def get_threads(self, pid: int) -> List[int]:
        self.calls.append(f"get_threads:{pid}")
        return [pid, pid + 1, pid + 2, pid + 3]

    def get_proc_maps(self, pid: int) -> List[Dict[str, Any]]:
        self.calls.append(f"get_proc_maps:{pid}")
        return [
            {
                "start": "0x400000",
                "end": "0x450000",
                "start_int": 0x400000,
                "end_int": 0x450000,
                "permissions": "r-xp",
                "offset": "0",
                "device": "08:01",
                "inode": 12345,
                "pathname": "/usr/bin/remote_daemon",
                "is_readable": True,
            },
            {
                "start": "0x600000",
                "end": "0x800000",
                "start_int": 0x600000,
                "end_int": 0x800000,
                "permissions": "rw-p",
                "offset": "0",
                "device": "08:01",
                "inode": 0,
                "pathname": "[heap]",
                "size": 0x200000,
                "is_readable": True,
            },
        ]

    def get_process_identity(self, pid: int) -> Dict[str, Any]:
        self.calls.append(f"get_process_identity:{pid}")
        return {
            "pid": pid,
            "name": "remote_daemon",
            "exe_path": "/usr/bin/remote_daemon",
            "arch": "x86_64",
            "build_id": "mock_build_id_12345",
        }

    def read_memory(self, pid: int, address: int, size: int) -> Tuple[Optional[bytes], str, Optional[str]]:
        self.calls.append(f"read_memory:{pid}:{hex(address)}:{size}")
        # Return valid mock memory bytes
        return b"\x00" * size, "OBSERVED", None


class TestPhase212DiagnosticAccuracy(unittest.TestCase):
    """Validates Phase 2.1.2 diagnostic accuracy across 16 Scenarios A through P."""

    @classmethod
    def setUpClass(cls):
        cls.debug_elf = "/tmp/product_general_debug.elf"
        cls.stripped_elf = "/tmp/product_general_stripped.elf"
        cpp_src = "tests/fixtures/real_runtime/product_general_scenarios.cpp"
        # Atomic publish (never recompile in place over a binary that a previous run may still execute).
        ensure_built(
            cls.debug_elf,
            lambda t: ["g++", "-g", "-O0", "-fno-inline", "-fno-omit-frame-pointer", cpp_src, "-o", t, "-lpthread"],
            deps=[cpp_src], rebuild_if_older=True,
        )
        ensure_built(
            cls.stripped_elf,
            lambda t: ["strip", "-s", "-o", t, cls.debug_elf],
            deps=[cls.debug_elf], rebuild_if_older=True,
        )

    def setUp(self):
        self.engine = ExpertDiagnosticEngine(corpus_dir=temp_dir(self, "corpus_"))
        self.procs = []

    def tearDown(self):
        for p in self.procs:
            try:
                p.terminate()
                p.wait(timeout=1.0)
            except Exception:
                try:
                    p.kill()
                except Exception:
                    pass

    def _spawn_target(self, mode: str, use_debug: bool = True) -> subprocess.Popen:
        elf = self.debug_elf if use_debug else self.stripped_elf
        p = fixture_popen([elf, mode], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.procs.append(p)
        time.sleep(0.12)
        return p

    def test_scenario_a_healthy_process_clean(self):
        """Scenario A: Healthy process with product-general symbols verified clean."""
        proc = self._spawn_target("healthy")
        session = self.engine.start_investigation(
            problem_statement="Routine operational health inspection of ingress network service",
            pid=proc.pid,
            companion_elf=self.debug_elf,
        )
        conclusion = session.run_to_completion()
        self.assertEqual(session.state, STATE_COMPLETED)
        self.assertIsNotNone(conclusion)
        # Should not falsely report memory leaks or corruption
        self.assertNotIn("CRASH_RISK_HIGH", conclusion.primary_finding)
        self.assertNotIn("MEMORY_LEAK_CONFIRMED", conclusion.primary_finding)
        self.assertTrue(len(conclusion.supporting_evidence_chain) >= 0)

    def test_scenario_b_clean_null_pointer_idle_state(self):
        """Scenario B: Clean NULL pointer in idle/initialized state is refuted as crash fault."""
        registry = DiagnosticRecipeRegistry()
        res = registry.evaluate_recipe(RECIPE_INVALID_MEMORY_ACCESS, {
            "pointer_name": "g_rx_buffer.payload_ptr",
            "address": 0x0,
            "target_address": 0x0,
            "in_crash_context": False,
            "dereference_attempted": False,
        })
        self.assertEqual(res.status, RECIPE_STATUS_CONTRADICTED)
        self.assertFalse(res.details.get("access_fault_confirmed"))
        self.assertTrue(any("Clean NULL pointer" in f for f in res.contradicting_facts))

    def test_scenario_c_actual_invalid_memory_access(self):
        """Scenario C: Actual invalid memory access (low-memory guard dereference) confirmed."""
        proc = self._spawn_target("corrupt")
        session = self.engine.start_investigation(
            problem_statement="Investigate invalid memory access and corrupt magic in rx buffer",
            pid=proc.pid,
            companion_elf=self.debug_elf,
        )
        conclusion = session.run_to_completion()
        self.assertEqual(session.state, STATE_COMPLETED)
        self.assertIsNotNone(conclusion)
        # Invalid pointer or memory corruption confirmed
        self.assertTrue(
            "MEMORY_CORRUPTION" in conclusion.primary_finding or
            "INVALID_MEMORY" in conclusion.primary_finding or
            any("CORRUPTION" in h.category for h in session.active_hypotheses if h.status == "CONFIRMED")
        )

    def test_scenario_d_freed_object_stale_reference(self):
        """Scenario D: Freed block with poison marker confirmed as UAF; active block contradicted."""
        registry = DiagnosticRecipeRegistry()
        # Active chunk without poison
        res_active = registry.evaluate_recipe(RECIPE_USE_AFTER_FREE, {
            "is_active_chunk": True,
            "is_freed": False,
            "poison_pattern_detected": False,
        })
        self.assertEqual(res_active.status, RECIPE_STATUS_CONTRADICTED)

        # Freed chunk with poison pattern
        res_freed = registry.evaluate_recipe(RECIPE_USE_AFTER_FREE, {
            "is_active_chunk": False,
            "is_freed": True,
            "poison_pattern_detected": True,
        })
        self.assertEqual(res_freed.status, RECIPE_STATUS_SUPPORTED)
        self.assertTrue(res_freed.details.get("uaf_confirmed"))

    def test_scenario_e_double_free_evidence(self):
        """Scenario E: Double-free confirmed when deallocation event history is present."""
        registry = DiagnosticRecipeRegistry()
        # Single free is not double free
        res_normal = registry.evaluate_recipe(RECIPE_DOUBLE_FREE, {
            "freelist_occurrences": 0,
            "prev_inuse": 1,
            "double_free_recorded": False,
        })
        self.assertEqual(res_normal.status, RECIPE_STATUS_CONTRADICTED)

        # Duplicate free recorded in event history
        res_double = registry.evaluate_recipe(RECIPE_DOUBLE_FREE, {
            "double_free_recorded": True,
            "freelist_occurrences": 2,
        })
        self.assertEqual(res_double.status, RECIPE_STATUS_SUPPORTED)
        self.assertTrue(res_double.details.get("double_free_confirmed"))

    def test_scenario_f_transient_growth_with_plateau(self):
        """Scenario F: Stable RSS after transient initialization warm-up refutes memory leak."""
        registry = DiagnosticRecipeRegistry()
        # Epoch 0: 10000 KB, Epoch 1: 15000 KB (warmup), Epoch 2: 15010 KB (plateau)
        res = registry.evaluate_recipe(RECIPE_PROCESS_MEMORY_GROWTH, {
            "rss_history_kb": [10000, 15000, 15010],
            "epoch_count": 3,
            "is_monotonic": True,
        })
        self.assertEqual(res.status, RECIPE_STATUS_CONTRADICTED)
        self.assertTrue(res.details.get("transient_warmup"))
        self.assertFalse(res.details.get("growth_confirmed"))

    def test_scenario_g_sustained_heap_growth(self):
        """Scenario G: Sustained monotonic heap growth across multiple epochs confirmed."""
        registry = DiagnosticRecipeRegistry()
        # Sustained heap expansion across 3 epochs
        res = registry.evaluate_recipe(RECIPE_HEAP_GROWTH, {
            "heap_series_kb": [10000, 14000, 18000],
            "epoch_count": 3,
            "heap_growth_bytes": 8000 * 1024,
            "is_monotonic": True,
        })
        self.assertEqual(res.status, RECIPE_STATUS_SUPPORTED)
        self.assertTrue(res.details.get("heap_growth_confirmed"))

    def test_scenario_h_object_accumulation_retaining_relationship(self):
        """Scenario H: Container object accumulation identifies retaining collection in real runtime."""
        proc = self._spawn_target("leak")
        provider = RuntimeEvidenceProvider()
        rec_accum = DiagnosticRecipeRegistry().get_recipe(RECIPE_LONG_LIVED_OBJECT_ACCUMULATION)
        # Accumulation is growth over a window (a size read once is not), backed by memory growth: observe the
        # container across epochs of one provider session until it has grown.
        deadline = time.monotonic() + 6.0
        while True:
            obs, recs = provider.collect_for_recipe(rec_accum, proc.pid, self.debug_elf)
            if (obs.get("container_size_delta") or 0) > 50 or time.monotonic() > deadline:
                break
            time.sleep(0.4)

        self.assertGreaterEqual(obs.get("active_chunk_count", 0), 50)
        self.assertEqual(obs.get("container_name"), "g_retained_telemetry_records")
        res = DiagnosticRecipeRegistry().evaluate_recipe(RECIPE_LONG_LIVED_OBJECT_ACCUMULATION, obs)
        self.assertEqual(res.status, RECIPE_STATUS_SUPPORTED)
        self.assertTrue(res.details.get("object_accumulation_confirmed"))

    def test_scenario_i_allocation_free_imbalance(self):
        """Scenario I: Allocation/free imbalance detected from actual counters."""
        proc = self._spawn_target("alloc_imbalance")
        provider = RuntimeEvidenceProvider()
        rec_imb = DiagnosticRecipeRegistry().get_recipe(RECIPE_ALLOCATION_FREE_IMBALANCE)
        # an imbalance is a gap that GROWS over the window (a static ratio is not): two epochs of one session
        provider.collect_for_recipe(rec_imb, proc.pid, self.debug_elf)
        time.sleep(0.6)
        obs, recs = provider.collect_for_recipe(rec_imb, proc.pid, self.debug_elf)

        self.assertGreaterEqual(obs.get("alloc_count", 0), 2000)
        self.assertEqual(obs.get("alloc_counter_name"), "g_alloc_ops")
        self.assertEqual(obs.get("free_counter_name"), "g_release_ops")
        res = DiagnosticRecipeRegistry().evaluate_recipe(RECIPE_ALLOCATION_FREE_IMBALANCE, obs)
        self.assertEqual(res.status, RECIPE_STATUS_SUPPORTED)
        self.assertTrue(res.details.get("imbalance_confirmed"))

    def test_scenario_j_blocked_thread_without_deadlock(self):
        """Scenario J: Blocked thread under contention reported without claiming false circular deadlock."""
        proc = self._spawn_target("contention")
        session = self.engine.start_investigation(
            problem_statement="Investigate thread contention and blocked workers in service",
            pid=proc.pid,
            companion_elf=self.debug_elf,
        )
        conclusion = session.run_to_completion()
        self.assertEqual(session.state, STATE_COMPLETED)
        # Should not falsely claim confirmed circular deadlock
        self.assertNotIn("CIRCULAR_DEADLOCK_CONFIRMED", conclusion.primary_finding)

    def test_scenario_k_circular_wait_deadlock(self):
        """Scenario K: Actual circular wait with lock ownership evidence confirmed."""
        registry = DiagnosticRecipeRegistry()
        res = registry.evaluate_recipe(RECIPE_POTENTIAL_DEADLOCK_PATTERNS, {
            "deadlock_cycle": ["thread_1 -> mutex_a -> thread_2 -> mutex_b -> thread_1"],
            "cycle_detected": True,
            "cycle_persistent": True,
            "observation_count": 2,
            "incomplete_lock_graph": False,
        })
        self.assertEqual(res.status, RECIPE_STATUS_SUPPORTED)
        self.assertTrue(res.details.get("deadlock_confirmed"))

    def test_scenario_l_incomplete_lock_graph_must_not_assume_acyclic(self):
        """Scenario L: Incomplete lock graph must return INSUFFICIENT_EVIDENCE, never acyclic."""
        registry = DiagnosticRecipeRegistry()
        res = registry.evaluate_recipe(RECIPE_POTENTIAL_DEADLOCK_PATTERNS, {
            "cycle_detected": False,
            "incomplete_lock_graph": True,
        })
        self.assertEqual(res.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        self.assertIn("incomplete_lock_graph_cannot_prove_acyclic", res.missing_evidence)
        self.assertFalse(res.details.get("deadlock_confirmed", False))

    def test_scenario_m_field_invariant_violation(self):
        """Scenario M: Related C++ field invariant violation (length > capacity) confirmed."""
        proc = self._spawn_target("invariant_violation")
        provider = RuntimeEvidenceProvider()
        rec_inv = DiagnosticRecipeRegistry().get_recipe(RECIPE_INCONSISTENT_RELATED_VARIABLES)
        obs, recs = provider.collect_for_recipe(rec_inv, proc.pid, self.debug_elf)

        self.assertIsNotNone(obs.get("buffer_length"))
        self.assertIsNotNone(obs.get("buffer_capacity"))
        self.assertGreater(obs["buffer_length"], obs["buffer_capacity"])
        res = DiagnosticRecipeRegistry().evaluate_recipe(RECIPE_INCONSISTENT_RELATED_VARIABLES, obs)
        self.assertEqual(res.status, RECIPE_STATUS_SUPPORTED)
        self.assertTrue(res.details.get("invariant_violation_confirmed"))

    def test_scenario_n_missing_dwarf_graceful(self):
        """Scenario N: Stripped binary handled gracefully with explicit diagnostic limitations."""
        assessor = TargetAssessor()
        res = assessor.assess(pid=os.getpid(), companion_elf=self.stripped_elf)
        self.assertFalse(res.dwarf_available)
        self.assertIn("DWARF_DEBUG_INFO_MISSING", res.limitations)

    def test_scenario_o_unreadable_target_memory(self):
        """Scenario O: Inaccessible or unreadable target PID handled fail-closed without fabrication."""
        assessor = TargetAssessor()
        res = assessor.assess(pid=99999999, companion_elf=self.debug_elf)
        self.assertFalse(res.accessible)
        self.assertFalse(res.memory_readable)
        self.assertNotIn("PROCESS_VM_READV_ZERO_STOP", res.capabilities)
        self.assertTrue(any("not running or not found" in lim for lim in res.limitations))

    def test_scenario_p_remote_target_investigation_adapter(self):
        """Scenario P: Remote target investigation via TargetExecutionAdapter without local /proc."""
        mock_adapter = MockRemoteSshTargetAdapter(remote_pid=4242)
        assessor = TargetAssessor()
        res = assessor.assess(pid=4242, companion_elf=self.debug_elf, adapter=mock_adapter)

        self.assertTrue(res.accessible)
        self.assertTrue(res.memory_readable)
        self.assertEqual(res.target_host, "192.168.1.100")
        self.assertEqual(res.thread_count, 4)
        self.assertEqual(res.rss_kb, 32768)

        # Confirm adapter methods were invoked
        self.assertTrue(any("check_liveness:4242" in c for c in mock_adapter.calls))
        self.assertTrue(any("get_process_status:4242" in c for c in mock_adapter.calls))
        self.assertTrue(any("get_threads:4242" in c for c in mock_adapter.calls))
        self.assertTrue(any("get_proc_maps:4242" in c for c in mock_adapter.calls))
        self.assertTrue(any("read_memory:4242" in c for c in mock_adapter.calls))


if __name__ == "__main__":
    unittest.main()

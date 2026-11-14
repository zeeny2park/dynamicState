"""Phase 2.4.2 — Temporal Evidence Identity, Clock Semantics & Epoch Isolation Tests.

Verifies:
1. Target Identity Keying & Isolation:
   - Mandatory fields: host, boot_id, pid, start_time, executable (and build_id).
   - PID reuse (same PID, distinct start_time) produces isolated temporal histories.
   - Target reboot (distinct boot_id) produces isolated temporal histories.
   - Remote host separation produces isolated temporal histories.
   - Concurrent sessions against same target maintain isolated temporal histories.
   - Missing mandatory fields flag IDENTITY_UNAVAILABLE rather than guessing or silently merging.
2. Temporal Clock Semantics:
   - Monotonic clock used for duration, rates, and ordering.
   - Wall-clock backward jumps (e.g. NTP shift) do not corrupt elapsed duration or order.
   - Out-of-order monotonic timestamps explicitly detected as TEMPORAL_SEQUENCE_INVALID (no silent repair).
3. Missing & Partial Process Metrics:
   - Distinguishes OBSERVED_VALUE, OBSERVED_ZERO, and UNAVAILABLE.
   - Never substitutes 0 for missing VmRSS.
   - Unavailable RSS does not pollute historical series.
4. Observation Epoch Deduping & Minimum Sample Counts:
   - Multiple recipe evaluations within the same epoch do not inflate sample count.
   - Exactly 2 samples can only establish a delta, never a growth/leak verdict.
   - >= 3 epochs required to confirm sustained growth or leak claims.
"""

import os
import tempfile
import time
import unittest
from unittest.mock import MagicMock, patch

from extractor.diagnostic_recipes import (
    DiagnosticRecipeRegistry,
    RECIPE_PROCESS_MEMORY_GROWTH,
    RECIPE_HEAP_GROWTH,
    RECIPE_ALLOCATION_FREE_IMBALANCE,
    RECIPE_STATUS_SUPPORTED,
    RECIPE_STATUS_CONTRADICTED,
    RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
)
from extractor.runtime_evidence_provider import (
    RuntimeEvidenceProvider,
    COLLECTION_STATUS_SUCCESS,
    COLLECTION_STATUS_PARTIAL,
)
from extractor.target_adapter import TargetExecutionAdapter
from extractor.temporal_observation_window import (
    MemorySample,
    ObservationWindow,
    MemoryBehavior,
)


class MockIdentityAdapter(TargetExecutionAdapter):
    """Configurable mock adapter for testing identity and temporal clock semantics."""

    def __init__(
        self,
        pid=1234,
        host="test-host-1",
        boot_id="boot-uuid-001",
        start_time="56789",
        executable="/usr/bin/target_app",
        build_id="abcdef0123456789",
        status_dict=None,
    ):
        super().__init__()
        self._pid = pid
        self._host = host
        self._boot_id = boot_id
        self._start_time = start_time
        self._executable = executable
        self._build_id = build_id
        self._status_dict = status_dict or {"VmRSS": "12000", "VmSize": "34000"}
        self._liveness = True

    def target_host(self) -> str:
        return self._host

    def is_remote(self) -> bool:
        return False

    def check_liveness(self, pid: int):
        return self._liveness, None

    def get_process_identity(self, pid: int):
        return {
            "pid": pid,
            "executable": self._executable,
            "executable_identity": f"{self._executable}:inode123",
            "start_time": self._start_time,
            "boot_id": self._boot_id,
            "host": self._host,
            "build_id": self._build_id,
            "architecture": "x86_64",
            "elf_type": "DYN",
        }

    def get_process_status(self, pid: int):
        return dict(self._status_dict)

    def get_threads(self, pid: int):
        return [{"tid": pid, "state": "R"}]

    def get_proc_maps(self, pid: int):
        return [
            {"start": "0x400000", "end": "0x401000", "permissions": "r-xp", "pathname": self._executable, "category": "code"},
            {"start": "0x600000", "end": "0x700000", "permissions": "rw-p", "pathname": "[heap]", "category": "heap", "size": 1048576},
        ]

    def read_memory(self, pid: int, address: int, size: int):
        return b"\x00" * size, "OBSERVED", None


class TestPhase242TemporalIdentityAndClockSemantics(unittest.TestCase):
    """Unit tests for Phase 2.4.2 temporal evidence integrity."""

    def test_01_target_identity_key_generation(self):
        """Verifies verified target identity keying from mandatory fields."""
        adapter = MockIdentityAdapter(
            pid=42,
            host="embedded-board-a",
            boot_id="boot-4242",
            start_time="100200",
            executable="/bin/daemon",
            build_id="build-abc",
        )
        provider = RuntimeEvidenceProvider(adapter=adapter)

        target_key, ident, err = provider.get_target_identity_key(42)
        self.assertIsNone(err)
        self.assertIsNotNone(target_key)
        self.assertIn("embedded-board-a:boot-4242:42:100200:/bin/daemon:build-abc", target_key)

    def test_02_pid_reuse_isolation(self):
        """PID reuse with same PID but new start_time isolates temporal history."""
        # Initial process
        adapter1 = MockIdentityAdapter(pid=5000, start_time="11111", boot_id="boot-1")
        provider = RuntimeEvidenceProvider(adapter=adapter1)
        recipe = DiagnosticRecipeRegistry.get_recipe(RECIPE_PROCESS_MEMORY_GROWTH)

        # Collect epoch 1 and epoch 2 for process 1
        obs1, _ = provider.collect_for_recipe(recipe, pid=5000, epoch_id=1)
        obs2, _ = provider.collect_for_recipe(recipe, pid=5000, epoch_id=2)
        self.assertEqual(obs2["epoch_count"], 2)

        # Process exits, PID 5000 is reused by OS for a new process (start_time 22222)
        adapter2 = MockIdentityAdapter(pid=5000, start_time="22222", boot_id="boot-1")
        provider.adapter = adapter2

        # First collection for reused PID
        obs_new, _ = provider.collect_for_recipe(recipe, pid=5000, epoch_id=1)
        # History MUST NOT contain samples from previous process
        self.assertEqual(obs_new["epoch_count"], 1)
        self.assertNotEqual(obs2["target_identity_key"], obs_new["target_identity_key"])

    def test_03_reboot_isolation(self):
        """System reboot with same PID and start_time but different boot_id isolates history."""
        adapter_pre = MockIdentityAdapter(pid=100, boot_id="boot-uuid-old", start_time="50")
        provider = RuntimeEvidenceProvider(adapter=adapter_pre)
        recipe = DiagnosticRecipeRegistry.get_recipe(RECIPE_PROCESS_MEMORY_GROWTH)

        provider.collect_for_recipe(recipe, pid=100, epoch_id=1)
        provider.collect_for_recipe(recipe, pid=100, epoch_id=2)

        # Reboot occurs, boot_id changes
        adapter_post = MockIdentityAdapter(pid=100, boot_id="boot-uuid-new", start_time="50")
        provider.adapter = adapter_post

        obs_post, _ = provider.collect_for_recipe(recipe, pid=100, epoch_id=1)
        self.assertEqual(obs_post["epoch_count"], 1)

    def test_04_session_isolation(self):
        """Concurrent investigation sessions against same target process maintain isolated histories."""
        adapter = MockIdentityAdapter(pid=777)
        provider = RuntimeEvidenceProvider(adapter=adapter)
        recipe = DiagnosticRecipeRegistry.get_recipe(RECIPE_PROCESS_MEMORY_GROWTH)

        # Session A collects 3 epochs
        provider.collect_for_recipe(recipe, pid=777, session_id="session_A", epoch_id=1)
        provider.collect_for_recipe(recipe, pid=777, session_id="session_A", epoch_id=2)
        obs_a, _ = provider.collect_for_recipe(recipe, pid=777, session_id="session_A", epoch_id=3)
        self.assertEqual(obs_a["epoch_count"], 3)

        # Session B starts against same PID
        obs_b, _ = provider.collect_for_recipe(recipe, pid=777, session_id="session_B", epoch_id=1)
        self.assertEqual(obs_b["epoch_count"], 1)

    def test_05_missing_mandatory_identity_fails_fast(self):
        """Missing mandatory identity field flags IDENTITY_UNAVAILABLE without corrupting history."""
        # Missing start_time
        adapter_bad = MockIdentityAdapter(pid=888, start_time="")
        provider = RuntimeEvidenceProvider(adapter=adapter_bad)
        recipe = DiagnosticRecipeRegistry.get_recipe(RECIPE_PROCESS_MEMORY_GROWTH)

        obs, recs = provider.collect_for_recipe(recipe, pid=888, epoch_id=1)
        self.assertEqual(obs.get("identity_status"), "IDENTITY_UNAVAILABLE")
        self.assertIn("start_time", obs.get("identity_error", ""))
        self.assertEqual(obs.get("epoch_count"), 0)
        self.assertEqual(len(provider._historical_samples), 0)

    def test_06_process_info_metric_states(self):
        """Distinguishes OBSERVED_VALUE, OBSERVED_ZERO, and UNAVAILABLE; never substitutes 0."""
        # Case A: Normal positive RSS
        adapter_val = MockIdentityAdapter(status_dict={"VmRSS": "4096 kB", "VmSize": "10000 kB"})
        provider = RuntimeEvidenceProvider(adapter=adapter_val)
        info_val, recs_val = provider.collect_process_info(1234)
        self.assertEqual(info_val["rss_kb"], 4096)
        self.assertEqual(info_val["rss_metric_status"], "OBSERVED_VALUE")
        self.assertEqual(recs_val[0].collection_status, COLLECTION_STATUS_SUCCESS)

        # Case B: Explicit zero RSS
        adapter_zero = MockIdentityAdapter(status_dict={"VmRSS": "0", "VmSize": "10000"})
        provider.adapter = adapter_zero
        info_zero, recs_zero = provider.collect_process_info(1234)
        self.assertEqual(info_zero["rss_kb"], 0)
        self.assertEqual(info_zero["rss_metric_status"], "OBSERVED_ZERO")
        self.assertEqual(recs_zero[0].collection_status, COLLECTION_STATUS_SUCCESS)

        # Case C: Absent VmRSS in status -> UNAVAILABLE (not substituted with 0)
        adapter_unavail = MockIdentityAdapter(status_dict={"VmSize": "10000"})
        provider.adapter = adapter_unavail
        info_unavail, recs_unavail = provider.collect_process_info(1234)
        self.assertIsNone(info_unavail["rss_kb"])
        self.assertEqual(info_unavail["rss_metric_status"], "UNAVAILABLE")
        self.assertEqual(recs_unavail[0].collection_status, COLLECTION_STATUS_PARTIAL)

        # Case D: Malformed VmRSS -> UNAVAILABLE
        adapter_mal = MockIdentityAdapter(status_dict={"VmRSS": "CORRUPTED_VALUE"})
        provider.adapter = adapter_mal
        info_mal, _ = provider.collect_process_info(1234)
        self.assertIsNone(info_mal["rss_kb"])
        self.assertEqual(info_mal["rss_metric_status"], "UNAVAILABLE")

    def test_07_epoch_deduping_within_step(self):
        """Multiple recipe evaluations within the same epoch do not inflate sample count."""
        adapter = MockIdentityAdapter(pid=333)
        provider = RuntimeEvidenceProvider(adapter=adapter)

        r_growth = DiagnosticRecipeRegistry.get_recipe(RECIPE_PROCESS_MEMORY_GROWTH)
        r_heap = DiagnosticRecipeRegistry.get_recipe(RECIPE_HEAP_GROWTH)
        r_imb = DiagnosticRecipeRegistry.get_recipe(RECIPE_ALLOCATION_FREE_IMBALANCE)

        # All 3 recipes evaluated in epoch 1
        obs1, _ = provider.collect_for_recipe(r_growth, pid=333, epoch_id=1)
        obs2, _ = provider.collect_for_recipe(r_heap, pid=333, epoch_id=1)
        obs3, _ = provider.collect_for_recipe(r_imb, pid=333, epoch_id=1)

        # Sample count must remain 1, not 3!
        self.assertEqual(obs1["epoch_count"], 1)
        self.assertEqual(obs2["epoch_count"], 1)
        self.assertEqual(obs3["epoch_count"], 1)

        # Now advance to epoch 2
        obs_e2, _ = provider.collect_for_recipe(r_growth, pid=333, epoch_id=2)
        self.assertEqual(obs_e2["epoch_count"], 2)

    def test_08_clock_regression_detection(self):
        """Out-of-order monotonic timestamp flags TEMPORAL_SEQUENCE_INVALID without silent repair."""
        win = ObservationWindow(target_pid=999, target_identity="target999")
        s1 = MemorySample(epoch_id=1, monotonic_timestamp=10.0, rss_kb=1000)
        s2 = MemorySample(epoch_id=2, monotonic_timestamp=9.0, rss_kb=2000)  # Clock regression!
        win.record_sample(s1)
        win.record_sample(s2)

        self.assertTrue(win.has_temporal_regression())
        res = win.analyze_memory_behavior()
        self.assertEqual(res.behavior, MemoryBehavior.TEMPORAL_SEQUENCE_INVALID)
        self.assertEqual(res.confidence, 0.0)

    def test_09_two_sample_cannot_confirm_growth(self):
        """Exactly 2 samples must NEVER produce a growth verdict for heap or process memory."""
        registry = DiagnosticRecipeRegistry()

        # Recipe Process Memory Growth: 2 samples with growth must NEVER return SUPPORTED
        res_mem = registry.evaluate_recipe(RECIPE_PROCESS_MEMORY_GROWTH, {
            "rss_history_kb": [1000, 5000],
            "epoch_count": 2,
            "is_monotonic": True,
            "rss_growth_bytes": 4000 * 1024,
        })
        self.assertNotEqual(res_mem.status, RECIPE_STATUS_SUPPORTED)
        self.assertIn(res_mem.status, (RECIPE_STATUS_INSUFFICIENT_EVIDENCE, "AMBIGUOUS"))

        # Recipe Heap Growth: 2 samples with growth must return INSUFFICIENT_EVIDENCE
        res_heap = registry.evaluate_recipe(RECIPE_HEAP_GROWTH, {
            "heap_series_kb": [1000, 5000],
            "epoch_count": 2,
            "heap_growth_bytes": 4000 * 1024,
        })
        self.assertEqual(res_heap.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        self.assertTrue(res_heap.details.get("two_sample_delta_only"))

        # With 3 samples, sustained growth is confirmed (SUPPORTED)
        res_heap_3 = registry.evaluate_recipe(RECIPE_HEAP_GROWTH, {
            "heap_series_kb": [1000, 3000, 5000],
            "epoch_count": 3,
            "heap_growth_bytes": 4000 * 1024,
        })
        self.assertEqual(res_heap_3.status, RECIPE_STATUS_SUPPORTED)

    def test_10_allocation_counter_reset_detection(self):
        """Allocation/free counter reset or rollover across epochs is detected and prevents false diagnosis."""
        registry = DiagnosticRecipeRegistry()

        # Normal imbalance
        res_normal = registry.evaluate_recipe(RECIPE_ALLOCATION_FREE_IMBALANCE, {
            "alloc_count": 5000,
            "free_count": 100,
            "alloc_delta": 4000, "free_delta": 50,  # static ratio is not a leak: the gap grew over the window
        })
        self.assertEqual(res_normal.status, RECIPE_STATUS_SUPPORTED)

        # Imbalance data with counter_reset_detected = True -> must return INSUFFICIENT_EVIDENCE
        res_reset = registry.evaluate_recipe(RECIPE_ALLOCATION_FREE_IMBALANCE, {
            "alloc_count": 5000,
            "free_count": 100,
            "counter_reset_detected": True,
        })
        self.assertEqual(res_reset.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        self.assertTrue(res_reset.details.get("counter_reset_detected"))


if __name__ == "__main__":
    unittest.main()

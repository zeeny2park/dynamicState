"""
Phase 2.4.3 Test Suite — Temporal Epoch Integrity & Missing Metrics Semantics.

Validates:
1. Minimum temporal separation (>=50ms) between distinct observation epochs. Caller-supplied
   epoch_id must NOT override temporal validity or artificially manufacture independent observations.
2. Genuinely separated observation epochs (>=50ms) are evaluated normally.
3. Multiple recipes sharing one observation epoch reuse the sample point (deduplication).
4. Duplicate epoch IDs enrich existing sample without rewriting original timestamp.
5. Out-of-order epoch IDs detect sequence violation and return INSUFFICIENT_EVIDENCE.
6. Clock regressions detect invalid temporal sequence (TEMPORAL_SEQUENCE_INVALID).
7. Session and identity boundary isolation prevents historical cross-contamination.
8. Missing VmRSS, malformed VmRSS, explicit zero: MemorySample.rss_kb is None, metric status
   UNAVAILABLE, preserved as None/null in serialization, never substituted with 0.
9. Mixed valid and unavailable epochs: unavailable epoch does not participate as 0 or create
   artificial memory growth deltas.
"""

import json
import time
import unittest
from unittest.mock import MagicMock, patch

from extractor.runtime_evidence_provider import RuntimeEvidenceProvider
from extractor.temporal_observation_window import (
    MemorySample,
    ObservationWindow,
    MemoryBehavior,
)
from extractor.diagnostic_recipes import (
    DiagnosticRecipeRegistry,
    RECIPE_PROCESS_MEMORY_GROWTH,
    RECIPE_HEAP_GROWTH,
    RECIPE_STATUS_SUPPORTED,
    RECIPE_STATUS_CONTRADICTED,
    RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
)


class DummyTargetAdapter:
    """Mock target adapter providing controlled process status responses."""

    def __init__(self, pid=1234, rss_kb=5000, alive=True):
        self.pid = pid
        self.rss_kb = rss_kb
        self.alive = alive
        self.custom_status = {}

    def check_liveness(self, pid):
        return self.alive, ""

    def get_process_identity(self, pid):
        return {
            "pid": pid,
            "host": "localhost",
            "boot_id": "boot-test-1",
            "start_time": 10000.0,
            "executable": "/bin/target_dummy",
            "exe_path": "/bin/target_dummy",
            "build_id": "build-abc",
        }

    def get_threads(self, pid):
        return [{"tid": pid, "state": "R"}]

    def get_process_status(self, pid):
        if self.custom_status:
            return dict(self.custom_status)
        if self.rss_kb is None:
            return {"Name": "target_dummy", "VmSize": "10000 kB"}
        return {
            "Name": "target_dummy",
            "VmRSS": f"{self.rss_kb} kB",
            "VmSize": f"{self.rss_kb * 2} kB",
        }

    def get_memory_maps(self, pid):
        return [
            {"pathname": "[heap]", "category": "heap", "size": 1024 * 1024, "start": 0x1000000, "end": 0x1100000}
        ]


class TestPhase243TemporalEpochAndMissingMetrics(unittest.TestCase):
    """Temporal epoch integrity and missing metric semantics validation."""

    def test_01_rapid_epoch_advancing_rejected_for_insufficient_separation(self):
        """Caller supplying incrementing epoch_id with <50ms elapsed time must be flagged as INSUFFICIENT_EVIDENCE."""
        adapter = DummyTargetAdapter(pid=5001, rss_kb=1000)
        provider = RuntimeEvidenceProvider(adapter=adapter)

        # Call epoch 1
        obs1, _ = provider.collect_for_recipe(RECIPE_PROCESS_MEMORY_GROWTH, pid=5001, epoch_id=1)
        adapter.rss_kb = 2000
        # Call epoch 2 immediately (< 50ms)
        obs2, _ = provider.collect_for_recipe(RECIPE_PROCESS_MEMORY_GROWTH, pid=5001, epoch_id=2)
        adapter.rss_kb = 3000
        # Call epoch 3 immediately (< 50ms)
        obs3, _ = provider.collect_for_recipe(RECIPE_PROCESS_MEMORY_GROWTH, pid=5001, epoch_id=3)

        self.assertTrue(obs3.get("insufficient_temporal_separation"))

        # Evaluate recipe
        res = DiagnosticRecipeRegistry.evaluate_recipe(RECIPE_PROCESS_MEMORY_GROWTH, obs3, prerequisites_met=True)
        self.assertEqual(res.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        self.assertIn("Insufficient temporal separation", res.confidence_basis)

    def test_02_genuinely_separated_epochs_evaluated_normally(self):
        """Observations separated by >= 50ms must evaluate normally."""
        adapter = DummyTargetAdapter(pid=5002, rss_kb=1000)
        provider = RuntimeEvidenceProvider(adapter=adapter)

        # Epoch 1
        obs1, _ = provider.collect_for_recipe(RECIPE_PROCESS_MEMORY_GROWTH, pid=5002, epoch_id=1)
        time.sleep(0.06)  # 60ms separation >= 50ms

        adapter.rss_kb = 2000
        obs2, _ = provider.collect_for_recipe(RECIPE_PROCESS_MEMORY_GROWTH, pid=5002, epoch_id=2)
        time.sleep(0.06)

        adapter.rss_kb = 3000
        obs3, _ = provider.collect_for_recipe(RECIPE_PROCESS_MEMORY_GROWTH, pid=5002, epoch_id=3)

        self.assertFalse(obs3.get("insufficient_temporal_separation", False))
        res = DiagnosticRecipeRegistry.evaluate_recipe(RECIPE_PROCESS_MEMORY_GROWTH, obs3, prerequisites_met=True)
        self.assertEqual(res.status, RECIPE_STATUS_SUPPORTED)
        self.assertTrue(res.details.get("growth_confirmed"))

    def test_03_same_epoch_deduplication_across_multiple_recipes(self):
        """Multiple recipes evaluated in the same observation epoch reuse the sample point without advancing epoch."""
        adapter = DummyTargetAdapter(pid=5003, rss_kb=4000)
        provider = RuntimeEvidenceProvider(adapter=adapter)

        # Collect for process memory growth
        obs_mem, _ = provider.collect_for_recipe(RECIPE_PROCESS_MEMORY_GROWTH, pid=5003, epoch_id=1)
        # Collect for heap growth in the same epoch
        obs_heap, _ = provider.collect_for_recipe(RECIPE_HEAP_GROWTH, pid=5003, epoch_id=1)

        # Total sample count in historical state must remain 1
        self.assertEqual(obs_mem["epoch_count"], 1)
        self.assertEqual(obs_heap["epoch_count"], 1)
        self.assertEqual(obs_heap["samples_count"], 1)

    def test_04_duplicate_epoch_id_enriches_without_rewriting_timestamp(self):
        """Duplicate epoch IDs enrich existing record and do not alter the original timestamp."""
        adapter = DummyTargetAdapter(pid=5004, rss_kb=2000)
        provider = RuntimeEvidenceProvider(adapter=adapter)

        obs1, _ = provider.collect_for_recipe(RECIPE_PROCESS_MEMORY_GROWTH, pid=5004, epoch_id=1)
        initial_mono_ns = obs1["observation_window"].samples[0].monotonic_timestamp

        time.sleep(0.02)
        adapter.rss_kb = 2500
        obs2, _ = provider.collect_for_recipe(RECIPE_PROCESS_MEMORY_GROWTH, pid=5004, epoch_id=1)

        # Samples count is still 1
        self.assertEqual(len(obs2["observation_window"].samples), 1)
        sample = obs2["observation_window"].samples[0]
        # Timestamp must be preserved, not overwritten by second call
        self.assertEqual(sample.monotonic_timestamp, initial_mono_ns)
        # RSS updated
        self.assertEqual(sample.rss_kb, 2500)

    def test_05_out_of_order_epoch_ids_rejected(self):
        """Epoch sequence that regresses (e.g. 2 then 1) must be detected and return INSUFFICIENT_EVIDENCE."""
        adapter = DummyTargetAdapter(pid=5005, rss_kb=1000)
        provider = RuntimeEvidenceProvider(adapter=adapter)

        provider.collect_for_recipe(RECIPE_PROCESS_MEMORY_GROWTH, pid=5005, epoch_id=2)
        time.sleep(0.06)
        obs_regressed, _ = provider.collect_for_recipe(RECIPE_PROCESS_MEMORY_GROWTH, pid=5005, epoch_id=1)

        self.assertTrue(obs_regressed.get("out_of_order_epoch_detected"))
        res = DiagnosticRecipeRegistry.evaluate_recipe(RECIPE_PROCESS_MEMORY_GROWTH, obs_regressed, prerequisites_met=True)
        self.assertEqual(res.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        self.assertIn("out-of-order", res.confidence_basis)

    def test_06_clock_regression_detected_as_invalid_temporal_sequence(self):
        """Monotonic clock regression in samples causes TEMPORAL_SEQUENCE_INVALID."""
        win = ObservationWindow(target_pid=5006, target_identity="host:boot:5006:1.0")
        s1 = MemorySample(epoch_id=1, monotonic_timestamp=100.0, rss_kb=1000)
        s2 = MemorySample(epoch_id=2, monotonic_timestamp=90.0, rss_kb=2000)  # Clock went backwards!

        win.record_sample(s1)
        win.record_sample(s2)

        self.assertTrue(win.has_temporal_regression())
        analysis = win.analyze_memory_behavior()
        self.assertEqual(analysis.behavior, MemoryBehavior.TEMPORAL_SEQUENCE_INVALID)
        self.assertIn("regressions", analysis.rationale)

    def test_07_scoped_history_isolation(self):
        """Historical samples are isolated across session boundaries and target identities."""
        adapter = DummyTargetAdapter(pid=5007, rss_kb=1000)
        provider = RuntimeEvidenceProvider(adapter=adapter)

        # Session A
        obs_a, _ = provider.collect_for_recipe(RECIPE_PROCESS_MEMORY_GROWTH, pid=5007, epoch_id=1, session_id="session_A")
        self.assertEqual(obs_a["epoch_count"], 1)

        # Session B (same pid, different investigation session)
        obs_b, _ = provider.collect_for_recipe(RECIPE_PROCESS_MEMORY_GROWTH, pid=5007, epoch_id=1, session_id="session_B")
        self.assertEqual(obs_b["epoch_count"], 1)

        # Advance Session A with delay
        time.sleep(0.06)
        obs_a2, _ = provider.collect_for_recipe(RECIPE_PROCESS_MEMORY_GROWTH, pid=5007, epoch_id=2, session_id="session_A")
        self.assertEqual(obs_a2["epoch_count"], 2)

        # Verify Session B was not affected
        scoped_b = "session_B::" + obs_b["target_identity_key"]
        self.assertEqual(len(provider._historical_samples[scoped_b]["samples"]), 1)

    def test_08_missing_rss_semantics_and_serialization(self):
        """Missing or malformed VmRSS results in rss_kb=None, status UNAVAILABLE, serialized as null, never 0."""
        # 1. Missing VmRSS in status
        adapter = DummyTargetAdapter(pid=5008, rss_kb=None)
        provider = RuntimeEvidenceProvider(adapter=adapter)

        info, _ = provider.collect_process_info(5008)
        self.assertIsNone(info["rss_kb"])
        self.assertEqual(info["rss_metric_status"], "UNAVAILABLE")
        self.assertIn("absent", info.get("rss_error", ""))

        # 2. Malformed VmRSS in status
        adapter.custom_status = {"Name": "dummy", "VmRSS": "corrupted_val_kB"}
        info_malformed, _ = provider.collect_process_info(5008)
        self.assertIsNone(info_malformed["rss_kb"])
        self.assertEqual(info_malformed["rss_metric_status"], "UNAVAILABLE")
        self.assertIn("Malformed", info_malformed.get("rss_error", ""))

        # 3. Explicit zero RSS in status
        adapter.custom_status = {"Name": "dummy", "VmRSS": "0 kB"}
        info_zero, _ = provider.collect_process_info(5008)
        self.assertEqual(info_zero["rss_kb"], 0)
        self.assertEqual(info_zero["rss_metric_status"], "OBSERVED_ZERO")

        # 4. MemorySample serialization retains null for rss_kb
        sample = MemorySample(epoch_id=1, monotonic_timestamp=10.0, rss_kb=None)
        s_dict = sample.to_dict()
        self.assertIsNone(s_dict["rss_kb"])
        self.assertEqual(s_dict["rss_metric_status"], "UNAVAILABLE")
        self.assertEqual(s_dict["collection_status"], "PARTIAL")

        # Serialized JSON must contain "rss_kb": null
        json_str = json.dumps(s_dict)
        self.assertIn('"rss_kb": null', json_str)
        self.assertNotIn('"rss_kb": 0', json_str)

    def test_09_mixed_valid_and_unavailable_epochs_do_not_create_artificial_growth(self):
        """Unavailable RSS in intermediate or initial epochs must not be treated as 0 or create false growth delta."""
        win = ObservationWindow(target_pid=5009, target_identity="dummy")
        # Epoch 1: unavailable RSS
        win.record_sample(MemorySample(epoch_id=1, monotonic_timestamp=1.0, rss_kb=None))
        # Epoch 2: valid RSS 5000 KB
        win.record_sample(MemorySample(epoch_id=2, monotonic_timestamp=2.0, rss_kb=5000))
        # Epoch 3: valid RSS 5000 KB
        win.record_sample(MemorySample(epoch_id=3, monotonic_timestamp=3.0, rss_kb=5000))
        # Epoch 4: valid RSS 5000 KB
        win.record_sample(MemorySample(epoch_id=4, monotonic_timestamp=4.0, rss_kb=5000))

        analysis = win.analyze_memory_behavior()
        # Since RSS changed from 5000 -> 5000 across valid samples, delta must be 0, NOT 5000!
        self.assertEqual(analysis.rss_delta_kb, 0)
        self.assertEqual(analysis.behavior, MemoryBehavior.STABLE_PLATEAU)


if __name__ == "__main__":
    unittest.main()

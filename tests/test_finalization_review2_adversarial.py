"""Finalization Review 2 — Adversarial Verification & Boundary Regression Suite.

Validates concrete edge cases uncovered during independent adversarial review:
1. Remote collection deadline boundaries (<200ms floor removal, NaN/Inf/0/negative/bool rejection, retry bounding)
2. Confidence & evidence adversarial properties (insertion-order independence, idempotency, contradiction weight sanitization)
3. Temporal analysis PARTIAL sample preservation and zero-duration identical-timestamp guard
4. Native collector repeated SIGTERM/SIGINT start-stop cycles
"""

import math
import os
import signal
import subprocess
import time
import unittest
from pathlib import Path

from extractor.competing_hypotheses import CompetingHypothesis
from extractor.evidence_ledger import EvidenceLedger
from extractor.target_adapter import RemoteSshTargetAdapter
from extractor.temporal_observation_window import (
    MemoryBehavior,
    MemorySample,
    ObservationWindow,
)


class TestRemoteDeadlineBoundaries(unittest.TestCase):
    """Section 3: Remote collection deadline boundary enforcement."""

    def _make_adapter(self, recorded_timeouts):
        def runner(args, timeout):
            recorded_timeouts.append(timeout)
            return 0, "ok", ""

        return RemoteSshTargetAdapter(
            host="10.0.0.1",
            timeout_sec=5.0,
            command_runner=runner,
            use_control_master=False,
        )

    def test_invalid_deadlines_raise_instead_of_becoming_unlimited(self):
        adapter = self._make_adapter([])
        for bad in (0, 0.0, -1.0, float("nan"), float("inf"), float("-inf"), True, False, "abc"):
            with self.assertRaises(ValueError, msg=f"collection_deadline({bad!r}) must raise ValueError"):
                with adapter.collection_deadline(bad):
                    pass

    def test_deadline_greater_and_less_than_requested_timeout(self):
        seen = []
        adapter = self._make_adapter(seen)
        with adapter.collection_deadline(10.0):
            adapter.run_ssh("echo a", timeout=2.0)
        self.assertAlmostEqual(seen[-1], 2.0, places=2)

        with adapter.collection_deadline(1.0):
            adapter.run_ssh("echo b", timeout=5.0)
        self.assertLessEqual(seen[-1], 1.01)
        self.assertGreater(seen[-1], 0.5)

    def test_remaining_deadline_below_200ms_never_inflated_to_200ms(self):
        seen = []
        adapter = self._make_adapter(seen)
        with adapter.collection_deadline(0.06):
            rc, _, _ = adapter.run_ssh("echo fast", timeout=5.0)
        self.assertEqual(rc, 0)
        self.assertEqual(len(seen), 1)
        self.assertLessEqual(seen[0], 0.07, f"Timeout {seen[0]}s inflated past 60ms deadline")

    def test_expired_deadline_aborts_without_running_ssh(self):
        seen = []
        adapter = self._make_adapter(seen)
        with adapter.collection_deadline(0.02):
            time.sleep(0.03)
            rc, _, err = adapter.run_ssh("echo late", timeout=5.0)
            with self.assertRaises(TimeoutError):
                adapter._bound_timeout(1.0)
        self.assertEqual(rc, -1)
        self.assertIn("deadline exceeded", err.lower())
        self.assertEqual(seen, [])

    def test_retry_near_deadline_does_not_exceed_remaining_budget(self):
        seen = []

        def mux_fail_runner(args, timeout):
            seen.append(timeout)
            return 255, "", "Control socket broken pipe"

        adapter = RemoteSshTargetAdapter(
            host="10.0.0.1",
            timeout_sec=5.0,
            command_runner=mux_fail_runner,
            use_control_master=True,
        )
        # With 0.3s total deadline (< 1.0s reconnect threshold), must NOT retry
        with adapter.collection_deadline(0.3):
            adapter.run_ssh("echo test", timeout=5.0)
        self.assertEqual(len(seen), 1, "Near-deadline mux failure must not trigger unbounded retry")
        self.assertLessEqual(seen[0], 0.31)



    def test_real_subprocess_killed_within_deadline_including_grandchild(self):
        """Real subprocess spawning a grandchild holding stdout must be killed via killpg within deadline."""
        adapter = RemoteSshTargetAdapter(
            host="10.0.0.1",
            timeout_sec=5.0,
            use_control_master=False,
        )
        t0 = time.monotonic()
        with adapter.collection_deadline(0.15):
            rc, out, err = adapter._default_command_runner(
                ["sh", "-c", "sleep 10 & wait"],
                timeout=adapter._bound_timeout(5.0),
            )
        elapsed = time.monotonic() - t0
        self.assertEqual(rc, -1)
        self.assertEqual(RemoteSshTargetAdapter.classify_remote_error(rc, err, out), "TIMEOUT")
        self.assertLess(elapsed, 0.8, f"Real subprocess with grandchild exceeded deadline: {elapsed:.2f}s")


class TestConfidenceAdversarialValidation(unittest.TestCase):
    """Section 4: Mathematical & adversarial confidence invariants."""

    def test_contradiction_weight_sanitization(self):
        hyp = CompetingHypothesis(
            hypothesis_id="HYP_CPU",
            title="CPU Saturation",
            category="CPU_UTILIZATION",
            confidence=0.50,
        )
        hyp.add_contradicting_observation("inf contra", weight=float("inf"), is_decisive=False)
        hyp.add_contradicting_observation("nan contra", weight=float("nan"), is_decisive=False)
        hyp.add_contradicting_observation("neg contra", weight=-3.0, is_decisive=False)
        hyp.add_contradicting_observation("bool contra", weight=True, is_decisive=False)
        self.assertTrue(math.isfinite(hyp.confidence))
        self.assertGreaterEqual(hyp.confidence, 0.05)
        self.assertLessEqual(hyp.confidence, 0.99)
        for v in hyp._contradiction_weights.values():
            self.assertTrue(math.isfinite(v) and 0.0 < v <= 1.0)

    def test_insertion_order_independence_and_idempotent_reevaluation(self):
        def build(order):
            h = CompetingHypothesis(
                hypothesis_id="HYP_MEM",
                title="Memory Growth",
                category="MEMORY_GROWTH",
                confidence=0.50,
            )
            for obs, w in order:
                h.add_supporting_observation(obs, weight=w)
            return h

        items = [("obs_alpha", 0.12), ("obs_beta", 0.18), ("obs_gamma", 0.09)]
        h1 = build(items)
        h2 = build(list(reversed(items)))
        self.assertEqual(h1.confidence, h2.confidence)
        self.assertEqual(h1.status, h2.status)

        # Idempotent repeated evaluation
        snap_conf, snap_status = h1.confidence, h1.status
        for _ in range(5):
            h1.evaluate_verdict()
            self.assertEqual(h1.confidence, snap_conf)
            self.assertEqual(h1.status, snap_status)


class TestTemporalPartialAndDuplicateTimestamps(unittest.TestCase):
    """Section 5: PARTIAL sample preservation and duplicate/zero-duration guards."""

    def test_identical_timestamps_produce_insufficient_with_zero_rate(self):
        win = ObservationWindow(target_pid=99)
        win.record_sample(MemorySample(epoch_id=1, monotonic_timestamp=100.0, rss_kb=1000))
        win.record_sample(MemorySample(epoch_id=2, monotonic_timestamp=100.0, rss_kb=5000))
        res = win.analyze_memory_behavior()
        self.assertEqual(res.behavior, MemoryBehavior.INSUFFICIENT_OBSERVATION)
        self.assertEqual(res.rss_growth_rate_kb_per_sec, 0.0)
        self.assertTrue(any("identical timestamps" in lim.lower() for lim in res.limitations))

    def test_partial_samples_preserved_and_missing_rss_never_treated_as_zero(self):
        win = ObservationWindow(target_pid=99)
        # All 3 samples lack rss_kb (so status becomes PARTIAL), but observe growing container_sizes
        win.record_sample(MemorySample(epoch_id=1, monotonic_timestamp=10.0, rss_kb=None, container_sizes={"cache": 100}))
        win.record_sample(MemorySample(epoch_id=2, monotonic_timestamp=11.0, rss_kb=None, container_sizes={"cache": 200}))
        win.record_sample(MemorySample(epoch_id=3, monotonic_timestamp=12.0, rss_kb=None, container_sizes={"cache": 350}))
        res = win.analyze_memory_behavior()
        self.assertEqual(res.behavior, MemoryBehavior.OBJECT_ACCUMULATION)
        self.assertEqual(res.rss_delta_kb, 0)
        self.assertIn("cache", res.retaining_containers)
        self.assertTrue(any("partial" in lim.lower() for lim in res.limitations))

    def test_partial_samples_without_any_valid_metrics_stay_inconclusive(self):
        win = ObservationWindow(target_pid=99)
        win.record_sample(MemorySample(epoch_id=1, monotonic_timestamp=10.0, rss_kb=None))
        win.record_sample(MemorySample(epoch_id=2, monotonic_timestamp=11.0, rss_kb=None))
        win.record_sample(MemorySample(epoch_id=3, monotonic_timestamp=12.0, rss_kb=None))
        res = win.analyze_memory_behavior()
        self.assertEqual(res.behavior, MemoryBehavior.INSUFFICIENT_OBSERVATION)


class TestNativeCollectorRepeatedLifecycle(unittest.TestCase):
    """Section 6: Repeated SIGTERM/SIGINT daemon shutdown cycles."""

    def setUp(self):
        self.collector_bin = str(
            Path(__file__).resolve().parent.parent / "target" / "collector" / "dynamicstate-collector"
        )

    def test_repeated_sigterm_and_sigint_daemon_shutdown_cycles(self):
        if not os.path.exists(self.collector_bin):
            self.skipTest("Native collector binary not built")
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGTERM):
            proc = subprocess.Popen(
                [self.collector_bin, "--daemon"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                time.sleep(0.03)
                proc.send_signal(sig)
                rc = proc.wait(timeout=5)
                self.assertEqual(rc, 0, f"Collector daemon failed clean shutdown on signal {sig}")
            finally:
                for stream in (proc.stdin, proc.stdout, proc.stderr):
                    if stream:
                        try:
                            stream.close()
                        except Exception:
                            pass
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()


if __name__ == "__main__":
    unittest.main()

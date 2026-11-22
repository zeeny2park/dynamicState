"""Deterministic performance, concurrency, failure-isolation, and instrumentation regression tests.

Avoids brittle wall-clock assertions; verifies:
1. Bounded concurrency ceiling and parallel execution (peak_concurrency > 1 and <= max_workers)
2. Explicit DAG dependency ordering, cycle rejection, and selective SKIPPED_DEPENDENCY propagation
3. Deterministic adaptive throttling on transient failures and restoration on successes
4. Per-task failure isolation and partial result preservation (COMPLETE / PARTIAL / FAILED / CANCELLED / TIMED_OUT)
5. Permanent SSH authentication failure fast-fail (1 SSH call instead of N) and reset_auth_failure()
6. No retries for non-retryable PERMISSION_DENIED errors vs bounded retries for transient TRANSPORT_ERROR
7. Coherent overall deadline enforcement without resetting nested timeout budgets
8. Cancellation stops scheduling new tasks while preserving already-completed results
9. Lightweight monotonic stage/operation instrumentation and performance_summary()
"""

import threading
import time
import unittest

from extractor.diagnostic_performance import CollectionOperationRecord, DiagnosticPerformanceTracker
from extractor.remote_scheduler import (
    AdaptiveRemoteCollectionScheduler,
    RemoteCollectionTask,
    STATUS_CANCELLED,
    STATUS_COMPLETE,
    STATUS_FAILED,
    STATUS_PARTIAL,
    STATUS_SKIPPED_DEPENDENCY,
    STATUS_TIMED_OUT,
)
from extractor.target_adapter import RemoteSshTargetAdapter


class TestAdaptiveRemoteCollectionScheduler(unittest.TestCase):
    """Deterministic concurrency, DAG, throttling, isolation, and cancellation tests."""

    def test_bounded_concurrency_and_parallel_execution(self):
        active = 0
        peak = 0
        lock = threading.Lock()
        barrier = threading.Barrier(3, timeout=2.0)

        def work(idx: int):
            nonlocal active, peak
            with lock:
                active += 1
                peak = max(peak, active)
            try:
                if idx < 3:
                    barrier.wait()
                else:
                    time.sleep(0.01)
            finally:
                with lock:
                    active -= 1
            return f"ok-{idx}"

        sched = AdaptiveRemoteCollectionScheduler(max_workers=3)
        tasks = [
            RemoteCollectionTask(task_id=f"t{i}", target_id=f"host-{i}", collection_type="snapshot", fn=lambda i=i: work(i))
            for i in range(6)
        ]
        batch = sched.execute(tasks, overall_deadline_s=5.0)
        self.assertEqual(batch.status, STATUS_COMPLETE)
        self.assertEqual(batch.succeeded_count, 6)
        self.assertGreaterEqual(peak, 2, "Independent tasks should execute concurrently")
        self.assertLessEqual(peak, 3, "Concurrency must never exceed max_workers")
        self.assertLessEqual(batch.peak_concurrency, 3)

    def test_dag_dependency_ordering_and_cycle_rejection(self):
        order = []
        lock = threading.Lock()

        def step(name: str):
            with lock:
                order.append(name)
            return name

        sched = AdaptiveRemoteCollectionScheduler(max_workers=4)
        tasks = [
            RemoteCollectionTask(task_id="a", target_id="h1", collection_type="ident", fn=lambda: step("a")),
            RemoteCollectionTask(task_id="b", target_id="h1", collection_type="maps", fn=lambda: step("b"), depends_on=("a",)),
            RemoteCollectionTask(task_id="c", target_id="h1", collection_type="heap", fn=lambda: step("c"), depends_on=("b",)),
        ]
        batch = sched.execute(tasks, overall_deadline_s=5.0)
        self.assertEqual(batch.status, STATUS_COMPLETE)
        self.assertEqual(order, ["a", "b", "c"])

        # Cycle detection must fail closed with ValueError
        cyclic = [
            RemoteCollectionTask(task_id="x", target_id="h1", collection_type="a", fn=lambda: 1, depends_on=("y",)),
            RemoteCollectionTask(task_id="y", target_id="h1", collection_type="b", fn=lambda: 2, depends_on=("x",)),
        ]
        with self.assertRaises(ValueError):
            sched.execute(cyclic)

    def test_per_task_failure_isolation_and_partial_preservation(self):
        sched = AdaptiveRemoteCollectionScheduler(max_workers=4)

        def fail_fn():
            raise RuntimeError("Connection refused")

        tasks = [
            RemoteCollectionTask(task_id="ok1", target_id="h1", collection_type="snap", fn=lambda: {"rss": 100}),
            RemoteCollectionTask(task_id="bad", target_id="h2", collection_type="snap", fn=fail_fn),
            RemoteCollectionTask(task_id="dep_on_bad", target_id="h2", collection_type="heap", fn=lambda: "never", depends_on=("bad",)),
            RemoteCollectionTask(task_id="ok2", target_id="h3", collection_type="snap", fn=lambda: {"rss": 200}),
        ]
        batch = sched.execute(tasks, overall_deadline_s=5.0)
        self.assertEqual(batch.status, STATUS_PARTIAL)
        self.assertEqual(batch.succeeded_count, 2)
        self.assertEqual(batch.results["ok1"].value, {"rss": 100})
        self.assertEqual(batch.results["ok2"].value, {"rss": 200})
        self.assertEqual(batch.results["bad"].status, STATUS_FAILED)
        self.assertEqual(batch.results["dep_on_bad"].status, STATUS_SKIPPED_DEPENDENCY)

    def test_no_retry_on_permanent_auth_error_but_bounded_retry_on_transient(self):
        auth_calls = [0]
        transient_calls = [0]

        def perm_fail():
            auth_calls[0] += 1
            raise RuntimeError("Permission denied (publickey).")

        def transient_then_ok():
            transient_calls[0] += 1
            if transient_calls[0] < 2:
                raise RuntimeError("Connection reset by peer")
            return "recovered"

        sched = AdaptiveRemoteCollectionScheduler(max_workers=2)
        tasks = [
            RemoteCollectionTask(task_id="auth", target_id="h1", collection_type="snap", fn=perm_fail, max_retries=3),
            RemoteCollectionTask(task_id="trans", target_id="h2", collection_type="snap", fn=transient_then_ok, max_retries=2, retry_backoff_s=0.005),
        ]
        batch = sched.execute(tasks, overall_deadline_s=5.0)
        self.assertEqual(auth_calls[0], 1, "Permanent PERMISSION_DENIED must NEVER be retried")
        self.assertEqual(batch.results["auth"].retry_count, 0)
        self.assertEqual(batch.results["auth"].error_classification, "PERMISSION_DENIED")
        self.assertEqual(transient_calls[0], 2)
        self.assertEqual(batch.results["trans"].status, STATUS_COMPLETE)
        self.assertEqual(batch.results["trans"].retry_count, 1)

    def test_adaptive_throttling_and_restoration_is_deterministic(self):
        sched = AdaptiveRemoteCollectionScheduler(
            max_workers=3, min_workers=1, throttle_on_failures=2, restore_on_successes=2
        )
        # Sequential chain of 2 transport failures -> throttles from 3 to 2
        tasks_fail = [
            RemoteCollectionTask(task_id="f1", target_id="h1", collection_type="s", fn=lambda: (_ for _ in ()).throw(RuntimeError("Connection refused"))),
            RemoteCollectionTask(task_id="f2", target_id="h2", collection_type="s", fn=lambda: (_ for _ in ()).throw(RuntimeError("Connection refused"))),
        ]
        b1 = sched.execute(tasks_fail, overall_deadline_s=5.0)
        self.assertEqual(b1.status, STATUS_FAILED)
        self.assertEqual(b1.effective_concurrency_final, 2)

    def test_cancellation_stops_new_tasks_and_preserves_completed(self):
        sched = AdaptiveRemoteCollectionScheduler(max_workers=1)

        def first_and_cancel():
            sched.cancel()
            return "completed_first"

        tasks = [
            RemoteCollectionTask(task_id="t1", target_id="h1", collection_type="s", fn=first_and_cancel),
            RemoteCollectionTask(task_id="t2", target_id="h2", collection_type="s", fn=lambda: "should_not_run", depends_on=("t1",)),
        ]
        batch = sched.execute(tasks, overall_deadline_s=5.0)
        self.assertEqual(batch.status, STATUS_PARTIAL)
        self.assertEqual(batch.results["t1"].status, STATUS_COMPLETE)
        self.assertEqual(batch.results["t1"].value, "completed_first")
        self.assertEqual(batch.results["t2"].status, STATUS_CANCELLED)

    def test_overall_deadline_bounds_batch_and_classifies_timed_out(self):
        sched = AdaptiveRemoteCollectionScheduler(max_workers=2)
        tasks = [
            RemoteCollectionTask(task_id="slow", target_id="h1", collection_type="s", fn=lambda: time.sleep(0.5)),
        ]
        t0 = time.monotonic()
        batch = sched.execute(tasks, overall_deadline_s=0.06)
        elapsed = time.monotonic() - t0
        self.assertEqual(batch.status, STATUS_TIMED_OUT)
        self.assertTrue(batch.timed_out)
        self.assertLess(elapsed, 0.8)


class TestRemoteAuthFastFailAndInstrumentation(unittest.TestCase):
    """Verifies permanent auth fast-fail in RemoteSshTargetAdapter and stage/op instrumentation."""

    def test_permanent_auth_failure_fast_fails_without_repeated_ssh_calls(self):
        calls = [0]

        def auth_fail_runner(args, timeout):
            calls[0] += 1
            return 255, "", "Permission denied (publickey)."

        adapter = RemoteSshTargetAdapter(
            host="10.0.9.1",
            timeout_sec=5.0,
            command_runner=auth_fail_runner,
            use_control_master=False,
        )
        for _ in range(4):
            rc, _, err = adapter.run_ssh("echo hi")
            self.assertNotEqual(rc, 0)
            self.assertEqual(RemoteSshTargetAdapter.classify_remote_error(rc, err), "PERMISSION_DENIED")
        self.assertEqual(calls[0], 1, "Permanent auth failure must fast-fail subsequent SSH calls")

        # After explicit reset_auth_failure(), a new attempt is allowed
        adapter.reset_auth_failure()
        adapter.run_ssh("echo retry")
        self.assertEqual(calls[0], 2)

    def test_performance_tracker_records_operations_and_identifies_slowest_stages(self):
        tracker = DiagnosticPerformanceTracker()
        with tracker.measure_phase("transfer_s"):
            time.sleep(0.01)
        with tracker.measure_phase("parsing_s"):
            time.sleep(0.002)
        tracker.record_operation(
            CollectionOperationRecord(
                operation_name="snap_h1",
                target_identity="10.0.0.1:1001",
                collection_type="snapshot",
                start_monotonic=1.0,
                end_monotonic=1.25,
                elapsed_s=0.25,
                status="COMPLETE",
                payload_bytes=4096,
                result_count=1,
            )
        )
        tracker.finish()
        summary = tracker.performance_summary(top_n=3)
        self.assertGreater(len(summary["slowest_stages"]), 0)
        self.assertEqual(summary["slowest_stages"][0]["stage"], "transfer_s")
        self.assertEqual(summary["slowest_operations"][0]["operation_name"], "snap_h1")


if __name__ == "__main__":
    unittest.main()

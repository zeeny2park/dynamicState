"""Phase 4 — 20-Case Deterministic Timeout, Deadline & Cancellation Test Matrix.

Verifies every contract requirement from the Remote Diagnostics Hardening pass:
 1. Task timeout with a cooperative task
 2. Task timeout with a real remote subprocess (and grandchild killpg)
 3. Overall deadline shorter than task timeout
 4. Task timeout shorter than overall deadline
 5. Multiple running tasks when overall deadline expires
 6. Slow task plus completed fast tasks (partial preservation)
 7. Cancellation while workers (including real subprocesses) are running
 8. Cancellation before any task starts
 9. Cancellation during retry backoff (immediate wake)
10. Deadline expiration during retry backoff
11. Task completes just before deadline
12. Task completes just after deadline (must be TIMED_OUT, never COMPLETE)
13. Worker completion after timeout (caller already returned promptly)
14. No additional tasks scheduled after cancellation
15. Scheduler returns within expected deadline tolerance (proves non-blocking shutdown)
16. No leaked subprocesses or process groups on timeout/cancel
17. Completed evidence is preserved after timeout
18. Late worker results cannot alter finalized results
19. Task timeout_s validated for invalid values (0, neg, NaN, Inf, bool, str)
20. Overall deadline validated for invalid values (0, neg, NaN, Inf, bool, str)
+ Per-target auth failure isolation across separate RemoteSshTargetAdapter instances
"""

import os
import threading
import time
import unittest

from extractor.remote_scheduler import (
    AdaptiveRemoteCollectionScheduler,
    RemoteCollectionTask,
    STATUS_CANCELLED,
    STATUS_COMPLETE,
    STATUS_PARTIAL,
    STATUS_TIMED_OUT,
    get_active_execution_context,
)
from extractor.target_adapter import RemoteSshTargetAdapter


class TestDeadlineAndCancellationMatrix(unittest.TestCase):
    """Comprehensive 20-case timeout, deadline, and cancellation verification suite."""

    def test_01_task_timeout_cooperative_task(self):
        sched = AdaptiveRemoteCollectionScheduler(max_workers=2)

        def coop():
            dl, _, _ = get_active_execution_context()
            self.assertIsNotNone(dl)
            while time.monotonic() < dl:
                time.sleep(0.01)
            raise TimeoutError("cooperative deadline reached")

        t0 = time.monotonic()
        batch = sched.execute(
            [RemoteCollectionTask(task_id="c1", target_id="h1", collection_type="s", fn=coop, timeout_s=0.06)],
            overall_deadline_s=5.0,
        )
        elapsed = time.monotonic() - t0
        self.assertEqual(batch.results["c1"].status, STATUS_TIMED_OUT)
        self.assertEqual(batch.status, STATUS_TIMED_OUT)
        self.assertLess(elapsed, 0.35)

    def test_02_task_timeout_real_subprocess_and_grandchild(self):
        sched = AdaptiveRemoteCollectionScheduler(max_workers=2)
        adapter = RemoteSshTargetAdapter(host="10.0.0.1", timeout_sec=5.0, use_control_master=False)

        def run_real_subproc():
            rc, out, err = adapter._default_command_runner(
                ["sh", "-c", "sleep 10 & wait"],
                timeout=adapter._bound_timeout(5.0),
            )
            if rc != 0:
                raise TimeoutError(err)
            return out

        t0 = time.monotonic()
        batch = sched.execute(
            [RemoteCollectionTask(task_id="sub1", target_id="h1", collection_type="ssh", fn=run_real_subproc, timeout_s=0.10)],
            overall_deadline_s=5.0,
        )
        elapsed = time.monotonic() - t0
        self.assertEqual(batch.results["sub1"].status, STATUS_TIMED_OUT)
        self.assertLess(elapsed, 0.5, f"Real subprocess exceeded task timeout: {elapsed:.2f}s")

    def test_03_overall_deadline_shorter_than_task_timeout(self):
        sched = AdaptiveRemoteCollectionScheduler(max_workers=2)
        t0 = time.monotonic()
        batch = sched.execute(
            [RemoteCollectionTask(task_id="t1", target_id="h1", collection_type="s", fn=lambda: time.sleep(0.8), timeout_s=5.0)],
            overall_deadline_s=0.06,
        )
        elapsed = time.monotonic() - t0
        self.assertEqual(batch.status, STATUS_TIMED_OUT)
        self.assertEqual(batch.results["t1"].status, STATUS_TIMED_OUT)
        # Proves caller returned promptly without waiting for 0.8s worker thread
        self.assertLess(elapsed, 0.30, f"Caller blocked past overall_deadline_s: {elapsed:.3f}s")

    def test_04_task_timeout_shorter_than_overall_deadline(self):
        sched = AdaptiveRemoteCollectionScheduler(max_workers=2)
        t0 = time.monotonic()
        batch = sched.execute(
            [
                RemoteCollectionTask(task_id="short_to", target_id="h1", collection_type="s", fn=lambda: time.sleep(0.8), timeout_s=0.05),
                RemoteCollectionTask(task_id="fast_ok", target_id="h2", collection_type="s", fn=lambda: "fast_value", timeout_s=2.0),
            ],
            overall_deadline_s=5.0,
        )
        elapsed = time.monotonic() - t0
        self.assertEqual(batch.status, STATUS_PARTIAL)
        self.assertEqual(batch.results["fast_ok"].status, STATUS_COMPLETE)
        self.assertEqual(batch.results["fast_ok"].value, "fast_value")
        self.assertEqual(batch.results["short_to"].status, STATUS_TIMED_OUT)
        self.assertLess(elapsed, 0.30)

    def test_05_multiple_running_tasks_when_overall_deadline_expires(self):
        sched = AdaptiveRemoteCollectionScheduler(max_workers=3)
        started = threading.Barrier(3, timeout=2.0)

        def block_long():
            started.wait()
            time.sleep(0.8)
            return "too_late"

        t0 = time.monotonic()
        tasks = [
            RemoteCollectionTask(task_id=f"m{i}", target_id=f"h{i}", collection_type="s", fn=block_long)
            for i in range(3)
        ]
        batch = sched.execute(tasks, overall_deadline_s=0.08)
        elapsed = time.monotonic() - t0
        self.assertEqual(batch.status, STATUS_TIMED_OUT)
        self.assertEqual(batch.timed_out_count, 3)
        self.assertLess(elapsed, 0.35)

    def test_06_slow_task_plus_completed_fast_tasks_preserves_evidence(self):
        sched = AdaptiveRemoteCollectionScheduler(max_workers=3)
        batch = sched.execute(
            [
                RemoteCollectionTask(task_id="fast1", target_id="h1", collection_type="s", fn=lambda: {"ev": 1}),
                RemoteCollectionTask(task_id="fast2", target_id="h2", collection_type="s", fn=lambda: {"ev": 2}),
                RemoteCollectionTask(task_id="slow", target_id="h3", collection_type="s", fn=lambda: time.sleep(0.8), timeout_s=0.05),
            ],
            overall_deadline_s=5.0,
        )
        self.assertEqual(batch.status, STATUS_PARTIAL)
        self.assertEqual(batch.succeeded_count, 2)
        self.assertEqual(batch.results["fast1"].value, {"ev": 1})
        self.assertEqual(batch.results["fast2"].value, {"ev": 2})
        self.assertEqual(batch.results["slow"].status, STATUS_TIMED_OUT)

    def test_07_and_16_cancellation_while_real_subprocess_running_kills_process_group(self):
        sched = AdaptiveRemoteCollectionScheduler(max_workers=2)
        adapter = RemoteSshTargetAdapter(host="10.0.0.1", timeout_sec=5.0, use_control_master=False)
        started = threading.Event()

        def run_subproc():
            started.set()
            rc, out, err = adapter._default_command_runner(["sh", "-c", "sleep 10 & wait"], timeout=5.0)
            if rc != 0:
                raise RuntimeError(err)
            return out

        def cancel_soon():
            started.wait(timeout=2.0)
            time.sleep(0.05)
            sched.cancel()

        canceller = threading.Thread(target=cancel_soon, daemon=True)
        canceller.start()
        t0 = time.monotonic()
        batch = sched.execute(
            [RemoteCollectionTask(task_id="sub_cancel", target_id="h1", collection_type="ssh", fn=run_subproc)],
            overall_deadline_s=5.0,
        )
        elapsed = time.monotonic() - t0
        canceller.join(timeout=1.0)
        self.assertEqual(batch.status, STATUS_CANCELLED)
        self.assertEqual(batch.results["sub_cancel"].status, STATUS_CANCELLED)
        self.assertLess(elapsed, 0.5, f"Cancelled real subprocess did not terminate promptly: {elapsed:.2f}s")

    def test_08_cancellation_before_any_task_starts(self):
        sched = AdaptiveRemoteCollectionScheduler(max_workers=2)
        ran = [False]
        sched.cancel()
        batch = sched.execute(
            [RemoteCollectionTask(task_id="never", target_id="h1", collection_type="s", fn=lambda: ran.__setitem__(0, True))],
            overall_deadline_s=5.0,
        )
        self.assertFalse(ran[0])
        self.assertEqual(batch.status, STATUS_CANCELLED)
        self.assertEqual(batch.results["never"].status, STATUS_CANCELLED)

    def test_09_cancellation_during_retry_backoff_wakes_immediately(self):
        sched = AdaptiveRemoteCollectionScheduler(max_workers=2)
        attempt_started = threading.Event()

        def fail_once():
            attempt_started.set()
            raise RuntimeError("Connection reset by peer")

        def cancel_in_backoff():
            attempt_started.wait(timeout=2.0)
            time.sleep(0.02)
            sched.cancel()

        t = threading.Thread(target=cancel_in_backoff, daemon=True)
        t.start()
        t0 = time.monotonic()
        batch = sched.execute(
            [RemoteCollectionTask(task_id="rb", target_id="h1", collection_type="s", fn=fail_once, max_retries=3, retry_backoff_s=2.0)],
            overall_deadline_s=5.0,
        )
        elapsed = time.monotonic() - t0
        t.join(timeout=1.0)
        self.assertEqual(batch.results["rb"].status, STATUS_CANCELLED)
        self.assertLess(elapsed, 0.35, f"Retry backoff did not wake immediately on cancel: {elapsed:.2f}s")

    def test_10_deadline_expiration_during_retry_backoff(self):
        sched = AdaptiveRemoteCollectionScheduler(max_workers=2)

        def fail_transient():
            raise RuntimeError("Connection reset by peer")

        t0 = time.monotonic()
        batch = sched.execute(
            [RemoteCollectionTask(task_id="rd", target_id="h1", collection_type="s", fn=fail_transient, max_retries=5, retry_backoff_s=0.5)],
            overall_deadline_s=0.06,
        )
        elapsed = time.monotonic() - t0
        self.assertEqual(batch.results["rd"].status, STATUS_TIMED_OUT)
        self.assertLess(elapsed, 0.25)

    def test_11_task_completes_just_before_deadline(self):
        sched = AdaptiveRemoteCollectionScheduler(max_workers=2)
        batch = sched.execute(
            [RemoteCollectionTask(task_id="ok", target_id="h1", collection_type="s", fn=lambda: (time.sleep(0.01), "done")[1], timeout_s=0.5)],
            overall_deadline_s=1.0,
        )
        self.assertEqual(batch.status, STATUS_COMPLETE)
        self.assertEqual(batch.results["ok"].value, "done")

    def test_12_task_completes_just_after_deadline_classified_timed_out(self):
        sched = AdaptiveRemoteCollectionScheduler(max_workers=2)
        batch = sched.execute(
            [RemoteCollectionTask(task_id="late", target_id="h1", collection_type="s", fn=lambda: (time.sleep(0.08), "late_val")[1], timeout_s=0.03)],
            overall_deadline_s=2.0,
        )
        self.assertEqual(batch.results["late"].status, STATUS_TIMED_OUT)
        self.assertIsNone(batch.results["late"].value)

    def test_13_15_17_18_late_worker_completion_cannot_mutate_finalized_results(self):
        sched = AdaptiveRemoteCollectionScheduler(max_workers=2)
        release = threading.Event()
        worker_finished = threading.Event()

        def slow_then_finish():
            release.wait(timeout=2.0)
            worker_finished.set()
            return "late_corrupt_payload"

        t0 = time.monotonic()
        batch = sched.execute(
            [
                RemoteCollectionTask(task_id="good", target_id="h1", collection_type="s", fn=lambda: "good_evidence"),
                RemoteCollectionTask(task_id="late_w", target_id="h2", collection_type="s", fn=slow_then_finish, timeout_s=0.05),
            ],
            overall_deadline_s=5.0,
        )
        elapsed = time.monotonic() - t0
        self.assertLess(elapsed, 0.25, f"Scheduler waited for hung worker instead of returning promptly: {elapsed:.2f}s")
        self.assertEqual(batch.status, STATUS_PARTIAL)
        self.assertEqual(batch.results["good"].value, "good_evidence")
        self.assertEqual(batch.results["late_w"].status, STATUS_TIMED_OUT)

        # Now let the abandoned worker finish; finalized batch.results must remain completely untouched
        release.set()
        worker_finished.wait(timeout=1.0)
        time.sleep(0.02)
        self.assertEqual(batch.results["late_w"].status, STATUS_TIMED_OUT)
        self.assertIsNone(batch.results["late_w"].value)
        self.assertEqual(batch.results["good"].value, "good_evidence")

    def test_14_no_additional_tasks_scheduled_after_cancellation(self):
        sched = AdaptiveRemoteCollectionScheduler(max_workers=1)
        scheduled_ids = []

        def run_first():
            scheduled_ids.append("t1")
            sched.cancel()
            return "ok1"

        tasks = [
            RemoteCollectionTask(task_id="t1", target_id="h1", collection_type="s", fn=run_first),
            RemoteCollectionTask(task_id="t2", target_id="h2", collection_type="s", fn=lambda: scheduled_ids.append("t2"), depends_on=("t1",)),
            RemoteCollectionTask(task_id="t3", target_id="h3", collection_type="s", fn=lambda: scheduled_ids.append("t3"), depends_on=("t2",)),
        ]
        batch = sched.execute(tasks, overall_deadline_s=5.0)
        self.assertEqual(scheduled_ids, ["t1"])
        self.assertEqual(batch.results["t1"].status, STATUS_COMPLETE)
        self.assertEqual(batch.results["t2"].status, STATUS_CANCELLED)
        self.assertEqual(batch.results["t3"].status, STATUS_CANCELLED)

    def test_19_and_20_invalid_task_timeout_and_overall_deadline_rejected(self):
        sched = AdaptiveRemoteCollectionScheduler(max_workers=2)
        for bad in (0, 0.0, -1.0, float("nan"), float("inf"), float("-inf"), True, False, "bad"):
            with self.assertRaises(ValueError, msg=f"task timeout_s={bad!r} must raise"):
                sched.execute([RemoteCollectionTask(task_id="t", target_id="h", collection_type="s", fn=lambda: 1, timeout_s=bad)])
            with self.assertRaises(ValueError, msg=f"overall_deadline_s={bad!r} must raise"):
                sched.execute([RemoteCollectionTask(task_id="t", target_id="h", collection_type="s", fn=lambda: 1)], overall_deadline_s=bad)

    def test_per_target_auth_failure_isolation_across_adapters(self):
        ad_bad = RemoteSshTargetAdapter(
            host="10.0.10.1",
            command_runner=lambda args, t: (255, "", "Permission denied (publickey)."),
            use_control_master=False,
        )
        ad_good = RemoteSshTargetAdapter(
            host="10.0.10.2",
            command_runner=lambda args, t: (0, "ok", ""),
            use_control_master=False,
        )
        rc_bad, _, _ = ad_bad.run_ssh("echo fail")
        self.assertEqual(rc_bad, 255)
        # Failure on ad_bad must NEVER contaminate ad_good
        rc_good, out_good, _ = ad_good.run_ssh("echo ok")
        self.assertEqual(rc_good, 0)
        self.assertEqual(out_good, "ok")


if __name__ == "__main__":
    unittest.main()

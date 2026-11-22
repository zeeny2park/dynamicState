"""Bounded, dependency-aware adaptive parallel scheduler for remote diagnostics collection.

Hardened Deadline & Cancellation Contract:
- Monotonic clock exclusively for all elapsed times and deadlines.
- Effective task deadline = min(task_deadline, overall_deadline); never reset by child calls.
- Task-level timeout_s and overall_deadline_s are strictly validated and enforced.
- Active execution context propagates (effective_deadline, cancel_event, cancel_hook_registrar)
  into worker threads so RemoteSshTargetAdapter terminates running subprocess groups immediately
  on timeout or cancellation.
- Retry backoff uses cancel_event.wait(min(backoff, remaining_budget)) and never exceeds budget.
- Executor shutdown uses wait=False when workers are abandoned after timeout/cancellation so the
  caller returns promptly within deadline tolerance.
- Finalized task results are immutable snapshots; late worker completions cannot mutate results.
"""

from __future__ import annotations

import contextlib
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
import math
import threading
import time
from typing import Any, Callable, Dict, Iterable, List, Optional, Set, Tuple

from extractor.diagnostic_performance import CollectionOperationRecord

STATUS_COMPLETE = "COMPLETE"
STATUS_PARTIAL = "PARTIAL"
STATUS_FAILED = "FAILED"
STATUS_CANCELLED = "CANCELLED"
STATUS_TIMED_OUT = "TIMED_OUT"
STATUS_SKIPPED_DEPENDENCY = "SKIPPED_DEPENDENCY"

NON_RETRYABLE_ERRORS = frozenset({"PERMISSION_DENIED", "INVALID_DATA", "CANCELLED"})

_EXEC_CTX = threading.local()


def get_active_execution_context() -> Tuple[Optional[float], Optional[threading.Event], Optional[Callable[[Callable[[], None]], Callable[[], None]]]]:
    """Returns (effective_deadline_monotonic, cancel_event, register_cancel_hook) for current worker thread."""
    return (
        getattr(_EXEC_CTX, "deadline", None),
        getattr(_EXEC_CTX, "cancel_event", None),
        getattr(_EXEC_CTX, "register_cancel_hook", None),
    )


@contextlib.contextmanager
def _worker_execution_scope(
    deadline: Optional[float],
    cancel_event: Optional[threading.Event],
    register_cancel_hook: Optional[Callable[[Callable[[], None]], Callable[[], None]]],
):
    prev_dl = getattr(_EXEC_CTX, "deadline", None)
    prev_ce = getattr(_EXEC_CTX, "cancel_event", None)
    prev_rh = getattr(_EXEC_CTX, "register_cancel_hook", None)
    _EXEC_CTX.deadline = deadline
    _EXEC_CTX.cancel_event = cancel_event
    _EXEC_CTX.register_cancel_hook = register_cancel_hook
    try:
        yield
    finally:
        _EXEC_CTX.deadline = prev_dl
        _EXEC_CTX.cancel_event = prev_ce
        _EXEC_CTX.register_cancel_hook = prev_rh


def _validate_positive_finite(val: Any, name: str) -> float:
    if isinstance(val, bool):
        raise ValueError(f"Invalid {name} '{val}': boolean is not allowed")
    try:
        fval = float(val)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"Invalid {name} '{val}': must be a positive finite number") from exc
    if not math.isfinite(fval) or fval <= 0:
        raise ValueError(f"Invalid {name} '{val}': must be a positive finite number")
    return fval


def _classify_exception(exc: BaseException) -> str:
    msg = str(exc or "").lower()
    if isinstance(exc, TimeoutError) or "timed out" in msg or "deadline exceeded" in msg:
        return "TIMEOUT"
    if "cancelled" in msg or "canceled" in msg:
        return "CANCELLED"
    if "permission denied" in msg or "authentication failed" in msg or "publickey" in msg:
        return "PERMISSION_DENIED"
    if "invalid_data" in msg or "invalid data" in msg:
        return "INVALID_DATA"
    if "unavailable" in msg or "no such" in msg:
        return "UNAVAILABLE"
    return "TRANSPORT_ERROR"


@dataclass(frozen=True)
class RemoteCollectionTask:
    """Unit of remote diagnostic collection scheduled by AdaptiveRemoteCollectionScheduler."""

    task_id: str
    target_id: str
    collection_type: str
    fn: Callable[[], Any]
    depends_on: Tuple[str, ...] = ()
    timeout_s: Optional[float] = None
    max_retries: int = 0
    retry_backoff_s: float = 0.02
    required: bool = True


@dataclass
class RemoteTaskResult:
    """Structured outcome for a single scheduled remote collection task."""

    task_id: str
    target_id: str
    collection_type: str
    status: str
    value: Any = None
    error: Optional[str] = None
    error_classification: str = "OK"
    retry_count: int = 0
    start_monotonic: float = 0.0
    end_monotonic: float = 0.0
    elapsed_s: float = 0.0
    payload_bytes: int = 0
    result_count: int = 0

    def to_operation_record(self) -> CollectionOperationRecord:
        return CollectionOperationRecord(
            operation_name=self.task_id,
            target_identity=self.target_id,
            collection_type=self.collection_type,
            start_monotonic=self.start_monotonic,
            end_monotonic=self.end_monotonic,
            elapsed_s=self.elapsed_s,
            status=self.status,
            retry_count=self.retry_count,
            payload_bytes=self.payload_bytes,
            result_count=self.result_count,
            error_classification=self.error_classification,
        )


@dataclass
class RemoteBatchResult:
    """Aggregated outcome of a bounded parallel remote collection batch."""

    status: str
    results: Dict[str, RemoteTaskResult] = field(default_factory=dict)
    total_elapsed_s: float = 0.0
    peak_concurrency: int = 0
    effective_concurrency_final: int = 0
    cancelled: bool = False
    timed_out: bool = False

    @property
    def succeeded_count(self) -> int:
        return sum(1 for r in self.results.values() if r.status == STATUS_COMPLETE)

    @property
    def failed_count(self) -> int:
        return sum(1 for r in self.results.values() if r.status in (STATUS_FAILED, STATUS_SKIPPED_DEPENDENCY))

    @property
    def timed_out_count(self) -> int:
        return sum(1 for r in self.results.values() if r.status == STATUS_TIMED_OUT)

    @property
    def cancelled_count(self) -> int:
        return sum(1 for r in self.results.values() if r.status == STATUS_CANCELLED)

    def to_operation_records(self) -> List[CollectionOperationRecord]:
        return [r.to_operation_record() for r in self.results.values()]


class AdaptiveRemoteCollectionScheduler:
    """Dependency-aware, bounded-concurrency scheduler with deterministic adaptive throttling."""

    MAX_WORKERS_CEILING = 16

    def __init__(
        self,
        max_workers: int = 4,
        min_workers: int = 1,
        throttle_on_failures: int = 2,
        restore_on_successes: int = 3,
    ) -> None:
        if isinstance(max_workers, bool) or not isinstance(max_workers, int) or max_workers < 1:
            raise ValueError(f"max_workers must be integer >= 1, got {max_workers!r}")
        if isinstance(min_workers, bool) or not isinstance(min_workers, int) or min_workers < 1:
            raise ValueError(f"min_workers must be integer >= 1, got {min_workers!r}")
        self.max_workers = min(max_workers, self.MAX_WORKERS_CEILING)
        self.min_workers = min(min_workers, self.max_workers)
        self.throttle_on_failures = max(1, int(throttle_on_failures))
        self.restore_on_successes = max(1, int(restore_on_successes))
        self._cancel_event = threading.Event()
        self._hooks_lock = threading.Lock()
        self._cancel_hooks: Set[Callable[[], None]] = set()

    def register_cancel_hook(self, hook: Callable[[], None]) -> Callable[[], None]:
        """Registers a termination hook invoked immediately on cancel(); returns an unregister callable."""
        with self._hooks_lock:
            self._cancel_hooks.add(hook)
        if self._cancel_event.is_set():
            try:
                hook()
            except Exception:  # noqa: BLE001
                pass

        def _unregister() -> None:
            with self._hooks_lock:
                self._cancel_hooks.discard(hook)

        return _unregister

    def _invoke_cancel_hooks(self) -> None:
        with self._hooks_lock:
            hooks = list(self._cancel_hooks)
        for h in hooks:
            try:
                h()
            except Exception:  # noqa: BLE001
                pass

    def cancel(self) -> None:
        """Signals cancellation: stops scheduling new tasks, triggers active termination hooks, preserves completed results."""
        self._cancel_event.set()
        self._invoke_cancel_hooks()

    def reset_cancel(self) -> None:
        self._cancel_event.clear()

    @staticmethod
    def _validate_dag(tasks: List[RemoteCollectionTask]) -> Dict[str, RemoteCollectionTask]:
        by_id: Dict[str, RemoteCollectionTask] = {}
        for t in tasks:
            if not t.task_id or t.task_id in by_id:
                raise ValueError(f"Duplicate or empty task_id: {t.task_id!r}")
            if t.timeout_s is not None:
                _validate_positive_finite(t.timeout_s, f"task '{t.task_id}' timeout_s")
            if isinstance(t.retry_backoff_s, bool) or not math.isfinite(float(t.retry_backoff_s)) or float(t.retry_backoff_s) < 0:
                raise ValueError(f"Invalid task '{t.task_id}' retry_backoff_s: {t.retry_backoff_s!r}")
            by_id[t.task_id] = t
        indeg: Dict[str, int] = {tid: 0 for tid in by_id}
        children: Dict[str, List[str]] = {tid: [] for tid in by_id}
        for tid, t in by_id.items():
            for dep in t.depends_on:
                if dep not in by_id:
                    raise ValueError(f"Task '{tid}' depends on unknown task '{dep}'")
                indeg[tid] += 1
                children[dep].append(tid)
        queue = [tid for tid, deg in indeg.items() if deg == 0]
        visited = 0
        while queue:
            cur = queue.pop()
            visited += 1
            for ch in children[cur]:
                indeg[ch] -= 1
                if indeg[ch] == 0:
                    queue.append(ch)
        if visited != len(by_id):
            raise ValueError("Cyclic dependency detected in remote collection tasks")
        return by_id

    def _run_task(
        self,
        task: RemoteCollectionTask,
        effective_deadline: Optional[float],
    ) -> RemoteTaskResult:
        t_start = time.monotonic()
        retries = 0
        last_err = ""
        last_cls = "OK"

        max_attempts = 1 + max(0, int(task.max_retries))
        with _worker_execution_scope(effective_deadline, self._cancel_event, self.register_cancel_hook):
            for attempt in range(max_attempts):
                if self._cancel_event.is_set():
                    now = time.monotonic()
                    return RemoteTaskResult(
                        task_id=task.task_id,
                        target_id=task.target_id,
                        collection_type=task.collection_type,
                        status=STATUS_CANCELLED,
                        error="Cancelled before execution",
                        error_classification="CANCELLED",
                        retry_count=retries,
                        start_monotonic=t_start,
                        end_monotonic=now,
                        elapsed_s=max(0.0, now - t_start),
                    )
                if effective_deadline is not None and time.monotonic() >= effective_deadline:
                    now = time.monotonic()
                    return RemoteTaskResult(
                        task_id=task.task_id,
                        target_id=task.target_id,
                        collection_type=task.collection_type,
                        status=STATUS_TIMED_OUT,
                        error="Effective task/overall deadline exceeded",
                        error_classification="TIMEOUT",
                        retry_count=retries,
                        start_monotonic=t_start,
                        end_monotonic=now,
                        elapsed_s=max(0.0, now - t_start),
                    )
                try:
                    val = task.fn()
                    now = time.monotonic()
                    # Late completion after deadline must NOT be reported as COMPLETE
                    if effective_deadline is not None and now > effective_deadline:
                        return RemoteTaskResult(
                            task_id=task.task_id,
                            target_id=task.target_id,
                            collection_type=task.collection_type,
                            status=STATUS_TIMED_OUT,
                            error="Task completed after its execution budget expired",
                            error_classification="TIMEOUT",
                            retry_count=retries,
                            start_monotonic=t_start,
                            end_monotonic=now,
                            elapsed_s=max(0.0, now - t_start),
                        )
                    payload_b = len(val) if isinstance(val, (bytes, bytearray, str)) else 0
                    res_cnt = len(val) if isinstance(val, (list, dict, tuple, set)) else (1 if val is not None else 0)
                    return RemoteTaskResult(
                        task_id=task.task_id,
                        target_id=task.target_id,
                        collection_type=task.collection_type,
                        status=STATUS_COMPLETE,
                        value=val,
                        error=None,
                        error_classification="OK",
                        retry_count=retries,
                        start_monotonic=t_start,
                        end_monotonic=now,
                        elapsed_s=max(0.0, now - t_start),
                        payload_bytes=payload_b,
                        result_count=res_cnt,
                    )
                except Exception as exc:  # noqa: BLE001
                    last_err = str(exc)
                    last_cls = _classify_exception(exc)
                    if self._cancel_event.is_set() or last_cls == "CANCELLED":
                        now = time.monotonic()
                        return RemoteTaskResult(
                            task_id=task.task_id,
                            target_id=task.target_id,
                            collection_type=task.collection_type,
                            status=STATUS_CANCELLED,
                            error=last_err or "Cancelled",
                            error_classification="CANCELLED",
                            retry_count=retries,
                            start_monotonic=t_start,
                            end_monotonic=now,
                            elapsed_s=max(0.0, now - t_start),
                        )
                    if last_cls in NON_RETRYABLE_ERRORS:
                        break
                    if attempt + 1 < max_attempts:
                        backoff = float(task.retry_backoff_s)
                        if effective_deadline is not None:
                            rem = effective_deadline - time.monotonic()
                            if rem <= backoff or rem <= 0.0:
                                last_cls = "TIMEOUT"
                                last_err = "Remaining budget insufficient for retry backoff"
                                break
                            backoff = min(backoff, rem)
                        retries += 1
                        if backoff > 0.0:
                            # Wakes immediately on cancel() and never exceeds remaining budget
                            cancelled_during_wait = self._cancel_event.wait(timeout=backoff)
                            if cancelled_during_wait:
                                now = time.monotonic()
                                return RemoteTaskResult(
                                    task_id=task.task_id,
                                    target_id=task.target_id,
                                    collection_type=task.collection_type,
                                    status=STATUS_CANCELLED,
                                    error="Cancelled during retry backoff",
                                    error_classification="CANCELLED",
                                    retry_count=retries,
                                    start_monotonic=t_start,
                                    end_monotonic=now,
                                    elapsed_s=max(0.0, now - t_start),
                                )
                            if effective_deadline is not None and time.monotonic() >= effective_deadline:
                                last_cls = "TIMEOUT"
                                last_err = "Deadline expired during retry backoff"
                                break

        now = time.monotonic()
        final_status = STATUS_TIMED_OUT if last_cls == "TIMEOUT" else STATUS_FAILED
        return RemoteTaskResult(
            task_id=task.task_id,
            target_id=task.target_id,
            collection_type=task.collection_type,
            status=final_status,
            error=last_err,
            error_classification=last_cls,
            retry_count=retries,
            start_monotonic=t_start,
            end_monotonic=now,
            elapsed_s=max(0.0, now - t_start),
        )

    def execute(
        self,
        tasks: Iterable[RemoteCollectionTask],
        overall_deadline_s: Optional[float] = None,
    ) -> RemoteBatchResult:
        """Executes tasks with bounded adaptive concurrency, strict task/overall deadlines, and non-blocking shutdown."""
        task_list = list(tasks)
        t_batch_start = time.monotonic()
        if overall_deadline_s is not None:
            overall_deadline: Optional[float] = t_batch_start + _validate_positive_finite(
                overall_deadline_s, "overall_deadline_s"
            )
        else:
            overall_deadline = None

        if not task_list:
            return RemoteBatchResult(
                status=STATUS_CANCELLED if self._cancel_event.is_set() else STATUS_COMPLETE,
                results={},
                total_elapsed_s=0.0,
                peak_concurrency=0,
                effective_concurrency_final=self.max_workers,
                cancelled=self._cancel_event.is_set(),
            )

        by_id = self._validate_dag(task_list)
        pending: Set[str] = set(by_id.keys())
        # running maps Future -> (task_id, submit_monotonic, effective_deadline_or_None)
        running: Dict[Future, Tuple[str, float, Optional[float]]] = {}
        results: Dict[str, RemoteTaskResult] = {}

        effective_limit = self.max_workers
        consecutive_failures = 0
        consecutive_successes = 0
        peak_concurrency = 0
        hit_timeout = False
        abandoned_workers = False

        pool = ThreadPoolExecutor(max_workers=self.max_workers)
        try:
            while pending or running:
                # 1. Propagate dependency failures to pending tasks
                progressed = True
                while progressed:
                    progressed = False
                    for tid in list(pending):
                        t = by_id[tid]
                        failed_deps = [
                            d for d in t.depends_on
                            if d in results and results[d].status != STATUS_COMPLETE
                        ]
                        if failed_deps:
                            now = time.monotonic()
                            results[tid] = RemoteTaskResult(
                                task_id=tid,
                                target_id=t.target_id,
                                collection_type=t.collection_type,
                                status=STATUS_SKIPPED_DEPENDENCY,
                                error=f"Dependency failed: {', '.join(failed_deps)}",
                                error_classification="DEPENDENCY_FAILED",
                                start_monotonic=now,
                                end_monotonic=now,
                                elapsed_s=0.0,
                            )
                            pending.remove(tid)
                            progressed = True

                # 2. Handle cancellation or overall deadline for pending tasks
                now_mono = time.monotonic()
                if self._cancel_event.is_set():
                    for tid in list(pending):
                        t = by_id[tid]
                        results[tid] = RemoteTaskResult(
                            task_id=tid,
                            target_id=t.target_id,
                            collection_type=t.collection_type,
                            status=STATUS_CANCELLED,
                            error="Batch cancelled before task start",
                            error_classification="CANCELLED",
                            start_monotonic=now_mono,
                            end_monotonic=now_mono,
                            elapsed_s=0.0,
                        )
                        pending.remove(tid)
                elif overall_deadline is not None and now_mono >= overall_deadline:
                    hit_timeout = True
                    for tid in list(pending):
                        t = by_id[tid]
                        results[tid] = RemoteTaskResult(
                            task_id=tid,
                            target_id=t.target_id,
                            collection_type=t.collection_type,
                            status=STATUS_TIMED_OUT,
                            error="Overall collection deadline exceeded before start",
                            error_classification="TIMEOUT",
                            start_monotonic=now_mono,
                            end_monotonic=now_mono,
                            elapsed_s=0.0,
                        )
                        pending.remove(tid)

                # 3. Schedule ready tasks up to effective_limit
                if pending and not self._cancel_event.is_set():
                    ready = sorted(
                        tid for tid in pending
                        if all(d in results and results[d].status == STATUS_COMPLETE for d in by_id[tid].depends_on)
                    )
                    for tid in ready:
                        if len(running) >= effective_limit:
                            break
                        t_sub = time.monotonic()
                        if overall_deadline is not None and t_sub >= overall_deadline:
                            hit_timeout = True
                            break
                        task_obj = by_id[tid]
                        task_dl = (t_sub + float(task_obj.timeout_s)) if task_obj.timeout_s is not None else None
                        dls = [d for d in (task_dl, overall_deadline) if d is not None]
                        eff_dl = min(dls) if dls else None
                        pending.remove(tid)
                        fut = pool.submit(self._run_task, task_obj, eff_dl)
                        running[fut] = (tid, t_sub, eff_dl)
                        if len(running) > peak_concurrency:
                            peak_concurrency = len(running)

                if not running:
                    break

                # 4. Compute exact next wake-up timeout (min across overall_deadline, running task deadlines, and cancel poll)
                now_mono = time.monotonic()
                deadlines_to_watch = [dl for (_, _, dl) in running.values() if dl is not None]
                if overall_deadline is not None:
                    deadlines_to_watch.append(overall_deadline)
                if deadlines_to_watch:
                    wait_timeout = min(0.02, max(0.005, min(deadlines_to_watch) - now_mono))
                else:
                    wait_timeout = 0.02  # periodic wake to observe cancel() promptly

                done, _ = wait(list(running.keys()), timeout=wait_timeout, return_when=FIRST_COMPLETED)

                for fut in done:
                    tid, _, _ = running.pop(fut)
                    res = fut.result()
                    if tid not in results:
                        results[tid] = res
                    if res.status == STATUS_COMPLETE:
                        consecutive_successes += 1
                        consecutive_failures = 0
                        if consecutive_successes >= self.restore_on_successes and effective_limit < self.max_workers:
                            effective_limit += 1
                            consecutive_successes = 0
                    elif res.error_classification in ("TIMEOUT", "TRANSPORT_ERROR"):
                        consecutive_failures += 1
                        consecutive_successes = 0
                        if consecutive_failures >= self.throttle_on_failures and effective_limit > self.min_workers:
                            effective_limit -= 1
                            consecutive_failures = 0

                # 5. Evict any running tasks whose effective deadline expired or when batch cancelled
                now_mono = time.monotonic()
                if self._cancel_event.is_set() and running:
                    self._invoke_cancel_hooks()
                    # Brief grace wait (20ms) for cooperative/subprocess-killed workers to finish cleanly
                    done_grace, _ = wait(list(running.keys()), timeout=0.02)
                    for fut in done_grace:
                        tid, _, _ = running.pop(fut)
                        if tid not in results:
                            results[tid] = fut.result()
                    for fut, (tid, t_sub, _) in list(running.items()):
                        fut.cancel()
                        abandoned_workers = True
                        if tid not in results:
                            t = by_id[tid]
                            results[tid] = RemoteTaskResult(
                                task_id=tid,
                                target_id=t.target_id,
                                collection_type=t.collection_type,
                                status=STATUS_CANCELLED,
                                error="Cancelled while running",
                                error_classification="CANCELLED",
                                start_monotonic=t_sub,
                                end_monotonic=now_mono,
                                elapsed_s=max(0.0, now_mono - t_sub),
                            )
                        running.pop(fut, None)
                    continue

                expired_futs = [
                    (fut, tid, t_sub)
                    for fut, (tid, t_sub, eff_dl) in running.items()
                    if eff_dl is not None and now_mono >= eff_dl
                ]
                for fut, tid, t_sub in expired_futs:
                    hit_timeout = True
                    fut.cancel()
                    abandoned_workers = True
                    if tid not in results:
                        t = by_id[tid]
                        results[tid] = RemoteTaskResult(
                            task_id=tid,
                            target_id=t.target_id,
                            collection_type=t.collection_type,
                            status=STATUS_TIMED_OUT,
                            error="Task or overall deadline exceeded while running",
                            error_classification="TIMEOUT",
                            start_monotonic=t_sub,
                            end_monotonic=now_mono,
                            elapsed_s=max(0.0, now_mono - t_sub),
                        )
                    running.pop(fut, None)
                    consecutive_failures += 1
                    consecutive_successes = 0
                    if consecutive_failures >= self.throttle_on_failures and effective_limit > self.min_workers:
                        effective_limit -= 1
                        consecutive_failures = 0

                if overall_deadline is not None and now_mono >= overall_deadline and not running:
                    hit_timeout = True
        finally:
            # Critical: NEVER block caller indefinitely waiting on abandoned timed-out/cancelled workers
            pool.shutdown(wait=(not abandoned_workers), cancel_futures=True)

        # Snapshot finalized results so late worker threads can never mutate returned batch
        final_results = dict(results)
        total_elapsed = max(0.0, time.monotonic() - t_batch_start)
        succeeded = sum(1 for r in final_results.values() if r.status == STATUS_COMPLETE)
        timed_out_cnt = sum(1 for r in final_results.values() if r.status == STATUS_TIMED_OUT)
        cancelled_cnt = sum(1 for r in final_results.values() if r.status == STATUS_CANCELLED)
        total = len(final_results)

        if succeeded == total:
            batch_status = STATUS_COMPLETE
        elif succeeded > 0:
            batch_status = STATUS_PARTIAL
        elif self._cancel_event.is_set() or cancelled_cnt == total:
            batch_status = STATUS_CANCELLED
        elif hit_timeout or timed_out_cnt > 0:
            batch_status = STATUS_TIMED_OUT
        else:
            batch_status = STATUS_FAILED

        return RemoteBatchResult(
            status=batch_status,
            results=final_results,
            total_elapsed_s=total_elapsed,
            peak_concurrency=peak_concurrency,
            effective_concurrency_final=effective_limit,
            cancelled=self._cancel_event.is_set(),
            timed_out=hit_timeout or timed_out_cnt > 0,
        )

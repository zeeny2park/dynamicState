"""Bounded, dependency-aware adaptive parallel scheduler for remote diagnostics collection.

Provides:
- Explicit DAG dependency scheduling (independent tasks run concurrently; dependent tasks preserve ordering)
- Bounded concurrency (configurable max_workers, hard ceiling, zero unbounded thread creation)
- Deterministic adaptive concurrency throttling on transient failures/timeouts
- Per-task failure isolation & partial result preservation (COMPLETE / PARTIAL / FAILED / CANCELLED / TIMED_OUT)
- Coherent overall deadline budget propagation (never resets nested timeout budgets)
- Failure-specific bounded retry (never retries permanent auth/permission failures)
- Clean cancellation preserving already-completed evidence
"""

from __future__ import annotations

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


def _classify_exception(exc: BaseException) -> str:
    msg = str(exc or "").lower()
    if isinstance(exc, TimeoutError) or "timed out" in msg or "deadline exceeded" in msg:
        return "TIMEOUT"
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

    def cancel(self) -> None:
        """Signals cancellation: stops scheduling new tasks while preserving completed results."""
        self._cancel_event.set()

    def reset_cancel(self) -> None:
        self._cancel_event.clear()

    @staticmethod
    def _validate_dag(tasks: List[RemoteCollectionTask]) -> Dict[str, RemoteCollectionTask]:
        by_id: Dict[str, RemoteCollectionTask] = {}
        for t in tasks:
            if not t.task_id or t.task_id in by_id:
                raise ValueError(f"Duplicate or empty task_id: {t.task_id!r}")
            by_id[t.task_id] = t
        # Detect missing dependencies and cycles via Kahn's algorithm
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
        overall_deadline: Optional[float],
    ) -> RemoteTaskResult:
        t_start = time.monotonic()
        retries = 0
        last_err = ""
        last_cls = "OK"

        max_attempts = 1 + max(0, int(task.max_retries))
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
            if overall_deadline is not None and time.monotonic() >= overall_deadline:
                now = time.monotonic()
                return RemoteTaskResult(
                    task_id=task.task_id,
                    target_id=task.target_id,
                    collection_type=task.collection_type,
                    status=STATUS_TIMED_OUT,
                    error="Overall collection deadline exceeded",
                    error_classification="TIMEOUT",
                    retry_count=retries,
                    start_monotonic=t_start,
                    end_monotonic=now,
                    elapsed_s=max(0.0, now - t_start),
                )
            try:
                val = task.fn()
                now = time.monotonic()
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
                # Never retry permanent errors (e.g., PERMISSION_DENIED, INVALID_DATA)
                if last_cls in NON_RETRYABLE_ERRORS:
                    break
                if attempt + 1 < max_attempts:
                    if overall_deadline is not None:
                        rem = overall_deadline - time.monotonic()
                        if rem <= task.retry_backoff_s:
                            break
                    retries += 1
                    if task.retry_backoff_s > 0:
                        time.sleep(task.retry_backoff_s)

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
        """Executes tasks with bounded adaptive concurrency, dependency ordering, and failure isolation."""
        task_list = list(tasks)
        t_batch_start = time.monotonic()
        if not task_list:
            return RemoteBatchResult(
                status=STATUS_COMPLETE,
                results={},
                total_elapsed_s=0.0,
                peak_concurrency=0,
                effective_concurrency_final=self.max_workers,
            )

        if overall_deadline_s is not None:
            if isinstance(overall_deadline_s, bool) or not math.isfinite(float(overall_deadline_s)) or float(overall_deadline_s) <= 0:
                raise ValueError(f"overall_deadline_s must be positive finite number, got {overall_deadline_s!r}")
            overall_deadline: Optional[float] = t_batch_start + float(overall_deadline_s)
        else:
            overall_deadline = None

        by_id = self._validate_dag(task_list)
        pending: Set[str] = set(by_id.keys())
        running: Dict[Future, str] = {}
        results: Dict[str, RemoteTaskResult] = {}

        effective_limit = self.max_workers
        consecutive_failures = 0
        consecutive_successes = 0
        peak_concurrency = 0
        hit_timeout = False

        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
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

                # 2. Check cancellation or overall deadline for unscheduled pending tasks
                if self._cancel_event.is_set():
                    now = time.monotonic()
                    for tid in list(pending):
                        t = by_id[tid]
                        results[tid] = RemoteTaskResult(
                            task_id=tid,
                            target_id=t.target_id,
                            collection_type=t.collection_type,
                            status=STATUS_CANCELLED,
                            error="Batch cancelled",
                            error_classification="CANCELLED",
                            start_monotonic=now,
                            end_monotonic=now,
                            elapsed_s=0.0,
                        )
                        pending.remove(tid)
                elif overall_deadline is not None and time.monotonic() >= overall_deadline:
                    hit_timeout = True
                    now = time.monotonic()
                    for tid in list(pending):
                        t = by_id[tid]
                        results[tid] = RemoteTaskResult(
                            task_id=tid,
                            target_id=t.target_id,
                            collection_type=t.collection_type,
                            status=STATUS_TIMED_OUT,
                            error="Overall collection deadline exceeded before start",
                            error_classification="TIMEOUT",
                            start_monotonic=now,
                            end_monotonic=now,
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
                        if overall_deadline is not None and time.monotonic() >= overall_deadline:
                            hit_timeout = True
                            break
                        pending.remove(tid)
                        fut = pool.submit(self._run_task, by_id[tid], overall_deadline)
                        running[fut] = tid
                        if len(running) > peak_concurrency:
                            peak_concurrency = len(running)

                if not running:
                    break

                # 4. Wait for at least one task to complete (bounded by overall deadline)
                wait_timeout = None
                if overall_deadline is not None:
                    wait_timeout = max(0.01, overall_deadline - time.monotonic())
                done, _ = wait(list(running.keys()), timeout=wait_timeout, return_when=FIRST_COMPLETED)

                if not done and overall_deadline is not None and time.monotonic() >= overall_deadline:
                    hit_timeout = True
                    # Do not block indefinitely on hung workers; record TIMED_OUT for remaining running tasks
                    now = time.monotonic()
                    for fut, tid in list(running.items()):
                        fut.cancel()
                        t = by_id[tid]
                        results[tid] = RemoteTaskResult(
                            task_id=tid,
                            target_id=t.target_id,
                            collection_type=t.collection_type,
                            status=STATUS_TIMED_OUT,
                            error="Overall collection deadline exceeded while running",
                            error_classification="TIMEOUT",
                            start_monotonic=t_batch_start,
                            end_monotonic=now,
                            elapsed_s=max(0.0, now - t_batch_start),
                        )
                        running.pop(fut, None)
                    break

                for fut in done:
                    tid = running.pop(fut)
                    res = fut.result()
                    results[tid] = res
                    # Deterministic adaptive concurrency adjustment
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

        total_elapsed = max(0.0, time.monotonic() - t_batch_start)
        succeeded = sum(1 for r in results.values() if r.status == STATUS_COMPLETE)
        timed_out_cnt = sum(1 for r in results.values() if r.status == STATUS_TIMED_OUT)
        cancelled_cnt = sum(1 for r in results.values() if r.status == STATUS_CANCELLED)
        total = len(results)

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
            results=results,
            total_elapsed_s=total_elapsed,
            peak_concurrency=peak_concurrency,
            effective_concurrency_final=effective_limit,
            cancelled=self._cancel_event.is_set(),
            timed_out=hit_timeout or timed_out_cnt > 0,
        )

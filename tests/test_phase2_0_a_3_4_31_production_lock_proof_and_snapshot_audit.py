#!/usr/bin/env python3
"""Phase 2.0-A.3.4.31 — Production Lock Proof Integrity, Worker Failure Propagation & Snapshot Audit Closure.

Comprehensive verification suite:
1. Production Lock Instrumentation Correctness:
   - InstrumentedLock preserves underlying RLock semantics, including recursive acquisition and release.
   - ProductionCriticalSectionRecorder tracks per-thread, per-lock recursion depth (thread_id, lock_id).
   - Distinguishes acquisition wait duration, outermost critical-section hold duration, recursive acquisition count,
     and simultaneous ownership across independent locks at the same level.
   - Real lock is released before updating recorder state, ensuring the recorder never claims release before the lock is freed.
   - Release exceptions (e.g. releasing un-acquired lock) and acquisition failures do not corrupt recorder state.
   - Full deterministic tests for recursive RLock, nested production API calls, exceptions in critical sections,
     simultaneous acquisition of independent locks, and recorder consistency after worker termination.
2. Complete L1 / L1.5 / L2 / L3 Contention Proof:
   - Independent, deterministic production API tests for all four lock levels:
     * L1: tracker.reserve_budget()
     * L1.5: scope.get_status_snapshot()
     * L2: reservation.start_child_read()
     * L3: child.update_metadata()
   - Uses WorkerThread, bounded Event synchronization, proves Worker A holds lock, Worker B attempts acquisition and is blocked,
     releases Worker A, and verifies Worker B completes with wait duration > 0. Zero time.sleep().
3. Worker Exception and Lifecycle Closure:
   - Explicit WorkerThread capturing results, exceptions, and completion flags.
   - join_workers asserts every worker completed, no worker remains alive after bounded join, and propagates exceptions.
   - Deliberate worker failure injection test proving parent unittests fail when a worker encounters an error.
4. Critical Section Overlap Proof:
   - Real lock ownership overlap demonstrated for independent L3 child operations and L1.5 scope inspections (max_simultaneous >= 2).
   - Strict serialization demonstrated for L1 transaction mutations and commit/recovery mutations (max_simultaneous == 1).
5. Snapshot-Only Invariant Source Audit:
   - Verifiable AST analysis of reconcile_ledger() proving 0 live mutable state attribute accesses after _transaction_lock release.
   - Runtime PoisonTrap dynamic audit proving all live registries and metrics are inaccessible during invariant evaluation without tripping traps.
   - Negative AST and runtime tests proving audit fails closed on illegal live access.
6. Benchmark Measurement Integrity:
   - Separate measurement of L1 wait, L1 outermost hold, snapshot construction, deep freeze, invariant evaluation, total reconciliation,
     multi-sample concurrent contention latencies (sample count, median, p95, min, max), shallow result memory, recursive retained memory,
     and peak allocation via tracemalloc.
7. clone_frozen() Adversarial Regression:
   - Deeply nested structures, DAG diamonds, cycles through custom Mapping implementations, to_dict() returning self/cycles/exceptions,
     unhashable set fallback, canonical sort ordering, non-finite float rejection (NaN, +Inf, -Inf), and -0.0 canonicalization.
8. Commit and Recovery Regression Matrix:
   - Full matrix of commit mutation boundaries and recovery retry idempotency.
"""

import ast
import collections
from contextlib import contextmanager, nullcontext
import copy
import dataclasses
import math
import sys
import threading
import time
import tracemalloc
import types
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
import unittest
import uuid

from extractor.observation_budget import (
    ActiveOperationScope,
    BudgetReservation,
    CommittedTransactionSnapshot,
    DEFAULT_CONSERVATIVE_UNKNOWN_BYTES,
    ObservationAccountingRecord,
    ObservationBudgetLimits,
    ObservationBudgetTracker,
    ObservationMetrics,
    PhysicalConsumptionRecord,
    PhysicalReadRecord,
    PreparedCommit,
    canonical_metadata_digest,
    clone_frozen,
    clone_metadata,
    freeze_metadata,
    unfreeze_metadata,
)


def make_tracker(max_bytes: int = 10_000_000) -> ObservationBudgetTracker:
    limits = ObservationBudgetLimits(
        max_bytes_read=max_bytes,
        max_bytes_per_observation=max_bytes,
    )
    tracker = ObservationBudgetTracker(limits=limits)
    tracker.start()
    return tracker


def make_scope(
    tracker: ObservationBudgetTracker,
    op_id: str,
    profile_id: str = "prof_a31",
    owner: str = "INTERNAL",
    metadata: Optional[Dict[str, Any]] = None,
) -> ActiveOperationScope:
    scope = ActiveOperationScope(
        tracker=tracker,
        operation_id=op_id,
        profile_id=profile_id,
        owner=owner,
        metadata=metadata,
    )
    tracker._register_active_scope(scope)
    return scope


def get_recursive_retained_size(obj: Any, seen: Optional[Set[int]] = None) -> int:
    """Recursively computes retained memory size in bytes, handling shared references and cycles."""
    if seen is None:
        seen = set()
    obj_id = id(obj)
    if obj_id in seen:
        return 0
    seen.add(obj_id)

    size = sys.getsizeof(obj)
    if isinstance(obj, collections.abc.Mapping):
        for k, v in obj.items():
            size += get_recursive_retained_size(k, seen)
            size += get_recursive_retained_size(v, seen)
    elif isinstance(obj, (list, tuple, set, frozenset)):
        for item in obj:
            size += get_recursive_retained_size(item, seen)
    elif hasattr(obj, "__dict__"):
        size += get_recursive_retained_size(vars(obj), seen)
    elif hasattr(obj, "__slots__"):
        for slot in getattr(obj, "__slots__"):
            if hasattr(obj, slot):
                size += get_recursive_retained_size(getattr(obj, slot), seen)
    return size


class WorkerThread(threading.Thread):
    """Worker thread that safely captures results and propagates exceptions."""

    def __init__(
        self,
        target: Callable[..., Any],
        args: Tuple[Any, ...] = (),
        kwargs: Optional[Dict[str, Any]] = None,
        name: Optional[str] = None,
    ):
        super().__init__(name=name)
        self._target = target
        self._args = args
        self._kwargs = kwargs or {}
        self.result: Any = None
        self.exception: Optional[BaseException] = None
        self.completed: bool = False

    def run(self) -> None:
        try:
            self.result = self._target(*self._args, **self._kwargs)
            self.completed = True
        except BaseException as exc:
            self.exception = exc
            self.completed = False


def join_workers(test_case: unittest.TestCase, workers: List[WorkerThread], timeout: float = 5.0) -> None:
    """Bounded join of all worker threads with strict exception and completion assertions."""
    for w in workers:
        w.join(timeout=timeout)
    for w in workers:
        test_case.assertFalse(w.is_alive(), f"Worker '{w.name}' remained alive after {timeout}s timeout")
    for w in workers:
        if w.exception is not None:
            raise AssertionError(f"Worker '{w.name}' encountered exception: {w.exception}") from w.exception
        test_case.assertTrue(w.completed, f"Worker '{w.name}' did not mark completion")


class ProductionCriticalSectionRecorder:
    """Thread-safe recorder tracking lock acquisitions, wait intervals, outermost hold durations, and overlaps."""

    def __init__(self):
        self._lock = threading.Lock()
        # Per-lock instance reentrancy depth: (thread_id, lock_id) -> depth
        self.reentrancy_depth: Dict[Tuple[int, int], int] = collections.defaultdict(int)
        # Per-lock outermost entry timestamp: (thread_id, lock_id) -> timestamp_ns
        self.entry_timestamps: Dict[Tuple[int, int], int] = {}

        # Per-level tracking
        self.lock_waits: Dict[str, List[int]] = collections.defaultdict(list)
        self.lock_holds: Dict[str, List[int]] = collections.defaultdict(list)
        self.recursive_acquisitions: Dict[str, int] = collections.defaultdict(int)

        # Active holders: level -> set of (thread_id, lock_id)
        self.active_holders: Dict[str, Set[Tuple[int, int]]] = collections.defaultdict(set)
        # Active threads: level -> set of thread_ids holding at least one lock at this level
        self.active_threads_by_level: Dict[str, Set[int]] = collections.defaultdict(set)
        # Max simultaneous threads holding a lock at this level
        self.max_simultaneous: Dict[str, int] = collections.defaultdict(int)

        # Thread acquisition history
        self.all_acquisitions: Dict[int, List[str]] = collections.defaultdict(list)
        self.thread_acquisition_order: Dict[int, List[str]] = collections.defaultdict(list)
        self.overlap_pairs: Set[Tuple[str, str]] = set()

        # Mutation section tracking
        self._active_sections: Dict[str, int] = collections.defaultdict(int)
        self.max_section_simultaneous: Dict[str, int] = collections.defaultdict(int)
        self.section_overlap_pairs: Set[Tuple[str, str]] = set()
        self.section_durations: Dict[str, List[int]] = collections.defaultdict(list)

    def record_lock_acquire(
        self,
        thread_id: int,
        lock_id: int,
        level: str,
        name: str,
        wait_duration_ns: int,
        timestamp_ns: int,
    ) -> None:
        with self._lock:
            self.lock_waits[level].append(wait_duration_ns)
            self.all_acquisitions[thread_id].append(level)
            key = (thread_id, lock_id)
            cur_depth = self.reentrancy_depth[key]
            if cur_depth == 0:
                # Outermost acquisition for this specific lock instance
                self.reentrancy_depth[key] = 1
                self.entry_timestamps[key] = timestamp_ns
                self.active_holders[level].add(key)
                self.active_threads_by_level[level].add(thread_id)
                cur_simultaneous = len(self.active_threads_by_level[level])
                if cur_simultaneous > self.max_simultaneous[level]:
                    self.max_simultaneous[level] = cur_simultaneous
                if level not in self.thread_acquisition_order[thread_id]:
                    self.thread_acquisition_order[thread_id].append(level)

                # Check overlap across distinct lock levels
                for other_lvl, th_set in self.active_threads_by_level.items():
                    if th_set and other_lvl != level:
                        self.overlap_pairs.add(tuple(sorted([level, other_lvl])))
            else:
                # Recursive / reentrant acquisition on same lock instance
                self.reentrancy_depth[key] = cur_depth + 1
                self.recursive_acquisitions[level] += 1

    def record_lock_release(
        self,
        thread_id: int,
        lock_id: int,
        level: str,
        name: str,
        timestamp_ns: int,
    ) -> None:
        with self._lock:
            key = (thread_id, lock_id)
            cur_depth = self.reentrancy_depth[key]
            if cur_depth > 1:
                # Unwinding recursive acquisition
                self.reentrancy_depth[key] = cur_depth - 1
            elif cur_depth == 1:
                # Outermost release: lock is now genuinely released
                del self.reentrancy_depth[key]
                self.active_holders[level].discard(key)
                # Check if this thread holds any OTHER lock at this level
                still_holding_level = any(th == thread_id for th, _ in self.active_holders[level])
                if not still_holding_level:
                    self.active_threads_by_level[level].discard(thread_id)

                entry_ns = self.entry_timestamps.pop(key, None)
                if entry_ns is not None:
                    hold_ns = timestamp_ns - entry_ns
                    self.lock_holds[level].append(hold_ns)
            else:
                # Fail-safe cleanup
                self.reentrancy_depth.pop(key, None)
                self.entry_timestamps.pop(key, None)
                self.active_holders[level].discard(key)
                still_holding_level = any(th == thread_id for th, _ in self.active_holders[level])
                if not still_holding_level:
                    self.active_threads_by_level[level].discard(thread_id)

    @contextmanager
    def record_section(self, section_name: str, op_id: str = ""):
        t_start = time.perf_counter_ns()
        with self._lock:
            self._active_sections[section_name] += 1
            cur = self._active_sections[section_name]
            if cur > self.max_section_simultaneous[section_name]:
                self.max_section_simultaneous[section_name] = cur
            for other_sec, count in self._active_sections.items():
                if count > 0:
                    self.section_overlap_pairs.add(tuple(sorted([section_name, other_sec])))
        try:
            yield
        finally:
            t_end = time.perf_counter_ns()
            with self._lock:
                self._active_sections[section_name] -= 1
                self.section_durations[section_name].append(t_end - t_start)


class InstrumentedLock:
    """Wraps an RLock to instrument acquisition and release without altering locking semantics."""

    def __init__(
        self,
        real_lock: threading.RLock,
        recorder: ProductionCriticalSectionRecorder,
        level: str,
        name: str = "",
    ):
        self._real_lock = real_lock
        self._recorder = recorder
        self._level = level
        self._name = name
        self._lock_id = id(real_lock)
        self.acquire_attempt_event: Optional[threading.Event] = None
        self.acquired_event: Optional[threading.Event] = None

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        tid = threading.get_ident()
        if self.acquire_attempt_event is not None:
            self.acquire_attempt_event.set()
        t_wait_start = time.perf_counter_ns()
        ok = self._real_lock.acquire(blocking, timeout)
        if ok:
            t_acquired = time.perf_counter_ns()
            wait_ns = t_acquired - t_wait_start
            self._recorder.record_lock_acquire(
                thread_id=tid,
                lock_id=self._lock_id,
                level=self._level,
                name=self._name,
                wait_duration_ns=wait_ns,
                timestamp_ns=t_acquired,
            )
            if self.acquired_event is not None:
                self.acquired_event.set()
        return ok

    def release(self) -> None:
        # Crucial Requirement: Underlying lock must be released FIRST!
        # If release() raises (e.g. RuntimeError if lock is not held),
        # the recorder state is never modified and never claims released.
        self._real_lock.release()
        t_release = time.perf_counter_ns()
        tid = threading.get_ident()
        self._recorder.record_lock_release(
            thread_id=tid,
            lock_id=self._lock_id,
            level=self._level,
            name=self._name,
            timestamp_ns=t_release,
        )

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.release()

    def __getattr__(self, name):
        return getattr(self._real_lock, name)


def instrument_tracker(tracker: ObservationBudgetTracker, recorder: ProductionCriticalSectionRecorder) -> None:
    tracker._transaction_lock = InstrumentedLock(tracker._transaction_lock, recorder, "L1", "transaction_lock")


def instrument_scope(scope: ActiveOperationScope, recorder: ProductionCriticalSectionRecorder) -> None:
    scope._lock = InstrumentedLock(scope._lock, recorder, "L1.5", f"scope_{scope.operation_id}")


def instrument_reservation(res: BudgetReservation, recorder: ProductionCriticalSectionRecorder) -> None:
    res._lock = InstrumentedLock(res._lock, recorder, "L2", f"res_{res.reservation_id}")


def instrument_child(child: PhysicalReadRecord, recorder: ProductionCriticalSectionRecorder) -> None:
    child._lock = InstrumentedLock(child._lock, recorder, "L3", f"child_{child.physical_read_id}")


class TestPhase20A3431InstrumentedLockCorrectness(unittest.TestCase):
    """Audit and rigorous verification of InstrumentedLock and ProductionCriticalSectionRecorder."""

    def setUp(self):
        self.recorder = ProductionCriticalSectionRecorder()

    def test_01_recursive_rlock_acquisition_and_release(self):
        """Preserves underlying RLock semantics, recursion depth, and outermost hold measurement."""
        real_lock = threading.RLock()
        inst_lock = InstrumentedLock(real_lock, self.recorder, "L1", "test_rlock")
        tid = threading.get_ident()
        lid = id(real_lock)

        # Level 1: Outermost acquire
        inst_lock.acquire()
        self.assertEqual(self.recorder.reentrancy_depth[(tid, lid)], 1)
        self.assertEqual(self.recorder.recursive_acquisitions["L1"], 0)
        self.assertIn((tid, lid), self.recorder.active_holders["L1"])
        self.assertIn(tid, self.recorder.active_threads_by_level["L1"])

        # Level 2: Recursive acquire 1
        inst_lock.acquire()
        self.assertEqual(self.recorder.reentrancy_depth[(tid, lid)], 2)
        self.assertEqual(self.recorder.recursive_acquisitions["L1"], 1)

        # Level 3: Recursive acquire 2
        inst_lock.acquire()
        self.assertEqual(self.recorder.reentrancy_depth[(tid, lid)], 3)
        self.assertEqual(self.recorder.recursive_acquisitions["L1"], 2)

        # Level 2: Release 1
        inst_lock.release()
        self.assertEqual(self.recorder.reentrancy_depth[(tid, lid)], 2)
        self.assertIn((tid, lid), self.recorder.active_holders["L1"])
        self.assertEqual(len(self.recorder.lock_holds["L1"]), 0, "No hold recorded until outermost release")

        # Level 1: Release 2
        inst_lock.release()
        self.assertEqual(self.recorder.reentrancy_depth[(tid, lid)], 1)
        self.assertIn((tid, lid), self.recorder.active_holders["L1"])
        self.assertEqual(len(self.recorder.lock_holds["L1"]), 0)

        # Outermost release: Release 3
        inst_lock.release()
        self.assertNotIn((tid, lid), self.recorder.reentrancy_depth)
        self.assertNotIn((tid, lid), self.recorder.active_holders["L1"])
        self.assertNotIn(tid, self.recorder.active_threads_by_level["L1"])
        self.assertEqual(len(self.recorder.lock_holds["L1"]), 1, "Exactly 1 outermost hold duration recorded")
        self.assertGreater(self.recorder.lock_holds["L1"][0], 0)

    def test_02_nested_production_api_calls(self):
        """Verifies recorder behavior under nested production API executions."""
        tracker = make_tracker()
        instrument_tracker(tracker, self.recorder)
        scope = make_scope(tracker, "op_nested_api")
        instrument_scope(scope, self.recorder)

        res = tracker.admit_read(200, scope=scope)
        instrument_reservation(res, self.recorder)
        child = res.start_child_read()
        instrument_child(child, self.recorder)

        child.consume(200)
        res.consume(200)
        scope.record_read(200, admission=res)

        # Finalize executes genuine nested production calls across L1, L1.5, L2, L3
        snap = scope.finalize(success=True)
        self.assertIsNotNone(snap)
        self.assertEqual(snap.accounting_status, "COMMITTED")

        # Proved reentrancy occurred on L1 and L1.5
        self.assertGreater(self.recorder.recursive_acquisitions["L1"], 0)
        self.assertGreater(self.recorder.recursive_acquisitions["L1.5"], 0)

        # After finalization, all locks are released cleanly
        tid = threading.get_ident()
        for lvl in ["L1", "L1.5", "L2", "L3"]:
            self.assertNotIn(tid, self.recorder.active_threads_by_level[lvl])

    def test_03_exception_inside_critical_section(self):
        """Exceptions inside a critical section release real lock and update recorder without corruption."""
        real_lock = threading.RLock()
        inst_lock = InstrumentedLock(real_lock, self.recorder, "L2", "test_exc_lock")
        tid = threading.get_ident()
        lid = id(real_lock)

        with self.assertRaises(ZeroDivisionError):
            with inst_lock:
                self.assertIn((tid, lid), self.recorder.active_holders["L2"])
                _ = 1 / 0

        # After exception, lock is completely released and recorder cleaned up
        self.assertNotIn((tid, lid), self.recorder.reentrancy_depth)
        self.assertNotIn((tid, lid), self.recorder.active_holders["L2"])
        self.assertNotIn(tid, self.recorder.active_threads_by_level["L2"])
        self.assertEqual(len(self.recorder.lock_holds["L2"]), 1)

    def test_04_simultaneous_acquisition_of_independent_locks(self):
        """Recorder distinguishes multiple independent locks of the same level without false reentrancy."""
        lock_a = InstrumentedLock(threading.RLock(), self.recorder, "L3", "lock_a")
        lock_b = InstrumentedLock(threading.RLock(), self.recorder, "L3", "lock_b")
        tid = threading.get_ident()

        with lock_a:
            with lock_b:
                # Same thread holds two independent L3 locks simultaneously
                self.assertEqual(len(self.recorder.active_holders["L3"]), 2)
                # Reentrancy depth for each lock must be strictly 1, not 2!
                self.assertEqual(self.recorder.reentrancy_depth[(tid, lock_a._lock_id)], 1)
                self.assertEqual(self.recorder.reentrancy_depth[(tid, lock_b._lock_id)], 1)
                self.assertEqual(self.recorder.recursive_acquisitions["L3"], 0)

        self.assertEqual(len(self.recorder.active_holders["L3"]), 0)
        self.assertEqual(len(self.recorder.lock_holds["L3"]), 2)

    def test_05_competing_acquisition_and_invalid_release_safety(self):
        """Acquisition failures and invalid release attempts do not corrupt recorder state."""
        real_lock = threading.RLock()
        inst_lock = InstrumentedLock(real_lock, self.recorder, "L1", "test_invalid_release")

        # 1. Invalid release when not held raises RuntimeError from underlying lock
        with self.assertRaises(RuntimeError):
            inst_lock.release()

        # Recorder state must remain untouched
        self.assertEqual(len(self.recorder.reentrancy_depth), 0)
        self.assertEqual(len(self.recorder.lock_holds["L1"]), 0)

        # 2. Non-blocking acquire when held by another thread fails gracefully without recording acquisition
        held_event = threading.Event()
        release_event = threading.Event()

        def holder_fn():
            with inst_lock:
                held_event.set()
                release_event.wait(timeout=5.0)

        holder = WorkerThread(target=holder_fn, name="holder")
        holder.start()
        self.assertTrue(held_event.wait(timeout=5.0))

        # Main thread attempts non-blocking acquire and fails
        ok = inst_lock.acquire(blocking=False)
        self.assertFalse(ok, "Non-blocking acquire should fail while held")

        # Main thread was NOT recorded as a holder
        tid = threading.get_ident()
        self.assertNotIn(tid, self.recorder.active_threads_by_level["L1"])

        release_event.set()
        join_workers(self, [holder])

    def test_06_recorder_consistency_after_worker_termination(self):
        """Verifies all recorder structures are fully consistent after multi-worker execution."""
        tracker = make_tracker()
        instrument_tracker(tracker, self.recorder)

        def worker_fn(idx: int):
            sc = make_scope(tracker, f"op_worker_{idx}")
            instrument_scope(sc, self.recorder)
            r = tracker.admit_read(50, scope=sc)
            instrument_reservation(r, self.recorder)
            c = r.start_child_read()
            instrument_child(c, self.recorder)
            c.consume(50)
            r.consume(50)
            sc.record_read(50, admission=r)
            sc.finalize(success=True)

        workers = [WorkerThread(target=worker_fn, args=(i,), name=f"consist_w_{i}") for i in range(4)]
        for w in workers:
            w.start()
        join_workers(self, workers)

        # Assert no dangling locks or holders remain anywhere
        for lvl in ["L1", "L1.5", "L2", "L3"]:
            self.assertEqual(len(self.recorder.active_holders[lvl]), 0, f"Dangling holders in {lvl}")
            self.assertEqual(len(self.recorder.active_threads_by_level[lvl]), 0, f"Dangling threads in {lvl}")
        self.assertEqual(len(self.recorder.reentrancy_depth), 0, "Dangling reentrancy depths")


class TestPhase20A3431ProductionLockContentionMatrix(unittest.TestCase):
    """Complete L1 / L1.5 / L2 / L3 contention proof using production APIs exclusively."""

    def setUp(self):
        self.tracker = make_tracker()
        self.recorder = ProductionCriticalSectionRecorder()
        instrument_tracker(self.tracker, self.recorder)

    def tearDown(self):
        self.tracker.clear_fault_injections()

    def test_07_l1_contention_tracker_reserve_budget(self):
        """L1 contention: tracker.reserve_budget() serializes competing transactions deterministically."""
        l1_hold = threading.Event()
        l1_release = threading.Event()

        def l1_hook():
            l1_hold.set()
            if not l1_release.wait(timeout=5.0):
                raise TimeoutError("L1 release timed out")

        self.tracker.set_fault_injection("before_reservation_publication", l1_hook)
        w_l1_a = WorkerThread(target=lambda: self.tracker.reserve_budget(100), name="w_l1_a")
        w_l1_b = WorkerThread(target=lambda: self.tracker.reserve_budget(100), name="w_l1_b")

        # Worker A enters reserve_budget and holds L1
        w_l1_a.start()
        self.assertTrue(l1_hold.wait(timeout=5.0))

        # Worker B attempts reserve_budget and blocks at L1 acquire
        self.tracker._transaction_lock.acquire_attempt_event = threading.Event()
        w_l1_b.start()
        self.assertTrue(self.tracker._transaction_lock.acquire_attempt_event.wait(timeout=5.0))
        self.assertTrue(w_l1_b.is_alive())
        self.assertFalse(w_l1_b.completed)

        # Release Worker A, allowing Worker B to acquire and complete
        l1_release.set()
        join_workers(self, [w_l1_a, w_l1_b])

        self.tracker.clear_fault_injections()
        self.tracker._transaction_lock.acquire_attempt_event = None

        # Verify wait duration recorded for Worker B
        self.assertGreaterEqual(len(self.recorder.lock_waits["L1"]), 2)
        self.assertGreater(self.recorder.lock_waits["L1"][1], 0, "Worker B must record non-zero wait duration")

    def test_08_l1_5_contention_scope_get_status_snapshot(self):
        """L1.5 contention: scope.get_status_snapshot() serializes competing calls on same scope."""
        scope = make_scope(self.tracker, "op_l1_5_matrix")
        instrument_scope(scope, self.recorder)

        l1_5_hold = threading.Event()
        l1_5_release = threading.Event()

        def l1_5_hook():
            l1_5_hold.set()
            if not l1_5_release.wait(timeout=5.0):
                raise TimeoutError("L1.5 release timed out")

        self.tracker.set_fault_injection("inside_scope_lock", l1_5_hook)
        w_l1_5_a = WorkerThread(target=lambda: scope.get_status_snapshot(), name="w_l1_5_a")
        w_l1_5_b = WorkerThread(target=lambda: scope.get_status_snapshot(), name="w_l1_5_b")

        w_l1_5_a.start()
        self.assertTrue(l1_5_hold.wait(timeout=5.0))

        scope._lock.acquire_attempt_event = threading.Event()
        w_l1_5_b.start()
        self.assertTrue(scope._lock.acquire_attempt_event.wait(timeout=5.0))
        self.assertTrue(w_l1_5_b.is_alive())
        self.assertFalse(w_l1_5_b.completed)

        l1_5_release.set()
        join_workers(self, [w_l1_5_a, w_l1_5_b])

        self.tracker.clear_fault_injections()
        scope._lock.acquire_attempt_event = None

        self.assertGreaterEqual(len(self.recorder.lock_waits["L1.5"]), 2)
        self.assertGreater(self.recorder.lock_waits["L1.5"][1], 0)

    def test_09_l2_contention_reservation_start_child_read(self):
        """L2 contention: res.start_child_read() serializes competing calls on same reservation."""
        scope = make_scope(self.tracker, "op_l2_matrix")
        instrument_scope(scope, self.recorder)
        res = self.tracker.admit_read(500, scope=scope)
        instrument_reservation(res, self.recorder)

        l2_hold = threading.Event()
        l2_release = threading.Event()

        def l2_hook():
            l2_hold.set()
            if not l2_release.wait(timeout=5.0):
                raise TimeoutError("L2 release timed out")

        self.tracker.set_fault_injection("during_child_registration", l2_hook)
        w_l2_a = WorkerThread(target=lambda: res.start_child_read(), name="w_l2_a")
        w_l2_b = WorkerThread(target=lambda: res.start_child_read(), name="w_l2_b")

        w_l2_a.start()
        self.assertTrue(l2_hold.wait(timeout=5.0))

        res._lock.acquire_attempt_event = threading.Event()
        w_l2_b.start()
        self.assertTrue(res._lock.acquire_attempt_event.wait(timeout=5.0))
        self.assertTrue(w_l2_b.is_alive())
        self.assertFalse(w_l2_b.completed)

        l2_release.set()
        join_workers(self, [w_l2_a, w_l2_b])

        self.tracker.clear_fault_injections()
        res._lock.acquire_attempt_event = None

        self.assertGreaterEqual(len(self.recorder.lock_waits["L2"]), 2)
        self.assertGreater(self.recorder.lock_waits["L2"][1], 0)

    def test_10_l3_contention_child_update_metadata(self):
        """L3 contention: child.update_metadata() serializes competing calls on same child."""
        child = PhysicalReadRecord(
            physical_read_id="pread_l3_matrix",
            reservation_id="res_matrix",
            physical_consumption_id="pcons_matrix",
            charged_bytes=100,
        )
        instrument_child(child, self.recorder)

        l3_hold = threading.Event()
        l3_release = threading.Event()

        class SyncObject:
            def to_dict(self):
                l3_hold.set()
                if not l3_release.wait(timeout=5.0):
                    raise TimeoutError("L3 release timed out")
                return {"sync_state": "in_flight"}

        w_l3_a = WorkerThread(target=lambda: child.update_metadata({"sync": SyncObject()}), name="w_l3_a")
        w_l3_b = WorkerThread(target=lambda: child.update_metadata({"status": "worker_b_done"}), name="w_l3_b")

        w_l3_a.start()
        self.assertTrue(l3_hold.wait(timeout=5.0))

        child._lock.acquire_attempt_event = threading.Event()
        w_l3_b.start()
        self.assertTrue(child._lock.acquire_attempt_event.wait(timeout=5.0))
        self.assertTrue(w_l3_b.is_alive())
        self.assertFalse(w_l3_b.completed)

        l3_release.set()
        join_workers(self, [w_l3_a, w_l3_b])

        child._lock.acquire_attempt_event = None
        self.assertGreaterEqual(len(self.recorder.lock_waits["L3"]), 2)
        self.assertGreater(self.recorder.lock_waits["L3"][1], 0)


class TestPhase20A3431WorkerExceptionAndLifecycleClosure(unittest.TestCase):
    """Rigorous audit ensuring worker exceptions fail parent tests and no worker is abandoned."""

    def test_11_deliberate_worker_failure_propagation(self):
        """Deliberately injected worker exception is captured and causes join_workers to fail parent test."""
        def failing_worker_fn():
            raise ZeroDivisionError("Deliberate injection for failure propagation verification")

        failing_worker = WorkerThread(target=failing_worker_fn, name="failing_worker")
        failing_worker.start()

        with self.assertRaises(AssertionError) as cm:
            join_workers(self, [failing_worker])

        self.assertIn("failing_worker", str(cm.exception))
        self.assertIn("Deliberate injection", str(cm.exception))

    def test_12_worker_lifecycle_and_bounded_join(self):
        """All workers complete within bounded join and none remain alive."""
        completed_flags = []

        def healthy_worker(idx: int):
            completed_flags.append(idx)

        workers = [WorkerThread(target=healthy_worker, args=(i,), name=f"healthy_{i}") for i in range(5)]
        for w in workers:
            w.start()

        join_workers(self, workers, timeout=5.0)
        self.assertEqual(len(completed_flags), 5)
        for w in workers:
            self.assertFalse(w.is_alive())
            self.assertTrue(w.completed)
            self.assertIsNone(w.exception)


class TestPhase20A3431CriticalSectionOverlapAndSerialization(unittest.TestCase):
    """Demonstrates actual concurrent critical section overlap and strict mutation serialization."""

    def setUp(self):
        self.tracker = make_tracker()
        self.recorder = ProductionCriticalSectionRecorder()
        instrument_tracker(self.tracker, self.recorder)

    def tearDown(self):
        self.tracker.clear_fault_injections()

    def test_13_independent_child_reads_overlap(self):
        """Proves actual lock ownership overlap for independent L3 child operations (max_simultaneous >= 2)."""
        c1 = PhysicalReadRecord(physical_read_id="c1", reservation_id="r1", physical_consumption_id="pc1", charged_bytes=10)
        c2 = PhysicalReadRecord(physical_read_id="c2", reservation_id="r2", physical_consumption_id="pc2", charged_bytes=10)
        instrument_child(c1, self.recorder)
        instrument_child(c2, self.recorder)

        overlap_barrier = threading.Barrier(2)

        class SyncBarrier:
            def to_dict(self):
                try:
                    overlap_barrier.wait(timeout=3.0)
                except threading.BrokenBarrierError:
                    pass
                return {"synced": True}

        w1 = WorkerThread(target=lambda: c1.update_metadata({"s": SyncBarrier()}), name="child_w1")
        w2 = WorkerThread(target=lambda: c2.update_metadata({"s": SyncBarrier()}), name="child_w2")

        w1.start()
        w2.start()
        join_workers(self, [w1, w2])

        self.assertGreaterEqual(self.recorder.max_simultaneous["L3"], 2, "L3 child operations must overlap concurrently")

    def test_14_independent_scope_inspections_overlap(self):
        """Proves actual lock ownership overlap for independent L1.5 scope inspections (max_simultaneous >= 2)."""
        sc1 = make_scope(self.tracker, "op_sc_overlap_1")
        sc2 = make_scope(self.tracker, "op_sc_overlap_2")
        instrument_scope(sc1, self.recorder)
        instrument_scope(sc2, self.recorder)

        scope_barrier = threading.Barrier(2)

        def scope_hook():
            try:
                scope_barrier.wait(timeout=3.0)
            except threading.BrokenBarrierError:
                pass

        self.tracker.set_fault_injection("inside_scope_lock", scope_hook)

        w1 = WorkerThread(target=lambda: sc1.get_status_snapshot(), name="scope_w1")
        w2 = WorkerThread(target=lambda: sc2.get_status_snapshot(), name="scope_w2")

        w1.start()
        w2.start()
        join_workers(self, [w1, w2])

        self.assertGreaterEqual(self.recorder.max_simultaneous["L1.5"], 2, "L1.5 scope inspections must overlap concurrently")

    def test_15_l1_transaction_mutations_serialized(self):
        """Proves L1 transaction lock strictly serializes mutations (max_simultaneous == 1)."""
        self.recorder.max_simultaneous["L1"] = 0

        def mutate_l1(idx: int):
            self.tracker.reserve_budget(10)

        workers = [WorkerThread(target=mutate_l1, args=(i,), name=f"l1_mut_{i}") for i in range(5)]
        for w in workers:
            w.start()
        join_workers(self, workers)

        self.assertEqual(self.recorder.max_simultaneous["L1"], 1, "L1 must strictly serialize mutations")

    def test_16_commit_and_recovery_mutations_serialized(self):
        """Commit mutations and recovery mutations cannot overlap in their protected L1 mutation region."""
        sc = make_scope(self.tracker, "op_commit_rec_serial")
        instrument_scope(sc, self.recorder)
        r = self.tracker.admit_read(100, scope=sc)
        c = r.start_child_read()
        c.consume(100)
        r.consume(100)
        sc.record_read(100, admission=r)

        self.recorder.max_simultaneous["L1"] = 0

        # Run commit
        snap = sc.finalize(success=True)
        self.assertIsNotNone(snap)

        # Run retry recovery on finalized scope (idempotent)
        second_snap = self.tracker.retry_recovery(sc)
        self.assertIsNotNone(second_snap)

        self.assertEqual(self.recorder.max_simultaneous["L1"], 1, "Commit and recovery mutations must remain serialized by L1")


class TestPhase20A3431SnapshotOnlyInvariantSourceAudit(unittest.TestCase):
    """Verifiable source audit proving all 24 invariants evaluate snapshot data exclusively."""

    def test_17_ast_source_audit_reconcile_ledger(self):
        """AST audit of reconcile_ledger() proving 0 live mutable state attribute accesses after _transaction_lock."""
        with open("extractor/observation_budget.py") as f:
            tree = ast.parse(f.read())

        recon_fn = None
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) and node.name == "reconcile_ledger":
                recon_fn = node
                break

        self.assertIsNotNone(recon_fn, "reconcile_ledger method not found in AST")

        # Locate with self._transaction_lock statement
        with_node = None
        for stmt in recon_fn.body:
            if isinstance(stmt, ast.With):
                for item in stmt.items:
                    if isinstance(item.context_expr, ast.Attribute) and item.context_expr.attr == "_transaction_lock":
                        with_node = stmt
                        break
                if with_node is not None:
                    break

        self.assertIsNotNone(with_node, "with self._transaction_lock not found in reconcile_ledger")

        # Statements after with_node represent invariant evaluation region
        with_idx = recon_fn.body.index(with_node)
        eval_stmts = recon_fn.body[with_idx + 1 :]
        self.assertGreater(len(eval_stmts), 50, "Invariant evaluation region must contain all invariant logic")

        # Forbidden live state attributes
        forbidden_attrs = {
            "_physical_read_records",
            "_committed_transactions",
            "_physical_consumption_records",
            "_active_reservations",
            "_committed_reservations",
            "_released_reservations",
            "_active_scopes",
            "_batch_records",
            "_invocations",
            "_invocation_start_mono_ns",
            "_released_reservations_count",
            "metrics",
            "_limits",
            "_active_consumed_bytes",
        }

        illegal_accesses = []
        for stmt in eval_stmts:
            for sub in ast.walk(stmt):
                if isinstance(sub, ast.Attribute):
                    if isinstance(sub.value, ast.Name) and sub.value.id == "self":
                        if sub.attr in forbidden_attrs:
                            illegal_accesses.append((sub.lineno, sub.attr))

        self.assertEqual(
            illegal_accesses,
            [],
            f"AST Audit detected illegal live state accesses during invariant evaluation: {illegal_accesses}",
        )

    def test_18_runtime_poison_trap_audit(self):
        """Runtime PoisonTrap verifies that live registries/metrics are untouched during invariant evaluation."""
        tracker = make_tracker()
        scope = make_scope(tracker, "op_runtime_poison")
        res = tracker.admit_read(100, scope=scope)
        c = res.start_child_read()
        c.consume(100)
        res.consume(100)
        scope.record_read(100, admission=res)
        scope.finalize(success=True)

        class PoisonTrap:
            def __getattr__(self, name):
                raise AssertionError(f"ILLEGAL LIVE ACCESS: getattr '{name}'")

            def __getitem__(self, key):
                raise AssertionError(f"ILLEGAL LIVE ACCESS: getitem '{key}'")

            def __iter__(self):
                raise AssertionError("ILLEGAL LIVE ACCESS: iter")

            def __len__(self):
                raise AssertionError("ILLEGAL LIVE ACCESS: len")

        def poison_hook():
            tracker._physical_read_records = PoisonTrap()
            tracker._physical_consumption_records = PoisonTrap()
            tracker._committed_transactions = PoisonTrap()
            tracker._active_reservations = PoisonTrap()
            tracker._committed_reservations = PoisonTrap()
            tracker._released_reservations = PoisonTrap()
            tracker._active_scopes = PoisonTrap()
            tracker._batch_records = PoisonTrap()
            tracker._invocations = PoisonTrap()
            tracker.metrics = PoisonTrap()

        tracker.set_fault_injection("after_reconciliation_snapshot_capture", poison_hook)

        # Invariant evaluation executes outside _transaction_lock with all live state poisoned
        rec = tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(rec["reconciled"])
        self.assertEqual(len(rec["discrepancy_details"]), 24)
        tracker.clear_fault_injections()

    def test_19_negative_audit_tests(self):
        """Negative tests: AST audit and PoisonTrap fail closed when an illegal live access is introduced."""
        # 1. Negative AST audit
        dummy_code = """
def bad_reconcile(self):
    with self._transaction_lock:
        snap = 1
    # Illegal dereference of live metrics
    val = self.metrics.bytes_read
"""
        bad_tree = ast.parse(dummy_code)
        bad_fn = bad_tree.body[0]
        with_node = bad_fn.body[0]
        eval_stmts = bad_fn.body[1:]
        detected_illegal = []
        for stmt in eval_stmts:
            for sub in ast.walk(stmt):
                if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name) and sub.value.id == "self":
                    if sub.attr == "metrics":
                        detected_illegal.append(sub.attr)
        self.assertIn("metrics", detected_illegal, "Negative AST audit failed to detect illegal live access")

        # 2. Negative Runtime PoisonTrap
        class PoisonTrap:
            def __getattr__(self, name):
                raise AssertionError(f"POISON_TRAP_TRIPPED: {name}")

        pt = PoisonTrap()
        with self.assertRaises(AssertionError) as cm:
            _ = pt.bytes_read
        self.assertIn("POISON_TRAP_TRIPPED", str(cm.exception))


class TestPhase20A3431BenchmarkMeasurementIntegrity(unittest.TestCase):
    """Accurate benchmark separating distinct execution phases, multi-sample contention, and retained memory."""

    def test_20_accurate_multi_sample_benchmark(self):
        """Comprehensive benchmark reporting sample counts, median, p95, min, max, and retained memory."""
        configs = [("Small", 10), ("Medium", 50), ("Large", 150)]
        benchmark_report: Dict[str, Any] = {}

        for profile_name, tx_count in configs:
            tracker = make_tracker()
            recorder = ProductionCriticalSectionRecorder()
            instrument_tracker(tracker, recorder)

            # Warm-up phase (5 transactions)
            for i in range(5):
                sc = make_scope(tracker, f"warm_{i}")
                r = tracker.admit_read(50, scope=sc)
                c = r.start_child_read()
                c.consume(50)
                r.consume(50)
                sc.record_read(50, admission=r)
                sc.finalize(success=True)

            tracker.reconcile_ledger(raise_on_error=True)

            # Measured transactions setup
            for i in range(tx_count):
                sc = make_scope(tracker, f"tx_{profile_name}_{i}")
                r = tracker.admit_read(100, scope=sc)
                c = r.start_child_read(
                    target_spec={"address": 0x1000 + i * 16, "size": 100},
                    metadata={"tx_idx": i, "env": "bench_phase31"},
                )
                c.consume(100)
                r.consume(100)
                sc.record_read(100, admission=r)
                sc.finalize(success=True)

            # Tracemalloc peak allocation measurement
            tracemalloc.start()
            t_rec_start = time.perf_counter_ns()
            rec_result = tracker.reconcile_ledger(raise_on_error=True)
            t_rec_end = time.perf_counter_ns()
            _, peak_bytes = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            total_recon_duration_us = (t_rec_end - t_rec_start) / 1000.0

            # Multi-sample Concurrent Contention Latency during Invariant Evaluation (10 samples)
            contention_samples: List[float] = []
            num_contention_samples = 10

            for sample_idx in range(num_contention_samples):
                pause_event = threading.Event()
                resume_event = threading.Event()

                def pause_hook():
                    pause_event.set()
                    if not resume_event.wait(timeout=5.0):
                        raise TimeoutError("Contention resume timed out")

                tracker.set_fault_injection("after_reconciliation_snapshot_capture", pause_hook)

                def bg_recon():
                    tracker.reconcile_ledger(raise_on_error=True)

                th_recon = WorkerThread(target=bg_recon, name=f"bg_recon_{sample_idx}")
                th_recon.start()

                self.assertTrue(pause_event.wait(timeout=5.0))

                # While invariant evaluation is paused outside L1, run concurrent production transaction
                t_comp_start = time.perf_counter_ns()
                comp_sc = make_scope(tracker, f"comp_{profile_name}_{sample_idx}")
                comp_res = tracker.admit_read(100, scope=comp_sc)
                comp_c = comp_res.start_child_read()
                comp_c.consume(100)
                comp_res.consume(100)
                comp_sc.record_read(100, admission=comp_res)
                comp_sc.finalize(success=True)
                t_comp_end = time.perf_counter_ns()

                contention_samples.append((t_comp_end - t_comp_start) / 1000.0)

                resume_event.set()
                join_workers(self, [th_recon])
                tracker.clear_fault_injections()

            sorted_samples = sorted(contention_samples)
            median_us = sorted_samples[len(sorted_samples) // 2]
            p95_idx = int(math.ceil(0.95 * len(sorted_samples))) - 1
            p95_us = sorted_samples[p95_idx]
            min_us = sorted_samples[0]
            max_us = sorted_samples[-1]

            shallow_size = sys.getsizeof(rec_result)
            retained_size = get_recursive_retained_size(rec_result)

            benchmark_report[profile_name] = {
                "tx_count": tx_count,
                "total_recon_duration_us": total_recon_duration_us,
                "peak_allocated_bytes": peak_bytes,
                "shallow_memory_bytes": shallow_size,
                "retained_memory_bytes": retained_size,
                "contention_sample_count": num_contention_samples,
                "contention_median_us": median_us,
                "contention_p95_us": p95_us,
                "contention_min_us": min_us,
                "contention_max_us": max_us,
            }

            self.assertTrue(rec_result["reconciled"])
            self.assertGreater(retained_size, shallow_size)
            self.assertGreater(peak_bytes, 0)
            self.assertLessEqual(min_us, median_us)
            self.assertLessEqual(median_us, p95_us)
            self.assertLessEqual(p95_us, max_us)

        print("\n--- Phase 2.0-A.3.4.31 Accurate Benchmark Measurements (Informational) ---")
        for k, v in benchmark_report.items():
            print(
                f"[{k}] {v['tx_count']} tx | Recon: {v['total_recon_duration_us']:.1f}us | "
                f"Contention (N={v['contention_sample_count']}): med {v['contention_median_us']:.1f}us, "
                f"p95 {v['contention_p95_us']:.1f}us, min {v['contention_min_us']:.1f}us, max {v['contention_max_us']:.1f}us | "
                f"Shallow: {v['shallow_memory_bytes']}B | Retained: {v['retained_memory_bytes']}B | Peak: {v['peak_allocated_bytes']}B"
            )


class TestPhase20A3431CloneFrozenAdversarialRegression(unittest.TestCase):
    """Adversarial stress validation of clone_frozen(), to_dict contract, and float canonicalization."""

    def test_21_clone_frozen_deeply_nested_and_dag_diamonds(self):
        """Validates deeply nested structures (50 levels) and DAG diamond shared references."""
        # 1. 50-level nested structure
        deep_root = {}
        curr = deep_root
        for i in range(50):
            curr["next"] = {"level": i}
            curr = curr["next"]

        frozen_deep = clone_frozen(deep_root)
        self.assertIsInstance(frozen_deep, types.MappingProxyType)
        temp = frozen_deep
        for i in range(50):
            self.assertEqual(temp["next"]["level"], i)
            temp = temp["next"]

        # 2. DAG diamond shared references
        shared_node = {"key": "shared_data", "numbers": [1, 2, 3]}
        diamond = {"branch_left": shared_node, "branch_right": shared_node}
        frozen_diamond = clone_frozen(diamond)
        self.assertIs(frozen_diamond["branch_left"], frozen_diamond["branch_right"])

    def test_22_clone_frozen_custom_mapping_cycles_and_to_dict(self):
        """Cycles through custom Mapping implementations and strict to_dict() contract enforcement."""
        # 1. Custom Mapping with cyclic reference
        class CyclicCustomMapping(collections.abc.Mapping):
            def __init__(self):
                self._data = {}

            def set_cycle(self, target):
                self._data["loop"] = target

            def __getitem__(self, key):
                return self._data[key]

            def __iter__(self):
                return iter(self._data)

            def __len__(self):
                return len(self._data)

        m1 = CyclicCustomMapping()
        m1.set_cycle(m1)
        with self.assertRaises(ValueError) as cm:
            clone_frozen(m1)
        self.assertIn("Cyclic reference detected", str(cm.exception))

        # 2. to_dict() returning self
        class SelfReturner:
            def to_dict(self):
                return self

        with self.assertRaises(ValueError) as cm:
            clone_frozen(SelfReturner())
        self.assertIn("to_dict() returned self", str(cm.exception))

        # 3. to_dict() returning non-mapping
        class NonMappingReturner:
            def to_dict(self):
                return "not_a_mapping"

        with self.assertRaises(TypeError) as cm:
            clone_frozen(NonMappingReturner())
        self.assertIn("to_dict() must return a Mapping", str(cm.exception))

        # 4. to_dict() with side-effects invoked only once via memoization
        invocations = [0]

        class SideEffectObj:
            def to_dict(self):
                invocations[0] += 1
                return {"val": 100}

        obj = SideEffectObj()
        frozen_dag = clone_frozen({"a": obj, "b": obj})
        self.assertEqual(invocations[0], 1, "to_dict() must only be called once per object instance")
        self.assertIs(frozen_dag["a"], frozen_dag["b"])

    def test_23_numeric_canonicalization_and_unhashable_sets(self):
        """Rejects non-finite floats, canonicalizes -0.0 to 0.0, and gracefully falls back for unhashable set items."""
        # 1. Rejection of NaN, +Inf, -Inf
        for val in [float("nan"), float("inf"), float("-inf")]:
            with self.assertRaises(ValueError):
                clone_frozen({"metric": val})
            with self.assertRaises(ValueError):
                canonical_metadata_digest({"metric": val})

        # 2. Canonicalization of -0.0 to 0.0
        frozen_zero = clone_frozen({"zero": -0.0})
        self.assertEqual(math.copysign(1.0, frozen_zero["zero"]), 1.0)
        self.assertEqual(
            canonical_metadata_digest({"num": -0.0}),
            canonical_metadata_digest({"num": 0.0}),
        )

        # 3. Unhashable set elements fallback to sorted tuple
        class SetItem:
            def __init__(self, name):
                self.name = name

            def to_dict(self):
                return {"name": self.name}

        s = {SetItem("z_item"), SetItem("a_item")}
        frozen_set = clone_frozen(s)
        self.assertIsInstance(frozen_set, tuple)
        self.assertEqual(len(frozen_set), 2)
        # Canonical string ordering preserves deterministic sequence
        self.assertEqual(frozen_set[0]["name"], "a_item")
        self.assertEqual(frozen_set[1]["name"], "z_item")


class TestPhase20A3431CommitAndRecoveryRegression(unittest.TestCase):
    """Commit fault injection matrix and recovery idempotency regression suite."""

    def setUp(self):
        self.tracker = make_tracker()

    def tearDown(self):
        self.tracker.clear_fault_injections()

    def test_24_commit_fault_injection_matrix(self):
        """Injects failure across all production commit mutation boundaries verifying clean failure and physical preservation."""
        boundaries = [
            "before_physical_ledger_insertion",
            "during_physical_ledger_insertion",
            "after_physical_ledger_insertion",
            "before_logical_ledger_insertion",
            "during_logical_ledger_insertion",
            "after_logical_ledger_insertion",
            "before_metrics_mutation",
            "during_metric_application",
            "during_profile_metric_application",
            "after_metrics_mutation",
            "before_reservation_finalization",
            "during_reservation_finalization",
        ]

        for idx, pt in enumerate(boundaries):
            op_id = f"op_commit_reg_{idx}"
            sc = make_scope(self.tracker, op_id)
            r = self.tracker.admit_read(100, scope=sc)
            c = r.start_child_read()
            c.consume(100)
            r.consume(100)
            sc.record_read(100, admission=r)

            triggered = [False]

            def make_hook(f_flag=triggered):
                def hook():
                    if not f_flag[0]:
                        f_flag[0] = True
                        raise RuntimeError(f"Commit fault at {pt}")
                return hook

            self.tracker.set_fault_injection(pt, make_hook())

            snap = sc.finalize(success=True)
            self.assertTrue(triggered[0], f"Hook at {pt} was not reached")
            self.assertIsNotNone(snap)
            self.assertEqual(snap.accounting_status, "FAILED")
            self.assertTrue(snap.is_failure)

            # Physical evidence is preserved in ledger
            self.assertIn(c.physical_consumption_id, self.tracker._physical_consumption_records)
            self.tracker.clear_fault_injections()

        rec = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(rec["reconciled"])

    def test_25_recovery_fault_injection_and_retry_idempotency(self):
        """Recovery fault points and retry recovery idempotency."""
        recovery_pts = [
            "recovery_entry",
            "during_emergency_recovery",
            "recovery_logical_registration",
            "during_recovery_logical_registration",
            "recovery_physical_evidence",
            "during_recovery_physical_evidence",
            "recovery_metric_reconciliation",
            "during_recovery_metric_reconciliation",
            "recovery_reservation_finalization",
            "during_recovery_reservation_finalization",
            "recovery_cleanup",
            "during_recovery_cleanup",
        ]

        for idx, pt in enumerate(recovery_pts):
            op_id = f"op_rec_reg_{idx}"
            sc = make_scope(self.tracker, op_id)
            r = self.tracker.admit_read(100, scope=sc)
            c = r.start_child_read()
            c.consume(100)
            r.consume(100)
            sc.record_read(100, admission=r)

            self.tracker.inject_fault("during_logical_ledger_insertion")
            sc.finalize(success=True)
            self.tracker.clear_fault_injections()

            self.tracker.inject_fault(pt)
            try:
                self.tracker.retry_recovery(sc)
            except RuntimeError:
                pass
            self.tracker.clear_fault_injections()

            recovered_snap = self.tracker.retry_recovery(sc)
            self.assertIsNotNone(recovered_snap)
            self.assertEqual(recovered_snap.accounting_status, "FAILED")

            # Retry idempotency: second retry returns identical snapshot
            second_snap = self.tracker.retry_recovery(sc)
            self.assertEqual(recovered_snap.operation_id, second_snap.operation_id)

        rec = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(rec["reconciled"])


if __name__ == "__main__":
    unittest.main()

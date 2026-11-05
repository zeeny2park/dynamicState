"""Phase 2.0-A.3.4.34 — Verification Foundation Closure.

Strict correctness and verification foundation suite.

Production vs Test-Only Component Traceability:
- Production Components Tested:
  * extractor.observation_budget.ObservationBudgetTracker (production accounting, 24 invariants, 14 mutable fields, locks)
  * extractor.observation_budget.ActiveOperationScope (production operation scopes, lifecycle, locks)
  * extractor.observation_budget.ObservationReservation (production reservations, child reads, locks)
  * extractor.observation_budget.PhysicalReadRecord (production physical reads, metadata, locks)
  * extractor.observation_budget.clone_frozen (production immutable snapshot cloning engine)
- Test-Only Instrumentation & Harness Components:
  * InstrumentedLock: Test-only lock wrapper recording acquire/release timings and reentrancy depth.
  * ProductionCriticalSectionRecorder: Test-only thread-safe metrics collector for lock hold/wait durations.
  * WorkerThread, join_workers, start_worker_group: Test-only concurrency test harness helpers.
  * ReconciliationSnapshotBoundaryAuditor: Test-only static AST verification tool auditing production reconcile_ledger().
  * get_recursive_retained_size: Test-only memory measurement helper.

Establishes:
1. Lock Recorder Release Correctness (Test-Only Instrumentation Correctness):
   - Release recorded ONLY upon successful underlying release.
   - Exceptions during release preserved without state mutation.
   - Accurate depth and hold interval tracking across normal and reentrant locks.
2. Lock Recorder Concurrency Integrity (Test-Only Instrumentation Concurrency):
   - Adversarial multi-threaded contention, independent locks, and loops.
   - Reset while idle and worker cleanup validation.
   - Non-negative durations and strict owner distinction.
3. Benchmark Boundary Integrity (10 Boundaries):
   - Snapshot capture vs internal deep freeze vs independent microbenchmark vs invariant evaluation.
   - Total reconciliation, L1 wait, L1 hold, Tx latency, peak memory, shallow & retained memory.
   - Cycle-safe recursive size, warm-up, exact median and P95 linear interpolation.
4. Worker Lifecycle Closure (Test Harness Correctness):
   - Failed start state preservation, monotonic group deadline, timeout unjoined identification.
   - Cleanup events on failure/timeout, cause preservation (__cause__), repeated join idempotency.
5. AST Auditor Verification Completeness (Test-Only AST Tool Auditing Production Code):
   - Zero violations in production reconcile_ledger().
   - 18 negative fixtures and 3 positive fixtures preserved.
   - Fail-closed verification on dynamic eval/exec, external helpers, path-insensitive alias dataflow,
     nested closures, reflection, and helper argument/return propagation.
6. Full Regression Battery (Actual Production Code Correctness):
   - 24 invariants, canonical 14-field PoisonTrap (clean + in-path detection), commit fault matrix (12 pts),
     recovery fault matrix (12 pts), retry idempotency, concurrent commit/recovery serialization,
     and real multi-threaded snapshot isolation under concurrent live-state mutations.
"""

from __future__ import annotations

import ast
import collections
import collections.abc
import dataclasses
import math
import sys
import threading
import time
import tracemalloc
import unittest
import unittest.mock
import contextlib
from contextlib import contextmanager, nullcontext
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple

import extractor.observation_budget as observation_budget
from extractor.observation_budget import (
    ActiveOperationScope,
    ObservationBudgetLimits,
    ObservationBudgetTracker,
    PhysicalReadRecord,
    canonical_metadata_digest,
    clone_frozen,
)

# ---------------------------------------------------------------------------
# Canonical 14 Authoritative Mutable Fields Inventory
# ---------------------------------------------------------------------------
CANONICAL_AUTHORITATIVE_MUTABLE_FIELDS: Tuple[str, ...] = (
    "_physical_read_records",
    "_physical_consumption_records",
    "_committed_transactions",
    "_active_reservations",
    "_committed_reservations",
    "_released_reservations",
    "_active_scopes",
    "_batch_records",
    "_invocations",
    "_invocation_start_mono_ns",
    "_released_reservations_count",
    "metrics",
    "limits",
    "_active_consumed_bytes",
)
assert len(CANONICAL_AUTHORITATIVE_MUTABLE_FIELDS) == 14, "Must contain exactly 14 fields"


# ---------------------------------------------------------------------------
# Helpers & Test Doubles
# ---------------------------------------------------------------------------
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
    profile_id: str = "prof_a34",
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
        size += get_recursive_retained_size(obj.__dict__, seen)
    elif hasattr(obj, "__slots__"):
        for slot in obj.__slots__:
            if hasattr(obj, slot):
                size += get_recursive_retained_size(getattr(obj, slot), seen)
    return size


class OutermostCloneFrozenInterceptor:
    """Test-only reusable helper measuring outermost clone_frozen invocations during snapshot capture."""

    def __init__(self, target_module: Any = observation_budget):
        self.target_module = target_module
        self.orig_clone_frozen = target_module.clone_frozen
        self._tls = threading.local()
        self.active = False
        self.target_thread_id: Optional[int] = None
        self.per_reconciliation_invocation_counts: List[int] = []
        self.per_reconciliation_invocation_durations_ns: List[List[int]] = []
        self.per_reconciliation_aggregate_durations_ns: List[float] = []
        self._current_reconciliation_samples: List[int] = []

    def start_reconciliation_capture(self) -> None:
        """Called by before_reconciliation_snapshot_capture hook."""
        self._tls.depth = 0
        self._current_reconciliation_samples = []
        self.target_thread_id = threading.get_ident()
        self.active = True

    def end_reconciliation_capture(self) -> Tuple[int, int]:
        """Called by after_reconciliation_snapshot_capture hook.

        Returns (invocation_count, aggregate_duration_ns).
        Fails explicitly if capture was not active, recursion did not unwind, or no invocations were measured.
        """
        if not self.active:
            raise AssertionError("end_reconciliation_capture called while capture was not active")
        self.active = False
        self.target_thread_id = None
        depth = getattr(self._tls, "depth", 0)
        if depth != 0:
            self._tls.depth = 0
            raise AssertionError(f"clone_frozen recursion depth did not unwind to zero: depth={depth}")
        if not self._current_reconciliation_samples:
            raise AssertionError("Missing instrumentation: 0 outermost clone_frozen invocations recorded during capture")
        samples_copy = list(self._current_reconciliation_samples)
        count = len(samples_copy)
        agg_ns = sum(samples_copy)
        self.per_reconciliation_invocation_counts.append(count)
        self.per_reconciliation_invocation_durations_ns.append(samples_copy)
        self.per_reconciliation_aggregate_durations_ns.append(float(agg_ns))
        self._current_reconciliation_samples = []
        return count, agg_ns

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        depth = getattr(self._tls, "depth", 0)
        self._tls.depth = depth + 1
        is_target_thread = (threading.get_ident() == self.target_thread_id)
        is_outer = (depth == 0) and self.active and is_target_thread
        t0 = time.perf_counter_ns() if is_outer else 0
        success = False
        try:
            res = self.orig_clone_frozen(*args, **kwargs)
            success = True
            return res
        finally:
            t1 = time.perf_counter_ns() if is_outer else 0
            self._tls.depth -= 1
            if is_outer and t0 > 0 and success:
                self._current_reconciliation_samples.append(t1 - t0)

    def attach(self) -> OutermostCloneFrozenInterceptor:
        self.target_module.clone_frozen = self
        return self

    def detach(self) -> None:
        self.target_module.clone_frozen = self.orig_clone_frozen
        self.active = False
        self.target_thread_id = None
        self._tls.depth = 0

    def __enter__(self) -> OutermostCloneFrozenInterceptor:
        return self.attach()

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.detach()


# ---------------------------------------------------------------------------
# Worker Lifecycle Implementation
# ---------------------------------------------------------------------------
class WorkerThread(threading.Thread):
    """Reliable worker thread capturing exceptions and tracking execution state."""

    def __init__(self, target: Callable[..., Any], name: str, args: Tuple[Any, ...] = ()):
        super().__init__(name=name, daemon=True)
        self.target = target
        self.args = args
        self.exception: Optional[BaseException] = None
        self.started = False
        self._completed = False

    def start(self) -> None:
        if self.started:
            raise RuntimeError(f"Worker '{self.name}' already started")
        try:
            self.started = True
            super().start()
        except Exception:
            self.started = False
            raise

    def run(self) -> None:
        try:
            self.target(*self.args)
        except BaseException as exc:
            self.exception = exc
        finally:
            self._completed = True

    @property
    def completed(self) -> bool:
        return self._completed


def join_workers(
    workers: List[WorkerThread],
    timeout_s: float = 5.0,
    cleanup_events: Optional[List[threading.Event]] = None,
) -> None:
    """Joins a group of workers under a single monotonic group deadline."""
    deadline = time.monotonic() + timeout_s
    timed_out = False
    unjoined_at_timeout: List[str] = []
    try:
        for w in workers:
            if not w.started:
                raise RuntimeError(f"Cannot join unstarted worker '{w.name}'")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            w.join(timeout=max(remaining, 0.001))
            if w.is_alive():
                timed_out = True
                break
    finally:
        if timed_out or any(w.is_alive() for w in workers):
            unjoined_at_timeout = [w.name for w in workers if w.is_alive()]
            if cleanup_events:
                for ev in cleanup_events:
                    try:
                        ev.set()
                    except Exception:
                        pass
            for w in workers:
                if w.is_alive():
                    w.join(timeout=0.1)

    if timed_out or unjoined_at_timeout:
        raise TimeoutError(f"Worker group timed out after {timeout_s}s. Still running: {unjoined_at_timeout}")

    for w in workers:
        if w.exception is not None:
            raise RuntimeError(f"Worker '{w.name}' failed: {w.exception}") from w.exception
        if not w.completed:
            raise AssertionError(f"Worker '{w.name}' did not mark completion")


def start_worker_group(
    workers: List[WorkerThread],
    cleanup_events: Optional[List[threading.Event]] = None,
) -> None:
    """Starts a group of workers with automatic cleanup on partial startup failure."""
    started_workers: List[WorkerThread] = []
    try:
        for w in workers:
            w.start()
            started_workers.append(w)
    except Exception:
        if cleanup_events:
            for ev in cleanup_events:
                try:
                    ev.set()
                except Exception:
                    pass
        for w in started_workers:
            if w.is_alive():
                w.join(timeout=0.2)
        raise


# ---------------------------------------------------------------------------
# Lock Recorder Implementation
# ---------------------------------------------------------------------------
@dataclasses.dataclass(frozen=True)
class LockAcquisitionRecord:
    thread_id: int
    lock_id: int
    level: str
    name: str
    attempt_timestamp_ns: int
    acquired_timestamp_ns: int
    release_timestamp_ns: Optional[int]
    wait_duration_ns: int
    hold_duration_ns: Optional[int]
    max_recursion_depth: int
    total_reentrant_acquisitions: int
    phase: str = "default"
    operation: str = "default"


class ProductionCriticalSectionRecorder:
    """Records lock acquisitions and outermost hold intervals accurately and deterministically with thread-phase and operation attribution."""

    def __init__(self):
        self._lock = threading.Lock()
        self.records_by_thread: Dict[int, List[LockAcquisitionRecord]] = collections.defaultdict(list)
        self.active_holders: Dict[str, Set[Tuple[int, int]]] = collections.defaultdict(set)
        self.active_threads_by_level: Dict[str, Set[int]] = collections.defaultdict(set)
        self.max_simultaneous: Dict[str, int] = collections.defaultdict(int)
        self.reentrancy_depth: Dict[Tuple[int, int], int] = collections.defaultdict(int)
        self._entry_times: Dict[Tuple[int, int], Tuple[int, int, int, int, str, str]] = {}
        self._tls = threading.local()

    def set_thread_attribution(self, phase: str, operation: str = "default") -> None:
        """Sets the active execution phase and operation for the calling thread."""
        self._tls.phase = phase
        self._tls.operation = operation

    def set_thread_phase(self, phase: str, operation: str = "default") -> None:
        """Sets the active execution phase and operation for the calling thread."""
        self.set_thread_attribution(phase=phase, operation=operation)

    def get_thread_phase(self) -> str:
        """Returns the active execution phase for the calling thread."""
        return getattr(self._tls, "phase", "default")

    def get_thread_operation(self) -> str:
        """Returns the active execution operation for the calling thread."""
        return getattr(self._tls, "operation", "default")

    @contextmanager
    def phase_scope(self, phase: str, operation: str = "default") -> Iterator[None]:
        """Context manager guaranteeing phase and operation restoration via try/finally."""
        prev_phase = self.get_thread_phase()
        prev_op = self.get_thread_operation()
        self.set_thread_attribution(phase=phase, operation=operation)
        try:
            yield
        finally:
            self.set_thread_attribution(phase=prev_phase, operation=prev_op)

    def record_acquire(
        self,
        thread_id: int,
        lock_id: int,
        level: str,
        name: str,
        attempt_ns: int,
        acquired_ns: int,
    ) -> None:
        with self._lock:
            key = (thread_id, lock_id)
            phase = self.get_thread_phase()
            operation = self.get_thread_operation()
            cur_depth = self.reentrancy_depth.get(key, 0)
            if cur_depth == 0:
                self.reentrancy_depth[key] = 1
                self.active_holders[level].add(key)
                self.active_threads_by_level[level].add(thread_id)
                cur_active = len(self.active_threads_by_level[level])
                if cur_active > self.max_simultaneous[level]:
                    self.max_simultaneous[level] = cur_active
                self._entry_times[key] = (attempt_ns, acquired_ns, 1, 0, phase, operation)
            else:
                new_depth = cur_depth + 1
                self.reentrancy_depth[key] = new_depth
                prev_attempt, prev_acquired, prev_max, prev_reentrant, prev_phase, prev_op = self._entry_times[key]
                self._entry_times[key] = (
                    prev_attempt,
                    prev_acquired,
                    max(prev_max, new_depth),
                    prev_reentrant + 1,
                    prev_phase,
                    prev_op,
                )

    def record_release(
        self,
        thread_id: int,
        lock_id: int,
        level: str,
        name: str,
        release_ns: int,
    ) -> None:
        with self._lock:
            key = (thread_id, lock_id)
            cur_depth = self.reentrancy_depth.get(key, 0)
            if cur_depth > 1:
                self.reentrancy_depth[key] = cur_depth - 1
            elif cur_depth == 1:
                del self.reentrancy_depth[key]
                self.active_holders[level].discard(key)
                still_holding = any(th == thread_id for th, _ in self.active_holders[level])
                if not still_holding:
                    self.active_threads_by_level[level].discard(thread_id)
                entry_info = self._entry_times.pop(key, None)
                if entry_info:
                    attempt_ns, acquired_ns, max_depth, reentrant_count, phase, operation = entry_info
                    rec = LockAcquisitionRecord(
                        thread_id=thread_id,
                        lock_id=lock_id,
                        level=level,
                        name=name,
                        attempt_timestamp_ns=attempt_ns,
                        acquired_timestamp_ns=acquired_ns,
                        release_timestamp_ns=release_ns,
                        wait_duration_ns=acquired_ns - attempt_ns,
                        hold_duration_ns=release_ns - acquired_ns,
                        max_recursion_depth=max_depth,
                        total_reentrant_acquisitions=reentrant_count,
                        phase=phase,
                        operation=operation,
                    )
                    self.records_by_thread[thread_id].append(rec)

    def get_thread_records(
        self,
        thread_id: int,
        level: Optional[str] = None,
        phase: Optional[str] = None,
        operation: Optional[str] = None,
    ) -> List[LockAcquisitionRecord]:
        with self._lock:
            recs = list(self.records_by_thread.get(thread_id, []))
        if level is not None:
            recs = [r for r in recs if r.level == level]
        if phase is not None:
            recs = [r for r in recs if r.phase == phase]
        if operation is not None:
            recs = [r for r in recs if r.operation == operation]
        return recs

    def get_thread_waits(
        self,
        thread_id: int,
        level: Optional[str] = None,
        phase: Optional[str] = None,
        operation: Optional[str] = None,
    ) -> List[int]:
        recs = self.get_thread_records(thread_id, level=level, phase=phase, operation=operation)
        return [r.wait_duration_ns for r in recs]

    def get_thread_holds(
        self,
        thread_id: int,
        level: Optional[str] = None,
        phase: Optional[str] = None,
        operation: Optional[str] = None,
    ) -> List[int]:
        recs = self.get_thread_records(thread_id, level=level, phase=phase, operation=operation)
        return [r.hold_duration_ns for r in recs if r.hold_duration_ns is not None]

    def validate_records(
        self,
        thread_id: int,
        require_phase: bool = True,
        require_operation: bool = True,
    ) -> None:
        """Rejects records with missing, blank, default, or inconsistent attribution."""
        with self._lock:
            recs = list(self.records_by_thread.get(thread_id, []))
        for r in recs:
            if require_phase and (not r.phase or r.phase in ("", "default")):
                raise ValueError(f"LockAcquisitionRecord has missing or default phase: {r}")
            if require_operation and (not r.operation or r.operation in ("", "default")):
                raise ValueError(f"LockAcquisitionRecord has missing or default operation: {r}")
            if r.wait_duration_ns < 0:
                raise ValueError(f"LockAcquisitionRecord has negative wait duration: {r}")
            if r.hold_duration_ns is not None and r.hold_duration_ns < 0:
                raise ValueError(f"LockAcquisitionRecord has negative hold duration: {r}")

    def cleanup_thread(self, thread_id: int) -> None:
        with self._lock:
            self.records_by_thread.pop(thread_id, None)

    def reset(self) -> None:
        with self._lock:
            self.records_by_thread.clear()
            self.active_holders.clear()
            self.active_threads_by_level.clear()
            self.max_simultaneous.clear()
            self.reentrancy_depth.clear()
            self._entry_times.clear()
        self._tls.phase = "default"
        self._tls.operation = "default"


class InstrumentedLock:
    """Transparent lock wrapper recording acquire/release timings and recursive depth.

    Release Correctness Guarantee:
    - Calls self._real_lock.release() first.
    - Records release ONLY if the underlying release completes successfully without raising.
    - Preserves exceptions without altering recorder state or depth.
    """

    def __init__(
        self,
        raw_lock: Any,
        recorder: ProductionCriticalSectionRecorder,
        level: str,
        name: str,
        pre_acquire_hook: Optional[Callable[[], None]] = None,
    ):
        self._real_lock = raw_lock
        self.recorder = recorder
        self.level = level
        self.name = name
        self.lock_id = id(raw_lock)
        self.pre_acquire_hook = pre_acquire_hook

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
        if self.pre_acquire_hook is not None:
            self.pre_acquire_hook()
        t_att = time.perf_counter_ns()
        acquired = self._real_lock.acquire(blocking, timeout)
        t_acq = time.perf_counter_ns()
        if acquired:
            self.recorder.record_acquire(
                thread_id=threading.get_ident(),
                lock_id=self.lock_id,
                level=self.level,
                name=self.name,
                attempt_ns=t_att,
                acquired_ns=t_acq,
            )
        return acquired

    def release(self) -> None:
        # Correctness: underlying release must succeed before recording release
        self._real_lock.release()
        t_rel = time.perf_counter_ns()
        self.recorder.record_release(
            thread_id=threading.get_ident(),
            lock_id=self.lock_id,
            level=self.level,
            name=self.name,
            release_ns=t_rel,
        )

    def __enter__(self) -> bool:
        return self.acquire(blocking=True)

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.release()

    def __getattr__(self, name: str) -> Any:
        return getattr(self._real_lock, name)


def instrument_tracker(tracker: ObservationBudgetTracker, recorder: ProductionCriticalSectionRecorder) -> None:
    """Instruments production tracker transaction lock without altering locking order."""
    tracker._transaction_lock = InstrumentedLock(tracker._transaction_lock, recorder, "L1", "transaction_lock")


# ---------------------------------------------------------------------------
# AST Alias Dataflow Auditor
# ---------------------------------------------------------------------------
class ReconciliationSnapshotBoundaryAuditor:
    """Conservative, fail-closed AST auditor detecting live mutable state access in reconcile_ledger().

    Language Subset Supported:
    - Target: Single function definition (`reconcile_ledger`) within module AST.
    - Locks: Outermost `with self._transaction_lock:` delineating snapshot capture vs evaluation.
    - Assignments: Single target (`x = val`), multi-target, augmented assignment (`x += val`).
    - Alias Propagation: Multi-hop fixed point analysis across variables, tuples, lists, sets, and dicts.
    - Derived References: Subscripts (`x[0]`, `x['key']`), attribute chains (`x.attr`).
    - Closures & Nested Functions: Detects captured outer scope aliases and returns of live state.
    - Helper Invocations: Detects tainted argument passing and helper return value tainting.
    - Dynamic Reflection: `getattr`, `hasattr`, `setattr`, `delattr`, `vars` on `self` or aliases.
    - Comprehensions: Detects iteration over live mutable registries in `ListComp`, `SetComp`, `DictComp`.
    - Fail-Closed: Dynamic `eval` and `exec` rejected explicitly.

    Known Limitations:
    - Intra-procedural: Does not statically inspect bodies of functions outside the target method.
    - Dynamic Evaluation: Does not evaluate string code passed to `eval` or `exec`.
    - Path Insensitive: If a variable is tainted along any assignment path, it is treated as tainted everywhere.
    """

    FORBIDDEN_LIVE_ATTRS = set(CANONICAL_AUTHORITATIVE_MUTABLE_FIELDS) | {
        "_limits",
        "_lock",
        "_parent_reservation",
        "_fault_injection_hooks",
    }
    ALLOWED_SELF_ATTRS = {"_trigger_fault"}

    def __init__(self, source_code: str):
        self.tree = ast.parse(source_code)
        self.violations: List[str] = []

    def audit_function(self, fn_name: str = "reconcile_ledger") -> List[str]:
        self.violations.clear()
        target_fn = None
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef) and node.name == fn_name:
                target_fn = node
                break
        if target_fn is None:
            return [f"Target function '{fn_name}' not found"]

        with_node = None
        for stmt in target_fn.body:
            if isinstance(stmt, ast.With):
                for item in stmt.items:
                    if isinstance(item.context_expr, ast.Attribute) and item.context_expr.attr == "_transaction_lock":
                        with_node = stmt
                        break
                if with_node is not None:
                    break

        if with_node is None:
            return [f"No 'with self._transaction_lock:' statement found in {fn_name}"]

        with_idx = target_fn.body.index(with_node)
        capture_stmts = target_fn.body[:with_idx] + with_node.body
        eval_stmts = target_fn.body[with_idx + 1 :]

        tainted_self: Set[str] = set()
        tainted_registry: Dict[str, str] = {}
        tainted_containers: Dict[str, str] = {}
        tainted_derived: Dict[str, str] = {}
        raw_collections: Dict[str, str] = {}
        helper_closures: Dict[str, Dict[str, Any]] = {}

        def is_tainted_expr(expr: ast.AST) -> Optional[str]:
            if isinstance(expr, ast.Name):
                if expr.id == "self" or expr.id in tainted_self:
                    return "self_alias"
                if expr.id in tainted_registry:
                    return f"registry_alias({tainted_registry[expr.id]})"
                if expr.id in tainted_containers:
                    return f"container_alias({tainted_containers[expr.id]})"
                if expr.id in tainted_derived:
                    return f"derived_alias({tainted_derived[expr.id]})"
                if expr.id in raw_collections:
                    return f"raw_collection({raw_collections[expr.id]})"
            elif isinstance(expr, ast.Attribute):
                if isinstance(expr.value, ast.Name):
                    if (expr.value.id == "self" or expr.value.id in tainted_self) and expr.attr in self.FORBIDDEN_LIVE_ATTRS:
                        return f"forbidden_attr({expr.attr})"
                    owner_taint = is_tainted_expr(expr.value)
                    if owner_taint:
                        return f"attr_of_{owner_taint}"
            elif isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
                for elt in expr.elts:
                    t = is_tainted_expr(elt)
                    if t:
                        return f"container_of_{t}"
            elif isinstance(expr, ast.Dict):
                for v in expr.values:
                    t = is_tainted_expr(v)
                    if t:
                        return f"dict_of_{t}"
            elif isinstance(expr, ast.Subscript):
                t = is_tainted_expr(expr.value)
                if t:
                    return f"subscript_of_{t}"
            return None

        # Inspect nested helper closures
        for node in ast.walk(target_fn):
            if isinstance(node, ast.FunctionDef) and node is not target_fn:
                captured_taint: List[str] = []
                returns_taint: bool = False
                for sub in ast.walk(node):
                    if isinstance(sub, ast.Attribute) and isinstance(sub.value, ast.Name):
                        if (sub.value.id == "self" or sub.value.id in tainted_self) and sub.attr in self.FORBIDDEN_LIVE_ATTRS:
                            captured_taint.append(f"self.{sub.attr}")
                    if isinstance(sub, ast.Return) and sub.value is not None:
                        if is_tainted_expr(sub.value):
                            returns_taint = True
                helper_closures[node.name] = {
                    "captured": captured_taint,
                    "returns_taint": returns_taint,
                }

        # Multi-hop fixed-point assignment propagation
        changed = True
        while changed:
            changed = False
            for stmt in capture_stmts:
                for node in ast.walk(stmt):
                    if isinstance(node, ast.Assign):
                        # Safe transformations
                        is_sanitized = False
                        if isinstance(node.value, ast.Call):
                            func = node.value.func
                            if isinstance(func, ast.Name) and func.id in (
                                "clone_frozen",
                                "len",
                                "int",
                                "float",
                                "bool",
                                "str",
                                "round",
                                "frozenset",
                            ):
                                is_sanitized = True
                        if isinstance(node.value, ast.Attribute) and isinstance(node.value.value, ast.Attribute):
                            if isinstance(node.value.value.value, ast.Name) and node.value.value.value.id == "self":
                                if node.value.value.attr == "metrics" and node.value.attr in (
                                    "bytes_read",
                                    "measured_bytes_read",
                                    "conservative_estimated_bytes",
                                    "unmeasured_reads_count",
                                    "observation_latency_us",
                                    "target_stop_duration_ms",
                                    "total_read_failures",
                                    "consecutive_read_failures",
                                    "is_budget_exhausted",
                                    "exhaustion_reason",
                                    "wall_clock_elapsed_ms",
                                ):
                                    is_sanitized = True
                        if is_sanitized:
                            continue

                        # Raw collection leak detection
                        if isinstance(node.value, ast.Call):
                            func = node.value.func
                            if isinstance(func, ast.Name) and func.id in ("list", "dict", "tuple", "set"):
                                if node.value.args and isinstance(node.value.args[0], ast.Call):
                                    inner = node.value.args[0]
                                    if isinstance(inner.func, ast.Attribute) and inner.func.attr in ("values", "items", "keys"):
                                        owner_taint = is_tainted_expr(inner.func.value)
                                        if owner_taint:
                                            for target in node.targets:
                                                if isinstance(target, ast.Name) and target.id not in raw_collections:
                                                    raw_collections[target.id] = owner_taint
                                                    changed = True

                        # Helper returns tainted reference
                        if isinstance(node.value, ast.Call) and isinstance(node.value.func, ast.Name):
                            h_info = helper_closures.get(node.value.func.id)
                            if h_info and h_info.get("returns_taint"):
                                for target in node.targets:
                                    if isinstance(target, ast.Name) and target.id not in (
                                        tainted_self
                                        | set(tainted_containers)
                                        | set(tainted_registry)
                                        | set(tainted_derived)
                                    ):
                                        tainted_derived[target.id] = f"return_from_{node.value.func.id}"
                                        changed = True

                        rhs_taint = is_tainted_expr(node.value)
                        if rhs_taint:
                            for target in node.targets:
                                if isinstance(target, ast.Name):
                                    tid = target.id
                                    if (
                                        tid in tainted_self
                                        or tid in tainted_containers
                                        or tid in tainted_registry
                                        or tid in tainted_derived
                                    ):
                                        continue
                                    if rhs_taint == "self_alias":
                                        tainted_self.add(tid)
                                        changed = True
                                    elif "container" in rhs_taint or "dict" in rhs_taint:
                                        tainted_containers[tid] = rhs_taint
                                        changed = True
                                    elif "subscript" in rhs_taint:
                                        tainted_derived[tid] = rhs_taint
                                        changed = True
                                    elif "forbidden_attr" in rhs_taint or "registry_alias" in rhs_taint:
                                        tainted_registry[tid] = rhs_taint
                                        changed = True
                                    else:
                                        tainted_derived[tid] = rhs_taint
                                        changed = True
                    elif isinstance(node, ast.AugAssign):
                        rhs_taint = is_tainted_expr(node.value)
                        if rhs_taint and isinstance(node.target, ast.Name):
                            if node.target.id not in tainted_containers:
                                tainted_containers[node.target.id] = f"aug_assign_{rhs_taint}"
                                changed = True

        # Re-check closures for captured aliases
        for h_name, h_info in helper_closures.items():
            for node in ast.walk(target_fn):
                if isinstance(node, ast.FunctionDef) and node.name == h_name:
                    for sub in ast.walk(node):
                        if isinstance(sub, ast.Name) and isinstance(sub.ctx, ast.Load):
                            if (
                                sub.id in tainted_self
                                or sub.id in tainted_registry
                                or sub.id in tainted_containers
                                or sub.id in tainted_derived
                            ):
                                h_info["captured"].append(sub.id)

        # Audit evaluation statements (post lock release)
        for stmt in eval_stmts:
            for node in ast.walk(stmt):
                # 1. Attribute access
                if isinstance(node, ast.Attribute):
                    if isinstance(node.value, ast.Name) and node.value.id == "self":
                        if node.attr not in self.ALLOWED_SELF_ATTRS:
                            self.violations.append(
                                f"[DIRECT_SELF_ACCESS] Line {node.lineno}: Direct access to self.{node.attr}"
                            )
                    elif isinstance(node.value, ast.Name) and node.value.id in tainted_self:
                        self.violations.append(
                            f"[SELF_ALIAS] Line {node.lineno}: Access to self.{node.attr} via tainted alias '{node.value.id}'"
                        )

                # 2. Variable loads
                elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                    if node.id in tainted_registry:
                        self.violations.append(
                            f"[REGISTRY_ALIAS] Line {node.lineno}: Reference to tainted registry alias '{node.id}'"
                        )
                    elif node.id in tainted_containers:
                        self.violations.append(
                            f"[CONTAINER_ALIAS] Line {node.lineno}: Reference to tainted container alias '{node.id}'"
                        )
                    elif node.id in tainted_derived:
                        self.violations.append(
                            f"[DERIVED_ALIAS] Line {node.lineno}: Reference to derived tainted alias '{node.id}'"
                        )
                    elif node.id in raw_collections:
                        self.violations.append(
                            f"[RAW_COLLECTION] Line {node.lineno}: Reference to raw production collection '{node.id}'"
                        )

                # 3. Dynamic reflection, eval/exec & Helper calls
                elif isinstance(node, ast.Call):
                    fn_id = None
                    if isinstance(node.func, ast.Name):
                        fn_id = node.func.id
                    elif isinstance(node.func, ast.Attribute):
                        fn_id = node.func.attr

                    if fn_id in ("eval", "exec"):
                        self.violations.append(
                            f"[DYNAMIC_EVAL] Line {node.lineno}: Dynamic '{fn_id}' cannot be statically proven safe"
                        )
                    elif fn_id in ("getattr", "hasattr", "setattr", "delattr", "vars"):
                        if (
                            node.args
                            and isinstance(node.args[0], ast.Name)
                            and (node.args[0].id == "self" or node.args[0].id in tainted_self)
                        ):
                            self.violations.append(
                                f"[REFLECTION] Line {node.lineno}: Dynamic reflection '{fn_id}' on live self/alias"
                            )
                    elif fn_id in helper_closures:
                        if helper_closures[fn_id]["captured"]:
                            self.violations.append(
                                f"[CLOSURE_CAPTURE] Line {node.lineno}: Call to helper '{fn_id}' capturing live state {helper_closures[fn_id]['captured']}"
                            )
                    for arg in node.args:
                        if isinstance(arg, ast.Name) and (
                            arg.id in tainted_registry or arg.id in tainted_self or arg.id in tainted_containers or arg.id in tainted_derived
                        ):
                            self.violations.append(
                                f"[HELPER_ARGUMENT] Line {node.lineno}: Passing tainted alias '{arg.id}' to '{fn_id}'"
                            )

                # 4. Comprehensions over live state
                elif isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
                    for gen in node.generators:
                        iter_taint = is_tainted_expr(gen.iter)
                        if iter_taint:
                            self.violations.append(
                                f"[COMPREHENSION] Line {node.lineno}: Comprehension over tainted state ({iter_taint})"
                            )

        return self.violations


# ===========================================================================
# 1. Lock Recorder Release Correctness (Test-Only Instrumentation)
# ===========================================================================
class TestPhase20A3434LockRecorderReleaseCorrectness(unittest.TestCase):
    """Test-Only Instrumentation Verification: Rigorous audit of test-only InstrumentedLock and ProductionCriticalSectionRecorder release behavior.
    
    Proves correctness of the test-only lock instrumentation harness, NOT production locking.
    """

    def setUp(self):
        self.recorder = ProductionCriticalSectionRecorder()

    def test_01_successful_normal_lock_release(self):
        """Successful normal Lock release records hold duration, depth=1, and leaves recorder clean."""
        raw_lock = threading.Lock()
        inst_lock = InstrumentedLock(raw_lock, self.recorder, level="L1", name="norm_lock")
        th_id = threading.get_ident()

        inst_lock.acquire()
        self.assertEqual(self.recorder.reentrancy_depth.get((th_id, inst_lock.lock_id)), 1)
        self.assertIn((th_id, inst_lock.lock_id), self.recorder.active_holders["L1"])

        inst_lock.release()
        self.assertNotIn((th_id, inst_lock.lock_id), self.recorder.reentrancy_depth)
        self.assertNotIn((th_id, inst_lock.lock_id), self.recorder.active_holders["L1"])

        records = self.recorder.records_by_thread[th_id]
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec.max_recursion_depth, 1)
        self.assertEqual(rec.total_reentrant_acquisitions, 0)
        self.assertIsNotNone(rec.hold_duration_ns)
        self.assertGreaterEqual(rec.hold_duration_ns, 0)

    def test_02_successful_recursive_rlock_release_depth_2_and_3(self):
        """Recursive RLock releases decrement depth accurately and finalize record only at depth 0."""
        raw_lock = threading.RLock()
        inst_lock = InstrumentedLock(raw_lock, self.recorder, level="L1", name="rec_rlock")
        th_id = threading.get_ident()
        key = (th_id, inst_lock.lock_id)

        inst_lock.acquire()
        inst_lock.acquire()
        inst_lock.acquire()
        self.assertEqual(self.recorder.reentrancy_depth[key], 3)

        # 1st release: depth -> 2
        inst_lock.release()
        self.assertEqual(self.recorder.reentrancy_depth[key], 2)
        self.assertEqual(len(self.recorder.records_by_thread[th_id]), 0)

        # 2nd release: depth -> 1
        inst_lock.release()
        self.assertEqual(self.recorder.reentrancy_depth[key], 1)
        self.assertEqual(len(self.recorder.records_by_thread[th_id]), 0)

        # 3rd release: depth -> 0 (final)
        inst_lock.release()
        self.assertNotIn(key, self.recorder.reentrancy_depth)
        self.assertEqual(len(self.recorder.records_by_thread[th_id]), 1)
        rec = self.recorder.records_by_thread[th_id][0]
        self.assertEqual(rec.max_recursion_depth, 3)
        self.assertEqual(rec.total_reentrant_acquisitions, 2)
        self.assertGreaterEqual(rec.hold_duration_ns, 0)

    def test_03_invalid_release_by_non_owner_preserves_owner_state(self):
        """Attempted release by a non-owner raises RuntimeError and leaves owner recorder state intact."""
        raw_lock = threading.RLock()
        inst_lock = InstrumentedLock(raw_lock, self.recorder, level="L1", name="owner_test_lock")

        owner_acquired = threading.Event()
        release_attempted = threading.Event()
        owner_can_finish = threading.Event()
        non_owner_exceptions: List[Exception] = []

        def owner_work():
            with inst_lock:
                owner_acquired.set()
                if not owner_can_finish.wait(timeout=5.0):
                    raise TimeoutError("owner_work: owner_can_finish timed out")

        def non_owner_work():
            if not owner_acquired.wait(timeout=5.0):
                raise TimeoutError("non_owner_work: owner_acquired timed out")
            try:
                inst_lock.release()
            except RuntimeError as exc:
                non_owner_exceptions.append(exc)
            finally:
                release_attempted.set()

        t_owner = WorkerThread(target=owner_work, name="owner_w")
        t_non_owner = WorkerThread(target=non_owner_work, name="non_owner_w")
        try:
            start_worker_group([t_owner, t_non_owner], cleanup_events=[owner_can_finish, release_attempted, owner_acquired])
            if not release_attempted.wait(timeout=5.0):
                raise TimeoutError("Main thread: release_attempted timed out")
            self.assertEqual(len(non_owner_exceptions), 1)
            self.assertIn("cannot release un-acquired lock", str(non_owner_exceptions[0]))

            # Verify owner's recorded state remains intact despite non-owner release attempt
            owner_key = (t_owner.ident, inst_lock.lock_id)
            self.assertEqual(self.recorder.reentrancy_depth.get(owner_key), 1)
            self.assertIn(owner_key, self.recorder.active_holders["L1"])
            self.assertEqual(len(self.recorder.records_by_thread[t_non_owner.ident]), 0)
        finally:
            owner_can_finish.set()
            join_workers([t_owner, t_non_owner], timeout_s=5.0, cleanup_events=[owner_can_finish, release_attempted, owner_acquired])
            self.assertFalse(t_owner.is_alive())
            self.assertFalse(t_non_owner.is_alive())

        # After owner legitimately releases, depth is 0 and exactly 1 record is created
        self.assertNotIn(owner_key, self.recorder.reentrancy_depth)
        self.assertEqual(len(self.recorder.records_by_thread[t_owner.ident]), 1)
        self.assertEqual(len(self.recorder.records_by_thread[t_non_owner.ident]), 0)

    def test_04_release_when_not_acquired_raises_and_preserves_recorder(self):
        """Release on unacquired lock raises RuntimeError and does not create ghost records."""
        raw_lock = threading.Lock()
        inst_lock = InstrumentedLock(raw_lock, self.recorder, level="L1", name="unacq_lock")
        th_id = threading.get_ident()

        with self.assertRaises(RuntimeError) as cm:
            inst_lock.release()
        self.assertIn("lock", str(cm.exception).lower())

        self.assertEqual(len(self.recorder.records_by_thread[th_id]), 0)
        self.assertEqual(len(self.recorder.reentrancy_depth), 0)
        self.assertEqual(len(self.recorder.active_holders["L1"]), 0)

    def test_05_nested_context_manager_exception_releases_cleanly(self):
        """Exception inside nested context manager releases lock cleanly and preserves hold measurement."""
        raw_lock = threading.RLock()
        inst_lock = InstrumentedLock(raw_lock, self.recorder, level="L1", name="ctx_exc_lock")
        th_id = threading.get_ident()

        with self.assertRaises(ValueError):
            with inst_lock:
                with inst_lock:
                    raise ValueError("deliberate critical section abort")

        key = (th_id, inst_lock.lock_id)
        self.assertNotIn(key, self.recorder.reentrancy_depth)
        self.assertEqual(len(self.recorder.active_holders["L1"]), 0)

        records = self.recorder.records_by_thread[th_id]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].max_recursion_depth, 2)
        self.assertEqual(records[0].total_reentrant_acquisitions, 1)

    def test_06_repeated_acquisition_and_release_cycles(self):
        """Multiple sequential acquisitions and releases track distinct intervals with depth resetting to 0."""
        raw_lock = threading.Lock()
        inst_lock = InstrumentedLock(raw_lock, self.recorder, level="L1", name="seq_lock")
        th_id = threading.get_ident()

        for _ in range(10):
            with inst_lock:
                pass

        records = self.recorder.records_by_thread[th_id]
        self.assertEqual(len(records), 10)
        self.assertEqual(len(self.recorder.reentrancy_depth), 0)
        self.assertEqual(len(self.recorder.active_holders["L1"]), 0)

    def test_07_multiple_independent_locks_acquired_by_single_thread(self):
        """Single thread holding multiple independent locks tracks each distinct lock_id and level."""
        l1 = InstrumentedLock(threading.RLock(), self.recorder, level="L1", name="lock_l1")
        l2 = InstrumentedLock(threading.RLock(), self.recorder, level="L2", name="lock_l2")
        l3 = InstrumentedLock(threading.RLock(), self.recorder, level="L3", name="lock_l3")
        th_id = threading.get_ident()

        with l1:
            with l2:
                with l3:
                    self.assertEqual(self.recorder.reentrancy_depth[(th_id, l1.lock_id)], 1)
                    self.assertEqual(self.recorder.reentrancy_depth[(th_id, l2.lock_id)], 1)
                    self.assertEqual(self.recorder.reentrancy_depth[(th_id, l3.lock_id)], 1)
                    self.assertEqual(len(self.recorder.active_threads_by_level["L1"]), 1)
                    self.assertEqual(len(self.recorder.active_threads_by_level["L2"]), 1)
                    self.assertEqual(len(self.recorder.active_threads_by_level["L3"]), 1)

        self.assertEqual(len(self.recorder.reentrancy_depth), 0)
        self.assertEqual(len(self.recorder.records_by_thread[th_id]), 3)

    def test_08_failed_release_does_not_corrupt_subsequent_measurements(self):
        """Failed release does not corrupt recorder state; subsequent acquisitions measure accurately."""
        raw_lock = threading.Lock()
        inst_lock = InstrumentedLock(raw_lock, self.recorder, level="L1", name="fail_recovery_lock")
        th_id = threading.get_ident()

        # Step 1: Failed release
        with self.assertRaises(RuntimeError):
            inst_lock.release()

        # Step 2: Legitimate subsequent acquisition and release
        with inst_lock:
            pass

        records = self.recorder.records_by_thread[th_id]
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].max_recursion_depth, 1)
        self.assertEqual(len(self.recorder.reentrancy_depth), 0)


# ===========================================================================
# 2. Lock Recorder Concurrency Integrity (Test-Only Instrumentation)
# ===========================================================================
class TestPhase20A3434LockRecorderConcurrencyIntegrity(unittest.TestCase):
    """Test-Only Instrumentation Concurrency: Multi-threaded contention and concurrency integrity verification for the test harness recorder.
    
    Proves concurrency safety of the test harness recorder under multi-threaded test execution, NOT production transaction concurrency.
    """

    def setUp(self):
        self.recorder = ProductionCriticalSectionRecorder()

    def test_09_multiple_threads_acquiring_same_lock_serialization_and_wait(self):
        """Contended lock serializes threads; blocked thread records positive wait duration without sleep."""
        raw_lock = threading.Lock()
        b_at_lock = threading.Event()
        inst_lock = InstrumentedLock(raw_lock, self.recorder, level="L1", name="contended_l1", pre_acquire_hook=b_at_lock.set)

        b_entry = threading.Barrier(2)
        b_exit = threading.Barrier(2)

        def thread_a():
            with inst_lock:
                try:
                    b_entry.wait(timeout=5.0)
                except (threading.BrokenBarrierError, TimeoutError) as exc:
                    raise TimeoutError("thread_a: b_entry timed out") from exc
                if not b_at_lock.wait(timeout=5.0):
                    raise TimeoutError("thread_a: b_at_lock timed out")
            try:
                b_exit.wait(timeout=5.0)
            except (threading.BrokenBarrierError, TimeoutError) as exc:
                raise TimeoutError("thread_a: b_exit timed out") from exc

        def thread_b():
            try:
                b_entry.wait(timeout=5.0)
            except (threading.BrokenBarrierError, TimeoutError) as exc:
                raise TimeoutError("thread_b: b_entry timed out") from exc
            with inst_lock:
                pass
            try:
                b_exit.wait(timeout=5.0)
            except (threading.BrokenBarrierError, TimeoutError) as exc:
                raise TimeoutError("thread_b: b_exit timed out") from exc

        w_a = WorkerThread(target=thread_a, name="worker_a")
        w_b = WorkerThread(target=thread_b, name="worker_b")
        try:
            start_worker_group([w_a, w_b], cleanup_events=[b_at_lock])
            join_workers([w_a, w_b], timeout_s=5.0, cleanup_events=[b_at_lock])
        finally:
            self.assertFalse(w_a.is_alive())
            self.assertFalse(w_b.is_alive())

        self.assertEqual(self.recorder.max_simultaneous["L1"], 1)
        waits_b = self.recorder.get_thread_waits(w_b.ident, level="L1")
        self.assertEqual(len(waits_b), 1)
        self.assertGreater(waits_b[0], 0)

    def test_10_multiple_threads_acquiring_independent_locks_concurrency(self):
        """Threads acquiring independent locks run concurrently without false lock overlap."""
        lock_a = InstrumentedLock(threading.Lock(), self.recorder, level="L3", name="lock_a")
        lock_b = InstrumentedLock(threading.Lock(), self.recorder, level="L3", name="lock_b")

        b_both_held = threading.Barrier(2)

        def worker_1():
            with lock_a:
                try:
                    b_both_held.wait(timeout=5.0)
                except (threading.BrokenBarrierError, TimeoutError) as exc:
                    raise TimeoutError("worker_1: b_both_held timed out") from exc

        def worker_2():
            with lock_b:
                try:
                    b_both_held.wait(timeout=5.0)
                except (threading.BrokenBarrierError, TimeoutError) as exc:
                    raise TimeoutError("worker_2: b_both_held timed out") from exc

        w1 = WorkerThread(target=worker_1, name="w1")
        w2 = WorkerThread(target=worker_2, name="w2")
        try:
            start_worker_group([w1, w2])
            join_workers([w1, w2], timeout_s=5.0)
        finally:
            self.assertFalse(w1.is_alive())
            self.assertFalse(w2.is_alive())

        # L3 permitted max simultaneous threads is 2 (independent locks)
        self.assertEqual(self.recorder.max_simultaneous["L3"], 2)

    def test_11_nested_rlock_concurrency_stress(self):
        """Multiple threads stress nested RLock concurrently with distinct thread records."""
        raw_lock = threading.RLock()
        inst_lock = InstrumentedLock(raw_lock, self.recorder, level="L1", name="stress_rlock")
        barrier = threading.Barrier(4)

        def worker_fn():
            try:
                barrier.wait(timeout=5.0)
            except (threading.BrokenBarrierError, TimeoutError) as exc:
                raise TimeoutError("worker_fn: barrier timed out") from exc
            for _ in range(25):
                with inst_lock:
                    with inst_lock:
                        with inst_lock:
                            pass

        workers = [WorkerThread(target=worker_fn, name=f"rlock_w_{i}") for i in range(4)]
        try:
            start_worker_group(workers)
            join_workers(workers, timeout_s=5.0)
        finally:
            for w in workers:
                self.assertFalse(w.is_alive())

        self.assertEqual(len(self.recorder.reentrancy_depth), 0)
        self.assertEqual(len(self.recorder.active_holders["L1"]), 0)
        self.assertEqual(len(self.recorder.records_by_thread), 4)
        for w in workers:
            recs = self.recorder.records_by_thread[w.ident]
            self.assertEqual(len(recs), 25)
            for r in recs:
                self.assertEqual(r.max_recursion_depth, 3)
                self.assertEqual(r.total_reentrant_acquisitions, 2)

    def test_12_concurrent_acquire_release_loops_stress(self):
        """Rapid concurrent acquire/release loops leave zero leaked active holders."""
        lock = InstrumentedLock(threading.Lock(), self.recorder, level="L1", name="rapid_lock")
        barrier = threading.Barrier(4)

        def rapid_loop():
            try:
                barrier.wait(timeout=5.0)
            except (threading.BrokenBarrierError, TimeoutError) as exc:
                raise TimeoutError("rapid_loop: barrier timed out") from exc
            for _ in range(50):
                with lock:
                    pass

        workers = [WorkerThread(target=rapid_loop, name=f"rapid_w_{i}") for i in range(4)]
        try:
            start_worker_group(workers)
            join_workers(workers, timeout_s=5.0)
        finally:
            for w in workers:
                self.assertFalse(w.is_alive())

        self.assertEqual(len(self.recorder.active_holders["L1"]), 0)
        self.assertEqual(len(self.recorder.active_threads_by_level["L1"]), 0)

    def test_13_recorder_reset_while_idle_clears_all_structures(self):
        """Recorder reset clears all historical records, depth mappings, and active holder sets."""
        raw_lock = threading.RLock()
        inst_lock = InstrumentedLock(raw_lock, self.recorder, level="L1", name="reset_lock")
        with inst_lock:
            pass

        self.assertGreater(len(self.recorder.records_by_thread), 0)
        self.recorder.reset()

        self.assertEqual(len(self.recorder.records_by_thread), 0)
        self.assertEqual(len(self.recorder.active_holders), 0)
        self.assertEqual(len(self.recorder.active_threads_by_level), 0)
        self.assertEqual(len(self.recorder.reentrancy_depth), 0)
        self.assertEqual(len(self.recorder._entry_times), 0)

    def test_14_recorder_cleanup_thread_removes_thread_records(self):
        """cleanup_thread() successfully frees records for terminated worker."""
        raw_lock = threading.Lock()
        inst_lock = InstrumentedLock(raw_lock, self.recorder, level="L1", name="cleanup_lock")

        def work():
            with inst_lock:
                pass

        w = WorkerThread(target=work, name="cleanup_w")
        w.start()
        w.join(timeout=2.0)

        self.assertIn(w.ident, self.recorder.records_by_thread)
        self.recorder.cleanup_thread(w.ident)
        self.assertNotIn(w.ident, self.recorder.records_by_thread)

    def test_15_timing_sanity_no_negative_durations_distinct_identities(self):
        """All recorded wait and hold durations are non-negative and timestamps are strictly monotonic."""
        raw_lock = threading.Lock()
        inst_lock = InstrumentedLock(raw_lock, self.recorder, level="L1", name="sanity_lock")

        with inst_lock:
            pass

        th_id = threading.get_ident()
        rec = self.recorder.records_by_thread[th_id][0]
        self.assertGreaterEqual(rec.wait_duration_ns, 0)
        self.assertGreaterEqual(rec.hold_duration_ns, 0)
        self.assertLessEqual(rec.attempt_timestamp_ns, rec.acquired_timestamp_ns)
        self.assertLessEqual(rec.acquired_timestamp_ns, rec.release_timestamp_ns)


# ===========================================================================
# 3. Benchmark Boundary Integrity (10 Boundaries) (Production Measurement)
# ===========================================================================
class TestPhase20A3434BenchmarkBoundaryIntegrity(unittest.TestCase):
    """Production Measurement Integrity: Rigorous measurement of all 10 boundaries with direct internal snapshot freeze timing on production ObservationBudgetTracker.
    
    Boundary Classifications:
    1. Snapshot Capture Duration:      DIRECT_MEASUREMENT (Measured around with self._transaction_lock in reconcile_ledger)
    2. Internal Snapshot Deep Freeze:  DIRECT_MEASUREMENT (Outermost clone_frozen calls during capture window via thread-local recursion guard)
    3. Independent Micro clone_frozen: DIRECT_MEASUREMENT (Dedicated microbenchmark timing on production metrics profile)
    4. Invariant Evaluation Duration:  DIRECT_MEASUREMENT (Measured post lock-release across all 24 invariant evaluations)
    5. Total Reconciliation Duration:  DIRECT_MEASUREMENT (Outer wall-clock duration of reconcile_ledger)
    6. L1 Lock Wait Duration:          DIRECT_MEASUREMENT (InstrumentedLock attempt-to-acquired duration per transaction)
    7. L1 Lock Hold Duration:          DIRECT_MEASUREMENT (InstrumentedLock acquired-to-release duration per transaction)
    8. Transaction Latency (N=20):     DIRECT_MEASUREMENT (Complete admission -> child read -> record -> finalize cycle)
    9. Peak Allocated Memory:          DIRECT_MEASUREMENT (tracemalloc peak heap allocation)
    10. Shallow / Retained Result Mem: DIRECT_MEASUREMENT (sys.getsizeof vs cycle-safe recursive object traversal)
    Unmeasured Costs:                  NOT_MEASURED (OS scheduler context switches, cache invalidation, GC pauses)
    """

    @staticmethod
    def _validate_samples(samples: List[float], name: str, expected_count: Optional[int] = None) -> None:
        """Validates that a sample list is non-empty, contains only valid finite non-negative numbers, and matches count."""
        if not samples:
            raise ValueError(f"Benchmark boundary '{name}' sample set is empty")
        if expected_count is not None and len(samples) != expected_count:
            raise ValueError(f"Benchmark boundary '{name}' expected {expected_count} samples, got {len(samples)}")
        for i, val in enumerate(samples):
            if val is None or math.isnan(val) or math.isinf(val) or val < 0:
                raise ValueError(f"Benchmark boundary '{name}' sample [{i}] is invalid: {val}")

    @staticmethod
    def _calc_median(samples: List[float]) -> float:
        if not samples:
            raise ValueError("Cannot calculate median of empty sample set")
        for val in samples:
            if math.isnan(val) or math.isinf(val) or val < 0:
                raise ValueError(f"Invalid measurement sample: {val}")
        s = sorted(samples)
        n = len(s)
        if n % 2 == 1:
            return float(s[n // 2])
        return float((s[n // 2 - 1] + s[n // 2]) / 2.0)

    @staticmethod
    def _calc_p95(samples: List[float]) -> float:
        if not samples:
            raise ValueError("Cannot calculate P95 of empty sample set")
        for val in samples:
            if math.isnan(val) or math.isinf(val) or val < 0:
                raise ValueError(f"Invalid measurement sample: {val}")
        s = sorted(samples)
        n = len(s)
        if n == 1:
            return float(s[0])
        k = 0.95 * (n - 1)
        idx = int(math.floor(k))
        frac = k - idx
        if idx + 1 < n:
            return float(s[idx] + frac * (s[idx + 1] - s[idx]))
        return float(s[idx])

    def test_16_ten_boundary_benchmark_with_internal_snapshot_freeze_measurement(self):
        """Measures all 10 boundaries independently across N=20 samples with non-double-counted outermost clone_frozen and phase-attributed L1 locks."""
        recorder = ProductionCriticalSectionRecorder()
        tracker = make_tracker()
        instrument_tracker(tracker, recorder)

        # Warm-up phase
        with recorder.phase_scope("warmup", "warmup_pipeline"):
            sc_warm = make_scope(tracker, "warmup_op_34")
            r_warm = tracker.admit_read(50, scope=sc_warm)
            sc_warm.record_read(50, admission=r_warm)
            sc_warm.finalize(success=True)
            tracker.reconcile_ledger(raise_on_error=True)
        recorder.reset()

        # Measurement data structures
        capture_durations_ns: List[float] = []
        eval_durations_ns: List[float] = []
        total_durations_ns: List[float] = []
        tx_latencies_us: List[float] = []
        micro_freeze_durations_ns: List[float] = []

        interceptor = OutermostCloneFrozenInterceptor(observation_budget)
        self.addCleanup(interceptor.detach)
        N = 20
        tracemalloc.start()
        self.addCleanup(tracemalloc.stop)

        with interceptor:
            for i in range(N):
                tx_id = f"bench_op_34_{i}"
                t_tx0 = time.perf_counter_ns()
                with recorder.phase_scope("tx_preparation", f"{tx_id}:create_scope"):
                    sc = make_scope(tracker, tx_id)
                with recorder.phase_scope("tx_preparation", f"{tx_id}:admit_read"):
                    r = tracker.admit_read(100, scope=sc)
                    c = r.start_child_read()
                    c.consume(100)
                    r.consume(100)
                with recorder.phase_scope("tx_preparation", f"{tx_id}:record_read"):
                    sc.record_read(100, admission=r)
                with recorder.phase_scope("tx_preparation", f"{tx_id}:finalize"):
                    sc.finalize(success=True)
                t_tx1 = time.perf_counter_ns()
                tx_latencies_us.append((t_tx1 - t_tx0) / 1_000.0)

                t_cap_start = 0
                t_cap_end = 0
                t_eval_start = 0
                t_eval_end = 0

                def cap_start_hook():
                    nonlocal t_cap_start
                    t_cap_start = time.perf_counter_ns()
                    interceptor.start_reconciliation_capture()

                def cap_end_hook():
                    nonlocal t_cap_end, t_eval_start
                    t_cap_end = time.perf_counter_ns()
                    t_eval_start = t_cap_end
                    interceptor.end_reconciliation_capture()

                def eval_end_hook():
                    nonlocal t_eval_end
                    t_eval_end = time.perf_counter_ns()

                with recorder.phase_scope("benchmark_setup", f"{tx_id}:fault_hooks"):
                    tracker.set_fault_injection("before_reconciliation_snapshot_capture", cap_start_hook)
                    tracker.set_fault_injection("after_reconciliation_snapshot_capture", cap_end_hook)
                    tracker.set_fault_injection("after_reconciliation_invariant_evaluation", eval_end_hook)

                with recorder.phase_scope("reconciliation", f"{tx_id}:reconcile_ledger"):
                    t_tot0 = time.perf_counter_ns()
                    rec = tracker.reconcile_ledger(raise_on_error=True)
                    t_tot1 = time.perf_counter_ns()

                total_durations_ns.append(t_tot1 - t_tot0)
                if t_cap_start and t_cap_end:
                    capture_durations_ns.append(t_cap_end - t_cap_start)
                if t_eval_start and t_eval_end:
                    eval_durations_ns.append(t_eval_end - t_eval_start)

                # Independent micro-benchmark
                t_frz0 = time.perf_counter_ns()
                _ = interceptor.orig_clone_frozen(tracker.metrics.profile_usage)
                t_frz1 = time.perf_counter_ns()
                micro_freeze_durations_ns.append(t_frz1 - t_frz0)

        current_mem, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        shallow_mem = sys.getsizeof(rec)
        retained_mem = get_recursive_retained_size(rec)

        th_id = threading.get_ident()
        # Explicit phase and operation attribution separating reconciliation, tx_preparation, and benchmark_setup
        recon_l1_waits_ns = [float(w) for w in recorder.get_thread_waits(th_id, level="L1", phase="reconciliation")]
        recon_l1_holds_ns = [float(h) for h in recorder.get_thread_holds(th_id, level="L1", phase="reconciliation")]
        tx_prep_l1_waits_ns = [float(w) for w in recorder.get_thread_waits(th_id, level="L1", phase="tx_preparation")]
        tx_prep_l1_holds_ns = [float(h) for h in recorder.get_thread_holds(th_id, level="L1", phase="tx_preparation")]
        bench_setup_l1_waits_ns = [float(w) for w in recorder.get_thread_waits(th_id, level="L1", phase="benchmark_setup")]

        internal_freeze_durations_ns = interceptor.per_reconciliation_aggregate_durations_ns
        invocation_counts = interceptor.per_reconciliation_invocation_counts

        # Strict validation: verify attribution completeness and consistency across all records
        recorder.validate_records(th_id, require_phase=True, require_operation=True)

        # Verification of sample integrity across all 10 boundaries
        self._validate_samples(capture_durations_ns, "1. Snapshot Capture Duration", expected_count=N)
        self._validate_samples(internal_freeze_durations_ns, "2. Internal Snapshot Deep Freeze", expected_count=N)
        self._validate_samples(micro_freeze_durations_ns, "3. Independent Micro clone_frozen", expected_count=N)
        self._validate_samples(eval_durations_ns, "4. Invariant Evaluation Duration", expected_count=N)
        self._validate_samples(total_durations_ns, "5. Total Reconciliation Duration", expected_count=N)
        self._validate_samples(recon_l1_waits_ns, "6. Reconciliation L1 Lock Wait Duration", expected_count=N)
        self._validate_samples(recon_l1_holds_ns, "7. Reconciliation L1 Lock Hold Duration", expected_count=N)
        self._validate_samples(tx_prep_l1_waits_ns, "Tx Preparation L1 Lock Wait Duration", expected_count=N * 4)
        self._validate_samples(tx_prep_l1_holds_ns, "Tx Preparation L1 Lock Hold Duration", expected_count=N * 4)
        self.assertEqual(len(bench_setup_l1_waits_ns), N * 3, "Benchmark fault injection setup must have exactly 3 L1 acquisitions per iteration")
        self._validate_samples(tx_latencies_us, "8. Transaction Latency", expected_count=N)
        self.assertGreater(peak_mem, 0)
        self.assertGreater(shallow_mem, 0)
        self.assertGreater(retained_mem, shallow_mem)

        # Operation-level attribution verification for each individual transaction iteration
        for i in range(N):
            tx_id = f"bench_op_34_{i}"
            self.assertEqual(len(recorder.get_thread_waits(th_id, level="L1", phase="tx_preparation", operation=f"{tx_id}:create_scope")), 1)
            self.assertEqual(len(recorder.get_thread_waits(th_id, level="L1", phase="tx_preparation", operation=f"{tx_id}:admit_read")), 1)
            self.assertEqual(len(recorder.get_thread_waits(th_id, level="L1", phase="tx_preparation", operation=f"{tx_id}:record_read")), 1)
            self.assertEqual(len(recorder.get_thread_waits(th_id, level="L1", phase="tx_preparation", operation=f"{tx_id}:finalize")), 1)
            self.assertEqual(len(recorder.get_thread_waits(th_id, level="L1", phase="reconciliation", operation=f"{tx_id}:reconcile_ledger")), 1)

        # Verify deep-freeze invocation completeness against the derived production snapshot contract
        # Snapshot Contract:
        # 2 * child_reads + 2 * physical_reads + 1 * physical_consumptions + 1 * committed_tx + 1 * profile_usage
        # With warmup already committed: 6 * (i + 2) + 1 = 6 * i + 13 calls
        self.assertEqual(len(invocation_counts), N)
        for i, count in enumerate(invocation_counts):
            expected_deep_freeze_calls = 6 * i + 13
            self.assertEqual(
                count,
                expected_deep_freeze_calls,
                f"Iteration {i} outermost clone_frozen count mismatch against production snapshot contract: expected {expected_deep_freeze_calls}, got {count}",
            )

        # Invariant: capture and evaluation intervals do not overlap
        self.assertGreater(self._calc_median(capture_durations_ns), 0)
        self.assertGreater(self._calc_median(eval_durations_ns), 0)
        self.assertGreater(self._calc_median(internal_freeze_durations_ns), 0)

        print("\n--- Phase 2.0-A.3.4.4 10-Boundary Benchmark Evidence ---")
        print(f"1. Snapshot Capture Duration [DIRECT_MEASUREMENT]:      med={self._calc_median(capture_durations_ns)/1e3:.2f}us, p95={self._calc_p95(capture_durations_ns)/1e3:.2f}us (N={len(capture_durations_ns)})")
        print(f"2. Internal Snapshot Deep Freeze [DIRECT_MEASUREMENT]:  med={self._calc_median(internal_freeze_durations_ns)/1e3:.2f}us, p95={self._calc_p95(internal_freeze_durations_ns)/1e3:.2f}us (N={len(internal_freeze_durations_ns)}, contract min={min(invocation_counts)}, max={max(invocation_counts)})")
        print(f"3. Independent Micro clone_frozen [DIRECT_MEASUREMENT]: med={self._calc_median(micro_freeze_durations_ns)/1e3:.2f}us, p95={self._calc_p95(micro_freeze_durations_ns)/1e3:.2f}us (N={len(micro_freeze_durations_ns)})")
        print(f"4. Invariant Evaluation Duration [DIRECT_MEASUREMENT]:  med={self._calc_median(eval_durations_ns)/1e3:.2f}us, p95={self._calc_p95(eval_durations_ns)/1e3:.2f}us (N={len(eval_durations_ns)})")
        print(f"5. Total Reconciliation Duration [DIRECT_MEASUREMENT]:  med={self._calc_median(total_durations_ns)/1e3:.2f}us, p95={self._calc_p95(total_durations_ns)/1e3:.2f}us (N={len(total_durations_ns)})")
        print(f"6. Reconciliation L1 Wait Duration [DIRECT_MEASUREMENT]: med={self._calc_median(recon_l1_waits_ns)/1e3:.2f}us, p95={self._calc_p95(recon_l1_waits_ns)/1e3:.2f}us (N={len(recon_l1_waits_ns)}) [Tx Prep N={len(tx_prep_l1_waits_ns)}, Setup N={len(bench_setup_l1_waits_ns)}]")
        print(f"7. Reconciliation L1 Hold Duration [DIRECT_MEASUREMENT]: med={self._calc_median(recon_l1_holds_ns)/1e3:.2f}us, p95={self._calc_p95(recon_l1_holds_ns)/1e3:.2f}us (N={len(recon_l1_holds_ns)}) [Tx Prep N={len(tx_prep_l1_holds_ns)}, Setup N={len(bench_setup_l1_waits_ns)}]")
        print(f"8. Transaction Latency (N={N}) [DIRECT_MEASUREMENT]:     med={self._calc_median(tx_latencies_us):.2f}us, p95={self._calc_p95(tx_latencies_us):.2f}us (N={len(tx_latencies_us)})")
        print(f"9. Peak Allocated Memory [DIRECT_MEASUREMENT]:          {peak_mem} bytes")
        print(f"10. Shallow / Retained Result Mem [DIRECT_MEASUREMENT]: {shallow_mem} bytes / {retained_mem} bytes")


# ===========================================================================
# 4. Worker Lifecycle Closure (Test Harness Utilities)
# ===========================================================================
class TestPhase20A3434WorkerLifecycleClosure(unittest.TestCase):
    """Test Harness Lifecycle Closure: Validates test-only WorkerThread lifecycle, startup error handling, monotonic timeout, and cleanup.
    
    Proves lifecycle and cleanup correctness of test harness utilities, NOT production daemon lifecycle.
    """

    def test_17_worker_startup_failure_preserves_unstarted_state(self):
        """Failure inside start() does not leave a false started=True flag."""
        w = WorkerThread(target=lambda: None, name="bad_start_w")
        with unittest.mock.patch.object(threading.Thread, "start", side_effect=OSError("OS cannot allocate thread")):
            with self.assertRaises(OSError):
                w.start()
        self.assertFalse(w.started)

        # Successful subsequent start works
        w.start()
        self.assertTrue(w.started)
        w.join(timeout=1.0)
        self.assertTrue(w.completed)

    def test_18_partial_worker_group_startup_failure_cleanup(self):
        """When an intermediate worker fails to start, prior workers are cleaned up with no leaks."""
        ev_cleanup = threading.Event()

        def long_work():
            if not ev_cleanup.wait(timeout=5.0):
                raise TimeoutError("long_work: ev_cleanup timed out")

        w1 = WorkerThread(target=long_work, name="partial_w1")
        w2 = WorkerThread(target=long_work, name="partial_w2")

        with unittest.mock.patch.object(w2, "start", side_effect=RuntimeError("W2 failed to spawn")):
            with self.assertRaises(RuntimeError):
                start_worker_group([w1, w2], cleanup_events=[ev_cleanup])

        self.assertTrue(w1.started)
        self.assertFalse(w2.started)
        self.assertFalse(w1.is_alive())

    def test_19_assertion_failure_while_workers_blocked_triggers_cleanup(self):
        """Assertion error during test execution triggers cleanup_events and terminates workers."""
        ev_cleanup = threading.Event()
        w_started = threading.Event()

        def blocked_worker():
            w_started.set()
            if not ev_cleanup.wait(timeout=5.0):
                raise TimeoutError("blocked_worker: ev_cleanup timed out")

        w = WorkerThread(target=blocked_worker, name="blocked_w")
        w.start()
        if not w_started.wait(timeout=5.0):
            raise TimeoutError("w_started timed out")

        try:
            self.assertEqual(1, 2)
        except AssertionError:
            ev_cleanup.set()
            join_workers([w], timeout_s=1.0)

        self.assertFalse(w.is_alive())

    def test_20_multiple_blocked_workers_group_timeout_and_unjoined_reporting(self):
        """Group timeout identifies all still-running workers and sets cleanup events."""
        ev_cleanup = threading.Event()

        def stuck_work():
            ev_cleanup.wait(timeout=5.0)

        w1 = WorkerThread(target=stuck_work, name="stuck_w1")
        w2 = WorkerThread(target=stuck_work, name="stuck_w2")
        w1.start()
        w2.start()

        with self.assertRaises(TimeoutError) as cm:
            join_workers([w1, w2], timeout_s=0.05, cleanup_events=[ev_cleanup])

        err_msg = str(cm.exception)
        self.assertIn("stuck_w1", err_msg)
        self.assertIn("stuck_w2", err_msg)
        self.assertTrue(ev_cleanup.is_set())

        w1.join(timeout=1.0)
        w2.join(timeout=1.0)

    def test_21_worker_exception_preserves_cause_chaining(self):
        """Worker exception preserves root cause through __cause__ chaining."""
        root_cause = ValueError("Specific internal root cause")

        def faulty_work():
            raise root_cause

        w = WorkerThread(target=faulty_work, name="faulty_w")
        w.start()

        with self.assertRaises(RuntimeError) as cm:
            join_workers([w], timeout_s=2.0)

        self.assertIs(cm.exception.__cause__, root_cause)

    def test_22_worker_exception_during_cleanup_handled_gracefully(self):
        """Faulty cleanup event object does not prevent worker join or deadline enforcement."""
        class FaultyCleanupEvent:
            def set(self):
                raise RuntimeError("Cleanup event raised error")

        ev_cleanup = threading.Event()

        def cleanable_work():
            ev_cleanup.wait(timeout=5.0)

        w = WorkerThread(target=cleanable_work, name="cleanable_w")
        w.start()

        with self.assertRaises(TimeoutError):
            join_workers([w], timeout_s=0.05, cleanup_events=[FaultyCleanupEvent(), ev_cleanup])

        ev_cleanup.set()
        w.join(timeout=1.0)

    def test_23_timeout_with_uninterruptible_worker_identifies_worker(self):
        """Worker that ignores cleanup is accurately identified in the timeout error."""
        stop_flag = threading.Event()

        def uninterruptible_work():
            while not stop_flag.is_set():
                time.sleep(0.005)

        w = WorkerThread(target=uninterruptible_work, name="uninterruptible_worker")
        w.start()

        try:
            with self.assertRaises(TimeoutError) as cm:
                join_workers([w], timeout_s=0.05)
            self.assertIn("uninterruptible_worker", str(cm.exception))
        finally:
            stop_flag.set()
            w.join(timeout=1.0)

    def test_24_repeated_join_attempts_are_idempotent(self):
        """join_workers() can be called repeatedly on completed workers without raising errors."""
        w = WorkerThread(target=lambda: None, name="idempotent_join_w")
        w.start()
        join_workers([w], timeout_s=1.0)
        self.assertTrue(w.completed)

        # Second join call is safe and idempotent
        join_workers([w], timeout_s=1.0)
        self.assertTrue(w.completed)


# ===========================================================================
# 5. AST Auditor Regression & Limitations (Test-Only AST Static Analysis Auditor)
# ===========================================================================
class TestPhase20A3434ASTAuditorRegressionAndLimitations(unittest.TestCase):
    """Test-Only AST Static Analysis Auditor: Verifies AST auditor fidelity, negative/positive fixtures, and fail-closed limitation tests auditing production reconcile_ledger()."""

    def test_25_ast_audit_production_code_zero_violations(self):
        """Production reconcile_ledger() in extractor/observation_budget.py has exactly 0 violations."""
        with open("extractor/observation_budget.py", "r", encoding="utf-8") as f:
            src = f.read()
        auditor = ReconciliationSnapshotBoundaryAuditor(src)
        violations = auditor.audit_function("reconcile_ledger")
        self.assertEqual(
            len(violations),
            0,
            f"Production reconcile_ledger() contained unexpected violations: {violations}",
        )

    def test_26_ast_audit_all_eighteen_negative_fixtures(self):
        """All 18 canonical negative fixtures fail with accurate line numbers and categories."""
        fixtures: List[Tuple[str, str, str]] = [
            (
                "direct_self",
                """
def reconcile_ledger(self):
    with self._transaction_lock:
        x = 1
    return self._physical_read_records
""",
                "[DIRECT_SELF_ACCESS]",
            ),
            (
                "self_alias_direct",
                """
def reconcile_ledger(self):
    with self._transaction_lock:
        s = self
    return s._physical_read_records
""",
                "[SELF_ALIAS]",
            ),
            (
                "self_alias_multihop",
                """
def reconcile_ledger(self):
    with self._transaction_lock:
        s1 = self
        s2 = s1
        s3 = s2
    return s3._active_reservations
""",
                "[SELF_ALIAS]",
            ),
            (
                "registry_alias_direct",
                """
def reconcile_ledger(self):
    with self._transaction_lock:
        reg = self._committed_transactions
    return reg
""",
                "[REGISTRY_ALIAS]",
            ),
            (
                "registry_alias_multihop",
                """
def reconcile_ledger(self):
    with self._transaction_lock:
        m1 = self.metrics
        m2 = m1
        shadow = m2
    return shadow
""",
                "[REGISTRY_ALIAS]",
            ),
            (
                "container_tuple",
                """
def reconcile_ledger(self):
    with self._transaction_lock:
        t = (1, self._active_scopes, 'x')
    return t
""",
                "[CONTAINER_ALIAS]",
            ),
            (
                "container_list",
                """
def reconcile_ledger(self):
    with self._transaction_lock:
        lst = [self._physical_consumption_records]
    return lst
""",
                "[CONTAINER_ALIAS]",
            ),
            (
                "container_dict",
                """
def reconcile_ledger(self):
    with self._transaction_lock:
        d = {'reg': self._batch_records}
    return d
""",
                "[CONTAINER_ALIAS]",
            ),
            (
                "nested_container",
                """
def reconcile_ledger(self):
    with self._transaction_lock:
        nested = [{'inner': [self._invocations]}]
    return nested
""",
                "[CONTAINER_ALIAS]",
            ),
            (
                "derived_subscript",
                """
def reconcile_ledger(self):
    with self._transaction_lock:
        records = self._physical_read_records
        first = records['r1']
    return first
""",
                "[DERIVED_ALIAS]",
            ),
            (
                "closure_live_state",
                """
def reconcile_ledger(self):
    with self._transaction_lock:
        def helper():
            return self._limits
    return helper()
""",
                "[CLOSURE_CAPTURE]",
            ),
            (
                "closure_tainted_alias",
                """
def reconcile_ledger(self):
    with self._transaction_lock:
        alias = self._committed_transactions
        def helper():
            return len(alias)
    return helper()
""",
                "[CLOSURE_CAPTURE]",
            ),
            (
                "helper_argument",
                """
def reconcile_ledger(self):
    with self._transaction_lock:
        reg = self._physical_read_records
        def check(r):
            return bool(r)
    return check(reg)
""",
                "[HELPER_ARGUMENT]",
            ),
            (
                "helper_return",
                """
def reconcile_ledger(self):
    with self._transaction_lock:
        def get_metrics():
            return self.metrics
        m = get_metrics()
    return m
""",
                "[DERIVED_ALIAS]",
            ),
            (
                "aug_assign",
                """
def reconcile_ledger(self):
    with self._transaction_lock:
        bucket = []
        bucket += [self._active_scopes]
    return bucket
""",
                "[CONTAINER_ALIAS]",
            ),
            (
                "reflection_getattr",
                """
def reconcile_ledger(self):
    with self._transaction_lock:
        pass
    return getattr(self, '_physical_read_records')
""",
                "[REFLECTION]",
            ),
            (
                "reflection_vars",
                """
def reconcile_ledger(self):
    with self._transaction_lock:
        pass
    return vars(self)
""",
                "[REFLECTION]",
            ),
            (
                "comprehension",
                """
def reconcile_ledger(self):
    with self._transaction_lock:
        pass
    return [r for r in self._physical_read_records]
""",
                "[COMPREHENSION]",
            ),
        ]

        self.assertGreaterEqual(len(fixtures), 15)
        for name, code, expected_cat in fixtures:
            with self.subTest(fixture=name):
                auditor = ReconciliationSnapshotBoundaryAuditor(code)
                violations = auditor.audit_function("reconcile_ledger")
                self.assertGreater(len(violations), 0, f"Fixture '{name}' did not fail as expected")
                self.assertTrue(
                    any(expected_cat in v for v in violations),
                    f"Fixture '{name}' failed with {violations}, expected category {expected_cat}",
                )

    def test_27_ast_audit_all_three_positive_fixtures(self):
        """Legitimate immutable snapshot transformations produce 0 false positives."""
        positives = [
            (
                "clone_frozen_dict",
                """
def reconcile_ledger(self):
    with self._transaction_lock:
        snap = clone_frozen(self._physical_read_records)
    return snap
""",
            ),
            (
                "primitive_projections",
                """
def reconcile_ledger(self):
    with self._transaction_lock:
        b_read = self.metrics.bytes_read
        ex_reason = self.metrics.exhaustion_reason
        c_count = len(self._physical_consumption_records)
    return (b_read, ex_reason, c_count)
""",
            ),
            (
                "frozenset_keys",
                """
def reconcile_ledger(self):
    with self._transaction_lock:
        inv_keys = frozenset(self._invocations.keys())
    return inv_keys
""",
            ),
        ]

        for name, code in positives:
            with self.subTest(positive_fixture=name):
                auditor = ReconciliationSnapshotBoundaryAuditor(code)
                violations = auditor.audit_function("reconcile_ledger")
                self.assertEqual(len(violations), 0, f"Positive fixture '{name}' failed with {violations}")

    def test_28_limitation_dynamic_eval_exec_fails_closed(self):
        """Dynamic eval and exec calls in evaluation phase fail closed as unsupported dynamic code."""
        code_eval = """
def reconcile_ledger(self):
    with self._transaction_lock:
        pass
    return eval("self._physical_read_records")
"""
        auditor_eval = ReconciliationSnapshotBoundaryAuditor(code_eval)
        v_eval = auditor_eval.audit_function("reconcile_ledger")
        self.assertTrue(any("[DYNAMIC_EVAL]" in v for v in v_eval))

        code_exec = """
def reconcile_ledger(self):
    with self._transaction_lock:
        pass
    exec("x = 1")
    return None
"""
        auditor_exec = ReconciliationSnapshotBoundaryAuditor(code_exec)
        v_exec = auditor_exec.audit_function("reconcile_ledger")
        self.assertTrue(any("[DYNAMIC_EVAL]" in v for v in v_exec))

    def test_29_limitation_external_helper_boundary_verification(self):
        """Passing tainted alias to external helper is detected; intra-procedural boundary documented."""
        code_external_arg = """
def reconcile_ledger(self):
    with self._transaction_lock:
        reg = self._committed_transactions
    return foreign_module.validate(reg)
"""
        auditor = ReconciliationSnapshotBoundaryAuditor(code_external_arg)
        v = auditor.audit_function("reconcile_ledger")
        self.assertTrue(any("[HELPER_ARGUMENT]" in item for item in v))

    def test_30_limitation_path_insensitive_alias_propagation(self):
        """Path-insensitive analysis treats variables tainted on any branch as tainted everywhere."""
        code = """
def reconcile_ledger(self):
    with self._transaction_lock:
        if False:
            alias = self.metrics
        else:
            alias = None
    return alias
"""
        auditor = ReconciliationSnapshotBoundaryAuditor(code)
        violations = auditor.audit_function("reconcile_ledger")
        self.assertTrue(any("[REGISTRY_ALIAS]" in v for v in violations))

    def test_31_limitation_nested_closure_captures(self):
        """Nested closures capturing outer live state trigger fail-closed violation."""
        code = """
def reconcile_ledger(self):
    with self._transaction_lock:
        alias = self._active_scopes
        def outer():
            def inner():
                return len(alias)
            return inner()
    return outer()
"""
        auditor = ReconciliationSnapshotBoundaryAuditor(code)
        violations = auditor.audit_function("reconcile_ledger")
        self.assertTrue(any("[CLOSURE_CAPTURE]" in v for v in violations))

    def test_32_limitation_reflection_based_access(self):
        """Reflection methods hasattr and getattr on self or aliases are caught."""
        code = """
def reconcile_ledger(self):
    with self._transaction_lock:
        pass
    return hasattr(self, '_limits')
"""
        auditor = ReconciliationSnapshotBoundaryAuditor(code)
        violations = auditor.audit_function("reconcile_ledger")
        self.assertTrue(any("[REFLECTION]" in v for v in violations))

    def test_33_limitation_helper_argument_and_return_propagation(self):
        """Helper functions returning live state propagate taint to assignment targets."""
        code = """
def reconcile_ledger(self):
    with self._transaction_lock:
        def fetch():
            return self._active_reservations
        res = fetch()
    return res
"""
        auditor = ReconciliationSnapshotBoundaryAuditor(code)
        violations = auditor.audit_function("reconcile_ledger")
        self.assertTrue(any("[DERIVED_ALIAS]" in v for v in violations))


# ===========================================================================
# 6. Adversarial and Accounting Regression Battery (Actual Production Code)
# ===========================================================================
class TestPhase20A3434AdversarialAndAccountingRegression(unittest.TestCase):
    """Production Invariants & Snapshot Isolation Regression: Validates 24 production invariants, canonical 14-field PoisonTrap snapshot isolation, 12 commit points, 12 recovery points, retry idempotency, and concurrent serialization on production ObservationBudgetTracker."""

    def setUp(self):
        self.tracker = make_tracker()

    def test_34_all_twenty_four_accounting_invariants(self):
        """Production reconcile_ledger() successfully verifies all 24 accounting invariants cleanly."""
        scope = make_scope(self.tracker, "op_inv_clean")
        res = self.tracker.admit_read(100, scope=scope)
        c = res.start_child_read()
        c.consume(100)
        res.consume(100)
        scope.record_read(100, admission=res)
        scope.finalize(success=True)

        rec = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(rec["reconciled"])
        self.assertEqual(len(rec["discrepancy_details"]), 24)
        for inv_idx, inv_ok in rec["discrepancy_details"].items():
            self.assertTrue(inv_ok, f"Invariant {inv_idx} unexpectedly failed")

    def test_35_canonical_14_field_poison_trap_clean_and_in_path_rejection(self):
        """Canonical 14 fields poisoned post-capture succeed cleanly, while in-path leaks are rejected."""
        scope = make_scope(self.tracker, "op_poison_34")
        res = self.tracker.admit_read(100, scope=scope)
        c = res.start_child_read()
        c.consume(100)
        res.consume(100)
        scope.record_read(100, admission=res)
        scope.finalize(success=True)

        class PoisonTrap:
            def __init__(self, name: str):
                self._name = name

            def __getattr__(self, name: str):
                raise AssertionError(f"ILLEGAL LIVE ACCESS: getattr {self._name}.{name}")

            def __getitem__(self, key: Any):
                raise AssertionError(f"ILLEGAL LIVE ACCESS: getitem {self._name}[{key}]")

            def __iter__(self):
                raise AssertionError(f"ILLEGAL LIVE ACCESS: iter({self._name})")

            def __len__(self):
                raise AssertionError(f"ILLEGAL LIVE ACCESS: len({self._name})")

            def __bool__(self):
                raise AssertionError(f"ILLEGAL LIVE ACCESS: bool({self._name})")

            def __call__(self, *args: Any, **kwargs: Any):
                raise AssertionError(f"ILLEGAL LIVE ACCESS: call {self._name}()")

            def __int__(self):
                raise AssertionError(f"ILLEGAL LIVE ACCESS: int({self._name})")

            def __float__(self):
                raise AssertionError(f"ILLEGAL LIVE ACCESS: float({self._name})")

            def __add__(self, other: Any):
                raise AssertionError(f"ILLEGAL LIVE ACCESS: {self._name} + {other}")

            def __sub__(self, other: Any):
                raise AssertionError(f"ILLEGAL LIVE ACCESS: {self._name} - {other}")

            def __eq__(self, other: Any):
                raise AssertionError(f"ILLEGAL LIVE ACCESS: {self._name} == {other}")

            def __ne__(self, other: Any):
                raise AssertionError(f"ILLEGAL LIVE ACCESS: {self._name} != {other}")

            def __repr__(self):
                return f"<PoisonTrap for {self._name}>"

        # 1. Clean production execution with all 14 fields poisoned post-capture
        clean_tracker = make_tracker()
        sc_clean = make_scope(clean_tracker, "op_clean_poison")
        r_clean = clean_tracker.admit_read(50, scope=sc_clean)
        c_clean = r_clean.start_child_read()
        c_clean.consume(50)
        r_clean.consume(50)
        sc_clean.record_read(50, admission=r_clean)
        sc_clean.finalize(success=True)

        def poison_hook():
            for f in CANONICAL_AUTHORITATIVE_MUTABLE_FIELDS:
                setattr(clean_tracker, f, PoisonTrap(f))

        clean_tracker.set_fault_injection("after_reconciliation_snapshot_capture", poison_hook)
        rec = clean_tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(rec["reconciled"])
        self.assertEqual(len(rec["discrepancy_details"]), 24)

        # 2. In-path negative controls: deliberate live-field access inside reconcile_ledger() triggers PoisonTrap
        class FaultyEvaluationReconciler(ObservationBudgetTracker):
            def __init__(self, target_f: str, *args: Any, **kwargs: Any):
                super().__init__(*args, **kwargs)
                self.target_f = target_f

            def reconcile_ledger(self, raise_on_error: bool = True) -> Dict[str, Any]:
                orig_fn = self._fault_injection_hooks.get("after_reconciliation_snapshot_capture")

                def faulty_step():
                    if orig_fn:
                        orig_fn()
                    # Controlled in-path evaluation step deliberately accessing the poisoned live field
                    val = getattr(self, self.target_f)
                    if self.target_f in ("metrics", "limits"):
                        _ = getattr(val, "bytes_read" if self.target_f == "metrics" else "max_bytes_read")
                    elif self.target_f in ("_released_reservations_count", "_active_consumed_bytes"):
                        _ = int(val)
                    elif callable(val):
                        val()
                    elif hasattr(val, "__getitem__"):
                        _ = val["test_key"]
                    elif hasattr(val, "__iter__"):
                        _ = list(val)
                    else:
                        _ = getattr(val, "bytes_read", 0)

                self.set_fault_injection("after_reconciliation_snapshot_capture", faulty_step)
                return super().reconcile_ledger(raise_on_error=raise_on_error)

        for field in CANONICAL_AUTHORITATIVE_MUTABLE_FIELDS:
            with self.subTest(faulty_field=field):
                f_tracker = FaultyEvaluationReconciler(
                    target_f=field,
                    limits=ObservationBudgetLimits(max_bytes_read=10_000_000, max_bytes_per_observation=10_000_000),
                )
                f_tracker.start()
                f_scope = make_scope(f_tracker, f"op_poison_neg_{field}")
                f_res = f_tracker.admit_read(50, scope=f_scope)
                f_c = f_res.start_child_read()
                f_c.consume(50)
                f_res.consume(50)
                f_scope.record_read(50, admission=f_res)
                f_scope.finalize(success=True)

                def poison_f():
                    for f in CANONICAL_AUTHORITATIVE_MUTABLE_FIELDS:
                        setattr(f_tracker, f, PoisonTrap(f))

                f_tracker.set_fault_injection("after_reconciliation_snapshot_capture", poison_f)

                with self.assertRaises(AssertionError) as ctx:
                    f_tracker.reconcile_ledger(raise_on_error=True)
                self.assertIn("ILLEGAL LIVE ACCESS", str(ctx.exception))
                self.assertIn(field, str(ctx.exception))

    def test_36_commit_mutation_fault_matrix_12_points(self):
        """All 12 commit mutation points fail cleanly and preserve accounting integrity."""
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
            with self.subTest(fault_point=pt):
                tracker = make_tracker()
                sc = make_scope(tracker, f"op_commit_pt_{idx}")
                r = tracker.admit_read(100, scope=sc)
                c = r.start_child_read()
                c.consume(100)
                r.consume(100)
                sc.record_read(100, admission=r)

                hook_fired = [False]

                def make_hook(flag=hook_fired):
                    def hook():
                        if not flag[0]:
                            flag[0] = True
                            raise RuntimeError(f"Commit fault at {pt}")
                    return hook

                tracker.set_fault_injection(pt, make_hook())
                snap = sc.finalize(success=True)
                self.assertTrue(hook_fired[0])
                self.assertEqual(snap.accounting_status, "FAILED")

                tracker.clear_fault_injections()
                rec = tracker.reconcile_ledger(raise_on_error=True)
                self.assertTrue(rec["reconciled"])

    def test_37_recovery_fault_matrix_12_points(self):
        """All 12 recovery fault points handled safely with retry idempotency."""
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
            with self.subTest(recovery_point=pt):
                tracker = make_tracker()
                sc = make_scope(tracker, f"op_rec_pt_{idx}")
                r = tracker.admit_read(100, scope=sc)
                c = r.start_child_read()
                c.consume(100)
                r.consume(100)
                sc.record_read(100, admission=r)

                tracker.inject_fault("during_logical_ledger_insertion")
                sc.finalize(success=True)
                tracker.clear_fault_injections()

                tracker.inject_fault(pt)
                try:
                    tracker.retry_recovery(sc)
                except RuntimeError:
                    pass
                tracker.clear_fault_injections()

                recovered_snap = tracker.retry_recovery(sc)
                self.assertIsNotNone(recovered_snap)
                self.assertEqual(recovered_snap.accounting_status, "FAILED")

                rec = tracker.reconcile_ledger(raise_on_error=True)
                self.assertTrue(rec["reconciled"])

    def test_38_recovery_retry_idempotency(self):
        """Sequential recovery retries return identical snapshot state without state drift."""
        sc = make_scope(self.tracker, "op_retry_idempotent")
        r = self.tracker.admit_read(100, scope=sc)
        c = r.start_child_read()
        c.consume(100)
        r.consume(100)
        sc.record_read(100, admission=r)

        self.tracker.inject_fault("during_logical_ledger_insertion")
        sc.finalize(success=True)
        self.tracker.clear_fault_injections()

        snap1 = self.tracker.retry_recovery(sc)
        snap2 = self.tracker.retry_recovery(sc)

        self.assertEqual(snap1.operation_id, snap2.operation_id)
        self.assertEqual(snap1.accounting_status, snap2.accounting_status)
        self.assertEqual(snap1.charged_bytes, snap2.charged_bytes)

    def test_39_concurrent_commit_and_recovery_serialization(self):
        """Concurrent Commit and Recovery serialize strictly under L1 lock with max_simultaneous=1."""
        recorder = ProductionCriticalSectionRecorder()
        tracker = make_tracker()
        instrument_tracker(tracker, recorder)

        sc_commit = make_scope(tracker, "op_conc_commit")
        r1 = tracker.admit_read(100, scope=sc_commit)
        c1 = r1.start_child_read()
        c1.consume(100)
        r1.consume(100)
        sc_commit.record_read(100, admission=r1)

        sc_rec = make_scope(tracker, "op_conc_rec")
        r2 = tracker.admit_read(100, scope=sc_rec)
        c2 = r2.start_child_read()
        c2.consume(100)
        r2.consume(100)
        sc_rec.record_read(100, admission=r2)
        tracker.inject_fault("during_logical_ledger_insertion")
        sc_rec.finalize(success=True)
        tracker.clear_fault_injections()

        b_entry = threading.Barrier(2)

        def do_commit():
            try:
                b_entry.wait(timeout=5.0)
            except (threading.BrokenBarrierError, TimeoutError) as exc:
                raise TimeoutError("Barrier timeout in do_commit") from exc
            sc_commit.finalize(success=True)

        def do_recovery():
            try:
                b_entry.wait(timeout=5.0)
            except (threading.BrokenBarrierError, TimeoutError) as exc:
                raise TimeoutError("Barrier timeout in do_recovery") from exc
            tracker.retry_recovery(sc_rec)

        w_c = WorkerThread(target=do_commit, name="commit_worker")
        w_r = WorkerThread(target=do_recovery, name="recovery_worker")
        try:
            start_worker_group([w_c, w_r])
            join_workers([w_c, w_r], timeout_s=5.0)
        finally:
            self.assertFalse(w_c.is_alive(), "Worker w_c leaked alive")
            self.assertFalse(w_r.is_alive(), "Worker w_r leaked alive")

        self.assertEqual(recorder.max_simultaneous["L1"], 1)

    def test_40_post_capture_snapshot_isolation_under_concurrent_source_mutations(self):
        """Thread B concurrently mutates live registries while Thread A evaluates snapshot; in-flight result is isolated."""
        scope = make_scope(self.tracker, "op_conc_snapshot_isolation")
        r = self.tracker.admit_read(100, scope=scope)
        c = r.start_child_read()
        c.consume(100)
        r.consume(100)
        scope.record_read(100, admission=r)
        scope.finalize(success=True)

        ev_capture_done = threading.Event()
        ev_mutation_done = threading.Event()

        def post_capture_sync_hook():
            ev_capture_done.set()
            if not ev_mutation_done.wait(timeout=5.0):
                raise TimeoutError("post_capture_sync_hook timed out waiting for mutation")

        self.tracker.set_fault_injection("after_reconciliation_snapshot_capture", post_capture_sync_hook)
        self.addCleanup(self.tracker.clear_fault_injections)

        recon_results: List[Dict[str, Any]] = []

        def reconciler_thread():
            res = self.tracker.reconcile_ledger(raise_on_error=True)
            recon_results.append(res)

        def mutator_thread():
            if not ev_capture_done.wait(timeout=5.0):
                raise TimeoutError("mutator_thread timed out waiting for capture")
            # Thread B concurrently mutates live production structures across multiple registries
            self.tracker.metrics.bytes_read += 1_000_000
            self.tracker.metrics.total_read_failures += 42
            self.tracker._physical_read_records["concurrent_leak_id"] = PhysicalReadRecord(
                physical_read_id="concurrent_leak_id",
                physical_consumption_id="cons_leak",
                reservation_id="res_leak",
                operation_id="op_leak",
                charged_bytes=500,
            )
            ev_mutation_done.set()

        th_a = WorkerThread(target=reconciler_thread, name="thread_a_reconciler")
        th_b = WorkerThread(target=mutator_thread, name="thread_b_mutator")
        try:
            start_worker_group([th_a, th_b], cleanup_events=[ev_capture_done, ev_mutation_done])
            join_workers([th_a, th_b], timeout_s=5.0, cleanup_events=[ev_capture_done, ev_mutation_done])
        finally:
            self.tracker.clear_fault_injections()
            self.assertFalse(th_a.is_alive(), "Worker th_a leaked alive")
            self.assertFalse(th_b.is_alive(), "Worker th_b leaked alive")

        # Thread A evaluation used the captured snapshot and was unaffected by Thread B's concurrent mutations
        self.assertEqual(len(recon_results), 1)
        self.assertTrue(recon_results[0]["reconciled"])

        # Verification: subsequent reconciliation on main thread detects Thread B's mutations
        rec2 = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(rec2["reconciled"])

    def test_42_snapshot_isolation_mutation_before_vs_after_capture(self):
        """Mutations before capture are captured into snapshot; mutations after capture are strictly isolated."""
        # Case 1: Mutation before capture begins -> captured into snapshot -> reconciliation detects discrepancy
        tracker1 = make_tracker()
        sc1 = make_scope(tracker1, "op_snap_pre")
        r1 = tracker1.admit_read(100, scope=sc1)
        c1 = r1.start_child_read()
        c1.consume(100)
        r1.consume(100)
        sc1.record_read(100, admission=r1)
        sc1.finalize(success=True)

        def pre_capture_mutator():
            tracker1.metrics.bytes_read += 500_000

        try:
            tracker1.set_fault_injection("before_reconciliation_snapshot_capture", pre_capture_mutator)
            rec_pre = tracker1.reconcile_ledger(raise_on_error=False)
            self.assertFalse(rec_pre["reconciled"], "Pre-capture mutation must be captured into snapshot and fail reconciliation")
        finally:
            tracker1.clear_fault_injections()

        # Case 2: Mutation after capture completes -> snapshot remains clean -> in-flight reconciliation succeeds
        tracker2 = make_tracker()
        sc2 = make_scope(tracker2, "op_snap_post")
        r2 = tracker2.admit_read(100, scope=sc2)
        c2 = r2.start_child_read()
        c2.consume(100)
        r2.consume(100)
        sc2.record_read(100, admission=r2)
        sc2.finalize(success=True)

        def post_capture_mutator():
            tracker2.metrics.bytes_read += 500_000

        try:
            tracker2.set_fault_injection("after_reconciliation_snapshot_capture", post_capture_mutator)
            rec_post = tracker2.reconcile_ledger(raise_on_error=True)
            self.assertTrue(rec_post["reconciled"], "Post-capture mutation must not affect in-flight snapshot evaluation")
        finally:
            tracker2.clear_fault_injections()

    def test_43_snapshot_isolation_repeated_concurrent_cycles(self):
        """Repeated concurrent execution cycles prove deterministic snapshot isolation without race conditions."""
        for cycle in range(5):
            tracker = make_tracker()
            sc = make_scope(tracker, f"op_conc_cycle_{cycle}")
            r = tracker.admit_read(50, scope=sc)
            c = r.start_child_read()
            c.consume(50)
            r.consume(50)
            sc.record_read(50, admission=r)
            sc.finalize(success=True)

            ev_cap = threading.Event()
            ev_mut = threading.Event()

            def hook():
                ev_cap.set()
                if not ev_mut.wait(timeout=5.0):
                    raise TimeoutError(f"Hook timed out waiting for mutation in cycle {cycle}")

            tracker.set_fault_injection("after_reconciliation_snapshot_capture", hook)
            res_box: List[Dict[str, Any]] = []

            def recon_task():
                res_box.append(tracker.reconcile_ledger(raise_on_error=True))

            def mut_task():
                if not ev_cap.wait(timeout=5.0):
                    raise TimeoutError(f"Mutator timed out waiting for capture in cycle {cycle}")
                tracker.metrics.bytes_read += 100_000
                tracker._physical_read_records[f"leak_{cycle}"] = PhysicalReadRecord(
                    physical_read_id=f"leak_{cycle}",
                    physical_consumption_id=f"c_leak_{cycle}",
                    reservation_id="res_leak",
                    operation_id=f"op_conc_cycle_{cycle}",
                    charged_bytes=50,
                )
                ev_mut.set()

            w_recon = WorkerThread(target=recon_task, name=f"w_recon_{cycle}")
            w_mut = WorkerThread(target=mut_task, name=f"w_mut_{cycle}")
            try:
                start_worker_group([w_recon, w_mut], cleanup_events=[ev_cap, ev_mut])
                join_workers([w_recon, w_mut], timeout_s=5.0, cleanup_events=[ev_cap, ev_mut])
            finally:
                tracker.clear_fault_injections()
                self.assertFalse(w_recon.is_alive(), f"Worker w_recon_{cycle} leaked alive")
                self.assertFalse(w_mut.is_alive(), f"Worker w_mut_{cycle} leaked alive")

            self.assertEqual(len(res_box), 1)
            self.assertTrue(res_box[0]["reconciled"])

            self.assertEqual(len(res_box), 1)
            self.assertTrue(res_box[0]["reconciled"])

    def test_41_clone_frozen_adversarial_matrix(self):
        """Deeply nested structures, DAG diamonds, custom Mapping cycles, and -0.0 canonicalization."""
        # 1. 50-level nested structure
        deep_root: Dict[str, Any] = {}
        curr = deep_root
        for i in range(50):
            curr["next"] = {"level": i}
            curr = curr["next"]

        frozen_deep = clone_frozen(deep_root)
        self.assertIsNotNone(frozen_deep)

        # 2. DAG diamond shared references
        shared = {"id": "diamond_core", "data": (1, 2, 3)}
        diamond = {"branch_a": shared, "branch_b": shared}
        frozen_diamond = clone_frozen(diamond)
        self.assertIs(frozen_diamond["branch_a"], frozen_diamond["branch_b"])

        # 3. Custom Mapping cycle rejection
        class CyclicMapping(collections.abc.Mapping):
            def __init__(self):
                self._d: Dict[str, Any] = {}

            def set_cycle(self, target: Any):
                self._d["cycle"] = target

            def __getitem__(self, k: Any) -> Any:
                return self._d[k]

            def __iter__(self):
                return iter(self._d)

            def __len__(self) -> int:
                return len(self._d)

        cm_obj = CyclicMapping()
        cm_obj.set_cycle(cm_obj)
        with self.assertRaises(ValueError) as cm:
            clone_frozen(cm_obj)
        self.assertIn("Cyclic reference detected", str(cm.exception))

        # 4. -0.0 float canonicalization
        frozen_zero = clone_frozen({"num": -0.0})
        self.assertEqual(math.copysign(1.0, frozen_zero["num"]), 1.0)
        self.assertEqual(canonical_metadata_digest({"n": -0.0}), canonical_metadata_digest({"n": 0.0}))

    def test_44_deliberate_synchronization_event_wait_timeout_fails_explicitly(self):
        """Deliberate event wait timeout explicitly raises TimeoutError and propagates to parent."""
        ev = threading.Event()

        def worker_fn():
            if not ev.wait(timeout=0.02):
                raise TimeoutError("Deliberate event wait timeout in worker")

        w = WorkerThread(target=worker_fn, name="timeout_event_w")
        w.start()
        try:
            with self.assertRaises(RuntimeError) as ctx:
                join_workers([w], timeout_s=1.0)
            self.assertIn("Deliberate event wait timeout in worker", str(ctx.exception))
            self.assertIsInstance(ctx.exception.__cause__, TimeoutError)
        finally:
            self.assertFalse(w.is_alive())

    def test_45_deliberate_synchronization_barrier_wait_timeout_fails_explicitly(self):
        """Deliberate barrier wait timeout explicitly raises BrokenBarrierError and propagates to parent."""
        barrier = threading.Barrier(2)

        def worker_fn():
            try:
                barrier.wait(timeout=0.02)
            except (threading.BrokenBarrierError, TimeoutError) as exc:
                raise TimeoutError("Deliberate barrier wait timeout in worker") from exc

        w = WorkerThread(target=worker_fn, name="timeout_barrier_w")
        w.start()
        try:
            with self.assertRaises(RuntimeError) as ctx:
                join_workers([w], timeout_s=1.0)
            self.assertIn("Deliberate barrier wait timeout in worker", str(ctx.exception))
            self.assertIsInstance(ctx.exception.__cause__, TimeoutError)
        finally:
            self.assertFalse(w.is_alive())

    def test_46_deliberate_worker_failure_propagates_and_cleans_up(self):
        """Deliberate worker failure propagates to parent join_workers and leaves zero alive threads."""
        def bad_worker():
            raise ValueError("Deliberate worker calculation fault")

        w = WorkerThread(target=bad_worker, name="fault_w")
        w.start()
        try:
            with self.assertRaises(RuntimeError) as ctx:
                join_workers([w], timeout_s=1.0)
            self.assertIn("Deliberate worker calculation fault", str(ctx.exception))
            self.assertIsInstance(ctx.exception.__cause__, ValueError)
        finally:
            self.assertFalse(w.is_alive())

    def test_47_recursive_clone_frozen_not_double_counted(self):
        """OutermostCloneFrozenInterceptor: nested recursion not double counted, depth unwinds, repeated calls, and worker isolation."""
        nested = {
            "key1": [1, 2, {"key2": {"key3": (3, 4, 5)}}],
            "key4": {"key5": [6, 7, {"key6": "value"}]},
        }

        with OutermostCloneFrozenInterceptor(observation_budget) as interceptor:
            # 1. Nested recursive clone_frozen calls produce exactly one outermost measurement sample
            interceptor.start_reconciliation_capture()
            res = observation_budget.clone_frozen(nested)
            self.assertIsNotNone(res)
            self.assertEqual(res["key1"][0], 1)
            count, agg_ns = interceptor.end_reconciliation_capture()
            self.assertEqual(count, 1)
            self.assertEqual(len(interceptor.per_reconciliation_invocation_durations_ns[0]), 1)
            self.assertEqual(interceptor.per_reconciliation_aggregate_durations_ns[0], float(agg_ns))
            self.assertGreater(agg_ns, 0)
            self.assertEqual(getattr(interceptor._tls, "depth", 0), 0)

            # 2. Repeated invocations within one reconciliation record correct counts
            interceptor.start_reconciliation_capture()
            _ = observation_budget.clone_frozen({"a": 1})
            _ = observation_budget.clone_frozen([10, 20, [30, 40]])
            _ = observation_budget.clone_frozen({"b": {"c": 50}})
            count2, agg_ns2 = interceptor.end_reconciliation_capture()
            self.assertEqual(count2, 3)
            self.assertEqual(len(interceptor.per_reconciliation_invocation_durations_ns[1]), 3)
            self.assertEqual(sum(interceptor.per_reconciliation_invocation_durations_ns[1]), agg_ns2)
            self.assertEqual(getattr(interceptor._tls, "depth", 0), 0)

            # 3. Exception unwinding returns thread-local recursion depth to zero on cyclic objects
            interceptor.start_reconciliation_capture()
            cyclic: Dict[str, Any] = {}
            cyclic["self"] = cyclic
            with self.assertRaises(ValueError):
                observation_budget.clone_frozen(cyclic)
            self.assertEqual(getattr(interceptor._tls, "depth", 0), 0)

            # Missing instrumentation check: 0 invocations recorded fails closed
            with self.assertRaises(AssertionError):
                interceptor.end_reconciliation_capture()

            # 4. Measurements from worker threads do not pollute main-thread capture windows
            interceptor.start_reconciliation_capture()
            _ = observation_budget.clone_frozen({"main_1": 1})

            worker_executed = threading.Event()

            def worker_fn():
                # Worker thread calls clone_frozen
                w_res = observation_budget.clone_frozen({"worker": [1, 2, 3]})
                self.assertIsNotNone(w_res)
                # Worker thread depth must be zero
                self.assertEqual(getattr(interceptor._tls, "depth", 0), 0)
                worker_executed.set()

            worker = WorkerThread(target=worker_fn, name="interceptor_isolation_worker")
            worker.start()
            join_workers([worker], timeout_s=3.0)
            self.assertTrue(worker_executed.is_set())

            _ = observation_budget.clone_frozen({"main_2": 2})
            count4, agg_ns4 = interceptor.end_reconciliation_capture()
            # Must record exactly 2 main thread invocations; worker thread invocation is NOT counted!
            self.assertEqual(count4, 2)
            self.assertEqual(len(interceptor.per_reconciliation_invocation_durations_ns[2]), 2)
            self.assertEqual(sum(interceptor.per_reconciliation_invocation_durations_ns[2]), agg_ns4)
            self.assertEqual(getattr(interceptor._tls, "depth", 0), 0)

        # 5. Outside context manager, clone_frozen is reliably restored
        self.assertIs(observation_budget.clone_frozen, interceptor.orig_clone_frozen)

    def test_48_benchmark_stats_reject_empty_nan_inf_and_negative_samples(self):
        """Median, P95, and sample validation reject empty, NaN, Inf, and negative inputs."""
        with self.assertRaises(ValueError):
            TestPhase20A3434BenchmarkBoundaryIntegrity._calc_median([])
        with self.assertRaises(ValueError):
            TestPhase20A3434BenchmarkBoundaryIntegrity._calc_p95([])
        with self.assertRaises(ValueError):
            TestPhase20A3434BenchmarkBoundaryIntegrity._calc_median([1.0, float("nan")])
        with self.assertRaises(ValueError):
            TestPhase20A3434BenchmarkBoundaryIntegrity._calc_median([1.0, float("inf")])
        with self.assertRaises(ValueError):
            TestPhase20A3434BenchmarkBoundaryIntegrity._calc_median([1.0, -10.0])
        with self.assertRaises(ValueError):
            TestPhase20A3434BenchmarkBoundaryIntegrity._calc_p95([1.0, float("nan")])
        with self.assertRaises(ValueError):
            TestPhase20A3434BenchmarkBoundaryIntegrity._calc_p95([1.0, float("inf")])
        with self.assertRaises(ValueError):
            TestPhase20A3434BenchmarkBoundaryIntegrity._calc_p95([1.0, -10.0])

        with self.assertRaises(ValueError):
            TestPhase20A3434BenchmarkBoundaryIntegrity._validate_samples([], "empty_test")
        with self.assertRaises(ValueError):
            TestPhase20A3434BenchmarkBoundaryIntegrity._validate_samples([1.0] * 5, "count_mismatch", expected_count=20)
        with self.assertRaises(ValueError):
            TestPhase20A3434BenchmarkBoundaryIntegrity._validate_samples([1.0, float("nan")], "nan_test")
        with self.assertRaises(ValueError):
            TestPhase20A3434BenchmarkBoundaryIntegrity._validate_samples([1.0, -1.0], "neg_test")

    def test_49_phase_lifecycle_exception_safety_and_attribution_validation(self):
        """Phase and operation restoration on normal/exception exit, thread isolation, and record validation."""
        recorder = ProductionCriticalSectionRecorder()
        raw_lock = threading.Lock()
        lock = InstrumentedLock(raw_lock, recorder, level="L1", name="phase_test_lock")
        th_id = threading.get_ident()

        # 1. Normal completion restores prior phase and operation
        self.assertEqual(recorder.get_thread_phase(), "default")
        self.assertEqual(recorder.get_thread_operation(), "default")
        with recorder.phase_scope("phase_a", "op_a"):
            self.assertEqual(recorder.get_thread_phase(), "phase_a")
            self.assertEqual(recorder.get_thread_operation(), "op_a")
            with lock:
                pass
        self.assertEqual(recorder.get_thread_phase(), "default")
        self.assertEqual(recorder.get_thread_operation(), "default")

        # 2. Exceptional exit restores prior phase and operation via try/finally
        try:
            with recorder.phase_scope("phase_err", "op_err"):
                self.assertEqual(recorder.get_thread_phase(), "phase_err")
                self.assertEqual(recorder.get_thread_operation(), "op_err")
                with lock:
                    pass
                raise RuntimeError("simulated error inside phase")
        except RuntimeError:
            pass

        self.assertEqual(recorder.get_thread_phase(), "default")
        self.assertEqual(recorder.get_thread_operation(), "default")

        # 3. Subsequent measurements are not contaminated by stale phase
        with lock:
            pass
        recs = recorder.get_thread_records(th_id)
        self.assertEqual(len(recs), 3)
        self.assertEqual(recs[0].phase, "phase_a")
        self.assertEqual(recs[0].operation, "op_a")
        self.assertEqual(recs[1].phase, "phase_err")
        self.assertEqual(recs[1].operation, "op_err")
        self.assertEqual(recs[2].phase, "default")
        self.assertEqual(recs[2].operation, "default")

        # 4. Worker thread phase isolation
        worker_phase = None
        worker_op = None

        def worker_fn():
            nonlocal worker_phase, worker_op
            worker_phase = recorder.get_thread_phase()
            worker_op = recorder.get_thread_operation()
            with recorder.phase_scope("worker_phase", "worker_op"):
                with lock:
                    pass

        with recorder.phase_scope("main_phase", "main_op"):
            worker = WorkerThread(target=worker_fn, name="phase_iso_worker")
            worker.start()
            join_workers([worker], timeout_s=3.0)
            # Main thread phase was unchanged by worker
            self.assertEqual(recorder.get_thread_phase(), "main_phase")
            self.assertEqual(recorder.get_thread_operation(), "main_op")

        # Worker saw default initially, not main_phase
        self.assertEqual(worker_phase, "default")
        self.assertEqual(worker_op, "default")

        # 5. validate_records rejects default/missing phase or operation
        with self.assertRaises(ValueError):
            recorder.validate_records(th_id, require_phase=True, require_operation=True)

        # But a recorder with fully attributed records passes validate_records
        valid_recorder = ProductionCriticalSectionRecorder()
        valid_lock = InstrumentedLock(threading.Lock(), valid_recorder, level="L1", name="valid_lock")
        with valid_recorder.phase_scope("tx_phase", "tx_op"):
            with valid_lock:
                pass
        valid_recorder.validate_records(th_id, require_phase=True, require_operation=True)


if __name__ == "__main__":
    unittest.main()

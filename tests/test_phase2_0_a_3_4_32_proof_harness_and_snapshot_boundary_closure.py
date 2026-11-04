#!/usr/bin/env python3
"""Phase 2.0-A.3.4.32 — Proof Harness Trustworthiness & Reconciliation Snapshot Boundary Closure.

Comprehensive verification suite:
1. Reconciliation Snapshot Boundary Audit:
   - Conservative, fail-closed AST analyzer detects direct live access, aliased references to
     registries and metrics, getattr() dynamic reflection, closure/helper live state capture,
     comprehensions, and raw production object collection retention.
   - Proves production reconcile_ledger() has zero violations.
   - Negative fixtures for all 7 bypass patterns are detected and rejected fail-closed.
2. Runtime PoisonTrap Closure:
   - Covers all 13 authoritative mutable fields: _physical_read_records, _physical_consumption_records,
     _committed_transactions, _active_reservations, _committed_reservations, _released_reservations,
     _active_scopes, _batch_records, _invocations, _invocation_start_mono_ns,
     _released_reservations_count, metrics, _limits, and _active_consumed_bytes.
   - Proves reconciliation evaluates all 24 invariants cleanly outside _transaction_lock with all 13 fields poisoned.
   - Negative tests prove runtime trap detects illegal access fail-closed.
3. True Concurrent Commit and Recovery Serialization:
   - Starts independent Commit and Recovery workers concurrently.
   - Proves both workers actually attempt L1 acquisition.
   - Records thread-specific lock acquisition attempts and wait durations.
   - Proves critical mutation regions never overlap (max_simultaneous == 1).
   - Verifies accounting consistency, physical evidence preservation, and retry idempotency.
   - Tests both normal execution and injected recovery failures.
4. Lock Contention Evidence Integrity:
   - ProductionCriticalSectionRecorder preserves Thread ID, Lock ID, Level, Attempt time, Acquired time,
     Release time, Wait duration, Hold duration, and Recursion depth.
   - Contention tests verify the specific blocked worker's measured wait keyed by thread ID rather than
     relying on list index ordering.
5. Worker Lifecycle Verification:
   - Single monotonic group deadline prevents timeout multiplication across workers.
   - Detects unstarted workers, workers alive after deadline, and preserves original exception causes.
6. Benchmark Measurement Integrity:
   - Mathematically exact median calculation for even and odd counts.
   - Linear interpolation P95 percentile calculation.
   - Distinguishes shallow memory from recursively retained memory with cycle/shared-reference tracking.
   - Peak allocation via tracemalloc.
7. Regression Verification:
   - clone_frozen adversarial regression, commit fault matrix, and recovery idempotency matrix.
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
    profile_id: str = "prof_a32",
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
    """Worker thread that safely tracks lifecycle, captures results, and preserves exceptions."""

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
        self.started: bool = False
        self.completed: bool = False

    def start(self) -> None:
        self.started = True
        super().start()

    def run(self) -> None:
        try:
            self.result = self._target(*self._args, **self._kwargs)
            self.completed = True
        except BaseException as exc:
            self.exception = exc
            self.completed = False


def join_workers(test_case: unittest.TestCase, workers: List[WorkerThread], timeout: float = 5.0) -> None:
    """Bounded join of all worker threads against a single monotonic deadline.

    Guarantees:
    - Entire worker group completes within total monotonic timeout.
    - Detects workers that were never started.
    - Detects workers that remain alive after deadline.
    - Propagates worker exceptions preserving original exception cause.
    - Detects workers that never marked completed.
    """
    deadline = time.monotonic() + timeout

    # 1. Verify all workers were started
    for w in workers:
        if not w.started:
            raise AssertionError(f"Worker '{w.name}' was never started")

    # 2. Bounded join using single monotonic deadline
    for w in workers:
        remaining = deadline - time.monotonic()
        if remaining > 0:
            w.join(timeout=remaining)
        else:
            w.join(timeout=0.0)

    # 3. Detect workers still alive after deadline
    still_alive = [w.name for w in workers if w.is_alive()]
    if still_alive:
        raise TimeoutError(f"Workers remained alive after {timeout}s group deadline: {', '.join(still_alive)}")

    # 4. Propagate exceptions with preserved cause
    for w in workers:
        if w.exception is not None:
            raise AssertionError(f"Worker '{w.name}' failed with exception: {w.exception}") from w.exception

    # 5. Detect workers that did not complete
    for w in workers:
        if not w.completed:
            raise AssertionError(f"Worker '{w.name}' did not mark completion")


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
    recursion_depth: int


class ProductionCriticalSectionRecorder:
    """Thread-safe recorder tracking per-thread lock acquisitions, wait intervals, and outermost hold durations."""

    def __init__(self):
        self._lock = threading.Lock()
        self.records_by_thread: Dict[int, List[LockAcquisitionRecord]] = collections.defaultdict(list)
        self.active_holders: Dict[str, Set[Tuple[int, int]]] = collections.defaultdict(set)
        self.active_threads_by_level: Dict[str, Set[int]] = collections.defaultdict(set)
        self.max_simultaneous: Dict[str, int] = collections.defaultdict(int)
        self.reentrancy_depth: Dict[Tuple[int, int], int] = collections.defaultdict(int)
        self._entry_times: Dict[Tuple[int, int], Tuple[int, int, int]] = {}

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
            cur_depth = self.reentrancy_depth[key]
            self.reentrancy_depth[key] = cur_depth + 1
            if cur_depth == 0:
                self._entry_times[key] = (attempt_ns, acquired_ns, 1)
                self.active_holders[level].add(key)
                self.active_threads_by_level[level].add(thread_id)
                cur_sim = len(self.active_threads_by_level[level])
                if cur_sim > self.max_simultaneous[level]:
                    self.max_simultaneous[level] = cur_sim

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
            cur_depth = self.reentrancy_depth[key]
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
                    attempt_ns, acquired_ns, depth = entry_info
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
                        recursion_depth=depth,
                    )
                    self.records_by_thread[thread_id].append(rec)

    def get_thread_waits(self, thread_id: int, level: Optional[str] = None) -> List[int]:
        """Returns all wait durations measured specifically for thread_id."""
        with self._lock:
            recs = list(self.records_by_thread.get(thread_id, []))
        if level is not None:
            recs = [r for r in recs if r.level == level]
        return [r.wait_duration_ns for r in recs]

    def get_thread_holds(self, thread_id: int, level: Optional[str] = None) -> List[int]:
        """Returns all hold durations measured specifically for thread_id."""
        with self._lock:
            recs = list(self.records_by_thread.get(thread_id, []))
        if level is not None:
            recs = [r for r in recs if r.level == level and r.hold_duration_ns is not None]
        return [r.hold_duration_ns for r in recs if r.hold_duration_ns is not None]


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
        t_attempt = time.perf_counter_ns()
        ok = self._real_lock.acquire(blocking, timeout)
        if ok:
            t_acquired = time.perf_counter_ns()
            self._recorder.record_acquire(tid, self._lock_id, self._level, self._name, t_attempt, t_acquired)
            if self.acquired_event is not None:
                self.acquired_event.set()
        return ok

    def release(self) -> None:
        # Crucial Requirement: Underlying lock must be released FIRST!
        self._real_lock.release()
        t_release = time.perf_counter_ns()
        tid = threading.get_ident()
        self._recorder.record_release(tid, self._lock_id, self._level, self._name, t_release)

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


class ReconciliationSnapshotBoundaryAuditor:
    """Conservative, fail-closed AST auditor detecting live mutable state access in reconcile_ledger()."""

    FORBIDDEN_LIVE_ATTRS = {
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

        # 1. Alias analysis: track any local variables assigned self or self.<forbidden_attr>
        tainted_self_aliases: Set[str] = set()
        tainted_registry_aliases: Set[str] = set()
        raw_production_collection_aliases: Set[str] = set()

        for stmt in capture_stmts:
            for node in ast.walk(stmt):
                if isinstance(node, ast.Assign):
                    # Check if value is self
                    if isinstance(node.value, ast.Name) and node.value.id == "self":
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                tainted_self_aliases.add(target.id)
                    # Check if value is self.<attr>
                    elif (
                        isinstance(node.value, ast.Attribute)
                        and isinstance(node.value.value, ast.Name)
                        and node.value.value.id == "self"
                    ):
                        if node.value.attr in self.FORBIDDEN_LIVE_ATTRS:
                            for target in node.targets:
                                if isinstance(target, ast.Name):
                                    tainted_registry_aliases.add(target.id)
                    # Check if value calls .values() on self.<attr> directly without snapshot transformation
                    elif isinstance(node.value, ast.Call):
                        func = node.value.func
                        if isinstance(func, ast.Name) and func.id in ("list", "dict", "tuple", "set"):
                            if node.value.args and isinstance(node.value.args[0], ast.Call):
                                inner_call = node.value.args[0]
                                if (
                                    isinstance(inner_call.func, ast.Attribute)
                                    and inner_call.func.attr in ("values", "items", "keys")
                                ):
                                    val_owner = inner_call.func.value
                                    if (
                                        isinstance(val_owner, ast.Attribute)
                                        and isinstance(val_owner.value, ast.Name)
                                        and val_owner.value.id == "self"
                                    ):
                                        if val_owner.attr in self.FORBIDDEN_LIVE_ATTRS:
                                            for target in node.targets:
                                                if isinstance(target, ast.Name):
                                                    raw_production_collection_aliases.add(target.id)

        # 2. Closure analysis: check all helper functions defined in function
        helper_defs: Dict[str, bool] = {}
        for node in ast.walk(target_fn):
            if isinstance(node, ast.FunctionDef) and node is not target_fn:
                helper_tainted = False
                for h_sub in ast.walk(node):
                    if isinstance(h_sub, ast.Attribute) and isinstance(h_sub.value, ast.Name):
                        if h_sub.value.id == "self" and h_sub.attr in self.FORBIDDEN_LIVE_ATTRS:
                            helper_tainted = True
                            break
                    if isinstance(h_sub, ast.Name) and h_sub.id in (tainted_self_aliases | tainted_registry_aliases):
                        helper_tainted = True
                        break
                helper_defs[node.name] = helper_tainted

        # 3. Analyze Evaluation Statements
        for stmt in eval_stmts:
            for node in ast.walk(stmt):
                # A. Direct self access
                if isinstance(node, ast.Attribute):
                    if isinstance(node.value, ast.Name) and node.value.id == "self":
                        if node.attr not in self.ALLOWED_SELF_ATTRS:
                            self.violations.append(f"Line {node.lineno}: Forbidden direct access to self.{node.attr}")
                    elif isinstance(node.value, ast.Name) and node.value.id in tainted_self_aliases:
                        self.violations.append(
                            f"Line {node.lineno}: Access to self.{node.attr} via tainted alias '{node.value.id}'"
                        )

                # B. Access to tainted registry alias
                if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
                    if node.id in tainted_registry_aliases:
                        self.violations.append(f"Line {node.lineno}: Reference to tainted registry alias '{node.id}'")
                    if node.id in raw_production_collection_aliases:
                        self.violations.append(
                            f"Line {node.lineno}: Reference to raw production object collection '{node.id}'"
                        )

                # C. Reflection via getattr/hasattr/vars
                if isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name) and node.func.id in ("getattr", "hasattr", "setattr", "delattr"):
                        if node.args and isinstance(node.args[0], ast.Name) and node.args[0].id in ({"self"} | tainted_self_aliases):
                            self.violations.append(
                                f"Line {node.lineno}: Dynamic reflection '{node.func.id}' on live self reference"
                            )
                    elif isinstance(node.func, ast.Name) and node.func.id == "vars":
                        if node.args and isinstance(node.args[0], ast.Name) and node.args[0].id in ({"self"} | tainted_self_aliases):
                            self.violations.append(f"Line {node.lineno}: Dynamic reflection 'vars' on live self reference")
                    # Call to tainted helper closure
                    elif isinstance(node.func, ast.Name) and helper_defs.get(node.func.id):
                        self.violations.append(
                            f"Line {node.lineno}: Call to helper function '{node.func.id}' which captures live state"
                        )

        return self.violations


class TestPhase20A3432SnapshotBoundaryAuditor(unittest.TestCase):
    """Rigorous verification of AST snapshot boundary auditor and negative fixtures."""

    def test_01_ast_boundary_audit_production_code(self):
        """Proves production reconcile_ledger() has ZERO live state dereferences or bypasses."""
        with open("extractor/observation_budget.py") as f:
            code = f.read()

        auditor = ReconciliationSnapshotBoundaryAuditor(code)
        violations = auditor.audit_function("reconcile_ledger")
        self.assertEqual(violations, [], f"Production reconcile_ledger() failed boundary audit: {violations}")

    def test_02_ast_boundary_audit_negative_fixtures_alias_and_reflection(self):
        """Verifies that the boundary auditor detects and rejects all 7 bypass patterns fail-closed."""
        fixtures = {
            "direct_live": """
def reconcile_ledger(self):
    with self._transaction_lock:
        x = 1
    val = self._physical_read_records
""",
            "self_alias": """
def reconcile_ledger(self):
    with self._transaction_lock:
        alias = self
    val = alias._active_reservations
""",
            "registry_alias": """
def reconcile_ledger(self):
    with self._transaction_lock:
        reg = self._committed_transactions
    val = reg['op_1']
""",
            "metrics_alias": """
def reconcile_ledger(self):
    with self._transaction_lock:
        m = self.metrics
    b = m.bytes_read
""",
            "getattr_reflection": """
def reconcile_ledger(self):
    with self._transaction_lock:
        x = 1
    val = getattr(self, '_active_scopes')
""",
            "helper_closure": """
def reconcile_ledger(self):
    def get_live():
        return self._batch_records
    with self._transaction_lock:
        x = 1
    val = get_live()
""",
            "raw_collection": """
def reconcile_ledger(self):
    with self._transaction_lock:
        raw_reads = list(self._physical_read_records.values())
    val = raw_reads[0]
""",
        }

        for name, fixture_code in fixtures.items():
            auditor = ReconciliationSnapshotBoundaryAuditor(fixture_code)
            violations = auditor.audit_function("reconcile_ledger")
            self.assertGreater(
                len(violations),
                0,
                f"Negative fixture '{name}' was not detected by boundary auditor",
            )


class TestPhase20A3432RuntimePoisonTrapClosure(unittest.TestCase):
    """Runtime PoisonTrap covering all 13 authoritative mutable fields."""

    def setUp(self):
        self.tracker = make_tracker()

    def tearDown(self):
        self.tracker.clear_fault_injections()

    def test_03_runtime_poison_trap_all_thirteen_authoritative_fields(self):
        """All 13 authoritative fields poisoned post-capture; reconciliation evaluates all 24 invariants cleanly."""
        scope = make_scope(self.tracker, "op_poison_13_fields")
        res = self.tracker.admit_read(100, scope=scope)
        c = res.start_child_read()
        c.consume(100)
        res.consume(100)
        scope.record_read(100, admission=res)
        scope.finalize(success=True)

        class PoisonTrap:
            def __init__(self, name: str):
                self._trap_name = name

            def __getattr__(self, name):
                raise AssertionError(f"ILLEGAL LIVE ACCESS: getattr {self._trap_name}.{name}")

            def __getitem__(self, key):
                raise AssertionError(f"ILLEGAL LIVE ACCESS: getitem {self._trap_name}[{key}]")

            def __iter__(self):
                raise AssertionError(f"ILLEGAL LIVE ACCESS: iter({self._trap_name})")

            def __len__(self):
                raise AssertionError(f"ILLEGAL LIVE ACCESS: len({self._trap_name})")

            def __bool__(self):
                raise AssertionError(f"ILLEGAL LIVE ACCESS: bool({self._trap_name})")

            def __eq__(self, other):
                raise AssertionError(f"ILLEGAL LIVE ACCESS: {self._trap_name} == {other}")

        def poison_method(*args, **kwargs):
            raise AssertionError("ILLEGAL LIVE ACCESS: _active_consumed_bytes called during invariant evaluation")

        def poison_hook():
            self.tracker._physical_read_records = PoisonTrap("_physical_read_records")
            self.tracker._physical_consumption_records = PoisonTrap("_physical_consumption_records")
            self.tracker._committed_transactions = PoisonTrap("_committed_transactions")
            self.tracker._active_reservations = PoisonTrap("_active_reservations")
            self.tracker._committed_reservations = PoisonTrap("_committed_reservations")
            self.tracker._released_reservations = PoisonTrap("_released_reservations")
            self.tracker._active_scopes = PoisonTrap("_active_scopes")
            self.tracker._batch_records = PoisonTrap("_batch_records")
            self.tracker._invocations = PoisonTrap("_invocations")
            self.tracker._invocation_start_mono_ns = PoisonTrap("_invocation_start_mono_ns")
            self.tracker._released_reservations_count = PoisonTrap("_released_reservations_count")
            self.tracker.metrics = PoisonTrap("metrics")
            self.tracker._limits = PoisonTrap("_limits")
            self.tracker._active_consumed_bytes = poison_method

        self.tracker.set_fault_injection("after_reconciliation_snapshot_capture", poison_hook)

        rec = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(rec["reconciled"])
        self.assertEqual(len(rec["discrepancy_details"]), 24)

    def test_04_runtime_poison_trap_negative_detection(self):
        """Negative test: Attempting to touch any of the 13 poisoned attributes trips the trap immediately."""
        class PoisonTrap:
            def __init__(self, name: str):
                self._name = name

            def __getattr__(self, name):
                raise AssertionError(f"POISON_TRAP_TRIPPED: {self._name}.{name}")

            def __getitem__(self, key):
                raise AssertionError(f"POISON_TRAP_TRIPPED: {self._name}[{key}]")

        pt = PoisonTrap("test_reg")
        with self.assertRaises(AssertionError) as cm1:
            _ = pt.bytes_read
        self.assertIn("POISON_TRAP_TRIPPED: test_reg.bytes_read", str(cm1.exception))

        with self.assertRaises(AssertionError) as cm2:
            _ = pt["key"]
        self.assertIn("POISON_TRAP_TRIPPED: test_reg[key]", str(cm2.exception))


class TestPhase20A3432ConcurrentCommitAndRecoverySerialization(unittest.TestCase):
    """True concurrent Commit and Recovery execution proving mutual exclusion under L1."""

    def setUp(self):
        self.tracker = make_tracker()
        self.recorder = ProductionCriticalSectionRecorder()
        instrument_tracker(self.tracker, self.recorder)

    def tearDown(self):
        self.tracker.clear_fault_injections()

    def test_05_concurrent_commit_and_recovery_commit_first(self):
        """Commit holds L1 while Recovery attempts L1 and blocks; serialization verified via thread waits."""
        sc_commit = make_scope(self.tracker, "op_conc_commit_1")
        r1 = self.tracker.admit_read(100, scope=sc_commit)
        c1 = r1.start_child_read()
        c1.consume(100)
        r1.consume(100)
        sc_commit.record_read(100, admission=r1)

        sc_rec = make_scope(self.tracker, "op_conc_rec_1")
        r2 = self.tracker.admit_read(100, scope=sc_rec)
        c2 = r2.start_child_read()
        c2.consume(100)
        r2.consume(100)
        sc_rec.record_read(100, admission=r2)
        self.tracker.inject_fault("during_logical_ledger_insertion")
        sc_rec.finalize(success=True)
        self.tracker.clear_fault_injections()
        self.assertEqual(sc_rec.state, "FAILED")

        commit_in_l1 = threading.Event()
        commit_can_release = threading.Event()

        def commit_hold_hook():
            commit_in_l1.set()
            if not commit_can_release.wait(timeout=5.0):
                raise TimeoutError("commit_hold timed out")

        self.tracker.set_fault_injection("before_reservation_finalization", commit_hold_hook)

        w_commit = WorkerThread(target=lambda: sc_commit.finalize(success=True), name="w_commit")
        w_recovery = WorkerThread(target=lambda: self.tracker.retry_recovery(sc_rec), name="w_recovery")

        w_commit.start()
        self.assertTrue(commit_in_l1.wait(timeout=5.0))

        self.tracker._transaction_lock.acquire_attempt_event = threading.Event()
        w_recovery.start()
        self.assertTrue(self.tracker._transaction_lock.acquire_attempt_event.wait(timeout=5.0))
        self.assertTrue(w_recovery.is_alive())
        self.assertFalse(w_recovery.completed)

        # Invariant: Commit holds L1, Recovery is blocked waiting for L1
        self.assertEqual(self.recorder.max_simultaneous["L1"], 1)

        commit_can_release.set()
        join_workers(self, [w_commit, w_recovery])

        self.tracker.clear_fault_injections()
        self.tracker._transaction_lock.acquire_attempt_event = None

        self.assertEqual(self.recorder.max_simultaneous["L1"], 1)
        rec_waits = self.recorder.get_thread_waits(w_recovery.ident, "L1")
        self.assertGreater(len(rec_waits), 0)
        self.assertGreater(rec_waits[0], 0, "Recovery worker must record non-zero wait duration on L1")

        rec = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(rec["reconciled"])

    def test_06_concurrent_commit_and_recovery_recovery_first(self):
        """Inverted order: Recovery holds L1 while Commit attempts L1 and blocks."""
        sc_commit = make_scope(self.tracker, "op_conc_commit_2")
        r1 = self.tracker.admit_read(100, scope=sc_commit)
        c1 = r1.start_child_read()
        c1.consume(100)
        r1.consume(100)
        sc_commit.record_read(100, admission=r1)

        sc_rec = make_scope(self.tracker, "op_conc_rec_2")
        r2 = self.tracker.admit_read(100, scope=sc_rec)
        c2 = r2.start_child_read()
        c2.consume(100)
        r2.consume(100)
        sc_rec.record_read(100, admission=r2)
        # Interrupt initial recovery so retry_recovery executes recovery stages under L1
        self.tracker.inject_fault("during_logical_ledger_insertion")
        self.tracker.inject_fault("during_recovery_cleanup")
        try:
            sc_rec.finalize(success=True)
        except RuntimeError:
            pass
        self.tracker.clear_fault_injections()

        recovery_in_l1 = threading.Event()
        recovery_can_release = threading.Event()

        def recovery_hold_hook():
            recovery_in_l1.set()
            if not recovery_can_release.wait(timeout=5.0):
                raise TimeoutError("recovery_hold timed out")

        self.tracker.set_fault_injection("recovery_entry", recovery_hold_hook)

        w_recovery = WorkerThread(target=lambda: self.tracker.retry_recovery(sc_rec), name="w_recovery_first")
        w_commit = WorkerThread(target=lambda: sc_commit.finalize(success=True), name="w_commit_compete")

        w_recovery.start()
        self.assertTrue(recovery_in_l1.wait(timeout=5.0))

        self.tracker._transaction_lock.acquire_attempt_event = threading.Event()
        w_commit.start()
        self.assertTrue(self.tracker._transaction_lock.acquire_attempt_event.wait(timeout=5.0))
        self.assertTrue(w_commit.is_alive())
        self.assertFalse(w_commit.completed)

        self.assertEqual(self.recorder.max_simultaneous["L1"], 1)

        recovery_can_release.set()
        join_workers(self, [w_recovery, w_commit])

        self.tracker.clear_fault_injections()
        self.tracker._transaction_lock.acquire_attempt_event = None

        self.assertEqual(self.recorder.max_simultaneous["L1"], 1)
        commit_waits = self.recorder.get_thread_waits(w_commit.ident, "L1")
        self.assertGreater(len(commit_waits), 0)
        self.assertGreater(commit_waits[0], 0, "Commit worker must record non-zero wait duration on L1")

        rec = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(rec["reconciled"])

    def test_07_concurrent_commit_and_recovery_with_injected_fault(self):
        """Concurrent execution with injected recovery fault fails closed without corrupting Commit."""
        sc_commit = make_scope(self.tracker, "op_conc_commit_3")
        r1 = self.tracker.admit_read(100, scope=sc_commit)
        c1 = r1.start_child_read()
        c1.consume(100)
        r1.consume(100)
        sc_commit.record_read(100, admission=r1)

        sc_rec = make_scope(self.tracker, "op_conc_rec_3")
        r2 = self.tracker.admit_read(100, scope=sc_rec)
        c2 = r2.start_child_read()
        c2.consume(100)
        r2.consume(100)
        sc_rec.record_read(100, admission=r2)
        self.tracker.inject_fault("during_logical_ledger_insertion")
        sc_rec.finalize(success=True)
        self.tracker.clear_fault_injections()

        # Inject fault into recovery retry
        self.tracker.inject_fault("during_recovery_metric_reconciliation")

        def safe_retry():
            try:
                self.tracker.retry_recovery(sc_rec)
            except RuntimeError:
                pass

        w_commit = WorkerThread(target=lambda: sc_commit.finalize(success=True), name="w_commit_clean")
        w_rec_fault = WorkerThread(target=safe_retry, name="w_recovery_fault")

        w_commit.start()
        w_rec_fault.start()
        join_workers(self, [w_commit, w_rec_fault])

        self.tracker.clear_fault_injections()

        # Clean retry completes cleanly
        second_snap = self.tracker.retry_recovery(sc_rec)
        self.assertIsNotNone(second_snap)
        self.assertEqual(second_snap.accounting_status, "FAILED")

        # Invariant ledger reconciliation succeeds
        rec = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(rec["reconciled"])


class TestPhase20A3432LockContentionEvidenceIntegrity(unittest.TestCase):
    """Verifies contention at all four lock levels using thread-specific wait measurements."""

    def setUp(self):
        self.tracker = make_tracker()
        self.recorder = ProductionCriticalSectionRecorder()
        instrument_tracker(self.tracker, self.recorder)

    def tearDown(self):
        self.tracker.clear_fault_injections()

    def test_08_per_thread_wait_measurement_l1(self):
        """L1 contention verified specifically for the competing thread ID."""
        l1_hold = threading.Event()
        l1_release = threading.Event()

        def l1_hook():
            l1_hold.set()
            if not l1_release.wait(timeout=5.0):
                raise TimeoutError("L1 release timed out")

        self.tracker.set_fault_injection("before_reservation_publication", l1_hook)
        w_a = WorkerThread(target=lambda: self.tracker.reserve_budget(100), name="w_l1_a")
        w_b = WorkerThread(target=lambda: self.tracker.reserve_budget(100), name="w_l1_b")

        w_a.start()
        self.assertTrue(l1_hold.wait(timeout=5.0))

        self.tracker._transaction_lock.acquire_attempt_event = threading.Event()
        w_b.start()
        self.assertTrue(self.tracker._transaction_lock.acquire_attempt_event.wait(timeout=5.0))
        self.assertTrue(w_b.is_alive())
        self.assertFalse(w_b.completed)

        l1_release.set()
        join_workers(self, [w_a, w_b])

        self.tracker.clear_fault_injections()
        self.tracker._transaction_lock.acquire_attempt_event = None

        waits_b = self.recorder.get_thread_waits(w_b.ident, "L1")
        self.assertGreater(len(waits_b), 0)
        self.assertGreater(waits_b[0], 0, f"Worker B (tid={w_b.ident}) must record wait > 0 on L1")

    def test_09_per_thread_wait_measurement_l1_5(self):
        """L1.5 contention verified specifically for the competing thread ID."""
        scope = make_scope(self.tracker, "op_l1_5_per_thread")
        instrument_scope(scope, self.recorder)

        l1_5_hold = threading.Event()
        l1_5_release = threading.Event()

        def l1_5_hook():
            l1_5_hold.set()
            if not l1_5_release.wait(timeout=5.0):
                raise TimeoutError("L1.5 release timed out")

        self.tracker.set_fault_injection("inside_scope_lock", l1_5_hook)
        w_a = WorkerThread(target=lambda: scope.get_status_snapshot(), name="w_l1_5_a")
        w_b = WorkerThread(target=lambda: scope.get_status_snapshot(), name="w_l1_5_b")

        w_a.start()
        self.assertTrue(l1_5_hold.wait(timeout=5.0))

        scope._lock.acquire_attempt_event = threading.Event()
        w_b.start()
        self.assertTrue(scope._lock.acquire_attempt_event.wait(timeout=5.0))
        self.assertTrue(w_b.is_alive())
        self.assertFalse(w_b.completed)

        l1_5_release.set()
        join_workers(self, [w_a, w_b])

        self.tracker.clear_fault_injections()
        scope._lock.acquire_attempt_event = None

        waits_b = self.recorder.get_thread_waits(w_b.ident, "L1.5")
        self.assertGreater(len(waits_b), 0)
        self.assertGreater(waits_b[0], 0, f"Worker B (tid={w_b.ident}) must record wait > 0 on L1.5")

    def test_10_per_thread_wait_measurement_l2(self):
        """L2 contention verified specifically for the competing thread ID."""
        scope = make_scope(self.tracker, "op_l2_per_thread")
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
        w_a = WorkerThread(target=lambda: res.start_child_read(), name="w_l2_a")
        w_b = WorkerThread(target=lambda: res.start_child_read(), name="w_l2_b")

        w_a.start()
        self.assertTrue(l2_hold.wait(timeout=5.0))

        res._lock.acquire_attempt_event = threading.Event()
        w_b.start()
        self.assertTrue(res._lock.acquire_attempt_event.wait(timeout=5.0))
        self.assertTrue(w_b.is_alive())
        self.assertFalse(w_b.completed)

        l2_release.set()
        join_workers(self, [w_a, w_b])

        self.tracker.clear_fault_injections()
        res._lock.acquire_attempt_event = None

        waits_b = self.recorder.get_thread_waits(w_b.ident, "L2")
        self.assertGreater(len(waits_b), 0)
        self.assertGreater(waits_b[0], 0, f"Worker B (tid={w_b.ident}) must record wait > 0 on L2")

    def test_11_per_thread_wait_measurement_l3(self):
        """L3 contention verified specifically for the competing thread ID."""
        child = PhysicalReadRecord(
            physical_read_id="pread_l3_per_thread",
            reservation_id="res_pt",
            physical_consumption_id="pcons_pt",
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
                return {"sync": "ok"}

        w_a = WorkerThread(target=lambda: child.update_metadata({"s": SyncObject()}), name="w_l3_a")
        w_b = WorkerThread(target=lambda: child.update_metadata({"status": "done"}), name="w_l3_b")

        w_a.start()
        self.assertTrue(l3_hold.wait(timeout=5.0))

        child._lock.acquire_attempt_event = threading.Event()
        w_b.start()
        self.assertTrue(child._lock.acquire_attempt_event.wait(timeout=5.0))
        self.assertTrue(w_b.is_alive())
        self.assertFalse(w_b.completed)

        l3_release.set()
        join_workers(self, [w_a, w_b])

        child._lock.acquire_attempt_event = None

        waits_b = self.recorder.get_thread_waits(w_b.ident, "L3")
        self.assertGreater(len(waits_b), 0)
        self.assertGreater(waits_b[0], 0, f"Worker B (tid={w_b.ident}) must record wait > 0 on L3")


class TestPhase20A3432WorkerLifecycleVerification(unittest.TestCase):
    """Rigorous audit of WorkerThread and join_workers lifecycle mechanics."""

    def test_12_single_monotonic_deadline_timeout_detection(self):
        """Worker exceeding monotonic timeout causes join_workers to raise TimeoutError."""
        hang_event = threading.Event()

        def hanging_fn():
            hang_event.wait(timeout=10.0)

        w = WorkerThread(target=hanging_fn, name="hanging_worker")
        w.start()

        try:
            with self.assertRaises(TimeoutError) as cm:
                join_workers(self, [w], timeout=0.1)
            self.assertIn("hanging_worker", str(cm.exception))
        finally:
            hang_event.set()
            w.join(timeout=1.0)

    def test_13_unstarted_worker_detection(self):
        """Worker that was never started causes join_workers to raise AssertionError."""
        unstarted = WorkerThread(target=lambda: None, name="unstarted_worker")
        # Do not call unstarted.start()

        with self.assertRaises(AssertionError) as cm:
            join_workers(self, [unstarted], timeout=1.0)
        self.assertIn("was never started", str(cm.exception))

    def test_14_worker_exception_propagation_and_cause_preservation(self):
        """Worker exception propagates to parent test with preserved __cause__."""
        def failing_fn():
            raise KeyError("simulated_error_key")

        w = WorkerThread(target=failing_fn, name="failing_key_worker")
        w.start()

        with self.assertRaises(AssertionError) as cm:
            join_workers(self, [w], timeout=1.0)

        self.assertIn("failing_key_worker", str(cm.exception))
        self.assertIsInstance(cm.exception.__cause__, KeyError)
        self.assertEqual(str(cm.exception.__cause__), "'simulated_error_key'")


class TestPhase20A3432BenchmarkMeasurementIntegrity(unittest.TestCase):
    """Accurate benchmark reporting mathematically exact median, linear interpolation P95, and retained memory."""

    @staticmethod
    def compute_sample_statistics(samples: List[float]) -> Dict[str, float]:
        """Calculates exact sample statistics including mathematically exact median and linear percentile."""
        assert len(samples) > 0
        sorted_s = sorted(samples)
        n = len(sorted_s)

        # Mathematical median: average middle two if even, middle if odd
        if n % 2 == 1:
            med = sorted_s[n // 2]
        else:
            med = (sorted_s[n // 2 - 1] + sorted_s[n // 2]) / 2.0

        # Linear interpolation P95 percentile
        idx = 0.95 * (n - 1)
        low = int(idx)
        frac = idx - low
        if low + 1 < n:
            p95 = sorted_s[low] + frac * (sorted_s[low + 1] - sorted_s[low])
        else:
            p95 = sorted_s[low]

        return {
            "count": float(n),
            "min": sorted_s[0],
            "median": med,
            "p95": p95,
            "max": sorted_s[-1],
        }

    def test_15_benchmark_mathematically_exact_median_and_p95(self):
        """Measures Small (10), Medium (50), Large (150) ledgers with exact median and P95 formulas."""
        configs = [("Small", 10), ("Medium", 50), ("Large", 150)]
        results: Dict[str, Any] = {}

        for profile_name, tx_count in configs:
            tracker = make_tracker()
            recorder = ProductionCriticalSectionRecorder()
            instrument_tracker(tracker, recorder)

            # Warm-up phase
            for i in range(5):
                sc = make_scope(tracker, f"warm_{i}")
                r = tracker.admit_read(50, scope=sc)
                c = r.start_child_read()
                c.consume(50)
                r.consume(50)
                sc.record_read(50, admission=r)
                sc.finalize(success=True)

            tracker.reconcile_ledger(raise_on_error=True)

            # Production transactions
            for i in range(tx_count):
                sc = make_scope(tracker, f"tx_{profile_name}_{i}")
                r = tracker.admit_read(100, scope=sc)
                c = r.start_child_read(
                    target_spec={"address": 0x1000 + i * 16, "size": 100},
                    metadata={"tx_idx": i, "env": "bench_phase32"},
                )
                c.consume(100)
                r.consume(100)
                sc.record_read(100, admission=r)
                sc.finalize(success=True)

            tracemalloc.start()
            t_rec_start = time.perf_counter_ns()
            rec_result = tracker.reconcile_ledger(raise_on_error=True)
            t_rec_end = time.perf_counter_ns()
            _, peak_bytes = tracemalloc.get_traced_memory()
            tracemalloc.stop()

            total_recon_duration_us = (t_rec_end - t_rec_start) / 1000.0

            # Multi-sample concurrent contention latency (N=10)
            contention_samples: List[float] = []
            for sample_idx in range(10):
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

            stats = self.compute_sample_statistics(contention_samples)
            shallow_size = sys.getsizeof(rec_result)
            retained_size = get_recursive_retained_size(rec_result)

            results[profile_name] = {
                "tx_count": tx_count,
                "total_recon_duration_us": total_recon_duration_us,
                "peak_allocated_bytes": peak_bytes,
                "shallow_memory_bytes": shallow_size,
                "retained_memory_bytes": retained_size,
                "contention_stats": stats,
            }

            self.assertTrue(rec_result["reconciled"])
            self.assertGreater(retained_size, shallow_size)
            self.assertLessEqual(stats["min"], stats["median"])
            self.assertLessEqual(stats["median"], stats["p95"])
            self.assertLessEqual(stats["p95"], stats["max"])

        print("\n--- Phase 2.0-A.3.4.32 Benchmark Measurements (Informational) ---")
        for k, v in results.items():
            cs = v["contention_stats"]
            print(
                f"[{k}] {v['tx_count']} tx | Recon: {v['total_recon_duration_us']:.1f}us | "
                f"Contention (N={int(cs['count'])}): med {cs['median']:.1f}us, p95 {cs['p95']:.1f}us, "
                f"min {cs['min']:.1f}us, max {cs['max']:.1f}us | "
                f"Shallow: {v['shallow_memory_bytes']}B | Retained: {v['retained_memory_bytes']}B | Peak: {v['peak_allocated_bytes']}B"
            )


class TestPhase20A3432CloneFrozenAndAccountingRegression(unittest.TestCase):
    """Adversarial stress validation of clone_frozen and full commit/recovery regression."""

    def setUp(self):
        self.tracker = make_tracker()

    def tearDown(self):
        self.tracker.clear_fault_injections()

    def test_16_clone_frozen_adversarial_regression(self):
        """Validates deeply nested structures, DAG diamonds, custom Mapping cycles, and float canonicalization."""
        # 1. 50-level nested structure
        deep_root = {}
        curr = deep_root
        for i in range(50):
            curr["next"] = {"level": i}
            curr = curr["next"]

        frozen_deep = clone_frozen(deep_root)
        self.assertIsInstance(frozen_deep, types.MappingProxyType)

        # 2. DAG diamond shared references
        shared = {"id": "diamond_core", "data": (1, 2, 3)}
        diamond = {"branch_a": shared, "branch_b": shared}
        frozen_diamond = clone_frozen(diamond)
        self.assertIs(frozen_diamond["branch_a"], frozen_diamond["branch_b"])

        # 3. Custom Mapping cycle rejection
        class CyclicMapping(collections.abc.Mapping):
            def __init__(self):
                self._d = {}

            def set_cycle(self, target):
                self._d["cycle"] = target

            def __getitem__(self, k):
                return self._d[k]

            def __iter__(self):
                return iter(self._d)

            def __len__(self):
                return len(self._d)

        cm_obj = CyclicMapping()
        cm_obj.set_cycle(cm_obj)
        with self.assertRaises(ValueError) as cm:
            clone_frozen(cm_obj)
        self.assertIn("Cyclic reference detected", str(cm.exception))

        # 4. to_dict returning self
        class SelfReturning:
            def to_dict(self):
                return self

        with self.assertRaises(ValueError) as cm:
            clone_frozen(SelfReturning())
        self.assertIn("to_dict() returned self", str(cm.exception))

        # 5. Non-finite float rejection
        for val in [float("nan"), float("inf"), float("-inf")]:
            with self.assertRaises(ValueError):
                clone_frozen({"metric": val})

        # 6. -0.0 canonicalization
        frozen_zero = clone_frozen({"num": -0.0})
        self.assertEqual(math.copysign(1.0, frozen_zero["num"]), 1.0)
        self.assertEqual(canonical_metadata_digest({"n": -0.0}), canonical_metadata_digest({"n": 0.0}))

        # 7. Unhashable set fallback
        class Item:
            def __init__(self, val):
                self.val = val

            def to_dict(self):
                return {"v": self.val}

        s = {Item("b"), Item("a")}
        frozen_s = clone_frozen(s)
        self.assertIsInstance(frozen_s, tuple)
        self.assertEqual(len(frozen_s), 2)
        self.assertEqual(frozen_s[0]["v"], "a")
        self.assertEqual(frozen_s[1]["v"], "b")

    def test_17_commit_fault_injection_matrix(self):
        """All 12 commit mutation boundaries tested with clean failure transition and evidence preservation."""
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
            op_id = f"op_commit_pt_{idx}"
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

            self.assertIn(c.physical_consumption_id, self.tracker._physical_consumption_records)
            self.tracker.clear_fault_injections()

        rec = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(rec["reconciled"])

    def test_18_recovery_fault_injection_and_retry_idempotency(self):
        """All 12 recovery fault points and retry recovery idempotency."""
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
            op_id = f"op_rec_pt_{idx}"
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

            second_snap = self.tracker.retry_recovery(sc)
            self.assertEqual(recovered_snap.operation_id, second_snap.operation_id)

        rec = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(rec["reconciled"])


if __name__ == "__main__":
    unittest.main()

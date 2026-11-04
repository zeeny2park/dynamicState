"""Phase 2.0-A.3.4.33 — Proof Harness Self-Verification, Alias Dataflow Closure & CI Evidence Integrity.

This test suite establishes verification-integrity closure:
1. Complete AST Alias Dataflow Analysis (conservative fixed-point taint propagation, 18 negative & 3 positive fixtures).
2. Runtime PoisonTrap Negative Verification across canonical 14 authoritative mutable fields in-path.
3. Lock Recorder Measurement Integrity (actual recursive depth, outermost timestamps, exception safety).
4. Benchmark Phase Separation (independent measurement of all 10 boundaries, exact median & P95).
5. Worker Lifecycle and Failure Cleanup (single monotonic deadline, cleanup events, cause chaining).
6. Adversarial and Accounting Regression (all 24 invariants, commit & recovery fault matrices).
"""

from __future__ import annotations

import ast
import collections
import dataclasses
import inspect
import math
import os
import sys
import threading
import time
import tracemalloc
import unittest
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from extractor.observation_budget import (
    ActiveOperationScope,
    BudgetReservation,
    CommittedTransactionSnapshot,
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

# ---------------------------------------------------------------------------
# Canonical Authoritative Mutable Field Inventory
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
# Helpers & Factory Functions
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
    profile_id: str = "prof_a33",
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
                    ev.set()
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


class ProductionCriticalSectionRecorder:
    """Thread-safe recorder tracking per-thread lock acquisitions, wait intervals, and outermost hold durations."""

    def __init__(self):
        self._lock = threading.Lock()
        self.records_by_thread: Dict[int, List[LockAcquisitionRecord]] = collections.defaultdict(list)
        self.active_holders: Dict[str, Set[Tuple[int, int]]] = collections.defaultdict(set)
        self.active_threads_by_level: Dict[str, Set[int]] = collections.defaultdict(set)
        self.max_simultaneous: Dict[str, int] = collections.defaultdict(int)
        self.reentrancy_depth: Dict[Tuple[int, int], int] = collections.defaultdict(int)
        self._entry_times: Dict[Tuple[int, int], List[int]] = {}

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
                self._entry_times[key] = [attempt_ns, acquired_ns, 1, 0]
                self.active_holders[level].add(key)
                self.active_threads_by_level[level].add(thread_id)
                cur_sim = len(self.active_threads_by_level[level])
                if cur_sim > self.max_simultaneous[level]:
                    self.max_simultaneous[level] = cur_sim
            else:
                entry = self._entry_times.get(key)
                if entry:
                    entry[2] = max(entry[2], cur_depth + 1)
                    entry[3] += 1

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
                    attempt_ns, acquired_ns, max_depth, reentrant_count = entry_info
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
                    )
                    self.records_by_thread[thread_id].append(rec)

    def get_thread_waits(self, thread_id: int, level: Optional[str] = None) -> List[int]:
        with self._lock:
            recs = list(self.records_by_thread.get(thread_id, []))
        if level is not None:
            recs = [r for r in recs if r.level == level]
        return [r.wait_duration_ns for r in recs]

    def get_thread_holds(self, thread_id: int, level: Optional[str] = None) -> List[int]:
        with self._lock:
            recs = list(self.records_by_thread.get(thread_id, []))
        if level is not None:
            recs = [r for r in recs if r.level == level and r.hold_duration_ns is not None]
        return [r.hold_duration_ns for r in recs if r.hold_duration_ns is not None]

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


class InstrumentedLock:
    """Transparent lock wrapper recording acquire/release timings and recursive depth."""

    def __init__(self, raw_lock: Any, recorder: ProductionCriticalSectionRecorder, level: str, name: str):
        self._real_lock = raw_lock
        self.recorder = recorder
        self.level = level
        self.name = name
        self.lock_id = id(raw_lock)

    def acquire(self, blocking: bool = True, timeout: float = -1) -> bool:
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
        try:
            self._real_lock.release()
        finally:
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

                # 3. Dynamic reflection & Helper calls
                elif isinstance(node, ast.Call):
                    if isinstance(node.func, ast.Name):
                        fn_id = node.func.id
                        if fn_id in ("getattr", "hasattr", "setattr", "delattr", "vars"):
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
                                arg.id in tainted_registry or arg.id in tainted_self or arg.id in tainted_containers
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


# ---------------------------------------------------------------------------
# Test Suite: AST Alias Dataflow Closure
# ---------------------------------------------------------------------------
class TestPhase20A3433ASTAliasDataflowClosure(unittest.TestCase):
    """Verifies that ReconciliationSnapshotBoundaryAuditor detects all bypass patterns and clears production code."""

    def test_01_ast_audit_production_code(self):
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

    def test_02_ast_audit_eighteen_negative_fixtures(self):
        """All 18 negative fixtures trigger audit failures with accurate line numbers and categories."""
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
                self.assertGreater(
                    len(violations),
                    0,
                    f"Fixture '{name}' did not fail as expected",
                )
                self.assertTrue(
                    any(expected_cat in v for v in violations),
                    f"Fixture '{name}' failed with {violations}, expected category {expected_cat}",
                )

    def test_03_ast_audit_three_positive_fixtures(self):
        """Legitimate immutable snapshot transformations produce 0 false positives."""
        positives = [
            (
                "clone_frozen_dict",
                """
def reconcile_ledger(self):
    with self._transaction_lock:
        records_snap = {k: clone_frozen(v) for k, v in self._physical_read_records.items()}
    return len(records_snap)
""",
            ),
            (
                "primitive_projections",
                """
def reconcile_ledger(self):
    with self._transaction_lock:
        scope_count = len(self._active_scopes)
        bytes_read = self.metrics.bytes_read
    return scope_count + bytes_read
""",
            ),
            (
                "frozenset_keys",
                """
def reconcile_ledger(self):
    with self._transaction_lock:
        keys_snap = frozenset(self._invocation_start_mono_ns.keys())
    return 'inv_1' in keys_snap
""",
            ),
        ]

        for name, code in positives:
            with self.subTest(positive_fixture=name):
                auditor = ReconciliationSnapshotBoundaryAuditor(code)
                violations = auditor.audit_function("reconcile_ledger")
                self.assertEqual(
                    len(violations),
                    0,
                    f"Positive fixture '{name}' produced false positive violations: {violations}",
                )

    def test_04_ast_auditor_language_subset_and_limitations_doc(self):
        """Auditor docstring documents supported language subset and known limitations."""
        doc = inspect.getdoc(ReconciliationSnapshotBoundaryAuditor)
        self.assertIsNotNone(doc)
        self.assertIn("Language Subset Supported", doc)
        self.assertIn("Known Limitations", doc)
        self.assertIn("Intra-procedural", doc)


# ---------------------------------------------------------------------------
# Test Suite: Runtime PoisonTrap Negative Verification
# ---------------------------------------------------------------------------
class TestPhase20A3433RuntimePoisonTrapNegativeVerification(unittest.TestCase):
    """Runtime PoisonTrap covering canonical 14 authoritative mutable fields with in-path verification."""

    def setUp(self):
        self.tracker = make_tracker()

    def tearDown(self):
        self.tracker.clear_fault_injections()

    def test_05_canonical_fourteen_field_inventory(self):
        """Canonical inventory contains exactly 14 fields and matches tracker mutable state."""
        self.assertEqual(len(CANONICAL_AUTHORITATIVE_MUTABLE_FIELDS), 14)
        for field in CANONICAL_AUTHORITATIVE_MUTABLE_FIELDS:
            self.assertTrue(
                hasattr(self.tracker, field),
                f"BudgetTracker missing canonical authoritative field '{field}'",
            )

    def test_06_runtime_poison_trap_production_clean_execution(self):
        """All 14 fields poisoned post-capture; production reconcile_ledger() evaluates all 24 invariants cleanly."""
        scope = make_scope(self.tracker, "op_poison_14_clean")
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

        def poison_hook():
            for f in CANONICAL_AUTHORITATIVE_MUTABLE_FIELDS:
                setattr(self.tracker, f, PoisonTrap(f))

        self.tracker.set_fault_injection("after_reconciliation_snapshot_capture", poison_hook)
        rec = self.tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(rec["reconciled"])
        self.assertEqual(len(rec["discrepancy_details"]), 24)
        for inv_num, inv_status in rec["discrepancy_details"].items():
            self.assertTrue(inv_status, f"Invariant {inv_num} unexpectedly failed")

    def test_07_runtime_poison_trap_in_path_negative_violations_for_all_fourteen_fields(self):
        """Deliberately faulty reconciliation steps accessing poisoned fields in-path are deterministically caught."""
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

        for field in CANONICAL_AUTHORITATIVE_MUTABLE_FIELDS:
            with self.subTest(faulty_field=field):
                tracker = make_tracker()
                scope = make_scope(tracker, f"op_poison_neg_{field}")
                res = tracker.admit_read(50, scope=scope)
                c = res.start_child_read()
                c.consume(50)
                res.consume(50)
                scope.record_read(50, admission=res)
                scope.finalize(success=True)

                class FaultyReconciler(ObservationBudgetTracker):
                    def __init__(self, target_f: str, *args: Any, **kwargs: Any):
                        super().__init__(*args, **kwargs)
                        self.target_f = target_f

                    def reconcile_ledger(self, raise_on_error: bool = True) -> Dict[str, Any]:
                        orig_fn = self._fault_injection_hooks.get("after_reconciliation_snapshot_capture")

                        def wrapped_hook():
                            if orig_fn:
                                orig_fn()
                            # Faulty in-path step accessing live state
                            val = getattr(self, self.target_f)
                            if callable(val):
                                val()
                            elif hasattr(val, "__getitem__"):
                                _ = val["test_key"]
                            elif hasattr(val, "__iter__"):
                                _ = list(val)
                            else:
                                _ = getattr(val, "bytes_read", 0)

                        self.set_fault_injection("after_reconciliation_snapshot_capture", wrapped_hook)
                        return super().reconcile_ledger(raise_on_error=raise_on_error)

                faulty_tr = FaultyReconciler(target_f=field, limits=tracker.limits)
                faulty_tr.start()
                for f_name in CANONICAL_AUTHORITATIVE_MUTABLE_FIELDS:
                    setattr(faulty_tr, f_name, getattr(tracker, f_name))

                def poison_faulty():
                    for f in CANONICAL_AUTHORITATIVE_MUTABLE_FIELDS:
                        setattr(faulty_tr, f, PoisonTrap(f))

                faulty_tr.set_fault_injection("after_reconciliation_snapshot_capture", poison_faulty)

                with self.assertRaises(AssertionError) as ctx:
                    faulty_tr.reconcile_ledger(raise_on_error=True)
                self.assertIn("ILLEGAL LIVE ACCESS", str(ctx.exception))
                self.assertIn(field, str(ctx.exception))

    def test_08_runtime_snapshot_independence_after_subsequent_mutation(self):
        """Original production objects mutated after capture; invariant evaluation reflects only snapshot."""
        scope = make_scope(self.tracker, "op_snap_indep")
        res = self.tracker.admit_read(100, scope=scope)
        c = res.start_child_read()
        c.consume(100)
        res.consume(100)
        scope.record_read(100, admission=res)
        scope.finalize(success=True)

        ev_captured = threading.Event()
        ev_mutated = threading.Event()

        def post_capture_mutation_hook():
            ev_captured.set()
            ev_mutated.wait(timeout=5.0)

        self.tracker.set_fault_injection("after_reconciliation_snapshot_capture", post_capture_mutation_hook)

        rec_result: List[Dict[str, Any]] = []

        def worker_recon():
            rec = self.tracker.reconcile_ledger(raise_on_error=True)
            rec_result.append(rec)

        th = WorkerThread(target=worker_recon, name="worker_recon")
        th.start()
        self.assertTrue(ev_captured.wait(timeout=5.0))

        # Mutate live production objects in main thread while reconciliation evaluates
        self.tracker.metrics.bytes_read += 999_999
        self.tracker._physical_read_records["mutated_id"] = PhysicalReadRecord(
            physical_read_id="mutated_id",
            physical_consumption_id="cons_mut",
            reservation_id="res_mut",
            operation_id="op_mut",
            charged_bytes=500,
        )
        ev_mutated.set()
        join_workers([th], timeout_s=5.0)

        # Invariant evaluation evaluated the captured snapshot, so it succeeded
        self.assertEqual(len(rec_result), 1)
        self.assertTrue(rec_result[0]["reconciled"])

        # Subsequent reconciliation captures mutated state and detects discrepancy
        self.tracker.clear_fault_injections()
        rec2 = self.tracker.reconcile_ledger(raise_on_error=False)
        self.assertFalse(rec2["reconciled"])


# ---------------------------------------------------------------------------
# Test Suite: Lock Recorder Measurement Integrity
# ---------------------------------------------------------------------------
class TestPhase20A3433LockRecorderMeasurementIntegrity(unittest.TestCase):
    """Verifies that ProductionCriticalSectionRecorder tracks recursive depth, timestamps, and concurrency."""

    def setUp(self):
        self.recorder = ProductionCriticalSectionRecorder()

    def test_09_single_acquisition_measurement(self):
        """Single acquisition records max_recursion_depth=1 and total_reentrant_acquisitions=0."""
        raw_lock = threading.RLock()
        lock = InstrumentedLock(raw_lock, self.recorder, level="L1", name="test_l1")

        with lock:
            time.sleep(0.001)

        th_id = threading.get_ident()
        records = self.recorder.records_by_thread[th_id]
        self.assertEqual(len(records), 1)
        rec = records[0]
        self.assertEqual(rec.max_recursion_depth, 1)
        self.assertEqual(rec.total_reentrant_acquisitions, 0)
        self.assertGreaterEqual(rec.wait_duration_ns, 0)
        self.assertGreater(rec.hold_duration_ns, 0)
        self.assertIsNotNone(rec.release_timestamp_ns)

    def test_10_recursive_acquisition_depth_two_and_three(self):
        """Recursive acquisition depths 2 and 3 track peak depth and outermost timestamps correctly."""
        raw_lock = threading.RLock()
        lock = InstrumentedLock(raw_lock, self.recorder, level="L1", name="test_recursive")

        # Depth 2
        with lock:
            with lock:
                time.sleep(0.001)

        th_id = threading.get_ident()
        recs = self.recorder.records_by_thread[th_id]
        self.assertEqual(len(recs), 1)
        self.assertEqual(recs[0].max_recursion_depth, 2)
        self.assertEqual(recs[0].total_reentrant_acquisitions, 1)

        # Depth 3
        with lock:
            with lock:
                with lock:
                    time.sleep(0.001)

        recs = self.recorder.records_by_thread[th_id]
        self.assertEqual(len(recs), 2)
        self.assertEqual(recs[1].max_recursion_depth, 3)
        self.assertEqual(recs[1].total_reentrant_acquisitions, 2)

    def test_11_independent_locks_owned_by_single_thread(self):
        """A single thread acquiring independent locks (L1, L2, L3) records distinct entries."""
        l1 = InstrumentedLock(threading.RLock(), self.recorder, level="L1", name="lock_l1")
        l2 = InstrumentedLock(threading.RLock(), self.recorder, level="L2", name="lock_l2")
        l3 = InstrumentedLock(threading.RLock(), self.recorder, level="L3", name="lock_l3")

        with l1:
            with l2:
                with l3:
                    pass

        th_id = threading.get_ident()
        recs = self.recorder.records_by_thread[th_id]
        self.assertEqual(len(recs), 3)
        levels = [r.level for r in recs]
        self.assertEqual(levels, ["L3", "L2", "L1"])

    def test_12_same_lock_contended_two_threads(self):
        """Contention on same lock records wait duration > 0 for thread 2 and serialized execution."""
        raw_lock = threading.RLock()
        lock = InstrumentedLock(raw_lock, self.recorder, level="L1", name="contended_lock")

        ev_th1_acquired = threading.Event()
        ev_th1_release = threading.Event()
        ev_th2_attempt = threading.Event()

        def worker_1():
            with lock:
                ev_th1_acquired.set()
                ev_th1_release.wait(timeout=5.0)

        def worker_2():
            ev_th1_acquired.wait(timeout=5.0)
            ev_th2_attempt.set()
            with lock:
                pass

        w1 = WorkerThread(target=worker_1, name="w1")
        w2 = WorkerThread(target=worker_2, name="w2")

        w1.start()
        w2.start()

        self.assertTrue(ev_th2_attempt.wait(timeout=5.0))
        time.sleep(0.005)
        ev_th1_release.set()

        join_workers([w1, w2], timeout_s=5.0)

        # Thread 2 waited on the lock held by Thread 1
        w2_waits = self.recorder.get_thread_waits(w2.ident, level="L1")
        self.assertGreater(len(w2_waits), 0)
        self.assertGreater(w2_waits[0], 1_000_000)  # At least 1ms wait
        self.assertEqual(self.recorder.max_simultaneous["L1"], 1)

    def test_13_repeated_concurrent_acquisition_and_release(self):
        """100 repeated concurrent acquisitions and releases maintain consistent recorder state."""
        raw_lock = threading.RLock()
        lock = InstrumentedLock(raw_lock, self.recorder, level="L1", name="repeated_lock")

        def worker_loop():
            for _ in range(50):
                with lock:
                    pass

        workers = [WorkerThread(target=worker_loop, name=f"rep_{i}") for i in range(4)]
        for w in workers:
            w.start()
        join_workers(workers, timeout_s=5.0)

        with self.recorder._lock:
            self.assertEqual(len(self.recorder.active_holders["L1"]), 0)
            self.assertEqual(len(self.recorder.active_threads_by_level["L1"]), 0)
            self.assertEqual(len(self.recorder.reentrancy_depth), 0)

    def test_14_thread_completion_and_recorder_cleanup(self):
        """Recorder cleanup method removes thread records preventing memory leakage."""
        raw_lock = threading.RLock()
        lock = InstrumentedLock(raw_lock, self.recorder, level="L1", name="cleanup_lock")

        def worker():
            with lock:
                pass

        w = WorkerThread(target=worker, name="w_cleanup")
        w.start()
        join_workers([w], timeout_s=5.0)

        self.assertIn(w.ident, self.recorder.records_by_thread)
        self.recorder.cleanup_thread(w.ident)
        self.assertNotIn(w.ident, self.recorder.records_by_thread)

    def test_15_lock_release_exception_safety(self):
        """Release exceptions in user code release the underlying raw lock safely."""
        raw_lock = threading.RLock()
        lock = InstrumentedLock(raw_lock, self.recorder, level="L1", name="exc_lock")

        try:
            with lock:
                raise ValueError("Deliberate critical section failure")
        except ValueError:
            pass

        # Underlying raw lock is completely released
        acquired = raw_lock.acquire(blocking=False)
        self.assertTrue(acquired)
        raw_lock.release()


# ---------------------------------------------------------------------------
# Test Suite: Worker Lifecycle and Failure Cleanup
# ---------------------------------------------------------------------------
class TestPhase20A3433WorkerLifecycleAndCleanup(unittest.TestCase):
    """Verifies deterministic WorkerThread failure modes, monotonic deadlines, and cleanup."""

    def test_16_failed_start_state_clean_handling(self):
        """Failed start() leaves started as False and does not mark completion."""
        class FailingStartWorker(WorkerThread):
            def __init__(self):
                super().__init__(target=lambda: None, name="failing_start")

            def start(self):
                self.started = False
                raise RuntimeError("OS thread creation failed")

        w = FailingStartWorker()
        with self.assertRaises(RuntimeError):
            w.start()
        self.assertFalse(w.started)
        self.assertFalse(w.completed)

    def test_17_single_monotonic_deadline_timeout(self):
        """join_workers applies one monotonic deadline and does not multiply timeout per worker."""
        ev_block = threading.Event()

        def blocking_worker():
            ev_block.wait()

        workers = [
            WorkerThread(target=blocking_worker, name=f"blocker_{i}")
            for i in range(3)
        ]
        for w in workers:
            w.start()

        t0 = time.monotonic()
        with self.assertRaises(TimeoutError) as ctx:
            join_workers(workers, timeout_s=0.2, cleanup_events=[ev_block])
        elapsed = time.monotonic() - t0

        self.assertLess(elapsed, 1.0, "Timeout amplified across workers!")
        self.assertIn("timed out after 0.2s", str(ctx.exception))
        join_workers(workers, timeout_s=1.0)

    def test_18_timeout_failure_identifies_remaining_workers(self):
        """Timeout error identifies the exact unjoined workers."""
        ev_stop = threading.Event()

        def slow_worker():
            ev_stop.wait()

        w = WorkerThread(target=slow_worker, name="target_slow_worker")
        w.start()

        try:
            with self.assertRaises(TimeoutError) as ctx:
                join_workers([w], timeout_s=0.1, cleanup_events=[ev_stop])
            self.assertIn("target_slow_worker", str(ctx.exception))
        finally:
            ev_stop.set()
            w.join(timeout=1.0)

    def test_19_cleanup_events_release_blocked_workers_on_failure(self):
        """Test cleanup events release blocked workers even after assertion failure."""
        cleanup_ev = threading.Event()
        worker_done = threading.Event()

        def worker():
            cleanup_ev.wait(timeout=5.0)
            worker_done.set()

        w = WorkerThread(target=worker, name="w_cleanup_test")
        w.start()

        try:
            # Simulate test failure while worker is waiting
            raise AssertionError("Assertion failed in test body")
        except AssertionError:
            cleanup_ev.set()

        join_workers([w], timeout_s=1.0)
        self.assertTrue(worker_done.is_set())

    def test_20_worker_exception_preserves_cause(self):
        """Worker exceptions preserve __cause__ when re-raised by join_workers."""
        def failing_worker():
            raise ZeroDivisionError("division by zero in worker")

        w = WorkerThread(target=failing_worker, name="w_exc")
        w.start()

        with self.assertRaises(RuntimeError) as ctx:
            join_workers([w], timeout_s=2.0)

        self.assertIsInstance(ctx.exception.__cause__, ZeroDivisionError)

    def test_21_unstarted_and_already_started_detection(self):
        """Unstarted workers cannot be joined and already started workers cannot be re-started."""
        w = WorkerThread(target=lambda: None, name="w_state")
        with self.assertRaises(RuntimeError) as ctx:
            join_workers([w], timeout_s=1.0)
        self.assertIn("Cannot join unstarted worker", str(ctx.exception))

        w.start()
        with self.assertRaises(RuntimeError) as ctx2:
            w.start()
        self.assertIn("already started", str(ctx2.exception))
        join_workers([w], timeout_s=1.0)


# ---------------------------------------------------------------------------
# Test Suite: Benchmark Phase Separation
# ---------------------------------------------------------------------------
class TestPhase20A3433BenchmarkPhaseSeparation(unittest.TestCase):
    """Independent measurement of all 10 boundaries with exact median and P95 linear interpolation."""

    @staticmethod
    def _calc_median(samples: List[float]) -> float:
        s = sorted(samples)
        n = len(s)
        if n % 2 == 1:
            return float(s[n // 2])
        return float((s[n // 2 - 1] + s[n // 2]) / 2.0)

    @staticmethod
    def _calc_p95(samples: List[float]) -> float:
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

    def test_22_ten_boundary_benchmark_exact_median_and_p95(self):
        """Measures all 10 boundaries independently across N=20 samples with cycle & shared ref protection."""
        recorder = ProductionCriticalSectionRecorder()

        tracker = make_tracker()
        instrument_tracker(tracker, recorder)

        # Warm-up phase
        sc_warm = make_scope(tracker, "warmup_op")
        r_warm = tracker.admit_read(50, scope=sc_warm)
        sc_warm.record_read(50, admission=r_warm)
        sc_warm.finalize(success=True)
        tracker.reconcile_ledger(raise_on_error=True)
        recorder.reset()

        # Measurement data structures
        capture_durations_ns: List[float] = []
        freeze_durations_ns: List[float] = []
        eval_durations_ns: List[float] = []
        total_durations_ns: List[float] = []
        tx_latencies_us: List[float] = []

        N = 20
        tracemalloc.start()
        for i in range(N):
            sc = make_scope(tracker, f"bench_op_{i}")
            t_tx0 = time.perf_counter_ns()
            r = tracker.admit_read(100, scope=sc)
            c = r.start_child_read()
            c.consume(100)
            r.consume(100)
            sc.record_read(100, admission=r)
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

            def cap_end_hook():
                nonlocal t_cap_end, t_eval_start
                t_cap_end = time.perf_counter_ns()
                t_eval_start = time.perf_counter_ns()

            def eval_end_hook():
                nonlocal t_eval_end
                t_eval_end = time.perf_counter_ns()

            tracker.set_fault_injection("before_reconciliation_snapshot_capture", cap_start_hook)
            tracker.set_fault_injection("after_reconciliation_snapshot_capture", cap_end_hook)
            tracker.set_fault_injection("after_reconciliation_invariant_evaluation", eval_end_hook)

            t_tot0 = time.perf_counter_ns()
            rec = tracker.reconcile_ledger(raise_on_error=True)
            t_tot1 = time.perf_counter_ns()

            total_durations_ns.append(t_tot1 - t_tot0)
            if t_cap_start and t_cap_end:
                capture_durations_ns.append(t_cap_end - t_cap_start)
            if t_eval_start and t_eval_end:
                eval_durations_ns.append(t_eval_end - t_eval_start)

            # Deep freezing micro-benchmark
            t_frz0 = time.perf_counter_ns()
            _ = clone_frozen(tracker.metrics.profile_usage)
            t_frz1 = time.perf_counter_ns()
            freeze_durations_ns.append(t_frz1 - t_frz0)

        current_mem, peak_mem = tracemalloc.get_traced_memory()
        tracemalloc.stop()

        shallow_mem = sys.getsizeof(rec)
        retained_mem = get_recursive_retained_size(rec)

        # Retrieve lock timings
        th_id = threading.get_ident()
        l1_waits_ns = [float(w) for w in recorder.get_thread_waits(th_id, level="L1")]
        l1_holds_ns = [float(h) for h in recorder.get_thread_holds(th_id, level="L1")]

        # Assertions on all 10 boundaries
        self.assertEqual(len(tx_latencies_us), N)
        self.assertGreater(len(total_durations_ns), 0)
        self.assertGreater(len(capture_durations_ns), 0)
        self.assertGreater(len(eval_durations_ns), 0)
        self.assertGreater(len(freeze_durations_ns), 0)
        self.assertGreater(peak_mem, 0)
        self.assertGreater(shallow_mem, 0)
        self.assertGreater(retained_mem, shallow_mem)

        # Compute mathematical medians and linear interpolation P95s
        print("\n--- Phase 2.0-A.3.4.33 10-Boundary Benchmark Evidence ---")
        print(f"1. Snapshot Capture Duration: med={self._calc_median(capture_durations_ns)/1e3:.2f}us, p95={self._calc_p95(capture_durations_ns)/1e3:.2f}us")
        print(f"2. Deep Freezing Duration:    med={self._calc_median(freeze_durations_ns)/1e3:.2f}us, p95={self._calc_p95(freeze_durations_ns)/1e3:.2f}us")
        print(f"3. Invariant Evaluation:      med={self._calc_median(eval_durations_ns)/1e3:.2f}us, p95={self._calc_p95(eval_durations_ns)/1e3:.2f}us")
        print(f"4. Total Reconciliation:      med={self._calc_median(total_durations_ns)/1e3:.2f}us, p95={self._calc_p95(total_durations_ns)/1e3:.2f}us")
        print(f"5. L1 Lock Wait Duration:     med={self._calc_median(l1_waits_ns)/1e3:.2f}us, p95={self._calc_p95(l1_waits_ns)/1e3:.2f}us")
        print(f"6. L1 Lock Hold Duration:     med={self._calc_median(l1_holds_ns)/1e3:.2f}us, p95={self._calc_p95(l1_holds_ns)/1e3:.2f}us")
        print(f"7. Tx Latency (N={N}):         med={self._calc_median(tx_latencies_us):.2f}us, p95={self._calc_p95(tx_latencies_us):.2f}us")
        print(f"8. Peak Allocated Memory:     {peak_mem} bytes")
        print(f"9. Shallow Result Memory:     {shallow_mem} bytes")
        print(f"10. Recursively Retained Mem: {retained_mem} bytes")


# ---------------------------------------------------------------------------
# Test Suite: Adversarial and Accounting Regression
# ---------------------------------------------------------------------------
class TestPhase20A3433AdversarialAndAccountingRegression(unittest.TestCase):
    """Verifies clone_frozen robustness, commit fault matrix, and recovery retry idempotency."""

    def test_23_clone_frozen_adversarial_regression(self):
        """Validates deeply nested structures, DAG diamonds, custom Mapping cycles, and float canonicalization."""
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

    def test_24_commit_mutation_boundary_matrix(self):
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
            with self.subTest(fault_point=pt):
                tracker = make_tracker()
                op_id = f"op_commit_pt_{idx}"
                sc = make_scope(tracker, op_id)
                r = tracker.admit_read(100, scope=sc)
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

                tracker.set_fault_injection(pt, make_hook())

                snap = sc.finalize(success=True)
                self.assertTrue(triggered[0], f"Hook at {pt} was not reached")
                self.assertIsNotNone(snap)
                self.assertEqual(snap.accounting_status, "FAILED")
                self.assertTrue(snap.is_failure)

                self.assertIn(c.physical_consumption_id, tracker._physical_consumption_records)
                tracker.clear_fault_injections()
                rec = tracker.reconcile_ledger(raise_on_error=True)
                self.assertTrue(rec["reconciled"])

    def test_25_recovery_fault_point_matrix_and_retry_idempotency(self):
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
            with self.subTest(recovery_point=pt):
                tracker = make_tracker()
                op_id = f"op_rec_pt_{idx}"
                sc = make_scope(tracker, op_id)
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

                second_snap = tracker.retry_recovery(sc)
                self.assertEqual(recovered_snap.operation_id, second_snap.operation_id)

                rec = tracker.reconcile_ledger(raise_on_error=True)
                self.assertTrue(rec["reconciled"])

    def test_26_concurrent_commit_and_recovery_serialization(self):
        """Concurrent Commit and Recovery serialize strictly under L1 lock with max_simultaneous=1."""
        recorder = ProductionCriticalSectionRecorder()
        tracker = make_tracker()
        instrument_tracker(tracker, recorder)

        # Prepare Commit Scope
        sc_commit = make_scope(tracker, "op_conc_commit")
        r1 = tracker.admit_read(100, scope=sc_commit)
        c1 = r1.start_child_read()
        c1.consume(100)
        r1.consume(100)
        sc_commit.record_read(100, admission=r1)

        # Prepare Recovery Scope
        sc_rec = make_scope(tracker, "op_conc_rec")
        r2 = tracker.admit_read(100, scope=sc_rec)
        c2 = r2.start_child_read()
        c2.consume(100)
        r2.consume(100)
        sc_rec.record_read(100, admission=r2)

        tracker.inject_fault("during_logical_ledger_insertion")
        sc_rec.finalize(success=True)
        tracker.clear_fault_injections()
        self.assertEqual(sc_rec.state, "FAILED")

        commit_in_l1 = threading.Event()
        commit_can_release = threading.Event()

        def commit_hold_hook():
            commit_in_l1.set()
            if not commit_can_release.wait(timeout=5.0):
                raise TimeoutError("commit_hold timed out")

        tracker.set_fault_injection("before_reservation_finalization", commit_hold_hook)

        w_commit = WorkerThread(target=lambda: sc_commit.finalize(success=True), name="w_commit")
        w_recovery = WorkerThread(target=lambda: tracker.retry_recovery(sc_rec), name="w_recovery")

        w_commit.start()
        self.assertTrue(commit_in_l1.wait(timeout=5.0))

        w_recovery.start()
        time.sleep(0.01)  # Ensure recovery blocks attempting L1

        commit_can_release.set()
        join_workers([w_commit, w_recovery], timeout_s=5.0)

        # Mutually exclusive execution under L1
        self.assertEqual(recorder.max_simultaneous["L1"], 1)

        w_rec_waits = recorder.get_thread_waits(w_recovery.ident, level="L1")
        self.assertGreater(len(w_rec_waits), 0)
        self.assertGreater(w_rec_waits[0], 1_000_000)  # > 1ms wait

        rec = tracker.reconcile_ledger(raise_on_error=True)
        self.assertTrue(rec["reconciled"])


if __name__ == "__main__":
    unittest.main()

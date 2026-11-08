"""Phase 2.1.3 — Concurrency Wait-For Graph & Temporal Deadlock Analysis

Builds an explicit wait-for graph with:
- ThreadNode, LockNode, WaitingEdge, OwnershipEdge, UnresolvedOwnershipEdge
- Completeness tracking (incomplete graph != acyclic)
- Temporal state separation:
  THREAD_BLOCKED, LOCK_CONTENTION, LONG_WAIT, REPEATED_BLOCKING,
  POTENTIAL_CIRCULAR_WAIT, OBSERVED_CIRCULAR_WAIT, PERSISTENT_DEADLOCK.
- cycle_persistent is NEVER defaulted to True (requires repeated observation).
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
import time
from typing import Any, Dict, List, Optional, Set, Tuple


class ConcurrencyState(str, Enum):
    THREAD_BLOCKED = "THREAD_BLOCKED"
    LOCK_CONTENTION = "LOCK_CONTENTION"
    LONG_WAIT = "LONG_WAIT"
    REPEATED_BLOCKING = "REPEATED_BLOCKING"
    POTENTIAL_CIRCULAR_WAIT = "POTENTIAL_CIRCULAR_WAIT"
    OBSERVED_CIRCULAR_WAIT = "OBSERVED_CIRCULAR_WAIT"
    PERSISTENT_DEADLOCK = "PERSISTENT_DEADLOCK"
    INCONCLUSIVE_INCOMPLETE_GRAPH = "INCONCLUSIVE_INCOMPLETE_GRAPH"


@dataclass
class ThreadNode:
    tid: int
    name: Optional[str] = None
    state: str = "WAITING"
    callstack: List[str] = field(default_factory=list)


@dataclass
class LockNode:
    lock_id: str
    address: Optional[int] = None
    lock_type: str = "mutex"
    owning_tid: Optional[int] = None


@dataclass
class WaitingEdge:
    tid: int
    lock_id: str
    wait_start_timestamp: float = field(default_factory=time.time)


@dataclass
class OwnershipEdge:
    lock_id: str
    tid: int
    acquire_timestamp: Optional[float] = None


@dataclass
class UnresolvedOwnershipEdge:
    lock_id: str
    waiting_tid: int
    reason: str = "Lock owner not currently traceable"


@dataclass
class WaitForGraphAnalysisResult:
    state: ConcurrencyState
    confidence: float
    rationale: str
    is_complete: bool
    unresolved_locks_count: int
    detected_cycles: List[List[str]]
    cycle_observed_count: int
    is_persistent: bool
    blocked_threads: List[int]
    supporting_facts: List[str]
    contradicting_facts: List[str]
    missing_evidence: List[str]
    details: Dict[str, Any] = field(default_factory=dict)


class WaitForGraph:
    """Explicit directed wait-for graph with cycle detection and completeness tracking."""

    def __init__(self):
        self.threads: Dict[int, ThreadNode] = {}
        self.locks: Dict[str, LockNode] = {}
        self.waiting_edges: List[WaitingEdge] = []
        self.ownership_edges: List[OwnershipEdge] = []
        self.unresolved_edges: List[UnresolvedOwnershipEdge] = []
        self.timestamp = time.time()

    def add_thread(self, tid: int, name: Optional[str] = None, state: str = "WAITING", callstack: Optional[List[str]] = None) -> None:
        self.threads[tid] = ThreadNode(tid=tid, name=name, state=state, callstack=callstack or [])

    def add_lock(self, lock_id: str, address: Optional[int] = None, lock_type: str = "mutex") -> None:
        if lock_id not in self.locks:
            self.locks[lock_id] = LockNode(lock_id=lock_id, address=address, lock_type=lock_type)

    def add_waiting_edge(self, tid: int, lock_id: str) -> None:
        self.add_thread(tid)
        self.add_lock(lock_id)
        self.waiting_edges.append(WaitingEdge(tid=tid, lock_id=lock_id))

    def add_ownership_edge(self, lock_id: str, tid: int) -> None:
        self.add_lock(lock_id)
        self.add_thread(tid)
        self.locks[lock_id].owning_tid = tid
        self.ownership_edges.append(OwnershipEdge(lock_id=lock_id, tid=tid))

    def add_unresolved_edge(self, lock_id: str, waiting_tid: int, reason: str = "Lock owner not traceable") -> None:
        self.add_lock(lock_id)
        self.add_thread(waiting_tid)
        self.unresolved_edges.append(UnresolvedOwnershipEdge(lock_id=lock_id, waiting_tid=waiting_tid, reason=reason))

    @property
    def is_complete(self) -> bool:
        """Graph is complete only if all locks waited upon have identifiable owners."""
        return len(self.unresolved_edges) == 0

    def find_cycles(self) -> List[List[str]]:
        """Detects circular wait-for cycles between threads."""
        # Build thread-to-thread wait graph
        # Thread A waits on Lock L; Lock L owned by Thread B => Edge A -> B
        t_to_t: Dict[int, List[Tuple[int, str]]] = {tid: [] for tid in self.threads}
        for w in self.waiting_edges:
            lock = self.locks.get(w.lock_id)
            if lock and lock.owning_tid is not None:
                t_to_t[w.tid].append((lock.owning_tid, w.lock_id))

        cycles: List[List[str]] = []
        visited: Set[int] = set()
        stack: List[Tuple[int, str]] = []

        def dfs(curr_tid: int):
            visited.add(curr_tid)
            for next_tid, lk in t_to_t.get(curr_tid, []):
                # Check cycle
                cycle_nodes = [t for t, _ in stack]
                if next_tid in cycle_nodes:
                    idx = cycle_nodes.index(next_tid)
                    cycle_slice = stack[idx:] + [(curr_tid, lk)]
                    cycle_repr = [f"thread_{t} -> {l}" for t, l in cycle_slice]
                    cycles.append(cycle_repr)
                elif next_tid not in visited:
                    stack.append((curr_tid, lk))
                    dfs(next_tid)
                    stack.pop()

        for tid in list(self.threads.keys()):
            if tid not in visited:
                dfs(tid)

        return cycles

    def analyze(self, historical_observations: int = 1) -> WaitForGraphAnalysisResult:
        """Evaluates graph semantics and temporal persistence."""
        cycles = self.find_cycles()
        blocked_tids = [w.tid for w in self.waiting_edges]

        # Case K: Incomplete lock graph must NOT be assumed acyclic!
        if not self.is_complete and not cycles:
            return WaitForGraphAnalysisResult(
                state=ConcurrencyState.INCONCLUSIVE_INCOMPLETE_GRAPH,
                confidence=0.40,
                rationale=(
                    f"Lock graph is incomplete ({len(self.unresolved_edges)} unresolved lock owners). "
                    "Cannot prove acyclic or absent deadlocks from partial visibility."
                ),
                is_complete=False,
                unresolved_locks_count=len(self.unresolved_edges),
                detected_cycles=[],
                cycle_observed_count=0,
                is_persistent=False,
                blocked_threads=blocked_tids,
                supporting_facts=[],
                contradicting_facts=[],
                missing_evidence=["complete_lock_ownership_info", "unresolved_lock_owners"],
                details={"unresolved_edges": len(self.unresolved_edges)},
            )

        # Case L: Circular wait observed only once is OBSERVED_CIRCULAR_WAIT, not PERSISTENT_DEADLOCK!
        if cycles:
            if historical_observations >= 2:
                return WaitForGraphAnalysisResult(
                    state=ConcurrencyState.PERSISTENT_DEADLOCK,
                    confidence=0.98,
                    rationale=f"Persistent circular wait deadlock verified across {historical_observations} temporal epochs.",
                    is_complete=self.is_complete,
                    unresolved_locks_count=len(self.unresolved_edges),
                    detected_cycles=cycles,
                    cycle_observed_count=historical_observations,
                    is_persistent=True,
                    blocked_threads=blocked_tids,
                    supporting_facts=["Cycle persistent across consecutive temporal observations", f"Cycles: {cycles}"],
                    contradicting_facts=[],
                    missing_evidence=[],
                    details={"deadlock_confirmed": True, "cycles": cycles},
                )
            else:
                return WaitForGraphAnalysisResult(
                    state=ConcurrencyState.OBSERVED_CIRCULAR_WAIT,
                    confidence=0.75,
                    rationale="Circular wait cycle observed in single epoch; requires repeated observation to prove persistence.",
                    is_complete=self.is_complete,
                    unresolved_locks_count=len(self.unresolved_edges),
                    detected_cycles=cycles,
                    cycle_observed_count=1,
                    is_persistent=False,
                    blocked_threads=blocked_tids,
                    supporting_facts=["Circular wait observed in current snapshot", f"Cycles: {cycles}"],
                    contradicting_facts=["Persistence across epochs not yet demonstrated"],
                    missing_evidence=["repeated_temporal_observation"],
                    details={"deadlock_confirmed": False, "transient_cycle": True},
                )

        # Case J: Blocked thread under contention without circular wait
        if blocked_tids:
            return WaitForGraphAnalysisResult(
                state=ConcurrencyState.LOCK_CONTENTION,
                confidence=0.88,
                rationale=f"Threads {blocked_tids} blocked waiting for locks, but wait-for graph is acyclic. Lock contention without deadlock.",
                is_complete=self.is_complete,
                unresolved_locks_count=len(self.unresolved_edges),
                detected_cycles=[],
                cycle_observed_count=0,
                is_persistent=False,
                blocked_threads=blocked_tids,
                supporting_facts=[f"Active lock contention on {len(self.waiting_edges)} threads without circular cycle"],
                contradicting_facts=["Wait-for graph is strictly acyclic"],
                missing_evidence=[],
                details={"contention": True, "deadlock_refuted": True},
            )

        return WaitForGraphAnalysisResult(
            state=ConcurrencyState.THREAD_BLOCKED,
            confidence=0.90,
            rationale="All threads are active or idle; no blocked lock acquisitions observed.",
            is_complete=self.is_complete,
            unresolved_locks_count=0,
            detected_cycles=[],
            cycle_observed_count=0,
            is_persistent=False,
            blocked_threads=[],
            supporting_facts=["No lock wait queues detected"],
            contradicting_facts=[],
            missing_evidence=[],
            details={"clean": True},
        )

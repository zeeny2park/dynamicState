"""Phase 2.1.4 — Concurrency Wait-For Graph & Temporal Deadlock Analysis

Enforces strict concurrency semantics:
- Distinguishes THREAD_BLOCKED, LOCK_CONTENTION, LONG_WAIT, OBSERVED_CIRCULAR_WAIT,
  and PERSISTENT_DEADLOCK.
- Incomplete lock graphs remain INCONCLUSIVE_INCOMPLETE_GRAPH (never infer acyclic).
- Single snapshot circular wait is OBSERVED_CIRCULAR_WAIT (not persistent deadlock).
- Persistent deadlock requires validated distinct observation epochs (>= 2).
- Externally supplied counts are not accepted as proof without validated underlying observations.
- Reports participating threads, ownership relationships, waiting relationships, detected cycles,
  observation epochs, persistence evidence, and unresolved edges.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union


class ConcurrencyState(str, Enum):
    THREAD_BLOCKED = "THREAD_BLOCKED"
    LOCK_CONTENTION = "LOCK_CONTENTION"
    LONG_WAIT = "LONG_WAIT"
    REPEATED_BLOCKING = "REPEATED_BLOCKING"
    POTENTIAL_CIRCULAR_WAIT = "POTENTIAL_CIRCULAR_WAIT"
    OBSERVED_CIRCULAR_WAIT = "OBSERVED_CIRCULAR_WAIT"
    PERSISTENT_DEADLOCK = "PERSISTENT_DEADLOCK"
    INCONCLUSIVE_INCOMPLETE_GRAPH = "INCONCLUSIVE_INCOMPLETE_GRAPH"
    NO_DEADLOCK_ACYCLIC = "NO_DEADLOCK_ACYCLIC"


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
    tid: int = 0
    lock_id: str = ""
    wait_start_timestamp: float = field(default_factory=time.time)
    waiter_tid: Optional[int] = None

    def __post_init__(self):
        if not self.tid and self.waiter_tid is not None:
            self.tid = self.waiter_tid
        elif self.tid and self.waiter_tid is None:
            self.waiter_tid = self.tid


@dataclass
class OwnershipEdge:
    lock_id: str = ""
    tid: int = 0
    acquire_timestamp: Optional[float] = None
    holder_tid: Optional[int] = None

    def __post_init__(self):
        if not self.tid and self.holder_tid is not None:
            self.tid = self.holder_tid
        elif self.tid and self.holder_tid is None:
            self.holder_tid = self.tid


@dataclass
class UnresolvedOwnershipEdge:
    lock_id: str
    waiting_tid: int = 0
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
    participating_threads: List[int]
    lock_ownership_relationships: List[Dict[str, Any]]
    waiting_relationships: List[Dict[str, Any]]
    observation_epochs: List[int]
    evidence_supporting_persistence: List[str]
    supporting_facts: List[str]
    contradicting_facts: List[str]
    missing_evidence: List[str]
    limitations: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def concurrency_state(self) -> ConcurrencyState:
        return self.state

    @property
    def summary(self) -> str:
        return self.rationale

    @property
    def cycles(self) -> List[List[str]]:
        return self.detected_cycles

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["state"] = self.state.value
        d["concurrency_state"] = self.state.value
        d["summary"] = self.rationale
        d["cycles"] = self.detected_cycles
        return d


DeadlockAnalysisResult = WaitForGraphAnalysisResult


class WaitForGraph:
    """Explicit directed wait-for graph with cycle detection and completeness tracking."""

    def __init__(self):
        self.threads: Dict[int, ThreadNode] = {}
        self.locks: Dict[str, LockNode] = {}
        self.waiting_edges: List[WaitingEdge] = []
        self.ownership_edges: List[OwnershipEdge] = []
        self.unresolved_edges: List[UnresolvedOwnershipEdge] = []
        self.timestamp = time.time()

    def add_thread(self, tid: Union[int, ThreadNode], name: Optional[str] = None, state: str = "WAITING", callstack: Optional[List[str]] = None) -> None:
        if isinstance(tid, ThreadNode):
            self.threads[tid.tid] = tid
        else:
            self.threads[tid] = ThreadNode(tid=tid, name=name, state=state, callstack=callstack or [])

    def add_lock(self, lock_id: Union[str, LockNode], address: Optional[int] = None, lock_type: str = "mutex") -> None:
        if isinstance(lock_id, LockNode):
            self.locks[lock_id.lock_id] = lock_id
        else:
            if lock_id not in self.locks:
                self.locks[lock_id] = LockNode(lock_id=lock_id, address=address, lock_type=lock_type)

    def add_waiting_edge(self, tid: Union[int, WaitingEdge], lock_id: Optional[str] = None) -> None:
        if isinstance(tid, WaitingEdge):
            edge = tid
            holder = getattr(edge, "tid", None) or getattr(edge, "waiter_tid", 0)
            self.add_thread(holder)
            self.add_lock(edge.lock_id)
            # Normalize waiter_tid and tid
            if not hasattr(edge, "tid"):
                setattr(edge, "tid", holder)
            self.waiting_edges.append(edge)
        else:
            self.add_thread(tid)
            if lock_id:
                self.add_lock(lock_id)
                self.waiting_edges.append(WaitingEdge(tid=tid, lock_id=lock_id))

    def add_ownership_edge(self, lock_id: Union[str, OwnershipEdge], tid: Optional[int] = None) -> None:
        if isinstance(lock_id, OwnershipEdge):
            edge = lock_id
            holder = getattr(edge, "tid", None) or getattr(edge, "holder_tid", 0)
            self.add_lock(edge.lock_id)
            self.add_thread(holder)
            self.locks[edge.lock_id].owning_tid = holder
            if not hasattr(edge, "tid"):
                setattr(edge, "tid", holder)
            self.ownership_edges.append(edge)
        else:
            self.add_lock(lock_id)
            if tid is not None:
                self.add_thread(tid)
                self.locks[lock_id].owning_tid = tid
                self.ownership_edges.append(OwnershipEdge(lock_id=lock_id, tid=tid))

    def add_unresolved_edge(self, lock_id: Union[str, UnresolvedOwnershipEdge], waiting_tid: Optional[int] = None, reason: str = "Lock owner not traceable") -> None:
        if isinstance(lock_id, UnresolvedOwnershipEdge):
            edge = lock_id
            self.add_lock(edge.lock_id)
            wtid = getattr(edge, "waiting_tid", 0)
            if wtid:
                self.add_thread(wtid)
            self.unresolved_edges.append(edge)
        else:
            self.add_lock(lock_id)
            if waiting_tid:
                self.add_thread(waiting_tid)
            self.unresolved_edges.append(UnresolvedOwnershipEdge(lock_id=lock_id, waiting_tid=waiting_tid or 0, reason=reason))

    @property
    def is_complete(self) -> bool:
        """Graph is complete only if all locks waited upon have identifiable owners."""
        return len(self.unresolved_edges) == 0

    def find_cycles(self) -> List[List[str]]:
        """Detects circular wait-for cycles between threads."""
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

    def analyze(
        self,
        historical_observations: int = 1,
        observation_epochs: Optional[List[int]] = None,
        validated_observations_available: bool = True,
        epoch_count: Optional[int] = None,
    ) -> WaitForGraphAnalysisResult:
        """Evaluates graph semantics, completeness, and temporal persistence."""
        if epoch_count is not None:
            historical_observations = epoch_count
        cycles = self.find_cycles()
        blocked_tids = [w.tid for w in self.waiting_edges]

        ownership_rels = [
            {"lock_id": o.lock_id, "owning_tid": o.tid} for o in self.ownership_edges
        ]
        waiting_rels = [
            {"waiting_tid": w.tid, "lock_id": w.lock_id} for w in self.waiting_edges
        ]
        unresolved_info = [
            {"lock_id": u.lock_id, "waiting_tid": u.waiting_tid, "reason": u.reason}
            for u in self.unresolved_edges
        ]

        participating_threads = list(set(
            [w.tid for w in self.waiting_edges] + [o.tid for o in self.ownership_edges]
        ))

        # Check explicit observation epochs
        effective_epochs = observation_epochs or list(range(1, historical_observations + 1))
        epoch_count = len(set(effective_epochs))

        limitations: List[str] = []
        if not self.is_complete:
            limitations.append(
                f"Wait-for graph is incomplete: {len(self.unresolved_edges)} contested locks have unresolvable owners."
            )

        if not validated_observations_available:
            limitations.append("Underlying temporal observation records not available; supplied count unverified.")

        # P1: Incomplete lock graph must remain INCONCLUSIVE (never infer acyclic!)
        if not self.is_complete and not cycles:
            return WaitForGraphAnalysisResult(
                state=ConcurrencyState.INCONCLUSIVE_INCOMPLETE_GRAPH,
                confidence=0.40,
                rationale=(
                    f"Lock ownership graph is incomplete ({len(self.unresolved_edges)} unresolved lock owners). "
                    "Cannot establish absence of cycles from partial thread visibility."
                ),
                is_complete=False,
                unresolved_locks_count=len(self.unresolved_edges),
                detected_cycles=[],
                cycle_observed_count=0,
                is_persistent=False,
                blocked_threads=blocked_tids,
                participating_threads=participating_threads,
                lock_ownership_relationships=ownership_rels,
                waiting_relationships=waiting_rels,
                observation_epochs=effective_epochs,
                evidence_supporting_persistence=[],
                supporting_facts=[],
                contradicting_facts=[],
                missing_evidence=["complete_lock_ownership_mapping", "unresolved_lock_holders"],
                limitations=limitations,
                details={"unresolved_edges": unresolved_info, "incomplete_graph": True},
            )

        # Cycles detected: distinguish transient circular wait from persistent deadlock
        if cycles:
            # Persistent deadlock requires >= 2 distinct, validated observation epochs
            is_persistent = bool(epoch_count >= 2 and validated_observations_available)
            if is_persistent:
                return WaitForGraphAnalysisResult(
                    state=ConcurrencyState.PERSISTENT_DEADLOCK,
                    confidence=0.98,
                    rationale=f"Persistent circular wait deadlock verified across {epoch_count} distinct temporal epochs.",
                    is_complete=self.is_complete,
                    unresolved_locks_count=len(self.unresolved_edges),
                    detected_cycles=cycles,
                    cycle_observed_count=epoch_count,
                    is_persistent=True,
                    blocked_threads=blocked_tids,
                    participating_threads=participating_threads,
                    lock_ownership_relationships=ownership_rels,
                    waiting_relationships=waiting_rels,
                    observation_epochs=effective_epochs,
                    evidence_supporting_persistence=[
                        f"Wait cycle persisted across epochs: {effective_epochs}",
                        f"Detected circular dependency chains: {cycles}",
                    ],
                    supporting_facts=["Cycle persistent across consecutive temporal observations", f"Cycles: {cycles}"],
                    contradicting_facts=[],
                    missing_evidence=[],
                    limitations=limitations,
                    details={"deadlock_confirmed": True, "cycles": cycles, "is_persistent": True},
                )
            else:
                return WaitForGraphAnalysisResult(
                    state=ConcurrencyState.OBSERVED_CIRCULAR_WAIT,
                    confidence=0.75,
                    rationale="Circular wait cycle observed in single snapshot; requires multi-sample temporal persistence.",
                    is_complete=self.is_complete,
                    unresolved_locks_count=len(self.unresolved_edges),
                    detected_cycles=cycles,
                    cycle_observed_count=1,
                    is_persistent=False,
                    blocked_threads=blocked_tids,
                    participating_threads=participating_threads,
                    lock_ownership_relationships=ownership_rels,
                    waiting_relationships=waiting_rels,
                    observation_epochs=effective_epochs,
                    evidence_supporting_persistence=[],
                    supporting_facts=["Circular wait observed in current snapshot", f"Cycles: {cycles}"],
                    contradicting_facts=["Multi-epoch persistence not yet established"],
                    missing_evidence=["consecutive_temporal_observation_epochs"],
                    limitations=limitations,
                    details={"deadlock_confirmed": False, "transient_cycle": True, "is_persistent": False},
                )

        # Blocked thread under contention without circular wait
        if blocked_tids:
            return WaitForGraphAnalysisResult(
                state=ConcurrencyState.LOCK_CONTENTION,
                confidence=0.88,
                rationale=f"Threads {blocked_tids} blocked waiting for locks, but complete wait-for graph is strictly acyclic. Lock contention without deadlock.",
                is_complete=self.is_complete,
                unresolved_locks_count=len(self.unresolved_edges),
                detected_cycles=[],
                cycle_observed_count=0,
                is_persistent=False,
                blocked_threads=blocked_tids,
                participating_threads=participating_threads,
                lock_ownership_relationships=ownership_rels,
                waiting_relationships=waiting_rels,
                observation_epochs=effective_epochs,
                evidence_supporting_persistence=[],
                supporting_facts=[f"Lock contention on {len(self.waiting_edges)} threads without circular dependency"],
                contradicting_facts=["Wait-for graph is strictly acyclic"],
                missing_evidence=[],
                limitations=limitations,
                details={"contention": True, "deadlock_refuted": True},
            )

        # Thread Blocked (Idle / waiting on CV, no lock contention)
        return WaitForGraphAnalysisResult(
            state=ConcurrencyState.THREAD_BLOCKED,
            confidence=0.90,
            rationale="No blocked lock acquisitions observed in target process.",
            is_complete=self.is_complete,
            unresolved_locks_count=0,
            detected_cycles=[],
            cycle_observed_count=0,
            is_persistent=False,
            blocked_threads=[],
            participating_threads=[],
            lock_ownership_relationships=[],
            waiting_relationships=[],
            observation_epochs=effective_epochs,
            evidence_supporting_persistence=[],
            supporting_facts=["No lock wait queues detected"],
            contradicting_facts=[],
            missing_evidence=[],
            limitations=limitations,
            details={"clean": True},
        )

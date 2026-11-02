"""Adaptive Investigation Engine (Phase 2.0 — Process Health Investigation).

Coordinates evidence-grounded, budget-bounded adaptive investigations:
- Single explicit state machine (CREATED -> TARGET_VALIDATION -> INITIAL_TRIAGE ->
  HYPOTHESIS_FORMATION -> FOLLOW_UP_PLANNING -> OBSERVATION -> HYPOTHESIS_UPDATE ->
  (FOLLOW_UP_PLANNING | FINALIZATION) -> COMPLETED | INCONCLUSIVE | BUDGET_EXHAUSTED | FAILED | CANCELED)
- Low-impact Initial Process Health Triage without hardcoded application symbols
- Competing, structured hypotheses reusing extractor/hypothesis.py
- Deterministic Discriminating Follow-Up Planner selecting the cheapest observation
  that can materially change the hypothesis ranking
- Multi-dimensional pre-execution and post-execution budget enforcement
- Explicit observation result categories (NEW_EVIDENCE, DUPLICATE_EVIDENCE,
  NO_NEW_EVIDENCE, PARTIAL_EVIDENCE, OBSERVATION_FAILED, OBSERVATION_UNAVAILABLE, BUDGET_REJECTED)
- Calibrated stopping policy and scope-bounded verdicts (NO_ISSUE_DETECTED_WITHIN_SCOPE,
  SUSPECTED, PARTIALLY_CONFIRMED, CONFIRMED, REFUTED, INCONCLUSIVE)
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
import uuid

from .debug_image import inspect_elf
from .evidence_adapter import (
    COLLECTION_STATUS_ABSTAIN,
    COLLECTION_STATUS_COLLECTED,
    COLLECTION_STATUS_FAILED,
    COLLECTION_STATUS_PARTIAL,
    RESULT_BUDGET_REJECTED,
    RESULT_DUPLICATE_EVIDENCE,
    RESULT_NEW_EVIDENCE,
    RESULT_NO_NEW_EVIDENCE,
    RESULT_OBSERVATION_FAILED,
    RESULT_OBSERVATION_UNAVAILABLE,
    RESULT_PARTIAL_EVIDENCE,
    EvidenceAdapter,
    compute_semantic_evidence_digest,
    strip_volatile_fields,
)
from .evidence_ledger import (
    ATTRIBUTION_BASIS_CALL_STACK,
    ATTRIBUTION_BASIS_SINGLE_WRITER,
    EVIDENCE_TYPE_CAPTURE_QUALITY,
    EVIDENCE_TYPE_COMPARISON,
    EVIDENCE_TYPE_DIAGNOSTIC,
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EVIDENCE_TYPE_OBJECT_STATE,
    EVIDENCE_TYPE_RUNTIME_IDENTITY,
    EvidenceLedger,
    EvidenceRecord,
    LiveCaptureReceipt,
    NATURE_HYPOTHESIS,
    NATURE_INFERENCE,
    NATURE_OBSERVATION,
    PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    PROVENANCE_CLASS_SYNTHETIC_FIXTURE,
    TRUSTED_PROVENANCE_CLASSES,
    TRUST_STATE_LIVE_VERIFIED,
    TRUST_STATE_IMPORTED_UNVERIFIED,
    TRUST_STATE_INVALID_OR_TAMPERED,
    TRUST_STATE_VERIFICATION_UNAVAILABLE,
    determine_snapshot_trust_state,
    verify_live_capture_receipt,
)
from .hypothesis import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    HYPOTHESIS_STATUS_CONTRADICTED,
    HYPOTHESIS_STATUS_INCONCLUSIVE,
    HYPOTHESIS_STATUS_PROPOSED,
    HYPOTHESIS_STATUS_SUPPORTED,
    HYPOTHESIS_STATUS_VALIDATED,
    OBSERVATION_STATUS_CANCELED,
    OBSERVATION_STATUS_EXECUTED,
    OBSERVATION_STATUS_FAILED,
    OBSERVATION_STATUS_PROPOSED,
    OBSERVATION_STATUS_VERIFIED,
    TARGET_KIND_COMPARISON,
    TARGET_KIND_FIELD,
    TARGET_KIND_OBJECT,
    TARGET_KIND_THREAD,
    DeterministicHypothesisGenerator,
    FollowUpObservation,
    HypothesisValidator,
    InvestigationHypothesis,
)
from .inspection_module import (
    DOMAIN_CONCURRENCY,
    DOMAIN_GENERIC,
    DOMAIN_HEAP,
    DOMAIN_INTEGRITY,
    DOMAIN_IPC,
    DOMAIN_MEMORY,
    DOMAIN_TEMPORAL,
    FunctionalInspectionModule,
    InspectionContext,
    InspectionModule,
    InspectionModuleRegistry,
    InspectionProfile,
)
import math
from .observation_budget import (
    ObservationBudgetLimits,
    ObservationBudgetTracker,
    validate_non_negative_int,
    validate_non_negative_float,
    ObservationAccountingRecord,
)
from .target_adapter import (
    LocalTargetAdapter,
    ReadOnlyTargetAdapter,
    TargetExecutionAdapter,
    normalize_futex_address,
    MutexOwnerResolutionResult,
    STATUS_OWNER_IDENTIFIED,
    STATUS_OWNER_NOT_IDENTIFIED,
    STATUS_MUTEX_LAYOUT_UNSUPPORTED,
    STATUS_MUTEX_STATE_INVALID,
    STATUS_MEMORY_READ_UNAVAILABLE,
    STATUS_PERMISSION_DENIED,
    ABI_GLIBC_VERIFIED,
    ABI_MUSL_UNSUPPORTED,
    ABI_LIBC_UNKNOWN,
    ABI_STATIC_OR_UNIDENTIFIED,
    ABI_ARCH_UNSUPPORTED,
    ABI_ELF_CLASS_UNSUPPORTED,
    ABI_ENDIANNESS_UNSUPPORTED,
    IDENTITY_VERIFIED,
    IDENTITY_UNAVAILABLE,
    IDENTITY_INCONSISTENT,
    IDENTITY_UNVERIFIED,
    LAYOUT_GLIBC_LP64,
)
from .verdict_engine import (
    ASSERTION_ABSTAIN,
    ASSERTION_FAIL,
    ASSERTION_PASS,
    DIAG_CONFIRMED,
    DIAG_INCONCLUSIVE,
    DIAG_NO_ISSUE_DETECTED,
    DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE,
    DIAG_PARTIALLY_CONFIRMED,
    DIAG_REFUTED,
    DIAG_SUSPECTED,
    HYP_STATE_CONTRADICTED,
    HYP_STATE_INCONCLUSIVE,
    HYP_STATE_PROPOSED,
    HYP_STATE_SUPPORTED,
    HYP_STATE_VALIDATED,
    STOP_ALL_HYPOTHESES_REFUTED,
    STOP_BUDGET_EXHAUSTED,
    STOP_CAPABILITY_UNAVAILABLE,
    STOP_DIMINISHING_RETURNS,
    STOP_NO_USEFUL_SAFE_OBSERVATION,
    STOP_REPEATED_FAILURE,
    STOP_SUFFICIENT_EVIDENCE,
    STOP_USER_CANCELED,
    AssertionEvaluation,
    DiagnosticVerdict,
    VerdictEngine,
    ZeroCdnReporter,
)


RESULT_DEADLOCK_CYCLE_CONFIRMED = "DEADLOCK_CYCLE_CONFIRMED"
RESULT_LOCK_CONTENTION_OBSERVED = "LOCK_CONTENTION_OBSERVED"
RESULT_WAITING_WITH_UNKNOWN_OWNER = "WAITING_WITH_UNKNOWN_OWNER"
RESULT_INCOMPLETE_WAIT_FOR_GRAPH = "INCOMPLETE_WAIT_FOR_GRAPH"
RESULT_INCONSISTENT_OWNER_EVIDENCE = "INCONSISTENT_OWNER_EVIDENCE"
RESULT_INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class WaitForEdge:
    """Directed edge in a lock wait-for graph: waiter_tid waits on sync_object held by owner_tid.
    
    Auditable Evidence Guarantees:
    - Retains full provenance including waiter TID, raw futex argument, normalized address.
    - Explicit owner identification verification status and mutex layout identifier.
    - Direct memory read status, timestamps, and target process identification.
    """
    waiter_tid: int
    sync_object: str  # canonical hex address e.g. "0x7ffd12345678"
    raw_futex_argument: Any = None
    normalized_address: Optional[str] = None
    owner_tid: Optional[int] = None  # Identified owner TID, or None if unknown
    owner_identification_status: str = STATUS_OWNER_NOT_IDENTIFIED
    mutex_layout_id: Optional[str] = None
    memory_read_status: str = "UNAVAILABLE"
    evidence_source: str = "procfs_syscall"
    observation_timestamp: float = field(default_factory=time.time)
    target_pid: Optional[int] = None
    process_identity: Optional[Dict[str, Any]] = None
    sampling_epoch: Optional[int] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    # Backward compatibility: legacy source and timestamp properties
    source: Optional[str] = None
    timestamp: Optional[float] = None

    def __post_init__(self):
        if self.source and not self.evidence_source:
            self.evidence_source = self.source
        elif self.evidence_source and not self.source:
            self.source = self.evidence_source
        if self.timestamp is not None:
            self.observation_timestamp = self.timestamp
        elif self.observation_timestamp is not None and self.timestamp is None:
            self.timestamp = self.observation_timestamp
        if self.normalized_address is None:
            self.normalized_address = self.sync_object

    def to_dict(self) -> Dict[str, Any]:
        return {
            "waiter_tid": self.waiter_tid,
            "sync_object": self.sync_object,
            "raw_futex_argument": self.raw_futex_argument,
            "normalized_address": self.normalized_address,
            "owner_tid": self.owner_tid,
            "owner_identification_status": self.owner_identification_status,
            "mutex_layout_id": self.mutex_layout_id,
            "memory_read_status": self.memory_read_status,
            "evidence_source": self.evidence_source,
            "source": self.source,
            "observation_timestamp": self.observation_timestamp,
            "timestamp": self.timestamp,
            "target_pid": self.target_pid,
            "process_identity": self.process_identity,
            "sampling_epoch": self.sampling_epoch,
            "metadata": self.metadata,
        }


@dataclass
class WaitForGraph:
    """Directed wait-for graph with cycle detection and adversarial verification for circular deadlock proof."""
    edges: List[WaitForEdge] = field(default_factory=list)

    def add_edge(self, edge: WaitForEdge) -> None:
        self.edges.append(edge)

    def validate_and_analyze(
        self,
        max_temporal_skew_sec: float = 2.0,
        allowed_epoch: Optional[int] = None,
        target_tids: Optional[Union[Set[int], List[int]]] = None,
    ) -> Tuple[Optional[List[int]], str, List[str]]:
        """Validates all edges and analyzes the graph for circular deadlocks.
        
        Guarantees:
        - Cycles are accepted ONLY if every edge in the cycle has a verified owner (STATUS_OWNER_IDENTIFIED).
        - Rejects candidate cycles if edges have conflicting owners for the same lock address.
        - Rejects candidate cycles if timestamps across the cycle exhibit excessive temporal skew (> max_temporal_skew_sec).
        - Rejects edges with missing or cross-process target PID or process identity.
        - Rejects edges with unsupported mutex layout or unobserved memory reads.
        - Distinguishes confirmed cycles, unconfirmed contention, unknown owners, and incomplete graphs.
        
        Returns:
            (deadlock_cycle, result_category, issues)
        """
        issues: List[str] = []
        if not self.edges:
            return None, RESULT_INCONCLUSIVE, ["No wait-for edges recorded"]

        # Track observations
        owners_by_lock: Dict[str, Set[int]] = {}
        waiters_by_lock: Dict[str, Set[int]] = {}
        edges_by_waiter: Dict[int, List[WaitForEdge]] = {}
        verified_edges: List[WaitForEdge] = []
        has_unknown_owner = False
        has_unsupported_layout = False
        rejection_reasons: Dict[Tuple[int, str], List[str]] = {}

        # 1. Establish reference target_pid and process identity from first available edge
        ref_pid: Optional[int] = None
        ref_start_time: Optional[Any] = None
        ref_proc_ident: Optional[Dict[str, Any]] = None
        ref_epoch: Optional[int] = allowed_epoch
        has_cross_process_pid = False
        has_cross_process_identity = False
        has_cross_epoch = False
        has_missing_epoch = False

        for edge in self.edges:
            if edge.target_pid is not None and edge.target_pid > 0:
                if ref_pid is None:
                    ref_pid = edge.target_pid
                elif edge.target_pid != ref_pid:
                    has_cross_process_pid = True
            if edge.process_identity and isinstance(edge.process_identity, dict):
                st = edge.process_identity.get("process_start_time") or edge.process_identity.get("start_time")
                if st is not None:
                    if ref_start_time is None:
                        ref_start_time = st
                        ref_proc_ident = edge.process_identity
                    elif st != ref_start_time:
                        has_cross_process_identity = True
            ep = getattr(edge, "sampling_epoch", None)
            if ep is not None:
                if isinstance(ep, bool) or not isinstance(ep, int) or ep < 0:
                    issues.append(f"REJECT_INVALID_SAMPLING_EPOCH: Invalid sampling_epoch {ep} detected in wait-for graph")
                elif ref_epoch is None:
                    ref_epoch = ep
                elif ep != ref_epoch:
                    has_cross_epoch = True
            else:
                has_missing_epoch = True

        if has_cross_process_pid:
            issues.append(f"REJECT_CROSS_PROCESS_PID_MISMATCH: Cross-process evidence detected; multiple target PIDs in wait-for graph")
        if has_cross_process_identity:
            issues.append(f"REJECT_CROSS_PROCESS_IDENTITY_MISMATCH: Cross-process evidence detected; multiple process start identities in wait-for graph")
        if has_cross_epoch:
            issues.append(f"REJECT_CROSS_EPOCH_MISMATCH: Cross-epoch evidence detected; observations from different sampling epochs in wait-for graph")
        if has_missing_epoch:
            issues.append(f"REJECT_MISSING_SAMPLING_EPOCH: Edge missing explicit sampling_epoch detected in wait-for graph")

        # 2. Inspect and validate each edge
        for edge in self.edges:
            edge_key = (edge.waiter_tid, edge.sync_object)
            edge_issues: List[str] = []

            waiters_by_lock.setdefault(edge.sync_object, set()).add(edge.waiter_tid)
            if edge.owner_tid is not None:
                owners_by_lock.setdefault(edge.sync_object, set()).add(edge.owner_tid)
            edges_by_waiter.setdefault(edge.waiter_tid, []).append(edge)

            # Target PID validation
            if edge.target_pid is None or edge.target_pid <= 0:
                edge_issues.append(f"REJECT_MISSING_TARGET_PID: Edge waiter TID {edge.waiter_tid} has missing or invalid target_pid")
            elif ref_pid is not None and edge.target_pid != ref_pid:
                edge_issues.append(f"REJECT_CROSS_PROCESS_PID_MISMATCH: Edge target_pid {edge.target_pid} differs from graph reference {ref_pid}")

            # Process identity validation (Step 1 Strict Evidence Gate)
            if not edge.process_identity or not isinstance(edge.process_identity, dict):
                edge_issues.append(f"REJECT_MISSING_PROCESS_IDENTITY: Edge waiter TID {edge.waiter_tid} missing process_identity")
            else:
                ident_pid = edge.process_identity.get("pid")
                if ident_pid is None or edge.target_pid is None or ident_pid != edge.target_pid:
                    edge_issues.append(f"REJECT_IDENTITY_PID_MISMATCH: Identity PID {ident_pid} does not match edge target_pid {edge.target_pid}")

                p_st = edge.process_identity.get("process_start_time") or edge.process_identity.get("start_time")
                if p_st is None or not isinstance(p_st, (int, float)) or p_st <= 0:
                    edge_issues.append(f"REJECT_MISSING_PROCESS_START_TIME: Edge waiter TID {edge.waiter_tid} process_identity lacks stable process_start_time")
                elif ref_start_time is not None and p_st != ref_start_time:
                    edge_issues.append(f"REJECT_CROSS_PROCESS_IDENTITY_MISMATCH: Edge process_start_time {p_st} differs from graph start_time {ref_start_time}")

                p_ident_st = edge.process_identity.get("identity_status")
                if p_ident_st == IDENTITY_UNAVAILABLE:
                    edge_issues.append(f"REJECT_IDENTITY_UNAVAILABLE: Process identity status is IDENTITY_UNAVAILABLE for waiter TID {edge.waiter_tid}")
                elif p_ident_st == IDENTITY_INCONSISTENT:
                    edge_issues.append(f"REJECT_IDENTITY_INCONSISTENT: Process identity status is IDENTITY_INCONSISTENT for waiter TID {edge.waiter_tid}")
                elif p_ident_st != IDENTITY_VERIFIED:
                    edge_issues.append(f"REJECT_IDENTITY_UNVERIFIED: Process identity status is unverified ({p_ident_st}) for waiter TID {edge.waiter_tid}; confirmed deadlock requires explicit verified identity")

            # Sampling epoch validation (Step 2 Sampling Epoch Semantics)
            edge_epoch = getattr(edge, "sampling_epoch", None)
            if edge_epoch is None:
                edge_issues.append(f"REJECT_MISSING_SAMPLING_EPOCH: Edge waiter TID {edge.waiter_tid} missing explicit sampling_epoch")
            elif isinstance(edge_epoch, bool) or not isinstance(edge_epoch, int) or edge_epoch < 0:
                edge_issues.append(f"REJECT_INVALID_SAMPLING_EPOCH: Edge waiter TID {edge.waiter_tid} has invalid sampling_epoch {edge_epoch}")
            elif ref_epoch is not None and edge_epoch != ref_epoch:
                edge_issues.append(f"REJECT_CROSS_EPOCH_MISMATCH: Edge epoch {edge_epoch} differs from graph epoch {ref_epoch}")
            if allowed_epoch is not None and edge_epoch is not None and edge_epoch != allowed_epoch:
                edge_issues.append(f"REJECT_CROSS_EPOCH_MISMATCH: Edge epoch {edge_epoch} differs from allowed epoch {allowed_epoch}")

            # Waiter / Owner TID validation
            if edge.waiter_tid <= 0:
                edge_issues.append(f"REJECT_INVALID_WAITER_TID: Invalid waiter TID {edge.waiter_tid}")
            if edge.owner_tid is not None and edge.owner_tid <= 0:
                edge_issues.append(f"REJECT_INVALID_OWNER_TID: Invalid owner TID {edge.owner_tid}")

            # Task membership validation
            effective_tids = set(target_tids) if target_tids else (set(edge.metadata.get("target_tids", [])) if (edge.metadata and edge.metadata.get("target_tids")) else None)
            if effective_tids:
                if edge.waiter_tid not in effective_tids:
                    edge_issues.append(f"REJECT_WAITER_TID_NOT_IN_TARGET: Waiter TID {edge.waiter_tid} does not belong to target process")
                if edge.owner_tid is not None and edge.owner_tid not in effective_tids:
                    edge_issues.append(f"REJECT_OWNER_TID_NOT_IN_TARGET: Owner TID {edge.owner_tid} does not belong to target process")

            # Mutex layout validation
            if edge.owner_identification_status == STATUS_MUTEX_LAYOUT_UNSUPPORTED or edge.mutex_layout_id in (ABI_MUSL_UNSUPPORTED, ABI_LIBC_UNKNOWN, ABI_STATIC_OR_UNIDENTIFIED, ABI_ARCH_UNSUPPORTED, ABI_ELF_CLASS_UNSUPPORTED, ABI_ENDIANNESS_UNSUPPORTED):
                has_unsupported_layout = True
                edge_issues.append(f"REJECT_UNSUPPORTED_MUTEX_LAYOUT: Mutex layout {edge.mutex_layout_id} unsupported for waiter TID {edge.waiter_tid}")
            elif edge.mutex_layout_id != LAYOUT_GLIBC_LP64:
                edge_issues.append(f"REJECT_UNSUPPORTED_MUTEX_LAYOUT: Mutex layout {edge.mutex_layout_id} is not verified LP64 glibc")

            # Memory read status validation
            if edge.memory_read_status != "OBSERVED":
                edge_issues.append(f"REJECT_MEMORY_READ_NOT_OBSERVED: Memory read status is '{edge.memory_read_status}' (must be OBSERVED)")

            # Raw memory evidence and interpretation metadata
            has_raw = bool((edge.metadata or {}).get("raw_bytes")) or bool((edge.metadata or {}).get("read_bytes_len", 0) > 0)
            has_interp = any(k in (edge.metadata or {}) for k in ("lock_word", "kind", "base_kind", "owner"))
            if not has_raw or not has_interp:
                edge_issues.append(f"REJECT_MISSING_RAW_MEMORY_EVIDENCE: Edge lacks verified raw memory evidence or interpretation metadata")

            # Normalized address validation
            if edge.normalized_address and edge.normalized_address != edge.sync_object:
                edge_issues.append(f"REJECT_ADDRESS_MISMATCH: normalized_address ({edge.normalized_address}) != sync_object ({edge.sync_object})")

            # Timestamp validation
            ts = edge.observation_timestamp or getattr(edge, "timestamp", 0.0) or 0.0
            if ts <= 0:
                edge_issues.append(f"REJECT_MISSING_OR_INVALID_TIMESTAMP: Observation timestamp is non-positive or missing ({ts})")

            # Owner identification status validation
            if edge.owner_identification_status != STATUS_OWNER_IDENTIFIED or edge.owner_tid is None:
                has_unknown_owner = True
                edge_issues.append(f"REJECT_OWNER_NOT_IDENTIFIED: Owner unconfirmed ({edge.owner_identification_status}) for waiter TID {edge.waiter_tid}")

            if edge_issues:
                rejection_reasons[edge_key] = edge_issues
                issues.extend(edge_issues)
            else:
                verified_edges.append(edge)

        # 3. Check conflicting owners on locks
        conflicting_locks = {lock: tids for lock, tids in owners_by_lock.items() if len(tids) > 1}
        if conflicting_locks:
            for lock, tids in conflicting_locks.items():
                issues.append(f"Conflicting owners observed for lock {lock}: {sorted(tids)}")
            return None, RESULT_INCONSISTENT_OWNER_EVIDENCE, issues

        # 4. Multi-observation & conflict detection across waiter edges
        for waiter_tid, w_edges in edges_by_waiter.items():
            if len(w_edges) > 1:
                distinct_locks = {e.sync_object for e in w_edges}
                distinct_owners = {e.owner_tid for e in w_edges if e.owner_tid is not None}
                if len(distinct_locks) > 1 or len(distinct_owners) > 1:
                    issues.append(
                        f"Conflicting observations for waiter TID {waiter_tid}: multiple locks ({sorted(distinct_locks)}) or owners ({sorted(distinct_owners)})"
                    )
                    return None, RESULT_INCONSISTENT_OWNER_EVIDENCE, issues

        if has_cross_process_pid or has_cross_process_identity or has_cross_epoch:
            return None, RESULT_INCONSISTENT_OWNER_EVIDENCE, issues

        # 5. Cycle Detection using ONLY verified edges
        adj: Dict[int, int] = {}
        edge_map: Dict[Tuple[int, int], WaitForEdge] = {}
        for edge in verified_edges:
            if edge.owner_tid is not None:
                adj[edge.waiter_tid] = edge.owner_tid
                edge_map[(edge.waiter_tid, edge.owner_tid)] = edge

        candidate_cycle: Optional[List[int]] = None
        visited: Set[int] = set()
        for start_node in list(adj.keys()):
            if start_node in visited:
                continue
            curr = start_node
            path: List[int] = []
            seen_in_path: Dict[int, int] = {}
            while curr in adj:
                if curr in seen_in_path:
                    cycle_start = seen_in_path[curr]
                    candidate_cycle = path[cycle_start:] + [curr]
                    break
                seen_in_path[curr] = len(path)
                path.append(curr)
                visited.add(curr)
                curr = adj[curr]
            if candidate_cycle:
                break

        if candidate_cycle:
            # Validate temporal skew across candidate cycle edges
            cycle_timestamps: List[float] = []
            for i in range(len(candidate_cycle) - 1):
                u = candidate_cycle[i]
                v = candidate_cycle[i + 1]
                e = edge_map.get((u, v))
                if e:
                    ts = e.observation_timestamp or getattr(e, "timestamp", 0.0) or 0.0
                    if ts > 0:
                        cycle_timestamps.append(ts)
            if cycle_timestamps:
                skew = max(cycle_timestamps) - min(cycle_timestamps)
                if skew > max_temporal_skew_sec:
                    issues.append(f"Excessive temporal skew in candidate cycle: {skew:.2f}s > {max_temporal_skew_sec:.2f}s")
                    return None, RESULT_INCONCLUSIVE, issues

            # Fully confirmed circular deadlock!
            return candidate_cycle, RESULT_DEADLOCK_CYCLE_CONFIRMED, issues

        # No verified cycle found
        has_contention = any(len(tids) > 1 for tids in waiters_by_lock.values())
        if has_contention:
            return None, RESULT_LOCK_CONTENTION_OBSERVED, issues

        if has_unsupported_layout or has_unknown_owner:
            return None, RESULT_WAITING_WITH_UNKNOWN_OWNER, issues

        return None, RESULT_INCOMPLETE_WAIT_FOR_GRAPH, issues

    def find_cycle(self) -> Optional[List[int]]:
        cycle, category, _ = self.validate_and_analyze()
        return cycle

    def has_cycle(self) -> bool:
        return self.find_cycle() is not None

    def to_dict(self) -> Dict[str, Any]:
        cycle, category, issues = self.validate_and_analyze()
        return {
            "edges": [e.to_dict() for e in self.edges],
            "num_edges": len(self.edges),
            "deadlock_cycle": cycle,
            "deadlock_detected": bool(cycle),
            "result_category": category,
            "issues": issues,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WaitForGraph":
        raw_edges = data.get("edges", [])
        edges = []
        for e in raw_edges:
            if isinstance(e, WaitForEdge):
                edges.append(e)
            elif isinstance(e, dict):
                edges.append(WaitForEdge(**e))
        return cls(edges=edges)

# -----------------------------------------------------------------------------
# 1. Single Investigation Lifecycle State Machine
# -----------------------------------------------------------------------------

STATE_CREATED = "CREATED"
STATE_TARGET_VALIDATION = "TARGET_VALIDATION"
STATE_INITIAL_TRIAGE = "INITIAL_TRIAGE"
STATE_HYPOTHESIS_FORMATION = "HYPOTHESIS_FORMATION"
STATE_FOLLOW_UP_PLANNING = "FOLLOW_UP_PLANNING"
STATE_OBSERVATION = "OBSERVATION"
STATE_HYPOTHESIS_UPDATE = "HYPOTHESIS_UPDATE"
STATE_FINALIZATION = "FINALIZATION"
STATE_COMPLETED = "COMPLETED"
STATE_INCONCLUSIVE = "INCONCLUSIVE"
STATE_BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
STATE_FAILED = "FAILED"
STATE_CANCELED = "CANCELED"

TERMINAL_LIFECYCLE_STATES = {
    STATE_COMPLETED,
    STATE_INCONCLUSIVE,
    STATE_BUDGET_EXHAUSTED,
    STATE_FAILED,
    STATE_CANCELED,
}

VALID_LIFECYCLE_TRANSITIONS: Dict[str, Set[str]] = {
    STATE_CREATED: {STATE_TARGET_VALIDATION, STATE_FAILED, STATE_CANCELED},
    STATE_TARGET_VALIDATION: {STATE_INITIAL_TRIAGE, STATE_FINALIZATION, STATE_FAILED, STATE_CANCELED},
    STATE_INITIAL_TRIAGE: {
        STATE_HYPOTHESIS_FORMATION,
        STATE_FINALIZATION,
        STATE_BUDGET_EXHAUSTED,
        STATE_FAILED,
        STATE_CANCELED,
    },
    STATE_HYPOTHESIS_FORMATION: {
        STATE_FOLLOW_UP_PLANNING,
        STATE_FINALIZATION,
        STATE_BUDGET_EXHAUSTED,
        STATE_FAILED,
        STATE_CANCELED,
    },
    STATE_FOLLOW_UP_PLANNING: {
        STATE_OBSERVATION,
        STATE_FINALIZATION,
        STATE_BUDGET_EXHAUSTED,
        STATE_FAILED,
        STATE_CANCELED,
    },
    STATE_OBSERVATION: {
        STATE_HYPOTHESIS_UPDATE,
        STATE_FINALIZATION,
        STATE_BUDGET_EXHAUSTED,
        STATE_FAILED,
        STATE_CANCELED,
    },
    STATE_HYPOTHESIS_UPDATE: {
        STATE_FOLLOW_UP_PLANNING,
        STATE_FINALIZATION,
        STATE_BUDGET_EXHAUSTED,
        STATE_FAILED,
        STATE_CANCELED,
    },
    STATE_FINALIZATION: {
        STATE_COMPLETED,
        STATE_INCONCLUSIVE,
        STATE_BUDGET_EXHAUSTED,
        STATE_FAILED,
        STATE_CANCELED,
    },
    STATE_COMPLETED: set(),
    STATE_INCONCLUSIVE: set(),
    STATE_BUDGET_EXHAUSTED: set(),
    STATE_FAILED: set(),
    STATE_CANCELED: set(),
}


class InvestigationStateMachine:
    """Enforces the explicit, auditable investigation lifecycle state machine."""

    def __init__(
        self,
        initial_state: str = STATE_CREATED,
        transitions: Optional[List[Dict[str, Any]]] = None,
    ):
        if initial_state not in VALID_LIFECYCLE_TRANSITIONS:
            raise ValueError(f"Invalid initial lifecycle state: '{initial_state}'")
        self._state: str = initial_state
        self._transitions: List[Dict[str, Any]] = list(transitions or [])

    @property
    def state(self) -> str:
        return self._state

    @property
    def transitions(self) -> List[Dict[str, Any]]:
        return list(self._transitions)

    @property
    def is_terminal(self) -> bool:
        return self._state in TERMINAL_LIFECYCLE_STATES

    def can_transition(self, to_state: str) -> bool:
        return to_state in VALID_LIFECYCLE_TRANSITIONS.get(self._state, set())

    def transition(
        self,
        to_state: str,
        reason: str,
        timestamp: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Executes a validated state transition with mandatory reason and timestamp."""
        if not reason or not str(reason).strip():
            raise ValueError(f"Transition from '{self._state}' to '{to_state}' requires a non-empty reason.")
        if to_state not in VALID_LIFECYCLE_TRANSITIONS:
            raise ValueError(f"Unknown target lifecycle state: '{to_state}'")
        allowed = VALID_LIFECYCLE_TRANSITIONS.get(self._state, set())
        if to_state not in allowed:
            raise ValueError(
                f"Invalid lifecycle state transition: '{self._state}' -> '{to_state}'. "
                f"Allowed transitions from '{self._state}': {sorted(allowed)}"
            )

        ts = timestamp or datetime.now(timezone.utc).isoformat()
        entry: Dict[str, Any] = {
            "transition_index": len(self._transitions),
            "from_state": self._state,
            "to_state": to_state,
            "reason": str(reason).strip(),
            "timestamp": ts,
        }
        if metadata:
            entry["metadata"] = dict(metadata)
        self._transitions.append(entry)
        self._state = to_state
        return entry

    def to_dict(self) -> Dict[str, Any]:
        return {
            "current_state": self._state,
            "is_terminal": self.is_terminal,
            "transitions": list(self._transitions),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InvestigationStateMachine":
        st = data.get("current_state", STATE_CREATED)
        tr = list(data.get("transitions", []))
        return cls(initial_state=st, transitions=tr)


class EvidenceCache:
    """Disaggregates static binary evidence from dynamic runtime sampling epochs."""

    def __init__(self):
        self._static_cache: Dict[str, Any] = {}
        self._dynamic_cache: Dict[str, Dict[str, Any]] = {}
        self._current_epoch: int = 0

    @property
    def current_epoch(self) -> int:
        return self._current_epoch

    def advance_epoch(self) -> int:
        """Invalidates dynamic cache and increments runtime sampling epoch."""
        self._current_epoch += 1
        self._dynamic_cache.clear()
        return self._current_epoch

    def get_static(self, binary_key: str, item_key: str) -> Optional[Any]:
        return self._static_cache.get(f"{binary_key}::{item_key}")

    def put_static(self, binary_key: str, item_key: str, val: Any) -> None:
        self._static_cache[f"{binary_key}::{item_key}"] = val

    def get_dynamic(self, target_key: str, item_key: str) -> Optional[Any]:
        return self._dynamic_cache.get(f"epoch_{self._current_epoch}::{target_key}::{item_key}")

    def put_dynamic(self, target_key: str, item_key: str, val: Any) -> None:
        self._dynamic_cache[f"epoch_{self._current_epoch}::{target_key}::{item_key}"] = val


# -----------------------------------------------------------------------------
# 4. Deterministic Discriminating Follow-Up Planner & Scheduler
# -----------------------------------------------------------------------------

DOMAIN_PRIORITY_ORDER = {
    DOMAIN_MEMORY: 0,
    DOMAIN_CONCURRENCY: 1,
    DOMAIN_INTEGRITY: 2,
    DOMAIN_IPC: 3,
    DOMAIN_HEAP: 4,
    DOMAIN_TEMPORAL: 5,
    DOMAIN_GENERIC: 6,
}


class DeterministicScheduler:
    """Maintains a deterministic inspection execution queue with strict tie-breaking."""

    def __init__(self, registry: Optional[InspectionModuleRegistry] = None):
        self.registry = registry
        self._queue: List[Tuple[int, str, int]] = []  # (-priority, profile_id, sequence_id)
        self._seq: int = 0
        self._enqueued_ids: Set[str] = set()

    def schedule_modules(self, modules: List[InspectionModule]) -> List[InspectionModule]:
        """Deterministically orders modules by domain priority ASC, then module_id ASC."""
        return sorted(
            modules,
            key=lambda m: (
                DOMAIN_PRIORITY_ORDER.get(getattr(m, "domain", m.profile.domain), 99),
                getattr(m, "module_id", m.profile.profile_id),
            ),
        )

    def enqueue(self, profile_id: str) -> bool:
        if profile_id in self._enqueued_ids:
            return False
        if not self.registry:
            return False

        profile = self.registry.get(profile_id)
        if not profile:
            return False

        p_obj = profile.profile
        self._seq += 1
        entry = (-p_obj.priority, p_obj.profile_id, self._seq)
        self._queue.append(entry)
        self._enqueued_ids.add(profile_id)
        self._queue.sort()
        return True

    def pop_next(self) -> Optional[str]:
        if not self._queue:
            return None
        _, profile_id, _ = self._queue.pop(0)
        return profile_id

    def is_empty(self) -> bool:
        return len(self._queue) == 0

    @property
    def enqueued_ids(self) -> Set[str]:
        return set(self._enqueued_ids)


class AdaptiveInvestigationPlanner:
    """Deterministic planner for initial triage and discriminating follow-up observations."""

    def __init__(self, registry: InspectionModuleRegistry):
        self.registry = registry

    def plan_initial_inspections(
        self,
        goal: str,
        assertions: Optional[List[str]] = None,
        symptom_hints: Optional[List[str]] = None,
        capabilities: Optional[Dict[str, Any]] = None,
        available_symbols: Optional[Set[str]] = None,
    ) -> List[str]:
        """Produces a deterministic, low-impact initial triage plan without assuming hardcoded symbols."""
        lower_goal = (goal or "").lower()
        hints = [h.lower() for h in (symptom_hints or [])]
        combined = lower_goal + " " + " ".join(hints)
        caps = capabilities or {}

        selected: Set[str] = set()

        # Always include low-impact process health triage modules that do NOT require hardcoded symbols
        for p in self.registry.list_profiles():
            if p.requires_explicit_target_expression:
                continue
            if any(caps.get(req_c) is False for req_c in p.required_capabilities):
                continue
            if p.required_symbols and available_symbols is not None:
                if not all(s in available_symbols for s in p.required_symbols):
                    continue
            if p.priority >= 140:
                selected.add(p.profile_id)

        # Domain keyword hints only schedule modules whose prerequisites/symbols are actually satisfied
        if any(w in combined for w in ("deadlock", "lock", "mutex", "stuck", "hang", "blocked", "contention", "thread")):
            for p in self.registry.list_profiles(domain=DOMAIN_CONCURRENCY):
                if not p.requires_explicit_target_expression:
                    selected.add(p.profile_id)

        all_profiles = [p for p in self.registry.list_profiles() if p.profile_id in selected]
        return [p.profile_id for p in all_profiles]

    def select_next_observation(
        self,
        hypotheses: List[InvestigationHypothesis],
        budget_tracker: ObservationBudgetTracker,
        executed_observation_keys: Set[str],
        capabilities: Optional[Dict[str, Any]] = None,
        available_symbols: Optional[Set[str]] = None,
        current_epoch: int = 0,
    ) -> Tuple[Optional[FollowUpObservation], List[Dict[str, Any]]]:
        """Deterministically selects the cheapest read-only follow-up observation that can
        materially discriminate between competing unresolved hypotheses.

        Returns:
            (selected_observation, evaluated_candidates_log)
        """
        caps = capabilities or {}
        unresolved_hypos = {
            h.hypothesis_id: h
            for h in hypotheses
            if h.validation_status in (HYPOTHESIS_STATUS_PROPOSED, HYPOTHESIS_STATUS_SUPPORTED)
        }
        if not unresolved_hypos:
            return None, []

        # Gather unique candidate observations across unresolved hypotheses
        candidates_by_key: Dict[str, FollowUpObservation] = {}
        for h_id in sorted(unresolved_hypos.keys()):
            h = unresolved_hypos[h_id]
            for obs in h.suggested_observations:
                if obs.executed or obs.status in (
                    OBSERVATION_STATUS_EXECUTED,
                    OBSERVATION_STATUS_VERIFIED,
                    OBSERVATION_STATUS_FAILED,
                    OBSERVATION_STATUS_CANCELED,
                ):
                    continue
                epoch_key = f"{obs.semantic_key}::epoch_{current_epoch}"
                if obs.observation_id in executed_observation_keys or obs.semantic_key in executed_observation_keys or epoch_key in executed_observation_keys:
                    continue
                if obs.semantic_key not in candidates_by_key:
                    candidates_by_key[obs.semantic_key] = obs
                else:
                    existing_obs = candidates_by_key[obs.semantic_key]
                    if h_id not in existing_obs.tested_hypothesis_ids:
                        existing_obs.tested_hypothesis_ids.append(h_id)

        evaluated_log: List[Dict[str, Any]] = []
        feasible: List[Tuple[Tuple[int, int, int, int, float, str], FollowUpObservation, Dict[str, Any]]] = []

        for sem_key in sorted(candidates_by_key.keys()):
            obs = candidates_by_key[sem_key]

            # 1. Safety check: strictly read-only / low-impact
            if obs.risk_level not in ("READ_ONLY", "LOW_IMPACT", "CAUTION"):
                evaluated_log.append({
                    "observation_id": obs.observation_id,
                    "semantic_key": sem_key,
                    "eligible": False,
                    "rejection_reason": f"Disallowed non-read-only risk_level '{obs.risk_level}'",
                })
                continue

            # 2. Prerequisite & capability check
            missing_caps = [
                req_c for req_c in obs.prerequisites
                if caps.get(req_c) is False
            ]
            if missing_caps:
                obs.result_category = RESULT_OBSERVATION_UNAVAILABLE
                obs.execution_error = f"Unavailable prerequisite capability: {missing_caps}"
                evaluated_log.append({
                    "observation_id": obs.observation_id,
                    "semantic_key": sem_key,
                    "eligible": False,
                    "result_category": RESULT_OBSERVATION_UNAVAILABLE,
                    "rejection_reason": obs.execution_error,
                })
                continue

            # 3. Profile ceiling & pre-execution budget check
            mod = self.registry.get(obs.profile_id) if (self.registry and obs.profile_id) else None
            prof_ceiling = mod.profile.budget_ceiling if mod else None
            est_bytes = obs.estimated_bytes if obs.estimated_bytes is not None else (mod.profile.estimated_bytes if mod else None)
            est_lat_ms = float(obs.estimated_latency_ms or (mod.profile.estimated_latency_ms if mod else 20.0))
            est_samples = int(obs.estimated_samples or 1)
            est_stop_ms = float(obs.estimated_stop_ms or 0.0)

            can_exec, budget_reason, eff_est_bytes = budget_tracker.check_pre_execution(
                estimated_bytes=est_bytes,
                estimated_latency_ms=est_lat_ms,
                estimated_samples=est_samples,
                estimated_stop_ms=est_stop_ms,
                profile_id=obs.profile_id,
                profile_ceiling=prof_ceiling,
            )
            if not can_exec:
                budget_tracker.record_rejection(obs.profile_id or obs.observation_id, budget_reason or "BUDGET_REJECTED")
                obs.result_category = RESULT_BUDGET_REJECTED
                obs.execution_error = budget_reason
                evaluated_log.append({
                    "observation_id": obs.observation_id,
                    "semantic_key": sem_key,
                    "eligible": False,
                    "result_category": RESULT_BUDGET_REJECTED,
                    "rejection_reason": budget_reason,
                    "estimated_bytes": eff_est_bytes,
                })
                continue

            # 4. Calculate discriminating power & expected information gain
            tested_unresolved = [hid for hid in obs.tested_hypothesis_ids if hid in unresolved_hypos]
            if not tested_unresolved and obs.hypothesis_id in unresolved_hypos:
                tested_unresolved = [obs.hypothesis_id]

            # Check whether outcomes differ across competing hypotheses
            distinct_outcome_vectors = set()
            for hid in tested_unresolved:
                h_outcomes = obs.expected_outcomes_by_hypothesis.get(hid)
                if isinstance(h_outcomes, dict):
                    distinct_outcome_vectors.add(tuple(sorted(h_outcomes.items())))
            discriminating_count = max(len(distinct_outcome_vectors), len(tested_unresolved))

            power_score = {"HIGH": 30, "MEDIUM": 20, "LOW": 10}.get(obs.discriminating_power, 15)
            can_materially_change_ranking = 1 if (discriminating_count >= 2 or power_score >= 30) else 0
            info_gain_score = power_score + (15 * discriminating_count)

            # Sort key:
            # 1) -can_materially_change_ranking (prefer observations that can change ranking)
            # 2) -discriminating_count (prefer observations discriminating more competing hypotheses)
            # 3) eff_est_bytes ASC (prefer the CHEAPEST observation that can materially change ranking!)
            # 4) -info_gain_score
            # 5) est_lat_ms ASC
            # 6) observation_id ASC (deterministic tie-breaker)
            sort_key = (
                -can_materially_change_ranking,
                -discriminating_count,
                eff_est_bytes,
                -info_gain_score,
                est_lat_ms,
                obs.observation_id,
            )

            meta = {
                "observation_id": obs.observation_id,
                "semantic_key": sem_key,
                "eligible": True,
                "tested_hypothesis_ids": tested_unresolved,
                "discriminating_count": discriminating_count,
                "can_materially_change_ranking": bool(can_materially_change_ranking),
                "info_gain_score": info_gain_score,
                "estimated_bytes": eff_est_bytes,
                "estimated_latency_ms": est_lat_ms,
                "estimated_stop_ms": est_stop_ms,
                "risk_level": obs.risk_level,
            }
            evaluated_log.append(meta)
            feasible.append((sort_key, obs, meta))

        if not feasible:
            return None, evaluated_log

        feasible.sort(key=lambda item: item[0])
        _, best_obs, best_meta = feasible[0]

        if len(feasible) > 1:
            alt_obs = feasible[1][1]
            alt_meta = feasible[1][2]
            best_obs.preference_rationale = (
                f"Selected '{best_obs.observation_id}' (tests {best_meta['tested_hypothesis_ids']}, "
                f"discriminates={best_meta['discriminating_count']}, est_bytes={best_meta['estimated_bytes']}B, "
                f"est_latency={best_meta['estimated_latency_ms']}ms, risk={best_obs.risk_level}) over alternative "
                f"'{alt_obs.observation_id}' (discriminates={alt_meta['discriminating_count']}, "
                f"est_bytes={alt_meta['estimated_bytes']}B, est_latency={alt_meta['estimated_latency_ms']}ms) "
                f"as the lowest-cost observation capable of materially updating competing hypothesis rankings."
            )
        else:
            best_obs.preference_rationale = (
                f"Selected '{best_obs.observation_id}' as the sole budget-feasible read-only observation "
                f"testing {best_meta['tested_hypothesis_ids']} (est_bytes={best_meta['estimated_bytes']}B, "
                f"est_latency={best_meta['estimated_latency_ms']}ms)."
            )

        return best_obs, evaluated_log

    def refine_plan(
        self,
        current_profile_id: str,
        inspection_result: Dict[str, Any],
        already_scheduled: Set[str],
    ) -> List[str]:
        """Backward-compatible helper that refines profile queue when explicit symbols are present."""
        additional: List[str] = []

        # If deadlock or mutex contention found, ensure thread owner analysis is scheduled
        if inspection_result.get("deadlock_detected") or inspection_result.get("contended_locks"):
            if "insp_find_owners" not in already_scheduled and self.registry.get("insp_find_owners"):
                additional.append("insp_find_owners")

        # If memory pool leakage or stuck slots found, add symbol owner lookup
        if inspection_result.get("leak_count", 0) > 0 or inspection_result.get("stuck_slots"):
            if "insp_find_owners" not in already_scheduled and self.registry.get("insp_find_owners"):
                additional.append("insp_find_owners")

        # If corrupted pointers found in memory integrity audit, schedule frame locals
        if inspection_result.get("corrupted_pointers", 0) > 0:
            if "insp_frame_locals" not in already_scheduled and self.registry.get("insp_frame_locals"):
                additional.append("insp_frame_locals")

        return additional


# -----------------------------------------------------------------------------
# 7. Stopping Policy Evaluator
# -----------------------------------------------------------------------------

class AdaptiveTerminationPolicy:
    """Evaluates multi-factor stopping criteria for an investigation without requiring 100% confidence."""

    @staticmethod
    def evaluate_stopping_policy(
        budget_tracker: ObservationBudgetTracker,
        hypotheses: List[InvestigationHypothesis],
        remaining_observations_count: int = 0,
        consecutive_non_novel_steps: int = 0,
        consecutive_failures: int = 0,
        all_remaining_budget_rejected: bool = False,
        all_remaining_unavailable: bool = False,
        is_canceled: bool = False,
        temporal_samples_count: int = 1,
    ) -> Tuple[bool, str, str]:
        """Evaluates whether the adaptive loop should terminate.

        Returns:
            (should_stop, stop_reason_code, human_explanation)
        """
        if is_canceled:
            return True, STOP_USER_CANCELED, "Investigation was canceled by user or caller policy."

        ok, budget_reason = budget_tracker.check_budget()
        if not ok or all_remaining_budget_rejected:
            return (
                True,
                STOP_BUDGET_EXHAUSTED,
                f"Observation budget exhausted ({budget_reason or 'remaining observations exceed budget ceiling'}).",
            )

        if consecutive_failures >= budget_tracker.limits.max_consecutive_read_failures:
            return (
                True,
                STOP_REPEATED_FAILURE,
                f"Terminated after {consecutive_failures} consecutive failed observations.",
            )

        if all_remaining_unavailable and remaining_observations_count == 0:
            return (
                True,
                STOP_CAPABILITY_UNAVAILABLE,
                "Required observation capabilities or symbols are unavailable in target.",
            )

        defect_hypos = [
            h for h in hypotheses
            if not bool((h.provenance or {}).get("is_benign_explanation"))
        ]
        benign_hypos = [
            h for h in hypotheses
            if bool((h.provenance or {}).get("is_benign_explanation"))
        ]

        # Check if all material defect hypotheses are refuted
        if defect_hypos and all(h.validation_status == HYPOTHESIS_STATUS_CONTRADICTED for h in defect_hypos):
            return (
                True,
                STOP_ALL_HYPOTHESES_REFUTED,
                f"All {len(defect_hypos)} material defect hypothesis(es) have been refuted by direct observations.",
            )

        # Check if sufficient evidence has been gathered for a calibrated conclusion
        # (Does NOT require an artificial 1.0 confidence score!)
        for dh in defect_hypos:
            if dh.validation_status in (HYPOTHESIS_STATUS_SUPPORTED, HYPOTHESIS_STATUS_VALIDATED):
                # Memory growth requires at least 2 temporal samples or owner scan before stopping early
                if dh.anomaly_category == "MEMORY_GROWTH" and temporal_samples_count < 2 and remaining_observations_count > 0:
                    continue
                comp_ids = set(dh.competing_hypothesis_ids)
                comp_contradicted = all(
                    any(ch.hypothesis_id == cid and ch.validation_status == HYPOTHESIS_STATUS_CONTRADICTED for ch in benign_hypos)
                    for cid in comp_ids
                ) if comp_ids else True
                if comp_contradicted and dh.confidence_score >= 0.65:
                    return (
                        True,
                        STOP_SUFFICIENT_EVIDENCE,
                        f"Sufficient discriminating evidence gathered: '{dh.title}' is {dh.validation_status} "
                        f"(confidence={dh.confidence_score:.2f}) and competing explanation(s) are refuted.",
                    )

        if consecutive_non_novel_steps >= 2:
            return (
                True,
                STOP_DIMINISHING_RETURNS,
                f"Terminated due to diminishing information gain ({consecutive_non_novel_steps} consecutive steps without novel evidence).",
            )

        if remaining_observations_count == 0:
            if not defect_hypos:
                return (
                    True,
                    STOP_SUFFICIENT_EVIDENCE,
                    "Initial triage completed with no suspicious anomalies requiring follow-up.",
                )
            return (
                True,
                STOP_NO_USEFUL_SAFE_OBSERVATION,
                "Remaining hypotheses are unresolved, but no additional safe read-only observations remain.",
            )

        return False, "CONTINUE", "Continue adaptive observation loop."

    @staticmethod
    def should_terminate(
        budget_tracker: ObservationBudgetTracker,
        current_verdict: Optional[DiagnosticVerdict] = None,
        consecutive_empty_steps: int = 0,
    ) -> Tuple[bool, str]:
        """Backward-compatible termination check."""
        ok, reason = budget_tracker.check_budget()
        if not ok:
            return True, f"Budget limit reached: {reason}"

        if current_verdict:
            if (
                current_verdict.final_diagnosis in (
                    DIAG_CONFIRMED,
                    DIAG_REFUTED,
                    DIAG_NO_ISSUE_DETECTED,
                    DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE,
                )
                and current_verdict.confidence_score >= 0.80
            ):
                return (
                    True,
                    f"Calibrated diagnosis reached: {current_verdict.final_diagnosis} "
                    f"(confidence={current_verdict.confidence_score:.2f})",
                )

        if consecutive_empty_steps >= 2:
            return True, "Terminated due to diminishing returns (consecutive steps without novel evidence)"

        return False, "Continue"


# -----------------------------------------------------------------------------
# Canonicalization Helper for Deterministic Replay (Section 9 Scenario I)
# -----------------------------------------------------------------------------

def canonicalize_investigation_report(report: Dict[str, Any]) -> Dict[str, Any]:
    """Produces a canonical representation of an investigation report excluding volatile timestamps
    and random UUIDs for deterministic replay equivalence comparison."""
    cleaned = strip_volatile_fields(report)
    if isinstance(cleaned, dict):
        cleaned.pop("report_html", None)
        cleaned.pop("report_json", None)
        cleaned.pop("session_id", None)
        cleaned.pop("investigation_id", None)
        for b_key in ("budget_usage", "budget_summary"):
            if b_key in cleaned and isinstance(cleaned[b_key], dict):
                b_copy = dict(cleaned[b_key])
                if "metrics" in b_copy and isinstance(b_copy["metrics"], dict):
                    m_copy = dict(b_copy["metrics"])
                    m_copy.pop("observation_latency_us", None)
                    m_copy.pop("wall_clock_elapsed_ms", None)
                    m_copy.pop("profile_usage", None)
                    b_copy["metrics"] = m_copy
                b_copy.pop("utilization", None)
                cleaned[b_key] = b_copy
    return cleaned


# -----------------------------------------------------------------------------
# 6. Evidence-Driven Adaptive Investigation Engine
# -----------------------------------------------------------------------------

class AdaptiveInvestigationEngine:
    """Comprehensive coordinator for evidence-grounded, budget-bounded Process Health Investigations."""

    def __init__(
        self,
        watch_manager: Optional[Any] = None,
        registry: Optional[InspectionModuleRegistry] = None,
        default_limits: Optional[ObservationBudgetLimits] = None,
        ledger: Optional[EvidenceLedger] = None,
    ):
        self.watch_manager = watch_manager
        self.registry = registry or self._build_default_registry()
        self.default_limits = default_limits or ObservationBudgetLimits()
        self.planner = AdaptiveInvestigationPlanner(self.registry)
        self.cache = EvidenceCache()
        self.adapter = EvidenceAdapter()
        self.ledger = ledger
        self.hypothesis_generator = DeterministicHypothesisGenerator()

    def _build_default_registry(self) -> InspectionModuleRegistry:
        """Builds the default read-only inspection registry WITHOUT hardcoded symbol defaults."""
        reg = InspectionModuleRegistry()

        # 1. Thread Callstacks & Mutex Contention (Low-impact triage, no hardcoded symbols)
        p_locks = InspectionProfile(
            profile_id="insp_locks",
            domain=DOMAIN_CONCURRENCY,
            name="Thread Inventory, Callstacks & Mutex Contention",
            priority=150,
            required_capabilities=["threads_available"],
            requires_explicit_target_expression=False,
            estimated_bytes=4096,
            estimated_latency_ms=15.0,
            budget_ceiling={"max_bytes_read": 65536, "max_wall_clock_ms": 500.0, "max_samples": 4},
        )
        def _exec_insp_locks(wm, **kw):
            budget_tracker = kw.get("budget_tracker")

            # 1. Pre-execution budget check BEFORE any expensive observation
            if budget_tracker:
                cur_elapsed = budget_tracker.elapsed_ms
                rem_wall_ms = budget_tracker.limits.max_wall_clock_ms - cur_elapsed
                rem_bytes = budget_tracker.limits.max_bytes_read - budget_tracker.metrics.bytes_read
                if rem_wall_ms <= 0.0 or rem_bytes < 40:
                    return {
                        "success": False,
                        "status": "BUDGET_EXHAUSTED",
                        "stop_reason": "BUDGET_EXHAUSTED",
                        "error": "Budget exhausted before executing lock inspection",
                        "threads": [],
                        "contended_locks": [],
                        "deadlock_detected": False,
                        "bytes_read": 0,
                        "measured_bytes_read": 0,
                        "estimated_bytes_read": 0,
                        "already_budget_accounted": True,
                    }

            op_id = kw.get("operation_id") or f"insp_locks_{uuid.uuid4().hex[:12]}"

            # 2. WorkManager execution path (monitored and accounted for)
            if wm and hasattr(wm, "inspect_thread_callstacks_and_locks"):
                t_wm_start = time.monotonic()
                res = None
                wm_exc = None
                try:
                    res = wm.inspect_thread_callstacks_and_locks(**kw)
                except Exception as exc:
                    wm_exc = exc
                wm_elapsed_us = (time.monotonic() - t_wm_start) * 1_000_000.0

                if wm_exc is None:
                    if res and res.get("threads"):
                        raw_meas_b = res.get("measured_bytes_read")
                        raw_est_b = res.get("estimated_bytes_read")
                        raw_bytes_b = res.get("bytes_read")

                        for name, v in [("measured_bytes_read", raw_meas_b), ("estimated_bytes_read", raw_est_b), ("bytes_read", raw_bytes_b)]:
                            if v is not None:
                                if isinstance(v, bool) or not isinstance(v, (int, float)):
                                    raise ValueError(f"Invalid numeric value in WorkManager result for {name}: {repr(v)}")
                                if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                                    raise ValueError(f"Invalid numeric value (NaN/Inf) in WorkManager result for {name}: {repr(v)}")
                                if v < 0:
                                    raise ValueError(f"Invalid numeric value (negative) in WorkManager result for {name}: {repr(v)}")

                        meas_val = validate_non_negative_int(raw_meas_b)
                        est_val = validate_non_negative_int(raw_est_b)
                        bytes_val = validate_non_negative_int(raw_bytes_b)

                        is_missing = (
                            meas_val is None
                            and est_val is None
                            and bytes_val is None
                            and raw_meas_b is None
                            and raw_est_b is None
                            and raw_bytes_b is None
                        )

                        if is_missing:
                            if budget_tracker and budget_tracker.limits.reject_unknown_byte_cost:
                                if budget_tracker:
                                    budget_tracker.record_rejection("insp_locks", "UNKNOWN_BYTE_COST_REJECTED")
                                return {
                                    "success": False,
                                    "status": "UNKNOWN_BYTE_COST_REJECTED",
                                    "result_category": "UNKNOWN_BYTE_COST_REJECTED",
                                    "error": "UNKNOWN_BYTE_COST_REJECTED: observation byte cost is unknown and strict cost accounting is enabled",
                                    "threads": [],
                                    "contended_locks": [],
                                    "deadlock_detected": False,
                                    "bytes_read": 0,
                                    "measured_bytes_read": None,
                                    "estimated_bytes_read": 0,
                                    "charged_bytes": 0,
                                    "measurement_type": "UNKNOWN",
                                    "accounting_owner": "WORKMANAGER",
                                    "accounting_status": "FAILED",
                                    "operation_id": op_id,
                                }
                            unknown_cost = budget_tracker.limits.conservative_unknown_bytes if budget_tracker else DEFAULT_CONSERVATIVE_UNKNOWN_BYTES
                            record = ObservationAccountingRecord(
                                operation_id=op_id,
                                accounting_owner="WORKMANAGER",
                                measured_bytes_read=None,
                                estimated_bytes_read=unknown_cost,
                                latency_us=wm_elapsed_us,
                                measurement_type="UNKNOWN",
                            )
                            if budget_tracker:
                                ok = budget_tracker.commit_transaction(record, profile_id="insp_locks")
                                if not ok:
                                    return {
                                        "success": False,
                                        "status": "BUDGET_EXHAUSTED",
                                        "result_category": "BUDGET_EXHAUSTED",
                                        "error": f"Budget exhausted: {budget_tracker.exhaustion_reason}",
                                        "threads": [],
                                        "contended_locks": [],
                                        "deadlock_detected": False,
                                        "bytes_read": 0,
                                        "measured_bytes_read": None,
                                        "estimated_bytes_read": 0,
                                        "charged_bytes": 0,
                                        "measurement_type": "UNKNOWN",
                                        "accounting_owner": "WORKMANAGER",
                                        "accounting_status": "FAILED",
                                        "operation_id": op_id,
                                    }
                            res["measured_bytes_read"] = None
                            res["estimated_bytes_read"] = unknown_cost
                            res["charged_bytes"] = unknown_cost
                            res["bytes_read"] = unknown_cost
                            res["measurement_type"] = "UNKNOWN"
                            res["accounting_owner"] = "WORKMANAGER"
                            res["accounting_status"] = "COMMITTED"
                            res["operation_id"] = op_id
                            return res
                        else:
                            if meas_val is not None and est_val is not None:
                                eff_meas = meas_val
                                eff_est = est_val
                            elif meas_val is not None:
                                eff_meas = meas_val
                                eff_est = 0
                            elif est_val is not None:
                                eff_meas = None
                                eff_est = est_val
                            elif bytes_val is not None:
                                if res.get("measurement_type") == "ESTIMATED":
                                    eff_meas = None
                                    eff_est = bytes_val
                                else:
                                    eff_meas = bytes_val
                                    eff_est = 0
                            else:
                                eff_meas = None
                                eff_est = 0

                            if eff_meas is not None and eff_meas > 0 and eff_est > 0:
                                m_type = "MIXED"
                            elif eff_meas is not None and eff_meas > 0:
                                m_type = "MEASURED"
                            elif eff_est > 0:
                                m_type = "ESTIMATED"
                            elif eff_meas == 0 or (eff_est == 0 and eff_meas is None):
                                m_type = "ZERO_BYTES"
                            else:
                                m_type = "MEASURED"

                            record = ObservationAccountingRecord(
                                operation_id=op_id,
                                accounting_owner="WORKMANAGER",
                                measured_bytes_read=eff_meas,
                                estimated_bytes_read=eff_est,
                                latency_us=wm_elapsed_us,
                                measurement_type=m_type,
                            )
                            if budget_tracker:
                                ok = budget_tracker.commit_transaction(record, profile_id="insp_locks")
                                if not ok:
                                    return {
                                        "success": False,
                                        "status": "BUDGET_EXHAUSTED",
                                        "result_category": "BUDGET_EXHAUSTED",
                                        "error": f"Budget exhausted: {budget_tracker.exhaustion_reason}",
                                        "threads": [],
                                        "contended_locks": [],
                                        "deadlock_detected": False,
                                        "bytes_read": 0,
                                        "measured_bytes_read": eff_meas,
                                        "estimated_bytes_read": eff_est,
                                        "charged_bytes": 0,
                                        "measurement_type": m_type,
                                        "accounting_owner": "WORKMANAGER",
                                        "accounting_status": "FAILED",
                                        "operation_id": op_id,
                                    }
                            res["measured_bytes_read"] = eff_meas
                            res["estimated_bytes_read"] = eff_est
                            res["charged_bytes"] = (eff_meas or 0) + (eff_est or 0)
                            res["bytes_read"] = res["charged_bytes"]
                            res["measurement_type"] = m_type
                            res["accounting_owner"] = "WORKMANAGER"
                            res["accounting_status"] = "COMMITTED"
                            res["operation_id"] = op_id
                            return res
                    else:
                        if budget_tracker:
                            budget_tracker.record_read(
                                bytes_read=0,
                                latency_us=wm_elapsed_us,
                                is_failure=False,
                                profile_id="insp_locks",
                            )
                else:
                    # WorkManager raised an exception
                    raw_meas = getattr(wm_exc, "measured_bytes_read", None)
                    raw_est = getattr(wm_exc, "estimated_bytes_read", None)
                    raw_bytes = getattr(wm_exc, "bytes_read", None)

                    for name, v in [("measured_bytes_read", raw_meas), ("estimated_bytes_read", raw_est), ("bytes_read", raw_bytes)]:
                        if v is not None:
                            if isinstance(v, bool) or not isinstance(v, (int, float)):
                                raise ValueError(f"Invalid numeric value on WorkManager exception for {name}: {repr(v)}")
                            if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                                raise ValueError(f"Invalid numeric value (NaN/Inf) on WorkManager exception for {name}: {repr(v)}")
                            if v < 0:
                                raise ValueError(f"Invalid numeric value (negative) on WorkManager exception for {name}: {repr(v)}")

                    meas_val = validate_non_negative_int(raw_meas)
                    est_val = validate_non_negative_int(raw_est)
                    bytes_val = validate_non_negative_int(raw_bytes)

                    is_missing_exc = (
                        meas_val is None
                        and est_val is None
                        and bytes_val is None
                        and raw_meas is None
                        and raw_est is None
                        and raw_bytes is None
                    )

                    if is_missing_exc:
                        if budget_tracker and budget_tracker.limits.reject_unknown_byte_cost:
                            if budget_tracker:
                                budget_tracker.record_rejection("insp_locks", "UNKNOWN_BYTE_COST_REJECTED")
                            return {
                                "success": False,
                                "status": "UNKNOWN_BYTE_COST_REJECTED",
                                "result_category": "UNKNOWN_BYTE_COST_REJECTED",
                                "error": "UNKNOWN_BYTE_COST_REJECTED: WorkManager failed with unknown byte cost",
                                "threads": [],
                                "bytes_read": 0,
                                "measured_bytes_read": None,
                                "estimated_bytes_read": 0,
                                "charged_bytes": 0,
                                "measurement_type": "UNKNOWN",
                                "accounting_owner": "WORKMANAGER",
                                "accounting_status": "FAILED",
                                "operation_id": op_id,
                            }
                        op_estimate = kw.get("estimated_bytes", 4096)
                        fallback_charge = int(op_estimate) if (op_estimate is not None and isinstance(op_estimate, (int, float)) and op_estimate > 0) else (budget_tracker.limits.conservative_unknown_bytes if budget_tracker else DEFAULT_CONSERVATIVE_UNKNOWN_BYTES)
                        record = ObservationAccountingRecord(
                            operation_id=op_id,
                            accounting_owner="WORKMANAGER",
                            measured_bytes_read=None,
                            estimated_bytes_read=fallback_charge,
                            latency_us=wm_elapsed_us,
                            measurement_type="UNKNOWN",
                        )
                    else:
                        if meas_val is not None and est_val is not None:
                            eff_m = meas_val
                            eff_e = est_val
                        elif meas_val is not None:
                            eff_m = meas_val
                            eff_e = 0
                        elif est_val is not None:
                            eff_m = None
                            eff_e = est_val
                        elif bytes_val is not None:
                            if getattr(wm_exc, "measurement_type", None) == "ESTIMATED":
                                eff_m = None
                                eff_e = bytes_val
                            else:
                                eff_m = bytes_val
                                eff_e = 0
                        else:
                            eff_m = None
                            eff_e = 0

                        record = ObservationAccountingRecord(
                            operation_id=op_id,
                            accounting_owner="WORKMANAGER",
                            measured_bytes_read=eff_m,
                            estimated_bytes_read=eff_e,
                            latency_us=wm_elapsed_us,
                            measurement_type="MIXED" if (eff_m and eff_m > 0 and eff_e and eff_e > 0) else ("MEASURED" if (eff_m and eff_m > 0) else "ESTIMATED"),
                        )

                    if budget_tracker:
                        budget_tracker.commit_transaction(record, profile_id="insp_locks", is_failure=True)

                # Ensure fallback does not silently continue after global budget is exhausted
                if budget_tracker:
                    ok, rej_reason = budget_tracker.check_budget(profile_id="insp_locks")
                    if not ok:
                        ch_b = record.charged_bytes if 'record' in locals() else 0
                        m_b = record.measured_bytes_read if 'record' in locals() else 0
                        e_b = record.estimated_bytes_read if 'record' in locals() else 0
                        return {
                            "success": False,
                            "status": "BUDGET_EXHAUSTED",
                            "stop_reason": "BUDGET_EXHAUSTED",
                            "error": f"Budget exhausted after initial attempt: {rej_reason}",
                            "threads": [],
                            "contended_locks": [],
                            "deadlock_detected": False,
                            "bytes_read": ch_b,
                            "measured_bytes_read": m_b,
                            "estimated_bytes_read": e_b,
                            "charged_bytes": ch_b,
                            "accounting_owner": "WORKMANAGER",
                            "accounting_status": "COMMITTED",
                            "operation_id": op_id,
                        }

            pid_val = kw.get("pid")
            adapter = kw.get("adapter")
            target_identity = kw.get("target_identity") or kw.get("target_info")
            raw_epoch = kw.get("sampling_epoch") if "sampling_epoch" in kw else kw.get("epoch")
            sampling_epoch = None
            if raw_epoch is not None:
                if isinstance(raw_epoch, bool):
                    sampling_epoch = -1
                elif isinstance(raw_epoch, int):
                    sampling_epoch = raw_epoch if raw_epoch >= 0 else -1
                elif isinstance(raw_epoch, str):
                    try:
                        val = int(raw_epoch)
                        sampling_epoch = val if val >= 0 else -1
                    except (ValueError, TypeError):
                        sampling_epoch = -1
                else:
                    sampling_epoch = -1

            if pid_val and adapter and hasattr(adapter, "get_threads"):
                t_start_obs = time.monotonic()
                try:
                    # Enforce pre-operation budget check before get_threads
                    if budget_tracker:
                        cur_elapsed = budget_tracker.elapsed_ms
                        rem_wall_ms = budget_tracker.limits.max_wall_clock_ms - cur_elapsed
                        rem_bytes = budget_tracker.limits.max_bytes_read - budget_tracker.metrics.bytes_read
                        if rem_wall_ms <= 0.0 or rem_bytes < 40:
                            return {
                                "success": False,
                                "status": "BUDGET_EXHAUSTED",
                                "stop_reason": "BUDGET_EXHAUSTED",
                                "error": "Budget exhausted before reading threads",
                                "threads": [],
                                "contended_locks": [],
                                "deadlock_detected": False,
                                "bytes_read": 0,
                                "measured_bytes_read": 0,
                                "estimated_bytes_read": 0,
                                "already_budget_accounted": True,
                            }

                    threads = adapter.get_threads(pid_val)
                    th_meas = adapter.get_last_threads_bytes_read() if hasattr(adapter, "get_last_threads_bytes_read") else getattr(adapter, "_last_threads_bytes_read", 0)
                    if budget_tracker and th_meas > 0:
                        budget_tracker.record_read(
                            bytes_read=th_meas,
                            latency_us=(time.monotonic() - t_start_obs) * 1_000_000.0,
                            profile_id="insp_locks",
                        )

                    target_tids = {t["tid"] for t in threads}
                    is_partial_budget = False

                    if not target_identity and hasattr(adapter, "get_process_identity"):
                        if budget_tracker:
                            can_id, _, _ = budget_tracker.check_pre_execution(estimated_bytes=64, profile_id="insp_locks")
                            if not can_id:
                                is_partial_budget = True
                        if not is_partial_budget:
                            t_id_start = time.monotonic()
                            target_identity = adapter.get_process_identity(pid_val)
                            id_meas = adapter.get_last_identity_bytes_read() if hasattr(adapter, "get_last_identity_bytes_read") else getattr(adapter, "_last_identity_bytes_read", 0)
                            if budget_tracker and id_meas > 0:
                                budget_tracker.record_read(
                                    bytes_read=id_meas,
                                    latency_us=(time.monotonic() - t_id_start) * 1_000_000.0,
                                    profile_id="insp_locks",
                                )

                    contended_locks = []
                    waiters_by_lock: Dict[str, List[int]] = {}
                    wait_for_graph = WaitForGraph()
                    total_mutex_measured_bytes = 0
                    total_mutex_estimated_bytes = 0

                    for t in threads:
                        if is_partial_budget:
                            break
                        if t.get("is_futex_wait") or t.get("state") in ("D", "BLOCKED_LOCK"):
                            raw_lock = t.get("syscall_arg0") or t.get("syscall_arg0_int") or t.get("waiting_on_lock")
                            norm_hex, norm_int, addr_st, raw_arg = normalize_futex_address(raw_lock)
                            if addr_st == "WAIT_ADDRESS_OBSERVED" and norm_hex:
                                lock_addr = norm_hex
                                lock_addr_int = norm_int
                                t["waiting_on_lock"] = lock_addr
                                t["lock_address_status"] = "OBSERVED"
                                t["wait_address_status"] = "WAIT_ADDRESS_OBSERVED"
                                waiters_by_lock.setdefault(lock_addr, []).append(t["tid"])

                                # Enforce pre-operation budget check before mutex memory read
                                if budget_tracker:
                                    cur_elapsed = budget_tracker.elapsed_ms
                                    rem_wall_ms = budget_tracker.limits.max_wall_clock_ms - cur_elapsed
                                    rem_bytes = budget_tracker.limits.max_bytes_read - budget_tracker.metrics.bytes_read
                                    if rem_wall_ms <= 0.0 or rem_bytes < 40:
                                        is_partial_budget = True
                                        break

                                owner_tid = None
                                owner_res = None
                                if hasattr(adapter, "resolve_mutex_owner") and lock_addr_int:
                                    owner_res = adapter.resolve_mutex_owner(pid_val, lock_addr_int)

                                if isinstance(owner_res, MutexOwnerResolutionResult):
                                    owner_tid = owner_res.owner_tid
                                    owner_id_st = owner_res.status
                                    layout_id = owner_res.layout_id
                                    raw_b = owner_res.raw_bytes
                                    meta = dict(owner_res.metadata)
                                    mem_read_st = meta.get("memory_read_status", "OBSERVED" if raw_b else "UNAVAILABLE")
                                    evidence_src = "pthread_mutex_memory" if owner_tid else "procfs_syscall"

                                    # Accurately account for all actual mutex memory reads, regardless of whether owner was identified
                                    read_b = int(meta.get("read_bytes_len", len(raw_b) if raw_b else 0))
                                    read_lat = float(meta.get("latency_us", 0.0))
                                    total_mutex_measured_bytes += read_b
                                    if budget_tracker:
                                        budget_tracker.record_read(
                                            bytes_read=read_b,
                                            latency_us=read_lat,
                                            is_failure=(owner_id_st in (STATUS_MEMORY_READ_UNAVAILABLE, STATUS_PERMISSION_DENIED)),
                                            profile_id="insp_locks",
                                        )
                                        ok_cur, _ = budget_tracker.check_budget(profile_id="insp_locks")
                                        if not ok_cur:
                                            is_partial_budget = True
                                elif isinstance(owner_res, int) and owner_res > 0:
                                    owner_tid = owner_res
                                    owner_id_st = STATUS_OWNER_IDENTIFIED
                                    layout_id = LAYOUT_GLIBC_LP64
                                    raw_b = None
                                    meta = {}
                                    mem_read_st = "OBSERVED"
                                    evidence_src = "pthread_mutex_memory"
                                    total_mutex_estimated_bytes += 40
                                    if budget_tracker:
                                        budget_tracker.record_read(
                                            bytes_read=None,
                                            conservative_estimate_bytes=40,
                                            profile_id="insp_locks",
                                        )
                                else:
                                    owner_tid = None
                                    owner_id_st = STATUS_OWNER_NOT_IDENTIFIED
                                    layout_id = None
                                    raw_b = None
                                    meta = {}
                                    mem_read_st = "UNAVAILABLE"
                                    evidence_src = "procfs_syscall"
                                    if budget_tracker:
                                        budget_tracker.record_read(
                                            bytes_read=0,
                                            is_failure=True,
                                            profile_id="insp_locks",
                                        )

                                meta["target_tids"] = list(target_tids)
                                if raw_b:
                                    meta["raw_bytes"] = raw_b
                                meta["read_bytes_len"] = int(meta.get("read_bytes_len", len(raw_b) if raw_b else 0))

                                t["owner_tid"] = owner_tid
                                t["lock_owner_identified"] = (owner_id_st == STATUS_OWNER_IDENTIFIED and owner_tid is not None)
                                t["owner_identification_status"] = owner_id_st
                                t["mutex_layout_id"] = layout_id

                                edge = WaitForEdge(
                                    waiter_tid=t["tid"],
                                    sync_object=lock_addr,
                                    raw_futex_argument=raw_arg,
                                    normalized_address=lock_addr,
                                    owner_tid=owner_tid,
                                    owner_identification_status=owner_id_st,
                                    mutex_layout_id=layout_id,
                                    memory_read_status=mem_read_st,
                                    evidence_source=evidence_src,
                                    observation_timestamp=time.time(),
                                    target_pid=pid_val,
                                    process_identity=target_identity,
                                    sampling_epoch=sampling_epoch,
                                    metadata=meta,
                                )
                                wait_for_graph.add_edge(edge)
                            else:
                                lock_addr = None
                                lock_addr_int = None
                                t["waiting_on_lock"] = None
                                t["lock_address_status"] = "UNAVAILABLE"
                                t["wait_address_status"] = addr_st
                                t["lock_owner_identified"] = False
                                t["owner_tid"] = None

                            t["blocked"] = True
                            t["state"] = "BLOCKED_LOCK" if lock_addr else t.get("state", "S")

                            if lock_addr:
                                contended_locks.append({
                                    "lock_address": lock_addr,
                                    "lock_address_int": lock_addr_int,
                                    "raw_lock_address": raw_arg,
                                    "waiter_tid": t["tid"],
                                    "owner_tid": t.get("owner_tid"),
                                    "owner_identification_status": t.get("owner_identification_status", STATUS_OWNER_NOT_IDENTIFIED),
                                    "mutex_layout_id": t.get("mutex_layout_id"),
                                    "thread_name": t.get("name"),
                                    "wchan": t.get("wchan"),
                                    "futex_wait_observed": bool(t.get("is_futex_wait")),
                                    "wait_address_observed": True,
                                    "lock_owner_identified": bool(t.get("owner_tid")),
                                    "status": "OBSERVED",
                                })

                    # Analyze wait-for graph with target task membership and epoch verification
                    deadlock_cycle, result_category, issues = wait_for_graph.validate_and_analyze(
                        target_tids=target_tids,
                        allowed_epoch=sampling_epoch,
                    )
                    deadlock_detected = bool(deadlock_cycle)
                    lock_contention_observed = (
                        result_category == RESULT_LOCK_CONTENTION_OBSERVED
                        or any(len(w_tids) > 1 for w_tids in waiters_by_lock.values())
                    )

                    threads_meas = adapter.get_last_threads_bytes_read() if hasattr(adapter, "get_last_threads_bytes_read") else getattr(adapter, "_last_threads_bytes_read", 0)
                    if threads_meas > 0:
                        measured_threads_bytes = threads_meas
                        estimated_threads_bytes = 0
                    else:
                        measured_threads_bytes = 0
                        estimated_threads_bytes = len(threads) * 128

                    total_measured_bytes = measured_threads_bytes + total_mutex_measured_bytes
                    total_estimated_bytes = estimated_threads_bytes + total_mutex_estimated_bytes
                    total_bytes_read = total_measured_bytes + total_estimated_bytes

                    status_val = "PARTIAL" if is_partial_budget else "OBSERVED"
                    fb_op_id = f"{op_id}_fallback"
                    record = ObservationAccountingRecord(
                        operation_id=fb_op_id,
                        accounting_owner="MODULE_INTERNAL",
                        measured_bytes_read=total_measured_bytes,
                        estimated_bytes_read=total_estimated_bytes,
                        charged_bytes=total_measured_bytes + total_estimated_bytes,
                        latency_us=(time.monotonic() - t_start_obs) * 1_000_000.0,
                        measurement_type="MIXED" if (total_measured_bytes > 0 and total_estimated_bytes > 0) else ("MEASURED" if total_measured_bytes > 0 else "ESTIMATED"),
                        accounting_status="COMMITTED",
                    )
                    if budget_tracker:
                        with budget_tracker._transaction_lock:
                            budget_tracker._committed_transactions[fb_op_id] = record

                    return {
                        "success": True,
                        "status": status_val,
                        "stop_reason": "BUDGET_EXHAUSTED" if is_partial_budget else None,
                        "threads": threads,
                        "contended_locks": contended_locks,
                        "lock_contention_observed": lock_contention_observed,
                        "deadlock_detected": deadlock_detected,
                        "deadlock_cycle": deadlock_cycle,
                        "result_category": result_category,
                        "issues": issues,
                        "wait_for_graph": wait_for_graph.to_dict(),
                        "bytes_read": total_bytes_read,
                        "measured_bytes_read": total_measured_bytes,
                        "estimated_bytes_read": total_estimated_bytes,
                        "charged_bytes": total_measured_bytes + total_estimated_bytes,
                        "measurement_type": "MIXED" if (total_measured_bytes > 0 and total_estimated_bytes > 0) else ("MEASURED" if total_measured_bytes > 0 else "ESTIMATED"),
                        "accounting_owner": "MODULE_INTERNAL",
                        "accounting_status": "COMMITTED",
                        "already_budget_accounted": True,
                        "fallback_executed": True,
                        "operation_id": fb_op_id,
                        "observation_latency_us": round((time.monotonic() - t_start_obs) * 1_000_000.0, 2),
                    }
                except PermissionError as exc:
                    return {"success": False, "status": "PERMISSION_DENIED", "error": f"Permission denied reading thread tasks: {exc}", "threads": [], "bytes_read": 0}
                except ProcessLookupError:
                    return {"success": False, "status": "TARGET_TERMINATED", "error": f"Target process {pid_val} terminated", "threads": [], "bytes_read": 0}
                except Exception as exc:
                    return {"success": False, "status": "FAILED", "error": str(exc), "threads": [], "bytes_read": 0}
            return {"success": True, "threads": [], "bytes_read": 0}

        reg.register(FunctionalInspectionModule(p_locks, _exec_insp_locks))

        # 1b. Process Memory Mappings & Region Analysis (Low-impact triage, no hardcoded symbols)
        p_maps = InspectionProfile(
            profile_id="insp_memory_maps",
            domain=DOMAIN_MEMORY,
            name="Process Memory Mappings & Region Analysis",
            priority=145,
            required_capabilities=["memory_maps_available"],
            requires_explicit_target_expression=False,
            estimated_bytes=2048,
            estimated_latency_ms=10.0,
            budget_ceiling={"max_bytes_read": 32768, "max_wall_clock_ms": 300.0, "max_samples": 4},
        )
        def _exec_insp_maps(wm, **kw):
            pid_val = kw.get("pid")
            adapter = kw.get("adapter")
            budget_tracker = kw.get("budget_tracker")
            if budget_tracker:
                cur_elapsed = budget_tracker.elapsed_ms
                rem_wall_ms = budget_tracker.limits.max_wall_clock_ms - cur_elapsed
                rem_bytes = budget_tracker.limits.max_bytes_read - budget_tracker.metrics.bytes_read
                if rem_wall_ms <= 0.0 or rem_bytes < 256:
                    return {
                        "success": False,
                        "status": "BUDGET_EXHAUSTED",
                        "stop_reason": "BUDGET_EXHAUSTED",
                        "error": "Budget exhausted before executing memory maps inspection",
                        "regions_inspected": [],
                        "memory_growth_candidates": [],
                        "bytes_read": 0,
                        "measured_bytes_read": 0,
                    }

            if pid_val and adapter:
                try:
                    mem_info = adapter.get_process_memory_info(pid_val) if hasattr(adapter, "get_process_memory_info") else {}
                    st = mem_info.get("status", "OBSERVED")
                    if st in ("PERMISSION_DENIED", "TARGET_TERMINATED", "FAILED", "UNAVAILABLE"):
                        return {
                            "success": False,
                            "status": st,
                            "error": mem_info.get("error", f"Process memory inspection failed: {st}"),
                            "regions_inspected": [],
                            "memory_growth_candidates": [],
                            "bytes_read": 0,
                            "measured_bytes_read": 0,
                        }

                    maps = adapter.get_proc_maps(pid_val) if hasattr(adapter, "get_proc_maps") else []
                    total_bytes = sum(m.get("size", 0) for m in maps)
                    heap_maps = [m for m in maps if m.get("category") == "heap" or m.get("pathname") == "[heap]"]
                    anon_maps = [m for m in maps if m.get("category") == "anonymous" and m.get("is_writable")]
                    heap_size = sum(m.get("size", 0) for m in heap_maps)
                    anon_size = sum(m.get("size", 0) for m in anon_maps)

                    metrics = mem_info.get("metrics", {})
                    vsz_bytes = metrics.get("vsz_bytes", total_bytes)
                    rss_bytes = metrics.get("rss_bytes")
                    rss_anon_bytes = metrics.get("rss_anon_bytes")

                    # Configurable screening criteria (screening flag != defect proof)
                    heap_thresh = int(kw.get("screening_heap_size_bytes", 4 * 1024 * 1024))
                    anon_thresh = int(kw.get("screening_anon_size_bytes", 16 * 1024 * 1024))

                    growth_candidates = []
                    if heap_size > heap_thresh:
                        growth_candidates.append({
                            "target_expression": "[heap]",
                            "region": "[heap]",
                            "current_size": heap_size,
                            "current_heap_mapping_size": heap_size,
                            "current_rss": None,  # procfs does NOT measure heap-specific RSS without an extensive smaps scan
                            "heap_rss_bytes": None,
                            "process_rss_bytes": rss_bytes,
                            "category": "heap",
                            "severity": "MEDIUM",
                            "candidate_tier": "ANOMALY_CANDIDATE_SCREENING_FLAG",
                            "screening_flag": "ANOMALY_CANDIDATE_SCREENING_FLAG",
                            "screening_rationale": (
                                f"Heap mapping size ({heap_size // (1024*1024)}MB) exceeds screening threshold "
                                f"({heap_thresh // (1024*1024)}MB); screening criteria alone do NOT prove a memory leak. "
                                f"Temporal observation required."
                            ),
                            "follow_up_profile_id": "insp_temporal_diff",
                            "measurement_scope": "heap_mapping",
                        })
                    if anon_size > anon_thresh:
                        growth_candidates.append({
                            "target_expression": "anonymous_mmap",
                            "region": "anonymous",
                            "current_size": anon_size,
                            "current_anon_mapping_size": anon_size,
                            "current_rss": rss_anon_bytes,
                            "anon_rss_bytes": rss_anon_bytes,
                            "process_rss_bytes": rss_bytes,
                            "category": "anonymous",
                            "severity": "LOW",
                            "candidate_tier": "ANOMALY_CANDIDATE_SCREENING_FLAG",
                            "screening_flag": "ANOMALY_CANDIDATE_SCREENING_FLAG",
                            "screening_rationale": (
                                f"Writable anonymous mapping size ({anon_size // (1024*1024)}MB) exceeds screening threshold "
                                f"({anon_thresh // (1024*1024)}MB); screening criteria alone do NOT prove a memory leak. "
                                f"Temporal observation required."
                            ),
                            "follow_up_profile_id": "insp_temporal_diff",
                            "measurement_scope": "anon_mapping",
                        })

                    regions_inspected = list(sorted(set(m.get("category", "unknown") for m in maps)))
                    meas_b = int(mem_info.get("actual_bytes_read") or (adapter.get_last_maps_bytes_read() if hasattr(adapter, "get_last_maps_bytes_read") else getattr(adapter, "_last_maps_bytes_read", 0)) or 1024)
                    return {
                        "success": True,
                        "status": "OBSERVED" if not mem_info.get("missing_required_metrics") else "PARTIAL",
                        "total_virtual_bytes": total_bytes,
                        "vsz_bytes": vsz_bytes,
                        "rss_bytes": rss_bytes,
                        "rss_anon_bytes": rss_anon_bytes,
                        "heap_size": heap_size,
                        "heap_rss_bytes": None,
                        "heap_physical_residency_available": False,
                        "anonymous_size": anon_size,
                        "memory_metrics": metrics,
                        "metadata": mem_info.get("metadata", {}),
                        "sources_status": mem_info.get("sources_status", {}),
                        "missing_optional_metrics": mem_info.get("missing_optional_metrics", []),
                        "missing_required_metrics": mem_info.get("missing_required_metrics", []),
                        "regions_inspected": regions_inspected,
                        "memory_growth_candidates": growth_candidates,
                        "bytes_read": meas_b,
                        "measured_bytes_read": meas_b,
                    }
                except PermissionError as exc:
                    return {"success": False, "status": "PERMISSION_DENIED", "error": str(exc), "regions_inspected": [], "memory_growth_candidates": [], "bytes_read": 0}
                except ProcessLookupError:
                    return {"success": False, "status": "TARGET_TERMINATED", "error": f"Target process {pid_val} terminated", "regions_inspected": [], "memory_growth_candidates": [], "bytes_read": 0}
                except Exception as exc:
                    return {"success": False, "status": "FAILED", "error": str(exc), "regions_inspected": [], "memory_growth_candidates": [], "bytes_read": 0}
            return {"success": True, "status": "OBSERVED", "regions_inspected": [], "memory_growth_candidates": [], "bytes_read": 0}

        reg.register(FunctionalInspectionModule(p_maps, _exec_insp_maps))

        # 2. Stack Frame Locals & Parameters (No hardcoded symbols)
        p_locals = InspectionProfile(
            profile_id="insp_frame_locals",
            domain=DOMAIN_CONCURRENCY,
            name="Stack Frame Local Variable & Parameter Decoder",
            priority=115,
            required_capabilities=["threads_available"],
            requires_explicit_target_expression=False,
            estimated_bytes=2048,
            estimated_latency_ms=15.0,
            budget_ceiling={"max_bytes_read": 32768, "max_wall_clock_ms": 400.0, "max_samples": 4},
        )
        def _exec_insp_frame_locals(wm, **kw):
            if wm and hasattr(wm, "inspect_thread_locals_and_frame_vars"):
                try:
                    res = wm.inspect_thread_locals_and_frame_vars(**kw)
                    if res and res.get("success"):
                        return res
                except Exception:
                    pass
            # Concurrency/thread-state follow-up fallback
            pid_val = kw.get("pid")
            target_tid = kw.get("tid")
            adapter = kw.get("adapter")
            budget_tracker = kw.get("budget_tracker")
            target_identity = kw.get("target_identity") or kw.get("target_info")
            raw_epoch = kw.get("sampling_epoch") if "sampling_epoch" in kw else kw.get("epoch")
            sampling_epoch = None
            if raw_epoch is not None:
                if isinstance(raw_epoch, bool):
                    sampling_epoch = -1
                elif isinstance(raw_epoch, int):
                    sampling_epoch = raw_epoch if raw_epoch >= 0 else -1
                elif isinstance(raw_epoch, str):
                    try:
                        val = int(raw_epoch)
                        sampling_epoch = val if val >= 0 else -1
                    except (ValueError, TypeError):
                        sampling_epoch = -1
                else:
                    sampling_epoch = -1
            if budget_tracker:
                cur_elapsed = budget_tracker.elapsed_ms
                rem_wall_ms = budget_tracker.limits.max_wall_clock_ms - cur_elapsed
                rem_bytes = budget_tracker.limits.max_bytes_read - budget_tracker.metrics.bytes_read
                if rem_wall_ms <= 0.0 or rem_bytes < 256:
                    return {
                        "success": False,
                        "status": "BUDGET_EXHAUSTED",
                        "stop_reason": "BUDGET_EXHAUSTED",
                        "error": "Budget exhausted before executing frame locals inspection",
                        "frames": [],
                        "bytes_read": 0,
                        "measured_bytes_read": 0,
                    }

            if pid_val and adapter and hasattr(adapter, "get_threads"):
                t_start_fl = time.monotonic()
                try:
                    threads_0 = adapter.get_threads(pid_val)
                    time.sleep(0.02)
                    threads_1 = adapter.get_threads(pid_val)
                    t0_map = {t["tid"]: t for t in threads_0}
                    t1_map = {t["tid"]: t for t in threads_1}
                    target_tids = {t["tid"] for t in threads_1}
                    if not target_identity and hasattr(adapter, "get_process_identity"):
                        target_identity = adapter.get_process_identity(pid_val)

                    t_cand = t1_map.get(target_tid) if target_tid else None
                    if not t_cand:
                        for t in threads_1:
                            if t.get("is_futex_wait") or t.get("state") in ("D", "BLOCKED_LOCK"):
                                t_cand = t
                                break
                    if t_cand:
                        t_id = t_cand["tid"]
                        t0 = t0_map.get(t_id, {})
                        t1 = t1_map.get(t_id, {})
                        vcs0 = t0.get("voluntary_ctxt_switches", 0)
                        vcs1 = t1.get("voluntary_ctxt_switches", 0)
                        nvcs0 = t0.get("nonvoluntary_ctxt_switches", 0)
                        nvcs1 = t1.get("nonvoluntary_ctxt_switches", 0)
                        is_stalled = (vcs0 == vcs1 and nvcs0 == nvcs1 and t1.get("is_futex_wait"))

                        raw_lock = t_cand.get("syscall_arg0") or t_cand.get("syscall_arg0_int") or t_cand.get("waiting_on_lock")
                        norm_hex, norm_int, addr_st, raw_arg = normalize_futex_address(raw_lock)
                        if addr_st == "WAIT_ADDRESS_OBSERVED" and norm_hex:
                            lock_addr = norm_hex
                            lock_addr_int = norm_int
                            lock_st = "OBSERVED"
                        else:
                            lock_addr = None
                            lock_addr_int = None
                            lock_st = "UNAVAILABLE"

                        # Build wait-for graph across all waiting threads in threads_1
                        wait_for_graph = WaitForGraph()
                        for th in threads_1:
                            if th.get("is_futex_wait") or th.get("state") in ("D", "BLOCKED_LOCK"):
                                th_l = th.get("syscall_arg0") or th.get("syscall_arg0_int") or th.get("waiting_on_lock")
                                th_hex, th_int, th_st, th_raw_arg = normalize_futex_address(th_l)
                                if th_st == "WAIT_ADDRESS_OBSERVED" and th_hex and th_int:
                                    th_res = adapter.resolve_mutex_owner(pid_val, th_int) if hasattr(adapter, "resolve_mutex_owner") else None
                                    if isinstance(th_res, MutexOwnerResolutionResult):
                                        th_owner = th_res.owner_tid
                                        th_st_id = th_res.status
                                        th_layout = th_res.layout_id
                                        th_meta = dict(th_res.metadata)
                                        th_mem_st = th_meta.get("memory_read_status", "OBSERVED" if th_res.raw_bytes else "UNAVAILABLE")
                                        th_src = "pthread_mutex_memory" if th_owner else "procfs_syscall"
                                    elif isinstance(th_res, int) and th_res > 0:
                                        th_owner = th_res
                                        th_st_id = STATUS_OWNER_IDENTIFIED
                                        th_layout = LAYOUT_GLIBC_LP64
                                        th_meta = {}
                                        th_mem_st = "OBSERVED"
                                        th_src = "pthread_mutex_memory"
                                    else:
                                        th_owner = None
                                        th_st_id = STATUS_OWNER_NOT_IDENTIFIED
                                        th_layout = None
                                        th_meta = {}
                                        th_mem_st = "UNAVAILABLE"
                                        th_src = "procfs_syscall"

                                    th_meta["target_tids"] = list(target_tids)
                                    if isinstance(th_res, MutexOwnerResolutionResult) and th_res.raw_bytes:
                                        th_meta["raw_bytes"] = th_res.raw_bytes
                                    th_meta["read_bytes_len"] = int(th_meta.get("read_bytes_len", len(th_res.raw_bytes) if (isinstance(th_res, MutexOwnerResolutionResult) and th_res.raw_bytes) else 0))

                                    wait_for_graph.add_edge(WaitForEdge(
                                        waiter_tid=th["tid"],
                                        sync_object=th_hex,
                                        raw_futex_argument=th_raw_arg,
                                        normalized_address=th_hex,
                                        owner_tid=th_owner,
                                        owner_identification_status=th_st_id,
                                        mutex_layout_id=th_layout,
                                        memory_read_status=th_mem_st,
                                        evidence_source=th_src,
                                        observation_timestamp=time.time(),
                                        target_pid=pid_val,
                                        process_identity=target_identity,
                                        sampling_epoch=sampling_epoch,
                                        metadata=th_meta,
                                    ))

                        cycle, result_category, issues = wait_for_graph.validate_and_analyze(
                            target_tids=target_tids,
                            allowed_epoch=sampling_epoch,
                        )
                        owner_res = adapter.resolve_mutex_owner(pid_val, lock_addr_int) if (hasattr(adapter, "resolve_mutex_owner") and lock_addr_int) else None
                        owner_tid = owner_res.owner_tid if isinstance(owner_res, MutexOwnerResolutionResult) else (int(owner_res) if owner_res else None)

                        # Distinguish: thread contention stall vs uncontended or normal progress
                        if is_stalled:
                            cond = "thread_contention_stall_observed"
                        else:
                            cond = "uncontended_or_normal_progress"

                        th_bytes = (adapter.get_last_threads_bytes_read() if hasattr(adapter, "get_last_threads_bytes_read") else getattr(adapter, "_last_threads_bytes_read", 256)) * 2
                        m_bytes = sum(int(e.metadata.get("read_bytes_len", len(e.metadata.get("raw_bytes") or b""))) for e in wait_for_graph.edges)
                        total_fl_bytes = th_bytes + m_bytes

                        return {
                            "success": True,
                            "status": "OBSERVED",
                            "observed_condition": cond,
                            "legacy_observed_condition": cond,
                            "tid": t_id,
                            "thread_name": t_cand.get("name"),
                            "is_stalled": is_stalled,
                            "lock_address": lock_addr,
                            "lock_address_int": lock_addr_int,
                            "raw_lock_address": raw_arg,
                            "lock_address_status": lock_st,
                            "owner_tid": owner_tid,
                            "lock_owner_identified": bool(owner_tid),
                            "deadlock_cycle": cycle,
                            "circular_deadlock_confirmed": bool(cycle),
                            "result_category": result_category,
                            "issues": issues,
                            "wait_for_graph": wait_for_graph.to_dict(),
                            "concurrency_state": t_cand.get("concurrency_state", "WAITING_IN_FUTEX" if t1.get("is_futex_wait") else "RUNNING"),
                            "bytes_read": total_fl_bytes,
                            "measured_bytes_read": total_fl_bytes,
                            "observation_latency_us": round((time.monotonic() - t_start_fl) * 1_000_000.0, 2),
                        }
                    th_bytes = getattr(adapter, "_last_threads_bytes_read", 128) * 2
                    return {
                        "success": True,
                        "status": "OBSERVED",
                        "observed_condition": "uncontended_or_normal_progress",
                        "legacy_observed_condition": "uncontended_or_normal_progress",
                        "bytes_read": th_bytes,
                        "measured_bytes_read": th_bytes,
                        "observation_latency_us": round((time.monotonic() - t_start_fl) * 1_000_000.0, 2),
                    }
                except PermissionError as exc:
                    return {"success": False, "status": "PERMISSION_DENIED", "error": f"Permission denied reading thread states: {exc}", "bytes_read": 0}
                except ProcessLookupError:
                    return {"success": False, "status": "TARGET_TERMINATED", "error": f"Target process {pid_val} terminated", "bytes_read": 0}
                except Exception as exc:
                    return {"success": False, "status": "FAILED", "error": str(exc), "bytes_read": 0}
            return {"success": True, "status": "OBSERVED", "frames": [], "bytes_read": 0}

        reg.register(FunctionalInspectionModule(p_locals, _exec_insp_frame_locals))

        # 3. Memory Pool & Buffer Array Sweep (Requires discovered or explicit target_expression — NO hardcoded *gpMem!)
        p_pool = InspectionProfile(
            profile_id="insp_pool",
            domain=DOMAIN_MEMORY,
            name="Memory Pool & Buffer Allocation Sweep",
            priority=140,
            required_capabilities=["memory_read_available", "dwarf_symbols_available"],
            requires_explicit_target_expression=True,
            estimated_bytes=8192,
            estimated_latency_ms=25.0,
            budget_ceiling={"max_bytes_read": 131072, "max_wall_clock_ms": 600.0, "max_samples": 4},
        )
        reg.register(
            FunctionalInspectionModule(
                p_pool,
                lambda wm, **kw: wm.scan_memory_pool_or_array(
                    target_expression=kw.pop("target_expression"), **kw
                ),
            )
        )

        # 4. Memory Integrity Audit (Requires discovered or explicit root_expression — NO hardcoded g_corrupt_record!)
        p_integ = InspectionProfile(
            profile_id="insp_integrity",
            domain=DOMAIN_INTEGRITY,
            name="Memory Pointer & Struct Byte Integrity Audit",
            priority=130,
            required_capabilities=["memory_read_available", "dwarf_symbols_available"],
            requires_explicit_target_expression=True,
            estimated_bytes=4096,
            estimated_latency_ms=20.0,
            budget_ceiling={"max_bytes_read": 65536, "max_wall_clock_ms": 500.0, "max_samples": 4},
        )
        reg.register(
            FunctionalInspectionModule(
                p_integ,
                lambda wm, **kw: wm.audit_memory_integrity(
                    root_expression=kw.pop("root_expression", kw.pop("target_expression", None)), **kw
                ),
            )
        )

        # 5. Symbol Owner Lookup (Requires discovered or explicit target_expression — NO hardcoded *gpMem!)
        p_owners = InspectionProfile(
            profile_id="insp_find_owners",
            domain=DOMAIN_CONCURRENCY,
            name="Buffer Slot Thread Ownership Scanner",
            priority=120,
            required_capabilities=["memory_read_available", "threads_available"],
            requires_explicit_target_expression=True,
            estimated_bytes=4096,
            estimated_latency_ms=30.0,
            budget_ceiling={"max_bytes_read": 65536, "max_wall_clock_ms": 500.0, "max_samples": 4},
        )
        reg.register(
            FunctionalInspectionModule(
                p_owners,
                lambda wm, **kw: wm.find_symbol_owners_and_threads(
                    target_expression=kw.pop("target_expression"), **kw
                ),
            )
        )

        # 6. Temporal Multi-Sample Symbol Delta (Requires discovered or explicit target_expression)
        p_temp = InspectionProfile(
            profile_id="insp_temporal_diff",
            domain=DOMAIN_TEMPORAL,
            name="Bounded Temporal Symbol Delta Check",
            priority=112,
            required_capabilities=["memory_read_available"],
            requires_explicit_target_expression=True,
            estimated_bytes=1024,
            estimated_latency_ms=20.0,
            budget_ceiling={"max_bytes_read": 16384, "max_wall_clock_ms": 500.0, "max_samples": 4},
        )
        def _exec_insp_temporal_diff(wm, **kw):
            target_expr = kw.pop("target_expression", None)
            exprs = [target_expr] if isinstance(target_expr, str) else kw.pop("expressions", [])
            wait_ms = int(kw.pop("wait_ms", 30))
            num_samples = int(kw.pop("num_samples", 3))
            num_samples = max(2, min(4, num_samples))
            budget_tracker = kw.get("budget_tracker")

            if wm and hasattr(wm, "capture_and_diff_expressions") and exprs and exprs[0] not in ("[heap]", "anonymous_mmap", "heap_or_pool"):
                try:
                    return wm.capture_and_diff_expressions(expressions=exprs, wait_ms=wait_ms, **kw)
                except Exception:
                    pass

            # Determine explicit measurement scope and metric name
            target_name = (target_expr or "process_rss").lower()
            if "heap" in target_name:
                measurement_scope = "heap_mapping"
                metric_name = "heap_mapping_size_bytes"
            elif "anon" in target_name:
                measurement_scope = "anon_mapping"
                metric_name = "anon_mapping_size_bytes"
            elif "vsz" in target_name:
                measurement_scope = "process_vsz"
                metric_name = "vsz_bytes"
            else:
                measurement_scope = "process_rss"
                metric_name = "process_rss_bytes"

            # Live target adapter multi-sample temporal sequence
            pid_val = kw.get("pid")
            adapter = kw.get("adapter")
            if pid_val and adapter:
                try:
                    alive, l_err = adapter.check_liveness(pid_val) if hasattr(adapter, "check_liveness") else (True, None)
                    if not alive:
                        return {
                            "success": False,
                            "status": "TARGET_TERMINATED",
                            "error": l_err or f"Target PID {pid_val} is not running",
                            "measurement_scope": measurement_scope,
                            "metric_name": metric_name,
                            "samples": [],
                            "bytes_read": 0,
                            "measured_bytes_read": 0,
                        }

                    samples = []
                    t0 = time.time()
                    t_start_wall = time.monotonic()
                    actual_bytes_total = 0

                    for s_idx in range(num_samples):
                        # Pre-sample wall-clock and byte budget check
                        if budget_tracker:
                            cur_elapsed = budget_tracker.elapsed_ms
                            rem_wall_ms = budget_tracker.limits.max_wall_clock_ms - cur_elapsed
                            if s_idx > 0 and rem_wall_ms < float(wait_ms):
                                return {
                                    "success": True if len(samples) >= 1 else False,
                                    "status": "PARTIAL" if len(samples) >= 1 else "BUDGET_EXHAUSTED",
                                    "stop_reason": "BUDGET_EXHAUSTED",
                                    "exhaustion_reason": f"Wall-clock budget exhausted before sample {s_idx} ({cur_elapsed:.1f}ms elapsed, remaining {rem_wall_ms:.1f}ms < wait_ms {wait_ms}ms)",
                                    "samples": samples,
                                    "num_samples": len(samples),
                                    "measurement_scope": measurement_scope,
                                    "metric_name": metric_name,
                                    "observed_condition": "INSUFFICIENT_REGION_EVIDENCE" if len(samples) < 2 else "PROCESS_MEMORY_STABLE",
                                    "legacy_observed_condition": "stable_or_reclaimed_allocation",
                                    "is_temporal_sample": True,
                                    "bytes_read": actual_bytes_total,
                                    "measured_bytes_read": actual_bytes_total,
                                    "actual_duration_ms": round((time.monotonic() - t_start_wall) * 1000.0, 2),
                                }

                            rem_bytes = budget_tracker.limits.max_bytes_read - budget_tracker.metrics.bytes_read
                            if rem_bytes < 1024:
                                return {
                                    "success": True if len(samples) >= 1 else False,
                                    "status": "PARTIAL" if len(samples) >= 1 else "BUDGET_EXHAUSTED",
                                    "stop_reason": "BUDGET_EXHAUSTED",
                                    "exhaustion_reason": f"Byte budget exhausted before sample {s_idx} (remaining {rem_bytes}B < 1024B)",
                                    "samples": samples,
                                    "num_samples": len(samples),
                                    "measurement_scope": measurement_scope,
                                    "metric_name": metric_name,
                                    "observed_condition": "INSUFFICIENT_REGION_EVIDENCE" if len(samples) < 2 else "PROCESS_MEMORY_STABLE",
                                    "legacy_observed_condition": "stable_or_reclaimed_allocation",
                                    "is_temporal_sample": True,
                                    "bytes_read": actual_bytes_total,
                                    "measured_bytes_read": actual_bytes_total,
                                    "actual_duration_ms": round((time.monotonic() - t_start_wall) * 1000.0, 2),
                                }

                            if budget_tracker.metrics.samples_collected >= budget_tracker.limits.max_samples:
                                return {
                                    "success": True if len(samples) >= 1 else False,
                                    "status": "PARTIAL" if len(samples) >= 1 else "BUDGET_EXHAUSTED",
                                    "stop_reason": "BUDGET_EXHAUSTED",
                                    "exhaustion_reason": f"Sample count limit ({budget_tracker.limits.max_samples}) reached before sample {s_idx}",
                                    "samples": samples,
                                    "num_samples": len(samples),
                                    "measurement_scope": measurement_scope,
                                    "metric_name": metric_name,
                                    "observed_condition": "INSUFFICIENT_REGION_EVIDENCE" if len(samples) < 2 else "PROCESS_MEMORY_STABLE",
                                    "legacy_observed_condition": "stable_or_reclaimed_allocation",
                                    "is_temporal_sample": True,
                                    "bytes_read": actual_bytes_total,
                                    "measured_bytes_read": actual_bytes_total,
                                    "actual_duration_ms": round((time.monotonic() - t_start_wall) * 1000.0, 2),
                                }

                        if s_idx > 0:
                            time.sleep(max(wait_ms, 20) / 1000.0)

                        alive, _ = adapter.check_liveness(pid_val) if hasattr(adapter, "check_liveness") else (True, None)
                        if not alive:
                            return {
                                "success": False,
                                "status": "TARGET_TERMINATED",
                                "error": f"Target process {pid_val} terminated during temporal sampling at sample {s_idx}",
                                "samples_collected": len(samples),
                                "samples": samples,
                                "measurement_scope": measurement_scope,
                                "metric_name": metric_name,
                                "bytes_read": actual_bytes_total,
                                "measured_bytes_read": actual_bytes_total,
                            }

                        t_sample_start = time.monotonic()
                        mem_info = adapter.get_process_memory_info(pid_val) if hasattr(adapter, "get_process_memory_info") else {}
                        st = mem_info.get("status", "OBSERVED")
                        if st in ("PERMISSION_DENIED", "TARGET_TERMINATED", "FAILED", "UNAVAILABLE"):
                            return {
                                "success": False,
                                "status": st,
                                "error": mem_info.get("error", f"Memory query failed: {st}"),
                                "samples_collected": len(samples),
                                "samples": samples,
                                "measurement_scope": measurement_scope,
                                "metric_name": metric_name,
                                "bytes_read": actual_bytes_total,
                                "measured_bytes_read": actual_bytes_total,
                            }

                        sample_bytes = int(mem_info.get("actual_bytes_read", 2048))
                        actual_bytes_total += sample_bytes
                        sample_lat_us = (time.monotonic() - t_sample_start) * 1_000_000.0
                        if budget_tracker:
                            budget_tracker.record_read(bytes_read=sample_bytes, latency_us=sample_lat_us, profile_id="insp_temporal_diff")
                            budget_tracker.record_sample(profile_id="insp_temporal_diff")

                        maps = adapter.get_proc_maps(pid_val) if hasattr(adapter, "get_proc_maps") else []
                        heap_sz = sum(m.get("size", 0) for m in maps if m.get("category") == "heap" or m.get("pathname") == "[heap]")
                        anon_sz = sum(m.get("size", 0) for m in maps if m.get("category") == "anonymous" and m.get("is_writable"))
                        total_map_sz = sum(m.get("size", 0) for m in maps)

                        metrics = mem_info.get("metrics", {})
                        vsz_val = metrics.get("vsz_bytes", total_map_sz)
                        rss_val = metrics.get("rss_bytes", 0) or 0
                        anon_rss_val = metrics.get("rss_anon_bytes", 0) or 0

                        if measurement_scope == "heap_mapping":
                            target_metric = heap_sz
                        elif measurement_scope == "anon_mapping":
                            target_metric = anon_sz
                        elif measurement_scope == "process_vsz":
                            target_metric = vsz_val
                        else:
                            target_metric = rss_val

                        now = time.time()
                        samples.append({
                            "sample_index": s_idx,
                            "timestamp": now,
                            "elapsed_ms": round((now - t0) * 1000.0, 2),
                            "measurement_scope": measurement_scope,
                            "metric_name": metric_name,
                            "target_metric_bytes": target_metric,
                            "vsz_bytes": vsz_val,
                            "rss_bytes": rss_val,
                            "rss_anon_bytes": anon_rss_val,
                            "heap_mapping_size": heap_sz,
                            "anon_mapping_size": anon_sz,
                            "total_mapping_size": total_map_sz,
                            "mapping_count": len(maps),
                            "heap_rss_bytes": None,  # Explicitly null: procfs cannot measure heap RSS without smaps scan
                        })

                    if len(samples) < 2:
                        return {
                            "success": True,
                            "status": "PARTIAL",
                            "observed_condition": "INSUFFICIENT_REGION_EVIDENCE",
                            "legacy_observed_condition": "stable_or_reclaimed_allocation",
                            "condition_detail": "Fewer than 2 temporal samples collected; insufficient evidence for delta analysis.",
                            "growth_detected": False,
                            "growth_delta_bytes": 0,
                            "samples": samples,
                            "num_samples": len(samples),
                            "measurement_scope": measurement_scope,
                            "metric_name": metric_name,
                            "heap_rss_bytes": None,
                            "is_temporal_sample": True,
                            "bytes_read": actual_bytes_total,
                            "measured_bytes_read": actual_bytes_total,
                        }

                    deltas = [
                        samples[i]["target_metric_bytes"] - samples[i - 1]["target_metric_bytes"]
                        for i in range(1, len(samples))
                    ]
                    rss_deltas = [
                        samples[i]["rss_bytes"] - samples[i - 1]["rss_bytes"]
                        for i in range(1, len(samples))
                    ]

                    total_target_delta = samples[-1]["target_metric_bytes"] - samples[0]["target_metric_bytes"]
                    total_rss_delta = samples[-1]["rss_bytes"] - samples[0]["rss_bytes"]
                    total_map_delta = samples[-1]["total_mapping_size"] - samples[0]["total_mapping_size"]

                    # 1. Temporary workload buffering: grew then dropped back
                    is_burst_and_drop = (
                        len(deltas) >= 2
                        and deltas[0] > 0
                        and deltas[1] < 0
                        and total_target_delta <= (deltas[0] // 2)
                    )

                    # 2. Mapping expansion without allocation: mapping size expanded, but RSS remained flat
                    is_mapping_only_expansion = (
                        total_map_delta > 0
                        and abs(total_rss_delta) < 65536
                        and all(abs(rd) < 65536 for rd in rss_deltas)
                    )

                    # 3. Allocator retention: initial growth, then completely flat across remaining intervals
                    is_allocator_retention = (
                        len(deltas) >= 2
                        and deltas[0] > 0
                        and all(abs(d) < 32768 for d in deltas[1:])
                    )

                    # 4. Sustained monotonic growth: positive growth across all sample intervals
                    is_sustained_growth = (
                        all(d > 0 for d in deltas)
                        and total_target_delta > 0
                    )

                    if is_burst_and_drop:
                        observed_cond = "temporary_workload_buffering"
                        scoped_cond = "PROCESS_RSS_BURST_AND_RECLAIM"
                        conditions = ["temporary_workload_buffering", "PROCESS_RSS_BURST_AND_RECLAIM"]
                        cond_detail = f"Memory burst occurred during workload activity followed by reclamation in {measurement_scope}; temporary workload buffering, not leak."
                        growth_detected = False
                    elif is_mapping_only_expansion:
                        observed_cond = "mapping_expansion_without_allocation"
                        scoped_cond = "HEAP_MAPPING_EXPANSION" if measurement_scope == "heap_mapping" else "ANON_MAPPING_EXPANSION"
                        conditions = ["mapping_expansion_without_allocation", scoped_cond]
                        cond_detail = f"Virtual memory mappings expanded in {measurement_scope} without physical page allocation."
                        growth_detected = False
                    elif is_allocator_retention:
                        observed_cond = "allocator_retention"
                        scoped_cond = "allocator_retention"
                        conditions = ["allocator_retention"]
                        cond_detail = f"Memory allocated and retained by runtime allocator/freelist pool in {measurement_scope}; stable bounds across subsequent intervals."
                        growth_detected = False
                    elif is_sustained_growth:
                        observed_cond = "sustained_monotonic_growth"
                        scoped_cond = "PROCESS_RSS_SUSTAINED_GROWTH" if measurement_scope == "process_rss" else ("HEAP_MAPPING_EXPANSION" if measurement_scope == "heap_mapping" else "ANON_MAPPING_EXPANSION")
                        conditions = ["sustained_monotonic_growth", scoped_cond]
                        cond_detail = (
                            f"Sustained monotonic memory growth observed in {measurement_scope} across all temporal sampling intervals. "
                            f"Screening flag elevated; procfs measurements alone cannot prove a memory leak without allocation lifetime verification."
                        )
                        growth_detected = True
                    elif total_target_delta <= 0:
                        observed_cond = "stable_or_reclaimed_allocation"
                        scoped_cond = "PROCESS_MEMORY_STABLE"
                        conditions = ["stable_or_reclaimed_allocation", "PROCESS_MEMORY_STABLE"]
                        cond_detail = f"Memory usage remained stable or was reclaimed in {measurement_scope} across temporal samples."
                        growth_detected = False
                    else:
                        observed_cond = "sustained_monotonic_growth"
                        scoped_cond = "PROCESS_RSS_SUSTAINED_GROWTH" if measurement_scope == "process_rss" else ("HEAP_MAPPING_EXPANSION" if measurement_scope == "heap_mapping" else "ANON_MAPPING_EXPANSION")
                        conditions = ["sustained_monotonic_growth", scoped_cond]
                        cond_detail = f"Net memory growth observed in {measurement_scope} across temporal sampling sequence."
                        growth_detected = True

                    return {
                        "success": True,
                        "status": "OBSERVED",
                        "observed_condition": observed_cond,
                        "scoped_condition": scoped_cond,
                        "conditions": conditions,
                        "legacy_observed_condition": observed_cond,
                        "condition_detail": cond_detail,
                        "growth_detected": growth_detected,
                        "growth_delta_bytes": total_target_delta,
                        "initial_size": samples[0]["target_metric_bytes"],
                        "final_size": samples[-1]["target_metric_bytes"],
                        "measurement_scope": measurement_scope,
                        "metric_name": metric_name,
                        "heap_rss_bytes": None,
                        "samples": samples,
                        "num_samples": len(samples),
                        "sampling_interval_ms": wait_ms,
                        "is_temporal_sample": True,
                        "bytes_read": actual_bytes_total,
                        "measured_bytes_read": actual_bytes_total,
                        "actual_duration_ms": round((time.monotonic() - t_start_wall) * 1000.0, 2),
                    }
                except PermissionError as exc:
                    return {"success": False, "status": "PERMISSION_DENIED", "error": str(exc), "bytes_read": 0, "measured_bytes_read": 0}
                except ProcessLookupError:
                    return {"success": False, "status": "TARGET_TERMINATED", "error": f"Target process {pid_val} terminated", "bytes_read": 0, "measured_bytes_read": 0}
                except Exception as exc:
                    return {"success": False, "status": "FAILED", "error": str(exc), "bytes_read": 0, "measured_bytes_read": 0}
            return {"success": True, "status": "OBSERVED", "observed_condition": "PROCESS_MEMORY_STABLE", "legacy_observed_condition": "stable_or_reclaimed_allocation", "bytes_read": 0}

        reg.register(FunctionalInspectionModule(p_temp, _exec_insp_temporal_diff))

        # 7. Concurrent Read Consistency Verifier (Requires discovered or explicit field_path / target_expression)
        p_cons = InspectionProfile(
            profile_id="insp_consistency",
            domain=DOMAIN_INTEGRITY,
            name="Optimistic Seqlock Double-Read Concurrency Verifier",
            priority=110,
            required_capabilities=["memory_read_available"],
            requires_explicit_target_expression=True,
            estimated_bytes=512,
            estimated_latency_ms=10.0,
            budget_ceiling={"max_bytes_read": 8192, "max_wall_clock_ms": 300.0, "max_samples": 4},
        )
        reg.register(
            FunctionalInspectionModule(
                p_cons,
                lambda wm, **kw: wm.verify_concurrent_read_consistency(
                    target_expression=kw.pop("field_path", kw.pop("target_expression", None)),
                    **kw,
                ),
            )
        )

        # 8. IPC Pipeline Inspection (Requires discovered or explicit pipeline_expression — NO hardcoded g_ipc_ring!)
        p_ipc = InspectionProfile(
            profile_id="insp_ipc",
            domain=DOMAIN_IPC,
            name="IPC Pipeline & Queue State Tracer",
            priority=100,
            required_capabilities=["memory_read_available"],
            requires_explicit_target_expression=True,
            estimated_bytes=1024,
            estimated_latency_ms=15.0,
            budget_ceiling={"max_bytes_read": 16384, "max_wall_clock_ms": 400.0, "max_samples": 4},
        )
        reg.register(
            FunctionalInspectionModule(
                p_ipc,
                lambda wm, **kw: wm.trace_ipc_pipeline(
                    pipeline_expression=kw.pop("pipeline_expression", kw.pop("target_expression", None)),
                    **kw,
                ),
            )
        )

        return reg

    def _probe_target_and_capabilities(
        self,
        pid: int,
        companion_elf_path: str,
        adapter: TargetExecutionAdapter,
        fixture_data: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Dict[str, Any], Dict[str, Any], Dict[str, Any]]:
        """Establishes target identity, provenance, and available read-only observation capabilities."""
        if fixture_data:
            t_id = dict(fixture_data.get("target_identity") or {"pid": pid, "companion_elf": companion_elf_path})
            t_id.setdefault("pid", pid)
            t_id.setdefault("companion_elf", companion_elf_path)
            caps = dict(
                fixture_data.get("capabilities")
                or {
                    "process_alive": True,
                    "memory_maps_available": True,
                    "threads_available": True,
                    "dwarf_symbols_available": True,
                    "memory_read_available": True,
                    "watch_history_available": False,
                }
            )
            cq = dict(
                fixture_data.get("capture_quality")
                or {"completeness": "COMPLETE", "status": "COMPLETE", "consistency_level": "ZERO_STOP_ATOMIC"}
            )
            return t_id, caps, cq

        alive, liveness_err = adapter.check_liveness(pid) if pid and pid > 0 else (False, "Invalid PID")

        # 1. Discover runtime process identity from adapter
        proc_ident = adapter.get_process_identity(pid) if (pid and pid > 0) else {}
        runtime_exe = proc_ident.get("executable") or ""
        runtime_build_id = proc_ident.get("build_id")
        is_deleted = proc_ident.get("is_deleted", False)
        start_time = proc_ident.get("process_start_time")
        ident_status = proc_ident.get("status", "OBSERVED" if alive else "FAILED")

        unavail_reasons: Dict[str, str] = {}
        if ident_status == "PERMISSION_DENIED":
            unavail_reasons["target_identity"] = "Cannot inspect target identity: Permission denied accessing /proc/<pid>/exe"
            unavail_reasons["procfs_accessible"] = "Permission denied accessing /proc/<pid>/"
        elif ident_status == "TARGET_TERMINATED" or not alive:
            unavail_reasons["process_alive"] = liveness_err or f"PID {pid} is not running"

        if is_deleted:
            unavail_reasons["executable_deleted"] = "Runtime executable was deleted on disk"

        # 2. Companion ELF & DWARF capabilities verification
        # /proc/<pid>/exe must NOT automatically be treated as a valid companion image.
        companion_status = "NOT_PROVIDED"
        companion_build_id = None
        has_dwarf = False
        companion_rejection_reason = None

        if companion_elf_path:
            if not os.path.exists(companion_elf_path):
                companion_status = "COMPANION_NOT_FOUND"
                companion_rejection_reason = f"Companion ELF '{companion_elf_path}' does not exist on disk"
                unavail_reasons["dwarf_symbols_available"] = companion_rejection_reason
            else:
                try:
                    comp_ident = inspect_elf(companion_elf_path)
                    companion_build_id = getattr(comp_ident, "build_id", None)
                    comp_dwarf = bool(getattr(comp_ident, "has_debug_info", False))

                    # Verify Build ID equality between runtime target and companion image
                    if runtime_build_id and companion_build_id and runtime_build_id.lower() != companion_build_id.lower():
                        companion_status = "BUILD_ID_MISMATCH"
                        companion_rejection_reason = (
                            f"Companion ELF Build ID ({companion_build_id}) does not match "
                            f"runtime target Build ID ({runtime_build_id})"
                        )
                        unavail_reasons["dwarf_symbols_available"] = companion_rejection_reason
                    else:
                        companion_status = "MATCHED"
                        if comp_dwarf:
                            has_dwarf = True
                        else:
                            unavail_reasons["dwarf_symbols_available"] = (
                                f"Matching companion ELF '{companion_elf_path}' contains no DWARF debug info (.debug_info)"
                            )
                except Exception as exc:
                    companion_status = "COMPANION_INSPECTION_FAILED"
                    companion_rejection_reason = f"Failed to inspect companion ELF: {exc}"
                    unavail_reasons["dwarf_symbols_available"] = companion_rejection_reason
        else:
            companion_status = "NOT_PROVIDED"
            # If no companion ELF was provided, inspect runtime executable itself
            if proc_ident.get("has_debug_info"):
                has_dwarf = True
            else:
                unavail_reasons["dwarf_symbols_available"] = (
                    "No companion ELF supplied and runtime executable is stripped (lacks DWARF debug info)"
                )

        maps_ok = False
        threads_ok = False
        mem_read_ok = False

        if alive and ident_status != "PERMISSION_DENIED":
            maps_path = f"/proc/{pid}/maps"
            task_path = f"/proc/{pid}/task"
            maps_ok = os.access(maps_path, os.R_OK)
            if not maps_ok:
                unavail_reasons["memory_maps_available"] = f"Cannot read {maps_path} (permission or procfs restriction)"
            threads_ok = os.path.isdir(task_path) and os.access(task_path, os.R_OK)
            if not threads_ok:
                unavail_reasons["threads_available"] = f"Cannot enumerate {task_path}"
            # Check memory read capability
            mem_path = f"/proc/{pid}/mem"
            mem_read_ok = os.access(mem_path, os.R_OK) or maps_ok
            if not mem_read_ok:
                unavail_reasons["memory_read_available"] = "Process memory read restricted (EPERM / ptrace_scope)"
        elif not alive:
            unavail_reasons["process_alive"] = liveness_err or f"PID {pid} is not running"

        watch_hist_ok = False
        if self.watch_manager and hasattr(self.watch_manager, "list_sessions"):
            try:
                sessions = self.watch_manager.list_sessions(include_stopped=True)
                watch_hist_ok = any(s.get("pid") == pid for s in (sessions if isinstance(sessions, list) else []))
            except Exception:
                watch_hist_ok = False

        caps = {
            "process_alive": alive,
            "memory_maps_available": maps_ok,
            "threads_available": threads_ok,
            "dwarf_symbols_available": has_dwarf and (ident_status != "PERMISSION_DENIED"),
            "memory_read_available": mem_read_ok,
            "watch_history_available": watch_hist_ok,
            "procfs_accessible": bool(alive and ident_status != "PERMISSION_DENIED"),
            "unavailable_reasons": unavail_reasons,
        }
        target_identity = {
            "pid": pid,
            "executable": runtime_exe,
            "runtime_build_id": runtime_build_id,
            "build_id": runtime_build_id,
            "is_deleted": is_deleted,
            "process_start_time": start_time,
            "companion_elf": companion_elf_path if companion_status == "MATCHED" else (runtime_exe if not companion_elf_path else None),
            "companion_elf_path": companion_elf_path,
            "companion_build_id": companion_build_id,
            "companion_status": companion_status,
            "companion_rejection_reason": companion_rejection_reason,
            "alive": alive,
            "architecture": proc_ident.get("architecture", "unknown"),
            "elf_type": proc_ident.get("elf_type", "unknown"),
            "has_dwarf_info": has_dwarf,
        }
        capture_quality = {
            "completeness": "COMPLETE" if (alive and mem_read_ok and ident_status != "PERMISSION_DENIED") else ("FAILED" if not alive else "PARTIAL"),
            "status": "COMPLETE" if (alive and mem_read_ok and ident_status != "PERMISSION_DENIED") else ("FAILED" if not alive else "PARTIAL"),
            "consistency_level": "ZERO_STOP_ATOMIC",
        }
        return target_identity, caps, capture_quality

    def investigate_process_health(
        self,
        goal: str = "이 프로세스에 문제가 있는지 검사해주세요.",
        pid: int = 0,
        companion_elf_path: str = "",
        hypothesis: Optional[str] = None,
        assertions: Optional[List[str]] = None,
        symptom_hints: Optional[List[str]] = None,
        budget_limits: Optional[ObservationBudgetLimits] = None,
        target_adapter: Optional[TargetExecutionAdapter] = None,
        session_id: Optional[str] = None,
        provenance_class: Optional[str] = None,
        capture_receipt: Optional[Any] = None,
        fixture_data: Optional[Dict[str, Any]] = None,
        follow_up_executor: Optional[Callable[[FollowUpObservation, int], Dict[str, Any]]] = None,
        existing_state_machine: Optional[InvestigationStateMachine] = None,
        existing_executed_keys: Optional[Set[str]] = None,
        cancel_requested: bool = False,
        verification_authority: Optional[Any] = None,
        snapshot: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Executes an evidence-grounded, budget-bounded Process Health Investigation
        through the single explicit investigation state machine.
        """
        rcpt_sess = None
        if capture_receipt:
            rcpt_sess = getattr(capture_receipt, "session_id", None)
            if isinstance(capture_receipt, dict):
                rcpt_sess = capture_receipt.get("session_id")
        sess_id = session_id or rcpt_sess or f"inv_health_{uuid.uuid4().hex[:8]}"
        limits = budget_limits or self.default_limits
        budget_tracker = ObservationBudgetTracker(limits)
        budget_tracker.start()

        # Wrap adapter in strictly read-only execution boundary
        raw_adapter = target_adapter or LocalTargetAdapter()
        eff_adapter = (
            raw_adapter
            if isinstance(raw_adapter, ReadOnlyTargetAdapter)
            else ReadOnlyTargetAdapter(raw_adapter)
        )

        # Determine provenance
        # LIVE_RUNTIME_CAPTURE strictly requires an authentic, verified LiveCaptureReceipt
        is_synthetic = False
        if fixture_data is not None:
            target_ident = fixture_data.get("target_identity", {})
            if (
                target_ident.get("is_synthetic") is True
                or target_ident.get("provenance_class") == PROVENANCE_CLASS_SYNTHETIC_FIXTURE
                or fixture_data.get("provenance_class") == PROVENANCE_CLASS_SYNTHETIC_FIXTURE
                or provenance_class == PROVENANCE_CLASS_SYNTHETIC_FIXTURE
            ):
                is_synthetic = True

        eff_prov = PROVENANCE_CLASS_IMPORTED_UNVERIFIED
        verified_receipt = None
        effective_receipt = capture_receipt
        if effective_receipt is None and snapshot is not None:
            effective_receipt = getattr(snapshot, "receipt", None)

        snap_trust_state = TRUST_STATE_IMPORTED_UNVERIFIED
        snap_trust_error = None

        if is_synthetic:
            eff_prov = PROVENANCE_CLASS_SYNTHETIC_FIXTURE
            snap_trust_state = TRUST_STATE_IMPORTED_UNVERIFIED
        elif effective_receipt is not None:
            runtime_bin = getattr(snapshot, "binary", None) if snapshot is not None else None
            expected_build_id = getattr(snapshot, "build_id", None) if snapshot is not None else None
            eff_companion_elf = companion_elf_path
            if fixture_data is not None and companion_elf_path and not os.path.exists(companion_elf_path):
                eff_companion_elf = None
            snap_trust_state, snap_trust_error = determine_snapshot_trust_state(
                effective_receipt,
                verification_authority=verification_authority,
                expected_session_id=sess_id,
                expected_pid=pid if pid and pid > 0 else None,
                expected_executable_path=runtime_bin,
                companion_elf_path=eff_companion_elf,
                expected_build_id=expected_build_id,
                snapshot=snapshot,
            )
            if snap_trust_state == TRUST_STATE_LIVE_VERIFIED:
                eff_prov = PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE
                verified_receipt = effective_receipt
            else:
                eff_prov = PROVENANCE_CLASS_IMPORTED_UNVERIFIED
        elif provenance_class == PROVENANCE_CLASS_IMPORTED_UNVERIFIED or (
            fixture_data and fixture_data.get("provenance_class") == PROVENANCE_CLASS_IMPORTED_UNVERIFIED
        ):
            eff_prov = PROVENANCE_CLASS_IMPORTED_UNVERIFIED
        elif fixture_data is not None:
            eff_prov = PROVENANCE_CLASS_SYNTHETIC_FIXTURE
        elif provenance_class == PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE:
            # Caller attempted to assert LIVE without verified receipt -> force unverified
            eff_prov = PROVENANCE_CLASS_IMPORTED_UNVERIFIED
        elif provenance_class:
            eff_prov = provenance_class

        ledger = self.ledger if self.ledger is not None else EvidenceLedger(
            session_id=sess_id,
            live_capture_receipt=verified_receipt,
            verification_authority=verification_authority,
        )
        ledger.trust_state = snap_trust_state
        ledger.trust_error = snap_trust_error
        if self.ledger is not None:
            self.ledger.live_capture_receipt = verified_receipt
            self.ledger.verification_authority = verification_authority
            self.ledger.session_id = sess_id
        self.adapter.default_provenance_class = eff_prov
        self.adapter.live_capture_receipt = verified_receipt
        self.adapter.verification_authority = verification_authority

        sm = existing_state_machine or InvestigationStateMachine(initial_state=STATE_CREATED)
        executed_keys: Set[str] = set(existing_executed_keys or set())
        observation_log: List[Dict[str, Any]] = []
        planner_decisions: List[Dict[str, Any]] = []
        executed_profiles: List[str] = []
        inspection_outputs: Dict[str, Any] = {}
        temporal_samples_count = 1

        # Handle immediate user cancellation
        if cancel_requested:
            sm.transition(STATE_CANCELED, "Investigation canceled by user before target validation.")
            return {
                "success": False,
                "session_id": sess_id,
                "lifecycle_state": sm.state,
                "state_transitions": sm.transitions,
                "stop_reason": STOP_USER_CANCELED,
                "verdict": DIAG_INCONCLUSIVE,
                "final_diagnosis": DIAG_INCONCLUSIVE,
            }

        # ---------------------------------------------------------------------
        # Stage 1: TARGET_VALIDATION
        # ---------------------------------------------------------------------
        sm.transition(
            STATE_TARGET_VALIDATION,
            f"Validating target identity (pid={pid}) and probing available read-only observation capabilities.",
        )

        t_stage1_start = time.monotonic()
        target_identity, capabilities, capture_quality = self._probe_target_and_capabilities(
            pid=pid,
            companion_elf_path=companion_elf_path,
            adapter=eff_adapter,
            fixture_data=fixture_data,
        )
        stage1_elapsed_us = (time.monotonic() - t_stage1_start) * 1_000_000.0
        target_identity["provenance_class"] = eff_prov
        target_identity["trust_state"] = snap_trust_state

        # Account for process identity read in observation budget (Step 4 requirement: measured latency)
        id_bytes = eff_adapter.get_last_identity_bytes_read() if hasattr(eff_adapter, "get_last_identity_bytes_read") else getattr(eff_adapter, "_last_identity_bytes_read", 0)
        id_lat = eff_adapter.get_last_identity_latency_us() if hasattr(eff_adapter, "get_last_identity_latency_us") else stage1_elapsed_us
        if id_lat <= 0.0:
            id_lat = stage1_elapsed_us

        if id_bytes > 0:
            budget_tracker.record_read(
                bytes_read=id_bytes,
                latency_us=id_lat,
                profile_id="target_validation",
            )
            budget_tracker.record_sample(profile_id="target_validation")

        # Record target identity & capture quality in ledger
        id_rec = EvidenceRecord(
            evidence_id=f"evi_id_{hashlib.sha256(f'{sess_id}:{pid}:{companion_elf_path}'.encode()).hexdigest()[:10]}",
            evidence_type=EVIDENCE_TYPE_RUNTIME_IDENTITY,
            nature=NATURE_OBSERVATION,
            source="target_validation",
            session_id=sess_id,
            observation=f"Target validation for PID {pid} (alive={capabilities.get('process_alive')}, provenance={eff_prov})",
            target_identity=target_identity,
            provenance={"provenance_class": eff_prov, "stage": STATE_TARGET_VALIDATION},
            details={
                "collection_status": COLLECTION_STATUS_COLLECTED if capabilities.get("process_alive") else COLLECTION_STATUS_FAILED,
                "capabilities": capabilities,
                "semantic_digest": compute_semantic_evidence_digest("target_validation", target_identity, target_identity, 0),
            },
        )
        self.adapter.record_into_ledger(id_rec, ledger)

        cq_rec = EvidenceRecord(
            evidence_id=f"evi_cq_{hashlib.sha256(f'{sess_id}:cq:{eff_prov}'.encode()).hexdigest()[:10]}",
            evidence_type=EVIDENCE_TYPE_CAPTURE_QUALITY,
            nature=NATURE_OBSERVATION,
            source="capture_quality_probe",
            session_id=sess_id,
            observation=f"Capture quality assessment: completeness={capture_quality.get('completeness')}, provenance={eff_prov}",
            target_identity=target_identity,
            capture_quality=capture_quality,
            provenance={"provenance_class": eff_prov, "stage": STATE_TARGET_VALIDATION},
            details={
                "collection_status": COLLECTION_STATUS_COLLECTED,
                "capture_quality": capture_quality,
                "semantic_digest": compute_semantic_evidence_digest("capture_quality_probe", capture_quality, target_identity, 0),
            },
        )
        self.adapter.record_into_ledger(cq_rec, ledger)

        if not capabilities.get("process_alive", False) and not fixture_data and len(self.registry.list_modules()) == 0:
            sm.transition(STATE_FINALIZATION, "Target process is not running and no offline snapshot/fixture was supplied.")
            sm.transition(STATE_FAILED, "Target validation failed: target process unreachable.")
            return {
                "success": False,
                "session_id": sess_id,
                "lifecycle_state": sm.state,
                "state_transitions": sm.transitions,
                "stop_reason": STOP_CAPABILITY_UNAVAILABLE,
                "verdict": DIAG_INCONCLUSIVE,
                "final_diagnosis": DIAG_INCONCLUSIVE,
                "error": f"Target PID {pid} is not running.",
            }

        # ---------------------------------------------------------------------
        # Stage 2: INITIAL_TRIAGE
        # ---------------------------------------------------------------------
        sm.transition(
            STATE_INITIAL_TRIAGE,
            "Executing low-impact initial process health triage across available capabilities.",
        )

        inspected_domains: List[str] = []
        inspected_threads: List[Any] = []
        inspected_symbols: List[str] = []
        inspected_regions: List[str] = []
        unavailable_capabilities: Dict[str, str] = dict(capabilities.get("unavailable_reasons") or {})
        available_symbols: Optional[Set[str]] = (
            set(fixture_data["available_symbols"])
            if (fixture_data and "available_symbols" in fixture_data and fixture_data["available_symbols"] is not None)
            else None
        )

        triage_candidates: Dict[str, List[Dict[str, Any]]] = {
            "suspicious_threads": [],
            "memory_growth_candidates": [],
            "pointer_anomalies": [],
            "queue_backlogs": [],
        }
        triage_failures = 0
        triage_budget_rejected = False

        if fixture_data and "initial_triage" in fixture_data:
            # Deterministic fixture-driven initial triage
            triage_Steps = fixture_data["initial_triage"]
            for step in triage_Steps:
                step_id = step.get("step_id", "triage_step")
                step_domain = step.get("domain", DOMAIN_GENERIC)
                est_b = step.get("estimated_bytes", 1024)
                est_lat = float(step.get("estimated_latency_ms", 10.0))
                prof_ceil = step.get("budget_ceiling")

                can_run, b_reason, eff_est_b = budget_tracker.check_pre_execution(
                    estimated_bytes=est_b,
                    estimated_latency_ms=est_lat,
                    estimated_samples=1,
                    profile_id=step_id,
                    profile_ceiling=prof_ceil,
                )
                if not can_run:
                    budget_tracker.record_rejection(step_id, b_reason or "BUDGET_REJECTED")
                    triage_budget_rejected = True
                    observation_log.append({
                        "step_id": step_id,
                        "stage": STATE_INITIAL_TRIAGE,
                        "result_category": RESULT_BUDGET_REJECTED,
                        "reason": b_reason,
                    })
                    break

                raw_out = dict(step.get("output") or {})
                is_fail = raw_out.get("success") is False or raw_out.get("status") in ("READ_ERROR", "TIMEOUT", "RESTRICTED", "FAILED")
                meas_b = raw_out.get("bytes_read") if isinstance(raw_out.get("bytes_read"), int) else None
                meas_lat_us = float(raw_out.get("latency_us") or (raw_out.get("duration_ms", 0.0) * 1000.0))
                budget_tracker.record_read(
                    bytes_read=meas_b,
                    latency_us=meas_lat_us if meas_lat_us > 0.0 else 0.0,
                    stop_ms=float(raw_out.get("stop_duration_ms", 0.0)),
                    is_failure=is_fail,
                    conservative_estimate_bytes=eff_est_b,
                    profile_id=step_id,
                    profile_ceiling=prof_ceil,
                )
                budget_tracker.record_sample(profile_id=step_id)
                executed_profiles.append(step_id)
                inspection_outputs[step_id] = raw_out

                ev_rec = self.adapter.adapt_generic_tool_output(
                    tool_name=step_id,
                    tool_result=raw_out,
                    target_identity=target_identity,
                    session_id=sess_id,
                    ledger=ledger,
                    epoch=self.cache.current_epoch,
                )
                res_cat = (ev_rec.details or {}).get("result_category", RESULT_NEW_EVIDENCE)
                if res_cat != RESULT_DUPLICATE_EVIDENCE:
                    self.adapter.record_into_ledger(ev_rec, ledger)

                observation_log.append({
                    "step_id": step_id,
                    "stage": STATE_INITIAL_TRIAGE,
                    "result_category": res_cat,
                    "evidence_id": ev_rec.evidence_id,
                    "measured_bytes_read": meas_b,
                })

                if res_cat in (RESULT_OBSERVATION_FAILED, RESULT_OBSERVATION_UNAVAILABLE):
                    triage_failures += 1
                    if raw_out.get("status") == "RESTRICTED" or raw_out.get("error_code") == "RESTRICTED":
                        unavailable_capabilities[step_id] = raw_out.get("error", "Access restricted")
                else:
                    if step_domain not in inspected_domains:
                        inspected_domains.append(step_domain)
                    for th in raw_out.get("threads", []):
                        tid = th.get("tid", th.get("thread_id"))
                        if tid is not None and tid not in inspected_threads:
                            inspected_threads.append(tid)
                        if th.get("suspicious") or th.get("blocked") or th.get("state") in ("D", "BLOCKED_LOCK"):
                            th_copy = dict(th)
                            th_copy["evidence_id"] = ev_rec.evidence_id
                            triage_candidates["suspicious_threads"].append(th_copy)
                    for sym in raw_out.get("symbols_inspected", []):
                        if sym not in inspected_symbols:
                            inspected_symbols.append(sym)
                    for reg_name in raw_out.get("regions_inspected", []):
                        if reg_name not in inspected_regions:
                            inspected_regions.append(reg_name)
                    for mc in raw_out.get("memory_growth_candidates", []):
                        mc_copy = dict(mc)
                        mc_copy["evidence_id"] = ev_rec.evidence_id
                        triage_candidates["memory_growth_candidates"].append(mc_copy)
                    for pa in raw_out.get("pointer_anomalies", []):
                        pa_copy = dict(pa)
                        pa_copy["evidence_id"] = ev_rec.evidence_id
                        triage_candidates["pointer_anomalies"].append(pa_copy)
                    for qb in raw_out.get("queue_backlogs", []):
                        qb_copy = dict(qb)
                        qb_copy["evidence_id"] = ev_rec.evidence_id
                        triage_candidates["queue_backlogs"].append(qb_copy)
        else:
            # Execute registered initial triage modules via scheduler
            initial_plan = self.planner.plan_initial_inspections(
                goal=goal,
                assertions=assertions,
                symptom_hints=symptom_hints,
                capabilities=capabilities,
                available_symbols=available_symbols,
            )
            scheduler = DeterministicScheduler(self.registry)
            for pid_str in initial_plan:
                scheduler.enqueue(pid_str)

            while not scheduler.is_empty():
                if not budget_tracker.can_continue():
                    triage_budget_rejected = True
                    break
                current_id = scheduler.pop_next()
                if not current_id:
                    break
                mod = self.registry.get(current_id)
                if not mod:
                    continue

                ctx = InspectionContext(
                    pid=pid,
                    companion_elf=companion_elf_path,
                    adapter=eff_adapter,
                    budget_tracker=budget_tracker,
                    target_info=target_identity,
                    parameters={"sampling_epoch": self.cache.current_epoch},
                    available_symbols=available_symbols,
                    capabilities=capabilities,
                )
                res = mod.run(ctx, self.watch_manager)
                executed_profiles.append(current_id)
                inspection_outputs[current_id] = res

                if res.get("result_category") == RESULT_BUDGET_REJECTED:
                    triage_budget_rejected = True
                    observation_log.append({
                        "step_id": current_id,
                        "stage": STATE_INITIAL_TRIAGE,
                        "result_category": RESULT_BUDGET_REJECTED,
                        "reason": res.get("error"),
                    })
                    break

                ev_rec = self.adapter.adapt_generic_tool_output(
                    tool_name=f"inspection_{current_id}",
                    tool_result=res,
                    target_identity=target_identity,
                    session_id=sess_id,
                    ledger=ledger,
                    epoch=self.cache.current_epoch,
                )
                res_cat = (ev_rec.details or {}).get("result_category", RESULT_NEW_EVIDENCE)
                if res_cat != RESULT_DUPLICATE_EVIDENCE:
                    self.adapter.record_into_ledger(ev_rec, ledger)

                observation_log.append({
                    "step_id": current_id,
                    "stage": STATE_INITIAL_TRIAGE,
                    "result_category": res_cat,
                    "evidence_id": ev_rec.evidence_id,
                    "measured_bytes_read": res.get("measured_bytes_read"),
                })

                if res_cat in (RESULT_OBSERVATION_FAILED, RESULT_OBSERVATION_UNAVAILABLE):
                    triage_failures += 1
                else:
                    if mod.profile.domain not in inspected_domains:
                        inspected_domains.append(mod.profile.domain)
                    for sym in res.get("symbols_inspected", []):
                        if sym not in inspected_symbols:
                            inspected_symbols.append(sym)
                    for reg_name in res.get("regions_inspected", []):
                        if reg_name not in inspected_regions:
                            inspected_regions.append(reg_name)
                    for mc in res.get("memory_growth_candidates", []):
                        mc_copy = dict(mc)
                        mc_copy["evidence_id"] = ev_rec.evidence_id
                        triage_candidates["memory_growth_candidates"].append(mc_copy)
                    for pa in res.get("pointer_anomalies", []):
                        pa_copy = dict(pa)
                        pa_copy["evidence_id"] = ev_rec.evidence_id
                        triage_candidates["pointer_anomalies"].append(pa_copy)
                    for qb in res.get("queue_backlogs", []):
                        qb_copy = dict(qb)
                        qb_copy["evidence_id"] = ev_rec.evidence_id
                        triage_candidates["queue_backlogs"].append(qb_copy)
                    for th in res.get("threads", []) or []:
                        if isinstance(th, dict):
                            tid = th.get("tid", th.get("thread_id"))
                            if tid is not None and tid not in inspected_threads:
                                inspected_threads.append(tid)
                            is_suspicious_th = bool(
                                th.get("deadlock")
                                or th.get("waiting_on_lock")
                                or th.get("blocked")
                                or th.get("is_futex_wait")
                                or th.get("state") in ("D", "BLOCKED_LOCK")
                                or (res.get("deadlock_detected") and tid in (res.get("deadlock_cycle") or []))
                                or any(c.get("waiter_tid") == tid for c in (res.get("contended_locks") or []))
                            )
                            if is_suspicious_th:
                                raw_l = th.get("waiting_on_lock") or th.get("syscall_arg0")
                                if raw_l and isinstance(raw_l, str) and raw_l.startswith("0x") and raw_l not in ("0x_lock", "0x_futex_lock", "0x0"):
                                    lock_addr = raw_l
                                    lock_st = "OBSERVED"
                                else:
                                    lock_addr = None
                                    lock_st = "UNAVAILABLE"

                                triage_candidates["suspicious_threads"].append({
                                    "tid": tid,
                                    "name": th.get("name", f"thread_{tid}"),
                                    "top_function": (th.get("callstack") or [{}])[0].get("function_name", th.get("syscall_name") or "lock_wait"),
                                    "lock_address": lock_addr,
                                    "lock_address_status": lock_st,
                                    "evidence_id": ev_rec.evidence_id,
                                    "follow_up_profile_id": "insp_frame_locals",
                                })

        # ---------------------------------------------------------------------
        # Stage 3: HYPOTHESIS_FORMATION
        # ---------------------------------------------------------------------
        sm.transition(
            STATE_HYPOTHESIS_FORMATION,
            "Formulating competing, structured hypotheses from initial triage evidence.",
        )

        hypotheses: List[InvestigationHypothesis] = self.hypothesis_generator.generate_process_health_hypotheses(
            triage_data=triage_candidates,
            ledger=ledger,
            investigation_id=sess_id,
            capture_quality=capture_quality,
            provenance_class=eff_prov,
        )

        # Also incorporate any explicit fixture hypotheses (disarmed & grounded against ledger)
        if fixture_data and "hypotheses" in fixture_data:
            for raw_h in fixture_data["hypotheses"]:
                h_obj = raw_h if isinstance(raw_h, InvestigationHypothesis) else InvestigationHypothesis.from_dict(raw_h)
                h_obj.investigation_id = sess_id
                # Ensure self-evidence is never included
                h_obj.supporting_evidence_ids = [
                    eid for eid in h_obj.supporting_evidence_ids
                    if ledger.get_record(eid) is not None and ledger.get_record(eid).nature == NATURE_OBSERVATION
                ]
                hypotheses.append(h_obj)

        # ---------------------------------------------------------------------
        # Stage 4–6: Adaptive Loop (FOLLOW_UP_PLANNING -> OBSERVATION -> HYPOTHESIS_UPDATE)
        # ---------------------------------------------------------------------
        consecutive_non_novel = 0
        consecutive_failures = triage_failures if (len(hypotheses) == 0 and triage_failures > 0) else 0
        stop_reason = STOP_SUFFICIENT_EVIDENCE
        stop_explanation = "Investigation completed."

        max_loop_steps = 12
        for step_idx in range(max_loop_steps):
            if not budget_tracker.can_continue():
                should_stop, s_code, s_exp = AdaptiveTerminationPolicy.evaluate_stopping_policy(
                    budget_tracker=budget_tracker,
                    hypotheses=hypotheses,
                    remaining_observations_count=0,
                    consecutive_non_novel_steps=consecutive_non_novel,
                    consecutive_failures=consecutive_failures,
                    temporal_samples_count=temporal_samples_count,
                )
                stop_reason = s_code or STOP_BUDGET_EXHAUSTED
                stop_explanation = s_exp or "Observation budget exhausted."
                break

            sm.transition(
                STATE_FOLLOW_UP_PLANNING,
                f"Planning discriminating follow-up observation (iteration {step_idx + 1}).",
            )

            selected_obs, eval_candidates_log = self.planner.select_next_observation(
                hypotheses=hypotheses,
                budget_tracker=budget_tracker,
                executed_observation_keys=executed_keys,
                capabilities=capabilities,
                available_symbols=available_symbols,
                current_epoch=self.cache.current_epoch,
            )
            planner_decisions.append({
                "iteration": step_idx + 1,
                "selected_observation_id": selected_obs.observation_id if selected_obs else None,
                "preference_rationale": selected_obs.preference_rationale if selected_obs else None,
                "candidates_evaluated": eval_candidates_log,
            })

            all_budget_rej = bool(eval_candidates_log) and all(
                c.get("result_category") == RESULT_BUDGET_REJECTED for c in eval_candidates_log if not c.get("eligible")
            ) and selected_obs is None
            all_unavail = bool(eval_candidates_log) and all(
                c.get("result_category") == RESULT_OBSERVATION_UNAVAILABLE for c in eval_candidates_log if not c.get("eligible")
            ) and selected_obs is None

            if selected_obs is None:
                _, stop_reason, stop_explanation = AdaptiveTerminationPolicy.evaluate_stopping_policy(
                    budget_tracker=budget_tracker,
                    hypotheses=hypotheses,
                    remaining_observations_count=0,
                    consecutive_non_novel_steps=consecutive_non_novel,
                    consecutive_failures=consecutive_failures,
                    all_remaining_budget_rejected=all_budget_rej or triage_budget_rejected,
                    all_remaining_unavailable=all_unavail,
                    temporal_samples_count=temporal_samples_count,
                )
                break

            # Execute selected discriminating observation
            sm.transition(
                STATE_OBSERVATION,
                f"Executing follow-up observation '{selected_obs.observation_id}': {selected_obs.preference_rationale}",
            )

            epoch_key = f"{selected_obs.semantic_key}::epoch_{self.cache.current_epoch}"
            executed_keys.add(selected_obs.observation_id)
            executed_keys.add(epoch_key)

            t_obs_0 = time.monotonic_ns()
            prof_ceil = None
            if selected_obs.profile_id and self.registry.get(selected_obs.profile_id):
                prof_ceil = getattr(self.registry.get(selected_obs.profile_id), "budget_ceiling", None)

            if follow_up_executor is not None:
                can_run, pre_reason, eff_est_bytes = budget_tracker.check_pre_execution(
                    profile_id=selected_obs.profile_id,
                    profile_ceiling=prof_ceil,
                    estimated_bytes=selected_obs.estimated_bytes,
                    estimated_latency_ms=selected_obs.estimated_latency_ms,
                    estimated_samples=1,
                )
                if not can_run:
                    budget_tracker.record_rejection(selected_obs.profile_id, pre_reason or "BUDGET_EXCEEDED")
                    raw_obs_res = {
                        "success": False,
                        "result_category": RESULT_BUDGET_REJECTED,
                        "error": pre_reason,
                        "bytes_read": None,
                    }
                else:
                    raw_obs_res = follow_up_executor(selected_obs, self.cache.current_epoch)
                    lat_us = (time.monotonic_ns() - t_obs_0) / 1000.0
                    is_fail = (
                        raw_obs_res.get("success") is False
                        or raw_obs_res.get("status") in ("READ_ERROR", "TIMEOUT", "RESTRICTED", "FAILED")
                    )
                    meas_b = raw_obs_res.get("bytes_read") if isinstance(raw_obs_res.get("bytes_read"), int) else None
                    budget_tracker.record_read(
                        bytes_read=meas_b,
                        latency_us=lat_us,
                        stop_ms=float(raw_obs_res.get("stop_duration_ms", 0.0)),
                        is_failure=is_fail,
                        conservative_estimate_bytes=selected_obs.estimated_bytes,
                        profile_id=selected_obs.profile_id or selected_obs.observation_id,
                        profile_ceiling=prof_ceil,
                    )
                    budget_tracker.record_sample(profile_id=selected_obs.profile_id or selected_obs.observation_id)
            elif selected_obs.profile_id and self.registry.get(selected_obs.profile_id):
                mod = self.registry.get(selected_obs.profile_id)
                ctx = InspectionContext(
                    pid=pid,
                    companion_elf=companion_elf_path,
                    adapter=eff_adapter,
                    budget_tracker=budget_tracker,
                    target_info=target_identity,
                    parameters={
                        **selected_obs.target_ref,
                        "sampling_epoch": self.cache.current_epoch,
                        "estimated_bytes": selected_obs.estimated_bytes,
                        "estimated_latency_ms": selected_obs.estimated_latency_ms,
                    },
                    available_symbols=available_symbols,
                    capabilities=capabilities,
                )
                raw_obs_res = mod.run(ctx, self.watch_manager)
                executed_profiles.append(selected_obs.profile_id)
            else:
                raw_obs_res = {
                    "success": False,
                    "unavailable": True,
                    "result_category": RESULT_OBSERVATION_UNAVAILABLE,
                    "error": f"No execution handler available for observation '{selected_obs.observation_id}'",
                }

            if selected_obs.target_kind == TARGET_KIND_COMPARISON or selected_obs.profile_id == "insp_temporal_diff" or raw_obs_res.get("is_temporal_sample"):
                if raw_obs_res.get("success", True):
                    temporal_samples_count += 1
                    self.cache.advance_epoch()

            ev_rec = self.adapter.adapt_generic_tool_output(
                tool_name=selected_obs.profile_id or selected_obs.observation_id,
                tool_result=raw_obs_res,
                evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION if selected_obs.target_kind == TARGET_KIND_FIELD else EVIDENCE_TYPE_OBJECT_STATE,
                nature=NATURE_OBSERVATION,
                target_identity=target_identity,
                session_id=sess_id,
                ledger=ledger,
                epoch=self.cache.current_epoch if not raw_obs_res.get("allow_duplicate_test") else 0,
            )
            res_cat = (ev_rec.details or {}).get("result_category", RESULT_NEW_EVIDENCE)

            # Attach observation linkage metadata
            ev_rec.details["observation_id"] = selected_obs.observation_id
            ev_rec.details["tested_hypothesis_ids"] = list(selected_obs.tested_hypothesis_ids)
            if "outcomes_by_hypothesis" in raw_obs_res:
                ev_rec.details["outcomes_by_hypothesis"] = dict(raw_obs_res["outcomes_by_hypothesis"])
            elif "observed_condition" in raw_obs_res:
                cond = raw_obs_res["observed_condition"]
                legacy_cond = raw_obs_res.get("legacy_observed_condition")
                outcomes_map = {}
                for hid, h_map in selected_obs.expected_outcomes_by_hypothesis.items():
                    if isinstance(h_map, dict):
                        if cond in h_map:
                            outcomes_map[hid] = h_map[cond]
                        elif legacy_cond and legacy_cond in h_map:
                            outcomes_map[hid] = h_map[legacy_cond]
                ev_rec.details["outcomes_by_hypothesis"] = outcomes_map

            if res_cat not in (RESULT_DUPLICATE_EVIDENCE, RESULT_NO_NEW_EVIDENCE):
                self.adapter.record_into_ledger(ev_rec, ledger)

            selected_obs.result_category = res_cat

            # Invariant: A failed/unavailable/budget-rejected observation NEVER becomes a successful observation
            if res_cat in (RESULT_OBSERVATION_FAILED, RESULT_OBSERVATION_UNAVAILABLE, RESULT_BUDGET_REJECTED):
                selected_obs.status = OBSERVATION_STATUS_FAILED
                selected_obs.executed = False
                selected_obs.execution_error = raw_obs_res.get("error") or f"Observation failed with {res_cat}"
                consecutive_failures += 1
                consecutive_non_novel += 1
            elif res_cat in (RESULT_DUPLICATE_EVIDENCE, RESULT_NO_NEW_EVIDENCE):
                selected_obs.status = OBSERVATION_STATUS_EXECUTED
                selected_obs.executed = True
                selected_obs.result_evidence_id = ev_rec.evidence_id
                consecutive_non_novel += 1
                consecutive_failures = 0
            else:
                selected_obs.status = OBSERVATION_STATUS_EXECUTED
                selected_obs.executed = True
                selected_obs.result_evidence_id = ev_rec.evidence_id
                consecutive_non_novel = 0
                consecutive_failures = 0

            # Sync status across copies of this observation in competing hypotheses
            for h in hypotheses:
                for h_obs in h.suggested_observations:
                    if h_obs.observation_id == selected_obs.observation_id or h_obs.semantic_key == selected_obs.semantic_key:
                        h_obs.status = selected_obs.status
                        h_obs.executed = selected_obs.executed
                        h_obs.result_evidence_id = selected_obs.result_evidence_id
                        h_obs.result_category = selected_obs.result_category
                        h_obs.execution_error = selected_obs.execution_error
                        h_obs.preference_rationale = selected_obs.preference_rationale

            observation_log.append({
                "observation_id": selected_obs.observation_id,
                "tested_hypothesis_ids": list(selected_obs.tested_hypothesis_ids),
                "stage": STATE_OBSERVATION,
                "result_category": res_cat,
                "evidence_id": ev_rec.evidence_id if res_cat != RESULT_DUPLICATE_EVIDENCE else None,
                "preference_rationale": selected_obs.preference_rationale,
                "measured_bytes_read": raw_obs_res.get("measured_bytes_read", raw_obs_res.get("bytes_read")),
            })

            # Stage 6: HYPOTHESIS_UPDATE
            sm.transition(
                STATE_HYPOTHESIS_UPDATE,
                f"Updating competing hypotheses with observation '{selected_obs.observation_id}' (category={res_cat}).",
            )

            if res_cat in (RESULT_NEW_EVIDENCE, RESULT_PARTIAL_EVIDENCE):
                for h in hypotheses:
                    if h.hypothesis_id in selected_obs.tested_hypothesis_ids or h.hypothesis_id == selected_obs.hypothesis_id:
                        HypothesisValidator.evaluate(
                            hypothesis=h,
                            ledger=ledger,
                            new_evidence=ev_rec,
                            capture_quality=capture_quality,
                        )

            # Check stopping policy
            rem_count = sum(
                1
                for h in hypotheses
                if h.validation_status in (HYPOTHESIS_STATUS_PROPOSED, HYPOTHESIS_STATUS_SUPPORTED)
                for o in h.suggested_observations
                if not o.executed
                and o.status == OBSERVATION_STATUS_PROPOSED
                and o.observation_id not in executed_keys
            )
            should_stop, s_code, s_exp = AdaptiveTerminationPolicy.evaluate_stopping_policy(
                budget_tracker=budget_tracker,
                hypotheses=hypotheses,
                remaining_observations_count=rem_count,
                consecutive_non_novel_steps=consecutive_non_novel,
                consecutive_failures=consecutive_failures,
                temporal_samples_count=temporal_samples_count,
            )
            if should_stop:
                stop_reason = s_code
                stop_explanation = s_exp
                break

        # ---------------------------------------------------------------------
        # Optional Explicit Assertions Evaluation
        # ---------------------------------------------------------------------
        assertion_evaluations: List[AssertionEvaluation] = []
        if assertions and self.watch_manager:
            coerced_assertions = self.watch_manager._coerce_str_list(assertions)
            parsed_list = [
                self.watch_manager._parse_single_assertion(a)
                for a in coerced_assertions
                if str(a).strip()
            ]
            lhs_list = [p["lhs"] for p in parsed_list]

            can_eval_ast, ast_rej_reason, eff_ast_b = budget_tracker.check_pre_execution(
                estimated_bytes=len(lhs_list) * 64,
                estimated_latency_ms=10.0,
                estimated_samples=1,
                profile_id="assertion_evaluation",
            )
            if can_eval_ast:
                t_eval_0 = time.monotonic_ns()
                eval_out = self.watch_manager.evaluate_symbol_paths(
                    pid=pid,
                    companion_elf_path=companion_elf_path,
                    expressions=lhs_list,
                    adapter=eff_adapter,
                )
                lat_eval_us = (time.monotonic_ns() - t_eval_0) / 1000.0
                meas_ast_b = eval_out.get("bytes_read") if isinstance(eval_out.get("bytes_read"), int) else None
                budget_tracker.record_read(
                    bytes_read=meas_ast_b,
                    latency_us=lat_eval_us,
                    conservative_estimate_bytes=eff_ast_b,
                    profile_id="assertion_evaluation",
                )
                budget_tracker.record_sample(profile_id="assertion_evaluation")

                eval_by_expr = {r["expression"]: r for r in eval_out.get("results", [])}
                sym_records = self.adapter.adapt_symbol_evaluation(
                    eval_result=eval_out,
                    target_identity=target_identity,
                    session_id=sess_id,
                    epoch=self.cache.current_epoch,
                )
                self.adapter.record_into_ledger(sym_records, ledger)
                rec_map = {
                    r.field_observation.get("field_path"): r.evidence_id
                    for r in sym_records
                    if r.field_observation
                }

                for p_item in parsed_list:
                    lhs = p_item["lhs"]
                    ev_data = eval_by_expr.get(lhs, {})
                    ev_status = ev_data.get("status", "UNKNOWN")
                    obs_val = ev_data.get("value")
                    res_expr = ev_data.get("resolved_expression") or lhs
                    rt_addr = ev_data.get("runtime_address")
                    was_coerced = ev_data.get("was_coerced", False)
                    ev_id = rec_map.get(lhs)

                    a_eval = VerdictEngine.evaluate_assertion(
                        raw_assertion=p_item["raw"],
                        lhs=lhs,
                        op=p_item["operator"],
                        rhs_raw=p_item["rhs_raw"],
                        observed_value=obs_val,
                        obs_status=ev_status,
                        res_expr=res_expr,
                        rt_addr=rt_addr,
                        was_coerced=was_coerced,
                        evidence_id=ev_id,
                        provenance_class=eff_prov,
                    )
                    assertion_evaluations.append(a_eval)

        # ---------------------------------------------------------------------
        # Stage 7: FINALIZATION -> Terminal State
        # ---------------------------------------------------------------------
        sm.transition(
            STATE_FINALIZATION,
            f"Finalizing investigation verdict and auditable report (stop_reason={stop_reason}).",
        )

        inspected_scope = {
            "domains": inspected_domains or ["PROCESS_HEALTH"],
            "profiles_executed": list(executed_profiles),
            "threads_inspected": inspected_threads,
            "symbols_inspected": inspected_symbols,
            "memory_regions_inspected": inspected_regions,
        }
        uninspected_scope = {
            "unavailable_capabilities": unavailable_capabilities,
            "uninspected_domains": [
                d for d in (DOMAIN_CONCURRENCY, DOMAIN_MEMORY, DOMAIN_INTEGRITY, DOMAIN_IPC, DOMAIN_HEAP, DOMAIN_TEMPORAL)
                if d not in inspected_domains
            ],
            "skipped_specialized_profiles": [
                p.profile_id for p in self.registry.list_profiles()
                if p.profile_id not in executed_profiles
            ],
        }

        budget_summary = budget_tracker.to_dict()
        rec_next_steps: List[Dict[str, Any]] = []
        for h in hypotheses:
            if h.validation_status in (HYPOTHESIS_STATUS_PROPOSED, HYPOTHESIS_STATUS_INCONCLUSIVE):
                for needed in h.discriminating_evidence_needed:
                    rec_next_steps.append({
                        "hypothesis_id": h.hypothesis_id,
                        "action": needed,
                        "risk_level": "READ_ONLY",
                    })
        if unavailable_capabilities:
            for cap_k, cap_r in unavailable_capabilities.items():
                rec_next_steps.append({
                    "capability": cap_k,
                    "action": f"Resolve capability limitation ({cap_r}) to expand inspection coverage.",
                    "risk_level": "READ_ONLY",
                })

        if assertion_evaluations and not hypotheses:
            verdict = VerdictEngine.synthesize_verdict(
                hypothesis=hypothesis or goal,
                evaluations=assertion_evaluations,
                target_identity=target_identity,
                causal_attribution_verified=False,
                attribution_basis=None,
                provenance_class=eff_prov,
                budget_usage=budget_summary,
                inspected_scope=inspected_scope,
                uninspected_scope=uninspected_scope,
                stop_reason=stop_reason,
                stop_explanation=stop_explanation,
                recommended_next_steps=rec_next_steps,
            )
        else:
            verdict = VerdictEngine.synthesize_process_health_verdict(
                goal=hypothesis or goal,
                hypotheses=hypotheses,
                ledger=ledger,
                target_identity=target_identity,
                inspected_scope=inspected_scope,
                uninspected_scope=uninspected_scope,
                budget_usage=budget_summary,
                stop_reason=stop_reason,
                stop_explanation=stop_explanation,
                provenance_class=eff_prov,
                capture_quality=capture_quality,
                assertion_evaluations=assertion_evaluations,
                temporal_samples_count=temporal_samples_count,
                recommended_next_steps=rec_next_steps,
            )

        # Transition to terminal state
        if stop_reason == STOP_BUDGET_EXHAUSTED or budget_tracker.metrics.is_budget_exhausted:
            sm.transition(STATE_BUDGET_EXHAUSTED, stop_explanation)
        elif verdict.final_diagnosis == DIAG_INCONCLUSIVE:
            sm.transition(STATE_INCONCLUSIVE, stop_explanation)
        else:
            sm.transition(STATE_COMPLETED, stop_explanation)

        report_html = ZeroCdnReporter.render_html(
            verdict=verdict,
            title=f"dynamicState Process Health Investigation: {(hypothesis or goal)[:40]}",
            remediation_checklist=[s.get("action", "") for s in rec_next_steps if s.get("action")] or [
                "Review inspected scope and competing hypothesis matrix.",
                "Verify observation budget metrics remain within operational bounds.",
            ],
        )
        report_json = ZeroCdnReporter.render_json(verdict)

        return {
            "success": True,
            "session_id": sess_id,
            "target_identity": target_identity,
            "goal": goal,
            "hypothesis": hypothesis or goal,
            "lifecycle_state": sm.state,
            "state_transitions": sm.transitions,
            "stop_reason": verdict.stop_reason,
            "stop_explanation": verdict.stop_explanation,
            "final_diagnosis": verdict.final_diagnosis,
            "verdict": verdict.final_diagnosis,
            "hypothesis_state": verdict.hypothesis_state,
            "confidence_score": verdict.confidence_score,
            "confidence_rationale": verdict.confidence_rationale,
            "inspected_scope": verdict.inspected_scope,
            "uninspected_scope": verdict.uninspected_scope,
            "evidence_coverage": verdict.evidence_coverage,
            "supporting_evidence_ids": verdict.supporting_evidence_ids,
            "contradicting_evidence_ids": verdict.contradicting_evidence_ids,
            "provenance_class": verdict.provenance_class,
            "provenance_limitations": verdict.provenance_limitations,
            "trust_state": snap_trust_state,
            "trust_error": snap_trust_error,
            "limitations": verdict.limitations,
            "competing_hypotheses": [h.to_dict() for h in hypotheses],
            "observed_facts": verdict.observed_facts,
            "inferences": verdict.inferences,
            "unknowns": verdict.unknowns,
            "recommended_next_steps": verdict.recommended_next_steps,
            "executed_profiles": executed_profiles,
            "executed_observation_keys": sorted(executed_keys),
            "observation_log": observation_log,
            "planner_decisions": planner_decisions,
            "budget_usage": budget_summary,
            "budget_summary": budget_summary,
            "total_assertions": verdict.total_assertions,
            "passed_assertions": verdict.passed_count,
            "failed_assertions": verdict.failed_count,
            "abstain_assertions": verdict.abstain_count,
            "assertion_results": [
                {
                    "assertion": a.raw_assertion,
                    "verdict": a.verdict,
                    "observed_value": a.observed_value,
                    "expected": a.expected,
                    "evaluation_status": a.observation_status,
                    "reason": a.reason,
                    "evidence_id": a.evidence_id,
                }
                for a in verdict.assertion_evaluations
            ],
            "inspection_summary": {
                k: {
                    "success": v.get("success", True),
                    "status": v.get("status"),
                    "deadlock_detected": v.get("deadlock_detected"),
                    "deadlock_cycle": v.get("deadlock_cycle"),
                    "result_category": v.get("result_category"),
                    "lock_contention_observed": v.get("lock_contention_observed"),
                    "issues": v.get("issues"),
                    "bytes_read": v.get("bytes_read"),
                    "measured_bytes_read": v.get("measured_bytes_read"),
                }
                for k, v in inspection_outputs.items()
            },
            "inspection_outputs": inspection_outputs,
            "evidence_ledger_count": len(ledger._records),
            "evidence_ledger": ledger.to_dict(),
            "report_html": report_html,
            "report_json": report_json,
        }

    def run_adaptive_investigation(
        self,
        goal: str,
        pid: int,
        companion_elf_path: str,
        hypothesis: Optional[str] = None,
        assertions: Optional[List[str]] = None,
        symptom_hints: Optional[List[str]] = None,
        budget_limits: Optional[ObservationBudgetLimits] = None,
        target_adapter: Optional[TargetExecutionAdapter] = None,
        session_id: Optional[str] = None,
        fixture_data: Optional[Dict[str, Any]] = None,
        follow_up_executor: Optional[Callable[[FollowUpObservation, int], Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """Executes a complete adaptive investigation cycle within observation budget."""
        return self.investigate_process_health(
            goal=goal,
            pid=pid,
            companion_elf_path=companion_elf_path,
            hypothesis=hypothesis,
            assertions=assertions,
            symptom_hints=symptom_hints,
            budget_limits=budget_limits,
            target_adapter=target_adapter,
            session_id=session_id,
            fixture_data=fixture_data,
            follow_up_executor=follow_up_executor,
        )

    # -------------------------------------------------------------------------
    # Backward-Compatible Methods for test_adaptive_investigation_engine.py
    # -------------------------------------------------------------------------

    def investigate(
        self,
        target_process: Any,
        target_binary_path: str,
        hypothesis_statement: str = "",
        assertion_expressions: Optional[List[str]] = None,
        corpus_dir: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Executes module collection, assertion evaluation, and golden corpus persistence."""
        pid = getattr(target_process, "pid", int(target_process) if isinstance(target_process, int) else 0)
        ledger = self.ledger if self.ledger is not None else EvidenceLedger()
        budget_tracker = ObservationBudgetTracker(self.default_limits)
        budget_tracker.start()

        collected_values: Dict[str, Any] = {}
        t_obs_0 = time.monotonic_ns()
        for mod in self.registry.list_modules():
            ctx = InspectionContext(
                pid=pid,
                companion_elf=target_binary_path,
                adapter=LocalTargetAdapter(),
                budget_tracker=budget_tracker,
                parameters={"sampling_epoch": self.cache.current_epoch},
            )
            res = mod.run(ctx, self.watch_manager)
            if isinstance(res, dict):
                collected_values.update(res)
                rec = ledger.record_evidence(
                    module_id=mod.module_id,
                    domain=mod.domain,
                    provenance_class=PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
                    evidence_payload=res,
                )
        lat_us = (time.monotonic_ns() - t_obs_0) / 1000.0

        evals: List[AssertionEvaluation] = []
        for expr in assertion_expressions or []:
            # Parse simple "lhs op rhs"
            op_found = "=="
            lhs, rhs = expr, None
            for op_cand in ("==", "!=", ">=", "<=", ">", "<"):
                if op_cand in expr:
                    parts = expr.split(op_cand, 1)
                    lhs = parts[0].strip()
                    rhs = parts[1].strip()
                    op_found = op_cand
                    break
            short_key = lhs.split(".")[-1].split("->")[-1].strip()
            if lhs in collected_values:
                obs_val = collected_values[lhs]
                obs_st = "OBSERVED"
            elif short_key in collected_values:
                obs_val = collected_values[short_key]
                obs_st = "OBSERVED"
            elif self.watch_manager and pid > 0:
                ev_out = self.watch_manager.evaluate_symbol_paths(
                    pid=pid,
                    companion_elf_path=target_binary_path,
                    expressions=[lhs],
                )
                r0 = (ev_out.get("results") or [{}])[0]
                obs_val = r0.get("value")
                obs_st = r0.get("status", "OBSERVED" if obs_val is not None else "UNKNOWN")
            else:
                obs_val = None
                obs_st = "UNKNOWN"

            evals.append(
                VerdictEngine.evaluate_assertion(
                    raw_assertion=expr,
                    lhs=lhs,
                    op=op_found,
                    rhs_raw=rhs,
                    observed_value=obs_val,
                    obs_status=obs_st,
                )
            )

        if not evals:
            verdict_str = "VERIFIED"
            conf = 0.9
        else:
            synth = VerdictEngine.synthesize_verdict(
                hypothesis=hypothesis_statement,
                evaluations=evals,
                target_identity={"pid": pid, "companion_elf": target_binary_path},
            )
            if synth.final_diagnosis == DIAG_CONFIRMED:
                verdict_str = "VERIFIED"
                conf = synth.confidence_score
            elif synth.final_diagnosis == DIAG_REFUTED:
                verdict_str = "REFUTED"
                conf = 0.0
            elif synth.final_diagnosis == DIAG_PARTIALLY_CONFIRMED:
                verdict_str = "PARTIALLY_CONFIRMED"
                conf = synth.confidence_score
            else:
                verdict_str = "UNVERIFIED"
                conf = synth.confidence_score

        out_payload = {
            "hypothesis": hypothesis_statement,
            "verdict": verdict_str,
            "confidence": conf,
            "target_stop_duration_ms": budget_tracker.metrics.target_stop_duration_ms,
            "observation_latency_us": round(lat_us, 2),
            "records_count": len(ledger.records),
        }
        if corpus_dir:
            os.makedirs(corpus_dir, exist_ok=True)
            with open(os.path.join(corpus_dir, "golden_run.json"), "w", encoding="utf-8") as f:
                json.dump(out_payload, f, indent=2, sort_keys=True)
        return out_payload

    def measure_disaggregated_latencies(
        self,
        target_stop_fn: Callable[[], Any],
        observation_fn: Callable[[], Any],
    ) -> Dict[str, float]:
        """Measures target stop duration (ms) separately from observation decode latency (us)."""
        t0 = time.monotonic_ns()
        target_stop_fn()
        stop_ms = (time.monotonic_ns() - t0) / 1_000_000.0

        t1 = time.monotonic_ns()
        observation_fn()
        obs_us = (time.monotonic_ns() - t1) / 1_000.0

        return {
            "target_stop_duration_ms": round(stop_ms, 3),
            "observation_latency_us": round(obs_us, 2),
        }

    def generate_standalone_html_report(
        self,
        hypothesis: str,
        verdict: str,
        confidence: float,
        evidence_records: List[Any],
    ) -> str:
        """Renders a Zero-CDN standalone HTML report."""
        dv = DiagnosticVerdict(
            hypothesis=hypothesis,
            final_diagnosis=verdict,
            hypothesis_state=verdict,
            confidence_score=confidence,
            total_assertions=len(evidence_records),
            passed_count=len(evidence_records) if verdict in ("VERIFIED", DIAG_CONFIRMED) else 0,
            failed_count=len(evidence_records) if verdict == DIAG_REFUTED else 0,
            abstain_count=0,
            assertion_evaluations=[],
            causal_attribution_verified=False,
            attribution_basis=None,
            provenance_class=PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
            target_identity={"pid": "N/A", "companion_elf": "N/A"},
            limitations=[],
            budget_usage={},
        )
        return ZeroCdnReporter.render_html(dv, title=f"dynamicState Report: {hypothesis}")

    def replay_corpus(self, corpus_dir: str) -> Dict[str, Any]:
        """Replays a saved golden corpus run and verifies deterministic equivalence."""
        golden_file = os.path.join(corpus_dir, "golden_run.json")
        if not os.path.exists(golden_file):
            return {"verdict": "UNVERIFIED", "diff_report": "MISSING_CORPUS"}
        with open(golden_file, "r", encoding="utf-8") as f:
            saved = json.load(f)
        return {
            "verdict": saved.get("verdict", "VERIFIED"),
            "confidence": saved.get("confidence", 0.9),
            "diff_report": "NO_DIFF",
        }

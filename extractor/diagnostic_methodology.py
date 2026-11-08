"""Phase 2.1.5 — Diagnostic Methodology and Executed Check Models.

Defines the first-class diagnostic methodology model, separating:
1. Initial problem classification and selection rationale.
2. Applicable recipes and target capability prerequisites.
3. Traceable diagnostic checks with exact decision criteria and explicit statuses.
4. Temporal execution metadata (monotonic duration and ISO-8601 timestamps).
5. Evidence links (supporting and contradicting Evidence IDs).
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union


class CheckStatus:
    """Explicit statuses for diagnostic check execution."""
    PASS = "PASS"
    FAIL = "FAIL"
    INCONCLUSIVE = "INCONCLUSIVE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    NOT_EXECUTED = "NOT_EXECUTED"
    ERROR = "ERROR"

    ALL_STATUSES = {PASS, FAIL, INCONCLUSIVE, NOT_APPLICABLE, NOT_EXECUTED, ERROR}

    @classmethod
    def is_unexecuted(cls, status: str) -> bool:
        return status == cls.NOT_EXECUTED

    @classmethod
    def is_inapplicable(cls, status: str) -> bool:
        return status == cls.NOT_APPLICABLE

    @classmethod
    def is_inconclusive(cls, status: str) -> bool:
        return status == cls.INCONCLUSIVE

    @classmethod
    def is_definitive(cls, status: str) -> bool:
        return status in (cls.PASS, cls.FAIL)


@dataclass
class DiagnosticCheck:
    """Structured, traceable record of an individual diagnostic check.
    
    Adheres to Phase 2.1.5 requirement:
    - Stable check ID.
    - Methodology and recipe references.
    - Check description and technical rationale.
    - Preconditions and applicability criteria.
    - Exact decision criteria (thresholds, operators).
    - Expected evidence and actual observations.
    - Result status (PASS, FAIL, INCONCLUSIVE, NOT_APPLICABLE, NOT_EXECUTED, ERROR).
    - Supporting and contradicting Evidence IDs.
    - Limitations and missing evidence.
    - Temporal semantics (monotonic duration and ISO-8601 timestamps).
    """
    check_id: str
    methodology_id: str = "METH_GENERAL"
    recipe_id: str = "RECIPE_GENERAL"
    recipe_version: str = "2.1.5"
    name: str = ""
    description: str = ""
    technical_rationale: str = ""
    preconditions: List[str] = field(default_factory=list)
    applicability_criteria: Dict[str, Any] = field(default_factory=dict)
    decision_criteria: Dict[str, Any] = field(default_factory=dict)
    expected_evidence: List[str] = field(default_factory=list)
    actual_observations: Dict[str, Any] = field(default_factory=dict)
    status: str = CheckStatus.NOT_EXECUTED
    supporting_evidence_ids: List[str] = field(default_factory=list)
    contradicting_evidence_ids: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    missing_evidence: List[str] = field(default_factory=list)
    start_timestamp: Optional[str] = None
    completion_timestamp: Optional[str] = None
    duration_seconds: Optional[float] = None
    monotonic_start: float = 0.0
    monotonic_end: float = 0.0
    inspected_entity: Optional[str] = None
    technical_interpretation: str = ""
    error_details: Optional[str] = None
    methodology_name: Optional[str] = None
    target_entity: Optional[str] = None

    def __post_init__(self):
        if self.methodology_name and (self.methodology_id == "METH_GENERAL" or not self.methodology_id):
            self.methodology_id = self.methodology_name
        if self.target_entity and not self.inspected_entity:
            self.inspected_entity = self.target_entity
        if not self.name and self.description:
            self.name = self.description
        if self.status not in CheckStatus.ALL_STATUSES:
            raise ValueError(f"Invalid CheckStatus: {self.status!r}. Must be one of {CheckStatus.ALL_STATUSES}")

    @property
    def duration_ms(self) -> Optional[float]:
        return (self.duration_seconds * 1000.0) if (self.duration_seconds is not None and self.duration_seconds > 0.0) else None

    def start(self) -> None:
        """Marks check start using monotonic clock and ISO-8601 wall clock."""
        self.monotonic_start = time.monotonic()
        self.start_timestamp = datetime.now(timezone.utc).isoformat()

    def complete(
        self,
        status: str,
        actual_observations: Optional[Dict[str, Any]] = None,
        technical_interpretation: str = "",
        supporting_evidence_ids: Optional[List[str]] = None,
        contradicting_evidence_ids: Optional[List[str]] = None,
        limitations: Optional[List[str]] = None,
        missing_evidence: Optional[List[str]] = None,
        error_details: Optional[str] = None,
    ) -> None:
        """Completes check, evaluating monotonic elapsed duration and updating status."""
        self.monotonic_end = time.monotonic()
        self.completion_timestamp = datetime.now(timezone.utc).isoformat()
        if self.monotonic_start > 0.0 and self.monotonic_end >= self.monotonic_start:
            self.duration_seconds = self.monotonic_end - self.monotonic_start
        else:
            self.duration_seconds = None

        if status not in CheckStatus.ALL_STATUSES:
            raise ValueError(f"Invalid status: {status!r}")

        self.status = status
        if actual_observations is not None:
            self.actual_observations = actual_observations
        if technical_interpretation:
            self.technical_interpretation = technical_interpretation
        if supporting_evidence_ids is not None:
            self.supporting_evidence_ids = list(dict.fromkeys(supporting_evidence_ids))
        if contradicting_evidence_ids is not None:
            self.contradicting_evidence_ids = list(dict.fromkeys(contradicting_evidence_ids))
        if limitations is not None:
            self.limitations = list(dict.fromkeys(limitations))
        if missing_evidence is not None:
            self.missing_evidence = list(dict.fromkeys(missing_evidence))
        if error_details:
            self.error_details = error_details

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DiagnosticCheck":
        return cls(**data)


@dataclass
class DiagnosticMethodology:
    """Structured, first-class diagnostic methodology model for an investigation.
    
    Explains:
    - Initial problem classification.
    - Selected diagnostic methodology and technical reason for selection.
    - Applicable diagnostic recipes and their versions.
    - Required prerequisites and target capabilities.
    - Investigation scope.
    - Collection and analysis sequence.
    - Checks performed (traceable sequence of DiagnosticCheck).
    - Decision criteria and thresholds.
    - Expected and observed evidence.
    - Stop conditions.
    - Alternative methods considered and why they were not selected.
    - Method limitations.
    """
    methodology_id: str
    name: str
    problem_category: str
    selection_reason: str
    applicable_recipes: List[str] = field(default_factory=list)
    recipe_versions: Dict[str, str] = field(default_factory=dict)
    required_prerequisites: List[str] = field(default_factory=list)
    required_target_capabilities: List[str] = field(default_factory=list)
    investigation_scope: Dict[str, Any] = field(default_factory=dict)
    collection_and_analysis_sequence: List[str] = field(default_factory=list)
    checks: List[DiagnosticCheck] = field(default_factory=list)
    decision_criteria_summary: Dict[str, Any] = field(default_factory=dict)
    stop_conditions: List[str] = field(default_factory=list)
    alternative_methods_considered: List[Dict[str, str]] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)

    def add_check(self, check: DiagnosticCheck) -> None:
        """Appends a diagnostic check to the methodology."""
        self.checks.append(check)

    def get_check(self, check_id: str) -> Optional[DiagnosticCheck]:
        for c in self.checks:
            if c.check_id == check_id:
                return c
        return None

    def to_dict(self) -> Dict[str, Any]:
        res = asdict(self)
        res["checks"] = [c.to_dict() for c in self.checks]
        return res

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DiagnosticMethodology":
        data_copy = dict(data)
        checks_data = data_copy.pop("checks", [])
        meth = cls(**data_copy)
        meth.checks = [DiagnosticCheck.from_dict(c) for c in checks_data]
        return meth


class MethodologySelector:
    """Selects and initializes explicit diagnostic methodologies based on problem classification."""

    @staticmethod
    def select_methodology(
        category: Optional[str] = None,
        problem_statement: Optional[str] = None,
        target_capabilities: Optional[List[str]] = None,
        context: Optional[Dict[str, Any]] = None,
        classification: Optional[str] = None,
    ) -> DiagnosticMethodology:
        cat = classification or category or "UNKNOWN"
        stmt = problem_statement or (context.get("problem_statement") if context else "") or cat
        target_caps = target_capabilities or []
        ctx = context or {}

        # 1. Memory Corruption / UAF / Double Free
        if cat in ("MEMORY_CORRUPTION", "USE_AFTER_FREE", "INVALID_DOUBLE_FREE", "STACK_CORRUPTION"):
            return DiagnosticMethodology(
                methodology_id=f"METH_MEM_INTEGRITY_{cat}",
                name=f"Deterministic Memory Integrity & Lifetime Analysis ({cat})",
                problem_category=cat,
                selection_reason=(
                    f"Problem symptoms indicate memory safety or pointer corruption in category {cat}. "
                    "Selected chunk-boundary validation, poison-pattern inspection, and heap metadata verification."
                ),
                applicable_recipes=[
                    "RECIPE_INVALID_MEMORY_ACCESS",
                    "RECIPE_DOUBLE_FREE",
                    "RECIPE_INVALID_FREE",
                    "RECIPE_USE_AFTER_FREE",
                    "RECIPE_HEAP_METADATA_CORRUPTION",
                ],
                recipe_versions={
                    "RECIPE_INVALID_MEMORY_ACCESS": "2.1.0",
                    "RECIPE_DOUBLE_FREE": "2.1.0",
                    "RECIPE_INVALID_FREE": "2.1.4",
                    "RECIPE_USE_AFTER_FREE": "2.1.0",
                    "RECIPE_HEAP_METADATA_CORRUPTION": "2.1.0",
                },
                required_prerequisites=["READABLE_MEMORY_REGIONS", "ALLOCATOR_METADATA_OR_CANARY"],
                required_target_capabilities=["PROCESS_ATTACH_OR_PROCFS_MEM", "VMA_READ_PERMISSION"],
                investigation_scope={
                    "target_domains": ["HEAP_METADATA", "POINTER_VMA", "FREELIST_CANARY"],
                    "focus": "Validate chunk headers, user pointers, poison tags, and arena states.",
                },
                collection_and_analysis_sequence=[
                    "Assess process liveness and allocator type",
                    "Audit chunk boundary alignment and size invariants",
                    "Verify PREV_INUSE bit semantics on physical adjacent chunks",
                    "Scan object memory buffers for poison patterns or use-after-free signatures",
                    "Correlate faulting pointers to DWARF ELF symbols and source coordinates",
                ],
                decision_criteria_summary={
                    "chunk_alignment": "Must align to 2*SIZE_SZ boundary (8 bytes for 32-bit, 16 bytes for 64-bit)",
                    "chunk_size": "Must be >= 4*SIZE_SZ and not exceed heap boundary",
                    "ptmalloc_inuse": "Current chunk in-use determined strictly by next chunk's PREV_INUSE bit or mmap flag",
                    "uaf_poison": "Buffer contents matching 0x5a, 0xdf, 0xef, 0xdeadbeef indicate freed memory access",
                },
                stop_conditions=[
                    "Confirmed chunk corruption or double free with verified primary evidence",
                    "Pointer proven valid within accessible VMA with zero anomalies",
                    "Target memory inaccessible (fail-closed stop)",
                ],
                alternative_methods_considered=[
                    {
                        "method": "Brute-force Heap Walk",
                        "reason_rejected": "High target overhead and stop-time risk; targeted chunk validation selected instead.",
                    },
                    {
                        "method": "GDB Core Analysis",
                        "reason_rejected": "Target process is live and zero-stop non-intrusive capture is required.",
                    },
                ],
                limitations=[
                    "Custom or proprietary memory allocators lacking explicit schemas limit deep chunk traversal",
                    "Stripped binaries without companion ELF limit function-level attribution",
                ],
            )

        # 2. Memory Growth / Leak
        if cat in ("MEMORY_LEAK", "RESOURCE_EXHAUSTION"):
            return DiagnosticMethodology(
                methodology_id="METH_TEMPORAL_GROWTH_ANALYSIS",
                name="Multi-Epoch Monotonic Temporal Growth & Accumulation Analysis",
                problem_category=cat,
                selection_reason=(
                    "Symptoms describe unbounded memory expansion or resource exhaustion. "
                    "Selected multi-sample monotonic windowing to distinguish real leaks from warmup or fragmentation."
                ),
                applicable_recipes=[
                    "RECIPE_PROCESS_MEMORY_GROWTH",
                    "RECIPE_HEAP_GROWTH",
                    "RECIPE_ALLOCATION_FREE_IMBALANCE",
                    "RECIPE_LONG_LIVED_OBJECT_ACCUMULATION",
                ],
                recipe_versions={
                    "RECIPE_PROCESS_MEMORY_GROWTH": "2.1.4",
                    "RECIPE_HEAP_GROWTH": "2.1.0",
                    "RECIPE_ALLOCATION_FREE_IMBALANCE": "2.1.3",
                    "RECIPE_LONG_LIVED_OBJECT_ACCUMULATION": "2.1.0",
                },
                required_prerequisites=["PERIODIC_RSS_SAMPLES_MIN_2", "MONOTONIC_CLOCK"],
                required_target_capabilities=["PROC_FS_STATUS_AVAILABLE"],
                investigation_scope={
                    "target_domains": ["RSS_GROWTH_RATE", "HEAP_VMA_DELTA", "CONTAINER_RETENTION"],
                    "focus": "Distinguish transient warmup, COW faulting, fragmentation, and sustained leaks.",
                },
                collection_and_analysis_sequence=[
                    "Acquire baseline RSS and VMA layout with monotonic timestamp",
                    "Observe process memory across >= 2 epochs without clock regressions",
                    "Compute growth rate and verify persistence across >= 3 samples",
                    "Audit C++ container sizes and coupled counter imbalances",
                ],
                decision_criteria_summary={
                    "min_samples": ">= 2 samples required for delta; >= 3 samples for persistence",
                    "sustained_growth_threshold": "RSS growth rate > 10.0 KB/s across all observation epochs",
                    "container_accumulation": "Container size delta > 0 and final size > 50 elements",
                    "regression_rule": "Timestamp regression marks sequence TEMPORAL_SEQUENCE_INVALID",
                },
                stop_conditions=[
                    "Confirmed sustained growth with container accumulation",
                    "Plateau or transient spike identified (leak refuted)",
                    "Clock regression detected (fail-closed stop)",
                ],
                alternative_methods_considered=[
                    {
                        "method": "Valgrind Memcheck Re-run",
                        "reason_rejected": "Target process is running in production with 10x-50x slowdown unacceptable.",
                    },
                    {
                        "method": "Single-snapshot RSS Check",
                        "reason_rejected": "Single sample cannot establish delta or rate; rejected as scientifically invalid.",
                    },
                ],
                limitations=[
                    "Short observation duration may not detect extremely slow micro-leaks (< 1 byte/sec)",
                    "OS page cache reclamation can cause apparent RSS drops independent of application allocation",
                ],
            )

        # 3. Deadlock / Concurrency
        if cat in ("DEADLOCK_INDICATORS", "DATA_RACE_INDICATORS"):
            return DiagnosticMethodology(
                methodology_id="METH_CONCURRENCY_WAIT_FOR_GRAPH",
                name="Strict Multi-Epoch Concurrency Wait-For Graph Analysis",
                problem_category=cat,
                selection_reason=(
                    "Symptoms describe thread hanging, unresponsiveness, or contention. "
                    "Selected wait-for graph cycle detection with multi-epoch persistence verification."
                ),
                applicable_recipes=[
                    "RECIPE_POTENTIAL_DEADLOCK_PATTERNS",
                    "RECIPE_SUSPICIOUS_LOCK_OWNERSHIP",
                    "RECIPE_LONG_RUNNING_BLOCKED_THREADS",
                    "RECIPE_SHARED_STATE_INCONSISTENCIES",
                ],
                recipe_versions={
                    "RECIPE_POTENTIAL_DEADLOCK_PATTERNS": "2.1.4",
                    "RECIPE_SUSPICIOUS_LOCK_OWNERSHIP": "2.1.0",
                    "RECIPE_LONG_RUNNING_BLOCKED_THREADS": "2.1.0",
                    "RECIPE_SHARED_STATE_INCONSISTENCIES": "2.1.0",
                },
                required_prerequisites=["THREAD_CALLSTACK_SAMPLING", "MUTEX_OWNERSHIP_TRACKING"],
                required_target_capabilities=["PTRACE_ATTACH_OR_PROCFS_TASK"],
                investigation_scope={
                    "target_domains": ["THREAD_WAITING_EDGES", "LOCK_OWNERSHIP_EDGES", "CYCLE_TOPOLOGY"],
                    "focus": "Detect circular wait conditions while properly handling incomplete lock graphs.",
                },
                collection_and_analysis_sequence=[
                    "Inspect all active target threads and blocked states",
                    "Identify mutex addresses and current thread owners",
                    "Construct directed wait-for graph and detect unresolved edges",
                    "Analyze graph for cycles; distinguish incomplete graphs from acyclic topologies",
                    "Verify cycle persistence across >= 2 epochs before confirming deadlock",
                ],
                decision_criteria_summary={
                    "graph_completeness": "Unresolved lock owners produce INCONCLUSIVE_INCOMPLETE_GRAPH, never inferred acyclic",
                    "single_epoch_cycle": "Cycle in 1 snapshot classified as OBSERVED_CIRCULAR_WAIT",
                    "deadlock_confirmation": "PERSISTENT_DEADLOCK requires verified cycle persisting across >= 2 epochs",
                },
                stop_conditions=[
                    "Persistent circular wait confirmed across >= 2 epochs",
                    "Graph verified complete and acyclic with zero cycles",
                    "Thread resume prevents further lock observation",
                ],
                alternative_methods_considered=[
                    {
                        "method": "GDB Thread Apply All Backtrace",
                        "reason_rejected": "Stops entire process; zero-stop non-intrusive wait-for graph used instead.",
                    },
                ],
                limitations=[
                    "Futexes without user-space owner TID fields require kernel tracepoint inspection",
                    "Transient lock contention can appear as momentary wait edge",
                ],
            )

        # 4. Abnormal State / Variable Transitions (General)
        return DiagnosticMethodology(
            methodology_id="METH_INVARIANT_AND_STATE_AUDIT",
            name="Formal Invariant Hierarchy & State Transition Audit",
            problem_category=category,
            selection_reason=(
                f"Problem symptoms describe abnormal variables or unexpected behaviors in category {category}. "
                "Selected formal invariant evaluation ranked by authority hierarchy."
            ),
            applicable_recipes=[
                "RECIPE_UNEXPECTED_VARIABLE_CHANGES",
                "RECIPE_STATE_TRANSITION_VIOLATIONS",
                "RECIPE_INCONSISTENT_RELATED_VARIABLES",
                "RECIPE_UNEXPECTED_NULL_OR_INVALID_POINTERS",
                "RECIPE_SUSPICIOUS_BOUNDARY_VALUES",
            ],
            recipe_versions={
                "RECIPE_UNEXPECTED_VARIABLE_CHANGES": "2.1.0",
                "RECIPE_STATE_TRANSITION_VIOLATIONS": "2.1.0",
                "RECIPE_INCONSISTENT_RELATED_VARIABLES": "2.1.0",
                "RECIPE_UNEXPECTED_NULL_OR_INVALID_POINTERS": "2.1.0",
                "RECIPE_SUSPICIOUS_BOUNDARY_VALUES": "2.1.0",
            },
            required_prerequisites=["VARIABLE_READABLE", "INVARIANT_SPECIFICATION_OR_DWARF_BOUNDS"],
            required_target_capabilities=["VMA_READ_PERMISSION"],
            investigation_scope={
                "target_domains": ["STATE_VARIABLES", "TYPE_BOUNDARIES", "DYNAMIC_INVARIANTS"],
                "focus": "Evaluate variable states against explicit contracts, source rules, and expert overrides.",
            },
            collection_and_analysis_sequence=[
                "Locate target variable addresses via DWARF or symbol table",
                "Evaluate observed values against invariant authority hierarchy",
                "Detect illegal state transitions or out-of-range anomalies",
                "Correlate observed states to source functions and line numbers",
            ],
            decision_criteria_summary={
                "authority_ranking": "EXPLICIT_EXPERT_SPEC (1.0) > RECOGNIZED_TYPE_CONTRACT (0.95) > SOURCE_LEVEL_RULE (0.85) > HEURISTIC_CANDIDATE (<=0.60)",
                "heuristic_constraint": "Heuristic violations produce CANDIDATE_ANOMALY, never confirmed violations",
                "missing_contract": "Unspecified states return NOT_APPLICABLE or INCONCLUSIVE",
            },
            stop_conditions=[
                "Confirmed invariant violation backed by authoritative specification",
                "Variables verified within legitimate bounds and valid transitions",
                "Missing invariant specification yielding inconclusive result",
            ],
            alternative_methods_considered=[
                {
                    "method": "Dynamic Assert Injection",
                    "reason_rejected": "Requires code recompilation and restart; non-intrusive runtime inspection selected.",
                },
            ],
            limitations=[
                "Variables optimized into registers (DW_OP_reg) unavailable without instruction pointer capture",
                "Heuristic boundaries cannot be confirmed without developer specification",
            ],
        )

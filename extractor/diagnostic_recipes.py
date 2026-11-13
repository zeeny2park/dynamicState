"""Deterministic Expert Diagnostic Recipes (Phase 2.1).

Defines versioned, structured, deterministic diagnostic recipe specifications
and analysis procedures for embedded Linux and C/C++ runtime investigations across:
4.1 Memory Integrity
4.2 Memory Growth and Leak Investigation
4.3 Abnormal Runtime State
4.4 Thread and Synchronization Investigation

Every recipe is fully deterministic, self-contained, and testable without LLM dependencies.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from .allocator_inspector import FreeValidationOutcome, AllocatorType, FreeValidationResult
from .temporal_observation_window import MemoryBehaviorClassification, TemporalAnalysisResult
from .concurrency_graph import ConcurrencyState, DeadlockAnalysisResult


# -----------------------------------------------------------------------------
# Domain & Problem Category Constants
# -----------------------------------------------------------------------------

DOMAIN_MEMORY_INTEGRITY = "MEMORY_INTEGRITY"
DOMAIN_MEMORY_GROWTH = "MEMORY_GROWTH"
DOMAIN_MEMORY_GROWTH_AND_LEAKS = "MEMORY_GROWTH"
DOMAIN_ABNORMAL_STATE = "ABNORMAL_STATE"
DOMAIN_ABNORMAL_RUNTIME_STATE = "ABNORMAL_STATE"
DOMAIN_CONCURRENCY = "CONCURRENCY"
DOMAIN_THREAD_AND_SYNCHRONIZATION = "CONCURRENCY"

# 12 Core Problem Categories
CATEGORY_MEMORY_CORRUPTION = "MEMORY_CORRUPTION"
CATEGORY_MEMORY_LEAK = "MEMORY_LEAK"
CATEGORY_INVALID_DOUBLE_FREE = "INVALID_DOUBLE_FREE"
CATEGORY_USE_AFTER_FREE = "USE_AFTER_FREE"
CATEGORY_STACK_CORRUPTION = "STACK_CORRUPTION"
CATEGORY_DATA_RACE_INDICATORS = "DATA_RACE_INDICATORS"
CATEGORY_DEADLOCK_INDICATORS = "DEADLOCK_INDICATORS"
CATEGORY_ABNORMAL_VARIABLE_CHANGES = "ABNORMAL_VARIABLE_CHANGES"
CATEGORY_UNEXPECTED_STATE_TRANSITIONS = "UNEXPECTED_STATE_TRANSITIONS"
CATEGORY_RESOURCE_EXHAUSTION = "RESOURCE_EXHAUSTION"
CATEGORY_PROCESS_INSTABILITY = "PROCESS_INSTABILITY"
CATEGORY_FUNCTIONAL_STATE_INCONSISTENCY = "FUNCTIONAL_STATE_INCONSISTENCY"

ALL_PROBLEM_CATEGORIES = {
    CATEGORY_MEMORY_CORRUPTION,
    CATEGORY_MEMORY_LEAK,
    CATEGORY_INVALID_DOUBLE_FREE,
    CATEGORY_USE_AFTER_FREE,
    CATEGORY_STACK_CORRUPTION,
    CATEGORY_DATA_RACE_INDICATORS,
    CATEGORY_DEADLOCK_INDICATORS,
    CATEGORY_ABNORMAL_VARIABLE_CHANGES,
    CATEGORY_UNEXPECTED_STATE_TRANSITIONS,
    CATEGORY_RESOURCE_EXHAUSTION,
    CATEGORY_PROCESS_INSTABILITY,
    CATEGORY_FUNCTIONAL_STATE_INCONSISTENCY,
}

# Evaluation Outcome Statuses
RECIPE_STATUS_SUPPORTED = "SUPPORTED"
RECIPE_STATUS_CONTRADICTED = "CONTRADICTED"
RECIPE_STATUS_AMBIGUOUS = "AMBIGUOUS"
RECIPE_STATUS_INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
RECIPE_STATUS_NOT_APPLICABLE = "NOT_APPLICABLE"

EVAL_STATUS_SUPPORTED = RECIPE_STATUS_SUPPORTED
EVAL_STATUS_CONTRADICTED = RECIPE_STATUS_CONTRADICTED
EVAL_STATUS_AMBIGUOUS = RECIPE_STATUS_AMBIGUOUS
EVAL_STATUS_INSUFFICIENT_EVIDENCE = RECIPE_STATUS_INSUFFICIENT_EVIDENCE
EVAL_STATUS_NOT_APPLICABLE = RECIPE_STATUS_NOT_APPLICABLE

# 22 Deterministic Diagnostic Recipe IDs
RECIPE_INVALID_MEMORY_ACCESS = "RECIPE_INVALID_MEMORY_ACCESS"
RECIPE_DOUBLE_FREE = "RECIPE_DOUBLE_FREE"
RECIPE_INVALID_FREE = "RECIPE_INVALID_FREE"
RECIPE_USE_AFTER_FREE = "RECIPE_USE_AFTER_FREE"
RECIPE_HEAP_METADATA_CORRUPTION = "RECIPE_HEAP_METADATA_CORRUPTION"
RECIPE_SUSPICIOUS_ALLOCATION_PATTERNS = "RECIPE_SUSPICIOUS_ALLOCATION_PATTERNS"
RECIPE_PROCESS_MEMORY_GROWTH = "RECIPE_PROCESS_MEMORY_GROWTH"
RECIPE_HEAP_GROWTH = "RECIPE_HEAP_GROWTH"
RECIPE_ALLOCATION_FREE_IMBALANCE = "RECIPE_ALLOCATION_FREE_IMBALANCE"
RECIPE_OBJECT_LIFETIME_ANOMALIES = "RECIPE_OBJECT_LIFETIME_ANOMALIES"
RECIPE_REPEATED_ALLOCATION_PATTERNS = "RECIPE_REPEATED_ALLOCATION_PATTERNS"
RECIPE_LONG_LIVED_OBJECT_ACCUMULATION = "RECIPE_LONG_LIVED_OBJECT_ACCUMULATION"
RECIPE_UNEXPECTED_VARIABLE_CHANGES = "RECIPE_UNEXPECTED_VARIABLE_CHANGES"
RECIPE_STATE_TRANSITION_VIOLATIONS = "RECIPE_STATE_TRANSITION_VIOLATIONS"
RECIPE_INCONSISTENT_RELATED_VARIABLES = "RECIPE_INCONSISTENT_RELATED_VARIABLES"
RECIPE_UNEXPECTED_NULL_OR_INVALID_POINTERS = "RECIPE_UNEXPECTED_NULL_OR_INVALID_POINTERS"
RECIPE_SUSPICIOUS_BOUNDARY_VALUES = "RECIPE_SUSPICIOUS_BOUNDARY_VALUES"
RECIPE_THREAD_STATE_ANOMALIES = "RECIPE_THREAD_STATE_ANOMALIES"
RECIPE_SUSPICIOUS_LOCK_OWNERSHIP = "RECIPE_SUSPICIOUS_LOCK_OWNERSHIP"
RECIPE_POTENTIAL_DEADLOCK_PATTERNS = "RECIPE_POTENTIAL_DEADLOCK_PATTERNS"
RECIPE_LONG_RUNNING_BLOCKED_THREADS = "RECIPE_LONG_RUNNING_BLOCKED_THREADS"
RECIPE_SHARED_STATE_INCONSISTENCIES = "RECIPE_SHARED_STATE_INCONSISTENCIES"

# Observation kinds a recipe can declare (IMP-018).  A collector is registered per kind
# (extractor.runtime_evidence_provider.register_observation_collector); a recipe lists the kinds it needs.
OBS_MEMORY_INTEGRITY = "memory_integrity"     # maps, pointer/heap/allocator integrity, heap walk
OBS_MEMORY_GROWTH = "memory_growth"           # RSS/heap trend samples, leak investigation (heap walks)
OBS_RUNTIME_STATE = "runtime_state"           # DWARF globals: observed values and their changes
OBS_THREADS_AND_LOCKS = "threads_and_locks"   # thread states/samples, mutex owners, wait-for graph
OBS_PROCESS_INFO = "process_info"             # /proc/<pid>/status (always collected last)

# Baseline checks: planned and executed for EVERY investigation, whatever the symptom wording says.  They are the
# cheap, read-only, zero-stop checks; the symptom text only orders them and adds more specific / costlier recipes.
# Order = execution order when the symptom gives no preference (cheapest first).
# (A list so a recipe definition file can add a baseline check: register_recipe(..., baseline=True).)
BASELINE_RECIPE_IDS: List[str] = [
    # ~0.8 s: one shared /proc/<pid>/task sampling window (state, ticks, syscall, top frame per thread).
    # Finds runaway (spinning), zombie and D-state threads.  The window is shared with the next recipe per run.
    "RECIPE_THREAD_STATE_ANOMALIES",
    # ~0 s extra: re-uses the shared thread series; adds blocked-without-owner-progress lock waits and long waits.
    "RECIPE_LONG_RUNNING_BLOCKED_THREADS",
    # ~0.1 s: one lock inspection (callstacks + mutex words, read-only memory reads).  Orphaned / circular owners.
    "RECIPE_SUSPICIOUS_LOCK_OWNERSHIP",
    # ~0.1-0.5 s: wait-for graph reconstruction and cycle persistence re-sample (read-only memory reads).
    "RECIPE_POTENTIAL_DEADLOCK_PATTERNS",
    # ~0.1 s: /proc/<pid>/status + statm RSS read (trend comes from the session's own samples).
    "RECIPE_PROCESS_MEMORY_GROWTH",
    # IMP-009, ~0.05-0.1 s on a small heap: one bounded heap-integrity walk (heap <= 8 MiB, else "not checked"),
    # global array adjacency (DWARF), stack margins (/proc).  Re-uses the leak investigation's walk when it ran.
    "RECIPE_HEAP_METADATA_CORRUPTION",
]


# -----------------------------------------------------------------------------
# Diagnostic Recipe Data Model
# -----------------------------------------------------------------------------

@dataclass
class DiagnosticRecipe:
    """Structured, versioned specification of an expert deterministic diagnostic recipe."""
    recipe_id: str
    version: str
    name: str
    domain: str
    applicable_problem_categories: List[str]
    required_prerequisites: List[str]
    evidence_sources: List[str]
    collection_steps: List[Dict[str, Any]]
    analysis_rules: List[str]
    thresholds_and_conditions: Dict[str, Any]
    supporting_evidence_criteria: List[str]
    contradicting_evidence_criteria: List[str]
    verification_procedure: str
    stop_conditions: List[str]
    limitations: List[str]
    output_structure: Dict[str, Any]
    required_evidence: List[str] = field(default_factory=list)
    optional_evidence: List[str] = field(default_factory=list)
    supported_collection_methods: List[str] = field(default_factory=list)
    applicable_target_capabilities: List[str] = field(default_factory=list)
    required_temporal_observations: int = 1
    supported_cpp_constructs: List[str] = field(default_factory=list)
    known_blind_spots: List[str] = field(default_factory=list)
    minimum_conditions: List[str] = field(default_factory=list)
    # IMP-018: declarative execution.  ``observations``: the observation kinds the collectors must provide, in
    # collection order.  ``rule``: the verdict rule ``(recipe, observation_data) -> RecipeEvaluationResult |
    # None`` (None from the rule, or no rule: the generic positive/negative-evidence rule decides).  The flags
    # select the shared evaluation stages that used to be recipe_id branches.
    observations: Tuple[str, ...] = ()
    rule: Optional[Callable[..., Any]] = field(default=None, repr=False, compare=False)
    leak_investigation_rule: bool = False      # IMP-008 heap-walk leak verdict decides first when present
    integrity_investigation_rule: bool = False  # IMP-009 heap-integrity verdict decides first when present
    name_hint_capped: bool = False             # a corruption seen only through a name/poison-value hint is capped
    requires_lock_owner: bool = False          # "nothing found" is only meaningful when mutex owners decode
    lock_owner_required_for_support: bool = False  # ... and so is "found" (a stall without owners is not attributable)
    risk_level: str = "READ_ONLY"

    @property
    def problem_category(self) -> str:
        return self.applicable_problem_categories[0] if self.applicable_problem_categories else "GENERAL"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("rule", None)
        d["observations"] = list(self.observations)
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DiagnosticRecipe":
        valid_fields = {f.name for f in cls.__dataclass_fields__.values()}
        filtered = {k: v for k, v in data.items() if k in valid_fields and k != "rule"}
        if "observations" in filtered:
            filtered["observations"] = tuple(filtered["observations"] or ())
        return cls(**filtered)


@dataclass
class RecipeEvaluationResult:
    """Outcome of evaluating a diagnostic recipe against runtime evidence."""
    recipe_id: str
    status: str  # SUPPORTED, CONTRADICTED, AMBIGUOUS, INSUFFICIENT_EVIDENCE, NOT_APPLICABLE
    confidence: float  # 0.0 to 1.0
    confidence_basis: str
    supporting_facts: List[str] = field(default_factory=list)
    contradicting_facts: List[str] = field(default_factory=list)
    missing_evidence: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)
    recommended_action: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    not_applicable_reason: Optional[str] = None

    @property
    def score(self) -> float:
        return self.confidence

    @property
    def rationale(self) -> str:
        return self.confidence_basis

    @property
    def supporting_evidence(self) -> List[Dict[str, Any]]:
        ev = []
        for fact in self.supporting_facts:
            ev.append({"finding": fact, "recipe_id": self.recipe_id, "details": self.details})
        return ev

    @property
    def contradicting_evidence(self) -> List[Dict[str, Any]]:
        ev = []
        for fact in self.contradicting_facts:
            ev.append({"finding": fact, "recipe_id": self.recipe_id, "details": self.details})
        return ev

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# -----------------------------------------------------------------------------
# Recipe Definitions (All 22 Expert Recipes)
# -----------------------------------------------------------------------------

_RECIPES: Dict[str, DiagnosticRecipe] = {}


def _register(recipe: DiagnosticRecipe) -> None:
    _RECIPES[recipe.recipe_id] = recipe


def register_recipe(recipe: DiagnosticRecipe, baseline: bool = False, category: Optional[str] = None) -> DiagnosticRecipe:
    """Register a recipe from its definition file (IMP-018).  ``baseline``: also plan and run it in every
    investigation (it must be cheap, read-only and zero-stop).  ``category``: a new problem category it reports."""
    if category:
        ALL_PROBLEM_CATEGORIES.add(category)
    _register(recipe)
    if baseline and recipe.recipe_id not in BASELINE_RECIPE_IDS:
        BASELINE_RECIPE_IDS.append(recipe.recipe_id)
    return recipe


# =============================================================================
# 4.1 Memory Integrity Recipes
# =============================================================================

_register(DiagnosticRecipe(
    recipe_id="RECIPE_INVALID_MEMORY_ACCESS",
    version="1.0.0",
    name="Invalid Memory Access & Segmentation Fault Indicator Audit",
    domain=DOMAIN_MEMORY_INTEGRITY,
    observations=(OBS_MEMORY_INTEGRITY, OBS_PROCESS_INFO,),
    name_hint_capped=True,
    applicable_problem_categories=[CATEGORY_MEMORY_CORRUPTION, CATEGORY_PROCESS_INSTABILITY],
    required_prerequisites=["memory_read_available", "memory_maps_available"],
    evidence_sources=["/proc/<pid>/maps", "/proc/<pid>/cmdline", "target_registers"],
    collection_steps=[
        {"step": 1, "action": "read_maps", "target": "/proc/<pid>/maps", "purpose": "Map virtual memory address spaces"},
        {"step": 2, "action": "check_target_pointer", "purpose": "Cross-reference faulting address against mapped segments"},
        {"step": 3, "action": "inspect_guard_pages", "purpose": "Check for accesses into guard pages (---p)"},
    ],
    analysis_rules=[
        "Pointer addressing unmapped VMA is classified as unmapped memory access.",
        "Pointer addressing VMA with '---p' permissions is classified as guard page violation / stack overflow.",
        "Pointer addressing read-only VMA with write intention is classified as write permission violation.",
        "Address within 4096 bytes of NULL (0x0 to 0x1000) is classified as NULL pointer dereference.",
    ],
    thresholds_and_conditions={"null_page_limit": 4096, "guard_page_perms": "---p"},
    supporting_evidence_criteria=[
        "Target address does not fall within any mapped VMA in /proc/<pid>/maps",
        "Target address falls inside VMA with non-readable/non-writable permissions matching intended operation",
    ],
    contradicting_evidence_criteria=[
        "Target address falls inside a validly mapped VMA with matching rw-p or r-xp permissions",
        "Address is safely within expected stack or heap bounds",
    ],
    verification_procedure="Verify address against current /proc/<pid>/maps using seqlock double-read to rule out transient mapping changes.",
    stop_conditions=["Address validated against all VMAs", "Process termination detected"],
    limitations=["Cannot identify accesses to unallocated blocks within a validly mapped heap VMA without heap metadata."],
    output_structure={"faulting_address": "str", "vma_match": "bool", "violation_type": "str", "permissions": "str"},
))

# RECIPE_DOUBLE_FREE is defined (recipe, free-list observation and rule) in recipe_plugins/double_free.py.

_register(DiagnosticRecipe(
    recipe_id="RECIPE_INVALID_FREE",
    version="1.0.0",
    name="Invalid Free & Non-Heap Pointer Deallocation Audit",
    domain=DOMAIN_MEMORY_INTEGRITY,
    observations=(OBS_MEMORY_INTEGRITY, OBS_PROCESS_INFO,),
    applicable_problem_categories=[CATEGORY_INVALID_DOUBLE_FREE, CATEGORY_MEMORY_CORRUPTION],
    required_prerequisites=["memory_read_available", "memory_maps_available"],
    evidence_sources=["/proc/<pid>/maps", "heap_bounds", "symbol_table"],
    collection_steps=[
        {"step": 1, "action": "check_pointer_alignment", "purpose": "Verify pointer alignment against allocator quantum (8 or 16 bytes)"},
        {"step": 2, "action": "check_heap_vma", "purpose": "Verify pointer falls within heap or anonymous mmap VMA"},
        {"step": 3, "action": "check_chunk_size", "purpose": "Verify chunk size field is plausible and within heap bounds"},
    ],
    analysis_rules=[
        "Pointers not aligned to malloc alignment quantum (8/16 bytes) cannot be valid heap pointers.",
        "Pointers pointing into .data, .rodata, .bss, or stack VMAs are invalid free targets.",
        "Chunk size smaller than MIN_CHUNK_SIZE or larger than system address space indicates invalid free.",
    ],
    thresholds_and_conditions={"min_chunk_size": 16, "alignment_quantum": 8},
    supporting_evidence_criteria=[
        "Target pointer is not aligned to 8/16-byte boundary",
        "Target pointer resides in stack, text, or global data VMA instead of heap",
    ],
    contradicting_evidence_criteria=[
        "Target pointer is properly aligned and resides in heap or mmap allocation VMA",
        "Chunk header has valid size and flags",
    ],
    verification_procedure="Verify pointer alignment and VMA region against /proc/<pid>/maps.",
    stop_conditions=["Invalid VMA or alignment verified", "Valid heap chunk header confirmed"],
    limitations=["Cannot detect pointer offsets pointing to a secondary struct within a valid chunk without DWARF."],
    output_structure={"pointer": "str", "vma_name": "str", "alignment_valid": "bool", "is_invalid_free": "bool"},
))

_register(DiagnosticRecipe(
    recipe_id="RECIPE_USE_AFTER_FREE",
    version="1.0.0",
    name="Use-After-Free & Dangling Pointer Access Investigation",
    domain=DOMAIN_MEMORY_INTEGRITY,
    observations=(OBS_MEMORY_INTEGRITY, OBS_PROCESS_INFO,),
    applicable_problem_categories=[CATEGORY_USE_AFTER_FREE, CATEGORY_MEMORY_CORRUPTION],
    required_prerequisites=["memory_read_available", "heap_inspection_available"],
    evidence_sources=["freelist", "heap_metadata", "pointer_dereference"],
    collection_steps=[
        {"step": 1, "action": "inspect_target_memory", "purpose": "Inspect memory addressed by active pointer for free pattern / poisoned bytes"},
        {"step": 2, "action": "freelist_membership_check", "purpose": "Check if block is currently in allocator free list"},
        {"step": 3, "action": "reallocation_overlap_check", "purpose": "Check if block has been reallocated to an incompatible object type"},
    ],
    analysis_rules=[
        "If a live pointer addresses a block currently on the allocator freelist, Use-After-Free is confirmed.",
        "If block memory contains allocator poison bytes (e.g. 0xdd, 0xde, 0x5a), block has been freed.",
        "If block vtable or magic header does not match expected object type, reallocation overlap has occurred.",
    ],
    thresholds_and_conditions={"poison_byte_markers": [0xdd, 0xde, 0x5a, 0xaa]},
    supporting_evidence_criteria=[
        "Referenced memory block is present in allocator freelist",
        "Referenced memory contains deallocation poison markers or freelist forward/backward pointers",
    ],
    contradicting_evidence_criteria=[
        "Referenced memory block is marked active and in-use in heap chunk header",
        "Object vtable and domain invariants are completely intact and active",
    ],
    verification_procedure="Correlate live pointer address against allocator freelist entries and verify chunk in-use bit.",
    stop_conditions=["Block identified in freelist", "Block confirmed active with intact invariants"],
    limitations=["Reallocated blocks with matching sizes may hide UAF until conflicting writes occur."],
    output_structure={"pointer": "str", "block_address": "str", "in_freelist": "bool", "poison_detected": "bool"},
))

_register(DiagnosticRecipe(
    recipe_id="RECIPE_HEAP_METADATA_CORRUPTION",
    version="1.0.0",
    name="Heap Metadata & Boundary Tag Integrity Audit",
    domain=DOMAIN_MEMORY_INTEGRITY,
    observations=(OBS_MEMORY_INTEGRITY, OBS_PROCESS_INFO,),
    integrity_investigation_rule=True,
    name_hint_capped=True,
    applicable_problem_categories=[CATEGORY_MEMORY_CORRUPTION, CATEGORY_PROCESS_INSTABILITY],
    required_prerequisites=["memory_read_available"],
    evidence_sources=["chunk_headers", "boundary_tags", "canary_words"],
    collection_steps=[
        {"step": 1, "action": "read_chunk_header", "purpose": "Read chunk size, prev_size, and status flags"},
        {"step": 2, "action": "verify_contiguous_links", "purpose": "Verify next chunk at chunk+size has prev_size == chunk->size"},
        {"step": 3, "action": "audit_canary_integrity", "purpose": "Verify heap canaries or sentinel words around chunk boundaries"},
    ],
    analysis_rules=[
        "next_chunk->prev_size must equal current_chunk->size when current_chunk is free.",
        "Chunk size must be non-zero and aligned to heap quantum.",
        "Overwritten sentinel or canary word indicates heap buffer overflow from preceding chunk.",
    ],
    thresholds_and_conditions={"canary_expected": 0xDEADBEEF},
    supporting_evidence_criteria=[
        "Contiguous chunk link check fails (next->prev_size != current->size)",
        "Heap canary or guard bytes corrupted",
    ],
    contradicting_evidence_criteria=[
        "All contiguous chunk size fields and flags match bi-directionally across the audited range",
        "All canaries intact",
    ],
    verification_procedure="Perform bidirectional traversal across neighboring chunks to verify boundary tag consistency.",
    stop_conditions=["Boundary tag mismatch detected", "Audited chunk range verified intact"],
    limitations=["Only audits accessible chunks; custom internal pool allocators require specific layout metadata."],
    output_structure={"chunk_address": "str", "links_consistent": "bool", "canary_intact": "bool"},
))

_register(DiagnosticRecipe(
    recipe_id="RECIPE_SUSPICIOUS_ALLOCATION_PATTERNS",
    version="1.0.0",
    name="Suspicious Allocation / Deallocation Pattern Detector",
    domain=DOMAIN_MEMORY_INTEGRITY,
    observations=(OBS_MEMORY_INTEGRITY, OBS_PROCESS_INFO,),
    applicable_problem_categories=[CATEGORY_MEMORY_CORRUPTION, CATEGORY_MEMORY_LEAK],
    required_prerequisites=["memory_read_available"],
    evidence_sources=["allocator_counters", "pool_freelists", "thread_alloc_stats"],
    collection_steps=[
        {"step": 1, "action": "read_alloc_counters", "purpose": "Inspect total allocated blocks vs freed blocks across threads"},
        {"step": 2, "action": "inspect_size_distribution", "purpose": "Check for outlier allocation requests (e.g. negative or > 2GB)"},
        {"step": 3, "action": "detect_freelist_cycling", "purpose": "Detect rapid churn on identical slot without progress"},
    ],
    analysis_rules=[
        "Allocation request with size > 1GB or negative (when cast to signed) indicates arithmetic overflow.",
        "Single-slot allocation and free loop without payload update indicates thrashing or leak.",
    ],
    thresholds_and_conditions={"max_plausible_single_alloc_bytes": 1073741824},
    supporting_evidence_criteria=[
        "Observed allocation request exceeds max plausible size or is negative",
        "Allocation counter exceeds deallocation counter by > 100,000 without corresponding cache structure",
    ],
    contradicting_evidence_criteria=[
        "Allocation sizes follow normal power-of-two or pool bin distribution",
        "Net allocations reconcile with active object count",
    ],
    verification_procedure="Sample allocation statistics across temporal epochs to detect runaway imbalances.",
    stop_conditions=["Anomaly confirmed", "Normal allocation profile verified"],
    limitations=["Requires allocator statistics or thread-local heap cache visibility."],
    output_structure={"outlier_alloc_detected": "bool", "alloc_free_ratio": "float"},
))


# =============================================================================
# 4.2 Memory Growth and Leak Investigation Recipes
# =============================================================================

_register(DiagnosticRecipe(
    recipe_id="RECIPE_PROCESS_MEMORY_GROWTH",
    version="1.0.0",
    name="Process-Level Memory Growth & RSS Trajectory Investigation",
    domain=DOMAIN_MEMORY_GROWTH,
    observations=(OBS_MEMORY_GROWTH, OBS_PROCESS_INFO,),
    leak_investigation_rule=True,
    applicable_problem_categories=[CATEGORY_MEMORY_LEAK, CATEGORY_RESOURCE_EXHAUSTION],
    required_prerequisites=["memory_maps_available"],
    evidence_sources=["/proc/<pid>/status", "/proc/<pid>/statm", "/proc/<pid>/maps"],
    collection_steps=[
        {"step": 1, "action": "sample_vm_metrics", "purpose": "Record VmSize, VmRSS, VmData, and VmPeak across temporal epochs"},
        {"step": 2, "action": "diff_vma_maps", "purpose": "Compare /proc/<pid>/maps between epochs to identify growing regions"},
        {"step": 3, "action": "evaluate_growth_rate", "purpose": "Calculate monotonic growth velocity (bytes/second)"},
    ],
    analysis_rules=[
        "RSS growth across >= 3 temporal epochs with zero contraction indicates memory leak or unmanaged growth.",
        "Expansion of [heap] or new anonymous mmap regions correlates with unreleased dynamic allocations.",
        "If RSS growth is accompanied by idle work queue, leak is confirmed.",
    ],
    thresholds_and_conditions={"min_sample_epochs": 3, "growth_threshold_bytes": 1048576},
    supporting_evidence_criteria=[
        "Monotonic increase in VmRSS and VmData across >= 3 consecutive temporal epochs",
        "Continuous expansion of anonymous mapping size without contraction",
    ],
    contradicting_evidence_criteria=[
        "VmRSS stabilizes or decreases during measurement period",
        "Memory growth is accounted for by intentional cache with LRU eviction",
    ],
    verification_procedure="Sample /proc/<pid>/statm over >= 3 epochs separated by configurable intervals.",
    stop_conditions=["Monotonic growth confirmed", "Memory stabilization observed", "Budget exhausted"],
    limitations=["Cannot pinpoint specific C++ class leaking without heap symbol/type scanning."],
    output_structure={"rss_growth_bytes": "int", "growth_rate_bps": "float", "is_monotonic": "bool"},
))

_register(DiagnosticRecipe(
    recipe_id="RECIPE_HEAP_GROWTH",
    version="1.0.0",
    name="Heap Arena & Pool Expansion Investigation",
    domain=DOMAIN_MEMORY_GROWTH,
    observations=(OBS_MEMORY_GROWTH, OBS_PROCESS_INFO,),
    leak_investigation_rule=True,
    applicable_problem_categories=[CATEGORY_MEMORY_LEAK, CATEGORY_RESOURCE_EXHAUSTION],
    required_prerequisites=["memory_read_available", "heap_inspection_available"],
    evidence_sources=["heap_arenas", "pool_headers", "brk_boundary"],
    collection_steps=[
        {"step": 1, "action": "read_arena_stats", "purpose": "Read arena system memory, in-use bytes, and free chunk bytes"},
        {"step": 2, "action": "track_chunk_counts", "purpose": "Count total active heap chunks across size categories"},
        {"step": 3, "action": "evaluate_fragmentation", "purpose": "Differentiate external fragmentation from genuine allocation accumulation"},
    ],
    analysis_rules=[
        "Heap growth with in_use_bytes / total_arena_bytes > 0.85 indicates real allocation growth (not fragmentation).",
        "Heap growth with in_use_bytes stable and high free chunk count indicates allocator fragmentation.",
    ],
    thresholds_and_conditions={"in_use_ratio_threshold": 0.80},
    supporting_evidence_criteria=[
        "Active allocated bytes in heap arenas increase monotonically across epochs",
        "High utilization ratio indicates memory is held by live chunks rather than unmapped free space",
    ],
    contradicting_evidence_criteria=[
        "In-use bytes remain constant while arena size increases due to fragmentation",
        "Allocated chunks decrease or stabilize",
    ],
    verification_procedure="Inspect heap arena descriptor structures across multiple observation epochs.",
    stop_conditions=["Growth pattern classified as leak or fragmentation", "Observation timeout"],
    limitations=["Requires allocator arena descriptor readability."],
    output_structure={"arena_bytes": "int", "in_use_bytes": "int", "fragmentation_ratio": "float"},
))

_register(DiagnosticRecipe(
    recipe_id="RECIPE_ALLOCATION_FREE_IMBALANCE",
    version="1.0.0",
    name="Allocation / Free Imbalance & Leak Detector",
    domain=DOMAIN_MEMORY_GROWTH,
    observations=(OBS_MEMORY_GROWTH, OBS_PROCESS_INFO,),
    applicable_problem_categories=[CATEGORY_MEMORY_LEAK],
    required_prerequisites=["memory_read_available", "dwarf_symbols_available"],
    evidence_sources=["global_alloc_counters", "pool_active_counts", "freelist"],
    collection_steps=[
        {"step": 1, "action": "read_pool_counters", "purpose": "Read active_count, alloc_count, and free_count from pool header"},
        {"step": 2, "action": "check_delta", "purpose": "Measure delta_alloc - delta_free over time window"},
        {"step": 3, "action": "verify_quiescence", "purpose": "Verify imbalance persists when target is quiescent / idle"},
    ],
    analysis_rules=[
        "If delta_alloc > 0 and delta_free == 0 while processing transactions, objects are leaking.",
        "Pool active_count monotonically increasing towards capacity confirms pool exhaustion leak.",
    ],
    thresholds_and_conditions={"min_imbalance_count": 10},
    supporting_evidence_criteria=[
        "delta_alloc significantly exceeds delta_free across observation window",
        "Pool active_count increases without corresponding decrements",
    ],
    contradicting_evidence_criteria=[
        "delta_alloc matches delta_free over complete transaction cycles",
        "active_count returns to baseline after burst completion",
    ],
    verification_procedure="Sample pool header counters before and after an interval of work.",
    stop_conditions=["Imbalance verified", "Balance verified"],
    limitations=["Requires pool or allocator to maintain allocation/deallocation counters."],
    output_structure={"delta_alloc": "int", "delta_free": "int", "net_leak_count": "int"},
))

_register(DiagnosticRecipe(
    recipe_id="RECIPE_OBJECT_LIFETIME_ANOMALIES",
    version="1.0.0",
    name="Object Lifetime & Premature / Prolonged Retention Anomaly Detector",
    domain=DOMAIN_MEMORY_GROWTH,
    observations=(OBS_MEMORY_INTEGRITY, OBS_MEMORY_GROWTH, OBS_PROCESS_INFO,),
    applicable_problem_categories=[CATEGORY_MEMORY_LEAK, CATEGORY_FUNCTIONAL_STATE_INCONSISTENCY],
    required_prerequisites=["memory_read_available", "dwarf_symbols_available"],
    evidence_sources=["object_timestamps", "ref_counts", "session_tables"],
    collection_steps=[
        {"step": 1, "action": "scan_object_ages", "purpose": "Calculate age = current_epoch - object.creation_epoch"},
        {"step": 2, "action": "inspect_ref_counts", "purpose": "Check for reference count cycle or non-zero ref on expired objects"},
        {"step": 3, "action": "check_owner_alive", "purpose": "Verify if owning thread/session is still active"},
    ],
    analysis_rules=[
        "Object whose session or connection has terminated but ref_count > 0 is an orphaned leak.",
        "Object whose age exceeds maximum expected lifetime TTL by 5x is considered an anomaly.",
    ],
    thresholds_and_conditions={"max_age_multiplier": 5.0},
    supporting_evidence_criteria=[
        "Object retained in global table despite owning session being marked CLOSED or DEAD",
        "Circular reference count preventing object destruction",
    ],
    contradicting_evidence_criteria=[
        "All retained objects have active, living owning sessions",
        "Object ages stay strictly within configured TTL limits",
    ],
    verification_procedure="Cross-reference object owner IDs against active session / thread table.",
    stop_conditions=["Orphaned object identified", "All lifetimes validated"],
    limitations=["Requires objects to carry timestamp, age, or session association."],
    output_structure={"anomalous_objects_count": "int", "sample_orphan_ptr": "str"},
))

_register(DiagnosticRecipe(
    recipe_id="RECIPE_REPEATED_ALLOCATION_PATTERNS",
    version="1.0.0",
    name="Repeated Allocation Pattern & Growth Generator Detector",
    domain=DOMAIN_MEMORY_GROWTH,
    observations=(OBS_MEMORY_GROWTH, OBS_PROCESS_INFO,),
    applicable_problem_categories=[CATEGORY_MEMORY_LEAK, CATEGORY_RESOURCE_EXHAUSTION],
    required_prerequisites=["memory_read_available"],
    evidence_sources=["heap_chunks", "call_stacks", "sampling_profile"],
    collection_steps=[
        {"step": 1, "action": "aggregate_chunk_sizes", "purpose": "Group heap chunks by identical size and structure"},
        {"step": 2, "action": "identify_dominant_size", "purpose": "Find chunk size class growing at highest rate"},
        {"step": 3, "action": "match_type_by_size", "purpose": "Map dominant size to C++ class definitions using DWARF"},
    ],
    analysis_rules=[
        "If > 70% of new heap allocations belong to a single size class, target that class as the primary leak candidate.",
    ],
    thresholds_and_conditions={"dominant_class_ratio": 0.70},
    supporting_evidence_criteria=[
        "A single chunk size class accounts for majority of new allocations across epochs",
    ],
    contradicting_evidence_criteria=[
        "Allocation growth is evenly distributed across multiple unrelated sizes",
    ],
    verification_procedure="Compute size histogram of heap chunks across consecutive snapshots.",
    stop_conditions=["Dominant size class identified", "No dominant size class found"],
    limitations=["Requires heap chunk scanning or DWARF type matching."],
    output_structure={"dominant_size": "int", "count": "int", "candidate_types": "list"},
))

_register(DiagnosticRecipe(
    recipe_id="RECIPE_LONG_LIVED_OBJECT_ACCUMULATION",
    version="1.0.0",
    name="Long-Lived Object Accumulation in Containers / Caches",
    domain=DOMAIN_MEMORY_GROWTH,
    observations=(OBS_MEMORY_GROWTH, OBS_PROCESS_INFO,),
    leak_investigation_rule=True,
    applicable_problem_categories=[CATEGORY_MEMORY_LEAK, CATEGORY_RESOURCE_EXHAUSTION],
    required_prerequisites=["memory_read_available", "dwarf_symbols_available"],
    evidence_sources=["std::vector", "std::map", "std::list", "custom_hash_table"],
    collection_steps=[
        {"step": 1, "action": "read_container_size", "purpose": "Inspect size and capacity member variables of global/static containers"},
        {"step": 2, "action": "track_container_growth", "purpose": "Measure container size across multiple epochs"},
        {"step": 3, "action": "inspect_eviction_mechanism", "purpose": "Check if container has an eviction policy or capacity ceiling"},
    ],
    analysis_rules=[
        "Container with size strictly monotonically increasing without an upper bound is an unbounded cache leak.",
        "Container capacity repeatedly doubling (vector reallocation) without shrinking indicates accumulator leak.",
    ],
    thresholds_and_conditions={"max_safe_elements": 100000},
    supporting_evidence_criteria=[
        "Container element count increases monotonically without eviction or clear",
        "Container capacity exceeds safe threshold without configured maximum limit",
    ],
    contradicting_evidence_criteria=[
        "Container size reaches ceiling and stabilizes due to eviction (e.g. LRU/FIFO)",
        "Container is periodically cleared",
    ],
    verification_procedure="Read container size member variable over >= 3 observation epochs.",
    stop_conditions=["Unbounded accumulation confirmed", "Bounded capacity verified"],
    limitations=["Requires locating container root symbol in DWARF."],
    output_structure={"container_symbol": "str", "element_count": "int", "is_unbounded": "bool"},
))


# =============================================================================
# 4.3 Abnormal Runtime State Recipes
# =============================================================================

_register(DiagnosticRecipe(
    recipe_id="RECIPE_UNEXPECTED_VARIABLE_CHANGES",
    version="1.0.0",
    name="Unexpected Variable Mutation & Range Violation Investigation",
    domain=DOMAIN_ABNORMAL_STATE,
    observations=(OBS_RUNTIME_STATE, OBS_PROCESS_INFO,),
    applicable_problem_categories=[CATEGORY_ABNORMAL_VARIABLE_CHANGES, CATEGORY_FUNCTIONAL_STATE_INCONSISTENCY],
    required_prerequisites=["memory_read_available", "dwarf_symbols_available"],
    evidence_sources=["dwarf_variables", "memory_snapshots", "watch_expressions"],
    collection_steps=[
        {"step": 1, "action": "resolve_variable_dwarf", "purpose": "Resolve variable address, type, and expected bounds from DWARF"},
        {"step": 2, "action": "sample_variable_value", "purpose": "Read typed variable value across epochs using seqlock check"},
        {"step": 3, "action": "evaluate_domain_constraints", "purpose": "Verify value against min, max, enum, or invariant constraints"},
    ],
    analysis_rules=[
        "Variable value outside [min, max] domain bounds confirms unexpected state.",
        "Floating point NaN or Infinity in physical measurement field indicates arithmetic error or corruption.",
        "Monotonic sequence counter decreasing indicates state reset or corruption.",
    ],
    thresholds_and_conditions={"allow_nan": False, "allow_inf": False},
    supporting_evidence_criteria=[
        "Variable holds value outside defined domain limits across consistent reads",
        "NaN / Inf observed in numeric sensor or metric variable",
    ],
    contradicting_evidence_criteria=[
        "Variable value is within defined domain limits",
        "Value change follows legal state machine or business logic transition",
    ],
    verification_procedure="Perform consistent double-read of variable to rule out torn concurrent writes.",
    stop_conditions=["Range violation confirmed", "Normal range verified"],
    limitations=["Domain bounds must be known from DWARF enums, ranges, or user configuration."],
    output_structure={"variable_path": "str", "observed_value": "Any", "expected_range": "str", "violation": "bool"},
))

_register(DiagnosticRecipe(
    recipe_id="RECIPE_STATE_TRANSITION_VIOLATIONS",
    version="1.0.0",
    name="State Machine Transition Invariant Violation Audit",
    domain=DOMAIN_ABNORMAL_STATE,
    observations=(OBS_RUNTIME_STATE, OBS_PROCESS_INFO,),
    applicable_problem_categories=[CATEGORY_UNEXPECTED_STATE_TRANSITIONS, CATEGORY_FUNCTIONAL_STATE_INCONSISTENCY],
    required_prerequisites=["memory_read_available", "dwarf_symbols_available"],
    evidence_sources=["state_enums", "transition_tables", "temporal_snapshots"],
    collection_steps=[
        {"step": 1, "action": "sample_state_before", "purpose": "Record initial state enum value at epoch N"},
        {"step": 2, "action": "sample_state_after", "purpose": "Record subsequent state enum value at epoch N+1"},
        {"step": 3, "action": "validate_transition_edge", "purpose": "Verify transition edge (S_before -> S_after) in legal state graph"},
    ],
    analysis_rules=[
        "Transition from terminal state (e.g. CLOSED, TERMINATED) to active state without reinitialization is invalid.",
        "Direct jump skipping mandatory intermediate state (e.g. INIT -> RUNNING without READY) violates state invariant.",
    ],
    thresholds_and_conditions={"strict_forward_transitions": True, "terminal_states": ["CLOSED", "TERMINATED", "FAILED"]},
    supporting_evidence_criteria=[
        "Observed transition edge (S_before -> S_after) does not exist in state machine specification",
        "State transitioned backwards along a strictly forward state graph",
    ],
    contradicting_evidence_criteria=[
        "Transition edge matches legal state transition graph",
        "State did not change across observation window",
    ],
    verification_procedure="Compare pre- and post-observation state values against authorized state transition matrix.",
    stop_conditions=["Illegal transition confirmed", "Legal transition or no transition confirmed"],
    limitations=["Requires state transition graph definition or enum ordering constraints."],
    output_structure={"state_before": "str", "state_after": "str", "is_valid_transition": "bool"},
))

_register(DiagnosticRecipe(
    recipe_id="RECIPE_INCONSISTENT_RELATED_VARIABLES",
    version="1.0.0",
    name="Related Variable & Invariant Coupling Consistency Audit",
    domain=DOMAIN_ABNORMAL_STATE,
    observations=(OBS_RUNTIME_STATE, OBS_PROCESS_INFO,),
    applicable_problem_categories=[CATEGORY_FUNCTIONAL_STATE_INCONSISTENCY, CATEGORY_DATA_RACE_INDICATORS],
    required_prerequisites=["memory_read_available", "dwarf_symbols_available"],
    evidence_sources=["paired_variables", "struct_members", "atomic_pairs"],
    collection_steps=[
        {"step": 1, "action": "read_variable_pair", "purpose": "Read coupled variables (e.g. head/tail, count/capacity, flag/pointer)"},
        {"step": 2, "action": "verify_invariant_relation", "purpose": "Evaluate invariant equation (e.g. size <= capacity, head == tail -> count == 0)"},
        {"step": 3, "action": "double_read_quiescence", "purpose": "Repeat read to distinguish transient mid-update skew from persistent corruption"},
    ],
    analysis_rules=[
        "Invariant size <= capacity must hold for all valid buffer structures.",
        "flag == READY must imply pointer != NULL.",
        "Persistent violation across seqlock double-read indicates broken invariant or unsynchronized data race.",
    ],
    thresholds_and_conditions={"seqlock_read_retries": 3, "paired_variable_tolerance": 0},
    supporting_evidence_criteria=[
        "Relational invariant (e.g. size <= capacity) fails across consistent double-reads",
        "Status flag indicates data is ready while data pointer remains NULL",
    ],
    contradicting_evidence_criteria=[
        "All related variables satisfy relational invariants",
        "Apparent discrepancy was a transient torn read that resolved upon second read",
    ],
    verification_procedure="Read both variables atomically or using consistency check, evaluate relational predicate.",
    stop_conditions=["Inconsistency verified", "Consistency verified"],
    limitations=["Relational invariant rules must be specified or deduced from standard data structures."],
    output_structure={"variables": "list", "invariant_predicate": "str", "is_consistent": "bool"},
))

_register(DiagnosticRecipe(
    recipe_id="RECIPE_UNEXPECTED_NULL_OR_INVALID_POINTERS",
    version="1.0.0",
    name="Unexpected NULL & Invalid Pointer Member Audit",
    domain=DOMAIN_ABNORMAL_STATE,
    observations=(OBS_MEMORY_INTEGRITY, OBS_RUNTIME_STATE, OBS_PROCESS_INFO,),
    applicable_problem_categories=[CATEGORY_MEMORY_CORRUPTION, CATEGORY_ABNORMAL_VARIABLE_CHANGES],
    required_prerequisites=["memory_read_available", "dwarf_symbols_available"],
    evidence_sources=["struct_pointers", "object_vptrs", "interface_tables"],
    collection_steps=[
        {"step": 1, "action": "read_pointer_members", "purpose": "Inspect pointer members of initialized structs/objects"},
        {"step": 2, "action": "verify_nullness_rules", "purpose": "Check whether NULL is permitted in current object lifecycle state"},
        {"step": 3, "action": "verify_pointer_target_vma", "purpose": "Verify non-null pointers target valid mapped memory"},
    ],
    analysis_rules=[
        "Mandatory pointer field holding NULL in state READY or RUNNING is an invalid state.",
        "Object vtable pointer (_vptr) holding NULL or targeting unmapped memory confirms object corruption.",
    ],
    thresholds_and_conditions={"null_page_limit": 4096, "kernel_space_min": 0xFFFF800000000000},
    supporting_evidence_criteria=[
        "Mandatory pointer is NULL while object state is marked active",
        "Object _vptr is NULL or points to non-executable memory",
    ],
    contradicting_evidence_criteria=[
        "All mandatory pointers hold non-null, validly mapped targets",
        "NULL pointer is explicitly permitted in current object state",
    ],
    verification_procedure="Inspect pointer value and check against /proc/<pid>/maps VMA permissions.",
    stop_conditions=["Invalid pointer confirmed", "All pointers valid"],
    limitations=["Requires DWARF struct layout to distinguish mandatory vs optional pointers."],
    output_structure={"pointer_path": "str", "pointer_val": "str", "vptr_valid": "bool", "is_invalid": "bool"},
))

_register(DiagnosticRecipe(
    recipe_id="RECIPE_SUSPICIOUS_BOUNDARY_VALUES",
    version="1.0.0",
    name="Suspicious Boundary Value & Sentinel Corruption Detector",
    domain=DOMAIN_ABNORMAL_STATE,
    observations=(OBS_RUNTIME_STATE, OBS_PROCESS_INFO,),
    applicable_problem_categories=[CATEGORY_ABNORMAL_VARIABLE_CHANGES, CATEGORY_MEMORY_CORRUPTION],
    required_prerequisites=["memory_read_available"],
    evidence_sources=["integer_variables", "index_variables", "buffer_lengths"],
    collection_steps=[
        {"step": 1, "action": "read_integer_variable", "purpose": "Read integer or index value"},
        {"step": 2, "action": "test_boundary_extremes", "purpose": "Compare against INT_MAX, UINT_MAX, -1, 0x7FFFFFFF, 0xFFFFFFFF"},
        {"step": 3, "action": "inspect_neighbor_memory", "purpose": "Check if boundary value resulted from memory underflow/overflow"},
    ],
    analysis_rules=[
        "Unsigned count holding 0xFFFFFFFF or 0xFFFFFFFFFFFFFFFF typically indicates unsigned underflow (0 - 1).",
        "Array index holding -1 or >= buffer size confirms out-of-bounds index corruption.",
    ],
    thresholds_and_conditions={"sentinels": [0xFFFFFFFF, 0x7FFFFFFF, 0xFFFFFFFFFFFFFFFF, -1]},
    supporting_evidence_criteria=[
        "Count or length variable holds 0xFFFFFFFF or -1 in active state",
        "Array index variable equals or exceeds allocated buffer bound",
    ],
    contradicting_evidence_criteria=[
        "Variable holds normal expected index within [0, count - 1]",
        "Sentinel -1 is expected in idle / not-found state",
    ],
    verification_procedure="Inspect variable value and evaluate against array bound or signedness boundary tags.",
    stop_conditions=["Boundary anomaly confirmed", "Normal value confirmed"],
    limitations=["Requires knowing if -1 is used as an intentional NOT_FOUND sentinel."],
    output_structure={"variable_path": "str", "value": "int", "is_underflow_indicator": "bool"},
))


# =============================================================================
# 4.4 Thread and Synchronization Investigation Recipes
# =============================================================================

_register(DiagnosticRecipe(
    recipe_id="RECIPE_THREAD_STATE_ANOMALIES",
    version="1.0.0",
    name="Thread State Anomalies & Abnormal Thread Status Audit",
    domain=DOMAIN_CONCURRENCY,
    observations=(OBS_THREADS_AND_LOCKS, OBS_PROCESS_INFO,),
    applicable_problem_categories=[CATEGORY_DEADLOCK_INDICATORS, CATEGORY_PROCESS_INSTABILITY],
    required_prerequisites=["threads_available"],
    evidence_sources=["/proc/<pid>/task/", "/proc/<pid>/task/<tid>/status", "/proc/<pid>/task/<tid>/wchan"],
    collection_steps=[
        {"step": 1, "action": "enumerate_tids", "purpose": "Enumerate all thread IDs in target process"},
        {"step": 2, "action": "read_thread_states", "purpose": "Sample state flag (R, S, D, Z, T) and wait channel (wchan)"},
        {"step": 3, "action": "detect_stuck_d_state", "purpose": "Identify threads stuck in uninterruptible sleep (D state)"},
    ],
    analysis_rules=[
        "Thread in 'D' state (uninterruptible sleep) across multiple epochs indicates kernel/driver block or NFS hang.",
        "Zombie thread ('Z') remaining uncollected indicates parent process is failing to waitpid().",
        "All worker threads in 'S' state on futex while input queue has pending items indicates dead worker pool.",
    ],
    thresholds_and_conditions={"d_state_max_epochs": 2},
    supporting_evidence_criteria=[
        "Thread persists in 'D' state across >= 2 temporal observation samples",
        "Zombie thread remains present across observation epochs",
        "Worker threads asleep on futex with non-empty input work queue",
    ],
    contradicting_evidence_criteria=[
        "Thread state transitions between R and S normally as work arrives",
        "No threads in D or Z state",
    ],
    verification_procedure="Sample /proc/<pid>/task/<tid>/status across >= 2 epochs separated by wait time.",
    stop_conditions=["Thread anomaly confirmed", "All threads normal"],
    limitations=["Kernel internals for D-state threads require kernel tracing if wchan is generic."],
    output_structure={"anomalous_tids": "list", "d_state_count": "int", "zombie_count": "int"},
))

_register(DiagnosticRecipe(
    recipe_id="RECIPE_SUSPICIOUS_LOCK_OWNERSHIP",
    version="1.0.0",
    name="Suspicious Lock Ownership & Orphaned Mutex Audit",
    domain=DOMAIN_CONCURRENCY,
    observations=(OBS_THREADS_AND_LOCKS, OBS_PROCESS_INFO,),
    requires_lock_owner=True,
    applicable_problem_categories=[CATEGORY_DEADLOCK_INDICATORS, CATEGORY_DATA_RACE_INDICATORS],
    required_prerequisites=["threads_available", "memory_read_available"],
    evidence_sources=["pthread_mutex_t", "futex_words", "thread_stacks"],
    collection_steps=[
        {"step": 1, "action": "inspect_mutex_words", "purpose": "Read __owner field / lock word of active mutexes"},
        {"step": 2, "action": "verify_owner_liveness", "purpose": "Check whether owner TID corresponds to a living thread"},
        {"step": 3, "action": "check_owner_progress", "purpose": "Verify if lock owner thread is executing or blocked"},
    ],
    analysis_rules=[
        "Mutex whose owner TID does not exist in /proc/<pid>/task/ is an orphaned lock (thread terminated holding lock).",
        "Mutex held continuously across multiple epochs by thread in S state waiting on another resource indicates contention/deadlock.",
    ],
    thresholds_and_conditions={"max_held_duration_ms": 5000, "orphan_lock_check": True},
    supporting_evidence_criteria=[
        "Mutex owner TID does not match any running thread in the process (orphaned lock)",
        "Owner thread is asleep holding lock while multiple waiter threads are queued",
    ],
    contradicting_evidence_criteria=[
        "Mutex lock word indicates unlocked (owner == 0)",
        "Lock owner rapidly releases lock between observation samples",
    ],
    verification_procedure="Read mutex memory word, extract owner TID, cross-check against /proc/<pid>/task/ entries.",
    stop_conditions=["Orphaned lock confirmed", "Active stall confirmed", "Lock turnover observed"],
    limitations=["Requires standard pthread_mutex_t or known custom spinlock/futex memory layout."],
    output_structure={"mutex_address": "str", "owner_tid": "int", "owner_alive": "bool", "is_orphaned": "bool"},
))

_register(DiagnosticRecipe(
    recipe_id="RECIPE_POTENTIAL_DEADLOCK_PATTERNS",
    version="1.0.0",
    name="Potential Deadlock & Wait-For Graph Cycle Detector",
    domain=DOMAIN_CONCURRENCY,
    observations=(OBS_THREADS_AND_LOCKS, OBS_PROCESS_INFO,),
    requires_lock_owner=True,
    applicable_problem_categories=[CATEGORY_DEADLOCK_INDICATORS],
    required_prerequisites=["threads_available", "memory_read_available"],
    evidence_sources=["thread_callstacks", "mutex_owners", "wait_for_graph"],
    collection_steps=[
        {"step": 1, "action": "reconstruct_wait_graph", "purpose": "Map Thread -> Waiting_On_Lock -> Owned_By_Thread"},
        {"step": 2, "action": "find_graph_cycles", "purpose": "Execute Tarjan's cycle detection algorithm on wait-for graph"},
        {"step": 3, "action": "verify_cycle_persistence", "purpose": "Resample wait-for graph after delay to confirm cycle is persistent (not transient)"},
    ],
    analysis_rules=[
        "A closed directed cycle in the wait-for graph persisting across 2 observation samples confirms deadlock.",
        "A thread attempting to acquire a non-recursive mutex it already holds confirms self-deadlock.",
    ],
    thresholds_and_conditions={"min_persistence_samples": 2},
    supporting_evidence_criteria=[
        "Closed cycle detected in wait-for graph (e.g. T1 -> M1 -> T2 -> M2 -> T1)",
        "Identical cycle persists with zero instruction / progress change across consecutive samples",
    ],
    contradicting_evidence_criteria=[
        "Wait-for graph is an acyclic directed graph (DAG)",
        "Cycle resolves or thread advances between samples (transient handoff)",
    ],
    verification_procedure="Reconstruct wait-for graph and confirm cycle persistence across 2 observation epochs.",
    stop_conditions=["Deadlock cycle confirmed", "Graph verified acyclic"],
    limitations=["Requires callstack DWARF and mutex address resolution for all participating threads."],
    output_structure={"deadlock_detected": "bool", "cycle_tids": "list", "cycle_locks": "list"},
))

_register(DiagnosticRecipe(
    recipe_id="RECIPE_LONG_RUNNING_BLOCKED_THREADS",
    version="1.0.0",
    name="Long-Running Blocked Thread & Worker Stall Audit",
    domain=DOMAIN_CONCURRENCY,
    observations=(OBS_THREADS_AND_LOCKS, OBS_PROCESS_INFO,),
    requires_lock_owner=True,
    lock_owner_required_for_support=True,
    applicable_problem_categories=[CATEGORY_DEADLOCK_INDICATORS, CATEGORY_PROCESS_INSTABILITY],
    required_prerequisites=["threads_available"],
    evidence_sources=["/proc/<pid>/task/<tid>/stat", "callstacks", "progress_counters"],
    collection_steps=[
        {"step": 1, "action": "sample_thread_ticks", "purpose": "Record utime + stime and voluntary_ctxt_switches per thread"},
        {"step": 2, "action": "identify_zero_tick_threads", "purpose": "Identify worker threads with zero CPU tick progress"},
        {"step": 3, "action": "correlate_pending_work", "purpose": "Inspect application queue / work counter to determine if work is pending"},
    ],
    analysis_rules=[
        "Worker thread blocked with zero tick change and non-empty work queue indicates worker starvation / hang.",
        "Worker thread blocked with zero tick change and empty work queue indicates benign idle wait.",
    ],
    thresholds_and_conditions={"blocked_threshold_ms": 1000, "min_epoch_samples": 2},
    supporting_evidence_criteria=[
        "Worker thread callstack is stationary in blocking wait while queue has pending tasks",
        "Progress counter remains unchanged across temporal observation window",
    ],
    contradicting_evidence_criteria=[
        "Work queue is empty (benign idle wait)",
        "Thread CPU ticks (utime + stime) are advancing",
    ],
    verification_procedure="Sample thread CPU ticks and compare against task queue size across epochs.",
    stop_conditions=["Worker stall confirmed", "Benign idle confirmed"],
    limitations=["Requires application task queue counter to separate active stall from benign idle wait."],
    output_structure={"stalled_threads": "list", "is_benign_idle": "bool", "pending_work_count": "int"},
))

_register(DiagnosticRecipe(
    recipe_id="RECIPE_SHARED_STATE_INCONSISTENCIES",
    version="1.0.0",
    name="Shared State Inconsistency & Data Race Indicator Audit",
    domain=DOMAIN_CONCURRENCY,
    observations=(OBS_RUNTIME_STATE, OBS_THREADS_AND_LOCKS, OBS_PROCESS_INFO,),
    applicable_problem_categories=[CATEGORY_DATA_RACE_INDICATORS, CATEGORY_FUNCTIONAL_STATE_INCONSISTENCY],
    required_prerequisites=["memory_read_available", "dwarf_symbols_available"],
    evidence_sources=["shared_structs", "mutex_locks", "thread_stacks"],
    collection_steps=[
        {"step": 1, "action": "identify_shared_struct", "purpose": "Target shared struct accessed by multiple threads"},
        {"step": 2, "action": "sample_struct_fields", "purpose": "Perform rapid consecutive reads of struct fields"},
        {"step": 3, "action": "detect_torn_read", "purpose": "Check if paired fields show partial update / torn read signatures"},
    ],
    analysis_rules=[
        "Torn read detected where 64-bit integer or pointer has half-updated word indicates unsynchronized concurrent write.",
        "Multiple threads concurrently executing write frames on shared variable without holding protecting mutex indicates data race.",
    ],
    thresholds_and_conditions={"inconsistency_sample_limit": 5, "seqlock_retries": 3},
    supporting_evidence_criteria=[
        "Inconsistent / torn read observed on shared struct without lock protection",
        "Threads concurrently modifying shared memory without mutual exclusion",
    ],
    contradicting_evidence_criteria=[
        "All accesses to shared struct occur under protecting lock",
        "Reads are consistent across consecutive samples",
    ],
    verification_procedure="Perform rapid consecutive memory reads and correlate with thread callstack mutex frames.",
    stop_conditions=["Shared state inconsistency confirmed", "Synchronization confirmed"],
    limitations=["Sampling-based race detection can miss rare races; TSAN or eBPF provides higher coverage."],
    output_structure={"shared_variable": "str", "torn_read_detected": "bool", "unprotected_concurrent_access": "bool"},
))


# -----------------------------------------------------------------------------
# Recipe Registry Interface & Deterministic Evaluation
# -----------------------------------------------------------------------------

class DiagnosticRecipeRegistry:
    """Registry and lookup engine for versioned deterministic diagnostic recipes."""

    @classmethod
    def get_recipe(cls, recipe_id: str) -> Optional[DiagnosticRecipe]:
        return _RECIPES.get(recipe_id)

    @classmethod
    def list_recipes(cls, domain: Optional[str] = None) -> List[DiagnosticRecipe]:
        if domain:
            return [r for r in _RECIPES.values() if r.domain == domain]
        return list(_RECIPES.values())

    @classmethod
    def list_recipe_ids(cls, domain: Optional[str] = None) -> List[str]:
        return [r.recipe_id for r in cls.list_recipes(domain=domain)]

    @classmethod
    def get_recipes_for_category(cls, category: str) -> List[DiagnosticRecipe]:
        return cls.find_recipes_for_categories([category])

    @classmethod
    def find_recipes_for_categories(cls, categories: List[str]) -> List[DiagnosticRecipe]:
        matched: List[DiagnosticRecipe] = []
        cat_set = set(categories)
        for r in _RECIPES.values():
            if any(c in cat_set for c in r.applicable_problem_categories):
                matched.append(r)
        return matched

    @classmethod
    def evaluate_recipe(
        cls,
        recipe_or_id: Union[str, DiagnosticRecipe],
        observation_data: Dict[str, Any],
        prerequisites_met: bool = True,
    ) -> RecipeEvaluationResult:
        """Deterministically evaluates a recipe against observation data."""
        if isinstance(recipe_or_id, DiagnosticRecipe):
            recipe = recipe_or_id
            recipe_id = recipe.recipe_id
        else:
            recipe_id = str(recipe_or_id)
            recipe = cls.get_recipe(recipe_id)
        if not recipe:
            return RecipeEvaluationResult(
                recipe_id=recipe_id,
                status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
                confidence=0.0,
                confidence_basis="Recipe not registered.",
                missing_evidence=[f"Unknown recipe ID: {recipe_id}"],
            )

        if not prerequisites_met or observation_data.get("prerequisites_missing"):
            missing = list(observation_data.get("missing_prerequisites") or recipe.required_prerequisites)
            return RecipeEvaluationResult(
                recipe_id=recipe_id,
                status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
                confidence=0.0,
                confidence_basis=f"Required prerequisites missing: {missing}",
                missing_evidence=missing,
                limitations=list(recipe.limitations),
                recommended_action=f"Ensure prerequisites ({', '.join(missing)}) are satisfied before re-evaluating.",
                details={"prerequisites_met": False},
            )

        # Dispatch deterministic evaluation logic per recipe
        return _evaluate_specific_recipe(recipe, observation_data)


# -----------------------------------------------------------------------------
# IMP-008: rules over the multi-observation heap-walk investigation (extractor.leak_attribution)
# -----------------------------------------------------------------------------
_LEAK_VERDICTS = ("LEAK_UNREACHABLE", "UNBOUNDED_GROWTH_OWNED")
_NO_LEAK_VERDICTS = ("NO_GROWTH", "IN_USE_SHRANK", "NO_GROWTH_TREND")


def _leak_details(li: Dict[str, Any], extra: Dict[str, Any]) -> Dict[str, Any]:
    owned_only = li.get("verdict") == "UNBOUNDED_GROWTH_OWNED"
    d = {
        "finding_category": CATEGORY_MEMORY_LEAK,
        "leak_verdict": li.get("verdict"),
        "leak_confirmed": li.get("verdict") == "LEAK_UNREACHABLE",
        "finding_summary": li.get("summary"),
        "rate_kb_per_sec": li.get("rate_kb_per_s"),
        "limitations": list(li.get("limitations") or []),
    }
    if owned_only:
        roots = ", ".join(dict.fromkeys(str(o.get("variable")) for o in li.get("growth_owners") or []))
        d["certainty_cap"] = "PROBABLE"
        d["certainty_cap_reason"] = (
            "the growing blocks are still referenced from %s: unbounded growth under that owner over the "
            "observation window; whether it is a leak or intended accumulation cannot be decided from memory" % roots)
    d.update(extra)
    return d


def _evaluate_leak_investigation(recipe: "DiagnosticRecipe", data: Dict[str, Any]) -> Optional[RecipeEvaluationResult]:
    """Evaluation of the memory recipes from the IMP-008 investigation; None = use the legacy rules."""
    li = data.get("leak_investigation")
    if not isinstance(li, dict) or not li.get("verdict"):
        return None
    rid = recipe.recipe_id
    verdict = li["verdict"]
    walks = int(li.get("walks") or 0)
    lims = list(li.get("limitations") or [])
    facts = list(li.get("facts") or [])
    if verdict == "LEAK_OWNER_UNSUPPORTED":
        return None
    if rid != "RECIPE_PROCESS_MEMORY_GROWTH" and walks == 0:
        return None                                  # follow-ups without walk data: legacy rules
    if rid == "RECIPE_LONG_LIVED_OBJECT_ACCUMULATION" and verdict in _NO_LEAK_VERDICTS:
        # no growth in the window says nothing about a container that is ALREADY large: keep the legacy census
        # rules (container size / object counts) for that question
        return None
    trend = data.get("memory_trend") or {}
    if verdict in _LEAK_VERDICTS:
        if rid == "RECIPE_LONG_LIVED_OBJECT_ACCUMULATION" and not li.get("growth_owners"):
            return RecipeEvaluationResult(
                recipe_id=rid, status=RECIPE_STATUS_NOT_APPLICABLE, confidence=0.9,
                confidence_basis="The growing blocks are unreachable: no container retains them.",
                not_applicable_reason="growing blocks have no reachable owner (no retaining container)",
                details={"object_accumulation_confirmed": False, "limitations": lims},
            )
        if rid == "RECIPE_LONG_LIVED_OBJECT_ACCUMULATION":
            own = [f for f in facts if f.startswith("unbounded growth under")]
            o = li["growth_owners"][0]
            return RecipeEvaluationResult(
                recipe_id=rid, status=RECIPE_STATUS_SUPPORTED, confidence=0.85,
                confidence_basis="; ".join(own) or str(li.get("summary")),
                supporting_facts=own or [str(li.get("summary"))],
                recommended_action="Inspect the eviction / capacity policy of the growing owner.",
                details=_leak_details(li, {"object_accumulation_confirmed": True, "container_symbol": o.get("variable"),
                                           "retained_count": o.get("blocks_delta"), "is_unbounded": True}),
            )
        if rid == "RECIPE_HEAP_GROWTH":
            if li.get("in_use_monotonic_growth") is False:
                rows = list(li.get("unreachable_growth") or []) + list(li.get("growth_owners") or [])
                fact = ("in-use heap rose and fell across %d heap walks over %.2f s, but +%d KB of blocks under it "
                        "grew across every walk"
                        % (walks, float(li.get("window_s") or 0.0),
                           sum(int(r.get("bytes_delta") or 0) for r in rows) // 1024))
            else:
                fact = ("in-use heap grew +%d KB (+%d blocks) across %d heap walks over %.2f s, without a drop"
                        % (int(li.get("in_use_growth_bytes") or 0) // 1024, int(li.get("in_use_growth_blocks") or 0),
                           walks, float(li.get("window_s") or 0.0)))
            return RecipeEvaluationResult(
                recipe_id=rid, status=RECIPE_STATUS_SUPPORTED, confidence=0.9, confidence_basis=fact,
                supporting_facts=[fact],
                recommended_action="See the leak attribution (owner path / unreachable size classes).",
                details=_leak_details(li, {"heap_growth_confirmed": True,
                                           "heap_growth_bytes": li.get("in_use_growth_bytes"),
                                           "live_leak_confirmed": verdict == "LEAK_UNREACHABLE"}),
            )
        return RecipeEvaluationResult(
            recipe_id=rid, status=RECIPE_STATUS_SUPPORTED,
            confidence=0.95 if verdict == "LEAK_UNREACHABLE" else 0.85,
            confidence_basis=str(li.get("summary")),
            supporting_facts=facts or [str(li.get("summary"))],
            limitations=lims,
            recommended_action=("Find where the unreachable blocks lose their last reference." if verdict ==
                                "LEAK_UNREACHABLE" else "Check whether the growing owner has an upper bound."),
            details=_leak_details(li, {"growth_confirmed": True,
                                       "classification": "CONFIRMED_LEAK" if verdict == "LEAK_UNREACHABLE"
                                       else "OBJECT_ACCUMULATION"}),
        )
    rss_grew = bool(trend.get("indicates_growth"))
    if verdict in _NO_LEAK_VERDICTS and not (verdict == "NO_GROWTH" and rss_grew):
        txt = str(li.get("summary") or verdict)
        return RecipeEvaluationResult(
            recipe_id=rid, status=RECIPE_STATUS_CONTRADICTED, confidence=0.9, confidence_basis=txt,
            contradicting_facts=[txt],
            recommended_action="Refute unmanaged memory growth in the observation window.",
            details={"growth_confirmed": False, "leak_verdict": verdict, "limitations": lims,
                     "transient_warmup": verdict == "IN_USE_SHRANK"},
        )
    if verdict == "NO_GROWTH" and rss_grew:
        lims = lims + ["growth observed, not established as a leak: RSS %+d KB but in-use heap %+d KB over the "
                       "walks (fragmentation, file / anonymous mappings outside malloc, or allocator caching)"
                       % (int(trend.get("rss_growth_kb") or 0), int(li.get("in_use_growth_bytes") or 0) // 1024)]
    return RecipeEvaluationResult(
        recipe_id=rid, status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE, confidence=0.3,
        confidence_basis="; ".join(lims) or str(li.get("summary") or verdict),
        missing_evidence=["heap_growth_attributed_to_unreachable_blocks_or_an_owner"],
        limitations=lims,
        details={"growth_confirmed": False, "leak_verdict": verdict, "limitations": lims},
    )


_NAME_HINT_CAP_REASON = ("the only corruption evidence is a variable whose name suggests a canary / magic / guard "
                         "holding a poison constant: a hint, not proof of damage (IMP-009)")


def _name_hint_only(data: Dict[str, Any]) -> bool:
    """The legacy corruption signal comes only from the variable-name / poison-value heuristic of the provider
    (``magic_corrupted`` / ``chunk_state == CORRUPTED``), with no observed fault context."""
    hint = bool(data.get("magic_corrupted")) or data.get("chunk_state") == "CORRUPTED" \
        or data.get("canary_corrupted") is True
    other = bool(data.get("fault_context") or data.get("is_fault_address") or data.get("dereferenced")
                 or data.get("object_valid") is False
                 or data.get("violation_type") not in (None, "NONE", "NONE_VALID_VMA"))
    return hint and not other


def _cap_name_hint(res: "RecipeEvaluationResult", data: Dict[str, Any]) -> "RecipeEvaluationResult":
    if res.status == RECIPE_STATUS_SUPPORTED and _name_hint_only(data):
        res.details = dict(res.details or {}, certainty_cap="PROBABLE", certainty_cap_reason=_NAME_HINT_CAP_REASON,
                           corruption_hint_only=True)
    return res


def _evaluate_integrity_investigation(recipe: "DiagnosticRecipe", data: Dict[str, Any]) -> Optional[RecipeEvaluationResult]:
    """IMP-009: RECIPE_HEAP_METADATA_CORRUPTION from the memory-integrity investigation (extractor.memory_integrity).

    * a stable damaged heap header whose previous chunk has a named owner, with an impossible header value or a
      content pattern continuing the buffer -> SUPPORTED, corruption confirmed (MEMORY_CORRUPTION);
    * other stable heap damage (owner unknown, free-list pointers, links), undersized-for-type blocks and global
      adjacent-overwrite candidates -> SUPPORTED capped at probable;
    * stack margin below the threshold only -> SUPPORTED, RESOURCE_EXHAUSTION, capped at probable, WARNING
      severity (an SP at / inside the guard region is STACK_CORRUPTION);
    * the heap was checked and nothing is damaged (the name/poison hint alone does not count) -> CONTRADICTED;
    * heap not checked (cap, unsupported, budget) and nothing else found -> INSUFFICIENT_EVIDENCE.
    None when there is no integrity record (legacy rules)."""
    mi = data.get("memory_integrity")
    if not isinstance(mi, dict):
        return None
    rid = recipe.recipe_id
    heap = mi.get("heap") or {}
    defects = list(heap.get("defects") or [])
    # free-list damage inside a FREE chunk that a typed pointer still refers to was written through that dangling
    # pointer: it is reported as USE_AFTER_FREE (here and by the use-after-free recipe), not as an overflow
    uaf_defects = [d for d in defects if d.get("use_after_free")]
    defects = [d for d in defects if not d.get("use_after_free")]
    undersized = list(heap.get("undersized_allocations") or [])
    glob = list((mi.get("globals") or {}).get("candidates") or [])
    stack_w = list((mi.get("stacks") or {}).get("warnings") or [])
    lims = list(mi.get("limitations") or [])
    hint = bool(data.get("magic_corrupted"))
    facts = [d["description"] for d in defects] + [u["description"] for u in undersized] + \
        [g["description"] for g in glob]
    stack_facts = [w["description"] for w in stack_w]
    confirmed = any(d.get("status") == "confirmed" for d in defects)
    base = {"memory_integrity_mode": mi.get("mode"), "heap_check_status": heap.get("status"), "limitations": lims}
    if facts:
        d = dict(base, finding_category=CATEGORY_MEMORY_CORRUPTION, corruption_confirmed=confirmed,
                 finding_summary="; ".join(facts[:4]))
        if not confirmed:
            why = []
            if defects:
                why.append("heap metadata damage whose overflowing block has no named owner, or free-list / link "
                           "damage (overflow or use-after-free write)")
            if undersized:
                why.append("a block smaller than the type of the pointer that reaches it")
            if glob:
                why.append("a global with an invalid value right after a full array (adjacent-overwrite candidate)")
            d["certainty_cap"] = "PROBABLE"
            d["certainty_cap_reason"] = "memory damage observed but not attributable with certainty: " + "; ".join(why)
        if hint:
            facts.append("additional hint: %s holds poison value %s" % (data.get("corruption_hint_variable"),
                                                                        data.get("observed_magic")))
        return RecipeEvaluationResult(
            recipe_id=rid, status=RECIPE_STATUS_SUPPORTED, confidence=0.95 if confirmed else 0.75,
            confidence_basis=facts[0], supporting_facts=facts + stack_facts, limitations=lims,
            recommended_action="Bound the writes into the named buffer (size of the copy / string length) and "
                               "rebuild with AddressSanitizer to find the write site.",
            details=d)
    if uaf_defects:
        uf = [d["description"] for d in uaf_defects]
        return RecipeEvaluationResult(
            recipe_id=rid, status=RECIPE_STATUS_SUPPORTED, confidence=0.9, confidence_basis=uf[0],
            supporting_facts=uf + stack_facts, limitations=lims,
            recommended_action="Clear the named pointer when its block is freed (or stop using it after free); "
                               "rebuild with AddressSanitizer to find the write site.",
            details=dict(base, finding_category=CATEGORY_USE_AFTER_FREE, corruption_confirmed=False,
                         finding_summary="; ".join(uf[:4]), certainty_cap="PROBABLE",
                         certainty_cap_reason="free-list damage seen by the integrity walk; the use-after-free check "
                                              "decides whether it is confirmed"))
    if stack_w:
        guard = [w for w in stack_w if w.get("kind") == "SP_IN_GUARD"]
        return RecipeEvaluationResult(
            recipe_id=rid, status=RECIPE_STATUS_SUPPORTED, confidence=0.9 if guard else 0.7,
            confidence_basis=stack_facts[0], supporting_facts=stack_facts, limitations=lims,
            recommended_action="Reduce recursion depth / large stack locals or raise the thread's stack size.",
            details=dict(base, finding_category=CATEGORY_STACK_CORRUPTION if guard else CATEGORY_RESOURCE_EXHAUSTION,
                         finding_severity="HIGH" if guard else "WARNING",
                         **({} if guard else {"certainty_cap": "PROBABLE",
                                              "certainty_cap_reason": "stack nearly exhausted: a warning, not a "
                                                                      "fault (the guard region was not reached)"})))
    if heap.get("status") in ("COMPLETED", "PARTIAL") and not hint:
        chk = heap.get("checked") or {}
        txt = ("heap metadata intact: %d chunks walked, top chunk(s), free lists and bin links consistent%s"
               % (int(chk.get("chunks") or 0),
                  ("; %d inconsistent read(s) changed between re-reads (target mutating the heap), not evidence"
                   % len(heap.get("inconsistent_reads_not_evidence") or []))
                  if heap.get("inconsistent_reads_not_evidence") else ""))
        return RecipeEvaluationResult(
            recipe_id=rid, status=RECIPE_STATUS_CONTRADICTED, confidence=0.85, confidence_basis=txt,
            contradicting_facts=[txt], limitations=lims,
            recommended_action="Refute heap metadata corruption in the walked heap.",
            details=dict(base, corruption_confirmed=False))
    if hint:
        return None                          # legacy (capped) rule for the name/poison hint
    return RecipeEvaluationResult(
        recipe_id=rid, status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE, confidence=0.2,
        confidence_basis="; ".join(lims) or "heap integrity not checked",
        missing_evidence=["heap_integrity_walk"], limitations=lims, details=dict(base, corruption_confirmed=False))


def _evaluate_specific_recipe(recipe: DiagnosticRecipe, data: Dict[str, Any]) -> RecipeEvaluationResult:
    rid = recipe.recipe_id
    if recipe.leak_investigation_rule:
        _li_res = _evaluate_leak_investigation(recipe, data)
        if _li_res is not None:
            return _li_res
    if recipe.integrity_investigation_rule:
        _mi_res = _evaluate_integrity_investigation(recipe, data)
        if _mi_res is not None:
            return _mi_res
    if recipe.name_hint_capped:
        # IMP-009: the name/poison-value heuristic can no longer confirm corruption on its own
        return _cap_name_hint(_evaluate_specific_recipe_rules(recipe, data), data)
    res = _evaluate_specific_recipe_rules(recipe, data)
    if recipe.requires_lock_owner and data.get("lock_owner_unsupported") \
            and not res.details.get("long_wait_threads") \
            and (res.status != RECIPE_STATUS_SUPPORTED or recipe.lock_owner_required_for_support):
        # a stall without decodable owners cannot be attributed to a lock/deadlock: report it as not evaluable
        out = _lock_owner_not_evaluable(recipe, data)
        if res.status == RECIPE_STATUS_SUPPORTED:
            out.confidence_basis += " Observed (not attributable): " + str(res.confidence_basis)
        return out
    return res


# Recipes whose "nothing found" verdict is only meaningful when mutex owners could be decoded.
_LOCK_OWNER_DEPENDENT_RECIPES = frozenset({
    "RECIPE_POTENTIAL_DEADLOCK_PATTERNS", "RECIPE_SUSPICIOUS_LOCK_OWNERSHIP",
    "RECIPE_LONG_RUNNING_BLOCKED_THREADS"})


def recipe_requires_lock_owner(recipe_id: str) -> bool:
    """Declared by the recipe (``requires_lock_owner``): its "nothing found" needs decodable mutex owners."""
    r = _RECIPES.get(recipe_id)
    return bool(r and r.requires_lock_owner)


def _lock_owner_not_evaluable(recipe: "DiagnosticRecipe", data: Dict[str, Any]) -> RecipeEvaluationResult:
    status = data.get("lock_owner_status") or "NOT_SUPPORTED_ON_TARGET"
    reason = data.get("lock_owner_status_reason") or ""
    why = f"lock-owner decoding is not supported on this target ({status}){': ' + reason if reason else ''}"
    return RecipeEvaluationResult(
        recipe_id=recipe.recipe_id,
        status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
        confidence=0.0,
        confidence_basis=f"Not checked: {why}. An empty wait-for graph here is not evidence of absence.",
        missing_evidence=["lock_owner_decoding"],
        limitations=list(recipe.limitations) + [f"not supported on this target: {why}"],
        details={"reason": f"not supported on this target: {why}", "lock_owner_status": status,
                 "lock_owner_unsupported": True},
    )


def _evaluate_specific_recipe_rules(recipe: DiagnosticRecipe, data: Dict[str, Any]) -> RecipeEvaluationResult:
    rid = recipe.recipe_id

    # IMP-018: the verdict rule is the one the recipe declares (DiagnosticRecipe.rule); no recipe_id ladder.
    rule = recipe.rule or _RULES.get(rid)
    if rule is not None:
        res = rule(recipe, data)
        if res is not None:
            return res

    _NON_JSON_KEYS = {
        "allocator_inspector", "allocator", "structural_discovery",
        "invariant_evaluator", "concurrency_graph", "wait_for_graph",
        "observation_window", "window", "ledger", "adapter",
    }
    safe_data = {
        k: v for k, v in data.items()
        if k not in _NON_JSON_KEYS and isinstance(v, (str, int, float, bool, list, dict, type(None)))
    }
    pos_evidence = data.get("positive_evidence_found", False)
    neg_evidence = data.get("negative_evidence_found", False)
    if pos_evidence and not neg_evidence:
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_SUPPORTED,
            confidence=0.85,
            confidence_basis=f"Deterministic criteria for recipe {recipe.name} satisfied.",
            supporting_facts=list(data.get("supporting_facts", ["Criteria verified by observation."])),
            recommended_action=f"Remediate {recipe.name} anomaly.",
            details=safe_data,
        )
    elif neg_evidence and not pos_evidence:
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_CONTRADICTED,
            confidence=0.85,
            confidence_basis=f"Counter-indicators observed for recipe {recipe.name}.",
            contradicting_facts=list(data.get("contradicting_facts", ["Counter-criteria verified."])),
            recommended_action=f"Refute {recipe.name} anomaly.",
            details=safe_data,
        )
    elif pos_evidence and neg_evidence:
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_AMBIGUOUS,
            confidence=0.50,
            confidence_basis="Conflicting positive and counter-indicators observed.",
            supporting_facts=list(data.get("supporting_facts", [])),
            contradicting_facts=list(data.get("contradicting_facts", [])),
            details=safe_data,
        )
    return RecipeEvaluationResult(
        recipe_id=rid,
        status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
        confidence=0.10,
        confidence_basis="Insufficient evidence collected to evaluate recipe criteria.",
        missing_evidence=["observation_evidence"],
        limitations=recipe.limitations,
    )


# -----------------------------------------------------------------------------
# IMP-018: per-recipe verdict rules (each was one branch of a recipe_id if/elif ladder)
# -----------------------------------------------------------------------------

def _rule_invalid_memory_access(recipe: DiagnosticRecipe, data: Dict[str, Any]) -> Optional[RecipeEvaluationResult]:
    """Verdict rule of RECIPE_INVALID_MEMORY_ACCESS (None: no rule matched; the generic rule decides)."""
    rid = recipe.recipe_id
    if data.get("violation_type") == "NONE" or data.get("is_healthy"):
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_CONTRADICTED,
            confidence=0.90,
            confidence_basis="Target process has no active invalid memory accesses; pointers are valid or quiescent.",
            contradicting_facts=["No faulting or invalid memory accesses observed"],
            recommended_action="Refute invalid memory access anomaly.",
            details={"violation_type": "NONE"},
        )

    addr = (
        data.get("faulting_address")
        or data.get("target_address")
        or data.get("fault_address")
        or data.get("pointer_address")
        or data.get("pointer_value")
        or data.get("address")
    )
    is_mapped = data.get("is_mapped")
    perms = data.get("vma_permissions") or data.get("region_permissions") or data.get("permissions", "")

    if addr is None:
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
            confidence=0.0,
            confidence_basis="Target address was not provided in observation.",
            missing_evidence=["faulting_address"],
            limitations=recipe.limitations,
        )
    try:
        addr_int = int(addr, 16) if isinstance(addr, str) and addr.startswith("0x") else int(addr)
    except Exception:
        addr_int = -1

    if "maps" in data and is_mapped is None and addr_int >= 0:
        for m in data["maps"]:
            if m.get("start", 0) <= addr_int < m.get("end", 0):
                is_mapped = True
                perms = perms or m.get("perms", "")
                break
        if is_mapped is None:
            is_mapped = False

    if perms and is_mapped is None:
        is_mapped = not ("---" in perms)

    is_crash_or_fault = bool(
        data.get("fault_context")
        or data.get("is_fault_address")
        or data.get("dereferenced")
        or data.get("violation_type") in ("NULL_POINTER_DEREFERENCE", "UNMAPPED_OR_GUARD_PAGE")
        or data.get("chunk_state") == "CORRUPTED"
        or data.get("magic_corrupted")
        or (data.get("violation_type") and data.get("violation_type") not in ("NONE", "NONE_VALID_VMA"))
    )

    # Distinguish clean idle null pointer (Scenario B) from actual null pointer dereference
    if addr_int == 0:
        if not is_crash_or_fault and (data.get("is_healthy") or data.get("is_null_allowed", True)):
            return RecipeEvaluationResult(
                recipe_id=rid,
                status=RECIPE_STATUS_CONTRADICTED,
                confidence=0.92,
                confidence_basis="Target pointer is NULL in clean idle state without dereference fault or invariant violation. Memory integrity preserved.",
                contradicting_facts=["Clean NULL pointer in idle state; zero fault indicators"],
                recommended_action="Refute invalid memory access; pointer is intentionally NULL.",
                details={"violation_type": "NONE_IDLE_NULL_POINTER", "is_healthy": True},
            )
        else:
            return RecipeEvaluationResult(
                recipe_id=rid,
                status=RECIPE_STATUS_SUPPORTED,
                confidence=0.98,
                confidence_basis="Address 0x0 was dereferenced in fault context. NULL pointer dereference confirmed.",
                supporting_facts=["Target address 0x0 dereferenced in fault context"],
                recommended_action="Trace pointer origin to identify uninitialized or failed allocation return.",
                details={"violation_type": "NULL_POINTER_DEREFERENCE"},
            )

    if 0 < addr_int <= 4096:
        # Case A: Low pointer address without dereference must NOT be reported as an actual access fault!
        is_dereferenced = bool(
            data.get("dereferenced")
            or data.get("fault_context")
            or data.get("is_fault_address")
            or "fault_address" in data
            or data.get("chunk_state") == "CORRUPTED"
            or data.get("magic_corrupted")
        )
        if not is_dereferenced and data.get("dereference_attempted") is False:
            return RecipeEvaluationResult(
                recipe_id=rid,
                status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
                confidence=0.88,
                confidence_basis=f"Address {hex(addr_int)} is in low-memory range [0x1, 0x1000] but no dereference was attempted or observed in execution context. Access fault cannot be confirmed.",
                contradicting_facts=["Low pointer without dereference is not an access fault"],
                not_applicable_reason="Dereference was not attempted on low pointer value",
                recommended_action="Refute access violation; monitor for subsequent dereference attempts.",
                details={"violation_type": "SUSPICIOUS_POINTER_VALUE", "access_fault_confirmed": False},
            )
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_SUPPORTED,
            confidence=0.98,
            confidence_basis=f"Address {hex(addr_int)} is within NULL guard page [0x1, 0x1000] and was accessed or involved in fault. Invalid low-memory access confirmed.",
            supporting_facts=[f"Target address {addr} is within NULL guard page [0x1, 0x1000]"],
            recommended_action="Trace pointer origin to identify uninitialized or failed allocation return.",
            details={"violation_type": "CONFIRMED_INVALID_DEREFERENCE", "access_fault_confirmed": True},
        )
    if is_mapped is False or (perms and "---p" in perms):
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_SUPPORTED,
            confidence=0.95,
            confidence_basis=f"Target address {addr} does not fall within readable VMA or targets guard page ({perms}).",
            supporting_facts=[f"Address {addr} is unmapped or guard page ({perms})"],
            recommended_action="Inspect callstack and pointer registers to locate unmapped / guard violation.",
            details={"violation_type": "UNMAPPED_OR_GUARD_PAGE", "access_fault_confirmed": True},
        )
    if is_mapped is True and ("r" in perms or "w" in perms or "x" in perms):
        # Case B: A mapped pointer is not proof that the object is valid!
        if data.get("object_valid") is False or data.get("magic_corrupted") or data.get("chunk_state") == "CORRUPTED":
            return RecipeEvaluationResult(
                recipe_id=rid,
                status=RECIPE_STATUS_SUPPORTED,
                confidence=0.92,
                confidence_basis=f"Target address {addr} resides in mapped VMA ({perms}) but referenced object metadata or canary is corrupted. Semantic object validity failed.",
                supporting_facts=["Mapped address references semantically invalid or corrupted object header"],
                recommended_action="Audit memory write sites targeting this object.",
                details={"violation_type": "CORRUPTED_OBJECT_HEADER", "object_valid": False, "access_fault_confirmed": True, "corrupted_object_header": True, "root_cause": "CORRUPTED_OBJECT_HEADER"},
            )
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_CONTRADICTED,
            confidence=0.90,
            confidence_basis=f"Target address {addr} is safely within a validly mapped VMA with permissions '{perms}'.",
            contradicting_facts=[f"Address {addr} resides in validly mapped VMA ({perms})"],
            recommended_action="Refute invalid memory access; evaluate internal data integrity.",
            details={"violation_type": "NONE_VALID_VMA", "object_valid": True, "access_fault_confirmed": False},
        )
    return RecipeEvaluationResult(
        recipe_id=rid,
        status=RECIPE_STATUS_AMBIGUOUS,
        confidence=0.40,
        confidence_basis="Address mapping is ambiguous or changed during read.",
        missing_evidence=["stable_vma_mapping"],
        limitations=recipe.limitations,
    )
    return None


def _rule_invalid_free(recipe: DiagnosticRecipe, data: Dict[str, Any]) -> Optional[RecipeEvaluationResult]:
    """Verdict rule of RECIPE_INVALID_FREE (None: no rule matched; the generic rule decides)."""
    rid = recipe.recipe_id
    alloc_insp = data.get("allocator_inspector") or data.get("allocator")
    ptr_addr = data.get("pointer_address") if "pointer_address" in data else (data.get("target_address") if "target_address" in data else data.get("address"))
    maps = data.get("maps") or data.get("proc_maps") or []
    if alloc_insp and ptr_addr is not None:
        val_res = alloc_insp.validate_free_target(ptr_addr, maps=maps)
        if not val_res.is_valid:
            return RecipeEvaluationResult(
                recipe_id=rid,
                status=RECIPE_STATUS_SUPPORTED,
                confidence=0.98,
                confidence_basis=f"Invalid free target detected ({val_res.outcome.value}): {val_res.reason}",
                supporting_facts=[val_res.reason],
                recommended_action="Ensure free() is only called on dynamically allocated heap memory chunks.",
                details={"is_invalid_free": True, "outcome": val_res.outcome.value, "reason": val_res.reason},
            )
        elif val_res.outcome == FreeValidationOutcome.FREE_TARGET_UNKNOWN_ALLOCATOR:
            return RecipeEvaluationResult(
                recipe_id=rid,
                status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
                confidence=0.25,
                confidence_basis=f"Cannot validate free target: {val_res.reason}",
                missing_evidence=["allocator_specification"],
                limitations=recipe.limitations,
                details={"is_invalid_free": False, "outcome": val_res.outcome.value},
            )
        else:
            return RecipeEvaluationResult(
                recipe_id=rid,
                status=RECIPE_STATUS_CONTRADICTED,
                confidence=0.92,
                confidence_basis=f"Target pointer is a valid free target: {val_res.reason}",
                contradicting_facts=["Pointer is a valid free target"] + ([val_res.reason] if val_res.reason else []),
                recommended_action="Refute invalid free; verify chunk lifetime and deallocation count.",
                details={"is_invalid_free": False, "outcome": val_res.outcome.value},
            )

    aligned = data.get("alignment_valid")
    vma_name = data.get("vma_name") or data.get("mapped_region") or ""
    if aligned is False or any(seg in vma_name for seg in ("[stack]", ".data", ".rodata", ".bss")):
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_SUPPORTED,
            confidence=0.97,
            confidence_basis=f"Pointer does not point to valid heap chunk (vma={vma_name}). Invalid free confirmed.",
            supporting_facts=[f"Pointer resides in segment {vma_name}"],
            recommended_action="Ensure free() is only called on dynamically allocated heap memory.",
            details={"is_invalid_free": True},
        )
    if (aligned is True or aligned is None) and ("[heap]" in vma_name or "anon" in vma_name):
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_CONTRADICTED,
            confidence=0.88,
            confidence_basis="Pointer is properly aligned and resides in heap allocation VMA.",
            contradicting_facts=["Pointer aligned to quantum", f"VMA {vma_name} is valid heap"],
            recommended_action="Refute invalid free; verify heap chunk metadata.",
            details={"is_invalid_free": False},
        )
    return RecipeEvaluationResult(
        recipe_id=rid,
        status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
        confidence=0.30,
        confidence_basis="Pointer VMA mapping or alignment could not be determined.",
        missing_evidence=["vma_region_info"],
        limitations=recipe.limitations,
    )
    return None


def _rule_use_after_free(recipe: DiagnosticRecipe, data: Dict[str, Any]) -> Optional[RecipeEvaluationResult]:
    """Verdict rule of RECIPE_USE_AFTER_FREE (None: no rule matched; the generic rule decides)."""
    rid = recipe.recipe_id
    in_free = (
        data.get("in_freelist", False)
        or (data.get("target_slot_status") == "FREE")
        or data.get("is_freed_object", False)
        or data.get("is_freed", False)
        or data.get("has_lifetime_evidence", False)
        or data.get("lifetime_evidence_available", False)
        or data.get("quarantine_record_found", False)
    )
    poison = (
        data.get("poison_detected", False)
        or (data.get("chunk_state") == "FREED")
        or data.get("poison_pattern_detected", False)
        or bool(data.get("poison_pattern"))
        or bool(data.get("memory_pattern"))
        or ("dddddddd" in str(data.get("memory_content_hex", "")))
    )
    active = data.get("is_active_chunk", False) or (data.get("target_slot_status") == "IN_USE")

    # Case C: Poison-like bytes without lifetime evidence must not confirm UAF!
    if poison and not in_free:
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
            confidence=0.45,
            confidence_basis="Poison-like bytes observed in memory payload, but allocator deallocation state or lifetime history is absent. Cannot establish UAF without proof of prior deallocation.",
            missing_evidence=["allocator_freed_state_confirmation", "lifetime_deallocation_event"],
            limitations=recipe.limitations,
            details={
                "uaf_confirmed": False,
                "stale_pointer_candidate": True,
                "poison_bytes_observed": True,
                "unconfirmed_poison_pattern": True,
            },
        )

    if in_free or (poison and in_free):
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_SUPPORTED,
            confidence=0.94,
            confidence_basis="Pointer dereferences a memory block currently on freelist, tracked as freed, or containing deallocation poison markers.",
            supporting_facts=[f"in_freelist={in_free}", f"poison_detected={poison}"],
            recommended_action="Locate dangling reference holders and nullify upon deallocation.",
            details={"uaf_confirmed": True, "chain": ["FREED_ALLOCATION", "STALE_POINTER_CANDIDATE", "CONFIRMED_USE_AFTER_FREE"]},
        )
    if active and not in_free and not poison:
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_CONTRADICTED,
            confidence=0.90,
            confidence_basis="Target block is marked active in chunk header with intact object invariants and no poison markers.",
            contradicting_facts=["Chunk is active in heap", "Zero poison markers detected"],
            recommended_action="Refute Use-After-Free hypothesis for this pointer.",
            details={"uaf_confirmed": False},
        )
    return RecipeEvaluationResult(
        recipe_id=rid,
        status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
        confidence=0.25,
        confidence_basis="Freelist state or chunk active bit could not be inspected.",
        missing_evidence=["chunk_inuse_bit", "freelist_check"],
        limitations=recipe.limitations,
    )
    return None


def _rule_process_memory_growth(recipe: DiagnosticRecipe, data: Dict[str, Any]) -> Optional[RecipeEvaluationResult]:
    """Verdict rule of RECIPE_PROCESS_MEMORY_GROWTH (None: no rule matched; the generic rule decides)."""
    rid = recipe.recipe_id
    if data.get("insufficient_temporal_separation"):
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
            confidence=0.20,
            confidence_basis="Insufficient temporal separation (<50ms) between observation epochs. Rapid caller increments cannot manufacture temporal validity.",
            missing_evidence=["adequate_temporal_separation"],
            limitations=recipe.limitations + ["Insufficient temporal separation (<50ms)"],
            details={"insufficient_temporal_separation": True},
        )
    if data.get("out_of_order_epoch_detected"):
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
            confidence=0.20,
            confidence_basis="Observation epochs arrived out-of-order. Temporal sequence cannot establish trend.",
            missing_evidence=["strictly_increasing_epoch_sequence"],
            limitations=recipe.limitations + ["Out-of-order epoch sequence"],
            details={"out_of_order_epoch_detected": True},
        )

    obs_win = data.get("observation_window") or data.get("window")
    if obs_win and hasattr(obs_win, "analyze_memory_behavior") and getattr(obs_win, "sample_count", lambda: 0)() >= 2:
        analysis = obs_win.analyze_memory_behavior()
        if analysis.classification == MemoryBehaviorClassification.TEMPORAL_SEQUENCE_INVALID:
            return RecipeEvaluationResult(
                recipe_id=rid,
                status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
                confidence=0.20,
                confidence_basis=f"Temporal sequence invalid: {analysis.summary}",
                missing_evidence=["valid_monotonic_temporal_sequence"],
                limitations=analysis.limitations or recipe.limitations,
                details={"classification": analysis.classification.value, "summary": analysis.summary},
            )
        elif analysis.classification == MemoryBehaviorClassification.INSUFFICIENT_OBSERVATION:
            return RecipeEvaluationResult(
                recipe_id=rid,
                status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
                confidence=0.20,
                confidence_basis=f"Insufficient observation: {analysis.summary}",
                missing_evidence=["adequate_temporal_separation_or_duration", "minimum_3_valid_epochs"],
                limitations=analysis.limitations or recipe.limitations,
                details={"classification": analysis.classification.value, "summary": analysis.summary, **(analysis.details or {})},
            )
        elif analysis.classification in (MemoryBehaviorClassification.CONFIRMED_LEAK, MemoryBehaviorClassification.SUSTAINED_RSS_GROWTH, MemoryBehaviorClassification.PROBABLE_LEAK):
            rate = getattr(analysis, "rss_growth_rate_kb_per_sec", getattr(analysis, "growth_rate_kb_per_sec", 0.0))
            return RecipeEvaluationResult(
                recipe_id=rid,
                status=RECIPE_STATUS_SUPPORTED,
                confidence=0.96 if analysis.classification == MemoryBehaviorClassification.CONFIRMED_LEAK else 0.88,
                confidence_basis=analysis.summary,
                supporting_facts=[analysis.summary, f"Rate: {rate:.2f} KB/s"],
                recommended_action="Proceed to Heap Growth and Object Accumulation recipes to isolate leaking types.",
                details={"growth_confirmed": True, "classification": analysis.classification.value, "rate_kb_per_sec": rate},
            )
        elif analysis.classification in (MemoryBehaviorClassification.STABLE_PLATEAU, MemoryBehaviorClassification.INITIALIZATION_WARMUP, MemoryBehaviorClassification.PERIODIC_RECLAMATION, MemoryBehaviorClassification.TRANSIENT_BURST):
            return RecipeEvaluationResult(
                recipe_id=rid,
                status=RECIPE_STATUS_CONTRADICTED,
                confidence=0.92,
                confidence_basis=analysis.summary,
                contradicting_facts=[analysis.summary],
                recommended_action="Refute unmanaged leak; memory behavior is bounded or reclaimed.",
                details={"growth_confirmed": False, "classification": analysis.classification.value},
            )

    rss_hist = data.get("rss_history_kb") or data.get("rss_series_kb") or []
    epochs = data.get("epoch_count", len(rss_hist))
    growth_bytes = data.get("rss_growth_bytes", 0)
    is_monotonic = data.get("is_monotonic")

    if rss_hist and not is_monotonic:
        is_monotonic = all(rss_hist[i] <= rss_hist[i+1] for i in range(len(rss_hist)-1))
        growth_bytes = (rss_hist[-1] - rss_hist[0]) * 1024

    # Scenario F check: Transient initialization growth followed by plateau
    if len(rss_hist) >= 3:
        # Check plateau between epoch 1 and subsequent epochs
        delta_later = (rss_hist[-1] - rss_hist[1]) * 1024
        max_plateau_tolerance = max(64 * 1024, int(0.02 * rss_hist[1] * 1024))
        if delta_later <= max_plateau_tolerance and (rss_hist[1] - rss_hist[0]) > 0:
            return RecipeEvaluationResult(
                recipe_id=rid,
                status=RECIPE_STATUS_CONTRADICTED,
                confidence=0.91,
                confidence_basis=f"Memory footprint stabilized at plateau ({rss_hist[-1]} KB) across later observation epochs (delta={delta_later} bytes). Transient initialization growth refuted as leak.",
                contradicting_facts=["Memory stabilized after initial warm-up", f"Plateau delta: {delta_later} bytes"],
                recommended_action="Refute unmanaged leak; process stabilized at plateau.",
                details={"growth_confirmed": False, "transient_warmup": True},
            )

    if is_monotonic and growth_bytes > 512 * 1024 and epochs >= 3:
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_SUPPORTED,
            confidence=0.93,
            confidence_basis=f"Monotonic RSS growth of {growth_bytes} bytes observed across {epochs} temporal epochs. Ongoing memory growth confirmed.",
            supporting_facts=[f"RSS growth: {growth_bytes} bytes", f"Monotonic growth over {epochs} epochs"],
            recommended_action="Proceed to Heap Growth and Object Accumulation recipes to isolate leaking types.",
            details={"growth_confirmed": True, "growth_bytes": growth_bytes},
        )
    elif is_monotonic and epochs == 2 and growth_bytes > 0:
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_AMBIGUOUS,
            confidence=0.50,
            confidence_basis=f"Observed {epochs} epochs; require >= 3 epochs to separate transient cache warm-up from leak.",
            missing_evidence=["temporal_epochs_minimum_3"],
            limitations=recipe.limitations,
        )
    elif (is_monotonic is False or growth_bytes <= 100 * 1024) and epochs >= 2:
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_CONTRADICTED,
            confidence=0.88,
            confidence_basis=f"Memory footprint is stable or contracted (delta={growth_bytes} bytes). Unmanaged memory growth refuted.",
            contradicting_facts=[f"Non-monotonic growth (delta={growth_bytes} bytes)"],
            recommended_action="Refute process memory growth hypothesis.",
            details={"growth_confirmed": False},
        )
    return RecipeEvaluationResult(
        recipe_id=rid,
        status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
        confidence=0.20,
        confidence_basis="Insufficient RSS history to evaluate memory growth.",
        missing_evidence=["rss_history"],
        limitations=recipe.limitations,
    )
    return None


def _rule_potential_deadlock_patterns(recipe: DiagnosticRecipe, data: Dict[str, Any]) -> Optional[RecipeEvaluationResult]:
    """Verdict rule of RECIPE_POTENTIAL_DEADLOCK_PATTERNS (None: no rule matched; the generic rule decides)."""
    rid = recipe.recipe_id
    cg = data.get("concurrency_graph") or data.get("wait_for_graph")
    if cg and hasattr(cg, "analyze") and (len(getattr(cg, "waiting_edges", [])) > 0 or len(getattr(cg, "ownership_edges", [])) > 0 or len(getattr(cg, "unresolved_edges", [])) > 0):
        analysis = cg.analyze()
        if analysis.concurrency_state == ConcurrencyState.INCONCLUSIVE_INCOMPLETE_GRAPH:
            return RecipeEvaluationResult(
                recipe_id=rid,
                status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
                confidence=0.45,
                confidence_basis=f"Lock ownership graph is incomplete: {analysis.summary}. Cannot determine whether graph is acyclic or contains cycles.",
                missing_evidence=["complete_lock_ownership_info"],
                limitations=analysis.limitations or recipe.limitations,
                details={"incomplete_lock_graph": True, "concurrency_state": analysis.concurrency_state.value},
            )
        elif analysis.concurrency_state == ConcurrencyState.PERSISTENT_DEADLOCK:
            return RecipeEvaluationResult(
                recipe_id=rid,
                status=RECIPE_STATUS_SUPPORTED,
                confidence=0.98,
                confidence_basis=f"Persistent deadlock confirmed: {analysis.summary}",
                supporting_facts=[f"Deadlock cycle: {c}" for c in analysis.cycles] or [analysis.summary],
                recommended_action="Enforce strict global lock acquisition hierarchy across participating functions.",
                details={"deadlock_confirmed": True, "state": "PERSISTENT_DEADLOCK", "cycles": analysis.cycles},
            )
        elif analysis.concurrency_state == ConcurrencyState.OBSERVED_CIRCULAR_WAIT:
            return RecipeEvaluationResult(
                recipe_id=rid,
                status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
                confidence=0.75,
                confidence_basis=f"Circular wait observed in current snapshot ({analysis.summary}), but persistence across multiple validated epochs has not yet been demonstrated.",
                supporting_facts=[analysis.summary],
                recommended_action="Perform consecutive temporal sampling to confirm cycle persistence.",
                details={"deadlock_confirmed": False, "state": "OBSERVED_CIRCULAR_WAIT", "transient_cycle": True},
            )
        elif analysis.concurrency_state in (ConcurrencyState.NO_DEADLOCK_ACYCLIC, ConcurrencyState.LOCK_CONTENTION, ConcurrencyState.THREAD_BLOCKED):
            return RecipeEvaluationResult(
                recipe_id=rid,
                status=RECIPE_STATUS_CONTRADICTED,
                confidence=0.90,
                confidence_basis=f"Complete lock graph verified acyclic with zero circular wait cycles ({analysis.summary}).",
                contradicting_facts=["Complete lock graph verified acyclic (DAG)"],
                recommended_action="Refute deadlock; inspect thread worker contention or external I/O stall.",
                details={"deadlock_confirmed": False, "state": "NO_DEADLOCK_ACYCLIC", "lock_graph_acyclic": True},
            )

    thread_locks = data.get("thread_locks") or data.get("lock_graph") or data.get("callstacks_info")
    cycle_detected = data.get("cycle_detected", False) or data.get("deadlock_detected", False) or bool(data.get("deadlock_cycle"))
    cycle_persistent = bool(data.get("cycle_persistent", False))
    incomplete_graph = data.get("incomplete_lock_graph", False) or data.get("insufficient_lock_info", False)

    if thread_locks and not cycle_detected and isinstance(thread_locks, dict):
        waiting_map = {}
        holding_map = {}
        for tid, info in thread_locks.items():
            if isinstance(info, dict):
                for lk in info.get("holding", []):
                    holding_map[lk] = tid
                if info.get("waiting_for"):
                    waiting_map[tid] = info["waiting_for"]
        for tid, wait_lk in waiting_map.items():
            holder = holding_map.get(wait_lk)
            if holder and holder in waiting_map:
                wait_lk2 = waiting_map[holder]
                if holding_map.get(wait_lk2) == tid:
                    cycle_detected = True
                    break

    # Scenario L: An incomplete lock graph must NEVER be interpreted as an acyclic graph!
    if incomplete_graph:
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
            confidence=0.45,
            confidence_basis="Lock ownership graph is incomplete (threads waiting on locks with unresolvable owner). Cannot determine whether graph is acyclic or contains cycles.",
            missing_evidence=["complete_lock_ownership_info", "incomplete_lock_graph_cannot_prove_acyclic"],
            limitations=recipe.limitations,
            details={"incomplete_lock_graph": True, "incomplete_graph": True},
        )

    if cycle_detected:
        obs_count = int(data.get("observation_count", data.get("historical_observations", 1)) or 1)
        is_persistent = bool(
            (data.get("is_persistent") if "is_persistent" in data else cycle_persistent)
            and obs_count >= 2
        )
        if is_persistent:
            return RecipeEvaluationResult(
                recipe_id=rid,
                status=RECIPE_STATUS_SUPPORTED,
                confidence=0.98,
                confidence_basis="Persistent wait-for graph cycle verified across consecutive samples. Deadlock confirmed.",
                supporting_facts=["Cycle verified persistent across threads"],
                recommended_action="Enforce strict global lock acquisition hierarchy across participating functions.",
                details={"deadlock_confirmed": True, "state": "PERSISTENT_DEADLOCK", "is_persistent": True},
            )
        else:
            # Case L: Circular wait observed only once is OBSERVED_CIRCULAR_WAIT, not PERSISTENT_DEADLOCK!
            return RecipeEvaluationResult(
                recipe_id=rid,
                status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
                confidence=0.75,
                confidence_basis="Circular wait observed in current snapshot, but temporal persistence across multiple epochs has not yet been demonstrated.",
                supporting_facts=["Circular wait observed in current snapshot"],
                recommended_action="Perform consecutive temporal sampling to confirm cycle persistence.",
                details={"deadlock_confirmed": False, "state": "OBSERVED_CIRCULAR_WAIT", "transient_cycle": True, "is_persistent": False},
            )
    elif thread_locks and not cycle_detected:
        # Check if threads are blocked without cycle (Scenario J)
        blocked_threads = data.get("blocked_threads", [])
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_CONTRADICTED,
            confidence=0.92,
            confidence_basis="Wait-for graph is a verified complete acyclic directed graph with no wait cycles.",
            contradicting_facts=["Wait-for graph is complete and acyclic"],
            recommended_action="Refute deadlock hypothesis; inspect thread contention and lock holding durations.",
            details={"deadlock_confirmed": False, "thread_contention": bool(blocked_threads), "lock_graph_acyclic": True},
        )
    return RecipeEvaluationResult(
        recipe_id=rid,
        status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
        confidence=0.20,
        confidence_basis="Thread stacks or lock ownership words could not be read.",
        missing_evidence=["thread_callstacks", "mutex_owners"],
        limitations=recipe.limitations,
    )
    return None


def _rule_heap_growth(recipe: DiagnosticRecipe, data: Dict[str, Any]) -> Optional[RecipeEvaluationResult]:
    """Verdict rule of RECIPE_HEAP_GROWTH (None: no rule matched; the generic rule decides)."""
    rid = recipe.recipe_id
    if data.get("insufficient_temporal_separation"):
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
            confidence=0.20,
            confidence_basis="Insufficient temporal separation (<50ms) between observation epochs.",
            missing_evidence=["adequate_temporal_separation"],
            limitations=recipe.limitations + ["Insufficient temporal separation (<50ms)"],
            details={"insufficient_temporal_separation": True},
        )
    if data.get("out_of_order_epoch_detected"):
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
            confidence=0.20,
            confidence_basis="Observation epochs arrived out-of-order.",
            missing_evidence=["strictly_increasing_epoch_sequence"],
            limitations=recipe.limitations + ["Out-of-order epoch sequence"],
            details={"out_of_order_epoch_detected": True},
        )

    # Case F: Heap VMA growth must be distinguished from live object growth!
    if data.get("heap_growth_type") == "VMA_RESERVATION_ONLY" or data.get("live_objects_growing") is False:
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
            confidence=0.90,
            confidence_basis="Heap VMA virtual mapping expanded, but live allocated object census is constant. Expansion represents allocator arena reservation or fragmentation rather than live object growth.",
            contradicting_facts=["Live allocated object population is constant"],
            recommended_action="Refute live object leak; check allocator fragmentation or mmap arena reservations.",
            details={"heap_growth_confirmed": False, "vma_reservation_only": True, "live_leak_confirmed": False},
        )

    heap_delta = data.get("heap_growth_bytes") or data.get("heap_kb_delta") or data.get("allocator_allocated_delta")
    heap_series = data.get("heap_series_kb") or []
    epochs = data.get("epoch_count", len(heap_series))
    if heap_delta is None and len(heap_series) >= 2:
        heap_delta = (heap_series[-1] - heap_series[0]) * 1024

    if heap_delta is not None and heap_delta > 256 * 1024:
        # Enforce >= 3 observation epochs to confirm sustained growth; 2 samples must not produce growth verdict
        if len(heap_series) == 2 or (0 < epochs < 3):
            return RecipeEvaluationResult(
                recipe_id=rid,
                status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
                confidence=0.40,
                confidence_basis=f"Initial heap expansion (+{heap_delta} bytes) observed across 2 samples, but at least 3 observation epochs are required to verify sustained growth versus transient arena reservation.",
                missing_evidence=["sustained_heap_growth_epochs >= 3"],
                limitations=recipe.limitations,
                details={"heap_growth_confirmed": False, "two_sample_delta_only": True},
            )
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_SUPPORTED,
            confidence=0.92,
            confidence_basis=f"Heap VMA / chunks grew by {heap_delta} bytes across {max(epochs, len(heap_series))} observation epochs. Ongoing heap growth confirmed.",
            supporting_facts=[f"Heap growth: {heap_delta} bytes"],
            recommended_action="Isolate leaking object types and retaining containers.",
            details={"heap_growth_confirmed": True, "heap_growth_bytes": heap_delta, "live_leak_confirmed": True},
        )
    elif heap_delta is not None and heap_delta <= 64 * 1024:
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_CONTRADICTED,
            confidence=0.90,
            confidence_basis=f"Heap footprint is stable (delta={heap_delta} bytes). Unmanaged heap expansion refuted.",
            contradicting_facts=[f"Heap stable (delta={heap_delta} bytes)"],
            recommended_action="Refute heap growth hypothesis.",
            details={"heap_growth_confirmed": False, "heap_stable": True},
        )
    return RecipeEvaluationResult(
        recipe_id=rid,
        status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
        confidence=0.25,
        confidence_basis="Insufficient heap observation epochs to evaluate heap growth.",
        missing_evidence=["heap_vma_temporal_samples"],
        limitations=recipe.limitations,
    )
    return None


def _rule_long_lived_object_accumulation(recipe: DiagnosticRecipe, data: Dict[str, Any]) -> Optional[RecipeEvaluationResult]:
    """Verdict rule of RECIPE_LONG_LIVED_OBJECT_ACCUMULATION (None: no rule matched; the generic rule decides)."""
    rid = recipe.recipe_id
    obj_delta = data.get("object_count_delta")
    if obj_delta is None:
        obj_delta = data.get("container_size_delta")
    if obj_delta is None:
        obj_delta = data.get("container_size")
    if obj_delta is None:
        obj_delta = data.get("active_chunk_count")
    if obj_delta is None:
        obj_delta = data.get("retained_objects_count")

    # Case G: A large but stable container must not be called accumulating memory!
    if (
        (data.get("is_accumulating") is False)
        or (data.get("object_count_delta") == 0)
        or (data.get("container_size_delta") == 0)
        or (data.get("container_delta") == 0)
        or (data.get("monotonic_growth") is False and (data.get("container_size") or 0) > 0)
    ):
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_NOT_APPLICABLE,
            confidence=0.91,
            confidence_basis=f"Container holds populated elements ({obj_delta}) but population delta across observation epochs is zero. Bounded static cache refuted as accumulating leak.",
            contradicting_facts=["Container element delta is zero across observation window"],
            not_applicable_reason="Container delta is zero across observation epochs",
            recommended_action="Refute object accumulation leak; container operates as stable bounded cache.",
            details={"object_accumulation_confirmed": False, "stable_container": True},
        )

    if obj_delta is not None and obj_delta > 50:
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_SUPPORTED,
            confidence=0.93,
            confidence_basis=f"Sustained accumulation of long-lived objects detected (count={obj_delta}). Object retention confirmed.",
            supporting_facts=[f"Retained objects count: {obj_delta}"],
            recommended_action="Inspect retaining container or owning object references.",
            details={"object_accumulation_confirmed": True, "retained_count": obj_delta},
        )
    elif obj_delta is not None and obj_delta <= 5:
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_CONTRADICTED,
            confidence=0.88,
            confidence_basis=f"Object population remains stable without unbounded accumulation (count={obj_delta}).",
            contradicting_facts=["Object population stable"],
            recommended_action="Refute object accumulation hypothesis.",
            details={"object_accumulation_confirmed": False, "population_stable": True},
        )
    return RecipeEvaluationResult(
        recipe_id=rid,
        status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
        confidence=0.25,
        confidence_basis="Object census or container size could not be determined across epochs.",
        missing_evidence=["object_census_data"],
        limitations=recipe.limitations,
    )
    return None


def _rule_unexpected_null_or_invalid_pointers(recipe: DiagnosticRecipe, data: Dict[str, Any]) -> Optional[RecipeEvaluationResult]:
    """Verdict rule of RECIPE_UNEXPECTED_NULL_OR_INVALID_POINTERS (None: no rule matched; the generic rule decides)."""
    rid = recipe.recipe_id
    ptr_val = data.get("pointer_value") or data.get("target_address") or data.get("address")
    is_mapped = data.get("is_mapped")
    is_null_allowed = data.get("is_null_allowed", False)
    is_active = data.get("is_active_lifecycle", False)

    if ptr_val is not None:
        try:
            pval_int = int(ptr_val, 16) if isinstance(ptr_val, str) and ptr_val.startswith("0x") else int(ptr_val)
        except Exception:
            pval_int = -1

        if pval_int == 0 and not is_null_allowed and is_active:
            return RecipeEvaluationResult(
                recipe_id=rid,
                status=RECIPE_STATUS_SUPPORTED,
                confidence=0.92,
                confidence_basis="Pointer member is NULL in active lifecycle state where non-null invariant is required.",
                supporting_facts=["Unexpected NULL pointer in active state"],
                recommended_action="Investigate why pointer was nullified or not initialized in active state.",
                details={"unexpected_null": True, "pointer": ptr_val},
            )
        elif pval_int > 0 and is_mapped is False:
            return RecipeEvaluationResult(
                recipe_id=rid,
                status=RECIPE_STATUS_SUPPORTED,
                confidence=0.95,
                confidence_basis=f"Pointer member targets unmapped address 0x{pval_int:x}.",
                supporting_facts=[f"Pointer 0x{pval_int:x} points outside mapped VMAs"],
                recommended_action="Inspect source assignment and allocation bounds for pointer.",
                details={"invalid_pointer": True, "pointer": ptr_val},
            )
        elif (pval_int == 0 and is_null_allowed) or (pval_int > 0 and is_mapped is True):
            return RecipeEvaluationResult(
                recipe_id=rid,
                status=RECIPE_STATUS_CONTRADICTED,
                confidence=0.90,
                confidence_basis=f"Pointer member is valid (value={ptr_val}, is_mapped={is_mapped}, null_allowed={is_null_allowed}).",
                contradicting_facts=["Pointer member is valid within lifecycle rules"],
                recommended_action="Refute unexpected null or invalid pointer hypothesis.",
                details={"unexpected_null": False, "pointer": ptr_val},
            )
    return RecipeEvaluationResult(
        recipe_id=rid,
        status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
        confidence=0.25,
        confidence_basis="Pointer member value or VMA mapping could not be determined.",
        missing_evidence=["pointer_member_observation"],
        limitations=recipe.limitations,
    )
    return None


def _rule_state_transition_violations(recipe: DiagnosticRecipe, data: Dict[str, Any]) -> Optional[RecipeEvaluationResult]:
    """Verdict rule of RECIPE_STATE_TRANSITION_VIOLATIONS (None: no rule matched; the generic rule decides)."""
    rid = recipe.recipe_id
    has_spec = bool(data.get("state_specification") or data.get("allowed_transitions") or data.get("allowed_states"))
    if data.get("missing_specification") or (not has_spec and not data.get("transition_violation")):
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_NOT_APPLICABLE,
            confidence=0.0,
            confidence_basis="No state machine specification, allowed state domain, or transition contract provided. State transition violation evaluation refused.",
            not_applicable_reason="Missing state transition specification",
            details={"not_applicable": True},
        )

    is_illegal = data.get("is_illegal_transition") or data.get("transition_violation")
    if is_illegal is None and "allowed_states" in data and "current_state" in data:
        is_illegal = data["current_state"] not in data["allowed_states"]
    s_before = data.get("state_before")
    s_after = data.get("state_after") or data.get("current_state")
    if data.get("transition_violation"):
        obs_trans = data.get("observed_transitions", [1, 999])
        s_before = s_before or obs_trans[0]
        s_after = s_after or obs_trans[-1]

    if is_illegal is True:
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_SUPPORTED,
            confidence=0.95,
            confidence_basis=f"Illegal state transition observed: '{s_before}' -> '{s_after}' violates state invariant.",
            supporting_facts=[f"Transition edge '{s_before}' -> '{s_after}' is unauthorized"],
            recommended_action="Audit caller state machine validation before state assignment.",
            details={"illegal_transition_confirmed": True},
        )
    elif is_illegal is False:
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_CONTRADICTED,
            confidence=0.92,
            confidence_basis=f"Transition '{s_before}' -> '{s_after}' is authorized in state transition specification.",
            contradicting_facts=[f"Transition '{s_before}' -> '{s_after}' is authorized"],
            recommended_action="Refute state transition violation hypothesis.",
            details={"illegal_transition_confirmed": False},
        )
    return RecipeEvaluationResult(
        recipe_id=rid,
        status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
        confidence=0.30,
        confidence_basis="State enum values could not be read across both observation epochs.",
        missing_evidence=["pre_and_post_state_observations"],
        limitations=recipe.limitations,
    )
    return None


def _rule_unexpected_variable_changes(recipe: DiagnosticRecipe, data: Dict[str, Any]) -> Optional[RecipeEvaluationResult]:
    """Verdict rule of RECIPE_UNEXPECTED_VARIABLE_CHANGES (None: no rule matched; the generic rule decides)."""
    rid = recipe.recipe_id
    curr_val = data.get("current_val") or data.get("current_value") or data.get("observed_value")
    val_range = data.get("valid_range") or data.get("expected_bounds")
    out_of_bounds = data.get("out_of_bounds")
    if curr_val is not None and val_range is not None:
        low, high = val_range
        out_of_bounds = curr_val < low or curr_val > high

    if out_of_bounds is True:
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_SUPPORTED,
            confidence=0.94,
            confidence_basis=f"Observed value '{curr_val}' violates expected domain bounds ({val_range}). Range anomaly confirmed.",
            supporting_facts=[f"Value {curr_val} outside bounds {val_range}"],
            recommended_action="Audit arithmetic operations and input validation on variable.",
            details={"violation_confirmed": True},
        )
    elif out_of_bounds is False:
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_CONTRADICTED,
            confidence=0.90,
            confidence_basis=f"Observed value '{curr_val}' satisfies expected domain bounds ({val_range}).",
            contradicting_facts=[f"Value {curr_val} within bounds {val_range}"],
            recommended_action="Refute unexpected variable change hypothesis.",
            details={"violation_confirmed": False},
        )
    return RecipeEvaluationResult(
        recipe_id=rid,
        status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
        confidence=0.30,
        confidence_basis="Variable value or expected domain bounds could not be determined.",
        missing_evidence=["typed_variable_value", "expected_bounds"],
        limitations=recipe.limitations,
    )
    return None


def _rule_heap_metadata_corruption(recipe: DiagnosticRecipe, data: Dict[str, Any]) -> Optional[RecipeEvaluationResult]:
    """Verdict rule of RECIPE_HEAP_METADATA_CORRUPTION (None: no rule matched; the generic rule decides)."""
    rid = recipe.recipe_id
    canary = data.get("canary_valid")
    if canary is None and (data.get("canary_corrupted") is True or data.get("magic_corrupted") is True):
        canary = False
    chunk_size = data.get("chunk_size") or data.get("chunk_size_bytes")
    if canary is False or (chunk_size is not None and chunk_size > 0x10000000000):
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_SUPPORTED,
            confidence=0.96,
            confidence_basis="Heap chunk header canary corrupted or impossible chunk size detected.",
            supporting_facts=["Heap chunk header corruption confirmed"],
            recommended_action="Enable AddressSanitizer to catch buffer overwrite.",
            details={"corruption_confirmed": True},
        )
    elif canary is True:
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_CONTRADICTED,
            confidence=0.91,
            confidence_basis="Heap chunk canaries intact across audited chunks.",
            contradicting_facts=["Canaries valid"],
            recommended_action="Refute heap metadata corruption for this region.",
            details={"corruption_confirmed": False, "canaries_intact": True},
        )
    return None


def _rule_suspicious_allocation_patterns(recipe: DiagnosticRecipe, data: Dict[str, Any]) -> Optional[RecipeEvaluationResult]:
    """Verdict rule of RECIPE_SUSPICIOUS_ALLOCATION_PATTERNS (None: no rule matched; the generic rule decides)."""
    rid = recipe.recipe_id
    req_bytes = data.get("requested_bytes") or data.get("allocation_size") or 0
    if req_bytes > 1024 * 1024 * 1024:
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_SUPPORTED,
            confidence=0.94,
            confidence_basis=f"Unusually large allocation requested: {req_bytes} bytes exceeds 1GB threshold.",
            supporting_facts=[f"Requested size: {req_bytes} bytes"],
            recommended_action="Check integer overflow or invalid size calculation in malloc call.",
            details={"size_violation": True},
        )
    return None


def _rule_allocation_free_imbalance(recipe: DiagnosticRecipe, data: Dict[str, Any]) -> Optional[RecipeEvaluationResult]:
    """Verdict rule of RECIPE_ALLOCATION_FREE_IMBALANCE (None: no rule matched; the generic rule decides)."""
    rid = recipe.recipe_id
    if data.get("incompatible_counters") or data.get("counter_compatibility") is False:
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_NOT_APPLICABLE,
            confidence=0.0,
            confidence_basis="Allocation and free counters measure incompatible subsystems, units, or non-matching scopes. Direct imbalance comparison refused.",
            not_applicable_reason="Incompatible counter measurement scopes",
            details={"not_applicable": True},
        )

    # Counter source changed between epochs (different symbol used for alloc counter) or reset/discontinuity
    if data.get("counter_source_changed"):
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
            confidence=0.20,
            confidence_basis="Counter source symbol changed between observation epochs; cross-epoch comparison is invalid.",
            missing_evidence=["consistent_counter_source_across_epochs"],
            limitations=["Counter source changed between epochs; alloc/free delta comparison rejected"],
            details={"imbalance_confirmed": False, "counter_source_changed": True},
        )

    # Counter reset or discontinuity across observation epochs
    if data.get("counter_reset_detected"):
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
            confidence=0.30,
            confidence_basis="Allocation/free counter reset or discontinuity detected across observation epochs; counters cannot be reliably compared.",
            missing_evidence=["continuous_monotonic_allocation_counters"],
            limitations=["Counter reset detected between observation epochs"],
            details={"imbalance_confirmed": False, "counter_reset_detected": True},
        )

    # Check temporal progression deltas if available across multiple epochs
    alloc_delta = data.get("alloc_delta")
    free_delta = data.get("free_delta")
    if alloc_delta is not None and free_delta is not None:
        if alloc_delta >= 5 * max(1, free_delta) and alloc_delta > 10:
            return RecipeEvaluationResult(
                recipe_id=rid,
                status=RECIPE_STATUS_SUPPORTED,
                confidence=0.94,
                confidence_basis=f"Severe temporal allocation/free delta imbalance: +{alloc_delta} allocations vs +{free_delta} frees across observation window.",
                supporting_facts=[f"Temporal delta: allocs=+{alloc_delta}, frees=+{free_delta}"],
                recommended_action="Audit dynamic allocation sites and ensure symmetric release.",
                details={"imbalance_confirmed": True, "alloc_delta": alloc_delta, "free_delta": free_delta},
            )
        elif abs(alloc_delta - free_delta) <= max(10, int(0.05 * max(1, alloc_delta))):
            return RecipeEvaluationResult(
                recipe_id=rid,
                status=RECIPE_STATUS_CONTRADICTED,
                confidence=0.92,
                confidence_basis=f"Temporal allocation and free progression are balanced (alloc delta=+{alloc_delta}, free delta=+{free_delta}).",
                contradicting_facts=["Balanced alloc/free progression delta"],
                recommended_action="Refute allocation imbalance hypothesis.",
                details={"imbalance_confirmed": False, "alloc_delta": alloc_delta, "free_delta": free_delta},
            )

    alloc_count = data.get("alloc_count") if data.get("alloc_count") is not None else data.get("cumulative_allocations")
    free_count = data.get("free_count") if data.get("free_count") is not None else data.get("cumulative_frees")
    if alloc_count is not None and free_count is not None:
        if alloc_count >= 5 * max(1, free_count):
            return RecipeEvaluationResult(
                recipe_id=rid,
                status=RECIPE_STATUS_SUPPORTED,
                confidence=0.92,
                confidence_basis=f"Severe allocation/free imbalance: {alloc_count} allocations vs {free_count} frees.",
                supporting_facts=[f"Allocs: {alloc_count}, Frees: {free_count}"],
                recommended_action="Audit object lifetime and ensure symmetrical free() in destructors.",
                details={"imbalance_confirmed": True},
            )
        elif abs(alloc_count - free_count) <= max(10, int(0.05 * alloc_count)):
            return RecipeEvaluationResult(
                recipe_id=rid,
                status=RECIPE_STATUS_CONTRADICTED,
                confidence=0.90,
                confidence_basis="Allocations and frees are balanced within tolerance.",
                contradicting_facts=["Balanced alloc/free ratio"],
                recommended_action="Refute allocation imbalance hypothesis.",
                details={"imbalance_confirmed": False},
            )
        else:
            return RecipeEvaluationResult(
                recipe_id=rid,
                status=RECIPE_STATUS_AMBIGUOUS,
                confidence=0.50,
                confidence_basis=f"Moderate disparity between allocations ({alloc_count}) and frees ({free_count}); within operational margin.",
                supporting_facts=[f"Allocs: {alloc_count}, Frees: {free_count}"],
                details={"imbalance_confirmed": False},
            )
    else:
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
            confidence=0.20,
            confidence_basis="Allocation and deallocation counters could not be observed from target process.",
            missing_evidence=["allocation_counters"],
            limitations=recipe.limitations,
        )
    return None


def _rule_suspicious_boundary_values(recipe: DiagnosticRecipe, data: Dict[str, Any]) -> Optional[RecipeEvaluationResult]:
    """Verdict rule of RECIPE_SUSPICIOUS_BOUNDARY_VALUES (None: no rule matched; the generic rule decides)."""
    rid = recipe.recipe_id
    val = data.get("value") or data.get("observed_value")
    if val in (0xFFFFFFFF, 0x7FFFFFFF, 0xFFFFFFFFFFFFFFFF, -1):
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_SUPPORTED,
            confidence=0.93,
            confidence_basis=f"Observed sentinel / boundary value {val} indicates possible unsigned underflow or unhandled error code.",
            supporting_facts=[f"Value {val} matches known sentinel/extreme"],
            recommended_action="Verify arithmetic underflow protection.",
            details={"boundary_violation": True},
        )
    return None


def _rule_inconsistent_related_variables(recipe: DiagnosticRecipe, data: Dict[str, Any]) -> Optional[RecipeEvaluationResult]:
    """Verdict rule of RECIPE_INCONSISTENT_RELATED_VARIABLES (None: no rule matched; the generic rule decides)."""
    rid = recipe.recipe_id
    if data.get("unrelated_field_pair") or data.get("fields_compatible") is False:
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_NOT_APPLICABLE,
            confidence=0.0,
            confidence_basis="Capacity and length fields belong to unrelated structures or objects. Coupling invariant evaluation refused.",
            not_applicable_reason="Unrelated field pairing refused",
            details={"not_applicable": True},
        )

    cap = data.get("buffer_capacity") or data.get("capacity")
    length = data.get("buffer_length") or data.get("length")
    field_incon = data.get("field_inconsistency", False)
    if (cap is not None and length is not None and length > cap) or field_incon:
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_SUPPORTED,
            confidence=0.95,
            confidence_basis=f"Coupled variable invariant violation detected: length ({length}) exceeds capacity ({cap}).",
            supporting_facts=[f"Length {length} exceeds capacity {cap}"],
            recommended_action="Audit bounds checking on buffer write routines.",
            details={"invariant_violation_confirmed": True, "field_inconsistency": True, "capacity": cap, "length": length},
        )
    elif cap is not None and length is not None and length <= cap:
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_CONTRADICTED,
            confidence=0.90,
            confidence_basis=f"Buffer length ({length}) strictly respects capacity ({cap}). Invariant holds.",
            contradicting_facts=["Length respects capacity"],
            recommended_action="Refute variable coupling inconsistency.",
            details={"invariant_violation_confirmed": False, "field_inconsistency": False},
        )
    return RecipeEvaluationResult(
        recipe_id=rid,
        status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
        confidence=0.25,
        confidence_basis="Coupled variables or capacity/length pair could not be observed.",
        missing_evidence=["paired_variables_data"],
        limitations=recipe.limitations,
    )
    return None


def _lock_waits_fully_observed(data: Dict[str, Any]) -> bool:
    """The lock-wait question of RECIPE_LONG_RUNNING_BLOCKED_THREADS can be answered "no": a usable thread-sampling
    window, mutex owners decodable on this target, a complete lock graph, no stalled lock wait, no wait cycle and no
    thread-state anomaly in the window (``threads_healthy``)."""
    return ((data.get("thread_sampling") or {}).get("status") == "OK"
            and data.get("threads_healthy") is True
            and not data.get("stalled_lock_waits")
            and not data.get("persistent_block")
            and not data.get("deadlock_detected")
            and not data.get("lock_owner_unsupported")
            and not data.get("incomplete_lock_graph"))


def _rule_long_running_blocked_threads(recipe: DiagnosticRecipe, data: Dict[str, Any]) -> Optional[RecipeEvaluationResult]:
    """Verdict rule of RECIPE_LONG_RUNNING_BLOCKED_THREADS (None: no rule matched; the generic rule decides)."""
    rid = recipe.recipe_id
    if not (not ("positive_evidence_found" in data or "negative_evidence_found" in data)):
        return None
    blocked = data.get("blocked_threads") or []
    stall_sec = data.get("blocked_duration_sec") or data.get("wait_duration_sec") or 0.0
    deadlock_det = data.get("deadlock_detected", False)
    if blocked and (stall_sec >= 1.0 or data.get("starvation_detected") or data.get("persistent_block")):
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_SUPPORTED,
            confidence=0.88,
            confidence_basis=f"Observed {len(blocked)} thread(s) blocked for {stall_sec}s without forward progress.",
            supporting_facts=[f"Blocked threads: {len(blocked)}"] + list(data.get("long_wait_findings") or []),
            recommended_action="Inspect lock holder critical section duration or futex wake signaling.",
            details={"blocked_thread_count": len(blocked), "blocked_duration_sec": stall_sec, "deadlock_detected": deadlock_det},
        )
    elif data.get("long_wait_threads") and _lock_waits_fully_observed(data):
        # HEALTHY rule (docs/HEALTHY_VERDICT.md): what this recipe CAN decide is whether a thread is blocked on a
        # lock whose owner makes no progress.  With a usable sampling window, decodable lock owners, a complete lock
        # graph, no stalled lock wait and no wait cycle, that question is answered "no" -> CONTRADICTED.  Whether a
        # long wait in a syscall (poll / read / condition variable) is expected is NOT decided: from outside an idle
        # wait and a stall look identical.  It is carried as a declared scope limit (long_waits_not_judged), never
        # as a supporting fact and never as evidence of health.
        lw = [t for t in data["long_wait_threads"] if isinstance(t, dict)]
        win = (data.get("thread_sampling") or {}).get("window_sec")
        not_judged = [{"tid": t.get("tid"), "name": t.get("name"), "syscall": t.get("syscall"),
                       "wait_kind": t.get("wait_kind"), "waited_at_least_sec": t.get("waited_at_least_sec")}
                      for t in lw]
        txt = ("no thread was blocked on a lock whose owner made no progress over the %ss sampling window; "
               "%d long wait(s) outside lock waits observed, cannot determine whether expected (not judged): %s"
               % (win, len(lw), "; ".join(f"'{t.get('name')}' in {t.get('syscall')}" for t in lw[:5])))
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_CONTRADICTED,
            confidence=0.80,
            confidence_basis=txt,
            contradicting_facts=["no lock wait without owner progress in the sampling window"],
            limitations=list(data.get("long_wait_findings") or []),
            details={"blocked_thread_count": 0, "long_wait_threads": [t.get("name") for t in lw],
                     "expectation": "UNKNOWN", "long_waits_not_judged": not_judged},
        )
    elif data.get("long_wait_threads"):
        # IMP-010: a thread sat in one syscall for the whole sampling window. From outside, a blocked-forever
        # thread and an idle worker look identical, so this is an observation, never a fault verdict.
        lw = data["long_wait_threads"]
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
            confidence=0.40,
            confidence_basis="Long wait observed, cannot determine whether expected: "
                             + "; ".join(f"'{t.get('name')}' in {t.get('syscall')}" for t in lw[:5]),
            # NOT supporting_facts: the engine turns every supporting fact into SUPPORTED evidence, and an
            # observation whose expectedness is unknown must not corroborate a fault.
            missing_evidence=["application_work_queue_state"],
            limitations=list(recipe.limitations) + list(data.get("long_wait_findings") or []),
            details={"long_wait_threads": [t.get("name") for t in lw], "expectation": "UNKNOWN"},
        )
    elif "blocked_threads" in data and not blocked:
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_CONTRADICTED,
            confidence=0.90,
            confidence_basis="Zero threads are blocked on locks or long-running waits.",
            contradicting_facts=["Zero blocked threads observed"],
            recommended_action="Refute long-running blocked thread stall.",
            details={"blocked_thread_count": 0},
        )
    return None


def _rule_suspicious_lock_ownership(recipe: DiagnosticRecipe, data: Dict[str, Any]) -> Optional[RecipeEvaluationResult]:
    """Verdict rule of RECIPE_SUSPICIOUS_LOCK_OWNERSHIP (None: no rule matched; the generic rule decides)."""
    rid = recipe.recipe_id
    if not (not ("positive_evidence_found" in data or "negative_evidence_found" in data)):
        return None
    deadlock_det = data.get("deadlock_detected", False)
    orphan_lock = data.get("orphan_lock_owner", False) or data.get("invalid_owner_tid", False)
    if deadlock_det or orphan_lock:
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_SUPPORTED,
            confidence=0.92,
            confidence_basis="Suspicious or circular mutex ownership verified in runtime lock table.",
            supporting_facts=["Suspicious/circular mutex ownership detected"],
            recommended_action="Audit mutex ownership lifecycle and lock acquisition ordering.",
            details={"suspicious_lock_ownership": True},
        )
    elif data.get("callstacks_info") and not deadlock_det and not orphan_lock and not data.get("incomplete_lock_graph"):
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_CONTRADICTED,
            confidence=0.88,
            confidence_basis="All inspected mutexes have valid active thread owners or are cleanly unlocked.",
            contradicting_facts=["Lock ownership verified clean"],
            recommended_action="Refute suspicious lock ownership.",
            details={"suspicious_lock_ownership": False},
        )
    return None


def _rule_thread_state_anomalies(recipe: DiagnosticRecipe, data: Dict[str, Any]) -> Optional[RecipeEvaluationResult]:
    """Verdict rule of RECIPE_THREAD_STATE_ANOMALIES (None: no rule matched; the generic rule decides)."""
    rid = recipe.recipe_id
    if not (not ("positive_evidence_found" in data or "negative_evidence_found" in data)):
        return None
    if data.get("zombie_threads") or data.get("runaway_threads") or data.get("thread_state_anomaly"):
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_SUPPORTED,
            confidence=0.88,
            confidence_basis="Abnormal thread scheduling/state distribution detected.",
            supporting_facts=["Thread state anomaly observed"] + list(data.get("thread_findings") or []),
            recommended_action="Inspect runaway or zombie thread creation sites.",
            # Decided by what fired: runaway / zombie / D-state threads are not a deadlock.
            details={"thread_state_anomaly": True,
                     "finding_category": CATEGORY_PROCESS_INSTABILITY,
                     "runaway_threads": [t.get("name") for t in (data.get("runaway_threads") or []) if isinstance(t, dict)]},
        )
    elif data.get("threads_healthy") is True:
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_CONTRADICTED,
            confidence=0.90,
            confidence_basis="All worker threads are in expected operational states with forward progress.",
            contradicting_facts=["All threads in normal state"],
            recommended_action="Refute thread state anomaly.",
            details={"thread_state_anomaly": False},
        )
    return None


def _rule_object_lifetime_anomalies(recipe: DiagnosticRecipe, data: Dict[str, Any]) -> Optional[RecipeEvaluationResult]:
    """Verdict rule of RECIPE_OBJECT_LIFETIME_ANOMALIES (None: no rule matched; the generic rule decides)."""
    rid = recipe.recipe_id
    if not (not ("positive_evidence_found" in data or "negative_evidence_found" in data)):
        return None
    if data.get("lifetime_expired") is True or data.get("dangling_reference") is True:
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_SUPPORTED,
            confidence=0.92,
            confidence_basis="Active reference points to object whose lifetime has expired.",
            supporting_facts=["Expired object lifetime reference detected"],
            recommended_action="Audit smart pointer / ownership lifetime bindings.",
            details={"lifetime_anomaly_confirmed": True},
        )
    elif data.get("lifetime_valid") is True:
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_CONTRADICTED,
            confidence=0.90,
            confidence_basis="Object lifetime and epoch counter verified valid and active.",
            contradicting_facts=["Object lifetime verified active"],
            recommended_action="Refute object lifetime anomaly.",
            details={"lifetime_anomaly_confirmed": False},
        )
    else:
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
            confidence=0.20,
            confidence_basis="Object lifetime history or allocator tracking could not be observed from target process.",
            missing_evidence=["object_lifetime_event_history", "lifetime_epoch_tracker"],
            limitations=recipe.limitations,
            details={"lifetime_anomaly_confirmed": False},
        )
    return None


def _rule_repeated_allocation_patterns(recipe: DiagnosticRecipe, data: Dict[str, Any]) -> Optional[RecipeEvaluationResult]:
    """Verdict rule of RECIPE_REPEATED_ALLOCATION_PATTERNS (None: no rule matched; the generic rule decides)."""
    rid = recipe.recipe_id
    if not (not ("positive_evidence_found" in data or "negative_evidence_found" in data)):
        return None
    if data.get("unreclaimed_site_growth") is True or (data.get("alloc_delta", 0) > 100 and data.get("free_delta", 0) == 0):
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_SUPPORTED,
            confidence=0.90,
            confidence_basis="Repeated allocation site exhibits monotonic growth with zero reclamation.",
            supporting_facts=["Repeated unreclaimed allocation pattern confirmed"],
            recommended_action="Inspect allocation callsite for missing deallocation path.",
            details={"repeated_leak_pattern": True},
        )
    elif data.get("alloc_reclaimed") is True:
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_CONTRADICTED,
            confidence=0.90,
            confidence_basis="Repeated allocations are balanced by corresponding deallocations.",
            contradicting_facts=["Repeated allocations properly reclaimed"],
            recommended_action="Refute unreclaimed repeated allocation leak.",
            details={"repeated_leak_pattern": False},
        )
    return None


def _rule_shared_state_inconsistencies(recipe: DiagnosticRecipe, data: Dict[str, Any]) -> Optional[RecipeEvaluationResult]:
    """Verdict rule of RECIPE_SHARED_STATE_INCONSISTENCIES (None: no rule matched; the generic rule decides)."""
    rid = recipe.recipe_id
    if not (not ("positive_evidence_found" in data or "negative_evidence_found" in data)):
        return None
    if data.get("shared_invariant_violated") is True or data.get("torn_shared_state") is True:
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_SUPPORTED,
            confidence=0.92,
            confidence_basis="Shared state invariant across concurrent threads is violated.",
            supporting_facts=["Shared state invariant violation observed"],
            recommended_action="Protect shared multi-field state updates with a common mutex.",
            details={"shared_state_inconsistency": True},
        )
    elif data.get("shared_invariant_intact") is True:
        return RecipeEvaluationResult(
            recipe_id=rid,
            status=RECIPE_STATUS_CONTRADICTED,
            confidence=0.90,
            confidence_basis="Shared state invariant holds across consecutive atomic snapshots.",
            contradicting_facts=["Shared state invariant intact"],
            recommended_action="Refute shared state inconsistency.",
            details={"shared_state_inconsistency": False},
        )
    return None


_RULES: Dict[str, Callable[[DiagnosticRecipe, Dict[str, Any]], Optional[RecipeEvaluationResult]]] = {
    "RECIPE_INVALID_MEMORY_ACCESS": _rule_invalid_memory_access,
    "RECIPE_INVALID_FREE": _rule_invalid_free,
    "RECIPE_USE_AFTER_FREE": _rule_use_after_free,
    "RECIPE_PROCESS_MEMORY_GROWTH": _rule_process_memory_growth,
    "RECIPE_POTENTIAL_DEADLOCK_PATTERNS": _rule_potential_deadlock_patterns,
    "RECIPE_HEAP_GROWTH": _rule_heap_growth,
    "RECIPE_LONG_LIVED_OBJECT_ACCUMULATION": _rule_long_lived_object_accumulation,
    "RECIPE_UNEXPECTED_NULL_OR_INVALID_POINTERS": _rule_unexpected_null_or_invalid_pointers,
    "RECIPE_STATE_TRANSITION_VIOLATIONS": _rule_state_transition_violations,
    "RECIPE_UNEXPECTED_VARIABLE_CHANGES": _rule_unexpected_variable_changes,
    "RECIPE_HEAP_METADATA_CORRUPTION": _rule_heap_metadata_corruption,
    "RECIPE_SUSPICIOUS_ALLOCATION_PATTERNS": _rule_suspicious_allocation_patterns,
    "RECIPE_ALLOCATION_FREE_IMBALANCE": _rule_allocation_free_imbalance,
    "RECIPE_SUSPICIOUS_BOUNDARY_VALUES": _rule_suspicious_boundary_values,
    "RECIPE_INCONSISTENT_RELATED_VARIABLES": _rule_inconsistent_related_variables,
    "RECIPE_LONG_RUNNING_BLOCKED_THREADS": _rule_long_running_blocked_threads,
    "RECIPE_SUSPICIOUS_LOCK_OWNERSHIP": _rule_suspicious_lock_ownership,
    "RECIPE_THREAD_STATE_ANOMALIES": _rule_thread_state_anomalies,
    "RECIPE_OBJECT_LIFETIME_ANOMALIES": _rule_object_lifetime_anomalies,
    "RECIPE_REPEATED_ALLOCATION_PATTERNS": _rule_repeated_allocation_patterns,
    "RECIPE_SHARED_STATE_INCONSISTENCIES": _rule_shared_state_inconsistencies,
}


# The 22 built-in recipes: those defined in this module plus RECIPE_DOUBLE_FREE, whose definition moved to its
# recipe definition file (recipe_plugins/double_free.py) under its built-in id.  Other definition files add more.
BUILTIN_RECIPE_IDS: Tuple[str, ...] = tuple(_RECIPES) + (RECIPE_DOUBLE_FREE,)

# IMP-018: recipe definition files (extractor/recipe_plugins/*.py) register themselves here.
def _load_recipe_plugins() -> None:
    import importlib
    import pkgutil
    from . import recipe_plugins
    for mod in sorted(m.name for m in pkgutil.iter_modules(recipe_plugins.__path__)):
        importlib.import_module(f"{recipe_plugins.__name__}.{mod}")


_load_recipe_plugins()

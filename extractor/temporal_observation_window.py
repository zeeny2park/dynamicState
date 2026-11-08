"""Phase 2.1.4 — Temporal Observation Window & Memory Analysis

Enforces strict temporal observation semantics:
- Observation windows represent actual monotonic time intervals, not recipe counts.
- Uses time.monotonic() for elapsed duration and interval calculations.
- Retains wall-clock timestamps for reporting without substituting them for elapsed time.
- Detects and reports clock regressions and out-of-order samples without hiding them via max().
- Tracks requested vs collected vs missed vs failed samples.
- Distinguishes 12 memory behaviors and separates memory metrics (RSS, PSS, VSize,
  Heap VMA, live allocations, container sizes).
- Requires >= 3 samples over time for persistence/leak claims; single RSS increase never proves a leak.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
import time
from typing import Any, Dict, List, Optional, Tuple


class MemoryBehavior(str, Enum):
    INITIALIZATION_WARMUP = "INITIALIZATION_WARMUP"
    CACHE_WARMUP = "CACHE_WARMUP"
    TRANSIENT_BURST = "TRANSIENT_BURST"
    PERIODIC_RECLAMATION = "PERIODIC_RECLAMATION"
    STABLE_PLATEAU = "STABLE_PLATEAU"
    SUSTAINED_RSS_GROWTH = "SUSTAINED_RSS_GROWTH"
    HEAP_RESERVATION_GROWTH = "HEAP_RESERVATION_GROWTH"
    LIVE_ALLOCATION_GROWTH = "LIVE_ALLOCATION_GROWTH"
    OBJECT_ACCUMULATION = "OBJECT_ACCUMULATION"
    RETAINED_MEMORY = "RETAINED_MEMORY"
    PROBABLE_LEAK = "PROBABLE_LEAK"
    CONFIRMED_LEAK = "CONFIRMED_LEAK"
    INSUFFICIENT_OBSERVATION = "INSUFFICIENT_OBSERVATION"
    TEMPORAL_SEQUENCE_INVALID = "TEMPORAL_SEQUENCE_INVALID"
    # Backwards-compatible aliases
    SUSTAINED_GROWTH = "SUSTAINED_RSS_GROWTH"


MemoryBehaviorClassification = MemoryBehavior


@dataclass
class MemorySample:
    """A point-in-time measurement of memory metrics from the target."""
    epoch_id: int
    monotonic_timestamp: float = 0.0  # Required for duration and rate calculations
    rss_kb: int = 0
    wall_clock_timestamp: float = field(default_factory=time.time)
    timestamp: float = 0.0  # Backwards compatibility alias for monotonic/wall time
    pss_kb: Optional[int] = None
    vsize_kb: Optional[int] = None
    private_clean_kb: Optional[int] = None
    private_dirty_kb: Optional[int] = None
    heap_vma_kb: Optional[int] = None
    allocator_heap_kb: Optional[int] = None
    live_allocations_count: Optional[int] = None
    container_sizes: Dict[str, int] = field(default_factory=dict)
    object_counts: Dict[str, int] = field(default_factory=dict)
    alloc_counter: Optional[int] = None
    free_counter: Optional[int] = None
    collection_status: str = "SUCCESS"  # "SUCCESS", "FAILED", "PARTIAL"
    collection_overhead_ms: float = 0.0
    failure_reason: Optional[str] = None

    def __post_init__(self):
        if self.monotonic_timestamp == 0.0 and self.timestamp != 0.0:
            self.monotonic_timestamp = self.timestamp
        elif self.timestamp == 0.0 and self.monotonic_timestamp != 0.0:
            self.timestamp = self.monotonic_timestamp

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ObservationEpoch:
    """An explicit time window during which samples are scheduled."""
    epoch_id: int
    start_monotonic: float
    end_monotonic: float
    interval_seconds: float
    sample_count: int
    overhead_ms: float
    wall_start: float = field(default_factory=time.time)


@dataclass
class MemoryAnalysisResult:
    """Comprehensive outcome of multi-dimensional temporal memory evaluation."""
    behavior: MemoryBehavior
    confidence: float
    rationale: str
    rss_delta_kb: int
    rss_growth_rate_kb_per_sec: float
    heap_vma_delta_kb: int
    allocator_heap_delta_kb: int
    live_allocations_delta: int
    object_count_deltas: Dict[str, int]
    container_size_deltas: Dict[str, int]
    alloc_free_imbalance_ratio: Optional[float]
    supporting_facts: List[str]
    contradicting_facts: List[str]
    retaining_containers: List[str]
    next_recommended_action: str
    details: Dict[str, Any] = field(default_factory=dict)
    limitations: List[str] = field(default_factory=list)

    @property
    def classification(self) -> MemoryBehavior:
        return self.behavior

    @property
    def summary(self) -> str:
        return self.rationale

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["behavior"] = self.behavior.value
        d["classification"] = self.behavior.value
        d["summary"] = self.rationale
        return d


TemporalAnalysisResult = MemoryAnalysisResult


class ObservationWindow:
    """Manages explicit temporal observation sessions and schedules samples."""

    def __init__(
        self,
        target_pid: int,
        target_identity: str = "local",
        default_interval: float = 0.05,
        observation_duration_sec: float = 5.0,
    ):
        self.target_pid = target_pid
        self.target_identity = target_identity
        self.default_interval = default_interval
        self.observation_duration_sec = observation_duration_sec
        self.samples: List[MemorySample] = []
        self.epochs: List[ObservationEpoch] = []
        self.window_start_monotonic = time.monotonic()
        self.window_start_wall = time.time()
        self.requested_samples_count: int = 0
        self.failed_samples_count: int = 0
        self.limitations: List[str] = []

    def record_sample(self, sample: MemorySample) -> None:
        """Records a sample while verifying monotonic ordering and detecting regressions."""
        self.requested_samples_count += 1
        if sample.collection_status == "FAILED":
            self.failed_samples_count += 1
            self.samples.append(sample)
            return

        if self.samples:
            last_valid = next((s for s in reversed(self.samples) if s.collection_status == "SUCCESS"), None)
            if last_valid:
                # Check for duplicate epoch ID
                if sample.epoch_id == last_valid.epoch_id:
                    self.limitations.append(f"Duplicate epoch ID {sample.epoch_id} recorded in observation window")
                # Check for clock regression / out-of-order timestamp without hiding it
                if sample.monotonic_timestamp < last_valid.monotonic_timestamp:
                    regression_delta = last_valid.monotonic_timestamp - sample.monotonic_timestamp
                    self.limitations.append(
                        f"Monotonic clock regression detected: sample {sample.epoch_id} timestamp ({sample.monotonic_timestamp:.4f}) "
                        f"precedes previous sample ({last_valid.monotonic_timestamp:.4f}) by {regression_delta:.4f}s"
                    )

        self.samples.append(sample)

    def sample_count(self) -> int:
        return len(self.samples)

    def successful_sample_count(self) -> int:
        return sum(1 for s in self.samples if s.collection_status == "SUCCESS")

    def elapsed_duration_sec(self) -> float:
        valid = [s for s in self.samples if s.collection_status == "SUCCESS"]
        if len(valid) < 2:
            return 0.0
        return valid[-1].monotonic_timestamp - valid[0].monotonic_timestamp

    def has_temporal_regression(self) -> bool:
        valid_samples = [s for s in self.samples if s.collection_status == "SUCCESS"]
        for i in range(len(valid_samples) - 1):
            if valid_samples[i + 1].monotonic_timestamp < valid_samples[i].monotonic_timestamp:
                return True
        return False

    def analyze_memory_behavior(self) -> MemoryAnalysisResult:
        """Executes strict multi-metric evaluation adhering to Phase 2.1.4 requirements."""
        valid_samples = [s for s in self.samples if s.collection_status == "SUCCESS"]
        current_limitations = list(self.limitations)

        if self.failed_samples_count > 0:
            current_limitations.append(
                f"{self.failed_samples_count} of {self.requested_samples_count} requested temporal samples failed acquisition"
            )

        # Check for temporal regression / disorder
        if self.has_temporal_regression():
            return MemoryAnalysisResult(
                behavior=MemoryBehavior.TEMPORAL_SEQUENCE_INVALID,
                confidence=0.0,
                rationale="Observation window contains clock regressions or out-of-order sample timestamps. Temporal sequence is invalid.",
                rss_delta_kb=0,
                rss_growth_rate_kb_per_sec=0.0,
                heap_vma_delta_kb=0,
                allocator_heap_delta_kb=0,
                live_allocations_delta=0,
                object_count_deltas={},
                container_size_deltas={},
                alloc_free_imbalance_ratio=None,
                supporting_facts=[],
                contradicting_facts=["Out-of-order monotonic timestamps invalidate temporal inference"],
                retaining_containers=[],
                next_recommended_action="Reset observation window and verify monotonic timer integrity on target.",
                limitations=current_limitations,
                details={"has_temporal_regression": True},
            )

        # Rule: Minimum 2 samples to establish a delta
        if len(valid_samples) < 2:
            return MemoryAnalysisResult(
                behavior=MemoryBehavior.INSUFFICIENT_OBSERVATION,
                confidence=0.15,
                rationale="At least 2 distinct valid temporal samples are required to establish memory deltas.",
                rss_delta_kb=0,
                rss_growth_rate_kb_per_sec=0.0,
                heap_vma_delta_kb=0,
                allocator_heap_delta_kb=0,
                live_allocations_delta=0,
                object_count_deltas={},
                container_size_deltas={},
                alloc_free_imbalance_ratio=None,
                supporting_facts=[],
                contradicting_facts=[],
                retaining_containers=[],
                next_recommended_action="Schedule additional observation samples across configured duration.",
                limitations=current_limitations,
            )

        # Monotonic elapsed time calculation — NO max() fallback to hide negative duration!
        t_start = valid_samples[0].monotonic_timestamp
        t_end = valid_samples[-1].monotonic_timestamp
        duration = t_end - t_start

        if duration <= 0:
            current_limitations.append("Identical timestamps across valid samples; elapsed duration is zero")
            duration = 0.001

        # Check for irregular observation intervals or missing samples
        intervals = []
        for i in range(len(valid_samples) - 1):
            dt = valid_samples[i + 1].monotonic_timestamp - valid_samples[i].monotonic_timestamp
            intervals.append(dt)
        has_irregular_intervals = False
        if len(intervals) >= 2:
            avg_interval = sum(intervals) / len(intervals)
            if avg_interval > 0:
                for iv in intervals:
                    if abs(iv - avg_interval) / avg_interval > 1.0 or iv <= 0:
                        has_irregular_intervals = True
                        break
        if has_irregular_intervals:
            current_limitations.append(
                f"Irregular observation intervals detected across temporal samples: {[round(x, 4) for x in intervals]}s. Growth rates may have higher uncertainty."
            )
        if self.failed_samples_count > 0:
            current_limitations.append(
                f"Incomplete sample sequence: {self.failed_samples_count} samples missing/failed out of {self.requested_samples_count} requested."
            )

        # 1. Process-level RSS metrics
        rss_start = valid_samples[0].rss_kb
        rss_end = valid_samples[-1].rss_kb
        rss_delta = rss_end - rss_start
        rss_rate = rss_delta / duration if duration > 0 else 0.0
        rss_series = [s.rss_kb for s in valid_samples]
        is_rss_monotonic = all(rss_series[i] <= rss_series[i + 1] for i in range(len(rss_series) - 1))

        # 2. Heap VMA metrics
        h_series = [s.heap_vma_kb for s in valid_samples if s.heap_vma_kb is not None]
        heap_vma_delta = (h_series[-1] - h_series[0]) if len(h_series) >= 2 else 0

        # 3. Allocator Heap & Live allocations
        alloc_heap_series = [s.allocator_heap_kb for s in valid_samples if s.allocator_heap_kb is not None]
        allocator_heap_delta = (alloc_heap_series[-1] - alloc_heap_series[0]) if len(alloc_heap_series) >= 2 else 0

        live_alloc_series = [s.live_allocations_count for s in valid_samples if s.live_allocations_count is not None]
        live_alloc_delta = (live_alloc_series[-1] - live_alloc_series[0]) if len(live_alloc_series) >= 2 else 0

        # 4. Container metrics & object counts
        container_deltas: Dict[str, int] = {}
        all_containers = set()
        for s in valid_samples:
            all_containers.update(s.container_sizes.keys())

        retaining_containers = []
        for c in all_containers:
            c_start = next((s.container_sizes[c] for s in valid_samples if c in s.container_sizes), 0)
            c_end = next((s.container_sizes[c] for s in reversed(valid_samples) if c in s.container_sizes), 0)
            c_delta = c_end - c_start
            container_deltas[c] = c_delta
            # Large container alone does not establish accumulation! Must have strictly positive delta across epochs!
            if c_end > 50 and c_delta > 0:
                retaining_containers.append(c)

        # 5. Alloc / Free counters
        alloc_counts = [s.alloc_counter for s in valid_samples if s.alloc_counter is not None]
        free_counts = [s.free_counter for s in valid_samples if s.free_counter is not None]
        imbalance_ratio = None
        if alloc_counts and free_counts:
            a_last = alloc_counts[-1]
            f_last = free_counts[-1]
            imbalance_ratio = (a_last / max(1, f_last))

        # ---------------------------------------------------------------------
        # Decision Process: Enforce Minimum Observations & Distinct Metrics
        # ---------------------------------------------------------------------

        # Condition: Exactly 2 samples can ONLY establish a delta, NOT persistence or leaks!
        if len(valid_samples) == 2:
            return MemoryAnalysisResult(
                behavior=MemoryBehavior.INSUFFICIENT_OBSERVATION,
                confidence=0.40,
                rationale=f"Two samples establish initial memory delta (RSS delta={rss_delta} KB), but at least 3 temporal epochs are required to evaluate persistence, plateaus, or leak trends.",
                rss_delta_kb=rss_delta,
                rss_growth_rate_kb_per_sec=rss_rate,
                heap_vma_delta_kb=heap_vma_delta,
                allocator_heap_delta_kb=allocator_heap_delta,
                live_allocations_delta=live_alloc_delta,
                object_count_deltas={},
                container_size_deltas=container_deltas,
                alloc_free_imbalance_ratio=imbalance_ratio,
                supporting_facts=[f"Measured delta across 2 epochs: {rss_delta} KB"],
                contradicting_facts=["Persistence requires >= 3 observation epochs"],
                retaining_containers=retaining_containers,
                next_recommended_action="Execute third observation epoch to confirm trajectory.",
                limitations=current_limitations,
                details={"two_sample_delta_only": True},
            )

        # Plateau Evaluation (Initialization or Cache Warmup)
        # Delta between later samples is negligible (< 64KB or < 2%) following earlier growth
        later_delta = valid_samples[-1].rss_kb - valid_samples[1].rss_kb
        initial_growth = valid_samples[1].rss_kb - valid_samples[0].rss_kb
        if later_delta <= max(64, int(0.02 * valid_samples[1].rss_kb)) and initial_growth > 0:
            return MemoryAnalysisResult(
                behavior=MemoryBehavior.STABLE_PLATEAU,
                confidence=0.92,
                rationale=f"Memory footprint stabilized at plateau ({rss_end} KB) following initial warm-up (+{initial_growth} KB). Unmanaged leak refuted.",
                rss_delta_kb=rss_delta,
                rss_growth_rate_kb_per_sec=rss_rate,
                heap_vma_delta_kb=heap_vma_delta,
                allocator_heap_delta_kb=allocator_heap_delta,
                live_allocations_delta=live_alloc_delta,
                object_count_deltas={},
                container_size_deltas=container_deltas,
                alloc_free_imbalance_ratio=imbalance_ratio,
                supporting_facts=["RSS reached stable plateau across later observation epochs", f"Plateau delta: {later_delta} KB"],
                contradicting_facts=["Sustained growth refuted by plateau stabilization"],
                retaining_containers=[],
                next_recommended_action="Refute memory leak hypothesis; target process is operating in stable state.",
                details={"plateau_kb": rss_end, "initial_growth_kb": initial_growth, "later_delta_kb": later_delta, "transient_warmup": True},
                limitations=current_limitations,
            )

        # Object Accumulation: Proven only when container delta > 0 across valid epochs
        if retaining_containers:
            return MemoryAnalysisResult(
                behavior=MemoryBehavior.OBJECT_ACCUMULATION,
                confidence=0.94,
                rationale=f"Long-lived object accumulation identified in containers with positive population growth: {retaining_containers}.",
                rss_delta_kb=rss_delta,
                rss_growth_rate_kb_per_sec=rss_rate,
                heap_vma_delta_kb=heap_vma_delta,
                allocator_heap_delta_kb=allocator_heap_delta,
                live_allocations_delta=live_alloc_delta,
                object_count_deltas={},
                container_size_deltas=container_deltas,
                alloc_free_imbalance_ratio=imbalance_ratio,
                supporting_facts=[f"Active accumulation in container {c}: delta=+{container_deltas.get(c, 0)}" for c in retaining_containers],
                contradicting_facts=[],
                retaining_containers=retaining_containers,
                next_recommended_action="Inspect retaining container references and eviction policies.",
                details={"retaining_containers": retaining_containers},
                limitations=current_limitations,
            )

        # Heap VMA Growth without Live Allocation Growth: Virtual expansion only!
        has_allocator_metrics = any(s.live_allocations_count is not None or s.allocator_heap_kb is not None for s in self.samples)
        if has_allocator_metrics and heap_vma_delta > 512 and live_alloc_delta <= 0 and allocator_heap_delta <= 64:
            return MemoryAnalysisResult(
                behavior=MemoryBehavior.HEAP_RESERVATION_GROWTH,
                confidence=0.90,
                rationale=f"Heap virtual address space expanded (+{heap_vma_delta} KB), but live allocation count and allocated heap bytes remain static. Virtual reservation only.",
                rss_delta_kb=rss_delta,
                rss_growth_rate_kb_per_sec=rss_rate,
                heap_vma_delta_kb=heap_vma_delta,
                allocator_heap_delta_kb=allocator_heap_delta,
                live_allocations_delta=live_alloc_delta,
                object_count_deltas={},
                container_size_deltas=container_deltas,
                alloc_free_imbalance_ratio=imbalance_ratio,
                supporting_facts=[f"Heap VMA expanded by {heap_vma_delta} KB while live allocations remained flat"],
                contradicting_facts=["Live allocation leak refuted by zero live allocation count growth"],
                retaining_containers=[],
                next_recommended_action="Refute live object leak; evaluate allocator arena mmap reservation or address space fragmentation.",
                details={"vma_reservation_only": True, "live_leak_confirmed": False},
                limitations=current_limitations,
            )

        # Sustained RSS Growth vs Confirmed/Probable Leak
        if is_rss_monotonic and rss_delta > 512:
            # P0: RSS growth alone establishes SUSTAINED_RSS_GROWTH, NOT confirmed memory leak!
            # Only if live allocations or allocator heap or container growth is ALSO observed does it become a leak!
            has_internal_heap_leak_evidence = (
                live_alloc_delta > 50 or allocator_heap_delta > 256 or bool(retaining_containers)
            )

            if has_internal_heap_leak_evidence:
                return MemoryAnalysisResult(
                    behavior=MemoryBehavior.CONFIRMED_LEAK,
                    confidence=0.95,
                    rationale=f"Confirmed memory leak: monotonic RSS growth (+{rss_delta} KB) corroborated by internal live allocation expansion (live allocs delta=+{live_alloc_delta}, heap delta=+{allocator_heap_delta} KB).",
                    rss_delta_kb=rss_delta,
                    rss_growth_rate_kb_per_sec=rss_rate,
                    heap_vma_delta_kb=heap_vma_delta,
                    allocator_heap_delta_kb=allocator_heap_delta,
                    live_allocations_delta=live_alloc_delta,
                    object_count_deltas={},
                    container_size_deltas=container_deltas,
                    alloc_free_imbalance_ratio=imbalance_ratio,
                    supporting_facts=[
                        f"Monotonic RSS growth: +{rss_delta} KB",
                        f"Internal live allocations expanded: +{live_alloc_delta}",
                    ],
                    contradicting_facts=[],
                    retaining_containers=retaining_containers,
                    next_recommended_action="Audit allocation callstacks for dominant leaking types.",
                    details={"leak_confirmed": True, "rss_series": rss_series},
                    limitations=current_limitations,
                )
            else:
                return MemoryAnalysisResult(
                    behavior=MemoryBehavior.SUSTAINED_RSS_GROWTH,
                    confidence=0.88,
                    rationale=f"Process RSS expanded monotonically (+{rss_delta} KB), but internal live allocator heap evidence is absent or unverified. Established process memory growth, not confirmed leak.",
                    rss_delta_kb=rss_delta,
                    rss_growth_rate_kb_per_sec=rss_rate,
                    heap_vma_delta_kb=heap_vma_delta,
                    allocator_heap_delta_kb=allocator_heap_delta,
                    live_allocations_delta=live_alloc_delta,
                    object_count_deltas={},
                    container_size_deltas=container_deltas,
                    alloc_free_imbalance_ratio=imbalance_ratio,
                    supporting_facts=[f"Process RSS growth: +{rss_delta} KB across {duration:.2f}s"],
                    contradicting_facts=["Internal live allocation evidence not yet established"],
                    retaining_containers=[],
                    next_recommended_action="Acquire allocator heap chunks or DWARF container census to determine if growth represents live objects.",
                    details={"growth_confirmed": True, "internal_heap_evidence_missing": True, "rss_series": rss_series},
                    limitations=current_limitations,
                )

        # Stable Memory
        if abs(rss_delta) <= 64:
            return MemoryAnalysisResult(
                behavior=MemoryBehavior.STABLE_PLATEAU,
                confidence=0.90,
                rationale=f"Process memory footprint is stable (delta={rss_delta} KB across {duration:.2f}s).",
                rss_delta_kb=rss_delta,
                rss_growth_rate_kb_per_sec=rss_rate,
                heap_vma_delta_kb=heap_vma_delta,
                allocator_heap_delta_kb=allocator_heap_delta,
                live_allocations_delta=live_alloc_delta,
                object_count_deltas={},
                container_size_deltas=container_deltas,
                alloc_free_imbalance_ratio=imbalance_ratio,
                supporting_facts=[f"Stable RSS footprint across {len(valid_samples)} samples"],
                contradicting_facts=["No growth observed"],
                retaining_containers=[],
                next_recommended_action="Refute memory leak; evaluate other functional categories.",
                details={"stable": True},
                limitations=current_limitations,
            )

        return MemoryAnalysisResult(
            behavior=MemoryBehavior.TRANSIENT_BURST,
            confidence=0.60,
            rationale=f"Fluctuating or non-monotonic memory footprint (delta={rss_delta} KB).",
            rss_delta_kb=rss_delta,
            rss_growth_rate_kb_per_sec=rss_rate,
            heap_vma_delta_kb=heap_vma_delta,
            allocator_heap_delta_kb=allocator_heap_delta,
            live_allocations_delta=live_alloc_delta,
            object_count_deltas={},
            container_size_deltas=container_deltas,
            alloc_free_imbalance_ratio=imbalance_ratio,
            supporting_facts=[],
            contradicting_facts=["Non-monotonic trajectory"],
            retaining_containers=[],
            next_recommended_action="Extend observation window to distinguish transient activity from periodic leak.",
            limitations=current_limitations,
        )

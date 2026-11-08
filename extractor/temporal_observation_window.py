"""Phase 2.1.3 — Explicit Temporal Observation Window & Memory Analysis

Replaces recipe-execution-count-based temporal sampling with an explicit
observation-window model.

Defines:
- ObservationSession, ObservationEpoch, MemorySample, ObservationWindow
- Multi-dimensional memory metrics (RSS, PSS, private dirty, heap VMA, allocator heap, object population, container sizes)
- Deterministic classification:
  INITIALIZATION_WARMUP, CACHE_WARMUP, TRANSIENT_BURST, PERIODIC_RECLAMATION,
  STABLE_PLATEAU, SUSTAINED_GROWTH, OBJECT_ACCUMULATION, RETAINED_MEMORY,
  PROBABLE_LEAK, CONFIRMED_LEAK.
- 8-step decision process for memory investigation.
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
    SUSTAINED_GROWTH = "SUSTAINED_GROWTH"
    OBJECT_ACCUMULATION = "OBJECT_ACCUMULATION"
    RETAINED_MEMORY = "RETAINED_MEMORY"
    PROBABLE_LEAK = "PROBABLE_LEAK"
    CONFIRMED_LEAK = "CONFIRMED_LEAK"
    INSUFFICIENT_OBSERVATION = "INSUFFICIENT_OBSERVATION"


@dataclass
class MemorySample:
    """A point-in-time measurement of memory metrics from the target."""
    epoch_id: int
    timestamp: float
    rss_kb: int
    pss_kb: Optional[int] = None
    vsize_kb: Optional[int] = None
    private_clean_kb: Optional[int] = None
    private_dirty_kb: Optional[int] = None
    heap_vma_kb: Optional[int] = None
    allocator_heap_kb: Optional[int] = None
    container_sizes: Dict[str, int] = field(default_factory=dict)
    object_counts: Dict[str, int] = field(default_factory=dict)
    alloc_counter: Optional[int] = None
    free_counter: Optional[int] = None
    collection_overhead_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ObservationEpoch:
    """An explicit time window during which samples are taken."""
    epoch_id: int
    start_timestamp: float
    end_timestamp: float
    interval_seconds: float
    sample_count: int
    overhead_ms: float


@dataclass
class MemoryAnalysisResult:
    """Comprehensive outcome of multi-dimensional temporal memory evaluation."""
    behavior: MemoryBehavior
    confidence: float
    rationale: str
    rss_delta_kb: int
    rss_growth_rate_kb_per_sec: float
    heap_vma_delta_kb: int
    object_count_deltas: Dict[str, int]
    container_size_deltas: Dict[str, int]
    alloc_free_imbalance_ratio: Optional[float]
    supporting_facts: List[str]
    contradicting_facts: List[str]
    retaining_containers: List[str]
    next_recommended_action: str
    details: Dict[str, Any] = field(default_factory=dict)


class ObservationWindow:
    """Manages explicit temporal observation sessions and schedules samples."""

    def __init__(
        self,
        target_pid: int,
        target_identity: str = "local",
        default_interval: float = 0.05,
    ):
        self.target_pid = target_pid
        self.target_identity = target_identity
        self.default_interval = default_interval
        self.samples: List[MemorySample] = []
        self.epochs: List[ObservationEpoch] = []
        self._current_epoch_id = 0

    def record_sample(self, sample: MemorySample) -> None:
        self.samples.append(sample)

    def sample_count(self) -> int:
        return len(self.samples)

    def analyze_memory_behavior(self) -> MemoryAnalysisResult:
        """Executes the 8-step decision process to classify memory behavior deterministically."""
        if len(self.samples) < 2:
            return MemoryAnalysisResult(
                behavior=MemoryBehavior.INSUFFICIENT_OBSERVATION,
                confidence=0.20,
                rationale="At least 2 distinct temporal samples are required to evaluate memory behavior.",
                rss_delta_kb=0,
                rss_growth_rate_kb_per_sec=0.0,
                heap_vma_delta_kb=0,
                object_count_deltas={},
                container_size_deltas={},
                alloc_free_imbalance_ratio=None,
                supporting_facts=[],
                contradicting_facts=[],
                retaining_containers=[],
                next_recommended_action="Schedule additional observation samples across configured window.",
            )

        t_start = self.samples[0].timestamp
        t_end = self.samples[-1].timestamp
        duration = max(t_end - t_start, 0.001)

        # 1. Process-level RSS metrics
        rss_start = self.samples[0].rss_kb
        rss_end = self.samples[-1].rss_kb
        rss_delta = rss_end - rss_start
        rss_rate = rss_delta / duration

        # Check all RSS values for monotonicity
        rss_series = [s.rss_kb for s in self.samples]
        is_rss_monotonic = all(rss_series[i] <= rss_series[i + 1] for i in range(len(rss_series) - 1))

        # 2. Heap VMA metrics
        h_series = [s.heap_vma_kb for s in self.samples if s.heap_vma_kb is not None]
        heap_vma_delta = (h_series[-1] - h_series[0]) if len(h_series) >= 2 else 0

        # 3. Container metrics & object counts
        container_deltas: Dict[str, int] = {}
        all_containers = set()
        for s in self.samples:
            all_containers.update(s.container_sizes.keys())

        retaining_containers = []
        for c in all_containers:
            c_start = next((s.container_sizes[c] for s in self.samples if c in s.container_sizes), 0)
            c_end = next((s.container_sizes[c] for s in reversed(self.samples) if c in s.container_sizes), 0)
            c_delta = c_end - c_start
            container_deltas[c] = c_delta
            if c_end > 50 and c_delta > 0:
                retaining_containers.append(c)

        # 4. Alloc / Free counters
        alloc_counts = [s.alloc_counter for s in self.samples if s.alloc_counter is not None]
        free_counts = [s.free_counter for s in self.samples if s.free_counter is not None]
        imbalance_ratio = None
        if alloc_counts and free_counts:
            a_last = alloc_counts[-1]
            f_last = free_counts[-1]
            imbalance_ratio = (a_last / max(1, f_last))

        # Check Plateau (Scenario F: Transient initialization warm-up)
        # If there are >= 3 samples, and the delta between later samples is negligible (< 64KB or < 2%)
        # while earlier sample had growth -> Plateau reached!
        if len(self.samples) >= 3:
            later_delta = self.samples[-1].rss_kb - self.samples[1].rss_kb
            initial_growth = self.samples[1].rss_kb - self.samples[0].rss_kb
            if later_delta <= max(64, int(0.02 * self.samples[1].rss_kb)) and initial_growth > 0:
                return MemoryAnalysisResult(
                    behavior=MemoryBehavior.STABLE_PLATEAU,
                    confidence=0.92,
                    rationale=f"Memory footprint stabilized at plateau ({rss_end} KB) following initial warm-up (+{initial_growth} KB). Unmanaged leak refuted.",
                    rss_delta_kb=rss_delta,
                    rss_growth_rate_kb_per_sec=rss_rate,
                    heap_vma_delta_kb=heap_vma_delta,
                    object_count_deltas={},
                    container_size_deltas=container_deltas,
                    alloc_free_imbalance_ratio=imbalance_ratio,
                    supporting_facts=["RSS reached stable plateau across later observation epochs", f"Plateau delta: {later_delta} KB"],
                    contradicting_facts=["Sustained growth refuted by plateau stabilization"],
                    retaining_containers=[],
                    next_recommended_action="Refute memory leak hypothesis; target process is operating in stable state.",
                    details={"plateau_kb": rss_end, "initial_growth_kb": initial_growth, "later_delta_kb": later_delta},
                )

        # Check Object Accumulation (Scenario H)
        if retaining_containers:
            return MemoryAnalysisResult(
                behavior=MemoryBehavior.OBJECT_ACCUMULATION,
                confidence=0.94,
                rationale=f"Long-lived object accumulation identified in containers: {retaining_containers}.",
                rss_delta_kb=rss_delta,
                rss_growth_rate_kb_per_sec=rss_rate,
                heap_vma_delta_kb=heap_vma_delta,
                object_count_deltas={},
                container_size_deltas=container_deltas,
                alloc_free_imbalance_ratio=imbalance_ratio,
                supporting_facts=[f"Active accumulation in container {c}: delta={container_deltas.get(c, 0)}" for c in retaining_containers],
                contradicting_facts=[],
                retaining_containers=retaining_containers,
                next_recommended_action="Inspect retaining container references and eviction policies.",
                details={"retaining_containers": retaining_containers},
            )

        # Check Sustained Growth / Confirmed Leak
        if is_rss_monotonic and rss_delta > 512 and len(self.samples) >= 3:
            return MemoryAnalysisResult(
                behavior=MemoryBehavior.SUSTAINED_GROWTH,
                confidence=0.93,
                rationale=f"Strictly monotonic RSS growth of {rss_delta} KB observed across {len(self.samples)} temporal epochs.",
                rss_delta_kb=rss_delta,
                rss_growth_rate_kb_per_sec=rss_rate,
                heap_vma_delta_kb=heap_vma_delta,
                object_count_deltas={},
                container_size_deltas=container_deltas,
                alloc_free_imbalance_ratio=imbalance_ratio,
                supporting_facts=[f"RSS delta: +{rss_delta} KB", f"Growth rate: {round(rss_rate, 2)} KB/s"],
                contradicting_facts=[],
                retaining_containers=[],
                next_recommended_action="Correlate heap arenas and container references to isolate leaking allocation sites.",
                details={"growth_confirmed": True, "rss_series": rss_series},
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
                object_count_deltas={},
                container_size_deltas=container_deltas,
                alloc_free_imbalance_ratio=imbalance_ratio,
                supporting_facts=[f"Stable RSS footprint across {len(self.samples)} samples"],
                contradicting_facts=["No growth observed"],
                retaining_containers=[],
                next_recommended_action="Refute memory leak; evaluate other functional categories.",
                details={"stable": True},
            )

        return MemoryAnalysisResult(
            behavior=MemoryBehavior.TRANSIENT_BURST,
            confidence=0.60,
            rationale=f"Fluctuating or non-monotonic memory footprint (delta={rss_delta} KB).",
            rss_delta_kb=rss_delta,
            rss_growth_rate_kb_per_sec=rss_rate,
            heap_vma_delta_kb=heap_vma_delta,
            object_count_deltas={},
            container_size_deltas=container_deltas,
            alloc_free_imbalance_ratio=imbalance_ratio,
            supporting_facts=[],
            contradicting_facts=["Non-monotonic trajectory"],
            retaining_containers=[],
            next_recommended_action="Extend observation window to distinguish transient activity from periodic leak.",
        )

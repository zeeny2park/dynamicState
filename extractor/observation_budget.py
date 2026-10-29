"""Observation Budget and Multi-Dimensional Resource Limiter.

Tracks and enforces multi-dimensional observation constraints:
- max_wall_clock_ms
- max_bytes_read
- min_poll_interval_ms
- max_consecutive_read_failures
- max_samples

Strictly separates distinct observation metrics:
- target_stop_duration_ms (process suspension time, strictly 0.00ms in zero-stop mode)
- observation_latency_us (DWARF decode / memory read execution latency)
- resource overhead (cumulative bytes read, sample counts)
- data consistency level (ZERO_STOP_ATOMIC, CONSISTENT, WEAK_UNSTOPPED, CONCURRENT)
"""

from dataclasses import asdict, dataclass, field
import time
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class ObservationBudgetLimits:
    """Configurable observation limits for investigation runs."""
    max_wall_clock_ms: float = 5000.0
    max_bytes_read: int = 33554432  # 32 MB
    min_poll_interval_ms: float = 10.0
    max_consecutive_read_failures: int = 3
    max_samples: int = 64

    @classmethod
    def from_dict(cls, d: Optional[Dict[str, Any]]) -> "ObservationBudgetLimits":
        if not d:
            return cls()
        return cls(
            max_wall_clock_ms=float(d.get("max_wall_clock_ms", d.get("timeout_ms", 5000.0))),
            max_bytes_read=int(d.get("max_bytes_read", d.get("max_bytes", 33554432))),
            min_poll_interval_ms=float(d.get("min_poll_interval_ms", 10.0)),
            max_consecutive_read_failures=int(d.get("max_consecutive_read_failures", 3)),
            max_samples=int(d.get("max_samples", 64)),
        )


@dataclass
class ObservationMetrics:
    """Disaggregated runtime observation metrics."""
    target_stop_duration_ms: float = 0.0
    observation_latency_us: float = 0.0
    bytes_read: int = 0
    samples_collected: int = 0
    consecutive_read_failures: int = 0
    total_read_failures: int = 0
    consistency_level: str = "ZERO_STOP_ATOMIC"
    wall_clock_elapsed_ms: float = 0.0
    is_budget_exhausted: bool = False
    exhaustion_reason: Optional[str] = None


class ObservationBudgetTracker:
    """Active multi-dimensional budget controller and metrics monitor."""

    def __init__(self, limits: Optional[ObservationBudgetLimits] = None):
        self.limits = limits or ObservationBudgetLimits()
        self.metrics = ObservationMetrics()
        self._start_time_ns: int = time.monotonic_ns()
        self._last_sample_ns: int = 0
        self._history: List[Dict[str, Any]] = []

    def start(self) -> None:
        """Reset or restart wall clock tracking."""
        self._start_time_ns = time.monotonic_ns()
        self._last_sample_ns = 0

    @property
    def elapsed_ms(self) -> float:
        """Wall clock time elapsed in milliseconds since start."""
        return (time.monotonic_ns() - self._start_time_ns) / 1_000_000.0

    def record_read(
        self,
        bytes_read: int,
        latency_us: float = 0.0,
        stop_ms: float = 0.0,
        is_failure: bool = False,
        consistency_level: Optional[str] = None,
    ) -> None:
        """Record an individual memory or DWARF read operation."""
        self.metrics.bytes_read += max(0, bytes_read)
        self.metrics.observation_latency_us += max(0.0, latency_us)
        self.metrics.target_stop_duration_ms += max(0.0, stop_ms)

        if consistency_level:
            self.metrics.consistency_level = consistency_level

        if is_failure:
            self.metrics.consecutive_read_failures += 1
            self.metrics.total_read_failures += 1
        else:
            self.metrics.consecutive_read_failures = 0

        self.metrics.wall_clock_elapsed_ms = round(self.elapsed_ms, 3)

    def record_sample(self, enforce_poll_interval: bool = False) -> None:
        """Record a completed observation sample, optionally throttling poll interval."""
        now_ns = time.monotonic_ns()
        if self._last_sample_ns > 0 and enforce_poll_interval:
            interval_ms = (now_ns - self._last_sample_ns) / 1_000_000.0
            if interval_ms < self.limits.min_poll_interval_ms:
                sleep_needed_s = (self.limits.min_poll_interval_ms - interval_ms) / 1000.0
                if sleep_needed_s > 0:
                    time.sleep(sleep_needed_s)
                    now_ns = time.monotonic_ns()

        self._last_sample_ns = now_ns
        self.metrics.samples_collected += 1
        self.metrics.wall_clock_elapsed_ms = round(self.elapsed_ms, 3)

    def check_budget(self) -> Tuple[bool, Optional[str]]:
        """Checks whether budget limits permit further observation."""
        cur_elapsed = self.elapsed_ms
        self.metrics.wall_clock_elapsed_ms = round(cur_elapsed, 3)

        if cur_elapsed >= self.limits.max_wall_clock_ms:
            self.metrics.is_budget_exhausted = True
            self.metrics.exhaustion_reason = f"EXCEEDED_WALL_CLOCK: elapsed {cur_elapsed:.1f}ms >= max {self.limits.max_wall_clock_ms:.1f}ms"
            return False, self.metrics.exhaustion_reason

        if self.metrics.bytes_read >= self.limits.max_bytes_read:
            self.metrics.is_budget_exhausted = True
            self.metrics.exhaustion_reason = f"EXCEEDED_BYTES_READ: read {self.metrics.bytes_read} >= max {self.limits.max_bytes_read}"
            return False, self.metrics.exhaustion_reason

        if self.metrics.consecutive_read_failures >= self.limits.max_consecutive_read_failures:
            self.metrics.is_budget_exhausted = True
            self.metrics.exhaustion_reason = (
                f"EXCEEDED_CONSECUTIVE_FAILURES: consecutive {self.metrics.consecutive_read_failures} "
                f">= max {self.limits.max_consecutive_read_failures}"
            )
            return False, self.metrics.exhaustion_reason

        if self.metrics.samples_collected >= self.limits.max_samples:
            self.metrics.is_budget_exhausted = True
            self.metrics.exhaustion_reason = f"EXCEEDED_MAX_SAMPLES: samples {self.metrics.samples_collected} >= max {self.limits.max_samples}"
            return False, self.metrics.exhaustion_reason

        return True, None

    def can_continue(self) -> bool:
        """Convenience boolean check."""
        ok, _ = self.check_budget()
        return ok

    def to_dict(self) -> Dict[str, Any]:
        """Serializes limits, metrics, and budget status."""
        self.metrics.wall_clock_elapsed_ms = round(self.elapsed_ms, 3)
        return {
            "limits": asdict(self.limits),
            "metrics": asdict(self.metrics),
            "budget_ok": not self.metrics.is_budget_exhausted,
            "exhaustion_reason": self.metrics.exhaustion_reason,
            "utilization": {
                "wall_clock_pct": round((self.metrics.wall_clock_elapsed_ms / max(1.0, self.limits.max_wall_clock_ms)) * 100.0, 1),
                "bytes_read_pct": round((self.metrics.bytes_read / max(1, self.limits.max_bytes_read)) * 100.0, 1),
                "samples_pct": round((self.metrics.samples_collected / max(1, self.limits.max_samples)) * 100.0, 1),
            },
        }

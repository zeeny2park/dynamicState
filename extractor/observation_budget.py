"""Observation Budget and Multi-Dimensional Resource Limiter.

Tracks and enforces multi-dimensional observation constraints:
- max_wall_clock_ms (wall-clock deadline)
- max_bytes_read (cumulative bytes read ceiling)
- max_samples (number of samples ceiling)
- max_consecutive_read_failures and max_total_read_failures
- min_poll_interval_ms (minimum polling interval)
- max_bytes_per_observation (per-observation byte ceiling)
- max_target_stop_ms (optional target stop duration ceiling)
- Per-profile ceilings (InspectionProfile.budget_ceiling)
- Conservative unknown-cost handling (never treats unknown byte cost as zero,
  and never silently fabricates measured byte counts)

Strictly separates distinct observation metrics:
- target_stop_duration_ms (process suspension time, 0.00ms in zero-stop mode)
- observation_latency_us (DWARF decode / memory read execution latency)
- measured_bytes_read vs conservative_estimated_bytes
- data consistency level (ZERO_STOP_ATOMIC, CONSISTENT, WEAK_UNSTOPPED, CONCURRENT)
"""

from dataclasses import asdict, dataclass, field
import time
from typing import Any, Dict, List, Optional, Tuple


DEFAULT_CONSERVATIVE_UNKNOWN_BYTES = 65536  # 64 KB conservative fallback when cost is unknown


@dataclass
class ObservationBudgetLimits:
    """Configurable multi-dimensional observation limits for investigation runs."""
    max_wall_clock_ms: float = 5000.0
    max_bytes_read: int = 33554432  # 32 MB
    min_poll_interval_ms: float = 10.0
    max_consecutive_read_failures: int = 3
    max_total_read_failures: int = 10
    max_samples: int = 64
    max_bytes_per_observation: int = 4194304  # 4 MB per single observation
    max_target_stop_ms: Optional[float] = None
    conservative_unknown_bytes: int = DEFAULT_CONSERVATIVE_UNKNOWN_BYTES
    reject_unknown_byte_cost: bool = False
    # Backward-compatible aliases accepted in constructor
    max_wall_time_ms: Optional[float] = None
    max_consecutive_failures: Optional[int] = None

    def __post_init__(self) -> None:
        if self.max_wall_time_ms is not None:
            self.max_wall_clock_ms = float(self.max_wall_time_ms)
        if self.max_consecutive_failures is not None:
            self.max_consecutive_read_failures = int(self.max_consecutive_failures)
        if self.conservative_unknown_bytes <= 0:
            self.conservative_unknown_bytes = DEFAULT_CONSERVATIVE_UNKNOWN_BYTES

    @classmethod
    def from_dict(cls, d: Optional[Dict[str, Any]]) -> "ObservationBudgetLimits":
        if not d:
            return cls()
        return cls(
            max_wall_clock_ms=float(
                d.get("max_wall_clock_ms", d.get("max_wall_time_ms", d.get("timeout_ms", 5000.0)))
            ),
            max_bytes_read=int(d.get("max_bytes_read", d.get("max_bytes", 33554432))),
            min_poll_interval_ms=float(d.get("min_poll_interval_ms", 10.0)),
            max_consecutive_read_failures=int(
                d.get("max_consecutive_read_failures", d.get("max_consecutive_failures", 3))
            ),
            max_total_read_failures=int(d.get("max_total_read_failures", 10)),
            max_samples=int(d.get("max_samples", 64)),
            max_bytes_per_observation=int(d.get("max_bytes_per_observation", 4194304)),
            max_target_stop_ms=(
                float(d["max_target_stop_ms"]) if d.get("max_target_stop_ms") is not None else None
            ),
            conservative_unknown_bytes=int(
                d.get("conservative_unknown_bytes", DEFAULT_CONSERVATIVE_UNKNOWN_BYTES)
            ),
            reject_unknown_byte_cost=bool(d.get("reject_unknown_byte_cost", False)),
        )


@dataclass
class ObservationMetrics:
    """Disaggregated runtime observation metrics without fabricated measurements."""
    target_stop_duration_ms: float = 0.0
    observation_latency_us: float = 0.0
    bytes_read: int = 0
    measured_bytes_read: int = 0
    conservative_estimated_bytes: int = 0
    unmeasured_reads_count: int = 0
    samples_collected: int = 0
    consecutive_read_failures: int = 0
    total_read_failures: int = 0
    rejected_observations_count: int = 0
    consistency_level: str = "ZERO_STOP_ATOMIC"
    wall_clock_elapsed_ms: float = 0.0
    is_budget_exhausted: bool = False
    exhaustion_reason: Optional[str] = None
    profile_usage: Dict[str, Dict[str, Any]] = field(default_factory=dict)


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

    @property
    def exhaustion_reason(self) -> Optional[str]:
        return self.metrics.exhaustion_reason

    def _get_or_init_profile_usage(self, profile_id: str) -> Dict[str, Any]:
        if profile_id not in self.metrics.profile_usage:
            self.metrics.profile_usage[profile_id] = {
                "bytes_read": 0,
                "measured_bytes_read": 0,
                "conservative_estimated_bytes": 0,
                "unmeasured_reads_count": 0,
                "samples_collected": 0,
                "wall_clock_ms": 0.0,
                "target_stop_ms": 0.0,
                "failures": 0,
                "rejected_count": 0,
            }
        return self.metrics.profile_usage[profile_id]

    def resolve_estimated_bytes(
        self,
        estimated_bytes: Optional[int],
        profile_ceiling: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Optional[int], bool, Optional[str]]:
        """Resolves estimated byte cost without ever treating unknown cost as zero.

        Returns:
            (resolved_bytes, used_conservative_estimate, rejection_reason)
        """
        ceil = profile_ceiling or {}
        if estimated_bytes is None or (isinstance(estimated_bytes, (int, float)) and estimated_bytes < 0):
            if self.limits.reject_unknown_byte_cost or ceil.get("reject_unknown_byte_cost"):
                return (
                    None,
                    False,
                    "UNKNOWN_BYTE_COST_REJECTED: observation byte cost is unknown and strict cost accounting is enabled",
                )
            fallback = ceil.get("conservative_unknown_bytes") or ceil.get("max_bytes_read") or self.limits.conservative_unknown_bytes
            eff = max(1, int(fallback))
            return eff, True, None

        return max(0, int(estimated_bytes)), False, None

    def check_pre_execution(
        self,
        estimated_bytes: Optional[int] = None,
        estimated_latency_ms: float = 0.0,
        estimated_samples: int = 1,
        estimated_stop_ms: float = 0.0,
        profile_id: Optional[str] = None,
        profile_ceiling: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, Optional[str], int]:
        """Validates whether an observation's conservative estimated cost fits within
        remaining global, per-observation, and per-profile budgets BEFORE execution.

        Returns:
            (allowed, rejection_reason, effective_estimated_bytes)
        """
        ok, existing_reason = self.check_budget()
        if not ok:
            return False, existing_reason, 0

        eff_bytes, used_conservative, err_reason = self.resolve_estimated_bytes(
            estimated_bytes, profile_ceiling=profile_ceiling
        )
        if err_reason or eff_bytes is None:
            return False, err_reason or "UNKNOWN_BYTE_COST_REJECTED", 0

        # 1. Per-observation byte ceiling
        if eff_bytes > self.limits.max_bytes_per_observation:
            return (
                False,
                f"EXCEEDED_PER_OBSERVATION_BYTES: estimated {eff_bytes}B > per-observation max {self.limits.max_bytes_per_observation}B",
                eff_bytes,
            )

        # 2. Per-profile budget ceiling enforcement
        ceil = profile_ceiling or {}
        if profile_id and ceil:
            p_usage = self._get_or_init_profile_usage(profile_id)
            p_max_bytes = ceil.get("max_bytes_read", ceil.get("max_bytes"))
            if p_max_bytes is not None and (p_usage["bytes_read"] + eff_bytes) > int(p_max_bytes):
                return (
                    False,
                    f"EXCEEDED_PROFILE_BYTES_CEILING: profile '{profile_id}' current {p_usage['bytes_read']}B + estimated {eff_bytes}B > ceiling {int(p_max_bytes)}B",
                    eff_bytes,
                )
            p_max_samples = ceil.get("max_samples")
            if p_max_samples is not None and (p_usage["samples_collected"] + max(0, estimated_samples)) > int(p_max_samples):
                return (
                    False,
                    f"EXCEEDED_PROFILE_SAMPLES_CEILING: profile '{profile_id}' current {p_usage['samples_collected']} + estimated {estimated_samples} > ceiling {int(p_max_samples)}",
                    eff_bytes,
                )
            p_max_ms = ceil.get("max_wall_clock_ms", ceil.get("timeout_ms"))
            if p_max_ms is not None and (p_usage["wall_clock_ms"] + max(0.0, estimated_latency_ms)) > float(p_max_ms):
                return (
                    False,
                    f"EXCEEDED_PROFILE_WALL_CLOCK_CEILING: profile '{profile_id}' current {p_usage['wall_clock_ms']:.1f}ms + estimated {estimated_latency_ms:.1f}ms > ceiling {float(p_max_ms):.1f}ms",
                    eff_bytes,
                )
            p_max_stop = ceil.get("max_target_stop_ms")
            if p_max_stop is not None and (p_usage["target_stop_ms"] + max(0.0, estimated_stop_ms)) > float(p_max_stop):
                return (
                    False,
                    f"EXCEEDED_PROFILE_STOP_CEILING: profile '{profile_id}' stop {p_usage['target_stop_ms'] + estimated_stop_ms:.2f}ms > ceiling {float(p_max_stop):.2f}ms",
                    eff_bytes,
                )

        # 3. Global remaining budget pre-check (never start an operation whose estimated cost exceeds remaining budget)
        if (self.metrics.bytes_read + eff_bytes) > self.limits.max_bytes_read:
            reason = (
                f"PRECHECK_EXCEEDED_BYTES_READ: current {self.metrics.bytes_read}B + "
                f"{'conservative ' if used_conservative else ''}estimated {eff_bytes}B > max {self.limits.max_bytes_read}B"
            )
            return False, reason, eff_bytes

        cur_elapsed = self.elapsed_ms
        if (cur_elapsed + max(0.0, estimated_latency_ms)) > self.limits.max_wall_clock_ms:
            reason = (
                f"PRECHECK_EXCEEDED_WALL_CLOCK: elapsed {cur_elapsed:.1f}ms + "
                f"estimated {estimated_latency_ms:.1f}ms > max {self.limits.max_wall_clock_ms:.1f}ms"
            )
            return False, reason, eff_bytes

        if (self.metrics.samples_collected + max(0, estimated_samples)) > self.limits.max_samples:
            reason = (
                f"PRECHECK_EXCEEDED_MAX_SAMPLES: current {self.metrics.samples_collected} + "
                f"estimated {estimated_samples} > max {self.limits.max_samples}"
            )
            return False, reason, eff_bytes

        if self.limits.max_target_stop_ms is not None:
            if (self.metrics.target_stop_duration_ms + max(0.0, estimated_stop_ms)) > self.limits.max_target_stop_ms:
                reason = (
                    f"PRECHECK_EXCEEDED_TARGET_STOP: current {self.metrics.target_stop_duration_ms:.2f}ms + "
                    f"estimated {estimated_stop_ms:.2f}ms > max {self.limits.max_target_stop_ms:.2f}ms"
                )
                return False, reason, eff_bytes

        return True, None, eff_bytes

    def record_rejection(self, profile_id: Optional[str], reason: str) -> None:
        """Records a pre-execution budget rejection without fabricating a read or sample."""
        self.metrics.rejected_observations_count += 1
        if profile_id:
            p_usage = self._get_or_init_profile_usage(profile_id)
            p_usage["rejected_count"] += 1
        self._history.append({
            "event": "BUDGET_REJECTED",
            "profile_id": profile_id,
            "reason": reason,
            "elapsed_ms": round(self.elapsed_ms, 3),
        })

    def record_read(
        self,
        bytes_read: Optional[int] = None,
        latency_us: float = 0.0,
        stop_ms: float = 0.0,
        is_failure: bool = False,
        consistency_level: Optional[str] = None,
        conservative_estimate_bytes: Optional[int] = None,
        profile_id: Optional[str] = None,
        profile_ceiling: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Record an individual memory or DWARF read operation.

        Never fabricates a measured byte count when bytes_read is None. Instead, tracks
        measured_bytes_read separately from conservative_estimated_bytes charged to the budget.
        """
        measured = bytes_read is not None and isinstance(bytes_read, (int, float)) and bytes_read >= 0
        if measured:
            actual_b = int(bytes_read)
            self.metrics.measured_bytes_read += actual_b
            self.metrics.bytes_read += actual_b
            charged_b = actual_b
            used_conservative = False
        else:
            self.metrics.unmeasured_reads_count += 1
            if is_failure:
                charged_b = max(0, int(conservative_estimate_bytes or 0))
            else:
                fallback = (
                    conservative_estimate_bytes
                    if (conservative_estimate_bytes is not None and conservative_estimate_bytes > 0)
                    else self.limits.conservative_unknown_bytes
                )
                charged_b = max(1, int(fallback))
            self.metrics.conservative_estimated_bytes += charged_b
            self.metrics.bytes_read += charged_b
            used_conservative = True

        lat_val = max(0.0, float(latency_us))
        stop_val = max(0.0, float(stop_ms))
        self.metrics.observation_latency_us += lat_val
        self.metrics.target_stop_duration_ms += stop_val

        if consistency_level:
            self.metrics.consistency_level = consistency_level

        if is_failure:
            self.metrics.consecutive_read_failures += 1
            self.metrics.total_read_failures += 1
        else:
            self.metrics.consecutive_read_failures = 0

        if profile_id:
            p_usage = self._get_or_init_profile_usage(profile_id)
            p_usage["bytes_read"] += charged_b
            if measured:
                p_usage["measured_bytes_read"] += charged_b
            else:
                p_usage["conservative_estimated_bytes"] += charged_b
                p_usage["unmeasured_reads_count"] += 1
            p_usage["wall_clock_ms"] = round(p_usage["wall_clock_ms"] + (lat_val / 1000.0), 3)
            p_usage["target_stop_ms"] = round(p_usage["target_stop_ms"] + stop_val, 3)
            if is_failure:
                p_usage["failures"] += 1

        self.metrics.wall_clock_elapsed_ms = round(self.elapsed_ms, 3)
        self.check_budget(profile_id=profile_id, profile_ceiling=profile_ceiling)

        rec_summary = {
            "measured_bytes_read": int(bytes_read) if measured else None,
            "charged_bytes": charged_b,
            "used_conservative_byte_estimate": used_conservative,
            "latency_us": lat_val,
            "stop_ms": stop_val,
            "is_failure": is_failure,
        }
        self._history.append({"event": "READ", "profile_id": profile_id, **rec_summary})
        return rec_summary

    def record_observation(
        self,
        duration_ms: float = 0.0,
        bytes_read: Optional[int] = 0,
        success: bool = True,
        stop_ms: float = 0.0,
    ) -> None:
        """Backward-compatible helper for recording an observation in tests."""
        self.record_read(
            bytes_read=bytes_read,
            latency_us=max(0.0, duration_ms * 1000.0),
            stop_ms=stop_ms,
            is_failure=not success,
        )
        self.record_sample()
        if self.metrics.bytes_read > self.limits.max_bytes_read:
            self.metrics.is_budget_exhausted = True
            self.metrics.exhaustion_reason = "BYTES_EXCEEDED"
        elif self.metrics.consecutive_read_failures >= self.limits.max_consecutive_read_failures:
            self.metrics.is_budget_exhausted = True
            self.metrics.exhaustion_reason = "CONSECUTIVE_FAILURES_EXCEEDED"
        elif duration_ms >= self.limits.max_wall_clock_ms or self.elapsed_ms >= self.limits.max_wall_clock_ms:
            self.metrics.is_budget_exhausted = True
            self.metrics.exhaustion_reason = "WALL_CLOCK_EXCEEDED"

    def is_exhausted(self) -> bool:
        """Backward-compatible check for whether the budget is exhausted."""
        if self.metrics.is_budget_exhausted:
            return True
        ok, _ = self.check_budget()
        return not ok

    def record_sample(self, enforce_poll_interval: bool = False, profile_id: Optional[str] = None) -> None:
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
        if profile_id:
            p_usage = self._get_or_init_profile_usage(profile_id)
            p_usage["samples_collected"] += 1
        self.metrics.wall_clock_elapsed_ms = round(self.elapsed_ms, 3)
        self.check_budget()

    def check_budget(
        self,
        profile_id: Optional[str] = None,
        profile_ceiling: Optional[Dict[str, Any]] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Checks whether budget limits permit further observation."""
        cur_elapsed = self.elapsed_ms
        self.metrics.wall_clock_elapsed_ms = round(cur_elapsed, 3)

        if self.metrics.is_budget_exhausted and self.metrics.exhaustion_reason:
            return False, self.metrics.exhaustion_reason

        if cur_elapsed >= self.limits.max_wall_clock_ms:
            self.metrics.is_budget_exhausted = True
            self.metrics.exhaustion_reason = (
                f"EXCEEDED_WALL_CLOCK: elapsed {cur_elapsed:.1f}ms >= max {self.limits.max_wall_clock_ms:.1f}ms"
            )
            return False, self.metrics.exhaustion_reason

        if self.metrics.bytes_read >= self.limits.max_bytes_read:
            self.metrics.is_budget_exhausted = True
            self.metrics.exhaustion_reason = (
                f"EXCEEDED_BYTES_READ: read {self.metrics.bytes_read} >= max {self.limits.max_bytes_read}"
            )
            return False, self.metrics.exhaustion_reason

        if self.metrics.consecutive_read_failures >= self.limits.max_consecutive_read_failures:
            self.metrics.is_budget_exhausted = True
            self.metrics.exhaustion_reason = (
                f"EXCEEDED_CONSECUTIVE_FAILURES: consecutive {self.metrics.consecutive_read_failures} "
                f">= max {self.limits.max_consecutive_read_failures}"
            )
            return False, self.metrics.exhaustion_reason

        if self.metrics.total_read_failures >= self.limits.max_total_read_failures:
            self.metrics.is_budget_exhausted = True
            self.metrics.exhaustion_reason = (
                f"EXCEEDED_TOTAL_FAILURES: total {self.metrics.total_read_failures} "
                f">= max {self.limits.max_total_read_failures}"
            )
            return False, self.metrics.exhaustion_reason

        if self.metrics.samples_collected >= self.limits.max_samples:
            self.metrics.is_budget_exhausted = True
            self.metrics.exhaustion_reason = (
                f"EXCEEDED_MAX_SAMPLES: samples {self.metrics.samples_collected} >= max {self.limits.max_samples}"
            )
            return False, self.metrics.exhaustion_reason

        if self.limits.max_target_stop_ms is not None and self.metrics.target_stop_duration_ms > self.limits.max_target_stop_ms:
            self.metrics.is_budget_exhausted = True
            self.metrics.exhaustion_reason = (
                f"EXCEEDED_TARGET_STOP_DURATION: stop {self.metrics.target_stop_duration_ms:.2f}ms "
                f"> max {self.limits.max_target_stop_ms:.2f}ms"
            )
            return False, self.metrics.exhaustion_reason

        return True, None

    def check_profile_ceiling(
        self,
        profile_id: str,
        profile_ceiling: Optional[Dict[str, Any]],
    ) -> Tuple[bool, Optional[str]]:
        """Checks whether a specific profile has exceeded its declared budget_ceiling."""
        if not profile_ceiling:
            return True, None
        p_usage = self._get_or_init_profile_usage(profile_id)
        p_max_bytes = profile_ceiling.get("max_bytes_read", profile_ceiling.get("max_bytes"))
        if p_max_bytes is not None and p_usage["bytes_read"] > int(p_max_bytes):
            return False, f"PROFILE_BYTES_CEILING_EXCEEDED: {p_usage['bytes_read']}B > {int(p_max_bytes)}B"
        p_max_samples = profile_ceiling.get("max_samples")
        if p_max_samples is not None and p_usage["samples_collected"] > int(p_max_samples):
            return False, f"PROFILE_SAMPLES_CEILING_EXCEEDED: {p_usage['samples_collected']} > {int(p_max_samples)}"
        p_max_ms = profile_ceiling.get("max_wall_clock_ms", profile_ceiling.get("timeout_ms"))
        if p_max_ms is not None and p_usage["wall_clock_ms"] > float(p_max_ms):
            return False, f"PROFILE_WALL_CLOCK_CEILING_EXCEEDED: {p_usage['wall_clock_ms']:.1f}ms > {float(p_max_ms):.1f}ms"
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
            "history_count": len(self._history),
            "utilization": {
                "wall_clock_pct": round(
                    (self.metrics.wall_clock_elapsed_ms / max(1.0, self.limits.max_wall_clock_ms)) * 100.0, 1
                ),
                "bytes_read_pct": round(
                    (self.metrics.bytes_read / max(1, self.limits.max_bytes_read)) * 100.0, 1
                ),
                "samples_pct": round(
                    (self.metrics.samples_collected / max(1, self.limits.max_samples)) * 100.0, 1
                ),
            },
        }

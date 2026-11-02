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
import math
import threading
import time
from typing import Any, Dict, List, Optional, Tuple


def validate_non_negative_int(val: Any) -> Optional[int]:
    """Strictly validate non-negative integer.

    Rejects:
    - bool (subclass of int in Python)
    - negative values (< 0)
    - float (including NaN, +Inf, -Inf, 1.0, 1.5)
    - None or non-numeric types
    - strings, dicts, lists

    Returns valid non-negative int, or None if invalid.
    """
    if isinstance(val, bool):
        return None
    if isinstance(val, int) and val >= 0:
        return val
    return None


def validate_non_negative_float(val: Any) -> Optional[float]:
    """Strictly validate non-negative finite float or int.

    Rejects:
    - bool
    - negative values (< 0.0)
    - NaN, +Inf, -Inf
    - non-numeric types

    Returns valid float >= 0.0, or None if invalid.
    """
    if isinstance(val, bool):
        return None
    if isinstance(val, (int, float)):
        fval = float(val)
        if math.isnan(fval) or math.isinf(fval) or fval < 0.0:
            return None
        return fval
    return None


@dataclass
class ObservationAccountingRecord:
    """Explicit, auditable, transactional record of observation budget accounting."""
    operation_id: str
    accounting_owner: str           # "MODULE_INTERNAL", "WORKMANAGER", "ADAPTER", etc.
    measured_bytes_read: Optional[int] = None
    estimated_bytes_read: Optional[int] = 0
    charged_bytes: Optional[int] = 0
    latency_us: float = 0.0
    accounting_status: str = "PENDING"  # "PENDING", "COMMITTED", "FAILED"
    measurement_type: str = "MEASURED"   # "MEASURED", "ESTIMATED", "CACHE_HIT", "MIXED", "UNKNOWN", "ZERO_BYTES"
    metadata: Dict[str, Any] = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)

    def validate(self) -> None:
        """Strictly validates all numeric fields before commit.

        Rejects bool, negative values, NaN, infinity, and malformed types.
        """
        if self.measured_bytes_read is not None:
            if isinstance(self.measured_bytes_read, bool):
                raise ValueError(f"Invalid boolean value for measured_bytes_read: {self.measured_bytes_read}")
            if isinstance(self.measured_bytes_read, float) and (math.isnan(self.measured_bytes_read) or math.isinf(self.measured_bytes_read)):
                raise ValueError(f"Invalid float (NaN/Inf) for measured_bytes_read: {self.measured_bytes_read}")
            if not isinstance(self.measured_bytes_read, (int, float)) or self.measured_bytes_read < 0:
                raise ValueError(f"Invalid negative or malformed value for measured_bytes_read: {self.measured_bytes_read}")
            self.measured_bytes_read = int(self.measured_bytes_read)

        if self.estimated_bytes_read is not None:
            if isinstance(self.estimated_bytes_read, bool):
                raise ValueError(f"Invalid boolean value for estimated_bytes_read: {self.estimated_bytes_read}")
            if isinstance(self.estimated_bytes_read, float) and (math.isnan(self.estimated_bytes_read) or math.isinf(self.estimated_bytes_read)):
                raise ValueError(f"Invalid float (NaN/Inf) for estimated_bytes_read: {self.estimated_bytes_read}")
            if not isinstance(self.estimated_bytes_read, (int, float)) or self.estimated_bytes_read < 0:
                raise ValueError(f"Invalid negative or malformed value for estimated_bytes_read: {self.estimated_bytes_read}")
            self.estimated_bytes_read = int(self.estimated_bytes_read)

        if self.charged_bytes is not None:
            if isinstance(self.charged_bytes, bool):
                raise ValueError(f"Invalid boolean value for charged_bytes: {self.charged_bytes}")
            if isinstance(self.charged_bytes, float) and (math.isnan(self.charged_bytes) or math.isinf(self.charged_bytes)):
                raise ValueError(f"Invalid float (NaN/Inf) for charged_bytes: {self.charged_bytes}")
            if not isinstance(self.charged_bytes, (int, float)) or self.charged_bytes < 0:
                raise ValueError(f"Invalid negative or malformed value for charged_bytes: {self.charged_bytes}")
            self.charged_bytes = int(self.charged_bytes)

        if self.latency_us is not None:
            if isinstance(self.latency_us, bool):
                raise ValueError(f"Invalid boolean value for latency_us: {self.latency_us}")
            if isinstance(self.latency_us, float) and (math.isnan(self.latency_us) or math.isinf(self.latency_us)):
                raise ValueError(f"Invalid float (NaN/Inf) for latency_us: {self.latency_us}")
            if not isinstance(self.latency_us, (int, float)) or self.latency_us < 0:
                raise ValueError(f"Invalid negative or malformed value for latency_us: {self.latency_us}")
            self.latency_us = float(self.latency_us)

    def transition_to(self, new_status: str) -> None:
        """Thread-safe transactional state transition validation.

        Allowed transitions:
        PENDING -> COMMITTED
        PENDING -> FAILED
        COMMITTED -> COMMITTED (idempotent no-op)
        FAILED -> FAILED (idempotent no-op)
        All other transitions raise RuntimeError.
        """
        with self._lock:
            if self.accounting_status == new_status:
                return
            if self.accounting_status == "COMMITTED":
                raise RuntimeError(
                    f"Cannot transition transaction '{self.operation_id}' from COMMITTED to {new_status}"
                )
            if self.accounting_status == "FAILED" and new_status == "COMMITTED":
                raise RuntimeError(
                    f"Cannot transition transaction '{self.operation_id}' from FAILED to COMMITTED"
                )
            if new_status not in ("PENDING", "COMMITTED", "FAILED"):
                raise ValueError(f"Invalid accounting status: {new_status}")
            self.accounting_status = new_status

    def commit(
        self,
        tracker: Optional["ObservationBudgetTracker"] = None,
        profile_id: Optional[str] = None,
        profile_ceiling: Optional[Dict[str, Any]] = None,
        is_failure: bool = False,
        stop_ms: float = 0.0,
    ) -> bool:
        """Atomically commits the accounting record to the budget tracker."""
        with self._lock:
            if self.accounting_status == "COMMITTED":
                return True  # Already committed, idempotent duplicate prevention
            self.validate()
            if tracker is not None:
                return tracker.commit_transaction(
                    self,
                    profile_id=profile_id,
                    profile_ceiling=profile_ceiling,
                    is_failure=is_failure,
                    stop_ms=stop_ms,
                )
            else:
                self.transition_to("COMMITTED")
                return True

    def to_dict(self) -> Dict[str, Any]:
        with self._lock:
            eff_charged = (
                self.charged_bytes
                if (self.charged_bytes is not None and self.charged_bytes > 0)
                else ((self.measured_bytes_read or 0) + (self.estimated_bytes_read or 0))
            )
            return {
                "operation_id": self.operation_id,
                "accounting_owner": self.accounting_owner,
                "measured_bytes_read": self.measured_bytes_read,
                "estimated_bytes_read": self.estimated_bytes_read if self.estimated_bytes_read is not None else 0,
                "charged_bytes": eff_charged,
                "latency_us": self.latency_us,
                "accounting_status": self.accounting_status,
                "measurement_type": self.measurement_type,
                "metadata": self.metadata,
            }


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
        self._committed_transactions: Dict[str, ObservationAccountingRecord] = {}
        self._transaction_lock = threading.RLock()

    def commit_transaction(
        self,
        record: ObservationAccountingRecord,
        profile_id: Optional[str] = None,
        profile_ceiling: Optional[Dict[str, Any]] = None,
        is_failure: bool = False,
        stop_ms: float = 0.0,
    ) -> bool:
        """Authoritatively commits an ObservationAccountingRecord to this tracker.

        Guarantees:
        - Atomic deduplication: duplicate commits for the same operation_id charge exactly once.
        - Concurrent commits for the same operation_id are thread-safe and charge exactly once.
        - Rejection of unknown cost if reject_unknown_byte_cost is set.
        - Strict numeric validation.
        - Reconciliation: charges tracker metrics for measured and/or estimated bytes.
        - State transition: marks record.accounting_status = 'COMMITTED' only on success.
        - Operation collision: detects conflicting parameters on duplicate operation_id.
        """
        with self._transaction_lock:
            # 1. Deduplication check
            rec_charge = (
                record.charged_bytes
                if (record.charged_bytes is not None and record.charged_bytes > 0)
                else ((record.measured_bytes_read or 0) + (record.estimated_bytes_read or 0))
            )
            if record.operation_id in self._committed_transactions:
                existing = self._committed_transactions[record.operation_id]
                if existing is not record:
                    # Check for conflicting parameters on collision
                    if (
                        existing.charged_bytes != rec_charge
                        or existing.accounting_owner != record.accounting_owner
                    ):
                        raise ValueError(
                            f"Operation ID collision: '{record.operation_id}' was already committed with "
                            f"owner={existing.accounting_owner}, charged={existing.charged_bytes}B, "
                            f"conflicting with owner={record.accounting_owner}, charged={rec_charge}B"
                        )
                # Idempotent duplicate: record is marked COMMITTED without charging again
                with record._lock:
                    if record.accounting_status != "COMMITTED":
                        record.transition_to("COMMITTED")
                return True

            # 2. Validate record fields
            try:
                record.validate()
            except ValueError as ve:
                with record._lock:
                    record.transition_to("FAILED")
                raise ve

            # 3. Check for unknown byte cost handling
            meas_b = record.measured_bytes_read
            est_b = record.estimated_bytes_read
            is_explicit_zero_meas = (meas_b is not None and meas_b == 0)
            is_explicit_zero_est = (est_b is not None and est_b == 0 and meas_b is None)
            is_missing_cost = (
                meas_b is None
                and (est_b is None or est_b == 0)
                and not is_explicit_zero_est
                and record.measurement_type not in ("CACHE_HIT", "ZERO_BYTES")
            )

            if is_missing_cost or record.measurement_type == "UNKNOWN":
                if self.limits.reject_unknown_byte_cost:
                    with record._lock:
                        record.transition_to("FAILED")
                    self.record_rejection(
                        profile_id or record.operation_id,
                        "UNKNOWN_BYTE_COST_REJECTED: observation byte cost is unknown and strict cost accounting is enabled",
                    )
                    return False
                elif is_missing_cost or (est_b is None or est_b == 0):
                    ceil = profile_ceiling or {}
                    fallback = (
                        ceil.get("conservative_unknown_bytes")
                        or self.limits.conservative_unknown_bytes
                    )
                    eff_fallback = max(1, int(fallback))
                    est_b = eff_fallback
                    record.estimated_bytes_read = eff_fallback
                    record.measurement_type = "UNKNOWN"

            # 4. Resolve effective charged bytes
            actual_meas = meas_b if (meas_b is not None and meas_b >= 0) else 0
            actual_est = est_b if (est_b is not None and est_b >= 0) else 0
            total_charge = actual_meas + actual_est
            record.charged_bytes = total_charge

            if record.measurement_type not in ("CACHE_HIT", "UNKNOWN"):
                if is_explicit_zero_meas:
                    record.measurement_type = "ZERO_BYTES"
                elif actual_meas > 0 and actual_est > 0:
                    record.measurement_type = "MIXED"
                elif actual_meas > 0:
                    record.measurement_type = "MEASURED"
                elif actual_est > 0:
                    record.measurement_type = "ESTIMATED"
                else:
                    record.measurement_type = "ZERO_BYTES"

            # 5. Check budget limits
            can_exec, rej_reason = self.check_budget(profile_id=profile_id, profile_ceiling=profile_ceiling)
            if not can_exec and not is_failure:
                with record._lock:
                    record.transition_to("FAILED")
                self.record_rejection(profile_id or record.operation_id, rej_reason or "BUDGET_EXHAUSTED")
                return False

            if not is_failure and total_charge > 0:
                if (self.metrics.bytes_read + total_charge) > self.limits.max_bytes_read:
                    with record._lock:
                        record.transition_to("FAILED")
                    reason = (
                        f"EXCEEDED_BYTES_READ: current {self.metrics.bytes_read}B + "
                        f"charged {total_charge}B > max {self.limits.max_bytes_read}B"
                    )
                    self.metrics.is_budget_exhausted = True
                    self.metrics.exhaustion_reason = reason
                    self.record_rejection(profile_id or record.operation_id, reason)
                    return False

            # 6. Apply charges to tracker metrics
            if actual_meas > 0:
                self.metrics.measured_bytes_read += actual_meas
                self.metrics.bytes_read += actual_meas
            if actual_est > 0:
                self.metrics.conservative_estimated_bytes += actual_est
                self.metrics.bytes_read += actual_est
                if actual_meas == 0:
                    self.metrics.unmeasured_reads_count += 1

            lat_val = max(0.0, float(record.latency_us))
            stop_val = max(0.0, float(stop_ms))
            self.metrics.observation_latency_us += lat_val
            self.metrics.target_stop_duration_ms += stop_val

            if is_failure:
                self.metrics.consecutive_read_failures += 1
                self.metrics.total_read_failures += 1
            else:
                self.metrics.consecutive_read_failures = 0

            eff_prof_id = profile_id or record.operation_id
            if eff_prof_id:
                p_usage = self._get_or_init_profile_usage(eff_prof_id)
                p_usage["bytes_read"] += total_charge
                p_usage["measured_bytes_read"] += actual_meas
                p_usage["conservative_estimated_bytes"] += actual_est
                if actual_meas == 0 and actual_est > 0:
                    p_usage["unmeasured_reads_count"] += 1
                p_usage["wall_clock_ms"] = round(p_usage["wall_clock_ms"] + (lat_val / 1000.0), 3)
                p_usage["target_stop_ms"] = round(p_usage["target_stop_ms"] + stop_val, 3)
                if is_failure:
                    p_usage["failures"] += 1

            self.metrics.wall_clock_elapsed_ms = round(self.elapsed_ms, 3)
            self.check_budget(profile_id=eff_prof_id, profile_ceiling=profile_ceiling)

            self._history.append({
                "event": "TRANSACTION_COMMIT",
                "operation_id": record.operation_id,
                "accounting_owner": record.accounting_owner,
                "measured_bytes_read": actual_meas if meas_b is not None else None,
                "estimated_bytes_read": actual_est,
                "charged_bytes": total_charge,
                "measurement_type": record.measurement_type,
                "latency_us": lat_val,
                "stop_ms": stop_val,
                "is_failure": is_failure,
                "elapsed_ms": round(self.elapsed_ms, 3),
            })

            with record._lock:
                record.transition_to("COMMITTED")
            self._committed_transactions[record.operation_id] = record
            return True

    def is_operation_committed(self, operation_id: str) -> bool:
        """Returns True if the operation_id has an authoritative committed transaction."""
        with self._transaction_lock:
            return operation_id in self._committed_transactions

    def get_committed_record(self, operation_id: str) -> Optional[ObservationAccountingRecord]:
        """Returns the authoritative committed ObservationAccountingRecord for operation_id."""
        with self._transaction_lock:
            return self._committed_transactions.get(operation_id)

    def get_committed_transactions(self) -> Dict[str, ObservationAccountingRecord]:
        """Returns a copy of all authoritative committed transactions."""
        with self._transaction_lock:
            return dict(self._committed_transactions)

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
        # Strict validation of numeric inputs: reject bool, negative, NaN, Inf
        if bytes_read is not None:
            if isinstance(bytes_read, bool):
                raise ValueError(f"Invalid boolean value for bytes_read: {bytes_read}")
            if isinstance(bytes_read, float) and (math.isnan(bytes_read) or math.isinf(bytes_read)):
                raise ValueError(f"Invalid float (NaN/Inf) for bytes_read: {bytes_read}")
            if not isinstance(bytes_read, (int, float)) or bytes_read < 0:
                raise ValueError(f"Invalid negative or malformed value for bytes_read: {bytes_read}")

        if conservative_estimate_bytes is not None:
            if isinstance(conservative_estimate_bytes, bool):
                raise ValueError(f"Invalid boolean value for conservative_estimate_bytes: {conservative_estimate_bytes}")
            if isinstance(conservative_estimate_bytes, float) and (math.isnan(conservative_estimate_bytes) or math.isinf(conservative_estimate_bytes)):
                raise ValueError(f"Invalid float (NaN/Inf) for conservative_estimate_bytes: {conservative_estimate_bytes}")
            if not isinstance(conservative_estimate_bytes, (int, float)) or conservative_estimate_bytes < 0:
                raise ValueError(f"Invalid negative or malformed value for conservative_estimate_bytes: {conservative_estimate_bytes}")

        if latency_us is not None:
            if isinstance(latency_us, bool):
                raise ValueError(f"Invalid boolean value for latency_us: {latency_us}")
            if isinstance(latency_us, float) and (math.isnan(latency_us) or math.isinf(latency_us)):
                raise ValueError(f"Invalid float (NaN/Inf) for latency_us: {latency_us}")
            if not isinstance(latency_us, (int, float)) or latency_us < 0:
                raise ValueError(f"Invalid negative or malformed value for latency_us: {latency_us}")

        # Measured reads: explicit integer >= 0 (partial reads use actual bytes obtained; 0 bytes obtained charged as 0 measured bytes)
        measured = bytes_read is not None and not isinstance(bytes_read, bool) and isinstance(bytes_read, (int, float)) and bytes_read >= 0
        if measured:
            actual_b = max(0, int(bytes_read))
            charged_b = actual_b
            self.metrics.measured_bytes_read += actual_b
            self.metrics.bytes_read += charged_b
            used_conservative = False
        else:
            self.metrics.unmeasured_reads_count += 1
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

        if profile_id and profile_ceiling:
            prof_ok, prof_reason = self.check_profile_ceiling(profile_id, profile_ceiling)
            if not prof_ok:
                return False, prof_reason

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

    def can_continue(
        self,
        profile_id: Optional[str] = None,
        profile_ceiling: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Convenience boolean check."""
        ok, _ = self.check_budget(profile_id=profile_id, profile_ceiling=profile_ceiling)
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

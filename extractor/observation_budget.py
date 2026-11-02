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

from collections.abc import Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
import hashlib
import json
import math
import threading
import time
import types
from typing import Any, Dict, Iterator, List, Optional, Set, Tuple
import uuid


def freeze_metadata(obj: Any) -> Any:
    """Recursively freezes metadata into deeply immutable structures.

    - dict / Mapping -> MappingProxyType of recursively frozen key-value pairs (keys must be strings)
    - list / tuple -> tuple of recursively frozen elements
    - set / frozenset -> frozenset of recursively frozen elements
    - primitives (int, float, str, bool, None) -> unchanged
    - objects with to_dict() -> frozen dict
    - unsupported mutable types -> raise TypeError
    """
    if isinstance(obj, Mapping):
        frozen_dict = {}
        for k, v in obj.items():
            if not isinstance(k, str):
                raise TypeError(f"Metadata dictionary keys must be strings, got {type(k).__name__}: {repr(k)}")
            frozen_dict[k] = freeze_metadata(v)
        return types.MappingProxyType(frozen_dict)
    elif isinstance(obj, (list, tuple)):
        return tuple(freeze_metadata(x) for x in obj)
    elif isinstance(obj, (set, frozenset)):
        return frozenset(freeze_metadata(x) for x in obj)
    elif isinstance(obj, (int, float, str, bool, type(None))):
        return obj
    elif hasattr(obj, "to_dict") and callable(getattr(obj, "to_dict")):
        return freeze_metadata(obj.to_dict())
    else:
        raise TypeError(f"Unsupported metadata value type: {type(obj).__name__} ({repr(obj)})")


def unfreeze_metadata(obj: Any) -> Any:
    """Recursively converts frozen metadata back to mutable Python types for serialization."""
    if isinstance(obj, Mapping):
        return {k: unfreeze_metadata(v) for k, v in obj.items()}
    elif isinstance(obj, (tuple, list)):
        return [unfreeze_metadata(x) for x in obj]
    elif isinstance(obj, (set, frozenset)):
        return {unfreeze_metadata(x) for x in obj}
    elif isinstance(obj, (int, float, str, bool, type(None))):
        return obj
    return obj


def canonical_metadata_digest(metadata: Any) -> str:
    """Computes a deterministic canonical SHA-256 digest of normalized metadata.

    Guarantees that dictionary key insertion order does not affect the digest.
    Rejects unsupported mutable or non-canonical types without silent string conversion.
    """
    def _normalize(obj: Any) -> Any:
        if isinstance(obj, Mapping):
            return {str(k): _normalize(obj[k]) for k in sorted(obj.keys())}
        elif isinstance(obj, (list, tuple)):
            return [_normalize(x) for x in obj]
        elif isinstance(obj, (set, frozenset)):
            return sorted([_normalize(x) for x in obj], key=lambda x: str(x))
        elif isinstance(obj, float):
            return round(obj, 4)
        elif isinstance(obj, (int, str, bool, type(None))):
            return obj
        elif hasattr(obj, "to_dict") and callable(getattr(obj, "to_dict")):
            return _normalize(obj.to_dict())
        raise TypeError(f"Unsupported metadata value type for canonical identity: {type(obj).__name__} ({repr(obj)})")

    normalized = _normalize(metadata or {})
    raw_json = json.dumps(normalized, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(raw_json.encode('utf-8')).hexdigest()


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


@dataclass(frozen=True)
class AccountingFingerprint:
    """Canonical immutable accounting fingerprint for operation collision detection."""
    operation_id: str
    accounting_owner: str
    measured_bytes_read: Optional[int]
    estimated_bytes_read: int
    charged_bytes: int
    measurement_type: str
    profile_id: Optional[str]
    is_failure: bool
    stop_ms: float
    latency_us: float
    session_id: Optional[str] = None
    metadata_digest: str = ""
    physical_consumption_id: Optional[str] = None

    def matches_logical_fields(self, other: "AccountingFingerprint") -> bool:
        """Checks if all logical identity and observation parameter fields match (ignoring physical_consumption_id)."""
        return (
            self.operation_id == other.operation_id
            and self.accounting_owner == other.accounting_owner
            and self.profile_id == other.profile_id
            and self.measured_bytes_read == other.measured_bytes_read
            and self.estimated_bytes_read == other.estimated_bytes_read
            and self.charged_bytes == other.charged_bytes
            and self.measurement_type == other.measurement_type
            and self.is_failure == other.is_failure
            and self.session_id == other.session_id
            and self.metadata_digest == other.metadata_digest
        )


@dataclass(frozen=True)
class CommittedTransactionSnapshot:
    """Immutable, tracker-owned record representing an authoritative committed transaction."""
    operation_id: str
    accounting_owner: str
    measured_bytes_read: Optional[int]
    estimated_bytes_read: int
    charged_bytes: int
    latency_us: float
    stop_ms: float
    is_failure: bool
    accounting_status: str
    measurement_type: str
    fingerprint: AccountingFingerprint
    metadata: Any
    committed_at_ms: float
    session_id: Optional[str] = None
    physical_consumption_id: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.metadata, types.MappingProxyType):
            object.__setattr__(self, "metadata", freeze_metadata(self.metadata or {}))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "operation_id": self.operation_id,
            "accounting_owner": self.accounting_owner,
            "measured_bytes_read": self.measured_bytes_read,
            "estimated_bytes_read": self.estimated_bytes_read,
            "charged_bytes": self.charged_bytes,
            "latency_us": self.latency_us,
            "stop_ms": self.stop_ms,
            "is_failure": self.is_failure,
            "accounting_status": self.accounting_status,
            "measurement_type": self.measurement_type,
            "metadata": unfreeze_metadata(self.metadata),
            "session_id": self.session_id,
            "physical_consumption_id": self.physical_consumption_id,
        }

    def to_record(self) -> "ObservationAccountingRecord":
        return ObservationAccountingRecord(
            operation_id=self.operation_id,
            accounting_owner=self.accounting_owner,
            measured_bytes_read=self.measured_bytes_read,
            estimated_bytes_read=self.estimated_bytes_read,
            charged_bytes=self.charged_bytes,
            latency_us=self.latency_us,
            accounting_status=self.accounting_status,
            measurement_type=self.measurement_type,
            metadata=unfreeze_metadata(self.metadata),
            session_id=self.session_id,
            physical_consumption_id=self.physical_consumption_id,
        )


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
    session_id: Optional[str] = None
    physical_consumption_id: Optional[str] = None
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
        PENDING -> REJECTED
        COMMITTED -> COMMITTED (idempotent no-op)
        FAILED -> FAILED (idempotent no-op)
        REJECTED -> REJECTED (idempotent no-op)
        All other transitions raise RuntimeError.
        """
        with self._lock:
            if self.accounting_status == new_status:
                return
            if self.accounting_status == "COMMITTED":
                raise RuntimeError(
                    f"Cannot transition transaction '{self.operation_id}' from COMMITTED to {new_status}"
                )
            if self.accounting_status in ("FAILED", "REJECTED") and new_status == "COMMITTED":
                raise RuntimeError(
                    f"Cannot transition transaction '{self.operation_id}' from {self.accounting_status} to COMMITTED"
                )
            if new_status not in ("PENDING", "COMMITTED", "FAILED", "REJECTED"):
                raise ValueError(f"Invalid accounting status: {new_status}")
            self.accounting_status = new_status

    def create_fingerprint(
        self,
        profile_id: Optional[str] = None,
        is_failure: bool = False,
        stop_ms: float = 0.0,
        session_id: Optional[str] = None,
        physical_consumption_id: Optional[str] = None,
    ) -> AccountingFingerprint:
        """Computes canonical immutable accounting fingerprint."""
        with self._lock:
            meas_val = self.measured_bytes_read
            est_val = self.estimated_bytes_read if self.estimated_bytes_read is not None else 0
            charged_val = (
                self.charged_bytes
                if (self.charged_bytes is not None and self.charged_bytes > 0)
                else ((meas_val or 0) + est_val)
            )
            meta_digest = canonical_metadata_digest(self.metadata)
            phys_id = physical_consumption_id or self.physical_consumption_id
            return AccountingFingerprint(
                operation_id=self.operation_id,
                accounting_owner=self.accounting_owner,
                measured_bytes_read=meas_val,
                estimated_bytes_read=est_val,
                charged_bytes=charged_val,
                measurement_type=self.measurement_type,
                profile_id=profile_id,
                is_failure=is_failure,
                stop_ms=round(max(0.0, float(stop_ms)), 4),
                latency_us=round(max(0.0, float(self.latency_us)), 4),
                session_id=self.session_id or session_id,
                metadata_digest=meta_digest,
                physical_consumption_id=phys_id,
            )

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
                "metadata": dict(self.metadata),
                "session_id": self.session_id,
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


@dataclass
class BudgetReservation:
    """Explicit tracker-owned reservation lifecycle:
    RESERVED -> CONSUMED -> FINALIZED
    RESERVED -> RELEASED (strictly when consumed_bytes == 0)
    """
    reservation_id: str
    operation_id: str
    reserved_bytes: int
    profile_id: Optional[str] = None
    state: str = "RESERVED"  # "RESERVED", "CONSUMED", "RELEASED", "FINALIZED"
    consumed_bytes: int = 0
    is_failure: bool = False
    scope_id: Optional[str] = None
    created_at_ms: float = 0.0
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def consume(
        self,
        actual_bytes: Optional[int],
        is_failure: bool = False,
    ) -> int:
        """Transitions RESERVED -> CONSUMED."""
        with self._lock:
            if self.state not in ("RESERVED", "CONSUMED"):
                raise RuntimeError(f"Cannot consume reservation '{self.reservation_id}' in state {self.state}")
            self.consumed_bytes = max(0, int(actual_bytes or 0))
            if is_failure:
                self.is_failure = True
            self.state = "CONSUMED"
            return self.consumed_bytes

    def release(self) -> None:
        """Transitions RESERVED -> RELEASED strictly when no physical consumption occurred."""
        with self._lock:
            if self.consumed_bytes > 0:
                raise RuntimeError(f"A reservation must never be released if physical consumption occurred ({self.consumed_bytes}B)")
            if self.state != "RESERVED":
                raise RuntimeError(f"Cannot release reservation '{self.reservation_id}' in state {self.state}")
            self.state = "RELEASED"

    def finalize(self) -> None:
        """Transitions CONSUMED or RESERVED -> FINALIZED upon tracker ledger commit."""
        with self._lock:
            if self.state not in ("CONSUMED", "RESERVED"):
                raise RuntimeError(f"Cannot finalize reservation '{self.reservation_id}' in state {self.state}")
            self.state = "FINALIZED"


class ActiveOperationScope:
    """Thread-scoped operation accounting context with state machine.

    Conceptual States:
    OPEN -> CONSUMING -> FINALIZING -> COMMITTED / FAILED / REJECTED
    """
    def __init__(
        self,
        tracker: "ObservationBudgetTracker",
        operation_id: str,
        profile_id: Optional[str] = None,
        owner: str = "MODULE_INTERNAL",
        metadata: Optional[Dict[str, Any]] = None,
        physical_consumption_id: Optional[str] = None,
    ):
        self.tracker = tracker
        self.operation_id = operation_id
        self.profile_id = profile_id
        self.owner = owner
        self.physical_consumption_id: str = physical_consumption_id or f"{operation_id}__phys_{uuid.uuid4().hex[:8]}"
        self.metadata: Dict[str, Any] = dict(metadata or {})
        self.measured_bytes_read: Optional[int] = None
        self.estimated_bytes_read: int = 0
        self.charged_bytes: int = 0
        self.latency_us: float = 0.0
        self.stop_ms: float = 0.0
        self.reads_count: int = 0
        self.is_failure: bool = False
        self.state: str = "OPEN"
        self._reads: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self.nesting_count: int = 1
        self._active_reservation: Optional[BudgetReservation] = None

    @property
    def is_finalized(self) -> bool:
        with self._lock:
            return self.state in ("COMMITTED", "FAILED", "REJECTED")

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
        reservation: Optional[BudgetReservation] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Record a read attributed directly to this operation scope.

        Validates inputs, reserves budget atomically, and buffers the read in the scope.
        Does NOT prematurely update global aggregate metrics.
        """
        with self._lock:
            if self.state in ("FINALIZING", "COMMITTED", "FAILED", "REJECTED"):
                raise RuntimeError(f"Cannot record read on scope '{self.operation_id}' in state {self.state}")

            if metadata:
                self.metadata.update(metadata)

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

            if bytes_read is None and self.tracker.limits.reject_unknown_byte_cost:
                self.tracker.record_rejection(
                    profile_id or self.profile_id or self.operation_id,
                    "UNKNOWN_BYTE_COST_REJECTED: observation byte cost is unknown and strict cost accounting is enabled",
                )
                self.is_failure = True
                raise ValueError("UNKNOWN_BYTE_COST_REJECTED: observation byte cost is unknown and strict cost accounting is enabled")

            # Check if budget is already exhausted (unless this read has a pre-existing in-flight reservation)
            if self.tracker.is_budget_exhausted and reservation is None:
                self.is_failure = True
                return {
                    "success": False,
                    "status": "BUDGET_EXHAUSTED",
                    "error": f"Budget exhausted: {self.tracker.exhaustion_reason}",
                    "measured_bytes_read": None,
                    "charged_bytes": 0,
                    "used_conservative_byte_estimate": False,
                    "latency_us": 0.0,
                    "stop_ms": 0.0,
                    "is_failure": True,
                }

            measured = bytes_read is not None and not isinstance(bytes_read, bool) and isinstance(bytes_read, (int, float)) and bytes_read >= 0
            if measured:
                actual_b = max(0, int(bytes_read))
                charged_b = actual_b
                used_conservative = False
            else:
                fallback = (
                    conservative_estimate_bytes
                    if (conservative_estimate_bytes is not None and conservative_estimate_bytes > 0)
                    else self.tracker.limits.conservative_unknown_bytes
                )
                charged_b = max(1, int(fallback))
                actual_b = None
                used_conservative = True

            # Atomic budget reservation lifecycle
            eff_prof_id = profile_id or self.profile_id
            if reservation is not None:
                res = reservation
                res.scope_id = self.physical_consumption_id
                res.consume(actual_bytes=charged_b, is_failure=is_failure)
            else:
                try:
                    res = self.tracker.reserve_budget(
                        estimated_bytes=charged_b,
                        profile_id=eff_prof_id,
                        operation_id=self.operation_id,
                        scope=self,
                        profile_ceiling=profile_ceiling,
                        allow_in_flight_overshoot=True,
                    )
                    res.consume(actual_bytes=charged_b, is_failure=is_failure)
                except ValueError as ve:
                    if "BUDGET_EXHAUSTED" in str(ve) or "PROFILE_CEILING_EXCEEDED" in str(ve):
                        self.is_failure = True
                        status_str = "BUDGET_EXHAUSTED" if "BUDGET_EXHAUSTED" in str(ve) else "PROFILE_CEILING_EXCEEDED"
                        return {
                            "success": False,
                            "status": status_str,
                            "error": str(ve),
                            "measured_bytes_read": None,
                            "charged_bytes": 0,
                            "used_conservative_byte_estimate": False,
                            "latency_us": 0.0,
                            "stop_ms": 0.0,
                            "is_failure": True,
                        }
                    raise

            lat_val = max(0.0, float(latency_us or 0.0))
            stop_val = max(0.0, float(stop_ms or 0.0))

            self.reads_count += 1
            if measured:
                if self.measured_bytes_read is None:
                    self.measured_bytes_read = 0
                self.measured_bytes_read += actual_b
            if used_conservative:
                self.estimated_bytes_read += charged_b
            self.charged_bytes += charged_b
            self.latency_us += lat_val
            self.stop_ms += stop_val
            if is_failure:
                self.is_failure = True

            self.state = "CONSUMING"

            read_entry = {
                "measured_bytes_read": actual_b,
                "charged_bytes": charged_b,
                "used_conservative_byte_estimate": used_conservative,
                "latency_us": lat_val,
                "stop_ms": stop_val,
                "is_failure": is_failure,
            }
            self._reads.append(read_entry)

            # Check if this read pushes active consumption over limits
            with self.tracker._transaction_lock:
                total_projected = self.tracker.metrics.bytes_read + self.tracker._active_consumed_bytes()
                if total_projected >= self.tracker.limits.max_bytes_read:
                    self.tracker.metrics.is_budget_exhausted = True
                    self.tracker.metrics.exhaustion_reason = (
                        f"EXCEEDED_BYTES_READ: projected {total_projected}B >= max {self.tracker.limits.max_bytes_read}B"
                    )

            return read_entry

    def finalize(
        self,
        success: bool = True,
        exc: Optional[BaseException] = None,
    ) -> Optional[CommittedTransactionSnapshot]:
        """Finalize and register the operation in the tracker ledger if not already committed."""
        with self._lock:
            if self.state in ("COMMITTED", "FAILED", "REJECTED"):
                return self.tracker.get_committed_record(self.operation_id)

            self.state = "FINALIZING"
            is_fail = (not success) or self.is_failure or (exc is not None)

            if self.tracker.is_operation_committed(self.operation_id):
                if self.reads_count == 0:
                    # Inner executor already authoritatively committed this operation
                    self.state = "COMMITTED"
                    self.tracker._finalize_scope_reservations(self)
                    self.tracker._unregister_active_scope(self)
                    return self.tracker.get_committed_record(self.operation_id)
                # Duplicate physical execution or collision
                return self.tracker._finalize_scope_duplicate_or_collision(self, is_fail=is_fail)

            if self.reads_count > 0:
                return self.tracker._finalize_scope_transaction(self, is_fail=is_fail)
            else:
                self.state = "FAILED" if is_fail else "COMMITTED"
                self.tracker._finalize_scope_reservations(self)
                self.tracker._unregister_active_scope(self)
                return None


class ObservationBudgetTracker:
    """Active multi-dimensional budget controller and metrics monitor."""

    def __init__(
        self,
        limits: Optional[ObservationBudgetLimits] = None,
        session_id: Optional[str] = None,
    ):
        self.limits = limits or ObservationBudgetLimits()
        self.metrics = ObservationMetrics()
        self.session_id: str = session_id or f"session_{uuid.uuid4().hex[:8]}"
        self._start_time_ns: int = time.monotonic_ns()
        self._last_sample_ns: int = 0
        self._history: List[Dict[str, Any]] = []
        self._committed_transactions: Dict[str, CommittedTransactionSnapshot] = {}
        self._physical_consumption_records: Dict[str, CommittedTransactionSnapshot] = {}
        self._active_reservations: Dict[str, BudgetReservation] = {}
        self._failed_operations: Dict[str, str] = {}
        self._transaction_lock = threading.RLock()
        self._thread_local = threading.local()
        self._active_scopes: Dict[str, Set[ActiveOperationScope]] = {}

    def _register_active_scope(self, scope: ActiveOperationScope) -> None:
        with self._transaction_lock:
            if scope.operation_id not in self._active_scopes:
                self._active_scopes[scope.operation_id] = set()
            self._active_scopes[scope.operation_id].add(scope)

    def _unregister_active_scope(self, scope: ActiveOperationScope) -> None:
        with self._transaction_lock:
            if scope.operation_id in self._active_scopes:
                self._active_scopes[scope.operation_id].discard(scope)
                if not self._active_scopes[scope.operation_id]:
                    del self._active_scopes[scope.operation_id]

    def _active_consumed_bytes(self) -> int:
        with self._transaction_lock:
            return sum(s.charged_bytes for scopes in self._active_scopes.values() for s in scopes)

    def _active_reservation_bytes(self, profile_id: Optional[str] = None) -> int:
        with self._transaction_lock:
            active_scope_phys_ids = {
                s.physical_consumption_id for scopes in self._active_scopes.values() for s in scopes if s.charged_bytes > 0
            }
            total = 0
            for r in self._active_reservations.values():
                if profile_id is not None and r.profile_id != profile_id:
                    continue
                if r.state == "RESERVED":
                    total += r.reserved_bytes
                elif r.state == "CONSUMED":
                    if r.scope_id is None or r.scope_id not in active_scope_phys_ids:
                        total += r.consumed_bytes
            return total

    @property
    def remaining_bytes(self) -> int:
        with self._transaction_lock:
            active_res = self._active_reservation_bytes()
            in_flight = self._active_consumed_bytes()
            return max(0, self.limits.max_bytes_read - self.metrics.bytes_read - active_res - in_flight)

    @property
    def remaining_wall_clock_ms(self) -> float:
        return max(0.0, self.limits.max_wall_clock_ms - self.elapsed_ms)

    @property
    def remaining_samples(self) -> int:
        with self._transaction_lock:
            return max(0, self.limits.max_samples - self.metrics.samples_collected)

    @property
    def is_budget_exhausted(self) -> bool:
        with self._transaction_lock:
            return self.metrics.is_budget_exhausted

    def reserve_budget(
        self,
        estimated_bytes: int,
        profile_id: Optional[str] = None,
        operation_id: Optional[str] = None,
        scope: Optional["ActiveOperationScope"] = None,
        profile_ceiling: Optional[Dict[str, Any]] = None,
        allow_in_flight_overshoot: bool = False,
    ) -> BudgetReservation:
        """Atomically reserves budget against global and profile limits before a physical read."""
        with self._transaction_lock:
            if isinstance(estimated_bytes, bool) or not isinstance(estimated_bytes, (int, float)) or estimated_bytes < 0:
                raise ValueError(f"Invalid non-negative reservation bytes: {estimated_bytes}")
            est_b = int(estimated_bytes)
            if self.is_budget_exhausted:
                raise ValueError(f"BUDGET_EXHAUSTED: cannot reserve budget ({self.exhaustion_reason})")

            # Check global limits
            active_res = self._active_reservation_bytes()
            in_flight = self._active_consumed_bytes()
            projected = self.metrics.bytes_read + active_res + in_flight + est_b

            if projected > self.limits.max_bytes_read:
                self.metrics.is_budget_exhausted = True
                self.metrics.exhaustion_reason = (
                    f"EXCEEDED_BYTES_READ: projected reservation {projected}B > max {self.limits.max_bytes_read}B"
                )
                if not allow_in_flight_overshoot:
                    raise ValueError(f"BUDGET_EXHAUSTED: {self.metrics.exhaustion_reason}")

            # Check profile limit if profile has ceiling
            eff_prof_id = profile_id or (scope.profile_id if scope else None)
            if eff_prof_id:
                p_usage = self._get_or_init_profile_usage(eff_prof_id)
                p_active_res = self._active_reservation_bytes(profile_id=eff_prof_id)
                ceil_limit = None
                if profile_ceiling:
                    ceil_limit = profile_ceiling.get("max_bytes_read", profile_ceiling.get("max_bytes"))
                if ceil_limit is None and hasattr(self.limits, "max_profile_bytes"):
                    ceil_limit = self.limits.max_profile_bytes.get(eff_prof_id)

                if ceil_limit is not None and (p_usage["bytes_read"] + p_active_res + est_b) > int(ceil_limit):
                    if not allow_in_flight_overshoot:
                        raise ValueError(
                            f"PROFILE_CEILING_EXCEEDED: Profile '{eff_prof_id}' projected "
                            f"{p_usage['bytes_read'] + p_active_res + est_b}B > max {ceil_limit}B"
                        )

            res_id = f"res_{uuid.uuid4().hex[:8]}"
            res = BudgetReservation(
                reservation_id=res_id,
                operation_id=operation_id or (scope.operation_id if scope else "standalone"),
                reserved_bytes=est_b,
                profile_id=eff_prof_id,
                scope_id=scope.physical_consumption_id if scope else None,
                created_at_ms=round(self.elapsed_ms, 3),
            )
            self._active_reservations[res_id] = res
            return res

    def release_reservation(self, reservation: BudgetReservation) -> None:
        """Transitions a reservation to RELEASED strictly when zero physical bytes were consumed."""
        with self._transaction_lock:
            reservation.release()
            self._active_reservations.pop(reservation.reservation_id, None)

    def _finalize_scope_reservations(self, scope: "ActiveOperationScope") -> None:
        """Transitions all reservations belonging to scope to FINALIZED and cleans them up."""
        with self._transaction_lock:
            to_remove = []
            for r_id, res in self._active_reservations.items():
                if res.scope_id == scope.physical_consumption_id or (res.operation_id == scope.operation_id and res.state in ("RESERVED", "CONSUMED")):
                    res.finalize()
                    to_remove.append(r_id)
            for r_id in to_remove:
                del self._active_reservations[r_id]

    @contextmanager
    def reservation(
        self,
        estimated_bytes: int,
        profile_id: Optional[str] = None,
        operation_id: Optional[str] = None,
        scope: Optional["ActiveOperationScope"] = None,
        profile_ceiling: Optional[Dict[str, Any]] = None,
    ) -> Iterator[BudgetReservation]:
        """Context manager for explicit reservation lifecycle."""
        res = self.reserve_budget(
            estimated_bytes=estimated_bytes,
            profile_id=profile_id,
            operation_id=operation_id,
            scope=scope,
            profile_ceiling=profile_ceiling,
        )
        try:
            yield res
        except Exception:
            if res.state == "RESERVED":
                self.release_reservation(res)
            raise

    @contextmanager
    def operation_scope(
        self,
        operation_id: str,
        profile_id: Optional[str] = None,
        owner: str = "MODULE_INTERNAL",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Iterator[ActiveOperationScope]:
        """Context manager establishing an authoritative thread-local operation scope."""
        if not hasattr(self._thread_local, "scope_stack"):
            self._thread_local.scope_stack = []

        existing_on_thread = None
        for s in self._thread_local.scope_stack:
            if s.operation_id == operation_id:
                existing_on_thread = s
                break

        if existing_on_thread is not None:
            existing_on_thread.nesting_count += 1
            if metadata:
                existing_on_thread.metadata.update(metadata)
            self._thread_local.scope_stack.append(existing_on_thread)
            inner_exc = None
            try:
                yield existing_on_thread
            except BaseException as exc:
                inner_exc = exc
                existing_on_thread.is_failure = True
                raise
            finally:
                self._thread_local.scope_stack.pop()
                existing_on_thread.nesting_count -= 1
                if existing_on_thread.nesting_count == 0:
                    existing_on_thread.finalize(success=(not existing_on_thread.is_failure and inner_exc is None), exc=inner_exc)
            return

        scope = ActiveOperationScope(
            tracker=self,
            operation_id=operation_id,
            profile_id=profile_id,
            owner=owner,
            metadata=metadata,
        )
        self._register_active_scope(scope)
        self._thread_local.scope_stack.append(scope)
        self._thread_local.current_scope = scope

        exc_occurred = None
        try:
            yield scope
        except BaseException as exc:
            exc_occurred = exc
            scope.is_failure = True
            raise
        finally:
            self._thread_local.scope_stack.pop()
            prev = self._thread_local.scope_stack[-1] if self._thread_local.scope_stack else None
            self._thread_local.current_scope = prev
            try:
                scope.finalize(success=(exc_occurred is None and not scope.is_failure), exc=exc_occurred)
            finally:
                self._unregister_active_scope(scope)

    def _finalize_scope_transaction(
        self,
        scope: "ActiveOperationScope",
        is_fail: bool = False,
    ) -> CommittedTransactionSnapshot:
        with self._transaction_lock:
            if scope.operation_id in self._committed_transactions:
                return self._finalize_scope_duplicate_or_collision(scope, is_fail=is_fail)

            try:
                meas_b = scope.measured_bytes_read
                est_b = scope.estimated_bytes_read
                total_charge = scope.charged_bytes

                if meas_b is not None and meas_b > 0 and est_b > 0:
                    m_type = "MIXED"
                elif meas_b is not None and meas_b > 0:
                    m_type = "MEASURED"
                elif est_b > 0:
                    m_type = "ESTIMATED"
                elif meas_b == 0:
                    m_type = "ZERO_BYTES"
                else:
                    m_type = "MEASURED"

                status = "FAILED" if is_fail else "COMMITTED"
                lat_val = max(0.0, float(scope.latency_us))
                stop_val = max(0.0, float(scope.stop_ms))
                actual_meas = meas_b if (meas_b is not None and meas_b >= 0) else 0
                actual_est = est_b if (est_b is not None and est_b >= 0) else 0

                try:
                    frozen_meta = freeze_metadata(scope.metadata)
                    meta_digest = canonical_metadata_digest(scope.metadata)
                except (TypeError, ValueError) as meta_err:
                    is_fail = True
                    status = "FAILED"
                    frozen_meta = freeze_metadata({"metadata_error": str(meta_err)})
                    meta_digest = canonical_metadata_digest(frozen_meta)

                cand_fp = AccountingFingerprint(
                    operation_id=scope.operation_id,
                    accounting_owner=scope.owner,
                    measured_bytes_read=meas_b,
                    estimated_bytes_read=est_b,
                    charged_bytes=total_charge,
                    measurement_type=m_type,
                    profile_id=scope.profile_id,
                    is_failure=is_fail,
                    stop_ms=round(stop_val, 4),
                    latency_us=round(lat_val, 4),
                    session_id=self.session_id,
                    metadata_digest=meta_digest,
                    physical_consumption_id=scope.physical_consumption_id,
                )

                # Commit metrics and ledger as one atomic transaction
                self.metrics.bytes_read += total_charge
                if actual_meas > 0:
                    self.metrics.measured_bytes_read += actual_meas
                if actual_est > 0:
                    self.metrics.conservative_estimated_bytes += actual_est
                    if actual_meas == 0:
                        self.metrics.unmeasured_reads_count += 1

                self.metrics.observation_latency_us += lat_val
                self.metrics.target_stop_duration_ms += stop_val

                if is_fail:
                    self.metrics.total_read_failures += 1
                    self.metrics.consecutive_read_failures += 1
                else:
                    self.metrics.consecutive_read_failures = 0

                eff_prof_id = scope.profile_id or scope.operation_id
                if eff_prof_id:
                    p_usage = self._get_or_init_profile_usage(eff_prof_id)
                    p_usage["bytes_read"] += total_charge
                    p_usage["measured_bytes_read"] += actual_meas
                    p_usage["conservative_estimated_bytes"] += actual_est
                    p_usage["wall_clock_ms"] = round(p_usage["wall_clock_ms"] + (lat_val / 1000.0), 3)
                    p_usage["target_stop_ms"] = round(p_usage["target_stop_ms"] + stop_val, 3)
                    if is_fail:
                        p_usage["failures"] += 1

                self.metrics.wall_clock_elapsed_ms = round(self.elapsed_ms, 3)
                if self.metrics.bytes_read >= self.limits.max_bytes_read:
                    self.metrics.is_budget_exhausted = True
                    self.metrics.exhaustion_reason = (
                        f"EXCEEDED_BYTES_READ: current {self.metrics.bytes_read}B >= max {self.limits.max_bytes_read}B"
                    )

                self._finalize_scope_reservations(scope)
                scope.state = status

                snapshot = CommittedTransactionSnapshot(
                    operation_id=scope.operation_id,
                    accounting_owner=scope.owner,
                    measured_bytes_read=meas_b,
                    estimated_bytes_read=est_b,
                    charged_bytes=total_charge,
                    latency_us=lat_val,
                    stop_ms=stop_val,
                    is_failure=is_fail,
                    accounting_status=status,
                    measurement_type=m_type,
                    fingerprint=cand_fp,
                    metadata=frozen_meta,
                    committed_at_ms=round(self.elapsed_ms, 3),
                    session_id=self.session_id,
                    physical_consumption_id=scope.physical_consumption_id,
                )
                self._committed_transactions[scope.operation_id] = snapshot
                self._physical_consumption_records[scope.physical_consumption_id] = snapshot
                self._unregister_active_scope(scope)

                self._history.append({
                    "event": "TRANSACTION_COMMIT",
                    "operation_id": scope.operation_id,
                    "accounting_owner": scope.owner,
                    "measured_bytes_read": actual_meas if meas_b is not None else None,
                    "estimated_bytes_read": actual_est,
                    "charged_bytes": total_charge,
                    "measurement_type": m_type,
                    "latency_us": lat_val,
                    "stop_ms": stop_val,
                    "is_failure": is_fail,
                    "elapsed_ms": round(self.elapsed_ms, 3),
                })
                return snapshot
            except Exception as e:
                if scope.charged_bytes > 0 and scope.operation_id not in self._committed_transactions:
                    return self._record_emergency_failure_snapshot(scope, error=e)
                raise

    def _finalize_scope_duplicate_or_collision(
        self,
        scope: "ActiveOperationScope",
        is_fail: bool = False,
    ) -> CommittedTransactionSnapshot:
        with self._transaction_lock:
            existing = self._committed_transactions.get(scope.operation_id)
            if existing is None:
                return self._finalize_scope_transaction(scope, is_fail=is_fail)

            meas_b = scope.measured_bytes_read
            est_b = scope.estimated_bytes_read
            total_charge = scope.charged_bytes

            if meas_b is not None and meas_b > 0 and est_b > 0:
                m_type = "MIXED"
            elif meas_b is not None and meas_b > 0:
                m_type = "MEASURED"
            elif est_b > 0:
                m_type = "ESTIMATED"
            elif meas_b == 0:
                m_type = "ZERO_BYTES"
            else:
                m_type = "MEASURED"

            lat_val = max(0.0, float(scope.latency_us))
            stop_val = max(0.0, float(scope.stop_ms))
            actual_meas = meas_b if (meas_b is not None and meas_b >= 0) else 0
            actual_est = est_b if (est_b is not None and est_b >= 0) else 0

            try:
                frozen_meta = freeze_metadata(scope.metadata)
                meta_digest = canonical_metadata_digest(scope.metadata)
            except Exception as meta_err:
                frozen_meta = freeze_metadata({"metadata_error": str(meta_err)})
                meta_digest = canonical_metadata_digest(frozen_meta)

            cand_fp = AccountingFingerprint(
                operation_id=scope.operation_id,
                accounting_owner=scope.owner,
                measured_bytes_read=meas_b,
                estimated_bytes_read=est_b,
                charged_bytes=total_charge,
                measurement_type=m_type,
                profile_id=scope.profile_id,
                is_failure=is_fail,
                stop_ms=round(stop_val, 4),
                latency_us=round(lat_val, 4),
                session_id=self.session_id,
                metadata_digest=meta_digest,
                physical_consumption_id=scope.physical_consumption_id,
            )

            self._finalize_scope_reservations(scope)
            self._unregister_active_scope(scope)

            if total_charge == 0:
                # No physical bytes were consumed: idempotent logical reference
                scope.state = "COMMITTED"
                return existing

            # Physical consumption occurred!
            eff_prof_id = scope.profile_id or scope.operation_id
            is_logical_match = existing.fingerprint.matches_logical_fields(cand_fp)

            if is_logical_match:
                # Same logical operation, concurrent duplicate physical execution!
                dup_id = f"{scope.operation_id}#duplicate_{scope.physical_consumption_id}"
                scope.state = "COMMITTED"

                self.metrics.bytes_read += total_charge
                if actual_meas > 0:
                    self.metrics.measured_bytes_read += actual_meas
                if actual_est > 0:
                    self.metrics.conservative_estimated_bytes += actual_est
                    if actual_meas == 0:
                        self.metrics.unmeasured_reads_count += 1

                self.metrics.observation_latency_us += lat_val
                self.metrics.target_stop_duration_ms += stop_val

                if is_fail:
                    self.metrics.total_read_failures += 1
                    self.metrics.consecutive_read_failures += 1
                else:
                    self.metrics.consecutive_read_failures = 0

                if eff_prof_id:
                    p_usage = self._get_or_init_profile_usage(eff_prof_id)
                    p_usage["bytes_read"] += total_charge
                    p_usage["measured_bytes_read"] += actual_meas
                    p_usage["conservative_estimated_bytes"] += actual_est
                    p_usage["wall_clock_ms"] = round(p_usage["wall_clock_ms"] + (lat_val / 1000.0), 3)
                    p_usage["target_stop_ms"] = round(p_usage["target_stop_ms"] + stop_val, 3)
                    if is_fail:
                        p_usage["failures"] += 1

                self.metrics.wall_clock_elapsed_ms = round(self.elapsed_ms, 3)
                if self.metrics.bytes_read >= self.limits.max_bytes_read:
                    self.metrics.is_budget_exhausted = True
                    self.metrics.exhaustion_reason = (
                        f"EXCEEDED_BYTES_READ: current {self.metrics.bytes_read}B >= max {self.limits.max_bytes_read}B"
                    )

                dup_snap = CommittedTransactionSnapshot(
                    operation_id=dup_id,
                    accounting_owner=scope.owner,
                    measured_bytes_read=meas_b,
                    estimated_bytes_read=est_b,
                    charged_bytes=total_charge,
                    latency_us=lat_val,
                    stop_ms=stop_val,
                    is_failure=is_fail,
                    accounting_status="COMMITTED",
                    measurement_type=m_type,
                    fingerprint=cand_fp,
                    metadata=freeze_metadata({"duplicate_of": scope.operation_id, **unfreeze_metadata(frozen_meta)}),
                    committed_at_ms=round(self.elapsed_ms, 3),
                    session_id=self.session_id,
                    physical_consumption_id=scope.physical_consumption_id,
                )
                self._committed_transactions[dup_id] = dup_snap
                self._physical_consumption_records[scope.physical_consumption_id] = dup_snap
                return dup_snap

            # Collision!
            scope.state = "REJECTED"
            collision_id = f"{scope.operation_id}#collision_{scope.physical_consumption_id}"
            self.metrics.bytes_read += total_charge
            if actual_meas > 0:
                self.metrics.measured_bytes_read += actual_meas
            if actual_est > 0:
                self.metrics.conservative_estimated_bytes += actual_est
            self.metrics.observation_latency_us += lat_val
            self.metrics.target_stop_duration_ms += stop_val
            self.metrics.total_read_failures += 1

            if eff_prof_id:
                p_usage = self._get_or_init_profile_usage(eff_prof_id)
                p_usage["bytes_read"] += total_charge
                p_usage["measured_bytes_read"] += actual_meas
                p_usage["conservative_estimated_bytes"] += actual_est
                p_usage["wall_clock_ms"] = round(p_usage["wall_clock_ms"] + (lat_val / 1000.0), 3)
                p_usage["target_stop_ms"] = round(p_usage["target_stop_ms"] + stop_val, 3)
                p_usage["failures"] += 1

            if self.metrics.bytes_read >= self.limits.max_bytes_read:
                self.metrics.is_budget_exhausted = True

            collision_snap = CommittedTransactionSnapshot(
                operation_id=collision_id,
                accounting_owner=scope.owner,
                measured_bytes_read=meas_b,
                estimated_bytes_read=est_b,
                charged_bytes=total_charge,
                latency_us=lat_val,
                stop_ms=stop_val,
                is_failure=True,
                accounting_status="REJECTED",
                measurement_type=m_type,
                fingerprint=cand_fp,
                metadata=freeze_metadata({"collision_with": scope.operation_id, **unfreeze_metadata(frozen_meta)}),
                committed_at_ms=round(self.elapsed_ms, 3),
                session_id=self.session_id,
                physical_consumption_id=scope.physical_consumption_id,
            )
            self._committed_transactions[collision_id] = collision_snap
            self._physical_consumption_records[scope.physical_consumption_id] = collision_snap

            raise ValueError(
                f"Operation ID collision: '{scope.operation_id}' was already committed with "
                f"fingerprint {existing.fingerprint}, conflicting with candidate {cand_fp}"
            )

    def _record_emergency_failure_snapshot(
        self,
        scope: "ActiveOperationScope",
        error: Exception,
    ) -> CommittedTransactionSnapshot:
        """Emergency ledger commit preserving consumed physical bytes when an unexpected finalization error occurs."""
        with self._transaction_lock:
            meas_b = scope.measured_bytes_read
            est_b = scope.estimated_bytes_read
            total_charge = scope.charged_bytes
            lat_val = max(0.0, float(scope.latency_us))
            stop_val = max(0.0, float(scope.stop_ms))

            self.metrics.bytes_read += total_charge
            if meas_b and meas_b > 0:
                self.metrics.measured_bytes_read += meas_b
            if est_b > 0:
                self.metrics.conservative_estimated_bytes += est_b
            self.metrics.observation_latency_us += lat_val
            self.metrics.target_stop_duration_ms += stop_val
            self.metrics.total_read_failures += 1

            eff_prof_id = scope.profile_id or scope.operation_id
            if eff_prof_id:
                p_usage = self._get_or_init_profile_usage(eff_prof_id)
                p_usage["bytes_read"] += total_charge
                p_usage["measured_bytes_read"] += (meas_b or 0)
                p_usage["conservative_estimated_bytes"] += est_b
                p_usage["wall_clock_ms"] = round(p_usage["wall_clock_ms"] + (lat_val / 1000.0), 3)
                p_usage["target_stop_ms"] = round(p_usage["target_stop_ms"] + stop_val, 3)
                p_usage["failures"] += 1

            if self.metrics.bytes_read >= self.limits.max_bytes_read:
                self.metrics.is_budget_exhausted = True

            scope.state = "FAILED"
            self._finalize_scope_reservations(scope)
            self._unregister_active_scope(scope)

            err_meta = freeze_metadata({"emergency_error": str(error), "error_type": type(error).__name__})
            fp = AccountingFingerprint(
                operation_id=scope.operation_id,
                accounting_owner=scope.owner,
                measured_bytes_read=meas_b,
                estimated_bytes_read=est_b,
                charged_bytes=total_charge,
                measurement_type="MEASURED" if meas_b else "ESTIMATED",
                profile_id=scope.profile_id,
                is_failure=True,
                stop_ms=round(stop_val, 4),
                latency_us=round(lat_val, 4),
                session_id=self.session_id,
                metadata_digest=canonical_metadata_digest(err_meta),
                physical_consumption_id=scope.physical_consumption_id,
            )

            snap = CommittedTransactionSnapshot(
                operation_id=scope.operation_id,
                accounting_owner=scope.owner,
                measured_bytes_read=meas_b,
                estimated_bytes_read=est_b,
                charged_bytes=total_charge,
                latency_us=lat_val,
                stop_ms=stop_val,
                is_failure=True,
                accounting_status="FAILED",
                measurement_type=fp.measurement_type,
                fingerprint=fp,
                metadata=err_meta,
                committed_at_ms=round(self.elapsed_ms, 3),
                session_id=self.session_id,
                physical_consumption_id=scope.physical_consumption_id,
            )
            self._committed_transactions[scope.operation_id] = snap
            self._physical_consumption_records[scope.physical_consumption_id] = snap
            return snap

    def reconcile_ledger(self) -> Dict[str, Any]:
        """Deterministically verifies that all aggregate metrics match the authoritative ledger exactly."""
        with self._transaction_lock:
            snaps = list(self._committed_transactions.values())
            sum_charged = sum(s.charged_bytes for s in snaps)
            sum_measured = sum(s.measured_bytes_read or 0 for s in snaps if s.measured_bytes_read is not None)
            sum_estimated = sum(s.estimated_bytes_read for s in snaps)
            sum_latency = sum(s.latency_us for s in snaps)
            sum_stop = sum(s.stop_ms for s in snaps)
            sum_failures = sum(1 for s in snaps if s.is_failure)
            sum_failed_status = sum(1 for s in snaps if s.accounting_status == "FAILED")
            sum_rejected_status = sum(1 for s in snaps if s.accounting_status == "REJECTED")

            discrepancies = []
            if sum_charged != self.metrics.bytes_read:
                discrepancies.append(f"bytes_read: ledger={sum_charged} vs metrics={self.metrics.bytes_read}")
            if sum_measured != self.metrics.measured_bytes_read:
                discrepancies.append(f"measured_bytes: ledger={sum_measured} vs metrics={self.metrics.measured_bytes_read}")
            if sum_estimated != self.metrics.conservative_estimated_bytes:
                discrepancies.append(f"estimated_bytes: ledger={sum_estimated} vs metrics={self.metrics.conservative_estimated_bytes}")
            if round(sum_latency, 2) != round(self.metrics.observation_latency_us, 2):
                discrepancies.append(f"latency: ledger={sum_latency} vs metrics={self.metrics.observation_latency_us}")
            if round(sum_stop, 2) != round(self.metrics.target_stop_duration_ms, 2):
                discrepancies.append(f"stop_duration: ledger={sum_stop} vs metrics={self.metrics.target_stop_duration_ms}")
            if sum_failures != self.metrics.total_read_failures:
                discrepancies.append(f"failures: ledger={sum_failures} vs metrics={self.metrics.total_read_failures}")

            # Check profile usage
            for prof_id, p_usage in self.metrics.profile_usage.items():
                p_snaps = [
                    s for s in snaps
                    if (s.fingerprint.profile_id == prof_id
                        or (s.fingerprint.profile_id is None and s.operation_id == prof_id)
                        or (s.fingerprint.profile_id is None and s.operation_id.startswith(f"{prof_id}#")))
                ]
                p_charged = sum(s.charged_bytes for s in p_snaps)
                p_meas = sum(s.measured_bytes_read or 0 for s in p_snaps if s.measured_bytes_read is not None)
                p_est = sum(s.estimated_bytes_read for s in p_snaps)
                p_fails = sum(1 for s in p_snaps if s.is_failure)
                if p_charged != p_usage["bytes_read"]:
                    discrepancies.append(f"profile '{prof_id}' bytes: ledger={p_charged} vs usage={p_usage['bytes_read']}")
                if p_meas != p_usage["measured_bytes_read"]:
                    discrepancies.append(f"profile '{prof_id}' measured: ledger={p_meas} vs usage={p_usage['measured_bytes_read']}")
                if p_est != p_usage["conservative_estimated_bytes"]:
                    discrepancies.append(f"profile '{prof_id}' estimated: ledger={p_est} vs usage={p_usage['conservative_estimated_bytes']}")
                if p_fails != p_usage["failures"]:
                    discrepancies.append(f"profile '{prof_id}' failures: ledger={p_fails} vs usage={p_usage['failures']}")

            active_res_bytes = sum(r.reserved_bytes for r in self._active_reservations.values() if r.state == "RESERVED")
            active_in_flight_bytes = self._active_consumed_bytes()
            duplicate_snaps = [s for s in snaps if "#duplicate_" in s.operation_id]
            collision_snaps = [s for s in snaps if "#collision_" in s.operation_id]

            if discrepancies:
                raise AssertionError(f"Tracker ledger reconciliation failed: {'; '.join(discrepancies)}")

            return {
                "reconciled": True,
                "total_transactions": len(snaps),
                "total_bytes_read": sum_charged,
                "total_measured_bytes": sum_measured,
                "total_estimated_bytes": sum_estimated,
                "total_latency_us": sum_latency,
                "total_stop_ms": sum_stop,
                "total_failures": sum_failures,
                "total_failed_outcomes": sum_failed_status,
                "total_rejected_outcomes": sum_rejected_status,
                "duplicate_logical_operations_count": len(duplicate_snaps),
                "collision_records_count": len(collision_snaps),
                "physical_consumption_records_count": len(self._physical_consumption_records),
                "active_reservations_bytes": active_res_bytes,
                "active_in_flight_bytes": active_in_flight_bytes,
            }

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
        - Canonical immutable fingerprint collision detection.
        - Concurrent commits for the same operation_id are thread-safe and charge exactly once.
        - Rejection of unknown cost if reject_unknown_byte_cost is set.
        - Strict numeric validation.
        - Preserves partial consumed costs on failure and budget exhaustion.
        - Single authoritative writer to all tracker metrics and ledger snapshots.
        """
        with self._transaction_lock:
            # 0. Session ID validation
            if record.session_id is not None and record.session_id != self.session_id:
                raise ValueError(
                    f"Session mismatch for operation '{record.operation_id}': "
                    f"tracker session is '{self.session_id}', record session is '{record.session_id}'"
                )

            # 1. Check if operation ID previously failed
            if record.operation_id in self._failed_operations and not is_failure:
                raise ValueError(
                    f"Failed operation ID '{record.operation_id}' cannot be recommitted as a successful transaction"
                )

            # 2. Validate record fields & freeze metadata
            try:
                record.validate()
                frozen_meta = freeze_metadata(record.metadata)
                meta_digest = canonical_metadata_digest(record.metadata)
            except (ValueError, TypeError) as ve:
                with record._lock:
                    record.transition_to("FAILED")
                self._failed_operations[record.operation_id] = f"VALIDATION_ERROR: {ve}"
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
                    self._failed_operations[record.operation_id] = "UNKNOWN_BYTE_COST_REJECTED"
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

            # 4. Resolve effective charged bytes and measurement type
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

            phys_id = record.physical_consumption_id or f"{record.operation_id}__phys_commit"
            record.physical_consumption_id = phys_id

            cand_fingerprint = record.create_fingerprint(
                profile_id=profile_id,
                is_failure=is_failure,
                stop_ms=stop_ms,
                session_id=self.session_id,
                physical_consumption_id=phys_id,
            )

            # 5. Collision & Deduplication check against authoritative committed snapshots
            if record.operation_id in self._committed_transactions:
                existing = self._committed_transactions[record.operation_id]
                if existing.is_failure and not is_failure:
                    raise ValueError(
                        f"Failed operation ID '{record.operation_id}' cannot be recommitted as a successful transaction"
                    )
                if existing.accounting_status in ("REJECTED", "FAILED") and not is_failure:
                    raise ValueError(
                        f"Rejected operation ID '{record.operation_id}' cannot be recommitted as a successful transaction"
                    )
                if existing.fingerprint.matches_logical_fields(cand_fingerprint):
                    # Duplicate commit of the same logical record: idempotent no-op
                    with record._lock:
                        if record.accounting_status != "COMMITTED":
                            record.transition_to("COMMITTED")
                    return True
                else:
                    raise ValueError(
                        f"Operation ID collision: '{record.operation_id}' was already committed with "
                        f"fingerprint {existing.fingerprint}, conflicting with candidate {cand_fingerprint}"
                    )

            # 6. Check budget limits
            can_exec, rej_reason = self.check_budget(profile_id=profile_id, profile_ceiling=profile_ceiling)
            if not can_exec and not is_failure:
                with record._lock:
                    record.transition_to("FAILED")
                self._failed_operations[record.operation_id] = rej_reason or "BUDGET_EXHAUSTED"
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
                    self._failed_operations[record.operation_id] = reason
                    self.metrics.is_budget_exhausted = True
                    self.metrics.exhaustion_reason = reason
                    self.record_rejection(profile_id or record.operation_id, reason)
                    return False

            # 7. Apply charges to tracker metrics (single writer)
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

            # Check if bytes_read exceeds or reaches max_bytes_read (including on failure!)
            if self.metrics.bytes_read >= self.limits.max_bytes_read:
                self.metrics.is_budget_exhausted = True
                self.metrics.exhaustion_reason = (
                    f"EXCEEDED_BYTES_READ: current {self.metrics.bytes_read}B >= max {self.limits.max_bytes_read}B"
                )

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
            record.session_id = self.session_id

            # Create immutable snapshot owned by tracker
            snapshot = CommittedTransactionSnapshot(
                operation_id=record.operation_id,
                accounting_owner=record.accounting_owner,
                measured_bytes_read=actual_meas if meas_b is not None else None,
                estimated_bytes_read=actual_est,
                charged_bytes=total_charge,
                latency_us=lat_val,
                stop_ms=stop_val,
                is_failure=is_failure,
                accounting_status="COMMITTED",
                measurement_type=record.measurement_type,
                fingerprint=cand_fingerprint,
                metadata=dict(record.metadata),
                committed_at_ms=round(self.elapsed_ms, 3),
                session_id=self.session_id,
                physical_consumption_id=phys_id,
            )
            self._committed_transactions[record.operation_id] = snapshot
            self._physical_consumption_records[phys_id] = snapshot
            return True

    def _register_scope_transaction(
        self,
        record: ObservationAccountingRecord,
        profile_id: Optional[str] = None,
        is_failure: bool = False,
        stop_ms: float = 0.0,
    ) -> CommittedTransactionSnapshot:
        """Internal tracker method registering accumulated scope transactions into ledger."""
        with self._transaction_lock:
            phys_id = record.physical_consumption_id or f"{record.operation_id}__phys_scope"
            record.physical_consumption_id = phys_id
            cand_fp = record.create_fingerprint(
                profile_id=profile_id,
                is_failure=is_failure,
                stop_ms=stop_ms,
                session_id=self.session_id,
                physical_consumption_id=phys_id,
            )
            if record.operation_id in self._committed_transactions:
                existing = self._committed_transactions[record.operation_id]
                if existing.fingerprint.matches_logical_fields(cand_fp):
                    return existing
                raise ValueError(
                    f"Operation ID collision: '{record.operation_id}' was already committed with "
                    f"fingerprint {existing.fingerprint}, conflicting with candidate {cand_fp}"
                )

            with record._lock:
                record.transition_to("COMMITTED")
            record.session_id = self.session_id

            snapshot = CommittedTransactionSnapshot(
                operation_id=record.operation_id,
                accounting_owner=record.accounting_owner,
                measured_bytes_read=record.measured_bytes_read,
                estimated_bytes_read=record.estimated_bytes_read or 0,
                charged_bytes=record.charged_bytes or 0,
                latency_us=max(0.0, float(record.latency_us)),
                stop_ms=max(0.0, float(stop_ms)),
                is_failure=is_failure,
                accounting_status="COMMITTED",
                measurement_type=record.measurement_type,
                fingerprint=cand_fp,
                metadata=dict(record.metadata),
                committed_at_ms=round(self.elapsed_ms, 3),
                session_id=self.session_id,
                physical_consumption_id=phys_id,
            )
            self._committed_transactions[record.operation_id] = snapshot
            self._physical_consumption_records[phys_id] = snapshot
            return snapshot

    def get_physical_consumption_records(self) -> Dict[str, CommittedTransactionSnapshot]:
        """Returns read-only dictionary of all physical consumption records."""
        with self._transaction_lock:
            return dict(self._physical_consumption_records)

    def get_active_reservations(self) -> Dict[str, BudgetReservation]:
        """Returns read-only dictionary of active reservations."""
        with self._transaction_lock:
            return dict(self._active_reservations)

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
        operation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Record an individual memory or DWARF read operation.

        Attributed directly to the active thread's operation_scope if active,
        or as an independent standalone operation if called outside any scope.
        """
        active_scope = getattr(self._thread_local, "current_scope", None)
        if active_scope is not None and operation_id is None:
            return active_scope.record_read(
                bytes_read=bytes_read,
                latency_us=latency_us,
                stop_ms=stop_ms,
                is_failure=is_failure,
                consistency_level=consistency_level,
                conservative_estimate_bytes=conservative_estimate_bytes,
                profile_id=profile_id,
                profile_ceiling=profile_ceiling,
            )

        op_id = operation_id or f"standalone_read_{uuid.uuid4().hex[:12]}"
        return self._record_read_internal(
            bytes_read=bytes_read,
            latency_us=latency_us,
            stop_ms=stop_ms,
            is_failure=is_failure,
            consistency_level=consistency_level,
            conservative_estimate_bytes=conservative_estimate_bytes,
            profile_id=profile_id,
            profile_ceiling=profile_ceiling,
            attributed_operation_id=op_id,
            in_scope=False,
        )

    def _record_read_internal(
        self,
        bytes_read: Optional[int] = None,
        latency_us: float = 0.0,
        stop_ms: float = 0.0,
        is_failure: bool = False,
        consistency_level: Optional[str] = None,
        conservative_estimate_bytes: Optional[int] = None,
        profile_id: Optional[str] = None,
        profile_ceiling: Optional[Dict[str, Any]] = None,
        attributed_operation_id: Optional[str] = None,
        in_scope: bool = False,
    ) -> Dict[str, Any]:
        """Internal tracker method applying charges to metrics and ledger."""
        with self._transaction_lock:
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

            if bytes_read is None and self.limits.reject_unknown_byte_cost:
                self.record_rejection(
                    profile_id or attributed_operation_id or "record_read",
                    "UNKNOWN_BYTE_COST_REJECTED: observation byte cost is unknown and strict cost accounting is enabled",
                )
                raise ValueError("UNKNOWN_BYTE_COST_REJECTED: observation byte cost is unknown and strict cost accounting is enabled")

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

            eff_prof_id = profile_id or attributed_operation_id
            if eff_prof_id:
                p_usage = self._get_or_init_profile_usage(eff_prof_id)
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

            # Check if bytes_read exceeds or reaches max_bytes_read
            if self.metrics.bytes_read >= self.limits.max_bytes_read:
                self.metrics.is_budget_exhausted = True
                self.metrics.exhaustion_reason = (
                    f"EXCEEDED_BYTES_READ: read {self.metrics.bytes_read} >= max {self.limits.max_bytes_read}"
                )

            self.check_budget(profile_id=eff_prof_id, profile_ceiling=profile_ceiling)

            rec_summary = {
                "measured_bytes_read": int(bytes_read) if measured else None,
                "charged_bytes": charged_b,
                "used_conservative_byte_estimate": used_conservative,
                "latency_us": lat_val,
                "stop_ms": stop_val,
                "is_failure": is_failure,
            }
            self._history.append({"event": "READ", "profile_id": profile_id, **rec_summary})

            # Standalone read ledger registration (when called outside an operation_scope)
            if not in_scope and attributed_operation_id:
                phys_id = f"{attributed_operation_id}__phys_standalone"
                cand_fp = AccountingFingerprint(
                    operation_id=attributed_operation_id,
                    accounting_owner="STANDALONE_READ",
                    measured_bytes_read=int(bytes_read) if measured else None,
                    estimated_bytes_read=charged_b if not measured else 0,
                    charged_bytes=charged_b,
                    measurement_type="MEASURED" if measured and actual_b > 0 else ("ZERO_BYTES" if measured else "ESTIMATED"),
                    profile_id=profile_id,
                    is_failure=is_failure,
                    stop_ms=round(stop_val, 4),
                    latency_us=round(lat_val, 4),
                    session_id=self.session_id,
                    metadata_digest=canonical_metadata_digest({}),
                    physical_consumption_id=phys_id,
                )
                snapshot = CommittedTransactionSnapshot(
                    operation_id=attributed_operation_id,
                    accounting_owner="STANDALONE_READ",
                    measured_bytes_read=int(bytes_read) if measured else None,
                    estimated_bytes_read=charged_b if not measured else 0,
                    charged_bytes=charged_b,
                    latency_us=lat_val,
                    stop_ms=stop_val,
                    is_failure=is_failure,
                    accounting_status="COMMITTED",
                    measurement_type=cand_fp.measurement_type,
                    fingerprint=cand_fp,
                    metadata={},
                    committed_at_ms=round(self.elapsed_ms, 3),
                    session_id=self.session_id,
                    physical_consumption_id=phys_id,
                )
                self._committed_transactions[attributed_operation_id] = snapshot
                self._physical_consumption_records[phys_id] = snapshot

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

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
import copy
from dataclasses import asdict, dataclass, field
import hashlib
import json
import math
import threading
import time
import types
from typing import Any, Callable, Dict, Iterator, List, Optional, Set, Tuple
import uuid

def clone_frozen(obj: Any) -> Any:
    """Recursively clones metadata or target_spec into an independent deeply frozen structure.

    Guarantees:
    - Mapping / MappingProxyType -> types.MappingProxyType with string keys and recursively frozen values.
    - list / tuple -> tuple of recursively frozen elements.
    - set / frozenset -> frozenset of recursively frozen elements.
    - bytes / bytearray -> bytes.
    - Supported primitives (int, float, str, bool, NoneType) -> returned directly (immutable).
    - Objects with to_dict() -> frozen dict of to_dict().
    - Unsupported mutable types -> raises TypeError explicitly.
    """
    if isinstance(obj, Mapping):
        frozen_dict = {}
        for k, v in obj.items():
            if not isinstance(k, str):
                raise TypeError(f"Metadata dictionary keys must be strings, got {type(k).__name__}: {repr(k)}")
            frozen_dict[k] = clone_frozen(v)
        return types.MappingProxyType(frozen_dict)
    elif isinstance(obj, (list, tuple)):
        return tuple(clone_frozen(x) for x in obj)
    elif isinstance(obj, (set, frozenset)):
        return frozenset(clone_frozen(x) for x in obj)
    elif isinstance(obj, (bytes, bytearray)):
        return bytes(obj)
    elif isinstance(obj, (int, float, str, bool, type(None))):
        return obj
    elif hasattr(obj, "to_dict") and callable(getattr(obj, "to_dict")):
        return clone_frozen(obj.to_dict())
    else:
        raise TypeError(f"Unsupported metadata value type for clone_frozen: {type(obj).__name__} ({repr(obj)})")


def freeze_metadata(obj: Any) -> Any:
    """Recursively freezes metadata into deeply immutable structures.

    - dict / Mapping -> MappingProxyType of recursively frozen key-value pairs (keys must be strings)
    - list / tuple -> tuple of recursively frozen elements
    - set / frozenset -> frozenset of recursively frozen elements
    - bytes / bytearray -> bytes
    - primitives (int, float, str, bool, None) -> unchanged
    - objects with to_dict() -> frozen dict
    - unsupported mutable types -> raise TypeError
    """
    return clone_frozen(obj)


def unfreeze_metadata(obj: Any) -> Any:
    """Recursively converts frozen metadata back to mutable Python types for serialization."""
    if isinstance(obj, Mapping):
        return {str(k): unfreeze_metadata(v) for k, v in obj.items()}
    elif isinstance(obj, (tuple, list)):
        return [unfreeze_metadata(x) for x in obj]
    elif isinstance(obj, (set, frozenset)):
        return {unfreeze_metadata(x) for x in obj}
    elif isinstance(obj, (bytes, bytearray)):
        return bytes(obj)
    elif isinstance(obj, (int, float, str, bool, type(None))):
        return obj
    elif hasattr(obj, "to_dict") and callable(getattr(obj, "to_dict")):
        return unfreeze_metadata(obj.to_dict())
    raise TypeError(f"Unsupported metadata value type for unfreeze: {type(obj).__name__} ({repr(obj)})")


def clone_metadata(obj: Any) -> Any:
    """Recursively clones metadata into standard mutable Python structures (dict, list, set)."""
    return unfreeze_metadata(obj)


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
    accounting_transaction_id: Optional[str] = None
    physical_read_id: Optional[str] = None

    def __post_init__(self) -> None:
        if not isinstance(self.metadata, types.MappingProxyType):
            object.__setattr__(self, "metadata", freeze_metadata(self.metadata or {}))
        if not getattr(self, "accounting_transaction_id", None):
            object.__setattr__(self, "accounting_transaction_id", f"tx_{uuid.uuid4().hex[:12]}")

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
            "accounting_transaction_id": self.accounting_transaction_id,
            "physical_read_id": self.physical_read_id,
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
            accounting_transaction_id=self.accounting_transaction_id,
            physical_read_id=self.physical_read_id,
        )

    def __deepcopy__(self, memo: Dict[int, Any]) -> "CommittedTransactionSnapshot":
        snap = CommittedTransactionSnapshot(
            operation_id=self.operation_id,
            accounting_owner=self.accounting_owner,
            measured_bytes_read=self.measured_bytes_read,
            estimated_bytes_read=self.estimated_bytes_read,
            charged_bytes=self.charged_bytes,
            latency_us=self.latency_us,
            stop_ms=self.stop_ms,
            is_failure=self.is_failure,
            accounting_status=self.accounting_status,
            measurement_type=self.measurement_type,
            fingerprint=self.fingerprint,
            metadata=clone_frozen(self.metadata) if self.metadata is not None else None,
            committed_at_ms=self.committed_at_ms,
            session_id=self.session_id,
            physical_consumption_id=self.physical_consumption_id,
            accounting_transaction_id=self.accounting_transaction_id,
            physical_read_id=self.physical_read_id,
        )
        memo[id(self)] = snap
        return snap


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
    accounting_transaction_id: Optional[str] = None
    physical_read_id: Optional[str] = None
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)

    def __deepcopy__(self, memo: Dict[int, Any]) -> "ObservationAccountingRecord":
        with self._lock:
            rec = ObservationAccountingRecord(
                operation_id=self.operation_id,
                accounting_owner=self.accounting_owner,
                measured_bytes_read=self.measured_bytes_read,
                estimated_bytes_read=self.estimated_bytes_read,
                charged_bytes=self.charged_bytes,
                latency_us=self.latency_us,
                accounting_status=self.accounting_status,
                measurement_type=self.measurement_type,
                metadata=clone_metadata(self.metadata) if self.metadata is not None else {},
                session_id=self.session_id,
                physical_consumption_id=self.physical_consumption_id,
                accounting_transaction_id=self.accounting_transaction_id,
                physical_read_id=self.physical_read_id,
            )
            memo[id(self)] = rec
            return rec

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
class PhysicalReadRecord:
    """Explicit, auditable record of a single physical I/O execution boundary."""
    physical_read_id: str
    reservation_id: str
    physical_consumption_id: str
    operation_id: Optional[str] = None
    target_type: str = "memory_slice"  # "memory_slice", "proc_maps", "thread_task", "proc_statm", "remote_ssh", etc.
    target_spec: Optional[Dict[str, Any]] = None
    state: str = "ADMITTED"  # "ADMITTED", "PHYSICAL_READ_STARTED", "CONSUMED", "ACCOUNTED", "RELEASED", "FAILED_ACCOUNTED"
    measured_bytes_read: Optional[int] = None
    estimated_bytes_read: int = 0
    charged_bytes: int = 0
    latency_us: float = 0.0
    is_failure: bool = False
    failure_reason: Optional[str] = None
    created_at_ms: float = field(default_factory=time.time)
    terminal_at_ms: Optional[float] = None
    _parent_reservation: Optional[Any] = field(default=None, init=False, repr=False)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)
    _transition_history: List[str] = field(default_factory=lambda: ["ADMITTED"], init=False, repr=False)

    def __post_init__(self) -> None:
        if self.target_spec is not None and not isinstance(self.target_spec, types.MappingProxyType):
            self.target_spec = clone_frozen(self.target_spec)

    def __deepcopy__(self, memo: Dict[int, Any]) -> "PhysicalReadRecord":
        with self._lock:
            rec = PhysicalReadRecord(
                physical_read_id=self.physical_read_id,
                reservation_id=self.reservation_id,
                physical_consumption_id=self.physical_consumption_id,
                operation_id=self.operation_id,
                target_type=self.target_type,
                target_spec=clone_frozen(self.target_spec) if self.target_spec is not None else None,
                state=self.state,
                measured_bytes_read=self.measured_bytes_read,
                estimated_bytes_read=self.estimated_bytes_read,
                charged_bytes=self.charged_bytes,
                latency_us=self.latency_us,
                is_failure=self.is_failure,
                failure_reason=self.failure_reason,
                created_at_ms=self.created_at_ms,
                terminal_at_ms=self.terminal_at_ms,
            )
            rec._transition_history = list(self._transition_history)
            rec._parent_reservation = None
            memo[id(self)] = rec
            return rec

    def update_target_spec(self, updates: Dict[str, Any]) -> None:
        """Safely updates target_spec metadata while preserving frozen immutability."""
        with self._lock:
            current = dict(self.target_spec or {})
            current.update(updates)
            self.target_spec = clone_frozen(current)

    @property
    def is_admitted(self) -> bool:
        with self._lock:
            return self.state == "ADMITTED"

    @property
    def is_started(self) -> bool:
        with self._lock:
            return self.state == "PHYSICAL_READ_STARTED"

    @property
    def is_consumed(self) -> bool:
        with self._lock:
            return self.state == "CONSUMED"

    @property
    def is_terminal(self) -> bool:
        with self._lock:
            return self.state in ("ACCOUNTED", "RELEASED", "FAILED_ACCOUNTED")

    @property
    def transition_history(self) -> List[str]:
        with self._lock:
            return list(self._transition_history)

    def mark_started(self) -> None:
        """Transitions ADMITTED -> PHYSICAL_READ_STARTED at the real I/O boundary."""
        with self._lock:
            if self.state == "RELEASED":
                raise RuntimeError(f"Cannot start physical read '{self.physical_read_id}' in terminal state 'RELEASED'")
            if self.state in ("ACCOUNTED", "FAILED_ACCOUNTED"):
                raise RuntimeError(f"Cannot start physical read '{self.physical_read_id}' in terminal state '{self.state}'")
            if self.state in ("PHYSICAL_READ_STARTED", "CONSUMED"):
                return  # Idempotent
            if self.state != "ADMITTED":
                raise RuntimeError(f"Cannot start physical read '{self.physical_read_id}' in state '{self.state}'")
            self.state = "PHYSICAL_READ_STARTED"
            self._transition_history.append("PHYSICAL_READ_STARTED")

    def consume(
        self,
        actual_bytes: Optional[int] = None,
        is_failure: bool = False,
        conservative_estimate_bytes: Optional[int] = None,
        latency_us: float = 0.0,
        failure_reason: Optional[str] = None,
    ) -> int:
        """Transitions ADMITTED or PHYSICAL_READ_STARTED -> CONSUMED."""
        with self._lock:
            if self.state in ("ACCOUNTED", "RELEASED", "FAILED_ACCOUNTED"):
                raise RuntimeError(f"Cannot consume physical read '{self.physical_read_id}' in terminal state '{self.state}'")
            if self.state not in ("ADMITTED", "PHYSICAL_READ_STARTED", "CONSUMED"):
                raise RuntimeError(f"Cannot consume physical read '{self.physical_read_id}' in state '{self.state}'")

            if self.state == "ADMITTED":
                self._transition_history.append("PHYSICAL_READ_STARTED")

            if actual_bytes is not None:
                m_val = max(0, int(actual_bytes))
                self.measured_bytes_read = m_val
                self.estimated_bytes_read = 0
                self.charged_bytes = m_val
            else:
                fallback = int(conservative_estimate_bytes or DEFAULT_CONSERVATIVE_UNKNOWN_BYTES)
                self.measured_bytes_read = None
                self.estimated_bytes_read = max(1, fallback)
                self.charged_bytes = self.estimated_bytes_read

            self.latency_us = max(0.0, float(latency_us or 0.0))
            if is_failure:
                self.is_failure = True
            if failure_reason:
                self.failure_reason = failure_reason
            self.state = "CONSUMED"
            self._transition_history.append("CONSUMED")
            ret_charged = self.charged_bytes

        if self._parent_reservation is not None:
            self._parent_reservation._on_child_read_updated(self)
        return ret_charged

    def release(self) -> None:
        """Transitions ADMITTED -> RELEASED strictly when 0 bytes consumed and I/O was never invoked."""
        with self._lock:
            if self.state == "RELEASED":
                return  # Idempotent for identical outcome
            if self.state in ("ACCOUNTED", "FAILED_ACCOUNTED"):
                raise RuntimeError(
                    f"Conflicting terminal transition: cannot release physical read '{self.physical_read_id}' in terminal state '{self.state}'"
                )
            if self.state == "PHYSICAL_READ_STARTED":
                raise RuntimeError(
                    f"PHYSICAL_READ_STARTED must never transition to RELEASED for physical read '{self.physical_read_id}'"
                )
            if self.charged_bytes > 0:
                raise RuntimeError(
                    f"Physical read '{self.physical_read_id}' cannot be released after consuming bytes ({self.charged_bytes}B)"
                )
            if self.state != "ADMITTED":
                raise RuntimeError(f"Cannot release physical read '{self.physical_read_id}' in state '{self.state}'")
            self.state = "RELEASED"
            self.terminal_at_ms = time.time()
            self._transition_history.append("RELEASED")

        if self._parent_reservation is not None:
            self._parent_reservation._on_child_read_updated(self)

    def account(self) -> None:
        """Transitions CONSUMED -> ACCOUNTED upon authoritative tracker commit."""
        with self._lock:
            if self.state == "ACCOUNTED":
                return  # Idempotent for identical outcome
            if self.state in ("RELEASED", "FAILED_ACCOUNTED"):
                raise RuntimeError(
                    f"Conflicting terminal transition: cannot account physical read '{self.physical_read_id}' in terminal state '{self.state}'"
                )
            if self.state != "CONSUMED":
                raise RuntimeError(f"Cannot account physical read '{self.physical_read_id}' in non-consumed state '{self.state}'")
            self.state = "ACCOUNTED"
            self.terminal_at_ms = time.time()
            self._transition_history.append("ACCOUNTED")

    def mark_failed_accounted(self, failure_reason: Optional[str] = None) -> None:
        """Transitions PHYSICAL_READ_STARTED or CONSUMED -> FAILED_ACCOUNTED preserving physical consumption."""
        with self._lock:
            if self.state == "FAILED_ACCOUNTED":
                if failure_reason is not None and self.failure_reason is not None and self.failure_reason != failure_reason:
                    raise ValueError(
                        f"Conflicting repeated FAILED_ACCOUNTED for physical read '{self.physical_read_id}': "
                        f"existing '{self.failure_reason}' != new '{failure_reason}'"
                    )
                return  # Idempotent for identical outcome
            if self.state in ("ACCOUNTED", "RELEASED"):
                raise RuntimeError(
                    f"Conflicting terminal transition: cannot mark failed_accounted for physical read '{self.physical_read_id}' in terminal state '{self.state}'"
                )
            if self.state not in ("PHYSICAL_READ_STARTED", "CONSUMED"):
                raise RuntimeError(f"Cannot mark failed_accounted for physical read '{self.physical_read_id}' in state '{self.state}'")
            if self.state == "PHYSICAL_READ_STARTED" and self.charged_bytes == 0 and self.measured_bytes_read is None:
                fallback = DEFAULT_CONSERVATIVE_UNKNOWN_BYTES
                self.estimated_bytes_read = fallback
                self.charged_bytes = fallback
                self._transition_history.append("CONSUMED")
            self.is_failure = True
            if failure_reason:
                self.failure_reason = failure_reason
            self.state = "FAILED_ACCOUNTED"
            self.terminal_at_ms = time.time()
            self._transition_history.append("FAILED_ACCOUNTED")

        if self._parent_reservation is not None:
            self._parent_reservation._on_child_read_updated(self)

    def to_consumption_record(
        self,
        operation_id: Optional[str] = None,
        committed_at_ms: Optional[float] = None,
        accounting_status: str = "COMMITTED",
    ) -> "PhysicalConsumptionRecord":
        with self._lock:
            eff_meas = self.measured_bytes_read
            eff_est = self.estimated_bytes_read
            eff_chg = self.charged_bytes
            return PhysicalConsumptionRecord(
                physical_consumption_id=self.physical_consumption_id,
                physical_read_id=self.physical_read_id,
                reservation_id=self.reservation_id,
                operation_id=operation_id or self.operation_id or "unspecified",
                measured_bytes_read=eff_meas,
                estimated_bytes_read=eff_est,
                charged_bytes=eff_chg,
                latency_us=self.latency_us,
                stop_ms=0.0,
                is_failure=self.is_failure,
                accounting_status=accounting_status,
                measurement_type="MEASURED" if eff_meas is not None else "ESTIMATED",
                target_type=self.target_type,
                target_spec=self.target_spec,
                created_at_ms=self.created_at_ms,
                committed_at_ms=committed_at_ms or time.time(),
            )


@dataclass(frozen=True)
class PhysicalConsumptionRecord:
    """Authoritative committed physical consumption record in tracker ledger."""
    physical_consumption_id: str
    physical_read_id: str
    reservation_id: str
    operation_id: str
    measured_bytes_read: Optional[int]
    estimated_bytes_read: int
    charged_bytes: int
    latency_us: float = 0.0
    stop_ms: float = 0.0
    is_failure: bool = False
    accounting_status: str = "COMMITTED"
    measurement_type: str = "MEASURED"
    target_type: str = "memory_slice"
    target_spec: Any = None
    created_at_ms: float = 0.0
    committed_at_ms: float = 0.0
    accounting_owner: str = "ADAPTER"
    fingerprint: Optional[AccountingFingerprint] = None
    metadata: Any = None
    session_id: Optional[str] = None

    def __post_init__(self) -> None:
        if self.target_spec is not None and not isinstance(self.target_spec, types.MappingProxyType):
            object.__setattr__(self, "target_spec", freeze_metadata(self.target_spec))
        if self.metadata is not None and not isinstance(self.metadata, types.MappingProxyType):
            object.__setattr__(self, "metadata", freeze_metadata(self.metadata))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "physical_consumption_id": self.physical_consumption_id,
            "physical_read_id": self.physical_read_id,
            "reservation_id": self.reservation_id,
            "operation_id": self.operation_id,
            "measured_bytes_read": self.measured_bytes_read,
            "estimated_bytes_read": self.estimated_bytes_read,
            "charged_bytes": self.charged_bytes,
            "latency_us": self.latency_us,
            "stop_ms": self.stop_ms,
            "is_failure": self.is_failure,
            "accounting_status": self.accounting_status,
            "measurement_type": self.measurement_type,
            "target_type": self.target_type,
            "target_spec": unfreeze_metadata(self.target_spec),
            "created_at_ms": self.created_at_ms,
            "committed_at_ms": self.committed_at_ms,
            "accounting_owner": self.accounting_owner,
            "session_id": self.session_id,
            "metadata": unfreeze_metadata(self.metadata),
        }

    def __deepcopy__(self, memo: Dict[int, Any]) -> "PhysicalConsumptionRecord":
        rec = PhysicalConsumptionRecord(
            physical_consumption_id=self.physical_consumption_id,
            physical_read_id=self.physical_read_id,
            reservation_id=self.reservation_id,
            operation_id=self.operation_id,
            measured_bytes_read=self.measured_bytes_read,
            estimated_bytes_read=self.estimated_bytes_read,
            charged_bytes=self.charged_bytes,
            latency_us=self.latency_us,
            stop_ms=self.stop_ms,
            is_failure=self.is_failure,
            accounting_status=self.accounting_status,
            measurement_type=self.measurement_type,
            target_type=self.target_type,
            target_spec=clone_frozen(self.target_spec) if self.target_spec is not None else None,
            created_at_ms=self.created_at_ms,
            committed_at_ms=self.committed_at_ms,
            accounting_owner=self.accounting_owner,
            fingerprint=self.fingerprint,
            metadata=clone_frozen(self.metadata) if self.metadata is not None else None,
            session_id=self.session_id,
        )
        memo[id(self)] = rec
        return rec


@dataclass
class RemoteInvocationRecord:
    """Authoritative runtime record of a single command-runner physical invocation."""
    invocation_id: str
    command_type: str
    physical_read_ids: List[str]
    start_time_ms: float
    completion_time_ms: Optional[float] = None
    batch_id: Optional[str] = None
    return_code: Optional[int] = None
    exception: Optional[str] = None
    output_byte_count: int = 0
    outcome: str = "IN_FLIGHT"  # "IN_FLIGHT", "COMPLETED", "TIMEOUT", "TRANSPORT_ERROR", "FAILED", "PREFLIGHT_REJECTED"

    def __deepcopy__(self, memo: Dict[int, Any]) -> "RemoteInvocationRecord":
        rec = RemoteInvocationRecord(
            invocation_id=self.invocation_id,
            command_type=self.command_type,
            physical_read_ids=list(self.physical_read_ids),
            start_time_ms=self.start_time_ms,
            completion_time_ms=self.completion_time_ms,
            batch_id=self.batch_id,
            return_code=self.return_code,
            exception=self.exception,
            output_byte_count=self.output_byte_count,
            outcome=self.outcome,
        )
        memo[id(self)] = rec
        return rec


@dataclass
class BatchSliceSpec:
    """Authoritative specification of a single memory slice within an execution batch."""
    slice_index: int
    address: int
    requested_size: int
    physical_read_id: str
    physical_consumption_id: str
    completion_status: str = "NOT_EXECUTED"  # "OBSERVED", "PARTIAL", "FAILED", "UNAVAILABLE", "NOT_EXECUTED", "UNKNOWN"
    measured_bytes_read: Optional[int] = None
    estimated_bytes_read: int = 0

    def __deepcopy__(self, memo: Dict[int, Any]) -> "BatchSliceSpec":
        spec = BatchSliceSpec(
            slice_index=self.slice_index,
            address=self.address,
            requested_size=self.requested_size,
            physical_read_id=self.physical_read_id,
            physical_consumption_id=self.physical_consumption_id,
            completion_status=self.completion_status,
            measured_bytes_read=self.measured_bytes_read,
            estimated_bytes_read=self.estimated_bytes_read,
        )
        memo[id(self)] = spec
        return spec


@dataclass
class BatchReadRecord:
    """Authoritative record of a batch read operation across slices."""
    batch_id: str
    invocation_id: str
    expected_slice_count: int
    slices: List[BatchSliceSpec] = field(default_factory=list)
    is_completed: bool = False
    is_partial: bool = False
    is_failed: bool = False
    created_at_ms: float = 0.0

    def __deepcopy__(self, memo: Dict[int, Any]) -> "BatchReadRecord":
        rec = BatchReadRecord(
            batch_id=self.batch_id,
            invocation_id=self.invocation_id,
            expected_slice_count=self.expected_slice_count,
            slices=[copy.deepcopy(s, memo) for s in self.slices],
            is_completed=self.is_completed,
            is_partial=self.is_partial,
            is_failed=self.is_failed,
            created_at_ms=self.created_at_ms,
        )
        memo[id(self)] = rec
        return rec


@dataclass
class BudgetReservation:
    """Explicit tracker-owned reservation lifecycle:
    ADMITTED -> PHYSICAL_READ_STARTED -> CONSUMED -> ACCOUNTED
    ADMITTED -> RELEASED (strictly when consumed_bytes == 0 and all child reads released)
    CONSUMED -> FAILED_ACCOUNTED (only if accounting itself cannot complete normally and recovery records the consumption)
    (Backward-compatible aliases: RESERVED -> CONSUMED -> FINALIZED)
    """
    reservation_id: str
    operation_id: str
    reserved_bytes: int
    profile_id: Optional[str] = None
    state: str = "ADMITTED"  # "ADMITTED", "RESERVED", "PHYSICAL_READ_STARTED", "CONSUMED", "RELEASED", "ACCOUNTED", "FINALIZED", "FAILED", "FAILED_ACCOUNTED"
    consumed_bytes: int = 0
    is_failure: bool = False
    scope_id: Optional[str] = None
    created_at_ms: float = 0.0
    physical_consumption_id: Optional[str] = None
    physical_read_id: Optional[str] = None
    child_reads: Dict[str, PhysicalReadRecord] = field(default_factory=dict)
    _lock: threading.RLock = field(default_factory=threading.RLock, init=False, repr=False)
    _transition_history: List[str] = field(default_factory=lambda: ["ADMITTED"], init=False, repr=False)

    def __deepcopy__(self, memo: Dict[int, Any]) -> "BudgetReservation":
        with self._lock:
            res = BudgetReservation(
                reservation_id=self.reservation_id,
                operation_id=self.operation_id,
                reserved_bytes=self.reserved_bytes,
                profile_id=self.profile_id,
                state=self.state,
                consumed_bytes=self.consumed_bytes,
                is_failure=self.is_failure,
                scope_id=self.scope_id,
                created_at_ms=self.created_at_ms,
                physical_consumption_id=self.physical_consumption_id,
                physical_read_id=self.physical_read_id,
                child_reads={k: copy.deepcopy(v, memo) for k, v in self.child_reads.items()},
            )
            res._transition_history = list(self._transition_history)
            memo[id(self)] = res
            return res

    @property
    def is_admitted(self) -> bool:
        with self._lock:
            return self.state in ("ADMITTED", "RESERVED")

    @property
    def is_physical_read_started(self) -> bool:
        with self._lock:
            return self.state == "PHYSICAL_READ_STARTED"

    @property
    def is_consumed(self) -> bool:
        with self._lock:
            return self.state == "CONSUMED"

    @property
    def is_released(self) -> bool:
        with self._lock:
            return self.state == "RELEASED"

    @property
    def is_accounted(self) -> bool:
        with self._lock:
            return self.state in ("ACCOUNTED", "FINALIZED", "FAILED_ACCOUNTED")

    @property
    def transition_history(self) -> List[str]:
        with self._lock:
            return list(self._transition_history)

    def _on_child_read_updated(self, child: PhysicalReadRecord) -> None:
        """Called by child physical read whenever its consumption state changes."""
        with self._lock:
            self.consumed_bytes = sum(c.charged_bytes for c in self.child_reads.values())
            if any(c.is_failure for c in self.child_reads.values()):
                self.is_failure = True
            if any(c.state == "PHYSICAL_READ_STARTED" for c in self.child_reads.values()) and self.state in ("ADMITTED", "RESERVED"):
                self.state = "PHYSICAL_READ_STARTED"
                if "PHYSICAL_READ_STARTED" not in self._transition_history:
                    self._transition_history.append("PHYSICAL_READ_STARTED")
            if any(c.state in ("CONSUMED", "ACCOUNTED", "FAILED_ACCOUNTED") for c in self.child_reads.values()) or self.consumed_bytes > 0:
                if self.state in ("ADMITTED", "RESERVED", "PHYSICAL_READ_STARTED"):
                    self.state = "CONSUMED"
                    if "CONSUMED" not in self._transition_history:
                        self._transition_history.append("CONSUMED")

    def start_child_read(
        self,
        target_type: str = "memory_slice",
        target_spec: Optional[Dict[str, Any]] = None,
        physical_read_id: Optional[str] = None,
        physical_consumption_id: Optional[str] = None,
    ) -> PhysicalReadRecord:
        """Starts and registers a child physical read under this aggregate reservation."""
        with self._lock:
            if self.state in ("RELEASED", "ACCOUNTED", "FINALIZED", "FAILED", "FAILED_ACCOUNTED"):
                raise RuntimeError(
                    f"Cannot start child read for reservation '{self.reservation_id}' in terminal state '{self.state}'"
                )

            pread_id = physical_read_id or f"pread_{uuid.uuid4().hex[:12]}"
            pcons_id = physical_consumption_id or f"pcons_{uuid.uuid4().hex[:12]}"

            if pread_id in self.child_reads:
                raise ValueError(f"Duplicate physical_read_id '{pread_id}' in reservation '{self.reservation_id}'")
            for existing_cr in self.child_reads.values():
                if existing_cr.physical_consumption_id == pcons_id:
                    raise ValueError(f"Duplicate physical_consumption_id '{pcons_id}' in reservation '{self.reservation_id}'")

            rec = PhysicalReadRecord(
                physical_read_id=pread_id,
                reservation_id=self.reservation_id,
                physical_consumption_id=pcons_id,
                operation_id=self.operation_id,
                target_type=target_type,
                target_spec=target_spec,
                created_at_ms=time.time(),
            )
            rec._parent_reservation = self
            self.child_reads[pread_id] = rec
            if self.physical_read_id is None:
                self.physical_read_id = pread_id
            if self.physical_consumption_id is None:
                self.physical_consumption_id = pcons_id
            return rec

    def get_child_reads(self) -> Dict[str, PhysicalReadRecord]:
        """Returns a deep copy of child physical reads to prevent external state mutation."""
        with self._lock:
            return copy.deepcopy(self.child_reads)

    def get_physical_read_records(self) -> Dict[str, PhysicalReadRecord]:
        """Returns deep copy of child physical reads for this reservation."""
        return self.get_child_reads()

    def mark_physical_read_started(
        self,
        physical_consumption_id: Optional[str] = None,
        physical_read_id: Optional[str] = None,
    ) -> None:
        """Transitions ADMITTED / RESERVED -> PHYSICAL_READ_STARTED."""
        with self._lock:
            if self.state in ("RELEASED", "ACCOUNTED", "FINALIZED", "FAILED", "FAILED_ACCOUNTED"):
                raise RuntimeError(f"Cannot start physical read for reservation '{self.reservation_id}' in terminal state {self.state}")
            if self.state in ("PHYSICAL_READ_STARTED", "CONSUMED"):
                if physical_consumption_id and not self.physical_consumption_id:
                    self.physical_consumption_id = physical_consumption_id
                if physical_read_id and not self.physical_read_id:
                    self.physical_read_id = physical_read_id
                return
            if self.state not in ("ADMITTED", "RESERVED"):
                raise RuntimeError(f"Cannot start physical read for reservation '{self.reservation_id}' in state {self.state}")
            self.state = "PHYSICAL_READ_STARTED"
            if physical_consumption_id:
                self.physical_consumption_id = physical_consumption_id
            elif not self.physical_consumption_id:
                self.physical_consumption_id = f"pcons_{uuid.uuid4().hex[:12]}"
            if physical_read_id:
                self.physical_read_id = physical_read_id
            elif not self.physical_read_id:
                self.physical_read_id = f"pread_{uuid.uuid4().hex[:12]}"
            self._transition_history.append("PHYSICAL_READ_STARTED")

    def consume(
        self,
        actual_bytes: Optional[int],
        is_failure: bool = False,
        accumulate: bool = False,
        child_read: Optional[PhysicalReadRecord] = None,
    ) -> int:
        """Transitions ADMITTED / RESERVED / PHYSICAL_READ_STARTED -> CONSUMED.
        
        If already in CONSUMED, accumulate=True is required to accumulate consumption
        without overwriting previous physical bytes.
        """
        with self._lock:
            if self.state in ("RELEASED", "ACCOUNTED", "FINALIZED", "FAILED", "FAILED_ACCOUNTED"):
                raise RuntimeError(f"Cannot consume reservation '{self.reservation_id}' in state {self.state}")
            b = max(0, int(actual_bytes or 0))

            if child_read is not None:
                child_read.consume(actual_bytes=actual_bytes, is_failure=is_failure)
                if is_failure:
                    self.is_failure = True
                self.consumed_bytes = sum(c.charged_bytes for c in self.child_reads.values())
                self.state = "CONSUMED"
                self._transition_history.append("CONSUMED")
                return self.consumed_bytes

            if self.child_reads:
                unconsumed = [c for c in self.child_reads.values() if c.state in ("ADMITTED", "PHYSICAL_READ_STARTED")]
                if unconsumed:
                    target_child = unconsumed[0]
                    target_child.consume(actual_bytes=actual_bytes, is_failure=is_failure)
                    if is_failure:
                        self.is_failure = True
                    self.consumed_bytes = sum(c.charged_bytes for c in self.child_reads.values())
                    self.state = "CONSUMED"
                    self._transition_history.append("CONSUMED")
                    return self.consumed_bytes
                elif self.state == "CONSUMED":
                    if not accumulate:
                        if b == self.consumed_bytes:
                            if is_failure:
                                self.is_failure = True
                            return self.consumed_bytes
                        raise RuntimeError(
                            f"Cannot consume reservation '{self.reservation_id}' in state CONSUMED without accumulate=True: "
                            f"physical consumption would be overwritten"
                        )
                    new_child = self.start_child_read()
                    new_child.consume(actual_bytes=actual_bytes, is_failure=is_failure)
                    if is_failure:
                        self.is_failure = True
                    self.consumed_bytes = sum(c.charged_bytes for c in self.child_reads.values())
                    self._transition_history.append("CONSUMED")
                    return self.consumed_bytes

            if self.state == "CONSUMED":
                if not accumulate:
                    if b == self.consumed_bytes:
                        if is_failure:
                            self.is_failure = True
                        return self.consumed_bytes
                    raise RuntimeError(
                        f"Cannot consume reservation '{self.reservation_id}' in state CONSUMED without accumulate=True: "
                        f"physical consumption would be overwritten"
                    )
            if self.state not in ("ADMITTED", "RESERVED", "PHYSICAL_READ_STARTED", "CONSUMED"):
                raise RuntimeError(f"Cannot consume reservation '{self.reservation_id}' in state {self.state}")

            if not self.physical_read_id:
                self.physical_read_id = f"pread_{uuid.uuid4().hex[:12]}"
            if not self.physical_consumption_id:
                self.physical_consumption_id = f"pcons_{uuid.uuid4().hex[:12]}"

            root = PhysicalReadRecord(
                physical_read_id=self.physical_read_id,
                reservation_id=self.reservation_id,
                physical_consumption_id=self.physical_consumption_id,
                operation_id=self.operation_id,
                target_type="memory_slice",
            )
            root.consume(actual_bytes=actual_bytes, is_failure=is_failure)
            self.child_reads[self.physical_read_id] = root
            if accumulate:
                self.consumed_bytes += b
            else:
                self.consumed_bytes = b
            if is_failure:
                self.is_failure = True
            self.state = "CONSUMED"
            self._transition_history.append("CONSUMED")
            return self.consumed_bytes

    def accumulate_consume(
        self,
        actual_bytes: Optional[int],
        is_failure: bool = False,
    ) -> int:
        """Convenience method to accumulate physical consumption atomically."""
        return self.consume(actual_bytes=actual_bytes, is_failure=is_failure, accumulate=True)

    def release(self) -> None:
        """Transitions ADMITTED / RESERVED / PHYSICAL_READ_STARTED -> RELEASED strictly when no physical consumption occurred."""
        with self._lock:
            if self.state in ("RELEASED", "ACCOUNTED", "FINALIZED", "FAILED", "FAILED_ACCOUNTED"):
                raise RuntimeError(f"Cannot release reservation '{self.reservation_id}' in state {self.state}")
            if self.consumed_bytes > 0:
                raise RuntimeError(f"A reservation must never be released if physical consumption occurred ({self.consumed_bytes}B)")
            for cr in self.child_reads.values():
                if cr.state == "PHYSICAL_READ_STARTED":
                    raise RuntimeError(
                        f"A reservation must never be released if child read '{cr.physical_read_id}' is in PHYSICAL_READ_STARTED"
                    )
                if cr.charged_bytes > 0 or cr.state in ("CONSUMED", "ACCOUNTED", "FAILED_ACCOUNTED"):
                    raise RuntimeError(f"A reservation must never be released if child physical read '{cr.physical_read_id}' consumed bytes ({cr.charged_bytes}B)")
            if self.state not in ("ADMITTED", "RESERVED", "PHYSICAL_READ_STARTED"):
                raise RuntimeError(f"Cannot release reservation '{self.reservation_id}' in state {self.state}")
            for cr in self.child_reads.values():
                if not cr.is_terminal:
                    cr.release()
            self.state = "RELEASED"
            self._transition_history.append("RELEASED")

    def account(self) -> None:
        """Transitions CONSUMED -> ACCOUNTED upon authoritative tracker commit."""
        with self._lock:
            if self.state in ("RELEASED", "ACCOUNTED", "FINALIZED", "FAILED_ACCOUNTED"):
                raise RuntimeError(f"Cannot account reservation '{self.reservation_id}' in state {self.state}")
            for cr in self.child_reads.values():
                if cr.state == "PHYSICAL_READ_STARTED":
                    raise RuntimeError(f"Cannot finalize reservation '{self.reservation_id}': child read '{cr.physical_read_id}' remains in flight")
            if self.state in ("ADMITTED", "RESERVED", "PHYSICAL_READ_STARTED") and self.consumed_bytes == 0 and not any(c.state in ("CONSUMED", "ACCOUNTED") for c in self.child_reads.values()):
                raise RuntimeError(f"Cannot account reservation '{self.reservation_id}' with zero consumption; must be released")
            for cr in self.child_reads.values():
                if cr.state == "CONSUMED":
                    cr.account()
            self.state = "ACCOUNTED"
            self._transition_history.append("ACCOUNTED")

    def finalize(self) -> None:
        """Transitions CONSUMED or RESERVED -> ACCOUNTED / FINALIZED upon tracker ledger commit."""
        with self._lock:
            if self.state in ("ACCOUNTED", "FINALIZED"):
                return  # Idempotent for identical outcome
            if self.state in ("RELEASED", "FAILED_ACCOUNTED"):
                raise RuntimeError(
                    f"Conflicting terminal transition: cannot finalize reservation '{self.reservation_id}' in state {self.state}"
                )
            for cr in self.child_reads.values():
                if cr.state == "PHYSICAL_READ_STARTED":
                    raise RuntimeError(f"Cannot finalize reservation '{self.reservation_id}': child read '{cr.physical_read_id}' remains in flight")
            if self.state in ("ADMITTED", "RESERVED", "PHYSICAL_READ_STARTED") and self.consumed_bytes == 0 and not any(c.state in ("CONSUMED", "ACCOUNTED") for c in self.child_reads.values()):
                raise RuntimeError(f"Cannot finalize reservation '{self.reservation_id}' with zero consumption; must be released")
            for cr in self.child_reads.values():
                if cr.state == "CONSUMED":
                    cr.account()
            self.state = "ACCOUNTED" if self.state in ("ADMITTED", "RESERVED", "PHYSICAL_READ_STARTED", "CONSUMED") else "FINALIZED"
            self._transition_history.append(self.state)

    @property
    def is_terminal(self) -> bool:
        with self._lock:
            return self.state in ("RELEASED", "ACCOUNTED", "FINALIZED", "FAILED", "FAILED_ACCOUNTED")

    def mark_failed_accounted(self) -> None:
        """Transitions CONSUMED -> FAILED_ACCOUNTED upon failure recovery recording."""
        with self._lock:
            if self.state == "FAILED_ACCOUNTED":
                return  # Idempotent for identical outcome
            if self.state in ("RELEASED", "ACCOUNTED", "FINALIZED"):
                raise RuntimeError(
                    f"Conflicting terminal transition: cannot mark failed_accounted for reservation '{self.reservation_id}' in state {self.state}"
                )
            for cr in self.child_reads.values():
                if not cr.is_terminal:
                    cr.mark_failed_accounted()
            self.state = "FAILED_ACCOUNTED"
            self._transition_history.append("FAILED_ACCOUNTED")


@dataclass
class PreparedCommit:
    """Pre-validated, immutable commit specification for failure-safe finalization."""
    snapshot: CommittedTransactionSnapshot
    target_op_id: str
    is_duplicate: bool
    is_collision: bool
    deltas: Dict[str, Any]
    scope: "ActiveOperationScope"
    reservations: List[BudgetReservation]


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
        self._admissions: List[BudgetReservation] = []

    @property
    def is_finalized(self) -> bool:
        with self._lock:
            return self.state in ("COMMITTED", "FAILED", "REJECTED")

    def admit_read(
        self,
        projected_bytes: int,
        profile_id: Optional[str] = None,
        profile_ceiling: Optional[Dict[str, Any]] = None,
        allow_in_flight_overshoot: bool = False,
    ) -> BudgetReservation:
        """Acquires a pre-read budget admission before starting physical target read."""
        with self._lock:
            if self.state in ("FINALIZING", "COMMITTED", "FAILED", "REJECTED"):
                raise RuntimeError(f"Cannot admit read on scope '{self.operation_id}' in state {self.state}")
            eff_prof = profile_id or self.profile_id
            res = self.tracker.admit_read(
                projected_bytes=projected_bytes,
                profile_id=eff_prof,
                operation_id=self.operation_id,
                scope=self,
                profile_ceiling=profile_ceiling,
                allow_in_flight_overshoot=allow_in_flight_overshoot,
            )
            self._admissions.append(res)
            return res

    @contextmanager
    def admitting_read(
        self,
        projected_bytes: int,
        profile_id: Optional[str] = None,
        profile_ceiling: Optional[Dict[str, Any]] = None,
    ) -> Iterator[BudgetReservation]:
        """Context manager for pre-read admission within this scope."""
        res = self.admit_read(projected_bytes, profile_id, profile_ceiling)
        try:
            yield res
        except BaseException:
            if res.state in ("ADMITTED", "RESERVED") and res.consumed_bytes == 0:
                self.tracker.release_reservation(res)
            raise

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
        admission: Optional[BudgetReservation] = None,
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

            # Check if budget is already exhausted (unless this read has a pre-existing in-flight reservation/admission)
            eff_res_check = admission or reservation
            if self.tracker.is_budget_exhausted and eff_res_check is None:
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
            eff_res = admission or reservation
            if eff_res is not None:
                res = eff_res
                res.scope_id = self.physical_consumption_id
                if not res.is_consumed:
                    res.consume(actual_bytes=charged_b, is_failure=is_failure)
                elif is_failure:
                    res.is_failure = True
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

            if is_failure or (measured and actual_b < charged_b):
                self.tracker._trigger_fault("after_partial_consumption")
            else:
                self.tracker._trigger_fault("after_full_consumption")

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

            adm_consumed = sum(r.consumed_bytes for r in self._admissions)
            if self.reads_count > 0 or adm_consumed > 0:
                if self.reads_count == 0 and adm_consumed > 0:
                    self.reads_count += len(self._admissions)
                    self.measured_bytes_read = adm_consumed
                    self.charged_bytes = adm_consumed
                return self.tracker._finalize_scope_transaction(self, is_fail=is_fail)
            else:
                self.state = "FAILED" if is_fail else "COMMITTED"
                self.tracker._finalize_scope_reservations(self)
                self.tracker._unregister_active_scope(self)
                return None


class ObservationBudgetTracker:
    """Active multi-dimensional budget controller and metrics monitor."""

    _thread_trackers = threading.local()

    @classmethod
    def get_active_thread_tracker(cls) -> Optional["ObservationBudgetTracker"]:
        """Returns the most recently entered budget tracker on this thread."""
        stack = getattr(cls._thread_trackers, "stack", None)
        return stack[-1] if stack else None

    @classmethod
    def get_active_thread_scope(cls) -> Optional["ActiveOperationScope"]:
        """Returns the active operation scope on this thread if available."""
        tracker = cls.get_active_thread_tracker()
        if tracker is not None and hasattr(tracker._thread_local, "current_scope"):
            return tracker._thread_local.current_scope
        return None

    def get_active_scope(self) -> Optional["ActiveOperationScope"]:
        """Returns the active operation scope on this thread for this tracker, if any."""
        if hasattr(self._thread_local, "current_scope"):
            return self._thread_local.current_scope
        return None

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
        self._physical_consumption_records: Dict[str, Any] = {}
        self._physical_read_records: Dict[str, PhysicalReadRecord] = {}
        self._active_reservations: Dict[str, BudgetReservation] = {}
        self._released_reservations_count: int = 0
        self._failed_operations: Dict[str, str] = {}
        self._fault_injection_hooks: Dict[str, Callable[[], None]] = {}
        self._transaction_lock = threading.RLock()
        self._thread_local = threading.local()
        self._active_scopes: Dict[str, Set[ActiveOperationScope]] = {}
        self._invocations: Dict[str, RemoteInvocationRecord] = {}
        self._batch_records: Dict[str, BatchReadRecord] = {}

    def get_invocation_records(self) -> Dict[str, RemoteInvocationRecord]:
        """Returns deep copy of runtime invocation records."""
        with self._transaction_lock:
            return copy.deepcopy(self._invocations)

    def get_batch_records(self) -> Dict[str, BatchReadRecord]:
        """Returns deep copy of registered batch records."""
        with self._transaction_lock:
            return copy.deepcopy(self._batch_records)

    def record_invocation_started(
        self,
        invocation_id: str,
        command_type: str,
        physical_read_ids: List[str],
        start_time_ms: Optional[float] = None,
        batch_id: Optional[str] = None,
    ) -> RemoteInvocationRecord:
        """Records the start of a physical command-runner invocation."""
        with self._transaction_lock:
            if invocation_id in self._invocations:
                # If already registered with identical details, return it
                existing = self._invocations[invocation_id]
                if existing.command_type == command_type and set(existing.physical_read_ids) == set(physical_read_ids):
                    return existing
                raise ValueError(f"Duplicate invocation_id '{invocation_id}'")
            t = start_time_ms if start_time_ms is not None else round(self.elapsed_ms, 3)
            rec = RemoteInvocationRecord(
                invocation_id=invocation_id,
                command_type=command_type,
                physical_read_ids=list(physical_read_ids),
                start_time_ms=t,
                batch_id=batch_id,
                outcome="IN_FLIGHT",
            )
            self._invocations[invocation_id] = rec
            return rec

    def record_invocation_completed(
        self,
        invocation_id: str,
        completion_time_ms: Optional[float] = None,
        return_code: Optional[int] = None,
        exception: Optional[str] = None,
        output_byte_count: int = 0,
        outcome: Optional[str] = None,
    ) -> None:
        """Records the completion of a physical command-runner invocation."""
        with self._transaction_lock:
            rec = self._invocations.get(invocation_id)
            if rec is None:
                rec = RemoteInvocationRecord(
                    invocation_id=invocation_id,
                    command_type="unknown",
                    physical_read_ids=[],
                    start_time_ms=round(self.elapsed_ms, 3),
                )
                self._invocations[invocation_id] = rec
            t = completion_time_ms if completion_time_ms is not None else round(self.elapsed_ms, 3)
            rec.completion_time_ms = t
            rec.return_code = return_code
            rec.exception = exception
            rec.output_byte_count = max(0, int(output_byte_count or 0))
            if outcome:
                rec.outcome = outcome
            elif exception:
                exc_lower = str(exception).lower()
                rec.outcome = "TIMEOUT" if ("timeout" in exc_lower or "timed out" in exc_lower) else "TRANSPORT_ERROR"
            elif return_code == 0:
                rec.outcome = "COMPLETED"
            else:
                rec.outcome = "FAILED"

    def register_batch_contract(
        self,
        batch_id: str,
        invocation_id: str,
        expected_slice_count: int,
        slices: Optional[List[BatchSliceSpec]] = None,
    ) -> BatchReadRecord:
        """Explicitly registers expected batch contract before invocation."""
        with self._transaction_lock:
            if expected_slice_count <= 0:
                raise ValueError(f"expected_slice_count must be positive: {expected_slice_count}")
            key = f"{batch_id}::{invocation_id}"
            rec = BatchReadRecord(
                batch_id=batch_id,
                invocation_id=invocation_id,
                expected_slice_count=int(expected_slice_count),
                slices=list(slices or []),
                created_at_ms=round(self.elapsed_ms, 3),
            )
            self._batch_records[key] = rec
            return rec

    def set_fault_injection(self, point: str, hook: Callable[[], None]) -> None:
        """Sets a deterministic fault injection hook for failure testing."""
        with self._transaction_lock:
            self._fault_injection_hooks[point] = hook

    def register_fault_injection(self, point: str, hook: Callable[[], None]) -> None:
        """Alias for set_fault_injection."""
        self.set_fault_injection(point, hook)

    def clear_fault_injections(self) -> None:
        """Clears all registered fault injection hooks."""
        with self._transaction_lock:
            self._fault_injection_hooks.clear()

    def _trigger_fault(self, point: str) -> None:
        """Invokes registered fault injection hook if present."""
        hook = self._fault_injection_hooks.get(point)
        if hook is not None:
            hook()

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

    def _active_consumed_bytes(self, profile_id: Optional[str] = None) -> int:
        with self._transaction_lock:
            active_scope_phys_ids = {
                s.physical_consumption_id for scopes in self._active_scopes.values() for s in scopes
                if (profile_id is None or s.profile_id == profile_id) and s.charged_bytes > 0
            }
            scope_bytes = sum(
                s.charged_bytes for scopes in self._active_scopes.values() for s in scopes
                if (profile_id is None or s.profile_id == profile_id)
            )
            standalone_consumed = sum(
                r.consumed_bytes for r in self._active_reservations.values()
                if r.consumed_bytes > 0
                and (profile_id is None or r.profile_id == profile_id)
                and (r.scope_id is None or r.scope_id not in active_scope_phys_ids)
            )
            return scope_bytes + standalone_consumed

    def _active_reservation_bytes(self, profile_id: Optional[str] = None) -> int:
        with self._transaction_lock:
            total = 0
            for r in self._active_reservations.values():
                if profile_id is not None and r.profile_id != profile_id:
                    continue
                if r.state in ("RESERVED", "ADMITTED", "PHYSICAL_READ_STARTED"):
                    rem = max(0, r.reserved_bytes - r.consumed_bytes)
                    total += rem
                elif r.state == "CONSUMED":
                    has_inflight_children = any(
                        c.state in ("ADMITTED", "PHYSICAL_READ_STARTED")
                        for c in getattr(r, "child_reads", {}).values()
                    )
                    if has_inflight_children:
                        rem = max(0, r.reserved_bytes - r.consumed_bytes)
                        total += rem
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

    def admit_read(
        self,
        projected_bytes: int,
        profile_id: Optional[str] = None,
        operation_id: Optional[str] = None,
        scope: Optional["ActiveOperationScope"] = None,
        profile_ceiling: Optional[Dict[str, Any]] = None,
        allow_in_flight_overshoot: bool = False,
    ) -> BudgetReservation:
        """Explicit pre-read budget admission API.
        
        Lifecycle:
        ADMITTED -> CONSUMED -> ACCOUNTED
        ADMITTED -> RELEASED (strictly when zero physical read occurred)
        """
        with self._transaction_lock:
            self._trigger_fault("before_admission")
            if isinstance(projected_bytes, bool) or not isinstance(projected_bytes, (int, float)) or projected_bytes < 0:
                raise ValueError(f"Invalid non-negative admission bytes: {projected_bytes}")
            proj_b = int(projected_bytes)

            if self.is_budget_exhausted:
                raise ValueError(f"BUDGET_EXHAUSTED: cannot admit read ({self.exhaustion_reason})")

            # Check global limits atomically
            active_res = self._active_reservation_bytes()
            in_flight = self._active_consumed_bytes()
            projected = self.metrics.bytes_read + active_res + in_flight + proj_b

            if projected > self.limits.max_bytes_read:
                self.metrics.is_budget_exhausted = True
                self.metrics.exhaustion_reason = (
                    f"EXCEEDED_BYTES_READ: projected admission {projected}B > max {self.limits.max_bytes_read}B"
                )
                if not allow_in_flight_overshoot:
                    raise ValueError(f"BUDGET_EXHAUSTED: {self.metrics.exhaustion_reason}")
                elif (projected - self.limits.max_bytes_read) > self.limits.max_bytes_per_observation:
                    raise ValueError(
                        f"BUDGET_EXHAUSTED: In-flight overshoot {projected - self.limits.max_bytes_read}B "
                        f"exceeds max buffer {self.limits.max_bytes_per_observation}B"
                    )

            # Check profile limit if profile has ceiling
            eff_prof_id = profile_id or (scope.profile_id if scope else None)
            if eff_prof_id:
                p_usage = self._get_or_init_profile_usage(eff_prof_id)
                p_active_res = self._active_reservation_bytes(profile_id=eff_prof_id)
                p_in_flight = self._active_consumed_bytes(profile_id=eff_prof_id)
                ceil_limit = None
                if profile_ceiling:
                    ceil_limit = profile_ceiling.get("max_bytes_read", profile_ceiling.get("max_bytes"))
                if ceil_limit is None and hasattr(self.limits, "max_profile_bytes"):
                    ceil_limit = self.limits.max_profile_bytes.get(eff_prof_id)

                if ceil_limit is not None and (p_usage["bytes_read"] + p_active_res + p_in_flight + proj_b) > int(ceil_limit):
                    raise ValueError(
                        f"PROFILE_CEILING_EXCEEDED: Profile '{eff_prof_id}' projected "
                        f"{p_usage['bytes_read'] + p_active_res + p_in_flight + proj_b}B > max {ceil_limit}B"
                    )

            res_id = f"adm_{uuid.uuid4().hex}"
            pcons_id = scope.physical_consumption_id if scope else None
            res = BudgetReservation(
                reservation_id=res_id,
                operation_id=operation_id or (scope.operation_id if scope else "standalone"),
                reserved_bytes=proj_b,
                profile_id=eff_prof_id,
                state="ADMITTED",
                scope_id=scope.physical_consumption_id if scope else None,
                physical_consumption_id=pcons_id,
                created_at_ms=round(self.elapsed_ms, 3),
            )
            self._active_reservations[res_id] = res
            self._trigger_fault("after_admission_before_read")
            return res

    @contextmanager
    def admitted_read(
        self,
        projected_bytes: int,
        profile_id: Optional[str] = None,
        operation_id: Optional[str] = None,
        scope: Optional["ActiveOperationScope"] = None,
        profile_ceiling: Optional[Dict[str, Any]] = None,
    ) -> Iterator[BudgetReservation]:
        """Context manager for pre-read admission lifecycle."""
        res = self.admit_read(
            projected_bytes=projected_bytes,
            profile_id=profile_id,
            operation_id=operation_id,
            scope=scope,
            profile_ceiling=profile_ceiling,
        )
        try:
            yield res
        except BaseException:
            if res.state in ("ADMITTED", "RESERVED") and res.consumed_bytes == 0:
                self.release_reservation(res)
            raise

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
                p_in_flight = self._active_consumed_bytes(profile_id=eff_prof_id)
                ceil_limit = None
                if profile_ceiling:
                    ceil_limit = profile_ceiling.get("max_bytes_read", profile_ceiling.get("max_bytes"))
                if ceil_limit is None and hasattr(self.limits, "max_profile_bytes"):
                    ceil_limit = self.limits.max_profile_bytes.get(eff_prof_id)

                if ceil_limit is not None and (p_usage["bytes_read"] + p_active_res + p_in_flight + est_b) > int(ceil_limit):
                    if not allow_in_flight_overshoot:
                        raise ValueError(
                            f"PROFILE_CEILING_EXCEEDED: Profile '{eff_prof_id}' projected "
                            f"{p_usage['bytes_read'] + p_active_res + p_in_flight + est_b}B > max {ceil_limit}B"
                        )

            res_id = f"res_{uuid.uuid4().hex[:8]}"
            res = BudgetReservation(
                reservation_id=res_id,
                operation_id=operation_id or (scope.operation_id if scope else "standalone"),
                reserved_bytes=est_b,
                profile_id=eff_prof_id,
                state="RESERVED",
                scope_id=scope.physical_consumption_id if scope else None,
                physical_consumption_id=scope.physical_consumption_id if scope else None,
                created_at_ms=round(self.elapsed_ms, 3),
            )
            self._active_reservations[res_id] = res
            return res

    def release_reservation(self, reservation: BudgetReservation) -> None:
        """Transitions a reservation to RELEASED strictly when zero physical bytes were consumed."""
        with self._transaction_lock:
            reservation.release()
            self._active_reservations.pop(reservation.reservation_id, None)
            self._released_reservations_count += 1

    def _finalize_scope_reservations(self, scope: "ActiveOperationScope") -> None:
        """Transitions all reservations belonging to scope to FINALIZED/ACCOUNTED and cleans them up."""
        with self._transaction_lock:
            to_remove = []
            for r_id, res in list(self._active_reservations.items()):
                if res.scope_id == scope.physical_consumption_id or (res.operation_id == scope.operation_id and res.state in ("ADMITTED", "RESERVED", "PHYSICAL_READ_STARTED", "CONSUMED")):
                    if res.consumed_bytes > 0 or scope.charged_bytes > 0:
                        res.finalize()
                    else:
                        if res.state in ("ADMITTED", "RESERVED", "PHYSICAL_READ_STARTED"):
                            res.release()
                            self._released_reservations_count += 1
                        else:
                            res.finalize()
                    to_remove.append(r_id)
            for r_id in to_remove:
                self._active_reservations.pop(r_id, None)

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
        projected_bytes: Optional[int] = None,
    ) -> Iterator[ActiveOperationScope]:
        """Context manager establishing an authoritative thread-local operation scope."""
        if not hasattr(ObservationBudgetTracker._thread_trackers, "stack"):
            ObservationBudgetTracker._thread_trackers.stack = []
        ObservationBudgetTracker._thread_trackers.stack.append(self)

        pre_adm = None
        if projected_bytes is not None and projected_bytes > 0:
            pre_adm = self.admit_read(projected_bytes, profile_id=profile_id, operation_id=operation_id)

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
            if pre_adm is not None:
                pre_adm.scope_id = existing_on_thread.physical_consumption_id
                existing_on_thread._admissions.append(pre_adm)
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
                if ObservationBudgetTracker._thread_trackers.stack:
                    ObservationBudgetTracker._thread_trackers.stack.pop()
            return

        scope = ActiveOperationScope(
            tracker=self,
            operation_id=operation_id,
            profile_id=profile_id,
            owner=owner,
            metadata=metadata,
        )
        if pre_adm is not None:
            pre_adm.scope_id = scope.physical_consumption_id
            scope._admissions.append(pre_adm)

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
                if ObservationBudgetTracker._thread_trackers.stack:
                    ObservationBudgetTracker._thread_trackers.stack.pop()

    def _prepare_scope_commit(
        self,
        scope: "ActiveOperationScope",
        is_fail: bool = False,
    ) -> PreparedCommit:
        """Pure prepare phase: strictly validates numeric fields, canonicalizes metadata,
        computes candidate fingerprints and metric deltas without mutating any tracker state.
        """
        meas_b = scope.measured_bytes_read
        est_b = scope.estimated_bytes_read
        total_charge = scope.charged_bytes

        # Strict validation of numeric fields
        for name, val in [("measured_bytes_read", meas_b), ("estimated_bytes_read", est_b), ("charged_bytes", total_charge)]:
            if val is not None:
                if isinstance(val, bool) or not isinstance(val, (int, float)):
                    raise ValueError(f"Invalid type for {name}: {type(val)}")
                if isinstance(val, float) and (math.isnan(val) or math.isinf(val)):
                    raise ValueError(f"Invalid float (NaN/Inf) for {name}: {val}")
                if val < 0:
                    raise ValueError(f"Negative value for {name}: {val}")

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
        actual_meas = int(meas_b) if (meas_b is not None and meas_b >= 0) else 0
        actual_est = int(est_b) if (est_b is not None and est_b >= 0) else 0

        # Metadata freeze and canonical digest
        self._trigger_fault("during_metadata_freeze")
        try:
            frozen_meta = freeze_metadata(scope.metadata)
            meta_digest = canonical_metadata_digest(scope.metadata)
        except (TypeError, ValueError) as meta_err:
            if total_charge == 0:
                raise meta_err
            is_fail = True
            status = "FAILED"
            frozen_meta = freeze_metadata({"metadata_error": str(meta_err)})
            meta_digest = canonical_metadata_digest(frozen_meta)

        self._trigger_fault("during_fingerprint_creation")
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

        self._trigger_fault("during_snapshot_construction")
        is_dup = False
        is_collision = False
        target_op_id = scope.operation_id

        if scope.operation_id in self._committed_transactions:
            existing = self._committed_transactions[scope.operation_id]
            if total_charge == 0:
                # Idempotent reference: return existing snapshot directly
                return PreparedCommit(
                    snapshot=existing,
                    target_op_id=scope.operation_id,
                    is_duplicate=False,
                    is_collision=False,
                    deltas={
                        "bytes_read": 0,
                        "measured_bytes_read": 0,
                        "conservative_estimated_bytes": 0,
                        "unmeasured_reads": 0,
                        "latency_us": 0.0,
                        "stop_ms": 0.0,
                        "is_failure": False,
                        "profile_id": scope.profile_id or scope.operation_id,
                    },
                    scope=scope,
                    reservations=[],
                )
            # Physical consumption occurred! Check duplicate vs collision
            if existing.fingerprint.matches_logical_fields(cand_fp):
                is_dup = True
                target_op_id = f"{scope.operation_id}#duplicate_{scope.physical_consumption_id}"
                status = "COMMITTED"
                frozen_meta = freeze_metadata({"duplicate_of": scope.operation_id, **unfreeze_metadata(frozen_meta)})
            else:
                is_collision = True
                target_op_id = f"{scope.operation_id}#collision_{scope.physical_consumption_id}"
                status = "REJECTED"
                is_fail = True
                frozen_meta = freeze_metadata({"collision_with": scope.operation_id, **unfreeze_metadata(frozen_meta)})

        snapshot = CommittedTransactionSnapshot(
            operation_id=target_op_id,
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

        deltas = {
            "bytes_read": total_charge,
            "measured_bytes_read": actual_meas,
            "conservative_estimated_bytes": actual_est,
            "unmeasured_reads": 1 if (actual_est > 0 and actual_meas == 0) else 0,
            "latency_us": lat_val,
            "stop_ms": stop_val,
            "is_failure": is_fail,
            "profile_id": scope.profile_id or scope.operation_id,
        }

        return PreparedCommit(
            snapshot=snapshot,
            target_op_id=target_op_id,
            is_duplicate=is_dup,
            is_collision=is_collision,
            deltas=deltas,
            scope=scope,
            reservations=[],
        )

    def _execute_scope_commit(
        self,
        prepared: PreparedCommit,
    ) -> CommittedTransactionSnapshot:
        """Atomic commit phase: applies deltas, updates ledgers, finalizes reservations,
        and provides crash-safe idempotent recovery.
        """
        with self._transaction_lock:
            # Idempotency check: if this physical consumption was already committed
            if prepared.snapshot.physical_consumption_id in self._physical_consumption_records:
                existing = self._physical_consumption_records[prepared.snapshot.physical_consumption_id]
                if existing.charged_bytes != prepared.snapshot.charged_bytes:
                    raise ValueError(
                        f"Physical consumption ID conflict: '{prepared.snapshot.physical_consumption_id}' "
                        f"already committed with {existing.charged_bytes}B, conflicting with {prepared.snapshot.charged_bytes}B"
                    )
                self._finalize_scope_reservations(prepared.scope)
                self._unregister_active_scope(prepared.scope)
                return existing

            if prepared.deltas["bytes_read"] == 0 and not prepared.is_duplicate and not prepared.is_collision:
                # Idempotent 0-byte reference
                self._finalize_scope_reservations(prepared.scope)
                self._unregister_active_scope(prepared.scope)
                return prepared.snapshot

            # Pre-validate child reads and physical IDs before mutating state
            all_res = list(prepared.scope._admissions)
            for r_id, res in self._active_reservations.items():
                if res.scope_id == prepared.scope.physical_consumption_id or res.operation_id == prepared.scope.operation_id:
                    if res not in all_res:
                        all_res.append(res)
            for res in all_res:
                for cr in res.child_reads.values():
                    if cr.physical_read_id in self._physical_read_records:
                        existing_cr = self._physical_read_records[cr.physical_read_id]
                        if existing_cr.charged_bytes != cr.charged_bytes:
                            raise ValueError(
                                f"Physical read ID conflict: '{cr.physical_read_id}' already committed with "
                                f"{existing_cr.charged_bytes}B, conflicting with {cr.charged_bytes}B"
                            )
                    if cr.physical_consumption_id in self._physical_consumption_records:
                        existing_pcons = self._physical_consumption_records[cr.physical_consumption_id]
                        if existing_pcons.charged_bytes != cr.charged_bytes:
                            raise ValueError(
                                f"Physical consumption ID conflict: '{cr.physical_consumption_id}' already committed with "
                                f"{existing_pcons.charged_bytes}B, conflicting with {cr.charged_bytes}B"
                            )
                    if cr.state == "PHYSICAL_READ_STARTED":
                        raise RuntimeError(
                            f"Cannot commit operation '{prepared.target_op_id}': child read '{cr.physical_read_id}' is still in flight"
                        )

            metrics_applied = False
            step = "start"
            try:
                # 1. Register physical ledger entry
                step = "physical_ledger"
                self._trigger_fault("before_physical_ledger_insertion")
                self._trigger_fault("during_physical_ledger_insertion")

                # Register all child physical reads and physical consumption records
                has_child_reads = False
                for res in all_res:
                    for cr in res.child_reads.values():
                        has_child_reads = True
                        cr.operation_id = prepared.target_op_id
                        if cr.state in ("CONSUMED", "ACCOUNTED"):
                            if cr.state == "CONSUMED":
                                cr.account()
                            pcons = cr.to_consumption_record(
                                operation_id=prepared.target_op_id,
                                committed_at_ms=time.time(),
                                accounting_status=prepared.snapshot.accounting_status,
                            )
                            self._physical_read_records[cr.physical_read_id] = cr
                            self._physical_consumption_records[cr.physical_consumption_id] = pcons
                        elif cr.state == "FAILED_ACCOUNTED":
                            pcons = cr.to_consumption_record(
                                operation_id=prepared.target_op_id,
                                committed_at_ms=time.time(),
                                accounting_status="FAILED",
                            )
                            self._physical_read_records[cr.physical_read_id] = cr
                            self._physical_consumption_records[cr.physical_consumption_id] = pcons

                if not has_child_reads:
                    root_pread_id = f"pread_{prepared.snapshot.physical_consumption_id}"
                    root_pcons = PhysicalConsumptionRecord(
                        physical_consumption_id=prepared.snapshot.physical_consumption_id,
                        physical_read_id=root_pread_id,
                        reservation_id=getattr(prepared.scope, "operation_id", "scope_res"),
                        operation_id=prepared.target_op_id,
                        measured_bytes_read=prepared.snapshot.measured_bytes_read,
                        estimated_bytes_read=prepared.snapshot.estimated_bytes_read,
                        charged_bytes=prepared.snapshot.charged_bytes,
                        latency_us=prepared.snapshot.latency_us,
                        stop_ms=prepared.snapshot.stop_ms,
                        is_failure=prepared.snapshot.is_failure,
                        accounting_status=prepared.snapshot.accounting_status,
                        measurement_type=prepared.snapshot.measurement_type,
                        created_at_ms=time.time(),
                        committed_at_ms=time.time(),
                        metadata=dict(prepared.snapshot.metadata),
                    )
                    self._physical_consumption_records[prepared.snapshot.physical_consumption_id] = root_pcons
                    root_cr = PhysicalReadRecord(
                        physical_read_id=root_pread_id,
                        reservation_id=getattr(prepared.scope, "operation_id", "scope_res"),
                        physical_consumption_id=prepared.snapshot.physical_consumption_id,
                        operation_id=prepared.target_op_id,
                        state="ACCOUNTED",
                        charged_bytes=prepared.snapshot.charged_bytes,
                        measured_bytes_read=prepared.snapshot.measured_bytes_read,
                        estimated_bytes_read=prepared.snapshot.estimated_bytes_read,
                        latency_us=prepared.snapshot.latency_us,
                        is_failure=prepared.snapshot.is_failure,
                    )
                    self._physical_read_records[root_pread_id] = root_cr

                self._trigger_fault("after_physical_ledger_insertion")

                # 2. Register logical ledger entry
                step = "logical_ledger"
                self._trigger_fault("before_logical_ledger_insertion")
                self._trigger_fault("during_logical_ledger_insertion")
                self._committed_transactions[prepared.target_op_id] = prepared.snapshot
                self._trigger_fault("after_logical_ledger_insertion")

                # 3. Apply global metrics
                step = "metrics"
                self._trigger_fault("before_metrics_mutation")
                self._trigger_fault("during_metric_application")
                d = prepared.deltas
                self.metrics.bytes_read += d["bytes_read"]
                self.metrics.measured_bytes_read += d["measured_bytes_read"]
                self.metrics.conservative_estimated_bytes += d["conservative_estimated_bytes"]
                self.metrics.unmeasured_reads_count += d["unmeasured_reads"]
                self.metrics.observation_latency_us += d["latency_us"]
                self.metrics.target_stop_duration_ms += d["stop_ms"]
                if d["is_failure"]:
                    self.metrics.total_read_failures += 1
                    self.metrics.consecutive_read_failures += 1
                else:
                    self.metrics.consecutive_read_failures = 0
                metrics_applied = True

                # 4. Apply profile metrics
                step = "profile_metrics"
                self._trigger_fault("during_profile_metric_application")
                eff_prof = d["profile_id"]
                if eff_prof:
                    p_usage = self._get_or_init_profile_usage(eff_prof)
                    p_usage["bytes_read"] += d["bytes_read"]
                    p_usage["measured_bytes_read"] += d["measured_bytes_read"]
                    p_usage["conservative_estimated_bytes"] += d["conservative_estimated_bytes"]
                    p_usage["wall_clock_ms"] = round(p_usage["wall_clock_ms"] + (d["latency_us"] / 1000.0), 3)
                    p_usage["target_stop_ms"] = round(p_usage["target_stop_ms"] + d["stop_ms"], 3)
                    if d["is_failure"]:
                        p_usage["failures"] += 1

                step = "after_metrics"
                self.metrics.wall_clock_elapsed_ms = round(self.elapsed_ms, 3)
                if self.metrics.bytes_read >= self.limits.max_bytes_read:
                    self.metrics.is_budget_exhausted = True
                    self.metrics.exhaustion_reason = (
                        f"EXCEEDED_BYTES_READ: current {self.metrics.bytes_read}B >= max {self.limits.max_bytes_read}B"
                    )
                self._trigger_fault("after_metrics_mutation")

                # 5. Finalize reservations
                step = "reservations"
                self._trigger_fault("during_reservation_finalization")
                self._finalize_scope_reservations(prepared.scope)
                prepared.scope.state = prepared.snapshot.accounting_status

                # 6. Append history
                step = "history"
                self._trigger_fault("during_history_append")
                self._history.append({
                    "event": "TRANSACTION_COMMIT",
                    "operation_id": prepared.target_op_id,
                    "accounting_owner": prepared.snapshot.accounting_owner,
                    "measured_bytes_read": prepared.snapshot.measured_bytes_read,
                    "estimated_bytes_read": prepared.snapshot.estimated_bytes_read,
                    "charged_bytes": prepared.snapshot.charged_bytes,
                    "measurement_type": prepared.snapshot.measurement_type,
                    "latency_us": prepared.snapshot.latency_us,
                    "stop_ms": prepared.snapshot.stop_ms,
                    "is_failure": prepared.snapshot.is_failure,
                    "elapsed_ms": round(self.elapsed_ms, 3),
                })
                self._unregister_active_scope(prepared.scope)

                if prepared.is_collision:
                    raise ValueError(
                        f"Operation ID collision: '{prepared.scope.operation_id}' was already committed with "
                        f"fingerprint conflicting with candidate {prepared.snapshot.fingerprint}"
                    )

                return prepared.snapshot

            except Exception as exc:
                if prepared.is_collision and "Operation ID collision" in str(exc):
                    raise
                # Explicit recovery protocol
                return self._recover_commit_failure(prepared, error=exc, metrics_applied=metrics_applied, step=step)

    def _recover_commit_failure(
        self,
        prepared: PreparedCommit,
        error: BaseException,
        metrics_applied: bool,
        step: str,
    ) -> CommittedTransactionSnapshot:
        """Crash-safe idempotent recovery protocol."""
        with self._transaction_lock:
            self._trigger_fault("during_emergency_recovery")

            snap = self._physical_consumption_records.get(prepared.snapshot.physical_consumption_id)
            if snap is None or not snap.is_failure or prepared.target_op_id not in self._committed_transactions:
                err_meta = freeze_metadata({"emergency_error": str(error), "failed_step": step, **unfreeze_metadata(prepared.snapshot.metadata)})
                fp = AccountingFingerprint(
                    operation_id=prepared.target_op_id,
                    accounting_owner=prepared.snapshot.accounting_owner,
                    measured_bytes_read=prepared.snapshot.measured_bytes_read,
                    estimated_bytes_read=prepared.snapshot.estimated_bytes_read,
                    charged_bytes=prepared.snapshot.charged_bytes,
                    measurement_type=prepared.snapshot.measurement_type,
                    profile_id=prepared.snapshot.fingerprint.profile_id,
                    is_failure=True,
                    stop_ms=prepared.snapshot.stop_ms,
                    latency_us=prepared.snapshot.latency_us,
                    session_id=self.session_id,
                    metadata_digest=canonical_metadata_digest(err_meta),
                    physical_consumption_id=prepared.snapshot.physical_consumption_id,
                )
                snap = CommittedTransactionSnapshot(
                    operation_id=prepared.target_op_id,
                    accounting_owner=prepared.snapshot.accounting_owner,
                    measured_bytes_read=prepared.snapshot.measured_bytes_read,
                    estimated_bytes_read=prepared.snapshot.estimated_bytes_read,
                    charged_bytes=prepared.snapshot.charged_bytes,
                    latency_us=prepared.snapshot.latency_us,
                    stop_ms=prepared.snapshot.stop_ms,
                    is_failure=True,
                    accounting_status="FAILED",
                    measurement_type=prepared.snapshot.measurement_type,
                    fingerprint=fp,
                    metadata=err_meta,
                    committed_at_ms=round(self.elapsed_ms, 3),
                    session_id=self.session_id,
                    physical_consumption_id=prepared.snapshot.physical_consumption_id,
                )
                self._committed_transactions[prepared.target_op_id] = snap

            # Preserve child reads into physical ledger
            all_res = list(prepared.scope._admissions)
            for r_id, res in self._active_reservations.items():
                if res.scope_id == prepared.scope.physical_consumption_id or res.operation_id == prepared.scope.operation_id:
                    if res not in all_res:
                        all_res.append(res)
            for res in all_res:
                for cr in res.child_reads.values():
                    if cr.state in ("CONSUMED", "PHYSICAL_READ_STARTED"):
                        cr.mark_failed_accounted(failure_reason=str(error))
                        pcons = cr.to_consumption_record(
                            operation_id=prepared.target_op_id,
                            committed_at_ms=time.time(),
                            accounting_status="FAILED",
                        )
                        self._physical_read_records[cr.physical_read_id] = cr
                        self._physical_consumption_records[cr.physical_consumption_id] = pcons

            if not any(getattr(r, "operation_id", None) == prepared.target_op_id for r in self._physical_read_records.values()):
                root_pread_id = f"pread_{prepared.snapshot.physical_consumption_id}"
                root_pcons = PhysicalConsumptionRecord(
                    physical_consumption_id=prepared.snapshot.physical_consumption_id,
                    physical_read_id=root_pread_id,
                    reservation_id=getattr(prepared.scope, "operation_id", "scope_res"),
                    operation_id=prepared.target_op_id,
                    measured_bytes_read=prepared.snapshot.measured_bytes_read,
                    estimated_bytes_read=prepared.snapshot.estimated_bytes_read,
                    charged_bytes=prepared.snapshot.charged_bytes,
                    latency_us=prepared.snapshot.latency_us,
                    stop_ms=prepared.snapshot.stop_ms,
                    is_failure=True,
                    accounting_status="FAILED",
                    measurement_type=prepared.snapshot.measurement_type,
                    created_at_ms=time.time(),
                    committed_at_ms=time.time(),
                    metadata=dict(prepared.snapshot.metadata),
                )
                self._physical_consumption_records[prepared.snapshot.physical_consumption_id] = root_pcons
                root_cr = PhysicalReadRecord(
                    physical_read_id=root_pread_id,
                    reservation_id=getattr(prepared.scope, "operation_id", "scope_res"),
                    physical_consumption_id=prepared.snapshot.physical_consumption_id,
                    operation_id=prepared.target_op_id,
                    state="FAILED_ACCOUNTED",
                    charged_bytes=prepared.snapshot.charged_bytes,
                    measured_bytes_read=prepared.snapshot.measured_bytes_read,
                    estimated_bytes_read=prepared.snapshot.estimated_bytes_read,
                    latency_us=prepared.snapshot.latency_us,
                    is_failure=True,
                )
                self._physical_read_records[root_pread_id] = root_cr

            if not metrics_applied and prepared.deltas["bytes_read"] > 0:
                d = prepared.deltas
                self.metrics.bytes_read += d["bytes_read"]
                self.metrics.measured_bytes_read += d["measured_bytes_read"]
                self.metrics.conservative_estimated_bytes += d["conservative_estimated_bytes"]
                self.metrics.unmeasured_reads_count += d["unmeasured_reads"]
                self.metrics.observation_latency_us += d["latency_us"]
                self.metrics.target_stop_duration_ms += d["stop_ms"]
                self.metrics.total_read_failures += 1
                self.metrics.consecutive_read_failures += 1

                eff_prof = d["profile_id"]
                if eff_prof:
                    p_usage = self._get_or_init_profile_usage(eff_prof)
                    p_usage["bytes_read"] += d["bytes_read"]
                    p_usage["measured_bytes_read"] += d["measured_bytes_read"]
                    p_usage["conservative_estimated_bytes"] += d["conservative_estimated_bytes"]
                    p_usage["wall_clock_ms"] = round(p_usage["wall_clock_ms"] + (d["latency_us"] / 1000.0), 3)
                    p_usage["target_stop_ms"] = round(p_usage["target_stop_ms"] + d["stop_ms"], 3)
                    p_usage["failures"] += 1
            elif metrics_applied:
                if step == "profile_metrics":
                    d = prepared.deltas
                    eff_prof = d.get("profile_id")
                    if eff_prof:
                        p_usage = self._get_or_init_profile_usage(eff_prof)
                        p_usage["bytes_read"] += d["bytes_read"]
                        p_usage["measured_bytes_read"] += d["measured_bytes_read"]
                        p_usage["conservative_estimated_bytes"] += d["conservative_estimated_bytes"]
                        p_usage["wall_clock_ms"] = round(p_usage["wall_clock_ms"] + (d["latency_us"] / 1000.0), 3)
                        p_usage["target_stop_ms"] = round(p_usage["target_stop_ms"] + d["stop_ms"], 3)
                if not prepared.snapshot.is_failure:
                    self.metrics.total_read_failures += 1
                    self.metrics.consecutive_read_failures += 1
                    eff_prof = prepared.deltas.get("profile_id")
                    if eff_prof:
                        p_usage = self._get_or_init_profile_usage(eff_prof)
                        p_usage["failures"] += 1

                if self.metrics.bytes_read >= self.limits.max_bytes_read:
                    self.metrics.is_budget_exhausted = True
                    self.metrics.exhaustion_reason = (
                        f"EXCEEDED_BYTES_READ: current {self.metrics.bytes_read}B >= max {self.limits.max_bytes_read}B"
                    )

            prepared.scope.state = "FAILED"
            self._finalize_scope_reservations(prepared.scope)
            self._unregister_active_scope(prepared.scope)
            return snap

    def _finalize_scope_transaction(
        self,
        scope: "ActiveOperationScope",
        is_fail: bool = False,
    ) -> CommittedTransactionSnapshot:
        with self._transaction_lock:
            try:
                prepared = self._prepare_scope_commit(scope, is_fail=is_fail)
                return self._execute_scope_commit(prepared)
            except Exception as exc:
                if any(k in str(exc) for k in ("Operation ID collision", "Physical read ID conflict", "Physical consumption ID conflict", "Accounting transaction ID conflict")):
                    raise
                if scope.charged_bytes > 0 or scope.reads_count > 0:
                    try:
                        cand_fp = AccountingFingerprint(
                            operation_id=scope.operation_id,
                            accounting_owner=scope.owner,
                            measured_bytes_read=scope.measured_bytes_read,
                            estimated_bytes_read=scope.estimated_bytes_read or 0,
                            charged_bytes=scope.charged_bytes or 0,
                            measurement_type="MIXED" if (scope.measured_bytes_read and scope.estimated_bytes_read) else ("MEASURED" if scope.measured_bytes_read is not None else "ESTIMATED"),
                            profile_id=scope.profile_id,
                            is_failure=True,
                            stop_ms=round(max(0.0, float(scope.stop_ms)), 4),
                            latency_us=round(max(0.0, float(scope.latency_us)), 4),
                            session_id=self.session_id,
                            metadata_digest=canonical_metadata_digest({"emergency": str(exc)}),
                            physical_consumption_id=scope.physical_consumption_id,
                        )
                        snapshot = CommittedTransactionSnapshot(
                            operation_id=scope.operation_id,
                            accounting_owner=scope.owner,
                            measured_bytes_read=scope.measured_bytes_read,
                            estimated_bytes_read=scope.estimated_bytes_read or 0,
                            charged_bytes=scope.charged_bytes or 0,
                            latency_us=max(0.0, float(scope.latency_us)),
                            stop_ms=max(0.0, float(scope.stop_ms)),
                            is_failure=True,
                            accounting_status="FAILED",
                            measurement_type=cand_fp.measurement_type,
                            fingerprint=cand_fp,
                            metadata={"emergency_error": str(exc)},
                            committed_at_ms=round(self.elapsed_ms, 3),
                            session_id=self.session_id,
                            physical_consumption_id=scope.physical_consumption_id,
                        )
                        deltas = {
                            "bytes_read": scope.charged_bytes or 0,
                            "measured_bytes_read": scope.measured_bytes_read or 0,
                            "conservative_estimated_bytes": scope.estimated_bytes_read or 0,
                            "unmeasured_reads": 1 if (scope.estimated_bytes_read and not scope.measured_bytes_read) else 0,
                            "latency_us": max(0.0, float(scope.latency_us)),
                            "stop_ms": max(0.0, float(scope.stop_ms)),
                            "is_failure": True,
                            "profile_id": scope.profile_id or scope.operation_id,
                        }
                        prep = PreparedCommit(
                            snapshot=snapshot,
                            target_op_id=scope.operation_id,
                            is_duplicate=False,
                            is_collision=False,
                            deltas=deltas,
                            scope=scope,
                            reservations=[],
                        )
                        return self._recover_commit_failure(prep, error=exc, metrics_applied=False, step="prepare_failed")
                    except Exception:
                        self._finalize_scope_reservations(scope)
                        self._unregister_active_scope(scope)
                        raise exc
                else:
                    self._finalize_scope_reservations(scope)
                    self._unregister_active_scope(scope)
                    raise

    def _finalize_scope_duplicate_or_collision(
        self,
        scope: "ActiveOperationScope",
        is_fail: bool = False,
    ) -> CommittedTransactionSnapshot:
        with self._transaction_lock:
            try:
                prepared = self._prepare_scope_commit(scope, is_fail=is_fail)
                return self._execute_scope_commit(prepared)
            except Exception as exc:
                if any(k in str(exc) for k in ("Operation ID collision", "Physical read ID conflict", "Physical consumption ID conflict", "Accounting transaction ID conflict")):
                    raise
                if scope.charged_bytes > 0 or scope.reads_count > 0:
                    try:
                        cand_fp = AccountingFingerprint(
                            operation_id=scope.operation_id,
                            accounting_owner=scope.owner,
                            measured_bytes_read=scope.measured_bytes_read,
                            estimated_bytes_read=scope.estimated_bytes_read or 0,
                            charged_bytes=scope.charged_bytes or 0,
                            measurement_type="MIXED" if (scope.measured_bytes_read and scope.estimated_bytes_read) else ("MEASURED" if scope.measured_bytes_read is not None else "ESTIMATED"),
                            profile_id=scope.profile_id,
                            is_failure=True,
                            stop_ms=round(max(0.0, float(scope.stop_ms)), 4),
                            latency_us=round(max(0.0, float(scope.latency_us)), 4),
                            session_id=self.session_id,
                            metadata_digest=canonical_metadata_digest({"emergency": str(exc)}),
                            physical_consumption_id=scope.physical_consumption_id,
                        )
                        target_op = f"{scope.operation_id}#emergency_{scope.physical_consumption_id}"
                        snapshot = CommittedTransactionSnapshot(
                            operation_id=target_op,
                            accounting_owner=scope.owner,
                            measured_bytes_read=scope.measured_bytes_read,
                            estimated_bytes_read=scope.estimated_bytes_read or 0,
                            charged_bytes=scope.charged_bytes or 0,
                            latency_us=max(0.0, float(scope.latency_us)),
                            stop_ms=max(0.0, float(scope.stop_ms)),
                            is_failure=True,
                            accounting_status="FAILED",
                            measurement_type=cand_fp.measurement_type,
                            fingerprint=cand_fp,
                            metadata={"emergency_error": str(exc)},
                            committed_at_ms=round(self.elapsed_ms, 3),
                            session_id=self.session_id,
                            physical_consumption_id=scope.physical_consumption_id,
                        )
                        deltas = {
                            "bytes_read": scope.charged_bytes or 0,
                            "measured_bytes_read": scope.measured_bytes_read or 0,
                            "conservative_estimated_bytes": scope.estimated_bytes_read or 0,
                            "unmeasured_reads": 1 if (scope.estimated_bytes_read and not scope.measured_bytes_read) else 0,
                            "latency_us": max(0.0, float(scope.latency_us)),
                            "stop_ms": max(0.0, float(scope.stop_ms)),
                            "is_failure": True,
                            "profile_id": scope.profile_id or scope.operation_id,
                        }
                        prep = PreparedCommit(
                            snapshot=snapshot,
                            target_op_id=target_op,
                            is_duplicate=True,
                            is_collision=False,
                            deltas=deltas,
                            scope=scope,
                            reservations=[],
                        )
                        return self._recover_commit_failure(prep, error=exc, metrics_applied=False, step="prepare_failed")
                    except Exception:
                        self._finalize_scope_reservations(scope)
                        self._unregister_active_scope(scope)
                        raise exc
                else:
                    self._finalize_scope_reservations(scope)
                    self._unregister_active_scope(scope)
                    raise

    def _record_emergency_failure_snapshot(
        self,
        scope: "ActiveOperationScope",
        error: Exception,
    ) -> CommittedTransactionSnapshot:
        with self._transaction_lock:
            prepared = self._prepare_scope_commit(scope, is_fail=True)
            return self._recover_commit_failure(prepared, error=error, metrics_applied=False, step="manual_emergency")

    def reconcile_ledger(self, raise_on_error: bool = True) -> Dict[str, Any]:
        """Deterministically verifies that all aggregate metrics match the authoritative ledger exactly.

        Enforces all 19 P0.8 authoritative accounting invariants.
        """
        with self._transaction_lock:
            snaps = list(self._committed_transactions.values())
            phys_snaps = list(self._physical_consumption_records.values())
            read_snaps = list(self._physical_read_records.values())
            discrepancies = []

            # 1. Uniqueness of physical read IDs
            read_ids = [r.physical_read_id for r in read_snaps]
            unique_read_ids = set(read_ids)
            inv_1_ok = (len(read_ids) == len(unique_read_ids))
            if not inv_1_ok:
                discrepancies.append(
                    f"Invariant 1 (physical_read_id uniqueness) violated: {len(read_ids)} total vs {len(unique_read_ids)} unique"
                )

            # 2. Uniqueness of physical consumption IDs
            phys_ids = [s.physical_consumption_id for s in phys_snaps]
            unique_phys_ids = set(phys_ids)
            inv_2_ok = (len(phys_ids) == len(unique_phys_ids))
            if not inv_2_ok:
                discrepancies.append(
                    f"Invariant 2 (physical_consumption_id uniqueness) violated: Physical consumption IDs not unique: {len(phys_ids)} total vs {len(unique_phys_ids)} unique"
                )

            # 3. Uniqueness of accounting transaction IDs
            tx_ids = [s.accounting_transaction_id for s in snaps if getattr(s, "accounting_transaction_id", None)]
            unique_tx_ids = set(tx_ids)
            inv_3_ok = (len(tx_ids) == len(unique_tx_ids))
            if not inv_3_ok:
                discrepancies.append(
                    f"Invariant 3 (accounting_transaction_id uniqueness) violated: {len(tx_ids)} total vs {len(unique_tx_ids)} unique"
                )

            # 4. Child identity uniqueness across reservations
            seen_child_pread_ids: Set[str] = set()
            inv_4_ok = True
            for r_id, r in self._active_reservations.items():
                if hasattr(r, "child_reads") and r.child_reads:
                    for cid in r.child_reads.keys():
                        if cid in seen_child_pread_ids:
                            inv_4_ok = False
                            discrepancies.append(
                                f"Invariant 4 (child identity uniqueness across reservations) violated: child read '{cid}' shared across multiple reservations"
                            )
                        seen_child_pread_ids.add(cid)

            # 5. Reservation-to-child linkage
            inv_5_ok = True
            for r in read_snaps:
                if not getattr(r, "reservation_id", None):
                    inv_5_ok = False
                    discrepancies.append(f"Invariant 5 (reservation-to-child linkage) violated: read '{r.physical_read_id}' has no reservation_id")

            # 6. Child-to-consumption linkage
            read_id_set = set(read_ids)
            inv_6_ok = True
            for p in phys_snaps:
                p_read_id = getattr(p, "physical_read_id", None)
                if p_read_id and p_read_id not in read_id_set:
                    inv_6_ok = False
                    discrepancies.append(
                        f"Invariant 6 (child-to-consumption linkage) violated: consumption '{p.physical_consumption_id}' points to unknown read '{p_read_id}'"
                    )

            # 7. Operation-to-accounting linkage
            committed_op_ids = set(self._committed_transactions.keys())
            active_scope_op_ids = {sc.operation_id for sc_list in self._active_scopes.values() for sc in sc_list}
            inv_7_ok = True
            for p in phys_snaps:
                p_op = getattr(p, "operation_id", None)
                if p_op and p_op not in committed_op_ids and p_op not in active_scope_op_ids:
                    if not any(p_op in s.operation_id for s in snaps) and not any(getattr(p, "physical_consumption_id", None) == s.physical_consumption_id for s in snaps):
                        inv_7_ok = False
                        discrepancies.append(
                            f"Invariant 7 (operation-to-accounting linkage) violated: physical record '{getattr(p, 'physical_consumption_id', None)}' has unlinked operation '{p_op}'"
                        )

            # 8. No child record overwritten
            inv_8_ok = inv_1_ok and inv_4_ok

            # 9. No started read released
            inv_9_ok = True
            for r in read_snaps:
                th = r.transition_history if hasattr(r, "transition_history") else []
                if "PHYSICAL_READ_STARTED" in th and "RELEASED" in th:
                    inv_9_ok = False
                    discrepancies.append(
                        f"Invariant 9 (no started read released) violated: read '{r.physical_read_id}' transitioned from STARTED to RELEASED: {th}"
                    )
            for r_id, r in self._active_reservations.items():
                if hasattr(r, "child_reads"):
                    for cr in r.child_reads.values():
                        cr_th = cr.transition_history if hasattr(cr, "transition_history") else []
                        if "PHYSICAL_READ_STARTED" in cr_th and "RELEASED" in cr_th:
                            inv_9_ok = False
                            discrepancies.append(
                                f"Invariant 9 (no started child read released) violated: child '{cr.physical_read_id}' of '{r_id}' transitioned from STARTED to RELEASED: {cr_th}"
                            )

            # 10. No in-flight child at reservation finalization
            inv_10_ok = True
            for r in read_snaps:
                if r.state == "PHYSICAL_READ_STARTED":
                    inv_10_ok = False
                    discrepancies.append(
                        f"Invariant 10 (no started read without terminal outcome) violated: read '{r.physical_read_id}' is still in PHYSICAL_READ_STARTED"
                    )
            for r_id, r in self._active_reservations.items():
                if hasattr(r, "child_reads"):
                    for cr in r.child_reads.values():
                        if cr.state == "PHYSICAL_READ_STARTED" and r.state in ("ACCOUNTED", "FINALIZED", "RELEASED"):
                            inv_10_ok = False
                            discrepancies.append(
                                f"Invariant 10 (no in-flight child at reservation finalization) violated: child read '{cr.physical_read_id}' of '{r_id}' is still PHYSICAL_READ_STARTED"
                            )

            # 11. No consumed child without accounting
            active_scope_phys_ids = {s.physical_consumption_id for sc_list in self._active_scopes.values() for s in sc_list}
            inv_11_ok = True
            for r_id, r in self._active_reservations.items():
                if r.state == "CONSUMED" and (r.scope_id is None or r.scope_id not in active_scope_phys_ids):
                    inv_11_ok = False
                    discrepancies.append(
                        f"Invariant 11 (no consumed child without accounting) violated: active consumed reservation '{r_id}' has no active scope"
                    )

            # 12. No accounting without physical evidence
            inv_12_ok = True
            for op_id, s in self._committed_transactions.items():
                if s.charged_bytes > 0:
                    has_phys = (
                        s.physical_consumption_id in self._physical_consumption_records
                        or any(getattr(p, "operation_id", None) == op_id for p in phys_snaps)
                        or any(getattr(r, "operation_id", None) == op_id for r in read_snaps)
                    )
                    if not has_phys:
                        inv_12_ok = False
                        discrepancies.append(
                            f"Invariant 12 (no accounting without physical evidence) violated: transaction '{op_id}' has charged_bytes={s.charged_bytes} but no physical evidence"
                        )

            # 13. No physical consumption without valid physical_read_id
            inv_13_ok = True
            for p in phys_snaps:
                p_read_id = getattr(p, "physical_read_id", None)
                if not p_read_id or p_read_id not in read_id_set:
                    inv_13_ok = False
                    discrepancies.append(
                        f"Invariant 13 (no physical consumption without valid physical_read_id) violated: record '{getattr(p, 'physical_consumption_id', None)}' has invalid read_id '{p_read_id}'"
                    )

            # 14. No duplicate physical execution identity
            inv_14_ok = inv_1_ok and inv_2_ok and inv_4_ok

            # 15. Aggregate reservation bytes equal child consumption sum
            inv_15_ok = True
            for r_id, r in self._active_reservations.items():
                if hasattr(r, "child_reads") and r.child_reads:
                    child_sum = sum(c.charged_bytes for c in r.child_reads.values())
                    if r.consumed_bytes != child_sum:
                        inv_15_ok = False
                        discrepancies.append(
                            f"Invariant 15 (aggregate reservation bytes equal child consumption sum) violated: reservation '{r_id}' consumed {r.consumed_bytes}B != child sum {child_sum}B"
                        )

            # 16. Committed bytes equal physical ledger totals
            sum_charged = sum(s.charged_bytes for s in snaps)
            inv_16_ok = True
            if read_snaps:
                sum_reads_charged = sum(r.charged_bytes for r in read_snaps)
                if sum_reads_charged != sum_charged:
                    inv_16_ok = False
                    discrepancies.append(
                        f"Invariant 16 (committed bytes equal physical ledger totals) violated: committed={sum_charged}B vs physical_reads={sum_reads_charged}B"
                    )

            # 17. Global metrics equal committed totals
            sum_measured = sum(s.measured_bytes_read or 0 for s in snaps if s.measured_bytes_read is not None)
            sum_estimated = sum(s.estimated_bytes_read for s in snaps)
            sum_latency = sum(s.latency_us for s in snaps)
            sum_stop = sum(s.stop_ms for s in snaps)
            sum_failures = sum(1 for s in snaps if s.is_failure)
            sum_failed_status = sum(1 for s in snaps if s.accounting_status == "FAILED")
            sum_rejected_status = sum(1 for s in snaps if s.accounting_status == "REJECTED")

            inv_17_ok = True
            if sum_charged != self.metrics.bytes_read:
                inv_17_ok = False
                discrepancies.append(f"Invariant 17 violated: bytes_read: ledger={sum_charged} vs metrics={self.metrics.bytes_read}")
            if sum_measured != self.metrics.measured_bytes_read:
                inv_17_ok = False
                discrepancies.append(f"Invariant 17 violated: measured_bytes ledger={sum_measured} vs metrics={self.metrics.measured_bytes_read}")
            if sum_estimated != self.metrics.conservative_estimated_bytes:
                inv_17_ok = False
                discrepancies.append(f"Invariant 17 violated: estimated_bytes ledger={sum_estimated} vs metrics={self.metrics.conservative_estimated_bytes}")
            if round(sum_latency, 2) != round(self.metrics.observation_latency_us, 2):
                inv_17_ok = False
                discrepancies.append(f"Invariant 17 violated: latency ledger={sum_latency} vs metrics={self.metrics.observation_latency_us}")
            if round(sum_stop, 2) != round(self.metrics.target_stop_duration_ms, 2):
                inv_17_ok = False
                discrepancies.append(f"Invariant 17 violated: stop_duration ledger={sum_stop} vs metrics={self.metrics.target_stop_duration_ms}")
            if sum_failures != self.metrics.total_read_failures:
                inv_17_ok = False
                discrepancies.append(f"Invariant 17 violated: failures ledger={sum_failures} vs metrics={self.metrics.total_read_failures}")

            # 18. Profile usage equals committed profile totals
            inv_18_ok = True
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
                    inv_18_ok = False
                    discrepancies.append(f"Invariant 18 (profile '{prof_id}' bytes) violated: ledger={p_charged} vs usage={p_usage['bytes_read']}")
                if p_meas != p_usage["measured_bytes_read"]:
                    inv_18_ok = False
                    discrepancies.append(f"Invariant 18 (profile '{prof_id}' measured) violated: ledger={p_meas} vs usage={p_usage['measured_bytes_read']}")
                if p_est != p_usage["conservative_estimated_bytes"]:
                    inv_18_ok = False
                    discrepancies.append(f"Invariant 18 (profile '{prof_id}' estimated) violated: ledger={p_est} vs usage={p_usage['conservative_estimated_bytes']}")
                if p_fails != p_usage["failures"]:
                    inv_18_ok = False
                    discrepancies.append(f"Invariant 18 (profile '{prof_id}' failures) violated: ledger={p_fails} vs usage={p_usage['failures']}")

            # 19. Unknown consumption never zero
            inv_19_ok = True
            for r in read_snaps:
                if r.is_failure and r.measured_bytes_read is None and r.charged_bytes == 0:
                    inv_19_ok = False
                    discrepancies.append(f"Invariant 19 (unknown consumption never zero) violated: read '{r.physical_read_id}' has unknown bytes charged as 0")
            for s in snaps:
                if s.measurement_type == "UNKNOWN" and s.charged_bytes == 0:
                    inv_19_ok = False
                    discrepancies.append(f"Invariant 19 (unknown consumption never zero) violated: transaction '{s.operation_id}' has unknown measurement charged as 0")

            # 20. Batch completeness contract
            inv_20_ok = True
            all_slices_for_batch: List[PhysicalReadRecord] = []
            for r in read_snaps:
                ts = getattr(r, "target_spec", None) or {}
                if "slice_index" in ts:
                    all_slices_for_batch.append(r)
            for r in self._active_reservations.values():
                for cr in getattr(r, "child_reads", {}).values():
                    ts = getattr(cr, "target_spec", None) or {}
                    if "slice_index" in ts and cr.physical_read_id not in {x.physical_read_id for x in all_slices_for_batch}:
                        all_slices_for_batch.append(cr)

            batch_groups: Dict[Tuple[str, str], List[PhysicalReadRecord]] = {}
            for r in all_slices_for_batch:
                ts = r.target_spec or {}
                b_id = ts.get("batch_id") or getattr(r, "reservation_id", "unknown_batch")
                inv_id = ts.get("invocation_id") or "unknown_inv"
                batch_groups.setdefault((b_id, inv_id), []).append(r)

            for (b_id, inv_id), group in batch_groups.items():
                # 1. Expected slice count: validated if specified or registered
                exp_counts = {r.target_spec.get("expected_slice_count") for r in group} - {None}
                if not exp_counts:
                    b_reg = self._batch_records.get(f"{b_id}::{inv_id}")
                    if b_reg:
                        exp_counts = {b_reg.expected_slice_count}

                if exp_counts:
                    if len(exp_counts) > 1:
                        inv_20_ok = False
                        discrepancies.append(
                            f"Invariant 20 (batch slice completeness) violated: batch '{b_id}' invocation '{inv_id}' "
                            f"has conflicting expected_slice_count values: {exp_counts}"
                        )
                        continue
                    expected_count = next(iter(exp_counts))
                    if not isinstance(expected_count, int) or expected_count <= 0:
                        inv_20_ok = False
                        discrepancies.append(
                            f"Invariant 20 (batch slice completeness) violated: batch '{b_id}' invocation '{inv_id}' "
                            f"has invalid expected_slice_count: {expected_count}"
                        )
                        continue
                else:
                    expected_count = len(group)

                # 2. Validate every slice index in [0, expected_count)
                slice_indices = [r.target_spec.get("slice_index") for r in group]
                out_of_range = [idx for idx in slice_indices if idx is None or not isinstance(idx, int) or idx < 0 or idx >= expected_count]
                if out_of_range:
                    inv_20_ok = False
                    discrepancies.append(
                        f"Invariant 20 (batch slice completeness) violated: batch '{b_id}' invocation '{inv_id}' "
                        f"has out-of-range slice indices: {out_of_range} (expected [0, {expected_count}))"
                    )

                if len(slice_indices) != len(set(slice_indices)):
                    inv_20_ok = False
                    discrepancies.append(
                        f"Invariant 20 (batch slice completeness) violated: batch '{b_id}' invocation '{inv_id}' "
                        f"has duplicate slice indices: {slice_indices}"
                    )

                valid_indices_set = set(idx for idx in slice_indices if isinstance(idx, int) and 0 <= idx < expected_count)
                expected_set = set(range(expected_count))
                if valid_indices_set != expected_set:
                    inv_20_ok = False
                    missing = sorted(list(expected_set - valid_indices_set))
                    discrepancies.append(
                        f"Invariant 20 (batch slice completeness) violated: batch '{b_id}' invocation '{inv_id}' "
                        f"is incomplete, missing slice indices: {missing}"
                    )

                # 3. Check duplicate physical_read_id or physical_consumption_id within batch
                batch_read_ids = [r.physical_read_id for r in group]
                if len(batch_read_ids) != len(set(batch_read_ids)):
                    inv_20_ok = False
                    discrepancies.append(
                        f"Invariant 20 (batch slice completeness) violated: batch '{b_id}' invocation '{inv_id}' "
                        f"contains duplicate physical_read_ids: {batch_read_ids}"
                    )
                batch_cons_ids = [r.physical_consumption_id for r in group if r.physical_consumption_id]
                if len(batch_cons_ids) != len(set(batch_cons_ids)):
                    inv_20_ok = False
                    discrepancies.append(
                        f"Invariant 20 (batch slice completeness) violated: batch '{b_id}' invocation '{inv_id}' "
                        f"contains duplicate physical_consumption_ids: {batch_cons_ids}"
                    )

                # 4. Check conflicting address or requested size metadata
                seen_specs: Dict[int, Tuple[int, int]] = {}
                for r in group:
                    s_idx = r.target_spec.get("slice_index")
                    addr = r.target_spec.get("address")
                    req_sz = r.target_spec.get("requested_size", r.target_spec.get("size"))
                    if s_idx is not None and addr is not None and req_sz is not None:
                        if s_idx in seen_specs:
                            if seen_specs[s_idx] != (addr, req_sz):
                                inv_20_ok = False
                                discrepancies.append(
                                    f"Invariant 20 (batch slice completeness) violated: batch '{b_id}' slice {s_idx} "
                                    f"has conflicting metadata: {seen_specs[s_idx]} vs {(addr, req_sz)}"
                                )
                        else:
                            seen_specs[s_idx] = (addr, req_sz)

                # 5. Check completion status and failed slice preservation
                for r in group:
                    c_status = r.target_spec.get("completion_status")
                    valid_statuses = {"OBSERVED", "PARTIAL", "FAILED", "UNAVAILABLE", "NOT_EXECUTED", "UNKNOWN", None}
                    if c_status not in valid_statuses:
                        inv_20_ok = False
                        discrepancies.append(
                            f"Invariant 20 (batch slice completeness) violated: slice '{r.physical_read_id}' "
                            f"has invalid completion_status: {c_status}"
                        )
                    if r.is_failure or c_status in ("FAILED", "UNAVAILABLE"):
                        if r.measured_bytes_read is not None and r.measured_bytes_read == 0 and r.estimated_bytes_read > 0:
                            inv_20_ok = False
                            discrepancies.append(
                                f"Invariant 20 (batch slice completeness) violated: failed slice '{r.physical_read_id}' "
                                f"falsely reported measured_bytes_read=0 alongside estimated_bytes_read={r.estimated_bytes_read}"
                            )

            # 21. Collector / fallback provenance separation (Active AND Committed)
            inv_21_ok = True
            provenance_groups: Dict[str, List[PhysicalReadRecord]] = {}
            for r in read_snaps:
                res_key = r.reservation_id or getattr(r, "operation_id", "unknown")
                provenance_groups.setdefault(res_key, []).append(r)
            for r_id, r in self._active_reservations.items():
                if hasattr(r, "child_reads") and r.child_reads:
                    for cr in r.child_reads.values():
                        if cr.physical_read_id not in {x.physical_read_id for x in provenance_groups.get(r_id, [])}:
                            provenance_groups.setdefault(r_id, []).append(cr)

            for grp_id, group_reads in provenance_groups.items():
                coll_reads = [
                    c for c in group_reads
                    if "collector" in getattr(c, "target_type", "") or (c.target_spec and c.target_spec.get("invocation_type") == "collector")
                ]
                shell_reads = [
                    c for c in group_reads
                    if "shell" in getattr(c, "target_type", "") or (c.target_spec and c.target_spec.get("invocation_type") == "shell_fallback")
                ]
                if coll_reads and shell_reads:
                    coll_read_ids = {c.physical_read_id for c in coll_reads}
                    shell_read_ids = {c.physical_read_id for c in shell_reads}
                    coll_cons_ids = {c.physical_consumption_id for c in coll_reads if c.physical_consumption_id}
                    shell_cons_ids = {c.physical_consumption_id for c in shell_reads if c.physical_consumption_id}
                    if coll_read_ids.intersection(shell_read_ids):
                        inv_21_ok = False
                        discrepancies.append(
                            f"Invariant 21 (collector/fallback provenance separation) violated: group '{grp_id}' "
                            f"shares physical_read_ids between collector and fallback"
                        )
                    if coll_cons_ids.intersection(shell_cons_ids):
                        inv_21_ok = False
                        discrepancies.append(
                            f"Invariant 21 (collector/fallback provenance separation) violated: group '{grp_id}' "
                            f"shares physical_consumption_ids between collector and fallback"
                        )
                    coll_inv_ids = {c.target_spec.get("invocation_id") for c in coll_reads if c.target_spec} - {None}
                    shell_inv_ids = {c.target_spec.get("invocation_id") for c in shell_reads if c.target_spec} - {None}
                    if coll_inv_ids and shell_inv_ids and coll_inv_ids.intersection(shell_inv_ids):
                        inv_21_ok = False
                        discrepancies.append(
                            f"Invariant 21 (collector/fallback provenance separation) violated: group '{grp_id}' "
                            f"shares invocation_ids between collector and fallback: {coll_inv_ids.intersection(shell_inv_ids)}"
                        )

            # 22. Invocation provenance & orphan record detection
            inv_22_ok = True
            all_active_child_reads = [cr for r in self._active_reservations.values() for cr in getattr(r, "child_reads", {}).values()]
            all_known_read_ids = set(read_ids).union({cr.physical_read_id for cr in all_active_child_reads})

            for inv_id, inv_rec in self._invocations.items():
                if inv_rec.outcome != "PREFLIGHT_REJECTED" and inv_rec.physical_read_ids:
                    for pid_ref in inv_rec.physical_read_ids:
                        if pid_ref not in all_known_read_ids:
                            inv_22_ok = False
                            discrepancies.append(
                                f"Invariant 22 (invocation provenance) violated: orphan invocation '{inv_id}' "
                                f"references non-existent physical_read_id '{pid_ref}'"
                            )

            if self._invocations:
                all_inspected_reads = list(read_snaps) + all_active_child_reads
                for r in all_inspected_reads:
                    ts = getattr(r, "target_spec", None) or {}
                    r_inv_id = ts.get("invocation_id")
                    if r_inv_id:
                        if r_inv_id not in self._invocations:
                            inv_22_ok = False
                            discrepancies.append(
                                f"Invariant 22 (invocation provenance) violated: physical read '{r.physical_read_id}' "
                                f"references unknown invocation_id '{r_inv_id}'"
                            )
                        else:
                            inv_obj = self._invocations[r_inv_id]
                            if r.physical_read_id not in inv_obj.physical_read_ids:
                                inv_22_ok = False
                                discrepancies.append(
                                    f"Invariant 22 (invocation provenance) violated: physical read '{r.physical_read_id}' "
                                    f"is not listed in invocation '{r_inv_id}' physical_read_ids"
                                )

            for r in read_snaps:
                if not r.reservation_id:
                    inv_22_ok = False
                    discrepancies.append(
                        f"Invariant 22 (orphan physical read) violated: committed read '{r.physical_read_id}' has no reservation_id"
                    )
                if r.state in ("ACCOUNTED", "FAILED_ACCOUNTED"):
                    if r.operation_id and r.operation_id not in self._committed_transactions:
                        if not any(getattr(r, "operation_id", None) == s.operation_id for s in snaps):
                            inv_22_ok = False
                            discrepancies.append(
                                f"Invariant 22 (orphan physical read) violated: committed read '{r.physical_read_id}' "
                                f"has operation_id '{r.operation_id}' not found in committed transactions"
                            )

            valid_states = {"ADMITTED", "RESERVED", "PHYSICAL_READ_STARTED", "CONSUMED", "RELEASED", "ACCOUNTED", "FINALIZED", "FAILED_ACCOUNTED"}
            for r_id, r in self._active_reservations.items():
                if r.state not in valid_states:
                    discrepancies.append(f"Reservation '{r_id}' in invalid state '{r.state}'")

            active_res_list = [r for r in self._active_reservations.values() if r.state in ("ADMITTED", "RESERVED", "PHYSICAL_READ_STARTED")]
            active_res_bytes = sum(r.reserved_bytes for r in active_res_list)
            consumed_unaccounted_bytes = sum(r.consumed_bytes for r in self._active_reservations.values() if r.state == "CONSUMED")
            active_in_flight_bytes = self._active_consumed_bytes()
            duplicate_snaps = [s for s in snaps if "#duplicate_" in s.operation_id]
            collision_snaps = [s for s in snaps if "#collision_" in s.operation_id]

            discrepancy_details = {
                "inv_1_physical_read_id_uniqueness": inv_1_ok,
                "inv_2_physical_consumption_id_uniqueness": inv_2_ok,
                "inv_3_accounting_transaction_id_uniqueness": inv_3_ok,
                "inv_4_child_identity_uniqueness": inv_4_ok,
                "inv_5_reservation_to_child_linkage": inv_5_ok,
                "inv_6_child_to_consumption_linkage": inv_6_ok,
                "inv_7_operation_to_accounting_linkage": inv_7_ok,
                "inv_8_no_child_overwrites": inv_8_ok,
                "inv_9_no_started_read_released": inv_9_ok,
                "inv_10_no_inflight_child_at_finalization": inv_10_ok,
                "inv_11_no_consumed_child_without_accounting": inv_11_ok,
                "inv_12_no_accounting_without_physical_evidence": inv_12_ok,
                "inv_13_no_consumption_without_valid_read_id": inv_13_ok,
                "inv_14_no_duplicate_physical_execution_identity": inv_14_ok,
                "inv_15_aggregate_reservation_equals_child_sum": inv_15_ok,
                "inv_16_committed_bytes_equal_physical_ledger": inv_16_ok,
                "inv_17_global_metrics_equal_committed_totals": inv_17_ok,
                "inv_18_profile_usage_equals_committed_profile_totals": inv_18_ok,
                "inv_19_unknown_consumption_never_zero": inv_19_ok,
                "inv_20_batch_slice_completeness": inv_20_ok,
                "inv_21_collector_fallback_provenance_separation": inv_21_ok,
                "inv_22_invocation_provenance_and_orphan_detection": inv_22_ok,
            }

            if discrepancies and raise_on_error:
                raise AssertionError(f"Tracker ledger reconciliation failed: {'; '.join(discrepancies)}")

            return {
                "reconciled": len(discrepancies) == 0,
                "discrepancies": discrepancies,
                "discrepancy_details": discrepancy_details,
                "total_transactions": len(snaps),
                "total_logical_transactions": len(snaps),
                "total_physical_records": len(phys_snaps),
                "total_physical_reads": len(read_snaps),
                "unique_physical_consumption_ids": len(unique_phys_ids),
                "unique_physical_read_ids": len(unique_read_ids),
                "duplicate_logical_operations_count": len(duplicate_snaps),
                "collision_records_count": len(collision_snaps),
                "total_bytes_read": sum_charged,
                "total_measured_bytes": sum_measured,
                "total_estimated_bytes": sum_estimated,
                "total_latency_us": sum_latency,
                "total_stop_ms": sum_stop,
                "total_failures": sum_failures,
                "total_failed_outcomes": sum_failed_status,
                "total_rejected_outcomes": sum_rejected_status,
                "active_reservations_count": len(active_res_list),
                "active_reservations_bytes": active_res_bytes,
                "consumed_unaccounted_reservations_bytes": consumed_unaccounted_bytes,
                "released_reservations_count": getattr(self, "_released_reservations_count", 0),
                "active_in_flight_scopes_count": len(self._active_scopes),
                "active_in_flight_bytes": active_in_flight_bytes,
                "physical_consumption_records_count": len(phys_snaps),
            }

    def commit_transaction(
        self,
        record: Optional[ObservationAccountingRecord] = None,
        profile_id: Optional[str] = None,
        profile_ceiling: Optional[Dict[str, Any]] = None,
        is_failure: bool = False,
        stop_ms: float = 0.0,
        reservations: Optional[List[BudgetReservation]] = None,
        operation_id: Optional[str] = None,
        measured_bytes: Optional[int] = None,
        estimated_bytes: Optional[int] = None,
        latency_us: float = 0.0,
        accounting_owner: str = "ADAPTER",
        metadata: Optional[Dict[str, Any]] = None,
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
        if record is None:
            if operation_id is None:
                raise ValueError("Must provide either record or operation_id to commit_transaction")
            res_consumed = sum(r.consumed_bytes for r in (reservations or []))
            if measured_bytes is None and estimated_bytes is None:
                child_reads = [cr for r in (reservations or []) for cr in getattr(r, "child_reads", {}).values()]
                if child_reads:
                    has_any_measured = any(cr.measured_bytes_read is not None for cr in child_reads)
                    measured_bytes = sum(cr.measured_bytes_read or 0 for cr in child_reads if cr.measured_bytes_read is not None) if has_any_measured else None
                    estimated_bytes = sum(cr.estimated_bytes_read for cr in child_reads)
                elif res_consumed > 0:
                    if is_failure:
                        estimated_bytes = res_consumed
                    else:
                        measured_bytes = res_consumed
            record = ObservationAccountingRecord(
                operation_id=operation_id,
                accounting_owner=accounting_owner,
                measured_bytes_read=measured_bytes,
                estimated_bytes_read=estimated_bytes or 0,
                charged_bytes=max(0, int(measured_bytes or 0)) + int(estimated_bytes or 0),
                latency_us=latency_us,
                session_id=self.session_id,
                metadata=dict(metadata or {}),
            )

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

            phys_id = record.physical_consumption_id or f"phys_{uuid.uuid4().hex}"
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

            if phys_id in self._physical_consumption_records:
                existing_phys = self._physical_consumption_records[phys_id]
                if existing_phys.charged_bytes == total_charge:
                    with record._lock:
                        if record.accounting_status != "COMMITTED":
                            record.transition_to("COMMITTED")
                    return True
                else:
                    raise ValueError(
                        f"Physical consumption ID conflict: '{phys_id}' already registered with "
                        f"{existing_phys.charged_bytes}B, conflicting with candidate {total_charge}B"
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

            # Validate accounting_transaction_id uniqueness if specified
            tx_id = record.accounting_transaction_id or f"tx_{uuid.uuid4().hex[:12]}"
            for existing_tx in self._committed_transactions.values():
                if existing_tx.accounting_transaction_id == tx_id and existing_tx.operation_id != record.operation_id:
                    raise ValueError(f"Accounting transaction ID conflict: '{tx_id}' already assigned to '{existing_tx.operation_id}'")

            # Pre-validate child reads before mutating any metrics or ledger state
            all_commit_res = list(reservations or [])
            for r_id, res in self._active_reservations.items():
                if res.operation_id == record.operation_id:
                    if res not in all_commit_res:
                        all_commit_res.append(res)
            for res in all_commit_res:
                for cr in res.child_reads.values():
                    if cr.physical_read_id in self._physical_read_records:
                        existing_cr = self._physical_read_records[cr.physical_read_id]
                        if existing_cr.charged_bytes != cr.charged_bytes:
                            for r in all_commit_res:
                                if not r.is_terminal:
                                    r.mark_failed_accounted()
                                self._active_reservations.pop(r.reservation_id, None)
                            raise ValueError(
                                f"Physical read ID conflict: '{cr.physical_read_id}' already committed with "
                                f"{existing_cr.charged_bytes}B, conflicting with {cr.charged_bytes}B"
                            )
                    if cr.state == "PHYSICAL_READ_STARTED":
                        raise RuntimeError(
                            f"Cannot commit transaction '{record.operation_id}': child read '{cr.physical_read_id}' is still in flight"
                        )

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
                accounting_transaction_id=tx_id,
            )
            self._committed_transactions[record.operation_id] = snapshot
            # Register child physical reads and physical consumption records
            all_commit_res = list(reservations or [])
            for r_id, res in self._active_reservations.items():
                if res.operation_id == record.operation_id:
                    if res not in all_commit_res:
                        all_commit_res.append(res)
            has_child_reads = False
            for res in all_commit_res:
                for cr in res.child_reads.values():
                    has_child_reads = True
                    cr.operation_id = record.operation_id
                    if cr.state in ("CONSUMED", "ACCOUNTED"):
                        if cr.state == "CONSUMED":
                            cr.account()
                        pcons = cr.to_consumption_record(
                            operation_id=record.operation_id,
                            committed_at_ms=time.time(),
                            accounting_status="COMMITTED",
                        )
                        self._physical_read_records[cr.physical_read_id] = cr
                        self._physical_consumption_records[cr.physical_consumption_id] = pcons
                    elif cr.state == "FAILED_ACCOUNTED":
                        pcons = cr.to_consumption_record(
                            operation_id=record.operation_id,
                            committed_at_ms=time.time(),
                            accounting_status="FAILED",
                        )
                        self._physical_read_records[cr.physical_read_id] = cr
                        self._physical_consumption_records[cr.physical_consumption_id] = pcons

            if not has_child_reads:
                root_pread_id = f"pread_{phys_id}"
                root_pcons = PhysicalConsumptionRecord(
                    physical_consumption_id=phys_id,
                    physical_read_id=root_pread_id,
                    reservation_id="direct_commit",
                    operation_id=record.operation_id,
                    measured_bytes_read=actual_meas if meas_b is not None else None,
                    estimated_bytes_read=actual_est,
                    charged_bytes=total_charge,
                    latency_us=lat_val,
                    stop_ms=stop_val,
                    is_failure=is_failure,
                    accounting_status="COMMITTED",
                    measurement_type=record.measurement_type,
                    created_at_ms=time.time(),
                    committed_at_ms=time.time(),
                    metadata=dict(record.metadata),
                )
                self._physical_consumption_records[phys_id] = root_pcons
                root_cr = PhysicalReadRecord(
                    physical_read_id=root_pread_id,
                    reservation_id="direct_commit",
                    physical_consumption_id=phys_id,
                    operation_id=record.operation_id,
                    state="ACCOUNTED",
                    charged_bytes=total_charge,
                    measured_bytes_read=actual_meas if meas_b is not None else None,
                    estimated_bytes_read=actual_est,
                    latency_us=lat_val,
                    is_failure=is_failure,
                )
                self._physical_read_records[root_pread_id] = root_cr

            # Finalize associated reservations
            if reservations:
                for res in reservations:
                    if res.consumed_bytes > 0 or total_charge > 0 or res.state == "CONSUMED":
                        if res.state in ("ADMITTED", "RESERVED", "PHYSICAL_READ_STARTED", "CONSUMED"):
                            res.account()
                    else:
                        if res.state in ("ADMITTED", "RESERVED"):
                            res.release()
                            self._released_reservations_count += 1
                        elif res.state == "PHYSICAL_READ_STARTED":
                            res.account()
                    self._active_reservations.pop(res.reservation_id, None)
            for r_id, res in list(self._active_reservations.items()):
                if res.operation_id == record.operation_id:
                    if res.consumed_bytes > 0 or total_charge > 0 or res.state == "CONSUMED":
                        if res.state in ("ADMITTED", "RESERVED", "PHYSICAL_READ_STARTED", "CONSUMED"):
                            res.account()
                    else:
                        if res.state in ("ADMITTED", "RESERVED"):
                            res.release()
                            self._released_reservations_count += 1
                        elif res.state == "PHYSICAL_READ_STARTED":
                            res.account()
                    self._active_reservations.pop(r_id, None)

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

            if not any(getattr(r, "operation_id", None) == record.operation_id for r in self._physical_read_records.values()):
                root_pread_id = f"pread_{phys_id}"
                root_pcons = PhysicalConsumptionRecord(
                    physical_consumption_id=phys_id,
                    physical_read_id=root_pread_id,
                    reservation_id="scope_register",
                    operation_id=record.operation_id,
                    measured_bytes_read=record.measured_bytes_read,
                    estimated_bytes_read=record.estimated_bytes_read or 0,
                    charged_bytes=record.charged_bytes or 0,
                    latency_us=float(record.latency_us or 0.0),
                    stop_ms=float(stop_ms or 0.0),
                    is_failure=is_failure,
                    accounting_status="COMMITTED",
                    measurement_type=record.measurement_type,
                    created_at_ms=time.time(),
                    committed_at_ms=round(self.elapsed_ms, 3),
                    metadata=dict(record.metadata),
                )
                self._physical_consumption_records[phys_id] = root_pcons
                root_cr = PhysicalReadRecord(
                    physical_read_id=root_pread_id,
                    reservation_id="scope_register",
                    physical_consumption_id=phys_id,
                    operation_id=record.operation_id,
                    state="ACCOUNTED",
                    charged_bytes=record.charged_bytes or 0,
                    measured_bytes_read=record.measured_bytes_read,
                    estimated_bytes_read=record.estimated_bytes_read or 0,
                    latency_us=float(record.latency_us or 0.0),
                    is_failure=is_failure,
                )
                self._physical_read_records[root_pread_id] = root_cr
            return snapshot

    def get_physical_consumption_records(self) -> Dict[str, Any]:
        """Returns read-only deep-copied dictionary of all physical consumption records."""
        with self._transaction_lock:
            return copy.deepcopy(self._physical_consumption_records)

    def get_physical_read_records(self) -> Dict[str, PhysicalReadRecord]:
        """Returns read-only deep-copied dictionary of all committed physical read records."""
        with self._transaction_lock:
            return copy.deepcopy(self._physical_read_records)

    def get_active_reservations(self) -> Dict[str, BudgetReservation]:
        """Returns read-only dictionary of active reservations."""
        with self._transaction_lock:
            return copy.deepcopy(self._active_reservations)

    def is_operation_committed(self, operation_id: str) -> bool:
        """Returns True if the operation_id has an authoritative committed transaction."""
        with self._transaction_lock:
            return operation_id in self._committed_transactions

    def get_committed_record(self, operation_id: str) -> Optional[CommittedTransactionSnapshot]:
        """Returns an independent deep copy of the authoritative committed transaction snapshot."""
        with self._transaction_lock:
            rec = self._committed_transactions.get(operation_id)
            if rec is None:
                return None
            return copy.deepcopy(rec)

    def get_child_reads(self, reservation_id: Optional[str] = None) -> Dict[str, PhysicalReadRecord]:
        """Returns deep copy of child physical reads for a reservation or across all active reservations."""
        with self._transaction_lock:
            if reservation_id is not None:
                res = self._active_reservations.get(reservation_id)
                if res is not None:
                    return res.get_child_reads()
                return {}
            result = {}
            for res in self._active_reservations.values():
                result.update(res.get_child_reads())
            return result

    def get_committed_transactions(self) -> Dict[str, ObservationAccountingRecord]:
        """Returns a deep-copied dictionary of all authoritative committed transactions."""
        with self._transaction_lock:
            return copy.deepcopy(self._committed_transactions)

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

    def get_profile_usage(self, profile_id: str) -> Dict[str, Any]:
        """Returns the live usage dictionary for a specific profile."""
        return self._get_or_init_profile_usage(profile_id)

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
                pcons = PhysicalConsumptionRecord(
                    physical_consumption_id=phys_id,
                    physical_read_id=f"pread_{phys_id}",
                    reservation_id="standalone",
                    operation_id=attributed_operation_id,
                    measured_bytes_read=int(bytes_read) if measured else None,
                    estimated_bytes_read=charged_b if not measured else 0,
                    charged_bytes=charged_b,
                    latency_us=lat_val,
                    stop_ms=stop_val,
                    is_failure=is_failure,
                    accounting_status="COMMITTED",
                    measurement_type=cand_fp.measurement_type,
                    created_at_ms=time.time(),
                    committed_at_ms=time.time(),
                    metadata={},
                )
                self._physical_consumption_records[phys_id] = pcons
                pread = PhysicalReadRecord(
                    physical_read_id=f"pread_{phys_id}",
                    reservation_id="standalone",
                    physical_consumption_id=phys_id,
                    operation_id=attributed_operation_id,
                    state="ACCOUNTED",
                    charged_bytes=charged_b,
                    measured_bytes_read=int(bytes_read) if measured else None,
                    estimated_bytes_read=charged_b if not measured else 0,
                    latency_us=lat_val,
                    is_failure=is_failure,
                )
                self._physical_read_records[pread.physical_read_id] = pread

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

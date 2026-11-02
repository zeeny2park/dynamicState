"""Declarative Inspection Profiles and Pre-authorized Read-Only Adapters.

Defines modular, reusable inspection profiles with strict contracts:
- Domain separation (CONCURRENCY, MEMORY, IPC, HEAP, INTEGRITY, TEMPORAL, GENERIC)
- Pre-authorized read-only adapters (Zero target writes / mutations)
- Explicit budget ceilings per inspection profile enforced before and after execution
- No silent fabrication of measured byte counts
"""

from abc import ABC, abstractmethod
from contextlib import nullcontext
from dataclasses import asdict, dataclass, field
import math
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union
import uuid
from .observation_budget import (
    ObservationBudgetTracker,
    validate_non_negative_int,
    validate_non_negative_float,
    ObservationAccountingRecord,
)
from .target_adapter import TargetExecutionAdapter, LocalTargetAdapter, RemoteSshTargetAdapter, ReadOnlyTargetAdapter


# Inspection Domains
DOMAIN_CONCURRENCY = "CONCURRENCY"
DOMAIN_MEMORY = "MEMORY"
DOMAIN_INTEGRITY = "INTEGRITY"
DOMAIN_IPC = "IPC"
DOMAIN_HEAP = "HEAP"
DOMAIN_TEMPORAL = "TEMPORAL"
DOMAIN_GENERIC = "GENERIC"


@dataclass
class InspectionProfile:
    """Declarative specification for a read-only inspection routine."""
    profile_id: str
    domain: str
    name: str
    description: str = ""
    priority: int = 100  # Higher = earlier execution in scheduler
    required_symbols: List[str] = field(default_factory=list)
    required_capabilities: List[str] = field(default_factory=list)
    requires_explicit_target_expression: bool = False
    estimated_bytes: Optional[int] = 4096
    estimated_latency_ms: float = 25.0
    estimated_samples: int = 1
    estimated_stop_ms: float = 0.0
    risk_level: str = "LOW_IMPACT"
    budget_ceiling: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)

    # Backward-compatible profile tier constants
    SHALLOW_DISCOVERY = "SHALLOW_DISCOVERY"
    DEEP_INSPECTION = "DEEP_INSPECTION"
    TEMPORAL_SAMPLING = "TEMPORAL_SAMPLING"

    def __post_init__(self) -> None:
        if not self.budget_ceiling:
            est_b = self.estimated_bytes if (self.estimated_bytes is not None and self.estimated_bytes > 0) else 65536
            self.budget_ceiling = {
                "max_bytes_read": max(65536, est_b * 8),
                "max_wall_clock_ms": max(500.0, self.estimated_latency_ms * 10.0),
                "max_samples": max(4, self.estimated_samples * 4),
                "max_target_stop_ms": self.estimated_stop_ms,
            }


class ReadOnlyWatchManager:
    """Strict capability boundary wrapping WatchSessionManager for inspection modules.

    Exposes ONLY approved diagnostic and read-only query methods.
    Blocks any mutation, process management, batch execution, or session deletion.
    """
    PERMITTED_DIAGNOSTIC_METHODS = {
        "auto_triage_incident",
        "inspect_thread_callstacks_and_locks",
        "inspect_thread_locals_and_frame_vars",
        "evaluate_symbol_paths",
        "find_symbol_owners_and_threads",
        "audit_memory_integrity",
        "verify_runtime_hypothesis",
        "export_incident_report",
        "resolve_target_context",
        "get_memory_mappings",
        "read_process_memory",
        "scan_memory_pool",
        "trace_ipc_pipeline",
        "verify_concurrent_read_consistency",
        "sample_statistical_hotspots",
        "flight_recorder_time_machine",
        "detect_behavioral_drift",
        "inspect_thread_local_storage",
        "inspect_dpdk_lcores_and_rings",
        "inspect_shared_memory_ipc",
        "scan_heap_objects",
        "build_dependency_graph",
    }

    def __init__(self, inner: Any):
        if isinstance(inner, ReadOnlyWatchManager):
            self._inner = inner._inner
        else:
            self._inner = inner

    def __getattr__(self, name: str) -> Any:
        if name in self.PERMITTED_DIAGNOSTIC_METHODS:
            return getattr(self._inner, name)
        raise PermissionError(
            f"Method '{name}' is not an authorized read-only diagnostic capability. "
            "Target mutation, arbitrary macro execution, and session manipulation are strictly blocked."
        )

    def __setattr__(self, name: str, value: Any) -> None:
        if name in ("_inner",):
            super().__setattr__(name, value)
        else:
            raise PermissionError(f"Modifying attribute '{name}' on ReadOnlyWatchManager is forbidden.")


@dataclass
class InspectionContext:
    """Read-only execution context provided to an inspection module."""
    pid: int
    companion_elf: str
    adapter: TargetExecutionAdapter
    budget_tracker: ObservationBudgetTracker
    target_info: Dict[str, Any] = field(default_factory=dict)
    parameters: Dict[str, Any] = field(default_factory=dict)
    extra_context: Dict[str, Any] = field(default_factory=dict)
    available_symbols: Optional[Set[str]] = None
    capabilities: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.adapter, ReadOnlyTargetAdapter):
            self.adapter = ReadOnlyTargetAdapter(self.adapter)
        self.enforce_read_only()

    def enforce_read_only(self) -> None:
        """Enforces that the execution context and all exposed handles are strictly read-only."""
        # 1. Parameter safety check
        for param_key in ("allow_mutation", "write_memory", "write_process_memory", "apply_mutation", "mutate", "inject", "kill"):
            if self.parameters.get(param_key):
                raise PermissionError(f"InspectionContext forbids parameter '{param_key}' requesting target mutation.")

        # 2. Adapter capability boundary verification
        if not isinstance(self.adapter, ReadOnlyTargetAdapter):
            self.adapter = ReadOnlyTargetAdapter(self.adapter)

        # 3. extra_context sanitization
        for k in list(self.extra_context.keys()):
            if any(forbidden in k.lower() for forbidden in ("mutate", "write", "kill", "inject", "exec")):
                raise PermissionError(f"InspectionContext extra_context contains forbidden mutating key '{k}'")


class InspectionModule(ABC):
    """Abstract contract for an inspection module."""

    def __init__(self, profile: InspectionProfile):
        self.profile = profile
        self.module_id = profile.profile_id
        self.domain = profile.domain

    @abstractmethod
    def run(self, ctx: InspectionContext, watch_manager: Any = None) -> Dict[str, Any]:
        """Executes the read-only inspection within budget."""
        raise NotImplementedError


class FunctionalInspectionModule(InspectionModule):
    """Wraps a read-only diagnostic function in a budget-enforced InspectionModule."""

    def __init__(
        self,
        profile: Optional[Union[InspectionProfile, str]] = None,
        func: Optional[Union[Callable[..., Dict[str, Any]], str]] = None,
        arg_mapper: Optional[Union[Callable[[InspectionContext], Dict[str, Any]], List[str]]] = None,
        pos_collect_fn: Optional[Callable[..., Dict[str, Any]]] = None,
        *,
        module_id: Optional[str] = None,
        domain: Optional[str] = None,
        profiles: Optional[List[str]] = None,
        collect_fn: Optional[Callable[..., Dict[str, Any]]] = None,
    ):
        # Support both (InspectionProfile, func) and (module_id, domain, profiles, collect_fn)
        if isinstance(profile, InspectionProfile):
            resolved_profile = profile
            resolved_func = func if callable(func) else collect_fn
            self.profiles = profiles or [InspectionProfile.SHALLOW_DISCOVERY]
        else:
            eff_id = module_id or (profile if isinstance(profile, str) else "mod_generic")
            eff_domain = domain or (func if isinstance(func, str) else DOMAIN_GENERIC)
            # Determine arg3 / arg4 if passed positionally: (module_id, domain, profiles, collect_fn)
            if isinstance(arg_mapper, list) and profiles is None:
                self.profiles = arg_mapper
                arg_mapper = None
            else:
                self.profiles = profiles or [InspectionProfile.SHALLOW_DISCOVERY]
            resolved_profile = InspectionProfile(
                profile_id=eff_id,
                domain=eff_domain,
                name=eff_id,
            )
            resolved_func = collect_fn or pos_collect_fn or (func if callable(func) else None)

        super().__init__(resolved_profile)
        self._func = resolved_func
        self.func = resolved_func
        self.collect_fn = resolved_func
        self._arg_mapper = arg_mapper or (
            lambda c: {
                "pid": c.pid,
                "companion_elf_path": c.companion_elf,
                "adapter": c.adapter,
                "budget_tracker": c.budget_tracker,
                **c.parameters,
            }
        )
        self.arg_mapper = self._arg_mapper

    def check_prerequisites(self, ctx: InspectionContext) -> Tuple[bool, Optional[str]]:
        """Validates required capabilities, symbols, and explicit target expressions before execution."""
        for req_cap in self.profile.required_capabilities:
            if ctx.capabilities and ctx.capabilities.get(req_cap) is False:
                return (
                    False,
                    f"Required capability '{req_cap}' is unavailable for profile '{self.profile.profile_id}'.",
                )

        if self.profile.required_symbols and ctx.available_symbols is not None:
            missing = [s for s in self.profile.required_symbols if s not in ctx.available_symbols]
            if missing:
                return (
                    False,
                    f"Required symbol(s) {missing} not present in target binary for profile '{self.profile.profile_id}'.",
                )

        if self.profile.requires_explicit_target_expression:
            has_expr = any(
                bool(ctx.parameters.get(k))
                for k in ("target_expression", "root_expression", "pipeline_expression", "expressions", "symbol_name")
            )
            if not has_expr:
                return (
                    False,
                    f"Profile '{self.profile.profile_id}' requires a discovered or explicit target expression; none available in target.",
                )

        return True, None

    def run(self, ctx: InspectionContext, watch_manager: Any = None) -> Dict[str, Any]:
        ctx.enforce_read_only()

        # 1. Prerequisite & capability check
        prereq_ok, prereq_reason = self.check_prerequisites(ctx)
        if not prereq_ok:
            return {
                "success": False,
                "unavailable": True,
                "result_category": "OBSERVATION_UNAVAILABLE",
                "error": prereq_reason,
                "error_code": "PREREQUISITE_UNAVAILABLE",
                "abstained": True,
                "profile_id": self.profile.profile_id,
            }

        # 2. Pre-execution budget check (global + per-observation + per-profile ceiling)
        est_bytes = ctx.parameters.get("estimated_bytes", self.profile.estimated_bytes)
        est_lat_ms = float(ctx.parameters.get("estimated_latency_ms", self.profile.estimated_latency_ms))
        est_samples = int(ctx.parameters.get("estimated_samples", self.profile.estimated_samples))
        est_stop_ms = float(ctx.parameters.get("estimated_stop_ms", self.profile.estimated_stop_ms))

        can_exec, reject_reason, eff_est_bytes = ctx.budget_tracker.check_pre_execution(
            estimated_bytes=est_bytes,
            estimated_latency_ms=est_lat_ms,
            estimated_samples=est_samples,
            estimated_stop_ms=est_stop_ms,
            profile_id=self.profile.profile_id,
            profile_ceiling=self.profile.budget_ceiling,
        )
        if not can_exec:
            ctx.budget_tracker.record_rejection(self.profile.profile_id, reject_reason or "BUDGET_EXCEEDED")
            return {
                "success": False,
                "status": "BUDGET_EXHAUSTED",
                "budget_rejected": True,
                "result_category": "BUDGET_REJECTED",
                "error": f"Inspection aborted before execution: observation budget exceeded ({reject_reason})",
                "error_code": "BUDGET_EXHAUSTED",
                "abstained": True,
                "profile_id": self.profile.profile_id,
                "estimated_bytes": eff_est_bytes,
            }

        t0_ns = time.monotonic_ns()
        op_id = f"{self.profile.profile_id}_{uuid.uuid4().hex[:12]}"
        kwargs = dict(self._arg_mapper(ctx))
        kwargs.setdefault("operation_id", op_id)
        # Strip internal budget estimation hints from downstream tool kwargs
        for meta_key in ("estimated_bytes", "estimated_latency_ms", "estimated_samples", "estimated_stop_ms"):
            kwargs.pop(meta_key, None)

        safe_wm = ReadOnlyWatchManager(watch_manager) if watch_manager is not None else None
        scope_cm = (
            ctx.budget_tracker.operation_scope(op_id, profile_id=self.profile.profile_id, owner="MODULE_INTERNAL")
            if ctx.budget_tracker and hasattr(ctx.budget_tracker, "operation_scope")
            else nullcontext()
        )
        scope = None
        try:
            with scope_cm as active_scope:
                scope = active_scope
                if self._func is None:
                    raise RuntimeError(f"No callable bound to InspectionModule '{self.profile.profile_id}'")

                try:
                    result = self._func(safe_wm, **kwargs)
                except TypeError:
                    try:
                        result = self._func(**kwargs)
                    except TypeError:
                        kw_no_pid = {k: v for k, v in kwargs.items() if k != "pid"}
                        try:
                            result = self._func(ctx.pid, **kw_no_pid)
                        except TypeError:
                            result = self._func(ctx.pid)

            if not isinstance(result, dict):
                result = {"success": True, "value": result}

            lat_us = (time.monotonic_ns() - t0_ns) / 1000.0
            is_fail = (
                result.get("success") is False
                or bool(result.get("error"))
                or result.get("status") in ("READ_ERROR", "TIMEOUT", "RESTRICTED", "FAILED")
            )
            is_unavail = (
                bool(result.get("unavailable"))
                or result.get("status") in ("RESTRICTED", "UNAVAILABLE", "SYMBOL_NOT_FOUND")
                or result.get("error_code") in ("RESTRICTED", "SYMBOL_NOT_FOUND", "CAPABILITY_UNAVAILABLE")
            )

            if result.get("status") == "UNKNOWN_BYTE_COST_REJECTED" or result.get("accounting_status") == "FAILED":
                out = dict(result)
                out.setdefault("profile_id", self.profile.profile_id)
                out["accounting_status"] = "FAILED"
                out["success"] = False
                out["abstained"] = True
                return out

            # Validate numeric byte fields if present in result
            raw_meas = result.get("measured_bytes_read")
            raw_est = result.get("estimated_bytes_read")
            raw_bytes = result.get("bytes_read")

            for name, v in [("measured_bytes_read", raw_meas), ("estimated_bytes_read", raw_est), ("bytes_read", raw_bytes)]:
                if v is not None:
                    if isinstance(v, bool) or not isinstance(v, (int, float)):
                        raise ValueError(f"Invalid numeric value in result for {name}: {repr(v)}")
                    if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                        raise ValueError(f"Invalid numeric value (NaN/Inf) in result for {name}: {repr(v)}")
                    if v < 0:
                        raise ValueError(f"Invalid numeric value (negative) in result for {name}: {repr(v)}")

            meas_b = validate_non_negative_int(raw_meas)
            est_b = validate_non_negative_int(raw_est)
            bytes_b = validate_non_negative_int(raw_bytes)

            actual_op_id = result.get("operation_id") or op_id

            # Authoritative single-writer accounting check:
            if ctx.budget_tracker.is_operation_committed(actual_op_id):
                comm_rec = ctx.budget_tracker.get_committed_record(actual_op_id)
                read_accounting = comm_rec.to_dict()
            elif scope is not None and getattr(scope, "reads_count", 0) > 0:
                # Inner function called tracker.record_read() through active operation scope
                comm_rec = scope.finalize(success=not is_fail)
                read_accounting = comm_rec.to_dict() if comm_rec else {
                    "operation_id": actual_op_id,
                    "measured_bytes_read": scope.measured_bytes_read,
                    "estimated_bytes_read": scope.estimated_bytes_read,
                    "charged_bytes": scope.charged_bytes,
                    "latency_us": scope.latency_us,
                    "accounting_status": "COMMITTED",
                    "measurement_type": "MEASURED" if scope.measured_bytes_read else "ESTIMATED",
                }
            else:
                # The tracker has NOT been charged for this operation yet, regardless of any
                # unverified dictionary flags like accounting_status="COMMITTED" or already_budget_accounted=True!
                is_missing = (
                    meas_b is None
                    and est_b is None
                    and bytes_b is None
                    and raw_meas is None
                    and raw_est is None
                    and raw_bytes is None
                    and result.get("measurement_type") not in ("CACHE_HIT", "ZERO_BYTES")
                )

                if is_missing:
                    if ctx.budget_tracker.limits.reject_unknown_byte_cost:
                        ctx.budget_tracker.record_rejection(self.profile.profile_id, "UNKNOWN_BYTE_COST_REJECTED")
                        return {
                            "success": False,
                            "status": "UNKNOWN_BYTE_COST_REJECTED",
                            "result_category": "UNKNOWN_BYTE_COST_REJECTED",
                            "error": "UNKNOWN_BYTE_COST_REJECTED: observation byte cost is unknown and strict cost accounting is enabled",
                            "error_code": "UNKNOWN_BYTE_COST_REJECTED",
                            "abstained": True,
                            "profile_id": self.profile.profile_id,
                            "measured_bytes_read": None,
                            "estimated_bytes_read": 0,
                            "charged_bytes": 0,
                            "measurement_type": "UNKNOWN",
                            "accounting_owner": "MODULE_INTERNAL",
                            "accounting_status": "FAILED",
                            "operation_id": actual_op_id,
                        }
                    fallback_charge = eff_est_bytes if (eff_est_bytes is not None and eff_est_bytes > 0) else ctx.budget_tracker.limits.conservative_unknown_bytes
                    record = ObservationAccountingRecord(
                        operation_id=actual_op_id,
                        accounting_owner=result.get("accounting_owner") or "MODULE_INTERNAL",
                        measured_bytes_read=None,
                        estimated_bytes_read=fallback_charge,
                        latency_us=lat_us,
                        measurement_type="UNKNOWN",
                    )
                else:
                    if meas_b is not None and est_b is not None:
                        eff_m = meas_b
                        eff_e = est_b
                    elif meas_b is not None:
                        eff_m = meas_b
                        eff_e = 0
                    elif est_b is not None:
                        eff_m = None
                        eff_e = est_b
                    elif bytes_b is not None:
                        if result.get("measurement_type") == "ESTIMATED":
                            eff_m = None
                            eff_e = bytes_b
                        else:
                            eff_m = bytes_b
                            eff_e = 0
                    else:
                        eff_m = None
                        eff_e = 0
                    if result.get("measurement_type") == "CACHE_HIT":
                        m_type = "CACHE_HIT"
                        eff_m = 0
                        eff_e = 0
                    elif eff_m is not None and eff_m > 0 and eff_e > 0:
                        m_type = "MIXED"
                    elif eff_m is not None and eff_m > 0:
                        m_type = "MEASURED"
                    elif eff_e > 0:
                        m_type = "ESTIMATED"
                    elif eff_m == 0 or (eff_e == 0 and eff_m is None):
                        m_type = "ZERO_BYTES"
                    else:
                        m_type = "MEASURED"

                    record = ObservationAccountingRecord(
                        operation_id=actual_op_id,
                        accounting_owner=result.get("accounting_owner") or "MODULE_INTERNAL",
                        measured_bytes_read=eff_m,
                        estimated_bytes_read=eff_e,
                        latency_us=lat_us,
                        measurement_type=m_type,
                    )

                ok = ctx.budget_tracker.commit_transaction(
                    record,
                    profile_id=self.profile.profile_id,
                    profile_ceiling=self.profile.budget_ceiling,
                    is_failure=is_fail,
                    stop_ms=float(result.get("stop_duration_ms", 0.0)),
                )
                if not ok:
                    return {
                        "success": False,
                        "status": "BUDGET_EXHAUSTED",
                        "result_category": "BUDGET_EXHAUSTED",
                        "error": f"Observation aborted: budget exhausted ({ctx.budget_tracker.exhaustion_reason})",
                        "error_code": "BUDGET_EXHAUSTED",
                        "abstained": True,
                        "profile_id": self.profile.profile_id,
                        "measured_bytes_read": record.measured_bytes_read,
                        "estimated_bytes_read": record.estimated_bytes_read,
                        "charged_bytes": 0,
                        "accounting_owner": "MODULE_INTERNAL",
                        "accounting_status": "FAILED",
                        "operation_id": actual_op_id,
                    }
                read_accounting = record.to_dict()

            ctx.budget_tracker.record_sample(profile_id=self.profile.profile_id)

            out = dict(result)
            out.setdefault("profile_id", self.profile.profile_id)
            out["operation_id"] = read_accounting["operation_id"]
            out["measured_bytes_read"] = read_accounting["measured_bytes_read"]
            out["estimated_bytes_read"] = read_accounting.get("estimated_bytes_read", 0)
            out["charged_bytes"] = read_accounting["charged_bytes"]
            out["measurement_type"] = read_accounting.get("measurement_type", "MEASURED")
            out["used_conservative_byte_estimate"] = bool(read_accounting.get("estimated_bytes_read", 0) > 0)
            out["observation_latency_us"] = round(lat_us, 2)
            out["accounting_owner"] = read_accounting.get("accounting_owner", "MODULE_INTERNAL")
            out["accounting_status"] = read_accounting.get("accounting_status", "COMMITTED")

            # Post-execution profile ceiling check
            prof_ok, prof_reason = ctx.budget_tracker.check_profile_ceiling(
                self.profile.profile_id, self.profile.budget_ceiling
            )
            if not prof_ok:
                out["profile_ceiling_exceeded"] = True
                out["profile_ceiling_reason"] = prof_reason

            if is_unavail:
                out["result_category"] = "OBSERVATION_UNAVAILABLE"
                out["abstained"] = True
            elif is_fail:
                out["result_category"] = "OBSERVATION_FAILED"
                out["abstained"] = True

            return out
        except Exception as exc:
            lat_us = (time.monotonic_ns() - t0_ns) / 1000.0
            exc_op_id = getattr(exc, "operation_id", op_id)

            # Check if exception already committed accounting authoritatively
            if ctx.budget_tracker.is_operation_committed(exc_op_id):
                comm_rec = ctx.budget_tracker.get_committed_record(exc_op_id)
                read_acct = comm_rec.to_dict()
            elif scope is not None and getattr(scope, "reads_count", 0) > 0:
                comm_rec = scope.finalize(success=False, exc=exc)
                read_acct = comm_rec.to_dict() if comm_rec else {
                    "operation_id": exc_op_id,
                    "measured_bytes_read": scope.measured_bytes_read,
                    "estimated_bytes_read": scope.estimated_bytes_read,
                    "charged_bytes": scope.charged_bytes,
                    "latency_us": scope.latency_us,
                    "accounting_status": "COMMITTED",
                    "measurement_type": "MEASURED" if scope.measured_bytes_read else "ESTIMATED",
                }
            else:
                raw_meas = getattr(exc, "measured_bytes_read", None)
                raw_est = getattr(exc, "estimated_bytes_read", None)
                raw_bytes = getattr(exc, "bytes_read", None)

                for name, v in [("measured_bytes_read", raw_meas), ("estimated_bytes_read", raw_est), ("bytes_read", raw_bytes)]:
                    if v is not None:
                        if isinstance(v, bool) or not isinstance(v, (int, float)):
                            raise ValueError(f"Invalid numeric value on exception for {name}: {repr(v)}")
                        if isinstance(v, float) and (math.isnan(v) or math.isinf(v)):
                            raise ValueError(f"Invalid numeric value (NaN/Inf) on exception for {name}: {repr(v)}")
                        if v < 0:
                            raise ValueError(f"Invalid numeric value (negative) on exception for {name}: {repr(v)}")

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
                    if ctx.budget_tracker.limits.reject_unknown_byte_cost:
                        ctx.budget_tracker.record_rejection(self.profile.profile_id, "UNKNOWN_BYTE_COST_REJECTED")
                        record = ObservationAccountingRecord(
                            operation_id=exc_op_id,
                            accounting_owner="MODULE_INTERNAL",
                            measured_bytes_read=None,
                            estimated_bytes_read=0,
                            latency_us=lat_us,
                            accounting_status="FAILED",
                            measurement_type="UNKNOWN",
                        )
                    else:
                        fallback_charge = eff_est_bytes if (eff_est_bytes is not None and eff_est_bytes > 0) else ctx.budget_tracker.limits.conservative_unknown_bytes
                        record = ObservationAccountingRecord(
                            operation_id=exc_op_id,
                            accounting_owner="MODULE_INTERNAL",
                            measured_bytes_read=None,
                            estimated_bytes_read=fallback_charge,
                            latency_us=lat_us,
                            measurement_type="UNKNOWN",
                        )
                        ctx.budget_tracker.commit_transaction(
                            record,
                            profile_id=self.profile.profile_id,
                            profile_ceiling=self.profile.budget_ceiling,
                            is_failure=True,
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
                        if getattr(exc, "measurement_type", None) == "ESTIMATED":
                            eff_m = None
                            eff_e = bytes_val
                        else:
                            eff_m = bytes_val
                            eff_e = 0
                    else:
                        eff_m = None
                        eff_e = 0
                    record = ObservationAccountingRecord(
                        operation_id=exc_op_id,
                        accounting_owner="MODULE_INTERNAL",
                        measured_bytes_read=eff_m,
                        estimated_bytes_read=eff_e,
                        latency_us=lat_us,
                        measurement_type="MIXED" if (eff_m and eff_m > 0 and eff_e and eff_e > 0) else ("MEASURED" if (eff_m and eff_m > 0) else "ESTIMATED"),
                    )
                    ctx.budget_tracker.commit_transaction(
                        record,
                        profile_id=self.profile.profile_id,
                        profile_ceiling=self.profile.budget_ceiling,
                        is_failure=True,
                    )
                read_acct = record.to_dict()

            ctx.budget_tracker.record_sample(profile_id=self.profile.profile_id)
            return {
                "success": False,
                "result_category": "OBSERVATION_FAILED",
                "error": str(exc),
                "error_code": type(exc).__name__,
                "abstained": True,
                "profile_id": self.profile.profile_id,
                "operation_id": read_acct["operation_id"],
                "measured_bytes_read": read_acct["measured_bytes_read"],
                "estimated_bytes_read": read_acct.get("estimated_bytes_read", 0),
                "charged_bytes": read_acct["charged_bytes"],
                "measurement_type": read_acct.get("measurement_type", "ESTIMATED"),
                "used_conservative_byte_estimate": bool(read_acct.get("estimated_bytes_read", 0) > 0),
                "accounting_owner": read_acct.get("accounting_owner", "MODULE_INTERNAL"),
                "accounting_status": read_acct.get("accounting_status", "COMMITTED"),
            }


class InspectionModuleRegistry:
    """Registry of pre-authorized read-only inspection modules."""

    def __init__(self):
        self._modules: Dict[str, InspectionModule] = {}

    def register(self, module: InspectionModule) -> None:
        self._modules[module.profile.profile_id] = module

    def get(self, profile_id: str) -> Optional[InspectionModule]:
        return self._modules.get(profile_id)

    def list_modules(self, domain: Optional[str] = None) -> List[InspectionModule]:
        mods = list(self._modules.values())
        if domain:
            mods = [m for m in mods if m.profile.domain == domain]
        return sorted(mods, key=lambda m: (-m.profile.priority, m.profile.profile_id))

    def list_profiles(self, domain: Optional[str] = None) -> List[InspectionProfile]:
        profiles = [m.profile for m in self._modules.values()]
        if domain:
            profiles = [p for p in profiles if p.domain == domain]
        # Deterministic sorting: priority DESC, then profile_id ASC
        return sorted(profiles, key=lambda p: (-p.priority, p.profile_id))

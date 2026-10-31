"""Declarative Inspection Profiles and Pre-authorized Read-Only Adapters.

Defines modular, reusable inspection profiles with strict contracts:
- Domain separation (CONCURRENCY, MEMORY, IPC, HEAP, INTEGRITY, TEMPORAL, GENERIC)
- Pre-authorized read-only adapters (Zero target writes / mutations)
- Explicit budget ceilings per inspection profile enforced before and after execution
- No silent fabrication of measured byte counts
"""

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
import time
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Union

from .observation_budget import ObservationBudgetTracker
from .target_adapter import TargetExecutionAdapter, LocalTargetAdapter, RemoteSshTargetAdapter


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

    def enforce_read_only(self) -> None:
        """Verifies that the context and parameters are strictly read-only."""
        if self.parameters.get("allow_mutation") or self.parameters.get("write_memory"):
            raise PermissionError("InspectionContext strictly forbids target memory or state mutation.")


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
                "budget_rejected": True,
                "result_category": "BUDGET_REJECTED",
                "error": f"Inspection aborted before execution: observation budget exceeded ({reject_reason})",
                "error_code": "BUDGET_EXHAUSTED",
                "abstained": True,
                "profile_id": self.profile.profile_id,
                "estimated_bytes": eff_est_bytes,
            }

        t0_ns = time.monotonic_ns()
        kwargs = dict(self._arg_mapper(ctx))
        # Strip internal budget estimation hints from downstream tool kwargs
        for meta_key in ("estimated_bytes", "estimated_latency_ms", "estimated_samples", "estimated_stop_ms"):
            kwargs.pop(meta_key, None)

        try:
            if self._func is None:
                raise RuntimeError(f"No callable bound to InspectionModule '{self.profile.profile_id}'")

            try:
                result = self._func(watch_manager, **kwargs)
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

            # Never fabricate measured bytes_read=4096 when bytes_read is not reported by the tool
            raw_measured_bytes = result.get("bytes_read")
            measured_bytes = (
                int(raw_measured_bytes)
                if (raw_measured_bytes is not None and not isinstance(raw_measured_bytes, bool) and isinstance(raw_measured_bytes, (int, float)) and raw_measured_bytes >= 0)
                else None
            )

            read_accounting = ctx.budget_tracker.record_read(
                bytes_read=measured_bytes,
                latency_us=lat_us,
                stop_ms=float(result.get("stop_duration_ms", 0.0)),
                is_failure=is_fail,
                conservative_estimate_bytes=eff_est_bytes,
                profile_id=self.profile.profile_id,
                profile_ceiling=self.profile.budget_ceiling,
            )
            ctx.budget_tracker.record_sample(profile_id=self.profile.profile_id)

            out = dict(result)
            out.setdefault("profile_id", self.profile.profile_id)
            out["measured_bytes_read"] = read_accounting["measured_bytes_read"]
            out["charged_bytes"] = read_accounting["charged_bytes"]
            out["used_conservative_byte_estimate"] = read_accounting["used_conservative_byte_estimate"]
            out["observation_latency_us"] = round(lat_us, 2)

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
            ctx.budget_tracker.record_read(
                bytes_read=0,
                latency_us=lat_us,
                is_failure=True,
                conservative_estimate_bytes=0,
                profile_id=self.profile.profile_id,
                profile_ceiling=self.profile.budget_ceiling,
            )
            ctx.budget_tracker.record_sample(profile_id=self.profile.profile_id)
            return {
                "success": False,
                "result_category": "OBSERVATION_FAILED",
                "error": str(exc),
                "error_code": type(exc).__name__,
                "abstained": True,
                "profile_id": self.profile.profile_id,
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

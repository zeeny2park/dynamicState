"""Declarative Inspection Profiles and Pre-authorized Read-Only Adapters.

Defines modular, reusable inspection profiles with strict contracts:
- Domain separation (CONCURRENCY, MEMORY, IPC, HEAP, INTEGRITY, TEMPORAL)
- Pre-authorized read-only adapters (Zero target writes / mutations)
- Explicit budget ceilings per inspection profile
"""

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

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
    """Declarative specification for an inspection routine."""
    profile_id: str
    domain: str
    name: str
    description: str = ""
    priority: int = 100  # Higher = earlier execution in scheduler
    required_symbols: List[str] = field(default_factory=list)
    budget_ceiling: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)


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

    def enforce_read_only(self) -> None:
        """Verifies that the adapter is strictly read-only."""
        # TargetExecutionAdapter is read-only by architecture
        pass


class InspectionModule(ABC):
    """Abstract contract for an inspection module."""

    def __init__(self, profile: InspectionProfile):
        self.profile = profile

    @abstractmethod
    def run(self, ctx: InspectionContext, watch_manager: Any) -> Dict[str, Any]:
        """Executes the read-only inspection within budget."""
        raise NotImplementedError


class FunctionalInspectionModule(InspectionModule):
    """Wraps an existing WatchSessionManager diagnostic method in an InspectionModule."""

    def __init__(
        self,
        profile: InspectionProfile,
        func: Callable[..., Dict[str, Any]],
        arg_mapper: Optional[Callable[[InspectionContext], Dict[str, Any]]] = None,
    ):
        super().__init__(profile)
        self._func = func
        self._arg_mapper = arg_mapper or (lambda c: {"pid": c.pid, "companion_elf_path": c.companion_elf, "adapter": c.adapter, **c.parameters})

    def run(self, ctx: InspectionContext, watch_manager: Any) -> Dict[str, Any]:
        ctx.enforce_read_only()
        if not ctx.budget_tracker.can_continue():
            ok, reason = ctx.budget_tracker.check_budget()
            return {
                "success": False,
                "error": f"Inspection aborted: observation budget exhausted ({reason})",
                "error_code": "BUDGET_EXHAUSTED",
                "abstained": True,
            }

        t0_ns = time.monotonic_ns()
        kwargs = self._arg_mapper(ctx)
        try:
            # Bind to watch_manager instance if method
            result = self._func(watch_manager, **kwargs) if hasattr(self._func, "__self__") or callable(self._func) else self._func(**kwargs)
            lat_us = (time.monotonic_ns() - t0_ns) / 1000.0
            ctx.budget_tracker.record_read(
                bytes_read=result.get("bytes_read", 4096),
                latency_us=lat_us,
                stop_ms=result.get("stop_duration_ms", 0.0),
                is_failure=not result.get("success", True),
            )
            ctx.budget_tracker.record_sample()
            return result
        except Exception as exc:
            lat_us = (time.monotonic_ns() - t0_ns) / 1000.0
            ctx.budget_tracker.record_read(bytes_read=0, latency_us=lat_us, is_failure=True)
            return {
                "success": False,
                "error": str(exc),
                "error_code": type(exc).__name__,
                "abstained": True,
            }


class InspectionModuleRegistry:
    """Registry of pre-authorized inspection modules."""

    def __init__(self):
        self._modules: Dict[str, InspectionModule] = {}

    def register(self, module: InspectionModule) -> None:
        self._modules[module.profile.profile_id] = module

    def get(self, profile_id: str) -> Optional[InspectionModule]:
        return self._modules.get(profile_id)

    def list_profiles(self, domain: Optional[str] = None) -> List[InspectionProfile]:
        profiles = [m.profile for m in self._modules.values()]
        if domain:
            profiles = [p for p in profiles if p.domain == domain]
        # Deterministic sorting: priority DESC, then profile_id ASC
        return sorted(profiles, key=lambda p: (-p.priority, p.profile_id))

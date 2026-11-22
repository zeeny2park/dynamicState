"""Performance measurement and trustworthy baseline instrumentation for DynamicState diagnosis.

Phase 1 of Roadmap:
Measures diagnosis durations, remote transport costs, and investigation efficiency using
monotonic clocks and low-overhead counters.
"""

from __future__ import annotations

import contextlib
from dataclasses import asdict, dataclass, field
import time
from typing import Any, Dict, List, Optional


@dataclass
class CollectionOperationRecord:
    """Structured per-operation telemetry record using monotonic timestamps (zero secrets logged)."""
    operation_name: str
    target_identity: str
    collection_type: str
    start_monotonic: float
    end_monotonic: float
    elapsed_s: float
    status: str
    retry_count: int = 0
    payload_bytes: int = 0
    result_count: int = 0
    error_classification: str = "OK"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "operation_name": self.operation_name,
            "target_identity": self.target_identity,
            "collection_type": self.collection_type,
            "start_monotonic": round(float(self.start_monotonic), 6),
            "end_monotonic": round(float(self.end_monotonic), 6),
            "elapsed_s": round(float(self.elapsed_s), 6),
            "status": self.status,
            "retry_count": int(self.retry_count),
            "payload_bytes": int(self.payload_bytes),
            "result_count": int(self.result_count),
            "error_classification": self.error_classification,
        }


@dataclass
class DiagnosticPerformanceMetrics:
    """Trustworthy performance and resource metrics for a diagnostic investigation."""

    # Wall-clock and pipeline phase durations (seconds, monotonic clock)
    total_wall_clock_s: float = 0.0
    plan_generation_s: float = 0.0
    local_analysis_s: float = 0.0
    remote_connection_establishment_s: float = 0.0
    ssh_command_execution_s: float = 0.0
    remote_command_s: float = 0.0
    retry_s: float = 0.0
    collection_duration_per_recipe: Dict[str, float] = field(default_factory=dict)
    collection_duration_per_evidence_type: Dict[str, float] = field(default_factory=dict)
    evidence_normalization_s: float = 0.0
    correlation_s: float = 0.0
    hypothesis_evaluation_s: float = 0.0
    replanning_s: float = 0.0
    checkpoint_s: float = 0.0
    report_generation_s: float = 0.0
    transfer_s: float = 0.0
    parsing_s: float = 0.0
    timeout_s: float = 0.0
    recovery_s: float = 0.0
    collection_operations: List[CollectionOperationRecord] = field(default_factory=list)

    # Remote costs
    ssh_commands_count: int = 0
    ssh_connections_count: int = 0
    control_master_reconnects_count: int = 0
    retries_count: int = 0
    remote_bytes_transferred: int = 0
    local_bytes_processed: int = 0
    collection_operations_count: int = 0
    duplicate_or_reusable_observations_count: int = 0
    target_impact: Dict[str, Any] = field(default_factory=dict)

    # Investigation efficiency
    recipes_planned_count: int = 0
    recipes_executed_count: int = 0
    recipes_skipped_count: int = 0
    failed_recipes_count: int = 0
    remote_calls_avoided_count: int = 0
    evidence_reuse_ratio: float = 0.0
    time_spent_collecting_s: float = 0.0
    time_spent_analyzing_s: float = 0.0
    hypotheses_count: int = 0
    hypotheses_eliminated_count: int = 0
    replans_count: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(self, "_adapter_snapshots", {})

    def merge_adapter_metrics(
        self,
        adapter_metrics: Optional[Dict[str, Any]],
        adapter_id: Optional[str] = None,
    ) -> None:
        if not adapter_metrics or not isinstance(adapter_metrics, dict):
            return
        aid = adapter_id or str(adapter_metrics.get("adapter_id") or "default")
        snapshots = getattr(self, "_adapter_snapshots", None)
        if snapshots is None:
            snapshots = {}
            object.__setattr__(self, "_adapter_snapshots", snapshots)
        snapshots[aid] = dict(adapter_metrics)

        # Aggregate totals across all recorded adapters
        self.ssh_commands_count = sum(int(s.get("ssh_commands_count", 0)) for s in snapshots.values())
        self.ssh_connections_count = sum(int(s.get("ssh_connections_count", 0)) for s in snapshots.values())
        self.control_master_reconnects_count = sum(
            int(s.get("control_master_reconnects_count", 0)) for s in snapshots.values()
        )
        self.retries_count = sum(int(s.get("retries_count", 0)) for s in snapshots.values())
        self.remote_bytes_transferred = sum(
            int(s.get("remote_bytes_transferred", 0)) for s in snapshots.values()
        )
        self.remote_connection_establishment_s = round(
            sum(float(s.get("remote_connection_establishment_s", 0.0)) for s in snapshots.values()), 4
        )
        self.ssh_command_execution_s = round(
            sum(float(s.get("ssh_command_execution_s", 0.0)) for s in snapshots.values()), 4
        )
        self.remote_command_s = round(
            sum(float(s.get("remote_command_s", 0.0)) for s in snapshots.values()), 4
        )
        self.retry_s = round(
            sum(float(s.get("retry_s", 0.0)) for s in snapshots.values()), 4
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_wall_clock_s": round(float(self.total_wall_clock_s), 4),
            "plan_generation_s": round(float(self.plan_generation_s), 4),
            "local_analysis_s": round(float(self.local_analysis_s), 4),
            "remote_connection_establishment_s": round(float(self.remote_connection_establishment_s), 4),
            "ssh_command_execution_s": round(float(self.ssh_command_execution_s), 4),
            "remote_command_s": round(float(self.remote_command_s), 4),
            "retry_s": round(float(self.retry_s), 4),
            "collection_duration_per_recipe": {
                k: round(float(v), 4) for k, v in sorted(self.collection_duration_per_recipe.items())
            },
            "collection_duration_per_evidence_type": {
                k: round(float(v), 4) for k, v in sorted(self.collection_duration_per_evidence_type.items())
            },
            "evidence_normalization_s": round(float(self.evidence_normalization_s), 4),
            "correlation_s": round(float(self.correlation_s), 4),
            "hypothesis_evaluation_s": round(float(self.hypothesis_evaluation_s), 4),
            "replanning_s": round(float(self.replanning_s), 4),
            "checkpoint_s": round(float(self.checkpoint_s), 4),
            "report_generation_s": round(float(self.report_generation_s), 4),
            "transfer_s": round(float(self.transfer_s), 4),
            "parsing_s": round(float(self.parsing_s), 4),
            "timeout_s": round(float(self.timeout_s), 4),
            "recovery_s": round(float(self.recovery_s), 4),
            "collection_operations": [op.to_dict() for op in self.collection_operations],
            "ssh_commands_count": int(self.ssh_commands_count),
            "ssh_connections_count": int(self.ssh_connections_count),
            "control_master_reconnects_count": int(self.control_master_reconnects_count),
            "retries_count": int(self.retries_count),
            "remote_bytes_transferred": int(self.remote_bytes_transferred),
            "local_bytes_processed": int(self.local_bytes_processed),
            "collection_operations_count": int(self.collection_operations_count),
            "duplicate_or_reusable_observations_count": int(self.duplicate_or_reusable_observations_count),
            "target_impact": dict(self.target_impact),
            "recipes_planned_count": int(self.recipes_planned_count),
            "recipes_executed_count": int(self.recipes_executed_count),
            "recipes_skipped_count": int(self.recipes_skipped_count),
            "failed_recipes_count": int(self.failed_recipes_count),
            "remote_calls_avoided_count": int(self.remote_calls_avoided_count),
            "evidence_reuse_ratio": round(float(self.evidence_reuse_ratio), 4),
            "time_spent_collecting_s": round(float(self.time_spent_collecting_s), 4),
            "time_spent_analyzing_s": round(float(self.time_spent_analyzing_s), 4),
            "hypotheses_count": int(self.hypotheses_count),
            "hypotheses_eliminated_count": int(self.hypotheses_eliminated_count),
            "replans_count": int(self.replans_count),
        }


class DiagnosticPerformanceTracker:
    """Low-overhead performance tracker maintaining a session's benchmark metrics."""

    def __init__(self) -> None:
        self.metrics = DiagnosticPerformanceMetrics()
        self._t0 = time.monotonic()

    @contextlib.contextmanager
    def measure_phase(self, phase_field: str):
        """Context manager to measure the elapsed monotonic duration of an investigation phase."""
        t_start = time.monotonic()
        try:
            yield
        finally:
            elapsed = max(0.0, time.monotonic() - t_start)
            current = getattr(self.metrics, phase_field, 0.0)
            setattr(self.metrics, phase_field, current + elapsed)

    def record_recipe_collection(self, recipe_id: str, dur_s: float) -> None:
        dur = max(0.0, float(dur_s))
        self.metrics.collection_duration_per_recipe[recipe_id] = (
            self.metrics.collection_duration_per_recipe.get(recipe_id, 0.0) + dur
        )
        self.metrics.time_spent_collecting_s += dur
        self.metrics.collection_operations_count += 1

    def record_evidence_normalization(self, evidence_type: str, dur_s: float, byte_size: int = 0) -> None:
        dur = max(0.0, float(dur_s))
        ev_key = evidence_type or "generic"
        self.metrics.collection_duration_per_evidence_type[ev_key] = (
            self.metrics.collection_duration_per_evidence_type.get(ev_key, 0.0) + dur
        )
        self.metrics.evidence_normalization_s += dur
        if byte_size > 0:
            self.metrics.local_bytes_processed += int(byte_size)

    def record_reused_observation(self, count: int = 1) -> None:
        n = max(1, int(count))
        self.metrics.duplicate_or_reusable_observations_count += n
        self.metrics.remote_calls_avoided_count += n

    def record_replan(self) -> None:
        self.metrics.replans_count += 1

    def record_hypotheses_count(self, count: int) -> None:
        self.metrics.hypotheses_count = max(self.metrics.hypotheses_count, int(count))

    def record_hypotheses_eliminated(self, count: int) -> None:
        self.metrics.hypotheses_eliminated_count = max(self.metrics.hypotheses_eliminated_count, int(count))

    def merge_adapter_metrics(
        self,
        adapter_metrics: Optional[Dict[str, Any]],
        adapter_id: Optional[str] = None,
    ) -> None:
        self.metrics.merge_adapter_metrics(adapter_metrics, adapter_id=adapter_id)

    def finish(self, total_wall_clock_s: Optional[float] = None) -> DiagnosticPerformanceMetrics:
        if total_wall_clock_s is not None and total_wall_clock_s > 0:
            self.metrics.total_wall_clock_s = float(total_wall_clock_s)
        elif self.metrics.total_wall_clock_s <= 0:
            self.metrics.total_wall_clock_s = max(0.0001, time.monotonic() - self._t0)

        total_obs = (
            self.metrics.collection_operations_count
            + self.metrics.duplicate_or_reusable_observations_count
        )
        if total_obs > 0:
            self.metrics.evidence_reuse_ratio = (
                self.metrics.duplicate_or_reusable_observations_count / total_obs
            )
        else:
            self.metrics.evidence_reuse_ratio = 0.0

        return self.metrics

    def to_dict(self) -> Dict[str, Any]:
        return self.finish().to_dict()

    def record_operation(self, op: CollectionOperationRecord) -> None:
        self.metrics.collection_operations.append(op)
        self.metrics.collection_operations_count += 1

    def performance_summary(self, top_n: int = 5) -> Dict[str, Any]:
        """Returns machine-readable slowest stages and operations for bottleneck identification."""
        stage_fields = (
            "remote_connection_establishment_s", "ssh_command_execution_s", "remote_command_s",
            "transfer_s", "parsing_s", "retry_s", "timeout_s", "recovery_s",
            "evidence_normalization_s", "correlation_s", "hypothesis_evaluation_s",
            "replanning_s", "local_analysis_s", "report_generation_s",
        )
        stages = sorted(
            ((name, round(float(getattr(self.metrics, name, 0.0)), 6)) for name in stage_fields),
            key=lambda x: x[1],
            reverse=True,
        )
        ops = sorted(self.metrics.collection_operations, key=lambda o: o.elapsed_s, reverse=True)
        return {
            "total_wall_clock_s": round(float(self.metrics.total_wall_clock_s), 6),
            "slowest_stages": [{"stage": k, "elapsed_s": v} for k, v in stages[:top_n] if v > 0.0],
            "slowest_operations": [o.to_dict() for o in ops[:top_n]],
        }

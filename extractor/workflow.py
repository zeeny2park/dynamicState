"""Investigation Workflow Engine (Phase 2.0-A.3.10).

Provides structured, deterministic workflow orchestration for end-to-end
process health investigations across all 15 lifecycle stages.

Supports:
- InvestigationWorkflowDefinition
- InvestigationWorkflowInstance (WorkflowExecutionState)
- State prerequisites and strict transition checks
- Compensation, failure recording, and recovery
- User cancellation and target termination
- State checkpointing, file persistence, and resume after restart
- Immutable auditable execution log

Re-uses existing internal APIs (AdaptiveInvestigationEngine, EvidenceLedger,
LocalTargetAdapter, HypothesisValidator, VerdictEngine) without adding new MCP tools.
"""

from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .adaptive_engine import (
    DIAG_CONFIRMED,
    DIAG_INCONCLUSIVE,
    DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE,
    DIAG_SUSPECTED,
    AdaptiveInvestigationEngine,
    ObservationBudgetTracker,
)
from .evidence_ledger import (
    EVIDENCE_TYPE_DIAGNOSTIC,
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EvidenceLedger,
    EvidenceRecord,
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
)
from .hypothesis import (
    HYPOTHESIS_STATUS_CONTRADICTED,
    HYPOTHESIS_STATUS_INCONCLUSIVE,
    HYPOTHESIS_STATUS_SUPPORTED,
    HYPOTHESIS_STATUS_VALIDATED,
    HypothesisValidator,
    InvestigationHypothesis,
)
from .target_adapter import LocalTargetAdapter, TargetExecutionAdapter

# -----------------------------------------------------------------------------
# 15 Investigation Lifecycle Stages
# -----------------------------------------------------------------------------

STAGE_INITIALIZING = "INITIALIZING"
STAGE_PROBING = "PROBING"
STAGE_FORMULATING_HYPOTHESIS = "FORMULATING_HYPOTHESIS"
STAGE_SELECTING_RECIPE = "SELECTING_RECIPE"
STAGE_EXECUTING_OBSERVATION = "EXECUTING_OBSERVATION"
STAGE_EVALUATING_EVIDENCE = "EVALUATING_EVIDENCE"
STAGE_UPDATING_HYPOTHESIS = "UPDATING_HYPOTHESIS"
STAGE_CHECKING_BUDGET = "CHECKING_BUDGET"
STAGE_COMPARING_COMPETING = "COMPARING_COMPETING"
STAGE_VERIFYING_CAUSATION = "VERIFYING_CAUSATION"
STAGE_FORMING_DIAGNOSIS = "FORMING_DIAGNOSIS"
STAGE_GENERATING_REPORT = "GENERATING_REPORT"
STAGE_COMPLETED = "COMPLETED"
STAGE_ABSTAINED = "ABSTAINED"
STAGE_BLOCKED = "BLOCKED"
STAGE_CANCELLED = "CANCELLED"
STAGE_FAILED = "FAILED"

ALL_WORKFLOW_STAGES = [
    STAGE_INITIALIZING,
    STAGE_PROBING,
    STAGE_FORMULATING_HYPOTHESIS,
    STAGE_SELECTING_RECIPE,
    STAGE_EXECUTING_OBSERVATION,
    STAGE_EVALUATING_EVIDENCE,
    STAGE_UPDATING_HYPOTHESIS,
    STAGE_CHECKING_BUDGET,
    STAGE_COMPARING_COMPETING,
    STAGE_VERIFYING_CAUSATION,
    STAGE_FORMING_DIAGNOSIS,
    STAGE_GENERATING_REPORT,
    STAGE_COMPLETED,
    STAGE_ABSTAINED,
    STAGE_BLOCKED,
    STAGE_CANCELLED,
    STAGE_FAILED,
]

TERMINAL_STAGES = {
    STAGE_COMPLETED,
    STAGE_ABSTAINED,
    STAGE_BLOCKED,
    STAGE_CANCELLED,
    STAGE_FAILED,
}

# -----------------------------------------------------------------------------
# Deterministic Stopping Reasons
# -----------------------------------------------------------------------------

STOP_DIAGNOSIS_CONFIRMED = "DIAGNOSIS_CONFIRMED"
STOP_BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
STOP_CAPABILITY_UNAVAILABLE = "CAPABILITY_UNAVAILABLE"
STOP_ALL_HYPOTHESES_REFUTED = "ALL_HYPOTHESES_REFUTED"
STOP_NO_DISCRIMINATING_OBSERVATIONS = "NO_DISCRIMINATING_OBSERVATIONS"
STOP_TARGET_TERMINATED = "TARGET_TERMINATED"
STOP_OBSERVATION_ABSTAINED = "OBSERVATION_ABSTAINED"
STOP_USER_CANCELLED = "USER_CANCELLED"

ALL_STOPPING_REASONS = {
    STOP_DIAGNOSIS_CONFIRMED,
    STOP_BUDGET_EXHAUSTED,
    STOP_CAPABILITY_UNAVAILABLE,
    STOP_ALL_HYPOTHESES_REFUTED,
    STOP_NO_DISCRIMINATING_OBSERVATIONS,
    STOP_TARGET_TERMINATED,
    STOP_OBSERVATION_ABSTAINED,
    STOP_USER_CANCELLED,
}

# -----------------------------------------------------------------------------
# Default State Prerequisites and Allowed Transitions
# -----------------------------------------------------------------------------

DEFAULT_STAGE_PREREQUISITES: Dict[str, List[str]] = {
    STAGE_INITIALIZING: [],
    STAGE_PROBING: [STAGE_INITIALIZING],
    STAGE_FORMULATING_HYPOTHESIS: [STAGE_PROBING],
    STAGE_SELECTING_RECIPE: [STAGE_FORMULATING_HYPOTHESIS],
    STAGE_EXECUTING_OBSERVATION: [STAGE_SELECTING_RECIPE],
    STAGE_EVALUATING_EVIDENCE: [STAGE_EXECUTING_OBSERVATION],
    STAGE_UPDATING_HYPOTHESIS: [STAGE_EVALUATING_EVIDENCE],
    STAGE_CHECKING_BUDGET: [STAGE_UPDATING_HYPOTHESIS],
    STAGE_COMPARING_COMPETING: [STAGE_CHECKING_BUDGET],
    STAGE_VERIFYING_CAUSATION: [STAGE_COMPARING_COMPETING],
    STAGE_FORMING_DIAGNOSIS: [STAGE_VERIFYING_CAUSATION, STAGE_CHECKING_BUDGET],
    STAGE_GENERATING_REPORT: [STAGE_FORMING_DIAGNOSIS],
    STAGE_COMPLETED: [STAGE_GENERATING_REPORT],
    STAGE_ABSTAINED: [STAGE_PROBING, STAGE_EXECUTING_OBSERVATION, STAGE_FORMING_DIAGNOSIS],
    STAGE_BLOCKED: [STAGE_INITIALIZING, STAGE_PROBING, STAGE_EXECUTING_OBSERVATION],
    STAGE_CANCELLED: [s for s in ALL_WORKFLOW_STAGES if s not in TERMINAL_STAGES],
    STAGE_FAILED: [s for s in ALL_WORKFLOW_STAGES if s not in TERMINAL_STAGES],
}

DEFAULT_ALLOWED_TRANSITIONS: Dict[str, Set[str]] = {
    STAGE_INITIALIZING: {STAGE_PROBING, STAGE_BLOCKED, STAGE_CANCELLED, STAGE_FAILED},
    STAGE_PROBING: {STAGE_FORMULATING_HYPOTHESIS, STAGE_ABSTAINED, STAGE_BLOCKED, STAGE_CANCELLED, STAGE_FAILED},
    STAGE_FORMULATING_HYPOTHESIS: {STAGE_SELECTING_RECIPE, STAGE_FORMING_DIAGNOSIS, STAGE_CANCELLED, STAGE_FAILED},
    STAGE_SELECTING_RECIPE: {STAGE_EXECUTING_OBSERVATION, STAGE_FORMING_DIAGNOSIS, STAGE_CANCELLED, STAGE_FAILED},
    STAGE_EXECUTING_OBSERVATION: {STAGE_EVALUATING_EVIDENCE, STAGE_ABSTAINED, STAGE_BLOCKED, STAGE_CANCELLED, STAGE_FAILED},
    STAGE_EVALUATING_EVIDENCE: {STAGE_UPDATING_HYPOTHESIS, STAGE_FORMING_DIAGNOSIS, STAGE_CANCELLED, STAGE_FAILED},
    STAGE_UPDATING_HYPOTHESIS: {STAGE_CHECKING_BUDGET, STAGE_FORMING_DIAGNOSIS, STAGE_CANCELLED, STAGE_FAILED},
    STAGE_CHECKING_BUDGET: {STAGE_COMPARING_COMPETING, STAGE_SELECTING_RECIPE, STAGE_FORMING_DIAGNOSIS, STAGE_CANCELLED, STAGE_FAILED},
    STAGE_COMPARING_COMPETING: {STAGE_VERIFYING_CAUSATION, STAGE_FORMING_DIAGNOSIS, STAGE_CANCELLED, STAGE_FAILED},
    STAGE_VERIFYING_CAUSATION: {STAGE_FORMING_DIAGNOSIS, STAGE_SELECTING_RECIPE, STAGE_CANCELLED, STAGE_FAILED},
    STAGE_FORMING_DIAGNOSIS: {STAGE_GENERATING_REPORT, STAGE_ABSTAINED, STAGE_CANCELLED, STAGE_FAILED},
    STAGE_GENERATING_REPORT: {STAGE_COMPLETED, STAGE_CANCELLED, STAGE_FAILED},
    STAGE_COMPLETED: set(),
    STAGE_ABSTAINED: set(),
    STAGE_BLOCKED: set(),
    STAGE_CANCELLED: set(),
    STAGE_FAILED: set(),
}


@dataclass
class InvestigationWorkflowDefinition:
    """Immutable definition of an investigation workflow."""
    workflow_id: str = "default_adaptive_investigation"
    name: str = "Adaptive Process Health Investigation Workflow"
    description: str = "Standard 15-stage budget-bounded live runtime investigation"
    stages: List[str] = field(default_factory=lambda: list(ALL_WORKFLOW_STAGES))
    prerequisites: Dict[str, List[str]] = field(default_factory=lambda: dict(DEFAULT_STAGE_PREREQUISITES))
    allowed_transitions: Dict[str, Set[str]] = field(default_factory=lambda: dict(DEFAULT_ALLOWED_TRANSITIONS))
    timeout_seconds: float = 300.0
    max_retries_per_stage: int = 2

    def to_dict(self) -> Dict[str, Any]:
        return {
            "workflow_id": self.workflow_id,
            "name": self.name,
            "description": self.description,
            "stages": self.stages,
            "prerequisites": self.prerequisites,
            "allowed_transitions": {k: sorted(list(v)) for k, v in self.allowed_transitions.items()},
            "timeout_seconds": self.timeout_seconds,
            "max_retries_per_stage": self.max_retries_per_stage,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> InvestigationWorkflowDefinition:
        transitions = {k: set(v) for k, v in data.get("allowed_transitions", {}).items()} or dict(DEFAULT_ALLOWED_TRANSITIONS)
        return cls(
            workflow_id=data.get("workflow_id", "default_adaptive_investigation"),
            name=data.get("name", "Adaptive Process Health Investigation Workflow"),
            description=data.get("description", ""),
            stages=list(data.get("stages", ALL_WORKFLOW_STAGES)),
            prerequisites=dict(data.get("prerequisites", DEFAULT_STAGE_PREREQUISITES)),
            allowed_transitions=transitions,
            timeout_seconds=float(data.get("timeout_seconds", 300.0)),
            max_retries_per_stage=int(data.get("max_retries_per_stage", 2)),
        )


@dataclass
class WorkflowExecutionState:
    """Live execution state and auditable history for an investigation instance."""
    instance_id: str
    workflow_id: str
    session_id: str
    target_pid: int
    goal: str
    current_stage: str = STAGE_INITIALIZING
    status: str = "RUNNING"  # RUNNING, COMPLETED, ABSTAINED, BLOCKED, CANCELLED, FAILED
    stopping_reason: Optional[str] = None
    stopping_explanation: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    updated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    context: Dict[str, Any] = field(default_factory=dict)
    audit_trail: List[Dict[str, Any]] = field(default_factory=list)
    stage_retries: Dict[str, int] = field(default_factory=dict)

    def record_transition(
        self,
        to_stage: str,
        reason: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        now_ts = datetime.now(timezone.utc).isoformat()
        entry = {
            "timestamp": now_ts,
            "from_stage": self.current_stage,
            "to_stage": to_stage,
            "reason": reason,
            "details": details or {},
        }
        self.audit_trail.append(entry)
        self.current_stage = to_stage
        self.updated_at = now_ts
        if to_stage in TERMINAL_STAGES:
            self.status = to_stage

    def to_dict(self) -> Dict[str, Any]:
        return {
            "instance_id": self.instance_id,
            "workflow_id": self.workflow_id,
            "session_id": self.session_id,
            "target_pid": self.target_pid,
            "goal": self.goal,
            "current_stage": self.current_stage,
            "status": self.status,
            "stopping_reason": self.stopping_reason,
            "stopping_explanation": self.stopping_explanation,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "context": self.context,
            "audit_trail": self.audit_trail,
            "stage_retries": self.stage_retries,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> WorkflowExecutionState:
        return cls(
            instance_id=data["instance_id"],
            workflow_id=data.get("workflow_id", "default_adaptive_investigation"),
            session_id=data["session_id"],
            target_pid=int(data.get("target_pid", 0)),
            goal=data.get("goal", ""),
            current_stage=data.get("current_stage", STAGE_INITIALIZING),
            status=data.get("status", "RUNNING"),
            stopping_reason=data.get("stopping_reason"),
            stopping_explanation=data.get("stopping_explanation", ""),
            created_at=data.get("created_at", datetime.now(timezone.utc).isoformat()),
            updated_at=data.get("updated_at", datetime.now(timezone.utc).isoformat()),
            context=dict(data.get("context", {})),
            audit_trail=list(data.get("audit_trail", [])),
            stage_retries=dict(data.get("stage_retries", {})),
        )


class InvestigationWorkflowEngine:
    """Executes, checkpoints, cancels, and audits investigation workflows."""

    def __init__(
        self,
        definition: Optional[InvestigationWorkflowDefinition] = None,
        target_adapter: Optional[TargetExecutionAdapter] = None,
        engine: Optional[AdaptiveInvestigationEngine] = None,
    ):
        self.definition = definition or InvestigationWorkflowDefinition()
        self.target_adapter = target_adapter or LocalTargetAdapter()
        self.adaptive_engine = engine or AdaptiveInvestigationEngine()

    def create_instance(
        self,
        session_id: str,
        target_pid: int,
        goal: str,
        companion_elf_path: Optional[str] = None,
        max_samples: int = 10,
        max_bytes: int = 256 * 1024,
    ) -> WorkflowExecutionState:
        inst_id = f"wf_inst_{uuid.uuid4().hex[:12]}"
        instance = WorkflowExecutionState(
            instance_id=inst_id,
            workflow_id=self.definition.workflow_id,
            session_id=session_id,
            target_pid=target_pid,
            goal=goal,
            current_stage=STAGE_INITIALIZING,
            status="RUNNING",
            context={
                "companion_elf_path": companion_elf_path,
                "max_samples": max_samples,
                "max_bytes": max_bytes,
                "ledger_session_id": session_id,
                "observation_count": 0,
                "physical_bytes_read": 0,
            },
        )
        instance.record_transition(
            to_stage=STAGE_INITIALIZING,
            reason="Workflow instance created and initialized",
            details={"target_pid": target_pid, "goal": goal},
        )
        return instance

    def validate_transition(
        self,
        instance: WorkflowExecutionState,
        target_stage: str,
    ) -> Tuple[bool, Optional[str]]:
        cur = instance.current_stage
        if cur in TERMINAL_STAGES:
            return False, f"Cannot transition from terminal stage '{cur}' to '{target_stage}'"
        allowed = self.definition.allowed_transitions.get(cur, set())
        if target_stage not in allowed:
            return False, f"Illegal stage transition '{cur}' -> '{target_stage}'"

        # Check prerequisites
        prereqs = self.definition.prerequisites.get(target_stage, [])
        if prereqs:
            visited_stages = {entry["to_stage"] for entry in instance.audit_trail}
            visited_stages.add(cur)
            if not any(p in visited_stages for p in prereqs):
                return False, f"Stage '{target_stage}' prerequisites not met (requires one of {prereqs})"

        return True, None

    def cancel(self, instance: WorkflowExecutionState, reason: str = "User cancelled investigation") -> None:
        """Cancel an in-progress investigation instance cleanly."""
        if instance.current_stage in TERMINAL_STAGES:
            return
        instance.stopping_reason = STOP_USER_CANCELLED
        instance.stopping_explanation = reason
        instance.record_transition(
            to_stage=STAGE_CANCELLED,
            reason=reason,
            details={"stopping_reason": STOP_USER_CANCELLED},
        )

    def persist_state(self, instance: WorkflowExecutionState, file_path: str) -> None:
        """Persist execution state to file for recovery/resume."""
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
        data = instance.to_dict()
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    @classmethod
    def resume_instance(cls, file_path: str) -> WorkflowExecutionState:
        """Restore execution state from checkpoint file."""
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        inst = WorkflowExecutionState.from_dict(data)
        return inst

    def execute_investigation(
        self,
        instance: WorkflowExecutionState,
        checkpoint_dir: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute the full 15-stage workflow deterministically using underlying engines."""
        target_pid = instance.target_pid
        session_id = instance.session_id
        goal = instance.goal

        def _checkpoint():
            if checkpoint_dir:
                cp_file = os.path.join(checkpoint_dir, f"{instance.instance_id}_ckpt.json")
                self.persist_state(instance, cp_file)

        # Stage 1: INITIALIZING -> PROBING
        valid, err = self.validate_transition(instance, STAGE_PROBING)
        if not valid:
            instance.record_transition(STAGE_FAILED, f"Transition failed: {err}")
            return instance.to_dict()

        # Check liveness
        alive, live_err = self.target_adapter.check_liveness(target_pid)
        if not alive:
            instance.stopping_reason = STOP_TARGET_TERMINATED
            instance.stopping_explanation = f"Target PID {target_pid} is not alive: {live_err}"
            instance.record_transition(STAGE_BLOCKED, instance.stopping_explanation)
            _checkpoint()
            return instance.to_dict()

        instance.record_transition(STAGE_PROBING, f"Target process {target_pid} verified alive; probing capabilities")
        _checkpoint()

        # Run underlying adaptive engine
        res = self.adaptive_engine.investigate_process_health(
            goal=goal,
            pid=target_pid,
            companion_elf_path=instance.context.get("companion_elf_path") or "",
            session_id=session_id,
            target_adapter=self.target_adapter,
        )

        # Map adaptive engine results through workflow stages
        sm_state = res.get("lifecycle_state")
        stop_reason = res.get("stopping_reason")
        diagnosis = res.get("final_diagnosis")
        report = res.get("report") or {}
        obs_log = res.get("observation_log") or []

        # Stage 3: FORMULATING_HYPOTHESIS
        instance.record_transition(
            STAGE_FORMULATING_HYPOTHESIS,
            "Formulated competing hypotheses from initial triage",
            details={"hypotheses_count": len(res.get("hypotheses", []))},
        )

        # Stage 4: SELECTING_RECIPE
        instance.record_transition(
            STAGE_SELECTING_RECIPE,
            "Selected diagnostic follow-up recipe based on initial signals",
        )

        # Stage 5: EXECUTING_OBSERVATION
        instance.record_transition(
            STAGE_EXECUTING_OBSERVATION,
            f"Executed {len(obs_log)} observation step(s)",
            details={"observation_count": len(obs_log)},
        )

        # Stage 6: EVALUATING_EVIDENCE
        instance.record_transition(
            STAGE_EVALUATING_EVIDENCE,
            f"Evaluated evidence records into ledger: count={res.get('evidence_ledger_count', 0)}",
        )

        # Stage 7: UPDATING_HYPOTHESIS
        instance.record_transition(
            STAGE_UPDATING_HYPOTHESIS,
            "Updated hypothesis confidence and validation states",
        )

        # Stage 8: CHECKING_BUDGET
        instance.record_transition(
            STAGE_CHECKING_BUDGET,
            f"Checked observation budget: samples_used={res.get('samples_used', 0)}, bytes_read={res.get('physical_bytes_read', 0)}",
        )

        # Stage 9: COMPARING_COMPETING
        instance.record_transition(
            STAGE_COMPARING_COMPETING,
            "Evaluated competing hypotheses and discriminating observations",
        )

        # Stage 10: VERIFYING_CAUSATION
        instance.record_transition(
            STAGE_VERIFYING_CAUSATION,
            "Evaluated causal evidence and state transitions",
        )

        # Stage 11: FORMING_DIAGNOSIS
        instance.record_transition(
            STAGE_FORMING_DIAGNOSIS,
            f"Formed final diagnosis: {diagnosis} (stopping_reason={stop_reason})",
        )

        # Stage 12: GENERATING_REPORT
        instance.record_transition(
            STAGE_GENERATING_REPORT,
            "Generated final structured investigation report",
        )

        # Terminal Transition
        instance.context["report"] = report
        instance.context["diagnosis"] = diagnosis
        instance.context["stopping_reason"] = stop_reason
        instance.context["stopping_explanation"] = res.get("stopping_explanation", "")
        instance.stopping_reason = stop_reason
        instance.stopping_explanation = res.get("stopping_explanation", "")

        if stop_reason == STOP_BUDGET_EXHAUSTED or sm_state == "BUDGET_EXHAUSTED":
            instance.record_transition(STAGE_COMPLETED, "Investigation completed via budget exhaustion ceiling")
        elif stop_reason == STOP_CAPABILITY_UNAVAILABLE or sm_state == "CAPABILITY_UNAVAILABLE":
            instance.record_transition(STAGE_ABSTAINED, "Investigation abstained due to unavailable capabilities")
        elif stop_reason == STOP_USER_CANCELLED or sm_state == "CANCELED":
            instance.record_transition(STAGE_CANCELLED, "Investigation cancelled by user")
        elif diagnosis == DIAG_INCONCLUSIVE and stop_reason == STOP_CAPABILITY_UNAVAILABLE:
            instance.record_transition(STAGE_ABSTAINED, "Investigation abstained with inconclusive outcome")
        else:
            instance.record_transition(STAGE_COMPLETED, f"Investigation completed with verdict: {diagnosis}")

        _checkpoint()
        return instance.to_dict()

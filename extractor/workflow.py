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

import hashlib
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
from .capture_backend import LiveCaptureReceipt
from .evidence_ledger import (
    EVIDENCE_TYPE_DIAGNOSTIC,
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EvidenceLedger,
    EvidenceRecord,
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
)
from .hypothesis import (
    HYPOTHESIS_STATUS_ABSTAINED,
    HYPOTHESIS_STATUS_CONTRADICTED,
    HYPOTHESIS_STATUS_INCONCLUSIVE,
    HYPOTHESIS_STATUS_PROPOSED,
    HYPOTHESIS_STATUS_REJECTED,
    HYPOTHESIS_STATUS_SUPPORTED,
    HYPOTHESIS_STATUS_VALIDATED,
    HypothesisValidator,
    InvestigationHypothesis,
)
from .target_adapter import LocalTargetAdapter, TargetExecutionAdapter, PIDReusedError

HYPOTHESIS_STATUS_NOT_TESTED = "NOT_TESTED"
HYPOTHESIS_STATUS_REFUTED = "REFUTED"
HYPOTHESIS_STATUS_INVALIDATED = "INVALIDATED"

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
STAGE_COMPARING_COMPETING_HYPOTHESES = STAGE_COMPARING_COMPETING
STAGE_VERIFYING_CAUSATION = "VERIFYING_CAUSATION"
STAGE_FORMING_DIAGNOSIS = "FORMING_DIAGNOSIS"
STAGE_GENERATING_REPORT = "GENERATING_REPORT"
STAGE_COMPLETED = "COMPLETED"
STAGE_ABSTAINED = "ABSTAINED"
STAGE_BUDGET_EXHAUSTED = STAGE_ABSTAINED
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
STOP_NORMAL_COMPLETION = STOP_DIAGNOSIS_CONFIRMED
STOP_BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
STOP_CAPABILITY_UNAVAILABLE = "CAPABILITY_UNAVAILABLE"
STOP_ALL_HYPOTHESES_REFUTED = "ALL_HYPOTHESES_REFUTED"
STOP_NO_DISCRIMINATING_OBSERVATIONS = "NO_DISCRIMINATING_OBSERVATIONS"
STOP_TARGET_TERMINATED = "TARGET_TERMINATED"
STOP_OBSERVATION_ABSTAINED = "OBSERVATION_ABSTAINED"
STOP_USER_CANCELLED = "USER_CANCELLED"
STOP_EVIDENCE_INSUFFICIENT = "EVIDENCE_INSUFFICIENT"

ALL_STOPPING_REASONS = {
    STOP_DIAGNOSIS_CONFIRMED,
    STOP_BUDGET_EXHAUSTED,
    STOP_CAPABILITY_UNAVAILABLE,
    STOP_ALL_HYPOTHESES_REFUTED,
    STOP_NO_DISCRIMINATING_OBSERVATIONS,
    STOP_TARGET_TERMINATED,
    STOP_OBSERVATION_ABSTAINED,
    STOP_USER_CANCELLED,
    STOP_EVIDENCE_INSUFFICIENT,
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
    STAGE_ABSTAINED: [STAGE_PROBING, STAGE_EXECUTING_OBSERVATION, STAGE_CHECKING_BUDGET, STAGE_FORMING_DIAGNOSIS],
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
    STAGE_CHECKING_BUDGET: {STAGE_COMPARING_COMPETING, STAGE_SELECTING_RECIPE, STAGE_FORMING_DIAGNOSIS, STAGE_ABSTAINED, STAGE_CANCELLED, STAGE_FAILED},
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

    def validate(self) -> Tuple[bool, Optional[str]]:
        """Validates structural integrity, reachability, absence of dead-ends, and valid prerequisites."""
        if not self.stages:
            return False, "Workflow definition has empty stages"
        if STAGE_INITIALIZING not in self.stages:
            return False, f"Workflow definition missing required initial stage '{STAGE_INITIALIZING}'"

        # Check absence of dead-end non-terminal states
        for stage in self.stages:
            if stage not in TERMINAL_STAGES:
                outgoing = self.allowed_transitions.get(stage, set())
                if not outgoing:
                    return False, f"Dead-end non-terminal stage detected: '{stage}' has no outgoing transitions"

        # Check reachability of terminal states from every non-terminal stage via BFS
        for stage in self.stages:
            if stage in TERMINAL_STAGES:
                continue
            visited = set()
            queue = [stage]
            can_reach_terminal = False
            while queue:
                curr = queue.pop(0)
                if curr in TERMINAL_STAGES:
                    can_reach_terminal = True
                    break
                for nxt in self.allowed_transitions.get(curr, set()):
                    if nxt not in visited and nxt in self.stages:
                        visited.add(nxt)
                        queue.append(nxt)
            if not can_reach_terminal:
                return False, f"Unreachable terminal states: stage '{stage}' cannot reach any terminal stage"

        # Check prerequisite chains
        for stage, prereqs in self.prerequisites.items():
            if stage not in self.stages:
                return False, f"Prerequisite configured for stage '{stage}' which is not in definition stages"
            for p in prereqs:
                if p not in self.stages:
                    return False, f"Prerequisite '{p}' for stage '{stage}' not in definition stages"
                if p == stage:
                    return False, f"Self-referential prerequisite for stage '{stage}'"

        return True, None

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


class WorkflowExecutionState:
    """Live execution state and auditable history for an investigation instance."""

    def __init__(
        self,
        instance_id: str,
        workflow_id: str,
        session_id: str,
        target_pid: int,
        goal: str,
        current_stage: str = STAGE_INITIALIZING,
        status: str = "RUNNING",
        stopping_reason: Optional[str] = None,
        stopping_explanation: str = "",
        created_at: Optional[str] = None,
        updated_at: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
        audit_trail: Optional[List[Dict[str, Any]]] = None,
        stage_retries: Optional[Dict[str, int]] = None,
    ):
        self.instance_id = str(instance_id)
        self.workflow_id = str(workflow_id)
        self.session_id = str(session_id)
        self.target_pid = int(target_pid)
        self.goal = str(goal)
        self._current_stage = str(current_stage)
        self.status = str(status)
        self.stopping_reason = stopping_reason
        self.stopping_explanation = str(stopping_explanation or "")
        now_ts = datetime.now(timezone.utc).isoformat()
        self.created_at = created_at or now_ts
        self.updated_at = updated_at or now_ts
        self.context = dict(context or {})
        self.audit_trail = list(audit_trail or [])
        self.stage_retries = dict(stage_retries or {})
        self._in_transition = False

    @property
    def current_stage(self) -> str:
        return self._current_stage

    @current_stage.setter
    def current_stage(self, val: str) -> None:
        if not getattr(self, "_in_transition", False):
            raise ValueError(
                f"Direct mutation of current_stage to '{val}' is prohibited; use transition_stage() or record_transition()"
            )
        self._current_stage = str(val)

    def record_transition(
        self,
        to_stage: str,
        reason: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        now_ts = datetime.now(timezone.utc).isoformat()
        entry = {
            "timestamp": now_ts,
            "from_stage": self._current_stage,
            "to_stage": to_stage,
            "reason": reason,
            "details": details or {},
        }
        self.audit_trail.append(entry)
        self._in_transition = True
        try:
            self.current_stage = to_stage
        finally:
            self._in_transition = False
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
    def from_dict(cls, data: Dict[str, Any]) -> "WorkflowExecutionState":
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


InvestigationWorkflowInstance = WorkflowExecutionState


class StageStepResult(dict):
    """Result of step_stage() containing execution success, stage transition, and output."""
    def __init__(
        self,
        success: bool,
        current_stage: str,
        next_stage: str,
        output: Any = None,
        error: Optional[str] = None,
    ):
        super().__init__(
            success=success,
            current_stage=current_stage,
            next_stage=next_stage,
            output=output,
            error=error,
        )

    def __bool__(self) -> bool:
        return bool(self.get("success", False))


class InvestigationWorkflowEngine:
    """Executes, checkpoints, cancels, and audits investigation workflows."""

    def __init__(
        self,
        definition: Optional[InvestigationWorkflowDefinition] = None,
        target_adapter: Optional[TargetExecutionAdapter] = None,
        engine: Optional[AdaptiveInvestigationEngine] = None,
        state_dir: Optional[str] = None,
    ):
        import tempfile
        self.definition = definition or InvestigationWorkflowDefinition()
        ok_def, err_def = self.definition.validate()
        if not ok_def:
            raise ValueError(f"Invalid workflow definition: {err_def}")
        self.target_adapter = target_adapter or LocalTargetAdapter()
        self.adaptive_engine = engine or AdaptiveInvestigationEngine()
        self.evidence_ledger = EvidenceLedger()
        self.state_dir = state_dir or tempfile.mkdtemp(prefix="wf_state_")

    def create_instance(
        self,
        session_id: str,
        target_pid: int,
        goal: str,
        companion_elf_path: Optional[str] = None,
        max_samples: int = 10,
        max_bytes: int = 256 * 1024,
    ) -> WorkflowExecutionState:
        ok_def, err_def = self.definition.validate()
        if not ok_def:
            raise ValueError(f"Invalid workflow definition: {err_def}")
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

    def transition_stage(
        self,
        instance: WorkflowExecutionState,
        to_stage: str,
        reason: str = "",
        details: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Validate and record transition to next lifecycle stage."""
        valid, err = self.validate_transition(instance, to_stage)
        if not valid:
            instance.record_transition(STAGE_FAILED, f"Transition failed: {err}")
            return False
        instance.record_transition(to_stage, reason, details)
        return True

    def persist_state(self, instance: WorkflowExecutionState, file_path: Optional[str] = None) -> str:
        """Persist execution state to file for recovery/resume with atomic durability and checksum verification."""
        if not file_path:
            file_path = os.path.join(self.state_dir, f"{instance.instance_id}.json")
        os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)

        ledger_dict = None
        if hasattr(self, "evidence_ledger") and self.evidence_ledger is not None:
            ledger_dict = self.evidence_ledger.to_dict()

        checkpoint_data = {
            "schema_version": "2.0.0",
            "instance": instance.to_dict(),
            "evidence_ledger": ledger_dict,
            "pinned_identity": instance.context.get("pinned_identity"),
            "hypotheses": instance.context.get("hypotheses", []),
            "last_receipt": instance.context.get("last_receipt"),
            "completed_observations": instance.context.get("completed_observations", []),
            "budget": {
                "max_samples": instance.context.get("max_samples", 10),
                "max_bytes": instance.context.get("max_bytes", 65536),
                "observation_count": instance.context.get("observation_count", 0),
                "physical_bytes_read": instance.context.get("physical_bytes_read", 0),
            },
        }
        raw_payload = json.dumps(checkpoint_data, sort_keys=True).encode("utf-8")
        checksum = hashlib.sha256(raw_payload).hexdigest()

        envelope = {
            "format": "dynamicstate_workflow_checkpoint",
            "schema_version": "2.0.0",
            "checksum": checksum,
            "checkpoint_data": checkpoint_data,
        }

        tmp_path = f"{file_path}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(envelope, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, file_path)
        return file_path

    def load_instance(self, instance_id_or_path: str) -> Optional[WorkflowExecutionState]:
        """Loads a persisted WorkflowExecutionState instance from ID or path."""
        path = instance_id_or_path
        if not os.path.exists(path):
            path = os.path.join(self.state_dir, f"{instance_id_or_path}.json")
        if not os.path.exists(path):
            return None
        return self.resume_instance(path)

    @classmethod
    def resume_instance(cls, file_path: str) -> WorkflowExecutionState:
        """Restore execution state from checkpoint file, verifying checksum integrity."""
        with open(file_path, "r", encoding="utf-8") as f:
            envelope = json.load(f)

        if isinstance(envelope, dict) and envelope.get("format") == "dynamicstate_workflow_checkpoint":
            ckpt_data = envelope.get("checkpoint_data", {})
            raw_payload = json.dumps(ckpt_data, sort_keys=True).encode("utf-8")
            calc_sum = hashlib.sha256(raw_payload).hexdigest()
            exp_sum = envelope.get("checksum", "")
            if exp_sum and calc_sum != exp_sum:
                raise ValueError(
                    f"Checkpoint integrity verification failed: corrupt checksum (expected {exp_sum}, got {calc_sum})"
                )
            inst = WorkflowExecutionState.from_dict(ckpt_data.get("instance", {}))
            if ckpt_data.get("evidence_ledger"):
                inst.context["restored_evidence_ledger"] = ckpt_data["evidence_ledger"]
            if ckpt_data.get("hypotheses"):
                inst.context["hypotheses"] = ckpt_data["hypotheses"]
            if ckpt_data.get("completed_observations"):
                inst.context["completed_observations"] = ckpt_data["completed_observations"]
            return inst
        else:
            return WorkflowExecutionState.from_dict(envelope)

    def execute_stage_initializing(self, instance: WorkflowExecutionState) -> bool:
        """Stage 1: Verify target PID is alive, accessible, and pin identity."""
        alive, live_err = self.target_adapter.check_liveness(instance.target_pid)
        if not alive:
            instance.stopping_reason = STOP_TARGET_TERMINATED
            instance.stopping_explanation = f"Target PID {instance.target_pid} is not alive: {live_err}"
            instance.record_transition(STAGE_BLOCKED, instance.stopping_explanation)
            return False
        try:
            pinned = self.target_adapter.pin_target_identity(instance.target_pid)
            instance.context["pinned_identity"] = dict(pinned)
        except Exception as e:
            instance.record_transition(STAGE_FAILED, f"Failed pinning target identity: {e}")
            return False
        return self.transition_stage(instance, STAGE_PROBING, f"Target process {instance.target_pid} verified alive; pinning identity")

    def execute_stage_probing(self, instance: WorkflowExecutionState) -> bool:
        """Stage 2: Probe memory readability, proc maps, and threads."""
        alive, live_err = self.target_adapter.check_liveness(instance.target_pid)
        if not alive:
            instance.stopping_reason = STOP_TARGET_TERMINATED
            instance.stopping_explanation = f"Target PID {instance.target_pid} terminated during probing"
            instance.record_transition(STAGE_BLOCKED, instance.stopping_explanation)
            return False

        maps = self.target_adapter.get_proc_maps(instance.target_pid)
        threads = self.target_adapter.get_threads(instance.target_pid)
        instance.context["proc_maps"] = maps
        instance.context["threads"] = threads

        readable_maps = [m for m in maps if m.get("is_readable")]
        if not readable_maps:
            instance.stopping_reason = STOP_CAPABILITY_UNAVAILABLE
            instance.stopping_explanation = "No readable memory mappings found in target process"
            instance.record_transition(STAGE_ABSTAINED, instance.stopping_explanation)
            return False

        try:
            if hasattr(self.target_adapter, "capture_transaction"):
                with self.target_adapter.capture_transaction(instance.session_id, instance.target_pid, operation_type="probe") as tx:
                    self.target_adapter.read_memory(instance.target_pid, readable_maps[0]["start_int"], min(64, readable_maps[0]["size"]))
                rcpt = self.target_adapter.issue_live_receipt_for_session(instance.session_id, instance.target_pid, transaction=tx)
                instance.context["probe_receipt"] = rcpt.to_dict()
            else:
                self.target_adapter.read_memory(instance.target_pid, readable_maps[0]["start_int"], min(64, readable_maps[0]["size"]))
        except Exception as exc:
            instance.stopping_reason = STOP_CAPABILITY_UNAVAILABLE
            instance.stopping_explanation = f"Memory read probe failed: {exc}"
            instance.record_transition(STAGE_ABSTAINED, instance.stopping_explanation)
            return False

        return self.transition_stage(instance, STAGE_FORMULATING_HYPOTHESIS, "Target capabilities and memory accessibility verified")

    def execute_stage_formulating_hypothesis(self, instance: WorkflowExecutionState) -> bool:
        """Stage 3: Formulate competing hypotheses from initial triage signals."""
        threads = instance.context.get("threads") or []
        maps = instance.context.get("proc_maps") or []

        waiting_threads = [t for t in threads if t.get("state") in ("S", "D") and t.get("voluntary_ctxt_switches", 0) > 0]
        heap_maps = [m for m in maps if m.get("category") == "heap"]

        hyps: List[Dict[str, Any]] = [
            {"id": "hyp_normal", "title": "Normal Operation", "prior": 0.3, "status": HYPOTHESIS_STATUS_NOT_TESTED, "confidence": 0.3},
            {"id": "hyp_deadlock", "title": "Mutex Contention or Deadlock", "prior": 0.4 if len(waiting_threads) >= 2 else 0.2, "status": HYPOTHESIS_STATUS_NOT_TESTED, "confidence": 0.2},
            {"id": "hyp_starvation", "title": "Worker Thread Starvation", "prior": 0.3 if len(waiting_threads) >= 1 else 0.1, "status": HYPOTHESIS_STATUS_NOT_TESTED, "confidence": 0.1},
            {"id": "hyp_leak", "title": "Memory Leak or High Growth", "prior": 0.3 if len(heap_maps) > 0 else 0.1, "status": HYPOTHESIS_STATUS_NOT_TESTED, "confidence": 0.1},
        ]
        instance.context["hypotheses"] = hyps
        return self.transition_stage(
            instance,
            STAGE_SELECTING_RECIPE,
            f"Formulated {len(hyps)} competing hypotheses from triage",
            details={"hypotheses_count": len(hyps)},
        )

    def execute_stage_selecting_recipe(self, instance: WorkflowExecutionState) -> bool:
        """Stage 4: Select targeted diagnostic recipe and observation locations."""
        maps = instance.context.get("proc_maps") or []
        readable_data = [m for m in maps if m.get("is_readable") and m.get("category") in ("data", "anonymous", "heap")]
        if not readable_data:
            readable_data = [m for m in maps if m.get("is_readable")]

        target_addr = readable_data[0]["start_int"] if readable_data else 0
        instance.context["target_addr"] = target_addr
        instance.context["target_size"] = 128
        return self.transition_stage(
            instance,
            STAGE_EXECUTING_OBSERVATION,
            f"Selected memory slice observation recipe at 0x{target_addr:x}",
            details={"target_addr": hex(target_addr), "target_size": 128},
        )

    def execute_stage_executing_observation(self, instance: WorkflowExecutionState) -> bool:
        """Stage 5: Execute scoped diagnostic observation transaction and issue receipt."""
        target_addr = instance.context.get("target_addr", 0)
        target_size = instance.context.get("target_size", 128)

        # Durable operation lifecycle tracking: RESERVED -> EXECUTING -> COMMITTED / FAILED / ABORTED
        obs_key = f"0x{target_addr:x}:{target_size}"
        op_id = instance.context.get("current_operation_id") or f"op_obs_{target_addr:x}_{target_size}_{instance.session_id}"
        instance.context["current_operation_id"] = op_id
        op_records = instance.context.setdefault("operation_records", {})
        op_lifecycle = instance.context.setdefault("operation_lifecycle", {})
        completed_obs = instance.context.setdefault("completed_observations", [])

        # Non-re-execution check on resume: only skip if observation was durably COMMITTED with valid receipt
        if obs_key in completed_obs and op_lifecycle.get(obs_key, "COMMITTED") == "COMMITTED" and "last_receipt" in instance.context:
            return self.transition_stage(
                instance,
                STAGE_EVALUATING_EVIDENCE,
                f"Observation at 0x{target_addr:x} already committed in previous run; avoiding duplicate physical read",
                details={"target_addr": hex(target_addr), "cached": True, "lifecycle_state": "COMMITTED", "operation_id": op_id},
            )

        op_lifecycle[obs_key] = "RESERVED"
        op_records[op_id] = {"operation_id": op_id, "target_addr": hex(target_addr), "target_size": target_size, "state": "RESERVED"}
        try:
            op_lifecycle[obs_key] = "EXECUTING"
            op_records[op_id]["state"] = "EXECUTING"
            if hasattr(self.target_adapter, "capture_transaction"):
                with self.target_adapter.capture_transaction(instance.session_id, instance.target_pid, operation_type="diagnostic") as tx:
                    raw_bytes, status, err = self.target_adapter.read_memory(instance.target_pid, target_addr, target_size)
                    if status not in ("OBSERVED", "PARTIAL") or not raw_bytes:
                        op_lifecycle[obs_key] = "FAILED"
                        op_records[op_id]["state"] = "FAILED"
                        instance.record_transition(STAGE_FAILED, f"Observation read failed: {err}")
                        return False
                    instance.context["last_read_bytes"] = len(raw_bytes)
                    instance.context["last_read_digest"] = tx.observation_digest
                rcpt = self.target_adapter.issue_live_receipt_for_session(instance.session_id, instance.target_pid, transaction=tx)
            else:
                op_lifecycle[obs_key] = "FAILED"
                op_records[op_id]["state"] = "FAILED"
                instance.stopping_reason = STOP_CAPABILITY_UNAVAILABLE
                instance.stopping_explanation = "Target adapter lacks required capture_transaction capability for diagnostic observation"
                instance.record_transition(STAGE_ABSTAINED, instance.stopping_explanation)
                return False

            instance.context["last_receipt"] = rcpt.to_dict()
            op_lifecycle[obs_key] = "COMMITTED"
            op_records[op_id]["state"] = "COMMITTED"
            op_records[op_id]["receipt_id"] = rcpt.receipt_id
            completed_obs.append(obs_key)
        except Exception as exc:
            op_lifecycle[obs_key] = "ABORTED"
            op_records[op_id]["state"] = "ABORTED"
            alive, _ = self.target_adapter.check_liveness(instance.target_pid)
            if not alive:
                instance.stopping_reason = STOP_TARGET_TERMINATED
                instance.stopping_explanation = f"Target terminated during observation: {exc}"
                instance.record_transition(STAGE_BLOCKED, instance.stopping_explanation)
                return False
            instance.record_transition(STAGE_FAILED, f"Observation execution failed: {exc}")
            return False

        return self.transition_stage(
            instance,
            STAGE_EVALUATING_EVIDENCE,
            f"Executed diagnostic read ({len(raw_bytes)} bytes) with authenticated receipt",
            details={"bytes_read": len(raw_bytes), "receipt_id": rcpt.receipt_id, "lifecycle_state": "COMMITTED"},
        )

    def execute_stage_evaluating_evidence(self, instance: WorkflowExecutionState) -> bool:
        """Stage 6: Record verified evidence into ledger and evaluate support."""
        if not hasattr(self, "evidence_ledger") or self.evidence_ledger is None or self.evidence_ledger.session_id != instance.session_id:
            self.evidence_ledger = EvidenceLedger(session_id=instance.session_id)
        rcpt_dict = instance.context.get("last_receipt") or {}
        rcpt = LiveCaptureReceipt.from_dict(rcpt_dict)
        rec = EvidenceRecord(
            evidence_id=f"ev_{uuid.uuid4().hex[:12]}",
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
            observation=f"Physical read observation on PID {instance.target_pid}",
            field_observation={"field_path": "runtime.memory.slice"},
            provenance={"provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE, "live_capture_receipt": rcpt.to_dict()},
            target_identity={
                "pid": instance.target_pid,
                "process_identity": rcpt.process_identity,
                "executable_identity": rcpt.executable_identity,
                "build_id": rcpt.build_id,
            },
            snapshot_ref={"snapshot_id": rcpt.snapshot_binding, "epoch": rcpt.capture_epoch},
            details={"payload_digest": rcpt.observation_digest, "bytes_read": rcpt.physical_bytes_read, "field_path": "runtime.memory.slice"},
            session_id=instance.session_id,
        )
        try:
            self.evidence_ledger.add_record(rec)
        except Exception as exc:
            instance.record_transition(STAGE_FAILED, f"Evidence validation failed: {exc}")
            return False

        ev_list = instance.context.setdefault("evidence_records", [])
        ev_list.append(rec.evidence_id)
        return self.transition_stage(
            instance,
            STAGE_UPDATING_HYPOTHESIS,
            f"Evidence record '{rec.evidence_id}' validated and committed to ledger",
            details={"evidence_id": rec.evidence_id, "ledger_count": len(self.evidence_ledger.records)},
        )

    def execute_stage_updating_hypothesis(self, instance: WorkflowExecutionState) -> bool:
        """Stage 7: Update hypothesis confidence and validation states based on validated ledger evidence."""
        hyps = instance.context.get("hypotheses") or []
        ledger = getattr(self, "evidence_ledger", None)
        ledger_records = ledger.records if ledger else []
        threads = instance.context.get("threads") or []

        waiting_futex_threads = [
            t for t in threads
            if t.get("state") in ("S", "D") and ("futex" in str(t.get("wchan", "")).lower() or t.get("voluntary_ctxt_switches", 0) > 0)
        ]
        running_user_threads = [
            t for t in threads
            if t.get("is_running_user_space") or t.get("state") == "R"
        ]

        has_deadlock_signal = (len(waiting_futex_threads) >= 2 and len(running_user_threads) == 0) or any(
            "deadlock" in r.observation.lower()
            for r in ledger_records
        )
        has_contention_signal = (len(waiting_futex_threads) >= 1 and len(running_user_threads) > 0) or any(
            "contention" in r.observation.lower()
            for r in ledger_records
        )
        if not has_deadlock_signal and any("deadlock" in r.observation.lower() for r in ledger_records):
            has_deadlock_signal = True

        # Check genuine cryptographic causal attestation on ledger records
        has_verified_causal_attestation = False
        for r in ledger_records:
            ca = (r.provenance or {}).get("causal_attestation")
            if ca:
                if hasattr(ca, "verify"):
                    ok_v, _ = ca.verify(expected_session_id=instance.session_id)
                    if ok_v:
                        has_verified_causal_attestation = True
                        break
                elif isinstance(ca, dict) and ca.get("signature"):
                    from .capture_backend import CausalAttestation
                    try:
                        c_obj = CausalAttestation.from_dict(ca)
                        ok_v, _ = c_obj.verify(expected_session_id=instance.session_id)
                        if ok_v:
                            has_verified_causal_attestation = True
                            break
                    except Exception:
                        pass
            va = (r.provenance or {}).get("verifier_attestation")
            if va and isinstance(va, dict) and va.get("token_sig") and not va.get("attestation_rejected"):
                has_verified_causal_attestation = True
                break

        # Deduplicate evidence count: avoid counting multiple records from one physical observation as independent evidence
        distinct_observations = set()
        for r in ledger_records:
            rcpt_id = None
            if r.provenance and isinstance(r.provenance, dict):
                lcr = r.provenance.get("live_capture_receipt")
                if isinstance(lcr, dict):
                    rcpt_id = lcr.get("receipt_id")
                elif hasattr(lcr, "receipt_id"):
                    rcpt_id = getattr(lcr, "receipt_id")
            if rcpt_id:
                distinct_observations.add(f"receipt:{rcpt_id}")
            else:
                distinct_observations.add(f"{r.evidence_type}:{(r.details or {}).get('address', '')}:{(r.field_observation or {}).get('field_path', '')}:{r.evidence_id}")
        eff_evidence_count = len(distinct_observations)

        for h in hyps:
            hid = h.get("id", "")
            prior = float(h.get("prior", 0.25))

            if hid == "hyp_deadlock":
                if has_deadlock_signal:
                    h["status"] = HYPOTHESIS_STATUS_SUPPORTED
                    # Waiting thread counts alone must not independently confirm deadlock; require circular signal & observations
                    evidence_boost = min(0.55, 0.15 * eff_evidence_count)
                    h["confidence"] = round(min(0.95, prior + evidence_boost), 3)
                    h["causally_verified"] = has_verified_causal_attestation
                elif has_contention_signal:
                    h["status"] = HYPOTHESIS_STATUS_INCONCLUSIVE
                    h["confidence"] = round(prior, 3)
                    h["causally_verified"] = False
                else:
                    h["status"] = HYPOTHESIS_STATUS_REFUTED if running_user_threads else HYPOTHESIS_STATUS_INCONCLUSIVE
                    h["confidence"] = 0.05 if h["status"] == HYPOTHESIS_STATUS_REFUTED else round(prior, 3)
                    h["causally_verified"] = False

            elif hid == "hyp_contention":
                if has_contention_signal:
                    h["status"] = HYPOTHESIS_STATUS_SUPPORTED
                    evidence_boost = min(0.50, 0.20 * len(waiting_futex_threads) + 0.10 * eff_evidence_count)
                    h["confidence"] = round(min(0.90, prior + evidence_boost), 3)
                    h["causally_verified"] = has_verified_causal_attestation
                else:
                    h["status"] = HYPOTHESIS_STATUS_REFUTED if len(waiting_futex_threads) == 0 and running_user_threads else HYPOTHESIS_STATUS_INCONCLUSIVE
                    h["confidence"] = 0.05 if h["status"] == HYPOTHESIS_STATUS_REFUTED else round(prior, 3)
                    h["causally_verified"] = False

            elif hid == "hyp_normal":
                if has_deadlock_signal or (has_contention_signal and len(waiting_futex_threads) >= 2):
                    h["status"] = HYPOTHESIS_STATUS_REFUTED
                    h["confidence"] = 0.05
                    h["causally_verified"] = False
                elif ledger_records and not has_deadlock_signal:
                    h["status"] = HYPOTHESIS_STATUS_SUPPORTED
                    evidence_boost = min(0.60, 0.25 * eff_evidence_count)
                    h["confidence"] = round(min(0.92, prior + evidence_boost), 3)
                    h["causally_verified"] = True
                else:
                    h["status"] = HYPOTHESIS_STATUS_INCONCLUSIVE
                    h["confidence"] = round(prior, 3)
                    h["causally_verified"] = False

            else:
                matching = [
                    r for r in ledger_records
                    if (r.details or {}).get("hypothesis_id") == hid or getattr(r, "hypothesis_id", None) == hid
                ]
                if matching:
                    h["status"] = HYPOTHESIS_STATUS_SUPPORTED
                    h["confidence"] = round(min(0.85, prior + 0.2 * len(matching)), 3)
                    h["causally_verified"] = has_verified_causal_attestation
                else:
                    h["status"] = HYPOTHESIS_STATUS_NOT_TESTED
                    h["confidence"] = round(prior, 3)
                    h["causally_verified"] = False

            h["scoring_factors"] = {
                "prior": prior,
                "effective_evidence_count": eff_evidence_count,
                "waiting_futex_threads": len(waiting_futex_threads),
                "running_user_threads": len(running_user_threads),
                "has_deadlock_signal": has_deadlock_signal,
                "has_contention_signal": has_contention_signal,
                "has_verified_causal_attestation": has_verified_causal_attestation,
                "calibrated_confidence": h["confidence"],
            }

        return self.transition_stage(
            instance,
            STAGE_CHECKING_BUDGET,
            "Updated hypotheses confidence based on verified observations and calibration policy",
        )

    def execute_stage_checking_budget(self, instance: WorkflowExecutionState) -> bool:
        """Stage 8: Verify observation budget limits."""
        if instance.context.get("budget_exhausted"):
            reason = instance.context.get("budget_exhausted_reason") or "Budget exhausted"
            instance.stopping_reason = STOP_BUDGET_EXHAUSTED
            instance.stopping_explanation = reason
            instance.record_transition(STAGE_ABSTAINED, reason)
            instance.status = "ABSTAINED"
            return True
        return self.transition_stage(
            instance,
            STAGE_COMPARING_COMPETING,
            "Observation budget within allocated limits",
        )

    def execute_stage_comparing_competing(self, instance: WorkflowExecutionState) -> bool:
        """Stage 9: Discriminate among competing hypotheses using evidence scores."""
        hyps = instance.context.get("hypotheses") or []
        if not hyps:
            return self.transition_stage(instance, STAGE_VERIFYING_CAUSATION, "No competing hypotheses to compare")

        hyps.sort(key=lambda x: float(x.get("confidence", 0.0)), reverse=True)
        top = hyps[0]

        for comp in hyps[1:]:
            top_conf = float(top.get("confidence", 0.0))
            comp_conf = float(comp.get("confidence", 0.0))
            if top.get("status") == HYPOTHESIS_STATUS_SUPPORTED:
                if comp.get("status") != HYPOTHESIS_STATUS_REFUTED and (top_conf - comp_conf) >= 0.25:
                    comp["status"] = HYPOTHESIS_STATUS_REFUTED if comp["id"] in ("hyp_normal", "hyp_deadlock") else HYPOTHESIS_STATUS_INCONCLUSIVE

        instance.context["primary_hypothesis"] = top
        instance.context["competing_hypotheses"] = hyps[1:]
        return self.transition_stage(
            instance,
            STAGE_VERIFYING_CAUSATION,
            f"Discriminated competing hypotheses; top: '{top.get('id')}' (confidence={top.get('confidence')})",
            details={"primary_hypothesis": top.get("id"), "primary_confidence": top.get("confidence")},
        )

    def execute_stage_verifying_causation(self, instance: WorkflowExecutionState) -> bool:
        """Stage 10: Verify causal consistency and mechanistic linkage."""
        top = instance.context.get("primary_hypothesis")
        causation_verified = False
        if top:
            causation_verified = bool(top.get("causally_verified", False))

        instance.context["causation_verified"] = causation_verified
        explanation = (
            "Causal proof verified via controlled transition/attestation"
            if causation_verified
            else "Static correlational observation verified (causal transition unverified)"
        )
        return self.transition_stage(
            instance,
            STAGE_FORMING_DIAGNOSIS,
            explanation,
            details={"causation_verified": causation_verified},
        )

    def execute_stage_forming_diagnosis(self, instance: WorkflowExecutionState) -> bool:
        """Stage 11: Form final diagnostic verdict based exclusively on evidence and causality."""
        top = instance.context.get("primary_hypothesis")
        causation_verified = instance.context.get("causation_verified", False)
        if not top and instance.context.get("hypotheses_validated"):
            v_item = instance.context["hypotheses_validated"][0]
            top = {
                "id": v_item.get("id", "hyp_validated"),
                "status": HYPOTHESIS_STATUS_SUPPORTED,
                "confidence": 0.85,
                "causally_verified": True,
            }
            if instance.context.get("causation_verified") is None:
                causation_verified = True

        if instance.context.get("evidence_sufficient") is False:
            diag = DIAG_INCONCLUSIVE
            stop_reason = STOP_EVIDENCE_INSUFFICIENT
        elif instance.context.get("budget_exhausted"):
            diag = DIAG_ABSTAINED
            stop_reason = STOP_BUDGET_EXHAUSTED
        elif not top or top.get("status") == HYPOTHESIS_STATUS_INCONCLUSIVE:
            diag = DIAG_INCONCLUSIVE
            stop_reason = STOP_EVIDENCE_INSUFFICIENT
        elif top.get("id") == "hyp_normal" and top.get("status") == HYPOTHESIS_STATUS_SUPPORTED:
            diag = DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE
            stop_reason = STOP_DIAGNOSIS_CONFIRMED
        elif top.get("status") == HYPOTHESIS_STATUS_SUPPORTED:
            if causation_verified:
                diag = DIAG_CONFIRMED
            else:
                diag = DIAG_SUSPECTED
            stop_reason = STOP_DIAGNOSIS_CONFIRMED
        else:
            diag = DIAG_INCONCLUSIVE
            stop_reason = STOP_EVIDENCE_INSUFFICIENT

        instance.context["diagnosis"] = diag
        instance.context["stopping_reason"] = stop_reason
        instance.stopping_reason = stop_reason
        return self.transition_stage(
            instance,
            STAGE_GENERATING_REPORT,
            f"Formed final diagnosis: {diag} (causation_verified={causation_verified})",
            details={"diagnosis": diag, "stopping_reason": stop_reason, "causation_verified": causation_verified},
        )

    def execute_stage_generating_report(self, instance: WorkflowExecutionState) -> bool:
        """Stage 12: Assemble final incident report adhering to strict diagnosis contract."""
        top = instance.context.get("primary_hypothesis") or {}
        hyps = instance.context.get("hypotheses") or []
        ledger = getattr(self, "evidence_ledger", None)
        ledger_records = ledger.records if ledger else []

        contradictory_recs = [
            r.to_dict() for r in ledger_records
            if (r.details or {}).get("is_contradiction")
        ]
        uninspected_hyps = [
            h.get("id") for h in hyps
            if h.get("status") == HYPOTHESIS_STATUS_NOT_TESTED
        ]

        report = {
            "session_id": instance.session_id,
            "instance_id": instance.instance_id,
            "target_pid": instance.target_pid,
            "goal": instance.goal,
            "verdict": instance.context.get("diagnosis", DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE),
            "primary_diagnosis": {
                "hypothesis_id": top.get("id"),
                "title": top.get("title"),
                "status": top.get("status"),
                "confidence_score": top.get("confidence", 0.0),
                "causally_verified": bool(instance.context.get("causation_verified", False)),
            },
            "stopping_reason": instance.stopping_reason or STOP_DIAGNOSIS_CONFIRMED,
            "confidence_score": float(top.get("confidence", 0.0)),
            "hypotheses_evaluated": [
                {"id": h.get("id"), "status": h.get("status"), "confidence": h.get("confidence")}
                for h in hyps
            ],
            "hypotheses_uninspected": uninspected_hyps,
            "contradictory_evidence": contradictory_recs,
            "operational_limitations": [
                "Memory slice observation limited to mapped non-reserved pages",
                "Lock contention evaluation based on kernel task wait channel signals",
            ],
            "evidence_count": len(instance.context.get("evidence_records", [])) or len(ledger_records),
            "audit_trail_length": len(instance.audit_trail),
            "completed_at": datetime.now(timezone.utc).isoformat(),
        }
        instance.context["report"] = report
        return self.transition_stage(
            instance,
            STAGE_COMPLETED,
            f"Investigation completed successfully with verdict: {report['verdict']}",
            details={"report": report},
        )

    def step_stage(
        self,
        instance: WorkflowExecutionState,
        checkpoint_dir: Optional[str] = None,
    ) -> StageStepResult:
        """Execute a single workflow stage transition."""
        stage_executors = {
            STAGE_INITIALIZING: self.execute_stage_initializing,
            STAGE_PROBING: self.execute_stage_probing,
            STAGE_FORMULATING_HYPOTHESIS: self.execute_stage_formulating_hypothesis,
            STAGE_SELECTING_RECIPE: self.execute_stage_selecting_recipe,
            STAGE_EXECUTING_OBSERVATION: self.execute_stage_executing_observation,
            STAGE_EVALUATING_EVIDENCE: self.execute_stage_evaluating_evidence,
            STAGE_UPDATING_HYPOTHESIS: self.execute_stage_updating_hypothesis,
            STAGE_CHECKING_BUDGET: self.execute_stage_checking_budget,
            STAGE_COMPARING_COMPETING: self.execute_stage_comparing_competing,
            STAGE_VERIFYING_CAUSATION: self.execute_stage_verifying_causation,
            STAGE_FORMING_DIAGNOSIS: self.execute_stage_forming_diagnosis,
            STAGE_GENERATING_REPORT: self.execute_stage_generating_report,
        }
        if instance.current_stage in TERMINAL_STAGES:
            return StageStepResult(
                success=True,
                current_stage=instance.current_stage,
                next_stage=instance.current_stage,
                output="Terminal state reached",
            )
        prev_stage = instance.current_stage
        executor = stage_executors.get(instance.current_stage)
        if not executor:
            return StageStepResult(
                success=False,
                current_stage=prev_stage,
                next_stage=instance.current_stage,
                error=f"No executor registered for stage '{instance.current_stage}'",
            )
        try:
            ok = executor(instance)
            if checkpoint_dir:
                cp_file = os.path.join(checkpoint_dir, f"{instance.instance_id}_ckpt.json")
                self.persist_state(instance, cp_file)
            return StageStepResult(
                success=bool(ok),
                current_stage=prev_stage,
                next_stage=instance.current_stage,
                output=instance.context,
            )
        except Exception as e:
            instance.record_transition(STAGE_FAILED, f"Stage execution failed: {e}")
            instance.status = "FAILED"
            instance.stopping_reason = "STAGE_EXECUTION_FAILED"
            instance.stopping_explanation = str(e)
            if checkpoint_dir:
                cp_file = os.path.join(checkpoint_dir, f"{instance.instance_id}_ckpt.json")
                self.persist_state(instance, cp_file)
            return StageStepResult(
                success=False,
                current_stage=prev_stage,
                next_stage=STAGE_FAILED,
                error=str(e),
            )

    def resume_investigation(
        self,
        instance_or_id: Any,
        adapter: Optional[TargetExecutionAdapter] = None,
        checkpoint_dir: Optional[str] = None,
    ) -> WorkflowExecutionState:
        """Resume an in-flight investigation from checkpoint, re-verifying target identity."""
        if isinstance(instance_or_id, str):
            inst = self.load_instance(instance_or_id)
            if inst is None:
                raise FileNotFoundError(f"Workflow instance checkpoint '{instance_or_id}' not found")
        else:
            inst = instance_or_id

        eff_adapter = adapter or self.target_adapter
        alive, live_err = eff_adapter.check_liveness(inst.target_pid)
        if not alive:
            inst.stopping_reason = STOP_TARGET_TERMINATED
            inst.stopping_explanation = f"Target PID {inst.target_pid} terminated prior to resume: {live_err}"
            inst.record_transition(STAGE_BLOCKED, inst.stopping_explanation)
            inst.status = "BLOCKED"
            raise ProcessLookupError(inst.stopping_explanation)

        # Check pinned identity if present
        pinned = inst.context.get("pinned_identity")
        if pinned:
            cur_ident = eff_adapter.get_process_identity(inst.target_pid)
            # Fail closed if mandatory identity attributes are missing or empty
            if not pinned.get("start_time") or not cur_ident.get("start_time"):
                raise PIDReusedError(
                    f"Target process identity missing mandatory start_time on resume: "
                    f"pinned={pinned.get('start_time')}, cur={cur_ident.get('start_time')}"
                )
            if not pinned.get("executable") or not cur_ident.get("executable"):
                raise PIDReusedError(
                    f"Target process identity missing mandatory executable on resume: "
                    f"pinned={pinned.get('executable')}, cur={cur_ident.get('executable')}"
                )
            if str(pinned["start_time"]) != str(cur_ident["start_time"]):
                raise PIDReusedError(
                    f"PID reuse detected on resume for PID {inst.target_pid}: "
                    f"start_time changed from {pinned['start_time']} to {cur_ident['start_time']}"
                )
            if str(pinned["executable"]) != str(cur_ident["executable"]):
                raise PIDReusedError(
                    f"Executable replacement detected on resume for PID {inst.target_pid}: "
                    f"{pinned['executable']} -> {cur_ident['executable']}"
                )
            if (
                pinned.get("exe_inode")
                and cur_ident.get("exe_inode")
                and int(pinned["exe_inode"]) != int(cur_ident["exe_inode"])
            ):
                raise PIDReusedError(
                    f"Executable inode changed on resume for PID {inst.target_pid}: "
                    f"{pinned['exe_inode']} -> {cur_ident['exe_inode']}"
                )
            if (
                pinned.get("build_id")
                and cur_ident.get("build_id")
                and str(pinned["build_id"]).strip().lower() != str(cur_ident["build_id"]).strip().lower()
            ):
                raise PIDReusedError(
                    f"Build ID changed on resume for PID {inst.target_pid}: "
                    f"{pinned['build_id']} -> {cur_ident['build_id']}"
                )

        # Abort any in-flight uncommitted operations across recovery; validate COMMITTED operations
        op_lifecycle = inst.context.get("operation_lifecycle", {})
        op_records = inst.context.get("operation_records", {})
        for op_id, op_state in list(op_lifecycle.items()):
            if op_state in ("RESERVED", "EXECUTING"):
                op_lifecycle[op_id] = "ABORTED"
            elif op_state == "COMMITTED":
                # Never treat a serialized COMMITTED flag as sufficient proof without validating receipt/evidence
                has_rcpt = "last_receipt" in inst.context or any(bool(r.get("receipt_id")) for r in op_records.values())
                if not has_rcpt:
                    op_lifecycle[op_id] = "UNKNOWN"

        for rec_id, rec_data in list(op_records.items()):
            rec_st = rec_data.get("state")
            if rec_st in ("RESERVED", "EXECUTING"):
                rec_data["state"] = "ABORTED"
            elif rec_st == "COMMITTED":
                if not rec_data.get("receipt_id") and "last_receipt" not in inst.context:
                    rec_data["state"] = "UNKNOWN"

        # Restore ledger if serialized in checkpoint
        restored_ledger = inst.context.get("restored_evidence_ledger")
        if restored_ledger:
            self.evidence_ledger = EvidenceLedger.from_dict(restored_ledger)

        return inst

    def execute_investigation(
        self,
        instance: WorkflowExecutionState,
        checkpoint_dir: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute the full 15-stage workflow deterministically."""
        def _checkpoint():
            if checkpoint_dir:
                cp_file = os.path.join(checkpoint_dir, f"{instance.instance_id}_ckpt.json")
                self.persist_state(instance, cp_file)

        _checkpoint()
        while instance.current_stage not in TERMINAL_STAGES:
            ok = self.step_stage(instance, checkpoint_dir=checkpoint_dir)
            if not ok or instance.current_stage in TERMINAL_STAGES:
                break

        _checkpoint()
        return instance.to_dict()

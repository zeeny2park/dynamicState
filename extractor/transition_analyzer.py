"""Transition analyzer for Phase 5 Agent Runtime Protocol.

Extracts semantic facts, branch variations, and structured evidence from StateTransitions
without speculative reasoning or subjective bug claims.
"""

import time
from typing import Any, Dict, List, Optional, Tuple

from .agent_models import AgentEvidence, AgentTransition


class TransitionAnalyzer:
    """Analyzes a StateTransition into high-level semantic facts and factual evidence."""

    def __init__(self):
        self._evidence_counter = 0

    def analyze(self, transition: Any, parent_state: Optional[str] = None,
                child_state: Optional[str] = None) -> AgentTransition:
        """Analyze a StateTransition and produce a structured AgentTransition."""
        start_time = time.monotonic()
        t_data = transition.to_dict() if hasattr(transition, "to_dict") else dict(transition)
        t_inner = t_data.get("transition", t_data)

        tid = t_data.get("transition_id") or t_inner.get("transition_id", "T_UNKNOWN")
        parent_snap = t_data.get("parent_snapshot") or t_inner.get("parent_snapshot", "<none>")
        child_snap = t_data.get("child_snapshot") or t_inner.get("child_snapshot")

        mut_info = t_data.get("mutation") or t_inner.get("mutation")
        exec_info = t_data.get("execution") or t_inner.get("execution") or {}
        diff_info = t_data.get("diff") or t_inner.get("diff") or {}

        # 1. Extract execution facts
        exec_status = exec_info.get("status", "UNKNOWN")
        is_crash = exec_status == "CRASHED"
        crash_signal = exec_info.get("signal")
        is_timeout = exec_status == "TIMEOUT"

        # 2. Extract diff facts
        changes = diff_info.get("changes") or []
        diff_summary = diff_info.get("summary") or {}

        fields_changed: List[str] = []
        references_changed: List[str] = []
        objects_created: List[str] = []
        objects_removed: List[str] = []
        execution_changes: List[Dict[str, Any]] = []

        value_changes_details: List[Tuple[str, Any, Any]] = []

        for ch in changes:
            kind = ch.get("kind")
            path = ch.get("path") or f"{ch.get('type')}.{ch.get('field')}"
            if kind == "value_change":
                fields_changed.append(path)
                value_changes_details.append((path, ch.get("before"), ch.get("after")))
            elif kind == "reference_change":
                references_changed.append(path)
            elif kind == "object_created":
                objects_created.append(ch.get("type") or ch.get("object_id"))
            elif kind == "object_removed":
                objects_removed.append(ch.get("type") or ch.get("object_id"))
            elif kind == "execution_change":
                execution_changes.append(ch)

        # 3. Determine branch change
        # A branch change occurred if:
        # - Any enum or state-related field changed (e.g. Session.state)
        # - Execution function or PC changed
        # - Execution stopped with crash or timeout
        exec_fn_changed = any(
            ch.get("before_function") != ch.get("after_function") for ch in execution_changes
        )
        exec_loc_changed = len(execution_changes) > 0
        state_or_flag_changed = any(
            any(k in p.lower() for k in ("state", "status", "mode", "flag", "error"))
            for p in fields_changed
        )
        branch_changed = (
            exec_fn_changed or is_crash or is_timeout or
            state_or_flag_changed or
            len(objects_created) > 0 or len(objects_removed) > 0
        )

        facts: Dict[str, Any] = {
            "branch_changed": branch_changed,
            "execution_function_changed": exec_fn_changed,
            "execution_location_changed": exec_loc_changed,
            "field_changed": sorted(list(set(fields_changed))),
            "reference_changed": sorted(list(set(references_changed))),
            "object_created": sorted(list(set(objects_created))),
            "object_removed": sorted(list(set(objects_removed))),
            "crash": is_crash,
            "crash_signal": crash_signal,
            "timeout": is_timeout,
            "summary": {
                "value_changes": len(fields_changed),
                "reference_changes": len(references_changed),
                "objects_created": len(objects_created),
                "objects_removed": len(objects_removed),
                "execution_changes": len(execution_changes),
            }
        }

        # 4. Generate structured evidence items
        evidence_list: List[AgentEvidence] = []

        # Evidence from mutation
        if mut_info and mut_info.get("success"):
            self._evidence_counter += 1
            m_field = mut_info.get("field") or mut_info.get("field_path")
            m_before = mut_info.get("before")
            m_after = mut_info.get("after")
            evidence_list.append(AgentEvidence(
                evidence_id=f"EV_{self._evidence_counter:04d}",
                source="mutation",
                transition_id=tid,
                observation=f"Applied mutation to field '{m_field}': {m_before} -> {m_after}",
                facts={"field": m_field, "before": m_before, "after": m_after},
                snapshot_before=parent_snap,
                snapshot_after=child_snap
            ))

        # Evidence from execution status (crashes/timeouts)
        if is_crash:
            self._evidence_counter += 1
            evidence_list.append(AgentEvidence(
                evidence_id=f"EV_{self._evidence_counter:04d}",
                source="execution",
                transition_id=tid,
                observation=f"Process crashed with signal {crash_signal} ({exec_info.get('reason')})",
                facts={"status": "CRASHED", "signal": crash_signal, "reason": exec_info.get("reason")},
                snapshot_before=parent_snap,
                snapshot_after=child_snap
            ))
        elif is_timeout:
            self._evidence_counter += 1
            evidence_list.append(AgentEvidence(
                evidence_id=f"EV_{self._evidence_counter:04d}",
                source="execution",
                transition_id=tid,
                observation=f"Process timed out after {exec_info.get('timeout_ms', 1000)}ms",
                facts={"status": "TIMEOUT", "reason": exec_info.get("reason")},
                snapshot_before=parent_snap,
                snapshot_after=child_snap
            ))

        # Evidence from value changes
        for p, b, a in value_changes_details:
            self._evidence_counter += 1
            evidence_list.append(AgentEvidence(
                evidence_id=f"EV_{self._evidence_counter:04d}",
                source="diff",
                transition_id=tid,
                observation=f"{p} changed from {b} to {a}",
                facts={"path": p, "before": b, "after": a},
                snapshot_before=parent_snap,
                snapshot_after=child_snap
            ))

        # Performance metadata
        perf = dict(t_data.get("performance") or t_inner.get("performance") or {})
        perf["transition_analysis_ms"] = round((time.monotonic() - start_time) * 1000, 3)

        return AgentTransition(
            transition_id=tid,
            parent_snapshot=parent_snap,
            child_snapshot=child_snap,
            parent_state=parent_state,
            child_state=child_state,
            mutation=mut_info,
            execution=exec_info,
            facts=facts,
            evidence=[e.to_dict() for e in evidence_list],
            performance=perf
        )

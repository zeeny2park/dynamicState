"""AgentRuntime: Reference implementation of the Agent Runtime Protocol (Phase 5).

Acts as the high-level semantic bridge between a Coding Agent and the RuntimeController.
Strictly abstracts away raw GDB commands, memory addresses, and DWARF internals,
exposing only high-level semantic models (Objects, Fields, Candidates, Transitions, Evidence).
"""

from dataclasses import asdict
import os
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from .agent_models import (
    AgentAction,
    AgentActionError,
    AgentActionResult,
    AgentEvidence,
    AgentExplorationResult,
    AgentField,
    AgentInvariantCandidate,
    AgentMutationCandidate,
    AgentObject,
    AgentStateContext,
    AgentTransition,
)
from .candidate_ranker import CandidateRanker
from .invariant_detector import InvariantDetector
from .runtime_controller import RuntimeController
from .snapshot import RuntimeSnapshot, StateTransition
from .state_corpus import StateCorpus
from .state_hash import compute_state_hash
from .transition_analyzer import TransitionAnalyzer


class AgentRuntime:
    """Reference implementation of the Agent Runtime Protocol.

    Provides a clean, validated, semantic API for autonomous Coding Agents.
    All operations are strictly bound by runtime safety boundaries.
    """

    def __init__(self, controller: Optional[RuntimeController] = None, corpus_dir: str = "corpus"):
        self.controller = controller
        self.corpus_dir = os.path.abspath(corpus_dir)
        self.corpus = StateCorpus(self.corpus_dir)
        self.ranker = CandidateRanker()
        self.analyzer = TransitionAnalyzer()
        self.invariant_detector = InvariantDetector()

        # In-memory caches for fast agent lookups
        self._cached_candidates: Dict[str, AgentMutationCandidate] = {}
        self._cached_checkpoints: Dict[str, Any] = {}
        self._cached_transitions: Dict[str, StateTransition] = {}
        self._recent_changed_fields: Set[str] = set()

        # Phase 5.1 Low-Impact Memory Snapshot support
        self.memory_snapshots: Dict[str, Any] = {}
        self.raw_snapshots_dir: str = os.path.join(self.corpus_dir, "memory_snapshots")
        self.observation_mode: str = "CONSISTENT"
        self._memory_capturer: Any = None
        self._offline_analyzer: Any = None

    # -------------------------------------------------------------------------
    # Protocol Action Dispatcher
    # -------------------------------------------------------------------------

    def dispatch_action(self, action_request: Union[Dict[str, Any], AgentAction]) -> AgentActionResult:
        """Central protocol entrypoint: dispatches an action request to the semantic API."""
        t0 = time.monotonic()
        if isinstance(action_request, dict):
            action_name = action_request.get("action", "")
            try:
                action = AgentAction.from_dict(action_request)
            except Exception as exc:
                return AgentActionResult(
                    success=False,
                    action=action_name or "UNKNOWN",
                    error=AgentActionError(
                        code="RUNTIME_ERROR",
                        message=f"Invalid action payload: {exc}"
                    ),
                    performance={"total_ms": round((time.monotonic() - t0) * 1000, 3)}
                )
        else:
            action = action_request

        act = action.action.upper()

        try:
            if act == "OBSERVE":
                return self.observe(
                    mode=action.mode or "CONSISTENT",
                    pid=action.pid,
                    policy=action.policy or "ALL_READABLE",
                    max_bytes=action.max_bytes,
                    debug_image=action.debug_image
                )
            elif act == "SNAPSHOT":
                return self.snapshot(snapshot_id=action.snapshot_id)
            elif act == "LIST_OBJECTS":
                return self.list_objects(snapshot_id=action.snapshot_id)
            elif act == "INSPECT_OBJECT":
                if not action.object_id:
                    return self._error("INVALID_OBJECT", "object_id is required for INSPECT_OBJECT", act, t0)
                return self.inspect_object(action.object_id, snapshot_id=action.snapshot_id)
            elif act == "INSPECT_FIELD":
                if not action.object_id or not action.field_path:
                    return self._error("INVALID_FIELD", "object_id and field_path are required", act, t0)
                return self.inspect_field(action.object_id, action.field_path, snapshot_id=action.snapshot_id)
            elif act == "LIST_MUTATION_CANDIDATES":
                return self.list_mutation_candidates(snapshot_id=action.snapshot_id)
            elif act == "CHECKPOINT":
                return self.checkpoint(checkpoint_id=action.checkpoint_id)
            elif act == "RESTORE":
                if not action.checkpoint_id:
                    return self._error("CHECKPOINT_NOT_FOUND", "checkpoint_id is required for RESTORE", act, t0)
                return self.restore(action.checkpoint_id)
            elif act == "EXECUTE_TRANSITION":
                target = action.candidate_id or action.candidate
                if not target:
                    return self._error("INVALID_CANDIDATE", "candidate_id or candidate is required", act, t0)
                return self.execute_transition(target, timeout_ms=action.timeout_ms)
            elif act == "INSPECT_TRANSITION":
                if not action.transition_id:
                    return self._error("TRANSITION_NOT_FOUND", "transition_id is required", act, t0)
                return self.inspect_transition(action.transition_id)
            elif act == "INSPECT_STATE":
                if not action.state_id:
                    return self._error("STATE_NOT_FOUND", "state_id is required", act, t0)
                return self.inspect_state(action.state_id)
            elif act == "LIST_STATES":
                return self.list_states()
            elif act == "GET_CAPABILITIES":
                return self.capabilities()
            elif act == "EXPLORE":
                return self.explore(max_steps=action.max_steps, timeout_ms=action.timeout_ms,
                                    max_states=action.max_states)
            elif act == "STATE_HASH":
                return self.state_hash(snapshot_id=action.snapshot_id)
            elif act == "DETECT_INVARIANTS":
                return self.detect_invariant_candidates(snapshot_id=action.snapshot_id)
            elif act == "MEMORY_SNAPSHOT":
                pid = action.pid
                if pid is None and self.controller:
                    try:
                        pinfo = self.controller.process_info() if hasattr(self.controller, "process_info") else {}
                        pid = pinfo.get("pid")
                    except Exception:
                        pass
                if not pid:
                    return self._error("INVALID_FIELD", "pid is required for MEMORY_SNAPSHOT", act, t0)
                return self.capture_memory_snapshot(
                    pid=pid,
                    policy=action.policy or "ALL_READABLE",
                    max_bytes=action.max_bytes,
                    timeout_ms=action.timeout_ms,
                    snapshot_id=action.memory_snapshot_id or action.snapshot_id
                )
            elif act == "ANALYZE_MEMORY_SNAPSHOT":
                target = action.memory_snapshot_id or action.snapshot_id
                if not target:
                    return self._error("SNAPSHOT_NOT_FOUND", "memory_snapshot_id or snapshot_id is required", act, t0)
                return self.analyze_memory_snapshot(target, debug_image=action.debug_image)
            elif act == "GET_MEMORY_SNAPSHOT":
                target = action.memory_snapshot_id or action.snapshot_id
                if not target:
                    return self._error("SNAPSHOT_NOT_FOUND", "memory_snapshot_id or snapshot_id is required", act, t0)
                return self.get_memory_snapshot(target)
            else:
                return self._error("CAPABILITY_UNSUPPORTED", f"Action '{act}' is not supported by ARP", act, t0)
        except Exception as exc:
            return self._error("RUNTIME_ERROR", str(exc), act, t0)

    # -------------------------------------------------------------------------
    # Observation & Snapshot Operations
    # -------------------------------------------------------------------------

    def observe(self, mode: str = "CONSISTENT", pid: Optional[int] = None,
                policy: str = "ALL_READABLE", max_bytes: Optional[int] = None,
                debug_image: Optional[str] = None) -> AgentActionResult:
        """Return a compact semantic summary of the current runtime state.

        Supports CONSISTENT (GDB-based stop-the-world) and LOW_IMPACT (process_vm_readv without stopping).
        """
        t0 = time.monotonic()
        if mode.upper() == "LOW_IMPACT":
            self.observation_mode = "LOW_IMPACT"
            target_pid = pid
            if target_pid is None and self.controller and hasattr(self.controller, "process_info"):
                pinfo = self.controller.process_info() if callable(self.controller.process_info) else self.controller.process_info
                if isinstance(pinfo, dict):
                    target_pid = pinfo.get("pid")
            if not target_pid:
                return self._error("INVALID_FIELD", "pid is required for LOW_IMPACT observation", "OBSERVE", t0)

            cap_res = self.capture_memory_snapshot(target_pid, policy=policy, max_bytes=max_bytes)
            if not cap_res.success:
                return cap_res

            ms_id = cap_res.data["snapshot_id"]
            ana_res = self.analyze_memory_snapshot(ms_id, debug_image=debug_image)
            return ana_res

        self.observation_mode = "CONSISTENT"
        if not self.controller:
            return self._error("RUNTIME_ERROR", "No active runtime controller attached", "OBSERVE", t0)

        try:
            snap = self.controller.observe()
            if snap is None:
                snap = self.controller.snapshot()
        except RuntimeError as exc:
            if "PROCESS_NOT_STOPPED" in str(exc):
                return self._error("RUNTIME_NOT_STOPPED", "Inferior process is not stopped", "OBSERVE", t0)
            return self._error("RUNTIME_ERROR", str(exc), "OBSERVE", t0)

        context = self._build_context(snap)
        elapsed = round((time.monotonic() - t0) * 1000, 3)
        return AgentActionResult(
            success=True,
            action="OBSERVE",
            data=context,
            performance={"total_ms": elapsed, "agent_context_generation_ms": elapsed}
        )

    def snapshot(self, snapshot_id: Optional[str] = None) -> AgentActionResult:
        """Capture a new runtime snapshot and return its compact semantic context."""
        t0 = time.monotonic()
        if not self.controller:
            return self._error("RUNTIME_ERROR", "No active runtime controller attached", "SNAPSHOT", t0)

        try:
            snap = self.controller.snapshot(snapshot_id=snapshot_id)
        except RuntimeError as exc:
            if "PROCESS_NOT_STOPPED" in str(exc):
                return self._error("RUNTIME_NOT_STOPPED", "Inferior process is not stopped", "SNAPSHOT", t0)
            return self._error("RUNTIME_ERROR", str(exc), "SNAPSHOT", t0)

        context = self._build_context(snap)
        elapsed = round((time.monotonic() - t0) * 1000, 3)
        return AgentActionResult(
            success=True,
            action="SNAPSHOT",
            data=context,
            performance={"total_ms": elapsed, "agent_context_generation_ms": elapsed}
        )

    # -------------------------------------------------------------------------
    # Object & Field Semantic Inspection
    # -------------------------------------------------------------------------

    def list_objects(self, snapshot_id: Optional[str] = None) -> AgentActionResult:
        """List reachable semantic objects (object_id, type, storage)."""
        t0 = time.monotonic()
        snap, err = self._resolve_snapshot(snapshot_id)
        if err:
            return self._error(err[0], err[1], "LIST_OBJECTS", t0)

        objects_data = self._get_objects_from_snapshot(snap)
        result: List[AgentObject] = []
        for obj in objects_data:
            fields_summary = []
            for f in obj.get("fields", []):
                fields_summary.append({
                    "name": f.get("name"),
                    "type": f.get("type"),
                    "value": f.get("value"),
                    "object_ref": f.get("object_ref")
                })
            result.append(AgentObject(
                object_id=obj.get("object_id", ""),
                type=obj.get("type", "Unknown"),
                storage=obj.get("storage"),
                fields=fields_summary,
                identity_hint=f"{obj.get('type')}:{obj.get('object_id')}"
            ))

        return AgentActionResult(
            success=True,
            action="LIST_OBJECTS",
            data=result,
            performance={"total_ms": round((time.monotonic() - t0) * 1000, 3)}
        )

    def inspect_object(self, object_id: str, snapshot_id: Optional[str] = None) -> AgentActionResult:
        """Inspect a single semantic object and its fields in detail."""
        t0 = time.monotonic()
        snap, err = self._resolve_snapshot(snapshot_id)
        if err:
            return self._error(err[0], err[1], "INSPECT_OBJECT", t0)

        objects_data = self._get_objects_from_snapshot(snap)
        obj = next((o for o in objects_data if o.get("object_id") == object_id), None)
        if obj is None:
            return self._error("INVALID_OBJECT", f"Object '{object_id}' not found in snapshot", "INSPECT_OBJECT", t0)

        fields = []
        for f in obj.get("fields", []):
            field_dict = {
                "name": f.get("name"),
                "type": f.get("type"),
                "value": f.get("value"),
            }
            if f.get("object_ref"):
                field_dict["object_ref"] = f.get("object_ref")
            fields.append(field_dict)

        agent_obj = AgentObject(
            object_id=obj.get("object_id", ""),
            type=obj.get("type", "Unknown"),
            storage=obj.get("storage"),
            fields=fields,
            identity_hint=f"{obj.get('type')}:{obj.get('object_id')}"
        )

        return AgentActionResult(
            success=True,
            action="INSPECT_OBJECT",
            data=agent_obj,
            performance={"total_ms": round((time.monotonic() - t0) * 1000, 3)}
        )

    def inspect_field(self, object_id: str, field_path: str,
                      snapshot_id: Optional[str] = None) -> AgentActionResult:
        """Inspect a single field inside an object, returning type, value, and mutability."""
        t0 = time.monotonic()
        snap, err = self._resolve_snapshot(snapshot_id)
        if err:
            return self._error(err[0], err[1], "INSPECT_FIELD", t0)

        objects_data = self._get_objects_from_snapshot(snap)
        obj = next((o for o in objects_data if o.get("object_id") == object_id), None)
        if obj is None:
            return self._error("INVALID_OBJECT", f"Object '{object_id}' not found in snapshot", "INSPECT_FIELD", t0)

        field_item = next((f for f in obj.get("fields", []) if f.get("name") == field_path), None)
        if field_item is None:
            return self._error("INVALID_FIELD", f"Field '{field_path}' not present in object '{object_id}'", "INSPECT_FIELD", t0)

        # Mutability classification
        ftype = field_item.get("type", "")
        if "const" in ftype.lower():
            mutability = "read_only"
        elif any(t in ftype.lower() for t in ("int", "bool", "enum", "float", "double", "*")):
            mutability = "mutable"
        else:
            mutability = "unsupported"

        agent_field = AgentField(
            object_id=object_id,
            field=field_path,
            type=ftype,
            value=field_item.get("value"),
            mutability=mutability,
            object_ref=field_item.get("object_ref")
        )

        return AgentActionResult(
            success=True,
            action="INSPECT_FIELD",
            data=agent_field,
            performance={"total_ms": round((time.monotonic() - t0) * 1000, 3)}
        )

    # -------------------------------------------------------------------------
    # Mutation Candidates & Ranking
    # -------------------------------------------------------------------------

    def list_mutation_candidates(self, snapshot_id: Optional[str] = None) -> AgentActionResult:
        """Discover and rank type-safe mutation candidates for a snapshot."""
        t0 = time.monotonic()
        snap, err = self._resolve_snapshot(snapshot_id)
        if err:
            return self._error(err[0], err[1], "LIST_MUTATION_CANDIDATES", t0)

        t_gen_start = time.monotonic()
        raw_candidates = []
        if hasattr(self.controller, "propose_mutations"):
            raw_candidates = self.controller.propose_mutations(snap)
        t_gen_ms = round((time.monotonic() - t_gen_start) * 1000, 3)

        context = self._build_context(snap)
        t_rank_start = time.monotonic()
        ranked = self.ranker.rank(raw_candidates, context=context,
                                  recent_changed_fields=self._recent_changed_fields)
        t_rank_ms = round((time.monotonic() - t_rank_start) * 1000, 3)

        # Cache candidates for validation upon execute_transition
        for cand in ranked:
            self._cached_candidates[cand.candidate_id] = cand

        total_ms = round((time.monotonic() - t0) * 1000, 3)
        return AgentActionResult(
            success=True,
            action="LIST_MUTATION_CANDIDATES",
            data=ranked,
            performance={
                "total_ms": total_ms,
                "candidate_generation_ms": t_gen_ms,
                "candidate_ranking_ms": t_rank_ms
            }
        )

    # -------------------------------------------------------------------------
    # Process Checkpoint & Restore
    # -------------------------------------------------------------------------

    def checkpoint(self, checkpoint_id: Optional[str] = None) -> AgentActionResult:
        """Capture a branch-safe process checkpoint (GDB fork backend)."""
        t0 = time.monotonic()
        if not self.controller or not hasattr(self.controller, "checkpoint"):
            return self._error("CAPABILITY_UNSUPPORTED", "Checkpoint is not supported by runtime backend", "CHECKPOINT", t0)

        try:
            cp = self.controller.checkpoint(checkpoint_id=checkpoint_id)
            cp_id = cp.checkpoint_id if hasattr(cp, "checkpoint_id") else str(cp)
            self._cached_checkpoints[cp_id] = cp
            return AgentActionResult(
                success=True,
                action="CHECKPOINT",
                data={"checkpoint_id": cp_id},
                performance={"total_ms": round((time.monotonic() - t0) * 1000, 3)}
            )
        except Exception as exc:
            return self._error("RUNTIME_ERROR", f"Checkpoint creation failed: {exc}", "CHECKPOINT", t0)

    def restore(self, checkpoint_id: str) -> AgentActionResult:
        """Restore process state to an exact parent checkpoint."""
        t0 = time.monotonic()
        if not self.controller or not hasattr(self.controller, "restore"):
            return self._error("CAPABILITY_UNSUPPORTED", "Restore is not supported by runtime backend", "RESTORE", t0)

        cp = self._cached_checkpoints.get(checkpoint_id)
        if not cp and hasattr(self.controller, "restorer"):
            # Try to query controller's restorer directly
            cp = next((c for c in getattr(self.controller.restorer, "_checkpoints", {}).values()
                       if getattr(c, "checkpoint_id", None) == checkpoint_id), None)

        if not cp:
            return self._error("CHECKPOINT_NOT_FOUND", f"Checkpoint '{checkpoint_id}' not found", "RESTORE", t0)

        try:
            self.controller.restore(cp)
            return AgentActionResult(
                success=True,
                action="RESTORE",
                data={"restored": True, "checkpoint_id": checkpoint_id},
                performance={"total_ms": round((time.monotonic() - t0) * 1000, 3)}
            )
        except Exception as exc:
            return self._error("RUNTIME_ERROR", f"Restore failed: {exc}", "RESTORE", t0)

    # -------------------------------------------------------------------------
    # State Transition Execution & Inspection
    # -------------------------------------------------------------------------

    def execute_transition(self, candidate: Union[str, Dict[str, Any], AgentMutationCandidate],
                           timeout_ms: int = 1000) -> AgentActionResult:
        """Execute a state transition driven by a pre-validated MutationCandidate.

        Strict Safety Guarantee: Agent cannot pass arbitrary memory writes or raw addresses;
        mutations must map to a valid MutationCandidate targeting a verified semantic field.
        """
        t0 = time.monotonic()
        if getattr(self, "observation_mode", "CONSISTENT") == "LOW_IMPACT":
            return self._error("CAPABILITY_UNSUPPORTED", "Mutation and transitions are not supported in LOW_IMPACT observation mode", "EXECUTE_TRANSITION", t0)

        if not self.controller:
            return self._error("RUNTIME_ERROR", "No active runtime controller attached", "EXECUTE_TRANSITION", t0)

        # 1. Resolve candidate
        cand_obj: Optional[AgentMutationCandidate] = None
        if isinstance(candidate, str):
            cand_obj = self._cached_candidates.get(candidate)
            if not cand_obj:
                return self._error("INVALID_CANDIDATE", f"Candidate '{candidate}' not found in proposed candidates", "EXECUTE_TRANSITION", t0)
        elif isinstance(candidate, dict):
            cand_id = candidate.get("candidate_id")
            if cand_id and cand_id in self._cached_candidates:
                cand_obj = self._cached_candidates[cand_id]
            else:
                try:
                    cand_obj = AgentMutationCandidate.from_dict(candidate)
                except Exception as exc:
                    return self._error("INVALID_CANDIDATE", f"Malformed candidate dict: {exc}", "EXECUTE_TRANSITION", t0)
        elif isinstance(candidate, AgentMutationCandidate):
            cand_obj = candidate
        else:
            return self._error("INVALID_CANDIDATE", "Candidate must be candidate_id or candidate object", "EXECUTE_TRANSITION", t0)

        # 2. Execute transition through controller
        try:
            trans = self.controller.execute_transition(
                object_id=cand_obj.object_id,
                field_path=cand_obj.field,
                value=cand_obj.proposed_value,
                timeout_ms=timeout_ms
            )
        except Exception as exc:
            return self._error("RUNTIME_ERROR", f"Transition execution error: {exc}", "EXECUTE_TRANSITION", t0)

        # 3. Check for mutation rejection
        mut_res = trans.mutation if hasattr(trans, "mutation") else (trans.to_dict().get("mutation") or {})
        mut_success = mut_res.success if hasattr(mut_res, "success") else mut_res.get("success", False)
        if not mut_success:
            err_code = mut_res.error.get("code") if hasattr(mut_res, "error") and mut_res.error else "MUTATION_REJECTED"
            err_msg = mut_res.error.get("message") if hasattr(mut_res, "error") and mut_res.error else "Mutation rejected by runtime"
            return AgentActionResult(
                success=False,
                action="EXECUTE_TRANSITION",
                error=AgentActionError(code=err_code or "MUTATION_REJECTED", message=err_msg),
                performance={"total_ms": round((time.monotonic() - t0) * 1000, 3)}
            )

        # 4. Analyze transition into facts and evidence
        parent_state = None
        child_state = None
        if hasattr(trans, "parent_snapshot") and trans.parent_snapshot in self.controller.snapshots:
            p_snap = self.controller.snapshots[trans.parent_snapshot]
            parent_state = self.corpus.hash_to_state.get(compute_state_hash(p_snap))

        if hasattr(trans, "child_snapshot") and trans.child_snapshot and trans.child_snapshot in self.controller.snapshots:
            c_snap = self.controller.snapshots[trans.child_snapshot]
            child_state, _ = self.corpus.add(c_snap)

        agent_trans = self.analyzer.analyze(trans, parent_state=parent_state, child_state=child_state)

        # Track recently changed fields for future candidate ranking
        for f in agent_trans.facts.get("field_changed", []):
            self._recent_changed_fields.add(f)

        # Cache transition and register in corpus
        self._cached_transitions[agent_trans.transition_id] = trans
        self.corpus.add_transition(trans)

        elapsed = round((time.monotonic() - t0) * 1000, 3)
        return AgentActionResult(
            success=True,
            action="EXECUTE_TRANSITION",
            data=agent_trans,
            performance={"total_ms": elapsed}
        )

    def inspect_transition(self, transition_id: str) -> AgentActionResult:
        """Inspect semantic facts, diff, and evidence of a recorded transition."""
        t0 = time.monotonic()
        trans = self._cached_transitions.get(transition_id)
        if not trans:
            trans_dict = self.corpus.get_transition(transition_id)
            if not trans_dict:
                return self._error("TRANSITION_NOT_FOUND", f"Transition '{transition_id}' not found", "INSPECT_TRANSITION", t0)
            trans = trans_dict

        agent_trans = self.analyzer.analyze(trans)
        return AgentActionResult(
            success=True,
            action="INSPECT_TRANSITION",
            data=agent_trans,
            performance={"total_ms": round((time.monotonic() - t0) * 1000, 3)}
        )

    # -------------------------------------------------------------------------
    # State Corpus & Invariant Detection
    # -------------------------------------------------------------------------

    def list_states(self) -> AgentActionResult:
        """List all indexed states in the State Corpus."""
        t0 = time.monotonic()
        raw_list = self.corpus.list()
        states_summary = []
        if isinstance(raw_list, list):
            for meta in raw_list:
                states_summary.append({
                    "state_id": meta.get("state_id"),
                    "state_hash": meta.get("state_hash"),
                    "timestamp": meta.get("created_at") or meta.get("timestamp"),
                    "metadata": meta.get("metadata", {})
                })
        elif isinstance(raw_list, dict):
            for sid, meta in raw_list.get("states", {}).items():
                states_summary.append({
                    "state_id": sid,
                    "state_hash": meta.get("state_hash"),
                    "timestamp": meta.get("timestamp") or meta.get("created_at"),
                    "metadata": meta.get("metadata", {})
                })
        return AgentActionResult(
            success=True,
            action="LIST_STATES",
            data=states_summary,
            performance={"total_ms": round((time.monotonic() - t0) * 1000, 3)}
        )

    def inspect_state(self, state_id: str) -> AgentActionResult:
        """Inspect a specific state from the corpus."""
        t0 = time.monotonic()
        state_data = self.corpus.get(state_id)
        if state_data is None:
            return self._error("STATE_NOT_FOUND", f"State '{state_id}' not found in corpus", "INSPECT_STATE", t0)

        context = self._build_context(state_data, state_id=state_id)
        return AgentActionResult(
            success=True,
            action="INSPECT_STATE",
            data=context,
            performance={"total_ms": round((time.monotonic() - t0) * 1000, 3)}
        )

    def state_hash(self, snapshot_id: Optional[str] = None) -> AgentActionResult:
        """Compute or retrieve the SHA-256 semantic state hash."""
        t0 = time.monotonic()
        snap, err = self._resolve_snapshot(snapshot_id)
        if err:
            return self._error(err[0], err[1], "STATE_HASH", t0)

        h = compute_state_hash(snap)
        return AgentActionResult(
            success=True,
            action="STATE_HASH",
            data={"state_hash": h, "snapshot_id": snap.snapshot_id if hasattr(snap, "snapshot_id") else snap.get("snapshot_id")},
            performance={"total_ms": round((time.monotonic() - t0) * 1000, 3)}
        )

    def detect_invariant_candidates(self, snapshot_id: Optional[str] = None) -> AgentActionResult:
        """Propose structural and numeric invariant candidates from observed state."""
        t0 = time.monotonic()
        snap, err = self._resolve_snapshot(snapshot_id)
        if err:
            return self._error(err[0], err[1], "DETECT_INVARIANTS", t0)

        candidates = self.invariant_detector.detect(snap)
        return AgentActionResult(
            success=True,
            action="DETECT_INVARIANTS",
            data=candidates,
            performance={"total_ms": round((time.monotonic() - t0) * 1000, 3)}
        )

    # -------------------------------------------------------------------------
    # State Exploration Loop
    # -------------------------------------------------------------------------

    def explore(self, max_steps: int = 10, timeout_ms: int = 1000,
                max_states: int = 20) -> AgentActionResult:
        """Run the autonomous branch-safe state exploration loop."""
        t0 = time.monotonic()
        if not self.controller:
            return self._error("RUNTIME_ERROR", "No active runtime controller attached", "EXPLORE", t0)

        # Enforce safety limits
        max_steps = min(max_steps, 50)
        timeout_ms = min(timeout_ms, 5000)

        try:
            result = self.controller.explore(
                max_steps=max_steps,
                timeout_ms=timeout_ms,
                corpus_dir=self.corpus_dir
            )
            summary = result.get("summary", {})
            agent_result = AgentExplorationResult(
                exploration_id=result.get("exploration_id", "E001"),
                seed_state=result.get("seed_state_id", "state_000001"),
                steps=result.get("steps", result.get("executed_count", summary.get("executed", 0))),
                new_states=summary.get("new_states", result.get("new_state_count", 0)),
                new_transitions=summary.get("executed", result.get("executed_count", 0)),
                crashes=summary.get("crashes", result.get("crash_count", 0)),
                timeouts=summary.get("timeouts", result.get("timeout_count", 0)),
                corpus_summary=result.get("corpus_status", {})
            )
            return AgentActionResult(
                success=True,
                action="EXPLORE",
                data=agent_result,
                performance={"total_ms": round((time.monotonic() - t0) * 1000, 3)}
            )
        except Exception as exc:
            return self._error("RUNTIME_ERROR", f"Exploration failed: {exc}", "EXPLORE", t0)

    # -------------------------------------------------------------------------
    # Capabilities & System Info
    # -------------------------------------------------------------------------

    def capabilities(self) -> AgentActionResult:
        """Return runtime capabilities and technical exploration limits."""
        t0 = time.monotonic()
        caps = {}
        if self.controller and hasattr(self.controller, "get_capabilities"):
            caps = self.controller.get_capabilities()

        res = {
            "runtime": {
                "snapshot": caps.get("semantic_snapshot", True),
                "mutation": caps.get("typed_mutation", True),
                "transition": True,
                "checkpoint": caps.get("checkpoint", True),
                "restore": caps.get("restore", True),
                "exploration": caps.get("branch_exploration", True),
                "state_hash": caps.get("state_hash", True),
                "crash_recovery": caps.get("crash_recovery", True),
                "timeout_recovery": caps.get("timeout_recovery", True),
            },
            "observation": caps.get("observation", {
                "gdb_consistent": True,
                "low_impact_memory_snapshot": True,
                "offline_semantic_analysis": True,
            }),
            "memory_snapshot": caps.get("memory_snapshot", {
                "process_vm_readv": True,
                "partial_read": True,
                "stack": True,
                "heap": True,
                "global": True,
                "all_readable": True,
            }),
            "debug": {
                "external_debug_image": caps.get("external_debug_image", True),
                "build_id_verification": True,
            },
            "mutation": {
                "integer": True,
                "boolean": True,
                "enum": True,
                "float": True,
                "pointer_null": True,
            },
            "limits": {
                "max_steps": 50,
                "max_timeout_ms": 5000,
                "max_candidates": 50,
                "max_corpus_states": 100,
            }
        }
        return AgentActionResult(
            success=True,
            action="GET_CAPABILITIES",
            data=res,
            performance={"total_ms": round((time.monotonic() - t0) * 1000, 3)}
        )

    # -------------------------------------------------------------------------
    # Low-Impact Memory Snapshot Operations (Phase 5.1)
    # -------------------------------------------------------------------------

    def capture_memory_snapshot(
        self,
        pid: int,
        policy: str = "ALL_READABLE",
        max_bytes: Optional[int] = None,
        timeout_ms: int = 2000,
        output_dir: Optional[str] = None,
        snapshot_id: Optional[str] = None
    ) -> AgentActionResult:
        """Capture memory regions from target process without halting it via process_vm_readv."""
        t0 = time.monotonic()
        from .memory_capture import MemoryCapture
        if self._memory_capturer is None:
            self._memory_capturer = MemoryCapture()

        if not self._memory_capturer.is_supported:
            return self._error("CAPABILITY_UNSUPPORTED", "process_vm_readv is not supported on this platform", "MEMORY_SNAPSHOT", t0)

        sid = snapshot_id or "M{:04d}".format(int(time.time() * 1000) % 10000)
        target_dir = output_dir or os.path.join(self.raw_snapshots_dir, sid)

        try:
            kwargs: Dict[str, Any] = {
                "pid": pid,
                "policy": policy,
                "output_dir": target_dir,
                "timeout_ms": timeout_ms,
                "snapshot_id": sid,
            }
            if max_bytes is not None:
                kwargs["max_bytes"] = max_bytes

            raw_snap = self._memory_capturer.capture(**kwargs)
            self.memory_snapshots[sid] = raw_snap
            elapsed = round((time.monotonic() - t0) * 1000, 3)

            return AgentActionResult(
                success=True,
                action="MEMORY_SNAPSHOT",
                data=raw_snap.to_metadata(),
                performance={"total_ms": elapsed, "capture_duration_us": raw_snap.duration_us}
            )
        except ProcessLookupError as exc:
            return self._error("MEMORY_CAPTURE_FAILED", f"Target process not found: {exc}", "MEMORY_SNAPSHOT", t0)
        except PermissionError as exc:
            return self._error("MEMORY_CAPTURE_FAILED", f"Permission denied capturing process: {exc}", "MEMORY_SNAPSHOT", t0)
        except Exception as exc:
            return self._error("MEMORY_CAPTURE_FAILED", str(exc), "MEMORY_SNAPSHOT", t0)

    def analyze_memory_snapshot(
        self,
        memory_snapshot_id: str,
        debug_image: Optional[str] = None,
        output: Optional[str] = None
    ) -> AgentActionResult:
        """Perform offline semantic reconstruction on captured memory without inferior connection."""
        t0 = time.monotonic()
        from .offline_analyzer import OfflineMemoryAnalyzer
        if self._offline_analyzer is None:
            self._offline_analyzer = OfflineMemoryAnalyzer()

        # 1. Resolve raw memory snapshot
        raw_snap = self._resolve_raw_memory_snapshot(memory_snapshot_id)
        if raw_snap is None:
            return self._error("SNAPSHOT_NOT_FOUND", f"Memory snapshot '{memory_snapshot_id}' not found", "ANALYZE_MEMORY_SNAPSHOT", t0)

        # 2. Resolve external debug image
        dimg_path = debug_image
        if not dimg_path and self.controller and hasattr(self.controller, "debug_image_path"):
            dimg_path = self.controller.debug_image_path
        if not dimg_path:
            return self._error("INVALID_FIELD", "debug_image path is required for offline analysis", "ANALYZE_MEMORY_SNAPSHOT", t0)

        try:
            semantic_snap = self._offline_analyzer.analyze(raw_snap, dimg_path)
            if output:
                os.makedirs(os.path.dirname(os.path.abspath(output)), exist_ok=True)
                semantic_snap.write_json(output)

            if self.controller and hasattr(self.controller, "snapshots"):
                self.controller.snapshots[semantic_snap.snapshot_id] = semantic_snap

            context = self._build_context(semantic_snap)
            elapsed = round((time.monotonic() - t0) * 1000, 3)

            return AgentActionResult(
                success=True,
                action="ANALYZE_MEMORY_SNAPSHOT",
                data=context,
                performance={"total_ms": elapsed, "agent_context_generation_ms": elapsed}
            )
        except Exception as exc:
            return self._error("RUNTIME_ERROR", f"Offline analysis failed: {exc}", "ANALYZE_MEMORY_SNAPSHOT", t0)

    def get_memory_snapshot(self, memory_snapshot_id: str) -> AgentActionResult:
        """Inspect a raw memory snapshot manifest and metadata."""
        t0 = time.monotonic()
        raw_snap = self._resolve_raw_memory_snapshot(memory_snapshot_id)
        if raw_snap is None:
            return self._error("SNAPSHOT_NOT_FOUND", f"Memory snapshot '{memory_snapshot_id}' not found", "GET_MEMORY_SNAPSHOT", t0)

        return AgentActionResult(
            success=True,
            action="GET_MEMORY_SNAPSHOT",
            data=raw_snap.to_dict(),
            performance={"total_ms": round((time.monotonic() - t0) * 1000, 3)}
        )

    def _resolve_raw_memory_snapshot(self, target: str) -> Optional[Any]:
        """Resolve a RawMemorySnapshot by ID or path."""
        from .memory_snapshot import RawMemorySnapshot
        if target in self.memory_snapshots:
            return self.memory_snapshots[target]
        if os.path.exists(target):
            try:
                snap = RawMemorySnapshot.load(target)
                self.memory_snapshots[snap.snapshot_id] = snap
                return snap
            except Exception:
                pass
        potential_dir = os.path.join(self.raw_snapshots_dir, target)
        if os.path.exists(potential_dir):
            try:
                snap = RawMemorySnapshot.load(potential_dir)
                self.memory_snapshots[target] = snap
                return snap
            except Exception:
                pass
        for root_dir in [self.raw_snapshots_dir, self.corpus_dir]:
            if root_dir and os.path.exists(root_dir):
                try:
                    for entry in os.listdir(root_dir):
                        sub = os.path.join(root_dir, entry)
                        if os.path.isdir(sub) and os.path.exists(os.path.join(sub, "metadata.json")):
                            try:
                                s = RawMemorySnapshot.load(sub)
                                self.memory_snapshots[s.snapshot_id] = s
                                if s.snapshot_id == target:
                                    return s
                            except Exception:
                                continue
                except Exception:
                    pass
        return None

    # -------------------------------------------------------------------------
    # Helper & Context Building Methods
    # -------------------------------------------------------------------------

    def _build_context(self, snap: Any, state_id: Optional[str] = None) -> AgentStateContext:
        """Construct a compact AgentStateContext from a raw snapshot."""
        s_data = snap.to_dict() if hasattr(snap, "to_dict") else dict(snap)
        s_inner = s_data.get("snapshot", s_data)

        snap_id = s_data.get("snapshot_id") or s_inner.get("snapshot_id", "S_UNKNOWN")

        # 1. Execution summary
        exec_data = s_data.get("execution") or s_inner.get("execution") or {}
        threads = exec_data.get("threads") or []
        top_frame: Dict[str, Any] = {}
        top_thread_id = 1
        if threads:
            top_thread = threads[0]
            top_thread_id = top_thread.get("thread_id", 1)
            frames = top_thread.get("frames") or []
            if frames:
                top_frame = frames[0]

        exec_summary = {
            "thread_id": top_thread_id,
            "function": top_frame.get("function", "<unknown>"),
            "frame_level": top_frame.get("level", 0),
            "location": top_frame.get("location"),
            "pc": top_frame.get("pc"),
        }

        # 2. Objects summary
        objects_data = self._get_objects_from_snapshot(s_data)
        object_summaries: List[Dict[str, Any]] = []
        for obj in objects_data[:10]:  # Top 10 objects for compact context
            field_dict = {}
            for f in obj.get("fields", []):
                val = f.get("value")
                if val is not None:
                    field_dict[f.get("name")] = val
                elif f.get("object_ref"):
                    field_dict[f.get("name")] = f.get("object_ref")
            object_summaries.append({
                "object_id": obj.get("object_id"),
                "type": obj.get("type"),
                "storage": obj.get("storage"),
                "fields": field_dict
            })

        # 3. Statistics
        persistent = s_data.get("persistent") or s_inner.get("persistent") or {}
        stats = persistent.get("statistics") or {}
        stats_summary = {
            "object_count": stats.get("object_count", len(objects_data)),
            "root_count": stats.get("root_count", len(persistent.get("roots", []))),
            "edge_count": stats.get("edge_count", 0),
        }

        # 4. State Hash & Provenance
        h = compute_state_hash(snap)
        prov = s_data.get("provenance") or s_inner.get("provenance")

        return AgentStateContext(
            snapshot_id=snap_id,
            state_id=state_id or self.corpus.hash_to_state.get(h),
            state_hash=h,
            execution=exec_summary,
            objects=object_summaries,
            statistics=stats_summary,
            provenance=prov
        )

    def _resolve_snapshot(self, snapshot_id: Optional[str]) -> Tuple[Optional[Any], Optional[Tuple[str, str]]]:
        """Resolve a snapshot from controller or corpus."""
        if snapshot_id:
            if self.controller and snapshot_id in self.controller.snapshots:
                return self.controller.snapshots[snapshot_id], None
            c_snap = self.corpus.get(snapshot_id)
            if c_snap:
                return c_snap, None
            return None, ("SNAPSHOT_NOT_FOUND", f"Snapshot '{snapshot_id}' not found")

        # Default to latest controller snapshot
        if self.controller:
            if self.controller._latest:
                return self.controller._latest, None
            try:
                snap = self.controller.observe()
                if snap:
                    return snap, None
            except Exception:
                pass
        return None, ("SNAPSHOT_NOT_FOUND", "No active snapshot available")

    @staticmethod
    def _get_objects_from_snapshot(snap: Any) -> List[Dict[str, Any]]:
        s_data = snap.to_dict() if hasattr(snap, "to_dict") else dict(snap)
        s_inner = s_data.get("snapshot", s_data)
        persistent = s_data.get("persistent") or s_inner.get("persistent") or {}
        return persistent.get("objects") or s_data.get("objects") or []

    @staticmethod
    def _error(code: str, message: str, action: str, t_start: float) -> AgentActionResult:
        return AgentActionResult(
            success=False,
            action=action,
            data=None,
            error=AgentActionError(code=code, message=message),
            performance={"total_ms": round((time.monotonic() - t_start) * 1000, 3)}
        )

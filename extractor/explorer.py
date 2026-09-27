"""Runtime State Exploration Engine and Mutation Candidate Generator for Phase 4."""

from dataclasses import asdict, dataclass
import time
from typing import Any, Dict, List, Optional

from .runtime_controller import RuntimeController
from .snapshot import RuntimeSnapshot, StateTransition
from .state_corpus import StateCorpus, StateInterestingness, compute_state_hash


@dataclass
class MutationCandidate:
    candidate_id: str
    snapshot_id: str
    object_id: str
    field_path: str
    current_value: Any
    proposed_value: Any
    type: str
    reason: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class StateExplorer:
    """Systematic deterministic state exploration loop."""

    def __init__(self, controller: RuntimeController, corpus: Optional[StateCorpus] = None,
                 corpus_dir: str = "corpus"):
        self.controller = controller
        self.corpus = corpus or StateCorpus(corpus_dir)
        self.corpus_dir = corpus_dir
        self._candidate_counter = 0
        self._exploration_counter = 0
        self.seed_snapshot: Optional[RuntimeSnapshot] = None
        self.seed_state_id: Optional[str] = None

    def seed(self, snapshot: Optional[RuntimeSnapshot] = None, metadata: Optional[Dict[str, Any]] = None) -> str:
        """Initialize the exploration with a seed snapshot."""
        if snapshot is None:
            snapshot = self.controller.observe()
        if snapshot is None:
            snapshot = self.controller.snapshot()
        self.seed_snapshot = snapshot
        state_id, _ = self.corpus.add(snapshot, metadata=metadata or {"role": "seed"})
        self.seed_state_id = state_id
        return state_id

    def propose_mutations(self, snapshot: Optional[RuntimeSnapshot] = None) -> List[MutationCandidate]:
        """Propose deterministic rule-based mutation candidates from a snapshot."""
        snap = snapshot or self.seed_snapshot or self.controller.observe()
        if snap is None:
            return []
        snap_dict = snap.to_dict() if hasattr(snap, "to_dict") else snap
        snap_id = (snap_dict.get("snapshot") or {}).get("snapshot_id") or "S_UNKNOWN"
        persistent = snap_dict.get("persistent") or {}
        objects = persistent.get("objects", [])

        candidates: List[MutationCandidate] = []

        for obj in objects:
            obj_id = obj.get("object_id")
            for f in obj.get("fields", []):
                fname = f.get("name")
                ftype = str(f.get("type", ""))
                val = f.get("value")
                avail = f.get("availability")
                if avail and avail != "available":
                    continue

                # 1. Pointer fields
                if ftype.endswith("*") or "pointer" in ftype.lower():
                    if val not in ("0x0", "null", "nullptr", None, 0):
                        self._candidate_counter += 1
                        candidates.append(MutationCandidate(
                            candidate_id="M{:04d}".format(self._candidate_counter),
                            snapshot_id=snap_id,
                            object_id=obj_id,
                            field_path=fname,
                            current_value=val,
                            proposed_value="null",
                            type=ftype,
                            reason="NULL_POINTER"
                        ))
                    continue

                # 2. Boolean fields
                if "bool" in ftype.lower():
                    is_true = val in (1, True, "true", "1")
                    new_val = False if is_true else True
                    self._candidate_counter += 1
                    candidates.append(MutationCandidate(
                        candidate_id="M{:04d}".format(self._candidate_counter),
                        snapshot_id=snap_id,
                        object_id=obj_id,
                        field_path=fname,
                        current_value=val,
                        proposed_value=new_val,
                        type=ftype,
                        reason="BOOLEAN_TOGGLE"
                    ))
                    continue

                # 3. Floating point fields
                if "float" in ftype.lower() or "double" in ftype.lower():
                    try:
                        fval = float(val)
                    except (ValueError, TypeError):
                        fval = 0.0
                    for proposed, r in [(0.0, "FLOAT_ZERO"), (1.0, "FLOAT_ONE"), (-1.0, "FLOAT_MINUS_ONE")]:
                        if proposed != fval:
                            self._candidate_counter += 1
                            candidates.append(MutationCandidate(
                                candidate_id="M{:04d}".format(self._candidate_counter),
                                snapshot_id=snap_id,
                                object_id=obj_id,
                                field_path=fname,
                                current_value=fval,
                                proposed_value=proposed,
                                type=ftype,
                                reason=r
                            ))
                    continue

                # 4. Integer / Enum fields
                try:
                    num = int(val)
                except (ValueError, TypeError):
                    continue

                # Determine bitwidth and signedness
                is_uint8 = "uint8" in ftype
                low_bound = 0 if "uint" in ftype or "unsigned" in ftype else -2147483648
                high_bound = 255 if is_uint8 else (65535 if "uint16" in ftype else 4294967295)

                proposals = []
                if num + 1 <= high_bound:
                    proposals.append((num + 1, "BOUNDARY_PLUS_ONE"))
                if num - 1 >= low_bound:
                    proposals.append((num - 1, "BOUNDARY_MINUS_ONE"))
                if num != 0 and 0 >= low_bound:
                    proposals.append((0, "ZERO_BOUNDARY"))
                if num != 1 and 1 <= high_bound:
                    proposals.append((1, "ONE_VALUE"))

                for pval, r in proposals:
                    self._candidate_counter += 1
                    candidates.append(MutationCandidate(
                        candidate_id="M{:04d}".format(self._candidate_counter),
                        snapshot_id=snap_id,
                        object_id=obj_id,
                        field_path=fname,
                        current_value=num,
                        proposed_value=pval,
                        type=ftype,
                        reason=r
                    ))

        return candidates

    def execute(self, candidate: MutationCandidate, timeout_ms: int = 1000) -> StateTransition:
        """Execute state transition corresponding to a proposed candidate."""
        return self.controller.execute_transition(
            object_id=candidate.object_id,
            field_path=candidate.field_path,
            value=candidate.proposed_value,
            timeout_ms=timeout_ms
        )

    def evaluate(self, transition: StateTransition, child_snapshot: Optional[Any] = None) -> Dict[str, Any]:
        """Evaluate interestingness of transition result."""
        is_new_hash = False
        if child_snapshot:
            child_hash = compute_state_hash(child_snapshot)
            is_new_hash = not self.corpus.contains(child_hash)
        return StateInterestingness.evaluate(
            parent_snapshot=None,
            child_snapshot=child_snapshot,
            transition=transition,
            is_new_hash=is_new_hash
        )

    def run(self, max_steps: int = 10, timeout_ms: int = 1000) -> Dict[str, Any]:
        """Run exploration loop up to max_steps."""
        t_start = time.monotonic()
        self._exploration_counter += 1
        eid = "E{:03d}".format(self._exploration_counter)

        if not self.seed_state_id:
            self.seed()

        t_cand_start = time.monotonic()
        candidates = self.propose_mutations()
        cand_ms = round((time.monotonic() - t_cand_start) * 1000, 3)

        executed_count = 0
        new_states_count = 0
        dup_states_count = 0
        crashes_count = 0
        timeouts_count = 0

        states_discovered = [self.seed_state_id]
        transitions_executed = []
        step_metrics = []

        to_execute = candidates[:max_steps]

        for cand in to_execute:
            t_step_start = time.monotonic()
            trans = self.execute(cand, timeout_ms=timeout_ms)
            step_ms = round((time.monotonic() - t_step_start) * 1000, 3)

            executed_count += 1
            tid = self.corpus.add_transition(trans)
            transitions_executed.append(tid)

            t_status = trans.execution.status if hasattr(trans.execution, "status") else trans.execution.get("status")

            if t_status == "CRASHED":
                crashes_count += 1
            elif t_status == "TIMEOUT":
                timeouts_count += 1
            elif t_status == "STOPPED":
                # Check child snapshot if available in controller
                child_id = trans.child_snapshot
                child_snap = self.controller.snapshots.get(child_id) if child_id else None
                if child_snap:
                    eval_res = self.evaluate(trans, child_snapshot=child_snap)
                    sid, is_new = self.corpus.add(child_snap, metadata={
                        "transition_id": tid,
                        "candidate_id": cand.candidate_id,
                        "interesting_reasons": eval_res.get("reasons", [])
                    })
                    if is_new:
                        new_states_count += 1
                        states_discovered.append(sid)
                    else:
                        dup_states_count += 1
                else:
                    dup_states_count += 1

            step_metrics.append({
                "candidate_id": cand.candidate_id,
                "transition_id": tid,
                "step_ms": step_ms,
                "status": t_status
            })

        total_time_ms = round((time.monotonic() - t_start) * 1000, 3)
        avg_step_ms = round(total_time_ms / max(1, executed_count), 3)

        return {
            "exploration_id": eid,
            "seed_state": self.seed_state_id,
            "steps": executed_count,
            "summary": {
                "candidates": len(candidates),
                "executed": executed_count,
                "new_states": new_states_count,
                "duplicate_states": dup_states_count,
                "crashes": crashes_count,
                "timeouts": timeouts_count
            },
            "performance": {
                "candidate_generation_ms": cand_ms,
                "total_time_ms": total_time_ms,
                "avg_step_ms": avg_step_ms,
                "step_metrics": step_metrics
            },
            "states": states_discovered,
            "transitions": transitions_executed
        }

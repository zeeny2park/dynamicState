"""Runtime State Exploration Engine and Mutation Candidate Generator for Phase 4."""

from dataclasses import asdict, dataclass
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from .runtime_controller import RuntimeController
from .snapshot import RuntimeSnapshot, StateTransition
from .state_corpus import StateCorpus, StateInterestingness
from .state_hash import compute_state_hash


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


def _infer_integer_bounds(ftype: str) -> Tuple[int, int]:
    """Infer integer bounds (min, max) from DWARF type string."""
    f = ftype.lower().strip()
    # Unsigned types
    if "uint8" in f or ("unsigned" in f and "char" in f):
        return 0, 255
    if "uint16" in f or ("unsigned" in f and "short" in f):
        return 0, 65535
    if "uint32" in f or ("unsigned" in f and ("int" in f or "long" in f and "long long" not in f)):
        return 0, 4294967295
    if "uint64" in f or ("unsigned" in f and "long long" in f):
        return 0, 18446744073709551615

    # Signed types
    if "int8" in f or ("signed" in f and "char" in f):
        return -128, 127
    if "int16" in f or ("short" in f and "unsigned" not in f):
        return -32768, 32767
    if "int64" in f or ("long long" in f and "unsigned" not in f):
        return -9223372036854775808, 9223372036854775807
    if "int32" in f or ("int" in f and "unsigned" not in f):
        return -2147483648, 2147483647

    # Default fallback to 32-bit signed
    return -2147483648, 2147483647


class StateExplorer:
    """Systematic deterministic branch-safe state exploration loop."""

    # Default known enum members when GDB type reflection is not directly accessible
    KNOWN_ENUMS = {
        "SessionState": ["DISCONNECTED", "CONNECTED", "ERROR"],
        "enum SessionState": ["DISCONNECTED", "CONNECTED", "ERROR"],
    }

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

    def _get_enum_members(self, ftype: str) -> List[str]:
        """Resolve enum member names via controller/types or fallback registry."""
        cleaned = ftype.replace("enum class ", "").replace("enum ", "").strip()
        # 1. Try controller types reflection if available
        if hasattr(self.controller, "types") and hasattr(self.controller, "gdb"):
            try:
                gdb_type = self.controller.gdb.lookup_type(ftype)
                members = self.controller.types.enum_members(gdb_type)
                if members:
                    return members
            except Exception:
                try:
                    gdb_type = self.controller.gdb.lookup_type("enum " + cleaned)
                    members = self.controller.types.enum_members(gdb_type)
                    if members:
                        return members
                except Exception:
                    pass

        # 2. Try KNOWN_ENUMS table
        return self.KNOWN_ENUMS.get(ftype) or self.KNOWN_ENUMS.get(cleaned) or []

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

                # 1. Pointer fields: only nullptr / null is permitted in Phase 4
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

                # 2. Boolean fields: toggle
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

                # 3. Enum fields: propose alternate symbolic enum members
                enum_members = self._get_enum_members(ftype)
                if enum_members or "enum" in ftype.lower():
                    cur_str = str(val).rsplit("::", 1)[-1]
                    for member in enum_members:
                        m_clean = member.rsplit("::", 1)[-1]
                        if m_clean != cur_str:
                            self._candidate_counter += 1
                            candidates.append(MutationCandidate(
                                candidate_id="M{:04d}".format(self._candidate_counter),
                                snapshot_id=snap_id,
                                object_id=obj_id,
                                field_path=fname,
                                current_value=val,
                                proposed_value=m_clean,
                                type=ftype,
                                reason="ENUM_MEMBER"
                            ))
                    if enum_members:
                        continue

                # 4. Floating point fields: finite values only
                if "float" in ftype.lower() or "double" in ftype.lower():
                    try:
                        fval = float(val)
                    except (ValueError, TypeError):
                        fval = 0.0
                    for proposed, r in [
                        (0.0, "FLOAT_ZERO"),
                        (1.0, "FLOAT_ONE"),
                        (-1.0, "FLOAT_MINUS_ONE"),
                        (fval - 1.0, "FLOAT_MINUS_STEP"),
                        (fval + 1.0, "FLOAT_PLUS_STEP")
                    ]:
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

                # 5. Integer fields: type-width-aware boundaries
                try:
                    num = int(val)
                except (ValueError, TypeError):
                    continue

                low_bound, high_bound = _infer_integer_bounds(ftype)
                is_signed = low_bound < 0

                proposals: List[Tuple[int, str]] = []
                # current - 1
                if num - 1 >= low_bound:
                    proposals.append((num - 1, "BOUNDARY_MINUS_ONE"))
                # current + 1
                if num + 1 <= high_bound:
                    proposals.append((num + 1, "BOUNDARY_PLUS_ONE"))
                # 0
                if num != 0 and low_bound <= 0 <= high_bound:
                    proposals.append((0, "ZERO_BOUNDARY"))
                # 1
                if num != 1 and low_bound <= 1 <= high_bound:
                    proposals.append((1, "ONE_VALUE"))
                # MAX
                if num != high_bound:
                    proposals.append((high_bound, "MAX_BOUNDARY"))
                # MIN (for signed integers)
                if is_signed and num != low_bound:
                    proposals.append((low_bound, "MIN_BOUNDARY"))

                # Eliminate duplicates while preserving proposal ordering
                seen_vals: Set[int] = set()
                for pval, r in proposals:
                    if pval not in seen_vals:
                        seen_vals.add(pval)
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
        """Run branch-safe exploration loop up to max_steps.

        Enforces the core Phase 4 invariant: every candidate mutation executes
        independently from the exact same parent runtime checkpoint.
        """
        t_start = time.monotonic()
        self._exploration_counter += 1
        eid = "E{:06d}".format(self._exploration_counter)

        if not self.seed_state_id:
            self.seed()

        parent_snapshot = self.seed_snapshot
        parent_snap_dict = parent_snapshot.to_dict() if hasattr(parent_snapshot, "to_dict") else parent_snapshot
        parent_snap_id = (parent_snap_dict.get("snapshot") or {}).get("snapshot_id") or "S_PARENT"

        # 1. Capture pristine Parent Runtime Checkpoint
        t_cp_start = time.monotonic()
        parent_checkpoint = self.controller.checkpoint()
        checkpoint_ms = round((time.monotonic() - t_cp_start) * 1000, 3)

        t_cand_start = time.monotonic()
        candidates = self.propose_mutations(parent_snapshot)
        cand_ms = round((time.monotonic() - t_cand_start) * 1000, 3)

        to_execute = candidates[:max_steps]

        executed_count = 0
        new_states_count = 0
        dup_states_count = 0
        crashes_count = 0
        timeouts_count = 0

        states_discovered = [self.seed_state_id]
        transitions_executed = []
        step_metrics = []

        try:
            for cand in to_execute:
                t_step_start = time.monotonic()

                # CRITICAL BRANCH-SAFE INVARIANT:
                # Restore parent checkpoint before every candidate execution!
                t_rest_start = time.monotonic()
                self.controller.restore(parent_checkpoint)
                restore_ms = round((time.monotonic() - t_rest_start) * 1000, 3)

                # Execute transition from the restored parent state
                trans = self.execute(cand, timeout_ms=timeout_ms)
                step_ms = round((time.monotonic() - t_step_start) * 1000, 3)

                executed_count += 1
                tid = self.corpus.add_transition(trans)
                transitions_executed.append(tid)

                t_status = trans.execution.status if hasattr(trans.execution, "status") else trans.execution.get("status")

                child_state_id = None
                is_interesting = False
                eval_reasons = []

                if t_status == "CRASHED":
                    crashes_count += 1
                    eval_reasons = ["CRASH"]
                    is_interesting = True
                elif t_status == "TIMEOUT":
                    timeouts_count += 1
                    eval_reasons = ["TIMEOUT"]
                    is_interesting = True
                elif t_status == "STOPPED":
                    child_id = trans.child_snapshot
                    child_snap = self.controller.snapshots.get(child_id) if child_id else None
                    if child_snap:
                        eval_res = self.evaluate(trans, child_snapshot=child_snap)
                        is_interesting = eval_res.get("interesting", False)
                        eval_reasons = eval_res.get("reasons", [])
                        child_hash = compute_state_hash(child_snap)
                        sid, is_new = self.corpus.add(child_snap, metadata={
                            "state_hash": child_hash,
                            "parent_state_id": self.seed_state_id,
                            "parent_snapshot_id": parent_snap_id,
                            "transition_id": tid,
                            "candidate_id": cand.candidate_id,
                            "interesting": is_interesting,
                            "interesting_reasons": eval_reasons,
                        })
                        child_state_id = sid
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
                    "target_object": cand.object_id,
                    "field_path": cand.field_path,
                    "proposed_value": cand.proposed_value,
                    "restore_ms": restore_ms,
                    "step_ms": step_ms,
                    "status": t_status,
                    "child_state_id": child_state_id,
                    "interesting": is_interesting,
                    "reasons": eval_reasons
                })
        finally:
            # Clean up parent checkpoint resources
            self.controller.release_checkpoint(parent_checkpoint)

        total_time_ms = round((time.monotonic() - t_start) * 1000, 3)
        avg_step_ms = round(total_time_ms / max(1, executed_count), 3)

        artifact = {
            "exploration_id": eid,
            "seed_state_id": self.seed_state_id,
            "seed_snapshot_id": parent_snap_id,
            "parent_checkpoint_id": parent_checkpoint.checkpoint_id,
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
                "checkpoint_creation_ms": checkpoint_ms,
                "candidate_generation_ms": cand_ms,
                "total_time_ms": total_time_ms,
                "avg_step_ms": avg_step_ms,
                "step_metrics": step_metrics
            },
            "states": states_discovered,
            "transitions": transitions_executed,
            "new_states": [s for s in states_discovered if s != self.seed_state_id],
            "interesting_states": [m["child_state_id"] for m in step_metrics if m.get("interesting") and m.get("child_state_id")],
            "crashes": [m["transition_id"] for m in step_metrics if m.get("status") == "CRASHED"],
            "timeouts": [m["transition_id"] for m in step_metrics if m.get("status") == "TIMEOUT"]
        }

        # Save exploration artifact to corpus/explorations/
        self.corpus.add_exploration(artifact)

        return artifact

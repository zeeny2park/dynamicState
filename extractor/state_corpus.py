"""Runtime State Corpus and semantic state hashing for Phase 4."""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import os
from typing import Any, Dict, List, Optional, Tuple

from .state_hash import compute_state_hash


class StateInterestingness:
    """Evaluates whether a state transition or resulting state is interesting."""

    @staticmethod
    def evaluate(parent_snapshot: Any, child_snapshot: Any, transition: Any,
                 is_new_hash: bool = False) -> Dict[str, Any]:
        reasons = []

        # 1. New semantic state discovered
        if is_new_hash:
            reasons.append("NEW_STATE")

        # 2. Crash or timeout observed
        t_data = transition.to_dict() if hasattr(transition, "to_dict") else transition
        exec_info = t_data.get("execution") or {}
        exec_status = exec_info.get("status")
        if exec_status == "CRASHED":
            reasons.append("CRASH")
        elif exec_status == "TIMEOUT":
            reasons.append("TIMEOUT")

        # 3. Semantic Diff changes
        diff_info = t_data.get("diff") or {}
        summary = diff_info.get("summary") or {}

        if summary.get("objects_created", 0) > 0:
            reasons.append("NEW_OBJECT")
        if summary.get("objects_removed", 0) > 0:
            reasons.append("OBJECT_REMOVED")
        if summary.get("reference_changes", 0) > 0:
            reasons.append("REFERENCE_CHANGED")
        if summary.get("value_changes", 0) > 0:
            reasons.append("VALUE_CHANGE")
        if summary.get("execution_changes", 0) > 0:
            reasons.append("EXECUTION_CHANGE")

        return {
            "interesting": len(reasons) > 0,
            "reasons": sorted(list(set(reasons)))
        }


class StateCorpus:
    """Manages persistent interesting runtime states, transitions, and explorations."""

    def __init__(self, corpus_dir: str = "corpus"):
        self.corpus_dir = os.path.abspath(corpus_dir)
        self.states_dir = os.path.join(self.corpus_dir, "states")
        self.transitions_dir = os.path.join(self.corpus_dir, "transitions")
        self.explorations_dir = os.path.join(self.corpus_dir, "explorations")
        self.index_file = os.path.join(self.corpus_dir, "index.json")

        self.states: Dict[str, Dict[str, Any]] = {}
        self.hash_to_state: Dict[str, str] = {}
        self.transitions: List[str] = []
        self.explorations: List[str] = []
        self._counter = 0

        self._ensure_dirs()
        self.load()

    def _ensure_dirs(self) -> None:
        os.makedirs(self.states_dir, exist_ok=True)
        os.makedirs(self.transitions_dir, exist_ok=True)
        os.makedirs(self.explorations_dir, exist_ok=True)

    def add(self, snapshot: Any, metadata: Optional[Dict[str, Any]] = None) -> Tuple[str, bool]:
        """Add a snapshot to corpus.

        Returns (state_id, is_new). If state_hash already exists, deduplicates and
        records observation.
        """
        snap_dict = snapshot.to_dict() if hasattr(snapshot, "to_dict") else snapshot
        s_hash = compute_state_hash(snap_dict)
        snapshot_id = snap_dict.get("snapshot_id") or (snap_dict.get("snapshot") or {}).get("snapshot_id") or "S_UNKNOWN"

        if s_hash in self.hash_to_state:
            state_id = self.hash_to_state[s_hash]
            record = self.states[state_id]
            if snapshot_id not in record.setdefault("observations", []):
                record["observations"].append(snapshot_id)
            self.save()
            return state_id, False

        self._counter += 1
        state_id = "state_{:06d}".format(self._counter)

        meta = metadata or {}
        state_meta = {
            "state_id": state_id,
            "state_hash": s_hash,
            "snapshot_id": snapshot_id,
            "parent_state_id": meta.get("parent_state_id"),
            "parent_snapshot_id": meta.get("parent_snapshot_id"),
            "transition_id": meta.get("transition_id"),
            "interesting": meta.get("interesting", True),
            "interesting_reasons": meta.get("interesting_reasons", ["SEED"] if not meta else []),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "observations": [snapshot_id],
        }
        custom_meta = {k: v for k, v in meta.items() if k not in state_meta}
        if custom_meta:
            state_meta["metadata"] = custom_meta

        # Write state directory and artifacts
        state_path = os.path.join(self.states_dir, state_id)
        os.makedirs(state_path, exist_ok=True)

        with open(os.path.join(state_path, "snapshot.json"), "w", encoding="utf-8") as f:
            json.dump(snap_dict, f, indent=2, ensure_ascii=False)
            f.write("\n")

        with open(os.path.join(state_path, "metadata.json"), "w", encoding="utf-8") as f:
            json.dump(state_meta, f, indent=2, ensure_ascii=False)
            f.write("\n")

        self.states[state_id] = state_meta
        self.hash_to_state[s_hash] = state_id
        self.save()
        return state_id, True

    def add_transition(self, transition: Any) -> str:
        """Add a transition artifact to corpus transitions directory."""
        trans_dict = transition.to_dict() if hasattr(transition, "to_dict") else transition
        tid = trans_dict.get("transition_id") or trans_dict.get("transition", {}).get("transition_id") or "T_UNKNOWN"
        t_path = os.path.join(self.transitions_dir, "{}.json".format(tid))

        with open(t_path, "w", encoding="utf-8") as f:
            json.dump(trans_dict, f, indent=2, ensure_ascii=False)
            f.write("\n")

        if tid not in self.transitions:
            self.transitions.append(tid)
        self.save()
        return tid

    def add_exploration(self, artifact: Dict[str, Any]) -> str:
        """Add an exploration summary artifact to corpus explorations directory."""
        eid = artifact.get("exploration_id", "E_UNKNOWN")
        e_path = os.path.join(self.explorations_dir, "{}.json".format(eid))

        with open(e_path, "w", encoding="utf-8") as f:
            json.dump(artifact, f, indent=2, ensure_ascii=False)
            f.write("\n")

        if eid not in self.explorations:
            self.explorations.append(eid)
        self.save()
        return eid

    def get(self, state_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve snapshot data for state_id."""
        s_path = os.path.join(self.states_dir, state_id, "snapshot.json")
        if not os.path.isfile(s_path):
            return None
        with open(s_path, encoding="utf-8") as f:
            return json.load(f)

    def get_transition(self, transition_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve transition artifact for transition_id."""
        t_path = os.path.join(self.transitions_dir, "{}.json".format(transition_id))
        if not os.path.isfile(t_path):
            return None
        with open(t_path, encoding="utf-8") as f:
            return json.load(f)

    def list_transitions(self) -> List[str]:
        """Return list of all transition IDs in corpus."""
        return list(self.transitions)

    def get_metadata(self, state_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve metadata for state_id."""
        return self.states.get(state_id)

    def list(self) -> List[Dict[str, Any]]:
        """Return list of all states in corpus."""
        return [self.states[k] for k in sorted(self.states.keys())]

    def contains(self, state_hash: str) -> bool:
        """Check if state_hash is already present in corpus."""
        return state_hash in self.hash_to_state

    def save(self) -> None:
        """Save index.json to corpus_dir."""
        index_data = {
            "schema_version": "0.4",
            "counter": self._counter,
            "states": self.states,
            "hash_to_state": self.hash_to_state,
            "transitions": self.transitions,
            "explorations": self.explorations
        }
        with open(self.index_file, "w", encoding="utf-8") as f:
            json.dump(index_data, f, indent=2, ensure_ascii=False)
            f.write("\n")

    def load(self) -> None:
        """Load index.json if present."""
        if not os.path.isfile(self.index_file):
            return
        try:
            with open(self.index_file, encoding="utf-8") as f:
                index_data = json.load(f)
            self._counter = index_data.get("counter", 0)
            self.states = index_data.get("states", {})
            self.hash_to_state = index_data.get("hash_to_state", {})
            self.transitions = index_data.get("transitions", [])
            self.explorations = index_data.get("explorations", [])
        except Exception:
            pass

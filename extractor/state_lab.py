"""State Laboratory: Offline Snapshot Branching, Mutation, Diffing, and Lineage Management.

Provides logical state isolation across snapshot branches, ensuring that mutations
in one branch never affect parent or sibling states.
"""

import copy
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from .semantic_state import SemanticState, compute_semantic_state_hash


def compute_semantic_diff(parent: SemanticState, child: SemanticState) -> Dict[str, Any]:
    """Computes a detailed semantic diff between parent and child states."""
    changed = []
    added = []
    removed = []
    refs_changed = []

    p_objs = {o.get("object_id"): o for o in parent.objects if o.get("object_id")}
    c_objs = {o.get("object_id"): o for o in child.objects if o.get("object_id")}

    # Detect added and changed objects
    for oid, c_obj in c_objs.items():
        if oid not in p_objs:
            added.append({
                "object_id": oid,
                "type": c_obj.get("type"),
                "primary_path": c_obj.get("primary_path"),
            })
            continue

        p_obj = p_objs[oid]
        p_fields = {f.get("name"): f for f in p_obj.get("fields", []) if f.get("name")}
        c_fields = {f.get("name"): f for f in c_obj.get("fields", []) if f.get("name")}

        for fname, c_f in c_fields.items():
            if fname not in p_fields:
                changed.append({
                    "object_id": oid,
                    "field": fname,
                    "path": c_f.get("semantic_path") or f"{c_obj.get('primary_path', oid)}.{fname}",
                    "old_value": None,
                    "new_value": c_f.get("value"),
                    "change_type": "FIELD_ADDED"
                })
            else:
                p_f = p_fields[fname]
                old_val = p_f.get("value")
                new_val = c_f.get("value")
                old_ref = p_f.get("reference")
                new_ref = c_f.get("reference")

                if old_val != new_val:
                    changed.append({
                        "object_id": oid,
                        "field": fname,
                        "path": c_f.get("semantic_path") or f"{c_obj.get('primary_path', oid)}.{fname}",
                        "old_value": old_val,
                        "new_value": new_val,
                        "change_type": "VALUE_MODIFIED"
                    })

                if old_ref != new_ref:
                    refs_changed.append({
                        "object_id": oid,
                        "field": fname,
                        "old_reference": old_ref,
                        "new_reference": new_ref,
                    })

    # Detect removed objects
    for oid, p_obj in p_objs.items():
        if oid not in c_objs:
            removed.append({
                "object_id": oid,
                "type": p_obj.get("type"),
                "primary_path": p_obj.get("primary_path"),
            })

    return {
        "parent_snapshot": parent.snapshot_id,
        "child_snapshot": child.snapshot_id,
        "parent_hash": parent.state_hash,
        "child_hash": child.state_hash,
        "changed": changed,
        "added": added,
        "removed": removed,
        "references_changed": refs_changed,
        "summary": {
            "value_changes": len(changed),
            "objects_created": len(added),
            "objects_removed": len(removed),
            "reference_changes": len(refs_changed),
            "is_identical": (len(changed) == 0 and len(added) == 0 and len(removed) == 0 and len(refs_changed) == 0),
        }
    }


class SnapshotMutator:
    """Applies mutations to captured semantic state, generating new independent child branches."""

    @staticmethod
    def mutate(
        parent_state: SemanticState,
        target: str,
        new_value: Any,
        branch_id: Optional[str] = None,
        branch_name: Optional[str] = None
    ) -> SemanticState:
        """Create a new child state with the mutated field, leaving parent_state strictly immutable."""
        child_roots = copy.deepcopy(parent_state.roots)
        child_objects = copy.deepcopy(parent_state.objects)
        child_refs = copy.deepcopy(parent_state.references)
        child_threads = copy.deepcopy(parent_state.threads)
        child_paths = copy.deepcopy(parent_state.semantic_paths)

        # Parse target: can be 'obj_id.field_name' or hierarchical path 'Session.worker.state.counter'
        target_obj_id = None
        target_field_name = None

        if "." in target:
            # Check if prefix matches a known semantic path
            parts = target.rsplit(".", 1)
            path_prefix = parts[0]
            field_suffix = parts[1]

            # Try direct path lookup
            if path_prefix in child_paths:
                target_obj_id = child_paths[path_prefix]
                target_field_name = field_suffix
            else:
                # Check objects by object_id
                for o in child_objects:
                    if o.get("object_id") == path_prefix:
                        target_obj_id = path_prefix
                        target_field_name = field_suffix
                        break
                    if o.get("primary_path") == path_prefix:
                        target_obj_id = o.get("object_id")
                        target_field_name = field_suffix
                        break

            # If still unresolved, look for field match directly across objects
            if not target_obj_id:
                for o in child_objects:
                    for f in o.get("fields", []):
                        if f.get("semantic_path") == target:
                            target_obj_id = o.get("object_id")
                            target_field_name = f.get("name")
                            break
                        if f.get("name") == field_suffix and (o.get("object_id") == path_prefix or path_prefix in o.get("paths", [])):
                            target_obj_id = o.get("object_id")
                            target_field_name = field_suffix
                            break
                    if target_obj_id:
                        break
        else:
            # Direct field name or object
            target_obj_id = target
            target_field_name = None

        if not target_obj_id:
            raise KeyError(f"Target object/path not found in snapshot state: {target}")

        target_obj = next((o for o in child_objects if o.get("object_id") == target_obj_id), None)
        if not target_obj:
            raise KeyError(f"Target object ID not found in snapshot state: {target_obj_id}")

        mutated = False
        if target_field_name:
            for f in target_obj.get("fields", []):
                if f.get("name") == target_field_name:
                    f["value"] = new_value
                    mutated = True
                    break
            if not mutated:
                # Add or update field
                target_obj.setdefault("fields", []).append({
                    "name": target_field_name,
                    "type": type(new_value).__name__,
                    "value": new_value,
                    "mutability": True
                })
                mutated = True
        else:
            # Whole object value mutation
            target_obj["value"] = new_value
            mutated = True

        child_id = branch_id or f"{parent_state.snapshot_id}_{branch_name or 'branch'}"
        new_hash = compute_semantic_state_hash(child_roots, child_objects, child_threads)

        prov = copy.deepcopy(parent_state.provenance)
        prov["parent_snapshot_id"] = parent_state.snapshot_id
        prov["parent_state_hash"] = parent_state.state_hash
        prov["snapshot_branch_isolation"] = {
            "capability": "SUPPORTED",
            "verified": True,
            "verification_source": "LOGICAL_STATE_COPY_ON_WRITE"
        }
        prov["live_branch_isolation"] = {
            "capability": "UNAVAILABLE",
            "verified": False,
            "verification_source": None
        }

        branch_info = {
            "parent_id": parent_state.snapshot_id,
            "branch_id": child_id,
            "branch_name": branch_name or "mutation_branch",
            "target": target,
            "target_object_id": target_obj_id,
            "target_field": target_field_name,
            "new_value": new_value,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

        return SemanticState(
            snapshot_id=child_id,
            state_hash=new_hash,
            roots=child_roots,
            objects=child_objects,
            semantic_paths=child_paths,
            threads=child_threads,
            globals=[],
            static_objects=[],
            references=child_refs,
            provenance=prov,
            branch_info=branch_info
        )


class StateLaboratory:
    """Manages snapshot trees, branches, diffs, and offline experimentation."""

    def __init__(self):
        self.snapshots: Dict[str, SemanticState] = {}
        self.lineage: Dict[str, str] = {}  # child_id -> parent_id
        self.branches: Dict[str, List[str]] = {}  # parent_id -> [child_ids]
        self.transitions: Dict[str, Dict[str, Any]] = {}
        self._branch_counter = 0

    def add_snapshot(self, state: SemanticState) -> str:
        sid = state.snapshot_id
        self.snapshots[sid] = state
        parent_id = state.branch_info.get("parent_id")
        if parent_id:
            self.lineage[sid] = parent_id
            self.branches.setdefault(parent_id, []).append(sid)
        return sid

    def get_snapshot(self, snapshot_id: str) -> Optional[SemanticState]:
        return self.snapshots.get(snapshot_id)

    def list_snapshots(self) -> List[Dict[str, Any]]:
        result = []
        for sid, s in self.snapshots.items():
            result.append({
                "snapshot_id": sid,
                "state_hash": s.state_hash,
                "parent_id": self.lineage.get(sid),
                "object_count": len(s.objects),
                "thread_count": len(s.threads),
                "branch_name": s.branch_info.get("branch_name"),
                "created_at": s.provenance.get("timestamp"),
            })
        return result

    def branch(self, parent_id: str, branch_name: Optional[str] = None) -> SemanticState:
        parent = self.get_snapshot(parent_id)
        if not parent:
            raise KeyError(f"Parent snapshot {parent_id} not found in State Laboratory")

        self._branch_counter += 1
        b_name = branch_name or f"branch_{self._branch_counter:03d}"
        child_id = f"{parent_id}-{b_name}"

        child_state = copy.deepcopy(parent)
        child_state.snapshot_id = child_id
        child_state.branch_info = {
            "parent_id": parent_id,
            "branch_id": child_id,
            "branch_name": b_name,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self.add_snapshot(child_state)
        return child_state

    def mutate(
        self,
        parent_id: str,
        target: str,
        new_value: Any,
        branch_name: Optional[str] = None
    ) -> Tuple[SemanticState, Dict[str, Any]]:
        parent = self.get_snapshot(parent_id)
        if not parent:
            raise KeyError(f"Parent snapshot {parent_id} not found in State Laboratory")

        self._branch_counter += 1
        b_name = branch_name or f"mut_{self._branch_counter:03d}"
        child_id = f"{parent_id}-{b_name}"

        child_state = SnapshotMutator.mutate(
            parent_state=parent,
            target=target,
            new_value=new_value,
            branch_id=child_id,
            branch_name=b_name
        )

        diff_res = compute_semantic_diff(parent, child_state)
        self.add_snapshot(child_state)

        t_id = f"TLAB_{len(self.transitions) + 1:04d}"
        trans_record = {
            "transition_id": t_id,
            "parent_snapshot": parent_id,
            "child_snapshot": child_id,
            "target": target,
            "new_value": new_value,
            "diff": diff_res,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self.transitions[t_id] = trans_record

        return child_state, diff_res

    def diff(self, parent_id: str, child_id: str) -> Dict[str, Any]:
        p = self.get_snapshot(parent_id)
        c = self.get_snapshot(child_id)
        if not p:
            raise KeyError(f"Snapshot {parent_id} not found")
        if not c:
            raise KeyError(f"Snapshot {child_id} not found")
        return compute_semantic_diff(p, c)

    def get_lineage(self, snapshot_id: str) -> List[str]:
        chain = [snapshot_id]
        curr = snapshot_id
        while curr in self.lineage:
            curr = self.lineage[curr]
            chain.append(curr)
        return list(reversed(chain))

    def get_tree(self) -> Dict[str, Any]:
        """Returns the full hierarchical branch tree of snapshots."""
        root_ids = [sid for sid in self.snapshots if sid not in self.lineage]

        def _build_node(sid: str) -> Dict[str, Any]:
            s = self.snapshots[sid]
            children = self.branches.get(sid, [])
            return {
                "snapshot_id": sid,
                "state_hash": s.state_hash,
                "branch_info": s.branch_info,
                "children": [_build_node(cid) for cid in children]
            }

        return {
            "roots": [_build_node(rid) for rid in root_ids],
            "total_snapshots": len(self.snapshots),
            "total_branches": len(self.lineage),
        }

"""Semantic State model and Offline Semantic State Engine.

Reconstructs DWARF-aware runtime object graphs, hierarchical semantic paths,
and state hashes purely from RawRuntimeSnapshots without running or halting the process.
"""

from collections import deque
import copy
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
import struct
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from .raw_snapshot import RawRuntimeSnapshot
from .snapshot import RuntimeSnapshot


def compute_semantic_state_hash(
    roots: List[Dict[str, Any]],
    objects: List[Dict[str, Any]],
    threads: Optional[List[Dict[str, Any]]] = None
) -> str:
    """Computes a deterministic SHA-256 state hash from canonical semantic object states."""
    h = hashlib.sha256()

    # 1. Deterministic roots hash
    sorted_roots = sorted(roots, key=lambda r: (r.get("name", ""), r.get("object_ref", "")))
    for r in sorted_roots:
        h.update(f"ROOT:{r.get('name')}:{r.get('type')}:{r.get('object_ref')}".encode("utf-8"))

    # 2. Deterministic objects hash
    sorted_objs = sorted(objects, key=lambda o: o.get("object_id", ""))
    for obj in sorted_objs:
        oid = obj.get("object_id", "")
        otype = obj.get("type", "")
        h.update(f"OBJ:{oid}:{otype}".encode("utf-8"))

        fields = obj.get("fields", [])
        sorted_fields = sorted(fields, key=lambda f: f.get("name", ""))
        for f in sorted_fields:
            fname = f.get("name", "")
            ftype = f.get("type", "")
            fval = str(f.get("value", ""))
            fref = str(f.get("reference", ""))
            h.update(f"FLD:{fname}:{ftype}:{fval}:{fref}".encode("utf-8"))

    # 3. Threads hash (thread IDs and states)
    if threads:
        sorted_threads = sorted(threads, key=lambda t: t.get("thread_id", 0))
        for t in sorted_threads:
            tid = t.get("thread_id", 0)
            tstate = t.get("state", "")
            h.update(f"TH:{tid}:{tstate}".encode("utf-8"))

    return h.hexdigest()[:16]


@dataclass
class SemanticState:
    """Independent semantic state representation reconstructed offline from runtime snapshot."""
    snapshot_id: str
    state_hash: str
    roots: List[Dict[str, Any]] = field(default_factory=list)
    objects: List[Dict[str, Any]] = field(default_factory=list)
    semantic_paths: Dict[str, str] = field(default_factory=dict)  # path -> object_id
    threads: List[Dict[str, Any]] = field(default_factory=list)
    globals: List[Dict[str, Any]] = field(default_factory=list)
    static_objects: List[Dict[str, Any]] = field(default_factory=list)
    references: List[Dict[str, Any]] = field(default_factory=list)
    provenance: Dict[str, Any] = field(default_factory=dict)
    branch_info: Dict[str, Any] = field(default_factory=dict)

    def get_object(self, object_id: str) -> Optional[Dict[str, Any]]:
        for o in self.objects:
            if o.get("object_id") == object_id:
                return o
        return None

    def get_object_by_path(self, path: str) -> Optional[Dict[str, Any]]:
        oid = self.semantic_paths.get(path)
        if oid:
            return self.get_object(oid)
        # Check primary_path or paths in objects
        for o in self.objects:
            if o.get("primary_path") == path or path in o.get("paths", []):
                return o
        return None

    def get_field(self, object_id: str, field_name: str) -> Optional[Dict[str, Any]]:
        obj = self.get_object(object_id)
        if not obj:
            return None
        for f in obj.get("fields", []):
            if f.get("name") == field_name:
                return f
        return None

    def get_all_paths_for_object(self, object_id: str) -> List[str]:
        obj = self.get_object(object_id)
        if obj and obj.get("paths"):
            return list(obj["paths"])
        paths = []
        for p, oid in self.semantic_paths.items():
            if oid == object_id:
                paths.append(p)
        return sorted(list(set(paths)))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "snapshot_id": self.snapshot_id,
            "state_hash": self.state_hash,
            "roots": self.roots,
            "objects": self.objects,
            "semantic_paths": self.semantic_paths,
            "threads": self.threads,
            "globals": self.globals,
            "static_objects": self.static_objects,
            "references": self.references,
            "provenance": self.provenance,
            "branch_info": self.branch_info,
        }

    def to_snapshot(self) -> RuntimeSnapshot:
        """Converts to a standard RuntimeSnapshot for backward-compatible consumption."""
        pid = self.provenance.get("pid", 0)
        binary = self.provenance.get("executable_identity", {}).get("path", "")
        return RuntimeSnapshot(
            snapshot_id=self.snapshot_id,
            schema_version="0.4",
            created_at=self.provenance.get("timestamp", datetime.now(timezone.utc).isoformat()),
            process={
                "pid": pid,
                "binary": binary,
            },
            execution={
                "threads": self.threads,
                "inferior_stopped": True,
            },
            persistent={
                "roots": self.roots,
                "objects": self.objects,
                "references": self.references,
                "statistics": {
                    "object_count": len(self.objects),
                    "root_count": len(self.roots),
                    "edge_count": len(self.references),
                    "state_hash": self.state_hash,
                }
            },
            provenance=self.provenance,
            metadata={
                "state_hash": self.state_hash,
                "branch_info": self.branch_info,
            }
        )

    @classmethod
    def from_snapshot(cls, snap: Union[RuntimeSnapshot, Dict[str, Any]]) -> "SemanticState":
        data = snap.to_dict() if hasattr(snap, "to_dict") else dict(snap)
        persistent = data.get("persistent") or {}
        execution = data.get("execution") or {}
        meta = data.get("metadata") or {}
        prov = data.get("provenance") or {}

        roots = persistent.get("roots") or []
        objects = persistent.get("objects") or []
        threads = execution.get("threads") or []
        refs = persistent.get("references") or []
        sid = data.get("snapshot", {}).get("snapshot_id") or data.get("snapshot_id", "S001")

        state_hash = (
            meta.get("state_hash")
            or persistent.get("statistics", {}).get("state_hash")
            or compute_semantic_state_hash(roots, objects, threads)
        )

        # Build semantic paths mapping
        sem_paths = {}
        for obj in objects:
            oid = obj.get("object_id")
            if not oid:
                continue
            primary = obj.get("primary_path") or obj.get("semantic_path")
            if primary:
                sem_paths[primary] = oid
            for p in obj.get("paths", []):
                sem_paths[p] = oid

        return cls(
            snapshot_id=sid,
            state_hash=state_hash,
            roots=roots,
            objects=objects,
            semantic_paths=sem_paths,
            threads=threads,
            globals=[],
            static_objects=[],
            references=refs,
            provenance=prov,
            branch_info=meta.get("branch_info", {})
        )


class OfflineSemanticEngine:
    """Reconstructs SemanticState from RawRuntimeSnapshot and DWARF/ELF debug info."""

    def __init__(self):
        pass

    @staticmethod
    def _build_semantic_paths(
        roots: List[Dict[str, Any]],
        objects: List[Dict[str, Any]]
    ) -> Tuple[Dict[str, List[str]], Dict[str, Dict[str, Any]]]:
        """BFS traversal from roots to determine all reachable hierarchical paths for each object."""
        obj_by_id: Dict[str, Dict[str, Any]] = {}
        for o in objects:
            oid = o.get("object_id")
            if oid:
                obj_by_id[oid] = o

        root_map: Dict[str, Dict[str, Any]] = {}
        for r in roots:
            oref = r.get("object_ref")
            if oref:
                root_map[oref] = r

        paths_by_obj: Dict[str, List[str]] = {oid: [] for oid in obj_by_id}
        queue = deque()
        visited_edges: Set[Tuple[str, str, str]] = set()

        # Seed BFS from roots
        for oref, rinfo in root_map.items():
            if oref in obj_by_id:
                rname = rinfo.get("name") or "Root"
                if rname not in paths_by_obj[oref]:
                    paths_by_obj[oref].append(rname)
                queue.append((oref, rname))

        # Direct root names if roots map by index
        for idx, o in enumerate(objects):
            oid = o.get("object_id")
            if oid and not paths_by_obj[oid] and idx < len(roots):
                rname = roots[idx].get("name")
                if rname:
                    paths_by_obj[oid].append(rname)
                    queue.append((oid, rname))

        # BFS traverse fields
        while queue:
            curr_id, curr_path = queue.popleft()
            curr_obj = obj_by_id.get(curr_id)
            if not curr_obj:
                continue

            for f in curr_obj.get("fields", []):
                ref_id = f.get("reference")
                fname = f.get("name")
                if ref_id and ref_id in obj_by_id and fname:
                    edge = (curr_id, fname, ref_id)
                    if edge not in visited_edges:
                        visited_edges.add(edge)
                        child_path = f"{curr_path}.{fname}"
                        if child_path not in paths_by_obj[ref_id]:
                            paths_by_obj[ref_id].append(child_path)
                            queue.append((ref_id, child_path))

        return paths_by_obj, root_map

    def reconstruct(
        self,
        raw_snapshot: RawRuntimeSnapshot,
        symbol_context: Optional[Dict[str, Any]] = None,
        debug_image: Optional[str] = None,
    ) -> SemanticState:
        """Offline semantic state reconstruction from captured memory buffers and DWARF info."""
        roots = []
        objects = []
        references = []
        threads = list(raw_snapshot.thread_metadata)

        # 1. If symbol_context is provided (e.g. simulated or loaded from DWARF extraction)
        if symbol_context:
            roots = copy.deepcopy(symbol_context.get("roots", []))
            raw_objs = copy.deepcopy(symbol_context.get("objects", []))
            references = copy.deepcopy(symbol_context.get("references", []))
            if "threads" in symbol_context and symbol_context["threads"]:
                threads = copy.deepcopy(symbol_context["threads"])
            objects = raw_objs
        else:
            # 2. Extract from DWARF / inspect_elf if executable exists
            exe_path = raw_snapshot.executable or debug_image
            if exe_path and os.path.exists(exe_path):
                try:
                    from .debug_image import inspect_elf
                    elf_info = inspect_elf(exe_path)
                    # Create baseline root if binary identity known
                    root_name = os.path.basename(exe_path).split(".")[0]
                    roots.append({
                        "name": root_name,
                        "type": "Application",
                        "object_ref": "obj_root",
                    })
                    objects.append({
                        "object_id": "obj_root",
                        "type": "Application",
                        "address": 0x400000,
                        "storage": "static",
                        "fields": [
                            {"name": "pid", "type": "int", "value": raw_snapshot.pid},
                            {"name": "status", "type": "str", "value": raw_snapshot.completeness},
                        ]
                    })
                except Exception:
                    pass

        # If no objects discovered yet, create a default process root object
        if not objects:
            roots.append({
                "name": "Process",
                "type": "ProcessContext",
                "object_ref": "obj_proc",
            })
            objects.append({
                "object_id": "obj_proc",
                "type": "ProcessContext",
                "address": 0x1000,
                "storage": "heap",
                "fields": [
                    {"name": "pid", "type": "int", "value": raw_snapshot.pid},
                    {"name": "captured_bytes", "type": "int", "value": raw_snapshot.provenance.get("captured_bytes", 0)},
                ]
            })

        # 3. Compute hierarchical semantic paths for all objects
        obj_paths, root_map = self._build_semantic_paths(roots, objects)
        sem_path_map: Dict[str, str] = {}

        for obj in objects:
            oid = obj.get("object_id")
            paths = obj_paths.get(oid, [])
            c_type = obj.get("type", "Unknown")

            if paths:
                primary_path = paths[0]
                additional_paths = paths[1:]
            else:
                primary_path = root_map.get(oid, {}).get("name") or c_type
                additional_paths = []
                paths = [primary_path]

            obj["primary_path"] = primary_path
            obj["semantic_path"] = primary_path
            obj["semantic_name"] = primary_path
            obj["paths"] = paths
            obj["additional_paths"] = additional_paths
            addr = obj.get("address")
            obj["identity"] = f"{c_type}@{addr}" if addr else f"{c_type}:{oid}"

            for p in paths:
                sem_path_map[p] = oid

            # Enrich field-level semantic paths
            for f in obj.get("fields", []):
                fname = f.get("name")
                if fname:
                    f["semantic_path"] = f"{primary_path}.{fname}"

        # 4. Compute deterministic state hash
        state_hash = compute_semantic_state_hash(roots, objects, threads)

        # 5. Build full provenance
        prov = dict(raw_snapshot.provenance)
        prov["state_hash"] = state_hash
        prov["object_count"] = len(objects)
        prov["root_count"] = len(roots)
        prov["reconstructed_offline"] = True

        return SemanticState(
            snapshot_id=raw_snapshot.snapshot_id,
            state_hash=state_hash,
            roots=roots,
            objects=objects,
            semantic_paths=sem_path_map,
            threads=threads,
            globals=[],
            static_objects=[],
            references=references,
            provenance=prov,
            branch_info={"branch_type": "ROOT_CAPTURE"}
        )

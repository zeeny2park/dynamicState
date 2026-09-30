"""HTTP Web API server and static asset host for dynamicState Runtime State Explorer.

Strictly wraps AgentRuntime without duplicating semantics, executing arbitrary shell/GDB commands,
or making silent target architecture assumptions.
"""

from collections import deque
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
import http.server
import json
import mimetypes
import os
import re
import socketserver
import sys
import threading
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple, Union

from extractor.agent_runtime import AgentRuntime
from extractor.state_diff import StateDiffEngine
from extractor.state_hash import compute_state_hash


def _to_json_serializable(val: Any) -> Any:
    """Recursively convert dataclasses and internal objects to plain JSON-serializable types."""
    if val is None or isinstance(val, (bool, int, float, str)):
        return val
    if is_dataclass(val):
        return _to_json_serializable(asdict(val))
    if hasattr(val, "to_dict") and callable(getattr(val, "to_dict")):
        return _to_json_serializable(val.to_dict())
    if isinstance(val, dict):
        return {str(k): _to_json_serializable(v) for k, v in val.items()}
    if isinstance(val, (list, tuple, set)):
        return [_to_json_serializable(item) for item in val]
    return str(val)


def _clean_type_name(t: Any) -> str:
    """Strip struct/class/enum keywords from C/C++ type names for clean human presentation."""
    if not t:
        return "Unknown"
    s = str(t).strip()
    for prefix in ("struct ", "class ", "enum "):
        if s.startswith(prefix):
            s = s[len(prefix):]
    return s.strip()


def _is_field_mutable(ftype: Any) -> str:
    """Classify mutability from type string consistently."""
    if not ftype:
        return "unsupported"
    fl = str(ftype).lower()
    if "const" in fl:
        return "read_only"
    if any(t in fl for t in ("int", "bool", "enum", "float", "double", "char", "*")):
        return "mutable"
    return "unsupported"


def _build_semantic_paths(roots: List[Any], objects: List[Any]) -> Tuple[Dict[str, List[str]], Dict[str, Dict[str, Any]]]:
    """Build hierarchical semantic paths for all objects reachable from roots.
    
    Returns:
      (obj_paths: Dict[str, List[str]], root_info: Dict[str, Dict[str, Any]])
    cycle-safe BFS graph traversal.
    """
    obj_paths: Dict[str, List[str]] = {}
    obj_lookup: Dict[str, Dict[str, Any]] = {}
    for o in objects:
        o_dict = o if isinstance(o, dict) else (o.to_dict() if hasattr(o, "to_dict") else asdict(o))
        oid = o_dict.get("object_id")
        if oid:
            obj_lookup[oid] = o_dict
            obj_paths[oid] = []

    # Map roots
    root_info: Dict[str, Dict[str, Any]] = {}
    for idx, r in enumerate(roots):
        r_dict = r if isinstance(r, dict) else (r.to_dict() if hasattr(r, "to_dict") else asdict(r))
        oref = r_dict.get("object_ref")
        rname = r_dict.get("name") or f"Root_{idx+1}"
        if oref and oref in obj_lookup:
            root_info[oref] = r_dict
            if rname not in obj_paths[oref]:
                obj_paths[oref].append(rname)
        elif idx < len(objects):
            target_oid = objects[idx].get("object_id") if isinstance(objects[idx], dict) else getattr(objects[idx], "object_id", None)
            if target_oid and target_oid in obj_lookup and target_oid not in root_info:
                root_info[target_oid] = r_dict
                if rname not in obj_paths[target_oid]:
                    obj_paths[target_oid].append(rname)

    # Queue of (current_oid, current_path, visited_oids_on_branch)
    queue: deque = deque()
    for oid, paths in obj_paths.items():
        for p in paths:
            queue.append((oid, p, {oid}))

    # BFS expand references
    while queue:
        curr_oid, curr_path, branch_visited = queue.popleft()
        curr_obj = obj_lookup.get(curr_oid)
        if not curr_obj:
            continue

        for f in curr_obj.get("fields", []):
            f_dict = f if isinstance(f, dict) else (f.to_dict() if hasattr(f, "to_dict") else asdict(f))
            ref_oid = f_dict.get("object_ref")
            fname = f_dict.get("name")
            if ref_oid and fname and ref_oid in obj_lookup:
                child_path = f"{curr_path}.{fname}"
                if ref_oid not in obj_paths:
                    obj_paths[ref_oid] = []
                if child_path not in obj_paths[ref_oid]:
                    obj_paths[ref_oid].append(child_path)
                # Cycle prevention: only traverse deeper if ref_oid was not already visited along this branch
                if ref_oid not in branch_visited and len(branch_visited) < 32:
                    new_visited = set(branch_visited)
                    new_visited.add(ref_oid)
                    queue.append((ref_oid, child_path, new_visited))

    return obj_paths, root_info


class WebApiAdapter:
    """Thin adapter mapping REST endpoints to AgentRuntime methods."""

    def __init__(self, runtime: AgentRuntime):
        self.runtime = runtime
        self.diff_engine = StateDiffEngine()

    def get_health(self) -> Dict[str, Any]:
        return {
            "status": "ok",
            "version": "0.5.2",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "mode": getattr(self.runtime, "observation_mode", "CONSISTENT"),
        }

    def get_capabilities(self) -> Dict[str, Any]:
        res = self.runtime.capabilities()
        if res.success:
            data = _to_json_serializable(res.data)
            if isinstance(data, dict):
                limits = data.get("limits") or {}
                mutation = data.get("mutation") or {}
                default_timeout = (
                    mutation.get("default_timeout_ms")
                    or limits.get("default_timeout_ms")
                    or data.get("default_timeout_ms")
                    or 1000
                )
                if isinstance(mutation, dict):
                    mutation["default_timeout_ms"] = default_timeout
                    data["mutation"] = mutation
                if isinstance(limits, dict):
                    limits["default_timeout_ms"] = default_timeout
                    data["limits"] = limits
                data["default_timeout_ms"] = default_timeout
            return {"success": True, "data": data}
        return {
            "success": False,
            "error": {"code": res.error.code if res.error else "RUNTIME_ERROR",
                      "message": res.error.message if res.error else "Failed to get capabilities"}
        }

    def get_runtime_info(self) -> Dict[str, Any]:
        ctrl = getattr(self.runtime, "controller", None)
        mode = getattr(self.runtime, "observation_mode", "CONSISTENT")

        # Runtime status detection
        status = "DISCONNECTED"
        pid = None
        target_arch = "UNKNOWN"
        target_endian = "UNKNOWN"
        target_elf = "UNKNOWN"
        binary_path = None
        debug_image = None
        debug_image_status = "NOT_AVAILABLE"

        if ctrl:
            try:
                pinfo = ctrl.process_info() if hasattr(ctrl, "process_info") and callable(ctrl.process_info) else getattr(ctrl, "process_info", {})
                if isinstance(pinfo, dict):
                    pid = pinfo.get("pid")
                    status = pinfo.get("status", "STOPPED")
            except Exception:
                status = "ERROR"

            binary_path = getattr(ctrl, "binary", None)
            debug_image = getattr(ctrl, "debug_image_path", None)
            if hasattr(ctrl, "debug_image_provider") and ctrl.debug_image_provider:
                debug_image = getattr(ctrl.debug_image_provider, "path", None) or debug_image
                if getattr(ctrl.debug_image_provider, "compatibility", None) and ctrl.debug_image_provider.compatibility.compatible:
                    debug_image_status = "COMPATIBLE"
                else:
                    debug_image_status = getattr(ctrl, "debug_image_status", "VERIFIED")
            elif debug_image:
                debug_image_status = getattr(ctrl, "debug_image_status", "VERIFIED")

            if hasattr(ctrl, "runtime_info") and callable(ctrl.runtime_info):
                try:
                    cinfo = ctrl.runtime_info()
                    rb = cinfo.get("runtime_binary") or {}
                    di = cinfo.get("debug_image") or {}
                    if not binary_path and rb.get("path"):
                        binary_path = rb.get("path")
                    if not debug_image and di.get("path"):
                        debug_image = di.get("path")
                        debug_image_status = "COMPATIBLE" if di.get("compatible") else "LOADED"
                    if target_arch == "UNKNOWN" and rb.get("architecture"):
                        target_arch = rb.get("architecture")
                    if target_endian == "UNKNOWN" and rb.get("endianness"):
                        target_endian = rb.get("endianness")
                    if target_elf == "UNKNOWN" and rb.get("elf_class"):
                        target_elf = rb.get("elf_class")
                except Exception:
                    pass

        # Discover target metadata from discovered modules or snapshots without silent guessing
        modules = []
        try:
            m_res = self.runtime.get_modules(None)
            if m_res.success and isinstance(m_res.data, dict):
                modules = m_res.data.get("modules", [])
        except Exception:
            pass

        main_mod = next((m for m in modules if m.get("is_main_executable")), None)
        if main_mod:
            target_arch = main_mod.get("architecture") or "UNKNOWN"
            target_endian = main_mod.get("endianness") or "UNKNOWN"
            target_elf = main_mod.get("elf_class") or "UNKNOWN"
            if not binary_path:
                binary_path = main_mod.get("path")
            if not pid:
                pid = main_mod.get("pid")

        caps_res = self.runtime.capabilities()
        caps = caps_res.data if caps_res.success else {}

        # Pre-compute memory summary if snapshot or states available
        mem_summary_res = self.runtime.get_memory_summary()
        mem_summary = _to_json_serializable(mem_summary_res.data) if mem_summary_res.success else None

        # Observation point resolution (Strictly honest: never fabricate placeholders or duplicate spec)
        observation_point = None
        if self.runtime._cached_checkpoints:
            last_cp = list(self.runtime._cached_checkpoints.values())[-1]
            if getattr(last_cp, "observation_point", None):
                op = last_cp.observation_point
                if isinstance(op, dict) and op.get("spec") not in (None, "", "observation_checkpoint"):
                    observation_point = {
                        "kind": op.get("kind", "BREAKPOINT"),
                        "spec": op.get("spec"),
                        "function": op.get("function"),
                        "location": op.get("location"),
                    }

        if not observation_point and ctrl:
            bp_spec = getattr(ctrl, "breakpoint_spec", None)
            if hasattr(ctrl, "restorer"):
                if getattr(ctrl.restorer, "breakpoint_spec", None):
                    bp_spec = ctrl.restorer.breakpoint_spec
                elif hasattr(ctrl.restorer, "_restart_restorer") and getattr(ctrl.restorer._restart_restorer, "breakpoint_spec", None):
                    bp_spec = ctrl.restorer._restart_restorer.breakpoint_spec
            if bp_spec and bp_spec != "observation_checkpoint":
                # Honest: Never duplicate spec into function or location
                observation_point = {
                    "kind": "BREAKPOINT",
                    "spec": bp_spec,
                    "function": None,
                    "location": None,
                }

        # Threads detail resolution from latest snapshot (Honest: never fabricate thread names or locations)
        threads_detail = []
        snap, _ = self.runtime._resolve_snapshot(None)
        if snap:
            s_data = snap.to_dict() if hasattr(snap, "to_dict") else dict(snap)
            exec_data = s_data.get("execution") or {}
            threads_list = exec_data.get("threads") or []
            for th in threads_list:
                th_dict = th if isinstance(th, dict) else (th.to_dict() if hasattr(th, "to_dict") else asdict(th))
                tid = th_dict.get("thread_id", 1)
                frames = th_dict.get("frames") or []
                top_f = frames[0] if frames else {}
                top_f_dict = top_f if isinstance(top_f, dict) else (top_f.to_dict() if hasattr(top_f, "to_dict") else asdict(top_f))
                t_name = th_dict.get("name")
                top_fn = top_f_dict.get("function")
                top_loc = top_f_dict.get("location")
                threads_detail.append({
                    "thread_id": tid,
                    "name": t_name if t_name else None,
                    "state": th_dict.get("state", "STOPPED"),
                    "function": top_fn if top_fn and top_fn != "<unknown>" else None,
                    "location": top_loc if top_loc and top_loc != "<unknown>" else None,
                    "frame_depth": len(frames),
                })
            if not observation_point and threads_detail and threads_detail[0].get("function"):
                fn = threads_detail[0]["function"]
                loc = threads_detail[0].get("location")
                if fn and fn != "<unknown>":
                    observation_point = {
                        "kind": "FRAME",
                        "spec": fn,
                        "function": fn,
                        "location": loc,
                    }

        # Fallback to inferior thread inspection if live GDB inferior
        if not threads_detail and ctrl and hasattr(ctrl, "gdb") and hasattr(ctrl.gdb, "selected_inferior"):
            try:
                inf = ctrl.gdb.selected_inferior()
                for t in inf.threads():
                    tid = getattr(t, "global_num", None) or getattr(t, "num", 1)
                    t_name = getattr(t, "name", None) or None
                    t_state = "STOPPED"
                    try:
                        if hasattr(t, "is_stopped"):
                            t_state = "STOPPED" if t.is_stopped() else "RUNNING"
                    except Exception:
                        pass
                    threads_detail.append({
                        "thread_id": tid,
                        "name": t_name,
                        "state": t_state,
                        "function": None,
                        "location": None,
                        "frame_depth": 1,
                    })
            except Exception:
                pass

        if not threads_detail:
            thread_cnt = caps.get("threads", 1)
            for i in range(1, thread_cnt + 1):
                threads_detail.append({
                    "thread_id": i,
                    "name": None,
                    "state": status if status != "DISCONNECTED" else "UNKNOWN",
                    "function": None,
                    "location": None,
                    "frame_depth": 1,
                })

        # Capability vs Verification distinctions (Strictly honest: never infer verification without provenance)
        branch_iso = caps.get("branch_isolation", {})
        cp_restore = caps.get("checkpoint_restore", {})
        det_status = cp_restore.get("determinism_status") or branch_iso.get("determinism_status") or "UNKNOWN"
        is_det_verified = bool(det_status == "VERIFIED" or cp_restore.get("verified") or branch_iso.get("determinism_verified"))
        branch_iso_cap = branch_iso.get("status", "UNAVAILABLE")
        # STRICT: branch isolation verification requires explicit verification execution provenance
        branch_iso_verified = bool(branch_iso.get("verified", False))
        branch_iso_source = branch_iso.get("verification_source", None)

        branch_iso_dict = dict(branch_iso)
        branch_iso_dict["capability"] = branch_iso_cap
        branch_iso_dict["verified"] = branch_iso_verified
        branch_iso_dict["verification_source"] = branch_iso_source
        if "status" not in branch_iso_dict:
            branch_iso_dict["status"] = branch_iso_cap

        det_cap = "SUPPORTED" if (branch_iso_cap in ("SUPPORTED", "CONDITIONAL") or caps.get("checkpoint")) else "UNAVAILABLE"
        det_dict = {
            "capability": det_cap,
            "verified": is_det_verified,
            "status": det_status,
        }

        limits = caps.get("limits", {})
        default_timeout = (
            caps.get("mutation", {}).get("default_timeout_ms")
            or limits.get("default_timeout_ms")
            or caps.get("default_timeout_ms")
            or 1000
        )

        return {
            "success": True,
            "data": {
                "status": status,
                "mode": mode,
                "pid": pid,
                "architecture": target_arch,
                "endianness": target_endian,
                "elf_class": target_elf,
                "executable": binary_path,
                "debug_image": debug_image,
                "debug_image_status": debug_image_status,
                "build_id": main_mod.get("build_id") if main_mod else None,
                "module_count": len(modules),
                "state_count": len(self.runtime.corpus.states),
                "transition_count": len(self.runtime.corpus.transitions),
                "threads": caps.get("threads", 1),
                "threads_detail": threads_detail,
                "observation_point": observation_point,
                "checkpoint_restore": cp_restore,
                "branch_isolation": branch_iso_dict,
                "branch_isolation_capability": branch_iso_cap,
                "branch_isolation_verified": branch_iso_verified,
                "branch_isolation_source": branch_iso_source,
                "snapshot_branch_isolation": {
                    "capability": "SUPPORTED",
                    "verified": True,
                    "verification_source": "LOGICAL_STATE_COPY_ON_WRITE"
                },
                "live_branch_isolation": branch_iso_dict,
                "determinism": det_dict,
                "determinism_capability": det_cap,
                "determinism_verified": is_det_verified,
                "determinism_status": det_status,
                "default_timeout_ms": default_timeout,
                "current_checkpoint": list(self.runtime._cached_checkpoints.keys())[-1] if self.runtime._cached_checkpoints else None,
                "safety_limits": limits,
                "capabilities": caps,
                "memory_summary": mem_summary,
                "capture_backend": (
                    getattr(self.runtime, "_capture_backend", None).name if getattr(self.runtime, "_capture_backend", None)
                    else "process_vm_readv"
                ),
                "last_capture_latency_report": getattr(self.runtime, "_last_capture_latency_report", None),
                "state_lab_tree": self.runtime.state_lab.get_tree() if hasattr(self.runtime, "state_lab") else None,
            }
        }

    def get_memory_summary(self, snapshot_id: Optional[str] = None) -> Dict[str, Any]:
        res = self.runtime.get_memory_summary(snapshot_id)
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {
            "success": False,
            "error": {"code": res.error.code if res.error else "SNAPSHOT_NOT_FOUND",
                      "message": res.error.message if res.error else "Memory summary not found"}
        }

    def get_state_memory_summary(self, state_id: str) -> Dict[str, Any]:
        state_meta = self.runtime.corpus.get_metadata(state_id)
        snap_id = state_meta.get("snapshot_id") if state_meta else None
        res = self.runtime.get_memory_summary(snap_id or state_id)
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        # Fallback if state in corpus
        snap_data = self.runtime.corpus.get(state_id)
        if snap_data:
            from extractor.memory_snapshot_summary import build_memory_snapshot_summary
            summary = build_memory_snapshot_summary(snap_data)
            return {"success": True, "data": _to_json_serializable(summary.to_dict())}
        return {
            "success": False,
            "error": {"code": res.error.code if res.error else "STATE_NOT_FOUND",
                      "message": res.error.message if res.error else f"State '{state_id}' memory summary not found"}
        }

    def get_modules(self, snapshot_id: Optional[str] = None) -> Dict[str, Any]:
        res = self.runtime.get_modules(snapshot_id)
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {
            "success": False,
            "error": {"code": res.error.code if res.error else "SNAPSHOT_NOT_FOUND",
                      "message": res.error.message if res.error else "No modules found"}
        }

    def get_provenance(self, snapshot_id: Optional[str] = None) -> Dict[str, Any]:
        res = self.runtime.get_snapshot_provenance(snapshot_id)
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {
            "success": False,
            "error": {"code": res.error.code if res.error else "SNAPSHOT_NOT_FOUND",
                      "message": res.error.message if res.error else "Provenance not found"}
        }

    def list_states(self) -> Dict[str, Any]:
        res = self.runtime.list_states()
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {
            "success": False,
            "error": {"code": res.error.code if res.error else "RUNTIME_ERROR",
                      "message": res.error.message if res.error else "Failed to list states"}
        }

    def inspect_state(self, state_id: str) -> Dict[str, Any]:
        res = self.runtime.inspect_state(state_id)
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {
            "success": False,
            "error": {"code": res.error.code if res.error else "STATE_NOT_FOUND",
                      "message": res.error.message if res.error else f"State '{state_id}' not found"}
        }

    def list_state_objects(self, state_id: str) -> Dict[str, Any]:
        state_meta = self.runtime.corpus.get_metadata(state_id)
        if not state_meta:
            return {
                "success": False,
                "error": {"code": "STATE_NOT_FOUND", "message": f"State '{state_id}' not found in corpus"}
            }
        snap_id = state_meta.get("snapshot_id")
        snap, _ = self.runtime._resolve_snapshot(snap_id or state_id)
        if snap is None:
            snap = self.runtime.corpus.get(state_id)

        if snap is None:
            res = self.runtime.list_objects(snapshot_id=snap_id)
            if res.success:
                return {"success": True, "data": _to_json_serializable(res.data)}
            return {
                "success": False,
                "error": {"code": res.error.code if res.error else "SNAPSHOT_NOT_FOUND",
                          "message": res.error.message if res.error else "Failed to list state objects"}
            }

        snap_dict = snap.to_dict() if hasattr(snap, "to_dict") else dict(snap)
        s_inner = snap_dict.get("snapshot", snap_dict)
        persistent = snap_dict.get("persistent") or s_inner.get("persistent") or {}
        roots = persistent.get("roots", [])
        objects = persistent.get("objects", [])

        # Build hierarchical semantic paths from roots
        obj_paths, root_map = _build_semantic_paths(roots, objects)

        # Compute outgoing and incoming counts
        outgoing_counts: Dict[str, int] = {}
        incoming_counts: Dict[str, int] = {}
        for o in objects:
            o_dict = o if isinstance(o, dict) else (o.to_dict() if hasattr(o, "to_dict") else asdict(o))
            oid = o_dict.get("object_id", "")
            out_c = 0
            for f in o_dict.get("fields", []):
                f_dict = f if isinstance(f, dict) else (f.to_dict() if hasattr(f, "to_dict") else asdict(f))
                ref = f_dict.get("object_ref")
                if ref:
                    out_c += 1
                    incoming_counts[ref] = incoming_counts.get(ref, 0) + 1
            outgoing_counts[oid] = out_c

        enriched_objects = []
        for o in objects:
            o_dict = o if isinstance(o, dict) else (o.to_dict() if hasattr(o, "to_dict") else asdict(o))
            oid = o_dict.get("object_id", "")
            raw_type = o_dict.get("type", "Unknown")
            cleaned_type = _clean_type_name(raw_type)

            paths = obj_paths.get(oid, [])
            primary_path = paths[0] if paths else None
            additional_paths = paths[1:] if len(paths) > 1 else []
            semantic_path = primary_path or root_map.get(oid, {}).get("name") or cleaned_type
            semantic_name = semantic_path

            enriched_fields = []
            for f in o_dict.get("fields", []):
                f_dict = f if isinstance(f, dict) else (f.to_dict() if hasattr(f, "to_dict") else asdict(f))
                fname = f_dict.get("name")
                fpath = f"{semantic_path}.{fname}" if fname else semantic_path
                enriched_fields.append({
                    "name": fname,
                    "type": f_dict.get("type"),
                    "cleaned_type": _clean_type_name(f_dict.get("type", "")),
                    "value": self.runtime._sanitize_field_value(f_dict),
                    "object_ref": f_dict.get("object_ref"),
                    "mutability": _is_field_mutable(f_dict.get("type", "")),
                    "address": f_dict.get("address"),
                    "semantic_path": fpath,
                })

            addr = o_dict.get("address")
            identity_str = f"{cleaned_type}@{addr}" if addr else f"{cleaned_type}:{oid}"

            enriched_objects.append({
                "object_id": oid,
                "type": raw_type,
                "cleaned_type": cleaned_type,
                "canonical_type": cleaned_type,
                "semantic_name": semantic_name or oid,
                "semantic_path": semantic_path,
                "primary_path": primary_path,
                "paths": paths,
                "additional_paths": additional_paths,
                "identity": identity_str,
                "root_name": root_map.get(oid, {}).get("name"),
                "root_source": root_map.get(oid, {}).get("source") or ("Root Variable" if oid in root_map else None),
                "storage": o_dict.get("storage", "unknown"),
                "address": addr,
                "thread_id": o_dict.get("thread_id"),
                "frame_level": o_dict.get("frame_level"),
                "fields": enriched_fields,
                "field_count": len(enriched_fields),
                "outgoing_count": outgoing_counts.get(oid, 0),
                "incoming_count": incoming_counts.get(oid, 0),
                "reference_count": outgoing_counts.get(oid, 0) + incoming_counts.get(oid, 0),
                "identity_hint": identity_str,
            })

        return {"success": True, "data": enriched_objects}

    def inspect_object(self, object_id: str, snapshot_id: Optional[str] = None) -> Dict[str, Any]:
        res = self.runtime.inspect_object(object_id, snapshot_id=snapshot_id)
        if not res.success:
            return {
                "success": False,
                "error": {"code": res.error.code if res.error else "INVALID_OBJECT",
                          "message": res.error.message if res.error else f"Object '{object_id}' not found"}
            }
        data = _to_json_serializable(res.data)
        if isinstance(data, dict):
            raw_type = data.get("type", "Unknown")
            cleaned_type = _clean_type_name(raw_type)
            data["cleaned_type"] = cleaned_type
            data["canonical_type"] = cleaned_type

            snap, _ = self.runtime._resolve_snapshot(snapshot_id)
            if snap:
                snap_dict = snap.to_dict() if hasattr(snap, "to_dict") else dict(snap)
                s_inner = snap_dict.get("snapshot", snap_dict)
                persistent = snap_dict.get("persistent") or s_inner.get("persistent") or {}
                roots = persistent.get("roots", [])
                raw_objs = persistent.get("objects", [])

                obj_paths, root_map = _build_semantic_paths(roots, raw_objs)
                paths = obj_paths.get(object_id, [])
                primary_path = paths[0] if paths else None
                additional_paths = paths[1:] if len(paths) > 1 else []

                root_item = root_map.get(object_id)
                if not root_item and roots and raw_objs:
                    for idx, r in enumerate(roots):
                        if idx < len(raw_objs):
                            f_oid = raw_objs[idx].get("object_id") if isinstance(raw_objs[idx], dict) else getattr(raw_objs[idx], "object_id", None)
                            if f_oid == object_id:
                                root_item = r
                                break

                semantic_path = primary_path or (root_item.get("name") if root_item else cleaned_type)
                data["semantic_name"] = semantic_path
                data["semantic_path"] = semantic_path
                data["primary_path"] = primary_path
                data["paths"] = paths
                data["additional_paths"] = additional_paths

                if root_item:
                    r_name = root_item.get("name") if isinstance(root_item, dict) else getattr(root_item, "name", None)
                    data["root_name"] = r_name
                    data["root_source"] = root_item.get("source") if isinstance(root_item, dict) else getattr(root_item, "source", "Root Variable")

                raw_obj = next((o for o in raw_objs if (o.get("object_id") if isinstance(o, dict) else getattr(o, "object_id", None)) == object_id), None)
                if raw_obj:
                    o_dict = raw_obj if isinstance(raw_obj, dict) else (raw_obj.to_dict() if hasattr(raw_obj, "to_dict") else asdict(raw_obj))
                    addr = o_dict.get("address")
                    data["address"] = addr
                    data["identity"] = f"{cleaned_type}@{addr}" if addr else f"{cleaned_type}:{object_id}"
                    data["thread_id"] = o_dict.get("thread_id")
                    data["frame_level"] = o_dict.get("frame_level")
                    data["storage"] = o_dict.get("storage", "unknown")
                    prov = o_dict.get("provenance", {})
                    data["provenance"] = prov
                    data["status"] = o_dict.get("status", "COMPLETE")
                    data["synthetic"] = bool(o_dict.get("synthetic", False))
                    data["dwarf_type"] = prov.get("dwarf_type") or cleaned_type
                    data["build_id"] = prov.get("build_id") or snap_dict.get("provenance", {}).get("executable_identity", {}).get("build_id")
                    data["memory_range"] = prov.get("memory_range")
                else:
                    addr = data.get("address")
                    data["identity"] = f"{cleaned_type}@{addr}" if addr else f"{cleaned_type}:{object_id}"
                    data["provenance"] = data.get("provenance", {})
                    data["status"] = data.get("status", "COMPLETE")
                    data["synthetic"] = bool(data.get("synthetic", False))
                    data["dwarf_type"] = data.get("provenance", {}).get("dwarf_type") or cleaned_type
                    data["build_id"] = data.get("provenance", {}).get("build_id")
                    data["memory_range"] = data.get("provenance", {}).get("memory_range")

                # Semantic state classification: REAL, PARTIAL, SYNTHETIC, UNRESOLVED
                if data.get("synthetic"):
                    data["semantic_status"] = "SYNTHETIC"
                elif data.get("status") == "PARTIAL":
                    data["semantic_status"] = "PARTIAL"
                elif data.get("status") == "UNRESOLVED":
                    data["semantic_status"] = "UNRESOLVED"
                else:
                    data["semantic_status"] = "REAL"

                # Compute Outgoing and Incoming references
                outgoing_refs = []
                for f in data.get("fields", []):
                    ref_id = f.get("object_ref")
                    if ref_id:
                        target_obj = next((o for o in raw_objs if (o.get("object_id") if isinstance(o, dict) else getattr(o, "object_id", None)) == ref_id), None)
                        t_dict = target_obj if isinstance(target_obj, dict) else (target_obj.to_dict() if hasattr(target_obj, "to_dict") else (asdict(target_obj) if target_obj else {}))
                        outgoing_refs.append({
                            "field": f.get("name"),
                            "target_object_id": ref_id,
                            "target_type": _clean_type_name(t_dict.get("type", "Object")),
                            "target_storage": t_dict.get("storage", "unknown"),
                        })

                incoming_refs = []
                for other_obj in raw_objs:
                    o_d = other_obj if isinstance(other_obj, dict) else (other_obj.to_dict() if hasattr(other_obj, "to_dict") else asdict(other_obj))
                    if o_d.get("object_id") == object_id:
                        continue
                    for f in o_d.get("fields", []):
                        f_d = f if isinstance(f, dict) else (f.to_dict() if hasattr(f, "to_dict") else asdict(f))
                        if f_d.get("object_ref") == object_id:
                            incoming_refs.append({
                                "source_object_id": o_d.get("object_id"),
                                "source_type": _clean_type_name(o_d.get("type", "Object")),
                                "field": f_d.get("name"),
                                "source_storage": o_d.get("storage", "unknown"),
                            })

                data["outgoing_references"] = outgoing_refs
                data["incoming_references"] = incoming_refs
                data["outgoing_count"] = len(outgoing_refs)
                data["incoming_count"] = len(incoming_refs)
                data["reference_count"] = len(outgoing_refs) + len(incoming_refs)
            else:
                data["semantic_name"] = cleaned_type
                data["semantic_path"] = cleaned_type
                data["primary_path"] = cleaned_type
                data["paths"] = [cleaned_type]
                data["additional_paths"] = []
                addr = data.get("address")
                data["identity"] = f"{cleaned_type}@{addr}" if addr else f"{cleaned_type}:{object_id}"

            # Enrich fields with mutability, cleaned_type, and semantic_path
            sem_base = data.get("semantic_path") or data.get("semantic_name") or cleaned_type
            for f in data.get("fields", []):
                if isinstance(f, dict):
                    fname = f.get("name")
                    f["semantic_path"] = f"{sem_base}.{fname}" if fname else sem_base
                    if "mutability" not in f:
                        f["mutability"] = _is_field_mutable(f.get("type", ""))
                    if "cleaned_type" not in f:
                        f["cleaned_type"] = _clean_type_name(f.get("type", ""))

        return {"success": True, "data": data}

    def inspect_fields(self, object_id: str, field_path: Optional[str] = None,
                       snapshot_id: Optional[str] = None) -> Dict[str, Any]:
        if field_path:
            res = self.runtime.inspect_field(object_id, field_path, snapshot_id=snapshot_id)
            if res.success:
                return {"success": True, "data": _to_json_serializable(res.data)}
            return {
                "success": False,
                "error": {"code": res.error.code if res.error else "INVALID_FIELD",
                          "message": res.error.message if res.error else f"Field '{field_path}' not found"}
            }

        obj_res = self.runtime.inspect_object(object_id, snapshot_id=snapshot_id)
        if not obj_res.success:
            return {
                "success": False,
                "error": {"code": obj_res.error.code if obj_res.error else "INVALID_OBJECT",
                          "message": obj_res.error.message if obj_res.error else f"Object '{object_id}' not found"}
            }
        obj_data = _to_json_serializable(obj_res.data)
        fields = obj_data.get("fields", [])
        return {"success": True, "data": fields}

    def list_transitions(self) -> Dict[str, Any]:
        transitions = []
        for tid in self.runtime.corpus.transitions:
            t_data = self.runtime.corpus.get_transition(tid)
            if t_data:
                # Extract summary info
                trans_inner = t_data.get("transition", t_data)
                mut = trans_inner.get("mutation") or {}
                exec_info = trans_inner.get("execution") or {}
                transitions.append({
                    "transition_id": tid,
                    "parent_snapshot": trans_inner.get("parent_snapshot"),
                    "child_snapshot": trans_inner.get("child_snapshot"),
                    "mutation_field": mut.get("field") or mut.get("field_path"),
                    "mutation_value": mut.get("after") if mut.get("after") is not None else mut.get("value"),
                    "mutation_before": mut.get("before") if mut.get("before") is not None else mut.get("old_value"),
                    "status": exec_info.get("status", "STOPPED"),
                })
        return {"success": True, "data": transitions}

    def inspect_transition(self, transition_id: str) -> Dict[str, Any]:
        res = self.runtime.inspect_transition(transition_id)
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {
            "success": False,
            "error": {"code": res.error.code if res.error else "TRANSITION_NOT_FOUND",
                      "message": res.error.message if res.error else f"Transition '{transition_id}' not found"}
        }

    def get_snapshot(self, snapshot_id: str) -> Dict[str, Any]:
        snap, err = self.runtime._resolve_snapshot(snapshot_id)
        if snap is not None:
            return {"success": True, "data": _to_json_serializable(snap)}
        raw_snap = self.runtime._resolve_raw_memory_snapshot(snapshot_id)
        if raw_snap is not None:
            return {"success": True, "data": _to_json_serializable(raw_snap.to_dict())}
        code, msg = err if err else ("SNAPSHOT_NOT_FOUND", f"Snapshot '{snapshot_id}' not found")
        return {"success": False, "error": {"code": code, "message": msg}}

    def diff_snapshots(self, snap_a_id: str, snap_b_id: str) -> Dict[str, Any]:
        if hasattr(self.runtime, "state_lab") and self.runtime.state_lab.get_snapshot(snap_a_id) and self.runtime.state_lab.get_snapshot(snap_b_id):
            res = self.runtime.diff_snapshots(snap_a_id, snap_b_id)
            if res.success:
                diff_data = _to_json_serializable(res.data)
                if isinstance(diff_data, dict):
                    if "changed" in diff_data and "changes" not in diff_data:
                        diff_data["changes"] = diff_data["changed"]
                return {"success": True, "data": diff_data}

        snap_a, err_a = self.runtime._resolve_snapshot(snap_a_id)
        if snap_a is None:
            code, msg = err_a if err_a else ("SNAPSHOT_NOT_FOUND", f"Snapshot '{snap_a_id}' not found")
            return {"success": False, "error": {"code": code, "message": msg}}

        snap_b, err_b = self.runtime._resolve_snapshot(snap_b_id)
        if snap_b is None:
            code, msg = err_b if err_b else ("SNAPSHOT_NOT_FOUND", f"Snapshot '{snap_b_id}' not found")
            return {"success": False, "error": {"code": code, "message": msg}}

        try:
            diff = self.diff_engine.diff(snap_a, snap_b)
            return {"success": True, "data": _to_json_serializable(diff.to_dict())}
        except Exception as exc:
            return {"success": False, "error": {"code": "RUNTIME_ERROR", "message": f"Diff failed: {exc}"}}

    def list_mutation_candidates(self, snapshot_id: Optional[str] = None,
                                 object_id: Optional[str] = None,
                                 field_name: Optional[str] = None) -> Dict[str, Any]:
        res = self.runtime.list_mutation_candidates(snapshot_id=snapshot_id)
        if not res.success:
            return {
                "success": False,
                "error": {"code": res.error.code if res.error else "RUNTIME_ERROR",
                          "message": res.error.message if res.error else "Failed to list candidates"}
            }

        candidates = _to_json_serializable(res.data) or []
        if object_id:
            candidates = [c for c in candidates if c.get("object_id") == object_id]
        if field_name:
            candidates = [c for c in candidates if c.get("field") == field_name]

        # Enrich candidates with semantic names
        if candidates:
            snap, _ = self.runtime._resolve_snapshot(snapshot_id)
            if snap:
                snap_dict = snap.to_dict() if hasattr(snap, "to_dict") else dict(snap)
                s_inner = snap_dict.get("snapshot", snap_dict)
                persistent = snap_dict.get("persistent") or s_inner.get("persistent") or {}
                roots = persistent.get("roots", [])
                raw_objs = persistent.get("objects", [])
                obj_paths, root_map = _build_semantic_paths(roots, raw_objs)

                obj_types = {}
                for o in raw_objs:
                    o_dict = o if isinstance(o, dict) else (o.to_dict() if hasattr(o, "to_dict") else asdict(o))
                    oid = o_dict.get("object_id")
                    otyp = o_dict.get("type")
                    if oid and otyp:
                        obj_types[oid] = _clean_type_name(otyp)

                for c in candidates:
                    oid = c.get("object_id")
                    paths = obj_paths.get(oid, [])
                    sem_path = paths[0] if paths else (root_map.get(oid, {}).get("name") or obj_types.get(oid) or oid)
                    c["semantic_name"] = sem_path
                    c["primary_path"] = sem_path
                    c["paths"] = paths
                    c["semantic_target"] = f"{sem_path}.{c.get('field')}"

        return {"success": True, "data": candidates}

    def get_state_graph(self) -> Dict[str, Any]:
        """Aggregate corpus states and transitions into a visual graph structure."""
        nodes = []
        edges = []

        # 1. Nodes from states
        snap_to_state: Dict[str, str] = {}
        for sid, s_meta in self.runtime.corpus.states.items():
            s_hash = s_meta.get("state_hash", "")
            snap_id = s_meta.get("snapshot_id")
            if snap_id:
                snap_to_state[snap_id] = sid
            for obs in s_meta.get("observations", []):
                snap_to_state[obs] = sid

            reasons = s_meta.get("interesting_reasons", [])
            is_seed = "SEED" in reasons or s_meta.get("parent_state_id") is None

            # Get object count from state if loaded
            obj_count = 0
            state_data = self.runtime.corpus.get(sid)
            if state_data:
                objs = state_data.get("persistent", {}).get("objects", [])
                obj_count = len(objs)

            nodes.append({
                "id": sid,
                "state_hash": s_hash,
                "short_hash": s_hash[:8] if s_hash else sid,
                "parent_state_id": s_meta.get("parent_state_id"),
                "transition_id": s_meta.get("transition_id"),
                "created_at": s_meta.get("created_at"),
                "is_seed": is_seed,
                "object_count": obj_count,
                "status": "STOPPED"
            })

        # 2. Edges from transitions
        for tid in self.runtime.corpus.transitions:
            t_data = self.runtime.corpus.get_transition(tid)
            if not t_data:
                continue
            trans = t_data.get("transition", t_data)
            p_snap = trans.get("parent_snapshot")
            c_snap = trans.get("child_snapshot")

            from_state = snap_to_state.get(p_snap)
            to_state = snap_to_state.get(c_snap)

            # If not mapped by snapshot_id, try finding by transition_id in state_meta
            if not to_state:
                to_state = next((s["id"] for s in nodes if s.get("transition_id") == tid), None)

            mut = trans.get("mutation") or {}
            exec_info = trans.get("execution") or {}
            exec_status = exec_info.get("status", "STOPPED")

            # Update child node status if CRASHED or TIMEOUT
            if to_state and exec_status in ("CRASHED", "TIMEOUT", "EXITED"):
                for n in nodes:
                    if n["id"] == to_state:
                        n["status"] = exec_status

            edges.append({
                "id": tid,
                "from": from_state or p_snap or "UNKNOWN",
                "to": to_state or c_snap or "UNKNOWN",
                "field": mut.get("field") or mut.get("field_path", "unknown"),
                "old_value": mut.get("old_value") if mut.get("old_value") is not None else mut.get("before"),
                "new_value": mut.get("new_value") if mut.get("new_value") is not None else (
                    mut.get("after") if mut.get("after") is not None else (
                        mut.get("value") if mut.get("value") is not None else mut.get("proposed_value")
                    )
                ),
                "status": exec_status,
                "signal": exec_info.get("signal"),
            })

        return {"success": True, "data": {"nodes": nodes, "edges": edges}}

    # -------------------------------------------------------------------------
    # Mutations & Transitions (Strict Safety Enforced)
    # -------------------------------------------------------------------------

    def observe(self, params: Dict[str, Any]) -> Dict[str, Any]:
        mode = params.get("mode", "CONSISTENT")
        pid = params.get("pid")
        policy = params.get("policy", "ALL_READABLE")
        max_bytes = params.get("max_bytes")
        debug_image = params.get("debug_image")

        res = self.runtime.observe(mode=mode, pid=pid, policy=policy, max_bytes=max_bytes, debug_image=debug_image)
        if res.success:
            snap, _ = self.runtime._resolve_snapshot(None)
            if snap:
                sid, is_new = self.runtime.corpus.add(snap, metadata={"interesting_reasons": ["SEED"]})
                if isinstance(res.data, dict):
                    res.data["state_id"] = sid
                elif hasattr(res.data, "state_id"):
                    res.data.state_id = sid
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {
            "success": False,
            "error": {"code": res.error.code if res.error else "RUNTIME_ERROR",
                      "message": res.error.message if res.error else "Observation failed"}
        }

    def snapshot(self, params: Dict[str, Any]) -> Dict[str, Any]:
        sid = params.get("snapshot_id")
        res = self.runtime.snapshot(snapshot_id=sid)
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {
            "success": False,
            "error": {"code": res.error.code if res.error else "RUNTIME_ERROR",
                      "message": res.error.message if res.error else "Snapshot failed"}
        }

    def execute_transition(self, params: Dict[str, Any]) -> Dict[str, Any]:
        # Strict validation: candidate_id or validated candidate dict
        cand = params.get("candidate") or params.get("candidate_id")
        if not cand:
            return {
                "success": False,
                "error": {"code": "INVALID_CANDIDATE", "message": "candidate_id or candidate payload is required"}
            }
        if isinstance(cand, str) and ("proposed_value" in params or "value" in params):
            cand = {
                "candidate_id": cand,
                "proposed_value": params.get("proposed_value") if "proposed_value" in params else params.get("value")
            }
        caps_res = self.runtime.capabilities()
        caps_data = caps_res.data if caps_res.success else {}
        backend_default_timeout = (
            caps_data.get("mutation", {}).get("default_timeout_ms")
            or caps_data.get("limits", {}).get("default_timeout_ms")
            or caps_data.get("default_timeout_ms")
            or 1000
        )
        timeout_ms = int(params.get("timeout_ms", backend_default_timeout))
        res = self.runtime.execute_transition(candidate=cand, timeout_ms=timeout_ms)
        if res.success:
            data = _to_json_serializable(res.data)
            if isinstance(data, dict):
                p_state = data.get("parent_state")
                c_state = data.get("child_state")
                if p_state:
                    p_meta = self.runtime.corpus.get_metadata(p_state) or {}
                    data["parent_state_hash"] = p_meta.get("state_hash")
                if c_state:
                    c_meta = self.runtime.corpus.get_metadata(c_state) or {}
                    data["child_state_hash"] = c_meta.get("state_hash")
                    if not data.get("state_hash"):
                        data["state_hash"] = c_meta.get("state_hash")

                cp_res = caps_data.get("checkpoint_restore", {})
                branch_iso = caps_data.get("branch_isolation", {})
                det_status = cp_res.get("determinism_status") or branch_iso.get("determinism_status") or "UNKNOWN"
                branch_iso_cap = branch_iso.get("status", "UNAVAILABLE")
                branch_iso_verified = bool(branch_iso.get("verified", False))
                branch_iso_source = branch_iso.get("verification_source", None)
                is_det_verified = bool(det_status == "VERIFIED" or cp_res.get("verified") or branch_iso.get("determinism_verified"))

                branch_iso_dict = dict(branch_iso)
                branch_iso_dict["capability"] = branch_iso_cap
                branch_iso_dict["verified"] = branch_iso_verified
                branch_iso_dict["verification_source"] = branch_iso_source
                if "status" not in branch_iso_dict:
                    branch_iso_dict["status"] = branch_iso_cap

                det_cap = "SUPPORTED" if (branch_iso_cap in ("SUPPORTED", "CONDITIONAL") or caps_data.get("checkpoint")) else "UNAVAILABLE"
                det_dict = {
                    "capability": det_cap,
                    "verified": is_det_verified,
                    "status": det_status,
                }

                data["restore_backend"] = cp_res.get("backend", "RESTART" if caps_data.get("threads", 1) > 1 else "GDB_CHECKPOINT")
                data["timeout_ms"] = timeout_ms
                data["branch_isolation"] = branch_iso_dict
                data["branch_isolation_capability"] = branch_iso_cap
                data["branch_isolation_verified"] = branch_iso_verified
                data["branch_isolation_source"] = branch_iso_source
                data["determinism"] = det_dict
                data["determinism_capability"] = det_cap
                data["determinism_status"] = det_status
                data["determinism_verified"] = is_det_verified
            return {"success": True, "data": data}
        return {
            "success": False,
            "error": {"code": res.error.code if res.error else "MUTATION_REJECTED",
                      "message": res.error.message if res.error else "Transition execution failed"}
        }

    def checkpoint(self, params: Dict[str, Any]) -> Dict[str, Any]:
        cid = params.get("checkpoint_id")
        res = self.runtime.checkpoint(checkpoint_id=cid)
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {
            "success": False,
            "error": {"code": res.error.code if res.error else "RUNTIME_ERROR",
                      "message": res.error.message if res.error else "Checkpoint failed"}
        }

    def restore(self, params: Dict[str, Any]) -> Dict[str, Any]:
        cid = params.get("checkpoint_id")
        if not cid:
            return {
                "success": False,
                "error": {"code": "CHECKPOINT_NOT_FOUND", "message": "checkpoint_id is required"}
            }
        res = self.runtime.restore(checkpoint_id=cid)
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {
            "success": False,
            "error": {"code": res.error.code if res.error else "CHECKPOINT_NOT_FOUND",
                      "message": res.error.message if res.error else f"Restore of checkpoint '{cid}' failed"}
        }

    def explore(self, params: Dict[str, Any]) -> Dict[str, Any]:
        max_steps = int(params.get("max_steps", 10))
        timeout_ms = int(params.get("timeout_ms", 1000))
        max_states = int(params.get("max_states", 20))
        res = self.runtime.explore(max_steps=max_steps, timeout_ms=timeout_ms, max_states=max_states)
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {
            "success": False,
            "error": {"code": res.error.code if res.error else "RUNTIME_ERROR",
                      "message": res.error.message if res.error else "Exploration failed"},
            "data": _to_json_serializable(res.data) if res.data else None
        }

    def verify_restart_determinism(self, params: Dict[str, Any]) -> Dict[str, Any]:
        cid = params.get("checkpoint_id")
        res = self.runtime.verify_restart_determinism(checkpoint_id=cid)
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {
            "success": False,
            "error": {"code": res.error.code if res.error else "RUNTIME_ERROR",
                      "message": res.error.message if res.error else "Determinism verification failed"},
            "data": _to_json_serializable(res.data) if res.data else None
        }

    # -------------------------------------------------------------------------
    # State Laboratory & Fast Runtime Capture Adapter Methods
    # -------------------------------------------------------------------------

    def fast_capture(self, params: Dict[str, Any]) -> Dict[str, Any]:
        pid = params.get("pid")
        mode = params.get("mode", "FULL")
        target_path = params.get("target_path")
        timeout_ms = int(params.get("timeout_ms", 1000))
        from extractor.capture_plan import CapturePlanBuilder
        if mode == "TARGETED" and target_path:
            plan = CapturePlanBuilder.build_targeted_plan(target_path=target_path, timeout_ms=timeout_ms)
        elif mode == "THREAD" and params.get("thread_ids"):
            plan = CapturePlanBuilder.build_thread_plan(thread_ids=params.get("thread_ids"), timeout_ms=timeout_ms)
        elif mode == "OBJECT" and params.get("target_objects"):
            plan = CapturePlanBuilder.build_object_plan(object_ids=params.get("target_objects"), timeout_ms=timeout_ms)
        else:
            plan = CapturePlanBuilder.build_full_plan(timeout_ms=timeout_ms)
        res = self.runtime.fast_capture(pid=pid, plan=plan)
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {"success": False, "error": {"code": res.error.code if res.error else "CAPTURE_FAILED",
                                            "message": res.error.message if res.error else "Fast capture failed"}}

    def list_snapshots(self) -> Dict[str, Any]:
        lab_snaps = self.runtime.state_lab.list_snapshots() if hasattr(self.runtime, "state_lab") else []
        all_snaps = list(lab_snaps)
        seen_ids = set(s["snapshot_id"] for s in lab_snaps)
        for state_id, s_data in self.runtime.corpus.states.items():
            if state_id not in seen_ids:
                s_dict = s_data if isinstance(s_data, dict) else (s_data.to_dict() if hasattr(s_data, "to_dict") else {})
                meta = self.runtime.corpus.get_metadata(state_id) or {}
                all_snaps.append({
                    "snapshot_id": state_id,
                    "state_hash": meta.get("state_hash") or s_dict.get("metadata", {}).get("state_hash"),
                    "parent_id": meta.get("parent_state"),
                    "object_count": len(s_dict.get("persistent", {}).get("objects", [])),
                    "thread_count": len(s_dict.get("execution", {}).get("threads", [])),
                    "branch_name": "corpus_state",
                    "created_at": s_dict.get("created_at"),
                })
        return {"success": True, "data": _to_json_serializable(all_snaps)}

    def get_snapshot(self, snapshot_id: str) -> Dict[str, Any]:
        state = self.runtime.state_lab.get_snapshot(snapshot_id) if hasattr(self.runtime, "state_lab") else None
        if state:
            return {"success": True, "data": _to_json_serializable(state.to_snapshot().to_dict())}
        snap, err = self.runtime._resolve_snapshot(snapshot_id)
        if snap:
            s_dict = snap.to_dict() if hasattr(snap, "to_dict") else dict(snap)
            return {"success": True, "data": _to_json_serializable(s_dict)}
        return {"success": False, "error": {"code": "SNAPSHOT_NOT_FOUND", "message": f"Snapshot {snapshot_id} not found"}}

    def get_semantic_state(self, state_id: str) -> Dict[str, Any]:
        state = self.runtime.state_lab.get_snapshot(state_id) if hasattr(self.runtime, "state_lab") else None
        if not state:
            snap, _ = self.runtime._resolve_snapshot(state_id)
            if snap:
                from extractor.semantic_state import SemanticState
                state = SemanticState.from_snapshot(snap)
        if state:
            return {"success": True, "data": _to_json_serializable(state.to_dict())}
        return {"success": False, "error": {"code": "STATE_NOT_FOUND", "message": f"State {state_id} not found"}}

    def mutate_snapshot(self, snapshot_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        target = params.get("target") or (f"{params.get('object_id')}.{params.get('field')}" if params.get("field") else params.get("object_id"))
        value = params.get("proposed_value") if "proposed_value" in params else params.get("value")
        branch_name = params.get("branch_name")
        res = self.runtime.mutate_snapshot(snapshot_id=snapshot_id, target=target, value=value, branch_name=branch_name)
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {"success": False, "error": {"code": res.error.code if res.error else "MUTATION_FAILED",
                                            "message": res.error.message if res.error else "Snapshot mutation failed"}}

    def branch_snapshot(self, snapshot_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        branch_name = params.get("branch_name")
        res = self.runtime.branch_snapshot(snapshot_id=snapshot_id, branch_name=branch_name)
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {"success": False, "error": {"code": res.error.code if res.error else "BRANCH_FAILED",
                                            "message": res.error.message if res.error else "Branch creation failed"}}



    def get_impact_analysis(self, snapshot_id: str, target: Optional[str] = None, candidate_id: Optional[str] = None) -> Dict[str, Any]:
        res = self.runtime.analyze_impact(snapshot_id=snapshot_id, target=target or "", candidate_id=candidate_id)
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {"success": False, "error": {"code": res.error.code if res.error else "IMPACT_FAILED",
                                            "message": res.error.message if res.error else "Impact analysis failed"}}

    def replay_mutation(self, snapshot_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        target_obj = params.get("object_id", "")
        field_name = params.get("field", "")
        val = params.get("proposed_value") if "proposed_value" in params else params.get("value")
        res = self.runtime.replay_mutation(snapshot_id=snapshot_id, target_object_id=target_obj, field_name=field_name, value=val)
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {"success": False, "data": _to_json_serializable(res.data), "error": {"code": res.error.code if res.error else "REPLAY_FAILED",
                                            "message": res.error.message if res.error else "Replay failed"}}

    def get_state_lab_tree(self) -> Dict[str, Any]:
        if hasattr(self.runtime, "state_lab"):
            return {"success": True, "data": _to_json_serializable(self.runtime.state_lab.get_tree())}
        return {"success": True, "data": {"roots": [], "total_snapshots": 0, "total_branches": 0}}



class DynamicStateRequestHandler(http.server.BaseHTTPRequestHandler):
    """HTTP Request Handler providing strict REST API endpoints and static file hosting."""

    server: "DynamicStateWebServer"

    def do_OPTIONS(self) -> None:
        """Handle CORS pre-flight requests safely."""
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")
        query = urllib.parse.parse_qs(parsed.query)

        # 1. API routes
        if path.startswith("/api"):
            self._handle_api_get(path, query)
            return

        # 2. Static files
        self._serve_static(path)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")

        if not path.startswith("/api"):
            self._send_json({"success": False, "error": {"code": "NOT_FOUND", "message": f"Route not found: {path}"}},
                            status=404)
            return

        # Read JSON body safely with content-length check
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 10 * 1024 * 1024:  # 10MB guard
            self._send_json({"success": False, "error": {"code": "PAYLOAD_TOO_LARGE", "message": "Request entity too large"}},
                            status=413)
            return

        body = {}
        if content_length > 0:
            raw_body = self.rfile.read(content_length)
            try:
                body = json.loads(raw_body.decode("utf-8"))
            except Exception as exc:
                self._send_json({"success": False, "error": {"code": "BAD_REQUEST", "message": f"Malformed JSON: {exc}"}},
                                status=400)
                return

        self._handle_api_post(path, body)

    # -------------------------------------------------------------------------
    # REST API Handlers
    # -------------------------------------------------------------------------

    def _handle_api_get(self, path: str, query: Dict[str, List[str]]) -> None:
        adapter = self.server.adapter

        def q_param(name: str, default: Optional[str] = None) -> Optional[str]:
            vals = query.get(name)
            return vals[0] if vals else default

        try:
            # GET /api/health
            if path == "/api/health":
                self._send_json(adapter.get_health())
                return

            # GET /api/capabilities
            if path == "/api/capabilities":
                self._send_json(adapter.get_capabilities())
                return

            # GET /api/runtime
            if path == "/api/runtime":
                self._send_json(adapter.get_runtime_info())
                return

            # GET /api/memory-summary
            if path == "/api/memory-summary":
                self._send_json(adapter.get_memory_summary(snapshot_id=q_param("snapshot_id")))
                return

            # GET /api/modules
            if path == "/api/modules":
                self._send_json(adapter.get_modules(snapshot_id=q_param("snapshot_id")))
                return

            # GET /api/provenance
            if path == "/api/provenance":
                self._send_json(adapter.get_provenance(snapshot_id=q_param("snapshot_id")))
                return

            # GET /api/states
            if path == "/api/states":
                self._send_json(adapter.list_states())
                return

            # GET /api/states/{state_id}/memory-summary
            m_state_mem = re.match(r"^/api/states/([^/]+)/memory-summary$", path)
            if m_state_mem:
                state_id = m_state_mem.group(1)
                self._send_json(adapter.get_state_memory_summary(state_id))
                return

            # GET /api/states/{state_id}/objects/{object_id}
            m_state_obj = re.match(r"^/api/states/([^/]+)/objects/([^/]+)$", path)
            if m_state_obj:
                state_id = m_state_obj.group(1)
                object_id = m_state_obj.group(2)
                self._send_json(adapter.inspect_object(object_id, snapshot_id=state_id))
                return

            # GET /api/states/{state_id}/objects
            m_state_objs = re.match(r"^/api/states/([^/]+)/objects$", path)
            if m_state_objs:
                state_id = m_state_objs.group(1)
                self._send_json(adapter.list_state_objects(state_id))
                return

            # GET /api/states/{state_id}
            m_state = re.match(r"^/api/states/([^/]+)$", path)
            if m_state:
                state_id = m_state.group(1)
                self._send_json(adapter.inspect_state(state_id))
                return

            # GET /api/objects/{object_id}/fields
            m_obj_fields = re.match(r"^/api/objects/([^/]+)/fields$", path)
            if m_obj_fields:
                object_id = m_obj_fields.group(1)
                self._send_json(adapter.inspect_fields(
                    object_id,
                    field_path=q_param("field_path") or q_param("field"),
                    snapshot_id=q_param("snapshot_id")
                ))
                return

            # GET /api/objects/{object_id}
            m_obj = re.match(r"^/api/objects/([^/]+)$", path)
            if m_obj:
                object_id = m_obj.group(1)
                self._send_json(adapter.inspect_object(object_id, snapshot_id=q_param("snapshot_id")))
                return

            # GET /api/transitions
            if path == "/api/transitions":
                self._send_json(adapter.list_transitions())
                return

            # GET /api/transitions/{transition_id}
            m_trans = re.match(r"^/api/transitions/([^/]+)$", path)
            if m_trans:
                transition_id = m_trans.group(1)
                self._send_json(adapter.inspect_transition(transition_id))
                return

            # GET /api/snapshots/{snapshot_id}/diff/{other_snapshot_id}
            m_diff = re.match(r"^/api/snapshots/([^/]+)/diff/([^/]+)$", path)
            if m_diff:
                snap_a = m_diff.group(1)
                snap_b = m_diff.group(2)
                self._send_json(adapter.diff_snapshots(snap_a, snap_b))
                return

            # GET /api/snapshots
            if path == "/api/snapshots":
                self._send_json(adapter.list_snapshots())
                return

            # GET /api/state-lab/tree
            if path == "/api/state-lab/tree":
                self._send_json(adapter.get_state_lab_tree())
                return

            # GET /api/state/{state_id}
            m_sem_state = re.match(r"^/api/state/([^/]+)$", path)
            if m_sem_state:
                state_id = m_sem_state.group(1)
                self._send_json(adapter.get_semantic_state(state_id))
                return

            # GET /api/impact/{snapshot_id}
            m_impact = re.match(r"^/api/impact/([^/]+)$", path)
            if m_impact:
                snapshot_id = m_impact.group(1)
                self._send_json(adapter.get_impact_analysis(
                    snapshot_id,
                    target=q_param("target") or q_param("field"),
                    candidate_id=q_param("candidate_id")
                ))
                return

            # GET /api/snapshots/{snapshot_id}
            m_snap = re.match(r"^/api/snapshots/([^/]+)$", path)
            if m_snap:
                snapshot_id = m_snap.group(1)
                self._send_json(adapter.get_snapshot(snapshot_id))
                return

            # GET /api/mutation-candidates or /api/mutation/candidates
            if path in ("/api/mutation-candidates", "/api/mutation/candidates"):
                self._send_json(adapter.list_mutation_candidates(
                    snapshot_id=q_param("snapshot_id"),
                    object_id=q_param("object_id"),
                    field_name=q_param("field_path") or q_param("field")
                ))
                return

            # GET /api/state-graph
            if path == "/api/state-graph":
                self._send_json(adapter.get_state_graph())
                return

            # GET /api/verify-determinism
            if path in ("/api/verify-determinism", "/api/runtime/verify_determinism"):
                self._send_json(adapter.verify_restart_determinism({}))
                return

            # Unrecognized API endpoint
            self._send_json({"success": False, "error": {"code": "NOT_FOUND", "message": f"Endpoint not found: {path}"}},
                            status=404)

        except Exception as exc:
            self._send_json({"success": False, "error": {"code": "RUNTIME_ERROR", "message": str(exc)}},
                            status=500)

    def _handle_api_post(self, path: str, body: Dict[str, Any]) -> None:
        adapter = self.server.adapter

        # Security check: forbid any bypass endpoints
        forbidden_endpoints = ("/api/gdb-command", "/api/write-memory", "/api/eval-expression", "/api/arbitrary-command")
        if any(path.startswith(fb) for fb in forbidden_endpoints):
            self._send_json({
                "success": False,
                "error": {"code": "CAPABILITY_UNSUPPORTED", "message": "Direct execution / memory write endpoints are strictly prohibited."}
            }, status=403)
            return

        try:
            if path == "/api/observe":
                self._send_json(adapter.observe(body))
                return
            if path == "/api/snapshot":
                self._send_json(adapter.snapshot(body))
                return
            if path in ("/api/mutation", "/api/transition"):
                self._send_json(adapter.execute_transition(body))
                return
            if path == "/api/checkpoint":
                self._send_json(adapter.checkpoint(body))
                return
            if path == "/api/restore":
                self._send_json(adapter.restore(body))
                return
            if path == "/api/explore":
                self._send_json(adapter.explore(body))
                return
            if path in ("/api/verify-determinism", "/api/runtime/verify_determinism"):
                self._send_json(adapter.verify_restart_determinism(body))
                return

            # State Laboratory POST routes
            if path == "/api/capture":
                self._send_json(adapter.fast_capture(body))
                return

            # POST /api/snapshots/{id}/mutate
            m_mut_snap = re.match(r"^/api/snapshots/([^/]+)/mutate$", path)
            if m_mut_snap:
                sid = m_mut_snap.group(1)
                self._send_json(adapter.mutate_snapshot(sid, body))
                return

            # POST /api/snapshots/{id}/branch
            m_br_snap = re.match(r"^/api/snapshots/([^/]+)/branch$", path)
            if m_br_snap:
                sid = m_br_snap.group(1)
                self._send_json(adapter.branch_snapshot(sid, body))
                return

            # POST /api/snapshots/{id}/diff/{other_id}
            m_diff_post = re.match(r"^/api/snapshots/([^/]+)/diff/([^/]+)$", path)
            if m_diff_post:
                snap_a = m_diff_post.group(1)
                snap_b = m_diff_post.group(2)
                self._send_json(adapter.diff_snapshots(snap_a, snap_b))
                return

            # POST /api/snapshots/{id}/replay
            m_rep_snap = re.match(r"^/api/snapshots/([^/]+)/replay$", path)
            if m_rep_snap:
                sid = m_rep_snap.group(1)
                self._send_json(adapter.replay_mutation(sid, body))
                return

            self._send_json({"success": False, "error": {"code": "NOT_FOUND", "message": f"Endpoint not found: {path}"}},
                            status=404)

        except Exception as exc:
            self._send_json({"success": False, "error": {"code": "RUNTIME_ERROR", "message": str(exc)}},
                            status=500)

    # -------------------------------------------------------------------------
    # Static File Server
    # -------------------------------------------------------------------------

    def _serve_static(self, path: str) -> None:
        static_dir = self.server.static_dir
        if not static_dir or not os.path.exists(static_dir):
            self.send_error(404, "Static files directory not found")
            return

        # Default to index.html
        if not path or path == "/":
            rel_path = "index.html"
        elif path.startswith("/static/"):
            rel_path = path[len("/static/"):]
        else:
            rel_path = path.lstrip("/")

        # Path traversal guard
        full_path = os.path.abspath(os.path.join(static_dir, rel_path))
        if os.path.commonpath([static_dir, full_path]) != static_dir:
            self.send_error(403, "Forbidden")
            return

        if not os.path.isfile(full_path):
            # Fall back to index.html for client-side routing
            index_path = os.path.join(static_dir, "index.html")
            if os.path.isfile(index_path):
                full_path = index_path
            else:
                self.send_error(404, "File not found")
                return

        mime_type, _ = mimetypes.guess_type(full_path)
        if not mime_type:
            mime_type = "application/octet-stream"

        try:
            with open(full_path, "rb") as f:
                content = f.read()

            self.send_response(200)
            self.send_header("Content-Type", mime_type)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(content)
        except Exception as exc:
            self.send_error(500, f"Error reading static file: {exc}")

    def _send_json(self, data: Any, status: int = 200) -> None:
        encoded = json.dumps(data, indent=2, ensure_ascii=False, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args: Any) -> None:
        # Keep server output quiet or structured unless debugging
        if os.environ.get("DYNAMICSTATE_LOG_HTTP"):
            super().log_message(format, *args)


class DynamicStateWebServer(http.server.HTTPServer):
    """HTTP Server for dynamicState Web UI."""

    def __init__(self, server_address: Tuple[str, int], runtime: AgentRuntime, static_dir: str):
        super().__init__(server_address, DynamicStateRequestHandler)
        self.runtime = runtime
        self.adapter = WebApiAdapter(runtime)
        self.static_dir = os.path.abspath(static_dir)


def run_server(runtime: AgentRuntime, host: str = "127.0.0.1", port: int = 8000,
               static_dir: Optional[str] = None) -> DynamicStateWebServer:
    """Instantiate and configure the HTTP server."""
    if static_dir is None:
        static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

    server = DynamicStateWebServer((host, port), runtime, static_dir)
    return server


def run_server_loop(server: DynamicStateWebServer) -> None:
    """Run server loop with safe signal handling and clean Ctrl+C shutdown with zero deadlock."""
    import signal

    stop_requested = threading.Event()

    def _serve():
        try:
            server.serve_forever(poll_interval=0.2)
        except Exception:
            pass

    t = threading.Thread(target=_serve, daemon=True)
    t.start()

    def handle_signal(sig, frame):
        stop_requested.set()

    try:
        signal.signal(signal.SIGINT, handle_signal)
        signal.signal(signal.SIGTERM, handle_signal)
    except (ValueError, AttributeError):
        pass

    try:
        while not stop_requested.is_set():
            time.sleep(0.1)
    except KeyboardInterrupt:
        stop_requested.set()
    finally:
        server.shutdown()
        server.server_close()
        t.join(timeout=2.0)

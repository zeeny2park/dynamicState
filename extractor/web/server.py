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
from extractor.static_analyzer import (
    StaticAnalysisProvider,
    get_static_provider,
    resolve_function_candidates,
    LAYOUT_MUTATION_CAVEAT,
)
from extractor.watch_session import WatchSessionManager


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
        self.watch_manager = getattr(runtime, "watch_session_manager", None) or WatchSessionManager(corpus_dir=self.runtime.corpus_dir)

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
                    data["decl_file"] = o_dict.get("decl_file")
                    data["decl_line"] = o_dict.get("decl_line")
                    data["type_decl_file"] = o_dict.get("decl_file")
                    data["type_decl_line"] = o_dict.get("decl_line")
                    data["display_name"] = o_dict.get("display_name") or o_dict.get("name") or data.get("semantic_name") or (f"{cleaned_type}@{addr}" if addr else object_id)
                else:
                    addr = data.get("address")
                    data["identity"] = f"{cleaned_type}@{addr}" if addr else f"{cleaned_type}:{object_id}"
                    data["provenance"] = data.get("provenance", {})
                    data["status"] = data.get("status", "COMPLETE")
                    data["synthetic"] = bool(data.get("synthetic", False))
                    data["dwarf_type"] = data.get("provenance", {}).get("dwarf_type") or cleaned_type
                    data["build_id"] = data.get("provenance", {}).get("build_id")
                    data["memory_range"] = data.get("provenance", {}).get("memory_range")
                    data["display_name"] = data.get("display_name") or data.get("name") or data.get("semantic_name") or (f"{cleaned_type}@{addr}" if addr else object_id)

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
                data["display_name"] = data.get("display_name") or data.get("name") or (f"{cleaned_type}@{addr}" if addr else object_id)

            # Enrich fields with mutability, cleaned_type, semantic_path, decl_file, decl_line, and interpretation
            sem_base = data.get("semantic_path") or data.get("semantic_name") or cleaned_type
            raw_fields = (o_dict.get("fields", []) if 'o_dict' in locals() and o_dict else [])
            rf_map = {rf.get("name"): rf for rf in raw_fields if isinstance(rf, dict)}

            for f in data.get("fields", []):
                if isinstance(f, dict):
                    fname = f.get("name")
                    f["semantic_path"] = f"{sem_base}.{fname}" if fname else sem_base
                    if "mutability" not in f:
                        f["mutability"] = _is_field_mutable(f.get("type", ""))
                    if "cleaned_type" not in f:
                        f["cleaned_type"] = _clean_type_name(f.get("type", ""))
                    rf = rf_map.get(fname, {})
                    if not f.get("decl_file"):
                        f["decl_file"] = rf.get("decl_file")
                    if not f.get("decl_line"):
                        f["decl_line"] = rf.get("decl_line")
                    if not f.get("type_decl_file"):
                        f["type_decl_file"] = rf.get("type_decl_file")
                    if not f.get("type_decl_line"):
                        f["type_decl_line"] = rf.get("type_decl_line")

                    f_st = f.get("status") or rf.get("status") or "RESOLVED"
                    if data.get("synthetic"):
                        f["interpretation"] = "interpreted"
                    elif f_st == "RESOLVED":
                        f["interpretation"] = "observed"
                    else:
                        f["interpretation"] = "unrecoverable"

            # Attach code navigation candidates
            static_prov = self._resolve_static_provider(snap_dict if 'snap_dict' in locals() else None)
            nav_info = resolve_function_candidates(
                target_object=data,
                target_field=None,
                snapshot=snap_dict if 'snap_dict' in locals() else None,
                static_provider=static_prov,
            )
            data["code_navigation"] = nav_info
            data["function_candidates"] = nav_info.get("candidates", [])

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

    def _resolve_static_provider(self, snapshot_dict: Optional[Dict[str, Any]] = None) -> StaticAnalysisProvider:
        debug_path = None
        if hasattr(self.runtime, "controller") and hasattr(self.runtime.controller, "debug_image_path"):
            debug_path = self.runtime.controller.debug_image_path
        if not debug_path and snapshot_dict:
            prov = snapshot_dict.get("provenance") or {}
            debug_path = prov.get("debug_image_path") or prov.get("executable_identity", {}).get("path")
            if not debug_path:
                proc = snapshot_dict.get("process") or {}
                debug_path = proc.get("binary")
        if not debug_path or not os.path.exists(debug_path):
            default_elf = os.path.abspath("build/app_debug.elf")
            if os.path.exists(default_elf):
                debug_path = default_elf

        if debug_path and os.path.exists(debug_path):
            return get_static_provider(backend="dwarf", debug_artifact_path=debug_path)
        return get_static_provider(backend="null")

    def get_code_navigation(self, object_id: str, field_name: Optional[str] = None,
                           snapshot_id: Optional[str] = None) -> Dict[str, Any]:
        """Correlate candidate functions and source code locations for an object and optional field."""
        snap, err = self.runtime._resolve_snapshot(snapshot_id)
        if err:
            return {
                "success": False,
                "error": {"code": err[0], "message": err[1]}
            }

        snap_dict = snap.to_dict() if hasattr(snap, "to_dict") else dict(snap)
        s_inner = snap_dict.get("snapshot", snap_dict)
        persistent = snap_dict.get("persistent") or s_inner.get("persistent") or {}
        raw_objs = persistent.get("objects", [])

        target_obj = next((o for o in raw_objs if (o.get("object_id") if isinstance(o, dict) else getattr(o, "object_id", None)) == object_id), None)
        if not target_obj:
            res = self.runtime.inspect_object(object_id, snapshot_id=snapshot_id)
            if not res.success:
                return {
                    "success": False,
                    "error": {"code": res.error.code if res.error else "INVALID_OBJECT",
                              "message": res.error.message if res.error else f"Object '{object_id}' not found"}
                }
            target_obj = _to_json_serializable(res.data)

        obj_dict = target_obj if isinstance(target_obj, dict) else (target_obj.to_dict() if hasattr(target_obj, "to_dict") else asdict(target_obj))

        target_field = None
        if field_name:
            for f in obj_dict.get("fields", []):
                f_d = f if isinstance(f, dict) else (f.to_dict() if hasattr(f, "to_dict") else asdict(f))
                if f_d.get("name") == field_name:
                    target_field = f_d
                    break
            if not target_field:
                target_field = {"name": field_name}

        static_prov = self._resolve_static_provider(snap_dict)
        nav_result = resolve_function_candidates(
            target_object=obj_dict,
            target_field=target_field,
            snapshot=snap_dict,
            static_provider=static_prov,
        )

        nav_result["type_decl_file"] = obj_dict.get("decl_file")
        nav_result["type_decl_line"] = obj_dict.get("decl_line")
        addr_val = obj_dict.get("address")
        nav_result["object_address"] = obj_dict.get("hex_address") or (hex(addr_val) if isinstance(addr_val, int) else addr_val)
        nav_result["object_size"] = obj_dict.get("size")

        return {"success": True, "data": nav_result}

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
        debug_image = params.get("debug_image")
        res = self.runtime.fast_capture(pid=pid, plan=plan, debug_image=debug_image)
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

    # -------------------------------------------------------------------------
    # Investigation Workflow API
    # -------------------------------------------------------------------------

    def validate_target(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Pre-validate local or remote embedded target process readability and debug-image compatibility."""
        raw_loc = params.get("locale") or params.get("language") or "en"
        locale = "ko" if str(raw_loc).lower().strip() in ("ko", "kor", "korean") else "en"
        is_ko = (locale == "ko")

        remote_host = (params.get("remote_host") or "").strip() or None
        ssh_user = (params.get("ssh_user") or "").strip() or None
        ssh_port = int(params.get("ssh_port") or 22)
        ssh_key = (params.get("ssh_key") or "").strip() or None
        ssh_proxy_jump = (params.get("ssh_proxy_jump") or "").strip() or None
        process_name = (params.get("process_name") or "").strip() or None

        raw_pid = params.get("pid")
        pid: Optional[int] = None

        # Pre-inspect debug image if provided (supports comma-separated main ELF + .so debug ELFs)
        raw_dbg_full = params.get("debug_image") or params.get("companion_elf")
        raw_dbg = raw_dbg_full.split(",")[0].strip() if (raw_dbg_full and isinstance(raw_dbg_full, str)) else raw_dbg_full
        dbg_path: Optional[str] = None
        dbg_ident = None
        if raw_dbg and isinstance(raw_dbg, str) and raw_dbg.strip():
            cand_dbg = os.path.abspath(raw_dbg.strip())
            if os.path.isfile(cand_dbg):
                dbg_path = cand_dbg
                try:
                    from extractor.debug_image import inspect_elf
                    dbg_ident = inspect_elf(dbg_path)
                except Exception:
                    dbg_ident = None

        # Resolve PID via process_name if pid is omitted/empty and process_name is given
        if (raw_pid is None or str(raw_pid).strip() in ("", "0")) and process_name:
            target_adapter = self.watch_manager._resolve_adapter(
                pid=1,
                remote_host=remote_host,
                ssh_user=ssh_user,
                ssh_port=ssh_port,
                ssh_key=ssh_key,
                ssh_proxy_jump=ssh_proxy_jump,
            )
            matches = target_adapter.find_processes(
                process_name=process_name,
                companion_build_id=(dbg_ident.build_id if dbg_ident else None),
            )
            if not matches:
                msg = (
                    f"대상 호스트({target_adapter.target_host()})에서 프로세스 '{process_name}'를 찾을 수 없습니다."
                    if is_ko else
                    f"No running process matching '{process_name}' found on {target_adapter.target_host()}."
                )
                act = "프로세스 이름이나 원격 호스트 연결 상태를 확인하세요." if is_ko else "Verify the process name or check target host connectivity."
                return {"success": True, "data": {"valid": False, "reason": "TARGET_NOT_FOUND", "message": msg, "next_action": act}}
            pid = int(matches[0]["pid"])
        else:
            if raw_pid is None or isinstance(raw_pid, bool):
                msg = "대상 PID가 필요하며 양의 정수여야 합니다." if is_ko else "Target PID is required and must be a positive integer."
                act = "실행 중인 대상 프로세스의 올바른 PID를 입력하세요." if is_ko else "Enter a valid running process PID."
                return {"success": False, "error": {"code": "INVALID_PARAM", "message": msg, "next_action": act}}

            try:
                pid = int(raw_pid)
                if pid <= 0 or pid > 2147483647:
                    raise ValueError("out of range")
            except (ValueError, TypeError):
                msg = f"유효하지 않은 PID 형식입니다: '{raw_pid}'. 1 이상의 정수여야 합니다." if is_ko else f"Invalid PID format: '{raw_pid}'. Must be an integer >= 1."
                act = "실행 중인 대상 프로세스의 올바른 PID를 입력하세요." if is_ko else "Enter a valid running process PID."
                return {"success": False, "error": {"code": "INVALID_PARAM", "message": msg, "next_action": act}}

        # Remote Embedded Target Validation Path
        if remote_host:
            target_adapter = self.watch_manager._resolve_adapter(
                pid=pid,
                remote_host=remote_host,
                ssh_user=ssh_user,
                ssh_port=ssh_port,
                ssh_key=ssh_key,
                ssh_proxy_jump=ssh_proxy_jump,
            )
            alive, live_err = target_adapter.check_liveness(pid)
            if not alive:
                reason = "PERMISSION_DENIED" if (live_err and "permission" in live_err.lower()) else "TARGET_NOT_FOUND"
                msg = (
                    f"원격 타깃({target_adapter.target_host()})의 PID {pid}에 접근할 수 없습니다: {live_err}"
                    if is_ko else
                    f"Remote target PID {pid} on {target_adapter.target_host()} is not accessible: {live_err}"
                )
                act = "SSH 연결 설정 및 원격 장비에서 대상 프로세스가 실행 중인지 확인하세요." if is_ko else "Verify SSH connectivity and check that the process is running on the remote target."
                return {"success": True, "data": {"valid": False, "reason": reason, "message": msg, "next_action": act}}

            if not raw_dbg or not isinstance(raw_dbg, str) or not raw_dbg.strip():
                msg = "매칭되는 non-stripped 디버그 이미지 ELF 경로가 필요합니다." if is_ko else "A matching non-stripped debug image ELF path is required."
                act = "DWARF 심볼이 포함된 바이너리 경로를 입력하세요." if is_ko else "Provide the path to an unstripped ELF binary containing DWARF symbols."
                return {"success": True, "data": {"valid": False, "reason": "DEBUG_IMAGE_NOT_FOUND", "message": msg, "next_action": act}}

            dbg_path = os.path.abspath(raw_dbg.strip())
            if not os.path.isfile(dbg_path):
                msg = f"디버그 이미지 파일 '{dbg_path}'를 찾을 수 없습니다." if is_ko else f"Debug image file '{dbg_path}' not found."
                act = "지정한 파일 경로가 실제로 존재하는지 확인하세요." if is_ko else "Verify that the specified file path exists on disk."
                return {"success": True, "data": {"valid": False, "reason": "DEBUG_IMAGE_NOT_FOUND", "message": msg, "next_action": act}}

            from extractor.debug_image import inspect_elf
            try:
                dbg_ident = inspect_elf(dbg_path)
            except Exception as e:
                msg = f"디버그 이미지가 유효한 ELF 파일이 아닙니다: {e}" if is_ko else f"Debug image is not a valid ELF file: {e}"
                act = "유효한 Linux ELF 바이너리를 지정하세요." if is_ko else "Provide a valid Linux ELF executable or shared library."
                return {"success": True, "data": {"valid": False, "reason": "INVALID_ELF", "message": msg, "next_action": act}}

            if not dbg_ident.has_debug_info:
                msg = "제공된 디버그 이미지에 DWARF 디버그 정보(.debug_info 섹션)가 없습니다." if is_ko else "Debug image contains no DWARF debug information (.debug_info section is missing)."
                act = "대상 프로그램을 디버그 플래그(-g 또는 -g3)로 컴파일하고 스트립되지 않은(non-stripped) 바이너리를 지정하세요." if is_ko else "Recompile target with debug symbols (-g or -g3) and provide the non-stripped binary."
                return {"success": True, "data": {"valid": False, "reason": "MISSING_DWARF", "message": msg, "next_action": act}}

            rem_ident = target_adapter.get_process_identity(pid)
            rem_bid = rem_ident.get("build_id")
            if rem_bid and dbg_ident.build_id and rem_bid.lower() != dbg_ident.build_id.lower():
                msg = (
                    f"Build ID 불일치: 원격 실행 바이너리({rem_bid[:16]}...)와 호스트 디버그 이미지({dbg_ident.build_id[:16]}...)가 다릅니다."
                    if is_ko else
                    f"Build ID mismatch: remote process binary ({rem_bid[:16]}...) does not match debug image ({dbg_ident.build_id[:16]}...)."
                )
                act = "원격 임베디드 프로세스와 동일한 빌드에서 생성된 nostrip 바이너리를 지정하세요." if is_ko else "Provide the exact matching debug image compiled from the same build."
                return {
                    "success": True,
                    "data": {
                        "valid": False,
                        "reason": "BUILD_ID_MISMATCH",
                        "message": msg,
                        "next_action": act,
                        "target_build_id": rem_bid,
                        "debug_image_build_id": dbg_ident.build_id,
                    }
                }

            rem_arch = rem_ident.get("architecture")
            if rem_arch and rem_arch != "unknown" and dbg_ident.architecture and rem_arch != dbg_ident.architecture:
                msg = f"아키텍처 불일치: 원격 프로세스는 {rem_arch}이지만 디버그 이미지는 {dbg_ident.architecture}입니다." if is_ko else f"Architecture mismatch: remote process is {rem_arch} but debug image is {dbg_ident.architecture}."
                act = f"원격 프로세스 아키텍처({rem_arch})에 맞는 바이너리를 제공하세요." if is_ko else f"Provide a binary matching target architecture ({rem_arch})."
                return {"success": True, "data": {"valid": False, "reason": "ARCH_MISMATCH", "message": msg, "next_action": act}}

            rec_symbols = []
            try:
                from extractor.dwarf_indexer import DwarfIndexer
                rec_symbols = DwarfIndexer.get_index(dbg_path).search_symbols(limit=10, smart_rank=True)
            except Exception:
                rec_symbols = []

            return {
                "success": True,
                "data": {
                    "valid": True,
                    "reason": "VALID",
                    "pid": pid,
                    "is_remote": True,
                    "target_host": target_adapter.target_host(),
                    "executable": rem_ident.get("executable") or f"/proc/{pid}/exe",
                    "executable_path": rem_ident.get("executable") or f"/proc/{pid}/exe",
                    "target_build_id": rem_bid or dbg_ident.build_id,
                    "debug_image": dbg_path,
                    "debug_image_path": dbg_path,
                    "debug_build_id": dbg_ident.build_id,
                    "debug_image_build_id": dbg_ident.build_id,
                    "has_dwarf": dbg_ident.has_debug_info,
                    "has_debug_info": dbg_ident.has_debug_info,
                    "build_id_match": True,
                    "architecture": dbg_ident.architecture,
                    "arch": dbg_ident.architecture,
                    "endianness": dbg_ident.endianness,
                    "endian": dbg_ident.endianness,
                    "memory_read_backend": "remote_proc_mem",
                    "capture_backend": "remote_proc_mem",
                    "backend": "remote_proc_mem",
                    "capture_quality": "LOW_IMPACT",
                    "recommended_symbols": rec_symbols,
                    "message": f"원격 타깃({target_adapter.target_host()}) 프로세스 및 디버그 이미지가 검증되었습니다." if is_ko else f"Remote target ({target_adapter.target_host()}) process and debug image verified successfully.",
                    "next_action": "상태 캡처 및 무중단 분석을 진행할 수 있습니다." if is_ko else "Ready to capture and analyze remote runtime state.",
                }
            }

        # 1. Local Process existence check
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            msg = f"대상 프로세스 PID {pid}를 찾을 수 없습니다 (ESRCH)." if is_ko else f"Target process PID {pid} was not found (ESRCH)."
            act = f"ps -p {pid} 명령으로 프로세스가 실행 중인지 확인하거나 대상 프로세스를 시작하세요." if is_ko else f"Verify that process {pid} is running using `ps -p {pid}` or start the target process."
            return {"success": True, "data": {"valid": False, "reason": "TARGET_NOT_FOUND", "message": msg, "next_action": act}}
        except PermissionError:
            msg = f"PID {pid}에 접근할 권한이 없습니다 (EPERM)." if is_ko else f"Permission denied accessing PID {pid} (EPERM)."
            act = "ptrace_scope 설정(/proc/sys/kernel/yama/ptrace_scope)을 확인하거나 동일한 사용자 또는 root 권한으로 실행하세요." if is_ko else "Check ptrace_scope settings (/proc/sys/kernel/yama/ptrace_scope) or run dynamicState as the same user or root."
            return {"success": True, "data": {"valid": False, "reason": "PERMISSION_DENIED", "message": msg, "next_action": act}}
        except Exception as e:
            msg = f"PID {pid} 접근 확인 실패: {e}" if is_ko else f"Failed to check PID {pid}: {e}"
            act = "프로세스 상태 및 시스템 권한을 확인하세요." if is_ko else "Check process status and system permissions."
            return {"success": True, "data": {"valid": False, "reason": "TARGET_CHECK_FAILED", "message": msg, "next_action": act}}

        # 2. Resolve /proc/<pid>/exe
        exe_path = None
        try:
            exe_path = os.readlink(f"/proc/{pid}/exe")
        except PermissionError:
            msg = f"/proc/{pid}/exe 심볼릭 링크를 읽을 권한이 없습니다 (EPERM)." if is_ko else f"Permission denied reading /proc/{pid}/exe (EPERM)."
            act = "프로세스 소유자와 동일한 사용자로 dynamicState를 실행하거나 권한을 승격하세요." if is_ko else "Run dynamicState as the target owner or with elevated permissions."
            return {"success": True, "data": {"valid": False, "reason": "PERMISSION_DENIED", "message": msg, "next_action": act}}
        except Exception:
            exe_path = None

        # 3. Check capture backend accessibility
        from extractor.capture_backend import ProcessVmCaptureBackend, ProcfsCaptureBackend
        vm_backend = ProcessVmCaptureBackend()
        proc_backend = ProcfsCaptureBackend()
        selected_backend = None

        if vm_backend.is_available(pid):
            selected_backend = "process_vm_readv"
        elif proc_backend.is_available(pid):
            selected_backend = "procfs"
        else:
            msg = f"PID {pid}의 메모리를 읽을 수 있는 백엔드가 없습니다 (process_vm_readv 및 /proc/{pid}/mem 모두 접근 불가)." if is_ko else f"No capture backend available for PID {pid} (both process_vm_readv and /proc/{pid}/mem are inaccessible)."
            act = "ptrace 권한을 확인하거나 sudo sysctl kernel.yama.ptrace_scope=0 설정을 검토하세요." if is_ko else "Check ptrace permissions or consider `sudo sysctl kernel.yama.ptrace_scope=0`."
            return {"success": True, "data": {"valid": False, "reason": "NO_BACKEND_AVAILABLE", "message": msg, "next_action": act}}

        # 4. Check debug image path
        if not raw_dbg or not isinstance(raw_dbg, str) or not raw_dbg.strip():
            msg = "매칭되는 non-stripped 디버그 이미지 ELF 경로가 필요합니다." if is_ko else "A matching non-stripped debug image ELF path is required."
            act = "DWARF 심볼이 포함된 바이너리 경로를 입력하세요." if is_ko else "Provide the path to an unstripped ELF binary containing DWARF symbols."
            return {"success": True, "data": {"valid": False, "reason": "DEBUG_IMAGE_NOT_FOUND", "message": msg, "next_action": act}}

        dbg_path = os.path.abspath(raw_dbg.strip())
        if not os.path.isfile(dbg_path):
            msg = f"디버그 이미지 파일 '{dbg_path}'를 찾을 수 없습니다." if is_ko else f"Debug image file '{dbg_path}' not found."
            act = "지정한 파일 경로가 실제로 존재하는지 확인하세요." if is_ko else "Verify that the specified file path exists on disk."
            return {"success": True, "data": {"valid": False, "reason": "DEBUG_IMAGE_NOT_FOUND", "message": msg, "next_action": act}}

        # 5. Inspect debug image ELF & DWARF
        from extractor.debug_image import inspect_elf
        try:
            dbg_ident = inspect_elf(dbg_path)
        except Exception as e:
            msg = f"디버그 이미지가 유효한 ELF 파일이 아닙니다: {e}" if is_ko else f"Debug image is not a valid ELF file: {e}"
            act = "유효한 Linux ELF 바이너리를 지정하세요." if is_ko else "Provide a valid Linux ELF executable or shared library."
            return {"success": True, "data": {"valid": False, "reason": "INVALID_ELF", "message": msg, "next_action": act}}

        if not dbg_ident.has_debug_info:
            msg = "제공된 디버그 이미지에 DWARF 디버그 정보(.debug_info 섹션)가 없습니다." if is_ko else "Debug image contains no DWARF debug information (.debug_info section is missing)."
            act = "대상 프로그램을 디버그 플래그(-g 또는 -g3)로 컴파일하고 스트립되지 않은(non-stripped) 바이너리를 지정하세요." if is_ko else "Recompile target with debug symbols (-g or -g3) and provide the non-stripped binary."
            return {"success": True, "data": {"valid": False, "reason": "MISSING_DWARF", "message": msg, "next_action": act}}

        # 6. Check target binary Build ID vs debug image Build ID
        target_ident = None
        if exe_path and os.path.isfile(exe_path):
            try:
                target_ident = inspect_elf(exe_path)
            except Exception:
                target_ident = None

        if target_ident and target_ident.build_id and dbg_ident.build_id:
            if target_ident.build_id.lower() != dbg_ident.build_id.lower():
                msg = (
                    f"Build ID 불일치: 실행 중인 바이너리 Build ID({target_ident.build_id[:16]}...)와 "
                    f"디버그 이미지 Build ID({dbg_ident.build_id[:16]}...)가 다릅니다."
                    if is_ko else
                    f"Build ID mismatch: running process binary ({target_ident.build_id[:16]}...) "
                    f"does not match debug image ({dbg_ident.build_id[:16]}...)."
                )
                act = "실행 중인 대상 프로세스와 동일한 빌드에서 생성된 디버그 바이너리를 지정하세요." if is_ko else "Provide the exact matching debug image compiled from the same build."
                return {
                    "success": True,
                    "data": {
                        "valid": False,
                        "reason": "BUILD_ID_MISMATCH",
                        "message": msg,
                        "next_action": act,
                        "target_build_id": target_ident.build_id,
                        "debug_image_build_id": dbg_ident.build_id,
                    }
                }

        # 7. Check architecture and endianness compatibility
        if target_ident and target_ident.architecture and dbg_ident.architecture:
            if target_ident.architecture != dbg_ident.architecture:
                msg = f"아키텍처 불일치: 프로세스는 {target_ident.architecture}이지만 디버그 이미지는 {dbg_ident.architecture}입니다." if is_ko else f"Architecture mismatch: process is {target_ident.architecture} but debug image is {dbg_ident.architecture}."
                act = f"대상 프로세스 아키텍처({target_ident.architecture})에 맞는 바이너리를 제공하세요." if is_ko else f"Provide a binary matching target architecture ({target_ident.architecture})."
                return {"success": True, "data": {"valid": False, "reason": "ARCH_MISMATCH", "message": msg, "next_action": act}}

        rec_symbols = []
        try:
            from extractor.dwarf_indexer import DwarfIndexer
            rec_symbols = DwarfIndexer.get_index(dbg_path).search_symbols(limit=10, smart_rank=True)
        except Exception:
            rec_symbols = []

        return {
            "success": True,
            "data": {
                "valid": True,
                "reason": "VALID",
                "pid": pid,
                "is_remote": False,
                "target_host": "localhost",
                "executable": exe_path or (target_ident.path if target_ident else f"/proc/{pid}/exe"),
                "executable_path": exe_path or (target_ident.path if target_ident else f"/proc/{pid}/exe"),
                "target_build_id": target_ident.build_id if target_ident else None,
                "debug_image": dbg_path,
                "debug_image_path": dbg_path,
                "debug_build_id": dbg_ident.build_id,
                "debug_image_build_id": dbg_ident.build_id,
                "has_dwarf": dbg_ident.has_debug_info,
                "has_debug_info": dbg_ident.has_debug_info,
                "build_id_match": True,
                "architecture": dbg_ident.architecture,
                "arch": dbg_ident.architecture,
                "endianness": dbg_ident.endianness,
                "endian": dbg_ident.endianness,
                "memory_read_backend": selected_backend,
                "capture_backend": selected_backend,
                "backend": selected_backend,
                "capture_quality": "CONSISTENT" if selected_backend == "process_vm_readv" else "LOW_IMPACT",
                "recommended_symbols": rec_symbols,
                "message": "대상 프로세스 및 디버그 이미지가 검증되었습니다." if is_ko else "Target process and debug image verified successfully.",
                "next_action": "상태 캡처 및 분석을 진행할 수 있습니다." if is_ko else "Ready to capture and analyze runtime state.",
            }
        }

    def deploy_remote_collector_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Deploys or verifies the C99 dynamicstate-collector on a remote SSH target."""
        try:
            remote_host = (params.get("remote_host") or "").strip()
            if not remote_host:
                return {"success": False, "error": {"code": "INVALID_PARAM", "message": "remote_host is required"}}
            adapter = self.watch_manager._resolve_adapter(
                pid=1,
                remote_host=remote_host,
                ssh_user=(params.get("ssh_user") or "").strip() or None,
                ssh_port=int(params.get("ssh_port") or 22),
                ssh_key=(params.get("ssh_key") or "").strip() or None,
                ssh_proxy_jump=(params.get("ssh_proxy_jump") or "").strip() or None,
            )
            if not hasattr(adapter, "ensure_remote_collector"):
                return {"success": False, "error": {"code": "UNSUPPORTED_ADAPTER", "message": "Target adapter is not remote SSH"}}
            res = adapter.ensure_remote_collector(
                local_collector_bin=(params.get("local_collector_bin") or "").strip() or None,
                remote_dest=str(params.get("remote_dest") or "/tmp/dynamicstate-collector"),
            )
            return {"success": True, "data": res}
        except Exception as e:
            return {"success": False, "error": {"code": "DEPLOY_COLLECTOR_ERROR", "message": str(e)}}

    def find_target_processes(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Discovers running processes on local or remote target filtered by name or companion ELF Build ID."""
        try:
            process_name = (params.get("process_name") or params.get("query") or "").strip() or None
            companion_elf = (params.get("companion_elf") or params.get("debug_image") or "").strip() or None
            remote_host = (params.get("remote_host") or "").strip() or None
            ssh_user = (params.get("ssh_user") or "").strip() or None
            ssh_port = int(params.get("ssh_port") or 22)
            ssh_key = (params.get("ssh_key") or "").strip() or None
            ssh_proxy_jump = (params.get("ssh_proxy_jump") or "").strip() or None

            companion_bid = None
            if companion_elf and os.path.isfile(companion_elf):
                try:
                    from extractor.debug_image import inspect_elf
                    companion_bid = inspect_elf(companion_elf).build_id
                except Exception:
                    companion_bid = None

            adapter = self.watch_manager._resolve_adapter(
                pid=1,
                remote_host=remote_host,
                ssh_user=ssh_user,
                ssh_port=ssh_port,
                ssh_key=ssh_key,
                ssh_proxy_jump=ssh_proxy_jump,
            )
            procs = adapter.find_processes(
                process_name=process_name,
                companion_build_id=companion_bid,
                limit=int(params.get("limit") or 30),
            )
            return {
                "success": True,
                "data": {
                    "target_host": adapter.target_host(),
                    "is_remote": adapter.is_remote(),
                    "companion_build_id": companion_bid,
                    "processes": procs,
                }
            }
        except Exception as e:
            return {"success": False, "error": {"code": "FIND_PROCESSES_ERROR", "message": str(e)}}

    def search_dwarf_symbols_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Searches DWARF globals, statics, and composite types with smart ranking."""
        try:
            companion_elf = (params.get("companion_elf") or params.get("debug_image") or "").strip()
            if not companion_elf or not os.path.isfile(companion_elf):
                return {"success": False, "error": {"code": "DEBUG_IMAGE_NOT_FOUND", "message": f"Companion ELF not found: '{companion_elf}'"}}
            from extractor.dwarf_indexer import DwarfIndexer
            idx = DwarfIndexer.get_index(companion_elf)
            query = str(params.get("query") or "")
            category = str(params.get("category") or "all")
            limit = int(params.get("limit") or 50)
            results = idx.search_symbols(query=query, category=category, limit=limit, smart_rank=True)
            return {"success": True, "data": {"companion_elf": companion_elf, "total": len(results), "symbols": results}}
        except Exception as e:
            return {"success": False, "error": {"code": "SYMBOL_SEARCH_ERROR", "message": str(e)}}

    def evaluate_symbol_paths_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluates C/C++ symbol path expressions against a local or remote target."""
        try:
            pid = int(params.get("pid") or 0)
            if pid <= 0:
                return {"success": False, "error": {"code": "INVALID_PID", "message": "Positive target PID is required"}}
            companion_elf = (params.get("companion_elf") or params.get("debug_image") or "").strip()
            if not companion_elf or not os.path.isfile(companion_elf):
                return {"success": False, "error": {"code": "DEBUG_IMAGE_NOT_FOUND", "message": f"Companion ELF not found: '{companion_elf}'"}}
            exprs = params.get("expressions") or []
            if isinstance(exprs, str):
                exprs = [e.strip() for e in exprs.split(",") if e.strip()]
            data = self.watch_manager.evaluate_symbol_paths(
                pid=pid,
                companion_elf_path=companion_elf,
                expressions=exprs,
                remote_host=(params.get("remote_host") or "").strip() or None,
                ssh_user=(params.get("ssh_user") or "").strip() or None,
                ssh_port=int(params.get("ssh_port") or 22),
                ssh_key=(params.get("ssh_key") or "").strip() or None,
                ssh_proxy_jump=(params.get("ssh_proxy_jump") or "").strip() or None,
            )
            return {"success": True, "data": data}
        except Exception as e:
            return {"success": False, "error": {"code": "EVAL_PATHS_ERROR", "message": str(e)}}

    def save_golden_baseline_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Saves current live target state as a named Golden Baseline."""
        try:
            pid = int(params.get("pid") or 0)
            if pid <= 0:
                return {"success": False, "error": {"code": "INVALID_PID", "message": "Positive target PID is required"}}
            companion_elf = (params.get("companion_elf") or params.get("debug_image") or "").strip()
            if not companion_elf or not os.path.isfile(companion_elf):
                return {"success": False, "error": {"code": "DEBUG_IMAGE_NOT_FOUND", "message": f"Companion ELF not found: '{companion_elf}'"}}
            exprs = params.get("expressions")
            if isinstance(exprs, str):
                exprs = [e.strip() for e in exprs.split(",") if e.strip()]
            label = str(params.get("label") or "Golden Baseline").strip()
            rec = self.watch_manager.save_golden_baseline(
                pid=pid,
                companion_elf_path=companion_elf,
                label=label,
                expressions=exprs,
                remote_host=(params.get("remote_host") or "").strip() or None,
                ssh_user=(params.get("ssh_user") or "").strip() or None,
                ssh_port=int(params.get("ssh_port") or 22),
                ssh_key=(params.get("ssh_key") or "").strip() or None,
                ssh_proxy_jump=(params.get("ssh_proxy_jump") or "").strip() or None,
            )
            return {"success": True, "data": rec}
        except Exception as e:
            return {"success": False, "error": {"code": "GOLDEN_BASELINE_SAVE_ERROR", "message": str(e)}}

    def list_golden_baselines_api(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Lists all saved Golden Baselines."""
        try:
            p = params or {}
            bid = (p.get("binary_build_id") or "").strip() or None
            items = self.watch_manager.list_golden_baselines(binary_build_id=bid)
            return {"success": True, "data": {"total": len(items), "baselines": items}}
        except Exception as e:
            return {"success": False, "error": {"code": "GOLDEN_BASELINE_LIST_ERROR", "message": str(e)}}

    def compare_golden_baseline_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Compares current live process against a saved Golden Baseline."""
        try:
            baseline_id = (params.get("baseline_id") or "").strip()
            if not baseline_id:
                return {"success": False, "error": {"code": "INVALID_BASELINE_ID", "message": "baseline_id is required"}}
            pid = int(params.get("pid") or 0)
            if pid <= 0:
                return {"success": False, "error": {"code": "INVALID_PID", "message": "Positive target PID is required"}}
            companion_elf = (params.get("companion_elf") or params.get("debug_image") or "").strip() or None
            res = self.watch_manager.compare_with_golden_baseline(
                baseline_id=baseline_id,
                pid=pid,
                companion_elf_path=companion_elf,
                remote_host=(params.get("remote_host") or "").strip() or None,
                ssh_user=(params.get("ssh_user") or "").strip() or None,
                ssh_port=int(params.get("ssh_port") or 22),
                ssh_key=(params.get("ssh_key") or "").strip() or None,
                ssh_proxy_jump=(params.get("ssh_proxy_jump") or "").strip() or None,
            )
            return {"success": True, "data": res}
        except Exception as e:
            return {"success": False, "error": {"code": "GOLDEN_BASELINE_COMPARE_ERROR", "message": str(e)}}

    def run_diagnostic_recipe_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Executes a guided diagnostic recipe (instant_xray, before_after_diff, timeseries_watch)."""
        try:
            pid = int(params.get("pid") or 0)
            if pid <= 0:
                return {"success": False, "error": {"code": "INVALID_PID", "message": "Positive target PID is required"}}
            companion_elf = (params.get("companion_elf") or params.get("debug_image") or "").strip()
            if not companion_elf or not os.path.isfile(companion_elf):
                return {"success": False, "error": {"code": "DEBUG_IMAGE_NOT_FOUND", "message": f"Companion ELF not found: '{companion_elf}'"}}
            recipe = str(params.get("recipe") or "instant_xray")
            exprs = params.get("expressions")
            if isinstance(exprs, str):
                exprs = [e.strip() for e in exprs.split(",") if e.strip()]
            res = self.watch_manager.run_diagnostic_recipe(
                recipe=recipe,
                pid=pid,
                companion_elf_path=companion_elf,
                expressions=exprs,
                duration_ms=int(params.get("duration_ms") or 1000),
                interval_ms=int(params.get("interval_ms") or 200),
                remote_host=(params.get("remote_host") or "").strip() or None,
                ssh_user=(params.get("ssh_user") or "").strip() or None,
                ssh_port=int(params.get("ssh_port") or 22),
                ssh_key=(params.get("ssh_key") or "").strip() or None,
                ssh_proxy_jump=(params.get("ssh_proxy_jump") or "").strip() or None,
            )
            return {"success": True, "data": res}
        except Exception as e:
            return {"success": False, "error": {"code": "DIAGNOSTIC_RECIPE_ERROR", "message": str(e)}}

    def scan_memory_pool_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Scans an entire memory pool or buffer array and returns slot allocation status and map chart."""
        try:
            pid = int(params.get("pid") or 0)
            if pid <= 0:
                return {"success": False, "error": {"code": "INVALID_PID", "message": "Positive target PID is required"}}
            companion_elf = (params.get("companion_elf") or params.get("debug_image") or "").strip()
            if not companion_elf:
                return {"success": False, "error": {"code": "DEBUG_IMAGE_NOT_FOUND", "message": "Companion ELF path is required"}}
            base_expr = (params.get("base_expression") or params.get("expression") or "").strip()
            if not base_expr:
                return {"success": False, "error": {"code": "INVALID_EXPRESSION", "message": "base_expression is required"}}
            count = int(params["count"]) if params.get("count") else None
            status_field = (params.get("status_field") or "").strip() or None
            inc_fields = params.get("include_fields")
            if isinstance(inc_fields, str):
                inc_fields = [f.strip() for f in inc_fields.split(",") if f.strip()]
            res = self.watch_manager.scan_memory_pool_or_array(
                pid=pid,
                companion_elf_path=companion_elf,
                base_expression=base_expr,
                count=count,
                status_field=status_field,
                include_fields=inc_fields,
                remote_host=(params.get("remote_host") or "").strip() or None,
                ssh_user=(params.get("ssh_user") or "").strip() or None,
                ssh_port=int(params.get("ssh_port") or 22),
                ssh_key=(params.get("ssh_key") or "").strip() or None,
                ssh_proxy_jump=(params.get("ssh_proxy_jump") or "").strip() or None,
            )
            return {"success": True, "data": res}
        except Exception as e:
            return {"success": False, "error": {"code": "POOL_SCAN_ERROR", "message": str(e)}}

    def find_symbol_owners_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Finds threads or global worker contexts holding or referencing a specific symbol/slot."""
        try:
            pid = int(params.get("pid") or 0)
            if pid <= 0:
                return {"success": False, "error": {"code": "INVALID_PID", "message": "Positive target PID is required"}}
            companion_elf = (params.get("companion_elf") or params.get("debug_image") or "").strip()
            if not companion_elf:
                return {"success": False, "error": {"code": "DEBUG_IMAGE_NOT_FOUND", "message": "Companion ELF path is required"}}
            target_expr = (params.get("target_expression") or params.get("expression") or "").strip()
            if not target_expr:
                return {"success": False, "error": {"code": "INVALID_EXPRESSION", "message": "target_expression is required"}}
            res = self.watch_manager.find_symbol_owners_and_threads(
                pid=pid,
                companion_elf_path=companion_elf,
                target_expression=target_expr,
                stack_scan_bytes=int(params.get("stack_scan_bytes") or 65536),
                remote_host=(params.get("remote_host") or "").strip() or None,
                ssh_user=(params.get("ssh_user") or "").strip() or None,
                ssh_port=int(params.get("ssh_port") or 22),
                ssh_key=(params.get("ssh_key") or "").strip() or None,
                ssh_proxy_jump=(params.get("ssh_proxy_jump") or "").strip() or None,
            )
            return {"success": True, "data": res}
        except Exception as e:
            return {"success": False, "error": {"code": "FIND_OWNERS_ERROR", "message": str(e)}}

    def workspace_chat_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Natural-language conversational router for the Minimalist Trace Workspace UI.

        Translates user chat prompts (e.g. 'memory pool *gpMem의 할당 현황을 맵 차트로 그려주세요',
        'gpMem 9번 인덱스를 사용 중인 쓰레드를 찾아주세요') into zero-stop process inspections
        and returns both a conversational reply and structured visual trace cards.
        """
        try:
            msg = str(params.get("message") or params.get("prompt") or "").strip()
            if not msg:
                return {"success": False, "error": {"code": "EMPTY_MESSAGE", "message": "Chat message is required"}}

            pid = int(params.get("pid") or 0)
            companion_elf = str(params.get("companion_elf") or params.get("debug_image") or "").strip()
            remote_host = (params.get("remote_host") or "").strip() or None
            ssh_user = (params.get("ssh_user") or "").strip() or None
            ssh_port = int(params.get("ssh_port") or 22)
            ssh_key = (params.get("ssh_key") or "").strip() or None
            ssh_proxy_jump = (params.get("ssh_proxy_jump") or "").strip() or None

            if pid <= 0 or not companion_elf or not os.path.isfile(companion_elf) or self.watch_manager.get_active_target_context().get("pid") == pid:
                try:
                    ctx_auto = self.watch_manager.resolve_target_context(
                        pid=pid if pid > 0 else None,
                        companion_elf_path=companion_elf or None,
                        process_name=(params.get("process_name") or "").strip() or None,
                        remote_host=remote_host,
                        ssh_user=ssh_user,
                        ssh_port=ssh_port,
                        ssh_key=ssh_key,
                        ssh_proxy_jump=ssh_proxy_jump,
                    )
                    pid = ctx_auto["pid"]
                    companion_elf = ctx_auto["companion_elf_path"]
                except Exception:
                    pass

            if pid <= 0 or not companion_elf or not os.path.isfile(companion_elf):
                return {
                    "success": False,
                    "error": {
                        "code": "TARGET_NOT_CONFIGURED",
                        "message": f"Valid running PID ({pid}) and nostrip ELF ('{companion_elf}') are required",
                    },
                }

            msg_low = msg.lower()
            wants_dpdk = any(k in msg_low for k in ("dpdk", "lcore", "pmd", "isolation", "isolcpus", "격리 코어", "데디케이티드", "dedicated", "rte_ring", "스핀락", "spinlock", "hugepage"))
            wants_tls = any(k in msg_low for k in ("tls", "thread_local", "__thread", "스레드별", "쓰레드별", "스레드 로컬", "쓰레드 로컬", "tcb")) and not wants_dpdk
            wants_seqlock = any(k in msg_low for k in ("seqlock", "시퀀스락", "일관성", "원자성", "torn read", "동시성 읽기", "이중 읽기", "double read", "atomic"))
            wants_flight_recorder = any(k in msg_low for k in ("타임머신", "플라이트 레코더", "flight recorder", "방금 잠깐", "튀었", "간헐적", "스파이크", "글리치", "링버퍼"))
            wants_drift = any(k in msg_low for k in ("행동 편차", "편차", "평소랑", "드리프트", "drift", "baseline 대비", "이상해졌"))
            wants_hotspots = any(k in msg_low for k in ("핫스팟", "hotspot", "프로파일", "flame", "cpu 점유", "바쁜 루프", "어느 함수에서 시간을", "통계적 샘플링"))
            wants_fuzzy = any(k in msg_low for k in ("퍼지", "의미 매칭", "관련된 심볼 찾아", "알아서 심볼", "fuzzy"))
            wants_symptom = any(k in msg_low for k in ("왜 멈췄", "왜 안", "응답이 없", "버벅", "느려졌", "증상", "자율 조사", "종합 판단", "왜 이래", "무슨 문제"))
            wants_dep_graph = any(k in msg_low for k in ("인과 그래프", "종속성 그래프", "의존성 그래프", "dependency graph", "causal chain", "인과 사슬", "누가 누구를"))
            wants_source_corr = any(k in msg_low for k in ("소스 코드", "소스코드", "코드 줄", "인라인", "source", "코드와 변수"))
            wants_ipc_pipeline = any(k in msg_low for k in ("파이프라인", "pipeline", "프로듀서", "컨슈머", "producer", "consumer", "멀티 프로세스", "병목"))
            wants_heap_scan = any(k in msg_low for k in ("힙", "heap", "누수", "leak", "객체 스캔", "인스턴스"))
            wants_triage = any(k in msg_low for k in ("종합 진단", "원클릭 진단", "auto-triage", "triage", "트리아지", "전체 진단", "원인 분석"))
            wants_frame_locals = any(k in msg_low for k in ("지역 변수", "지역변수", "파라미터", "매개변수", "인자", "local", "frame var", "스택 변수")) and not wants_tls
            wants_condition = any(k in msg_low for k in ("조건", "순간", "until", "trigger", "트리거", "감시", "포착")) or bool(re.search(r"(==|!=|>=|<=)", msg))
            wants_linked = any(k in msg_low for k in ("연결 리스트", "리스트", "체인", "순회", "사이클", "cycle", "linked", "next"))
            wants_callstack = any(k in msg_low for k in ("콜스택", "callstack", "backtrace", "데드락", "deadlock", "뮤텍스", "mutex", "락", "lock", "블로킹", "어느 함수")) and not wants_seqlock
            wants_audit = any(k in msg_low for k in ("무결성", "감사", "오염", "audit", "corruption", "dangling", "전수 검사", "깨진"))
            wants_code_ptr = any(k in msg_low for k in ("함수 포인터", "콜백", "callback", "vtable", "vptr", "가상 함수"))
            wants_shm = any(k in msg_low for k in ("공유 메모리", "shm", "mmap", "캐스팅", "cast", "ipc"))
            wants_pool = any(k in msg_low for k in ("맵", "pool", "할당", "buffer", "버퍼", "슬롯 현황")) and not wants_condition and not wants_ipc_pipeline and not wants_heap_scan
            wants_owner = any(k in msg_low for k in ("쓰레드", "스레드", "thread", "누가", "사용 중인", "점유", "owner", "인덱스")) and not wants_callstack and not wants_condition and not wants_frame_locals and not wants_triage and not wants_ipc_pipeline and not wants_heap_scan and not wants_tls and not wants_dpdk
            wants_diff = any(k in msg_low for k in ("diff", "전후", "변화", "비교"))
            wants_blueprint = any(k in msg_low for k in ("블루프린트", "blueprint", "연결", "x-ray", "구조")) and not wants_linked

            trace_cards: List[Dict[str, Any]] = []
            reply_parts: List[str] = []

            bp_data = self.watch_manager.get_process_xray_blueprint(
                pid=pid,
                companion_elf_path=companion_elf,
                remote_host=remote_host,
                ssh_user=ssh_user,
                ssh_port=ssh_port,
                ssh_key=ssh_key,
                ssh_proxy_jump=ssh_proxy_jump,
            )
            pools_list = bp_data.get("categories", {}).get("memory_pools_and_buffers", [])
            default_pool_expr = pools_list[0]["recommended_pool_expression"] if pools_list else "*gpMem"
            default_pool_name = pools_list[0]["name"] if pools_list else "gpMem"

            if wants_blueprint and not wants_pool and not wants_owner:
                trace_cards.append({
                    "card_type": "XRAY_BLUEPRINT",
                    "title": f"PID {pid} X-Ray 블루프린트 & 활성 스레드",
                    "data": bp_data,
                })
                reply_parts.append(
                    f"PID {pid} 프로세스에 무정지(0.00ms)로 연결하여 활성 스레드 {bp_data.get('threads_count', 0)}개와 "
                    f"메모리 풀 {len(pools_list)}개를 포함한 DWARF 전역 심볼 구조를 워크스페이스에 추가했습니다."
                )

            if wants_pool:
                # Extract explicit pool expression or use discovered default pool
                m_expr = re.search(r"(\*[A-Za-z_][A-Za-z0-9_]*|[A-Za-z_][A-Za-z0-9_]*(?:->|\.)[A-Za-z_][A-Za-z0-9_]*)", msg)
                base_expr = m_expr.group(1) if m_expr else default_pool_expr
                pool_res = self.watch_manager.scan_memory_pool_or_array(
                    pid=pid,
                    companion_elf_path=companion_elf,
                    base_expression=base_expr,
                    remote_host=remote_host,
                    ssh_user=ssh_user,
                    ssh_port=ssh_port,
                    ssh_key=ssh_key,
                    ssh_proxy_jump=ssh_proxy_jump,
                )
                p_sum = pool_res["pool_summary"]
                trace_cards.append({
                    "card_type": "POOL_MAP",
                    "title": f"{pool_res['resolved_array_expression']} 메모리 풀 할당 맵 ({p_sum['allocated_count']}/{p_sum['total_slots']})",
                    "data": pool_res,
                })
                reply_parts.append(
                    f"{pool_res['resolved_array_expression']} 총 {p_sum['total_slots']}개 버퍼 중 "
                    f"{p_sum['allocated_count']}개({p_sum['utilization_pct']}%)가 할당(IN_USE)되어 있습니다 "
                    f"(인덱스: {p_sum['allocated_indices']})."
                )

            if wants_owner:
                m_idx_expr = re.search(r"([A-Za-z_][A-Za-z0-9_.\->]*\[\s*\d+\s*\])", msg)
                m_kor_idx = re.search(r"(?:([A-Za-z_][A-Za-z0-9_]*)\s*)?(\d+)\s*번", msg)
                if m_idx_expr:
                    target_expr = m_idx_expr.group(1)
                elif m_kor_idx:
                    sym_prefix = m_kor_idx.group(1) or default_pool_name
                    target_expr = f"{sym_prefix}[{m_kor_idx.group(2)}]"
                else:
                    target_expr = f"{default_pool_name}[0]"

                owner_res = self.watch_manager.find_symbol_owners_and_threads(
                    pid=pid,
                    companion_elf_path=companion_elf,
                    target_expression=target_expr,
                    remote_host=remote_host,
                    ssh_user=ssh_user,
                    ssh_port=ssh_port,
                    ssh_key=ssh_key,
                    ssh_proxy_jump=ssh_proxy_jump,
                )
                trace_cards.append({
                    "card_type": "THREAD_OWNER",
                    "title": f"{owner_res['target_expression']} 점유 스레드 역추적 결과",
                    "data": owner_res,
                })
                m_threads = owner_res.get("matched_threads", [])
                if m_threads:
                    t_str = ", ".join(f"TID {t['tid']} ({t['thread_name']})" for t in m_threads)
                    reply_parts.append(f"{owner_res['target_expression']} ({owner_res['target_runtime_address']})를 사용 중인 스레드는 {t_str} 입니다.")
                else:
                    reply_parts.append(f"{owner_res['target_expression']}를 현재 점유/참조 중인 스레드가 발견되지 않았습니다.")

            if wants_dpdk:
                dpdk_res = self.watch_manager.inspect_dpdk_lcores_and_rings(
                    pid=pid,
                    companion_elf_path=companion_elf,
                    sample_window_ms=int(params.get("sample_window_ms") or 40),
                    ring_expressions=params.get("ring_expressions"),
                    spinlock_expressions=params.get("spinlock_expressions"),
                    remote_host=remote_host,
                    ssh_user=ssh_user,
                    ssh_port=ssh_port,
                    ssh_key=ssh_key,
                    ssh_proxy_jump=ssh_proxy_jump,
                )
                trace_cards.append({
                    "card_type": "DPDK_LCORE_INSPECTOR",
                    "title": f"DPDK 격리 코어(lcore) & PMD 링 무정지 진단 ({dpdk_res['overall_dpdk_status']} · PMD {dpdk_res['dedicated_pmd_lcores_count']}개)",
                    "data": dpdk_res,
                })
                reply_parts.append(dpdk_res.get("llm_next_step_hint", "DPDK 격리 코어 및 PMD 링 분석을 완료했습니다."))

            if wants_tls:
                tls_res = self.watch_manager.inspect_thread_local_storage(
                    pid=pid,
                    companion_elf_path=companion_elf,
                    tid=int(params["tid"]) if params.get("tid") else None,
                    variable_names=params.get("variable_names"),
                    remote_host=remote_host,
                    ssh_user=ssh_user,
                    ssh_port=ssh_port,
                    ssh_key=ssh_key,
                    ssh_proxy_jump=ssh_proxy_jump,
                )
                trace_cards.append({
                    "card_type": "TLS_INSPECTOR",
                    "title": f"스레드별 TLS(thread_local) 변수 해독 ({tls_res['tls_variables_discovered']} vars · {tls_res['tcb_resolved_count']}/{tls_res['threads_count']} TCBs)",
                    "data": tls_res,
                })
                reply_parts.append(tls_res.get("llm_next_step_hint", "스레드별 TLS 변수 해독을 완료했습니다."))

            if wants_seqlock:
                seq_res = self.watch_manager.verify_concurrent_read_consistency(
                    pid=pid,
                    companion_elf_path=companion_elf,
                    expressions=params.get("expressions"),
                    retries=int(params.get("retries") or 3),
                    inter_read_delay_ms=int(params.get("inter_read_delay_ms") or 4),
                    remote_host=remote_host,
                    ssh_user=ssh_user,
                    ssh_port=ssh_port,
                    ssh_key=ssh_key,
                    ssh_proxy_jump=ssh_proxy_jump,
                )
                trace_cards.append({
                    "card_type": "CONCURRENCY_VERIFIER",
                    "title": f"동시성 이중 읽기(Seqlock) 일관성 검증 ({seq_res['overall_consistency_status']})",
                    "data": seq_res,
                })
                reply_parts.append(seq_res.get("llm_next_step_hint", "동시성 읽기 일관성 검증을 완료했습니다."))

            if wants_flight_recorder:
                fr_res = self.watch_manager.flight_recorder_time_machine(
                    pid=pid,
                    companion_elf_path=companion_elf,
                    frames_count=int(params.get("frames_count") or 8),
                    interval_ms=int(params.get("interval_ms") or 20),
                    remote_host=remote_host,
                    ssh_user=ssh_user,
                    ssh_port=ssh_port,
                    ssh_key=ssh_key,
                    ssh_proxy_jump=ssh_proxy_jump,
                )
                trace_cards.append({
                    "card_type": "FLIGHT_RECORDER",
                    "title": f"타임머신 플라이트 레코더 ({fr_res['frames_recorded']} frames · 글리치 {fr_res['transient_glitches_count']}건)",
                    "data": fr_res,
                })
                reply_parts.append(fr_res.get("llm_next_step_hint", "타임머신 플라이트 레코더 분석을 완료했습니다."))

            if wants_drift:
                dr_res = self.watch_manager.detect_behavioral_drift(
                    pid=pid,
                    companion_elf_path=companion_elf,
                    save_as_new_baseline=bool(params.get("save_as_new_baseline", False)),
                    remote_host=remote_host,
                    ssh_user=ssh_user,
                    ssh_port=ssh_port,
                    ssh_key=ssh_key,
                    ssh_proxy_jump=ssh_proxy_jump,
                )
                trace_cards.append({
                    "card_type": "BEHAVIORAL_DRIFT",
                    "title": f"행동 편차(Behavioral Drift) 경보 ({dr_res['drift_status']} · Score {dr_res['drift_score']}/100)",
                    "data": dr_res,
                })
                reply_parts.append(dr_res.get("llm_next_step_hint", "행동 편차 진단을 완료했습니다."))

            if wants_hotspots:
                hs_res = self.watch_manager.sample_statistical_hotspots(
                    pid=pid,
                    companion_elf_path=companion_elf,
                    samples_count=int(params.get("samples_count") or 6),
                    interval_ms=int(params.get("interval_ms") or 30),
                    remote_host=remote_host,
                    ssh_user=ssh_user,
                    ssh_port=ssh_port,
                    ssh_key=ssh_key,
                    ssh_proxy_jump=ssh_proxy_jump,
                )
                trace_cards.append({
                    "card_type": "STATISTICAL_HOTSPOTS",
                    "title": f"무정지 통계적 CPU & 콜스택 핫스팟 프로파일 ({hs_res['samples_taken']} samples · {hs_res['elapsed_ms']}ms)",
                    "data": hs_res,
                })
                reply_parts.append(hs_res.get("llm_next_step_hint", "무정지 통계적 핫스팟 프로파일링을 완료했습니다."))

            if wants_fuzzy:
                fz_res = self.watch_manager.resolve_fuzzy_symbol_intent(
                    pid=pid,
                    companion_elf_path=companion_elf,
                    natural_query=msg,
                    remote_host=remote_host,
                    ssh_user=ssh_user,
                    ssh_port=ssh_port,
                    ssh_key=ssh_key,
                    ssh_proxy_jump=ssh_proxy_jump,
                )
                trace_cards.append({
                    "card_type": "FUZZY_INTENT_RESOLVER",
                    "title": f"자연어 의도 기반 DWARF 심볼 자동 매칭 ({fz_res['matches_count']} matches)",
                    "data": fz_res,
                })
                reply_parts.append(fz_res.get("llm_next_step_hint", "자연어 의도 기반 심볼 매칭을 완료했습니다."))

            if wants_symptom:
                sym_res = self.watch_manager.investigate_symptom(
                    pid=pid,
                    companion_elf_path=companion_elf,
                    symptom_query=msg,
                    remote_host=remote_host,
                    ssh_user=ssh_user,
                    ssh_port=ssh_port,
                    ssh_key=ssh_key,
                    ssh_proxy_jump=ssh_proxy_jump,
                )
                trace_cards.append({
                    "card_type": "SYMPTOM_INVESTIGATION",
                    "title": f"증상 기반 자율 종합 조사 ({sym_res['classified_symptom']} · 확신도 {int(sym_res['confidence_score']*100)}%)",
                    "data": sym_res,
                })
                reply_parts.append(sym_res.get("llm_next_step_hint", "증상 기반 자율 종합 조사를 완료했습니다."))

            if wants_dep_graph:
                dg_res = self.watch_manager.build_dependency_graph(
                    pid=pid,
                    companion_elf_path=companion_elf,
                    remote_host=remote_host,
                    ssh_user=ssh_user,
                    ssh_port=ssh_port,
                    ssh_key=ssh_key,
                    ssh_proxy_jump=ssh_proxy_jump,
                )
                trace_cards.append({
                    "card_type": "DEPENDENCY_GRAPH",
                    "title": f"스레드·락·버퍼·IPC 인과 종속성 그래프 ({dg_res['nodes_count']} nodes · {len(dg_res['causal_chains'])} chains)",
                    "data": dg_res,
                })
                reply_parts.append(dg_res.get("llm_next_step_hint", "종속성 및 인과 그래프 합성을 완료했습니다."))

            if wants_source_corr:
                sc_res = self.watch_manager.correlate_source_and_state(
                    pid=pid,
                    companion_elf_path=companion_elf,
                    source_location=params.get("source_location"),
                    remote_host=remote_host,
                    ssh_user=ssh_user,
                    ssh_port=ssh_port,
                    ssh_key=ssh_key,
                    ssh_proxy_jump=ssh_proxy_jump,
                )
                trace_cards.append({
                    "card_type": "SOURCE_CORRELATION",
                    "title": f"소스 코드 & 실시간 메모리 변수 인라인 매핑 ({sc_res['snippets_count']} snippets)",
                    "data": sc_res,
                })
                reply_parts.append(sc_res.get("llm_next_step_hint", "소스 코드와 실시간 메모리 변수 매핑을 완료했습니다."))

            if wants_ipc_pipeline:
                ipc_res = self.watch_manager.trace_ipc_pipeline(
                    pid=pid,
                    companion_elf_path=companion_elf,
                    cast_type=params.get("cast_type"),
                    address=params.get("address"),
                    shm_name=params.get("shm_name"),
                    remote_host=remote_host,
                    ssh_user=ssh_user,
                    ssh_port=ssh_port,
                    ssh_key=ssh_key,
                    ssh_proxy_jump=ssh_proxy_jump,
                )
                trace_cards.append({
                    "card_type": "IPC_PIPELINE",
                    "title": f"멀티 프로세스 IPC 파이프라인 진단 ({ipc_res['pipeline_health']})",
                    "data": ipc_res,
                })
                reply_parts.append(ipc_res.get("llm_next_step_hint", "멀티 프로세스 IPC 파이프라인 진단을 완료했습니다."))

            if wants_heap_scan:
                hp_res = self.watch_manager.scan_heap_objects(
                    pid=pid,
                    companion_elf_path=companion_elf,
                    class_filter=params.get("class_filter"),
                    remote_host=remote_host,
                    ssh_user=ssh_user,
                    ssh_port=ssh_port,
                    ssh_key=ssh_key,
                    ssh_proxy_jump=ssh_proxy_jump,
                )
                trace_cards.append({
                    "card_type": "HEAP_SCANNER",
                    "title": f"힙(Heap) C++ 객체 & 누수 스캐너 (객체 {hp_res['total_objects_found']}개 · 누수 의심 {hp_res['leaked_candidates_count']}개)",
                    "data": hp_res,
                })
                reply_parts.append(hp_res.get("llm_next_step_hint", "힙 객체 및 누수 스캔을 완료했습니다."))

            if wants_triage:
                tr_res = self.watch_manager.auto_triage_incident(
                    pid=pid,
                    companion_elf_path=companion_elf,
                    remote_host=remote_host,
                    ssh_user=ssh_user,
                    ssh_port=ssh_port,
                    ssh_key=ssh_key,
                    ssh_proxy_jump=ssh_proxy_jump,
                )
                trace_cards.append({
                    "card_type": "AUTO_TRIAGE",
                    "title": f"원클릭 종합 진단 리포트 (Health {tr_res['health_score']}/100 · {tr_res['overall_status']})",
                    "data": tr_res,
                })
                reply_parts.append(tr_res.get("llm_next_step_hint", "원클릭 종합 진단을 완료했습니다."))

            if wants_frame_locals:
                fl_res = self.watch_manager.inspect_thread_locals_and_frame_vars(
                    pid=pid,
                    companion_elf_path=companion_elf,
                    tid=int(params["tid"]) if params.get("tid") else None,
                    remote_host=remote_host,
                    ssh_user=ssh_user,
                    ssh_port=ssh_port,
                    ssh_key=ssh_key,
                    ssh_proxy_jump=ssh_proxy_jump,
                )
                trace_cards.append({
                    "card_type": "FRAME_LOCALS",
                    "title": f"스레드 스택 프레임 인자 & 지역변수 해독 ({fl_res['threads_count']} threads)",
                    "data": fl_res,
                })
                reply_parts.append(fl_res.get("llm_next_step_hint", "스택 프레임 지역변수 해독을 완료했습니다."))

            if wants_condition:
                m_cond = re.search(r"([A-Za-z_*][A-Za-z0-9_.\->\[\]]*\s*(?:==|!=|>=|<=|>|<)\s*[A-Za-z0-9_xX.\-]+)", msg)
                cond_expr = m_cond.group(1) if m_cond else (params.get("condition_expression") or "ANY_CHANGE")
                cond_res = self.watch_manager.watch_until_condition(
                    pid=pid,
                    companion_elf_path=companion_elf,
                    condition_expression=cond_expr,
                    poll_interval_ms=int(params.get("poll_interval_ms") or 30),
                    timeout_ms=int(params.get("timeout_ms") or 800),
                    hold_duration_ms=int(params.get("hold_duration_ms") or 0),
                    remote_host=remote_host,
                    ssh_user=ssh_user,
                    ssh_port=ssh_port,
                    ssh_key=ssh_key,
                    ssh_proxy_jump=ssh_proxy_jump,
                )
                trace_cards.append({
                    "card_type": "CONDITION_TRIGGER",
                    "title": f"조건부 트리거 감시: {cond_expr} ({TRIGGERED if cond_res[triggered] else TIMEOUT})",
                    "data": cond_res,
                })
                reply_parts.append(cond_res.get("llm_next_step_hint", "조건부 감시를 완료했습니다."))

            if wants_linked:
                # Find list head symbol in message or DWARF variables
                m_head = re.search(r"([A-Za-z_][A-Za-z0-9_]*(?:list|head|queue|chain|node|root)[A-Za-z0-9_]*)", msg, re.IGNORECASE)
                head_expr = m_head.group(1) if m_head else (params.get("head_expression") or "g_task_list")
                list_res = self.watch_manager.traverse_linked_structure(
                    pid=pid,
                    companion_elf_path=companion_elf,
                    head_expression=head_expr,
                    next_field=params.get("next_field") or "next",
                    max_depth=int(params.get("max_depth") or 64),
                    remote_host=remote_host,
                    ssh_user=ssh_user,
                    ssh_port=ssh_port,
                    ssh_key=ssh_key,
                    ssh_proxy_jump=ssh_proxy_jump,
                )
                trace_cards.append({
                    "card_type": "LINKED_LIST_CHAIN",
                    "title": f"{head_expr} 연결 구조 체인 순회 ({list_res['nodes_count']} nodes · {list_res['termination_reason']})",
                    "data": list_res,
                })
                reply_parts.append(list_res.get("llm_next_step_hint", "연결 구조 순회를 완료했습니다."))

            if wants_callstack:
                cs_res = self.watch_manager.inspect_thread_callstacks_and_locks(
                    pid=pid,
                    companion_elf_path=companion_elf,
                    tid=int(params["tid"]) if params.get("tid") else None,
                    remote_host=remote_host,
                    ssh_user=ssh_user,
                    ssh_port=ssh_port,
                    ssh_key=ssh_key,
                    ssh_proxy_jump=ssh_proxy_jump,
                )
                trace_cards.append({
                    "card_type": "CALLSTACK_AND_LOCKS",
                    "title": f"무정지 스레드 콜스택 & 뮤텍스/데드락 분석 ({cs_res['threads_inspected']} threads)",
                    "data": cs_res,
                })
                reply_parts.append(cs_res.get("llm_next_step_hint", "스레드 콜스택 및 뮤텍스 분석을 완료했습니다."))

            if wants_audit:
                audit_res = self.watch_manager.audit_memory_integrity(
                    pid=pid,
                    companion_elf_path=companion_elf,
                    remote_host=remote_host,
                    ssh_user=ssh_user,
                    ssh_port=ssh_port,
                    ssh_key=ssh_key,
                    ssh_proxy_jump=ssh_proxy_jump,
                )
                trace_cards.append({
                    "card_type": "MEMORY_AUDIT",
                    "title": f"메모리 무결성 & 포인터 건강 감사 ({audit_res['health_status']} · 이상 {audit_res['anomalies_count']}건)",
                    "data": audit_res,
                })
                reply_parts.append(audit_res.get("llm_next_step_hint", "메모리 무결성 감사를 완료했습니다."))

            if wants_code_ptr:
                tokens = re.findall(r"(\*?[A-Za-z_][A-Za-z0-9_.\->\[\]]*)", msg)
                cands = [t for t in tokens if any(k in t.lower() for k in ("g_", "cb", "handler", "ops", "vptr", "poly", "obj", "session"))]
                cp_res = self.watch_manager.resolve_code_pointers(
                    pid=pid,
                    companion_elf_path=companion_elf,
                    expressions=cands or [default_pool_expr],
                    remote_host=remote_host,
                    ssh_user=ssh_user,
                    ssh_port=ssh_port,
                    ssh_key=ssh_key,
                    ssh_proxy_jump=ssh_proxy_jump,
                )
                trace_cards.append({
                    "card_type": "CODE_POINTERS",
                    "title": f"함수 포인터 & C++ vtable 심볼 역해석",
                    "data": cp_res,
                })
                reply_parts.append("함수 포인터 및 가상 함수 테이블(vtable) 심볼 매핑을 완료했습니다.")

            if wants_shm:
                shm_res = self.watch_manager.inspect_shared_memory_ipc(
                    pid=pid,
                    companion_elf_path=companion_elf,
                    cast_type=params.get("cast_type"),
                    address=params.get("address"),
                    shm_name=params.get("shm_name"),
                    remote_host=remote_host,
                    ssh_user=ssh_user,
                    ssh_port=ssh_port,
                    ssh_key=ssh_key,
                    ssh_proxy_jump=ssh_proxy_jump,
                )
                trace_cards.append({
                    "card_type": "SHARED_MEMORY_IPC",
                    "title": f"공유 메모리(SHM/IPC) & 타입 오버레이 분석 ({shm_res['shared_mappings_count']} mappings)",
                    "data": shm_res,
                })
                reply_parts.append(shm_res.get("llm_next_step_hint", "공유 메모리 및 IPC 피어 프로세스 탐색을 완료했습니다."))

            if wants_diff and not trace_cards:
                diff_res = self.watch_manager.capture_and_diff_expressions(
                    pid=pid,
                    companion_elf_path=companion_elf,
                    wait_ms=int(params.get("wait_ms") or 500),
                    remote_host=remote_host,
                    ssh_user=ssh_user,
                    ssh_port=ssh_port,
                    ssh_key=ssh_key,
                    ssh_proxy_jump=ssh_proxy_jump,
                )
                trace_cards.append({
                    "card_type": "SYMBOL_EVAL",
                    "title": f"{diff_res['wait_ms']}ms 전후 상태 변화(Diff)",
                    "data": diff_res,
                })
                reply_parts.append(
                    f"{diff_res['wait_ms']}ms 구간 동안 {diff_res['summary']['changed_count']}개 필드가 변경되었고 "
                    f"{diff_res['summary']['unchanged_count']}개 필드가 유지되었습니다."
                )

            if not trace_cards:
                # Default fallback: evaluate expression if found in message, otherwise return X-Ray Blueprint
                tokens = re.findall(r"(\*?[A-Za-z_][A-Za-z0-9_.\->\[\]]*)", msg)
                stopwords = {"memory", "pool", "buffer", "thread", "pid", "the", "and", "for"}
                cand_exprs = [t for t in tokens if t.lower() not in stopwords and (t.startswith("*") or "->" in t or "." in t or "[" in t or t.startswith("g"))]
                if cand_exprs:
                    ev_res = self.watch_manager.evaluate_symbol_paths(
                        pid=pid,
                        companion_elf_path=companion_elf,
                        expressions=cand_exprs[:5],
                        remote_host=remote_host,
                        ssh_user=ssh_user,
                        ssh_port=ssh_port,
                        ssh_key=ssh_key,
                        ssh_proxy_jump=ssh_proxy_jump,
                    )
                    trace_cards.append({
                        "card_type": "SYMBOL_EVAL",
                        "title": f"심볼 평가: {', '.join(cand_exprs[:3])}",
                        "data": ev_res,
                    })
                    reply_parts.append(f"요청하신 심볼({', '.join(cand_exprs[:3])})을 무정지(0.00ms)로 해독하여 워크스페이스에 추가했습니다.")
                else:
                    trace_cards.append({
                        "card_type": "XRAY_BLUEPRINT",
                        "title": f"PID {pid} X-Ray 블루프린트",
                        "data": bp_data,
                    })
                    reply_parts.append(f"PID {pid} 프로세스의 X-Ray 블루프린트를 워크스페이스에 추가했습니다.")

            from extractor.debug_image import inspect_elf
            elf_ident = inspect_elf(companion_elf)
            return {
                "success": True,
                "data": {
                    "title": "프로세스 메모리 트레이스 완료 (0.00ms 무정지)",
                    "reply_markdown": " ".join(reply_parts),
                    "trace_cards": trace_cards,
                    "telemetry": {
                        "pid": pid,
                        "build_id": elf_ident.build_id,
                        "load_bias": bp_data.get("load_bias", "0x0"),
                        "threads_count": bp_data.get("threads_count", 0),
                    },
                },
            }
        except Exception as e:
            return {"success": False, "error": {"code": "WORKSPACE_CHAT_ERROR", "message": str(e)}}

    def get_xray_blueprint_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Returns categorized DWARF X-Ray blueprint for a target process."""
        try:
            pid = int(params.get("pid") or 0)
            if pid <= 0:
                return {"success": False, "error": {"code": "INVALID_PID", "message": "Positive target PID is required"}}
            companion_elf = (params.get("companion_elf") or params.get("debug_image") or "").strip()
            if not companion_elf:
                return {"success": False, "error": {"code": "DEBUG_IMAGE_NOT_FOUND", "message": "Companion ELF path is required"}}
            res = self.watch_manager.get_process_xray_blueprint(
                pid=pid,
                companion_elf_path=companion_elf,
                remote_host=(params.get("remote_host") or "").strip() or None,
                ssh_user=(params.get("ssh_user") or "").strip() or None,
                ssh_port=int(params.get("ssh_port") or 22),
                ssh_key=(params.get("ssh_key") or "").strip() or None,
                ssh_proxy_jump=(params.get("ssh_proxy_jump") or "").strip() or None,
            )
            return {"success": True, "data": res}
        except Exception as e:
            return {"success": False, "error": {"code": "XRAY_BLUEPRINT_ERROR", "message": str(e)}}

    def watch_until_condition_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Polls target expressions until a condition triggers or times out (0.00ms stop)."""
        try:
            pid = int(params.get("pid") or 0)
            companion_elf = (params.get("companion_elf") or params.get("debug_image") or "").strip()
            cond_expr = (params.get("condition_expression") or params.get("condition") or "ANY_CHANGE").strip()
            res = self.watch_manager.watch_until_condition(
                pid=pid,
                companion_elf_path=companion_elf,
                condition_expression=cond_expr,
                watch_expressions=params.get("watch_expressions"),
                poll_interval_ms=int(params.get("poll_interval_ms") or 40),
                timeout_ms=int(params.get("timeout_ms") or 2000),
                hold_duration_ms=int(params.get("hold_duration_ms") or 0),
                find_owner_on_hit=params.get("find_owner_on_hit"),
                remote_host=(params.get("remote_host") or "").strip() or None,
                ssh_user=(params.get("ssh_user") or "").strip() or None,
                ssh_port=int(params.get("ssh_port") or 22),
                ssh_key=(params.get("ssh_key") or "").strip() or None,
                ssh_proxy_jump=(params.get("ssh_proxy_jump") or "").strip() or None,
            )
            return {"success": True, "data": res}
        except Exception as e:
            return {"success": False, "error": {"code": "WATCH_CONDITION_ERROR", "message": str(e)}}

    def traverse_linked_structure_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Traverses a linked list or pointer chain in 0.00ms zero-stop mode."""
        try:
            pid = int(params.get("pid") or 0)
            companion_elf = (params.get("companion_elf") or params.get("debug_image") or "").strip()
            head_expr = (params.get("head_expression") or "").strip()
            res = self.watch_manager.traverse_linked_structure(
                pid=pid,
                companion_elf_path=companion_elf,
                head_expression=head_expr,
                next_field=(params.get("next_field") or "next").strip(),
                max_depth=int(params.get("max_depth") or 64),
                include_fields=params.get("include_fields"),
                remote_host=(params.get("remote_host") or "").strip() or None,
                ssh_user=(params.get("ssh_user") or "").strip() or None,
                ssh_port=int(params.get("ssh_port") or 22),
                ssh_key=(params.get("ssh_key") or "").strip() or None,
                ssh_proxy_jump=(params.get("ssh_proxy_jump") or "").strip() or None,
            )
            return {"success": True, "data": res}
        except Exception as e:
            return {"success": False, "error": {"code": "TRAVERSE_LIST_ERROR", "message": str(e)}}

    def inspect_thread_callstacks_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Unwinds thread callstacks and decodes mutex owners / deadlock cycles in 0.00ms zero-stop mode."""
        try:
            pid = int(params.get("pid") or 0)
            companion_elf = (params.get("companion_elf") or params.get("debug_image") or "").strip()
            res = self.watch_manager.inspect_thread_callstacks_and_locks(
                pid=pid,
                companion_elf_path=companion_elf,
                tid=int(params["tid"]) if params.get("tid") else None,
                lock_expressions=params.get("lock_expressions"),
                max_frames=int(params.get("max_frames") or 12),
                remote_host=(params.get("remote_host") or "").strip() or None,
                ssh_user=(params.get("ssh_user") or "").strip() or None,
                ssh_port=int(params.get("ssh_port") or 22),
                ssh_key=(params.get("ssh_key") or "").strip() or None,
                ssh_proxy_jump=(params.get("ssh_proxy_jump") or "").strip() or None,
            )
            return {"success": True, "data": res}
        except Exception as e:
            return {"success": False, "error": {"code": "CALLSTACK_INSPECT_ERROR", "message": str(e)}}

    def audit_memory_integrity_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Audits DWARF symbols and memory pools for dangling pointers, corrupted bools/enums, and counter drift."""
        try:
            pid = int(params.get("pid") or 0)
            companion_elf = (params.get("companion_elf") or params.get("debug_image") or "").strip()
            res = self.watch_manager.audit_memory_integrity(
                pid=pid,
                companion_elf_path=companion_elf,
                target_expressions=params.get("target_expressions"),
                remote_host=(params.get("remote_host") or "").strip() or None,
                ssh_user=(params.get("ssh_user") or "").strip() or None,
                ssh_port=int(params.get("ssh_port") or 22),
                ssh_key=(params.get("ssh_key") or "").strip() or None,
                ssh_proxy_jump=(params.get("ssh_proxy_jump") or "").strip() or None,
            )
            return {"success": True, "data": res}
        except Exception as e:
            return {"success": False, "error": {"code": "MEMORY_AUDIT_ERROR", "message": str(e)}}

    def resolve_code_pointers_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Resolves function pointers and C++ vtable slots to function names and file:line."""
        try:
            pid = int(params.get("pid") or 0)
            companion_elf = (params.get("companion_elf") or params.get("debug_image") or "").strip()
            exprs = params.get("expressions") or []
            if isinstance(exprs, str):
                exprs = [e.strip() for e in exprs.split(",") if e.strip()]
            res = self.watch_manager.resolve_code_pointers(
                pid=pid,
                companion_elf_path=companion_elf,
                expressions=exprs,
                vtable_slots=int(params.get("vtable_slots") or 6),
                remote_host=(params.get("remote_host") or "").strip() or None,
                ssh_user=(params.get("ssh_user") or "").strip() or None,
                ssh_port=int(params.get("ssh_port") or 22),
                ssh_key=(params.get("ssh_key") or "").strip() or None,
                ssh_proxy_jump=(params.get("ssh_proxy_jump") or "").strip() or None,
            )
            return {"success": True, "data": res}
        except Exception as e:
            return {"success": False, "error": {"code": "RESOLVE_CODE_PTR_ERROR", "message": str(e)}}

    def inspect_shared_memory_ipc_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Inspects POSIX shm / shared mmap regions with DWARF type overlay casting and peer PID discovery."""
        try:
            pid = int(params.get("pid") or 0)
            companion_elf = (params.get("companion_elf") or params.get("debug_image") or "").strip()
            res = self.watch_manager.inspect_shared_memory_ipc(
                pid=pid,
                companion_elf_path=companion_elf,
                cast_type=params.get("cast_type"),
                address=params.get("address"),
                shm_name=params.get("shm_name"),
                discover_peer_processes=bool(params.get("discover_peer_processes", True)),
                remote_host=(params.get("remote_host") or "").strip() or None,
                ssh_user=(params.get("ssh_user") or "").strip() or None,
                ssh_port=int(params.get("ssh_port") or 22),
                ssh_key=(params.get("ssh_key") or "").strip() or None,
                ssh_proxy_jump=(params.get("ssh_proxy_jump") or "").strip() or None,
            )
            return {"success": True, "data": res}
        except Exception as e:
            return {"success": False, "error": {"code": "INSPECT_SHM_ERROR", "message": str(e)}}

    def inspect_thread_locals_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Decodes function parameters and local variables across active thread stack frames (0.00ms stop)."""
        try:
            pid = int(params.get("pid") or 0)
            companion_elf = (params.get("companion_elf") or params.get("debug_image") or "").strip()
            res = self.watch_manager.inspect_thread_locals_and_frame_vars(
                pid=pid,
                companion_elf_path=companion_elf,
                tid=int(params["tid"]) if params.get("tid") else None,
                max_frames=int(params.get("max_frames") or 8),
                remote_host=(params.get("remote_host") or "").strip() or None,
                ssh_user=(params.get("ssh_user") or "").strip() or None,
                ssh_port=int(params.get("ssh_port") or 22),
                ssh_key=(params.get("ssh_key") or "").strip() or None,
                ssh_proxy_jump=(params.get("ssh_proxy_jump") or "").strip() or None,
            )
            return {"success": True, "data": res}
        except Exception as e:
            return {"success": False, "error": {"code": "FRAME_LOCALS_ERROR", "message": str(e)}}

    def auto_triage_incident_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Runs 1-call composite zero-stop incident auto-triage across memory, locks, pools, and lists."""
        try:
            pid = int(params.get("pid") or 0)
            companion_elf = (params.get("companion_elf") or params.get("debug_image") or "").strip()
            res = self.watch_manager.auto_triage_incident(
                pid=pid,
                companion_elf_path=companion_elf,
                remote_host=(params.get("remote_host") or "").strip() or None,
                ssh_user=(params.get("ssh_user") or "").strip() or None,
                ssh_port=int(params.get("ssh_port") or 22),
                ssh_key=(params.get("ssh_key") or "").strip() or None,
                ssh_proxy_jump=(params.get("ssh_proxy_jump") or "").strip() or None,
            )
            return {"success": True, "data": res}
        except Exception as e:
            return {"success": False, "error": {"code": "AUTO_TRIAGE_ERROR", "message": str(e)}}

    def trace_ipc_pipeline_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Analyzes cross-process shared memory & IPC pipeline lag/bottlenecks (0.00ms stop)."""
        try:
            pid = int(params.get("pid") or 0)
            companion_elf = (params.get("companion_elf") or params.get("debug_image") or "").strip()
            res = self.watch_manager.trace_ipc_pipeline(
                pid=pid,
                companion_elf_path=companion_elf,
                cast_type=params.get("cast_type"),
                address=params.get("address"),
                shm_name=params.get("shm_name"),
                remote_host=(params.get("remote_host") or "").strip() or None,
                ssh_user=(params.get("ssh_user") or "").strip() or None,
                ssh_port=int(params.get("ssh_port") or 22),
                ssh_key=(params.get("ssh_key") or "").strip() or None,
                ssh_proxy_jump=(params.get("ssh_proxy_jump") or "").strip() or None,
            )
            return {"success": True, "data": res}
        except Exception as e:
            return {"success": False, "error": {"code": "IPC_PIPELINE_ERROR", "message": str(e)}}

    def scan_heap_objects_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Scans `[heap]` and `.data` for C++ polymorphic objects via `_vptr` and detects leaked instances."""
        try:
            pid = int(params.get("pid") or 0)
            companion_elf = (params.get("companion_elf") or params.get("debug_image") or "").strip()
            res = self.watch_manager.scan_heap_objects(
                pid=pid,
                companion_elf_path=companion_elf,
                class_filter=params.get("class_filter"),
                max_scan_bytes=int(params.get("max_scan_bytes") or 524288),
                max_objects=int(params.get("max_objects") or 64),
                remote_host=(params.get("remote_host") or "").strip() or None,
                ssh_user=(params.get("ssh_user") or "").strip() or None,
                ssh_port=int(params.get("ssh_port") or 22),
                ssh_key=(params.get("ssh_key") or "").strip() or None,
                ssh_proxy_jump=(params.get("ssh_proxy_jump") or "").strip() or None,
            )
            return {"success": True, "data": res}
        except Exception as e:
            return {"success": False, "error": {"code": "SCAN_HEAP_ERROR", "message": str(e)}}

    def build_dependency_graph_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Synthesizes directed cross-entity dependency graph and causal chains (0.00ms stop)."""
        try:
            pid = int(params.get("pid") or 0)
            companion_elf = (params.get("companion_elf") or params.get("debug_image") or "").strip()
            res = self.watch_manager.build_dependency_graph(
                pid=pid,
                companion_elf_path=companion_elf,
                remote_host=(params.get("remote_host") or "").strip() or None,
                ssh_user=(params.get("ssh_user") or "").strip() or None,
                ssh_port=int(params.get("ssh_port") or 22),
                ssh_key=(params.get("ssh_key") or "").strip() or None,
                ssh_proxy_jump=(params.get("ssh_proxy_jump") or "").strip() or None,
            )
            return {"success": True, "data": res}
        except Exception as e:
            return {"success": False, "error": {"code": "DEPENDENCY_GRAPH_ERROR", "message": str(e)}}

    def correlate_source_and_state_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Correlates DWARF source locations with C/C++ source code and inline live variables."""
        try:
            pid = int(params.get("pid") or 0)
            companion_elf = (params.get("companion_elf") or params.get("debug_image") or "").strip()
            res = self.watch_manager.correlate_source_and_state(
                pid=pid,
                companion_elf_path=companion_elf,
                source_location=params.get("source_location"),
                tid=int(params["tid"]) if params.get("tid") else None,
                context_lines=int(params.get("context_lines") or 8),
                source_search_dirs=params.get("source_search_dirs"),
                remote_host=(params.get("remote_host") or "").strip() or None,
                ssh_user=(params.get("ssh_user") or "").strip() or None,
                ssh_port=int(params.get("ssh_port") or 22),
                ssh_key=(params.get("ssh_key") or "").strip() or None,
                ssh_proxy_jump=(params.get("ssh_proxy_jump") or "").strip() or None,
            )
            return {"success": True, "data": res}
        except Exception as e:
            return {"success": False, "error": {"code": "SOURCE_CORRELATE_ERROR", "message": str(e)}}

    def investigate_symptom_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Autonomous symptom-driven root-cause investigator (0.00ms stop)."""
        try:
            pid = int(params.get("pid") or 0)
            companion_elf = (params.get("companion_elf") or params.get("debug_image") or "").strip()
            symptom_query = str(params.get("symptom_query") or params.get("query") or params.get("message") or "왜 멈췄지?").strip()
            res = self.watch_manager.investigate_symptom(
                pid=pid,
                companion_elf_path=companion_elf,
                symptom_query=symptom_query,
                remote_host=(params.get("remote_host") or "").strip() or None,
                ssh_user=(params.get("ssh_user") or "").strip() or None,
                ssh_port=int(params.get("ssh_port") or 22),
                ssh_key=(params.get("ssh_key") or "").strip() or None,
                ssh_proxy_jump=(params.get("ssh_proxy_jump") or "").strip() or None,
            )
            return {"success": True, "data": res}
        except Exception as e:
            return {"success": False, "error": {"code": "INVESTIGATE_SYMPTOM_ERROR", "message": str(e)}}

    def sample_statistical_hotspots_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Samples statistical CPU & callstack hotspots with 0.00ms stop time."""
        try:
            pid = int(params.get("pid") or 0)
            companion_elf = (params.get("companion_elf") or params.get("debug_image") or "").strip()
            res = self.watch_manager.sample_statistical_hotspots(
                pid=pid,
                companion_elf_path=companion_elf,
                samples_count=int(params.get("samples_count") or 6),
                interval_ms=int(params.get("interval_ms") or 35),
                remote_host=(params.get("remote_host") or "").strip() or None,
                ssh_user=(params.get("ssh_user") or "").strip() or None,
                ssh_port=int(params.get("ssh_port") or 22),
                ssh_key=(params.get("ssh_key") or "").strip() or None,
                ssh_proxy_jump=(params.get("ssh_proxy_jump") or "").strip() or None,
            )
            return {"success": True, "data": res}
        except Exception as e:
            return {"success": False, "error": {"code": "HOTSPOTS_ERROR", "message": str(e)}}

    def resolve_fuzzy_intent_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Resolves vague natural-language user intent to concrete DWARF symbols and live values."""
        try:
            pid = int(params.get("pid") or 0)
            companion_elf = (params.get("companion_elf") or params.get("debug_image") or "").strip()
            natural_query = str(params.get("natural_query") or params.get("query") or params.get("message") or "").strip()
            res = self.watch_manager.resolve_fuzzy_symbol_intent(
                pid=pid,
                companion_elf_path=companion_elf,
                natural_query=natural_query,
                limit=int(params.get("limit") or 5),
                remote_host=(params.get("remote_host") or "").strip() or None,
                ssh_user=(params.get("ssh_user") or "").strip() or None,
                ssh_port=int(params.get("ssh_port") or 22),
                ssh_key=(params.get("ssh_key") or "").strip() or None,
                ssh_proxy_jump=(params.get("ssh_proxy_jump") or "").strip() or None,
            )
            return {"success": True, "data": res}
        except Exception as e:
            return {"success": False, "error": {"code": "FUZZY_INTENT_ERROR", "message": str(e)}}

    def flight_recorder_time_machine_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Captures Flight Recorder Time-Machine micro-frames and detects transient glitches (0.00ms stop)."""
        try:
            pid = int(params.get("pid") or 0)
            companion_elf = (params.get("companion_elf") or params.get("debug_image") or "").strip()
            res = self.watch_manager.flight_recorder_time_machine(
                pid=pid,
                companion_elf_path=companion_elf,
                frames_count=int(params.get("frames_count") or 8),
                interval_ms=int(params.get("interval_ms") or 25),
                watch_expressions=params.get("watch_expressions"),
                remote_host=(params.get("remote_host") or "").strip() or None,
                ssh_user=(params.get("ssh_user") or "").strip() or None,
                ssh_port=int(params.get("ssh_port") or 22),
                ssh_key=(params.get("ssh_key") or "").strip() or None,
                ssh_proxy_jump=(params.get("ssh_proxy_jump") or "").strip() or None,
            )
            return {"success": True, "data": res}
        except Exception as e:
            return {"success": False, "error": {"code": "FLIGHT_RECORDER_ERROR", "message": str(e)}}

    def detect_behavioral_drift_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Detects multi-dimensional behavioral drift against a baseline profile (0.00ms stop)."""
        try:
            pid = int(params.get("pid") or 0)
            companion_elf = (params.get("companion_elf") or params.get("debug_image") or "").strip()
            res = self.watch_manager.detect_behavioral_drift(
                pid=pid,
                companion_elf_path=companion_elf,
                baseline_id=params.get("baseline_id"),
                save_as_new_baseline=bool(params.get("save_as_new_baseline", False)),
                remote_host=(params.get("remote_host") or "").strip() or None,
                ssh_user=(params.get("ssh_user") or "").strip() or None,
                ssh_port=int(params.get("ssh_port") or 22),
                ssh_key=(params.get("ssh_key") or "").strip() or None,
                ssh_proxy_jump=(params.get("ssh_proxy_jump") or "").strip() or None,
            )
            return {"success": True, "data": res}
        except Exception as e:
            return {"success": False, "error": {"code": "BEHAVIORAL_DRIFT_ERROR", "message": str(e)}}

    def inspect_thread_local_storage_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Decodes per-thread TLS (__thread / thread_local) variables across all active threads (0.00ms stop)."""
        try:
            pid = int(params.get("pid") or 0)
            companion_elf = (params.get("companion_elf") or params.get("debug_image") or "").strip()
            var_names = params.get("variable_names")
            if isinstance(var_names, str):
                var_names = [v.strip() for v in var_names.split(",") if v.strip()]
            res = self.watch_manager.inspect_thread_local_storage(
                pid=pid,
                companion_elf_path=companion_elf,
                tid=int(params["tid"]) if params.get("tid") else None,
                variable_names=var_names,
                remote_host=(params.get("remote_host") or "").strip() or None,
                ssh_user=(params.get("ssh_user") or "").strip() or None,
                ssh_port=int(params.get("ssh_port") or 22),
                ssh_key=(params.get("ssh_key") or "").strip() or None,
                ssh_proxy_jump=(params.get("ssh_proxy_jump") or "").strip() or None,
            )
            return {"success": True, "data": res}
        except Exception as e:
            return {"success": False, "error": {"code": "TLS_INSPECT_ERROR", "message": str(e)}}

    def verify_concurrent_read_consistency_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Verifies concurrent read consistency using optimistic Seqlock double-reads (0.00ms stop)."""
        try:
            pid = int(params.get("pid") or 0)
            companion_elf = (params.get("companion_elf") or params.get("debug_image") or "").strip()
            exprs = params.get("expressions")
            if isinstance(exprs, str):
                exprs = [e.strip() for e in exprs.split(",") if e.strip()]
            res = self.watch_manager.verify_concurrent_read_consistency(
                pid=pid,
                companion_elf_path=companion_elf,
                expressions=exprs,
                retries=int(params.get("retries") or 3),
                inter_read_delay_ms=int(params.get("inter_read_delay_ms") or 4),
                remote_host=(params.get("remote_host") or "").strip() or None,
                ssh_user=(params.get("ssh_user") or "").strip() or None,
                ssh_port=int(params.get("ssh_port") or 22),
                ssh_key=(params.get("ssh_key") or "").strip() or None,
                ssh_proxy_jump=(params.get("ssh_proxy_jump") or "").strip() or None,
            )
            return {"success": True, "data": res}
        except Exception as e:
            return {"success": False, "error": {"code": "VERIFY_CONSISTENCY_ERROR", "message": str(e)}}

    def inspect_dpdk_lcores_and_rings_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Inspects DPDK isolated-core dedicated lcores, PMD poll loops, lockless rings, and spinlocks (0.00ms stop)."""
        try:
            pid = int(params.get("pid") or 0)
            companion_elf = (params.get("companion_elf") or params.get("debug_image") or "").strip()
            r_exprs = params.get("ring_expressions")
            if isinstance(r_exprs, str):
                r_exprs = [x.strip() for x in r_exprs.split(",") if x.strip()]
            s_exprs = params.get("spinlock_expressions")
            if isinstance(s_exprs, str):
                s_exprs = [x.strip() for x in s_exprs.split(",") if x.strip()]
            res = self.watch_manager.inspect_dpdk_lcores_and_rings(
                pid=pid,
                companion_elf_path=companion_elf,
                sample_window_ms=int(params.get("sample_window_ms") or 40),
                ring_expressions=r_exprs,
                spinlock_expressions=s_exprs,
                remote_host=(params.get("remote_host") or "").strip() or None,
                ssh_user=(params.get("ssh_user") or "").strip() or None,
                ssh_port=int(params.get("ssh_port") or 22),
                ssh_key=(params.get("ssh_key") or "").strip() or None,
                ssh_proxy_jump=(params.get("ssh_proxy_jump") or "").strip() or None,
            )
            return {"success": True, "data": res}
        except Exception as e:
            return {"success": False, "error": {"code": "DPDK_INSPECT_ERROR", "message": str(e)}}

    def get_active_context_api(self, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Returns or binds the Stateful Target Session Context."""
        try:
            if params and (params.get("pid") or params.get("companion_elf") or params.get("process_name")):
                res = self.watch_manager.bind_target_context(
                    pid=int(params["pid"]) if params.get("pid") else None,
                    companion_elf_path=(params.get("companion_elf") or params.get("debug_image") or "").strip() or None,
                    process_name=(params.get("process_name") or "").strip() or None,
                    remote_host=(params.get("remote_host") or "").strip() or None,
                    ssh_user=(params.get("ssh_user") or "").strip() or None,
                    ssh_port=int(params.get("ssh_port") or 22),
                    ssh_key=(params.get("ssh_key") or "").strip() or None,
                    ssh_proxy_jump=(params.get("ssh_proxy_jump") or "").strip() or None,
                )
                return {"success": True, "data": res}
            return {"success": True, "data": self.watch_manager.get_active_target_context()}
        except Exception as e:
            return {"success": False, "error": {"code": "ACTIVE_CONTEXT_ERROR", "message": str(e)}}

    def coerce_expression_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Forgiving C/C++ Expression Auto-Coercer endpoint."""
        try:
            from extractor.dwarf_indexer import DwarfIndexer
            expr = str(params.get("expression") or "").strip()
            ctx = self.watch_manager.resolve_target_context(
                pid=int(params["pid"]) if params.get("pid") else None,
                companion_elf_path=(params.get("companion_elf") or params.get("debug_image") or "").strip() or None,
            )
            primary_elf, _ = self.watch_manager._split_companion_elf_paths(ctx["companion_elf_path"])
            idx = DwarfIndexer.get_index(primary_elf)
            res = self.watch_manager.coerce_and_resolve_expression(idx=idx, raw_expr=expr)
            res_clean = {k: v for k, v in res.items() if k != "ops"}
            return {"success": True, "data": {"pid": ctx["pid"], "companion_elf": ctx["companion_elf_path"], **res_clean}}
        except Exception as e:
            return {"success": False, "error": {"code": "COERCE_EXPRESSION_ERROR", "message": str(e)}}

    def ask_runtime_question_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Universal 1-Call Zero-Stop Intent Gateway endpoint (`/api/watch/ask`)."""
        try:
            q = str(params.get("question") or params.get("message") or "").strip()
            res = self.watch_manager.ask_runtime_question(
                question=q,
                pid=int(params["pid"]) if params.get("pid") else None,
                companion_elf_path=(params.get("companion_elf") or params.get("debug_image") or "").strip() or None,
                process_name=(params.get("process_name") or "").strip() or None,
                remote_host=(params.get("remote_host") or "").strip() or None,
                ssh_user=(params.get("ssh_user") or "").strip() or None,
                ssh_port=int(params.get("ssh_port") or 22),
                ssh_key=(params.get("ssh_key") or "").strip() or None,
                ssh_proxy_jump=(params.get("ssh_proxy_jump") or "").strip() or None,
            )
            return {"success": True, "data": res}
        except Exception as e:
            return {"success": False, "error": {"code": "ASK_GATEWAY_ERROR", "message": str(e)}}

    def smart_compact_query_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """LLM Token-Budgeted Smart Compactor & Anomaly-First Pagination endpoint (`/api/watch/smart-compact`)."""
        try:
            res = self.watch_manager.smart_compact_query(
                query_or_expression=str(params.get("query") or params.get("expression") or "*gpMem"),
                mode=str(params.get("mode") or "auto"),
                pid=int(params["pid"]) if params.get("pid") else None,
                companion_elf_path=(params.get("companion_elf") or params.get("debug_image") or "").strip() or None,
                max_tokens=int(params.get("max_tokens") or 800),
                drop_zero_or_free=bool(params.get("drop_zero_or_free", True)),
                cursor_offset=int(params.get("cursor_offset") or 0),
                page_size=int(params.get("page_size") or 16),
                remote_host=(params.get("remote_host") or "").strip() or None,
                ssh_user=(params.get("ssh_user") or "").strip() or None,
                ssh_port=int(params.get("ssh_port") or 22),
                ssh_key=(params.get("ssh_key") or "").strip() or None,
                ssh_proxy_jump=(params.get("ssh_proxy_jump") or "").strip() or None,
            )
            return {"success": True, "data": res}
        except Exception as e:
            return {"success": False, "error": {"code": "SMART_COMPACT_ERROR", "message": str(e)}}

    def batch_execute_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """1-Call Multi-Tool Composite Batch Macro Executor endpoint (`/api/watch/batch-execute`)."""
        try:
            steps = params.get("steps") or []
            res = self.watch_manager.execute_batch_macro(
                steps=steps,
                pid=int(params["pid"]) if params.get("pid") else None,
                companion_elf_path=(params.get("companion_elf") or params.get("debug_image") or "").strip() or None,
                process_name=(params.get("process_name") or "").strip() or None,
                compact=bool(params.get("compact", True)),
                max_tokens_per_step=int(params.get("max_tokens_per_step") or 800),
                remote_host=(params.get("remote_host") or "").strip() or None,
                ssh_user=(params.get("ssh_user") or "").strip() or None,
                ssh_port=int(params.get("ssh_port") or 22),
                ssh_key=(params.get("ssh_key") or "").strip() or None,
                ssh_proxy_jump=(params.get("ssh_proxy_jump") or "").strip() or None,
            )
            return {"success": True, "data": res}
        except Exception as e:
            return {"success": False, "error": {"code": "BATCH_EXECUTE_ERROR", "message": str(e)}}

    def verify_hypothesis_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Declarative Multi-Assertion Hypothesis Verifier endpoint (`/api/watch/verify-hypothesis`)."""
        try:
            assertions = params.get("assertions") or []
            if isinstance(assertions, str):
                assertions = [x.strip() for x in assertions.split(",") if x.strip()]
            res = self.watch_manager.verify_runtime_hypothesis(
                hypothesis=str(params.get("hypothesis") or "Runtime Hypothesis Verification"),
                assertions=assertions,
                correlate_owners=bool(params.get("correlate_owners", True)),
                pid=int(params["pid"]) if params.get("pid") else None,
                companion_elf_path=(params.get("companion_elf") or params.get("debug_image") or "").strip() or None,
                process_name=(params.get("process_name") or "").strip() or None,
                remote_host=(params.get("remote_host") or "").strip() or None,
                ssh_user=(params.get("ssh_user") or "").strip() or None,
                ssh_port=int(params.get("ssh_port") or 22),
                ssh_key=(params.get("ssh_key") or "").strip() or None,
                ssh_proxy_jump=(params.get("ssh_proxy_jump") or "").strip() or None,
            )
            return {"success": True, "data": res}
        except Exception as e:
            return {"success": False, "error": {"code": "VERIFY_HYPOTHESIS_ERROR", "message": str(e)}}

    def export_incident_report_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """1-Call Incident Report & Remediation Exporter endpoint (`/api/watch/export-report`)."""
        try:
            assertions = params.get("assertions")
            if isinstance(assertions, str):
                assertions = [x.strip() for x in assertions.split(",") if x.strip()]
            res = self.watch_manager.export_incident_report(
                title=str(params.get("title") or "dynamicState Zero-Stop Runtime Incident Report"),
                hypothesis=params.get("hypothesis"),
                assertions=assertions,
                output_path=params.get("output_path"),
                pid=int(params["pid"]) if params.get("pid") else None,
                companion_elf_path=(params.get("companion_elf") or params.get("debug_image") or "").strip() or None,
                process_name=(params.get("process_name") or "").strip() or None,
                remote_host=(params.get("remote_host") or "").strip() or None,
                ssh_user=(params.get("ssh_user") or "").strip() or None,
                ssh_port=int(params.get("ssh_port") or 22),
                ssh_key=(params.get("ssh_key") or "").strip() or None,
                ssh_proxy_jump=(params.get("ssh_proxy_jump") or "").strip() or None,
            )
            return {"success": True, "data": res}
        except Exception as e:
            return {"success": False, "error": {"code": "EXPORT_REPORT_ERROR", "message": str(e)}}

    def capture_and_diff_paths_api(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Samples C/C++ symbol expressions twice across wait_ms and returns changed/unchanged fields."""
        try:
            pid = int(params.get("pid") or 0)
            if pid <= 0:
                return {"success": False, "error": {"code": "INVALID_PID", "message": "Positive target PID is required"}}
            companion_elf = (params.get("companion_elf") or params.get("debug_image") or "").strip()
            if not companion_elf or not os.path.isfile(companion_elf):
                return {"success": False, "error": {"code": "DEBUG_IMAGE_NOT_FOUND", "message": f"Companion ELF not found: '{companion_elf}'"}}
            exprs = params.get("expressions")
            if isinstance(exprs, str):
                exprs = [e.strip() for e in exprs.split(",") if e.strip()]
            wait_ms = int(params.get("wait_ms") or 500)
            data = self.watch_manager.capture_and_diff_expressions(
                pid=pid,
                companion_elf_path=companion_elf,
                expressions=exprs,
                wait_ms=wait_ms,
                remote_host=(params.get("remote_host") or "").strip() or None,
                ssh_user=(params.get("ssh_user") or "").strip() or None,
                ssh_port=int(params.get("ssh_port") or 22),
                ssh_key=(params.get("ssh_key") or "").strip() or None,
                ssh_proxy_jump=(params.get("ssh_proxy_jump") or "").strip() or None,
            )
            return {"success": True, "data": data}
        except Exception as e:
            return {"success": False, "error": {"code": "CAPTURE_DIFF_ERROR", "message": str(e)}}

    # -------------------------------------------------------------------------
    # Phase 21 & Phase 23 Watch Session & Temporal Memory Explorer Endpoints
    # -------------------------------------------------------------------------

    def list_watch_sessions(self, query: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Lists metadata summaries of all watch sessions."""
        try:
            include_stopped = True
            if query and query.get("include_stopped"):
                val = str(query["include_stopped"][0]).lower()
                include_stopped = (val in ("true", "1", "yes"))
            sessions = self.watch_manager.list_sessions(include_stopped=include_stopped)
            return {"success": True, "data": {"total": len(sessions), "sessions": sessions}}
        except Exception as e:
            return {"success": False, "error": {"code": "LIST_SESSIONS_ERROR", "message": str(e)}}

    def get_watch_session_status(self, session_id: str) -> Dict[str, Any]:
        """Retrieves compact health and observation count for a session."""
        try:
            st = self.watch_manager.get_session_status(session_id)
            if not st.get("found"):
                return {"success": False, "error": {"code": "NOT_FOUND", "message": f"Watch session '{session_id}' not found"}}
            return {"success": True, "data": st}
        except Exception as e:
            return {"success": False, "error": {"code": "GET_STATUS_ERROR", "message": str(e)}}

    def get_watch_memory_map(
        self,
        pid: int,
        companion_elf: Optional[str] = None,
        remote_host: Optional[str] = None,
        ssh_user: Optional[str] = None,
        ssh_port: int = 22,
        ssh_key: Optional[str] = None,
        ssh_proxy_jump: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Explores process memory mappings, active threads, and discoverable variables across local or remote target."""
        try:
            data = self.watch_manager.get_memory_map_and_threads(
                pid=pid,
                companion_elf_path=companion_elf,
                remote_host=remote_host,
                ssh_user=ssh_user,
                ssh_port=ssh_port,
                ssh_key=ssh_key,
                ssh_proxy_jump=ssh_proxy_jump,
            )
            return {"success": True, "data": data}
        except Exception as e:
            return {"success": False, "error": {"code": "MEMORY_MAP_ERROR", "message": str(e)}}

    def create_watch_session(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Creates and starts a persistent watch session with GNU Build ID validation."""
        try:
            pid = int(params.get("pid", 0))
            if pid <= 0:
                return {"success": False, "error": {"code": "INVALID_PID", "message": "Target PID must be a positive integer"}}
            companion_elf = params.get("companion_elf") or params.get("companion_elf_path") or params.get("debug_image")
            interval_ms = int(params.get("interval_ms", 500))
            max_samples = int(params.get("max_samples", 1000))
            watch_items = params.get("watch_items") or []
            capture_mode = params.get("capture_mode", "ZERO_STOP")
            remote_host = params.get("remote_host")
            ssh_user = params.get("ssh_user")
            ssh_port = int(params.get("ssh_port", 22))
            ssh_key = params.get("ssh_key")
            ssh_proxy_jump = params.get("ssh_proxy_jump")

            session = self.watch_manager.create_session(
                pid=pid,
                companion_elf_path=companion_elf,
                interval_ms=interval_ms,
                max_samples=max_samples,
                initial_watch_items=watch_items,
                capture_mode=capture_mode,
                remote_host=remote_host,
                ssh_user=ssh_user,
                ssh_port=ssh_port,
                ssh_key=ssh_key,
                ssh_proxy_jump=ssh_proxy_jump,
            )
            return {"success": True, "data": session.to_dict()}
        except Exception as e:
            err_code = "BUILD_ID_MISMATCH" if "Build ID mismatch" in str(e) else "SESSION_CREATE_ERROR"
            return {"success": False, "error": {"code": err_code, "message": str(e)}}

    def get_watch_session(self, session_id: str) -> Dict[str, Any]:
        """Retrieves session metadata, watch items, and current status."""
        session = self.watch_manager.get_session(session_id)
        if not session:
            return {"success": False, "error": {"code": "NOT_FOUND", "message": f"Watch session '{session_id}' not found"}}
        return {"success": True, "data": session.to_dict()}

    def stop_watch_session(self, session_id: str) -> Dict[str, Any]:
        """Stops an active watch session."""
        session = self.watch_manager.stop_session(session_id)
        if not session:
            return {"success": False, "error": {"code": "NOT_FOUND", "message": f"Watch session '{session_id}' not found"}}
        return {"success": True, "data": session.to_dict()}

    def update_watch_items(self, session_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Adds or removes a watch item from an active or paused session."""
        action = params.get("action", "add")
        if action == "add":
            item_data = params.get("item") or params
            try:
                item = self.watch_manager.add_watch_item(session_id, item_data)
                return {"success": True, "data": item.to_dict()}
            except Exception as e:
                return {"success": False, "error": {"code": "ADD_WATCH_ITEM_ERROR", "message": str(e)}}
        elif action == "remove":
            item_id = params.get("item_id", "")
            removed = self.watch_manager.remove_watch_item(session_id, item_id)
            if not removed:
                return {"success": False, "error": {"code": "NOT_FOUND", "message": f"Watch item '{item_id}' not found"}}
            return {"success": True, "data": {"removed": True, "item_id": item_id}}
        else:
            return {"success": False, "error": {"code": "INVALID_ACTION", "message": f"Unknown action '{action}'"}}

    def get_watch_observations(self, session_id: str, query: Dict[str, Any]) -> Dict[str, Any]:
        """Retrieves time-series observations and gaps with optional sequence bounds/pagination."""
        try:
            start_seq = int(query["start_seq"][0]) if query.get("start_seq") else None
            end_seq = int(query["end_seq"][0]) if query.get("end_seq") else None
            limit = int(query["limit"][0]) if query.get("limit") else 200
            offset = int(query["offset"][0]) if query.get("offset") else 0
            data = self.watch_manager.get_observations(session_id, start_seq=start_seq, end_seq=end_seq, limit=limit, offset=offset)
            return {"success": True, "data": data}
        except Exception as e:
            return {"success": False, "error": {"code": "GET_OBSERVATIONS_ERROR", "message": str(e)}}

    def inspect_memory_range(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Inspects a bounded slice of target process memory (max 4096 bytes)."""
        from extractor.watch_session import read_process_memory_slice
        try:
            pid = int(params.get("pid", 0))
            if pid <= 0:
                return {"success": False, "error": {"code": "INVALID_PID", "message": "Valid positive PID is required"}}
            raw_addr = params.get("address", 0)
            if isinstance(raw_addr, str) and raw_addr.startswith("0x"):
                addr = int(raw_addr, 16)
            else:
                addr = int(raw_addr)
            size = int(params.get("size", 64))
            size = max(1, min(size, 4096))

            # DWARF variable match lookup if companion_elf is provided
            dwarf_match = None
            companion_elf = params.get("companion_elf") or params.get("debug_image")
            if companion_elf and os.path.isfile(companion_elf):
                try:
                    from extractor.dwarf_indexer import DwarfIndexer
                    idx = DwarfIndexer.get_index(companion_elf)
                    # Find load bias from target mappings
                    from extractor.target_adapter import LocalTargetAdapter
                    local_adapter = LocalTargetAdapter()
                    maps = local_adapter.get_proc_maps(pid)
                    load_bias = 0
                    for m in maps:
                        if m.get("category") == "code" or "r-x" in m.get("permissions", ""):
                            load_bias = int(m.get("start", "0"), 16)
                            break
                    for var in idx.variables:
                        if var.runtime_address is not None:
                            var_addr = var.runtime_address + load_bias if var.runtime_address < 0x10000000 else var.runtime_address
                            if var_addr == addr or (var_addr <= addr < var_addr + max(var.size or 4, 1)):
                                dwarf_match = {
                                    "name": var.name,
                                    "type_name": var.type_name,
                                    "runtime_address": f"0x{var_addr:x}",
                                    "size": var.size or 4,
                                }
                                break
                except Exception:
                    dwarf_match = None

            raw_bytes, read_st, read_err = read_process_memory_slice(pid, addr, size)
            if read_st == "OBSERVED" and raw_bytes is not None:
                ascii_repr = "".join((chr(b) if 32 <= b <= 126 else ".") for b in raw_bytes)
                return {
                    "success": True,
                    "data": {
                        "pid": pid,
                        "address": f"0x{addr:x}",
                        "address_int": addr,
                        "size": len(raw_bytes),
                        "bytes_read": len(raw_bytes),
                        "bytes_hex": raw_bytes.hex(),
                        "raw_hex": raw_bytes.hex(),
                        "ascii": ascii_repr,
                        "status": "OBSERVED",
                        "dwarf_match": dwarf_match,
                    }
                }
            elif read_st == "PARTIAL":
                ascii_repr = "".join((chr(b) if 32 <= b <= 126 else ".") for b in raw_bytes) if raw_bytes else ""
                return {
                    "success": True,
                    "data": {
                        "pid": pid,
                        "address": f"0x{addr:x}",
                        "address_int": addr,
                        "size": len(raw_bytes) if raw_bytes else 0,
                        "bytes_read": len(raw_bytes) if raw_bytes else 0,
                        "bytes_hex": raw_bytes.hex() if raw_bytes else "",
                        "raw_hex": raw_bytes.hex() if raw_bytes else "",
                        "ascii": ascii_repr,
                        "status": "PARTIAL",
                        "error": read_err or "Partial memory read",
                        "dwarf_match": dwarf_match,
                    }
                }
            else:
                return {
                    "success": True,
                    "data": {
                        "pid": pid,
                        "address": f"0x{addr:x}",
                        "address_int": addr,
                        "size": 0,
                        "bytes_read": 0,
                        "bytes_hex": "",
                        "raw_hex": "",
                        "ascii": "",
                        "status": "UNMAPPED",
                        "error": read_err or f"Unable to read memory at 0x{addr:x}",
                        "dwarf_match": None,
                    }
                }
        except Exception as e:
            return {"success": False, "error": {"code": "INSPECT_RANGE_ERROR", "message": str(e)}}

    def capture_watch_session(self, session_id: str) -> Dict[str, Any]:
        """Triggers an immediate synchronous capture of all watch items for a session."""
        try:
            obs = self.watch_manager.capture_once(session_id)
            return {"success": True, "data": obs.to_dict()}
        except Exception as e:
            return {"success": False, "error": {"code": "CAPTURE_ERROR", "message": str(e)}}

    def compare_watch_observations(self, session_id: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Compares two observation snapshots within a session."""
        try:
            seq_a = int(params.get("seq_a", 1))
            seq_b = int(params.get("seq_b", 2))
            res = self.watch_manager.compare_observations(session_id, seq_a, seq_b)
            return {"success": True, "data": res}
        except Exception as e:
            return {"success": False, "error": {"code": "COMPARE_ERROR", "message": str(e)}}

    def start_investigation(self, params: Dict[str, Any]) -> Dict[str, Any]:
        goal = params.get("goal") or "General state investigation"
        auth_target = params.get("authorize_target")
        if auth_target is None and params.get("pid"):
            auth_target = True
        else:
            auth_target = bool(auth_target)

        res = self.runtime.start_investigation(
            goal=goal,
            snapshot_id=params.get("snapshot_id"),
            memory_snapshot_path=params.get("memory_snapshot_path"),
            pid=params.get("pid"),
            debug_image=params.get("debug_image"),
            constraints=params.get("constraints"),
            budgets=params.get("budgets"),
            authorize_target=auth_target,
            watch_session_id=params.get("watch_session_id"),
            observation_window=params.get("observation_window"),
        )
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {
            "success": False,
            "data": _to_json_serializable(res.data) if res.data else None,
            "error": {
                "code": res.error.code if res.error else "INVESTIGATION_FAILED",
                "message": res.error.message if res.error else "Investigation failed"
            }
        }

    def analyze_temporal_investigation(self, params: Dict[str, Any]) -> Dict[str, Any]:
        """Phase 24: Evidence-first temporal investigation workflow endpoint."""
        goal = params.get("goal") or "Temporal state investigation"
        watch_session_id = params.get("watch_session_id") or params.get("session_id")
        obs_window = dict(params.get("observation_window") or {})
        for k in ("duration_sec", "guard_address", "buffer_address", "guard_threshold", "start_seq", "end_seq", "limit"):
            if k in params and k not in obs_window:
                obs_window[k] = params[k]

        res = self.runtime.start_investigation(
            goal=goal,
            watch_session_id=watch_session_id,
            observation_window=obs_window,
            debug_image=params.get("debug_image"),
            constraints=params.get("constraints"),
            authorize_target=True,
        )
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {
            "success": False,
            "data": _to_json_serializable(res.data) if res.data else None,
            "error": {
                "code": res.error.code if res.error else "TEMPORAL_INVESTIGATION_FAILED",
                "message": res.error.message if res.error else "Temporal investigation failed"
            }
        }

    def get_investigation_status(self, investigation_id: Optional[str]) -> Dict[str, Any]:
        if not investigation_id:
            return {"success": False, "error": {"code": "INVALID_PARAM", "message": "investigation_id is required"}}
        res = self.runtime.get_investigation_status(investigation_id)
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {"success": False, "error": {"code": res.error.code if res.error else "NOT_FOUND",
                                            "message": res.error.message if res.error else "Investigation status not found"}}

    def get_evidence(self, investigation_id: Optional[str], evidence_id: Optional[str] = None, finding_id: Optional[str] = None) -> Dict[str, Any]:
        if not investigation_id:
            return {"success": False, "error": {"code": "INVALID_PARAM", "message": "investigation_id is required"}}
        res = self.runtime.get_evidence(investigation_id, evidence_id=evidence_id, finding_id=finding_id)
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {"success": False, "error": {"code": res.error.code if res.error else "NOT_FOUND",
                                            "message": res.error.message if res.error else "Evidence not found"}}

    def compare_observations(self, params: Dict[str, Any]) -> Dict[str, Any]:
        inv_id = params.get("investigation_id")
        snap_a = params.get("snapshot_a")
        snap_b = params.get("snapshot_b")
        if not inv_id or not snap_a or not snap_b:
            return {"success": False, "error": {"code": "INVALID_PARAM", "message": "investigation_id, snapshot_a, and snapshot_b are required"}}
        res = self.runtime.compare_observations(inv_id, snap_a, snap_b)
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {"success": False, "error": {"code": res.error.code if res.error else "COMPARE_FAILED",
                                            "message": res.error.message if res.error else "Comparison failed"}}

    def follow_evidence(self, investigation_id: Optional[str], evidence_id: Optional[str], direction: str = "related_objects") -> Dict[str, Any]:
        if not investigation_id or not evidence_id:
            return {"success": False, "error": {"code": "INVALID_PARAM", "message": "investigation_id and evidence_id are required"}}
        res = self.runtime.follow_evidence(investigation_id, evidence_id, direction=direction)
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {"success": False, "error": {"code": res.error.code if res.error else "NOT_FOUND",
                                            "message": res.error.message if res.error else "Failed to follow evidence"}}

    def get_next_steps(self, investigation_id: Optional[str]) -> Dict[str, Any]:
        if not investigation_id:
            return {"success": False, "error": {"code": "INVALID_PARAM", "message": "investigation_id is required"}}
        res = self.runtime.get_next_steps(investigation_id)
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {"success": False, "error": {"code": res.error.code if res.error else "NOT_FOUND",
                                            "message": res.error.message if res.error else "Failed to get next steps"}}

    def get_investigation_report(self, investigation_id: Optional[str]) -> Dict[str, Any]:
        if not investigation_id:
            return {"success": False, "error": {"code": "INVALID_PARAM", "message": "investigation_id is required"}}
        res = self.runtime.get_investigation_report(investigation_id)
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {"success": False, "error": {"code": res.error.code if res.error else "NOT_FOUND",
                                            "message": res.error.message if res.error else "Report not found"}}

    def list_investigations(self) -> Dict[str, Any]:
        sessions = getattr(self.runtime.investigation_manager, "sessions", {})
        summaries = [s.to_dict() for s in sessions.values()]
        return {"success": True, "data": _to_json_serializable(summaries)}

    def get_hypotheses(self, investigation_id: Optional[str], status_filter: Optional[str] = None) -> Dict[str, Any]:
        if not investigation_id:
            return {"success": False, "error": {"code": "INVALID_PARAM", "message": "investigation_id is required"}}
        res = self.runtime.get_hypotheses(investigation_id, status_filter=status_filter)
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {"success": False, "error": {"code": res.error.code if res.error else "NOT_FOUND",
                                            "message": res.error.message if res.error else "Failed to get hypotheses"}}

    def evaluate_hypothesis(self, params: Dict[str, Any]) -> Dict[str, Any]:
        inv_id = params.get("investigation_id")
        hypo_id = params.get("hypothesis_id")
        if not inv_id or not hypo_id:
            return {"success": False, "error": {"code": "INVALID_PARAM", "message": "investigation_id and hypothesis_id are required"}}
        new_ev = params.get("new_evidence")
        det_trans = bool(params.get("deterministic_transition_verified", False))
        proof_eid = params.get("proof_evidence_id")
        res = self.runtime.evaluate_hypothesis(
            inv_id,
            hypo_id,
            new_evidence=new_ev,
            deterministic_transition_verified=det_trans,
            proof_evidence_id=proof_eid,
        )
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {"success": False, "error": {"code": res.error.code if res.error else "EVAL_ERROR",
                                            "message": res.error.message if res.error else "Failed to evaluate hypothesis"}}

    def execute_observation(self, params: Dict[str, Any]) -> Dict[str, Any]:
        inv_id = params.get("investigation_id")
        obs_id = params.get("observation_id")
        if not inv_id or not obs_id:
            return {"success": False, "error": {"code": "INVALID_PARAM", "message": "investigation_id and observation_id are required"}}
        res_data = params.get("result_data")
        res = self.runtime.execute_observation(inv_id, obs_id, result_data=res_data)
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {"success": False, "error": {"code": res.error.code if res.error else "OBSERVATION_ERROR",
                                            "message": res.error.message if res.error else "Failed to execute observation"}}

    def cancel_observation(self, params: Dict[str, Any]) -> Dict[str, Any]:
        inv_id = params.get("investigation_id")
        obs_id = params.get("observation_id")
        reason = params.get("reason")
        if not inv_id or not obs_id:
            return {"success": False, "error": {"code": "INVALID_PARAM", "message": "investigation_id and observation_id are required"}}
        res = self.runtime.cancel_observation(inv_id, obs_id, reason=reason)
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {"success": False, "error": {"code": res.error.code if res.error else "CANCEL_ERROR",
                                            "message": res.error.message if res.error else "Failed to cancel observation"}}

    def get_investigation_timeline(self, investigation_id: Optional[str]) -> Dict[str, Any]:
        if not investigation_id:
            return {"success": False, "error": {"code": "INVALID_PARAM", "message": "investigation_id is required"}}
        res = self.runtime.get_investigation_timeline(investigation_id)
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {"success": False, "error": {"code": res.error.code if res.error else "NOT_FOUND",
                                            "message": res.error.message if res.error else "Failed to get timeline"}}

    def get_finding_drilldown(self, investigation_id: Optional[str], finding_id: Optional[str]) -> Dict[str, Any]:
        if not investigation_id or not finding_id:
            return {"success": False, "error": {"code": "INVALID_PARAM", "message": "investigation_id and finding_id are required"}}
        res = self.runtime.get_finding_drilldown(investigation_id, finding_id)
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {"success": False, "error": {"code": res.error.code if res.error else "NOT_FOUND",
                                            "message": res.error.message if res.error else "Failed to get finding drilldown"}}

    def run_investigation_cycle(self, params: Dict[str, Any]) -> Dict[str, Any]:
        inv_id = params.get("investigation_id")
        if not inv_id:
            return {"success": False, "error": {"code": "INVALID_PARAM", "message": "investigation_id is required"}}
        max_iter = int(params.get("max_iterations", 5))
        max_obs = int(params.get("max_observations", 10))
        stop_on_contra = bool(params.get("stop_on_contradiction", False))
        res = self.runtime.run_investigation_cycle(
            inv_id,
            max_iterations=max_iter,
            max_observations=max_obs,
            stop_on_contradiction=stop_on_contra,
        )
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {"success": False, "error": {"code": res.error.code if res.error else "CYCLE_ERROR",
                                            "message": res.error.message if res.error else "Failed to run cycle"}}

    def step_investigation_cycle(self, params: Dict[str, Any]) -> Dict[str, Any]:
        inv_id = params.get("investigation_id")
        if not inv_id:
            return {"success": False, "error": {"code": "INVALID_PARAM", "message": "investigation_id is required"}}
        res = self.runtime.step_investigation_cycle(inv_id)
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {"success": False, "error": {"code": res.error.code if res.error else "CYCLE_STEP_ERROR",
                                            "message": res.error.message if res.error else "Failed to step cycle"}}

    def propose_hypothesis(self, params: Dict[str, Any]) -> Dict[str, Any]:
        inv_id = params.get("investigation_id")
        if not inv_id:
            return {"success": False, "error": {"code": "INVALID_PARAM", "message": "investigation_id is required"}}
        hypo_data = params.get("hypothesis_data") or params.get("hypothesis") or params
        res = self.runtime.propose_hypothesis(inv_id, hypo_data)
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {"success": False, "error": {"code": res.error.code if res.error else "PROPOSAL_ERROR",
                                            "message": res.error.message if res.error else "Failed to propose hypothesis"}}

    def save_investigation(self, params: Dict[str, Any]) -> Dict[str, Any]:
        inv_id = params.get("investigation_id")
        if not inv_id:
            return {"success": False, "error": {"code": "INVALID_PARAM", "message": "investigation_id is required"}}
        res = self.runtime.save_investigation_session(inv_id, file_path=params.get("file_path"))
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {"success": False, "error": {"code": res.error.code if res.error else "SAVE_ERROR",
                                            "message": res.error.message if res.error else "Failed to save session"}}

    def load_investigation(self, params: Dict[str, Any]) -> Dict[str, Any]:
        data_or_path = params.get("file_path") or params.get("session_data") or params
        res = self.runtime.load_investigation_session(data_or_path)
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {"success": False, "error": {"code": res.error.code if res.error else "LOAD_ERROR",
                                            "message": res.error.message if res.error else "Failed to load session"}}

    def analyze_investigation_chat(self, params: Dict[str, Any]) -> Dict[str, Any]:
        # Privileged configuration protection: reject any attempts to supply execution configuration from client
        privileged_keys = {
            "cli_command", "cli_args", "executable", "allow_dangerous_permissions",
            "safe_working_dir", "max_output_bytes", "command", "binary_path", "shell",
        }
        for pk in privileged_keys:
            if pk in params:
                return {
                    "success": False,
                    "error": {
                        "code": "PRIVILEGED_CONFIG_FORBIDDEN",
                        "message": f"Parameter '{pk}' is privileged server-side configuration and cannot be specified in client requests."
                    }
                }

        inv_id = params.get("investigation_id")
        if not inv_id or not isinstance(inv_id, str):
            return {"success": False, "error": {"code": "INVALID_PARAM", "message": "investigation_id is required and must be a string"}}

        provider_override = params.get("provider_override")
        if provider_override is not None:
            from extractor.llm_provider import LLMProviderManager
            if not isinstance(provider_override, str) or provider_override.lower().strip() not in LLMProviderManager.ALLOWED_PROVIDERS:
                return {
                    "success": False,
                    "error": {
                        "code": "INVALID_PARAM",
                        "message": f"Invalid provider_override '{provider_override}'. Allowed providers: {sorted(LLMProviderManager.ALLOWED_PROVIDERS)}"
                    }
                }

        msg = params.get("message") or params.get("user_message") or "Analyze the observed state changes and propose evidence-grounded hypotheses."
        req_id = params.get("request_id")
        allow_fallback = bool(params.get("allow_fallback", False))
        raw_loc = params.get("locale") or params.get("language") or "en"
        locale = "ko" if str(raw_loc).lower().strip() in ("ko", "kor", "korean") else "en"
        res = self.runtime.analyze_investigation_chat(
            investigation_id=inv_id,
            message=msg,
            request_id=req_id,
            provider_override=provider_override,
            allow_fallback=allow_fallback,
            locale=locale,
        )
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {"success": False, "error": {"code": res.error.code if res.error else "CONVERSATIONAL_ANALYSIS_ERROR",
                                            "message": res.error.message if res.error else "Failed to analyze chat"}}

    def cancel_investigation_chat(self, params: Dict[str, Any]) -> Dict[str, Any]:
        req_id = params.get("request_id")
        if not req_id:
            return {"success": False, "error": {"code": "INVALID_PARAM", "message": "request_id is required"}}
        res = self.runtime.cancel_investigation_chat(req_id)
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {"success": False, "error": {"code": res.error.code if res.error else "CANCEL_ERROR",
                                            "message": res.error.message if res.error else "Failed to cancel chat"}}

    def get_llm_status(self) -> Dict[str, Any]:
        res = self.runtime.get_llm_status()
        if res.success:
            return {"success": True, "data": _to_json_serializable(res.data)}
        return {"success": False, "error": {"code": res.error.code if res.error else "RUNTIME_ERROR",
                                            "message": res.error.message if res.error else "Failed to get LLM status"}}


WebRuntimeAdapter = WebApiAdapter


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

    def do_HEAD(self) -> None:
        """Handle HEAD requests by processing GET headers without error."""
        self.do_GET()

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

            # GET /api/states/{state_id}/objects/{object_id}/code-navigation
            m_state_obj_nav = re.match(r"^/api/states/([^/]+)/objects/([^/]+)/code-navigation$", path)
            if m_state_obj_nav:
                state_id = m_state_obj_nav.group(1)
                object_id = m_state_obj_nav.group(2)
                self._send_json(adapter.get_code_navigation(
                    object_id,
                    field_name=q_param("field") or q_param("field_path"),
                    snapshot_id=state_id
                ))
                return

            # GET /api/objects/{object_id}/code-navigation
            m_obj_nav = re.match(r"^/api/objects/([^/]+)/code-navigation$", path)
            if m_obj_nav:
                object_id = m_obj_nav.group(1)
                self._send_json(adapter.get_code_navigation(
                    object_id,
                    field_name=q_param("field") or q_param("field_path"),
                    snapshot_id=q_param("snapshot_id")
                ))
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

            # GET /api/investigation/status
            if path == "/api/investigation/status":
                self._send_json(adapter.get_investigation_status(q_param("investigation_id")))
                return

            # GET /api/investigation/evidence
            if path == "/api/investigation/evidence":
                self._send_json(adapter.get_evidence(
                    q_param("investigation_id"),
                    evidence_id=q_param("evidence_id"),
                    finding_id=q_param("finding_id")
                ))
                return

            # GET /api/investigation/follow
            if path == "/api/investigation/follow":
                self._send_json(adapter.follow_evidence(
                    q_param("investigation_id"),
                    q_param("evidence_id"),
                    direction=q_param("direction", "related_objects")
                ))
                return

            # GET /api/investigation/next-steps
            if path == "/api/investigation/next-steps":
                self._send_json(adapter.get_next_steps(q_param("investigation_id")))
                return

            # GET /api/investigation/report
            if path == "/api/investigation/report":
                self._send_json(adapter.get_investigation_report(q_param("investigation_id")))
                return

            # GET /api/investigation/hypotheses
            if path == "/api/investigation/hypotheses":
                self._send_json(adapter.get_hypotheses(
                    q_param("investigation_id"),
                    status_filter=q_param("status_filter")
                ))
                return

            # GET /api/investigation/timeline
            if path == "/api/investigation/timeline":
                self._send_json(adapter.get_investigation_timeline(q_param("investigation_id")))
                return

            # GET /api/investigation/drilldown
            if path == "/api/investigation/drilldown":
                self._send_json(adapter.get_finding_drilldown(
                    q_param("investigation_id"),
                    q_param("finding_id")
                ))
                return

            # GET /api/investigations
            if path == "/api/investigations":
                self._send_json(adapter.list_investigations())
                return

            # GET /api/llm/status and /api/investigation/llm-status
            if path in ("/api/llm/status", "/api/investigation/llm-status", "/api/investigation/chat/status"):
                self._send_json(adapter.get_llm_status())
                return

            # GET /api/watch/sessions
            if path == "/api/watch/sessions":
                self._send_json(adapter.list_watch_sessions(query))
                return

            # GET /api/watch/memory-map
            if path == "/api/watch/memory-map":
                pid_str = q_param("pid")
                if not pid_str:
                    self._send_json({"success": False, "error": {"code": "INVALID_PARAM", "message": "Query parameter 'pid' is required"}}, status=400)
                    return
                try:
                    pid = int(pid_str)
                except ValueError:
                    self._send_json({"success": False, "error": {"code": "INVALID_PARAM", "message": f"Invalid PID: {pid_str}"}}, status=400)
                    return
                companion_elf = q_param("companion_elf") or q_param("debug_image")
                remote_host = q_param("remote_host")
                ssh_user = q_param("ssh_user")
                ssh_port = int(q_param("ssh_port") or 22)
                ssh_key = q_param("ssh_key")
                ssh_proxy_jump = q_param("ssh_proxy_jump")
                self._send_json(adapter.get_watch_memory_map(
                    pid,
                    companion_elf=companion_elf,
                    remote_host=remote_host,
                    ssh_user=ssh_user,
                    ssh_port=ssh_port,
                    ssh_key=ssh_key,
                    ssh_proxy_jump=ssh_proxy_jump,
                ))
                return

            # GET /api/watch/session/{session_id}/status
            m_watch_status = re.match(r"^/api/watch/session/([^/]+)/status$", path)
            if m_watch_status:
                session_id = m_watch_status.group(1)
                self._send_json(adapter.get_watch_session_status(session_id))
                return

            # GET /api/watch/session/{session_id}/observations
            m_watch_obs = re.match(r"^/api/watch/session/([^/]+)/observations$", path)
            if m_watch_obs:
                session_id = m_watch_obs.group(1)
                self._send_json(adapter.get_watch_observations(session_id, query))
                return

            # GET /api/watch/session/{session_id}
            m_watch_sess = re.match(r"^/api/watch/session/([^/]+)$", path)
            if m_watch_sess:
                session_id = m_watch_sess.group(1)
                self._send_json(adapter.get_watch_session(session_id))
                return

            # GET /api/target/processes
            if path == "/api/target/processes":
                self._send_json(adapter.find_target_processes({
                    "process_name": q_param("process_name") or q_param("query"),
                    "companion_elf": q_param("companion_elf") or q_param("debug_image"),
                    "remote_host": q_param("remote_host"),
                    "ssh_user": q_param("ssh_user"),
                    "ssh_port": q_param("ssh_port", "22"),
                    "ssh_key": q_param("ssh_key"),
                    "ssh_proxy_jump": q_param("ssh_proxy_jump"),
                }))
                return

            # GET /api/watch/baselines
            if path == "/api/watch/baselines":
                self._send_json(adapter.list_golden_baselines_api({
                    "binary_build_id": q_param("binary_build_id"),
                }))
                return

            # GET /api/watch/search-symbols
            if path == "/api/watch/search-symbols":
                self._send_json(adapter.search_dwarf_symbols_api({
                    "companion_elf": q_param("companion_elf") or q_param("debug_image"),
                    "query": q_param("query", ""),
                    "category": q_param("category", "all"),
                    "limit": q_param("limit", "50"),
                }))
                return

            # GET /api/target/inspect-range
            if path == "/api/target/inspect-range":
                pid_str = q_param("pid")
                addr_str = q_param("address")
                size_str = q_param("size", "64")
                if not pid_str or not addr_str:
                    self._send_json({"success": False, "error": {"code": "INVALID_PARAM", "message": "Query parameters 'pid' and 'address' are required"}}, status=400)
                    return
                self._send_json(adapter.inspect_memory_range({
                    "pid": pid_str,
                    "address": addr_str,
                    "size": size_str,
                }))
                return

            # GET /api/watch/session/{session_id}/compare
            m_watch_cmp = re.match(r"^/api/watch/session/([^/]+)/compare$", path)
            if m_watch_cmp:
                session_id = m_watch_cmp.group(1)
                self._send_json(adapter.compare_watch_observations(session_id, {
                    "seq_a": q_param("seq_a", "1"),
                    "seq_b": q_param("seq_b", "2"),
                }))
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

            # Investigation POST routes
            if path in ("/api/investigation/validate-target", "/api/investigation/validate"):
                self._send_json(adapter.validate_target(body))
                return

            if path == "/api/investigation/start":
                self._send_json(adapter.start_investigation(body))
                return

            if path in ("/api/investigation/temporal-analyze", "/api/investigation/temporal-plan"):
                self._send_json(adapter.analyze_temporal_investigation(body))
                return

            if path == "/api/investigation/compare":
                self._send_json(adapter.compare_observations(body))
                return

            if path in ("/api/investigation/hypotheses/evaluate", "/api/investigation/evaluate"):
                self._send_json(adapter.evaluate_hypothesis(body))
                return

            if path in ("/api/investigation/observe", "/api/investigation/observations/execute"):
                self._send_json(adapter.execute_observation(body))
                return

            if path in ("/api/investigation/cancel-observation", "/api/investigation/observations/cancel"):
                self._send_json(adapter.cancel_observation(body))
                return

            if path in ("/api/investigation/cycle", "/api/investigation/run-cycle"):
                self._send_json(adapter.run_investigation_cycle(body))
                return

            if path in ("/api/investigation/step", "/api/investigation/step-cycle"):
                self._send_json(adapter.step_investigation_cycle(body))
                return

            if path in ("/api/investigation/hypotheses/propose", "/api/investigation/propose-hypothesis", "/api/investigation/propose"):
                self._send_json(adapter.propose_hypothesis(body))
                return

            if path == "/api/investigation/save":
                self._send_json(adapter.save_investigation(body))
                return

            if path == "/api/investigation/load":
                self._send_json(adapter.load_investigation(body))
                return

            if path in ("/api/investigation/chat", "/api/investigation/analyze-chat"):
                self._send_json(adapter.analyze_investigation_chat(body))
                return

            if path in ("/api/investigation/chat/cancel", "/api/investigation/cancel-chat"):
                self._send_json(adapter.cancel_investigation_chat(body))
                return

            # POST /api/watch/session/create
            if path == "/api/watch/session/create":
                self._send_json(adapter.create_watch_session(body))
                return

            # POST /api/watch/session/{session_id}/stop
            m_watch_stop = re.match(r"^/api/watch/session/([^/]+)/stop$", path)
            if m_watch_stop:
                session_id = m_watch_stop.group(1)
                self._send_json(adapter.stop_watch_session(session_id))
                return

            # POST /api/watch/session/{session_id}/watch
            m_watch_item = re.match(r"^/api/watch/session/([^/]+)/watch$", path)
            if m_watch_item:
                session_id = m_watch_item.group(1)
                self._send_json(adapter.update_watch_items(session_id, body))
                return

            # POST /api/target/deploy-collector
            if path == "/api/target/deploy-collector":
                self._send_json(adapter.deploy_remote_collector_api(body))
                return

            # POST /api/target/find-processes
            if path in ("/api/target/find-processes", "/api/target/processes"):
                self._send_json(adapter.find_target_processes(body))
                return

            # POST /api/watch/search-symbols
            if path == "/api/watch/search-symbols":
                self._send_json(adapter.search_dwarf_symbols_api(body))
                return

            # POST /api/watch/eval-paths
            if path == "/api/watch/eval-paths":
                self._send_json(adapter.evaluate_symbol_paths_api(body))
                return

            # POST /api/watch/recipe
            if path == "/api/watch/recipe":
                self._send_json(adapter.run_diagnostic_recipe_api(body))
                return

            # POST /api/watch/baseline/save
            if path == "/api/watch/baseline/save":
                self._send_json(adapter.save_golden_baseline_api(body))
                return

            # POST /api/watch/baseline/compare
            if path == "/api/watch/baseline/compare":
                self._send_json(adapter.compare_golden_baseline_api(body))
                return

            # POST /api/watch/capture-diff
            if path == "/api/watch/capture-diff":
                self._send_json(adapter.capture_and_diff_paths_api(body))
                return

            # POST /api/watch/scan-pool
            if path == "/api/watch/scan-pool":
                self._send_json(adapter.scan_memory_pool_api(body))
                return

            # POST /api/watch/find-owners
            if path == "/api/watch/find-owners":
                self._send_json(adapter.find_symbol_owners_api(body))
                return

            # POST /api/watch/xray-blueprint
            if path == "/api/watch/xray-blueprint":
                self._send_json(adapter.get_xray_blueprint_api(body))
                return

            # POST /api/workspace/chat
            if path == "/api/workspace/chat":
                self._send_json(adapter.workspace_chat_api(body))
                return

            # Phase 40 (Phase 10) Advanced Diagnostic Routes
            if path == "/api/watch/until-condition":
                self._send_json(adapter.watch_until_condition_api(body))
                return
            if path == "/api/watch/traverse-list":
                self._send_json(adapter.traverse_linked_structure_api(body))
                return
            if path == "/api/watch/thread-callstacks":
                self._send_json(adapter.inspect_thread_callstacks_api(body))
                return
            if path == "/api/watch/audit-integrity":
                self._send_json(adapter.audit_memory_integrity_api(body))
                return
            if path == "/api/watch/resolve-code-pointers":
                self._send_json(adapter.resolve_code_pointers_api(body))
                return
            if path == "/api/watch/inspect-shm":
                self._send_json(adapter.inspect_shared_memory_ipc_api(body))
                return
            if path == "/api/watch/frame-locals":
                self._send_json(adapter.inspect_thread_locals_api(body))
                return
            if path == "/api/watch/auto-triage":
                self._send_json(adapter.auto_triage_incident_api(body))
                return
            if path == "/api/watch/ipc-pipeline":
                self._send_json(adapter.trace_ipc_pipeline_api(body))
                return
            if path == "/api/watch/scan-heap":
                self._send_json(adapter.scan_heap_objects_api(body))
                return
            if path == "/api/watch/dependency-graph":
                self._send_json(adapter.build_dependency_graph_api(body))
                return
            if path == "/api/watch/correlate-source":
                self._send_json(adapter.correlate_source_and_state_api(body))
                return
            if path == "/api/watch/investigate-symptom":
                self._send_json(adapter.investigate_symptom_api(body))
                return
            if path == "/api/watch/statistical-hotspots":
                self._send_json(adapter.sample_statistical_hotspots_api(body))
                return
            if path == "/api/watch/resolve-fuzzy-intent":
                self._send_json(adapter.resolve_fuzzy_intent_api(body))
                return
            if path == "/api/watch/flight-recorder":
                self._send_json(adapter.flight_recorder_time_machine_api(body))
                return
            if path == "/api/watch/behavioral-drift":
                self._send_json(adapter.detect_behavioral_drift_api(body))
                return
            if path == "/api/watch/tls-storage":
                self._send_json(adapter.inspect_thread_local_storage_api(body))
                return
            if path == "/api/watch/verify-consistency":
                self._send_json(adapter.verify_concurrent_read_consistency_api(body))
                return
            if path == "/api/watch/dpdk-lcores":
                self._send_json(adapter.inspect_dpdk_lcores_and_rings_api(body))
                return
            if path == "/api/watch/active-context":
                self._send_json(adapter.get_active_context_api(body))
                return
            if path == "/api/watch/coerce-expression":
                self._send_json(adapter.coerce_expression_api(body))
                return
            if path == "/api/watch/ask":
                self._send_json(adapter.ask_runtime_question_api(body))
                return
            if path == "/api/watch/smart-compact":
                self._send_json(adapter.smart_compact_query_api(body))
                return
            if path == "/api/watch/batch-execute":
                self._send_json(adapter.batch_execute_api(body))
                return
            if path == "/api/watch/verify-hypothesis":
                self._send_json(adapter.verify_hypothesis_api(body))
                return
            if path == "/api/watch/export-report":
                self._send_json(adapter.export_incident_report_api(body))
                return

            # POST /api/target/inspect-range
            if path == "/api/target/inspect-range":
                self._send_json(adapter.inspect_memory_range(body))
                return

            # POST /api/watch/session/{session_id}/capture
            m_watch_cap = re.match(r"^/api/watch/session/([^/]+)/capture$", path)
            if m_watch_cap:
                session_id = m_watch_cap.group(1)
                self._send_json(adapter.capture_watch_session(session_id))
                return

            # POST /api/watch/session/{session_id}/compare
            m_watch_cmp_post = re.match(r"^/api/watch/session/([^/]+)/compare$", path)
            if m_watch_cmp_post:
                session_id = m_watch_cmp_post.group(1)
                self._send_json(adapter.compare_watch_observations(session_id, body))
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
        if path in ("/workspace", "/workspace/"):
            ws_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "workspace_static")
            ws_index = os.path.join(ws_dir, "index.html")
            if os.path.isfile(ws_index):
                with open(ws_index, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(content)))
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                self.wfile.write(content)
                return
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
        except (BrokenPipeError, ConnectionResetError):
            pass
        except Exception as exc:
            try:
                self.send_error(500, f"Error reading static file: {exc}")
            except (BrokenPipeError, ConnectionResetError):
                pass

    def _send_json(self, data: Any, status: int = 200) -> None:
        try:
            encoded = json.dumps(data, indent=2, ensure_ascii=False, default=str).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(encoded)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, format: str, *args: Any) -> None:
        # Keep server output quiet or structured unless debugging
        if os.environ.get("DYNAMICSTATE_LOG_HTTP"):
            super().log_message(format, *args)


class DynamicStateWebServer(http.server.ThreadingHTTPServer):
    """HTTP Server for dynamicState Web UI."""
    daemon_threads = True

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

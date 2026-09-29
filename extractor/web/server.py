"""HTTP Web API server and static asset host for dynamicState Runtime State Explorer.

Strictly wraps AgentRuntime without duplicating semantics, executing arbitrary shell/GDB commands,
or making silent target architecture assumptions.
"""

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
            return {"success": True, "data": _to_json_serializable(res.data)}
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

        # Observation point resolution
        observation_point = None
        if self.runtime._cached_checkpoints:
            last_cp = list(self.runtime._cached_checkpoints.values())[-1]
            if getattr(last_cp, "observation_point", None):
                observation_point = last_cp.observation_point

        if not observation_point and ctrl:
            bp_spec = getattr(ctrl, "breakpoint_spec", None)
            if hasattr(ctrl, "restorer"):
                if getattr(ctrl.restorer, "breakpoint_spec", None):
                    bp_spec = ctrl.restorer.breakpoint_spec
                elif hasattr(ctrl.restorer, "_restart_restorer") and getattr(ctrl.restorer._restart_restorer, "breakpoint_spec", None):
                    bp_spec = ctrl.restorer._restart_restorer.breakpoint_spec
            if bp_spec:
                observation_point = {
                    "kind": "BREAKPOINT",
                    "spec": bp_spec,
                    "function": bp_spec,
                    "location": bp_spec,
                }

        # Threads detail resolution from latest snapshot
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
                if not t_name:
                    t_name = "Main Thread" if tid == 1 else f"Worker #{tid}"
                threads_detail.append({
                    "thread_id": tid,
                    "name": t_name,
                    "state": th_dict.get("state", "STOPPED"),
                    "function": top_f_dict.get("function") or "<unknown>",
                    "location": top_f_dict.get("location") or (f"{top_f_dict.get('function')}()" if top_f_dict.get("function") else "<unknown>"),
                    "frame_depth": len(frames),
                })
            if not observation_point and threads_detail and threads_detail[0]["function"] != "<unknown>":
                observation_point = {
                    "kind": "FRAME",
                    "spec": threads_detail[0]["function"],
                    "function": threads_detail[0]["function"],
                    "location": threads_detail[0]["location"],
                }

        # Fallback to inferior thread inspection if live GDB inferior
        if not threads_detail and ctrl and hasattr(ctrl, "gdb") and hasattr(ctrl.gdb, "selected_inferior"):
            try:
                inf = ctrl.gdb.selected_inferior()
                for t in inf.threads():
                    tid = getattr(t, "global_num", None) or getattr(t, "num", 1)
                    t_name = getattr(t, "name", None) or ("Main Thread" if tid == 1 else f"Worker #{tid}")
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
                        "function": "<unknown>",
                        "location": "<unknown>",
                        "frame_depth": 1,
                    })
            except Exception:
                pass

        if not threads_detail:
            thread_cnt = caps.get("threads", 1)
            for i in range(1, thread_cnt + 1):
                threads_detail.append({
                    "thread_id": i,
                    "name": "Main Thread" if i == 1 else f"Worker #{i}",
                    "state": status if status != "DISCONNECTED" else "UNKNOWN",
                    "function": "<unknown>",
                    "location": "<unknown>",
                    "frame_depth": 1,
                })

        if not observation_point:
            observation_point = {
                "kind": "BREAKPOINT",
                "spec": "observation_checkpoint",
                "function": "observation_checkpoint",
                "location": "observation_checkpoint",
            }

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
                "checkpoint_restore": caps.get("checkpoint_restore", {}),
                "branch_isolation": caps.get("branch_isolation", {}),
                "current_checkpoint": list(self.runtime._cached_checkpoints.keys())[-1] if self.runtime._cached_checkpoints else None,
                "safety_limits": caps.get("limits", {}),
                "capabilities": caps,
                "memory_summary": mem_summary,
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

        # Build root mapping (object_ref -> root)
        root_map: Dict[str, Dict[str, Any]] = {}
        for idx, r in enumerate(roots):
            r_dict = r if isinstance(r, dict) else (r.to_dict() if hasattr(r, "to_dict") else asdict(r))
            oref = r_dict.get("object_ref")
            if oref:
                root_map[oref] = r_dict
            elif idx < len(objects):
                fallback_oid = objects[idx].get("object_id") if isinstance(objects[idx], dict) else getattr(objects[idx], "object_id", None)
                if fallback_oid and fallback_oid not in root_map:
                    root_map[fallback_oid] = r_dict

        # Build parent reference map (object_ref -> parent_path)
        parent_ref_map: Dict[str, str] = {}
        for o in objects:
            o_dict = o if isinstance(o, dict) else (o.to_dict() if hasattr(o, "to_dict") else asdict(o))
            oid = o_dict.get("object_id")
            p_name = root_map.get(oid, {}).get("name") or _clean_type_name(o_dict.get("type", ""))
            for f in o_dict.get("fields", []):
                f_dict = f if isinstance(f, dict) else (f.to_dict() if hasattr(f, "to_dict") else asdict(f))
                ref = f_dict.get("object_ref")
                if ref and ref not in parent_ref_map:
                    parent_ref_map[ref] = f"{p_name}.{f_dict.get('name')}"

        enriched_objects = []
        for o in objects:
            o_dict = o if isinstance(o, dict) else (o.to_dict() if hasattr(o, "to_dict") else asdict(o))
            oid = o_dict.get("object_id", "")
            raw_type = o_dict.get("type", "Unknown")
            cleaned_type = _clean_type_name(raw_type)

            semantic_name = None
            if oid in root_map:
                semantic_name = root_map[oid].get("name")
            elif oid in parent_ref_map:
                semantic_name = parent_ref_map[oid]
            else:
                semantic_name = cleaned_type

            enriched_fields = []
            for f in o_dict.get("fields", []):
                f_dict = f if isinstance(f, dict) else (f.to_dict() if hasattr(f, "to_dict") else asdict(f))
                enriched_fields.append({
                    "name": f_dict.get("name"),
                    "type": f_dict.get("type"),
                    "value": self.runtime._sanitize_field_value(f_dict),
                    "object_ref": f_dict.get("object_ref"),
                    "mutability": _is_field_mutable(f_dict.get("type", "")),
                    "address": f_dict.get("address"),
                })

            enriched_objects.append({
                "object_id": oid,
                "type": raw_type,
                "cleaned_type": cleaned_type,
                "semantic_name": semantic_name or oid,
                "root_name": root_map.get(oid, {}).get("name"),
                "root_source": root_map.get(oid, {}).get("source"),
                "storage": o_dict.get("storage", "unknown"),
                "address": o_dict.get("address"),
                "thread_id": o_dict.get("thread_id"),
                "frame_level": o_dict.get("frame_level"),
                "fields": enriched_fields,
                "identity_hint": f"{raw_type}:{oid}",
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

            snap, _ = self.runtime._resolve_snapshot(snapshot_id)
            if snap:
                snap_dict = snap.to_dict() if hasattr(snap, "to_dict") else dict(snap)
                s_inner = snap_dict.get("snapshot", snap_dict)
                persistent = snap_dict.get("persistent") or s_inner.get("persistent") or {}
                roots = persistent.get("roots", [])
                raw_objs = persistent.get("objects", [])
                root_item = next((r for r in roots if (r.get("object_ref") if isinstance(r, dict) else getattr(r, "object_ref", None)) == object_id), None)
                if not root_item and roots and raw_objs:
                    for idx, r in enumerate(roots):
                        if idx < len(raw_objs):
                            f_oid = raw_objs[idx].get("object_id") if isinstance(raw_objs[idx], dict) else getattr(raw_objs[idx], "object_id", None)
                            if f_oid == object_id:
                                root_item = r
                                break

                if root_item:
                    r_name = root_item.get("name") if isinstance(root_item, dict) else getattr(root_item, "name", None)
                    data["root_name"] = r_name
                    data["semantic_name"] = r_name
                else:
                    data["semantic_name"] = cleaned_type

                raw_obj = next((o for o in raw_objs if (o.get("object_id") if isinstance(o, dict) else getattr(o, "object_id", None)) == object_id), None)
                if raw_obj:
                    o_dict = raw_obj if isinstance(raw_obj, dict) else (raw_obj.to_dict() if hasattr(raw_obj, "to_dict") else asdict(raw_obj))
                    data["address"] = o_dict.get("address")
                    data["thread_id"] = o_dict.get("thread_id")
                    data["frame_level"] = o_dict.get("frame_level")
            else:
                data["semantic_name"] = cleaned_type

            # Enrich fields with mutability
            for f in data.get("fields", []):
                if isinstance(f, dict) and "mutability" not in f:
                    f["mutability"] = _is_field_mutable(f.get("type", ""))

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
                root_names = {}
                for idx, r in enumerate(roots):
                    r_dict = r if isinstance(r, dict) else (r.to_dict() if hasattr(r, "to_dict") else asdict(r))
                    oref = r_dict.get("object_ref")
                    rname = r_dict.get("name")
                    if oref and rname:
                        root_names[oref] = rname
                    elif idx < len(raw_objs):
                        f_oid = raw_objs[idx].get("object_id") if isinstance(raw_objs[idx], dict) else getattr(raw_objs[idx], "object_id", None)
                        if f_oid and rname and f_oid not in root_names:
                            root_names[f_oid] = rname

                obj_types = {}
                for o in raw_objs:
                    o_dict = o if isinstance(o, dict) else (o.to_dict() if hasattr(o, "to_dict") else asdict(o))
                    oid = o_dict.get("object_id")
                    otyp = o_dict.get("type")
                    if oid and otyp:
                        obj_types[oid] = _clean_type_name(otyp)

                for c in candidates:
                    oid = c.get("object_id")
                    sem_name = root_names.get(oid) or obj_types.get(oid) or oid
                    c["semantic_name"] = sem_name
                    c["semantic_target"] = f"{sem_name}.{c.get('field')}"

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
        timeout_ms = int(params.get("timeout_ms", 1000))
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

                caps_res = self.runtime.capabilities()
                caps_data = caps_res.data if caps_res.success else {}
                cp_res = caps_data.get("checkpoint_restore", {})
                data["restore_backend"] = cp_res.get("backend", "RESTART" if caps_data.get("threads", 1) > 1 else "GDB_CHECKPOINT")
                data["timeout_ms"] = timeout_ms
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

            # GET /api/snapshots/{snapshot_id}
            m_snap = re.match(r"^/api/snapshots/([^/]+)$", path)
            if m_snap:
                snapshot_id = m_snap.group(1)
                self._send_json(adapter.get_snapshot(snapshot_id))
                return

            # GET /api/mutation-candidates
            if path == "/api/mutation-candidates":
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

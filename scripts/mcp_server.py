#!/usr/bin/env python3
"""dynamicState MCP Server

Model Context Protocol (MCP) server for dynamicState runtime state exploration,
live memory capture, and C++ semantic investigation.
"""

import json
import os
import sys
from typing import Any, Dict, List, Optional, Tuple, Union

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

try:
    from mcp.server.mcpserver import MCPServer
except ImportError:
    class MCPServer:  # type: ignore[no-redef]
        def __init__(self, name: str, version: str = "1.0.0", description: str = ""):
            self.name = name
            self.version = version
            self.description = description
            self.tools = {}

        def tool(self, name: Optional[str] = None):
            def decorator(fn):
                t_name = name or fn.__name__
                self.tools[t_name] = fn
                return fn
            return decorator

        def run(self, transport: str = "stdio"):
            pass
from extractor.agent_runtime import AgentRuntime

server = MCPServer(
    name="dynamicstate",
    version="1.0.0",
    description="dynamicState runtime state exploration and live memory capture engine"
)

runtime = AgentRuntime(corpus_dir=os.path.join(PROJECT_ROOT, "corpus"))


import functools


def _validate_mcp_pid(pid: Any, allow_none: bool = True) -> Optional[int]:
    """Validates and normalizes a PID parameter for MCP tools.
    
    Compatibility Policy:
    - Rejects booleans (`True`/`False` are not valid PIDs).
    - Accepts positive integers > 1.
    - Accepts integral floats (e.g. `123.0`) and decimal strings (`"123.0"`) for JSON number interoperability.
    - Strictly rejects fractional numeric values (e.g. `123.45`, `"123.45"`).
    - Rejects negative numbers, PID 0 (when required), and PID 1 (init/systemd).
    - Strictly rejects unsupported types (list, dict, tuple, etc.).
    """
    if isinstance(pid, bool):
        raise ValueError("Invalid target PID: boolean values are not valid PIDs")
    if pid is None:
        if not allow_none:
            raise ValueError("No target PID provided and no target session bound")
        return None
    if not isinstance(pid, (int, float, str)):
        raise ValueError(f"Unsupported PID type: {type(pid).__name__}")
    if isinstance(pid, float):
        if not pid.is_integer():
            raise ValueError(f"Invalid fractional PID {pid}: PID must be an integer > 1")
        pid = int(pid)
    if isinstance(pid, str):
        s = pid.strip()
        if not s:
            if not allow_none:
                raise ValueError("No target PID provided and no target session bound")
            return None
        if "." in s:
            try:
                f_val = float(s)
                if not f_val.is_integer():
                    raise ValueError(f"Invalid fractional PID '{s}': PID must be an integer > 1")
                pid = int(f_val)
                s = str(pid)
            except ValueError as ve:
                if "fractional" in str(ve):
                    raise
                raise ValueError(f"Invalid non-numeric PID '{s}'")
        if s.startswith("-") or s == "1":
            raise ValueError(f"Invalid or reserved system PID '{s}': PID must be an integer > 1")
        if s.isdigit():
            p_int = int(s)
            if p_int <= 1:
                if p_int == 0 and allow_none:
                    return None
                raise ValueError(f"Invalid or reserved system PID {p_int}: PID must be an integer > 1")
            return p_int
        raise ValueError(f"Invalid non-numeric PID '{s}'")
    if isinstance(pid, int):
        p_int = pid
        if p_int == 1 or p_int < 0:
            raise ValueError(f"Invalid or reserved system PID {p_int}: PID must be an integer > 1 (PID 1 is reserved)")
        if p_int == 0:
            if not allow_none:
                raise ValueError("Invalid target PID 0: PID must be an integer > 1")
            return None
        return p_int
    raise ValueError(f"Unsupported PID type: {type(pid).__name__}")


def _normalize_mcp_error(err_msg: Any, explicit_code: Optional[str] = None) -> Tuple[str, Optional[str]]:
    """Normalize raw error messages and exception codes into machine-readable MCP error codes and recovery hints.
    
    Precedence & Guarantees:
    1. Preserves explicit domain error codes (`explicit_code in domain_codes`) without heuristic mutation.
    2. Fallback heuristic pattern matching only applies when code is generic (`ValueError`, `RuntimeError`, etc.) or None.
    3. Handles collisions cleanly (NO_TARGET_SPECIFIED vs INVALID_PID, BUILD_ID_MISMATCH vs DEBUG_IMAGE_NOT_FOUND, etc.).
    4. Guards against incidental substring false-positives (e.g. 'timeout_counter' does not trigger TIMEOUT).
    5. Unknown exception types remain distinguishable instead of being collapsed to misleading domain codes.
    
    Returns:
        (error_code, recovery_hint)
    """
    domain_codes = {
        "NO_TARGET_SPECIFIED",
        "INVALID_PID",
        "BUILD_ID_MISMATCH",
        "DEBUG_IMAGE_NOT_FOUND",
        "MISSING_DWARF",
        "SESSION_NOT_FOUND",
        "SNAPSHOT_NOT_FOUND",
        "OBJECT_NOT_FOUND",
        "PROCESS_EXITED",
        "PERMISSION_DENIED",
        "PARTIAL_BATCH_FAILURE",
        "ALL_STEPS_FAILED",
        "UNSUPPORTED_CAPABILITY",
        "TIMEOUT",
    }

    hints_by_code = {
        "NO_TARGET_SPECIFIED": "Bind a target first via `runtime_target_connect(pid=...)` or provide `pid` explicitly.",
        "INVALID_PID": "Specify a valid positive integer PID greater than 1.",
        "BUILD_ID_MISMATCH": "Provide the companion ELF binary matching the target's exact Build ID.",
        "DEBUG_IMAGE_NOT_FOUND": "Verify that companion_elf path exists and contains unstripped DWARF (.debug_info) debug symbols.",
        "MISSING_DWARF": "Verify that companion_elf path exists and contains unstripped DWARF (.debug_info) debug symbols.",
        "SESSION_NOT_FOUND": "Query active sessions via `runtime_watch_session_list` or create one via `runtime_watch_session_create`.",
        "SNAPSHOT_NOT_FOUND": "Capture a fresh memory snapshot via `runtime_capture_memory` before querying snapshot objects.",
        "OBJECT_NOT_FOUND": "List available object identifiers via `runtime_list_objects`.",
        "PROCESS_EXITED": "The target process has terminated. Verify if it restarted or bind a new PID via `runtime_target_connect`.",
        "PERMISSION_DENIED": "Check process ownership or ensure Yama ptrace_scope (/proc/sys/kernel/yama/ptrace_scope) allows memory inspection.",
        "PARTIAL_BATCH_FAILURE": "Review failed steps in 'step_results' to diagnose individual action failures.",
        "ALL_STEPS_FAILED": "Check target process liveness and parameters for all batch steps.",
        "UNSUPPORTED_CAPABILITY": "Check supported capabilities via `runtime_get_capabilities`.",
        "TIMEOUT": "Retry with a larger timeout or check if the target process is responsive.",
    }

    # Rule 1: Always preserve explicit domain error codes
    if explicit_code and explicit_code in domain_codes:
        return explicit_code, hints_by_code.get(explicit_code)

    msg = str(err_msg or "").strip()
    msg_lower = msg.lower()
    code: Optional[str] = None

    # Rule 2: Message-based heuristic classification
    if any(k in msg_lower for k in (
        "no target pid",
        "target pid is required",
        "target pid could not be resolved",
        "no target session bound",
        "bind a target first",
        "target process pid is required",
        "no investigation target provided",
        "no target specified",
    )):
        code = "NO_TARGET_SPECIFIED"
    elif any(k in msg_lower for k in (
        "invalid target pid",
        "boolean values are not valid",
        "boolean value is not a valid",
        "fractional pid",
        "reserved system pid",
        "pid must be an integer",
        "non-numeric target pid",
        "unsupported pid type",
        "unsupported target pid type",
        "invalid non-numeric pid",
    )):
        code = "INVALID_PID"
    elif ("build-id" in msg_lower or "build_id" in msg_lower or "build id" in msg_lower) and (
        "mismatch" in msg_lower or "differ" in msg_lower or "rejected" in msg_lower
    ):
        code = "BUILD_ID_MISMATCH"
    elif any(k in msg_lower for k in (
        "companion elf with dwarf debug info could not be resolved",
        "debug image not found",
        "cannot find elf",
        "missing dwarf",
        "no such file or directory",
    )) or ("companion elf" in msg_lower and "not found" in msg_lower):
        code = "DEBUG_IMAGE_NOT_FOUND"
    elif (
        ("session" in msg_lower and ("not found" in msg_lower or "does not exist" in msg_lower or "unknown" in msg_lower))
        or "no watch session" in msg_lower
    ):
        code = "SESSION_NOT_FOUND"
    elif (
        ("snapshot" in msg_lower and ("not found" in msg_lower or "does not exist" in msg_lower or "unknown" in msg_lower))
        or "no active snapshot" in msg_lower
    ):
        code = "SNAPSHOT_NOT_FOUND"
    elif ("object" in msg_lower and ("not found" in msg_lower or "does not exist" in msg_lower or "unknown" in msg_lower)):
        code = "OBJECT_NOT_FOUND"
    elif any(k in msg_lower for k in ("target process dead", "no such process", "esrch", "process terminated")) or (
        "process" in msg_lower and ("exited" in msg_lower or "terminated" in msg_lower)
    ):
        code = "PROCESS_EXITED"
    elif any(k in msg_lower for k in ("permission denied", "operation not permitted", "eperm", "ptrace_scope")):
        code = "PERMISSION_DENIED"
    elif any(k in msg_lower for k in ("unsupported batch action", "unsupported capability", "capability not supported")):
        code = "UNSUPPORTED_CAPABILITY"
    elif any(k in msg_lower for k in ("timed out", "timeout expired", "operation timed out", "connection timed out")) or msg_lower == "timeout":
        code = "TIMEOUT"
    elif "all batch step(s) failed" in msg_lower or "all batch steps failed" in msg_lower:
        code = "ALL_STEPS_FAILED"
    elif "batch step(s) failed" in msg_lower:
        code = "PARTIAL_BATCH_FAILURE"
    else:
        code = explicit_code or "ERROR"

    hint = hints_by_code.get(code)
    return code, hint


def _format_mcp_payload(res: Any) -> str:
    """Format MCP tool or watch session result into clean JSON string with safe copy and standardized error contracts.
    
    Guarantees:
    - Never mutates caller-owned dictionaries (operates on shallow copy).
    - Conforms to standard error envelope: success, error, error_code, error_message, recovery_hint.
    - Never reclassifies success responses as errors.
    - Does not fabricate error messages when none exist.
    """
    if hasattr(res, "to_dict"):
        data = res.to_dict()
    elif isinstance(res, dict):
        data = dict(res)  # Shallow copy to avoid mutating caller-owned dictionaries
    else:
        data = {"result": str(res)}

    # Determine failure state without reclassifying successful responses
    is_failure = False
    if "success" in data:
        is_failure = (data["success"] is False)
    elif "error" in data or "error_code" in data:
        is_failure = True
        data["success"] = False

    if is_failure:
        err = data.get("error")
        err_msg = ""
        if isinstance(err, dict):
            if "error_code" not in data and "code" in err:
                data["error_code"] = err["code"]
            if "error_message" not in data and "message" in err:
                data["error_message"] = err["message"]
            err_msg = str(data.get("error_message") or err.get("message") or "")
        elif isinstance(err, str):
            err_msg = err
            if "error_message" not in data:
                data["error_message"] = err
        elif "error_message" in data and isinstance(data["error_message"], str):
            err_msg = data["error_message"]
            if "error" not in data:
                data["error"] = err_msg

        code, hint = _normalize_mcp_error(err_msg, data.get("error_code"))
        data["error_code"] = code
        if hint and "recovery_hint" not in data:
            data["recovery_hint"] = hint

    return json.dumps(data, indent=2, ensure_ascii=False, default=str)


def _format_result(res: Any) -> str:
    """Format AgentActionResult into a clean JSON string with standardized error contracts."""
    return _format_mcp_payload(res)


def _format_watch_result(data: Any) -> str:
    """Format Watch Session result into clean JSON string with standardized error contracts."""
    return _format_mcp_payload(data)


@server.tool()
def runtime_capture_memory(
    pid: Optional[int] = None,
    policy: str = "ALL_READABLE",
    max_bytes: int = 33554432,
    timeout_ms: int = 2000
) -> str:
    """Capture raw memory of a live running Linux process non-intrusively via process_vm_readv.
    
    If `pid` is omitted, inherits from the active target bound via `runtime_target_connect`.
    
    Args:
        pid: Optional target process PID (if omitted, uses bound target session).
        policy: Region filter policy (ALL_READABLE, STACK, HEAP, GLOBAL, etc.).
        max_bytes: Maximum total bytes to capture (default: 32MB).
        timeout_ms: Timeout in milliseconds.
    """
    try:
        if pid is None:
            try:
                _c = _resolve_mcp_target(pid=pid)
                pid = _c.get("pid")
            except Exception:
                pass
        valid_pid = _validate_mcp_pid(pid, allow_none=False)
        res = runtime.dispatch_action({
            "action": "MEMORY_SNAPSHOT",
            "pid": valid_pid,
            "policy": policy,
            "max_bytes": max(4096, min(int(max_bytes or 33554432), 134217728)),
            "timeout_ms": max(50, min(int(timeout_ms or 2000), 30000)),
        })
        return _format_result(res)
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_observe(
    pid: Optional[int] = None,
    debug_image: Optional[str] = None,
    mode: str = "LOW_IMPACT"
) -> str:
    """Observe active execution state, threads, and root objects from a running process or stopped inferior.
    
    If `pid` or `debug_image` is omitted, inherits from the active target bound via `runtime_target_connect`.
    
    Args:
        pid: Optional live process PID (if omitted, uses bound target session).
        debug_image: Optional path to external debug ELF binary with DWARF symbols (if omitted, uses bound target session).
        mode: Observation mode ('LOW_IMPACT' for non-stop live capture, 'CONSISTENT' for stopped execution).
    """
    try:
        if pid is None or debug_image is None:
            try:
                _c = _resolve_mcp_target(pid=pid, companion_elf=debug_image)
                pid = pid if pid is not None else _c.get("pid")
                debug_image = debug_image or _c.get("companion_elf_path")
            except Exception:
                pass
        valid_pid = _validate_mcp_pid(pid, allow_none=True)
        res = runtime.dispatch_action({
            "action": "OBSERVE",
            "pid": valid_pid,
            "debug_image": debug_image,
            "mode": mode
        })
        return _format_result(res)
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_list_objects(snapshot_id: Optional[str] = None) -> str:
    """List all reachable semantic objects discovered in the active or specified snapshot.
    
    Args:
        snapshot_id: Optional snapshot identifier.
    """
    try:
        res = runtime.dispatch_action({
            "action": "LIST_OBJECTS",
            "snapshot_id": snapshot_id
        })
        return _format_result(res)
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_inspect_object(object_id: str, snapshot_id: Optional[str] = None) -> str:
    """Inspect field values, types, and pointer references of a specific semantic object.
    
    Args:
        object_id: Object identifier (e.g. 'obj_0001').
        snapshot_id: Optional snapshot identifier.
    """
    try:
        res = runtime.dispatch_action({
            "action": "INSPECT_OBJECT",
            "object_id": object_id,
            "snapshot_id": snapshot_id
        })
        return _format_result(res)
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_inspect_field(
    object_id: str,
    field_path: str,
    snapshot_id: Optional[str] = None
) -> str:
    """Inspect a single field's type, current decoded value, and mutability.
    
    Args:
        object_id: Object identifier.
        field_path: Dot-separated field path (e.g. 'worker.state.counter').
        snapshot_id: Optional snapshot identifier.
    """
    try:
        res = runtime.dispatch_action({
            "action": "INSPECT_FIELD",
            "object_id": object_id,
            "field_path": field_path,
            "snapshot_id": snapshot_id
        })
        return _format_result(res)
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_start_investigation(
    goal: str,
    pid: Optional[int] = None,
    debug_image: Optional[str] = None,
    memory_snapshot_path: Optional[str] = None,
    watch_session_id: Optional[str] = None,
    observation_window: Optional[Dict[str, Any]] = None,
) -> str:
    """Launch an evidence-first investigation session against a live PID, offline snapshot, or persistent watch session.
    
    If target parameters are omitted, inherits from the active target bound via `runtime_target_connect`.
    
    Args:
        goal: Natural language investigation goal (e.g. 'Investigate worker counter mismatch' or Korean equivalent).
        pid: Target process PID for live capture (if omitted, uses bound target session).
        debug_image: Path to external debug ELF binary with DWARF symbols (if omitted, uses bound session).
        memory_snapshot_path: Path to offline raw memory snapshot directory.
        watch_session_id: Optional persistent watch session ID (e.g. from runtime_watch_session_create).
        observation_window: Optional dict with start_seq, end_seq, duration_sec, guard_address, etc.
    """
    try:
        if pid is None and debug_image is None and not memory_snapshot_path and not watch_session_id:
            try:
                _c = _resolve_mcp_target(pid=pid, companion_elf=debug_image)
                pid = _c.get("pid")
                debug_image = _c.get("companion_elf_path")
            except Exception:
                pass
        valid_pid = _validate_mcp_pid(pid, allow_none=True)
        if valid_pid is None and not memory_snapshot_path and not watch_session_id:
            return _format_watch_result({
                "success": False,
                "error": "No investigation target provided. Specify 'pid', 'memory_snapshot_path', 'watch_session_id', or bind a target first via 'runtime_target_connect'.",
                "error_code": "NO_TARGET_SPECIFIED",
                "recovery_hint": "Call runtime_target_connect(pid=..., companion_elf=...) or provide 'pid' to runtime_start_investigation."
            })
        res = runtime.dispatch_action({
            "action": "START_INVESTIGATION",
            "goal": goal,
            "pid": valid_pid,
            "debug_image": debug_image,
            "memory_snapshot_path": memory_snapshot_path,
            "watch_session_id": watch_session_id,
            "observation_window": observation_window,
            "authorize_target": True
        })
        return _format_result(res)
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_get_investigation_report(investigation_id: str) -> str:
    """Retrieve full synthesis report, verified evidence, and causal findings for an investigation.
    
    Args:
        investigation_id: Investigation session ID (e.g. 'inv_...').
    """
    try:
        res = runtime.dispatch_action({
            "action": "GET_INVESTIGATION_REPORT",
            "investigation_id": investigation_id
        })
        return _format_result(res)
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_checkpoint(checkpoint_id: Optional[str] = None) -> str:
    """Create a branch-safe execution savepoint.
    
    Args:
        checkpoint_id: Optional identifier for checkpoint (e.g. 'C_SEED').
    """
    try:
        res = runtime.dispatch_action({
            "action": "CHECKPOINT",
            "checkpoint_id": checkpoint_id
        })
        return _format_result(res)
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_restore(checkpoint_id: str) -> str:
    """Rollback execution state to a previously saved checkpoint.
    
    Args:
        checkpoint_id: Checkpoint identifier to restore.
    """
    try:
        res = runtime.dispatch_action({
            "action": "RESTORE",
            "checkpoint_id": checkpoint_id
        })
        return _format_result(res)
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_list_candidates(snapshot_id: Optional[str] = None) -> str:
    """Discover and rank type-safe mutation hypotheses for the current state.
    
    Args:
        snapshot_id: Optional snapshot identifier.
    """
    try:
        res = runtime.dispatch_action({
            "action": "LIST_MUTATION_CANDIDATES",
            "snapshot_id": snapshot_id
        })
        return _format_result(res)
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_execute_transition(candidate_id: str, timeout_ms: int = 1000) -> str:
    """Apply a mutation candidate, resume execution, and return semantic transition facts and diff.
    
    Args:
        candidate_id: Identifier of the mutation candidate (e.g. 'M0001').
        timeout_ms: Execution timeout in milliseconds.
    """
    try:
        res = runtime.dispatch_action({
            "action": "EXECUTE_TRANSITION",
            "candidate_id": candidate_id,
            "timeout_ms": max(50, min(int(timeout_ms or 1000), 30000)),
        })
        return _format_result(res)
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_get_capabilities() -> str:
    """Query runtime platform capabilities, supported observation backends, and safety limits."""
    try:
        res = runtime.dispatch_action({
            "action": "GET_CAPABILITIES"
        })
        return _format_result(res)
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


# -----------------------------------------------------------------------------
# Phase 23: Watch Session and Temporal Explorer MCP Tools
# -----------------------------------------------------------------------------


@server.tool()
def runtime_watch_session_create(
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    interval_ms: int = 500,
    max_samples: int = 1000,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    watch_items: Optional[List[Dict[str, Any]]] = None,
    capture_mode: str = "ZERO_STOP",
) -> str:
    """Create and start a persistent observation session for a local or remote target.
    
    If `pid` or `companion_elf` is omitted, inherits from the active target bound via `runtime_target_connect`.
    
    Args:
        pid: Optional target process PID (if omitted, uses bound target session).
        companion_elf: Local path to non-stripped companion ELF with DWARF symbols (if omitted, uses bound session).
        interval_ms: Sampling interval in milliseconds (default: 500ms, clamped 50..60000).
        max_samples: Maximum observations to capture before stopping (default: 1000).
        remote_host: Optional SSH remote host/IP for embedded target observation.
        ssh_user: Optional SSH username.
        ssh_port: SSH port (default: 22).
        ssh_key: Optional path to SSH private key.
        ssh_proxy_jump: Optional SSH jump host / proxy chain (e.g. 'jump.example.com').
        watch_items: Optional initial list of watch items [{'name', 'address', 'size', 'type_name'}].
        capture_mode: Capture mode ('ZERO_STOP' default).
    """
    try:
        if pid is None or companion_elf is None:
            try:
                _c = _resolve_mcp_target(pid=pid, companion_elf=companion_elf, remote_host=remote_host, ssh_user=ssh_user, ssh_port=ssh_port, ssh_key=ssh_key, ssh_proxy_jump=ssh_proxy_jump)
                pid = pid if pid is not None else _c.get("pid")
                companion_elf = companion_elf or _c.get("companion_elf_path")
            except Exception:
                pass
        pid = _validate_mcp_pid(pid, allow_none=False)
        session = runtime.watch_session_manager.create_session(
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
        return _format_watch_result({
            "success": True,
            "session_id": session.session_id,
            "status": session.status,
            "pid": session.pid,
            "target_host": session.provenance.get("host", "localhost"),
            "is_remote": session.provenance.get("is_remote", False),
            "watch_items_count": len(session.watch_items),
            "binary_build_id": session.binary_build_id,
            "configuration": session.configuration,
            "capabilities": session.capabilities,
        })
    except Exception as e:
        return _format_watch_result({
            "success": False,
            "error": str(e),
            "error_code": type(e).__name__,
        })


@server.tool()
def runtime_watch_session_status(session_id: str) -> str:
    """Get fast compact status of a watch session without loading full observation history.
    
    Args:
        session_id: Target session identifier.
    """
    try:
        st = runtime.watch_session_manager.get_session_status(session_id)
        if not st.get("found"):
            return _format_watch_result({"success": False, "error": f"Session '{session_id}' not found", "error_code": "SESSION_NOT_FOUND"})
        return _format_watch_result({"success": True, **st})
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_watch_session_get(session_id: str) -> str:
    """Retrieve full configuration, provenance, capabilities, and watch items for a session.
    
    Args:
        session_id: Target session identifier.
    """
    try:
        session = runtime.watch_session_manager.get_session(session_id)
        if not session:
            return _format_watch_result({"success": False, "error": f"Session '{session_id}' not found", "error_code": "SESSION_NOT_FOUND"})
        return _format_watch_result({
            "success": True,
            **session.to_dict(include_observations=False),
        })
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_watch_session_list(include_stopped: bool = True) -> str:
    """List metadata summaries of active and persisted watch sessions.
    
    Args:
        include_stopped: If True, include completed/stopped sessions (default: True).
    """
    try:
        sessions = runtime.watch_session_manager.list_sessions(include_stopped=include_stopped)
        return _format_watch_result({
            "success": True,
            "total_sessions": len(sessions),
            "sessions": sessions,
        })
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_watch_inspect_target(
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """Inspect memory mappings, threads, and discoverable variables for a local or remote target.
    
    If `pid` or `companion_elf` is omitted, inherits from the active target bound via `runtime_target_connect`.
    
    Args:
        pid: Optional target process PID (if omitted, uses bound target session).
        companion_elf: Local path to non-stripped companion ELF with DWARF symbols (if omitted, uses bound session).
        remote_host: Optional SSH remote host/IP.
        ssh_user: Optional SSH username.
        ssh_port: SSH port (default: 22).
        ssh_key: Optional path to SSH private key.
        ssh_proxy_jump: Optional SSH jump host.
    """
    try:
        if pid is None or companion_elf is None:
            try:
                _c = _resolve_mcp_target(pid=pid, companion_elf=companion_elf, remote_host=remote_host, ssh_user=ssh_user, ssh_port=ssh_port, ssh_key=ssh_key, ssh_proxy_jump=ssh_proxy_jump)
                pid = pid if pid is not None else _c.get("pid")
                companion_elf = companion_elf or _c.get("companion_elf_path")
            except Exception:
                pass
        pid = _validate_mcp_pid(pid, allow_none=False)
        data = runtime.watch_session_manager.get_memory_map_and_threads(
            pid=pid,
            companion_elf_path=companion_elf,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
        )
        return _format_watch_result({
            "success": True,
            "pid": data["pid"],
            "target_host": data.get("target_host", "localhost"),
            "is_remote": data.get("is_remote", False),
            "base_address": data.get("base_address", "0x0"),
            "load_bias": data.get("load_bias", "0x0"),
            "load_bias_ambiguous": data.get("load_bias_ambiguous", False),
            "mappings_count": len(data.get("mappings", [])),
            "threads_count": len(data.get("threads", [])),
            "discoverable_variables_count": len(data.get("discoverable_variables", [])),
            "mappings": data.get("mappings", []),
            "threads": data.get("threads", []),
            "discoverable_variables": data.get("discoverable_variables", []),
        })
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_watch_item_add(
    session_id: str,
    name: str,
    address: Union[int, str],
    size: int = 4,
    type_name: str = "raw_bytes",
    scope: str = "global",
    source_location: Optional[str] = None,
    expression: Optional[str] = None,
) -> str:
    """Add a variable or memory address range to a watch session's observation list.
    
    Args:
        session_id: Active session identifier.
        name: Identifier or variable name.
        address: Runtime virtual memory address (int or hex string e.g. '0x5555...').
        size: Bytes to sample (1..65536, default: 4).
        type_name: Data type for decoding (int, uint, float, double, pointer, string, raw_bytes).
        scope: Scope category (global, heap, thread, object).
        source_location: Optional file:line source reference.
        expression: Optional high-level expression.
    """
    try:
        item = runtime.watch_session_manager.add_watch_item(session_id, {
            "name": name,
            "address": address,
            "size": size,
            "type_name": type_name,
            "scope": scope,
            "source_location": source_location,
            "expression": expression,
        })
        return _format_watch_result({
            "success": True,
            "session_id": session_id,
            "watch_item": item.to_dict(),
        })
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_watch_item_remove(session_id: str, item_id: str) -> str:
    """Remove an item from the watch list while preserving recorded observation history.
    
    Args:
        session_id: Session identifier.
        item_id: Watch item ID to remove.
    """
    try:
        removed = runtime.watch_session_manager.remove_watch_item(session_id, item_id)
        if not removed:
            return _format_watch_result({"success": False, "error": f"Item '{item_id}' not found in session '{session_id}'", "error_code": "ITEM_NOT_FOUND"})
        return _format_watch_result({
            "success": True,
            "session_id": session_id,
            "removed_item_id": item_id,
        })
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_watch_session_observations(
    session_id: str,
    start_seq: Optional[int] = None,
    end_seq: Optional[int] = None,
    limit: int = 50,
    offset: int = 0,
) -> str:
    """Retrieve paginated recorded observations and sampling gaps for a session.
    
    Args:
        session_id: Session identifier.
        start_seq: Optional lower bound sequence number (inclusive).
        end_seq: Optional upper bound sequence number (inclusive).
        limit: Maximum observations to return per page (default: 50, max: 500).
        offset: Pagination offset (default: 0).
    """
    try:
        clamped_limit = max(1, min(limit, 500))
        data = runtime.watch_session_manager.get_observations(
            session_id=session_id,
            start_seq=start_seq,
            end_seq=end_seq,
            limit=clamped_limit,
            offset=max(0, offset),
        )
        return _format_watch_result({
            "success": True,
            **data,
        })
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_watch_session_stop(session_id: str) -> str:
    """Stop active sampling for a watch session and persist final state.
    
    Args:
        session_id: Session identifier to stop.
    """
    try:
        stopped = runtime.watch_session_manager.stop_session(session_id)
        if not stopped:
            return _format_watch_result({"success": False, "error": f"Session '{session_id}' not found", "error_code": "SESSION_NOT_FOUND"})
        return _format_watch_result({
            "success": True,
            "session_id": stopped.session_id,
            "status": stopped.status,
            "end_time": stopped.end_time,
            "total_observations": stopped.total_observations or len(stopped.observations),
        })
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


# -----------------------------------------------------------------------------
# Phase 32 & Phase 48 (Phase 18): High-Level Intent-Driven MCP Tools with
# Stateful Target Context, Auto-Heal PID, and Zero-Path ELF Discovery
# -----------------------------------------------------------------------------

def _resolve_mcp_target(
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    process_name: Optional[str] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> Dict[str, Any]:
    return runtime.watch_session_manager.resolve_target_context(
        pid=pid,
        companion_elf_path=companion_elf,
        process_name=process_name,
        remote_host=remote_host,
        ssh_user=ssh_user,
        ssh_port=ssh_port,
        ssh_key=ssh_key,
        ssh_proxy_jump=ssh_proxy_jump,
    )


@server.tool()
def runtime_target_connect(
    companion_elf: Optional[str] = None,
    pid: Optional[int] = None,
    process_name: Optional[str] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    auto_deploy_collector: bool = False,
) -> str:
    """Connect to a local or remote embedded target process by PID or process name,
    verify GNU Build ID against the host's non-stripped companion ELF, calculate ASLR load bias,
    and return top recommended state variables to inspect.

    Args:
        companion_elf: Local path on host to non-stripped ELF binary with DWARF symbols.
        pid: Optional numeric PID on target host (if omitted, resolved via process_name).
        process_name: Optional process/daemon name on target host (e.g. 'sensor_daemon').
        remote_host: Optional SSH hostname/IP of embedded device.
        ssh_user: Optional SSH username.
        ssh_port: SSH port (default: 22).
        ssh_key: Optional SSH private key path.
        ssh_proxy_jump: Optional SSH jump host.
    """
    try:
        from extractor.debug_image import inspect_elf
        from extractor.dwarf_indexer import DwarfIndexer

        if pid is not None:
            pid = _validate_mcp_pid(pid, allow_none=True)

        elf_auto_discovered = False
        elf_discovery_source = None
        if not companion_elf and (pid or process_name):
            try:
                ctx_auto = runtime.watch_session_manager.resolve_target_context(
                    pid=pid,
                    companion_elf_path=None,
                    process_name=process_name,
                    remote_host=remote_host,
                    ssh_user=ssh_user,
                    ssh_port=ssh_port,
                    ssh_key=ssh_key,
                    ssh_proxy_jump=ssh_proxy_jump,
                )
                pid = ctx_auto["pid"]
                companion_elf = ctx_auto["companion_elf_path"]
                elf_auto_discovered = ctx_auto.get("elf_auto_discovered", False)
                elf_discovery_source = ctx_auto.get("elf_discovery_source")
            except Exception:
                pass

        if not companion_elf or not os.path.isfile(companion_elf):
            return _format_watch_result({
                "success": False,
                "error": f"Companion ELF not found: '{companion_elf}'",
                "error_code": "DEBUG_IMAGE_NOT_FOUND",
            })

        dbg_ident = inspect_elf(companion_elf)
        if not dbg_ident.has_debug_info:
            return _format_watch_result({
                "success": False,
                "error": f"Companion ELF '{companion_elf}' has no DWARF debug info (.debug_info missing)",
                "error_code": "MISSING_DWARF",
            })

        adapter = runtime.watch_session_manager._resolve_adapter(
            pid=pid or 1,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
        )

        resolved_pid = pid
        matched_procs = []
        if (resolved_pid is None or resolved_pid <= 0) and process_name:
            matched_procs = adapter.find_processes(
                process_name=process_name,
                companion_build_id=dbg_ident.build_id,
                limit=10,
            )
            if not matched_procs:
                return _format_watch_result({
                    "success": False,
                    "error": f"No running process matching '{process_name}' found on {adapter.target_host()}",
                    "error_code": "PROCESS_NOT_FOUND",
                })
            resolved_pid = int(matched_procs[0]["pid"])

        if not resolved_pid or resolved_pid <= 0:
            return _format_watch_result({
                "success": False,
                "error": "Provide either 'pid' or 'process_name' to identify the target process",
                "error_code": "INVALID_TARGET",
            })

        map_data = runtime.watch_session_manager.get_memory_map_and_threads(
            pid=resolved_pid,
            companion_elf_path=companion_elf,
            adapter=adapter,
        )
        load_bias_int = map_data.get("base_address_int", 0)
        idx = DwarfIndexer.get_index(companion_elf)
        recommended = idx.search_symbols(
            query="",
            category="variables",
            limit=15,
            smart_rank=True,
            load_bias=load_bias_int,
            is_dyn=(idx.elf_type == "ET_DYN"),
        )

        collector_info = None
        if auto_deploy_collector and hasattr(adapter, "ensure_remote_collector"):
            collector_info = adapter.ensure_remote_collector()

        bound_ctx = runtime.watch_session_manager.bind_target_context(
            pid=resolved_pid,
            companion_elf_path=companion_elf,
            process_name=process_name or os.path.basename(companion_elf),
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
            adapter=adapter,
        )
        return _format_watch_result({
            "success": True,
            "pid": resolved_pid,
            "elf_auto_discovered": elf_auto_discovered,
            "elf_discovery_source": elf_discovery_source,
            "active_context_bound": True,
            "active_context": bound_ctx,
            "collector_deployment": collector_info,
            "target_host": adapter.target_host(),
            "is_remote": adapter.is_remote(),
            "companion_elf": os.path.abspath(companion_elf),
            "build_id": dbg_ident.build_id,
            "architecture": dbg_ident.architecture,
            "load_bias": map_data.get("load_bias", "0x0"),
            "threads_count": len(map_data.get("threads", [])),
            "threads": map_data.get("threads", []),
            "matched_processes": matched_procs[:5] if matched_procs else None,
            "recommended_symbols": recommended,
        })
    except Exception as e:
        return _format_watch_result({
            "success": False,
            "error": str(e),
            "error_code": type(e).__name__,
        })


@server.tool()
def runtime_symbol_search(
    companion_elf: Optional[str] = None,
    query: str = "",
    category: str = "all",
    limit: int = 30,
    pid: Optional[int] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    fast_only: bool = False,
) -> str:
    """Search DWARF global/static variables, struct definitions, and enums by keyword with smart state ranking.

    Args:
        companion_elf: Path to non-stripped companion ELF binary.
        query: Optional keyword filter (e.g. 'state', 'queue', 'session', 'counter'). Empty returns top-ranked state symbols.
        category: Filter category ('all', 'variables', 'types', 'structs', 'enums').
        limit: Max results to return (default: 30).
        pid: Optional target PID to compute relocated runtime addresses.
        remote_host: Optional SSH remote host.
    """
    try:
        from extractor.dwarf_indexer import DwarfIndexer
        if not companion_elf or not pid:
            try:
                c_info = _resolve_mcp_target(pid=pid, companion_elf=companion_elf, remote_host=remote_host, ssh_user=ssh_user, ssh_port=ssh_port, ssh_key=ssh_key, ssh_proxy_jump=ssh_proxy_jump)
                pid = pid or c_info["pid"]
                companion_elf = companion_elf or c_info["companion_elf_path"]
            except Exception:
                pass
        if not companion_elf or not os.path.isfile(companion_elf):
            return _format_watch_result({"success": False, "error": f"Companion ELF not found: '{companion_elf}'", "error_code": "DEBUG_IMAGE_NOT_FOUND"})

        load_bias_int = 0
        if pid and pid > 0:
            try:
                map_data = runtime.watch_session_manager.get_memory_map_and_threads(
                    pid=pid,
                    companion_elf_path=companion_elf,
                    remote_host=remote_host,
                    ssh_user=ssh_user,
                    ssh_port=ssh_port,
                    ssh_key=ssh_key,
                    ssh_proxy_jump=ssh_proxy_jump,
                )
                load_bias_int = map_data.get("base_address_int", 0)
            except Exception:
                load_bias_int = 0

        if fast_only:
            fast_syms = DwarfIndexer.get_fast_symbol_table(companion_elf, load_bias=load_bias_int)
            q_low = (query or "").strip().lower()
            if q_low:
                fast_syms = [s for s in fast_syms if q_low in s["name"].lower()]
            fast_syms = fast_syms[:max(1, min(int(limit), 200))]
            return _format_watch_result({
                "success": True,
                "companion_elf": os.path.abspath(companion_elf),
                "query": query,
                "mode": "fast_symtab",
                "returned_count": len(fast_syms),
                "symbols": fast_syms,
            })

        idx = DwarfIndexer.get_index(companion_elf)

        results = idx.search_symbols(
            query=query,
            category=category,
            limit=max(1, min(int(limit), 200)),
            smart_rank=True,
            load_bias=load_bias_int,
            is_dyn=(idx.elf_type == "ET_DYN"),
        )
        return _format_watch_result({
            "success": True,
            "companion_elf": os.path.abspath(companion_elf),
            "query": query,
            "category": category,
            "returned_count": len(results),
            "symbols": results,
        })
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_eval_memory_path(
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    expressions: Optional[List[str]] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """Evaluate C/C++ symbol path expressions (including structs, pointer dereferences `->`, and array indices `[i]`)
    directly from live local or remote embedded target memory with 0.00ms process stop time.

    Examples of expressions:
      - "g_session" (decodes entire struct hierarchy)
      - "g_session.worker.state.counter"
      - "g_heap_state->value"
      - "g_node_a.next->id"

    Args:
        pid: Target process PID.
        companion_elf: Path to non-stripped companion ELF with DWARF symbols.
        expressions: List of C/C++ symbol path expressions to evaluate.
        remote_host: Optional SSH remote host for embedded device.
        ssh_user: Optional SSH username.
        ssh_port: SSH port (default: 22).
        ssh_key: Optional SSH private key path.
        ssh_proxy_jump: Optional SSH jump host.
    """
    try:
        data = runtime.watch_session_manager.evaluate_symbol_paths(
            pid=pid,
            companion_elf_path=companion_elf,
            expressions=expressions,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
        )
        return _format_watch_result({"success": True, **data})
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_capture_and_diff(
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    expressions: Optional[List[str]] = None,
    wait_ms: int = 500,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """Sample C/C++ symbol expressions twice separated by `wait_ms` (without stopping the process)
    and return a diff of fields that changed vs. fields that remained stuck/unchanged.

    Args:
        pid: Target process PID.
        companion_elf: Path to non-stripped companion ELF with DWARF symbols.
        expressions: Optional list of symbol expressions (if omitted, auto-selects top state globals).
        wait_ms: Interval in milliseconds between snapshot A and snapshot B (default: 500ms).
        remote_host: Optional SSH remote host for embedded device.
        ssh_user: Optional SSH username.
        ssh_port: SSH port (default: 22).
        ssh_key: Optional SSH private key path.
        ssh_proxy_jump: Optional SSH jump host.
    """
    try:
        data = runtime.watch_session_manager.capture_and_diff_expressions(
            pid=pid,
            companion_elf_path=companion_elf,
            expressions=expressions,
            wait_ms=wait_ms,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
        )
        return _format_watch_result({"success": True, **data})
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_run_diagnostic_recipe(
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    recipe: str = "instant_xray",
    expressions: Optional[List[str]] = None,
    duration_ms: int = 1000,
    interval_ms: int = 200,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """Run a guided embedded diagnostic recipe in a single call:
    - 'instant_xray': Decode top state globals and heap pointer targets immediately (Silent Hang triage).
    - 'before_after_diff': Sample twice across `duration_ms` and report mutated vs unchanged fields.
    - 'timeseries_watch': Sample periodically over `duration_ms` and classify active vs stuck variables.
    """
    try:
        if pid is None or companion_elf is None or runtime.watch_session_manager.get_active_target_context().get('pid') == pid:
            _ctx = _resolve_mcp_target(pid=pid, companion_elf=companion_elf, remote_host=remote_host, ssh_user=ssh_user, ssh_port=ssh_port, ssh_key=ssh_key, ssh_proxy_jump=ssh_proxy_jump)
            pid = _ctx['pid']
            companion_elf = _ctx['companion_elf_path']
        res = runtime.watch_session_manager.run_diagnostic_recipe(
            recipe=recipe,
            pid=pid,
            companion_elf_path=companion_elf,
            expressions=expressions,
            duration_ms=duration_ms,
            interval_ms=interval_ms,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
        )
        return _format_watch_result({"success": True, **res})
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_golden_baseline_save(
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    label: str = "Golden Baseline",
    expressions: Optional[List[str]] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """Save the current healthy runtime state of a process as a persistent Golden Baseline for future comparison."""
    try:
        if pid is None or companion_elf is None or runtime.watch_session_manager.get_active_target_context().get('pid') == pid:
            _ctx = _resolve_mcp_target(pid=pid, companion_elf=companion_elf, remote_host=remote_host, ssh_user=ssh_user, ssh_port=ssh_port, ssh_key=ssh_key, ssh_proxy_jump=ssh_proxy_jump)
            pid = _ctx['pid']
            companion_elf = _ctx['companion_elf_path']
        rec = runtime.watch_session_manager.save_golden_baseline(
            pid=pid,
            companion_elf_path=companion_elf,
            label=label,
            expressions=expressions,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
        )
        return _format_watch_result({"success": True, **rec})
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_golden_baseline_compare(
    baseline_id: str = "",
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """Compare a currently running local or remote embedded process against a saved Golden Baseline."""
    try:
        if pid is None or companion_elf is None or runtime.watch_session_manager.get_active_target_context().get('pid') == pid:
            _ctx = _resolve_mcp_target(pid=pid, companion_elf=companion_elf, remote_host=remote_host, ssh_user=ssh_user, ssh_port=ssh_port, ssh_key=ssh_key, ssh_proxy_jump=ssh_proxy_jump)
            pid = _ctx['pid']
            companion_elf = _ctx['companion_elf_path']
        res = runtime.watch_session_manager.compare_with_golden_baseline(
            baseline_id=baseline_id,
            pid=pid,
            companion_elf_path=companion_elf,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
        )
        return _format_watch_result({"success": True, **res})
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_get_xray_blueprint(
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """Generate a 1-call Process X-Ray Blueprint categorizing DWARF globals into Memory Pools/Buffers,
    Thread/Worker Contexts, State Machines, Counters, and C++ STL Containers, with ready-to-run MCP call hints.
    """
    try:
        if pid is None or companion_elf is None or runtime.watch_session_manager.get_active_target_context().get('pid') == pid:
            _ctx = _resolve_mcp_target(pid=pid, companion_elf=companion_elf, remote_host=remote_host, ssh_user=ssh_user, ssh_port=ssh_port, ssh_key=ssh_key, ssh_proxy_jump=ssh_proxy_jump)
            pid = _ctx['pid']
            companion_elf = _ctx['companion_elf_path']
        res = runtime.watch_session_manager.get_process_xray_blueprint(
            pid=pid,
            companion_elf_path=companion_elf,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
        )
        return _format_watch_result({"success": True, **res})
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_scan_memory_pool(
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    base_expression: str = "*gpMem",
    count: Optional[int] = None,
    status_field: Optional[str] = None,
    include_fields: Optional[List[str]] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """Scan an entire memory pool or buffer array (e.g. '*gpMem', 'gpMem->buffers', 'g_buffers')
    in a single 0.00ms zero-stop batch read and return slot-by-slot allocation status ('IN_USE' vs 'FREE'),
    utilization summary, allocation_bitmap, and a visual ascii_map_chart.
    """
    try:
        if pid is None or companion_elf is None or runtime.watch_session_manager.get_active_target_context().get('pid') == pid:
            _ctx = _resolve_mcp_target(pid=pid, companion_elf=companion_elf, remote_host=remote_host, ssh_user=ssh_user, ssh_port=ssh_port, ssh_key=ssh_key, ssh_proxy_jump=ssh_proxy_jump)
            pid = _ctx['pid']
            companion_elf = _ctx['companion_elf_path']
        res = runtime.watch_session_manager.scan_memory_pool_or_array(
            pid=pid,
            companion_elf_path=companion_elf,
            base_expression=base_expression,
            count=count,
            status_field=status_field,
            include_fields=include_fields,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
        )
        return _format_watch_result({"success": True, **res})
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_find_symbol_owners(
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    target_expression: str = "",
    stack_scan_bytes: int = 65536,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """Find which thread(s) or global worker contexts are currently using or holding a pointer to
    a specific buffer slot or C/C++ symbol (e.g. 'gpMem->buffers[9]' or 'gpMem[9]') with 0.00ms stop time.
    Checks: (1) struct owner/TID fields, (2) global worker/context tables, and (3) active thread stack memory.
    """
    try:
        if pid is None or companion_elf is None or runtime.watch_session_manager.get_active_target_context().get('pid') == pid:
            _ctx = _resolve_mcp_target(pid=pid, companion_elf=companion_elf, remote_host=remote_host, ssh_user=ssh_user, ssh_port=ssh_port, ssh_key=ssh_key, ssh_proxy_jump=ssh_proxy_jump)
            pid = _ctx['pid']
            companion_elf = _ctx['companion_elf_path']
        res = runtime.watch_session_manager.find_symbol_owners_and_threads(
            pid=pid,
            companion_elf_path=companion_elf,
            target_expression=target_expression,
            stack_scan_bytes=stack_scan_bytes,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
        )
        return _format_watch_result({"success": True, **res})
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_watch_until_condition(
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    condition_expression: str = "ANY_CHANGE",
    watch_expressions: Optional[List[str]] = None,
    poll_interval_ms: int = 40,
    timeout_ms: int = 2500,
    hold_duration_ms: int = 0,
    find_owner_on_hit: Optional[str] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """Zero-stop conditional watchpoint & anomaly snapshot catcher (0.00ms stop time).
    Polls target expressions until `condition_expression` becomes true (or stays true for `hold_duration_ms`,
    or `ANY_CHANGE` occurs), and immediately captures before/after diffs plus optional thread owner lookup.
    """
    try:
        if pid is None or companion_elf is None or runtime.watch_session_manager.get_active_target_context().get('pid') == pid:
            _ctx = _resolve_mcp_target(pid=pid, companion_elf=companion_elf, remote_host=remote_host, ssh_user=ssh_user, ssh_port=ssh_port, ssh_key=ssh_key, ssh_proxy_jump=ssh_proxy_jump)
            pid = _ctx['pid']
            companion_elf = _ctx['companion_elf_path']
        res = runtime.watch_session_manager.watch_until_condition(
            pid=pid,
            companion_elf_path=companion_elf,
            condition_expression=condition_expression,
            watch_expressions=watch_expressions,
            poll_interval_ms=poll_interval_ms,
            timeout_ms=timeout_ms,
            hold_duration_ms=hold_duration_ms,
            find_owner_on_hit=find_owner_on_hit,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
        )
        return _format_watch_result({"success": True, **res})
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_traverse_linked_structure(
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    head_expression: str = "",
    next_field: str = "next",
    max_depth: int = 64,
    include_fields: Optional[List[str]] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """Traverse a non-contiguous linked list, queue, or tree pointer chain (`node->next`) in a single
    0.00ms zero-stop MCP call. Automatically detects pointer cycles (infinite loops) and corrupted/unmapped links.
    """
    try:
        if pid is None or companion_elf is None or runtime.watch_session_manager.get_active_target_context().get('pid') == pid:
            _ctx = _resolve_mcp_target(pid=pid, companion_elf=companion_elf, remote_host=remote_host, ssh_user=ssh_user, ssh_port=ssh_port, ssh_key=ssh_key, ssh_proxy_jump=ssh_proxy_jump)
            pid = _ctx['pid']
            companion_elf = _ctx['companion_elf_path']
        res = runtime.watch_session_manager.traverse_linked_structure(
            pid=pid,
            companion_elf_path=companion_elf,
            head_expression=head_expression,
            next_field=next_field,
            max_depth=max_depth,
            include_fields=include_fields,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
        )
        return _format_watch_result({"success": True, **res})
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_inspect_thread_callstack_and_locks(
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    tid: Optional[int] = None,
    lock_expressions: Optional[List[str]] = None,
    max_frames: int = 12,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """Zero-stop replacement for `gdb thread apply all bt` + mutex deadlock detector (0.00ms stop time).
    Unwinds active thread callstacks via stack return addresses & DWARF subprograms, decodes `pthread_mutex_t`
    (`__owner` TID), matches `futex` wait addresses to mutexes, and detects circular deadlock cycles.
    """
    try:
        if pid is None or companion_elf is None or runtime.watch_session_manager.get_active_target_context().get('pid') == pid:
            _ctx = _resolve_mcp_target(pid=pid, companion_elf=companion_elf, remote_host=remote_host, ssh_user=ssh_user, ssh_port=ssh_port, ssh_key=ssh_key, ssh_proxy_jump=ssh_proxy_jump)
            pid = _ctx['pid']
            companion_elf = _ctx['companion_elf_path']
        res = runtime.watch_session_manager.inspect_thread_callstacks_and_locks(
            pid=pid,
            companion_elf_path=companion_elf,
            tid=tid,
            lock_expressions=lock_expressions,
            max_frames=max_frames,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
        )
        return _format_watch_result({"success": True, **res})
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_audit_memory_integrity(
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    target_expressions: Optional[List[str]] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """Automated DWARF-guided memory corruption & pointer health auditor (0.00ms stop time).
    Detects dangling/unmapped pointers, corrupted bool bytes (buffer overflow), out-of-range enums,
    memory pool header counter drift, and orphaned thread owner TIDs.
    """
    try:
        if pid is None or companion_elf is None or runtime.watch_session_manager.get_active_target_context().get('pid') == pid:
            _ctx = _resolve_mcp_target(pid=pid, companion_elf=companion_elf, remote_host=remote_host, ssh_user=ssh_user, ssh_port=ssh_port, ssh_key=ssh_key, ssh_proxy_jump=ssh_proxy_jump)
            pid = _ctx['pid']
            companion_elf = _ctx['companion_elf_path']
        res = runtime.watch_session_manager.audit_memory_integrity(
            pid=pid,
            companion_elf_path=companion_elf,
            target_expressions=target_expressions,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
        )
        return _format_watch_result({"success": True, **res})
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_resolve_code_pointers(
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    expressions: Optional[List[str]] = None,
    vtable_slots: int = 6,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """Resolve function pointers, callback struct fields, or C++ polymorphic object `_vptr` / `vtable`
    slots to exact C/C++ function names and DWARF source `file:line` locations (0.00ms stop time).
    """
    try:
        if pid is None or companion_elf is None or runtime.watch_session_manager.get_active_target_context().get('pid') == pid:
            _ctx = _resolve_mcp_target(pid=pid, companion_elf=companion_elf, remote_host=remote_host, ssh_user=ssh_user, ssh_port=ssh_port, ssh_key=ssh_key, ssh_proxy_jump=ssh_proxy_jump)
            pid = _ctx['pid']
            companion_elf = _ctx['companion_elf_path']
        res = runtime.watch_session_manager.resolve_code_pointers(
            pid=pid,
            companion_elf_path=companion_elf,
            expressions=expressions,
            vtable_slots=vtable_slots,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
        )
        return _format_watch_result({"success": True, **res})
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_inspect_shared_memory_ipc(
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    cast_type: Optional[str] = None,
    address: Optional[str] = None,
    shm_name: Optional[str] = None,
    discover_peer_processes: bool = True,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """Inspect POSIX shared memory (`/dev/shm/*`, shared `mmap`) or overlay a DWARF struct type (`cast_type`)
    onto any arbitrary runtime address, and discover peer processes sharing the same IPC mapping (0.00ms stop time).
    """
    try:
        if pid is None or companion_elf is None or runtime.watch_session_manager.get_active_target_context().get('pid') == pid:
            _ctx = _resolve_mcp_target(pid=pid, companion_elf=companion_elf, remote_host=remote_host, ssh_user=ssh_user, ssh_port=ssh_port, ssh_key=ssh_key, ssh_proxy_jump=ssh_proxy_jump)
            pid = _ctx['pid']
            companion_elf = _ctx['companion_elf_path']
        res = runtime.watch_session_manager.inspect_shared_memory_ipc(
            pid=pid,
            companion_elf_path=companion_elf,
            cast_type=cast_type,
            address=address,
            shm_name=shm_name,
            discover_peer_processes=discover_peer_processes,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
        )
        return _format_watch_result({"success": True, **res})
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_inspect_thread_locals_and_frame_vars(
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    tid: Optional[int] = None,
    max_frames: int = 8,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """Decode formal parameters and local variables (`DW_TAG_formal_parameter`, `DW_TAG_variable`)
    on active thread callstack frames using DWARF `DW_OP_fbreg` / frame-pointer unwinding in 0.00ms zero-stop mode.
    """
    try:
        if pid is None or companion_elf is None or runtime.watch_session_manager.get_active_target_context().get('pid') == pid:
            _ctx = _resolve_mcp_target(pid=pid, companion_elf=companion_elf, remote_host=remote_host, ssh_user=ssh_user, ssh_port=ssh_port, ssh_key=ssh_key, ssh_proxy_jump=ssh_proxy_jump)
            pid = _ctx['pid']
            companion_elf = _ctx['companion_elf_path']
        res = runtime.watch_session_manager.inspect_thread_locals_and_frame_vars(
            pid=pid,
            companion_elf_path=companion_elf,
            tid=tid,
            max_frames=max_frames,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
        )
        return _format_watch_result({"success": True, **res})
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_auto_triage_incident(
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """1-Call Composite Zero-Stop Incident Auto-Triage & Root-Cause Correlator (0.00ms stop time).
    Combines Memory Integrity Audit, Thread Callstacks & Mutex Deadlock Check, Memory Pool Pressure Sweep,
    and Linked-List Cycle Detection into a ranked root-cause scorecard (`findings`, `health_score`).
    """
    try:
        if pid is None or companion_elf is None or runtime.watch_session_manager.get_active_target_context().get('pid') == pid:
            _ctx = _resolve_mcp_target(pid=pid, companion_elf=companion_elf, remote_host=remote_host, ssh_user=ssh_user, ssh_port=ssh_port, ssh_key=ssh_key, ssh_proxy_jump=ssh_proxy_jump)
            pid = _ctx['pid']
            companion_elf = _ctx['companion_elf_path']
        res = runtime.watch_session_manager.auto_triage_incident(
            pid=pid,
            companion_elf_path=companion_elf,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
        )
        return _format_watch_result({"success": True, **res})
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_trace_ipc_pipeline(
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    cast_type: Optional[str] = None,
    address: Optional[str] = None,
    shm_name: Optional[str] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """Cross-process shared memory (`shm` / `MAP_SHARED`) & IPC FD pipeline bottleneck analyzer (0.00ms stop).
    Auto-detects or overlays DWARF struct types onto shared memory, calculates producer/consumer sequence lag
    (`pending_backlog`, `backlog_utilization_pct`), and maps connected peer processes and their states.
    """
    try:
        if pid is None or companion_elf is None or runtime.watch_session_manager.get_active_target_context().get('pid') == pid:
            _ctx = _resolve_mcp_target(pid=pid, companion_elf=companion_elf, remote_host=remote_host, ssh_user=ssh_user, ssh_port=ssh_port, ssh_key=ssh_key, ssh_proxy_jump=ssh_proxy_jump)
            pid = _ctx['pid']
            companion_elf = _ctx['companion_elf_path']
        res = runtime.watch_session_manager.trace_ipc_pipeline(
            pid=pid,
            companion_elf_path=companion_elf,
            cast_type=cast_type,
            address=address,
            shm_name=shm_name,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
        )
        return _format_watch_result({"success": True, **res})
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_scan_heap_objects(
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    class_filter: Optional[str] = None,
    max_scan_bytes: int = 524288,
    max_objects: int = 64,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """Zero-stop C++ polymorphic `vtable` (`_ZTV*`) heap & data segment object census + leak detector (0.00ms stop).
    Scans `[heap]` and `.data` for live C++ class instances via relocated `_vptr` signatures, decodes their DWARF fields,
    and flags unreferenced heap objects (`is_leaked_candidate = True`).
    """
    try:
        if pid is None or companion_elf is None or runtime.watch_session_manager.get_active_target_context().get('pid') == pid:
            _ctx = _resolve_mcp_target(pid=pid, companion_elf=companion_elf, remote_host=remote_host, ssh_user=ssh_user, ssh_port=ssh_port, ssh_key=ssh_key, ssh_proxy_jump=ssh_proxy_jump)
            pid = _ctx['pid']
            companion_elf = _ctx['companion_elf_path']
        res = runtime.watch_session_manager.scan_heap_objects(
            pid=pid,
            companion_elf_path=companion_elf,
            class_filter=class_filter,
            max_scan_bytes=max_scan_bytes,
            max_objects=max_objects,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
        )
        return _format_watch_result({"success": True, **res})
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})




@server.tool()
def runtime_build_dependency_graph(
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """Synthesize a directed cross-entity dependency & causal graph across:
    `[Process] ➔ [Thread] ➔ [Mutex Lock / Stack Frame] ➔ [Memory Pool Slot / Heap Object] ➔ [Shared Memory Peer]`
    in 0.00ms zero-stop mode, and identify `root_blocker_nodes` and `causal_chains`.
    """
    try:
        if pid is None or companion_elf is None or runtime.watch_session_manager.get_active_target_context().get('pid') == pid:
            _ctx = _resolve_mcp_target(pid=pid, companion_elf=companion_elf, remote_host=remote_host, ssh_user=ssh_user, ssh_port=ssh_port, ssh_key=ssh_key, ssh_proxy_jump=ssh_proxy_jump)
            pid = _ctx['pid']
            companion_elf = _ctx['companion_elf_path']
        res = runtime.watch_session_manager.build_dependency_graph(
            pid=pid,
            companion_elf_path=companion_elf,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
        )
        return _format_watch_result({"success": True, **res})
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_correlate_source_and_state(
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    source_location: Optional[str] = None,
    tid: Optional[int] = None,
    context_lines: int = 8,
    source_search_dirs: Optional[List[str]] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """Correlate DWARF `file:line` source locations and active stack frames with real C/C++
    source code files on disk, overlaying live runtime values of parameters, local variables,
    and referenced global symbols inline (`annotated_lines`) in 0.00ms zero-stop mode.
    """
    try:
        if pid is None or companion_elf is None or runtime.watch_session_manager.get_active_target_context().get('pid') == pid:
            _ctx = _resolve_mcp_target(pid=pid, companion_elf=companion_elf, remote_host=remote_host, ssh_user=ssh_user, ssh_port=ssh_port, ssh_key=ssh_key, ssh_proxy_jump=ssh_proxy_jump)
            pid = _ctx['pid']
            companion_elf = _ctx['companion_elf_path']
        res = runtime.watch_session_manager.correlate_source_and_state(
            pid=pid,
            companion_elf_path=companion_elf,
            source_location=source_location,
            tid=tid,
            context_lines=context_lines,
            source_search_dirs=source_search_dirs,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
        )
        return _format_watch_result({"success": True, **res})
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_investigate_symptom(
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    symptom_query: str = "왜 멈췄지? 전체적인 문제를 종합 분석해줘",
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """Autonomous Symptom-Driven Multi-Stage Root-Cause Investigator (0.00ms stop time).
    Accepts any simple, high-level user symptom question (e.g. '왜 멈췄지?', '버벅거려', '메모리가 새는 것 같아',
    '왜 응답이 없지?') and automatically orchestrates Triage + Causal Dependency Graph + Heap Leak Scan +
    Source-to-Runtime Inline Code Correlation in a single call.
    """
    try:
        if pid is None or companion_elf is None or runtime.watch_session_manager.get_active_target_context().get('pid') == pid:
            _ctx = _resolve_mcp_target(pid=pid, companion_elf=companion_elf, remote_host=remote_host, ssh_user=ssh_user, ssh_port=ssh_port, ssh_key=ssh_key, ssh_proxy_jump=ssh_proxy_jump)
            pid = _ctx['pid']
            companion_elf = _ctx['companion_elf_path']
        res = runtime.watch_session_manager.investigate_symptom(
            pid=pid,
            companion_elf_path=companion_elf,
            symptom_query=symptom_query,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
        )
        return _format_watch_result({"success": True, **res})
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})




@server.tool()
def runtime_sample_statistical_hotspots(
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    samples_count: int = 6,
    interval_ms: int = 35,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """Zero-stop statistical CPU & callstack hotspot profiler (`0.00ms` stop time).
    Replacement for `perf top` / `gdb` sampling on stripped or embedded targets: samples thread CPU tick
    deltas (`utime + stime`), callstack residency (`hotspot_functions`, `flame_stacks`), and counter mutation
    velocity (`counter_rates`) across `samples_count * interval_ms`.
    """
    try:
        if pid is None or companion_elf is None or runtime.watch_session_manager.get_active_target_context().get('pid') == pid:
            _ctx = _resolve_mcp_target(pid=pid, companion_elf=companion_elf, remote_host=remote_host, ssh_user=ssh_user, ssh_port=ssh_port, ssh_key=ssh_key, ssh_proxy_jump=ssh_proxy_jump)
            pid = _ctx['pid']
            companion_elf = _ctx['companion_elf_path']
        res = runtime.watch_session_manager.sample_statistical_hotspots(
            pid=pid,
            companion_elf_path=companion_elf,
            samples_count=samples_count,
            interval_ms=interval_ms,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
        )
        return _format_watch_result({"success": True, **res})
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_resolve_fuzzy_intent(
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    natural_query: str = "",
    limit: int = 5,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """Semantic / Fuzzy Intent-to-Symbol Resolver (`0.00ms` stop time).
    Translates vague natural-language concepts (e.g. '버퍼 풀', '워커 스레드', '세션 객체', '작업 리스트',
    '카운터') into concrete DWARF symbols & member paths, and evaluates their live runtime values immediately.
    """
    try:
        if pid is None or companion_elf is None or runtime.watch_session_manager.get_active_target_context().get('pid') == pid:
            _ctx = _resolve_mcp_target(pid=pid, companion_elf=companion_elf, remote_host=remote_host, ssh_user=ssh_user, ssh_port=ssh_port, ssh_key=ssh_key, ssh_proxy_jump=ssh_proxy_jump)
            pid = _ctx['pid']
            companion_elf = _ctx['companion_elf_path']
        res = runtime.watch_session_manager.resolve_fuzzy_symbol_intent(
            pid=pid,
            companion_elf_path=companion_elf,
            natural_query=natural_query,
            limit=limit,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
        )
        return _format_watch_result({"success": True, **res})
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})




@server.tool()
def runtime_flight_recorder_time_machine(
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    frames_count: int = 8,
    interval_ms: int = 25,
    watch_expressions: Optional[List[str]] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """Zero-stop Anomaly Time-Machine Flight Recorder (`0.00ms` stop time).
    Maintains a per-PID circular blackbox ring buffer of micro-snapshots (`frames_count` samples across `interval_ms`),
    detects transient spikes/glitches (A -> B -> A value reversals), and reconstructs `pre_anomaly_frame`,
    `peak_anomaly_frame`, and `post_anomaly_frame`.
    """
    try:
        if pid is None or companion_elf is None or runtime.watch_session_manager.get_active_target_context().get('pid') == pid:
            _ctx = _resolve_mcp_target(pid=pid, companion_elf=companion_elf, remote_host=remote_host, ssh_user=ssh_user, ssh_port=ssh_port, ssh_key=ssh_key, ssh_proxy_jump=ssh_proxy_jump)
            pid = _ctx['pid']
            companion_elf = _ctx['companion_elf_path']
        res = runtime.watch_session_manager.flight_recorder_time_machine(
            pid=pid,
            companion_elf_path=companion_elf,
            frames_count=frames_count,
            interval_ms=interval_ms,
            watch_expressions=watch_expressions,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
        )
        return _format_watch_result({"success": True, **res})
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_detect_behavioral_drift(
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    baseline_id: Optional[str] = None,
    save_as_new_baseline: bool = False,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """Zero-Stop Behavioral Drift Detector (`0.00ms` stop time).
    Compares a multi-dimensional behavioral fingerprint (scalar symbols, memory pool utilization %,
    active thread count, mutex locks, and C++ heap object/leak counts) against a saved or learned baseline
    and reports `drift_score` (0..100), `drift_status`, and `drifted_dimensions`.
    """
    try:
        if pid is None or companion_elf is None or runtime.watch_session_manager.get_active_target_context().get('pid') == pid:
            _ctx = _resolve_mcp_target(pid=pid, companion_elf=companion_elf, remote_host=remote_host, ssh_user=ssh_user, ssh_port=ssh_port, ssh_key=ssh_key, ssh_proxy_jump=ssh_proxy_jump)
            pid = _ctx['pid']
            companion_elf = _ctx['companion_elf_path']
        res = runtime.watch_session_manager.detect_behavioral_drift(
            pid=pid,
            companion_elf_path=companion_elf,
            baseline_id=baseline_id,
            save_as_new_baseline=save_as_new_baseline,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
        )
        return _format_watch_result({"success": True, **res})
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_inspect_thread_local_storage(
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    tid: Optional[int] = None,
    variable_names: Optional[List[str]] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """Zero-Stop Per-Thread TLS (`__thread` / `thread_local`) Variable Decoder (`0.00ms` stop time).
    Resolves ELF `PT_TLS` segment geometry (`memsz`, `align`) and DWARF `DW_OP_form_tls_address` /
    `DW_OP_gnu_push_tls_address` offsets, locates each thread's glibc TCB (`struct pthread *`) via
    its `tcbhead_t` self-pointer + TID signature, and decodes per-thread TLS variable values across
    all active threads without stopping the target process.
    """
    try:
        if pid is None or companion_elf is None or runtime.watch_session_manager.get_active_target_context().get('pid') == pid:
            _ctx = _resolve_mcp_target(pid=pid, companion_elf=companion_elf, remote_host=remote_host, ssh_user=ssh_user, ssh_port=ssh_port, ssh_key=ssh_key, ssh_proxy_jump=ssh_proxy_jump)
            pid = _ctx['pid']
            companion_elf = _ctx['companion_elf_path']
        res = runtime.watch_session_manager.inspect_thread_local_storage(
            pid=pid,
            companion_elf_path=companion_elf,
            tid=tid,
            variable_names=variable_names,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
        )
        return _format_watch_result({"success": True, **res})
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_verify_concurrent_read_consistency(
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    expressions: Optional[List[str]] = None,
    retries: int = 3,
    inter_read_delay_ms: int = 4,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """Optimistic Seqlock Double-Read Concurrency Verifier (`0.00ms` stop time).
    Reads target structs, pointers, and state variables twice (`Read 1 -> delay -> Read 2`, with up to `retries` attempts)
    to verify zero-stop snapshot atomicity, detect torn reads or concurrent mutations in flight, and classify each symbol as:
    `ATOMIC_CONSISTENT`, `TORN_READ_RECOVERED`, or `CONCURRENTLY_MUTATING`.
    """
    try:
        if pid is None or companion_elf is None or runtime.watch_session_manager.get_active_target_context().get('pid') == pid:
            _ctx = _resolve_mcp_target(pid=pid, companion_elf=companion_elf, remote_host=remote_host, ssh_user=ssh_user, ssh_port=ssh_port, ssh_key=ssh_key, ssh_proxy_jump=ssh_proxy_jump)
            pid = _ctx['pid']
            companion_elf = _ctx['companion_elf_path']
        res = runtime.watch_session_manager.verify_concurrent_read_consistency(
            pid=pid,
            companion_elf_path=companion_elf,
            expressions=expressions,
            retries=retries,
            inter_read_delay_ms=inter_read_delay_ms,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
        )
        return _format_watch_result({"success": True, **res})
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_inspect_dpdk_lcores_and_rings(
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    sample_window_ms: int = 40,
    ring_expressions: Optional[List[str]] = None,
    spinlock_expressions: Optional[List[str]] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """Zero-Stop DPDK Isolated-Core (`isolcpus`) Dedicated Lcore, PMD Poll-Loop, Lockless Ring (`rte_ring`)
    & User-Space Spinlock (`rte_spinlock_t`) Inspector (`0.00ms` stop time).
    Engineered for DPDK / poll-mode dedicated threads running 100% in user space (`state == 'R'`,
    `syscall == 'running'`, `kstkesp == 0`): decodes CPU core pinning, kernel isolation jitter,
    `per_lcore_*` TLS variables, pure leaf poll-loop callstacks/locals via `CALL rel32` target recovery,
    and `rte_ring` producer/consumer head/tail progression vs stalls.
    """
    try:
        if pid is None or companion_elf is None or runtime.watch_session_manager.get_active_target_context().get('pid') == pid:
            _ctx = _resolve_mcp_target(pid=pid, companion_elf=companion_elf, remote_host=remote_host, ssh_user=ssh_user, ssh_port=ssh_port, ssh_key=ssh_key, ssh_proxy_jump=ssh_proxy_jump)
            pid = _ctx['pid']
            companion_elf = _ctx['companion_elf_path']
        res = runtime.watch_session_manager.inspect_dpdk_lcores_and_rings(
            pid=pid,
            companion_elf_path=companion_elf,
            sample_window_ms=sample_window_ms,
            ring_expressions=ring_expressions,
            spinlock_expressions=spinlock_expressions,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
        )
        return _format_watch_result({"success": True, **res})
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_get_active_context() -> str:
    """Return the currently bound Stateful Target Session Context `(pid, process_name, companion_elf_path, build_id, auto_healed_count)`.
    Once bound via `runtime_target_connect` (or any `runtime_*` tool call), subsequent MCP tool calls can omit `pid` and `companion_elf`.
    """
    try:
        ctx = runtime.watch_session_manager.get_active_target_context()
        return _format_watch_result({"success": True, **ctx})
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_coerce_expression(
    expression: str,
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
) -> str:
    """Forgiving C/C++ Expression Auto-Coercer (`0.00ms` stop time).
    Resolves `.` <-> `->` operator mismatches (e.g., `gpMem.buffers[2].seq` -> `gpMem->buffers[2].seq`),
    bare struct member names without root globals (e.g., `buffers[2].seq` -> `gpMem->buffers[2].seq`),
    and root/member symbol typos against the target's DWARF index.
    """
    try:
        from extractor.dwarf_indexer import DwarfIndexer
        ctx = _resolve_mcp_target(pid=pid, companion_elf=companion_elf)
        primary_elf, _ = runtime.watch_session_manager._split_companion_elf_paths(ctx["companion_elf_path"])
        idx = DwarfIndexer.get_index(primary_elf)
        res = runtime.watch_session_manager.coerce_and_resolve_expression(idx=idx, raw_expr=expression)
        res_clean = {k: v for k, v in res.items() if k != "ops"}
        return _format_watch_result({"success": True, "pid": ctx["pid"], "companion_elf": ctx["companion_elf_path"], **res_clean})
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_ask(
    question: str,
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    process_name: Optional[str] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """Universal 1-Call Zero-Stop Intent Gateway (`0.00ms` stop time).
    Accepts any C/C++ expression (automatically coercing `.` <-> `->`, bare member names, and typos)
    OR any natural-language diagnostic question (e.g., 'gpMem.buffers[2].seq', 'buffers[2] 누가 잡고 있어?',
    'dpdk lcore 상태는?', 'tls 변수 보여줘', '왜 멈췄지?'). Automatically inherits or heals `(pid, companion_elf)`
    from the active target context so the LLM never needs to repeat parameters or guess tool names.
    """
    try:
        res = runtime.watch_session_manager.ask_runtime_question(
            question=question,
            pid=pid,
            companion_elf_path=companion_elf,
            process_name=process_name,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
        )
        return _format_watch_result({"success": True, **res})
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_smart_compact_query(
    query_or_expression: str = "*gpMem",
    mode: str = "auto",
    max_tokens: int = 800,
    drop_zero_or_free: bool = True,
    cursor_offset: int = 0,
    page_size: int = 16,
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """LLM Context-Window Budgeter & Anomaly-First Smart Compactor (`0.00ms` stop time).
    Strips repetitive `FREE` slots and zero/NULL struct fields (`drop_zero_or_free=True`), preserves 100%
    of `IN_USE` / anomalous / non-zero items first, and supports cursor pagination (`cursor_offset`, `page_size`)
    with `token_reduction_pct` telemetry so massive pools or structs never overflow the LLM context window.
    """
    try:
        res = runtime.watch_session_manager.smart_compact_query(
            query_or_expression=query_or_expression,
            mode=mode,
            pid=pid,
            companion_elf_path=companion_elf,
            max_tokens=max_tokens,
            drop_zero_or_free=drop_zero_or_free,
            cursor_offset=cursor_offset,
            page_size=page_size,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
        )
        return _format_watch_result({"success": True, **res})
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_batch_execute(
    steps: List[Dict[str, Any]],
    compact: bool = True,
    max_tokens_per_step: int = 800,
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    process_name: Optional[str] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """1-Call Multi-Tool Composite Batch Macro Executor (`0.00ms` stop time).
    Executes multiple heterogeneous zero-stop steps (`eval`, `scan_pool`, `find_owners`, `tls`,
    `dpdk_lcores`, `triage`, `ask`) in a single MCP round-trip while sharing target context,
    ASLR load-bias cache, and DWARF index.
    """
    try:
        res = runtime.watch_session_manager.execute_batch_macro(
            steps=steps,
            pid=pid,
            companion_elf_path=companion_elf,
            process_name=process_name,
            compact=compact,
            max_tokens_per_step=max_tokens_per_step,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
        )
        return _format_watch_result(res)
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_verify_hypothesis(
    hypothesis: str,
    assertions: List[str],
    correlate_owners: bool = True,
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    process_name: Optional[str] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """Declarative Multi-Assertion Hypothesis Verifier (`0.00ms` stop time).
    Evaluates a root-cause hypothesis and a list of forgiving C/C++ assertions (`==`, `!=`, `>=`, `<=`,
    `>`, `<`, `IS_NULL`, `NOT_NULL`), returning `verdict` (`CONFIRMED`, `PARTIALLY_CONFIRMED`, `REFUTED`),
    `confidence_score`, per-assertion evidence, and automatic thread-owner lookup on referenced buffer slots.
    """
    try:
        res = runtime.watch_session_manager.verify_runtime_hypothesis(
            hypothesis=hypothesis,
            assertions=assertions,
            correlate_owners=correlate_owners,
            pid=pid,
            companion_elf_path=companion_elf,
            process_name=process_name,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
        )
        return _format_watch_result({"success": True, **res})
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_export_incident_report(
    title: str = "dynamicState Zero-Stop Runtime Incident Report",
    hypothesis: Optional[str] = None,
    assertions: Optional[List[str]] = None,
    output_path: Optional[str] = None,
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    process_name: Optional[str] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """1-Call Comprehensive Incident Report & Remediation Exporter (`0.00ms` stop time).
    Combines Target Identity, Auto-Triage Scorecard, Thread Callstacks & Locks, and Hypothesis
    Verification into a structured Markdown + JSON report (`report_markdown`, `remediation_checklist`).
    """
    try:
        res = runtime.watch_session_manager.export_incident_report(
            title=title,
            hypothesis=hypothesis,
            assertions=assertions,
            output_path=output_path,
            pid=pid,
            companion_elf_path=companion_elf,
            process_name=process_name,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
        )
        return _format_watch_result({"success": True, **res})
    except Exception as e:
        return _format_watch_result({"success": False, "error": str(e), "error_code": type(e).__name__})


@server.tool()
def runtime_get_playbook() -> str:
    """Returns the structured decision playbook for when and how to use dynamicState MCP tools
    on live local or remote embedded Linux processes.
    """
    return _format_watch_result({
        "success": True,
        "recommended_workflow": [
            "1. Connect & Blueprint: Call `runtime_target_connect` or `runtime_get_xray_blueprint` to verify Build ID and discover categorized Memory Pools, Worker Contexts, and State Machines.",
            "2. Choose Diagnostic Scenario:",
            "   - Scenario A (Silent Hang / Stuck State): Call `runtime_run_diagnostic_recipe(recipe='instant_xray', ...)` or `runtime_eval_memory_path(expressions=[...])`.",
            "   - Scenario B (Memory Pool Allocation Map): Call `runtime_scan_memory_pool(base_expression='*gpMem')` to get the full slot allocation bitmap and map chart in 1 call.",
            "   - Scenario C (Find Thread Using Buffer Index N): Call `runtime_find_symbol_owners(target_expression='gpMem->buffers[9]')` to scan struct TID fields, worker tables, and thread stacks.",
            "   - Scenario D (Event Before/After Mutation): Call `runtime_capture_and_diff(expressions=[...], wait_ms=1000)`.",
            "   - Scenario E (Regression vs Healthy Baseline): Call `runtime_golden_baseline_save` when healthy, then `runtime_golden_baseline_compare` when degraded.",
            "   - Scenario F (Intermittent Condition Trigger / Watchpoint): Call `runtime_watch_until_condition(condition_expression='gpMem->active_buffers >= 30')`.",
            "   - Scenario G (Linked List / Tree Pointer Chain & Cycle Detection): Call `runtime_traverse_linked_structure(head_expression='g_task_list', next_field='next')`.",
            "   - Scenario H (Deadlock / Mutex Owner & Zero-Stop Callstacks): Call `runtime_inspect_thread_callstack_and_locks`.",
            "   - Scenario I (Memory Corruption / Dangling Pointer Audit): Call `runtime_audit_memory_integrity`.",
            "   - Scenario J (Function Pointer / C++ vtable Symbolization): Call `runtime_resolve_code_pointers`.",
            "   - Scenario K (Shared Memory IPC & Type Overlay Casting): Call `runtime_inspect_shared_memory_ipc`."
        ],
        "zero_stop_guarantee": "All recommended tools read memory non-intrusively (0.00ms target stop time) and never inject code into the target process.",
    })


if __name__ == "__main__":
    server.run(transport="stdio")

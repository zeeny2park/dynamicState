#!/usr/bin/env python3
"""dynamicState MCP Server

Model Context Protocol (MCP) server for dynamicState runtime state exploration,
live memory capture, and C++ semantic investigation.
"""

import json
import os
import sys
from typing import Any, Dict, List, Optional, Union

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


def _format_result(res: Any) -> str:
    """Format AgentActionResult into a clean JSON string."""
    if hasattr(res, "to_dict"):
        data = res.to_dict()
    elif isinstance(res, dict):
        data = res
    else:
        data = {"result": str(res)}
    return json.dumps(data, indent=2, ensure_ascii=False)


@server.tool()
def runtime_capture_memory(
    pid: int,
    policy: str = "ALL_READABLE",
    max_bytes: int = 33554432,
    timeout_ms: int = 2000
) -> str:
    """Capture raw memory of a live running Linux process non-intrusively via process_vm_readv.
    
    Args:
        pid: Target process PID.
        policy: Region filter policy (ALL_READABLE, STACK, HEAP, GLOBAL, etc.).
        max_bytes: Maximum total bytes to capture (default: 32MB).
        timeout_ms: Timeout in milliseconds.
    """
    res = runtime.dispatch_action({
        "action": "MEMORY_SNAPSHOT",
        "pid": pid,
        "policy": policy,
        "max_bytes": max_bytes,
        "timeout_ms": timeout_ms
    })
    return _format_result(res)


@server.tool()
def runtime_observe(
    pid: Optional[int] = None,
    debug_image: Optional[str] = None,
    mode: str = "LOW_IMPACT"
) -> str:
    """Observe active execution state, threads, and root objects from a running process or stopped inferior.
    
    Args:
        pid: Optional live process PID.
        debug_image: Path to external debug ELF binary with DWARF symbols.
        mode: Observation mode ('LOW_IMPACT' for non-stop live capture, 'CONSISTENT' for stopped execution).
    """
    res = runtime.dispatch_action({
        "action": "OBSERVE",
        "pid": pid,
        "debug_image": debug_image,
        "mode": mode
    })
    return _format_result(res)


@server.tool()
def runtime_list_objects(snapshot_id: Optional[str] = None) -> str:
    """List all reachable semantic objects discovered in the active or specified snapshot.
    
    Args:
        snapshot_id: Optional snapshot identifier.
    """
    res = runtime.dispatch_action({
        "action": "LIST_OBJECTS",
        "snapshot_id": snapshot_id
    })
    return _format_result(res)


@server.tool()
def runtime_inspect_object(object_id: str, snapshot_id: Optional[str] = None) -> str:
    """Inspect field values, types, and pointer references of a specific semantic object.
    
    Args:
        object_id: Object identifier (e.g. 'obj_0001').
        snapshot_id: Optional snapshot identifier.
    """
    res = runtime.dispatch_action({
        "action": "INSPECT_OBJECT",
        "object_id": object_id,
        "snapshot_id": snapshot_id
    })
    return _format_result(res)


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
    res = runtime.dispatch_action({
        "action": "INSPECT_FIELD",
        "object_id": object_id,
        "field_path": field_path,
        "snapshot_id": snapshot_id
    })
    return _format_result(res)


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
    
    Args:
        goal: Natural language investigation goal (e.g. 'Investigate worker counter mismatch' or Korean equivalent).
        pid: Target process PID for live capture.
        debug_image: Path to external debug ELF binary with DWARF symbols.
        memory_snapshot_path: Path to offline raw memory snapshot directory.
        watch_session_id: Optional persistent watch session ID (e.g. from runtime_watch_session_create).
        observation_window: Optional dict with start_seq, end_seq, duration_sec, guard_address, etc.
    """
    res = runtime.dispatch_action({
        "action": "START_INVESTIGATION",
        "goal": goal,
        "pid": pid,
        "debug_image": debug_image,
        "memory_snapshot_path": memory_snapshot_path,
        "watch_session_id": watch_session_id,
        "observation_window": observation_window,
        "authorize_target": True
    })
    return _format_result(res)


@server.tool()
def runtime_get_investigation_report(investigation_id: str) -> str:
    """Retrieve full synthesis report, verified evidence, and causal findings for an investigation.
    
    Args:
        investigation_id: Investigation session ID (e.g. 'inv_...').
    """
    res = runtime.dispatch_action({
        "action": "GET_INVESTIGATION_REPORT",
        "investigation_id": investigation_id
    })
    return _format_result(res)


@server.tool()
def runtime_checkpoint(checkpoint_id: Optional[str] = None) -> str:
    """Create a branch-safe execution savepoint.
    
    Args:
        checkpoint_id: Optional identifier for checkpoint (e.g. 'C_SEED').
    """
    res = runtime.dispatch_action({
        "action": "CHECKPOINT",
        "checkpoint_id": checkpoint_id
    })
    return _format_result(res)


@server.tool()
def runtime_restore(checkpoint_id: str) -> str:
    """Rollback execution state to a previously saved checkpoint.
    
    Args:
        checkpoint_id: Checkpoint identifier to restore.
    """
    res = runtime.dispatch_action({
        "action": "RESTORE",
        "checkpoint_id": checkpoint_id
    })
    return _format_result(res)


@server.tool()
def runtime_list_candidates(snapshot_id: Optional[str] = None) -> str:
    """Discover and rank type-safe mutation hypotheses for the current state.
    
    Args:
        snapshot_id: Optional snapshot identifier.
    """
    res = runtime.dispatch_action({
        "action": "LIST_MUTATION_CANDIDATES",
        "snapshot_id": snapshot_id
    })
    return _format_result(res)


@server.tool()
def runtime_execute_transition(candidate_id: str, timeout_ms: int = 1000) -> str:
    """Apply a mutation candidate, resume execution, and return semantic transition facts and diff.
    
    Args:
        candidate_id: Identifier of the mutation candidate (e.g. 'M0001').
        timeout_ms: Execution timeout in milliseconds.
    """
    res = runtime.dispatch_action({
        "action": "EXECUTE_TRANSITION",
        "candidate_id": candidate_id,
        "timeout_ms": timeout_ms
    })
    return _format_result(res)


@server.tool()
def runtime_get_capabilities() -> str:
    """Query runtime platform capabilities, supported observation backends, and safety limits."""
    res = runtime.dispatch_action({
        "action": "GET_CAPABILITIES"
    })
    return _format_result(res)


# -----------------------------------------------------------------------------
# Phase 23: Watch Session and Temporal Explorer MCP Tools
# -----------------------------------------------------------------------------

def _format_watch_result(data: Any) -> str:
    """Format Watch Session result into clean JSON string."""
    return json.dumps(data, indent=2, ensure_ascii=False)


@server.tool()
def runtime_watch_session_create(
    pid: int,
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
    
    Args:
        pid: Target process PID (interpreted in target host namespace).
        companion_elf: Local path to non-stripped companion ELF with DWARF symbols.
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
        if pid <= 0:
            return _format_watch_result({"success": False, "error": f"Invalid PID {pid}", "error_code": "INVALID_PID"})
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
    pid: int,
    companion_elf: Optional[str] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """Inspect memory mappings, threads, and discoverable variables for a local or remote target.
    
    Args:
        pid: Target process PID.
        companion_elf: Local path to non-stripped companion ELF with DWARF symbols.
        remote_host: Optional SSH remote host/IP.
        ssh_user: Optional SSH username.
        ssh_port: SSH port (default: 22).
        ssh_key: Optional path to SSH private key.
        ssh_proxy_jump: Optional SSH jump host.
    """
    try:
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
# Phase 32: High-Level Intent-Driven MCP Tools for Embedded Live Analysis
# -----------------------------------------------------------------------------

@server.tool()
def runtime_target_connect(
    companion_elf: str,
    pid: Optional[int] = None,
    process_name: Optional[str] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
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

        return _format_watch_result({
            "success": True,
            "pid": resolved_pid,
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
    companion_elf: str,
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
    pid: int,
    companion_elf: str,
    expressions: List[str],
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
    pid: int,
    companion_elf: str,
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
    pid: int,
    companion_elf: str,
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
    pid: int,
    companion_elf: str,
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
    baseline_id: str,
    pid: int,
    companion_elf: Optional[str] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
) -> str:
    """Compare a currently running local or remote embedded process against a saved Golden Baseline."""
    try:
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


if __name__ == "__main__":
    server.run(transport="stdio")

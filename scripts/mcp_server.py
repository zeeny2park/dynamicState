#!/usr/bin/env python3
"""dynamicState MCP Server

Model Context Protocol (MCP) server for dynamicState runtime state exploration,
live memory capture, and C++ semantic investigation.
"""

import json
import os
import sys
from typing import Any, Dict, Optional

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from mcp.server.mcpserver import MCPServer
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
    memory_snapshot_path: Optional[str] = None
) -> str:
    """Launch an evidence-first investigation session against a live PID or offline snapshot.
    
    Args:
        goal: Natural language investigation goal (e.g. 'Investigate worker counter mismatch').
        pid: Target process PID for live capture.
        debug_image: Path to external debug ELF binary with DWARF symbols.
        memory_snapshot_path: Path to offline raw memory snapshot directory.
    """
    res = runtime.dispatch_action({
        "action": "START_INVESTIGATION",
        "goal": goal,
        "pid": pid,
        "debug_image": debug_image,
        "memory_snapshot_path": memory_snapshot_path,
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


if __name__ == "__main__":
    server.run(transport="stdio")

"""Cross-call Investigation Ledger, Repeat-Call Delta Tracker, Code-Anchor Extractor,
and Self-Recovery Action Builder for continuous LLM coding-agent troubleshooting.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import os
import threading
import time
from collections import OrderedDict
from typing import Any, Dict, Iterator, List, Optional, Tuple

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX
    fcntl = None  # type: ignore[assignment]


_MAX_TARGETS = 32
_MAX_CALLS_PER_TARGET = 24
_MAX_ANCHORS_PER_TARGET = 32

_LOGGER = logging.getLogger(__name__)

_PREDICATE_SEVERITY_RANK: Dict[str, int] = {
    "OPEN": 0,
    "PIVOT_REQUIRED": 1,
    "EXHAUSTED": 2,
    "MET": 3,
    "BLOCKED": 4,
}

# Tools that are intentionally called repeatedly to observe time progression
_TEMPORAL_REPEAT_TOOLS = frozenset({
    "runtime_capture_and_diff",
    "runtime_watch_until_condition",
    "runtime_flight_recorder_time_machine",
    "runtime_detect_behavioral_drift",
})


def make_target_key(pid: Optional[int], remote_target: Optional[Dict[str, Any]] = None) -> str:
    host = "local"
    port_suffix = ""
    if isinstance(remote_target, dict) and remote_target.get("remote_host"):
        host = str(remote_target["remote_host"]).strip()
        port = remote_target.get("ssh_port")
        if port is not None and str(port) not in ("", "22"):
            port_suffix = f"@{port}"
    return f"{host}{port_suffix}:{int(pid) if pid is not None else 'none'}"


def _canonical_arg_signature(tool_name: str, args: Optional[Dict[str, Any]]) -> str:
    """Stable signature for anti-looping deduplication of identical tool calls."""
    if not isinstance(args, dict):
        return tool_name
    parts: List[str] = [tool_name]
    for k in sorted(args.keys()):
        if k in ("pid", "remote_host", "ssh_user", "ssh_port", "ssh_key", "ssh_proxy_jump", "companion_elf", "debug_image"):
            continue
        v = args[k]
        if isinstance(v, list):
            parts.append(f"{k}={','.join(str(x) for x in v[:6])}")
        elif v is not None:
            parts.append(f"{k}={v}")
    return "|".join(parts)


def _is_empty_result(tool_name: str, payload: Dict[str, Any]) -> bool:
    if not isinstance(payload, dict):
        return True
    if payload.get("success") is False:
        return True
    if tool_name == "runtime_symbol_search":
        return len(payload.get("symbols") or []) == 0
    if tool_name == "runtime_heap_leak_candidates":
        cands = (
            payload.get("candidates")
            or payload.get("classes")
            or payload.get("top_candidates")
            or payload.get("size_classes")
            or []
        )
        return len(cands) == 0
    if tool_name == "runtime_heap_owner_lookup":
        results = payload.get("results") or []
        return not any(
            isinstance(r, dict) and (r.get("referrers") or r.get("owners"))
            for r in results
        )
    if tool_name == "runtime_trace_ipc_pipeline":
        peers = payload.get("peer_processes") or payload.get("peers") or []
        shms = payload.get("shared_memory_regions") or payload.get("shm_regions") or []
        return len(peers) == 0 and len(shms) == 0
    if tool_name == "runtime_scan_heap_objects":
        objs = payload.get("objects") or payload.get("instances") or []
        return len(objs) == 0
    return False


def extract_code_anchors(tool_name: str, payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract normalized source-code anchors (file:line, function, variable_path, symbol)
    so a coding agent can jump directly from runtime evidence into repository source files.
    """
    if not isinstance(payload, dict):
        return []
    anchors: List[Dict[str, Any]] = []
    seen = set()

    def _add(
        *,
        source_location: Optional[str] = None,
        file_path: Optional[str] = None,
        line: Optional[int] = None,
        function: Optional[str] = None,
        symbol: Optional[str] = None,
        variable_path: Optional[str] = None,
        note: Optional[str] = None,
    ) -> None:
        if source_location and not file_path and ":" in str(source_location):
            fp, _, ln = str(source_location).rpartition(":")
            file_path = fp or None
            try:
                line = int(ln)
            except (TypeError, ValueError):
                pass
        if not any((file_path, function, symbol, variable_path)):
            return
        key = (file_path or "", line or 0, function or "", symbol or "", variable_path or "")
        if key in seen:
            return
        seen.add(key)
        entry: Dict[str, Any] = {"origin_tool": tool_name}
        if file_path:
            entry["file"] = str(file_path)
        if line is not None:
            entry["line"] = int(line)
        if function:
            entry["function"] = str(function)
        if symbol:
            entry["symbol"] = str(symbol)
        if variable_path:
            entry["variable_path"] = str(variable_path)
        if note:
            entry["note"] = str(note)
        anchors.append(entry)

    # 1. Thread call stacks & lock waiters
    for t in (payload.get("threads") or []):
        if not isinstance(t, dict):
            continue
        tid = t.get("tid")
        for fr in (t.get("frames") or t.get("callstack") or [])[:4]:
            if isinstance(fr, dict):
                _add(
                    source_location=fr.get("source_location") or fr.get("file_line"),
                    file_path=fr.get("file") or fr.get("source_file"),
                    line=fr.get("line"),
                    function=fr.get("function") or fr.get("symbol"),
                    note=f"tid={tid}" if tid is not None else None,
                )

    # 2. DWARF symbol search hits
    for sym in (payload.get("symbols") or [])[:8]:
        if isinstance(sym, dict):
            _add(
                file_path=sym.get("decl_file") or sym.get("file"),
                line=sym.get("decl_line") or sym.get("line"),
                symbol=sym.get("name"),
                note=sym.get("type") or sym.get("category"),
            )

    # 3. Heap owner lookup referrers
    for r in (payload.get("results") or []):
        if not isinstance(r, dict):
            continue
        for ref in (r.get("referrers") or r.get("owners") or [])[:4]:
            if isinstance(ref, dict):
                _add(
                    source_location=ref.get("source_location"),
                    file_path=ref.get("decl_file") or ref.get("file"),
                    line=ref.get("decl_line") or ref.get("line"),
                    variable_path=ref.get("variable_path") or ref.get("variable"),
                    note=ref.get("root_kind"),
                )

    # 4. Source correlation / findings
    for item in (payload.get("correlations") or payload.get("findings") or [])[:6]:
        if isinstance(item, dict):
            _add(
                source_location=item.get("source_location"),
                file_path=item.get("file") or item.get("source_file"),
                line=item.get("line"),
                function=item.get("function") or item.get("function_name"),
                variable_path=item.get("variable_path") or item.get("variable"),
                note=item.get("category") or item.get("summary"),
            )

    # 5. Evaluated memory expressions
    ev_map = payload.get("results") if isinstance(payload.get("results"), dict) else payload.get("evaluated")
    if isinstance(ev_map, dict):
        for expr, val in list(ev_map.items())[:6]:
            if isinstance(val, dict):
                _add(
                    file_path=val.get("decl_file") or val.get("file"),
                    line=val.get("decl_line") or val.get("line"),
                    variable_path=str(expr),
                    note=val.get("type"),
                )

    return anchors[:12]


def _snapshot_for_delta(tool_name: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Extract a tiny comparable snapshot from a tool payload for repeat-call delta tracking."""
    if tool_name == "runtime_inspect_thread_callstack_and_locks":
        threads: Dict[int, Dict[str, Any]] = {}
        for t in (payload.get("threads") or []):
            if not isinstance(t, dict) or t.get("tid") is None:
                continue
            tid = int(t["tid"])
            frames = t.get("frames") or t.get("callstack") or []
            top_fn = ""
            if frames and isinstance(frames[0], dict):
                top_fn = str(frames[0].get("function") or frames[0].get("symbol") or "")
            threads[tid] = {
                "state": str(t.get("state") or ""),
                "syscall": str(t.get("syscall") or ""),
                "waiting_on_lock": bool(t.get("waiting_on_lock")),
                "lock_addr": str(t.get("lock_addr") or t.get("mutex_addr") or ""),
                "top_fn": top_fn,
            }
        return {"threads": threads}

    if tool_name == "runtime_heap_leak_candidates":
        cands = (
            payload.get("candidates")
            or payload.get("classes")
            or payload.get("top_candidates")
            or payload.get("size_classes")
            or []
        )
        by_size: Dict[int, int] = {}
        for c in cands:
            if not isinstance(c, dict):
                continue
            sz = int(c.get("chunk_size") or c.get("size") or 0)
            cnt = int(c.get("count") or c.get("blocks") or 1)
            if sz > 0:
                by_size[sz] = by_size.get(sz, 0) + cnt
        return {"by_size": by_size, "total_classes": len(by_size)}

    if tool_name == "runtime_eval_memory_path":
        ev = payload.get("results") if isinstance(payload.get("results"), dict) else (payload.get("evaluated") or {})
        vals: Dict[str, str] = {}
        if isinstance(ev, dict):
            for k, v in list(ev.items())[:24]:
                if isinstance(v, dict) and "value" in v:
                    vals[str(k)] = repr(v["value"])[:120]
                else:
                    vals[str(k)] = repr(v)[:120]
        return {"values": vals}

    if tool_name == "runtime_trace_ipc_pipeline":
        peers = payload.get("peer_processes") or payload.get("peers") or []
        peer_pids = sorted({int(p["pid"]) for p in peers if isinstance(p, dict) and p.get("pid") is not None})
        backlog = payload.get("pending_backlog")
        return {"peer_pids": peer_pids, "pending_backlog": backlog}

    return {}


def compute_delta_from_last_call(
    tool_name: str,
    prev_snapshot: Dict[str, Any],
    cur_snapshot: Dict[str, Any],
    elapsed_s: float,
) -> Optional[Dict[str, Any]]:
    """Compute a concise, token-efficient delta between consecutive calls of the same tool."""
    elapsed_s = round(max(0.0, float(elapsed_s)), 2)

    if tool_name == "runtime_inspect_thread_callstack_and_locks":
        p_thr = prev_snapshot.get("threads") or {}
        c_thr = cur_snapshot.get("threads") or {}
        stuck: List[Dict[str, Any]] = []
        progressed: List[int] = []
        for tid, cur in c_thr.items():
            prev = p_thr.get(tid)
            if prev is None:
                continue
            same_wait = (
                cur["waiting_on_lock"]
                and prev["waiting_on_lock"]
                and cur["lock_addr"] == prev["lock_addr"]
                and cur["top_fn"] == prev["top_fn"]
            ) or (
                cur["syscall"]
                and cur["syscall"] == prev["syscall"]
                and cur["top_fn"] == prev["top_fn"]
                and cur["state"] in ("S", "D")
            )
            if same_wait:
                stuck.append({
                    "tid": tid,
                    "syscall": cur["syscall"],
                    "top_fn": cur["top_fn"],
                    "waiting_on_lock": cur["waiting_on_lock"],
                    "lock_addr": cur["lock_addr"] or None,
                })
            elif cur != prev:
                progressed.append(tid)
        new_tids = sorted(set(c_thr.keys()) - set(p_thr.keys()))
        exited_tids = sorted(set(p_thr.keys()) - set(c_thr.keys()))
        return {
            "elapsed_s": elapsed_s,
            "stuck_threads": stuck[:8],
            "stuck_count": len(stuck),
            "progressed_tids": progressed[:8],
            "new_tids": new_tids[:8],
            "exited_tids": exited_tids[:8],
            "summary": (
                f"over {elapsed_s}s: {len(stuck)} thread(s) stayed stuck on same frame/wait, "
                f"{len(progressed)} progressed, +{len(new_tids)}/-{len(exited_tids)} threads"
            ),
        }

    if tool_name == "runtime_heap_leak_candidates":
        p_sz = prev_snapshot.get("by_size") or {}
        c_sz = cur_snapshot.get("by_size") or {}
        growing: List[Dict[str, Any]] = []
        shrank: List[Dict[str, Any]] = []
        for sz in sorted(set(p_sz.keys()) | set(c_sz.keys())):
            delta = int(c_sz.get(sz, 0)) - int(p_sz.get(sz, 0))
            if delta > 0:
                growing.append({"chunk_size": sz, "count_delta": delta, "current_count": int(c_sz.get(sz, 0))})
            elif delta < 0:
                shrank.append({"chunk_size": sz, "count_delta": delta})
        growing.sort(key=lambda x: x["count_delta"] * x["chunk_size"], reverse=True)
        return {
            "elapsed_s": elapsed_s,
            "growing_size_classes": growing[:6],
            "shrinking_count": len(shrank),
            "summary": (
                f"over {elapsed_s}s: {len(growing)} size class(es) grew"
                + (f" (top: {growing[0]['chunk_size']}B +{growing[0]['count_delta']})" if growing else "")
            ),
        }

    if tool_name == "runtime_eval_memory_path":
        p_vals = prev_snapshot.get("values") or {}
        c_vals = cur_snapshot.get("values") or {}
        changed: List[Dict[str, Any]] = []
        unchanged: List[str] = []
        for expr, cur_v in c_vals.items():
            if expr in p_vals:
                if p_vals[expr] != cur_v:
                    changed.append({"expression": expr, "before": p_vals[expr], "after": cur_v})
                else:
                    unchanged.append(expr)
        return {
            "elapsed_s": elapsed_s,
            "changed_expressions": changed[:8],
            "unchanged_expressions": unchanged[:8],
            "summary": f"over {elapsed_s}s: {len(changed)} expression(s) changed, {len(unchanged)} unchanged",
        }

    if tool_name == "runtime_trace_ipc_pipeline":
        p_peers = set(prev_snapshot.get("peer_pids") or [])
        c_peers = set(cur_snapshot.get("peer_pids") or [])
        out: Dict[str, Any] = {
            "elapsed_s": elapsed_s,
            "new_peer_pids": sorted(c_peers - p_peers),
            "gone_peer_pids": sorted(p_peers - c_peers),
        }
        pb = prev_snapshot.get("pending_backlog")
        cb = cur_snapshot.get("pending_backlog")
        if isinstance(pb, (int, float)) and isinstance(cb, (int, float)):
            out["pending_backlog_delta"] = cb - pb
        out["summary"] = (
            f"over {elapsed_s}s: peers +{len(out['new_peer_pids'])}/-{len(out['gone_peer_pids'])}"
            + (f", backlog delta {out['pending_backlog_delta']:+}" if "pending_backlog_delta" in out else "")
        )
        return out

    return None


def build_recovery_actions(
    tool_name: str,
    payload: Dict[str, Any],
    *,
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    args: Optional[Dict[str, Any]] = None,
    remote_target: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Build concrete self-recovery actions when a tool fails or returns empty results."""
    if not isinstance(payload, dict):
        return []
    failed = payload.get("success") is False
    empty = _is_empty_result(tool_name, payload)
    if not failed and not empty:
        return []

    err_txt = str(payload.get("error") or payload.get("error_message") or "").lower()
    rm_args = (
        {k: v for k, v in remote_target.items() if v is not None}
        if isinstance(remote_target, dict) else {}
    )
    base_args: Dict[str, Any] = {**rm_args}
    if pid is not None:
        base_args["pid"] = int(pid)
    if companion_elf:
        base_args["companion_elf"] = str(companion_elf)

    actions: List[Dict[str, Any]] = []

    # 1. Permission / ptrace / unreadable target
    if any(k in err_txt for k in ("permission denied", "eperm", "ptrace", "operation not permitted")):
        actions.append({
            "id": "recover_permission_blocked",
            "mcp_tool": "runtime_get_capabilities",
            "mcp_args": {**rm_args},
            "reason": "Target memory read was blocked by OS permissions/ptrace_scope; verify capabilities or run with CAP_SYS_PTRACE/same UID.",
        })
        return actions

    # 2. Symbol search returned 0 hits
    if tool_name == "runtime_symbol_search":
        q = str((args or {}).get("query") or payload.get("query") or "").strip()
        if not (args or {}).get("fast_only") and companion_elf:
            tokens = [tok for tok in q.replace("::", " ").replace("_", " ").split() if len(tok) >= 3]
            fallback_q = tokens[0] if tokens else q
            actions.append({
                "id": "recover_symbol_search_fast_symtab",
                "mcp_tool": "runtime_symbol_search",
                "mcp_args": {**base_args, "query": fallback_q, "fast_only": True, "limit": 50},
                "reason": "DWARF symbol query returned 0 hits; retry with fast_only=True ELF symtab and a shorter root token (handles stripped/mangled names).",
            })
        if pid is not None and companion_elf:
            actions.append({
                "id": "recover_symbol_via_vtable_scan",
                "mcp_tool": "runtime_scan_heap_objects",
                "mcp_args": {**base_args},
                "reason": "No matching global symbol found; scan live C++ vtable instances in heap/.data to discover active objects.",
            })
        return actions

    # 3. Expression evaluation failed
    if tool_name == "runtime_eval_memory_path" and failed:
        exprs = (args or {}).get("expressions") or []
        first_expr = str(exprs[0]) if isinstance(exprs, list) and exprs else ""
        root_sym = first_expr.split(".")[0].split("->")[0].split("[")[0].strip()
        if root_sym and companion_elf:
            actions.append({
                "id": "recover_eval_via_symbol_search",
                "mcp_tool": "runtime_symbol_search",
                "mcp_args": {**base_args, "query": root_sym, "limit": 20},
                "reason": f"Expression '{first_expr}' failed; search exact DWARF symbol/member spelling for '{root_sym}'.",
            })
        if first_expr and pid is not None and companion_elf:
            actions.append({
                "id": "recover_eval_via_coerce",
                "mcp_tool": "runtime_coerce_expression",
                "mcp_args": {**base_args, "expression": first_expr},
                "reason": "Expression syntax or pointer dereference failed; normalize it via runtime_coerce_expression.",
            })
        return actions

    # 4. Heap leak candidates empty
    if tool_name == "runtime_heap_leak_candidates":
        if pid is not None and companion_elf:
            actions.append({
                "id": "recover_heap_via_vtable_scan",
                "mcp_tool": "runtime_scan_heap_objects",
                "mcp_args": {**base_args},
                "reason": "No unreachable glibc heap leak candidates found; check reachable C++ object accumulation via vtable scan.",
            })
        if pid is not None:
            actions.append({
                "id": "recover_heap_via_capture_diff",
                "mcp_tool": "runtime_capture_and_diff",
                "mcp_args": {**base_args, "wait_ms": 3000},
                "reason": "Single-point heap scan found no unreachable blocks; capture a before/after diff over 3s to catch growing containers or mmap pools.",
            })
        return actions

    # 5. IPC pipeline empty
    if tool_name == "runtime_trace_ipc_pipeline" and pid is not None:
        actions.append({
            "id": "recover_ipc_via_thread_stacks",
            "mcp_tool": "runtime_inspect_thread_callstack_and_locks",
            "mcp_args": {**base_args},
            "reason": "No shared-memory or IPC peers detected; inspect thread call stacks to identify non-IPC waits or local I/O stalls.",
        })
        return actions

    # 6. Generic fallback for any other empty/failed narrow tool
    if pid is not None:
        actions.append({
            "id": "recover_explain_process_behavior",
            "mcp_tool": "runtime_explain_process_behavior",
            "mcp_args": {**base_args},
            "reason": f"{tool_name} yielded no actionable data; pivot to high-level process behavior synthesis.",
        })
    return actions


class TargetTrackingLedger:
    """Per-target investigation ledger across consecutive MCP/CLI tool calls.

    Separates:
    - Evidence discovery (code anchors, deltas, raw observations)
    - Hypothesis validation (SUPPORTED / CONTRADICTED / INCONCLUSIVE / BLOCKED / UNVALIDATED)
    - Playbook Exit Predicate satisfaction (MET only when actual completion criteria are met)
    """

    def __init__(self, target_key: str):
        self.target_key = target_key
        self.created_at = time.monotonic()
        self.calls: List[Dict[str, Any]] = []
        self.last_by_tool: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        self.dead_end_signatures: set = set()
        self.tried_signatures: Dict[str, int] = {}
        self.code_anchors: List[Dict[str, Any]] = []
        self._anchor_keys: set = set()
        # Playbook Loop State Machine
        self.active_playbook: Optional[Dict[str, Any]] = None
        self.playbook_slots: Dict[str, Dict[str, Any]] = {}
        self.max_iterations: Optional[int] = None  # None = no arbitrary cap unless explicitly configured
        self.iteration: int = 0
        self.consecutive_plateaus: int = 0
        self.predicate_status: str = "OPEN"  # OPEN | MET | PIVOT_REQUIRED | BLOCKED | EXHAUSTED
        self.hypothesis_status: str = "UNVALIDATED"  # UNVALIDATED | SUPPORTED | CONTRADICTED | INCONCLUSIVE | BLOCKED
        self.evidence_provenance: List[Dict[str, Any]] = []
        self.exit_predicate_evaluation: Dict[str, Any] = {
            "satisfied": False,
            "status": "OPEN",
            "hypothesis_status": "UNVALIDATED",
            "reason": "Investigation started; no hypothesis validated yet.",
            "provenance": [],
        }
        self.decision_log: List[Dict[str, Any]] = []
        # Persistence revision tracking (prevents stale in-memory overwrites)
        self.revision: int = 0
        self.updated_at_epoch: float = time.time()
        self._disk_mtime_ns: int = 0

    def _restore_from_slot(
        self,
        slot: Dict[str, Any],
        *,
        playbook: Optional[Dict[str, Any]] = None,
        max_iterations: Optional[int] = None,
    ) -> Dict[str, Any]:
        slot_pb = slot.get("active_playbook")
        if isinstance(playbook, dict):
            self.active_playbook = dict(playbook)
        elif isinstance(slot_pb, dict):
            self.active_playbook = dict(slot_pb)
        if max_iterations is not None:
            self.max_iterations = max(1, int(max_iterations))
        else:
            raw_max = slot.get("max_iterations")
            self.max_iterations = int(raw_max) if raw_max is not None else None
        self.iteration = int(slot.get("iteration") or 0)
        self.consecutive_plateaus = int(slot.get("consecutive_plateaus") or 0)
        restored_ps = str(slot.get("predicate_status") or "OPEN")
        if restored_ps == "EXHAUSTED" and (self.max_iterations is None or self.iteration < self.max_iterations):
            restored_ps = "OPEN"
        self.predicate_status = restored_ps
        self.hypothesis_status = str(slot.get("hypothesis_status") or "UNVALIDATED")
        self.evidence_provenance = list(slot.get("evidence_provenance") or [])[-_MAX_CALLS_PER_TARGET:]
        if isinstance(slot.get("exit_predicate_evaluation"), dict):
            self.exit_predicate_evaluation = dict(slot["exit_predicate_evaluation"])
        self.decision_log = list(slot.get("decision_log") or [])[-_MAX_CALLS_PER_TARGET:]
        self.revision = max(self.revision, int(slot.get("revision") or 0))
        self.updated_at_epoch = max(self.updated_at_epoch, float(slot.get("updated_at_epoch") or 0.0))
        self._sync_active_playbook_slot()
        return self.loop_state()

    def resume_playbook(
        self,
        playbook_id: str,
        *,
        max_iterations: Optional[int] = None,
    ) -> Optional[Dict[str, Any]]:
        """Restore a previously persisted playbook slot as the active playbook."""
        slot = self.playbook_slots.get(str(playbook_id).strip())
        if not isinstance(slot, dict):
            return None
        return self._restore_from_slot(slot, max_iterations=max_iterations)

    def activate_playbook(
        self,
        playbook: Dict[str, Any],
        *,
        max_iterations: Optional[int] = None,
        resume: bool = False,
    ) -> Dict[str, Any]:
        pb_id = str((playbook or {}).get("playbook_id") or "").strip()
        if resume and pb_id and isinstance(self.playbook_slots.get(pb_id), dict):
            return self._restore_from_slot(
                self.playbook_slots[pb_id],
                playbook=playbook,
                max_iterations=max_iterations,
            )
        self.active_playbook = dict(playbook)
        # Only enforce an iteration limit when explicitly configured by the caller
        self.max_iterations = max(1, int(max_iterations)) if max_iterations is not None else None
        self.iteration = 0
        self.consecutive_plateaus = 0
        self.predicate_status = "OPEN"
        self.hypothesis_status = "UNVALIDATED"
        self.evidence_provenance = []
        self.exit_predicate_evaluation = {
            "satisfied": False,
            "status": "OPEN",
            "hypothesis_status": "UNVALIDATED",
            "reason": "Playbook activated; awaiting hypothesis validation against exit predicate.",
            "provenance": [],
        }
        self.revision += 1
        self.updated_at_epoch = time.time()
        self._sync_active_playbook_slot()
        return self.loop_state()

    def _sync_active_playbook_slot(self) -> None:
        """Persist the active playbook's isolated state slot keyed by playbook_id."""
        pb = self.active_playbook
        if not isinstance(pb, dict):
            return
        pb_id = str(pb.get("playbook_id") or "").strip()
        if not pb_id:
            return
        self.playbook_slots[pb_id] = {
            "playbook_id": pb_id,
            "active_playbook": dict(pb),
            "max_iterations": self.max_iterations,
            "iteration": self.iteration,
            "consecutive_plateaus": self.consecutive_plateaus,
            "predicate_status": self.predicate_status,
            "hypothesis_status": self.hypothesis_status,
            "evidence_provenance": list(self.evidence_provenance[-_MAX_CALLS_PER_TARGET:]),
            "exit_predicate_evaluation": dict(self.exit_predicate_evaluation),
            "decision_log": list(self.decision_log[-_MAX_CALLS_PER_TARGET:]),
            "revision": self.revision,
            "updated_at_epoch": self.updated_at_epoch,
        }

    def get_playbook_slot(self, playbook_id: str) -> Optional[Dict[str, Any]]:
        slot = self.playbook_slots.get(str(playbook_id))
        return dict(slot) if isinstance(slot, dict) else None

    def list_playbook_slots(self) -> List[str]:
        return sorted(self.playbook_slots.keys())

    def _has_corroborated_root_anchor(self) -> bool:
        """True when at least one code anchor carries file:line, variable_path, or symbol."""
        return any(
            bool(a.get("file") or a.get("variable_path") or a.get("symbol") or a.get("function"))
            for a in self.code_anchors
        )

    def _evaluate_exit_predicate(
        self,
        *,
        tool_name: str,
        payload: Dict[str, Any],
        delta: Optional[Dict[str, Any]],
        empty: bool,
        is_hard_blocked: bool,
    ) -> Tuple[str, str, str]:
        """Evaluate the active playbook's actual exit predicate.

        Returns (predicate_status_candidate, hypothesis_status, reason).
        Code anchors alone NEVER satisfy MET; hypothesis validation is strictly required.
        """
        if is_hard_blocked:
            err = str(payload.get("error") or payload.get("error_message") or "target access blocked")
            return "BLOCKED", "BLOCKED", f"Hard external blocker encountered: {err}"

        pb_id = str((self.active_playbook or {}).get("playbook_id") or "")
        verdict = str(payload.get("verdict") or "").upper()
        cov_qual = str(
            (payload.get("agent_summary") or {}).get("verdict_qualifier")
            or (payload.get("coverage") or {}).get("verdict_qualifier")
            or ""
        ).upper()
        findings = [f for f in (payload.get("findings") or []) if isinstance(f, dict)]
        has_confirmed_fault = (
            verdict in ("FAULT", "DEFECT_CONFIRMED", "CONFIRMED", "CRITICAL")
            or any(
                str(f.get("status") or "").upper() in ("SUPPORTED", "CONFIRMED")
                or str(f.get("severity") or "").upper() in ("HIGH", "CRITICAL")
                for f in findings
            )
        )
        has_clean_refutation = (
            verdict == "HEALTHY"
            and cov_qual not in ("NO_FAULT_LIMITED_OBSERVATION", "BLOCKED_EXECUTION", "PARTIAL_OBSERVATION")
            and not bool((payload.get("memory_integrity") or {}).get("heap", {}).get("full_walk_skipped"))
        )
        has_owner_path = any(
            bool(a.get("variable_path")) for a in self.code_anchors
        ) or any(
            isinstance(r, dict) and bool(r.get("referrers") or r.get("owners"))
            for r in (payload.get("results") if isinstance(payload.get("results"), list) else [])
        )
        has_direct_eval = any(c["tool"] in ("runtime_eval_memory_path", "runtime_capture_and_diff") and not c.get("empty_or_failed") for c in self.calls)
        has_temporal_evidence = any(
            p.get("kind") == "temporal_delta" for p in self.evidence_provenance
        ) or (
            delta is not None and (
                delta.get("stuck_count", 0) > 0
                or len(delta.get("growing_size_classes") or []) > 0
                or len(delta.get("changed_expressions") or []) > 0
            )
        )
        has_prior_supported = any(p.get("hypothesis_status") == "SUPPORTED" for p in self.evidence_provenance)
        has_prior_contradicted = any(p.get("hypothesis_status") == "CONTRADICTED" for p in self.evidence_provenance)

        # Record provenance of hypothesis validation (distinct from raw anchor discovery)
        cur_hyp = "INCONCLUSIVE"
        if has_confirmed_fault:
            cur_hyp = "SUPPORTED"
            self.evidence_provenance.append({
                "iter": self.iteration,
                "tool": tool_name,
                "kind": "fault_supported",
                "hypothesis_status": "SUPPORTED",
                "detail": verdict or (findings[0].get("recipe_id") if findings else "confirmed_finding"),
            })
        elif has_clean_refutation:
            cur_hyp = "CONTRADICTED"
            self.evidence_provenance.append({
                "iter": self.iteration,
                "tool": tool_name,
                "kind": "hypothesis_refuted",
                "hypothesis_status": "CONTRADICTED",
                "detail": "Validated HEALTHY with complete coverage",
            })
        elif has_temporal_evidence:
            cur_hyp = "SUPPORTED" if (delta and (delta.get("stuck_count", 0) > 0 or len(delta.get("growing_size_classes") or []) > 0)) else "INCONCLUSIVE"
            self.evidence_provenance.append({
                "iter": self.iteration,
                "tool": tool_name,
                "kind": "temporal_delta",
                "hypothesis_status": cur_hyp,
                "detail": delta.get("summary") if isinstance(delta, dict) else "temporal_observation",
            })
        elif tool_name == "runtime_eval_memory_path" and not empty and payload.get("success") is not False:
            cur_hyp = "INCONCLUSIVE"
            self.evidence_provenance.append({
                "iter": self.iteration,
                "tool": tool_name,
                "kind": "direct_memory_eval",
                "hypothesis_status": "INCONCLUSIVE",
                "detail": "Direct symbol evaluation recorded",
            })

        supported_now = has_confirmed_fault or has_prior_supported
        contradicted_now = has_clean_refutation or has_prior_contradicted
        has_anchor = self._has_corroborated_root_anchor()

        # Playbook-specific Exit Predicate verification:
        # Note: runtime_correlate_source_and_state returning arbitrary anchors WITHOUT validated
        # hypothesis evidence (supported_now / contradicted_now / direct eval) MUST NOT return MET.
        if pb_id == "memory-leak-and-growth":
            if supported_now and (has_owner_path or has_anchor):
                return "MET", "SUPPORTED", "Memory leak/growth hypothesis SUPPORTED with owning variable/code anchor."
            if contradicted_now and (has_temporal_evidence or has_clean_refutation):
                return "MET", "CONTRADICTED", "Sustained memory growth CONTRADICTED with validated observation coverage."
            return "OPEN", ("SUPPORTED" if supported_now else ("CONTRADICTED" if contradicted_now else "INCONCLUSIVE")), (
                "Awaiting confirmed leak ownership/code anchor or validated growth refutation."
            )

        if pb_id == "heap-corruption-and-uaf":
            if supported_now and has_anchor:
                return "MET", "SUPPORTED", "Heap corruption/UAF defect SUPPORTED with corroborating symbol/code anchor."
            if contradicted_now:
                return "MET", "CONTRADICTED", "Full heap integrity check CONTRADICTED active corruption."
            return "OPEN", ("SUPPORTED" if supported_now else "INCONCLUSIVE"), (
                "Awaiting confirmed corruption/UAF defect with anchor or full integrity refutation."
            )

        if pb_id == "hang-deadlock-and-contention":
            stuck_confirmed = any(
                p.get("kind") == "temporal_delta" and p.get("hypothesis_status") == "SUPPORTED"
                for p in self.evidence_provenance
            )
            if (supported_now or stuck_confirmed) and has_anchor:
                return "MET", "SUPPORTED", "Hang/deadlock/stall SUPPORTED with lock/frame code anchor."
            if contradicted_now:
                return "MET", "CONTRADICTED", "All threads confirmed progressing normally."
            return "OPEN", ("SUPPORTED" if (supported_now or stuck_confirmed) else "INCONCLUSIVE"), (
                "Awaiting confirmed deadlock/sustained stuck thread with source anchor or validated liveness."
            )

        if pb_id == "fd-and-ipc-stall":
            if supported_now and has_anchor:
                return "MET", "SUPPORTED", "FD leak or IPC stall SUPPORTED with call-stack/code anchor."
            if contradicted_now:
                return "MET", "CONTRADICTED", "FD count and IPC endpoints confirmed stable."
            return "OPEN", ("SUPPORTED" if supported_now else "INCONCLUSIVE"), (
                "Awaiting confirmed FD/IPC fault with code anchor or validated stability."
            )

        if pb_id == "state-and-variable-bug":
            if has_direct_eval and has_anchor and (supported_now or contradicted_now):
                st_h = "SUPPORTED" if supported_now else "CONTRADICTED"
                return "MET", st_h, f"Target symbol values directly evaluated and correlated to source ({st_h})."
            return "OPEN", ("SUPPORTED" if supported_now else ("CONTRADICTED" if contradicted_now else "INCONCLUSIVE")), (
                "Awaiting direct live symbol evaluation + source correlation validating or refuting the invariant."
            )

        if pb_id == "intermittent-temporal-bug":
            if (has_temporal_evidence or supported_now) and has_anchor:
                return "MET", "SUPPORTED", "Intermittent anomaly window captured with temporal delta and code anchor."
            if contradicted_now and has_temporal_evidence:
                return "MET", "CONTRADICTED", "Temporal observation window completed with validated baseline telemetry."
            return "OPEN", ("SUPPORTED" if supported_now else "INCONCLUSIVE"), (
                "Awaiting temporal delta capture with code anchor or validated baseline observation window."
            )

        # Generic (no specific playbook activated)
        if supported_now and has_anchor:
            return "MET", "SUPPORTED", "Fault hypothesis SUPPORTED with corroborating code anchor."
        if contradicted_now:
            return "MET", "CONTRADICTED", "Fault hypothesis CONTRADICTED with validated complete coverage."
        return "OPEN", ("SUPPORTED" if supported_now else "INCONCLUSIVE"), (
            "Evidence collected, but exit predicate is not yet satisfied."
        )

    def loop_state(self) -> Dict[str, Any]:
        pb = self.active_playbook
        next_step = None
        pivot_hint = None
        if isinstance(pb, dict):
            steps = pb.get("steps") or []
            used_tools = {c["tool"] for c in self.calls}
            for st in steps:
                if st.get("tool") not in used_tools:
                    next_step = st
                    break
            pivots = pb.get("pivot_rules") or []
            if self.predicate_status == "PIVOT_REQUIRED" and pivots:
                pivot_hint = pivots[min(max(0, self.consecutive_plateaus - 2), len(pivots) - 1)]
        return {
            "playbook_id": pb.get("playbook_id") if isinstance(pb, dict) else None,
            "exit_predicate": pb.get("exit_predicate") if isinstance(pb, dict) else None,
            "iteration": self.iteration,
            "max_iterations": self.max_iterations,
            "predicate_status": self.predicate_status,
            "hypothesis_status": self.hypothesis_status,
            "exit_predicate_evaluation": dict(self.exit_predicate_evaluation),
            "consecutive_plateaus": self.consecutive_plateaus,
            "next_planned_step": next_step,
            "pivot_recommendation": pivot_hint,
            "decision_log": self.decision_log[-12:],
        }

    def record(
        self,
        tool_name: str,
        args: Optional[Dict[str, Any]],
        payload: Dict[str, Any],
        *,
        now: Optional[float] = None,
    ) -> Tuple[Optional[Dict[str, Any]], List[Dict[str, Any]]]:
        ts = time.monotonic() if now is None else float(now)
        sig = _canonical_arg_signature(tool_name, args)
        self.tried_signatures[sig] = self.tried_signatures.get(sig, 0) + 1
        empty = _is_empty_result(tool_name, payload)
        if empty and tool_name not in _TEMPORAL_REPEAT_TOOLS:
            self.dead_end_signatures.add(sig)

        cur_snap = _snapshot_for_delta(tool_name, payload)
        delta: Optional[Dict[str, Any]] = None
        if tool_name in self.last_by_tool and cur_snap:
            prev_ts, prev_snap = self.last_by_tool[tool_name]
            delta = compute_delta_from_last_call(tool_name, prev_snap, cur_snap, ts - prev_ts)
        if cur_snap:
            self.last_by_tool[tool_name] = (ts, cur_snap)

        new_anchors = extract_code_anchors(tool_name, payload)
        for a in new_anchors:
            ak = (a.get("file", ""), a.get("line", 0), a.get("function", ""), a.get("symbol", ""), a.get("variable_path", ""))
            if ak not in self._anchor_keys and len(self.code_anchors) < _MAX_ANCHORS_PER_TARGET:
                self._anchor_keys.add(ak)
                self.code_anchors.append(a)

        self.calls.append({
            "tool": tool_name,
            "sig": sig,
            "elapsed_s": round(ts - self.created_at, 2),
            "empty_or_failed": empty,
        })
        if len(self.calls) > _MAX_CALLS_PER_TARGET:
            self.calls = self.calls[-_MAX_CALLS_PER_TARGET:]

        # Update Playbook Loop State Machine
        self.iteration += 1
        err_low = str(payload.get("error") or payload.get("error_message") or "").lower()
        is_hard_blocked = payload.get("success") is False and any(
            k in err_low for k in ("permission denied", "eperm", "ptrace", "no such process", "esrch", "process_exited")
        )
        verdict = str(payload.get("verdict") or "").upper()
        evidence_moved = bool(
            (not empty)
            and (
                len(new_anchors) > 0
                or (delta is not None and (
                    delta.get("stuck_count", 0) > 0
                    or len(delta.get("growing_size_classes") or []) > 0
                    or len(delta.get("changed_expressions") or []) > 0
                ))
                or verdict in ("FAULT", "DEFECT_CONFIRMED", "DEGRADED", "HEALTHY")
                or (tool_name == "runtime_eval_memory_path" and payload.get("success") is not False)
            )
        )

        pred_cand, hyp_status, pred_reason = self._evaluate_exit_predicate(
            tool_name=tool_name,
            payload=payload,
            delta=delta,
            empty=empty,
            is_hard_blocked=is_hard_blocked,
        )
        self.hypothesis_status = hyp_status

        if pred_cand == "BLOCKED":
            self.predicate_status = "BLOCKED"
        elif pred_cand == "MET":
            self.predicate_status = "MET"
            self.consecutive_plateaus = 0
        elif self.max_iterations is not None and self.iteration >= self.max_iterations:
            self.predicate_status = "EXHAUSTED"
            pred_reason = f"Explicit iteration limit ({self.max_iterations}) reached before exit predicate was satisfied."
        elif evidence_moved:
            self.consecutive_plateaus = 0
            self.predicate_status = "OPEN"
        else:
            self.consecutive_plateaus += 1
            if self.consecutive_plateaus >= 2:
                self.predicate_status = "PIVOT_REQUIRED"
            else:
                self.predicate_status = "OPEN"

        self.exit_predicate_evaluation = {
            "satisfied": self.predicate_status == "MET",
            "status": self.predicate_status,
            "hypothesis_status": self.hypothesis_status,
            "reason": pred_reason,
            "provenance": list(self.evidence_provenance[-8:]),
        }

        self.decision_log.append({
            "iter": self.iteration,
            "tool": tool_name,
            "evidence_moved": evidence_moved,
            "new_anchors": len(new_anchors),
            "hypothesis_status": self.hypothesis_status,
            "predicate_status": self.predicate_status,
            "note": (delta.get("summary") if isinstance(delta, dict) else ("empty/failed" if empty else "observed")),
        })
        if len(self.decision_log) > _MAX_CALLS_PER_TARGET:
            self.decision_log = self.decision_log[-_MAX_CALLS_PER_TARGET:]

        self.revision += 1
        self.updated_at_epoch = time.time()
        self._sync_active_playbook_slot()
        return delta, new_anchors

    def filter_actions(self, actions: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Suppress actions that repeat an already-tried dead-end tool+args signature."""
        kept: List[Dict[str, Any]] = []
        suppressed: List[str] = []
        for a in actions:
            if not isinstance(a, dict):
                continue
            tool = str(a.get("mcp_tool") or "")
            sig = _canonical_arg_signature(tool, a.get("mcp_args"))
            if tool not in _TEMPORAL_REPEAT_TOOLS and sig in self.dead_end_signatures:
                suppressed.append(sig)
                continue
            kept.append(a)
        return kept, suppressed

    def summary(self) -> Dict[str, Any]:
        tools_used = list(dict.fromkeys(c["tool"] for c in self.calls))
        return {
            "target_key": self.target_key,
            "calls_in_session": len(self.calls),
            "tools_used": tools_used,
            "dead_end_calls_suppressed_ready": len(self.dead_end_signatures),
            "code_anchors_collected": len(self.code_anchors),
            "top_code_anchors": self.code_anchors[:5],
            "playbook_slots": self.list_playbook_slots(),
            "loop_state": self.loop_state(),
        }


class TrackingLedgerStore:
    """Thread-safe bounded LRU store of per-target TargetTrackingLedger instances
    with collision-safe atomic disk persistence, restart recovery, and stale-overwrite protection.
    """

    def __init__(self, max_targets: int = _MAX_TARGETS, persist_dir: Optional[str] = None):
        self._lock = threading.Lock()
        self._max_targets = max_targets
        self._persist_dir = persist_dir
        self._ledgers: "OrderedDict[str, TargetTrackingLedger]" = OrderedDict()
        self._corruption_events: Dict[str, Dict[str, Any]] = {}

    def get_corruption_event(self, target_key: str) -> Optional[Dict[str, Any]]:
        ev = self._corruption_events.get(str(target_key))
        return dict(ev) if isinstance(ev, dict) else None

    def list_corruption_events(self) -> Dict[str, Dict[str, Any]]:
        return {k: dict(v) for k, v in self._corruption_events.items()}

    def _effective_persist_dir(self) -> Optional[str]:
        return self._persist_dir or os.environ.get("DYNAMICSTATE_LEDGER_DIR") or None

    def _ledger_path(self, target_key: str) -> Optional[str]:
        pdir = self._effective_persist_dir()
        if not pdir:
            return None
        # Collision-safe: human-readable prefix + 16-char SHA-256 of exact target_key
        safe = "".join(c if c.isalnum() or c in ("-", ".") else "_" for c in str(target_key))[:40]
        digest = hashlib.sha256(str(target_key).encode("utf-8")).hexdigest()[:16]
        return os.path.join(pdir, f"ledger_{safe}_{digest}.json")

    def _deserialize(self, target_key: str, data: Dict[str, Any], mtime_ns: int = 0) -> TargetTrackingLedger:
        ledger = TargetTrackingLedger(target_key)
        ledger.active_playbook = data.get("active_playbook")
        raw_slots = data.get("playbook_slots")
        if isinstance(raw_slots, dict):
            ledger.playbook_slots = {
                str(k): dict(v) for k, v in raw_slots.items() if isinstance(v, dict)
            }
        raw_max = data.get("max_iterations")
        ledger.max_iterations = int(raw_max) if raw_max is not None else None
        ledger.iteration = int(data.get("iteration") or 0)
        ledger.consecutive_plateaus = int(data.get("consecutive_plateaus") or 0)
        ledger.predicate_status = str(data.get("predicate_status") or "OPEN")
        ledger.hypothesis_status = str(data.get("hypothesis_status") or "UNVALIDATED")
        ledger.evidence_provenance = list(data.get("evidence_provenance") or [])[-_MAX_CALLS_PER_TARGET:]
        if isinstance(data.get("exit_predicate_evaluation"), dict):
            ledger.exit_predicate_evaluation = dict(data["exit_predicate_evaluation"])
        ledger.decision_log = list(data.get("decision_log") or [])[-_MAX_CALLS_PER_TARGET:]
        ledger.code_anchors = list(data.get("code_anchors") or [])[:_MAX_ANCHORS_PER_TARGET]
        ledger._anchor_keys = {
            (a.get("file", ""), a.get("line", 0), a.get("function", ""), a.get("symbol", ""), a.get("variable_path", ""))
            for a in ledger.code_anchors if isinstance(a, dict)
        }
        ledger.dead_end_signatures = set(data.get("dead_end_signatures") or [])
        ledger.calls = list(data.get("calls") or [])[-_MAX_CALLS_PER_TARGET:]
        ledger.revision = int(data.get("revision") or 0)
        ledger.updated_at_epoch = float(data.get("updated_at_epoch") or 0.0)
        ledger._disk_mtime_ns = mtime_ns
        return ledger

    @staticmethod
    def _merge_dict_list(primary: List[Dict[str, Any]], secondary: List[Dict[str, Any]], limit: int) -> List[Dict[str, Any]]:
        merged: List[Dict[str, Any]] = []
        seen = set()
        for item in list(primary or []) + list(secondary or []):
            if not isinstance(item, dict):
                continue
            key = json.dumps(item, sort_keys=True, ensure_ascii=False, default=str)
            if key not in seen:
                seen.add(key)
                merged.append(item)
        return merged[-limit:]

    @classmethod
    def _merge_same_playbook_slot(cls, mslot: Dict[str, Any], dslot: Dict[str, Any]) -> Dict[str, Any]:
        """Merge two concurrent updates to the same playbook slot without silently dropping either writer."""
        m_rev = int(mslot.get("revision") or 0)
        d_rev = int(dslot.get("revision") or 0)
        m_ts = float(mslot.get("updated_at_epoch") or 0.0)
        d_ts = float(dslot.get("updated_at_epoch") or 0.0)
        # Prefer the side with higher revision (or newer timestamp on tie) as base
        base, other = (dict(dslot), mslot) if (d_rev > m_rev or (d_rev == m_rev and d_ts > m_ts)) else (dict(mslot), dslot)

        merged_prov = cls._merge_dict_list(
            other.get("evidence_provenance") or [],
            base.get("evidence_provenance") or [],
            _MAX_CALLS_PER_TARGET,
        )
        merged_dlog = cls._merge_dict_list(
            other.get("decision_log") or [],
            base.get("decision_log") or [],
            _MAX_CALLS_PER_TARGET,
        )
        base["evidence_provenance"] = merged_prov
        base["decision_log"] = merged_dlog
        base["iteration"] = max(int(mslot.get("iteration") or 0), int(dslot.get("iteration") or 0), len(merged_dlog))

        m_ps = str(mslot.get("predicate_status") or "OPEN")
        d_ps = str(dslot.get("predicate_status") or "OPEN")
        if _PREDICATE_SEVERITY_RANK.get(d_ps, 0) > _PREDICATE_SEVERITY_RANK.get(m_ps, 0):
            base["predicate_status"] = d_ps
            if isinstance(dslot.get("exit_predicate_evaluation"), dict):
                base["exit_predicate_evaluation"] = dict(dslot["exit_predicate_evaluation"])
            base["hypothesis_status"] = str(dslot.get("hypothesis_status") or base.get("hypothesis_status") or "UNVALIDATED")
        elif _PREDICATE_SEVERITY_RANK.get(m_ps, 0) > _PREDICATE_SEVERITY_RANK.get(d_ps, 0):
            base["predicate_status"] = m_ps
            if isinstance(mslot.get("exit_predicate_evaluation"), dict):
                base["exit_predicate_evaluation"] = dict(mslot["exit_predicate_evaluation"])
            base["hypothesis_status"] = str(mslot.get("hypothesis_status") or base.get("hypothesis_status") or "UNVALIDATED")

        base["revision"] = max(m_rev, d_rev) + 1
        base["updated_at_epoch"] = max(m_ts, d_ts, time.time())
        return base

    def _merge_newer_disk(self, mem: TargetTrackingLedger, disk: TargetTrackingLedger) -> None:
        """Merge newer disk state into in-memory ledger without losing either side's anchors, logs, or playbook slots."""
        for a in disk.code_anchors:
            if not isinstance(a, dict):
                continue
            ak = (a.get("file", ""), a.get("line", 0), a.get("function", ""), a.get("symbol", ""), a.get("variable_path", ""))
            if ak not in mem._anchor_keys and len(mem.code_anchors) < _MAX_ANCHORS_PER_TARGET:
                mem._anchor_keys.add(ak)
                mem.code_anchors.append(a)
        mem.dead_end_signatures.update(disk.dead_end_signatures)
        mem.calls = self._merge_dict_list(disk.calls, mem.calls, _MAX_CALLS_PER_TARGET)

        active_pb_id = str((mem.active_playbook or {}).get("playbook_id") or "").strip()
        # Merge per-playbook state slots without losing concurrent distinct or same-playbook updates
        for pb_id, dslot in (disk.playbook_slots or {}).items():
            if not isinstance(dslot, dict):
                continue
            mslot = mem.playbook_slots.get(pb_id)
            if mslot is None:
                mem.playbook_slots[pb_id] = dict(dslot)
            elif dslot != mslot:
                merged_slot = self._merge_same_playbook_slot(mslot, dslot)
                mem.playbook_slots[pb_id] = merged_slot
                if pb_id == active_pb_id:
                    mem.iteration = int(merged_slot.get("iteration") or mem.iteration)
                    mem.predicate_status = str(merged_slot.get("predicate_status") or mem.predicate_status)
                    mem.hypothesis_status = str(merged_slot.get("hypothesis_status") or mem.hypothesis_status)
                    mem.evidence_provenance = list(merged_slot.get("evidence_provenance") or mem.evidence_provenance)
                    if isinstance(merged_slot.get("exit_predicate_evaluation"), dict):
                        mem.exit_predicate_evaluation = dict(merged_slot["exit_predicate_evaluation"])
                    mem.decision_log = list(merged_slot.get("decision_log") or mem.decision_log)

        if disk.revision >= mem.revision:
            mem.revision = max(disk.revision, mem.revision) + 1
            mem.decision_log = self._merge_dict_list(disk.decision_log, mem.decision_log, _MAX_CALLS_PER_TARGET)

    @contextlib.contextmanager
    def _file_lock(self, path: str) -> Iterator[None]:
        """Cross-process advisory lock protecting read-merge-replace on ledger persistence."""
        if fcntl is None:
            yield
            return
        os.makedirs(os.path.dirname(path), exist_ok=True)
        lock_path = f"{path}.lock"
        fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            try:
                fcntl.flock(fd, fcntl.LOCK_UN)
            finally:
                os.close(fd)

    def _quarantine_corrupt_file(self, target_key: str, path: str, reason: str) -> Optional[str]:
        """Preserve a corrupted ledger file under a `.corrupt.<ts>` suffix rather than silently overwriting it."""
        ts_ms = int(time.time() * 1000)
        qpath = f"{path}.corrupt.{ts_ms}"
        suffix = 0
        while os.path.exists(qpath):
            suffix += 1
            qpath = f"{path}.corrupt.{ts_ms}.{suffix}"
        quarantined: Optional[str] = None
        try:
            os.replace(path, qpath)
            quarantined = qpath
        except OSError:
            quarantined = None
        ev = {
            "target_key": target_key,
            "original_path": path,
            "quarantine_path": quarantined,
            "reason": str(reason),
            "detected_at_epoch": time.time(),
        }
        self._corruption_events[str(target_key)] = ev
        _LOGGER.warning(
            "Quarantined corrupted tracking ledger for %s (%s): %s -> %s",
            target_key,
            reason,
            path,
            quarantined or "<failed-to-quarantine>",
        )
        return quarantined

    def _try_load(self, target_key: str, *, quarantine_on_corrupt: bool = True) -> Optional[TargetTrackingLedger]:
        path = self._ledger_path(target_key)
        if not path or not os.path.isfile(path):
            return None
        try:
            st = os.stat(path)
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, dict) or data.get("target_key") != target_key:
                if quarantine_on_corrupt:
                    self._quarantine_corrupt_file(target_key, path, "invalid_schema_or_target_key_mismatch")
                return None
            return self._deserialize(target_key, data, mtime_ns=st.st_mtime_ns)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError, TypeError) as exc:
            if quarantine_on_corrupt:
                self._quarantine_corrupt_file(target_key, path, f"{type(exc).__name__}: {exc}")
            return None
        except OSError as exc:
            _LOGGER.warning("Failed to read tracking ledger %s: %s", path, exc)
            return None

    @staticmethod
    def _fsync_parent_dir(path: str) -> None:
        parent = os.path.dirname(os.path.abspath(path))
        if not parent:
            return
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        try:
            dir_fd = os.open(parent, flags)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)
        except OSError:
            pass

    def save(self, target_key: str) -> bool:
        path = self._ledger_path(target_key)
        if not path:
            return False
        with self._lock:
            ledger = self._ledgers.get(target_key)
            if ledger is None:
                return False
            try:
                with self._file_lock(path):
                    # Guard against stale in-memory state overwriting newer disk state or concurrent playbooks
                    disk_existing = self._try_load(target_key, quarantine_on_corrupt=True)
                    _has_divergent_disk_slot = (
                        disk_existing is not None
                        and any(
                            isinstance(dslot, dict)
                            and (
                                pb_id not in ledger.playbook_slots
                                or int(dslot.get("revision") or 0) > int((ledger.playbook_slots.get(pb_id) or {}).get("revision") or 0)
                                or (
                                    int(dslot.get("revision") or 0) == int((ledger.playbook_slots.get(pb_id) or {}).get("revision") or 0)
                                    and dslot != ledger.playbook_slots.get(pb_id)
                                )
                            )
                            for pb_id, dslot in (disk_existing.playbook_slots or {}).items()
                        )
                    )
                    if disk_existing is not None and (
                        disk_existing.revision > ledger.revision
                        or _has_divergent_disk_slot
                        or (disk_existing._disk_mtime_ns > ledger._disk_mtime_ns and disk_existing.updated_at_epoch >= ledger.updated_at_epoch)
                    ):
                        self._merge_newer_disk(ledger, disk_existing)
                    data = {
                        "target_key": ledger.target_key,
                        "revision": ledger.revision,
                        "updated_at_epoch": ledger.updated_at_epoch,
                        "active_playbook": ledger.active_playbook,
                        "playbook_slots": ledger.playbook_slots,
                        "max_iterations": ledger.max_iterations,
                        "iteration": ledger.iteration,
                        "consecutive_plateaus": ledger.consecutive_plateaus,
                        "predicate_status": ledger.predicate_status,
                        "hypothesis_status": ledger.hypothesis_status,
                        "evidence_provenance": ledger.evidence_provenance[-_MAX_CALLS_PER_TARGET:],
                        "exit_predicate_evaluation": ledger.exit_predicate_evaluation,
                        "decision_log": ledger.decision_log[-_MAX_CALLS_PER_TARGET:],
                        "code_anchors": ledger.code_anchors[:_MAX_ANCHORS_PER_TARGET],
                        "dead_end_signatures": sorted(ledger.dead_end_signatures),
                        "calls": ledger.calls[-_MAX_CALLS_PER_TARGET:],
                    }
                    os.makedirs(os.path.dirname(path), exist_ok=True)
                    tmp = f"{path}.{os.getpid()}.{threading.get_ident()}.{time.monotonic_ns()}.tmp"
                    open_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    if hasattr(os, "O_NOFOLLOW"):
                        open_flags |= os.O_NOFOLLOW
                    fd = os.open(tmp, open_flags, 0o600)
                    try:
                        with os.fdopen(fd, "w", encoding="utf-8") as f:
                            json.dump(data, f, ensure_ascii=False, indent=2)
                            f.flush()
                            os.fsync(f.fileno())
                        os.replace(tmp, path)
                        self._fsync_parent_dir(path)
                    except BaseException:
                        try:
                            if os.path.exists(tmp):
                                os.unlink(tmp)
                        except OSError:
                            pass
                        raise
                    try:
                        ledger._disk_mtime_ns = os.stat(path).st_mtime_ns
                    except OSError:
                        pass
                    return True
            except OSError:
                return False

    def _put_bounded_locked(self, target_key: str, ledger: TargetTrackingLedger) -> None:
        self._ledgers[target_key] = ledger
        self._ledgers.move_to_end(target_key)
        while len(self._ledgers) > self._max_targets:
            self._ledgers.popitem(last=False)

    def get_or_create(self, target_key: str) -> TargetTrackingLedger:
        with self._lock:
            ledger = self._ledgers.get(target_key)
            if ledger is None:
                ledger = self._try_load(target_key) or TargetTrackingLedger(target_key)
                self._put_bounded_locked(target_key, ledger)
            else:
                # Check if disk has a newer revision (e.g. written by another worker/process)
                disk = self._try_load(target_key)
                if disk is not None and disk.revision > ledger.revision:
                    ledger = disk
                    self._put_bounded_locked(target_key, ledger)
                else:
                    self._ledgers.move_to_end(target_key)
            return ledger

    def get(self, target_key: str) -> Optional[TargetTrackingLedger]:
        """Retrieve a ledger from memory OR recover it from disk persistence after restart."""
        with self._lock:
            ledger = self._ledgers.get(target_key)
            disk = self._try_load(target_key)
            if ledger is None:
                if disk is not None:
                    self._put_bounded_locked(target_key, disk)
                    return disk
                return None
            if disk is not None and disk.revision > ledger.revision:
                self._put_bounded_locked(target_key, disk)
                return disk
            self._ledgers.move_to_end(target_key)
            return ledger

    def clear(self) -> None:
        with self._lock:
            self._ledgers.clear()


GLOBAL_TRACKING_LEDGER = TrackingLedgerStore()


def enrich_tool_response(
    tool_name: str,
    payload: Dict[str, Any],
    *,
    pid: Optional[int] = None,
    companion_elf: Optional[str] = None,
    args: Optional[Dict[str, Any]] = None,
    remote_target: Optional[Dict[str, Any]] = None,
    ledger_store: Optional[TrackingLedgerStore] = None,
    now: Optional[float] = None,
) -> Dict[str, Any]:
    """Record a tool call in the tracking ledger and attach delta_from_last_call,
    code_anchors, filtered next_drilldown, recovery_actions, and tracking_context.
    """
    if not isinstance(payload, dict):
        return payload
    store = ledger_store or GLOBAL_TRACKING_LEDGER
    tkey = make_target_key(pid, remote_target)
    ledger = store.get_or_create(tkey)
    delta, new_anchors = ledger.record(tool_name, args, payload, now=now)

    if delta is not None:
        payload["delta_from_last_call"] = delta
    if new_anchors:
        payload["code_anchors"] = new_anchors

    # Build or filter next_drilldown
    existing_next = payload.get("next_drilldown")
    if existing_next is None and pid is not None and payload.get("success") is not False:
        from .state_intelligence import build_narrow_tool_next_steps
        existing_next = build_narrow_tool_next_steps(
            tool_name, payload, pid=pid, companion_elf=companion_elf, remote_target=remote_target
        )
    if isinstance(existing_next, list) and existing_next:
        filtered, suppressed = ledger.filter_actions(existing_next)
        if filtered:
            payload["next_drilldown"] = filtered
        else:
            payload.pop("next_drilldown", None)
        if suppressed:
            payload["suppressed_repeat_actions"] = suppressed

    # Attach self-recovery actions on error or empty result
    rec_actions = build_recovery_actions(
        tool_name, payload, pid=pid, companion_elf=companion_elf, args=args, remote_target=remote_target
    )
    if rec_actions:
        filtered_rec, _ = ledger.filter_actions(rec_actions)
        if filtered_rec:
            payload["recovery_actions"] = filtered_rec

    payload["tracking_context"] = ledger.summary()
    store.save(tkey)
    return payload

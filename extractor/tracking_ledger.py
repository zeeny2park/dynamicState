"""Cross-call Investigation Ledger, Repeat-Call Delta Tracker, Code-Anchor Extractor,
and Self-Recovery Action Builder for continuous LLM coding-agent troubleshooting.
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Any, Dict, List, Optional, Tuple


_MAX_TARGETS = 32
_MAX_CALLS_PER_TARGET = 24
_MAX_ANCHORS_PER_TARGET = 32

# Tools that are intentionally called repeatedly to observe time progression
_TEMPORAL_REPEAT_TOOLS = frozenset({
    "runtime_capture_and_diff",
    "runtime_watch_until_condition",
    "runtime_flight_recorder_time_machine",
    "runtime_detect_behavioral_drift",
})


def make_target_key(pid: Optional[int], remote_target: Optional[Dict[str, Any]] = None) -> str:
    host = "local"
    if isinstance(remote_target, dict) and remote_target.get("remote_host"):
        host = str(remote_target["remote_host"]).strip()
    return f"{host}:{int(pid) if pid is not None else 'none'}"


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
    """Per-target in-memory investigation ledger across consecutive MCP tool calls."""

    def __init__(self, target_key: str):
        self.target_key = target_key
        self.created_at = time.monotonic()
        self.calls: List[Dict[str, Any]] = []
        self.last_by_tool: Dict[str, Tuple[float, Dict[str, Any]]] = {}
        self.dead_end_signatures: set = set()
        self.tried_signatures: Dict[str, int] = {}
        self.code_anchors: List[Dict[str, Any]] = []
        self._anchor_keys: set = set()
        # Playbook Loop State Machine (pstack-inspired)
        self.active_playbook: Optional[Dict[str, Any]] = None
        self.max_iterations: int = 6
        self.iteration: int = 0
        self.consecutive_plateaus: int = 0
        self.predicate_status: str = "OPEN"  # OPEN | MET | PIVOT_REQUIRED | BLOCKED | EXHAUSTED
        self.decision_log: List[Dict[str, Any]] = []

    def activate_playbook(
        self,
        playbook: Dict[str, Any],
        *,
        max_iterations: Optional[int] = None,
    ) -> Dict[str, Any]:
        self.active_playbook = dict(playbook)
        self.max_iterations = max(1, int(max_iterations or playbook.get("default_max_iterations") or 6))
        self.iteration = 0
        self.consecutive_plateaus = 0
        self.predicate_status = "OPEN"
        return self.loop_state()

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
            "consecutive_plateaus": self.consecutive_plateaus,
            "next_planned_step": next_step,
            "pivot_recommendation": pivot_hint,
            "decision_log": self.decision_log[-8:],
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

        # Update Playbook Loop State Machine on every recorded call
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
                or (tool_name == "runtime_correlate_source_and_state" and not empty)
            )
        )
        if is_hard_blocked:
            self.predicate_status = "BLOCKED"
        elif verdict in ("FAULT", "DEFECT_CONFIRMED") and len(self.code_anchors) > 0:
            self.predicate_status = "MET"
            self.consecutive_plateaus = 0
        elif tool_name == "runtime_correlate_source_and_state" and len(self.code_anchors) > 0:
            self.predicate_status = "MET"
            self.consecutive_plateaus = 0
        elif self.iteration >= self.max_iterations:
            self.predicate_status = "EXHAUSTED"
        elif evidence_moved:
            self.consecutive_plateaus = 0
            self.predicate_status = "OPEN"
        else:
            self.consecutive_plateaus += 1
            if self.consecutive_plateaus >= 2:
                self.predicate_status = "PIVOT_REQUIRED"
            else:
                self.predicate_status = "OPEN"

        self.decision_log.append({
            "iter": self.iteration,
            "tool": tool_name,
            "evidence_moved": evidence_moved,
            "new_anchors": len(new_anchors),
            "predicate_status": self.predicate_status,
            "note": (delta.get("summary") if isinstance(delta, dict) else ("empty/failed" if empty else "observed")),
        })
        if len(self.decision_log) > _MAX_CALLS_PER_TARGET:
            self.decision_log = self.decision_log[-_MAX_CALLS_PER_TARGET:]

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
            "loop_state": self.loop_state(),
        }


class TrackingLedgerStore:
    """Thread-safe bounded LRU store of per-target TargetTrackingLedger instances."""

    def __init__(self, max_targets: int = _MAX_TARGETS):
        self._lock = threading.Lock()
        self._max_targets = max_targets
        self._ledgers: "OrderedDict[str, TargetTrackingLedger]" = OrderedDict()

    def get_or_create(self, target_key: str) -> TargetTrackingLedger:
        with self._lock:
            ledger = self._ledgers.get(target_key)
            if ledger is None:
                ledger = TargetTrackingLedger(target_key)
                self._ledgers[target_key] = ledger
                if len(self._ledgers) > self._max_targets:
                    self._ledgers.popitem(last=False)
            else:
                self._ledgers.move_to_end(target_key)
            return ledger

    def get(self, target_key: str) -> Optional[TargetTrackingLedger]:
        with self._lock:
            return self._ledgers.get(target_key)

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
    return payload

"""Capture-and-diff of expressions, golden baselines (save / list / compare) and the scenario recipe runner.

Moved verbatim from extractor/watch_session.py; functions take the ``WatchSessionManager`` first (``mgr``) and
are bound on it as methods.
"""

import json
import os
import tempfile
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..debug_image import inspect_elf
from ..dwarf_indexer import DwarfIndexer
from ..target_adapter import TargetExecutionAdapter
from .process_memory import ZERO_STOP_NON_ATOMIC_CONSISTENCY


def capture_and_diff_expressions(
    mgr,
    pid: int,
    companion_elf_path: str,
    expressions: Optional[List[str]] = None,
    wait_ms: int = 500,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    ssh_proxy_command: Optional[str] = None,
    adapter: Optional[TargetExecutionAdapter] = None,
) -> Dict[str, Any]:
    """Samples a set of symbol expressions twice separated by `wait_ms` (without stopping the target)
        and returns a structured comparison of changed, unchanged, and unreadable fields.
        """
    target_adapter = mgr._resolve_adapter(
        pid=pid,
        remote_host=remote_host,
        ssh_user=ssh_user,
        ssh_port=ssh_port,
        ssh_key=ssh_key,
        ssh_proxy_jump=ssh_proxy_jump,
        ssh_proxy_command=ssh_proxy_command,
        adapter=adapter,
    )

    ctx_info = mgr.resolve_target_context(
        pid=pid,
        companion_elf_path=companion_elf_path,
        remote_host=remote_host,
        ssh_user=ssh_user,
        ssh_port=ssh_port,
        ssh_key=ssh_key,
        ssh_proxy_jump=ssh_proxy_jump,
        adapter=adapter,
    )
    pid = ctx_info["pid"]
    companion_elf_path = ctx_info["companion_elf_path"]
    primary_elf, _ = mgr._split_companion_elf_paths(companion_elf_path)
    idx = DwarfIndexer.get_index(primary_elf or companion_elf_path)
    expr_list = mgr._coerce_str_list(expressions)
    if not expr_list:
        # Automatically pick top ranked global/static variables
        top_syms = idx.search_symbols(query="", category="variables", limit=15, smart_rank=True)
        expr_list = [s["name"] for s in top_syms]

    snap_a = mgr.evaluate_symbol_paths(
        pid=pid,
        companion_elf_path=companion_elf_path,
        expressions=expr_list,
        adapter=target_adapter,
    )

    clamped_wait_ms = max(10, min(int(wait_ms), 30000))
    time.sleep(clamped_wait_ms / 1000.0)

    snap_b = mgr.evaluate_symbol_paths(
        pid=pid,
        companion_elf_path=companion_elf_path,
        expressions=expr_list,
        adapter=target_adapter,
    )

    def _flatten_val(prefix: str, val: Any, out: Dict[str, Any]) -> None:
        if isinstance(val, dict):
            for k, v in val.items():
                _flatten_val(f"{prefix}.{k}", v, out)
        else:
            out[prefix] = val

    changed: List[Dict[str, Any]] = []
    unchanged: List[Dict[str, Any]] = []
    unreadable: List[Dict[str, Any]] = []

    map_a = {r["expression"]: r for r in snap_a.get("results", [])}
    map_b = {r["expression"]: r for r in snap_b.get("results", [])}

    for expr_str in expr_list:
        ra = map_a.get(expr_str, {})
        rb = map_b.get(expr_str, {})
        st_a = ra.get("status", "MISSING")
        st_b = rb.get("status", "MISSING")

        if st_a != "OBSERVED" or st_b != "OBSERVED":
            unreadable.append({
                "expression": expr_str,
                "status_before": st_a,
                "status_after": st_b,
                "error": rb.get("error") or ra.get("error"),
            })
            continue

        flat_a: Dict[str, Any] = {}
        flat_b: Dict[str, Any] = {}
        _flatten_val(expr_str, ra.get("value"), flat_a)
        _flatten_val(expr_str, rb.get("value"), flat_b)

        all_keys = sorted(set(flat_a.keys()) | set(flat_b.keys()))
        for k in all_keys:
            va = flat_a.get(k)
            vb = flat_b.get(k)
            if va != vb:
                delta = (vb - va) if (isinstance(va, (int, float)) and isinstance(vb, (int, float)) and not isinstance(va, bool) and not isinstance(vb, bool)) else None
                changed.append({
                    "path": k,
                    "root_expression": expr_str,
                    "before": va,
                    "after": vb,
                    "delta": delta,
                    "runtime_address": rb.get("runtime_address"),
                    "type_name": rb.get("type_name"),
                })
            else:
                unchanged.append({
                    "path": k,
                    "root_expression": expr_str,
                    "value": va,
                    "runtime_address": rb.get("runtime_address"),
                    "type_name": rb.get("type_name"),
                })

    return {
        "pid": pid,
        "target_host": target_adapter.target_host(),
        "is_remote": target_adapter.is_remote(),
        "wait_ms": clamped_wait_ms,
        "stop_duration_ms": 0.0,
        "timestamp_before": snap_a.get("timestamp"),
        "timestamp_after": snap_b.get("timestamp"),
        "summary": {
            "expressions_evaluated": len(expr_list),
            "changed_count": len(changed),
            "unchanged_count": len(unchanged),
            "unreadable_count": len(unreadable),
        },
        "changed": changed,
        "unchanged": unchanged,
        "unreadable": unreadable,
        "consistency": dict(ZERO_STOP_NON_ATOMIC_CONSISTENCY),
    }


# -------------------------------------------------------------------------
# Phase 34 (Phase 3): Golden Baseline Management & Diagnostic Recipes
# -------------------------------------------------------------------------

def _auto_select_diagnostic_expressions(
    mgr,
    companion_elf_path: str,
    max_items: int = 12,
) -> List[str]:
    """Automatically selects top state, counter, queue, and pointer-target expressions from DWARF."""
    idx = DwarfIndexer.get_index(companion_elf_path)
    top_syms = idx.search_symbols(query="", category="variables", limit=max_items, smart_rank=True)
    exprs: List[str] = []
    for s in top_syms:
        name = s.get("name", "")
        if not name:
            continue
        if s.get("is_pointer") and s.get("members"):
            for m in s["members"][:3]:
                m_expr = m.get("expression") or f"{name}->{m['name']}"
                if m_expr not in exprs:
                    exprs.append(m_expr)
        else:
            if name not in exprs:
                exprs.append(name)
        if len(exprs) >= max_items:
            break
    return exprs


def save_golden_baseline(
    mgr,
    pid: int,
    companion_elf_path: str,
    label: str = "Golden Baseline",
    expressions: Optional[List[str]] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    adapter: Optional[TargetExecutionAdapter] = None,
) -> Dict[str, Any]:
    """Captures current target state for key symbol expressions and persists it as a Golden Baseline."""
    target_adapter = mgr._resolve_adapter(
        pid=pid,
        remote_host=remote_host,
        ssh_user=ssh_user,
        ssh_port=ssh_port,
        ssh_key=ssh_key,
        ssh_proxy_jump=ssh_proxy_jump,
        adapter=adapter,
    )
    expr_list = [e.strip() for e in (expressions or []) if e and e.strip()]
    if not expr_list:
        expr_list = mgr._auto_select_diagnostic_expressions(companion_elf_path, max_items=15)

    eval_res = mgr.evaluate_symbol_paths(
        pid=pid,
        companion_elf_path=companion_elf_path,
        expressions=expr_list,
        adapter=target_adapter,
    )
    elf_ident = inspect_elf(companion_elf_path)
    baseline_id = f"golden_{int(time.time())}_{uuid.uuid4().hex[:6]}"
    clean_label = (label or "Golden Baseline").strip()

    def _flatten(prefix: str, val: Any, out: Dict[str, Any]) -> None:
        if isinstance(val, dict):
            for k, v in val.items():
                _flatten(f"{prefix}.{k}", v, out)
        else:
            out[prefix] = val

    flat_values: Dict[str, Any] = {}
    for r in eval_res.get("results", []):
        if r.get("status") == "OBSERVED":
            _flatten(r["expression"], r.get("value"), flat_values)

    record = {
        "baseline_id": baseline_id,
        "label": clean_label,
        "pid": pid,
        "target_host": target_adapter.target_host(),
        "is_remote": target_adapter.is_remote(),
        "companion_elf_path": os.path.abspath(companion_elf_path),
        "binary_build_id": elf_ident.build_id,
        "architecture": elf_ident.architecture,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "expressions": expr_list,
        "results": eval_res.get("results", []),
        "flattened_values": flat_values,
    }

    file_path = os.path.join(mgr.baselines_dir, f"{baseline_id}.json")
    tmp_fd, tmp_path = tempfile.mkstemp(dir=mgr.baselines_dir, prefix="gold_", suffix=".tmp")
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            json.dump(record, f, indent=2, ensure_ascii=False)
        os.replace(tmp_path, file_path)
    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise

    return record


def list_golden_baselines(mgr, binary_build_id: Optional[str] = None) -> List[Dict[str, Any]]:
    """Lists all persisted Golden Baselines, sorted newest first."""
    items: List[Dict[str, Any]] = []
    if not os.path.exists(mgr.baselines_dir):
        return items
    target_bid = (binary_build_id or "").strip().lower() or None
    for entry in os.listdir(mgr.baselines_dir):
        if not entry.endswith(".json"):
            continue
        p = os.path.join(mgr.baselines_dir, entry)
        try:
            with open(p, "r", encoding="utf-8") as f:
                d = json.load(f)
            bid = (d.get("binary_build_id") or "").lower()
            if target_bid and bid and bid != target_bid:
                continue
            items.append({
                "baseline_id": d.get("baseline_id"),
                "label": d.get("label"),
                "pid": d.get("pid"),
                "target_host": d.get("target_host", "localhost"),
                "binary_build_id": d.get("binary_build_id"),
                "companion_elf_path": d.get("companion_elf_path"),
                "created_at": d.get("created_at"),
                "expressions_count": len(d.get("expressions", [])),
                "fields_count": len(d.get("flattened_values", {})),
            })
        except Exception:
            pass
    items.sort(key=lambda x: x.get("created_at") or "", reverse=True)
    return items


def get_golden_baseline(mgr, baseline_id: str) -> Optional[Dict[str, Any]]:
    """Loads a Golden Baseline record by ID."""
    if not baseline_id:
        return None
    safe_id = os.path.basename(baseline_id)
    p = os.path.join(mgr.baselines_dir, f"{safe_id}.json")
    if not os.path.isfile(p):
        return None
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def compare_with_golden_baseline(
    mgr,
    baseline_id: str,
    pid: int,
    companion_elf_path: Optional[str] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    adapter: Optional[TargetExecutionAdapter] = None,
) -> Dict[str, Any]:
    """Compares current live process state against a saved Golden Baseline without stopping the target."""
    baseline = mgr.get_golden_baseline(baseline_id)
    if not baseline:
        raise ValueError(f"Golden baseline '{baseline_id}' not found")

    elf_path = companion_elf_path or baseline.get("companion_elf_path")
    if not elf_path or not os.path.isfile(elf_path):
        raise FileNotFoundError(f"Companion ELF not found for baseline comparison: '{elf_path}'")

    exprs = baseline.get("expressions") or []
    live_eval = mgr.evaluate_symbol_paths(
        pid=pid,
        companion_elf_path=elf_path,
        expressions=exprs,
        remote_host=remote_host,
        ssh_user=ssh_user,
        ssh_port=ssh_port,
        ssh_key=ssh_key,
        ssh_proxy_jump=ssh_proxy_jump,
        adapter=adapter,
    )

    def _flatten(prefix: str, val: Any, out: Dict[str, Any]) -> None:
        if isinstance(val, dict):
            for k, v in val.items():
                _flatten(f"{prefix}.{k}", v, out)
        else:
            out[prefix] = val

    live_flat: Dict[str, Any] = {}
    unreadable: List[Dict[str, Any]] = []
    for r in live_eval.get("results", []):
        if r.get("status") == "OBSERVED":
            _flatten(r["expression"], r.get("value"), live_flat)
        else:
            unreadable.append({
                "expression": r.get("expression"),
                "status": r.get("status"),
                "error": r.get("error"),
            })

    gold_flat = baseline.get("flattened_values") or {}
    changed: List[Dict[str, Any]] = []
    unchanged: List[Dict[str, Any]] = []

    for k in sorted(set(gold_flat.keys()) | set(live_flat.keys())):
        if k not in live_flat:
            continue
        gv = gold_flat.get(k)
        lv = live_flat.get(k)
        if gv != lv:
            delta = (lv - gv) if (isinstance(gv, (int, float)) and isinstance(lv, (int, float)) and not isinstance(gv, bool) and not isinstance(lv, bool)) else None
            changed.append({
                "path": k,
                "golden_value": gv,
                "live_value": lv,
                "delta": delta,
            })
        else:
            unchanged.append({
                "path": k,
                "value": lv,
            })

    return {
        "baseline_id": baseline_id,
        "baseline_label": baseline.get("label"),
        "baseline_created_at": baseline.get("created_at"),
        "pid": pid,
        "target_host": live_eval.get("target_host", "localhost"),
        "is_remote": live_eval.get("is_remote", False),
        "stop_duration_ms": 0.0,
        "compared_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_fields_compared": len(changed) + len(unchanged),
            "changed_count": len(changed),
            "unchanged_count": len(unchanged),
            "unreadable_count": len(unreadable),
        },
        "changed": changed,
        "unchanged": unchanged,
        "unreadable": unreadable,
    }


def run_diagnostic_recipe(
    mgr,
    recipe: str,
    pid: int,
    companion_elf_path: str,
    expressions: Optional[List[str]] = None,
    duration_ms: int = 1200,
    interval_ms: int = 200,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    adapter: Optional[TargetExecutionAdapter] = None,
) -> Dict[str, Any]:
    """Executes one of the 3 guided diagnostic recipes:
        1. `instant_xray`: Immediate zero-stop state decode of top state/pointer variables.
        2. `before_after_diff`: Two-point snapshot diff across `duration_ms` window.
        3. `timeseries_watch`: Automated Watch Session sampling over `duration_ms`, classifying active vs stuck variables.
        """
    recipe_key = (recipe or "instant_xray").strip().lower()
    target_adapter = mgr._resolve_adapter(
        pid=pid,
        remote_host=remote_host,
        ssh_user=ssh_user,
        ssh_port=ssh_port,
        ssh_key=ssh_key,
        ssh_proxy_jump=ssh_proxy_jump,
        adapter=adapter,
    )
    expr_list = [e.strip() for e in (expressions or []) if e and e.strip()]
    if not expr_list:
        expr_list = mgr._auto_select_diagnostic_expressions(companion_elf_path, max_items=12)

    if recipe_key in ("instant_xray", "xray", "snapshot"):
        ev = mgr.evaluate_symbol_paths(
            pid=pid,
            companion_elf_path=companion_elf_path,
            expressions=expr_list,
            adapter=target_adapter,
        )
        flat_state: Dict[str, Any] = {}
        for r in ev.get("results", []):
            if r.get("status") == "OBSERVED":
                if isinstance(r.get("value"), dict):
                    for k, v in r["value"].items():
                        flat_state[f"{r['expression']}.{k}"] = v
                else:
                    flat_state[r["expression"]] = r.get("value")
        return {
            "recipe": "instant_xray",
            "title": "Instant State X-Ray (Zero-Stop)",
            "pid": pid,
            "target_host": target_adapter.target_host(),
            "stop_duration_ms": 0.0,
            "expressions": expr_list,
            "flattened_state": flat_state,
            "results": ev.get("results", []),
        }

    if recipe_key in ("before_after_diff", "diff"):
        diff_data = mgr.capture_and_diff_expressions(
            pid=pid,
            companion_elf_path=companion_elf_path,
            expressions=expr_list,
            wait_ms=max(50, min(int(duration_ms), 15000)),
            adapter=target_adapter,
        )
        return {
            "recipe": "before_after_diff",
            "title": f"Before/After State Diff ({diff_data['wait_ms']} ms window)",
            **diff_data,
        }

    if recipe_key in ("timeseries_watch", "auto_watch", "watch"):
        clamped_int = max(50, min(int(interval_ms), 2000))
        clamped_dur = max(200, min(int(duration_ms), 15000))
        num_samples = max(2, min(20, int(clamped_dur // clamped_int) + 1))

        session = mgr.create_session(
            pid=pid,
            companion_elf_path=companion_elf_path,
            interval_ms=0,
            capture_mode="MANUAL",
            adapter=target_adapter,
        )
        for ex in expr_list:
            try:
                mgr.add_watch_item(session.session_id, {
                    "name": ex,
                    "expression": ex,
                    "address": 0,
                    "scope": "expression",
                    "source": "diagnostic_recipe",
                })
            except Exception:
                pass

        for s_idx in range(num_samples):
            mgr.capture_once(session.session_id)
            if s_idx + 1 < num_samples:
                time.sleep(clamped_int / 1000.0)

        obs_list = session.observations
        active_vars: List[Dict[str, Any]] = []
        stuck_vars: List[Dict[str, Any]] = []

        for w in session.watch_items:
            series = []
            for o in obs_list:
                ve = o.values.get(w.item_id, {})
                if ve.get("status") == "OBSERVED":
                    series.append(ve.get("value"))
            if not series:
                continue
            first_v = series[0]
            last_v = series[-1]
            transitions = sum(1 for i in range(1, len(series)) if series[i] != series[i - 1])
            entry_summary = {
                "item_id": w.item_id,
                "name": w.name,
                "type_name": w.type_name,
                "address": f"0x{w.address:x}",
                "samples_count": len(series),
                "first_value": first_v,
                "last_value": last_v,
                "transitions_count": transitions,
            }
            if transitions > 0:
                active_vars.append(entry_summary)
            else:
                stuck_vars.append(entry_summary)

        return {
            "recipe": "timeseries_watch",
            "title": f"Auto Time-Series Watch ({len(obs_list)} samples over {clamped_dur} ms)",
            "session_id": session.session_id,
            "pid": pid,
            "target_host": target_adapter.target_host(),
            "stop_duration_ms": 0.0,
            "samples_captured": len(obs_list),
            "summary": {
                "watched_count": len(session.watch_items),
                "active_changing_count": len(active_vars),
                "stuck_unchanged_count": len(stuck_vars),
            },
            "active_variables": active_vars,
            "stuck_variables": stuck_vars,
        }

    raise ValueError(f"Unknown diagnostic recipe '{recipe}'. Supported: instant_xray, before_after_diff, timeseries_watch")

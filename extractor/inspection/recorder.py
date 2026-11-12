"""Temporal inspection: watch-until-condition, the flight recorder (time machine) and behavioural drift against a
golden baseline.

Moved verbatim from extractor/watch_session.py; functions take the ``WatchSessionManager`` first (``mgr``) and
are bound on it as methods.
"""

import re
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..dwarf_indexer import DwarfIndexer
from ..target_adapter import TargetExecutionAdapter


# -------------------------------------------------------------------------
# Phase 40 (Phase 10): 6 Advanced LLM MCP Engine Capabilities
# -------------------------------------------------------------------------

def _parse_condition_clauses(condition_expression: str) -> Tuple[str, List[Dict[str, Any]], List[str]]:
    """Parses a condition expression like:
        - `gpMem->active_buffers >= 5`
        - `gpMem->buffers[9].in_use == 1 && gpMem->active_buffers > 0`
        - `ANY_CHANGE`
        Returns (combinator, clauses, referenced_symbols).
        """
    raw = (condition_expression or "").strip()
    if not raw or raw.upper() in ("ANY_CHANGE", "CHANGE", "CHANGED", "*"):
        return "ANY_CHANGE", [], []

    combinator = "AND"
    if "||" in raw or " or " in raw.lower():
        combinator = "OR"
        parts = re.split(r"\|\||\bor\b", raw, flags=re.IGNORECASE)
    else:
        parts = re.split(r"&&|\band\b", raw, flags=re.IGNORECASE)

    clauses: List[Dict[str, Any]] = []
    symbols: List[str] = []
    op_regex = re.compile(r"^(.*?)\s*(==|!=|>=|<=|>|<)\s*(.+)$")

    for p in parts:
        p_str = p.strip()
        if not p_str:
            continue
        m = op_regex.match(p_str)
        if m:
            lhs = m.group(1).strip()
            op = m.group(2).strip()
            rhs_raw = m.group(3).strip()
            rhs_val: Any = rhs_raw
            if rhs_raw.lower() in ("true", "null", "nullptr"):
                rhs_val = 1 if rhs_raw.lower() == "true" else 0
            elif rhs_raw.lower() == "false":
                rhs_val = 0
            elif rhs_raw.startswith("0x") or rhs_raw.startswith("0X"):
                try:
                    rhs_val = int(rhs_raw, 16)
                except ValueError:
                    rhs_val = rhs_raw
            else:
                try:
                    rhs_val = int(rhs_raw)
                except ValueError:
                    try:
                        rhs_val = float(rhs_raw)
                    except ValueError:
                        rhs_val = rhs_raw.strip("'\"")
            clauses.append({"lhs": lhs, "op": op, "rhs": rhs_val, "raw": p_str})
            if lhs not in symbols:
                symbols.append(lhs)
        else:
            clauses.append({"lhs": p_str, "op": "TRUTHY", "rhs": 0, "raw": p_str})
            if p_str not in symbols:
                symbols.append(p_str)

    return combinator, clauses, symbols


def _coerce_numeric_or_str(val: Any) -> Any:
    if isinstance(val, (int, float)):
        return val
    if isinstance(val, str):
        s = val.strip()
        if s.startswith("0x") or s.startswith("0X"):
            try:
                return int(s, 16)
            except ValueError:
                pass
        m_enum = re.search(r"\((-?\d+)\)\s*$", s)
        if m_enum:
            try:
                return int(m_enum.group(1))
            except ValueError:
                pass
        try:
            return int(s)
        except ValueError:
            try:
                return float(s)
            except ValueError:
                return s
    return val


def _evaluate_parsed_clauses(
    cls,
    combinator: str,
    clauses: List[Dict[str, Any]],
    current_vals: Dict[str, Any],
    baseline_vals: Dict[str, Any],
) -> Tuple[bool, List[Dict[str, Any]]]:
    if combinator == "ANY_CHANGE":
        diffs = []
        for k, v in current_vals.items():
            if k in baseline_vals and baseline_vals[k] != v:
                diffs.append({"expression": k, "before": baseline_vals[k], "after": v, "matched": True})
        return (len(diffs) > 0), diffs

    if not clauses:
        return False, []

    clause_results: List[Dict[str, Any]] = []
    bools: List[bool] = []
    for c in clauses:
        lhs_expr = c["lhs"]
        op = c["op"]
        rhs = c["rhs"]
        raw_obs = current_vals.get(lhs_expr)
        obs = cls._coerce_numeric_or_str(raw_obs)
        rhs_cmp = cls._coerce_numeric_or_str(rhs)

        matched = False
        try:
            if op == "TRUTHY":
                matched = bool(obs) and obs != 0 and obs != "0x0"
            elif op == "==":
                matched = (obs == rhs_cmp)
            elif op == "!=":
                matched = (obs != rhs_cmp)
            elif op == ">=":
                matched = (obs >= rhs_cmp)  # type: ignore[operator]
            elif op == "<=":
                matched = (obs <= rhs_cmp)  # type: ignore[operator]
            elif op == ">":
                matched = (obs > rhs_cmp)   # type: ignore[operator]
            elif op == "<":
                matched = (obs < rhs_cmp)   # type: ignore[operator]
        except Exception:
            matched = False

        bools.append(matched)
        clause_results.append({
            "clause": c["raw"],
            "lhs": lhs_expr,
            "observed_value": raw_obs,
            "operator": op,
            "expected_rhs": rhs,
            "matched": matched,
        })

    overall = any(bools) if combinator == "OR" else all(bools)
    return overall, clause_results


def watch_until_condition(
    mgr,
    pid: int,
    companion_elf_path: str,
    condition_expression: str,
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
    adapter: Optional[TargetExecutionAdapter] = None,
) -> Dict[str, Any]:
    """Zero-stop conditional watchpoint & anomaly snapshot catcher.
        Polls target symbol expressions at `poll_interval_ms` without stopping the target process (zero-stop),
        evaluates `condition_expression` (or waits until it holds continuously for `hold_duration_ms`),
        and immediately captures a before/after state diff + optional thread owner reverse-lookup on hit.
        """
    target_adapter = mgr._resolve_adapter(
        pid=pid,
        remote_host=remote_host,
        ssh_user=ssh_user,
        ssh_port=ssh_port,
        ssh_key=ssh_key,
        ssh_proxy_jump=ssh_proxy_jump,
        adapter=adapter,
    )

    combinator, clauses, cond_symbols = mgr._parse_condition_clauses(condition_expression)
    all_exprs: List[str] = []
    for s in cond_symbols:
        if s and s not in all_exprs:
            all_exprs.append(s)
    for w in (watch_expressions or []):
        w_s = (w or "").strip()
        if w_s and w_s not in all_exprs:
            all_exprs.append(w_s)

    if not all_exprs:
        # Auto-populate top state variables if ANY_CHANGE with no explicit watch_expressions
        primary_elf, _ = mgr._split_companion_elf_paths(companion_elf_path)
        idx = DwarfIndexer.get_index(primary_elf)
        top_syms = idx.search_symbols(query="", category="variables", limit=6, smart_rank=True)
        all_exprs = [s["name"] for s in top_syms if s.get("name")]

    clamped_poll_ms = max(10, min(int(poll_interval_ms), 5000))
    clamped_timeout_ms = max(20, min(int(timeout_ms), 30000))
    clamped_hold_ms = max(0, min(int(hold_duration_ms), clamped_timeout_ms))

    def _sample_flat() -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
        eval_res = mgr.evaluate_symbol_paths(
            pid=pid,
            companion_elf_path=companion_elf_path,
            expressions=all_exprs,
            adapter=target_adapter,
        )
        flat: Dict[str, Any] = {}
        raw_list = eval_res.get("results", [])
        for item in raw_list:
            if item.get("status") == "OBSERVED":
                ex = item["expression"]
                val = item.get("value")
                flat[ex] = val
                if isinstance(val, dict):
                    for k, v in val.items():
                        flat[f"{ex}.{k}"] = v
                        flat[f"{ex}->{k}"] = v
        return flat, raw_list

    t_start_ns = time.monotonic_ns()
    baseline_flat, baseline_raw = _sample_flat()
    samples_taken = 1
    triggered = False
    hold_start_ns: Optional[int] = None
    latest_flat = dict(baseline_flat)
    latest_raw = list(baseline_raw)
    latest_clause_evals: List[Dict[str, Any]] = []

    while True:
        now_ns = time.monotonic_ns()
        is_match, clause_evals = mgr._evaluate_parsed_clauses(
            combinator, clauses, latest_flat, baseline_flat
        )
        latest_clause_evals = clause_evals

        if is_match:
            if clamped_hold_ms <= 0:
                triggered = True
                break
            if hold_start_ns is None:
                hold_start_ns = now_ns
            elif (now_ns - hold_start_ns) >= clamped_hold_ms * 1_000_000:
                triggered = True
                break
        else:
            hold_start_ns = None

        elapsed_ms_now = (now_ns - t_start_ns) / 1_000_000.0
        if elapsed_ms_now >= clamped_timeout_ms:
            break

        sleep_s = min(clamped_poll_ms, max(5.0, clamped_timeout_ms - elapsed_ms_now)) / 1000.0
        time.sleep(sleep_s)
        latest_flat, latest_raw = _sample_flat()
        samples_taken += 1

    total_elapsed_ms = round((time.monotonic_ns() - t_start_ns) / 1_000_000.0, 2)

    # Compute before vs trigger/final diff
    changed: List[Dict[str, Any]] = []
    unchanged: List[Dict[str, Any]] = []
    for k, before_v in baseline_flat.items():
        after_v = latest_flat.get(k)
        if isinstance(before_v, dict) or isinstance(after_v, dict):
            continue
        if before_v != after_v:
            delta = None
            if isinstance(before_v, (int, float)) and isinstance(after_v, (int, float)):
                delta = after_v - before_v
            changed.append({
                "path": k,
                "before": before_v,
                "after": after_v,
                "delta": delta,
            })
        else:
            unchanged.append({"path": k, "value": after_v})

    # Optional automatic thread owner lookup on hit
    owner_trace = None
    owner_target = (find_owner_on_hit or "").strip()
    if not owner_target and triggered and cond_symbols:
        # If a condition references an indexed slot like gpMem->buffers[9].in_use, strip trailing field
        cand = cond_symbols[0]
        m_slot = re.match(r"^(.+\[\d+\])(?:\.[A-Za-z0-9_]+)?$", cand)
        if m_slot:
            owner_target = m_slot.group(1)

    if triggered and owner_target:
        try:
            owner_trace = mgr.find_symbol_owners_and_threads(
                pid=pid,
                companion_elf_path=companion_elf_path,
                target_expression=owner_target,
                adapter=target_adapter,
            )
        except Exception:
            owner_trace = None

    return {
        "pid": pid,
        "target_host": target_adapter.target_host(),
        "is_remote": target_adapter.is_remote(),
        "stop_duration_ms": 0.0,
        "condition_expression": condition_expression,
        "combinator": combinator,
        "triggered": triggered,
        "samples_taken": samples_taken,
        "poll_interval_ms": clamped_poll_ms,
        "hold_duration_ms": clamped_hold_ms,
        "elapsed_ms": total_elapsed_ms,
        "clause_evaluations": latest_clause_evals,
        "trigger_snapshot": latest_raw,
        "changed": changed,
        "unchanged": unchanged[:30],
        "owner_trace_on_hit": owner_trace,
        "llm_next_step_hint": (
            f"Condition '{condition_expression}' TRIGGERED after {total_elapsed_ms}ms ({samples_taken} zero-stop samples). "
            + (
                f"Owner lookup identified {owner_trace['matched_threads_count']} thread(s) holding '{owner_target}'."
                if owner_trace and owner_trace.get("matched_threads_count")
                else f"{len(changed)} field(s) mutated during the watch window."
            )
            if triggered
            else f"Condition '{condition_expression}' did not trigger within {clamped_timeout_ms}ms ({samples_taken} samples). Inspect `clause_evaluations` to see current values."
        ),
    }


# -------------------------------------------------------------------------
# Phase 45 (Phase 15): Anomaly Time-Machine Flight Recorder Ring Buffer
#                      & Behavioral Drift Detector
# -------------------------------------------------------------------------

def _flatten_decoded_value(cls, prefix: str, val: Any, out: Dict[str, Any], depth: int = 0) -> None:
    if depth > 4:
        out[prefix] = val
        return
    if isinstance(val, dict):
        if not val:
            out[prefix] = {}
            return
        for k, v in val.items():
            sep = "->" if prefix.startswith("*") else "."
            clean_p = prefix[1:] if (prefix.startswith("*") and sep == "->") else prefix
            cls._flatten_decoded_value(f"{clean_p}{sep}{k}", v, out, depth + 1)
    elif isinstance(val, list):
        for idx_i, item in enumerate(val[:8]):
            cls._flatten_decoded_value(f"{prefix}[{idx_i}]", item, out, depth + 1)
    else:
        out[prefix] = val


def flight_recorder_time_machine(
    mgr,
    pid: int,
    companion_elf_path: str,
    frames_count: int = 8,
    interval_ms: int = 25,
    watch_expressions: Optional[List[str]] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    adapter: Optional[TargetExecutionAdapter] = None,
) -> Dict[str, Any]:
    """Zero-stop Anomaly Time-Machine Flight Recorder (`zero-stop` stop time).
        Maintains an per-PID circular blackbox ring buffer of micro-snapshots (`_flight_recorder_buffers`)
        and records `frames_count` rapid frames across `interval_ms`.
        Automatically identifies transient spikes, value reversals (A -> B -> A glitches), lock micro-stalls,
        and reconstructs `pre_anomaly_frame`, `peak_anomaly_frame`, and `post_anomaly_frame`.
        """
    target_adapter = mgr._resolve_adapter(
        pid=pid,
        remote_host=remote_host,
        ssh_user=ssh_user,
        ssh_port=ssh_port,
        ssh_key=ssh_key,
        ssh_proxy_jump=ssh_proxy_jump,
        adapter=adapter,
    )
    t_start_ns = time.monotonic_ns()
    if not hasattr(mgr, "_flight_recorder_buffers"):
        mgr._flight_recorder_buffers: Dict[int, deque] = {}

    ring: deque = mgr._flight_recorder_buffers.setdefault(pid, deque(maxlen=64))
    clamped_frames = max(3, min(int(frames_count), 24))
    clamped_interval_ms = max(10, min(int(interval_ms), 250))

    # Auto-discover key state/counter/pool expressions if not provided
    primary_elf, _ = mgr._split_companion_elf_paths(companion_elf_path)
    if not primary_elf:
        raise ValueError("Valid companion ELF path is required")
    idx = DwarfIndexer.get_index(primary_elf)

    exprs: List[str] = list(watch_expressions or [])
    if not exprs:
        for v in idx.variables:
            if v.name and not v.name.startswith("__") and v.link_time_address is not None:
                canon_v = idx.resolve_canonical_type(v.type_offset)
                if canon_v and canon_v.tag == "DW_TAG_pointer_type":
                    pt = idx.resolve_canonical_type(canon_v.target_type_offset)
                    if pt and pt.tag in ("DW_TAG_structure_type", "DW_TAG_class_type"):
                        exprs.append(f"*{v.name}")
                        continue
                exprs.append(v.name)
            if len(exprs) >= 8:
                break

    recorded_frames: List[Dict[str, Any]] = []
    base_seq = len(ring)

    for f_i in range(clamped_frames):
        frame_ts_ms = round((time.monotonic_ns() - t_start_ns) / 1_000_000.0, 2)
        ev_res = mgr.evaluate_symbol_paths(
            pid=pid,
            companion_elf_path=companion_elf_path,
            expressions=exprs[:8],
            adapter=target_adapter,
        )
        flat_values: Dict[str, Any] = {}
        for r in ev_res.get("results", []):
            if r.get("status") == "OBSERVED":
                mgr._flatten_decoded_value(r["expression"], r.get("value"), flat_values)

        # Compute an instant anomaly/stress score for this frame
        stress_score = 0
        stress_reasons: List[str] = []
        for k, v in flat_values.items():
            kl = k.lower()
            v_num = mgr._coerce_numeric_or_str(v)
            if isinstance(v_num, (int, float)):
                if ("active" in kl or "in_use" in kl or "spike" in kl or "err" in kl or "backlog" in kl) and v_num > 0:
                    stress_score += int(v_num) * 5
                    stress_reasons.append(f"{k}={v_num}")
            elif isinstance(v, str) and v.startswith("0x") and "dead" in v.lower():
                stress_score += 50
                stress_reasons.append(f"{k}={v}")

        frame_obj = {
            "frame_seq": base_seq + f_i + 1,
            "offset_ms": frame_ts_ms,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "stress_score": stress_score,
            "stress_highlights": stress_reasons[:4],
            "values": flat_values,
        }
        ring.append(frame_obj)
        recorded_frames.append(frame_obj)

        if f_i + 1 < clamped_frames:
            time.sleep(clamped_interval_ms / 1000.0)

    # Analyze timeline across recorded_frames for transient glitches (A -> B -> A) and monotonic trends
    all_keys: List[str] = []
    for fr in recorded_frames:
        for k in fr["values"]:
            if k not in all_keys:
                all_keys.append(k)

    transient_glitches: List[Dict[str, Any]] = []
    monotonic_trends: List[Dict[str, Any]] = []

    for k in all_keys:
        series = [fr["values"].get(k) for fr in recorded_frames]
        distinct = []
        for val in series:
            if not distinct or distinct[-1] != val:
                distinct.append(val)
        if len(distinct) >= 3 and distinct[0] == distinct[-1]:
            # Classic transient spike/glitch: started at A, spiked to B, returned to A!
            peak_val = distinct[1]
            peak_frame_seq = next(
                (fr["frame_seq"] for fr in recorded_frames if fr["values"].get(k) == peak_val),
                recorded_frames[len(recorded_frames) // 2]["frame_seq"],
            )
            transient_glitches.append({
                "path": k,
                "pattern": "TRANSIENT_SPIKE_REVERSAL",
                "baseline_value": distinct[0],
                "spike_value": peak_val,
                "restored_value": distinct[-1],
                "peak_frame_seq": peak_frame_seq,
                "timeline_values": series,
            })
        elif len(distinct) >= 2:
            monotonic_trends.append({
                "path": k,
                "start_value": series[0],
                "end_value": series[-1],
                "transitions_count": len(distinct) - 1,
                "timeline_values": series,
            })

    # Identify Peak Anomaly Frame, Pre-Anomaly Frame, and Post-Anomaly Frame
    peak_idx = 0
    best_stress = -1
    for idx_f, fr in enumerate(recorded_frames):
        if fr["stress_score"] > best_stress:
            best_stress = fr["stress_score"]
            peak_idx = idx_f

    pre_frame = recorded_frames[max(0, peak_idx - 1)]
    peak_frame = recorded_frames[peak_idx]
    post_frame = recorded_frames[min(len(recorded_frames) - 1, peak_idx + 1)]

    elapsed_ms = round((time.monotonic_ns() - t_start_ns) / 1_000_000.0, 2)
    return {
        "pid": pid,
        "target_host": target_adapter.target_host(),
        "is_remote": target_adapter.is_remote(),
        "stop_duration_ms": 0.0,
        "frames_recorded": len(recorded_frames),
        "ring_buffer_total_frames": len(ring),
        "interval_ms": clamped_interval_ms,
        "elapsed_ms": elapsed_ms,
        "transient_glitches_count": len(transient_glitches),
        "transient_glitches": transient_glitches,
        "monotonic_trends": monotonic_trends[:12],
        "time_machine_triad": {
            "pre_anomaly_frame": pre_frame,
            "peak_anomaly_frame": peak_frame,
            "post_anomaly_frame": post_frame,
        },
        "frames": recorded_frames,
        "llm_next_step_hint": (
            f"Flight Recorder captured {len(recorded_frames)} zero-stop frames ({elapsed_ms}ms) and detected "
            f"{len(transient_glitches)} transient spike reversal(s): "
            + ", ".join(f"{g['path']} ({g['baseline_value']} ➔ {g['spike_value']} ➔ {g['restored_value']} at frame #{g['peak_frame_seq']})" for g in transient_glitches[:3])
            if transient_glitches
            else f"Flight Recorder captured {len(recorded_frames)} zero-stop frames ({elapsed_ms}ms). Peak stress frame #{peak_frame['frame_seq']} (score={peak_frame['stress_score']})."
        ),
    }


def detect_behavioral_drift(
    mgr,
    pid: int,
    companion_elf_path: str,
    baseline_id: Optional[str] = None,
    save_as_new_baseline: bool = False,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    adapter: Optional[TargetExecutionAdapter] = None,
) -> Dict[str, Any]:
    """Zero-Stop Behavioral Drift Detector (`zero-stop` stop time).
        Captures a multi-dimensional behavioral fingerprint of the live process:
        1. Global/Static State & Counter Values
        2. Memory Pool Utilization % & Allocated Slot Counts
        3. Active Thread Count & Mutex Lock States
        4. C++ Polymorphic Heap Object Counts & Unreferenced Leak Candidates
        Compares the current fingerprint against either a saved Golden Baseline (`baseline_id`)
        or the process's initial learned fingerprint cached on first connection, and computes
        `drift_score` (0..100), `drift_status`, and `drifted_dimensions`.
        """
    target_adapter = mgr._resolve_adapter(
        pid=pid,
        remote_host=remote_host,
        ssh_user=ssh_user,
        ssh_port=ssh_port,
        ssh_key=ssh_key,
        ssh_proxy_jump=ssh_proxy_jump,
        adapter=adapter,
    )
    t_start_ns = time.monotonic_ns()
    if not hasattr(mgr, "_learned_behavioral_profiles"):
        mgr._learned_behavioral_profiles: Dict[int, Dict[str, Any]] = {}

    blueprint = mgr.get_process_xray_blueprint(
        pid=pid,
        companion_elf_path=companion_elf_path,
        adapter=target_adapter,
    )
    callstacks = mgr.inspect_thread_callstacks_and_locks(
        pid=pid,
        companion_elf_path=companion_elf_path,
        adapter=target_adapter,
    )
    heap_scan = mgr.scan_heap_objects(
        pid=pid,
        companion_elf_path=companion_elf_path,
        adapter=target_adapter,
    )

    # Collect pool utilization metrics
    pool_metrics: Dict[str, Dict[str, Any]] = {}
    for pm in blueprint.get("categories", {}).get("memory_pools_and_buffers", [])[:2]:
        expr = pm.get("recommended_pool_expression") or pm.get("name")
        if not expr:
            continue
        try:
            ps = mgr.scan_memory_pool_or_array(
                pid=pid,
                companion_elf_path=companion_elf_path,
                base_expression=expr,
                adapter=target_adapter,
            )
            pool_metrics[ps["resolved_array_expression"]] = {
                "allocated_count": ps["pool_summary"]["allocated_count"],
                "total_slots": ps["pool_summary"]["total_slots"],
                "utilization_pct": ps["pool_summary"]["utilization_pct"],
            }
        except Exception:
            pass

    # Collect scalar state & counter values
    primary_elf, _ = mgr._split_companion_elf_paths(companion_elf_path)
    idx = DwarfIndexer.get_index(primary_elf)
    scalar_exprs = [
        v.name for v in idx.variables
        if v.name and not v.name.startswith("__") and v.link_time_address is not None
    ][:10]
    scalar_values: Dict[str, Any] = {}
    if scalar_exprs:
        try:
            ev = mgr.evaluate_symbol_paths(
                pid=pid,
                companion_elf_path=companion_elf_path,
                expressions=scalar_exprs,
                adapter=target_adapter,
            )
            for r in ev.get("results", []):
                if r.get("status") == "OBSERVED":
                    mgr._flatten_decoded_value(r["expression"], r.get("value"), scalar_values)
        except Exception:
            pass

    locked_mutexes = [lk["name"] for lk in callstacks.get("locks", []) if lk.get("is_locked")]

    current_profile = {
        "captured_at": datetime.now(timezone.utc).isoformat(),
        "threads_count": blueprint.get("threads_count", 0),
        "locked_mutexes": locked_mutexes,
        "pools": pool_metrics,
        "heap_total_objects": heap_scan.get("total_objects_found", 0),
        "heap_leaked_candidates": heap_scan.get("leaked_candidates_count", 0),
        "scalars": scalar_values,
    }

    if save_as_new_baseline or pid not in mgr._learned_behavioral_profiles:
        # If no baseline exists yet, store current profile as baseline (unless a Golden Baseline exists on disk)
        disk_baselines = mgr.list_golden_baselines()
        if disk_baselines and not save_as_new_baseline:
            b_rec = disk_baselines[0]
            b_vals = b_rec.get("values") or {}
            baseline_profile = {
                "captured_at": b_rec.get("created_at"),
                "threads_count": current_profile["threads_count"],
                "locked_mutexes": [],
                "pools": {},
                "heap_total_objects": 0,
                "heap_leaked_candidates": 0,
                "scalars": b_vals,
            }
        else:
            mgr._learned_behavioral_profiles[pid] = current_profile
            baseline_profile = current_profile
    else:
        baseline_profile = mgr._learned_behavioral_profiles[pid]

    # Compare `current_profile` vs `baseline_profile` across all dimensions
    drifted_dimensions: List[Dict[str, Any]] = []
    drift_score = 0

    # Dimension 1: Thread count drift
    if current_profile["threads_count"] != baseline_profile.get("threads_count", current_profile["threads_count"]):
        drifted_dimensions.append({
            "dimension": "THREAD_COUNT_DRIFT",
            "severity": "MEDIUM",
            "metric": "threads_count",
            "baseline": baseline_profile.get("threads_count"),
            "current": current_profile["threads_count"],
            "detail": f"Active thread count changed from {baseline_profile.get('threads_count')} to {current_profile['threads_count']}",
        })
        drift_score += 15

    # Dimension 2: Newly locked mutexes
    base_locks = set(baseline_profile.get("locked_mutexes") or [])
    for lk_name in locked_mutexes:
        if lk_name not in base_locks:
            drifted_dimensions.append({
                "dimension": "NEW_MUTEX_CONTENTION",
                "severity": "HIGH",
                "metric": lk_name,
                "baseline": "UNLOCKED",
                "current": "LOCKED",
                "detail": f"Mutex '{lk_name}' was UNLOCKED in baseline but is currently LOCKED.",
            })
            drift_score += 25

    # Dimension 3: Memory Pool utilization surge
    base_pools = baseline_profile.get("pools") or {}
    for p_expr, p_cur in pool_metrics.items():
        p_base = base_pools.get(p_expr)
        if p_base:
            delta_pct = round(p_cur["utilization_pct"] - p_base["utilization_pct"], 2)
            if abs(delta_pct) >= 10.0:
                drifted_dimensions.append({
                    "dimension": "MEMORY_POOL_UTILIZATION_DRIFT",
                    "severity": "HIGH" if delta_pct >= 25.0 else "MEDIUM",
                    "metric": p_expr,
                    "baseline": f"{p_base['allocated_count']}/{p_base['total_slots']} ({p_base['utilization_pct']}%)",
                    "current": f"{p_cur['allocated_count']}/{p_cur['total_slots']} ({p_cur['utilization_pct']}%)",
                    "detail": f"Pool '{p_expr}' utilization shifted by {delta_pct:+.1f}%.",
                })
                drift_score += 25
        elif p_cur["utilization_pct"] >= 25.0:
            drifted_dimensions.append({
                "dimension": "MEMORY_POOL_ACTIVE_ALLOCATION",
                "severity": "MEDIUM",
                "metric": p_expr,
                "baseline": "0%",
                "current": f"{p_cur['allocated_count']}/{p_cur['total_slots']} ({p_cur['utilization_pct']}%)",
                "detail": f"Pool '{p_expr}' has {p_cur['allocated_count']} active slot(s) ({p_cur['utilization_pct']}%).",
            })
            drift_score += 15

    # Dimension 4: Heap leak drift
    base_leaks = int(baseline_profile.get("heap_leaked_candidates", 0))
    cur_leaks = int(current_profile["heap_leaked_candidates"])
    if cur_leaks > base_leaks:
        drifted_dimensions.append({
            "dimension": "HEAP_LEAK_GROWTH",
            "severity": "CRITICAL",
            "metric": "heap_leaked_candidates",
            "baseline": base_leaks,
            "current": cur_leaks,
            "detail": f"Unreferenced C++ heap leak candidates increased from {base_leaks} to {cur_leaks}.",
        })
        drift_score += 35

    # Dimension 5: Scalar state/flag/pointer drift
    base_scalars = baseline_profile.get("scalars") or {}
    for sk, sv in scalar_values.items():
        if sk in base_scalars and base_scalars[sk] != sv:
            drifted_dimensions.append({
                "dimension": "SYMBOL_VALUE_DRIFT",
                "severity": "MEDIUM",
                "metric": sk,
                "baseline": base_scalars[sk],
                "current": sv,
                "detail": f"Symbol '{sk}' drifted from {base_scalars[sk]} to {sv}.",
            })
            drift_score += 10

    drift_score = min(100, drift_score)
    drift_status = (
        "SEVERE_BEHAVIORAL_DRIFT"
        if drift_score >= 50
        else ("MODERATE_DRIFT" if drift_score > 0 else "STABLE_ON_BASELINE")
    )

    latency_us = round((time.monotonic_ns() - t_start_ns) / 1000.0, 2)
    return {
        "pid": pid,
        "target_host": target_adapter.target_host(),
        "is_remote": target_adapter.is_remote(),
        "stop_duration_ms": 0.0,
        "evaluation_latency_us": latency_us,
        "drift_status": drift_status,
        "drift_score": drift_score,
        "drifted_dimensions_count": len(drifted_dimensions),
        "drifted_dimensions": drifted_dimensions,
        "baseline_profile": baseline_profile,
        "current_profile": current_profile,
        "llm_next_step_hint": (
            f"Behavioral Drift Check: {drift_status} (Drift Score: {drift_score}/100, {len(drifted_dimensions)} dimension(s) shifted). "
            + (drifted_dimensions[0]["detail"] if drifted_dimensions else "Process matches baseline profile.")
        ),
    }

"""Statistical hotspot profiler (per-thread CPU ticks + sampled call stacks) and fuzzy symbol-intent resolution.

Moved verbatim from extractor/watch_session.py; functions take the ``WatchSessionManager`` first (``mgr``) and
are bound on it as methods.
"""

import os
import re
import time
from typing import Any, Dict, List, Optional, Tuple

from ..dwarf_indexer import DwarfIndexer
from ..target_adapter import TargetExecutionAdapter


# -------------------------------------------------------------------------
# Phase 44 (Phase 14): Zero-Stop Statistical CPU/Callstack Hotspot Profiler
#                      & Fuzzy Natural-Language Symbol Intent Resolver
# -------------------------------------------------------------------------

def _read_thread_cpu_ticks_local(pid: int) -> Dict[int, Dict[str, Any]]:
    """Reads `/proc/<pid>/task/<tid>/stat` to extract per-thread `state`, `utime`, and `stime` ticks."""
    out: Dict[int, Dict[str, Any]] = {}
    task_dir = f"/proc/{pid}/task"
    if not os.path.isdir(task_dir):
        return out
    try:
        for tid_str in os.listdir(task_dir):
            if not tid_str.isdigit():
                continue
            tid_val = int(tid_str)
            stat_path = os.path.join(task_dir, tid_str, "stat")
            try:
                with open(stat_path, "r", encoding="utf-8") as sf:
                    txt = sf.read()
                lpar = txt.find("(")
                rpar = txt.rfind(")")
                if lpar == -1 or rpar == -1:
                    continue
                comm = txt[lpar + 1 : rpar]
                fields = txt[rpar + 1 :].strip().split()
                # In /proc/[pid]/stat, after `(comm)`:
                # index 0 is state (field 3), index 11 is utime (field 14), index 12 is stime (field 15)
                state = fields[0] if len(fields) > 0 else "S"
                utime = int(fields[11]) if len(fields) > 11 else 0
                stime = int(fields[12]) if len(fields) > 12 else 0
                out[tid_val] = {
                    "tid": tid_val,
                    "name": comm,
                    "state": state,
                    "utime": utime,
                    "stime": stime,
                    "total_ticks": utime + stime,
                }
            except Exception:
                continue
    except Exception:
        pass
    return out


def sample_statistical_hotspots(
    mgr,
    pid: int,
    companion_elf_path: str,
    samples_count: int = 6,
    interval_ms: int = 35,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    adapter: Optional[TargetExecutionAdapter] = None,
) -> Dict[str, Any]:
    """Zero-stop statistical CPU & callstack hotspot profiler (`zero-stop` stop time).
        Takes `samples_count` rapid non-intrusive snapshots across `interval_ms`, measuring:
        1. Per-thread CPU tick deltas (`utime + stime`) and runnable (`R`) vs sleeping (`S`/`D`) ratios.
        2. Function-level callstack appearance frequency (`hotspot_functions`) and folded flame-graph strings (`flame_stacks`).
        3. High-velocity counter/sequence mutation rates (`counter_rates_per_sec`) to distinguish productive work from busy-spin loops.
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
    clamped_samples = max(2, min(int(samples_count), 25))
    clamped_interval_ms = max(10, min(int(interval_ms), 500))

    # Discover candidate counter/sequence expressions from blueprint
    blueprint = mgr.get_process_xray_blueprint(
        pid=pid,
        companion_elf_path=companion_elf_path,
        adapter=target_adapter,
    )
    counter_exprs: List[str] = []
    for c_item in blueprint.get("categories", {}).get("counters_and_metrics", [])[:6]:
        if c_item.get("name"):
            counter_exprs.append(c_item["name"])
    for s_item in blueprint.get("categories", {}).get("state_machines_and_flags", [])[:4]:
        if s_item.get("name") and s_item["name"] not in counter_exprs:
            counter_exprs.append(s_item["name"])
    primary_elf, _ = mgr._split_companion_elf_paths(companion_elf_path)
    if primary_elf:
        idx_c = DwarfIndexer.get_index(primary_elf)
        for v in idx_c.variables:
            if v.name and not v.name.startswith("__") and v.link_time_address is not None:
                if any(k in v.name.lower() for k in ("count", "cnt", "seq", "total", "ticks", "packets", "ops", "ready")):
                    if v.name not in counter_exprs:
                        counter_exprs.insert(0, v.name)

    ticks_t0 = mgr._read_thread_cpu_ticks_local(pid) if not target_adapter.is_remote() else {}
    counters_t0: Dict[str, float] = {}
    if counter_exprs:
        try:
            ev0 = mgr.evaluate_symbol_paths(
                pid=pid,
                companion_elf_path=companion_elf_path,
                expressions=counter_exprs,
                adapter=target_adapter,
            )
            for r in ev0.get("results", []):
                val = r.get("value")
                if isinstance(val, (int, float)):
                    counters_t0[r["expression"]] = float(val)
                elif isinstance(val, str):
                    try:
                        counters_t0[r["expression"]] = float(int(val, 0))
                    except ValueError:
                        pass
        except Exception:
            pass

    # Collect N statistical callstack samples
    func_hit_counts: Dict[str, Dict[str, Any]] = {}
    flame_counts: Dict[str, int] = {}
    thread_runnable_hits: Dict[int, int] = {}
    thread_names: Dict[int, str] = {}

    for s_i in range(clamped_samples):
        cs = mgr.inspect_thread_callstacks_and_locks(
            pid=pid,
            companion_elf_path=companion_elf_path,
            max_frames=8,
            adapter=target_adapter,
        )
        for th in cs.get("threads", []):
            t_tid = int(th["tid"])
            t_name = th.get("name", f"tid_{t_tid}")
            thread_names[t_tid] = t_name
            if th.get("state") == "R":
                thread_runnable_hits[t_tid] = thread_runnable_hits.get(t_tid, 0) + 1

            frames = th.get("callstack") or []
            if frames:
                # Record folded stack from bottom-most frame to top frame
                chain_names = [f.get("function_name") or "unknown" for f in reversed(frames)]
                folded_key = f"{t_name};" + ";".join(chain_names)
                flame_counts[folded_key] = flame_counts.get(folded_key, 0) + 1

            seen_in_sample = set()
            for f_idx, fr in enumerate(frames):
                fn = fr.get("function_name") or "unknown"
                entry = func_hit_counts.setdefault(fn, {
                    "function_name": fn,
                    "source_location": fr.get("source_location"),
                    "self_samples": 0,
                    "inclusive_samples": 0,
                    "threads": set(),
                })
                if f_idx == 0:
                    entry["self_samples"] += 1
                if fn not in seen_in_sample:
                    entry["inclusive_samples"] += 1
                    seen_in_sample.add(fn)
                entry["threads"].add(f"TID {t_tid} ({t_name})")

        if s_i + 1 < clamped_samples:
            time.sleep(clamped_interval_ms / 1000.0)

    elapsed_sec = max(0.001, (time.monotonic_ns() - t_start_ns) / 1_000_000_000.0)
    ticks_t1 = mgr._read_thread_cpu_ticks_local(pid) if not target_adapter.is_remote() else {}

    # Compute per-thread CPU tick deltas and share %
    total_tick_delta = 0
    thread_profiles: List[Dict[str, Any]] = []
    all_tids = sorted(set(list(thread_names.keys()) + list(ticks_t1.keys())))
    for t_tid in all_tids:
        t0_info = ticks_t0.get(t_tid, {})
        t1_info = ticks_t1.get(t_tid, {})
        d_utime = max(0, int(t1_info.get("utime", 0)) - int(t0_info.get("utime", 0)))
        d_stime = max(0, int(t1_info.get("stime", 0)) - int(t0_info.get("stime", 0)))
        d_total = d_utime + d_stime
        total_tick_delta += d_total
        run_hits = thread_runnable_hits.get(t_tid, 0)
        thread_profiles.append({
            "tid": t_tid,
            "name": thread_names.get(t_tid) or t1_info.get("name", "thread"),
            "state": t1_info.get("state", "S"),
            "utime_delta_ticks": d_utime,
            "stime_delta_ticks": d_stime,
            "total_delta_ticks": d_total,
            "runnable_sample_pct": round((run_hits * 100.0) / clamped_samples, 1),
        })

    for tp in thread_profiles:
        tp["cpu_share_pct"] = (
            round((tp["total_delta_ticks"] * 100.0) / total_tick_delta, 1)
            if total_tick_delta > 0
            else tp["runnable_sample_pct"]
        )
    thread_profiles.sort(key=lambda x: (x["cpu_share_pct"], x["runnable_sample_pct"]), reverse=True)

    # Compute counter velocity (mutations per second)
    counter_rates: List[Dict[str, Any]] = []
    if counters_t0:
        try:
            ev1 = mgr.evaluate_symbol_paths(
                pid=pid,
                companion_elf_path=companion_elf_path,
                expressions=list(counters_t0.keys()),
                adapter=target_adapter,
            )
            for r in ev1.get("results", []):
                expr = r.get("expression")
                val1 = r.get("value")
                v1_num = None
                if isinstance(val1, (int, float)):
                    v1_num = float(val1)
                elif isinstance(val1, str):
                    try:
                        v1_num = float(int(val1, 0))
                    except ValueError:
                        pass
                if expr in counters_t0 and v1_num is not None:
                    v0 = counters_t0[expr]
                    v1 = v1_num
                    delta = v1 - v0
                    counter_rates.append({
                        "expression": expr,
                        "before": v0,
                        "after": v1,
                        "delta": delta,
                        "rate_per_sec": round(delta / elapsed_sec, 2),
                    })
        except Exception:
            pass

    # Format ranked hotspot functions
    hotspot_functions: List[Dict[str, Any]] = []
    for fn, info in func_hit_counts.items():
        hotspot_functions.append({
            "function_name": fn,
            "source_location": info["source_location"],
            "self_samples": info["self_samples"],
            "inclusive_samples": info["inclusive_samples"],
            "self_pct": round((info["self_samples"] * 100.0) / clamped_samples, 1),
            "inclusive_pct": round((info["inclusive_samples"] * 100.0) / clamped_samples, 1),
            "threads": sorted(info["threads"]),
        })
    hotspot_functions.sort(key=lambda x: (x["self_samples"], x["inclusive_samples"]), reverse=True)

    flame_stacks = [
        {"folded_stack": k, "samples": v, "pct": round((v * 100.0) / clamped_samples, 1)}
        for k, v in sorted(flame_counts.items(), key=lambda item: item[1], reverse=True)
    ]

    top_fn = hotspot_functions[0] if hotspot_functions else None
    top_th = thread_profiles[0] if thread_profiles else None
    elapsed_ms = round(elapsed_sec * 1000.0, 2)

    return {
        "pid": pid,
        "target_host": target_adapter.target_host(),
        "is_remote": target_adapter.is_remote(),
        "stop_duration_ms": 0.0,
        "samples_taken": clamped_samples,
        "interval_ms": clamped_interval_ms,
        "elapsed_ms": elapsed_ms,
        "thread_cpu_profiles": thread_profiles,
        "hotspot_functions": hotspot_functions,
        "flame_stacks": flame_stacks,
        "counter_rates": counter_rates,
        "llm_next_step_hint": (
            f"Statistical hotspot profiling ({clamped_samples} samples over {elapsed_ms}ms, zero-stop): "
            + (f"Top hotspot function is `{top_fn['function_name']}()` ({top_fn['inclusive_pct']}% inclusive, {top_fn['source_location']}) " if top_fn else "")
            + (f"on thread TID {top_th['tid']} ({top_th['name']}, CPU share {top_th['cpu_share_pct']}%)." if top_th else "")
        ),
    }


def resolve_fuzzy_symbol_intent(
    mgr,
    pid: int,
    companion_elf_path: str,
    natural_query: str,
    limit: int = 5,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    adapter: Optional[TargetExecutionAdapter] = None,
) -> Dict[str, Any]:
    """Semantic / Fuzzy Intent-to-Symbol Resolver (zero-stop; the target is not suspended).
        Maps vague natural-language user descriptions (e.g. '버퍼 풀', '워커 스레드', '세션 객체',
        '뮤텍스 락', '작업 리스트', '카운터') to concrete DWARF symbols & member paths, and evaluates
        their live values immediately.
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
    primary_elf, _ = mgr._split_companion_elf_paths(companion_elf_path)
    if not primary_elf:
        raise ValueError("Valid companion ELF path is required")

    idx = DwarfIndexer.get_index(primary_elf)
    q_low = (natural_query or "").lower()

    # Bilingual semantic concept dictionary (Korean/English -> DWARF symbol/type/member tokens)
    concept_synonyms = [
        (("버퍼", "풀", "메모리 풀", "슬롯", "buffer", "pool", "slot", "slab", "arena"), ("pool", "mem", "buf", "slot", "active_buffers", "total_buffers")),
        (("워커", "스레드", "쓰레드", "작업자", "worker", "thread", "context", "task"), ("worker", "thread", "tid", "ctx", "task")),
        (("락", "뮤텍스", "데드락", "동기화", "lock", "mutex", "futex", "sema"), ("mutex", "lock", "sem", "cond")),
        (("리스트", "큐", "연결", "체인", "노드", "list", "queue", "chain", "node"), ("list", "queue", "head", "tail", "node", "next")),
        (("세션", "채널", "클라이언트", "콜백", "객체", "session", "client", "channel", "callback"), ("session", "client", "chan", "cb", "handler", "poly")),
        (("카운터", "시퀀스", "통계", "에러", "상태", "플래그", "counter", "seq", "stat", "state", "flag", "ready"), ("seq", "count", "cnt", "total", "active", "ready", "state", "err", "running")),
    ]

    expanded_keywords: List[str] = []
    for triggers, targets in concept_synonyms:
        if any(t in q_low for t in triggers):
            for tgt in targets:
                if tgt not in expanded_keywords:
                    expanded_keywords.append(tgt)

    # Also extract any ASCII identifiers directly mentioned in the query
    for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", natural_query or ""):
        tl = tok.lower()
        if tl not in ("the", "and", "for", "pid", "show", "check") and tl not in expanded_keywords:
            expanded_keywords.append(tl)

    if not expanded_keywords:
        expanded_keywords = ["pool", "mem", "worker", "state", "count", "mutex"]

    scored_candidates: List[Tuple[int, Dict[str, Any]]] = []
    seen_names = set()

    for var in idx.variables:
        if var.link_time_address is None or var.is_declaration or not var.name or var.name.startswith("__"):
            continue
        if var.name in seen_names:
            continue
        seen_names.add(var.name)

        t_name = idx.get_type_name(var.type_offset)
        canon_t = idx.resolve_canonical_type(var.type_offset)
        member_names: List[str] = []
        if canon_t:
            if canon_t.tag in ("DW_TAG_structure_type", "DW_TAG_class_type"):
                member_names = [m.name for m in canon_t.members if m.name]
            elif canon_t.tag == "DW_TAG_pointer_type":
                pt = idx.resolve_canonical_type(canon_t.target_type_offset)
                if pt and pt.tag in ("DW_TAG_structure_type", "DW_TAG_class_type"):
                    member_names = [m.name for m in pt.members if m.name]

        haystack = f"{var.name} {t_name} {' '.join(member_names)}".lower()
        score = 0
        matched_terms: List[str] = []
        for kw in expanded_keywords:
            if kw in var.name.lower():
                score += 30
                matched_terms.append(kw)
            elif kw in t_name.lower():
                score += 20
                matched_terms.append(kw)
            elif any(kw in mn.lower() for mn in member_names):
                score += 15
                matched_terms.append(kw)
            elif kw in haystack:
                score += 5

        if score > 0:
            rec_expr = f"*{var.name}" if (canon_t and canon_t.tag == "DW_TAG_pointer_type") else var.name
            scored_candidates.append((score, {
                "symbol_name": var.name,
                "recommended_expression": rec_expr,
                "type_name": t_name,
                "decl_location": f"{var.decl_file}:{var.decl_line}" if var.decl_file else None,
                "member_fields": member_names[:10],
                "relevance_score": score,
                "matched_concepts": matched_terms,
            }))

    scored_candidates.sort(key=lambda item: item[0], reverse=True)
    top_matches = [item[1] for item in scored_candidates[: max(1, min(int(limit), 12))]]

    # Live-evaluate top matched expressions
    eval_exprs = [m["recommended_expression"] for m in top_matches]
    if eval_exprs:
        try:
            ev_res = mgr.evaluate_symbol_paths(
                pid=pid,
                companion_elf_path=companion_elf_path,
                expressions=eval_exprs,
                adapter=target_adapter,
            )
            val_by_expr = {r["expression"]: r.get("value") for r in ev_res.get("results", []) if "expression" in r}
            for m in top_matches:
                m["live_value"] = val_by_expr.get(m["recommended_expression"])
        except Exception:
            pass

    latency_us = round((time.monotonic_ns() - t_start_ns) / 1000.0, 2)
    return {
        "pid": pid,
        "target_host": target_adapter.target_host(),
        "is_remote": target_adapter.is_remote(),
        "stop_duration_ms": 0.0,
        "evaluation_latency_us": latency_us,
        "natural_query": natural_query,
        "expanded_keywords": expanded_keywords,
        "matches_count": len(top_matches),
        "matches": top_matches,
        "llm_next_step_hint": (
            f"Resolved '{natural_query}' to {len(top_matches)} DWARF symbol(s): "
            + ", ".join(f"{m['recommended_expression']} ({m['type_name']})" for m in top_matches[:3])
            if top_matches
            else f"No matching DWARF symbols found for '{natural_query}'."
        ),
    }

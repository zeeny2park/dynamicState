"""File-descriptor leak / exhaustion recipe (IMP-018) - registered entirely from this file.

Observation kind ``fd_usage``: a few cheap /proc samples over a short window - open fd count
(/proc/PID/fd), the soft RLIMIT_NOFILE (/proc/PID/limits), the thread count (/proc/PID/status) and the targets
of the fds that appeared during the window.  Read-only, zero-stop, no ptrace.

Verdict rule: SUPPORTED when the count rose at every sample (by >= MIN_GROWTH in total) or is at >= 90 % of
the limit; CONTRADICTED when it did not grow and is below 80 % of the limit; otherwise not enough evidence.
The subject is the kind of the new descriptors (socket / pipe / a file path), i.e. what is leaking.
"""

from __future__ import annotations

import os
import re
import time
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from ..diagnostic_recipes import (
    DOMAIN_ABNORMAL_STATE,
    RECIPE_STATUS_CONTRADICTED,
    RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
    RECIPE_STATUS_SUPPORTED,
    DiagnosticRecipe,
    RecipeEvaluationResult,
    register_recipe,
)
from ..runtime_evidence_provider import register_observation_collector

RECIPE_FD_LEAK = "RECIPE_FD_LEAK"
CATEGORY_FD_LEAK = "FD_LEAK"
OBS_FD_USAGE = "fd_usage"

SAMPLES = 3
INTERVAL_S = 0.4
MIN_GROWTH = 3


def _target_kind(link: str) -> str:
    m = re.match(r"^(socket|pipe|anon_inode):", link)
    if m:
        return m.group(1) if m.group(1) != "anon_inode" else link
    return link


def _read_fds(adapter: Any, pid: int) -> Optional[Dict[str, str]]:
    """{fd: link target} or None when the fd table cannot be read."""
    if adapter is None or not getattr(adapter, "is_remote", lambda: False)():
        try:
            out = {}
            for fd in os.listdir(f"/proc/{pid}/fd"):
                try:
                    out[fd] = os.readlink(f"/proc/{pid}/fd/{fd}")
                except OSError:
                    out[fd] = "?"
            return out
        except OSError:
            return None
    run = getattr(adapter, "run_ssh", None)
    if not callable(run):
        return None
    try:
        rc, txt, _ = run(f"ls -l /proc/{int(pid)}/fd 2>/dev/null")
    except Exception:  # noqa: BLE001
        return None
    if rc != 0:
        return None
    out = {}
    for line in str(txt).splitlines():
        m = re.search(r"\s(\d+)\s+->\s+(.*)$", line)
        if m:
            out[m.group(1)] = m.group(2).strip()
    return out


def _read_text(adapter: Any, pid: int, name: str) -> str:
    try:
        if adapter is not None and getattr(adapter, "is_remote", lambda: False)():
            raw = adapter.read_target_file(pid, f"/proc/{pid}/{name}", 16384)
            return raw.decode("utf-8", "replace") if raw else ""
        with open(f"/proc/{pid}/{name}", "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except Exception:  # noqa: BLE001
        return ""


def _fd_limit(adapter: Any, pid: int) -> Optional[int]:
    m = re.search(r"^Max open files\s+(\d+|unlimited)", _read_text(adapter, pid, "limits"), re.M)
    return int(m.group(1)) if m and m.group(1).isdigit() else None


def _threads(adapter: Any, pid: int) -> Optional[int]:
    m = re.search(r"^Threads:\s+(\d+)", _read_text(adapter, pid, "status"), re.M)
    return int(m.group(1)) if m else None


def collect_fd_usage(provider: Any, ctx: Dict[str, Any]) -> None:
    pid = ctx["pid"]
    adapter = getattr(provider, "adapter", None)
    samples: List[Dict[str, Any]] = []
    first: Optional[Dict[str, str]] = None
    last: Optional[Dict[str, str]] = None
    t0 = time.monotonic()
    for i in range(SAMPLES):
        fds = _read_fds(adapter, pid)
        if fds is None:
            break
        first = fds if first is None else first
        last = fds
        samples.append({"t_s": round(time.monotonic() - t0, 3), "open_fds": len(fds), "threads": _threads(adapter, pid)})
        if i + 1 < SAMPLES:
            time.sleep(INTERVAL_S)
    obs: Dict[str, Any] = {"samples": samples, "fd_limit": _fd_limit(adapter, pid)}
    if first is not None and last is not None:
        new = [last[k] for k in last if k not in first or first[k] != last[k]]
        kinds = Counter(_target_kind(v) for v in new)
        obs["new_fd_targets"] = [{"fd_target": k, "count": n} for k, n in kinds.most_common(5)]
        obs["open_fds_by_kind"] = dict(Counter(_target_kind(v).split("/")[0] or "file" for v in last.values()).most_common(8))
    if not samples:
        obs["unavailable"] = "the fd table of the process could not be read"
    ctx["observation_data"]["fd_usage"] = obs
    return None


def fd_leak_rule(recipe: DiagnosticRecipe, data: Dict[str, Any]) -> Optional[RecipeEvaluationResult]:
    rid = recipe.recipe_id
    fu = data.get("fd_usage") or {}
    s = [x["open_fds"] for x in fu.get("samples") or []]
    if len(s) < 2:
        return RecipeEvaluationResult(
            recipe_id=rid, status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE, confidence=0.0,
            confidence_basis=f"fd count not observed: {fu.get('unavailable') or 'fewer than 2 samples'}",
            missing_evidence=["fd_count_trend"], limitations=list(recipe.limitations), details={"fd_usage": fu})
    limit = fu.get("fd_limit")
    growth = s[-1] - s[0]
    rising = all(b > a for a, b in zip(s, s[1:]))
    window = (fu["samples"][-1]["t_s"] - fu["samples"][0]["t_s"]) or 1e-9
    trend = (f"open fds {' -> '.join(map(str, s))} over {window:.1f} s (+{growth}, {growth / window:.1f}/s)"
             + (f", limit {limit}" if limit else ""))
    details = {"fd_usage": fu, "fd_count_trend": s, "fd_growth": growth, "fd_limit": limit,
               "fd_growth_per_s": round(growth / window, 2)}
    near_limit = bool(limit) and s[-1] >= 0.9 * limit
    if (rising and growth >= MIN_GROWTH) or near_limit:
        return RecipeEvaluationResult(
            recipe_id=rid, status=RECIPE_STATUS_SUPPORTED, confidence=0.85 if rising else 0.7,
            confidence_basis=("File descriptors are leaking: " if rising else "File descriptors near the limit: ") + trend,
            supporting_facts=[trend] + [f"new descriptors: {t['count']} x {t['fd_target']}" for t in fu.get("new_fd_targets") or []],
            recommended_action="Find the code path that opens the listed descriptor kind without closing it "
                               "(missing close()/fclose(), sockets not closed on error paths).",
            details=details)
    if growth <= 0 and (not limit or s[-1] < 0.8 * limit):
        return RecipeEvaluationResult(
            recipe_id=rid, status=RECIPE_STATUS_CONTRADICTED, confidence=0.8,
            confidence_basis="fd count did not grow: " + trend, contradicting_facts=[trend],
            recommended_action="No fd leak in the observed window.", details=details)
    return RecipeEvaluationResult(
        recipe_id=rid, status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE, confidence=0.2,
        confidence_basis="fd count changed but not monotonically enough to call a leak: " + trend,
        missing_evidence=["longer fd_count_trend"], limitations=list(recipe.limitations), details=details)


register_observation_collector(OBS_FD_USAGE, collect_fd_usage)
register_recipe(DiagnosticRecipe(
    recipe_id=RECIPE_FD_LEAK,
    version="1.0.0",
    name="File Descriptor Leak / Exhaustion",
    domain=DOMAIN_ABNORMAL_STATE,
    applicable_problem_categories=[CATEGORY_FD_LEAK],
    required_prerequisites=[],
    evidence_sources=["/proc/<pid>/fd", "/proc/<pid>/limits", "/proc/<pid>/status"],
    collection_steps=[{"step": 1, "action": "sample_fd_table", "purpose": f"{SAMPLES} samples, {INTERVAL_S} s apart"}],
    analysis_rules=["fd count rising at every sample (>= %d in total) is a leak" % MIN_GROWTH,
                    "fd count >= 90 % of RLIMIT_NOFILE is exhaustion"],
    thresholds_and_conditions={"samples": SAMPLES, "interval_s": INTERVAL_S, "min_growth": MIN_GROWTH},
    supporting_evidence_criteria=["monotonic fd count growth", "fd count near the limit"],
    contradicting_evidence_criteria=["no fd growth below 80 % of the limit"],
    verification_procedure="Re-sample /proc/<pid>/fd later; a leak keeps growing.",
    stop_conditions=["fd table unreadable"],
    limitations=["a short window: a slow leak (< 1 fd per window) is not distinguishable from normal churn"],
    output_structure={"fd_count_trend": "list[int]", "new_fd_targets": "list"},
    observations=(OBS_FD_USAGE,),
    rule=fd_leak_rule,
), baseline=True, category=CATEGORY_FD_LEAK)

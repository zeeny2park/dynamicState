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


# ---------------------------------------------------------------------------------------------- presentation
# How this diagnosis is shown to a person: registered from this file as well (extractor/report_registry.py).
_TXT = {
    "trend": ("Open file descriptors rose from {a} to {b} in {win} s ({rate}/s).",
              "열린 파일 디스크립터가 {win}초 동안 {a}개에서 {b}개로 늘었습니다 (초당 {rate}개)."),
    "limit": ("The limit is {limit}; at this rate it is reached in about {eta}.",
              "한도는 {limit}개이며, 이 속도면 약 {eta} 뒤에 도달합니다."),
    "near": ("{b} of {limit} descriptors are in use ({pct}% of the limit).",
             "한도 {limit}개 중 {b}개를 쓰고 있습니다 (한도의 {pct}%)."),
    "new": ("What appeared during the observation: {x}.", "관측하는 동안 새로 생긴 것: {x}."),
    "open": ("Open now, by kind", "현재 열려 있는 것 (종류별)"),
    "chart": ("Open file descriptors over the observation", "관측하는 동안 열린 파일 디스크립터 수"),
    "x": ("seconds since first sample", "첫 샘플 이후 경과(초)"), "y": ("open descriptors", "열린 디스크립터 수"),
    "tip": ("sample {i}: {n} open", "샘플 {i}: {n}개 열림"),
    "closer": ("Which code opened them was not observed; look for the path that opens {x} without closing it.",
               "어느 코드가 열었는지는 관측되지 않았습니다. {x}을(를) 열고 닫지 않는 경로를 찾으세요."),
}


def _eta(seconds: float, ko: bool) -> str:
    for size, en, k in ((86400, "day(s)", "일"), (3600, "hour(s)", "시간"), (60, "minute(s)", "분")):
        if seconds >= size:
            return f"{seconds / size:.1f} {en}" if not ko else f"{seconds / size:.1f}{k}"
    return f"{seconds:.0f} s" if not ko else f"{seconds:.0f}초"


def _fd_obs(report: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    checks = ((report or {}).get("section_d_detailed_inspection_results") or {}).get("checks") or []
    for c in checks:
        if isinstance(c, dict) and c.get("recipe_id") == RECIPE_FD_LEAK:
            fu = (c.get("actual_observations") or {}).get("fd_usage")
            if isinstance(fu, dict):
                return fu
    return {}


def _fd_facts(i: int, fu: Dict[str, Any], wrap: Any) -> List[str]:
    """The sentences of the fd finding; ``wrap`` formats an identifier for the output medium."""
    s = [x for x in fu.get("samples") or [] if isinstance(x, dict) and isinstance(x.get("open_fds"), int)]
    out: List[str] = []
    if len(s) < 2:
        return out
    a, b = s[0]["open_fds"], s[-1]["open_fds"]
    win = (s[-1].get("t_s") or 0) - (s[0].get("t_s") or 0)
    limit = fu.get("fd_limit")
    if b > a and win > 0:
        rate = (b - a) / win
        out.append(_TXT["trend"][i].format(a=a, b=b, win=f"{win:.1f}", rate=f"{rate:.1f}"))
        if limit and limit > b:
            out.append(_TXT["limit"][i].format(limit=limit, eta=_eta((limit - b) / rate, bool(i))))
    elif limit:
        out.append(_TXT["near"][i].format(b=b, limit=limit, pct=round(b * 100 / limit)))
    new = [t for t in fu.get("new_fd_targets") or [] if isinstance(t, dict) and t.get("fd_target")]
    if new:
        out.append(_TXT["new"][i].format(x=", ".join(f"{wrap(t['fd_target'])} × {t.get('count')}" for t in new)))
        out.append(_TXT["closer"][i].format(x=wrap(new[0]["fd_target"])))
    return out


def fd_finding_text(ctx: Any, finding: Dict[str, Any], report: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return {"lines": _fd_facts(ctx.i, _fd_obs(report), lambda x: "`" + str(x).replace("`", "'") + "`")}


def fd_finding_viz(lx: Any, finding: Dict[str, Any], report: Optional[Dict[str, Any]], uid: str = "0") -> str:
    from ..report_visuals import chip, code, esc, facts_list, series_chart, share_bars
    fu = _fd_obs(report)
    s = [x for x in fu.get("samples") or [] if isinstance(x, dict) and isinstance(x.get("open_fds"), int)]
    if len(s) < 2:
        return ""
    i = lx.i
    out = [f'<h4>{esc(_TXT["chart"][i])} {chip(lx, "obs")}</h4>',
           series_chart([float(x.get("t_s") or 0) for x in s], [float(x["open_fds"]) for x in s], _TXT["chart"][i],
                        _TXT["x"][i], _TXT["y"][i], [_TXT["tip"][i].format(i=k + 1, n=x["open_fds"]) for k, x in enumerate(s)])]
    # the sentences carry target-controlled names: escape the sentence, then mark the names as code
    marks: List[str] = []

    def wrap(x: Any) -> str:
        marks.append(str(x))
        return f"\x00{len(marks) - 1}\x00"

    facts = []
    for line in _fd_facts(i, fu, wrap):
        h = esc(line)
        for k, m in enumerate(marks):
            h = h.replace(f"\x00{k}\x00", code(m))
        facts.append(h)
    out.append(facts_list(facts))
    kinds = fu.get("open_fds_by_kind")
    if isinstance(kinds, dict) and kinds:
        out.append(f'<h4>{esc(_TXT["open"][i])}</h4>'
                   + share_bars([(str(k), float(v)) for k, v in kinds.items() if isinstance(v, (int, float))]))
    return "".join(out)


def _register_presentation() -> None:
    from ..report_registry import register_category, register_finding_text, register_finding_viz, register_recipe_label
    register_category(CATEGORY_FD_LEAK, "file descriptor leak", "파일 디스크립터 누수")
    register_recipe_label(RECIPE_FD_LEAK, "ABNORMAL_STATE", "File descriptor leak", "파일 디스크립터 누수",
                          "open file descriptors that keep increasing or approach the limit",
                          "계속 늘어나거나 한도에 가까워지는 열린 파일 디스크립터")
    register_finding_text(CATEGORY_FD_LEAK, fd_finding_text)
    register_finding_viz(CATEGORY_FD_LEAK, fd_finding_viz)


_register_presentation()

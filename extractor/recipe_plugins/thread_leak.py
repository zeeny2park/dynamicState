"""Thread leak / thread exhaustion recipe - registered entirely from this file (docs/EXTENDING_DIAGNOSIS.md).

Data: the thread-count series and the per-thread rows of the thread sampler.  The sampler window is cached per run
and shared with the other thread checks, so this check normally adds no sampling time (if it runs first it takes
that one window itself).  The collector ``thread_growth`` below (the only observation kind of this recipe: the
``threads_and_locks`` collector ends collection, so it cannot be combined) reorganises that data (which threads appeared during the window, grouped by name and top frame) and reads two
limits: the soft RLIMIT_NPROC from /proc/PID/limits and the kernel ``threads-max``.  Read-only, zero-stop.

Verdict rule (``thread_leak_rule``):
  SUPPORTED     the count rose at EVERY sample of the window (strictly higher than the sample before), by at least
                MIN_GROWTH in total, over at least MIN_SAMPLES samples; or the count is at >= 90 % of a limit that
                was actually read.
  CONTRADICTED  the count did not grow over the window and is below 80 % of every limit that was read.
  otherwise     INSUFFICIENT_EVIDENCE (too few samples, or a rise that was not monotonic).
A thread pool that is still starting up looks the same as a leak for as long as the window is short: the rule
cannot tell "pool filling to a fixed size" from "threads created and never ended" without a longer window.  That is
stated in the recipe limitations and in the evidence of every SUPPORTED result.
The cause named is the (thread name, top function, source line) shared by the threads that appeared during the window.
The code that *creates* the threads is not observed (a thread's creator is not recorded by the kernel).
"""

from __future__ import annotations

import re
from collections import Counter
from typing import Any, Dict, List, Optional

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
from .fd_leak import _eta, _read_text

RECIPE_THREAD_LEAK = "RECIPE_THREAD_LEAK"
CATEGORY_THREAD_LEAK = "THREAD_LEAK"
OBS_THREAD_GROWTH = "thread_growth"

MIN_SAMPLES = 4        # a series shorter than this is not a trend
MIN_GROWTH = 4         # total threads gained over the window (every sample must be higher than the one before)
NEAR_LIMIT = 0.9       # SUPPORTED at >= 90 % of a limit that was read
CLEAR_LIMIT = 0.8      # CONTRADICTED needs to be below 80 % of every limit that was read
MAX_GROUPS = 3


# ---------------------------------------------------------------------------------------------- collection
def _limits(adapter: Any, pid: int) -> Dict[str, Optional[int]]:
    """Soft RLIMIT_NPROC (per user, all tasks of the user) and kernel threads-max (system wide); None = not read."""
    m = re.search(r"^Max processes\s+(\d+|unlimited)", _read_text(adapter, pid, "limits"), re.M)
    nproc = int(m.group(1)) if m and m.group(1).isdigit() else None
    tmax = None
    try:
        if adapter is not None and getattr(adapter, "is_remote", lambda: False)():
            raw = adapter.read_target_file(pid, "/proc/sys/kernel/threads-max", 64)
            txt = raw.decode("utf-8", "replace") if raw else ""
        else:
            with open("/proc/sys/kernel/threads-max", "r", encoding="utf-8") as fh:
                txt = fh.read()
        if txt.strip().isdigit():
            tmax = int(txt.strip())
    except Exception:  # noqa: BLE001
        tmax = None
    return {"rlimit_nproc": nproc, "threads_max": tmax}


def new_thread_groups(rows: Any) -> List[Dict[str, Any]]:
    """Threads first seen after the first sample, grouped by (name, top function, source line)."""
    c: Counter = Counter()
    for r in rows or []:
        if not isinstance(r, dict) or r.get("appeared_at_sample") in (None, 0, 1):
            continue
        c[(str(r.get("name") or ""), str(r.get("top_function") or ""), str(r.get("top_source_location") or ""))] += 1
    out = []
    for (name, fn, loc), n in c.most_common(MAX_GROUPS):
        g: Dict[str, Any] = {"count": n}
        if name:
            g["thread_name"] = name
        if fn:
            g["function_name"] = fn
        if loc:
            g["source_location"] = loc
        out.append(g)
    return out


def collect_thread_growth(provider: Any, ctx: Dict[str, Any]) -> None:
    od = ctx["observation_data"]
    adapter = getattr(provider, "adapter", None)
    if "thread_count_series" not in od:
        # The sampler window of the thread checks is cached per run (same sampling config): this is a cache hit when
        # one of them already ran, and one ordinary sampling window otherwise.
        try:
            provider._collect_thread_series(ctx["recipe"], ctx["pid"], ctx.get("companion_elf"), od, ctx["all_records"])
        except Exception:  # noqa: BLE001
            pass
    obs: Dict[str, Any] = {"new_threads": new_thread_groups(od.get("thread_summary"))}
    try:
        obs.update(_limits(adapter, ctx["pid"]))
    except Exception:  # noqa: BLE001
        obs.update({"rlimit_nproc": None, "threads_max": None})
    od[OBS_THREAD_GROWTH] = obs
    return None


# ---------------------------------------------------------------------------------------------- the rule
def _series(data: Dict[str, Any]) -> List[int]:
    s = data.get("thread_count_series")
    return [x for x in s if isinstance(x, int) and not isinstance(x, bool)] if isinstance(s, list) else []


def _window(data: Dict[str, Any]) -> Optional[float]:
    w = (data.get("thread_sampling") or {}).get("window_sec")
    return float(w) if isinstance(w, (int, float)) and w > 0 else None


def thread_leak_rule(recipe: DiagnosticRecipe, data: Dict[str, Any]) -> Optional[RecipeEvaluationResult]:
    rid = recipe.recipe_id
    s = _series(data)
    tg = data.get(OBS_THREAD_GROWTH) or {}
    if len(s) < MIN_SAMPLES:
        why = (data.get("thread_sampling") or {}).get("status") or f"{len(s)} sample(s), need {MIN_SAMPLES}"
        return RecipeEvaluationResult(
            recipe_id=rid, status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE, confidence=0.0,
            confidence_basis=f"thread count trend not observed: {why}",
            missing_evidence=["thread_count_series"], limitations=list(recipe.limitations),
            details={"thread_count_series": s})
    limits = {k: tg.get(k) for k in ("rlimit_nproc", "threads_max") if isinstance(tg.get(k), int) and tg.get(k) > 0}
    growth = s[-1] - s[0]
    rising = all(b > a for a, b in zip(s, s[1:]))
    win = _window(data)
    trend = (f"threads {' -> '.join(map(str, s))}" + (f" over {win:.1f} s (+{growth}, {growth / win:.1f}/s)" if win else f" (+{growth})"))
    lim_txt = ", ".join(f"{k} {v}" for k, v in limits.items())
    details = {"thread_count_series": s, "thread_growth": growth, "limits_read": limits,
               "new_threads": tg.get("new_threads") or [], "window_sec": win}
    near = [k for k, v in limits.items() if s[-1] >= NEAR_LIMIT * v]
    if (rising and growth >= MIN_GROWTH) or near:
        groups = [g for g in tg.get("new_threads") or [] if isinstance(g, dict)]
        facts = [trend + (f"; limits: {lim_txt}" if lim_txt else "; no thread limit was read")]
        for g in groups:
            facts.append(f"new threads: {g.get('count')} x {g.get('thread_name') or '?'}"
                         + (f" in {g['function_name']}" if g.get("function_name") else "")
                         + (f" ({g['source_location']})" if g.get("source_location") else ""))
        facts.append("every sample had more threads than the one before; a pool still filling to a fixed size looks "
                     "the same in a window this short")
        return RecipeEvaluationResult(
            recipe_id=rid, status=RECIPE_STATUS_SUPPORTED, confidence=0.8 if rising else 0.7,
            confidence_basis=("Threads keep being created and are not ending: " if rising
                              else f"Thread count near a limit ({', '.join(near)}): ") + trend,
            supporting_facts=facts,
            recommended_action="Find the code that starts the listed threads and make sure each one ends or is joined/"
                               "detached (thread-per-request without a join, a pool without a size bound).",
            limitations=list(recipe.limitations), details=details)
    if growth <= 0 and all(s[-1] < CLEAR_LIMIT * v for v in limits.values()):
        return RecipeEvaluationResult(
            recipe_id=rid, status=RECIPE_STATUS_CONTRADICTED, confidence=0.75,
            confidence_basis="thread count did not grow during the observed window: " + trend,
            contradicting_facts=[trend], recommended_action="No thread leak in the observed window.",
            limitations=list(recipe.limitations), details=details)
    return RecipeEvaluationResult(
        recipe_id=rid, status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE, confidence=0.2,
        confidence_basis="thread count changed but not monotonically (or not by enough) to call a leak: " + trend,
        missing_evidence=["longer thread_count_series"], limitations=list(recipe.limitations), details=details)


register_observation_collector(OBS_THREAD_GROWTH, collect_thread_growth)
register_recipe(DiagnosticRecipe(
    recipe_id=RECIPE_THREAD_LEAK,
    version="1.0.0",
    name="Thread Leak / Thread Exhaustion",
    domain=DOMAIN_ABNORMAL_STATE,
    applicable_problem_categories=[CATEGORY_THREAD_LEAK],
    required_prerequisites=[],
    evidence_sources=["/proc/<pid>/task", "/proc/<pid>/limits", "/proc/sys/kernel/threads-max"],
    collection_steps=[{"step": 1, "action": "reuse_thread_series",
                       "purpose": "the thread sampler window shared with the other thread checks; no extra sampling"},
                      {"step": 2, "action": "read_thread_limits", "purpose": "RLIMIT_NPROC and kernel threads-max"}],
    analysis_rules=["thread count higher at every sample than at the one before, by >= %d in total over >= %d samples, "
                    "is a leak" % (MIN_GROWTH, MIN_SAMPLES),
                    "thread count >= 90 %% of a limit that was read is exhaustion"],
    thresholds_and_conditions={"min_samples": MIN_SAMPLES, "min_growth": MIN_GROWTH, "near_limit": NEAR_LIMIT,
                               "clear_limit": CLEAR_LIMIT},
    supporting_evidence_criteria=["monotonic thread count growth", "thread count near RLIMIT_NPROC / threads-max"],
    contradicting_evidence_criteria=["no thread count growth below 80 % of every limit read"],
    verification_procedure="Count /proc/<pid>/task again later; a leak keeps growing, a pool stops at its size.",
    stop_conditions=["thread sampling unavailable"],
    limitations=["a short window cannot tell a thread pool that is still starting up (it grows, then stays flat) from a "
                 "leak; only a longer observation can",
                 "a leak slower than about one thread per sample interval is not distinguishable from no growth",
                 "RLIMIT_NPROC counts every task of the user and threads-max is system wide: reaching them is a "
                 "bound on this process's threads, not a measure of other users of the limit",
                 "the code that creates the threads is not observed; only the threads that appeared are"],
    output_structure={"thread_count_series": "list[int]", "new_threads": "list"},
    observations=(OBS_THREAD_GROWTH,),
    rule=thread_leak_rule,
), baseline=True, category=CATEGORY_THREAD_LEAK)


# ---------------------------------------------------------------------------------------------- presentation
_TXT = {
    "trend": ("The process had {a} threads at the first sample and {b} at the last, {win}; every sample had more "
              "threads than the one before.",
              "첫 샘플에서 스레드가 {a}개였고 마지막 샘플에서 {b}개였습니다 ({win}). 모든 샘플이 직전 샘플보다 스레드가 많았습니다."),
    "win": ("over {w} s (+{r}/s)", "{w}초 동안 초당 +{r}개"),
    "nowin": ("window length not recorded", "관측 구간 길이는 기록되지 않았습니다"),
    "new": ("Threads that appeared during the observation: {x}.", "관측하는 동안 새로 생긴 스레드: {x}."),
    "grp": ("{n} named {name}, starting in {fn}", "{name} 이름 {n}개, 시작 함수 {fn}"),
    "grp_nofn": ("{n} named {name}", "{name} 이름 {n}개"),
    "limit": ("Limit {k} is {v}; at this rate this process's threads alone would reach it in about {eta}.",
              "한도 {k}은(는) {v}개이며, 이 속도면 이 프로세스의 스레드만으로 약 {eta} 뒤에 도달합니다."),
    "near": ("{b} threads against a limit {k} of {v} ({pct}% of it).", "한도 {k} {v}개 중 {b}개를 쓰고 있습니다 ({pct}%)."),
    "nolimit": ("No thread limit was read (not observed).", "스레드 한도는 읽지 못했습니다 (관측되지 않음)."),
    "pool": ("A thread pool that is still filling up looks the same in a window this short; only a longer observation "
             "tells a leak from a pool that stops at its size.",
             "짧은 관측 구간에서는 아직 채워지는 중인 스레드 풀도 똑같이 보입니다. 누수인지 크기가 정해진 풀인지는 더 오래 봐야 알 수 있습니다."),
    "closer": ("Which code creates these threads was not observed; look for the code that starts {x} threads without "
               "joining or detaching them.",
               "이 스레드를 만드는 코드는 관측되지 않았습니다. {x} 스레드를 시작하고 join/detach 하지 않는 코드를 찾으세요."),
    "chart": ("Thread count over the observation", "관측하는 동안 스레드 수"),
    "x": ("sample number ({iv} s apart, nominal)", "샘플 번호 (약 {iv}초 간격)"),
    "y": ("threads", "스레드 수"),
    "tip": ("sample {i}: {n} threads", "샘플 {i}: 스레드 {n}개"),
    "newh": ("New threads (name, start function)", "새로 생긴 스레드 (이름, 시작 함수)"),
    "nonew": ("Which threads are new was not observed.", "어떤 스레드가 새로 생겼는지는 관측되지 않았습니다."),
}

_LIMIT_NAMES = {"rlimit_nproc": "RLIMIT_NPROC", "threads_max": "threads-max"}


def _tl_check(report: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    checks = ((report or {}).get("section_d_detailed_inspection_results") or {}).get("checks") or []
    for c in checks:
        if isinstance(c, dict) and c.get("recipe_id") == RECIPE_THREAD_LEAK:
            ao = c.get("actual_observations")
            if isinstance(ao, dict):
                return ao
    return {}


def _tl_series(ao: Dict[str, Any]) -> List[int]:
    return _series(ao)


def _tl_facts(i: int, ao: Dict[str, Any], wrap: Any) -> List[str]:
    """Sentences of the thread finding; ``wrap`` formats an identifier for the output medium."""
    s = _tl_series(ao)
    if len(s) < 2:
        return []
    tg = ao.get(OBS_THREAD_GROWTH) if isinstance(ao.get(OBS_THREAD_GROWTH), dict) else {}
    win = _window(ao)
    a, b = s[0], s[-1]
    out: List[str] = []
    rate = (b - a) / win if win else None
    wtxt = _TXT["win"][i].format(w=f"{win:.1f}", r=f"{rate:.1f}") if win and b > a else _TXT["nowin"][i]
    out.append(_TXT["trend"][i].format(a=a, b=b, win=wtxt))
    groups = [g for g in tg.get("new_threads") or [] if isinstance(g, dict)]
    if groups:
        parts = []
        for g in groups:
            name = wrap(g.get("thread_name") or "?")
            if g.get("function_name"):
                parts.append(_TXT["grp"][i].format(n=g.get("count"), name=name, fn=wrap(g["function_name"])))
            else:
                parts.append(_TXT["grp_nofn"][i].format(n=g.get("count"), name=name))
        out.append(_TXT["new"][i].format(x="; ".join(parts)))
    else:
        out.append(_TXT["nonew"][i])
    shown = False
    for k, label in _LIMIT_NAMES.items():
        v = tg.get(k)
        if isinstance(v, int) and v > 0:
            shown = True
            if rate and rate > 0 and v > b:
                out.append(_TXT["limit"][i].format(k=label, v=v, eta=_eta((v - b) / rate, bool(i))))
            else:
                out.append(_TXT["near"][i].format(b=b, k=label, v=v, pct=round(b * 100 / v)))
    if not shown:
        out.append(_TXT["nolimit"][i])
    out.append(_TXT["pool"][i])
    if groups:
        out.append(_TXT["closer"][i].format(x=wrap(groups[0].get("thread_name") or "?")))
    return out


def thread_finding_text(ctx: Any, finding: Dict[str, Any], report: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return {"lines": _tl_facts(ctx.i, _tl_check(report), lambda x: "`" + str(x).replace("`", "'") + "`")}


def thread_finding_viz(lx: Any, finding: Dict[str, Any], report: Optional[Dict[str, Any]], uid: str = "0") -> str:
    from ..report_visuals import chip, code, esc, facts_list, series_chart, share_bars
    ao = _tl_check(report)
    s = _tl_series(ao)
    if len(s) < 2:
        return ""
    i = lx.i
    win = _window(ao)
    iv = f"{win / (len(s) - 1):.2f}" if win else "?"
    out = [f'<h4>{esc(_TXT["chart"][i])} {chip(lx, "obs")}</h4>',
           series_chart([float(k + 1) for k in range(len(s))], [float(n) for n in s], _TXT["chart"][i],
                        _TXT["x"][i].format(iv=iv), _TXT["y"][i],
                        [_TXT["tip"][i].format(i=k + 1, n=n) for k, n in enumerate(s)])]
    marks: List[str] = []

    def wrap(x: Any) -> str:
        marks.append(str(x))
        return f"\x00{len(marks) - 1}\x00"

    facts = []
    for line in _tl_facts(i, ao, wrap):
        h = esc(line)
        for k, m in enumerate(marks):
            h = h.replace(f"\x00{k}\x00", code(m))
        facts.append(h)
    out.append(facts_list(facts))
    tg = ao.get(OBS_THREAD_GROWTH) if isinstance(ao.get(OBS_THREAD_GROWTH), dict) else {}
    groups = [g for g in tg.get("new_threads") or [] if isinstance(g, dict)]
    if groups:
        out.append(f'<h4>{esc(_TXT["newh"][i])} {chip(lx, "obs")}</h4>'
                   + share_bars([((str(g.get("thread_name") or "?") + (" / " + str(g["function_name"]) if g.get("function_name") else "")),
                                  float(g.get("count") or 0)) for g in groups]))
    else:
        out.append(f'<p class="dsv-note">{esc(_TXT["nonew"][i])} {chip(lx, "no")}</p>')
    return "".join(out)


def _register_presentation() -> None:
    from ..report_registry import register_category, register_finding_text, register_finding_viz, register_recipe_label
    register_category(CATEGORY_THREAD_LEAK, "thread leak", "스레드 누수")
    register_recipe_label(RECIPE_THREAD_LEAK, "ABNORMAL_STATE", "Thread leak", "스레드 누수",
                          "a thread count that keeps rising during the observation or approaches a limit",
                          "관측 중 계속 늘어나거나 한도에 가까워지는 스레드 수")
    register_finding_text(CATEGORY_THREAD_LEAK, thread_finding_text)
    register_finding_viz(CATEGORY_THREAD_LEAK, thread_finding_viz)


_register_presentation()

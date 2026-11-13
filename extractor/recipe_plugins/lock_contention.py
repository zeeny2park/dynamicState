"""Lock contention - registered entirely from this file (docs/EXTENDING_DIAGNOSIS.md).

"The process is slow because everything queues on lock X": several threads spend most of the observation blocked
on one mutex whose owner keeps making progress.  This is a degradation, never a fault: a finding of this check
carries ``finding_severity = "INFO"`` and, when it is the only finding, the diagnosis verdict is DEGRADED.  It is
not a deadlock (the owner moves) and not an orphan lock (the owner is a live thread of the process).

Data: the shared thread-sampler window (5 samples over about 0.7 s, cached per run and shared with the other thread
checks, so this check adds no sampling time).  Every sample of that window carries one lock inspection; the sampler
reduces it to ``lock_wait_samples``: per mutex the owner tid, the state word and the tids blocked in a futex wait
on it, plus the owner's cumulative CPU ticks + context switches read in the same sample.  Observation kind
``lock_contention`` reorganises that into one row per mutex (waiters and owner per sample).  Read-only, zero-stop.

Verdict rule (``lock_contention_rule``; thresholds are recipe thresholds, values measured in the tests/benchmark):
  SUPPORTED     >= MIN_SAMPLES samples with a lock inspection, and one mutex had >= MIN_WAITERS (2) threads waiting
                in >= SUPPORT_FRACTION (75 %) of the samples, and its ownership or the owner's progress changed in
                the window (the owner tid differs between samples, or the owner's CPU ticks / context switches
                rose between two samples in which it was the owner), the owner is a thread of the process, and
                no wait cycle was seen.  Category LOCK_CONTENTION, severity INFO (not a fault), capped at probable.
  CONTRADICTED  the lock waits were observed completely (>= MIN_SAMPLES samples) and no mutex had >= MIN_WAITERS
                waiters in more than CLEAR_FRACTION (40 %) of them.
  INSUFFICIENT  fewer than MIN_SAMPLES lock inspections; a mutex between the two bars; or the waiters are there but
                the owner did not move (that is a stall: the deadlock / blocked-thread checks own it), the owner
                is not a thread of the process (orphan), or a wait cycle was seen (deadlock).
Not measured: how long each hold lasts.  Samples are 0.15 s apart, so a hold shorter than that is seen only as
"locked at this instant"; the rule decides from how often the lock was found locked with waiters, not from hold
times.  Mutexes the inspector cannot discover (no debug info for the variable, not named by a futex wait) are outside
the check; this is a declared limit.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from ..diagnostic_recipes import (
    DOMAIN_CONCURRENCY,
    RECIPE_STATUS_CONTRADICTED,
    RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
    RECIPE_STATUS_SUPPORTED,
    DiagnosticRecipe,
    RecipeEvaluationResult,
    register_recipe,
)
from ..runtime_evidence_provider import register_observation_collector

RECIPE_LOCK_CONTENTION = "RECIPE_LOCK_CONTENTION"
CATEGORY_LOCK_CONTENTION = "LOCK_CONTENTION"
OBS_LOCK_CONTENTION = "lock_contention"

MIN_SAMPLES = 4            # samples with a lock inspection needed for any verdict
MIN_WAITERS = 2            # threads blocked on the mutex for a sample to count as "queued"
SUPPORT_FRACTION = 0.75    # fraction of the samples that must be queued for SUPPORTED
CLEAR_FRACTION = 0.4       # CONTRADICTED only when no mutex was queued in more than this fraction
MAX_LOCK_ROWS = 6

LOCKED_WORDS = (1, 2)


# ---------------------------------------------------------------------------------------------- reduction
def _where(rows: List[Dict[str, Any]], tids: List[int], limit: int = 3) -> List[Dict[str, Any]]:
    """Name and source location of the given threads, from the thread rows of the window."""
    by_tid = {r.get("tid"): r for r in rows if isinstance(r, dict)}
    out: List[Dict[str, Any]] = []
    for t in tids:
        r = by_tid.get(t) or {}
        item = {"tid": t, "thread_name": r.get("name")}
        if r.get("top_function"):
            item["function_name"] = r["top_function"]
        if r.get("top_source_location"):
            item["source_location"] = r["top_source_location"]
        out.append(item)
        if len(out) >= limit:
            break
    return out


def analyse(samples: List[Dict[str, Any]], thread_rows: Optional[List[Dict[str, Any]]] = None,
            cycle_seen: bool = False) -> Dict[str, Any]:
    """One row per mutex from the sampler's ``lock_wait_samples`` (pure; no I/O)."""
    samples = [s for s in samples if isinstance(s, dict) and isinstance(s.get("locks"), list)]
    rows_in = [r for r in (thread_rows or []) if isinstance(r, dict)]
    n = len(samples)
    obs: Dict[str, Any] = {"samples": n, "window_s": 0.0, "mutexes": [], "wait_cycle_seen": bool(cycle_seen),
                           "min_waiters": MIN_WAITERS}
    if n:
        obs["window_s"] = round(float(samples[-1].get("t_s", 0.0)) - float(samples[0].get("t_s", 0.0)), 3)
    addrs: Dict[str, str] = {}
    for s in samples:
        for l in s["locks"]:
            if isinstance(l, dict) and l.get("address") is not None:
                addrs.setdefault(str(l["address"]), str(l.get("lock") or l["address"]))
    out: List[Dict[str, Any]] = []
    for addr, name in addrs.items():
        per: List[Dict[str, Any]] = []
        owners: List[int] = []
        progressed = changed = gone = False
        prev: Optional[Dict[str, Any]] = None
        for s in samples:
            l = next((x for x in s["locks"] if isinstance(x, dict) and str(x.get("address")) == addr), None)
            owner = l.get("owner_tid") if l else None
            owner = owner if isinstance(owner, int) and owner > 0 and l.get("state_word") in LOCKED_WORDS else None
            waiters = [int(w) for w in (l.get("waiter_tids") or [])] if l else []
            work = (s.get("owner_work") or {}).get(str(owner)) if owner is not None else None
            per.append({"t_s": s.get("t_s"), "o": owner, "n": len(waiters), "w": waiters[:8]})
            if owner is not None:
                if owner not in owners:
                    owners.append(owner)
                if s.get("thread_ids") and owner not in s["thread_ids"]:
                    gone = True
                if prev is not None and prev["o"] is not None:
                    if prev["o"] != owner:
                        changed = True
                    elif work is not None and prev["work"] is not None and work > prev["work"]:
                        progressed = True
            prev = {"o": owner, "work": work}
        queued = sum(1 for p in per if p["n"] >= MIN_WAITERS)
        allw = sorted({w for p in per for w in p["w"]})
        out.append({"lock_name": name, "address": addr, "per_sample": per, "samples_queued": queued,
                    "queued_fraction": round(queued / n, 3) if n else 0.0,
                    "max_waiters": max((p["n"] for p in per), default=0),
                    "mean_waiters": round(sum(p["n"] for p in per) / n, 2) if n else 0.0,
                    "owner_tids": owners, "owner_changed": changed or len(owners) > 1, "owner_progressed": progressed,
                    "owner_gone": gone,
                    "owner_where": _where(rows_in, owners), "waiter_where": _where(rows_in, allw)})
    out.sort(key=lambda r: (-r["queued_fraction"], -r["mean_waiters"], r["lock_name"]))
    obs["mutexes"] = out[:MAX_LOCK_ROWS]
    return obs


def collect_lock_contention(provider: Any, ctx: Dict[str, Any]) -> None:
    od = ctx["observation_data"]
    if "thread_count_series" not in od:
        # the sampler window is cached per run and shared with the other thread checks (cache hit when one ran)
        try:
            provider._collect_thread_series(ctx["recipe"], ctx["pid"], ctx.get("companion_elf"), od, ctx["all_records"])
        except Exception:  # noqa: BLE001
            pass
    ts = od.get("thread_sampling") or {}
    obs = analyse(od.get("lock_wait_samples") or [], od.get("thread_summary") or [], bool(od.get("lock_cycle_seen")))
    obs["sampling_status"] = ts.get("status")
    od[OBS_LOCK_CONTENTION] = obs
    return None


# ---------------------------------------------------------------------------------------------- the rule
def _row_text(r: Dict[str, Any], n: int) -> str:
    return ("mutex '%s': >= %d threads waiting in %d of %d samples (up to %d, mean %.1f); %s"
            % (r["lock_name"], MIN_WAITERS, r["samples_queued"], n, r["max_waiters"], r["mean_waiters"],
               ("the owner changed between samples (%d different owners)" % len(r["owner_tids"])
                if r["owner_changed"] else "the owner's CPU time / context switches advanced")))


def lock_contention_rule(recipe: DiagnosticRecipe, data: Dict[str, Any]) -> Optional[RecipeEvaluationResult]:
    rid = recipe.recipe_id
    lc = data.get(OBS_LOCK_CONTENTION) or {}
    n = int(lc.get("samples") or 0)
    locks = [r for r in lc.get("mutexes") or [] if isinstance(r, dict)]
    details: Dict[str, Any] = {"lock_contention": lc}

    def insufficient(why: str, conf: float = 0.2) -> RecipeEvaluationResult:
        return RecipeEvaluationResult(
            recipe_id=rid, status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE, confidence=conf,
            confidence_basis="lock contention not decided: " + why, missing_evidence=["lock_wait_samples"],
            limitations=list(recipe.limitations), details=dict(details, reason=why))

    if n < MIN_SAMPLES:
        return insufficient("%d sample(s) with a lock inspection, need %d" % (n, MIN_SAMPLES), 0.0)
    best = locks[0] if locks else None
    frac = best["queued_fraction"] if best else 0.0
    if best is None or frac <= CLEAR_FRACTION:
        txt = ("%d samples over %.2f s: no mutex had %d or more threads waiting in more than %d %% of them%s"
               % (n, float(lc.get("window_s") or 0.0), MIN_WAITERS, int(CLEAR_FRACTION * 100),
                  ("; busiest: " + _row_text(best, n)) if best and best["samples_queued"] else ""))
        return RecipeEvaluationResult(
            recipe_id=rid, status=RECIPE_STATUS_CONTRADICTED, confidence=0.75, confidence_basis=txt,
            contradicting_facts=[txt], recommended_action="No lock contention in the observed window.",
            limitations=list(recipe.limitations), details=dict(details, mutexes=len(locks)))
    if frac < SUPPORT_FRACTION:
        return insufficient("mutex '%s' had %d or more waiters in %d %% of the samples: between the %d %% and %d %% bars"
                            % (best["lock_name"], MIN_WAITERS, round(frac * 100), int(CLEAR_FRACTION * 100),
                               int(SUPPORT_FRACTION * 100)), 0.3)
    if lc.get("wait_cycle_seen"):
        return insufficient("a wait cycle was seen: that is a deadlock, not contention", 0.3)
    hot = [r for r in locks if r["queued_fraction"] >= SUPPORT_FRACTION]
    ok = [r for r in hot if not r["owner_gone"] and (r["owner_changed"] or r["owner_progressed"])]
    if not ok:
        why = ("its owner is not a thread of the process" if any(r["owner_gone"] for r in hot)
               else "its owner made no progress (same owner, no CPU time or context switch): a stall, not contention")
        return insufficient("mutex '%s' is queued on but %s" % (hot[0]["lock_name"], why), 0.3)
    facts = [_row_text(r, n) for r in ok]
    facts.append("%d samples over %.2f s, one lock inspection each" % (n, float(lc.get("window_s") or 0.0)))
    ctr = [{"lock_name": r["lock_name"],
            "owner_name": sorted({w["thread_name"] for w in r["owner_where"] if w.get("thread_name")}),
            "source_location": [w["source_location"] for w in r["owner_where"] if w.get("source_location")][:2]}
           for r in ok]
    details.update(finding_category=CATEGORY_LOCK_CONTENTION, finding_severity="INFO", non_fault=True,
                   finding_summary=facts[0], certainty_cap="PROBABLE",
                   certainty_cap_reason="contention explains slowness; it is a degradation, not a fault",
                   contended_locks=ctr, queued_fraction=ok[0]["queued_fraction"], samples=n)
    return RecipeEvaluationResult(
        recipe_id=rid, status=RECIPE_STATUS_SUPPORTED, confidence=0.7, confidence_basis=facts[0],
        supporting_facts=facts, limitations=list(recipe.limitations),
        recommended_action="Not a deadlock. Shorten the critical section of the contended mutex, split it (per-bucket "
                           "or per-object locks), or move the slow work out of the lock.",
        details=details)


register_observation_collector(OBS_LOCK_CONTENTION, collect_lock_contention)
register_recipe(DiagnosticRecipe(
    recipe_id=RECIPE_LOCK_CONTENTION,
    version="1.0.0",
    name="Lock Contention (threads queue on a mutex whose owner keeps running)",
    domain=DOMAIN_CONCURRENCY,
    applicable_problem_categories=[CATEGORY_LOCK_CONTENTION],
    required_prerequisites=[],
    evidence_sources=["pthread_mutex_t words", "/proc/<pid>/task", "/proc/<tid>/syscall", "/proc/<tid>/stat"],
    collection_steps=[{"step": 1, "action": "reuse_thread_series",
                       "purpose": "the thread sampler window shared with the other thread checks; one lock inspection "
                                  "per sample, no extra sampling"}],
    analysis_rules=["a mutex with >= %d waiting threads in >= %d %% of >= %d samples, whose owner changed or made "
                    "progress, is contention (a degradation, not a fault)"
                    % (MIN_WAITERS, int(SUPPORT_FRACTION * 100), MIN_SAMPLES)],
    thresholds_and_conditions={"lock_contention_min_samples": MIN_SAMPLES, "lock_contention_min_waiters": MIN_WAITERS,
                               "lock_contention_support_fraction": SUPPORT_FRACTION,
                               "lock_contention_clear_fraction": CLEAR_FRACTION},
    supporting_evidence_criteria=["a mutex with queued waiters in most samples and an owner that changes or runs"],
    contradicting_evidence_criteria=["no mutex with two or more waiters in more than 40 % of the samples"],
    verification_procedure="Profile lock hold times (e.g. with a lock profiler): the contended mutex is held for a "
                           "large share of the wall time.",
    stop_conditions=["fewer than %d lock inspections in the sampler window" % MIN_SAMPLES],
    limitations=["how long each hold lasts is not measured: samples are 0.15 s apart and see only whether the lock was "
                 "locked with waiters at that instant",
                 "only pthread_mutex_t variables the inspector discovers (debug info or a futex wait address) are "
                 "examined; a program-private lock or one without debug info is invisible",
                 "contention that comes in bursts shorter than the window is not reported"],
    output_structure={"mutexes": "list[{lock_name, per_sample[{o, n, w}], queued_fraction, owner_where}]"},
    observations=(OBS_LOCK_CONTENTION,),
    rule=lock_contention_rule,
), baseline=True, category=CATEGORY_LOCK_CONTENTION)


# ---------------------------------------------------------------------------------------------- presentation
_TXT = {
    "queue": ("Threads queue on mutex {lock}: at least {k} threads were blocked waiting for it in {q} of {n} samples "
              "(up to {mx} at once, {mean} on average).",
              "스레드들이 뮤텍스 {lock}에서 줄을 서 있습니다. {n}번의 샘플 중 {q}번에서 {k}개 이상의 스레드가 이 락을 기다렸습니다 "
              "(최대 {mx}개, 평균 {mean}개)."),
    "owner_chg": ("The owner of the lock was different in different samples ({names}), so it is being handed on: the "
                  "lock is busy, not stuck.",
                  "락의 소유자가 샘플마다 달랐습니다 ({names}). 락이 계속 넘겨지고 있으므로 멈춘 것이 아니라 바쁜 것입니다."),
    "owner_run": ("The owner ({names}) kept using CPU or switching context while holding it, so it is making progress.",
                  "소유자({names})는 락을 잡은 채로 CPU를 쓰거나 문맥 전환을 계속했으므로 진행 중입니다."),
    "owner_at": ("The lock is held at {locs}.", "락을 잡고 있는 위치: {locs}."),
    "not_fault": ("This is a slowdown, not a fault: nothing is stuck (no deadlock, no lost lock). How long each hold "
                  "lasts was not measured; only how often the lock was found locked with waiters.",
                  "이것은 결함이 아니라 속도 저하입니다. 멈춰 있는 것은 없습니다(교착도, 잃어버린 락도 없음). 락을 한 번 잡을 때 "
                  "얼마나 오래 쥐는지는 측정하지 않았고, 락이 잠긴 채 대기자가 있는 빈도만 관측했습니다."),
    "title": ("Waiters and owner of {lock}, per sample", "{lock}의 샘플별 대기자 수와 소유자"),
    "waiters": ("waiting threads per sample", "샘플별 대기 스레드 수"),
    "owners": ("owner per sample (tid)", "샘플별 소유자 (tid)"),
    "held_at": ("Where the lock is held", "락을 잡고 있는 위치"),
    "waiting": ("Threads waiting for it", "기다리는 스레드"),
    "no_hold": ("Not observed: how long each hold lasts.", "관측하지 못한 것: 한 번 잡을 때 쥐는 시간."),
    "free": ("free", "비어 있음"),
    "tip": ("sample {i}: {n} waiting, owner {o}", "샘플 {i}: 대기 {n}개, 소유자 {o}"),
}


def _lc_obs(report: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    checks = ((report or {}).get("section_d_detailed_inspection_results") or {}).get("checks") or []
    for c in checks:
        if isinstance(c, dict) and c.get("recipe_id") == RECIPE_LOCK_CONTENTION:
            lc = (c.get("actual_observations") or {}).get(OBS_LOCK_CONTENTION)
            if isinstance(lc, dict):
                return lc
    return {}


def _hot_rows(lc: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [r for r in lc.get("mutexes") or [] if isinstance(r, dict) and isinstance(r.get("queued_fraction"), (int, float))
            and r["queued_fraction"] >= SUPPORT_FRACTION and not r.get("owner_gone")
            and (r.get("owner_changed") or r.get("owner_progressed"))]


def _owner_names(r: Dict[str, Any], wrap: Any) -> str:
    names = sorted({str(w.get("thread_name")) for w in r.get("owner_where") or [] if isinstance(w, dict) and w.get("thread_name")})
    return ", ".join(wrap(x) for x in names) or ", ".join("tid %s" % t for t in r.get("owner_tids") or [])


def _lc_facts(i: int, lc: Dict[str, Any], wrap: Any) -> List[str]:
    out: List[str] = []
    n = int(lc.get("samples") or 0)
    for r in _hot_rows(lc)[:3]:
        out.append(_TXT["queue"][i].format(lock=wrap(r.get("lock_name")), k=int(lc.get("min_waiters") or MIN_WAITERS),
                                           q=r.get("samples_queued"), n=n, mx=r.get("max_waiters"),
                                           mean=r.get("mean_waiters")))
        out.append(_TXT["owner_chg" if r.get("owner_changed") else "owner_run"][i].format(names=_owner_names(r, wrap)))
        locs = [str(w["source_location"]) for w in r.get("owner_where") or [] if isinstance(w, dict) and w.get("source_location")]
        if locs:
            out.append(_TXT["owner_at"][i].format(locs=", ".join(wrap(x) for x in locs[:3])))
    if out:
        out.append(_TXT["not_fault"][i])
    return out


def _wrap_md(x: Any) -> str:
    return "`" + str(x).replace("`", "'") + "`"


def lock_contention_finding_text(ctx: Any, finding: Dict[str, Any], report: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    return {"lines": _lc_facts(ctx.i, _lc_obs(report), _wrap_md)}


def lock_contention_finding_viz(lx: Any, finding: Dict[str, Any], report: Optional[Dict[str, Any]], uid: str = "0") -> str:
    from ..report_visuals import chip, code, esc, facts_list, thread_strip
    from .lock_faults import _facts_html
    lc = _lc_obs(report)
    rows = _hot_rows(lc)
    if not rows:
        return ""
    i = lx.i
    out: List[str] = []
    for r in rows[:3]:
        per = [p for p in r.get("per_sample") or [] if isinstance(p, dict)][:40]
        cells = []
        for k, p in enumerate(per, 1):
            n = int(p.get("n") or 0)
            tip = _TXT["tip"][i].format(i=k, n=n, o=p.get("o") if p.get("o") is not None else _TXT["free"][i])
            cells.append(f'<i class="dsv-st-{"D" if n >= int(lc.get("min_waiters") or MIN_WAITERS) else "S"}" '
                         f'title="{esc(tip)}">{n}</i>')
        owners = " → ".join(code(p.get("o") if p.get("o") is not None else "-") for p in per)
        who = "".join(
            f'<li>{code(w.get("thread_name") or "tid %s" % w.get("tid"))} <span class="dsv-note">tid {esc(w.get("tid"))}</span>'
            + (f' {code(w["source_location"])}' if w.get("source_location") else "") + "</li>"
            for w in r.get("waiter_where") or [] if isinstance(w, dict))
        held = "".join(
            f'<li>{code(w.get("thread_name") or "tid %s" % w.get("tid"))}'
            + (f' {code(w["function_name"])}' if w.get("function_name") else "")
            + (f' {code(w["source_location"])}' if w.get("source_location") else "") + "</li>"
            for w in r.get("owner_where") or [] if isinstance(w, dict))
        title = esc(_TXT["title"][i].replace("{lock}", "\x00")).replace("\x00", code(r.get("lock_name")))
        out.append(
            f'<h4>{title} {chip(lx, "obs")}</h4>'
            f'<div class="dsv-scroll"><table class="dsv-tbl"><tbody>'
            f'<tr><th>{esc(_TXT["waiters"][i])}</th><td><span class="dsv-smp">{"".join(cells)}</span></td></tr>'
            f'<tr><th>{esc(_TXT["owners"][i])}</th><td>{owners}</td></tr>'
            f'<tr><th>{esc(_TXT["held_at"][i])}</th><td><ul class="dsv-facts">{held}</ul></td></tr>'
            f'<tr><th>{esc(_TXT["waiting"][i])}</th><td><ul class="dsv-facts">{who}</ul></td></tr>'
            f'</tbody></table></div>')
    out.append(_facts_html(_lc_facts, i, lc))
    out.append(f'<p class="dsv-note">{esc(_TXT["no_hold"][i])} {chip(lx, "no")}</p>')
    out.append(thread_strip(lx, finding, report, []))   # waiters are not a cycle: nothing highlighted
    return "".join(out)


def _register_presentation() -> None:
    from ..report_registry import register_category, register_finding_text, register_finding_viz, register_recipe_label
    register_category(CATEGORY_LOCK_CONTENTION, "threads queue on one lock (lock contention)",
                      "여러 스레드가 한 락에서 줄을 서 있음 (락 경합)")
    register_recipe_label(RECIPE_LOCK_CONTENTION, "CONCURRENCY", "Lock contention", "락 경합",
                          "several threads blocked on one mutex whose owner keeps making progress",
                          "소유자가 계속 진행하는 한 뮤텍스를 여러 스레드가 기다리는 상태")
    register_finding_text(CATEGORY_LOCK_CONTENTION, lock_contention_finding_text)
    register_finding_viz(CATEGORY_LOCK_CONTENTION, lock_contention_finding_viz)


_register_presentation()

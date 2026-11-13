"""The HEALTHY verdict of ``diagnose`` (rule RULE_5B_HEALTHY_WITHIN_BASELINE_SCOPE; docs/HEALTHY_VERDICT.md).

HEALTHY means: every baseline check ran to completion with the evidence it needs and found nothing, within its
stated scope.  It is a positive statement about what was checked, never "nothing was found because nothing could
be looked at" (that stays INCONCLUSIVE, IMP-001).

A diagnosis is HEALTHY only if ALL of the following hold (rule 5 is applied before rule 4 in the code):

1. Collection succeeded: none of the blocking ``not_covered`` kinds (``BLOCKING_KINDS``: target unreadable /
   unreachable, missing debug image, ABI detection failed, a stage failed, nothing executed, a baseline check not
   run, observation budget exhausted, engine limitation, unattributed finding, unexpected error) and no kind this
   rule does not know (an unknown kind blocks).
2. No finding of any severity and no FAIL check (baseline or symptom-specific); the aggregator verdict is
   INCONCLUSIVE or HEALTHY (never a fault, DEGRADED or ABORTED).
3. Every baseline recipe (``diagnostic_recipes.BASELINE_RECIPE_IDS``) has at least one executed check and every
   check of it cleared:
   * status PASS (the recipe looked and found nothing: CONTRADICTED), or
   * RECIPE_HEAP_METADATA_CORRUPTION INCONCLUSIVE only because the heap was above the baseline walk cap (a declared
     cost limit: ``memory_integrity.heap.not_checked_reason == "above_baseline_cap"``) while the global-adjacency
     and stack-margin parts completed and found nothing.  Listed in ``not_checked``.
   * RECIPE_FREED_MEMORY_USE / RECIPE_DOUBLE_FREE INCONCLUSIVE only because they reuse that heap walk and it was
     skipped for the same cap.  Listed in ``not_checked``.
   Anything else (INCONCLUSIVE, ERROR, NOT_APPLICABLE, UNSUPPORTED, NOT_EXECUTED) blocks.  In particular a baseline
   check that could not run for a target-support reason (e.g. mutex owners not decodable -> the deadlock / lock
   checks are INCONCLUSIVE) blocks: the question it owns was not answered.
4. Scope limits do not block but are listed in ``healthy_scope.not_checked`` and named in the summary:
   features unsupported on the target ABI that no baseline check needed (``unsupported_on_target``), the heap cap
   above, long waits in syscalls whose expectedness cannot be judged from outside (``long_wait_not_judged``),
   leak-owner attribution limits when the leak check itself cleared, remote-target limits, symptom-specific
   (non-baseline) checks that reached no result, recipes not planned for the symptom, and the questions of recipes
   this mode cannot execute (``unsupported_in_mode``: declared ``requires_capabilities``, left out of the plan).

5. Verification scope (stage 1): every problem category a *specific* symptom asks about (the classifier's
   candidate categories; none for a vague / general health check) is answered by a check that answers that category
   and ran to completion with a clear result (PASS).  Otherwise the verdict is INCONCLUSIVE with the blocking reason
   ``symptom_question_unanswered`` naming the category and what happened to its checks (no result, or not
   supported in this mode).  "Evidence exists" is not enough: the question must have been checked.

Beyond rule 5, a symptom-specific check that reached no result does not gate HEALTHY when another completed check
answered the same question (a FAIL still blocks, through rule 2); it is listed as not checked.  Defect classes no baseline check looks for (data races, logic errors) and the
forms of use-after-free / double free that leave no trace in a heap walk are always listed as not checked
(``outside_baseline``).
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple

from .diagnostic_methodology import CheckStatus

HEALTHY_RULE_ID = "RULE_5B_HEALTHY_WITHIN_BASELINE_SCOPE"

OBS_FREED_MEMORY_USE = "freed_memory_use"   # observation key of RECIPE_FREED_MEMORY_USE (recipe_plugins.use_after_free)

# not_covered kinds that mean the diagnosis could not look (never a scope limit)
BLOCKING_KINDS = frozenset({
    "target_unreadable", "target_unreachable", "invalid_target", "missing_debug_image", "abi_detection_failed",
    "stage_failed", "not_executed", "baseline_check_not_run", "budget_exhausted", "limitation",
    "unattributed_finding", "unexpected_error",
})
# not_covered kinds that are declared scope limits (listed, not blocking).  check_* kinds are decided per check.
SCOPE_KINDS = frozenset({
    "unsupported_on_target", "recipes_not_planned", "remote_limitation", "collector_not_deployed",
    "integrity_not_checked", "integrity_limited", "leak_owner_limited", "report_not_saved", "long_wait_not_judged",
    "unsupported_in_mode",
})

# What each built-in baseline check clears, in plain words (en, ko).  A plugin baseline recipe uses its name.
BASELINE_SCOPE_LABELS: Dict[str, Tuple[str, str]] = {
    "RECIPE_THREAD_STATE_ANOMALIES": ("threads spinning without progress, zombie or stuck threads",
                                      "진전 없이 도는 스레드, 좀비·멈춘 스레드"),
    "RECIPE_LONG_RUNNING_BLOCKED_THREADS": ("threads blocked on a lock whose owner makes no progress",
                                            "락 소유자가 진행하지 않는데 그 락을 기다리는 스레드"),
    "RECIPE_SUSPICIOUS_LOCK_OWNERSHIP": ("locks held by a dead or invalid owner", "죽었거나 잘못된 소유자가 잡은 락"),
    "RECIPE_POTENTIAL_DEADLOCK_PATTERNS": ("deadlock (lock wait-for cycles)", "교착 상태(락 대기 고리)"),
    "RECIPE_PROCESS_MEMORY_GROWTH": ("memory growth / leak in the observation window", "관측 구간의 메모리 증가·누수"),
    "RECIPE_HEAP_METADATA_CORRUPTION": ("heap metadata damage, global array overruns, stack exhaustion",
                                        "힙 메타데이터 손상, 전역 배열 넘침, 스택 고갈"),
    "RECIPE_FD_LEAK": ("file-descriptor leak", "파일 디스크립터 누수"),
}

OUTSIDE_BASELINE = ("data races and program-logic errors (no baseline check looks for them); a use-after-free "
                    "that leaves no typed pointer to a freed block and no write into one, and a double free of a "
                    "block re-allocated in between (the heap walk cannot see them)",
                    "데이터 레이스, 프로그램 논리 오류 (기본 검사가 찾지 않는 종류); 해제된 블록을 가리키는 타입 있는 "
                    "포인터도, 해제된 블록에 대한 쓰기도 남기지 않은 해제 후 사용, 그리고 사이에 다시 할당된 블록의 "
                    "이중 해제 (힙 순회로는 보이지 않음)")


_NOT_CHECKED_ORDER = {k: i for i, k in enumerate((
    "integrity_not_checked", "long_wait_not_judged", "leak_owner_limited", "integrity_limited",
    "unsupported_on_target", "remote_limitation", "symptom_checks_without_result", "unsupported_in_mode",
    "outside_baseline"))}


def _st(c: Any) -> str:
    return str(getattr(c, "status", ""))


def _obs(c: Any) -> Dict[str, Any]:
    ob = getattr(c, "actual_observations", None)
    return ob if isinstance(ob, dict) else {}


def _uaf_cap_scope_limit(c: Any) -> Optional[Dict[str, Any]]:
    """RECIPE_FREED_MEMORY_USE that could not run only because the heap was not walked under the baseline cap.

    The use-after-free check reuses the heap-integrity walk; when that walk was skipped for the declared cost
    limit (heap above the baseline cap) the UAF observation is NOT_CHECKED.  That is the same scope limit as the
    integrity check, not missing evidence, so it is reported in ``not_checked`` instead of blocking HEALTHY."""
    obs = _obs(c)
    u = obs.get(OBS_FREED_MEMORY_USE)
    if not isinstance(u, dict) or u.get("status") != "NOT_CHECKED" or u.get("findings"):
        return None
    heap = ((obs.get("memory_integrity") or {}).get("heap") or {})
    # structured reason only (stage 1): the check's own record carries the heap walk's not_checked_reason
    if heap.get("not_checked_reason") != "above_baseline_cap" \
            and u.get("heap_not_checked_reason") != "above_baseline_cap":
        return None
    return {"kind": "uaf_not_checked", "item": "use_after_free",
            "label": ("use-after-free (heap above the baseline walk cap; a memory-corruption symptom runs the full walk)",
                      "해제 후 사용 (힙이 기본 검사 상한보다 큼; 메모리 손상 증상을 주면 전체 순회를 실행함)"),
            "reason": "use-after-free not checked: heap larger than the baseline cap"}


def _double_free_cap_scope_limit(c: Any) -> Optional[Dict[str, Any]]:
    """RECIPE_DOUBLE_FREE that could not run only because the heap was not walked under the baseline cap.

    The double-free check reads the free lists of the heap-integrity walk; when that walk was skipped for the
    declared cost limit, the observation is NOT_CHECKED with ``heap_not_checked_reason == "above_baseline_cap"``:
    the same scope limit as the integrity check, listed in ``not_checked`` instead of blocking HEALTHY."""
    u = _obs(c).get("free_list_repeats")
    if not isinstance(u, dict) or u.get("status") != "NOT_CHECKED" or u.get("findings"):
        return None
    if u.get("heap_not_checked_reason") != "above_baseline_cap":
        return None
    return {"kind": "double_free_not_checked", "item": "double_free",
            "label": ("double free (heap above the baseline walk cap; a memory-corruption symptom runs the full walk)",
                      "이중 해제 (힙이 기본 검사 상한보다 큼; 메모리 손상 증상을 주면 전체 순회를 실행함)"),
            "reason": "double free not checked: heap larger than the baseline cap"}


def _registered_scope_label(recipe_id: str) -> Optional[Tuple[str, str]]:
    """What a plugin baseline recipe clears, from its check-list label (report_registry)."""
    from .report_registry import recipe_label
    lab = recipe_label(recipe_id)
    return (lab[3], lab[4]) if lab else None


def _plain(recipe_id: str) -> str:
    return str(recipe_id).replace("RECIPE_", "").replace("_", " ").lower()


def _plain_ko(recipe_id: str) -> str:
    """The Korean check name used in the check list; the English words when the recipe has no Korean name."""
    from .report_registry import recipe_label
    lab = recipe_label(recipe_id)
    if lab:
        return lab[2]
    from .report_visuals import _RECIPES
    meta = _RECIPES.get(str(recipe_id))
    return meta[2] if meta else _plain(recipe_id)


def _heap_cap_scope_limit(c: Any) -> Optional[Dict[str, Any]]:
    """RECIPE_HEAP_METADATA_CORRUPTION that is INCONCLUSIVE only because of the baseline heap cap -> scope item."""
    mi = _obs(c).get("memory_integrity")
    if not isinstance(mi, dict):
        return None
    heap = mi.get("heap") or {}
    if heap.get("status") != "NOT_CHECKED" or heap.get("not_checked_reason") != "above_baseline_cap":
        return None
    if (mi.get("globals") or {}).get("status") != "COMPLETED" or (mi.get("stacks") or {}).get("status") != "COMPLETED":
        return None
    if heap.get("defects") or (mi.get("globals") or {}).get("candidates") or (mi.get("stacks") or {}).get("warnings"):
        return None
    mb = float(heap.get("estimated_heap_bytes") or 0) / 1048576.0
    cap = float(heap.get("baseline_cap_bytes") or 0) / 1048576.0
    return {"kind": "integrity_not_checked", "item": "heap_integrity",
            "label": (f"heap integrity (heap {mb:.1f} MiB is above the {cap:.1f} MiB baseline walk cap; global "
                      "arrays and stack margins were checked)",
                      f"힙 무결성 (힙 {mb:.1f} MiB가 기본 검사 상한 {cap:.1f} MiB보다 큼; 전역 배열과 스택 여유는 검사함)"),
            "reason": "heap integrity not checked: heap larger than the baseline cap; a memory-corruption symptom "
                      "runs the full walk"}


def long_wait_scope_items(checks: Iterable[Any]) -> List[Dict[str, Any]]:
    """not_covered rows for long waits a PASSed RECIPE_LONG_RUNNING_BLOCKED_THREADS could not judge."""
    out: List[Dict[str, Any]] = []
    seen = set()
    for c in checks:
        if getattr(c, "recipe_id", None) != "RECIPE_LONG_RUNNING_BLOCKED_THREADS" or _st(c) != CheckStatus.PASS:
            continue
        for t in _obs(c).get("long_wait_threads") or []:
            if not isinstance(t, dict) or t.get("tid") in seen:
                continue
            seen.add(t.get("tid"))
            out.append({"kind": "long_wait_not_judged", "item": f"{t.get('name')} (tid {t.get('tid')})",
                        "thread": t.get("name"), "tid": t.get("tid"), "syscall": t.get("syscall"),
                        "reason": f"waited in {t.get('syscall')}"
                                  f"{' (' + str(t.get('wait_kind')) + ')' if t.get('wait_kind') else ''} for the whole "
                                  f"{t.get('waited_at_least_sec')} s window: an idle wait and a stall look the same "
                                  "from outside, so whether this wait is expected was not judged"})
    return out


def _recipe_categories(recipe_id: str) -> List[str]:
    """The problem categories a recipe answers (its own and the ones it is planned for)."""
    from .diagnostic_recipes import DiagnosticRecipeRegistry
    r = DiagnosticRecipeRegistry.get_recipe(str(recipe_id))
    if r is None:
        return []
    return list(dict.fromkeys([r.problem_category] + list(r.applicable_problem_categories or [])))


def symptom_question_gaps(symptom_categories: Iterable[str], checks: List[Any],
                          not_covered: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Rule 5 (verification scope): every problem category the symptom asks about must be answered by a check of
    that category that ran to completion and cleared (PASS).  One blocking row per unanswered category.

    A category no registered recipe looks at is not a question this tool can be asked (skipped).  A category whose
    checks all ended without a result, or could not run in this mode (``unsupported_in_mode``), is unanswered: the
    diagnosis looked at the baseline but not at what the symptom asked, so it is INCONCLUSIVE with that reason."""
    from .diagnostic_recipes import DiagnosticRecipeRegistry
    by_cat: Dict[str, List[Any]] = {}
    for c in checks:
        for cat in _recipe_categories(str(getattr(c, "recipe_id", ""))):
            by_cat.setdefault(cat, []).append(c)
    not_in_mode: Dict[str, List[str]] = {}
    for n in not_covered:
        if n.get("kind") == "unsupported_in_mode":
            for rid in [x for x in str(n.get("item") or "").split(",") if x]:
                for cat in _recipe_categories(rid):
                    not_in_mode.setdefault(cat, []).append(rid)
    out: List[Dict[str, Any]] = []
    for cat in dict.fromkeys(str(x) for x in symptom_categories or [] if x):
        if not DiagnosticRecipeRegistry.get_recipes_for_category(cat):
            continue
        cs = by_cat.get(cat) or []
        if any(_st(c) == CheckStatus.PASS for c in cs):
            continue
        if any(_st(c) == CheckStatus.FAIL for c in cs):
            continue  # a FAIL blocks through rule 2
        parts = [f"{getattr(c, 'recipe_id', '')} {_st(c)}" for c in cs]
        parts += [f"{rid} not supported in this mode" for rid in not_in_mode.get(cat, [])]
        out.append({"kind": "symptom_question_unanswered", "item": cat,
                    "reason": (f"the symptom asks about {cat} and no check of it ran to completion"
                               + (f" ({'; '.join(parts)})" if parts else " (none was executed)"))})
    return out


def evaluate(*, verdict: str, findings: List[Dict[str, Any]], checks: List[Any], not_covered: List[Dict[str, Any]],
             baseline_ids: Iterable[str], recipe_names: Optional[Dict[str, str]] = None,
             symptom_categories: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    """Apply the HEALTHY rule.  ``checks`` are the session's executed DiagnosticCheck objects.
    ``symptom_categories``: the problem categories a specific symptom asks about (rule 5; None or empty for a
    general health check, whose scope is the baseline).

    Returns ``healthy_scope``: {rule, healthy (bool), checked [{recipe_id, what, what_ko, result}],
    not_checked [{kind, item, label, label_ko, reason}], blocking [{kind, item, reason}]}."""
    names = recipe_names or {}
    baseline = list(dict.fromkeys(baseline_ids))
    blocking: List[Dict[str, Any]] = []
    not_checked: List[Dict[str, Any]] = []
    checked: List[Dict[str, Any]] = []

    def block(kind: str, item: str, reason: str) -> None:
        blocking.append({"kind": kind, "item": item, "reason": reason})

    if verdict not in ("INCONCLUSIVE", "HEALTHY"):
        block("verdict", verdict, f"the aggregated verdict is {verdict}")
    if findings:
        block("finding", ",".join(dict.fromkeys(str(f.get("category")) for f in findings)),
              f"{len(findings)} finding(s) were produced")
    for c in checks:
        if _st(c) == CheckStatus.FAIL:
            block("check_fail", str(getattr(c, "recipe_id", "")), "a check found the anomaly it looks for")

    # 3. baseline checks
    by_recipe: Dict[str, List[Any]] = {}
    for c in checks:
        by_recipe.setdefault(str(getattr(c, "recipe_id", "")), []).append(c)
    for rid in baseline:
        cs = by_recipe.get(rid) or []
        if not cs:
            block("baseline_check_missing", rid, "baseline check was not executed")
            continue
        ok = True
        partial: List[str] = []
        for c in cs:
            st = _st(c)
            if st == CheckStatus.PASS:
                continue
            lim = None
            if st == CheckStatus.INCONCLUSIVE:
                if rid == "RECIPE_HEAP_METADATA_CORRUPTION":
                    lim = _heap_cap_scope_limit(c)
                elif rid == "RECIPE_FREED_MEMORY_USE":
                    lim = _uaf_cap_scope_limit(c)
                elif rid == "RECIPE_DOUBLE_FREE":
                    lim = _double_free_cap_scope_limit(c)
            if lim is not None:
                partial.append("global arrays and stack margins checked, heap not walked (above the baseline cap)"
                               if rid == "RECIPE_HEAP_METADATA_CORRUPTION" else "heap not walked (above the baseline cap)")
                not_checked.append({"kind": lim["kind"], "item": lim["item"], "label": lim["label"][0],
                                    "label_ko": lim["label"][1], "reason": lim["reason"]})
                continue
            ok = False
            why = "; ".join(list(getattr(c, "limitations", None) or []) + list(getattr(c, "missing_evidence", None) or [])) \
                or str(getattr(c, "technical_interpretation", "") or "")
            block(f"baseline_check_{st.lower()}", rid, f"baseline check ended {st}" + (f": {why}" if why else ""))
        if ok:
            en, ko = BASELINE_SCOPE_LABELS.get(rid) or _registered_scope_label(rid) or ((names.get(rid) or _plain(rid),) * 2)
            res = "; ".join([str(getattr(c, "technical_interpretation", "") or "") for c in cs
                             if _st(c) == CheckStatus.PASS] + partial)
            checked.append({"recipe_id": rid, "what": en, "what_ko": ko, "result": res})

    # 5. the questions of a specific symptom were answered by a completed check (verification scope)
    for gap in symptom_question_gaps(symptom_categories or [], checks, not_covered):
        block(gap["kind"], gap["item"], gap["reason"])

    # 4. not_covered: blocking kinds vs scope limits
    sym_open: List[str] = []
    long_waits: List[Dict[str, Any]] = []
    for n in not_covered:
        kind = str(n.get("kind") or "")
        item = str(n.get("item") or "")
        if kind.startswith("check_"):
            if item in baseline:
                continue  # decided per check above
            if item not in sym_open:
                sym_open.append(item)
            continue
        if kind == "unsupported_on_target" and item in baseline:
            continue  # the check itself is INCONCLUSIVE and blocks above
        if kind in BLOCKING_KINDS or kind not in SCOPE_KINDS:
            block(kind, item, str(n.get("reason") or kind))
            continue
        if kind == "integrity_not_checked" and any(x["kind"] == "integrity_not_checked" for x in not_checked):
            continue  # already listed from the heap-cap decision
        if kind == "recipes_not_planned":
            continue  # summarised below with the symptom-specific checks
        if kind == "long_wait_not_judged":
            long_waits.append(n)
            continue  # one item for all long waits, below
        if kind == "unsupported_in_mode":
            # Questions whose checks this mode cannot execute (declared capability requirement).  Never a gate:
            # no baseline check owns them; they are listed so a HEALTHY verdict does not read as "examined".
            from .diagnostic_recipes import CAPABILITY_DESCRIPTIONS
            cap_en, cap_ko = CAPABILITY_DESCRIPTIONS.get(str(n.get("capability")), (str(n.get("capability")),) * 2)
            ids = [x for x in item.split(",") if x]
            en_names = ", ".join(_plain(x) for x in ids)
            ko_names = ", ".join(_plain_ko(x) for x in ids)
            not_checked.append({
                "kind": kind, "item": item, "capability": n.get("capability"),
                "label": f"not examined: {en_names} (a zero-stop diagnosis cannot answer these: they need {cap_en})",
                "label_ko": f"점검하지 않음: {ko_names} (무정지 진단으로는 답할 수 없음: {cap_ko} 필요)",
                "reason": str(n.get("reason") or "")})
            continue
        label = {
            "unsupported_on_target": (f"{item} (not supported on this target)", f"{item} (이 대상에서 지원되지 않음)"),
            "leak_owner_limited": ("which variable owns heap memory (leak-owner attribution was limited)",
                                   "힙 메모리를 쥔 변수 추적 (누수 소유자 추적이 제한됨)"),
            "integrity_limited": (f"part of the memory-integrity check ({n.get('reason')})",
                                  f"메모리 무결성 검사의 일부 (엔진 원문: {n.get('reason')})"),
            "integrity_not_checked": (f"part of the memory-integrity check ({n.get('reason')})",
                                      f"메모리 무결성 검사의 일부 (엔진 원문: {n.get('reason')})"),
            "remote_limitation": (f"{item} on the remote target", f"원격 대상의 {item}"),
            "collector_not_deployed": ("native collector (slower shell reads were used)", "네이티브 수집기 (느린 셸 읽기 사용)"),
            "report_not_saved": ("saving the full report", "전체 보고서 저장"),
        }.get(kind, (item, item))
        not_checked.append({"kind": kind, "item": item, "label": label[0], "label_ko": label[1],
                            "reason": str(n.get("reason") or "")})
    if long_waits:
        who = ", ".join(str(n.get("item")) for n in long_waits[:4]) + (
            f" and {len(long_waits) - 4} more" if len(long_waits) > 4 else "")
        who_ko = ", ".join(str(n.get("item")) for n in long_waits[:4]) + (
            f" 외 {len(long_waits) - 4}개" if len(long_waits) > 4 else "")
        not_checked.append({"kind": "long_wait_not_judged", "item": ",".join(str(n.get("item")) for n in long_waits),
                            "label": f"whether the long wait of {who} is expected (an idle wait and a stall look "
                                     "the same from outside)",
                            "label_ko": f"{who_ko}의 긴 대기가 정상인지 (밖에서는 유휴 대기와 멈춤이 같아 보임)",
                            "reason": "; ".join(f"{n.get('item')}: {n.get('reason')}" for n in long_waits)})
    if sym_open:
        plain = ", ".join(_plain(x) for x in sym_open)
        plain_ko = ", ".join(_plain_ko(x) for x in sym_open)
        not_checked.append({"kind": "symptom_checks_without_result", "item": ",".join(sym_open),
                            "label": f"symptom-specific checks that reached no result ({plain})",
                            "label_ko": f"결론을 내지 못한 증상별 추가 검사 ({plain_ko})",
                            "reason": "these checks are not part of the baseline; they ran but could not decide"})
    not_checked.append({"kind": "outside_baseline", "item": "outside_baseline", "label": OUTSIDE_BASELINE[0],
                        "label_ko": OUTSIDE_BASELINE[1], "reason": "not covered by any baseline check"})
    # most consequential first (the summary names the first few)
    not_checked.sort(key=lambda x: _NOT_CHECKED_ORDER.get(x["kind"], len(_NOT_CHECKED_ORDER)))
    return {"rule": HEALTHY_RULE_ID, "healthy": not blocking, "checked": checked, "not_checked": not_checked,
            "blocking": blocking}


def display_label(x: Dict[str, Any], ko: bool) -> str:
    """The text of a ``not_checked`` item of a ``healthy_scope`` for display.  A saved result may carry an English
    check list inside its Korean label (written before the check names were localised), so the Korean label of a
    symptom-check item is rebuilt here from the recipe ids it names."""
    if ko and x.get("kind") == "symptom_checks_without_result" and x.get("item"):
        names = ", ".join(_plain_ko(r) for r in str(x["item"]).split(",") if r)
        return f"결론을 내지 못한 증상별 추가 검사 ({names})"
    return str(x.get("label_ko" if ko else "label") or x.get("item"))


def display_what(x: Dict[str, Any], ko: bool) -> str:
    """What a ``checked`` item of a ``healthy_scope`` cleared; Korean from the check's registered label when there is one."""
    if ko:
        lab = BASELINE_SCOPE_LABELS.get(str(x.get("recipe_id"))) or _registered_scope_label(str(x.get("recipe_id")))
        if lab:
            return lab[1]
    return str(x.get("what_ko" if ko else "what"))


def not_healthy_scope(not_covered: List[Dict[str, Any]], why: str) -> Dict[str, Any]:
    """healthy_scope of a diagnosis that stopped before the checks (pre-flight / stage failure)."""
    blocking = [{"kind": str(n.get("kind")), "item": str(n.get("item")), "reason": str(n.get("reason") or "")}
                for n in not_covered if n.get("kind") not in SCOPE_KINDS] or [{"kind": "not_run", "item": "diagnosis",
                                                                                 "reason": why}]
    return {"rule": HEALTHY_RULE_ID, "healthy": False, "checked": [], "not_checked": [], "blocking": blocking}


def summary_sentence(scope: Dict[str, Any], n_baseline: int, lang: str = "en", max_items: int = 3) -> str:
    """First sentence of a HEALTHY summary: healthy within scope + what was not checked."""
    ko = lang == "ko"
    items = [display_label(x, ko) for x in scope.get("not_checked") or []]
    shown = items[:max_items]
    more = len(items) - len(shown)
    if ko:
        s = (f"점검한 범위 안에서 정상입니다: 기본 검사 {n_baseline}개가 모두 끝까지 실행되었고 아무것도 발견하지 "
             f"못했습니다. 점검하지 못한 것: {'; '.join(shown)}")
        return s + (f" 외 {more}건." if more > 0 else ".")
    s = (f"healthy within the checked scope: all {n_baseline} baseline checks ran to completion and found nothing. "
         f"Not checked: {'; '.join(shown)}")
    return s + (f"; and {more} more." if more > 0 else ".")

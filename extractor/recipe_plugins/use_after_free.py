"""Use-after-free from memory reads alone - registered entirely from this file (see extractor.uaf_detection).

Observation kind ``freed_memory_use``: re-uses the heap walk of the session's integrity check (IMP-009, itself
re-using the IMP-008 leak walk when that ran) and its reverse reference map (or builds a typed-globals-only map),
then re-reads the free chunks a few times over a short window.  Read-only, zero-stop, no ptrace.

Verdict rule
    confirmed: a typed global/static pointer (or a member reached from one) still points into a free chunk AND
               that chunk was written while free (payload change, or stable free-list damage) -> SUPPORTED,
               USE_AFTER_FREE, not capped (confirmed);
    probable:  a free chunk written while free with no typed referrer ("owner unknown: no reference remains")
               -> SUPPORTED, capped at probable;
    candidate: a stable dangling typed pointer, no write observed -> SUPPORTED, capped at probable, WARNING
               severity (a latent bug, not a proven use);
    nothing dangling and no write in the walked heap -> CONTRADICTED; heap not walked -> INSUFFICIENT_EVIDENCE.

The legacy ``RECIPE_USE_AFTER_FREE`` (allocator lifetime events / poison bytes at one probed pointer) is kept as
it was: without an allocation tracer it is INSUFFICIENT_EVIDENCE on every live target.
"""

from __future__ import annotations

import uuid
from typing import Any, Dict, List, Optional

from ..diagnostic_recipes import (
    CATEGORY_USE_AFTER_FREE,
    DOMAIN_MEMORY_INTEGRITY,
    RECIPE_STATUS_CONTRADICTED,
    RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
    RECIPE_STATUS_SUPPORTED,
    DiagnosticRecipe,
    RecipeEvaluationResult,
    register_recipe,
)
from ..runtime_evidence_provider import register_observation_collector

RECIPE_FREED_MEMORY_USE = "RECIPE_FREED_MEMORY_USE"
OBS_FREED_MEMORY_USE = "freed_memory_use"


def _state(provider: Any) -> Dict[Any, Any]:
    st = getattr(provider, "_uaf_state", None)
    if st is None:
        st = {}
        provider._uaf_state = st
    return st


def collect_freed_memory_use(provider: Any, ctx: Dict[str, Any]) -> None:
    from ..memory_integrity import _remaining, ensure_integrity
    from ..runtime_evidence_provider import (COLLECTION_STATUS_PARTIAL, COLLECTION_STATUS_SUCCESS,
                                             PROVENANCE_LIVE_RUNTIME_CAPTURE, RuntimeEvidenceRecord)
    from ..uaf_detection import run_uaf
    pid = ctx["pid"]
    od = ctx["observation_data"]
    if getattr(provider, "memory_observation", None) is None:
        # same gate as the integrity walk: only a diagnose session (multi-observation memory config) walks the heap
        od[OBS_FREED_MEMORY_USE] = {"status": "NOT_CHECKED", "findings": [], "not_evidence": [],
                                    "limitations": ["use-after-free not checked: no heap-walk session"]}
        return None
    key = (ctx.get("session_id") or "default", int(pid))
    st = _state(provider)
    rec = st.get(key)
    fresh = rec is None
    if fresh:
        mi, objs, _ = ensure_integrity(provider, pid, ctx.get("companion_elf"), ctx.get("classification"),
                                       ctx.get("session_id"))
        wall, _b = _remaining(getattr(provider, "budget_tracker", None))
        try:
            rec = run_uaf(provider.adapter, pid, ctx.get("companion_elf"), objs, mi, remaining_wall_s=wall)
        except Exception as exc:  # noqa: BLE001 - a detection failure is a limitation, never a crash
            rec = {"status": "FAILED", "findings": [], "not_evidence": [],
                   "limitations": ["use-after-free check failed: %s: %s" % (type(exc).__name__, exc)],
                   "cost": {"bytes_read": 0}}
        st[key] = rec
    od[OBS_FREED_MEMORY_USE] = rec
    if fresh:
        nbytes = int((rec.get("cost") or {}).get("bytes_read") or 0)
        if nbytes:
            od["bytes_read"] = int(od.get("bytes_read") or 0) + nbytes
        ctx["all_records"].append(RuntimeEvidenceRecord(
            evidence_id=f"ev_{uuid.uuid4().hex[:12]}",
            collection_method="freed_chunk_rereads",
            target_pid=pid,
            observed_value={"status": rec.get("status"), "findings": len(rec.get("findings") or []),
                            "checked": rec.get("checked")},
            collection_scope="MEMORY_INTEGRITY",
            collection_status=COLLECTION_STATUS_SUCCESS if rec.get("status") == "COMPLETED" else COLLECTION_STATUS_PARTIAL,
            limitations=list(rec.get("limitations") or []),
            provenance_class=PROVENANCE_LIVE_RUNTIME_CAPTURE,
            raw_details={"cost": rec.get("cost")},
        ))
    return None


def freed_memory_use_rule(recipe: DiagnosticRecipe, data: Dict[str, Any]) -> Optional[RecipeEvaluationResult]:
    rid = recipe.recipe_id
    rec = data.get(OBS_FREED_MEMORY_USE) or {}
    lims = list(rec.get("limitations") or [])
    fs = list(rec.get("findings") or [])
    if fs:
        levels = {f["level"] for f in fs}
        confirmed = "confirmed" in levels
        facts = [f["description"] for f in fs]
        d: Dict[str, Any] = {"finding_category": CATEGORY_USE_AFTER_FREE, "uaf_findings": fs,
                             "finding_summary": "; ".join(facts[:3]), "limitations": lims,
                             "corruption_confirmed": confirmed}
        if not confirmed:
            d["certainty_cap"] = "PROBABLE"
            d["certainty_cap_reason"] = (
                "freed memory written with no typed pointer left to it (owner unknown)" if "probable" in levels else
                "a dangling pointer to a free chunk with no write observed: a candidate, a use is not proven")
        if levels == {"candidate"}:
            d["finding_severity"] = "WARNING"
        return RecipeEvaluationResult(
            recipe_id=rid, status=RECIPE_STATUS_SUPPORTED,
            confidence=0.95 if confirmed else (0.75 if "probable" in levels else 0.5),
            confidence_basis=facts[0], supporting_facts=facts, limitations=lims,
            recommended_action="Clear (or stop using) the named pointer when its block is freed; rebuild with "
                               "AddressSanitizer to find the access site.",
            details=d)
    if rec.get("status") == "COMPLETED":
        chk = rec.get("checked") or {}
        txt = ("no typed pointer refers to a free chunk and no free chunk was written: %d free chunks tracked, %d "
               "payloads hashed over %.2f s (%d re-reads)" % (int(chk.get("tracked_chunks") or 0),
                                                                int(chk.get("hashed_chunks") or 0),
                                                                float(chk.get("window_s") or 0.0),
                                                                int(chk.get("reads") or 0)))
        return RecipeEvaluationResult(
            recipe_id=rid, status=RECIPE_STATUS_CONTRADICTED, confidence=0.8, confidence_basis=txt,
            contradicting_facts=[txt], limitations=lims,
            recommended_action="No use after free visible in the walked heap during the window.",
            details={"freed_memory_checked": True, "limitations": lims})
    return RecipeEvaluationResult(
        recipe_id=rid, status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE, confidence=0.1,
        confidence_basis="; ".join(lims) or "use-after-free not checked",
        missing_evidence=["heap_walk_with_free_chunk_rereads"], limitations=lims,
        details={"freed_memory_checked": False, "limitations": lims})


register_observation_collector(OBS_FREED_MEMORY_USE, collect_freed_memory_use)
register_recipe(DiagnosticRecipe(
    recipe_id=RECIPE_FREED_MEMORY_USE,
    version="1.0.0",
    name="Use After Free: Dangling Pointers and Writes into Freed Memory",
    domain=DOMAIN_MEMORY_INTEGRITY,
    applicable_problem_categories=[CATEGORY_USE_AFTER_FREE],
    required_prerequisites=["memory_read_available", "heap_inspection_available"],
    evidence_sources=["heap_walk", "free_lists", "typed_reference_map", "free_chunk_rereads"],
    collection_steps=[
        {"step": 1, "action": "reuse_integrity_walk", "purpose": "free chunks and the list holding each"},
        {"step": 2, "action": "typed_reference_map", "purpose": "typed pointers whose value is inside a free chunk"},
        {"step": 3, "action": "reread_free_chunks", "purpose": "payload hashes + list identity over a short window"},
        {"step": 4, "action": "reallocation_probe", "purpose": "quick re-reads exclude an allocate-write-free cycle"},
    ],
    analysis_rules=[
        "a stable typed pointer into a free chunk is a dangling reference (candidate, warning)",
        "a free chunk's payload changing while it stays on the same free list was written by the program",
        "both together confirm a use after free naming the pointer",
    ],
    thresholds_and_conditions={"observations": 3, "window_s": 0.4, "reuse_probe_reads": 5,
                               "max_tracked_chunks": 4096, "max_hashed_chunks": 1024, "max_hashed_bytes": 524288},
    supporting_evidence_criteria=["dangling typed pointer", "payload written while free", "free-list damage in a "
                                  "free chunk a typed pointer refers to"],
    contradicting_evidence_criteria=["no typed pointer into a free chunk and no free payload change"],
    verification_procedure="Diagnose again: a dangling pointer stays; rebuild with AddressSanitizer for the site.",
    stop_conditions=["heap not walkable / above the baseline cap"],
    limitations=["a write made before the first read with no pointer left is not distinguishable from the freed "
                 "object's last contents",
                 "a dangling pointer to a chunk that was re-allocated since is invisible (the chunk is in use)",
                 "read-only uses of freed memory, pointers held only in registers or untyped words, and munmapped "
                 "blocks are not seen"],
    output_structure={"findings": "list[{level, variable, variable_path, freed_chunk, free_list, "
                                  "written_while_free}]"},
    observations=(OBS_FREED_MEMORY_USE,),
    rule=freed_memory_use_rule,
), baseline=True, category=CATEGORY_USE_AFTER_FREE)


# ---------------------------------------------------------------------------------------------- presentation
# Plain-language summary of a use-after-free finding (presentation only).  Every value comes from the finding's
# ``freed_memory_use`` record; a value that is absent is left out of its sentence, and what was seen is kept apart
# from what is inferred.  key -> (English, Korean)
_UAF_TXT: Dict[str, Any] = {
    "ptr": ("The pointer {v} still holds the address of a heap block{size} that has already been freed: "
            "the allocator lists that block as free{lst}.",
            "포인터 {v}이(가) 이미 해제된 힙 블록{size}의 주소를 아직 들고 있습니다. "
            "할당자는 이 블록을 해제된 블록으로 기록하고 있습니다{lst}."),
    "ptrs": ("The pointers {v} still hold the address of a heap block{size} that has already been freed: "
             "the allocator lists that block as free{lst}.",
             "포인터 {v}이(가) 이미 해제된 힙 블록{size}의 주소를 아직 들고 있습니다. "
             "할당자는 이 블록을 해제된 블록으로 기록하고 있습니다{lst}."),
    "noptr": ("The heap block{size} is on the allocator's free list, but its contents changed while it was "
              "free{lst}. No variable the tool can identify still points to it, so the owner is unknown.",
              "힙 블록{size}은 할당자의 해제 목록에 있는데, 해제된 상태에서 내용이 바뀌었습니다{lst}. "
              "이 블록을 가리키는 변수는 확인되지 않아 소유자는 알 수 없습니다."),
    "size": (" ({n} bytes, at {addr})", "(크기 {n}바이트, 주소 {addr})"),
    "size_n": (" ({n} bytes)", "(크기 {n}바이트)"),
    "size_a": (" (at {addr})", "(주소 {addr})"),
    "lst": (" (on {name})", " ({name}에 있음)"),
    "seen": ("It was seen free in {n} reads over {win} s, and the pointer kept its value.",
             "{win}초 동안 {n}번 읽는 내내 이 블록은 해제된 상태였고 포인터 값도 그대로였습니다."),
    "seen_noptr": ("It was seen free in {n} reads over {win} s.", "{win}초 동안 {n}번 읽는 내내 이 블록은 해제된 상태였습니다."),
    "written_ptr": ("Seen: the block's contents changed while it was free, so something wrote into freed memory. "
                    "Inferred: because {v} still points into the block, the write most likely went through that "
                    "pointer.",
                    "관측: 블록이 해제된 동안 내용이 바뀌었으므로, 누군가 해제된 메모리에 썼습니다. "
                    "추정: {v}이(가) 아직 이 블록을 가리키고 있으므로 그 포인터를 통해 쓰였을 가능성이 높습니다."),
    "written_meta": ("Seen: the allocator's own bookkeeping inside the freed block was overwritten, so something "
                     "wrote into freed memory. Inferred: because {v} still points into the block, the write most "
                     "likely went through that pointer.",
                     "관측: 해제된 블록 안의 할당자 관리 정보가 덮어쓰였으므로, 누군가 해제된 메모리에 썼습니다. "
                     "추정: {v}이(가) 아직 이 블록을 가리키고 있으므로 그 포인터를 통해 쓰였을 가능성이 높습니다."),
    "written_noptr": ("Seen: the block's contents changed while it was free, so something wrote into freed memory.",
                      "관측: 블록이 해제된 동안 내용이 바뀌었으므로, 누군가 해제된 메모리에 썼습니다."),
    "not_written": ("No write into the freed block was observed, so an actual use of freed memory is not proven. "
                    "The risk, inferred rather than seen, is the next read or write through the pointer, or the "
                    "allocator handing the same block to a new owner.",
                    "해제된 블록에 대한 쓰기는 관측되지 않아, 해제된 메모리를 실제로 사용했다는 것은 입증되지 않았습니다. "
                    "위험은(관측이 아닌 추정) 이 포인터를 통한 다음 읽기·쓰기, 또는 할당자가 같은 블록을 새 소유자에게 "
                    "다시 내주는 경우입니다."),
    "who": ("Which code freed the block, and which code uses it afterwards, was not observed (allocator calls are "
            "not traced). Look for the paths that free what {v} points to, and for later uses of {v}.",
            "어느 코드가 블록을 해제했고 그 뒤 어느 코드가 사용하는지는 관측되지 않았습니다(할당자 호출은 추적하지 않음). "
            "{v}이(가) 가리키는 대상을 해제하는 경로와, 그 뒤 {v}을(를) 사용하는 곳을 찾으세요."),
    "who_noptr": ("Which code freed the block, and which code wrote into it, was not observed (allocator calls are "
                  "not traced).",
                  "어느 코드가 블록을 해제했고 어느 코드가 그 안에 썼는지는 관측되지 않았습니다(할당자 호출은 추적하지 않음)."),
}


def _uaf_list_name(name: Any, i: int) -> str:
    """The free list as named by the heap walker, without the position suffix; Korean for the known shapes."""
    import re
    from .double_free import _list_name
    base = re.sub(r", entry \d+ of \d+$", "", str(name or ""))
    return _list_name(base, i) if base else ""


def uaf_sentences(i: int, x: Dict[str, Any]) -> List[str]:
    """The sentences for one ``freed_memory_use`` finding in language ``i`` (0 en, 1 ko)."""
    code = lambda v: "`" + str(v).replace("`", "'") + "`"  # noqa: E731
    ptrs: List[str] = []
    for p in x.get("dangling_pointers") or []:
        if isinstance(p, dict) and (p.get("variable_path") or p.get("variable")):
            n = str(p.get("variable_path") or p.get("variable"))
            if n not in ptrs:
                ptrs.append(n)
    if not ptrs and (x.get("variable_path") or x.get("variable")):
        ptrs = [str(x.get("variable_path") or x.get("variable"))]
    v = ", ".join(code(p) for p in ptrs[:3])
    addr, n = x.get("user_address") or x.get("freed_chunk"), x.get("chunk_size")
    has_n = isinstance(n, int) and not isinstance(n, bool)
    if has_n and addr:
        size = _UAF_TXT["size"][i].format(n=n, addr=code(addr))
    elif has_n:
        size = _UAF_TXT["size_n"][i].format(n=n)
    elif addr:
        size = _UAF_TXT["size_a"][i].format(addr=code(addr))
    else:
        size = ""
    ln = _uaf_list_name(x.get("free_list"), i)
    lst = _UAF_TXT["lst"][i].format(name=code(ln)) if ln else ""
    written = bool(x.get("written_while_free"))
    out: List[str] = []
    if ptrs:
        out.append(_UAF_TXT["ptr" if len(ptrs) == 1 else "ptrs"][i].format(v=v, size=size, lst=lst))
    else:
        out.append(_UAF_TXT["noptr"][i].format(size=size, lst=lst))
    reads, win = x.get("observed_free_in_reads"), x.get("window_s")
    if reads and isinstance(win, (int, float)) and not isinstance(win, bool):
        out.append(_UAF_TXT["seen" if ptrs else "seen_noptr"][i].format(n=reads, win="%g" % round(float(win), 2)))
    if written and ptrs:
        meta = "allocator metadata" in str(x.get("write_evidence") or "")
        out.append(_UAF_TXT["written_meta" if meta else "written_ptr"][i].format(v=v))
    elif written:
        out.append(_UAF_TXT["written_noptr"][i])
    else:
        out.append(_UAF_TXT["not_written"][i])
    out.append(_UAF_TXT["who"][i].format(v=code(ptrs[0])) if ptrs else _UAF_TXT["who_noptr"][i])
    return out


def uaf_finding_text(ctx: Any, finding: Dict[str, Any], report: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    from ..report_visuals import _observations
    items: List[Dict[str, Any]] = []
    for o in _observations(report, finding.get("recipe_ids")):
        fm = o.get("freed_memory_use")
        for x in ((fm or {}).get("findings") or []) if isinstance(fm, dict) else []:
            if isinstance(x, dict) and x.get("freed_chunk"):
                items.append(x)
    lines: List[str] = []
    for x in items[:2]:
        lines += uaf_sentences(ctx.i, x)
    return {"lines": lines}


def _register_presentation() -> None:
    from ..report_registry import register_finding_text, register_recipe_label
    register_recipe_label(RECIPE_FREED_MEMORY_USE, "MEMORY_INTEGRITY", "Use of freed memory", "해제된 메모리 사용",
                          "pointers that still refer to freed blocks, and writes into freed blocks",
                          "해제된 블록을 여전히 가리키는 포인터, 해제된 블록에 대한 쓰기")
    register_finding_text(CATEGORY_USE_AFTER_FREE, uaf_finding_text)


_register_presentation()

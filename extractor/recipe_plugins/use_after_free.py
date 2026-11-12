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
from typing import Any, Dict, Optional

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

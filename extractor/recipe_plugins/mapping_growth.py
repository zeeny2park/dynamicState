"""Memory growth outside malloc - registered entirely from this file (IMP-018 recipe definition file).

The leak recipes (RECIPE_PROCESS_MEMORY_GROWTH / RECIPE_HEAP_GROWTH) reach a verdict only when the glibc heap's
in-use blocks grow.  A process can also grow through memory malloc never sees: mmap() without munmap(), a custom
allocator carving its own mappings, thread stacks.  This check measures that part directly.

Observation kind ``mapping_growth`` (read-only, zero-stop, no ptrace): ``SAMPLES`` reads of /proc/PID/maps and
/proc/PID/status, ``INTERVAL_S`` apart.  Between consecutive samples the anonymous writable address ranges that
appeared are classified by owner:

* malloc: the brk ``[heap]``, a thread-arena heap (anonymous mapping starting on a ``HEAP_MAX_SIZE`` boundary,
  where glibc puts ``heap_info``), or a range that is a chain of glibc mmapped chunks (a chunk header with
  IS_MMAPPED whose size fills the range exactly; 16 bytes read per chunk, at most ``MAX_HEADER_READS``);
* thread-stack-like: a mapping directly above a ``---p`` guard mapping (the layout pthread gives a stack);
* outside malloc: every other anonymous writable range (``[stack]`` growth included).

Removed ranges are subtracted (a removal that cannot be attributed to malloc is subtracted from the outside total,
so churn never adds up to growth).  When outside-malloc growth was seen, the typed globals/statics of the
executable (DWARF; pointers, arrays and structs, not followed into the heap) are read once and every pointer whose
value lies in a newly appeared outside range is reported with its variable path.  The heap in-use series of the
leak investigation is attached when that investigation already walked the heap in this session (never started
from here).

Verdict rule (thresholds in ``thresholds_and_conditions``)
    SUPPORTED     outside-malloc anonymous memory grew at EVERY step, by >= MIN_GROWTH_KB in total, and RSS grew
                  by >= MIN_RSS_GROWTH_KB over the window.  Category MAPPING_GROWTH, capped at probable: the growth
                  is measured, but whether it is a leak or intended use cannot be decided from memory.
    CONTRADICTED  outside-malloc growth over the window <= NO_GROWTH_KB (nothing grows outside malloc).
    INSUFFICIENT  fewer than 2 samples, or growth that is not sustained / not resident (churn, reservations).
"""

from __future__ import annotations

import bisect
import struct
import time
import uuid
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..diagnostic_recipes import (
    DOMAIN_MEMORY_GROWTH,
    RECIPE_STATUS_CONTRADICTED,
    RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
    RECIPE_STATUS_SUPPORTED,
    DiagnosticRecipe,
    RecipeEvaluationResult,
    register_recipe,
)
from ..runtime_evidence_provider import register_observation_collector

RECIPE_MAPPING_GROWTH = "RECIPE_MAPPING_GROWTH"
CATEGORY_MAPPING_GROWTH = "MAPPING_GROWTH"
OBS_MAPPING_GROWTH = "mapping_growth"

SAMPLES = 4
INTERVAL_S = 0.3
MIN_GROWTH_KB = 512          # outside-malloc growth over the window for a finding
MIN_RSS_GROWTH_KB = 256      # ... and resident memory must grow too (a reservation that is never touched is not)
NO_GROWTH_KB = 64            # at most this much outside-malloc growth = nothing grows outside malloc
HEAP_MAX_SIZE = 64 << 20     # glibc HEAP_MAX_SIZE on 64-bit: thread-arena heaps start on this boundary
MAX_HEADER_READS = 512       # mmapped-chunk headers read per diagnosis
MAX_GLOBAL_BYTES = 4 << 20   # typed globals read for the owner search
MAX_OWNERS = 8

KIND_OUTSIDE = "anonymous"
KIND_STACK = "thread_stack_like"
KIND_MALLOC_MMAP = "malloc_mmapped"
KIND_HEAP = "malloc_heap"


# ------------------------------------------------------------------------------------------------ collection
def _kb(v: Any) -> Optional[int]:
    try:
        return int(str(v).split()[0])
    except (TypeError, ValueError, IndexError):
        return None


def _anon_rw(maps: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Anonymous writable mappings, sorted, each with its owner class and whether a guard mapping sits below."""
    ms = sorted((m for m in maps if m.get("start_int") is not None), key=lambda m: int(m["start_int"]))
    out: List[Dict[str, Any]] = []
    prev: Optional[Dict[str, Any]] = None
    for m in ms:
        s, e = int(m["start_int"]), int(m["end_int"])
        p = str(m.get("pathname") or "")
        perms = str(m.get("permissions") or "")
        if "w" in perms and (not p or p in ("[heap]", "[stack]") or p.startswith("[anon")):
            if p == "[heap]" or (not p and s % HEAP_MAX_SIZE == 0):
                kind = KIND_HEAP
            elif (prev is not None and int(prev["end_int"]) == s and str(prev.get("permissions") or "").startswith("---")
                  and not prev.get("pathname")):
                kind = KIND_STACK
            else:
                kind = KIND_OUTSIDE
            out.append({"start": s, "end": e, "kind": kind, "name": p})
        prev = m
    return out


def _subtract(a: List[Tuple[int, int]], b: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
    """Ranges of ``a`` not covered by ``b`` (both sorted, non-overlapping)."""
    out: List[Tuple[int, int]] = []
    j = 0
    for s, e in a:
        cur = s
        while j < len(b) and b[j][1] <= cur:
            j += 1
        k = j
        while k < len(b) and b[k][0] < e:
            if b[k][0] > cur:
                out.append((cur, b[k][0]))
            cur = max(cur, b[k][1])
            k += 1
        if cur < e:
            out.append((cur, e))
    return out


class _Reader:
    """16-byte header reads and the typed-global reads, through the zero-stop batch path, counted."""

    def __init__(self, adapter: Any, pid: int):
        self.adapter, self.pid = adapter, int(pid)
        self.bytes_read = 0
        self.header_reads = 0

    def read_many(self, ranges: List[Tuple[int, int]]) -> List[Optional[bytes]]:
        if not ranges:
            return []
        try:
            res = self.adapter.read_memory_batch(self.pid, ranges)
        except Exception:  # noqa: BLE001 - an unreadable range is "not classified", never a crash
            return [None] * len(ranges)
        out = []
        for r in res:
            d = r[0] if r else None
            if d:
                self.bytes_read += len(d)
            out.append(bytes(d) if d else None)
        return out


def _malloc_chain(rd: _Reader, s: int, e: int, page: int = 4096) -> int:
    """Bytes at the start of [s, e) that form a chain of glibc mmapped chunks (header: prev_size, size|IS_MMAPPED;
    a chunk occupies prev_size + size bytes, page aligned)."""
    pos = s
    while pos < e and rd.header_reads < MAX_HEADER_READS:
        rd.header_reads += 1
        b = rd.read_many([(pos, 16)])[0]
        if not b or len(b) < 16:
            break
        prev_size, size = struct.unpack_from("<QQ", b, 0)
        span = prev_size + (size & ~0x7)
        if not (size & 0x2) or (size & 0x4) or prev_size >= page or (size & ~0x7) < 32 or span % page \
                or pos + span > e:
            break
        pos += span
    return pos - s


def _classify_added(rd: _Reader, added: List[Tuple[int, int]], cur: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Each added range with its owner class (malloc chain split off the anonymous kind)."""
    starts = [m["start"] for m in cur]
    out: List[Dict[str, Any]] = []
    for s, e in added:
        i = bisect.bisect_right(starts, s) - 1
        m = cur[i] if i >= 0 and cur[i]["start"] <= s < cur[i]["end"] else None
        kind = m["kind"] if m else KIND_OUTSIDE
        vma = (m["start"], m["end"]) if m else (s, e)
        if kind == KIND_OUTSIDE:
            n = _malloc_chain(rd, s, e)
            if n == 0 and rd.header_reads < MAX_HEADER_READS:
                time.sleep(0.005)               # the allocator may not have written the header yet
                n = _malloc_chain(rd, s, e)
            if n:
                out.append({"start": s, "end": s + n, "kind": KIND_MALLOC_MMAP, "vma": vma})
            if s + n < e:
                out.append({"start": s + n, "end": e, "kind": KIND_OUTSIDE, "vma": vma})
        else:
            out.append({"start": s, "end": e, "kind": kind, "vma": vma})
    return out


def _proc_sample(adapter: Any, pid: int) -> Optional[Dict[str, Any]]:
    try:
        st = adapter.get_process_status(pid) or {}
        maps = adapter.get_proc_maps(pid) or []
    except Exception:  # noqa: BLE001
        return None
    rss = _kb(st.get("VmRSS"))
    if rss is None or not maps:
        return None
    return {"t": time.monotonic(), "rss_kb": rss, "threads": _kb(st.get("Threads")), "anon": _anon_rw(maps)}


def _typed_owners(provider: Any, ctx: Dict[str, Any], rd: _Reader, ranges: List[Tuple[int, int]]) -> Dict[str, Any]:
    """Typed globals/statics of the executable whose pointer value lies in one of ``ranges`` (sorted)."""
    from ..reachability import _module_contexts
    elf = ctx.get("companion_elf")
    if not elf or not ranges:
        return {"status": "NOT_RUN", "reason": "no executable with DWARF" if not elf else "no new range", "owners": []}
    try:
        maps = provider.adapter.get_proc_maps(ctx["pid"]) or []
        mods = _module_contexts(provider.adapter, ctx["pid"], elf, None, maps)[:1]
    except Exception as exc:  # noqa: BLE001
        return {"status": "FAILED", "reason": "%s: %s" % (type(exc).__name__, exc), "owners": []}
    if not mods:
        return {"status": "NOT_RUN", "reason": "the executable has no DWARF debug information", "owners": []}
    mname, idx, bias, is_dyn = mods[0]
    starts = [s for s, _ in ranges]

    def inside(v: int) -> bool:
        i = bisect.bisect_right(starts, v) - 1
        return i >= 0 and ranges[i][0] <= v < ranges[i][1]

    canon: Dict[int, Any] = {}

    def T(off: Optional[int]) -> Any:
        if off is None:
            return None
        if off not in canon:
            canon[off] = idx.resolve_canonical_type(off)
        return canon[off]

    def size_of(t: Any) -> int:
        if t is None:
            return 0
        if t.tag in ("DW_TAG_pointer_type", "DW_TAG_reference_type"):
            return 8
        if t.tag == "DW_TAG_array_type" and not t.byte_size and t.array_count:
            return int(t.array_count) * size_of(T(t.target_type_offset))
        return int(t.byte_size or 0)

    hits: Dict[str, int] = {}

    def scan(buf: bytes, off: int, t: Any, path: str, depth: int) -> None:
        if t is None or depth > 6 or off >= len(buf):
            return
        if t.tag in ("DW_TAG_pointer_type", "DW_TAG_reference_type"):
            if off + 8 <= len(buf) and inside(struct.unpack_from("<Q", buf, off)[0]):
                hits[path] = hits.get(path, 0) + 1
        elif t.tag in ("DW_TAG_structure_type", "DW_TAG_class_type", "DW_TAG_union_type"):
            for m in t.members or []:
                if m.type_offset is not None:
                    scan(buf, off + int(m.offset or 0), T(m.type_offset), "%s.%s" % (path, m.name or "<anon>"), depth + 1)
        elif t.tag == "DW_TAG_array_type":
            et = T(t.target_type_offset)
            esz = size_of(et)
            if esz <= 0 or et is None:
                return
            n = min(int(t.array_count or (int(t.byte_size or 0) // esz)), (len(buf) - off) // esz, 1 << 20)
            if et.tag in ("DW_TAG_pointer_type", "DW_TAG_reference_type") and esz == 8:
                for k in range(n):
                    if inside(struct.unpack_from("<Q", buf, off + 8 * k)[0]):
                        hits[path + "[*]"] = hits.get(path + "[*]", 0) + 1
            elif et.tag in ("DW_TAG_structure_type", "DW_TAG_class_type", "DW_TAG_array_type"):
                for k in range(min(n, 65536)):
                    scan(buf, off + k * esz, et, path + "[*]", depth + 1)

    wanted = []
    total = 0
    for var, kind in [(v, "global") for v in idx.global_variables] + [(v, "static") for v in idx.static_variables]:
        if var.link_time_address is None or var.is_declaration or not var.name:
            continue
        t = T(var.type_offset)
        if t is None or t.tag in ("DW_TAG_base_type", "DW_TAG_enumeration_type"):
            continue
        sz = size_of(t)
        if sz <= 0 or total + sz > MAX_GLOBAL_BYTES:
            continue
        total += sz
        wanted.append((var, kind, t, (bias + var.link_time_address) if is_dyn else var.link_time_address, sz))
    datas = rd.read_many([(a, sz) for _, _, _, a, sz in wanted])
    owners = []
    for (var, kind, t, a, sz), buf in zip(wanted, datas):
        if not buf:
            continue
        hits.clear()
        scan(buf, 0, t, var.name, 0)
        for path, n in hits.items():
            owners.append({"variable": var.name, "variable_path": path, "root_kind": kind, "module": mname,
                           "pointers_into_new_ranges": n})
    owners.sort(key=lambda o: -o["pointers_into_new_ranges"])
    return {"status": "COMPLETED", "globals_read": len(wanted), "owners": owners[:MAX_OWNERS]}


def _leak_walks(provider: Any, ctx: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Heap in-use series of the leak investigation, when it already walked the heap in this session."""
    st = getattr(provider, "_imp008_state", None) or {}
    inv = (st.get("investigations") or {}).get((ctx.get("session_id") or "default", int(ctx["pid"]))) or {}
    return [{"t": w.get("t"), "in_use_bytes": w.get("in_use_bytes"), "rss_kb": w.get("rss_kb")}
            for w in inv.get("heap_walks") or []
            if isinstance(w, dict) and w.get("status") == "OK" and isinstance(w.get("in_use_bytes"), int)]


def collect_mapping_growth(provider: Any, ctx: Dict[str, Any]) -> None:
    from ..runtime_evidence_provider import (COLLECTION_STATUS_PARTIAL, COLLECTION_STATUS_SUCCESS,
                                             PROVENANCE_LIVE_RUNTIME_CAPTURE, RuntimeEvidenceRecord)
    pid = ctx["pid"]
    adapter = provider.adapter
    rd = _Reader(adapter, pid)
    snaps: List[Dict[str, Any]] = []
    steps: List[Dict[str, Any]] = []
    known_malloc: List[Tuple[int, int]] = []         # ranges classified as malloc in this window
    added_outside: List[Dict[str, Any]] = []
    for i in range(SAMPLES):
        s = _proc_sample(adapter, pid)
        if s is None:
            break
        if snaps:
            prev = snaps[-1]
            pr = [(m["start"], m["end"]) for m in prev["anon"]]
            cr = [(m["start"], m["end"]) for m in s["anon"]]
            added = _classify_added(rd, _subtract(cr, pr), s["anon"])
            removed = _subtract(pr, cr)
            rem_outside = 0
            rem_malloc = 0
            for a, b in removed:
                owner = next((m["kind"] for m in prev["anon"] if m["start"] <= a < m["end"]), KIND_OUTSIDE)
                if owner == KIND_HEAP or any(x <= a and b <= y for x, y in known_malloc):
                    rem_malloc += b - a
                else:
                    rem_outside += b - a
            for r in added:
                if r["kind"] in (KIND_HEAP, KIND_MALLOC_MMAP):
                    known_malloc.append((r["start"], r["end"]))
                else:
                    added_outside.append(r)
            sz = lambda k: sum(r["end"] - r["start"] for r in added if r["kind"] == k)  # noqa: E731
            steps.append({"added_outside_kb": (sz(KIND_OUTSIDE) + sz(KIND_STACK)) // 1024,
                          "added_stack_like_kb": sz(KIND_STACK) // 1024,
                          "added_malloc_kb": (sz(KIND_HEAP) + sz(KIND_MALLOC_MMAP)) // 1024,
                          "removed_outside_kb": rem_outside // 1024, "removed_malloc_kb": rem_malloc // 1024,
                          "net_outside_kb": (sz(KIND_OUTSIDE) + sz(KIND_STACK) - rem_outside) // 1024})
        snaps.append(s)
        if i + 1 < SAMPLES:
            time.sleep(INTERVAL_S)
    obs: Dict[str, Any] = {"samples": [], "steps": steps}
    if not snaps:
        obs["unavailable"] = "/proc/<pid>/maps or status could not be read"
    t0 = snaps[0]["t"] if snaps else 0.0
    cum = 0
    for k, s in enumerate(snaps):
        if k:
            cum += steps[k - 1]["net_outside_kb"]
        malloc_kb = sum(m["end"] - m["start"] for m in s["anon"] if m["kind"] == KIND_HEAP) // 1024
        obs["samples"].append({"t_s": round(s["t"] - t0, 3), "rss_kb": s["rss_kb"], "threads": s["threads"],
                               "anon_rw_kb": sum(m["end"] - m["start"] for m in s["anon"]) // 1024,
                               "malloc_heap_kb": malloc_kb, "outside_growth_kb": cum})
    if len(snaps) >= 2:
        obs["outside_growth_kb"] = cum
        obs["rss_growth_kb"] = snaps[-1]["rss_kb"] - snaps[0]["rss_kb"]
        obs["malloc_growth_kb"] = sum(x["added_malloc_kb"] - x["removed_malloc_kb"] for x in steps)
        # what grew, per mapping of the last sample (address range, size, how much of it is new)
        last = snaps[-1]["anon"]
        first = [(m["start"], m["end"]) for m in snaps[0]["anon"]]
        live = [r for r in added_outside if any(m["start"] <= r["start"] < m["end"] for m in last)]
        grown: Dict[Tuple[int, int], Dict[str, Any]] = {}
        for r in live:
            vm = next(((m["start"], m["end"]) for m in last if m["start"] <= r["start"] < m["end"]), r["vma"])
            g = grown.setdefault(vm, {"start": "0x%x" % vm[0], "end": "0x%x" % vm[1], "size_kb": (vm[1] - vm[0]) // 1024,
                                      "added_kb": 0, "kind": r["kind"],
                                      "appeared": _subtract([vm], first) == [vm]})  # no overlap with the first sample
            g["added_kb"] += (r["end"] - r["start"]) // 1024
        rows = sorted(grown.values(), key=lambda g: -g["added_kb"])
        obs["grown_mappings"] = rows[:12]
        obs["grown_mapping_count"] = len(rows)
        obs["new_anonymous_mappings"] = sum(1 for g in rows if g["appeared"] and g["kind"] == KIND_OUTSIDE)
        obs["thread_stack_like_kb"] = sum(x["added_stack_like_kb"] for x in steps)
        if cum > 0 and live:
            rngs = sorted((r["start"], r["end"]) for r in live)
            obs["owner_search"] = _typed_owners(provider, ctx, rd, rngs)
        else:
            obs["owner_search"] = {"status": "NOT_RUN", "reason": "nothing grew outside malloc", "owners": []}
    obs["heap_walks"] = _leak_walks(provider, ctx)
    obs["header_reads"] = rd.header_reads
    obs["bytes_read"] = rd.bytes_read
    od = ctx["observation_data"]
    od[OBS_MAPPING_GROWTH] = obs
    if rd.bytes_read:
        od["bytes_read"] = int(od.get("bytes_read") or 0) + rd.bytes_read
    ctx["all_records"].append(RuntimeEvidenceRecord(
        evidence_id=f"ev_{uuid.uuid4().hex[:12]}",
        collection_method="proc_maps_series",
        target_pid=pid,
        observed_value={"samples": len(snaps), "outside_growth_kb": obs.get("outside_growth_kb"),
                        "rss_growth_kb": obs.get("rss_growth_kb")},
        collection_scope="PROC_MAPS",
        collection_status=COLLECTION_STATUS_SUCCESS if len(snaps) == SAMPLES else COLLECTION_STATUS_PARTIAL,
        limitations=[obs["unavailable"]] if obs.get("unavailable") else [],
        provenance_class=PROVENANCE_LIVE_RUNTIME_CAPTURE,
        raw_details={"bytes_read": rd.bytes_read, "header_reads": rd.header_reads},
    ))
    return None


# ------------------------------------------------------------------------------------------------ verdict
def mapping_growth_rule(recipe: DiagnosticRecipe, data: Dict[str, Any]) -> Optional[RecipeEvaluationResult]:
    rid = recipe.recipe_id
    mg = data.get(OBS_MAPPING_GROWTH) or {}
    s = [x for x in mg.get("samples") or [] if isinstance(x, dict)]
    steps = [x for x in mg.get("steps") or [] if isinstance(x, dict)]
    if len(s) < 2 or len(steps) != len(s) - 1:
        return RecipeEvaluationResult(
            recipe_id=rid, status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE, confidence=0.0,
            confidence_basis="memory mappings not observed: %s" % (mg.get("unavailable") or "fewer than 2 samples"),
            missing_evidence=["proc_maps_series"], limitations=list(recipe.limitations), details={"mapping_growth": mg})
    out_kb = int(mg.get("outside_growth_kb") or 0)
    rss_kb = int(mg.get("rss_growth_kb") or 0)
    mal_kb = int(mg.get("malloc_growth_kb") or 0)
    win = float(s[-1].get("t_s") or 0.0) - float(s[0].get("t_s") or 0.0)
    nets = [int(x.get("net_outside_kb") or 0) for x in steps]
    trend = ("anonymous memory outside malloc %+d KB over %.1f s (per step %s KB), RSS %+d KB, malloc heap mappings "
             "%+d KB" % (out_kb, win, "/".join("%+d" % n for n in nets), rss_kb, mal_kb))
    details: Dict[str, Any] = {"mapping_growth": mg, "outside_growth_kb": out_kb, "rss_growth_kb": rss_kb}
    rss = [int(x.get("rss_kb") or 0) for x in s]
    if all(n > 0 for n in nets) and out_kb >= MIN_GROWTH_KB and rss_kb >= MIN_RSS_GROWTH_KB \
            and all(b - a >= -64 for a, b in zip(rss, rss[1:])):
        facts = ["memory grows outside malloc: " + trend]
        rows = mg.get("grown_mappings") or []
        new = int(mg.get("new_anonymous_mappings") or 0)
        if rows:
            facts.append("grown or new anonymous mappings: %d (%d newly appeared); largest %s-%s %d KB (+%d KB)"
                         % (int(mg.get("grown_mapping_count") or len(rows)), new, rows[0]["start"], rows[0]["end"],
                            rows[0]["size_kb"], rows[0]["added_kb"]))
        if mg.get("thread_stack_like_kb"):
            facts.append("%d KB of it is in mappings with the layout of a thread stack (guard page below)"
                         % int(mg["thread_stack_like_kb"]))
        owners = (mg.get("owner_search") or {}).get("owners") or []
        for o in owners[:3]:
            facts.append("%d pointer(s) in %s variable %s point into the new mappings"
                         % (o["pointers_into_new_ranges"], o["root_kind"], o["variable_path"]))
        walks = mg.get("heap_walks") or []
        if len(walks) >= 2:
            facts.append("heap in-use %+d KB across %d heap walks"
                         % ((walks[-1]["in_use_bytes"] - walks[0]["in_use_bytes"]) // 1024, len(walks)))
        details.update(finding_category=CATEGORY_MAPPING_GROWTH, growth_confirmed=True,
                       finding_summary="; ".join(facts[:3]), certainty_cap="PROBABLE",
                       certainty_cap_reason="growth of memory outside malloc is measured; whether it is a leak or "
                                            "intended use cannot be decided from memory",
                       owners=[{"variable": o["variable"], "variable_path": o["variable_path"]} for o in owners[:3]])
        return RecipeEvaluationResult(
            recipe_id=rid, status=RECIPE_STATUS_SUPPORTED, confidence=0.8, confidence_basis=facts[0],
            supporting_facts=facts, limitations=list(recipe.limitations),
            recommended_action=("Find the code that maps memory (mmap, a custom allocator, thread creation) and "
                                "never releases it" + (", starting from what %s holds" % owners[0]["variable_path"]
                                                       if owners else "") + "."),
            details=details)
    if out_kb <= NO_GROWTH_KB:
        return RecipeEvaluationResult(
            recipe_id=rid, status=RECIPE_STATUS_CONTRADICTED, confidence=0.8,
            confidence_basis="nothing grows outside malloc: " + trend, contradicting_facts=["no growth outside malloc: " + trend],
            recommended_action="No memory growth outside malloc in the observed window.", details=details)
    return RecipeEvaluationResult(
        recipe_id=rid, status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE, confidence=0.2,
        confidence_basis="memory outside malloc changed, but not as sustained resident growth: " + trend,
        missing_evidence=["longer proc_maps_series"], limitations=list(recipe.limitations), details=details)


register_observation_collector(OBS_MAPPING_GROWTH, collect_mapping_growth)
register_recipe(DiagnosticRecipe(
    recipe_id=RECIPE_MAPPING_GROWTH,
    version="1.0.0",
    name="Memory Growth Outside malloc (anonymous mappings, stacks)",
    domain=DOMAIN_MEMORY_GROWTH,
    applicable_problem_categories=[CATEGORY_MAPPING_GROWTH],
    required_prerequisites=[],
    evidence_sources=["/proc/<pid>/maps", "/proc/<pid>/status", "mmapped chunk headers", "typed globals (DWARF)"],
    collection_steps=[
        {"step": 1, "action": "sample_maps", "purpose": f"{SAMPLES} samples, {INTERVAL_S} s apart"},
        {"step": 2, "action": "classify_new_ranges", "purpose": "malloc heap / mmapped chunk / stack-like / other"},
        {"step": 3, "action": "typed_owner_search", "purpose": "typed globals pointing into the new ranges"},
    ],
    analysis_rules=["outside-malloc anonymous memory growing at every step (>= %d KB) with RSS growth (>= %d KB) is "
                    "growth outside malloc" % (MIN_GROWTH_KB, MIN_RSS_GROWTH_KB),
                    "<= %d KB outside-malloc growth: nothing grows outside malloc" % NO_GROWTH_KB],
    thresholds_and_conditions={"samples": SAMPLES, "interval_s": INTERVAL_S, "min_growth_kb": MIN_GROWTH_KB,
                               "min_rss_growth_kb": MIN_RSS_GROWTH_KB, "no_growth_kb": NO_GROWTH_KB,
                               "max_header_reads": MAX_HEADER_READS},
    supporting_evidence_criteria=["sustained growth of anonymous mappings not owned by malloc, with RSS growth"],
    contradicting_evidence_criteria=["no growth of anonymous memory outside malloc"],
    verification_procedure="Re-sample /proc/<pid>/maps later; the named mappings keep growing.",
    stop_conditions=["maps unreadable"],
    limitations=["a short window: growth slower than about %d KB per %.1f s is not distinguished from churn"
                 % (MIN_GROWTH_KB, INTERVAL_S * (SAMPLES - 1)),
                 "which code maps the memory is not observed (no tracing); only typed global/static pointers are "
                 "searched for an owner, not pointers held in the heap, on stacks or in registers",
                 "an mmapped malloc block allocated with an alignment (memalign) is not recognised as malloc's"],
    output_structure={"samples": "list", "grown_mappings": "list", "owner_search": "dict"},
    observations=(OBS_MAPPING_GROWTH,),
    rule=mapping_growth_rule,
), baseline=True, category=CATEGORY_MAPPING_GROWTH)

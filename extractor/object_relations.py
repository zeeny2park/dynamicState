"""Object relation model (roadmap stage 3): finding -> memory object -> owning variable -> thread.

One small typed model, filled per finding from the evidence the checks already gathered (no target access, no new
reads).  Each finding gets ``findings[].object_relations``::

    {"version": 1,
     "chains": [{"nodes": [{"id", "role", "kind", "name", "attrs"}...],
                 "links": [{"source", "target", "how", "established", "basis"}...]}],
     "note": str (only when no chain applies)}

Roles, in chain order: ``memory_object`` (heap blocks / one heap block / a mapping / a lock / a global's storage),
``variable`` (the owning variable or path), ``thread``.  Every chain has exactly one node per role; a role the
evidence does not establish is a node with ``established: false`` reached by a link whose ``how`` is
``not_established`` and whose ``basis`` says why - never a name guessed from co-occurrence.

Link kinds (``how``) and what each one means:

* ``typed_pointer_path``  - a typed pointer path from the variable reaches the blocks (heap-walk reachability)
* ``dangling_pointer``    - the variable holds the address of the freed block (read from memory)
* ``holds_reference``     - the variable still holds the block's address (read from memory)
* ``pointer_into_mapping``- the variable holds an address inside the grown mapping (read from memory)
* ``debug_symbol``        - the object is the variable at that address in the debug information
* ``arena_attribution``   - the blocks are in an allocator arena whose only attached thread is this one
* ``run_counters``        - the only thread that ran while the mapping grew (per-thread run counters)
* ``lock_owner_field``    - the mutex's owner field names the thread
* ``thread_samples``      - the thread itself is the finding (sampled state), no memory object involved
* ``not_established``     - the link could not be established; ``basis`` says why

The model never feeds a verdict or a status; it is presentation of evidence already in the result.
"""

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Optional

VERSION = 1
ROLES = ("memory_object", "variable", "thread")
LINK_KINDS = ("typed_pointer_path", "dangling_pointer", "holds_reference", "pointer_into_mapping", "debug_symbol",
              "arena_attribution", "run_counters", "lock_owner_field", "thread_samples", "not_established")
MAX_CHAINS = 4

# Why a link is not established (``links[].reason`` -> ``basis``)
NOT_ESTABLISHED = {
    "unreachable": "no reference to these blocks remains in memory (unreachable)",
    "untraced_use": "which thread uses the block is not observable without tracing",
    "untraced_free": "free() calls are not traced, so the freeing thread is not observable",
    "untraced_write": "the writing thread is not observable without tracing",
    "mmapped_no_arena": "mmapped blocks belong to no arena, so no allocating thread is recorded",
    "arena_shared": "several threads share the blocks' arena",
    "arena_unattributed": "the blocks' arena is not attached to exactly one thread",
    "no_owner_variable": "no variable holding the block's address was found",
    "no_path": "no variable path reaches the block",
    "no_mapping_owner": "no global or static variable holds an address in the grown range",
    "no_single_thread": "more than one thread (or none) ran while the mapping grew",
    "owner_changed": "the owner changed between samples: no single thread",
    "owner_unread": "the mutex's owner field could not be read",
    "no_symbol": "the mutex address matches no variable in the debug information",
    "not_memory": "the finding is about the thread's execution, not a memory object",
}


@dataclass
class RelationNode:
    id: str
    role: str                      # memory_object | variable | thread
    kind: str                      # heap_blocks | heap_block | mapping | lock | global_storage | variable | thread | unknown
    name: Optional[str] = None
    established: bool = True
    attrs: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RelationLink:
    source: str                    # node id (the memory object for variable and thread links)
    target: str
    how: str                       # one of LINK_KINDS
    established: bool
    basis: str = ""
    reason: Optional[str] = None   # key of NOT_ESTABLISHED when not established


@dataclass
class RelationChain:
    nodes: List[RelationNode] = field(default_factory=list)
    links: List[RelationLink] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"nodes": [asdict(n) for n in self.nodes], "links": [asdict(x) for x in self.links]}


def _chain(mem: Dict[str, Any], var: Optional[Dict[str, Any]], var_how: str, var_basis: str,
           thr: Optional[Dict[str, Any]], thr_how: str, thr_basis: str) -> RelationChain:
    """One chain: a memory object, the variable owning it, the thread related to it.  ``var`` / ``thr`` None means
    not established (``*_basis`` says why)."""
    assert var_how in LINK_KINDS and thr_how in LINK_KINDS
    c = RelationChain()
    m = RelationNode(id="m", role="memory_object", kind=mem.get("kind") or "unknown", name=mem.get("name"),
                     established=mem.get("established", True), attrs=dict(mem.get("attrs") or {}))
    c.nodes.append(m)
    if var is None:
        c.nodes.append(RelationNode(id="v", role="variable", kind="variable", established=False))
        c.links.append(RelationLink("m", "v", "not_established", False, NOT_ESTABLISHED.get(var_basis, var_basis),
                                    var_basis if var_basis in NOT_ESTABLISHED else None))
    else:
        c.nodes.append(RelationNode(id="v", role="variable", kind="variable", name=var.get("name"),
                                    attrs=dict(var.get("attrs") or {})))
        c.links.append(RelationLink("m", "v", var_how, True, var_basis))
    if thr is None:
        c.nodes.append(RelationNode(id="t", role="thread", kind="thread", established=False))
        c.links.append(RelationLink("m", "t", "not_established", False, NOT_ESTABLISHED.get(thr_basis, thr_basis),
                                    thr_basis if thr_basis in NOT_ESTABLISHED else None))
    else:
        c.nodes.append(RelationNode(id="t", role="thread", kind="thread", name=thr.get("name"),
                                    attrs={k: v for k, v in thr.items() if k != "name" and v is not None}))
        c.links.append(RelationLink("m", "t", thr_how, True, thr_basis))
    return c


def _is_symbol(name: Any) -> bool:
    s = str(name or "")
    return bool(s) and not s.startswith("0x") and not s.isdigit()


# ------------------------------------------------------------------------------------------------ per evidence kind
def _leak(li: Dict[str, Any]) -> List[RelationChain]:
    out: List[RelationChain] = []
    for row in li.get("growth_owners") or []:
        if not isinstance(row, dict):
            continue
        mem = {"kind": "heap_blocks", "attrs": {"blocks_delta": row.get("blocks_delta"),
                                                "bytes_delta": row.get("bytes_delta"),
                                                "walks": li.get("walks")}}
        vattrs: Dict[str, Any] = {"root": row.get("variable"), "owner_kind": row.get("owner_kind")}
        cont = row.get("container")
        if isinstance(cont, dict) and cont.get("decoded"):
            vattrs["container"] = {k: cont.get(k) for k in ("type", "size_last", "capacity", "size_first")
                                   if cont.get(k) is not None}
        thr, how, basis = _arena_thread(row)
        out.append(_chain(mem, {"name": row.get("variable_path") or row.get("variable"), "attrs": vattrs},
                          "typed_pointer_path",
                          "a typed pointer path from %s %s reaches the growing blocks (heap walk)"
                          % (row.get("owner_kind") or "global", row.get("variable")), thr, how, basis))
    for row in li.get("unreachable_growth") or []:
        if not isinstance(row, dict):
            continue
        mem = {"kind": "heap_blocks", "attrs": {"blocks_delta": row.get("blocks_delta"),
                                                "bytes_delta": row.get("bytes_delta"),
                                                "chunk_size": row.get("chunk_size"), "walks": li.get("walks"),
                                                "candidate_type": row.get("candidate_type")}}
        thr, how, basis = _arena_thread(row)
        out.append(_chain(mem, None, "not_established",
                          "unreachable", thr, how, basis))
    return out


def _arena_thread(row: Dict[str, Any]):
    if row.get("allocating_thread_name"):
        return ({"name": row["allocating_thread_name"], "tid": row.get("allocating_thread_tid")}, "arena_attribution",
                str(row.get("arena_evidence") or "the blocks' arena has one attached thread"))
    if row.get("mmapped"):
        return None, "not_established", "mmapped_no_arena"
    if row.get("arena_threads_ambiguous"):
        return None, "not_established", "arena_shared"
    return None, "not_established", "arena_unattributed"


def _mapping(mg: Dict[str, Any]) -> List[RelationChain]:
    grown = [g for g in mg.get("grown_mappings") or [] if isinstance(g, dict)]
    if not grown and not mg.get("outside_growth_kb"):
        return []
    mem = {"kind": "mapping", "name": (grown[0].get("start") if len(grown) == 1 else None),
           "attrs": {"mappings": len(grown) or None, "added_kb": mg.get("outside_growth_kb")}}
    owners = [o for o in ((mg.get("owner_search") or {}).get("owners") or []) if isinstance(o, dict)]
    gt = mg.get("growth_thread") or {}
    thr, how, tb = (None, "not_established", "no_single_thread")
    if gt.get("status") == "ATTRIBUTED":
        thr, how, tb = ({"name": gt.get("allocating_thread_name"), "tid": gt.get("allocating_thread_tid")},
                        "run_counters", str(gt.get("evidence") or "the only thread that ran"))
    if owners:
        o = owners[0]
        attrs = {"root": o.get("variable"), "owner_kind": o.get("root_kind")}
        if isinstance(o.get("container"), dict):
            attrs["container"] = {k: o["container"].get(k) for k in ("type", "size") if o["container"].get(k) is not None}
        return [_chain(mem, {"name": o.get("variable_path") or o.get("variable"), "attrs": attrs},
                       "pointer_into_mapping", "%s holds %s address(es) inside the grown range(s)"
                       % (o.get("variable_path"), o.get("pointers_into_new_ranges")), thr, how, tb)]
    return [_chain(mem, None, "not_established", "no_mapping_owner", thr, how, tb)]


def _freed_use(fm: Dict[str, Any]) -> List[RelationChain]:
    out = []
    for f in fm.get("findings") or []:
        if not isinstance(f, dict):
            continue
        mem = {"kind": "heap_block", "name": f.get("freed_chunk"),
               "attrs": {"state": "free", "chunk_size": f.get("chunk_size")}}
        dp = next((d for d in f.get("dangling_pointers") or [] if isinstance(d, dict)), None)
        var = {"name": dp.get("variable_path") or dp.get("variable"), "attrs": {"owner_kind": dp.get("owner_kind")}} \
            if dp else None
        out.append(_chain(mem, var, "dangling_pointer" if var else "not_established",
                          "the variable still holds the freed block's address" if var else "no_owner_variable",
                          None, "not_established", "untraced_use"))
    return out


def _double_free(fr: Dict[str, Any]) -> List[RelationChain]:
    out = []
    for f in fr.get("findings") or []:
        if not isinstance(f, dict):
            continue
        mem = {"kind": "heap_block", "name": f.get("freed_chunk") or f.get("user_address"),
               "attrs": {"state": "free (listed twice)", "chunk_size": f.get("chunk_size")}}
        o = next((x for x in f.get("owners") or [] if isinstance(x, dict)), None)
        var = {"name": o.get("variable_path") or o.get("variable"), "attrs": {"owner_kind": o.get("owner_kind")}} \
            if o else None
        out.append(_chain(mem, var, "holds_reference" if var else "not_established",
                          "the variable still holds the block's address" if var else "no_owner_variable",
                          None, "not_established", "untraced_free"))
    return out


def _integrity(mi: Dict[str, Any]) -> List[RelationChain]:
    out = []
    heap = mi.get("heap") if isinstance(mi.get("heap"), dict) else {}
    for d in heap.get("defects") or []:
        if not isinstance(d, dict):
            continue
        buf = d.get("overflowing_buffer") if isinstance(d.get("overflowing_buffer"), dict) else None
        if buf is None:
            continue
        mem = {"kind": "heap_block", "name": buf.get("user_address"),
               "attrs": {"usable_size": buf.get("usable_size"), "defect": d.get("kind")}}
        var = {"name": buf.get("variable_path") or buf.get("variable"), "attrs": {"owner_kind": buf.get("owner_kind")}} \
            if (buf.get("variable_path") or buf.get("variable")) else None
        out.append(_chain(mem, var, "typed_pointer_path" if var else "not_established",
                          "a typed pointer path from the variable reaches the overflowing block" if var else "no_path",
                          None, "not_established", "untraced_write"))
    glob = mi.get("globals") if isinstance(mi.get("globals"), dict) else {}
    for g in list(glob.get("defects") or []) + list(glob.get("candidates") or []):
        arr = g.get("overflowed_array") if isinstance(g, dict) else None
        if not isinstance(arr, dict):
            continue
        mem = {"kind": "global_storage", "name": arr.get("variable"),
               "attrs": {"size": arr.get("size"), "address": arr.get("address"),
                         "neighbour": (g.get("overwritten_neighbour") or {}).get("variable")}}
        out.append(_chain(mem, {"name": arr.get("variable_path") or arr.get("variable")}, "debug_symbol",
                          "the storage is this variable in the debug information", None, "not_established",
                          "untraced_write"))
    return out


def _lock_mem(name: Any, addr: Any, **attrs: Any) -> Dict[str, Any]:
    return {"kind": "lock", "name": name if _is_symbol(name) else (addr or name),
            "attrs": {k: v for k, v in dict(address=addr, **attrs).items() if v is not None}}


def _lock_var(name: Any):
    if _is_symbol(name):
        return {"name": str(name)}, "debug_symbol", "the mutex is this variable in the debug information"
    return None, "not_established", "no_symbol"


def _cycle(edges: Iterable[Any]) -> List[RelationChain]:
    out = []
    for e in edges or []:
        if not isinstance(e, dict):
            continue
        var, vh, vb = _lock_var(e.get("lock_name"))
        mem = _lock_mem(e.get("lock_name"), e.get("lock_address"), waiter_tid=e.get("waiter_tid"),
                        waiter_name=e.get("waiter_name"))
        thr = {"name": e.get("owner_name"), "tid": e.get("owner_tid")} if e.get("owner_tid") is not None else None
        out.append(_chain(mem, var, vh, vb, thr, "lock_owner_field" if thr else "not_established",
                          "the mutex's owner field names this thread, which waits in the cycle" if thr else
                          "owner_unread"))
    return out


def _lock_wait(lw: Dict[str, Any]) -> List[RelationChain]:
    out = []
    for o in lw.get("orphan_locks") or []:
        if not isinstance(o, dict):
            continue
        var, vh, vb = _lock_var(o.get("lock_name"))
        mem = _lock_mem(o.get("lock_name"), o.get("lock_address"),
                        waiters=len(o.get("waiters") or []) or None)
        out.append(_chain(mem, var, vh, vb, {"name": None, "tid": o.get("owner_tid"), "alive": o.get("owner_alive")},
                          "lock_owner_field", "the mutex's owner field names this thread, which no longer exists"))
    for s in lw.get("self_waits") or []:
        if not isinstance(s, dict):
            continue
        var, vh, vb = _lock_var(s.get("lock_name"))
        out.append(_chain(_lock_mem(s.get("lock_name"), s.get("lock_address")), var, vh, vb,
                          {"name": s.get("waiter_name"), "tid": s.get("waiter_tid")}, "lock_owner_field",
                          "the mutex's owner field names the thread that waits for it"))
    return out


def _contention(lc: Dict[str, Any]) -> List[RelationChain]:
    out = []
    for m in lc.get("mutexes") or []:
        if not isinstance(m, dict):
            continue
        var, vh, vb = _lock_var(m.get("lock_name"))
        mem = _lock_mem(m.get("lock_name"), m.get("address"), max_waiters=m.get("max_waiters"),
                        owner_changed=m.get("owner_changed"))
        owners = list(m.get("owner_tids") or [])
        where = {w.get("tid"): w for w in m.get("owner_where") or [] if isinstance(w, dict)}
        if len(owners) == 1:
            w = where.get(owners[0]) or {}
            out.append(_chain(mem, var, vh, vb, {"name": w.get("thread_name"), "tid": owners[0]},
                              "lock_owner_field", "the mutex's owner field named this thread in every sample"))
        else:
            out.append(_chain(mem, var, vh, vb, None, "not_established", "owner_changed"))
    return out


def _threads(rows: Iterable[Any]) -> List[RelationChain]:
    out = []
    for r in rows or []:
        if not isinstance(r, dict) or r.get("tid") is None:
            continue
        mem = {"kind": "none", "established": False}
        c = _chain(mem, None, "not_established", "not_memory",
                   {"name": r.get("name"), "tid": r.get("tid")}, "thread_samples",
                   "the thread's sampled state is the finding")
        c.nodes[0].established = False
        out.append(c)
    return out


# ------------------------------------------------------------------------------------------------ assembly
def _observations(report: Optional[Dict[str, Any]], rule_ids: Iterable[str]) -> List[Dict[str, Any]]:
    wanted = set(rule_ids or [])
    out = []
    checks = ((report or {}).get("section_d_detailed_inspection_results") or {}).get("checks") or []
    for c in checks:
        if isinstance(c, dict) and c.get("recipe_id") in wanted and c.get("status") == "FAIL" \
                and isinstance(c.get("actual_observations"), dict):
            out.append(c["actual_observations"])
    return out


def _key(c: RelationChain) -> tuple:
    return tuple((n.role, n.kind, str(n.name)) for n in c.nodes) + tuple((x.how,) for x in c.links)


def build_relations(finding: Dict[str, Any], report: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """The relation chains of one finding from the observations of the checks that failed for it."""
    chains: List[RelationChain] = []
    for ob in _observations(report, finding.get("recipe_ids") or []):
        if isinstance(ob.get("leak_investigation"), dict):
            chains += _leak(ob["leak_investigation"])
        if isinstance(ob.get("mapping_growth"), dict):
            chains += _mapping(ob["mapping_growth"])
        if isinstance(ob.get("freed_memory_use"), dict):
            chains += _freed_use(ob["freed_memory_use"])
        if isinstance(ob.get("free_list_repeats"), dict):
            chains += _double_free(ob["free_list_repeats"])
        if isinstance(ob.get("memory_integrity"), dict):
            chains += _integrity(ob["memory_integrity"])
        if isinstance(ob.get("deadlock_cycle"), list):
            chains += _cycle(ob["deadlock_cycle"])
        if isinstance(ob.get("lock_wait_state"), dict):
            chains += _lock_wait(ob["lock_wait_state"])
        if isinstance(ob.get("lock_contention"), dict):
            chains += _contention(ob["lock_contention"])
    if not chains:
        for ob in _observations(report, finding.get("recipe_ids") or []):
            chains += _threads(ob.get("runaway_threads") or [])
    uniq: List[RelationChain] = []
    seen = set()
    for c in chains:
        k = _key(c)
        if k not in seen:
            seen.add(k)
            uniq.append(c)
    out: Dict[str, Any] = {"version": VERSION, "chains": [c.to_dict() for c in uniq[:MAX_CHAINS]]}
    if len(uniq) > MAX_CHAINS:
        out["chains_omitted"] = len(uniq) - MAX_CHAINS
    if not uniq:
        out["note"] = "the evidence of this finding names no memory object, owning variable or thread relation"
    return out


def attach_object_relations(findings: List[Dict[str, Any]], report: Optional[Dict[str, Any]]) -> None:
    """``findings[].object_relations`` for every finding (never raises; never changes any other field)."""
    for f in findings or []:
        if not isinstance(f, dict):
            continue
        try:
            f["object_relations"] = build_relations(f, report)
        except Exception as exc:  # noqa: BLE001 - presentation only
            f["object_relations"] = {"version": VERSION, "chains": [],
                                     "note": "relations not built: %s: %s" % (type(exc).__name__, exc)}

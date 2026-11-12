"""Type-driven heap reachability and reverse lookup: address -> owning variable (IMP-007, parts 2-3).

Builds, for every heap chunk found by :mod:`extractor.heap_walker`, the list of *referrers*: the
names of the pointer slots that point into it, e.g. ``g_cache.entries[3].data``.

Roots (each referrer says which kind of root produced it)
---------------------------------------------------------
* ``global`` / ``static``  - DWARF global and file/function static variables of the main
  executable and of every loaded debug module (typed).
* ``local``                - locals/parameters of stack frames, when the existing frame decoder
  (``WatchSessionManager.inspect_thread_locals_and_frame_vars``) supports the target (typed,
  reported as "thread, function, variable").  It is x86_64-only today (IMP-015); elsewhere:
* ``stack_conservative``   - every word of each thread's live stack (from the thread's stack
  pointer when the kernel exposes it, else the whole stack mapping) that holds a chunk address:
  "referenced from stack of thread <name> (conservative, no variable name)".
* ``data_conservative``    - writable data of every loaded module (libc stdio buffers, ld.so ...)
  and ``anon_conservative`` - other anonymous writable mappings (TLS blocks); untyped.
* ``heap_conservative``    - words inside reachable chunks whose type is unknown (``void*``,
  ``char*`` targets, slack) that point to otherwise unreached chunks.

Typed traversal
---------------
Pointers are followed by DWARF type: struct/class members (including base classes), unions,
arrays, pointer-to-pointer, linked structures.  A pointer whose target lies inside a chunk maps to
the containing chunk (interior pointers keep their offset).  ``void*`` / ``char*`` (pointee
without members) record the edge but are not descended.  A pointer to a struct ``T`` whose chunk
holds room for >= 2 ``T`` is walked as an array (``p[i].m``), otherwise as ``p->m``.  Cycles are
cut by a visited set keyed on (address, type); the traversal is bounded by ``max_nodes`` /
``max_edges`` and reports truncation.

Path syntax: ``.`` member of an object, ``->`` member through a pointer, ``[i]`` element; a run of
more than 3 identical steps renders as ``(->next)*N``.

Leak candidates = in-use chunks (``in_use``/``in_use_mmapped``) reached by no root at all
(typed or conservative).  Pointers that live only in CPU registers are invisible to a non-stopping
reader, so a block referenced only from a register is a (rare) false candidate.
"""

import bisect
import os
import struct
import time
from array import array
from collections import deque
from dataclasses import dataclass
from typing import Any, Deque, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from .heap_walker import (
    IN_USE_STATES,
    ST_IN_USE,
    ST_INTERNAL,
    ST_MMAPPED,
    ST_TOP,
    STATE_NAMES,
    BudgetedReader,
    HeapWalker,
    HeapWalkResult,
    HeapWalkBudgetExhausted,
    _map_bounds,
)

_STRUCT_TAGS = ("DW_TAG_structure_type", "DW_TAG_class_type", "DW_TAG_union_type")
_PTR_TAGS = ("DW_TAG_pointer_type", "DW_TAG_reference_type", "DW_TAG_rvalue_reference_type")

KIND_GLOBAL = "global"
KIND_STATIC = "static"
KIND_LOCAL = "local"
KIND_STACK_CONS = "stack_conservative"
KIND_DATA_CONS = "data_conservative"
KIND_ANON_CONS = "anon_conservative"
KIND_HEAP_CONS = "heap_conservative"
TYPED_KINDS = (KIND_GLOBAL, KIND_STATIC, KIND_LOCAL)

REACH_TYPED = "typed"
REACH_CONSERVATIVE = "conservative"
REACH_NONE = "none"


@dataclass
class _Root:
    kind: str
    name: str
    module: Optional[str] = None
    thread: Optional[str] = None
    tid: Optional[int] = None
    function: Optional[str] = None
    region: Optional[str] = None


@dataclass
class ReachabilityLimits:
    max_nodes: int = 2_000_000
    max_edges: int = 4_000_000
    max_array_elems: int = 4_000_000
    max_refs_per_chunk: int = 8
    max_root_var_bytes: int = 64 * 1024 * 1024
    max_conservative_region_bytes: int = 16 * 1024 * 1024
    # A thread stack whose stack pointer is unknown (running thread) is scanned from its top down to at most this
    # many bytes (None = max_conservative_region_bytes).  Live frames and the thread descriptor sit at the top.
    max_stack_without_sp_bytes: Optional[int] = None
    max_conservative_total_bytes: int = 256 * 1024 * 1024
    max_mmapped_content_bytes: int = 64 * 1024 * 1024
    max_path_tokens: int = 4096


class ReachabilityAnalyzer:
    def __init__(self, walk: HeapWalkResult, walker: HeapWalker, reader: BudgetedReader,
                 modules: Sequence[Tuple[str, Any, int, bool]], limits: Optional[ReachabilityLimits] = None):
        self.walk = walk
        self.walker = walker
        self.reader = reader
        self.modules = list(modules)            # (module name, DwarfIndex, load bias, is_dyn)
        self.limits = limits or ReachabilityLimits()
        self.ct = walk.chunks
        self.snap = walk.snapshot
        n = len(self.ct)
        self.reach = bytearray(n)               # 0 none, 1 conservative, 2 typed
        self.refs: Dict[int, List[Tuple[int, str, int, int, int]]] = {}   # ci -> [(node, suffix, root, slot, interior)]
        self.ref_counts: Dict[int, int] = {}
        self.roots: List[_Root] = []
        self.node_parent = array("q")
        self.node_suffix: List[str] = []
        self.node_root = array("l")
        self.visited: Set[Tuple[int, int]] = set()
        self.queue: Deque[Tuple[int, int, Optional[int], bool, int]] = deque()   # (node, addr, type, as_array, module)
        self.untyped_reached: Set[int] = set()
        self.pending_probe: Dict[int, List[Tuple[int, str, int, int, Optional[int], Any]]] = {}
        self.edges = 0
        self.truncated: List[str] = []
        self.typed_local_slots: Set[int] = set()
        self.stats: Dict[str, Any] = {}
        self._tcache: Dict[Tuple[int, int], Any] = {}
        self._members_cache: Dict[Tuple[int, int], List[Tuple[str, int, Optional[int]]]] = {}
        self._hasptr_cache: Dict[Tuple[int, int], bool] = {}
        self._anon_ranges = self._anonymous_ranges()
        self._mmapped_read = 0
        # IMP-008: typed pointers into an arena's old top chunk (target allocated after the walk read the
        # arena) wait here until the walker caught up with the new top; bounded per arena.
        self.pending_top: Dict[int, List[Tuple[int, str, int, int, int, int, Optional[int]]]] = {}
        self._top_catch_up: Dict[int, int] = {}
        self.max_top_catch_up = 4
        # IMP-009: ci -> (node, suffix, root, sizeof pointee, type name, module, type die) of the first typed
        # struct pointer to the start of the block (input of the "allocation smaller than its type" check)
        self.typed_pointee: Dict[int, Tuple[int, str, int, int, str, int, int]] = {}

    # ------------------------------------------------------------------ type helpers
    def _canon(self, mi: int, off: Optional[int]):
        if off is None:
            return None
        key = (mi, off)
        t = self._tcache.get(key, False)
        if t is False:
            t = self.modules[mi][1].resolve_canonical_type(off)
            self._tcache[key] = t
        return t

    def _members(self, mi: int, t) -> List[Tuple[str, int, Optional[int]]]:
        key = (mi, t.die_offset)
        cached = self._members_cache.get(key)
        if cached is not None:
            return cached
        idx = self.modules[mi][1]
        out: List[Tuple[str, int, Optional[int]]] = []

        def _collect(tt, base, depth):
            if depth > 16:
                return
            for b in getattr(tt, "base_classes", []) or []:      # same flattening as CppObjectDecoder
                bt = idx.resolve_canonical_type(b.type_offset)
                if bt is not None and bt.tag in _STRUCT_TAGS:
                    _collect(bt, base + int(b.offset or 0), depth + 1)
            for m in tt.members:
                if m.type_offset is None:
                    continue
                out.append((m.name or "<anon>", base + int(m.offset or 0), m.type_offset))
        _collect(t, 0, 0)
        out = [m for m in out if self._has_pointers(mi, m[2])]
        self._members_cache[key] = out
        return out

    def _has_pointers(self, mi: int, off: Optional[int], depth: int = 0) -> bool:
        if off is None or depth > 32:
            return False
        key = (mi, off)
        hit = self._hasptr_cache.get(key)
        if hit is not None:
            return hit
        self._hasptr_cache[key] = False          # cycle guard
        t = self._canon(mi, off)
        res = False
        if t is not None:
            if t.tag in _PTR_TAGS:
                pt = self._canon(mi, t.target_type_offset)
                res = not (pt is not None and pt.tag == "DW_TAG_subroutine_type")
            elif t.tag in _STRUCT_TAGS:
                idx = self.modules[mi][1]
                res = any(self._has_pointers(mi, m.type_offset, depth + 1) for m in t.members) or any(
                    self._has_pointers(mi, b.type_offset, depth + 1) for b in (getattr(t, "base_classes", []) or []))
            elif t.tag == "DW_TAG_array_type":
                res = self._has_pointers(mi, t.target_type_offset, depth + 1)
        self._hasptr_cache[key] = res
        return res

    def _type_size(self, mi: int, off: Optional[int]) -> int:
        t = self._canon(mi, off)
        if t is None:
            return 0
        if t.tag in _PTR_TAGS:
            return 8
        if t.tag == "DW_TAG_array_type":
            if t.byte_size:
                return int(t.byte_size)
            if t.array_count:
                return int(t.array_count) * self._type_size(mi, t.target_type_offset)
            return 0
        return int(t.byte_size or 0)

    # ------------------------------------------------------------------ nodes / paths
    def _new_root(self, root: _Root) -> int:
        self.roots.append(root)
        return len(self.roots) - 1

    def _new_node(self, parent: int, suffix: str, root: int) -> int:
        self.node_parent.append(parent)
        self.node_suffix.append(suffix)
        self.node_root.append(root)
        return len(self.node_suffix) - 1

    def render(self, node: int, suffix: str = "") -> str:
        toks: List[str] = [suffix] if suffix else []
        n = node
        guard = 0
        while n >= 0 and guard < self.limits.max_path_tokens:
            toks.append(self.node_suffix[n])
            n = self.node_parent[n]
            guard += 1
        toks.reverse()
        # compress runs of identical steps
        parts: List[str] = []
        i = 0
        while i < len(toks):
            j = i
            while j + 1 < len(toks) and toks[j + 1] == toks[i]:
                j += 1
            run = j - i + 1
            if run > 3:
                parts.append("(%s)*%d" % (toks[i], run))
            else:
                parts.append(toks[i] * run)
            i = j + 1
        s = "".join(parts)
        if n >= 0:
            s = "..." + s
        return s

    # ------------------------------------------------------------------ edges
    def _record_ref(self, ci: int, node: int, suffix: str, root: int, slot: int, interior: int, typed: bool) -> None:
        self.ref_counts[ci] = self.ref_counts.get(ci, 0) + 1
        lst = self.refs.setdefault(ci, [])
        if len(lst) < self.limits.max_refs_per_chunk:
            lst.append((node, suffix, root, slot, interior))
        lvl = 2 if typed else 1
        if self.reach[ci] < lvl:
            self.reach[ci] = lvl

    def _in_anon(self, v: int) -> bool:
        i = bisect.bisect_right(self._anon_ranges, (v, 1 << 64)) - 1
        return i >= 0 and self._anon_ranges[i][0] <= v < self._anon_ranges[i][1]

    def _on_pointer(self, node: int, suffix: str, root: int, slot: int, value: int, mi: int,
                    pointee_off: Optional[int]) -> None:
        ci = self.ct.find_containing(value)
        if ci is None:
            ai = self._beyond_top_arena(value)
            if ai is not None:
                self.pending_top.setdefault(ai, []).append((node, suffix, root, slot, value, mi, pointee_off))
                return
            if (value & 0xFFF) == 0x10 and self._in_anon(value):
                self.pending_probe.setdefault(value, []).append((node, suffix, root, slot, pointee_off, mi))
            return
        if self.ct.states[ci] == ST_TOP and hasattr(self.walker, "extend_arena_top"):
            ai = int(self.ct.arena[ci])
            if self._top_catch_up.get(ai, 0) < self.max_top_catch_up:
                self.pending_top.setdefault(ai, []).append((node, suffix, root, slot, value, mi, pointee_off))
                return
        self.edges += 1
        if self.edges > self.limits.max_edges:
            if "max_edges" not in self.truncated:
                self.truncated.append("max_edges")
            return
        user = self.ct.addrs[ci] + 16
        self._record_ref(ci, node, suffix, root, slot, value - user, typed=True)
        if self.ct.states[ci] not in IN_USE_STATES:
            return                                  # dangling pointer to a free block: do not descend
        pt = self._canon(mi, pointee_off)
        if value == user and ci not in self.typed_pointee and pt is not None and pt.tag in _STRUCT_TAGS \
                and int(pt.byte_size or 0) > 0 and (pt.members or getattr(pt, "base_classes", None)):
            # IMP-009: first typed pointer to the start of the block, with its pointee struct size
            self.typed_pointee[ci] = (node, suffix, root, int(pt.byte_size), pt.name or "", mi, pt.die_offset)
        if pt is None or pt.tag in ("DW_TAG_base_type", "DW_TAG_enumeration_type", "DW_TAG_subroutine_type") or (
                pt.tag in _STRUCT_TAGS and not pt.members and not getattr(pt, "base_classes", None)):
            self.untyped_reached.add(ci)            # void*, char*, opaque struct: edge only
            return
        if not self._has_pointers(mi, pointee_off):
            return
        key = (value, pt.die_offset)
        if key in self.visited:
            return
        self.visited.add(key)
        if len(self.node_suffix) >= self.limits.max_nodes:
            if "max_nodes" not in self.truncated:
                self.truncated.append("max_nodes")
            return
        child = self._new_node(node, suffix, root)
        esz = self._type_size(mi, pointee_off)
        user_end = self.ct.addrs[ci] + 16 + self.ct.usable_size(ci)
        as_array = esz > 0 and (user_end - value) // esz >= 2
        self.queue.append((child, value, pointee_off, as_array, mi))

    def _beyond_top_arena(self, value: int) -> Optional[int]:
        """Arena whose heap grew past the walked segment and now holds ``value`` (above its old top)."""
        if not hasattr(self.walker, "extend_arena_top"):
            return None
        layout = getattr(self.walker, "_layout", None)
        hmax = int(getattr(layout, "heap_max_size", 0) or (64 << 20))
        for ai, info in enumerate(self.walk.arenas):
            if self._top_catch_up.get(ai, 0) >= self.max_top_catch_up:
                continue
            try:
                top = int(str(info.get("top")), 16)
            except (TypeError, ValueError):
                continue
            if not (top < value < top + hmax):
                continue
            if ai and (value & ~(hmax - 1)) != (top & ~(hmax - 1)):
                continue
            return ai
        return None

    def _chunk_bytes(self, ci: int) -> Optional[Tuple[bytes, int]]:
        a = self.ct.addrs[ci]
        size = int(self.ct.sizes[ci])
        loc = self.snap.locate(a, size)
        if loc is not None:
            return loc
        if self.ct.states[ci] == ST_MMAPPED:
            want = min(size, self.limits.max_mmapped_content_bytes - self._mmapped_read)
            if want <= 0:
                if "mmapped_content_budget" not in self.truncated:
                    self.truncated.append("mmapped_content_budget")
                return None
            data = self.reader.read(a, want)
            if data:
                self._mmapped_read += len(data)
                self.snap.add(a, data)
                return self.snap.locate(a, len(data))
        return None

    # ------------------------------------------------------------------ typed scan
    def _scan(self, node: int, root: int, mi: int, buf: bytes, boff: int, addr: int, type_off: Optional[int],
              prefix: str, deref_top: bool, depth: int = 0) -> None:
        if depth > 64:
            return
        t = self._canon(mi, type_off)
        if t is None:
            return
        tag = t.tag
        if tag in _PTR_TAGS:
            if boff + 8 > len(buf):
                return
            v = struct.unpack_from("<Q", buf, boff)[0]
            if v:
                self._on_pointer(node, prefix, root, addr, v, mi, t.target_type_offset)
            return
        if tag in _STRUCT_TAGS:
            sep = "->" if (deref_top and not prefix) else "."
            for name, moff, mtype in self._members(mi, t):
                self._scan(node, root, mi, buf, boff + moff, addr + moff, mtype, prefix + sep + name, False, depth + 1)
            return
        if tag == "DW_TAG_array_type":
            et_off = t.target_type_offset
            if not self._has_pointers(mi, et_off):
                return
            esz = self._type_size(mi, et_off)
            if esz <= 0:
                return
            count = t.array_count if t.array_count else (int(t.byte_size or 0) // esz)
            count = min(int(count or 0), (len(buf) - boff) // esz)
            self._scan_elements(node, root, mi, buf, boff, addr, et_off, esz, count, prefix, depth)

    def _scan_elements(self, node: int, root: int, mi: int, buf: bytes, boff: int, addr: int, et_off: Optional[int],
                       esz: int, count: int, prefix: str, depth: int) -> None:
        if count > self.limits.max_array_elems:
            count = self.limits.max_array_elems
            if "max_array_elems" not in self.truncated:
                self.truncated.append("max_array_elems")
        et = self._canon(mi, et_off)
        if et is not None and et.tag in _PTR_TAGS and esz == 8:
            # fast path: array of pointers
            words = array("Q", bytes(buf[boff:boff + count * 8]))
            pt = et.target_type_offset
            find = self.ct.find_containing
            for i, v in enumerate(words):
                if v and (find(v) is not None or ((v & 0xFFF) == 0x10 and self._in_anon(v))):
                    self._on_pointer(node, "%s[%d]" % (prefix, i), root, addr + i * 8, v, mi, pt)
            return
        for i in range(count):
            self._scan(node, root, mi, buf, boff + i * esz, addr + i * esz, et_off, "%s[%d]" % (prefix, i), False,
                       depth + 1)

    def _drain(self) -> None:
        while True:
            while self.queue:
                node, addr, type_off, as_array, mi = self.queue.popleft()
                ci = self.ct.find_containing(addr)
                if ci is None:
                    continue
                loc = self._chunk_bytes(ci)
                if loc is None:
                    continue
                buf, coff = loc
                boff = coff + (addr - self.ct.addrs[ci])
                chunk_end = coff + 16 + self.ct.usable_size(ci)
                view = buf if chunk_end >= len(buf) else memoryview(buf)[:chunk_end]   # no copy of the whole segment per chunk
                root = self.node_root[node]
                pt = self._canon(mi, type_off)
                if as_array or (pt is not None and pt.tag not in _STRUCT_TAGS):
                    # T* to an array of T in the chunk (p[i]...), or T** / scalar pointee (p[0])
                    esz = self._type_size(mi, type_off)
                    count = (min(len(view), chunk_end) - boff) // esz if as_array else 1
                    self._scan_elements(node, root, mi, view, boff, addr, type_off, esz, count, "", 0)
                else:
                    self._scan(node, root, mi, view, boff, addr, type_off, "", True)
            if self.pending_top:
                ptop = self.pending_top
                self.pending_top = {}
                grown = False
                for ai in ptop:
                    self._top_catch_up[ai] = self._top_catch_up.get(ai, 0) + 1
                    if self.walker.extend_arena_top(ai) > 0:
                        grown = True
                    else:
                        self._top_catch_up[ai] = self.max_top_catch_up      # nothing more to gain
                if grown:
                    self._grow()
                for ai, lst in ptop.items():
                    for node, suffix, root, slot, value, mi, pointee_off in lst:
                        self._on_pointer(node, suffix, root, slot, value, mi, pointee_off)
                continue
            if not self.pending_probe:
                return
            pend = self.pending_probe
            self.pending_probe = {}
            added = self.walker.probe_mmapped(pend.keys())
            if added:
                self._grow()
                for value, lst in pend.items():
                    if self.ct.find_containing(value) is None:
                        continue
                    for node, suffix, root, slot, pointee_off, mi in lst:
                        self._on_pointer(node, suffix, root, slot, value, mi, pointee_off)

    def _grow(self) -> None:
        """The chunk table was re-sorted after new mmapped chunks: remap per-chunk state."""
        old_addrs = self._addr_of_index
        new_index = {a: i for i, a in enumerate(self.ct.addrs)}
        reach = bytearray(len(self.ct))
        for i, a in enumerate(old_addrs):
            reach[new_index[a]] = self.reach[i]
        self.reach = reach
        self.refs = {new_index[old_addrs[i]]: v for i, v in self.refs.items()}
        self.ref_counts = {new_index[old_addrs[i]]: v for i, v in self.ref_counts.items()}
        self.untyped_reached = {new_index[old_addrs[i]] for i in self.untyped_reached}
        self.typed_pointee = {new_index[old_addrs[i]]: v for i, v in self.typed_pointee.items()}
        self._addr_of_index = list(self.ct.addrs)

    # ------------------------------------------------------------------ roots
    def add_global_roots(self) -> int:
        """Typed roots: DWARF globals/statics of every module. Reads their memory in one batch."""
        wanted: List[Tuple[int, Any, int, int]] = []
        seen: Set[Tuple[int, int]] = set()
        for mi, (mname, idx, bias, is_dyn) in enumerate(self.modules):
            for var, kind in [(v, KIND_GLOBAL) for v in idx.global_variables] + [(v, KIND_STATIC) for v in idx.static_variables]:
                if var.link_time_address is None or var.is_declaration or not var.name:
                    continue
                if not self._has_pointers(mi, var.type_offset):
                    continue
                size = self._type_size(mi, var.type_offset)
                if size <= 0 or size > self.limits.max_root_var_bytes:
                    continue
                rt = (bias + var.link_time_address) if is_dyn else var.link_time_address
                if (rt, var.type_offset) in seen:
                    continue
                seen.add((rt, var.type_offset))
                wanted.append((mi, var, rt, size, kind, mname))
        datas = self.reader.read_ranges([(rt, size) for _, _, rt, size, _, _ in wanted]) if wanted else []
        n = 0
        for (mi, var, rt, size, kind, mname), data in zip(wanted, datas):
            if not data:
                continue
            r = self._new_root(_Root(kind=kind, name=var.name, module=mname))
            node = self._new_node(-1, var.name, r)
            self._scan(node, r, mi, data, 0, rt, var.type_offset, "", False)
            n += 1
        self._drain()
        self.stats["global_roots"] = n
        return n

    def add_local_roots(self, frames_result: Dict[str, Any]) -> Dict[str, Any]:
        """Typed roots from the existing frame decoder output (only where it is supported)."""
        info = {"threads": 0, "typed_locals": 0, "decoder_status": {}}
        if not frames_result or not self.modules:
            return info
        mi = 0
        idx = self.modules[0][1]
        wanted = []
        for th in frames_result.get("threads", []) or []:
            info["threads"] += 1
            info["decoder_status"][str(th.get("tid"))] = th.get("frame_decode_status")
            for fr in th.get("frames", []) or []:
                fn = fr.get("function_name")
                subs = idx.subprograms_by_name.get(fn or "", [])
                for v in list(fr.get("parameters") or []) + list(fr.get("locals") or []):
                    try:
                        va = int(str(v.get("runtime_address")), 16)
                    except (TypeError, ValueError):
                        continue
                    toff = None
                    for sp in subs:
                        dv = sp.get_variable(v.get("name")) if hasattr(sp, "get_variable") else None
                        if dv is not None and dv.type_offset is not None:
                            toff = dv.type_offset
                            break
                    if toff is None or not self._has_pointers(mi, toff):
                        continue
                    size = self._type_size(mi, toff)
                    if size <= 0 or size > 1 << 20:
                        continue
                    wanted.append((th, fn, v.get("name"), va, toff, size))
        datas = self.reader.read_ranges([(va, size) for *_, va, toff, size in wanted]) if wanted else []
        for (th, fn, vname, va, toff, size), data in zip(wanted, datas):
            if not data:
                continue
            r = self._new_root(_Root(kind=KIND_LOCAL, name=vname, thread=th.get("name"), tid=th.get("tid"), function=fn))
            node = self._new_node(-1, vname, r)
            for k in range(0, size, 8):
                self.typed_local_slots.add(va + k)
            self._scan(node, r, mi, data, 0, va, toff, "", False)
            info["typed_locals"] += 1
        self._drain()
        return info

    # ------------------------------------------------------------------ conservative
    def _anonymous_ranges(self) -> List[Tuple[int, int]]:
        out = []
        for m in self.walk.mappings:
            if (m.get("pathname") or "") or "w" not in (m.get("permissions") or ""):
                continue
            out.append(_map_bounds(m))
        out.sort()
        return out

    def _prefixes(self) -> List[bytes]:
        pre = set()
        rngs = list(self.walk.heap_ranges) + list(self._anon_ranges)
        for s, e in rngs:
            for hi in range(s >> 32, ((e - 1) >> 32) + 1):
                pre.add(struct.pack("<I", hi))
        return sorted(pre)

    def _pointer_words(self, buf: bytes, base: int, prefixes: Sequence[bytes]) -> Iterable[Tuple[int, int]]:
        """(offset, value) of 8-aligned little-endian words whose upper half matches a heap prefix."""
        lim = len(buf) - 8
        for pfx in prefixes:
            pos = buf.find(pfx, 4)
            while pos != -1:
                woff = pos - 4
                if (base + woff) % 8 == 0 and woff <= lim:
                    yield woff, struct.unpack_from("<Q", buf, woff)[0]
                pos = buf.find(pfx, pos + 1)

    def _conservative_region(self, ctx: Any, start: int, buf: bytes, prefixes: Sequence[bytes],
                             skip_slots: Optional[Set[int]] = None, suffix_fmt: Optional[str] = None) -> List[int]:
        """Record untyped references found in ``buf``.  ``ctx`` is (root, parent_node) or a callable
        creating it on first use (so that scanning many chunks does not allocate nodes per chunk)."""
        newly: List[int] = []
        probe: Dict[int, List[int]] = {}
        find = self.ct.find_containing
        hits: List[Tuple[int, int]] = []
        for woff, v in self._pointer_words(buf, start, prefixes):
            slot = start + woff
            if skip_slots and slot in skip_slots:
                continue
            ci = find(v)
            if ci is None:
                if (v & 0xFFF) == 0x10 and self._in_anon(v):
                    probe.setdefault(v, []).append(slot)
                continue
            if self.ct.states[ci] not in IN_USE_STATES or self.reach[ci] == 2:
                continue
            hits.append((slot, v))
        if probe:
            if self.walker.probe_mmapped(probe.keys()):
                self._grow()
                for v, slots in probe.items():
                    ci = find(v)
                    if ci is not None and self.reach[ci] != 2:
                        hits.extend((slot, v) for slot in slots)
        if not hits:
            return newly
        if callable(ctx):
            ctx = ctx()
        root, parent_node = ctx
        for slot, v in hits:
            ci = find(v)
            if ci is None:
                continue
            first = self.reach[ci] == 0
            suffix = (suffix_fmt % (slot - start)) if suffix_fmt else ""
            self._record_ref(ci, parent_node, suffix, root, slot, v - (self.ct.addrs[ci] + 16), typed=False)
            if first:
                newly.append(ci)
        return newly

    def add_conservative_roots(self, threads: Sequence[Dict[str, Any]], exe_path: Optional[str] = None) -> Dict[str, Any]:
        prefixes = self._prefixes()
        info = {"stacks": [], "data_regions": 0, "anon_regions": 0, "bytes_scanned": 0}
        newly: List[int] = []
        total = 0
        stack_ranges: List[Tuple[int, int]] = []
        regions: List[Tuple[str, Dict[str, Any], int, int]] = []
        for t in threads:
            si = t.get("stack_info") or {}
            s = int(si.get("start_int") or 0)
            e = int(si.get("end_int") or 0)
            if not (e > s > 0):
                continue
            stack_ranges.append((s, e))
            sp = int(si.get("sp_int") or 0)
            frm = (sp & ~7) if s <= sp < e else s
            frm = max(frm, e - self.limits.max_conservative_region_bytes)
            if not (s <= sp < e) and self.limits.max_stack_without_sp_bytes is not None:
                frm = max(frm, e - int(self.limits.max_stack_without_sp_bytes))
            regions.append((KIND_STACK_CONS, {"thread": t.get("name"), "tid": t.get("tid"),
                                              "from_sp": bool(s <= sp < e)}, frm, e))
        heap_r = list(self.walk.heap_ranges)
        # threads whose stack the adapter could not identify (running threads expose no stack
        # pointer): their stack is an anonymous mapping above a PROT_NONE guard whose top (the
        # thread descriptor) holds the TID.  Such mappings are matched after reading them.
        unresolved = {int(t.get("tid")): t.get("name") for t in threads
                      if t.get("tid") is not None and not (t.get("stack_info") or {}).get("end_int")}
        ordered = sorted(self.walk.mappings, key=lambda mm: _map_bounds(mm)[0])
        guarded: Set[int] = set()
        for prev, cur in zip(ordered, ordered[1:]):
            if _map_bounds(prev)[1] == _map_bounds(cur)[0] and (prev.get("permissions") or "").startswith("---"):
                guarded.add(_map_bounds(cur)[0])
        for m in self.walk.mappings:
            perms = m.get("permissions") or ""
            if "r" not in perms or "w" not in perms:
                continue
            s, e = _map_bounds(m)
            p = m.get("pathname") or ""
            if p.startswith("["):
                continue
            if any(ss <= s < se for ss, se in stack_ranges) or any(hs <= s < he or s <= hs < e for hs, he in heap_r):
                continue
            kind = KIND_DATA_CONS if p else KIND_ANON_CONS
            is_guarded = s in guarded and not p
            lo, hi = s, min(e, s + self.limits.max_conservative_region_bytes)
            if is_guarded and unresolved and self.limits.max_stack_without_sp_bytes is not None:
                # probably the stack of a running thread: its live part is at the top
                lo, hi = max(s, e - int(self.limits.max_stack_without_sp_bytes)), e
            regions.append((kind, {"region": os.path.basename(p) if p else "anonymous 0x%x" % s,
                                   "guarded": is_guarded}, lo, hi))
        reads = []
        for kind, meta, s, e in regions:
            if total + (e - s) > self.limits.max_conservative_total_bytes:
                if "conservative_total_bytes" not in self.truncated:
                    self.truncated.append("conservative_total_bytes")
                continue
            total += e - s
            reads.append((kind, meta, s, e))
        datas = self.reader.read_ranges([(s, e - s) for _, _, s, e in reads]) if reads else []
        for (kind, meta, s, e), data in zip(reads, datas):
            if not data:
                continue
            info["bytes_scanned"] += len(data)
            if meta.get("guarded") and unresolved:
                top = data[-65536:]
                for tid, tname in list(unresolved.items()):
                    if struct.pack("<i", tid) in top:
                        kind = KIND_STACK_CONS
                        meta = {"thread": tname, "tid": tid, "from_sp": False}
                        unresolved.pop(tid, None)
                        break
            if kind == KIND_STACK_CONS:
                r = self._new_root(_Root(kind=kind, name="stack of thread %s" % meta["thread"], thread=meta["thread"],
                                         tid=meta["tid"], region="0x%x-0x%x" % (s, e)))
                info["stacks"].append({"thread": meta["thread"], "tid": meta["tid"], "bytes": len(data),
                                       "from_stack_pointer": meta["from_sp"]})
                newly += self._conservative_region((r, -1), s, data, prefixes, skip_slots=self.typed_local_slots)
            else:
                r = self._new_root(_Root(kind=kind, name=meta["region"], region="0x%x-0x%x" % (s, e)))
                info["data_regions" if kind == KIND_DATA_CONS else "anon_regions"] += 1
                newly += self._conservative_region((r, -1), s, data, prefixes)
        self._propagate_conservative(prefixes, newly)
        return info

    def _propagate_conservative(self, prefixes: Sequence[bytes], seeds: List[int]) -> None:
        """Scan the contents of every reached in-use chunk for pointers to still-unreached chunks."""
        work: Deque[int] = deque()
        done: Set[int] = set()
        for ci in range(len(self.ct)):
            if self.reach[ci] and self.ct.states[ci] in (ST_IN_USE, ST_MMAPPED):
                work.append(self.ct.addrs[ci])
        for ci in seeds:
            work.append(self.ct.addrs[ci])
        scanned = 0
        while work:
            a = work.popleft()
            if a in done:
                continue
            done.add(a)
            ci = self.ct.index_of_chunk(a)
            if ci is None:
                continue
            loc = self._chunk_bytes(ci)
            if loc is None:
                continue
            buf, coff = loc
            user_off = coff + 16
            end = min(len(buf), coff + 16 + self.ct.usable_size(ci))
            body = buf[user_off:end]
            scanned += len(body)

            def _ctx(a=a):
                root = self._new_root(_Root(kind=KIND_HEAP_CONS, name="inside chunk 0x%x" % (a + 16)))
                pci = self.ct.index_of_chunk(a)
                parent = self._best_ref(pci) if pci is not None else None
                if parent and parent[0] >= 0:
                    return root, self._new_node(parent[0], parent[1], root)
                if parent and 0 <= parent[2] < len(self.roots):
                    return root, self._new_node(-1, "(chunk 0x%x via %s)" % (a + 16, self.roots[parent[2]].name), root)
                return root, self._new_node(-1, "(chunk 0x%x)" % (a + 16), root)
            for nci in self._conservative_region(_ctx, a + 16, body, prefixes, suffix_fmt="->[+0x%x]"):
                work.append(self.ct.addrs[nci])
        self.stats["conservative_heap_bytes_scanned"] = scanned

    def _best_ref(self, ci: int) -> Optional[Tuple[int, str, int]]:
        lst = self.refs.get(ci)
        if not lst:
            return None
        node, suffix, root, _slot, _interior = lst[0]
        return node, suffix, root

    # ------------------------------------------------------------------ run / results
    def prepare(self) -> None:
        self._addr_of_index = list(self.ct.addrs)

    def referrers(self, ci: int) -> List[Dict[str, Any]]:
        out = []
        for node, suffix, root, slot, interior in self.refs.get(ci, []):
            r = self.roots[root] if 0 <= root < len(self.roots) else _Root(kind=KIND_HEAP_CONS, name="?")
            d: Dict[str, Any] = {"kind": r.kind, "typed": r.kind in TYPED_KINDS, "slot_address": "0x%x" % slot,
                                 "interior_offset": int(interior)}
            if r.kind in TYPED_KINDS or (r.kind == KIND_HEAP_CONS and node >= 0):
                d["path"] = self.render(node, suffix) if node >= 0 else suffix
            if r.kind == KIND_LOCAL:
                d.update(thread=r.thread, tid=r.tid, function=r.function, variable=r.name)
                d["description"] = "thread %s, function %s, variable %s" % (r.thread, r.function, d.get("path") or r.name)
            elif r.kind == KIND_STACK_CONS:
                d.update(thread=r.thread, tid=r.tid)
                d["description"] = "referenced from stack of thread %s (conservative, no variable name)" % r.thread
            elif r.kind in (KIND_DATA_CONS, KIND_ANON_CONS):
                d["region"] = r.name
                d["description"] = "referenced from %s data (conservative, no variable name)" % r.name
            elif r.kind == KIND_HEAP_CONS:
                d["description"] = "referenced from inside %s (untyped word, conservative)" % (
                    d.get("path", r.name).rsplit("->[+", 1)[0])
            else:
                d["module"] = r.module
                d["description"] = "%s variable path %s" % (r.kind, d["path"])
            out.append(d)
        return out

    def reach_of(self, ci: int) -> str:
        return {2: REACH_TYPED, 1: REACH_CONSERVATIVE}.get(self.reach[ci], REACH_NONE)

    def leak_candidates(self) -> List[int]:
        return [ci for ci in range(len(self.ct))
                if self.reach[ci] == 0 and self.ct.states[ci] in (ST_IN_USE, ST_MMAPPED)]


# ======================================================================================
# Orchestration + reverse lookup API
# ======================================================================================
_ANALYSES: Dict[str, "HeapOwnershipAnalysis"] = {}
_ANALYSES_ORDER: List[str] = []
_MAX_CACHED = 4

DEFAULT_ANALYSIS_BUDGET = {
    "max_wall_clock_ms": 300000.0,
    "max_bytes_read": 1024 * 1024 * 1024,
    "max_samples": 1 << 30,
    "max_bytes_per_observation": 1 << 40,
    "max_consecutive_read_failures": 1 << 20,
    "max_total_read_failures": 1 << 20,
}


class HeapOwnershipAnalysis:
    """Result of one heap walk + reachability pass; answers address -> owner queries."""

    def __init__(self, pid: int, walk: HeapWalkResult, analyzer: Optional[ReachabilityAnalyzer],
                 budget: Any, reader: BudgetedReader, info: Dict[str, Any]):
        import uuid
        self.analysis_id = "heap_%s" % uuid.uuid4().hex[:12]
        self.pid = pid
        self.walk = walk
        self.analyzer = analyzer
        self.budget = budget
        self.reader = reader
        self.info = info
        self.status = walk.status
        self.message = walk.message
        if analyzer is not None and analyzer.truncated and self.status == "OK":
            self.status = "PARTIAL"
            self.message = "reachability truncated: %s" % ", ".join(analyzer.truncated)
        if info.get("reachability_error"):
            self.status = "PARTIAL"
            self.message = info["reachability_error"]

    @property
    def ok(self) -> bool:
        return self.walk.ok and self.analyzer is not None

    @property
    def leak_candidates_complete(self) -> bool:
        return self.ok and self.status == "OK"

    def summary(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "analysis_id": self.analysis_id,
            "pid": self.pid,
            "status": self.status,
            "message": self.message,
            "allocator": "glibc_ptmalloc",
            "heap_walk": self.walk.summary(),
            "target_stop_ms": 0.0,
            "signals_sent": 0,
        }
        out.update(self.info)
        if self.analyzer is not None:
            an = self.analyzer
            reach = {REACH_TYPED: 0, REACH_CONSERVATIVE: 0, REACH_NONE: 0}
            for ci in range(len(an.ct)):
                if an.ct.states[ci] in (ST_IN_USE, ST_MMAPPED):
                    reach[an.reach_of(ci)] += 1
            out["reachability"] = {
                "in_use_chunks_by_reach": reach,
                "leak_candidates": reach[REACH_NONE],
                "leak_candidates_complete": self.leak_candidates_complete,
                "typed_nodes": len(an.node_suffix),
                "typed_edges": an.edges,
                "roots": self._root_counts(),
                "truncated": list(an.truncated),
                **an.stats,
            }
        metrics = self.budget.to_dict().get("metrics", {})
        out["cost"] = {
            "bytes_read": self.reader.bytes_read,
            "read_batches": self.reader.batches,
            "slices_read": self.reader.slices_read,
            "budget_bytes_charged": metrics.get("bytes_read"),
            "budget_target_stop_ms": metrics.get("target_stop_duration_ms"),
            "wall_ms": self.info.get("wall_ms"),
        }
        return out

    def _root_counts(self) -> Dict[str, int]:
        c: Dict[str, int] = {}
        for r in self.analyzer.roots:
            c[r.kind] = c.get(r.kind, 0) + 1
        return c

    def lookup(self, address: int) -> Dict[str, Any]:
        """Reverse lookup: address -> containing chunk, size, state and the referencing paths."""
        address = int(address)
        res: Dict[str, Any] = {"address": "0x%x" % address}
        if not self.ok:
            res.update(status=self.status, message=self.message)
            return res
        an = self.analyzer
        ct = an.ct
        ci = ct.find_containing(address, user_only=False)
        if ci is None and (address & 0xFFF) >= 0x10:
            # maybe an mmapped chunk not seen yet: probe its page-aligned header
            if an.walker.probe_mmapped([(address & ~0xFFF) + 0x10]):
                an._grow()
                ci = ct.find_containing(address, user_only=False)
        if ci is None:
            res["in_heap"] = False
            res["status"] = "NOT_IN_A_HEAP_CHUNK"
            for m in self.walk.mappings:
                s, e = _map_bounds(m)
                if s <= address < e:
                    res["mapping"] = {"start": "0x%x" % s, "end": "0x%x" % e, "permissions": m.get("permissions"),
                                      "pathname": m.get("pathname") or ""}
                    break
            return res
        user = ct.addrs[ci] + 16
        res.update(in_heap=True, status="FOUND", chunk=ct.chunk_dict(ci), offset_in_block=address - user)
        if address < user:
            res["note"] = "address is inside the chunk header (not a user pointer)"
        st = ct.states[ci]
        res["reachability"] = an.reach_of(ci) if st in IN_USE_STATES else None
        res["referrers"] = an.referrers(ci)
        res["referrer_count"] = an.ref_counts.get(ci, 0)
        res["leak_candidate"] = st in (ST_IN_USE, ST_MMAPPED) and an.reach[ci] == 0
        if res["leak_candidate"]:
            res["classification"] = "no reachable path (leak candidate)"
        elif st not in IN_USE_STATES:
            res["classification"] = "free block (%s)" % STATE_NAMES[st]
        elif st == ST_INTERNAL:
            res["classification"] = "allocator internal (tcache_perthread_struct)"
        elif an.reach[ci] == 2:
            res["classification"] = "owned by typed path"
        else:
            res["classification"] = "reachable only through untyped / conservative references"
        return res

    def leak_report(self, max_examples_per_class: int = 8, max_classes: int = 64) -> Dict[str, Any]:
        if not self.ok:
            return {"status": self.status, "message": self.message, "leak_candidates": None}
        an = self.analyzer
        ct = an.ct
        groups: Dict[int, Dict[str, Any]] = {}
        cands = an.leak_candidates()
        for ci in cands:
            sz = int(ct.sizes[ci])
            g = groups.setdefault(sz, {"chunk_size": sz, "usable_size": ct.usable_size(ci), "count": 0,
                                       "total_bytes": 0, "examples": []})
            g["count"] += 1
            g["total_bytes"] += sz
            if len(g["examples"]) < max_examples_per_class:
                g["examples"].append({"user_address": "0x%x" % (ct.addrs[ci] + 16),
                                      "state": STATE_NAMES[ct.states[ci]], "arena_index": int(ct.arena[ci])})
        ordered = sorted(groups.values(), key=lambda g: -g["total_bytes"])[:max_classes]
        return {
            "status": self.status,
            "message": self.message,
            "leak_candidates_complete": self.leak_candidates_complete,
            "definition": "in-use chunk reached by no root (typed globals/statics/locals, conservative stacks, "
                          "module data, anonymous mappings, or contents of reachable chunks)",
            "total_candidates": len(cands),
            "total_bytes": sum(int(ct.sizes[ci]) for ci in cands),
            "by_size_class": ordered,
        }

    def leak_candidate_addresses(self) -> List[int]:
        if not self.ok:
            return []
        return [self.analyzer.ct.addrs[ci] + 16 for ci in self.analyzer.leak_candidates()]


def _module_contexts(adapter: Any, pid: int, companion_elf_path: Optional[str], manager: Any,
                     maps: List[Dict[str, Any]]) -> List[Tuple[str, Any, int, bool]]:
    """(module, DwarfIndex, load bias, is_dyn) for the main executable first, then extra modules."""
    from .dwarf_indexer import DwarfIndexer
    if not companion_elf_path:
        return []
    if manager is not None:
        md = manager._get_process_maps_and_load_bias(pid=pid, companion_elf_path=companion_elf_path, adapter=adapter)
        mods = list(md.get("loaded_debug_modules") or [])
    else:
        from .debug_image import inspect_elf
        from .watch_session import calculate_load_bias
        primary = str(companion_elf_path).split(",")[0].strip()
        bias = calculate_load_bias(inspect_elf(primary), adapter.get_process_identity(pid), maps)["load_bias"]
        mods = [{"module": os.path.basename(primary), "debug_image": os.path.abspath(primary),
                 "load_bias_int": bias, "is_main_executable": True}]
    mods.sort(key=lambda m: 0 if m.get("is_main_executable") else 1)
    out = []
    for m in mods:
        try:
            idx = DwarfIndexer.get_index(m["debug_image"])
        except Exception:  # noqa: BLE001
            continue
        out.append((m.get("module") or os.path.basename(m["debug_image"]), idx, int(m.get("load_bias_int") or 0),
                    idx.elf_type == "ET_DYN"))
    return out


def build_reachability(walk: HeapWalkResult, walker: HeapWalker, reader: BudgetedReader, adapter: Any, pid: int,
                       companion_elf_path: Optional[str], manager: Any, include_typed_locals: bool,
                       limits: Optional[ReachabilityLimits], info: Dict[str, Any]) -> Optional[ReachabilityAnalyzer]:
    """Reverse reference map over an existing walk (roots: globals/statics, typed locals, conservative).
    Fills ``info`` (root sources / reachability_error).  Split out of :func:`analyze_heap_ownership` so a caller
    can walk first and pay for reachability only when it needs owner names (IMP-009 baseline integrity walk)."""
    analyzer: Optional[ReachabilityAnalyzer] = None
    try:
        modules = _module_contexts(adapter, pid, companion_elf_path, manager, walk.mappings)
        info["typed_modules"] = [m[0] for m in modules]
        analyzer = ReachabilityAnalyzer(walk, walker, reader, modules, limits=limits)
        analyzer.prepare()
        if modules:
            info["root_sources"]["globals_statics"] = analyzer.add_global_roots()
        else:
            info["root_sources"]["globals_statics"] = "no companion ELF with DWARF: no typed global roots"
        before = adapter.cumulative_physical_bytes_read
        threads = adapter.get_threads(pid) or []
        reader.account_external(adapter.cumulative_physical_bytes_read - before, "thread discovery")
        if include_typed_locals and manager is not None and modules:
            before = adapter.cumulative_physical_bytes_read
            try:
                frames = manager.inspect_thread_locals_and_frame_vars(
                    pid=pid, companion_elf_path=companion_elf_path, adapter=adapter, max_frames=16)
            except Exception as exc:  # noqa: BLE001
                frames = {"error": str(exc)}
            reader.account_external(adapter.cumulative_physical_bytes_read - before, "frame decoder")
            loc = analyzer.add_local_roots(frames)
            statuses = set((loc.get("decoder_status") or {}).values())
            loc["note"] = ("typed locals from the frame decoder" if "SUPPORTED" in statuses else
                           "frame-locals decoder not supported on this target (%s): stack references are "
                           "conservative (no variable names)" % ", ".join(sorted(str(s) for s in statuses)))
            info["root_sources"]["locals"] = loc
        else:
            info["root_sources"]["locals"] = "typed locals not requested / no companion ELF"
        info["root_sources"]["conservative"] = analyzer.add_conservative_roots(threads)
    except HeapWalkBudgetExhausted as exc:
        info["reachability_error"] = "observation budget exhausted during reachability: %s" % exc
    return analyzer


def analyze_heap_ownership(
    pid: int,
    companion_elf_path: Optional[str] = None,
    adapter: Any = None,
    manager: Any = None,
    budget_limits: Optional[Dict[str, Any]] = None,
    include_typed_locals: bool = True,
    use_libc_debug_info: bool = True,
    force_signature_scan: bool = False,
    limits: Optional[ReachabilityLimits] = None,
    abi: Any = None,
    cache: bool = True,
) -> HeapOwnershipAnalysis:
    """Walk the heap of ``pid`` and build the reverse reference map (zero-stop, budgeted)."""
    from .observation_budget import ObservationBudgetLimits, ObservationBudgetTracker
    if adapter is None:
        from .target_adapter import LocalTargetAdapter
        adapter = LocalTargetAdapter()
    t0 = time.monotonic()
    lim = dict(DEFAULT_ANALYSIS_BUDGET)
    lim.update(budget_limits or {})
    budget = ObservationBudgetTracker(ObservationBudgetLimits.from_dict(lim))
    reader = BudgetedReader(adapter, pid, budget)
    walker = HeapWalker(adapter, pid, budget=budget, reader=reader, abi=abi,
                        use_libc_debug_info=use_libc_debug_info, force_signature_scan=force_signature_scan)
    walk = walker.walk()
    info: Dict[str, Any] = {"companion_elf": companion_elf_path, "root_sources": {}}
    analyzer: Optional[ReachabilityAnalyzer] = None
    if walk.ok:
        analyzer = build_reachability(walk, walker, reader, adapter, pid, companion_elf_path, manager,
                                      include_typed_locals, limits, info)
    info["wall_ms"] = round((time.monotonic() - t0) * 1000.0, 2)
    an = HeapOwnershipAnalysis(pid, walk, analyzer, budget, reader, info)
    if cache:
        _ANALYSES[an.analysis_id] = an
        _ANALYSES_ORDER.append(an.analysis_id)
        while len(_ANALYSES_ORDER) > _MAX_CACHED:
            _ANALYSES.pop(_ANALYSES_ORDER.pop(0), None)
    return an


def get_cached_analysis(analysis_id: Optional[str]) -> Optional[HeapOwnershipAnalysis]:
    return _ANALYSES.get(analysis_id or "")

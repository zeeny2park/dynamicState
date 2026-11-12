"""IMP-009 (1): glibc heap metadata integrity - which buffer overflowed, named by its owning variable.

Works on an IMP-007 walk (:class:`~extractor.heap_walker.HeapWalkResult` + its snapshot) of a RUNNING process;
every extra byte is read through the walk's zero-stop, budgeted reader.  No signal, no ptrace.

Checks (all on metadata glibc keeps consistent at rest)
------------------------------------------------------
* ``chunk_header_damaged``  - a header whose size field is impossible (misaligned, below MINSIZE, beyond the
  segment, IS_MMAPPED inside an arena): the walker's hard inconsistency after its re-reads.
* ``top_chunk_damaged``     - the arena's top chunk size misaligned / beyond its segment / flag bits impossible.
* ``free_chunk_link_damaged`` - a free chunk in a regular bin whose ``fd``/``bk`` do not form the double link
  glibc maintains (``fd->bk == p`` and ``bk->fd == p``), or whose size disagrees with the next ``prev_size``.
* ``tcache_pointer_damaged`` / ``fastbin_pointer_damaged`` - a singly-linked free-list pointer that after
  safe-linking demangling is misaligned or points outside every heap segment.

Stable versus transient
-----------------------
The target keeps running, so an inconsistent copy can be a torn read.  A candidate is corruption evidence only
when (a) every read attempt of the walker hit it at the same address, and (b) ``stability_reads`` further reads
of its metadata windows (previous header, damaged header, list pointers, arena ``top`` slot), separated by
``stability_interval_s``, return bytes identical to the walk's copy, and (c) the owning arena's mutex was free in
those reads (an arena mid-operation is not at rest; up to ``extra_reads_when_locked`` further reads are made).
Anything else is reported as ``inconsistent read, not evidence``.

Attribution
-----------
A linear overflow runs from lower to higher addresses, so the chunk immediately BEFORE a damaged header is the
likely overflowing buffer: its owner path(s) come from the reverse reference map (IMP-007), with its usable size
and how far the damage extends (bytes after its usable end that continue the same content: a repeated byte or
printable text).  The damaged chunk's own owners are reported as the victim.

Limits (what metadata cannot show)
----------------------------------
An overrun that stays inside the chunk's usable slack (malloc(24) has 24 usable bytes on LP64, malloc(20) has
24 too) or that only rewrites the NEXT chunk's user data without reaching its header is invisible from
metadata; so is any overflow of a non-heap buffer.  A write that restores a plausible size value is not
recognised.  Only glibc ptmalloc (see :mod:`extractor.heap_walker` support gating) is understood.
"""

import struct
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .heap_walker import (
    IS_MMAPPED,
    NON_MAIN_ARENA,
    PREV_INUSE,
    SIZE_BITS,
    ST_FASTBIN,
    ST_FREE,
    ST_IN_USE,
    ST_INTERNAL,
    ST_MMAPPED,
    ST_TCACHE,
    ST_TOP,
    STATE_NAMES,
    HeapWalkBudgetExhausted,
)

STATUS_CONFIRMED = "confirmed"
STATUS_PROBABLE = "probable"

KIND_HEADER = "chunk_header_damaged"
KIND_TOP = "top_chunk_damaged"
KIND_FREE_LINK = "free_chunk_link_damaged"
KIND_TCACHE = "tcache_pointer_damaged"
KIND_FASTBIN = "fastbin_pointer_damaged"
KIND_UNDERSIZED = "undersized_allocation_for_type"

_HARD_REASONS = ("invalid chunk size", "runs past segment end", "IS_MMAPPED set", "chunk header beyond segment")


def _u64(b: bytes, off: int = 0) -> int:
    return struct.unpack_from("<Q", b, off)[0]


def _printable(b: bytes) -> bool:
    return bool(b) and all(0x20 <= c < 0x7f for c in b)


def _pattern(b: Optional[bytes]) -> Optional[str]:
    if not b:
        return None
    if b[0] != 0 and b.count(b[0]) == len(b):
        return "repeated byte 0x%02x" % b[0]
    if _printable(b):
        return "printable text"
    return None


def _continuation(tail: Optional[bytes], hdr: Optional[bytes]) -> Tuple[Optional[str], bool]:
    """(content pattern of the bytes written over the size field, whether the previous chunk's last usable bytes
    carry the same pattern - the signature of one linear overrun)."""
    p = _pattern(hdr)
    if p is None:
        return None, False
    t = _pattern(tail)
    same = t is not None and (t == p if p.startswith("repeated") else t == "printable text")
    return p, same


def _extent(data: Optional[bytes], pattern: Optional[str]) -> Optional[int]:
    """Bytes from the usable end on that continue ``pattern`` (lower bound of how far the overrun reached)."""
    if not data or not pattern:
        return None
    if pattern.startswith("repeated byte"):
        b = data[0]
        n = 0
        while n < len(data) and data[n] == b:
            n += 1
        return n
    n = 0
    while n < len(data) and 0x20 <= data[n] < 0x7f:
        n += 1
    if n < len(data) and data[n] == 0:
        n += 1                       # the string terminator was written too
    return n


class _Candidate:
    __slots__ = ("kind", "at", "arena", "windows", "info", "prev", "victim", "status", "stable_reads",
                 "why_not")

    def __init__(self, kind: str, at: int, arena: int, windows: List[Tuple[int, int]], info: Dict[str, Any],
                 prev: Optional[int] = None, victim: Optional[int] = None) -> None:
        self.kind = kind
        self.at = at
        self.arena = arena
        self.windows = windows
        self.info = info
        self.prev = prev            # chunk address of the likely overflowing chunk
        self.victim = victim        # chunk address of the damaged chunk
        self.status: Optional[str] = None
        self.stable_reads = 0
        self.why_not: Optional[str] = None


class HeapIntegrityChecker:
    """Find stable metadata damage in a heap walk and attribute it (see module docstring)."""

    def __init__(self, walk: Any, walker: Any, reader: Any, stability_reads: int = 2,
                 stability_interval_s: float = 0.03, extra_reads_when_locked: int = 3,
                 sleep: Callable[[float], None] = time.sleep, max_list_len: int = 1 << 16) -> None:
        self.walk = walk
        self.walker = walker
        self.reader = reader
        self.layout = getattr(walker, "_layout", None) or walk.layout
        self.arena_addrs: List[int] = list(getattr(walker, "_arena_addrs", []) or [])
        self.stability_reads = max(1, int(stability_reads))
        self.stability_interval_s = float(stability_interval_s)
        self.extra_reads_when_locked = int(extra_reads_when_locked)
        self.sleep = sleep
        self.max_list_len = max_list_len
        self.candidates: List[_Candidate] = []
        self.transient: List[Dict[str, Any]] = []
        self.checked: Dict[str, int] = {}

    # ------------------------------------------------------------------ helpers
    def _seg_of(self, addr: int) -> Optional[Tuple[int, int]]:
        for s, e in self.walk.heap_ranges:
            if s <= addr < e:
                return s, e
        return None

    def _in_heap(self, addr: int) -> bool:
        return self._seg_of(addr) is not None

    def _chunk_ending_at(self, addr: int) -> Optional[int]:
        ct = self.walk.chunks
        i = ct.find_containing(addr - 1, user_only=False)
        if i is not None and ct.addrs[i] + ct.sizes[i] == addr:
            return int(ct.addrs[i])
        return None

    # ------------------------------------------------------------------ detection
    def detect(self) -> None:
        if self.layout is None:
            return
        self._detect_hard_headers()
        self._detect_top()
        self._detect_regular_bins()
        self._detect_tcache()
        self._detect_fastbins()

    def _detect_hard_headers(self) -> None:
        n = 0
        for inc in self.walk.inconsistencies:
            reason = str(inc.get("reason") or "")
            at = inc.get("at")
            if at is None or not any(r in reason for r in _HARD_REASONS):
                continue
            n += 1
            x = int(str(at), 16)
            sites = inc.get("attempt_sites") or [at]
            info = {"reason": reason, "read_attempts": len(sites)}
            prev = int(str(inc["previous_chunk"]), 16) if inc.get("previous_chunk") else None
            if len(set(sites)) > 1:
                self.transient.append({"kind": KIND_HEADER, "at": at, "reason": reason,
                                       "why": "the inconsistency moved between the walker's re-reads (%s)"
                                              % ", ".join(sites)})
                continue
            wins = [(x, 16)] + ([(prev, 16)] if prev is not None else [])
            hdr = self.walk.snapshot.get(x, 16)
            if hdr is not None:
                info["observed_size_field"] = "0x%x" % _u64(hdr, 8)
                info["observed_prev_size_field"] = "0x%x" % _u64(hdr, 0)
            self.candidates.append(_Candidate(KIND_HEADER, x, int(inc.get("arena") or 0), wins, info,
                                              prev=prev, victim=x))
        self.checked["hard_header_inconsistencies"] = n

    def _detect_top(self) -> None:
        lay = self.layout
        ct = self.walk.chunks
        n = 0
        for ai, info in enumerate(self.walk.arenas):
            try:
                top = int(str(info.get("top")), 16)
            except (TypeError, ValueError):
                continue
            ti = ct.index_of_chunk(top)
            if ti is None or ct.states[ti] != ST_TOP:
                continue
            hdr = self.walk.snapshot.get(top, 16)
            seg = self._seg_of(top)
            if hdr is None or seg is None:
                continue
            n += 1
            sf = _u64(hdr, 8)
            size = sf & ~SIZE_BITS
            why = []
            if size % lay.malloc_alignment:
                why.append("size 0x%x is not a multiple of %d" % (size, lay.malloc_alignment))
            if size < 16:
                why.append("size 0x%x below the minimum" % size)
            if top + size > seg[1]:
                why.append("size 0x%x runs %d bytes past the end of its heap segment" % (size, top + size - seg[1]))
            if sf & IS_MMAPPED:
                why.append("IS_MMAPPED flag set on the top chunk")
            if ai == 0 and sf & NON_MAIN_ARENA:
                why.append("NON_MAIN_ARENA flag set on the main arena's top chunk")
            if not why:
                continue
            prev = self._chunk_ending_at(top)
            a = self.arena_addrs[ai] if ai < len(self.arena_addrs) else None
            wins = [(top, 16)] + ([(prev, 16)] if prev is not None else []) + \
                ([(a + lay.ms["top"], 8)] if a is not None else [])
            self.candidates.append(_Candidate(KIND_TOP, top, ai, wins,
                                              {"reason": "top chunk " + "; ".join(why),
                                               "observed_size_field": "0x%x" % sf,
                                               "observed_prev_size_field": "0x%x" % _u64(hdr, 0)},
                                              prev=prev, victim=top))
        self.checked["top_chunks"] = n

    def _detect_regular_bins(self) -> None:
        """Free chunks in regular bins: double links and the boundary tag of the next chunk."""
        lay = self.layout
        ct = self.walk.chunks
        snap = self.walk.snapshot
        bin_lo_hi = []
        for a in self.arena_addrs:
            bin_lo_hi.append((a + lay.ms["bins"] - 16, a + lay.ms["bins"] + 254 * 8))
        damaged = {c.victim for c in self.candidates if c.kind in (KIND_HEADER, KIND_TOP) and c.victim is not None}
        n = 0
        for i in range(len(ct)):
            if ct.states[i] != ST_FREE or int(ct.arena[i]) < 0:
                continue
            p = int(ct.addrs[i])
            size = int(ct.sizes[i])
            if p in damaged or p + size in damaged:
                # a damaged header itself, or a chunk whose "free" state comes from the damaged header after it
                continue
            body = snap.get(p, 32)
            nxt = snap.get(p + size, 16)
            if body is None:
                continue
            n += 1
            fd, bk = _u64(body, 16), _u64(body, 24)
            why = []

            def ok_link(v: int, back: bool) -> bool:
                # a link points to a free chunk of a walked heap or to a bin head inside an arena struct
                if any(lo <= v < hi for lo, hi in bin_lo_hi):
                    other = snap.u64(v + (16 if back else 24))
                    return other is None or other == p
                j = ct.index_of_chunk(v)
                if j is None:
                    return False
                other = snap.u64(v + (16 if back else 24))
                return other is None or other == p
            if fd % 16 or not ok_link(fd, back=False):
                why.append("fd 0x%x is not a free chunk / bin whose bk points back" % fd)
            if bk % 16 or not ok_link(bk, back=True):
                why.append("bk 0x%x is not a free chunk / bin whose fd points back" % bk)
            if nxt is not None and _u64(nxt, 0) != size and not (_u64(nxt, 8) & PREV_INUSE):
                why.append("next chunk's prev_size 0x%x differs from this free chunk's size 0x%x" % (_u64(nxt, 0), size))
            if not why:
                continue
            prev = self._chunk_ending_at(p)
            # every byte the verdict depended on: this chunk's header and links, the back links read at fd / bk,
            # the next boundary tag and the previous header
            wins = [(p, 32)] + ([(p + size, 16)] if nxt is not None else []) + ([(prev, 16)] if prev else []) + \
                [(v + o, 8) for v, o in ((fd, 24), (bk, 16)) if snap.get(v + o, 8) is not None]
            self.candidates.append(_Candidate(KIND_FREE_LINK, p, int(ct.arena[i]), wins,
                                              {"reason": "free chunk " + "; ".join(why), "fd": "0x%x" % fd,
                                               "bk": "0x%x" % bk}, prev=prev, victim=p))
        self.checked["free_chunks_in_bins"] = n

    def _demangle(self, slot: int, val: int) -> int:
        return ((slot >> 12) ^ val) if self.layout.safe_linking else val

    def _bad_list_pointer(self, ptr: int, want_size: int) -> Optional[str]:
        if ptr % self.layout.malloc_alignment:
            return "misaligned (0x%x)" % ptr
        if not self._in_heap(ptr - 16):
            return "points outside every heap segment (0x%x)" % ptr
        return None

    def _list_member(self, chunk: int, want: int) -> bool:
        """A free-list entry must be a walked chunk of the bin's size (or the damaged region starting there)."""
        ct = self.walk.chunks
        i = ct.index_of_chunk(chunk)
        if i is None:
            return False
        if int(ct.sizes[i]) == want:
            return True
        return any(int(str(d.get("at")), 16) == chunk for d in self.walk.damaged_regions)

    def _detect_tcache(self) -> None:
        lay = self.layout
        ct = self.walk.chunks
        snap = self.walk.snapshot
        width = lay.tcache_count_width
        cfmt = "<%d%s" % (lay.tcache_bins, "H" if width == 2 else "B")
        structs = set()
        for t in self.walk.tcache_structs:
            structs.add(int(str(t["address"]), 16))
        # the first chunk of each arena segment, if it has the tcache struct size and failed the walker's
        # validation (a damaged list makes the walker leave it unmarked)
        for a in self.walk.arenas:
            for seg in a.get("segments", []):
                fc = int(str(seg["first_chunk"]), 16)
                i = ct.index_of_chunk(fc)
                if i is not None and ct.sizes[i] == lay.tcache_chunk_size and ct.states[i] in (ST_IN_USE, ST_INTERNAL):
                    structs.add(fc + 16)
        n = 0
        for user in sorted(structs):
            body = snap.get(user, lay.tcache_struct_size)
            if body is None:
                continue
            counts = struct.unpack_from(cfmt, body, 0)
            entries = struct.unpack_from("<%dQ" % lay.tcache_bins, body, lay.tcache_entries_off)
            if any(c > 0xffff for c in counts) or sum(1 for c, e in zip(counts, entries) if (c == 0) != (e == 0)) > 2:
                continue                       # not a tcache struct (or a torn copy): no claim
            n += 1
            for b in range(lay.tcache_bins):
                c, e = counts[b], entries[b]
                if not c or not e:
                    continue
                want = lay.min_chunk + b * lay.malloc_alignment
                slot = user + lay.tcache_entries_off + 8 * b
                # every byte the list walk depended on: the bin's count and head, then each entry's next slot
                path = [(user + b * width, width), (slot, 8)]
                cur, prev_cur = e, None
                for k in range(min(int(c), self.max_list_len) + 1):   # +1: the last entry's next must be NULL
                    bad = self._bad_list_pointer(cur, want)
                    if bad is not None:
                        src = ("tcache bin %d head" % b) if prev_cur is None else \
                            ("next pointer of free chunk 0x%x (entry %d of tcache bin %d)" % (prev_cur - 16, k - 1, b))
                        victim = prev_cur - 16 if prev_cur is not None else None
                        wslot = slot if prev_cur is None else prev_cur
                        prev = self._chunk_ending_at(victim) if victim is not None else None
                        wins = path + ([(victim, 16)] if victim is not None else []) + ([(prev, 16)] if prev else [])
                        raw = snap.u64(wslot)
                        ui = ct.index_of_user(user)
                        self.candidates.append(_Candidate(
                            KIND_TCACHE, wslot, int(ct.arena[ui]) if ui is not None else 0,
                            wins, {"reason": "%s %s" % (src, bad), "bin_chunk_size": want,
                                   "raw_pointer": "0x%x" % (raw or 0),
                                   "safe_linking": bool(lay.safe_linking)}, prev=prev, victim=victim))
                        break
                    if not self._list_member(cur - 16, want):
                        break                  # the copy of the list disagrees with the walk (torn): no claim
                    raw = snap.u64(cur)
                    if raw is None:
                        break
                    path.append((cur, 8))
                    prev_cur = cur
                    cur = self._demangle(cur, raw)
                    if cur == 0:
                        break
        self.checked["tcache_structs"] = n

    def _detect_fastbins(self) -> None:
        lay = self.layout
        ct = self.walk.chunks
        snap = self.walk.snapshot
        n = 0
        for ai, a in enumerate(self.arena_addrs):
            for b in range(lay.nfastbins):
                slot = a + lay.ms["fastbinsY"] + 8 * b
                p = snap.u64(slot)
                if not p:
                    continue
                n += 1
                want = lay.min_chunk + b * lay.malloc_alignment
                prev_p = None
                seen = set()
                path = [(slot, 8)]
                while p and p not in seen and len(seen) < self.max_list_len:
                    seen.add(p)
                    bad = self._bad_list_pointer(p + 16, want)
                    if bad is not None:
                        wslot = slot if prev_p is None else prev_p + 16
                        victim = prev_p
                        prev = self._chunk_ending_at(victim) if victim is not None else None
                        wins = path + ([(victim, 16)] if victim is not None else []) + ([(prev, 16)] if prev else [])
                        src = ("fastbin %d head of arena %d" % (b, ai)) if prev_p is None else \
                            ("fd of free chunk 0x%x in fastbin %d" % (prev_p, b))
                        self.candidates.append(_Candidate(KIND_FASTBIN, wslot, ai, wins,
                                                          {"reason": "%s %s" % (src, bad), "bin_chunk_size": want},
                                                          prev=prev, victim=victim))
                        break
                    if not self._list_member(p, want):
                        break
                    raw = snap.u64(p + 16)
                    if raw is None:
                        break
                    path.append((p + 16, 8))
                    prev_p = p
                    p = self._demangle(p + 16, raw)
        self.checked["fastbin_lists"] = n

    # ------------------------------------------------------------------ stability
    def confirm_stability(self) -> None:
        """Re-read every candidate's windows (plus each arena's mutex) ``stability_reads`` times."""
        if not self.candidates:
            return
        lay = self.layout
        mutexes = [(a + lay.ms["mutex"], 4) for a in self.arena_addrs]
        expected = []
        for c in self.candidates:
            exp = [self.walk.snapshot.get(a, n) for a, n in c.windows]
            expected.append(exp)
            if any(e is None for e in exp):
                c.why_not = "the walk holds no copy of the candidate's metadata"
        ranges = [w for c in self.candidates for w in c.windows] + mutexes
        locked = [0] * len(self.candidates)
        reads = 0
        max_reads = self.stability_reads + self.extra_reads_when_locked
        while reads < max_reads:
            self.sleep(self.stability_interval_s)
            try:
                datas = self.reader.read_ranges(ranges)
            except HeapWalkBudgetExhausted as exc:
                for c in self.candidates:
                    c.why_not = c.why_not or "observation budget exhausted before the re-reads: %s" % exc
                return
            reads += 1
            mx = datas[len(ranges) - len(mutexes):]
            k = 0
            pending_lock = False
            for ci, c in enumerate(self.candidates):
                got = datas[k:k + len(c.windows)]
                k += len(c.windows)
                if c.why_not:
                    continue
                if any(g != e for g, e in zip(got, expected[ci])):
                    c.why_not = ("metadata bytes changed between reads %.0f ms apart (target mutating the heap): "
                                 "inconsistent read, not evidence" % (self.stability_interval_s * 1000))
                    continue
                m = mx[c.arena] if c.arena < len(mx) else None
                if c.kind != KIND_TCACHE and m is not None and len(m) == 4 and struct.unpack("<i", m)[0] != 0:
                    locked[ci] += 1
                    pending_lock = True
                    continue
                c.stable_reads += 1
            done = all(c.why_not or c.stable_reads >= self.stability_reads for c in self.candidates)
            if done or (reads >= self.stability_reads and not pending_lock):
                break
        for ci, c in enumerate(self.candidates):
            if not c.why_not and c.stable_reads < self.stability_reads:
                c.why_not = ("arena %d was locked (mid-operation) in %d of %d re-reads: not at rest, "
                             "inconsistent read, not evidence" % (c.arena, locked[ci], reads))
        self.checked["stability_reads"] = reads

    # ------------------------------------------------------------------ attribution
    @staticmethod
    def owner_of(analyzer: Any, chunk_addr: Optional[int]) -> Dict[str, Any]:
        """{variable, variable_path, owner_kind, owners[]} of the chunk at ``chunk_addr`` (typed referrers first)."""
        out: Dict[str, Any] = {}
        if analyzer is None or chunk_addr is None:
            return {"owner_unknown": "no reverse reference map (reachability not run)"}
        ci = analyzer.ct.index_of_chunk(chunk_addr)
        if ci is None:
            return {"owner_unknown": "chunk not in the walked chunk table"}
        typed, other = [], []
        for node, suffix, root, slot, interior in analyzer.refs.get(ci, []):
            r = analyzer.roots[root] if 0 <= root < len(analyzer.roots) else None
            if r is None:
                continue
            if r.kind in ("global", "static", "local"):
                path = analyzer.render(node, suffix) if node >= 0 else suffix
                typed.append({"owner_kind": r.kind, "root_variable": r.name, "path": path,
                              "interior_offset": int(interior),
                              **({"function": r.function, "thread": r.thread} if r.kind == "local" else {})})
            else:
                other.append({"owner_kind": r.kind, "description": r.name,
                              **({"referencing_thread": r.thread} if r.thread else {})})
        if typed:
            out["variable"] = typed[0]["root_variable"]
            out["variable_path"] = typed[0]["path"]
            out["owner_kind"] = typed[0]["owner_kind"]
            out["owners"] = [{"variable": t["root_variable"], "variable_path": t["path"],
                              "owner_kind": t["owner_kind"]} for t in typed[:4]]
        elif other:
            out["owner_unknown"] = "referenced only untyped (%s): no variable name" % other[0]["description"]
            out["untyped_referrers"] = other[:4]
        else:
            out["owner_unknown"] = "no reference to this block was found"
        return out

    def attribute(self, analyzer: Any) -> List[Dict[str, Any]]:
        ct = self.walk.chunks
        snap = self.walk.snapshot
        defects: List[Dict[str, Any]] = []
        for c in self.candidates:
            if c.why_not:
                self.transient.append({"kind": c.kind, "at": "0x%x" % c.at, "reason": c.info.get("reason"),
                                       "why": c.why_not})
                continue
            d: Dict[str, Any] = {"kind": c.kind, "at": "0x%x" % c.at, "arena_index": c.arena,
                                 "reason": c.info.get("reason"), "stable": True,
                                 "stable_rereads": c.stable_reads,
                                 "details": {k: v for k, v in c.info.items() if k != "reason"}}
            impossible = c.kind in (KIND_HEADER, KIND_TOP)
            pattern = None
            if c.prev is not None:
                pi = ct.index_of_chunk(c.prev)
                usable = ct.usable_size(pi) if pi is not None else None
                usable_end = c.prev + 16 + usable if usable is not None else None
                buf = {"chunk_address": "0x%x" % c.prev, "user_address": "0x%x" % (c.prev + 16),
                       "usable_size": usable, "state": STATE_NAMES.get(ct.states[pi]) if pi is not None else None}
                buf.update(self.owner_of(analyzer, c.prev))
                if c.kind in (KIND_HEADER, KIND_TOP) and usable_end is not None and c.victim is not None:
                    tail = snap.get(c.victim, 8)            # last 8 usable bytes of the previous chunk
                    szf = snap.get(c.victim + 8, 8)
                    pattern, contiguous = _continuation(tail, szf)
                    after = None
                    for n in (4096, 1024, 256, 64, 16, 8):
                        after = snap.get(usable_end, n)
                        if after is not None:
                            break
                    ext = _extent(after, pattern)
                    d["damage"] = {"usable_end": "0x%x" % usable_end,
                                   "bytes_past_usable_end": ext if ext is not None else 8,
                                   "extent_basis": ("%s written over the size field and beyond" % pattern
                                                    + ("; the buffer's last usable bytes hold the same pattern"
                                                       if contiguous else "")) if pattern else
                                   "at least the 8-byte size field (content pattern not recognised)",
                                   "pattern": pattern, "continues_buffer_content": contiguous}
                d["overflowing_buffer"] = buf
            else:
                d["overflowing_buffer"] = {"owner_unknown": "no chunk ends right before the damaged metadata"}
            if c.victim is not None:
                vi = ct.index_of_chunk(c.victim)
                vic = {"chunk_address": "0x%x" % c.victim,
                       "state": STATE_NAMES.get(ct.states[vi]) if vi is not None else None}
                if c.kind == KIND_TOP:
                    vic["description"] = "top chunk of arena %d (unallocated, no owner)" % c.arena
                else:
                    vic.update(self.owner_of(analyzer, c.victim))
                d["victim"] = vic
            named = bool(d["overflowing_buffer"].get("variable"))
            if c.kind in (KIND_HEADER, KIND_TOP) and named and (impossible or pattern):
                d["status"] = STATUS_CONFIRMED
            else:
                d["status"] = STATUS_PROBABLE
            d["description"] = self._describe(d)
            defects.append(d)
        return defects

    @staticmethod
    def _describe(d: Dict[str, Any]) -> str:
        buf = d.get("overflowing_buffer") or {}
        who = buf.get("variable_path") or buf.get("variable")
        what = {"chunk_header_damaged": "heap chunk header damaged",
                "top_chunk_damaged": "top chunk header damaged",
                "free_chunk_link_damaged": "free chunk links damaged",
                "tcache_pointer_damaged": "tcache free-list pointer damaged",
                "fastbin_pointer_damaged": "fastbin free-list pointer damaged"}.get(d["kind"], d["kind"])
        s = "%s at %s (%s), stable across %d re-reads" % (what, d["at"], d.get("reason"), d.get("stable_rereads", 0))
        if d["kind"] in (KIND_HEADER, KIND_TOP):
            if who:
                s += "; overflowing buffer: %s (block %s, usable %s bytes)" % (who, buf.get("user_address"),
                                                                              buf.get("usable_size"))
            else:
                s += "; overflowing buffer: owner unknown (%s)" % buf.get("owner_unknown", "no owner found")
            dmg = d.get("damage") or {}
            if dmg:
                s += "; the write reached %s bytes past its usable end (%s)" % (dmg.get("bytes_past_usable_end"),
                                                                                dmg.get("extent_basis"))
        else:
            if who:
                s += "; the chunk before it belongs to %s" % who
            s += "; a use-after-free write through a dangling pointer or an overflow of the previous chunk"
        vic = d.get("victim") or {}
        if vic.get("variable_path"):
            s += "; damaged block belongs to %s" % vic["variable_path"]
        elif vic.get("description"):
            s += "; damaged: %s" % vic["description"]
        return s


def undersized_allocations(analyzer: Any, max_reports: int = 16) -> List[Dict[str, Any]]:
    """Blocks reached by a typed ``struct T *`` at offset 0 whose usable size is below ``sizeof(T)``.

    No check for ``void*`` / ``char*`` / scalar pointees (no type), for structs whose last member is an array of
    0 or 1 elements (flexible-array idiom: allocated as header + n), for blocks of a damaged region (inferred
    size) or mmapped blocks.  ``usable >= sizeof(T)`` passes even when the block holds k >= 1 elements, and a base
    class pointer to a larger derived object passes too.  Count x element-size checks from an adjacent length
    member are not made (not unambiguous from DWARF alone)."""
    out: List[Dict[str, Any]] = []
    if analyzer is None:
        return out
    ct = analyzer.ct
    damaged = set()
    for d in getattr(analyzer.walk, "damaged_regions", []) or []:
        try:
            damaged.add(int(str(d["at"]), 16))
        except (KeyError, ValueError):
            pass
    for ci, (node, suffix, root, tsize, tname, mi, die) in sorted(analyzer.typed_pointee.items()):
        if ct.states[ci] != ST_IN_USE or int(ct.addrs[ci]) in damaged:
            continue
        usable = ct.usable_size(ci)
        if usable >= tsize:
            continue
        t = analyzer._canon(mi, die)
        mems = list(getattr(t, "members", []) or [])
        if mems:
            last = analyzer._canon(mi, mems[-1].type_offset)
            if last is not None and last.tag == "DW_TAG_array_type" and int(last.array_count or 0) <= 1:
                continue
        r = analyzer.roots[root] if 0 <= root < len(analyzer.roots) else None
        if r is None or r.kind not in ("global", "static", "local"):
            continue
        path = analyzer.render(node, suffix) if node >= 0 else suffix
        out.append({"kind": KIND_UNDERSIZED, "status": STATUS_PROBABLE, "variable": r.name, "variable_path": path,
                    "type": "struct %s" % tname if tname else "anonymous struct", "type_size": tsize,
                    "usable_size": usable, "user_address": "0x%x" % (ct.addrs[ci] + 16),
                    "description": "undersized allocation for type %s (needs %d, block has %d) reached through %s: "
                                   "writing its last members overflows the block"
                                   % ("struct " + tname if tname else "anonymous struct", tsize, usable, path)})
        if len(out) >= max_reports:
            break
    return out

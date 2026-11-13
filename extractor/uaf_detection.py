"""Use-after-free detection from memory reads alone (glibc ptmalloc, running process, zero-stop).

Two complementary signals over a heap walk (:mod:`extractor.heap_walker`) and its reverse reference map
(:mod:`extractor.reachability`); every byte is read through the adapter's zero-stop batch path.

1. Dangling reference
   A TYPED pointer - a DWARF global/static, or a struct member / array element reached from one through the
   typed graph (``g_conn->rx``, ``g_sessions[1]``) - whose value points into the user area of a chunk the walker
   marks FREE (tcache, fastbin, unsorted / small / large bin).  The top chunk, slack past it and unmapped memory
   are not chunks and never count.  Conservative (untyped stack / data / heap word) hits and typed locals are
   corroboration only: a dead local still holding the value it passed to ``free()`` is the normal case.  A
   program's own pool that keeps "freed" objects on its own list holds IN-USE chunks (to glibc) and cannot
   trigger; a chunk freed and immediately re-allocated is in use again and cannot trigger either.
   The reference must be stable: re-read at every observation of the window with the same value, and the
   chunk still free (still on the same free list) each time.  Alone it is a candidate (WARNING): a dangling
   pointer is a latent bug, not proof that it is used.

2. Writes into freed memory
   Over the observation window (the walk's copy, then ``observations`` re-reads spaced over ``window_s``) the
   payload of every tracked free chunk BEYOND the allocator's metadata is hashed: the first 16 bytes of a tcache /
   fastbin entry (next pointer + tcache key) and ``fd``/``bk`` (+ ``fd_nextsize``/``bk_nextsize`` for large-bin
   sizes) of a bin chunk are skipped, and so are the last 8 usable bytes (the next chunk's ``prev_size``, which the
   allocator writes for a binned chunk).  glibc never touches that payload while the chunk stays free, so a change
   while the chunk stayed free on the SAME list (tcache / fastbin chain identical, bin chunk's size and
   neighbours' links unchanged) was written by the program.  Torn-read discipline (as IMP-009): the change must be
   seen in at least two reads (persisting or repeating), and ``reuse_probe_reads`` quick re-reads of the chunk's
   list must show it free every time (a chunk briefly re-allocated, written and freed again in between would
   otherwise look like a write while free).  Without a typed referrer this is reported only where an immediate
   re-allocation is structurally excluded: not the head of a LIFO tcache / fastbin list, not the end of a bin the
   next allocation takes, not a large-bin chunk (best fit can take any of them).

Verdict per freed chunk
   dangling typed pointer + payload written while free (stable)        -> confirmed use after free
   dangling typed pointer + stable free-list damage (IMP-009 defect)   -> confirmed use after free
   payload written while free, no typed referrer                       -> probable ("owner unknown")
   dangling typed pointer, no write observed                           -> candidate (warning)

Cost is bounded: at most ``max_tracked_chunks`` free chunks are tracked (header + list metadata, ~32 bytes each
per observation), at most ``max_hashed_chunks`` / ``max_hashed_bytes`` (and ``max_payload_bytes_per_chunk`` per
chunk) of payload are hashed; whatever is above a cap is listed in ``limitations``.

What memory reads cannot see: a write made before the first read with no pointer left (indistinguishable from
the freed object's own last contents), a dangling pointer to a chunk that has since been re-allocated (it is in
use again, the old and new owner share it), a dangling pointer held only in a register or an untyped word, a use
that only READS freed memory, writes into the first 16 bytes of a tcache/fastbin entry that do not break the list
(left to IMP-009 when they do), and munmapped (large, mmapped) blocks.
"""

import bisect
import hashlib
import struct
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from .heap_walker import (
    PREV_INUSE,
    SIZE_BITS,
    ST_FASTBIN,
    ST_FREE,
    ST_TCACHE,
    BudgetedReader,
    HeapWalkBudgetExhausted,
)

FREE_STATES = (ST_TCACHE, ST_FASTBIN, ST_FREE)
TYPED_OWNER_KINDS = ("global", "static")
LEVEL_CONFIRMED = "confirmed"
LEVEL_PROBABLE = "probable"
LEVEL_CANDIDATE = "candidate"
LARGE_MIN_CHUNK = 1024             # LP64: smallbins hold chunks below 1024 bytes (MIN_LARGE_SIZE)
UAF_DEFECT_KINDS = ("tcache_pointer_damaged", "fastbin_pointer_damaged", "free_chunk_link_damaged")


@dataclass
class UafConfig:
    observations: int = 3               # re-reads after the walk's copy
    window_s: float = 0.4               # minimum span from the walk to the last re-read
    min_interval_s: float = 0.08
    reuse_probe_reads: int = 5
    reuse_probe_interval_s: float = 0.02
    max_tracked_chunks: int = 4096
    max_hashed_chunks: int = 1024
    max_hashed_bytes: int = 512 * 1024
    max_payload_bytes_per_chunk: int = 4096
    max_list_len: int = 256
    max_reports: int = 16
    max_read_bytes: int = 8 * 1024 * 1024
    max_wall_s: float = 3.0


class _Free:
    __slots__ = ("ci", "addr", "size", "state", "list_kind", "list_key", "pos", "list_name", "skip", "hash_len",
                 "h0", "refs", "corroboration", "takes_next")

    def __init__(self, ci: int, addr: int, size: int, state: int) -> None:
        self.ci = ci
        self.addr = addr
        self.size = size
        self.state = state
        self.list_kind = ""
        self.list_key: Tuple[Any, ...] = ()
        self.pos = -1
        self.list_name = ""
        self.skip = 16
        self.hash_len = 0
        self.h0: Optional[bytes] = None
        self.refs: List[Dict[str, Any]] = []
        self.corroboration: List[str] = []
        self.takes_next = False         # the next allocation of this size would take this chunk (LIFO head / bin end)

    @property
    def payload_start(self) -> int:
        return self.addr + 16 + self.skip

    @property
    def payload_len(self) -> int:
        return max(0, self.size - 16 - self.skip)       # user area minus metadata minus the trailing prev_size word


def _coalesce(ranges: Sequence[Tuple[int, int]], gap: int = 512, max_span: int = 256 * 1024) -> List[Tuple[int, int]]:
    """Merge nearby ranges into fewer reads (each read costs a syscall; free chunks cluster in the heap)."""
    out: List[List[int]] = []
    for a, n in sorted((int(a), int(n)) for a, n in ranges if n > 0):
        if out and a <= out[-1][1] + gap and max(out[-1][1], a + n) - out[-1][0] <= max_span:
            out[-1][1] = max(out[-1][1], a + n)
        else:
            out.append([a, a + n])
    return [(a, e - a) for a, e in out]


class _Reads:
    """The ranges of one observation (each read at one moment), looked up by bisection (MemorySnapshot.add is
    quadratic in the number of regions; an observation has thousands of small ones)."""

    def __init__(self, ranges: Sequence[Tuple[int, int]], datas: Sequence[Optional[bytes]]) -> None:
        regs = sorted(((a, d) for (a, _n), d in zip(ranges, datas) if d), key=lambda x: x[0])
        self.starts = [a for a, _ in regs]
        self.bufs = [d for _, d in regs]

    def get(self, addr: int, size: int) -> Optional[bytes]:
        i = bisect.bisect_right(self.starts, addr) - 1
        for j in range(i, max(-1, i - 4), -1):          # a few overlapping regions (header ranges) look back
            off = addr - self.starts[j]
            b = self.bufs[j]
            if 0 <= off and off + size <= len(b):
                return b[off:off + size]
        return None

    def u64(self, addr: int) -> Optional[int]:
        b = self.get(addr, 8)
        return None if b is None else _u64(b)


def _u64(b: bytes, off: int = 0) -> int:
    return struct.unpack_from("<Q", b, off)[0]


def _hash(b: Optional[bytes]) -> Optional[bytes]:
    return None if b is None else hashlib.blake2b(b, digest_size=16).digest()


class UafDetector:
    """One detection over an existing walk (``walk``/``walker``) and, when available, its reachability map."""

    def __init__(self, walk: Any, walker: Any, adapter: Any, pid: int, analyzer: Any = None,
                 cfg: Optional[UafConfig] = None, budget: Any = None, walk_time: Optional[float] = None,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        from .observation_budget import ObservationBudgetLimits, ObservationBudgetTracker
        self.walk = walk
        self.walker = walker
        self.layout = walk.layout
        self.ct = walk.chunks
        self.snap = walk.snapshot
        self.adapter = adapter
        self.pid = int(pid)
        self.analyzer = analyzer
        self.cfg = cfg or UafConfig()
        self.sleep = sleep
        self.walk_time = walk_time if walk_time is not None else time.monotonic()
        self.reader = BudgetedReader(adapter, pid, budget or ObservationBudgetTracker(ObservationBudgetLimits(
            max_wall_clock_ms=self.cfg.max_wall_s * 1000.0 + 2000.0, max_bytes_read=self.cfg.max_read_bytes,
            max_samples=1 << 30, max_bytes_per_observation=1 << 40, max_consecutive_read_failures=1 << 20,
            max_total_read_failures=1 << 20)), profile_id="use_after_free")
        self.arena_addrs = [int(str(a["address"]), 16) for a in walk.arenas]
        self.limitations: List[str] = []
        self.free: Dict[int, _Free] = {}            # chunk address -> record
        self.lists: Dict[Tuple[Any, ...], List[int]] = {}     # list key -> chunk addresses in list order (walk)
        self.tcache_keys: set = set()
        self.stats: Dict[str, Any] = {}

    # ------------------------------------------------------------------ census (walk copy, no reads)
    def _demangle(self, slot: int, val: int) -> int:
        return ((slot >> 12) ^ val) if self.layout.safe_linking else val

    def _tcache_chain(self, buf: Any, user: int, b: int, u64: Callable[[int], Optional[int]]) -> Optional[List[int]]:
        lay = self.layout
        width = lay.tcache_count_width
        cnt = struct.unpack_from("<H" if width == 2 else "<B", buf, b * width)[0]
        cur = _u64(buf, lay.tcache_entries_off + 8 * b)
        out: List[int] = []
        for _ in range(min(int(cnt), self.cfg.max_list_len)):
            if not cur:
                return None
            out.append(cur - 16)
            raw = u64(cur)
            if raw is None:
                return None
            cur = self._demangle(cur, raw)
        return out if cur == 0 and len(out) == cnt else None

    def _fast_chain(self, head: int, u64: Callable[[int], Optional[int]]) -> Optional[List[int]]:
        out: List[int] = []
        p = head
        while p:
            if len(out) >= self.cfg.max_list_len or p in out:
                return None
            out.append(p)
            raw = u64(p + 16)
            if raw is None:
                return None
            p = self._demangle(p + 16, raw)
        return out

    def _bin_of(self, fd: int) -> Optional[Tuple[int, int]]:
        """(arena index, bin index) of a bin header reached by following fd pointers."""
        p = fd
        for _ in range(64):
            if self.ct.index_of_chunk(p) is None:
                break
            nxt = self.snap.u64(p + 16)
            if nxt is None:
                return None
            p = nxt
        else:
            return None
        base_off = self.layout.ms.get("bins")
        if base_off is None:
            return None
        for ai, a in enumerate(self.arena_addrs):
            d = p - (a + base_off - 16)
            if d >= 0 and d % 16 == 0 and 1 <= d // 16 + 1 < self.layout.nbins:
                return ai, d // 16 + 1
        return None

    def census(self) -> None:
        lay = self.layout
        ct = self.ct
        for ci in range(len(ct)):
            if ct.states[ci] in FREE_STATES:
                a = int(ct.addrs[ci])
                self.free[a] = _Free(ci, a, int(ct.sizes[ci]), int(ct.states[ci]))
        # tcache chains (validated structs of the walk)
        for t in self.walk.tcache_structs:
            user = int(str(t["address"]), 16)
            body = self.snap.get(user, lay.tcache_struct_size)
            if body is None:
                continue
            for b in range(lay.tcache_bins):
                chain = self._tcache_chain(body, user, b, self.snap.u64)
                if not chain:
                    continue
                key = ("tcache", user, b)
                self.lists[key] = chain
                for pos, c in enumerate(chain):
                    f = self.free.get(c)
                    if f is None or f.state != ST_TCACHE:
                        continue
                    f.list_kind, f.list_key, f.pos, f.skip = "tcache", key, pos, 16
                    f.takes_next = pos == 0
                    f.list_name = ("tcache bin %d (chunk size %d) of the tcache at 0x%x, entry %d of %d"
                                   % (b, f.size, user, pos, len(chain)))
                    k = self.snap.u64(c + 24)
                    if k:
                        self.tcache_keys.add(k)
        # fastbins
        for ai, a in enumerate(self.arena_addrs):
            ab = self.snap.get(a + lay.ms["fastbinsY"], 8 * lay.nfastbins)
            if ab is None:
                continue
            for b in range(lay.nfastbins):
                chain = self._fast_chain(_u64(ab, 8 * b), self.snap.u64)
                if not chain:
                    continue
                key = ("fastbin", ai, b)
                self.lists[key] = chain
                for pos, c in enumerate(chain):
                    f = self.free.get(c)
                    if f is None or f.state != ST_FASTBIN:
                        continue
                    f.list_kind, f.list_key, f.pos, f.skip = "fastbin", key, pos, 16
                    f.takes_next = pos == 0
                    f.list_name = "fastbin %d (chunk size %d) of arena %d, entry %d of %d" % (b, f.size, ai, pos,
                                                                                              len(chain))
        # regular bins: fd/bk (+ nextsize links for large sizes)
        for f in self.free.values():
            if f.state != ST_FREE:
                continue
            f.list_kind = "bin"
            f.list_key = ("bin", f.addr)
            f.skip = 32 if f.size >= LARGE_MIN_CHUNK else 16
            fd = self.snap.u64(f.addr + 16)
            where = self._bin_of(fd) if fd else None
            if where is None:
                f.list_name = "a regular bin (unsorted / small / large) of arena %d" % int(self.ct.arena[f.ci])
            else:
                ai, i = where
                kind = "unsorted bin" if i == 1 else ("small bin %d" % i if i < 64 else "large bin %d" % i)
                f.list_name = "%s of arena %d" % (kind, ai)
            # fd -> bin header: this chunk is the bin's last entry, the one the next allocation takes
            f.takes_next = bool(fd) and self.ct.index_of_chunk(fd) is None
        # chunks marked free but on no chain we could re-derive are not tracked (no list identity)
        for a in [a for a, f in self.free.items() if not f.list_kind]:
            del self.free[a]

    # ------------------------------------------------------------------ dangling references (reachability map)
    def collect_refs(self) -> None:
        an = self.analyzer
        if an is None:
            return
        for f in self.free.values():
            ci = an.ct.index_of_chunk(f.addr)
            if ci is None:
                continue
            for node, suffix, root, slot, interior in an.refs.get(ci, []):
                r = an.roots[root] if 0 <= root < len(an.roots) else None
                if r is None:
                    continue
                if r.kind in TYPED_OWNER_KINDS:
                    path = an.render(node, suffix) if node >= 0 else suffix
                    f.refs.append({"root": r.name, "kind": r.kind, "path": path, "slot": int(slot),
                                   "interior": int(interior), "module": r.module})
                elif r.kind == "local":
                    f.corroboration.append("typed local %s in %s (thread %s)" % (
                        an.render(node, suffix) if node >= 0 else r.name, r.function, r.thread))
                else:
                    f.corroboration.append("untyped word (%s)" % (r.thread and "stack of thread %s" % r.thread
                                                                  or r.name))

    # ------------------------------------------------------------------ selection under the caps
    def select(self) -> Tuple[List[_Free], List[Tuple[Any, ...]]]:
        cfg = self.cfg
        refd_lists = []
        other_lists = []
        for key, chain in self.lists.items():
            (refd_lists if any(self.free.get(c) is not None and self.free[c].refs for c in chain)
             else other_lists).append(key)
        bins = [f for f in self.free.values() if f.list_kind == "bin"]
        bins.sort(key=lambda f: (not f.refs, f.addr))
        tracked: List[_Free] = []
        lists: List[Tuple[Any, ...]] = []
        n_total = len(self.free)
        for key in refd_lists + sorted(other_lists, key=str):
            members = [self.free[c] for c in self.lists[key] if c in self.free]
            if len(tracked) + len(members) > cfg.max_tracked_chunks:
                continue
            tracked.extend(members)
            lists.append(key)
        for f in bins:
            if len(tracked) >= cfg.max_tracked_chunks:
                break
            tracked.append(f)
        if len(tracked) < n_total:
            self.limitations.append("use-after-free: %d of %d free chunks tracked (cap %d chunks): the others were "
                                    "not checked for dangling references or writes"
                                    % (len(tracked), n_total, cfg.max_tracked_chunks))
        # payload hashing caps: referenced chunks first, then small to large
        order = sorted(tracked, key=lambda f: (not f.refs, f.size, f.addr))
        hashed = 0
        hbytes = 0
        partial = 0
        skipped = 0
        for f in order:
            n = min(f.payload_len, cfg.max_payload_bytes_per_chunk)
            if n <= 0:
                continue
            if hashed >= cfg.max_hashed_chunks or hbytes + n > cfg.max_hashed_bytes:
                skipped += 1
                continue
            data = self.snap.get(f.payload_start, n)
            if data is None:
                skipped += 1
                continue
            f.hash_len = n
            f.h0 = _hash(data)
            hashed += 1
            hbytes += n
            if n < f.payload_len:
                partial += 1
        if skipped:
            self.limitations.append("use-after-free: payload of %d free chunk(s) not hashed (caps: %d chunks, %d "
                                    "bytes): writes into them were not checked"
                                    % (skipped, cfg.max_hashed_chunks, cfg.max_hashed_bytes))
        if partial:
            self.limitations.append("use-after-free: %d large free chunk(s) hashed over their first %d payload bytes "
                                    "only" % (partial, cfg.max_payload_bytes_per_chunk))
        self.stats.update(free_chunks=n_total, tracked_chunks=len(tracked), hashed_chunks=hashed,
                          hashed_bytes=hbytes)
        return tracked, lists

    # ------------------------------------------------------------------ one observation (re-read)
    def observe(self, tracked: Sequence[_Free], lists: Sequence[Tuple[Any, ...]], slots: Sequence[int],
                containers: Sequence[Tuple[int, int]]) -> Dict[str, Any]:
        lay = self.layout
        ranges: List[Tuple[int, int]] = []
        for f in tracked:
            ranges.append((f.addr, 16 + f.skip + f.hash_len))
            if f.list_kind == "bin":
                ranges.append((f.addr + f.size, 16))
        tc_structs = sorted({k[1] for k in lists if k[0] == "tcache"})
        fb_arenas = sorted({k[1] for k in lists if k[0] == "fastbin"})
        ranges += [(u, lay.tcache_struct_size) for u in tc_structs]
        ranges += [(self.arena_addrs[ai] + lay.ms["fastbinsY"], 8 * lay.nfastbins) for ai in fb_arenas]
        ranges += [(s, 8) for s in slots]
        for ca, cs in containers:
            ranges += [(ca + 16, 16), (ca + cs, 16)]
        merged = _coalesce(ranges)
        datas = self.reader.read_ranges(merged)
        t = time.monotonic()
        snap = _Reads(merged, datas)
        out: Dict[str, Any] = {"t": t, "chains": {}, "free": {}, "hash": {}, "sig": {}, "slots": {}, "container_freed": {}}
        for k in lists:
            if k[0] == "tcache":
                body = snap.get(k[1], lay.tcache_struct_size)
                out["chains"][k] = self._tcache_chain(body, k[1], k[2], snap.u64) if body is not None else None
            else:
                ab = snap.get(self.arena_addrs[k[1]] + lay.ms["fastbinsY"], 8 * lay.nfastbins)
                out["chains"][k] = self._fast_chain(_u64(ab, 8 * k[2]), snap.u64) if ab is not None else None
        for f in tracked:
            hdr = snap.get(f.addr, 16 + f.skip)
            ok = hdr is not None and (_u64(hdr, 8) & ~SIZE_BITS) == f.size
            sig: Any = None
            if ok and f.list_kind == "bin":
                nxt = snap.get(f.addr + f.size, 16)
                ok = nxt is not None and not (_u64(nxt, 8) & PREV_INUSE) and _u64(nxt, 0) == f.size
                sig = hdr[16:16 + f.skip]
            elif ok:
                chain = out["chains"].get(f.list_key)
                ok = chain is not None and f.addr in chain
                sig = tuple(chain) if ok else None
            out["free"][f.addr] = ok
            out["sig"][f.addr] = sig
            if f.hash_len:
                out["hash"][f.addr] = _hash(snap.get(f.payload_start, f.hash_len))
        for s in slots:
            out["slots"][s] = snap.u64(s)
        for ca, cs in containers:
            key = snap.u64(ca + 24)
            nxt = snap.get(ca + cs, 16)
            out["container_freed"][ca] = bool((key is not None and key in self.tcache_keys)
                                              or (nxt is not None and not (_u64(nxt, 8) & PREV_INUSE)))
        return out

    # ------------------------------------------------------------------ the whole detection
    def run(self, integrity_defects: Sequence[Dict[str, Any]] = ()) -> Dict[str, Any]:
        cfg = self.cfg
        t0 = time.monotonic()
        rec: Dict[str, Any] = {"status": "COMPLETED", "findings": [], "not_evidence": [], "limitations": self.limitations}
        self.census()
        self.collect_refs()
        if self.analyzer is None:
            self.limitations.append("use-after-free: no reverse reference map: dangling pointers not checked")
        tracked, lists = self.select()
        refd = [f for f in tracked if f.refs]
        slots = sorted({r["slot"] for f in refd for r in f.refs})
        containers = []
        for s in slots:
            ci = self.ct.find_containing(s)
            if ci is not None:
                containers.append((int(self.ct.addrs[ci]), int(self.ct.sizes[ci])))
        containers = sorted(set(containers))
        obs: List[Dict[str, Any]] = []
        n = max(2, int(cfg.observations)) if tracked else 0   # no free chunk: nothing can dangle or be written
        try:
            for i in range(n):
                target = self.walk_time + cfg.window_s * (i + 1) / n
                now = time.monotonic()
                if obs:
                    target = max(target, obs[-1]["t"] + cfg.min_interval_s)
                if target > now:
                    self.sleep(target - now)
                obs.append(self.observe(tracked, lists, slots, containers))
                if time.monotonic() - t0 > cfg.max_wall_s:
                    break
        except HeapWalkBudgetExhausted as exc:
            self.limitations.append("use-after-free: observation budget exhausted during the re-reads: %s" % exc)
        if tracked and len(obs) < 2:
            rec["status"] = "LIMITED"
            self.limitations.append("use-after-free: fewer than 2 re-reads of the free chunks could be made")
            return self._finish(rec, t0, obs)
        # ---- per chunk evaluation
        cands: List[Dict[str, Any]] = []
        for f in tracked:
            always_free = all(o["free"].get(f.addr) for o in obs)
            same_list = always_free and all(o["sig"].get(f.addr) == obs[0]["sig"].get(f.addr) for o in obs)
            if not always_free:
                for r in f.refs:
                    rec["not_evidence"].append({"referrer_path": r["path"], "chunk": "0x%x" % f.addr,
                                                "why": "the chunk left its free list during the window "
                                                       "(re-allocated): the pointer is no longer dangling"})
                continue
            dangling = []
            for r in f.refs:
                v0 = f.addr + 16 + r["interior"]
                cont = self.ct.find_containing(r["slot"])
                ca = int(self.ct.addrs[cont]) if cont is not None else None
                if all(o["slots"].get(r["slot"]) == v0 for o in obs) and not any(
                        ca is not None and o["container_freed"].get(ca) for o in obs):
                    dangling.append(r)
                else:
                    rec["not_evidence"].append({"referrer_path": r["path"], "chunk": "0x%x" % f.addr,
                                                "why": "the pointer changed (or its container was freed) during "
                                                       "the window: transient, not evidence"})
            write = None
            if f.hash_len and same_list:
                hs = [f.h0] + [o["hash"].get(f.addr) for o in obs]
                if None not in hs:
                    changed = [i for i in range(1, len(hs)) if hs[i] != hs[0]]
                    if changed:
                        # stable: the new content is seen in two reads (persisting or changing again)
                        stable = len(changed) >= 2
                        write = {"changed_in_reads": len(changed), "reads": len(hs) - 1, "stable": stable,
                                 "distinct_contents": len(set(hs))}
            if not dangling and write is None:
                continue
            cands.append({"f": f, "dangling": dangling, "write": write})
        # ---- reuse probe for every write candidate (a quick allocate-write-free cycle in between?)
        wc = [c for c in cands if c["write"] is not None]
        if wc:
            plists = sorted({c["f"].list_key for c in wc if c["f"].list_kind != "bin"}, key=str)
            # every member of a probed list is re-read (its chain runs through them)
            ptracked = [f for f in tracked if f.list_key in plists] + [c["f"] for c in wc if c["f"].list_kind == "bin"]
            try:
                for _ in range(cfg.reuse_probe_reads):
                    self.sleep(cfg.reuse_probe_interval_s)
                    o = self.observe(ptracked, plists, [], [])
                    for c in wc:
                        f = c["f"]
                        if not o["free"].get(f.addr) or o["sig"].get(f.addr) != obs[0]["sig"].get(f.addr):
                            c["write"]["reused"] = True
            except HeapWalkBudgetExhausted as exc:
                self.limitations.append("use-after-free: budget exhausted during the re-allocation probe: %s" % exc)
                for c in wc:
                    c["write"]["reused"] = True
        integ = {}
        for d in integrity_defects or ():
            u = d.get("use_after_free")
            if u:
                integ[int(str(u["freed_chunk"]), 16)] = d
        for c in cands:
            f, dangling, write = c["f"], c["dangling"], c["write"]
            if write is not None and write.get("reused"):
                rec["not_evidence"].append({"chunk": "0x%x" % f.addr, "why": "payload changed but the chunk was seen "
                                            "re-allocated (or its list changed) in a quick re-read: an allocate-"
                                            "write-free cycle, not a write while free"})
                write = None
            if write is not None and not write["stable"]:
                rec["not_evidence"].append({"chunk": "0x%x" % f.addr, "why": "payload differed in a single read "
                                            "only: not stable, not evidence"})
                write = None
            if write is not None and not dangling:
                if f.takes_next or f.size >= LARGE_MIN_CHUNK:
                    rec["not_evidence"].append({
                        "chunk": "0x%x" % f.addr, "why": "payload changed while free, no typed pointer refers to it, "
                        "and the chunk is %s: an immediate re-allocation, write and free between two reads cannot be "
                        "excluded" % ("the next one its size class hands out" if f.takes_next else
                                      "in a large bin (best fit)")})
                    write = None
            if not dangling and write is None:
                continue
            level = LEVEL_CANDIDATE
            if dangling and write is not None:
                level = LEVEL_CONFIRMED
            elif write is not None:
                level = LEVEL_PROBABLE
            rec["findings"].append(self._row(f, dangling, write, level, obs))
            integ.pop(f.addr, None)
        # free-list damage in a free chunk a typed pointer still refers to (classified by the integrity check)
        for addr, d in integ.items():
            u = d["use_after_free"]
            row = {"level": LEVEL_CONFIRMED, "variable": u.get("variable"), "variable_path": u.get("variable_path"),
                   "freed_chunk": u["freed_chunk"], "free_list": u.get("free_list"),
                   "written_while_free": True, "write_evidence": "allocator metadata of the free chunk overwritten "
                   "(%s), stable across %s re-reads" % (d.get("reason"), d.get("stable_rereads")),
                   "dangling_pointers": [{"variable": u.get("variable"), "variable_path": u.get("variable_path")}]}
            row["description"] = ("use after free: %s still points to freed chunk %s and the chunk's free-list "
                                  "metadata was written while free (%s)" % (u.get("variable_path"), u["freed_chunk"],
                                                                            d.get("reason")))
            rec["findings"].append(row)
        rec["findings"].sort(key=lambda r: {LEVEL_CONFIRMED: 0, LEVEL_PROBABLE: 1, LEVEL_CANDIDATE: 2}[r["level"]])
        if len(rec["findings"]) > cfg.max_reports:
            self.limitations.append("use-after-free: %d findings, first %d reported"
                                    % (len(rec["findings"]), cfg.max_reports))
            rec["findings"] = rec["findings"][:cfg.max_reports]
        rec["not_evidence"] = rec["not_evidence"][:32]
        return self._finish(rec, t0, obs)

    def _row(self, f: _Free, dangling: List[Dict[str, Any]], write: Optional[Dict[str, Any]], level: str,
             obs: List[Dict[str, Any]]) -> Dict[str, Any]:
        window = obs[-1]["t"] - self.walk_time
        row: Dict[str, Any] = {
            "level": level, "freed_chunk": "0x%x" % f.addr, "user_address": "0x%x" % (f.addr + 16),
            "chunk_size": f.size, "free_list": f.list_name, "written_while_free": write is not None,
            "observed_free_in_reads": len(obs) + 1, "window_s": round(window, 3),
        }
        if dangling:
            r = dangling[0]
            row["variable"] = r["root"]
            row["variable_path"] = r["path"]
            row["dangling_pointers"] = [{"variable": d["root"], "variable_path": d["path"], "owner_kind": d["kind"],
                                         "slot_address": "0x%x" % d["slot"], "interior_offset": d["interior"]}
                                        for d in dangling[:4]]
        else:
            row["owner_unknown"] = "no reference remains: no typed pointer refers to the freed chunk"
        if f.corroboration:
            row["corroboration"] = f.corroboration[:4]
        if write is not None:
            row["write_evidence"] = ("payload beyond the allocator metadata changed in %d of %d re-reads (%d "
                                     "distinct contents) while the chunk stayed free on the same list"
                                     % (write["changed_in_reads"], write["reads"], write["distinct_contents"]))
        where = "freed chunk %s (size %d, %s)" % (row["freed_chunk"], f.size, f.list_name)
        if level == LEVEL_CONFIRMED:
            row["description"] = ("use after free: %s still points to %s and the chunk was written while free (%s)"
                                  % (row["variable_path"], where, row["write_evidence"]))
        elif level == LEVEL_PROBABLE:
            row["description"] = ("%s was written while free (%s); owner unknown: no reference remains"
                                  % (where, row["write_evidence"]))
        else:
            row["description"] = ("dangling pointer: %s points to %s, stable over %.2f s; no write into it was "
                                  "observed (candidate: a use is not proven)" % (row["variable_path"], where, window))
        return row

    def _finish(self, rec: Dict[str, Any], t0: float, obs: List[Dict[str, Any]]) -> Dict[str, Any]:
        rec["checked"] = dict(self.stats, reads=len(obs), window_s=round((obs[-1]["t"] - self.walk_time), 3)
                              if obs else 0.0)
        rec["cost"] = {"bytes_read": int(self.reader.bytes_read), "wall_s": round(time.monotonic() - t0, 3)}
        rec["limitations"] = list(dict.fromkeys(self.limitations))
        return rec


# ---------------------------------------------------------------------------------- integrity interplay
def classify_integrity_defects(defects: List[Dict[str, Any]]) -> None:
    """IMP-009 free-list damage IN a free chunk that a typed global/static pointer still refers to is a write
    through that dangling pointer (use after free), not an overflow - unless the same chunk's header is damaged
    too (a linear overflow of the previous chunk reaches the header first).  Such a defect gets
    ``use_after_free`` and loses the overflow attribution (its previous chunk is just a neighbour)."""
    header_victims = {str((d.get("victim") or {}).get("chunk_address")) for d in defects
                      if d.get("kind") in ("chunk_header_damaged", "top_chunk_damaged")}
    for d in defects:
        vic = d.get("victim") or {}
        if d.get("kind") not in UAF_DEFECT_KINDS or not vic.get("chunk_address"):
            continue
        if str(vic["chunk_address"]) in header_victims:
            continue
        owners = [o for o in vic.get("owners") or [] if o.get("owner_kind") in TYPED_OWNER_KINDS]
        if not owners:
            continue
        o = owners[0]
        d["use_after_free"] = {"variable": o.get("variable"), "variable_path": o.get("variable_path"),
                               "freed_chunk": vic["chunk_address"],
                               "free_list": {"tcache_pointer_damaged": "tcache", "fastbin_pointer_damaged": "fastbin",
                                             "free_chunk_link_damaged": "regular bin"}[d["kind"]]}
        prev = d.pop("overflowing_buffer", None) or {}
        d["previous_chunk"] = {"chunk_address": prev.get("chunk_address"),
                               "owner": prev.get("variable_path") or prev.get("owner_unknown")}
        d["description"] = ("%s; the damaged chunk is FREE and still referenced by %s: a write through that dangling "
                             "pointer (use after free), not an overflow (its own header is intact)"
                             % (d.get("description", "").split("; a use-after-free write")[0],
                                o.get("variable_path")))


# ---------------------------------------------------------------------------------- provider glue
def _globals_analyzer(walk: Any, walker: Any, adapter: Any, pid: int, companion_elf: Optional[str],
                      reader: Any, lims: List[str]) -> Any:
    """Typed-roots-only reverse map (globals / statics and everything reached from them) - no conservative scan."""
    from .reachability import ReachabilityAnalyzer, ReachabilityLimits, _module_contexts
    if not companion_elf:
        lims.append("use-after-free: no debug image: no typed roots, dangling pointers not checked")
        return None
    try:
        mods = _module_contexts(adapter, pid, companion_elf, None, walk.mappings)
    except Exception as exc:  # noqa: BLE001
        lims.append("use-after-free: debug modules unavailable (%s: %s)" % (type(exc).__name__, exc))
        return None
    if not mods:
        lims.append("use-after-free: no DWARF module: dangling pointers not checked")
        return None
    an = ReachabilityAnalyzer(walk, walker, reader, mods, limits=ReachabilityLimits())
    an.prepare()
    an.add_global_roots()
    return an


def run_uaf(adapter: Any, pid: int, companion_elf: Optional[str], objs: Dict[str, Any], integrity: Dict[str, Any],
            cfg: Optional[UafConfig] = None, remaining_wall_s: Optional[float] = None) -> Dict[str, Any]:
    """Detection over the integrity check's walk (``objs`` from :func:`memory_integrity.ensure_integrity`)."""
    cfg = cfg or UafConfig()
    heap = (integrity or {}).get("heap") or {}
    walk = objs.get("walk") if objs else None
    if walk is None or not getattr(walk, "ok", False) or heap.get("status") not in ("COMPLETED", "PARTIAL"):
        why = "; ".join(l for l in (integrity or {}).get("limitations") or [] if "heap" in l) or \
            "heap %s" % (heap.get("status") or "not walked")
        status = "UNSUPPORTED" if heap.get("status") == "UNSUPPORTED" else "NOT_CHECKED"
        out = {"status": status, "findings": [], "not_evidence": [],
               "limitations": ["use-after-free not checked: no usable heap walk (%s)" % why], "cost": {"bytes_read": 0}}
        if heap.get("not_checked_reason"):
            # structured reason (the HEALTHY rule reads it, as for the double-free record)
            out["heap_not_checked_reason"] = heap["not_checked_reason"]
        return out
    if remaining_wall_s is not None and remaining_wall_s < cfg.window_s + 1.0:
        cfg = UafConfig(**dict(cfg.__dict__, window_s=max(0.1, remaining_wall_s / 4.0), observations=2,
                               reuse_probe_reads=2))
    lims: List[str] = []
    analyzer = objs.get("analyzer")
    det_reader = None
    det = UafDetector(walk, objs.get("walker"), adapter, pid, analyzer=None, cfg=cfg, walk_time=objs.get("t_walk"))
    if objs.get("walker") is not None:
        # the walk's own reader carries the (already spent) integrity budget; top catch-up / mmapped probes made
        # while building the reference map are charged to this detection instead
        objs["walker"].reader = det.reader
    if analyzer is None:
        try:
            analyzer = _globals_analyzer(walk, objs.get("walker"), adapter, pid, companion_elf, det.reader, lims)
        except HeapWalkBudgetExhausted as exc:
            lims.append("use-after-free: budget exhausted building the reference map: %s" % exc)
        except Exception as exc:  # noqa: BLE001
            lims.append("use-after-free: reference map failed (%s: %s)" % (type(exc).__name__, exc))
        det_reader = "typed globals / statics only (own map)"
    det.analyzer = analyzer
    det.limitations.extend(lims)
    rec = det.run(heap.get("defects") or [])
    rec["reference_map"] = det_reader or "shared with the integrity / leak walk"
    rec["walk_source"] = heap.get("walk_source")
    return rec

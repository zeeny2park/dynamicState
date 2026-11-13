"""Double free from memory reads alone - RECIPE_DOUBLE_FREE, registered entirely from this file.

Observation kind ``free_list_repeats``: re-uses the heap walk of the session's integrity check (IMP-009, itself
re-using the IMP-008 leak walk when that ran) - no second walk - and looks at glibc's singly-linked free lists in
that walk's copy: every tcache bin of every thread's ``tcache_perthread_struct`` and every fastbin of every arena
(safe-linking demangled on glibc >= 2.32).  Read-only, zero-stop, no ptrace.

What a double free leaves behind (and survives glibc's own checks)
    * the same chunk twice in one list: a fastbin double free with another free in between (``free(a); free(b);
      free(a)`` with that size's tcache full - glibc only compares the list head) makes the fastbin a cycle
      a -> b -> a; a tcache double free whose key word was overwritten in between (glibc >= 2.29 checks the key)
      makes a tcache cycle, with ``counts[]`` including the repeat;
    * the same chunk on two lists: freed into a fastbin or a regular bin while that size's tcache was full, the
      tcache drained by allocations, then freed again: the second free goes into the tcache (the key word holds a
      bin pointer, not the tcache key, so glibc does not look) and the chunk is in both.  A regular-bin listing is
      recognised from the chunk's boundary tag (next chunk's PREV_INUSE clear while a tcache / fastbin lists it)
      together with a bin link that points to the chunk (an arena bin head, or a free chunk's fd/bk).

Stability (the target keeps running): a repeat is evidence only when ``stability_reads`` live re-walks of every
list involved (and re-reads of the boundary tag / bin link of a regular-bin claim), ``interval_s`` apart, give
exactly the same chain as the walk's copy, with the arena mutex free for a fastbin / regular-bin claim (a locked
arena is mid-operation; up to ``extra_reads_when_locked`` further reads).  Otherwise the observation is listed in
``not_evidence`` ("inconsistent read, not evidence").  A list whose copy is inconsistent (does not end, leaves the
walked chunks, tcache count differs from its length) is re-walked live; a list that never settles is
"not walked completely" and blocks a CONTRADICTED verdict.

Verdict rule
    stable repeat / stable two-list listing -> SUPPORTED, INVALID_DOUBLE_FREE: confirmed on safe-linking glibc
    (>= 2.32: a program write of a raw pointer cannot form a valid link, only free() can) or when every list
    reaches the chunk straight from its head slot; otherwise capped at probable (on older glibc a use-after-free
    write of a free chunk's address into another free chunk makes the same shape);
    every list walked completely, nothing repeated -> CONTRADICTED;
    heap not walked (above the 8 MiB baseline cap, unsupported allocator, budget exhausted) or a list not walked
    completely -> INSUFFICIENT_EVIDENCE with the reason.

Not observable: who called free() the second time (free calls are not traced); a block freed, re-allocated and
freed again by its stale owner (it is listed once, like any free block); regular bins are not walked for repeats
(glibc aborts such a double free itself); munmapped (large, mmapped) blocks.

The rule also accepts a per-chunk record supplied by a caller (an allocator event tracer or a single probed chunk:
``double_free_recorded`` / ``duplicate_free_event``, ``freelist_occurrences``, ``in_freelist``, ``slot_status``,
``prev_inuse``, ``operation``); no live collector produces it.
"""

from __future__ import annotations

import struct
import time
import uuid
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from ..diagnostic_recipes import (
    CATEGORY_INVALID_DOUBLE_FREE,
    CATEGORY_MEMORY_CORRUPTION,
    DOMAIN_MEMORY_INTEGRITY,
    RECIPE_DOUBLE_FREE,
    RECIPE_STATUS_CONTRADICTED,
    RECIPE_STATUS_INSUFFICIENT_EVIDENCE,
    RECIPE_STATUS_SUPPORTED,
    DiagnosticRecipe,
    RecipeEvaluationResult,
    register_recipe,
)
from ..runtime_evidence_provider import register_observation_collector

OBS_FREE_LIST_REPEATS = "free_list_repeats"
LEVEL_CONFIRMED = "confirmed"
LEVEL_PROBABLE = "probable"
_PREV_INUSE = 0x1
_SIZE_BITS = 0x7


@dataclass
class DoubleFreeConfig:
    stability_reads: int = 2
    extra_reads_when_locked: int = 3
    interval_s: float = 0.03
    settle_attempts: int = 3            # live re-walks of a list whose copy was inconsistent
    max_list_len: int = 4096
    max_rewalked_lists: int = 64
    max_read_bytes: int = 1 << 20
    max_wall_s: float = 2.0
    max_reports: int = 8


def _u64(b: bytes, off: int = 0) -> int:
    return struct.unpack_from("<Q", b, off)[0]


def _hx(v: int) -> str:
    return "0x%x" % v


# ---------------------------------------------------------------------------------------------- detection
class FreeListRepeatDetector:
    """One detection over an existing heap walk (``walk``: HeapWalkResult with its snapshot)."""

    def __init__(self, walk: Any, reader: Any = None, cfg: Optional[DoubleFreeConfig] = None,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.walk = walk
        self.layout = walk.layout
        self.ct = walk.chunks
        self.snap = walk.snapshot
        self.reader = reader
        self.cfg = cfg or DoubleFreeConfig()
        self.sleep = sleep
        self.arena_addrs = [int(str(a["address"]), 16) for a in walk.arenas if a.get("address")]
        self.limitations: List[str] = []
        self.not_evidence: List[Dict[str, Any]] = []
        self.unresolved: List[Dict[str, Any]] = []
        self.checked: Dict[str, Any] = {}
        self._rewalked = 0
        self._free_links: Optional[Dict[int, List[Tuple[int, int]]]] = None

    # ------------------------------------------------------------------ memory accessors
    def _snap_get(self, addr: int, n: int) -> Optional[bytes]:
        return self.snap.get(addr, n)

    def _live_get(self, addr: int, n: int) -> Optional[bytes]:
        if self.reader is None:
            return None
        return self.reader.read(addr, n)

    # ------------------------------------------------------------------ lists
    def _demangle(self, slot: int, val: int) -> int:
        return ((slot >> 12) ^ val) if self.layout.safe_linking else val

    def tcache_structs(self) -> List[int]:
        """User addresses of tcache_perthread_structs: the walker's validated ones, the first chunk of each arena
        segment of the tcache-struct size, and any other chunk of that size whose bytes read as one (a list with a
        repeat makes the walker leave its struct unvalidated)."""
        from ..heap_walker import ST_IN_USE, ST_INTERNAL
        lay = self.layout
        ct = self.ct
        out = {int(str(t["address"]), 16) for t in self.walk.tcache_structs}
        firsts = set()
        for a in self.walk.arenas:
            for seg in a.get("segments", []) or []:
                try:
                    firsts.add(int(str(seg["first_chunk"]), 16))
                except (KeyError, ValueError):
                    pass
        csize = lay.tcache_chunk_size
        for i in range(len(ct)):
            if ct.sizes[i] != csize or ct.states[i] not in (ST_IN_USE, ST_INTERNAL):
                continue
            user = int(ct.addrs[i]) + 16
            if user in out:
                continue
            if int(ct.addrs[i]) in firsts or self._looks_like_tcache(user):
                out.add(user)
        return sorted(out)

    def _counts_entries(self, body: bytes) -> Tuple[Sequence[int], Sequence[int]]:
        lay = self.layout
        cfmt = "<%d%s" % (lay.tcache_bins, "H" if lay.tcache_count_width == 2 else "B")
        return (struct.unpack_from(cfmt, body, 0),
                struct.unpack_from("<%dQ" % lay.tcache_bins, body, lay.tcache_entries_off))

    def _looks_like_tcache(self, user: int) -> bool:
        lay = self.layout
        body = self.snap.get(user, lay.tcache_struct_size)
        if body is None:
            return False
        counts, entries = self._counts_entries(body)
        some = False
        for b, (c, e) in enumerate(zip(counts, entries)):
            if (c == 0) != (e == 0):
                return False
            if e:
                ci = self.ct.index_of_user(e)
                if ci is None or int(self.ct.sizes[ci]) != lay.min_chunk + b * lay.malloc_alignment:
                    return False
                some = True
        return some

    def list_keys(self) -> List[Tuple[Any, ...]]:
        lay = self.layout
        keys: List[Tuple[Any, ...]] = []
        structs = self.tcache_structs()
        self.checked["tcache_structs"] = len(structs)
        for user in structs:
            body = self.snap.get(user, lay.tcache_struct_size)
            if body is None:
                continue
            counts, entries = self._counts_entries(body)
            for b in range(lay.tcache_bins):
                if counts[b] or entries[b]:
                    keys.append(("tcache", user, b))
        for ai, a in enumerate(self.arena_addrs):
            ab = self.snap.get(a + lay.ms["fastbinsY"], 8 * lay.nfastbins)
            if ab is None:
                self.limitations.append("fastbins of arena %d not in the walk's copy" % ai)
                continue
            for b in range(lay.nfastbins):
                if _u64(ab, 8 * b):
                    keys.append(("fastbin", ai, b))
        return keys

    def list_name(self, key: Tuple[Any, ...]) -> str:
        lay = self.layout
        if key[0] == "tcache":
            return "tcache bin %d (chunk size %d) of the tcache at 0x%x" % (key[2], lay.min_chunk + key[2] * lay.malloc_alignment, key[1])
        return "fastbin %d (chunk size %d) of arena %d" % (key[2], lay.min_chunk + key[2] * lay.malloc_alignment, key[1])

    def head_slot(self, key: Tuple[Any, ...]) -> int:
        lay = self.layout
        if key[0] == "tcache":
            return key[1] + lay.tcache_entries_off + 8 * key[2]
        return self.arena_addrs[key[1]] + lay.ms["fastbinsY"] + 8 * key[2]

    def walk_list(self, key: Tuple[Any, ...], get: Callable[[int, int], Optional[bytes]]) -> Dict[str, Any]:
        """Follow one list -> {outcome: complete | repeat | incomplete, chain: [chunk addresses], ...}."""
        lay = self.layout
        want = lay.min_chunk + key[2] * lay.malloc_alignment
        r: Dict[str, Any] = {"key": key, "chain": [], "outcome": "incomplete"}
        count = None
        if key[0] == "tcache":
            w = lay.tcache_count_width
            cb = get(key[1] + key[2] * w, w)
            if cb is None or len(cb) < w:
                r["why"] = "tcache count not readable"
                return r
            count = struct.unpack("<H" if w == 2 else "<B", cb)[0]
            r["count"] = int(count)
        slot = self.head_slot(key)
        hb = get(slot, 8)
        if hb is None or len(hb) < 8:
            r["why"] = "list head not readable"
            return r
        cur = _u64(hb)
        tc = key[0] == "tcache"
        pos_of: Dict[int, int] = {}
        chain: List[int] = r["chain"]
        while cur:
            chunk = cur - 16 if tc else cur
            if chunk in pos_of:
                r["outcome"] = "repeat"
                r["repeat"] = [pos_of[chunk], len(chain)]
                return r
            if len(chain) >= self.cfg.max_list_len:
                r["why"] = "longer than %d entries" % self.cfg.max_list_len
                return r
            ci = self.ct.index_of_chunk(chunk)
            if cur % lay.malloc_alignment or ci is None or int(self.ct.sizes[ci]) != want:
                r["why"] = "entry %d (0x%x) is not a walked chunk of size %d" % (len(chain), cur, want)
                return r
            pos_of[chunk] = len(chain)
            chain.append(chunk)
            link = chunk + 16
            nb = get(link, 8)
            if nb is None or len(nb) < 8:
                r["why"] = "link of entry %d not readable" % (len(chain) - 1)
                return r
            cur = self._demangle(link, _u64(nb))
        if count is not None and count != len(chain):
            r["why"] = "tcache count %d but the list holds %d entries" % (count, len(chain))
            return r
        r["outcome"] = "complete"
        return r

    @staticmethod
    def _same(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
        return (a.get("outcome") == b.get("outcome") and a.get("chain") == b.get("chain")
                and a.get("repeat") == b.get("repeat") and a.get("count") == b.get("count"))

    # ------------------------------------------------------------------ regular bins (two-list claims)
    def _bin_links_to(self, chunk: int) -> List[Dict[str, Any]]:
        """Bin links (arena bin heads, fd/bk of free chunks in bins) whose value is ``chunk``."""
        from ..heap_walker import ST_FREE
        lay = self.layout
        out: List[Dict[str, Any]] = []
        off = lay.ms.get("bins")
        if off is None:
            return out
        for ai, a in enumerate(self.arena_addrs):
            nb = 2 * (lay.nbins - 1)
            bins = self.snap.get(a + off, 8 * nb)
            if bins is None:
                continue
            for k in range(nb):
                if _u64(bins, 8 * k) == chunk:
                    i = k // 2 + 1
                    kind = "unsorted bin" if i == 1 else ("small bin %d" % i if i < 64 else "large bin %d" % i)
                    out.append({"bin": "%s of arena %d" % (kind, ai), "link_at": a + off + 8 * k,
                                "link": "%s %s" % (kind, "fd" if k % 2 == 0 else "bk"), "arena": ai})
        if self._free_links is None:
            self._free_links = {}
            ct = self.ct
            for i in range(len(ct)):
                if ct.states[i] != ST_FREE or int(ct.arena[i]) < 0:
                    continue
                p = int(ct.addrs[i])
                body = self.snap.get(p + 16, 16)
                if body is None:
                    continue
                for o in (0, 8):
                    self._free_links.setdefault(_u64(body, o), []).append((p, o))
        for p, o in self._free_links.get(chunk, [])[:4]:
            if p == chunk:
                continue
            out.append({"bin": "a regular bin of arena %d" % int(self.ct.arena[self.ct.index_of_chunk(p)]),
                        "link_at": p + 16 + o, "link": "%s of free chunk 0x%x" % ("fd" if o == 0 else "bk", p),
                        "arena": int(self.ct.arena[self.ct.index_of_chunk(p)])})
        return out

    def _bin_claim(self, chunk: int) -> Optional[Dict[str, Any]]:
        ci = self.ct.index_of_chunk(chunk)
        if ci is None:
            return None
        nxt = chunk + int(self.ct.sizes[ci])
        sf = self.snap.u64(nxt + 8)
        if sf is None or sf & _PREV_INUSE:
            return None
        links = self._bin_links_to(chunk)
        if not links:
            return None
        return {"boundary_tag_at": nxt + 8, "links": links}

    # ------------------------------------------------------------------ detection + confirmation
    def run(self) -> Dict[str, Any]:
        t0 = time.monotonic()
        keys = self.list_keys()
        results: Dict[Tuple[Any, ...], Dict[str, Any]] = {}
        reference_from_live: Dict[Tuple[Any, ...], bool] = {}
        for k in keys:
            r = self.walk_list(k, self._snap_get)
            if r["outcome"] == "incomplete":
                r = self._settle(k, r)
                reference_from_live[k] = True
            results[k] = r
        self.checked.update(tcache_lists=sum(1 for k in keys if k[0] == "tcache"),
                            fastbin_lists=sum(1 for k in keys if k[0] == "fastbin"),
                            list_entries=sum(len(r["chain"]) for r in results.values()),
                            lists_rewalked_live=self._rewalked)
        # candidates: one per chunk, with every list it is on
        cands: Dict[int, Dict[str, Any]] = {}
        member: Dict[int, List[Tuple[Tuple[Any, ...], int]]] = {}
        for k, r in results.items():
            if r["outcome"] == "incomplete":
                continue
            for pos, c in enumerate(r["chain"]):
                member.setdefault(c, []).append((k, pos))
            if r["outcome"] == "repeat":
                c = r["chain"][r["repeat"][0]]
                cands.setdefault(c, {"chunk": c, "lists": {}, "bin": None})["lists"][k] = r
        for c, ms in member.items():
            if len({k for k, _ in ms}) > 1:
                cd = cands.setdefault(c, {"chunk": c, "lists": {}, "bin": None})
                for k, _ in ms:
                    cd["lists"][k] = results[k]
            claim = None if reference_from_live.get(ms[0][0]) else self._bin_claim(c)
            if claim is not None:
                cd = cands.setdefault(c, {"chunk": c, "lists": {}, "bin": None})
                for k, _ in ms:
                    cd["lists"][k] = results[k]
                cd["bin"] = claim
        findings: List[Dict[str, Any]] = []
        for c in sorted(cands)[:self.cfg.max_reports * 4]:
            cd = cands[c]
            ok, n, why = self._confirm(cd)
            if not ok:
                self.not_evidence.append({"chunk_address": _hx(c), "lists": [self.list_name(k) for k in cd["lists"]],
                                          "observed": self._what(cd), "why": why})
                continue
            findings.append(self._finding(cd, n))
            if len(findings) >= self.cfg.max_reports:
                break
        for k, r in results.items():
            if r["outcome"] == "incomplete":
                self.unresolved.append({"list": self.list_name(k), "why": r.get("why")})
        self.checked["wall_s"] = round(time.monotonic() - t0, 3)
        status = "COMPLETED" if not self.unresolved else "INCOMPLETE"
        return {"status": status, "findings": findings, "not_evidence": self.not_evidence[:16],
                "lists_not_walked_completely": self.unresolved[:16], "limitations": list(self.limitations),
                "checked": dict(self.checked, safe_linking=bool(self.layout.safe_linking)),
                "cost": {"bytes_read": int(getattr(self.reader, "bytes_read", 0) or 0)}}

    def _settle(self, key: Tuple[Any, ...], first: Dict[str, Any]) -> Dict[str, Any]:
        """Live re-walks of a list whose copy was inconsistent; the first settled result (complete or repeat)."""
        from ..heap_walker import HeapWalkBudgetExhausted
        if self.reader is None or self._rewalked >= self.cfg.max_rewalked_lists:
            first = dict(first, why=(first.get("why") or "") + "; not re-walked (re-walk limit)")
            return first
        self._rewalked += 1
        r = first
        for _ in range(self.cfg.settle_attempts):
            self.sleep(self.cfg.interval_s)
            try:
                r = self.walk_list(key, self._live_get)
            except HeapWalkBudgetExhausted as exc:
                return dict(first, why="observation budget exhausted while re-walking: %s" % exc)
            if r["outcome"] != "incomplete":
                r["live"] = True
                return r
        return dict(r, why="inconsistent in the walk's copy and in %d live re-walks (%s)"
                    % (self.cfg.settle_attempts, r.get("why")))

    def _confirm(self, cd: Dict[str, Any]) -> Tuple[bool, int, str]:
        """Re-walk every list of the candidate (and re-read a bin claim) until ``stability_reads`` identical,
        unlocked reads; any difference -> transient."""
        from ..heap_walker import HeapWalkBudgetExhausted
        if self.reader is None:
            return False, 0, "no live reader for the stability re-reads"
        lay = self.layout
        arenas = {k[1] for k in cd["lists"] if k[0] == "fastbin"}
        windows: List[Tuple[int, int, Optional[bytes]]] = []
        if cd["bin"]:
            arenas |= {lk["arena"] for lk in cd["bin"]["links"]}
            windows.append((cd["bin"]["boundary_tag_at"], 8, self.snap.get(cd["bin"]["boundary_tag_at"], 8)))
            windows += [(lk["link_at"], 8, self.snap.get(lk["link_at"], 8)) for lk in cd["bin"]["links"]]
        mutexes = [(self.arena_addrs[a] + lay.ms["mutex"], 4) for a in sorted(arenas) if a < len(self.arena_addrs)]
        stable, reads, locked = 0, 0, 0
        while reads < self.cfg.stability_reads + self.cfg.extra_reads_when_locked:
            self.sleep(self.cfg.interval_s)
            reads += 1
            try:
                for k, ref in cd["lists"].items():
                    if not self._same(self.walk_list(k, self._live_get), ref):
                        return False, stable, ("%s changed between reads %.0f ms apart (target mutating its free "
                                               "lists): inconsistent read, not evidence"
                                               % (self.list_name(k), self.cfg.interval_s * 1000))
                got = self.reader.read_ranges([(a, n) for a, n, _ in windows] + mutexes) if (windows or mutexes) else []
            except HeapWalkBudgetExhausted as exc:
                return False, stable, "observation budget exhausted before the re-reads: %s" % exc
            if any(g != e for g, (_, _, e) in zip(got[:len(windows)], windows)):
                return False, stable, ("boundary tag / bin link changed between reads: inconsistent read, "
                                       "not evidence")
            mx = got[len(windows):]
            if any(m is not None and len(m) == 4 and struct.unpack("<i", m)[0] != 0 for m in mx):
                locked += 1
                continue
            stable += 1
            if stable >= self.cfg.stability_reads:
                self.checked["stability_reads"] = max(int(self.checked.get("stability_reads") or 0), reads)
                return True, stable, ""
        return False, stable, ("arena locked (mid-operation) in %d of %d re-reads: not at rest, inconsistent read, "
                               "not evidence" % (locked, reads))

    def _what(self, cd: Dict[str, Any]) -> str:
        parts = []
        for k, r in cd["lists"].items():
            if r["outcome"] == "repeat":
                parts.append("%s repeats it (entries %d and %d)" % (self.list_name(k), r["repeat"][0], r["repeat"][1]))
            else:
                parts.append("on %s (entry %d)" % (self.list_name(k), r["chain"].index(cd["chunk"])))
        if cd["bin"]:
            parts.append("also in %s" % cd["bin"]["links"][0]["bin"])
        return "; ".join(parts)

    def _finding(self, cd: Dict[str, Any], stable_reads: int) -> Dict[str, Any]:
        c = cd["chunk"]
        ci = self.ct.index_of_chunk(c)
        size = int(self.ct.sizes[ci]) if ci is not None else None
        lists: List[Dict[str, Any]] = []
        from_head = True
        for k, r in cd["lists"].items():
            pos = r["chain"].index(c)
            from_head = from_head and pos == 0
            e: Dict[str, Any] = {"list": self.list_name(k), "list_kind": k[0], "head_slot": _hx(self.head_slot(k)),
                                 "chain": [_hx(x) for x in r["chain"]], "position": pos,
                                 "returns_to": r["repeat"][0] if r["outcome"] == "repeat" else None}
            if k[0] == "tcache":
                e["tcache_count"] = r.get("count")
                if r["outcome"] == "repeat":
                    e["distinct_entries"] = len(r["chain"])
                    e["count_includes_repeat"] = bool(r.get("count") is not None and r["repeat"][1] < r["count"])
            lists.append(e)
        if cd["bin"]:
            lk = cd["bin"]["links"][0]
            lists.append({"list": lk["bin"], "list_kind": "bin", "position": None, "returns_to": None,
                          "chain": [], "evidence": "next chunk's PREV_INUSE bit clear (boundary tag at %s) and %s "
                                                   "points to the chunk" % (_hx(cd["bin"]["boundary_tag_at"]), lk["link"])})
            from_head = from_head and lk["link"].split(" ")[0] in ("unsorted", "small", "large")
        repeat = any(x["returns_to"] is not None for x in lists)
        level = LEVEL_CONFIRMED if (self.layout.safe_linking or from_head) else LEVEL_PROBABLE
        f: Dict[str, Any] = {
            "kind": "repeat_in_one_list" if repeat and len(lists) == 1 else "listed_on_two_lists" if not repeat
            else "repeat_and_two_lists",
            "level": level, "chunk_address": _hx(c), "freed_chunk": _hx(c + 16), "user_address": _hx(c + 16),
            "chunk_size": size, "request_sizes": _request_range(size, self.layout), "lists": lists,
            "stable": True, "stable_rereads": stable_reads,
            "consequence": "two later allocations of this size can both receive address %s: two owners would "
                           "then share one block" % _hx(c + 16),
            "who_freed": "not observable: free() calls are not traced; only the lists' state is read",
        }
        if level == LEVEL_PROBABLE:
            f["level_reason"] = ("glibc without safe-linking (< 2.32): a write of a free chunk's address into "
                                 "another free chunk's link through a dangling pointer makes the same shape")
        return f


def _request_range(size: Optional[int], lay: Any) -> Optional[List[int]]:
    """malloc() request sizes that get a chunk of ``size`` (LP64: usable = size - 8)."""
    if not size:
        return None
    hi = size - 8
    lo = 0 if size <= lay.min_chunk else size - lay.malloc_alignment - 8 + 1
    return [lo, hi]


def describe(f: Dict[str, Any]) -> str:
    """One sentence of a finding (also used by the presentation as the engine's own text)."""
    lists = f.get("lists") or []
    where = []
    for x in lists:
        if x.get("returns_to") is not None:
            where.append("%s twice (entries %s and %d: the list returns to it)"
                         % (x["list"], x["returns_to"], len(x.get("chain") or [])))
        elif x.get("position") is not None:
            where.append("%s (entry %d)" % (x["list"], x["position"]))
        else:
            where.append("%s (%s)" % (x["list"], x.get("evidence")))
    s = ("block %s (chunk %s, size %s) is listed as free %s, stable across %s re-reads: it was freed twice"
         % (f.get("user_address"), f.get("chunk_address"), f.get("chunk_size"),
            ("on " + " and on ".join(where)) if where else "", f.get("stable_rereads")))
    for x in lists:
        if x.get("list_kind") == "tcache" and x.get("returns_to") is not None and x.get("tcache_count") is not None:
            s += "; its tcache count is %s but the list holds %s distinct blocks" % (x["tcache_count"],
                                                                                   x.get("distinct_entries"))
    s += "; " + str(f.get("consequence"))
    who = f.get("variable_path") or f.get("variable")
    if who:
        s += "; still referenced by %s (the pointer that was freed twice, or a copy of it)" % ", ".join(
            o.get("variable_path") or o.get("variable") for o in (f.get("owners") or [{"variable_path": who}]))
    elif f.get("owner_unknown"):
        s += "; owner unknown (%s)" % f["owner_unknown"]
    s += "; which code called free() twice is not observable (free calls are not traced)"
    return s


# ---------------------------------------------------------------------------------------------- collector
def _state(provider: Any) -> Dict[Any, Any]:
    st = getattr(provider, "_double_free_state", None)
    if st is None:
        st = {}
        provider._double_free_state = st
    return st


def run_double_free(adapter: Any, pid: int, companion_elf: Optional[str], objs: Dict[str, Any],
                    integrity: Dict[str, Any], cfg: Optional[DoubleFreeConfig] = None) -> Dict[str, Any]:
    """Detection over the integrity check's walk (``objs`` from :func:`memory_integrity.ensure_integrity`)."""
    from ..heap_integrity import HeapIntegrityChecker
    from ..heap_walker import BudgetedReader, HeapWalkBudgetExhausted
    from ..observation_budget import ObservationBudgetLimits, ObservationBudgetTracker
    cfg = cfg or DoubleFreeConfig()
    heap = (integrity or {}).get("heap") or {}
    walk = objs.get("walk") if objs else None
    if walk is None or not getattr(walk, "ok", False) or heap.get("status") not in ("COMPLETED", "PARTIAL"):
        why = "; ".join(l for l in (integrity or {}).get("limitations") or [] if "heap" in l) or \
            "heap %s" % (heap.get("status") or "not walked")
        out = {"status": "UNSUPPORTED" if heap.get("status") == "UNSUPPORTED" else "NOT_CHECKED", "findings": [],
               "not_evidence": [], "limitations": ["double free not checked: no usable heap walk (%s)" % why],
               "cost": {"bytes_read": 0}}
        if heap.get("not_checked_reason"):
            out["heap_not_checked_reason"] = heap["not_checked_reason"]
        return out
    reader = BudgetedReader(adapter, pid, ObservationBudgetTracker(ObservationBudgetLimits(
        max_wall_clock_ms=cfg.max_wall_s * 1000.0 + 1000.0, max_bytes_read=cfg.max_read_bytes,
        max_samples=1 << 30, max_bytes_per_observation=1 << 40, max_consecutive_read_failures=1 << 20,
        max_total_read_failures=1 << 20)), profile_id="double_free")
    det = FreeListRepeatDetector(walk, reader, cfg)
    rec = det.run()
    rec["walk_source"] = heap.get("walk_source")
    if rec["findings"]:
        analyzer = objs.get("analyzer")
        ref = "shared with the integrity / leak walk"
        if analyzer is None:
            from ..uaf_detection import _globals_analyzer
            lims: List[str] = []
            try:
                analyzer = _globals_analyzer(walk, objs.get("walker"), adapter, pid, companion_elf, reader, lims)
            except HeapWalkBudgetExhausted as exc:
                lims.append("double free: budget exhausted building the reference map: %s" % exc)
            except Exception as exc:  # noqa: BLE001 - attribution failure is a limitation, never a crash
                lims.append("double free: reference map failed (%s: %s)" % (type(exc).__name__, exc))
            rec["limitations"].extend(x.replace("use-after-free", "double free") for x in lims)
            ref = "typed globals / statics only (own map)"
        rec["reference_map"] = ref
        for f in rec["findings"]:
            own = HeapIntegrityChecker.owner_of(analyzer, int(f["chunk_address"], 16))
            f.update({k: v for k, v in own.items() if k in ("variable", "variable_path", "owner_kind", "owners",
                                                            "owner_unknown")})
            f["description"] = describe(f)
        rec["cost"]["bytes_read"] = int(reader.bytes_read)
    return rec


def collect_free_list_repeats(provider: Any, ctx: Dict[str, Any]) -> None:
    from ..memory_integrity import ensure_integrity
    from ..runtime_evidence_provider import (COLLECTION_STATUS_PARTIAL, COLLECTION_STATUS_SUCCESS,
                                             PROVENANCE_LIVE_RUNTIME_CAPTURE, RuntimeEvidenceRecord)
    pid = ctx["pid"]
    od = ctx["observation_data"]
    # free() calls themselves are never traced: who freed twice is not observable, only the lists' state
    od["lifecycle_tracing_unavailable"] = True
    if getattr(provider, "memory_observation", None) is None:
        # same gate as the integrity walk: only a diagnose session (multi-observation memory config) walks the heap
        od[OBS_FREE_LIST_REPEATS] = {"status": "NOT_CHECKED", "findings": [], "not_evidence": [],
                                     "limitations": ["double free not checked: no heap-walk session"]}
        return None
    key = (ctx.get("session_id") or "default", int(pid))
    st = _state(provider)
    rec = st.get(key)
    fresh = rec is None
    if fresh:
        mi, objs, _ = ensure_integrity(provider, pid, ctx.get("companion_elf"), ctx.get("classification"),
                                       ctx.get("session_id"))
        try:
            rec = run_double_free(provider.adapter, pid, ctx.get("companion_elf"), objs, mi)
        except Exception as exc:  # noqa: BLE001 - a detection failure is a limitation, never a crash
            rec = {"status": "FAILED", "findings": [], "not_evidence": [],
                   "limitations": ["double free check failed: %s: %s" % (type(exc).__name__, exc)],
                   "cost": {"bytes_read": 0}}
        st[key] = rec
    od[OBS_FREE_LIST_REPEATS] = rec
    if fresh:
        nbytes = int((rec.get("cost") or {}).get("bytes_read") or 0)
        if nbytes:
            od["bytes_read"] = int(od.get("bytes_read") or 0) + nbytes
        ctx["all_records"].append(RuntimeEvidenceRecord(
            evidence_id=f"ev_{uuid.uuid4().hex[:12]}",
            collection_method="free_list_walk",
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


# ---------------------------------------------------------------------------------------------- rule
_POINT_KEYS = ("in_freelist", "freelist_occurrences", "double_free_recorded", "duplicate_free_event", "slot_status",
               "prev_inuse", "operation", "freed_epoch", "allocation_event_history")


def _point_rule(recipe: DiagnosticRecipe, data: Dict[str, Any]) -> RecipeEvaluationResult:
    """A per-chunk record supplied by a caller (allocator event tracer / one probed chunk)."""
    rid = recipe.recipe_id
    in_freelist = data.get("in_freelist", False)
    freelist_occ = data.get("freelist_occurrences", 0)
    recorded = data.get("double_free_recorded", False) or data.get("duplicate_free_event", False)
    prev_inuse = data.get("prev_inuse")
    if data.get("slot_status") == "IN_USE":
        freelist_occ = 0
        prev_inuse = 1
    is_double_free = (
        recorded
        or freelist_occ > 1
        or (in_freelist and data.get("operation") == "FREE")
        or (data.get("slot_status") == "FREE" and data.get("operation") == "FREE")
        or bool(data.get("freed_epoch") and data.get("current_epoch") and data.get("operation") == "FREE")
    )
    if not is_double_free and (freelist_occ == 1 or in_freelist):
        # one free-list listing is a normal single free
        return RecipeEvaluationResult(
            recipe_id=rid, status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE, confidence=0.35,
            confidence_basis="The chunk is listed once on a free list: a normal single free. One listing cannot "
                             "prove a double free without a repeated listing or a second free event.",
            missing_evidence=["second_deallocation_event", "duplicate_freelist_entry"],
            limitations=list(recipe.limitations),
            details={"double_free_confirmed": False, "single_freelist_occurrence": True,
                     "single_freelist_observation": True})
    if is_double_free:
        return RecipeEvaluationResult(
            recipe_id=rid, status=RECIPE_STATUS_SUPPORTED, confidence=0.96,
            confidence_basis="The chunk was freed twice according to the supplied free events, or it is listed "
                             "more than once on the free lists.",
            supporting_facts=["Double free observed on chunk/slot"],
            recommended_action="Audit object destruction lifecycle to ensure single ownership.",
            details={"double_free_confirmed": True, "finding_category": CATEGORY_INVALID_DOUBLE_FREE})
    if freelist_occ == 0 and prev_inuse == 1 and not recorded:
        return RecipeEvaluationResult(
            recipe_id=rid, status=RECIPE_STATUS_CONTRADICTED, confidence=0.92,
            confidence_basis="The chunk is in use (prev_inuse == 1), on no free list, with no duplicate free event.",
            contradicting_facts=["Chunk not present in freelist", "prev_inuse is 1"],
            recommended_action="Refute double free hypothesis for this chunk.",
            details={"double_free_confirmed": False})
    return RecipeEvaluationResult(
        recipe_id=rid, status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE, confidence=0.20,
        confidence_basis="A single snapshot of one chunk cannot prove that a free happened twice; free events or "
                         "a free-list walk are needed.",
        missing_evidence=["allocation_free_event_history", "freelist_traversal_data"],
        limitations=list(recipe.limitations))


def double_free_rule(recipe: DiagnosticRecipe, data: Dict[str, Any]) -> Optional[RecipeEvaluationResult]:
    rid = recipe.recipe_id
    rec = data.get(OBS_FREE_LIST_REPEATS)
    rec = rec if isinstance(rec, dict) else {}
    lims = list(rec.get("limitations") or [])
    point = _point_rule(recipe, data) if any(k in data for k in _POINT_KEYS) else None
    fs = [f for f in rec.get("findings") or [] if isinstance(f, dict)]
    if fs:
        confirmed = any(f.get("level") == LEVEL_CONFIRMED for f in fs)
        facts = [str(f.get("description") or describe(f)) for f in fs]
        d: Dict[str, Any] = {"finding_category": CATEGORY_INVALID_DOUBLE_FREE, "double_free_findings": fs,
                             "double_free_confirmed": True, "corruption_confirmed": confirmed,
                             "finding_summary": "; ".join(facts[:2]),
                             "limitations": lims}
        if not confirmed:
            d["certainty_cap"] = "PROBABLE"
            d["certainty_cap_reason"] = str(fs[0].get("level_reason") or "free-list repeat without safe-linking")
        return RecipeEvaluationResult(
            recipe_id=rid, status=RECIPE_STATUS_SUPPORTED, confidence=0.95 if confirmed else 0.75,
            confidence_basis=facts[0], supporting_facts=facts, limitations=lims,
            recommended_action="Find where the named pointer (or the object holding it) is freed and make it free "
                               "exactly once (clear the pointer after free); rebuild with AddressSanitizer to get "
                               "both free() call stacks.",
            details=d)
    if point is not None and point.status == RECIPE_STATUS_SUPPORTED:
        return point
    if rec.get("status") == "COMPLETED":
        chk = rec.get("checked") or {}
        ne = rec.get("not_evidence") or []
        txt = ("every free list walked completely and no block is listed twice: %d tcache bin lists (%d tcache "
               "structs) and %d fastbin lists, %d entries"
               % (int(chk.get("tcache_lists") or 0), int(chk.get("tcache_structs") or 0),
                  int(chk.get("fastbin_lists") or 0), int(chk.get("list_entries") or 0))
               + ("; %d transient repeat(s) did not hold on re-read (not evidence)" % len(ne) if ne else ""))
        return RecipeEvaluationResult(
            recipe_id=rid, status=RECIPE_STATUS_CONTRADICTED, confidence=0.8, confidence_basis=txt,
            contradicting_facts=[txt], limitations=lims,
            recommended_action="No double free visible on the walked free lists.",
            details={"free_lists_checked": True, "double_free_confirmed": False, "limitations": lims})
    if point is not None:
        return point
    reasons = list(lims)
    for u in rec.get("lists_not_walked_completely") or []:
        reasons.append("%s not walked completely: %s" % (u.get("list"), u.get("why")))
    if rec.get("status") == "FAILED" or not rec:
        reasons = reasons or ["double free not checked: no free-list observation"]
    return RecipeEvaluationResult(
        recipe_id=rid, status=RECIPE_STATUS_INSUFFICIENT_EVIDENCE, confidence=0.1,
        confidence_basis="; ".join(reasons) or "double free not checked",
        missing_evidence=["complete_free_list_walk"], limitations=reasons,
        details={"free_lists_checked": False, "double_free_confirmed": False, "limitations": reasons,
                 **({"heap_not_checked_reason": rec["heap_not_checked_reason"]}
                    if rec.get("heap_not_checked_reason") else {})})


register_observation_collector(OBS_FREE_LIST_REPEATS, collect_free_list_repeats)
register_recipe(DiagnosticRecipe(
    recipe_id=RECIPE_DOUBLE_FREE,
    version="2.0.0",
    name="Double Free: A Block Listed Twice on the Allocator's Free Lists",
    domain=DOMAIN_MEMORY_INTEGRITY,
    applicable_problem_categories=[CATEGORY_INVALID_DOUBLE_FREE, CATEGORY_MEMORY_CORRUPTION],
    required_prerequisites=["memory_read_available", "heap_inspection_available"],
    evidence_sources=["heap_walk", "tcache_bins", "fastbins", "bin_links", "typed_reference_map"],
    collection_steps=[
        {"step": 1, "action": "reuse_integrity_walk", "purpose": "tcache structs, arena fastbins, chunk table"},
        {"step": 2, "action": "walk_free_lists", "purpose": "a chunk repeated in one list or on two lists"},
        {"step": 3, "action": "reread_lists", "purpose": "identical live re-walks with the arena at rest"},
        {"step": 4, "action": "typed_reference_map", "purpose": "typed pointers that still hold the block"},
    ],
    analysis_rules=[
        "a chunk repeated in one tcache bin / fastbin (the list returns to it) was freed twice",
        "a chunk on two lists (tcache and fastbin, or tcache / fastbin and a regular bin) was freed twice",
        "a repeat must be reproduced by every stability re-read before it is evidence",
    ],
    thresholds_and_conditions={"stability_reads": 2, "interval_s": 0.03, "extra_reads_when_locked": 3,
                               "max_list_len": 4096},
    supporting_evidence_criteria=["stable repeated entry in a tcache bin or fastbin",
                                  "the same chunk stably listed on two free lists"],
    contradicting_evidence_criteria=["every tcache bin and fastbin walked to its end with no chunk listed twice"],
    verification_procedure="Diagnose again: the repeat stays until the program allocates that size; rebuild with "
                           "AddressSanitizer to get both free() call stacks.",
    stop_conditions=["heap not walkable / above the baseline cap", "a list never read consistently"],
    limitations=["who called free() twice is not observable (free calls are not traced)",
                 "a block freed, re-allocated and freed again by its stale owner is listed once: not distinguishable "
                 "from a normal free",
                 "regular bins are not walked for repeats (glibc aborts that double free itself); munmapped blocks "
                 "are not seen",
                 "the repeat disappears once the program allocates that size again"],
    output_structure={"findings": "list[{level, chunk_address, chunk_size, lists[{list, chain, position, "
                                  "returns_to, tcache_count}], variable_path, consequence}]"},
    observations=(OBS_FREE_LIST_REPEATS,),
    rule=double_free_rule,
), baseline=True, category=CATEGORY_INVALID_DOUBLE_FREE)

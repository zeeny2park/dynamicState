"""glibc ptmalloc heap walker (IMP-007, part 1).

Produces the list of heap chunks ``{address, chunk size, usable size, state}`` of a RUNNING
process without stopping it: every byte is read through the adapter's zero-stop read path
(``read_memory_batch`` -> process_vm_readv / remote collector) and charged to an
:class:`~extractor.observation_budget.ObservationBudgetTracker`.  No signal is ever sent and no
ptrace attach is made.

Scope / support (refused otherwise, never guessed)
-------------------------------------------------
* Target ABI gate: IMP-015 ``FEATURE_ALLOCATOR_CHUNKS`` (x86_64 / aarch64, 64-bit little endian,
  glibc).  Non-glibc (musl, static/unknown libc) -> UNSUPPORTED_ALLOCATOR / INCONCLUSIVE.
* glibc version: :data:`SUPPORTED_GLIBC_MIN` .. :data:`SUPPORTED_GLIBC_MAX` (2.27 - 2.41).
  < 2.27 has no ``have_fastchunks`` member (different ``malloc_state`` layout); >= 2.42 reworked
  the tcache (large-chunk tcache, changed count semantics) and is not validated here.  Unknown
  version -> INCONCLUSIVE.
* A program that interposes ``malloc`` (its own allocator, jemalloc/tcmalloc/mimalloc preloaded)
  is refused as UNSUPPORTED_ALLOCATOR: the ptmalloc heap would not describe its allocations.

Locating ``main_arena`` and the struct layouts (in order of preference)
-----------------------------------------------------------------------
1. ``libc_dwarf``: a local debug image of the mapped libc (``/usr/lib/debug/.build-id/xx/yy.debug``
   or the libc itself if it carries DWARF) - ``main_arena`` address and the ``malloc_state`` /
   ``_heap_info`` / ``tcache_perthread_struct`` layouts are read from DWARF.
2. ``libc_symtab``: only an ELF ``.symtab`` with ``main_arena`` -> address from the symbol, layout
   from the version table :func:`layout_for_version`.
3. ``signature_scan``: no symbols (the usual production case): scan libc's writable data
   (``.data``/``.bss``) for the ``malloc_state`` signature - empty bins point to themselves
   (``bin->fd == bin->bk == bin_at(i)``) - and accept only a candidate whose ``next`` ring closes
   back on itself, whose ``top`` is a valid chunk header and whose counters are plausible.
Every located arena is validated structurally regardless of the method.

Walk
----
* main arena: the ``[heap]`` (brk) segment from its start to ``top``;
* thread arenas (``main_arena.next`` ring): every ``heap_info`` segment of the arena
  (``heap_for_ptr(top)`` then the ``prev`` chain), first chunk after ``heap_info`` (+ the arena
  struct for the arena's first heap), ``h->ar_ptr == arena`` is checked;
* chunks are walked sequentially; a chunk is in use when the NEXT chunk's PREV_INUSE bit is set
  (via :class:`~extractor.allocator_inspector.GlibcPtMallocInspector`), except that chunks that
  sit in a tcache (``tcache_perthread_struct`` of every thread, found by validated signature) or a
  fastbin (``malloc_state.fastbinsY``) are reported FREE although their in-use bit is still set.
  Safe-linking (glibc >= 2.32) pointers are demangled: ``REVEAL_PTR(p) = (&p >> 12) ^ p``;
* mmapped chunks (IS_MMAPPED) are on no arena list: they are found by validating the chunk header
  at the start of anonymous mappings (and of adjacent chunks in merged mappings), and on demand
  through :meth:`HeapWalker.probe_mmapped` for addresses met by the referrer scan.

Torn reads
----------
The target keeps running while it is read.  Every header is bounds-checked (alignment, minimum
size, inside the segment, IS_MMAPPED never set inside an arena heap) - a failure is a *hard*
inconsistency: the whole segment is re-read together with the arena's ``top`` in one batch and
walked again (``max_retries`` times), then the rest of the segment is reported as an
``inconsistent`` region.  Metadata checks (``prev_size`` of the next chunk equal to the size of a
free chunk, NON_MAIN_ARENA consistent with the arena for in-use chunks) are *soft*: the size chain
is intact, the walk continues and the chunks are counted in ``soft_inconsistency_count``.  Any
inconsistency makes the status PARTIAL.  Every hard inconsistency records where each read attempt hit
it (``attempt_sites``) and the chunk before it (``previous_chunk``): :mod:`extractor.heap_integrity` decides
whether it is a torn read or stable damage (IMP-009).  After the retries the walk is *resynchronised*
(:meth:`HeapWalker._resync`): the first position after the bad header from which a valid header chain reaches
``top`` (or the end of an old thread heap) is found by a bounded forward scan, the bytes in between become one
damaged region entry (``damaged_regions``) and the chunks after it are listed, so one damaged header does not
hide the rest of the heap.  Never a crash or an unbounded loop: iteration is capped
by ``segment_size / MINSIZE`` and every list (arenas, heaps, fastbins, tcache) is bounded and
cycle-checked.  The arena ``top`` is re-read after the walk; a move is reported as a warning.
"""

import bisect
import os
import re
import struct
import time
from array import array
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from .allocator_inspector import GlibcPtMallocInspector
from .observation_budget import ObservationBudgetLimits, ObservationBudgetTracker
from .target_abi import (
    _GLIBC_BANNER_RE,
    FEATURE_ALLOCATOR_CHUNKS,
    SUPPORT_INCONCLUSIVE,
    SUPPORT_SUPPORTED,
    TargetABI,
    check_support,
    detect_target_abi,
)

_MAX_BANNER_SCAN = 4 * 1024 * 1024

# --------------------------------------------------------------------------------------
# Status values
# --------------------------------------------------------------------------------------
STATUS_OK = "OK"
STATUS_PARTIAL = "PARTIAL"                          # walked, but some region inconsistent / budget hit
STATUS_UNSUPPORTED_ALLOCATOR = "UNSUPPORTED_ALLOCATOR"
STATUS_UNSUPPORTED_GLIBC_VERSION = "UNSUPPORTED_GLIBC_VERSION"
STATUS_INCONCLUSIVE = SUPPORT_INCONCLUSIVE          # "INCONCLUSIVE_ABI_UNDETECTED"
STATUS_ARENA_NOT_FOUND = "ARENA_NOT_FOUND"
STATUS_BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
STATUS_TARGET_UNREADABLE = "TARGET_UNREADABLE"

SUPPORTED_GLIBC_MIN = (2, 27)
SUPPORTED_GLIBC_MAX = (2, 41)
SUPPORTED_ARCHITECTURES = ("x86_64", "aarch64")

# chunk states
ST_IN_USE = 1
ST_FREE = 2            # free chunk in a regular bin (unsorted / small / large)
ST_TCACHE = 3          # free, cached in a thread's tcache (in-use bit still set)
ST_FASTBIN = 4         # free, in an arena fastbin (in-use bit still set)
ST_TOP = 5             # the arena's top chunk (wilderness)
ST_MMAPPED = 6         # in use, IS_MMAPPED
ST_INTERNAL = 7        # in use by the allocator itself (tcache_perthread_struct)

STATE_NAMES = {
    ST_IN_USE: "in_use",
    ST_FREE: "free",
    ST_TCACHE: "free_tcache",
    ST_FASTBIN: "free_fastbin",
    ST_TOP: "top",
    ST_MMAPPED: "in_use_mmapped",
    ST_INTERNAL: "allocator_internal",
}
IN_USE_STATES = (ST_IN_USE, ST_MMAPPED, ST_INTERNAL)

PREV_INUSE = 0x1
IS_MMAPPED = 0x2
NON_MAIN_ARENA = 0x4
SIZE_BITS = 0x7

# Allocator libraries that replace ptmalloc when mapped (refused).
_FOREIGN_ALLOCATOR_RE = re.compile(r"lib(?:jemalloc|tcmalloc|tcmalloc_minimal|mimalloc|hoard|rpmalloc|snmalloc|scudo)[\w.+-]*\.so")
_MALLOC_ENTRY_SYMBOLS = (b"malloc", b"free", b"calloc", b"realloc")


class HeapWalkBudgetExhausted(RuntimeError):
    pass


# --------------------------------------------------------------------------------------
# Layouts
# --------------------------------------------------------------------------------------
@dataclass
class GlibcMallocLayout:
    """ptmalloc layout for LP64 little-endian glibc (x86_64 / aarch64)."""
    version: Tuple[int, int]
    source: str = "layout_table"              # layout_table | libc_dwarf
    size_sz: int = 8
    malloc_alignment: int = 16
    min_chunk: int = 32
    nfastbins: int = 10
    nbins: int = 128
    ms: Dict[str, int] = field(default_factory=dict)   # malloc_state member offsets
    ms_size: int = 0x898
    heap_info_size: Optional[int] = None      # validated at runtime (h->ar_ptr == arena)
    heap_max_size: int = 64 * 1024 * 1024     # 2 * DEFAULT_MMAP_THRESHOLD_MAX (LP64)
    tcache_bins: int = 64
    tcache_count_width: int = 2
    safe_linking: bool = True
    tcache_key_is_struct: bool = False        # 2.29-2.33: entry->key == tcache struct pointer

    @property
    def tcache_struct_size(self) -> int:
        return self.tcache_bins * self.tcache_count_width + self.tcache_bins * self.size_sz

    @property
    def tcache_chunk_size(self) -> int:
        req = self.tcache_struct_size + self.size_sz
        return max(self.min_chunk, (req + self.malloc_alignment - 1) & ~(self.malloc_alignment - 1))

    @property
    def tcache_entries_off(self) -> int:
        return self.tcache_bins * self.tcache_count_width

    def bin_at(self, arena: int, i: int) -> int:
        """Address used as the fake chunk for bin ``i`` (1-based), as glibc's ``bin_at``."""
        return arena + self.ms["bins"] + (i - 1) * 2 * self.size_sz - 2 * self.size_sz

    def to_dict(self) -> Dict[str, Any]:
        return {
            "glibc_version": "%d.%d" % self.version,
            "source": self.source,
            "malloc_state_size": self.ms_size,
            "malloc_state_offsets": dict(self.ms),
            "heap_info_size": self.heap_info_size,
            "heap_max_size": self.heap_max_size,
            "tcache_bins": self.tcache_bins,
            "tcache_count_width": self.tcache_count_width,
            "tcache_struct_chunk_size": self.tcache_chunk_size,
            "safe_linking": self.safe_linking,
        }


# malloc_state (LP64) for glibc >= 2.27: mutex(4) flags(4) have_fastchunks(4) pad(4) fastbinsY[10]
# top last_remainder bins[254] binmap[4] next next_free attached_threads system_mem max_system_mem.
_MS_OFFSETS_227 = {
    "mutex": 0, "flags": 4, "have_fastchunks": 8, "fastbinsY": 16, "top": 96, "last_remainder": 104,
    "bins": 112, "binmap": 2144, "next": 2160, "next_free": 2168, "attached_threads": 2176,
    "system_mem": 2184, "max_system_mem": 2192,
}


def parse_glibc_version(ver: Optional[str]) -> Optional[Tuple[int, int]]:
    if not ver:
        return None
    m = re.match(r"^\s*(\d+)\.(\d+)", str(ver))
    return (int(m.group(1)), int(m.group(2))) if m else None


def layout_for_version(version: Tuple[int, int]) -> Optional[GlibcMallocLayout]:
    """Documented fallback layout table (LP64 little endian), keyed by glibc version.

    2.27-2.29: tcache counts are ``char``; 2.30+: ``uint16_t``.  2.29+: ``tcache_entry.key``
    (== tcache struct until 2.33, random ``tcache_key`` from 2.34).  2.32+: safe-linking.
    2.35+: ``heap_info.pagesize`` (sizeof 48 instead of 32) - validated at runtime anyway.
    """
    if version < SUPPORTED_GLIBC_MIN or version > SUPPORTED_GLIBC_MAX:
        return None
    return GlibcMallocLayout(
        version=version,
        ms=dict(_MS_OFFSETS_227),
        ms_size=0x898,
        heap_info_size=48 if version >= (2, 35) else 32,
        tcache_count_width=2 if version >= (2, 30) else 1,
        safe_linking=version >= (2, 32),
        tcache_key_is_struct=(2, 29) <= version <= (2, 33),
    )


def layout_from_dwarf(idx: Any, version: Tuple[int, int]) -> Optional[GlibcMallocLayout]:
    """Build the layout from libc DWARF (``struct malloc_state`` etc.); None if not present."""
    base = layout_for_version(version)
    if base is None:
        return None
    try:
        ms_t = idx.resolve_type_by_name("malloc_state")
        if ms_t is None or not ms_t.members:
            return None
        offs = {m.name: int(m.offset) for m in ms_t.members if m.name}
        if not all(k in offs for k in ("fastbinsY", "top", "bins", "next", "system_mem")):
            return None
        base.ms = {k: offs.get(k, base.ms.get(k)) for k in set(base.ms) | set(offs)}
        base.ms_size = int(ms_t.byte_size or base.ms_size)
        hi = idx.resolve_type_by_name("_heap_info") or idx.resolve_type_by_name("heap_info")
        if hi is not None and hi.byte_size:
            base.heap_info_size = int(hi.byte_size)
        tc = idx.resolve_type_by_name("tcache_perthread_struct")
        if tc is not None and tc.members:
            for m in tc.members:
                if m.name == "counts":
                    arr = idx.resolve_canonical_type(m.type_offset)
                    elem = idx.resolve_canonical_type(arr.target_type_offset) if arr is not None else None
                    if elem is not None and elem.byte_size:
                        base.tcache_count_width = int(elem.byte_size)
                    if arr is not None and arr.array_count:
                        base.tcache_bins = int(arr.array_count)
        base.source = "libc_dwarf"
        return base
    except Exception:  # noqa: BLE001 - fall back to the table
        return None


# --------------------------------------------------------------------------------------
# Minimal ELF symbol reader (symtab / dynsym) - local files only
# --------------------------------------------------------------------------------------
def elf_symbols(path: str, wanted: Optional[Iterable[bytes]] = None, sections: Sequence[str] = (".symtab", ".dynsym"),
                defined_only: bool = True, max_bytes: int = 256 * 1024 * 1024) -> Dict[bytes, int]:
    """Return {name: st_value} for (wanted) symbols of a 64-bit little-endian ELF file."""
    want = set(wanted) if wanted is not None else None
    out: Dict[bytes, int] = {}
    try:
        if os.path.getsize(path) > max_bytes:
            return out
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return out
    if len(data) < 64 or data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        return out
    e_shoff, = struct.unpack_from("<Q", data, 0x28)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 0x3A)
    if not e_shoff or e_shentsize < 64 or e_shoff + e_shnum * e_shentsize > len(data):
        return out
    secs = []
    for i in range(e_shnum):
        o = e_shoff + i * e_shentsize
        name, typ, _flags, _addr, off, size, link, _info, _align, entsize = struct.unpack_from("<IIQQQQIIQQ", data, o)
        secs.append((name, typ, off, size, link, entsize))
    if e_shstrndx >= len(secs):
        return out
    shstr_off = secs[e_shstrndx][2]

    def _sname(n: int) -> str:
        e = data.find(b"\x00", shstr_off + n)
        return data[shstr_off + n:e].decode("ascii", "replace")

    for name_i, typ, off, size, link, entsize in secs:
        if _sname(name_i) not in sections or typ not in (2, 11) or entsize < 24 or link >= len(secs):
            continue
        str_off = secs[link][2]
        for k in range(size // entsize):
            so = off + k * entsize
            if so + 24 > len(data):
                break
            st_name, st_info, _st_other, st_shndx, st_value, _st_size = struct.unpack_from("<IBBHQQ", data, so)
            if not st_name or (defined_only and st_shndx == 0):
                continue
            e = data.find(b"\x00", str_off + st_name)
            nm = data[str_off + st_name:e]
            if want is not None and nm not in want:
                continue
            out.setdefault(nm, st_value)
    return out


# --------------------------------------------------------------------------------------
# Budgeted zero-stop reader + snapshot
# --------------------------------------------------------------------------------------
class BudgetedReader:
    """All target reads of the heap analysis go through here: the adapter's zero-stop batch
    read path, split into slices of at most ``max_slice`` bytes, and charged to the budget."""

    def __init__(self, adapter: Any, pid: int, budget: ObservationBudgetTracker,
                 max_slice: int = 4 * 1024 * 1024, max_batch: int = 64, profile_id: str = "heap_ownership"):
        self.adapter = adapter
        self.pid = int(pid)
        self.budget = budget
        self.max_slice = max(4096, int(max_slice))
        self.max_batch = max(1, int(max_batch))
        self.profile_id = profile_id
        self.bytes_read = 0
        self.slices_read = 0
        self.batches = 0
        self.failed_slices = 0
        self.read_wall_ms = 0.0

    def account_external(self, nbytes: int, label: str = "") -> None:
        """Charge bytes read by a delegated existing API (frame decoder, thread discovery)."""
        if nbytes > 0:
            self.budget.record_read(bytes_read=int(nbytes), stop_ms=0.0, consistency_level="WEAK_UNSTOPPED",
                                    profile_id=self.profile_id)
            self.bytes_read += int(nbytes)

    def read_ranges(self, ranges: Sequence[Tuple[int, int]]) -> List[Optional[bytes]]:
        """Read every (addr, size); returns bytes (possibly shorter on a partial read) or None."""
        plan: List[Tuple[int, int, int]] = []          # (range idx, addr, size)
        for ri, (a, n) in enumerate(ranges):
            a, n = int(a), int(n)
            off = 0
            while off < n:
                sz = min(self.max_slice, n - off)
                plan.append((ri, a + off, sz))
                off += sz
        total = sum(p[2] for p in plan)
        ok, why, _ = self.budget.check_pre_execution(estimated_bytes=total, profile_id=self.profile_id)
        if not ok:
            raise HeapWalkBudgetExhausted(why or "budget exhausted")
        parts: List[List[Optional[bytes]]] = [[] for _ in ranges]
        for b in range(0, len(plan), self.max_batch):
            grp = plan[b:b + self.max_batch]
            t0 = time.monotonic()
            res = self.adapter.read_memory_batch(self.pid, [(a, n) for _, a, n in grp])
            dt = (time.monotonic() - t0) * 1000.0
            self.read_wall_ms += dt
            self.batches += 1
            got = 0
            for (ri, a, n), r in zip(grp, res):
                data = r[0] if r else None
                if data is None or len(data) == 0:
                    self.failed_slices += 1
                    parts[ri].append(None)
                    continue
                got += len(data)
                parts[ri].append(bytes(data))
                if len(data) < n:
                    self.failed_slices += 1
                    parts[ri].append(None)       # terminate this range at the partial read
            self.slices_read += len(grp)
            self.bytes_read += got
            self.budget.record_read(bytes_read=got, latency_us=dt * 1000.0, stop_ms=0.0,
                                    consistency_level="WEAK_UNSTOPPED", profile_id=self.profile_id,
                                    physical_reads=len(grp))
        out: List[Optional[bytes]] = []
        for p in parts:
            buf = bytearray()
            for piece in p:
                if piece is None:
                    break
                buf += piece
            out.append(bytes(buf) if buf else None)
        return out

    def read(self, addr: int, size: int) -> Optional[bytes]:
        return self.read_ranges([(addr, size)])[0]

    def stats(self) -> Dict[str, Any]:
        return {
            "bytes_read": self.bytes_read,
            "slices_read": self.slices_read,
            "batches": self.batches,
            "failed_slices": self.failed_slices,
            "read_wall_ms": round(self.read_wall_ms, 2),
            "target_stop_ms": 0.0,
        }


class MemorySnapshot:
    """Locally held copies of target memory regions ({start: bytes}), each read at one moment."""

    def __init__(self) -> None:
        self._starts: List[int] = []
        self._bufs: List[bytes] = []

    def add(self, start: int, data: bytes) -> None:
        end = start + len(data)
        # a newer, larger read replaces the regions it fully covers
        keep = [(s, b) for s, b in zip(self._starts, self._bufs) if not (start <= s and s + len(b) <= end)]
        self._starts = [s for s, _ in keep]
        self._bufs = [b for _, b in keep]
        i = bisect.bisect_left(self._starts, start)
        self._starts.insert(i, start)
        self._bufs.insert(i, data)

    def locate(self, addr: int, size: int = 1) -> Optional[Tuple[bytes, int]]:
        i = bisect.bisect_right(self._starts, addr) - 1
        # regions may overlap (e.g. an arena struct inside its heap segment): look a few back
        for j in range(i, max(-1, i - 8), -1):
            s = self._starts[j]
            b = self._bufs[j]
            off = addr - s
            if off + size <= len(b):
                return b, off
        return None

    def u64(self, addr: int) -> Optional[int]:
        loc = self.locate(addr, 8)
        if loc is None:
            return None
        return struct.unpack_from("<Q", loc[0], loc[1])[0]

    def get(self, addr: int, size: int) -> Optional[bytes]:
        loc = self.locate(addr, size)
        if loc is None:
            return None
        return loc[0][loc[1]:loc[1] + size]

    def regions(self) -> List[Tuple[int, bytes]]:
        return list(zip(self._starts, self._bufs))

    @property
    def total_bytes(self) -> int:
        return sum(len(b) for b in self._bufs)


# --------------------------------------------------------------------------------------
# Chunk table
# --------------------------------------------------------------------------------------
class ChunkTable:
    """Compact sorted chunk table (parallel arrays) with containing-chunk lookup."""

    def __init__(self) -> None:
        self.addrs = array("Q")
        self.sizes = array("Q")
        self.states = bytearray()
        self.arena = array("h")     # arena index, -1 = mmapped
        self._sorted = True
        self._index: Dict[int, int] = {}

    def append(self, addr: int, size: int, state: int, arena: int) -> None:
        if self.addrs and addr <= self.addrs[-1]:
            self._sorted = False
        self.addrs.append(addr)
        self.sizes.append(size)
        self.states.append(state)
        self.arena.append(arena)

    def finalize(self) -> None:
        if not self._sorted:
            order = sorted(range(len(self.addrs)), key=self.addrs.__getitem__)
            self.addrs = array("Q", (self.addrs[i] for i in order))
            self.sizes = array("Q", (self.sizes[i] for i in order))
            self.states = bytearray(self.states[i] for i in order)
            self.arena = array("h", (self.arena[i] for i in order))
            self._sorted = True
        self._index = {a: i for i, a in enumerate(self.addrs)}

    def __len__(self) -> int:
        return len(self.addrs)

    def index_of_chunk(self, chunk_addr: int) -> Optional[int]:
        return self._index.get(chunk_addr)

    def index_of_user(self, user_ptr: int) -> Optional[int]:
        return self._index.get(user_ptr - 16)

    def find_containing(self, addr: int, user_only: bool = True) -> Optional[int]:
        """Index of the chunk whose (user) area contains ``addr``."""
        i = bisect.bisect_right(self.addrs, addr) - 1
        if i < 0:
            return None
        a = self.addrs[i]
        lo = a + 16 if user_only else a
        if lo <= addr < a + self.sizes[i]:
            return i
        return None

    def usable_size(self, i: int) -> int:
        size = self.sizes[i]
        if self.states[i] == ST_MMAPPED:
            return max(0, size - 16)
        return max(0, size - 8)

    def chunk_dict(self, i: int) -> Dict[str, Any]:
        a = self.addrs[i]
        st = self.states[i]
        return {
            "chunk_address": "0x%x" % a,
            "user_address": "0x%x" % (a + 16),
            "chunk_size": int(self.sizes[i]),
            "usable_size": self.usable_size(i),
            "state": STATE_NAMES.get(st, str(st)),
            "in_use": st in IN_USE_STATES,
            "arena_index": int(self.arena[i]),
        }


# --------------------------------------------------------------------------------------
# Result
# --------------------------------------------------------------------------------------
@dataclass
class HeapWalkResult:
    status: str
    message: str = ""
    abi: Optional[Dict[str, Any]] = None
    support: Optional[Dict[str, Any]] = None
    layout: Optional[GlibcMallocLayout] = None
    arena_location: Dict[str, Any] = field(default_factory=dict)
    arenas: List[Dict[str, Any]] = field(default_factory=list)
    chunks: ChunkTable = field(default_factory=ChunkTable)
    snapshot: MemorySnapshot = field(default_factory=MemorySnapshot)
    tcache_structs: List[Dict[str, Any]] = field(default_factory=list)
    inconsistencies: List[Dict[str, Any]] = field(default_factory=list)
    soft_inconsistencies: List[Dict[str, Any]] = field(default_factory=list)   # first examples
    soft_inconsistency_count: int = 0
    # IMP-009: regions between a damaged header and the point where the walk resynchronised
    damaged_regions: List[Dict[str, Any]] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    mappings: List[Dict[str, Any]] = field(default_factory=list)
    heap_ranges: List[Tuple[int, int]] = field(default_factory=list)   # arena segments + mmapped chunks
    stats: Dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status in (STATUS_OK, STATUS_PARTIAL)

    def counts(self) -> Dict[str, Any]:
        by_state: Dict[str, int] = {}
        in_use_bytes = 0
        for i in range(len(self.chunks)):
            st = self.chunks.states[i]
            by_state[STATE_NAMES[st]] = by_state.get(STATE_NAMES[st], 0) + 1
            if st in (ST_IN_USE, ST_MMAPPED):
                in_use_bytes += self.chunks.sizes[i]
        return {"chunks": len(self.chunks), "by_state": by_state, "in_use_chunk_bytes": int(in_use_bytes)}

    def summary(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "message": self.message,
            "abi": self.abi,
            "support": self.support,
            "layout": self.layout.to_dict() if self.layout else None,
            "arena_location": self.arena_location,
            "arenas": self.arenas,
            "counts": self.counts() if self.ok else None,
            "tcache_structs": self.tcache_structs,
            "inconsistencies": self.inconsistencies,
            "soft_inconsistency_count": self.soft_inconsistency_count,
            "soft_inconsistencies": self.soft_inconsistencies,
            "damaged_regions": self.damaged_regions,
            "warnings": self.warnings,
            "stats": self.stats,
        }


def _u64(b: bytes, off: int) -> int:
    return struct.unpack_from("<Q", b, off)[0]


def _map_bounds(m: Dict[str, Any]) -> Tuple[int, int]:
    s = m.get("start_int")
    e = m.get("end_int")
    if s is None:
        s = int(str(m.get("start", "0")), 16)
    if e is None:
        e = int(str(m.get("end", "0")), 16)
    return int(s), int(e)


# --------------------------------------------------------------------------------------
# Walker
# --------------------------------------------------------------------------------------
class HeapWalker:
    """Walk the glibc ptmalloc heap of a running process (see module docstring)."""

    def __init__(
        self,
        adapter: Any,
        pid: int,
        budget: Optional[ObservationBudgetTracker] = None,
        abi: Optional[TargetABI] = None,
        use_libc_debug_info: bool = True,
        force_signature_scan: bool = False,
        debug_search_paths: Sequence[str] = ("/usr/lib/debug",),
        max_retries: int = 2,
        max_slice: int = 4 * 1024 * 1024,
        max_arenas: int = 1024,
        max_heaps_per_arena: int = 4096,
        reader: Optional[BudgetedReader] = None,
        resync: bool = True,
    ) -> None:
        self.adapter = adapter
        self.pid = int(pid)
        self.budget = budget or ObservationBudgetTracker(ObservationBudgetLimits(
            max_wall_clock_ms=120000.0, max_bytes_read=1024 * 1024 * 1024, max_samples=1 << 30,
            max_bytes_per_observation=1 << 40, max_consecutive_read_failures=1 << 20,
            max_total_read_failures=1 << 20))
        self.reader = reader or BudgetedReader(adapter, pid, self.budget, max_slice=max_slice)
        self.abi = abi
        self.use_libc_debug_info = use_libc_debug_info
        self.force_signature_scan = force_signature_scan
        self.debug_search_paths = list(debug_search_paths)
        self.max_retries = max(0, int(max_retries))
        self.max_arenas = max_arenas
        self.max_heaps_per_arena = max_heaps_per_arena
        self.inspector = GlibcPtMallocInspector(arch_bits=64)
        self.result: Optional[HeapWalkResult] = None
        self._maps: List[Dict[str, Any]] = []
        self._anon_probe_done: set = set()
        self._layout: Optional[GlibcMallocLayout] = None
        self._arena_addrs: List[int] = []
        self.top_extensions = 0
        # IMP-009: resynchronise the walk after a damaged header (see _resync)
        self.resync = bool(resync)
        self.resync_scan_bytes = 256 * 1024
        self.resync_max_chains = 256

    # ---------------------------------------------------------------- gating
    def _gate(self) -> Optional[HeapWalkResult]:
        abi = self.abi
        if abi is None:
            abi = detect_target_abi(self.adapter, self.pid, maps=self._maps)
            self.abi = abi
        dec = check_support(abi, FEATURE_ALLOCATOR_CHUNKS)
        base = dict(abi=abi.to_dict(), support=dec.to_dict())
        if dec.status == SUPPORT_INCONCLUSIVE:
            return HeapWalkResult(status=STATUS_INCONCLUSIVE, message=dec.message, **base)
        if dec.status != SUPPORT_SUPPORTED:
            return HeapWalkResult(
                status=STATUS_UNSUPPORTED_ALLOCATOR,
                message=f"unsupported allocator: glibc ptmalloc heap walking is not supported on this target ({dec.message})",
                **base)
        ver = parse_glibc_version(abi.libc_version)
        if ver is None:
            ver = self._glibc_version_from_memory(abi)
            if ver is not None:
                abi.libc_version = "%d.%d" % ver
                abi.evidence.append("glibc version banner read from the target's mapped libc")
                base["abi"] = abi.to_dict()
        if ver is None:
            return HeapWalkResult(status=STATUS_INCONCLUSIVE,
                                  message="inconclusive: glibc version of the target could not be identified "
                                          "(the ptmalloc layout depends on it)", **base)
        if ver < SUPPORTED_GLIBC_MIN or ver > SUPPORTED_GLIBC_MAX:
            return HeapWalkResult(
                status=STATUS_UNSUPPORTED_GLIBC_VERSION,
                message="unsupported allocator version: glibc %d.%d (supported: %d.%d - %d.%d)"
                        % (ver + SUPPORTED_GLIBC_MIN + SUPPORTED_GLIBC_MAX), **base)
        foreign = self._foreign_allocator(abi)
        if foreign:
            return HeapWalkResult(status=STATUS_UNSUPPORTED_ALLOCATOR,
                                  message=f"unsupported allocator: {foreign}; the glibc ptmalloc heap does not "
                                          f"describe this program's allocations", **base)
        return None

    def _glibc_version_from_memory(self, abi: TargetABI) -> Optional[Tuple[int, int]]:
        """The ``GNU C Library ... version X.Y`` banner lives in libc's read-only data, which is
        mapped in the target: read it through the zero-stop path (works for remote targets too)."""
        if not abi.libc_path:
            return None
        ranges = []
        for m in self._maps:
            if (m.get("pathname") or "") != abi.libc_path or "w" in (m.get("permissions") or ""):
                continue
            s, e = _map_bounds(m)
            ranges.append((s, min(e - s, _MAX_BANNER_SCAN - sum(n for _, n in ranges))))
            if sum(n for _, n in ranges) >= _MAX_BANNER_SCAN:
                break
        if not ranges:
            return None
        try:
            for data in self.reader.read_ranges(ranges):
                mm = _GLIBC_BANNER_RE.search(data or b"")
                if mm:
                    return parse_glibc_version(mm.group(1).decode("ascii", "replace"))
        except HeapWalkBudgetExhausted:
            return None
        return None

    def _foreign_allocator(self, abi: TargetABI) -> Optional[str]:
        libc_path = abi.libc_path or ""
        seen = set()
        exe = None
        try:
            ident = self.adapter.get_process_identity(self.pid) or {}
            exe = ident.get("executable")
        except Exception:  # noqa: BLE001
            pass
        paths: List[str] = []
        for m in self._maps:
            p = (m.get("pathname") or "").strip()
            if not p.startswith("/") or p in seen:
                continue
            seen.add(p)
            if _FOREIGN_ALLOCATOR_RE.search(os.path.basename(p)):
                return f"allocator library {os.path.basename(p)} is mapped"
            paths.append(p)
        if self._is_remote():
            return None   # symbol check needs the module files locally
        for p in paths:
            base = os.path.basename(p)
            if p == libc_path or base.startswith(("libc.so", "libc-", "ld-linux", "ld-", "ld64", "libpthread",
                                                  "libstdc++", "libgcc_s", "libm.so", "libdl", "librt")):
                continue
            if not (p == exe or ".so" in base):
                continue
            syms = elf_symbols(p, wanted=_MALLOC_ENTRY_SYMBOLS, sections=(".dynsym",))
            if b"malloc" in syms and b"free" in syms:
                return f"malloc/free are defined (interposed) by {base}"
        return None

    def _is_remote(self) -> bool:
        try:
            return bool(self.adapter.is_remote())
        except Exception:  # noqa: BLE001
            return True

    # ---------------------------------------------------------------- arena location
    def _libc_maps(self, libc_path: str) -> List[Dict[str, Any]]:
        return [m for m in self._maps if (m.get("pathname") or "") == libc_path]

    def _libc_base(self, libc_path: str) -> Optional[int]:
        cands = [m for m in self._libc_maps(libc_path) if int(m.get("offset_int", int(str(m.get("offset", "0")), 16))) == 0]
        if not cands:
            return None
        return min(_map_bounds(m)[0] for m in cands)

    def _libc_debug_image(self, libc_path: str) -> Optional[str]:
        if self._is_remote() or not libc_path or not os.path.exists(libc_path):
            return None
        try:
            from .debug_image import inspect_elf
            ident = inspect_elf(libc_path)
        except Exception:  # noqa: BLE001
            return None
        if ident.build_id and len(ident.build_id) > 2:
            for sp in self.debug_search_paths:
                cand = os.path.join(sp, ".build-id", ident.build_id[:2], ident.build_id[2:] + ".debug")
                if os.path.exists(cand):
                    return cand
        if not ident.stripped:
            return libc_path
        return None

    def _locate_main_arena(self, abi: TargetABI, ver: Tuple[int, int]) -> Tuple[Optional[int], Optional[GlibcMallocLayout], Dict[str, Any]]:
        loc: Dict[str, Any] = {"method": None, "evidence": []}
        libc_path = abi.libc_path or ""
        base = self._libc_base(libc_path) if libc_path else None
        layout = layout_for_version(ver)
        if not self.force_signature_scan and base is not None:
            dbg = self._libc_debug_image(libc_path)
            if dbg:
                loc["debug_image"] = dbg
                if self.use_libc_debug_info:
                    try:
                        from .dwarf_indexer import DwarfIndexer
                        idx = DwarfIndexer.get_index(dbg)
                        dl = layout_from_dwarf(idx, ver)
                        vars_ = [v for v in idx.variables_by_name.get("main_arena", []) if v.link_time_address]
                        if dl is not None and vars_:
                            loc["method"] = "libc_dwarf"
                            loc["evidence"].append(f"main_arena and malloc_state layout from DWARF of {dbg}")
                            return base + int(vars_[0].link_time_address), dl, loc
                    except Exception as exc:  # noqa: BLE001
                        loc["evidence"].append(f"libc DWARF unusable: {exc}")
                syms = elf_symbols(dbg, wanted=[b"main_arena"], sections=(".symtab",))
                if b"main_arena" in syms and layout is not None:
                    loc["method"] = "libc_symtab"
                    loc["evidence"].append(f"main_arena from .symtab of {dbg}; layout from glibc {ver[0]}.{ver[1]} table")
                    return base + syms[b"main_arena"], layout, loc
        if layout is None:
            return None, None, loc
        addr = self._signature_scan(libc_path, layout, loc)
        if addr is not None:
            loc["method"] = "signature_scan"
        return addr, layout, loc

    def _signature_scan(self, libc_path: str, layout: GlibcMallocLayout, loc: Dict[str, Any]) -> Optional[int]:
        """Find main_arena in libc's writable data by the self-referencing empty-bin signature."""
        regions: List[Tuple[int, int]] = []
        maps = sorted(self._maps, key=lambda m: _map_bounds(m)[0])
        last_libc_end = None
        for m in maps:
            s, e = _map_bounds(m)
            p = (m.get("pathname") or "")
            perms = m.get("permissions") or ""
            if p == libc_path and "w" in perms and "r" in perms:
                regions.append((s, e))
            if p == libc_path:
                last_libc_end = e
        if last_libc_end is not None:
            for m in maps:
                s, e = _map_bounds(m)
                if s == last_libc_end and not (m.get("pathname") or "") and "w" in (m.get("permissions") or ""):
                    regions.append((s, min(e, s + 1024 * 1024)))   # libc .bss continuation
        if not regions:
            loc["evidence"].append("signature scan: no writable libc data mapping found")
            return None
        datas = self.reader.read_ranges([(s, e - s) for s, e in regions])
        bins_off = layout.ms["bins"]
        cands: Dict[int, int] = {}
        for (s, _e), d in zip(regions, datas):
            if not d:
                continue
            self.result.snapshot.add(s, d)
            words = memoryview(d)[: len(d) // 8 * 8].cast("Q")
            n = len(words)
            for wi in range(n - 1):
                w = words[wi]
                if w == s + wi * 8 - 16 and words[wi + 1] == w:
                    # bin fd at s+wi*8; arena = fd_addr - bins_off - 16*k
                    pos = s + wi * 8
                    for k in range(0, 127):
                        a = pos - bins_off - 16 * k
                        if a < s:
                            break
                        cands[a] = cands.get(a, 0) + 1
        best = None
        for a, hits in sorted(cands.items(), key=lambda kv: -kv[1]):
            if hits < 32:
                break
            if self._validate_arena_struct(a, layout, main=True):
                if best is not None:
                    loc["evidence"].append("signature scan: more than one valid main_arena candidate - refused")
                    return None
                best = a
        if best is None:
            loc["evidence"].append("signature scan: no candidate passed malloc_state validation")
        else:
            loc["evidence"].append(f"signature scan: malloc_state at 0x{best:x} (empty-bin self references, next ring closed)")
        return best

    def _arena_bytes(self, a: int, layout: GlibcMallocLayout) -> Optional[bytes]:
        b = self.result.snapshot.get(a, layout.ms_size)
        if b is None:
            b = self.reader.read(a, layout.ms_size)
            if b is not None and len(b) >= layout.ms_size:
                self.result.snapshot.add(a, b)
            else:
                return None
        return b

    def _validate_arena_struct(self, a: int, layout: GlibcMallocLayout, main: bool) -> bool:
        b = self.result.snapshot.get(a, layout.ms_size)
        if b is None:
            return False
        ms = layout.ms
        mutex, flags = struct.unpack_from("<iI", b, ms["mutex"])
        if mutex not in (0, 1, 2) or flags > 0xff:
            return False
        top = _u64(b, ms["top"])
        if top == 0 or top % 16:
            return False
        if _u64(b, ms["attached_threads"]) > 1 << 20:
            return False
        sysmem = _u64(b, ms["system_mem"])
        if sysmem > 1 << 46 or sysmem > _u64(b, ms["max_system_mem"]) and _u64(b, ms["max_system_mem"]) != 0:
            return False
        # empty bins must point to themselves; non-empty bins point to 16-aligned chunks
        self_refs = 0
        for i in range(1, 127):
            fd = _u64(b, ms["bins"] + (i - 1) * 16)
            bk = _u64(b, ms["bins"] + (i - 1) * 16 + 8)
            ba = layout.bin_at(a, i)
            if fd == ba and bk == ba:
                self_refs += 1
            elif fd == ba or bk == ba or fd % 16 or bk % 16 or fd == 0 or bk == 0:
                return False
        if self_refs < 16:
            return False
        nxt = _u64(b, ms["next"])
        if nxt == 0 or nxt % 8:
            return False
        if main:
            # the next ring must come back to this arena
            cur = nxt
            for _ in range(self.max_arenas):
                if cur == a:
                    return True
                cb = self._arena_bytes(cur, layout)
                if cb is None:
                    return False
                cur = _u64(cb, ms["next"])
            return False
        return True

    # ---------------------------------------------------------------- walk
    def walk(self) -> HeapWalkResult:
        t0 = time.monotonic()
        try:
            self._maps = list(self.adapter.get_proc_maps(self.pid) or [])
        except Exception as exc:  # noqa: BLE001
            return HeapWalkResult(status=STATUS_TARGET_UNREADABLE, message=f"cannot read memory maps: {exc}")
        refused = self._gate()
        if refused is not None:
            refused.stats = {"wall_ms": round((time.monotonic() - t0) * 1000.0, 2), **self.reader.stats()}
            self.result = refused
            return refused
        abi = self.abi
        ver = parse_glibc_version(abi.libc_version)
        res = HeapWalkResult(status=STATUS_OK, abi=abi.to_dict(),
                             support=check_support(abi, FEATURE_ALLOCATOR_CHUNKS).to_dict(), mappings=self._maps)
        self.result = res
        try:
            main_arena, layout, loc = self._locate_main_arena(abi, ver)
            res.arena_location = loc
            res.layout = layout
            if main_arena is None or layout is None:
                res.status = STATUS_ARENA_NOT_FOUND
                res.message = "main_arena could not be located (no libc symbols and no valid malloc_state signature)"
                return self._finish(res, t0)
            loc["main_arena"] = "0x%x" % main_arena
            valid = False
            for _attempt in range(self.max_retries + 1):
                if self._arena_bytes(main_arena, layout) is not None and \
                        self._validate_arena_struct(main_arena, layout, main=True):
                    valid = True
                    break
                fresh = self.reader.read(main_arena, layout.ms_size)      # torn read of the arena: re-read
                if fresh is not None and len(fresh) >= layout.ms_size:
                    res.snapshot.add(main_arena, fresh)
            if not valid:
                res.status = STATUS_ARENA_NOT_FOUND
                res.message = f"main_arena candidate 0x{main_arena:x} failed malloc_state validation"
                return self._finish(res, t0)
            arenas = [main_arena]
            cur = _u64(self._arena_bytes(main_arena, layout), layout.ms["next"])
            while cur != main_arena and len(arenas) < self.max_arenas:
                if cur in arenas or self._arena_bytes(cur, layout) is None:
                    res.warnings.append(f"arena ring broken at 0x{cur:x}")
                    break
                arenas.append(cur)
                cur = _u64(self._arena_bytes(cur, layout), layout.ms["next"])
            self._layout = layout
            self._arena_addrs = list(arenas)
            for ai, a in enumerate(arenas):
                self._walk_arena(ai, a, layout, is_main=(ai == 0))
            # did the heap move under us?  (top re-read after the walk; informational)
            tops = self.reader.read_ranges([(a + layout.ms["top"], 8) for a in arenas])
            for ai, (a, tb) in enumerate(zip(arenas, tops)):
                if tb and len(tb) == 8 and "0x%x" % _u64(tb, 0) != res.arenas[ai]["top"]:
                    res.warnings.append(f"arena {ai}: top moved during the walk (target allocating concurrently); "
                                        f"chunks carved from top after the arena was read are not listed")
            self._scan_mmapped_mappings(layout)
            res.chunks.finalize()
            self._mark_tcache(layout, arenas)
            self._mark_fastbins(layout, arenas)
        except HeapWalkBudgetExhausted as exc:
            res.status = STATUS_BUDGET_EXHAUSTED
            res.message = f"observation budget exhausted during heap walk: {exc}"
            res.chunks.finalize()
        if res.status == STATUS_OK and (res.inconsistencies or res.soft_inconsistency_count):
            res.status = STATUS_PARTIAL
            res.message = (f"{len(res.inconsistencies)} region(s) unwalkable and {res.soft_inconsistency_count} chunk(s) "
                           f"with inconsistent metadata (target modified the heap while it was read, or the "
                           f"metadata is damaged: see heap_integrity for the stable/transient decision)")
        return self._finish(res, t0)

    def _finish(self, res: HeapWalkResult, t0: float) -> HeapWalkResult:
        res.stats = {"wall_ms": round((time.monotonic() - t0) * 1000.0, 2), **self.reader.stats(),
                     "snapshot_bytes": res.snapshot.total_bytes}
        return res

    def _walk_arena(self, ai: int, a: int, layout: GlibcMallocLayout, is_main: bool) -> None:
        res = self.result
        ms = layout.ms
        ab = self._arena_bytes(a, layout)
        top = _u64(ab, ms["top"])
        info: Dict[str, Any] = {"index": ai, "address": "0x%x" % a, "is_main": is_main, "top": "0x%x" % top,
                                "system_mem": _u64(ab, ms["system_mem"]), "segments": []}
        res.arenas.append(info)
        if top == layout.bin_at(a, 1):
            info["note"] = "arena never used (top is the initial fake chunk)"
            return
        if is_main:
            seg = None
            for attempt in range(2):
                for m in self._maps:
                    s, e = _map_bounds(m)
                    if s <= top < e:
                        seg = (s, e, m)
                        break
                if seg is not None or attempt:
                    break
                # the brk heap grew/shrank since the maps were read: refresh both and look again
                self._maps = list(self.adapter.get_proc_maps(self.pid) or [])
                res.mappings = self._maps
                fresh = self.reader.read(a, layout.ms_size)
                if fresh is not None and len(fresh) >= layout.ms_size:
                    res.snapshot.add(a, fresh)
                    top = _u64(fresh, ms["top"])
                    info["top"] = "0x%x" % top
            if seg is None:
                res.inconsistencies.append({"arena": ai, "reason": f"main arena top 0x{top:x} is not mapped"})
                return
            s, e, m = seg
            if (m.get("pathname") or "") != "[heap]":
                res.warnings.append("main arena top is not in [heap] (non-contiguous main arena); walking its mapping")
            first = s if (s + 16) % 16 == 0 else ((s + 15) & ~15)
            self._walk_segment(ai, a, layout, first, e, top, s, is_main=True, info=info)
            return
        # thread arena: heaps from heap_for_ptr(top) backwards through prev
        hmask = ~(layout.heap_max_size - 1) & 0xFFFFFFFFFFFFFFFF
        h = top & hmask
        heaps: List[Tuple[int, int]] = []
        seen = set()
        while h and h not in seen and len(heaps) < self.max_heaps_per_arena:
            seen.add(h)
            hb = self.reader.read(h, 48)
            if hb is None or len(hb) < 32:
                res.inconsistencies.append({"arena": ai, "reason": f"heap_info at 0x{h:x} unreadable"})
                break
            ar_ptr, prev, hsize = struct.unpack_from("<QQQ", hb, 0)
            if ar_ptr != a or hsize == 0 or hsize > layout.heap_max_size:
                res.inconsistencies.append({"arena": ai, "reason": f"heap_info at 0x{h:x} does not belong to arena "
                                                                   f"0x{a:x} (ar_ptr=0x{ar_ptr:x}, size={hsize})"})
                break
            heaps.append((h, hsize))
            h = prev & hmask if prev else 0
        for h, hsize in reversed(heaps):
            if h < a < h + 4096:
                # the arena's first heap: heap_info, malloc_state, then chunks
                if layout.heap_info_size is None or h + layout.heap_info_size != a:
                    hi = a - h
                    if hi in (32, 48):
                        layout.heap_info_size = hi
                first = (a + layout.ms_size + 15) & ~15
            else:
                first = h + (layout.heap_info_size or 48)
            self._walk_segment(ai, a, layout, first, h + hsize, top, h, is_main=False, info=info)

    def _walk_segment(self, ai: int, arena: int, layout: GlibcMallocLayout, first: int, end: int, top: int,
                      seg_start: int, is_main: bool, info: Dict[str, Any]) -> None:
        """Walk one heap segment.  A *hard* inconsistency (impossible size, chunk past the end,
        IS_MMAPPED inside an arena) means the copy is torn: the whole segment is re-read together
        with the arena's ``top`` in one batch and walked again (``max_retries`` times); after that
        the rest of the segment is reported as inconsistent.  *Soft* inconsistencies (a free
        chunk's size differs from the next ``prev_size``, NON_MAIN_ARENA flag mismatch) are typical
        of a chunk being freed/merged at the moment of the copy: the walk continues (the size chain
        is intact) and the affected chunks are counted and reported."""
        res = self.result
        top_slot = arena + layout.ms["top"]
        attempt = 0
        sites: List[str] = []          # IMP-009: where each read attempt hit its hard inconsistency
        while True:
            if attempt == 0:
                buf = self.reader.read(seg_start, end - seg_start)
            else:
                fresh_top, buf = self.reader.read_ranges([(top_slot, 8), (seg_start, end - seg_start)])
                if fresh_top and len(fresh_top) == 8:
                    top = _u64(fresh_top, 0)
            if buf is None:
                res.inconsistencies.append({"arena": ai, "segment": "0x%x" % seg_start, "reason": "segment unreadable"})
                return
            pending, hard, soft, reached_top = self._walk_buffer(buf, layout, first, seg_start, top, is_main)
            if hard is not None:
                sites.append(hard["at"])
            if hard is None or attempt >= self.max_retries:
                break
            attempt += 1
        seg_end = seg_start + len(buf)
        seg_info = {"start": "0x%x" % seg_start, "end": "0x%x" % seg_end, "first_chunk": "0x%x" % first,
                    "chunks": len(pending), "reached_top": reached_top, "read_attempts": attempt + 1}
        info["segments"].append(seg_info)
        res.heap_ranges.append((seg_start, seg_end))
        if hard is not None:
            hard.update({"arena": ai, "segment": "0x%x" % seg_start, "retries": attempt, "attempt_sites": sites,
                         "previous_chunk": "0x%x" % pending[-1][0] if pending else None})
            res.inconsistencies.append(hard)
            if self.resync:
                more, soft2, rs = self._resync(buf, layout, int(hard["at"], 16), seg_start, top, is_main)
                if rs is not None:
                    # IMP-009: one damaged header must not hide the rest of the segment
                    hard.update(rs)
                    hard["unwalked_bytes"] = rs["resynchronised_at_int"] - int(hard["at"], 16)
                    del hard["resynchronised_at_int"]
                    pending.extend(more)
                    soft.extend(soft2)
                    seg_info["chunks"] = len(pending)
                    seg_info["reached_top"] = rs["resync_reached_top"]
                    res.damaged_regions.append({"arena": ai, "at": hard["at"], "reason": hard["reason"],
                                                "inferred_size": hard["unwalked_bytes"],
                                                "resynchronised_at": hard["resynchronised_at"],
                                                "previous_chunk": hard.get("previous_chunk")})
        if soft:
            seg_info["chunks_with_inconsistent_metadata"] = len(soft)
            res.soft_inconsistencies.extend({"arena": ai, "at": "0x%x" % p, "reason": r} for p, r in soft[:16])
            res.soft_inconsistency_count += len(soft)
        for p, sz, st in pending:
            res.chunks.append(p, sz, st, ai)
        res.snapshot.add(seg_start, bytes(buf))

    def _walk_buffer(self, buf: bytes, layout: GlibcMallocLayout, first: int, seg_start: int, top: int,
                     is_main: bool):
        """Sequential chunk walk over a local copy.  Returns (chunks, hard, soft, reached_top)."""
        end = seg_start + len(buf)
        pos = first
        cap = (end - first) // layout.min_chunk + 2           # bounded: never loops
        pending: List[Tuple[int, int, int]] = []
        soft: List[Tuple[int, str]] = []
        min_chunk, align = layout.min_chunk, layout.malloc_alignment
        n = 0
        while pos < end:
            if n >= cap:
                return pending, {"at": "0x%x" % pos, "reason": "iteration cap reached", "unwalked_bytes": end - pos}, soft, False
            off = pos - seg_start
            if pos == top:
                size = (_u64(buf, off + 8) & ~SIZE_BITS) if off + 16 <= len(buf) else 0
                pending.append((pos, size, ST_TOP))
                return pending, None, soft, True
            if off + 16 > len(buf):
                return pending, {"at": "0x%x" % pos, "reason": "chunk header beyond segment",
                                 "unwalked_bytes": end - pos}, soft, False
            sf = _u64(buf, off + 8)
            size = sf & ~SIZE_BITS
            if not is_main and size in (0, 16) and pos + 48 >= end:
                return pending, None, soft, False             # fencepost at the end of an old heap
            reason = None
            if size < min_chunk or size % align:
                reason = "invalid chunk size 0x%x" % size
            elif pos + size > end:
                reason = "chunk size 0x%x runs past segment end" % size
            elif sf & IS_MMAPPED:
                reason = "IS_MMAPPED set on an arena chunk"
            if reason is not None:
                return pending, {"at": "0x%x" % pos, "reason": reason, "unwalked_bytes": end - pos}, soft, False
            noff = off + size
            if noff + 16 <= len(buf):
                in_use = bool(_u64(buf, noff + 8) & PREV_INUSE)
                if not in_use and _u64(buf, noff) != size:
                    soft.append((pos, "free chunk size differs from next chunk's prev_size"))
                elif in_use and bool(sf & NON_MAIN_ARENA) == is_main:
                    soft.append((pos, "NON_MAIN_ARENA flag inconsistent with the arena"))
            else:
                in_use = True
            pending.append((pos, size, ST_IN_USE if in_use else ST_FREE))
            pos += size
            n += 1
        return pending, None, soft, False

    def _resync(self, buf: bytes, layout: GlibcMallocLayout, bad: int, seg_start: int, top: int, is_main: bool):
        """IMP-009: after a hard inconsistency at ``bad`` the size chain is broken.  Scan forward (16-byte
        steps, at most :attr:`resync_scan_bytes`) for the first position ``Y`` from which a sequential walk is
        consistent to the end of the segment: it must reach the arena's ``top`` exactly (or, in an old thread
        heap, the fencepost), with every header valid.  ``[bad, Y)`` becomes one *damaged region* entry of
        inferred size ``Y - bad`` (its real chunk boundaries are unknown: it may cover several chunks), followed
        by the chunks from ``Y``.  Limits: a damaged region longer than the scan window, or a chain from ``Y`` that
        breaks again, leaves the rest unwalked (no resynchronisation is reported).  Returns
        (chunks, soft, info) or ([], [], None)."""
        end = seg_start + len(buf)
        align, min_chunk = layout.malloc_alignment, layout.min_chunk
        y = bad + align
        limit = min(end - 16, bad + self.resync_scan_bytes)
        need_top = seg_start <= top < end
        tries = 0
        while y <= limit and tries < self.resync_max_chains:
            off = y - seg_start
            if y == top:
                cand_ok = True
            else:
                sf = _u64(buf, off + 8)
                size = sf & ~SIZE_BITS
                cand_ok = (size >= min_chunk and size % align == 0 and y + size <= end and not sf & IS_MMAPPED
                           and not (is_main and sf & NON_MAIN_ARENA))
            if cand_ok:
                tries += 1
                pending, hard, soft, reached = self._walk_buffer(buf, layout, y, seg_start, top, is_main)
                if hard is None and (reached or not need_top) and pending:
                    # state of the damaged region from the PREV_INUSE bit of the header found at y
                    in_use = bool(_u64(buf, off + 8) & PREV_INUSE)
                    out = [(bad, y - bad, ST_IN_USE if in_use else ST_FREE)] + pending
                    return out, soft, {"resynchronised_at": "0x%x" % y, "resynchronised_at_int": y,
                                       "resync_method": "forward scan for a header chain that reaches %s"
                                                        % ("top" if reached else "the segment end"),
                                       "resync_candidates_tried": tries, "resync_reached_top": bool(reached),
                                       "resync_recovered_chunks": len(pending)}
            y += align
        return [], [], None

    # ---------------------------------------------------------------- top catch-up (IMP-008)
    def extend_arena_top(self, ai: int) -> int:
        """The target kept allocating after arena ``ai`` was read: chunks carved from ``top`` since then
        are not in the table, so a pointer into the old top chunk (typically the newest element of a
        growing list, held by its root variable) leads nowhere.  Re-read the arena's current ``top`` and
        walk only the bytes between the old and the new top (same segment, one zero-stop batch read);
        the old TOP entry becomes the first carved chunk.  Returns the number of chunks added (0 when
        nothing could be added: top did not move forward, moved to another segment, or the read tore)."""
        res = self.result
        layout = self._layout
        if res is None or layout is None or not (0 <= ai < len(self._arena_addrs)) or ai >= len(res.arenas):
            return 0
        a = self._arena_addrs[ai]
        info = res.arenas[ai]
        try:
            old_top = int(str(info.get("top")), 16)
        except (TypeError, ValueError):
            return 0
        ti = res.chunks.index_of_chunk(old_top)
        if ti is None or res.chunks.states[ti] != ST_TOP:
            return 0
        seg = next(((s, e) for s, e in res.heap_ranges if s <= old_top < e), None)
        if seg is None:
            return 0
        is_main = ai == 0
        try:
            tb = self.reader.read(a + layout.ms["top"], 8)
            if not tb or len(tb) < 8:
                return 0
            new_top = _u64(tb, 0)
            seg_end = seg[1]
            if not (old_top < new_top):
                return 0
            if new_top + 16 > seg_end:
                # the segment itself grew (brk / heap_info size): only the current mapping bound matters
                if is_main:
                    maps = list(self.adapter.get_proc_maps(self.pid) or [])
                    m = next((mm for mm in maps if _map_bounds(mm)[0] == seg[0]), None)
                    seg_end = _map_bounds(m)[1] if m else seg_end
                else:
                    hb = self.reader.read(seg[0], 24)
                    if hb and len(hb) >= 24:
                        seg_end = seg[0] + struct.unpack_from("<QQQ", hb, 0)[2]
                if new_top + 16 > seg_end:
                    return 0
            buf = self.reader.read(old_top, new_top + 16 - old_top)
        except HeapWalkBudgetExhausted:
            return 0
        if not buf or len(buf) < new_top + 16 - old_top:
            return 0
        pending, hard, _soft, reached = self._walk_buffer(buf, layout, old_top, old_top, new_top, is_main)
        if hard is not None or not reached or len(pending) < 2:
            res.warnings.append(f"arena {ai}: top catch-up 0x{old_top:x}..0x{new_top:x} not walkable (target "
                                f"modified it while it was read)")
            return 0
        p0, sz0, st0 = pending[0]
        res.chunks.sizes[ti] = sz0
        res.chunks.states[ti] = st0
        for p, sz, st in pending[1:]:
            res.chunks.append(p, sz, st, ai)
        res.chunks._sorted = False
        res.chunks.finalize()
        res.snapshot.add(old_top, bytes(buf))
        if new_top + 16 > seg[1]:
            res.heap_ranges = [(s, max(e, new_top + 16)) if (s, e) == seg else (s, e) for s, e in res.heap_ranges]
        info["top"] = "0x%x" % new_top
        info["top_catch_up_chunks"] = int(info.get("top_catch_up_chunks", 0)) + len(pending) - 1
        self.top_extensions += 1
        return len(pending) - 1

    # ---------------------------------------------------------------- mmapped chunks
    def _candidate_anon_maps(self) -> List[Tuple[int, int]]:
        out = []
        heap_ranges = self.result.heap_ranges
        for m in self._maps:
            p = (m.get("pathname") or "")
            perms = m.get("permissions") or ""
            if p or "r" not in perms or "w" not in perms:
                continue
            s, e = _map_bounds(m)
            # The kernel merges adjacent anonymous mappings with equal permissions: mmapped chunks placed
            # right below a thread arena's heap share one VMA with the heap's writable part (IMP-008).
            # Probe the parts of the mapping outside every arena segment instead of skipping it.
            pieces = [(s, e)]
            for hs, he in heap_ranges:
                nxt = []
                for ps, pe in pieces:
                    if he <= ps or hs >= pe:
                        nxt.append((ps, pe))
                        continue
                    if ps < hs:
                        nxt.append((ps, hs))
                    if he < pe:
                        nxt.append((he, pe))
                pieces = nxt
            out.extend((ps, pe) for ps, pe in pieces if pe - ps >= 4096)
        return out

    def _valid_mmapped_header(self, hdr: bytes, addr: int, limit: int) -> Optional[int]:
        if hdr is None or len(hdr) < 16:
            return None
        prev_size, sf = struct.unpack_from("<QQ", hdr, 0)
        size = sf & ~SIZE_BITS
        info = self.inspector.inspect_chunk(hdr[:16], addr, is_user_ptr=False)   # header parse reused
        if not info.is_mmapped or sf & NON_MAIN_ARENA or prev_size % 16 or prev_size >= 4096:
            return None
        if size < 4096 or size % 4096 or addr + size > limit or (addr - prev_size) % 4096:
            return None
        return size

    def _scan_mmapped_mappings(self, layout: GlibcMallocLayout) -> None:
        maps = self._candidate_anon_maps()
        probes = [(s, e) for s, e in maps]
        rounds = 0
        while probes and rounds < 4096:
            rounds += 1
            hdrs = self.reader.read_ranges([(a, 16) for a, _ in probes])
            nxt = []
            for (a, lim), hdr in zip(probes, hdrs):
                size = self._valid_mmapped_header(hdr, a, lim)
                if size is None:
                    continue
                self._add_mmapped(a, size)
                if a + size + 16 <= lim:
                    nxt.append((a + size, lim))
            probes = nxt

    def _add_mmapped(self, a: int, size: int) -> None:
        res = self.result
        if a in self._anon_probe_done:
            return
        self._anon_probe_done.add(a)
        res.chunks.append(a, size, ST_MMAPPED, -1)
        res.heap_ranges.append((a, a + size))

    def probe_mmapped(self, user_ptrs: Iterable[int]) -> List[int]:
        """Validate IS_MMAPPED chunk headers at ``ptr - 16`` for pointers found by the referrer
        scan inside anonymous mappings; adds the chunks found.  Returns the new chunk addresses."""
        res = self.result
        cands = []
        for p in set(user_ptrs):
            a = p - 16
            if a in self._anon_probe_done or a % 4096:
                continue
            for m in self._maps:
                s, e = _map_bounds(m)
                if s <= a < e and not (m.get("pathname") or ""):
                    cands.append((a, e))
                    break
        if not cands:
            return []
        hdrs = self.reader.read_ranges([(a, 16) for a, _ in cands])
        added = []
        for (a, lim), hdr in zip(cands, hdrs):
            size = self._valid_mmapped_header(hdr, a, lim)
            if size is not None:
                self._add_mmapped(a, size)
                added.append(a)
            else:
                self._anon_probe_done.add(a)
        if added:
            res.chunks.finalize()
        return added

    # ---------------------------------------------------------------- tcache / fastbins
    def _demangle(self, layout: GlibcMallocLayout, slot_addr: int, val: int) -> int:
        return ((slot_addr >> 12) ^ val) if layout.safe_linking else val

    def _mark_tcache(self, layout: GlibcMallocLayout, arenas: List[int]) -> None:
        res = self.result
        ct = res.chunks
        csize = layout.tcache_chunk_size
        first_chunks = set()
        for a in res.arenas:
            for seg in a.get("segments", []):
                first_chunks.add(int(seg["first_chunk"], 16))
        width = layout.tcache_count_width
        cfmt = "<%d%s" % (layout.tcache_bins, "H" if width == 2 else "B")
        keys = set()
        for i in range(len(ct)):
            if ct.sizes[i] != csize or ct.states[i] != ST_IN_USE:
                continue
            user = ct.addrs[i] + 16
            body = res.snapshot.get(user, layout.tcache_struct_size)
            if body is None:
                continue
            counts = struct.unpack_from(cfmt, body, 0)
            entries = struct.unpack_from("<%dQ" % layout.tcache_bins, body, layout.tcache_entries_off)
            ok = True
            members: List[int] = []
            for b in range(layout.tcache_bins):
                c, e = counts[b], entries[b]
                if c == 0:
                    if e != 0:
                        ok = False
                        break
                    continue
                if c > 65535 or e == 0:
                    ok = False
                    break
                want = layout.min_chunk + b * layout.malloc_alignment
                cur = e
                for _ in range(c):
                    ci = ct.index_of_user(cur)
                    if ci is None or ct.sizes[ci] != want:
                        ok = False
                        break
                    members.append(ci)
                    raw = res.snapshot.u64(cur)
                    key = res.snapshot.u64(cur + 8)
                    if raw is None:
                        ok = False
                        break
                    if key is not None:
                        keys.add(key)
                    cur = self._demangle(layout, cur, raw)
                if not ok or cur != 0:
                    ok = False
                    break
            if not ok:
                continue
            empty = not members
            if empty and ct.addrs[i] not in first_chunks:
                continue      # an all-zero block of that size elsewhere is indistinguishable: leave it
            ct.states[i] = ST_INTERNAL
            for ci in members:
                ct.states[ci] = ST_TCACHE
            res.tcache_structs.append({"address": "0x%x" % user, "cached_chunks": len(members),
                                       "arena_index": int(ct.arena[i]), "validated": "entries" if members else "first_chunk"})

    def _mark_fastbins(self, layout: GlibcMallocLayout, arenas: List[int]) -> None:
        res = self.result
        ct = res.chunks
        for ai, a in enumerate(arenas):
            ab = self._arena_bytes(a, layout)
            marked = 0
            for b in range(layout.nfastbins):
                p = _u64(ab, layout.ms["fastbinsY"] + 8 * b)
                want = layout.min_chunk + b * layout.malloc_alignment
                seen = set()
                while p and p not in seen and len(seen) < 1 << 20:
                    seen.add(p)
                    ci = ct.index_of_chunk(p)
                    if ci is None or ct.sizes[ci] != want:
                        res.warnings.append(f"fastbin {b} of arena {ai}: 0x{p:x} is not a walked chunk of size {want}")
                        break
                    if ct.states[ci] == ST_IN_USE:
                        ct.states[ci] = ST_FASTBIN
                        marked += 1
                    raw = res.snapshot.u64(p + 16)
                    if raw is None:
                        break
                    p = self._demangle(layout, p + 16, raw)
            res.arenas[ai]["fastbin_chunks"] = marked

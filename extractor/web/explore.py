"""Exploring a diagnosed process from the web UI: read-only, bound to one diagnosis job.

Every function here reads the target of ONE job (its pid, its transport, its debug image) and nothing else: the pid,
the host and the debug image come from the job, never from the request.  Reads go through the same backend functions
the rest of the tool uses (``WatchSessionManager`` = ``extractor/inspection/*``, ``TargetExecutionAdapter.read_memory``);
nothing stops the target, sends it a signal or writes to it.  Each call reports what it cost (reads, bytes, time).

Bounds (also in ``docs/ui-redesign/API_CONTRACT.md``):
  * one-shot reads: a token bucket per job (``READ_BURST`` reads, refilled at ``READ_RATE_PER_S``), one read at a time;
  * a memory range is at most ``RANGE_MAX`` bytes; an expression at most ``EXPR_MAX`` characters of a small C grammar;
  * observation (``WatchSession``): ``WATCH_MAX_ITEMS`` items, ``SAMPLE_BYTES_MAX`` bytes per sample,
    ``BYTES_PER_S_MAX`` bytes per second, interval ``INTERVAL_MIN_S`` (``INTERVAL_MIN_REMOTE_S`` over SSH) ..
    ``INTERVAL_MAX_S``; sampling stops by itself when no client asked for ``IDLE_STOP_S`` seconds, after
    ``MAX_LIFETIME_S`` seconds of sampling, when the target exits or a read fails.
"""
from __future__ import annotations

import os
import re
import threading
import time
from collections import deque
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------------------------------- limits
READ_BURST = 30
READ_RATE_PER_S = 5.0
RANGE_MAX = 4096
EXPR_MAX = 200
QUERY_MAX = 64
MAX_FRAMES = 24
MEMBERS_MAX = 4096
WATCH_MAX_ITEMS = 16
SAMPLE_BYTES_MAX = 256 * 1024          # a 4,096 x 48-byte pool (196,608 B) plus the tracked items fit
BYTES_PER_S_MAX = 512 * 1024           # the same pool every 0.5 s is 393,216 B/s
INTERVALS_S = (0.5, 1.0, 2.0, 5.0)
INTERVAL_MIN_S = 0.5
INTERVAL_MIN_REMOTE_S = 2.0            # one SSH/daemon exchange per read (~7 ms pinned, ~49 ms average in the QEMU matrix)
INTERVAL_MAX_S = 5.0
IDLE_STOP_S = 30.0
MAX_LIFETIME_S = 30 * 60.0
HISTORY = 120                          # samples kept per item (the UI draws the last 30)
SPARK_N = 30
POOL_CELLS = 4096
POOL_RESERVE_ELEMS = 2                 # one element read to locate the array, one for the selected element
MAX_ACTIVE_WATCHES = 4

_IDENT = r"[A-Za-z_][A-Za-z0-9_]{0,127}"
_EXPR_RE = re.compile(r"^\*{0,4}" + _IDENT + r"(?:(?:\.|->)" + _IDENT + r"|\[\d{1,7}\])*$")
_QUERY_RE = re.compile(r"^[A-Za-z0-9_:.]{0,64}$")
_ADDR_RE = re.compile(r"^(?:0x[0-9a-fA-F]{1,16}|[0-9]{1,20})$")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class ExploreError(Exception):
    """A refused or failed exploration request: ``code`` (machine), HTTP ``status``, ``message`` (engine English)."""

    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code, self.message, self.status = code, message, status

    def to_dict(self) -> Dict[str, Any]:
        return {"success": False, "error": {"code": self.code, "message": self.message}}


# ---------------------------------------------------------------------------------------------------- validation
def parse_addr(raw: Any) -> int:
    s = str(raw or "").strip()
    if not _ADDR_RE.match(s):
        raise ExploreError("INVALID_PARAM", "addr must be a hexadecimal (0x...) or decimal address")
    v = int(s, 16) if s.lower().startswith("0x") else int(s)
    if not 0 < v < (1 << 64):
        raise ExploreError("INVALID_PARAM", "addr is out of range")
    return v


def parse_len(raw: Any, default: int = 256) -> int:
    s = str(raw if raw is not None else default).strip()
    if not s.isdigit() or len(s) > 6:
        raise ExploreError("INVALID_PARAM", "len must be a positive integer")
    v = int(s)
    if not 1 <= v <= RANGE_MAX:
        raise ExploreError("INVALID_PARAM", f"len must be 1..{RANGE_MAX}")
    return v


def check_expr(raw: Any) -> str:
    s = str(raw or "").strip()
    if not s or len(s) > EXPR_MAX or not _EXPR_RE.match(s):
        raise ExploreError("INVALID_PARAM", "expr must be a variable name with optional .field, ->field, [index] or a leading *")
    return s


def check_query(raw: Any) -> str:
    s = str(raw or "").strip()
    if len(s) > QUERY_MAX or not _QUERY_RE.match(s):
        raise ExploreError("INVALID_PARAM", "q must be up to 64 characters of letters, digits, '_', ':' or '.'")
    return s


def check_tid(raw: Any) -> int:
    s = str(raw or "").strip()
    if not s.isdigit() or len(s) > 9 or int(s) <= 0:
        raise ExploreError("INVALID_PARAM", "tid must be a positive integer")
    return int(s)


def check_name(raw: Any, what: str = "name") -> str:
    s = str(raw or "")
    if not s or len(s) > 64 or any(ord(c) < 32 or ord(c) == 127 for c in s):
        raise ExploreError("INVALID_PARAM", f"{what} must be 1..64 printable characters")
    return s


# ---------------------------------------------------------------------------------------------------- the target
def _proc_start_ticks(pid: int) -> Optional[int]:
    try:
        with open(f"/proc/{int(pid)}/stat", "r", encoding="utf-8", errors="replace") as fh:
            rest = fh.read().rsplit(")", 1)[1].split()
        if rest[0] in ("Z", "X"):
            return None
        return int(rest[19])
    except (OSError, IndexError, ValueError):
        return None


class _Bucket:
    def __init__(self, burst: int, rate: float):
        self.burst, self.rate = float(burst), float(rate)
        self.tokens, self.t = float(burst), time.monotonic()
        self.lock = threading.Lock()

    def take(self) -> bool:
        with self.lock:
            now = time.monotonic()
            self.tokens = min(self.burst, self.tokens + (now - self.t) * self.rate)
            self.t = now
            if self.tokens < 1.0:
                return False
            self.tokens -= 1.0
            return True


class JobTarget:
    """The process of one job: identity check before every read, one adapter (one SSH connection) for all reads."""

    def __init__(self, job: Any, corpus_dir: str):
        from extractor.watch_session import WatchSessionManager
        self.job = job
        self.pid = int(job.pid)
        rt = (job.params or {}).get("remote_target") or None
        self.remote: Optional[Dict[str, Any]] = dict(rt) if rt else None
        self.start_ticks = getattr(job, "start_ticks", None)
        self.debug_image: Optional[str] = (job.params or {}).get("debug_image") or None
        # A manager of its own: the inspection functions remember an "active target" on their manager; this one never
        # leaves the job's process, whatever else the runtime does.
        self.mgr = WatchSessionManager(corpus_dir=corpus_dir)
        self._adapter = None
        self.io_lock = threading.Lock()
        self.bucket = _Bucket(READ_BURST, READ_RATE_PER_S)
        self.exited: Optional[str] = None

    @property
    def is_remote(self) -> bool:
        return self.remote is not None

    @property
    def adapter(self) -> Any:
        if self._adapter is None:
            if self.remote:
                from extractor.target_adapter import RemoteSshTargetAdapter
                r = self.remote
                self._adapter = RemoteSshTargetAdapter(host=r["remote_host"], user=r.get("ssh_user"), port=int(r.get("ssh_port") or 22),
                                                       key_file=r.get("ssh_key"), proxy_jump=r.get("ssh_proxy_jump"),
                                                       collector_path=r.get("collector_path"))
            else:
                from extractor.target_adapter import LocalTargetAdapter
                self._adapter = LocalTargetAdapter()
        return self._adapter

    def elf(self) -> Optional[str]:
        """The debug image of the job: the one it was diagnosed with, else (local) the running executable."""
        if self.debug_image and os.path.isfile(self.debug_image):
            return self.debug_image
        if self.is_remote:
            return None
        try:
            path = os.readlink(f"/proc/{self.pid}/exe")
        except OSError:
            return None
        if path.endswith(" (deleted)") or not os.path.isfile(path):
            return f"/proc/{self.pid}/exe"
        return path

    def check(self) -> None:
        """Refuse when the job's process is gone or the pid now belongs to another process."""
        if self.exited:
            raise ExploreError("TARGET_EXITED", self.exited, 410)
        if self.is_remote:
            ok, why = self.adapter.check_liveness(self.pid)
            if not ok:
                self.exited = f"process {self.pid} on {self.remote['remote_host']} is gone ({why})"
                raise ExploreError("TARGET_EXITED", self.exited, 410)
            return
        ticks = _proc_start_ticks(self.pid)
        if ticks is None:
            self.exited = f"process {self.pid} exited (/proc/{self.pid} gone, ESRCH)"
            raise ExploreError("TARGET_EXITED", self.exited, 410)
        if self.start_ticks is not None and ticks != self.start_ticks:
            self.exited = f"pid {self.pid} now belongs to another process (start time changed)"
            raise ExploreError("TARGET_EXITED", self.exited, 410)

    def remote_kw(self) -> Dict[str, Any]:
        return {"adapter": self.adapter}

    def run(self, fn: Callable[[], Any], limited: bool = True) -> Tuple[Any, Dict[str, Any]]:
        """One read under the job's rules: identity, rate, one at a time, cost measured on the job's adapter."""
        if limited and not self.bucket.take():
            raise ExploreError("RATE_LIMITED", f"at most {READ_RATE_PER_S:g} reads per second per diagnosis "
                                               f"(burst {READ_BURST}); try again shortly", 429)
        with self.io_lock:
            self.check()
            ad = self.adapter
            r0, b0, t0 = ad.physical_reads_count, ad.physical_bytes_read, time.monotonic()
            try:
                out = fn()
            except ExploreError:
                raise
            except Exception as exc:  # noqa: BLE001
                try:
                    self.check()
                except ExploreError:
                    raise
                raise ExploreError("READ_FAILED", f"{type(exc).__name__}: {exc}", 502)
            cost = {"reads": ad.physical_reads_count - r0, "bytes": ad.physical_bytes_read - b0,
                    "ms": round((time.monotonic() - t0) * 1000, 1), "stop_ms": 0, "writes": 0,
                    "transport": "ssh" if self.is_remote else "local", "at": _now_iso()}
        if isinstance(out, dict):
            got = out.get("pid")
            if out.get("auto_healed_pid") or (got is not None and int(got) != self.pid):
                self.exited = f"process {self.pid} is gone; another process answered"
                raise ExploreError("TARGET_EXITED", self.exited, 410)
        return out, cost


# ---------------------------------------------------------------------------------------------------- one-shot reads
class JobExplorer:
    """The read routes of one job.  Each method returns plain data plus ``cost``; words are made in ``explore_view``."""

    def __init__(self, job: Any, corpus_dir: str):
        self.job = job
        self.target = JobTarget(job, corpus_dir)
        self.watch: Optional["WatchSession"] = None
        self.watch_lock = threading.Lock()
        self._dwarf_seen: Dict[str, bool] = {}

    # -- helpers
    def _need_elf(self) -> str:
        elf = self.target.elf()
        if not elf:
            raise ExploreError("NO_DEBUG_INFO", "no debug image for this target: give a debug ELF when diagnosing", 409)
        return elf

    def _index(self) -> Any:
        from extractor.dwarf_indexer import DwarfIndexer
        elf = self._need_elf()
        self._need_dwarf()
        return DwarfIndexer.get_index(elf)

    def _need_dwarf(self) -> None:
        """Everything that names a variable, a type or a lock needs DWARF: say so plainly instead of "symbol not found"."""
        self._need_elf()
        if not self.has_dwarf():
            raise ExploreError("NO_DEBUG_INFO", "the executable has no DWARF debug information", 409)

    def has_dwarf(self) -> bool:
        elf = self.target.elf()
        if not elf:
            return False
        hit = self._dwarf_seen.get(elf)
        if hit is not None:
            return hit
        try:
            from extractor.debug_image import inspect_elf
            ok = bool(inspect_elf(elf).has_debug_info)
        except Exception:  # noqa: BLE001
            return False
        self._dwarf_seen[elf] = ok
        return ok

    # -- threads
    def thread(self, tid: int) -> Dict[str, Any]:
        t = self.target
        if not t.is_remote and not os.path.isdir(f"/proc/{t.pid}/task/{tid}"):
            t.check()
            raise ExploreError("NOT_FOUND", f"thread {tid} is not a thread of process {t.pid}", 404)
        elf = self.target.elf() or ""

        def read() -> Dict[str, Any]:
            cs = t.mgr.inspect_thread_callstacks_and_locks(pid=t.pid, companion_elf_path=elf, tid=tid, max_frames=MAX_FRAMES,
                                                           **t.remote_kw())
            lo = None
            try:
                if not self.has_dwarf():
                    raise ValueError("no DWARF debug information")
                lo = t.mgr.inspect_thread_locals_and_frame_vars(pid=t.pid, companion_elf_path=elf, tid=tid,
                                                                max_frames=MAX_FRAMES, **t.remote_kw())
            except Exception as exc:  # noqa: BLE001 - locals are optional (no DWARF, remote)
                lo = {"error": f"{type(exc).__name__}: {exc}"}
            return {"pid": cs.get("pid"), "cs": cs, "lo": lo}

        raw, cost = t.run(read)
        cs, lo = raw["cs"], raw["lo"] or {}
        th = next((x for x in cs.get("threads") or [] if x.get("tid") == tid), None)
        if th is None:
            raise ExploreError("NOT_FOUND", f"thread {tid} is not a thread of process {t.pid}", 404)
        lth = next((x for x in lo.get("threads") or [] if x.get("tid") == tid), {}) if isinstance(lo, dict) else {}
        by_frame = {}
        for f in lth.get("frames") or []:
            if f.get("stack_frame_index") is not None:
                by_frame[int(f["stack_frame_index"])] = f
        frames = []
        for f in th.get("callstack") or []:
            i = int(f.get("frame_index", len(frames)))
            lf = by_frame.get(i)
            frames.append({"i": i, "fn": f.get("function_name") or f.get("symbol_plus_offset") or f.get("runtime_pc"),
                           "loc": f.get("source_location"), "module": f.get("module"), "pc": f.get("runtime_pc"),
                           "estimated": bool(f.get("estimated")), "unwind": f.get("unwind"),
                           "params": (lf or {}).get("parameters"), "locals": (lf or {}).get("locals"),
                           "vars_status": (lf or {}).get("variables_status") if lf else None})
        holds = [{"name": lk.get("name"), "address": lk.get("runtime_address")} for lk in cs.get("locks") or []
                 if lk.get("owner_tid") == tid]
        w = th.get("waiting_on_lock") or None
        waits = {"name": w.get("lock_name"), "address": w.get("lock_address"), "owner_tid": w.get("held_by_tid"),
                 "owner_name": w.get("held_by_thread_name")} if w else None
        top_user = th.get("top_user_frame_index")
        return {"tid": tid, "name": th.get("name"), "state": th.get("state"), "syscall": th.get("syscall"),
                "frames": frames, "holds": holds, "waits": waits, "default_frame": top_user if isinstance(top_user, int) else 0,
                "unwind_status": th.get("unwind_status"), "locals_status": lo.get("frame_decode_status") if isinstance(lo, dict) else None,
                "locals_error": lo.get("error") if isinstance(lo, dict) else None, "has_dwarf": self.has_dwarf(),
                "registers_from": "syscall" if th.get("syscall_sp") else None, "cost": cost}

    def threads_named(self, name: str) -> Dict[str, Any]:
        """The members of a thread group: every thread whose name is ``name`` (``/proc/pid/task/*/comm``), no memory read."""
        t = self.target

        def read() -> Dict[str, Any]:
            out = []
            for th in t.adapter.get_threads(t.pid) or []:
                if str(th.get("name") or "") == name:
                    out.append({"tid": int(th.get("tid")), "state": th.get("state")})
                if len(out) >= MEMBERS_MAX:
                    break
            return {"members": sorted(out, key=lambda x: x["tid"])}

        raw, cost = t.run(read)
        return {"name": name, "members": raw["members"], "cost": cost}

    # -- memory
    def memory_maps(self) -> Dict[str, Any]:
        t = self.target
        elf = t.elf() if self.has_dwarf() else None          # the maps do not need DWARF; a stripped image must not fail them
        raw, cost = t.run(lambda: t.mgr.get_memory_map_and_threads(pid=t.pid, companion_elf_path=elf, max_discoverable_vars=0,
                                                                   **t.remote_kw()))
        maps = [{"start": m.get("start"), "end": m.get("end"), "size": m.get("size"), "perm": m.get("permissions"),
                 "kind": m.get("category"), "path": m.get("pathname") or "", "readable": bool(m.get("is_readable"))}
                for m in raw.get("mappings") or []]
        return {"maps": maps, "cost": cost}

    def memory_range(self, addr: Optional[int], length: int, expr: Optional[str] = None) -> Dict[str, Any]:
        """``length`` bytes at ``addr`` (one read), or at the address the pointer ``expr`` holds (one more read), with the
        heap layout the diagnosis found marked and a typed decode when the address is a global the debug image knows."""
        t = self.target
        if addr is None:
            if not expr:
                raise ExploreError("INVALID_PARAM", "addr or expr is required")
            v = self.value(expr)
            if v.get("status") != "OBSERVED" or not isinstance(v.get("value"), str) or not str(v["value"]).startswith("0x"):
                raise ExploreError("NOT_FOUND", f"{expr} does not hold a pointer ({v.get('error') or v.get('value')})", 404)
            addr = int(v["value"], 16)
            blk = next((b for b in self.heap_blocks() if b["user"] == addr), None)
            if blk:
                addr = blk["chunk"]
        if not 0 < addr or addr + length > (1 << 64):
            raise ExploreError("INVALID_PARAM", "the range runs past the end of the address space")
        data, cost = t.run(lambda: {"read": t.adapter.read_memory(t.pid, addr, length)})
        b, status, err = data["read"]
        if status not in ("OBSERVED", "PARTIAL"):
            t.check()
        out: Dict[str, Any] = {"addr": addr, "len": length, "status": status, "error": err, "bytes": (b or b"").hex(),
                               "cost": cost, "marks": self.marks_for(addr, length)}
        out["decode"] = self._decode_at(addr, b or b"")
        return out

    def _decode_at(self, addr: int, data: bytes) -> Dict[str, Any]:
        """Typed decode when the start address is a global the debug image knows, else a raw one (u64, u32, text, pointers)."""
        typed = None
        try:
            if self.target.elf():
                typed = self._global_at(addr)
        except Exception:  # noqa: BLE001
            typed = None
        raw = []
        for off in range(0, min(len(data), 64) - 7, 8):
            v = int.from_bytes(data[off:off + 8], "little")
            raw.append({"off": off, "u64": v, "ptr": v >= 0x10000 and v < (1 << 48),
                        "u32": [int.from_bytes(data[off:off + 4], "little"), int.from_bytes(data[off + 4:off + 8], "little")]})
        text = "".join(chr(c) if 32 <= c < 127 else "." for c in data[:64])
        return {"typed": typed, "raw": raw, "text": text}

    def _global_at(self, addr: int) -> Optional[Dict[str, Any]]:
        idx = self._index()
        bias = self._load_bias()
        if bias is None:
            return None
        for var in list(getattr(idx, "variables", []) or [])[:20000]:
            ra = getattr(var, "runtime_address", None)
            if ra is None:
                continue
            a = ra + bias
            size = max(int(getattr(var, "size", 0) or 0), 1)
            if a <= addr < a + size:
                return {"name": var.name, "type": getattr(var, "type_name", None), "size": size, "offset": addr - a}
        return None

    def _load_bias(self) -> Optional[int]:
        t = self.target
        try:
            maps = t.adapter.get_proc_maps(t.pid)
        except Exception:  # noqa: BLE001
            return None
        elf = t.elf() or ""
        real = os.path.realpath(elf) if elf else ""
        for m in maps or []:
            path = m.get("pathname") or m.get("path") or ""
            if path and (path == real or os.path.basename(path) == os.path.basename(real)):
                try:
                    return int(str(m.get("start")), 16) - int(str(m.get("offset") or "0"), 16)
                except ValueError:
                    return None
        return None

    def files(self) -> Dict[str, Any]:
        t = self.target
        if t.is_remote:
            raise ExploreError("UNSUPPORTED_REMOTE", "the open-file list is read from /proc/PID/fd on this host only", 409)

        def read() -> Dict[str, Any]:
            out = []
            base = f"/proc/{t.pid}/fd"
            names = sorted(os.listdir(base), key=lambda x: int(x) if x.isdigit() else 0)
            for n in names[:512]:
                try:
                    link = os.readlink(os.path.join(base, n))
                except OSError:
                    continue
                kind = ("socket" if link.startswith("socket:") else "pipe" if link.startswith("pipe:")
                        else "anon" if link.startswith("anon_inode:") else "tty" if link.startswith("/dev/pts") or link.startswith("/dev/tty")
                        else "device" if link.startswith("/dev/") else "file")
                out.append({"fd": int(n), "kind": kind, "target": link})
            return {"fds": out, "total": len(names)}

        raw, cost = t.run(read)
        return {"fds": raw["fds"], "total": raw["total"], "cost": cost}

    def modules(self) -> Dict[str, Any]:
        t = self.target
        raw, cost = t.run(lambda: {"maps": t.adapter.get_proc_maps(t.pid)})
        mods: Dict[str, Dict[str, Any]] = {}
        for m in raw["maps"] or []:
            path = m.get("pathname") or m.get("path") or ""
            if not path.startswith("/"):
                continue
            try:
                start = int(str(m.get("start")), 16)
            except ValueError:
                continue
            cur = mods.setdefault(path, {"path": path, "name": os.path.basename(path), "base": start})
            cur["base"] = min(cur["base"], start)
        out = []
        from extractor.debug_image import inspect_elf
        dbg_elf = os.path.realpath(t.elf() or "") if t.elf() else ""
        for path, m in sorted(mods.items(), key=lambda kv: kv[1]["base"]):
            debug = "unknown"
            local = path if not t.is_remote else None
            if dbg_elf and os.path.basename(path) == os.path.basename(dbg_elf):
                local = dbg_elf
            if local and os.path.isfile(local):
                try:
                    ident = inspect_elf(local)
                    debug = "dwarf" if ident.has_debug_info else ("symbols" if not ident.stripped else "none")
                except Exception:  # noqa: BLE001
                    debug = "unknown"
            out.append({"name": m["name"], "path": path, "base": f"0x{m['base']:x}", "debug": debug})
        return {"modules": out[:64], "total": len(out), "cost": cost}

    # -- variables
    def search(self, q: str) -> Dict[str, Any]:
        """Globals and statics whose name contains ``q``, from DWARF (no read of the target)."""
        if not self.has_dwarf():
            raise ExploreError("NO_DEBUG_INFO", "the executable has no DWARF debug information", 409)
        idx = self._index()
        res = idx.search_symbols(query=q, category="all", limit=60, smart_rank=True)
        out = []
        for s in res:
            if s.get("kind") not in ("global_variable", "static_variable"):
                continue
            out.append({"name": s.get("name"), "type": s.get("type_name"), "size": s.get("size"), "kind": s.get("kind"),
                        "decl": s.get("source_location"), "is_pointer": bool(s.get("is_pointer")),
                        "pool": self._pool_hint(s)})
            if len(out) >= 30:
                break
        return {"q": q, "vars": out, "cost": {"reads": 0, "bytes": 0, "ms": 0, "stop_ms": 0, "writes": 0,
                                              "transport": "dwarf", "at": _now_iso()}}

    def _pool_hint(self, sym: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """An array of structs with a status-like field: the pool view's prefill (expression, count, field)."""
        m = re.match(r"^(?:struct\s+)?([A-Za-z_][A-Za-z0-9_]*)\[(\d+)\]$", str(sym.get("type_name") or "").strip())
        if not m:
            return None
        try:
            geo = pool_geometry(self._index(), sym.get("name"), None)
        except ExploreError:
            return None
        if not geo.get("field"):
            return None
        fit = pool_fit_count(geo["elem_size"])
        # a pool the sample budget cannot cover is offered as its first ``fit`` elements (``total`` says how many exist)
        return {"expr": sym.get("name"), "count": min(geo["count"], fit), "total": geo["count"], "field": geo["field"]}

    def value(self, expr: str) -> Dict[str, Any]:
        t = self.target
        elf = self._need_elf()

        def read() -> Any:
            self._need_dwarf()                      # after the liveness check of ``run``: a gone target is 410 first
            return t.mgr.evaluate_symbol_paths(pid=t.pid, companion_elf_path=elf, expressions=[expr], **t.remote_kw())

        raw, cost = t.run(read)
        r = (raw.get("results") or [{}])[0]
        return {"expr": expr, "status": r.get("status"), "error": r.get("error"), "type": r.get("type_name"), "size": r.get("size"),
                "addr": r.get("runtime_address"), "value": r.get("value"), "decl": r.get("source_location"),
                "pointer": _is_pointer_type(r.get("type_name")), "cost": cost}

    def lock(self, name: str) -> Dict[str, Any]:
        """A mutex: owner and waiters with where each one is (one stack read of every thread) and the mutex words."""
        t = self.target
        elf = t.elf() or ""
        exprs = [name] if _EXPR_RE.match(name) else None

        def read() -> Any:
            self._need_dwarf()                      # after the liveness check of ``run``: a gone target is 410 first
            return t.mgr.inspect_thread_callstacks_and_locks(pid=t.pid, companion_elf_path=elf, tid=None,
                                                             lock_expressions=exprs, max_frames=8, **t.remote_kw())

        raw, cost = t.run(read)
        lk = next((x for x in raw.get("locks") or [] if x.get("name") == name), None)
        if lk is None:
            raise ExploreError("NOT_FOUND", f"no mutex named {name} was found", 404)
        threads = {x.get("tid"): x for x in raw.get("threads") or []}

        def where(tid: Any) -> Dict[str, Any]:
            th = threads.get(tid) or {}
            cs = th.get("callstack") or []
            top = cs[0] if cs else {}
            ui = th.get("top_user_frame_index")
            user = cs[ui] if isinstance(ui, int) and ui < len(cs) else {}
            return {"tid": tid, "name": th.get("name"), "top": top.get("function_name"),
                    "at": user.get("function_name"), "loc": user.get("source_location")}

        waiters = list(lk.get("waiting_tids") or []) + [x for x in lk.get("inferred_waiting_tids") or [] if x not in (lk.get("waiting_tids") or [])]
        return {"name": name, "type": lk.get("type_name"), "addr": lk.get("runtime_address"), "locked": lk.get("is_locked"),
                "lock_word": lk.get("lock_state_word"), "owner_tid": lk.get("owner_tid"),
                "owner": where(lk.get("owner_tid")) if lk.get("owner_tid") else None,
                "waiters": [where(w) for w in waiters[:32]], "waiter_count": len(waiters), "cost": cost,
                "owner_expr": f"{name}.__data.__owner" if str(lk.get("type_name") or "").startswith("pthread_mutex") else None}


    # -- what a finding names (no read: the diagnosis's own result and DWARF)
    def static_type(self, expr: str) -> Optional[str]:
        """The C type of ``expr`` from DWARF alone (``rb.buf`` -> ``unsigned char*``), or None."""
        try:
            idx = self._index()
        except ExploreError:
            return None
        m = re.match(r"^(\**)(" + _IDENT + r")(.*)$", expr)
        if not m:
            return None
        stars, root, rest = m.group(1), m.group(2), m.group(3)
        syms = [s for s in idx.search_symbols(query=root, category="all", limit=20, smart_rank=True)
                if s.get("name") == root and s.get("kind") in ("global_variable", "static_variable")]
        if not syms:
            return None
        ty = _base_type(syms[0].get("type_name"))
        for step in re.findall(r"(\.|->)(" + _IDENT + r")|\[(\d+)\]", rest):
            if step[2]:
                ty = re.sub(r"\[\d+\]$", "", ty) if ty.endswith("]") else ty.rstrip("*").strip()
                continue
            base = ty.rstrip("*").strip().replace("struct ", "")
            st = [x for x in idx.search_symbols(query=base, category="all", limit=20, smart_rank=True)
                  if x.get("name") == base and x.get("kind") == "struct_type"]
            mem = next((x for x in (st[0].get("members") or []) if x.get("name") == step[1]), None) if st else None
            if mem is None:
                return None
            ty = _base_type(mem.get("type_name"))
        for _ in stars:
            ty = ty[:-1].strip() if ty.endswith("*") else ty
        return ty

    def heap_blocks(self) -> List[Dict[str, Any]]:
        """The heap blocks the diagnosis described (overflowing buffer, its header, the bytes past its end, the damaged
        neighbour), from the result's memory-integrity observations."""
        res = getattr(self.job, "result", None) or {}
        rep = res.get("report") if isinstance(res.get("report"), dict) else {}
        checks = ((rep or {}).get("section_d_detailed_inspection_results") or {}).get("checks") or []
        out: List[Dict[str, Any]] = []
        for c in checks:
            mi = ((c or {}).get("actual_observations") or {}).get("memory_integrity") or {}
            for dfc in ((mi.get("heap") or {}).get("defects") or []):
                ob, dmg = dfc.get("overflowing_buffer") or {}, dfc.get("damage") or {}
                try:
                    chunk, user = int(str(ob["chunk_address"]), 16), int(str(ob["user_address"]), 16)
                    usable = int(ob["usable_size"])
                except (KeyError, TypeError, ValueError):
                    continue
                past = int(dmg.get("bytes_past_usable_end") or 0)
                end = user + usable
                blk = {"variable": ob.get("variable_path") or ob.get("variable"), "chunk": chunk, "user": user, "usable": usable,
                       "past": past, "marks": [
                           {"from": chunk, "to": user, "cls": "b-hdr", "label": "r_hdr", "note": f"chunk 0x{chunk:x}"},
                           {"from": user, "to": end, "cls": "b-buf", "label": "r_buf",
                            "note": f"{ob.get('variable_path') or ob.get('variable') or ''} · {usable} B"},
                       ]}
                if past:
                    blk["marks"].append({"from": end, "to": end + past, "cls": "b-over", "label": "r_over",
                                         "note": f"{past} B · {dmg.get('pattern') or ''}".strip(" ·")})
                vic = dfc.get("victim") or {}
                if vic.get("chunk_address"):
                    blk["victim"] = vic.get("variable_path") or vic.get("variable")
                if not any(b["chunk"] == chunk for b in out):
                    out.append(blk)
        return out

    def marks_for(self, addr: int, length: int) -> List[Dict[str, Any]]:
        out = []
        for b in self.heap_blocks():
            for m in b["marks"]:
                if m["from"] < addr + length and m["to"] > addr:
                    out.append(dict(m))
        return out

    def chips(self) -> Dict[str, Any]:
        """The related-information chips of each finding, by the proposal's rule (EXPLORE_PROPOSAL_KO.md 5), from what the
        finding names; no target read (types from DWARF, addresses from the result)."""
        res = getattr(self.job, "result", None) or {}
        from extractor.process_profile import build_process_profile
        prof = res.get("process_profile") if isinstance(res.get("process_profile"), dict) else None
        if prof is None:
            try:
                prof = build_process_profile(res, res.get("report"))
            except Exception:  # noqa: BLE001
                prof = {}
        th = (prof or {}).get("threads") or {}
        names: Dict[int, str] = {}
        groups: Dict[int, int] = {}
        for gi, r in enumerate(th.get("rows") or []):
            for tid in r.get("tids") or ([r["tid"]] if r.get("tid") else []):
                names[int(tid)] = str(r.get("name") or tid)
                if (r.get("count") or 1) > 1:
                    groups[int(tid)] = gi
        lock_names = {str(it.get("name")) for it in ((prof or {}).get("locks") or {}).get("items") or [] if it.get("name")}
        blocks = self.heap_blocks()
        out: Dict[str, List[Dict[str, Any]]] = {}
        for n, f in enumerate([f for f in res.get("findings") or [] if isinstance(f, dict)], 1):
            chips: List[Dict[str, Any]] = []
            seen = set()
            fns = [str(d.get("name")) for d in f.get("subject_details") or [] if isinstance(d, dict) and d.get("kind") == "function"]

            def add(k: str, chip: Dict[str, Any]) -> None:
                if k not in seen:
                    seen.add(k)
                    chips.append(chip)

            for d in f.get("subject_details") or []:
                if not isinstance(d, dict):
                    continue
                kind, name = d.get("kind"), str(d.get("name") or "")
                if kind == "thread" and name.isdigit() and int(name) in names:
                    tid = int(name)
                    keys = f"pf:threads grp:{groups[tid]}" if tid in groups else f"pf:threads th:{tid}"
                    focus = f"grp:{groups[tid]}" if tid in groups else f"th:{tid}"
                    add("th" + name, {"kind": "ch_thread", "label": names[tid], "act": "goto",
                                      "attrs": {"keys": keys, "focus": focus, "tid": tid, "fns": " ".join(fns[:8])}})
                elif kind == "lock" and name:
                    add("lk" + name, {"kind": "ch_lock", "label": name, "act": "goto",
                                      "attrs": {"keys": f"pf:locks lk:{_key(name)}", "focus": f"lk:{_key(name)}"}})
                elif kind == "variable" and name and _EXPR_RE.match(name):
                    ty = self.static_type(name)
                    blk = next((b for b in blocks if b.get("variable") == name), None)
                    if ty is not None and _is_pointer_type(ty):
                        attrs = {"keys": "pf:memory range", "focus": "range", "expr": name, "len": 160}
                        if blk:
                            attrs.update(addr=f"0x{blk['chunk']:x}", len=min(RANGE_MAX, max(160, ((blk["usable"] + blk["past"] + 48 + 15) // 16) * 16)))
                        add("mem" + name, {"kind": "ch_range", "label": name, "label_key": "ch_around", "act": "goto-range", "attrs": attrs})
                        add("trk" + name, {"kind": "ch_watch", "label": name, "act": "track", "attrs": {"expr": name}})
                    elif ty is not None:
                        add("var" + name, {"kind": "ch_value", "label": name, "act": "goto",
                                           "attrs": {"keys": f"pf:vars var:{_key(name)}", "focus": f"var:{_key(name)}", "q": name}})
            for addr in re.findall(r"\b0x[0-9a-fA-F]{6,16}\b", " ".join(str(x) for x in f.get("observed") or [])):
                a = int(addr, 16)
                if a >= (1 << 48) or a < 0x10000:        # a value (a damaged size field, a pattern), not a user-space address
                    continue
                if any(b["chunk"] <= a < b["user"] + b["usable"] + b["past"] + 64 for b in blocks):
                    continue
                add("addr" + addr, {"kind": "ch_mem", "label": addr, "act": "goto-range",
                                    "attrs": {"keys": "pf:memory range", "focus": "range", "addr": f"0x{max(16, a - 32):x}", "len": 128}})
            out[str(n)] = chips
        return out


def _key(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.:\-]", "_", str(s))[:96]


def _is_pointer_type(type_name: Any) -> bool:
    s = str(type_name or "").strip()
    return s.endswith("*") and "(" not in s


# ---------------------------------------------------------------------------------------------------- pools
_INT_SIZES = {"char": 1, "signed char": 1, "unsigned char": 1, "uint8_t": 1, "int8_t": 1, "bool": 1, "_Bool": 1,
              "short": 2, "unsigned short": 2, "uint16_t": 2, "int16_t": 2, "int": 4, "unsigned int": 4, "uint32_t": 4,
              "int32_t": 4, "long": 8, "unsigned long": 8, "uint64_t": 8, "int64_t": 8, "size_t": 8, "long long": 8,
              "unsigned long long": 8}


def _base_type(t: str) -> str:
    return re.sub(r"\b(volatile|const)\b", "", str(t or "")).replace("enum ", "").strip()


def pool_geometry(idx: Any, name: Any, field: Optional[str]) -> Dict[str, Any]:
    """Count, element size and the status field of an array global from DWARF (no read).  The status field is the one
    the caller names, else a field named ``state`` / ``status``, else the first enumeration field, else none."""
    name = str(name or "")
    syms = [s for s in idx.search_symbols(query=name, category="all", limit=20, smart_rank=True)
            if s.get("name") == name and s.get("kind") in ("global_variable", "static_variable")]
    if not syms:
        raise ExploreError("NOT_FOUND", f"no global or static array named {name}", 404)
    s = syms[0]
    m = re.match(r"^(?:struct\s+)?([A-Za-z_][A-Za-z0-9_]*)\[(\d+)\]$", _base_type(s.get("type_name")))
    if not m:
        raise ExploreError("INVALID_PARAM", f"{name} is not an array (type {s.get('type_name')})")
    elem_type, count = m.group(1), int(m.group(2))
    size = int(s.get("size") or 0)
    if count <= 0 or size <= 0 or size % count:
        raise ExploreError("INVALID_PARAM", f"cannot tell the element size of {name}")
    elem = size // count
    members = []
    st = [x for x in idx.search_symbols(query=elem_type, category="all", limit=20, smart_rank=True)
          if x.get("name") == elem_type and x.get("kind") == "struct_type"]
    if st:
        members = list(st[0].get("members") or [])
    enums: Dict[str, Dict[str, str]] = {}

    def enum_values(type_name: str) -> Optional[Dict[str, str]]:
        tn = _base_type(type_name)
        if tn in enums:
            return enums[tn]
        hit = [x for x in idx.search_symbols(query=tn, category="all", limit=20, smart_rank=True)
               if x.get("name") == tn and x.get("kind") == "enum_type"]
        enums[tn] = hit[0].get("enum_values") if hit else None
        return enums[tn]

    chosen = None
    if field:
        chosen = next((x for x in members if x.get("name") == field), None)
        if chosen is None:
            raise ExploreError("INVALID_PARAM", f"{elem_type} has no field {field}")
    else:
        chosen = next((x for x in members if x.get("name") in ("state", "status")), None) or \
            next((x for x in members if enum_values(x.get("type_name") or "")), None)
    out: Dict[str, Any] = {"name": name, "count": count, "elem_size": elem, "elem_type": elem_type, "field": None,
                           "members": [{"name": x.get("name"), "type": x.get("type_name"), "offset": x.get("offset")} for x in members]}
    if chosen is not None:
        ev = enum_values(chosen.get("type_name") or "")
        tn = _base_type(chosen.get("type_name") or "")
        fsize = 4 if ev else _INT_SIZES.get(tn)
        offs = sorted(int(x.get("offset") or 0) for x in members)
        o = int(chosen.get("offset") or 0)
        nxt = next((x for x in offs if x > o), elem)
        if fsize is None or fsize > nxt - o:
            fsize = min(8, nxt - o)
        if fsize not in (1, 2, 4, 8):
            raise ExploreError("INVALID_PARAM", f"field {chosen.get('name')} is not an integer or enumeration")
        out.update(field=chosen.get("name"), field_type=chosen.get("type_name"), field_offset=o, field_size=fsize,
                   enum={int(k): v for k, v in (ev or {}).items()} if ev else None)
    return out


def pool_fit_count(elem_size: int, spent: int = 0, interval: Optional[float] = None) -> int:
    """The most elements of ``elem_size`` bytes one pool read may cover within the per-sample (and, given the interval,
    the per-second) byte budget after ``spent`` bytes of tracked items, reserve included."""
    room = SAMPLE_BYTES_MAX - spent
    if interval:
        room = min(room, int(BYTES_PER_S_MAX * interval) - spent)
    return max(0, room // max(1, elem_size) - POOL_RESERVE_ELEMS)


# ---------------------------------------------------------------------------------------------------- observation
def _flatten(value: Any, prefix: str = "", out: Optional[Dict[str, Any]] = None, depth: int = 0) -> Dict[str, Any]:
    out = {} if out is None else out
    if isinstance(value, dict) and depth < 3:
        for k, v in list(value.items())[:64]:
            _flatten(v, f"{prefix}.{k}", out, depth + 1)
    elif isinstance(value, list) and depth < 3:
        for i, v in enumerate(value[:64]):
            _flatten(v, f"{prefix}[{i}]", out, depth + 1)
    else:
        out[prefix] = value if isinstance(value, (int, float, str)) or value is None else str(value)
    return out


class _Track:
    def __init__(self, spec: Dict[str, Any], seq0: int):
        self.spec = spec
        self.id = spec["id"]
        self.label = spec["label"]
        self.since = seq0
        self.type: Optional[str] = spec.get("type")
        self.size = int(spec.get("size") or 8)
        self.hist: deque = deque(maxlen=HISTORY)        # (seq, t, {leaf: value})
        self.changes: Dict[str, int] = {}
        self.last_change: Dict[str, Tuple[int, str]] = {}
        self.error: Optional[str] = None

    def push(self, seq: int, t: str, leaves: Dict[str, Any]) -> None:
        if self.hist:
            prev = self.hist[-1][2]
            for k, v in leaves.items():
                if k in prev and prev[k] != v:
                    self.changes[k] = self.changes.get(k, 0) + 1
                    self.last_change[k] = (seq, t)
        self.hist.append((seq, t, leaves))

    def view(self) -> Dict[str, Any]:
        cur = self.hist[-1][2] if self.hist else {}
        leaves = list(cur.keys())
        whole = leaves == [""]
        fields = []
        for k in leaves:
            series = [h[2].get(k) for h in list(self.hist)[-SPARK_N:]]
            lc = self.last_change.get(k)
            fields.append({"name": k, "value": cur.get(k), "spark": series, "changes": self.changes.get(k, 0),
                           "last_change": lc[1] if lc else None})
        total = sum(self.changes.values())
        lcs = [v for v in self.last_change.values()]
        last = max(lcs)[1] if lcs else None
        out = {"id": self.id, "label": self.label, "type": self.type, "error": self.error, "changes": total, "last_change": last,
               "since": self.since}
        if whole:
            out.update(value=cur.get(""), spark=fields[0]["spark"] if fields else [])
        else:
            out.update(fields=fields, spark=[_digest(h[2]) for h in list(self.hist)[-SPARK_N:]])
        return out


def _digest(leaves: Dict[str, Any]) -> str:
    return "|".join(f"{k}={leaves[k]}" for k in sorted(leaves))


class WatchSession:
    """The observation of one job: tracked items and at most one pool, sampled on a thread at an interval."""

    def __init__(self, explorer: JobExplorer, on_stop: Optional[Callable[["WatchSession"], None]] = None):
        self.x = explorer
        self.t = explorer.target
        self.cond = threading.Condition()
        self.items: List[_Track] = []
        self.pool: Optional[Dict[str, Any]] = None
        self.interval = 1.0
        self.running = False
        self.state = "idle"            # idle | running | paused | stopped
        self.reason: Optional[str] = None
        self.reason_detail: Optional[str] = None
        self.seq = 0
        self.n = 0
        self.first_t: Optional[str] = None
        self.last_t: Optional[str] = None
        self.started = time.monotonic()
        self.last_client = time.monotonic()
        self.thread: Optional[threading.Thread] = None
        self.pin: Optional[Dict[str, Any]] = None
        self.cost: Dict[str, Any] = {}
        self.on_stop = on_stop
        self._stop = threading.Event()

    # -- configuration
    def min_interval(self) -> float:
        return INTERVAL_MIN_REMOTE_S if self.t.is_remote else INTERVAL_MIN_S

    def configure(self, body: Dict[str, Any]) -> None:
        if not isinstance(body, dict):
            raise ExploreError("INVALID_PARAM", "body must be an object")
        interval = body.get("interval_s", self.interval)
        try:
            interval = float(interval)
        except (TypeError, ValueError):
            raise ExploreError("INVALID_PARAM", "interval_s must be a number")
        if interval not in INTERVALS_S or interval < self.min_interval() or interval > INTERVAL_MAX_S:
            allowed = [x for x in INTERVALS_S if x >= self.min_interval()]
            raise ExploreError("INVALID_PARAM", f"interval_s must be one of {allowed}")
        items_in = body.get("items", None)
        specs: Optional[List[Dict[str, Any]]] = None
        if items_in is not None:
            if not isinstance(items_in, list) or len(items_in) > WATCH_MAX_ITEMS:
                raise ExploreError("INVALID_PARAM", f"items must be a list of at most {WATCH_MAX_ITEMS}")
            specs = [self._item_spec(x) for x in items_in]
            if len({s["id"] for s in specs}) != len(specs):
                raise ExploreError("INVALID_PARAM", "items must not repeat")
        pool_in = body.get("pool", "keep")
        pool_spec = None
        if pool_in not in ("keep", None):
            pool_spec = self._pool_spec(pool_in)
        # budget check before anything changes
        bytes_items = sum(s["size"] for s in specs) if specs is not None else sum(t.size for t in self.items)
        bytes_pool = pool_spec["bytes"] if pool_spec else (self.pool["bytes"] if self.pool and pool_in == "keep" else 0)
        pool_src = pool_spec if pool_spec else (self.pool if self.pool and pool_in == "keep" else None)
        per_sample = bytes_items + (pool_src["reserved"] if pool_src else bytes_pool)
        pool_geo = pool_spec["geo"] if pool_spec else (self.pool["geo"] if self.pool and pool_in == "keep" else None)

        def fit_hint() -> str:
            if not pool_geo:
                return ""
            n = pool_fit_count(pool_geo["elem_size"], bytes_items, interval)
            return (f"; this pool ({pool_geo['count']} elements of {pool_geo['elem_size']} B) can be observed up to its first "
                    f"{n} elements at this interval: give count {n} or less" if n else "")

        if per_sample > SAMPLE_BYTES_MAX:
            raise ExploreError("BUDGET", f"one sample would read {per_sample} bytes; the limit is {SAMPLE_BYTES_MAX}" + fit_hint())
        if per_sample / interval > BYTES_PER_S_MAX:
            raise ExploreError("BUDGET", f"{per_sample / interval:.0f} bytes per second at this interval; the limit is "
                                         f"{BYTES_PER_S_MAX}: choose a longer interval" + fit_hint())
        with self.cond:
            self.interval = interval
            if specs is not None:
                old = {t.id: t for t in self.items}
                self.items = [old.get(s["id"]) or _Track(s, self.seq) for s in specs]
            if pool_in is None:
                self.pool = None
            elif pool_spec is not None:
                if self.pool and self.pool["key"] == pool_spec["key"]:
                    self.pool["sel"] = pool_spec["sel"]
                else:
                    self.pool = pool_spec
            pin = body.get("pin")
            if pin == "now":
                self.pin = self._snapshot_values() if self.n else None
            elif pin == "clear":
                self.pin = None
            run = body.get("running", True)
            if not isinstance(run, bool):
                raise ExploreError("INVALID_PARAM", "running must be true or false")
            if not self.items and not self.pool:
                run = False
            if run and self.state == "stopped" and self.reason == "target_exited":
                run = False
            self.running = run
            if run:
                self.started = time.monotonic() if self.state in ("idle", "stopped") else self.started
                self.state, self.reason = "running", None
            elif self.state != "stopped" or self.reason != "target_exited":
                self.state = "paused" if (self.items or self.pool) else "idle"
            self.last_client = time.monotonic()
            self.cond.notify_all()
        if self.running:
            self._ensure_thread()
        self._publish()

    def _item_spec(self, raw: Any) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raise ExploreError("INVALID_PARAM", "an item is {expr} or {addr, type}")
        if raw.get("expr") is not None:
            expr = check_expr(raw.get("expr"))
            size = self._expr_size(expr)
            return {"id": "e:" + expr, "kind": "expr", "expr": expr, "label": expr, "size": size}
        if raw.get("addr") is not None:
            addr = parse_addr(raw.get("addr"))
            ty = str(raw.get("type") or "u64")
            if ty not in ("u64", "u32", "i32", "u8"):
                raise ExploreError("INVALID_PARAM", "type must be u64, u32, i32 or u8")
            size = {"u64": 8, "u32": 4, "i32": 4, "u8": 1}[ty]
            return {"id": f"a:{addr:x}:{ty}", "kind": "addr", "addr": addr, "type": ty, "label": f"0x{addr:x} ({ty})",
                    "size": size}
        raise ExploreError("INVALID_PARAM", "an item is {expr} or {addr, type}")

    def _expr_size(self, expr: str) -> int:
        """The bytes one evaluation reads (the expression's type size from DWARF; pointer steps add a word each)."""
        try:
            idx = self.x._index()
        except ExploreError:
            raise
        root = re.match(r"^\**(" + _IDENT + ")", expr).group(1)
        syms = [s for s in idx.search_symbols(query=root, category="all", limit=20, smart_rank=True)
                if s.get("name") == root and s.get("kind") in ("global_variable", "static_variable")]
        if not syms:
            raise ExploreError("NOT_FOUND", f"no global or static variable named {root}", 404)
        size = int(syms[0].get("size") or 8)
        hops = expr.count("->") + expr.count("*")
        return min(size, SAMPLE_BYTES_MAX) + 8 * hops

    def _pool_spec(self, raw: Any) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raise ExploreError("INVALID_PARAM", "pool is {expr, count, field, sel}")
        expr = check_expr(raw.get("expr"))
        if not re.match("^" + _IDENT + "$", expr):
            raise ExploreError("INVALID_PARAM", "the pool expression must be the name of a global or static array")
        field = raw.get("field") or None
        if field is not None and not re.match("^" + _IDENT + "$", str(field)):
            raise ExploreError("INVALID_PARAM", "field must be a field name")
        geo = pool_geometry(self.x._index(), expr, field)
        if not geo.get("field"):
            raise ExploreError("INVALID_PARAM", f"{geo['elem_type']} has no state/status or enumeration field; name one")
        count = raw.get("count", geo["count"])
        if isinstance(count, bool) or not str(count).isdigit() or not 1 <= int(count) <= geo["count"]:
            raise ExploreError("INVALID_PARAM", f"count must be 1..{geo['count']}")
        count = int(count)
        sel = raw.get("sel")
        if sel is not None and (isinstance(sel, bool) or not str(sel).isdigit() or int(sel) >= count):
            raise ExploreError("INVALID_PARAM", "sel must be an element index")
        nbytes = count * geo["elem_size"] + (geo["elem_size"] if sel is not None else 0)
        reserved = (count + POOL_RESERVE_ELEMS) * geo["elem_size"]       # what the budget check charges: + locating read, + selected element
        per_cell = max(1, -(-count // POOL_CELLS))
        return {"key": f"{expr}:{count}:{geo['field']}", "expr": expr, "count": count, "geo": geo, "bytes": nbytes, "reserved": reserved,
                "sel": int(sel) if sel is not None else None, "per_cell": per_cell, "classes": None, "base_counts": None,
                "prev_cells": None, "frame": None, "base": None, "sel_last_change": None, "sel_prev": None, "start_seq": None}

    # -- sampling
    def _ensure_thread(self) -> None:
        with self.cond:
            if self.thread is not None and self.thread.is_alive():
                return
            self._stop.clear()
            self.thread = threading.Thread(target=self._loop, name=f"watch-{self.x.job.job_id[:6]}", daemon=True)
            self.thread.start()

    def touch(self) -> None:
        self.last_client = time.monotonic()

    def _loop(self) -> None:
        next_at = time.monotonic()
        while not self._stop.is_set():
            with self.cond:
                if not self.running:
                    return
                if time.monotonic() - self.last_client > IDLE_STOP_S:
                    self._halt("idle", f"no client asked for {IDLE_STOP_S:.0f} s")
                    return
                if time.monotonic() - self.started > MAX_LIFETIME_S:
                    self._halt("max_lifetime", f"sampling ran for {MAX_LIFETIME_S / 60:.0f} min")
                    return
                interval = self.interval
            try:
                self._sample()
            except ExploreError as exc:
                with self.cond:
                    self._halt("target_exited" if exc.code == "TARGET_EXITED" else "read_failed", exc.message)
                self._publish()
                return
            next_at += interval
            delay = next_at - time.monotonic()
            if delay < 0:
                next_at = time.monotonic()
                delay = 0
            with self.cond:
                self.cond.wait(delay)

    def _halt(self, reason: str, detail: str) -> None:
        self.running = False
        self.state = "stopped"
        self.reason, self.reason_detail = reason, detail
        self.cond.notify_all()
        self._stop.set()
        if self.on_stop:
            try:
                self.on_stop(self)
            except Exception:  # noqa: BLE001
                pass

    def stop(self, reason: str = "stopped", detail: str = "") -> None:
        with self.cond:
            if self.state != "stopped":
                self._halt(reason, detail)
        self._publish()

    def _sample(self) -> None:
        t = self.t
        with self.cond:
            items = list(self.items)
            pool = self.pool
        exprs = [it.spec["expr"] for it in items if it.spec["kind"] == "expr"]
        elf = t.elf() or ""

        def read() -> Dict[str, Any]:
            out: Dict[str, Any] = {"pid": t.pid, "exprs": None, "addrs": {}, "pool": None, "sel": None}
            if exprs:
                out["exprs"] = t.mgr.evaluate_symbol_paths(pid=t.pid, companion_elf_path=elf, expressions=exprs, **t.remote_kw())
            for it in items:
                if it.spec["kind"] == "addr":
                    out["addrs"][it.id] = t.adapter.read_memory(t.pid, it.spec["addr"], it.size)
            if pool:
                if pool["base"] is None:
                    r = t.mgr.evaluate_symbol_paths(pid=t.pid, companion_elf_path=elf, expressions=[f"{pool['expr']}[0]"],
                                                    **t.remote_kw())
                    r0 = (r.get("results") or [{}])[0]
                    if r0.get("status") != "OBSERVED" or not r0.get("runtime_address"):
                        raise ExploreError("READ_FAILED", f"cannot locate {pool['expr']}: {r0.get('error')}", 502)
                    pool["base"] = int(str(r0["runtime_address"]), 16)
                g = pool["geo"]
                out["pool"] = t.adapter.read_memory(t.pid, pool["base"], pool["count"] * g["elem_size"])
                if pool["sel"] is not None:
                    r = t.mgr.evaluate_symbol_paths(pid=t.pid, companion_elf_path=elf,
                                                    expressions=[f"{pool['expr']}[{pool['sel']}]"], **t.remote_kw())
                    out["sel"] = (r.get("results") or [{}])[0]
            return out

        raw, cost = t.run(read, limited=False)
        stamp = _now_iso()
        with self.cond:
            self.seq += 1
            self.n += 1
            self.first_t = self.first_t or stamp
            self.last_t = stamp
            res = {r.get("expression"): r for r in ((raw.get("exprs") or {}).get("results") or [])}
            for it in items:
                if it.spec["kind"] == "expr":
                    r = res.get(it.spec["expr"]) or {}
                    if r.get("status") == "OBSERVED":
                        it.type = it.type or r.get("type_name")
                        it.error = None
                        it.push(self.seq, stamp, _flatten(r.get("value")))
                    else:
                        it.error = str(r.get("error") or r.get("status") or "not read")
                else:
                    b, st, err = raw["addrs"].get(it.id) or (None, "UNAVAILABLE", "not read")
                    if b and len(b) >= it.size:
                        v = int.from_bytes(b[:it.size], "little", signed=it.spec["type"] == "i32")
                        it.error = None
                        it.type = it.spec["type"]
                        it.push(self.seq, stamp, {"": v})
                    else:
                        it.error = err or st
            if pool is not None and raw.get("pool") is not None:
                b, st, err = raw["pool"]
                if not b:
                    raise ExploreError("READ_FAILED", f"pool read failed: {err or st}", 502)
                self._pool_frame(pool, b, raw.get("sel"))
            self.cost = dict(cost, interval_s=self.interval, reads_per_s=round(cost["reads"] / self.interval, 2),
                             bytes_per_s=round(cost["bytes"] / self.interval))
            self.cond.notify_all()
        self._publish()

    def _pool_frame(self, pool: Dict[str, Any], b: bytes, sel: Optional[Dict[str, Any]]) -> None:
        g = pool["geo"]
        es, off, fs, n = g["elem_size"], g["field_offset"], g["field_size"], pool["count"]
        vals = [int.from_bytes(b[i * es + off:i * es + off + fs], "little") for i in range(min(n, len(b) // es))]
        counts: Dict[int, int] = {}
        for v in vals:
            counts[v] = counts.get(v, 0) + 1
        if pool["classes"] is None:          # stable colours: zero is "empty", then enum order (or the most frequent)
            keys = sorted(set(vals) | set((g.get("enum") or {}).keys()))
            nonzero = [k for k in keys if k != 0]
            if len(nonzero) > 5:
                nonzero = sorted(nonzero, key=lambda k: -counts.get(k, 0))[:4]
                nonzero.sort()
            pool["classes"] = {0: 0, **{k: i + 1 for i, k in enumerate(nonzero[:5])}}
            pool["other"] = len([k for k in keys if k != 0]) > 5
            pool["start_seq"] = self.seq
        cls = pool["classes"]
        other = 5 if pool.get("other") else None

        def c(v: int) -> int:
            return cls.get(v, other if other is not None else 5)

        per = pool["per_cell"]
        cells = []
        for i in range(0, len(vals), per):
            chunk = vals[i:i + per]
            if per == 1:
                cells.append(c(chunk[0]))
            else:
                tally: Dict[int, int] = {}
                for v in chunk:
                    tally[c(v)] = tally.get(c(v), 0) + 1
                cells.append(max(tally.items(), key=lambda kv: (kv[1], -kv[0]))[0])
        cstr = "".join(str(x) for x in cells)
        ccounts = [0] * 6
        for v in vals:
            ccounts[c(v)] += 1
        if pool["base_counts"] is None:
            pool["base_counts"] = list(ccounts)
        prev = pool["prev_cells"]
        changed = sum(1 for a, z in zip(prev, cstr) if a != z) if prev else 0
        pool["prev_cells"] = cstr
        pool["frame"] = {"cells": cstr, "counts": ccounts, "changed": changed, "seq": self.seq, "vals": None}
        pool["last_vals"] = vals
        if sel is not None and pool["sel"] is not None:
            leaves = _flatten(sel.get("value")) if sel.get("status") == "OBSERVED" else {}
            if pool.get("sel_prev") is not None and pool["sel_prev"][0] == pool["sel"]:
                if pool["sel_prev"][1].get("." + g["field"]) != leaves.get("." + g["field"]):
                    pool["sel_last_change"] = (self.seq, self.last_t)
            else:
                pool["sel_last_change"] = None
            pool["sel_prev"] = (pool["sel"], leaves)
            pool["sel_view"] = {"index": pool["sel"], "addr": sel.get("runtime_address"), "fields": leaves,
                                "last_change": pool["sel_last_change"][1] if pool.get("sel_last_change") else None}
        else:
            pool["sel_view"] = None

    def _legend(self, pool: Dict[str, Any]) -> List[Dict[str, Any]]:
        g = pool["geo"]
        enum = g.get("enum") or {}
        fr = pool.get("frame") or {}
        cnt = fr.get("counts") or [0] * 6
        base = pool.get("base_counts") or cnt
        out = []
        for v, k in sorted((pool.get("classes") or {}).items(), key=lambda kv: kv[1]):
            out.append({"cls": k, "value": v, "name": enum.get(v) or str(v), "count": cnt[k], "delta": cnt[k] - base[k]})
        if pool.get("other"):
            out.append({"cls": 5, "value": None, "name": None, "count": cnt[5], "delta": cnt[5] - base[5]})
        return out

    def _snapshot_values(self) -> Dict[str, Any]:
        leaves = {}
        for it in self.items:
            if it.hist:
                for k, v in it.hist[-1][2].items():
                    leaves[it.label + k] = v
        pool = None
        if self.pool and self.pool.get("frame"):
            pool = {"counts": list(self.pool["frame"]["counts"]), "cells": self.pool["frame"]["cells"]}
        return {"seq": self.seq, "t": self.last_t, "leaves": leaves, "pool": pool}

    def _compare(self) -> Optional[Dict[str, Any]]:
        if not self.pin:
            return None
        now = self._snapshot_values()
        changed, same = [], 0
        for k, before in self.pin["leaves"].items():
            after = now["leaves"].get(k)
            if after != before:
                d = after - before if isinstance(after, (int, float)) and isinstance(before, (int, float)) and not isinstance(after, bool) else None
                changed.append({"name": k, "before": before, "now": after, "diff": d})
            else:
                same += 1
        pool = None
        if self.pin.get("pool") and now.get("pool") and self.pool:
            leg = self._legend(self.pool)
            names = {x["cls"]: x["name"] for x in leg}
            per = []
            for k in range(6):
                a, z = self.pin["pool"]["counts"][k], now["pool"]["counts"][k]
                if a != z:
                    per.append({"cls": k, "name": names.get(k), "before": a, "now": z, "diff": z - a})
            cells = sum(1 for a, z in zip(self.pin["pool"]["cells"], now["pool"]["cells"]) if a != z)
            pool = {"counts": per, "cells_changed": cells, "cells": len(now["pool"]["cells"])}
        return {"from_seq": self.pin["seq"], "from_t": self.pin["t"], "to_seq": now["seq"], "to_t": now["t"],
                "changed": changed, "same": same, "pool": pool}

    def snapshot(self) -> Dict[str, Any]:
        """Everything the UI shows (and the report keeps) for this observation, as plain data."""
        with self.cond:
            pool = None
            if self.pool:
                p, g = self.pool, self.pool["geo"]
                pool = {"expr": p["expr"], "count": p["count"], "total": g["count"], "truncated": p["count"] < g["count"], "elem_size": g["elem_size"], "elem_type": g["elem_type"],
                        "field": g["field"], "field_type": g.get("field_type"), "per_cell": p["per_cell"],
                        "bytes": p["count"] * g["elem_size"], "legend": self._legend(p) if p.get("frame") else [],
                        "cells": (p.get("frame") or {}).get("cells"), "changed": (p.get("frame") or {}).get("changed", 0),
                        "sel": p.get("sel"), "sel_view": p.get("sel_view"), "start_seq": p.get("start_seq"),
                        "members": [m["name"] for m in g.get("members") or []]}
            per_sample = sum(t.size for t in self.items) + (self.pool["bytes"] if self.pool else 0)
            reads = sum(1 for t in self.items) + (2 if self.pool and self.pool.get("sel") is not None else 1 if self.pool else 0)
            return {"seq": self.seq, "samples": self.n, "state": self.state, "reason": self.reason, "reason_detail": self.reason_detail,
                    "interval_s": self.interval, "intervals": [x for x in INTERVALS_S if x >= self.min_interval()],
                    "transport": "ssh" if self.t.is_remote else "local", "first_t": self.first_t, "last_t": self.last_t,
                    "items": [it.view() for it in self.items], "pool": pool, "compare": self._compare(),
                    "pinned": bool(self.pin), "cost": self.cost,
                    "plan": {"reads_per_sample": reads, "bytes_per_sample": per_sample,
                             "reads_per_s": round(reads / self.interval, 2), "bytes_per_s": round(per_sample / self.interval),
                             "limits": {"items": WATCH_MAX_ITEMS, "bytes_per_sample": SAMPLE_BYTES_MAX,
                                        "bytes_per_s": BYTES_PER_S_MAX, "idle_stop_s": IDLE_STOP_S,
                                        "max_lifetime_s": MAX_LIFETIME_S}}}

    # -- publication (SSE / polling)
    def _publish(self) -> None:
        with self.cond:
            self.version = getattr(self, "version", 0) + 1
            self.cond.notify_all()

    def wait(self, after: int, timeout: float) -> Tuple[int, bool]:
        """Block until the published version is past ``after`` (or timeout); returns (version, alive)."""
        self.touch()
        with self.cond:
            if getattr(self, "version", 0) <= after and self.state == "running":
                self.cond.wait(timeout)
            return getattr(self, "version", 0), self.state == "running"


class ExploreHub:
    """One explorer per job, created on first use; watch sessions are capped across jobs."""

    def __init__(self, corpus_dir: str):
        self.corpus_dir = corpus_dir
        self.lock = threading.Lock()
        self.by_job: Dict[str, JobExplorer] = {}

    def get(self, job: Any) -> JobExplorer:
        with self.lock:
            x = self.by_job.get(job.job_id)
            if x is None:
                x = self.by_job[job.job_id] = JobExplorer(job, self.corpus_dir)
            return x

    def prune(self, alive_ids: List[str]) -> None:
        with self.lock:
            for jid in [j for j in self.by_job if j not in alive_ids]:
                x = self.by_job.pop(jid)
                if x.watch is not None:
                    x.watch.stop("job_evicted")

    def watch(self, job: Any, create: bool = True) -> Optional[WatchSession]:
        x = self.get(job)
        with x.watch_lock:
            if x.watch is None and create:
                with self.lock:
                    active = sum(1 for y in self.by_job.values() if y.watch is not None and y.watch.state == "running")
                if active >= MAX_ACTIVE_WATCHES:
                    raise ExploreError("TOO_MANY_WATCHES", f"at most {MAX_ACTIVE_WATCHES} observations run at the same time", 429)
                x.watch = WatchSession(x)
            return x.watch

    def stop_all(self) -> None:
        with self.lock:
            xs = list(self.by_job.values())
        for x in xs:
            if x.watch is not None:
                x.watch.stop("server_stopped")

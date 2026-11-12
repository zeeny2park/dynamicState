"""IMP-010: per-thread time-series sampling wired to the thread-misbehaviour recipes.

Read-only (only /proc reads and process_vm reads through the adapter; no signals, no stop).

Three parts:

* ``augment_lock_info``      widens the mutex candidates of ``inspect_thread_callstacks_and_locks`` with
                             struct-member mutexes (reported as ``variable.member``) and with futex addresses
                             threads are currently waiting on.  Owner decoding is gated by the IMP-015 support
                             table (``FEATURE_MUTEX_OWNER``): on an unsupported / undetected target the lock is
                             reported with an explicit status and no owner is guessed.
* ``LockObservationSeries``  feeds every successful lock inspection into a ``WaitForGraph`` and judges
                             persistence with the graph's multi-observation semantics.  A failed sample is not
                             an observation; a different cycle is not persistence.
* ``ThreadSampler``          collects N samples per thread (state, utime/stime, context switches, syscall,
                             top frame) and derives CPU share, time in the same frame/syscall, time since last
                             progress and thread-count trend, then maps them onto the EXISTING recipe input keys.
"""

from __future__ import annotations

import os
import struct
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from .concurrency_graph import WaitForGraph
from .target_abi import (
    FEATURE_MUTEX_OWNER,
    TargetABI,
    check_support,
    detect_target_abi,
    syscall_name as abi_syscall_name,
)

try:
    CLK_TCK = float(os.sysconf("SC_CLK_TCK"))
except (ValueError, OSError, AttributeError):  # pragma: no cover
    CLK_TCK = 100.0

MUTEX_SPAN = 40          # sizeof(pthread_mutex_t) on 64-bit glibc; upper bound used to match futex addresses
FUTEX_CMD_WAIT = 0
FUTEX_CMD_WAIT_BITSET = 9
LONG_WAIT_VERDICT = "long wait observed, cannot determine whether expected"


# --------------------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------------------
@dataclass
class ThreadSamplingConfig:
    samples: int = 5
    interval_sec: float = 0.15
    runaway_cpu_share: float = 0.50
    # A spinner can still take a stray voluntary switch (page-fault lock, start-up tail). Requiring exactly zero
    # made the verdict flip on a single event; tolerate a negligible rate instead.
    runaway_max_voluntary_switches_per_sec: float = 2.0
    min_samples_for_verdict: int = 3
    max_window_fraction_of_budget: float = 0.5

    @classmethod
    def from_thresholds(cls, thresholds: Optional[Dict[str, Any]]) -> "ThreadSamplingConfig":
        cfg = cls()
        t = thresholds or {}
        try:
            if t.get("thread_sample_count") is not None:
                cfg.samples = max(2, int(t["thread_sample_count"]))
            if t.get("thread_sample_interval_sec") is not None:
                cfg.interval_sec = max(0.0, float(t["thread_sample_interval_sec"]))
            if t.get("runaway_cpu_share") is not None:
                cfg.runaway_cpu_share = float(t["runaway_cpu_share"])
        except (TypeError, ValueError):
            pass
        return cfg


# --------------------------------------------------------------------------------------
# Lock sample helpers
# --------------------------------------------------------------------------------------
def _edge_key(e: Dict[str, Any]) -> Tuple[int, str, int]:
    return (
        int(e.get("waiter_tid") or e.get("tid") or 0),
        str(e.get("lock_address") or e.get("lock_name") or ""),
        int(e.get("owner_tid") or 0),
    )


def cycle_signature(cycle: List[Dict[str, Any]]) -> frozenset:
    return frozenset(_edge_key(c) for c in cycle if isinstance(c, dict))


def _graph_from_edges(edges: List[Dict[str, Any]]) -> WaitForGraph:
    g = WaitForGraph()
    for e in edges:
        w, lk, o = _edge_key(e)
        if not w or not o:
            continue
        g.add_thread(w, name=e.get("waiter_name"))
        g.add_thread(o, name=e.get("owner_name"))
        g.add_lock(lk, lock_type="mutex")
        g.add_ownership_edge(lk, o)
        g.add_waiting_edge(w, lk)
    return g


def _cycles_as_edges(graph_cycles: List[List[str]], edges: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
    by_key = {(_edge_key(e)[0], _edge_key(e)[1]): e for e in edges}
    out: List[List[Dict[str, Any]]] = []
    for cyc in graph_cycles:
        items: List[Dict[str, Any]] = []
        for s in cyc:  # "thread_<tid> -> <lock_id>"
            try:
                left, lk = s.split(" -> ", 1)
                tid = int(left.replace("thread_", ""))
            except ValueError:
                items = []
                break
            e = by_key.get((tid, lk))
            if e is None:
                items = []
                break
            items.append(e)
        if items:
            out.append(items)
    return out


def _global_only_cycle_edges(edges: List[Dict[str, Any]]) -> Set[Tuple[int, str, int]]:
    """Edges that lie on a cycle formed by ``edges`` alone (the inspector already judged those)."""
    g = _graph_from_edges(edges)
    keys: Set[Tuple[int, str, int]] = set()
    for cyc in _cycles_as_edges(g.find_cycles(), edges):
        keys.update(_edge_key(e) for e in cyc)
    return keys


def sample_edges(info: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Wait-for edges of one lock inspection, trusting the inspector's own cycle verdict.

    Cycle edges come from ``deadlock_cycles`` (only when the inspector reported a deadlock); all other wait
    edges are kept because they can close a cycle together with member/futex edges.
    """
    edges = [e for e in (info.get("wait_for_edges") or []) if isinstance(e, dict)]
    in_global_cycle = _global_only_cycle_edges(edges)
    out = [e for e in edges if _edge_key(e) not in in_global_cycle]
    if info.get("deadlock_detected"):
        for cyc in info.get("deadlock_cycles") or ([info.get("deadlock_cycle")] if info.get("deadlock_cycle") else []):
            out.extend(c for c in cyc if isinstance(c, dict))
    return out


class LockObservationSeries:
    """One ``WaitForGraph`` per successful lock inspection; persistence judged across graphs."""

    def __init__(self) -> None:
        self.samples: List[Dict[str, Any]] = []   # successful observations only
        self.failures: List[Dict[str, Any]] = []

    def add_sample(self, index: int, info: Dict[str, Any]) -> Dict[str, Any]:
        edges = sample_edges(info)
        graph = _graph_from_edges(edges)
        cycles = _cycles_as_edges(graph.find_cycles(), edges)
        rec = {
            "index": index,
            "graph": graph,
            "edges": edges,
            "cycles": cycles,
            "signatures": {cycle_signature(c) for c in cycles},
        }
        self.samples.append(rec)
        return rec

    def add_failure(self, index: int, reason: str) -> None:
        self.failures.append({"index": index, "reason": reason})

    @property
    def observation_count(self) -> int:
        return len(self.samples)

    def persistence(self, signature: frozenset) -> Dict[str, Any]:
        """Is the cycle ``signature`` observed in >= 2 distinct successful samples?"""
        epochs = [s["index"] for s in self.samples if signature in s["signatures"]]
        if not epochs:
            return {"persistent": False, "epochs": [], "state": "NOT_OBSERVED"}
        last = next(s for s in reversed(self.samples) if signature in s["signatures"])
        res = last["graph"].analyze(observation_epochs=epochs)
        return {
            "persistent": bool(res.is_persistent),
            "epochs": epochs,
            "state": getattr(res.state, "value", str(res.state)),
        }


# --------------------------------------------------------------------------------------
# Widening mutex candidates: struct members + futex addresses
# --------------------------------------------------------------------------------------
@dataclass
class _MemberCandidate:
    name: str            # variable.member (or variable->member for pointer globals)
    link_addr: int       # link-time address of the *variable*
    offset: int          # byte offset of the mutex inside the variable (or the pointee)
    via_pointer: bool
    dynamic: bool        # module is ET_DYN: runtime = bias + link
    bias: int


def _is_mutex_type_name(name: str) -> bool:
    n = (name or "").lower()
    return "pthread_mutex_t" in n or n.endswith("mutex_t") or n.endswith("mutex")


def _walk_members(idx: Any, type_offset: Optional[int], prefix: str, base_off: int, depth: int,
                  out: List[Tuple[str, int]]) -> None:
    if depth > 3:
        return
    canon = idx.resolve_canonical_type(type_offset)
    if canon is None:
        return
    if canon.tag == "DW_TAG_array_type":
        elem = idx.resolve_canonical_type(canon.target_type_offset)
        count = canon.array_count or 0
        esize = (elem.byte_size if elem is not None else 0) or 0
        if elem is not None and esize and 0 < count <= 64 and elem.tag in ("DW_TAG_structure_type", "DW_TAG_class_type"):
            for i in range(count):
                _walk_members(idx, canon.target_type_offset, f"{prefix}[{i}]", base_off + i * esize, depth + 1, out)
        return
    if canon.tag not in ("DW_TAG_structure_type", "DW_TAG_class_type"):
        return
    for m in canon.members:
        if not m.name:
            continue
        mname = idx.get_type_name(m.type_offset)
        if _is_mutex_type_name(mname):
            out.append((f"{prefix}.{m.name}", base_off + int(m.offset or 0)))
        else:
            _walk_members(idx, m.type_offset, f"{prefix}.{m.name}", base_off + int(m.offset or 0), depth + 1, out)


class _DwarfData:
    """Static (per companion ELF) index of member-mutex candidates and of global data ranges."""

    def __init__(self) -> None:
        self.members: List[Tuple[str, int, int, bool]] = []     # (name, var_link_addr, offset, via_pointer)
        self.ranges: List[Tuple[int, int, str, Any, Optional[int]]] = []  # (start, end, var, idx, type_off) link-time

    @classmethod
    def build(cls, idx: Any) -> "_DwarfData":
        d = cls()
        seen: Set[str] = set()
        for var in idx.variables:
            if var.link_time_address is None or var.is_declaration or not var.name or var.is_tls:
                continue
            if var.name in seen:
                continue
            seen.add(var.name)
            canon = idx.resolve_canonical_type(var.type_offset)
            if canon is None:
                continue
            size = canon.byte_size or 0
            if size:
                d.ranges.append((var.link_time_address, var.link_time_address + size, var.name, idx, var.type_offset))
            found: List[Tuple[str, int]] = []
            if canon.tag == "DW_TAG_pointer_type":
                tgt = idx.resolve_canonical_type(canon.target_type_offset)
                if tgt is not None and tgt.tag in ("DW_TAG_structure_type", "DW_TAG_class_type"):
                    _walk_members(idx, canon.target_type_offset, var.name, 0, 0, found)
                    for n, off in found:
                        d.members.append((n.replace(var.name + ".", var.name + "->", 1), var.link_time_address, off, True))
                continue
            _walk_members(idx, var.type_offset, var.name, 0, 0, found)
            for n, off in found:
                d.members.append((n, var.link_time_address, off, False))
        return d


_DWARF_CACHE: Dict[Tuple[str, float, int], _DwarfData] = {}


def _dwarf_data_for(idx: Any, path: str) -> _DwarfData:
    try:
        st = os.stat(path)
        key = (path, st.st_mtime, st.st_size)
    except OSError:
        key = (path, 0.0, 0)
    d = _DWARF_CACHE.get(key)
    if d is None:
        d = _DwarfData.build(idx)
        _DWARF_CACHE[key] = d
    return d


def _read_proc_file(path: str, counters: Optional[Dict[str, int]]) -> Optional[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            data = f.read()
        if counters is not None:
            counters["proc_reads"] = counters.get("proc_reads", 0) + 1
        return data
    except OSError:
        if counters is not None:
            counters["proc_read_errors"] = counters.get("proc_read_errors", 0) + 1
        return None


def read_syscall(pid: int, tid: int, counters: Optional[Dict[str, int]] = None) -> Optional[Dict[str, Any]]:
    raw = _read_proc_file(f"/proc/{pid}/task/{tid}/syscall", counters)
    if raw is None:
        return None
    raw = raw.strip()
    if not raw:
        return None
    if raw.startswith("running"):
        return {"running": True}
    parts = raw.split()
    try:
        nr = int(parts[0])
        args = [int(p, 16) for p in parts[1:7]]
    except ValueError:
        return None
    return {"running": False, "nr": nr, "args": args}


def augment_lock_info(
    info: Any,
    *,
    pid: int,
    adapter: Any,
    companion_elf: str,
    watch_manager: Any,
    counters: Optional[Dict[str, int]] = None,
) -> Any:
    """Return ``info`` extended with struct-member mutexes and futex-address locks.

    Never raises: any failure leaves ``info`` unchanged and adds a limitation.  Remote targets are returned
    unchanged (thread syscall data is not available remotely; roadmap IMP-011/021).
    """
    if not isinstance(info, dict) or info.get("error") or not info.get("threads"):
        return info
    try:
        if adapter.is_remote():
            return info
    except Exception:  # noqa: BLE001
        return info
    out = dict(info)
    notes: List[str] = list(info.get("limitations") or [])
    try:
        abi = TargetABI.from_dict(info["target_abi"]) if info.get("target_abi") else detect_target_abi(adapter, pid)
        owner_support = check_support(abi, FEATURE_MUTEX_OWNER)
        primary, _ = watch_manager._split_companion_elf_paths(companion_elf)
        if not primary:
            return info
        from .dwarf_indexer import DwarfIndexer
        idx = DwarfIndexer.get_index(primary)
        map_data = watch_manager._get_process_maps_and_load_bias(pid=pid, companion_elf_path=companion_elf, adapter=adapter)
        bias = int(map_data.get("base_address_int", 0) or 0)
        is_dyn = idx.elf_type == "ET_DYN"
        data = _dwarf_data_for(idx, primary)

        def rt(link: int) -> int:
            return (bias + link) if is_dyn else link

        ptr_size = idx.pointer_size or ((abi.word_size or 64) // 8)
        endian = "<" if (idx.endianness or abi.endianness or "little") == "little" else ">"
        thread_names = {int(t["tid"]): t.get("name") for t in info.get("threads", []) if t.get("tid") is not None}

        locks: List[Dict[str, Any]] = [dict(l) for l in (info.get("locks") or [])]
        known_addrs = {int(l.get("runtime_address_int") or 0) for l in locks}
        new_locks: List[Dict[str, Any]] = []

        def read_mutex(name: str, addr: int, source: str) -> Dict[str, Any]:
            entry: Dict[str, Any] = {
                "name": name,
                "runtime_address": f"0x{addr:x}",
                "runtime_address_int": addr,
                "type_name": "pthread_mutex_t",
                "discovered_via": source,
                "waiting_tids": [],
            }
            if not owner_support.supported:
                entry.update(is_locked=None, lock_state_word=None, recursion_count=None, owner_tid=None,
                             owner_thread_name=None, owner_status=owner_support.status,
                             owner_status_reason=owner_support.message)
                return entry
            raw, st, err = adapter.read_memory(pid, addr, 12)
            if st != "OBSERVED" or not raw or len(raw) < 12:
                entry.update(is_locked=None, owner_tid=None, owner_thread_name=None, owner_status="READ_FAILED",
                             owner_status_reason=str(err or st))
                return entry
            lock_word, count_word, owner = struct.unpack(endian + "iii", raw[:12])
            entry.update(
                is_locked=(lock_word != 0) or owner > 0,
                lock_state_word=lock_word,
                recursion_count=count_word,
                owner_tid=owner if owner > 0 else None,
                owner_thread_name=(thread_names.get(owner) if owner in thread_names
                                   else ("DEAD_OR_EXTERNAL_THREAD" if owner > 0 else None)),
                owner_status=owner_support.status,
            )
            return entry

        # 1) struct-member mutexes (variable.member)
        for name, var_link, off, via_ptr in data.members:
            var_rt = rt(var_link)
            if via_ptr:
                raw, st, _ = adapter.read_memory(pid, var_rt, ptr_size)
                if st != "OBSERVED" or not raw or len(raw) < ptr_size:
                    continue
                base = struct.unpack(endian + ("Q" if ptr_size == 8 else "I"), raw[:ptr_size])[0]
                if not base:
                    continue
                addr = base + off
            else:
                addr = var_rt + off
            if addr in known_addrs:
                # the inspector already reports this address (lock-like variable name): give it the member name
                for l in locks:
                    if int(l.get("runtime_address_int") or 0) == addr and "." not in str(l.get("name")) and "->" not in str(l.get("name")):
                        l["name"] = name
                continue
            known_addrs.add(addr)
            new_locks.append(read_mutex(name, addr, "STRUCT_MEMBER"))

        # 2) futex addresses threads are waiting on that no known lock covers
        def covering(addr: int) -> Optional[Dict[str, Any]]:
            for l in locks + new_locks:
                a = int(l.get("runtime_address_int") or 0)
                if a <= addr < a + MUTEX_SPAN:
                    return l
            return None

        thread_sys: Dict[int, Dict[str, Any]] = {}
        for t in info["threads"]:
            tid = int(t["tid"])
            sc = read_syscall(pid, tid, counters)
            if sc and not sc.get("running"):
                thread_sys[tid] = sc
        for tid, sc in thread_sys.items():
            sc_name = abi_syscall_name(abi, sc["nr"])
            if sc_name != "futex" or not sc["args"]:
                continue
            uaddr = sc["args"][0]
            if not uaddr or covering(uaddr) is not None:
                continue
            cmd = (sc["args"][1] & 0x7F) if len(sc["args"]) > 1 else -1
            if cmd != FUTEX_CMD_WAIT:
                continue  # FUTEX_WAIT_BITSET etc. is how glibc waits on condition variables: not a mutex
            sym = _symbolize(data, rt, uaddr, idx)
            name = sym or f"futex@0x{uaddr:x}"
            entry = read_mutex(name, uaddr, "FUTEX_WAIT_ADDRESS")
            if owner_support.supported:
                word = entry.get("lock_state_word")
                owner = entry.get("owner_tid")
                # only accept as a pthread mutex when the layout validates: contended word and a live owner thread
                if word not in (1, 2) or owner not in thread_names:
                    continue
            new_locks.append(entry)
            known_addrs.add(uaddr)

        if not new_locks and locks == (info.get("locks") or []):
            return info

        # 3) edges for waiting threads
        wait_edges = [dict(e) for e in (info.get("wait_for_edges") or [])]
        existing_waiters = {(e["waiter_tid"], str(e.get("lock_address"))) for e in wait_edges}
        threads_out = [dict(t) for t in info["threads"]]
        added: List[Dict[str, Any]] = []
        for t in threads_out:
            tid = int(t["tid"])
            sc = thread_sys.get(tid)
            if not sc or not sc["args"] or abi_syscall_name(abi, sc["nr"]) != "futex":
                continue
            uaddr = sc["args"][0]
            lk = None
            for l in new_locks:
                a = int(l["runtime_address_int"])
                if a <= uaddr < a + MUTEX_SPAN:
                    lk = l
                    break
            if lk is None or t.get("waiting_on_lock"):
                continue
            t["waiting_on_lock"] = {
                "lock_name": lk["name"],
                "lock_address": lk["runtime_address"],
                "held_by_tid": lk.get("owner_tid"),
                "held_by_thread_name": lk.get("owner_thread_name"),
                "resolved_via": lk["discovered_via"],
            }
            if tid not in lk["waiting_tids"]:
                lk["waiting_tids"].append(tid)
            owner = lk.get("owner_tid")
            if owner and owner != tid and (tid, lk["runtime_address"]) not in existing_waiters:
                e = {
                    "waiter_tid": tid,
                    "waiter_name": t.get("name"),
                    "lock_name": lk["name"],
                    "lock_address": lk["runtime_address"],
                    "owner_tid": owner,
                    "owner_name": lk.get("owner_thread_name"),
                }
                wait_edges.append(e)
                added.append(e)

        out["locks"] = locks + new_locks
        out["locks_inspected"] = len(out["locks"])
        out["threads"] = threads_out
        out["wait_for_edges"] = wait_edges
        out["blocked_threads"] = [t for t in threads_out if t.get("waiting_on_lock") is not None]
        if not owner_support.supported:
            out["lock_owner_status"] = owner_support.status
            out["lock_owner_status_reason"] = owner_support.message

        # 4) cycles that need the new edges (pure-global cycles were already judged by the inspector)
        if added:
            already_judged = _global_only_cycle_edges([e for e in wait_edges if e not in added])
            g_edges = [e for e in wait_edges if _edge_key(e) not in already_judged]
            g = _graph_from_edges(g_edges)
            new_cycles = _cycles_as_edges(g.find_cycles(), g_edges)
            have = [cycle_signature(c) for c in (info.get("deadlock_cycles") or [])]
            extra = [c for c in new_cycles if cycle_signature(c) not in have]
            if extra:
                cycles = list(info.get("deadlock_cycles") or []) + extra
                out["deadlock_cycles"] = cycles
                out["deadlock_cycle"] = cycles[0]
                out["deadlock_detected"] = True
                out["status"] = "ANOMALIES_DETECTED"
                out["llm_next_step_hint"] = (
                    f"CRITICAL DEADLOCK DETECTED: Circular mutex wait across {len(cycles[0])} threads: "
                    + " -> ".join(f"TID {e['waiter_tid']} ({e['waiter_name']}) waits on {e['lock_name']} held by "
                                  f"TID {e['owner_tid']}" for e in cycles[0])
                )
            elif out.get("status") == "OBSERVED":
                out["status"] = "ANOMALIES_DETECTED"
    except Exception as exc:  # noqa: BLE001
        notes.append(f"member/futex mutex discovery failed: {type(exc).__name__}: {exc}")
        out = dict(info)
        out["limitations"] = notes
        return out
    return out


def _symbolize(data: _DwarfData, rt: Callable[[int], int], addr: int, idx: Any) -> Optional[str]:
    """Name a data address as ``var`` or ``var.member`` using DWARF globals."""
    for start, end, var, vidx, toff in data.ranges:
        if rt(start) <= addr < rt(end):
            off = addr - rt(start)
            found: List[Tuple[str, int]] = []
            _walk_members(vidx, toff, var, 0, 0, found)
            for n, moff in found:
                if moff == off:
                    return n
            return var if off == 0 else f"{var}+0x{off:x}"
    return None


# --------------------------------------------------------------------------------------
# Thread time series
# --------------------------------------------------------------------------------------
def read_thread_fields(pid: int, tid: int, counters: Dict[str, int]) -> Optional[Dict[str, Any]]:
    """state, utime/stime, context switches, io syscall counters of one thread (4 small /proc reads)."""
    base = f"/proc/{pid}/task/{tid}"
    stat = _read_proc_file(f"{base}/stat", counters)
    if stat is None:
        return None
    rp = stat.rfind(")")
    lp = stat.find("(")
    if rp == -1 or lp == -1:
        return None
    rest = stat[rp + 1:].split()
    if len(rest) < 13:
        return None
    try:
        rec: Dict[str, Any] = {
            "tid": tid,
            "name": stat[lp + 1:rp],
            "state": rest[0],
            "utime_ticks": int(rest[11]),
            "stime_ticks": int(rest[12]),
        }
    except ValueError:
        return None
    vol = invol = None
    status = _read_proc_file(f"{base}/status", counters)
    for line in (status or "").splitlines():
        if line.startswith("voluntary_ctxt_switches:"):
            vol = int(line.split(":", 1)[1])
        elif line.startswith("nonvoluntary_ctxt_switches:"):
            invol = int(line.split(":", 1)[1])
    rec["voluntary_ctxt_switches"] = vol
    rec["nonvoluntary_ctxt_switches"] = invol
    io = _read_proc_file(f"{base}/io", counters)
    syscr = syscw = None
    for line in (io or "").splitlines():
        if line.startswith("syscr:"):
            syscr = int(line.split(":", 1)[1])
        elif line.startswith("syscw:"):
            syscw = int(line.split(":", 1)[1])
    rec["io_syscalls"] = (syscr + syscw) if (syscr is not None and syscw is not None) else None
    rec["syscall"] = read_syscall(pid, tid, counters)
    return rec


def read_local_thread_samples(pid: int, counters: Dict[str, int]) -> Optional[List[Dict[str, Any]]]:
    """One local sample (LocalTargetAdapter.read_thread_samples): None when /proc/PID/task is unreadable."""
    try:
        tids = sorted(int(x) for x in os.listdir(f"/proc/{pid}/task") if x.isdigit())
    except OSError:
        return None
    counters["proc_reads"] = counters.get("proc_reads", 0) + 1
    out: List[Dict[str, Any]] = []
    for tid in tids:
        rec = read_thread_fields(pid, tid, counters)   # a thread may vanish mid-read: skipped
        if rec is not None:
            out.append(rec)
    return out


def _top_frame(thread_report: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    cs = thread_report.get("callstack") or []
    if not cs:
        return None
    # IMP-011: for blocked threads frame 0 is now the libc wait frame, and for running threads a stale
    # libc callee can sit above the real leaf. Report the first frame that belongs to code with debug
    # info (the "top user frame"); fall back to frame 0 when the unwinder gives no such index.
    idx = thread_report.get("top_user_frame_index")
    f = cs[idx] if isinstance(idx, int) and 0 <= idx < len(cs) else cs[0]
    return {
        "function": f.get("function_name"),
        "source_location": f.get("source_location"),
        "estimated": bool(f.get("estimated")),
        "unwind": f.get("unwind"),
    }


@dataclass
class ThreadSeries:
    pid: int
    config: ThreadSamplingConfig
    abi: Optional[TargetABI] = None
    samples: List[Dict[str, Any]] = field(default_factory=list)       # {"index","t","threads":{tid:rec}}
    lock_series: LockObservationSeries = field(default_factory=LockObservationSeries)
    failures: List[Dict[str, Any]] = field(default_factory=list)
    counters: Dict[str, int] = field(default_factory=dict)
    wall_sec: float = 0.0
    stop_reason: Optional[str] = None


class ThreadSampler:
    def __init__(self, adapter: Any, watch_manager: Any, budget_tracker: Any = None) -> None:
        self.adapter = adapter
        self.watch_manager = watch_manager
        self.budget_tracker = budget_tracker

    # -- collection -------------------------------------------------------------------
    def _budget_ok(self, t_start: float, cfg: ThreadSamplingConfig) -> Optional[str]:
        bt = self.budget_tracker
        if bt is None:
            return None
        try:
            if not bt.can_continue():
                return f"observation budget exhausted: {bt.exhaustion_reason}"
            remaining_ms = float(bt.limits.max_wall_clock_ms) - float(bt.elapsed_ms)
            if (time.monotonic() - t_start) * 1000.0 > max(0.0, remaining_ms) * cfg.max_window_fraction_of_budget + 1:
                return "sampling window reached its share of the wall-clock budget"
        except Exception:  # noqa: BLE001
            return None
        return None

    def _target_alive(self, pid: int, remote: bool) -> bool:
        if not remote:
            return os.path.exists(f"/proc/{pid}")
        try:
            return bool(self.adapter.check_liveness(pid)[0])
        except Exception:  # noqa: BLE001
            return True

    def collect(
        self,
        pid: int,
        companion_elf: str,
        config: Optional[ThreadSamplingConfig] = None,
        inspect_fn: Optional[Callable[[], Any]] = None,
    ) -> ThreadSeries:
        cfg = config or ThreadSamplingConfig()
        series = ThreadSeries(pid=pid, config=cfg)
        t_start = time.monotonic()
        try:
            remote = bool(self.adapter.is_remote())
        except Exception:  # noqa: BLE001
            remote = True
        supported = bool(getattr(type(self.adapter), "thread_samples_supported", False))
        if remote and not supported:
            series.stop_reason = ("remote target: this adapter does not provide per-thread CPU time / context "
                                  "switches / syscalls (read_thread_samples)")
            return series
        interval = cfg.interval_sec
        n_max = cfg.samples
        if self.budget_tracker is not None:
            try:
                interval = max(interval, float(self.budget_tracker.limits.min_poll_interval_ms) / 1000.0)
                n_max = min(n_max, int(self.budget_tracker.limits.max_samples))
            except Exception:  # noqa: BLE001
                pass
        for i in range(1, n_max + 1):
            if i > 1:
                why = self._budget_ok(t_start, cfg)
                if why:
                    series.stop_reason = why
                    break
                time.sleep(interval)
            t_now = time.monotonic()
            recs: Optional[List[Dict[str, Any]]]
            if supported:
                recs = self.adapter.read_thread_samples(pid, series.counters)
            else:
                recs = read_local_thread_samples(pid, series.counters)
            if recs is None:
                series.failures.append({"index": i, "stage": "enumerate", "error": "thread enumeration failed"})
                if not self._target_alive(pid, remote):
                    series.stop_reason = "target process exited"
                    break
                continue
            threads: Dict[int, Dict[str, Any]] = {int(r["tid"]): r for r in recs}
            info = None
            if inspect_fn is not None:
                try:
                    info = inspect_fn()
                    if not isinstance(info, dict):
                        raise TypeError(f"unexpected result type {type(info).__name__}")
                    if info.get("error") or info.get("success") is False or (
                        info.get("status") == "INCONCLUSIVE" and not info.get("deadlock_detected")
                    ):
                        raise RuntimeError(str(info.get("error") or "; ".join(str(x) for x in (info.get("limitations") or [])[:3])
                                               or "inspection INCONCLUSIVE"))
                    info = augment_lock_info(
                        info, pid=pid, adapter=self.adapter, companion_elf=companion_elf,
                        watch_manager=self.watch_manager, counters=series.counters,
                    )
                    if series.abi is None and info.get("target_abi"):
                        series.abi = TargetABI.from_dict(info["target_abi"])
                    series.lock_series.add_sample(i, info)
                    by_tid = {int(t["tid"]): t for t in info.get("threads", []) if t.get("tid") is not None}
                    for tid, rec in threads.items():
                        tr = by_tid.get(tid)
                        if tr:
                            rec["top_frame"] = _top_frame(tr)
                            rec["waiting_on_lock"] = tr.get("waiting_on_lock")
                except Exception as exc:  # noqa: BLE001
                    reason = f"{type(exc).__name__}: {exc}"
                    series.lock_series.add_failure(i, reason)
                    series.failures.append({"index": i, "stage": "lock_inspection", "error": reason})
            if self.budget_tracker is not None:
                try:
                    self.budget_tracker.record_sample()
                except Exception:  # noqa: BLE001
                    pass
            series.samples.append({"index": i, "t": t_now, "threads": threads})
        if series.abi is None:
            try:
                series.abi = detect_target_abi(self.adapter, pid)
            except Exception:  # noqa: BLE001
                series.abi = None
        series.wall_sec = time.monotonic() - t_start
        return series


# --------------------------------------------------------------------------------------
# Derivation
# --------------------------------------------------------------------------------------
def _trend(counts: List[int]) -> str:
    if len(counts) < 2:
        return "unknown"
    if all(c == counts[0] for c in counts):
        return "stable"
    if all(b >= a for a, b in zip(counts, counts[1:])):
        return "growing"
    if all(b <= a for a, b in zip(counts, counts[1:])):
        return "shrinking"
    return "fluctuating"


def _run_start(values: List[Any], times: List[float]) -> float:
    """Seconds the final value has been held (from first sample of the trailing constant run)."""
    j = len(values) - 1
    while j > 0 and values[j - 1] == values[j]:
        j -= 1
    return times[-1] - times[j]


def derive(series: ThreadSeries) -> Dict[str, Any]:
    samples = series.samples
    cfg = series.config
    abi = series.abi
    out: Dict[str, Any] = {"threads": {}, "sample_count": len(samples)}
    counts = [len(s["threads"]) for s in samples]
    out["thread_count_series"] = counts
    out["thread_count_trend"] = _trend(counts)
    all_tids: Set[int] = set()
    for s in samples:
        all_tids.update(s["threads"])
    for tid in sorted(all_tids):
        pts = [(s["index"], s["t"], s["threads"][tid]) for s in samples if tid in s["threads"]]
        first_idx, last_idx = pts[0][0], pts[-1][0]
        contiguous = len(pts) == (last_idx - first_idx + 1)
        t0, t1 = pts[0][1], pts[-1][1]
        window = max(1e-9, t1 - t0)
        recs = [p[2] for p in pts]
        times = [p[1] for p in pts]
        d: Dict[str, Any] = {
            "tid": tid,
            "name": recs[-1]["name"],
            "samples_present": len(pts),
            "present_in_all_samples": len(pts) == len(samples),
            "appeared_at_sample": first_idx if first_idx > samples[0]["index"] else None,
            "disappeared_after_sample": last_idx if last_idx < samples[-1]["index"] else None,
            "contiguous": contiguous,
            "window_sec": round(window, 4),
            "states": [r["state"] for r in recs],
        }
        ticks = [r["utime_ticks"] + r["stime_ticks"] for r in recs]
        d["cpu_ticks_delta"] = ticks[-1] - ticks[0]
        d["cpu_share"] = round((ticks[-1] - ticks[0]) / CLK_TCK / window, 3) if len(pts) >= 2 else None
        vols = [r.get("voluntary_ctxt_switches") for r in recs]
        invs = [r.get("nonvoluntary_ctxt_switches") for r in recs]
        d["voluntary_switches_delta"] = (vols[-1] - vols[0]) if None not in (vols[0], vols[-1]) else None
        d["involuntary_switches_delta"] = (invs[-1] - invs[0]) if None not in (invs[0], invs[-1]) else None
        ios = [r.get("io_syscalls") for r in recs]
        d["io_syscalls_delta"] = (ios[-1] - ios[0]) if None not in (ios[0], ios[-1]) else None
        # syscalls (number + name for the TARGET ABI)
        scs = [r.get("syscall") for r in recs]
        sc_keys: List[Any] = []
        for sc in scs:
            if sc and not sc.get("running"):
                sc_keys.append((sc["nr"], tuple(sc["args"][:2])))
            else:
                sc_keys.append(None)
        d["syscall_samples"] = [
            (None if k is None else {"nr": k[0], "name": abi_syscall_name(abi, k[0])}) for k in sc_keys
        ]
        last_sc = next((sc for sc in reversed(scs) if sc and not sc.get("running")), None)
        d["syscall_nr"] = last_sc["nr"] if last_sc else None
        d["syscall"] = abi_syscall_name(abi, last_sc["nr"]) if last_sc else None
        d["same_syscall_sec"] = round(_run_start(sc_keys, times), 4) if sc_keys[-1] is not None else 0.0
        frames = [(r.get("top_frame") or {}).get("function") for r in recs]
        d["top_frames"] = frames
        known = [f for f in frames if f]
        d["top_function"] = known[-1] if known else None
        d["top_source_location"] = next(((r.get("top_frame") or {}).get("source_location") for r in reversed(recs)
                                         if (r.get("top_frame") or {}).get("function")), None)
        d["same_frame_sec"] = round(_run_start(frames, times), 4) if frames[-1] else 0.0
        d["distinct_top_functions"] = len(set(known))
        # share of samples in the most common top function (the stack-scan unwinder can be noisy in a single sample)
        d["top_function_dominance"] = (max(known.count(f) for f in set(known)) / len(frames)) if known else None
        if known:
            d["top_function"] = max(set(known), key=known.count)
        # time since last progress = no CPU time and no context switch since the previous sample
        last_prog = times[0]
        progressed = False
        for k in range(1, len(recs)):
            a, b = recs[k - 1], recs[k]
            if (b["utime_ticks"] + b["stime_ticks"] != a["utime_ticks"] + a["stime_ticks"]
                    or b.get("voluntary_ctxt_switches") != a.get("voluntary_ctxt_switches")
                    or b.get("nonvoluntary_ctxt_switches") != a.get("nonvoluntary_ctxt_switches")):
                last_prog = times[k]
                progressed = True
        d["idle_sec"] = round(times[-1] - last_prog, 4)
        d["idle_is_lower_bound"] = not progressed
        wl = [r.get("waiting_on_lock") for r in recs]
        d["waiting_on_lock"] = wl[-1]["lock_name"] if wl[-1] else None
        d["waiting_on_lock_all_samples"] = bool(all(wl)) and len(wl) >= 2
        d["lock_owner_tid"] = wl[-1].get("held_by_tid") if wl[-1] else None
        d["lock_owner_name"] = wl[-1].get("held_by_thread_name") if wl[-1] else None
        d["_sc_keys"] = sc_keys
        out["threads"][tid] = d
    return out


def _fmt_pct(x: Optional[float]) -> str:
    return "n/a" if x is None else f"{x * 100:.0f}%"


def judge(series: ThreadSeries) -> Dict[str, Any]:
    """Map the derived series onto the existing recipe input keys (+ explanatory keys)."""
    cfg = series.config
    dv = derive(series)
    good = len(series.samples)
    result: Dict[str, Any] = {
        "thread_sampling": {
            "samples_collected": good,
            "samples_requested": cfg.samples,
            "interval_sec": cfg.interval_sec,
            "window_sec": round(series.samples[-1]["t"] - series.samples[0]["t"], 4) if good >= 2 else 0.0,
            "wall_sec": round(series.wall_sec, 4),
            "proc_reads": series.counters.get("proc_reads", 0),
            "failed_samples": list(series.failures),
            "stop_reason": series.stop_reason,
            "lock_observations": series.lock_series.observation_count,
        },
        "thread_count_series": dv["thread_count_series"],
        "thread_count_trend": dv["thread_count_trend"],
    }
    if good < max(2, cfg.min_samples_for_verdict):
        result["thread_sampling"]["status"] = "INSUFFICIENT_SAMPLES"
        return result
    result["thread_sampling"]["status"] = "OK"
    threads = dv["threads"]
    window = result["thread_sampling"]["window_sec"]
    runaway: List[Dict[str, Any]] = []
    long_waits: List[Dict[str, Any]] = []
    zombies: List[Dict[str, Any]] = []
    d_state: List[Dict[str, Any]] = []
    stalled_lock_waits: List[Dict[str, Any]] = []
    contended_lock_waits: List[Dict[str, Any]] = []
    findings: List[str] = []
    long_wait_findings: List[str] = []
    summary: List[Dict[str, Any]] = []

    for tid, d in threads.items():
        public = {k: v for k, v in d.items() if not k.startswith("_")}
        summary.append(public)
        if not d["contiguous"] or d["samples_present"] < cfg.min_samples_for_verdict:
            continue  # appeared/disappeared mid-window: not enough continuous observation to judge
        states = d["states"]
        label = f"'{d['name']}' (tid {tid})"
        if all(s == "Z" for s in states):
            zombies.append(public)
            findings.append(f"Thread {label} stayed a zombie for the whole window.")
        if all(s == "D" for s in states):
            d_state.append(public)
            findings.append(f"Thread {label} stayed in uninterruptible sleep (D) for {window:.2f}s.")
        # --- CPU monopoly without observable progress -----------------------------------
        share = d["cpu_share"] or 0.0
        if (share >= cfg.runaway_cpu_share and all(s == "R" for s in states)
                and (d["voluntary_switches_delta"] or 0) <= cfg.runaway_max_voluntary_switches_per_sec * max(window, 1e-6)
                and d["io_syscalls_delta"] in (0, None)
                and (d["top_function_dominance"] is None or d["top_function_dominance"] >= 0.8)):
            fn = d["top_function"] or "unresolved"
            r = dict(public, verdict="CPU monopoly without observable progress", function=fn,
                     cpu_share_pct=round(share * 100, 1))
            runaway.append(r)
            findings.append(
                f"Thread {label} used {_fmt_pct(share)} CPU over {window:.2f}s with no voluntary context switch, "
                f"no read/write syscall, and the same top frame `{fn}` in most samples ({_fmt_pct(d['top_function_dominance'])}): "
                f"CPU monopoly without observable progress."
            )
        # --- long wait in one syscall for the whole window -------------------------------
        keys = d["_sc_keys"]
        if (d["present_in_all_samples"] and keys[0] is not None and all(k == keys[0] for k in keys)
                and all(s in ("S", "D") for s in states)
                and d["cpu_ticks_delta"] == 0
                and d["voluntary_switches_delta"] == 0 and d["involuntary_switches_delta"] == 0):
            lw = dict(public, verdict=LONG_WAIT_VERDICT, waited_at_least_sec=round(window, 3),
                      expectation="UNKNOWN", wait_kind=_wait_kind(series, tid, d))
            long_waits.append(lw)
            if d["waiting_on_lock"]:
                owner = threads.get(d["lock_owner_tid"]) if d["lock_owner_tid"] else None
                owner_alive = owner is not None
                owner_moving = bool(owner and (owner["cpu_ticks_delta"] or owner["voluntary_switches_delta"]
                                               or owner["involuntary_switches_delta"]))
                item = dict(public, lock=d["waiting_on_lock"], owner_tid=d["lock_owner_tid"],
                            owner_name=d["lock_owner_name"], owner_alive=owner_alive, owner_progressing=owner_moving)
                if owner_moving:
                    contended_lock_waits.append(item)
                else:
                    stalled_lock_waits.append(item)
            long_wait_findings.append(
                f"Thread {label} stayed in {d['syscall'] or 'syscall ' + str(d['syscall_nr'])}"
                f"{' (' + lw['wait_kind'] + ')' if lw['wait_kind'] else ''} for the whole {window:.2f}s window "
                f"with no CPU time and no context switch: {LONG_WAIT_VERDICT}."
            )
    anomalous = bool(runaway or zombies or d_state)
    result["thread_summary"] = summary
    result["thread_findings"] = findings
    result["long_wait_findings"] = long_wait_findings
    result["long_wait_threads"] = long_waits
    result["contended_lock_waits"] = contended_lock_waits
    result["stalled_lock_waits"] = stalled_lock_waits
    result["runaway_threads"] = runaway
    result["zombie_threads"] = zombies
    result["d_state_threads"] = d_state
    result["thread_state_anomaly"] = anomalous
    lock_cycle_seen = any(smp["cycles"] for smp in series.lock_series.samples)
    # "healthy" = no state anomaly AND no blocked-without-owner-progress lock wait AND no wait cycle.  Idle waits of
    # unknown expectation do not make a process unhealthy (nor do they prove health: see long_wait_threads).
    if not anomalous and not stalled_lock_waits and not lock_cycle_seen:
        result["threads_healthy"] = True
    if stalled_lock_waits:
        result["blocked_duration_sec"] = round(window, 3)
        result["persistent_block"] = True
    else:
        result["blocked_duration_sec"] = 0.0
    return result


def _wait_kind(series: ThreadSeries, tid: int, d: Dict[str, Any]) -> str:
    name = d.get("syscall") or ""
    last = series.samples[-1]["threads"].get(tid, {}).get("syscall") or {}
    args = last.get("args") or []
    if name == "futex" and len(args) > 1:
        cmd = args[1] & 0x7F
        if d.get("waiting_on_lock"):
            return f"mutex {d['waiting_on_lock']}"
        if cmd == FUTEX_CMD_WAIT_BITSET:
            return "futex bitset wait (condition variable or similar)"
        return f"futex cmd {cmd}"
    return name

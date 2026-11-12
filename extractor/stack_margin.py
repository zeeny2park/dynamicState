"""IMP-009 (3): per-thread stack depth and margin to the guard region, from /proc only (zero-stop).

* Stack pointer: only for threads blocked in a system call, from ``/proc/PID/task/TID/syscall`` (already parsed
  by the adapter's thread listing).  A running thread exposes no stack pointer without stopping it: its margin is
  reported as unknown, never guessed.
* Guard: for a pthread stack, the PROT_NONE mapping right below the stack mapping; the margin is
  ``sp - start of the stack mapping``.  For the main thread (``[stack]``, grows on demand) the limit is
  ``stack top - RLIMIT_STACK`` (soft limit from ``/proc/PID/limits``); unlimited -> margin unknown.  A stack
  without a guard mapping below it (coroutine / custom stacks) -> margin unknown.
* Verdict per thread: ``EXHAUSTION_WARNING`` when the margin is below ``min_margin_bytes`` AND below
  ``min_margin_fraction`` of the stack size (a small idle thread with a small stack is not flagged);
  ``SP_IN_GUARD`` (corruption-grade) only when the stack pointer is at or inside the guard region.
"""

from typing import Any, Dict, List, Optional, Tuple

DEFAULT_MIN_MARGIN_BYTES = 16 * 1024
DEFAULT_MIN_MARGIN_FRACTION = 0.10


def _bounds(m: Dict[str, Any]) -> Tuple[int, int]:
    s = m.get("start_int")
    e = m.get("end_int")
    if s is None:
        s = int(str(m.get("start", "0")), 16)
    if e is None:
        e = int(str(m.get("end", "0")), 16)
    return int(s), int(e)


def _rlimit_stack(adapter: Any, pid: int) -> Optional[int]:
    try:
        raw = adapter.read_target_file(pid, "/proc/%d/limits" % pid, 8192)
    except Exception:  # noqa: BLE001
        return None
    if not raw:
        return None
    for line in raw.decode("utf-8", "replace").splitlines():
        if line.startswith("Max stack size"):
            parts = line[len("Max stack size"):].split()
            if not parts:
                return None
            if parts[0] == "unlimited":
                return -1
            try:
                return int(parts[0])
            except ValueError:
                return None
    return None


def check_stack_margins(adapter: Any, pid: int, threads: Optional[List[Dict[str, Any]]] = None,
                        maps: Optional[List[Dict[str, Any]]] = None,
                        min_margin_bytes: int = DEFAULT_MIN_MARGIN_BYTES,
                        min_margin_fraction: float = DEFAULT_MIN_MARGIN_FRACTION) -> Dict[str, Any]:
    pid = int(pid)
    if threads is None:
        threads = adapter.get_threads(pid) or []
    if maps is None:
        maps = adapter.get_proc_maps(pid) or []
    ordered = sorted(maps, key=lambda m: _bounds(m)[0])
    by_start = {_bounds(m)[0]: i for i, m in enumerate(ordered)}
    rlim = None
    rows: List[Dict[str, Any]] = []
    warnings: List[Dict[str, Any]] = []
    unknown = 0
    for t in threads:
        si = t.get("stack_info") or {}
        name = str(t.get("name") or "")
        task = int(t.get("tid") or 0)
        row: Dict[str, Any] = {"task_id": task, "thread": name}
        s, e = int(si.get("start_int") or 0), int(si.get("end_int") or 0)
        sp = si.get("sp_int")
        if not (e > s > 0):
            row["margin"] = "unknown: stack mapping not identified"
            unknown += 1
            rows.append(row)
            continue
        if not sp:
            row["margin"] = "unknown: thread running (no stack pointer without stopping it)"
            unknown += 1
            rows.append(row)
            continue
        sp = int(sp)
        if str(si.get("permissions") or "").startswith("---"):
            # the mapping holding the stack pointer is PROT_NONE: the thread ran into its guard region
            row.update(margin_bytes=0, in_guard=True)
            rows.append(row)
            warnings.append({"kind": "SP_IN_GUARD", "thread_name": name, "tid": task, "margin_bytes": 0,
                             "description": "thread %s (tid %d): stack pointer 0x%x is inside the PROT_NONE guard "
                                            "region 0x%x-0x%x: stack overflow" % (name, task, sp, s, e)})
            continue
        i = by_start.get(s)
        below = ordered[i - 1] if i is not None and i > 0 else None
        guard: Optional[Tuple[int, int]] = None
        if below is not None and _bounds(below)[1] == s and (below.get("permissions") or "").startswith("---"):
            guard = _bounds(below)
            limit = s
            size = e - s
        elif task == pid or (ordered[i].get("pathname") if i is not None else "") == "[stack]":
            if rlim is None:
                rlim = _rlimit_stack(adapter, pid)
            if rlim is None or rlim < 0:
                row["margin"] = "unknown: main stack size limit %s" % ("unlimited" if rlim == -1 else "not readable")
                unknown += 1
                rows.append(row)
                continue
            limit = e - rlim
            size = rlim
        else:
            row["margin"] = "unknown: no guard mapping below this stack"
            unknown += 1
            rows.append(row)
            continue
        margin = sp - limit
        row.update(stack_size=size, used_bytes=e - sp, margin_bytes=margin)
        rows.append(row)
        if margin <= 0:
            warnings.append({"kind": "SP_IN_GUARD", "thread_name": name, "tid": task, "stack_size": size,
                             "margin_bytes": margin,
                             "description": "thread %s (tid %d): stack pointer 0x%x is at the guard limit 0x%x: "
                                            "stack overflow" % (name, task, sp, limit)})
        elif margin < min_margin_bytes and margin < size * min_margin_fraction:
            warnings.append({"kind": "EXHAUSTION_WARNING", "thread_name": name, "tid": task, "stack_size": size,
                             "used_bytes": e - sp, "margin_bytes": margin,
                             "description": "thread %s (tid %d): stack nearly exhausted, %d bytes left to the guard "
                                            "region (%d of %d bytes used)" % (name, task, margin, e - sp, size)})
    return {"threads_checked": len(threads), "threads_margin_unknown": unknown, "threshold_bytes": min_margin_bytes,
            "threshold_fraction": min_margin_fraction, "threads": rows, "warnings": warnings}

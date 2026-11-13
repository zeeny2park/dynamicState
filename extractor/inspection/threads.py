"""Thread and lock inspection: CFI-unwound call stacks (IMP-011), exact source lines, mutex owners / deadlock
cycles, and per-frame locals.

Moved verbatim from extractor/watch_session.py.  Each function takes the ``WatchSessionManager`` first (``mgr``);
the manager binds them as methods, so ``manager.inspect_thread_callstacks_and_locks(...)`` is unchanged.
"""

import os
import re
import struct
import time
from typing import Any, Dict, List, Optional, Set, Tuple

from ..cfi_unwinder import (
    UNWIND_SCAN as CFI_UNWIND_SCAN,
    decode_call_before,
    make_unwinder_for_process,
    parse_proc_syscall,
)
from ..dwarf_indexer import DwarfIndex, DwarfIndexer
from ..target_abi import (
    FEATURE_CFI_UNWIND,
    FEATURE_FRAME_LAYOUT,
    FEATURE_MUTEX_OWNER,
    FEATURE_SYSCALL_NAMES,
    SUPPORT_NOT_SUPPORTED_ON_TARGET,
    SUPPORT_SUPPORTED,
    TargetABI,
    abi_support_summary,
    check_support,
    detect_target_abi,
    syscall_name as abi_syscall_name,
)
from ..target_adapter import TargetExecutionAdapter


# ------------------------------------------------------------------------------------------
# IMP-011: CFI unwinding helpers shared by the call-stack and frame-locals inspectors
# ------------------------------------------------------------------------------------------
def _imp011_prepare_unwinder(
    target_adapter: TargetExecutionAdapter, pid: int, target_abi: TargetABI,
    map_data: Dict[str, Any], endian: str,
) -> Tuple[Optional[Any], Any, Optional[str]]:
    """(unwinder or None, FEATURE_CFI_UNWIND decision, reason when no unwinder)."""
    support = check_support(target_abi, FEATURE_CFI_UNWIND)
    if not support.supported:
        return None, support, support.message
    provider = None
    if target_adapter.is_remote():
        # IMP-011 part 3: SP/PC come from the adapter's per-thread "syscall" field; module images are the
        # companion image (main executable) plus library images fetched from the target (size-capped, cached).
        if not getattr(target_adapter, "thread_samples_supported", False):
            return None, support, "remote adapter provides no per-thread SP/PC, CFI unwinding not attempted"
        from ..remote_module_images import RemoteImageResolver, find_main_remote_path
        main_mod = next((m for m in map_data.get("loaded_debug_modules", []) if m.get("is_main_executable")), None)
        provider = RemoteImageResolver(
            target_adapter, pid,
            find_main_remote_path(map_data.get("mappings") or [], (main_mod or {}).get("module")),
            (main_mod or {}).get("debug_image"),
        )

    def _read(addr: int, size: int) -> Tuple[Optional[bytes], str, Optional[str]]:
        return target_adapter.read_memory(pid, addr, size)

    try:
        uw = make_unwinder_for_process(
            target_abi.architecture, map_data.get("mappings") or [], _read, endian=endian, pid=pid,
            image_provider=provider,
        )
        if uw is not None and provider is not None:
            uw.remote_image_provider = provider
    except Exception as exc:  # noqa: BLE001
        return None, support, f"CFI unwinder unavailable: {type(exc).__name__}: {exc}"
    return uw, support, None if uw is not None else "CFI unwinder unavailable for this architecture"


def _imp011_read_syscall(pid: int, tid: int) -> Dict[str, Any]:
    try:
        with open(f"/proc/{pid}/task/{tid}/syscall", "r", encoding="utf-8") as sf:
            return parse_proc_syscall(sf.read())
    except Exception:  # noqa: BLE001
        return {"state": "unavailable"}


def _imp011_unwind_thread(
    unwinder: Optional[Any], sc_info: Dict[str, Any], window: Optional[Tuple[int, int]], max_frames: int,
) -> Optional[Dict[str, Any]]:
    """Blocked thread: CFI from the kernel-reported SP/PC.  Running thread: labelled two-read sample."""
    if unwinder is None:
        return None
    try:
        if sc_info.get("sp") and sc_info.get("pc"):
            return unwinder.unwind_blocked(int(sc_info["sp"]), int(sc_info["pc"]), max_frames=max_frames)
        if sc_info.get("state") == "running" and window and window[1] > window[0]:
            return unwinder.sample_running(int(window[0]), int(window[1]), max_frames=max_frames)
    except Exception:  # noqa: BLE001 - unwinding must never break the inspection
        return None
    return None


def _imp011_thread_summary(res: Optional[Dict[str, Any]], sc_info: Dict[str, Any], reason: Optional[str]) -> Dict[str, Any]:
    """Thread-level fields describing how the call stack was obtained (added, never renamed)."""
    if res is None:
        state = sc_info.get("state")
        return {
            "unwind_status": "SCAN_ESTIMATED",
            "unwind_stop_reason": reason or (
                "thread running on a CPU and no stack sample could be anchored" if state == "running"
                else "no kernel-reported SP/PC for this thread"
            ),
            "unwind_cost": None,
            "unwind_notes": [],
        }
    return {
        "unwind_status": res["status"],
        "unwind_stop_reason": res["stop_reason"],
        "unwind_cost": res["cost"],
        "unwind_notes": list(res.get("notes") or [])[:8],
        "running_sample_stable": res.get("sample_stable"),
    }


def _apply_exact_source_line(resolved: Dict[str, Any], idx: "DwarfIndex", lookup_lt_pc: int) -> Dict[str, Any]:
    """Replace the definition-line `source_location` of a symbolized frame by the exact line of the
        blocked call / current instruction from the DWARF line table (`lookup_lt_pc` is pc-1 for caller
        frames).  The definition line stays in `function_decl_line` / `function_decl_location`.  New fields:
        `source_line_exact` (bool), `source_line_basis`, `inlined_chain` + `inlined_function` when the
        address lies in inlined code.  Without a covering line-table entry the definition line stays."""
    out = dict(resolved)
    out["function_decl_line"] = resolved.get("decl_line")
    out["function_decl_location"] = resolved.get("source_location")
    out["source_line_exact"] = False
    if resolved.get("resolution_source") != "DWARF_SUBPROGRAM":
        return out
    try:
        ln = idx.resolve_source_line(lookup_lt_pc)
    except Exception:
        ln = None
    if not ln:
        return out
    out["source_location"] = f"{ln['file']}:{ln['line']}"
    out["source_line"] = ln["line"]
    out["source_line_exact"] = True
    out["source_line_basis"] = "DWARF_LINE_TABLE"
    try:  # the statement text, only when the source file is present on this host
        with open(ln["path"], encoding="utf-8", errors="replace") as sf:
            for n, txt in enumerate(sf, 1):
                if n == ln["line"]:
                    out["source_line_text"] = txt.strip()[:200]
                    break
    except (OSError, KeyError):
        pass
    chain = ln.get("inlined_chain") or []
    if len(chain) > 1:
        out["inlined_chain"] = [{k: c[k] for k in ("function", "file", "line")} for c in chain]
        out["inlined_function"] = chain[0]["function"]
        out["inlined_into"] = chain[1]["function"]
    return out


def inspect_thread_callstacks_and_locks(
    mgr,
    pid: int,
    companion_elf_path: str,
    tid: Optional[int] = None,
    lock_expressions: Optional[List[str]] = None,
    max_frames: int = 12,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    adapter: Optional[TargetExecutionAdapter] = None,
) -> Dict[str, Any]:
    """Zero-stop replacement for `gdb thread apply all bt` + mutex deadlock analyzer.
        1. Decodes `pthread_mutex_t` (`__lock`, `__owner` TID) and custom lock structs to identify which thread holds each mutex.
        2. Reads `/proc/<pid>/task/<tid>/syscall` to detect threads blocked on `futex(uaddr, ...)` and matches `uaddr` to mutex addresses.
        3. IMP-011: unwinds each blocked thread with CFI (.eh_frame/.debug_frame of every mapped module) from the
           kernel-reported SP/PC; frames carry `unwind` ("registers" | "cfi" | "frame_pointer" | "scan_estimated" |
           "cfi_after_scan" | "running_sample_estimated") and `estimated`.  Running threads get a labelled two-read
           stack sample.  The legacy return-address scan is used only where neither is possible (remote targets,
           unsupported architectures) and its frames are marked estimated.  Frames are symbolized via DWARF
           subprograms, ELF symbols (incl. /usr/lib/debug/.build-id) or `module+offset`.
        4. Detects circular wait deadlock cycles across threads and mutexes.
        """
    target_adapter = mgr._resolve_adapter(
        pid=pid,
        remote_host=remote_host,
        ssh_user=ssh_user,
        ssh_port=ssh_port,
        ssh_key=ssh_key,
        ssh_proxy_jump=ssh_proxy_jump,
        adapter=adapter,
    )
    t_start_ns = time.monotonic_ns()
    primary_elf, _ = mgr._split_companion_elf_paths(companion_elf_path)
    if not primary_elf:
        raise ValueError("Valid companion ELF path is required")

    map_data = mgr._get_process_maps_and_load_bias(
        pid=pid,
        companion_elf_path=companion_elf_path,
        adapter=target_adapter,
    )
    load_bias = map_data.get("base_address_int", 0)
    primary_idx = DwarfIndexer.get_index(primary_elf)
    # IMP-015: target ABI from the target itself (never the host); gates every layout assumption below.
    target_abi = detect_target_abi(target_adapter, pid)
    owner_support = check_support(target_abi, FEATURE_MUTEX_OWNER)
    syscall_support = check_support(target_abi, FEATURE_SYSCALL_NAMES)
    frame_support = check_support(target_abi, FEATURE_FRAME_LAYOUT)
    ptr_size = primary_idx.pointer_size or ((target_abi.word_size or 64) // 8)
    endian = primary_idx.endianness or target_abi.endianness or "little"
    ptr_fmt = ("<" if endian == "little" else ">") + ("Q" if ptr_size == 8 else "I")

    # Build module code ranges for return-address stack unwinding
    module_contexts: List[Tuple[str, DwarfIndex, int, bool]] = [
        (os.path.basename(primary_elf), primary_idx, load_bias, (primary_idx.elf_type == "ET_DYN"))
    ]
    for mod_info in map_data.get("loaded_debug_modules", []):
        if not mod_info.get("is_main_executable") and mod_info.get("debug_image"):
            try:
                so_idx = DwarfIndexer.get_index(mod_info["debug_image"])
                module_contexts.append((
                    mod_info.get("module") or os.path.basename(mod_info["debug_image"]),
                    so_idx,
                    int(mod_info.get("load_bias_int", 0)),
                    (so_idx.elf_type == "ET_DYN"),
                ))
            except Exception:
                pass

    exec_vmas: List[Tuple[int, int, str]] = []
    for m in map_data.get("mappings", []):
        perms = m.get("permissions", "")
        ms = int(m["start_int"]) if m.get("start_int") is not None else int(m.get("start", "0"), 16)
        me = int(m["end_int"]) if m.get("end_int") is not None else int(m.get("end", "0"), 16)
        if "x" in perms and ms > 0 and me > ms:
            exec_vmas.append((ms, me, os.path.basename(m.get("pathname") or "")))

    def _symbolize_runtime_pc(rt_pc: int) -> Optional[Dict[str, Any]]:
        for mod_name, m_idx, m_bias, m_dyn in module_contexts:
            lt_pc = (rt_pc - m_bias) if m_dyn else rt_pc
            if lt_pc <= 0:
                continue
            resolved = m_idx.resolve_code_address(lt_pc)
            if resolved is not None:
                resolved = mgr._apply_exact_source_line(resolved, m_idx, lt_pc)
                return {
                    "runtime_pc": f"0x{rt_pc:x}",
                    "module": mod_name,
                    **resolved,
                }
        return None

    # IMP-011: CFI unwinder (x86_64 / aarch64, local targets); None -> labelled scan fallback below.
    unwinder, cfi_support, unwinder_reason = mgr._imp011_prepare_unwinder(
        target_adapter, pid, target_abi, map_data, endian
    )
    debug_module_paths: Set[str] = set()
    try:
        if target_adapter.is_remote():
            _rp = getattr(getattr(unwinder, "remote_image_provider", None), "main_remote_path", None)
            if _rp:
                debug_module_paths.update({_rp, os.path.realpath(_rp)})
        else:
            debug_module_paths.add(os.path.realpath(f"/proc/{pid}/exe"))
    except Exception:
        pass
    for mod_info in map_data.get("loaded_debug_modules", []):
        if mod_info.get("debug_image"):
            debug_module_paths.add(os.path.realpath(mod_info["debug_image"]))

    def _cfi_callstack_frames(res: Dict[str, Any]) -> List[Dict[str, Any]]:
        out_frames: List[Dict[str, Any]] = []
        for fr in res.get("frames", []):
            lookup = int(fr["lookup_pc"])
            desc = unwinder.describe_pc(int(fr["pc"]), lookup)
            sym = None
            mpath = desc.get("module_path")
            if mpath and (mpath in debug_module_paths or os.path.realpath(mpath) in debug_module_paths):
                sym = _symbolize_runtime_pc(lookup)
            if sym is None:
                lt = desc.get("link_pc")
                if desc.get("elf_symbol"):
                    start = int(desc.get("elf_symbol_start") or lookup)
                    off = lookup - start
                    fname = desc["elf_symbol"]
                    sym = {"function_name": fname, "linkage_name": fname, "low_pc": f"0x{start:x}",
                           "low_pc_int": start, "offset_in_func": off,
                           "symbol_plus_offset": f"{fname}+0x{off:x}" if off else fname,
                           "decl_file": None, "decl_line": None, "source_location": None,
                           "resolution_source": "ELF_SYMBOL"}
                else:
                    fname = f"{desc.get('module') or '??'}+0x{(lt if lt is not None else lookup):x}"
                    sym = {"function_name": fname, "linkage_name": None, "offset_in_func": None,
                           "symbol_plus_offset": fname, "decl_file": None, "decl_line": None,
                           "source_location": None, "resolution_source": "UNRESOLVED"}
                sym["module"] = desc.get("module")
            slot = fr.get("stack_slot")
            sp_v = fr.get("sp")
            entry: Dict[str, Any] = {
                "frame_index": len(out_frames),
                "stack_address": f"0x{(sp_v if sp_v is not None else (slot or 0)):x}" if (sp_v or slot) else None,
                **sym,
                "runtime_pc": f"0x{int(fr['pc']):x}",
                "unwind": fr["unwind"],
                "estimated": bool(fr["estimated"]),
                "cfa": f"0x{int(fr['cfa']):x}" if fr.get("cfa") is not None else None,
                "module_path": mpath,
            }
            if fr.get("unwound_via"):
                entry["unwound_via"] = fr["unwound_via"]
            if fr.get("pc_is_function_entry"):
                entry["pc_is_function_entry"] = True
            if fr.get("pac_stripped"):
                entry["pac_stripped"] = True
            if fr.get("fp_inferred"):
                entry["fp_inferred"] = True
            out_frames.append(entry)
        return out_frames

    all_threads = target_adapter.get_threads(pid)
    threads_by_tid: Dict[int, Dict[str, Any]] = {int(t["tid"]): t for t in all_threads}
    target_threads = [t for t in all_threads if tid is None or int(t["tid"]) == int(tid)]

    # ---------------------------------------------------------------------
    # Part A: Discover & Decode Mutexes / Locks
    # ---------------------------------------------------------------------
    candidate_locks: List[Tuple[str, int, int, Optional[int], DwarfIndex]] = []
    seen_lock_names: Set[str] = set()

    for mod_name, m_idx, m_bias, m_dyn in module_contexts:
        for var in m_idx.variables:
            if var.link_time_address is None or var.is_declaration or not var.name:
                continue
            t_name = m_idx.get_type_name(var.type_offset)
            nl = var.name.lower()
            tl = t_name.lower()
            is_explicit = bool(lock_expressions and var.name in lock_expressions)
            # IMP-018: a lock is selected by its TYPE; the name is used only when the type name is unknown
            is_lock_like = any(k in tl for k in ("mutex", "lock", "rwlock", "spinlock", "sem_t")) or (
                not tl.strip() and any(k in nl for k in ("mutex", "lock", "rwlock", "spinlock")))
            if (is_explicit or is_lock_like) and var.name not in seen_lock_names:
                seen_lock_names.add(var.name)
                rt_addr = (m_bias + var.link_time_address) if m_dyn else var.link_time_address
                canon_t = m_idx.resolve_canonical_type(var.type_offset)
                bsize = canon_t.byte_size if (canon_t and canon_t.byte_size) else 40
                candidate_locks.append((var.name, rt_addr, max(16, min(bsize, 128)), var.type_offset, m_idx))

    locks_report: List[Dict[str, Any]] = []
    locks_by_addr: Dict[int, Dict[str, Any]] = {}
    lock_read_errors: List[str] = []
    stack_read_errors: List[str] = []
    limitations: List[str] = []
    if not map_data.get("mappings"):
        limitations.append(f"Process memory mappings (/proc/{pid}/maps) could not be read.")
    if not all_threads:
        limitations.append(f"Process thread list (/proc/{pid}/task) could not be read.")

    for l_name, l_addr, l_size, l_toff, l_idx in candidate_locks:
        if not owner_support.supported:
            # IMP-015: the glibc pthread_mutex_t owner layout is not valid (or not verifiable) for this
            # target -> report the lock without any owner / locked-state interpretation.
            l_info = {
                "name": l_name,
                "runtime_address": f"0x{l_addr:x}",
                "runtime_address_int": l_addr,
                "type_name": l_idx.get_type_name(l_toff),
                "is_locked": None,
                "lock_state_word": None,
                "recursion_count": None,
                "owner_tid": None,
                "owner_thread_name": None,
                "owner_status": owner_support.status,
                "owner_status_reason": owner_support.message,
                "waiting_tids": [],
                "inferred_waiting_tids": [],
            }
            locks_report.append(l_info)
            locks_by_addr[l_addr] = l_info
            continue
        try:
            raw_lock, lst, l_err = target_adapter.read_memory(pid, l_addr, l_size)
        except Exception as l_exc:
            raw_lock, lst, l_err = None, "READ_ERROR", f"{type(l_exc).__name__}: {l_exc}"
        if lst != "OBSERVED" or not raw_lock or len(raw_lock) < 12:
            lock_read_errors.append(f"Failed to read mutex '{l_name}' at 0x{l_addr:x}: {l_err or lst}")
            continue
        i_fmt = "<iii" if endian == "little" else ">iii"
        lock_word, count_word, owner_tid = struct.unpack(i_fmt, raw_lock[:12])

        # Also check custom struct members if DWARF has explicit owner_tid / locked fields
        canon_l = l_idx.resolve_canonical_type(l_toff)
        if canon_l and canon_l.tag in ("DW_TAG_structure_type", "DW_TAG_class_type"):
            for m in canon_l.members:
                if not m.name:
                    continue
                mnl = m.name.lower()
                if ("owner" in mnl or "tid" in mnl) and m.offset + 4 <= len(raw_lock):
                    custom_tid = struct.unpack("<i" if endian == "little" else ">i", raw_lock[m.offset:m.offset + 4])[0]
                    if custom_tid > 0:
                        owner_tid = custom_tid
                elif ("lock" in mnl or "held" in mnl) and m.offset + 4 <= len(raw_lock):
                    custom_lk = struct.unpack("<i" if endian == "little" else ">i", raw_lock[m.offset:m.offset + 4])[0]
                    if custom_lk != 0:
                        lock_word = custom_lk

        is_locked = (lock_word != 0) or (owner_tid > 0)
        owner_thread_name = threads_by_tid[owner_tid]["name"] if owner_tid in threads_by_tid else ("DEAD_OR_EXTERNAL_THREAD" if owner_tid > 0 else None)
        l_info = {
            "name": l_name,
            "runtime_address": f"0x{l_addr:x}",
            "runtime_address_int": l_addr,
            "type_name": l_idx.get_type_name(l_toff),
            "is_locked": is_locked,
            "lock_state_word": lock_word,
            "recursion_count": count_word,
            "owner_tid": owner_tid if owner_tid > 0 else None,
            "owner_thread_name": owner_thread_name,
            "owner_status": owner_support.status,
            "waiting_tids": [],
            "inferred_waiting_tids": [],
        }
        locks_report.append(l_info)
        locks_by_addr[l_addr] = l_info

    # ---------------------------------------------------------------------
    # Part B: Thread Syscall / Futex Wait & Zero-Stop Stack Unwinding
    # ---------------------------------------------------------------------
    thread_reports: List[Dict[str, Any]] = []
    wait_for_edges: List[Dict[str, Any]] = []  # waiter_tid -> owner_tid

    for t in target_threads:
        t_tid = int(t["tid"])
        t_name = t.get("name", f"thread_{t_tid}")
        t_state = t.get("state", "S")
        s_info = t.get("stack_info") or {}
        sp_int = int(s_info.get("sp_int") or 0)
        pc_int = int(s_info.get("pc_int") or 0)

        # Read /proc/<pid>/task/<tid>/syscall if local to get syscall number and arg0 (futex uaddr)
        syscall_nr: Optional[int] = None
        syscall_name: Optional[str] = None
        syscall_arg0: Optional[int] = None
        waiting_on_lock: Optional[Dict[str, Any]] = None

        sc_info: Dict[str, Any] = {"state": "unavailable"}
        if target_adapter.is_remote():
            sc_info = dict(t.get("syscall") or {"state": "unavailable"})   # adapter-provided (IMP-011 part 3)
        else:
            sc_info = mgr._imp011_read_syscall(pid, t_tid)
        # Is the precise source unusable?  Only then may the stack-scan fallback below run.
        syscall_record_unusable = (sc_info.get("state") not in ("blocked", "running", "not_in_syscall")
                                   or (sc_info.get("state") == "blocked" and not sc_info.get("args")))
        if sc_info.get("state") == "blocked":
            syscall_nr = int(sc_info["nr"])
            # IMP-015: number -> name via the table of the TARGET architecture; None when unsupported/undetected
            syscall_name = abi_syscall_name(target_abi, syscall_nr)
            if sc_info.get("args"):
                syscall_arg0 = int(sc_info["args"][0])
        if sc_info.get("sp") and sc_info.get("pc"):
            sp_int = int(sc_info["sp"])
            pc_int = int(sc_info["pc"])

        # Check if syscall_arg0 points into any known mutex (pthread_mutex_t is 40 bytes)
        if syscall_arg0 is not None and syscall_arg0 > 0:
            for l_addr, l_info in locks_by_addr.items():
                if l_addr <= syscall_arg0 < l_addr + 40:
                    waiting_on_lock = {
                        "lock_name": l_info["name"],
                        "lock_address": l_info["runtime_address"],
                        "held_by_tid": l_info["owner_tid"],
                        "held_by_thread_name": l_info["owner_thread_name"],
                    }
                    if t_tid not in l_info["waiting_tids"]:
                        l_info["waiting_tids"].append(t_tid)
                    if l_info["owner_tid"] and l_info["owner_tid"] != t_tid:
                        wait_for_edges.append({
                            "waiter_tid": t_tid,
                            "waiter_name": t_name,
                            "lock_name": l_info["name"],
                            "lock_address": l_info["runtime_address"],
                            "owner_tid": l_info["owner_tid"],
                            "owner_name": l_info["owner_thread_name"],
                        })
                    break

        # IMP-011: CFI unwinding from the kernel-reported SP/PC (blocked thread).  Running threads get a
        # labelled two-read sample below, once the stack region is known.  Only where neither is
        # possible does the legacy return-address scan run, and its frames are marked estimated.
        frames: List[Dict[str, Any]] = []
        seen_funcs: Set[str] = set()
        cfi_res = mgr._imp011_unwind_thread(unwinder, sc_info, None, max_frames)

        if pc_int > 0 and cfi_res is None:
            top_sym = _symbolize_runtime_pc(pc_int)
            if top_sym:
                frames.append({"frame_index": 0, "stack_address": f"0x{sp_int:x}" if sp_int else None, **top_sym,
                               "unwind": "registers", "estimated": False})
                seen_funcs.add(top_sym["function_name"])

        s_start = int(s_info.get("start_int") or 0)
        s_end = int(s_info.get("end_int") or 0)

        all_mappings = map_data.get("mappings", [])
        if sp_int > 0:
            for m in all_mappings:
                ms = int(m["start_int"]) if m.get("start_int") is not None else int(m.get("start", "0"), 16)
                me = int(m["end_int"]) if m.get("end_int") is not None else int(m.get("end", "0"), 16)
                if ms <= sp_int < me:
                    s_start, s_end = ms, me
                    break

        if (s_start <= 0 or (t_tid != pid and not (s_start <= sp_int < s_end))) and t_tid != pid:
            for m_i, m in enumerate(all_mappings):
                perms = m.get("permissions", "")
                if m.get("category") != "anonymous" or "r" not in perms or "w" not in perms:
                    continue
                ms = int(m["start_int"]) if m.get("start_int") is not None else int(m.get("start", "0"), 16)
                me = int(m["end_int"]) if m.get("end_int") is not None else int(m.get("end", "0"), 16)
                has_guard = (m_i > 0 and all_mappings[m_i - 1].get("permissions", "").startswith("---"))
                if not has_guard or not (65536 <= (me - ms) <= 16 * 1024 * 1024):
                    continue
                tcb_from = max(ms, me - 8192)
                raw_tcb, tst, _ = target_adapter.read_memory(pid, tcb_from, me - tcb_from)
                if tst == "OBSERVED" and raw_tcb:
                    tid_pair = struct.pack("<ii" if endian == "little" else ">ii", t_tid, pid)
                    tid_single = struct.pack("<i" if endian == "little" else ">i", t_tid)
                    if tid_pair in raw_tcb or tid_single in raw_tcb:
                        s_start, s_end = ms, me
                        break

        if s_start > 0 and s_end > s_start:
            tcb_int = int(s_info.get("tcb_address_int") or 0)
            stack_ceiling = (tcb_int - 64) if (s_start < tcb_int <= s_end) else s_end
            scan_from = sp_int if (sp_int > 0 and s_start <= sp_int < stack_ceiling) else max(s_start, stack_ceiling - 32768)
            scan_from = scan_from & ~(ptr_size - 1)
            scan_len = min(32768, max(0, stack_ceiling - scan_from))
            if cfi_res is None and sc_info.get("state") == "running":
                cfi_res = mgr._imp011_unwind_thread(
                    unwinder, sc_info, (scan_from, scan_from + scan_len), max_frames
                )
                if cfi_res is not None and not cfi_res.get("frames"):
                    cfi_res = None
            if cfi_res is not None:
                frames = _cfi_callstack_frames(cfi_res)
            # The raw stack read is still needed by the scan fallback and by the mutex-pointer fallback below.
            need_raw = cfi_res is None or (waiting_on_lock is None and syscall_record_unusable and bool(locks_by_addr)
                                           and t_state in ("S", "D"))
            if scan_len >= ptr_size and need_raw:
                try:
                    raw_stack, sst, s_err = target_adapter.read_memory(pid, scan_from, scan_len)
                except Exception as s_exc:
                    raw_stack, sst, s_err = None, "READ_ERROR", f"{type(s_exc).__name__}: {s_exc}"
                if (sst != "OBSERVED" or not raw_stack) and cfi_res is None:
                    stack_read_errors.append(f"Failed to read stack for TID {t_tid}: {s_err or sst}")
                if sst == "OBSERVED" and raw_stack:
                    num_words = len(raw_stack) // ptr_size
                    for w_i in range(num_words if cfi_res is None else 0):
                        if len(frames) >= max_frames:
                            break
                        cand_pc = struct.unpack_from(ptr_fmt, raw_stack, w_i * ptr_size)[0]
                        in_exec = any(es <= cand_pc < ee for es, ee, _ in exec_vmas)
                        if not in_exec:
                            continue
                        # Skip exact function entry pointers (offset_in_func == 0), which are function pointers (e.g. start_routine), not return addresses
                        exact_sym = _symbolize_runtime_pc(cand_pc)
                        if exact_sym and exact_sym.get("offset_in_func") == 0:
                            continue
                        sym = _symbolize_runtime_pc(cand_pc - 1)
                        if sym and sym["function_name"] not in ("_start", "__libc_start_main_impl", "clone", "clone3", "start_thread"):
                            slot_addr = scan_from + w_i * ptr_size
                            # If this is the innermost return address on a running user-space thread (pc_int == 0),
                            # decode the call instruction before it (x86_64 CALL rel32 / aarch64 BL, per target
                            # architecture - IMP-011) to recover a pure leaf poll-mode function.
                            call_len = {"x86_64": 5, "aarch64": 4}.get(target_abi.architecture or "")
                            if not frames and pc_int == 0 and (t_state == "R" or t.get("is_running_user_space")) and call_len:
                                call_bytes, cb_st, _ = target_adapter.read_memory(pid, cand_pc - call_len, call_len)
                                c_kind, callee_pc = (None, None)
                                if cb_st == "OBSERVED" and call_bytes and len(call_bytes) == call_len:
                                    c_kind, callee_pc = decode_call_before(target_abi.architecture or "", call_bytes, cand_pc, endian)
                                if c_kind == "direct" and callee_pc:
                                    callee_sym = _symbolize_runtime_pc(callee_pc)
                                    if callee_sym and callee_sym.get("resolution_source") == "DWARF_SUBPROGRAM":
                                        if callee_sym and callee_sym["function_name"] != sym["function_name"]:
                                            frames.append({
                                                "frame_index": 0,
                                                "stack_address": f"0x{slot_addr - ptr_size:x}",
                                                "unwound_via": "LEAF_CALL_TARGET_RECOVERY",
                                                **callee_sym,
                                                "unwind": CFI_UNWIND_SCAN,
                                                "estimated": True,
                                            })
                            if not frames or frames[-1]["function_name"] != sym["function_name"]:
                                frames.append({
                                    "frame_index": len(frames),
                                    "stack_address": f"0x{slot_addr:x}",
                                    **sym,
                                    "unwind": CFI_UNWIND_SCAN,
                                    "estimated": True,
                                })

                    # Fallback ONLY when the syscall record of this thread could not be read (unavailable, remote adapter
                    # without it, or a blocked record without arguments).  A readable record is authoritative: "blocked"
                    # names the futex address the thread waits on, "running" / "not in syscall" say it is not waiting in
                    # the kernel at all (the stack of such a thread still holds stale &mutex values from earlier calls;
                    # measured on lock_hotspot / lock_convoy: every stack-only "waiter" was a thread whose record said
                    # "running").  Waiters found here are inferred and marked so (``inferred`` / ``confidence``) and are
                    # kept out of ``waiting_tids`` (which the lock-contention and lock-fault judgements count).
                    # Scan active stack frames (from innermost SP upward) for pointers into locked pthread_mutex_t objects
                    if waiting_on_lock is None and syscall_record_unusable and locks_by_addr and t_state in ("S", "D"):
                        matched_lock_info = None
                        for w_i in range(num_words):
                            cand_val = struct.unpack_from(ptr_fmt, raw_stack, w_i * ptr_size)[0]
                            for l_addr, l_info in locks_by_addr.items():
                                if l_addr <= cand_val < l_addr + 40:
                                    if l_info.get("is_locked") and l_info.get("owner_tid") and l_info.get("owner_tid") != t_tid:
                                        matched_lock_info = l_info
                                        break
                            if matched_lock_info is not None:
                                break
                        if matched_lock_info is None:
                            for w_i in range(num_words):
                                cand_val = struct.unpack_from(ptr_fmt, raw_stack, w_i * ptr_size)[0]
                                for l_addr, l_info in locks_by_addr.items():
                                    if l_addr <= cand_val < l_addr + 40:
                                        if l_info.get("is_locked") and not l_info.get("owner_tid"):
                                            matched_lock_info = l_info
                                            break
                                if matched_lock_info is not None:
                                    break
                        if matched_lock_info is not None:
                            waiting_on_lock = {
                                "lock_name": matched_lock_info["name"],
                                "lock_address": matched_lock_info["runtime_address"],
                                "held_by_tid": matched_lock_info["owner_tid"],
                                "held_by_thread_name": matched_lock_info["owner_thread_name"],
                                "resolved_via": "STACK_MUTEX_POINTER_SCAN",
                                "inferred": True,
                                "confidence": "LOW",
                            }
                            if t_tid not in matched_lock_info["inferred_waiting_tids"]:
                                matched_lock_info["inferred_waiting_tids"].append(t_tid)
                            if matched_lock_info["owner_tid"] and matched_lock_info["owner_tid"] != t_tid:
                                wait_for_edges.append({
                                    "waiter_tid": t_tid,
                                    "waiter_name": t_name,
                                    "lock_name": matched_lock_info["name"],
                                    "lock_address": matched_lock_info["runtime_address"],
                                    "owner_tid": matched_lock_info["owner_tid"],
                                    "owner_name": matched_lock_info["owner_thread_name"],
                                    "inferred": True,
                                })

        thread_reports.append({
            "tid": t_tid,
            "name": t_name,
            "state": t_state,
            "syscall": syscall_name,
            "syscall_nr": syscall_nr,
            "syscall_status": syscall_support.status,
            "syscall_arg0": f"0x{syscall_arg0:x}" if syscall_arg0 is not None else None,
            "waiting_on_lock": waiting_on_lock,
            "frames_count": len(frames),
            "callstack": frames,
            # IMP-011 (added fields): how the stack was obtained and what it cost
            **mgr._imp011_thread_summary(cfi_res, sc_info, unwinder_reason),
            "top_user_frame_index": next((i for i, f in enumerate(frames)
                                         if f.get("resolution_source") == "DWARF_SUBPROGRAM"), None),
            "syscall_sp": f"0x{sc_info['sp']:x}" if sc_info.get("sp") else None,
            "syscall_pc": f"0x{sc_info['pc']:x}" if sc_info.get("pc") else None,
        })

    # ---------------------------------------------------------------------
    # Part C: Detect Deadlock Cycles in Wait-For Graph
    # ---------------------------------------------------------------------
    deadlock_cycles: List[List[Dict[str, Any]]] = []
    adj: Dict[int, List[Dict[str, Any]]] = {}
    for edge in wait_for_edges:
        adj.setdefault(edge["waiter_tid"], []).append(edge)

    visited_tids: Set[int] = set()
    for start_tid in list(adj.keys()):
        if start_tid in visited_tids:
            continue
        path_edges: List[Dict[str, Any]] = []
        path_tids: List[int] = [start_tid]
        curr = start_tid
        while curr in adj and adj[curr]:
            next_edge = adj[curr][0]
            path_edges.append(next_edge)
            nxt_tid = int(next_edge["owner_tid"])
            if nxt_tid in path_tids:
                cycle_start = path_tids.index(nxt_tid)
                deadlock_cycles.append(path_edges[cycle_start:])
                break
            if nxt_tid in visited_tids:
                break
            path_tids.append(nxt_tid)
            visited_tids.add(curr)
            curr = nxt_tid

    if lock_read_errors and (not locks_report or len(lock_read_errors) == len(candidate_locks)):
        limitations.extend(lock_read_errors)
    if stack_read_errors:
        limitations.extend(stack_read_errors)
    is_inconclusive = bool(
        not deadlock_cycles
        and not wait_for_edges
        and limitations
        and (
            not all_threads
            or not map_data.get("mappings")
            or (candidate_locks and not locks_report)
            or (target_threads and len(stack_read_errors) >= len(target_threads))
        )
    )
    cs_status = "ANOMALIES_DETECTED" if (deadlock_cycles or wait_for_edges) else ("INCONCLUSIVE" if is_inconclusive else "OBSERVED")
    latency_us = round((time.monotonic_ns() - t_start_ns) / 1000.0, 2)
    return {
        "pid": pid,
        "target_host": target_adapter.target_host(),
        "is_remote": target_adapter.is_remote(),
        "stop_duration_ms": 0.0,
        "evaluation_latency_us": latency_us,
        "status": cs_status,
        "limitations": limitations,
        "target_abi": target_abi.to_dict(),
        "abi_support": abi_support_summary(
            target_abi, [FEATURE_MUTEX_OWNER, FEATURE_SYSCALL_NAMES, FEATURE_FRAME_LAYOUT, FEATURE_CFI_UNWIND]
        ),
        "cfi_unwind_status": cfi_support.status,
        "cfi_unwind_status_reason": unwinder_reason or cfi_support.message,
        "lock_owner_status": owner_support.status,
        "lock_owner_status_reason": owner_support.message,
        "threads_inspected": len(thread_reports),
        "threads": thread_reports,
        "locks_inspected": len(locks_report),
        "locks": locks_report,
        "wait_for_edges": wait_for_edges,
        "deadlock_detected": len(deadlock_cycles) > 0,
        "deadlock_cycles": deadlock_cycles,
        "deadlock_cycle": deadlock_cycles[0] if deadlock_cycles else [],
        "blocked_threads": [tr for tr in thread_reports if tr.get("waiting_on_lock") is not None],
        "llm_next_step_hint": (
            f"CRITICAL DEADLOCK DETECTED: Circular mutex wait across {len(deadlock_cycles[0])} threads: "
            + " -> ".join(f"TID {e['waiter_tid']} ({e['waiter_name']}) waits on {e['lock_name']} held by TID {e['owner_tid']}" for e in deadlock_cycles[0])
            if deadlock_cycles
            else (
                f"Lock contention active: {len(wait_for_edges)} thread(s) blocked waiting on a held mutex."
                if wait_for_edges
                else (
                    f"Thread/lock inspection inconclusive due to read failure(s): {'; '.join(limitations[:3])}"
                    if is_inconclusive
                    else f"Inspected {len(thread_reports)} thread callstack(s) and {len(locks_report)} mutex(es) in zero-stop mode."
                )
            )
        ),
    }


# -------------------------------------------------------------------------
# Phase 41 (Phase 11): Zero-Stop Stack Frame Local/Parameter Decoder
#                      & 1-Call Composite Incident Auto-Triage
# -------------------------------------------------------------------------

def inspect_thread_locals_and_frame_vars(
    mgr,
    pid: int,
    companion_elf_path: str,
    tid: Optional[int] = None,
    max_frames: int = 8,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    adapter: Optional[TargetExecutionAdapter] = None,
) -> Dict[str, Any]:
    """Decodes function formal parameters and local variables (`DW_TAG_formal_parameter`, `DW_TAG_variable`)
        on each active thread's stack frames in zero-stop mode using DWARF `DW_OP_fbreg` / frame-pointer unwinding,
        plus function-scoped static variables (`DW_OP_addr`).
        """
    target_adapter = mgr._resolve_adapter(
        pid=pid,
        remote_host=remote_host,
        ssh_user=ssh_user,
        ssh_port=ssh_port,
        ssh_key=ssh_key,
        ssh_proxy_jump=ssh_proxy_jump,
        adapter=adapter,
    )
    t_start_ns = time.monotonic_ns()
    primary_elf, _ = mgr._split_companion_elf_paths(companion_elf_path)
    if not primary_elf:
        raise ValueError("Valid companion ELF path is required")

    map_data = mgr._get_process_maps_and_load_bias(
        pid=pid,
        companion_elf_path=companion_elf_path,
        adapter=target_adapter,
    )
    load_bias = map_data.get("base_address_int", 0)
    idx = DwarfIndexer.get_index(primary_elf)
    is_dyn = (idx.elf_type == "ET_DYN")
    # IMP-015: frame-pointer / CFA / call-rel32 conventions below are x86_64 only.
    target_abi = detect_target_abi(target_adapter, pid)
    frame_support = check_support(target_abi, FEATURE_FRAME_LAYOUT)
    ptr_size = idx.pointer_size or ((target_abi.word_size or 64) // 8)
    endian = idx.endianness or target_abi.endianness or "little"
    ptr_fmt = ("<" if endian == "little" else ">") + ("Q" if ptr_size == 8 else "I")

    exec_vmas: List[Tuple[int, int]] = []
    all_mappings = map_data.get("mappings", [])
    for m in all_mappings:
        perms = m.get("permissions", "")
        ms = int(m["start_int"]) if m.get("start_int") is not None else int(m.get("start", "0"), 16)
        me = int(m["end_int"]) if m.get("end_int") is not None else int(m.get("end", "0"), 16)
        if "x" in perms and ms > 0 and me > ms:
            exec_vmas.append((ms, me))

    def _find_dwarf_subprogram(rt_pc: int) -> Optional[Any]:
        lt_pc = (rt_pc - load_bias) if is_dyn else rt_pc
        if lt_pc <= 0:
            return None
        best = None
        best_span = None
        for subp in idx.subprograms:
            if subp.low_pc is None or subp.low_pc <= 0:
                continue
            if subp.low_pc == lt_pc:
                return subp
            if subp.high_pc is not None and subp.low_pc <= lt_pc < subp.high_pc:
                span = subp.high_pc - subp.low_pc
                if best_span is None or span < best_span:
                    best = subp
                    best_span = span
        return best

    # IMP-011: CFA of every frame from the CFI unwinder; DW_OP_fbreg evaluated against DW_AT_frame_base.
    unwinder, cfi_support, unwinder_reason = mgr._imp011_prepare_unwinder(
        target_adapter, pid, target_abi, map_data, endian
    )
    try:
        main_exe_real = os.path.realpath(f"/proc/{pid}/exe")
    except Exception:
        main_exe_real = None
    sp_dw = {"x86_64": 7, "aarch64": 31}.get(target_abi.architecture or "")

    def _frame_reg(fr: Dict[str, Any], regno: int) -> Optional[int]:
        if sp_dw is not None and regno == sp_dw:
            return fr.get("sp")
        return (fr.get("regs") or {}).get(regno)

    def _eval_frame_base(subp: Any, fr: Dict[str, Any]) -> Tuple[Optional[int], str]:
        fb = (subp.frame_base or "").strip()
        cfa = fr.get("cfa")
        if not fb or "DW_OP_call_frame_cfa" in fb:
            return cfa, "DW_OP_call_frame_cfa"
        m_b = re.search(r"DW_OP_breg(\d+)[^:]*:\s*(-?\d+)", fb)
        if m_b:
            rv = _frame_reg(fr, int(m_b.group(1)))
            return (rv + int(m_b.group(2)) if rv is not None else None), fb
        m_r = re.search(r"DW_OP_reg(\d+)", fb)
        if m_r:
            return _frame_reg(fr, int(m_r.group(1))), fb
        return None, fb

    def _decode_cfi_frame_vars(subp: Any, fr: Dict[str, Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Optional[int], str]:
        params: List[Dict[str, Any]] = []
        locs: List[Dict[str, Any]] = []
        fbase, fb_kind = _eval_frame_base(subp, fr)
        for v in subp.variables:
            if not v.name:
                continue
            loc_str = v.location_expr or ""
            var_rt_addr = 0
            m_fb = re.search(r"DW_OP_fbreg:\s*(-?\d+)", loc_str)
            m_breg = re.search(r"DW_OP_breg(\d+)\s*(?:\([^)]+\))?:\s*(-?\d+)", loc_str)
            m_addr = re.search(r"DW_OP_addr:\s*([0-9a-fA-F]+)", loc_str)
            if m_fb and fbase is not None:
                var_rt_addr = fbase + int(m_fb.group(1))
            elif m_breg:
                rv = _frame_reg(fr, int(m_breg.group(1)))
                if rv is not None:
                    var_rt_addr = rv + int(m_breg.group(2))
            elif m_addr:
                lt_a = int(m_addr.group(1), 16)
                var_rt_addr = (load_bias + lt_a) if is_dyn else lt_a
            if var_rt_addr <= 0:
                continue
            v_val, v_st, _, _ = mgr._decode_typed_memory(
                adapter=target_adapter, pid=pid, idx=idx, addr=var_rt_addr,
                type_offset=v.type_offset, depth=0, max_struct_depth=2,
            )
            if v_st != "OBSERVED":
                continue
            v_entry = {
                "name": v.name,
                "type_name": idx.get_type_name(v.type_offset),
                "runtime_address": f"0x{var_rt_addr:x}",
                "location_expr": loc_str,
                "value": v_val,
            }
            (params if v.is_parameter else locs).append(v_entry)
        return params, locs, fbase, fb_kind

    def _cfi_frames_out(res: Dict[str, Any]) -> List[Dict[str, Any]]:
        out_frames: List[Dict[str, Any]] = []
        for fr in res.get("frames", []):
            if len(out_frames) >= max_frames:
                break
            lookup = int(fr["lookup_pc"])
            desc = unwinder.describe_pc(int(fr["pc"]), lookup)
            mpath = desc.get("module_path")
            if main_exe_real and mpath and os.path.realpath(mpath) != main_exe_real:
                continue  # DWARF of the companion ELF describes the main executable only
            subp = _find_dwarf_subprogram(lookup)
            if subp is None or subp.name in ("_start",):
                continue
            if fr.get("cfa") is None:
                params, locs, fbase, fb_kind = [], [], None, "CFA_UNKNOWN"
                v_status = "CFA_UNKNOWN"
            else:
                params, locs, fbase, fb_kind = _decode_cfi_frame_vars(subp, fr)
                v_status = SUPPORT_SUPPORTED if fbase is not None else "FRAME_BASE_UNKNOWN"
            fp_reg = {"x86_64": 6, "aarch64": 29}.get(target_abi.architecture or "")
            fp_val = (fr.get("regs") or {}).get(fp_reg) if fp_reg is not None else None
            out_frames.append({
                "frame_index": len(out_frames),
                "function_name": subp.name,
                "source_location": f"{subp.decl_file}:{subp.decl_line}" if subp.decl_file else None,
                "runtime_pc": f"0x{int(fr['pc']):x}",
                "cfa_address": f"0x{int(fr['cfa']):x}" if fr.get("cfa") is not None else None,
                "fp_address": f"0x{fp_val:x}" if fp_val else None,
                "parameters": params,
                "locals": locs,
                "variables_status": v_status,
                "frame_base": fb_kind,
                "frame_base_address": f"0x{fbase:x}" if fbase is not None else None,
                "unwind": fr["unwind"],
                "estimated": bool(fr["estimated"]),
                "stack_frame_index": fr.get("index"),
                **({"unwound_via": fr["unwound_via"]} if fr.get("unwound_via") else {}),
            })
        return out_frames

    all_threads = target_adapter.get_threads(pid)
    target_threads = [t for t in all_threads if tid is None or int(t["tid"]) == int(tid)]
    thread_results: List[Dict[str, Any]] = []
    # Legacy (no CFI) CFA guesses are only meaningful for the x86_64 frame layout.
    legacy_layout_ok = frame_support.supported and target_abi.architecture == "x86_64"
    legacy_status = frame_support.status if (legacy_layout_ok or not frame_support.supported) else SUPPORT_NOT_SUPPORTED_ON_TARGET

    for t in target_threads:
        t_tid = int(t["tid"])
        t_name = t.get("name", f"thread_{t_tid}")
        s_info = t.get("stack_info") or {}
        sp_int = int(s_info.get("sp_int") or 0)
        s_start = int(s_info.get("start_int") or 0)
        s_end = int(s_info.get("end_int") or 0)

        if sp_int > 0:
            for m in all_mappings:
                ms = int(m["start_int"]) if m.get("start_int") is not None else int(m.get("start", "0"), 16)
                me = int(m["end_int"]) if m.get("end_int") is not None else int(m.get("end", "0"), 16)
                if ms <= sp_int < me:
                    s_start, s_end = ms, me
                    break

        if (s_start <= 0 or (t_tid != pid and not (s_start <= sp_int < s_end))) and t_tid != pid:
            for m_i, m in enumerate(all_mappings):
                perms = m.get("permissions", "")
                if m.get("category") != "anonymous" or "r" not in perms or "w" not in perms:
                    continue
                ms = int(m["start_int"]) if m.get("start_int") is not None else int(m.get("start", "0"), 16)
                me = int(m["end_int"]) if m.get("end_int") is not None else int(m.get("end", "0"), 16)
                has_guard = (m_i > 0 and all_mappings[m_i - 1].get("permissions", "").startswith("---"))
                if not has_guard or not (65536 <= (me - ms) <= 16 * 1024 * 1024):
                    continue
                tcb_from = max(ms, me - 8192)
                raw_tcb, tst, _ = target_adapter.read_memory(pid, tcb_from, me - tcb_from)
                if tst == "OBSERVED" and raw_tcb:
                    tid_pair = struct.pack("<ii" if endian == "little" else ">ii", t_tid, pid)
                    tid_single = struct.pack("<i" if endian == "little" else ">i", t_tid)
                    if tid_pair in raw_tcb or tid_single in raw_tcb:
                        s_start, s_end = ms, me
                        break

        frames_out: List[Dict[str, Any]] = []
        sc_info: Dict[str, Any] = {"state": "unavailable"}
        if target_adapter.is_remote():
            sc_info = dict(t.get("syscall") or {"state": "unavailable"})   # adapter-provided (IMP-011 part 3)
        else:
            sc_info = mgr._imp011_read_syscall(pid, t_tid)
        cfi_res = mgr._imp011_unwind_thread(unwinder, sc_info, None, 64)
        if s_start > 0 and s_end > s_start:
            tcb_int = int(s_info.get("tcb_address_int") or 0)
            stack_ceiling = (tcb_int - 64) if (s_start < tcb_int <= s_end) else s_end
            scan_from = sp_int if (sp_int > 0 and s_start <= sp_int < stack_ceiling) else max(s_start, stack_ceiling - 32768)
            scan_from = scan_from & ~(ptr_size - 1)
            scan_len = min(32768, max(0, stack_ceiling - scan_from))
            if cfi_res is None and sc_info.get("state") == "running":
                cfi_res = mgr._imp011_unwind_thread(unwinder, sc_info, (scan_from, scan_from + scan_len), 64)
                if cfi_res is not None and not cfi_res.get("frames"):
                    cfi_res = None
            if cfi_res is not None:
                frames_out = _cfi_frames_out(cfi_res)
                raw_stack, sst = None, "SKIPPED_CFI"
            else:
                raw_stack, sst, _ = target_adapter.read_memory(pid, scan_from, scan_len)

            if sst == "OBSERVED" and raw_stack:
                num_words = len(raw_stack) // ptr_size
                # First pass: collect candidate return address slots [(word_idx, slot_addr, rt_pc, subp)]
                raw_hits: List[Tuple[int, int, int, Any]] = []
                for w_i in range(num_words):
                    cand_pc = struct.unpack_from(ptr_fmt, raw_stack, w_i * ptr_size)[0]
                    if not any(es <= cand_pc < ee for es, ee in exec_vmas):
                        continue
                    exact_subp = _find_dwarf_subprogram(cand_pc)
                    lt_cand = (cand_pc - load_bias) if is_dyn else cand_pc
                    if exact_subp is not None and exact_subp.low_pc == lt_cand:
                        continue
                    subp = _find_dwarf_subprogram(cand_pc - 1)
                    if subp is not None and subp.name not in ("_start", "__libc_start_main_impl", "clone", "clone3", "start_thread"):
                        slot_addr = scan_from + w_i * ptr_size
                        if not raw_hits and (t.get("state") == "R" or t.get("is_running_user_space")) and legacy_layout_ok:
                            call_bytes, cb_st, _ = target_adapter.read_memory(pid, cand_pc - 5, 5)
                            if cb_st == "OBSERVED" and call_bytes and len(call_bytes) == 5 and call_bytes[0] == 0xe8:
                                rel32 = struct.unpack("<i" if endian == "little" else ">i", call_bytes[1:5])[0]
                                callee_pc = (cand_pc + rel32) & 0xffffffffffffffff
                                callee_subp = _find_dwarf_subprogram(callee_pc)
                                if callee_subp is not None and callee_subp.name != subp.name:
                                    raw_hits.append((max(0, w_i - 1), slot_addr - ptr_size, callee_pc, callee_subp))
                        if not raw_hits or raw_hits[-1][3].name != subp.name:
                            raw_hits.append((w_i, slot_addr, cand_pc, subp))

                # Second pass: for each frame hit, determine its CFA / FP and decode its parameters & local variables
                for h_idx, (w_i, slot_addr, cand_pc, subp) in enumerate(raw_hits[:max_frames]):
                    if not legacy_layout_ok:
                        # IMP-015/IMP-011: without CFI the CFA/frame-pointer guesses below are the x86_64
                        # convention only. Function identity (return-address scan + DWARF) is kept; no values.
                        frames_out.append({
                            "frame_index": h_idx,
                            "function_name": subp.name,
                            "source_location": f"{subp.decl_file}:{subp.decl_line}" if subp.decl_file else None,
                            "runtime_pc": f"0x{cand_pc:x}",
                            "cfa_address": None,
                            "fp_address": None,
                            "parameters": [],
                            "locals": [],
                            "variables_status": legacy_status,
                            "unwind": CFI_UNWIND_SCAN,
                            "estimated": True,
                        })
                        continue
                    # Determine CFA for `subp`:
                    # Strategy A: check if the callee saved `subp`'s frame pointer `rbp` at `slot_addr - ptr_size`
                    cfa_addr = 0
                    fp_addr = 0
                    if w_i >= 1:
                        prev_word = struct.unpack_from(ptr_fmt, raw_stack, (w_i - 1) * ptr_size)[0]
                        if slot_addr <= prev_word < s_end and (prev_word - slot_addr) <= 16384:
                            fp_addr = prev_word
                            cfa_addr = fp_addr + 2 * ptr_size

                    # Strategy B: if there is a caller return address slot `next_slot_addr` in `raw_hits[h_idx + 1]`,
                    # `subp`'s own return address back to its caller is at `next_slot_addr`, so `cfa = next_slot_addr + ptr_size`!
                    if cfa_addr == 0 and (h_idx + 1) < len(raw_hits):
                        caller_ret_slot = raw_hits[h_idx + 1][1]
                        if caller_ret_slot > slot_addr and (caller_ret_slot - slot_addr) <= 16384:
                            cfa_addr = caller_ret_slot + ptr_size
                            fp_addr = caller_ret_slot - ptr_size

                    # Strategy C: search upward on stack from w_i + 1 for a saved frame-pointer chain `[saved_rbp, ret_pc]`
                    if cfa_addr == 0:
                        for up_i in range(w_i + 1, min(num_words - 1, w_i + 128)):
                            cand_ret = struct.unpack_from(ptr_fmt, raw_stack, (up_i + 1) * ptr_size)[0]
                            if any(es <= cand_ret < ee for es, ee in exec_vmas):
                                caller_slot = scan_from + (up_i + 1) * ptr_size
                                cfa_addr = caller_slot + ptr_size
                                fp_addr = caller_slot - ptr_size
                                break

                    decoded_params: List[Dict[str, Any]] = []
                    decoded_locals: List[Dict[str, Any]] = []

                    for v in subp.variables:
                        if not v.name:
                            continue
                        loc_str = v.location_expr or ""
                        var_rt_addr = 0

                        m_fb = re.search(r"DW_OP_fbreg:\s*(-?\d+)", loc_str)
                        m_breg = re.search(r"DW_OP_breg\d+\s*(?:\([^)]+\))?:\s*(-?\d+)", loc_str)
                        m_addr = re.search(r"DW_OP_addr:\s*([0-9a-fA-F]+)", loc_str)

                        if m_fb and cfa_addr > 0:
                            fb_off = int(m_fb.group(1))
                            var_rt_addr = cfa_addr + fb_off
                        elif m_breg and fp_addr > 0:
                            br_off = int(m_breg.group(1))
                            var_rt_addr = fp_addr + br_off
                        elif m_addr:
                            lt_a = int(m_addr.group(1), 16)
                            var_rt_addr = (load_bias + lt_a) if is_dyn else lt_a

                        if var_rt_addr <= 0:
                            continue

                        v_val, v_st, _, _ = mgr._decode_typed_memory(
                            adapter=target_adapter,
                            pid=pid,
                            idx=idx,
                            addr=var_rt_addr,
                            type_offset=v.type_offset,
                            depth=0,
                            max_struct_depth=2,
                        )
                        if v_st != "OBSERVED":
                            continue

                        v_entry = {
                            "name": v.name,
                            "type_name": idx.get_type_name(v.type_offset),
                            "runtime_address": f"0x{var_rt_addr:x}",
                            "location_expr": loc_str,
                            "value": v_val,
                        }
                        if v.is_parameter:
                            decoded_params.append(v_entry)
                        else:
                            decoded_locals.append(v_entry)

                    frames_out.append({
                        "frame_index": h_idx,
                        "function_name": subp.name,
                        "source_location": f"{subp.decl_file}:{subp.decl_line}" if subp.decl_file else None,
                        "runtime_pc": f"0x{cand_pc:x}",
                        "cfa_address": f"0x{cfa_addr:x}" if cfa_addr else None,
                        "fp_address": f"0x{fp_addr:x}" if fp_addr else None,
                        "parameters": decoded_params,
                        "locals": decoded_locals,
                        "unwind": CFI_UNWIND_SCAN,
                        "estimated": True,
                    })

        thread_results.append({
            "tid": t_tid,
            "name": t_name,
            "state": t.get("state", "S"),
            "frames_count": len(frames_out),
            "frames": frames_out,
            "frame_decode_status": frame_support.status if (cfi_res is not None or legacy_layout_ok) else legacy_status,
            # IMP-011 (added fields)
            **mgr._imp011_thread_summary(cfi_res, sc_info, unwinder_reason),
        })

    latency_us = round((time.monotonic_ns() - t_start_ns) / 1000.0, 2)
    return {
        "pid": pid,
        "target_host": target_adapter.target_host(),
        "is_remote": target_adapter.is_remote(),
        "stop_duration_ms": 0.0,
        "evaluation_latency_us": latency_us,
        "target_abi": target_abi.to_dict(),
        "frame_decode_status": frame_support.status,
        "frame_decode_status_reason": frame_support.message,
        "cfi_unwind_status": cfi_support.status,
        "cfi_unwind_status_reason": unwinder_reason or cfi_support.message,
        "threads_count": len(thread_results),
        "threads": thread_results,
        "llm_next_step_hint": (
            f"Stack frame decoding {frame_support.message}; frames are identified but no parameter/local values were produced."
            if not frame_support.supported else
            f"Decoded stack frame parameters and local variables across {len(thread_results)} thread(s) without stopping the target."
        ),
    }

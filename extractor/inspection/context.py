"""Stateful target context: bind / get the active target and resolve pid, debug image and companion libraries for
every inspection call.

Moved verbatim from extractor/watch_session.py; functions take the ``WatchSessionManager`` first (``mgr``) and
are bound on it as methods.
"""

import os
import time
from typing import Any, Dict, List, Optional, Tuple

from ..debug_image import inspect_elf
from ..target_adapter import TargetExecutionAdapter


def _coerce_int(
    val: Any,
    default: int,
    min_val: Optional[int] = None,
    max_val: Optional[int] = None,
) -> int:
    """Safely coerces arbitrary input to int and clamps within [min_val, max_val]."""
    if val is None or isinstance(val, bool):
        res = default
    else:
        try:
            if isinstance(val, str):
                s = val.strip()
                res = int(s, 16) if s.lower().startswith("0x") else int(float(s))
            else:
                res = int(val)
        except (ValueError, TypeError, OverflowError):
            res = default
    if min_val is not None and res < min_val:
        res = min_val
    if max_val is not None and res > max_val:
        res = max_val
    return res


# -------------------------------------------------------------------------
# Phase 48 (Phase 18): Stateful Target Context, Auto-Heal PID / Zero-Path
# ELF Discovery, Forgiving C/C++ Expression Auto-Coercer, and 1-Call
# Universal Intent Gateway (`runtime_ask`)
# -------------------------------------------------------------------------

def get_active_target_context(mgr) -> Dict[str, Any]:
    """Returns the currently bound stateful target context `(pid, process_name, companion_elf_path, ...)`."""
    with mgr._lock:
        ctx = dict(mgr._active_target_context)
    ctx["has_active_context"] = bool(ctx.get("pid") or ctx.get("companion_elf_path"))
    return ctx


def bind_target_context(
    mgr,
    pid: Optional[int] = None,
    companion_elf_path: Optional[str] = None,
    process_name: Optional[str] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    adapter: Optional[TargetExecutionAdapter] = None,
) -> Dict[str, Any]:
    """Explicitly binds or updates the stateful target session context so subsequent MCP/API calls
        can omit `pid` and `companion_elf_path`.
        """
    return mgr.resolve_target_context(
        pid=pid,
        companion_elf_path=companion_elf_path,
        process_name=process_name,
        remote_host=remote_host,
        ssh_user=ssh_user,
        ssh_port=ssh_port,
        ssh_key=ssh_key,
        ssh_proxy_jump=ssh_proxy_jump,
        adapter=adapter,
    )


def resolve_target_context(
    mgr,
    pid: Optional[int] = None,
    companion_elf_path: Optional[str] = None,
    process_name: Optional[str] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    adapter: Optional[TargetExecutionAdapter] = None,
) -> Dict[str, Any]:
    """Resolves `(pid, companion_elf_path, ...)` using:
        1. Explicit parameters if provided.
        2. Inheritance from `self._active_target_context` when `pid` or `companion_elf_path` is omitted.
        3. Zero-path ELF auto-discovery from `/proc/<pid>/exe` (or `.debug` sidecar) when `companion_elf_path` is omitted.
        4. Automatic PID self-healing (`auto_healed_pid = True`) when the bound target process has restarted under a new PID.
        """
    with mgr._lock:
        saved = dict(mgr._active_target_context)

    if isinstance(pid, bool):
        raise ValueError("Invalid target PID: boolean value is not a valid PID")
    if pid is not None and isinstance(pid, str):
        p_str = pid.strip()
        if p_str.startswith("-") or p_str == "1":
            raise ValueError(f"Invalid or reserved system PID: {p_str} (PID must be an integer > 1)")
        if p_str.isdigit():
            pid = int(p_str)
        elif p_str and not process_name:
            process_name = p_str
            pid = None
        elif p_str:
            raise ValueError(f"Invalid non-numeric target PID: {p_str}")
    if pid is not None and isinstance(pid, (int, float)):
        p_int = int(pid)
        if p_int == 1 or p_int < 0:
            raise ValueError(f"Invalid or reserved system PID {p_int}: PID must be an integer > 1 (PID 1 is reserved)")
        if p_int == 0 and not process_name and not saved.get("pid"):
            raise ValueError("Invalid target PID 0: PID must be an integer > 1")

    explicit_pid = int(pid) if (pid is not None and int(pid) > 1) else None
    saved_pid = int(saved["pid"]) if (saved.get("pid") is not None and int(saved["pid"]) > 0) else None
    eff_pid = explicit_pid if explicit_pid is not None else saved_pid
    is_same_target = (explicit_pid is None or explicit_pid == saved_pid)

    # Do NOT inherit remote SSH parameters or remote host across different target processes
    if is_same_target:
        eff_remote_host = remote_host if remote_host is not None else saved.get("remote_host")
        eff_ssh_user = ssh_user if ssh_user is not None else saved.get("ssh_user")
        coerced_port = mgr._coerce_int(ssh_port, 22, 1, 65535)
        eff_ssh_port = coerced_port if (coerced_port and coerced_port != 22) else mgr._coerce_int(saved.get("ssh_port"), 22, 1, 65535)
        eff_ssh_key = ssh_key if ssh_key is not None else saved.get("ssh_key")
        eff_ssh_jump = ssh_proxy_jump if ssh_proxy_jump is not None else saved.get("ssh_proxy_jump")
    else:
        eff_remote_host = remote_host
        eff_ssh_user = ssh_user
        eff_ssh_port = mgr._coerce_int(ssh_port, 22, 1, 65535) or 22
        eff_ssh_key = ssh_key
        eff_ssh_jump = ssh_proxy_jump

    # If caller explicitly switched to a different PID without specifying companion_elf_path,
    # prefer auto-discovering `/proc/<pid>/exe` first if it differs from saved_pid
    if explicit_pid is not None and saved_pid is not None and explicit_pid != saved_pid and not companion_elf_path:
        eff_elf = None
        eff_proc_name = process_name
    else:
        eff_elf = companion_elf_path if (companion_elf_path and str(companion_elf_path).strip()) else saved.get("companion_elf_path")
        eff_proc_name = process_name or (saved.get("process_name") if is_same_target else None)

    target_adapter = mgr._resolve_adapter(
        pid=eff_pid or 1,
        remote_host=eff_remote_host,
        ssh_user=eff_ssh_user,
        ssh_port=eff_ssh_port,
        ssh_key=eff_ssh_key,
        ssh_proxy_jump=eff_ssh_jump,
        adapter=adapter,
    )

    elf_auto_discovered = False
    elf_discovery_source = None
    auto_healed_pid = False
    previous_pid = None

    # Step 1: If eff_elf is known, inspect its build_id & basename for process discovery/healing
    known_build_id = saved.get("build_id") if is_same_target else None
    if eff_elf:
        primary_cand, _ = mgr._split_companion_elf_paths(eff_elf)
        if primary_cand and os.path.isfile(primary_cand):
            try:
                ident = inspect_elf(primary_cand)
                known_build_id = ident.build_id
                if not eff_proc_name:
                    eff_proc_name = os.path.basename(primary_cand)
            except Exception:
                pass

    # Step 2: Check liveness of eff_pid; if dead (process restarted!) or omitted, attempt PID auto-discovery / auto-healing
    pid_alive = False
    if eff_pid is not None and eff_pid > 0:
        alive_ok, _ = target_adapter.check_liveness(eff_pid)
        if alive_ok and not target_adapter.is_remote():
            # Also verify it is not a zombie ('Z')
            try:
                with open(f"/proc/{eff_pid}/status", "r", encoding="utf-8", errors="replace") as sf:
                    st_txt = sf.read()
                if "State:	Z" in st_txt:
                    alive_ok = False
            except Exception:
                alive_ok = False
        pid_alive = alive_ok

    # Only auto-heal when either pid was omitted OR pid was previously bound (or companion_elf_path/process_name given)
    can_search_replacement = bool(
        eff_proc_name
        or (eff_elf and os.path.isfile(mgr._split_companion_elf_paths(eff_elf)[0]))
    )
    # Do not auto-heal arbitrary unrelated synthetic PIDs (like 999999 in negative unit tests) unless
    # that PID was the previously bound PID or pid was omitted!
    should_attempt_heal = (
        not pid_alive
        and can_search_replacement
        and (explicit_pid is None or explicit_pid == saved_pid or process_name is not None)
    )

    if should_attempt_heal:
        search_name = eff_proc_name
        if not search_name and eff_elf:
            search_name = os.path.basename(mgr._split_companion_elf_paths(eff_elf)[0])
        try:
            cands = target_adapter.find_processes(
                process_name=search_name,
                companion_build_id=known_build_id,
                limit=10,
            )
        except Exception:
            cands = []

        # Local fallback: scan /proc for matching executable path or comm name
        if not cands and not target_adapter.is_remote() and (search_name or eff_elf):
            primary_abs = os.path.abspath(mgr._split_companion_elf_paths(eff_elf)[0]) if eff_elf else None
            for entry in os.listdir("/proc"):
                if not entry.isdigit():
                    continue
                cand_p = int(entry)
                if cand_p == eff_pid:
                    continue
                try:
                    with open(f"/proc/{cand_p}/status", "r", encoding="utf-8", errors="replace") as sf:
                        st_txt = sf.read()
                    if "State:	Z" in st_txt:
                        continue
                    exe_real = os.readlink(f"/proc/{cand_p}/exe").replace(" (deleted)", "").strip()
                    with open(f"/proc/{cand_p}/comm", "r", encoding="utf-8", errors="replace") as cf:
                        comm_str = cf.read().strip()
                    if (primary_abs and os.path.abspath(exe_real) == primary_abs) or (
                        search_name and (comm_str == search_name[:15] or os.path.basename(exe_real) == search_name)
                    ):
                        cands.append({"pid": cand_p, "name": comm_str, "executable": exe_real})
                except Exception:
                    continue
            cands.sort(key=lambda x: int(x["pid"]), reverse=True)

        if cands:
            new_pid = int(cands[0]["pid"])
            if eff_pid is not None and eff_pid != new_pid:
                auto_healed_pid = True
                previous_pid = eff_pid
            elif saved_pid is not None and saved_pid != new_pid:
                auto_healed_pid = True
                previous_pid = saved_pid
            eff_pid = new_pid
            pid_alive = True

    # Step 3: Zero-Path ELF Auto-Discovery when eff_elf is omitted and eff_pid is known
    if (not eff_elf or not str(eff_elf).strip()) and eff_pid and eff_pid > 0 and not target_adapter.is_remote():
        cand_paths: List[Tuple[str, str]] = []
        try:
            exe_link = os.readlink(f"/proc/{eff_pid}/exe").replace(" (deleted)", "").strip()
            if exe_link and os.path.isfile(exe_link):
                cand_paths.append((exe_link, "proc_pid_exe"))
                cand_paths.append((f"{exe_link}.debug", "sidecar_debug"))
                cand_paths.append((f"{exe_link}.dbg", "sidecar_dbg"))
                cand_paths.append((f"{exe_link}_debug", "sidecar_underscore_debug"))
        except Exception:
            pass
        cand_paths.append((f"/proc/{eff_pid}/exe", "proc_pid_exe_direct"))

        for c_path, c_src in cand_paths:
            if not os.path.isfile(c_path):
                continue
            try:
                c_ident = inspect_elf(c_path)
                if c_ident.has_debug_info:
                    eff_elf = os.path.abspath(c_path) if c_src != "proc_pid_exe_direct" else c_path
                    known_build_id = c_ident.build_id
                    elf_auto_discovered = True
                    elf_discovery_source = c_src
                    break
            except Exception:
                continue

        # If still not found, fall back to the saved companion ELF only for the bound target itself
        # Never inherit it across targets: an explicit PID that is not the bound target must not receive
        # the bound target's debug image.
        if not eff_elf and saved.get("companion_elf_path") and (explicit_pid is None or explicit_pid == saved_pid):
            eff_elf = saved.get("companion_elf_path")

    if not eff_pid or eff_pid <= 0:
        raise ValueError("Target PID could not be resolved. Provide `pid` or `process_name`, or bind a target first via `runtime_target_connect`.")
    if not eff_elf:
        raise ValueError(f"Companion ELF with DWARF debug info could not be resolved for PID {eff_pid}. Provide `companion_elf`.")

    # Step 4: Persist resolved active context when pid is alive and eff_elf exists
    primary_resolved, _ = mgr._split_companion_elf_paths(eff_elf)
    if pid_alive and primary_resolved and os.path.isfile(primary_resolved):
        try:
            proc_ident = target_adapter.get_process_identity(eff_pid)
            proc_bid = proc_ident.get("build_id")
            elf_ident = inspect_elf(primary_resolved)
            elf_bid = getattr(elf_ident, "build_id", None)
            if proc_bid and elf_bid and str(proc_bid).strip().lower() != str(elf_bid).strip().lower():
                raise ValueError(
                    f"Target process '{eff_pid}' running executable has build-id '{proc_bid}', "
                    f"but companion image '{eff_elf}' has build-id '{elf_bid}'. Mismatched symbols rejected."
                )
            if not known_build_id:
                known_build_id = elf_bid or proc_bid
        except ValueError:
            raise
        except Exception:
            pass

        if not eff_proc_name:
            if not target_adapter.is_remote():
                try:
                    with open(f"/proc/{eff_pid}/comm", "r", encoding="utf-8", errors="replace") as cf:
                        eff_proc_name = cf.read().strip()
                except Exception:
                    pass
            if not eff_proc_name:
                eff_proc_name = os.path.basename(primary_resolved)
        with mgr._lock:
            healed_cnt = int(mgr._active_target_context.get("auto_healed_count") or 0) + (1 if auto_healed_pid else 0)
            mgr._active_target_context.update({
                "pid": int(eff_pid),
                "process_name": eff_proc_name,
                "companion_elf_path": eff_elf,
                "build_id": known_build_id,
                "remote_host": eff_remote_host,
                "ssh_user": eff_ssh_user,
                "ssh_port": eff_ssh_port,
                "ssh_key": eff_ssh_key,
                "ssh_proxy_jump": eff_ssh_jump,
                "bound_at_unix": time.time(),
                "auto_healed_count": healed_cnt,
                "last_previous_pid": previous_pid if auto_healed_pid else mgr._active_target_context.get("last_previous_pid"),
            })

    return {
        "is_bound": True,
        "pid": int(eff_pid),
        "process_name": eff_proc_name,
        "companion_elf_path": eff_elf,
        "build_id": known_build_id,
        "remote_host": eff_remote_host,
        "ssh_user": eff_ssh_user,
        "ssh_port": eff_ssh_port,
        "ssh_key": eff_ssh_key,
        "ssh_proxy_jump": eff_ssh_jump,
        "auto_healed_pid": auto_healed_pid,
        "previous_pid": previous_pid,
        "elf_auto_discovered": elf_auto_discovered,
        "elf_discovery_source": elf_discovery_source,
    }

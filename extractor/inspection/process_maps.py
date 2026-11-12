"""Process memory maps, ELF load bias (main image and shared libraries) and the memory-map/thread overview.

Moved verbatim from extractor/watch_session.py; ``WatchSessionManager`` binds the functions taking the manager
as methods, and extractor.watch_session re-exports ``calculate_load_bias``.
"""

import os
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from ..debug_image import BinaryIdentity, inspect_elf
from ..dwarf_indexer import DwarfIndexer
from ..target_adapter import TargetExecutionAdapter


# -----------------------------------------------------------------------------
# Address Correctness: ELF PT_LOAD Relocation and Load Bias
# -----------------------------------------------------------------------------

def calculate_load_bias(
    companion_identity: Optional[BinaryIdentity],
    runtime_identity: Optional[Union[BinaryIdentity, Dict[str, Any]]],
    mappings: List[Dict[str, Any]],
    page_size: int = 4096,
) -> Dict[str, Any]:
    """Calculates ELF load bias and validates relocation addresses for PIE/DYN and non-PIE binaries.
    
    Relocation semantics:
    - ET_EXEC: fixed link-time address mapping, load_bias is 0.
    - ET_DYN (PIE / Shared Library): kernel maps PT_LOAD segments with dynamic base.
      load_bias = mapping_start - (p_vaddr & ~(page_size - 1))
      Runtime address = link_time_address + load_bias.
    """
    is_dyn = False
    elf_type = "unknown"
    if companion_identity and companion_identity.elf_type:
        elf_type = companion_identity.elf_type
    elif runtime_identity:
        if isinstance(runtime_identity, dict):
            elf_type = runtime_identity.get("elf_type", "unknown")
        else:
            elf_type = runtime_identity.elf_type or "unknown"

    if elf_type == "ET_DYN":
        is_dyn = True
    elif elf_type == "ET_EXEC":
        is_dyn = False
    else:
        # If unknown, check if any mapping has high address or PIE
        is_dyn = True

    if not is_dyn:
        return {
            "load_bias": 0,
            "load_bias_hex": "0x0",
            "is_dyn": False,
            "is_ambiguous": False,
            "ambiguity_reason": None,
            "verified_segments": 1,
        }

    # Extract PT_LOAD segments
    pt_loads: List[Dict[str, Any]] = []
    if companion_identity and companion_identity.pt_loads:
        pt_loads = companion_identity.pt_loads
    elif runtime_identity:
        if isinstance(runtime_identity, dict):
            pt_loads = runtime_identity.get("pt_loads", [])
        else:
            pt_loads = getattr(runtime_identity, "pt_loads", [])

    if not pt_loads:
        first_exec = next((m for m in mappings if m.get("is_executable")), None)
        bias = first_exec["start_int"] if first_exec else (mappings[0]["start_int"] if mappings else 0)
        return {
            "load_bias": bias,
            "load_bias_hex": f"0x{bias:x}",
            "is_dyn": True,
            "is_ambiguous": first_exec is None,
            "ambiguity_reason": "No PT_LOAD segments found; used fallback mapping" if first_exec is None else None,
            "verified_segments": 0,
        }

    sorted_loads = sorted(pt_loads, key=lambda p: p.get("p_offset", 0))
    seg0 = sorted_loads[0]
    seg0_off_page = seg0.get("p_offset", 0) - (seg0.get("p_offset", 0) % page_size)
    seg0_vaddr_page = seg0.get("p_vaddr", 0) - (seg0.get("p_vaddr", 0) % page_size)

    # Filter out kernel pseudo-mappings ([usertrap], [vdso], [vvar], [vsyscall], [heap], [stack])
    non_pseudo_maps = [
        m for m in mappings
        if not str(m.get("pathname", "")).strip().startswith("[")
    ]
    search_pool = non_pseudo_maps if non_pseudo_maps else mappings

    candidates = [m for m in search_pool if m.get("offset_int", 0) == seg0_off_page]
    if not candidates:
        candidates = [m for m in search_pool if m.get("offset_int", 0) == 0]
    if not candidates:
        candidates = search_pool[:1]

    if not candidates:
        return {
            "load_bias": 0,
            "load_bias_hex": "0x0",
            "is_dyn": True,
            "is_ambiguous": True,
            "ambiguity_reason": "No memory mappings available to determine load bias",
            "verified_segments": 0,
        }

    runtime_exe = ""
    if isinstance(runtime_identity, dict):
        runtime_exe = str(runtime_identity.get("executable") or runtime_identity.get("path") or "").strip()
    elif runtime_identity is not None:
        runtime_exe = str(getattr(runtime_identity, "path", "") or "").strip()
    companion_exe = str(getattr(companion_identity, "path", "") or "").strip() if companion_identity else ""
    runtime_base_name = os.path.basename(runtime_exe) if runtime_exe else ""
    companion_base_name = os.path.basename(companion_exe) if companion_exe else ""

    def _score_candidate(cand: Dict[str, Any]) -> Tuple[int, int, int, int, int]:
        c_path = str(cand.get("pathname", "")).strip()
        c_base = os.path.basename(c_path) if c_path else ""
        cand_bias = cand["start_int"] - seg0_vaddr_page

        # 1. Exact or basename match with runtime executable
        exe_match = 0
        if runtime_exe and c_path and (c_path == runtime_exe or c_base == runtime_base_name):
            exe_match = 3
        elif companion_exe and c_path and (c_path == companion_exe or c_base == companion_base_name):
            exe_match = 2
        elif c_path and not c_path.startswith("[") and ".so" not in c_base:
            exe_match = 1

        # 2. Count how many PT_LOAD segments align with mappings of the same module
        same_module_maps = [m for m in search_pool if str(m.get("pathname", "")).strip() == c_path] if c_path else search_pool
        seg_verified = 0
        for s in sorted_loads:
            exp_vaddr = s.get("p_vaddr", 0) + cand_bias
            if any(m["start_int"] <= exp_vaddr < m["end_int"] for m in same_module_maps):
                seg_verified += 1

        # 3. Permission compatibility with seg0 PF_X (p_flags & 1)
        seg0_is_exec = bool(seg0.get("p_flags", 0) & 1)
        cand_is_exec = bool(cand.get("is_executable") or cand.get("category") == "code")
        perm_match = 1 if (seg0_is_exec == cand_is_exec or cand_is_exec) else 0

        # 4. Prefer normal user-space PIE load addresses over low trap pages
        normal_vma = 1 if cand["start_int"] >= 0x400000 else 0

        return (exe_match, seg_verified, normal_vma, perm_match, -cand["start_int"])

    best = max(candidates, key=_score_candidate)
    load_bias = best["start_int"] - seg0_vaddr_page

    verified = 1
    ambiguous = False
    ambiguity_reason = None
    for s in sorted_loads[1:]:
        exp_vaddr = s.get("p_vaddr", 0) + load_bias
        if any(m["start_int"] <= exp_vaddr < m["end_int"] for m in mappings):
            verified += 1
        else:
            # Segment not mapped in known regions
            pass

    return {
        "load_bias": load_bias,
        "load_bias_hex": f"0x{load_bias:x}",
        "is_dyn": True,
        "is_ambiguous": ambiguous,
        "ambiguity_reason": ambiguity_reason,
        "verified_segments": verified,
    }


def _resolve_shared_lib_load_bias(
    so_ident: BinaryIdentity,
    so_debug_path: str,
    mappings: List[Dict[str, Any]],
    page_size: int = 4096,
) -> Optional[Tuple[int, str, List[Dict[str, Any]]]]:
    """Matches a companion debug .so image to its runtime mappings in /proc/<pid>/maps
        and computes its per-module ASLR load_bias.
        """
    dbg_base = os.path.basename(so_debug_path)
    # Strip common debug suffixes/prefixes: libfoo_debug.so -> libfoo, libfoo.so.debug -> libfoo.so
    stem = dbg_base
    for suf in (".debug", ".elf", "_debug.so", "-debug.so", ".so"):
        if stem.endswith(suf):
            stem = stem[:-len(suf)]
            break

    matched_maps = []
    runtime_so_path = ""
    for m in mappings:
        p = str(m.get("pathname", "")).strip()
        if not p or p.startswith("["):
            continue
        p_base = os.path.basename(p)
        if p_base == dbg_base or (stem and p_base.startswith(stem) and ".so" in p_base):
            matched_maps.append(m)
            if not runtime_so_path:
                runtime_so_path = p

    if not matched_maps:
        return None

    bias_info = calculate_load_bias(
        companion_identity=so_ident,
        runtime_identity={"executable": runtime_so_path, "elf_type": so_ident.elf_type, "pt_loads": so_ident.pt_loads},
        mappings=matched_maps,
        page_size=page_size,
    )
    return bias_info["load_bias"], (os.path.basename(runtime_so_path) or dbg_base), matched_maps


def _get_process_maps_and_load_bias(
    mgr,
    pid: Optional[int] = None,
    companion_elf_path: Optional[str] = None,
    adapter: Optional[TargetExecutionAdapter] = None,
    ttl_sec: float = 2.0,
) -> Dict[str, Any]:
    """Fast, lightweight resolution of process memory mappings, main ELF load_bias, and
        loaded shared-library debug modules WITHOUT scanning /proc/<pid>/task threads or
        materializing all DWARF discoverable_variables. Cached for `ttl_sec` seconds."""
    if (pid is None or pid <= 0) or (not companion_elf_path and mgr._active_target_context.get("companion_elf_path")):
        try:
            ctx_r = mgr.resolve_target_context(pid=pid, companion_elf_path=companion_elf_path, adapter=adapter)
            pid = ctx_r["pid"]
            companion_elf_path = companion_elf_path or ctx_r["companion_elf_path"]
        except Exception:
            pass
    target_adapter = adapter or mgr._resolve_adapter(pid=pid or 1)
    cache_key = (pid, str(companion_elf_path or ""), target_adapter.target_host())
    now_mono = time.monotonic()

    with mgr._lock:
        cached = mgr._maps_bias_cache.get(cache_key)
        if cached is not None and (now_mono - cached[0]) <= ttl_sec:
            return cached[1]

    alive, live_err = target_adapter.check_liveness(pid)
    if not alive:
        raise RuntimeError(f"Target process PID {pid} is not accessible on {target_adapter.target_host()}: {live_err}")

    mappings = target_adapter.get_proc_maps(pid)
    runtime_ident = target_adapter.get_process_identity(pid)
    primary_elf, extra_so_elfs = mgr._split_companion_elf_paths(companion_elf_path)

    companion_identity: Optional[BinaryIdentity] = None
    if primary_elf:
        if not os.path.exists(primary_elf):
            raise FileNotFoundError(f"Companion ELF binary not found: '{primary_elf}'")
        companion_identity = inspect_elf(primary_elf)

    bias_info = calculate_load_bias(companion_identity, runtime_ident, mappings)
    load_bias = bias_info["load_bias"]

    loaded_debug_modules: List[Dict[str, Any]] = []
    if primary_elf and companion_identity:
        loaded_debug_modules.append({
            "module": os.path.basename(runtime_ident.get("executable") or primary_elf),
            "debug_image": os.path.abspath(primary_elf),
            "build_id": companion_identity.build_id,
            "load_bias": f"0x{load_bias:x}",
            "load_bias_int": load_bias,
            "is_main_executable": True,
        })

    for so_path in extra_so_elfs:
        if not os.path.isfile(so_path):
            continue
        try:
            so_ident = inspect_elf(so_path)
            if not so_ident.has_debug_info:
                continue
            resolved_so = mgr._resolve_shared_lib_load_bias(so_ident, so_path, mappings)
            if resolved_so is None:
                continue
            so_bias, so_mod_name, _ = resolved_so
            loaded_debug_modules.append({
                "module": so_mod_name,
                "debug_image": os.path.abspath(so_path),
                "build_id": so_ident.build_id,
                "load_bias": f"0x{so_bias:x}",
                "load_bias_int": so_bias,
                "is_main_executable": False,
            })
        except Exception:
            pass

    result = {
        "pid": pid,
        "base_address": f"0x{load_bias:x}",
        "base_address_int": load_bias,
        "load_bias": f"0x{load_bias:x}",
        "load_bias_ambiguous": bias_info["is_ambiguous"],
        "load_bias_reason": bias_info.get("ambiguity_reason"),
        "loaded_debug_modules": loaded_debug_modules,
        "mappings": mappings,
    }
    with mgr._lock:
        if len(mgr._maps_bias_cache) > 128:
            mgr._maps_bias_cache.clear()
        mgr._maps_bias_cache[cache_key] = (now_mono, result)
        if pid and pid > 0 and primary_elf and os.path.isfile(primary_elf):
            exe_name = os.path.basename(runtime_ident.get("executable") or primary_elf)
            mgr._active_target_context.update({
                "pid": int(pid),
                "process_name": exe_name,
                "companion_elf_path": os.path.abspath(companion_elf_path or primary_elf),
                "build_id": companion_identity.build_id if companion_identity else None,
                "bound_at_unix": time.time(),
            })
    return result


def get_memory_map_and_threads(
    mgr,
    pid: int,
    companion_elf_path: Optional[str] = None,
    remote_host: Optional[str] = None,
    ssh_user: Optional[str] = None,
    ssh_port: int = 22,
    ssh_key: Optional[str] = None,
    ssh_proxy_jump: Optional[str] = None,
    ssh_proxy_command: Optional[str] = None,
    adapter: Optional[TargetExecutionAdapter] = None,
    extra_debug_images: Optional[List[str]] = None,
    debug_dir: Optional[str] = None,
    max_discoverable_vars: int = 500,
) -> Dict[str, Any]:
    """Explores process memory mappings, threads, and discoverable variables across local or remote target."""
    target_adapter = mgr._resolve_adapter(
        pid=pid,
        remote_host=remote_host,
        ssh_user=ssh_user,
        ssh_port=ssh_port,
        ssh_key=ssh_key,
        ssh_proxy_jump=ssh_proxy_jump,
        ssh_proxy_command=ssh_proxy_command,
        adapter=adapter,
    )

    alive, live_err = target_adapter.check_liveness(pid)
    if not alive:
        raise RuntimeError(f"Target process PID {pid} is not accessible on {target_adapter.target_host()}: {live_err}")

    # 1. Parse maps and threads from adapter
    mappings = target_adapter.get_proc_maps(pid)
    threads = target_adapter.get_threads(pid)
    runtime_ident = target_adapter.get_process_identity(pid)

    primary_elf, extra_so_elfs = mgr._split_companion_elf_paths(
        companion_elf_path, extra_debug_images=extra_debug_images, debug_dir=debug_dir
    )
    companion_elf_path = primary_elf

    # 2. Inspect companion ELF (DWARF stays host-side)
    companion_identity: Optional[BinaryIdentity] = None
    if companion_elf_path:
        if not os.path.exists(companion_elf_path):
            raise FileNotFoundError(f"Companion ELF binary not found: '{companion_elf_path}'")
        try:
            companion_identity = inspect_elf(companion_elf_path)
        except Exception as e:
            raise ValueError(f"Invalid ELF image '{companion_elf_path}': {e}")

        if not companion_identity.has_debug_info:
            raise ValueError(f"Companion ELF '{companion_elf_path}' contains no DWARF debug information")

        # Validate Build ID
        if runtime_ident.get("build_id") and companion_identity.build_id:
            if runtime_ident["build_id"] != companion_identity.build_id:
                raise ValueError(
                    f"Build ID mismatch: runtime process {pid} on {target_adapter.target_host()} has build-id "
                    f"'{runtime_ident['build_id']}', but companion image '{companion_elf_path}' "
                    f"has build-id '{companion_identity.build_id}'. Mismatched symbols rejected."
                )

        # Validate Architecture
        if runtime_ident.get("architecture") and companion_identity.architecture:
            if runtime_ident["architecture"] != companion_identity.architecture and runtime_ident["architecture"] != "unknown":
                raise ValueError(
                    f"Architecture mismatch: runtime process is '{runtime_ident['architecture']}', "
                    f"companion ELF is '{companion_identity.architecture}'"
                )

    # 3. Calculate ELF load bias
    bias_info = calculate_load_bias(companion_identity, runtime_ident, mappings)
    load_bias = bias_info["load_bias"]
    is_dyn = bias_info["is_dyn"]

    # 4. Discoverable variables from companion ELF DWARF
    discoverable_variables: List[Dict[str, Any]] = []
    if companion_elf_path and os.path.exists(companion_elf_path):
        try:
            idx = DwarfIndexer.get_index(companion_elf_path)
            for var in idx.variables:
                if len(discoverable_variables) >= max_discoverable_vars:
                    break
                if var.link_time_address is not None:
                    runtime_addr = (load_bias + var.link_time_address) if is_dyn else var.link_time_address
                    t_name = idx.get_type_name(var.type_offset)
                    t_die = idx.types_by_die.get(var.type_offset)
                    size = t_die.byte_size if t_die and t_die.byte_size else 4
                    loc = f"{var.decl_file}:{var.decl_line}" if var.decl_file else None

                    # Find matching memory region
                    matching_cat = "unknown"
                    for m in mappings:
                        if m["start_int"] <= runtime_addr < m["end_int"]:
                            matching_cat = m["category"]
                            break

                    # Extract members if struct/class
                    members = []
                    if t_die and t_die.members:
                        for mem in t_die.members:
                            m_type_name = idx.get_type_name(mem.type_offset)
                            mem_addr = runtime_addr + mem.offset
                            m_die = idx.types_by_die.get(mem.type_offset)
                            m_size = mem.byte_size if mem.byte_size else (m_die.byte_size if m_die and m_die.byte_size else 4)
                            is_ptr = bool(m_type_name and ("*" in m_type_name or "pointer" in m_type_name.lower()))
                            members.append({
                                "name": mem.name,
                                "full_name": f"{var.name}.{mem.name}",
                                "offset": mem.offset,
                                "size": m_size,
                                "type_name": m_type_name or "unknown",
                                "runtime_address": f"0x{mem_addr:x}",
                                "runtime_address_int": mem_addr,
                                "is_pointer": is_ptr,
                            })

                    discoverable_variables.append({
                        "name": var.name,
                        "type_name": t_name,
                        "size": size,
                        "link_time_address": f"0x{var.link_time_address:x}",
                        "runtime_address": f"0x{runtime_addr:x}",
                        "runtime_address_int": runtime_addr,
                        "source_location": loc,
                        "memory_category": matching_cat,
                        "is_global": True,
                        "members": members,
                        "has_members": len(members) > 0,
                    })
        except Exception:
            pass

    # 5. Phase 6: Discover variables from additional shared library (.so) debug images
    loaded_debug_modules: List[Dict[str, Any]] = []
    if companion_elf_path and companion_identity:
        loaded_debug_modules.append({
            "module": os.path.basename(runtime_ident.get("executable") or companion_elf_path),
            "debug_image": os.path.abspath(companion_elf_path),
            "build_id": companion_identity.build_id,
            "load_bias": f"0x{load_bias:x}",
            "load_bias_int": load_bias,
            "is_main_executable": True,
        })

    for so_path in extra_so_elfs:
        if not os.path.isfile(so_path):
            continue
        try:
            so_ident = inspect_elf(so_path)
            if not so_ident.has_debug_info:
                continue
            resolved_so = mgr._resolve_shared_lib_load_bias(so_ident, so_path, mappings)
            if resolved_so is None:
                continue
            so_bias, so_mod_name, so_maps = resolved_so
            so_idx = DwarfIndexer.get_index(so_path)
            so_is_dyn = (so_idx.elf_type == "ET_DYN")
            loaded_debug_modules.append({
                "module": so_mod_name,
                "debug_image": os.path.abspath(so_path),
                "build_id": so_ident.build_id,
                "load_bias": f"0x{so_bias:x}",
                "load_bias_int": so_bias,
                "is_main_executable": False,
            })
            for var in so_idx.variables:
                if var.link_time_address is not None and not var.is_declaration and var.name and not var.name.startswith("__"):
                    rt_addr = (so_bias + var.link_time_address) if so_is_dyn else var.link_time_address
                    t_name = so_idx.get_type_name(var.type_offset)
                    t_die = so_idx.types_by_die.get(var.type_offset)
                    sz = t_die.byte_size if (t_die and t_die.byte_size) else 4
                    loc = f"{var.decl_file}:{var.decl_line}" if var.decl_file else None
                    members = []
                    if t_die and t_die.members:
                        for mem in t_die.members:
                            m_tname = so_idx.get_type_name(mem.type_offset)
                            m_addr = rt_addr + mem.offset
                            m_die = so_idx.types_by_die.get(mem.type_offset)
                            m_sz = mem.byte_size if mem.byte_size else (m_die.byte_size if m_die and m_die.byte_size else 4)
                            members.append({
                                "name": mem.name,
                                "full_name": f"{var.name}.{mem.name}",
                                "offset": mem.offset,
                                "size": m_sz,
                                "type_name": m_tname or "unknown",
                                "runtime_address": f"0x{m_addr:x}",
                                "runtime_address_int": m_addr,
                                "is_pointer": bool(m_tname and "*" in m_tname),
                            })
                    discoverable_variables.append({
                        "name": var.name,
                        "qualified_name": f"{so_mod_name}::{var.name}",
                        "module": so_mod_name,
                        "type_name": t_name,
                        "size": sz,
                        "link_time_address": f"0x{var.link_time_address:x}",
                        "runtime_address": f"0x{rt_addr:x}",
                        "runtime_address_int": rt_addr,
                        "source_location": loc,
                        "memory_category": "shared_library",
                        "is_global": True,
                        "members": members,
                        "has_members": len(members) > 0,
                    })
        except Exception:
            pass

    return {
        "pid": pid,
        "is_remote": target_adapter.is_remote(),
        "target_host": target_adapter.target_host(),
        "base_address": f"0x{load_bias:x}",
        "base_address_int": load_bias,
        "load_bias": f"0x{load_bias:x}",
        "load_bias_ambiguous": bias_info["is_ambiguous"],
        "load_bias_reason": bias_info.get("ambiguity_reason"),
        "loaded_debug_modules": loaded_debug_modules,
        "mappings": mappings,
        "threads": threads,
        "discoverable_variables": discoverable_variables,
    }

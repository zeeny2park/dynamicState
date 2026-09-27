"""Region selection policies for low-impact process memory capture.

Supported policies:
- STACK: Thread stacks ([stack], [stack:...])
- HEAP: Dynamic heap region ([heap])
- GLOBAL: Static and global variables (data / bss segments of main binary)
- EXECUTABLE: Text / code segments
- SHARED_LIBRARY: Shared libraries (.so)
- ALL_READABLE: All readable user-space memory mappings
- SELECTED: Explicitly designated address ranges [(start, end), ...]
"""

from typing import Any, Dict, List, Optional, Set, Tuple
from .memory_maps import MemoryRegion


POLICY_STACK = "STACK"
POLICY_HEAP = "HEAP"
POLICY_GLOBAL = "GLOBAL"
POLICY_EXECUTABLE = "EXECUTABLE"
POLICY_SHARED_LIBRARY = "SHARED_LIBRARY"
POLICY_ALL_READABLE = "ALL_READABLE"
POLICY_SELECTED = "SELECTED"

VALID_POLICIES = {
    POLICY_STACK,
    POLICY_HEAP,
    POLICY_GLOBAL,
    POLICY_EXECUTABLE,
    POLICY_SHARED_LIBRARY,
    POLICY_ALL_READABLE,
    POLICY_SELECTED,
}

DEFAULT_MAX_TOTAL_BYTES = 32 * 1024 * 1024       # 32 MB
DEFAULT_MAX_REGION_BYTES = 16 * 1024 * 1024      # 16 MB


def filter_regions(
    regions: List[MemoryRegion],
    policy: str = POLICY_ALL_READABLE,
    selected_ranges: Optional[List[Tuple[int, int]]] = None,
    max_total_bytes: Optional[int] = DEFAULT_MAX_TOTAL_BYTES,
    max_region_bytes: Optional[int] = DEFAULT_MAX_REGION_BYTES,
) -> List[MemoryRegion]:
    """Filter readable memory regions according to selection policy and safety limits."""
    pol = policy.upper()
    if pol not in VALID_POLICIES:
        raise ValueError(f"Unknown region selection policy '{policy}'. Must be one of {sorted(VALID_POLICIES)}")

    candidates: List[MemoryRegion] = []

    for r in regions:
        # Ignore unreadable regions immediately
        if not r.readable:
            continue

        # Skip kernel vsyscall / vvar which often fault on user-space process_vm_readv
        if r.category in ("vvar", "vdso") or "[vvar]" in r.pathname or "[vsyscall]" in r.pathname:
            continue

        if pol == POLICY_ALL_READABLE:
            candidates.append(r)
        elif pol == POLICY_STACK:
            if r.category == "stack" or r.pathname.startswith("[stack"):
                candidates.append(r)
        elif pol == POLICY_HEAP:
            if r.category == "heap" or r.pathname == "[heap]":
                candidates.append(r)
        elif pol == POLICY_GLOBAL:
            if r.category == "global":
                candidates.append(r)
            elif r.pathname and not r.pathname.startswith("[") and not r.executable and r.writable and r.category != "shared_library":
                candidates.append(r)
        elif pol == POLICY_EXECUTABLE:
            if r.executable:
                candidates.append(r)
        elif pol == POLICY_SHARED_LIBRARY:
            if r.category == "shared_library":
                candidates.append(r)
        elif pol == POLICY_SELECTED:
            if selected_ranges:
                for s_start, s_end in selected_ranges:
                    if max(r.start, s_start) < min(r.end, s_end):
                        candidates.append(r)
                        break

    # Apply size caps
    selected: List[MemoryRegion] = []
    total_bytes = 0

    for r in candidates:
        r_size = r.size
        if max_region_bytes and r_size > max_region_bytes:
            # Clamp region to max_region_bytes
            r_clamped = MemoryRegion(
                start=r.start,
                end=r.start + max_region_bytes,
                permissions=r.permissions,
                path=r.pathname,
                kind=r.category,
                size=max_region_bytes,
                offset=r.offset,
                device=r.device,
                inode=r.inode,
                pathname=r.pathname,
                readable=r.readable,
                writable=r.writable,
                executable=r.executable,
                category=r.category
            )
            r = r_clamped
            r_size = max_region_bytes

        if max_total_bytes and (total_bytes + r_size) > max_total_bytes:
            remaining = max_total_bytes - total_bytes
            if remaining > 0:
                r_truncated = MemoryRegion(
                    start=r.start,
                    end=r.start + remaining,
                    permissions=r.permissions,
                    path=r.pathname,
                    kind=r.category,
                    size=remaining,
                    offset=r.offset,
                    device=r.device,
                    inode=r.inode,
                    pathname=r.pathname,
                    readable=r.readable,
                    writable=r.writable,
                    executable=r.executable,
                    category=r.category
                )
                selected.append(r_truncated)
                total_bytes += remaining
            break

        selected.append(r)
        total_bytes += r_size

    return selected

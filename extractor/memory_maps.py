"""Linux process mapping reader; classifies known addresses and supports low-impact capture."""

from dataclasses import dataclass
import os
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True)
class MemoryRegion:
    start: int
    end: int
    permissions: str
    path: str = ""
    kind: str = "unknown"
    size: int = 0
    offset: int = 0
    device: str = ""
    inode: int = 0
    pathname: str = ""
    readable: bool = False
    writable: bool = False
    executable: bool = False
    category: str = "unknown"

    def __post_init__(self):
        # Synchronize backward-compatible aliases
        p_name = self.pathname or self.path
        if p_name != self.path:
            object.__setattr__(self, "path", p_name)
        if p_name != self.pathname:
            object.__setattr__(self, "pathname", p_name)

        cat = self.category if self.category != "unknown" else self.kind
        if cat != self.kind:
            object.__setattr__(self, "kind", cat)
        if cat != self.category:
            object.__setattr__(self, "category", cat)

        if self.size == 0 and self.end > self.start:
            object.__setattr__(self, "size", self.end - self.start)

        if "r" in self.permissions and not self.readable:
            object.__setattr__(self, "readable", True)
        if "w" in self.permissions and not self.writable:
            object.__setattr__(self, "writable", True)
        if "x" in self.permissions and not self.executable:
            object.__setattr__(self, "executable", True)

    def fingerprint(self) -> Tuple[int, int, str, int, str, int, str]:
        """Returns deterministic mapping identity tuple (start, end, permissions, offset, device, inode, pathname)."""
        return (
            self.start,
            self.end,
            self.permissions,
            self.offset,
            self.device,
            self.inode,
            self.pathname,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "start": "0x{:x}".format(self.start),
            "end": "0x{:x}".format(self.end),
            "start_addr": self.start,
            "end_addr": self.end,
            "size": self.size,
            "permissions": self.permissions,
            "offset": self.offset,
            "device": self.device,
            "inode": self.inode,
            "pathname": self.pathname,
            "readable": self.readable,
            "writable": self.writable,
            "executable": self.executable,
            "category": self.category,
            "kind": self.kind,
        }


def get_region_fingerprint(r: Any) -> Tuple[int, int, str, int, str, int, str]:
    """Extract deterministic mapping fingerprint from MemoryRegion or dict."""
    if isinstance(r, MemoryRegion):
        return r.fingerprint()
    if isinstance(r, dict):
        start_raw = r.get("start_addr", r.get("start", 0))
        end_raw = r.get("end_addr", r.get("end", 0))
        start_val = int(start_raw, 16) if isinstance(start_raw, str) else int(start_raw)
        end_val = int(end_raw, 16) if isinstance(end_raw, str) else int(end_raw)
        return (
            start_val,
            end_val,
            str(r.get("permissions", "")),
            int(r.get("offset", 0)),
            str(r.get("device", "")),
            int(r.get("inode", 0)),
            str(r.get("pathname", r.get("path", ""))),
        )
    return (
        getattr(r, "start", 0),
        getattr(r, "end", 0),
        getattr(r, "permissions", ""),
        getattr(r, "offset", 0),
        getattr(r, "device", ""),
        getattr(r, "inode", 0),
        getattr(r, "pathname", getattr(r, "path", "")),
    )


class MemoryMapProvider:
    def __init__(self, pid, binary=None):
        self.pid = pid
        self.binary = binary
        self._regions = None

    def get_regions(self) -> List[MemoryRegion]:
        if self._regions is not None:
            return self._regions
        regions = []
        if not self.pid:
            self._regions = regions
            return regions
        maps_path = "/proc/{}/maps".format(self.pid)
        if not os.path.exists(maps_path):
            self._regions = regions
            return regions
        try:
            with open(maps_path, encoding="utf-8") as maps:
                for line in maps:
                    try:
                        parts = line.rstrip("\n").split(None, 5)
                        if len(parts) < 5:
                            continue
                        start_text, end_text = parts[0].split("-", 1)
                        start = int(start_text, 16)
                        end = int(end_text, 16)
                        perms = parts[1]
                        try:
                            offset = int(parts[2], 16)
                        except (ValueError, TypeError):
                            offset = 0
                        device = parts[3]
                        try:
                            inode = int(parts[4])
                        except (ValueError, TypeError):
                            inode = 0
                        pathname = parts[5] if len(parts) == 6 else ""
                        category = self._kind(perms, pathname)

                        regions.append(MemoryRegion(
                            start=start,
                            end=end,
                            permissions=perms,
                            path=pathname,
                            kind=category,
                            size=end - start,
                            offset=offset,
                            device=device,
                            inode=inode,
                            pathname=pathname,
                            readable=("r" in perms),
                            writable=("w" in perms),
                            executable=("x" in perms),
                            category=category
                        ))
                    except (ValueError, IndexError):
                        continue
        except OSError:
            pass
        self._regions = regions
        return regions

    def classify(self, address) -> str:
        if address is None:
            return "unknown"
        try:
            number = int(address, 16) if isinstance(address, str) else int(address)
        except (TypeError, ValueError):
            return "unknown"
        for region in self.get_regions():
            if region.start <= number < region.end:
                return region.kind
        return "unknown"

    def _kind(self, permissions, path) -> str:
        if path == "[heap]":
            return "heap"
        if path.startswith("[stack"):
            return "stack"
        if "[vdso]" in path:
            return "vdso"
        if "[vvar]" in path:
            return "vvar"
        if permissions.endswith("s"):
            return "shared"
        # File-backed mapping of the main executable contains globals/static
        # storage. This is a mapping classification, not a lifetime claim.
        if self.binary and path and (path == self.binary or os.path.realpath(path) == os.path.realpath(self.binary)):
            if "x" not in permissions and "w" in permissions:
                return "global"
            return "global" if "x" not in permissions else "executable"
        if path.endswith(".so") or ".so." in path:
            return "shared_library"
        if "x" in permissions:
            return "executable"
        if path and not path.startswith("["):
            return "file"
        if not path or path.startswith("[anon"):
            return "anonymous"
        return "unknown"

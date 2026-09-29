"""GDB Python API compatibility layer for dynamicState.

Ensures backward compatibility with GDB 9.2+ and forward compatibility with modern GDB versions:
- GDB 9.2 compatibility: handles missing Frame.level() (introduced in GDB 11.0)
- Safe progspace attribute access
- Resilient thread status inspection
- Version detection and capability interrogation
"""

from dataclasses import dataclass
import re
from typing import Any, Iterator, Optional, Tuple


@dataclass(frozen=True)
class GdbVersion:
    major: Optional[int]
    minor: Optional[int]
    raw: str
    status: str  # "RESOLVED" or "UNKNOWN"

    def is_known(self) -> bool:
        return self.status == "RESOLVED" and self.major is not None

    def supports_frame_level(self) -> bool:
        """Frame.level() was introduced in GDB 11.0. If unknown, assume unsupported (conservative)."""
        return bool(self.is_known() and self.major is not None and self.major >= 11)

    def __iter__(self) -> Iterator[Any]:
        """Support tuple unpacking (major, minor, raw) for backward compatibility."""
        return iter((self.major, self.minor, self.raw))

    def __getitem__(self, index: int) -> Any:
        return (self.major, self.minor, self.raw)[index]


def get_gdb_version(gdb_module: Any) -> GdbVersion:
    """Parse GDB version into GdbVersion object with explicit UNKNOWN status.

    NEVER silently falls back to arbitrary versions like 9.2 when GDB or version is unknown.
    """
    if not gdb_module or not hasattr(gdb_module, "VERSION"):
        return GdbVersion(major=None, minor=None, raw="UNKNOWN", status="UNKNOWN")
    raw = str(getattr(gdb_module, "VERSION", "")).strip()
    if not raw:
        return GdbVersion(major=None, minor=None, raw="UNKNOWN", status="UNKNOWN")
    m = re.search(r"(\d+)\.(\d+)", raw)
    if m:
        return GdbVersion(major=int(m.group(1)), minor=int(m.group(2)), raw=raw, status="RESOLVED")
    return GdbVersion(major=None, minor=None, raw=raw, status="UNKNOWN")


def get_frame_level(frame: Any, fallback_level: int = 0) -> int:
    """Retrieve execution frame level compatible with GDB >= 9.2.
    
    Note: Frame.level() was introduced in GDB 11.0. In GDB 9.2 and 10.x,
    calling frame.level() raises AttributeError. This helper gracefully
    falls back to caller-tracked stack depth.
    """
    if frame is None:
        return fallback_level
    if hasattr(frame, "level") and callable(getattr(frame, "level")):
        try:
            return int(frame.level())
        except Exception:
            pass
    return fallback_level


def get_frame_function(frame: Any) -> str:
    """Safely retrieve function name from a GDB frame."""
    if frame is None:
        return "<unknown>"
    try:
        name = frame.name()
        return str(name) if name else "<unknown>"
    except Exception:
        return "<unknown>"


def get_frame_pc(frame: Any) -> Optional[int]:
    """Safely retrieve program counter address from a GDB frame."""
    if frame is None:
        return None
    try:
        return int(frame.pc())
    except Exception:
        return None


def get_progspace_filename(gdb_module: Any) -> Optional[str]:
    """Safely retrieve current progspace filename across GDB versions."""
    if not gdb_module:
        return None
    try:
        ps = gdb_module.current_progspace()
        if ps and hasattr(ps, "filename") and ps.filename:
            return str(ps.filename)
    except Exception:
        pass
    return None


def is_thread_stopped(thread: Any) -> bool:
    """Safely check if an inferior thread is stopped."""
    if thread is None:
        return False
    if hasattr(thread, "is_stopped") and callable(getattr(thread, "is_stopped")):
        try:
            return bool(thread.is_stopped())
        except Exception:
            return False
    return True

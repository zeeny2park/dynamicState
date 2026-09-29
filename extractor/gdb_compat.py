"""GDB Python API compatibility layer for dynamicState.

Ensures backward compatibility with GDB 9.2+ and forward compatibility with modern GDB versions:
- GDB 9.2 compatibility: handles missing Frame.level() (introduced in GDB 11.0)
- Safe progspace attribute access
- Resilient thread status inspection
- Version detection and capability interrogation
"""

import re
from typing import Any, Optional, Tuple


def get_gdb_version(gdb_module: Any) -> Tuple[int, int, str]:
    """Parse GDB version into (major, minor, raw_string). Defaults to (9, 2, '9.2') if unknown."""
    if not gdb_module or not hasattr(gdb_module, "VERSION"):
        return (9, 2, "9.2")
    raw = str(getattr(gdb_module, "VERSION", "9.2"))
    m = re.search(r"(\d+)\.(\d+)", raw)
    if m:
        return (int(m.group(1)), int(m.group(2)), raw)
    return (9, 2, raw)


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

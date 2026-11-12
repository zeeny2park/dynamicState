"""Zero-stop process memory primitives: process_vm_readv / /proc/<pid>/mem reads and scalar decoding.

Moved verbatim from extractor/watch_session.py (which re-exports every public name here).
"""

import ctypes
import errno
import os
import struct
import sys
from typing import Any, Dict, Optional, Tuple




ZERO_STOP_NON_ATOMIC_CONSISTENCY: Dict[str, Any] = {
    "level": "NON_ATOMIC",
    "is_consistent_snapshot": False,
    "process_stopped": False,
    "is_atomic_read": False,
    "mechanism": "ZERO_STOP_CONCURRENT_READ",
    "causal_guarantee": "NONE",
    "has_causal_guarantee": False,
    "data_completeness": "BEST_EFFORT_NON_ATOMIC",
    "warning": "Read concurrently on live running threads without process suspension. Multi-variable observations may reflect distinct execution instants and cannot establish causal sequencing.",
}


# -----------------------------------------------------------------------------
# Ctypes / Linux process_vm_readv binding
# -----------------------------------------------------------------------------

class _struct_iovec(ctypes.Structure):
    _fields_ = [
        ("iov_base", ctypes.c_void_p),
        ("iov_len", ctypes.c_size_t),
    ]


_libc = None


_has_process_vm_readv = False


if sys.platform.startswith("linux"):
    try:
        _libc = ctypes.CDLL(None, use_errno=True)
        if hasattr(_libc, "process_vm_readv"):
            fn = _libc.process_vm_readv
            fn.argtypes = [
                ctypes.c_int,
                ctypes.POINTER(_struct_iovec),
                ctypes.c_ulong,
                ctypes.POINTER(_struct_iovec),
                ctypes.c_ulong,
                ctypes.c_ulong,
            ]
            fn.restype = ctypes.c_ssize_t
            _has_process_vm_readv = True
    except Exception:
        _has_process_vm_readv = False


def read_process_memory_slice(pid: int, address: int, size: int) -> Tuple[Optional[bytes], str, Optional[str]]:
    """Safely reads arbitrary byte slice from target process memory without suspending it.

    Returns:
        (bytes, "OBSERVED", None) on success.
        (partial_bytes, "PARTIAL", msg) on partial read.
        (None, "UNAVAILABLE", reason) on unmapped memory or EFAULT.
        (None, "TARGET_TERMINATED", reason) if target process exited.
        (None, "PERMISSION_DENIED", reason) on EPERM.
    """
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 1:
        return None, "UNAVAILABLE", f"Invalid or reserved system PID: {pid} (must be integer > 1)"
    if address is None or not isinstance(address, int) or address < 0:
        return None, "UNAVAILABLE", f"Invalid memory address: {address}"
    if size <= 0:
        return b"", "OBSERVED", None
    size = min(int(size), 16 * 1024 * 1024)

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return None, "TARGET_TERMINATED", f"Target PID {pid} is no longer running"
    except PermissionError:
        return None, "PERMISSION_DENIED", f"Permission denied accessing PID {pid}"
    except Exception as e:
        return None, "UNAVAILABLE", f"Liveness check failed: {e}"

    if _has_process_vm_readv and _libc:
        buf = ctypes.create_string_buffer(size)
        local_iov = _struct_iovec(ctypes.cast(buf, ctypes.c_void_p), size)
        remote_iov = _struct_iovec(ctypes.c_void_p(address), size)
        nread = _libc.process_vm_readv(
            pid,
            ctypes.byref(local_iov),
            1,
            ctypes.byref(remote_iov),
            1,
            0,
        )
        if nread == size:
            return buf.raw, "OBSERVED", None
        elif nread > 0:
            return buf.raw[:nread], "PARTIAL", f"Partial read: {nread}/{size} bytes"
        else:
            err = ctypes.get_errno()
            if err == errno.EFAULT:
                return None, "UNAVAILABLE", f"Address 0x{address:x} is not mapped or inaccessible (EFAULT)"
            elif err == errno.ESRCH:
                return None, "TARGET_TERMINATED", f"Process {pid} exited (ESRCH)"
            # Fall through to /proc/<pid>/mem when process_vm_readv returns EPERM/ENOSYS

    # Fallback to /proc/<pid>/mem
    mem_path = f"/proc/{pid}/mem"
    try:
        with open(mem_path, "rb", buffering=0) as f:
            f.seek(address)
            data = f.read(size)
            if len(data) == size:
                return data, "OBSERVED", None
            elif len(data) > 0:
                return data, "PARTIAL", f"Partial read: {len(data)}/{size} bytes"
            else:
                return None, "UNAVAILABLE", f"No data read at 0x{address:x}"
    except OSError as e:
        if e.errno == errno.EFAULT:
            return None, "UNAVAILABLE", f"Address 0x{address:x} is not mapped or inaccessible (EFAULT)"
        elif e.errno == errno.ESRCH:
            return None, "TARGET_TERMINATED", f"Process {pid} exited (ESRCH)"
        elif e.errno in (errno.EACCES, errno.EPERM):
            return None, "PERMISSION_DENIED", f"Permission denied opening /proc/{pid}/mem"
        return None, "UNAVAILABLE", f"Failed reading /proc/{pid}/mem: {e}"


def decode_value_from_bytes(raw: bytes, type_name: str, endian: str = "little") -> Tuple[Any, Optional[str]]:
    """Decodes raw byte buffer into typed representation based on type_name."""
    endian_fmt = "<" if endian == "little" else ">"
    tn = (type_name or "").lower().strip()
    try:
        if tn in ("int", "int32", "int32_t", "signed int", "int_least32_t", "int_fast32_t"):
            if len(raw) < 4:
                return None, "Insufficient bytes for 32-bit int"
            val = struct.unpack(endian_fmt + "i", raw[:4])[0]
            return val, None
        elif tn in ("uint", "uint32", "uint32_t", "unsigned int", "uint_least32_t", "uint_fast32_t"):
            if len(raw) < 4:
                return None, "Insufficient bytes for 32-bit uint"
            val = struct.unpack(endian_fmt + "I", raw[:4])[0]
            return val, None
        elif tn in ("int64", "int64_t", "long int", "long long int", "long long", "long", "ssize_t", "int_least64_t", "int_fast64_t"):
            if len(raw) < 8:
                return None, "Insufficient bytes for 64-bit int"
            val = struct.unpack(endian_fmt + "q", raw[:8])[0]
            return val, None
        elif tn in ("uint64", "uint64_t", "long unsigned int", "long long unsigned int", "unsigned long long", "unsigned long", "size_t", "uintptr_t", "uint_least64_t", "uint_fast64_t"):
            if len(raw) < 8:
                return None, "Insufficient bytes for 64-bit uint"
            val = struct.unpack(endian_fmt + "Q", raw[:8])[0]
            return val, None
        elif tn in ("short", "int16", "int16_t"):
            if len(raw) < 2:
                return None, "Insufficient bytes for 16-bit short"
            val = struct.unpack(endian_fmt + "h", raw[:2])[0]
            return val, None
        elif tn in ("ushort", "uint16", "uint16_t", "unsigned short"):
            if len(raw) < 2:
                return None, "Insufficient bytes for 16-bit ushort"
            val = struct.unpack(endian_fmt + "H", raw[:2])[0]
            return val, None
        elif tn in ("char", "int8", "int8_t", "signed char"):
            if len(raw) < 1:
                return None, "Insufficient bytes for 8-bit char"
            val = struct.unpack(endian_fmt + "b", raw[:1])[0]
            return val, None
        elif tn in ("uchar", "uint8", "uint8_t", "unsigned char", "bool"):
            if len(raw) < 1:
                return None, "Insufficient bytes for 8-bit uchar/bool"
            val = struct.unpack(endian_fmt + "B", raw[:1])[0]
            if tn == "bool":
                return bool(val), None
            return val, None
        elif tn in ("float", "float32"):
            if len(raw) < 4:
                return None, "Insufficient bytes for float"
            val = struct.unpack(endian_fmt + "f", raw[:4])[0]
            return round(val, 6), None
        elif tn in ("double", "float64"):
            if len(raw) < 8:
                return None, "Insufficient bytes for double"
            val = struct.unpack(endian_fmt + "d", raw[:8])[0]
            return round(val, 6), None
        elif "*" in tn or tn.startswith("pointer") or tn == "ptr":
            ptr_size = 8 if len(raw) >= 8 else 4
            fmt = endian_fmt + ("Q" if ptr_size == 8 else "I")
            val = struct.unpack(fmt, raw[:ptr_size])[0]
            return f"0x{val:016x}" if ptr_size == 8 else f"0x{val:08x}", None
        elif tn in ("string", "char*"):
            null_pos = raw.find(b"\x00")
            slice_bytes = raw[:null_pos] if null_pos != -1 else raw
            return slice_bytes.decode("utf-8", errors="replace"), None
        else:
            return f"0x{raw.hex()}", None
    except Exception as exc:
        return None, f"DECODE_ERROR: {exc}"

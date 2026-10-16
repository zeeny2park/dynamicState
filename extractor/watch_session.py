"""Phase 21: Persistent Watch Session and Temporal Memory Explorer Foundation.

Enforces:
1. Versioned, validated observation schemas (ObservationSession, WatchItem, Observation, CaptureGap, AllocationEvent).
2. GNU Build ID and architecture validation between companion ELF and live target process.
3. Durable persistence to disk (survives UI refreshes and server restarts).
4. Zero-stop / non-intrusive memory sampling via process_vm_readv with fallback to /proc/<pid>/mem.
5. No synthetic data in production paths: missing samples marked explicitly as UNAVAILABLE or PARTIAL.
6. Truthful capability reporting: allocation events marked UNSUPPORTED when heap tracer is absent.
7. Replay semantics: ordered by sequence number and monotonic timestamp.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import errno
import json
import os
import struct
import sys
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import uuid

import ctypes

from .debug_image import BinaryIdentity, inspect_elf
from .dwarf_indexer import DwarfIndex, DwarfIndexer, DwarfVariable


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
    if size <= 0:
        return b"", "OBSERVED", None

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
            elif err == errno.EPERM:
                return None, "PERMISSION_DENIED", f"Permission denied reading 0x{address:x} (EPERM)"
            else:
                return None, "UNAVAILABLE", f"process_vm_readv failed with errno {err}"

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
        elif tn in ("int64", "int64_t", "long long", "long", "int_least64_t", "int_fast64_t"):
            if len(raw) < 8:
                return None, "Insufficient bytes for 64-bit int"
            val = struct.unpack(endian_fmt + "q", raw[:8])[0]
            return val, None
        elif tn in ("uint64", "uint64_t", "unsigned long long", "unsigned long", "size_t", "uintptr_t"):
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


# -----------------------------------------------------------------------------
# Versioned Data Contracts
# -----------------------------------------------------------------------------

@dataclass
class WatchItem:
    """An observable variable, object field, or validated memory address range."""
    item_id: str
    name: str
    scope: str                     # "global", "heap", "thread", "address_range", "object"
    address: int                   # runtime virtual address
    type_name: str                 # e.g. "int", "uint32_t", "pointer", "raw_bytes"
    size: int                      # bytes to read
    source_location: Optional[str] = None
    status: str = "ACTIVE"         # "ACTIVE", "OUT_OF_SCOPE", "UNRESOLVED"
    expression: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "item_id": self.item_id,
            "name": self.name,
            "scope": self.scope,
            "address": f"0x{self.address:x}",
            "address_int": self.address,
            "type_name": self.type_name,
            "size": self.size,
            "source_location": self.source_location,
            "status": self.status,
            "expression": self.expression,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "WatchItem":
        addr = d.get("address_int")
        if addr is None:
            raw_addr = d.get("address", 0)
            if isinstance(raw_addr, str) and raw_addr.startswith("0x"):
                addr = int(raw_addr, 16)
            else:
                addr = int(raw_addr)
        return cls(
            item_id=d["item_id"],
            name=d.get("name", "unnamed"),
            scope=d.get("scope", "global"),
            address=addr,
            type_name=d.get("type_name", "raw_bytes"),
            size=int(d.get("size", 4)),
            source_location=d.get("source_location"),
            status=d.get("status", "ACTIVE"),
            expression=d.get("expression"),
        )


@dataclass
class Observation:
    """Immutable state observation at a discrete point in time."""
    session_id: str
    seq: int
    monotonic_ns: int
    timestamp: str                 # ISO-8601 wall-clock
    thread_id: Optional[int] = None
    values: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    source_snapshot_id: Optional[str] = None
    completeness: str = "COMPLETE" # "COMPLETE", "PARTIAL", "FAILED"
    capture_latency_us: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "seq": self.seq,
            "monotonic_ns": self.monotonic_ns,
            "timestamp": self.timestamp,
            "thread_id": self.thread_id,
            "values": self.values,
            "source_snapshot_id": self.source_snapshot_id,
            "completeness": self.completeness,
            "capture_latency_us": self.capture_latency_us,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Observation":
        return cls(
            session_id=d["session_id"],
            seq=d["seq"],
            monotonic_ns=d["monotonic_ns"],
            timestamp=d["timestamp"],
            thread_id=d.get("thread_id"),
            values=d.get("values", {}),
            source_snapshot_id=d.get("source_snapshot_id"),
            completeness=d.get("completeness", "COMPLETE"),
            capture_latency_us=d.get("capture_latency_us"),
        )


@dataclass
class CaptureGap:
    """Discontinuity in sampling due to overrun, sleep, or permission issues."""
    gap_id: str
    start_ns: int
    end_ns: int
    duration_ms: float
    reason: str                    # "SAMPLING_OVERRUN", "PROCESS_SLEEPING", "MAPPING_CHANGED", "PERMISSION_DENIED"
    missing_seq_range: Optional[List[int]] = None
    timestamp: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "gap_id": self.gap_id,
            "start_ns": self.start_ns,
            "end_ns": self.end_ns,
            "duration_ms": self.duration_ms,
            "reason": self.reason,
            "missing_seq_range": self.missing_seq_range,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CaptureGap":
        return cls(
            gap_id=d["gap_id"],
            start_ns=d["start_ns"],
            end_ns=d["end_ns"],
            duration_ms=d["duration_ms"],
            reason=d["reason"],
            missing_seq_range=d.get("missing_seq_range"),
            timestamp=d.get("timestamp", ""),
        )


@dataclass
class AllocationEvent:
    """Heap allocation/free event schema for future allocator recorder integration."""
    seq: int
    timestamp: str
    thread_id: int
    operation: str                 # "ALLOC", "FREE", "REALLOC"
    address: int
    size: int
    allocation_generation: Optional[int] = None
    caller_pc: Optional[int] = None
    result: str = "RECORDED"
    provenance: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "thread_id": self.thread_id,
            "operation": self.operation,
            "address": f"0x{self.address:x}",
            "address_int": self.address,
            "size": self.size,
            "allocation_generation": self.allocation_generation,
            "caller_pc": f"0x{self.caller_pc:x}" if self.caller_pc else None,
            "result": self.result,
            "provenance": self.provenance,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "AllocationEvent":
        addr = d.get("address_int")
        if addr is None:
            raw_addr = d.get("address", 0)
            addr = int(raw_addr, 16) if isinstance(raw_addr, str) and raw_addr.startswith("0x") else int(raw_addr)
        caller_pc = None
        if d.get("caller_pc"):
            raw_pc = d["caller_pc"]
            caller_pc = int(raw_pc, 16) if isinstance(raw_pc, str) and raw_pc.startswith("0x") else int(raw_pc)
        return cls(
            seq=d["seq"],
            timestamp=d["timestamp"],
            thread_id=d["thread_id"],
            operation=d["operation"],
            address=addr,
            size=d["size"],
            allocation_generation=d.get("allocation_generation"),
            caller_pc=caller_pc,
            result=d.get("result", "RECORDED"),
            provenance=d.get("provenance", {}),
        )


@dataclass
class ObservationSession:
    """Persistent observation session holding metadata, watch items, and recorded observations."""
    session_id: str
    schema_version: str = "1.0.0"
    pid: int = 0
    target_identity: Dict[str, Any] = field(default_factory=dict)
    binary_build_id: Optional[str] = None
    companion_elf_path: Optional[str] = None
    start_time: str = ""
    end_time: Optional[str] = None
    status: str = "RUNNING"        # "RUNNING", "PAUSED", "STOPPED", "FAILED"
    capture_mode: str = "ZERO_STOP"
    configuration: Dict[str, Any] = field(default_factory=dict)
    provenance: Dict[str, Any] = field(default_factory=dict)
    watch_items: List[WatchItem] = field(default_factory=list)
    observations: List[Observation] = field(default_factory=list)
    gaps: List[CaptureGap] = field(default_factory=list)
    allocation_events: List[AllocationEvent] = field(default_factory=list)
    capabilities: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "schema_version": self.schema_version,
            "pid": self.pid,
            "target_identity": self.target_identity,
            "binary_build_id": self.binary_build_id,
            "companion_elf_path": self.companion_elf_path,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "status": self.status,
            "capture_mode": self.capture_mode,
            "configuration": self.configuration,
            "provenance": self.provenance,
            "watch_items": [w.to_dict() for w in self.watch_items],
            "observations": [o.to_dict() for o in self.observations],
            "gaps": [g.to_dict() for g in self.gaps],
            "allocation_events": [a.to_dict() for a in self.allocation_events],
            "capabilities": self.capabilities,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ObservationSession":
        return cls(
            session_id=d["session_id"],
            schema_version=d.get("schema_version", "1.0.0"),
            pid=d.get("pid", 0),
            target_identity=d.get("target_identity", {}),
            binary_build_id=d.get("binary_build_id"),
            companion_elf_path=d.get("companion_elf_path"),
            start_time=d.get("start_time", ""),
            end_time=d.get("end_time"),
            status=d.get("status", "STOPPED"),
            capture_mode=d.get("capture_mode", "ZERO_STOP"),
            configuration=d.get("configuration", {}),
            provenance=d.get("provenance", {}),
            watch_items=[WatchItem.from_dict(w) for w in d.get("watch_items", [])],
            observations=[Observation.from_dict(o) for o in d.get("observations", [])],
            gaps=[CaptureGap.from_dict(g) for g in d.get("gaps", [])],
            allocation_events=[AllocationEvent.from_dict(a) for a in d.get("allocation_events", [])],
            capabilities=d.get("capabilities", {}),
        )


# -----------------------------------------------------------------------------
# Watch Session Manager
# -----------------------------------------------------------------------------

class WatchSessionManager:
    """Manages persistent watch session lifecycle, periodic zero-stop capture, and storage."""

    def __init__(self, corpus_dir: str):
        self.corpus_dir = os.path.abspath(corpus_dir)
        self.sessions_dir = os.path.join(self.corpus_dir, "watch_sessions")
        os.makedirs(self.sessions_dir, exist_ok=True)

        self._lock = threading.RLock()
        self._sessions: Dict[str, ObservationSession] = {}
        self._threads: Dict[str, threading.Thread] = {}
        self._stop_events: Dict[str, threading.Event] = {}

    def _get_session_file(self, session_id: str) -> str:
        return os.path.join(self.sessions_dir, f"{session_id}.json")

    def _persist_session(self, session: ObservationSession) -> None:
        """Atomically persists session to disk."""
        target_path = self._get_session_file(session.session_id)
        tmp_fd, tmp_path = tempfile.mkstemp(dir=self.sessions_dir, prefix="sess_", suffix=".tmp")
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                json.dump(session.to_dict(), f, indent=2, ensure_ascii=False)
            os.replace(tmp_path, target_path)
        except Exception:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

    def get_memory_map_and_threads(self, pid: int, companion_elf_path: Optional[str] = None) -> Dict[str, Any]:
        """Explores process memory mappings, threads, and discoverable variables."""
        try:
            os.kill(pid, 0)
        except Exception as e:
            raise RuntimeError(f"Target process PID {pid} is not accessible: {e}")

        # 1. Parse /proc/<pid>/maps
        mappings: List[Dict[str, Any]] = []
        maps_path = f"/proc/{pid}/maps"
        base_address = 0
        exe_real = ""
        try:
            exe_real = os.path.realpath(f"/proc/{pid}/exe")
        except Exception:
            pass

        if os.path.exists(maps_path):
            with open(maps_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    parts = line.strip().split(maxsplit=5)
                    if len(parts) >= 5:
                        addr_range = parts[0]
                        perms = parts[1]
                        offset = parts[2]
                        pathname = parts[5] if len(parts) >= 6 else ""

                        start_hex, end_hex = addr_range.split("-")
                        s_int = int(start_hex, 16)
                        e_int = int(end_hex, 16)

                        category = "anonymous"
                        if pathname == "[heap]":
                            category = "heap"
                        elif pathname.startswith("[stack"):
                            category = "stack"
                        elif pathname:
                            if "x" in perms:
                                category = "code"
                            elif "w" in perms:
                                category = "data"
                            else:
                                category = "file"

                        # Determine base address for main executable
                        if exe_real and pathname == exe_real and base_address == 0:
                            base_address = s_int

                        mappings.append({
                            "start": f"0x{s_int:x}",
                            "end": f"0x{e_int:x}",
                            "start_int": s_int,
                            "end_int": e_int,
                            "size": e_int - s_int,
                            "permissions": perms,
                            "offset": offset,
                            "category": category,
                            "pathname": pathname,
                            "is_readable": "r" in perms,
                            "is_writable": "w" in perms,
                            "is_executable": "x" in perms,
                        })

        # 2. Parse /proc/<pid>/task
        threads: List[Dict[str, Any]] = []
        task_dir = f"/proc/{pid}/task"
        if os.path.exists(task_dir):
            try:
                for tid_entry in os.listdir(task_dir):
                    if tid_entry.isdigit():
                        tid = int(tid_entry)
                        comm = "unknown"
                        state = "UNKNOWN"
                        comm_file = os.path.join(task_dir, tid_entry, "comm")
                        if os.path.exists(comm_file):
                            try:
                                with open(comm_file, "r") as cf:
                                    comm = cf.read().strip()
                            except Exception:
                                pass
                        stat_file = os.path.join(task_dir, tid_entry, "stat")
                        if os.path.exists(stat_file):
                            try:
                                with open(stat_file, "r") as sf:
                                    tokens = sf.read().strip().split()
                                    if len(tokens) >= 3:
                                        state = tokens[2]
                            except Exception:
                                pass
                        threads.append({
                            "tid": tid,
                            "name": comm,
                            "state": state,
                        })
            except Exception:
                pass
        threads.sort(key=lambda t: t["tid"])

        # 3. Discoverable variables from companion ELF DWARF
        discoverable_variables: List[Dict[str, Any]] = []
        if companion_elf_path and os.path.exists(companion_elf_path):
            try:
                elf_ident = inspect_elf(companion_elf_path)
                is_dyn = (elf_ident.elf_type == "ET_DYN")
                idx = DwarfIndexer.get_index(companion_elf_path)
                for var in idx.variables:
                    if var.link_time_address is not None:
                        runtime_addr = (base_address + var.link_time_address) if is_dyn else var.link_time_address
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
                        })
            except Exception as e:
                pass

        return {
            "pid": pid,
            "base_address": f"0x{base_address:x}",
            "base_address_int": base_address,
            "mappings": mappings,
            "threads": threads,
            "discoverable_variables": discoverable_variables,
        }

    def create_session(
        self,
        pid: int,
        companion_elf_path: Optional[str] = None,
        interval_ms: int = 500,
        max_samples: int = 1000,
        initial_watch_items: Optional[List[Dict[str, Any]]] = None,
        capture_mode: str = "ZERO_STOP",
    ) -> ObservationSession:
        """Validates target and companion ELF, creates a durable session, and begins periodic capture."""
        with self._lock:
            # 1. Target process liveness check
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                raise ValueError(f"Target PID {pid} was not found (ESRCH)")
            except PermissionError:
                raise PermissionError(f"Permission denied accessing target PID {pid} (EPERM)")

            # 2. Inspect runtime executable
            runtime_exe = ""
            try:
                runtime_exe = os.path.realpath(f"/proc/{pid}/exe")
            except Exception:
                pass

            runtime_identity: Optional[BinaryIdentity] = None
            if runtime_exe and os.path.exists(runtime_exe):
                try:
                    runtime_identity = inspect_elf(runtime_exe)
                except Exception:
                    pass

            # 3. Validate companion ELF if supplied
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

                # Verify GNU Build ID compatibility
                if runtime_identity and runtime_identity.build_id and companion_identity.build_id:
                    if runtime_identity.build_id != companion_identity.build_id:
                        raise ValueError(
                            f"Build ID mismatch: runtime process {pid} build-id is "
                            f"'{runtime_identity.build_id}', but companion image '{companion_elf_path}' "
                            f"has build-id '{companion_identity.build_id}'. Mismatched symbols rejected."
                        )

                # Verify Architecture compatibility
                if runtime_identity and runtime_identity.architecture and companion_identity.architecture:
                    if runtime_identity.architecture != companion_identity.architecture:
                        raise ValueError(
                            f"Architecture mismatch: runtime process is '{runtime_identity.architecture}', "
                            f"companion ELF is '{companion_identity.architecture}'"
                        )

            # 4. Resolve base address for PIE/DYN binaries
            map_data = self.get_memory_map_and_threads(pid, companion_elf_path)
            base_address = map_data.get("base_address_int", 0)
            is_dyn = False
            if companion_identity and companion_identity.elf_type == "ET_DYN":
                is_dyn = True
            elif runtime_identity and runtime_identity.elf_type == "ET_DYN":
                is_dyn = True

            # 5. Process watch items
            watch_items: List[WatchItem] = []
            if initial_watch_items:
                for idx, item_data in enumerate(initial_watch_items):
                    raw_addr = item_data.get("address") or item_data.get("runtime_address") or item_data.get("link_time_address", 0)
                    addr_int = int(raw_addr, 16) if isinstance(raw_addr, str) and raw_addr.startswith("0x") else int(raw_addr)

                    # Relocate link-time address to runtime address if needed
                    if is_dyn and item_data.get("is_link_time") and base_address > 0:
                        addr_int = base_address + addr_int

                    # Validate address against memory map
                    readable = any(
                        m["start_int"] <= addr_int < m["end_int"] and m["is_readable"]
                        for m in map_data["mappings"]
                    )
                    status = "ACTIVE" if readable else "OUT_OF_SCOPE"

                    item_id = item_data.get("item_id") or f"watch_{item_data.get('name', 'var')}_{idx}"
                    watch_items.append(WatchItem(
                        item_id=item_id,
                        name=item_data.get("name", f"var_{idx}"),
                        scope=item_data.get("scope", "global"),
                        address=addr_int,
                        type_name=item_data.get("type_name", "raw_bytes"),
                        size=int(item_data.get("size", 4)),
                        source_location=item_data.get("source_location"),
                        status=status,
                        expression=item_data.get("expression"),
                    ))

            # 6. Construct ObservationSession
            session_id = f"watch_{pid}_{int(time.time())}_{uuid.uuid4().hex[:6]}"
            target_ident = {
                "pid": pid,
                "executable": runtime_exe,
                "architecture": runtime_identity.architecture if runtime_identity else "unknown",
                "elf_type": runtime_identity.elf_type if runtime_identity else "unknown",
            }
            capabilities = {
                "capture_backend": "process_vm_readv",
                "zero_stop_supported": True,
                "allocation_tracking": {
                    "supported": False,
                    "status": "UNSUPPORTED_ON_BACKEND",
                    "reason": "Heap allocation/free event recording requires an active heap hook (LD_PRELOAD / eBPF uretprobe). ProcessVmCaptureBackend does not trace allocations.",
                },
            }

            session = ObservationSession(
                session_id=session_id,
                schema_version="1.0.0",
                pid=pid,
                target_identity=target_ident,
                binary_build_id=runtime_identity.build_id if runtime_identity else (companion_identity.build_id if companion_identity else None),
                companion_elf_path=companion_elf_path,
                start_time=datetime.now(timezone.utc).isoformat(),
                status="RUNNING",
                capture_mode=capture_mode,
                configuration={
                    "interval_ms": max(50, min(interval_ms, 60000)),
                    "max_samples": max(1, min(max_samples, 50000)),
                    "base_address": f"0x{base_address:x}",
                },
                provenance={
                    "transport": "local",
                    "backend": "process_vm_readv",
                    "host": os.uname().nodename,
                },
                watch_items=watch_items,
                observations=[],
                gaps=[],
                allocation_events=[],
                capabilities=capabilities,
            )

            self._persist_session(session)
            self._sessions[session_id] = session

            # 7. Start background capture thread
            stop_evt = threading.Event()
            self._stop_events[session_id] = stop_evt
            th = threading.Thread(
                target=self._capture_worker,
                args=(session_id, stop_evt),
                name=f"WatchSessionWorker-{session_id}",
                daemon=True,
            )
            self._threads[session_id] = th
            th.start()

            return session

    def get_session(self, session_id: str) -> Optional[ObservationSession]:
        """Retrieves session from cache or loads durable copy from disk."""
        with self._lock:
            if session_id in self._sessions:
                return self._sessions[session_id]

            # Try loading from disk
            sess_path = self._get_session_file(session_id)
            if os.path.exists(sess_path):
                try:
                    with open(sess_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    session = ObservationSession.from_dict(data)
                    # If loaded from disk and marked RUNNING without an active worker, mark STOPPED
                    if session.status == "RUNNING" and session_id not in self._threads:
                        session.status = "STOPPED"
                        session.end_time = session.end_time or datetime.now(timezone.utc).isoformat()
                        self._persist_session(session)
                    self._sessions[session_id] = session
                    return session
                except Exception:
                    return None
            return None

    def stop_session(self, session_id: str) -> Optional[ObservationSession]:
        """Stops an active watch session and flushes state."""
        with self._lock:
            session = self.get_session(session_id)
            if not session:
                return None

            evt = self._stop_events.get(session_id)
            if evt:
                evt.set()

            th = self._threads.get(session_id)
            if th and th.is_alive() and th != threading.current_thread():
                th.join(timeout=1.0)

            session.status = "STOPPED"
            session.end_time = datetime.now(timezone.utc).isoformat()
            self._persist_session(session)
            return session

    def add_watch_item(self, session_id: str, item_dict: Dict[str, Any]) -> WatchItem:
        """Adds a new watch item to an existing session."""
        with self._lock:
            session = self.get_session(session_id)
            if not session:
                raise ValueError(f"Session '{session_id}' not found")

            raw_addr = item_dict.get("address") or item_dict.get("runtime_address", 0)
            addr_int = int(raw_addr, 16) if isinstance(raw_addr, str) and raw_addr.startswith("0x") else int(raw_addr)
            size = int(item_dict.get("size", 4))
            if size <= 0 or size > 65536:
                raise ValueError(f"Invalid size {size}: must be between 1 and 65536 bytes")

            # Validate against current mappings
            map_data = self.get_memory_map_and_threads(session.pid, session.companion_elf_path)
            readable = any(
                m["start_int"] <= addr_int < m["end_int"] and m["is_readable"]
                for m in map_data["mappings"]
            )
            status = "ACTIVE" if readable else "OUT_OF_SCOPE"

            name = item_dict.get("name") or f"addr_0x{addr_int:x}"
            item_id = item_dict.get("item_id") or f"watch_{name}_{uuid.uuid4().hex[:4]}"

            # Check for existing item with same item_id
            for idx, existing in enumerate(session.watch_items):
                if existing.item_id == item_id:
                    session.watch_items[idx] = WatchItem(
                        item_id=item_id,
                        name=name,
                        scope=item_dict.get("scope", existing.scope),
                        address=addr_int,
                        type_name=item_dict.get("type_name", existing.type_name),
                        size=size,
                        source_location=item_dict.get("source_location", existing.source_location),
                        status=status,
                        expression=item_dict.get("expression", existing.expression),
                    )
                    self._persist_session(session)
                    return session.watch_items[idx]

            item = WatchItem(
                item_id=item_id,
                name=name,
                scope=item_dict.get("scope", "global"),
                address=addr_int,
                type_name=item_dict.get("type_name", "raw_bytes"),
                size=size,
                source_location=item_dict.get("source_location"),
                status=status,
                expression=item_dict.get("expression"),
            )
            session.watch_items.append(item)
            self._persist_session(session)
            return item

    def remove_watch_item(self, session_id: str, item_id: str) -> bool:
        """Removes a watch item from session without deleting recorded observation history."""
        with self._lock:
            session = self.get_session(session_id)
            if not session:
                return False

            orig_len = len(session.watch_items)
            session.watch_items = [w for w in session.watch_items if w.item_id != item_id]
            if len(session.watch_items) != orig_len:
                self._persist_session(session)
                return True
            return False

    def get_observations(
        self,
        session_id: str,
        start_seq: Optional[int] = None,
        end_seq: Optional[int] = None,
        limit: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Returns ordered observations and gaps with pagination/filtering."""
        with self._lock:
            session = self.get_session(session_id)
            if not session:
                raise ValueError(f"Session '{session_id}' not found")

            obs = session.observations
            if start_seq is not None:
                obs = [o for o in obs if o.seq >= start_seq]
            if end_seq is not None:
                obs = [o for o in obs if o.seq <= end_seq]
            if limit is not None and limit > 0:
                obs = obs[-limit:]

            return {
                "session_id": session.session_id,
                "status": session.status,
                "total_observations": len(session.observations),
                "returned_count": len(obs),
                "observations": [o.to_dict() for o in obs],
                "gaps": [g.to_dict() for g in session.gaps],
                "watch_items": [w.to_dict() for w in session.watch_items],
            }

    def _capture_worker(self, session_id: str, stop_evt: threading.Event) -> None:
        """Periodic background sampling loop."""
        session = self.get_session(session_id)
        if not session:
            return

        interval_s = float(session.configuration.get("interval_ms", 500)) / 1000.0
        max_samples = int(session.configuration.get("max_samples", 1000))
        last_tick_end_ns = time.monotonic_ns()

        while not stop_evt.is_set():
            t_start_ns = time.monotonic_ns()

            # Liveness check
            try:
                os.kill(session.pid, 0)
            except (ProcessLookupError, PermissionError):
                with self._lock:
                    session.status = "STOPPED"
                    session.end_time = datetime.now(timezone.utc).isoformat()
                    self._persist_session(session)
                break

            # Gap detection: if elapsed time > 1.8x expected interval, record gap
            elapsed_since_last_ms = (t_start_ns - last_tick_end_ns) / 1_000_000.0
            if len(session.observations) > 0 and elapsed_since_last_ms > (interval_s * 1000.0 * 1.8):
                gap = CaptureGap(
                    gap_id=f"gap_{uuid.uuid4().hex[:6]}",
                    start_ns=last_tick_end_ns,
                    end_ns=t_start_ns,
                    duration_ms=round(elapsed_since_last_ms - (interval_s * 1000.0), 2),
                    reason="SAMPLING_OVERRUN",
                    timestamp=datetime.now(timezone.utc).isoformat(),
                )
                session.gaps.append(gap)

            # Sample each watch item
            seq = len(session.observations) + 1
            wall_clock = datetime.now(timezone.utc).isoformat()
            values: Dict[str, Dict[str, Any]] = {}
            obs_completeness = "COMPLETE"

            for item in list(session.watch_items):
                raw_bytes, read_st, read_err = read_process_memory_slice(session.pid, item.address, item.size)
                if read_st == "OBSERVED" and raw_bytes is not None:
                    decoded_val, dec_err = decode_value_from_bytes(raw_bytes, item.type_name)
                    st = "OBSERVED" if dec_err is None else "DECODE_ERROR"
                    values[item.item_id] = {
                        "value": decoded_val,
                        "raw_hex": raw_bytes.hex(),
                        "status": st,
                        "error": dec_err,
                    }
                elif read_st == "PARTIAL":
                    obs_completeness = "PARTIAL"
                    values[item.item_id] = {
                        "value": None,
                        "raw_hex": raw_bytes.hex() if raw_bytes else "",
                        "status": "PARTIAL",
                        "error": read_err or "Partial memory read",
                    }
                else:
                    obs_completeness = "PARTIAL"
                    values[item.item_id] = {
                        "value": None,
                        "raw_hex": "",
                        "status": "UNAVAILABLE",
                        "error": read_err or "Memory read failed or unmapped",
                    }

            t_end_ns = time.monotonic_ns()
            latency_us = round((t_end_ns - t_start_ns) / 1000.0, 2)
            last_tick_end_ns = t_end_ns

            observation = Observation(
                session_id=session.session_id,
                seq=seq,
                monotonic_ns=t_start_ns,
                timestamp=wall_clock,
                values=values,
                completeness=obs_completeness,
                capture_latency_us=latency_us,
            )

            with self._lock:
                session.observations.append(observation)
                # Persist to disk periodically (every sample or when stopping)
                self._persist_session(session)

                if len(session.observations) >= max_samples:
                    session.status = "STOPPED"
                    session.end_time = datetime.now(timezone.utc).isoformat()
                    self._persist_session(session)
                    break

            # Sleep remainder of interval
            spent_s = (time.monotonic_ns() - t_start_ns) / 1_000_000_000.0
            sleep_s = max(0.01, interval_s - spent_s)
            stop_evt.wait(timeout=sleep_s)

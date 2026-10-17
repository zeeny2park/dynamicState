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
from .target_adapter import TargetExecutionAdapter, LocalTargetAdapter, RemoteSshTargetAdapter


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
    source: str = "custom_range"   # "global_variable", "memory_map", "thread_stack", "custom_range", "object_field"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "item_id": self.item_id,
            "name": self.name,
            "scope": self.scope,
            "source": self.source,
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
            source=d.get("source", "custom_range"),
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
    zero_stop: bool = True

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
            "zero_stop": self.zero_stop,
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
            zero_stop=d.get("zero_stop", True),
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
    schema_version: str = "1.1.0"
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
    total_observations: int = 0

    def to_dict(self, include_observations: bool = True) -> Dict[str, Any]:
        d = {
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
            "gaps": [g.to_dict() for g in self.gaps],
            "allocation_events": [a.to_dict() for a in self.allocation_events],
            "capabilities": self.capabilities,
            "total_observations": self.total_observations or len(self.observations),
        }
        if include_observations:
            d["observations"] = [o.to_dict() for o in self.observations]
        return d

    def to_summary_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "pid": self.pid,
            "status": self.status,
            "is_remote": self.provenance.get("is_remote", False),
            "target_host": self.provenance.get("host", "localhost"),
            "binary_build_id": self.binary_build_id,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "total_observations": self.total_observations or len(self.observations),
            "watch_items_count": len(self.watch_items),
            "gaps_count": len(self.gaps),
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ObservationSession":
        obs_list = [Observation.from_dict(o) for o in d.get("observations", [])]
        tot = d.get("total_observations")
        if tot is None:
            tot = len(obs_list)
        return cls(
            session_id=d["session_id"],
            schema_version=d.get("schema_version", "1.1.0"),
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
            observations=obs_list,
            gaps=[CaptureGap.from_dict(g) for g in d.get("gaps", [])],
            allocation_events=[AllocationEvent.from_dict(a) for a in d.get("allocation_events", [])],
            capabilities=d.get("capabilities", {}),
            total_observations=tot,
        )


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

    candidates = [m for m in mappings if m.get("offset_int", 0) == seg0_off_page]
    if not candidates:
        candidates = [m for m in mappings if m.get("offset_int", 0) == 0]
    if not candidates:
        candidates = mappings[:1]

    if not candidates:
        return {
            "load_bias": 0,
            "load_bias_hex": "0x0",
            "is_dyn": True,
            "is_ambiguous": True,
            "ambiguity_reason": "No memory mappings available to determine load bias",
            "verified_segments": 0,
        }

    best = next((c for c in candidates if c.get("is_executable") or c.get("category") == "code"), candidates[0])
    seg0_vaddr_page = seg0.get("p_vaddr", 0) - (seg0.get("p_vaddr", 0) % page_size)
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
        self._adapters: Dict[str, TargetExecutionAdapter] = {}

    def _get_session_dir(self, session_id: str) -> str:
        d = os.path.join(self.sessions_dir, session_id)
        os.makedirs(d, exist_ok=True)
        return d

    def _get_session_file(self, session_id: str) -> str:
        # Primary session file in directory
        return os.path.join(self._get_session_dir(session_id), "session.json")

    def _get_observations_file(self, session_id: str) -> str:
        return os.path.join(self._get_session_dir(session_id), "observations.jsonl")

    def _persist_session(self, session: ObservationSession) -> None:
        """Atomically persists session metadata and watch configuration to disk."""
        target_path = self._get_session_file(session.session_id)
        parent_dir = os.path.dirname(target_path)
        tmp_fd, tmp_path = tempfile.mkstemp(dir=parent_dir, prefix="sess_", suffix=".tmp")
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                json.dump(session.to_dict(include_observations=False), f, indent=2, ensure_ascii=False)
            os.replace(tmp_path, target_path)
        except Exception:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise

        # Also maintain legacy file format for full backward compatibility if it exists
        legacy_path = os.path.join(self.sessions_dir, f"{session.session_id}.json")
        if os.path.exists(legacy_path):
            try:
                tmp_fd2, tmp_path2 = tempfile.mkstemp(dir=self.sessions_dir, prefix="legacy_", suffix=".tmp")
                with os.fdopen(tmp_fd2, "w", encoding="utf-8") as f2:
                    json.dump(session.to_dict(include_observations=True), f2, indent=2, ensure_ascii=False)
                os.replace(tmp_path2, legacy_path)
            except Exception:
                if os.path.exists(tmp_path2):
                    os.remove(tmp_path2)

    def _append_observation_to_file(self, session_id: str, observation: Observation) -> None:
        """Appends a single observation to the durable JSONL log."""
        jsonl_path = self._get_observations_file(session_id)
        line = json.dumps(observation.to_dict(), ensure_ascii=False) + "\n"
        with open(jsonl_path, "a", encoding="utf-8") as f:
            f.write(line)
            f.flush()

    def _resolve_adapter(
        self,
        pid: int,
        remote_host: Optional[str] = None,
        ssh_user: Optional[str] = None,
        ssh_port: int = 22,
        ssh_key: Optional[str] = None,
        ssh_proxy_jump: Optional[str] = None,
        ssh_proxy_command: Optional[str] = None,
        adapter: Optional[TargetExecutionAdapter] = None,
    ) -> TargetExecutionAdapter:
        if adapter is not None:
            return adapter
        if remote_host:
            return RemoteSshTargetAdapter(
                host=remote_host,
                user=ssh_user,
                port=ssh_port,
                key_file=ssh_key,
                proxy_jump=ssh_proxy_jump,
                proxy_command=ssh_proxy_command,
            )
        return LocalTargetAdapter()

    def get_memory_map_and_threads(
        self,
        pid: int,
        companion_elf_path: Optional[str] = None,
        remote_host: Optional[str] = None,
        ssh_user: Optional[str] = None,
        ssh_port: int = 22,
        ssh_key: Optional[str] = None,
        ssh_proxy_jump: Optional[str] = None,
        ssh_proxy_command: Optional[str] = None,
        adapter: Optional[TargetExecutionAdapter] = None,
    ) -> Dict[str, Any]:
        """Explores process memory mappings, threads, and discoverable variables across local or remote target."""
        target_adapter = self._resolve_adapter(
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

        return {
            "pid": pid,
            "is_remote": target_adapter.is_remote(),
            "target_host": target_adapter.target_host(),
            "base_address": f"0x{load_bias:x}",
            "base_address_int": load_bias,
            "load_bias": f"0x{load_bias:x}",
            "load_bias_ambiguous": bias_info["is_ambiguous"],
            "load_bias_reason": bias_info.get("ambiguity_reason"),
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
        remote_host: Optional[str] = None,
        ssh_user: Optional[str] = None,
        ssh_port: int = 22,
        ssh_key: Optional[str] = None,
        ssh_proxy_jump: Optional[str] = None,
        ssh_proxy_command: Optional[str] = None,
        adapter: Optional[TargetExecutionAdapter] = None,
        max_storage_bytes: int = 52428800,
        max_duration_sec: int = 3600,
    ) -> ObservationSession:
        """Validates target and companion ELF, creates a durable session, and begins periodic capture."""
        with self._lock:
            target_adapter = self._resolve_adapter(
                pid=pid,
                remote_host=remote_host,
                ssh_user=ssh_user,
                ssh_port=ssh_port,
                ssh_key=ssh_key,
                ssh_proxy_jump=ssh_proxy_jump,
                ssh_proxy_command=ssh_proxy_command,
                adapter=adapter,
            )

            # 1. Target process liveness check
            alive, live_err = target_adapter.check_liveness(pid)
            if not alive:
                err_msg = live_err or f"Target PID {pid} was not found"
                if "Permission" in err_msg or "EPERM" in err_msg:
                    raise PermissionError(err_msg)
                raise ValueError(err_msg)

            # 2. Inspect runtime executable
            runtime_ident = target_adapter.get_process_identity(pid)

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
                if runtime_ident.get("build_id") and companion_identity.build_id:
                    if runtime_ident["build_id"] != companion_identity.build_id:
                        raise ValueError(
                            f"Build ID mismatch: runtime process {pid} build-id is "
                            f"'{runtime_ident['build_id']}', but companion image '{companion_elf_path}' "
                            f"has build-id '{companion_identity.build_id}'. Mismatched symbols rejected."
                        )

                # Verify Architecture compatibility
                if runtime_ident.get("architecture") and companion_identity.architecture:
                    if runtime_ident["architecture"] != companion_identity.architecture and runtime_ident["architecture"] != "unknown":
                        raise ValueError(
                            f"Architecture mismatch: runtime process is '{runtime_ident['architecture']}', "
                            f"companion ELF is '{companion_identity.architecture}'"
                        )

            # 4. Resolve memory map and load bias
            map_data = self.get_memory_map_and_threads(
                pid=pid,
                companion_elf_path=companion_elf_path,
                adapter=target_adapter,
            )
            base_address = map_data.get("base_address_int", 0)
            is_dyn = (companion_identity and companion_identity.elf_type == "ET_DYN") or (runtime_ident.get("elf_type") == "ET_DYN")

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
                "executable": runtime_ident.get("executable", ""),
                "architecture": runtime_ident.get("architecture", "unknown"),
                "elf_type": runtime_ident.get("elf_type", "unknown"),
            }
            backend_name = "remote_proc_mem" if target_adapter.is_remote() else "process_vm_readv"
            transport_name = "ssh_proxy" if target_adapter.is_remote() else "local"

            capabilities = {
                "capture_backend": backend_name,
                "zero_stop_supported": True,
                "is_remote": target_adapter.is_remote(),
                "allocation_tracking": {
                    "supported": False,
                    "status": "UNSUPPORTED_ON_BACKEND",
                    "reason": "Heap allocation/free event recording requires an active heap hook (LD_PRELOAD / eBPF uretprobe). Neither ProcessVmCaptureBackend nor RemoteSshAdapter traces allocations without a tracer.",
                },
            }

            is_manual = (capture_mode == "MANUAL" or interval_ms <= 0)
            status = "STOPPED" if is_manual else "RUNNING"
            session = ObservationSession(
                session_id=session_id,
                schema_version="1.1.0",
                pid=pid,
                target_identity=target_ident,
                binary_build_id=runtime_ident.get("build_id") or (companion_identity.build_id if companion_identity else None),
                companion_elf_path=companion_elf_path,
                start_time=datetime.now(timezone.utc).isoformat(),
                status=status,
                capture_mode=capture_mode,
                configuration={
                    "interval_ms": 0 if is_manual else max(50, min(interval_ms, 60000)),
                    "max_samples": max(1, min(max_samples, 50000)),
                    "max_storage_bytes": max_storage_bytes,
                    "max_duration_sec": max_duration_sec,
                    "base_address": f"0x{base_address:x}",
                    "load_bias": f"0x{base_address:x}",
                    "load_bias_ambiguous": map_data.get("load_bias_ambiguous", False),
                },
                provenance={
                    "transport": transport_name,
                    "backend": backend_name,
                    "host": target_adapter.target_host(),
                    "is_remote": target_adapter.is_remote(),
                    "remote_pid": pid if target_adapter.is_remote() else None,
                },
                watch_items=watch_items,
                observations=[],
                gaps=[],
                allocation_events=[],
                capabilities=capabilities,
                total_observations=0,
            )

            self._persist_session(session)
            self._sessions[session_id] = session
            self._adapters[session_id] = target_adapter

            # 7. Start background capture thread only if periodic capture requested
            if status == "RUNNING":
                stop_evt = threading.Event()
                self._stop_events[session_id] = stop_evt
                th = threading.Thread(
                    target=self._capture_worker,
                    args=(session_id, stop_evt, target_adapter),
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

            # 1. Try loading from directory structure: corpus/watch_sessions/{session_id}/session.json
            dir_sess_path = self._get_session_file(session_id)
            data = None
            if os.path.exists(dir_sess_path):
                try:
                    with open(dir_sess_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                except Exception:
                    data = None

            # 2. Try loading from legacy single file: corpus/watch_sessions/{session_id}.json
            if data is None:
                legacy_path = os.path.join(self.sessions_dir, f"{session_id}.json")
                if os.path.exists(legacy_path):
                    try:
                        with open(legacy_path, "r", encoding="utf-8") as f:
                            data = json.load(f)
                    except Exception:
                        data = None

            if data:
                try:
                    session = ObservationSession.from_dict(data)

                    # Load observations from JSONL if observations list was not loaded from monolithic JSON
                    jsonl_path = self._get_observations_file(session_id)
                    if os.path.exists(jsonl_path) and not session.observations:
                        loaded_obs = []
                        with open(jsonl_path, "r", encoding="utf-8") as jf:
                            for line in jf:
                                if line.strip():
                                    try:
                                        loaded_obs.append(Observation.from_dict(json.loads(line)))
                                    except Exception:
                                        pass
                        session.observations = loaded_obs
                        session.total_observations = len(loaded_obs)

                    # If loaded from disk and marked RUNNING without an active worker, mark STOPPED
                    if session.status == "RUNNING" and session_id not in self._threads:
                        session.status = "STOPPED"
                        session.end_time = session.end_time or datetime.now(timezone.utc).isoformat()
                        session.gaps.append(CaptureGap(
                            gap_id=f"gap_restart_{uuid.uuid4().hex[:6]}",
                            start_ns=0,
                            end_ns=0,
                            duration_ms=0.0,
                            reason="SERVER_RESTARTED_CAPTURE_ABORTED",
                            timestamp=datetime.now(timezone.utc).isoformat(),
                        ))
                        self._persist_session(session)

                    self._sessions[session_id] = session
                    return session
                except Exception:
                    return None
            return None

    def list_sessions(self, include_stopped: bool = True) -> List[Dict[str, Any]]:
        """Lists metadata summaries of all persisted and active watch sessions."""
        with self._lock:
            results: List[Dict[str, Any]] = []
            seen_ids = set()

            # Active in-memory sessions
            for sid, s in self._sessions.items():
                seen_ids.add(sid)
                if include_stopped or s.status == "RUNNING":
                    results.append(s.to_summary_dict())

            # Disk-discovered sessions
            if os.path.exists(self.sessions_dir):
                for entry in os.listdir(self.sessions_dir):
                    entry_path = os.path.join(self.sessions_dir, entry)
                    sid = None
                    if os.path.isdir(entry_path):
                        meta_file = os.path.join(entry_path, "session.json")
                        if os.path.exists(meta_file):
                            sid = entry
                    elif entry.endswith(".json") and not entry.endswith(".tmp"):
                        sid = entry[:-5]

                    if sid and sid not in seen_ids:
                        s = self.get_session(sid)
                        if s:
                            seen_ids.add(sid)
                            if include_stopped or s.status == "RUNNING":
                                results.append(s.to_summary_dict())

            results.sort(key=lambda s: s.get("start_time", ""), reverse=True)
            return results

    def get_session_status(self, session_id: str) -> Dict[str, Any]:
        """Fast status query without loading all historical observations into memory."""
        session = self.get_session(session_id)
        if not session:
            return {"session_id": session_id, "found": False, "status": "NOT_FOUND"}

        last_obs_seq = None
        last_obs_time = None
        if session.observations:
            last_obs = session.observations[-1]
            last_obs_seq = last_obs.seq
            last_obs_time = last_obs.timestamp

        return {
            "session_id": session.session_id,
            "found": True,
            "status": session.status,
            "pid": session.pid,
            "is_remote": session.provenance.get("is_remote", False),
            "target_host": session.provenance.get("host", "localhost"),
            "total_observations": session.total_observations or len(session.observations),
            "last_observation_seq": last_obs_seq,
            "last_observation_timestamp": last_obs_time,
            "watch_items_count": len(session.watch_items),
            "gaps_count": len(session.gaps),
            "health": "HEALTHY" if session.status == "RUNNING" else "STOPPED",
            "capabilities": session.capabilities,
        }

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
                th.join(timeout=2.0)

            session.status = "STOPPED"
            session.end_time = datetime.now(timezone.utc).isoformat()
            self._persist_session(session)

            adapter = self._adapters.get(session_id)
            if adapter:
                try:
                    adapter.close()
                except Exception:
                    pass

            return session

    def add_watch_item(self, session_id: str, item_dict: Union[Dict[str, Any], WatchItem]) -> WatchItem:
        """Adds a new watch item to an existing session."""
        if hasattr(item_dict, "to_dict"):
            item_dict = item_dict.to_dict()
        with self._lock:
            session = self.get_session(session_id)
            if not session:
                raise ValueError(f"Session '{session_id}' not found")

            raw_addr = item_dict.get("address") or item_dict.get("runtime_address", 0)
            addr_int = int(raw_addr, 16) if isinstance(raw_addr, str) and raw_addr.startswith("0x") else int(raw_addr)
            size = int(item_dict.get("size", 4))
            if size <= 0 or size > 65536:
                raise ValueError(f"Invalid size {size}: must be between 1 and 65536 bytes")

            # Validate against target mappings
            adapter = self._adapters.get(session_id)
            map_data = self.get_memory_map_and_threads(session.pid, session.companion_elf_path, adapter=adapter)
            readable = any(
                m["start_int"] <= addr_int < m["end_int"] and m["is_readable"]
                for m in map_data["mappings"]
            )
            status = "ACTIVE" if readable else "OUT_OF_SCOPE"

            name = item_dict.get("name") or f"addr_0x{addr_int:x}"
            item_id = item_dict.get("item_id") or f"watch_{name}_{uuid.uuid4().hex[:4]}"

            # Check for existing item with same item_id
            source = item_dict.get("source", "custom_range")
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
                        source=source,
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
                source=source,
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
        limit: Optional[int] = 50,
        offset: int = 0,
    ) -> Dict[str, Any]:
        """Returns ordered observations and gaps with streaming pagination and bounds."""
        with self._lock:
            session = self.get_session(session_id)
            if not session:
                raise ValueError(f"Session '{session_id}' not found")

            jsonl_path = self._get_observations_file(session_id)
            results: List[Dict[str, Any]] = []
            total_count = 0

            # Stream from append-friendly JSONL file if available
            if os.path.exists(jsonl_path):
                with open(jsonl_path, "r", encoding="utf-8") as f:
                    for line in f:
                        if not line.strip():
                            continue
                        try:
                            d = json.loads(line)
                            seq = d.get("seq", 0)
                            if start_seq is not None and seq < start_seq:
                                continue
                            if end_seq is not None and seq > end_seq:
                                continue

                            total_count += 1
                            if total_count > offset:
                                if limit is None or len(results) < limit:
                                    results.append(d)
                        except Exception:
                            pass
            else:
                # In-memory / legacy list fallback
                obs = session.observations
                if start_seq is not None:
                    obs = [o for o in obs if o.seq >= start_seq]
                if end_seq is not None:
                    obs = [o for o in obs if o.seq <= end_seq]
                total_count = len(obs)
                page = obs[offset:offset + limit] if limit else obs[offset:]
                results = [o.to_dict() for o in page]

            return {
                "session_id": session.session_id,
                "status": session.status,
                "total_observations": total_count,
                "returned_count": len(results),
                "offset": offset,
                "limit": limit,
                "observations": results,
                "gaps": [g.to_dict() for g in session.gaps],
                "watch_items": [w.to_dict() for w in session.watch_items],
            }

    def capture_once(self, session_id: str) -> Observation:
        """Executes a single synchronous capture of all watch items for a session."""
        with self._lock:
            session = self.get_session(session_id)
            if not session:
                raise ValueError(f"Session '{session_id}' not found")
            adapter = self._adapters.get(session_id)
            if not adapter:
                adapter = self._resolve_adapter(pid=session.pid)
                self._adapters[session_id] = adapter

            t_start_ns = time.monotonic_ns()
            wall_clock = datetime.now(timezone.utc).isoformat()
            seq = (session.total_observations or len(session.observations)) + 1
            values: Dict[str, Dict[str, Any]] = {}
            obs_completeness = "COMPLETE"

            # Check liveness
            alive, live_err = adapter.check_liveness(session.pid)
            if not alive:
                raise RuntimeError(f"Target process PID {session.pid} is not accessible: {live_err}")

            for item in list(session.watch_items):
                raw_bytes, read_st, read_err = adapter.read_memory(session.pid, item.address, item.size)
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

            obs = Observation(
                session_id=session.session_id,
                seq=seq,
                monotonic_ns=t_start_ns,
                timestamp=wall_clock,
                values=values,
                completeness=obs_completeness,
                capture_latency_us=latency_us,
            )

            self._append_observation_to_file(session.session_id, obs)
            session.observations.append(obs)
            session.total_observations = len(session.observations)
            self._persist_session(session)
            return obs

    def compare_observations(self, session_id: str, seq_a: int, seq_b: int) -> Dict[str, Any]:
        """Compares two specific observation records within a session."""
        session = self.get_session(session_id)
        if not session:
            raise ValueError(f"Session '{session_id}' not found")

        # Find observation A and B
        obs_a = next((o for o in session.observations if o.seq == seq_a), None)
        obs_b = next((o for o in session.observations if o.seq == seq_b), None)

        if not obs_a or not obs_b:
            all_obs = self.get_observations(session_id, limit=50000).get("observations", [])
            if not obs_a:
                for o in all_obs:
                    if o.get("seq") == seq_a:
                        obs_a = Observation.from_dict(o)
                        break
            if not obs_b:
                for o in all_obs:
                    if o.get("seq") == seq_b:
                        obs_b = Observation.from_dict(o)
                        break

        if not obs_a or not obs_b:
            raise ValueError(f"One or both observation sequences (#{seq_a}, #{seq_b}) not found in session '{session_id}'")

        items_map = {w.item_id: w for w in session.watch_items}
        diffs = []
        for item_id, item in items_map.items():
            val_a_entry = obs_a.values.get(item_id, {})
            val_b_entry = obs_b.values.get(item_id, {})

            st_a = val_a_entry.get("status", "MISSING") if val_a_entry else "MISSING"
            st_b = val_b_entry.get("status", "MISSING") if val_b_entry else "MISSING"
            val_a = val_a_entry.get("value") if val_a_entry else None
            val_b = val_b_entry.get("value") if val_b_entry else None
            raw_a = val_a_entry.get("raw_hex", "") if val_a_entry else ""
            raw_b = val_b_entry.get("raw_hex", "") if val_b_entry else ""

            # Semantics:
            # Missing or failed reads must NEVER be interpreted as unchanged!
            if not val_a_entry and val_b_entry:
                diff_state = "ADDED"
            elif val_a_entry and not val_b_entry:
                diff_state = "REMOVED"
            elif st_a == "MISSING" or st_b == "MISSING":
                diff_state = "MISSING"
            elif st_a in ("UNAVAILABLE", "ERROR") or st_b in ("UNAVAILABLE", "ERROR"):
                diff_state = "UNREADABLE"
            elif st_a == "PARTIAL" or st_b == "PARTIAL":
                diff_state = "PARTIAL"
            elif st_a == "DECODE_ERROR" or st_b == "DECODE_ERROR":
                diff_state = "UNKNOWN"
            else:
                diff_state = "CHANGED" if (val_a != val_b or raw_a != raw_b) else "UNCHANGED"

            is_pointer = (item.type_name in ("pointer", "void*") or item.type_name.endswith("*"))
            pointer_change_type = "NONE"
            if is_pointer:
                if val_a != val_b:
                    pointer_change_type = "POINTER_ADDRESS_CHANGED"
                elif raw_a != raw_b:
                    pointer_change_type = "REFERENCED_MEMORY_CHANGED"
                else:
                    pointer_change_type = "STABLE"

            diffs.append({
                "item_id": item_id,
                "name": item.name,
                "scope": item.scope,
                "source": item.source,
                "type_name": item.type_name,
                "address": f"0x{item.address:x}",
                "size": item.size,
                "state": diff_state,
                "diff_state": diff_state,
                "value_a": val_a,
                "value_b": val_b,
                "raw_hex_a": raw_a,
                "raw_hex_b": raw_b,
                "before": {"value": val_a, "raw_hex": raw_a, "status": st_a},
                "after": {"value": val_b, "raw_hex": raw_b, "status": st_b},
                "is_pointer": is_pointer,
                "pointer_address_changed": is_pointer and (val_a != val_b),
                "pointer_change_type": pointer_change_type,
            })

        return {
            "session_id": session_id,
            "seq_a": seq_a,
            "seq_b": seq_b,
            "timestamp_a": obs_a.timestamp,
            "timestamp_b": obs_b.timestamp,
            "quality_a": obs_a.completeness,
            "quality_b": obs_b.completeness,
            "diffs": diffs,
            "summary": {
                "total_items": len(diffs),
                "changed": sum(1 for d in diffs if d["state"] == "CHANGED"),
                "unchanged": sum(1 for d in diffs if d["state"] == "UNCHANGED"),
                "unreadable": sum(1 for d in diffs if d["state"] == "UNREADABLE"),
                "partial": sum(1 for d in diffs if d["state"] == "PARTIAL"),
                "missing": sum(1 for d in diffs if d["state"] == "MISSING"),
                "unknown": sum(1 for d in diffs if d["state"] == "UNKNOWN"),
                "added": sum(1 for d in diffs if d["state"] == "ADDED"),
                "removed": sum(1 for d in diffs if d["state"] == "REMOVED"),
                "changed_count": sum(1 for d in diffs if d["state"] == "CHANGED"),
                "unchanged_count": sum(1 for d in diffs if d["state"] == "UNCHANGED"),
                "unreadable_count": sum(1 for d in diffs if d["state"] == "UNREADABLE"),
                "partial_count": sum(1 for d in diffs if d["state"] == "PARTIAL"),
                "missing_count": sum(1 for d in diffs if d["state"] == "MISSING"),
                "unknown_count": sum(1 for d in diffs if d["state"] == "UNKNOWN"),
                "added_count": sum(1 for d in diffs if d["state"] == "ADDED"),
                "removed_count": sum(1 for d in diffs if d["state"] == "REMOVED"),
            }
        }

    def _capture_worker(
        self,
        session_id: str,
        stop_evt: threading.Event,
        adapter: TargetExecutionAdapter,
    ) -> None:
        """Periodic background sampling loop using TargetExecutionAdapter."""
        session = self.get_session(session_id)
        if not session:
            return

        interval_s = float(session.configuration.get("interval_ms", 500)) / 1000.0
        max_samples = int(session.configuration.get("max_samples", 1000))
        max_storage_bytes = int(session.configuration.get("max_storage_bytes", 52428800))
        max_duration_sec = float(session.configuration.get("max_duration_sec", 3600))

        start_epoch = time.time()
        last_tick_end_ns = time.monotonic_ns()
        jsonl_path = self._get_observations_file(session_id)

        while not stop_evt.is_set():
            t_start_ns = time.monotonic_ns()

            # Bound 1: Duration bound
            if (time.time() - start_epoch) >= max_duration_sec:
                with self._lock:
                    session.status = "STOPPED"
                    session.end_time = datetime.now(timezone.utc).isoformat()
                    session.gaps.append(CaptureGap(
                        gap_id=f"gap_{uuid.uuid4().hex[:6]}",
                        start_ns=t_start_ns,
                        end_ns=t_start_ns,
                        duration_ms=0.0,
                        reason="DURATION_LIMIT_EXCEEDED",
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    ))
                    self._persist_session(session)
                break

            # Bound 2: Storage bytes bound
            if os.path.exists(jsonl_path) and os.path.getsize(jsonl_path) >= max_storage_bytes:
                with self._lock:
                    session.status = "STOPPED"
                    session.end_time = datetime.now(timezone.utc).isoformat()
                    session.gaps.append(CaptureGap(
                        gap_id=f"gap_{uuid.uuid4().hex[:6]}",
                        start_ns=t_start_ns,
                        end_ns=t_start_ns,
                        duration_ms=0.0,
                        reason="STORAGE_LIMIT_EXCEEDED",
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    ))
                    self._persist_session(session)
                break

            # Liveness check via adapter
            alive, live_err = adapter.check_liveness(session.pid)
            if not alive:
                with self._lock:
                    session.status = "STOPPED"
                    session.end_time = datetime.now(timezone.utc).isoformat()
                    session.gaps.append(CaptureGap(
                        gap_id=f"gap_{uuid.uuid4().hex[:6]}",
                        start_ns=t_start_ns,
                        end_ns=t_start_ns,
                        duration_ms=0.0,
                        reason="TARGET_TERMINATED",
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    ))
                    self._persist_session(session)
                break

            # Gap detection: if elapsed time > 1.8x expected interval, record gap
            elapsed_since_last_ms = (t_start_ns - last_tick_end_ns) / 1_000_000.0
            if (session.total_observations or len(session.observations)) > 0 and elapsed_since_last_ms > (interval_s * 1000.0 * 1.8):
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
            seq = (session.total_observations or len(session.observations)) + 1
            wall_clock = datetime.now(timezone.utc).isoformat()
            values: Dict[str, Dict[str, Any]] = {}
            obs_completeness = "COMPLETE"

            for item in list(session.watch_items):
                raw_bytes, read_st, read_err = adapter.read_memory(session.pid, item.address, item.size)
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

            # Durable append-only write
            self._append_observation_to_file(session.session_id, observation)

            with self._lock:
                session.observations.append(observation)
                session.total_observations = len(session.observations)

                # Persist metadata periodically (every 10 samples)
                if session.total_observations % 10 == 0:
                    self._persist_session(session)

                # Bound 3: Max samples bound
                if session.total_observations >= max_samples:
                    session.status = "STOPPED"
                    session.end_time = datetime.now(timezone.utc).isoformat()
                    self._persist_session(session)
                    break

            # Sleep remainder of interval
            spent_s = (time.monotonic_ns() - t_start_ns) / 1_000_000_000.0
            sleep_s = max(0.01, interval_s - spent_s)
            stop_evt.wait(timeout=sleep_s)

        # Final flush on worker exit
        with self._lock:
            if session.status == "RUNNING":
                session.status = "STOPPED"
                session.end_time = datetime.now(timezone.utc).isoformat()
            self._persist_session(session)

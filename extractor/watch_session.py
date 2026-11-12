from collections import deque
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
import re
import struct
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import uuid

import ctypes

from .debug_image import BinaryIdentity, inspect_elf
from .dwarf_indexer import DwarfIndex, DwarfIndexer, DwarfVariable
from .cpp_decoder import CppContainerDecoder
from .allocator_inspector import detect_allocator, classify_pointer_integrity, PointerClassification, AllocatorType
from .target_adapter import TargetExecutionAdapter, LocalTargetAdapter, RemoteSshTargetAdapter
from .cfi_unwinder import (
    UNWIND_SCAN as CFI_UNWIND_SCAN,
    decode_call_before,
    make_unwinder_for_process,
    parse_proc_syscall,
)
from .target_abi import (
    FEATURE_ALLOCATOR_CHUNKS,
    FEATURE_CFI_UNWIND,
    FEATURE_FRAME_LAYOUT,
    FEATURE_MUTEX_OWNER,
    FEATURE_SYSCALL_NAMES,
    FEATURE_TCB_SCAN,
    SUPPORT_NOT_SUPPORTED_ON_TARGET,
    SUPPORT_SUPPORTED,
    TargetABI,
    abi_support_summary,
    check_support,
    detect_target_abi,
    syscall_name as abi_syscall_name,
)
from .verdict_engine import (
    VerdictEngine,
    AssertionEvaluation,
    sanitize_report_output_path,
    ASSERTION_PASS,
    ASSERTION_FAIL,
    ASSERTION_ABSTAIN,
)
from .evidence_adapter import EvidenceAdapter
from .evidence_ledger import EvidenceLedger
from .diagnostic_verdict_aggregator import VERDICT_INCONCLUSIVE, health_score_for, verdict_for_scan
from .observation_budget import ObservationBudgetTracker, ObservationBudgetLimits
from .inspection.process_memory import (  # re-exported: imported from extractor.watch_session elsewhere
    ZERO_STOP_NON_ATOMIC_CONSISTENCY,
    decode_value_from_bytes,
    read_process_memory_slice,
)
from .inspection import process_maps as _process_maps
from .inspection.process_maps import (  # re-exported: imported from extractor.watch_session elsewhere
    calculate_load_bias,
)
from .inspection import threads as _threads
from .inspection import tls as _tls
from .inspection import expressions as _expressions
from .inspection import baselines as _baselines
from .inspection import pools as _pools
from .inspection import memory as _memory
from .inspection import ipc as _ipc
# @inspection-imports@


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
    # IMP-015: ABI detected from the target at attach time (architecture, word size, endianness, libc)
    target_abi: Dict[str, Any] = field(default_factory=dict)

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
            "target_abi": self.target_abi,
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
            "architecture": self.target_abi.get("architecture"),
            "libc": self.target_abi.get("libc"),
            "word_size": self.target_abi.get("word_size"),
            "abi_detection_status": self.target_abi.get("status"),
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
            target_abi=d.get("target_abi") or {},
            total_observations=tot,
        )


# -----------------------------------------------------------------------------
# Watch Session Manager
# -----------------------------------------------------------------------------

class WatchSessionManager:
    """Manages persistent watch session lifecycle, periodic zero-stop capture, and storage."""

    def __init__(self, corpus_dir: str):
        self.corpus_dir = os.path.abspath(corpus_dir)
        self.sessions_dir = os.path.join(self.corpus_dir, "watch_sessions")
        self.baselines_dir = os.path.join(self.corpus_dir, "golden_baselines")
        os.makedirs(self.sessions_dir, exist_ok=True)
        os.makedirs(self.baselines_dir, exist_ok=True)

        self._lock = threading.RLock()
        self._sessions: Dict[str, ObservationSession] = {}
        self._threads: Dict[str, threading.Thread] = {}
        self._stop_events: Dict[str, threading.Event] = {}
        self._adapters: Dict[str, TargetExecutionAdapter] = {}
        self._maps_bias_cache: Dict[Tuple[int, str, str], Tuple[float, Dict[str, Any]]] = {}
        self._active_target_context: Dict[str, Any] = {
            "pid": None,
            "process_name": None,
            "companion_elf_path": None,
            "build_id": None,
            "remote_host": None,
            "ssh_user": None,
            "ssh_port": 22,
            "ssh_key": None,
            "ssh_proxy_jump": None,
            "bound_at_unix": None,
            "auto_healed_count": 0,
            "last_previous_pid": None,
        }

    @staticmethod
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

    @staticmethod
    def _coerce_str_list(val: Any) -> List[str]:
        """Safely coerces None, comma-separated string, JSON list string, or iterable into List[str]."""
        if val is None:
            return []
        if isinstance(val, str):
            s = val.strip()
            if not s:
                return []
            if s.startswith("[") and s.endswith("]"):
                try:
                    parsed = json.loads(s)
                    if isinstance(parsed, list):
                        return [str(x).strip() for x in parsed if x is not None and str(x).strip()]
                except Exception:
                    pass
            return [x.strip() for x in s.split(",") if x.strip()]
        if isinstance(val, (list, tuple, set)):
            return [str(x).strip() for x in val if x is not None and str(x).strip()]
        return [str(val).strip()] if str(val).strip() else []

    @staticmethod
    def _coerce_steps_list(val: Any, max_steps: int = 32) -> List[Dict[str, Any]]:
        """Safely coerces batch macro steps from JSON string, single dict, or list of dicts."""
        if val is None:
            return []
        if isinstance(val, str):
            s = val.strip()
            if not s:
                return []
            try:
                parsed = json.loads(s)
                if isinstance(parsed, dict):
                    return [parsed]
                if isinstance(parsed, list):
                    val = parsed
                else:
                    return [{"action": "ask", "question": s}]
            except Exception:
                return [{"action": "ask", "question": s}]
        if isinstance(val, dict):
            return [val]
        if isinstance(val, (list, tuple)):
            out: List[Dict[str, Any]] = []
            for item in val[:max_steps]:
                if isinstance(item, dict):
                    out.append(item)
                elif isinstance(item, str) and item.strip():
                    out.append({"action": "eval", "expression": item.strip()})
                else:
                    out.append({
                        "action": "malformed_step",
                        "raw_item": item,
                        "error": f"Invalid step format: expected dictionary or expression string, got {type(item).__name__}",
                    })
            return out
        return []

    def _get_session_dir(self, session_id: str) -> str:
        if not session_id or not isinstance(session_id, str) or ".." in session_id or "/" in session_id or "\\" in session_id:
            raise ValueError(f"Invalid session_id '{session_id}': path traversal characters prohibited")
        d = os.path.join(self.sessions_dir, session_id)
        os.makedirs(d, mode=0o700, exist_ok=True)
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
        collector_path: Optional[str] = None,
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
                collector_path=collector_path,
            )
        return LocalTargetAdapter()

    @staticmethod
    def _split_companion_elf_paths(
        companion_elf_path: Optional[str],
        extra_debug_images: Optional[List[str]] = None,
        debug_dir: Optional[str] = None,
    ) -> Tuple[Optional[str], List[str]]:
        """Splits primary companion ELF path and any additional shared library (.so) debug ELF paths."""
        primary: Optional[str] = None
        extras: List[str] = []
        if companion_elf_path:
            parts = [p.strip() for p in str(companion_elf_path).split(",") if p.strip()]
            if parts:
                primary = parts[0]
                extras.extend(parts[1:])
        if extra_debug_images:
            for p in extra_debug_images:
                if p and str(p).strip() and str(p).strip() not in extras and str(p).strip() != primary:
                    extras.append(str(p).strip())
        if debug_dir and os.path.isdir(debug_dir):
            for entry in sorted(os.listdir(debug_dir)):
                if entry.endswith((".so", ".debug", ".elf")):
                    fp = os.path.abspath(os.path.join(debug_dir, entry))
                    if os.path.isfile(fp) and fp != primary and fp not in extras:
                        extras.append(fp)
        return primary, extras

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

            # 3. Validate companion ELF if supplied (supports comma-separated main ELF + .so ELFs)
            companion_identity: Optional[BinaryIdentity] = None
            primary_comp_elf, _ = self._split_companion_elf_paths(companion_elf_path)
            if primary_comp_elf:
                if not os.path.exists(primary_comp_elf):
                    raise FileNotFoundError(f"Companion ELF binary not found: '{primary_comp_elf}'")
                try:
                    companion_identity = inspect_elf(primary_comp_elf)
                except Exception as e:
                    raise ValueError(f"Invalid ELF image '{primary_comp_elf}': {e}")

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

            # 5b. Detect the target ABI from the target itself (ELF header, PT_INTERP, mapped libc)
            try:
                target_abi_rec = detect_target_abi(target_adapter, pid).to_dict()
            except Exception as abi_exc:  # noqa: BLE001 - detection failure must not break attach
                target_abi_rec = TargetABI(error=f"ABI detection raised: {abi_exc}").to_dict()

            # 6. Construct ObservationSession
            session_id = f"watch_{pid}_{int(time.time())}_{uuid.uuid4().hex[:6]}"
            target_ident = {
                "pid": pid,
                "executable": runtime_ident.get("executable", ""),
                "architecture": runtime_ident.get("architecture", "unknown"),
                "elf_type": runtime_ident.get("elf_type", "unknown"),
                "word_size": target_abi_rec.get("word_size"),
                "libc": target_abi_rec.get("libc"),
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
                target_abi=target_abi_rec,
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
            "health": "ACTIVE" if session.status == "RUNNING" else "STOPPED",
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

        with self._lock:
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
            addr_int = int(raw_addr, 16) if isinstance(raw_addr, str) and raw_addr.startswith("0x") else int(raw_addr or 0)
            expr_candidate = (item_dict.get("expression") or item_dict.get("name") or "").strip()
            adapter = self._adapters.get(session_id) or self._resolve_adapter(pid=session.pid)

            # Auto-resolve C/C++ symbol expression if address is 0/omitted and companion ELF is present
            if addr_int == 0 and expr_candidate and session.companion_elf_path and os.path.exists(session.companion_elf_path):
                try:
                    ev_res = self.evaluate_symbol_paths(
                        pid=session.pid,
                        companion_elf_path=session.companion_elf_path,
                        expressions=[expr_candidate],
                        adapter=adapter,
                    )
                    ev_list = ev_res.get("results", [])
                    if ev_list and ev_list[0].get("runtime_address_int"):
                        addr_int = int(ev_list[0]["runtime_address_int"])
                        if not item_dict.get("size") and ev_list[0].get("size"):
                            item_dict["size"] = int(ev_list[0]["size"])
                        if (not item_dict.get("type_name") or item_dict.get("type_name") == "raw_bytes") and ev_list[0].get("type_name"):
                            item_dict["type_name"] = ev_list[0]["type_name"]
                        if not item_dict.get("expression"):
                            item_dict["expression"] = expr_candidate
                except Exception:
                    pass

            size = int(item_dict.get("size", 4))
            if size <= 0 or size > 65536:
                raise ValueError(f"Invalid size {size}: must be between 1 and 65536 bytes")

            # Validate against target mappings using lightweight cached maps/load_bias helper
            adapter = self._adapters.get(session_id) or self._resolve_adapter(pid=session.pid)
            map_data = self._get_process_maps_and_load_bias(session.pid, session.companion_elf_path, adapter=adapter)
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
        """Returns ordered observations and gaps with fast in-memory ring-buffer serving and JSONL fallback."""
        with self._lock:
            session = self.get_session(session_id)
            if not session:
                raise ValueError(f"Session '{session_id}' not found")

            jsonl_path = self._get_observations_file(session_id)
            results: List[Dict[str, Any]] = []
            total_count = 0

            # Fast path: serve directly from in-memory observations if all recorded observations are resident in memory
            in_mem_obs = session.observations
            total_recorded = session.total_observations or len(in_mem_obs)
            can_serve_from_mem = bool(in_mem_obs and len(in_mem_obs) >= total_recorded)
            if not can_serve_from_mem and in_mem_obs and start_seq is not None and in_mem_obs[0].seq <= start_seq:
                can_serve_from_mem = True

            if can_serve_from_mem or not os.path.exists(jsonl_path):
                obs = in_mem_obs
                if start_seq is not None:
                    obs = [o for o in obs if o.seq >= start_seq]
                if end_seq is not None:
                    obs = [o for o in obs if o.seq <= end_seq]
                total_count = len(obs) if (start_seq is not None or end_seq is not None) else total_recorded
                page = obs[offset:offset + limit] if limit else obs[offset:]
                results = [o.to_dict() for o in page]
            else:
                # Fallback: stream from append-friendly JSONL file when historical observations were evicted from memory
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

    @staticmethod
    def _sample_watch_item(adapter: TargetExecutionAdapter, pid: int, item: WatchItem) -> Tuple[Dict[str, Any], str]:
        """Reads and decodes a watch item from the target process.

        For pointer types (e.g. `Buffer*`, `void*`, `pointer`), this also samples a bounded
        slice (up to 64 bytes) of the pointed-to memory so that referenced memory mutations
        can be distinguished from pointer reassignments.
        """
        raw_bytes, read_st, read_err = adapter.read_memory(pid, item.address, item.size)
        is_pointer = (item.type_name in ("pointer", "void*") or item.type_name.endswith("*"))

        if read_st == "OBSERVED" and raw_bytes is not None:
            decoded_val, dec_err = decode_value_from_bytes(raw_bytes, item.type_name)
            st = "OBSERVED" if dec_err is None else "DECODE_ERROR"
            entry: Dict[str, Any] = {
                "value": decoded_val,
                "raw_hex": raw_bytes.hex(),
                "status": st,
                "error": dec_err,
                "is_pointer": is_pointer,
            }

            if is_pointer:
                target_addr = None
                if isinstance(decoded_val, str) and decoded_val.startswith("0x"):
                    try:
                        target_addr = int(decoded_val, 16)
                    except ValueError:
                        target_addr = None
                elif isinstance(decoded_val, int):
                    target_addr = decoded_val

                if target_addr is not None and target_addr > 0:
                    ref_bytes, ref_st, ref_err = adapter.read_memory(pid, target_addr, 64)
                    entry["referenced_address"] = f"0x{target_addr:x}"
                    entry["referenced_status"] = ref_st
                    entry["referenced_raw_hex"] = ref_bytes.hex() if (ref_st == "OBSERVED" and ref_bytes) else ""
                    if ref_err:
                        entry["referenced_error"] = ref_err
                elif target_addr == 0:
                    entry["referenced_address"] = "0x0"
                    entry["referenced_status"] = "NULL_POINTER"
                    entry["referenced_raw_hex"] = ""
                else:
                    entry["referenced_address"] = "UNKNOWN"
                    entry["referenced_status"] = "INVALID_POINTER"
                    entry["referenced_raw_hex"] = ""

            return entry, "COMPLETE" if st == "OBSERVED" else "PARTIAL"

        elif read_st == "PARTIAL":
            entry = {
                "value": None,
                "raw_hex": raw_bytes.hex() if raw_bytes else "",
                "status": "PARTIAL",
                "error": read_err or "Partial memory read",
                "is_pointer": is_pointer,
            }
            return entry, "PARTIAL"
        else:
            entry = {
                "value": None,
                "raw_hex": "",
                "status": read_st if read_st in ("UNAVAILABLE", "PERMISSION_DENIED", "TARGET_TERMINATED") else "UNAVAILABLE",
                "error": read_err or "Memory read failed or unmapped",
                "is_pointer": is_pointer,
            }
            return entry, "PARTIAL"

    def _sample_session_watch_items(
        self,
        session: ObservationSession,
        adapter: TargetExecutionAdapter,
    ) -> Tuple[Dict[str, Dict[str, Any]], str]:
        """Samples all watch items for a session, supporting dynamic pointer-chain expressions
        and single-roundtrip batched memory reads on remote targets.
        """
        values: Dict[str, Dict[str, Any]] = {}
        obs_completeness = "COMPLETE"
        items = list(session.watch_items)
        if not items:
            return values, obs_completeness

        dynamic_expr_items: List[WatchItem] = []
        direct_items: List[WatchItem] = []
        has_companion = bool(session.companion_elf_path and os.path.exists(session.companion_elf_path))

        for item in items:
            expr_str = (item.expression or "").strip()
            if has_companion and expr_str and ("->" in expr_str or "*" in expr_str or "[" in expr_str):
                dynamic_expr_items.append(item)
            else:
                direct_items.append(item)

        # 1. Dynamically evaluate pointer-chain / array watch items via DWARF traversal
        if dynamic_expr_items and has_companion:
            exprs = [str(w.expression or w.name) for w in dynamic_expr_items]
            try:
                ev_res = self.evaluate_symbol_paths(
                    pid=session.pid,
                    companion_elf_path=str(session.companion_elf_path),
                    expressions=exprs,
                    adapter=adapter,
                )
                ev_map = {r["expression"]: r for r in ev_res.get("results", [])}
            except Exception:
                ev_map = {}

            for w in dynamic_expr_items:
                ex = str(w.expression or w.name)
                r = ev_map.get(ex)
                if r and r.get("status") == "OBSERVED":
                    if r.get("runtime_address_int"):
                        w.address = int(r["runtime_address_int"])
                    values[w.item_id] = {
                        "value": r.get("value"),
                        "raw_hex": r.get("raw_hex", ""),
                        "status": "OBSERVED",
                        "error": None,
                        "is_pointer": bool(w.type_name.endswith("*")),
                        "resolved_address": r.get("runtime_address"),
                        "pointer_chain": r.get("pointer_chain"),
                    }
                else:
                    obs_completeness = "PARTIAL"
                    values[w.item_id] = {
                        "value": None,
                        "raw_hex": "",
                        "status": (r.get("status") if r else "UNAVAILABLE"),
                        "error": (r.get("error") if r else "Dynamic expression evaluation failed"),
                        "is_pointer": bool(w.type_name.endswith("*")),
                    }

        # 2. Sample direct-address items (use batch read when remote and >= 2 non-pointer items)
        non_ptr_direct = [
            w for w in direct_items
            if not (w.type_name in ("pointer", "void*") or w.type_name.endswith("*"))
        ]
        ptr_direct = [
            w for w in direct_items
            if (w.type_name in ("pointer", "void*") or w.type_name.endswith("*"))
        ]

        if adapter.is_remote() and len(non_ptr_direct) >= 2 and hasattr(adapter, "read_memory_batch"):
            slices = [(w.address, w.size) for w in non_ptr_direct]
            batch_res = adapter.read_memory_batch(session.pid, slices)
            for w, (raw_bytes, read_st, read_err) in zip(non_ptr_direct, batch_res):
                if read_st == "OBSERVED" and raw_bytes is not None:
                    decoded_val, dec_err = decode_value_from_bytes(raw_bytes, w.type_name)
                    st = "OBSERVED" if dec_err is None else "DECODE_ERROR"
                    values[w.item_id] = {
                        "value": decoded_val,
                        "raw_hex": raw_bytes.hex(),
                        "status": st,
                        "error": dec_err,
                        "is_pointer": False,
                    }
                    if st != "OBSERVED":
                        obs_completeness = "PARTIAL"
                elif read_st == "PARTIAL":
                    obs_completeness = "PARTIAL"
                    values[w.item_id] = {
                        "value": None,
                        "raw_hex": raw_bytes.hex() if raw_bytes else "",
                        "status": "PARTIAL",
                        "error": read_err or "Partial memory read",
                        "is_pointer": False,
                    }
                else:
                    obs_completeness = "PARTIAL"
                    values[w.item_id] = {
                        "value": None,
                        "raw_hex": "",
                        "status": read_st if read_st in ("UNAVAILABLE", "PERMISSION_DENIED", "TARGET_TERMINATED") else "UNAVAILABLE",
                        "error": read_err or "Memory read failed or unmapped",
                        "is_pointer": False,
                    }
            for w in ptr_direct:
                item_entry, comp = self._sample_watch_item(adapter, session.pid, w)
                values[w.item_id] = item_entry
                if comp != "COMPLETE":
                    obs_completeness = "PARTIAL"
        else:
            for w in direct_items:
                item_entry, comp = self._sample_watch_item(adapter, session.pid, w)
                values[w.item_id] = item_entry
                if comp != "COMPLETE":
                    obs_completeness = "PARTIAL"

        return values, obs_completeness

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

            values, obs_completeness = self._sample_session_watch_items(session, adapter)

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
            session.total_observations = (session.total_observations or (len(session.observations) - 1)) + 1
            if len(session.observations) > 500:
                del session.observations[:-500]
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

            is_pointer = (item.type_name in ("pointer", "void*") or item.type_name.endswith("*"))
            ref_hex_a = val_a_entry.get("referenced_raw_hex", "") if val_a_entry else ""
            ref_hex_b = val_b_entry.get("referenced_raw_hex", "") if val_b_entry else ""
            ref_st_a = val_a_entry.get("referenced_status", "NONE") if val_a_entry else "NONE"
            ref_st_b = val_b_entry.get("referenced_status", "NONE") if val_b_entry else "NONE"
            ref_addr_a = val_a_entry.get("referenced_address", "") if val_a_entry else ""
            ref_addr_b = val_b_entry.get("referenced_address", "") if val_b_entry else ""

            # Semantics:
            # Missing or failed reads must NEVER be interpreted as unchanged!
            if not val_a_entry and val_b_entry:
                diff_state = "ADDED"
            elif val_a_entry and not val_b_entry:
                diff_state = "REMOVED"
            elif st_a == "MISSING" or st_b == "MISSING":
                diff_state = "MISSING"
            elif st_a in ("UNAVAILABLE", "ERROR", "PERMISSION_DENIED", "TARGET_TERMINATED") or st_b in ("UNAVAILABLE", "ERROR", "PERMISSION_DENIED", "TARGET_TERMINATED"):
                diff_state = "UNREADABLE"
            elif st_a == "PARTIAL" or st_b == "PARTIAL":
                diff_state = "PARTIAL"
            elif st_a == "DECODE_ERROR" or st_b == "DECODE_ERROR":
                diff_state = "UNKNOWN"
            else:
                if is_pointer:
                    if val_a != val_b:
                        diff_state = "CHANGED"
                        pointer_change_type = "POINTER_ADDRESS_CHANGED"
                    elif ref_hex_a != ref_hex_b:
                        diff_state = "CHANGED"
                        pointer_change_type = "REFERENCED_MEMORY_CHANGED"
                    else:
                        diff_state = "UNCHANGED"
                        pointer_change_type = "STABLE"
                else:
                    diff_state = "CHANGED" if (val_a != val_b or raw_a != raw_b) else "UNCHANGED"
                    pointer_change_type = "NONE"

            if not is_pointer:
                pointer_change_type = "NONE"

            diffs.append({
                "item_id": item_id,
                "name": item.name,
                "scope": item.scope,
                "source": item.source,
                "source_location": item.source_location,
                "type_name": item.type_name,
                "address": f"0x{item.address:x}",
                "size": item.size,
                "state": diff_state,
                "diff_state": diff_state,
                "value_a": val_a,
                "value_b": val_b,
                "raw_hex_a": raw_a,
                "raw_hex_b": raw_b,
                "status_a": st_a,
                "status_b": st_b,
                "before": {
                    "value": val_a,
                    "raw_hex": raw_a,
                    "status": st_a,
                    "referenced_address": ref_addr_a,
                    "referenced_raw_hex": ref_hex_a,
                    "referenced_status": ref_st_a,
                },
                "after": {
                    "value": val_b,
                    "raw_hex": raw_b,
                    "status": st_b,
                    "referenced_address": ref_addr_b,
                    "referenced_raw_hex": ref_hex_b,
                    "referenced_status": ref_st_b,
                },
                "is_pointer": is_pointer,
                "pointer_address_changed": is_pointer and (val_a != val_b),
                "pointer_change_type": pointer_change_type,
                "referenced_raw_hex_a": ref_hex_a,
                "referenced_raw_hex_b": ref_hex_b,
                "referenced_status_a": ref_st_a,
                "referenced_status_b": ref_st_b,
                "pid": session.pid,
                "binary_build_id": session.binary_build_id,
                "capture_backend": session.capabilities.get("capture_backend", "process_vm_readv"),
                "timestamp_a": obs_a.timestamp,
                "timestamp_b": obs_b.timestamp,
            })

        return {
            "session_id": session_id,
            "pid": session.pid,
            "binary_build_id": session.binary_build_id,
            "capture_backend": session.capabilities.get("capture_backend", "process_vm_readv"),
            "seq_a": seq_a,
            "seq_b": seq_b,
            "timestamp_a": obs_a.timestamp,
            "timestamp_b": obs_b.timestamp,
            "quality_a": obs_a.completeness,
            "quality_b": obs_b.completeness,
            "snapshot_a": obs_a.to_dict(),
            "snapshot_b": obs_b.to_dict(),
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
                is_transport_err = bool(live_err and any(k in live_err.lower() for k in ("transport failure", "timed out", "ssh execution error")))
                with self._lock:
                    session.gaps.append(CaptureGap(
                        gap_id=f"gap_{uuid.uuid4().hex[:6]}",
                        start_ns=t_start_ns,
                        end_ns=t_start_ns,
                        duration_ms=0.0,
                        reason="TRANSPORT_DISCONNECTED" if is_transport_err else "TARGET_TERMINATED",
                        timestamp=datetime.now(timezone.utc).isoformat(),
                    ))
                    if len(session.gaps) > 500:
                        del session.gaps[:-500]
                    session.status = "STOPPED"
                    session.end_time = datetime.now(timezone.utc).isoformat()
                    try:
                        self._persist_session(session)
                    except OSError:
                        pass
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

            values, obs_completeness = self._sample_session_watch_items(session, adapter)

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
                session.total_observations = seq
                if len(session.observations) > 500:
                    del session.observations[:-500]

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

    # -------------------------------------------------------------------------
    # Phase 40 (Phase 10): 6 Advanced LLM MCP Engine Capabilities
    # -------------------------------------------------------------------------

    @staticmethod
    def _parse_condition_clauses(condition_expression: str) -> Tuple[str, List[Dict[str, Any]], List[str]]:
        """Parses a condition expression like:
        - `gpMem->active_buffers >= 5`
        - `gpMem->buffers[9].in_use == 1 && gpMem->active_buffers > 0`
        - `ANY_CHANGE`
        Returns (combinator, clauses, referenced_symbols).
        """
        raw = (condition_expression or "").strip()
        if not raw or raw.upper() in ("ANY_CHANGE", "CHANGE", "CHANGED", "*"):
            return "ANY_CHANGE", [], []

        combinator = "AND"
        if "||" in raw or " or " in raw.lower():
            combinator = "OR"
            parts = re.split(r"\|\||\bor\b", raw, flags=re.IGNORECASE)
        else:
            parts = re.split(r"&&|\band\b", raw, flags=re.IGNORECASE)

        clauses: List[Dict[str, Any]] = []
        symbols: List[str] = []
        op_regex = re.compile(r"^(.*?)\s*(==|!=|>=|<=|>|<)\s*(.+)$")

        for p in parts:
            p_str = p.strip()
            if not p_str:
                continue
            m = op_regex.match(p_str)
            if m:
                lhs = m.group(1).strip()
                op = m.group(2).strip()
                rhs_raw = m.group(3).strip()
                rhs_val: Any = rhs_raw
                if rhs_raw.lower() in ("true", "null", "nullptr"):
                    rhs_val = 1 if rhs_raw.lower() == "true" else 0
                elif rhs_raw.lower() == "false":
                    rhs_val = 0
                elif rhs_raw.startswith("0x") or rhs_raw.startswith("0X"):
                    try:
                        rhs_val = int(rhs_raw, 16)
                    except ValueError:
                        rhs_val = rhs_raw
                else:
                    try:
                        rhs_val = int(rhs_raw)
                    except ValueError:
                        try:
                            rhs_val = float(rhs_raw)
                        except ValueError:
                            rhs_val = rhs_raw.strip("'\"")
                clauses.append({"lhs": lhs, "op": op, "rhs": rhs_val, "raw": p_str})
                if lhs not in symbols:
                    symbols.append(lhs)
            else:
                clauses.append({"lhs": p_str, "op": "TRUTHY", "rhs": 0, "raw": p_str})
                if p_str not in symbols:
                    symbols.append(p_str)

        return combinator, clauses, symbols

    @staticmethod
    def _coerce_numeric_or_str(val: Any) -> Any:
        if isinstance(val, (int, float)):
            return val
        if isinstance(val, str):
            s = val.strip()
            if s.startswith("0x") or s.startswith("0X"):
                try:
                    return int(s, 16)
                except ValueError:
                    pass
            m_enum = re.search(r"\((-?\d+)\)\s*$", s)
            if m_enum:
                try:
                    return int(m_enum.group(1))
                except ValueError:
                    pass
            try:
                return int(s)
            except ValueError:
                try:
                    return float(s)
                except ValueError:
                    return s
        return val

    @classmethod
    def _evaluate_parsed_clauses(
        cls,
        combinator: str,
        clauses: List[Dict[str, Any]],
        current_vals: Dict[str, Any],
        baseline_vals: Dict[str, Any],
    ) -> Tuple[bool, List[Dict[str, Any]]]:
        if combinator == "ANY_CHANGE":
            diffs = []
            for k, v in current_vals.items():
                if k in baseline_vals and baseline_vals[k] != v:
                    diffs.append({"expression": k, "before": baseline_vals[k], "after": v, "matched": True})
            return (len(diffs) > 0), diffs

        if not clauses:
            return False, []

        clause_results: List[Dict[str, Any]] = []
        bools: List[bool] = []
        for c in clauses:
            lhs_expr = c["lhs"]
            op = c["op"]
            rhs = c["rhs"]
            raw_obs = current_vals.get(lhs_expr)
            obs = cls._coerce_numeric_or_str(raw_obs)
            rhs_cmp = cls._coerce_numeric_or_str(rhs)

            matched = False
            try:
                if op == "TRUTHY":
                    matched = bool(obs) and obs != 0 and obs != "0x0"
                elif op == "==":
                    matched = (obs == rhs_cmp)
                elif op == "!=":
                    matched = (obs != rhs_cmp)
                elif op == ">=":
                    matched = (obs >= rhs_cmp)  # type: ignore[operator]
                elif op == "<=":
                    matched = (obs <= rhs_cmp)  # type: ignore[operator]
                elif op == ">":
                    matched = (obs > rhs_cmp)   # type: ignore[operator]
                elif op == "<":
                    matched = (obs < rhs_cmp)   # type: ignore[operator]
            except Exception:
                matched = False

            bools.append(matched)
            clause_results.append({
                "clause": c["raw"],
                "lhs": lhs_expr,
                "observed_value": raw_obs,
                "operator": op,
                "expected_rhs": rhs,
                "matched": matched,
            })

        overall = any(bools) if combinator == "OR" else all(bools)
        return overall, clause_results

    def watch_until_condition(
        self,
        pid: int,
        companion_elf_path: str,
        condition_expression: str,
        watch_expressions: Optional[List[str]] = None,
        poll_interval_ms: int = 40,
        timeout_ms: int = 2500,
        hold_duration_ms: int = 0,
        find_owner_on_hit: Optional[str] = None,
        remote_host: Optional[str] = None,
        ssh_user: Optional[str] = None,
        ssh_port: int = 22,
        ssh_key: Optional[str] = None,
        ssh_proxy_jump: Optional[str] = None,
        adapter: Optional[TargetExecutionAdapter] = None,
    ) -> Dict[str, Any]:
        """Zero-stop conditional watchpoint & anomaly snapshot catcher.
        Polls target symbol expressions at `poll_interval_ms` without stopping the target process (zero-stop),
        evaluates `condition_expression` (or waits until it holds continuously for `hold_duration_ms`),
        and immediately captures a before/after state diff + optional thread owner reverse-lookup on hit.
        """
        target_adapter = self._resolve_adapter(
            pid=pid,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
            adapter=adapter,
        )

        combinator, clauses, cond_symbols = self._parse_condition_clauses(condition_expression)
        all_exprs: List[str] = []
        for s in cond_symbols:
            if s and s not in all_exprs:
                all_exprs.append(s)
        for w in (watch_expressions or []):
            w_s = (w or "").strip()
            if w_s and w_s not in all_exprs:
                all_exprs.append(w_s)

        if not all_exprs:
            # Auto-populate top state variables if ANY_CHANGE with no explicit watch_expressions
            primary_elf, _ = self._split_companion_elf_paths(companion_elf_path)
            idx = DwarfIndexer.get_index(primary_elf)
            top_syms = idx.search_symbols(query="", category="variables", limit=6, smart_rank=True)
            all_exprs = [s["name"] for s in top_syms if s.get("name")]

        clamped_poll_ms = max(10, min(int(poll_interval_ms), 5000))
        clamped_timeout_ms = max(20, min(int(timeout_ms), 30000))
        clamped_hold_ms = max(0, min(int(hold_duration_ms), clamped_timeout_ms))

        def _sample_flat() -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
            eval_res = self.evaluate_symbol_paths(
                pid=pid,
                companion_elf_path=companion_elf_path,
                expressions=all_exprs,
                adapter=target_adapter,
            )
            flat: Dict[str, Any] = {}
            raw_list = eval_res.get("results", [])
            for item in raw_list:
                if item.get("status") == "OBSERVED":
                    ex = item["expression"]
                    val = item.get("value")
                    flat[ex] = val
                    if isinstance(val, dict):
                        for k, v in val.items():
                            flat[f"{ex}.{k}"] = v
                            flat[f"{ex}->{k}"] = v
            return flat, raw_list

        t_start_ns = time.monotonic_ns()
        baseline_flat, baseline_raw = _sample_flat()
        samples_taken = 1
        triggered = False
        hold_start_ns: Optional[int] = None
        latest_flat = dict(baseline_flat)
        latest_raw = list(baseline_raw)
        latest_clause_evals: List[Dict[str, Any]] = []

        while True:
            now_ns = time.monotonic_ns()
            is_match, clause_evals = self._evaluate_parsed_clauses(
                combinator, clauses, latest_flat, baseline_flat
            )
            latest_clause_evals = clause_evals

            if is_match:
                if clamped_hold_ms <= 0:
                    triggered = True
                    break
                if hold_start_ns is None:
                    hold_start_ns = now_ns
                elif (now_ns - hold_start_ns) >= clamped_hold_ms * 1_000_000:
                    triggered = True
                    break
            else:
                hold_start_ns = None

            elapsed_ms_now = (now_ns - t_start_ns) / 1_000_000.0
            if elapsed_ms_now >= clamped_timeout_ms:
                break

            sleep_s = min(clamped_poll_ms, max(5.0, clamped_timeout_ms - elapsed_ms_now)) / 1000.0
            time.sleep(sleep_s)
            latest_flat, latest_raw = _sample_flat()
            samples_taken += 1

        total_elapsed_ms = round((time.monotonic_ns() - t_start_ns) / 1_000_000.0, 2)

        # Compute before vs trigger/final diff
        changed: List[Dict[str, Any]] = []
        unchanged: List[Dict[str, Any]] = []
        for k, before_v in baseline_flat.items():
            after_v = latest_flat.get(k)
            if isinstance(before_v, dict) or isinstance(after_v, dict):
                continue
            if before_v != after_v:
                delta = None
                if isinstance(before_v, (int, float)) and isinstance(after_v, (int, float)):
                    delta = after_v - before_v
                changed.append({
                    "path": k,
                    "before": before_v,
                    "after": after_v,
                    "delta": delta,
                })
            else:
                unchanged.append({"path": k, "value": after_v})

        # Optional automatic thread owner lookup on hit
        owner_trace = None
        owner_target = (find_owner_on_hit or "").strip()
        if not owner_target and triggered and cond_symbols:
            # If a condition references an indexed slot like gpMem->buffers[9].in_use, strip trailing field
            cand = cond_symbols[0]
            m_slot = re.match(r"^(.+\[\d+\])(?:\.[A-Za-z0-9_]+)?$", cand)
            if m_slot:
                owner_target = m_slot.group(1)

        if triggered and owner_target:
            try:
                owner_trace = self.find_symbol_owners_and_threads(
                    pid=pid,
                    companion_elf_path=companion_elf_path,
                    target_expression=owner_target,
                    adapter=target_adapter,
                )
            except Exception:
                owner_trace = None

        return {
            "pid": pid,
            "target_host": target_adapter.target_host(),
            "is_remote": target_adapter.is_remote(),
            "stop_duration_ms": 0.0,
            "condition_expression": condition_expression,
            "combinator": combinator,
            "triggered": triggered,
            "samples_taken": samples_taken,
            "poll_interval_ms": clamped_poll_ms,
            "hold_duration_ms": clamped_hold_ms,
            "elapsed_ms": total_elapsed_ms,
            "clause_evaluations": latest_clause_evals,
            "trigger_snapshot": latest_raw,
            "changed": changed,
            "unchanged": unchanged[:30],
            "owner_trace_on_hit": owner_trace,
            "llm_next_step_hint": (
                f"Condition '{condition_expression}' TRIGGERED after {total_elapsed_ms}ms ({samples_taken} zero-stop samples). "
                + (
                    f"Owner lookup identified {owner_trace['matched_threads_count']} thread(s) holding '{owner_target}'."
                    if owner_trace and owner_trace.get("matched_threads_count")
                    else f"{len(changed)} field(s) mutated during the watch window."
                )
                if triggered
                else f"Condition '{condition_expression}' did not trigger within {clamped_timeout_ms}ms ({samples_taken} samples). Inspect `clause_evaluations` to see current values."
            ),
        }

    def auto_triage_incident(
        self,
        pid: int,
        companion_elf_path: str,
        remote_host: Optional[str] = None,
        ssh_user: Optional[str] = None,
        ssh_port: int = 22,
        ssh_key: Optional[str] = None,
        ssh_proxy_jump: Optional[str] = None,
        adapter: Optional[TargetExecutionAdapter] = None,
    ) -> Dict[str, Any]:
        """1-Call Composite Zero-Stop Incident Auto-Triage & Root-Cause Correlator.
        Executes in a single pass without stopping the target:
        1. Process X-Ray Blueprint discovery
        2. Memory & Pointer Integrity Audit (`audit_memory_integrity`)
        3. Thread Callstacks, Mutex Contention & Deadlock Check (`inspect_thread_callstacks_and_locks`)
        4. Memory Pool Utilization & Allocated Slot Ownership Sweep (`scan_memory_pool_or_array`)
        5. Linked List / Queue Pointer Chain Cycle Sweep (`traverse_linked_structure`)
        Synthesizes ranked root-cause `findings` and `source_remediation_targets`.
        """
        target_adapter = self._resolve_adapter(
            pid=pid,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
            adapter=adapter,
        )
        t_start_ns = time.monotonic_ns()

        limitations: List[str] = []
        try:
            blueprint = self.get_process_xray_blueprint(
                pid=pid,
                companion_elf_path=companion_elf_path,
                adapter=target_adapter,
            )
        except Exception as bp_exc:
            limitations.append(f"get_process_xray_blueprint failed: {type(bp_exc).__name__}: {bp_exc}")
            blueprint = {"categories": {}}

        try:
            audit_res = self.audit_memory_integrity(
                pid=pid,
                companion_elf_path=companion_elf_path,
                adapter=target_adapter,
            )
            for lim in (audit_res.get("limitations") or []):
                if lim not in limitations:
                    limitations.append(lim)
            if audit_res.get("health_status") == "INCONCLUSIVE" and not audit_res.get("limitations"):
                limitations.append("audit_memory_integrity returned INCONCLUSIVE")
        except Exception as au_exc:
            err_msg = f"audit_memory_integrity failed: {type(au_exc).__name__}: {au_exc}"
            limitations.append(err_msg)
            audit_res = {"health_status": "INCONCLUSIVE", "anomalies": [], "limitations": [err_msg]}

        try:
            callstack_res = self.inspect_thread_callstacks_and_locks(
                pid=pid,
                companion_elf_path=companion_elf_path,
                adapter=target_adapter,
            )
            for lim in (callstack_res.get("limitations") or []):
                if lim not in limitations:
                    limitations.append(lim)
            if callstack_res.get("status") == "INCONCLUSIVE" and not callstack_res.get("limitations"):
                limitations.append("inspect_thread_callstacks_and_locks returned INCONCLUSIVE")
        except Exception as cs_exc:
            err_msg = f"inspect_thread_callstacks_and_locks failed: {type(cs_exc).__name__}: {cs_exc}"
            limitations.append(err_msg)
            callstack_res = {"status": "INCONCLUSIVE", "threads": [], "locks": [], "deadlock_detected": False, "limitations": [err_msg]}

        findings: List[Dict[str, Any]] = []
        source_targets: List[str] = []

        # 1. Check Deadlocks & Mutex Contention
        if callstack_res.get("deadlock_detected"):
            for cyc in callstack_res.get("deadlock_cycles", []):
                desc = " -> ".join(f"TID {e['waiter_tid']} ({e['waiter_name']}) waits on {e['lock_name']} held by TID {e['owner_tid']}" for e in cyc)
                findings.append({
                    "severity": "CRITICAL",
                    "category": "DEADLOCK",
                    "title": "Circular Mutex Deadlock Detected",
                    "summary": desc,
                    "recommended_action": "Inspect lock acquisition order in the involved thread functions.",
                })
        for lk in callstack_res.get("locks", []):
            if lk.get("is_locked") and lk.get("owner_tid"):
                owner_th = next((t for t in callstack_res.get("threads", []) if t["tid"] == lk["owner_tid"]), None)
                # IMP-011: CFI stacks start with the (source-less) libc wait frames: take the first frame with a source line
                top_loc = next((f.get("source_location") for f in ((owner_th or {}).get("callstack") or [])
                                if f.get("source_location")), None)
                if top_loc and top_loc not in source_targets:
                    source_targets.append(top_loc)
                findings.append({
                    "severity": "HIGH" if lk.get("waiting_tids") else "MEDIUM",
                    "category": "MUTEX_LOCK_HELD",
                    "title": f"Mutex '{lk['name']}' Held by TID {lk['owner_tid']} ({lk.get('owner_thread_name')})",
                    "summary": f"Mutex {lk['name']} ({lk['runtime_address']}) is locked by TID {lk['owner_tid']}" + (f" with waiting threads {lk['waiting_tids']}" if lk.get("waiting_tids") else ""),
                    "source_location": top_loc,
                    "recommended_action": f"Check why TID {lk['owner_tid']} ({lk.get('owner_thread_name')}) is holding '{lk['name']}' without releasing it.",
                })

        # 2. Check Memory Corruption & Pointer Integrity Anomalies
        for anom in audit_res.get("anomalies", []):
            findings.append({
                "severity": "CRITICAL" if anom["anomaly_kind"] in ("DANGLING_OR_UNMAPPED_POINTER", "CORRUPTED_BOOL_VALUE") else "HIGH",
                "category": "MEMORY_CORRUPTION",
                "title": f"{anom['anomaly_kind']} on '{anom['expression']}'",
                "summary": anom["detail"],
                "recommended_action": f"Inspect writes to '{anom['expression']}' ({anom['runtime_address']}) and adjacent struct fields for buffer overflow or use-after-free.",
            })

        # 3. Sweep Discovered Memory Pools
        pool_reports: List[Dict[str, Any]] = []
        pools_meta = blueprint.get("categories", {}).get("memory_pools_and_buffers", [])
        for pm in pools_meta[:3]:
            expr = pm.get("recommended_pool_expression") or pm.get("name")
            if not expr:
                continue
            try:
                p_scan = self.scan_memory_pool_or_array(
                    pid=pid,
                    companion_elf_path=companion_elf_path,
                    base_expression=expr,
                    adapter=target_adapter,
                )
                pool_reports.append(p_scan)
                util = p_scan["pool_summary"]["utilization_pct"]
                if util >= 75.0:
                    findings.append({
                        "severity": "HIGH" if util >= 90.0 else "MEDIUM",
                        "category": "MEMORY_POOL_PRESSURE",
                        "title": f"High Memory Pool Utilization on '{p_scan['resolved_array_expression']}' ({util}%)",
                        "summary": f"{p_scan['pool_summary']['allocated_count']}/{p_scan['pool_summary']['total_slots']} slots allocated.",
                        "recommended_action": "Run `runtime_find_symbol_owners` on allocated slot indices to identify leaking threads.",
                    })
            except Exception as pool_exc:
                limitations.append(f"scan_memory_pool_or_array('{expr}') failed: {type(pool_exc).__name__}: {pool_exc}")

        # 4. Sweep Discovered Linked-List Head Pointers for Cycles or Dangling Links
        linked_list_reports: List[Dict[str, Any]] = []
        try:
            primary_elf, _ = self._split_companion_elf_paths(companion_elf_path)
            idx = DwarfIndexer.get_index(primary_elf)
            for var in idx.variables:
                if var.link_time_address is None or var.is_declaration or not var.name or var.name.startswith("__"):
                    continue
                canon_t = idx.resolve_canonical_type(var.type_offset)
                if canon_t and canon_t.tag == "DW_TAG_pointer_type":
                    target_t = idx.resolve_canonical_type(canon_t.target_type_offset)
                    if target_t and target_t.tag in ("DW_TAG_structure_type", "DW_TAG_class_type"):
                        has_next = any(m.name in ("next", "p_next", "next_node") for m in target_t.members)
                        if has_next:
                            try:
                                ll_res = self.traverse_linked_structure(
                                    pid=pid,
                                    companion_elf_path=companion_elf_path,
                                    head_expression=var.name,
                                    max_depth=64,
                                    adapter=target_adapter,
                                )
                                linked_list_reports.append(ll_res)
                                if ll_res.get("cycle_detected"):
                                    findings.append({
                                        "severity": "CRITICAL",
                                        "category": "LINKED_LIST_CYCLE",
                                        "title": f"Infinite Pointer Cycle in Linked List '{var.name}'",
                                        "summary": ll_res["llm_next_step_hint"],
                                        "recommended_action": f"Fix list insertion/removal logic on '{var.name}' where node points back to index #{ll_res['cycle_target_index']}.",
                                    })
                                elif ll_res.get("corrupted_link_detected"):
                                    findings.append({
                                        "severity": "CRITICAL",
                                        "category": "LINKED_LIST_CORRUPTION",
                                        "title": f"Corrupted Pointer Link in Linked List '{var.name}'",
                                        "summary": ll_res["llm_next_step_hint"],
                                        "recommended_action": f"Inspect node link mutation on '{var.name}' (unmapped address {ll_res.get('corrupted_address')}).",
                                    })
                            except Exception as ll_exc:
                                limitations.append(f"traverse_linked_structure('{var.name}') failed: {type(ll_exc).__name__}: {ll_exc}")
        except Exception as idx_exc:
            limitations.append(f"DWARF linked-list sweep failed: {type(idx_exc).__name__}: {idx_exc}")

        # IMP-017: this is a finding SCAN; it decides no verdict of its own.  Its status is the one verdict
        # vocabulary via the aggregator's explicit scan mapping (a scan never certifies health; a collection
        # failure without findings is INCONCLUSIVE; a scan finding is at most PROBABLE_FAULT).
        sev_Order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        findings.sort(key=lambda f: sev_Order.get(f.get("severity", "LOW"), 3))
        overall_status = verdict_for_scan(findings)
        score = health_score_for(overall_status, findings)
        severity_counts = {k: sum(1 for f in findings if f.get("severity") == k) for k in sev_Order}

        latency_us = round((time.monotonic_ns() - t_start_ns) / 1000.0, 2)
        return {
            "pid": pid,
            "target_host": target_adapter.target_host(),
            "is_remote": target_adapter.is_remote(),
            "collection_mode": "ZERO_STOP",
            "stop_duration_ms": 0.0,
            "evaluation_latency_us": latency_us,
            "overall_status": overall_status,
            "verdict": overall_status,
            "health_score": score,
            "severity_counts": severity_counts,
            "limitations": limitations,
            "findings_count": len(findings),
            "findings": findings,
            "source_remediation_targets": source_targets,
            "memory_audit": audit_res,
            "callstacks_and_locks": callstack_res,
            "memory_pools": pool_reports,
            "linked_lists": linked_list_reports,
            "llm_next_step_hint": (
                f"Auto-Triage found {len(findings)} issue(s) (Status: {overall_status}). Top finding: [{findings[0]['severity']}] {findings[0]['title']} — {findings[0]['summary']}"
                if findings
                else (
                    f"Auto-Triage inconclusive due to collection failure(s): {'; '.join(limitations[:3])}"
                    if limitations
                    else "Auto-Triage found no issue in the audited symbols, pools, locks and linked lists. A scan does "
                         "not certify the process healthy: run diagnose for a verdict."
                )
            ),
        }

    # -------------------------------------------------------------------------
    # Phase 43 (Phase 13): Autonomous Symptom Investigator, Cross-Entity
    #                      Dependency Graph Synthesizer, and Source-to-Runtime
    #                      Inline Correlator
    # -------------------------------------------------------------------------

    def build_dependency_graph(
        self,
        pid: int,
        companion_elf_path: str,
        remote_host: Optional[str] = None,
        ssh_user: Optional[str] = None,
        ssh_port: int = 22,
        ssh_key: Optional[str] = None,
        ssh_proxy_jump: Optional[str] = None,
        adapter: Optional[TargetExecutionAdapter] = None,
    ) -> Dict[str, Any]:
        """Synthesizes a directed cross-entity dependency & causal graph across:
        `[Process] ➔ [Thread] ➔ [Mutex Lock / Stack Frame] ➔ [Memory Pool Slot / Heap Object] ➔ [Shared Memory Peer]`
        without stopping the target, and identifies `root_blocker_nodes` and `causal_chains`.
        """
        target_adapter = self._resolve_adapter(
            pid=pid,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
            adapter=adapter,
        )
        t_start_ns = time.monotonic_ns()
        primary_elf, _ = self._split_companion_elf_paths(companion_elf_path)
        if not primary_elf:
            raise ValueError("Valid companion ELF path is required")

        blueprint = self.get_process_xray_blueprint(
            pid=pid,
            companion_elf_path=companion_elf_path,
            adapter=target_adapter,
        )
        callstacks = self.inspect_thread_callstacks_and_locks(
            pid=pid,
            companion_elf_path=companion_elf_path,
            adapter=target_adapter,
        )
        ipc_res = self.trace_ipc_pipeline(
            pid=pid,
            companion_elf_path=companion_elf_path,
            adapter=target_adapter,
        )

        nodes: Dict[str, Dict[str, Any]] = {}
        edges: List[Dict[str, Any]] = []

        def _add_node(node_id: str, kind: str, label: str, status: str = "NORMAL", meta: Optional[Dict[str, Any]] = None) -> None:
            if node_id not in nodes:
                nodes[node_id] = {
                    "id": node_id,
                    "kind": kind,
                    "label": label,
                    "status": status,
                    "metadata": meta or {},
                }
            else:
                if status in ("CRITICAL", "BLOCKED", "CONTENDED") and nodes[node_id]["status"] == "NORMAL":
                    nodes[node_id]["status"] = status
                if meta:
                    nodes[node_id]["metadata"].update(meta)

        def _add_edge(src: str, dst: str, relation: str, detail: str = "") -> None:
            for e in edges:
                if e["from"] == src and e["to"] == dst and e["relation"] == relation:
                    return
            edges.append({
                "from": src,
                "to": dst,
                "relation": relation,
                "detail": detail,
            })

        # 1. Process Node
        proc_node_id = f"PROC:{pid}"
        _add_node(
            proc_node_id,
            kind="PROCESS",
            label=f"PID {pid} ({os.path.basename(primary_elf)})",
            status="NORMAL",
            meta={"pid": pid, "load_bias": blueprint.get("load_bias")},
        )

        # 2. Thread & Lock Nodes
        threads_by_tid: Dict[int, Dict[str, Any]] = {}
        for t in callstacks.get("threads", []):
            tid_val = int(t["tid"])
            threads_by_tid[tid_val] = t
            t_node_id = f"THREAD:{tid_val}"
            top_frame = t["callstack"][0] if t.get("callstack") else None
            wait_lock = t.get("waiting_on_lock")
            t_status = "BLOCKED" if wait_lock else "NORMAL"
            _add_node(
                t_node_id,
                kind="THREAD",
                label=f"TID {tid_val} ({t.get('name', 'thread')})",
                status=t_status,
                meta={
                    "tid": tid_val,
                    "name": t.get("name"),
                    "state": t.get("state"),
                    "syscall": t.get("syscall"),
                    "top_function": top_frame.get("function_name") if top_frame else None,
                    "source_location": next((f.get("source_location") for f in (t.get("callstack") or [])
                                             if f.get("source_location")), None),
                },
            )
            _add_edge(proc_node_id, t_node_id, "HAS_THREAD")

        for lk in callstacks.get("locks", []):
            lk_name = lk["name"]
            lk_node_id = f"LOCK:{lk_name}"
            is_contended = bool(lk.get("waiting_tids"))
            _add_node(
                lk_node_id,
                kind="MUTEX_LOCK",
                label=f"Mutex {lk_name} ({lk.get('runtime_address')})",
                status="CONTENDED" if is_contended else ("LOCKED" if lk.get("is_locked") else "NORMAL"),
                meta=lk,
            )
            owner_tid = lk.get("owner_tid")
            if owner_tid:
                owner_id = f"THREAD:{owner_tid}"
                _add_node(owner_id, kind="THREAD", label=f"TID {owner_tid} ({lk.get('owner_thread_name') or 'thread'})")
                _add_edge(
                    lk_node_id,
                    owner_id,
                    "HELD_BY_THREAD",
                    detail=f"Mutex {lk_name} is held by TID {owner_tid}",
                )
            for w_tid in (lk.get("waiting_tids") or []):
                waiter_id = f"THREAD:{w_tid}"
                _add_node(waiter_id, kind="THREAD", label=f"TID {w_tid}", status="BLOCKED")
                _add_edge(
                    waiter_id,
                    lk_node_id,
                    "WAITS_ON_LOCK",
                    detail=f"TID {w_tid} blocked in futex waiting for {lk_name}",
                )

        # 3. Memory Pool & Occupied Buffer Slot Ownership Edges
        pools_meta = blueprint.get("categories", {}).get("memory_pools_and_buffers", [])
        for pm in pools_meta[:2]:
            expr = pm.get("recommended_pool_expression") or pm.get("name")
            if not expr:
                continue
            try:
                p_scan = self.scan_memory_pool_or_array(
                    pid=pid,
                    companion_elf_path=companion_elf_path,
                    base_expression=expr,
                    adapter=target_adapter,
                )
                arr_expr = p_scan["resolved_array_expression"]
                pool_id = f"POOL:{arr_expr}"
                util_pct = p_scan["pool_summary"]["utilization_pct"]
                _add_node(
                    pool_id,
                    kind="MEMORY_POOL",
                    label=f"Pool {arr_expr} ({p_scan['pool_summary']['allocated_count']}/{p_scan['pool_summary']['total_slots']} IN_USE, {util_pct}%)",
                    status="CONTENDED" if util_pct >= 75.0 else "NORMAL",
                    meta=p_scan["pool_summary"],
                )
                _add_edge(proc_node_id, pool_id, "OWNS_POOL")

                # Inspect up to 4 allocated slots to link slots -> owner threads
                for alloc_idx in p_scan["pool_summary"].get("allocated_indices", [])[:4]:
                    slot_expr = f"{arr_expr}[{alloc_idx}]"
                    slot_node_id = f"SLOT:{slot_expr}"
                    owner_res = self.find_symbol_owners_and_threads(
                        pid=pid,
                        companion_elf_path=companion_elf_path,
                        target_expression=slot_expr,
                        adapter=target_adapter,
                    )
                    _add_node(
                        slot_node_id,
                        kind="BUFFER_SLOT",
                        label=f"{slot_expr} ({owner_res.get('target_runtime_address')})",
                        status="IN_USE",
                        meta={
                            "expression": slot_expr,
                            "runtime_address": owner_res.get("target_runtime_address"),
                        },
                    )
                    _add_edge(pool_id, slot_node_id, "HAS_ALLOCATED_SLOT")
                    for mt in owner_res.get("matched_threads", []):
                        mt_tid = int(mt["tid"])
                        t_node_id = f"THREAD:{mt_tid}"
                        _add_node(t_node_id, kind="THREAD", label=f"TID {mt_tid} ({mt.get('thread_name', 'thread')})")
                        ev_kind = (mt.get("evidence") or [{}])[0].get("evidence_kind", "REFERENCES_SLOT")
                        _add_edge(
                            t_node_id,
                            slot_node_id,
                            "OCCUPIES_SLOT",
                            detail=f"TID {mt_tid} ({mt.get('thread_name')}) holds {slot_expr} via {ev_kind}",
                        )
            except Exception:
                pass

        # 4. Shared Memory IPC & Peer Process Edges
        for shm in ipc_res.get("shared_mappings", []):
            shm_path = shm.get("pathname") or shm.get("start")
            shm_id = f"SHM:{shm_path}"
            p_health = ipc_res.get("pipeline_health", "HEALTHY_PIPELINE")
            _add_node(
                shm_id,
                kind="SHARED_MEMORY",
                label=f"SHM {shm_path} ({p_health})",
                status="CONTENDED" if p_health != "HEALTHY_PIPELINE" else "NORMAL",
                meta=ipc_res.get("metrics") or {},
            )
            _add_edge(proc_node_id, shm_id, "MAPS_SHM", detail=ipc_res.get("bottleneck_diagnosis", ""))
            for peer in ipc_res.get("peer_processes", []):
                if peer.get("shared_pathname") == shm_path or not peer.get("shared_pathname"):
                    peer_id = f"PEER_PROC:{peer['peer_pid']}"
                    _add_node(
                        peer_id,
                        kind="PEER_PROCESS",
                        label=f"Peer PID {peer['peer_pid']} ({peer.get('peer_name', 'peer')})",
                        status="NORMAL",
                        meta=peer,
                    )
                    _add_edge(shm_id, peer_id, "SHARED_WITH_PEER")

        # Synthesize Root Blocker Nodes & Human/LLM-Readable Causal Chains
        root_blocker_nodes: List[Dict[str, Any]] = []
        causal_chains: List[Dict[str, Any]] = []

        # Pattern 1: Thread A waits on Lock L held by Thread B (which may also occupy a Buffer Slot)
        for e_wait in edges:
            if e_wait["relation"] != "WAITS_ON_LOCK":
                continue
            waiter_id = e_wait["from"]
            lock_id = e_wait["to"]
            holder_edges = [e for e in edges if e["from"] == lock_id and e["relation"] == "HELD_BY_THREAD"]
            for eh in holder_edges:
                holder_id = eh["to"]
                holder_node = nodes.get(holder_id, {})
                waiter_node = nodes.get(waiter_id, {})
                lock_node = nodes.get(lock_id, {})
                held_slots = [e["to"] for e in edges if e["from"] == holder_id and e["relation"] == "OCCUPIES_SLOT"]

                chain_steps = [
                    f"{waiter_node.get('label', waiter_id)} is BLOCKED waiting on {lock_node.get('label', lock_id)}",
                    f"{lock_node.get('label', lock_id)} is currently HELD by {holder_node.get('label', holder_id)} at {holder_node.get('metadata', {}).get('source_location') or holder_node.get('metadata', {}).get('top_function') or 'active frame'}",
                ]
                if held_slots:
                    chain_steps.append(f"{holder_node.get('label', holder_id)} simultaneously occupies {', '.join(held_slots)}")

                causal_chains.append({
                    "chain_type": "LOCK_CONTENTION_CHAIN",
                    "root_blocker_id": holder_id,
                    "root_blocker_label": holder_node.get("label", holder_id),
                    "source_location": holder_node.get("metadata", {}).get("source_location"),
                    "impacted_entities": [waiter_id, lock_id] + held_slots,
                    "steps": chain_steps,
                    "ascii_flow": f"[{waiter_node.get('label', waiter_id)}] ──(waits)──▶ [{lock_node.get('label', lock_id)}] ──(held by)──▶ [{holder_node.get('label', holder_id)}]"
                    + (f" ──(occupies)──▶ [{', '.join(held_slots)}]" if held_slots else ""),
                })
                if not any(r["id"] == holder_id for r in root_blocker_nodes):
                    root_blocker_nodes.append(holder_node)

        # Pattern 2: Thread occupies buffer slots even when no mutex is contended
        for e_slot in edges:
            if e_slot["relation"] != "OCCUPIES_SLOT":
                continue
            holder_id = e_slot["from"]
            slot_id = e_slot["to"]
            holder_node = nodes.get(holder_id, {})
            slot_node = nodes.get(slot_id, {})
            if not any(c.get("root_blocker_id") == holder_id for c in causal_chains):
                causal_chains.append({
                    "chain_type": "RESOURCE_HOLD_CHAIN",
                    "root_blocker_id": holder_id,
                    "root_blocker_label": holder_node.get("label", holder_id),
                    "source_location": holder_node.get("metadata", {}).get("source_location"),
                    "impacted_entities": [slot_id],
                    "steps": [
                        f"{holder_node.get('label', holder_id)} occupies {slot_node.get('label', slot_id)}",
                    ],
                    "ascii_flow": f"[{holder_node.get('label', holder_id)}] ──(occupies)──▶ [{slot_node.get('label', slot_id)}]",
                })

        # Pattern 3: Shared Memory IPC Backlog Chain
        if ipc_res.get("pipeline_health") not in (None, "HEALTHY_PIPELINE"):
            peers = ipc_res.get("peer_processes") or []
            peer_label = f"PID {peers[0]['peer_pid']} ({peers[0]['peer_name']})" if peers else "Consumer Process"
            causal_chains.append({
                "chain_type": "IPC_BACKLOG_CHAIN",
                "root_blocker_id": f"PEER_PROC:{peers[0]['peer_pid']}" if peers else proc_node_id,
                "root_blocker_label": peer_label,
                "source_location": None,
                "impacted_entities": [proc_node_id],
                "steps": [ipc_res.get("bottleneck_diagnosis", "")],
                "ascii_flow": f"[PID {pid}] ──(SHM backlog {ipc_res.get('metrics', {}).get('pending_backlog', 0)})──▶ [{peer_label}]",
            })

        latency_us = round((time.monotonic_ns() - t_start_ns) / 1000.0, 2)
        return {
            "pid": pid,
            "target_host": target_adapter.target_host(),
            "is_remote": target_adapter.is_remote(),
            "stop_duration_ms": 0.0,
            "evaluation_latency_us": latency_us,
            "nodes_count": len(nodes),
            "edges_count": len(edges),
            "nodes": list(nodes.values()),
            "edges": edges,
            "root_blocker_nodes": root_blocker_nodes,
            "causal_chains": causal_chains,
            "llm_next_step_hint": (
                f"Synthesized {len(causal_chains)} causal chain(s) across {len(nodes)} runtime entities. "
                + (f"Top root blocker: {causal_chains[0]['ascii_flow']}" if causal_chains else "No blocking dependency chains detected.")
            ),
        }

    def correlate_source_and_state(
        self,
        pid: int,
        companion_elf_path: str,
        source_location: Optional[str] = None,
        tid: Optional[int] = None,
        context_lines: int = 8,
        source_search_dirs: Optional[List[str]] = None,
        remote_host: Optional[str] = None,
        ssh_user: Optional[str] = None,
        ssh_port: int = 22,
        ssh_key: Optional[str] = None,
        ssh_proxy_jump: Optional[str] = None,
        adapter: Optional[TargetExecutionAdapter] = None,
    ) -> Dict[str, Any]:
        """Correlates DWARF `file:line` source locations and active stack frames with real C/C++
        source code files on disk, overlaying live runtime values of parameters, local variables,
        and referenced global symbols inline (`annotated_lines`) without stopping the target.
        """
        target_adapter = self._resolve_adapter(
            pid=pid,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
            adapter=adapter,
        )
        t_start_ns = time.monotonic_ns()
        primary_elf, _ = self._split_companion_elf_paths(companion_elf_path)
        if not primary_elf:
            raise ValueError("Valid companion ELF path is required")

        idx = DwarfIndexer.get_index(primary_elf)
        elf_dir = os.path.dirname(os.path.abspath(primary_elf))
        search_dirs = list(source_search_dirs or []) + [elf_dir, os.getcwd(), "/tmp"]

        # Decode active thread frame locals/parameters so we can overlay them onto source lines
        frame_locals_res = self.inspect_thread_locals_and_frame_vars(
            pid=pid,
            companion_elf_path=companion_elf_path,
            tid=tid,
            max_frames=6,
            adapter=target_adapter,
        )

        # Collect target (file, line, function_name, live_vars_dict) tuples to annotate
        targets_to_annotate: List[Dict[str, Any]] = []

        if source_location and ":" in source_location:
            f_part, l_part = source_location.rsplit(":", 1)
            try:
                line_no = int(l_part.strip())
            except ValueError:
                line_no = 1
            live_map: Dict[str, Any] = {}
            matched_fn = None
            for th in frame_locals_res.get("threads", []):
                for fr in th.get("frames", []):
                    fr_loc = fr.get("source_location") or ""
                    if os.path.basename(f_part) in fr_loc:
                        matched_fn = fr.get("function_name")
                        for p in fr.get("parameters", []):
                            live_map[p["name"]] = p["value"]
                        for l in fr.get("locals", []):
                            live_map[l["name"]] = l["value"]
            targets_to_annotate.append({
                "file_hint": f_part.strip(),
                "target_line": line_no,
                "function_name": matched_fn,
                "tid": tid,
                "live_variables": live_map,
            })
        else:
            for th in frame_locals_res.get("threads", []):
                for fr in th.get("frames", [])[:2]:
                    fr_loc = fr.get("source_location")
                    if not fr_loc or ":" not in fr_loc:
                        continue
                    f_part, l_part = fr_loc.rsplit(":", 1)
                    try:
                        line_no = int(l_part.strip())
                    except ValueError:
                        continue
                    live_map = {}
                    for p in fr.get("parameters", []):
                        live_map[p["name"]] = p["value"]
                    for l in fr.get("locals", []):
                        live_map[l["name"]] = l["value"]
                    targets_to_annotate.append({
                        "file_hint": f_part.strip(),
                        "target_line": line_no,
                        "function_name": fr.get("function_name"),
                        "tid": th.get("tid"),
                        "thread_name": th.get("name"),
                        "live_variables": live_map,
                    })

        # Also add top global variables to a global lookup table so references in source lines get annotated
        global_var_names = {
            v.name for v in idx.variables
            if v.name and not v.name.startswith("__") and v.link_time_address is not None
        }

        def _locate_source_file(file_hint: str) -> Optional[str]:
            if os.path.isabs(file_hint) and os.path.isfile(file_hint):
                return file_hint
            base_name = os.path.basename(file_hint)
            for d in search_dirs:
                cand1 = os.path.join(d, file_hint)
                if os.path.isfile(cand1):
                    return cand1
                cand2 = os.path.join(d, base_name)
                if os.path.isfile(cand2):
                    return cand2
            return None

        snippets: List[Dict[str, Any]] = []
        clamped_ctx = max(3, min(int(context_lines), 25))

        for tgt in targets_to_annotate[:4]:
            resolved_path = _locate_source_file(tgt["file_hint"])
            t_line = int(tgt["target_line"])
            live_vars = dict(tgt.get("live_variables") or {})

            if resolved_path and os.path.isfile(resolved_path):
                try:
                    with open(resolved_path, "r", encoding="utf-8", errors="replace") as sf:
                        all_lines = sf.read().splitlines()
                except Exception:
                    all_lines = []
            else:
                all_lines = []

            annotated_lines: List[Dict[str, Any]] = []
            if all_lines:
                start_ln = max(1, t_line - clamped_ctx // 2)
                end_ln = min(len(all_lines), t_line + clamped_ctx)
                window_text = "\n".join(all_lines[start_ln - 1 : end_ln])

                # Check if any DWARF global variable appears in this source window
                referenced_globals = [g for g in global_var_names if re.search(rf"\b{re.escape(g)}\b", window_text)]
                if referenced_globals:
                    try:
                        g_eval = self.evaluate_symbol_paths(
                            pid=pid,
                            companion_elf_path=companion_elf_path,
                            expressions=referenced_globals[:6],
                            adapter=target_adapter,
                        )
                        for r in g_eval.get("results", []):
                            if r.get("status") == "OBSERVED" and r.get("expression"):
                                live_vars[r["expression"]] = r.get("value")
                    except Exception:
                        pass

                for ln_no in range(start_ln, end_ln + 1):
                    code_str = all_lines[ln_no - 1]
                    inline_hits: Dict[str, Any] = {}
                    for v_name, v_val in live_vars.items():
                        if re.search(rf"\b{re.escape(v_name)}\b", code_str):
                            inline_hits[v_name] = v_val
                    annotated_lines.append({
                        "line_number": ln_no,
                        "is_target_line": (ln_no == t_line),
                        "code": code_str,
                        "live_annotations": inline_hits,
                        "formatted": (
                            f"{'▶' if ln_no == t_line else ' '} {ln_no:4d} | {code_str}"
                            + (f"   // [LIVE] " + ", ".join(f"{k}={json.dumps(v, ensure_ascii=False)}" for k, v in inline_hits.items()) if inline_hits else "")
                        ),
                    })

            snippets.append({
                "file_hint": tgt["file_hint"],
                "resolved_source_path": resolved_path,
                "target_line": t_line,
                "function_name": tgt.get("function_name"),
                "tid": tgt.get("tid"),
                "thread_name": tgt.get("thread_name"),
                "live_variables": live_vars,
                "annotated_lines": annotated_lines,
                "annotated_code_block": "\n".join(l["formatted"] for l in annotated_lines) if annotated_lines else None,
            })

        latency_us = round((time.monotonic_ns() - t_start_ns) / 1000.0, 2)
        return {
            "pid": pid,
            "target_host": target_adapter.target_host(),
            "is_remote": target_adapter.is_remote(),
            "stop_duration_ms": 0.0,
            "evaluation_latency_us": latency_us,
            "snippets_count": len(snippets),
            "snippets": snippets,
            "llm_next_step_hint": (
                f"Correlated {len(snippets)} active source location(s) with inline live runtime variable values."
                if snippets
                else "No source locations with debug line info were found on active frames."
            ),
        }

    def investigate_symptom(
        self,
        pid: int,
        companion_elf_path: str,
        symptom_query: str = "왜 멈췄지? 전체적인 문제를 종합 분석해줘",
        remote_host: Optional[str] = None,
        ssh_user: Optional[str] = None,
        ssh_port: int = 22,
        ssh_key: Optional[str] = None,
        ssh_proxy_jump: Optional[str] = None,
        adapter: Optional[TargetExecutionAdapter] = None,
    ) -> Dict[str, Any]:
        """Autonomous Symptom-Driven Multi-Stage Root-Cause Investigator (zero-stop; the target is not suspended).
        Accepts a simple, high-level user symptom question (e.g. '왜 멈췄지?', '버벅거려', '메모리가 새는 것 같아',
        '왜 응답이 없지?') and automatically orchestrates:
        1. Symptom Classification (`HANG_OR_DEADLOCK`, `MEMORY_LEAK_OR_EXHAUSTION`, `MEMORY_CORRUPTION`, `IPC_BOTTLENECK`, `GENERAL_ANOMALY`)
        2. One-Call Incident Auto-Triage (`auto_triage_incident`)
        3. Cross-Entity Causal Dependency Graph (`build_dependency_graph`)
        4. Heap Polymorphic Leak Census (`scan_heap_objects`) when memory/leak/general symptoms are present
        5. Source-to-Runtime Inline Code Correlation (`correlate_source_and_state`) on the root blocker frame
        Synthesizes a unified `root_cause_hypothesis`, `causal_chain`, `confidence_score`, and `remediation_plan`.
        """
        target_adapter = self._resolve_adapter(
            pid=pid,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
            adapter=adapter,
        )
        t_start_ns = time.monotonic_ns()
        q_low = (symptom_query or "").lower()

        # 1. Classify user's natural-language symptom intent
        if any(k in q_low for k in ("멈췄", "멈춤", "응답", "락", "데드락", "블록", "hang", "stuck", "freeze", "deadlock", "wait")):
            classified_symptom = "HANG_OR_DEADLOCK"
        elif any(k in q_low for k in ("누수", "새는", "메모리 부족", "고갈", "힙", "leak", "oom", "exhaust")):
            classified_symptom = "MEMORY_LEAK_OR_EXHAUSTION"
        elif any(k in q_low for k in ("깨졌", "오염", "크래시", "세그폴트", "유효하지", "corrupt", "crash", "dangling", "overflow")):
            classified_symptom = "MEMORY_CORRUPTION"
        elif any(k in q_low for k in ("느려", "지연", "밀려", "파이프라인", "큐", "프로듀서", "컨슈머", "slow", "lag", "ipc", "drop")):
            classified_symptom = "PIPELINE_OR_PERF_BOTTLENECK"
        else:
            classified_symptom = "COMPREHENSIVE_SYMPTOM_CHECK"

        # 2. Run composite triage + dependency graph + source correlation + heap scan
        legacy_sweep_errors: List[Dict[str, Any]] = []
        try:
            triage = self.auto_triage_incident(
                pid=pid,
                companion_elf_path=companion_elf_path,
                adapter=target_adapter,
            )
        except Exception as exc:
            legacy_sweep_errors.append({"stage": "auto_triage_incident", "error_type": type(exc).__name__, "error": str(exc)})
            triage = {"overall_status": "INCONCLUSIVE", "health_score": None, "findings": [], "limitations": [f"{type(exc).__name__}: {exc}"], "source_remediation_targets": []}
        try:
            dep_graph = self.build_dependency_graph(
                pid=pid,
                companion_elf_path=companion_elf_path,
                adapter=target_adapter,
            )
        except Exception as exc:
            legacy_sweep_errors.append({"stage": "build_dependency_graph", "error_type": type(exc).__name__, "error": str(exc)})
            dep_graph = {"causal_chains": [], "nodes_count": 0, "edges_count": 0, "nodes": [], "edges": [], "root_blocker_nodes": []}
        try:
            heap_report = self.scan_heap_objects(
                pid=pid,
                companion_elf_path=companion_elf_path,
                adapter=target_adapter,
            )
        except Exception as exc:
            legacy_sweep_errors.append({"stage": "scan_heap_objects", "error_type": type(exc).__name__, "error": str(exc)})
            heap_report = {"leaked_candidates_count": 0, "total_objects_found": 0, "objects": [], "class_histogram": {}}

        # Merge heap leak findings into triage findings if any leaked objects were discovered
        findings = list(triage.get("findings") or [])
        if heap_report.get("leaked_candidates_count", 0) > 0:
            leaked_objs = [o for o in heap_report.get("objects", []) if o.get("is_leaked_candidate")]
            sample_leak = leaked_objs[0]
            findings.append({
                "severity": "HIGH",
                "category": "HEAP_MEMORY_LEAK",
                "title": f"Unreferenced C++ Heap Object Leak ({heap_report['leaked_candidates_count']} instance(s) of {sample_leak['class_name']})",
                "summary": f"Heap object {sample_leak['class_name']} @ {sample_leak['address']} has no incoming pointer from globals, thread stacks, or heap.",
                "recommended_action": f"Verify destructor / smart-pointer lifecycle for dynamically allocated `{sample_leak['class_name']}` instances.",
            })

        # Run statistical hotspot profiler when slowness/CPU/comprehensive symptoms are queried
        hotspot_report = None
        if classified_symptom in ("PIPELINE_OR_PERF_BOTTLENECK", "COMPREHENSIVE_SYMPTOM_CHECK", "HANG_OR_DEADLOCK"):
            try:
                hotspot_report = self.sample_statistical_hotspots(
                    pid=pid,
                    companion_elf_path=companion_elf_path,
                    samples_count=4,
                    interval_ms=25,
                    adapter=target_adapter,
                )
                top_hs = (hotspot_report.get("hotspot_functions") or [None])[0]
                if top_hs and top_hs.get("inclusive_pct", 0) >= 75.0 and not findings:
                    findings.append({
                        "severity": "HIGH",
                        "category": "CPU_HOTSPOT_LOOP",
                        "title": f"High Callstack Residency in `{top_hs['function_name']}()` ({top_hs['inclusive_pct']}%)",
                        "summary": f"Function `{top_hs['function_name']}` ({top_hs.get('source_location')}) appeared in {top_hs['inclusive_pct']}% of statistical samples across {top_hs.get('threads')}.",
                        "source_location": top_hs.get("source_location"),
                        "recommended_action": f"Inspect loop termination condition and sleep/yield intervals inside `{top_hs['function_name']}()`.",
                    })
            except Exception as hs_exc:
                legacy_sweep_errors.append({"stage": "sample_statistical_hotspots", "error_type": type(hs_exc).__name__, "error": str(hs_exc)})
                hotspot_report = None

        # Correlate source code with runtime variables at top remediation target or active thread frame
        top_source_loc = (triage.get("source_remediation_targets") or [None])[0]
        try:
            source_corr = self.correlate_source_and_state(
                pid=pid,
                companion_elf_path=companion_elf_path,
                source_location=top_source_loc,
                adapter=target_adapter,
            )
        except Exception as exc:
            legacy_sweep_errors.append({"stage": "correlate_source_and_state", "error_type": type(exc).__name__, "error": str(exc)})
            source_corr = {"snippets": []}

        # Synthesize primary root-cause hypothesis and step-by-step causal narrative
        causal_chains = dep_graph.get("causal_chains") or []
        if findings or causal_chains:
            top_f = findings[0] if findings else None
            top_chain = causal_chains[0] if causal_chains else None
            if top_chain and top_f:
                hypothesis = f"[{top_f['category']}] {top_f['title']} — {top_chain['ascii_flow']}"
            elif top_f:
                hypothesis = f"[{top_f['category']}] {top_f['title']}: {top_f['summary']}"
            else:
                hypothesis = f"[{top_chain['chain_type']}] {top_chain['ascii_flow']}"
            confidence_score = 0.94 if (top_f and top_f.get("severity") == "CRITICAL") else 0.88
        elif legacy_sweep_errors or triage.get("overall_status") == "INCONCLUSIVE" or triage.get("limitations"):
            lim_parts = [f"{e.get('stage')}: {e.get('error')}" for e in legacy_sweep_errors] + list(triage.get("limitations") or [])
            hypothesis = f"Diagnostic inspection inconclusive due to collection failure(s): {'; '.join(lim_parts[:3])}"
            confidence_score = 0.20
        else:
            hypothesis = "No critical lock contention, memory corruption, or unreferenced heap leak detected in current zero-stop snapshot."
            confidence_score = 0.80

        remediation_steps: List[str] = []
        for f in findings[:4]:
            if f.get("recommended_action") and f["recommended_action"] not in remediation_steps:
                remediation_steps.append(f["recommended_action"])

        # IMP-017: the verification step and the verdict are diagnose() (the retired adaptive engine used to run
        # here).  The scans above are context; they decide nothing.
        diagnosis: Optional[Dict[str, Any]] = None
        diagnosis_error_details: List[Dict[str, Any]] = []
        exec_status = "COMPLETED"
        fail_category: Optional[str] = None
        stop_reason = "SUFFICIENT_EVIDENCE"
        try:
            from . import expert_diagnostic_engine as _ede
            diagnosis = _ede.diagnose(pid, debug_image=companion_elf_path or None, symptom=symptom_query,
                                      adapter=target_adapter, corpus_dir=self.corpus_dir).to_dict()
            if not diagnosis.get("checks_run"):
                exec_status = "INCONCLUSIVE"
            stop_reason = str(diagnosis.get("stop_reason") or stop_reason)
        except Exception as diag_exc:  # noqa: BLE001 - never swallowed: reported and capped below
            exec_status = "FAILED"
            fail_category = type(diag_exc).__name__
            stop_reason = "DIAGNOSIS_EXCEPTION"
            diagnosis_error_details.append({"stage": "diagnose", "error_type": type(diag_exc).__name__,
                                            "error": str(diag_exc)})
            confidence_score = min(confidence_score, 0.35)
        checks = list((diagnosis or {}).get("checks_run") or [])
        actual_obs_cnt = len(checks)
        succ_obs_cnt = sum(1 for c in checks if c.get("status") in ("PASS", "FAIL"))
        fail_obs_cnt = sum(1 for c in checks if c.get("status") == "ERROR")
        abs_obs_cnt = actual_obs_cnt - succ_obs_cnt - fail_obs_cnt
        consumed_budget = dict((diagnosis or {}).get("collection_impact") or {})

        all_symp_limitations = list(triage.get("limitations") or []) + [
            f"{e.get('stage')}: {e.get('error')}" for e in legacy_sweep_errors
        ]
        if diagnosis is not None:
            eff_overall_status = str(diagnosis.get("verdict") or VERDICT_INCONCLUSIVE)
            confidence_score = float(diagnosis.get("confidence") or 0.0)
            if diagnosis.get("findings"):
                top = diagnosis["findings"][0]
                hypothesis = (f"[{top.get('category')}] {top.get('description')}"
                              + (f" (subjects: {', '.join(map(str, (top.get('subjects') or [])[:4]))})"
                                 if top.get("subjects") else ""))
        else:
            eff_overall_status = verdict_for_scan(findings)
        if eff_overall_status == VERDICT_INCONCLUSIVE:
            confidence_score = min(confidence_score, 0.20)
            if stop_reason == "SUFFICIENT_EVIDENCE":
                stop_reason = "NO_USEFUL_SAFE_OBSERVATION_REMAINS"
        eff_health_score = health_score_for(eff_overall_status, (diagnosis or {}).get("findings") or findings)

        latency_us = round((time.monotonic_ns() - t_start_ns) / 1000.0, 2)
        return {
            "pid": pid,
            "target_host": target_adapter.target_host(),
            "is_remote": target_adapter.is_remote(),
            "stop_duration_ms": 0.0,
            "evaluation_latency_us": latency_us,
            "symptom_query": symptom_query,
            "execution_status": exec_status,
            "overall_status": eff_overall_status,
            "failure_category": fail_category,
            "stop_reason": stop_reason,
            "limitations": all_symp_limitations,
            "verdict": eff_overall_status,
            "diagnostic_error_details": diagnosis_error_details,
            "collection_error_details": list(legacy_sweep_errors),
            "actual_observation_count": actual_obs_cnt,
            "successful_observation_count": succ_obs_cnt,
            "failed_observation_count": fail_obs_cnt,
            "abstained_observation_count": abs_obs_cnt,
            "consumed_execution_budget": consumed_budget,
            "diagnosis_succeeded": diagnosis is not None,
            "legacy_findings": list(findings),
            "diagnosis": diagnosis,
            "classified_symptom": classified_symptom,
            "root_cause_hypothesis": hypothesis,
            "confidence_score": confidence_score,
            "health_score": eff_health_score,
            "findings_count": len(findings),
            "findings": findings,
            "causal_chains": causal_chains,
            "dependency_graph": {
                "nodes_count": dep_graph.get("nodes_count", 0),
                "edges_count": dep_graph.get("edges_count", 0),
                "nodes": dep_graph.get("nodes", []),
                "edges": dep_graph.get("edges", []),
                "root_blocker_nodes": dep_graph.get("root_blocker_nodes", []),
            },
            "annotated_source_snippets": source_corr.get("snippets", []),
            "heap_leak_summary": {
                "total_objects_found": heap_report.get("total_objects_found", 0),
                "leaked_candidates_count": heap_report.get("leaked_candidates_count", 0),
                "class_histogram": heap_report.get("class_histogram", {}),
            },
            "statistical_hotspots": hotspot_report,
            "remediation_steps": remediation_steps,
            "llm_next_step_hint": (
                f"Symptom Investigation ({classified_symptom}) complete with confidence {int(confidence_score * 100)}%: {hypothesis}"
            ),
        }

    # -------------------------------------------------------------------------
    # Phase 44 (Phase 14): Zero-Stop Statistical CPU/Callstack Hotspot Profiler
    #                      & Fuzzy Natural-Language Symbol Intent Resolver
    # -------------------------------------------------------------------------

    @staticmethod
    def _read_thread_cpu_ticks_local(pid: int) -> Dict[int, Dict[str, Any]]:
        """Reads `/proc/<pid>/task/<tid>/stat` to extract per-thread `state`, `utime`, and `stime` ticks."""
        out: Dict[int, Dict[str, Any]] = {}
        task_dir = f"/proc/{pid}/task"
        if not os.path.isdir(task_dir):
            return out
        try:
            for tid_str in os.listdir(task_dir):
                if not tid_str.isdigit():
                    continue
                tid_val = int(tid_str)
                stat_path = os.path.join(task_dir, tid_str, "stat")
                try:
                    with open(stat_path, "r", encoding="utf-8") as sf:
                        txt = sf.read()
                    lpar = txt.find("(")
                    rpar = txt.rfind(")")
                    if lpar == -1 or rpar == -1:
                        continue
                    comm = txt[lpar + 1 : rpar]
                    fields = txt[rpar + 1 :].strip().split()
                    # In /proc/[pid]/stat, after `(comm)`:
                    # index 0 is state (field 3), index 11 is utime (field 14), index 12 is stime (field 15)
                    state = fields[0] if len(fields) > 0 else "S"
                    utime = int(fields[11]) if len(fields) > 11 else 0
                    stime = int(fields[12]) if len(fields) > 12 else 0
                    out[tid_val] = {
                        "tid": tid_val,
                        "name": comm,
                        "state": state,
                        "utime": utime,
                        "stime": stime,
                        "total_ticks": utime + stime,
                    }
                except Exception:
                    continue
        except Exception:
            pass
        return out

    def sample_statistical_hotspots(
        self,
        pid: int,
        companion_elf_path: str,
        samples_count: int = 6,
        interval_ms: int = 35,
        remote_host: Optional[str] = None,
        ssh_user: Optional[str] = None,
        ssh_port: int = 22,
        ssh_key: Optional[str] = None,
        ssh_proxy_jump: Optional[str] = None,
        adapter: Optional[TargetExecutionAdapter] = None,
    ) -> Dict[str, Any]:
        """Zero-stop statistical CPU & callstack hotspot profiler (`zero-stop` stop time).
        Takes `samples_count` rapid non-intrusive snapshots across `interval_ms`, measuring:
        1. Per-thread CPU tick deltas (`utime + stime`) and runnable (`R`) vs sleeping (`S`/`D`) ratios.
        2. Function-level callstack appearance frequency (`hotspot_functions`) and folded flame-graph strings (`flame_stacks`).
        3. High-velocity counter/sequence mutation rates (`counter_rates_per_sec`) to distinguish productive work from busy-spin loops.
        """
        target_adapter = self._resolve_adapter(
            pid=pid,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
            adapter=adapter,
        )
        t_start_ns = time.monotonic_ns()
        clamped_samples = max(2, min(int(samples_count), 25))
        clamped_interval_ms = max(10, min(int(interval_ms), 500))

        # Discover candidate counter/sequence expressions from blueprint
        blueprint = self.get_process_xray_blueprint(
            pid=pid,
            companion_elf_path=companion_elf_path,
            adapter=target_adapter,
        )
        counter_exprs: List[str] = []
        for c_item in blueprint.get("categories", {}).get("counters_and_metrics", [])[:6]:
            if c_item.get("name"):
                counter_exprs.append(c_item["name"])
        for s_item in blueprint.get("categories", {}).get("state_machines_and_flags", [])[:4]:
            if s_item.get("name") and s_item["name"] not in counter_exprs:
                counter_exprs.append(s_item["name"])
        primary_elf, _ = self._split_companion_elf_paths(companion_elf_path)
        if primary_elf:
            idx_c = DwarfIndexer.get_index(primary_elf)
            for v in idx_c.variables:
                if v.name and not v.name.startswith("__") and v.link_time_address is not None:
                    if any(k in v.name.lower() for k in ("count", "cnt", "seq", "total", "ticks", "packets", "ops", "ready")):
                        if v.name not in counter_exprs:
                            counter_exprs.insert(0, v.name)

        ticks_t0 = self._read_thread_cpu_ticks_local(pid) if not target_adapter.is_remote() else {}
        counters_t0: Dict[str, float] = {}
        if counter_exprs:
            try:
                ev0 = self.evaluate_symbol_paths(
                    pid=pid,
                    companion_elf_path=companion_elf_path,
                    expressions=counter_exprs,
                    adapter=target_adapter,
                )
                for r in ev0.get("results", []):
                    val = r.get("value")
                    if isinstance(val, (int, float)):
                        counters_t0[r["expression"]] = float(val)
                    elif isinstance(val, str):
                        try:
                            counters_t0[r["expression"]] = float(int(val, 0))
                        except ValueError:
                            pass
            except Exception:
                pass

        # Collect N statistical callstack samples
        func_hit_counts: Dict[str, Dict[str, Any]] = {}
        flame_counts: Dict[str, int] = {}
        thread_runnable_hits: Dict[int, int] = {}
        thread_names: Dict[int, str] = {}

        for s_i in range(clamped_samples):
            cs = self.inspect_thread_callstacks_and_locks(
                pid=pid,
                companion_elf_path=companion_elf_path,
                max_frames=8,
                adapter=target_adapter,
            )
            for th in cs.get("threads", []):
                t_tid = int(th["tid"])
                t_name = th.get("name", f"tid_{t_tid}")
                thread_names[t_tid] = t_name
                if th.get("state") == "R":
                    thread_runnable_hits[t_tid] = thread_runnable_hits.get(t_tid, 0) + 1

                frames = th.get("callstack") or []
                if frames:
                    # Record folded stack from bottom-most frame to top frame
                    chain_names = [f.get("function_name") or "unknown" for f in reversed(frames)]
                    folded_key = f"{t_name};" + ";".join(chain_names)
                    flame_counts[folded_key] = flame_counts.get(folded_key, 0) + 1

                seen_in_sample = set()
                for f_idx, fr in enumerate(frames):
                    fn = fr.get("function_name") or "unknown"
                    entry = func_hit_counts.setdefault(fn, {
                        "function_name": fn,
                        "source_location": fr.get("source_location"),
                        "self_samples": 0,
                        "inclusive_samples": 0,
                        "threads": set(),
                    })
                    if f_idx == 0:
                        entry["self_samples"] += 1
                    if fn not in seen_in_sample:
                        entry["inclusive_samples"] += 1
                        seen_in_sample.add(fn)
                    entry["threads"].add(f"TID {t_tid} ({t_name})")

            if s_i + 1 < clamped_samples:
                time.sleep(clamped_interval_ms / 1000.0)

        elapsed_sec = max(0.001, (time.monotonic_ns() - t_start_ns) / 1_000_000_000.0)
        ticks_t1 = self._read_thread_cpu_ticks_local(pid) if not target_adapter.is_remote() else {}

        # Compute per-thread CPU tick deltas and share %
        total_tick_delta = 0
        thread_profiles: List[Dict[str, Any]] = []
        all_tids = sorted(set(list(thread_names.keys()) + list(ticks_t1.keys())))
        for t_tid in all_tids:
            t0_info = ticks_t0.get(t_tid, {})
            t1_info = ticks_t1.get(t_tid, {})
            d_utime = max(0, int(t1_info.get("utime", 0)) - int(t0_info.get("utime", 0)))
            d_stime = max(0, int(t1_info.get("stime", 0)) - int(t0_info.get("stime", 0)))
            d_total = d_utime + d_stime
            total_tick_delta += d_total
            run_hits = thread_runnable_hits.get(t_tid, 0)
            thread_profiles.append({
                "tid": t_tid,
                "name": thread_names.get(t_tid) or t1_info.get("name", "thread"),
                "state": t1_info.get("state", "S"),
                "utime_delta_ticks": d_utime,
                "stime_delta_ticks": d_stime,
                "total_delta_ticks": d_total,
                "runnable_sample_pct": round((run_hits * 100.0) / clamped_samples, 1),
            })

        for tp in thread_profiles:
            tp["cpu_share_pct"] = (
                round((tp["total_delta_ticks"] * 100.0) / total_tick_delta, 1)
                if total_tick_delta > 0
                else tp["runnable_sample_pct"]
            )
        thread_profiles.sort(key=lambda x: (x["cpu_share_pct"], x["runnable_sample_pct"]), reverse=True)

        # Compute counter velocity (mutations per second)
        counter_rates: List[Dict[str, Any]] = []
        if counters_t0:
            try:
                ev1 = self.evaluate_symbol_paths(
                    pid=pid,
                    companion_elf_path=companion_elf_path,
                    expressions=list(counters_t0.keys()),
                    adapter=target_adapter,
                )
                for r in ev1.get("results", []):
                    expr = r.get("expression")
                    val1 = r.get("value")
                    v1_num = None
                    if isinstance(val1, (int, float)):
                        v1_num = float(val1)
                    elif isinstance(val1, str):
                        try:
                            v1_num = float(int(val1, 0))
                        except ValueError:
                            pass
                    if expr in counters_t0 and v1_num is not None:
                        v0 = counters_t0[expr]
                        v1 = v1_num
                        delta = v1 - v0
                        counter_rates.append({
                            "expression": expr,
                            "before": v0,
                            "after": v1,
                            "delta": delta,
                            "rate_per_sec": round(delta / elapsed_sec, 2),
                        })
            except Exception:
                pass

        # Format ranked hotspot functions
        hotspot_functions: List[Dict[str, Any]] = []
        for fn, info in func_hit_counts.items():
            hotspot_functions.append({
                "function_name": fn,
                "source_location": info["source_location"],
                "self_samples": info["self_samples"],
                "inclusive_samples": info["inclusive_samples"],
                "self_pct": round((info["self_samples"] * 100.0) / clamped_samples, 1),
                "inclusive_pct": round((info["inclusive_samples"] * 100.0) / clamped_samples, 1),
                "threads": sorted(info["threads"]),
            })
        hotspot_functions.sort(key=lambda x: (x["self_samples"], x["inclusive_samples"]), reverse=True)

        flame_stacks = [
            {"folded_stack": k, "samples": v, "pct": round((v * 100.0) / clamped_samples, 1)}
            for k, v in sorted(flame_counts.items(), key=lambda item: item[1], reverse=True)
        ]

        top_fn = hotspot_functions[0] if hotspot_functions else None
        top_th = thread_profiles[0] if thread_profiles else None
        elapsed_ms = round(elapsed_sec * 1000.0, 2)

        return {
            "pid": pid,
            "target_host": target_adapter.target_host(),
            "is_remote": target_adapter.is_remote(),
            "stop_duration_ms": 0.0,
            "samples_taken": clamped_samples,
            "interval_ms": clamped_interval_ms,
            "elapsed_ms": elapsed_ms,
            "thread_cpu_profiles": thread_profiles,
            "hotspot_functions": hotspot_functions,
            "flame_stacks": flame_stacks,
            "counter_rates": counter_rates,
            "llm_next_step_hint": (
                f"Statistical hotspot profiling ({clamped_samples} samples over {elapsed_ms}ms, zero-stop): "
                + (f"Top hotspot function is `{top_fn['function_name']}()` ({top_fn['inclusive_pct']}% inclusive, {top_fn['source_location']}) " if top_fn else "")
                + (f"on thread TID {top_th['tid']} ({top_th['name']}, CPU share {top_th['cpu_share_pct']}%)." if top_th else "")
            ),
        }

    def resolve_fuzzy_symbol_intent(
        self,
        pid: int,
        companion_elf_path: str,
        natural_query: str,
        limit: int = 5,
        remote_host: Optional[str] = None,
        ssh_user: Optional[str] = None,
        ssh_port: int = 22,
        ssh_key: Optional[str] = None,
        ssh_proxy_jump: Optional[str] = None,
        adapter: Optional[TargetExecutionAdapter] = None,
    ) -> Dict[str, Any]:
        """Semantic / Fuzzy Intent-to-Symbol Resolver (zero-stop; the target is not suspended).
        Maps vague natural-language user descriptions (e.g. '버퍼 풀', '워커 스레드', '세션 객체',
        '뮤텍스 락', '작업 리스트', '카운터') to concrete DWARF symbols & member paths, and evaluates
        their live values immediately.
        """
        target_adapter = self._resolve_adapter(
            pid=pid,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
            adapter=adapter,
        )
        t_start_ns = time.monotonic_ns()
        primary_elf, _ = self._split_companion_elf_paths(companion_elf_path)
        if not primary_elf:
            raise ValueError("Valid companion ELF path is required")

        idx = DwarfIndexer.get_index(primary_elf)
        q_low = (natural_query or "").lower()

        # Bilingual semantic concept dictionary (Korean/English -> DWARF symbol/type/member tokens)
        concept_synonyms = [
            (("버퍼", "풀", "메모리 풀", "슬롯", "buffer", "pool", "slot", "slab", "arena"), ("pool", "mem", "buf", "slot", "active_buffers", "total_buffers")),
            (("워커", "스레드", "쓰레드", "작업자", "worker", "thread", "context", "task"), ("worker", "thread", "tid", "ctx", "task")),
            (("락", "뮤텍스", "데드락", "동기화", "lock", "mutex", "futex", "sema"), ("mutex", "lock", "sem", "cond")),
            (("리스트", "큐", "연결", "체인", "노드", "list", "queue", "chain", "node"), ("list", "queue", "head", "tail", "node", "next")),
            (("세션", "채널", "클라이언트", "콜백", "객체", "session", "client", "channel", "callback"), ("session", "client", "chan", "cb", "handler", "poly")),
            (("카운터", "시퀀스", "통계", "에러", "상태", "플래그", "counter", "seq", "stat", "state", "flag", "ready"), ("seq", "count", "cnt", "total", "active", "ready", "state", "err", "running")),
        ]

        expanded_keywords: List[str] = []
        for triggers, targets in concept_synonyms:
            if any(t in q_low for t in triggers):
                for tgt in targets:
                    if tgt not in expanded_keywords:
                        expanded_keywords.append(tgt)

        # Also extract any ASCII identifiers directly mentioned in the query
        for tok in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", natural_query or ""):
            tl = tok.lower()
            if tl not in ("the", "and", "for", "pid", "show", "check") and tl not in expanded_keywords:
                expanded_keywords.append(tl)

        if not expanded_keywords:
            expanded_keywords = ["pool", "mem", "worker", "state", "count", "mutex"]

        scored_candidates: List[Tuple[int, Dict[str, Any]]] = []
        seen_names = set()

        for var in idx.variables:
            if var.link_time_address is None or var.is_declaration or not var.name or var.name.startswith("__"):
                continue
            if var.name in seen_names:
                continue
            seen_names.add(var.name)

            t_name = idx.get_type_name(var.type_offset)
            canon_t = idx.resolve_canonical_type(var.type_offset)
            member_names: List[str] = []
            if canon_t:
                if canon_t.tag in ("DW_TAG_structure_type", "DW_TAG_class_type"):
                    member_names = [m.name for m in canon_t.members if m.name]
                elif canon_t.tag == "DW_TAG_pointer_type":
                    pt = idx.resolve_canonical_type(canon_t.target_type_offset)
                    if pt and pt.tag in ("DW_TAG_structure_type", "DW_TAG_class_type"):
                        member_names = [m.name for m in pt.members if m.name]

            haystack = f"{var.name} {t_name} {' '.join(member_names)}".lower()
            score = 0
            matched_terms: List[str] = []
            for kw in expanded_keywords:
                if kw in var.name.lower():
                    score += 30
                    matched_terms.append(kw)
                elif kw in t_name.lower():
                    score += 20
                    matched_terms.append(kw)
                elif any(kw in mn.lower() for mn in member_names):
                    score += 15
                    matched_terms.append(kw)
                elif kw in haystack:
                    score += 5

            if score > 0:
                rec_expr = f"*{var.name}" if (canon_t and canon_t.tag == "DW_TAG_pointer_type") else var.name
                scored_candidates.append((score, {
                    "symbol_name": var.name,
                    "recommended_expression": rec_expr,
                    "type_name": t_name,
                    "decl_location": f"{var.decl_file}:{var.decl_line}" if var.decl_file else None,
                    "member_fields": member_names[:10],
                    "relevance_score": score,
                    "matched_concepts": matched_terms,
                }))

        scored_candidates.sort(key=lambda item: item[0], reverse=True)
        top_matches = [item[1] for item in scored_candidates[: max(1, min(int(limit), 12))]]

        # Live-evaluate top matched expressions
        eval_exprs = [m["recommended_expression"] for m in top_matches]
        if eval_exprs:
            try:
                ev_res = self.evaluate_symbol_paths(
                    pid=pid,
                    companion_elf_path=companion_elf_path,
                    expressions=eval_exprs,
                    adapter=target_adapter,
                )
                val_by_expr = {r["expression"]: r.get("value") for r in ev_res.get("results", []) if "expression" in r}
                for m in top_matches:
                    m["live_value"] = val_by_expr.get(m["recommended_expression"])
            except Exception:
                pass

        latency_us = round((time.monotonic_ns() - t_start_ns) / 1000.0, 2)
        return {
            "pid": pid,
            "target_host": target_adapter.target_host(),
            "is_remote": target_adapter.is_remote(),
            "stop_duration_ms": 0.0,
            "evaluation_latency_us": latency_us,
            "natural_query": natural_query,
            "expanded_keywords": expanded_keywords,
            "matches_count": len(top_matches),
            "matches": top_matches,
            "llm_next_step_hint": (
                f"Resolved '{natural_query}' to {len(top_matches)} DWARF symbol(s): "
                + ", ".join(f"{m['recommended_expression']} ({m['type_name']})" for m in top_matches[:3])
                if top_matches
                else f"No matching DWARF symbols found for '{natural_query}'."
            ),
        }

    # -------------------------------------------------------------------------
    # Phase 45 (Phase 15): Anomaly Time-Machine Flight Recorder Ring Buffer
    #                      & Behavioral Drift Detector
    # -------------------------------------------------------------------------

    @classmethod
    def _flatten_decoded_value(cls, prefix: str, val: Any, out: Dict[str, Any], depth: int = 0) -> None:
        if depth > 4:
            out[prefix] = val
            return
        if isinstance(val, dict):
            if not val:
                out[prefix] = {}
                return
            for k, v in val.items():
                sep = "->" if prefix.startswith("*") else "."
                clean_p = prefix[1:] if (prefix.startswith("*") and sep == "->") else prefix
                cls._flatten_decoded_value(f"{clean_p}{sep}{k}", v, out, depth + 1)
        elif isinstance(val, list):
            for idx_i, item in enumerate(val[:8]):
                cls._flatten_decoded_value(f"{prefix}[{idx_i}]", item, out, depth + 1)
        else:
            out[prefix] = val

    def flight_recorder_time_machine(
        self,
        pid: int,
        companion_elf_path: str,
        frames_count: int = 8,
        interval_ms: int = 25,
        watch_expressions: Optional[List[str]] = None,
        remote_host: Optional[str] = None,
        ssh_user: Optional[str] = None,
        ssh_port: int = 22,
        ssh_key: Optional[str] = None,
        ssh_proxy_jump: Optional[str] = None,
        adapter: Optional[TargetExecutionAdapter] = None,
    ) -> Dict[str, Any]:
        """Zero-stop Anomaly Time-Machine Flight Recorder (`zero-stop` stop time).
        Maintains an per-PID circular blackbox ring buffer of micro-snapshots (`_flight_recorder_buffers`)
        and records `frames_count` rapid frames across `interval_ms`.
        Automatically identifies transient spikes, value reversals (A -> B -> A glitches), lock micro-stalls,
        and reconstructs `pre_anomaly_frame`, `peak_anomaly_frame`, and `post_anomaly_frame`.
        """
        target_adapter = self._resolve_adapter(
            pid=pid,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
            adapter=adapter,
        )
        t_start_ns = time.monotonic_ns()
        if not hasattr(self, "_flight_recorder_buffers"):
            self._flight_recorder_buffers: Dict[int, deque] = {}

        ring: deque = self._flight_recorder_buffers.setdefault(pid, deque(maxlen=64))
        clamped_frames = max(3, min(int(frames_count), 24))
        clamped_interval_ms = max(10, min(int(interval_ms), 250))

        # Auto-discover key state/counter/pool expressions if not provided
        primary_elf, _ = self._split_companion_elf_paths(companion_elf_path)
        if not primary_elf:
            raise ValueError("Valid companion ELF path is required")
        idx = DwarfIndexer.get_index(primary_elf)

        exprs: List[str] = list(watch_expressions or [])
        if not exprs:
            for v in idx.variables:
                if v.name and not v.name.startswith("__") and v.link_time_address is not None:
                    canon_v = idx.resolve_canonical_type(v.type_offset)
                    if canon_v and canon_v.tag == "DW_TAG_pointer_type":
                        pt = idx.resolve_canonical_type(canon_v.target_type_offset)
                        if pt and pt.tag in ("DW_TAG_structure_type", "DW_TAG_class_type"):
                            exprs.append(f"*{v.name}")
                            continue
                    exprs.append(v.name)
                if len(exprs) >= 8:
                    break

        recorded_frames: List[Dict[str, Any]] = []
        base_seq = len(ring)

        for f_i in range(clamped_frames):
            frame_ts_ms = round((time.monotonic_ns() - t_start_ns) / 1_000_000.0, 2)
            ev_res = self.evaluate_symbol_paths(
                pid=pid,
                companion_elf_path=companion_elf_path,
                expressions=exprs[:8],
                adapter=target_adapter,
            )
            flat_values: Dict[str, Any] = {}
            for r in ev_res.get("results", []):
                if r.get("status") == "OBSERVED":
                    self._flatten_decoded_value(r["expression"], r.get("value"), flat_values)

            # Compute an instant anomaly/stress score for this frame
            stress_score = 0
            stress_reasons: List[str] = []
            for k, v in flat_values.items():
                kl = k.lower()
                v_num = self._coerce_numeric_or_str(v)
                if isinstance(v_num, (int, float)):
                    if ("active" in kl or "in_use" in kl or "spike" in kl or "err" in kl or "backlog" in kl) and v_num > 0:
                        stress_score += int(v_num) * 5
                        stress_reasons.append(f"{k}={v_num}")
                elif isinstance(v, str) and v.startswith("0x") and "dead" in v.lower():
                    stress_score += 50
                    stress_reasons.append(f"{k}={v}")

            frame_obj = {
                "frame_seq": base_seq + f_i + 1,
                "offset_ms": frame_ts_ms,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "stress_score": stress_score,
                "stress_highlights": stress_reasons[:4],
                "values": flat_values,
            }
            ring.append(frame_obj)
            recorded_frames.append(frame_obj)

            if f_i + 1 < clamped_frames:
                time.sleep(clamped_interval_ms / 1000.0)

        # Analyze timeline across recorded_frames for transient glitches (A -> B -> A) and monotonic trends
        all_keys: List[str] = []
        for fr in recorded_frames:
            for k in fr["values"]:
                if k not in all_keys:
                    all_keys.append(k)

        transient_glitches: List[Dict[str, Any]] = []
        monotonic_trends: List[Dict[str, Any]] = []

        for k in all_keys:
            series = [fr["values"].get(k) for fr in recorded_frames]
            distinct = []
            for val in series:
                if not distinct or distinct[-1] != val:
                    distinct.append(val)
            if len(distinct) >= 3 and distinct[0] == distinct[-1]:
                # Classic transient spike/glitch: started at A, spiked to B, returned to A!
                peak_val = distinct[1]
                peak_frame_seq = next(
                    (fr["frame_seq"] for fr in recorded_frames if fr["values"].get(k) == peak_val),
                    recorded_frames[len(recorded_frames) // 2]["frame_seq"],
                )
                transient_glitches.append({
                    "path": k,
                    "pattern": "TRANSIENT_SPIKE_REVERSAL",
                    "baseline_value": distinct[0],
                    "spike_value": peak_val,
                    "restored_value": distinct[-1],
                    "peak_frame_seq": peak_frame_seq,
                    "timeline_values": series,
                })
            elif len(distinct) >= 2:
                monotonic_trends.append({
                    "path": k,
                    "start_value": series[0],
                    "end_value": series[-1],
                    "transitions_count": len(distinct) - 1,
                    "timeline_values": series,
                })

        # Identify Peak Anomaly Frame, Pre-Anomaly Frame, and Post-Anomaly Frame
        peak_idx = 0
        best_stress = -1
        for idx_f, fr in enumerate(recorded_frames):
            if fr["stress_score"] > best_stress:
                best_stress = fr["stress_score"]
                peak_idx = idx_f

        pre_frame = recorded_frames[max(0, peak_idx - 1)]
        peak_frame = recorded_frames[peak_idx]
        post_frame = recorded_frames[min(len(recorded_frames) - 1, peak_idx + 1)]

        elapsed_ms = round((time.monotonic_ns() - t_start_ns) / 1_000_000.0, 2)
        return {
            "pid": pid,
            "target_host": target_adapter.target_host(),
            "is_remote": target_adapter.is_remote(),
            "stop_duration_ms": 0.0,
            "frames_recorded": len(recorded_frames),
            "ring_buffer_total_frames": len(ring),
            "interval_ms": clamped_interval_ms,
            "elapsed_ms": elapsed_ms,
            "transient_glitches_count": len(transient_glitches),
            "transient_glitches": transient_glitches,
            "monotonic_trends": monotonic_trends[:12],
            "time_machine_triad": {
                "pre_anomaly_frame": pre_frame,
                "peak_anomaly_frame": peak_frame,
                "post_anomaly_frame": post_frame,
            },
            "frames": recorded_frames,
            "llm_next_step_hint": (
                f"Flight Recorder captured {len(recorded_frames)} zero-stop frames ({elapsed_ms}ms) and detected "
                f"{len(transient_glitches)} transient spike reversal(s): "
                + ", ".join(f"{g['path']} ({g['baseline_value']} ➔ {g['spike_value']} ➔ {g['restored_value']} at frame #{g['peak_frame_seq']})" for g in transient_glitches[:3])
                if transient_glitches
                else f"Flight Recorder captured {len(recorded_frames)} zero-stop frames ({elapsed_ms}ms). Peak stress frame #{peak_frame['frame_seq']} (score={peak_frame['stress_score']})."
            ),
        }

    def detect_behavioral_drift(
        self,
        pid: int,
        companion_elf_path: str,
        baseline_id: Optional[str] = None,
        save_as_new_baseline: bool = False,
        remote_host: Optional[str] = None,
        ssh_user: Optional[str] = None,
        ssh_port: int = 22,
        ssh_key: Optional[str] = None,
        ssh_proxy_jump: Optional[str] = None,
        adapter: Optional[TargetExecutionAdapter] = None,
    ) -> Dict[str, Any]:
        """Zero-Stop Behavioral Drift Detector (`zero-stop` stop time).
        Captures a multi-dimensional behavioral fingerprint of the live process:
        1. Global/Static State & Counter Values
        2. Memory Pool Utilization % & Allocated Slot Counts
        3. Active Thread Count & Mutex Lock States
        4. C++ Polymorphic Heap Object Counts & Unreferenced Leak Candidates
        Compares the current fingerprint against either a saved Golden Baseline (`baseline_id`)
        or the process's initial learned fingerprint cached on first connection, and computes
        `drift_score` (0..100), `drift_status`, and `drifted_dimensions`.
        """
        target_adapter = self._resolve_adapter(
            pid=pid,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
            adapter=adapter,
        )
        t_start_ns = time.monotonic_ns()
        if not hasattr(self, "_learned_behavioral_profiles"):
            self._learned_behavioral_profiles: Dict[int, Dict[str, Any]] = {}

        blueprint = self.get_process_xray_blueprint(
            pid=pid,
            companion_elf_path=companion_elf_path,
            adapter=target_adapter,
        )
        callstacks = self.inspect_thread_callstacks_and_locks(
            pid=pid,
            companion_elf_path=companion_elf_path,
            adapter=target_adapter,
        )
        heap_scan = self.scan_heap_objects(
            pid=pid,
            companion_elf_path=companion_elf_path,
            adapter=target_adapter,
        )

        # Collect pool utilization metrics
        pool_metrics: Dict[str, Dict[str, Any]] = {}
        for pm in blueprint.get("categories", {}).get("memory_pools_and_buffers", [])[:2]:
            expr = pm.get("recommended_pool_expression") or pm.get("name")
            if not expr:
                continue
            try:
                ps = self.scan_memory_pool_or_array(
                    pid=pid,
                    companion_elf_path=companion_elf_path,
                    base_expression=expr,
                    adapter=target_adapter,
                )
                pool_metrics[ps["resolved_array_expression"]] = {
                    "allocated_count": ps["pool_summary"]["allocated_count"],
                    "total_slots": ps["pool_summary"]["total_slots"],
                    "utilization_pct": ps["pool_summary"]["utilization_pct"],
                }
            except Exception:
                pass

        # Collect scalar state & counter values
        primary_elf, _ = self._split_companion_elf_paths(companion_elf_path)
        idx = DwarfIndexer.get_index(primary_elf)
        scalar_exprs = [
            v.name for v in idx.variables
            if v.name and not v.name.startswith("__") and v.link_time_address is not None
        ][:10]
        scalar_values: Dict[str, Any] = {}
        if scalar_exprs:
            try:
                ev = self.evaluate_symbol_paths(
                    pid=pid,
                    companion_elf_path=companion_elf_path,
                    expressions=scalar_exprs,
                    adapter=target_adapter,
                )
                for r in ev.get("results", []):
                    if r.get("status") == "OBSERVED":
                        self._flatten_decoded_value(r["expression"], r.get("value"), scalar_values)
            except Exception:
                pass

        locked_mutexes = [lk["name"] for lk in callstacks.get("locks", []) if lk.get("is_locked")]

        current_profile = {
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "threads_count": blueprint.get("threads_count", 0),
            "locked_mutexes": locked_mutexes,
            "pools": pool_metrics,
            "heap_total_objects": heap_scan.get("total_objects_found", 0),
            "heap_leaked_candidates": heap_scan.get("leaked_candidates_count", 0),
            "scalars": scalar_values,
        }

        if save_as_new_baseline or pid not in self._learned_behavioral_profiles:
            # If no baseline exists yet, store current profile as baseline (unless a Golden Baseline exists on disk)
            disk_baselines = self.list_golden_baselines()
            if disk_baselines and not save_as_new_baseline:
                b_rec = disk_baselines[0]
                b_vals = b_rec.get("values") or {}
                baseline_profile = {
                    "captured_at": b_rec.get("created_at"),
                    "threads_count": current_profile["threads_count"],
                    "locked_mutexes": [],
                    "pools": {},
                    "heap_total_objects": 0,
                    "heap_leaked_candidates": 0,
                    "scalars": b_vals,
                }
            else:
                self._learned_behavioral_profiles[pid] = current_profile
                baseline_profile = current_profile
        else:
            baseline_profile = self._learned_behavioral_profiles[pid]

        # Compare `current_profile` vs `baseline_profile` across all dimensions
        drifted_dimensions: List[Dict[str, Any]] = []
        drift_score = 0

        # Dimension 1: Thread count drift
        if current_profile["threads_count"] != baseline_profile.get("threads_count", current_profile["threads_count"]):
            drifted_dimensions.append({
                "dimension": "THREAD_COUNT_DRIFT",
                "severity": "MEDIUM",
                "metric": "threads_count",
                "baseline": baseline_profile.get("threads_count"),
                "current": current_profile["threads_count"],
                "detail": f"Active thread count changed from {baseline_profile.get('threads_count')} to {current_profile['threads_count']}",
            })
            drift_score += 15

        # Dimension 2: Newly locked mutexes
        base_locks = set(baseline_profile.get("locked_mutexes") or [])
        for lk_name in locked_mutexes:
            if lk_name not in base_locks:
                drifted_dimensions.append({
                    "dimension": "NEW_MUTEX_CONTENTION",
                    "severity": "HIGH",
                    "metric": lk_name,
                    "baseline": "UNLOCKED",
                    "current": "LOCKED",
                    "detail": f"Mutex '{lk_name}' was UNLOCKED in baseline but is currently LOCKED.",
                })
                drift_score += 25

        # Dimension 3: Memory Pool utilization surge
        base_pools = baseline_profile.get("pools") or {}
        for p_expr, p_cur in pool_metrics.items():
            p_base = base_pools.get(p_expr)
            if p_base:
                delta_pct = round(p_cur["utilization_pct"] - p_base["utilization_pct"], 2)
                if abs(delta_pct) >= 10.0:
                    drifted_dimensions.append({
                        "dimension": "MEMORY_POOL_UTILIZATION_DRIFT",
                        "severity": "HIGH" if delta_pct >= 25.0 else "MEDIUM",
                        "metric": p_expr,
                        "baseline": f"{p_base['allocated_count']}/{p_base['total_slots']} ({p_base['utilization_pct']}%)",
                        "current": f"{p_cur['allocated_count']}/{p_cur['total_slots']} ({p_cur['utilization_pct']}%)",
                        "detail": f"Pool '{p_expr}' utilization shifted by {delta_pct:+.1f}%.",
                    })
                    drift_score += 25
            elif p_cur["utilization_pct"] >= 25.0:
                drifted_dimensions.append({
                    "dimension": "MEMORY_POOL_ACTIVE_ALLOCATION",
                    "severity": "MEDIUM",
                    "metric": p_expr,
                    "baseline": "0%",
                    "current": f"{p_cur['allocated_count']}/{p_cur['total_slots']} ({p_cur['utilization_pct']}%)",
                    "detail": f"Pool '{p_expr}' has {p_cur['allocated_count']} active slot(s) ({p_cur['utilization_pct']}%).",
                })
                drift_score += 15

        # Dimension 4: Heap leak drift
        base_leaks = int(baseline_profile.get("heap_leaked_candidates", 0))
        cur_leaks = int(current_profile["heap_leaked_candidates"])
        if cur_leaks > base_leaks:
            drifted_dimensions.append({
                "dimension": "HEAP_LEAK_GROWTH",
                "severity": "CRITICAL",
                "metric": "heap_leaked_candidates",
                "baseline": base_leaks,
                "current": cur_leaks,
                "detail": f"Unreferenced C++ heap leak candidates increased from {base_leaks} to {cur_leaks}.",
            })
            drift_score += 35

        # Dimension 5: Scalar state/flag/pointer drift
        base_scalars = baseline_profile.get("scalars") or {}
        for sk, sv in scalar_values.items():
            if sk in base_scalars and base_scalars[sk] != sv:
                drifted_dimensions.append({
                    "dimension": "SYMBOL_VALUE_DRIFT",
                    "severity": "MEDIUM",
                    "metric": sk,
                    "baseline": base_scalars[sk],
                    "current": sv,
                    "detail": f"Symbol '{sk}' drifted from {base_scalars[sk]} to {sv}.",
                })
                drift_score += 10

        drift_score = min(100, drift_score)
        drift_status = (
            "SEVERE_BEHAVIORAL_DRIFT"
            if drift_score >= 50
            else ("MODERATE_DRIFT" if drift_score > 0 else "STABLE_ON_BASELINE")
        )

        latency_us = round((time.monotonic_ns() - t_start_ns) / 1000.0, 2)
        return {
            "pid": pid,
            "target_host": target_adapter.target_host(),
            "is_remote": target_adapter.is_remote(),
            "stop_duration_ms": 0.0,
            "evaluation_latency_us": latency_us,
            "drift_status": drift_status,
            "drift_score": drift_score,
            "drifted_dimensions_count": len(drifted_dimensions),
            "drifted_dimensions": drifted_dimensions,
            "baseline_profile": baseline_profile,
            "current_profile": current_profile,
            "llm_next_step_hint": (
                f"Behavioral Drift Check: {drift_status} (Drift Score: {drift_score}/100, {len(drifted_dimensions)} dimension(s) shifted). "
                + (drifted_dimensions[0]["detail"] if drifted_dimensions else "Process matches baseline profile.")
            ),
        }


    # -------------------------------------------------------------------------
    # Phase 48 (Phase 18): Stateful Target Context, Auto-Heal PID / Zero-Path
    # ELF Discovery, Forgiving C/C++ Expression Auto-Coercer, and 1-Call
    # Universal Intent Gateway (`runtime_ask`)
    # -------------------------------------------------------------------------

    def get_active_target_context(self) -> Dict[str, Any]:
        """Returns the currently bound stateful target context `(pid, process_name, companion_elf_path, ...)`."""
        with self._lock:
            ctx = dict(self._active_target_context)
        ctx["has_active_context"] = bool(ctx.get("pid") or ctx.get("companion_elf_path"))
        return ctx

    def bind_target_context(
        self,
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
        return self.resolve_target_context(
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
        self,
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
        with self._lock:
            saved = dict(self._active_target_context)

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
            coerced_port = self._coerce_int(ssh_port, 22, 1, 65535)
            eff_ssh_port = coerced_port if (coerced_port and coerced_port != 22) else self._coerce_int(saved.get("ssh_port"), 22, 1, 65535)
            eff_ssh_key = ssh_key if ssh_key is not None else saved.get("ssh_key")
            eff_ssh_jump = ssh_proxy_jump if ssh_proxy_jump is not None else saved.get("ssh_proxy_jump")
        else:
            eff_remote_host = remote_host
            eff_ssh_user = ssh_user
            eff_ssh_port = self._coerce_int(ssh_port, 22, 1, 65535) or 22
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

        target_adapter = self._resolve_adapter(
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
            primary_cand, _ = self._split_companion_elf_paths(eff_elf)
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
            or (eff_elf and os.path.isfile(self._split_companion_elf_paths(eff_elf)[0]))
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
                search_name = os.path.basename(self._split_companion_elf_paths(eff_elf)[0])
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
                primary_abs = os.path.abspath(self._split_companion_elf_paths(eff_elf)[0]) if eff_elf else None
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
        primary_resolved, _ = self._split_companion_elf_paths(eff_elf)
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
            with self._lock:
                healed_cnt = int(self._active_target_context.get("auto_healed_count") or 0) + (1 if auto_healed_pid else 0)
                self._active_target_context.update({
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
                    "last_previous_pid": previous_pid if auto_healed_pid else self._active_target_context.get("last_previous_pid"),
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

    def ask_runtime_question(
        self,
        question: str,
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
        """Universal 1-Call Intent Gateway (`runtime_ask`) in zero-stop mode.
        Accepts any C/C++ expression (even with `.` vs `->` mistakes, omitted root globals, or typos)
        OR any natural-language diagnostic question in Korean/English, automatically resolves/heals
        the active `(pid, companion_elf)` context, routes to the optimal zero-stop engine, and returns
        a unified response.
        """
        t_start_ns = time.monotonic_ns()
        ctx_info = self.resolve_target_context(
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
        eff_pid = ctx_info["pid"]
        eff_elf = ctx_info["companion_elf_path"]
        q_str = (question or "").strip()
        q_low = q_str.lower()

        # Extract candidate C/C++ expression tokens from question if present
        expr_candidates: List[str] = []
        # Check if the entire question is a single C/C++ expression
        if re.match(r"^[\*\(\)\w:\.\->\[\]]+$", q_str) and not q_str.isdigit():
            expr_candidates.append(q_str)
        else:
            for m in re.finditer(r"(\*?[A-Za-z_][A-Za-z0-9_]*(?:(?:\.|->)[A-Za-z_][A-Za-z0-9_]*|\[\d+\])+)", q_str):
                tok = m.group(1)
                if tok not in expr_candidates:
                    expr_candidates.append(tok)

        routed_tool = ""
        routed_result: Dict[str, Any] = {}

        # Route 1: DPDK / Lcore / PMD / rte_ring / rte_spinlock intent
        if any(k in q_low for k in ("dpdk", "lcore", "pmd", "rte_ring", "isolcpu", "spinlock", "폴링 코어")):
            routed_tool = "runtime_inspect_dpdk_lcores_and_rings"
            routed_result = self.inspect_dpdk_lcores_and_rings(
                pid=eff_pid,
                companion_elf_path=eff_elf,
                remote_host=ctx_info.get("remote_host"),
                ssh_user=ctx_info.get("ssh_user"),
                ssh_port=ctx_info.get("ssh_port", 22),
                ssh_key=ctx_info.get("ssh_key"),
                ssh_proxy_jump=ctx_info.get("ssh_proxy_jump"),
                adapter=adapter,
            )
        # Route 2: Thread-Local Storage (`__thread` / `thread_local`) intent
        elif any(k in q_low for k in ("tls", "thread_local", "__thread", "스레드 로컬")):
            routed_tool = "runtime_inspect_thread_local_storage"
            routed_result = self.inspect_thread_local_storage(
                pid=eff_pid,
                companion_elf_path=eff_elf,
                remote_host=ctx_info.get("remote_host"),
                ssh_user=ctx_info.get("ssh_user"),
                ssh_port=ctx_info.get("ssh_port", 22),
                ssh_key=ctx_info.get("ssh_key"),
                ssh_proxy_jump=ctx_info.get("ssh_proxy_jump"),
                adapter=adapter,
            )
        # Route 3: Thread Ownership / Who holds buffer slot intent
        elif any(k in q_low for k in ("누가", "owner", "소유", "잡고", "홀딩", "holding", "using")) and (
            expr_candidates or re.search(r"(\d+)\s*번", q_str) or "buffer" in q_low or "버퍼" in q_low
        ):
            routed_tool = "runtime_find_symbol_owners"
            target_expr = expr_candidates[0] if expr_candidates else "buffers[0]"
            if not expr_candidates:
                m_num = re.search(r"(\d+)", q_str)
                if m_num:
                    target_expr = f"buffers[{m_num.group(1)}]"
            routed_result = self.find_symbol_owners_and_threads(
                pid=eff_pid,
                companion_elf_path=eff_elf,
                target_expression=target_expr,
                remote_host=ctx_info.get("remote_host"),
                ssh_user=ctx_info.get("ssh_user"),
                ssh_port=ctx_info.get("ssh_port", 22),
                ssh_key=ctx_info.get("ssh_key"),
                ssh_proxy_jump=ctx_info.get("ssh_proxy_jump"),
                adapter=adapter,
            )
        # Route 4: Memory Pool / Slot Bitmap Scan intent
        elif any(k in q_low for k in ("메모리 풀", "버퍼 풀", "memory pool", "slot map", "할당 현황", "bitmap")):
            routed_tool = "runtime_scan_memory_pool"
            base_expr = expr_candidates[0] if expr_candidates else "*gpMem"
            routed_result = self.scan_memory_pool_or_array(
                pid=eff_pid,
                companion_elf_path=eff_elf,
                base_expression=base_expr,
                remote_host=ctx_info.get("remote_host"),
                ssh_user=ctx_info.get("ssh_user"),
                ssh_port=ctx_info.get("ssh_port", 22),
                ssh_key=ctx_info.get("ssh_key"),
                ssh_proxy_jump=ctx_info.get("ssh_proxy_jump"),
                adapter=adapter,
            )
        # Route 5: Direct or Forgiving C/C++ Expression Evaluation
        elif expr_candidates:
            routed_tool = "runtime_eval_memory_path"
            routed_result = self.evaluate_symbol_paths(
                pid=eff_pid,
                companion_elf_path=eff_elf,
                expressions=expr_candidates,
                remote_host=ctx_info.get("remote_host"),
                ssh_user=ctx_info.get("ssh_user"),
                ssh_port=ctx_info.get("ssh_port", 22),
                ssh_key=ctx_info.get("ssh_key"),
                ssh_proxy_jump=ctx_info.get("ssh_proxy_jump"),
                adapter=adapter,
            )
        # Route 6: Autonomous Symptom Investigation
        else:
            routed_tool = "runtime_investigate_symptom"
            routed_result = self.investigate_symptom(
                pid=eff_pid,
                companion_elf_path=eff_elf,
                symptom_query=q_str or "왜 멈췄지? 전체 상태 종합 진단",
                remote_host=ctx_info.get("remote_host"),
                ssh_user=ctx_info.get("ssh_user"),
                ssh_port=ctx_info.get("ssh_port", 22),
                ssh_key=ctx_info.get("ssh_key"),
                ssh_proxy_jump=ctx_info.get("ssh_proxy_jump"),
                adapter=adapter,
            )

        latency_us = round((time.monotonic_ns() - t_start_ns) / 1000.0, 2)
        out: Dict[str, Any] = {
            **routed_result,
            "question": q_str,
            "routed_tool": routed_tool,
            "pid": eff_pid,
            "companion_elf": eff_elf,
            "auto_healed_pid": ctx_info.get("auto_healed_pid", False),
            "previous_pid": ctx_info.get("previous_pid"),
            "elf_auto_discovered": ctx_info.get("elf_auto_discovered", False),
            "elf_discovery_source": ctx_info.get("elf_discovery_source"),
            "active_context": ctx_info,
            "stop_duration_ms": 0.0,
            "gateway_latency_us": latency_us,
            "result": routed_result,
        }
        return out

    def summarize_for_llm_budget(
        self,
        data: Dict[str, Any],
        max_tokens: int = 1200,
        drop_zero_or_free: bool = True,
        cursor_offset: int = 0,
        page_size: int = 16,
    ) -> Dict[str, Any]:
        """LLM Context-Window Budgeter & Anomaly-First Smart Compactor.
        1. Strips repetitive `FREE` slots or all-zero/NULL struct fields (`drop_zero_or_free=True`)
           while preserving 100% of `IN_USE`, anomalous, or non-zero items first.
        2. Applies deterministic cursor pagination (`cursor_offset`, `page_size`) to large collections
           (`slots`, `results`, `threads`, `objects`, `nodes`) and returns `pagination.next_cursor_offset`.
        3. Reports `original_estimated_tokens`, `compacted_estimated_tokens`, and `token_reduction_pct`.
        """
        raw_json_str = json.dumps(data, ensure_ascii=False, default=str)
        orig_tokens = max(1, len(raw_json_str) // 4)
        clamped_offset = max(0, int(cursor_offset or 0))
        clamped_page = max(1, min(int(page_size or 16), 200))

        compacted: Dict[str, Any] = {}
        for k, v in data.items():
            # Omit redundant verbose ASCII chart or duplicate alias keys when compacting for LLM token budget
            if k in ("ascii_map_chart", "allocation_bitmap", "evaluated", "raw_hex") and orig_tokens > max_tokens:
                continue
            compacted[k] = v

        omitted_zero_or_free_count = 0
        pagination_meta: Optional[Dict[str, Any]] = None

        # Case 1: Memory Pool Scanner output (`slots`)
        if isinstance(data.get("slots"), list):
            all_slots = data["slots"]
            if drop_zero_or_free:
                active_slots = [s for s in all_slots if s.get("is_allocated") or s.get("status") == "IN_USE"]
                free_slots = [s for s in all_slots if not (s.get("is_allocated") or s.get("status") == "IN_USE")]
                omitted_zero_or_free_count += len(free_slots)
                target_list = active_slots
            else:
                target_list = all_slots

            total_filtered = len(target_list)
            sliced = target_list[clamped_offset:clamped_offset + clamped_page]
            # Strip zero fields inside each slot if drop_zero_or_free is True
            cleaned_slots = []
            for s in sliced:
                s_copy = dict(s)
                if drop_zero_or_free and isinstance(s_copy.get("fields"), dict):
                    s_copy["fields"] = {
                        fk: fv for fk, fv in s_copy["fields"].items()
                        if fv not in (0, "0x0", "", None) or fk in ("in_use", "owner_tid", "seq")
                    }
                cleaned_slots.append(s_copy)

            compacted["slots"] = cleaned_slots
            compacted["collapsed_free_slots_count"] = omitted_zero_or_free_count
            has_more = (clamped_offset + clamped_page) < total_filtered
            pagination_meta = {
                "collection": "slots",
                "total_raw_items": len(all_slots),
                "total_active_items": total_filtered,
                "omitted_free_or_zero_items": omitted_zero_or_free_count,
                "cursor_offset": clamped_offset,
                "page_size": clamped_page,
                "returned_items": len(cleaned_slots),
                "has_more": has_more,
                "next_cursor_offset": (clamped_offset + clamped_page) if has_more else None,
            }

        # Case 2: Symbol Evaluation output (`results`)
        elif isinstance(data.get("results"), list):
            cleaned_results = []
            for r in data["results"]:
                r_copy = {rk: rv for rk, rv in r.items() if rk != "raw_hex"}
                val = r_copy.get("value")
                if drop_zero_or_free and isinstance(val, dict):
                    non_zero_dict = {}
                    zero_keys = []
                    for fk, fv in val.items():
                        if fv in (0, 0.0, "0x0", "", None, False) or (isinstance(fv, list) and all(x == 0 for x in fv)):
                            zero_keys.append(fk)
                        else:
                            non_zero_dict[fk] = fv
                    if zero_keys:
                        omitted_zero_or_free_count += len(zero_keys)
                        non_zero_dict["_omitted_zero_fields_count"] = len(zero_keys)
                        r_copy["value"] = non_zero_dict
                elif drop_zero_or_free and isinstance(val, list) and len(val) > clamped_page:
                    non_zero_items = [
                        {"index": idx_i, "value": item_v}
                        for idx_i, item_v in enumerate(val)
                        if item_v not in (0, 0.0, "0x0", "", None)
                    ]
                    omitted_zero_or_free_count += (len(val) - len(non_zero_items))
                    r_copy["value"] = non_zero_items[clamped_offset:clamped_offset + clamped_page]
                    r_copy["array_compaction"] = {
                        "total_elements": len(val),
                        "non_zero_elements": len(non_zero_items),
                        "omitted_zero_elements": len(val) - len(non_zero_items),
                    }
                cleaned_results.append(r_copy)
            compacted["results"] = cleaned_results
            if "evaluated" in compacted:
                compacted["evaluated"] = cleaned_results

        compacted_json_str = json.dumps(compacted, ensure_ascii=False, default=str)
        comp_tokens = max(1, len(compacted_json_str) // 4)
        reduction_pct = round(max(0.0, (1.0 - (comp_tokens / float(orig_tokens))) * 100.0), 1)

        compacted["token_budget_meta"] = {
            "max_tokens_requested": max_tokens,
            "original_estimated_tokens": orig_tokens,
            "compacted_estimated_tokens": comp_tokens,
            "token_reduction_pct": reduction_pct,
            "drop_zero_or_free": drop_zero_or_free,
            "omitted_zero_or_free_count": omitted_zero_or_free_count,
            "anomaly_first_preserved": True,
            "pagination": pagination_meta,
        }
        return compacted

    def smart_compact_query(
        self,
        query_or_expression: str = "*gpMem",
        mode: str = "auto",
        pid: Optional[int] = None,
        companion_elf_path: Optional[str] = None,
        max_tokens: int = 800,
        drop_zero_or_free: bool = True,
        cursor_offset: int = 0,
        page_size: int = 16,
        remote_host: Optional[str] = None,
        ssh_user: Optional[str] = None,
        ssh_port: int = 22,
        ssh_key: Optional[str] = None,
        ssh_proxy_jump: Optional[str] = None,
        adapter: Optional[TargetExecutionAdapter] = None,
    ) -> Dict[str, Any]:
        """Executes a zero-stop query or expression evaluation and automatically applies
        `summarize_for_llm_budget` (anomaly-first noise filtering + cursor pagination).
        """
        ctx_info = self.resolve_target_context(
            pid=pid,
            companion_elf_path=companion_elf_path,
            remote_host=remote_host,
            ssh_user=ssh_user,
            ssh_port=ssh_port,
            ssh_key=ssh_key,
            ssh_proxy_jump=ssh_proxy_jump,
            adapter=adapter,
        )
        eff_pid = ctx_info["pid"]
        eff_elf = ctx_info["companion_elf_path"]
        q_clean = (query_or_expression or "*gpMem").strip()

        if mode == "pool" or (mode == "auto" and (q_clean.startswith("*") or "pool" in q_clean.lower() or q_clean.endswith("buffers"))):
            raw_res = self.scan_memory_pool_or_array(
                pid=eff_pid,
                companion_elf_path=eff_elf,
                base_expression=q_clean,
                remote_host=ctx_info.get("remote_host"),
                ssh_user=ctx_info.get("ssh_user"),
                ssh_port=ctx_info.get("ssh_port", 22),
                ssh_key=ctx_info.get("ssh_key"),
                ssh_proxy_jump=ctx_info.get("ssh_proxy_jump"),
                adapter=adapter,
            )
        elif mode == "eval":
            raw_res = self.evaluate_symbol_paths(
                pid=eff_pid,
                companion_elf_path=eff_elf,
                expressions=[x.strip() for x in q_clean.split(",") if x.strip()],
                remote_host=ctx_info.get("remote_host"),
                ssh_user=ctx_info.get("ssh_user"),
                ssh_port=ctx_info.get("ssh_port", 22),
                ssh_key=ctx_info.get("ssh_key"),
                ssh_proxy_jump=ctx_info.get("ssh_proxy_jump"),
                adapter=adapter,
            )
        else:
            raw_res = self.ask_runtime_question(
                question=q_clean,
                pid=eff_pid,
                companion_elf_path=eff_elf,
                remote_host=ctx_info.get("remote_host"),
                ssh_user=ctx_info.get("ssh_user"),
                ssh_port=ctx_info.get("ssh_port", 22),
                ssh_key=ctx_info.get("ssh_key"),
                ssh_proxy_jump=ctx_info.get("ssh_proxy_jump"),
                adapter=adapter,
            )

        return self.summarize_for_llm_budget(
            data=raw_res,
            max_tokens=max_tokens,
            drop_zero_or_free=drop_zero_or_free,
            cursor_offset=cursor_offset,
            page_size=page_size,
        )

    def execute_batch_macro(
        self,
        steps: List[Dict[str, Any]],
        pid: Optional[int] = None,
        companion_elf_path: Optional[str] = None,
        process_name: Optional[str] = None,
        compact: bool = True,
        max_tokens_per_step: int = 800,
        remote_host: Optional[str] = None,
        ssh_user: Optional[str] = None,
        ssh_port: int = 22,
        ssh_key: Optional[str] = None,
        ssh_proxy_jump: Optional[str] = None,
        adapter: Optional[TargetExecutionAdapter] = None,
    ) -> Dict[str, Any]:
        """1-Call Multi-Tool Composite Batch Macro Executor (`runtime_batch_execute`) in zero-stop mode.
        Executes multiple heterogeneous diagnostic steps (`eval`, `scan_pool`, `find_owners`, `tls`,
        `dpdk_lcores`, `verify_consistency`, `triage`, `ask`) in a single round-trip while sharing
        the bound target context, ASLR load-bias cache, and DWARF index.
        """
        t_start_ns = time.monotonic_ns()
        ctx_info = self.resolve_target_context(
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
        eff_pid = ctx_info["pid"]
        eff_elf = ctx_info["companion_elf_path"]

        step_results: List[Dict[str, Any]] = []
        cross_step_highlights: List[str] = []
        succeeded_count = 0
        failed_count = 0

        normalized_steps = self._coerce_steps_list(steps, max_steps=32)
        for idx_s, step in enumerate(normalized_steps):
            step_id = str(step.get("step_id") or f"step_{idx_s + 1}")
            action = str(step.get("action") or step.get("tool") or "ask").strip().lower()
            step_t0 = time.monotonic_ns()
            try:
                if action == "malformed_step":
                    raise ValueError(step.get("error") or "Malformed step input: expected dictionary")
                elif action in ("eval", "runtime_eval_memory_path", "evaluate_symbol_paths"):
                    exprs = step.get("expressions") or ([step["expression"]] if step.get("expression") else ["*gpMem"])
                    if isinstance(exprs, str):
                        exprs = [x.strip() for x in exprs.split(",") if x.strip()]
                    raw_out = self.evaluate_symbol_paths(
                        pid=eff_pid,
                        companion_elf_path=eff_elf,
                        expressions=exprs,
                        adapter=adapter,
                    )
                elif action in ("scan_pool", "pool", "runtime_scan_memory_pool", "scan_memory_pool_or_array"):
                    base_e = str(step.get("base_expression") or step.get("expression") or "*gpMem")
                    raw_out = self.scan_memory_pool_or_array(
                        pid=eff_pid,
                        companion_elf_path=eff_elf,
                        base_expression=base_e,
                        count=step.get("count"),
                        adapter=adapter,
                    )
                    p_sum = raw_out.get("pool_summary") or {}
                    cross_step_highlights.append(
                        f"[{step_id}:scan_pool] {raw_out.get('resolved_array_expression')}: {p_sum.get('allocated_count')}/{p_sum.get('total_slots')} IN_USE ({p_sum.get('utilization_pct')}%)"
                    )
                elif action in ("find_owners", "owners", "runtime_find_symbol_owners", "find_symbol_owners_and_threads"):
                    t_expr = str(step.get("target_expression") or step.get("expression") or "buffers[0]")
                    raw_out = self.find_symbol_owners_and_threads(
                        pid=eff_pid,
                        companion_elf_path=eff_elf,
                        target_expression=t_expr,
                        adapter=adapter,
                    )
                    m_ths = raw_out.get("matched_threads") or []
                    cross_step_highlights.append(
                        f"[{step_id}:find_owners] {raw_out.get('resolved_expression')}: {len(m_ths)} owner thread(s) ({[t['thread_name'] for t in m_ths]})"
                    )
                elif action in ("tls", "runtime_inspect_thread_local_storage", "inspect_thread_local_storage"):
                    raw_out = self.inspect_thread_local_storage(
                        pid=eff_pid,
                        companion_elf_path=eff_elf,
                        tid=step.get("tid"),
                        variable_names=step.get("variable_names"),
                        adapter=adapter,
                    )
                elif action in ("dpdk", "dpdk_lcores", "runtime_inspect_dpdk_lcores_and_rings", "inspect_dpdk_lcores_and_rings"):
                    raw_out = self.inspect_dpdk_lcores_and_rings(
                        pid=eff_pid,
                        companion_elf_path=eff_elf,
                        sample_window_ms=int(step.get("sample_window_ms") or 30),
                        adapter=adapter,
                    )
                elif action in ("triage", "auto_triage", "runtime_auto_triage_incident", "auto_triage_incident"):
                    raw_out = self.auto_triage_incident(
                        pid=eff_pid,
                        companion_elf_path=eff_elf,
                        adapter=adapter,
                    )
                elif action in ("callstack", "callstacks", "locks", "runtime_inspect_thread_callstack_and_locks", "inspect_thread_callstack_and_locks", "inspect_thread_callstacks_and_locks"):
                    raw_out = self.inspect_thread_callstacks_and_locks(
                        pid=eff_pid,
                        companion_elf_path=eff_elf,
                        adapter=adapter,
                    )
                elif action in ("diff", "capture_diff", "capture_and_diff", "runtime_capture_and_diff"):
                    raw_out = self.capture_and_diff_expressions(
                        pid=eff_pid,
                        companion_elf_path=eff_elf,
                        expressions=step.get("expressions"),
                        wait_ms=int(step.get("wait_ms") or 200),
                        adapter=adapter,
                    )
                elif action in ("heap", "scan_heap", "runtime_scan_heap_objects", "scan_heap_objects"):
                    raw_out = self.scan_heap_objects(
                        pid=eff_pid,
                        companion_elf_path=eff_elf,
                        class_filter=step.get("class_filter"),
                        adapter=adapter,
                    )
                elif action in ("verify_consistency", "runtime_verify_concurrent_read_consistency", "verify_concurrent_read_consistency"):
                    raw_out = self.verify_concurrent_read_consistency(
                        pid=eff_pid,
                        companion_elf_path=eff_elf,
                        expressions=step.get("expressions") or ["gpRegistry.magic"],
                        retries=int(step.get("retries") or 3),
                        inter_read_delay_ms=int(step.get("inter_read_delay_ms") or 5),
                        adapter=adapter,
                    )
                elif action in ("ask", "question", "ask_runtime_question", "runtime_ask"):
                    q_txt = str(step.get("question") or step.get("expression") or "프로세스 상태 요약")
                    raw_out = self.ask_runtime_question(
                        question=q_txt,
                        pid=eff_pid,
                        companion_elf_path=eff_elf,
                        adapter=adapter,
                    )
                else:
                    raise ValueError(f"Unsupported batch action '{action}'. Supported actions: eval, scan_pool, find_owners, tls, dpdk, triage, callstack, diff, heap, verify_consistency, ask.")

                final_out = (
                    self.summarize_for_llm_budget(
                        data=raw_out,
                        max_tokens=max_tokens_per_step,
                        drop_zero_or_free=bool(step.get("drop_zero_or_free", True)),
                        cursor_offset=int(step.get("cursor_offset") or 0),
                        page_size=int(step.get("page_size") or 16),
                    )
                    if compact
                    else raw_out
                )
                # Check if step produced a structured failure dictionary without raising
                is_step_failed = False
                step_failure_msg = None
                if isinstance(raw_out, dict):
                    if raw_out.get("success") is False:
                        is_step_failed = True
                        step_failure_msg = raw_out.get("error") or raw_out.get("error_message") or "Step execution returned failure"
                    elif raw_out.get("status") in ("FAILED", "ERROR") and "results" not in raw_out:
                        is_step_failed = True
                        step_failure_msg = raw_out.get("error") or f"Step returned status {raw_out.get('status')}"

                if is_step_failed:
                    failed_count += 1
                    step_results.append({
                        "step_id": step_id,
                        "action": action,
                        "success": False,
                        "error": step_failure_msg,
                        "elapsed_us": round((time.monotonic_ns() - step_t0) / 1000.0, 2),
                        "output": final_out,
                    })
                else:
                    succeeded_count += 1
                    step_results.append({
                        "step_id": step_id,
                        "action": action,
                        "success": True,
                        "elapsed_us": round((time.monotonic_ns() - step_t0) / 1000.0, 2),
                        "output": final_out,
                    })
            except Exception as step_exc:
                failed_count += 1
                step_results.append({
                    "step_id": step_id,
                    "action": action,
                    "success": False,
                    "error": str(step_exc),
                    "elapsed_us": round((time.monotonic_ns() - step_t0) / 1000.0, 2),
                })

        total_latency_us = round((time.monotonic_ns() - t_start_ns) / 1000.0, 2)
        total_steps = len(normalized_steps)
        overall_success = (failed_count == 0)
        is_partial = (succeeded_count > 0 and failed_count > 0)

        res: Dict[str, Any] = {
            "success": overall_success,
            "partial_success": is_partial,
            "pid": eff_pid,
            "companion_elf": eff_elf,
            "auto_healed_pid": ctx_info.get("auto_healed_pid", False),
            "elf_auto_discovered": ctx_info.get("elf_auto_discovered", False),
            "stop_duration_ms": 0.0,
            "batch_latency_us": total_latency_us,
            "compact_mode": compact,
            "steps_requested": total_steps,
            "steps_succeeded": succeeded_count,
            "steps_failed": failed_count,
            "cross_step_highlights": cross_step_highlights,
            "step_results": step_results,
            "llm_next_step_hint": (
                f"Executed {succeeded_count}/{total_steps} batch diagnostic step(s) in {total_latency_us}us without stopping the target."
            ),
        }
        if failed_count > 0:
            if is_partial:
                res["error_code"] = "PARTIAL_BATCH_FAILURE"
                res["error"] = f"{failed_count} of {total_steps} batch step(s) failed"
                res["recovery_hint"] = "Review failed steps in 'step_results' to diagnose individual action failures."
            else:
                res["error_code"] = "ALL_STEPS_FAILED"
                res["error"] = f"All {failed_count} batch step(s) failed"
                res["recovery_hint"] = "Check target process liveness and parameters for all batch steps."
        return res


    # -------------------------------------------------------------------------
    # Phase 50 (Phase 20): Declarative Multi-Assertion Hypothesis Verifier
    # (`verify_runtime_hypothesis`) & 1-Call Incident Report Exporter
    # (`export_incident_report`)
    # -------------------------------------------------------------------------

    @staticmethod
    def _parse_single_assertion(assertion_str: str) -> Dict[str, Any]:
        """Parses a declarative C/C++ assertion string such as:
        - `gpMem.active_buffers >= 2`
        - `buffers[5].seq == 5005`
        - `g_null_pool_ptr == NULL` or `g_null_pool_ptr IS_NULL`
        - `gpMem NOT_NULL`
        - `buffers[5].in_use` (truthy check `!= 0`)
        """
        s = (assertion_str or "").strip()
        if not s:
            raise ValueError("Empty assertion string")

        m_unary = re.match(r"^(.+?)\s+(IS_NULL|NOT_NULL)$", s, flags=re.IGNORECASE)
        if m_unary:
            lhs = m_unary.group(1).strip()
            op = m_unary.group(2).upper()
            return {"raw": s, "lhs": lhs, "operator": op, "rhs_raw": None}

        for op in ("==", "!=", ">=", "<=", ">", "<"):
            if op in s:
                lhs, rhs = s.split(op, 1)
                return {"raw": s, "lhs": lhs.strip(), "operator": op, "rhs_raw": rhs.strip()}

        return {"raw": s, "lhs": s, "operator": "TRUTHY", "rhs_raw": "!= 0"}

    @staticmethod
    def _compare_assertion_values(observed: Any, op: str, rhs_raw: Optional[str]) -> Tuple[bool, Any]:
        """Compares observed DWARF-decoded value against expected operator and RHS literal."""
        def _is_null_like(v: Any) -> bool:
            if v is None or v == 0 or v is False:
                return True
            if isinstance(v, str) and v.strip().lower() in ("0", "0x0", "null", "nullptr", "0x00000000", "0x0000000000000000"):
                return True
            return False

        if op == "IS_NULL":
            return _is_null_like(observed), "NULL (0x0)"
        if op == "NOT_NULL":
            return (not _is_null_like(observed)), "NOT_NULL (!= 0x0)"
        if op == "TRUTHY":
            return (not _is_null_like(observed)), "!= 0"

        rhs_clean = (rhs_raw or "").strip()
        if (rhs_clean.startswith("'") and rhs_clean.endswith("'")) or (rhs_clean.startswith('"') and rhs_clean.endswith('"')):
            rhs_val: Any = rhs_clean[1:-1]
        elif rhs_clean.lower() in ("null", "nullptr", "0x0"):
            rhs_val = 0
        elif rhs_clean.lower() in ("true", "false"):
            rhs_val = 1 if rhs_clean.lower() == "true" else 0
        elif rhs_clean.lower().startswith("0x"):
            try:
                rhs_val = int(rhs_clean, 16)
            except ValueError:
                rhs_val = rhs_clean
        else:
            try:
                rhs_val = int(rhs_clean)
            except ValueError:
                try:
                    rhs_val = float(rhs_clean)
                except ValueError:
                    rhs_val = rhs_clean

        # Normalize observed value if comparing against numeric
        obs_norm: Any = observed
        if isinstance(rhs_val, (int, float)):
            if isinstance(observed, str):
                obs_s = observed.strip().lower()
                if obs_s in ("null", "nullptr"):
                    obs_norm = 0
                elif obs_s.startswith("0x"):
                    try:
                        obs_norm = int(obs_s, 16)
                    except ValueError:
                        pass
                else:
                    # Handle enum format `"STATE_ACTIVE (2)"`
                    m_enum = re.search(r"\((-?\d+)\)\s*$", obs_s)
                    if m_enum:
                        obs_norm = int(m_enum.group(1))
                    else:
                        try:
                            obs_norm = float(obs_s) if "." in obs_s else int(obs_s)
                        except ValueError:
                            pass
            elif isinstance(observed, bool):
                obs_norm = 1 if observed else 0

        try:
            if op == "==":
                if isinstance(rhs_val, str) and not isinstance(obs_norm, str):
                    return str(obs_norm) == rhs_val, rhs_val
                return obs_norm == rhs_val, rhs_val
            if op == "!=":
                return obs_norm != rhs_val, rhs_val
            if op == ">=":
                return float(obs_norm) >= float(rhs_val), rhs_val
            if op == "<=":
                return float(obs_norm) <= float(rhs_val), rhs_val
            if op == ">":
                return float(obs_norm) > float(rhs_val), rhs_val
            if op == "<":
                return float(obs_norm) < float(rhs_val), rhs_val
        except Exception:
            return False, rhs_val
        return False, rhs_val

    def verify_runtime_hypothesis(
        self,
        hypothesis: str,
        assertions: List[str],
        pid: Optional[int] = None,
        companion_elf_path: Optional[str] = None,
        process_name: Optional[str] = None,
        correlate_owners: bool = True,
        remote_host: Optional[str] = None,
        ssh_user: Optional[str] = None,
        ssh_port: int = 22,
        ssh_key: Optional[str] = None,
        ssh_proxy_jump: Optional[str] = None,
        adapter: Optional[TargetExecutionAdapter] = None,
        report_html_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Declarative Multi-Assertion Hypothesis Verifier (`runtime_verify_hypothesis`)."""
        t_start_ns = time.monotonic_ns()
        ctx_info = self.resolve_target_context(
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
        eff_pid = ctx_info["pid"]
        eff_elf = ctx_info["companion_elf_path"]

        coerced_assertions = self._coerce_str_list(assertions)
        parsed_list = [self._parse_single_assertion(a) for a in coerced_assertions if str(a).strip()]
        lhs_exprs = [p["lhs"] for p in parsed_list]

        eval_out = self.evaluate_symbol_paths(
            pid=eff_pid,
            companion_elf_path=eff_elf,
            expressions=lhs_exprs,
            remote_host=ctx_info.get("remote_host"),
            ssh_user=ctx_info.get("ssh_user"),
            ssh_port=ctx_info.get("ssh_port", 22),
            ssh_key=ctx_info.get("ssh_key"),
            ssh_proxy_jump=ctx_info.get("ssh_proxy_jump"),
            adapter=adapter,
        )
        eval_by_expr = {r["expression"]: r for r in eval_out.get("results", [])}

        assertion_results: List[Dict[str, Any]] = []
        ae_list: List[AssertionEvaluation] = []
        passed_count = 0
        failed_count = 0
        abstain_count = 0
        slot_expressions_to_correlate: List[str] = []

        for p_item in parsed_list:
            lhs = p_item["lhs"]
            op = p_item["operator"]
            rhs_raw = p_item["rhs_raw"]
            ev = eval_by_expr.get(lhs, {})
            st = ev.get("status", "UNKNOWN")
            obs_val = ev.get("value")
            res_expr = ev.get("resolved_expression") or lhs

            if st == "OBSERVED":
                passed, expected_val = self._compare_assertion_values(obs_val, op, rhs_raw)
                a_verdict = ASSERTION_PASS if passed else ASSERTION_FAIL
            elif st == "NULL_POINTER" and op in ("IS_NULL", "==") and "->" not in lhs and "." not in lhs:
                passed, expected_val = self._compare_assertion_values(0, op, rhs_raw)
                a_verdict = ASSERTION_PASS if passed else ASSERTION_FAIL
            else:
                passed = False
                expected_val = rhs_raw
                a_verdict = ASSERTION_ABSTAIN

            if a_verdict == ASSERTION_PASS:
                passed_count += 1
            elif a_verdict == ASSERTION_FAIL:
                failed_count += 1
            else:
                abstain_count += 1

            m_slot = re.match(r"^(.+?\[\s*\d+\s*\])", res_expr)
            if m_slot:
                slot_base = m_slot.group(1)
                if slot_base not in slot_expressions_to_correlate:
                    slot_expressions_to_correlate.append(slot_base)

            assertion_results.append({
                "assertion": p_item["raw"],
                "lhs_expression": lhs,
                "resolved_expression": res_expr,
                "was_coerced": ev.get("was_coerced", False),
                "operator": op,
                "expected": expected_val,
                "observed_value": obs_val,
                "evaluation_status": st,
                "verdict": a_verdict,
                "runtime_address": ev.get("runtime_address"),
                "passed": passed,
                "self_repair": ev.get("self_repair"),
            })
            ae_list.append(
                AssertionEvaluation(
                    raw_assertion=p_item["raw"],
                    lhs_expression=lhs,
                    resolved_expression=res_expr,
                    operator=op,
                    expected=expected_val,
                    observed_value=obs_val,
                    observation_status=st,
                    verdict=a_verdict,
                    reason="Condition satisfied" if a_verdict == ASSERTION_PASS else (
                        f"Observation status {st}" if a_verdict == ASSERTION_ABSTAIN else f"Observed {obs_val} != {op} {expected_val}"
                    ),
                    runtime_address=ev.get("runtime_address"),
                    was_coerced=ev.get("was_coerced", False),
                )
            )

        correlated_slot_owners: Dict[str, Any] = {}
        if correlate_owners and slot_expressions_to_correlate:
            for s_expr in slot_expressions_to_correlate[:4]:
                try:
                    ow = self.find_symbol_owners_and_threads(
                        pid=eff_pid,
                        companion_elf_path=eff_elf,
                        target_expression=s_expr,
                        adapter=adapter,
                    )
                    correlated_slot_owners[s_expr] = [
                        {"tid": t["tid"], "thread_name": t["thread_name"], "confidence": t["confidence"]}
                        for t in (ow.get("matched_threads") or [])
                    ]
                except Exception:
                    pass

        total_cnt = len(assertion_results)
        latency_us = round((time.monotonic_ns() - t_start_ns) / 1000.0, 2)
        ledger = EvidenceLedger()
        ev_adapter = EvidenceAdapter()
        sym_recs = ev_adapter.adapt_symbol_evaluation(
            eval_result=eval_out,
            target_identity={"pid": eff_pid, "companion_elf": eff_elf},
            session_id=ledger.session_id,
        )
        ev_adapter.record_into_ledger(sym_recs, ledger)
        # IMP-017: the assertion-outcome rollup and its report live in verdict_engine (this class only collects)
        hv = VerdictEngine.summarize_hypothesis_verification(
            hypothesis=hypothesis, evaluations=ae_list, total=total_cnt, passed=passed_count, failed=failed_count,
            abstained=abstain_count, target_identity={"pid": eff_pid, "companion_elf": eff_elf},
            latency_us=latency_us, bytes_read=len(lhs_exprs) * 64,
        )
        verdict, pass_ratio = hv["outcome"], hv["pass_ratio"]
        report_html, report_json = hv["report_html"], hv["report_json"]

        saved_html_path = None
        save_html_error = None
        if report_html_path and str(report_html_path).strip():
            san_html, html_err = sanitize_report_output_path(report_html_path, file_type="HTML report")
            if html_err or not san_html:
                save_html_error = html_err or f"Invalid HTML report path: {report_html_path}"
                print(f"WARNING: {save_html_error}", file=sys.stderr)
            else:
                try:
                    os.makedirs(os.path.dirname(san_html), exist_ok=True)
                    with open(san_html, "w", encoding="utf-8") as hf:
                        hf.write(report_html)
                    saved_html_path = san_html
                except OSError as os_err:
                    save_html_error = f"Failed to write HTML report to {san_html}: {os_err}"

        # Persist golden corpus snapshot if corpus_dir is configured
        if self.corpus_dir:
            try:
                os.makedirs(self.corpus_dir, exist_ok=True)
                snap_file = os.path.join(self.corpus_dir, f"000_verify_snapshot_{eff_pid}.json")
                with open(snap_file, "w", encoding="utf-8") as cf:
                    json.dump(
                        {
                            "goal": "Verify worker integrity",
                            "hypothesis": hypothesis,
                            "verdict": verdict,
                            "pid": eff_pid,
                            "confidence": round(pass_ratio, 3),
                        },
                        cf,
                        indent=2,
                    )
            except Exception:
                pass

        return {
            "pid": eff_pid,
            "companion_elf": eff_elf,
            "stop_duration_ms": 0.0,
            "target_stop_duration_ms": 0.0,
            "verification_latency_us": latency_us,
            "observation_latency_us": latency_us,
            "hypothesis": hypothesis,
            "verdict": verdict,
            "confidence": round(pass_ratio, 3),
            "confidence_score": round(pass_ratio, 3),
            "total_assertions": total_cnt,
            "passed_assertions": passed_count,
            "failed_assertions": failed_count,
            "abstain_assertions": abstain_count,
            "assertion_results": assertion_results,
            "correlated_slot_owners": correlated_slot_owners,
            "evidence_ledger": ledger.to_dict(),
            "report_html": report_html,
            "report_json": report_json,
            "saved_html_path": saved_html_path,
            "save_html_error": save_html_error,
            "llm_next_step_hint": (
                f"Hypothesis '{hypothesis}' is {verdict} ({passed_count}/{total_cnt} assertions passed, "
                f"confidence {round(pass_ratio * 100, 1)}%) in zero-stop mode."
            ),
        }

    def export_incident_report(
        self,
        title: str = "dynamicState Zero-Stop Runtime Incident Report",
        hypothesis: Optional[str] = None,
        assertions: Optional[List[str]] = None,
        output_path: Optional[str] = None,
        report_html_path: Optional[str] = None,
        template_path: Optional[str] = None,
        pid: Optional[int] = None,
        companion_elf_path: Optional[str] = None,
        process_name: Optional[str] = None,
        remote_host: Optional[str] = None,
        ssh_user: Optional[str] = None,
        ssh_port: int = 22,
        ssh_key: Optional[str] = None,
        ssh_proxy_jump: Optional[str] = None,
        adapter: Optional[TargetExecutionAdapter] = None,
        language: str = "en",
    ) -> Dict[str, Any]:
        """1-Call Incident Report exporter (`runtime_export_incident_report`, CLI `export-report`, web).

        IMP-017: delegates to :func:`extractor.incident_report.export_incident_report`, which runs ``diagnose()``
        once; this class no longer decides a verdict or builds the report.  Only the target context (bound PID /
        ELF / SSH settings) is resolved here.
        """
        from .incident_report import export_incident_report as _export
        pre: List[str] = []
        build_id = None
        if pid is not None and (isinstance(pid, bool) or pid <= 0):
            return _export(title=title, pid=pid, language=language)
        try:
            ctx_info = self.resolve_target_context(
                pid=pid, companion_elf_path=companion_elf_path, process_name=process_name,
                remote_host=remote_host, ssh_user=ssh_user, ssh_port=ssh_port, ssh_key=ssh_key,
                ssh_proxy_jump=ssh_proxy_jump, adapter=adapter,
            )
        except Exception as ctx_exc:  # noqa: BLE001
            ctx_info = {"pid": pid, "companion_elf_path": companion_elf_path, "process_name": process_name,
                        "remote_host": remote_host, "ssh_user": ssh_user, "ssh_port": ssh_port, "ssh_key": ssh_key,
                        "ssh_proxy_jump": ssh_proxy_jump}
            pre.append(f"resolve_target_context failed: {type(ctx_exc).__name__}: {ctx_exc}")
        build_id = ctx_info.get("build_id")
        return _export(
            title=title, hypothesis=hypothesis, assertions=assertions, output_path=output_path,
            report_html_path=report_html_path, template_path=template_path,
            pid=ctx_info.get("pid") or pid, companion_elf_path=ctx_info.get("companion_elf_path") or companion_elf_path,
            process_name=ctx_info.get("process_name"), build_id=build_id,
            remote_host=ctx_info.get("remote_host"), ssh_user=ctx_info.get("ssh_user"),
            ssh_port=ctx_info.get("ssh_port") or 22, ssh_key=ctx_info.get("ssh_key"),
            ssh_proxy_jump=ctx_info.get("ssh_proxy_jump"), adapter=adapter, corpus_dir=self.corpus_dir,
            hypothesis_verifier=self.verify_runtime_hypothesis, pre_limitations=pre, language=language,
        )

    # --- extractor/inspection/process_maps.py: memory maps, load bias, thread list ---
    _resolve_shared_lib_load_bias = staticmethod(_process_maps._resolve_shared_lib_load_bias)
    _get_process_maps_and_load_bias = _process_maps._get_process_maps_and_load_bias
    get_memory_map_and_threads = _process_maps.get_memory_map_and_threads

    # --- extractor/inspection/threads.py: thread/lock inspection, CFI call stacks, frame locals ---
    _imp011_prepare_unwinder = staticmethod(_threads._imp011_prepare_unwinder)
    _imp011_read_syscall = staticmethod(_threads._imp011_read_syscall)
    _imp011_unwind_thread = staticmethod(_threads._imp011_unwind_thread)
    _imp011_thread_summary = staticmethod(_threads._imp011_thread_summary)
    _apply_exact_source_line = staticmethod(_threads._apply_exact_source_line)
    inspect_thread_callstacks_and_locks = _threads.inspect_thread_callstacks_and_locks
    inspect_thread_locals_and_frame_vars = _threads.inspect_thread_locals_and_frame_vars

    # --- extractor/inspection/tls.py: thread-local storage, TCB discovery, concurrent-read consistency ---
    _tls_first_block_offset_aarch64 = staticmethod(_tls._tls_first_block_offset_aarch64)
    _discover_thread_pointers_aarch64 = _tls._discover_thread_pointers_aarch64
    _discover_thread_tcb_addresses = _tls._discover_thread_tcb_addresses
    inspect_thread_local_storage = _tls.inspect_thread_local_storage
    verify_concurrent_read_consistency = _tls.verify_concurrent_read_consistency

    # --- extractor/inspection/expressions.py: symbol-path expressions and typed decoding ---
    _tokenize_symbol_expression = staticmethod(_expressions._tokenize_symbol_expression)
    _decode_typed_memory = _expressions._decode_typed_memory
    evaluate_symbol_paths = _expressions.evaluate_symbol_paths
    _resolve_expression_to_target = _expressions._resolve_expression_to_target
    _find_primary_pool_array_member = staticmethod(_expressions._find_primary_pool_array_member)
    _reconstruct_expression_from_ops = staticmethod(_expressions._reconstruct_expression_from_ops)
    coerce_and_resolve_expression = _expressions.coerce_and_resolve_expression
    build_self_repairing_diagnostic = _expressions.build_self_repairing_diagnostic

    # --- extractor/inspection/baselines.py: capture-and-diff, golden baselines, scenario recipes ---
    capture_and_diff_expressions = _baselines.capture_and_diff_expressions
    _auto_select_diagnostic_expressions = _baselines._auto_select_diagnostic_expressions
    save_golden_baseline = _baselines.save_golden_baseline
    list_golden_baselines = _baselines.list_golden_baselines
    get_golden_baseline = _baselines.get_golden_baseline
    compare_with_golden_baseline = _baselines.compare_with_golden_baseline
    run_diagnostic_recipe = _baselines.run_diagnostic_recipe

    # --- extractor/inspection/pools.py: pool/array scanner, owner lookup, x-ray blueprint, linked structures ---
    scan_memory_pool_or_array = _pools.scan_memory_pool_or_array
    find_symbol_owners_and_threads = _pools.find_symbol_owners_and_threads
    get_process_xray_blueprint = _pools.get_process_xray_blueprint
    traverse_linked_structure = _pools.traverse_linked_structure

    # --- extractor/inspection/memory.py: memory integrity audit, code pointers, heap objects ---
    audit_memory_integrity = _memory.audit_memory_integrity
    resolve_code_pointers = _memory.resolve_code_pointers
    scan_heap_objects = _memory.scan_heap_objects

    # --- extractor/inspection/ipc.py: shared memory / IPC pipelines, DPDK lcores and rings ---
    inspect_shared_memory_ipc = _ipc.inspect_shared_memory_ipc
    trace_ipc_pipeline = _ipc.trace_ipc_pipeline
    inspect_dpdk_lcores_and_rings = _ipc.inspect_dpdk_lcores_and_rings

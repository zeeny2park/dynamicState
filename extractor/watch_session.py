"""Phase 21: Persistent Watch Session and Temporal Memory Explorer Foundation.

Enforces:
1. Versioned, validated observation schemas (ObservationSession, WatchItem, Observation, CaptureGap, AllocationEvent).
2. GNU Build ID and architecture validation between companion ELF and live target process.
3. Durable persistence to disk (survives UI refreshes and server restarts).
4. Zero-stop / non-intrusive memory sampling via process_vm_readv with fallback to /proc/<pid>/mem.
5. No synthetic data in production paths: missing samples marked explicitly as UNAVAILABLE or PARTIAL.
6. Truthful capability reporting: allocation events marked UNSUPPORTED when heap tracer is absent.
7. Replay semantics: ordered by sequence number and monotonic timestamp.

This module holds the watch-session lifecycle (schemas, persistence, create/stop, watch items, sampling, the
capture worker, observation comparison).  The inspection methods of ``WatchSessionManager`` (threads/locks, TLS,
memory audit, pools, expressions, baselines, triage, recorder, target context, batch macro, hypotheses) live in
``extractor/inspection/`` as functions taking the manager first and are bound on the class at the bottom, so
``manager.<method>(...)`` is unchanged for the MCP server, the web server, the CLI and the evidence provider.
No verdict is generated here (IMP-017).
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional, Tuple, Union
import uuid

from .debug_image import BinaryIdentity, inspect_elf
from .target_adapter import TargetExecutionAdapter, LocalTargetAdapter, RemoteSshTargetAdapter
from .target_abi import TargetABI, detect_target_abi

# Re-exported: imported or patched as extractor.watch_session.<name> elsewhere (mcp_server, tests, ebpf/heap readers).
from .target_abi import check_support  # noqa: F401
from .verdict_engine import sanitize_report_output_path  # noqa: F401
from .inspection.process_memory import (  # noqa: F401
    ZERO_STOP_NON_ATOMIC_CONSISTENCY,
    decode_value_from_bytes,
    read_process_memory_slice,
)
from .inspection.process_maps import calculate_load_bias  # noqa: F401

from .inspection import (
    baselines as _baselines,
    batch as _batch,
    context as _context,
    expressions as _expressions,
    hypothesis as _hypothesis,
    ipc as _ipc,
    memory as _memory,
    pools as _pools,
    process_maps as _process_maps,
    profiler as _profiler,
    recorder as _recorder,
    threads as _threads,
    tls as _tls,
    triage as _triage,
)


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
    # Inspection facade: functions in extractor/inspection/* take the manager first and are bound here as
    # methods (static/class methods where they were), so callers keep using manager.<method>(...).
    # -------------------------------------------------------------------------

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

    # --- extractor/inspection/triage.py: auto-triage scan, symptom investigator, dependency graph, source correlation ---
    auto_triage_incident = _triage.auto_triage_incident
    build_dependency_graph = _triage.build_dependency_graph
    correlate_source_and_state = _triage.correlate_source_and_state
    investigate_symptom = _triage.investigate_symptom

    # --- extractor/inspection/profiler.py: statistical hotspots, fuzzy symbol intent ---
    _read_thread_cpu_ticks_local = staticmethod(_profiler._read_thread_cpu_ticks_local)
    sample_statistical_hotspots = _profiler.sample_statistical_hotspots
    resolve_fuzzy_symbol_intent = _profiler.resolve_fuzzy_symbol_intent

    # --- extractor/inspection/recorder.py: watch-until-condition, flight recorder, behavioural drift ---
    _parse_condition_clauses = staticmethod(_recorder._parse_condition_clauses)
    _coerce_numeric_or_str = staticmethod(_recorder._coerce_numeric_or_str)
    _evaluate_parsed_clauses = classmethod(_recorder._evaluate_parsed_clauses)
    watch_until_condition = _recorder.watch_until_condition
    _flatten_decoded_value = classmethod(_recorder._flatten_decoded_value)
    flight_recorder_time_machine = _recorder.flight_recorder_time_machine
    detect_behavioral_drift = _recorder.detect_behavioral_drift

    # --- extractor/inspection/context.py: target-context binding and resolution ---
    _coerce_int = staticmethod(_context._coerce_int)
    get_active_target_context = _context.get_active_target_context
    bind_target_context = _context.bind_target_context
    resolve_target_context = _context.resolve_target_context

    # --- extractor/inspection/batch.py: runtime questions, token budget, batch macro ---
    _coerce_steps_list = staticmethod(_batch._coerce_steps_list)
    ask_runtime_question = _batch.ask_runtime_question
    summarize_for_llm_budget = _batch.summarize_for_llm_budget
    smart_compact_query = _batch.smart_compact_query
    execute_batch_macro = _batch.execute_batch_macro

    # --- extractor/inspection/hypothesis.py: hypothesis assertions, incident report export ---
    _parse_single_assertion = staticmethod(_hypothesis._parse_single_assertion)
    _compare_assertion_values = staticmethod(_hypothesis._compare_assertion_values)
    verify_runtime_hypothesis = _hypothesis.verify_runtime_hypothesis
    export_incident_report = _hypothesis.export_incident_report

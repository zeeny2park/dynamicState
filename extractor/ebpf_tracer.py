"""Phase 1 eBPF Stack-Variable & Function Tracing Proof of Concept (Hardened).

Provides an isolated, optional eBPF-based userspace function tracing backend that:
1. Validates target process existence, access, and executable identity (/proc/<pid>/exe, Build ID).
2. Supports stripped production binaries using matching external debug ELFs and precise file offsets.
3. Attaches uprobe (function entry) and uretprobe (function return) to target binary without pipe deadlock.
4. Filters strictly by target PID.
5. Records monotonic/real timestamps, PID/TID, probe type, function identity,
   architecture-supported argument and register values, and stack pointer / frame metadata.
6. Distinguishes observed values, unavailable values, unsupported features, and lost events.
7. Preserves existing CONSISTENT and LOW_IMPACT semantics: observations are explicitly
   labeled as PROBE_POINT_EVENT and never misrepresented as consistent process-wide snapshots.
8. Provides a clean interface (DwarfLocationResolverInterface) for future Phase 2 DWARF location evaluation.
"""

from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import os
import platform
import re
import shutil
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional, Tuple, Union
import uuid

from .debug_image import BinaryIdentity, inspect_elf
from .dwarf_indexer import DwarfIndex, DwarfIndexer, DwarfSubprogram


# -----------------------------------------------------------------------------
# Value status indicators & Observation schemas
# -----------------------------------------------------------------------------

STATUS_OBSERVED = "OBSERVED"
STATUS_UNAVAILABLE = "UNAVAILABLE"
STATUS_UNSUPPORTED_PHASE1 = "UNSUPPORTED_PHASE1"
STATUS_LOST = "LOST"


@dataclass
class TraceValue:
    """Represents an observed, unavailable, or unsupported variable/register/argument value."""
    name: str
    status: str                         # OBSERVED, UNAVAILABLE, UNSUPPORTED_PHASE1, LOST
    value: Optional[Union[int, str, float, bool]] = None
    value_hex: Optional[str] = None
    location: Optional[str] = None      # e.g., "register:arg0", "register:sp", "stack:0x..."
    type_name: Optional[str] = None
    reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "value": self.value,
            "value_hex": self.value_hex,
            "location": self.location,
            "type_name": self.type_name,
            "reason": self.reason,
        }


@dataclass
class FrameMetadata:
    """Architecture-specific frame and stack pointer metadata."""
    stack_pointer: Optional[int] = None
    frame_pointer: Optional[int] = None
    instruction_pointer: Optional[int] = None
    return_address: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stack_pointer": f"0x{self.stack_pointer:x}" if self.stack_pointer is not None else None,
            "frame_pointer": f"0x{self.frame_pointer:x}" if self.frame_pointer is not None else None,
            "instruction_pointer": f"0x{self.instruction_pointer:x}" if self.instruction_pointer is not None else None,
            "return_address": f"0x{self.return_address:x}" if self.return_address is not None else None,
        }


@dataclass
class TraceEvent:
    """Individual observation event from an entry or return probe."""
    sequence: int
    timestamp_ns: int
    pid: int
    tid: int
    probe_type: str                     # "ENTRY" or "RETURN"
    function_name: str
    function_offset: Optional[int]
    registers: Dict[str, int] = field(default_factory=dict)
    arguments: Dict[str, TraceValue] = field(default_factory=dict)
    return_value: Optional[TraceValue] = None
    frame_metadata: Optional[FrameMetadata] = None
    local_variables: Dict[str, TraceValue] = field(default_factory=dict)
    raw_payload: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "sequence": self.sequence,
            "timestamp_ns": self.timestamp_ns,
            "pid": self.pid,
            "tid": self.tid,
            "probe_type": self.probe_type,
            "function_name": self.function_name,
            "function_offset": f"0x{self.function_offset:x}" if self.function_offset is not None else None,
            "registers": {k: f"0x{v:x}" for k, v in self.registers.items()},
            "arguments": {k: v.to_dict() for k, v in self.arguments.items()},
            "return_value": self.return_value.to_dict() if self.return_value else None,
            "frame_metadata": self.frame_metadata.to_dict() if self.frame_metadata else None,
            "local_variables": {k: v.to_dict() for k, v in self.local_variables.items()},
            "raw_payload": self.raw_payload,
        }


@dataclass
class TraceObservationSession:
    """Complete record of an eBPF tracing session."""
    session_id: str
    target_pid: int
    target_binary: str
    function_name: str
    architecture: str
    backend_name: str
    start_time: str
    target_build_id: Optional[str] = None
    build_id_status: str = "VERIFIED"              # VERIFIED, MISMATCHED, UNAVAILABLE, EXPLICITLY_UNCHECKED
    probe_offset: Optional[str] = None             # e.g., "0xc90"
    end_time: Optional[str] = None
    events: List[TraceEvent] = field(default_factory=list)
    total_events: int = 0
    lost_events: int = 0
    malformed_records: int = 0
    overhead_stats: Dict[str, Any] = field(default_factory=dict)
    consistency_level: str = "PROBE_POINT_EVENT"   # Strictly distinguished from CONSISTENT or LOW_IMPACT snapshots!
    status: str = "SUCCESS"                        # SUCCESS, PARTIAL, UNSUPPORTED_ENVIRONMENT, PERMISSION_DENIED, FAILED
    error_message: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "target_pid": self.target_pid,
            "target_binary": self.target_binary,
            "target_build_id": self.target_build_id,
            "build_id_status": self.build_id_status,
            "function_name": self.function_name,
            "probe_offset": self.probe_offset,
            "architecture": self.architecture,
            "backend_name": self.backend_name,
            "start_time": self.start_time,
            "end_time": self.end_time,
            "consistency_level": self.consistency_level,
            "status": self.status,
            "error_message": self.error_message,
            "total_events": self.total_events,
            "lost_events": self.lost_events,
            "malformed_records": self.malformed_records,
            "overhead_stats": self.overhead_stats,
            "events": [e.to_dict() for e in self.events],
        }


# -----------------------------------------------------------------------------
# Interface for Future DWARF Location Evaluation (Phase 2 Interface)
# -----------------------------------------------------------------------------

class DwarfLocationResolverInterface(ABC):
    """Abstract contract for dynamic DWARF location evaluation."""

    @abstractmethod
    def resolve_variable(
        self,
        subprogram: Optional[DwarfSubprogram],
        variable_name: str,
        registers: Dict[str, int],
        frame_metadata: FrameMetadata,
    ) -> TraceValue:
        """Evaluate a local variable's runtime location and value."""
        pass


class Phase1DwarfLocationResolver(DwarfLocationResolverInterface):
    """Phase 1 stub resolver that explicitly documents deferred local variable evaluation."""

    def resolve_variable(
        self,
        subprogram: Optional[DwarfSubprogram],
        variable_name: str,
        registers: Dict[str, int],
        frame_metadata: FrameMetadata,
    ) -> TraceValue:
        return TraceValue(
            name=variable_name,
            status=STATUS_UNSUPPORTED_PHASE1,
            value=None,
            value_hex=None,
            location=None,
            reason=(
                "DWARF-based dynamic location evaluation for arbitrary stack/local variables inside "
                "function bodies is deferred to Phase 2. Phase 1 only establishes function entry "
                "and return probe locations."
            ),
        )


# -----------------------------------------------------------------------------
# Environment and Capability Inspection
# -----------------------------------------------------------------------------

@dataclass
class EbpfCapabilityResult:
    """Report on kernel, architecture, and privilege prerequisites for eBPF tracing."""
    supported: bool
    backend: str                        # "bpftrace", "libbpf", "none"
    architecture: str
    kernel_version: str
    is_privileged: bool
    unprivileged_bpf_disabled: int
    has_bpf_fs: bool
    bpftrace_path: Optional[str] = None
    clang_path: Optional[str] = None
    reasons: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class EbpfEnvironmentChecker:
    """Verifies kernel, architecture, compilers, privileges, and dependency requirements."""

    @classmethod
    def check_prerequisites(cls) -> EbpfCapabilityResult:
        reasons: List[str] = []
        is_linux = sys.platform.startswith("linux")
        if not is_linux:
            return EbpfCapabilityResult(
                supported=False,
                backend="none",
                architecture=platform.machine(),
                kernel_version=platform.release(),
                is_privileged=False,
                unprivileged_bpf_disabled=2,
                has_bpf_fs=False,
                reasons=["eBPF tracing is only supported on Linux."],
            )

        arch = platform.machine()
        if arch not in ("x86_64", "aarch64", "arm64"):
            reasons.append(f"Architecture '{arch}' not fully validated for userspace uprobe tracing.")

        kernel_ver = platform.release()

        # Check privileges
        euid = os.geteuid() if hasattr(os, "geteuid") else -1
        is_root = (euid == 0)
        has_sudo = False
        if not is_root:
            try:
                res = subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=1.0)
                if res.returncode == 0:
                    has_sudo = True
            except Exception:
                pass

        is_privileged = is_root or has_sudo

        # Check /proc/sys/kernel/unprivileged_bpf_disabled
        unpriv_val = 2
        try:
            with open("/proc/sys/kernel/unprivileged_bpf_disabled", "r") as f:
                unpriv_val = int(f.read().strip())
        except Exception:
            pass

        if unpriv_val != 0 and not is_privileged:
            reasons.append(
                "Unprivileged eBPF is disabled (/proc/sys/kernel/unprivileged_bpf_disabled != 0) "
                "and current user lacks root or passwordless sudo privileges (CAP_BPF / CAP_SYS_ADMIN required)."
            )

        # Check /sys/fs/bpf
        has_bpf_fs = os.path.exists("/sys/fs/bpf")
        if not has_bpf_fs:
            reasons.append("BPF filesystem (/sys/fs/bpf) is not mounted.")

        bpftrace_path = shutil.which("bpftrace")
        clang_path = shutil.which("clang")
        has_libbpf_headers = os.path.exists("/usr/include/bpf/bpf.h")

        # Phase 1 only executes bpftrace.
        # Report backend truthfully:
        if bpftrace_path:
            backend = "bpftrace"
        elif clang_path and has_libbpf_headers:
            backend = "libbpf"
            reasons.append(
                "bpftrace executable not found in PATH. libbpf execution backend is not "
                "implemented in Phase 1 (deferred to Phase 2)."
            )
        else:
            backend = "none"
            reasons.append("bpftrace executable not found in PATH.")

        supported = (len(reasons) == 0) and is_privileged and (backend == "bpftrace")

        return EbpfCapabilityResult(
            supported=supported,
            backend=backend,
            architecture=arch,
            kernel_version=kernel_ver,
            is_privileged=is_privileged,
            unprivileged_bpf_disabled=unpriv_val,
            has_bpf_fs=has_bpf_fs,
            bpftrace_path=bpftrace_path,
            clang_path=clang_path,
            reasons=reasons,
        )


# -----------------------------------------------------------------------------
# Pure-Python ELF Symbol Resolver (Fallback for binaries without DWARF)
# -----------------------------------------------------------------------------

def find_elf_symbols(path: str, sym_name: str) -> List[int]:
    """Extract symbol virtual addresses from ELF .symtab or .dynsym sections."""
    if not os.path.exists(path):
        return []
    try:
        with open(path, "rb") as f:
            ident = f.read(16)
            if len(ident) < 16 or ident[:4] != b"\x7fELF":
                return []
            is_64 = ident[4] == 2
            endian = "<" if ident[5] == 1 else ">"
            f.seek(16)
            if is_64:
                hdr = f.read(48)
                if len(hdr) < 48:
                    return []
                e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack(
                    endian + "HHIQQQIHHHHHH", hdr
                )
            else:
                hdr = f.read(36)
                if len(hdr) < 36:
                    return []
                e_type, e_machine, e_version, e_entry, e_phoff, e_shoff, e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, e_shstrndx = struct.unpack(
                    endian + "HHIIIIIHHHHHH", hdr
                )

            if e_shoff == 0 or e_shnum == 0 or e_shentsize == 0:
                return []

            f.seek(e_shoff)
            sh_data = f.read(e_shentsize * e_shnum)
            sections = []
            for i in range(e_shnum):
                chunk = sh_data[i * e_shentsize : (i + 1) * e_shentsize]
                if len(chunk) < e_shentsize:
                    break
                if is_64:
                    sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack(
                        endian + "IIQQQQIIQQ", chunk
                    )
                else:
                    sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = struct.unpack(
                        endian + "IIIIIIIIII", chunk
                    )
                sections.append({
                    "type": sh_type,
                    "offset": sh_offset,
                    "size": sh_size,
                    "link": sh_link,
                    "entsize": sh_entsize,
                })

            matches = []
            # SHT_SYMTAB = 2, SHT_DYNSYM = 11
            for s in sections:
                if s["type"] in (2, 11) and s["entsize"] > 0 and 0 <= s["link"] < len(sections):
                    strtab_sec = sections[s["link"]]
                    f.seek(strtab_sec["offset"])
                    strtab = f.read(strtab_sec["size"])

                    f.seek(s["offset"])
                    sym_data = f.read(s["size"])
                    num_syms = s["size"] // s["entsize"]
                    for j in range(num_syms):
                        sym_chunk = sym_data[j * s["entsize"] : (j + 1) * s["entsize"]]
                        if is_64:
                            st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack(
                                endian + "IBBHQQ", sym_chunk
                            )
                        else:
                            st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack(
                                endian + "IIIBBH", sym_chunk
                            )

                        if st_name < len(strtab):
                            end = strtab.find(b"\x00", st_name)
                            if end == -1:
                                end = len(strtab)
                            cur_name = strtab[st_name:end].decode("latin1", errors="replace")
                            if cur_name == sym_name:
                                matches.append(st_value)
            return matches
    except Exception:
        return []


# -----------------------------------------------------------------------------
# Event Decoder
# -----------------------------------------------------------------------------

class EbpfEventDecoder:
    """Robust decoder for streaming eBPF probe records.

    Handles JSON-encoded or delimited event records, filters by target PID,
    and isolates corrupted or truncated lines without raising exceptions.
    """

    def __init__(self, target_pid: int, architecture: str, function_name: str, function_offset: Optional[int] = None):
        self.target_pid = target_pid
        self.architecture = architecture
        self.function_name = function_name
        self.function_offset = function_offset
        self.sequence_counter = 0
        self.malformed_count = 0
        self.lost_count = 0
        self.resolver: DwarfLocationResolverInterface = Phase1DwarfLocationResolver()

    def decode_line(self, line: str) -> Optional[TraceEvent]:
        """Decode a single line of probe output. Returns None if ignored or malformed."""
        line = line.strip()
        if not line:
            return None

        # Filter out informational / warning lines from bpftrace
        if (
            line.startswith("Attaching ")
            or line.startswith("READY ")
            or line.startswith("WARNING: ")
            or line.startswith("INFO: ")
            or line.startswith("Program ID: ")
            or line.startswith("The verifier log:")
            or line.startswith("processed ")
        ):
            return None

        # Detect dropped event markers from bpftrace / kernel ringbuffer
        if "lost" in line.lower() and ("event" in line.lower() or "sample" in line.lower()):
            m = re.search(r"lost\s+(\d+)\s+(?:events?|samples?)", line, re.IGNORECASE)
            if m:
                self.lost_count += int(m.group(1))
            else:
                self.lost_count += 1
            return None

        # Attempt JSON decoding
        payload: Optional[Dict[str, Any]] = None
        if line.startswith("{"):
            try:
                payload = json.loads(line)
            except Exception:
                self.malformed_count += 1
                return None
        else:
            # Fallback: Key-value parser (e.g. TYPE=ENTRY pid=123 ...)
            payload = self._parse_kv_line(line)
            if not payload:
                # Unrecognized line
                return None

        # Filter strictly by PID
        pid = payload.get("pid")
        if pid is None:
            return None
        try:
            if int(pid) != self.target_pid:
                return None
        except (ValueError, TypeError):
            return None

        tid = int(payload.get("tid", pid))
        probe_type = str(payload.get("type", "ENTRY")).upper()
        timestamp_ns = int(payload.get("time", time.time_ns()))

        self.sequence_counter += 1

        # Extract registers and frame metadata based on architecture
        registers: Dict[str, int] = {}
        sp: Optional[int] = None
        fp: Optional[int] = None
        pc: Optional[int] = None
        ra: Optional[int] = None

        for k, v in payload.items():
            if k in ("type", "pid", "tid", "time"):
                continue
            int_val: Optional[int] = None
            if isinstance(v, int):
                int_val = v
            elif isinstance(v, str):
                try:
                    int_val = int(v, 16) if v.startswith("0x") or v.startswith("0X") else int(v)
                except ValueError:
                    pass
            if int_val is not None:
                registers[k] = int_val
                if k in ("sp", "rsp"):
                    sp = int_val
                elif k in ("fp", "bp", "rbp", "x29", "r29"):
                    fp = int_val
                elif k in ("pc", "ip", "rip"):
                    pc = int_val
                elif k in ("ra", "lr", "r30"):
                    ra = int_val

        frame_meta = FrameMetadata(
            stack_pointer=sp,
            frame_pointer=fp,
            instruction_pointer=pc,
            return_address=ra,
        )

        arguments: Dict[str, TraceValue] = {}
        return_value: Optional[TraceValue] = None

        if probe_type == "ENTRY":
            # Map registers to standard calling convention arguments
            # x86_64: arg0=rdi, arg1=rsi, arg2=rdx, arg3=rcx, arg4=r8, arg5=r9
            # aarch64: arg0=x0, arg1=x1, arg2=x2, arg3=x3, arg4=x4, arg5=x5, arg6=x6, arg7=x7
            for i in range(8):
                arg_key = f"arg{i}"
                if arg_key in registers:
                    arguments[f"param_{i}"] = TraceValue(
                        name=f"param_{i}",
                        status=STATUS_OBSERVED,
                        value=registers[arg_key],
                        value_hex=f"0x{registers[arg_key]:x}",
                        location=f"register:{arg_key}",
                    )
        elif probe_type == "RETURN":
            ret_val = payload.get("ret")
            if ret_val is not None:
                int_ret = None
                try:
                    int_ret = int(ret_val, 16) if str(ret_val).startswith("0x") else int(ret_val)
                except ValueError:
                    pass
                if int_ret is not None:
                    return_value = TraceValue(
                        name="return_value",
                        status=STATUS_OBSERVED,
                        value=int_ret,
                        value_hex=f"0x{int_ret:x}",
                        location="register:retval",
                    )
                else:
                    return_value = TraceValue(
                        name="return_value",
                        status=STATUS_UNAVAILABLE,
                        reason="Failed to parse return value",
                    )

        # Local variables: explicitly mark as deferred in Phase 1
        local_vars: Dict[str, TraceValue] = {
            "local_variables": self.resolver.resolve_variable(None, "locals", registers, frame_meta)
        }

        return TraceEvent(
            sequence=self.sequence_counter,
            timestamp_ns=timestamp_ns,
            pid=pid,
            tid=tid,
            probe_type=probe_type,
            function_name=self.function_name,
            function_offset=self.function_offset,
            registers=registers,
            arguments=arguments,
            return_value=return_value,
            frame_metadata=frame_meta,
            local_variables=local_vars,
            raw_payload=line,
        )

    def _parse_kv_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parse key=value pairs from a text line."""
        tokens = line.split()
        kv_pairs: Dict[str, Any] = {}
        for tok in tokens:
            if "=" in tok:
                k, v = tok.split("=", 1)
                kv_pairs[k.lower()] = v
        if "pid" in kv_pairs or "type" in kv_pairs or "sp" in kv_pairs:
            return kv_pairs
        return None


# -----------------------------------------------------------------------------
# eBPF Tracer Engine
# -----------------------------------------------------------------------------

class EbpfTracer:
    """Isolated userspace eBPF function tracing backend."""

    def __init__(self, use_sudo: bool = True):
        self.use_sudo = use_sudo
        self._lock = threading.Lock()

    def trace(
        self,
        pid: int,
        binary_path: str,
        function_name: str,
        debug_image: Optional[str] = None,
        duration_s: float = 3.0,
        entry_only: bool = False,
        verify_build_id: bool = True,
    ) -> TraceObservationSession:
        """Trace function execution using eBPF uprobe/uretprobe."""
        t_start_iso = datetime.now(timezone.utc).isoformat()
        t0 = time.monotonic()
        session_id = f"trace_ebpf_{uuid.uuid4().hex[:12]}"

        # 1. Validate target process PID and accessibility
        if pid <= 0:
            return TraceObservationSession(
                session_id=session_id,
                target_pid=pid,
                target_binary=binary_path,
                target_build_id=None,
                build_id_status="UNAVAILABLE",
                function_name=function_name,
                probe_offset=None,
                architecture=platform.machine(),
                backend_name="none",
                start_time=t_start_iso,
                end_time=datetime.now(timezone.utc).isoformat(),
                status="FAILED",
                error_message=f"Invalid target PID: {pid}",
            )

        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return TraceObservationSession(
                session_id=session_id,
                target_pid=pid,
                target_binary=binary_path,
                target_build_id=None,
                build_id_status="UNAVAILABLE",
                function_name=function_name,
                probe_offset=None,
                architecture=platform.machine(),
                backend_name="none",
                start_time=t_start_iso,
                end_time=datetime.now(timezone.utc).isoformat(),
                status="FAILED",
                error_message=f"Target process PID {pid} does not exist",
            )
        except PermissionError:
            # PID exists, but cannot signal without root/sudo
            pass

        # 2. Inspect target binary ELF & Build ID
        abs_binary = os.path.abspath(binary_path)
        if not os.path.exists(abs_binary):
            return TraceObservationSession(
                session_id=session_id,
                target_pid=pid,
                target_binary=abs_binary,
                target_build_id=None,
                build_id_status="UNAVAILABLE",
                function_name=function_name,
                probe_offset=None,
                architecture=platform.machine(),
                backend_name="none",
                start_time=t_start_iso,
                end_time=datetime.now(timezone.utc).isoformat(),
                status="FAILED",
                error_message=f"Binary file not found: {abs_binary}",
            )

        elf_info: BinaryIdentity = inspect_elf(abs_binary)
        target_build_id = elf_info.build_id
        arch = elf_info.architecture

        # 3. Validate running process identity (/proc/<pid>/exe)
        proc_exe_path = f"/proc/{pid}/exe"
        if os.path.exists(proc_exe_path):
            try:
                proc_real = os.path.realpath(proc_exe_path)
                req_real = os.path.realpath(abs_binary)
                if proc_real != req_real:
                    s_proc = os.stat(proc_exe_path)
                    s_req = os.stat(abs_binary)
                    if (s_proc.st_dev, s_proc.st_ino) != (s_req.st_dev, s_req.st_ino):
                        proc_elf = inspect_elf(proc_exe_path)
                        if not proc_elf.build_id or proc_elf.build_id != target_build_id:
                            return TraceObservationSession(
                                session_id=session_id,
                                target_pid=pid,
                                target_binary=abs_binary,
                                target_build_id=target_build_id,
                                build_id_status="MISMATCHED",
                                function_name=function_name,
                                probe_offset=None,
                                architecture=arch,
                                backend_name="none",
                                start_time=t_start_iso,
                                end_time=datetime.now(timezone.utc).isoformat(),
                                status="FAILED",
                                error_message=(
                                    f"Target PID {pid} running executable '{proc_real}' does not match "
                                    f"requested binary '{req_real}'"
                                ),
                            )
            except (PermissionError, FileNotFoundError, OSError):
                # Namespace / container visibility restriction
                pass

        # 4. Validate Build ID & external debug image
        build_id_status = "UNAVAILABLE"
        if not verify_build_id:
            build_id_status = "EXPLICITLY_UNCHECKED"
        else:
            if debug_image:
                abs_dbg = os.path.abspath(debug_image)
                if not os.path.exists(abs_dbg):
                    return TraceObservationSession(
                        session_id=session_id,
                        target_pid=pid,
                        target_binary=abs_binary,
                        target_build_id=target_build_id,
                        build_id_status="UNAVAILABLE",
                        function_name=function_name,
                        probe_offset=None,
                        architecture=arch,
                        backend_name="none",
                        start_time=t_start_iso,
                        end_time=datetime.now(timezone.utc).isoformat(),
                        status="FAILED",
                        error_message=f"Debug image not found: {abs_dbg}",
                    )
                dbg_info = inspect_elf(abs_dbg)
                if dbg_info.architecture != elf_info.architecture:
                    return TraceObservationSession(
                        session_id=session_id,
                        target_pid=pid,
                        target_binary=abs_binary,
                        target_build_id=target_build_id,
                        build_id_status="MISMATCHED",
                        function_name=function_name,
                        probe_offset=None,
                        architecture=arch,
                        backend_name="none",
                        start_time=t_start_iso,
                        end_time=datetime.now(timezone.utc).isoformat(),
                        status="FAILED",
                        error_message=(
                            f"Architecture mismatch: binary '{elf_info.architecture}' != debug image '{dbg_info.architecture}'"
                        ),
                    )
                if target_build_id and dbg_info.build_id:
                    if target_build_id != dbg_info.build_id:
                        return TraceObservationSession(
                            session_id=session_id,
                            target_pid=pid,
                            target_binary=abs_binary,
                            target_build_id=target_build_id,
                            build_id_status="MISMATCHED",
                            function_name=function_name,
                            probe_offset=None,
                            architecture=arch,
                            backend_name="none",
                            start_time=t_start_iso,
                            end_time=datetime.now(timezone.utc).isoformat(),
                            status="FAILED",
                            error_message=(
                                f"Build ID mismatch: binary '{target_build_id}' != debug image '{dbg_info.build_id}'"
                            ),
                        )
                    build_id_status = "VERIFIED"
                else:
                    build_id_status = "UNAVAILABLE"
            else:
                if target_build_id:
                    build_id_status = "VERIFIED"
                else:
                    build_id_status = "UNAVAILABLE"

        # 5. Check environment prerequisites
        cap = EbpfEnvironmentChecker.check_prerequisites()
        if not cap.supported:
            fail_status = "PERMISSION_DENIED" if not cap.is_privileged else "UNSUPPORTED_ENVIRONMENT"
            return TraceObservationSession(
                session_id=session_id,
                target_pid=pid,
                target_binary=abs_binary,
                target_build_id=target_build_id,
                build_id_status=build_id_status,
                function_name=function_name,
                probe_offset=None,
                architecture=arch,
                backend_name=cap.backend,
                start_time=t_start_iso,
                end_time=datetime.now(timezone.utc).isoformat(),
                status=fail_status,
                error_message="; ".join(cap.reasons),
            )

        # 6. Resolve probe target and file offset
        func_offset, attach_spec, resolve_err = self._resolve_probe_target(
            elf_info=elf_info,
            binary_path=abs_binary,
            function_name=function_name,
            debug_image=debug_image,
        )
        probe_offset_str = f"0x{func_offset:x}" if func_offset is not None else None

        if resolve_err or not attach_spec:
            return TraceObservationSession(
                session_id=session_id,
                target_pid=pid,
                target_binary=abs_binary,
                target_build_id=target_build_id,
                build_id_status=build_id_status,
                function_name=function_name,
                probe_offset=None,
                architecture=arch,
                backend_name=cap.backend,
                start_time=t_start_iso,
                end_time=datetime.now(timezone.utc).isoformat(),
                status="FAILED",
                error_message=resolve_err or f"Failed to resolve probe target for '{function_name}'",
            )

        # 7. Generate probe script (bpftrace-based bounded format)
        probe_script = self._generate_bpftrace_script(
            binary_path=abs_binary,
            attach_spec=attach_spec,
            target_pid=pid,
            arch=arch,
            entry_only=entry_only,
        )

        # 8. Launch probe process with guaranteed cleanup
        decoder = EbpfEventDecoder(
            target_pid=pid,
            architecture=arch,
            function_name=function_name,
            function_offset=func_offset,
        )

        events: List[TraceEvent] = []
        attach_latency_ms = 0.0
        script_file = None
        proc: Optional[subprocess.Popen] = None
        stderr_lines: List[str] = []
        target_alive = True

        try:
            with tempfile.NamedTemporaryFile("w", suffix=".bt", delete=False) as f:
                f.write(probe_script)
                script_file = f.name

            cmd = []
            if self.use_sudo and os.geteuid() != 0:
                cmd.extend(["sudo", "-n"])
            cmd.extend(["bpftrace", "--unsafe", "-B", "none", script_file])

            import select
            t_attach_start = time.monotonic()
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                start_new_session=True,
            )

            # Wait for attach confirmation ("Attaching ...") while draining stderr to prevent deadlock
            timeout_attach = time.monotonic() + 5.0
            attached = False
            while time.monotonic() < timeout_attach:
                if proc.poll() is not None:
                    break
                rlist, _, _ = select.select([proc.stdout, proc.stderr], [], [], 0.05)
                for r in rlist:
                    if r == proc.stdout:
                        line = proc.stdout.readline()
                        if "Attaching " in line:
                            attached = True
                            attach_latency_ms = round((time.monotonic() - t_attach_start) * 1000, 2)
                            break
                    elif r == proc.stderr:
                        err_line = proc.stderr.readline()
                        if err_line and len(stderr_lines) < 200:
                            stderr_lines.append(err_line.strip())
                if attached:
                    break

            if not attached and proc.poll() is not None:
                try:
                    for l in proc.stderr.readlines():
                        stderr_lines.append(l.strip())
                except Exception:
                    pass
                err_msg = "\n".join(stderr_lines).strip()
                return TraceObservationSession(
                    session_id=session_id,
                    target_pid=pid,
                    target_binary=abs_binary,
                    target_build_id=target_build_id,
                    build_id_status=build_id_status,
                    function_name=function_name,
                    probe_offset=probe_offset_str,
                    architecture=arch,
                    backend_name="bpftrace",
                    start_time=t_start_iso,
                    end_time=datetime.now(timezone.utc).isoformat(),
                    status="FAILED",
                    error_message=f"bpftrace process terminated prematurely: {err_msg}",
                )

            # Collect events for the specified duration
            end_deadline = time.monotonic() + duration_s
            max_events = 10000
            while time.monotonic() < end_deadline:
                if proc.poll() is not None:
                    break
                # Check target process liveness
                try:
                    os.kill(pid, 0)
                except OSError:
                    target_alive = False
                    break

                rlist, _, _ = select.select([proc.stdout, proc.stderr], [], [], 0.05)
                for r in rlist:
                    if r == proc.stdout:
                        line = proc.stdout.readline()
                        if line:
                            ev = decoder.decode_line(line)
                            if ev is not None:
                                events.append(ev)
                                if len(events) >= max_events:
                                    break
                    elif r == proc.stderr:
                        err_line = proc.stderr.readline()
                        if err_line and len(stderr_lines) < 200:
                            stderr_lines.append(err_line.strip())

                if len(events) >= max_events:
                    break

        finally:
            # Reliable attach/detach cleanup
            if proc:
                try:
                    if proc.poll() is None:
                        # Send SIGINT to entire process group
                        if self.use_sudo and os.geteuid() != 0:
                            subprocess.run(["sudo", "-n", "kill", "-INT", f"-{proc.pid}"], check=False)
                        else:
                            try:
                                os.killpg(os.getpgid(proc.pid), signal.SIGINT)
                            except OSError:
                                proc.send_signal(signal.SIGINT)
                        try:
                            proc.wait(timeout=2.0)
                        except subprocess.TimeoutExpired:
                            if self.use_sudo and os.geteuid() != 0:
                                subprocess.run(["sudo", "-n", "kill", "-KILL", f"-{proc.pid}"], check=False)
                            else:
                                try:
                                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                                except OSError:
                                    proc.kill()
                            proc.wait(timeout=1.0)
                    if proc.stdout:
                        try:
                            for rem in proc.stdout.readlines():
                                ev = decoder.decode_line(rem)
                                if ev is not None:
                                    events.append(ev)
                        except Exception:
                            pass
                        try:
                            proc.stdout.close()
                        except Exception:
                            pass
                    if proc.stderr:
                        try:
                            proc.stderr.close()
                        except Exception:
                            pass
                except Exception:
                    pass

            if script_file and os.path.exists(script_file):
                try:
                    os.unlink(script_file)
                except Exception:
                    pass

        t_end = time.monotonic()
        total_duration_ms = round((t_end - t0) * 1000, 2)

        status = "SUCCESS"
        error_msg = None
        if not target_alive:
            if len(events) > 0:
                status = "PARTIAL"
                error_msg = f"Target process PID {pid} exited during trace; {len(events)} events captured"
            else:
                status = "FAILED"
                error_msg = f"Target process PID {pid} exited before any events could be captured"
        elif proc and proc.poll() is not None and proc.returncode != 0 and len(events) == 0:
            status = "FAILED"
            err_details = "\n".join(stderr_lines).strip()
            error_msg = f"bpftrace exited with code {proc.returncode}: {err_details}"

        return TraceObservationSession(
            session_id=session_id,
            target_pid=pid,
            target_binary=abs_binary,
            target_build_id=target_build_id,
            build_id_status=build_id_status,
            function_name=function_name,
            probe_offset=probe_offset_str,
            architecture=arch,
            backend_name="bpftrace",
            start_time=t_start_iso,
            end_time=datetime.now(timezone.utc).isoformat(),
            events=events,
            total_events=len(events),
            lost_events=decoder.lost_count,
            malformed_records=decoder.malformed_count,
            overhead_stats={
                "attach_latency_ms": attach_latency_ms,
                "total_trace_duration_ms": total_duration_ms,
                "sample_count": len(events),
            },
            consistency_level="PROBE_POINT_EVENT",
            status=status,
            error_message=error_msg,
        )

    def _resolve_probe_target(
        self,
        elf_info: BinaryIdentity,
        binary_path: str,
        function_name: str,
        debug_image: Optional[str] = None,
    ) -> Tuple[Optional[int], Optional[str], Optional[str]]:
        """Resolve function name or symbol to file-relative probe offset.

        Returns (file_offset, attach_spec, error_message).
        """
        # If user passed an explicit hex offset (e.g. 0xd80)
        if function_name.startswith("0x") or function_name.startswith("0X"):
            try:
                raw_val = int(function_name, 16)
                # Check if raw_val is virtual address or file offset
                fo = self._virt_to_file_offset(elf_info, binary_path, raw_val)
                if fo is not None:
                    return fo, f"0x{fo:x}", None
                file_sz = os.path.getsize(binary_path)
                if 0 <= raw_val < file_sz:
                    return raw_val, f"0x{raw_val:x}", None
                return None, None, f"Specified offset 0x{raw_val:x} is outside binary file size"
            except ValueError:
                pass

        search_path = debug_image if (debug_image and os.path.exists(debug_image)) else binary_path

        # 1. Search DWARF subprograms
        subprograms: List[DwarfSubprogram] = []
        try:
            d_index = DwarfIndexer.get_index(search_path)
            subprograms = d_index.subprograms_by_name.get(function_name, [])
        except Exception:
            pass

        # 2. Search ELF symbols if not found in DWARF
        symbols: List[int] = []
        if not subprograms:
            symbols = find_elf_symbols(search_path, function_name)
            if not symbols and search_path != binary_path:
                symbols = find_elf_symbols(binary_path, function_name)

        if not subprograms and not symbols:
            if elf_info.is_stripped and not debug_image:
                return (
                    None,
                    None,
                    f"Function '{function_name}' could not be resolved: binary is stripped and no "
                    f"matching debug image was provided.",
                )
            return None, None, f"Function '{function_name}' not found in '{search_path}'"

        # 3. Disambiguate overloaded or duplicate functions
        if subprograms:
            distinct_addrs = sorted(list(set(s.low_pc for s in subprograms if s.low_pc is not None)))
            if len(distinct_addrs) > 1:
                addrs_str = ", ".join(f"0x{a:x}" for a in distinct_addrs)
                linkages = [s.linkage_name for s in subprograms if s.linkage_name and s.linkage_name != function_name]
                link_hint = f" (e.g. '{linkages[0]}')" if linkages else ""
                return (
                    None,
                    None,
                    f"Ambiguous function name '{function_name}': matches {len(distinct_addrs)} distinct "
                    f"subprogram locations ({addrs_str}). Disambiguate using mangled linkage name{link_hint} "
                    f"or exact offset.",
                )
            virt_addr = distinct_addrs[0]
        else:
            distinct_addrs = sorted(list(set(symbols)))
            if len(distinct_addrs) > 1:
                addrs_str = ", ".join(f"0x{a:x}" for a in distinct_addrs)
                return (
                    None,
                    None,
                    f"Ambiguous symbol name '{function_name}': matches {len(distinct_addrs)} distinct "
                    f"locations ({addrs_str}). Disambiguate using mangled linkage name or exact offset.",
                )
            virt_addr = distinct_addrs[0]

        # 4. Map virtual address to file-relative offset in the target binary
        file_offset = self._virt_to_file_offset(elf_info, binary_path, virt_addr)
        if file_offset is None:
            return (
                None,
                None,
                f"Virtual address 0x{virt_addr:x} could not be mapped to any PT_LOAD segment in '{binary_path}'",
            )

        file_size = os.path.getsize(binary_path)
        if file_offset < 0 or file_offset >= file_size:
            return (
                None,
                None,
                f"Computed file offset 0x{file_offset:x} exceeds file size ({file_size} bytes)",
            )

        attach_spec = f"0x{file_offset:x}"
        return file_offset, attach_spec, None

    def _virt_to_file_offset(self, elf_info: BinaryIdentity, binary_path: str, virt_addr: int) -> Optional[int]:
        """Convert a virtual address (low_pc) to a file-relative offset using PT_LOAD segments."""
        for seg in elf_info.pt_loads:
            p_vaddr = seg["p_vaddr"]
            p_memsz = seg["p_memsz"]
            p_offset = seg["p_offset"]
            p_filesz = seg["p_filesz"]
            if p_vaddr <= virt_addr < p_vaddr + p_memsz:
                if virt_addr - p_vaddr < p_filesz:
                    return (virt_addr - p_vaddr) + p_offset
        return None

    def _generate_bpftrace_script(
        self,
        binary_path: str,
        attach_spec: str,
        target_pid: int,
        arch: str,
        entry_only: bool,
    ) -> str:
        """Generate a minimal bpftrace script with bounded JSON formatting and PID filter."""
        # Architecture-specific register mappings
        if arch in ("aarch64", "arm64"):
            fp_expr = 'reg("r29")'
            ra_expr = 'reg("r30")'
        else:
            # x86_64
            fp_expr = 'reg("bp")'
            ra_expr = '0'

        entry_probe = f"""uprobe:{binary_path}:{attach_spec}
/pid == {target_pid}/
{{
    printf("{{\\"type\\":\\"ENTRY\\",\\"pid\\":%d,\\"tid\\":%d,\\"time\\":%llu,\\"sp\\":\\"0x%lx\\",\\"pc\\":\\"0x%lx\\",\\"fp\\":\\"0x%lx\\",\\"ra\\":\\"0x%lx\\",\\"arg0\\":%ld,\\"arg1\\":%ld,\\"arg2\\":%ld,\\"arg3\\":%ld,\\"arg4\\":%ld,\\"arg5\\":%ld}}\\n",
           pid, tid, nsecs, reg("sp"), reg("pc"), {fp_expr}, {ra_expr}, arg0, arg1, arg2, arg3, arg4, arg5);
}}
"""
        return_probe = ""
        if not entry_only:
            return_probe = f"""uretprobe:{binary_path}:{attach_spec}
/pid == {target_pid}/
{{
    printf("{{\\"type\\":\\"RETURN\\",\\"pid\\":%d,\\"tid\\":%d,\\"time\\":%llu,\\"sp\\":\\"0x%lx\\",\\"pc\\":\\"0x%lx\\",\\"ret\\":%ld}}\\n",
           pid, tid, nsecs, reg("sp"), reg("pc"), retval);
}}
"""
        return entry_probe + "\n" + return_probe

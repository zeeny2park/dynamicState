"""Phase 1 eBPF Stack-Variable & Function Tracing Proof of Concept.

Provides an isolated, optional eBPF-based userspace function tracing backend that:
1. Attaches uprobe (function entry) and uretprobe (function return) to target binary.
2. Filters strictly by target PID.
3. Records monotonic/real timestamps, PID/TID, probe type, function identity,
   architecture-supported argument and register values, and stack pointer / frame metadata.
4. Distinguishes observed values, unavailable values, unsupported features, and lost events.
5. Preserves existing CONSISTENT and LOW_IMPACT semantics: observations are explicitly
   labeled as PROBE_POINT_EVENT and never misrepresented as consistent process-wide snapshots.
6. Provides a clean interface (DwarfLocationResolverInterface) for future Phase 2 DWARF location evaluation.
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
    target_build_id: Optional[str]
    function_name: str
    architecture: str
    backend_name: str
    start_time: str
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
            "function_name": self.function_name,
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
    """Abstract contract for dynamic DWARF location evaluation (e.g., DW_AT_location, registers, stack frame)."""

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
            # Check if passwordless sudo is available
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

        backend = "none"
        if bpftrace_path:
            backend = "bpftrace"
        elif clang_path and os.path.exists("/usr/include/bpf/bpf.h"):
            backend = "libbpf"
        else:
            reasons.append("Neither 'bpftrace' nor 'clang + libbpf-dev' found in PATH/system.")

        supported = (len(reasons) == 0) and is_privileged and (backend != "none")

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
        if not line or line.startswith("Attaching ") or line.startswith("READY "):
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
        if pid is None or int(pid) != self.target_pid:
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
                elif k in ("fp", "bp", "rbp", "x29"):
                    fp = int_val
                elif k in ("pc", "ip", "rip"):
                    pc = int_val

        frame_meta = FrameMetadata(
            stack_pointer=sp,
            frame_pointer=fp,
            instruction_pointer=pc,
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

        # 1. Inspect target binary ELF & Build ID
        abs_binary = os.path.abspath(binary_path)
        if not os.path.exists(abs_binary):
            return TraceObservationSession(
                session_id=session_id,
                target_pid=pid,
                target_binary=abs_binary,
                target_build_id=None,
                function_name=function_name,
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

        # If external debug image specified, verify Build ID
        if debug_image:
            abs_dbg = os.path.abspath(debug_image)
            if os.path.exists(abs_dbg):
                dbg_info = inspect_elf(abs_dbg)
                if verify_build_id and target_build_id and dbg_info.build_id:
                    if target_build_id != dbg_info.build_id:
                        return TraceObservationSession(
                            session_id=session_id,
                            target_pid=pid,
                            target_binary=abs_binary,
                            target_build_id=target_build_id,
                            function_name=function_name,
                            architecture=arch,
                            backend_name="none",
                            start_time=t_start_iso,
                            end_time=datetime.now(timezone.utc).isoformat(),
                            status="FAILED",
                            error_message=f"Build ID mismatch: binary '{target_build_id}' != debug image '{dbg_info.build_id}'",
                        )

        # 2. Check environment prerequisites
        cap = EbpfEnvironmentChecker.check_prerequisites()
        if not cap.supported:
            return TraceObservationSession(
                session_id=session_id,
                target_pid=pid,
                target_binary=abs_binary,
                target_build_id=target_build_id,
                function_name=function_name,
                architecture=arch,
                backend_name=cap.backend,
                start_time=t_start_iso,
                end_time=datetime.now(timezone.utc).isoformat(),
                status="UNSUPPORTED_ENVIRONMENT",
                error_message="; ".join(cap.reasons),
            )

        # 3. Resolve function offset / symbol
        func_offset: Optional[int] = None
        try:
            indexer_path = debug_image if (debug_image and os.path.exists(debug_image)) else abs_binary
            d_index = DwarfIndexer.get_index(indexer_path)
            subps = d_index.subprograms_by_name.get(function_name, [])
            if subps:
                func_offset = subps[0].low_pc
        except Exception:
            pass

        # 4. Generate probe script (bpftrace-based bounded format)
        probe_script = self._generate_bpftrace_script(
            binary_path=abs_binary,
            function_name=function_name,
            target_pid=pid,
            arch=arch,
            entry_only=entry_only,
        )

        # 5. Launch probe process with guaranteed cleanup
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

        try:
            with tempfile.NamedTemporaryFile("w", suffix=".bt", delete=False) as f:
                f.write(probe_script)
                script_file = f.name

            cmd = []
            if self.use_sudo and os.geteuid() != 0:
                cmd.extend(["sudo", "-n"])
            cmd.extend(["bpftrace", "-B", "none", script_file])

            import select
            t_attach_start = time.monotonic()
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )

            # Wait for attach confirmation ("Attaching ...")
            timeout_attach = time.monotonic() + 5.0
            attached = False
            while time.monotonic() < timeout_attach:
                if proc.poll() is not None:
                    break
                rlist, _, _ = select.select([proc.stdout], [], [], 0.05)
                if rlist:
                    line = proc.stdout.readline()
                    if "Attaching " in line:
                        attached = True
                        attach_latency_ms = round((time.monotonic() - t_attach_start) * 1000, 2)
                        break

            if not attached and proc.poll() is not None:
                stderr_out = proc.stderr.read()
                return TraceObservationSession(
                    session_id=session_id,
                    target_pid=pid,
                    target_binary=abs_binary,
                    target_build_id=target_build_id,
                    function_name=function_name,
                    architecture=arch,
                    backend_name="bpftrace",
                    start_time=t_start_iso,
                    end_time=datetime.now(timezone.utc).isoformat(),
                    status="FAILED",
                    error_message=f"bpftrace process terminated prematurely: {stderr_out.strip()}",
                )

            # Collect events for the specified duration
            end_deadline = time.monotonic() + duration_s
            while time.monotonic() < end_deadline:
                if proc.poll() is not None:
                    break
                rlist, _, _ = select.select([proc.stdout], [], [], 0.05)
                if rlist:
                    line = proc.stdout.readline()
                    if line:
                        ev = decoder.decode_line(line)
                        if ev is not None:
                            events.append(ev)

        finally:
            # Reliable attach/detach cleanup
            if proc:
                try:
                    if proc.poll() is None:
                        # Send SIGINT to allow bpftrace to detach probes and drain ring buffer
                        if self.use_sudo and os.geteuid() != 0:
                            subprocess.run(["sudo", "-n", "kill", "-INT", str(proc.pid)], check=False)
                        else:
                            proc.send_signal(signal.SIGINT)
                        try:
                            proc.wait(timeout=2.0)
                        except subprocess.TimeoutExpired:
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
                except Exception:
                    pass

            if script_file and os.path.exists(script_file):
                try:
                    os.unlink(script_file)
                except Exception:
                    pass

        t_end = time.monotonic()
        total_duration_ms = round((t_end - t0) * 1000, 2)

        return TraceObservationSession(
            session_id=session_id,
            target_pid=pid,
            target_binary=abs_binary,
            target_build_id=target_build_id,
            function_name=function_name,
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
            status="SUCCESS",
        )

    def _generate_bpftrace_script(
        self,
        binary_path: str,
        function_name: str,
        target_pid: int,
        arch: str,
        entry_only: bool,
    ) -> str:
        """Generate a minimal bpftrace script with bounded JSON formatting and PID filter."""
        # Registers by architecture
        # bpftrace provides reg("sp") and reg("pc") on both arm64 and x86_64,
        # arg0..arg5 builtins, and retval for uretprobe
        entry_probe = f"""uprobe:{binary_path}:{function_name}
/pid == {target_pid}/
{{
    printf("{{\\"type\\":\\"ENTRY\\",\\"pid\\":%d,\\"tid\\":%d,\\"time\\":%llu,\\"sp\\":\\"0x%lx\\",\\"pc\\":\\"0x%lx\\",\\"arg0\\":%ld,\\"arg1\\":%ld,\\"arg2\\":%ld,\\"arg3\\":%ld}}\\n",
           pid, tid, nsecs, reg("sp"), reg("pc"), arg0, arg1, arg2, arg3);
}}
"""
        return_probe = ""
        if not entry_only:
            return_probe = f"""uretprobe:{binary_path}:{function_name}
/pid == {target_pid}/
{{
    printf("{{\\"type\\":\\"RETURN\\",\\"pid\\":%d,\\"tid\\":%d,\\"time\\":%llu,\\"sp\\":\\"0x%lx\\",\\"pc\\":\\"0x%lx\\",\\"ret\\":%ld}}\\n",
           pid, tid, nsecs, reg("sp"), reg("pc"), retval);
}}
"""
        return entry_probe + "\n" + return_probe

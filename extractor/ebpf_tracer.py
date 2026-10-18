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
STATUS_OPTIMIZED_OUT = "OPTIMIZED_OUT"
STATUS_UNSUPPORTED = "UNSUPPORTED"
STATUS_ERROR = "ERROR"
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
    return_address_status: str = STATUS_OBSERVED
    return_address_reason: Optional[str] = None
    link_time_address: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stack_pointer": f"0x{self.stack_pointer:x}" if self.stack_pointer is not None else None,
            "frame_pointer": f"0x{self.frame_pointer:x}" if self.frame_pointer is not None else None,
            "instruction_pointer": f"0x{self.instruction_pointer:x}" if self.instruction_pointer is not None else None,
            "return_address": f"0x{self.return_address:x}" if self.return_address is not None else None,
            "return_address_status": self.return_address_status,
            "return_address_reason": self.return_address_reason,
            "link_time_address": f"0x{self.link_time_address:x}" if self.link_time_address is not None else None,
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
    supports_uprobe_offset: bool = False
    uprobe_offset_status: str = "NOT_CHECKED"
    uprobe_offset_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ProbeCleanupResult:
    """Detailed report of process termination and group reaping."""
    success: bool
    child_reaped: bool
    group_terminated: bool
    status: str                         # "CLEAN", "ALREADY_EXITED", "GROUP_KILL_FAILED", "REAP_FAILED", "UNCERTAIN"
    details: str

    def __bool__(self) -> bool:
        return self.success

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, bool):
            return self.success == other
        if isinstance(other, ProbeCleanupResult):
            return (
                self.success == other.success
                and self.child_reaped == other.child_reaped
                and self.group_terminated == other.group_terminated
                and self.status == other.status
                and self.details == other.details
            )
        return False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class EbpfEnvironmentChecker:
    """Verifies kernel, architecture, compilers, privileges, and dependency requirements."""

    _UPROBE_OFFSET_CACHE: Dict[Tuple[str, int, int, int], Tuple[bool, str, str]] = {}

    @classmethod
    def invalidate_uprobe_offset_cache(cls) -> None:
        """Clear cached uprobe offset capability results."""
        cls._UPROBE_OFFSET_CACHE.clear()

    @classmethod
    def _find_second_instruction_offset(
        cls,
        bin_path: str,
        sym_name: str,
        arch: str,
    ) -> Tuple[Optional[int], Optional[str]]:
        """Find a verified nonzero instruction boundary offset within sym_name.

        Returns:
            Tuple[Optional[int], Optional[str]]: (offset, error_reason)
            If offset is None, capability detection must return UNKNOWN with error_reason.
        """
        if not AddressValidator.is_supported_architecture(arch):
            return None, f"Unsupported architecture '{arch}' for instruction offset detection"

        objdump = shutil.which("objdump")
        if not objdump:
            return None, "Disassembler 'objdump' not found in PATH to verify instruction boundaries"

        try:
            res = subprocess.run([objdump, "-d", bin_path], capture_output=True, text=True, timeout=2.0)
            if res.returncode != 0:
                err = res.stderr.strip() if res.stderr else f"exit code {res.returncode}"
                return None, f"objdump failed while disassembling binary: {err}"
        except Exception as e:
            return None, f"Failed to execute objdump: {e}"

        return cls._parse_disassembly_for_second_instruction(res.stdout, sym_name, arch)

    @classmethod
    def _parse_disassembly_for_second_instruction(
        cls,
        disasm_text: str,
        sym_name: str,
        arch: str,
    ) -> Tuple[Optional[int], Optional[str]]:
        """Parse objdump disassembly text to find the second instruction offset in sym_name."""
        if not AddressValidator.is_supported_architecture(arch):
            return None, f"Unsupported architecture '{arch}'"

        lines = disasm_text.splitlines()
        in_sym = False
        inst_addrs: List[int] = []
        sym_re = re.compile(rf"<({re.escape(sym_name)})>:")
        other_sym_re = re.compile(r"^\s*[0-9a-fA-F]+\s+<.*>:")
        inst_re = re.compile(r"^\s*([0-9a-fA-F]+):")

        for line in lines:
            line_str = line.strip()
            if not line_str:
                continue
            if sym_re.search(line):
                in_sym = True
                continue
            elif in_sym and (other_sym_re.search(line) or line.startswith("Disassembly of section")):
                break
            elif in_sym:
                m = inst_re.match(line)
                if m:
                    inst_addrs.append(int(m.group(1), 16))

        if not in_sym:
            return None, f"Symbol '{sym_name}' not found in disassembly"
        if len(inst_addrs) < 2:
            return None, f"Symbol '{sym_name}' contains fewer than 2 instructions in disassembly"

        # Check strictly monotonic increasing addresses
        for i in range(len(inst_addrs) - 1):
            if inst_addrs[i + 1] <= inst_addrs[i]:
                return None, f"Non-increasing or duplicate instruction address at index {i + 1}: 0x{inst_addrs[i+1]:x} <= 0x{inst_addrs[i]:x}"

        base_addr = inst_addrs[0]
        second_addr = inst_addrs[1]
        max_addr = inst_addrs[-1]
        offset = second_addr - base_addr

        if offset <= 0:
            return None, f"Non-positive instruction offset computed: {offset}"
        if second_addr >= max_addr:
            return None, f"Second instruction at offset 0x{offset:x} is at or beyond function end (max 0x{max_addr:x})"

        norm_arch = arch.lower()
        if norm_arch in ("aarch64", "arm64"):
            for addr in inst_addrs:
                if addr % 4 != 0:
                    return None, f"AArch64 instruction address 0x{addr:x} is not 4-byte aligned"
            if offset % 4 != 0:
                return None, f"AArch64 instruction offset 0x{offset:x} is not 4-byte aligned"
        elif norm_arch in ("x86_64", "amd64"):
            if offset > 15:
                return None, f"x86-64 instruction offset {offset} exceeds maximum x86 instruction length (15 bytes)"

        return offset, None

    @classmethod
    def _verify_process_group_state(
        cls,
        pid: int,
        cmd_prefix: List[str],
    ) -> Tuple[Optional[bool], Optional[str]]:
        """Verify whether any processes still linger in process group pid using signal 0.

        Returns:
            Tuple[Optional[bool], Optional[str]]:
            - (True, None): verified that process group is absent (ESRCH / no such process).
            - (False, None): verified that living processes remain in process group pid (signal 0 delivered).
            - (None, error_reason): inconclusive (permission error, command failure, unexpected error, timeout).
        """
        if cmd_prefix:
            try:
                chk = subprocess.run(
                    cmd_prefix + ["kill", "-0", "--", f"-{pid}"],
                    capture_output=True,
                    text=True,
                    timeout=1.0,
                )
                if chk.returncode == 0:
                    return False, None
                err = (chk.stderr.strip() or chk.stdout.strip()).lower()
                # Positively verify ESRCH / No such process
                if "no such process" in err or "esrch" in err:
                    return True, None
                elif "operation not permitted" in err or "permission denied" in err:
                    return None, f"Permission denied inspecting process group {pid}: {chk.stderr.strip()}"
                else:
                    return None, f"Ambiguous diagnostic inspecting process group {pid} (exit {chk.returncode}): {chk.stderr.strip() or chk.stdout.strip()}"
            except subprocess.TimeoutExpired:
                return None, f"Timeout verifying process group {pid}"
            except Exception as e:
                return None, f"Exception verifying process group {pid}: {e}"
        else:
            try:
                os.killpg(pid, 0)
                return False, None
            except ProcessLookupError:
                return True, None
            except PermissionError as e:
                return None, f"Permission denied inspecting process group {pid}: {e}"
            except Exception as e:
                return None, f"Exception verifying process group {pid}: {e}"

    @classmethod
    def _terminate_probe_process(
        cls,
        proc: Optional[subprocess.Popen],
        cmd_prefix: List[str],
        is_session_leader: Optional[bool] = None,
    ) -> ProbeCleanupResult:
        """Safely terminate and reap a probe process and its entire process group.

        Distinguishes the direct Popen child, privilege wrapper (sudo -n), and
        descendant process group. Verifies exit code and stderr of cleanup commands,
        reaps the direct child, and verifies with signal 0 whether descendant processes
        remain in the process group.

        Returns:
            ProbeCleanupResult: Structured result reporting child_reaped, group_terminated,
            and status ("CLEAN", "ALREADY_EXITED", "GROUP_KILL_FAILED", "REAP_FAILED", "UNCERTAIN").
            Evaluates as a boolean for backward compatibility (True on success).
        """
        if proc is None:
            return ProbeCleanupResult(
                success=True,
                child_reaped=True,
                group_terminated=True,
                status="CLEAN",
                details="No process to terminate",
            )

        pid = getattr(proc, "pid", None)
        child_already_exited = (proc.poll() is not None)

        # Handle non-int or invalid PIDs (e.g. mocks without explicit pid or pid <= 1)
        if not isinstance(pid, int) or pid <= 1:
            if child_already_exited:
                return ProbeCleanupResult(
                    success=True,
                    child_reaped=True,
                    group_terminated=True,
                    status="ALREADY_EXITED",
                    details=f"Direct child already exited (mock/untracked pid {pid})",
                )
            try:
                proc.kill()
            except Exception:
                pass
            child_reaped = False
            try:
                proc.communicate(timeout=1.0)
                child_reaped = (proc.poll() is not None)
            except Exception:
                child_reaped = (proc.poll() is not None)
            if not child_reaped:
                return ProbeCleanupResult(
                    success=False,
                    child_reaped=False,
                    group_terminated=False,
                    status="REAP_FAILED",
                    details=f"Direct child could not be reaped (mock/untracked pid {pid})",
                )
            return ProbeCleanupResult(
                success=True,
                child_reaped=True,
                group_terminated=True,
                status="CLEAN",
                details=f"Direct child reaped (mock/untracked pid {pid})",
            )

        # Check process group/session semantics if not explicitly specified
        if is_session_leader is None and not child_already_exited:
            try:
                child_pgid = os.getpgid(pid)
                if child_pgid != pid and child_pgid == os.getpgrp():
                    is_session_leader = False
                elif child_pgid == pid:
                    is_session_leader = True
            except Exception:
                pass

        # If process is confirmed NOT to be a session leader, avoid collateral process group signaling
        if is_session_leader is False:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            except Exception:
                pass
            child_reaped = False
            try:
                proc.communicate(timeout=1.0)
                child_reaped = (proc.poll() is not None)
            except Exception:
                child_reaped = (proc.poll() is not None)
            if not child_reaped:
                return ProbeCleanupResult(
                    success=False,
                    child_reaped=False,
                    group_terminated=False,
                    status="REAP_FAILED",
                    details=f"Direct child (pid {pid}) could not be reaped within timeout",
                )
            return ProbeCleanupResult(
                success=True,
                child_reaped=True,
                group_terminated=True,
                status="CLEAN",
                details=f"Direct child reaped (not a session leader, skipped collateral group signaling)",
            )

        # Handle already-exited child process: verify process group is also dead
        if child_already_exited:
            group_terminated, group_verify_err = cls._verify_process_group_state(pid, cmd_prefix)

            # If descendants are still running in the group, terminate them
            if group_terminated is False:
                kill_err = None
                if cmd_prefix:
                    try:
                        chk_kill = subprocess.run(
                            cmd_prefix + ["kill", "-KILL", "--", f"-{pid}"],
                            capture_output=True,
                            text=True,
                            timeout=1.0,
                        )
                        if chk_kill.returncode != 0:
                            err_k = (chk_kill.stderr.strip() or chk_kill.stdout.strip()).lower()
                            if not ("no such process" in err_k or "esrch" in err_k):
                                kill_err = chk_kill.stderr.strip() or f"exit code {chk_kill.returncode}"
                    except Exception as e:
                        kill_err = str(e)
                else:
                    try:
                        os.killpg(pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    except Exception as e:
                        kill_err = str(e)

                # Re-verify after kill
                group_terminated, group_verify_err = cls._verify_process_group_state(pid, cmd_prefix)
                if kill_err:
                    return ProbeCleanupResult(
                        success=False,
                        child_reaped=True,
                        group_terminated=bool(group_terminated),
                        status="GROUP_KILL_FAILED",
                        details=f"Process group SIGKILL failed: {kill_err}",
                    )

            if group_terminated is False:
                return ProbeCleanupResult(
                    success=False,
                    child_reaped=True,
                    group_terminated=False,
                    status="GROUP_KILL_FAILED",
                    details=f"Process group {pid} still contains active processes after termination",
                )
            if group_terminated is None:
                return ProbeCleanupResult(
                    success=False,
                    child_reaped=True,
                    group_terminated=False,
                    status="UNCERTAIN",
                    details=f"Child already exited, but process group state could not be verified: {group_verify_err}",
                )
            return ProbeCleanupResult(
                success=True,
                child_reaped=True,
                group_terminated=True,
                status="ALREADY_EXITED",
                details=f"Direct child already exited and process group {pid} verified absent (ALREADY_EXITED)",
            )

        # Child is still running: terminate process group and direct child
        group_kill_err: Optional[str] = None
        if cmd_prefix:
            try:
                res = subprocess.run(
                    cmd_prefix + ["kill", "-KILL", "--", f"-{pid}"],
                    capture_output=True,
                    text=True,
                    timeout=1.0,
                )
                if res.returncode != 0:
                    err_out = (res.stderr.strip() or res.stdout.strip())
                    if not ("no such process" in err_out.lower() or "esrch" in err_out.lower()):
                        group_kill_err = err_out or f"exit code {res.returncode}"
            except Exception as e:
                group_kill_err = str(e)
        else:
            try:
                os.killpg(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            except Exception as e:
                group_kill_err = str(e)

        try:
            proc.kill()
        except ProcessLookupError:
            pass
        except Exception:
            pass

        # Drain pipes and reap direct child
        child_reaped = False
        try:
            proc.communicate(timeout=1.0)
            child_reaped = (proc.poll() is not None)
        except subprocess.TimeoutExpired:
            try:
                proc.wait(timeout=0.5)
                child_reaped = (proc.poll() is not None)
            except Exception:
                child_reaped = (proc.poll() is not None)
        except Exception:
            child_reaped = (proc.poll() is not None)

        if not child_reaped:
            return ProbeCleanupResult(
                success=False,
                child_reaped=False,
                group_terminated=False,
                status="REAP_FAILED",
                details=f"Direct Popen child (pid {pid}) could not be reaped within timeout",
            )

        # Verify whether any descendant processes still linger in the process group using signal 0
        group_terminated, group_verify_err = cls._verify_process_group_state(pid, cmd_prefix)

        if group_kill_err:
            return ProbeCleanupResult(
                success=False,
                child_reaped=True,
                group_terminated=bool(group_terminated),
                status="GROUP_KILL_FAILED",
                details=f"Process group SIGKILL command failed: {group_kill_err}",
            )

        if group_terminated is False:
            return ProbeCleanupResult(
                success=False,
                child_reaped=True,
                group_terminated=False,
                status="GROUP_KILL_FAILED",
                details=f"Process group {pid} still contains active processes after termination",
            )

        if group_terminated is None:
            return ProbeCleanupResult(
                success=False,
                child_reaped=True,
                group_terminated=False,
                status="UNCERTAIN",
                details=f"Child reaped, but process group state could not be verified: {group_verify_err}",
            )

        return ProbeCleanupResult(
            success=True,
            child_reaped=True,
            group_terminated=True,
            status="CLEAN",
            details=f"Direct child reaped and process group {pid} verified terminated (CLEAN)",
        )

    @classmethod
    def check_uprobe_offset_support(
        cls,
        bpftrace_path: Optional[str] = None,
        is_privileged: bool = False,
        force_refresh: bool = False,
    ) -> Tuple[bool, str, str]:
        """Detect at runtime whether the installed bpftrace binary supports nonzero uprobe offsets.

        Actively compiles a deterministic test executable containing a dedicated probe target,
        runs bpftrace with a probe at a nonzero instruction offset, and verifies that the probe
        event is actually triggered and observed upon process execution.

        Returns:
            Tuple[bool, str, str]: (is_supported, status, reason)
            status is one of: "SUPPORTED", "UNSUPPORTED", "UNKNOWN", "NOT_CHECKED"
        """
        path = bpftrace_path if bpftrace_path is not None else shutil.which("bpftrace")
        if not path:
            return False, "NOT_CHECKED", "bpftrace executable not found in PATH"
        if not is_privileged:
            return False, "NOT_CHECKED", "Privileges (root or passwordless sudo) required to check probe capabilities"

        euid = os.geteuid() if hasattr(os, "geteuid") else -1
        cache_key = None
        try:
            st = os.stat(path)
            cache_key = (path, st.st_mtime_ns, st.st_size, euid)
            if not force_refresh and cache_key in cls._UPROBE_OFFSET_CACHE:
                return cls._UPROBE_OFFSET_CACHE[cache_key]
        except Exception:
            pass

        gcc_path = shutil.which("gcc")
        if not gcc_path:
            return False, "UNKNOWN", "Compiler 'gcc' not found in PATH to build probe test binary"

        cmd_prefix = [] if (hasattr(os, "geteuid") and os.geteuid() == 0) else ["sudo", "-n"]
        test_src = None
        test_bin = None
        arch = platform.machine().lower()
        proc = None

        try:
            with tempfile.NamedTemporaryFile("w", suffix=".c", delete=False) as tf:
                tf.write(
                    "#include <stdio.h>\n"
                    "__attribute__((noinline)) int probe_target(void) {\n"
                    "    __asm__ volatile(\"nop; nop; nop; nop;\");\n"
                    "    return 42;\n"
                    "}\n"
                    "int main(void) {\n"
                    "    return probe_target();\n"
                    "}\n"
                )
                test_src = tf.name
            test_bin = test_src + ".bin"

            comp = subprocess.run(
                [gcc_path, "-O0", "-g", "-fno-inline", "-fno-omit-frame-pointer", test_src, "-o", test_bin],
                capture_output=True,
                timeout=5.0,
            )
            if comp.returncode != 0:
                err_text = comp.stderr.decode("utf-8", errors="ignore") if isinstance(comp.stderr, bytes) else str(comp.stderr)
                return False, "UNKNOWN", f"Failed to build probe test binary: {err_text.strip()}"

            offset, err_reason = cls._find_second_instruction_offset(test_bin, "probe_target", arch)
            if offset is None:
                return False, "UNKNOWN", f"Instruction offset determination failed: {err_reason}"

            probe_script = f"uprobe:{test_bin}:probe_target+{offset} {{ printf(\"PROBE_OFFSET_HIT\\n\"); exit(); }}"
            probe_cmd = cmd_prefix + [path, "-e", probe_script, "-c", test_bin]
            try:
                proc = subprocess.Popen(
                    probe_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    start_new_session=True,
                )
                stdout, stderr = proc.communicate(timeout=3.0)
                err = (stderr.strip() or stdout.strip())

                if proc.returncode == 0 and "PROBE_OFFSET_HIT" in stdout:
                    res = (True, "SUPPORTED", f"uprobe offset support verified via active execution (offset +{offset})")
                elif "compiled without (k|u)probe offset support" in err or "offset is not supported" in err.lower():
                    res = (False, "UNSUPPORTED", f"bpftrace compiled without (k|u)probe offset support: {err}")
                elif "permission denied" in err.lower() or "operation not permitted" in err.lower():
                    res = (False, "UNKNOWN", f"bpftrace probe offset attachment failed with permission error: {err}")
                elif proc.returncode != 0:
                    res = (False, "UNKNOWN", f"bpftrace probe offset attachment failed (exit code {proc.returncode}): {err}")
                else:
                    res = (False, "UNKNOWN", f"bpftrace exited without observing PROBE_OFFSET_HIT event: {stdout.strip()}")

                # Only cache definitive supported or unsupported results; do not cache inconclusive UNKNOWN outcomes
                if cache_key and res[1] in ("SUPPORTED", "UNSUPPORTED"):
                    cls._UPROBE_OFFSET_CACHE[cache_key] = res
                return res

            except subprocess.TimeoutExpired:
                reaped = cls._terminate_probe_process(proc, cmd_prefix, is_session_leader=True)
                return (
                    False,
                    "UNKNOWN",
                    f"Probe execution check timed out after 3.0s without confirming event trigger (process reaped: {reaped})",
                )

        except Exception as e:
            return False, "UNKNOWN", f"Error detecting uprobe offset support: {e}"
        finally:
            cls._terminate_probe_process(proc, cmd_prefix, is_session_leader=True)
            if test_src and os.path.exists(test_src):
                try:
                    os.remove(test_src)
                except Exception:
                    try:
                        if cmd_prefix:
                            subprocess.run(cmd_prefix + ["rm", "-f", test_src], capture_output=True, timeout=1.0)
                    except Exception:
                        pass
            if test_bin and os.path.exists(test_bin):
                try:
                    os.remove(test_bin)
                except Exception:
                    try:
                        if cmd_prefix:
                            subprocess.run(cmd_prefix + ["rm", "-f", test_bin], capture_output=True, timeout=1.0)
                    except Exception:
                        pass

    @classmethod
    def check_prerequisites(
        cls,
        active_probe: bool = False,
        force_refresh: bool = False,
    ) -> EbpfCapabilityResult:
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

        offset_supported = False
        offset_status = "NOT_CHECKED"
        offset_reason = None

        if supported and backend == "bpftrace":
            cache_key = None
            if bpftrace_path:
                try:
                    st = os.stat(bpftrace_path)
                    cache_key = (bpftrace_path, st.st_mtime_ns, st.st_size, euid)
                except Exception:
                    pass

            if active_probe:
                offset_supported, offset_status, offset_reason = cls.check_uprobe_offset_support(
                    bpftrace_path=bpftrace_path,
                    is_privileged=is_privileged,
                    force_refresh=force_refresh,
                )
            elif not force_refresh and cache_key and cache_key in cls._UPROBE_OFFSET_CACHE:
                offset_supported, offset_status, offset_reason = cls._UPROBE_OFFSET_CACHE[cache_key]
            else:
                offset_status = "NOT_CHECKED"
                offset_supported = False
                offset_reason = "Active uprobe offset probe has not been run (call capabilities(active_probe=True) to test)"
        elif not is_privileged:
            offset_reason = "Privileges (root or passwordless sudo) required to check probe capabilities"
            offset_status = "NOT_CHECKED"
        else:
            offset_reason = "bpftrace backend not available or environment not supported"
            offset_status = "NOT_CHECKED"

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
            supports_uprobe_offset=offset_supported,
            uprobe_offset_status=offset_status,
            uprobe_offset_reason=offset_reason,
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
# Address and Instruction Pointer Validation
# -----------------------------------------------------------------------------

class AddressValidator:
    """Architecture-correct userspace address validator distinguishing code and data addresses.

    Linux Userspace Address Rules:
    - x86_64:
      - 4-level paging canonical userspace: [0x1000, 0x00007fffffffffff] (48-bit canonical ceiling, default)
      - 5-level paging canonical userspace: [0x1000, 0x00ffffffffffffff] (57-bit canonical ceiling, if explicitly configured)
      - Addresses in kernel space (bit 63 set, or non-canonical high addresses) are strictly invalid.
      - Instruction pointer (PC) has 1-byte granularity (variable instruction length).
    - AArch64 (ARM64):
      - 48-bit userspace VA: [0x1000, 0x0000ffffffffffff] (standard Linux AArch64 default)
      - 52-bit userspace VA: [0x1000, 0x000fffffffffffff] (LVA extension, if explicitly configured)
      - Instruction pointer (PC) MUST be 4-byte aligned (pc % 4 == 0) and CANNOT use TBI tags ((pc >> 56) == 0).
        Hardware instruction fetch forbids TBI tags; tag bits cause a translation fault.
      - Data pointers MAY use Top Byte Ignore (TBI) in userspace: bits [63:56] contain tag bits.
        TBI is an architectural hardware capability of AArch64 (configured via TCR_EL1.TBI0 in the kernel),
        not an assumption that every userspace process universally enables or generates tagged pointers.
        When present, tagged data addresses are normalized (untagged) before range validation and process memory access.
    - Low memory: addresses < 0x1000 (page 0 / NULL page) are strictly rejected for runtime execution/data.
    - Architecture fail-closed policy: unsupported architectures (e.g., riscv, mips, x86_32) are strictly rejected (return False / None).
    """

    PAGE_SIZE_MIN = 0x1000
    X86_64_4LEVEL_MAX = 0x00007FFFFFFFFFFF     # 4-level paging userspace ceiling (48-bit canonical, default)
    X86_64_USER_MAX = 0x00FFFFFFFFFFFFFF       # 5-level paging userspace ceiling (57-bit)
    AARCH64_48BIT_MAX = 0x0000FFFFFFFFFFFF     # 48-bit userspace ceiling (standard Linux AArch64 default)
    AARCH64_52BIT_MAX = 0x000FFFFFFFFFFFFF     # 52-bit userspace ceiling (LVA extension)
    AARCH64_USER_MAX = AARCH64_52BIT_MAX       # Backward-compat alias

    SUPPORTED_ARCHITECTURES = frozenset({"x86_64", "amd64", "aarch64", "arm64"})

    @classmethod
    def is_supported_architecture(cls, arch: Optional[str]) -> bool:
        """Return True if the architecture is supported by userspace validation rules."""
        if not arch or not isinstance(arch, str):
            return False
        return arch.lower() in cls.SUPPORTED_ARCHITECTURES

    @classmethod
    def normalize_data_address(cls, addr: Optional[int], arch: str = "x86_64") -> Optional[int]:
        """Normalize data address by stripping AArch64 TBI tag bits [63:56].

        Fails closed (returns None) for unsupported architectures, negative values, or invalid types.
        Leaves x86_64 addresses unchanged.
        """
        if addr is None or not isinstance(addr, int):
            return None
        if not cls.is_supported_architecture(arch):
            return None
        if addr < 0:
            return None
        norm = arch.lower()
        if norm in ("aarch64", "arm64"):
            return addr & 0x00FFFFFFFFFFFFFF
        return addr

    @classmethod
    def untag_data_address(cls, addr: int, arch: str = "x86_64") -> int:
        """Strip AArch64 Top Byte Ignore (TBI) tag bits [63:56] from data pointer."""
        res = cls.normalize_data_address(addr, arch)
        return res if res is not None else 0

    @classmethod
    def is_valid_instruction_pointer(
        cls,
        pc: Optional[int],
        arch: str = "x86_64",
        is_link_time: bool = False,
        five_level_paging: bool = False,
        fifty_two_bit_va: bool = False,
    ) -> bool:
        """Validate userspace instruction pointer according to architecture rules."""
        if pc is None or not isinstance(pc, int):
            return False
        if not cls.is_supported_architecture(arch):
            return False

        min_bound = 0 if is_link_time else cls.PAGE_SIZE_MIN
        if pc < min_bound:
            return False

        norm = arch.lower()
        if norm in ("aarch64", "arm64"):
            # 1. Reject if TBI tag is present (hardware instruction fetch does not support TBI)
            if (pc >> 56) != 0:
                return False
            # 2. Must be 4-byte aligned
            if (pc % 4) != 0:
                return False
            # 3. Must be within AArch64 userspace ceiling (default 48-bit VA, 52-bit if explicitly enabled)
            limit = cls.AARCH64_52BIT_MAX if fifty_two_bit_va else cls.AARCH64_48BIT_MAX
            return pc <= limit
        else:
            # x86_64: 4-level paging userspace limit is 0x00007fffffffffff; 5-level paging is 0x00ffffffffffffff
            limit = cls.X86_64_USER_MAX if five_level_paging else cls.X86_64_4LEVEL_MAX
            return pc <= limit

    @classmethod
    def is_valid_memory_address(
        cls,
        addr: Optional[int],
        size: int = 1,
        arch: str = "x86_64",
        five_level_paging: bool = False,
        fifty_two_bit_va: bool = False,
    ) -> bool:
        """Validate userspace data memory address according to architecture rules."""
        if addr is None or not isinstance(addr, int) or not isinstance(size, int):
            return False
        if not cls.is_supported_architecture(arch):
            return False
        if size <= 0 or size > 65536:
            return False

        norm_addr = cls.normalize_data_address(addr, arch)
        if norm_addr is None or norm_addr < cls.PAGE_SIZE_MIN:
            return False

        # Check for 64-bit integer overflow: norm_addr + size - 1 < norm_addr
        end_addr = norm_addr + size - 1
        if end_addr < norm_addr:
            return False

        norm = arch.lower()
        if norm in ("aarch64", "arm64"):
            max_limit = cls.AARCH64_52BIT_MAX if fifty_two_bit_va else cls.AARCH64_48BIT_MAX
        else:
            max_limit = cls.X86_64_USER_MAX if five_level_paging else cls.X86_64_4LEVEL_MAX

        return end_addr <= max_limit

    @classmethod
    def compute_link_time_pc(
        cls,
        runtime_pc: Optional[int],
        load_bias: int,
        arch: str = "x86_64",
        five_level_paging: bool = False,
        fifty_two_bit_va: bool = False,
    ) -> Optional[int]:
        """Compute link-time PC from runtime PC and load bias with underflow detection."""
        if not cls.is_supported_architecture(arch):
            return None
        if not cls.is_valid_instruction_pointer(
            runtime_pc, arch, five_level_paging=five_level_paging, fifty_two_bit_va=fifty_two_bit_va
        ):
            return None
        if not isinstance(load_bias, int) or load_bias < 0:
            return None

        # Underflow check: runtime_pc < load_bias
        if runtime_pc < load_bias:
            return None

        link_pc = runtime_pc - load_bias
        if not cls.is_valid_instruction_pointer(
            link_pc, arch, is_link_time=True, five_level_paging=five_level_paging, fifty_two_bit_va=fifty_two_bit_va
        ):
            return None

        return link_pc


# -----------------------------------------------------------------------------
# Event Decoder
# -----------------------------------------------------------------------------

class EbpfEventDecoder:
    """Robust decoder for streaming eBPF probe records.

    Handles JSON-encoded or delimited event records, filters by target PID,
    and isolates corrupted or truncated lines without raising exceptions.
    """

    def __init__(
        self,
        target_pid: int,
        architecture: str,
        function_name: str,
        function_offset: Optional[int] = None,
        load_bias: int = 0,
        subprogram: Optional[Any] = None,
        resolver: Optional[DwarfLocationResolverInterface] = None,
    ):
        self.target_pid = target_pid
        self.architecture = architecture
        self.function_name = function_name
        self.function_offset = function_offset
        self.load_bias = load_bias
        self.subprogram = subprogram
        self.sequence_counter = 0
        self.malformed_count = 0
        self.lost_count = 0
        self.resolver: DwarfLocationResolverInterface = resolver or Phase1DwarfLocationResolver()

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
            if v is None:
                # Explicitly unavailable / null register
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
                if k in ("pc", "ip", "rip"):
                    if AddressValidator.is_valid_instruction_pointer(int_val, self.architecture):
                        registers[k] = int_val
                        pc = int_val
                    else:
                        pc = None
                else:
                    registers[k] = int_val
                    if k in ("sp", "rsp"):
                        sp = int_val
                    elif k in ("fp", "bp", "rbp", "x29", "r29"):
                        fp = int_val
                    elif k in ("ra", "lr", "r30"):
                        ra = int_val

        # On x86_64, there is no link register; return address is passed on the stack ((%rsp)).
        # Never report a hardcoded 0x0 or fabricate a return address.
        arch_norm = self.architecture.lower()
        ra_status = STATUS_OBSERVED
        ra_reason = None
        if arch_norm in ("x86_64", "amd64"):
            if ra is None or ra == 0:
                ra = None
                ra_status = STATUS_UNAVAILABLE
                ra_reason = "Return address register is not available on x86_64 (passed on stack via (%rsp))."
        else:
            if ra is None:
                ra_status = STATUS_UNAVAILABLE
                ra_reason = "Return address register not captured in probe payload"

        # Populate canonical architecture registers from parsed values and arguments
        if arch_norm in ("aarch64", "arm64"):
            for i in range(8):
                if f"arg{i}" in registers and f"x{i}" not in registers:
                    registers[f"x{i}"] = registers[f"arg{i}"]
            if fp is not None:
                registers.setdefault("x29", fp)
                registers.setdefault("r29", fp)
                registers.setdefault("fp", fp)
            if ra is not None:
                registers.setdefault("x30", ra)
                registers.setdefault("r30", ra)
                registers.setdefault("lr", ra)
                registers.setdefault("ra", ra)
            if sp is not None:
                registers.setdefault("sp", sp)
            if pc is not None:
                registers.setdefault("pc", pc)
        elif arch_norm in ("x86_64", "amd64"):
            x86_arg_regs = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]
            for i, r_name in enumerate(x86_arg_regs):
                if f"arg{i}" in registers and r_name not in registers:
                    registers[r_name] = registers[f"arg{i}"]
            if fp is not None:
                registers.setdefault("rbp", fp)
                registers.setdefault("bp", fp)
                registers.setdefault("fp", fp)
            if sp is not None:
                registers.setdefault("rsp", sp)
                registers.setdefault("sp", sp)
            if pc is not None:
                registers.setdefault("rip", pc)
                registers.setdefault("pc", pc)

        link_pc: Optional[int] = (
            AddressValidator.compute_link_time_pc(pc, self.load_bias, self.architecture)
            if pc is not None
            else None
        )

        frame_meta = FrameMetadata(
            stack_pointer=sp,
            frame_pointer=fp,
            instruction_pointer=pc,
            return_address=ra,
            return_address_status=ra_status,
            return_address_reason=ra_reason,
            link_time_address=link_pc,
        )

        arguments: Dict[str, TraceValue] = {}
        return_value: Optional[TraceValue] = None

        if probe_type == "ENTRY":
            # Map registers to standard calling convention arguments
            # x86_64: arg0=rdi, arg1=rsi, arg2=rdx, arg3=rcx, arg4=r8, arg5=r9
            # aarch64: arg0=x0, arg1=x1, arg2=x2, arg3=x3, arg4=x4, arg5=x5, arg6=x6, arg7=x7
            max_args = 8 if arch_norm in ("aarch64", "arm64") else 6
            for i in range(max_args):
                arg_key = f"arg{i}"
                if arg_key in registers:
                    val = registers[arg_key]
                    val_hex = f"0x{(val & 0xFFFFFFFFFFFFFFFF):x}"
                    arguments[f"param_{i}"] = TraceValue(
                        name=f"param_{i}",
                        status=STATUS_OBSERVED,
                        value=val,
                        value_hex=val_hex,
                        location=f"register:{arg_key}",
                    )
                elif arg_key in payload and payload[arg_key] is None:
                    arguments[f"param_{i}"] = TraceValue(
                        name=f"param_{i}",
                        status=STATUS_UNAVAILABLE,
                        location=f"register:{arg_key}",
                        reason="Argument register is null in probe payload",
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
                    ret_hex = f"0x{(int_ret & 0xFFFFFFFFFFFFFFFF):x}"
                    return_value = TraceValue(
                        name="return_value",
                        status=STATUS_OBSERVED,
                        value=int_ret,
                        value_hex=ret_hex,
                        location="register:retval",
                    )
                else:
                    return_value = TraceValue(
                        name="return_value",
                        status=STATUS_UNAVAILABLE,
                        reason="Failed to parse return value",
                    )

        # Local variables: resolve via DWARF resolver if available
        local_vars: Dict[str, TraceValue] = {
            "local_variables": TraceValue(
                name="local_variables",
                status=STATUS_UNSUPPORTED_PHASE1,
                reason="Arbitrary userspace local variable evaluation is deferred to Phase 2.",
            )
        }
        if self.subprogram and getattr(self.subprogram, "variables", None):
            if hasattr(self.resolver, "link_time_address"):
                self.resolver.link_time_address = link_pc
            if probe_type == "RETURN":
                for v in self.subprogram.variables:
                    local_vars[v.name] = TraceValue(
                        name=v.name,
                        status=STATUS_UNAVAILABLE,
                        reason="Function execution completed (return probe); stack frame and register context are destroyed.",
                    )
            else:
                for v in self.subprogram.variables:
                    local_vars[v.name] = self.resolver.resolve_variable(self.subprogram, v.name, registers, frame_meta)

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

        # 8. Determine load bias and configure DWARF location resolver
        load_bias = 0
        target_subp = None
        resolver: DwarfLocationResolverInterface = Phase1DwarfLocationResolver()
        try:
            search_path = debug_image if (debug_image and os.path.exists(debug_image)) else abs_binary
            d_index = DwarfIndexer.get_index(search_path)
            subps = list(d_index.subprograms_by_name.get(function_name, []))
            if not subps:
                for sp in d_index.subprograms:
                    if sp.name == function_name or sp.linkage_name == function_name:
                        subps.append(sp)
            if subps:
                # 1. Match subprograms to file offset via PT_LOAD
                matching_subps = []
                for sp in subps:
                    if sp.low_pc is not None:
                        sp_fo = self._virt_to_file_offset(elf_info, abs_binary, sp.low_pc)
                        if sp_fo == func_offset:
                            matching_subps.append(sp)
                candidates = matching_subps if matching_subps else [sp for sp in subps if sp.low_pc is not None]
                if not candidates:
                    candidates = subps

                # 2. Check for multiple distinct definitions with different entry points
                distinct_definitions = [
                    sp for sp in candidates
                    if getattr(sp, "variables", None) and not getattr(sp, "is_declaration", False)
                ]
                if len(distinct_definitions) > 1:
                    distinct_pcs = {sp.low_pc for sp in distinct_definitions if sp.low_pc is not None}
                    if len(distinct_pcs) > 1:
                        addrs_str = ", ".join(f"0x{a:x}" for a in sorted(distinct_pcs))
                        return TraceObservationSession(
                            session_id=session_id,
                            target_pid=pid,
                            target_binary=abs_binary,
                            target_build_id=target_build_id,
                            build_id_status=build_id_status,
                            function_name=function_name,
                            probe_offset=probe_offset_str,
                            architecture=arch,
                            backend_name=cap.backend,
                            start_time=t_start_iso,
                            end_time=datetime.now(timezone.utc).isoformat(),
                            status="FAILED",
                            error_message=(
                                f"Ambiguous DWARF subprograms for '{function_name}': matches multiple candidate "
                                f"definitions at distinct locations ({addrs_str}). Disambiguate using linkage name or exact offset."
                            ),
                        )
                # Prefer definition with variables over empty declaration DIE
                target_subp = distinct_definitions[0] if distinct_definitions else candidates[0]

            # Calculate load bias for PIE binaries
            if elf_info.elf_type == "ET_DYN":
                try:
                    with open(f"/proc/{pid}/maps", "r") as mf:
                        for mline in mf:
                            parts = mline.strip().split()
                            if len(parts) >= 6 and (os.path.basename(abs_binary) in parts[5] or parts[5] == abs_binary):
                                if parts[2] == "00000000" or "x" in parts[1]:
                                    addr_range = parts[0]
                                    start_vaddr = int(addr_range.split("-")[0], 16)
                                    map_offset = int(parts[2], 16)
                                    seg_vaddr = 0
                                    for seg in elf_info.pt_loads:
                                        if seg.get("p_offset") == map_offset:
                                            seg_vaddr = seg.get("p_vaddr", 0)
                                            break
                                    load_bias = start_vaddr - seg_vaddr
                                    break
                except Exception:
                    pass

            def proc_mem_reader(addr: int, size: int) -> Optional[bytes]:
                norm_addr = AddressValidator.normalize_data_address(addr, arch)
                if norm_addr is None or not AddressValidator.is_valid_memory_address(norm_addr, size, arch):
                    return None
                try:
                    from .watch_session import read_process_memory_slice
                    data, status, _ = read_process_memory_slice(pid, norm_addr, size)
                    if status == "OBSERVED" and data is not None and len(data) == size:
                        return data
                    return None
                except Exception:
                    return None

            from .dwarf_evaluator import Phase2DwarfLocationResolver
            resolver = Phase2DwarfLocationResolver(
                binary_identity=elf_info,
                link_time_address=target_subp.low_pc if target_subp and target_subp.low_pc is not None else None,
                load_bias=load_bias,
                architecture=arch,
                memory_reader=proc_mem_reader,
                debug_artifact_path=search_path,
            )
        except Exception:
            pass

        # 9. Launch probe process with guaranteed cleanup
        decoder = EbpfEventDecoder(
            target_pid=pid,
            architecture=arch,
            function_name=function_name,
            function_offset=func_offset,
            load_bias=load_bias,
            subprogram=target_subp,
            resolver=resolver,
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
        elif proc and proc.poll() is not None and proc.returncode != 0 and proc.returncode != -signal.SIGINT:
            err_details = "\n".join(stderr_lines).strip()
            if len(events) > 0:
                status = "PARTIAL"
                error_msg = f"bpftrace terminated prematurely with code {proc.returncode} ({err_details}); {len(events)} events captured"
            else:
                status = "FAILED"
                error_msg = f"bpftrace exited with code {proc.returncode}: {err_details}"
        elif decoder.lost_count > 0:
            status = "PARTIAL"
            error_msg = f"Trace completed with {decoder.lost_count} lost event(s) due to buffer saturation; {len(events)} events captured"
        elif len(events) == 0:
            status = "PARTIAL"
            error_msg = "Attached successfully, but 0 events were captured during trace duration (function was not invoked)"

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
                "load_bias": f"0x{load_bias:x}",
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
            subprograms = list(d_index.subprograms_by_name.get(function_name, []))
            if not subprograms:
                for sp in d_index.subprograms:
                    if sp.name == function_name or sp.linkage_name == function_name:
                        subprograms.append(sp)
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
            entry_fmt = (
                '{\\"type\\":\\"ENTRY\\",\\"pid\\":%d,\\"tid\\":%d,\\"time\\":%llu,'
                '\\"sp\\":\\"0x%lx\\",\\"pc\\":\\"0x%lx\\",\\"fp\\":\\"0x%lx\\",\\"ra\\":\\"0x%lx\\",'
                '\\"arg0\\":%ld,\\"arg1\\":%ld,\\"arg2\\":%ld,\\"arg3\\":%ld,'
                '\\"arg4\\":%ld,\\"arg5\\":%ld,\\"arg6\\":%ld,\\"arg7\\":%ld}\\n'
            )
            entry_args = (
                'pid, tid, nsecs, reg("sp"), reg("pc"), reg("r29"), reg("r30"), '
                'arg0, arg1, arg2, arg3, arg4, arg5, arg6, arg7'
            )
        elif arch == "x86_64":
            # x86_64 has no link register for return address (passed on stack via (%rsp)).
            # Avoid reporting hardcoded 0x0; emit ra as null so it is marked UNAVAILABLE.
            entry_fmt = (
                '{\\"type\\":\\"ENTRY\\",\\"pid\\":%d,\\"tid\\":%d,\\"time\\":%llu,'
                '\\"sp\\":\\"0x%lx\\",\\"pc\\":\\"0x%lx\\",\\"fp\\":\\"0x%lx\\",\\"ra\\":null,'
                '\\"arg0\\":%ld,\\"arg1\\":%ld,\\"arg2\\":%ld,\\"arg3\\":%ld,'
                '\\"arg4\\":%ld,\\"arg5\\":%ld}\\n'
            )
            entry_args = 'pid, tid, nsecs, reg("sp"), reg("pc"), reg("bp"), arg0, arg1, arg2, arg3, arg4, arg5'
        else:
            raise ValueError(f"Architecture '{arch}' not supported for eBPF tracing.")

        entry_probe = f"""uprobe:{binary_path}:{attach_spec}
/pid == {target_pid}/
{{
    printf("{entry_fmt}",
           {entry_args});
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

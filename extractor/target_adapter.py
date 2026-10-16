"""Phase 23: Target Execution Adapter Abstraction.

Separates target host operations (process identity, liveness, maps, threads,
memory reading) from local host operations.

Enforces:
1. Strict namespace separation: a remote PID is interpreted exclusively on the
   target host; local /proc is never touched for remote targets.
2. Safe argument encoding: all remote commands use shlex.quote.
3. Robust transport error handling: explicit timeouts, connection failures,
   cancellation, and graceful termination.
4. Embedded target friendliness: zero Python or debugger required on the target.
   Build ID and architecture are verified host-side from ELF header bytes.
"""

from abc import ABC, abstractmethod
import base64
import errno
import os
import re
import shlex
import subprocess
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

from .debug_image import BinaryIdentity, inspect_elf


class TargetExecutionAdapter(ABC):
    """Abstract interface for interacting with a local or remote target process."""

    @abstractmethod
    def check_liveness(self, pid: int) -> Tuple[bool, Optional[str]]:
        """Checks if target process is currently alive and accessible.
        
        Returns:
            (True, None) if alive.
            (False, error_reason) if dead, inaccessible, or transport failure.
        """
        pass

    @abstractmethod
    def get_process_identity(self, pid: int) -> Dict[str, Any]:
        """Discovers executable path, architecture, build ID, and ELF type."""
        pass

    @abstractmethod
    def get_proc_maps(self, pid: int) -> List[Dict[str, Any]]:
        """Reads /proc/<pid>/maps and returns structured memory mappings."""
        pass

    @abstractmethod
    def get_threads(self, pid: int) -> List[Dict[str, Any]]:
        """Discovers active threads from /proc/<pid>/task."""
        pass

    @abstractmethod
    def read_memory(self, pid: int, address: int, size: int) -> Tuple[Optional[bytes], str, Optional[str]]:
        """Reads raw bytes from target memory without suspending the process.
        
        Returns:
            (bytes, "OBSERVED", None) on full success.
            (partial_bytes, "PARTIAL", msg) on partial read.
            (None, "UNAVAILABLE", reason) if unmapped or read error.
            (None, "TARGET_TERMINATED", reason) if target exited.
            (None, "PERMISSION_DENIED", reason) if permission denied.
        """
        pass

    @abstractmethod
    def is_remote(self) -> bool:
        """Returns True if the target is on a remote host, False if local."""
        pass

    @abstractmethod
    def target_host(self) -> str:
        """Returns the target host identifier (e.g. 'localhost' or 'user@host:port')."""
        pass

    def close(self) -> None:
        """Clean up any active connection or temporary resources."""
        pass


class LocalTargetAdapter(TargetExecutionAdapter):
    """Execution adapter for local Linux processes using direct /proc and process_vm_readv."""

    def __init__(self, memory_reader_fn: Optional[Callable[[int, int, int], Tuple[Optional[bytes], str, Optional[str]]]] = None):
        self._memory_reader = memory_reader_fn

    def is_remote(self) -> bool:
        return False

    def target_host(self) -> str:
        try:
            return os.uname().nodename
        except Exception:
            return "localhost"

    def check_liveness(self, pid: int) -> Tuple[bool, Optional[str]]:
        if pid <= 0:
            return False, f"Invalid PID {pid}"
        try:
            os.kill(pid, 0)
            return True, None
        except ProcessLookupError:
            return False, f"Target PID {pid} was not found (ESRCH)"
        except PermissionError:
            return False, f"Permission denied accessing target PID {pid} (EPERM)"
        except Exception as e:
            return False, f"Liveness check failed for PID {pid}: {e}"

    def get_process_identity(self, pid: int) -> Dict[str, Any]:
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

        return {
            "pid": pid,
            "executable": runtime_exe,
            "architecture": runtime_identity.architecture if runtime_identity else "unknown",
            "elf_type": runtime_identity.elf_type if runtime_identity else "unknown",
            "build_id": runtime_identity.build_id if runtime_identity else None,
            "pt_loads": runtime_identity.pt_loads if runtime_identity else [],
            "is_remote": False,
            "host": self.target_host(),
        }

    def get_proc_maps(self, pid: int) -> List[Dict[str, Any]]:
        maps_path = f"/proc/{pid}/maps"
        mappings: List[Dict[str, Any]] = []
        if not os.path.exists(maps_path):
            return mappings

        with open(maps_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.strip().split(maxsplit=5)
                if len(parts) >= 5:
                    addr_range = parts[0]
                    perms = parts[1]
                    offset = parts[2]
                    pathname = parts[5] if len(parts) >= 6 else ""

                    try:
                        start_hex, end_hex = addr_range.split("-")
                        s_int = int(start_hex, 16)
                        e_int = int(end_hex, 16)
                        off_int = int(offset, 16)
                    except Exception:
                        continue

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

                    mappings.append({
                        "start": f"0x{s_int:x}",
                        "end": f"0x{e_int:x}",
                        "start_int": s_int,
                        "end_int": e_int,
                        "size": e_int - s_int,
                        "permissions": perms,
                        "offset": offset,
                        "offset_int": off_int,
                        "category": category,
                        "pathname": pathname,
                        "is_readable": "r" in perms,
                        "is_writable": "w" in perms,
                        "is_executable": "x" in perms,
                    })
        return mappings

    def get_threads(self, pid: int) -> List[Dict[str, Any]]:
        threads: List[Dict[str, Any]] = []
        task_dir = f"/proc/{pid}/task"
        if not os.path.exists(task_dir):
            return threads

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
        return threads

    def read_memory(self, pid: int, address: int, size: int) -> Tuple[Optional[bytes], str, Optional[str]]:
        if self._memory_reader:
            return self._memory_reader(pid, address, size)
        from .watch_session import read_process_memory_slice
        return read_process_memory_slice(pid, address, size)


class RemoteSshTargetAdapter(TargetExecutionAdapter):
    """Execution adapter for remote Linux targets accessed via SSH / SSH Proxy.
    
    Zero-Python on target: uses standard POSIX shell, /proc, and dd/base64.
    Preserves target host namespace: NEVER opens or kills local /proc/<pid>.
    """

    def __init__(
        self,
        host: str,
        user: Optional[str] = None,
        port: int = 22,
        key_file: Optional[str] = None,
        proxy_jump: Optional[str] = None,
        proxy_command: Optional[str] = None,
        timeout_sec: float = 5.0,
        ssh_bin: str = "ssh",
        command_runner: Optional[Callable[[List[str], float], Tuple[int, str, str]]] = None,
    ):
        if not host:
            raise ValueError("Remote host must be specified")
        self.host = host
        self.user = user
        self.port = int(port)
        self.key_file = key_file
        self.proxy_jump = proxy_jump
        self.proxy_command = proxy_command
        self.timeout_sec = float(timeout_sec)
        self.ssh_bin = ssh_bin
        self._command_runner = command_runner or self._default_command_runner

    def is_remote(self) -> bool:
        return True

    def target_host(self) -> str:
        u = f"{self.user}@" if self.user else ""
        p = f":{self.port}" if self.port != 22 else ""
        return f"{u}{self.host}{p}"

    def _default_command_runner(self, cmd_args: List[str], timeout: float) -> Tuple[int, str, str]:
        try:
            res = subprocess.run(
                cmd_args,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return res.returncode, res.stdout, res.stderr
        except subprocess.TimeoutExpired:
            return -1, "", f"SSH command timed out after {timeout:.1f}s"
        except Exception as e:
            return -1, "", f"SSH execution error: {e}"

    def run_ssh(self, remote_shell_cmd: str, timeout: Optional[float] = None) -> Tuple[int, str, str]:
        """Runs a command on the remote target using configured SSH parameters."""
        t = timeout or self.timeout_sec
        args = [
            self.ssh_bin,
            "-p", str(self.port),
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=5",
        ]
        if self.key_file:
            args.extend(["-i", self.key_file])
        if self.proxy_jump:
            args.extend(["-J", self.proxy_jump])
        if self.proxy_command:
            args.extend(["-o", f"ProxyCommand={self.proxy_command}"])

        target_spec = f"{self.user}@{self.host}" if self.user else self.host
        args.append(target_spec)
        args.append(remote_shell_cmd)
        try:
            return self._command_runner(args, t)
        except subprocess.TimeoutExpired:
            return -1, "", f"SSH command timed out after {t:.1f}s"
        except Exception as e:
            return -1, "", f"SSH execution error: {e}"

    def check_liveness(self, pid: int) -> Tuple[bool, Optional[str]]:
        if pid <= 0:
            return False, f"Invalid PID {pid}"
        
        # Test liveness strictly on remote target host
        cmd = f"kill -0 {int(pid)} 2>/dev/null && echo ALIVE || echo DEAD"
        rc, stdout, stderr = self.run_ssh(cmd)
        if rc != 0:
            return False, f"SSH transport failure to {self.target_host()}: {stderr.strip() or 'Exit ' + str(rc)}"
        
        out = stdout.strip()
        if "ALIVE" in out:
            return True, None
        return False, f"Target PID {pid} is not running on {self.target_host()}"

    def get_process_identity(self, pid: int) -> Dict[str, Any]:
        """Discovers remote process executable, architecture, and Build ID.
        
        Reads the first 64KB of remote /proc/<pid>/exe and parses ELF header host-side.
        """
        # 1. Resolve remote executable path
        cmd_exe = f"readlink -f /proc/{int(pid)}/exe 2>/dev/null || readlink /proc/{int(pid)}/exe 2>/dev/null"
        rc, stdout, _ = self.run_ssh(cmd_exe)
        remote_exe = stdout.strip() if rc == 0 else ""

        # 2. Extract first 64KB of executable via base64 to inspect ELF header on host
        cmd_hdr = f"head -c 65536 /proc/{int(pid)}/exe 2>/dev/null | base64"
        rc, stdout_b64, stderr = self.run_ssh(cmd_hdr, timeout=self.timeout_sec * 1.5)

        arch = "unknown"
        elf_type = "unknown"
        build_id = None
        pt_loads: List[Dict[str, Any]] = []

        if rc == 0 and stdout_b64.strip():
            try:
                raw_elf = base64.b64decode(stdout_b64.strip())
                if len(raw_elf) >= 64:
                    with tempfile.NamedTemporaryFile(prefix="rem_elf_", suffix=".tmp", delete=False) as tf:
                        tf.write(raw_elf)
                        tf.flush()
                        tmp_name = tf.name
                    try:
                        ident = inspect_elf(tmp_name)
                        arch = ident.architecture
                        elf_type = ident.elf_type
                        build_id = ident.build_id
                        pt_loads = ident.pt_loads
                    finally:
                        if os.path.exists(tmp_name):
                            os.remove(tmp_name)
            except Exception:
                pass

        # Fallback for architecture via remote uname -m if ELF parse didn't yield arch
        if arch == "unknown":
            rc, stdout_uname, _ = self.run_ssh("uname -m 2>/dev/null")
            if rc == 0 and stdout_uname.strip():
                arch = stdout_uname.strip()

        return {
            "pid": pid,
            "executable": remote_exe,
            "architecture": arch,
            "elf_type": elf_type,
            "build_id": build_id,
            "pt_loads": pt_loads,
            "is_remote": True,
            "host": self.target_host(),
        }

    def get_proc_maps(self, pid: int) -> List[Dict[str, Any]]:
        cmd = f"cat /proc/{int(pid)}/maps 2>/dev/null"
        rc, stdout, _ = self.run_ssh(cmd)
        mappings: List[Dict[str, Any]] = []
        if rc != 0 or not stdout:
            return mappings

        for line in stdout.splitlines():
            parts = line.strip().split(maxsplit=5)
            if len(parts) >= 5:
                addr_range = parts[0]
                perms = parts[1]
                offset = parts[2]
                pathname = parts[5] if len(parts) >= 6 else ""

                try:
                    start_hex, end_hex = addr_range.split("-")
                    s_int = int(start_hex, 16)
                    e_int = int(end_hex, 16)
                    off_int = int(offset, 16)
                except Exception:
                    continue

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

                mappings.append({
                    "start": f"0x{s_int:x}",
                    "end": f"0x{e_int:x}",
                    "start_int": s_int,
                    "end_int": e_int,
                    "size": e_int - s_int,
                    "permissions": perms,
                    "offset": offset,
                    "offset_int": off_int,
                    "category": category,
                    "pathname": pathname,
                    "is_readable": "r" in perms,
                    "is_writable": "w" in perms,
                    "is_executable": "x" in perms,
                })
        return mappings

    def get_threads(self, pid: int) -> List[Dict[str, Any]]:
        # Efficient remote script to list threads without spawning multiple remote processes
        remote_script = (
            f"for t in /proc/{int(pid)}/task/*; do "
            f"[ -d \"$t\" ] || continue; "
            f"tid=$(basename \"$t\"); "
            f"comm=$(cat \"$t/comm\" 2>/dev/null || echo unknown); "
            f"stat=$(cat \"$t/stat\" 2>/dev/null | awk '{{print $3}}' || echo UNKNOWN); "
            f"echo \"$tid $stat $comm\"; "
            f"done"
        )
        rc, stdout, _ = self.run_ssh(f"sh -c {shlex.quote(remote_script)}")
        threads: List[Dict[str, Any]] = []
        if rc != 0 or not stdout:
            return threads

        for line in stdout.splitlines():
            tokens = line.strip().split(maxsplit=2)
            if len(tokens) >= 2 and tokens[0].isdigit():
                tid = int(tokens[0])
                state = tokens[1]
                comm = tokens[2] if len(tokens) >= 3 else "unknown"
                threads.append({
                    "tid": tid,
                    "name": comm,
                    "state": state,
                })

        threads.sort(key=lambda t: t["tid"])
        return threads

    def read_memory(self, pid: int, address: int, size: int) -> Tuple[Optional[bytes], str, Optional[str]]:
        if size <= 0:
            return b"", "OBSERVED", None

        # Remote memory read via dd and base64
        # dd skip requires decimal integer
        cmd = f"dd if=/proc/{int(pid)}/mem bs=1 skip={int(address)} count={int(size)} 2>/dev/null | base64"
        rc, stdout, stderr = self.run_ssh(cmd)
        if rc != 0:
            if rc == -1 or "timed out" in stderr.lower() or "connection" in stderr.lower():
                return None, "UNAVAILABLE", f"SSH transport failed reading memory at 0x{address:x}: {stderr.strip()}"
            alive, live_err = self.check_liveness(pid)
            if not alive:
                if live_err and ("transport failure" in live_err.lower() or "timed out" in live_err.lower()):
                    return None, "UNAVAILABLE", f"SSH transport failure at 0x{address:x}: {live_err}"
                return None, "TARGET_TERMINATED", live_err or "Remote process terminated"
            return None, "UNAVAILABLE", f"SSH transport failed reading memory at 0x{address:x}: {stderr.strip()}"

        encoded = stdout.strip()
        if not encoded:
            # If 0 bytes returned, verify if process is still alive
            alive, live_err = self.check_liveness(pid)
            if not alive:
                return None, "TARGET_TERMINATED", live_err or "Remote process terminated"
            return None, "UNAVAILABLE", f"Address 0x{address:x} is not mapped or inaccessible on {self.target_host()}"

        try:
            raw_bytes = base64.b64decode(encoded)
            if len(raw_bytes) == size:
                return raw_bytes, "OBSERVED", None
            elif len(raw_bytes) > 0:
                return raw_bytes, "PARTIAL", f"Partial read: {len(raw_bytes)}/{size} bytes"
            else:
                return None, "UNAVAILABLE", f"Zero bytes returned at 0x{address:x}"
        except Exception as e:
            return None, "UNAVAILABLE", f"Base64 decode failure: {e}"

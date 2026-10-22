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

    def get_memory_mappings(self, pid: int) -> List[Dict[str, Any]]:
        """Convenience alias for get_proc_maps."""
        return self.get_proc_maps(pid)

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

    def read_memory_batch(
        self,
        pid: int,
        slices: List[Tuple[int, int]],
    ) -> List[Tuple[Optional[bytes], str, Optional[str]]]:
        """Reads multiple (address, size) slices in a single batch operation when supported."""
        return [self.read_memory(pid, addr, sz) for addr, sz in slices]

    @abstractmethod
    def is_remote(self) -> bool:
        """Returns True if the target is on a remote host, False if local."""
        pass

    @abstractmethod
    def target_host(self) -> str:
        """Returns the target host identifier (e.g. 'localhost' or 'user@host:port')."""
        pass

    def find_processes(
        self,
        process_name: Optional[str] = None,
        companion_build_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Discovers running processes on the target host, optionally filtered by name or Build ID."""
        return []

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

    get_memory_mappings = get_proc_maps

    def get_threads(self, pid: int) -> List[Dict[str, Any]]:
        threads: List[Dict[str, Any]] = []
        task_dir = f"/proc/{pid}/task"
        if not os.path.exists(task_dir):
            return threads

        # Pre-fetch proc maps to locate thread stacks
        maps = self.get_proc_maps(pid)
        stack_maps = [m for m in maps if m.get("category") == "stack" or m.get("pathname", "").startswith("[stack")]

        try:
            for tid_entry in os.listdir(task_dir):
                if tid_entry.isdigit():
                    tid = int(tid_entry)
                    comm = "unknown"
                    state = "UNKNOWN"
                    startstack = 0
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
                                raw_stat = sf.read().strip()
                                rparen = raw_stat.rfind(")")
                                if rparen != -1:
                                    rest = raw_stat[rparen + 1:].strip().split()
                                    if len(rest) >= 1:
                                        state = rest[0]
                                    if len(rest) >= 26:
                                        try:
                                            startstack = int(rest[25])
                                        except (ValueError, IndexError):
                                            pass
                        except Exception:
                            pass

                    # Determine stack range
                    stack_info: Dict[str, Any] = {"status": "UNAVAILABLE", "reason": "Thread stack mapping not identifiable in proc maps"}
                    matched_map = None
                    if tid == pid:
                        # Main thread stack
                        for m in stack_maps:
                            if m.get("pathname") == "[stack]":
                                matched_map = m
                                break
                    if not matched_map:
                        for m in stack_maps:
                            if m.get("pathname") == f"[stack:{tid}]":
                                matched_map = m
                                break
                    if not matched_map and startstack > 0:
                        for m in maps:
                            if m["start_int"] <= startstack < m["end_int"]:
                                matched_map = m
                                break

                    if matched_map:
                        stack_info = {
                            "status": "AVAILABLE",
                            "start": matched_map["start"],
                            "end": matched_map["end"],
                            "start_int": matched_map["start_int"],
                            "end_int": matched_map["end_int"],
                            "size": matched_map["size"],
                            "permissions": matched_map["permissions"],
                        }

                    threads.append({
                        "tid": tid,
                        "name": comm,
                        "state": state,
                        "stack_info": stack_info,
                        "local_variables": {
                            "status": "UNSUPPORTED",
                            "reason": "Stack frame inspection requires an active debugger backend (GDB/ptrace frame unwind).",
                        },
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

    def find_processes(
        self,
        process_name: Optional[str] = None,
        companion_build_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        q = (process_name or "").strip().lower()
        target_bid = (companion_build_id or "").strip().lower() or None

        try:
            proc_entries = [e for e in os.listdir("/proc") if e.isdigit()]
        except Exception:
            return results

        for pid_str in proc_entries:
            pid = int(pid_str)
            comm = ""
            cmdline = ""
            exe_path = ""
            try:
                with open(f"/proc/{pid}/comm", "r", encoding="utf-8", errors="replace") as f:
                    comm = f.read().strip()
            except Exception:
                continue

            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    raw_cmd = f.read(512)
                    cmdline = raw_cmd.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
            except Exception:
                pass

            try:
                exe_path = os.path.realpath(f"/proc/{pid}/exe")
            except Exception:
                exe_path = ""

            exe_base = os.path.basename(exe_path) if exe_path else ""
            if q:
                if q not in comm.lower() and q not in exe_base.lower() and q not in cmdline.lower():
                    continue

            proc_bid = None
            bid_match = False
            if target_bid and exe_path and os.path.isfile(exe_path):
                try:
                    ident = inspect_elf(exe_path)
                    proc_bid = ident.build_id
                    if proc_bid and proc_bid.lower() == target_bid:
                        bid_match = True
                except Exception:
                    pass

            exact_name = bool(q and (comm.lower() == q or exe_base.lower() == q))
            results.append({
                "pid": pid,
                "name": comm or exe_base or f"pid_{pid}",
                "executable": exe_path,
                "cmdline": cmdline,
                "build_id": proc_bid,
                "build_id_match": bid_match,
                "exact_name_match": exact_name,
                "is_remote": False,
                "host": self.target_host(),
            })

        results.sort(key=lambda r: (
            1 if r.get("build_id_match") else 0,
            1 if r.get("exact_name_match") else 0,
            r.get("pid", 0),
        ), reverse=True)
        return results[:max(1, limit)]


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
        use_control_master: bool = False,
        collector_path: Optional[str] = None,
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
        self.use_control_master = bool(use_control_master)
        self.collector_path = (collector_path or "").strip() or None

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
        if self.use_control_master:
            args.extend([
                "-o", "ControlMaster=auto",
                "-o", "ControlPath=/tmp/dynstate_ssh_%r@%h:%p",
                "-o", "ControlPersist=60s",
            ])

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
                    "stack_info": {
                        "status": "UNAVAILABLE",
                        "reason": "Remote thread stack mapping not inspected over lightweight ssh adapter",
                    },
                    "local_variables": {
                        "status": "UNSUPPORTED",
                        "reason": "Stack frame inspection requires an active debugger backend.",
                    },
                })

        threads.sort(key=lambda t: t["tid"])
        return threads

    def _read_slices_via_collector(
        self,
        pid: int,
        slices: List[Tuple[int, int]],
    ) -> Optional[List[Tuple[Optional[bytes], str, Optional[str]]]]:
        """Uses C99 dynamicstate-collector --read-slices on the remote target for zero-stop process_vm_readv batch reads."""
        if not self.collector_path or not slices:
            return None
        import json as _json
        spec = ",".join(f"0x{int(addr):x}:{max(0, int(sz))}" for addr, sz in slices)
        cmd = f"{shlex.quote(self.collector_path)} -p {int(pid)} --read-slices {shlex.quote(spec)} 2>/dev/null"
        rc, stdout, _ = self.run_ssh(cmd)
        if rc != 0 or not stdout.strip():
            return None
        try:
            payload = _json.loads(stdout.strip().splitlines()[-1])
            if not payload.get("success") or "slices" not in payload:
                if payload.get("error") == "TARGET_TERMINATED":
                    return [(None, "TARGET_TERMINATED", "Remote process terminated") for _ in slices]
                return None
            out_list: List[Tuple[Optional[bytes], str, Optional[str]]] = []
            raw_slices = payload.get("slices", [])
            for idx, (req_addr, req_sz) in enumerate(slices):
                if req_sz <= 0:
                    out_list.append((b"", "OBSERVED", None))
                    continue
                s_item = raw_slices[idx] if idx < len(raw_slices) else {}
                st = s_item.get("status", "UNAVAILABLE")
                hex_str = s_item.get("hex", "")
                raw_b = bytes.fromhex(hex_str) if hex_str else b""
                if st == "OBSERVED" and len(raw_b) == req_sz:
                    out_list.append((raw_b, "OBSERVED", None))
                elif len(raw_b) > 0:
                    out_list.append((raw_b, "PARTIAL", f"Partial read: {len(raw_b)}/{req_sz} bytes"))
                else:
                    out_list.append((None, st if st in ("UNAVAILABLE", "PERMISSION_DENIED", "TARGET_TERMINATED") else "UNAVAILABLE", f"Collector read status: {st} at 0x{req_addr:x}"))
            return out_list
        except Exception:
            return None

    def read_memory_batch(
        self,
        pid: int,
        slices: List[Tuple[int, int]],
    ) -> List[Tuple[Optional[bytes], str, Optional[str]]]:
        """Reads multiple memory slices in a single SSH roundtrip (via C99 collector or batched POSIX shell)."""
        if not slices:
            return []
        if len(slices) == 1 and not self.collector_path:
            return [self.read_memory(pid, slices[0][0], slices[0][1])]

        if self.collector_path:
            coll_res = self._read_slices_via_collector(pid, slices)
            if coll_res is not None:
                return coll_res

        # Single-SSH batched shell read with page-aligned dd fallback for 64-bit BusyBox offsets
        cmds = []
        for idx, (addr, sz) in enumerate(slices):
            a_int = int(addr)
            s_int = max(0, int(sz))
            if s_int == 0:
                cmds.append(f"echo '{idx}|'")
                continue
            page_sz = 4096
            page_num = a_int // page_sz
            page_off = a_int % page_sz
            pages_needed = ((page_off + s_int + page_sz - 1) // page_sz)
            cmds.append(
                f"b=$(dd if=/proc/{int(pid)}/mem bs=1 skip={a_int} count={s_int} 2>/dev/null | base64 | tr -d '\\n'); "
                f"if [ -z \"$b\" ]; then "
                f"b=$(dd if=/proc/{int(pid)}/mem bs={page_sz} skip={page_num} count={pages_needed} 2>/dev/null | "
                f"dd bs=1 skip={page_off} count={s_int} 2>/dev/null | base64 | tr -d '\\n'); "
                f"fi; "
                f"echo \"{idx}|$b\""
            )
        remote_script = "; ".join(cmds)
        rc, stdout, stderr = self.run_ssh(f"sh -c {shlex.quote(remote_script)}")
        if rc != 0:
            alive, live_err = self.check_liveness(pid)
            if not alive:
                st = "UNAVAILABLE" if (live_err and ("transport" in live_err.lower() or "timed out" in live_err.lower())) else "TARGET_TERMINATED"
                return [(None, st, live_err or "Remote process terminated") for _ in slices]
            return [(None, "UNAVAILABLE", f"SSH batch read failed: {stderr.strip()}") for _ in slices]

        by_idx: Dict[int, str] = {}
        for line in stdout.splitlines():
            if "|" in line:
                k_str, val_b64 = line.strip().split("|", 1)
                if k_str.isdigit():
                    by_idx[int(k_str)] = val_b64.strip()

        results: List[Tuple[Optional[bytes], str, Optional[str]]] = []
        for idx, (addr, sz) in enumerate(slices):
            if sz <= 0:
                results.append((b"", "OBSERVED", None))
                continue
            b64_str = by_idx.get(idx, "")
            if not b64_str:
                results.append((None, "UNAVAILABLE", f"Address 0x{int(addr):x} is not mapped or inaccessible on {self.target_host()}"))
                continue
            try:
                raw_b = base64.b64decode(b64_str)
                if len(raw_b) == sz:
                    results.append((raw_b, "OBSERVED", None))
                elif len(raw_b) > 0:
                    results.append((raw_b, "PARTIAL", f"Partial read: {len(raw_b)}/{sz} bytes"))
                else:
                    results.append((None, "UNAVAILABLE", f"Zero bytes returned at 0x{int(addr):x}"))
            except Exception as e:
                results.append((None, "UNAVAILABLE", f"Base64 decode failure: {e}"))
        return results

    def read_memory(self, pid: int, address: int, size: int) -> Tuple[Optional[bytes], str, Optional[str]]:
        if size <= 0:
            return b"", "OBSERVED", None

        if self.collector_path:
            coll_res = self._read_slices_via_collector(pid, [(address, size)])
            if coll_res is not None and len(coll_res) == 1:
                return coll_res[0]

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

    def find_processes(
        self,
        process_name: Optional[str] = None,
        companion_build_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Discovers running processes on the remote target via a single POSIX shell scan of /proc."""
        remote_script = (
            "for p in /proc/[0-9]*; do "
            "[ -d \"$p\" ] || continue; "
            "pid=$(basename \"$p\"); "
            "comm=$(cat \"$p/comm\" 2>/dev/null | tr -d '\n' || true); "
            "[ -n \"$comm\" ] || continue; "
            "exe=$(readlink -f \"$p/exe\" 2>/dev/null || readlink \"$p/exe\" 2>/dev/null || true); "
            "cmd=$(tr '\000' ' ' < \"$p/cmdline\" 2>/dev/null | head -c 200 || true); "
            "echo \"$pid|$comm|$exe|$cmd\"; "
            "done"
        )
        rc, stdout, _ = self.run_ssh(f"sh -c {shlex.quote(remote_script)}")
        results: List[Dict[str, Any]] = []
        if rc != 0 or not stdout:
            return results

        q = (process_name or "").strip().lower()
        target_bid = (companion_build_id or "").strip().lower() or None

        for line in stdout.splitlines():
            parts = line.strip().split("|", 3)
            if len(parts) < 2 or not parts[0].isdigit():
                continue
            pid = int(parts[0])
            comm = parts[1].strip()
            exe_path = parts[2].strip() if len(parts) >= 3 else ""
            cmdline = parts[3].strip() if len(parts) >= 4 else ""
            exe_base = os.path.basename(exe_path) if exe_path else ""

            if q:
                if q not in comm.lower() and q not in exe_base.lower() and q not in cmdline.lower():
                    continue

            exact_name = bool(q and (comm.lower() == q or exe_base.lower() == q))
            results.append({
                "pid": pid,
                "name": comm or exe_base or f"pid_{pid}",
                "executable": exe_path,
                "cmdline": cmdline,
                "build_id": None,
                "build_id_match": False,
                "exact_name_match": exact_name,
                "is_remote": True,
                "host": self.target_host(),
            })

        # Sort exact matches first; if target_bid is provided, verify Build ID on top candidates (up to 5)
        results.sort(key=lambda r: (1 if r.get("exact_name_match") else 0, r.get("pid", 0)), reverse=True)
        if target_bid:
            for cand in results[:5]:
                ident = self.get_process_identity(cand["pid"])
                bid = ident.get("build_id")
                cand["build_id"] = bid
                if bid and bid.lower() == target_bid:
                    cand["build_id_match"] = True
            results.sort(key=lambda r: (
                1 if r.get("build_id_match") else 0,
                1 if r.get("exact_name_match") else 0,
                r.get("pid", 0),
            ), reverse=True)

        return results[:max(1, limit)]

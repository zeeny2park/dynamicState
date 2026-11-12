"""QEMU guest lifecycle for the matrix: argument building, boot/SSH wait, guaranteed teardown."""
from __future__ import annotations

import os
import signal
import socket
import subprocess
import time
from typing import Callable, Dict, List, Optional, Sequence

# Resource limits that imitate a constrained board (roadmap: 64-128 MB, one core).
MAX_MEM_MB = 128
MIN_MEM_MB = 64


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def build_qemu_args(
    *,
    qemu_bin: str,
    machine: str,
    cpu: str,
    mem_mb: int,
    kernel: str,
    initrd: str,
    console_tty: str,
    ssh_port: int,
    console_log: str,
    extra_append: str = "",
) -> List[str]:
    """Headless, 1 vCPU, user-mode networking with only a localhost-bound SSH forward."""
    if not (MIN_MEM_MB <= int(mem_mb) <= MAX_MEM_MB):
        raise ValueError(f"guest memory must be {MIN_MEM_MB}-{MAX_MEM_MB} MB (got {mem_mb})")
    if not (1 <= int(ssh_port) <= 65535):
        raise ValueError(f"bad ssh port {ssh_port}")
    append = f"console={console_tty} panic=-1 quiet loglevel=3 {extra_append}".strip()
    return [
        qemu_bin,
        "-M", machine,
        "-cpu", cpu,
        "-smp", "1",
        "-m", str(int(mem_mb)),
        "-accel", "tcg,thread=single",
        "-display", "none",
        "-monitor", "none",
        "-serial", f"file:{console_log}",
        "-no-reboot",
        "-kernel", kernel,
        "-initrd", initrd,
        "-append", append,
        "-netdev", f"user,id=n0,hostfwd=tcp:127.0.0.1:{int(ssh_port)}-:22",
        "-device", "virtio-net-pci,netdev=n0,romfile=",
    ]


class QemuVM:
    """Owns one QEMU process (own session/process group). ``stop`` is idempotent and kills the group."""

    def __init__(
        self,
        args: Sequence[str],
        ssh_port: int,
        console_log: str,
        popen: Callable[..., "subprocess.Popen"] = subprocess.Popen,
    ):
        self.args = list(args)
        self.ssh_port = ssh_port
        self.console_log = console_log
        self._popen = popen
        self.proc: Optional["subprocess.Popen"] = None
        self.boot_started: Optional[float] = None
        self.ssh_ready_after_s: Optional[float] = None

    # -- lifecycle ------------------------------------------------------------------
    def start(self) -> None:
        if self.proc is not None:
            raise RuntimeError("VM already started")
        self.boot_started = time.monotonic()
        self.proc = self._popen(
            self.args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            start_new_session=True,
        )

    def alive(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def stop(self, grace_s: float = 3.0) -> Dict[str, object]:
        """SIGTERM the process group, escalate to SIGKILL after ``grace_s``. Never raises."""
        info: Dict[str, object] = {"was_running": self.alive(), "killed": False}
        p = self.proc
        if p is None:
            return info
        if p.poll() is None:
            self._signal_group(p, signal.SIGTERM)
            try:
                p.wait(timeout=grace_s)
            except subprocess.TimeoutExpired:
                self._signal_group(p, signal.SIGKILL)
                info["killed"] = True
                try:
                    p.wait(timeout=grace_s)
                except subprocess.TimeoutExpired:
                    info["still_running"] = True
        info["returncode"] = p.returncode
        return info

    @staticmethod
    def _signal_group(p: "subprocess.Popen", sig: int) -> None:
        try:
            os.killpg(os.getpgid(p.pid), sig)
        except (ProcessLookupError, PermissionError, OSError):
            try:
                p.send_signal(sig)
            except Exception:  # noqa: BLE001
                pass

    # -- readiness ------------------------------------------------------------------
    def wait_ready(
        self,
        timeout_s: float,
        probe: Callable[[], bool],
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
        interval_s: float = 3.0,
    ) -> bool:
        """Poll ``probe`` (an SSH 'true') until it succeeds, the VM dies, or ``timeout_s`` elapses."""
        t0 = clock()
        while clock() - t0 < timeout_s:
            if not self.alive():
                return False
            try:
                if probe():
                    self.ssh_ready_after_s = round(clock() - t0, 1)
                    return True
            except Exception:  # noqa: BLE001
                pass
            sleep(interval_s)
        return False

    def console_tail(self, n: int = 2000) -> str:
        try:
            with open(self.console_log, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                f.seek(max(0, size - n))
                return f.read().decode("utf-8", "replace")
        except OSError:
            return ""

    def stderr_text(self) -> str:
        if self.proc is not None and self.proc.stderr is not None and self.proc.poll() is not None:
            try:
                return self.proc.stderr.read().decode("utf-8", "replace")
            except Exception:  # noqa: BLE001
                return ""
        return ""


def leftover_qemu_processes() -> List[str]:
    """Command lines of running qemu-system-* processes (for the post-run assertion)."""
    out = subprocess.run(["pgrep", "-fa", "qemu-system"], capture_output=True, text=True)
    return [l for l in out.stdout.splitlines() if l.strip() and "pgrep" not in l]

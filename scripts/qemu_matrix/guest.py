"""One running guest: throwaway key, boot, SSH helpers, counted SSH transport for the product adapter."""
from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import entries, images, vm

SSH_COMMON_OPTS = [
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "StrictHostKeyChecking=no",
    "-o", "LogLevel=ERROR",
    "-o", "IdentitiesOnly=yes",
]


def inject_ssh_opts(args: List[str]) -> List[str]:
    """Put our options before the adapter's (ssh keeps the FIRST value of an option), so the guest's
    throwaway host key never touches the user's known_hosts."""
    return [args[0]] + SSH_COMMON_OPTS + list(args[1:])


class CountingTransport:
    """Command runner + stream opener for RemoteSshTargetAdapter that counts remote commands.

    ``commands`` counts every ssh invocation (one-shot commands and daemon-channel opens)."""

    def __init__(self, timeout_floor: float = 0.0):
        self.commands = 0
        self.stream_opens = 0
        self.wall_in_ssh_s = 0.0
        self._lock = threading.Lock()

    def runner(self, args: List[str], timeout: float, input_bytes: Optional[bytes] = None) -> Tuple[int, str, str]:
        with self._lock:
            self.commands += 1
        t0 = time.monotonic()
        try:
            r = subprocess.run(inject_ssh_opts(args), input=input_bytes, capture_output=True, timeout=timeout)
            return r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace")
        except subprocess.TimeoutExpired:
            return -1, "", f"SSH command timed out after {timeout:.1f}s"
        finally:
            self.wall_in_ssh_s += time.monotonic() - t0

    def opener(self, args: List[str]) -> "subprocess.Popen":
        with self._lock:
            self.commands += 1
            self.stream_opens += 1
        return subprocess.Popen(inject_ssh_opts(args), stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, close_fds=True)

    def snapshot(self) -> Dict[str, Any]:
        return {"commands": self.commands, "stream_opens": self.stream_opens}


class Guest:
    def __init__(self, entry_name: str, work_dir: Optional[str] = None, boot_timeout_s: float = 240.0):
        self.entry = entries.ENTRIES[entry_name]
        self.name = entry_name
        self.boot_timeout_s = boot_timeout_s
        self.work = work_dir or tempfile.mkdtemp(prefix=f"dsqemu_{entry_name}_", dir=images.cache_dir() if os.path.isdir(images.cache_dir()) else None)
        self.key = os.path.join(self.work, "id_ed25519")
        self.port = vm.free_port()
        self.vm: Optional[vm.QemuVM] = None
        self.boot_info: Dict[str, Any] = {}
        self.workdir = "/tmp"

    # ---- key + start ----
    def _make_key(self) -> str:
        subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "dynamicstate-matrix", "-f", self.key],
                       check=True)
        return open(self.key + ".pub").read()

    def start(self) -> None:
        pub = self._make_key()
        paths = entries.image_paths(self.name)
        initrd = images.compose_initrd(paths["initrd"], pub, os.path.join(self.work, "initrd.cpio.gz"))
        console = os.path.join(self.work, "console.log")
        e = self.entry
        args = vm.build_qemu_args(
            qemu_bin=e["qemu_bin"], machine=e["machine"], cpu=e["cpu"], mem_mb=e["mem_mb"],
            kernel=paths["kernel"], initrd=initrd, console_tty=e["console_tty"], ssh_port=self.port,
            console_log=console)
        self.vm = vm.QemuVM(args, self.port, console)
        self.vm.start()
        ok = self.vm.wait_ready(self.boot_timeout_s, lambda: self.ssh("true", timeout=15)[0] == 0)
        self.boot_info = {"ssh_ready": ok, "ssh_ready_after_s": self.vm.ssh_ready_after_s,
                          "mem_mb": e["mem_mb"], "vcpus": 1, "qemu_args": args}
        if not ok:
            raise RuntimeError("guest did not become reachable over SSH: console tail:\n" + self.vm.console_tail()
                               + "\n" + self.vm.stderr_text())

    def stop(self) -> Dict[str, Any]:
        info = self.vm.stop() if self.vm else {}
        self.boot_info["shutdown"] = info
        return info

    # ---- raw ssh (not counted; used by the harness itself) ----
    def ssh_base(self) -> List[str]:
        return ["ssh", "-p", str(self.port), "-i", self.key, "-o", "BatchMode=yes", "-o", "ConnectTimeout=10",
                *SSH_COMMON_OPTS, "root@127.0.0.1"]

    def ssh(self, cmd: str, timeout: float = 60.0, input_bytes: Optional[bytes] = None) -> Tuple[int, str, str]:
        try:
            r = subprocess.run(self.ssh_base() + [cmd], input=input_bytes, capture_output=True, timeout=timeout)
            return r.returncode, r.stdout.decode("utf-8", "replace"), r.stderr.decode("utf-8", "replace")
        except subprocess.TimeoutExpired:
            return -1, "", f"timeout after {timeout}s"

    def upload(self, local: str, remote: str, mode: str = "755") -> None:
        with open(local, "rb") as f:
            data = f.read()
        rc, _, err = self.ssh(f"cat > {remote} && chmod {mode} {remote}", timeout=120, input_bytes=data)
        if rc != 0:
            raise RuntimeError(f"upload {local} -> {remote} failed: {err}")

    # ---- product adapter ----
    def make_adapter(self, transport: Optional[CountingTransport] = None, **kw):
        from extractor.target_adapter import RemoteSshTargetAdapter
        tr = transport or CountingTransport()
        params = dict(host="127.0.0.1", user="root", port=self.port, key_file=self.key, timeout_sec=30.0,
                      command_runner=tr.runner, stream_opener=tr.opener)
        params.update(kw)
        return RemoteSshTargetAdapter(**params), tr

"""Cross-compile the matrix's target programs (host side; nothing is built inside the guest).

Entries use the distro glibc cross compiler.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from typing import Dict, List, Optional

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
TARGET_SRC = {
    "memtarget": os.path.join(REPO, "scripts", "qemu_matrix", "targets", "memtarget.c"),
    "deadlock": os.path.join(REPO, "tests", "fixtures", "real_runtime", "proc_thread_circular_deadlock.c"),
}


def cc_cmd(cc: str, src: str, out: str) -> List[str]:
    return [cc, "-g", "-O0", "-Wl,--build-id=sha1", "-pthread", src, "-o", out]


def _run(cmd: List[str]) -> None:
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"build failed: {' '.join(cmd)}\n{r.stderr}")


def build_entry_targets(entry: Dict, outdir: str) -> Dict[str, Dict[str, str]]:
    """Returns {name: {"debug": host -g ELF, "guest": stripped copy to upload}}."""
    cc = entry["cc"]
    if not shutil.which(cc):
        raise RuntimeError(f"cross compiler {cc} not installed")
    os.makedirs(outdir, exist_ok=True)
    out: Dict[str, Dict[str, str]] = {}
    strip = cc[:-3] + "strip"
    for name, src in TARGET_SRC.items():
        dbg = os.path.join(outdir, name + ".debug")
        _run(cc_cmd(cc, src, dbg))
        guest = os.path.join(outdir, name)
        shutil.copy2(dbg, guest)
        if shutil.which(strip):
            _run([strip, "--strip-debug", guest])  # keeps .symtab + build-id; the -g ELF stays on the host
        out[name] = {"debug": dbg, "guest": guest}
    return out

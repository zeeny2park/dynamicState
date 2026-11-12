"""Cross-compile the matrix's target programs (host side; nothing is built inside the guest).

glibc entries use the distro cross compiler.  musl entries reuse the SAME cross gcc but compile and link
against the Alpine musl sysroot (``-nostdinc -nostdlib``, musl crt files, ``libc.musl-<arch>.so.1`` and the
musl dynamic loader path), producing a genuine musl-linked dynamic executable.
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


def glibc_cc_cmd(cc: str, src: str, out: str) -> List[str]:
    return [cc, "-g", "-O0", "-Wl,--build-id=sha1", "-pthread", src, "-o", out]


def musl_cc_cmd(cc: str, sysroot: str, src: str, out: str, loader: str, libc_so: str, libgcc: str, gcc_inc: str) -> List[str]:
    lib = os.path.join(sysroot, "usr", "lib")
    return [
        cc, "-g", "-O0", "-nostdinc", "-isystem", gcc_inc, "-isystem", os.path.join(sysroot, "usr", "include"),
        "-D_REENTRANT", "-c", src, "-o", out + ".o",
    ], [
        cc, "-nostdlib", "-pie", "-Wl,--build-id=sha1", f"-Wl,-dynamic-linker={loader}",
        os.path.join(lib, "Scrt1.o"), os.path.join(lib, "crti.o"), out + ".o",
        os.path.join(sysroot, "lib", libc_so), libgcc, os.path.join(lib, "crtn.o"), "-o", out,
    ]


def _run(cmd: List[str]) -> None:
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"build failed: {' '.join(cmd)}\n{r.stderr}")


def build_entry_targets(entry: Dict, outdir: str, cache: str) -> Dict[str, Dict[str, str]]:
    """Returns {name: {"debug": host -g ELF, "guest": stripped copy to upload}}."""
    cc = entry["cc"]
    if not shutil.which(cc):
        raise RuntimeError(f"cross compiler {cc} not installed")
    os.makedirs(outdir, exist_ok=True)
    out: Dict[str, Dict[str, str]] = {}
    strip = cc[:-3] + "strip"
    for name, src in TARGET_SRC.items():
        dbg = os.path.join(outdir, name + ".debug")
        if entry["libc"] == "musl":
            sysroot = entry.get("musl_sysroot") or os.path.join(cache, entry["name"], "musl-sysroot")
            gcc_inc = subprocess.run([cc, "-print-file-name=include"], capture_output=True, text=True).stdout.strip()
            libgcc = subprocess.run([cc, "-print-libgcc-file-name"], capture_output=True, text=True).stdout.strip()
            c1, c2 = musl_cc_cmd(cc, sysroot, src, dbg, entry["musl_loader"], entry["musl_libc_so"], libgcc, gcc_inc)
            _run(c1)
            _run(c2)
            os.unlink(dbg + ".o")
        else:
            _run(glibc_cc_cmd(cc, src, dbg))
        guest = os.path.join(outdir, name)
        shutil.copy2(dbg, guest)
        if shutil.which(strip):
            _run([strip, "--strip-debug", guest])  # keeps .symtab + build-id; the -g ELF stays on the host
        out[name] = {"debug": dbg, "guest": guest}
    return out

"""Race-free builders for test fixture binaries that live at fixed, shared /tmp paths.

Several test files share fixed paths such as /tmp/expert_diagnostic_debug.elf.  When the per-file
baseline runs files in parallel, one file recompiling the binary in place while another executes it
fails with ETXTBSY ("Text file busy") or FileNotFoundError.  The helpers here:

* serialise builds with an flock on a sidecar lock file,
* compile into a unique temporary name in the same directory, and
* publish with an atomic os.replace(), only when the target is missing (or, optionally, older than
  its source), so a process executing the previous inode is never disturbed.

This module is deliberately not named ``test_*`` so unittest discovery does not collect it.
"""

import fcntl
import os
import subprocess
import tempfile
from typing import List, Optional, Tuple

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FIXTURE_DIR = os.path.join(REPO_ROOT, "tests", "fixtures", "real_runtime")

EXPERT_DEBUG_ELF = "/tmp/expert_diagnostic_debug.elf"
EXPERT_STRIPPED_ELF = "/tmp/expert_diagnostic_stripped.elf"
REAL_RUNTIME_DEBUG_ELF = "/tmp/real_runtime_app_debug.elf"

_EXPERT_SRC = os.path.join(FIXTURE_DIR, "expert_diagnostic_scenarios.cpp")
_EXPERT_CXXFLAGS = ["-g", "-O0", "-fno-inline", "-fno-omit-frame-pointer"]
_REAL_RUNTIME_SRC = os.path.join(FIXTURE_DIR, "main.cpp")
_REAL_RUNTIME_FLAGS = ["-fPIE", "-pie", "-g", "-O0", "-fno-inline", "-fno-omit-frame-pointer",
                       "-Wl,--build-id=sha1"]


def _is_stale(dest: str, deps: List[str], rebuild_if_older: bool) -> bool:
    if not os.path.isfile(dest):
        return True
    if not rebuild_if_older:
        return False
    mtime = os.path.getmtime(dest)
    return any(os.path.getmtime(d) > mtime for d in deps if os.path.exists(d))


def _publish(dest: str, build_cmd_for_tmp) -> None:
    fd, tmp = tempfile.mkstemp(prefix=os.path.basename(dest) + ".", suffix=".tmp",
                               dir=os.path.dirname(dest) or ".")
    os.close(fd)
    try:
        res = subprocess.run(build_cmd_for_tmp(tmp), capture_output=True, text=True)
        if res.returncode != 0:
            raise RuntimeError(f"Failed building fixture {dest}: {res.stderr.strip()[-2000:]}")
        os.chmod(tmp, 0o755)
        os.replace(tmp, dest)  # atomic; readers/executors keep whichever inode they opened
        tmp = None
    finally:
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)


class _Lock:
    def __init__(self, dest: str):
        self._path = dest + ".buildlock"

    def __enter__(self):
        self._fh = open(self._path, "a+")
        fcntl.flock(self._fh, fcntl.LOCK_EX)
        return self

    def __exit__(self, *exc):
        fcntl.flock(self._fh, fcntl.LOCK_UN)
        self._fh.close()


def ensure_expert_diagnostic_fixture(need_stripped: bool = True) -> Tuple[str, str]:
    """Return (debug_elf, stripped_elf) at their shared /tmp paths, building atomically if needed."""
    with _Lock(EXPERT_DEBUG_ELF):
        rebuilt = False
        if _is_stale(EXPERT_DEBUG_ELF, [_EXPERT_SRC], rebuild_if_older=True):
            _publish(EXPERT_DEBUG_ELF,
                     lambda t: ["g++", *_EXPERT_CXXFLAGS, _EXPERT_SRC, "-o", t, "-lpthread"])
            rebuilt = True
        if need_stripped and (rebuilt or _is_stale(EXPERT_STRIPPED_ELF, [EXPERT_DEBUG_ELF],
                                                   rebuild_if_older=True)):
            _publish(EXPERT_STRIPPED_ELF,
                     lambda t: ["strip", "-s", "-o", t, EXPERT_DEBUG_ELF])
    return EXPERT_DEBUG_ELF, EXPERT_STRIPPED_ELF


def ensure_real_runtime_app_debug(dest: str = REAL_RUNTIME_DEBUG_ELF) -> str:
    """CI/baseline prebuild this path; if it is missing build it atomically (never in place)."""
    with _Lock(dest):
        if _is_stale(dest, [], rebuild_if_older=False):
            _publish(dest, lambda t: ["g++", *_REAL_RUNTIME_FLAGS, _REAL_RUNTIME_SRC, "-o", t,
                                      "-lpthread"])
    return dest


def ensure_built(dest: str, argv_for_tmp, deps=(), rebuild_if_older: bool = False) -> str:
    """Generic atomic build: run ``argv_for_tmp(tmp_path)`` into a unique temp file and publish it at
    ``dest`` under a lock, only if ``dest`` is missing (or older than ``deps`` when requested)."""
    with _Lock(dest):
        if _is_stale(dest, list(deps), rebuild_if_older):
            _publish(dest, argv_for_tmp)
    return dest

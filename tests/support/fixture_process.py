"""Contained launcher for long-lived fixture/target processes (tests, benchmarks, scripts).

Rule: every long-lived fixture process (a program that keeps running until someone stops it) is started
through this module, never with a bare ``subprocess.Popen``.  Short tool invocations (gcc, gdb, readelf)
do not need it.  ``tests/test_fixture_process_policy.py`` enforces the rule.

Why this module lives in ``tests/support`` and not elsewhere: ``tests/`` is already importable from the
repository root as a namespace package (``from tests.fixture_builds import ...`` is used all over), the
benchmarks already put the repository root on ``sys.path`` to import ``extractor``, and it must not ship
inside ``extractor/`` (product code).  So ``from tests.support.fixture_process import ...`` works in both
without path hacks.

Layers (no single mechanism covers every way a runner can end, so they are stacked):

1. Die with the parent.  ``PR_SET_PDEATHSIG(SIGKILL)`` is set between fork and exec, the fixture gets its
   own session/process group (so the whole tree can be killed).  PDEATHSIG fires when the *thread* that
   forked exits, so all forks are done from one process-lifetime launcher thread, never from a (possibly
   short-lived) caller thread.  It is cleared when the child execs a setuid/setgid binary (irrelevant to
   fixtures, but it means the other layers must not be skipped).
2. An external watchdog process (one per fixture, own session, stdlib only, started right after the fork).
   It does not depend on the test's ``finally``: it kills the whole fixture tree when the runner dies
   (EOF on a pipe the runner holds, which also works for SIGKILL), when the hard lifetime expires, or when
   the resident memory of the tree (``/proc/<pid>/statm`` summed over the process group and descendants)
   exceeds the ceiling.  A limit hit is reported to the runner through a second pipe and surfaces as
   ``FixtureMemoryCeilingExceeded`` / ``FixtureLifetimeExceeded`` from ``poll()``/``wait()``/``check()``/
   leaving ``fixture_process(...)`` -- never as a silent pass.
3. A sweep in the runner: ``atexit`` plus SIGTERM/SIGINT/SIGHUP handlers kill every fixture the runner
   started, then re-raise the signal (or chain to the previous handler).
4. The fixtures that grow without bound cap themselves in their own source (see the ``FIXTURE_CAP``
   comments in the C files).

RLIMIT_AS is deliberately NOT used: thread-heavy fixtures legitimately map several GB of stacks/arenas
(address space, not memory), so a safe value is far above any harmful resident size; the RSS watchdog is
the right measure.  cgroup v2 ``memory.max`` via ``systemd-run --user --scope`` is not used either: it is
not available without a user session on GitHub runners, and the portable watchdog is required anyway.

Defaults: resident ceiling ``DEFAULT_MAX_RSS_MIB`` (1.5 GiB), lifetime ``DEFAULT_MAX_LIFETIME_S``.
Extend per call (``max_rss_mib=...``, ``max_lifetime_s=...``) or globally via the environment variables
``DYNAMICSTATE_FIXTURE_MAX_RSS_MIB`` / ``DYNAMICSTATE_FIXTURE_MAX_LIFETIME_S``.  Per-fixture ceilings live
in ``FIXTURE_RSS_OVERRIDES_MIB`` (keyed by executable basename, each with the measurement behind it).

Usage::

    with fixture_process([binary], stdout=subprocess.PIPE, text=True) as proc:
        ...                      # proc is a subprocess.Popen subclass

    proc = fixture_popen([binary], ...)   # drop-in for subprocess.Popen when a context manager is awkward
"""

from __future__ import annotations

import atexit
import concurrent.futures
import contextlib
import ctypes
import os
import queue
import signal
import subprocess
import sys
import threading
import time
from typing import Any, Dict, Iterator, Optional, Tuple

_REAL_POPEN = subprocess.Popen  # tests that patch subprocess.Popen must not affect the launcher itself

DEFAULT_MAX_RSS_MIB = 1536
DEFAULT_MAX_LIFETIME_S = 600.0
WATCHDOG_TICK_S = 0.1

# Per-fixture resident ceilings (MiB), keyed by executable basename.  Only where a measurement requires it.
FIXTURE_RSS_OVERRIDES_MIB: Dict[str, int] = {}

_PR_SET_PDEATHSIG = 1
try:
    _libc = ctypes.CDLL(None, use_errno=True)
    _prctl = _libc.prctl
    _prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    _prctl.restype = ctypes.c_int
except (OSError, AttributeError):  # pragma: no cover - non-glibc/non-Linux
    _prctl = None


class FixtureLimitExceeded(RuntimeError):
    """A contained fixture was killed by its watchdog (memory ceiling or lifetime)."""


class FixtureMemoryCeilingExceeded(FixtureLimitExceeded):
    """The fixture exceeded its resident-memory ceiling and was killed."""


class FixtureLifetimeExceeded(FixtureLimitExceeded):
    """The fixture outlived its hard maximum lifetime and was killed."""


# ----------------------------------------------------------------------------------------------- watchdog
_WATCHDOG_SRC = r'''
import os, sys, time, select, signal
pid = int(sys.argv[1]); pfd = int(sys.argv[2]); rfd = int(sys.argv[3])
limit = int(sys.argv[4]); deadline = float(sys.argv[5]); tick = float(sys.argv[6]); name = sys.argv[7]; own = sys.argv[8] == "1"
PAGE = os.sysconf("SC_PAGE_SIZE")
for s in (signal.SIGINT, signal.SIGHUP, signal.SIGTERM):
    signal.signal(s, signal.SIG_IGN)

def procs():
    out = {}
    try:
        names = os.listdir("/proc")
    except OSError:
        return out
    for n in names:
        if not n.isdigit():
            continue
        try:
            with open("/proc/%s/stat" % n, "rb") as f:
                s = f.read().decode("ascii", "replace")
            rest = s[s.rfind(")") + 2:].split()
            out[int(n)] = (rest[0], int(rest[1]), int(rest[2]))
        except (OSError, ValueError, IndexError):
            pass
    return out

def tree():
    allp = procs()
    members = {p for p, (st, pp, pg) in allp.items() if (pg == pid if own else p == pid) and st != "Z"}
    changed = True
    while changed:
        changed = False
        for p, (st, pp, pg) in allp.items():
            if pp in members and p not in members and st != "Z":
                members.add(p); changed = True
    return members

def rss(p):
    try:
        with open("/proc/%d/statm" % p, "rb") as f:
            return int(f.read().split()[1]) * PAGE
    except (OSError, ValueError, IndexError):
        return 0

def kill_all(extra=()):
    if own:
        try:
            os.killpg(pid, signal.SIGKILL)
        except OSError:
            pass
    for p in set(tree()) | set(extra):
        try:
            os.kill(p, signal.SIGKILL)
        except OSError:
            pass

def report(kind, text):
    try:
        os.write(rfd, (kind + "\t" + text).encode("utf-8", "replace")[:900])
    except OSError:
        pass

known = set(); n = 0; parent_gone = False
try:
    while True:
        r, _, _ = select.select([pfd], [], [], tick)
        if r:
            try:
                if os.read(pfd, 1) == b"":
                    parent_gone = True
            except OSError:
                parent_gone = True
        if parent_gone:
            kill_all(known)           # runner is gone or released the fixture: nothing may survive it
            break
        if n % 5 == 0:
            known = tree()
            if not known:
                break                 # fixture tree is gone
        else:
            known = {p for p in known if os.path.exists("/proc/%d" % p)}
        n += 1
        total = sum(rss(p) for p in known)
        if total > limit:
            report("memory", "%s (pid %d) resident %d MiB exceeded the ceiling of %d MiB across %d process(es)"
                   % (name, pid, total >> 20, limit >> 20, len(known)))
            kill_all(known); break
        if time.monotonic() > deadline:
            report("lifetime", "%s (pid %d) outlived its maximum lifetime and was killed" % (name, pid))
            kill_all(known); break
except BaseException:
    kill_all(known)                   # fail closed
    raise
'''


# ---------------------------------------------------------------------------------------- launcher thread
class _LauncherThread:
    """One long-lived thread performs every fork so PDEATHSIG is tied to the process lifetime."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._q: "queue.Queue[Any]" = queue.Queue()
        self._thread: Optional[threading.Thread] = None

    def reset_after_fork(self) -> None:
        self._lock = threading.Lock()
        self._q = queue.Queue()
        self._thread = None

    def _run(self) -> None:
        while True:
            fn, fut = self._q.get()
            try:
                fut.set_result(fn())
            except BaseException as exc:  # noqa: BLE001 - re-raised in the caller
                fut.set_exception(exc)

    def call(self, fn):
        with self._lock:
            if self._thread is None or not self._thread.is_alive():
                self._thread = threading.Thread(target=self._run, name="fixture-launcher", daemon=True)
                self._thread.start()
        if threading.current_thread() is self._thread:
            return fn()
        fut: "concurrent.futures.Future[Any]" = concurrent.futures.Future()
        self._q.put((fn, fut))
        return fut.result()


_LAUNCHER = _LauncherThread()
_REGISTRY: Dict[int, "FixtureProcess"] = {}
_REG_LOCK = threading.Lock()
_HOOKS_INSTALLED = False
_SIGNALS_INSTALLED = False


def _after_fork_in_child() -> None:
    global _REG_LOCK
    _LAUNCHER.reset_after_fork()
    _REG_LOCK = threading.Lock()
    _REGISTRY.clear()


os.register_at_fork(after_in_child=_after_fork_in_child)


def _child_setup(parent_pid: int, user_preexec) -> None:
    # Runs in the forked child before exec: keep it tiny.
    if _prctl is not None:
        _prctl(_PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0)
        if os.getppid() != parent_pid:  # the parent already died before the prctl took effect
            os._exit(1)
    if user_preexec is not None:
        user_preexec()


def _exe_basename(args: Any) -> str:
    exe = args if isinstance(args, (str, bytes, os.PathLike)) else (args[0] if args else "")
    return os.path.basename(os.fsdecode(exe)) if exe else "?"


def _resolve_limits(args: Any, max_rss_mib: Optional[float], max_lifetime_s: Optional[float]) -> Tuple[float, float]:
    if max_rss_mib is None:
        env = os.environ.get("DYNAMICSTATE_FIXTURE_MAX_RSS_MIB")
        if env:
            max_rss_mib = float(env)
        else:
            max_rss_mib = FIXTURE_RSS_OVERRIDES_MIB.get(_exe_basename(args), DEFAULT_MAX_RSS_MIB)
    if max_lifetime_s is None:
        env = os.environ.get("DYNAMICSTATE_FIXTURE_MAX_LIFETIME_S")
        max_lifetime_s = float(env) if env else DEFAULT_MAX_LIFETIME_S
    return float(max_rss_mib), float(max_lifetime_s)


class FixtureProcess(subprocess.Popen):
    """``subprocess.Popen`` plus containment.  Construct with :func:`fixture_popen`."""

    _fx_released = False
    _fx_violation: Optional[FixtureLimitExceeded] = None
    _fx_hold: Optional[int] = None
    _fx_res: Optional[int] = None
    _fx_wd: Optional[Any] = None

    def __init__(self, args, *, max_rss_mib=None, max_lifetime_s=None, name=None, own_session=True, **kw):
        user_preexec = kw.pop("preexec_fn", None)
        if kw.pop("start_new_session", True) is False:   # explicit opt-out keeps the caller's session/group
            own_session = False
        self._fx_own = bool(own_session)
        kw.pop("process_group", None)
        self.max_rss_mib, self.max_lifetime_s = _resolve_limits(args, max_rss_mib, max_lifetime_s)
        self.fixture_name = name or _exe_basename(args)
        parent_pid = os.getpid()
        super().__init__(args, start_new_session=self._fx_own,
                         preexec_fn=lambda: _child_setup(parent_pid, user_preexec), **kw)
        with _REG_LOCK:
            _REGISTRY[self.pid] = self
        try:
            self._fx_start_watchdog()
        except BaseException:
            _kill_group(self.pid)
            raise

    def _fx_start_watchdog(self) -> None:
        pr, pw = os.pipe()          # runner-liveness pipe: the watchdog reads, we hold the write end
        rr, rw = os.pipe()          # report pipe: the watchdog writes, we read
        try:
            os.set_blocking(rr, False)
            cmd = [sys.executable, "-I", "-S", "-c", _WATCHDOG_SRC, str(self.pid), str(pr), str(rw),
                   str(int(self.max_rss_mib * 1048576)), repr(time.monotonic() + self.max_lifetime_s),
                   repr(WATCHDOG_TICK_S), self.fixture_name, "1" if self._fx_own else "0"]
            self._fx_wd = _REAL_POPEN(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                           stderr=subprocess.DEVNULL, pass_fds=(pr, rw),
                                           start_new_session=True)
        except BaseException:
            os.close(pw)
            os.close(rr)
            raise
        finally:
            os.close(pr)
            os.close(rw)
        self._fx_hold, self._fx_res = pw, rr

    # -- limit reporting ---------------------------------------------------------------------------
    def _fx_collect(self) -> None:
        if self._fx_violation is not None or self._fx_res is None:
            return
        try:
            data = os.read(self._fx_res, 4096)
        except OSError:
            return
        if data:
            kind, _, text = data.decode("utf-8", "replace").partition("\t")
            if kind == "memory":
                self._fx_violation = FixtureMemoryCeilingExceeded("fixture exceeded memory ceiling: " + text)
            else:
                self._fx_violation = FixtureLifetimeExceeded("fixture exceeded its lifetime limit: " + text)

    @property
    def violation(self) -> Optional[FixtureLimitExceeded]:
        self._fx_collect()
        return self._fx_violation

    def check(self) -> None:
        """Raise the distinct limit error if the watchdog killed this fixture."""
        v = self.violation
        if v is not None:
            raise v

    def _handle_exitstatus(self, *a, **kw):
        super()._handle_exitstatus(*a, **kw)
        self._fx_release()

    def _fx_release(self) -> None:
        if self._fx_released:
            return
        self._fx_collect()
        self._fx_released = True
        with _REG_LOCK:
            _REGISTRY.pop(self.pid, None)
        for attr in ("_fx_hold", "_fx_res"):
            fd = getattr(self, attr)
            if fd is not None:
                setattr(self, attr, None)
                with contextlib.suppress(OSError):
                    os.close(fd)   # closing the hold end tells the watchdog to sweep leftovers and exit
        wd = self._fx_wd
        if wd is not None:
            with contextlib.suppress(Exception):
                wd.wait(timeout=2)

    def poll(self):
        rc = super().poll()
        if rc is not None:
            self.check()
        return rc

    def wait(self, timeout=None):
        rc = super().wait(timeout)
        self.check()
        return rc

    def kill_tree(self) -> None:
        """SIGKILL the whole process group and reap the leader (never raises the limit error)."""
        _kill_group(self.pid)
        with contextlib.suppress(Exception):
            _REAL_POPEN.wait(self, timeout=10)


def _kill_group(pid: int) -> None:
    with contextlib.suppress(OSError):
        if os.getpgid(pid) == pid:   # never signal a group we do not own (own_session=False keeps the caller's)
            os.killpg(pid, signal.SIGKILL)
    with contextlib.suppress(OSError):
        os.kill(pid, signal.SIGKILL)


def fixture_popen(args, *, max_rss_mib: Optional[float] = None, max_lifetime_s: Optional[float] = None,
                  name: Optional[str] = None, own_session: bool = True, **kw) -> FixtureProcess:
    """Start a contained fixture; drop-in replacement for ``subprocess.Popen`` (same kwargs and object API)."""
    _install_hooks()
    return _LAUNCHER.call(lambda: FixtureProcess(args, max_rss_mib=max_rss_mib, max_lifetime_s=max_lifetime_s,
                                                 name=name, own_session=own_session, **kw))


@contextlib.contextmanager
def fixture_process(args, **kw) -> Iterator[FixtureProcess]:
    """``with fixture_process([binary], ...) as proc:`` -- always killed on exit; limit errors are raised."""
    proc = fixture_popen(args, **kw)
    try:
        yield proc
    finally:
        proc.kill_tree()
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            if stream is not None:
                with contextlib.suppress(Exception):
                    stream.close()
        proc.check()


# ------------------------------------------------------------------------------------------ runner sweep
def kill_all_fixtures() -> int:
    """Kill every fixture this runner started and has not reaped yet; returns how many were killed."""
    with _REG_LOCK:
        procs = list(_REGISTRY.values())
    for p in procs:
        _kill_group(p.pid)
    for p in procs:
        with contextlib.suppress(Exception):
            _REAL_POPEN.wait(p, timeout=5)
    return len(procs)


def _install_hooks() -> None:
    """atexit sweep (once) and signal handlers (from the main thread, as soon as a launch happens there)."""
    global _HOOKS_INSTALLED, _SIGNALS_INSTALLED
    if not _HOOKS_INSTALLED:
        _HOOKS_INSTALLED = True
        atexit.register(kill_all_fixtures)
    if _SIGNALS_INSTALLED or threading.current_thread() is not threading.main_thread():
        return  # handlers can only be set from the main thread; the other layers still apply
    _SIGNALS_INSTALLED = True
    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        try:
            previous = signal.getsignal(signum)
            if previous is signal.SIG_IGN:
                continue

            def handler(sig, frame, _prev=previous):
                kill_all_fixtures()
                if callable(_prev):
                    return _prev(sig, frame)
                signal.signal(sig, signal.SIG_DFL)
                os.kill(os.getpid(), sig)

            signal.signal(signum, handler)
        except (ValueError, OSError):
            pass


# ------------------------------------------------------------------------------------------------- CLI
def main(argv=None) -> int:
    """``python3 -m tests.support.fixture_process [--pidfile F] [limits] -- CMD ARGS...``

    For shell scripts: runs CMD contained (stdio inherited), writes the fixture's pid to ``--pidfile`` right
    after the start, exits with the fixture's status (128+N for a signal) or 97 when a limit killed it.
    """
    import argparse
    ap = argparse.ArgumentParser(prog="python3 -m tests.support.fixture_process")
    ap.add_argument("--pidfile")
    ap.add_argument("--max-rss-mib", type=float)
    ap.add_argument("--max-lifetime-s", type=float)
    ap.add_argument("cmd", nargs=argparse.REMAINDER)
    a = ap.parse_args(argv)
    cmd = a.cmd[1:] if a.cmd and a.cmd[0] == "--" else a.cmd
    if not cmd:
        ap.error("no command given")
    proc = fixture_popen(cmd, max_rss_mib=a.max_rss_mib, max_lifetime_s=a.max_lifetime_s)
    if a.pidfile:
        tmp = a.pidfile + ".tmp"
        with open(tmp, "w") as fh:
            fh.write(str(proc.pid))
        os.replace(tmp, a.pidfile)
    try:
        rc = proc.wait()
    except FixtureLimitExceeded as exc:
        print(f"fixture_process: {exc}", file=sys.stderr)
        return 97
    return rc if rc >= 0 else 128 - rc


if __name__ == "__main__":
    sys.exit(main())

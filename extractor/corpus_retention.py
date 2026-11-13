"""Retention for the *default* corpus directory (/tmp/dynamicstate_corpus) and a size cap for the DWARF disk cache.

Only the implicit default location is ever pruned: a corpus directory the caller passed explicitly (the web server's
--corpus, tests, benchmarks) is never touched.  Pruning unit = one direct child (file or directory) of
``investigations/``, ``reports/`` and ``watch_sessions/``; ``golden_baselines/`` is never pruned.  An entry modified
within the grace period is treated as in use (a running session rewrites its file) and is never removed.  Every
filesystem step tolerates entries that vanish concurrently (several processes share the default location).

Environment:
  DYNAMICSTATE_CORPUS_MAX_AGE_DAYS   default 7    entries older than this are removed (0 = no age limit)
  DYNAMICSTATE_CORPUS_MAX_MB         default 1024 total size cap, oldest entries removed first (0 = no size cap)
  DYNAMICSTATE_CORPUS_GRACE_SECONDS  default 3600 entries touched more recently than this are never removed
  DYNAMICSTATE_DWARF_CACHE_MAX_MB    default 512  DWARF cache cap, least recently used removed first (0 = no cap)
"""
import os
import shutil
import tempfile
import threading
import time
from typing import Iterable, List, Optional, Tuple

DEFAULT_CORPUS_NAME = "dynamicstate_corpus"
PRUNED_SUBDIRS = ("investigations", "reports", "watch_sessions")
DEFAULT_MAX_AGE_DAYS = 7.0
DEFAULT_MAX_MB = 1024.0
DEFAULT_GRACE_SECONDS = 3600.0
DEFAULT_DWARF_CACHE_MAX_MB = 512.0
_THROTTLE_SECONDS = 300.0

_last_run = {}  # type: dict
_last_run_lock = threading.Lock()


def default_corpus_dir() -> str:
    return os.path.join("/tmp", DEFAULT_CORPUS_NAME)


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, "")) if os.environ.get(name, "").strip() else default
    except ValueError:
        return default


def _entry_stat(path: str) -> Optional[Tuple[float, int]]:
    """(newest mtime, total bytes) of a file or directory tree, or None if it vanished."""
    try:
        st = os.lstat(path)
    except OSError:
        return None
    if not os.path.isdir(path) or os.path.islink(path):
        return st.st_mtime, st.st_size
    newest, total = st.st_mtime, 0
    for root, dirs, files in os.walk(path):
        for name in files + dirs:
            try:
                s = os.lstat(os.path.join(root, name))
            except OSError:
                continue
            newest = max(newest, s.st_mtime)
            total += s.st_size
    return newest, total


def _remove(path: str) -> None:
    try:
        if os.path.isdir(path) and not os.path.islink(path):
            shutil.rmtree(path, ignore_errors=True)
        else:
            os.unlink(path)
    except OSError:
        pass


def prune_corpus(corpus_dir: str, max_age_days: Optional[float] = None, max_mb: Optional[float] = None,
                 grace_seconds: Optional[float] = None, now: Optional[float] = None) -> List[str]:
    """Apply the retention policy to ``corpus_dir``; return the removed paths."""
    max_age_days = _env_float("DYNAMICSTATE_CORPUS_MAX_AGE_DAYS", DEFAULT_MAX_AGE_DAYS) if max_age_days is None else max_age_days
    max_mb = _env_float("DYNAMICSTATE_CORPUS_MAX_MB", DEFAULT_MAX_MB) if max_mb is None else max_mb
    grace = _env_float("DYNAMICSTATE_CORPUS_GRACE_SECONDS", DEFAULT_GRACE_SECONDS) if grace_seconds is None else grace_seconds
    now = time.time() if now is None else now
    entries = []  # (mtime, size, path)
    for sub in PRUNED_SUBDIRS:
        base = os.path.join(corpus_dir, sub)
        try:
            names = os.listdir(base)
        except OSError:
            continue
        for name in names:
            path = os.path.join(base, name)
            info = _entry_stat(path)
            if info is not None:
                entries.append((info[0], info[1], path))
    entries.sort()
    removed = []  # type: List[str]
    keep = []
    for mtime, size, path in entries:
        if now - mtime < grace:
            keep.append((mtime, size, path))
        elif max_age_days > 0 and now - mtime > max_age_days * 86400.0:
            _remove(path)
            removed.append(path)
        else:
            keep.append((mtime, size, path))
    if max_mb > 0:
        total = sum(s for _, s, _ in keep)
        limit = int(max_mb * 1024 * 1024)
        for mtime, size, path in keep:  # oldest first
            if total <= limit:
                break
            if now - mtime < grace:
                continue
            _remove(path)
            removed.append(path)
            total -= size
    return removed


def resolve_corpus_dir(corpus_dir: Optional[str]) -> str:
    """The constructor helper: explicit dirs are returned untouched; the default dir is pruned (throttled)."""
    if corpus_dir:
        return corpus_dir
    default = default_corpus_dir()
    now = time.monotonic()
    with _last_run_lock:
        if now - _last_run.get(default, -1e9) < _THROTTLE_SECONDS:
            return default
        _last_run[default] = now
    try:
        prune_corpus(default)
    except Exception:  # noqa: BLE001 - retention is housekeeping; it must never fail a diagnosis
        pass
    return default


def prune_cache_dir(cache_dir: str, max_mb: Optional[float] = None, protect: Iterable[str] = (),
                    now: Optional[float] = None) -> List[str]:
    """Keep the DWARF cache under ``max_mb``: remove least recently used ``dwarf_idx_*.json`` first.

    ``dw_*.tmp`` files are in-progress writes of other processes: never removed unless stale (older than one hour,
    i.e. left behind by a crashed writer).  Readers touch an entry on hit, so mtime is the recency.
    """
    max_mb = _env_float("DYNAMICSTATE_DWARF_CACHE_MAX_MB", DEFAULT_DWARF_CACHE_MAX_MB) if max_mb is None else max_mb
    now = time.time() if now is None else now
    protected = {os.path.abspath(p) for p in protect}
    try:
        names = os.listdir(cache_dir)
    except OSError:
        return []
    removed = []  # type: List[str]
    files = []
    for name in names:
        path = os.path.join(cache_dir, name)
        try:
            st = os.stat(path)
        except OSError:
            continue
        if name.startswith("dw_") and name.endswith(".tmp"):
            if now - st.st_mtime > 3600:
                _remove(path)
                removed.append(path)
            continue
        if name.startswith("dwarf_idx_") and name.endswith(".json"):
            files.append((st.st_mtime, st.st_size, path))
    if max_mb <= 0:
        return removed
    files.sort()
    total = sum(s for _, s, _ in files)
    limit = int(max_mb * 1024 * 1024)
    for mtime, size, path in files:
        if total <= limit:
            break
        if os.path.abspath(path) in protected:
            continue
        _remove(path)
        removed.append(path)
        total -= size
    return removed

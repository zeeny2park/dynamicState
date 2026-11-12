"""IMP-011: ELF images of a remote target's modules for the CFI unwinder (.eh_frame / symbols).

The unwinder needs the bytes of every executable module a stack passes through.  On a remote target they
are not on the host:

* the main executable is the companion/debug image the user already supplied;
* shared libraries (the libc wait wrappers are the first frames of every blocked thread) are fetched once
  through ``adapter.read_target_file`` and cached in a private temp directory.

Cache key: (target host, path, size, mtime) -- size/mtime come from ``adapter.stat_target_file`` (one cheap
exchange, re-checked at most every ``REVALIDATE_SEC``); where the target cannot report them the size of the
fetched bytes is used.  Images larger than ``DEFAULT_MAX_IMAGE_BYTES`` (env ``DYNAMICSTATE_REMOTE_IMAGE_MAX_BYTES``)
and images that cannot be fetched are NOT guessed: the resolver returns ``None`` and the unwinder then stops at
that frame and labels the rest of the stack as estimated (exactly as for an unreadable local image).
"""

from __future__ import annotations

import atexit
import os
import shutil
import tempfile
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

DEFAULT_MAX_IMAGE_BYTES = 32 * 1024 * 1024
REVALIDATE_SEC = 30.0

_LOCK = threading.Lock()
_DIR: Optional[str] = None
# (host, path) -> (size, mtime, local_path or None (known unusable), checked_at_monotonic)
_CACHE: Dict[Tuple[str, str], Tuple[Optional[int], Optional[int], Optional[str], float]] = {}


def _cache_dir() -> str:
    global _DIR
    if _DIR is None or not os.path.isdir(_DIR):
        _DIR = tempfile.mkdtemp(prefix="dynstate_remote_images_")
        atexit.register(shutil.rmtree, _DIR, True)
    return _DIR


def clear_cache() -> None:
    with _LOCK:
        _CACHE.clear()


def max_image_bytes() -> int:
    try:
        return max(1, int(os.environ.get("DYNAMICSTATE_REMOTE_IMAGE_MAX_BYTES", DEFAULT_MAX_IMAGE_BYTES)))
    except ValueError:
        return DEFAULT_MAX_IMAGE_BYTES


class RemoteImageResolver:
    """Callable ``remote_path -> local file path | None`` for ``CfiUnwinder`` (``image_provider``)."""

    def __init__(self, adapter: Any, pid: int, main_remote_path: Optional[str], main_local_image: Optional[str],
                 max_bytes: Optional[int] = None, clock: Callable[[], float] = time.monotonic):
        self.adapter = adapter
        self.pid = int(pid)
        self.main_remote_path = main_remote_path
        self.main_local_image = main_local_image
        self.max_bytes = int(max_bytes) if max_bytes else max_image_bytes()
        self._clock = clock
        self.fetches: List[str] = []          # remote paths fetched by this resolver (observability / tests)
        self.skipped: Dict[str, str] = {}     # remote path -> reason it could not be used

    def __call__(self, path: str) -> Optional[str]:
        if self.main_remote_path and path == self.main_remote_path:
            return self.main_local_image if self.main_local_image and os.path.isfile(self.main_local_image) else None
        host = ""
        try:
            host = str(self.adapter.target_host())
        except Exception:  # noqa: BLE001
            pass
        key = (host, path)
        now = self._clock()
        with _LOCK:
            hit = _CACHE.get(key)
        stat: Optional[Tuple[int, int]] = None
        if hit is not None and (now - hit[3]) <= REVALIDATE_SEC:
            return self._usable(path, hit[2])
        stat_fn = getattr(self.adapter, "stat_target_file", None)
        if callable(stat_fn):
            try:
                stat = stat_fn(self.pid, path)
            except Exception:  # noqa: BLE001
                stat = None
        if hit is not None and stat is not None and (hit[0], hit[1]) == (stat[0], stat[1]):
            with _LOCK:
                _CACHE[key] = (hit[0], hit[1], hit[2], now)
            return self._usable(path, hit[2])
        if stat is not None and stat[0] > self.max_bytes:
            return self._remember(key, stat, None, now, f"image is {stat[0]} bytes, above the {self.max_bytes} byte cap")
        try:
            data = self.adapter.read_target_file(self.pid, path, self.max_bytes + 1)
        except Exception as exc:  # noqa: BLE001
            data = None
            self.skipped[path] = f"fetch failed: {type(exc).__name__}"
        if not data:
            return self._remember(key, stat, None, now, self.skipped.get(path) or "could not be read from the target")
        if len(data) > self.max_bytes:
            return self._remember(key, stat, None, now, f"image exceeds the {self.max_bytes} byte cap")
        if data[:4] != b"\x7fELF":
            return self._remember(key, stat, None, now, "fetched bytes are not an ELF image")
        if stat is not None and stat[0] != len(data):
            return self._remember(key, stat, None, now, f"fetched {len(data)} bytes, target reports {stat[0]} (truncated)")
        fd, local = tempfile.mkstemp(prefix="img_", suffix=".so", dir=_cache_dir())
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        self.fetches.append(path)
        size = stat[0] if stat is not None else len(data)
        mtime = stat[1] if stat is not None else None
        self._remember(key, (size, mtime if mtime is not None else 0), local, now, None)
        return local

    def _usable(self, path: str, local: Optional[str]) -> Optional[str]:
        if local is not None and os.path.isfile(local):
            return local
        if local is None:
            self.skipped.setdefault(path, "previously unavailable")
        return None

    def _remember(self, key: Tuple[str, str], stat: Optional[Tuple[int, int]], local: Optional[str],
                  now: float, why: Optional[str]) -> Optional[str]:
        if why:
            self.skipped[key[1]] = why
        with _LOCK:
            _CACHE[key] = (stat[0] if stat else None, stat[1] if stat else None, local, now)
        return local


def find_main_remote_path(mappings: Sequence[Dict[str, Any]], main_module_name: Optional[str]) -> Optional[str]:
    """Target-side path of the main executable: the file mapping whose basename is the main module name."""
    if not main_module_name:
        return None
    for m in mappings:
        p = (m.get("pathname") or "")
        if p.startswith("/") and os.path.basename(p) == main_module_name:
            return p
    return None

"""Environment sanitising for launching the system GDB.

``actions/setup-python`` (and similar relocatable Python distributions) export
``LD_LIBRARY_PATH``/``PYTHONHOME``/``PYTHONPATH`` pointing into a tool cache such as
``/opt/hostedtoolcache/Python/3.10.x/x64``.  The system ``/usr/bin/gdb`` is linked against the
distro ``libpython3.x``; with that variable inherited the dynamic loader picks the tool-cache
libpython instead, which is built without the modules Debian/Ubuntu compile in (``math``,
``_posixsubprocess``, ...), while GDB still points it at the distro stdlib.  GDB's embedded Python
then fails with ``ModuleNotFoundError: No module named 'math'``.

``gdb_subprocess_env()`` returns a copy of the environment with only the tool-cache specific
entries removed; everything else is preserved.
"""

import os
from typing import Dict, Mapping, Optional

_TOOLCACHE_MARKERS = ("/hostedtoolcache/", "/_work/_tool/", "/_work/_temp/")
_PATH_LIST_VARS = ("LD_LIBRARY_PATH", "LIBRARY_PATH", "PYTHONPATH")
_SINGLE_PATH_VARS = ("PYTHONHOME",)


def _toolcache_roots(env: Mapping[str, str]):
    roots = []
    for key in ("RUNNER_TOOL_CACHE", "AGENT_TOOLSDIRECTORY"):
        val = env.get(key)
        if val:
            roots.append(os.path.normpath(val) + os.sep)
    return roots


def _in_toolcache(path: str, roots) -> bool:
    norm = os.path.normpath(path) + os.sep
    return any(m in norm for m in _TOOLCACHE_MARKERS) or any(norm.startswith(r) for r in roots)


def gdb_subprocess_env(base: Optional[Mapping[str, str]] = None) -> Dict[str, str]:
    """Return ``base`` (default ``os.environ``) minus tool-cache Python entries (see module doc)."""
    env = dict(os.environ if base is None else base)
    roots = _toolcache_roots(env)
    for var in _PATH_LIST_VARS:
        if var in env:
            kept = [p for p in env[var].split(os.pathsep) if p and not _in_toolcache(p, roots)]
            if kept:
                env[var] = os.pathsep.join(kept)
            else:
                del env[var]
    for var in _SINGLE_PATH_VARS:
        if var in env and _in_toolcache(env[var], roots):
            del env[var]
    return env

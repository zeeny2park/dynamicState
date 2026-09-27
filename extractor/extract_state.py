"""Composition root for GDB command and future runtime backends."""

from .execution import GdbBackend
from .serializer import to_json


def snapshot(gdb_module, max_depth=None, include_globals=True):
    return GdbBackend(gdb_module).snapshot(max_depth=max_depth, include_globals=include_globals)


def snapshot_json(gdb_module, max_depth=None, include_globals=True):
    return to_json(snapshot(gdb_module, max_depth=max_depth, include_globals=include_globals))

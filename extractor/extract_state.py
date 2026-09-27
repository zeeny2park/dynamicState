"""Composition root for GDB command and future runtime backends."""

from .execution import GdbBackend
from .serializer import to_json


def snapshot(gdb_module, max_depth=None, include_globals=True, debug_image=None):
    from .debug_image import DebugImageProvider
    provider = None
    if debug_image:
        provider = DebugImageProvider(debug_image)
        backend = GdbBackend(gdb_module, debug_image_provider=provider)
        pinfo = backend.process_info()
        runtime_bin = pinfo.get("binary")
        if runtime_bin:
            compat = provider.verify(runtime_bin)
            if not compat.compatible:
                raise RuntimeError("DEBUG_IMAGE_INCOMPATIBLE: {}".format(compat.reason))
        gdb_module.execute("set confirm off")
        gdb_module.execute("symbol-file {}".format(debug_image))
    else:
        backend = GdbBackend(gdb_module)
    return backend.snapshot(max_depth=max_depth, include_globals=include_globals)


def snapshot_json(gdb_module, max_depth=None, include_globals=True, debug_image=None):
    return to_json(snapshot(gdb_module, max_depth=max_depth, include_globals=include_globals, debug_image=debug_image))


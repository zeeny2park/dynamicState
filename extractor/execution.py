"""Runtime backend interface and GDB implementation."""

import time

from .runtime_state import ExecutionState, FrameState, ThreadState


class RuntimeBackend:
    """Minimal extension point; Phase 1 implements snapshot only."""
    def snapshot(self):  # pragma: no cover - interface
        raise NotImplementedError


class GdbBackend(RuntimeBackend):
    def __init__(self, gdb_module, debug_image_provider=None):
        self.gdb = gdb_module
        self.debug_image_provider = debug_image_provider
        self.runtime_binary_path = None

    def process_info(self):
        inferior = self.gdb.selected_inferior()
        pid = getattr(inferior, "pid", 0) or None
        binary = None
        if pid:
            import os
            proc_exe = "/proc/{}/exe".format(pid)
            if os.path.exists(proc_exe):
                try:
                    binary = os.path.realpath(proc_exe)
                except Exception:
                    pass
        if not binary and getattr(self, "runtime_binary_path", None):
            binary = self.runtime_binary_path
        if not binary:
            try:
                binary = self.gdb.current_progspace().filename
            except Exception:
                pass
        return {"pid": pid, "binary": binary}

    def snapshot(self, max_depth=None, include_globals=True):
        # Imports stay local to avoid making the backend interface depend on
        # graph construction at module-import time.
        from .object_graph import ObjectGraphBuilder
        from .runtime_state import PersistentState, RuntimeState
        from .type_resolver import TypeResolver
        from .memory_maps import MemoryMapProvider
        process = self.process_info()
        graph = ObjectGraphBuilder(self, TypeResolver(self.gdb), max_object_depth=max_depth,
                                    memory_maps=MemoryMapProvider(process["pid"], process["binary"]))
        traversal_start = time.monotonic()
        execution = self.execution(graph)
        traversal_ms = (time.monotonic() - traversal_start) * 1000
        roots_start = time.monotonic()
        if include_globals:
            self.global_roots(graph)
        roots_ms = (time.monotonic() - roots_start) * 1000

        # Provenance and debug image performance
        provenance = None
        load_ms = 0.0
        id_ms = 0.0
        verify_ms = 0.0
        if self.debug_image_provider:
            if not self.debug_image_provider.runtime_identity and process.get("binary"):
                self.debug_image_provider.verify(process["binary"])
            provenance = self.debug_image_provider.get_provenance()
            load_ms = self.debug_image_provider.load_ms
            id_ms = self.debug_image_provider.identity_check_ms
            verify_ms = self.debug_image_provider.verification_ms
        elif process.get("binary"):
            try:
                from .debug_image import inspect_elf, DebugImageProvider
                import os
                progspace_fn = None
                try:
                    progspace_fn = self.gdb.current_progspace().filename
                except Exception:
                    pass

                # If progspace filename is different from running process binary,
                # an external debug image / symbol file was loaded in GDB
                if (progspace_fn and os.path.exists(progspace_fn) and
                        os.path.realpath(progspace_fn) != os.path.realpath(process["binary"])):
                    provider = DebugImageProvider(progspace_fn)
                    provider.verify(process["binary"])
                    self.debug_image_provider = provider
                    provenance = provider.get_provenance()
                    load_ms = provider.load_ms
                    id_ms = provider.identity_check_ms
                    verify_ms = provider.verification_ms
                else:
                    t_check = time.monotonic()
                    r_ident = inspect_elf(process["binary"])
                    id_ms = round((time.monotonic() - t_check) * 1000, 3)
                    provenance = {
                        "runtime_binary": {
                            "path": r_ident.path,
                            "build_id": r_ident.build_id,
                            "architecture": r_ident.architecture,
                            "elf_class": r_ident.elf_class,
                            "endianness": r_ident.endianness,
                            "stripped": r_ident.stripped,
                        },
                        "debug_image": {
                            "path": r_ident.path,
                            "build_id": r_ident.build_id,
                            "architecture": r_ident.architecture,
                            "elf_class": r_ident.elf_class,
                            "endianness": r_ident.endianness,
                            "source": "embedded",
                            "verified": True,
                            "compatible": True,
                            "reason": "EMBEDDED_DEBUG_INFO" if r_ident.has_debug_info else "STRIPPED_NO_DEBUG_IMAGE",
                        },
                        "performance": {
                            "debug_image_load_ms": 0.0,
                            "binary_identity_check_ms": id_ms,
                            "debug_image_verification_ms": 0.0,
                        },
                    }
            except Exception:
                provenance = None

        perf_stats = {
            "root_discovery_ms": round(roots_ms, 3),
            "traversal_ms": round(traversal_ms, 3),
            "objects_per_second": round(
                len(graph.objects) / max(traversal_ms / 1000.0, 0.000001), 3
            ),
            "debug_image_load_ms": load_ms,
            "binary_identity_check_ms": id_ms,
            "debug_image_verification_ms": verify_ms,
        }

        persistent = PersistentState(roots=graph.roots, objects=graph.objects,
            statistics={"root_count": len(graph.roots), "object_count": len(graph.objects),
                        "edge_count": sum(1 for obj in graph.objects for field in obj.fields if field.object_ref),
                        "heap_objects": self._storage_count(graph.objects, "heap"),
                        "stack_objects": self._storage_count(graph.objects, "stack"),
                        "global_objects": self._storage_count(graph.objects, "global"),
                        "unknown_objects": self._storage_count(graph.objects, "unknown"),
                        "max_depth_reached": graph.max_depth_reached,
                        "cycles_detected": graph.cycles_detected,
                        "unreadable_objects": graph.unreadable_objects,
                        "performance": perf_stats,
                        "storage": self._storage_statistics(graph.objects)})
        # ``objects`` remains as a Phase-1-compatible alias.
        return RuntimeState(schema_version="0.2", process=process, execution=execution,
                            objects=graph.objects, persistent=persistent, provenance=provenance)

    @staticmethod
    def _storage_statistics(objects):
        result = {}
        for obj in objects:
            result[obj.storage] = result.get(obj.storage, 0) + 1
        return result

    @staticmethod
    def _storage_count(objects, storage):
        return sum(1 for obj in objects if obj.storage == storage)

    def thread_id(self, thread):
        return getattr(thread, "global_num", None) or getattr(thread, "num", 0)

    def frames(self, thread, graph):
        thread.switch()
        frames = []
        frame = self.gdb.newest_frame()
        while frame is not None:
            state = FrameState(level=frame.level(), function=frame.name(),
                               pc=self.format_address(frame.pc()))
            for symbol in self._symbols(frame):
                name = getattr(symbol, "print_name", None) or getattr(symbol, "name", None)
                if not name:
                    continue
                try:
                    value = frame.read_var(symbol)
                    context = {"thread_id": self.thread_id(thread), "frame_level": frame.level()}
                    variable = graph.variable(name, value, storage="stack", context=context)
                except Exception as exc:
                    variable = graph.variable_unavailable(name, symbol, exc) if hasattr(graph, "variable_unavailable") else None
                    if variable is None:
                        from .runtime_state import VariableState
                        variable = VariableState(name=name, type=str(getattr(symbol, "type", "<unknown>")),
                                                 value=None, availability=self.availability(exc), error=str(exc))
                if getattr(symbol, "is_argument", False):
                    state.arguments[name] = variable
                elif getattr(symbol, "is_variable", False):
                    state.locals[name] = variable
                if variable.object_ref:
                    graph.add_root(name, "frame", variable, thread_id=self.thread_id(thread),
                                   frame_level=frame.level(), function=frame.name())
            frames.append(state)
            frame = frame.older()
        return frames

    def execution(self, graph):
        threads = []
        for thread in self.gdb.selected_inferior().threads():
            try:
                threads.append(ThreadState(thread_id=self.thread_id(thread), frames=self.frames(thread, graph)))
            except Exception as exc:
                # A thread can disappear while inspected; retain a valid snapshot.
                threads.append(ThreadState(thread_id=self.thread_id(thread), frames=[]))
        return ExecutionState(threads=threads)

    def global_roots(self, graph):
        """Discover symbols exposed by GDB's global and static DWARF blocks."""
        seen = set()
        for thread in self.gdb.selected_inferior().threads():
            try:
                thread.switch()
                frame = self.gdb.newest_frame()
                if frame is None:
                    continue
                block = frame.block()
                blocks = (block.global_block, block.static_block)
                for root_block in blocks:
                    for symbol in root_block:
                        name = getattr(symbol, "print_name", None) or getattr(symbol, "name", None)
                        key = (name, str(getattr(symbol, "type", "")))
                        if not name or key in seen or not getattr(symbol, "is_variable", False):
                            continue
                        seen.add(key)
                        try:
                            value = frame.read_var(symbol)
                            variable = graph.variable(name, value, storage="global")
                            if variable.object_ref:
                                graph.add_root(name, "global", variable)
                        except Exception:
                            # A symbol can be present but unavailable in this inferior.
                            continue
            except Exception:
                continue

    def _symbols(self, frame):
        block = frame.block()
        seen = set()
        while block is not None:
            for symbol in block:
                name = getattr(symbol, "print_name", None) or getattr(symbol, "name", None)
                if name and name not in seen and (getattr(symbol, "is_argument", False) or getattr(symbol, "is_variable", False)):
                    seen.add(name)
                    yield symbol
            # Do not leak file/global symbols into a frame's locals. The
            # function block is the outermost block that still belongs to this
            # frame; its parent is normally the global block.
            if getattr(block, "function", None) is not None:
                break
            block = block.superblock

    def value_type(self, value):
        return value.type

    def format_address(self, address):
        return None if address is None else "0x{:x}".format(int(address))

    def value_address(self, value):
        try:
            return self.format_address(value.address)
        except Exception:
            return None

    def object_address(self, value):
        # Dereferenced pointers generally have an lvalue address; use it for identity.
        return self.value_address(value)

    def primitive_value(self, value, kind):
        if kind == "primitive":
            try:
                code = getattr(value.type.strip_typedefs(), "code", None)
                if code == getattr(self.gdb, "TYPE_CODE_FLT", None):
                    return float(value)
                return int(value)
            except Exception:
                try:
                    return float(value)
                except Exception:
                    return str(value)
        if kind == "enum":
            return str(value)
        return str(value) if kind not in ("aggregate", "pointer", "reference") else None

    def pointer_text(self, value):
        try:
            return self.format_address(int(value))
        except Exception:
            return str(value)

    def dereference(self, value):
        try:
            if int(value) == 0:
                return None, None
            return value.dereference(), None
        except Exception as exc:
            return None, "unreadable: {}".format(exc)

    def fields(self, value):
        value_type = value.type.strip_typedefs()
        for field in value_type.fields():
            if getattr(field, "is_base_class", False):
                yield {"name": getattr(field, "name", "<base>"), "is_base_class": True}
                continue
            name = field.name
            offset = None
            try:
                offset = int(field.bitpos) // 8
            except Exception:
                pass
            yield {"name": name, "type": str(field.type), "offset": offset, "value": value[name]}

    @staticmethod
    def availability(exc):
        text = str(exc).lower()
        return "optimized_out" if "optimized out" in text else "unavailable"

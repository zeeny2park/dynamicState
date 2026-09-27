"""Deterministic runtime API; GDB-specific mutation remains in this adapter."""

import json
import math
import os
import re
import threading
import time
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional

from .execution import GdbBackend
from .mutation import MutationResult, mutation_error
from .snapshot import RuntimeSnapshot
from .state_diff import StateDiffEngine
from .type_resolver import TypeResolver


@dataclass
class ExecutionResult:
    status: str
    reason: Optional[str] = None
    signal: Optional[str] = None
    exit_code: Optional[int] = None
    error: Optional[Dict[str, str]] = None
    performance: Optional[Dict[str, float]] = None

    def to_dict(self):
        return asdict(self)


@dataclass
class RuntimeCapabilities:
    checkpoint: bool = True
    restore: bool = True
    typed_mutation: bool = True
    semantic_snapshot: bool = True
    semantic_diff: bool = True
    state_hash: bool = True
    branch_exploration: bool = True
    crash_recovery: bool = True
    timeout_recovery: bool = True
    external_debug_image: bool = True
    multi_thread_determinism: bool = False
    external_io_rollback: bool = False
    exploration_mode: str = "deterministic_single_thread_context"
    backend: str = "generic"
    observation: Optional[Dict[str, bool]] = None
    memory_snapshot: Optional[Dict[str, bool]] = None

    def __post_init__(self):
        import platform
        has_vm_readv = (platform.system() == "Linux")
        if self.observation is None:
            self.observation = {
                "gdb_consistent": True,
                "low_impact_memory_snapshot": has_vm_readv,
                "offline_semantic_analysis": True,
            }
        if self.memory_snapshot is None:
            self.memory_snapshot = {
                "process_vm_readv": has_vm_readv,
                "partial_read": True,
                "stack": True,
                "heap": True,
                "global": True,
                "all_readable": True,
            }

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RuntimeController:
    def observe(self):
        raise NotImplementedError

    def snapshot(self, snapshot_id=None, output=None):
        raise NotImplementedError

    def get_object(self, object_id):
        raise NotImplementedError

    def get_field(self, object_id, field):
        raise NotImplementedError

    def mutate(self, object_id, field_path, value):
        raise NotImplementedError

    def continue_execution(self, timeout_ms=1000):
        raise NotImplementedError

    def diff(self, before, after):
        raise NotImplementedError

    def execute_transition(self, object_id=None, field_path=None, value=None, path=None,
                           timeout_ms=1000, transition_id=None, output=None):
        raise NotImplementedError

    def checkpoint(self, checkpoint_id=None):
        if not hasattr(self, "_default_restorer"):
            from .state_restorer import MockStateRestorer
            self._default_restorer = MockStateRestorer()
        return self._default_restorer.checkpoint(checkpoint_id=checkpoint_id)

    def restore(self, checkpoint):
        if hasattr(self, "_default_restorer"):
            self._default_restorer.restore(checkpoint)

    def release_checkpoint(self, checkpoint):
        if hasattr(self, "_default_restorer"):
            self._default_restorer.release(checkpoint)

    def execute_transition_from_checkpoint(self, checkpoint, candidate, timeout_ms=1000):
        self.restore(checkpoint)
        cand_obj = candidate.object_id if hasattr(candidate, "object_id") else candidate.get("object_id")
        cand_field = candidate.field_path if hasattr(candidate, "field_path") else candidate.get("field_path")
        cand_val = candidate.proposed_value if hasattr(candidate, "proposed_value") else candidate.get("proposed_value")
        return self.execute_transition(
            object_id=cand_obj,
            field_path=cand_field,
            value=cand_val,
            timeout_ms=timeout_ms
        )

    def get_capabilities(self) -> Dict[str, Any]:
        return RuntimeCapabilities().to_dict()

    def get_type_info(self, type_name: str) -> Optional[Any]:
        return None

    def get_enum_members(self, type_name: str):
        return []

    def get_integer_range(self, type_name: str):
        return None

    def propose_mutations(self, snapshot=None):
        raise NotImplementedError

    def explore(self, max_steps=10, timeout_ms=1000, corpus_dir="corpus"):
        raise NotImplementedError

    def load_debug_image(self, path: str):
        pass

    def runtime_info(self) -> Dict[str, Any]:
        return {}

    def attach(self, pid: int, debug_image: Optional[str] = None):
        pass


class GdbRuntimeController(RuntimeController):
    def __init__(self, gdb_module, debug_image_provider=None):
        self.gdb = gdb_module
        self.debug_image_provider = debug_image_provider
        self.backend = GdbBackend(gdb_module, debug_image_provider=debug_image_provider)
        self.types = TypeResolver(gdb_module)
        from .state_restorer import GdbCheckpointRestorer
        self.restorer = GdbCheckpointRestorer(gdb_module)
        self.snapshots: Dict[str, RuntimeSnapshot] = {}
        self._counter = 0
        self._transition_counter = 0
        self._latest: Optional[RuntimeSnapshot] = None
        self._last_mutation: Optional[MutationResult] = None
        self._last_execution: Optional[ExecutionResult] = None

    def load_debug_image(self, path: str):
        from .debug_image import DebugImageProvider
        provider = DebugImageProvider(path)
        pinfo = self.backend.process_info()
        runtime_bin = pinfo.get("binary")
        if runtime_bin:
            compat = provider.verify(runtime_bin)
            if not compat.compatible:
                raise RuntimeError("DEBUG_IMAGE_INCOMPATIBLE: {}".format(compat.reason))
        else:
            if not provider.debug_identity:
                raise RuntimeError("DEBUG_IMAGE_INVALID: failed to load debug image")

        if runtime_bin:
            self.backend.runtime_binary_path = runtime_bin

        # Register build-id in shadow debug directory so GDB locates separate debug file natively
        if provider.debug_identity and provider.debug_identity.build_id:
            bid = provider.debug_identity.build_id
            shadow_dir = "/tmp/.dynamicstate_debug"
            link_dir = os.path.join(shadow_dir, ".build-id", bid[:2])
            os.makedirs(link_dir, exist_ok=True)
            link_file = os.path.join(link_dir, bid[2:] + ".debug")
            if os.path.exists(link_file) or os.path.islink(link_file):
                try:
                    os.unlink(link_file)
                except Exception:
                    pass
            try:
                os.symlink(os.path.abspath(path), link_file)
            except Exception:
                pass
            try:
                cur = self.gdb.parameter("debug-file-directory") or ""
                if shadow_dir not in cur:
                    new_val = "{}:{}".format(shadow_dir, cur) if cur else shadow_dir
                    self.gdb.execute("set debug-file-directory {}".format(new_val))
            except Exception:
                pass

        try:
            self.gdb.execute("set confirm off")
            if not self._is_stopped() and runtime_bin:
                self.gdb.execute("file {}".format(runtime_bin))
            else:
                self.gdb.execute("symbol-file {}".format(path))
        except Exception as exc:
            raise RuntimeError("GDB_SYMBOL_FILE_FAILED: {}".format(exc))

        self.debug_image_provider = provider
        self.backend.debug_image_provider = provider
        return provider.compatibility or (provider.verify(runtime_bin) if runtime_bin else None)

    def runtime_info(self) -> Dict[str, Any]:
        pinfo = self.backend.process_info()
        r_bin = pinfo.get("binary")
        r_ident = None
        if r_bin:
            try:
                from .debug_image import inspect_elf
                r_ident = inspect_elf(r_bin).to_dict()
            except Exception:
                r_ident = {"path": r_bin}

        debug_ident = None
        if self.debug_image_provider and self.debug_image_provider.debug_identity:
            debug_ident = self.debug_image_provider.debug_identity.to_dict()
            debug_ident["source"] = "external"
            debug_ident["verified"] = bool(self.debug_image_provider.compatibility and self.debug_image_provider.compatibility.compatible)
            debug_ident["compatible"] = bool(self.debug_image_provider.compatibility and self.debug_image_provider.compatibility.compatible)
            debug_ident["reason"] = self.debug_image_provider.compatibility.reason if self.debug_image_provider.compatibility else None
        else:
            progspace_fn = None
            try:
                progspace_fn = self.gdb.current_progspace().filename
            except Exception:
                pass
            if r_bin and progspace_fn and os.path.exists(progspace_fn) and os.path.realpath(progspace_fn) != os.path.realpath(r_bin):
                from .debug_image import DebugImageProvider
                provider = DebugImageProvider(progspace_fn)
                provider.verify(r_bin)
                self.debug_image_provider = provider
                self.backend.debug_image_provider = provider
                debug_ident = provider.debug_identity.to_dict()
                debug_ident["source"] = "external"
                debug_ident["verified"] = bool(provider.compatibility and provider.compatibility.compatible)
                debug_ident["compatible"] = bool(provider.compatibility and provider.compatibility.compatible)
                debug_ident["reason"] = provider.compatibility.reason if provider.compatibility else None
            elif r_ident:
                debug_ident = dict(r_ident)
                debug_ident["source"] = "embedded"
                debug_ident["verified"] = True
                debug_ident["compatible"] = True
                debug_ident["reason"] = "EMBEDDED_DEBUG_INFO" if r_ident.get("has_debug_info") else "STRIPPED_NO_DEBUG_IMAGE"

        return {
            "process": pinfo,
            "runtime_binary": r_ident,
            "debug_image": debug_ident,
            "capabilities": self.get_capabilities()
        }

    def attach(self, pid: int, debug_image: Optional[str] = None):
        try:
            self.gdb.execute("attach {}".format(pid))
        except Exception as exc:
            raise RuntimeError("ATTACH_FAILED: {}".format(exc))

        if debug_image:
            self.load_debug_image(debug_image)

    def get_capabilities(self) -> Dict[str, Any]:
        thread_count = 1
        try:
            inf = self.gdb.selected_inferior()
            thread_count = len(inf.threads())
        except Exception:
            pass
        return RuntimeCapabilities(
            checkpoint=True,
            restore=True,
            typed_mutation=True,
            semantic_snapshot=True,
            semantic_diff=True,
            state_hash=True,
            branch_exploration=True,
            crash_recovery=True,
            timeout_recovery=True,
            external_debug_image=True,
            multi_thread_determinism=False,
            external_io_rollback=False,
            exploration_mode="deterministic_single_thread_context" if thread_count <= 1 else "multi_thread_experimental",
            backend="gdb_fork"
        ).to_dict()

    def get_type_info(self, type_name: str) -> Optional[Any]:
        if not type_name:
            return None
        cleaned = type_name.replace("enum class ", "").replace("enum ", "").replace("struct ", "").replace("class ", "").strip()
        for prefix in ["", "struct ", "class ", "enum "]:
            try:
                return self.gdb.lookup_type(prefix + cleaned).strip_typedefs()
            except Exception:
                pass
        return None

    def get_enum_members(self, type_name: str):
        gdb_type = self.get_type_info(type_name)
        if gdb_type is not None:
            return self.types.enum_members(gdb_type)
        return []

    def get_integer_range(self, type_name: str):
        gdb_type = self.get_type_info(type_name)
        if gdb_type is not None and self.types.kind(gdb_type) == "primitive":
            return self.types.integer_range(gdb_type)
        return None

    def checkpoint(self, checkpoint_id=None):
        return self.restorer.checkpoint(checkpoint_id=checkpoint_id)

    def restore(self, checkpoint):
        self.restorer.restore(checkpoint)
        self._latest = None

    def release_checkpoint(self, checkpoint):
        self.restorer.release(checkpoint)

    def execute_transition_from_checkpoint(self, checkpoint, candidate, timeout_ms=1000):
        self.restore(checkpoint)
        cand_obj = candidate.object_id if hasattr(candidate, "object_id") else candidate.get("object_id")
        cand_field = candidate.field_path if hasattr(candidate, "field_path") else candidate.get("field_path")
        cand_val = candidate.proposed_value if hasattr(candidate, "proposed_value") else candidate.get("proposed_value")
        return self.execute_transition(
            object_id=cand_obj,
            field_path=cand_field,
            value=cand_val,
            timeout_ms=timeout_ms
        )

    def observe(self):
        if self._is_stopped():
            return self.snapshot()
        return self._latest

    def get_object(self, object_id):
        if not self._latest:
            return None
        return next((o for o in self._latest.persistent.objects if o.object_id == object_id), None)

    def get_field(self, object_id, field):
        obj = self.get_object(object_id)
        if not obj:
            return None
        return next((f for f in obj.fields if f.name == field), None)

    def propose_mutations(self, snapshot=None):
        from .explorer import StateExplorer
        return StateExplorer(self).propose_mutations(snapshot)

    def explore(self, max_steps=10, timeout_ms=1000, corpus_dir="corpus", debug_image=None):
        if debug_image:
            self.load_debug_image(debug_image)
        from .explorer import StateExplorer
        return StateExplorer(self, corpus_dir=corpus_dir).run(max_steps=max_steps, timeout_ms=timeout_ms)

    def snapshot(self, snapshot_id=None, output=None, max_depth=None, include_globals=True, debug_image=None):
        if debug_image:
            self.load_debug_image(debug_image)
        if not self._is_stopped():
            raise RuntimeError("PROCESS_NOT_STOPPED")
        self._counter += 1
        identifier = snapshot_id or "S{:03d}".format(self._counter)
        if identifier in self.snapshots:
            raise RuntimeError("SNAPSHOT_EXISTS: {}".format(identifier))
        start = time.monotonic()
        state = self.backend.snapshot(max_depth=max_depth, include_globals=include_globals)
        transition = None
        if self._latest and self._last_mutation:
            tid = "T{:03d}".format(self._transition_counter) if self._transition_counter else "T001"
            transition = {
                "origin_transition_id": tid,
                "parent_snapshot": self._latest.snapshot_id,
                "child_snapshot": identifier,
            }
        result = RuntimeSnapshot.from_runtime_state(state, identifier, transition=transition)
        performance = result.persistent.statistics.setdefault("performance", {})
        serialization_start = time.monotonic()
        # Measure JSON conversion even when the caller keeps the snapshot in memory.
        json.dumps(result.to_dict(), ensure_ascii=False, default=str)
        performance["serialization_ms"] = round((time.monotonic() - serialization_start) * 1000, 3)
        performance["snapshot_ms"] = round((time.monotonic() - start) * 1000, 3)
        self.snapshots[identifier] = result
        self._latest = result
        if output:
            result.write_json(output)
        return result

    def mutate(self, object_id=None, field_path=None, value=None, path=None, object=None, field=None):
        start = time.monotonic()
        if not self._is_stopped():
            return mutation_error("PROCESS_NOT_STOPPED", "inferior must be stopped")
        object_id = object_id or object
        field_path = field_path or field
        if object_id and "." in str(object_id) and value is None and field_path is not None:
            value = field_path
            path = object_id
            object_id = None
            field_path = None
        if path:
            resolved_obj, resolved_field, error = self._semantic_path(path)
            if error:
                return mutation_error(error, "semantic path requires exactly one matching object", path=path)
            object_id, field_path = resolved_obj, resolved_field
        if not object_id or not field_path:
            return mutation_error("OBJECT_NOT_FOUND", "object and field are required")
        if not self._latest:
            return mutation_error("SNAPSHOT_INVALID", "take a snapshot before mutation")
        obj = next((o for o in self._latest.persistent.objects if o.object_id == object_id), None)
        if obj is None:
            return mutation_error("OBJECT_NOT_FOUND", "object is not in the latest snapshot", object_id=object_id)
        if "." in field_path:
            return mutation_error("UNSUPPORTED_TYPE", "nested field mutation is not supported in Phase 3", field=field_path)
        if not any(item.name == field_path for item in obj.fields):
            return mutation_error("FIELD_NOT_FOUND", "field is not present in the snapshot DWARF object",
                                  object_id=object_id, field=field_path)
        try:
            resolution_start = time.monotonic()
            runtime_object = self._runtime_object(obj.address, obj.type)
            field_value = runtime_object[field_path]
            field_type = field_value.type
            field_kind = self.types.kind(field_type)
            before = self.backend.pointer_text(field_value) if field_kind in ("pointer", "reference") else self.backend.primitive_value(field_value, field_kind)
            converted, error = self._convert(field_type, value)
            if error:
                return mutation_error(error["code"], error["message"], field=field_path,
                                      expected=self.types.display_name(field_type), received=type(value).__name__)
            resolution_ms = (time.monotonic() - resolution_start) * 1000
            write_start = time.monotonic()
            field_value.assign(converted)
            write_ms = (time.monotonic() - write_start) * 1000
            after_value = runtime_object[field_path]
            after = self.backend.pointer_text(after_value) if field_kind in ("pointer", "reference") else self.backend.primitive_value(after_value, field_kind)
            res = MutationResult(True, object_id, field_path, self.types.display_name(field_type), before, after,
                                 self.backend.value_address(after_value), performance={
                                     "resolution_ms": round(resolution_ms, 3), "write_ms": round(write_ms, 3),
                                     "total_ms": round((time.monotonic() - start) * 1000, 3)})
            self._last_mutation = res
            return res
        except KeyError:
            return mutation_error("FIELD_NOT_FOUND", "field is not present in the DWARF object", field=field_path)
        except Exception as exc:
            return mutation_error("MUTATION_FAILED", str(exc), object_id=object_id, field=field_path)

    def continue_execution(self, timeout_ms=1000):
        if not self._is_stopped():
            return ExecutionResult("PROCESS_NOT_STOPPED", error={"code": "PROCESS_NOT_STOPPED"})
        start, timed_out = time.monotonic(), [False]
        timer = None
        if timeout_ms:
            def interrupt():
                timed_out[0] = True
                try:
                    self.gdb.post_event(lambda: self.gdb.execute("interrupt", to_string=True))
                except Exception:
                    pass
            timer = threading.Timer(timeout_ms / 1000.0, interrupt)
            timer.daemon = True
            timer.start()
        try:
            try:
                # signal 0 continues execution without delivering any pending signals from prior stops
                self.gdb.execute("signal 0")
            except Exception:
                self.gdb.execute("continue")
        except Exception as exc:
            text = str(exc)
            if "exited" in text.lower():
                return ExecutionResult("EXITED", reason=text, performance={"total_ms": round((time.monotonic() - start) * 1000, 3)})
            return ExecutionResult("GDB_ERROR", error={"code": "GDB_ERROR", "message": text})
        finally:
            if timer:
                timer.cancel()
        info = self.gdb.execute("info program", to_string=True).lower()
        elapsed = round((time.monotonic() - start) * 1000, 3)
        if timed_out[0]:
            res = ExecutionResult("TIMEOUT", reason="interrupt requested after timeout", performance={"total_ms": elapsed})
        elif "exited" in info or "not being run" in info:
            res = ExecutionResult("EXITED", reason=info.strip(), performance={"total_ms": elapsed})
        elif "signal" in info:
            crash_sig = None
            for sig in ("sigsegv", "sigbus", "sigfpe", "sigill", "sigabrt", "sigtrap"):
                if sig in info:
                    crash_sig = sig.upper()
                    break
            if crash_sig:
                res = ExecutionResult("CRASHED", signal=crash_sig, reason=info.strip(), performance={"total_ms": elapsed})
            else:
                res = ExecutionResult("SIGNAL", reason=info.strip(), performance={"total_ms": elapsed})
        else:
            reason = "breakpoint" if "breakpoint" in info else "breakpoint_or_stop"
            res = ExecutionResult("STOPPED", reason=reason, performance={"total_ms": elapsed})
        self._last_execution = res
        return res

    def diff(self, before, after):
        return StateDiffEngine().diff(before, after)

    def execute_transition(self, object_id=None, field_path=None, value=None, path=None,
                           timeout_ms=1000, transition_id=None, output=None,
                           parent_snapshot_id=None, child_snapshot_id=None,
                           snapshots_dir=None, parent_output=None, child_output=None,
                           debug_image=None):
        if debug_image:
            self.load_debug_image(debug_image)
        import os
        from .snapshot import StateTransition
        t_total_start = time.monotonic()
        self._transition_counter += 1
        tid = transition_id or "T{:03d}".format(self._transition_counter)

        if not self._is_stopped():
            exec_res = ExecutionResult("PROCESS_NOT_STOPPED", error={"code": "PROCESS_NOT_STOPPED"})
            return StateTransition(
                transition_id=tid,
                parent_snapshot="<none>",
                child_snapshot=None,
                mutation=None,
                execution=exec_res,
                diff=None,
                performance={"total_ms": round((time.monotonic() - t_total_start) * 1000, 3)}
            )

        # 1. Snapshot A (Parent)
        t_snap_a = time.monotonic()
        if parent_snapshot_id and parent_snapshot_id in self.snapshots:
            parent_snapshot = self.snapshots[parent_snapshot_id]
        elif self._latest and (parent_snapshot_id is None or self._latest.snapshot_id == parent_snapshot_id):
            parent_snapshot = self._latest
        else:
            parent_snapshot = self.snapshot(snapshot_id=parent_snapshot_id)
        snap_before_ms = round((time.monotonic() - t_snap_a) * 1000, 3)

        if snapshots_dir:
            os.makedirs(snapshots_dir, exist_ok=True)
            parent_output = parent_output or os.path.join(snapshots_dir, "{}.json".format(parent_snapshot.snapshot_id))
        if parent_output:
            parent_snapshot.write_json(parent_output)

        # 2. Mutation
        t_mut = time.monotonic()
        mutation_res = self.mutate(
            object_id=object_id,
            field_path=field_path,
            value=value,
            path=path
        )
        mutation_ms = round((time.monotonic() - t_mut) * 1000, 3)

        if not mutation_res.success:
            exec_res = ExecutionResult("NOT_RUN", reason="mutation failed")
            perf = {
                "snapshot_before_ms": snap_before_ms,
                "mutation_ms": mutation_ms,
                "continue_ms": 0.0,
                "snapshot_after_ms": 0.0,
                "diff_ms": 0.0,
                "total_ms": round((time.monotonic() - t_total_start) * 1000, 3)
            }
            trans = StateTransition(
                transition_id=tid,
                parent_snapshot=parent_snapshot.snapshot_id,
                child_snapshot=None,
                mutation=mutation_res,
                execution=exec_res,
                diff=None,
                performance=perf
            )
            if output:
                trans.write_json(output)
            return trans

        # 3. Continue execution
        t_cont = time.monotonic()
        execution_res = self.continue_execution(timeout_ms=timeout_ms)
        continue_ms = round((time.monotonic() - t_cont) * 1000, 3)

        # 4. Snapshot B (Child) & Semantic Diff (only when stopped)
        child_snapshot = None
        diff_res = None
        snap_after_ms = 0.0
        diff_ms = 0.0

        if execution_res.status == "STOPPED":
            t_snap_b = time.monotonic()
            child_snapshot = self.snapshot(snapshot_id=child_snapshot_id)
            snap_after_ms = round((time.monotonic() - t_snap_b) * 1000, 3)

            if snapshots_dir:
                child_output = child_output or os.path.join(snapshots_dir, "{}.json".format(child_snapshot.snapshot_id))
            if child_output:
                child_snapshot.write_json(child_output)

            t_diff = time.monotonic()
            diff_res = self.diff(parent_snapshot, child_snapshot)
            diff_ms = round((time.monotonic() - t_diff) * 1000, 3)

        perf = {
            "snapshot_before_ms": snap_before_ms,
            "mutation_ms": mutation_ms,
            "continue_ms": continue_ms,
            "snapshot_after_ms": snap_after_ms,
            "diff_ms": diff_ms,
            "total_ms": round((time.monotonic() - t_total_start) * 1000, 3)
        }

        trans = StateTransition(
            transition_id=tid,
            parent_snapshot=parent_snapshot.snapshot_id,
            child_snapshot=child_snapshot.snapshot_id if child_snapshot else None,
            mutation=mutation_res,
            execution=execution_res,
            diff=diff_res,
            performance=perf
        )
        if output:
            trans.write_json(output)
        return trans

    def build_transition(self, transition_id, parent, child, mutation, execution, performance=None):
        from .snapshot import StateTransition
        parent_id = parent.snapshot_id if hasattr(parent, "snapshot_id") else (parent.get("snapshot", {}).get("snapshot_id") or str(parent))
        child_id = (child.snapshot_id if hasattr(child, "snapshot_id") else (child.get("snapshot", {}).get("snapshot_id") or str(child))) if child else None
        mut_dict = mutation.to_dict() if hasattr(mutation, "to_dict") else mutation
        exec_dict = execution.to_dict() if hasattr(execution, "to_dict") else execution
        diff_dict = self.diff(parent, child).to_dict() if (parent and child) else None
        return StateTransition(
            transition_id=transition_id,
            parent_snapshot=parent_id,
            child_snapshot=child_id,
            mutation=mut_dict,
            execution=exec_dict,
            diff=diff_dict,
            performance=performance
        )

    def _is_stopped(self):
        try:
            thread = self.gdb.selected_thread()
            return thread is not None and thread.is_stopped()
        except Exception:
            return False

    def _runtime_object(self, address, type_name):
        address_value = int(address, 16)
        try:
            target_type = self.gdb.lookup_type(type_name).strip_typedefs()
        except Exception:
            try:
                target_type = self.gdb.lookup_type("struct " + type_name).strip_typedefs()
            except Exception:
                target_type = self.gdb.lookup_type("class " + type_name).strip_typedefs()
        return self.gdb.Value(address_value).cast(target_type.pointer()).dereference()

    def _semantic_path(self, path):
        if not self._latest or "." not in path:
            return None, None, "OBJECT_NOT_FOUND"
        type_name, field = path.rsplit(".", 1)
        matches = [o.object_id for o in self._latest.persistent.objects if o.type == type_name]
        if len(matches) != 1:
            return None, None, "AMBIGUOUS_OBJECT" if matches else "OBJECT_NOT_FOUND"
        return matches[0], field, None

    def _convert(self, field_type, value):
        kind = self.types.kind(field_type)
        display = self.types.display_name(field_type)
        try:
            if kind == "pointer":
                if value is None or (isinstance(value, str) and value.lower() in ("null", "nullptr", "0")) or value == 0:
                    return self.gdb.Value(0).cast(field_type), None
                return None, {"code": "TYPE_CONVERSION_ERROR", "message": "only NULL pointer mutation is allowed"}
            if kind == "enum":
                if isinstance(value, int):
                    return self.gdb.Value(value).cast(field_type), None
                if isinstance(value, str) and (value.isdigit() or (value.startswith("-") and value[1:].isdigit())):
                    return self.gdb.Value(int(value)).cast(field_type), None
                if not isinstance(value, str) or not re.match(r"^[A-Za-z_][A-Za-z0-9_:]*$", value):
                    return None, {"code": "TYPE_CONVERSION_ERROR", "message": "invalid enum value"}
                try:
                    enum_value = self.gdb.parse_and_eval(value)
                except Exception:
                    try:
                        enum_value = self.gdb.parse_and_eval("{}::{}".format(display, value))
                    except Exception:
                        return None, {"code": "TYPE_CONVERSION_ERROR", "message": "cannot resolve enum value: {}".format(value)}
                return enum_value.cast(field_type), None
            if kind != "primitive":
                return None, {"code": "UNSUPPORTED_TYPE", "message": "only scalar fields are mutable"}
            if "bool" in display:
                if isinstance(value, str):
                    if value.lower() not in ("true", "false", "0", "1"):
                        return None, {"code": "TYPE_CONVERSION_ERROR", "message": "expected bool"}
                    value = value.lower() in ("true", "1")
                elif value not in (True, False, 0, 1):
                    return None, {"code": "TYPE_CONVERSION_ERROR", "message": "expected bool"}
                return self.gdb.Value(bool(value)).cast(field_type), None
            if self.types.code(field_type) == getattr(self.gdb, "TYPE_CODE_FLT", None):
                number = float(value)
                if not math.isfinite(number):
                    raise ValueError("non-finite float")
                return self.gdb.Value(number).cast(field_type), None
            number = int(value)
            bits = int(field_type.sizeof) * 8
            signed = not ("unsigned" in display or display.startswith("uint"))
            low, high = (-(1 << (bits - 1)), (1 << (bits - 1)) - 1) if signed else (0, (1 << bits) - 1)
            if number < low or number > high:
                return None, {"code": "RANGE_ERROR", "message": "value outside {} range".format(display)}
            return self.gdb.Value(number).cast(field_type), None
        except Exception as exc:
            return None, {"code": "TYPE_CONVERSION_ERROR", "message": str(exc)}

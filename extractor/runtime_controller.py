"""Deterministic runtime API; GDB-specific mutation remains in this adapter."""

import math
import json
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

    def propose_mutations(self, snapshot=None):
        raise NotImplementedError

    def explore(self, max_steps=10, timeout_ms=1000, corpus_dir="corpus"):
        raise NotImplementedError


class GdbRuntimeController(RuntimeController):
    def __init__(self, gdb_module):
        self.gdb = gdb_module
        self.backend = GdbBackend(gdb_module)
        self.types = TypeResolver(gdb_module)
        self.snapshots: Dict[str, RuntimeSnapshot] = {}
        self._counter = 0
        self._transition_counter = 0
        self._latest: Optional[RuntimeSnapshot] = None
        self._last_mutation: Optional[MutationResult] = None
        self._last_execution: Optional[ExecutionResult] = None

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

    def explore(self, max_steps=10, timeout_ms=1000, corpus_dir="corpus"):
        from .explorer import StateExplorer
        return StateExplorer(self, corpus_dir=corpus_dir).run(max_steps=max_steps, timeout_ms=timeout_ms)

    def snapshot(self, snapshot_id=None, output=None, max_depth=None, include_globals=True):
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
                           snapshots_dir=None, parent_output=None, child_output=None):
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

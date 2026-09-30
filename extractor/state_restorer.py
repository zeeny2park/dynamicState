"""Runtime execution state restorer and checkpoint abstraction for Phase 4 & Phase 4.1.

Distinguishes between:
- Semantic Snapshot: JSON artifact observing process semantic state (e.g. S001)
- Runtime Checkpoint: Execution state capable of restoring inferior memory (e.g. C001)

Backend Semantics:
- GDB_CHECKPOINT: OS copy-on-write fork checkpoint of execution and memory state (Single-Thread Only)
- RESTART: Deterministic process restart to predefined observation breakpoint (Multi-Thread Capable)
- NONE: Attached inferior or non-restorable execution (Observation Only)
"""

from dataclasses import asdict, dataclass, field
import re
import time
from typing import Any, Callable, Dict, List, Optional, Set


@dataclass
class RuntimeCheckpoint:
    """Runtime checkpoint descriptor for restoring execution state."""
    checkpoint_id: str
    backend: str
    metadata: Dict[str, Any]
    scope: str = "MULTITHREAD"
    restore_semantics: str = "RESTART_TO_OBSERVATION_POINT"
    observation_point: Optional[Dict[str, Any]] = None
    determinism: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.determinism is None:
            backend_up = self.backend.upper()
            d["determinism"] = {
                "required": (backend_up in ("RESTART", "MOCK")),
                "status": "VERIFIED" if backend_up in ("GDB_CHECKPOINT", "MOCK") else "UNKNOWN",
            }
        return d


class StateRestorer:
    """Abstract interface for capturing and restoring runtime execution state."""

    def get_capability(self, thread_count: int = 1) -> Dict[str, Any]:
        return {
            "supported": True,
            "backend": "GENERIC",
            "scope": "MULTITHREAD",
            "semantics": "MEMORY_CHECKPOINT",
            "determinism_required": False,
            "determinism_status": "UNKNOWN",
            "threads": thread_count,
            "reason": None,
        }

    def checkpoint(self, checkpoint_id: Optional[str] = None) -> RuntimeCheckpoint:
        raise NotImplementedError

    def restore(self, checkpoint: RuntimeCheckpoint) -> None:
        raise NotImplementedError

    def release(self, checkpoint: RuntimeCheckpoint) -> None:
        pass

    def verify_restart_determinism(self, checkpoint: RuntimeCheckpoint, controller=None) -> Dict[str, Any]:
        return {
            "deterministic": True,
            "status": "VERIFIED",
            "parent_state_hash": None,
            "restored_state_hash": None,
            "mismatches": [],
        }


class NullRestorer(StateRestorer):
    """Null restorer used when inferior cannot support branch isolation."""

    def __init__(self, reason: Optional[str] = None, backend: str = "NONE"):
        self.reason = reason or "Branch isolation is unavailable for this target."
        self.backend_name = backend

    def get_capability(self, thread_count: int = 1) -> Dict[str, Any]:
        return {
            "supported": False,
            "backend": self.backend_name,
            "scope": "NONE",
            "semantics": "OBSERVATION_ONLY",
            "determinism_required": False,
            "determinism_status": "UNKNOWN",
            "threads": thread_count,
            "reason": self.reason,
        }

    def checkpoint(self, checkpoint_id: Optional[str] = None) -> RuntimeCheckpoint:
        raise RuntimeError(f"CHECKPOINT_UNSUPPORTED: {self.reason}")

    def restore(self, checkpoint: RuntimeCheckpoint) -> None:
        raise RuntimeError(f"RESTORE_UNSUPPORTED: {self.reason}")

    def release(self, checkpoint: RuntimeCheckpoint) -> None:
        pass

    def verify_restart_determinism(self, checkpoint: RuntimeCheckpoint, controller=None) -> Dict[str, Any]:
        return {
            "deterministic": False,
            "status": "FAILED",
            "reason": f"CHECKPOINT_UNSUPPORTED: {self.reason}",
            "mismatches": [],
        }


class MockStateRestorer(StateRestorer):
    """In-memory mock restorer for unit testing and simulation."""

    def __init__(self, capture_fn: Optional[Callable[[], Any]] = None,
                 restore_fn: Optional[Callable[[Any], None]] = None,
                 max_checkpoints: int = 10,
                 simulated_nondeterminism: bool = False):
        self.capture_fn = capture_fn
        self.restore_fn = restore_fn
        self.max_checkpoints = max_checkpoints
        self.simulated_nondeterminism = simulated_nondeterminism
        self._counter = 0
        self._store: Dict[str, Any] = {}
        self.checkpoints: Dict[str, RuntimeCheckpoint] = {}
        self.restore_count = 0
        self.last_determinism_result: Optional[Dict[str, Any]] = None

    def get_capability(self, thread_count: int = 1) -> Dict[str, Any]:
        det_status = "UNKNOWN"
        if self.last_determinism_result:
            det_status = self.last_determinism_result.get("status", "UNKNOWN")
        elif not self.simulated_nondeterminism:
            det_status = "VERIFIED"
        return {
            "supported": True,
            "backend": "MOCK",
            "scope": "MULTITHREAD",
            "semantics": "MEMORY_CHECKPOINT",
            "determinism_required": False,
            "determinism_status": det_status,
            "threads": thread_count,
            "reason": None,
        }

    def checkpoint(self, checkpoint_id: Optional[str] = None) -> RuntimeCheckpoint:
        if len(self.checkpoints) >= self.max_checkpoints:
            raise RuntimeError(f"CHECKPOINT_LIMIT_REACHED: maximum checkpoint limit ({self.max_checkpoints}) exceeded")
        self._counter += 1
        cid = checkpoint_id or f"C{self._counter:03d}"
        saved_data = self.capture_fn() if self.capture_fn else {"mock_state": cid}
        self._store[cid] = saved_data
        cp = RuntimeCheckpoint(
            checkpoint_id=cid,
            backend="MOCK",
            scope="MULTITHREAD",
            restore_semantics="MEMORY_CHECKPOINT",
            observation_point={"kind": "MOCK", "spec": "mock_func"},
            determinism={"required": False, "status": "VERIFIED"},
            metadata={"created_at": time.time(), "index": self._counter}
        )
        self.checkpoints[cid] = cp
        return cp

    def restore(self, checkpoint: RuntimeCheckpoint) -> None:
        if checkpoint is None or not hasattr(checkpoint, "checkpoint_id"):
            raise RuntimeError("CHECKPOINT_STATE_INVALID: checkpoint descriptor is required")
        cid = checkpoint.checkpoint_id
        if cid not in self._store:
            raise RuntimeError(f"CHECKPOINT_NOT_FOUND: checkpoint '{cid}' not found")
        saved_data = self._store[cid]
        if self.restore_fn:
            self.restore_fn(saved_data)
        self.restore_count += 1

    def release(self, checkpoint: RuntimeCheckpoint) -> None:
        if checkpoint is None or not hasattr(checkpoint, "checkpoint_id"):
            raise RuntimeError("CHECKPOINT_STATE_INVALID: checkpoint descriptor is required")
        cid = checkpoint.checkpoint_id
        if cid not in self._store and cid not in self.checkpoints:
            raise RuntimeError(f"CHECKPOINT_NOT_FOUND: checkpoint '{cid}' not registered")
        self._store.pop(cid, None)
        self.checkpoints.pop(cid, None)

    def verify_restart_determinism(self, checkpoint: RuntimeCheckpoint, controller=None) -> Dict[str, Any]:
        if self.simulated_nondeterminism:
            res = {
                "deterministic": False,
                "status": "NON_DETERMINISTIC",
                "parent_state_hash": "mock_hash_parent",
                "restored_state_hash": "mock_hash_restored_differ",
                "mismatches": [{"path": "mock.counter", "before": 10, "after": 99}],
                "reason": "NON_DETERMINISTIC_RUNTIME_STATE",
            }
        else:
            res = {
                "deterministic": True,
                "status": "VERIFIED",
                "parent_state_hash": "mock_hash_deterministic",
                "restored_state_hash": "mock_hash_deterministic",
                "mismatches": [],
            }
        self.last_determinism_result = res
        return res


class GdbCheckpointRestorer(StateRestorer):
    """GDB-native fork-based checkpoint and restore engine.

    Uses OS copy-on-write fork via GDB 'checkpoint' command.
    Maintains a master pristine checkpoint and creates disposable worker
    clones for branch-safe candidate mutation execution.
    Supported strictly for single-threaded processes due to Linux fork() constraints.
    """

    def __init__(self, gdb_module, max_checkpoints: int = 10):
        self.gdb = gdb_module
        self.max_checkpoints = max_checkpoints
        self._counter = 0
        self._checkpoints: Dict[str, Dict[str, Any]] = {}

    def _list_gdb_checkpoints(self) -> Dict[str, Dict[str, Any]]:
        """Parse GDB 'info checkpoints' output robustly."""
        try:
            out = self.gdb.execute("info checkpoints", to_string=True)
        except Exception as exc:
            raise RuntimeError(f"CHECKPOINT_STATE_INVALID: failed to query GDB checkpoints: {exc}")
        result = {}
        for line in out.strip().splitlines():
            line_str = line.strip()
            if not line_str or line_str.startswith("No checkpoints"):
                continue
            m = re.match(r"^\s*(\*?)\s*([0-9]+(?:\.[0-9]+)?)\s+(.+)$", line_str)
            if m:
                is_cur = bool(m.group(1))
                cp_id = m.group(2)
                result[cp_id] = {"current": is_cur, "desc": m.group(3), "line": line_str}
        return result

    def get_capability(self, thread_count: int = 1) -> Dict[str, Any]:
        if thread_count > 1:
            return {
                "supported": False,
                "backend": "GDB_CHECKPOINT",
                "scope": "SINGLE_THREAD_ONLY",
                "semantics": "MEMORY_CHECKPOINT",
                "determinism_required": False,
                "determinism_status": "FAILED",
                "threads": thread_count,
                "reason": f"GDB fork checkpoint cannot checkpoint multiple threads ({thread_count} active threads).",
            }
        return {
            "supported": True,
            "backend": "GDB_CHECKPOINT",
            "scope": "SINGLE_THREAD_ONLY",
            "semantics": "MEMORY_CHECKPOINT",
            "determinism_required": False,
            "determinism_status": "VERIFIED",
            "threads": thread_count,
            "reason": None,
        }

    def checkpoint(self, checkpoint_id: Optional[str] = None) -> RuntimeCheckpoint:
        """Create a new GDB fork checkpoint."""
        if len(self._checkpoints) >= self.max_checkpoints:
            raise RuntimeError(f"CHECKPOINT_LIMIT_REACHED: maximum checkpoint limit ({self.max_checkpoints}) exceeded")

        # Thread count validation
        thread_count = 1
        try:
            if hasattr(self.gdb, "selected_inferior"):
                inf = self.gdb.selected_inferior()
                thread_count = len(inf.threads())
        except Exception:
            pass
        if thread_count > 1:
            raise RuntimeError(
                f"MULTITHREAD_CHECKPOINT_UNSUPPORTED: GDB fork checkpoint cannot checkpoint multiple threads "
                f"({thread_count} active threads). Forking a multithreaded process drops other threads and deadlocks."
            )

        # Inferior state validation
        try:
            thread = self.gdb.selected_thread()
            if thread is None or not thread.is_stopped():
                raise RuntimeError("CHECKPOINT_STATE_INVALID: inferior must be stopped to capture checkpoint")
        except Exception as exc:
            if "CHECKPOINT_STATE_INVALID" in str(exc):
                raise
            raise RuntimeError(f"CHECKPOINT_STATE_INVALID: {exc}")

        self._counter += 1
        cid = checkpoint_id or f"C{self._counter:03d}"

        before = set(self._list_gdb_checkpoints().keys())
        try:
            self.gdb.execute("checkpoint")
        except Exception as exc:
            raise RuntimeError(f"CHECKPOINT_CREATE_FAILED: GDB execution error: {exc}")

        after = set(self._list_gdb_checkpoints().keys())
        diff = after - before
        if not diff:
            if "0" in after and "0" not in before:
                new_gdb_id = "0"
            elif after:
                new_gdb_id = sorted(list(after), key=lambda x: [int(p) for p in x.split(".")])[-1]
            else:
                raise RuntimeError("CHECKPOINT_CREATE_FAILED: no new checkpoint ID created by GDB")
        else:
            non_zero_diff = [gid for gid in diff if gid != "0"]
            if non_zero_diff:
                new_gdb_id = sorted(non_zero_diff, key=lambda x: [int(p) for p in x.split(".")])[-1]
            else:
                new_gdb_id = list(diff)[0]

        cp_record = {
            "checkpoint_id": cid,
            "master_gdb_id": str(new_gdb_id),
            "active_worker_gdb_id": None
        }
        self._checkpoints[cid] = cp_record

        return RuntimeCheckpoint(
            checkpoint_id=cid,
            backend="gdb_fork",
            scope="SINGLE_THREAD_ONLY",
            restore_semantics="MEMORY_CHECKPOINT",
            observation_point={"kind": "GDB_CHECKPOINT", "spec": str(new_gdb_id)},
            determinism={"required": False, "status": "VERIFIED"},
            metadata={"gdb_id": str(new_gdb_id)}
        )

    def restore(self, checkpoint: RuntimeCheckpoint) -> None:
        """Restore inferior execution context to a clean clone of the checkpoint."""
        if checkpoint is None or not hasattr(checkpoint, "checkpoint_id"):
            raise RuntimeError("CHECKPOINT_STATE_INVALID: checkpoint descriptor is required")

        cid = checkpoint.checkpoint_id
        if cid not in self._checkpoints:
            raise RuntimeError(f"CHECKPOINT_NOT_FOUND: checkpoint '{cid}' not found")

        record = self._checkpoints[cid]
        master_id = record["master_gdb_id"]

        cps = self._list_gdb_checkpoints()
        if master_id not in cps:
            raise RuntimeError(f"CHECKPOINT_RESTORE_FAILED: master checkpoint {master_id} does not exist in GDB")

        # Clean up any existing worker clone from a previous mutation
        old_worker = record.get("active_worker_gdb_id")
        if old_worker is not None and old_worker in cps:
            try:
                self.gdb.execute(f"restart {master_id}")
                self.gdb.execute(f"delete checkpoint {old_worker}")
            except Exception:
                pass
            record["active_worker_gdb_id"] = None

        # 1. Switch back to master checkpoint
        try:
            self.gdb.execute(f"restart {master_id}")
        except Exception as exc:
            raise RuntimeError(f"CHECKPOINT_RESTORE_FAILED: cannot restart master checkpoint {master_id}: {exc}")

        # 2. Fork a disposable worker clone from master
        before = set(self._list_gdb_checkpoints().keys())
        try:
            self.gdb.execute("checkpoint")
        except Exception as exc:
            raise RuntimeError(f"CHECKPOINT_RESTORE_FAILED: cannot clone worker from master {master_id}: {exc}")

        after = set(self._list_gdb_checkpoints().keys())
        diff = after - before
        non_zero_worker_diff = [gid for gid in diff if gid != "0"]
        if non_zero_worker_diff:
            worker_id = sorted(non_zero_worker_diff, key=lambda x: [int(p) for p in x.split(".")])[-1]
        elif diff:
            worker_id = list(diff)[0]
        else:
            worker_id = master_id

        # 3. Switch to worker clone for candidate execution
        try:
            self.gdb.execute(f"restart {worker_id}")
            record["active_worker_gdb_id"] = str(worker_id)
        except Exception as exc:
            raise RuntimeError(f"CHECKPOINT_RESTORE_FAILED: cannot switch to worker clone {worker_id}: {exc}")

    def release(self, checkpoint: RuntimeCheckpoint) -> None:
        """Release and clean up GDB fork processes for this checkpoint."""
        if checkpoint is None or not hasattr(checkpoint, "checkpoint_id"):
            raise RuntimeError("CHECKPOINT_STATE_INVALID: checkpoint descriptor is required")

        cid = checkpoint.checkpoint_id
        record = self._checkpoints.pop(cid, None)
        if not record:
            raise RuntimeError(f"CHECKPOINT_NOT_FOUND: checkpoint '{cid}' not registered")

        cps = self._list_gdb_checkpoints()
        worker_id = record.get("active_worker_gdb_id")
        master_id = record.get("master_gdb_id")

        if worker_id is not None and worker_id in cps:
            if master_id is not None and master_id in cps:
                try:
                    self.gdb.execute(f"restart {master_id}")
                except Exception:
                    pass
            try:
                self.gdb.execute(f"delete checkpoint {worker_id}")
            except Exception:
                pass

        cps = self._list_gdb_checkpoints()
        other_ids = [gid for gid in cps if gid != master_id]
        if other_ids:
            target_switch = "0" if "0" in other_ids else other_ids[0]
            try:
                self.gdb.execute(f"restart {target_switch}")
            except Exception:
                pass
            if master_id is not None and master_id in cps:
                try:
                    self.gdb.execute(f"delete checkpoint {master_id}")
                except Exception:
                    pass

    def verify_restart_determinism(self, checkpoint: RuntimeCheckpoint, controller=None) -> Dict[str, Any]:
        return {
            "deterministic": True,
            "status": "VERIFIED",
            "parent_state_hash": None,
            "restored_state_hash": None,
            "mismatches": [],
        }


class RestartBasedRestorer(StateRestorer):
    """Deterministic restart-based state restorer for multithreaded targets.

    Provides true branch isolation for multithreaded programs launched by GDB.
    When restoring, re-runs the program from entry to the observation breakpoint,
    cleanly resetting all threads, stacks, TLS, and synchronization primitives.
    
    Strict restore validation conditions:
    1. Process starts and reaches stopped state at expected observation breakpoint
    2. Execution location / function matches expected observation point
    3. Thread count matches expected count at observation point
    4. Deterministic state verification API detects any semantic mismatches
    """

    def __init__(self, gdb_module, breakpoint_spec: Optional[str] = None):
        self.gdb = gdb_module
        self.breakpoint_spec = breakpoint_spec
        self._counter = 0
        self._checkpoints: Dict[str, RuntimeCheckpoint] = {}
        self.last_determinism_result: Optional[Dict[str, Any]] = None

    def get_capability(self, thread_count: int = 1) -> Dict[str, Any]:
        det_status = "UNKNOWN"
        if self.last_determinism_result:
            det_status = self.last_determinism_result.get("status", "UNKNOWN")
        return {
            "supported": True,
            "backend": "RESTART",
            "scope": "MULTITHREAD",
            "semantics": "RESTART_TO_OBSERVATION_POINT",
            "determinism_required": True,
            "determinism_status": det_status,
            "threads": thread_count,
            "reason": None,
        }

    def _ensure_breakpoint(self, spec: str):
        try:
            self.gdb.execute("set confirm off")
            self.gdb.execute(f"break {spec}")
        except Exception:
            pass

    def _resolve_observation_point(self) -> Dict[str, Any]:
        bp_spec = self.breakpoint_spec
        func_name = None
        location = None
        pc_hex = None
        thread_count = 1

        try:
            frame = self.gdb.selected_frame()
            if frame:
                func_name = frame.name()
                sal = frame.find_sal()
                if sal and sal.symtab and sal.line:
                    location = f"{sal.symtab.filename}:{sal.line}"
                pc_hex = hex(frame.pc())
        except Exception:
            pass

        try:
            if hasattr(self.gdb, "selected_inferior"):
                inf = self.gdb.selected_inferior()
                thread_count = len(inf.threads())
        except Exception:
            pass

        if not bp_spec:
            if func_name:
                bp_spec = func_name
            elif location:
                bp_spec = location
            elif pc_hex:
                bp_spec = f"*{pc_hex}"
            else:
                bp_spec = "observation_checkpoint"
            self.breakpoint_spec = bp_spec

        return {
            "kind": "BREAKPOINT",
            "spec": bp_spec,
            "function": func_name,
            "location": location,
            "pc": pc_hex,
            "expected_thread_count": thread_count,
        }

    def checkpoint(self, checkpoint_id: Optional[str] = None) -> RuntimeCheckpoint:
        # Inferior state validation
        try:
            if hasattr(self.gdb, "selected_thread"):
                thread = self.gdb.selected_thread()
                if thread is not None and not thread.is_stopped():
                    raise RuntimeError("CHECKPOINT_STATE_INVALID: inferior must be stopped to capture checkpoint")
        except Exception as exc:
            if "CHECKPOINT_STATE_INVALID" in str(exc):
                raise
            raise RuntimeError(f"CHECKPOINT_STATE_INVALID: {exc}")

        obs_point = self._resolve_observation_point()
        bp_spec = obs_point["spec"]
        self._ensure_breakpoint(bp_spec)

        self._counter += 1
        cid = checkpoint_id or f"C{self._counter:03d}"

        det_status = "UNKNOWN"
        if self.last_determinism_result and self.last_determinism_result.get("deterministic"):
            det_status = "VERIFIED"
        elif self.last_determinism_result:
            det_status = self.last_determinism_result.get("status", "FAILED")

        cp = RuntimeCheckpoint(
            checkpoint_id=cid,
            backend="RESTART",
            scope="MULTITHREAD",
            restore_semantics="RESTART_TO_OBSERVATION_POINT",
            observation_point=obs_point,
            determinism={
                "required": True,
                "status": det_status,
            },
            metadata={
                "breakpoint": bp_spec,
                "expected_function": obs_point["function"],
                "expected_location": obs_point["location"],
                "expected_thread_count": obs_point["expected_thread_count"],
                "created_at": time.time(),
            }
        )
        self._checkpoints[cid] = cp
        return cp

    def restore(self, checkpoint: RuntimeCheckpoint) -> None:
        """Restore inferior execution by deterministic restart to observation point.

        Validates all restore success conditions:
        1. Process restarts cleanly
        2. Expected observation breakpoint is reached
        3. Inferior is stopped
        4. Thread count matches expected count
        """
        if checkpoint is None or not hasattr(checkpoint, "checkpoint_id"):
            raise RuntimeError("CHECKPOINT_STATE_INVALID: checkpoint descriptor is required")

        cid = checkpoint.checkpoint_id
        record = self._checkpoints.get(cid) or checkpoint

        metadata = record.metadata if hasattr(record, "metadata") else getattr(checkpoint, "metadata", {})
        bp_spec = metadata.get("breakpoint") or self.breakpoint_spec or "observation_checkpoint"
        self._ensure_breakpoint(bp_spec)

        try:
            self.gdb.execute("set confirm off")
            self.gdb.execute("run")
        except Exception as exc:
            raise RuntimeError(f"RESTORE_FAILED: restart execution failed: {exc}")

        # 1. Process stopped validation
        try:
            if hasattr(self.gdb, "selected_thread"):
                thread = self.gdb.selected_thread()
                if thread is not None and hasattr(thread, "is_stopped") and not thread.is_stopped():
                    raise RuntimeError("RESTORE_FAILED: inferior is not stopped after restart")
        except Exception as exc:
            if "RESTORE_FAILED" in str(exc):
                raise
            raise RuntimeError(f"RESTORE_FAILED: cannot verify inferior stop state: {exc}")

        # 2. Reached expected observation point / function
        exp_func = metadata.get("expected_function")
        exp_loc = metadata.get("expected_location")
        cur_func = None
        cur_loc = None
        try:
            if hasattr(self.gdb, "selected_frame"):
                frame = self.gdb.selected_frame()
                if frame:
                    cur_func = frame.name()
                    sal = frame.find_sal()
                    if sal and sal.symtab and sal.line:
                        cur_loc = f"{sal.symtab.filename}:{sal.line}"
        except Exception:
            pass

        if exp_func and hasattr(self.gdb, "selected_frame"):
            func_match = (cur_func == exp_func) or (cur_func and bp_spec in str(cur_func)) or (cur_func and str(cur_func) in bp_spec)
            loc_match = bool(exp_loc and cur_loc and (exp_loc in cur_loc or cur_loc in exp_loc))
            if not (func_match or loc_match):
                raise RuntimeError(
                    f"RESTORE_OBSERVATION_POINT_NOT_REACHED: inferior stopped at '{cur_func}' ({cur_loc}), "
                    f"expected '{exp_func}' ({exp_loc})"
                )

        # 3. Thread count validation
        exp_threads = metadata.get("expected_thread_count")
        if exp_threads is not None:
            try:
                inf = self.gdb.selected_inferior()
                cur_threads = len(inf.threads())
                if cur_threads != exp_threads:
                    raise RuntimeError(
                        f"RESTORE_THREAD_COUNT_MISMATCH: expected {exp_threads} threads at observation point, "
                        f"got {cur_threads}"
                    )
            except Exception as exc:
                if "RESTORE_THREAD_COUNT_MISMATCH" in str(exc):
                    raise
                pass

    def release(self, checkpoint: RuntimeCheckpoint) -> None:
        if checkpoint is None or not hasattr(checkpoint, "checkpoint_id"):
            return
        self._checkpoints.pop(checkpoint.checkpoint_id, None)

    def verify_restart_determinism(self, checkpoint: RuntimeCheckpoint, controller=None) -> Dict[str, Any]:
        """Verify that restarting the inferior deterministically reproduces the exact same semantic state.

        Takes a parent snapshot, executes restore(checkpoint), takes a restored snapshot,
        and computes the state hash. Excludes non-semantic values (PID, addresses).
        """
        from .state_hash import compute_state_hash

        cid = checkpoint.checkpoint_id

        # 1. Capture parent state snapshot before restart
        parent_snapshot = None
        if controller is not None and hasattr(controller, "snapshot"):
            parent_snapshot = controller.snapshot()
        else:
            try:
                from .execution import GdbBackend
                backend = GdbBackend(self.gdb)
                parent_snapshot = backend.snapshot()
            except Exception as exc:
                res = {
                    "deterministic": False,
                    "status": "FAILED",
                    "reason": f"PARENT_SNAPSHOT_FAILED: {exc}",
                    "mismatches": [],
                }
                self.last_determinism_result = res
                return res

        parent_hash = compute_state_hash(parent_snapshot)

        # 2. Perform restore/restart
        try:
            self.restore(checkpoint)
        except Exception as exc:
            res = {
                "deterministic": False,
                "status": "FAILED",
                "parent_state_hash": parent_hash,
                "restored_state_hash": None,
                "mismatches": [],
                "reason": f"RESTART_REPRODUCTION_FAILED: {exc}",
            }
            self.last_determinism_result = res
            if hasattr(checkpoint, "determinism") and isinstance(checkpoint.determinism, dict):
                checkpoint.determinism["status"] = "FAILED"
                checkpoint.determinism["reason"] = str(exc)
            return res

        # 3. Capture restored state snapshot after restart
        restored_snapshot = None
        if controller is not None and hasattr(controller, "snapshot"):
            restored_snapshot = controller.snapshot()
        else:
            try:
                from .execution import GdbBackend
                backend = GdbBackend(self.gdb)
                restored_snapshot = backend.snapshot()
            except Exception as exc:
                res = {
                    "deterministic": False,
                    "status": "FAILED",
                    "parent_state_hash": parent_hash,
                    "restored_state_hash": None,
                    "mismatches": [],
                    "reason": f"RESTORED_SNAPSHOT_FAILED: {exc}",
                }
                self.last_determinism_result = res
                return res

        restored_hash = compute_state_hash(restored_snapshot)

        # 4. Compare parent and restored state hashes
        if parent_hash == restored_hash:
            res = {
                "deterministic": True,
                "status": "VERIFIED",
                "parent_state_hash": parent_hash,
                "restored_state_hash": restored_hash,
                "mismatches": [],
            }
            if hasattr(checkpoint, "determinism") and isinstance(checkpoint.determinism, dict):
                checkpoint.determinism["status"] = "VERIFIED"
                checkpoint.determinism["verified_at"] = time.time()
            self.last_determinism_result = res
            return res
        else:
            mismatches = []
            if controller is not None and hasattr(controller, "diff"):
                try:
                    diff = controller.diff(parent_snapshot, restored_snapshot)
                    diff_dict = diff.to_dict() if hasattr(diff, "to_dict") else diff
                    for obj_diff in diff_dict.get("objects", []):
                        oid = obj_diff.get("object_id")
                        for fd in obj_diff.get("field_diffs", []):
                            mismatches.append({
                                "path": f"{oid}.{fd.get('field_path')}",
                                "before": fd.get("value_before"),
                                "after": fd.get("value_after"),
                            })
                except Exception:
                    pass

            res = {
                "deterministic": False,
                "status": "NON_DETERMINISTIC",
                "parent_state_hash": parent_hash,
                "restored_state_hash": restored_hash,
                "mismatches": mismatches,
                "reason": "NON_DETERMINISTIC_RUNTIME_STATE",
            }
            if hasattr(checkpoint, "determinism") and isinstance(checkpoint.determinism, dict):
                checkpoint.determinism["status"] = "NON_DETERMINISTIC"
                checkpoint.determinism["verified_at"] = time.time()
                checkpoint.determinism["reason"] = "NON_DETERMINISTIC_RUNTIME_STATE"
            self.last_determinism_result = res
            return res

    def verify_tls_determinism(self, tls_vars: Optional[List[str]] = None) -> Dict[str, Any]:
        """Verify thread-local storage across all threads in the inferior."""
        var_names = tls_vars or ["t_thread_id", "t_worker_counter", "t_worker_state"]
        result = {}
        try:
            inf = self.gdb.selected_inferior()
            threads = inf.threads()
            for t in threads:
                t.switch()
                t_num = getattr(t, "num", 0)
                t_dict = {}
                for v in var_names:
                    try:
                        val = self.gdb.parse_and_eval(v)
                        t_dict[v] = int(val) if str(val).lstrip("-").isdigit() else str(val)
                    except Exception as exc:
                        t_dict[v] = f"UNAVAILABLE: {exc}"
                result[t_num] = t_dict
            has_error = any("UNAVAILABLE" in str(v) for t in result.values() for v in t.values())
            return {
                "status": "UNKNOWN" if has_error else "VERIFIED",
                "threads": len(threads),
                "tls_values": result,
                "reason": "TLS lookup partially unavailable" if has_error else None,
            }
        except Exception as exc:
            return {
                "status": "UNKNOWN",
                "threads": 0,
                "reason": f"TLS lookup unsupported or failed: {exc}",
                "tls_values": {},
            }


class AdaptiveGdbRestorer(StateRestorer):
    """Adaptive restorer that routes between GdbCheckpointRestorer, RestartBasedRestorer, and NullRestorer."""

    def __init__(self, controller, breakpoint_spec: Optional[str] = None):
        self.controller = controller
        self.gdb = getattr(controller, "gdb", controller)
        self.breakpoint_spec = breakpoint_spec
        self._fork_restorer = GdbCheckpointRestorer(self.gdb)
        self._restart_restorer = RestartBasedRestorer(self.gdb, breakpoint_spec=breakpoint_spec)

    def _get_active_restorer(self, thread_count: int) -> StateRestorer:
        is_attached = getattr(self.controller, "is_attached", False)
        if is_attached:
            if thread_count > 1:
                return NullRestorer(
                    reason="Attached multithreaded target: GDB cannot fork multiple threads and restart is unavailable."
                )
            return self._fork_restorer
        else:
            if thread_count > 1:
                return self._restart_restorer
            return self._fork_restorer

    def get_capability(self, thread_count: int = 1) -> Dict[str, Any]:
        restorer = self._get_active_restorer(thread_count)
        return restorer.get_capability(thread_count)

    def checkpoint(self, checkpoint_id: Optional[str] = None) -> RuntimeCheckpoint:
        thread_count = 1
        try:
            if hasattr(self.gdb, "selected_inferior"):
                inf = self.gdb.selected_inferior()
                thread_count = len(inf.threads())
        except Exception:
            pass
        restorer = self._get_active_restorer(thread_count)
        return restorer.checkpoint(checkpoint_id=checkpoint_id)

    def restore(self, checkpoint: RuntimeCheckpoint) -> None:
        if checkpoint is None or not hasattr(checkpoint, "backend"):
            raise RuntimeError("CHECKPOINT_STATE_INVALID: valid checkpoint descriptor required")
        backend_up = checkpoint.backend.upper()
        if backend_up == "RESTART":
            self._restart_restorer.restore(checkpoint)
        elif backend_up in ("GDB_FORK", "GDB_CHECKPOINT"):
            self._fork_restorer.restore(checkpoint)
        else:
            thread_count = 1
            try:
                if hasattr(self.gdb, "selected_inferior"):
                    inf = self.gdb.selected_inferior()
                    thread_count = len(inf.threads())
            except Exception:
                pass
            restorer = self._get_active_restorer(thread_count)
            restorer.restore(checkpoint)

    def release(self, checkpoint: RuntimeCheckpoint) -> None:
        if checkpoint is None or not hasattr(checkpoint, "backend"):
            return
        if checkpoint.backend.upper() == "RESTART":
            self._restart_restorer.release(checkpoint)
        else:
            self._fork_restorer.release(checkpoint)

    def verify_restart_determinism(self, checkpoint: RuntimeCheckpoint, controller=None) -> Dict[str, Any]:
        ctrl = controller or self.controller
        thread_count = 1
        try:
            if hasattr(self.gdb, "selected_inferior"):
                inf = self.gdb.selected_inferior()
                thread_count = len(inf.threads())
        except Exception:
            pass
        restorer = self._get_active_restorer(thread_count)
        return restorer.verify_restart_determinism(checkpoint, controller=ctrl)

    def verify_tls_determinism(self, tls_vars: Optional[List[str]] = None) -> Dict[str, Any]:
        thread_count = 1
        try:
            if hasattr(self.gdb, "selected_inferior"):
                inf = self.gdb.selected_inferior()
                thread_count = len(inf.threads())
        except Exception:
            pass
        restorer = self._get_active_restorer(thread_count)
        if hasattr(restorer, "verify_tls_determinism"):
            return restorer.verify_tls_determinism(tls_vars=tls_vars)
        return {"status": "UNKNOWN", "threads": thread_count, "reason": "Restorer does not support TLS inspection"}


def create_restorer(controller_or_gdb, mode: str = "auto", breakpoint_spec: Optional[str] = None) -> StateRestorer:
    if mode == "mock":
        return MockStateRestorer()
    gdb_mod = getattr(controller_or_gdb, "gdb", controller_or_gdb)
    if mode == "restart":
        return RestartBasedRestorer(gdb_mod, breakpoint_spec=breakpoint_spec)
    if mode == "gdb_checkpoint":
        return GdbCheckpointRestorer(gdb_mod)
    if mode == "null":
        return NullRestorer()
    return AdaptiveGdbRestorer(controller_or_gdb, breakpoint_spec=breakpoint_spec)

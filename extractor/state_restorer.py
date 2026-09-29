"""Runtime execution state restorer and checkpoint abstraction for Phase 4.

Distinguishes between:
- Semantic Snapshot: JSON artifact observing process semantic state (e.g. S001)
- Runtime Checkpoint: Execution state capable of restoring inferior memory (e.g. C001)
"""

from dataclasses import asdict, dataclass
import re
import time
from typing import Any, Callable, Dict, Optional, Set


@dataclass
class RuntimeCheckpoint:
    """Runtime checkpoint descriptor for restoring execution state."""
    checkpoint_id: str
    backend: str
    metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class StateRestorer:
    """Abstract interface for capturing and restoring runtime execution state."""

    def get_capability(self, thread_count: int = 1) -> Dict[str, Any]:
        return {
            "supported": True,
            "backend": "GENERIC",
            "scope": "MULTITHREAD",
            "threads": thread_count,
            "reason": None,
        }

    def checkpoint(self, checkpoint_id: Optional[str] = None) -> RuntimeCheckpoint:
        raise NotImplementedError

    def restore(self, checkpoint: RuntimeCheckpoint) -> None:
        raise NotImplementedError

    def release(self, checkpoint: RuntimeCheckpoint) -> None:
        pass


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
            "threads": thread_count,
            "reason": self.reason,
        }

    def checkpoint(self, checkpoint_id: Optional[str] = None) -> RuntimeCheckpoint:
        raise RuntimeError(f"CHECKPOINT_UNSUPPORTED: {self.reason}")

    def restore(self, checkpoint: RuntimeCheckpoint) -> None:
        raise RuntimeError(f"RESTORE_UNSUPPORTED: {self.reason}")

    def release(self, checkpoint: RuntimeCheckpoint) -> None:
        pass


class MockStateRestorer(StateRestorer):
    """In-memory mock restorer for unit testing and simulation."""

    def __init__(self, capture_fn: Optional[Callable[[], Any]] = None,
                 restore_fn: Optional[Callable[[Any], None]] = None,
                 max_checkpoints: int = 10):
        self.capture_fn = capture_fn
        self.restore_fn = restore_fn
        self.max_checkpoints = max_checkpoints
        self._counter = 0
        self._store: Dict[str, Any] = {}
        self.checkpoints: Dict[str, RuntimeCheckpoint] = {}
        self.restore_count = 0

    def get_capability(self, thread_count: int = 1) -> Dict[str, Any]:
        return {
            "supported": True,
            "backend": "MOCK",
            "scope": "MULTITHREAD",
            "threads": thread_count,
            "reason": None,
        }

    def checkpoint(self, checkpoint_id: Optional[str] = None) -> RuntimeCheckpoint:
        if len(self.checkpoints) >= self.max_checkpoints:
            raise RuntimeError("CHECKPOINT_LIMIT_REACHED: maximum checkpoint limit ({}) exceeded".format(self.max_checkpoints))
        self._counter += 1
        cid = checkpoint_id or "C{:03d}".format(self._counter)
        saved_data = self.capture_fn() if self.capture_fn else {"mock_state": cid}
        self._store[cid] = saved_data
        cp = RuntimeCheckpoint(
            checkpoint_id=cid,
            backend="mock",
            metadata={"created_at": time.time(), "index": self._counter}
        )
        self.checkpoints[cid] = cp
        return cp

    def restore(self, checkpoint: RuntimeCheckpoint) -> None:
        if checkpoint is None or not hasattr(checkpoint, "checkpoint_id"):
            raise RuntimeError("CHECKPOINT_STATE_INVALID: checkpoint descriptor is required")
        cid = checkpoint.checkpoint_id
        if cid not in self._store:
            raise RuntimeError("CHECKPOINT_NOT_FOUND: checkpoint '{}' not found".format(cid))
        saved_data = self._store[cid]
        if self.restore_fn:
            self.restore_fn(saved_data)
        self.restore_count += 1

    def release(self, checkpoint: RuntimeCheckpoint) -> None:
        if checkpoint is None or not hasattr(checkpoint, "checkpoint_id"):
            raise RuntimeError("CHECKPOINT_STATE_INVALID: checkpoint descriptor is required")
        cid = checkpoint.checkpoint_id
        if cid not in self._store and cid not in self.checkpoints:
            raise RuntimeError("CHECKPOINT_NOT_FOUND: checkpoint '{}' not registered".format(cid))
        self._store.pop(cid, None)
        self.checkpoints.pop(cid, None)


class GdbCheckpointRestorer(StateRestorer):
    """GDB-native fork-based checkpoint and restore engine.

    Uses OS copy-on-write fork via GDB 'checkpoint' command.
    Maintains a master pristine checkpoint and creates disposable worker
    clones for branch-safe candidate mutation execution.
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
            raise RuntimeError("CHECKPOINT_STATE_INVALID: failed to query GDB checkpoints: {}".format(exc))
        result = {}
        for line in out.strip().splitlines():
            line_str = line.strip()
            if not line_str or line_str.startswith("No checkpoints"):
                continue
            # Regex to match: optional '*' followed by checkpoint ID (can be 0, 1, 1.1, etc.)
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
                "threads": thread_count,
                "reason": f"GDB fork checkpoint cannot checkpoint multiple threads ({thread_count} active threads).",
            }
        return {
            "supported": True,
            "backend": "GDB_CHECKPOINT",
            "scope": "SINGLE_THREAD_ONLY",
            "threads": thread_count,
            "reason": None,
        }

    def checkpoint(self, checkpoint_id: Optional[str] = None) -> RuntimeCheckpoint:
        """Create a new GDB fork checkpoint."""
        if len(self._checkpoints) >= self.max_checkpoints:
            raise RuntimeError("CHECKPOINT_LIMIT_REACHED: maximum checkpoint limit ({}) exceeded".format(self.max_checkpoints))

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
            raise RuntimeError("CHECKPOINT_STATE_INVALID: {}".format(exc))

        self._counter += 1
        cid = checkpoint_id or "C{:03d}".format(self._counter)

        before = set(self._list_gdb_checkpoints().keys())
        try:
            self.gdb.execute("checkpoint")
        except Exception as exc:
            raise RuntimeError("CHECKPOINT_CREATE_FAILED: GDB execution error: {}".format(exc))

        after = set(self._list_gdb_checkpoints().keys())
        diff = after - before
        if not diff:
            # Checkpoint 0 might have been created as initial checkpoint
            if "0" in after and "0" not in before:
                new_gdb_id = "0"
            elif after:
                # Fallback to the latest checkpoint present
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
            metadata={"gdb_id": str(new_gdb_id)}
        )

    def restore(self, checkpoint: RuntimeCheckpoint) -> None:
        """Restore inferior execution context to a clean clone of the checkpoint."""
        if checkpoint is None or not hasattr(checkpoint, "checkpoint_id"):
            raise RuntimeError("CHECKPOINT_STATE_INVALID: checkpoint descriptor is required")

        cid = checkpoint.checkpoint_id
        if cid not in self._checkpoints:
            raise RuntimeError("CHECKPOINT_NOT_FOUND: checkpoint '{}' not found".format(cid))

        record = self._checkpoints[cid]
        master_id = record["master_gdb_id"]

        cps = self._list_gdb_checkpoints()
        if master_id not in cps:
            raise RuntimeError("CHECKPOINT_RESTORE_FAILED: master checkpoint {} does not exist in GDB".format(master_id))

        # Clean up any existing worker clone from a previous mutation
        old_worker = record.get("active_worker_gdb_id")
        if old_worker is not None and old_worker in cps:
            try:
                self.gdb.execute("restart {}".format(master_id))
                self.gdb.execute("delete checkpoint {}".format(old_worker))
            except Exception:
                pass
            record["active_worker_gdb_id"] = None

        # 1. Switch back to master checkpoint
        try:
            self.gdb.execute("restart {}".format(master_id))
        except Exception as exc:
            raise RuntimeError("CHECKPOINT_RESTORE_FAILED: cannot restart master checkpoint {}: {}".format(master_id, exc))

        # 2. Fork a disposable worker clone from master
        before = set(self._list_gdb_checkpoints().keys())
        try:
            self.gdb.execute("checkpoint")
        except Exception as exc:
            raise RuntimeError("CHECKPOINT_RESTORE_FAILED: cannot clone worker from master {}: {}".format(master_id, exc))

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
            self.gdb.execute("restart {}".format(worker_id))
            record["active_worker_gdb_id"] = str(worker_id)
        except Exception as exc:
            raise RuntimeError("CHECKPOINT_RESTORE_FAILED: cannot switch to worker clone {}: {}".format(worker_id, exc))

    def release(self, checkpoint: RuntimeCheckpoint) -> None:
        """Release and clean up GDB fork processes for this checkpoint."""
        if checkpoint is None or not hasattr(checkpoint, "checkpoint_id"):
            raise RuntimeError("CHECKPOINT_STATE_INVALID: checkpoint descriptor is required")

        cid = checkpoint.checkpoint_id
        record = self._checkpoints.pop(cid, None)
        if not record:
            raise RuntimeError("CHECKPOINT_NOT_FOUND: checkpoint '{}' not registered".format(cid))

        cps = self._list_gdb_checkpoints()
        worker_id = record.get("active_worker_gdb_id")
        master_id = record.get("master_gdb_id")

        # 1. Switch to master to delete worker clone
        if worker_id is not None and worker_id in cps:
            if master_id is not None and master_id in cps:
                try:
                    self.gdb.execute("restart {}".format(master_id))
                except Exception:
                    pass
            try:
                self.gdb.execute("delete checkpoint {}".format(worker_id))
            except Exception:
                pass

        # 2. Switch away from master to delete master checkpoint
        cps = self._list_gdb_checkpoints()
        other_ids = [gid for gid in cps if gid != master_id]
        if other_ids:
            target_switch = "0" if "0" in other_ids else other_ids[0]
            try:
                self.gdb.execute("restart {}".format(target_switch))
            except Exception:
                pass
            if master_id is not None and master_id in cps:
                try:
                    self.gdb.execute("delete checkpoint {}".format(master_id))
                except Exception:
                    pass


class RestartBasedRestorer(StateRestorer):
    """Deterministic restart-based state restorer for multithreaded targets.

    Provides true branch isolation for multithreaded programs launched by GDB.
    When restoring, re-runs the program from entry to the observation breakpoint,
    cleanly resetting all threads, stacks, TLS, and synchronization primitives.
    """

    def __init__(self, gdb_module, breakpoint_spec: Optional[str] = None):
        self.gdb = gdb_module
        self.breakpoint_spec = breakpoint_spec
        self._counter = 0
        self._checkpoints: Dict[str, Dict[str, Any]] = {}

    def get_capability(self, thread_count: int = 1) -> Dict[str, Any]:
        return {
            "supported": True,
            "backend": "RESTART",
            "scope": "MULTITHREAD",
            "threads": thread_count,
            "reason": None,
        }

    def _ensure_breakpoint(self, spec: str):
        try:
            self.gdb.execute("set confirm off")
            self.gdb.execute(f"break {spec}")
        except Exception:
            pass

    def _resolve_breakpoint_spec(self) -> str:
        if self.breakpoint_spec:
            return self.breakpoint_spec
        try:
            frame = self.gdb.selected_frame()
            name = frame.name()
            if name:
                self.breakpoint_spec = name
                return name
            sal = frame.find_sal()
            if sal and sal.symtab and sal.line:
                self.breakpoint_spec = f"{sal.symtab.filename}:{sal.line}"
                return self.breakpoint_spec
            pc = frame.pc()
            self.breakpoint_spec = f"*{hex(pc)}"
            return self.breakpoint_spec
        except Exception:
            pass
        return "observation_checkpoint"

    def checkpoint(self, checkpoint_id: Optional[str] = None) -> RuntimeCheckpoint:
        bp_spec = self._resolve_breakpoint_spec()
        self._ensure_breakpoint(bp_spec)
        self._counter += 1
        cid = checkpoint_id or f"C{self._counter:03d}"
        self._checkpoints[cid] = {
            "checkpoint_id": cid,
            "breakpoint": bp_spec,
            "created_at": time.time(),
        }
        return RuntimeCheckpoint(
            checkpoint_id=cid,
            backend="restart",
            metadata={"breakpoint": bp_spec}
        )

    def restore(self, checkpoint: RuntimeCheckpoint) -> None:
        if checkpoint is None or not hasattr(checkpoint, "checkpoint_id"):
            raise RuntimeError("CHECKPOINT_STATE_INVALID: checkpoint descriptor is required")
        cid = checkpoint.checkpoint_id
        if cid not in self._checkpoints:
            raise RuntimeError(f"CHECKPOINT_NOT_FOUND: checkpoint '{cid}' not found")
        bp_spec = self._checkpoints[cid].get("breakpoint") or self._resolve_breakpoint_spec()
        self._ensure_breakpoint(bp_spec)
        try:
            self.gdb.execute("set confirm off")
            self.gdb.execute("run")
        except Exception as exc:
            raise RuntimeError(f"CHECKPOINT_RESTORE_FAILED: restart failed: {exc}")

    def release(self, checkpoint: RuntimeCheckpoint) -> None:
        if checkpoint is None or not hasattr(checkpoint, "checkpoint_id"):
            return
        self._checkpoints.pop(checkpoint.checkpoint_id, None)


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
        if checkpoint.backend == "restart":
            self._restart_restorer.restore(checkpoint)
        elif checkpoint.backend in ("gdb_fork", "GDB_CHECKPOINT"):
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
        if checkpoint.backend == "restart":
            self._restart_restorer.release(checkpoint)
        else:
            self._fork_restorer.release(checkpoint)


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



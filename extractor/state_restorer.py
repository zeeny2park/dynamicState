"""Runtime execution state restorer and checkpoint abstraction for Phase 4.

Distinguishes between:
- Semantic Snapshot: JSON artifact observing process semantic state (e.g. S001)
- Runtime Checkpoint: Execution state capable of restoring inferior memory (e.g. C001)
"""

from dataclasses import asdict, dataclass
import time
from typing import Any, Callable, Dict, Optional


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

    def checkpoint(self, checkpoint_id: Optional[str] = None) -> RuntimeCheckpoint:
        raise NotImplementedError

    def restore(self, checkpoint: RuntimeCheckpoint) -> None:
        raise NotImplementedError

    def release(self, checkpoint: RuntimeCheckpoint) -> None:
        pass


class MockStateRestorer(StateRestorer):
    """In-memory mock restorer for unit testing and simulation."""

    def __init__(self, capture_fn: Optional[Callable[[], Any]] = None,
                 restore_fn: Optional[Callable[[Any], None]] = None):
        self.capture_fn = capture_fn
        self.restore_fn = restore_fn
        self._counter = 0
        self._store: Dict[str, Any] = {}
        self.checkpoints: Dict[str, RuntimeCheckpoint] = {}
        self.restore_count = 0

    def checkpoint(self, checkpoint_id: Optional[str] = None) -> RuntimeCheckpoint:
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
        cid = checkpoint.checkpoint_id
        if cid not in self._store:
            raise RuntimeError("CHECKPOINT_NOT_FOUND: {}".format(cid))
        saved_data = self._store[cid]
        if self.restore_fn:
            self.restore_fn(saved_data)
        self.restore_count += 1

    def release(self, checkpoint: RuntimeCheckpoint) -> None:
        cid = checkpoint.checkpoint_id
        self._store.pop(cid, None)
        self.checkpoints.pop(cid, None)


class GdbCheckpointRestorer(StateRestorer):
    """GDB-native fork-based checkpoint and restore engine.

    Uses OS copy-on-write fork via GDB 'checkpoint' command.
    Maintains a master pristine checkpoint and creates disposable worker
    clones for branch-safe candidate mutation execution.
    """

    def __init__(self, gdb_module):
        self.gdb = gdb_module
        self._counter = 0
        self._checkpoints: Dict[str, Dict[str, Any]] = {}

    def _list_gdb_checkpoints(self) -> Dict[int, Dict[str, Any]]:
        """Parse GDB 'info checkpoints' output."""
        try:
            out = self.gdb.execute("info checkpoints", to_string=True)
        except Exception:
            return {}
        result = {}
        for line in out.strip().splitlines():
            line_str = line.strip()
            if not line_str or line_str.startswith("No checkpoints"):
                continue
            parts = line_str.split()
            if not parts:
                continue
            is_cur = parts[0] == "*"
            idx_str = parts[1] if is_cur else parts[0]
            if idx_str.isdigit():
                result[int(idx_str)] = {"current": is_cur, "line": line_str}
        return result

    def checkpoint(self, checkpoint_id: Optional[str] = None) -> RuntimeCheckpoint:
        """Create a new GDB fork checkpoint."""
        self._counter += 1
        cid = checkpoint_id or "C{:03d}".format(self._counter)

        before = set(self._list_gdb_checkpoints().keys())
        try:
            self.gdb.execute("checkpoint")
        except Exception as exc:
            raise RuntimeError("GDB_CHECKPOINT_FAILED: {}".format(exc))

        after = set(self._list_gdb_checkpoints().keys())
        diff = after - before
        if not diff:
            # Checkpoint 0 might have been created
            new_gdb_id = 0 if (0 in after and 0 not in before) else (max(after) if after else 0)
        else:
            new_gdb_id = list(diff)[0]

        cp_record = {
            "checkpoint_id": cid,
            "master_gdb_id": new_gdb_id,
            "active_worker_gdb_id": None
        }
        self._checkpoints[cid] = cp_record

        return RuntimeCheckpoint(
            checkpoint_id=cid,
            backend="gdb_fork",
            metadata={"gdb_id": new_gdb_id}
        )

    def restore(self, checkpoint: RuntimeCheckpoint) -> None:
        """Restore inferior execution context to a clean clone of the checkpoint."""
        cid = checkpoint.checkpoint_id
        if cid not in self._checkpoints:
            raise RuntimeError("CHECKPOINT_NOT_FOUND: {}".format(cid))

        record = self._checkpoints[cid]
        master_id = record["master_gdb_id"]

        # Clean up any existing worker clone
        old_worker = record.get("active_worker_gdb_id")
        cps = self._list_gdb_checkpoints()
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
            raise RuntimeError("GDB_RESTART_FAILED: cannot restore master checkpoint {}: {}".format(master_id, exc))

        # 2. Fork a disposable worker clone from master
        before = set(self._list_gdb_checkpoints().keys())
        try:
            self.gdb.execute("checkpoint")
        except Exception as exc:
            raise RuntimeError("GDB_WORKER_CLONE_FAILED: {}".format(exc))

        after = set(self._list_gdb_checkpoints().keys())
        diff = after - before
        worker_id = list(diff)[0] if diff else master_id

        # 3. Switch to worker clone for candidate execution
        try:
            self.gdb.execute("restart {}".format(worker_id))
            record["active_worker_gdb_id"] = worker_id
        except Exception as exc:
            raise RuntimeError("GDB_SWITCH_WORKER_FAILED: {}".format(exc))

    def release(self, checkpoint: RuntimeCheckpoint) -> None:
        """Release and clean up GDB fork processes for this checkpoint."""
        cid = checkpoint.checkpoint_id
        record = self._checkpoints.pop(cid, None)
        if not record:
            return

        cps = self._list_gdb_checkpoints()
        worker_id = record.get("active_worker_gdb_id")
        master_id = record.get("master_gdb_id")

        for gid in [worker_id, master_id]:
            if gid is not None and gid in cps:
                try:
                    self.gdb.execute("delete checkpoint {}".format(gid))
                except Exception:
                    pass

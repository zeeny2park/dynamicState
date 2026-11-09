"""Phase 23: Target Execution Adapter Abstraction.

Separates target host operations (process identity, liveness, maps, threads,
memory reading) from local host operations.

Enforces:
1. Strict namespace separation: a remote PID is interpreted exclusively on the
   target host; local /proc is never touched for remote targets.
2. Safe argument encoding: all remote commands use shlex.quote.
3. Robust transport error handling: explicit timeouts, connection failures,
   cancellation, and graceful termination.
4. Embedded target friendliness: zero Python or debugger required on the target.
   Build ID and architecture are verified host-side from ELF header bytes.
"""

from abc import ABC, abstractmethod
import base64
import contextlib
import contextvars
from dataclasses import dataclass, field
import errno
import hashlib
import json
import os
import re
import shlex
import subprocess
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
import uuid

from .debug_image import BinaryIdentity, inspect_elf



def _parse_cpulist(cpulist_str: str) -> List[int]:
    """Parses Linux CPU list format (e.g. '2', '0,2-4') into a sorted list of CPU IDs."""
    cpus: List[int] = []
    if not cpulist_str:
        return cpus
    for part in cpulist_str.strip().split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            bounds = part.split("-", 1)
            try:
                lo, hi = int(bounds[0]), int(bounds[1])
                if 0 <= lo <= hi and (hi - lo) <= 1024:
                    cpus.extend(range(lo, hi + 1))
            except ValueError:
                pass
        else:
            try:
                cpus.append(int(part))
            except ValueError:
                pass
    return sorted(set(cpus))


def _get_kernel_isolated_cpus() -> List[int]:
    """Reads /sys/devices/system/cpu/isolated and /sys/devices/system/cpu/nohz_full."""
    isolated: List[int] = []
    for sys_path in ("/sys/devices/system/cpu/isolated", "/sys/devices/system/cpu/nohz_full"):
        try:
            if os.path.exists(sys_path):
                with open(sys_path, "r", encoding="utf-8") as f:
                    isolated.extend(_parse_cpulist(f.read().strip()))
        except Exception:
            pass
    return sorted(set(isolated))


class TargetIdentityChangedError(RuntimeError):
    """Raised when a pinned target PID is reused or executes a different binary."""


class PIDReusedError(TargetIdentityChangedError):
    """Raised when target PID reuse is detected during or after capture operations."""


_current_capture_tx: contextvars.ContextVar[Optional["CaptureTransaction"]] = contextvars.ContextVar("_current_capture_tx", default=None)
_tx_stack: contextvars.ContextVar[List["CaptureTransaction"]] = contextvars.ContextVar("_tx_stack", default=None)


@dataclass
class CaptureTransaction:
    """Explicit capture transaction scoping physical reads, binding receipts, and verifying target identity invariants."""
    transaction_id: str
    session_id: str
    pid: int
    operation_type: str = "diagnostic"  # "diagnostic" or "probe"
    target_host: str = "localhost"
    adapter_id: str = ""
    snapshot_binding: str = ""
    start_time_ns: int = 0
    end_time_ns: int = 0
    pre_identity: Dict[str, Any] = field(default_factory=dict)
    post_identity: Dict[str, Any] = field(default_factory=dict)
    physical_reads_count: int = 0
    physical_bytes_read: int = 0
    read_payloads: List[bytes] = field(default_factory=list)
    read_operations: List[Dict[str, Any]] = field(default_factory=list)
    committed: bool = False
    aborted: bool = False
    abort_reason: Optional[str] = None
    receipt_issued: bool = False

    @property
    def observation_digest(self) -> str:
        if not self.read_operations and not self.read_payloads:
            return ""
        target_ident = {
            "pid": int(self.pid),
            "process_identity": str(self.pre_identity.get("process_identity", "")),
            "executable_identity": str(self.pre_identity.get("executable_identity") or self.pre_identity.get("executable", "")),
            "build_id": str(self.pre_identity.get("build_id", "")),
            "target_host": str(self.target_host),
            "adapter_id": str(self.adapter_id),
        }
        if self.read_operations:
            read_seq = [
                {
                    "address": int(op.get("address", 0)),
                    "requested_size": int(op.get("requested_size", 0)),
                    "actual_bytes_read": int(op.get("actual_bytes_read", len(op.get("data", b"")))),
                    "status": str(op.get("status", "OBSERVED")),
                    "payload_sha256": hashlib.sha256(op.get("data", b"")).hexdigest(),
                }
                for op in self.read_operations
            ]
        else:
            read_seq = [
                {
                    "address": 0,
                    "requested_size": len(p),
                    "actual_bytes_read": len(p),
                    "status": "OBSERVED",
                    "payload_sha256": hashlib.sha256(p).hexdigest(),
                }
                for p in self.read_payloads
            ]
        canonical_obj = {
            "target_identity": target_ident,
            "operation_id": str(self.transaction_id),
            "operation_type": str(self.operation_type),
            "read_sequence": read_seq,
        }
        raw_json = json.dumps(canonical_obj, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(raw_json).hexdigest()


class TargetExecutionAdapter(ABC):
    """Abstract interface for interacting with a local or remote target process."""

    def _ensure_tracking_state(self) -> None:
        if not hasattr(self, "_adapter_id"):
            self._adapter_id: str = f"adapter_{uuid.uuid4().hex[:12]}"
        if not hasattr(self, "_physical_reads_count"):
            self._physical_reads_count: int = 0
        if not hasattr(self, "_physical_bytes_read"):
            self._physical_bytes_read: int = 0
        if not hasattr(self, "_unscoped_physical_reads_count"):
            self._unscoped_physical_reads_count: int = 0
        if not hasattr(self, "_unscoped_physical_bytes_read"):
            self._unscoped_physical_bytes_read: int = 0
        if not hasattr(self, "_capture_epoch"):
            self._capture_epoch: int = 0
        if not hasattr(self, "_pinned_identities"):
            self._pinned_identities: Dict[int, Dict[str, Any]] = {}
        if not hasattr(self, "_observation_dedup_cache"):
            self._observation_dedup_cache: Dict[Tuple[int, str, int, int, int], Tuple[Optional[bytes], str, Optional[str]]] = {}
        if not hasattr(self, "_issued_live_receipts"):
            self._issued_live_receipts: List[Any] = []
        if not hasattr(self, "_last_committed_transaction"):
            self._last_committed_transaction: Optional[CaptureTransaction] = None
        if not hasattr(self, "_active_transactions"):
            self._active_transactions: Dict[str, CaptureTransaction] = {}
        if not hasattr(self, "_committed_transactions"):
            self._committed_transactions: Dict[str, CaptureTransaction] = {}
        if not hasattr(self, "_active_by_scope"):
            self._active_by_scope: Dict[Tuple[str, str, int], CaptureTransaction] = {}
        if not hasattr(self, "_auto_transaction"):
            self._auto_transaction: Optional[CaptureTransaction] = None

    @property
    def adapter_id(self) -> str:
        self._ensure_tracking_state()
        return self._adapter_id

    @property
    def _active_transaction(self) -> Optional[CaptureTransaction]:
        self._ensure_tracking_state()
        ctx_tx = _current_capture_tx.get(None)
        if ctx_tx is not None and ctx_tx.adapter_id == self.adapter_id and not ctx_tx.committed and not ctx_tx.aborted:
            return ctx_tx
        if len(self._active_transactions) == 1:
            tx = next(iter(self._active_transactions.values()))
            if not tx.committed and not tx.aborted:
                return tx
        return None

    @_active_transaction.setter
    def _active_transaction(self, val: Optional[CaptureTransaction]) -> None:
        self._ensure_tracking_state()
        if val is not None:
            self._active_transactions[val.transaction_id] = val
            _current_capture_tx.set(val)
        else:
            ctx_tx = _current_capture_tx.get(None)
            if ctx_tx is not None:
                self._active_transactions.pop(ctx_tx.transaction_id, None)
                _current_capture_tx.set(None)

    @property
    def physical_reads_count(self) -> int:
        self._ensure_tracking_state()
        return self._physical_reads_count

    @property
    def cumulative_physical_bytes_read(self) -> int:
        self._ensure_tracking_state()
        return self._physical_bytes_read

    @property
    def physical_bytes_read(self) -> int:
        self._ensure_tracking_state()
        return self._physical_bytes_read

    @property
    def unscoped_physical_reads_count(self) -> int:
        self._ensure_tracking_state()
        return self._unscoped_physical_reads_count

    @property
    def unscoped_physical_bytes_read(self) -> int:
        self._ensure_tracking_state()
        return self._unscoped_physical_bytes_read

    @property
    def capture_epoch(self) -> int:
        self._ensure_tracking_state()
        return self._capture_epoch

    def advance_epoch(self) -> int:
        self._ensure_tracking_state()
        self._capture_epoch += 1
        return self._capture_epoch

    def reset_accounting(self) -> None:
        self._ensure_tracking_state()
        if self._active_transactions:
            active_ids = list(self._active_transactions.keys())
            raise RuntimeError(
                f"Cannot reset accounting while capture transactions are active ({len(active_ids)} active: {active_ids[:3]}). "
                f"Transactions must be committed or rolled back prior to resetting accounting."
            )
        self._physical_reads_count = 0
        self._physical_bytes_read = 0
        self._unscoped_physical_reads_count = 0
        self._unscoped_physical_bytes_read = 0
        self._observation_dedup_cache.clear()
        self._issued_live_receipts.clear()
        self._last_committed_transaction = None
        self._committed_transactions.clear()
        self._active_by_scope.clear()
        self._auto_transaction = None
        _current_capture_tx.set(None)
        _tx_stack.set([])

    def _record_physical_read(
        self,
        num_bytes: int,
        num_reads: int = 1,
        data: Optional[bytes] = None,
        pid: Optional[int] = None,
        address: int = 0,
        requested_size: Optional[int] = None,
        status: str = "OBSERVED",
        transaction: Optional[CaptureTransaction] = None,
    ) -> None:
        self._ensure_tracking_state()

        eff_tx: Optional[CaptureTransaction] = None
        if transaction is not None:
            if transaction.adapter_id and transaction.adapter_id != self.adapter_id:
                raise ValueError(
                    f"Transaction ownership mismatch: transaction '{transaction.transaction_id}' "
                    f"belongs to adapter '{transaction.adapter_id}', not '{self.adapter_id}'"
                )
            if transaction.aborted:
                raise ValueError(
                    f"Cannot record physical read on aborted capture transaction '{transaction.transaction_id}': {transaction.abort_reason}"
                )
            if transaction.committed:
                raise ValueError(
                    f"Cannot record physical read on committed capture transaction '{transaction.transaction_id}'"
                )
            eff_tx = transaction
        else:
            ctx_tx = _current_capture_tx.get(None)
            if ctx_tx is not None and not ctx_tx.committed and not ctx_tx.aborted:
                if ctx_tx.adapter_id == self.adapter_id:
                    if pid is None or int(ctx_tx.pid) == int(pid):
                        eff_tx = ctx_tx
            if eff_tx is None and pid is not None:
                # Check thread-local transaction context stack for active transaction on this adapter and PID
                cur_stack = _tx_stack.get(None) or []
                for t in reversed(cur_stack):
                    if t.adapter_id == self.adapter_id and not t.committed and not t.aborted:
                        if int(t.pid) == int(pid):
                            eff_tx = t
                            break

        # Mutate accounting counters only AFTER transaction validation passes
        if num_reads > 0:
            self._physical_reads_count += int(num_reads)
        if num_bytes > 0:
            self._physical_bytes_read += int(num_bytes)

        if eff_tx is not None:
            if num_reads > 0:
                eff_tx.physical_reads_count += int(num_reads)
            if num_bytes > 0:
                eff_tx.physical_bytes_read += int(num_bytes)
            if data is not None:
                eff_tx.read_payloads.append(data)
                eff_tx.read_operations.append({
                    "address": int(address),
                    "requested_size": int(requested_size if requested_size is not None else num_bytes),
                    "actual_bytes_read": len(data),
                    "status": str(status),
                    "data": data,
                })
        else:
            # Unscoped physical reads remain strictly unscoped.
            # No automatic production transaction is created.
            if num_reads > 0:
                self._unscoped_physical_reads_count += int(num_reads)
            if num_bytes > 0:
                self._unscoped_physical_bytes_read += int(num_bytes)

    def begin_capture_transaction(
        self,
        session_id: str,
        pid: int,
        operation_type: str = "diagnostic",
        snapshot_binding: Optional[str] = None,
    ) -> CaptureTransaction:
        """Begin a scoped capture transaction for target process memory operations."""
        self._ensure_tracking_state()
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 1:
            raise ValueError(f"Invalid target PID {pid} (must be integer > 1)")
        alive, live_err = self.check_liveness(pid)
        if not alive:
            raise ProcessLookupError(f"Cannot begin capture transaction: target PID {pid} is not alive: {live_err}")

        if int(pid) in self._pinned_identities:
            ok_pin, pin_err = self.verify_pinned_identity(int(pid))
            if not ok_pin:
                raise PIDReusedError(f"Cannot begin capture transaction: {pin_err}")
            ident = self._pinned_identities[int(pid)]
        else:
            ident = self.pin_target_identity(int(pid))

        th = self.target_host() if hasattr(self, "target_host") else "localhost"
        tx = CaptureTransaction(
            transaction_id=f"ctx_{uuid.uuid4().hex[:12]}",
            session_id=str(session_id),
            pid=int(pid),
            operation_type=str(operation_type),
            target_host=str(th),
            adapter_id=self.adapter_id,
            snapshot_binding=snapshot_binding or f"live_reads:{pid}:epoch_{self._capture_epoch}",
            start_time_ns=time.time_ns(),
            pre_identity=dict(ident),
        )
        self._active_transactions[tx.transaction_id] = tx
        self._active_by_scope[(str(th), str(session_id), int(pid))] = tx

        cur_stack = _tx_stack.get(None) or []
        new_stack = list(cur_stack) + [tx]
        _tx_stack.set(new_stack)
        _current_capture_tx.set(tx)
        return tx

    def commit_capture_transaction(
        self,
        tx: Optional[CaptureTransaction] = None,
    ) -> CaptureTransaction:
        """Commit an active capture transaction, verifying target identity post-capture."""
        self._ensure_tracking_state()
        target_tx = tx or _current_capture_tx.get(None)
        if not target_tx or target_tx.aborted:
            raise ValueError("No active or valid capture transaction to commit")
        if target_tx.adapter_id and target_tx.adapter_id != self.adapter_id:
            raise ValueError(
                f"Transaction ownership mismatch: transaction '{target_tx.transaction_id}' "
                f"belongs to adapter '{target_tx.adapter_id}', not '{self.adapter_id}'"
            )
        if target_tx.committed:
            return target_tx

        cur_stack = _tx_stack.get(None) or []
        if cur_stack and target_tx in cur_stack:
            idx = cur_stack.index(target_tx)
            for inner_tx in cur_stack[idx + 1:]:
                if inner_tx.pid == target_tx.pid and inner_tx.session_id == target_tx.session_id:
                    if not inner_tx.committed and not inner_tx.aborted:
                        raise ValueError(
                            f"Cannot commit outer transaction '{target_tx.transaction_id}' while nested inner transaction '{inner_tx.transaction_id}' is active"
                        )

        cur_ident = self.get_process_identity(target_tx.pid)
        alive, live_err = self.check_liveness(target_tx.pid)
        if not alive:
            self.rollback_capture_transaction(target_tx, f"Target process exited during capture: {live_err}")
            raise ProcessLookupError(f"Target process {target_tx.pid} terminated during capture: {live_err}")

        ok_pin, pin_err = self.verify_pinned_identity(target_tx.pid)
        if not ok_pin:
            self.rollback_capture_transaction(target_tx, f"Pinned identity changed: {pin_err}")
            raise PIDReusedError(f"Pinned identity changed during capture transaction on PID {target_tx.pid}: {pin_err}")

        for mandatory_field in ("start_time", "executable"):
            pre_val = target_tx.pre_identity.get(mandatory_field)
            cur_val = cur_ident.get(mandatory_field)
            if not pre_val or not cur_val:
                self.rollback_capture_transaction(target_tx, f"Missing mandatory identity field '{mandatory_field}'")
                raise PIDReusedError(
                    f"Missing mandatory identity field '{mandatory_field}' on PID {target_tx.pid} during capture transaction commit (pre={pre_val!r}, cur={cur_val!r})"
                )

        for field_name, err_name in [
            ("start_time", "start_time changed"),
            ("boot_id", "boot_id changed"),
            ("executable", "Executable replaced"),
            ("exe_inode", "Executable inode changed"),
        ]:
            pre_val = target_tx.pre_identity.get(field_name)
            cur_val = cur_ident.get(field_name)
            if pre_val and cur_val and str(pre_val) != str(cur_val):
                self.rollback_capture_transaction(target_tx, f"{err_name} during capture transaction")
                raise PIDReusedError(
                    f"{err_name} on PID {target_tx.pid}: {pre_val} -> {cur_val}"
                )

        pre_bid = target_tx.pre_identity.get("build_id")
        cur_bid = cur_ident.get("build_id")
        if pre_bid and cur_bid and str(pre_bid).strip().lower() != str(cur_bid).strip().lower():
            self.rollback_capture_transaction(target_tx, "Build ID changed during capture transaction")
            raise PIDReusedError(
                f"Build ID changed on PID {target_tx.pid}: {pre_bid} -> {cur_bid}"
            )

        th = self.target_host() if hasattr(self, "target_host") else "localhost"
        if str(target_tx.target_host) != str(th):
            self.rollback_capture_transaction(target_tx, "Target host changed during capture transaction")
            raise PIDReusedError(
                f"Target host changed during capture transaction: {target_tx.target_host} -> {th}"
            )

        if target_tx.physical_bytes_read <= 0:
            self.rollback_capture_transaction(target_tx, "Zero physical bytes read during capture transaction")
            raise ValueError(
                f"Capture transaction '{target_tx.transaction_id}' committed with 0 physical bytes read"
            )

        # P0-2: Integrate DurableTrustStore.record_used_operation() before committing transaction
        from .capture_backend import get_default_trust_store
        eff_ts = getattr(self, "trust_store", None) or get_default_trust_store()
        if eff_ts:
            op_meta = {
                "process_identity": str(cur_ident.get("process_identity", "")),
                "executable_identity": str(cur_ident.get("executable_identity") or cur_ident.get("executable", "")),
                "build_id": str(cur_ident.get("build_id", "")),
                "target_host": str(th),
                "operation_type": str(target_tx.operation_type),
                "physical_bytes_read": int(target_tx.physical_bytes_read),
                "physical_reads_count": int(target_tx.physical_reads_count),
                "adapter_id": str(self.adapter_id),
            }
            try:
                eff_ts.record_used_operation(
                    op_id=target_tx.transaction_id,
                    session_id=target_tx.session_id,
                    pid=target_tx.pid,
                    metadata=op_meta,
                    allow_idempotent=False,
                )
            except Exception as e:
                self.rollback_capture_transaction(target_tx, f"Trust store persistence failed: {e}")
                raise

        target_tx.post_identity = dict(cur_ident)
        target_tx.end_time_ns = time.time_ns()
        target_tx.committed = True

        self._committed_transactions[target_tx.transaction_id] = target_tx
        self._last_committed_transaction = target_tx
        self._active_transactions.pop(target_tx.transaction_id, None)
        self._active_by_scope.pop((str(target_tx.target_host), str(target_tx.session_id), int(target_tx.pid)), None)

        if cur_stack and target_tx in cur_stack:
            new_stack = [t for t in cur_stack if t.transaction_id != target_tx.transaction_id]
            _tx_stack.set(new_stack)
            _current_capture_tx.set(new_stack[-1] if new_stack else None)

        return target_tx

    def rollback_capture_transaction(
        self,
        tx: Optional[CaptureTransaction] = None,
        reason: str = "",
    ) -> None:
        """Roll back an in-flight capture transaction."""
        self._ensure_tracking_state()
        target_tx = tx or _current_capture_tx.get(None)
        if not target_tx and len(self._active_transactions) == 1:
            target_tx = next(iter(self._active_transactions.values()))
        if target_tx:
            target_tx.aborted = True
            target_tx.abort_reason = reason or "Capture transaction rolled back"
            self._active_transactions.pop(target_tx.transaction_id, None)
            self._active_by_scope.pop((str(target_tx.target_host), str(target_tx.session_id), int(target_tx.pid)), None)
            cur_stack = _tx_stack.get(None) or []
            if cur_stack and target_tx in cur_stack:
                new_stack = [t for t in cur_stack if t.transaction_id != target_tx.transaction_id]
                _tx_stack.set(new_stack)
                _current_capture_tx.set(new_stack[-1] if new_stack else None)

    @contextlib.contextmanager
    def capture_transaction(
        self,
        session_id: str,
        pid: int,
        operation_type: str = "diagnostic",
        snapshot_binding: Optional[str] = None,
    ):
        """Context manager managing an explicit capture transaction lifecycle."""
        tx = self.begin_capture_transaction(session_id, pid, operation_type, snapshot_binding)
        try:
            yield tx
            if not tx.aborted and not tx.committed:
                self.commit_capture_transaction(tx)
        except BaseException as exc:
            if not tx.aborted and not tx.committed:
                self.rollback_capture_transaction(tx, str(exc))
            raise

    def measure_read_latency(
        self,
        pid: int,
        address: int,
        size: int,
        samples: int = 10,
    ) -> Dict[str, Any]:
        """Measure exact physical memory read latency on target using monotonic clocks.

        Uses the documented nearest-rank percentile convention:
            index = max(0, min(ceil(p * N) - 1, N - 1))
        Distinguishes physical read latency, target suspension time, and collector overhead.
        Reports successful and failed sample counts separately.
        Flags mocked executions explicitly.
        """
        import math

        latencies_ms: List[float] = []
        failed_reads: List[Dict[str, Any]] = []
        is_mocked = getattr(self.read_memory, "_is_mock", False) or hasattr(self.read_memory, "mock_calls")

        for s_idx in range(max(1, samples)):
            t0 = time.monotonic_ns()
            data, status, err = self.read_memory(pid, address, size)
            elapsed_ms = (time.monotonic_ns() - t0) / 1_000_000.0
            if status == "OBSERVED":
                latencies_ms.append(elapsed_ms)
            else:
                failed_reads.append({"sample_index": s_idx, "status": status, "error": str(err), "elapsed_ms": elapsed_ms})

        if not latencies_ms:
            return {
                "sample_count": 0,
                "total_samples_attempted": max(1, samples),
                "successful_sample_count": 0,
                "failed_sample_count": len(failed_reads),
                "failed_samples": failed_reads,
                "read_latency_p50_ms": None,
                "read_latency_p95_ms": None,
                "read_latency_max_ms": None,
                "target_suspension_applicable": False,
                "target_suspension_status": "NOT_APPLICABLE",
                "process_suspension_time_ms": None,
                "measurement_method": "monotonic_ns_user_space",
                "percentile_convention": "nearest_rank (ceil(p*N)-1)",
                "is_mocked": is_mocked,
                "hardware_sla_validated": False,
                "notes": "No successful memory reads observed",
            }

        latencies_ms.sort()
        n = len(latencies_ms)
        p50_idx = max(0, min(math.ceil(0.50 * n) - 1, n - 1))
        p95_idx = max(0, min(math.ceil(0.95 * n) - 1, n - 1))
        p50 = latencies_ms[p50_idx]
        p95 = latencies_ms[p95_idx]
        max_lat = latencies_ms[-1]

        return {
            "sample_count": n,
            "samples_collected": n,
            "total_samples_attempted": max(1, samples),
            "successful_sample_count": n,
            "failed_sample_count": len(failed_reads),
            "failed_samples": failed_reads,
            "read_latency_p50_ms": round(p50, 4),
            "read_latency_p95_ms": round(p95, 4),
            "read_latency_max_ms": round(max_lat, 4),
            "physical_read_latency_p50_ms": round(p50, 4),
            "physical_read_latency_p95_ms": round(p95, 4),
            "physical_read_latency_max_ms": round(max_lat, 4),
            "target_suspension_applicable": False,
            "target_suspension_status": "NOT_APPLICABLE",
            "process_suspension_time_ms": None,
            "collector_overhead_ms": 0.0,
            "clock_source": "time.monotonic_ns",
            "measurement_type": "MEASURED",
            "percentile_convention": "nearest_rank (ceil(p*N)-1)",
            "suspension_explanation": "Zero-stop concurrent read (process_vm_readv / procfs mem); target process was not suspended with SIGSTOP",
            "measurement_method": "monotonic_ns_user_space",
            "is_mocked": is_mocked,
            "hardware_sla_validated": bool(not is_mocked and max_lat < 4.5),
            "sla_4_5ms_satisfied": bool(max_lat < 4.5),
        }

    def pin_target_identity(self, pid: int, companion_build_id: Optional[str] = None) -> Dict[str, Any]:
        """Pin target process identity (PID, start_time, boot_id, executable, Build ID) to prevent PID reuse."""
        self._ensure_tracking_state()
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 1:
            raise ValueError(f"Invalid target PID {pid} (must be integer > 1)")
        ident = self.get_process_identity(pid)
        for req_field in ("start_time", "executable"):
            if not ident.get(req_field):
                raise PIDReusedError(
                    f"Cannot pin target identity for PID {pid}: missing mandatory attribute '{req_field}'"
                )
        if companion_build_id:
            ident["companion_build_id"] = str(companion_build_id)
        if companion_build_id and ident.get("build_id"):
            if str(ident["build_id"]).strip().lower() != str(companion_build_id).strip().lower():
                raise ValueError(
                    f"Build ID mismatch for PID {pid}: target={ident['build_id']}, companion={companion_build_id}"
                )
        self._pinned_identities[int(pid)] = dict(ident)
        return ident

    def verify_pinned_identity(self, pid: int) -> Tuple[bool, Optional[str]]:
        """Verify that a pinned target process has not been replaced via PID reuse or execve."""
        self._ensure_tracking_state()
        pinned = self._pinned_identities.get(int(pid))
        if not pinned:
            return True, None
        cur = self.get_process_identity(int(pid))
        for req_field in ("start_time", "executable"):
            p_val = pinned.get(req_field)
            c_val = cur.get(req_field)
            if not p_val or not c_val:
                return False, f"Missing mandatory identity field '{req_field}' on PID {pid} during verification (pinned={p_val!r}, cur={c_val!r})"
            if str(p_val) != str(c_val):
                return False, f"PID reuse detected: target identity changed for '{req_field}' on PID {pid}: {p_val} -> {c_val}"
        if pinned.get("exe_inode") and cur.get("exe_inode") and int(pinned["exe_inode"]) != int(cur["exe_inode"]):
            return False, f"Executable inode changed on PID {pid}: {pinned['exe_inode']} -> {cur['exe_inode']}"
        if pinned.get("build_id") and cur.get("build_id") and str(pinned["build_id"]).strip().lower() != str(cur["build_id"]).strip().lower():
            return False, f"Build ID changed on PID {pid}: {pinned['build_id']} -> {cur['build_id']}"
        return True, None

    def issue_live_receipt_for_session(
        self,
        session_id: str,
        pid: int,
        snapshot_binding: Optional[str] = None,
        companion_build_id: Optional[str] = None,
        transaction: Optional[Union[CaptureTransaction, str]] = None,
    ) -> Any:
        """Issue an authenticated LiveCaptureReceipt bound to verified physical reads performed in a transaction."""
        self._ensure_tracking_state()
        from .capture_backend import get_default_trust_store, get_trusted_capture_authority_token, issue_live_capture_receipt

        tx: Optional[CaptureTransaction] = None
        if transaction is None:
            raise ValueError(
                "Explicit committed CaptureTransaction reference or transaction ID required for live capture receipt issuance; "
                "implicit, single-candidate, and automatic transaction selection is strictly prohibited."
            )
        if isinstance(transaction, str):
            tx = self._committed_transactions.get(transaction)
            if tx is None:
                if transaction in self._active_transactions:
                    raise ValueError(f"Cannot issue live receipt: capture transaction '{transaction}' is active and not committed")
                raise ValueError(f"Capture transaction '{transaction}' not found on adapter")
        else:
            tx = transaction
            if tx.adapter_id and tx.adapter_id != self.adapter_id:
                raise ValueError(
                    f"Transaction ownership mismatch: transaction '{tx.transaction_id}' "
                    f"belongs to adapter '{tx.adapter_id}', not '{self.adapter_id}'"
                )
            if tx.aborted:
                raise ValueError(
                    f"Cannot issue live capture receipt for aborted capture transaction '{tx.transaction_id}': {tx.abort_reason}"
                )
            if not tx.committed:
                raise ValueError(f"Cannot issue live capture receipt for uncommitted capture transaction '{tx.transaction_id}'")
            if tx.transaction_id not in self._committed_transactions:
                raise ValueError(f"Capture transaction '{tx.transaction_id}' is not recorded in adapter committed transactions")

        if tx.adapter_id and tx.adapter_id != self.adapter_id:
            raise ValueError(
                f"Transaction ownership mismatch: transaction '{tx.transaction_id}' "
                f"belongs to adapter '{tx.adapter_id}', not '{self.adapter_id}'"
            )
        if tx.receipt_issued:
            raise ValueError(f"Cannot reuse capture transaction '{tx.transaction_id}': receipt already issued. New physical reads required.")

        if tx.physical_bytes_read <= 0:
            raise ValueError(
                f"Cannot issue live capture receipt for PID {pid}: no physical reads performed in capture transaction (physical_bytes_read={self._physical_bytes_read})"
            )

        if str(tx.session_id) != str(session_id):
            raise ValueError(
                f"Session mismatch for transaction '{tx.transaction_id}': transaction session is '{tx.session_id}', expected '{session_id}'"
            )

        if int(tx.pid) != int(pid):
            raise ValueError(
                f"PID mismatch for transaction '{tx.transaction_id}': transaction PID is {tx.pid}, expected {pid}"
            )

        th = self.target_host() if hasattr(self, "target_host") else "localhost"
        if str(tx.target_host) != str(th):
            raise ValueError(
                f"Target host mismatch for transaction '{tx.transaction_id}': transaction host is '{tx.target_host}', expected '{th}'"
            )

        if not tx.committed:
            raise ValueError(
                f"Cannot issue live capture receipt for uncommitted capture transaction '{tx.transaction_id}'"
            )

        if tx.aborted:
            raise ValueError(
                f"Cannot issue live capture receipt for aborted capture transaction '{tx.transaction_id}': {tx.abort_reason}"
            )

        if tx.receipt_issued:
            raise ValueError(
                f"Cannot reuse capture transaction '{tx.transaction_id}': receipt already issued. New physical reads required."
            )

        if int(pid) in self._pinned_identities:
            ok_pin, pin_err = self.verify_pinned_identity(int(pid))
            if not ok_pin:
                raise ValueError(f"Cannot issue live receipt: pinned identity verification failed: {pin_err}")
            ident = self._pinned_identities[int(pid)]
        else:
            ident = self.get_process_identity(int(pid))
            alive, live_err = self.check_liveness(int(pid))
            if not alive:
                raise ValueError(f"Cannot issue live receipt: process {pid} is not alive or accessible: {live_err}")
            self.pin_target_identity(int(pid))

        proc_id = ident.get("process_identity")
        start_time = ident.get("start_time")
        if not proc_id or not start_time:
            raise ValueError(f"Cannot issue live receipt: missing start_time / verified process identity for PID {pid}")
        if not proc_id or proc_id.startswith(f"{pid}::"):
            proc_id = f"{pid}:{start_time}:{ident.get('boot_id', 'local')}"

        exe_id = ident.get("executable_identity") or ident.get("executable")
        if not exe_id:
            raise ValueError(f"Cannot issue live receipt: missing verified executable identity for PID {pid}")

        bid = ident.get("build_id") or ""
        if companion_build_id:
            if bid and str(bid).strip().lower() != str(companion_build_id).strip().lower():
                raise ValueError(
                    f"Cannot issue live receipt: Build ID mismatch between process ({bid}) and companion ELF ({companion_build_id})"
                )
            if not bid:
                bid = companion_build_id

        is_custom = bool(getattr(self, "_memory_reader", None) is not None)
        if is_custom:
            auth_lvl = "TEST"
            if getattr(self, "_force_production_authority", False):
                raise ValueError("Prohibited authority escalation: custom memory reader cannot obtain PRODUCTION authority")
        else:
            auth_lvl = "TEST" if getattr(self, "_force_test_authority", False) else "PRODUCTION"

        target_constraints: Dict[str, Any] = {}
        if self.is_remote():
            th = self.target_host()
            if not th:
                raise ValueError("Remote execution adapter missing target_host")
            target_constraints["target_host"] = th
            target_constraints["is_remote"] = True

        bind_str = snapshot_binding or tx.snapshot_binding or f"live_reads:{pid}:epoch_{self._capture_epoch}:bytes_{tx.physical_bytes_read}"
        token = get_trusted_capture_authority_token()
        rcpt = issue_live_capture_receipt(
            session_id=session_id,
            pid=int(pid),
            process_identity=proc_id,
            executable_identity=exe_id,
            build_id=bid,
            snapshot_binding=bind_str,
            capture_epoch=self._capture_epoch,
            authority_level=auth_lvl,
            provenance_class="LIVE_RUNTIME_CAPTURE",
            target_constraints=target_constraints,
            operation_id=tx.transaction_id,
            observation_digest=tx.observation_digest,
            physical_bytes_read=tx.physical_bytes_read,
            physical_reads_count=tx.physical_reads_count,
            operation_type=tx.operation_type,
            capture_authority_token=token,
        )
        eff_ts = getattr(self, "trust_store", None) or get_default_trust_store()
        if eff_ts:
            try:
                eff_ts.bind_operation_receipt(tx.transaction_id, rcpt.receipt_id)
            except Exception as e:
                raise RuntimeError(f"Failed to bind receipt to operation in durable trust store: {e}") from e
        tx.receipt_issued = True
        self._issued_live_receipts.append(rcpt)
        return rcpt

    def read_unscoped(self, pid: int, address: int, size: int) -> Tuple[Optional[bytes], str, Optional[str]]:
        """Perform an explicitly unscoped physical read that cannot attest to production diagnostic evidence."""
        # Save active transaction context if any
        token = _current_capture_tx.set(None)
        try:
            self._ensure_tracking_state()
            if hasattr(self, "read_memory"):
                data, st, err = self.read_memory(pid, address, size)
            else:
                data, st, err = None, "UNAVAILABLE", "Adapter has no read_memory"
            return data, st, err
        finally:
            _current_capture_tx.reset(token)

    @abstractmethod
    def check_liveness(self, pid: int) -> Tuple[bool, Optional[str]]:
        """Checks if target process is currently alive and accessible.
        
        Returns:
            (True, None) if alive.
            (False, error_reason) if dead, inaccessible, or transport failure.
        """
        pass

    @abstractmethod
    def get_process_identity(self, pid: int) -> Dict[str, Any]:
        """Discovers executable path, architecture, build ID, and ELF type."""
        pass

    @abstractmethod
    def get_proc_maps(self, pid: int) -> List[Dict[str, Any]]:
        """Reads /proc/<pid>/maps and returns structured memory mappings."""
        pass

    def get_process_status(self, pid: int) -> Dict[str, Any]:
        """Reads /proc/<pid>/status fields (e.g. VmRSS, VmSize, Threads) from target host."""
        return {}

    def get_memory_mappings(self, pid: int) -> List[Dict[str, Any]]:
        """Convenience alias for get_proc_maps."""
        return self.get_proc_maps(pid)

    @abstractmethod
    def get_threads(self, pid: int) -> List[Dict[str, Any]]:
        """Discovers active threads from /proc/<pid>/task."""
        pass

    @abstractmethod
    def read_memory(self, pid: int, address: int, size: int) -> Tuple[Optional[bytes], str, Optional[str]]:
        """Reads raw bytes from target memory without suspending the process.
        
        Returns:
            (bytes, "OBSERVED", None) on full success.
            (partial_bytes, "PARTIAL", msg) on partial read.
            (None, "UNAVAILABLE", reason) if unmapped or read error.
            (None, "TARGET_TERMINATED", reason) if target exited.
            (None, "PERMISSION_DENIED", reason) if permission denied.
        """
        pass

    def read_memory_batch(
        self,
        pid: int,
        slices: List[Tuple[int, int]],
    ) -> List[Tuple[Optional[bytes], str, Optional[str]]]:
        """Reads multiple (address, size) slices in a single batch operation when supported."""
        return [self.read_memory(pid, addr, sz) for addr, sz in slices]

    @abstractmethod
    def is_remote(self) -> bool:
        """Returns True if the target is on a remote host, False if local."""
        pass

    @abstractmethod
    def target_host(self) -> str:
        """Returns the target host identifier (e.g. 'localhost' or 'user@host:port')."""
        pass

    def find_processes(
        self,
        process_name: Optional[str] = None,
        companion_build_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Discovers running processes on the target host, optionally filtered by name or Build ID."""
        return []

    def close(self) -> None:
        """Clean up any active connection or temporary resources."""
        pass


class LocalTargetAdapter(TargetExecutionAdapter):
    """Execution adapter for local Linux processes using direct /proc and process_vm_readv."""

    def __init__(
        self,
        memory_reader_fn: Optional[Callable[[int, int, int], Tuple[Optional[bytes], str, Optional[str]]]] = None,
        adapter_id: Optional[str] = None,
    ):
        self._ensure_tracking_state()
        if adapter_id:
            self._adapter_id = str(adapter_id)
        self._memory_reader = memory_reader_fn

    def is_remote(self) -> bool:
        return False

    def target_host(self) -> str:
        try:
            return os.uname().nodename
        except Exception:
            return "localhost"

    def check_liveness(self, pid: int) -> Tuple[bool, Optional[str]]:
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 1:
            return False, f"Invalid or reserved system PID {pid} (must be integer > 1)"
        try:
            os.kill(pid, 0)
            return True, None
        except ProcessLookupError:
            return False, f"Target PID {pid} was not found (ESRCH)"
        except PermissionError:
            return False, f"Permission denied accessing target PID {pid} (EPERM)"
        except Exception as e:
            return False, f"Liveness check failed for PID {pid}: {e}"

    def get_process_identity(self, pid: int) -> Dict[str, Any]:
        runtime_exe = ""
        try:
            runtime_exe = os.path.realpath(f"/proc/{pid}/exe")
        except Exception:
            pass

        runtime_identity: Optional[BinaryIdentity] = None
        if runtime_exe and os.path.exists(runtime_exe):
            try:
                runtime_identity = inspect_elf(runtime_exe)
            except Exception:
                pass

        start_time = ""
        try:
            with open(f"/proc/{int(pid)}/stat", "r", encoding="utf-8", errors="replace") as sf:
                raw_stat = sf.read().strip()
            rparen = raw_stat.rfind(")")
            if rparen != -1:
                after_comm = raw_stat[rparen + 1 :].strip().split()
                if len(after_comm) >= 20:
                    start_time = after_comm[19]
        except Exception:
            pass

        boot_id = "local"
        try:
            with open("/proc/sys/kernel/random/boot_id", "r", encoding="utf-8") as bf:
                boot_id = bf.read().strip()
        except Exception:
            pass

        exe_inode = 0
        try:
            if runtime_exe and os.path.exists(runtime_exe):
                exe_inode = int(os.stat(runtime_exe).st_ino)
        except Exception:
            pass

        page_size = 4096
        try:
            page_size = int(os.sysconf("SC_PAGE_SIZE"))
        except Exception:
            pass

        return {
            "pid": pid,
            "executable": runtime_exe,
            "executable_identity": f"{runtime_exe}:{exe_inode}" if runtime_exe else "",
            "exe_inode": exe_inode,
            "start_time": start_time,
            "boot_id": boot_id,
            "process_identity": f"{pid}:{start_time}:{boot_id}" if start_time else f"{pid}::{boot_id}",
            "architecture": runtime_identity.architecture if runtime_identity else "unknown",
            "elf_type": runtime_identity.elf_type if runtime_identity else "unknown",
            "build_id": runtime_identity.build_id if runtime_identity else None,
            "pt_loads": runtime_identity.pt_loads if runtime_identity else [],
            "page_size": page_size,
            "is_remote": False,
            "host": self.target_host(),
        }

    def get_proc_maps(self, pid: int) -> List[Dict[str, Any]]:
        maps_path = f"/proc/{pid}/maps"
        mappings: List[Dict[str, Any]] = []
        if not os.path.exists(maps_path):
            return mappings

        with open(maps_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = line.strip().split(maxsplit=5)
                if len(parts) >= 5:
                    addr_range = parts[0]
                    perms = parts[1]
                    offset = parts[2]
                    pathname = parts[5] if len(parts) >= 6 else ""

                    try:
                        start_hex, end_hex = addr_range.split("-")
                        s_int = int(start_hex, 16)
                        e_int = int(end_hex, 16)
                        off_int = int(offset, 16)
                    except Exception:
                        continue

                    path_low = pathname.lower()
                    is_hugepage = any(k in path_low for k in ("huge", "rtemap", "hugetlb"))
                    category = "anonymous"
                    if pathname == "[heap]":
                        category = "heap"
                    elif pathname.startswith("[stack"):
                        category = "stack"
                    elif is_hugepage and "w" in perms:
                        category = "data"
                    elif pathname:
                        if "x" in perms:
                            category = "code"
                        elif "w" in perms:
                            category = "data"
                        else:
                            category = "file"

                    mappings.append({
                        "start": f"0x{s_int:x}",
                        "end": f"0x{e_int:x}",
                        "start_int": s_int,
                        "end_int": e_int,
                        "size": e_int - s_int,
                        "permissions": perms,
                        "offset": offset,
                        "offset_int": off_int,
                        "category": category,
                        "pathname": pathname,
                        "is_hugepage": is_hugepage,
                        "is_readable": "r" in perms,
                        "is_writable": "w" in perms,
                        "is_executable": "x" in perms,
                    })
        return mappings

    get_memory_mappings = get_proc_maps

    def get_process_status(self, pid: int) -> Dict[str, Any]:
        status: Dict[str, Any] = {}
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 1:
            return status
        path = f"/proc/{pid}/status"
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            k = parts[0].strip()
                            v = parts[1].strip()
                            if k in ("VmRSS", "VmSize", "VmPeak", "VmData", "VmStk", "VmExe", "Threads"):
                                val_parts = v.split()
                                try:
                                    status[k] = int(val_parts[0])
                                except ValueError:
                                    status[k] = v
                            else:
                                status[k] = v
            except Exception:
                pass
        return status

    def get_threads(self, pid: int) -> List[Dict[str, Any]]:
        import struct as _struct
        threads: List[Dict[str, Any]] = []
        task_dir = f"/proc/{pid}/task"
        if not os.path.exists(task_dir):
            return threads

        maps = self.get_proc_maps(pid)
        stack_maps = [m for m in maps if m.get("category") == "stack" or m.get("pathname", "").startswith("[stack")]
        kernel_isolated = set(_get_kernel_isolated_cpus())
        sched_policy_names = {
            0: "SCHED_OTHER",
            1: "SCHED_FIFO",
            2: "SCHED_RR",
            3: "SCHED_BATCH",
            5: "SCHED_IDLE",
            6: "SCHED_DEADLINE",
        }

        try:
            for tid_entry in os.listdir(task_dir):
                if tid_entry.isdigit():
                    tid = int(tid_entry)
                    comm = "unknown"
                    state = "UNKNOWN"
                    startstack = 0
                    utime_ticks = 0
                    stime_ticks = 0
                    cpu_id: Optional[int] = None
                    rt_priority = 0
                    sched_policy = "SCHED_OTHER"
                    comm_file = os.path.join(task_dir, tid_entry, "comm")
                    if os.path.exists(comm_file):
                        try:
                            with open(comm_file, "r", encoding="utf-8", errors="replace") as cf:
                                comm = cf.read().strip()
                        except Exception:
                            pass
                    kstkesp = 0
                    stat_file = os.path.join(task_dir, tid_entry, "stat")
                    if os.path.exists(stat_file):
                        try:
                            with open(stat_file, "r", encoding="utf-8", errors="replace") as sf:
                                raw_stat = sf.read().strip()
                                rparen = raw_stat.rfind(")")
                                if rparen != -1:
                                    rest = raw_stat[rparen + 1:].strip().split()
                                    if len(rest) >= 1:
                                        state = rest[0]
                                    if len(rest) >= 13:
                                        try:
                                            utime_ticks = int(rest[11])
                                            stime_ticks = int(rest[12])
                                        except (ValueError, IndexError):
                                            pass
                                    if len(rest) >= 26:
                                        try:
                                            startstack = int(rest[25])
                                        except (ValueError, IndexError):
                                            pass
                                    if len(rest) >= 27:
                                        try:
                                            kstkesp = int(rest[26])
                                        except (ValueError, IndexError):
                                            pass
                                    if len(rest) >= 37:
                                        try:
                                            cpu_id = int(rest[36])
                                        except (ValueError, IndexError):
                                            pass
                                    if len(rest) >= 39:
                                        try:
                                            rt_priority = int(rest[37])
                                            pol_num = int(rest[38])
                                            sched_policy = sched_policy_names.get(pol_num, f"POLICY_{pol_num}")
                                        except (ValueError, IndexError):
                                            pass
                        except Exception:
                            pass

                    cpus_allowed_list = ""
                    numa_nodes_list = ""
                    voluntary_cs = 0
                    nonvoluntary_cs = 0
                    status_file = os.path.join(task_dir, tid_entry, "status")
                    if os.path.exists(status_file):
                        try:
                            with open(status_file, "r", encoding="utf-8", errors="replace") as stf:
                                for sline in stf:
                                    if sline.startswith("Cpus_allowed_list:"):
                                        cpus_allowed_list = sline.split(":", 1)[1].strip()
                                    elif sline.startswith("Mems_allowed_list:"):
                                        numa_nodes_list = sline.split(":", 1)[1].strip()
                                    elif sline.startswith("voluntary_ctxt_switches:"):
                                        try:
                                            voluntary_cs = int(sline.split(":", 1)[1].strip())
                                        except ValueError:
                                            pass
                                    elif sline.startswith("nonvoluntary_ctxt_switches:"):
                                        try:
                                            nonvoluntary_cs = int(sline.split(":", 1)[1].strip())
                                        except ValueError:
                                            pass
                        except Exception:
                            pass

                    pinned_cpus = _parse_cpulist(cpus_allowed_list)
                    if not pinned_cpus and hasattr(os, "sched_getaffinity"):
                        try:
                            pinned_cpus = sorted(os.sched_getaffinity(tid))
                            if pinned_cpus and not cpus_allowed_list:
                                cpus_allowed_list = ",".join(str(c) for c in pinned_cpus)
                        except Exception:
                            pass
                    is_single_core_pinned = (len(pinned_cpus) == 1)

                    syscall_sp = 0
                    is_running_user_space = (state == "R")
                    syscall_file = os.path.join(task_dir, tid_entry, "syscall")
                    if os.path.exists(syscall_file):
                        try:
                            with open(syscall_file, "r", encoding="utf-8", errors="replace") as syf:
                                sy_raw = syf.read().strip()
                                if sy_raw.startswith("running"):
                                    is_running_user_space = True
                                else:
                                    sy_parts = sy_raw.split()
                                    if len(sy_parts) >= 2 and sy_parts[-2].startswith("0x"):
                                        syscall_sp = int(sy_parts[-2], 16)
                        except Exception:
                            pass

                    sp_int = syscall_sp or kstkesp

                    stack_info: Dict[str, Any] = {"status": "UNAVAILABLE", "reason": "Thread stack mapping not identifiable in proc maps"}
                    matched_map = None
                    if sp_int > 0:
                        for m in maps:
                            if m["start_int"] <= sp_int < m["end_int"]:
                                matched_map = m
                                break
                    if not matched_map and tid == pid:
                        for m in stack_maps:
                            if m.get("pathname") == "[stack]":
                                matched_map = m
                                break
                    if not matched_map:
                        for m in stack_maps:
                            if m.get("pathname") == f"[stack:{tid}]":
                                matched_map = m
                                break
                    if not matched_map and tid == pid and startstack > 0:
                        for m in maps:
                            if m["start_int"] <= startstack < m["end_int"]:
                                matched_map = m
                                break

                    if matched_map:
                        stack_info = {
                            "status": "AVAILABLE",
                            "start": matched_map["start"],
                            "end": matched_map["end"],
                            "start_int": matched_map["start_int"],
                            "end_int": matched_map["end_int"],
                            "size": matched_map["size"],
                            "permissions": matched_map["permissions"],
                            "sp": f"0x{sp_int:x}" if sp_int > 0 else None,
                            "sp_int": sp_int if sp_int > 0 else None,
                            "tcb_address": None,
                            "tcb_address_int": None,
                        }

                    threads.append({
                        "tid": tid,
                        "name": comm,
                        "state": state,
                        "cpu_id": cpu_id,
                        "cpus_allowed_list": cpus_allowed_list,
                        "pinned_cpus": pinned_cpus,
                        "is_single_core_pinned": is_single_core_pinned,
                        "is_kernel_isolated_core": bool(cpu_id is not None and cpu_id in kernel_isolated),
                        "numa_nodes_list": numa_nodes_list,
                        "sched_policy": sched_policy,
                        "rt_priority": rt_priority,
                        "utime_ticks": utime_ticks,
                        "stime_ticks": stime_ticks,
                        "voluntary_ctxt_switches": voluntary_cs,
                        "nonvoluntary_ctxt_switches": nonvoluntary_cs,
                        "is_running_user_space": is_running_user_space,
                        "stack_info": stack_info,
                        "local_variables": {
                            "status": "UNSUPPORTED",
                            "reason": "Stack frame inspection requires an active debugger backend (GDB/ptrace frame unwind).",
                        },
                    })

            # Resolve stack_info and TCB address for pure user-space poll-mode threads (e.g. DPDK lcores where sp_int == 0)
            unresolved_threads = [t for t in threads if t["stack_info"].get("status") != "AVAILABLE" or t["stack_info"].get("tcb_address") is None]
            if unresolved_threads and self._memory_reader is None:
                target_tids = {t["tid"]: t for t in threads}
                for m in maps:
                    if not m.get("is_readable") or not m.get("is_writable"):
                        continue
                    pathname = (m.get("pathname") or "").strip()
                    if pathname and not pathname.startswith("[stack") and not m.get("is_hugepage"):
                        continue
                    vma_s = int(m["start_int"])
                    vma_e = int(m["end_int"])
                    if (vma_e - vma_s) < 4096:
                        continue
                    top_from = max(vma_s, vma_e - 24576)
                    raw_top, r_st, _ = self.read_memory(pid, top_from, vma_e - top_from)
                    if r_st != "OBSERVED" or not raw_top or len(raw_top) < 64:
                        continue
                    limit = len(raw_top) - 24
                    for off in range(0, limit, 8):
                        cand_tcb = top_from + off
                        w0 = _struct.unpack_from("<Q", raw_top, off)[0]
                        if w0 != cand_tcb:
                            continue
                        w2 = _struct.unpack_from("<Q", raw_top, off + 16)[0]
                        if w2 != cand_tcb:
                            continue
                        tcb_slice = raw_top[off : off + 1536]
                        matched_tid = None
                        if len(tcb_slice) >= 0x2d4:
                            v2d0 = _struct.unpack_from("<i", tcb_slice, 0x2d0)[0]
                            if v2d0 in target_tids:
                                matched_tid = v2d0
                        if matched_tid is None:
                            for toff in range(0x40, min(len(tcb_slice) - 4, 0x580), 4):
                                vtid = _struct.unpack_from("<i", tcb_slice, toff)[0]
                                if vtid in target_tids and vtid != pid:
                                    matched_tid = vtid
                                    break
                        if matched_tid is not None:
                            th_obj = target_tids[matched_tid]
                            s_inf = th_obj["stack_info"]
                            if s_inf.get("status") != "AVAILABLE":
                                th_obj["stack_info"] = {
                                    "status": "AVAILABLE",
                                    "start": m["start"],
                                    "end": m["end"],
                                    "start_int": vma_s,
                                    "end_int": vma_e,
                                    "size": m["size"],
                                    "permissions": m["permissions"],
                                    "sp": None,
                                    "sp_int": None,
                                    "tcb_address": f"0x{cand_tcb:x}",
                                    "tcb_address_int": cand_tcb,
                                }
                            else:
                                s_inf["tcb_address"] = f"0x{cand_tcb:x}"
                                s_inf["tcb_address_int"] = cand_tcb
        except Exception:
            pass

        threads.sort(key=lambda t: t["tid"])
        return threads

    def read_memory(self, pid: int, address: int, size: int) -> Tuple[Optional[bytes], str, Optional[str]]:
        self._ensure_tracking_state()
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 1:
            return None, "UNAVAILABLE", f"Invalid or reserved PID {pid}"
        ok_pin, pin_err = self.verify_pinned_identity(pid)
        if not ok_pin:
            return None, "PID_REUSED", pin_err
        if self._memory_reader:
            data, st, err = self._memory_reader(pid, address, size)
            if data is not None and len(data) > 0:
                self._record_physical_read(len(data), 1, data=data, pid=pid, address=address, requested_size=size, status=st)
            return data, st, err
        from .watch_session import read_process_memory_slice
        data, st, err = read_process_memory_slice(pid, address, size)
        if data is not None and len(data) > 0:
            self._record_physical_read(len(data), 1, data=data, pid=pid, address=address, requested_size=size, status=st)
        return data, st, err

    def find_processes(
        self,
        process_name: Optional[str] = None,
        companion_build_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        results: List[Dict[str, Any]] = []
        q = (process_name or "").strip().lower()
        target_bid = (companion_build_id or "").strip().lower() or None

        try:
            proc_entries = [e for e in os.listdir("/proc") if e.isdigit()]
        except Exception:
            return results

        for pid_str in proc_entries:
            pid = int(pid_str)
            if pid <= 1:
                continue
            comm = ""
            cmdline = ""
            exe_path = ""
            try:
                with open(f"/proc/{pid}/comm", "r", encoding="utf-8", errors="replace") as f:
                    comm = f.read().strip()
            except Exception:
                continue

            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    raw_cmd = f.read(512)
                    cmdline = raw_cmd.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
            except Exception:
                pass

            try:
                exe_path = os.path.realpath(f"/proc/{pid}/exe")
            except Exception:
                exe_path = ""

            exe_base = os.path.basename(exe_path) if exe_path else ""
            if q:
                if q not in comm.lower() and q not in exe_base.lower() and q not in cmdline.lower():
                    continue

            proc_bid = None
            bid_match = False
            has_dwarf = False
            if exe_path and os.path.isfile(exe_path):
                try:
                    ident = inspect_elf(exe_path)
                    proc_bid = ident.build_id
                    has_dwarf = bool(getattr(ident, "has_debug_info", False) or getattr(ident, "has_dwarf_info", False))
                    if target_bid and proc_bid and proc_bid.lower() == target_bid:
                        bid_match = True
                except Exception:
                    pass

            exact_name = bool(q and (comm.lower() == q or exe_base.lower() == q))
            results.append({
                "pid": pid,
                "name": comm or exe_base or f"pid_{pid}",
                "executable": exe_path,
                "cmdline": cmdline,
                "build_id": proc_bid,
                "has_dwarf_info": has_dwarf,
                "build_id_match": bid_match,
                "exact_name_match": exact_name,
                "is_remote": False,
                "host": self.target_host(),
            })

        results.sort(key=lambda r: (
            1 if r.get("build_id_match") else 0,
            1 if r.get("exact_name_match") else 0,
            1 if r.get("has_dwarf_info") else 0,
            r.get("pid", 0),
        ), reverse=True)
        return results[:max(1, limit)]


class RemoteSshTargetAdapter(TargetExecutionAdapter):
    """Execution adapter for remote Linux targets accessed via SSH / SSH Proxy.
    
    Zero-Python on target: uses standard POSIX shell, /proc, and dd/base64.
    Preserves target host namespace: NEVER opens or kills local /proc/<pid>.
    """

    def __init__(
        self,
        host: str,
        user: Optional[str] = None,
        port: int = 22,
        key_file: Optional[str] = None,
        proxy_jump: Optional[str] = None,
        proxy_command: Optional[str] = None,
        timeout_sec: float = 5.0,
        ssh_bin: str = "ssh",
        command_runner: Optional[Callable[[List[str], float], Tuple[int, str, str]]] = None,
        use_control_master: bool = False,
        collector_path: Optional[str] = None,
    ):
        self._ensure_tracking_state()
        if not host or not isinstance(host, str) or not host.strip():
            raise ValueError("Remote host must be specified")
        if host.strip().startswith("-"):
            raise ValueError(f"Invalid remote host '{host}': leading dash prohibited (argument injection guard)")
        if user is not None and (not isinstance(user, str) or user.strip().startswith("-")):
            raise ValueError(f"Invalid SSH user '{user}': leading dash prohibited")
        if proxy_jump is not None and (not isinstance(proxy_jump, str) or proxy_jump.strip().startswith("-")):
            raise ValueError(f"Invalid SSH proxy_jump '{proxy_jump}': leading dash prohibited")
        self.host = host.strip()
        self.user = user.strip() if isinstance(user, str) and user.strip() else None
        self.port = int(port)
        self.key_file = key_file
        self.proxy_jump = proxy_jump
        self.proxy_command = proxy_command
        self.timeout_sec = float(timeout_sec)
        self.ssh_bin = ssh_bin
        self._command_runner = command_runner or self._default_command_runner
        self.use_control_master = bool(use_control_master)
        self.collector_path = (collector_path or "").strip() or None

    def is_remote(self) -> bool:
        return True

    def target_host(self) -> str:
        u = f"{self.user}@" if self.user else ""
        p = f":{self.port}" if self.port != 22 else ""
        return f"{u}{self.host}{p}"

    def _default_command_runner(self, cmd_args: List[str], timeout: float) -> Tuple[int, str, str]:
        try:
            res = subprocess.run(
                cmd_args,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            return res.returncode, res.stdout, res.stderr
        except subprocess.TimeoutExpired:
            return -1, "", f"SSH command timed out after {timeout:.1f}s"
        except Exception as e:
            return -1, "", f"SSH execution error: {e}"

    def run_ssh(self, remote_shell_cmd: str, timeout: Optional[float] = None) -> Tuple[int, str, str]:
        """Runs a command on the remote target using configured SSH parameters."""
        t = timeout or self.timeout_sec
        args = [
            self.ssh_bin,
            "-p", str(self.port),
            "-o", "BatchMode=yes",
            "-o", "StrictHostKeyChecking=accept-new",
            "-o", "ConnectTimeout=5",
        ]
        if self.key_file:
            args.extend(["-i", self.key_file])
        if self.proxy_jump:
            args.extend(["-J", self.proxy_jump])
        if self.proxy_command:
            args.extend(["-o", f"ProxyCommand={self.proxy_command}"])
        if self.use_control_master:
            ctrl_dir = os.path.join(tempfile.gettempdir(), f"dynstate_ssh_{os.getuid() if hasattr(os, 'getuid') else 0}")
            try:
                os.makedirs(ctrl_dir, mode=0o700, exist_ok=True)
                os.chmod(ctrl_dir, 0o700)
            except Exception:
                pass
            args.extend([
                "-o", "ControlMaster=auto",
                "-o", f"ControlPath={ctrl_dir}/ssh_%r@%h:%p",
                "-o", "ControlPersist=60s",
            ])

        target_spec = f"{self.user}@{self.host}" if self.user else self.host
        args.append("--")
        args.append(target_spec)
        args.append(remote_shell_cmd)
        try:
            return self._command_runner(args, t)
        except subprocess.TimeoutExpired:
            return -1, "", f"SSH command timed out after {t:.1f}s"
        except Exception as e:
            return -1, "", f"SSH execution error: {e}"

    def check_liveness(self, pid: int) -> Tuple[bool, Optional[str]]:
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 1:
            return False, f"Invalid PID {pid} (must be integer > 1)"
        
        # Test liveness strictly on remote target host
        cmd = f"kill -0 {int(pid)} 2>/dev/null && echo ALIVE || echo DEAD"
        rc, stdout, stderr = self.run_ssh(cmd)
        if rc != 0:
            return False, f"SSH transport failure to {self.target_host()}: {stderr.strip() or 'Exit ' + str(rc)}"
        
        out = stdout.strip()
        if "ALIVE" in out:
            return True, None
        return False, f"Target PID {pid} is not running on {self.target_host()}"

    def get_process_identity(self, pid: int) -> Dict[str, Any]:
        """Discovers remote process executable, architecture, and Build ID.
        
        Reads the first 64KB of remote /proc/<pid>/exe and parses ELF header host-side.
        """
        # 1. Resolve remote executable path
        cmd_exe = f"readlink -f /proc/{int(pid)}/exe 2>/dev/null || readlink /proc/{int(pid)}/exe 2>/dev/null"
        rc, stdout, _ = self.run_ssh(cmd_exe)
        remote_exe = stdout.strip() if rc == 0 else ""

        # 2. Extract first 64KB of executable via base64 to inspect ELF header on host
        cmd_hdr = f"head -c 65536 /proc/{int(pid)}/exe 2>/dev/null | base64"
        rc, stdout_b64, stderr = self.run_ssh(cmd_hdr, timeout=self.timeout_sec * 1.5)

        arch = "unknown"
        elf_type = "unknown"
        build_id = None
        pt_loads: List[Dict[str, Any]] = []

        if rc == 0 and stdout_b64.strip():
            try:
                raw_elf = base64.b64decode(stdout_b64.strip())
                if len(raw_elf) >= 64:
                    with tempfile.NamedTemporaryFile(prefix="rem_elf_", suffix=".tmp", delete=False) as tf:
                        tf.write(raw_elf)
                        tf.flush()
                        tmp_name = tf.name
                    try:
                        ident = inspect_elf(tmp_name)
                        arch = ident.architecture
                        elf_type = ident.elf_type
                        build_id = ident.build_id
                        pt_loads = ident.pt_loads
                    finally:
                        if os.path.exists(tmp_name):
                            os.remove(tmp_name)
            except Exception:
                pass

        # Fallback for architecture via remote uname -m if ELF parse didn't yield arch
        if arch == "unknown":
            rc, stdout_uname, _ = self.run_ssh("uname -m 2>/dev/null")
            if rc == 0 and stdout_uname.strip():
                arch = stdout_uname.strip()

        return {
            "pid": pid,
            "executable": remote_exe,
            "architecture": arch,
            "elf_type": elf_type,
            "build_id": build_id,
            "pt_loads": pt_loads,
            "is_remote": True,
            "host": self.target_host(),
        }

    def get_proc_maps(self, pid: int) -> List[Dict[str, Any]]:
        cmd = f"cat /proc/{int(pid)}/maps 2>/dev/null"
        rc, stdout, _ = self.run_ssh(cmd)
        mappings: List[Dict[str, Any]] = []
        if rc != 0 or not stdout:
            return mappings

        for line in stdout.splitlines():
            parts = line.strip().split(maxsplit=5)
            if len(parts) >= 5:
                addr_range = parts[0]
                perms = parts[1]
                offset = parts[2]
                pathname = parts[5] if len(parts) >= 6 else ""

                try:
                    start_hex, end_hex = addr_range.split("-")
                    s_int = int(start_hex, 16)
                    e_int = int(end_hex, 16)
                    off_int = int(offset, 16)
                except Exception:
                    continue

                category = "anonymous"
                if pathname == "[heap]":
                    category = "heap"
                elif pathname.startswith("[stack"):
                    category = "stack"
                elif pathname:
                    if "x" in perms:
                        category = "code"
                    elif "w" in perms:
                        category = "data"
                    else:
                        category = "file"

                mappings.append({
                    "start": f"0x{s_int:x}",
                    "end": f"0x{e_int:x}",
                    "start_int": s_int,
                    "end_int": e_int,
                    "size": e_int - s_int,
                    "permissions": perms,
                    "offset": offset,
                    "offset_int": off_int,
                    "category": category,
                    "pathname": pathname,
                    "is_readable": "r" in perms,
                    "is_writable": "w" in perms,
                    "is_executable": "x" in perms,
                })
        return mappings

    def get_process_status(self, pid: int) -> Dict[str, Any]:
        status: Dict[str, Any] = {}
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 1:
            return status
        cmd = f"cat /proc/{int(pid)}/status 2>/dev/null"
        rc, stdout, _ = self.run_ssh(cmd)
        if rc == 0 and stdout:
            for line in stdout.splitlines():
                parts = line.split(":", 1)
                if len(parts) == 2:
                    k = parts[0].strip()
                    v = parts[1].strip()
                    if k in ("VmRSS", "VmSize", "VmPeak", "VmData", "VmStk", "VmExe", "Threads"):
                        val_parts = v.split()
                        try:
                            status[k] = int(val_parts[0])
                        except ValueError:
                            status[k] = v
                    else:
                        status[k] = v
        return status

    def get_threads(self, pid: int) -> List[Dict[str, Any]]:
        # Efficient remote script to list threads without spawning multiple remote processes
        remote_script = (
            f"for t in /proc/{int(pid)}/task/*; do "
            f"[ -d \"$t\" ] || continue; "
            f"tid=$(basename \"$t\"); "
            f"comm=$(cat \"$t/comm\" 2>/dev/null || echo unknown); "
            f"stat=$(sed 's/.*) //' \"$t/stat\" 2>/dev/null | awk '{{print $1}}' || echo UNKNOWN); "
            f"echo \"$tid $stat $comm\"; "
            f"done"
        )
        rc, stdout, _ = self.run_ssh(f"sh -c {shlex.quote(remote_script)}")
        threads: List[Dict[str, Any]] = []
        if rc != 0 or not stdout:
            return threads

        for line in stdout.splitlines():
            tokens = line.strip().split(maxsplit=2)
            if len(tokens) >= 2 and tokens[0].isdigit():
                tid = int(tokens[0])
                state = tokens[1]
                comm = tokens[2] if len(tokens) >= 3 else "unknown"
                threads.append({
                    "tid": tid,
                    "name": comm,
                    "state": state,
                    "stack_info": {
                        "status": "UNAVAILABLE",
                        "reason": "Remote thread stack mapping not inspected over lightweight ssh adapter",
                    },
                    "local_variables": {
                        "status": "UNSUPPORTED",
                        "reason": "Stack frame inspection requires an active debugger backend.",
                    },
                })

        threads.sort(key=lambda t: t["tid"])
        return threads

    def _read_slices_via_collector(
        self,
        pid: int,
        slices: List[Tuple[int, int]],
    ) -> Optional[List[Tuple[Optional[bytes], str, Optional[str]]]]:
        """Uses C99 dynamicstate-collector --read-slices on the remote target for zero-stop process_vm_readv batch reads."""
        if not self.collector_path or not slices:
            return None
        import json as _json
        spec = ",".join(f"0x{int(addr):x}:{max(0, int(sz))}" for addr, sz in slices)
        cmd = f"{shlex.quote(self.collector_path)} -p {int(pid)} --read-slices {shlex.quote(spec)} 2>/dev/null"
        rc, stdout, _ = self.run_ssh(cmd)
        if rc != 0 or not stdout.strip():
            return None
        try:
            payload = _json.loads(stdout.strip().splitlines()[-1])
            if not payload.get("success") or "slices" not in payload:
                if payload.get("error") == "TARGET_TERMINATED":
                    return [(None, "TARGET_TERMINATED", "Remote process terminated") for _ in slices]
                return None
            out_list: List[Tuple[Optional[bytes], str, Optional[str]]] = []
            raw_slices = payload.get("slices", [])
            for idx, (req_addr, req_sz) in enumerate(slices):
                if req_sz <= 0:
                    out_list.append((b"", "OBSERVED", None))
                    continue
                s_item = raw_slices[idx] if idx < len(raw_slices) else {}
                st = s_item.get("status", "UNAVAILABLE")
                hex_str = s_item.get("hex", "")
                raw_b = bytes.fromhex(hex_str) if hex_str else b""
                if st == "OBSERVED" and len(raw_b) == req_sz:
                    out_list.append((raw_b, "OBSERVED", None))
                elif len(raw_b) > 0:
                    out_list.append((raw_b, "PARTIAL", f"Partial read: {len(raw_b)}/{req_sz} bytes"))
                else:
                    out_list.append((None, st if st in ("UNAVAILABLE", "PERMISSION_DENIED", "TARGET_TERMINATED") else "UNAVAILABLE", f"Collector read status: {st} at 0x{req_addr:x}"))
            return out_list
        except Exception:
            return None

    def read_memory_batch(
        self,
        pid: int,
        slices: List[Tuple[int, int]],
    ) -> List[Tuple[Optional[bytes], str, Optional[str]]]:
        """Reads multiple memory slices in a single SSH roundtrip (via C99 collector or batched POSIX shell)."""
        if not slices:
            return []
        if len(slices) == 1 and not self.collector_path:
            return [self.read_memory(pid, slices[0][0], slices[0][1])]

        if self.collector_path:
            coll_res = self._read_slices_via_collector(pid, slices)
            if coll_res is not None:
                return coll_res

        # Single-SSH batched shell read with page-aligned dd fallback for 64-bit BusyBox offsets
        cmds = []
        for idx, (addr, sz) in enumerate(slices):
            a_int = int(addr)
            s_int = max(0, int(sz))
            if s_int == 0:
                cmds.append(f"echo '{idx}|'")
                continue
            page_sz = 4096
            page_num = a_int // page_sz
            page_off = a_int % page_sz
            pages_needed = ((page_off + s_int + page_sz - 1) // page_sz)
            cmds.append(
                f"b=$(dd if=/proc/{int(pid)}/mem bs=1 skip={a_int} count={s_int} 2>/dev/null | base64 | tr -d '\\n'); "
                f"if [ -z \"$b\" ]; then "
                f"b=$(dd if=/proc/{int(pid)}/mem bs={page_sz} skip={page_num} count={pages_needed} 2>/dev/null | "
                f"dd bs=1 skip={page_off} count={s_int} 2>/dev/null | base64 | tr -d '\\n'); "
                f"fi; "
                f"echo \"{idx}|$b\""
            )
        remote_script = "; ".join(cmds)
        rc, stdout, stderr = self.run_ssh(f"sh -c {shlex.quote(remote_script)}")
        if rc != 0:
            alive, live_err = self.check_liveness(pid)
            if not alive:
                st = "UNAVAILABLE" if (live_err and ("transport" in live_err.lower() or "timed out" in live_err.lower())) else "TARGET_TERMINATED"
                return [(None, st, live_err or "Remote process terminated") for _ in slices]
            return [(None, "UNAVAILABLE", f"SSH batch read failed: {stderr.strip()}") for _ in slices]

        by_idx: Dict[int, str] = {}
        for line in stdout.splitlines():
            if "|" in line:
                k_str, val_b64 = line.strip().split("|", 1)
                if k_str.isdigit():
                    by_idx[int(k_str)] = val_b64.strip()

        results: List[Tuple[Optional[bytes], str, Optional[str]]] = []
        for idx, (addr, sz) in enumerate(slices):
            if sz <= 0:
                results.append((b"", "OBSERVED", None))
                continue
            b64_str = by_idx.get(idx, "")
            if not b64_str:
                results.append((None, "UNAVAILABLE", f"Address 0x{int(addr):x} is not mapped or inaccessible on {self.target_host()}"))
                continue
            try:
                raw_b = base64.b64decode(b64_str)
                if len(raw_b) == sz:
                    results.append((raw_b, "OBSERVED", None))
                elif len(raw_b) > 0:
                    results.append((raw_b, "PARTIAL", f"Partial read: {len(raw_b)}/{sz} bytes"))
                else:
                    results.append((None, "UNAVAILABLE", f"Zero bytes returned at 0x{int(addr):x}"))
            except Exception as e:
                results.append((None, "UNAVAILABLE", f"Base64 decode failure: {e}"))
        return results

    def read_memory(self, pid: int, address: int, size: int) -> Tuple[Optional[bytes], str, Optional[str]]:
        if size <= 0:
            return b"", "OBSERVED", None

        if self.collector_path:
            coll_res = self._read_slices_via_collector(pid, [(address, size)])
            if coll_res is not None and len(coll_res) == 1:
                return coll_res[0]

        # Remote memory read via dd and base64
        # dd skip requires decimal integer
        cmd = f"dd if=/proc/{int(pid)}/mem bs=1 skip={int(address)} count={int(size)} 2>/dev/null | base64"
        rc, stdout, stderr = self.run_ssh(cmd)
        if rc != 0:
            if rc == -1 or "timed out" in stderr.lower() or "connection" in stderr.lower():
                return None, "UNAVAILABLE", f"SSH transport failed reading memory at 0x{address:x}: {stderr.strip()}"
            alive, live_err = self.check_liveness(pid)
            if not alive:
                if live_err and ("transport failure" in live_err.lower() or "timed out" in live_err.lower()):
                    return None, "UNAVAILABLE", f"SSH transport failure at 0x{address:x}: {live_err}"
                return None, "TARGET_TERMINATED", live_err or "Remote process terminated"
            return None, "UNAVAILABLE", f"SSH transport failed reading memory at 0x{address:x}: {stderr.strip()}"

        encoded = stdout.strip()
        if not encoded:
            # If 0 bytes returned, verify if process is still alive
            alive, live_err = self.check_liveness(pid)
            if not alive:
                return None, "TARGET_TERMINATED", live_err or "Remote process terminated"
            return None, "UNAVAILABLE", f"Address 0x{address:x} is not mapped or inaccessible on {self.target_host()}"

        try:
            raw_bytes = base64.b64decode(encoded)
            if len(raw_bytes) == size:
                self._record_physical_read(len(raw_bytes), 1, data=raw_bytes, pid=pid, address=address, requested_size=size, status="OBSERVED")
                return raw_bytes, "OBSERVED", None
            elif len(raw_bytes) > 0:
                self._record_physical_read(len(raw_bytes), 1, data=raw_bytes, pid=pid, address=address, requested_size=size, status="PARTIAL")
                return raw_bytes, "PARTIAL", f"Partial read: {len(raw_bytes)}/{size} bytes"
            else:
                return None, "UNAVAILABLE", f"Zero bytes returned at 0x{address:x}"
        except Exception as e:
            return None, "UNAVAILABLE", f"Base64 decode failure: {e}"

    def find_processes(
        self,
        process_name: Optional[str] = None,
        companion_build_id: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Discovers running processes on the remote target via a single POSIX shell scan of /proc."""
        remote_script = (
            "for p in /proc/[0-9]*; do "
            "[ -d \"$p\" ] || continue; "
            "pid=$(basename \"$p\"); "
            "comm=$(cat \"$p/comm\" 2>/dev/null | tr -d '\n' || true); "
            "[ -n \"$comm\" ] || continue; "
            "exe=$(readlink -f \"$p/exe\" 2>/dev/null || readlink \"$p/exe\" 2>/dev/null || true); "
            "cmd=$(tr '\000' ' ' < \"$p/cmdline\" 2>/dev/null | head -c 200 || true); "
            "echo \"$pid|$comm|$exe|$cmd\"; "
            "done"
        )
        rc, stdout, _ = self.run_ssh(f"sh -c {shlex.quote(remote_script)}")
        results: List[Dict[str, Any]] = []
        if rc != 0 or not stdout:
            return results

        q = (process_name or "").strip().lower()
        target_bid = (companion_build_id or "").strip().lower() or None

        for line in stdout.splitlines():
            parts = line.strip().split("|", 3)
            if len(parts) < 2 or not parts[0].isdigit():
                continue
            pid = int(parts[0])
            comm = parts[1].strip()
            exe_path = parts[2].strip() if len(parts) >= 3 else ""
            cmdline = parts[3].strip() if len(parts) >= 4 else ""
            exe_base = os.path.basename(exe_path) if exe_path else ""

            if q:
                if q not in comm.lower() and q not in exe_base.lower() and q not in cmdline.lower():
                    continue

            exact_name = bool(q and (comm.lower() == q or exe_base.lower() == q))
            results.append({
                "pid": pid,
                "name": comm or exe_base or f"pid_{pid}",
                "executable": exe_path,
                "cmdline": cmdline,
                "build_id": None,
                "build_id_match": False,
                "exact_name_match": exact_name,
                "is_remote": True,
                "host": self.target_host(),
            })

        # Sort exact matches first; if target_bid is provided, verify Build ID on top candidates (up to 5)
        results.sort(key=lambda r: (1 if r.get("exact_name_match") else 0, r.get("pid", 0)), reverse=True)
        if target_bid:
            for cand in results[:5]:
                ident = self.get_process_identity(cand["pid"])
                bid = ident.get("build_id")
                cand["build_id"] = bid
                if bid and bid.lower() == target_bid:
                    cand["build_id_match"] = True
            results.sort(key=lambda r: (
                1 if r.get("build_id_match") else 0,
                1 if r.get("exact_name_match") else 0,
                r.get("pid", 0),
            ), reverse=True)

        return results[:max(1, limit)]

    def ensure_remote_collector(
        self,
        local_collector_bin: Optional[str] = None,
        remote_dest: str = "/tmp/dynamicstate-collector",
    ) -> Dict[str, Any]:
        """Checks if dynamicstate-collector is present on the remote target, and if not,
        automatically deploys a matching architecture binary over SSH without requiring scp.
        Falls back gracefully to batched POSIX shell mode if binary architecture mismatches.
        """
        dest = (remote_dest or "/tmp/dynamicstate-collector").strip()
        check_cmd = f"[ -x {shlex.quote(dest)} ] && {shlex.quote(dest)} --help >/dev/null 2>&1 && echo READY || echo MISSING"
        rc, stdout, stderr = self.run_ssh(f"sh -c {shlex.quote(check_cmd)}")
        if rc != 0:
            return {
                "deployed": False,
                "status": "SSH_ERROR",
                "collector_path": None,
                "reason": stderr.strip() or f"SSH exited with {rc}",
            }

        if "READY" in stdout:
            self.collector_path = dest
            return {
                "deployed": True,
                "status": "ALREADY_PRESENT",
                "collector_path": dest,
                "reason": "Collector binary already present and executable on target",
            }

        # Check if local collector binary is available
        cand_bin = local_collector_bin
        if not cand_bin:
            repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
            default_bin = os.path.join(repo_root, "target", "collector", "dynamicstate-collector")
            if os.path.isfile(default_bin):
                cand_bin = default_bin

        if not cand_bin or not os.path.isfile(cand_bin):
            return {
                "deployed": False,
                "status": "FALLBACK_SHELL",
                "collector_path": None,
                "reason": "No local dynamicstate-collector binary found to deploy; using batched POSIX shell fallback",
            }

        # Check architecture compatibility between local collector binary and remote uname -m
        try:
            local_ident = inspect_elf(cand_bin)
            local_arch = (local_ident.architecture or "").lower()
        except Exception as e:
            return {
                "deployed": False,
                "status": "FALLBACK_SHELL",
                "collector_path": None,
                "reason": f"Local collector binary is not a valid ELF: {e}",
            }

        rc_u, out_u, _ = self.run_ssh("uname -m 2>/dev/null")
        rem_arch_raw = out_u.strip().lower() if rc_u == 0 else ""
        arch_aliases = {
            "x86_64": ("x86_64", "amd64"),
            "aarch64": ("aarch64", "arm64"),
            "arm": ("arm", "armv7l", "armv6l", "armhf"),
            "riscv64": ("riscv64",),
            "mips": ("mips", "mips64", "mipsel"),
        }
        compatible_remotes = arch_aliases.get(local_arch, (local_arch,))
        if rem_arch_raw and local_arch and rem_arch_raw not in compatible_remotes:
            return {
                "deployed": False,
                "status": "FALLBACK_SHELL",
                "collector_path": None,
                "local_architecture": local_arch,
                "remote_architecture": rem_arch_raw,
                "reason": (
                    f"Architecture mismatch: local collector is '{local_arch}' but remote target is '{rem_arch_raw}'. "
                    f"Cross-compile collector with CC=<arch>-gcc or use batched POSIX shell fallback."
                ),
            }

        with open(cand_bin, "rb") as bf:
            raw_bytes = bf.read()
        b64_payload = base64.b64encode(raw_bytes).decode("ascii")
        upload_cmd = (
            f"sh -c 'echo {shlex.quote(b64_payload)} | base64 -d > {shlex.quote(dest)} && "
            f"chmod 755 {shlex.quote(dest)} && {shlex.quote(dest)} --help >/dev/null 2>&1 && echo DEPLOY_OK'"
        )
        rc_up, out_up, err_up = self.run_ssh(upload_cmd, timeout=max(10.0, self.timeout_sec * 2))
        if rc_up == 0 and "DEPLOY_OK" in out_up:
            self.collector_path = dest
            return {
                "deployed": True,
                "status": "DEPLOYED_BINARY",
                "collector_path": dest,
                "bytes_transferred": len(raw_bytes),
                "architecture": local_arch,
                "reason": f"Successfully deployed dynamicstate-collector ({len(raw_bytes)} bytes) to {dest}",
            }

        return {
            "deployed": False,
            "status": "FALLBACK_SHELL",
            "collector_path": None,
            "reason": f"Failed deploying collector to {dest}: {err_up.strip() or out_up.strip()}",
        }

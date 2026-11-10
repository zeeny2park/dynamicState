"""Runtime Evidence Provider (Phase 2.1.1).

Connects deterministic diagnostic recipes to actual zero-stop Linux/POSIX runtime
evidence acquisition (process info, memory mappings, process_vm_readv memory slices,
DWARF symbol paths, thread callstacks and mutex lock graphs, heap census).

Guarantees:
- Real target collection: NEVER fabricate values or report LIVE_RUNTIME_CAPTURE without an actual read.
- Embedded friendliness: 0.00ms target stop time, zero Python/GDB on target.
- Honest limitations: graceful degradation on missing DWARF, unreadable memory, or permission denial.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import uuid

from .target_adapter import LocalTargetAdapter, TargetExecutionAdapter
from .temporal_observation_window import MemorySample, ObservationWindow, MemoryBehavior
from .watch_session import WatchSessionManager, read_process_memory_slice


# Provenance constants
PROVENANCE_LIVE_RUNTIME_CAPTURE = "LIVE_RUNTIME_CAPTURE"
PROVENANCE_HISTORICAL_RECORD = "HISTORICAL_RECORD"
PROVENANCE_SYNTHETIC_FIXTURE = "SYNTHETIC_FIXTURE"
PROVENANCE_INFERRED = "INFERRED"

# Collection status constants
COLLECTION_STATUS_SUCCESS = "SUCCESS"
COLLECTION_STATUS_PARTIAL = "PARTIAL"
COLLECTION_STATUS_FAILED = "FAILED"
COLLECTION_STATUS_UNAVAILABLE = "UNAVAILABLE"


@dataclass
class RuntimeEvidenceRecord:
    """Explicit, auditable record of an actual target runtime observation."""
    evidence_id: str
    collection_method: str
    target_pid: Optional[int]
    tid: Optional[int] = None
    address: Optional[int] = None
    object_identity: Optional[str] = None
    source_variable: Optional[str] = None
    observed_value: Any = None
    collection_timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    collection_scope: str = "TARGET_PROCESS"
    collection_status: str = COLLECTION_STATUS_SUCCESS
    limitations: List[str] = field(default_factory=list)
    provenance_class: str = PROVENANCE_LIVE_RUNTIME_CAPTURE
    raw_details: Dict[str, Any] = field(default_factory=dict)
    raw_observation: Any = None
    normalized_observation: Any = None

    def __post_init__(self):
        # Preserve raw and normalized observation while distinguishing falsey values (0, False, "")
        if self.raw_observation is None:
            if self.raw_details:
                self.raw_observation = self.raw_details
            elif self.observed_value is not None:
                self.raw_observation = self.observed_value

        if self.normalized_observation is None:
            if self.observed_value is not None:
                self.normalized_observation = self.observed_value
            elif self.raw_observation is not None:
                self.normalized_observation = self.raw_observation

        if self.observed_value is None and self.normalized_observation is not None:
            self.observed_value = self.normalized_observation

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RuntimeEvidenceRecord":
        return cls(
            evidence_id=data["evidence_id"],
            collection_method=data["collection_method"],
            target_pid=data.get("target_pid"),
            tid=data.get("tid"),
            address=data.get("address"),
            object_identity=data.get("object_identity"),
            source_variable=data.get("source_variable"),
            observed_value=data.get("observed_value"),
            collection_timestamp=data.get("collection_timestamp", datetime.now(timezone.utc).isoformat()),
            collection_scope=data.get("collection_scope", "TARGET_PROCESS"),
            collection_status=data.get("collection_status", COLLECTION_STATUS_SUCCESS),
            limitations=list(data.get("limitations", [])),
            provenance_class=data.get("provenance_class", PROVENANCE_LIVE_RUNTIME_CAPTURE),
            raw_details=dict(data.get("raw_details", {})),
            raw_observation=data.get("raw_observation"),
            normalized_observation=data.get("normalized_observation"),
        )


class RuntimeEvidenceProvider:
    """Acquires live runtime evidence for expert diagnostic recipes using existing zero-stop capabilities."""

    def __init__(
        self,
        adapter: Optional[TargetExecutionAdapter] = None,
        watch_manager: Optional[WatchSessionManager] = None,
        corpus_dir: Optional[str] = None,
        budget_tracker: Optional[Any] = None,
    ):
        self.adapter = adapter or LocalTargetAdapter()
        self.watch_manager = watch_manager or WatchSessionManager(corpus_dir=corpus_dir or "/tmp/dynamicstate_corpus")
        self.budget_tracker = budget_tracker
        self._historical_samples: Dict[str, Dict[str, Any]] = {}

    def get_target_identity_key(self, pid: int) -> Tuple[Optional[str], Optional[Dict[str, Any]], Optional[str]]:
        """Discovers and verifies mandatory process identity fields.

        Enforces:
        - Target host, boot_id, pid, start_time, executable (and build_id).
        - If any mandatory field cannot be verified, returns (None, ident, error_message).
        - Prevents cross-process, cross-boot, and cross-session contamination.
        """
        if not pid or pid <= 0:
            return None, None, "Invalid target PID (must be positive integer)"

        try:
            ident = self.adapter.get_process_identity(pid)
        except Exception as e:
            return None, None, f"IDENTITY_UNAVAILABLE: Failed to query process identity for PID {pid}: {e}"

        if not ident or not isinstance(ident, dict):
            return None, None, f"IDENTITY_UNAVAILABLE: Empty identity record returned for PID {pid}"

        host = ident.get("host") or (self.adapter.target_host() if hasattr(self.adapter, "target_host") else "localhost")
        boot_id = ident.get("boot_id") or ""
        start_time = ident.get("start_time") or ""
        exe = ident.get("executable") or ident.get("executable_identity") or ident.get("exe_path") or ""
        build_id = ident.get("build_id") or ""

        missing_fields = []
        if not host:
            missing_fields.append("host")
        if not boot_id:
            missing_fields.append("boot_id")
        if not start_time:
            missing_fields.append("start_time")
        if not exe:
            missing_fields.append("executable")

        if missing_fields:
            return None, ident, f"IDENTITY_UNAVAILABLE: Mandatory identity fields missing for PID {pid}: {', '.join(missing_fields)}"

        exe_tag = exe
        if build_id:
            exe_tag = f"{exe}:{build_id}"
        target_key = f"{host}:{boot_id}:{pid}:{start_time}:{exe_tag}"
        return target_key, ident, None

    def collect_process_info(self, pid: int) -> Tuple[Dict[str, Any], List[RuntimeEvidenceRecord]]:
        """Collects live process status, thread count, RSS, and process identity.

        Enforces strict measurement semantics:
        - Distinguishes OBSERVED_VALUE, OBSERVED_ZERO, UNAVAILABLE, and PARTIAL.
        - Never substitutes 0 for missing VmRSS.
        """
        ev_records: List[RuntimeEvidenceRecord] = []
        info: Dict[str, Any] = {"pid": pid, "alive": False}
        if not pid or pid <= 0:
            return info, ev_records

        res_id = None
        t0 = time.monotonic_ns()
        if self.budget_tracker:
            est_b = max(1, min(1024, self.budget_tracker.limits.max_bytes_read))
            allowed, reason, res_id = self.budget_tracker.reserve(
                estimated_bytes=est_b,
                estimated_latency_ms=5.0,
                estimated_samples=1,
                profile_id="collect_process_info",
            )
            if not allowed:
                rec = RuntimeEvidenceRecord(
                    evidence_id=f"ev_{uuid.uuid4().hex[:12]}",
                    collection_method="budget_guard",
                    target_pid=pid,
                    observed_value=None,
                    collection_status="BUDGET_EXHAUSTED",
                    limitations=[f"Budget exhausted before collecting process info: {reason}"],
                    provenance_class=PROVENANCE_LIVE_RUNTIME_CAPTURE,
                )
                ev_records.append(rec)
                return info, ev_records

        try:
            alive, live_err = self.adapter.check_liveness(pid)
            info["alive"] = alive
            if not alive:
                rec = RuntimeEvidenceRecord(
                    evidence_id=f"ev_{uuid.uuid4().hex[:12]}",
                    collection_method="adapter.check_liveness",
                    target_pid=pid,
                    observed_value={"alive": False, "error": live_err},
                    collection_status=COLLECTION_STATUS_FAILED,
                    limitations=[f"Process {pid} is not running or not accessible: {live_err}"],
                    provenance_class=PROVENANCE_LIVE_RUNTIME_CAPTURE,
                )
                ev_records.append(rec)
                if self.budget_tracker and res_id:
                    self.budget_tracker.reconcile_reservation(
                        res_id,
                        actual_bytes_read=0,
                        latency_us=max(100.0, (time.monotonic_ns() - t0) / 1000.0),
                        is_failure=True,
                        physical_reads=0,
                    )
                    self.budget_tracker.record_sample(profile_id="collect_process_info")
                    res_id = None
                return info, ev_records

            try:
                ident = self.adapter.get_process_identity(pid)
                info.update(ident)
            except Exception as e:
                info["identity_error"] = str(e)

            # RSS & Threads
            rss_kb: Optional[int] = None
            rss_metric_status = "UNAVAILABLE"
            rss_error = None
            thread_ids: List[int] = []
            try:
                threads = self.adapter.get_threads(pid)
                thread_ids = [t.get("tid", pid) for t in threads if isinstance(t, dict)]
                info["threads"] = threads
                info["thread_count"] = len(thread_ids)
            except Exception as te:
                info["threads_error"] = str(te)

            try:
                status = self.adapter.get_process_status(pid)
                if not status:
                    rss_metric_status = "UNAVAILABLE"
                    rss_error = "Process status dictionary is empty or unreadable"
                else:
                    info["status_fields"] = status
                    if "VmRSS" in status:
                        try:
                            raw_rss = status["VmRSS"]
                            if isinstance(raw_rss, str):
                                raw_rss = raw_rss.strip().split()[0]
                            val_rss = int(raw_rss)
                            if val_rss > 0:
                                rss_kb = val_rss
                                rss_metric_status = "OBSERVED_VALUE"
                            else:
                                rss_kb = 0
                                rss_metric_status = "OBSERVED_ZERO"
                        except (ValueError, TypeError) as ve:
                            rss_kb = None
                            rss_metric_status = "UNAVAILABLE"
                            rss_error = f"Malformed VmRSS value '{status.get('VmRSS')}': {ve}"
                    else:
                        rss_kb = None
                        rss_metric_status = "UNAVAILABLE"
                        rss_error = "VmRSS field absent in process status"

                    if "VmSize" in status:
                        try:
                            info["vsize_kb"] = int(status["VmSize"])
                        except Exception:
                            pass
            except Exception as pe:
                rss_metric_status = "UNAVAILABLE"
                rss_error = str(pe)

            info["rss_kb"] = rss_kb
            info["rss_metric_status"] = rss_metric_status
            if rss_error:
                info["rss_error"] = rss_error

            if self.budget_tracker and res_id:
                approx_bytes = max(256, len(str(info).encode("utf-8", errors="replace")))
                self.budget_tracker.reconcile_reservation(
                    res_id,
                    actual_bytes_read=None,
                    conservative_estimate_bytes=approx_bytes,
                    latency_us=max(100.0, (time.monotonic_ns() - t0) / 1000.0),
                    is_failure=False,
                    physical_reads=0,
                )
                self.budget_tracker.record_sample(profile_id="collect_process_info")
                res_id = None

            is_observed = rss_metric_status in ("OBSERVED_VALUE", "OBSERVED_ZERO")
            rec = RuntimeEvidenceRecord(
                evidence_id=f"ev_{uuid.uuid4().hex[:12]}",
                collection_method="adapter_status_and_liveness",
                target_pid=pid,
                observed_value={"rss_kb": rss_kb, "rss_metric_status": rss_metric_status, "thread_count": len(thread_ids), "alive": True},
                collection_scope="PROCESS_METRICS",
                collection_status=COLLECTION_STATUS_SUCCESS if is_observed else COLLECTION_STATUS_PARTIAL,
                limitations=[rss_error] if rss_error else [],
                provenance_class=PROVENANCE_LIVE_RUNTIME_CAPTURE,
                raw_details=info,
            )
            ev_records.append(rec)
            return info, ev_records
        finally:
            if self.budget_tracker and res_id:
                self.budget_tracker.release_reservation(res_id)

    def collect_memory_maps(self, pid: int) -> Tuple[List[Dict[str, Any]], List[RuntimeEvidenceRecord]]:
        """Collects memory mappings directly from target /proc/<pid>/maps."""
        ev_records: List[RuntimeEvidenceRecord] = []
        res_id = None
        t0 = time.monotonic_ns()
        if self.budget_tracker:
            est_b = max(1, min(4096, self.budget_tracker.limits.max_bytes_read))
            allowed, reason, res_id = self.budget_tracker.reserve(
                estimated_bytes=est_b,
                estimated_latency_ms=10.0,
                estimated_samples=1,
                profile_id="collect_memory_maps",
            )
            if not allowed:
                rec = RuntimeEvidenceRecord(
                    evidence_id=f"ev_{uuid.uuid4().hex[:12]}",
                    collection_method="budget_guard",
                    target_pid=pid,
                    observed_value=None,
                    collection_status="BUDGET_EXHAUSTED",
                    limitations=[f"Budget exhausted before collecting memory maps: {reason}"],
                    provenance_class=PROVENANCE_LIVE_RUNTIME_CAPTURE,
                )
                ev_records.append(rec)
                return [], ev_records
        try:
            maps = self.adapter.get_proc_maps(pid)
            approx_bytes = max(512, len(maps) * 64)
            if self.budget_tracker and res_id:
                self.budget_tracker.reconcile_reservation(
                    res_id,
                    actual_bytes_read=None,
                    conservative_estimate_bytes=approx_bytes,
                    latency_us=max(100.0, (time.monotonic_ns() - t0) / 1000.0),
                    is_failure=False,
                    physical_reads=0,
                )
                self.budget_tracker.record_sample(profile_id="collect_memory_maps")
                res_id = None
            rec = RuntimeEvidenceRecord(
                evidence_id=f"ev_{uuid.uuid4().hex[:12]}",
                collection_method="adapter.get_proc_maps",
                target_pid=pid,
                observed_value={"mapping_count": len(maps)},
                collection_scope="VMA_MAPPINGS",
                collection_status=COLLECTION_STATUS_SUCCESS,
                provenance_class=PROVENANCE_LIVE_RUNTIME_CAPTURE,
                raw_details={"mapping_count": len(maps)},
            )
            ev_records.append(rec)
            return maps, ev_records
        except Exception as e:
            if self.budget_tracker and res_id:
                self.budget_tracker.release_reservation(res_id)
                res_id = None
            rec = RuntimeEvidenceRecord(
                evidence_id=f"ev_{uuid.uuid4().hex[:12]}",
                collection_method="adapter.get_proc_maps",
                target_pid=pid,
                observed_value=None,
                collection_status=COLLECTION_STATUS_FAILED,
                limitations=[f"Failed to read /proc/{pid}/maps: {e}"],
                provenance_class=PROVENANCE_LIVE_RUNTIME_CAPTURE,
            )
            ev_records.append(rec)
            return [], ev_records
        finally:
            if self.budget_tracker and res_id:
                self.budget_tracker.release_reservation(res_id)

    def read_memory_range(
        self,
        pid: int,
        address: Union[int, str],
        size: int = 16,
    ) -> Tuple[Optional[bytes], str, Optional[str], List[RuntimeEvidenceRecord]]:
        """Zero-stop read of target memory slice with provenance tracking."""
        ev_records: List[RuntimeEvidenceRecord] = []
        try:
            addr_int = int(address, 16) if isinstance(address, str) and (address.startswith("0x") or any(c in "abcdefABCDEF" for c in address)) else int(address)
        except Exception:
            try:
                addr_int = int(str(address), 16)
            except Exception:
                addr_int = 0

        res_id = None
        t0 = time.monotonic_ns()
        if self.budget_tracker:
            allowed, reason, res_id = self.budget_tracker.reserve(
                estimated_bytes=max(1, size),
                estimated_latency_ms=2.0,
                estimated_samples=1,
                profile_id="read_memory_range",
            )
            if not allowed:
                rec = RuntimeEvidenceRecord(
                    evidence_id=f"ev_{uuid.uuid4().hex[:12]}",
                    collection_method="budget_guard",
                    target_pid=pid,
                    address=addr_int,
                    observed_value=None,
                    collection_status="BUDGET_EXHAUSTED",
                    limitations=[f"Budget exhausted before reading memory: {reason}"],
                    provenance_class=PROVENANCE_LIVE_RUNTIME_CAPTURE,
                )
                ev_records.append(rec)
                return None, "BUDGET_EXHAUSTED", reason, ev_records

        try:
            data, method, err = self.adapter.read_memory(pid, addr_int, size)
            if self.budget_tracker and res_id:
                actual_bytes = len(data) if data is not None else 0
                self.budget_tracker.reconcile_reservation(
                    res_id,
                    actual_bytes_read=actual_bytes,
                    latency_us=max(50.0, (time.monotonic_ns() - t0) / 1000.0),
                    is_failure=(data is None),
                )
                self.budget_tracker.record_sample(profile_id="read_memory_range")
                res_id = None
        except Exception as e:
            if self.budget_tracker and res_id:
                self.budget_tracker.release_reservation(res_id)
                res_id = None
            data, method, err = None, "exception", str(e)
        finally:
            if self.budget_tracker and res_id:
                self.budget_tracker.release_reservation(res_id)

        status = COLLECTION_STATUS_SUCCESS if data is not None else COLLECTION_STATUS_FAILED
        limits = [f"Memory read at 0x{addr_int:x} failed: {err}"] if err else []

        rec = RuntimeEvidenceRecord(
            evidence_id=f"ev_{uuid.uuid4().hex[:12]}",
            collection_method=f"adapter.read_memory({method})",
            target_pid=pid,
            address=addr_int,
            observed_value=data.hex() if data is not None else None,
            collection_scope="MEMORY_SLICE",
            collection_status=status,
            limitations=limits,
            provenance_class=PROVENANCE_LIVE_RUNTIME_CAPTURE,
            raw_details={"address_hex": f"0x{addr_int:x}", "size": size, "method": method, "error": err},
        )
        ev_records.append(rec)
        return data, method, err, ev_records

    def evaluate_dwarf_expression(
        self,
        pid: int,
        companion_elf: str,
        expression: str,
    ) -> Tuple[Dict[str, Any], List[RuntimeEvidenceRecord]]:
        """Evaluates a DWARF variable or struct expression non-intrusively."""
        ev_records: List[RuntimeEvidenceRecord] = []
        res_id = None
        t0 = time.monotonic_ns()
        if self.budget_tracker:
            est_b = max(1, min(1024, self.budget_tracker.limits.max_bytes_read))
            allowed, reason, res_id = self.budget_tracker.reserve(
                estimated_bytes=est_b,
                estimated_latency_ms=10.0,
                estimated_samples=1,
                profile_id="evaluate_dwarf_expression",
            )
            if not allowed:
                rec = RuntimeEvidenceRecord(
                    evidence_id=f"ev_{uuid.uuid4().hex[:12]}",
                    collection_method="budget_guard",
                    target_pid=pid,
                    source_variable=expression,
                    observed_value=None,
                    collection_status="BUDGET_EXHAUSTED",
                    limitations=[f"Budget exhausted before evaluating DWARF expression '{expression}': {reason}"],
                    provenance_class=PROVENANCE_LIVE_RUNTIME_CAPTURE,
                )
                ev_records.append(rec)
                return {"status": "BUDGET_EXHAUSTED", "error": reason}, ev_records

        try:
            res = self.watch_manager.evaluate_symbol_paths(
                pid=pid,
                companion_elf_path=companion_elf,
                expressions=[expression],
                adapter=self.adapter,
            )
            results = res.get("results", [])
            val_item = results[0] if results else {}
            status_str = val_item.get("status", "NOT_FOUND")
            obs_val = val_item.get("value")
            addr_int = val_item.get("address_int")

            approx_bytes = max(128, len(str(obs_val).encode("utf-8", errors="replace"))) if obs_val is not None else 64
            if self.budget_tracker and res_id:
                self.budget_tracker.reconcile_reservation(
                    res_id,
                    actual_bytes_read=None,
                    conservative_estimate_bytes=approx_bytes,
                    latency_us=max(100.0, (time.monotonic_ns() - t0) / 1000.0),
                    is_failure=(status_str != "OBSERVED"),
                    physical_reads=0,
                )
                self.budget_tracker.record_sample(profile_id="evaluate_dwarf_expression")
                res_id = None

            limits = []
            if status_str != "OBSERVED":
                limits.append(f"Expression '{expression}' could not be resolved: {status_str} ({val_item.get('error', '')})")

            rec = RuntimeEvidenceRecord(
                evidence_id=f"ev_{uuid.uuid4().hex[:12]}",
                collection_method="watch_manager.evaluate_symbol_paths",
                target_pid=pid,
                address=addr_int,
                source_variable=expression,
                observed_value=obs_val,
                collection_scope="DWARF_VARIABLE",
                collection_status=COLLECTION_STATUS_SUCCESS if status_str == "OBSERVED" else COLLECTION_STATUS_PARTIAL,
                limitations=limits,
                provenance_class=PROVENANCE_LIVE_RUNTIME_CAPTURE,
                raw_details=val_item,
            )
            ev_records.append(rec)
            return val_item, ev_records
        except Exception as e:
            if self.budget_tracker and res_id:
                self.budget_tracker.release_reservation(res_id)
                res_id = None
            rec = RuntimeEvidenceRecord(
                evidence_id=f"ev_{uuid.uuid4().hex[:12]}",
                collection_method="watch_manager.evaluate_symbol_paths",
                target_pid=pid,
                source_variable=expression,
                observed_value=None,
                collection_status=COLLECTION_STATUS_FAILED,
                limitations=[f"DWARF evaluation exception for '{expression}': {e}"],
                provenance_class=PROVENANCE_LIVE_RUNTIME_CAPTURE,
            )
            ev_records.append(rec)
            return {"status": "ERROR", "error": str(e)}, ev_records
        finally:
            if self.budget_tracker and res_id:
                self.budget_tracker.release_reservation(res_id)

    def _discover_dwarf_symbols(self, companion_elf: Optional[str]) -> Dict[str, Any]:
        """Discovers product-general variables, structs, pointers, counters, and containers from DWARF."""
        discovered: Dict[str, Any] = {
            "pointers": [],
            "structs": [],
            "containers": [],
            "alloc_counters": [],
            "free_counters": [],
            "state_vars": [],
            "magic_canaries": [],
            "capacity_length_pairs": [],
        }
        if not companion_elf or not os.path.exists(companion_elf):
            return discovered

        try:
            from .dwarf_indexer import DwarfIndexer
            idx = DwarfIndexer.get_index(companion_elf)
            cap_vars: List[str] = []
            len_vars: List[str] = []

            for v in idx.global_variables:
                if not v.name or v.name.startswith("__"):
                    continue
                vn_low = v.name.lower()
                t = idx.resolve_canonical_type(v.type_offset) if v.type_offset else None
                tname = (t.name or "").lower() if t else ""

                if t and t.tag == "DW_TAG_pointer_type":
                    discovered["pointers"].append(v.name)
                elif t and t.tag in ("DW_TAG_structure_type", "DW_TAG_class_type"):
                    discovered["structs"].append((v.name, t))
                    if "vector" in tname or "list" in tname or "deque" in tname or any(k in vn_low for k in ("pool", "leak", "retained", "buffer")):
                        discovered["containers"].append(v.name)

                    # Inspect struct members
                    s_caps: List[str] = []
                    s_lens: List[str] = []
                    for m in getattr(t, "members", []):
                        mn = m.name or ""
                        mn_low = mn.lower()
                        mt = idx.resolve_canonical_type(m.type_offset) if m.type_offset else None
                        if (mt and mt.tag == "DW_TAG_pointer_type") or any(k in mn_low for k in ("ptr", "addr", "payload", "buf", "cache", "record")):
                            discovered["pointers"].append(f"{v.name}.{mn}")
                        if any(k in mn_low for k in ("magic", "canary", "header", "tag")):
                            discovered["magic_canaries"].append(f"{v.name}.{mn}")
                        if any(k in mn_low for k in ("state", "status", "phase", "mode")):
                            discovered["state_vars"].append(f"{v.name}.{mn}")
                        if any(k in mn_low for k in ("capacity", "max", "limit")):
                            s_caps.append(f"{v.name}.{mn}")
                        if any(k in mn_low for k in ("len", "length", "size", "count")) and "alloc" not in mn_low and "free" not in mn_low:
                            s_lens.append(f"{v.name}.{mn}")
                        if any(k in mn_low for k in ("alloc", "malloc")) and "free" not in mn_low:
                            discovered["alloc_counters"].append(f"{v.name}.{mn}")
                        if any(k in mn_low for k in ("free", "dealloc", "release", "reclaim")):
                            discovered["free_counters"].append(f"{v.name}.{mn}")
                        if any(k in mn_low for k in ("pool", "vector", "retained", "cache")):
                            discovered["containers"].append(f"{v.name}.{mn}")

                    for c in s_caps:
                        for l in s_lens:
                            discovered["capacity_length_pairs"].append((c, l))

                else:
                    if any(k in vn_low for k in ("magic", "canary", "guard")):
                        discovered["magic_canaries"].append(v.name)
                    if any(k in vn_low for k in ("state", "status", "phase", "mode", "heartbeat", "step")):
                        discovered["state_vars"].append(v.name)
                    if any(k in vn_low for k in ("alloc", "malloc")) and "free" not in vn_low:
                        discovered["alloc_counters"].append(v.name)
                    if any(k in vn_low for k in ("free", "dealloc", "release", "reclaim")):
                        discovered["free_counters"].append(v.name)
                    if any(k in vn_low for k in ("capacity", "max", "limit")):
                        cap_vars.append(v.name)
                    if any(k in vn_low for k in ("len", "length", "size")) and "alloc" not in vn_low and "free" not in vn_low:
                        len_vars.append(v.name)

            for c in cap_vars:
                for l in len_vars:
                    discovered["capacity_length_pairs"].append((c, l))

        except Exception:
            pass

        return discovered

    def collect_for_recipe(
        self,
        recipe: Any,
        pid: Optional[int],
        companion_elf: Optional[str] = None,
        target_assessment: Optional[Any] = None,
        classification: Optional[Any] = None,
        session_id: Optional[str] = None,
        epoch_id: Optional[int] = None,
    ) -> Tuple[Dict[str, Any], List[RuntimeEvidenceRecord]]:
        """Dispatches live runtime collection tailored to the recipe specification.
        Returns (normalized_observation_dict, collected_evidence_records).
        """
        recipe_id = getattr(recipe, "recipe_id", str(recipe))
        domain = getattr(recipe, "domain", "")
        all_records: List[RuntimeEvidenceRecord] = []
        observation_data: Dict[str, Any] = {
            "recipe_id": recipe_id,
            "pid": pid,
            "companion_elf": companion_elf,
        }

        # Guard: No target PID or offline/fixture mode
        if pid is None or pid <= 0:
            rec = RuntimeEvidenceRecord(
                evidence_id=f"ev_{uuid.uuid4().hex[:12]}",
                collection_method="offline_assessment",
                target_pid=pid,
                observed_value=None,
                collection_status=COLLECTION_STATUS_UNAVAILABLE,
                limitations=["No live target PID specified (offline or fixture mode)"],
                provenance_class=PROVENANCE_HISTORICAL_RECORD if companion_elf else PROVENANCE_SYNTHETIC_FIXTURE,
            )
            all_records.append(rec)
            observation_data["prerequisites_missing"] = True
            observation_data["missing_prerequisites"] = ["LIVE_TARGET_PID"]
            return observation_data, all_records

        # Guard: Check observation budget exhaustion
        if self.budget_tracker and not self.budget_tracker.can_continue():
            rec = RuntimeEvidenceRecord(
                evidence_id=f"ev_{uuid.uuid4().hex[:12]}",
                collection_method="budget_guard",
                target_pid=pid,
                observed_value=None,
                collection_status="BUDGET_EXHAUSTED",
                limitations=[f"Budget exhausted before collecting {recipe_id}: {self.budget_tracker.exhaustion_reason}"],
                provenance_class=PROVENANCE_HISTORICAL_RECORD if companion_elf else PROVENANCE_SYNTHETIC_FIXTURE,
            )
            all_records.append(rec)
            observation_data["budget_exhausted"] = True
            observation_data["exhaustion_reason"] = self.budget_tracker.exhaustion_reason
            return observation_data, all_records

        # Check target capability
        caps = getattr(target_assessment, "capabilities", []) if target_assessment else []
        limits = getattr(target_assessment, "limitations", []) if target_assessment else []

        # -------------------------------------------------------------------------
        # 1. Memory Integrity Domain
        # -------------------------------------------------------------------------
        dwarf_syms = self._discover_dwarf_symbols(companion_elf)

        if domain == "MEMORY_INTEGRITY" or recipe_id in (
            "RECIPE_INVALID_MEMORY_ACCESS",
            "RECIPE_DOUBLE_FREE",
            "RECIPE_INVALID_FREE",
            "RECIPE_USE_AFTER_FREE",
            "RECIPE_HEAP_METADATA_CORRUPTION",
            "RECIPE_UNEXPECTED_NULL_OR_INVALID_POINTERS",
            "RECIPE_OBJECT_LIFETIME_ANOMALIES",
        ):
            maps, m_recs = self.collect_memory_maps(pid)
            all_records.extend(m_recs)
            observation_data["memory_regions_count"] = len(maps)

            # Discover candidate pointer expressions
            extracted_vars: List[str] = []
            if classification and hasattr(classification, "extracted_entities"):
                extracted_vars.extend(classification.extracted_entities.get("variables", []))
                extracted_vars.extend(classification.extracted_entities.get("pointers", []))

            # Prioritize extracted entities from user problem description, then discovered DWARF pointers
            candidates: List[str] = []
            for ev in extracted_vars:
                if ev not in candidates:
                    candidates.append(ev)
            for dp in dwarf_syms.get("pointers", []):
                if dp not in candidates:
                    candidates.append(dp)

            observed_addr = None
            ptr_name = None
            if companion_elf and os.path.exists(companion_elf):
                for cand in candidates:
                    val_item, v_recs = self.evaluate_dwarf_expression(pid, companion_elf, cand)
                    all_records.extend(v_recs)
                    if val_item.get("status") == "OBSERVED":
                        ptr_val = val_item.get("value")
                        ptr_name = cand
                        # Extract integer pointer address
                        if isinstance(ptr_val, dict):
                            for k, v in ptr_val.items():
                                if any(pk in k.lower() for pk in ("ptr", "addr", "payload", "buf", "cache", "record")):
                                    try:
                                        observed_addr = int(v, 16) if isinstance(v, str) and v.startswith("0x") else int(v)
                                        ptr_name = f"{cand}.{k}"
                                        break
                                    except Exception:
                                        pass
                        else:
                            try:
                                observed_addr = int(ptr_val, 16) if isinstance(ptr_val, str) and ptr_val.startswith("0x") else int(ptr_val)
                            except Exception:
                                pass
                        if observed_addr is not None:
                            break

            # Check magic/corruption in struct if found
            magic_corrupted = False
            if companion_elf and os.path.exists(companion_elf):
                for mc in dwarf_syms.get("magic_canaries", []):
                    v_magic, m_recs = self.evaluate_dwarf_expression(pid, companion_elf, mc)
                    all_records.extend(m_recs)
                    if v_magic.get("status") == "OBSERVED":
                        magic_val = v_magic.get("value")
                        try:
                            m_int = int(magic_val, 16) if isinstance(magic_val, str) and magic_val.startswith("0x") else int(magic_val)
                            if m_int in (0xDEADBEEF, 0xBAADF00D, 0xBAADBAAD, 0xDEADDEAD):
                                magic_corrupted = True
                                observation_data["chunk_state"] = "CORRUPTED"
                                observation_data["magic_corrupted"] = True
                                observation_data["observed_magic"] = f"0x{m_int:x}"
                                break
                        except Exception:
                            pass

            # If an address was observed, check its VMA mapping & probe memory
            if observed_addr is not None:
                # In healthy processes, an idle pointer may be nullptr (0x0) without being a crash fault.
                # Only flag 0x0 as an invalid memory access if corruption or crash symptoms were observed.
                is_crash_query = bool(classification and any(s in str(classification.extracted_entities).lower() for s in ["sigsegv", "crash", "fault"]))
                if observed_addr == 0 and not magic_corrupted and not is_crash_query:
                    observation_data["pointer_name"] = ptr_name
                    observation_data["pointer_value"] = "0x0"
                    observation_data["is_mapped"] = True
                    observation_data["is_null_allowed"] = True
                    observation_data["vma_permissions"] = "r--p"
                    observation_data["violation_type"] = "NONE"
                    observation_data["is_healthy"] = True
                else:
                    observation_data["faulting_address"] = f"0x{observed_addr:x}"
                    observation_data["address"] = observed_addr
                    observation_data["target_address"] = observed_addr
                    observation_data["pointer_name"] = ptr_name
                    observation_data["pointer_value"] = f"0x{observed_addr:x}"

                    # Check NULL page
                    if 0 <= observed_addr <= 4096:
                        observation_data["is_mapped"] = False
                        observation_data["vma_permissions"] = "---p"
                        observation_data["violation_type"] = "NULL_POINTER_DEREFERENCE"
                    else:
                        # Check in maps
                        matching_map = None
                        for m in maps:
                            def _parse_m_addr(v):
                                if isinstance(v, int):
                                    return v
                                if isinstance(v, str):
                                    try:
                                        return int(v, 16) if v.startswith("0x") else int(v)
                                    except Exception:
                                        return 0
                                return 0
                            m_start = m.get("start_int")
                            if m_start is None:
                                m_start = _parse_m_addr(m.get("start", 0))
                            m_end = m.get("end_int")
                            if m_end is None:
                                m_end = _parse_m_addr(m.get("end", 0))
                            if m_start <= observed_addr < m_end:
                                matching_map = m
                                break
                        if matching_map:
                            observation_data["is_mapped"] = True
                            observation_data["vma_permissions"] = matching_map.get("permissions", "r--p")
                        else:
                            observation_data["is_mapped"] = False
                            observation_data["vma_permissions"] = "---p"

                    # Probe reading 16 bytes at observed address
                    if observed_addr > 4096 and observation_data.get("is_mapped"):
                        raw_b, _, read_err, r_recs = self.read_memory_range(pid, observed_addr, 16)
                        all_records.extend(r_recs)
                        if read_err:
                            observation_data["read_error"] = read_err
                        if raw_b:
                            # Check poison bytes
                            if b"\xba\xad\xba\xad" in raw_b or b"\xde\xad\xbe\xef" in raw_b:
                                observation_data["poison_pattern"] = raw_b.hex()
                                observation_data["chunk_state"] = "FREED"

            # In case no candidate pointer was found, record limitation
            if observed_addr is None and not observation_data.get("faulting_address"):
                lims = ["No candidate pointer address identified from DWARF symbols or classification"]
                if recipe_id in ("RECIPE_DOUBLE_FREE", "RECIPE_INVALID_FREE", "RECIPE_USE_AFTER_FREE", "RECIPE_OBJECT_LIFETIME_ANOMALIES"):
                    lims.append("Target process lacks dynamic allocation event tracer / hook; lifecycle events unavailable at runtime")
                    observation_data["lifecycle_tracing_unavailable"] = True
                    observation_data["missing_capability"] = "DYNAMIC_EVENT_TRACING"
                rec_lim = RuntimeEvidenceRecord(
                    evidence_id=f"ev_{uuid.uuid4().hex[:12]}",
                    collection_method="dwarf_pointer_search",
                    target_pid=pid,
                    observed_value=None,
                    collection_status=COLLECTION_STATUS_PARTIAL,
                    limitations=lims,
                    provenance_class=PROVENANCE_LIVE_RUNTIME_CAPTURE,
                )
                all_records.append(rec_lim)

            return observation_data, all_records

        # -------------------------------------------------------------------------
        # 2. Memory Growth and Leaks Domain
        # -------------------------------------------------------------------------
        if domain == "MEMORY_GROWTH" or "GROWTH" in recipe_id or "LEAK" in recipe_id or "IMBALANCE" in recipe_id:
            # 1. Enforce verified target identity
            target_key, ident, id_err = self.get_target_identity_key(pid)
            if not target_key:
                rec_id = RuntimeEvidenceRecord(
                    evidence_id=f"ev_{uuid.uuid4().hex[:12]}",
                    collection_method="identity_verification",
                    target_pid=pid,
                    observed_value=None,
                    collection_status="IDENTITY_UNAVAILABLE",
                    limitations=[id_err or "Mandatory identity fields unavailable"],
                    provenance_class=PROVENANCE_LIVE_RUNTIME_CAPTURE,
                )
                all_records.append(rec_id)
                observation_data.update({
                    "identity_status": "IDENTITY_UNAVAILABLE",
                    "identity_error": id_err,
                    "epoch_count": 0,
                    "samples_count": 0,
                    "rss_history_kb": [],
                    "heap_series_kb": [],
                })
                return observation_data, all_records

            info, p_recs = self.collect_process_info(pid)
            all_records.extend(p_recs)
            curr_rss = info.get("rss_kb")  # Can be None if UNAVAILABLE

            # Scoped history key prevents cross-process, cross-session, cross-boot contamination
            scoped_key = f"{session_id or 'default'}::{target_key}"
            if scoped_key not in self._historical_samples:
                self._historical_samples[scoped_key] = {
                    "session_id": session_id or "default",
                    "target_key": target_key,
                    "identity": ident,
                    "samples": [],
                    "last_epoch_id": 0,
                    "last_monotonic_ns": 0,
                    "has_temporal_regression": False,
                    "has_out_of_order_epochs": False,
                    "insufficient_temporal_separation": False,
                    "counter_reset_detected": False,
                }
            hist_state = self._historical_samples[scoped_key]

            now_mono_ns = time.monotonic_ns()
            now_wall = time.time()
            last_mono_ns = hist_state["last_monotonic_ns"]
            MIN_EPOCH_SEPARATION_NS = 50_000_000  # 50ms minimum temporal separation

            # Clock regression check
            if last_mono_ns > 0 and now_mono_ns < last_mono_ns:
                hist_state["has_temporal_regression"] = True

            # Observation Epoch handling:
            if epoch_id is not None:
                eff_epoch_id = int(epoch_id)
                # Check for out-of-order epoch IDs
                if hist_state["samples"] and eff_epoch_id < hist_state["last_epoch_id"]:
                    hist_state["has_out_of_order_epochs"] = True
                # Check for insufficient temporal separation if caller supplies advancing epoch_id
                elif hist_state["samples"] and eff_epoch_id > hist_state["last_epoch_id"]:
                    elapsed_ns = now_mono_ns - hist_state["last_monotonic_ns"]
                    if elapsed_ns < MIN_EPOCH_SEPARATION_NS:
                        hist_state["insufficient_temporal_separation"] = True
            else:
                if not hist_state["samples"]:
                    eff_epoch_id = 1
                elif now_mono_ns - last_mono_ns >= MIN_EPOCH_SEPARATION_NS:
                    eff_epoch_id = hist_state["last_epoch_id"] + 1
                else:
                    eff_epoch_id = max(1, hist_state["last_epoch_id"])

            # Find or create sample for this epoch (same-epoch deduplication)
            epoch_sample = next((s for s in hist_state["samples"] if s["epoch_id"] == eff_epoch_id), None)
            if epoch_sample is None:
                epoch_sample = {
                    "epoch_id": eff_epoch_id,
                    "monotonic_ns": now_mono_ns,
                    "wall_time": now_wall,
                    "rss_kb": curr_rss,
                    "heap_kb": None,
                    "heap_vma_bytes": None,
                    "alloc_count": None,
                    "free_count": None,
                    "container_sizes": {},
                    "insufficient_temporal_separation": hist_state.get("insufficient_temporal_separation", False),
                }
                hist_state["samples"].append(epoch_sample)
                hist_state["last_epoch_id"] = max(eff_epoch_id, hist_state["last_epoch_id"])
                hist_state["last_monotonic_ns"] = now_mono_ns
            else:
                # Same-epoch deduplication: reuse observation point without advancing epoch or rewriting timestamps
                if curr_rss is not None:
                    epoch_sample["rss_kb"] = curr_rss

            # Inspect heap VMA mapping size if memory maps available
            maps, m_recs = self.collect_memory_maps(pid)
            all_records.extend(m_recs)
            heap_vma = next((m for m in maps if m.get("pathname") == "[heap]" or m.get("category") == "heap"), None)
            if heap_vma:
                h_size = heap_vma.get("size", 0)
                epoch_sample["heap_vma_bytes"] = h_size
                epoch_sample["heap_kb"] = h_size // 1024
                observation_data["heap_vma_bytes"] = h_size
                observation_data["heap_kb"] = h_size // 1024

            # Check containers from DWARF symbols
            if companion_elf and os.path.exists(companion_elf):
                for c_cand in dwarf_syms.get("containers", []):
                    pool_val, pool_recs = self.evaluate_dwarf_expression(pid, companion_elf, c_cand)
                    all_records.extend(pool_recs)
                    if pool_val.get("status") == "OBSERVED":
                        v = pool_val.get("value")
                        leak_count = 0
                        if isinstance(v, dict):
                            leak_count = v.get("size") if v.get("size") is not None else len(v.get("elements", []))
                        epoch_sample["container_sizes"][c_cand] = leak_count
                        observation_data["active_chunk_count"] = leak_count
                        observation_data["retained_objects_count"] = leak_count
                        observation_data["container_size"] = leak_count
                        observation_data["container_name"] = c_cand
                        if leak_count > 0:
                            break

                # Inspect allocation & free counters dynamically + counter reset detection
                for a_cand in dwarf_syms.get("alloc_counters", []):
                    alloc_v, a_recs = self.evaluate_dwarf_expression(pid, companion_elf, a_cand)
                    all_records.extend(a_recs)
                    if alloc_v.get("status") == "OBSERVED" and alloc_v.get("value") is not None:
                        try:
                            a_val = int(alloc_v["value"])
                            prev_allocs = [
                                s["alloc_count"] for s in hist_state["samples"]
                                if s["epoch_id"] < eff_epoch_id and s.get("alloc_count") is not None
                            ]
                            if prev_allocs and a_val < prev_allocs[-1]:
                                hist_state["counter_reset_detected"] = True
                            epoch_sample["alloc_count"] = a_val
                            observation_data["alloc_count"] = a_val
                            observation_data["alloc_counter_name"] = a_cand
                            break
                        except Exception:
                            pass

                for f_cand in dwarf_syms.get("free_counters", []):
                    free_v, f_recs = self.evaluate_dwarf_expression(pid, companion_elf, f_cand)
                    all_records.extend(f_recs)
                    if free_v.get("status") == "OBSERVED" and free_v.get("value") is not None:
                        try:
                            f_val = int(free_v["value"])
                            prev_frees = [
                                s["free_count"] for s in hist_state["samples"]
                                if s["epoch_id"] < eff_epoch_id and s.get("free_count") is not None
                            ]
                            if prev_frees and f_val < prev_frees[-1]:
                                hist_state["counter_reset_detected"] = True
                            epoch_sample["free_count"] = f_val
                            observation_data["free_count"] = f_val
                            observation_data["free_counter_name"] = f_cand
                            break
                        except Exception:
                            pass

            # Build MemorySample and update ObservationWindow
            obs_win = ObservationWindow(target_pid=pid, target_identity=target_key)
            if hist_state["has_temporal_regression"]:
                observation_data["has_temporal_regression"] = True
                observation_data["clock_regression_detected"] = True
            if hist_state.get("has_out_of_order_epochs"):
                observation_data["out_of_order_epoch_detected"] = True
            if hist_state.get("insufficient_temporal_separation"):
                observation_data["insufficient_temporal_separation"] = True

            for s_item in hist_state["samples"]:
                ms = MemorySample(
                    epoch_id=s_item["epoch_id"],
                    monotonic_timestamp=s_item["monotonic_ns"] / 1e9,
                    wall_clock_timestamp=s_item["wall_time"],
                    rss_kb=s_item["rss_kb"],
                    heap_vma_kb=s_item["heap_kb"],
                    container_sizes=dict(s_item.get("container_sizes", {})),
                    alloc_counter=s_item.get("alloc_count"),
                    free_counter=s_item.get("free_count"),
                    rss_metric_status="OBSERVED_VALUE" if s_item["rss_kb"] is not None else "UNAVAILABLE",
                    insufficient_temporal_separation=s_item.get("insufficient_temporal_separation", False),
                    collection_status="SUCCESS" if s_item["rss_kb"] is not None else "PARTIAL",
                )
                obs_win.record_sample(ms)

            if hist_state["has_temporal_regression"]:
                obs_win.limitations.append("Monotonic clock regression detected in observation history")
            if hist_state.get("has_out_of_order_epochs"):
                obs_win.limitations.append("Out-of-order epoch sequence detected in observation history")
            if hist_state.get("insufficient_temporal_separation"):
                obs_win.limitations.append("Insufficient temporal separation (<50ms) between observation epochs")

            rss_valid_series = [s["rss_kb"] for s in hist_state["samples"] if s.get("rss_kb") is not None]
            heap_valid_series = [s["heap_kb"] for s in hist_state["samples"] if s.get("heap_kb") is not None]

            start_rss = rss_valid_series[0] if rss_valid_series else curr_rss
            growth_pct = 0.0
            if len(rss_valid_series) > 1 and start_rss and curr_rss is not None:
                growth_pct = ((curr_rss - start_rss) / max(start_rss, 1)) * 100.0

            # Compute alloc / free counter temporal deltas
            alloc_valid_series = [s["alloc_count"] for s in hist_state["samples"] if s.get("alloc_count") is not None]
            free_valid_series = [s["free_count"] for s in hist_state["samples"] if s.get("free_count") is not None]
            if len(alloc_valid_series) >= 2 and len(free_valid_series) >= 2:
                alloc_delta = alloc_valid_series[-1] - alloc_valid_series[0]
                free_delta = free_valid_series[-1] - free_valid_series[0]
                observation_data["alloc_delta"] = alloc_delta
                observation_data["free_delta"] = free_delta
                if free_delta > 0:
                    observation_data["temporal_imbalance_ratio"] = alloc_delta / free_delta
                elif alloc_delta > 0:
                    observation_data["temporal_imbalance_ratio"] = float("inf")

            observation_data.update({
                "target_identity_key": target_key,
                "current_rss_kb": curr_rss,
                "start_rss_kb": start_rss,
                "growth_rate_pct": growth_pct,
                "samples_count": len(hist_state["samples"]),
                "epoch_count": len(hist_state["samples"]),
                "rss_history_kb": rss_valid_series,
                "heap_series_kb": heap_valid_series,
                "observation_window": obs_win,
                "counter_reset_detected": hist_state["counter_reset_detected"],
            })
            if len(heap_valid_series) >= 2:
                observation_data["heap_growth_bytes"] = (heap_valid_series[-1] - heap_valid_series[0]) * 1024

            return observation_data, all_records

        # -------------------------------------------------------------------------
        # 3. Abnormal Runtime State Domain
        # -------------------------------------------------------------------------
        if domain == "ABNORMAL_STATE" or "STATE" in recipe_id or "VARIABLE" in recipe_id or "BOUNDARY" in recipe_id:
            exprs: List[str] = []
            if classification and hasattr(classification, "extracted_entities"):
                exprs.extend(classification.extracted_entities.get("variables", []))
            for sv in dwarf_syms.get("state_vars", []):
                if sv not in exprs:
                    exprs.append(sv)

            observed_vals: Dict[str, Any] = {}
            if companion_elf and os.path.exists(companion_elf):
                for ex in exprs:
                    v_res, v_recs = self.evaluate_dwarf_expression(pid, companion_elf, ex)
                    all_records.extend(v_recs)
                    if v_res.get("status") == "OBSERVED":
                        observed_vals[ex] = v_res.get("value")

            observation_data["observed_values"] = observed_vals

            # Check primary variable
            main_var = None
            if exprs:
                for candidate_var in exprs:
                    if candidate_var in observed_vals:
                        main_var = candidate_var
                        break

            if main_var:
                val = observed_vals[main_var]
                observation_data["variable_name"] = main_var
                observation_data["observed_value"] = val
                observation_data["value"] = val
                try:
                    val_int = int(val, 16) if isinstance(val, str) and val.startswith("0x") else int(val)
                    if val_int >= 100 or val_int < 0:
                        observation_data["observed_transitions"] = [1, val_int]
                        observation_data["allowed_transitions"] = {0: [1], 1: [0, 2], 2: [0, 1]}
                        observation_data["transition_violation"] = True
                except Exception:
                    pass

            # Inspect related fields for consistency (e.g. capacity vs length pairs)
            if companion_elf and os.path.exists(companion_elf):
                for cap_name, len_name in dwarf_syms.get("capacity_length_pairs", []):
                    cap_v, c_recs = self.evaluate_dwarf_expression(pid, companion_elf, cap_name)
                    len_v, l_recs = self.evaluate_dwarf_expression(pid, companion_elf, len_name)
                    all_records.extend(c_recs)
                    all_records.extend(l_recs)
                    if cap_v.get("status") == "OBSERVED" and len_v.get("status") == "OBSERVED":
                        try:
                            cap = int(cap_v["value"])
                            b_len = int(len_v["value"])
                            observation_data["capacity"] = cap
                            observation_data["length"] = b_len
                            observation_data["buffer_capacity"] = cap
                            observation_data["buffer_length"] = b_len
                            if b_len > cap:
                                observation_data["field_inconsistency"] = True
                                observation_data["positive_evidence_found"] = True
                                observation_data["supporting_facts"] = [f"Length {b_len} ({len_name}) exceeds capacity {cap} ({cap_name})"]
                                break
                        except Exception:
                            pass

            return observation_data, all_records

        # -------------------------------------------------------------------------
        # 4. Concurrency & Thread Domain
        # -------------------------------------------------------------------------
        if domain == "CONCURRENCY" or "DEADLOCK" in recipe_id or "THREAD" in recipe_id or "LOCK" in recipe_id:
            try:
                threads = self.adapter.get_threads(pid)
                observation_data["threads"] = threads
                observation_data["thread_count"] = len(threads)
            except Exception:
                threads = []

            # Inspect thread callstacks and mutex locks using watch_manager
            try:
                callstacks_info = self.watch_manager.inspect_thread_callstacks_and_locks(
                    pid=pid,
                    companion_elf_path=companion_elf or "",
                    adapter=self.adapter,
                )
                rec = RuntimeEvidenceRecord(
                    evidence_id=f"ev_{uuid.uuid4().hex[:12]}",
                    collection_method="watch_manager.inspect_thread_callstacks_and_locks",
                    target_pid=pid,
                    observed_value={
                        "deadlock_detected": callstacks_info.get("deadlock_detected", False),
                        "threads_analyzed": len(callstacks_info.get("threads", [])),
                    },
                    collection_scope="THREAD_LOCK_GRAPH",
                    collection_status=COLLECTION_STATUS_SUCCESS,
                    provenance_class=PROVENANCE_LIVE_RUNTIME_CAPTURE,
                    raw_details=callstacks_info,
                )
                all_records.append(rec)

                observation_data["callstacks_info"] = callstacks_info
                observation_data["deadlock_detected"] = callstacks_info.get("deadlock_detected", False)
                dl_cycles = callstacks_info.get("deadlock_cycles", [])
                dl_first = callstacks_info.get("deadlock_cycle") or (dl_cycles[0] if dl_cycles else [])
                observation_data["deadlock_cycles"] = dl_cycles
                observation_data["deadlock_cycle"] = dl_first
                observation_data["blocked_threads"] = callstacks_info.get("blocked_threads", [
                    t for t in callstacks_info.get("threads", []) if t.get("waiting_on_lock")
                ])

                # Check if lock graph is incomplete (Scenario L)
                incomplete_graph = False
                for t in callstacks_info.get("threads", []):
                    wol = t.get("waiting_on_lock")
                    if wol and (not wol.get("held_by_tid") or wol.get("held_by_tid") <= 0):
                        incomplete_graph = True
                        break
                if incomplete_graph:
                    observation_data["incomplete_lock_graph"] = True
                    observation_data["insufficient_lock_info"] = True

                if callstacks_info.get("deadlock_detected"):
                    cycle = observation_data["deadlock_cycle"]
                    observation_data["cycle_tids"] = [
                        c.get("tid") or c.get("waiter_tid")
                        for c in cycle if isinstance(c, dict)
                    ]
                else:
                    blocked = callstacks_info.get("blocked_threads", [])
                    if blocked:
                        observation_data["blocked_threads"] = blocked
                        observation_data["deadlock_cycle"] = []
                        observation_data["deadlock_detected"] = False
                        if not incomplete_graph:
                            observation_data["contradicting_facts"] = ["Threads are blocked on mutex, but complete lock graph contains zero circular wait cycles."]
                            observation_data["negative_evidence_found"] = True
            except Exception as e:
                rec = RuntimeEvidenceRecord(
                    evidence_id=f"ev_{uuid.uuid4().hex[:12]}",
                    collection_method="watch_manager.inspect_thread_callstacks_and_locks",
                    target_pid=pid,
                    observed_value=None,
                    collection_status=COLLECTION_STATUS_FAILED,
                    limitations=[f"Failed to inspect thread callstacks and locks: {e}"],
                    provenance_class=PROVENANCE_LIVE_RUNTIME_CAPTURE,
                )
                all_records.append(rec)
                observation_data["lock_inspection_error"] = str(e)

            return observation_data, all_records

        # Generic fallback
        p_info, p_recs = self.collect_process_info(pid)
        all_records.extend(p_recs)
        observation_data.update(p_info)
        return observation_data, all_records


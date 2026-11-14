"""Runtime Evidence Provider (Phase 2.1.1).

Connects deterministic diagnostic recipes to actual zero-stop Linux/POSIX runtime
evidence acquisition (process info, memory mappings, process_vm_readv memory slices,
DWARF symbol paths, thread callstacks and mutex lock graphs, heap census).

Guarantees:
- Real target collection: NEVER fabricate values or report LIVE_RUNTIME_CAPTURE without an actual read.
- Embedded friendliness: zero-stop target observation, zero Python/GDB on target.
- Honest limitations: graceful degradation on missing DWARF, unreadable memory, or permission denial.
"""

from dataclasses import dataclass, field
from .dataclass_dict import asdict
from .corpus_retention import resolve_corpus_dir
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import time
from typing import Callable, Any, Dict, List, Optional, Set, Tuple, Union
import uuid

from .target_adapter import LocalTargetAdapter, TargetExecutionAdapter
from .temporal_observation_window import MemorySample, ObservationWindow, MemoryBehavior
from .watch_session import WatchSessionManager, read_process_memory_slice
from .thread_sampler import (
    LockObservationSeries,
    ThreadSampler,
    ThreadSamplingConfig,
    augment_lock_info,
    judge as judge_thread_series,
)

# Recipes whose inputs come from the per-thread time series (IMP-010)
THREAD_SAMPLING_RECIPES = frozenset({"RECIPE_THREAD_STATE_ANOMALIES", "RECIPE_LONG_RUNNING_BLOCKED_THREADS"})

# One lock inspection reads every mutex word first and each thread's futex wait afterwards.  A contended mutex being
# handed on shows, for a moment, a thread still inside its futex wait while the word already reads unlocked (or
# locked with the owner field not yet written): a waiter with no owner, i.e. an "incomplete lock graph", which makes
# the deadlock / blocked-thread checks INCONCLUSIVE.  On a loaded host the woken waiter can sit on a run queue for
# milliseconds, so the moment is not rare (measured: 2 of 200 inspections of a 4-thread hot mutex at load 5).
# Before the graph is declared incomplete it is re-read after these gaps; it is incomplete only if every re-read
# still has a waiter with no owner.  A persistent unresolved owner (undecodable layout, a real stall) is unchanged.
UNRESOLVED_WAIT_REREAD_GAPS_S = (0.02, 0.05, 0.1)


def unresolved_lock_waits(info: Any) -> List[Tuple[int, str]]:
    """(tid, lock address) of every thread waiting on a lock whose owner is not resolved in this inspection."""
    out: List[Tuple[int, str]] = []
    for t in (info or {}).get("threads", []) if isinstance(info, dict) else []:
        wol = t.get("waiting_on_lock") if isinstance(t, dict) else None
        if wol and (not wol.get("held_by_tid") or wol.get("held_by_tid") <= 0):
            out.append((int(t.get("tid") or 0), str(wol.get("lock_address"))))
    return sorted(out)


# ---------------------------------------------------------------------------------------------------------------
# Names rank candidates; they are never evidence (IMP-018 / IMP-009).
#
# A name is split into whole tokens (``_``, ``::``, ``.``, camelCase, digits); a role is a whole token, never a
# substring: "silent" is not a length, "stage" is not a tag, "freelist_len" is not a free counter.  Two variables
# are only paired (alloc/free counters, capacity/length) when the DWARF types are integers and they are
# demonstrably related: the same scope (members of one struct, or both globals) and the same name stem once the
# role token is removed ("g_buf_cap" / "g_buf_len", "alloc_count" / "free_count", "capacity" / "length").
# ---------------------------------------------------------------------------------------------------------------
_NAME_TOKEN_RE = re.compile(r"[A-Z]+(?=[A-Z][a-z])|[A-Z]?[a-z]+|[A-Z]+|[0-9]+")

ROLE_ALLOC = frozenset({"alloc", "allocs", "allocated", "allocation", "allocations", "malloc", "mallocs",
                        "malloced", "calloc", "callocs"})
ROLE_FREE = frozenset({"free", "frees", "freed", "dealloc", "deallocs", "deallocated", "deallocation",
                       "deallocations", "release", "releases", "released", "reclaim", "reclaims", "reclaimed"})
ROLE_CAPACITY = frozenset({"capacity", "cap", "max", "maximum", "limit"})
ROLE_LENGTH = frozenset({"len", "length", "size", "count", "cnt", "used"})
ROLE_MAGIC = frozenset({"magic", "canary", "cookie", "guard"})
ROLE_STATE = frozenset({"state", "status", "phase", "mode", "heartbeat", "step"})
ROLE_CONTAINER = frozenset({"pool", "vector", "vec", "list", "queue", "cache", "registry", "retained", "leak",
                            "buffer", "buffers", "map", "table", "deque"})


def name_tokens(name: str) -> List[str]:
    """Lower-case whole-word tokens of an identifier or a member path (``a.b``, ``ns::x``, ``fooBarLen``)."""
    leaf = re.split(r"\.|->|::", str(name or ""))[-1]
    return [t.lower() for t in _NAME_TOKEN_RE.findall(leaf)]


def name_has_role(name: str, role: frozenset) -> bool:
    return any(t in role for t in name_tokens(name))


def name_stem(name: str, role: frozenset) -> Tuple[str, ...]:
    """The tokens of the leaf name with the role tokens and one-letter scope prefixes (g_, s_, m_) removed: the
    part that names WHAT is counted.  ``g_limit`` and ``g_used`` share no stem."""
    return tuple(t for t in name_tokens(name) if t not in role and len(t) > 1)


def is_integer_type(t: Any) -> bool:
    """A DWARF base type holding an integer (not char / bool / floating point); typedefs must be resolved."""
    if t is None or getattr(t, "tag", None) != "DW_TAG_base_type":
        return False
    n = (getattr(t, "name", "") or "").lower()
    if any(x in n for x in ("char", "bool", "float", "double", "complex")):
        return False
    return any(x in n for x in ("int", "long", "short", "size", "unsigned", "signed"))


def _as_int(v: Any) -> Optional[int]:
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        try:
            return int(v, 0)
        except ValueError:
            return None
    return None


def canonical_type(idx: Any, type_offset: Any) -> Any:
    """The canonical DWARF type (typedef / const / volatile / _Atomic removed), or None."""
    t = idx.resolve_canonical_type(type_offset) if type_offset else None
    seen = 0
    while t is not None and t.tag == "DW_TAG_atomic_type" and t.target_type_offset is not None and seen < 8:
        t = idx.resolve_canonical_type(t.target_type_offset)
        seen += 1
    return t


def related_pairs(names: List[str], role_a: frozenset, role_b: frozenset) -> List[Tuple[str, str]]:
    """(a, b) pairs of names in ONE scope whose roles are a and b and whose stems are equal."""
    out: List[Tuple[str, str]] = []
    a_names = [n for n in names if name_has_role(n, role_a) and not name_has_role(n, role_b)]
    b_names = [n for n in names if name_has_role(n, role_b) and not name_has_role(n, role_a)]
    for a in a_names:
        for b in b_names:
            if a != b and name_stem(a, role_a) == name_stem(b, role_b):
                out.append((a, b))
    return out


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
        rec = cls._from_dict_fields(data)
        # A persisted record is restored as it was: __post_init__ must not re-derive the observation from
        # raw_details added after creation (e.g. duration_sec), or a reloaded report differs from the original.
        for k in ("observed_value", "raw_observation", "normalized_observation"):
            if k in data:
                setattr(rec, k, data[k])
        return rec

    @classmethod
    def _from_dict_fields(cls, data: Dict[str, Any]) -> "RuntimeEvidenceRecord":
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
        self.watch_manager = watch_manager or WatchSessionManager(corpus_dir=resolve_corpus_dir(corpus_dir))
        self.budget_tracker = budget_tracker
        self._historical_samples: Dict[str, Dict[str, Any]] = {}
        # IMP-010: overrides for ThreadSamplingConfig (thread_sample_count, thread_sample_interval_sec, ...)
        self.thread_sampling_overrides: Dict[str, Any] = {}
        # When a dict, a usable thread series is shared by all thread recipes of the run (None = never share)
        self.thread_series_cache: Optional[Dict[Any, Any]] = None
        # IMP-008: multi-observation memory investigation (leak_attribution.MemoryObservationConfig); None = legacy
        # single-sample behaviour of the memory branch (direct provider users / epoch-driven callers).
        self.memory_observation: Optional[Any] = None

    def _inspect_locks(self, pid: int, companion_elf: Optional[str]) -> Any:
        """One lock inspection (existing callstack/lock interface) widened with member / futex mutexes (IMP-010)."""
        info = self.watch_manager.inspect_thread_callstacks_and_locks(
            pid=pid,
            companion_elf_path=companion_elf or "",
            adapter=self.adapter,
        )
        return augment_lock_info(
            info, pid=pid, adapter=self.adapter, companion_elf=companion_elf or "", watch_manager=self.watch_manager,
        )

    def _collect_thread_series(
        self,
        recipe: Any,
        pid: int,
        companion_elf: Optional[str],
        observation_data: Dict[str, Any],
        all_records: List[RuntimeEvidenceRecord],
    ) -> None:
        """IMP-010: N samples per thread -> existing thread-recipe input keys (runaway_threads, zombie_threads,
        thread_state_anomaly, threads_healthy, blocked_duration_sec, persistent_block) + long_wait_threads."""
        cfg = ThreadSamplingConfig.from_thresholds({**getattr(recipe, "thresholds_and_conditions", {}), **self.thread_sampling_overrides})
        cache_key = (pid, repr(cfg))
        try:
            if self.thread_series_cache is not None and cache_key in self.thread_series_cache:
                # Same sample series as an earlier recipe of this run (thread recipes share one sampling window)
                derived = self.thread_series_cache[cache_key]
            else:
                sampler = ThreadSampler(self.adapter, self.watch_manager, self.budget_tracker)
                inspect = lambda: self._inspect_locks(pid, companion_elf)  # noqa: E731
                if self.memory_observation is not None:
                    # IMP-008: one /proc memory sample per thread sample - the memory trend shares this window
                    from .leak_attribution import cosampling_inspect
                    inspect = cosampling_inspect(self, pid, inspect)
                series = sampler.collect(pid, companion_elf or "", cfg, inspect_fn=inspect)
                derived = judge_thread_series(series)
                if self.thread_series_cache is not None and derived.get("thread_sampling", {}).get("status") == "OK":
                    self.thread_series_cache[cache_key] = derived
        except Exception as exc:  # noqa: BLE001
            all_records.append(RuntimeEvidenceRecord(
                evidence_id=f"ev_{uuid.uuid4().hex[:12]}",
                collection_method="thread_sampler",
                target_pid=pid,
                observed_value=None,
                collection_scope="THREAD_TIME_SERIES",
                collection_status=COLLECTION_STATUS_FAILED,
                limitations=[f"Thread time-series sampling failed: {type(exc).__name__}: {exc}"],
                provenance_class=PROVENANCE_LIVE_RUNTIME_CAPTURE,
            ))
            observation_data["thread_sampling"] = {"status": "FAILED", "error": f"{type(exc).__name__}: {exc}"}
            return
        meta = derived.get("thread_sampling", {})
        ok = meta.get("status") == "OK"
        all_records.append(RuntimeEvidenceRecord(
            evidence_id=f"ev_{uuid.uuid4().hex[:12]}",
            collection_method="thread_sampler",
            target_pid=pid,
            observed_value={k: derived.get(k) for k in (
                "thread_sampling", "thread_findings", "thread_count_trend", "thread_count_series") if k in derived},
            collection_scope="THREAD_TIME_SERIES",
            collection_status=COLLECTION_STATUS_SUCCESS if ok else COLLECTION_STATUS_FAILED,
            limitations=([] if ok else [f"Thread time series not usable: {meta.get('status')} {meta.get('stop_reason') or ''}".strip()]),
            provenance_class=PROVENANCE_LIVE_RUNTIME_CAPTURE,
            raw_details=derived,
        ))
        # Only a usable series may influence rule inputs; an unusable one adds nothing (no "healthy" by default).
        keep = dict(derived)
        if not ok:
            for k in ("threads_healthy", "thread_state_anomaly", "runaway_threads", "zombie_threads",
                      "blocked_duration_sec", "persistent_block", "long_wait_threads"):
                keep.pop(k, None)
        observation_data.update(keep)

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

    @staticmethod
    def _pointer_value(companion_elf: str, val_item: Dict[str, Any]) -> Optional[int]:
        """The address held by an evaluated expression, only when its DWARF type is a pointer (else None)."""
        if not isinstance(val_item, dict) or val_item.get("status") != "OBSERVED":
            return None
        try:
            from .dwarf_indexer import DwarfIndexer
            t_off = val_item.get("type_offset")
            t = DwarfIndexer.get_index(companion_elf).resolve_canonical_type(t_off) if t_off else None
        except Exception:  # noqa: BLE001 - an unresolvable type is "not known to be a pointer"
            t = None
        if not t or t.tag != "DW_TAG_pointer_type":
            return None
        v = val_item.get("value")
        try:
            return int(v, 16) if isinstance(v, str) and v.startswith("0x") else int(v)
        except Exception:  # noqa: BLE001
            return None

    @staticmethod
    def _value_type_kind(companion_elf: str, val_item: Dict[str, Any]) -> str:
        """integer / enum / pointer / other / unknown: what the DWARF type of an evaluated expression says it is."""
        try:
            from .dwarf_indexer import DwarfIndexer
            t_off = val_item.get("type_offset")
            if not t_off:
                return "unknown"
            t = canonical_type(DwarfIndexer.get_index(companion_elf), t_off)
        except Exception:  # noqa: BLE001 - an unresolvable type is "unknown", never "integer"
            return "unknown"
        if t is None:
            return "unknown"
        if t.tag == "DW_TAG_enumeration_type":
            return "enum"
        if t.tag == "DW_TAG_pointer_type":
            return "pointer"
        return "integer" if is_integer_type(t) else "other"

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

    def _check_magic_siblings(self, pid: int, companion_elf: str, arrays: List[Tuple[str, int, str]],
                              all_records: List[RuntimeEvidenceRecord]) -> Optional[Dict[str, Any]]:
        """The one array element whose magic field disagrees with >= 3 agreeing non-zero siblings (else None).

        Zero is an unused slot, not a disagreement; a value that occurs more than once is a second state (an
        allocated / freed magic), not damage."""
        for arr, count, member in arrays[:4]:
            vals: List[Tuple[int, int]] = []
            for i in range(min(int(count), 32)):
                item, recs = self.evaluate_dwarf_expression(pid, companion_elf, f"{arr}[{i}].{member}")
                all_records.extend(recs)
                if item.get("status") != "OBSERVED":
                    continue
                iv = _as_int(item.get("value"))
                if iv is not None and iv != 0:
                    vals.append((i, iv))
            if len(vals) < 4:
                continue
            freq: Dict[int, int] = {}
            for _, iv in vals:
                freq[iv] = freq.get(iv, 0) + 1
            expected, n_exp = max(freq.items(), key=lambda kv: kv[1])
            outliers = [(i, iv) for i, iv in vals if iv != expected]
            if n_exp >= 3 and len(outliers) == 1:
                i, iv = outliers[0]
                return {"variable": f"{arr}[{i}].{member}", "observed": f"0x{iv:x}", "expected": f"0x{expected:x}",
                        "expected_from": f"{n_exp} sibling elements of {arr} hold 0x{expected:x}"}
        return None

    def _discover_dwarf_symbols(self, companion_elf: Optional[str]) -> Dict[str, Any]:
        """Discovers product-general variables, structs, pointers, counters, and containers from DWARF.

        The DWARF type and layout decide what a variable can be; a name only ranks candidates of the right type
        (see ``name_tokens``).  Counter and capacity/length pairs are formed only between integer variables of one
        scope with the same name stem (``related_pairs``); a poison-looking value in a "magic" variable is not
        corruption (that needs an expected value: see ``_check_magic_siblings``)."""
        discovered: Dict[str, Any] = {
            "pointers": [],
            "structs": [],
            "containers": [],
            "alloc_counters": [],
            "free_counters": [],
            # (alloc, free) counter pairs: integer, same scope, same stem
            "alloc_free_pairs": [],
            "state_vars": [],
            # integer members / globals whose name has a magic token (ranked candidates only, never evidence)
            "magic_canaries": [],
            # (array variable, element count, magic member): the same magic field in sibling array elements, the
            # only expected value available without a specification
            "magic_sibling_arrays": [],
            "capacity_length_pairs": [],
            # IMP-018: structure-based candidates (type / layout, no names): "<var>.<count member>" of a struct
            # holding a pointer and an integer count (a pointer+length container); enum-typed state variables.
            "container_counts": [],
        }
        if not companion_elf or not os.path.exists(companion_elf):
            return discovered

        try:
            from .dwarf_indexer import DwarfIndexer
            idx = DwarfIndexer.get_index(companion_elf)
            int_globals: List[str] = []

            def _canon(off: Any) -> Any:
                return canonical_type(idx, off)

            for v in idx.global_variables:
                if not v.name or v.name.startswith("__"):
                    continue
                t = _canon(v.type_offset)
                tname = (t.name or "").lower() if t else ""

                if t and t.tag == "DW_TAG_pointer_type":
                    discovered["pointers"].append(v.name)
                elif t and t.tag in ("DW_TAG_structure_type", "DW_TAG_class_type"):
                    discovered["structs"].append((v.name, t))
                    # a decoded standard container (its type), or a name that ranks it; the collector reads only a
                    # decoded container's size (see _obs_memory_growth)
                    if any(k in tname for k in ("vector", "list", "deque", "map", "set")) \
                            or name_has_role(v.name, ROLE_CONTAINER):
                        discovered["containers"].append(v.name)

                    int_members: List[str] = []
                    for m in getattr(t, "members", []):
                        mn = m.name or ""
                        if not mn:
                            continue
                        mt = _canon(m.type_offset)
                        # Only the DWARF type says a member is a pointer.  A name is not evidence: an int32_t
                        # `total_buffers` (value 32) used to be read as a pointer to 0x20 because it contains "buf".
                        if mt and mt.tag == "DW_TAG_pointer_type":
                            discovered["pointers"].append(f"{v.name}.{mn}")
                        if is_integer_type(mt):
                            int_members.append(mn)
                            if name_has_role(mn, ROLE_MAGIC):
                                discovered["magic_canaries"].append(f"{v.name}.{mn}")
                            if name_has_role(mn, ROLE_STATE):
                                discovered["state_vars"].append(f"{v.name}.{mn}")
                        elif mt and mt.tag in ("DW_TAG_structure_type", "DW_TAG_class_type") \
                                and (any(k in (mt.name or "").lower() for k in ("vector", "list", "deque", "map"))
                                     or name_has_role(mn, ROLE_CONTAINER)):
                            discovered["containers"].append(f"{v.name}.{mn}")
                    # pairs only inside this struct: the struct is the relation, the stem says which fields
                    for a, b in related_pairs(int_members, ROLE_ALLOC, ROLE_FREE):
                        discovered["alloc_free_pairs"].append((f"{v.name}.{a}", f"{v.name}.{b}"))
                    for c, ln in related_pairs(int_members, ROLE_CAPACITY, ROLE_LENGTH):
                        discovered["capacity_length_pairs"].append((f"{v.name}.{c}", f"{v.name}.{ln}"))

                elif t and t.tag == "DW_TAG_array_type" and t.array_count and t.array_count >= 3:
                    et = _canon(t.target_type_offset)
                    if et and et.tag in ("DW_TAG_structure_type", "DW_TAG_class_type"):
                        for m in getattr(et, "members", []) or []:
                            if m.name and name_has_role(m.name, ROLE_MAGIC) and is_integer_type(_canon(m.type_offset)):
                                discovered["magic_sibling_arrays"].append((v.name, int(t.array_count), m.name))
                                break

                elif is_integer_type(t):
                    int_globals.append(v.name)
                    if name_has_role(v.name, ROLE_MAGIC):
                        discovered["magic_canaries"].append(v.name)
                    if name_has_role(v.name, ROLE_STATE):
                        discovered["state_vars"].append(v.name)

            # Globals are one scope only through a shared, non-empty stem ("g_buf_len" / "g_buf_cap").
            for a, b in related_pairs(int_globals, ROLE_ALLOC, ROLE_FREE):
                if name_stem(a, ROLE_ALLOC):
                    discovered["alloc_free_pairs"].append((a, b))
            for c, ln in related_pairs(int_globals, ROLE_CAPACITY, ROLE_LENGTH):
                if name_stem(c, ROLE_CAPACITY):
                    discovered["capacity_length_pairs"].append((c, ln))
            for a, b in discovered["alloc_free_pairs"]:
                discovered["alloc_counters"].append(a)
                discovered["free_counters"].append(b)

            # IMP-018: structure-based selection.  Name keywords above only RANK (they come first); the type /
            # layout tells what a variable is.
            for v in idx.global_variables:
                if not v.name or v.name.startswith("__") or not v.type_offset:
                    continue
                t = canonical_type(idx, v.type_offset)
                if t is None:
                    continue
                if t.tag == "DW_TAG_enumeration_type" and v.name not in discovered["state_vars"]:
                    discovered["state_vars"].append(v.name)
                if t.tag not in ("DW_TAG_structure_type", "DW_TAG_class_type"):
                    continue
                has_ptr, counts = False, []
                for m in getattr(t, "members", []) or []:
                    if not m.name or not m.type_offset:
                        continue
                    mt = canonical_type(idx, m.type_offset)
                    if mt is None:
                        continue
                    if mt.tag == "DW_TAG_pointer_type":
                        has_ptr = True
                    elif is_integer_type(mt):
                        counts.append(f"{v.name}.{m.name}")
                    elif mt.tag == "DW_TAG_enumeration_type" and f"{v.name}.{m.name}" not in discovered["state_vars"]:
                        discovered["state_vars"].append(f"{v.name}.{m.name}")
                if has_ptr and counts:
                    # rank a member whose name says it counts (len / count / size) before the first integer
                    ranked = [c for c in counts if name_has_role(c, ROLE_LENGTH)] or counts
                    discovered["container_counts"].append(ranked[0])

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

        dwarf_syms = self._discover_dwarf_symbols(companion_elf)
        # IMP-018: collectors are registered per observation kind; the recipe declares the kinds it needs
        # (DiagnosticRecipe.observations).  A collector that returns a result ends the collection.
        ctx = {
            "recipe": recipe, "recipe_id": recipe_id, "domain": domain, "pid": pid, "companion_elf": companion_elf,
            "target_assessment": target_assessment, "classification": classification, "session_id": session_id,
            "epoch_id": epoch_id, "caps": caps, "limits": limits, "dwarf_syms": dwarf_syms,
            "observation_data": observation_data, "all_records": all_records,
        }
        for kind in declared_observations(recipe):
            collector = OBSERVATION_COLLECTORS.get(kind)
            if collector is None:
                if kind != "process_info":
                    observation_data.setdefault("unavailable_observations", []).append(kind)
                continue
            res = collector(self, ctx)
            if res is not None:
                return res

        # Generic fallback
        p_info, p_recs = self.collect_process_info(pid)
        all_records.extend(p_recs)
        observation_data.update(p_info)
        return observation_data, all_records

    def _obs_memory_integrity(self, ctx: Dict[str, Any]) -> Optional[Tuple[Dict[str, Any], List[RuntimeEvidenceRecord]]]:
        """Collector of observation kind ``memory_integrity`` (returns the final result to stop collection, else None)."""
        recipe = ctx["recipe"]
        recipe_id = ctx["recipe_id"]
        domain = ctx["domain"]
        pid = ctx["pid"]
        companion_elf = ctx["companion_elf"]
        classification = ctx["classification"]
        session_id = ctx["session_id"]
        dwarf_syms = ctx["dwarf_syms"]
        observation_data = ctx["observation_data"]
        all_records = ctx["all_records"]
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
                    if isinstance(ptr_val, dict):
                        # a struct: only its members whose DWARF type is a pointer hold an address
                        for k in list(ptr_val)[:16]:
                            sub_item, s_recs = self.evaluate_dwarf_expression(pid, companion_elf, f"{cand}.{k}")
                            all_records.extend(s_recs)
                            sub_addr = self._pointer_value(companion_elf, sub_item)
                            if sub_addr is not None:
                                observed_addr, ptr_name = sub_addr, f"{cand}.{k}"
                                break
                    else:
                        # the value of a non-pointer (an integer counter, a flag) is not an address
                        observed_addr = self._pointer_value(companion_elf, val_item)
                        if observed_addr is not None:
                            ptr_name = cand
                    if observed_addr is not None:
                        break

        # Check magic/corruption in struct if found
        # A magic / canary value is corruption only against an expected value.  A poison-looking constant
        # (0xDEADBEEF ...) is very often the program's VALID magic, so a value alone is a neutral note.  The
        # expected value available without a specification is the same field in sibling array elements: when
        # >= 3 siblings agree and one element alone differs, that element's field was overwritten.
        magic_corrupted = False
        if companion_elf and os.path.exists(companion_elf):
            sib = self._check_magic_siblings(pid, companion_elf, dwarf_syms.get("magic_sibling_arrays", []),
                                             all_records)
            if sib is not None:
                magic_corrupted = True
                observation_data["chunk_state"] = "CORRUPTED"
                observation_data["magic_corrupted"] = True
                observation_data["observed_magic"] = sib["observed"]
                observation_data["expected_magic"] = sib["expected"]
                observation_data["magic_expected_from"] = sib["expected_from"]
                # IMP-009: still a hint (the rules cap it at probable); damage is proven by the heap checks
                observation_data["corruption_hint_source"] = "sibling_magic_disagreement"
                observation_data["corruption_hint_variable"] = sib["variable"]
            notes: Dict[str, str] = {}
            for mc in dwarf_syms.get("magic_canaries", [])[:8]:
                v_magic, m_recs = self.evaluate_dwarf_expression(pid, companion_elf, mc)
                all_records.extend(m_recs)
                if v_magic.get("status") == "OBSERVED":
                    m_int = _as_int(v_magic.get("value"))
                    if m_int is not None:
                        notes[mc] = f"0x{m_int:x}"
            if notes:
                # neutral: without an expected value nothing is compared - evidence neither way
                observation_data["magic_values_observed"] = notes
                observation_data["magic_values_not_judged"] = (
                    "no expected value (a specification or disagreeing siblings): magic values are not compared")

        # If an address was observed, check its VMA mapping & probe memory
        if observed_addr is not None:
            # IMP-018: a NULL pointer VALUE is an observed fact; a dereference is not observable from outside
            # (no fault is caught), so a NULL value is never reported as "dereferenced" - with or without a
            # crash symptom.  Other evidence (a corrupted magic) still counts on its own.
            if observed_addr == 0 and not magic_corrupted:
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

                # NULL page: record the observed pointer value only (IMP-018: not a dereference)
                if observed_addr == 0:
                    observation_data["null_pointer_value"] = True
                elif 0 < observed_addr <= 4096:
                    # A pointer VALUE inside the NULL page is observed; whether anything dereferenced it is not
                    # observable from outside (no fault is caught).  Say so explicitly: the rule must not read
                    # a missing key as "dereferenced".
                    observation_data["dereference_attempted"] = False
                    observation_data["is_mapped"] = False
                    observation_data["vma_permissions"] = "---p"
                    observation_data["violation_type"] = "NULL_PAGE_POINTER_VALUE"
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

        if _recipe_attr(recipe, "integrity_investigation_rule") and self.memory_observation is not None:
            # IMP-009: heap metadata integrity (+ global adjacency, stack margins) of a diagnose run
            from .memory_integrity import attach_integrity_observation
            attach_integrity_observation(self, recipe, pid, companion_elf, classification, session_id,
                                         observation_data, all_records)

        return observation_data, all_records
        return None

    def _obs_memory_growth(self, ctx: Dict[str, Any]) -> Optional[Tuple[Dict[str, Any], List[RuntimeEvidenceRecord]]]:
        """Collector of observation kind ``memory_growth`` (returns the final result to stop collection, else None)."""
        recipe = ctx["recipe"]
        recipe_id = ctx["recipe_id"]
        domain = ctx["domain"]
        pid = ctx["pid"]
        companion_elf = ctx["companion_elf"]
        classification = ctx["classification"]
        session_id = ctx["session_id"]
        epoch_id = ctx["epoch_id"]
        dwarf_syms = ctx["dwarf_syms"]
        observation_data = ctx["observation_data"]
        all_records = ctx["all_records"]
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
                "counter_source_changed": False,
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
                "alloc_counter_symbol": None,  # tracks which symbol sourced alloc_count this epoch
                "free_count": None,
                "free_counter_symbol": None,  # tracks which symbol sourced free_count this epoch
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
                    # Only a decoded standard container (the decoder marks it with "container") has an element
                    # count.  A plain struct's member that happens to be called "size" is not one (a pool's block
                    # size of 4096 used to be read as 4096 retained objects).
                    if not (isinstance(v, dict) and v.get("container")):
                        continue
                    leak_count = v.get("size") if v.get("size") is not None else len(v.get("elements", []))
                    if not isinstance(leak_count, int):
                        continue
                    epoch_sample["container_sizes"][c_cand] = leak_count
                    observation_data["active_chunk_count"] = leak_count
                    observation_data["retained_objects_count"] = leak_count
                    observation_data["container_size"] = leak_count
                    observation_data["container_name"] = c_cand
                    if leak_count > 0:
                        break
            # IMP-018: structure-based containers (pointer + integer count) when no named container was found
            if not observation_data.get("container_size"):
                for c_cand in dwarf_syms.get("container_counts", []):
                    cnt_val, cnt_recs = self.evaluate_dwarf_expression(pid, companion_elf, c_cand)
                    all_records.extend(cnt_recs)
                    v = cnt_val.get("value") if cnt_val.get("status") == "OBSERVED" else None
                    try:
                        v = int(v, 0) if isinstance(v, str) else v
                    except ValueError:
                        v = None
                    if isinstance(v, int) and not isinstance(v, bool) and v > 0:
                        epoch_sample["container_sizes"][c_cand] = v
                        observation_data["container_size"] = v
                        observation_data["container_name"] = c_cand
                        observation_data["container_selected_by"] = "structure"
                        break
            # The census over the window: a size alone is not accumulation, its change across epochs may be.
            c_sel = observation_data.get("container_name")
            if c_sel:
                c_series = [s["container_sizes"][c_sel] for s in hist_state["samples"]
                            if c_sel in (s.get("container_sizes") or {})]
                observation_data["container_size_series"] = c_series
                if len(c_series) >= 2:
                    observation_data["container_size_delta"] = c_series[-1] - c_series[0]

            # Allocation / free counters: only a demonstrated PAIR (integer, one scope, same stem) is read, both
            # in the same epoch, so that the two numbers describe the same thing (+ counter reset detection).
            for a_cand, f_cand in dwarf_syms.get("alloc_free_pairs", []):
                alloc_v, a_recs = self.evaluate_dwarf_expression(pid, companion_elf, a_cand)
                all_records.extend(a_recs)
                free_v, f_recs = self.evaluate_dwarf_expression(pid, companion_elf, f_cand)
                all_records.extend(f_recs)
                a_val = _as_int(alloc_v.get("value")) if alloc_v.get("status") == "OBSERVED" else None
                f_val = _as_int(free_v.get("value")) if free_v.get("status") == "OBSERVED" else None
                if a_val is None or f_val is None:
                    continue
                for key, val, sym in (("alloc", a_val, a_cand), ("free", f_val, f_cand)):
                    prev = [s[f"{key}_count"] for s in hist_state["samples"]
                            if s["epoch_id"] < eff_epoch_id and s.get(f"{key}_count") is not None]
                    if prev and val < prev[-1]:
                        hist_state["counter_reset_detected"] = True
                    prev_syms = [s.get(f"{key}_counter_symbol") for s in hist_state["samples"]
                                 if s["epoch_id"] < eff_epoch_id and s.get(f"{key}_counter_symbol") is not None]
                    if prev_syms and prev_syms[-1] != sym:
                        # Detect counter source change across epochs
                        hist_state["counter_source_changed"] = True
                        hist_state["counter_reset_detected"] = True
                    epoch_sample[f"{key}_count"] = val
                    epoch_sample[f"{key}_counter_symbol"] = sym
                    observation_data[f"{key}_count"] = val
                    observation_data[f"{key}_counter_name"] = sym
                break

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
            # Skip temporal delta when counter source changed across epochs (invalid comparison)
            if hist_state.get("counter_source_changed", False):
                observation_data["alloc_delta"] = None
                observation_data["free_delta"] = None
                observation_data["counter_source_changed"] = True
            else:
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
            "counter_source_changed": hist_state.get("counter_source_changed", False),
        })
        if len(heap_valid_series) >= 2:
            observation_data["heap_growth_bytes"] = (heap_valid_series[-1] - heap_valid_series[0]) * 1024

        if self.memory_observation is not None:
            # IMP-008: >= 3 spaced observations in this run; heap walks + growth attribution when the trend or
            # the run asks for them (shared by the memory recipes of the session).
            from .leak_attribution import attach_memory_observation
            attach_memory_observation(self, recipe, pid, companion_elf, classification, session_id,
                                      observation_data, all_records, target_key=target_key)

        return observation_data, all_records
        return None

    def _obs_runtime_state(self, ctx: Dict[str, Any]) -> Optional[Tuple[Dict[str, Any], List[RuntimeEvidenceRecord]]]:
        """Collector of observation kind ``runtime_state`` (returns the final result to stop collection, else None)."""
        recipe_id = ctx["recipe_id"]
        domain = ctx["domain"]
        pid = ctx["pid"]
        companion_elf = ctx["companion_elf"]
        classification = ctx["classification"]
        dwarf_syms = ctx["dwarf_syms"]
        observation_data = ctx["observation_data"]
        all_records = ctx["all_records"]
        exprs: List[str] = []
        if classification and hasattr(classification, "extracted_entities"):
            exprs.extend(classification.extracted_entities.get("variables", []))
        for sv in dwarf_syms.get("state_vars", []):
            if sv not in exprs:
                exprs.append(sv)

        observed_vals: Dict[str, Any] = {}
        value_kinds: Dict[str, str] = {}
        if companion_elf and os.path.exists(companion_elf):
            for ex in exprs:
                v_res, v_recs = self.evaluate_dwarf_expression(pid, companion_elf, ex)
                all_records.extend(v_recs)
                if v_res.get("status") == "OBSERVED":
                    observed_vals[ex] = v_res.get("value")
                    value_kinds[ex] = self._value_type_kind(companion_elf, v_res)

        observation_data["observed_values"] = observed_vals

        # Check primary variable.  The same type check applies to a name the user gave (symptom text /
        # related_objects) as to a discovered one: only an integer or enum value is a state value.
        main_var = None
        if exprs:
            for candidate_var in exprs:
                if candidate_var in observed_vals and value_kinds.get(candidate_var) in ("integer", "enum"):
                    main_var = candidate_var
                    break

        if main_var:
            val = observed_vals[main_var]
            observation_data["variable_name"] = main_var
            observation_data["variable_type_kind"] = value_kinds.get(main_var)
            observation_data["observed_value"] = val
            observation_data["value"] = val
            # IMP-018: a value is only an observation.  A transition violation needs an observed transition
            # and a state specification; "value >= 100" was neither, so it no longer counts as one.
            # The observed value is the current state; with a caller-supplied specification (allowed_states) the
            # rule compares the two - an observed value against a declared contract.
            try:
                observation_data["current_state"] = int(val, 16) if isinstance(val, str) and val.startswith("0x") else int(val)
            except (TypeError, ValueError):
                pass

        # Inspect related fields for consistency (capacity vs length).  Pairs come from discovery: integer fields
        # of one struct (or globals sharing a stem) whose roles are capacity and length - never a cross product
        # of names.  A violation must hold over two identical reads (a pair caught mid-update is not evidence),
        # and it is recorded for the capacity/length rule only: it is not generic "positive evidence" that any
        # other recipe of this collector would inherit.
        if companion_elf and os.path.exists(companion_elf):
            for cap_name, len_name in dwarf_syms.get("capacity_length_pairs", [])[:16]:
                reads: List[Tuple[int, int]] = []
                for _ in range(2):
                    cap_v, c_recs = self.evaluate_dwarf_expression(pid, companion_elf, cap_name)
                    len_v, l_recs = self.evaluate_dwarf_expression(pid, companion_elf, len_name)
                    all_records.extend(c_recs)
                    all_records.extend(l_recs)
                    cap = _as_int(cap_v.get("value")) if cap_v.get("status") == "OBSERVED" else None
                    b_len = _as_int(len_v.get("value")) if len_v.get("status") == "OBSERVED" else None
                    if cap is None or b_len is None:
                        break
                    reads.append((cap, b_len))
                    if b_len <= cap:
                        break           # the invariant holds on this read: nothing to confirm
                if not reads:
                    continue
                cap, b_len = reads[-1]
                if b_len > cap and not (len(reads) == 2 and reads[0] == reads[1]):
                    observation_data["capacity_length_unstable"] = [cap_name, len_name]
                    continue            # changed between the reads: caught mid-update, not a stable violation
                observation_data["capacity"] = cap
                observation_data["length"] = b_len
                observation_data["buffer_capacity"] = cap
                observation_data["buffer_length"] = b_len
                observation_data["capacity_length_pair"] = [cap_name, len_name]
                if b_len > cap:
                    observation_data["field_inconsistency"] = True
                    observation_data["field_inconsistency_facts"] = [
                        f"Length {b_len} ({len_name}) exceeds capacity {cap} ({cap_name}) on two consecutive reads"]
                    break

        return observation_data, all_records
        return None

    def _obs_threads_and_locks(self, ctx: Dict[str, Any]) -> Optional[Tuple[Dict[str, Any], List[RuntimeEvidenceRecord]]]:
        """Collector of observation kind ``threads_and_locks`` (returns the final result to stop collection, else None)."""
        recipe = ctx["recipe"]
        recipe_id = ctx["recipe_id"]
        domain = ctx["domain"]
        pid = ctx["pid"]
        companion_elf = ctx["companion_elf"]
        observation_data = ctx["observation_data"]
        all_records = ctx["all_records"]
        try:
            threads = self.adapter.get_threads(pid)
            observation_data["threads"] = threads
            observation_data["thread_count"] = len(threads)
        except Exception:
            threads = []

        # Inspect thread callstacks and mutex locks using watch_manager
        try:
            callstacks_info = self._inspect_locks(pid, companion_elf)
            transient_unresolved: List[List[Tuple[int, str]]] = []
            if isinstance(callstacks_info, dict) and not callstacks_info.get("deadlock_detected"):
                for gap in UNRESOLVED_WAIT_REREAD_GAPS_S:
                    pending = unresolved_lock_waits(callstacks_info)
                    if not pending:
                        break
                    transient_unresolved.append(pending)
                    time.sleep(gap)
                    try:
                        again = self._inspect_locks(pid, companion_elf)
                    except Exception:  # noqa: BLE001 - a failed re-read settles nothing: keep the last inspection
                        break
                    if not isinstance(again, dict) or again.get("error") or again.get("success") is False:
                        break
                    callstacks_info = again
                    if again.get("deadlock_detected"):
                        break   # a cycle goes through the persistence re-observation below like any first read
                if transient_unresolved and not unresolved_lock_waits(callstacks_info):
                    observation_data["transient_unresolved_lock_waits"] = [
                        [{"tid": t, "lock_address": a} for t, a in p] for p in transient_unresolved]
            lock_series = LockObservationSeries()   # IMP-010: every successful inspection feeds a WaitForGraph
            lock_series.add_sample(1, callstacks_info)
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
            _lo_status = callstacks_info.get("lock_owner_status")
            if _lo_status and _lo_status != "SUPPORTED":
                # Owner words could not be decoded on this target: an empty wait-for graph is "not
                # interpretable", never "no deadlock" (consumed by the lock-dependent recipes).
                observation_data["lock_owner_status"] = _lo_status
                observation_data["lock_owner_status_reason"] = callstacks_info.get("lock_owner_status_reason") or ""
                observation_data["lock_owner_unsupported"] = True
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

            observation_data["cycle_persistent"] = False
            observation_data["is_persistent"] = False
            observation_data["observation_count"] = 1
            observation_data["historical_observations"] = 1

            if callstacks_info.get("deadlock_detected"):
                cycle = observation_data["deadlock_cycle"]
                first_cycle_tids = [
                    c.get("tid") or c.get("waiter_tid")
                    for c in cycle if isinstance(c, dict)
                ]
                first_cycle_edges = {
                    (
                        int(c.get("waiter_tid") or c.get("tid") or 0),
                        str(c.get("lock_address") or c.get("lock_name") or ""),
                        int(c.get("owner_tid") or 0),
                    )
                    for c in cycle if isinstance(c, dict)
                }
                observation_data["cycle_tids"] = first_cycle_tids

                # IMP-003: Re-observe after a short interval to verify whether the circular wait persists
                reobserve_delay = float(recipe.thresholds_and_conditions.get("reobserve_interval_sec", 0.05))
                if reobserve_delay > 0:
                    time.sleep(min(reobserve_delay, 0.25))
                callstacks_info_2: Any = None
                second_error: Optional[str] = None
                try:
                    callstacks_info_2 = self._inspect_locks(pid, companion_elf)
                except Exception as e2:
                    second_error = f"{type(e2).__name__}: {e2}"
                if second_error is None:
                    if not isinstance(callstacks_info_2, dict):
                        second_error = f"unexpected result type {type(callstacks_info_2).__name__}"
                    elif callstacks_info_2.get("error") or callstacks_info_2.get("success") is False:
                        second_error = str(callstacks_info_2.get("error") or "inspection reported success=False")
                    elif (
                        callstacks_info_2.get("status") == "INCONCLUSIVE"
                        and not callstacks_info_2.get("deadlock_detected")
                    ):
                        second_error = "; ".join(str(x) for x in (callstacks_info_2.get("limitations") or [])[:3]) or "inspection INCONCLUSIVE"

                if second_error is not None:
                    # A failed re-read is neither an observation nor evidence that the cycle resolved.
                    all_records.append(RuntimeEvidenceRecord(
                        evidence_id=f"ev_{uuid.uuid4().hex[:12]}",
                        collection_method="watch_manager.inspect_thread_callstacks_and_locks",
                        target_pid=pid,
                        observed_value={"sample_index": 2},
                        collection_scope="THREAD_LOCK_GRAPH",
                        collection_status=COLLECTION_STATUS_FAILED,
                        limitations=[f"Deadlock persistence re-observation (sample 2) failed: {second_error}"],
                        provenance_class=PROVENANCE_LIVE_RUNTIME_CAPTURE,
                        raw_details=callstacks_info_2 if isinstance(callstacks_info_2, dict) else {},
                    ))
                    observation_data["reobservation_error"] = second_error
                    lock_series.add_failure(2, second_error)
                else:
                    lock_series.add_sample(2, callstacks_info_2)
                    rec_2 = RuntimeEvidenceRecord(
                        evidence_id=f"ev_{uuid.uuid4().hex[:12]}",
                        collection_method="watch_manager.inspect_thread_callstacks_and_locks",
                        target_pid=pid,
                        observed_value={
                            "deadlock_detected": callstacks_info_2.get("deadlock_detected", False),
                            "threads_analyzed": len(callstacks_info_2.get("threads", [])),
                            "sample_index": 2,
                        },
                        collection_scope="THREAD_LOCK_GRAPH",
                        collection_status=COLLECTION_STATUS_SUCCESS,
                        provenance_class=PROVENANCE_LIVE_RUNTIME_CAPTURE,
                        raw_details=callstacks_info_2,
                    )
                    all_records.append(rec_2)
                    observation_data["observation_count"] = 2
                    observation_data["historical_observations"] = 2

                    # Persistence is judged by the wait-for graph's multi-observation semantics over the
                    # successful samples (IMP-010); a different cycle is a different signature.
                    persistence = lock_series.persistence(frozenset(first_cycle_edges)) if first_cycle_edges else {
                        "persistent": False, "epochs": [], "state": "NOT_OBSERVED"}
                    observation_data["lock_graph_persistence"] = persistence
                    same_cycle_persisted = bool(first_cycle_edges and persistence["persistent"])
                    observation_data["cycle_persistent"] = same_cycle_persisted
                    observation_data["is_persistent"] = same_cycle_persisted
                    if not same_cycle_persisted and not callstacks_info_2.get("deadlock_detected"):
                        observation_data["transient_cycle_resolved"] = True
            else:
                blocked = callstacks_info.get("blocked_threads", [])
                if blocked:
                    observation_data["blocked_threads"] = blocked
                    observation_data["deadlock_cycle"] = []
                    observation_data["deadlock_detected"] = False
                    if not incomplete_graph and not observation_data.get("lock_owner_unsupported"):
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

        if recipe_id in THREAD_SAMPLING_RECIPES:
            self._collect_thread_series(recipe, pid, companion_elf, observation_data, all_records)

        return observation_data, all_records
        return None




# ---------------------------------------------------------------------------------------------------------------
# IMP-018: observation collectors, registered per observation kind
# ---------------------------------------------------------------------------------------------------------------

ObservationCollector = Callable[["RuntimeEvidenceProvider", Dict[str, Any]],
                                Optional[Tuple[Dict[str, Any], List[RuntimeEvidenceRecord]]]]
OBSERVATION_COLLECTORS: Dict[str, ObservationCollector] = {}


def register_observation_collector(kind: str, collector: ObservationCollector) -> None:
    """Register the collector of one observation kind.  ``collector(provider, ctx)`` reads the target, adds to
    ``ctx["observation_data"]`` / ``ctx["all_records"]`` and returns None (continue with the next declared kind)
    or the final ``(observation_data, records)``.  ``ctx`` holds recipe, recipe_id, pid, companion_elf,
    target_assessment, classification, session_id, epoch_id, caps, limits, dwarf_syms."""
    OBSERVATION_COLLECTORS[kind] = collector


def _recipe_attr(recipe: Any, name: str) -> Any:
    """A declared attribute of ``recipe`` (a DiagnosticRecipe, or a recipe id looked up in the registry)."""
    if hasattr(recipe, name):
        return getattr(recipe, name)
    from .diagnostic_recipes import DiagnosticRecipeRegistry
    return getattr(DiagnosticRecipeRegistry.get_recipe(getattr(recipe, "recipe_id", str(recipe))), name, None)


def declared_observations(recipe: Any) -> List[str]:
    """The observation kinds a recipe declares; a recipe that declares none gets only process info."""
    kinds = list(getattr(recipe, "observations", None) or ())
    if not kinds:
        from .diagnostic_recipes import DiagnosticRecipeRegistry
        reg = DiagnosticRecipeRegistry.get_recipe(getattr(recipe, "recipe_id", str(recipe)))
        kinds = list(getattr(reg, "observations", None) or ())
    return kinds or ["process_info"]


register_observation_collector("memory_integrity", RuntimeEvidenceProvider._obs_memory_integrity)
register_observation_collector("memory_growth", RuntimeEvidenceProvider._obs_memory_growth)
register_observation_collector("runtime_state", RuntimeEvidenceProvider._obs_runtime_state)
register_observation_collector("threads_and_locks", RuntimeEvidenceProvider._obs_threads_and_locks)

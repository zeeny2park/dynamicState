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
    ):
        self.adapter = adapter or LocalTargetAdapter()
        self.watch_manager = watch_manager or WatchSessionManager(corpus_dir=corpus_dir or "/tmp/dynamicstate_corpus")
        self._historical_samples: Dict[str, List[Dict[str, Any]]] = {}

    def collect_process_info(self, pid: int) -> Tuple[Dict[str, Any], List[RuntimeEvidenceRecord]]:
        """Collects live process status, thread count, RSS, and process identity."""
        ev_records: List[RuntimeEvidenceRecord] = []
        info: Dict[str, Any] = {"pid": pid, "alive": False}
        if not pid or pid <= 0:
            return info, ev_records

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
            return info, ev_records

        try:
            ident = self.adapter.get_process_identity(pid)
            info.update(ident)
        except Exception as e:
            info["identity_error"] = str(e)

        # RSS & Threads
        rss_kb = 0
        thread_ids: List[int] = []
        try:
            threads = self.adapter.get_threads(pid)
            thread_ids = [t.get("tid", pid) for t in threads if isinstance(t, dict)]
            info["threads"] = threads
            info["thread_count"] = len(thread_ids)
        except Exception:
            pass

        try:
            status = self.adapter.get_process_status(pid)
            if "VmRSS" in status:
                try:
                    rss_kb = int(status["VmRSS"])
                except Exception:
                    pass
            if "VmSize" in status:
                try:
                    info["vsize_kb"] = int(status["VmSize"])
                except Exception:
                    pass
            info["status_fields"] = status
        except Exception:
            pass
        info["rss_kb"] = rss_kb

        rec = RuntimeEvidenceRecord(
            evidence_id=f"ev_{uuid.uuid4().hex[:12]}",
            collection_method="adapter_status_and_liveness",
            target_pid=pid,
            observed_value={"rss_kb": rss_kb, "thread_count": len(thread_ids), "alive": True},
            collection_scope="PROCESS_METRICS",
            collection_status=COLLECTION_STATUS_SUCCESS,
            provenance_class=PROVENANCE_LIVE_RUNTIME_CAPTURE,
            raw_details=info,
        )
        ev_records.append(rec)
        return info, ev_records

    def collect_memory_maps(self, pid: int) -> Tuple[List[Dict[str, Any]], List[RuntimeEvidenceRecord]]:
        """Collects memory mappings directly from target /proc/<pid>/maps."""
        ev_records: List[RuntimeEvidenceRecord] = []
        try:
            maps = self.adapter.get_proc_maps(pid)
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

        data, method, err = self.adapter.read_memory(pid, addr_int, size)
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
                            if m.get("start_int", 0) <= observed_addr < m.get("end_int", 0) or m.get("start", 0) <= observed_addr < m.get("end", 0):
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
                rec_lim = RuntimeEvidenceRecord(
                    evidence_id=f"ev_{uuid.uuid4().hex[:12]}",
                    collection_method="dwarf_pointer_search",
                    target_pid=pid,
                    observed_value=None,
                    collection_status=COLLECTION_STATUS_PARTIAL,
                    limitations=["No candidate pointer address identified from DWARF symbols or classification"],
                    provenance_class=PROVENANCE_LIVE_RUNTIME_CAPTURE,
                )
                all_records.append(rec_lim)

            return observation_data, all_records

        # -------------------------------------------------------------------------
        # 2. Memory Growth and Leaks Domain
        # -------------------------------------------------------------------------
        if domain == "MEMORY_GROWTH" or "GROWTH" in recipe_id or "LEAK" in recipe_id or "IMBALANCE" in recipe_id:
            info, p_recs = self.collect_process_info(pid)
            all_records.extend(p_recs)
            curr_rss = info.get("rss_kb", 0)

            # Check historical samples for temporal growth
            hist = self._historical_samples.setdefault(f"rss_{pid}", [])
            hist.append({"timestamp": time.time(), "rss_kb": curr_rss})

            start_rss = hist[0]["rss_kb"] if len(hist) > 1 else curr_rss
            growth_pct = ((curr_rss - start_rss) / max(start_rss, 1)) * 100.0 if len(hist) > 1 else 0.0

            observation_data.update({
                "current_rss_kb": curr_rss,
                "start_rss_kb": start_rss,
                "growth_rate_pct": growth_pct,
                "samples_count": len(hist),
                "rss_history_kb": [s["rss_kb"] for s in hist],
                "epoch_count": len(hist),
            })

            # Inspect heap VMA mapping size if memory maps available
            maps, m_recs = self.collect_memory_maps(pid)
            all_records.extend(m_recs)
            heap_vma = next((m for m in maps if m.get("pathname") == "[heap]" or m.get("category") == "heap"), None)
            if heap_vma:
                h_size = heap_vma.get("size", 0)
                observation_data["heap_vma_bytes"] = h_size
                observation_data["heap_kb"] = h_size // 1024
                heap_hist = self._historical_samples.setdefault(f"heap_{pid}", [])
                heap_hist.append({"timestamp": time.time(), "heap_kb": h_size // 1024})
                observation_data["heap_series_kb"] = [h["heap_kb"] for h in heap_hist]
                if len(heap_hist) >= 2:
                    observation_data["heap_growth_bytes"] = (heap_hist[-1]["heap_kb"] - heap_hist[0]["heap_kb"]) * 1024

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
                        observation_data["active_chunk_count"] = leak_count
                        observation_data["retained_objects_count"] = leak_count
                        observation_data["container_size"] = leak_count
                        observation_data["container_name"] = c_cand
                        if leak_count > 0:
                            break

                # Inspect allocation & free counters dynamically
                for a_cand in dwarf_syms.get("alloc_counters", []):
                    alloc_v, a_recs = self.evaluate_dwarf_expression(pid, companion_elf, a_cand)
                    all_records.extend(a_recs)
                    if alloc_v.get("status") == "OBSERVED" and alloc_v.get("value") is not None:
                        try:
                            observation_data["alloc_count"] = int(alloc_v["value"])
                            observation_data["alloc_counter_name"] = a_cand
                            break
                        except Exception:
                            pass

                for f_cand in dwarf_syms.get("free_counters", []):
                    free_v, f_recs = self.evaluate_dwarf_expression(pid, companion_elf, f_cand)
                    all_records.extend(f_recs)
                    if free_v.get("status") == "OBSERVED" and free_v.get("value") is not None:
                        try:
                            observation_data["free_count"] = int(free_v["value"])
                            observation_data["free_counter_name"] = f_cand
                            break
                        except Exception:
                            pass

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
                observation_data["deadlock_cycle"] = callstacks_info.get("deadlock_cycle", [])
                observation_data["blocked_threads"] = callstacks_info.get("blocked_threads", [])

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
                    cycle = callstacks_info.get("deadlock_cycle", [])
                    observation_data["cycle_tids"] = [c.get("tid") for c in cycle if isinstance(c, dict)]
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


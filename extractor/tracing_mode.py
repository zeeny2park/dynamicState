"""Selective eBPF/uprobe Dynamic Event Tracing Mode (Roadmap Stage 3).

Provides an optional, explicit runtime event tracing subsystem for DynamicState:
- Decision 6.1: Zero-stop read-only memory capture remains the default.
- Tracing is an opt-in mode (enable_tracing=True or DYNAMICSTATE_ENABLE_TRACING=1).
- Distinguishes statically derived candidate locations ("정적 후보, 관측 아님") from
  runtime eBPF-observed event locations ("추적 관측, 런타임 이벤트").
- Activates CAP_ALLOCATION_TRACING capability when enabled and supported.
- Safely bounds tracing duration, event volume, and ensures clean process termination.
"""

from __future__ import annotations

import logging
import math
import os
import re
import shutil
import subprocess
import threading
import time
from typing import Any, Dict, List, Optional, Tuple, Union

from .diagnostic_recipes import (
    CAP_ALLOCATION_TRACING,
    temporary_capabilities,
)
from .ebpf_tracer import (
    EbpfCapabilityResult,
    EbpfEnvironmentChecker,
    EbpfTracer,
    runtime_to_elf_address,
)
from .debug_image import inspect_elf

logger = logging.getLogger("dynamicstate.tracing_mode")

ENV_ENABLE_TRACING = "DYNAMICSTATE_ENABLE_TRACING"
DEFAULT_TRACING_DURATION_S = 1.5
MAX_TRACING_DURATION_S = 10.0
MAX_EVENTS_CAP = 500


def _mapping_matches_binary(map_path: str, binary_path: str) -> bool:
    cleaned = map_path.removesuffix(" (deleted)")
    try:
        return os.path.realpath(cleaned) == os.path.realpath(binary_path)
    except OSError:
        return cleaned == binary_path


def _runtime_to_elf_address(addr: int, binary_path: str, maps_text: str) -> Optional[int]:
    """Convert a runtime instruction address to an ELF virtual address using PT_LOAD map bias."""
    try:
        elf = inspect_elf(binary_path)
    except Exception:
        return None
    return runtime_to_elf_address(addr, binary_path, elf, maps_text)


def is_tracing_enabled(explicit_flag: Optional[bool] = None) -> bool:
    """Return True if selective tracing mode is explicitly requested via parameter or environment."""
    if explicit_flag is not None:
        return bool(explicit_flag)
    val = os.environ.get(ENV_ENABLE_TRACING, "").strip().lower()
    return val in ("1", "true", "yes", "on", "enable", "enabled")


def check_tracing_support() -> Tuple[bool, str, Optional[EbpfCapabilityResult]]:
    """Verify host kernel, architecture, privileges, and bpftrace prerequisites for eBPF tracing."""
    try:
        checker = EbpfEnvironmentChecker()
        prereqs = checker.check_prerequisites()
        if not prereqs.supported:
            reason = "; ".join(prereqs.reasons) if prereqs.reasons else "eBPF prerequisites not satisfied"
            return False, reason, prereqs
        return True, "", prereqs
    except Exception as exc:
        return False, f"Failed to check eBPF prerequisites: {exc}", None


class SelectiveTracingSession:
    """Manages an opt-in eBPF dynamic event tracing session during process diagnosis."""

    def __init__(
        self,
        pid: int,
        binary_path: str,
        debug_image: Optional[str] = None,
        duration_s: float = DEFAULT_TRACING_DURATION_S,
        max_events: int = MAX_EVENTS_CAP,
    ):
        self.pid = pid
        self.binary_path = os.path.realpath(binary_path) if binary_path else ""
        self.debug_image = os.path.realpath(debug_image) if debug_image else self.binary_path
        if (isinstance(duration_s, bool) or not isinstance(duration_s, (int, float)) or
                not math.isfinite(float(duration_s)) or duration_s <= 0):
            raise ValueError("duration_s must be a finite positive number")
        if isinstance(max_events, bool) or not isinstance(max_events, int) or not 1 <= max_events <= MAX_EVENTS_CAP:
            raise ValueError(f"max_events must be an integer between 1 and {MAX_EVENTS_CAP}")
        self.duration_s = min(float(duration_s), MAX_TRACING_DURATION_S)
        self.max_events = max_events
        self.collected_events: List[Dict[str, Any]] = []
        self.is_supported, self.unsupported_reason, self.capability_result = check_tracing_support()

    def run_trace(self, target_functions: Optional[List[str]] = None) -> Dict[str, Any]:
        """Execute a short, bounded probe run if prerequisites are met."""
        if not self.is_supported:
            return {
                "status": "UNSUPPORTED_ENVIRONMENT",
                "reason": self.unsupported_reason,
                "events": [],
                "locations": [],
                "events_count": 0,
                "lost_events": 0,
                "malformed_records": 0,
                "sessions": [],
            }

        if not target_functions:
            target_functions = ["free", "malloc"]
        if (not isinstance(target_functions, list) or
                any(not isinstance(fn, str) or not fn or len(fn) > 512 or
                    any(ord(ch) < 32 or ord(ch) == 127 for ch in fn) for fn in target_functions)):
            raise ValueError("target_functions must be a list of non-empty printable symbol names")
        if len(set(target_functions)) != len(target_functions):
            target_functions = list(dict.fromkeys(target_functions))

        events_out: List[Dict[str, Any]] = []
        locations_out: List[Dict[str, Any]] = []
        session_summaries: List[Dict[str, Any]] = []
        failures: List[str] = []
        reported_events = 0
        lost_events = 0
        malformed_records = 0
        truncated_events = 0

        # One monotonic deadline covers every function, including attach time and cleanup.
        total_deadline = time.monotonic() + self.duration_s
        for fn in target_functions:
            remaining_time = total_deadline - time.monotonic()
            if remaining_time <= 0:
                failures.append("total tracing deadline exceeded before all functions completed")
                break
            try:
                tracer = EbpfTracer()
                session = tracer.trace(
                    pid=self.pid,
                    binary_path=self.binary_path,
                    function_name=fn,
                    debug_image=self.debug_image,
                    duration_s=remaining_time,
                    verify_build_id=True,
                    max_events=max(1, self.max_events - len(events_out)),
                    deadline=total_deadline,
                )
                if session is None:
                    failures.append(f"{fn}: tracer returned no session")
                    session_summaries.append({"function": fn, "status": "FAILED",
                                              "error_message": "tracer returned no session"})
                    continue

                session_status = str(getattr(session, "status", "UNKNOWN"))
                session_events = list(getattr(session, "events", []) or [])
                session_lost = max(0, int(getattr(session, "lost_events", 0) or 0))
                session_malformed = max(0, int(getattr(session, "malformed_records", 0) or 0))
                session_total = max(len(session_events), int(getattr(session, "total_events", 0) or 0))
                lost_events += session_lost
                malformed_records += session_malformed
                session_truncated = max(0, int(getattr(session, "truncated_events", 0) or 0))
                truncated_events += session_truncated
                reported_events += max(session_total, int(getattr(session, "reported_events", 0) or 0))
                session_summary = {
                    "function": fn,
                    "session_id": getattr(session, "session_id", None),
                    "status": session_status,
                    "total_events": session_total,
                    "lost_events": session_lost,
                    "malformed_records": session_malformed,
                    "reported_events": max(0, int(getattr(session, "reported_events", session_total) or 0)),
                    "collected_events": max(0, int(getattr(session, "collected_events", len(session_events)) or 0)),
                    "truncated_events": session_truncated,
                    "event_cap_reached": bool(getattr(session, "event_cap_reached", False)),
                    "error_message": getattr(session, "error_message", None),
                    "target_pid": getattr(session, "target_pid", self.pid),
                    "target_binary": getattr(session, "target_binary", self.binary_path),
                    "target_build_id": getattr(session, "target_build_id", None),
                    "build_id_status": getattr(session, "build_id_status", None),
                    "consistency_level": getattr(session, "consistency_level", None),
                    "target_identity": dict(getattr(session, "target_identity", {}) or {}),
                    "identity_status": getattr(session, "identity_status", None),
                }
                session_summaries.append(session_summary)
                if session_status not in ("SUCCESS", "OBSERVED"):
                    failures.append(f"{fn}: {session_status}")
                if session_summary["error_message"]:
                    failures.append(f"{fn}: {session_summary['error_message']}")

                remaining = max(0, self.max_events - len(events_out))
                if len(session_events) > remaining:
                    truncated_events += len(session_events) - remaining
                for ev in session_events[:remaining]:
                    ed = ev.to_dict()
                    events_out.append(ed)
                    # Extract return address / caller location if observed
                    loc_entry = self._extract_call_location(ed, fn)
                    if loc_entry:
                        locations_out.append(loc_entry)
                if len(events_out) >= self.max_events:
                    if fn != target_functions[-1]:
                        failures.append("global max_events cap reached before all target functions were traced")
                    break
            except Exception as exc:
                logger.debug("eBPF tracing for %s encountered non-fatal error: %s", fn, exc)
                failures.append(f"{fn}: {type(exc).__name__}: {exc}")
                session_summaries.append({"function": fn, "status": "FAILED",
                                          "error_message": f"{type(exc).__name__}: {exc}"[:500]})
                continue

        self.collected_events = events_out
        incomplete = bool(failures or lost_events or malformed_records or truncated_events or
                          any(s.get("event_cap_reached") for s in session_summaries))
        session_statuses = [str(item.get("status") or "UNKNOWN") for item in session_summaries]
        if session_statuses and all(value == "UNSUPPORTED_ENVIRONMENT" for value in session_statuses):
            status = "UNSUPPORTED_ENVIRONMENT"
        elif session_statuses and all(value == "PERMISSION_DENIED" for value in session_statuses):
            status = "PERMISSION_DENIED"
        elif not session_summaries:
            status = "FAILED"
        elif incomplete:
            status = "PARTIAL"
        elif events_out:
            status = "OBSERVED"
        else:
            status = "NO_EVENTS_OBSERVED"
        return {
            "status": status,
            "events_count": len(events_out),
            "reported_events_count": reported_events,
            "collected_events_count": len(events_out),
            "lost_events": lost_events,
            "malformed_records": malformed_records,
            "events_truncated": truncated_events,
            "sessions": session_summaries,
            "errors": failures,
            "events": events_out,
            "locations": locations_out,
        }

    def _extract_call_location(self, event_dict: Dict[str, Any], function_name: str) -> Optional[Dict[str, Any]]:
        """Resolve caller address from event registers to a source line via addr2line or DWARF line table."""
        regs = event_dict.get("registers") or {}
        # In aarch64, lr (r30) holds the return address at function entry
        caller_pc = None
        for rk in ("lr", "r30", "return_address", "ret_addr"):
            val_obj = regs.get(rk)
            if isinstance(val_obj, dict) and val_obj.get("value") is not None:
                try:
                    caller_pc = int(val_obj["value"])
                    break
                except (ValueError, TypeError):
                    pass

        if caller_pc is None or caller_pc <= 4096:
            return None

        # Resolve address to file:line using addr2line if available
        loc_str = self._resolve_address(caller_pc)
        if not loc_str:
            return None

        file_part, _, line_part = loc_str.partition(":")
        short_file = os.path.basename(file_part)
        display_loc = f"{short_file}:{line_part}" if line_part else short_file

        return {
            "basis": "tracing",
            "observed": True,
            "is_traced": True,
            "location": display_loc,
            "file": file_part,
            "line": int(line_part) if line_part.isdigit() else None,
            "function": function_name,
            "address": hex(caller_pc),
            "reason": f"Observed 런타임 call site for {function_name}() via eBPF uprobe",
            "reason_ko": f"eBPF uprobe로 관측된 {function_name}() 호출 지점",
        }

    def _resolve_address(self, addr: int) -> Optional[str]:
        """Resolve instruction address to file:line string."""
        target_img = self.debug_image or self.binary_path
        if not target_img or not os.path.exists(target_img):
            return None
        try:
            with open(f"/proc/{self.pid}/maps", "r", encoding="utf-8", errors="replace") as fh:
                maps_text = fh.read()
            elf_addr = _runtime_to_elf_address(addr, self.binary_path, maps_text)
            if elf_addr is None:
                return None
            cmd = ["addr2line", "-e", target_img, "-f", "-C", hex(elf_addr)]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=2.0)
            if res.returncode == 0:
                lines = [ln.strip() for ln in res.stdout.strip().splitlines() if ln.strip()]
                # addr2line output is usually function_name \n file:line
                candidate = lines[1] if len(lines) >= 2 else (lines[0] if lines else "")
                match = re.match(r"^(.+):(\d+)(?: \(discriminator \d+\))?$", candidate)
                if match and match.group(1) not in ("??", "") and int(match.group(2)) > 0:
                    return f"{match.group(1)}:{match.group(2)}"
        except Exception:
            pass
        return None


def format_traced_locations_for_finding(
    finding: Dict[str, Any],
    traced_locations: List[Dict[str, Any]],
    trace_summary: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Format observed runtime tracing locations for a finding, clearly distinguishing from static candidates."""
    summary = trace_summary or {}
    collection_status = str(summary.get("status") or "")
    details = {
        "collection_status": collection_status,
        "events_count": int(summary.get("events_count") or 0),
        "reported_events_count": int(summary.get("reported_events_count") or 0),
        "collected_events_count": int(summary.get("collected_events_count") or 0),
        "lost_events": int(summary.get("lost_events") or 0),
        "malformed_records": int(summary.get("malformed_records") or 0),
        "events_truncated": int(summary.get("events_truncated") or 0),
        "sessions": list(summary.get("sessions") or []),
        "errors": list(summary.get("errors") or []),
    }
    if not traced_locations:
        status = "NOT_OBSERVED" if collection_status in ("", "OBSERVED", "NO_EVENTS_OBSERVED") else collection_status
        return {
            "basis": "tracing",
            "observed": False,
            "is_traced": True,
            "status": status,
            "status_text": "no runtime events observed for this defect",
            "status_text_ko": "이 결함과 관련된 런타임 추적 이벤트가 관측되지 않음",
            "locations": [],
            **details,
        }

    # Filter or match locations relevant to finding category
    cat = str(finding.get("category") or "")
    if cat in ("INVALID_DOUBLE_FREE", "USE_AFTER_FREE"):
        relevant = [loc for loc in traced_locations if loc.get("function") in ("free", "realloc")]
    elif cat in ("MEMORY_LEAK", "MEMORY_CORRUPTION"):
        relevant = [loc for loc in traced_locations if loc.get("function") in ("malloc", "calloc", "realloc")]
    else:
        relevant = list(traced_locations)

    if not relevant:
        relevant = traced_locations[:3]

    return {
        "basis": "tracing",
        "observed": True,
        "is_traced": True,
        "status": "OBSERVED" if collection_status in ("", "OBSERVED") else collection_status,
        "status_text": "observed at runtime via eBPF/uprobe",
        "status_text_ko": "eBPF/uprobe를 통해 런타임에 직접 관측됨",
        "method": "Linux eBPF uprobe/uretprobe dynamic event tracing",
        "locations": relevant[:3],
        **details,
    }


def attach_traced_locations(
    findings: List[Dict[str, Any]],
    pid: int,
    binary_path: str,
    debug_image: Optional[str] = None,
    *,
    enabled: bool = False,
    duration_s: float = DEFAULT_TRACING_DURATION_S,
) -> None:
    """Attach traced_locations to each finding in findings."""
    if not findings:
        return

    if not enabled:
        for f in findings:
            if isinstance(f, dict):
                f["traced_locations"] = {
                    "basis": "tracing",
                    "observed": False,
                    "is_traced": False,
                    "status": "TRACING_DISABLED",
                    "status_text": "selective tracing mode is off (DYNAMIC_EVENT_TRACING)",
                    "status_text_ko": "선택적 추적 모드(DYNAMIC_EVENT_TRACING)가 꺼져 있음",
                    "locations": [],
                }
        return

    # Tracing is enabled: run a session
    session = SelectiveTracingSession(pid, binary_path, debug_image=debug_image, duration_s=duration_s)
    trace_res = session.run_trace()
    all_locs = trace_res.get("locations") or []

    for f in findings:
        if isinstance(f, dict):
            f["traced_locations"] = format_traced_locations_for_finding(f, all_locs, trace_res)


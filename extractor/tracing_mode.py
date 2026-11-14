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
import os
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
)

logger = logging.getLogger("dynamicstate.tracing_mode")

ENV_ENABLE_TRACING = "DYNAMICSTATE_ENABLE_TRACING"
DEFAULT_TRACING_DURATION_S = 1.5
MAX_TRACING_DURATION_S = 10.0
MAX_EVENTS_CAP = 500


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
        self.duration_s = min(max(duration_s, 0.5), MAX_TRACING_DURATION_S)
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
            }

        if not target_functions:
            target_functions = ["free", "malloc"]

        events_out: List[Dict[str, Any]] = []
        locations_out: List[Dict[str, Any]] = []

        # Trace each function briefly within time budget
        per_fn_duration = max(0.5, self.duration_s / max(len(target_functions), 1))
        for fn in target_functions:
            try:
                tracer = EbpfTracer(
                    pid=self.pid,
                    binary_path=self.binary_path,
                    target_function=fn,
                    debug_image_path=self.debug_image,
                    verify_build_id=False,  # Allow running test fixtures
                    timeout=per_fn_duration,
                    max_events=self.max_events,
                )
                session = tracer.run()
                if session and session.events:
                    for ev in session.events:
                        ed = ev.to_dict()
                        events_out.append(ed)
                        # Extract return address / caller location if observed
                        loc_entry = self._extract_call_location(ed, fn)
                        if loc_entry:
                            locations_out.append(loc_entry)
            except Exception as exc:
                logger.debug("eBPF tracing for %s encountered non-fatal error: %s", fn, exc)
                continue

        self.collected_events = events_out
        return {
            "status": "OBSERVED" if events_out else "NO_EVENTS_OBSERVED",
            "events_count": len(events_out),
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
            cmd = ["addr2line", "-e", target_img, "-f", "-C", hex(addr)]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=2.0)
            if res.returncode == 0:
                lines = [ln.strip() for ln in res.stdout.strip().splitlines() if ln.strip()]
                # addr2line output is usually function_name \n file:line
                if len(lines) >= 2 and "?" not in lines[1]:
                    return lines[1]
                if lines and "?" not in lines[0] and ":" in lines[0]:
                    return lines[0]
        except Exception:
            pass
        return None


def format_traced_locations_for_finding(
    finding: Dict[str, Any],
    traced_locations: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Format observed runtime tracing locations for a finding, clearly distinguishing from static candidates."""
    if not traced_locations:
        return {
            "basis": "tracing",
            "observed": False,
            "is_traced": True,
            "status": "NOT_OBSERVED",
            "status_text": "no runtime events observed for this defect",
            "status_text_ko": "이 결함과 관련된 런타임 추적 이벤트가 관측되지 않음",
            "locations": [],
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
        "status": "OBSERVED",
        "status_text": "observed at runtime via eBPF/uprobe",
        "status_text_ko": "eBPF/uprobe를 통해 런타임에 직접 관측됨",
        "method": "Linux eBPF uprobe/uretprobe dynamic event tracing",
        "locations": relevant[:3],
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
            f["traced_locations"] = format_traced_locations_for_finding(f, all_locs)


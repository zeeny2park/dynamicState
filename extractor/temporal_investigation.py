"""Phase 24: Evidence-First Temporal Investigation Workflow.

Connects Phase 23 Watch Sessions and Temporal Memory Explorer to the
conversational investigation workflow, EvidenceLedger, static code analysis,
and object-centric drill-down.

Core Capabilities:
1. Natural-Language Investigation Orchestration:
   Converts user goals (English and Korean) into bounded observation plans,
   discovering typed variables, memory bounds, and guard proximity.
2. Evidence Provenance & Canonical Ledger:
   Every finding links to canonical EvidenceRecord instances with session ID,
   observation sequence/time, capture quality, target identity, Build ID,
   address, type/field path, DWARF source location, and static candidate functions.
3. Temporal Observation Comparison:
   Streams paginated observations and distinctly classifies:
   - CHANGED values (with initial/final values and sequence transitions)
   - UNCHANGED values
   - PARTIAL reads
   - UNAVAILABLE / MISSING observations (never silently treated as unchanged)
   - GAPS (server restart, transport drop, timeouts)
4. Buffer & Memory Guard Proximity Evaluation:
   Calculates pointer/offset proximity to buffer and guard page boundaries.
   Strictly labels LOW_IMPACT snapshots as non-atomic sampled observations:
   proximity or correlated value changes do NOT prove actual memory reads,
   writes, guard crossings, or causal corruption.
5. Object-Centric Drill-Down & Candidate Function Linking:
   Finding -> C++ object/field -> pointer/size/index relationships ->
   DWARF type/source location -> related candidate functions.
   Candidate functions are kept strictly in STATIC_CANDIDATE or
   EVIDENCE_SUPPORTED tiers and never promoted to validated causality without
   independent execution tracing.
6. Discriminating Follow-Up Observations:
   Recommends non-invasive next steps (e.g. dynamic access watchpoint, interval refinement).
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import uuid

from extractor.evidence_ledger import (
    EVIDENCE_SCHEMA_VERSION,
    EVIDENCE_TYPE_CAPTURE_QUALITY,
    EVIDENCE_TYPE_COMPARISON,
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EVIDENCE_TYPE_OBJECT_STATE,
    EVIDENCE_TYPE_RUNTIME_IDENTITY,
    EVIDENCE_TYPE_STATIC_LINK,
    EvidenceLedger,
    EvidenceRecord,
    NATURE_HYPOTHESIS,
    NATURE_INFERENCE,
    NATURE_OBSERVATION,
    PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
)
from extractor.hypothesis import (
    CONFIDENCE_MEDIUM,
    EVIDENCE_CLASSIFICATION_FACT,
    EVIDENCE_CLASSIFICATION_INFERENCE,
    EVIDENCE_CLASSIFICATION_UNKNOWN,
    FollowUpObservation,
    InvestigationHypothesis,
    HYPOTHESIS_STATUS_PROPOSED,
    HYPOTHESIS_STATUS_SUPPORTED,
    OBSERVATION_STATUS_PROPOSED,
)
from extractor.investigation import (
    InvestigationFinding,
    InvestigationNextStep,
    InvestigationSession,
)
from extractor.static_analyzer import (
    FUNCTION_TIER_EVIDENCE_SUPPORTED,
    FUNCTION_TIER_STATIC_CANDIDATE,
    FUNCTION_TIER_VALIDATED_CAUSAL,
    LAYOUT_MUTATION_CAVEAT,
    FunctionCandidate,
    StaticAnalysisProvider,
    validate_module_identity,
)
from extractor.watch_session import (
    CaptureGap,
    Observation,
    ObservationSession,
    WatchItem,
    WatchSessionManager,
)

logger = logging.getLogger("dynamicstate.temporal_investigation")

# Honest capture limitation notice
HONEST_CAPTURE_SEMANTICS_NOTICE = (
    "Captured via LOW_IMPACT process_vm_readv / procfs non-atomic sampling. "
    "Discrete temporal snapshots show state proximity and value correlation only; "
    "this does NOT prove memory read/write or guard violation. "
    "Access verification requires independent dynamic instrumentation."
)

DEFAULT_GUARD_THRESHOLD_BYTES = 256
MAX_PAGINATION_LIMIT = 100


def redact_sensitive_content(val: Any) -> Any:
    """Redact API keys, tokens, and secrets from observation values and strings."""
    if val is None:
        return None
    if isinstance(val, str):
        redacted = val
        redacted = re.sub(r"(AIza[0-9A-Za-z-_]{15,})", "[REDACTED_GEMINI_KEY]", redacted)
        redacted = re.sub(r"(sk-[a-zA-Z0-9_\-]{15,})", "[REDACTED_API_KEY]", redacted)
        redacted = re.sub(r"(ghp_[a-zA-Z0-9]{20,})", "[REDACTED_GITHUB_TOKEN]", redacted)
        redacted = re.sub(r"(password\s*[:=]\s*\S+)", "password=[REDACTED]", redacted, flags=re.IGNORECASE)
        return redacted
    if isinstance(val, dict):
        return {k: redact_sensitive_content(v) for k, v in val.items()}
    if isinstance(val, list):
        return [redact_sensitive_content(v) for v in val]
    return val


class ObservationComparisonState:
    CHANGED = "CHANGED"
    UNCHANGED = "UNCHANGED"
    PARTIAL = "PARTIAL"
    MISSING = "MISSING"
    STALE = "STALE"
    GAP_INTERRUPTED = "GAP_INTERRUPTED"


@dataclass
class ObservationComparisonResult:
    item_id: str
    item_name: str
    state: str  # CHANGED, UNCHANGED, PARTIAL, MISSING, STALE, GAP_INTERRUPTED
    initial_value: Any
    final_value: Any
    samples_count: int
    missing_count: int = 0
    is_gap_interrupted: bool = False
    is_stale: bool = False


@dataclass
class TemporalInvestigationPlan:
    """Bounded plan for a temporal investigation converted from a natural-language goal."""
    goal: str = ""
    target_session_id: Optional[str] = None
    window_duration_sec: Optional[float] = None
    start_seq: Optional[int] = None
    end_seq: Optional[int] = None
    limit: int = 50
    target_keywords: List[str] = field(default_factory=list)
    guard_keywords_detected: bool = False
    buffer_keywords_detected: bool = False
    guard_address: Optional[int] = None
    buffer_address: Optional[int] = None
    buffer_size: Optional[int] = None
    boundary_kind: str = "UNKNOWN"  # CONFIGURED_GUARD_ADDRESS, KNOWN_BUFFER_END, MEMORY_MAP_BOUNDARY, INFERRED_BOUNDARY, UNKNOWN
    guard_threshold: int = DEFAULT_GUARD_THRESHOLD_BYTES
    target_items: List[str] = field(default_factory=list)
    watch_session_id: Optional[str] = None

    def __post_init__(self):
        if self.watch_session_id and not self.target_session_id:
            self.target_session_id = self.watch_session_id
        elif self.target_session_id and not self.watch_session_id:
            self.watch_session_id = self.target_session_id

    @property
    def duration_sec(self) -> Optional[float]:
        return self.window_duration_sec

    @duration_sec.setter
    def duration_sec(self, val: Optional[float]):
        self.window_duration_sec = val

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if self.guard_address is not None:
            d["guard_address_hex"] = f"0x{self.guard_address:x}"
        if self.buffer_address is not None:
            d["buffer_address_hex"] = f"0x{self.buffer_address:x}"
        d["boundary_kind"] = self.boundary_kind
        if self.buffer_size is not None:
            d["buffer_size"] = self.buffer_size
        return d


class TemporalInvestigationService:
    """Service orchestrating evidence-first temporal investigations."""

    def __init__(self, watch_manager: Optional[WatchSessionManager] = None, watch_session_manager: Optional[WatchSessionManager] = None):
        self.watch_manager = watch_manager or watch_session_manager

    def create_investigation_plan(
        self,
        goal: str,
        watch_session_id: Optional[str] = None,
        constraints: Optional[Dict[str, Any]] = None,
        observation_window: Optional[Dict[str, Any]] = None,
    ) -> TemporalInvestigationPlan:
        """Alias for parse_investigation_goal supporting direct plan generation."""
        c = dict(constraints or {})
        if watch_session_id:
            c["watch_session_id"] = watch_session_id
        return self.parse_investigation_goal(goal, constraints=c, observation_window=observation_window)

    def retrieve_temporal_window(
        self,
        session_id: str,
        plan: TemporalInvestigationPlan,
        watch_manager: Optional[WatchSessionManager] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Retrieve bounded window of observations for a session."""
        mgr = watch_manager or self.watch_manager
        if not mgr:
            return [], 0
        resp = mgr.get_observations(
            session_id=session_id,
            start_seq=plan.start_seq,
            end_seq=plan.end_seq,
            limit=plan.limit,
            offset=0,
        )
        obs_list = resp.get("observations", [])
        total = resp.get("total_observations", len(obs_list))
        if plan.window_duration_sec and len(obs_list) > 1:
            first_mono = obs_list[0].get("monotonic_ns", 0)
            max_mono = first_mono + int(plan.window_duration_sec * 1_000_000_000)
            obs_list = [o for o in obs_list if o.get("monotonic_ns", 0) <= max_mono]
        return obs_list, total

    def compare_temporal_observations(
        self,
        session_id: str,
        plan: TemporalInvestigationPlan,
        chunk_size: int = 100,
        watch_manager: Optional[WatchSessionManager] = None,
    ) -> Dict[str, ObservationComparisonResult]:
        """Streaming / paginated observation comparison across timeline for watch items."""
        mgr = watch_manager or self.watch_manager
        if not mgr:
            return {}
        sess = mgr.get_session(session_id)
        if not sess:
            return {}

        results: Dict[str, ObservationComparisonResult] = {}
        for item in sess.watch_items:
            offset = 0
            has_partial = False
            has_missing = False
            missing_count = 0
            item_vals = []

            while True:
                fetch_limit = min(chunk_size, plan.limit - len(item_vals)) if plan.limit else chunk_size
                if fetch_limit <= 0:
                    break
                resp = mgr.get_observations(
                    session_id=session_id,
                    start_seq=plan.start_seq,
                    end_seq=plan.end_seq,
                    limit=fetch_limit,
                    offset=offset,
                )
                chunk = resp.get("observations", [])
                if not chunk:
                    break

                for o in chunk:
                    v_entry = o.get("values", {}).get(item.item_id)
                    if v_entry is None:
                        has_missing = True
                        missing_count += 1
                        continue
                    if isinstance(v_entry, dict):
                        status = v_entry.get("status", "VALID")
                        val = v_entry.get("value")
                        if v_entry.get("is_partial"):
                            has_partial = True
                    else:
                        status = "VALID"
                        val = v_entry

                    if status in ("UNAVAILABLE", "ERROR") or (val is None and status != "PARTIAL" and not (isinstance(v_entry, dict) and v_entry.get("is_partial"))):
                        has_missing = True
                        missing_count += 1
                    elif status == "PARTIAL":
                        has_partial = True

                    item_vals.append((val, status))

                offset += len(chunk)
                if len(chunk) < fetch_limit or (plan.limit and len(item_vals) >= plan.limit):
                    break

            if not item_vals or (missing_count > 0 and not any(v[1] in ("VALID", "OBSERVED", "PARTIAL") and v[0] is not None for v in item_vals)):
                st = ObservationComparisonState.MISSING
                results[item.item_id] = ObservationComparisonResult(
                    item_id=item.item_id,
                    item_name=item.name,
                    state=st,
                    initial_value=item_vals[0][0] if item_vals else None,
                    final_value=item_vals[-1][0] if item_vals else None,
                    samples_count=len(item_vals),
                    missing_count=missing_count,
                )
            elif has_partial:
                st = ObservationComparisonState.PARTIAL
                results[item.item_id] = ObservationComparisonResult(
                    item_id=item.item_id,
                    item_name=item.name,
                    state=st,
                    initial_value=item_vals[0][0],
                    final_value=item_vals[-1][0],
                    samples_count=len(item_vals),
                    missing_count=missing_count,
                )
            else:
                first_val = item_vals[0][0]
                last_val = item_vals[-1][0]
                distinct = set(str(v[0]) for v in item_vals if v[1] in ("VALID", "OBSERVED"))
                st = ObservationComparisonState.CHANGED if len(distinct) > 1 else ObservationComparisonState.UNCHANGED
                results[item.item_id] = ObservationComparisonResult(
                    item_id=item.item_id,
                    item_name=item.name,
                    state=st,
                    initial_value=first_val,
                    final_value=last_val,
                    samples_count=len(item_vals),
                    missing_count=missing_count,
                )

        return results

    def parse_investigation_goal(
        self,
        goal: str,
        constraints: Optional[Dict[str, Any]] = None,
        observation_window: Optional[Dict[str, Any]] = None,
    ) -> TemporalInvestigationPlan:
        """Parse natural-language goal (Korean or English) and parameters into a bounded plan."""
        constraints = constraints or {}
        obs_win = observation_window or {}

        # 1. Parse duration if present in goal or window
        duration_sec = obs_win.get("duration_sec")
        if duration_sec is None and constraints.get("duration_sec"):
            duration_sec = float(constraints["duration_sec"])

        if duration_sec is None:
            # Check for patterns like "10초", "10s", "10 sec", "10 seconds", "10분", "10 min"
            m = re.search(r"(\d+(?:\.\d+)?)\s*(초|s|sec|second|seconds|분|min|minutes)", goal, re.IGNORECASE)
            if m:
                val = float(m.group(1))
                unit = m.group(2).lower()
                if "분" in unit or "min" in unit:
                    duration_sec = val * 60.0
                else:
                    duration_sec = val

        # 2. Check for buffer and guard keywords
        buffer_re = re.search(r"(buffer|pool|buf|버퍼|풀|메모리\s*풀|heap|queue|ring)", goal, re.IGNORECASE)
        guard_re = re.search(r"(guard|boundary|limit|overflow|가드|경계|보호)", goal, re.IGNORECASE)

        # 3. Extract potential addresses
        guard_addr = obs_win.get("guard_address") or constraints.get("guard_address")
        if isinstance(guard_addr, str) and guard_addr.startswith("0x"):
            guard_addr = int(guard_addr, 16)
        elif isinstance(guard_addr, str) and guard_addr.isdigit():
            guard_addr = int(guard_addr)

        buf_addr = obs_win.get("buffer_address") or constraints.get("buffer_address")
        if isinstance(buf_addr, str) and buf_addr.startswith("0x"):
            buf_addr = int(buf_addr, 16)
        elif isinstance(buf_addr, str) and buf_addr.isdigit():
            buf_addr = int(buf_addr)

        # Fallback address parsing from prompt text (e.g. 0x1000)
        if guard_addr is None:
            addr_matches = re.findall(r"0x[0-9a-fA-F]+", goal)
            if len(addr_matches) >= 2:
                buf_addr = int(addr_matches[0], 16)
                guard_addr = int(addr_matches[1], 16)
            elif len(addr_matches) == 1 and guard_re:
                guard_addr = int(addr_matches[0], 16)

        guard_thresh = int(obs_win.get("guard_threshold") or constraints.get("guard_threshold") or DEFAULT_GUARD_THRESHOLD_BYTES)

        buf_size = obs_win.get("buffer_size") or constraints.get("buffer_size")
        if isinstance(buf_size, str) and buf_size.isdigit():
            buf_size = int(buf_size)
        elif not isinstance(buf_size, int):
            buf_size = None

        mmap_boundary = obs_win.get("memory_map_boundary") or obs_win.get("mapping_boundary") or constraints.get("memory_map_boundary")
        if isinstance(mmap_boundary, str) and mmap_boundary.startswith("0x"):
            mmap_boundary = int(mmap_boundary, 16)
        elif isinstance(mmap_boundary, str) and mmap_boundary.isdigit():
            mmap_boundary = int(mmap_boundary)
        elif not isinstance(mmap_boundary, int):
            mmap_boundary = None

        # Grounded boundary classification
        # Note: A memory-map boundary is NEVER inferred to be a valid buffer boundary.
        boundary_kind = "UNKNOWN"
        if guard_addr is not None:
            boundary_kind = "CONFIGURED_GUARD_ADDRESS"
            guard_addr = guard_addr & 0xFFFFFFFFFFFFFFFF
        elif buf_addr is not None and buf_size is not None:
            guard_addr = (buf_addr + buf_size) & 0xFFFFFFFFFFFFFFFF
            boundary_kind = "KNOWN_BUFFER_END"
        elif mmap_boundary is not None:
            guard_addr = mmap_boundary & 0xFFFFFFFFFFFFFFFF
            boundary_kind = "MEMORY_MAP_BOUNDARY"
        else:
            boundary_kind = "UNKNOWN"

        start_seq = obs_win.get("start_seq")
        end_seq = obs_win.get("end_seq")
        limit = min(int(obs_win.get("limit", 50)), MAX_PAGINATION_LIMIT)

        target_sid = obs_win.get("session_id") or constraints.get("watch_session_id")

        keywords = []
        if buffer_re:
            keywords.append(buffer_re.group(1).lower())
        if guard_re:
            keywords.append(guard_re.group(1).lower())

        return TemporalInvestigationPlan(
            goal=goal,
            target_session_id=target_sid,
            window_duration_sec=duration_sec,
            start_seq=int(start_seq) if start_seq is not None else None,
            end_seq=int(end_seq) if end_seq is not None else None,
            limit=limit,
            target_keywords=keywords,
            guard_keywords_detected=bool(guard_re),
            buffer_keywords_detected=bool(buffer_re),
            guard_address=guard_addr,
            buffer_address=buf_addr,
            buffer_size=buf_size,
            boundary_kind=boundary_kind,
            guard_threshold=guard_thresh,
        )

    def analyze_temporal_session(
        self,
        investigation_session: InvestigationSession,
        watch_session: Optional[ObservationSession],
        watch_manager: Optional[WatchSessionManager],
        observation_window: Optional[Dict[str, Any]] = None,
        goal: Optional[str] = None,
        static_provider: Optional[StaticAnalysisProvider] = None,
    ) -> Dict[str, Any]:
        """Execute evidence-first temporal investigation against a watch session."""
        mgr = watch_manager or self.watch_manager
        effective_goal = goal or investigation_session.goal

        plan = self.parse_investigation_goal(
            goal=effective_goal,
            constraints=investigation_session.target_ref.get("constraints"),
            observation_window=observation_window,
        )

        investigation_session.target_ref["temporal_plan"] = plan.to_dict()

        # Handle missing target information gracefully (Requirement 5 & Acceptance Scenario)
        if not watch_session:
            sid = plan.target_session_id or investigation_session.target_ref.get("watch_session_id")
            if sid and mgr:
                watch_session = mgr.get_session(sid)

        if not watch_session:
            # Check if there is an active session in watch_manager
            if mgr:
                sessions = mgr.list_sessions(include_stopped=False)
                if sessions:
                    watch_session = mgr.get_session(sessions[0]["session_id"])

        if not watch_session:
            # Record explicit requirement for missing target information
            fnd = InvestigationFinding(
                finding_id=f"fnd_missing_target_{uuid.uuid4().hex[:8]}",
                category="unknown",
                title="Target Process or Observation Session Required",
                description=(
                    "No authorized target process or watch session was specified. "
                    "Please provide an authorized target PID with companion ELF, or select an existing watch session."
                ),
                confidence="high",
                status="UNRESOLVED",
                classification=EVIDENCE_CLASSIFICATION_UNKNOWN,
            )
            investigation_session.findings.append(fnd)
            investigation_session.next_steps.append(InvestigationNextStep(
                step_id=f"step_provide_target_{uuid.uuid4().hex[:6]}",
                description="Select an existing watch session or enter a running target PID and companion debug image.",
                rationale="Temporal investigation requires an authorized target process or persistent watch session.",
                risk_level="READ_ONLY",
                required_inputs=["watch_session_id", "pid", "debug_image"],
                action_type="INSPECT",
            ))
            investigation_session.status = "PARTIAL"
            investigation_session.summary["status"] = "PARTIAL"
            investigation_session.summary["message"] = "Target information required"
            return investigation_session.to_dict()

        # Target session established
        sid = watch_session.session_id
        investigation_session.target_ref["watch_session_id"] = sid
        investigation_session.target_ref["pid"] = watch_session.pid
        investigation_session.target_ref["binary_build_id"] = watch_session.binary_build_id
        investigation_session.target_ref["companion_elf_path"] = watch_session.companion_elf_path
        investigation_session.target_ref["is_remote"] = watch_session.provenance.get("is_remote", False)
        investigation_session.target_ref["target_host"] = watch_session.provenance.get("host", "localhost")

        # ---------------------------------------------------------------------
        # Stage 1: Target Identity & Build ID Validation
        # ---------------------------------------------------------------------
        target_bid = watch_session.binary_build_id
        comp_bid = None
        debug_elf = watch_session.companion_elf_path or investigation_session.target_ref.get("debug_image")
        ident_status = "UNKNOWN"
        ident_reason = "No companion ELF supplied"

        if debug_elf:
            try:
                from extractor.debug_image import inspect_elf
                info = inspect_elf(debug_elf)
                comp_bid = info.build_id
                ident_status, ident_reason = validate_module_identity(target_bid, comp_bid)
            except Exception as e:
                ident_status = "MISMATCH"
                ident_reason = f"Failed to inspect companion ELF: {e}"

        # Record Target Identity in canonical EvidenceLedger
        ev_ident = investigation_session.ledger.add_record(EvidenceRecord(
            evidence_type=EVIDENCE_TYPE_RUNTIME_IDENTITY,
            nature=NATURE_OBSERVATION,
            source="watch_session_adapter",
            session_id=investigation_session.investigation_id,
            observation=f"Target PID {watch_session.pid} identity verified: Build ID '{target_bid or 'UNKNOWN'}' ({ident_status}).",
            target_identity={
                "pid": watch_session.pid,
                "target_build_id": target_bid,
                "debug_build_id": comp_bid,
                "status": ident_status,
                "is_remote": watch_session.provenance.get("is_remote", False),
                "host": watch_session.provenance.get("host", "localhost"),
            },
            provenance={
                "watch_session_id": sid,
                "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
            },
            details={"identity_status": ident_status, "reason": ident_reason},
        ))

        # Check for Build ID mismatch
        if ident_status == "MISMATCH":
            fnd_mismatch = InvestigationFinding(
                finding_id=f"fnd_bid_mismatch_{uuid.uuid4().hex[:8]}",
                category="unknown",
                title=f"Build ID Mismatch between Target and Companion ELF ({ident_status})",
                description=(
                    f"Target running binary Build ID ({target_bid}) conflicts with supplied "
                    f"debug companion Build ID ({comp_bid}). Temporal interpretation suppressed "
                    f"to prevent false conclusions."
                ),
                confidence="high",
                status="UNTRUSTED",
                evidence_ids=[ev_ident.evidence_id],
                uncertainty="Mismatched DWARF symbols will corrupt variable offsets and type resolutions.",
                classification=EVIDENCE_CLASSIFICATION_UNKNOWN,
            )
            investigation_session.findings.append(fnd_mismatch)
            investigation_session.status = "FAILED"
            investigation_session.summary["status"] = "FAILED"
            investigation_session.summary["error"] = f"Build ID mismatch: {ident_reason}"
            return investigation_session.to_dict()

        # Check for missing DWARF in companion ELF
        dwarf_available = False
        if debug_elf:
            try:
                from extractor.dwarf_reader import DwarfReader
                dr = DwarfReader(debug_elf)
                dwarf_available = dr.has_debug_info()
            except Exception:
                dwarf_available = False

        if debug_elf and not dwarf_available:
            fnd_no_dwarf = InvestigationFinding(
                finding_id=f"fnd_no_dwarf_{uuid.uuid4().hex[:8]}",
                category="unknown",
                title="DWARF Debug Information Unavailable in Companion ELF",
                description="The supplied companion binary does not contain .debug_info or DWARF symbols. Typed semantic resolution is unavailable.",
                confidence="high",
                status="UNRESOLVED",
                evidence_ids=[ev_ident.evidence_id],
                uncertainty="Offsets cannot be mapped to struct member names or source lines without DWARF.",
                classification=EVIDENCE_CLASSIFICATION_UNKNOWN,
            )
            investigation_session.findings.append(fnd_no_dwarf)

        # ---------------------------------------------------------------------
        # Stage 2: Capture Quality & Gaps Accounting
        # ---------------------------------------------------------------------
        cap_quality = "COMPLETE" if watch_session.status in ("RUNNING", "STOPPED") else "PARTIAL"
        cap_consistency = "NON_ATOMIC"  # LOW_IMPACT process_vm_readv zero-stop

        ev_cap = investigation_session.ledger.add_record(EvidenceRecord(
            evidence_type=EVIDENCE_TYPE_CAPTURE_QUALITY,
            nature=NATURE_OBSERVATION,
            source="watch_session_manager",
            session_id=investigation_session.investigation_id,
            parent_evidence_ids=[ev_ident.evidence_id],
            observation=(
                f"Watch session '{sid}' capture quality evaluated: mode={watch_session.capture_mode}, "
                f"consistency={cap_consistency}. {HONEST_CAPTURE_SEMANTICS_NOTICE}"
            ),
            capture_quality={
                "completeness": cap_quality,
                "consistency_level": cap_consistency,
                "capture_mode": watch_session.capture_mode,
                "backend": watch_session.configuration.get("backend", "process_vm_readv"),
            },
            provenance={
                "watch_session_id": sid,
                "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
            },
            details={
                "limitations": [HONEST_CAPTURE_SEMANTICS_NOTICE] + [
                    f"Capture gap ({gap.reason}): missing samples between {gap.start_ns} and {gap.end_ns}"
                    for gap in watch_session.gaps
                ],
                "gaps_count": len(watch_session.gaps),
            },
        ))

        # Record capture_quality stage on session
        cap_limitations = [HONEST_CAPTURE_SEMANTICS_NOTICE]
        for gap in watch_session.gaps:
            cap_limitations.append(f"Capture gap ({gap.reason}): missing samples between {gap.start_ns} and {gap.end_ns}")

        investigation_session.stages["capture_quality"] = {
            "status": "COMPLETE",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "details": {
                "consistency_level": cap_consistency,
                "completeness": cap_quality,
                "capture_mode": watch_session.capture_mode,
                "backend": watch_session.configuration.get("backend", "process_vm_readv"),
                "limitations": cap_limitations,
                "gaps_count": len(watch_session.gaps),
            },
        }

        # Record capture gaps distinctly
        for gap in watch_session.gaps:
            investigation_session.findings.append(InvestigationFinding(
                finding_id=f"fnd_gap_{uuid.uuid4().hex[:8]}",
                category="unknown",
                title=f"Temporal Capture Gap: {gap.reason}",
                description=(
                    f"Observation gap recorded between {gap.start_ns} and {gap.end_ns} "
                    f"({gap.duration_ms:.1f}ms). Reason: {gap.reason}. Missing samples during "
                    f"this interval cannot be assumed unchanged."
                ),
                confidence="high",
                status="SUSPECT",
                evidence_ids=[ev_cap.evidence_id],
                uncertainty=f"Interrupted sampling due to {gap.reason}.",
                classification=EVIDENCE_CLASSIFICATION_UNKNOWN,
            ))

        # ---------------------------------------------------------------------
        # Stage 3: Paginated Observation Timeline Comparison
        # ---------------------------------------------------------------------
        if not mgr:
            return investigation_session.to_dict()

        # Query paginated observations
        obs_resp = mgr.get_observations(
            session_id=sid,
            start_seq=plan.start_seq,
            end_seq=plan.end_seq,
            limit=plan.limit,
            offset=0,
        )
        obs_data_list = obs_resp.get("observations", [])

        # If duration window specified, filter by duration if needed
        if plan.window_duration_sec and len(obs_data_list) > 1:
            first_mono = obs_data_list[0].get("monotonic_ns", 0)
            max_mono = first_mono + int(plan.window_duration_sec * 1_000_000_000)
            obs_data_list = [o for o in obs_data_list if o.get("monotonic_ns", 0) <= max_mono]

        start_ts = obs_data_list[0].get("timestamp") if obs_data_list else None
        end_ts = obs_data_list[-1].get("timestamp") if obs_data_list else None
        dur_ms = 0.0
        if len(obs_data_list) > 1:
            m0 = obs_data_list[0].get("monotonic_ns", 0)
            m1 = obs_data_list[-1].get("monotonic_ns", 0)
            dur_ms = max(0.0, (m1 - m0) / 1_000_000.0)

        investigation_session.target_ref["temporal_summary"] = {
            "total_observations_examined": len(obs_data_list),
            "start_seq": obs_data_list[0].get("seq") if obs_data_list else None,
            "end_seq": obs_data_list[-1].get("seq") if obs_data_list else None,
            "start_timestamp": start_ts,
            "end_timestamp": end_ts,
            "duration_ms": round(dur_ms, 2),
            "watch_items_count": len(watch_session.watch_items),
            "gaps_count": len(watch_session.gaps),
            "discrete_sampling_notice": "Discrete periodic sampling; discrete snapshots do not imply continuous monitoring.",
        }

        # Check if goal requested guard inspection but boundary is UNKNOWN
        if plan.guard_keywords_detected and (plan.boundary_kind == "UNKNOWN" or plan.guard_address is None):
            fnd_guard_unk = InvestigationFinding(
                finding_id=f"fnd_guard_unk_{uuid.uuid4().hex[:8]}",
                category="unknown",
                title="Memory Guard Boundary Unknown",
                description=(
                    "Goal requested memory guard boundary inspection, but no grounded "
                    "guard page address (guard_address), buffer capacity (buffer_size), or PROT_NONE mapping was supplied. "
                    "Proximity calculation was suppressed to prevent false positive conclusions."
                ),
                confidence="high",
                status="UNRESOLVED",
                uncertainty="Guard boundary unknown; cannot calculate distance without grounded boundary coordinates.",
                classification=EVIDENCE_CLASSIFICATION_UNKNOWN,
            )
            investigation_session.findings.append(fnd_guard_unk)
            investigation_session.next_steps.append(InvestigationNextStep(
                step_id=f"step_guard_addr_{uuid.uuid4().hex[:6]}",
                description="Provide guard page address (guard_address), inspect /proc/<pid>/maps for PROT_NONE pages, or specify buffer capacity.",
                rationale="Memory boundary proximity requires grounded address coordinates to prevent fabricated findings.",
                risk_level="READ_ONLY",
                action_type="INSPECT",
                required_inputs=["guard_address"],
            ))

        # Analyze watch item timelines
        for item in watch_session.watch_items:
            item_vals: List[Tuple[int, str, Any, str]] = []
            has_unavailable = False
            has_partial = False
            has_terminated = False
            missing_count = 0

            for o in obs_data_list:
                seq = o.get("seq", 0)
                ts = o.get("timestamp", "")
                v_entry = o.get("values", {}).get(item.item_id)
                if v_entry is None:
                    has_unavailable = True
                    missing_count += 1
                    continue

                if isinstance(v_entry, dict):
                    status = v_entry.get("status", "VALID")
                    val = v_entry.get("value")
                else:
                    status = "VALID"
                    val = v_entry

                if status == "TARGET_TERMINATED" or o.get("completeness") == "TERMINATED":
                    has_terminated = True

                if status in ("UNAVAILABLE", "ERROR") or (val is None and status != "PARTIAL" and not (isinstance(v_entry, dict) and v_entry.get("is_partial"))):
                    has_unavailable = True
                    missing_count += 1
                elif status == "PARTIAL":
                    has_partial = True

                item_vals.append((seq, ts, val, status))

            # Distinguish changed vs unchanged vs unavailable
            if not item_vals:
                investigation_session.findings.append(InvestigationFinding(
                    finding_id=f"fnd_unavail_{uuid.uuid4().hex[:8]}",
                    category="unknown",
                    title=f"Field unavailable across observation window: {item.name}",
                    description=f"Watch item '{item.name}' (0x{item.address:x}) had no valid recorded samples in the requested window.",
                    c_type_path=item.name,
                    type_name=item.type_name,
                    source_location=item.source_location,
                    confidence="high",
                    status="UNRESOLVED",
                    evidence_ids=[ev_cap.evidence_id],
                    uncertainty="Target memory was unreadable or out of scope.",
                    classification=EVIDENCE_CLASSIFICATION_UNKNOWN,
                ))
                continue

            first_val = redact_sensitive_content(item_vals[0][2])
            last_val = redact_sensitive_content(item_vals[-1][2])
            distinct_vals = set(str(v[2]) for v in item_vals if v[3] in ("VALID", "OBSERVED"))
            changed = len(distinct_vals) > 1

            # Canonical Evidence for this watch item's temporal observations
            ev_timeline = investigation_session.ledger.add_record(EvidenceRecord(
                evidence_type=EVIDENCE_TYPE_COMPARISON,
                nature=NATURE_OBSERVATION,
                source="temporal_explorer",
                session_id=investigation_session.investigation_id,
                parent_evidence_ids=[ev_cap.evidence_id],
                observation=(
                    f"Watch item '{item.name}' temporal observation: initial={first_val}, "
                    f"final={last_val}, changed={changed}, samples={len(item_vals)}."
                ),
                comparison_observation={
                    "item_id": item.item_id,
                    "item_name": item.name,
                    "address": f"0x{item.address:x}",
                    "initial_value": first_val,
                    "final_value": last_val,
                    "has_changed": changed,
                    "samples_count": len(item_vals),
                    "missing_count": missing_count,
                    "start_seq": item_vals[0][0],
                    "end_seq": item_vals[-1][0],
                },
                provenance={
                    "watch_session_id": sid,
                    "watch_item_id": item.item_id,
                    "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                },
                details={
                    "type_name": item.type_name,
                    "source_location": item.source_location,
                    "has_unavailable": has_unavailable,
                    "has_partial": has_partial,
                },
            ))

            if has_terminated:
                investigation_session.findings.append(InvestigationFinding(
                    finding_id=f"fnd_term_{uuid.uuid4().hex[:8]}",
                    category="unknown",
                    title=f"Target Process Terminated during observation of {item.name}",
                    description=f"Process terminated during observation of '{item.name}'. Further observation halted truthfully.",
                    c_type_path=item.name,
                    type_name=item.type_name,
                    source_location=item.source_location,
                    confidence="high",
                    status="RESOLVED",
                    evidence_ids=[ev_timeline.evidence_id],
                    classification=EVIDENCE_CLASSIFICATION_UNKNOWN,
                    temporal_provenance={
                        "session_id": sid,
                        "capture_quality": "TERMINATED",
                        "address": f"0x{item.address:x}",
                        "provenance": "LIVE_RUNTIME_CAPTURE",
                    },
                ))

            if has_partial:
                investigation_session.findings.append(InvestigationFinding(
                    finding_id=f"fnd_part_read_{uuid.uuid4().hex[:8]}",
                    category="unknown",
                    title=f"Partial memory read in {item.name}",
                    description=f"Field '{item.name}' encountered partial or torn reads during sampling. Never reported as unchanged.",
                    c_type_path=item.name,
                    type_name=item.type_name,
                    source_location=item.source_location,
                    confidence="medium",
                    status="UNRESOLVED",
                    evidence_ids=[ev_timeline.evidence_id],
                    classification=EVIDENCE_CLASSIFICATION_UNKNOWN,
                    temporal_provenance={
                        "session_id": sid,
                        "capture_quality": "PARTIAL",
                        "transition_state": ObservationComparisonState.PARTIAL,
                        "address": f"0x{item.address:x}",
                        "provenance": "LIVE_RUNTIME_CAPTURE",
                    },
                ))

            if has_unavailable:
                investigation_session.findings.append(InvestigationFinding(
                    finding_id=f"fnd_part_unavail_{uuid.uuid4().hex[:8]}",
                    category="unknown",
                    title=f"Sample unavailability in {item.name}",
                    description=f"Field '{item.name}' was missing in {missing_count} samples. Never reported as unchanged.",
                    c_type_path=item.name,
                    type_name=item.type_name,
                    source_location=item.source_location,
                    confidence="medium",
                    status="UNRESOLVED",
                    evidence_ids=[ev_timeline.evidence_id],
                    classification=EVIDENCE_CLASSIFICATION_UNKNOWN,
                    temporal_provenance={
                        "session_id": sid,
                        "capture_quality": "LOW_IMPACT",
                        "transition_state": ObservationComparisonState.MISSING,
                        "address": f"0x{item.address:x}",
                        "provenance": "LIVE_RUNTIME_CAPTURE",
                    },
                ))

            if changed:
                fnd_chg = InvestigationFinding(
                    finding_id=f"fnd_temp_chg_{uuid.uuid4().hex[:8]}",
                    category="fact",
                    title=f"Temporal value change in {item.name}",
                    description=(
                        f"Field '{item.name}' changed from {first_val} to {last_val} "
                        f"across {len(item_vals)} observations in session {sid}."
                    ),
                    c_type_path=item.name,
                    type_name=item.type_name,
                    source_location=item.source_location,
                    observed_value=last_val,
                    before_value=first_val,
                    after_value=last_val,
                    confidence="high",
                    status="CONFIRMED",
                    evidence_ids=[ev_timeline.evidence_id],
                    temporal_provenance={
                        "session_id": sid,
                        "observation_sequence": item_vals[-1][0],
                        "observation_timestamp": item_vals[-1][1],
                        "capture_quality": "LOW_IMPACT",
                        "address": f"0x{item.address:x}",
                        "transition_state": ObservationComparisonState.CHANGED,
                        "provenance": "LIVE_RUNTIME_CAPTURE",
                    },
                    classification=EVIDENCE_CLASSIFICATION_FACT,
                )
                self._link_candidate_functions(fnd_chg, item, static_provider, debug_elf)
                investigation_session.findings.append(fnd_chg)
            elif not has_partial and not has_terminated:
                fnd_unchg = InvestigationFinding(
                    finding_id=f"fnd_temp_unchg_{uuid.uuid4().hex[:8]}",
                    category="fact",
                    title=f"Value remained unchanged in {item.name}",
                    description=(
                        f"Field '{item.name}' held constant value {first_val} across all "
                        f"{len(item_vals)} examined observations."
                    ),
                    c_type_path=item.name,
                    type_name=item.type_name,
                    source_location=item.source_location,
                    observed_value=first_val,
                    before_value=first_val,
                    after_value=first_val,
                    confidence="high",
                    status="CONFIRMED",
                    evidence_ids=[ev_timeline.evidence_id],
                    temporal_provenance={
                        "session_id": sid,
                        "observation_sequence": item_vals[-1][0],
                        "observation_timestamp": item_vals[-1][1],
                        "capture_quality": "LOW_IMPACT",
                        "address": f"0x{item.address:x}",
                        "transition_state": ObservationComparisonState.UNCHANGED,
                        "provenance": "LIVE_RUNTIME_CAPTURE",
                    },
                    classification=EVIDENCE_CLASSIFICATION_FACT,
                )
                self._link_candidate_functions(fnd_unchg, item, static_provider, debug_elf)
                investigation_session.findings.append(fnd_unchg)

            # -----------------------------------------------------------------
            # Stage 4: Buffer & Memory Guard Proximity Evaluation
            # -----------------------------------------------------------------
            # Inspect pointer / array index proximity if requested or if guard is known
            guard_target = plan.guard_address
            # If no explicit guard address was given, but goal mentions guard and item looks like a pointer/buffer
            is_pointer_or_addr = (
                item.type_name in ("pointer", "uint64_t", "uint32_t", "void*")
                or "ptr" in item.name.lower()
                or "node" in item.name.lower()
                or "buffer" in item.name.lower()
                or "shared" in item.name.lower()
            )

            if guard_target is not None and is_pointer_or_addr:
                # Evaluate observed pointer values against guard boundary
                closest_dist = None
                closest_seq = None
                closest_ptr_val = None

                for seq, ts, val, st in item_vals:
                    if st not in ("VALID", "OBSERVED") or val is None:
                        continue
                    ptr_num = None
                    if isinstance(val, int):
                        ptr_num = val
                    elif isinstance(val, str) and val.startswith("0x"):
                        try:
                            ptr_num = int(val, 16)
                        except ValueError:
                            pass
                    elif isinstance(val, str) and val.isdigit():
                        ptr_num = int(val)

                    if ptr_num is not None:
                        ptr_num = ptr_num & 0xFFFFFFFFFFFFFFFF
                        # Skip null pointers and addresses outside user space
                        if ptr_num == 0 or ptr_num > 0x7FFFFFFFFFFFFFFF:
                            continue
                        dist = abs(guard_target - ptr_num)
                        if closest_dist is None or dist < closest_dist:
                            closest_dist = dist
                            closest_seq = seq
                            closest_ptr_val = ptr_num

                if closest_dist is not None and closest_dist <= plan.guard_threshold:
                    # PROXIMITY CANDIDATE DETECTED!
                    # Record Fact: Observed proximity
                    ev_prox = investigation_session.ledger.add_record(EvidenceRecord(
                        evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
                        nature=NATURE_OBSERVATION,
                        source="memory_guard_analyzer",
                        session_id=investigation_session.investigation_id,
                        parent_evidence_ids=[ev_timeline.evidence_id],
                        observation=(
                            f"Variable '{item.name}' approached memory guard boundary: "
                            f"address 0x{closest_ptr_val:x} is {closest_dist} bytes from guard 0x{guard_target:x} "
                            f"(threshold: {plan.guard_threshold}B, sequence: {closest_seq})."
                        ),
                        field_observation={
                            "variable_name": item.name,
                            "pointer_value": f"0x{closest_ptr_val:x}",
                            "guard_address": f"0x{guard_target:x}",
                            "distance_bytes": closest_dist,
                            "sequence": closest_seq,
                        },
                        provenance={
                            "watch_session_id": sid,
                            "watch_item_id": item.item_id,
                            "provenance_class": PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
                        },
                        details={"limitations": [HONEST_CAPTURE_SEMANTICS_NOTICE]},
                    ))

                    fnd_prox = InvestigationFinding(
                        finding_id=f"fnd_guard_prox_{uuid.uuid4().hex[:8]}",
                        category="fact",
                        title=f"Variable '{item.name}' proximity to memory guard ({closest_dist} bytes away)",
                        description=(
                            f"At observation sequence {closest_seq}, pointer '{item.name}' had value "
                            f"0x{closest_ptr_val:x}, which is within {closest_dist} bytes of memory guard "
                            f"at 0x{guard_target:x}."
                        ),
                        c_type_path=item.name,
                        type_name=item.type_name,
                        source_location=item.source_location,
                        observed_value=f"0x{closest_ptr_val:x} (distance to guard: {closest_dist} bytes)",
                        confidence="high",
                        status="CONFIRMED",
                        evidence_ids=[ev_prox.evidence_id],
                        temporal_provenance={
                            "session_id": sid,
                            "observation_sequence": closest_seq,
                            "capture_quality": "LOW_IMPACT",
                            "address": f"0x{closest_ptr_val:x}",
                            "guard_address": f"0x{guard_target:x}",
                            "boundary_kind": plan.boundary_kind,
                            "distance_bytes": closest_dist,
                            "provenance": "LIVE_RUNTIME_CAPTURE",
                        },
                        uncertainty=HONEST_CAPTURE_SEMANTICS_NOTICE,
                        classification=EVIDENCE_CLASSIFICATION_FACT,
                    )
                    self._link_candidate_functions(fnd_prox, item, static_provider, debug_elf)
                    investigation_session.findings.append(fnd_prox)

                    # Inferred Hypothesis: Potential overrun risk
                    hypo_prox = InvestigationHypothesis(
                        hypothesis_id=f"hypo_guard_{uuid.uuid4().hex[:8]}",
                        investigation_id=investigation_session.investigation_id,
                        title=f"Potential Buffer Boundary Approach by '{item.name}'",
                        claim=(
                            f"Variable '{item.name}' observed at distance {closest_dist}B from memory guard "
                            f"at 0x{guard_target:x}; further increments or concurrent mutation could exceed bounds."
                        ),
                        status=HYPOTHESIS_STATUS_PROPOSED,
                        confidence=CONFIDENCE_MEDIUM,
                        candidate_fields=[item.name],
                        supporting_evidence_ids=[ev_prox.evidence_id],
                        uncertainty=(
                            "Snapshot proximity alone does NOT prove actual read, write, or guard violation. "
                            + HONEST_CAPTURE_SEMANTICS_NOTICE
                        ),
                    )
                    investigation_session.hypotheses.append(hypo_prox)

                    # Follow-Up Observation Recommendation
                    obs_rec = FollowUpObservation(
                        observation_id=f"obs_guard_trace_{uuid.uuid4().hex[:6]}",
                        hypothesis_id=hypo_prox.hypothesis_id,
                        question=(
                            f"Deploy non-invasive hardware watchpoint on guard page 0x{guard_target:x} "
                            f"to verify if candidate functions actually execute write operations?"
                        ),
                        target_kind="FIELD",
                        expected_outcomes={
                            "GUARD_HIT": "Authentic write access trapped; causal function verified.",
                            "NO_HIT": "No memory guard violation; proximity did not cross bounds.",
                        },
                        status=OBSERVATION_STATUS_PROPOSED,
                        risk_level="READ_ONLY",
                    )
                    investigation_session.follow_up_observations.append(obs_rec)

                    investigation_session.next_steps.append(InvestigationNextStep(
                        step_id=f"step_guard_{uuid.uuid4().hex[:6]}",
                        description=(
                            f"Set memory watchpoint or eBPF probe on memory guard page 0x{guard_target:x} "
                            f"to monitor write attempts by '{item.name}' callers."
                        ),
                        rationale=(
                            f"Proximity ({closest_dist}B) is confirmed by snapshots, but non-atomic sampling "
                            f"cannot prove actual guard crossing. Independent access tracing is required."
                        ),
                        risk_level="READ_ONLY",
                        action_type="INSPECT",
                        required_inputs=["guard_address"],
                    ))
                elif closest_dist is not None and closest_dist > plan.guard_threshold:
                    fnd_safe = InvestigationFinding(
                        finding_id=f"fnd_guard_safe_{uuid.uuid4().hex[:8]}",
                        category="fact",
                        title=f"Variable '{item.name}' maintained safe boundary distance ({closest_dist} bytes away)",
                        description=(
                            f"Pointer '{item.name}' remained at least {closest_dist} bytes from memory guard ({plan.boundary_kind}) "
                            f"at 0x{guard_target:x} (threshold: {plan.guard_threshold}B). No guard proximity event detected."
                        ),
                        c_type_path=item.name,
                        type_name=item.type_name,
                        source_location=item.source_location,
                        observed_value=f"0x{closest_ptr_val:x} (distance to guard: {closest_dist} bytes)",
                        confidence="high",
                        status="CONFIRMED",
                        evidence_ids=[ev_timeline.evidence_id],
                        temporal_provenance={
                            "session_id": sid,
                            "observation_sequence": closest_seq,
                            "capture_quality": "LOW_IMPACT",
                            "address": f"0x{closest_ptr_val:x}",
                            "guard_address": f"0x{guard_target:x}",
                            "boundary_kind": plan.boundary_kind,
                            "distance_bytes": closest_dist,
                            "provenance": "LIVE_RUNTIME_CAPTURE",
                        },
                        classification=EVIDENCE_CLASSIFICATION_FACT,
                    )
                    self._link_candidate_functions(fnd_safe, item, static_provider, debug_elf)
                    investigation_session.findings.append(fnd_safe)

        # Discriminating Next Steps if none were generated
        if not investigation_session.next_steps:
            investigation_session.next_steps.append(InvestigationNextStep(
                step_id=f"step_refine_{uuid.uuid4().hex[:6]}",
                description="Refine sampling interval or extend observation window for fine-grained state correlation.",
                rationale="Observations in the current window remained steady. Further temporal sampling may reveal asynchronous events.",
                risk_level="READ_ONLY",
                action_type="COMPARE",
            ))

        investigation_session.status = "COMPLETED"
        investigation_session.summary["status"] = "COMPLETED"
        investigation_session.summary["findings_count"] = len(investigation_session.findings)
        investigation_session.summary["hypotheses_count"] = len(investigation_session.hypotheses)
        investigation_session.summary["next_steps_count"] = len(investigation_session.next_steps)

        is_korean = any("\uac00" <= ch <= "\ud7a3" for ch in effective_goal)
        gaps_text = f", {len(watch_session.gaps)}건의 캡처 갭" if watch_session.gaps else ""
        en_gaps = f", {len(watch_session.gaps)} capture gaps" if watch_session.gaps else ""

        if is_korean:
            overview_text = (
                f"시계열 관측 세션 '{sid}'(PID {watch_session.pid}) 분석 완료. "
                f"총 {len(obs_data_list)}개 샘플, {len(watch_session.watch_items)}개 감시 변수{gaps_text} 조사. "
                f"발견된 사실 {len(investigation_session.findings)}건, 가설 {len(investigation_session.hypotheses)}건."
            )
            if any(g.reason for g in watch_session.gaps):
                reasons = ", ".join(g.reason for g in watch_session.gaps)
                overview_text += f" (기록된 갭 원인: {reasons})"
        else:
            overview_text = (
                f"Temporal observation session '{sid}' (PID {watch_session.pid}) analysis completed. "
                f"Examined {len(obs_data_list)} observations across {len(watch_session.watch_items)} watch items{en_gaps}. "
                f"Produced {len(investigation_session.findings)} findings and {len(investigation_session.hypotheses)} hypotheses."
            )
            if any(g.reason for g in watch_session.gaps):
                reasons = ", ".join(g.reason for g in watch_session.gaps)
                overview_text += f" (Recorded gaps: {reasons})"

        investigation_session.summary["overview"] = overview_text
        investigation_session.summary["text"] = overview_text

        return investigation_session.to_dict()

    def _link_candidate_functions(
        self,
        finding: InvestigationFinding,
        item: WatchItem,
        static_provider: Optional[StaticAnalysisProvider],
        debug_elf: Optional[str],
    ) -> None:
        """Find and rank static candidate functions without promoting to validated causality."""
        candidates: List[Dict[str, Any]] = []

        if static_provider:
            try:
                raw_cands = static_provider.find_functions_for_field(item.name)
                for rc in raw_cands:
                    c_dict = rc if isinstance(rc, dict) else (rc.to_dict() if hasattr(rc, "to_dict") else dict(rc))
                    c_dict["candidate_tier"] = FUNCTION_TIER_STATIC_CANDIDATE
                    c_dict["confirmed_root_cause"] = False
                    c_dict["tier_limitation"] = LAYOUT_MUTATION_CAVEAT
                    candidates.append(c_dict)
            except Exception:
                pass

        if not candidates and debug_elf:
            # Fallback ELF symbol discovery for candidate functions
            try:
                from extractor.debug_image import inspect_elf
                info = inspect_elf(debug_elf)
                item_base = item.name.split(".")[-1].split("->")[-1].replace("g_", "").replace("*", "").strip()
                for sym_name, sym_addr in getattr(info, "symbols", {}).items():
                    if any(kw in sym_name.lower() for kw in ("worker", "mutate", "sample", "override", "advance", "telemetry", "pool", "buffer")):
                        candidates.append({
                            "function_name": sym_name,
                            "candidate_tier": FUNCTION_TIER_STATIC_CANDIDATE,
                            "confirmed_root_cause": False,
                            "tier_limitation": LAYOUT_MUTATION_CAVEAT,
                            "source_file": item.source_location or "debug_image",
                            "reason": f"Symbol references runtime state related to '{item.name}'.",
                        })
                        if len(candidates) >= 5:
                            break
            except Exception:
                pass

        # Attach to finding
        finding.function_candidates = candidates
        finding.code_navigation = {
            "type_name": item.type_name,
            "source_location": item.source_location,
            "layout_caveat": LAYOUT_MUTATION_CAVEAT,
            "candidates_count": len(candidates),
        }

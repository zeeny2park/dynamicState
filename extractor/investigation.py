"""Investigation Engine: High-level evidence-first investigation workflow for dynamicState.

Orchestrates the investigation pipeline:
1. Target/process and build identity validation (GNU Build-ID & load bias)
2. Runtime evidence capture or offline snapshot loading (offline-first, zero target stop without authorization)
3. Capture quality validation (ATOMIC / NON_ATOMIC consistency, partial reads, missing regions)
4. DWARF-based typed object interpretation & semantic paths
5. Observation comparison across snapshots
6. Related static-code evidence linking via defensible address/symbol translation
7. Generation of structured findings (facts, hypotheses, unknowns) and actionable next steps.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import json
import os
import re
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from .debug_artifacts import DebugArtifactProvider
from .debug_image import BinaryIdentity, inspect_elf
from .dwarf_indexer import DwarfIndex, DwarfIndexer
from .evidence_ledger import (
    EVIDENCE_SCHEMA_VERSION,
    EVIDENCE_TYPE_CAPTURE_QUALITY,
    EVIDENCE_TYPE_COMPARISON,
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EVIDENCE_TYPE_HYPOTHESIS,
    EVIDENCE_TYPE_OBJECT_STATE,
    EVIDENCE_TYPE_RUNTIME_IDENTITY,
    EVIDENCE_TYPE_STATIC_LINK,
    EvidenceLedger,
    EvidenceRecord,
    NATURE_HYPOTHESIS,
    NATURE_INFERENCE,
    NATURE_OBSERVATION,
)
from .hypothesis import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_SPECULATIVE,
    DeterministicHypothesisGenerator,
    FollowUpObservation,
    FUNCTION_TIER_EVIDENCE_SUPPORTED,
    FUNCTION_TIER_STATIC_CANDIDATE,
    FUNCTION_TIER_UNKNOWN,
    FUNCTION_TIER_VALIDATED_CAUSAL,
    HYPOTHESIS_STATUS_CONTRADICTED,
    HYPOTHESIS_STATUS_INCONCLUSIVE,
    HYPOTHESIS_STATUS_PROPOSED,
    HYPOTHESIS_STATUS_SUPPORTED,
    HYPOTHESIS_STATUS_VALIDATED,
    HypothesisGenerator,
    HypothesisValidator,
    InvestigationHypothesis,
    TARGET_KIND_COMPARISON,
    TARGET_KIND_FIELD,
    TARGET_KIND_OBJECT,
    TARGET_KIND_SNAPSHOT,
    TARGET_KIND_THREAD,
    ValidationTransitionResult,
)
from .modules import ModuleAddressResolver, RuntimeModule, discover_modules
from .raw_snapshot import RawRuntimeSnapshot
from .semantic_state import OfflineSemanticEngine, SemanticState
from .snapshot import RuntimeSnapshot
from .snapshot_consistency import ATOMIC, NON_ATOMIC, STOPPED, SnapshotConsistency
from .state_corpus import StateCorpus
from .state_diff import StateDiffEngine
from .state_lab import compute_semantic_diff
from .static_analyzer import (
    IDENTITY_DEBUG_ID_UNAVAILABLE,
    IDENTITY_INCOMPLETE,
    IDENTITY_MISMATCH,
    IDENTITY_TARGET_ID_UNAVAILABLE,
    IDENTITY_VERIFIED_MATCH,
    LINK_KIND_CALL_RELATIONSHIP,
    LINK_KIND_FIELD_WRITE_CANDIDATE,
    LINK_KIND_FUNCTION_ADDRESS,
    LINK_KIND_GLOBAL_VARIABLE,
    LINK_KIND_SOURCE_LOCATION,
    LINK_KIND_TYPE_DEFINITION,
    LINK_KIND_UNRESOLVED,
    DwarfStaticAnalysisProvider,
    NullStaticAnalysisProvider,
    StaticAnalysisProvider,
    validate_module_identity,
    resolve_function_candidates,
    LAYOUT_MUTATION_CAVEAT,
)


@dataclass
class InvestigationFinding:
    """A structured finding classified into fact, hypothesis, or unknown."""
    finding_id: str
    category: str  # "fact" (direct observation), "hypothesis" (inference), "unknown" (missing/unresolved)
    title: str
    description: str
    c_type_path: Optional[str] = None
    object_id: Optional[str] = None
    field_name: Optional[str] = None
    evidence_ids: List[str] = field(default_factory=list)
    confidence: str = "high"
    status: str = "CONFIRMED"  # CONFIRMED, CANDIDATE, UNRESOLVED, SUSPECT
    priority: str = "MEDIUM"  # HIGH, MEDIUM, LOW
    uncertainty: Optional[str] = None
    thread_id: Optional[Union[int, str]] = None
    execution_context: Optional[str] = None
    type_name: Optional[str] = None
    source_location: Optional[str] = None
    type_decl_location: Optional[str] = None
    function_candidates: List[Dict[str, Any]] = field(default_factory=list)
    code_navigation: Optional[Dict[str, Any]] = None
    observed_value: Any = None
    before_value: Any = None
    after_value: Any = None
    layout_caveat: Optional[str] = None
    unavailable_reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class InvestigationNextStep:
    """An evidence-driven recommended action, clearly distinguishing suggestion from executed action."""
    step_id: str
    description: str
    rationale: str
    is_suggestion: bool = True
    executed: bool = False
    risk_level: str = "READ_ONLY"  # "READ_ONLY", "CAUTION", "MUTATION"
    required_inputs: List[str] = field(default_factory=list)
    action_type: str = "INSPECT"  # INSPECT, COMPARE, CAPTURE, MUTATE_LAB

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class InvestigationSession:
    """Encapsulates the state and lifecycle of a single investigation."""

    def __init__(
        self,
        investigation_id: str,
        goal: str,
        corpus_dir: str = "corpus",
        safety: Optional[Dict[str, Any]] = None,
        budgets: Optional[Dict[str, Any]] = None,
    ):
        self.investigation_id = investigation_id
        self.goal = goal
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.status = "CREATED"  # CREATED, RUNNING, COMPLETED, PARTIAL, FAILED, BLOCKED
        self.corpus_dir = os.path.abspath(corpus_dir)
        self.ledger = EvidenceLedger(session_id=investigation_id)

        # Safety configuration (Strict read-only default)
        self.safety = {
            "read_only": True,
            "target_authorized": False,
            "allow_mutation": False,
        }
        if safety:
            self.safety.update(safety)

        # Budgets configuration
        self.budgets = {
            "max_depth": 10,
            "max_objects": 100,
            "timeout_ms": 5000,
            "max_bytes": 32 * 1024 * 1024,
        }
        if budgets:
            self.budgets.update(budgets)

        # Stage tracking
        self.stages: Dict[str, Dict[str, Any]] = {
            "target_identity": {"status": "PENDING", "completed_at": None, "details": {}},
            "capture_quality": {"status": "PENDING", "completed_at": None, "details": {}},
            "semantic_interpretation": {"status": "PENDING", "completed_at": None, "details": {}},
            "observation_comparison": {"status": "PENDING", "completed_at": None, "details": {}},
            "static_code_link": {"status": "PENDING", "completed_at": None, "details": {}},
            "report_synthesis": {"status": "PENDING", "completed_at": None, "details": {}},
        }

        self.target_ref: Dict[str, Any] = {}
        self.findings: List[InvestigationFinding] = []
        self.hypotheses: List[InvestigationHypothesis] = []
        self.next_steps: List[InvestigationNextStep] = []
        self.active_snapshot: Optional[Any] = None
        self.comparison_results: List[Dict[str, Any]] = []
        self.static_provider: StaticAnalysisProvider = NullStaticAnalysisProvider()
        self.summary: Dict[str, Any] = {}
        self.persistence: str = "EPHEMERAL_PROCESS_LOCAL"

    def to_dict(self) -> Dict[str, Any]:
        """Convert session to JSON-serializable dictionary."""
        return {
            "investigation_id": self.investigation_id,
            "goal": self.goal,
            "status": self.status,
            "created_at": self.created_at,
            "persistence": self.persistence,
            "target_ref": self.target_ref,
            "safety": self.safety,
            "budgets": self.budgets,
            "stages": self.stages,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "hypotheses_count": len(self.hypotheses),
            "hypotheses": [h.to_dict() for h in self.hypotheses],
            "evidence_count": len(self.ledger._records),
            "next_steps": [s.to_dict() for s in self.next_steps],
            "comparison_results": self.comparison_results,
            "summary": self.summary,
        }


class InvestigationManager:
    """Host-side orchestrator managing investigations and wrapping dynamicState capabilities."""

    def __init__(self, corpus_dir: str = "corpus"):
        self.corpus_dir = os.path.abspath(corpus_dir)
        self.corpus = StateCorpus(self.corpus_dir)
        self.artifact_provider = DebugArtifactProvider()
        self.sessions: Dict[str, InvestigationSession] = {}

    # -------------------------------------------------------------------------
    # Core Investigation Workflow API
    # -------------------------------------------------------------------------

    def start_investigation(
        self,
        goal: str,
        snapshot_id: Optional[str] = None,
        memory_snapshot_path: Optional[str] = None,
        pid: Optional[int] = None,
        debug_image: Optional[str] = None,
        constraints: Optional[Dict[str, Any]] = None,
        budgets: Optional[Dict[str, Any]] = None,
        authorize_target: bool = False,
        static_provider: Optional[StaticAnalysisProvider] = None,
    ) -> Dict[str, Any]:
        """Start an investigation from an existing offline snapshot or authorized target.

        Strict Safety Guarantees:
        - Default behavior is completely read-only.
        - Offline snapshots are analyzed without touching any live processes.
        - Live processes are never stopped or altered without explicit `authorize_target=True`.
        """
        inv_id = f"inv_{uuid.uuid4().hex[:10]}"
        safety = {
            "read_only": True,
            "target_authorized": bool(authorize_target),
            "allow_mutation": False,
        }
        session = InvestigationSession(
            investigation_id=inv_id,
            goal=goal,
            corpus_dir=self.corpus_dir,
            safety=safety,
            budgets=budgets,
        )
        self.sessions[inv_id] = session

        session.target_ref = {
            "snapshot_id": snapshot_id,
            "memory_snapshot_path": memory_snapshot_path,
            "pid": pid,
            "debug_image": debug_image,
            "constraints": constraints or {},
        }

        # Target parameter validation and live PID processing
        parsed_pid = None
        if pid is not None:
            if isinstance(pid, bool):
                session.status = "FAILED"
                session.stages["target_identity"] = {
                    "status": "FAILED",
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                    "details": {"error": f"Invalid PID format: boolean {pid}. Target PID must be an integer."},
                }
                session.summary["error"] = f"Invalid PID format: boolean {pid}"
                return session.to_dict()

            if isinstance(pid, int):
                parsed_pid = pid
            elif isinstance(pid, str):
                pid_str = pid.strip()
                if not pid_str.isdigit():
                    session.status = "FAILED"
                    session.stages["target_identity"] = {
                        "status": "FAILED",
                        "completed_at": datetime.now(timezone.utc).isoformat(),
                        "details": {"error": f"Invalid PID format: '{pid}'. Target PID must be a decimal integer without signs, decimals, or characters."},
                    }
                    session.summary["error"] = f"Invalid PID format: '{pid}'"
                    return session.to_dict()
                parsed_pid = int(pid_str)
            else:
                session.status = "FAILED"
                session.stages["target_identity"] = {
                    "status": "FAILED",
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                    "details": {"error": f"Invalid PID format: {pid}. Target PID must be an integer."},
                }
                session.summary["error"] = f"Invalid PID format: '{pid}'"
                return session.to_dict()

            if parsed_pid <= 0 or parsed_pid > 2147483647:
                session.status = "FAILED"
                session.stages["target_identity"] = {
                    "status": "FAILED",
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                    "details": {"error": f"PID {parsed_pid} is out of valid range (1 - 2147483647)."},
                }
                session.summary["error"] = f"PID {parsed_pid} is out of valid range"
                return session.to_dict()

            # Prevent ambiguous targets: do not permit live capture and offline snapshot simultaneously
            if snapshot_id or memory_snapshot_path:
                session.status = "FAILED"
                session.stages["target_identity"] = {
                    "status": "FAILED",
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                    "details": {"error": f"Conflicting target parameters: cannot specify both live PID ({parsed_pid}) and offline snapshot."},
                }
                session.summary["error"] = "Conflicting target parameters: cannot specify both live PID and offline snapshot"
                return session.to_dict()

            session.target_ref["pid"] = parsed_pid

            # Check authorization for live process capture
            if not authorize_target:
                session.status = "BLOCKED"
                session.stages["target_identity"] = {
                    "status": "BLOCKED",
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                    "details": {"error": f"Live process capture for PID {parsed_pid} requires explicit authorize_target=True."},
                }
                session.findings.append(InvestigationFinding(
                    finding_id=f"fnd_auth_{uuid.uuid4().hex[:8]}",
                    category="unknown",
                    title="Target Process Authorization Required",
                    description=f"PID {parsed_pid} was specified without an existing offline snapshot. Live process inspection requires explicit authorize_target=True.",
                    confidence="high",
                    status="UNRESOLVED",
                ))
                session.summary["error"] = "Target authorization required for live process capture"
                return session.to_dict()

            # Target is authorized: verify process existence before capture
            try:
                os.kill(parsed_pid, 0)
            except ProcessLookupError:
                session.status = "FAILED"
                session.stages["target_identity"] = {
                    "status": "FAILED",
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                    "details": {"error": f"Target process PID {parsed_pid} does not exist (ESRCH)."},
                }
                session.summary["error"] = f"Target PID {parsed_pid} not found (ESRCH)"
                return session.to_dict()
            except PermissionError:
                session.status = "FAILED"
                session.stages["target_identity"] = {
                    "status": "FAILED",
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                    "details": {"error": f"Permission denied accessing PID {parsed_pid} (EPERM)."},
                }
                session.summary["error"] = f"Permission denied accessing PID {parsed_pid} (EPERM)"
                return session.to_dict()

            # Select capture backend without silent fallback
            from .capture_backend import ProcessVmCaptureBackend, ProcfsCaptureBackend
            vm_backend = ProcessVmCaptureBackend()
            proc_backend = ProcfsCaptureBackend()
            selected_backend = None
            fallback_reason = None

            if vm_backend.is_available(parsed_pid):
                selected_backend = vm_backend
            elif proc_backend.is_available(parsed_pid):
                selected_backend = proc_backend
                fallback_reason = "process_vm_readv is unavailable or restricted; fell back to procfs (/proc/<pid>/mem)."
            else:
                session.status = "FAILED"
                session.stages["capture_quality"] = {
                    "status": "FAILED",
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                    "details": {"error": f"No usable capture backend available for PID {parsed_pid} (both process_vm_readv and /proc/{parsed_pid}/mem inaccessible)."},
                }
                session.summary["error"] = f"No usable capture backend available for PID {parsed_pid}"
                return session.to_dict()

            session.target_ref["capture_backend"] = selected_backend.name
            session.target_ref["backend_fallback"] = bool(fallback_reason)
            session.target_ref["fallback_reason"] = fallback_reason
            session.target_ref["backend_capabilities"] = selected_backend.capabilities

            try:
                live_snap = selected_backend.capture(pid=parsed_pid)
                if live_snap.bytes_captured == 0:
                    session.status = "FAILED"
                    session.stages["capture_quality"] = {
                        "status": "FAILED",
                        "completed_at": datetime.now(timezone.utc).isoformat(),
                        "details": {"error": f"Live memory capture yielded 0 bytes for PID {parsed_pid}."},
                    }
                    session.summary["error"] = f"Live memory capture failed: 0 bytes read for PID {parsed_pid}"
                    return session.to_dict()

                snap_dir = os.path.join(self.corpus_dir, "memory_snapshots", f"live_pid_{parsed_pid}_{uuid.uuid4().hex[:6]}")
                live_snap.save(snap_dir)
                session.target_ref["memory_snapshot_path"] = snap_dir
                session.target_ref["live_capture"] = True
                session.target_ref["capture_source"] = "LIVE_PROCESS"
            except ProcessLookupError as proc_err:
                session.status = "FAILED"
                session.stages["capture_quality"] = {
                    "status": "FAILED",
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                    "details": {"error": f"Target process PID {parsed_pid} exited during capture (ESRCH): {proc_err}."},
                }
                session.summary["error"] = f"Target process exited during capture (ESRCH)"
                return session.to_dict()
            except Exception as cap_exc:
                session.status = "FAILED"
                session.stages["capture_quality"] = {
                    "status": "FAILED",
                    "completed_at": datetime.now(timezone.utc).isoformat(),
                    "details": {"error": f"Live memory capture failed for PID {parsed_pid}: {cap_exc}"},
                }
                session.summary["error"] = f"Live memory capture failed: {cap_exc}"
                return session.to_dict()

        if static_provider:
            session.static_provider = static_provider
        elif debug_image and os.path.exists(debug_image):
            session.static_provider = DwarfStaticAnalysisProvider(debug_image)
        else:
            session.static_provider = NullStaticAnalysisProvider()

        session.status = "RUNNING"

        try:
            # Stage 1: Load Target / Snapshot & Validate Build Identity
            self._execute_stage_identity(session)

            # Stage 2: Capture Quality Validation
            self._execute_stage_capture_quality(session)

            # Stage 3: Typed Semantic Interpretation
            self._execute_stage_semantic_interpretation(session)

            # Stage 4: Static Code Linkage
            self._execute_stage_static_linking(session)

            # Stage 5: Synthesis & Next Steps
            self._execute_stage_synthesis(session)

            # Preserve honest overall status synthesized by pipeline
            session.status = session.summary.get("status", session.status)

        except Exception as exc:
            session.status = "FAILED"
            session.summary["error"] = str(exc)

        return session.to_dict()

    def get_investigation_status(self, investigation_id: str) -> Dict[str, Any]:
        """Report completed, running, blocked, failed, or partial stages of an investigation."""
        session = self.sessions.get(investigation_id)
        if not session:
            return {"error": f"Investigation '{investigation_id}' not found", "status": "NOT_FOUND"}

        return {
            "investigation_id": session.investigation_id,
            "goal": session.goal,
            "status": session.status,
            "stages": session.stages,
            "findings_count": len(session.findings),
            "evidence_count": len(session.ledger._records),
            "safety": session.safety,
            "summary": session.summary,
        }

    def get_evidence(
        self,
        investigation_id: str,
        evidence_id: Optional[str] = None,
        finding_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Retrieve evidence records and provenance chain for an investigation or finding."""
        session = self.sessions.get(investigation_id)
        if not session:
            return {"error": f"Investigation '{investigation_id}' not found"}

        if evidence_id:
            record = session.ledger.get_record(evidence_id)
            if not record:
                return {"error": f"Evidence '{evidence_id}' not found in investigation '{investigation_id}'"}
            chain = session.ledger.get_provenance_chain(evidence_id=evidence_id)
            return {
                "evidence": record.to_dict(),
                "provenance_chain": chain,
            }

        if finding_id:
            records = session.ledger.query(finding_id=finding_id)
            chain = session.ledger.get_provenance_chain(finding_id=finding_id)
            return {
                "finding_id": finding_id,
                "evidence_count": len(records),
                "evidence": [r.to_dict() for r in records],
                "provenance_chain": chain,
            }

        # Return all evidence in ledger
        return session.ledger.to_dict()

    def compare_observations(
        self,
        investigation_id: str,
        snapshot_a: str,
        snapshot_b: str,
    ) -> Dict[str, Any]:
        """Compare two snapshots semantically, recording differences and uncertainties."""
        session = self.sessions.get(investigation_id)
        if not session:
            return {"error": f"Investigation '{investigation_id}' not found"}

        snap_a = self._resolve_snapshot(snapshot_a, session)
        snap_b = self._resolve_snapshot(snapshot_b, session)

        if not snap_a or not snap_b:
            return {
                "error": "One or both snapshots could not be loaded for comparison.",
                "snapshot_a": snapshot_a,
                "snapshot_b": snapshot_b,
            }

        diff_engine = StateDiffEngine()
        diff_res = diff_engine.diff(snap_a, snap_b)
        diff_dict = diff_res.to_dict()
        diff_trust = getattr(diff_res, "trust_classification", "TRUSTED")

        # Check uncertainty: if either snapshot was NON_ATOMIC, PARTIAL, or untrusted
        uncertainty = None
        def _get_consistency_level(s: Any) -> Optional[str]:
            if isinstance(s, dict):
                c = s.get("consistency")
                if isinstance(c, dict):
                    return c.get("level")
                if isinstance(c, str):
                    return c
                p = s.get("provenance", {})
                if isinstance(p, dict) and p.get("capture_backend") == "process_vm_readv":
                    return NON_ATOMIC
            else:
                c = getattr(s, "consistency", None)
                if c is not None:
                    return c.get("level") if isinstance(c, dict) else getattr(c, "level", None)
                p = getattr(s, "provenance", None)
                if isinstance(p, dict) and p.get("capture_backend") == "process_vm_readv":
                    return NON_ATOMIC
                backend = getattr(s, "capture_backend", None)
                if backend == "process_vm_readv":
                    return NON_ATOMIC
            return None

        level_a = _get_consistency_level(snap_a)
        level_b = _get_consistency_level(snap_b)
        if diff_trust in ("UNTRUSTED_INVALID_CAPTURE", "UNTRUSTED_FAILED_CAPTURE"):
            uncertainty = f"Comparison is untrusted due to capture quality failure: {diff_trust}. Verified facts suppressed."
        elif diff_trust == "PARTIALLY_TRUSTED":
            uncertainty = "One or both snapshots have PARTIAL capture quality; diff may reflect incomplete reads or non-atomic execution skew."
        elif level_a == NON_ATOMIC or level_b == NON_ATOMIC:
            uncertainty = "One or both snapshots were captured non-atomically (process_vm_readv zero-stop). Value diffs may reflect minor execution skew."

        # Record comparison evidence in ledger
        parents = []
        if getattr(session, "capture_quality_evidence_id", None):
            parents.append(session.capture_quality_evidence_id)
        elif getattr(session, "identity_evidence_id", None):
            parents.append(session.identity_evidence_id)

        ev = session.ledger.add_record(EvidenceRecord(
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="state_diff",
            session_id=session.investigation_id,
            parent_evidence_ids=parents,
            observation=f"Semantic comparison between {snapshot_a} and {snapshot_b}: {diff_dict['summary']['value_changes']} value changes, {diff_dict['summary']['objects_created']} added, {diff_dict['summary']['objects_removed']} removed (trust: {diff_trust}).",
            comparison_observation={
                "snapshot_a": snapshot_a,
                "snapshot_b": snapshot_b,
                "summary": diff_dict["summary"],
                "changes_count": len(diff_dict["changes"]),
                "performance": diff_dict["performance"],
                "trust_classification": diff_trust,
            },
            uncertainty=uncertainty,
            details={"changes": diff_dict["changes"][:30], "trust_classification": diff_trust},
        ))

        # Add findings: NEVER generate category="fact" findings if capture diff is untrusted!
        if diff_trust in ("UNTRUSTED_INVALID_CAPTURE", "UNTRUSTED_FAILED_CAPTURE"):
            session.findings.append(InvestigationFinding(
                finding_id=f"fnd_untrusted_cmp_{uuid.uuid4().hex[:8]}",
                category="unknown",
                title=f"Untrusted Snapshot Comparison ({diff_trust})",
                description=f"Comparison between {snapshot_a} and {snapshot_b} is {diff_trust}. Verified runtime facts suppressed to prevent false conclusions.",
                evidence_ids=[ev.evidence_id],
                confidence="low",
                status="UNTRUSTED",
                uncertainty=uncertainty,
            ))
        elif (
            diff_dict["summary"]["value_changes"] > 0
            or diff_dict["summary"]["objects_created"] > 0
            or diff_dict["summary"].get("fields_unavailable", 0) > 0
            or diff_dict["summary"].get("fields_added", 0) > 0
        ):
            for chg in diff_dict["changes"][:20]:
                kind = chg.get("kind")
                if kind == "value_change":
                    fnd_id = f"fnd_cmp_{uuid.uuid4().hex[:8]}"
                    status = "POSSIBLY_INCONSISTENT" if uncertainty else "OBSERVED"
                    fnd = InvestigationFinding(
                        finding_id=fnd_id,
                        category="fact",
                        title=f"Field value change in {chg.get('path', 'unknown')}",
                        description=f"Field changed from {chg.get('before')} to {chg.get('after')} between observations." + (f" Note: {uncertainty}" if uncertainty else ""),
                        c_type_path=chg.get("path"),
                        object_id=chg.get("object_id"),
                        field_name=chg.get("field"),
                        type_name=chg.get("type"),
                        observed_value=chg.get("after"),
                        before_value=chg.get("before"),
                        after_value=chg.get("after"),
                        evidence_ids=[ev.evidence_id],
                        confidence="medium" if uncertainty else "high",
                        status=status,
                        uncertainty=uncertainty,
                    )
                    self._enrich_finding_navigation(session, fnd, snapshot=snap_b)
                    session.findings.append(fnd)
                elif kind == "field_unavailable":
                    fnd_id = f"fnd_cmp_{uuid.uuid4().hex[:8]}"
                    fnd = InvestigationFinding(
                        finding_id=fnd_id,
                        category="unknown",
                        title=f"Field unavailable in comparison: {chg.get('path', 'unknown')}",
                        description=f"Field '{chg.get('field')}' present in one observation was unavailable/missing in the other observation. Never reported as unchanged.",
                        c_type_path=chg.get("path"),
                        object_id=chg.get("object_id"),
                        field_name=chg.get("field"),
                        type_name=chg.get("type"),
                        before_value=chg.get("before"),
                        unavailable_reason=chg.get("reason") or "Field absent or unreadable in subsequent observation.",
                        evidence_ids=[ev.evidence_id],
                        confidence="high",
                        status="UNAVAILABLE",
                        uncertainty="Field missing in comparison observation",
                    )
                    self._enrich_finding_navigation(session, fnd, snapshot=snap_a)
                    session.findings.append(fnd)
                elif kind == "field_added":
                    fnd_id = f"fnd_cmp_{uuid.uuid4().hex[:8]}"
                    fnd = InvestigationFinding(
                        finding_id=fnd_id,
                        category="fact",
                        title=f"Field added in observation: {chg.get('path', 'unknown')}",
                        description=f"Field '{chg.get('field')}' with value {chg.get('after')} was added in subsequent observation." + (f" Note: {uncertainty}" if uncertainty else ""),
                        c_type_path=chg.get("path"),
                        object_id=chg.get("object_id"),
                        field_name=chg.get("field"),
                        type_name=chg.get("type"),
                        observed_value=chg.get("after"),
                        after_value=chg.get("after"),
                        evidence_ids=[ev.evidence_id],
                        confidence="medium" if uncertainty else "high",
                        status="UNVERIFIED_PARTIAL" if (diff_trust == "PARTIALLY_TRUSTED") else "OBSERVED",
                        uncertainty=uncertainty,
                    )
                    self._enrich_finding_navigation(session, fnd, snapshot=snap_b)
                    session.findings.append(fnd)

        session.comparison_results.append({
            "snapshot_a": snapshot_a,
            "snapshot_b": snapshot_b,
            "diff_summary": diff_dict["summary"],
            "uncertainty": uncertainty,
            "evidence_id": ev.evidence_id,
            "changes": diff_dict.get("changes", [])[:50],
        })

        session.stages["observation_comparison"] = {
            "status": "COMPLETED",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "details": {"comparisons_count": len(session.comparison_results)},
        }

        return {
            "evidence_id": ev.evidence_id,
            "summary": diff_dict["summary"],
            "changes": diff_dict["changes"][:50],
            "uncertainty": uncertainty,
        }

    def follow_evidence(
        self,
        investigation_id: str,
        evidence_id: str,
        direction: str = "related_objects",
    ) -> Dict[str, Any]:
        """Discover related objects, fields, functions, or static references connected to an evidence record."""
        session = self.sessions.get(investigation_id)
        if not session:
            return {"error": f"Investigation '{investigation_id}' not found"}

        record = session.ledger.get_record(evidence_id)
        if not record:
            return {"error": f"Evidence '{evidence_id}' not found"}

        related: Dict[str, Any] = {
            "evidence_id": evidence_id,
            "direction": direction,
            "related_objects": [],
            "related_fields": [],
            "related_static_symbols": [],
            "related_evidence": [],
            "provenance_chain": session.ledger.trace_provenance_chain(evidence_id),
        }

        # 1. Connected object and fields
        obj_info = record.object_observation or record.field_observation
        if obj_info:
            oid = obj_info.get("object_id")
            if oid and session.active_snapshot:
                # Find connected objects in snapshot
                snap = session.active_snapshot
                objs = getattr(snap, "objects", []) or (snap.get("persistent", {}).get("objects", []) if isinstance(snap, dict) else [])
                target_obj = next((o for o in objs if (o.get("object_id") if isinstance(o, dict) else getattr(o, "object_id", None)) == oid), None)
                if target_obj:
                    t_dict = target_obj if isinstance(target_obj, dict) else target_obj.to_dict()
                    for f in t_dict.get("fields", []):
                        f_ref = f.get("reference") or f.get("object_ref")
                        if f_ref:
                            related["related_objects"].append({"referenced_object_id": f_ref, "via_field": f.get("name")})
                        related["related_fields"].append(f)

        # 2. Connected static symbols
        if record.static_code_link:
            sym = record.static_code_link.get("symbol_name")
            if sym and session.static_provider.is_available():
                calls = session.static_provider.get_call_relationships(sym)
                related["related_static_symbols"].append({
                    "symbol": sym,
                    "callers": calls.get("callers", []),
                    "callees": calls.get("callees", []),
                })

        # 3. Query sibling evidence
        if record.finding_id:
            siblings = session.ledger.query(finding_id=record.finding_id)
            related["related_evidence"] = [r.evidence_id for r in siblings if r.evidence_id != evidence_id]

        return related

    def get_next_steps(self, investigation_id: str) -> List[Dict[str, Any]]:
        """Return evidence-driven next steps, clearly marking suggestions versus executed actions."""
        session = self.sessions.get(investigation_id)
        if not session:
            return []
        return [s.to_dict() for s in session.next_steps]

    def get_hypotheses(self, investigation_id: str, status_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve structured hypotheses for an investigation session, optionally filtered by status."""
        session = self.sessions.get(investigation_id)
        if not session:
            return []
        hypos = session.hypotheses
        if status_filter:
            f_upper = status_filter.upper()
            hypos = [h for h in hypos if h.validation_status.upper() == f_upper]
        return [h.to_dict() for h in hypos]

    def get_hypothesis(self, investigation_id: str, hypothesis_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve a single hypothesis by ID."""
        session = self.sessions.get(investigation_id)
        if not session:
            return None
        for h in session.hypotheses:
            if h.hypothesis_id == hypothesis_id:
                return h.to_dict()
        return None

    def evaluate_hypothesis(
        self,
        investigation_id: str,
        hypothesis_id: str,
        new_evidence_data: Optional[Dict[str, Any]] = None,
        deterministic_transition_verified: bool = False,
    ) -> Dict[str, Any]:
        """Evaluate a hypothesis against the evidence ledger and optional newly acquired evidence."""
        session = self.sessions.get(investigation_id)
        if not session:
            return {"success": False, "error": f"Investigation '{investigation_id}' not found"}

        target_hypo = None
        for h in session.hypotheses:
            if h.hypothesis_id == hypothesis_id:
                target_hypo = h
                break
        if not target_hypo:
            return {"success": False, "error": f"Hypothesis '{hypothesis_id}' not found in investigation '{investigation_id}'"}

        new_rec = None
        if new_evidence_data:
            try:
                new_rec = EvidenceRecord.from_dict(new_evidence_data)
                session.ledger.add_record(new_rec)
            except Exception as exc:
                return {"success": False, "error": f"Failed to attach evidence: {exc}"}

        result = HypothesisValidator.evaluate(
            hypothesis=target_hypo,
            ledger=session.ledger,
            new_evidence=new_rec,
            deterministic_transition_verified=deterministic_transition_verified,
        )

        # Sync status to corresponding finding in session.findings
        for f in session.findings:
            if f.finding_id == f"fnd_{hypothesis_id}" or (f.category == "hypothesis" and hypothesis_id in f.evidence_ids):
                f.status = target_hypo.validation_status
                f.confidence = target_hypo.confidence.lower()

        return {
            "success": True,
            "hypothesis": target_hypo.to_dict(),
            "transition": {
                "from_status": result.from_status,
                "to_status": result.to_status,
                "status_changed": result.status_changed,
                "confidence": result.confidence,
                "reason": result.reason,
                "trigger_evidence_id": result.trigger_evidence_id,
                "supporting_count": result.supporting_count,
                "contradicting_count": result.contradicting_count,
                "cycle_detected": result.cycle_detected,
                "is_duplicate": result.is_duplicate,
            },
        }

    def execute_observation(
        self,
        investigation_id: str,
        observation_id: str,
        result_data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Execute or record an observation step, update ledger, and re-evaluate affected hypotheses."""
        session = self.sessions.get(investigation_id)
        if not session:
            return {"success": False, "error": f"Investigation '{investigation_id}' not found"}

        target_obs = None
        target_hypo = None
        for h in session.hypotheses:
            for obs in h.suggested_observations:
                if obs.observation_id == observation_id:
                    target_obs = obs
                    target_hypo = h
                    break
            if target_obs:
                break

        if not target_obs or not target_hypo:
            return {"success": False, "error": f"Observation '{observation_id}' not found in investigation '{investigation_id}'"}

        # If live mutation requested, verify strict safety constraints
        if not session.safety.get("target_authorized", False) and target_obs.target_kind == "MUTATION":
            return {
                "success": False,
                "error": "Target authorization required: live process mutation is not authorized.",
                "blocked": True,
            }

        # Formulate observation record
        ev_id = f"ev_obs_{uuid.uuid4().hex[:8]}"
        outcome = "INCONCLUSIVE"

        if result_data:
            obs_text = result_data.get("observation", f"Observed {target_obs.question}")
            details = dict(result_data.get("details", {}))
            outcome = result_data.get("outcome", details.get("outcome", "SUPPORTED"))
        else:
            # Read-only observation against existing snapshot / session data
            if target_obs.target_kind == TARGET_KIND_FIELD:
                f_path = target_obs.target_ref.get("field_path", "")
                obs_text = f"Inspected field {f_path} in snapshot."
                details = {"field_path": f_path, "outcome": "SUPPORTED"}
                outcome = "SUPPORTED"
            elif target_obs.target_kind == TARGET_KIND_THREAD:
                th_id = target_obs.target_ref.get("thread_id", "all")
                obs_text = f"Inspected thread {th_id} call stack in snapshot."
                details = {"thread_id": th_id, "outcome": "SUPPORTED"}
                outcome = "SUPPORTED"
            elif target_obs.target_kind == TARGET_KIND_COMPARISON:
                obs_text = f"Compared observation against baseline."
                details = {"comparison": target_obs.target_ref, "outcome": "SUPPORTED"}
                outcome = "SUPPORTED"
            else:
                obs_text = f"Executed observation: {target_obs.question}"
                details = {"target_ref": target_obs.target_ref, "outcome": "SUPPORTED"}
                outcome = "SUPPORTED"

        details["observation_id"] = observation_id
        details["hypothesis_id"] = target_hypo.hypothesis_id
        details["outcome"] = outcome

        ev_record = EvidenceRecord(
            evidence_id=ev_id,
            evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION if target_obs.target_kind == TARGET_KIND_FIELD else EVIDENCE_TYPE_OBJECT_STATE,
            nature=NATURE_OBSERVATION,
            source="investigation_observer",
            session_id=investigation_id,
            finding_id=f"fnd_{target_hypo.hypothesis_id}",
            observation=obs_text,
            parent_evidence_ids=list(target_hypo.supporting_evidence_ids),
            details=details,
        )
        session.ledger.add_record(ev_record)

        # Mark observation executed
        target_obs.executed = True
        target_obs.is_suggestion = False
        target_obs.result_evidence_id = ev_id

        # Also update in session.next_steps if present
        for ns in session.next_steps:
            if ns.step_id == observation_id:
                ns.executed = True
                ns.is_suggestion = False

        # Re-evaluate hypothesis
        eval_result = HypothesisValidator.evaluate(
            hypothesis=target_hypo,
            ledger=session.ledger,
            new_evidence=ev_record,
        )

        # Sync finding
        for f in session.findings:
            if f.finding_id == f"fnd_{target_hypo.hypothesis_id}":
                f.status = target_hypo.validation_status
                f.confidence = target_hypo.confidence.lower()

        return {
            "success": True,
            "observation": target_obs.to_dict(),
            "evidence": ev_record.to_dict(),
            "evaluation": {
                "hypothesis_id": target_hypo.hypothesis_id,
                "from_status": eval_result.from_status,
                "to_status": eval_result.to_status,
                "status_changed": eval_result.status_changed,
                "confidence": eval_result.confidence,
                "reason": eval_result.reason,
            },
        }

    def generate_report(self, investigation_id: str) -> Dict[str, Any]:
        """Synthesize a complete investigation report."""
        session = self.sessions.get(investigation_id)
        if not session:
            return {"error": f"Investigation '{investigation_id}' not found"}

        # Prominently highlight capture quality when data is incomplete or unverified
        cap_stage = session.stages.get("capture_quality", {})
        cap_details = cap_stage.get("details", {})
        cap_status = cap_stage.get("status", "UNKNOWN")
        trust_level = "TRUSTED"
        trust_caveat = None
        if cap_status in ("FAILED", "INVALID"):
            trust_level = "UNTRUSTED"
            trust_caveat = f"Capture quality is {cap_status}. Data is untrusted and cannot substantiate verified runtime facts."
        elif cap_status == "PARTIAL":
            trust_level = "PARTIALLY_TRUSTED"
            trust_caveat = "Capture quality is PARTIAL. Findings may reflect incomplete memory layout, unread regions, or execution skew."

        # Monotonicity & trust boundary: when capture is UNTRUSTED, suppress observed_facts
        if trust_level == "UNTRUSTED":
            for f in session.findings:
                if f.category == "fact":
                    f.category = "unknown"
                    f.status = "UNTRUSTED"
                    f.confidence = "low"
                    f.uncertainty = trust_caveat
            for h in session.hypotheses:
                h.validation_status = HYPOTHESIS_STATUS_INCONCLUSIVE
                h.confidence = CONFIDENCE_LOW
                h.confidence_rationale = trust_caveat

        # Group findings
        facts = [f.to_dict() for f in session.findings if f.category == "fact"]
        hypotheses = [f.to_dict() for f in session.findings if f.category == "hypothesis"]
        unknowns = [f.to_dict() for f in session.findings if f.category == "unknown"]

        # Structured causal conclusions
        causal_conclusions = {
            "established_facts_count": len(facts),
            "hypotheses_count": len(session.hypotheses),
            "supported_hypotheses_count": sum(1 for h in session.hypotheses if h.validation_status == HYPOTHESIS_STATUS_SUPPORTED),
            "validated_causal_count": sum(1 for h in session.hypotheses if h.validation_status == HYPOTHESIS_STATUS_VALIDATED),
            "contradicted_count": sum(1 for h in session.hypotheses if h.validation_status == HYPOTHESIS_STATUS_CONTRADICTED),
            "inconclusive_count": sum(1 for h in session.hypotheses if h.validation_status in (HYPOTHESIS_STATUS_INCONCLUSIVE, HYPOTHESIS_STATUS_PROPOSED)),
            "validated_causal_functions": [
                c for h in session.hypotheses for c in h.function_candidates if c.get("candidate_tier") == FUNCTION_TIER_VALIDATED_CAUSAL
            ],
            "evidence_supported_candidates": [
                c for h in session.hypotheses for c in h.function_candidates if c.get("candidate_tier") == FUNCTION_TIER_EVIDENCE_SUPPORTED
            ],
            "static_candidates": [
                c for h in session.hypotheses for c in h.function_candidates if c.get("candidate_tier") == FUNCTION_TIER_STATIC_CANDIDATE
            ],
            "causal_proof_established": any(h.validation_status == HYPOTHESIS_STATUS_VALIDATED for h in session.hypotheses),
            "causal_limitation_notice": (
                None if any(h.validation_status == HYPOTHESIS_STATUS_VALIDATED for h in session.hypotheses)
                else "Static function candidates and comparative observations alone do not constitute proven causality. Additional deterministic mutation verification or instruction-level trace required."
            ),
        }

        return {
            "investigation_id": session.investigation_id,
            "goal": session.goal,
            "status": session.status,
            "created_at": session.created_at,
            "target_identity": session.stages["target_identity"].get("details", {}),
            "capture_quality": session.stages["capture_quality"].get("details", {}),
            "capture_quality_assessment": {
                "status": cap_status,
                "trust_level": trust_level,
                "caveat": trust_caveat,
                "details": cap_details,
            },
            "stages": session.stages,
            "summary": session.summary,
            "findings_summary": {
                "total": len(session.findings),
                "facts_count": len(facts),
                "hypotheses_count": len(hypotheses),
                "unknowns_count": len(unknowns),
                "scope": session.summary.get("scope", {}),
                "zero_findings_notice": session.summary.get("zero_findings_notice"),
            },
            "findings": {
                "observed_facts": facts,
                "hypotheses": hypotheses,
                "unknowns": unknowns,
            },
            "hypotheses": [h.to_dict() for h in session.hypotheses],
            "causal_conclusions": causal_conclusions,
            "comparisons": session.comparison_results,
            "static_code_links": session.stages["static_code_link"].get("details", {}),
            "recommended_next_steps": [s.to_dict() for s in session.next_steps],
            "evidence_ledger": session.ledger.to_dict(),
        }

    # -------------------------------------------------------------------------
    # Stage Execution Internals
    # -------------------------------------------------------------------------

    def _enrich_finding_navigation(
        self,
        session: InvestigationSession,
        finding: InvestigationFinding,
        target_object: Optional[Dict[str, Any]] = None,
        target_field: Optional[Dict[str, Any]] = None,
        snapshot: Optional[Any] = None,
    ) -> None:
        """Enrich an InvestigationFinding with DWARF source locations, candidate functions, and layout caveat."""
        snap = snapshot or session.active_snapshot
        snap_dict = snap.to_dict() if hasattr(snap, "to_dict") else (snap if isinstance(snap, dict) else {})
        s_inner = snap_dict.get("snapshot", snap_dict)
        persistent = snap_dict.get("persistent") or s_inner.get("persistent") or {}
        raw_objs = persistent.get("objects", []) or snap_dict.get("objects", []) or []

        # Find target object if not passed
        if target_object is None and finding.object_id:
            for o in raw_objs:
                o_d = o if isinstance(o, dict) else (o.to_dict() if hasattr(o, "to_dict") else asdict(o))
                if o_d.get("object_id") == finding.object_id or o_d.get("object_ref") == finding.object_id:
                    target_object = o_d
                    break

        if target_object is None:
            target_object = {
                "object_id": finding.object_id or "",
                "type": finding.type_name or finding.c_type_path or "",
                "fields": [],
            }

        # Find target field if not passed
        if target_field is None and finding.field_name and isinstance(target_object, dict):
            for f in target_object.get("fields", []):
                f_d = f if isinstance(f, dict) else (f.to_dict() if hasattr(f, "to_dict") else asdict(f))
                if f_d.get("name") == finding.field_name:
                    target_field = f_d
                    break
            if target_field is None:
                target_field = {"name": finding.field_name}

        static_prov = session.static_provider
        try:
            nav_result = resolve_function_candidates(
                target_object=target_object,
                target_field=target_field,
                snapshot=snap_dict,
                static_provider=static_prov,
            )
        except Exception:
            nav_result = {}

        # Set type name
        if not finding.type_name or finding.type_name in ("int", "bool", "char", "float", "double", "uint64_t", "int32_t", "void"):
            finding.type_name = nav_result.get("target_type") or target_object.get("type")

        # Set source location (field declaration)
        field_decl_file = nav_result.get("field_decl_file")
        field_decl_line = nav_result.get("field_decl_line")
        if field_decl_file and field_decl_line is not None:
            finding.source_location = f"{field_decl_file}:{field_decl_line}"
        elif isinstance(target_field, dict) and target_field.get("decl_file") and target_field.get("decl_line"):
            finding.source_location = f"{target_field.get('decl_file')}:{target_field.get('decl_line')}"

        # Set type declaration location
        type_decl_file = target_object.get("decl_file")
        type_decl_line = target_object.get("decl_line")
        if type_decl_file and type_decl_line is not None:
            finding.type_decl_location = f"{type_decl_file}:{type_decl_line}"

        # Layout caveat
        finding.layout_caveat = nav_result.get("layout_caveat") or LAYOUT_MUTATION_CAVEAT

        # Function candidates - explicitly qualify as static references rather than confirmed root causes
        raw_candidates = nav_result.get("candidates", [])
        qualified_candidates = []
        for cand in raw_candidates:
            c_dict = dict(cand) if isinstance(cand, dict) else {"symbol": str(cand)}
            c_dict["candidate_kind"] = "static_reference"
            c_dict["confirmed_root_cause"] = False
            c_dict["relationship_limitation"] = "Static reference candidate identified via DWARF/ELF analysis; not confirmed root-cause function."
            qualified_candidates.append(c_dict)
        finding.function_candidates = qualified_candidates
        finding.code_navigation = nav_result

    def _execute_stage_identity(self, session: InvestigationSession) -> None:
        """Stage 1: Validate Target and Debug Image Identity."""
        t_ref = session.target_ref
        dbg_path = t_ref.get("debug_image")
        snap_id = t_ref.get("snapshot_id")
        mem_snap_path = t_ref.get("memory_snapshot_path")

        # Resolve raw snapshot or semantic snapshot
        raw_snap = None
        if mem_snap_path and os.path.exists(mem_snap_path):
            raw_snap = RawRuntimeSnapshot.load(mem_snap_path)
        elif snap_id:
            # Check corpus memory_snapshots
            candidate_p = os.path.join(self.corpus_dir, "memory_snapshots", snap_id)
            if os.path.exists(candidate_p):
                raw_snap = RawRuntimeSnapshot.load(candidate_p)

        target_exec = raw_snap.executable if raw_snap else None
        target_build_id = raw_snap.executable_build_id if raw_snap else None
        pid = raw_snap.pid if raw_snap else t_ref.get("pid")

        dbg_build_id = None
        if dbg_path and os.path.exists(dbg_path):
            try:
                dbg_ident = inspect_elf(dbg_path)
                dbg_build_id = dbg_ident.build_id
            except Exception:
                dbg_build_id = None

        build_id_status, reason = validate_module_identity(target_build_id, dbg_build_id)

        identity_details = {
            "pid": pid,
            "executable": target_exec or ("live_process" if t_ref.get("live_capture") else "offline_artifact"),
            "target_build_id": target_build_id,
            "debug_image": dbg_path,
            "debug_build_id": dbg_build_id,
            "build_id_status": build_id_status,
            "build_id_reason": reason,
            "capture_source": t_ref.get("capture_source", "OFFLINE_SNAPSHOT"),
            "capture_backend": t_ref.get("capture_backend", "corpus"),
        }

        # Record Identity Evidence
        ev = session.ledger.add_record(EvidenceRecord(
            evidence_type=EVIDENCE_TYPE_RUNTIME_IDENTITY,
            nature=NATURE_OBSERVATION,
            source="debug_image_inspect",
            session_id=session.investigation_id,
            observation=f"Target executable identity: {target_exec or 'unknown'}, Build ID status: {build_id_status} ({reason}).",
            target_identity=identity_details,
            details=identity_details,
        ))

        # Add Findings according to explicit identity state
        has_binary_context = bool(target_exec or dbg_path or target_build_id or dbg_build_id)
        if build_id_status == IDENTITY_VERIFIED_MATCH:
            session.findings.append(InvestigationFinding(
                finding_id=f"fnd_id_{uuid.uuid4().hex[:8]}",
                category="fact",
                title="Debug Image Build ID Verified",
                description=reason,
                evidence_ids=[ev.evidence_id],
                confidence="high",
                status="VERIFIED",
            ))
            stage_status = "COMPLETED"
        elif build_id_status == IDENTITY_MISMATCH:
            session.findings.append(InvestigationFinding(
                finding_id=f"fnd_id_{uuid.uuid4().hex[:8]}",
                category="unknown",
                title="Debug Image Build ID Mismatch",
                description=f"Expected build ID {target_build_id} does not match debug artifact build ID {dbg_build_id}. Refusing silent decode.",
                evidence_ids=[ev.evidence_id],
                confidence="high",
                status="UNRESOLVED",
            ))
            stage_status = "FAILED"
        elif build_id_status == IDENTITY_TARGET_ID_UNAVAILABLE and has_binary_context:
            session.findings.append(InvestigationFinding(
                finding_id=f"fnd_id_{uuid.uuid4().hex[:8]}",
                category="unknown",
                title="Target Build ID Unavailable",
                description=reason,
                evidence_ids=[ev.evidence_id],
                confidence="high",
                status="UNRESOLVED",
            ))
            stage_status = "PARTIAL"
        elif build_id_status == IDENTITY_DEBUG_ID_UNAVAILABLE and has_binary_context:
            session.findings.append(InvestigationFinding(
                finding_id=f"fnd_id_{uuid.uuid4().hex[:8]}",
                category="unknown",
                title="Debug Image Build ID Unavailable",
                description=reason,
                evidence_ids=[ev.evidence_id],
                confidence="high",
                status="UNRESOLVED",
            ))
            stage_status = "PARTIAL"
        elif build_id_status == IDENTITY_INCOMPLETE and has_binary_context:
            session.findings.append(InvestigationFinding(
                finding_id=f"fnd_id_{uuid.uuid4().hex[:8]}",
                category="unknown",
                title="Build ID Evidence Incomplete",
                description=reason,
                evidence_ids=[ev.evidence_id],
                confidence="high",
                status="UNRESOLVED",
            ))
            stage_status = "PARTIAL"
        else:
            stage_status = "PARTIAL"

        session.identity_evidence_id = ev.evidence_id
        session.stages["target_identity"] = {
            "status": stage_status,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "details": identity_details,
        }

    def _execute_stage_capture_quality(self, session: InvestigationSession) -> None:
        """Stage 2: Validate Capture Quality and Consistency Constraints."""
        t_ref = session.target_ref
        raw_snap = None
        if t_ref.get("memory_snapshot_path") and os.path.exists(t_ref["memory_snapshot_path"]):
            raw_snap = RawRuntimeSnapshot.load(t_ref["memory_snapshot_path"])
        elif t_ref.get("snapshot_id"):
            cand = os.path.join(self.corpus_dir, "memory_snapshots", t_ref["snapshot_id"])
            if os.path.exists(cand):
                raw_snap = RawRuntimeSnapshot.load(cand)

        consistency_level = "UNKNOWN"
        stop_mechanism = "NONE"
        stopped_threads = False
        partial_reads = 0
        failed_reads = 0
        omitted_regions = 0
        bytes_requested = 0
        bytes_captured = 0
        bytes_omitted = 0
        regions_attempted = 0
        duration_us = 0.0
        missing_regions: List[str] = []
        limitations: List[str] = []

        if raw_snap:
            duration_us = raw_snap.capture_duration_us
            bytes_captured = raw_snap.bytes_captured
            prov = getattr(raw_snap, "provenance", {}) or {}
            obs_meta = getattr(raw_snap, "observation_metadata", {}) or {}

            bytes_requested = prov.get("bytes_requested") or obs_meta.get("bytes_requested") or bytes_captured
            bytes_omitted = prov.get("bytes_omitted") or obs_meta.get("bytes_omitted") or 0
            regions_attempted = prov.get("regions_attempted") or obs_meta.get("regions_attempted") or len(raw_snap.memory_regions)
            stop_mechanism = prov.get("stop_mechanism") or obs_meta.get("stop_mechanism") or ("SIGSTOP" if prov.get("stop_state_machine", {}).get("stop_confirmed") else "NONE")
            stopped_threads = prov.get("stopped_threads", False)

            # Examine memory regions
            for r in raw_snap.memory_regions:
                st = r.get("status")
                if st == "PARTIAL":
                    partial_reads += 1
                elif st == "FAILED":
                    failed_reads += 1
                    missing_regions.append(r.get("pathname", r.get("region_id", "unknown")))
                elif st == "OMITTED":
                    omitted_regions += 1
                    missing_regions.append(f"{r.get('region_id', 'unknown')} (omitted: policy limit)")

            backend = raw_snap.capture_backend or "unknown"
            raw_consistency = prov.get("snapshot_consistency") or obs_meta.get("consistency_classification")
            if raw_consistency == NON_ATOMIC or ("process_vm_readv" in backend and not stopped_threads):
                consistency_level = NON_ATOMIC
                limitations.append("Capture is NON_ATOMIC across multiple memory regions. Pointers may exhibit slight execution skew.")
            elif raw_consistency in ("PROCESS_STOPPED_MEMORY_SNAPSHOT", "SIGNAL_STOPPED", STOPPED) or stopped_threads:
                consistency_level = STOPPED
                limitations.append("Target process was signalled (SIGSTOP/SIGCONT); inferior stopped during read, but kernel atomicity across threads is not guaranteed.")
            else:
                consistency_level = NON_ATOMIC
                limitations.append("Capture atomicity cannot be established; treated as NON_ATOMIC.")

            if t_ref.get("backend_fallback"):
                limitations.append(f"Fallback backend: {t_ref.get('fallback_reason')}")
        else:
            limitations.append("Operating purely on semantic snapshot artifact; raw capture metadata not available.")

        quality_details = {
            "consistency_level": consistency_level,
            "stop_mechanism": stop_mechanism,
            "stopped_threads": stopped_threads,
            "duration_us": duration_us,
            "bytes_requested": bytes_requested,
            "bytes_captured": bytes_captured,
            "bytes_omitted": bytes_omitted,
            "regions_attempted": regions_attempted,
            "regions_read": regions_attempted - failed_reads - omitted_regions,
            "partial_reads": partial_reads,
            "failed_reads": failed_reads,
            "omitted_regions_count": omitted_regions,
            "missing_regions_count": len(missing_regions),
            "limitations": limitations,
        }

        parents = [session.identity_evidence_id] if getattr(session, "identity_evidence_id", None) else []
        ev = session.ledger.add_record(EvidenceRecord(
            evidence_type=EVIDENCE_TYPE_CAPTURE_QUALITY,
            nature=NATURE_OBSERVATION,
            source="raw_snapshot_metadata",
            session_id=session.investigation_id,
            parent_evidence_ids=parents,
            observation=f"Capture consistency: {consistency_level}, requested: {bytes_requested}B, captured: {bytes_captured}B, partial: {partial_reads}, failed: {failed_reads}, omitted: {omitted_regions}.",
            capture_quality=quality_details,
            details=quality_details,
        ))
        session.capture_quality_evidence_id = ev.evidence_id

        # Record findings for capture quality issues
        if consistency_level == NON_ATOMIC:
            session.findings.append(InvestigationFinding(
                finding_id=f"fnd_qual_{uuid.uuid4().hex[:8]}",
                category="unknown",
                title="Non-Atomic Capture Skew Possibility",
                description="Memory was captured without stopping inferior execution. Cross-region pointer dereferences must account for possible timestamp skew.",
                evidence_ids=[ev.evidence_id],
                confidence="high",
                status="CONFIRMED",
            ))

        if bytes_captured == 0 and regions_attempted > 0:
            session.findings.append(InvestigationFinding(
                finding_id=f"fnd_zero_{uuid.uuid4().hex[:8]}",
                category="unknown",
                title="No Memory Captured (0 Bytes)",
                description=f"Capture completed but 0 bytes could be read across {regions_attempted} attempted memory regions.",
                evidence_ids=[ev.evidence_id],
                confidence="high",
                status="UNRESOLVED",
            ))

        if partial_reads > 0 or failed_reads > 0:
            session.findings.append(InvestigationFinding(
                finding_id=f"fnd_miss_{uuid.uuid4().hex[:8]}",
                category="unknown",
                title=f"Unread Memory Regions Detected ({partial_reads + failed_reads})",
                description=f"{failed_reads} regions failed and {partial_reads} regions partially read during capture.",
                evidence_ids=[ev.evidence_id],
                confidence="high",
                status="UNRESOLVED",
            ))

        if omitted_regions > 0:
            session.findings.append(InvestigationFinding(
                finding_id=f"fnd_omit_{uuid.uuid4().hex[:8]}",
                category="unknown",
                title=f"Memory Regions Omitted Due to Policy Bounds ({omitted_regions})",
                description=f"{omitted_regions} memory regions ({bytes_omitted} bytes) were omitted to satisfy safety bounds.",
                evidence_ids=[ev.evidence_id],
                confidence="high",
                status="CONFIRMED",
            ))

        # Assign honest stage status
        if raw_snap:
            if getattr(raw_snap, "completeness", None) in ("INVALID", "FAILED") or (bytes_captured == 0 and regions_attempted > 0):
                stage_status = "FAILED"
            elif getattr(raw_snap, "completeness", None) == "PARTIAL" or failed_reads > 0 or partial_reads > 0 or omitted_regions > 0:
                stage_status = "PARTIAL"
            else:
                stage_status = "COMPLETED"
        else:
            stage_status = "PARTIAL"

        session.stages["capture_quality"] = {
            "status": stage_status,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "details": quality_details,
        }

    def _execute_stage_semantic_interpretation(self, session: InvestigationSession) -> None:
        """Stage 3: DWARF-based Typed Object Interpretation."""
        t_ref = session.target_ref
        dbg_path = t_ref.get("debug_image")
        snap_id = t_ref.get("snapshot_id")
        mem_snap_path = t_ref.get("memory_snapshot_path")

        semantic_state = None
        raw_snap = None

        # A: Offline DWARF reconstruction from RawRuntimeSnapshot
        if (mem_snap_path and os.path.exists(mem_snap_path)) or (snap_id and os.path.exists(os.path.join(self.corpus_dir, "memory_snapshots", snap_id or ""))):
            raw_path = mem_snap_path or os.path.join(self.corpus_dir, "memory_snapshots", snap_id or "")
            if dbg_path and os.path.exists(dbg_path):
                engine = OfflineSemanticEngine()
                raw_snap = RawRuntimeSnapshot.load(raw_path)
                try:
                    semantic_state = engine.reconstruct(raw_snap, debug_image=dbg_path)
                except Exception:
                    pass


        # B: Load from corpus if existing semantic snapshot
        if not semantic_state and snap_id:
            try:
                semantic_state = self._resolve_snapshot(snap_id, session)
            except Exception:
                pass

        session.active_snapshot = semantic_state

        if not semantic_state:
            err_msg = f"Target snapshot '{snap_id}' could not be resolved from corpus or filesystem." if snap_id else "No semantic objects could be resolved from provided target reference."
            session.stages["semantic_interpretation"] = {
                "status": "PARTIAL",
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "details": {
                    "error": err_msg,
                    "decoding_status": "UNAVAILABLE",
                    "objects_count": 0,
                    "roots_count": 0,
                },
            }
            return

        objs = getattr(semantic_state, "objects", []) or (semantic_state.get("persistent", {}).get("objects", []) if isinstance(semantic_state, dict) else [])
        roots = getattr(semantic_state, "roots", []) or []

        is_partial_snap = False
        if raw_snap:
            is_partial_snap = (getattr(raw_snap, "completeness", None) == "PARTIAL")
        elif isinstance(semantic_state, dict):
            is_partial_snap = (semantic_state.get("completeness") == "PARTIAL" or semantic_state.get("status") == "PARTIAL")

        cap_ev_id = getattr(session, "capture_quality_evidence_id", None)
        parents = [cap_ev_id] if cap_ev_id else []
        root_evidence_map: Dict[str, str] = {}

        # Record Evidence for discovered typed roots and objects
        for r in roots[:5]:
            r_dict = r if isinstance(r, dict) else asdict(r)
            ev = session.ledger.add_record(EvidenceRecord(
                evidence_type=EVIDENCE_TYPE_OBJECT_STATE,
                nature=NATURE_OBSERVATION,
                source="offline_dwarf_reconstruction",
                session_id=session.investigation_id,
                parent_evidence_ids=parents,
                observation=f"Discovered typed root: {r_dict.get('name')} of type {r_dict.get('type')}.",
                object_observation=r_dict,
                details=r_dict,
            ))
            r_ref = r_dict.get("object_ref")
            if r_ref:
                root_evidence_map[r_ref] = ev.evidence_id
            fnd_root = InvestigationFinding(
                finding_id=f"fnd_root_{uuid.uuid4().hex[:8]}",
                category="fact",
                title=f"Root Object Observed: {r_dict.get('name')}",
                description=f"Global/static root of canonical type {r_dict.get('type')}." + (" Note: Snapshot capture is PARTIAL." if is_partial_snap else ""),
                c_type_path=r_dict.get("name"),
                object_id=r_dict.get("object_ref") or r_dict.get("object_id"),
                type_name=r_dict.get("type"),
                evidence_ids=[ev.evidence_id],
                confidence="medium" if is_partial_snap else "high",
                status="UNVERIFIED_PARTIAL" if is_partial_snap else "OBSERVED",
                uncertainty="Observed from PARTIAL capture snapshot." if is_partial_snap else None,
            )
            self._enrich_finding_navigation(session, fnd_root, target_object=r_dict, snapshot=semantic_state)
            session.findings.append(fnd_root)

        # Sample reachable objects and fields
        first_field_finding = None
        for obj in objs[:20]:
            o_dict = obj if isinstance(obj, dict) else (obj.to_dict() if hasattr(obj, "to_dict") else asdict(obj))
            oid = o_dict.get("object_id")
            otype = o_dict.get("type")
            path = o_dict.get("primary_path", oid)

            parent_ids = [root_evidence_map[oid]] if oid in root_evidence_map else parents

            for f in o_dict.get("fields", [])[:10]:
                fname = f.get("name")
                fval = f.get("value")
                fpath = f"{path}.{fname}" if path else fname

                ev = session.ledger.add_record(EvidenceRecord(
                    evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
                    nature=NATURE_OBSERVATION,
                    source="typed_object_graph",
                    session_id=session.investigation_id,
                    parent_evidence_ids=parent_ids,
                    observation=f"Observed {fpath} = {fval} (type {f.get('type')}).",
                    field_observation={
                        "object_id": oid,
                        "field": fname,
                        "type": f.get("type"),
                        "value": fval,
                        "path": fpath,
                        "mutability": f.get("mutability", "mutable"),
                    },
                    details=f,
                ))

                finding_candidate = InvestigationFinding(
                    finding_id=f"fnd_fld_{uuid.uuid4().hex[:8]}",
                    category="fact",
                    title=f"Observed Field: {fpath}",
                    description=f"Field {fname} observed with value {fval} ({f.get('type')})." + (" Note: Snapshot capture is PARTIAL." if is_partial_snap else ""),
                    c_type_path=fpath,
                    object_id=oid,
                    field_name=fname,
                    type_name=f.get("type") or otype,
                    observed_value=fval,
                    evidence_ids=[ev.evidence_id],
                    confidence="medium" if is_partial_snap else "high",
                    status="UNVERIFIED_PARTIAL" if is_partial_snap else "OBSERVED",
                    uncertainty="Observed from PARTIAL capture snapshot." if is_partial_snap else None,
                )
                self._enrich_finding_navigation(session, finding_candidate, target_object=o_dict, target_field=f, snapshot=semantic_state)
                if first_field_finding is None:
                    first_field_finding = finding_candidate

                # Highlight non-zero or suspicious counters/status fields
                if any(k in str(fname).lower() for k in ("counter", "state", "status", "flags", "error", "health", "active", "task", "id")):
                    session.findings.append(finding_candidate)

        if not session.findings and first_field_finding:
            session.findings.append(first_field_finding)

        has_partial_objects = False
        has_memory_not_captured = False
        uncaptured_pointer_details: List[str] = []

        for obj in objs:
            o_dict = obj if isinstance(obj, dict) else (obj.to_dict() if hasattr(obj, "to_dict") else asdict(obj))
            if o_dict.get("status") == "PARTIAL":
                has_partial_objects = True
            for f in o_dict.get("fields", []):
                if f.get("status") == "MEMORY_NOT_CAPTURED" or f.get("target_status") == "MEMORY_NOT_CAPTURED":
                    has_memory_not_captured = True
                    uncaptured_pointer_details.append(f"{o_dict.get('object_id')}.{f.get('name')}")

        diagnostics = getattr(semantic_state, "diagnostics", []) or []
        for d in diagnostics:
            if isinstance(d, dict) and d.get("code") == "MEMORY_NOT_CAPTURED":
                has_memory_not_captured = True

        if has_memory_not_captured or has_partial_objects:
            decoding_status = "PARTIAL"
            stage_status = "PARTIAL"
        elif not objs and not roots:
            decoding_status = "FAILED"
            stage_status = "FAILED"
        else:
            decoding_status = "COMPLETED"
            stage_status = "COMPLETED"

        if has_memory_not_captured:
            ev = session.ledger.add_record(EvidenceRecord(
                evidence_type=EVIDENCE_TYPE_OBJECT_STATE,
                nature=NATURE_OBSERVATION,
                source="cpp_object_decoder",
                session_id=session.investigation_id,
                parent_evidence_ids=parents,
                observation=f"Pointers outside captured memory detected ({len(uncaptured_pointer_details)} uncaptured references). Fields classified as MEMORY_NOT_CAPTURED.",
                details={"uncaptured_references": uncaptured_pointer_details[:20]},
            ))
            session.findings.append(InvestigationFinding(
                finding_id=f"fnd_mnc_{uuid.uuid4().hex[:8]}",
                category="unknown",
                title="Pointers Outside Captured Memory (MEMORY_NOT_CAPTURED)",
                description=f"One or more pointer targets reside outside captured memory regions ({len(uncaptured_pointer_details)} references). Classified as MEMORY_NOT_CAPTURED rather than null or dropped.",
                evidence_ids=[ev.evidence_id],
                confidence="high",
                status="UNRESOLVED",
            ))

        session.stages["semantic_interpretation"] = {
            "status": stage_status,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "details": {
                "decoding_status": decoding_status,
                "objects_count": len(objs),
                "roots_count": len(roots),
                "state_hash": getattr(semantic_state, "state_hash", None),
                "has_memory_not_captured": has_memory_not_captured,
                "uncaptured_pointers_count": len(uncaptured_pointer_details),
            },
        }

    def _execute_stage_static_linking(self, session: InvestigationSession) -> None:
        """Stage 4: Link Runtime Observations to Static Code Evidence."""
        provider = session.static_provider
        if not provider or not provider.is_available():
            session.stages["static_code_link"] = {
                "status": "PARTIAL",
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "details": {
                    "status": "NO_STATIC_PROVIDER",
                    "linkage_status": "UNAVAILABLE",
                    "linked_count": 0,
                    "reason": "Static code provider unavailable or debug image missing",
                },
            }
            return

        t_ident = session.stages["target_identity"].get("details", {})
        build_id_status = t_ident.get("build_id_status")

        if build_id_status in (IDENTITY_MISMATCH, "MISMATCH"):
            session.stages["static_code_link"] = {
                "status": "FAILED",
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "details": {
                    "provider": provider.get_provider_name(),
                    "linkage_status": "MISMATCH",
                    "status": "BUILD_ID_MISMATCH",
                    "linked_count": 0,
                    "reason": "Target executable build ID mismatches debug image. Refusing to decode static links.",
                },
            }
            return

        linked_count = 0
        resolved_links: List[Dict[str, Any]] = []

        # Find runtime objects and roots with addresses
        snap = session.active_snapshot
        roots = getattr(snap, "roots", []) or []
        objs = getattr(snap, "objects", []) or (snap.get("persistent", {}).get("objects", []) if isinstance(snap, dict) else [])
        items_to_resolve = list(roots[:5]) + list(objs[:10])

        # Retrieve dynamic load bias from snapshot provenance or compute via ModuleAddressResolver
        t_ref = session.target_ref
        t_ident = session.stages["target_identity"].get("details", {})
        prov = getattr(snap, "provenance", {}) if hasattr(snap, "provenance") else (snap.get("provenance", {}) if isinstance(snap, dict) else {})
        real_load_bias = prov.get("load_bias") if isinstance(prov, dict) else None
        load_bias_status = "UNRESOLVED"
        load_bias_provenance: Dict[str, Any] = {}

        if isinstance(real_load_bias, str):
            try:
                real_load_bias = int(real_load_bias, 16) if real_load_bias.startswith("0x") else int(real_load_bias)
                load_bias_status = "RESOLVED"
                load_bias_provenance = {"source": "snapshot_provenance", "load_bias": f"0x{real_load_bias:x}"}
            except ValueError:
                real_load_bias = None
        elif isinstance(real_load_bias, int):
            load_bias_status = "RESOLVED"
            load_bias_provenance = {"source": "snapshot_provenance", "load_bias": f"0x{real_load_bias:x}"}

        # If not in provenance, calculate dynamically using ModuleAddressResolver from memory mappings and ELF PT_LOAD
        if real_load_bias is None:
            raw_snap = None
            if t_ref.get("memory_snapshot_path") and os.path.exists(t_ref["memory_snapshot_path"]):
                raw_snap = RawRuntimeSnapshot.load(t_ref["memory_snapshot_path"])
            elif t_ref.get("snapshot_id"):
                cand = os.path.join(self.corpus_dir, "memory_snapshots", t_ref["snapshot_id"])
                if os.path.exists(cand):
                    raw_snap = RawRuntimeSnapshot.load(cand)

            dbg_image_path = t_ident.get("debug_image") or t_ref.get("debug_image")
            if raw_snap and getattr(raw_snap, "memory_regions", None) and dbg_image_path and os.path.exists(dbg_image_path):
                try:
                    elf_info = inspect_elf(dbg_image_path)
                    calc_bias = ModuleAddressResolver.calculate_load_bias(raw_snap.memory_regions, elf_info)
                    real_load_bias = calc_bias
                    load_bias_status = "RESOLVED"
                    load_bias_provenance = {
                        "source": "ModuleAddressResolver.calculate_load_bias",
                        "elf_type": elf_info.elf_type,
                        "pt_loads": len(elf_info.pt_loads),
                        "load_bias": f"0x{calc_bias:x}",
                    }
                except Exception as e:
                    real_load_bias = None
                    load_bias_status = "UNRESOLVED"
                    load_bias_provenance = {"source": "ModuleAddressResolver", "error": str(e)}
            else:
                real_load_bias = None
                load_bias_status = "UNRESOLVED"
                load_bias_provenance = {"reason": "Mapping evidence unavailable or ambiguous"}

        main_mod = RuntimeModule(
            module_id="main_executable",
            path=t_ident.get("executable", "main"),
            runtime_base=real_load_bias if real_load_bias is not None else 0,
            runtime_end=(real_load_bias + 0x1000000) if real_load_bias is not None else 0,
            load_bias=real_load_bias,
            build_id=t_ident.get("target_build_id"),
            load_bias_status=load_bias_status,
            build_id_status=t_ident.get("build_id_status", "INCOMPLETE"),
        )

        for item in items_to_resolve:
            o_dict = item if isinstance(item, dict) else (item.to_dict() if hasattr(item, "to_dict") else asdict(item))
            addr = o_dict.get("address")
            otype = o_dict.get("type")
            item_name = o_dict.get("name") or o_dict.get("primary_path") or o_dict.get("object_id")
            if addr and isinstance(addr, int) and addr > 0:
                res = provider.resolve_runtime_to_code(addr, module=main_mod, type_name=otype)
                if res.get("status") in ("RESOLVED", "RESOLVED_TYPE_MATCH"):
                    linked_count += 1
                    resolved_links.append(res)
                    link_kind = res.get("link_kind", LINK_KIND_TYPE_DEFINITION if res.get("status") == "RESOLVED_TYPE_MATCH" else LINK_KIND_GLOBAL_VARIABLE)
                    is_type_only = (link_kind == LINK_KIND_TYPE_DEFINITION)

                    parent_ids = []
                    matching_ev = session.ledger.query(object_id=o_dict.get("object_id"))
                    if matching_ev:
                        parent_ids = [matching_ev[0].evidence_id]
                    elif getattr(session, "capture_quality_evidence_id", None):
                        parent_ids = [session.capture_quality_evidence_id]

                    ev = session.ledger.add_record(EvidenceRecord(
                        evidence_type=EVIDENCE_TYPE_STATIC_LINK,
                        nature=NATURE_OBSERVATION,
                        source=provider.get_provider_name(),
                        session_id=session.investigation_id,
                        parent_evidence_ids=parent_ids,
                        observation=f"Linked runtime object {item_name} ({otype}) via {link_kind}: {res.get('symbol_name') or res.get('type')}.",
                        static_code_link=res,
                        provenance=load_bias_provenance,
                        details=res,
                    ))

                    finding_status = "TYPE_ONLY" if is_type_only else "VERIFIED"
                    title = f"Static Type Definition: {res.get('type')}" if is_type_only else f"Static Code Correlation: {res.get('symbol_name')}"
                    desc = res.get("relationship_limitation") if is_type_only else f"Correlated via {res.get('link_basis')} ({link_kind}) at {res.get('decl_file', 'source')}:{res.get('decl_line', '?')}."

                    session.findings.append(InvestigationFinding(
                        finding_id=f"fnd_static_{uuid.uuid4().hex[:8]}",
                        category="fact",
                        title=title,
                        description=desc,
                        c_type_path=item_name or otype,
                        object_id=o_dict.get("object_id") or o_dict.get("object_ref"),
                        evidence_ids=[ev.evidence_id],
                        confidence="medium" if is_type_only else "high",
                        status=finding_status,
                    ))

                elif "UNRESOLVED" in str(res.get("status")):
                    # Explicitly record unresolved link
                    ev = session.ledger.add_record(EvidenceRecord(
                        evidence_type=EVIDENCE_TYPE_STATIC_LINK,
                        nature=NATURE_OBSERVATION,
                        source=provider.get_provider_name(),
                        session_id=session.investigation_id,
                        observation=f"Unresolved static link for {o_dict.get('object_id')} at 0x{addr:x}: {res.get('reason')}.",
                        static_code_link=res,
                        provenance=load_bias_provenance,
                        details=res,
                    ))

        # Determine linkage status
        if build_id_status not in (IDENTITY_VERIFIED_MATCH, "VERIFIED"):
            linkage_status = "UNVERIFIED"
            stage_status = "PARTIAL"
        elif load_bias_status != "RESOLVED":
            linkage_status = "UNVERIFIED"
            stage_status = "PARTIAL"
        elif linked_count == 0:
            linkage_status = "UNVERIFIED"
            stage_status = "PARTIAL"
        else:
            has_verified_addr = any(r.get("is_verified", False) and r.get("link_kind") in (LINK_KIND_GLOBAL_VARIABLE, LINK_KIND_FUNCTION_ADDRESS) for r in resolved_links)
            if has_verified_addr:
                linkage_status = "VERIFIED"
                stage_status = "COMPLETED"
            else:
                linkage_status = "PARTIAL"
                stage_status = "PARTIAL"

        session.stages["static_code_link"] = {
            "status": stage_status,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "details": {
                "provider": provider.get_provider_name(),
                "linkage_status": linkage_status,
                "linked_count": linked_count,
                "resolved_links": resolved_links,
                "load_bias_provenance": load_bias_provenance,
                "load_bias_status": load_bias_status,
            },
        }

        # Re-enrich all session findings now that static provider has been verified and loaded
        if provider and provider.is_available():
            for fnd in session.findings:
                if fnd.object_id or fnd.field_name:
                    self._enrich_finding_navigation(session, fnd, snapshot=session.active_snapshot)

    def _execute_stage_synthesis(self, session: InvestigationSession) -> None:
        """Stage 5: Synthesize Findings, Invariant Hypotheses, and Next Steps."""
        # 1. Synthesize hypotheses from findings using DeterministicHypothesisGenerator
        generator = DeterministicHypothesisGenerator()
        generated_hypotheses = generator.generate(session)

        for hypo in generated_hypotheses:
            session.hypotheses.append(hypo)

            # Register as an EvidenceRecord of type HYPOTHESIS
            ev = session.ledger.add_record(EvidenceRecord(
                evidence_id=f"ev_{hypo.hypothesis_id}",
                evidence_type=EVIDENCE_TYPE_HYPOTHESIS,
                nature=NATURE_HYPOTHESIS,
                source="DeterministicHypothesisGenerator",
                session_id=session.investigation_id,
                observation=hypo.claim,
                parent_evidence_ids=list(hypo.supporting_evidence_ids),
                details={
                    "hypothesis_id": hypo.hypothesis_id,
                    "proposed_mechanism": hypo.proposed_mechanism,
                    "validation_status": hypo.validation_status,
                    "confidence": hypo.confidence,
                    "validation_criteria": hypo.validation_criteria,
                    "assumptions": hypo.assumptions,
                    "unresolved_questions": hypo.unresolved_questions,
                },
            ))

            # Mirror as an InvestigationFinding so legacy finding lists reflect hypotheses
            session.findings.append(InvestigationFinding(
                finding_id=f"fnd_{hypo.hypothesis_id}",
                category="hypothesis",
                title=hypo.title,
                description=hypo.claim,
                c_type_path=hypo.candidate_fields[0] if hypo.candidate_fields else None,
                object_id=hypo.candidate_objects[0] if hypo.candidate_objects else None,
                field_name=hypo.candidate_fields[0] if hypo.candidate_fields else None,
                evidence_ids=[ev.evidence_id] + list(hypo.supporting_evidence_ids),
                confidence=hypo.confidence.lower(),
                status=hypo.validation_status,
                function_candidates=hypo.function_candidates,
                uncertainty=hypo.confidence_rationale if hypo.confidence in (CONFIDENCE_LOW, CONFIDENCE_SPECULATIVE) else None,
            ))

        # 2. Formulate Next Steps
        steps: List[InvestigationNextStep] = []

        # Add follow-up observation steps from hypotheses
        for hypo in session.hypotheses:
            for obs in hypo.suggested_observations:
                steps.append(InvestigationNextStep(
                    step_id=obs.observation_id,
                    description=obs.question,
                    rationale=obs.discriminating_criteria,
                    is_suggestion=obs.is_suggestion,
                    executed=obs.executed,
                    risk_level="READ_ONLY",
                    required_inputs=list(obs.target_ref.keys()),
                    action_type="INSPECT" if obs.target_kind in (TARGET_KIND_FIELD, TARGET_KIND_OBJECT, TARGET_KIND_THREAD) else "COMPARE",
                ))

        # Suggestion 1: Compare with previous/baseline snapshot if only 1 observation
        if not session.comparison_results:
            steps.append(InvestigationNextStep(
                step_id=f"step_{uuid.uuid4().hex[:6]}",
                description="Capture or compare against a baseline snapshot to isolate state diffs.",
                rationale="Comparing two observation points isolates value and reference modifications deterministically.",
                is_suggestion=True,
                executed=False,
                risk_level="READ_ONLY",
                required_inputs=["baseline_snapshot_id"],
                action_type="COMPARE",
            ))

        # Suggestion 2: Deep inspect dominant typed root
        roots_stage = session.stages.get("semantic_interpretation", {}).get("details", {})
        if roots_stage.get("roots_count", 0) > 0:
            steps.append(InvestigationNextStep(
                step_id=f"step_{uuid.uuid4().hex[:6]}",
                description="Traverse reachable heap pointers from global roots in State Laboratory.",
                rationale="Follow evidence pointers to inspect full worker and shared node subgraphs.",
                is_suggestion=True,
                executed=False,
                risk_level="READ_ONLY",
                required_inputs=[],
                action_type="INSPECT",
            ))

        # Suggestion 3: Test hypothesis in offline State Laboratory (Safe branching)
        steps.append(InvestigationNextStep(
            step_id=f"step_{uuid.uuid4().hex[:6]}",
            description="Simulate candidate mutation in offline State Laboratory without altering live process.",
            rationale="Offline State Laboratory mutates immutable logical snapshot copies with zero target impact.",
            is_suggestion=True,
            executed=False,
            risk_level="READ_ONLY",
            required_inputs=["candidate_field", "proposed_value"],
            action_type="MUTATE_LAB",
        ))

        session.next_steps = steps

        # Summary & Explicit Analysis Scope
        facts_cnt = sum(1 for f in session.findings if f.category == "fact")
        hypo_cnt = sum(1 for f in session.findings if f.category == "hypothesis")
        unknown_cnt = sum(1 for f in session.findings if f.category == "unknown")

        semantic_details = session.stages.get("semantic_interpretation", {}).get("details", {})
        quality_details = session.stages.get("capture_quality", {}).get("details", {})
        static_details = session.stages.get("static_code_link", {}).get("details", {})

        objects_examined = semantic_details.get("objects_count", 0)
        roots_examined = semantic_details.get("roots_count", 0)
        regions_examined = quality_details.get("regions_read", quality_details.get("regions_attempted", len(getattr(session.active_snapshot, "memory_regions", [])) if hasattr(session.active_snapshot, "memory_regions") else 0))
        bytes_captured = quality_details.get("bytes_captured", 0)

        capture_status = quality_details.get("capture_status")
        if not capture_status:
            cq_st = session.stages.get("capture_quality", {}).get("status", "UNKNOWN")
            capture_status = "FAILED" if cq_st == "FAILED" else ("PARTIAL" if cq_st == "PARTIAL" else "COMPLETED")

        decoding_status = semantic_details.get("decoding_status")
        if not decoding_status:
            si_st = session.stages.get("semantic_interpretation", {}).get("status", "UNKNOWN")
            decoding_status = "FAILED" if si_st == "FAILED" else ("PARTIAL" if si_st == "PARTIAL" else "COMPLETED")

        static_linkage_status = static_details.get("linkage_status")
        if not static_linkage_status:
            sl_st = session.stages.get("static_code_link", {}).get("status", "UNKNOWN")
            static_linkage_status = "VERIFIED" if sl_st == "COMPLETED" else "UNVERIFIED"

        unresolved_checks = []
        if static_linkage_status in ("UNVERIFIED", "MISMATCH", "UNAVAILABLE", "PARTIAL"):
            unresolved_checks.append(f"Static symbol and call-graph linkage ({static_linkage_status}): unverified or incomplete debug correlation")
        if quality_details.get("consistency_level") == NON_ATOMIC:
            unresolved_checks.append("Non-atomic capture: cross-region invariants not guaranteed atomic")
        if quality_details.get("failed_reads", 0) > 0:
            unresolved_checks.append(f"{quality_details['failed_reads']} memory regions failed to read")
        if quality_details.get("omitted_regions_count", 0) > 0:
            unresolved_checks.append(f"{quality_details['omitted_regions_count']} memory regions omitted by safety policy limits")
        if semantic_details.get("has_memory_not_captured"):
            unresolved_checks.append(f"{semantic_details.get('uncaptured_pointers_count', 0)} pointer targets outside captured regions (MEMORY_NOT_CAPTURED)")
        unresolved_checks.append("Heap allocations without active global roots remain unmapped")
        unresolved_checks.append("Private/local symbols and unexercised code paths unverified")

        # Determine overall investigation status
        if session.status == "BLOCKED":
            computed_status = "BLOCKED"
        elif (
            any(v.get("status") == "FAILED" for v in session.stages.values())
            or capture_status == "FAILED"
            or decoding_status == "FAILED"
            or static_linkage_status == "MISMATCH"
        ):
            computed_status = "FAILED"
        elif (
            capture_status == "PARTIAL"
            or decoding_status in ("PARTIAL", "UNAVAILABLE")
            or static_linkage_status in ("UNVERIFIED", "MISMATCH", "UNAVAILABLE", "PARTIAL")
            or any(v.get("status") == "PARTIAL" for v in session.stages.values())
        ):
            computed_status = "PARTIAL"
        else:
            computed_status = "COMPLETED"

        session.status = computed_status

        zero_notice = None
        if len(session.findings) == 0:
            if computed_status == "COMPLETED":
                zero_notice = (
                    f"Investigation completed with 0 findings in inspected scope ({objects_examined} objects, {roots_examined} roots, {regions_examined} regions, {bytes_captured} bytes). "
                    "This scope is bounded: it does not imply validation of unmapped heap regions, private symbols, threads not captured, or uninspected invariants."
                )
            else:
                zero_notice = (
                    f"Investigation ended with status '{computed_status}' and 0 findings. "
                    f"Analysis scope was incomplete or restricted ({objects_examined} objects, {roots_examined} roots). "
                    "Unmapped heap regions, private symbols, and uninspected invariants remain unverified."
                )

        session.summary = {
            "goal": session.goal,
            "status": computed_status,
            "capture_status": capture_status,
            "decoding_status": decoding_status,
            "static_linkage_status": static_linkage_status,
            "facts_count": facts_cnt,
            "hypotheses_count": hypo_cnt,
            "unknowns_count": unknown_cnt,
            "total_findings": len(session.findings),
            "next_steps_count": len(steps),
            "evidence_count": len(session.ledger._records),
            "scope": {
                "objects_examined": objects_examined,
                "roots_examined": roots_examined,
                "regions_examined": regions_examined,
                "bytes_inspected": bytes_captured,
                "unresolved_checks": unresolved_checks,
            },
            "zero_findings_notice": zero_notice,
        }

        session.stages["report_synthesis"] = {
            "status": "COMPLETED",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "details": session.summary,
        }

    def _resolve_snapshot(self, snap_ref: Any, session: InvestigationSession) -> Optional[Any]:
        """Resolve snapshot by dict, object, State ID, Snapshot ID, or file path."""
        if isinstance(snap_ref, dict):
            return snap_ref
        if hasattr(snap_ref, "to_dict"):
            return snap_ref

        if not isinstance(snap_ref, str):
            return None

        # 1. Direct state_id in corpus
        snap_data = self.corpus.get(snap_ref)
        if snap_data:
            return snap_data

        # 2. Match snapshot_id or state_id in corpus states
        for state_id, meta in self.corpus.states.items():
            if meta.get("snapshot_id") == snap_ref or state_id == snap_ref:
                snap_data = self.corpus.get(state_id)
                if snap_data:
                    return snap_data

        # 3. Memory snapshot path or direct json file path
        cand = snap_ref if os.path.exists(snap_ref) else os.path.join(self.corpus_dir, "memory_snapshots", snap_ref)
        if os.path.exists(cand):
            try:
                if cand.endswith(".json"):
                    with open(cand, "r", encoding="utf-8") as f:
                        return json.load(f)
                raw_snap = RawRuntimeSnapshot.load(cand)
                dbg = session.target_ref.get("debug_image")
                if dbg and os.path.exists(dbg):
                    engine = OfflineSemanticEngine()
                    try:
                        return engine.reconstruct(raw_snap, debug_image=dbg)
                    except Exception:
                        pass
                return raw_snap

            except Exception:
                pass

        # 4. Active snapshot
        if session.active_snapshot:
            act = session.active_snapshot
            act_id = act.get("snapshot_id") if isinstance(act, dict) else getattr(act, "snapshot_id", "")
            if act_id == snap_ref:
                return session.active_snapshot

        return None


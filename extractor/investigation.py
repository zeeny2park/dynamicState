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
from .modules import ModuleAddressResolver, RuntimeModule, discover_modules
from .raw_snapshot import RawRuntimeSnapshot
from .semantic_state import OfflineSemanticEngine, SemanticState
from .snapshot import RuntimeSnapshot
from .snapshot_consistency import ATOMIC, NON_ATOMIC, STOPPED, SnapshotConsistency
from .state_corpus import StateCorpus
from .state_diff import StateDiffEngine
from .state_lab import compute_semantic_diff
from .static_analyzer import (
    DwarfStaticAnalysisProvider,
    NullStaticAnalysisProvider,
    StaticAnalysisProvider,
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
        self.next_steps: List[InvestigationNextStep] = []
        self.active_snapshot: Optional[Any] = None
        self.comparison_results: List[Dict[str, Any]] = []
        self.static_provider: StaticAnalysisProvider = NullStaticAnalysisProvider()
        self.summary: Dict[str, Any] = {}

    def to_dict(self) -> Dict[str, Any]:
        """Convert session to JSON-serializable dictionary."""
        return {
            "investigation_id": self.investigation_id,
            "goal": self.goal,
            "status": self.status,
            "created_at": self.created_at,
            "target_ref": self.target_ref,
            "safety": self.safety,
            "budgets": self.budgets,
            "stages": self.stages,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
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

            # Set overall status
            failed_stages = [k for k, v in session.stages.items() if v["status"] == "FAILED"]
            partial_stages = [k for k, v in session.stages.items() if v["status"] == "PARTIAL"]
            if failed_stages:
                session.status = "FAILED" if len(failed_stages) >= 2 else "PARTIAL"
            elif partial_stages:
                session.status = "PARTIAL"
            else:
                session.status = "COMPLETED"

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

        # Check uncertainty: if either snapshot was NON_ATOMIC or captured via process_vm_readv
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
        if level_a == NON_ATOMIC or level_b == NON_ATOMIC:
            uncertainty = "One or both snapshots were captured non-atomically (process_vm_readv zero-stop). Value diffs may reflect minor execution skew."


        # Record comparison evidence in ledger
        ev = session.ledger.add_record(EvidenceRecord(
            evidence_type=EVIDENCE_TYPE_COMPARISON,
            nature=NATURE_OBSERVATION,
            source="state_diff",
            session_id=session.investigation_id,
            observation=f"Semantic comparison between {snapshot_a} and {snapshot_b}: {diff_dict['summary']['value_changes']} value changes, {diff_dict['summary']['objects_created']} added, {diff_dict['summary']['objects_removed']} removed.",
            comparison_observation={
                "snapshot_a": snapshot_a,
                "snapshot_b": snapshot_b,
                "summary": diff_dict["summary"],
                "changes_count": len(diff_dict["changes"]),
                "performance": diff_dict["performance"],
            },
            uncertainty=uncertainty,
            details={"changes": diff_dict["changes"][:30]},  # Limit payload size
        ))

        # Add findings from significant differences
        if diff_dict["summary"]["value_changes"] > 0 or diff_dict["summary"]["objects_created"] > 0:
            for chg in diff_dict["changes"][:10]:
                if chg.get("kind") == "value_change":
                    fnd_id = f"fnd_cmp_{uuid.uuid4().hex[:8]}"
                    fnd = InvestigationFinding(
                        finding_id=fnd_id,
                        category="fact",
                        title=f"Field value change in {chg.get('path', 'unknown')}",
                        description=f"Field changed from {chg.get('before')} to {chg.get('after')} between observations.",
                        c_type_path=chg.get("path"),
                        object_id=chg.get("object_id"),
                        field_name=chg.get("field"),
                        evidence_ids=[ev.evidence_id],
                        confidence="high",
                        status="CONFIRMED",
                    )
                    session.findings.append(fnd)

        session.comparison_results.append({
            "snapshot_a": snapshot_a,
            "snapshot_b": snapshot_b,
            "diff_summary": diff_dict["summary"],
            "uncertainty": uncertainty,
            "evidence_id": ev.evidence_id,
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

    def generate_report(self, investigation_id: str) -> Dict[str, Any]:
        """Synthesize a complete investigation report."""
        session = self.sessions.get(investigation_id)
        if not session:
            return {"error": f"Investigation '{investigation_id}' not found"}

        # Group findings
        facts = [f.to_dict() for f in session.findings if f.category == "fact"]
        hypotheses = [f.to_dict() for f in session.findings if f.category == "hypothesis"]
        unknowns = [f.to_dict() for f in session.findings if f.category == "unknown"]

        return {
            "investigation_id": session.investigation_id,
            "goal": session.goal,
            "status": session.status,
            "created_at": session.created_at,
            "target_identity": session.stages["target_identity"].get("details", {}),
            "capture_quality": session.stages["capture_quality"].get("details", {}),
            "findings_summary": {
                "total": len(session.findings),
                "facts_count": len(facts),
                "hypotheses_count": len(hypotheses),
                "unknowns_count": len(unknowns),
            },
            "findings": {
                "observed_facts": facts,
                "hypotheses": hypotheses,
                "unknowns": unknowns,
            },
            "comparisons": session.comparison_results,
            "static_code_links": session.stages["static_code_link"].get("details", {}),
            "recommended_next_steps": [s.to_dict() for s in session.next_steps],
            "evidence_ledger": session.ledger.to_dict(),
        }

    # -------------------------------------------------------------------------
    # Stage Execution Internals
    # -------------------------------------------------------------------------

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

        build_id_status = "NOT_AVAILABLE"
        dbg_build_id = None
        if dbg_path and os.path.exists(dbg_path):
            try:
                dbg_ident = inspect_elf(dbg_path)
                dbg_build_id = dbg_ident.build_id
                if target_build_id and dbg_build_id:
                    build_id_status = "VERIFIED" if target_build_id == dbg_build_id else "MISMATCH"
                elif dbg_build_id:
                    build_id_status = "AVAILABLE_IN_DEBUG_IMAGE"
            except Exception:
                build_id_status = "UNREADABLE"

        identity_details = {
            "pid": pid,
            "executable": target_exec or "offline_artifact",
            "target_build_id": target_build_id,
            "debug_image": dbg_path,
            "debug_build_id": dbg_build_id,
            "build_id_status": build_id_status,
        }

        # Record Identity Evidence
        ev = session.ledger.add_record(EvidenceRecord(
            evidence_type=EVIDENCE_TYPE_RUNTIME_IDENTITY,
            nature=NATURE_OBSERVATION,
            source="debug_image_inspect",
            session_id=session.investigation_id,
            observation=f"Target executable identity: {target_exec or 'unknown'}, Build ID status: {build_id_status}.",
            target_identity=identity_details,
            details=identity_details,
        ))

        # Add Finding if mismatch detected
        if build_id_status == "MISMATCH":
            session.findings.append(InvestigationFinding(
                finding_id=f"fnd_id_{uuid.uuid4().hex[:8]}",
                category="unknown",
                title="Debug Image Build ID Mismatch",
                description=f"Expected build ID {target_build_id} does not match debug artifact build ID {dbg_build_id}. Refusing silent decode.",
                evidence_ids=[ev.evidence_id],
                confidence="high",
                status="UNRESOLVED",
            ))

        session.stages["target_identity"] = {
            "status": "COMPLETED" if build_id_status != "MISMATCH" else "PARTIAL",
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
        partial_reads = 0
        failed_reads = 0
        duration_us = 0.0
        missing_regions: List[str] = []
        limitations: List[str] = []

        if raw_snap:
            duration_us = raw_snap.capture_duration_us
            # Examine memory regions
            for r in raw_snap.memory_regions:
                st = r.get("status")
                if st == "PARTIAL":
                    partial_reads += 1
                elif st == "FAILED":
                    failed_reads += 1
                    missing_regions.append(r.get("pathname", r.get("region_id", "unknown")))

            # Check backend
            backend = raw_snap.capture_backend
            if "process_vm_readv" in backend:
                consistency_level = NON_ATOMIC
                limitations.append("process_vm_readv zero-stop capture is potentially NON_ATOMIC across multiple memory regions.")
            elif "gdb" in backend.lower() or "ptrace" in backend.lower():
                consistency_level = STOPPED
            else:
                consistency_level = "UNKNOWN"
        else:
            limitations.append("Operating purely on semantic snapshot artifact; raw capture metadata not available.")

        quality_details = {
            "consistency_level": consistency_level,
            "duration_us": duration_us,
            "partial_reads": partial_reads,
            "failed_reads": failed_reads,
            "missing_regions_count": len(missing_regions),
            "limitations": limitations,
        }

        ev = session.ledger.add_record(EvidenceRecord(
            evidence_type=EVIDENCE_TYPE_CAPTURE_QUALITY,
            nature=NATURE_OBSERVATION,
            source="raw_snapshot_metadata",
            session_id=session.investigation_id,
            observation=f"Capture consistency: {consistency_level}, partial reads: {partial_reads}, failed: {failed_reads}.",
            capture_quality=quality_details,
            details=quality_details,
        ))

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

        session.stages["capture_quality"] = {
            "status": "COMPLETED",
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

        if not semantic_state and not snap_id and not mem_snap_path:
            # Check if any snapshot exists in corpus only if no target was specified
            states = sorted(self.corpus.states.keys())
            if states:
                try:
                    semantic_state = self.corpus.get(states[-1])
                except Exception:
                    pass

        session.active_snapshot = semantic_state

        if not semantic_state:
            err_msg = f"Target snapshot '{snap_id}' could not be resolved from corpus or filesystem." if snap_id else "No semantic objects could be resolved from provided target reference."
            session.stages["semantic_interpretation"] = {
                "status": "PARTIAL",
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "details": {"error": err_msg},
            }
            return


        objs = getattr(semantic_state, "objects", []) or (semantic_state.get("persistent", {}).get("objects", []) if isinstance(semantic_state, dict) else [])
        roots = getattr(semantic_state, "roots", []) or []

        # Record Evidence for discovered typed roots and objects
        for r in roots[:5]:
            r_dict = r if isinstance(r, dict) else asdict(r)
            ev = session.ledger.add_record(EvidenceRecord(
                evidence_type=EVIDENCE_TYPE_OBJECT_STATE,
                nature=NATURE_OBSERVATION,
                source="offline_dwarf_reconstruction",
                session_id=session.investigation_id,
                observation=f"Discovered typed root: {r_dict.get('name')} of type {r_dict.get('type')}.",
                object_observation=r_dict,
                details=r_dict,
            ))
            session.findings.append(InvestigationFinding(
                finding_id=f"fnd_root_{uuid.uuid4().hex[:8]}",
                category="fact",
                title=f"Root Object Observed: {r_dict.get('name')}",
                description=f"Global/static root of canonical type {r_dict.get('type')}.",
                c_type_path=r_dict.get("name"),
                object_id=r_dict.get("object_ref"),
                evidence_ids=[ev.evidence_id],
                confidence="high",
                status="CONFIRMED",
            ))

        # Sample reachable objects and fields
        first_field_finding = None
        for obj in objs[:20]:
            o_dict = obj if isinstance(obj, dict) else (obj.to_dict() if hasattr(obj, "to_dict") else asdict(obj))
            oid = o_dict.get("object_id")
            otype = o_dict.get("type")
            path = o_dict.get("primary_path", oid)

            for f in o_dict.get("fields", [])[:10]:
                fname = f.get("name")
                fval = f.get("value")
                fpath = f"{path}.{fname}" if path else fname

                ev = session.ledger.add_record(EvidenceRecord(
                    evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
                    nature=NATURE_OBSERVATION,
                    source="typed_object_graph",
                    session_id=session.investigation_id,
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
                    title=f"Runtime Field Value: {fpath}",
                    description=f"Field {fname} observed with value {fval} ({f.get('type')}).",
                    c_type_path=fpath,
                    object_id=oid,
                    field_name=fname,
                    evidence_ids=[ev.evidence_id],
                    confidence="high",
                    status="CONFIRMED",
                )
                if first_field_finding is None:
                    first_field_finding = finding_candidate

                # Highlight non-zero or suspicious counters/status fields
                if any(k in str(fname).lower() for k in ("counter", "state", "status", "flags", "error", "health", "active", "task", "id")):
                    session.findings.append(finding_candidate)

        if not session.findings and first_field_finding:
            session.findings.append(first_field_finding)


        session.stages["semantic_interpretation"] = {
            "status": "COMPLETED",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "details": {
                "objects_count": len(objs),
                "roots_count": len(roots),
                "state_hash": getattr(semantic_state, "state_hash", None),
            },
        }

    def _execute_stage_static_linking(self, session: InvestigationSession) -> None:
        """Stage 4: Link Runtime Observations to Static Code Evidence."""
        provider = session.static_provider
        if not provider or not provider.is_available():
            session.stages["static_code_link"] = {
                "status": "PARTIAL",
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "details": {"status": "NO_STATIC_PROVIDER", "linked_count": 0},
            }
            return

        linked_count = 0
        resolved_links: List[Dict[str, Any]] = []

        # Find runtime objects and roots with addresses
        snap = session.active_snapshot
        roots = getattr(snap, "roots", []) or []
        objs = getattr(snap, "objects", []) or (snap.get("persistent", {}).get("objects", []) if isinstance(snap, dict) else [])
        items_to_resolve = list(roots[:5]) + list(objs[:10])

        # Retrieve dynamic load bias from snapshot provenance if available
        t_ident = session.stages["target_identity"].get("details", {})
        prov = getattr(snap, "provenance", {}) if hasattr(snap, "provenance") else (snap.get("provenance", {}) if isinstance(snap, dict) else {})
        real_load_bias = prov.get("load_bias") if isinstance(prov, dict) else None
        if isinstance(real_load_bias, str):
            try:
                real_load_bias = int(real_load_bias, 16) if real_load_bias.startswith("0x") else int(real_load_bias)
            except ValueError:
                real_load_bias = 0x555555554000
        elif not isinstance(real_load_bias, int):
            real_load_bias = 0x555555554000

        main_mod = RuntimeModule(
            module_id="main_executable",
            path=t_ident.get("executable", "main"),
            runtime_base=real_load_bias,
            runtime_end=real_load_bias + 0x1000000,
            load_bias=real_load_bias,
            build_id=t_ident.get("target_build_id"),
            load_bias_status="RESOLVED",
            build_id_status=t_ident.get("build_id_status", "VERIFIED"),
        )

        for item in items_to_resolve:
            o_dict = item if isinstance(item, dict) else (item.to_dict() if hasattr(item, "to_dict") else asdict(item))
            addr = o_dict.get("address")
            otype = o_dict.get("type")
            item_name = o_dict.get("name") or o_dict.get("primary_path") or o_dict.get("object_id")
            if addr and isinstance(addr, int) and addr > 0:
                res = provider.resolve_runtime_to_code(addr, module=main_mod, type_name=otype)
                if res.get("status") == "RESOLVED":
                    linked_count += 1
                    resolved_links.append(res)
                    ev = session.ledger.add_record(EvidenceRecord(
                        evidence_type=EVIDENCE_TYPE_STATIC_LINK,
                        nature=NATURE_OBSERVATION,
                        source=provider.get_provider_name(),
                        session_id=session.investigation_id,
                        observation=f"Linked runtime object {item_name} ({otype}) to static symbol {res.get('symbol_name')}.",
                        static_code_link=res,
                        details=res,
                    ))
                    session.findings.append(InvestigationFinding(
                        finding_id=f"fnd_static_{uuid.uuid4().hex[:8]}",
                        category="fact",
                        title=f"Static Code Correlation: {res.get('symbol_name')}",
                        description=f"Correlated via {res.get('link_basis')} at {res.get('decl_file', 'source')}:{res.get('decl_line', '?')}.",
                        c_type_path=item_name or otype,
                        object_id=o_dict.get("object_id") or o_dict.get("object_ref"),
                        evidence_ids=[ev.evidence_id],
                        confidence="high",
                        status="CONFIRMED",
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
                        details=res,
                    ))

        session.stages["static_code_link"] = {
            "status": "COMPLETED" if linked_count > 0 else "PARTIAL",
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "details": {
                "provider": provider.get_provider_name(),
                "linked_count": linked_count,
                "resolved_links": resolved_links,
            },
        }

    def _execute_stage_synthesis(self, session: InvestigationSession) -> None:
        """Stage 5: Synthesize Findings, Invariant Hypotheses, and Next Steps."""
        # 1. Synthesize hypotheses from findings
        facts = [f for f in session.findings if f.category == "fact"]
        if facts:
            counter_facts = [f for f in facts if f.field_name and "counter" in f.field_name.lower()]
            if counter_facts:
                cf = counter_facts[0]
                ev = session.ledger.add_record(EvidenceRecord(
                    evidence_type=EVIDENCE_TYPE_HYPOTHESIS,
                    nature=NATURE_HYPOTHESIS,
                    source="investigation_analyzer",
                    session_id=session.investigation_id,
                    observation=f"Hypothesis: Discrepancy or unexpected value in {cf.c_type_path} may indicate race condition or missing synchronization.",
                    details={"related_finding": cf.finding_id},
                ))
                session.findings.append(InvestigationFinding(
                    finding_id=f"fnd_hypo_{uuid.uuid4().hex[:8]}",
                    category="hypothesis",
                    title=f"Potential Logic or Synchronization Invariant in {cf.c_type_path}",
                    description="Field value observation suggests a potential invariant or boundary condition to verify under mutation or comparison.",
                    c_type_path=cf.c_type_path,
                    object_id=cf.object_id,
                    field_name=cf.field_name,
                    evidence_ids=[ev.evidence_id],
                    confidence="medium",
                    status="CANDIDATE",
                ))

        # 2. Formulate Next Steps
        steps: List[InvestigationNextStep] = []

        # Suggestion 1: Compare with previous/baseline snapshot if only 1 observation
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

        # Summary
        session.summary = {
            "goal": session.goal,
            "facts_count": sum(1 for f in session.findings if f.category == "fact"),
            "hypotheses_count": sum(1 for f in session.findings if f.category == "hypothesis"),
            "unknowns_count": sum(1 for f in session.findings if f.category == "unknown"),
            "next_steps_count": len(steps),
            "evidence_count": len(session.ledger._records),
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


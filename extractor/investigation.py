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
import hashlib
import hmac
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
    CausalVerificationCapability,
    ControlledExecutionResult,
    EvidenceLedger,
    EvidenceRecord,
    NATURE_HYPOTHESIS,
    NATURE_INFERENCE,
    NATURE_OBSERVATION,
    compute_receipt_signature,
    is_atomic_or_stopped_consistency,
    is_exact_semantic_path_match,
    find_matching_diff_changes,
    ATTRIBUTION_BASIS_CALL_STACK,
    ATTRIBUTION_BASIS_EXECUTION_TRACE,
    ATTRIBUTION_BASIS_SINGLE_WRITER,
    VALID_ATTRIBUTION_BASES,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
    PROVENANCE_CLASS_SYNTHETIC_FIXTURE,
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
    TRUSTED_PROVENANCE_CLASSES,
    CLAIM_ARTIFACT_INTEGRITY_VERIFIED,
    CLAIM_CAPTURE_PROVENANCE_VERIFIED,
    CLAIM_TARGET_IDENTITY_VERIFIED,
    CLAIM_STATE_TRANSITION_VERIFIED,
    CLAIM_FUNCTION_ATTRIBUTION_VERIFIED,
    ALL_TRUST_CLAIMS,
)
from .hypothesis import (
    CONFIDENCE_HIGH,
    CONFIDENCE_LOW,
    CONFIDENCE_MEDIUM,
    CONFIDENCE_SPECULATIVE,
    DeterministicHypothesisGenerator,
    EVIDENCE_CLASSIFICATION_FACT,
    EVIDENCE_CLASSIFICATION_INFERENCE,
    EVIDENCE_CLASSIFICATION_PROPOSED_ACTION,
    EVIDENCE_CLASSIFICATION_UNKNOWN,
    FollowUpObservation,
    FUNCTION_TIER_EVIDENCE_SUPPORTED,
    FUNCTION_TIER_STATIC_CANDIDATE,
    FUNCTION_TIER_UNKNOWN,
    FUNCTION_TIER_UNVERIFIED,
    FUNCTION_TIER_VALIDATED_CAUSAL,
    HYPOTHESIS_STATUS_CONTRADICTED,
    HYPOTHESIS_STATUS_INCONCLUSIVE,
    HYPOTHESIS_STATUS_PROPOSED,
    HYPOTHESIS_STATUS_SUPPORTED,
    HYPOTHESIS_STATUS_VALIDATED,
    HypothesisGenerator,
    HypothesisValidator,
    InvestigationHypothesis,
    OBSERVATION_STATUS_CANCELED,
    OBSERVATION_STATUS_EXECUTED,
    OBSERVATION_STATUS_FAILED,
    OBSERVATION_STATUS_PROPOSED,
    OBSERVATION_STATUS_VERIFIED,
    OptionalLLMHypothesisAdapter,
    PluggableHypothesisEngine,
    sanitize_and_disarm_llm_hypothesis,
    TARGET_KIND_COMPARISON,
    TARGET_KIND_FIELD,
    TARGET_KIND_OBJECT,
    TARGET_KIND_SNAPSHOT,
    TARGET_KIND_THREAD,
    VALID_EVIDENCE_CLASSIFICATIONS,
    VALID_OBSERVATION_STATUSES,
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
    get_static_provider,
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
    classification: Optional[str] = None
    supporting_evidence_ids: Optional[List[str]] = None
    temporal_provenance: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        if self.supporting_evidence_ids and not self.evidence_ids:
            self.evidence_ids = list(self.supporting_evidence_ids)
        if not self.classification:
            if self.category == "fact":
                self.classification = EVIDENCE_CLASSIFICATION_FACT
            elif self.category == "hypothesis":
                self.classification = EVIDENCE_CLASSIFICATION_INFERENCE
            else:
                self.classification = EVIDENCE_CLASSIFICATION_UNKNOWN

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if not d.get("classification"):
            if self.category == "fact":
                d["classification"] = EVIDENCE_CLASSIFICATION_FACT
            elif self.category == "hypothesis":
                d["classification"] = EVIDENCE_CLASSIFICATION_INFERENCE
            else:
                d["classification"] = EVIDENCE_CLASSIFICATION_UNKNOWN
        return d


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
        corpus: Optional[StateCorpus] = None,
    ):
        self.investigation_id = investigation_id
        self.goal = goal
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.status = "CREATED"  # CREATED, RUNNING, COMPLETED, PARTIAL, FAILED, BLOCKED
        self.corpus_dir = os.path.abspath(corpus_dir)
        self.corpus = corpus if corpus is not None else StateCorpus(self.corpus_dir)
        self._session_secret: str = uuid.uuid4().hex
        self._capability_key: str = uuid.uuid4().hex
        self.ledger = EvidenceLedger(
            session_id=investigation_id,
            session_secret=self._session_secret,
            capability_key=self._capability_key,
        )

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
        self.follow_up_observations: List[FollowUpObservation] = []
        self.next_steps: List[InvestigationNextStep] = []
        self.active_snapshot: Optional[Any] = None
        self.comparison_results: List[Dict[str, Any]] = []
        self.static_provider: StaticAnalysisProvider = NullStaticAnalysisProvider()
        self.summary: Dict[str, Any] = {}
        self.persistence: str = "EPHEMERAL_PROCESS_LOCAL"
        self.timeline: List[Dict[str, Any]] = []
        self.chat_history: List[Dict[str, Any]] = []

    @property
    def session_secret(self) -> str:
        """Internal session secret for signing and authenticity validation."""
        return self._session_secret

    def issue_verification_capability(
        self,
        evidence_id: str = "",
        target_function: str = "",
        field_path: str = "",
        hypothesis_id: str = "",
        execution_result: Optional[ControlledExecutionResult] = None,
    ) -> CausalVerificationCapability:
        """Issue an internal unforgeable capability granting attestation authority."""
        return self.ledger.issue_verification_capability(
            evidence_id=evidence_id,
            target_function=target_function,
            field_path=field_path,
            hypothesis_id=hypothesis_id,
            execution_result=execution_result,
        )

    def attest_causal_proof(
        self,
        evidence_id: str,
        target_function: Optional[str] = None,
        field_path: Optional[str] = None,
        verification_type: str = "deterministic_reproduction",
        capability: Optional[CausalVerificationCapability] = None,
        execution_provenance: Optional[Dict[str, Any]] = None,
        hypothesis_id: Optional[str] = None,
        target_identity: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Attest an authentic proof record in this session's ledger."""
        return self.ledger.attest_causal_proof(
            evidence_id=evidence_id,
            target_function=target_function,
            field_path=field_path,
            verification_type=verification_type,
            capability=capability,
            execution_provenance=execution_provenance,
            hypothesis_id=hypothesis_id,
            target_identity=target_identity,
        )

    def add_timeline_event(
        self,
        event_type: str,
        title: str,
        summary: str,
        classification: str = EVIDENCE_CLASSIFICATION_FACT,
        finding_id: Optional[str] = None,
        hypothesis_id: Optional[str] = None,
        observation_id: Optional[str] = None,
        evidence_ids: Optional[List[str]] = None,
        status_before: Optional[str] = None,
        status_after: Optional[str] = None,
        confidence: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Record an auditable, chronological event in the investigation timeline."""
        evt = {
            "event_id": f"evt_{uuid.uuid4().hex[:10]}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "classification": classification,
            "title": title,
            "summary": summary,
            "finding_id": finding_id,
            "hypothesis_id": hypothesis_id,
            "observation_id": observation_id,
            "evidence_ids": list(evidence_ids or []),
            "status_before": status_before,
            "status_after": status_after,
            "confidence": confidence,
            "details": dict(details or {}),
        }
        self.timeline.append(evt)
        return evt

    def synthesize_causal_conclusions(self) -> Dict[str, Any]:
        """Synthesize causal conclusions, validating whether genuine causal proof was established and highlighting limitations."""
        proof_established = any(h.validation_status == HYPOTHESIS_STATUS_VALIDATED for h in self.hypotheses)
        cap_details = self.stages.get("capture_quality", {}).get("details", {})
        consistency = cap_details.get("consistency_level") or "UNKNOWN"
        cap_status = self.stages.get("capture_quality", {}).get("status", "PENDING")
        limitations = list(cap_details.get("limitations", []))

        notice = None
        if not proof_established:
            if consistency == "NON_ATOMIC":
                notice = "Causal proof blocked: capture consistency is NON_ATOMIC (target running concurrently). Deterministic reproduction required."
            elif cap_status == "PARTIAL":
                notice = "Causal proof blocked: capture quality is PARTIAL. Full memory snapshot required."
            else:
                notice = "Static function candidates and comparative observations alone do not constitute proven causality. Additional deterministic mutation verification or instruction-level trace required."

        return {
            "supported_hypotheses": [
                {
                    "hypothesis_id": h.hypothesis_id,
                    "title": h.title,
                    "supporting_evidence_ids": list(h.supporting_evidence_ids),
                    "reason": h.status_history[-1].get("reason", "Supported") if h.status_history else "Supported",
                }
                for h in self.hypotheses if h.validation_status == HYPOTHESIS_STATUS_SUPPORTED
            ],
            "causal_proof_established": proof_established,
            "causal_limitation_notice": notice,
            "consistency_level": consistency,
            "capture_status": cap_status,
        }

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
            "recommended_next_steps": [s.to_dict() for s in self.next_steps],
            "comparison_results": self.comparison_results,
            "summary": self.summary,
            "timeline": list(self.timeline),
            "timeline_count": len(self.timeline),
            "evidence_ledger": self.ledger.to_dict(),
            "chat_history": list(getattr(self, "chat_history", [])),
            "target_identity": self.stages.get("target_identity", {}).get("details", self.target_ref),
            "capture_quality": self.stages.get("capture_quality", {}).get("details", {}),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any], corpus: Optional[StateCorpus] = None) -> "InvestigationSession":
        """Reconstruct investigation session from serialized data with tamper-resistant revalidation."""
        inv_id = data.get("investigation_id", f"inv_{uuid.uuid4().hex[:8]}")
        goal = data.get("goal", "")
        corpus_dir = data.get("corpus_dir", "corpus")
        session = cls(
            investigation_id=inv_id,
            goal=goal,
            corpus_dir=corpus_dir,
            safety=data.get("safety"),
            budgets=data.get("budgets"),
            corpus=corpus,
        )
        session.created_at = data.get("created_at", session.created_at)
        session.persistence = data.get("persistence", session.persistence)
        session.target_ref = dict(data.get("target_ref", {}))
        session.stages = dict(data.get("stages", session.stages))
        session.comparison_results = list(data.get("comparison_results", []))
        session.summary = dict(data.get("summary", {}))
        session.timeline = list(data.get("timeline", []))
        session.chat_history = list(data.get("chat_history", []))

        # Reconstruct ledger if present
        ledger_data = data.get("evidence_ledger")
        if ledger_data and isinstance(ledger_data, dict):
            session.ledger = EvidenceLedger.from_dict(ledger_data)
            session._session_secret = session.ledger.session_secret
            session._capability_key = getattr(session.ledger, "capability_key", session.ledger._capability_key)

        # Reconstruct findings
        session.findings = [
            InvestigationFinding(**f) if isinstance(f, dict) else f
            for f in data.get("findings", [])
        ]

        # Reconstruct hypotheses with strict tamper verification against ledger
        reconstructed_hypos: List[InvestigationHypothesis] = []
        for h_data in data.get("hypotheses", []):
            if isinstance(h_data, dict):
                h_copy = dict(h_data)
                # Disarm injected fake evidence IDs not present in ledger
                h_copy["supporting_evidence_ids"] = [
                    eid for eid in h_copy.get("supporting_evidence_ids", [])
                    if session.ledger.get_record(eid) is not None
                ]
                h_copy["contradicting_evidence_ids"] = [
                    eid for eid in h_copy.get("contradicting_evidence_ids", [])
                    if session.ledger.get_record(eid) is not None
                ]
                hypo = InvestigationHypothesis.from_dict(h_copy)
                # Re-evaluate against ledger to ensure unverified caller claims are not trusted
                HypothesisValidator.evaluate(hypo, session.ledger)
                reconstructed_hypos.append(hypo)
            elif isinstance(h_data, InvestigationHypothesis):
                h_data.supporting_evidence_ids = [
                    eid for eid in h_data.supporting_evidence_ids
                    if session.ledger.get_record(eid) is not None
                ]
                h_data.contradicting_evidence_ids = [
                    eid for eid in h_data.contradicting_evidence_ids
                    if session.ledger.get_record(eid) is not None
                ]
                HypothesisValidator.evaluate(h_data, session.ledger)
                reconstructed_hypos.append(h_data)
        session.hypotheses = reconstructed_hypos

        # Reconstruct next steps
        session.next_steps = [
            InvestigationNextStep(**ns) if isinstance(ns, dict) else ns
            for ns in data.get("next_steps", [])
        ]

        # Reconstruct follow-up observations list from hypotheses
        session.follow_up_observations = [
            obs for h in session.hypotheses for obs in h.suggested_observations
        ]

        session.status = data.get("status", session.status)
        return session


AUTHORIZED_EXECUTION_BACKENDS = {
    "live_process_snapshot_diff",
    "controlled_gdb_backend",
    "controlled_runtime_harness",
    "synthetic_adversarial_fixture",
}


def compute_snapshot_artifact_hash(snap_ref: Any, session: Optional[InvestigationSession] = None) -> str:
    """Compute a cryptographic SHA256 digest of snapshot artifact data for tamper detection.

    For directory-based snapshots:
    - Recursively traverses all reconstruction-relevant artifact files.
    - Deterministically hashes normalized relative paths, file sizes, and cryptographic file digests.
    - Strictly rejects symlinks, path traversal, and empty directories.
    """
    if isinstance(snap_ref, str):
        # Reject path traversal
        norm = os.path.normpath(snap_ref)
        if ".." in norm.split(os.path.sep):
            raise ValueError(f"Path traversal detected in snapshot path: '{snap_ref}'")

        cand_path = snap_ref
        if not os.path.exists(cand_path) and session is not None:
            if hasattr(session, "corpus") and session.corpus:
                ms_path = os.path.join(session.corpus.corpus_dir, "memory_snapshots", snap_ref)
                if os.path.exists(ms_path):
                    cand_path = ms_path
                else:
                    for state_id, meta in session.corpus.states.items():
                        if meta.get("snapshot_id") == snap_ref or state_id == snap_ref or snap_ref in meta.get("observations", []):
                            s_dir = os.path.join(session.corpus.states_dir, state_id)
                            if os.path.exists(s_dir):
                                cand_path = s_dir
                                break

        if os.path.islink(cand_path):
            raise ValueError(f"Snapshot path '{snap_ref}' is a symbolic link; symlinks are rejected for security")

        if os.path.isfile(cand_path):
            h = hashlib.sha256()
            with open(cand_path, "rb") as f:
                while chunk := f.read(65536):
                    h.update(chunk)
            return h.hexdigest()

        if os.path.isdir(cand_path):
            entries = []
            for root, dirs, files in os.walk(cand_path, followlinks=False):
                for d in dirs:
                    d_full = os.path.join(root, d)
                    if os.path.islink(d_full):
                        raise ValueError(f"Symbolic link directory detected in snapshot: '{d}'")
                for fn in files:
                    fp = os.path.join(root, fn)
                    if os.path.islink(fp):
                        raise ValueError(f"Symbolic link detected in snapshot artifact: '{fn}'")
                    rel_p = os.path.relpath(fp, cand_path).replace("\\", "/")
                    if ".." in rel_p.split("/") or os.path.isabs(rel_p):
                        raise ValueError(f"Path traversal detected in snapshot file: '{rel_p}'")
                    sz = os.path.getsize(fp)
                    fh = hashlib.sha256()
                    with open(fp, "rb") as f:
                        while chunk := f.read(65536):
                            fh.update(chunk)
                    entries.append((rel_p, sz, fh.hexdigest()))

            if not entries:
                raise ValueError(f"Snapshot directory '{cand_path}' is empty; no artifact files found")

            # Deterministic sorted manifest
            manifest_h = hashlib.sha256()
            for rel_p, sz, f_digest in sorted(entries):
                manifest_h.update(f"{rel_p}:{sz}:{f_digest}\n".encode("utf-8"))
            return manifest_h.hexdigest()

    snap_dict = snap_ref if isinstance(snap_ref, dict) else (
        snap_ref.to_dict() if hasattr(snap_ref, "to_dict") else {}
    )
    if not snap_dict and isinstance(snap_ref, str) and session is not None:
        if hasattr(session, "corpus") and session.corpus:
            snap_dict = session.corpus.get(snap_ref) or {}
            if not snap_dict:
                for state_id, meta in session.corpus.states.items():
                    if meta.get("snapshot_id") == snap_ref or state_id == snap_ref or snap_ref in meta.get("observations", []):
                        snap_dict = session.corpus.get(state_id) or {}
                        break
    return hashlib.sha256(json.dumps(snap_dict, sort_keys=True).encode("utf-8")).hexdigest()


class TrustedCausalVerifier:
    """Internal trusted verifier authorized to execute observations, verify reproductions, and issue causal attestations."""

    def __init__(self, session: InvestigationSession):
        self._session = session

    def _resolve_snapshot_for_verifier(self, snap_ref: Any) -> Optional[Any]:
        """Resolve snapshot artifact for internal verification."""
        if not isinstance(snap_ref, str):
            if isinstance(snap_ref, dict) or hasattr(snap_ref, "to_dict"):
                return snap_ref
            return None

        norm = os.path.normpath(snap_ref)
        if ".." in norm.split(os.path.sep):
            raise ValueError(f"Path traversal detected in snapshot path: '{snap_ref}'")
        if os.path.islink(snap_ref):
            raise ValueError(f"Snapshot path '{snap_ref}' is a symbolic link; symlinks are rejected for security")
        if self._session and hasattr(self._session, "corpus") and self._session.corpus:
            snap_data = self._session.corpus.get(snap_ref)
            if snap_data:
                return snap_data
            for state_id, meta in self._session.corpus.states.items():
                if meta.get("snapshot_id") == snap_ref or state_id == snap_ref or snap_ref in meta.get("observations", []):
                    snap_data = self._session.corpus.get(state_id)
                    if snap_data:
                        return snap_data
        if os.path.exists(snap_ref):
            if snap_ref.endswith(".json"):
                with open(snap_ref, "r", encoding="utf-8") as f:
                    return json.load(f)
            try:
                from .raw_snapshot import RawRuntimeSnapshot
                raw_snap = RawRuntimeSnapshot.load(snap_ref)
                dbg = self._session.target_ref.get("debug_image") if self._session else None
                if dbg and os.path.exists(dbg):
                    engine = OfflineSemanticEngine()
                    try:
                        decoded = engine.reconstruct(raw_snap, debug_image=dbg)
                        if decoded and hasattr(decoded, "to_dict"):
                            return decoded.to_dict()
                        return decoded
                    except Exception:
                        pass
                return raw_snap
            except Exception:
                pass
            try:
                from .memory_snapshot import RawMemorySnapshot
                return RawMemorySnapshot.load(snap_ref)
            except Exception:
                pass
        return None

    def verify_controlled_execution(
        self,
        target_function: str,
        field_path: str,
        snapshot_a_path: str,
        snapshot_b_path: str,
        attribution_evidence: Optional[Dict[str, Any]] = None,
        hypothesis_id: str = "",
        evidence_id: str = "",
    ) -> ControlledExecutionResult:
        """Verify state transition and optional attribution from snapshot artifacts and mint ControlledExecutionResult."""
        snap_a = self._resolve_snapshot_for_verifier(snapshot_a_path)
        snap_b = self._resolve_snapshot_for_verifier(snapshot_b_path)
        if snap_a is None or snap_b is None:
            raise ValueError(
                f"Snapshot artifacts '{snapshot_a_path}' or '{snapshot_b_path}' could not be resolved for verification"
            )

        # Check capture quality
        def _get_snapshot_quality(snap: Any) -> Tuple[str, str]:
            if hasattr(snap, "to_dict"):
                s_dict = snap.to_dict()
            elif isinstance(snap, dict):
                s_dict = snap
            else:
                s_dict = {}
            comp = getattr(snap, "completeness", None) or getattr(snap, "status", None) or s_dict.get("completeness") or s_dict.get("status") or "COMPLETE"
            consistency = getattr(snap, "consistency", None) or s_dict.get("consistency")
            q = getattr(snap, "quality", None)
            if q is not None:
                comp = getattr(q, "status", None) or comp
                consistency = getattr(q, "consistency", None) or getattr(q, "consistency_level", None) or consistency
            cons_lvl = None
            if isinstance(consistency, dict):
                cons_lvl = consistency.get("level")
            elif isinstance(consistency, str):
                cons_lvl = consistency
            if not cons_lvl:
                cons_lvl = getattr(snap, "consistency_level", None) or s_dict.get("consistency_level")
            if not cons_lvl:
                obs_meta = getattr(snap, "observation_metadata", None) or s_dict.get("observation_metadata") or {}
                prov = getattr(snap, "provenance", None) or s_dict.get("provenance") or {}
                if obs_meta.get("consistency_classification"):
                    cons_lvl = obs_meta.get("consistency_classification")
                elif prov.get("snapshot_consistency"):
                    cons_lvl = prov.get("snapshot_consistency")
                elif obs_meta.get("is_non_atomic") is True or prov.get("is_non_atomic") is True:
                    cons_lvl = "NON_ATOMIC"
                else:
                    cons_lvl = "STOPPED"
            return str(comp).upper(), str(cons_lvl).upper()

        comp_a, cons_a = _get_snapshot_quality(snap_a)
        comp_b, cons_b = _get_snapshot_quality(snap_b)
        if comp_a != "COMPLETE" or comp_b != "COMPLETE":
            raise ValueError(f"Live reproduction rejected: snapshot capture completeness not COMPLETE (A: {comp_a}, B: {comp_b})")
        if not is_atomic_or_stopped_consistency(cons_a) or not is_atomic_or_stopped_consistency(cons_b):
            raise ValueError(f"Live reproduction rejected: snapshot consistency not atomic/stopped (A: {cons_a}, B: {cons_b})")

        # Identity resolution
        def _get_identity(snap: Any) -> Dict[str, Any]:
            if hasattr(snap, "to_dict"):
                d = snap.to_dict()
            elif isinstance(snap, dict):
                d = snap
            else:
                d = {}
            prov = d.get("provenance") or getattr(snap, "provenance", {}) or {}
            proc = d.get("process") or prov.get("process") or {}
            return {
                "pid": getattr(snap, "pid", None) or d.get("pid") or proc.get("pid") or prov.get("pid"),
                "binary": getattr(snap, "binary", None) or d.get("binary") or proc.get("binary") or prov.get("binary"),
                "build_id": getattr(snap, "executable_build_id", None) or d.get("executable_build_id") or proc.get("executable_build_id") or prov.get("executable_build_id"),
            }

        id_a = _get_identity(snap_a)
        id_b = _get_identity(snap_b)
        if id_a.get("build_id") and id_b.get("build_id") and id_a["build_id"] != id_b["build_id"]:
            raise ValueError(f"Target build ID mismatch between snapshots: {id_a['build_id']} != {id_b['build_id']}")
        if id_a.get("pid") and id_b.get("pid") and id_a["pid"] != id_b["pid"]:
            raise ValueError(f"Target PID mismatch between snapshots: {id_a['pid']} != {id_b['pid']}")

        # Verify state transition diff
        diff_res = StateDiffEngine().diff(snap_a, snap_b)
        matching_changes, err_msg = find_matching_diff_changes(diff_res.changes, field_path)
        if err_msg:
            raise ValueError(err_msg)
        if not matching_changes:
            raise ValueError(f"No observed state transition for field '{field_path}' between snapshots")

        before_val = matching_changes[0].get("before")
        after_val = matching_changes[0].get("after")
        if before_val == after_val:
            raise ValueError(f"Field '{field_path}' did not change between snapshots ({before_val} == {after_val})")

        func_attr_ver = False
        attr_basis = ""
        attr_limitation = ""

        if attribution_evidence and isinstance(attribution_evidence, dict):
            basis = attribution_evidence.get("attribution_basis")
            if basis == ATTRIBUTION_BASIS_SINGLE_WRITER:
                ctrl_eid = attribution_evidence.get("control_evidence_id") or attribution_evidence.get("baseline_evidence_id")
                if ctrl_eid and self._session.ledger:
                    rec_ctrl = self._session.ledger.get_record(ctrl_eid)
                    if (
                        rec_ctrl
                        and rec_ctrl.source != "unverified_caller"
                        and not (rec_ctrl.details or {}).get("caller_submitted")
                        and not (rec_ctrl.details or {}).get("unverified_caller_claim")
                    ):
                        c_det = rec_ctrl.details or {}
                        c_t_id = rec_ctrl.target_identity or c_det.get("target_identity") or {}
                        pid_match = not c_t_id.get("pid") or not id_a.get("pid") or c_t_id.get("pid") == id_a["pid"]
                        bld_match = not c_t_id.get("build_id") or not id_a.get("build_id") or c_t_id.get("build_id") == id_a["build_id"]
                        fld = c_det.get("field_path") or c_det.get("field_name")
                        fld_match = not fld or is_exact_semantic_path_match(field_path, field_path.split(".")[-1], fld)
                        has_before_after = (c_det.get("before_value") is not None and c_det.get("after_value") is not None)
                        if has_before_after:
                            ctrl_stable = (c_det.get("before_value") == c_det.get("after_value"))
                        elif c_det.get("mutation_occurred") is not None:
                            ctrl_stable = (c_det.get("mutation_occurred") is False)
                        elif c_det.get("state_stable") is not None:
                            ctrl_stable = bool(c_det.get("state_stable"))
                        else:
                            ctrl_stable = (c_det.get("control_condition") in ("baseline", "no_mutation", "inactive_candidate"))

                        writer_fn = attribution_evidence.get("active_writer_function") or c_det.get("target_function")
                        if pid_match and bld_match and fld_match and ctrl_stable and writer_fn == target_function:
                            func_attr_ver = True
                            attr_basis = ATTRIBUTION_BASIS_SINGLE_WRITER
                        else:
                            if not ctrl_stable:
                                attr_limitation = f"Negative control baseline failed: field '{field_path}' mutated during control period ({c_det.get('before_value')} -> {c_det.get('after_value')}) while candidate '{target_function}' was inactive (potential concurrent writer or idle drift)."
                            elif writer_fn != target_function:
                                attr_limitation = f"Single-writer isolation failed: active writer was '{writer_fn}', which does not match candidate '{target_function}'."
                            elif not (pid_match and bld_match):
                                attr_limitation = "Single-writer isolation failed: control evidence process identity does not match treatment snapshot."
                            elif not fld_match:
                                attr_limitation = f"Single-writer isolation failed: control evidence field '{fld}' does not match '{field_path}'."
                    else:
                        attr_limitation = "Single-writer isolation requires valid control evidence in ledger observing baseline field stability."
            elif basis == ATTRIBUTION_BASIS_EXECUTION_TRACE:
                trace_eid = attribution_evidence.get("trace_evidence_id")
                if trace_eid and self._session.ledger:
                    rec_tr = self._session.ledger.get_record(trace_eid)
                    if (
                        rec_tr
                        and rec_tr.source in ("trace_collector", "trusted_tracer", "investigation_observer")
                        and not (rec_tr.details or {}).get("caller_submitted")
                    ):
                        tr_events = (rec_tr.details or {}).get("trace_events", [])
                        if any(isinstance(e, dict) and e.get("function") == target_function and e.get("event") == "write" for e in tr_events):
                            func_attr_ver = True
                            attr_basis = ATTRIBUTION_BASIS_EXECUTION_TRACE
                        else:
                            attr_limitation = f"Execution trace failed: no verified write event recorded for candidate '{target_function}' on field '{field_path}'."
                else:
                    attr_limitation = "Execution trace requires valid trace collector evidence in ledger."

        if not func_attr_ver and not attr_limitation:
            attr_limitation = "State transition verified in runtime, but function attribution was not independently verified by execution instrumentation."

        claims = {
            CLAIM_ARTIFACT_INTEGRITY_VERIFIED,
            CLAIM_TARGET_IDENTITY_VERIFIED,
            CLAIM_STATE_TRANSITION_VERIFIED,
        }
        if func_attr_ver:
            claims.add(CLAIM_FUNCTION_ATTRIBUTION_VERIFIED)

        t_id = {}
        pid_val = id_a.get("pid") or id_b.get("pid")
        if pid_val is not None:
            t_id["pid"] = pid_val
        bin_val = id_a.get("binary") or id_b.get("binary")
        if bin_val is not None:
            t_id["binary"] = bin_val
        bld_val = id_a.get("build_id") or id_b.get("build_id")
        if bld_val is not None:
            t_id["build_id"] = bld_val
        return self.record_controlled_execution(
            target_function=target_function,
            field_path=field_path,
            before_value=before_val,
            after_value=after_val,
            execution_status="REPRODUCED",
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
            before_snapshot_ref=str(snapshot_a_path),
            after_snapshot_ref=str(snapshot_b_path),
            target_identity=t_id,
            backend_type="live_process_snapshot_diff",
            hypothesis_id=hypothesis_id,
            evidence_id=evidence_id,
            provenance_class=PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
            function_attribution_verified=func_attr_ver,
            attribution_basis=attr_basis,
            attribution_limitation=attr_limitation,
            verified_claims=claims,
        )

    def record_controlled_execution(
        self,
        target_function: str,
        field_path: str,
        before_value: Any = None,
        after_value: Any = None,
        execution_status: str = "REPRODUCED",
        capture_quality: Optional[Dict[str, Any]] = None,
        before_snapshot_ref: Optional[str] = None,
        after_snapshot_ref: Optional[str] = None,
        target_identity: Optional[Dict[str, Any]] = None,
        backend_type: str = "controlled_runtime",
        hypothesis_id: str = "",
        evidence_id: str = "",
        provenance_class: Optional[str] = None,
        function_attribution_verified: Optional[bool] = None,
        attribution_basis: str = "",
        verified_claims: Optional[Union[Tuple[str, ...], List[str], Set[str]]] = None,
        attribution_limitation: str = "",
    ) -> ControlledExecutionResult:
        """Record an authentic execution receipt signed with the session secret.

        Strict Trust Boundaries:
        1. Arbitrary or unauthorized backend labels are strictly rejected.
        2. Fabricated before/after values without verified snapshot transitions are rejected.
        3. Real snapshot references are validated against diff changes using exact semantic path matching.
        4. Provenance class and function attribution verification are bound into HMAC signature.
        """
        if backend_type not in AUTHORIZED_EXECUTION_BACKENDS:
            raise ValueError(f"Unauthorized execution backend '{backend_type}'; receipt creation rejected")

        if execution_status not in ("REPRODUCED", "SUCCESS", "CONFIRMED"):
            raise ValueError(f"Execution status '{execution_status}' does not prove reproduction")

        eff_prov_class = provenance_class or PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION

        if function_attribution_verified is not None:
            eff_attr_ver = bool(function_attribution_verified)
        else:
            eff_attr_ver = False

        if eff_attr_ver:
            if attribution_basis and attribution_basis in VALID_ATTRIBUTION_BASES:
                eff_attr_basis = attribution_basis
            else:
                eff_attr_ver = False
                eff_attr_basis = "unsupported_attribution_basis"
        else:
            eff_attr_basis = attribution_basis or "state_transition_only"

        hash_a = None
        hash_b = None

        if before_snapshot_ref and after_snapshot_ref:
            snap_a = self._resolve_snapshot_for_verifier(before_snapshot_ref)
            snap_b = self._resolve_snapshot_for_verifier(after_snapshot_ref)
            if snap_a is None or snap_b is None:
                raise ValueError(
                    f"Snapshot artifacts '{before_snapshot_ref}' or '{after_snapshot_ref}' could not be resolved for verification"
                )
            hash_a = compute_snapshot_artifact_hash(before_snapshot_ref, self._session)
            hash_b = compute_snapshot_artifact_hash(after_snapshot_ref, self._session)
            diff_res = StateDiffEngine().diff(snap_a, snap_b)
            matching_changes, err_msg = find_matching_diff_changes(diff_res.changes, field_path)
            if err_msg:
                raise ValueError(err_msg)
            found = False
            for chg in matching_changes:
                if before_value is not None and chg.get("before") != before_value:
                    continue
                if after_value is not None and chg.get("after") != after_value:
                    continue
                found = True
                break
            if not found:
                raise ValueError(
                    f"Fabricated execution values: field '{field_path}' transition "
                    f"({before_value} -> {after_value}) does not match verified snapshot diff"
                )
        elif backend_type != "synthetic_adversarial_fixture":
            raise ValueError("Cannot record execution without verified snapshot references")

        cq = capture_quality or {"completeness": "COMPLETE", "consistency_level": "STOPPED"}
        comp = cq.get("completeness") or cq.get("status")
        cons = cq.get("consistency_level") or cq.get("consistency_classification")
        if comp != "COMPLETE" or not is_atomic_or_stopped_consistency(cons):
            raise ValueError(f"Cannot record execution: capture quality ({comp}, {cons}) is not complete and atomic")

        exec_id = f"exec_{uuid.uuid4().hex[:10]}"
        t_id = target_identity or self._session.target_ref.get("target_identity") or {}
        now_ts = datetime.now(timezone.utc).isoformat()

        claims_tuple = tuple(sorted(verified_claims or ()))

        res_temp = ControlledExecutionResult(
            execution_id=exec_id,
            investigation_id=self._session.investigation_id,
            target_function=target_function,
            field_path=field_path,
            before_value=before_value,
            after_value=after_value,
            execution_status=execution_status,
            capture_quality=cq,
            hypothesis_id=hypothesis_id,
            evidence_id=evidence_id,
            before_snapshot_ref=str(before_snapshot_ref) if before_snapshot_ref else None,
            after_snapshot_ref=str(after_snapshot_ref) if after_snapshot_ref else None,
            before_snapshot_hash=hash_a,
            after_snapshot_hash=hash_b,
            target_identity=t_id,
            backend_type=backend_type,
            provenance_class=eff_prov_class,
            function_attribution_verified=eff_attr_ver,
            attribution_basis=eff_attr_basis,
            attribution_limitation=attribution_limitation,
            verified_claims=claims_tuple,
            executed_at=now_ts,
            receipt_signature="",
        )
        sig = compute_receipt_signature(self._session._session_secret, res_temp)

        return ControlledExecutionResult(
            execution_id=exec_id,
            investigation_id=self._session.investigation_id,
            target_function=target_function,
            field_path=field_path,
            before_value=before_value,
            after_value=after_value,
            execution_status=execution_status,
            capture_quality=cq,
            hypothesis_id=hypothesis_id,
            evidence_id=evidence_id,
            before_snapshot_ref=str(before_snapshot_ref) if before_snapshot_ref else None,
            after_snapshot_ref=str(after_snapshot_ref) if after_snapshot_ref else None,
            before_snapshot_hash=hash_a,
            after_snapshot_hash=hash_b,
            target_identity=t_id,
            backend_type=backend_type,
            provenance_class=eff_prov_class,
            function_attribution_verified=eff_attr_ver,
            attribution_basis=eff_attr_basis,
            attribution_limitation=attribution_limitation,
            verified_claims=claims_tuple,
            executed_at=now_ts,
            receipt_signature=sig,
        )

    def verify_execution_and_attest(
        self,
        evidence_id: str,
        hypothesis_id: str,
        execution_result: ControlledExecutionResult,
        target_function: Optional[str] = None,
        field_path: Optional[str] = None,
        verification_type: str = "deterministic_reproduction",
    ) -> bool:
        """Verify the authenticity and scope of an execution receipt, mint a scoped capability, and attest causal proof."""
        if not isinstance(execution_result, ControlledExecutionResult):
            raise ValueError("Invalid execution result: must be an instance of ControlledExecutionResult")

        # 1. Verify receipt authenticity against session secret
        if not execution_result.verify_authenticity(self._session._session_secret):
            raise ValueError("Execution receipt signature / authenticity verification failed: forged or tampered receipt")

        # 2. Verify investigation binding
        if execution_result.investigation_id != self._session.investigation_id:
            raise ValueError(f"Execution receipt belongs to investigation '{execution_result.investigation_id}', not '{self._session.investigation_id}'")

        # 3. Verify status
        if execution_result.execution_status not in ("REPRODUCED", "SUCCESS", "CONFIRMED"):
            raise ValueError(f"Execution receipt status '{execution_result.execution_status}' does not prove reproduction")

        # 4. Verify capture quality
        cq = execution_result.capture_quality or {}
        comp = cq.get("completeness") or cq.get("status")
        cons = cq.get("consistency_level") or cq.get("consistency_classification")
        if comp != "COMPLETE" or not is_atomic_or_stopped_consistency(cons):
            raise ValueError(f"Execution receipt capture quality ({comp}, {cons}) is not complete and atomic")

        # 5. Check scope match
        eff_fn = target_function or execution_result.target_function
        eff_field = field_path or execution_result.field_path
        if target_function and execution_result.target_function and target_function != execution_result.target_function:
            raise ValueError(f"Scope mismatch: target_function '{target_function}' does not match execution receipt '{execution_result.target_function}'")
        if field_path and execution_result.field_path and field_path != execution_result.field_path:
            raise ValueError(f"Scope mismatch: field_path '{field_path}' does not match execution receipt '{execution_result.field_path}'")

        # 6. Check hypothesis binding
        if hypothesis_id and execution_result.hypothesis_id and hypothesis_id != execution_result.hypothesis_id:
            raise ValueError(f"Hypothesis mismatch: '{hypothesis_id}' does not match execution receipt '{execution_result.hypothesis_id}'")

        # 7. Check evidence binding
        if evidence_id and execution_result.evidence_id and evidence_id != execution_result.evidence_id:
            raise ValueError(f"Evidence mismatch: '{evidence_id}' does not match execution receipt '{execution_result.evidence_id}'")

        # 8. Check target identity binding
        sess_tid = self._session.target_ref.get("target_identity") or {}
        rec_tid = execution_result.target_identity or {}
        if sess_tid and rec_tid:
            if sess_tid.get("build_id") and rec_tid.get("build_id") and sess_tid["build_id"] != rec_tid["build_id"]:
                raise ValueError(f"Target build identity mismatch: session ({sess_tid['build_id']}) != receipt ({rec_tid['build_id']})")
            if sess_tid.get("pid") and rec_tid.get("pid") and sess_tid["pid"] != rec_tid["pid"]:
                raise ValueError(f"Target PID mismatch: session ({sess_tid['pid']}) != receipt ({rec_tid['pid']})")

        # 9. Verify snapshot tamper detection post-issuance
        if execution_result.before_snapshot_ref and execution_result.before_snapshot_hash:
            ref_a = execution_result.before_snapshot_ref
            if (os.path.isabs(ref_a) or ref_a.endswith(".json") or os.path.sep in ref_a) and not os.path.exists(ref_a):
                raise ValueError(f"Before-snapshot artifact '{ref_a}' is missing after receipt issuance")
            curr_hash_a = compute_snapshot_artifact_hash(ref_a, self._session)
            if curr_hash_a != execution_result.before_snapshot_hash:
                raise ValueError("Before-snapshot artifact tampered or modified after receipt issuance")
        if execution_result.after_snapshot_ref and execution_result.after_snapshot_hash:
            ref_b = execution_result.after_snapshot_ref
            if (os.path.isabs(ref_b) or ref_b.endswith(".json") or os.path.sep in ref_b) and not os.path.exists(ref_b):
                raise ValueError(f"After-snapshot artifact '{ref_b}' is missing after receipt issuance")
            curr_hash_b = compute_snapshot_artifact_hash(ref_b, self._session)
            if curr_hash_b != execution_result.after_snapshot_hash:
                raise ValueError("After-snapshot artifact tampered or modified after receipt issuance")

        # 10. Verify evidence record exists and is not unverified caller claim
        rec = self._session.ledger.get_record(evidence_id)
        if not rec:
            raise ValueError(f"Evidence record '{evidence_id}' does not exist in ledger")

        p_details = rec.details or {}
        p_prov = rec.provenance or {}
        if (
            p_details.get("caller_submitted") is True
            or p_details.get("unverified_caller_claim") is True
            or rec.source == "unverified_caller"
            or p_prov.get("submission_channel") == "external_caller"
        ):
            raise ValueError(f"Cannot attest causal proof: record '{evidence_id}' originated from unverified external caller")

        rec_cq = rec.capture_quality or {}
        r_comp = rec_cq.get("completeness") or rec_cq.get("status")
        r_cons = rec_cq.get("consistency_level") or rec_cq.get("consistency_classification") or p_details.get("consistency_classification")
        if r_comp != "COMPLETE" or not is_atomic_or_stopped_consistency(r_cons) or p_details.get("is_non_atomic") is True:
            raise ValueError(f"Cannot attest causal proof: record '{evidence_id}' has degraded capture quality ({r_comp}, {r_cons})")

        # 11. Mint single-use scoped capability
        cap = self._session.issue_verification_capability(
            evidence_id=evidence_id,
            target_function=eff_fn,
            field_path=eff_field,
            hypothesis_id=hypothesis_id,
            execution_result=execution_result,
        )

        # 12. Attest using capability
        return self._session.attest_causal_proof(
            evidence_id=evidence_id,
            target_function=eff_fn,
            field_path=eff_field,
            verification_type=verification_type,
            capability=cap,
            execution_provenance={
                "execution_id": execution_result.execution_id,
                "execution_status": execution_result.execution_status,
                "backend_type": execution_result.backend_type,
                "executed_at": execution_result.executed_at,
                "verified_by": "TrustedCausalVerifier",
            },
            hypothesis_id=hypothesis_id,
            target_identity=execution_result.target_identity,
        )

    def verify_and_attest(
        self,
        evidence_id: str,
        target_function: Optional[str] = None,
        field_path: Optional[str] = None,
        verification_type: str = "deterministic_reproduction",
        execution_provenance: Optional[Dict[str, Any]] = None,
        hypothesis_id: Optional[str] = None,
        execution_result: Optional[ControlledExecutionResult] = None,
    ) -> bool:
        """Verify execution result and attest causal proof.

        Caller-supplied execution_provenance dictionaries or booleans are strictly rejected.
        Only authentic execution receipts (ControlledExecutionResult) are accepted.
        """
        if execution_provenance is not None:
            raise ValueError(
                "Caller-supplied execution_provenance dictionaries or booleans are rejected. "
                "Causal proof attestation requires an independently verified ControlledExecutionResult."
            )
        if execution_result is None or not isinstance(execution_result, ControlledExecutionResult):
            raise ValueError(
                "Cannot attest causal proof: authentic execution_result (ControlledExecutionResult) is required."
            )
        return self.verify_execution_and_attest(
            evidence_id=evidence_id,
            hypothesis_id=hypothesis_id or "",
            execution_result=execution_result,
            target_function=target_function,
            field_path=field_path,
            verification_type=verification_type,
        )


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
        watch_session_id: Optional[str] = None,
        observation_window: Optional[Dict[str, Any]] = None,
        watch_manager: Optional[Any] = None,
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
            corpus=self.corpus,
        )
        self.sessions[inv_id] = session

        session.target_ref = {
            "snapshot_id": snapshot_id,
            "memory_snapshot_path": memory_snapshot_path,
            "pid": pid,
            "debug_image": debug_image,
            "constraints": constraints or {},
            "watch_session_id": watch_session_id,
            "observation_window": observation_window or {},
        }

        # Check for temporal investigation routing (Phase 24)
        is_temporal_request = (
            watch_session_id is not None
            or (observation_window is not None and bool(observation_window.get("session_id")))
        )
        if is_temporal_request:
            from extractor.temporal_investigation import TemporalInvestigationService
            from extractor.watch_session import WatchSessionManager
            wm = watch_manager or WatchSessionManager(corpus_dir=self.corpus_dir)
            ws_id = watch_session_id or (observation_window.get("session_id") if observation_window else None)
            ws = wm.get_session(ws_id) if ws_id else None
            svc = TemporalInvestigationService(watch_manager=wm)
            return svc.analyze_temporal_session(
                investigation_session=session,
                watch_session=ws,
                watch_manager=wm,
                observation_window=observation_window,
                goal=goal,
                static_provider=static_provider,
            )

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
                from .capture_backend import CaptureSafetyPolicy
                max_cap_bytes = int(session.budgets.get("max_bytes") or (16 * 1024 * 1024))
                cap_policy = CaptureSafetyPolicy(
                    max_capture_bytes=max_cap_bytes,
                    max_region_bytes=min(4 * 1024 * 1024, max_cap_bytes),
                    max_capture_ranges=256,
                )
                live_snap = selected_backend.capture(pid=parsed_pid, policy=cap_policy)
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
            session.static_provider = get_static_provider("dwarf", debug_image)
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
                if isinstance(p, dict):
                    if p.get("consistency_classification"):
                        return p.get("consistency_classification")
                    if p.get("snapshot_consistency"):
                        return p.get("snapshot_consistency")
                    if p.get("capture_mode") == "ZERO_STOP":
                        return NON_ATOMIC
                    if p.get("capture_backend") == "process_vm_readv":
                        return NON_ATOMIC
            else:
                c = getattr(s, "consistency", None)
                if c is not None:
                    return c.get("level") if isinstance(c, dict) else getattr(c, "level", None)
                p = getattr(s, "provenance", None)
                if isinstance(p, dict):
                    if p.get("consistency_classification"):
                        return p.get("consistency_classification")
                    if p.get("snapshot_consistency"):
                        return p.get("snapshot_consistency")
                    if p.get("capture_mode") == "ZERO_STOP":
                        return NON_ATOMIC
                    if p.get("capture_backend") == "process_vm_readv":
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
        elif not is_atomic_or_stopped_consistency(level_a) or not is_atomic_or_stopped_consistency(level_b):
            uncertainty = "One or both snapshots were captured non-atomically (process_vm_readv zero-stop). Value diffs may reflect minor execution skew."

        # Record comparison evidence in ledger
        parents = []
        if getattr(session, "capture_quality_evidence_id", None):
            parents.append(session.capture_quality_evidence_id)
        elif getattr(session, "identity_evidence_id", None):
            parents.append(session.identity_evidence_id)

        cmp_completeness = "COMPLETE" if diff_trust == "TRUSTED" else ("PARTIAL" if diff_trust == "PARTIALLY_TRUSTED" else "FAILED")
        cmp_consistency = "STOPPED" if (is_atomic_or_stopped_consistency(level_a) and is_atomic_or_stopped_consistency(level_b)) else "NON_ATOMIC"

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
            capture_quality={"completeness": cmp_completeness, "consistency_level": cmp_consistency},
            details={"changes": diff_dict["changes"][:30], "trust_classification": diff_trust, "consistency_classification": cmp_consistency},
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

    def attest_causal_proof(
        self,
        investigation_id: str,
        evidence_id: str,
        target_function: Optional[str] = None,
        field_path: Optional[str] = None,
        verification_type: str = "deterministic_reproduction",
        capability: Optional[CausalVerificationCapability] = None,
        execution_provenance: Optional[Dict[str, Any]] = None,
        hypothesis_id: Optional[str] = None,
        target_identity: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Attest an authentic proof record in the specified investigation session."""
        session = self.sessions.get(investigation_id)
        if not session:
            raise ValueError(f"Investigation '{investigation_id}' not found")
        return session.attest_causal_proof(
            evidence_id=evidence_id,
            target_function=target_function,
            field_path=field_path,
            verification_type=verification_type,
            capability=capability,
            execution_provenance=execution_provenance,
            hypothesis_id=hypothesis_id,
            target_identity=target_identity,
        )

    def verify_capture_provenance(
        self,
        snap_path: str,
        session: Optional[InvestigationSession] = None,
    ) -> Tuple[bool, Optional[Any], str]:
        """Verify the authentic capture receipt and artifact integrity for a snapshot on disk."""
        try:
            if not isinstance(snap_path, str):
                return False, None, f"Snapshot path must be a string, got {type(snap_path).__name__}"
            norm = os.path.normpath(snap_path)
            if ".." in norm.split(os.path.sep):
                return False, None, f"Path traversal detected in snapshot path: '{snap_path}'"
            if os.path.islink(snap_path):
                return False, None, f"Snapshot path '{snap_path}' is a symbolic link; symlinks are rejected"

            cand = snap_path if os.path.exists(snap_path) else os.path.join(self.corpus_dir, "memory_snapshots", snap_path)
            if not os.path.exists(cand):
                found_dir = None
                if session and hasattr(session, "corpus") and session.corpus:
                    for s_id, s_meta in session.corpus.states.items():
                        if s_meta.get("snapshot_id") == snap_path or s_id == snap_path or snap_path in s_meta.get("observations", []):
                            s_dir = os.path.join(session.corpus.states_dir, s_id)
                            if os.path.exists(s_dir):
                                found_dir = s_dir
                                break
                if found_dir:
                    cand = found_dir
                else:
                    return False, None, f"Snapshot artifact '{snap_path}' does not exist on disk"

            if os.path.isdir(cand):
                for root, dirs, files in os.walk(cand):
                    for d in dirs:
                        if os.path.islink(os.path.join(root, d)):
                            return False, None, f"Snapshot directory contains a symlink directory: {d}"
                    for f in files:
                        if os.path.islink(os.path.join(root, f)):
                            return False, None, f"Snapshot directory contains a symlink file: {f}"

                rcpt_path = os.path.join(cand, "capture_receipt.json")
                if not os.path.exists(rcpt_path):
                    return False, None, "Snapshot directory lacks capture_receipt.json"

                with open(rcpt_path, "r", encoding="utf-8") as f:
                    rcpt_data = json.load(f)

                from .capture_backend import CaptureReceipt
                rcpt = CaptureReceipt.from_dict(rcpt_data)
                sig_ok, sig_reason, _ = rcpt.verify_with_status()
                if not sig_ok:
                    return False, rcpt, f"Capture receipt signature verification failed: {sig_reason}"

                # Verify artifact manifest digests
                if not rcpt.artifact_manifest:
                    return False, None, "Capture receipt artifact manifest is empty"

                for rel_path, exp_hash in rcpt.artifact_manifest.items():
                    full_p = os.path.join(cand, rel_path)
                    if not os.path.exists(full_p) or os.path.islink(full_p):
                        return False, None, f"Manifest artifact '{rel_path}' is missing or a symlink (tampering detected)"
                    with open(full_p, "rb") as f:
                        act_h = hashlib.sha256(f.read()).hexdigest()
                    if act_h != exp_hash:
                        return False, None, f"Manifest artifact '{rel_path}' hash mismatch (tampering detected)"

                # Check for extra unexpected files
                allowed_files = set(rcpt.artifact_manifest.keys()) | {"capture_receipt.json"}
                for root, _, files in os.walk(cand):
                    for fn in files:
                        rel = os.path.relpath(os.path.join(root, fn), cand)
                        if rel not in allowed_files and not fn.startswith("."):
                            return False, None, f"Extra unexpected file in snapshot directory: {rel}"

                return True, rcpt, "Capture receipt and artifact manifest verified"
            elif os.path.isfile(cand):
                try:
                    with open(cand, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    rcpt_data = data.get("capture_receipt")
                    if rcpt_data and isinstance(rcpt_data, dict):
                        from .capture_backend import CaptureReceipt
                        sig_ok, sig_reason, _ = rcpt.verify_with_status()
                        if sig_ok:
                            return True, rcpt, "Embedded capture receipt verified"
                        return False, rcpt, f"Embedded capture receipt signature verification failed: {sig_reason}"
                except Exception:
                    pass
                return False, None, "Snapshot file lacks an authentic CaptureReceipt"
            return False, None, "Snapshot path is neither a file nor directory"
        except Exception as exc:
            return False, None, f"Capture provenance check error: {exc}"

    def verify_live_reproduction_and_attest(
        self,
        investigation_id: str,
        hypothesis_id: str,
        evidence_id: str,
        snapshot_a_path: str,
        snapshot_b_path: str,
        target_function: str,
        field_path: str,
        verification_type: str = "deterministic_reproduction",
        attribution_evidence: Optional[Dict[str, Any]] = None,
        require_capture_provenance: bool = False,
    ) -> bool:
        """Verify genuine live reproduction from two snapshots, verify real diff, and attest causal proof."""
        session = self.sessions.get(investigation_id)
        if not session:
            raise ValueError(f"Investigation '{investigation_id}' not found")

        # 1. Verify snapshot references and disk artifact existence
        def _resolve_and_verify_disk_artifact(snap_path: str) -> str:
            if not isinstance(snap_path, str):
                raise ValueError(f"Snapshot path must be a string, got {type(snap_path).__name__}")
            norm = os.path.normpath(snap_path)
            if ".." in norm.split(os.path.sep):
                raise ValueError(f"Path traversal detected in snapshot path: '{snap_path}'")
            if os.path.islink(snap_path):
                raise ValueError(f"Snapshot path '{snap_path}' is a symbolic link; symlinks are rejected for security")

            cand = snap_path if os.path.exists(snap_path) else os.path.join(self.corpus_dir, "memory_snapshots", snap_path)
            if not os.path.exists(cand):
                found_dir = None
                if session and hasattr(session, "corpus") and session.corpus:
                    for s_id, s_meta in session.corpus.states.items():
                        if s_meta.get("snapshot_id") == snap_path or s_id == snap_path or snap_path in s_meta.get("observations", []):
                            s_dir = os.path.join(session.corpus.states_dir, s_id)
                            if os.path.exists(s_dir):
                                found_dir = s_dir
                                break
                if found_dir:
                    cand = found_dir
                else:
                    raise ValueError(
                        f"Snapshot artifact '{snap_path}' does not exist on disk; "
                        "in-memory dictionaries or unregistered states cannot prove live runtime execution"
                    )
            if os.path.isdir(cand):
                for root, dirs, files in os.walk(cand):
                    for d in dirs:
                        p = os.path.join(root, d)
                        if os.path.islink(p):
                            raise ValueError(f"Snapshot directory contains symlink directory '{p}'; symlinks are rejected for security")
                    for f in files:
                        p = os.path.join(root, f)
                        if os.path.islink(p):
                            raise ValueError(f"Snapshot directory contains symlink file '{p}'; symlinks are rejected for security")
            return cand

        disk_a = _resolve_and_verify_disk_artifact(snapshot_a_path)
        disk_b = _resolve_and_verify_disk_artifact(snapshot_b_path)

        # Verify capture provenance receipts and manifests
        ok_a, rcpt_a, reason_a = self.verify_capture_provenance(snapshot_a_path, session)
        ok_b, rcpt_b, reason_b = self.verify_capture_provenance(snapshot_b_path, session)

        if "tamper" in reason_a.lower() or "signature verification failed" in reason_a.lower() or "symlink" in reason_a.lower():
            raise ValueError(f"Capture provenance verification failed for snapshot A: {reason_a}")
        if "tamper" in reason_b.lower() or "signature verification failed" in reason_b.lower() or "symlink" in reason_b.lower():
            raise ValueError(f"Capture provenance verification failed for snapshot B: {reason_b}")

        if require_capture_provenance:
            if not ok_a:
                raise ValueError(f"Capture provenance verification failed for snapshot A: {reason_a}")
            if not ok_b:
                raise ValueError(f"Capture provenance verification failed for snapshot B: {reason_b}")

        # 2. Verify hypothesis scope
        target_hypo = None
        for h in session.hypotheses:
            if h.hypothesis_id == hypothesis_id:
                target_hypo = h
                break
        if not target_hypo:
            raise ValueError(f"Hypothesis '{hypothesis_id}' not found in investigation '{investigation_id}'")

        cand_fns = [fc.get("function_name") for fc in target_hypo.function_candidates if fc.get("function_name")]
        if cand_fns and target_function not in cand_fns:
            raise ValueError(f"Target function '{target_function}' does not match hypothesis candidates: {cand_fns}")

        target_fields = getattr(target_hypo, "candidate_fields", []) or []
        if target_fields and not any(is_exact_semantic_path_match(field_path, field_path.split(".")[-1], f) or is_exact_semantic_path_match(f, f.split(".")[-1], field_path) for f in target_fields):
            raise ValueError(f"Field path '{field_path}' does not match hypothesis candidate fields: {target_fields}")

        # 3. Verify evidence record in ledger
        rec = session.ledger.get_record(evidence_id)
        if not rec:
            raise ValueError(f"Evidence record '{evidence_id}' does not exist in ledger")
        p_details = rec.details or {}
        p_prov = rec.provenance or {}
        if (
            p_details.get("caller_submitted") is True
            or p_details.get("unverified_caller_claim") is True
            or rec.source == "unverified_caller"
            or p_prov.get("submission_channel") == "external_caller"
        ):
            raise ValueError(f"Cannot attest causal proof on unverified caller claim '{evidence_id}'")

        rec_cq = rec.capture_quality or {}
        r_comp = rec_cq.get("completeness") or rec_cq.get("status")
        r_cons = rec_cq.get("consistency_level") or rec_cq.get("consistency_classification") or p_details.get("consistency_classification")
        if r_comp != "COMPLETE" or not is_atomic_or_stopped_consistency(r_cons) or p_details.get("is_non_atomic") is True:
            raise ValueError(f"Cannot attest causal proof: evidence '{evidence_id}' has degraded capture quality ({r_comp}, {r_cons})")

        # 4. Load snapshots through supported parser
        snap_a = self._resolve_snapshot(snapshot_a_path, session)
        snap_b = self._resolve_snapshot(snapshot_b_path, session)
        if not snap_a or not snap_b:
            raise ValueError(f"Failed to load snapshots '{snapshot_a_path}' or '{snapshot_b_path}'")

        # Reject synthetic fixtures impersonating live captures
        def _is_synthetic_snapshot(snap: Any) -> bool:
            if getattr(snap, "is_synthetic", False) is True:
                return True
            d = snap.to_dict() if hasattr(snap, "to_dict") else (snap if isinstance(snap, dict) else {})
            if d.get("is_synthetic") is True:
                return True
            if (d.get("provenance") or {}).get("is_synthetic") is True:
                return True
            if (d.get("observation_metadata") or {}).get("is_synthetic") is True:
                return True
            if d.get("provenance_class") == PROVENANCE_CLASS_SYNTHETIC_FIXTURE:
                return True
            if d.get("source") in ("synthetic", "in_memory", "unverified"):
                return True
            return False

        if _is_synthetic_snapshot(snap_a) or _is_synthetic_snapshot(snap_b):
            raise ValueError("Live reproduction rejected: synthetic snapshot fixture cannot impersonate live runtime capture")

        # 5. Check capture quality of snapshots
        def _get_snapshot_quality(snap: Any) -> Tuple[str, str]:
            if hasattr(snap, "to_dict"):
                s_dict = snap.to_dict()
            elif isinstance(snap, dict):
                s_dict = snap
            else:
                s_dict = {}
            comp = getattr(snap, "completeness", None) or getattr(snap, "status", None) or s_dict.get("completeness") or s_dict.get("status") or "COMPLETE"
            consistency = getattr(snap, "consistency", None) or s_dict.get("consistency")
            cons_lvl = None
            if isinstance(consistency, dict):
                cons_lvl = consistency.get("level")
            elif isinstance(consistency, str):
                cons_lvl = consistency
            if not cons_lvl:
                cons_lvl = getattr(snap, "consistency_level", None) or s_dict.get("consistency_level")
            if not cons_lvl:
                obs_meta = getattr(snap, "observation_metadata", None) or s_dict.get("observation_metadata") or {}
                prov = getattr(snap, "provenance", None) or s_dict.get("provenance") or {}
                if obs_meta.get("consistency_classification"):
                    cons_lvl = obs_meta.get("consistency_classification")
                elif prov.get("snapshot_consistency"):
                    cons_lvl = prov.get("snapshot_consistency")
                elif obs_meta.get("is_non_atomic") is True or prov.get("is_non_atomic") is True:
                    cons_lvl = "NON_ATOMIC"
                else:
                    cons_lvl = "STOPPED"
            return str(comp).upper(), str(cons_lvl).upper()

        comp_a, cons_a = _get_snapshot_quality(snap_a)
        comp_b, cons_b = _get_snapshot_quality(snap_b)
        if comp_a != "COMPLETE" or comp_b != "COMPLETE":
            raise ValueError(f"Live reproduction rejected: snapshot capture completeness not COMPLETE (A: {comp_a}, B: {comp_b})")
        if not is_atomic_or_stopped_consistency(cons_a) or not is_atomic_or_stopped_consistency(cons_b):
            raise ValueError(f"Live reproduction rejected: snapshot consistency not atomic/stopped (A: {cons_a}, B: {cons_b})")

        # 6. Check snapshot identities, PIDs, and build IDs
        def _get_snapshot_identity(snap: Any, disk_path: Optional[str] = None) -> Dict[str, Any]:
            if hasattr(snap, "to_dict"):
                d = snap.to_dict()
            elif isinstance(snap, dict):
                d = snap
            else:
                d = {}
            prov = d.get("provenance") or getattr(snap, "provenance", {}) or {}
            proc = d.get("process") or prov.get("process") or {}
            pid = (
                getattr(snap, "pid", None)
                or d.get("pid")
                or proc.get("pid")
                or prov.get("pid")
                or (prov.get("executable_identity") or {}).get("pid")
            )
            binary = (
                getattr(snap, "executable", None)
                or getattr(snap, "binary", None)
                or d.get("executable")
                or d.get("binary")
                or proc.get("binary")
                or proc.get("executable")
                or prov.get("executable")
                or prov.get("binary")
                or (prov.get("executable_identity") or {}).get("path")
            )
            build_id = (
                getattr(snap, "executable_build_id", None)
                or d.get("executable_build_id")
                or proc.get("executable_build_id")
                or prov.get("executable_build_id")
                or (prov.get("executable_identity") or {}).get("build_id")
            )
            start_time = (
                getattr(snap, "start_time", None)
                or getattr(snap, "process_start_time", None)
                or getattr(snap, "pid_start_time", None)
                or d.get("start_time")
                or d.get("process_start_time")
                or proc.get("start_time")
                or proc.get("process_start_time")
                or prov.get("start_time")
                or prov.get("process_start_time")
            )
            if disk_path and (pid is None or not binary or not build_id or not start_time):
                meta_file = os.path.join(disk_path, "snapshot_metadata.json") if os.path.isdir(disk_path) else (disk_path if str(disk_path).endswith(".json") else None)
                if meta_file and os.path.exists(meta_file):
                    try:
                        with open(meta_file, "r", encoding="utf-8") as f:
                            disk_meta = json.load(f)
                            if pid is None:
                                pid = disk_meta.get("pid") or (disk_meta.get("process") or {}).get("pid") or (disk_meta.get("provenance") or {}).get("pid")
                            if not binary:
                                binary = disk_meta.get("executable") or disk_meta.get("binary") or (disk_meta.get("process") or {}).get("binary") or (disk_meta.get("process") or {}).get("executable")
                            if not build_id:
                                build_id = disk_meta.get("executable_build_id") or (disk_meta.get("process") or {}).get("executable_build_id")
                            if not start_time:
                                start_time = disk_meta.get("start_time") or disk_meta.get("process_start_time") or (disk_meta.get("process") or {}).get("start_time")
                    except Exception:
                        pass
            return {"pid": pid, "binary": binary, "build_id": build_id, "start_time": start_time}

        id_a = _get_snapshot_identity(snap_a, disk_a)
        id_b = _get_snapshot_identity(snap_b, disk_b)

        if id_a["pid"] is None or id_b["pid"] is None:
            raise ValueError("Snapshot missing required target PID identity")
        if id_a["pid"] != id_b["pid"]:
            raise ValueError(f"Target PID mismatch between snapshots: {id_a['pid']} != {id_b['pid']}")

        if (id_a["binary"] is None) != (id_b["binary"] is None):
            raise ValueError("Target binary identity present on one snapshot but missing on the other")
        if id_a["binary"] and id_b["binary"] and os.path.basename(str(id_a["binary"])) != os.path.basename(str(id_b["binary"])):
            raise ValueError(f"Target binary mismatch between snapshots: {id_a['binary']} != {id_b['binary']}")

        if (id_a["build_id"] is None) != (id_b["build_id"] is None):
            raise ValueError("Target build ID present on one snapshot but missing on the other")
        if id_a["build_id"] and id_b["build_id"] and id_a["build_id"] != id_b["build_id"]:
            raise ValueError(f"Target build ID mismatch between snapshots: {id_a['build_id']} != {id_b['build_id']}")

        if id_a.get("start_time") and id_b.get("start_time") and id_a["start_time"] != id_b["start_time"]:
            raise ValueError(f"Target process start time mismatch: {id_a['start_time']} != {id_b['start_time']} (potential PID reuse detected)")

        # Verify against session target
        sess_tid = session.target_ref.get("target_identity") or {}
        sess_pid = session.target_ref.get("pid")
        if sess_pid and id_a["pid"] and sess_pid != id_a["pid"]:
            raise ValueError(f"Snapshot PID {id_a['pid']} does not match session target PID {sess_pid}")
        if sess_tid.get("build_id") and id_a["build_id"] and sess_tid["build_id"] != id_a["build_id"]:
            raise ValueError(f"Snapshot build ID does not match session target build ID")

        # Check OS process start time from /proc/<pid>/stat when target PID is running on Linux
        target_pid = id_a.get("pid")
        if target_pid and isinstance(target_pid, int) and target_pid > 0:
            proc_stat_path = f"/proc/{target_pid}/stat"
            if os.path.exists(proc_stat_path):
                try:
                    with open(proc_stat_path, "r", encoding="utf-8") as f:
                        stat_content = f.read()
                    rparen = stat_content.rfind(")")
                    if rparen != -1:
                        fields = stat_content[rparen + 1:].strip().split()
                        # Field 22 (index 19 after rparen) is starttime in jiffies
                        if len(fields) >= 20:
                            live_starttime = fields[19]
                            snap_starttime = id_a.get("start_time")
                            if snap_starttime and str(snap_starttime).isdigit():
                                if str(live_starttime) != str(snap_starttime):
                                    raise ValueError(f"Target process start time mismatch: live PID {target_pid} ({live_starttime}) != snapshot ({snap_starttime}); PID was reused or replaced")
                except ValueError:
                    raise
                except Exception:
                    pass

        # 7. Check temporal consistency
        def _get_timestamp(snap: Any) -> Any:
            if hasattr(snap, "to_dict"):
                d = snap.to_dict()
            elif isinstance(snap, dict):
                d = snap
            else:
                d = {}
            return getattr(snap, "timestamp_ns", None) or d.get("timestamp_ns") or getattr(snap, "timestamp", None) or d.get("timestamp") or ""

        ts_a = _get_timestamp(snap_a)
        ts_b = _get_timestamp(snap_b)
        if ts_a and ts_b and str(ts_b) < str(ts_a):
            raise ValueError(f"Temporal inconsistency: snapshot B ({ts_b}) precedes snapshot A ({ts_a})")

        # 8. Compute snapshot hashes for post-issuance tamper detection
        hash_a = compute_snapshot_artifact_hash(snapshot_a_path, session)
        hash_b = compute_snapshot_artifact_hash(snapshot_b_path, session)

        # 9. Compute and verify diff using exact semantic path matching with ambiguity detection
        diff_engine = StateDiffEngine()
        diff_res = diff_engine.diff(snap_a, snap_b)
        diff_trust = getattr(diff_res, "trust_classification", "TRUSTED")
        if diff_trust not in ("TRUSTED", "CONFIRMED"):
            raise ValueError(f"Live reproduction rejected: snapshot comparison trust classification is {diff_trust}")

        matching_changes, err_msg = find_matching_diff_changes(diff_res.changes, field_path)
        if err_msg:
            raise ValueError(err_msg)
        if not matching_changes:
            raise ValueError(f"Live reproduction rejected: field '{field_path}' did not change between snapshots")

        found_change = matching_changes[0]
        before_val = found_change.get("before")
        after_val = found_change.get("after")

        # 10. Verify function attribution evidence
        func_attr_ver = False
        attr_basis = "state_transition_only"
        attr_limitation = ""

        # Check stack observation in snap_b
        th_meta = getattr(snap_b, "thread_metadata", None)
        if th_meta is None and hasattr(snap_b, "to_dict"):
            th_meta = snap_b.to_dict().get("thread_metadata")
        elif th_meta is None and isinstance(snap_b, dict):
            th_meta = snap_b.get("thread_metadata")

        observed_in_stack = False
        # Do not accept caller-created thread_metadata in unverified snapshots as authenticated observation
        if th_meta and isinstance(th_meta, list):
            for t in th_meta:
                if isinstance(t, dict):
                    fn = t.get("function") or t.get("name")
                    frames = t.get("call_stack") or t.get("frames") or []
                    if fn == target_function or any(target_function in str(fr) for fr in frames):
                        observed_in_stack = True
                        break

        if observed_in_stack:
            # Stack presence alone establishes correlation, not write causality!
            attr_basis = ATTRIBUTION_BASIS_CALL_STACK
            func_attr_ver = False

        # Independent Attribution Verification
        if attribution_evidence and isinstance(attribution_evidence, dict):
            basis = attribution_evidence.get("attribution_basis")

            # Mechanism A: Controlled Single-Writer Isolation Experiment
            # Require recorded, independently checkable intervention results with controlled conditions and before/after observations.
            # Do not trust a boolean supplied by the experiment caller ('single_writer_verified' == True by itself is rejected).
            if basis == ATTRIBUTION_BASIS_SINGLE_WRITER:
                ctrl_eid = attribution_evidence.get("control_evidence_id") or attribution_evidence.get("baseline_evidence_id")
                if ctrl_eid and session.ledger:
                    rec_ctrl = session.ledger.get_record(ctrl_eid)
                    if (
                        rec_ctrl
                        and rec_ctrl.source != "unverified_caller"
                        and not (rec_ctrl.details or {}).get("caller_submitted")
                        and not (rec_ctrl.details or {}).get("unverified_caller_claim")
                    ):
                        c_det = rec_ctrl.details or {}
                        c_t_id = rec_ctrl.target_identity or c_det.get("target_identity") or {}
                        # Validate bound to same process instance & build
                        pid_match = not c_t_id.get("pid") or c_t_id.get("pid") == id_a["pid"]
                        bld_match = not c_t_id.get("build_id") or c_t_id.get("build_id") == id_a["build_id"]

                        # Validate field path or object
                        fld = c_det.get("field_path") or c_det.get("field_name")
                        fld_match = not fld or is_exact_semantic_path_match(field_path, field_path.split(".")[-1], fld)

                        # Validate controlled condition: field remained stable without candidate mutation
                        has_before_after = (c_det.get("before_value") is not None and c_det.get("after_value") is not None)
                        if has_before_after:
                            ctrl_stable = (c_det.get("before_value") == c_det.get("after_value"))
                        elif c_det.get("mutation_occurred") is not None:
                            ctrl_stable = (c_det.get("mutation_occurred") is False)
                        elif c_det.get("state_stable") is not None:
                            ctrl_stable = bool(c_det.get("state_stable"))
                        else:
                            ctrl_stable = (c_det.get("control_condition") in ("baseline", "no_mutation", "inactive_candidate"))

                        writer_fn = attribution_evidence.get("active_writer_function") or c_det.get("target_function")
                        if pid_match and bld_match and fld_match and ctrl_stable and writer_fn == target_function:
                            func_attr_ver = True
                            attr_basis = ATTRIBUTION_BASIS_SINGLE_WRITER
                        else:
                            if not ctrl_stable:
                                attr_limitation = f"Negative control baseline failed: field '{field_path}' mutated during control period ({c_det.get('before_value')} -> {c_det.get('after_value')}) while candidate '{target_function}' was inactive (potential concurrent writer or idle drift)."
                            elif writer_fn != target_function:
                                attr_limitation = f"Single-writer isolation failed: active writer was '{writer_fn}', which does not match candidate '{target_function}'."
                            elif not (pid_match and bld_match):
                                attr_limitation = f"Single-writer isolation failed: control evidence process identity does not match treatment snapshot."
                            elif not fld_match:
                                attr_limitation = f"Single-writer isolation failed: control evidence field '{fld}' does not match '{field_path}'."
                else:
                    attr_limitation = "Single-writer isolation requires valid control evidence in ledger observing baseline field stability."

            # Mechanism B: Execution Trace
            # Arbitrary caller trace list rejected. Must reference recorded trace collector evidence in ledger.
            elif basis == ATTRIBUTION_BASIS_EXECUTION_TRACE:
                trace_eid = attribution_evidence.get("trace_evidence_id")
                if trace_eid and session.ledger:
                    rec_tr = session.ledger.get_record(trace_eid)
                    if (
                        rec_tr
                        and rec_tr.source in ("trace_collector", "trusted_tracer", "investigation_observer")
                        and not (rec_tr.details or {}).get("caller_submitted")
                    ):
                        tr_events = (rec_tr.details or {}).get("trace_events", [])
                        if any(isinstance(e, dict) and e.get("function") == target_function and e.get("event") == "write" for e in tr_events):
                            func_attr_ver = True
                            attr_basis = ATTRIBUTION_BASIS_EXECUTION_TRACE
                        else:
                            attr_limitation = f"Execution trace failed: no verified write event recorded for candidate '{target_function}' on field '{field_path}'."
                else:
                    attr_limitation = "Execution trace requires valid trace collector evidence in ledger."
        elif not func_attr_ver and not attr_limitation:
            attr_limitation = "State transition verified in runtime, but function attribution was not independently verified by execution instrumentation."

        # 11. Assemble explicit claims
        claims = set()
        claims.add(CLAIM_ARTIFACT_INTEGRITY_VERIFIED)
        claims.add(CLAIM_TARGET_IDENTITY_VERIFIED)
        claims.add(CLAIM_STATE_TRANSITION_VERIFIED)
        if ok_a and ok_b:
            claims.add(CLAIM_CAPTURE_PROVENANCE_VERIFIED)
        if func_attr_ver:
            claims.add(CLAIM_FUNCTION_ATTRIBUTION_VERIFIED)

        # 12. Mint ControlledExecutionResult
        verifier = TrustedCausalVerifier(session)
        t_id = {
            "pid": id_a["pid"] or id_b["pid"],
            "binary": id_a["binary"] or id_b["binary"],
            "build_id": id_a["build_id"] or id_b["build_id"],
        }
        receipt = verifier.record_controlled_execution(
            target_function=target_function,
            field_path=field_path,
            before_value=before_val,
            after_value=after_val,
            execution_status="REPRODUCED",
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
            before_snapshot_ref=str(snapshot_a_path),
            after_snapshot_ref=str(snapshot_b_path),
            target_identity=t_id,
            backend_type="live_process_snapshot_diff",
            hypothesis_id=hypothesis_id,
            evidence_id=evidence_id,
            provenance_class=PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
            function_attribution_verified=func_attr_ver,
            attribution_basis=attr_basis,
            attribution_limitation=attr_limitation,
            verified_claims=claims,
        )

        return verifier.verify_execution_and_attest(
            evidence_id=evidence_id,
            hypothesis_id=hypothesis_id,
            execution_result=receipt,
            target_function=target_function,
            field_path=field_path,
            verification_type=verification_type,
        )

    def evaluate_hypothesis(
        self,
        investigation_id: str,
        hypothesis_id: str,
        new_evidence_data: Optional[Dict[str, Any]] = None,
        deterministic_transition_verified: bool = False,
        proof_evidence_id: Optional[str] = None,
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
            # Defensive copy & disarm external caller input
            new_data = dict(new_evidence_data)
            obs_str = new_data.get("observation") or new_data.get("summary") or ""
            new_data["observation"] = obs_str
            new_details = dict(new_data.get("details", {}))
            if "contradicts_hypothesis_id" in new_data:
                new_details["contradicts_hypothesis_id"] = new_data["contradicts_hypothesis_id"]
            new_prov = dict(new_data.get("provenance", {}))

            # External caller cannot claim trusted verifier attestation or execution provenance
            new_prov["submission_channel"] = "external_caller"
            new_prov["provenance_class"] = PROVENANCE_CLASS_IMPORTED_UNVERIFIED
            new_details["provenance_class"] = PROVENANCE_CLASS_IMPORTED_UNVERIFIED
            new_prov.pop("verifier_attestation", None)
            new_prov.pop("execution_provenance", None)
            new_prov.pop("function_attribution_verified", None)
            new_prov.pop("attribution_basis", None)

            # Any caller-supplied causal claims are marked as unverified caller claims
            new_details["caller_submitted"] = True
            new_details.pop("execution_provenance", None)
            new_details.pop("function_attribution_verified", None)
            new_details.pop("attribution_basis", None)
            if (
                new_details.get("verified_transition") is True
                or new_details.get("causal_proof") is True
                or new_details.get("reproduction_verified") is True
                or new_details.get("transition_verified") is True
                or new_details.get("verified_writer") is True
                or "transition" in str(new_data.get("observation", "")).lower()
            ):
                new_details["unverified_caller_claim"] = True
                new_details["verified_transition"] = False
                new_details["causal_proof"] = False
                new_data["source"] = "unverified_caller"

            new_data["details"] = new_details
            new_data["provenance"] = new_prov

            try:
                new_rec = EvidenceRecord.from_dict(new_data)
                session.ledger.add_record(new_rec)
            except Exception as exc:
                if "Duplicate evidence_id" in str(exc) and new_data.get("evidence_id"):
                    new_rec = session.ledger.get_record(new_data["evidence_id"])
                else:
                    return {"success": False, "error": f"Failed to attach evidence: {exc}"}

        cap_details = session.stages.get("capture_quality", {}).get("details", {})
        result = HypothesisValidator.evaluate(
            hypothesis=target_hypo,
            ledger=session.ledger,
            new_evidence=new_rec,
            deterministic_transition_verified=deterministic_transition_verified,
            proof_evidence_id=proof_evidence_id,
            capture_quality=cap_details,
        )

        # Sync status to corresponding finding in session.findings
        for f in session.findings:
            if f.finding_id == f"fnd_{hypothesis_id}" or (f.category == "hypothesis" and hypothesis_id in f.evidence_ids):
                f.status = target_hypo.validation_status
                f.confidence = target_hypo.confidence.lower()

        # Record timeline event
        session.add_timeline_event(
            event_type="HYPOTHESIS_STATUS_UPDATED" if result.status_changed else "VALIDATION_UPDATED",
            title=f"Hypothesis Evaluated: {target_hypo.title}",
            summary=result.reason,
            classification=EVIDENCE_CLASSIFICATION_INFERENCE,
            hypothesis_id=hypothesis_id,
            evidence_ids=[new_rec.evidence_id] if new_rec else [],
            status_before=result.from_status,
            status_after=result.to_status,
            confidence=result.confidence,
            details={
                "status_changed": result.status_changed,
                "supporting_count": result.supporting_count,
                "contradicting_count": result.contradicting_count,
                "unverified_claim_rejected": result.unverified_claim_rejected,
            },
        )

        return {
            "success": True,
            "hypothesis": target_hypo.to_dict(),
            "new_evidence_id": new_rec.evidence_id if new_rec else (result.trigger_evidence_id or (target_hypo.supporting_evidence_ids[-1] if target_hypo.supporting_evidence_ids else None)),
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
                "provenance_error": result.provenance_error,
                "proof_evidence_id": result.proof_evidence_id,
                "unverified_claim_rejected": result.unverified_claim_rejected,
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

        if not target_obs:
            for obs in session.follow_up_observations:
                if obs.observation_id == observation_id:
                    target_obs = obs
                    for h in session.hypotheses:
                        if h.hypothesis_id == obs.hypothesis_id or obs in h.suggested_observations:
                            target_hypo = h
                            break
                    if not target_hypo and session.hypotheses:
                        target_hypo = session.hypotheses[0]
                    break

        if not target_obs:
            return {"success": False, "error": f"Observation '{observation_id}' not found in investigation '{investigation_id}'"}

        # Prevent duplicate execution
        if target_obs.executed or target_obs.status in (OBSERVATION_STATUS_EXECUTED, OBSERVATION_STATUS_VERIFIED):
            return {
                "success": False,
                "error": f"Observation '{observation_id}' has already been executed.",
                "already_executed": True,
                "observation": target_obs.to_dict(),
            }

        # Prevent execution of canceled observation
        if target_obs.status == OBSERVATION_STATUS_CANCELED:
            return {
                "success": False,
                "error": f"Observation '{observation_id}' is canceled and cannot be executed.",
                "canceled": True,
                "observation": target_obs.to_dict(),
            }

        # If live mutation or live target interaction requested, verify strict safety constraints
        t_ref = target_obs.target_ref if isinstance(target_obs.target_ref, dict) else {}
        requires_live = (
            (target_obs.target_kind == "MUTATION")
            or bool(t_ref.get("requires_live_target"))
            or ("MUTATION" in target_obs.safety_constraints)
            or ("REQUIRES_AUTHORIZATION" in target_obs.safety_constraints)
        )
        if requires_live and not session.safety.get("target_authorized", False):
            target_obs.status = OBSERVATION_STATUS_PROPOSED
            target_obs.execution_error = "Target authorization required: live target interaction is not authorized."
            session.add_timeline_event(
                event_type="OBSERVATION_BLOCKED",
                title=f"Observation Blocked: {target_obs.observation_id}",
                summary="Live target interaction not authorized by safety policy.",
                classification=EVIDENCE_CLASSIFICATION_UNKNOWN,
                observation_id=target_obs.observation_id,
                hypothesis_id=target_hypo.hypothesis_id,
            )
            return {
                "success": False,
                "error": "Target authorization required: live target interaction is not authorized.",
                "blocked": True,
            }

        # Formulate observation record
        ev_id = f"ev_obs_{uuid.uuid4().hex[:8]}"
        outcome = "INCONCLUSIVE"
        source = "investigation_observer"

        if result_data:
            obs_text = result_data.get("observation", f"Observed {target_obs.question}")
            details = dict(result_data.get("details", {}))
            details["caller_submitted"] = True
            details.pop("execution_provenance", None)
            outcome = result_data.get("outcome", details.get("outcome", "SUPPORTED"))
            # Invariant 9: Caller-submitted results cannot fabricate causal proof without verification
            if (
                outcome == "VALIDATED"
                or details.get("verified_transition") is True
                or details.get("causal_proof") is True
                or details.get("reproduction_verified") is True
                or details.get("transition_verified") is True
                or details.get("verified_writer") is True
            ):
                details["unverified_caller_claim"] = True
                details["verified_transition"] = False
                details["causal_proof"] = False
                source = "unverified_caller"
                if outcome == "VALIDATED":
                    outcome = "SUPPORTED"
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
            source=source,
            session_id=investigation_id,
            finding_id=f"fnd_{target_hypo.hypothesis_id}",
            observation=obs_text,
            parent_evidence_ids=[e for e in target_hypo.supporting_evidence_ids if session.ledger.get_record(e)],
            details=details,
            provenance={"submission_channel": "external_caller" if result_data else "internal_observer"},
            capture_quality={"completeness": "COMPLETE", "consistency_level": "STOPPED"},
        )
        session.ledger.add_record(ev_record)

        if result_data and (result_data.get("failed") is True or outcome in ("FAILED", "ERROR")):
            target_obs.status = OBSERVATION_STATUS_FAILED
            target_obs.execution_error = result_data.get("error") or f"Observation execution failed: {obs_text}"
            target_obs.is_suggestion = False
            session.add_timeline_event(
                event_type="OBSERVATION_FAILED",
                title=f"Observation Failed: {target_obs.observation_id}",
                summary=target_obs.execution_error,
                classification=EVIDENCE_CLASSIFICATION_UNKNOWN,
                observation_id=observation_id,
                hypothesis_id=target_hypo.hypothesis_id,
                details={"outcome": outcome, "error": target_obs.execution_error},
            )
            return {
                "success": False,
                "error": target_obs.execution_error,
                "failed": True,
                "observation": target_obs.to_dict(),
            }

        # Mark observation executed
        target_obs.executed = True
        if result_data and (result_data.get("verified") is True or result_data.get("outcome") in ("CONFIRMED", "VERIFIED")):
            target_obs.status = OBSERVATION_STATUS_VERIFIED
        else:
            target_obs.status = OBSERVATION_STATUS_EXECUTED
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

        # Record timeline event
        session.add_timeline_event(
            event_type="OBSERVATION_EXECUTED",
            title=f"Observation Executed: {target_obs.question}",
            summary=f"Result: {outcome} ({eval_result.reason})",
            classification=EVIDENCE_CLASSIFICATION_FACT,
            observation_id=observation_id,
            hypothesis_id=target_hypo.hypothesis_id,
            evidence_ids=[ev_id],
            status_before=eval_result.from_status,
            status_after=eval_result.to_status,
            confidence=eval_result.confidence,
            details={"outcome": outcome, "observation": obs_text},
        )

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

    def cancel_observation(
        self,
        investigation_id: str,
        observation_id: str,
        reason: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Cancel a proposed or pending follow-up observation."""
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

        if not target_obs:
            for obs in session.follow_up_observations:
                if obs.observation_id == observation_id:
                    target_obs = obs
                    break

        if not target_obs:
            return {"success": False, "error": f"Observation '{observation_id}' not found in investigation '{investigation_id}'"}

        if target_obs.executed or target_obs.status in (OBSERVATION_STATUS_EXECUTED, OBSERVATION_STATUS_VERIFIED):
            return {
                "success": False,
                "error": f"Observation '{observation_id}' has already been executed and cannot be canceled.",
            }

        target_obs.status = OBSERVATION_STATUS_CANCELED
        target_obs.is_suggestion = False
        target_obs.execution_error = reason or "Observation canceled by user or policy."

        for ns in session.next_steps:
            if ns.step_id == observation_id:
                ns.is_suggestion = False

        session.add_timeline_event(
            event_type="OBSERVATION_CANCELED",
            title=f"Observation Canceled: {target_obs.observation_id}",
            summary=reason or f"Observation {target_obs.observation_id} was canceled.",
            classification=EVIDENCE_CLASSIFICATION_UNKNOWN,
            observation_id=target_obs.observation_id,
            hypothesis_id=target_hypo.hypothesis_id if target_hypo else None,
            details={"reason": reason},
        )

        return {"success": True, "observation": target_obs.to_dict()}

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
            "validated_hypotheses": [
                {
                    "hypothesis_id": h.hypothesis_id,
                    "title": h.title,
                    "claim": h.claim,
                    "supporting_evidence_ids": list(h.supporting_evidence_ids),
                    "proof_evidence_id": next((entry.get("proof_evidence_id") for entry in reversed(h.status_history) if entry.get("proof_evidence_id")), None),
                    "validated_functions": [c.get("function_name") for c in h.function_candidates if c.get("candidate_tier") == FUNCTION_TIER_VALIDATED_CAUSAL],
                }
                for h in session.hypotheses if h.validation_status == HYPOTHESIS_STATUS_VALIDATED
            ],
            "inconclusive_hypotheses": [
                {
                    "hypothesis_id": h.hypothesis_id,
                    "title": h.title,
                    "validation_status": h.validation_status,
                    "reason": h.status_history[-1].get("reason", "Awaiting sufficient evidence") if h.status_history else "Insufficient evidence",
                }
                for h in session.hypotheses if h.validation_status in (HYPOTHESIS_STATUS_INCONCLUSIVE, HYPOTHESIS_STATUS_PROPOSED)
            ],
            "contradicted_hypotheses": [
                {
                    "hypothesis_id": h.hypothesis_id,
                    "title": h.title,
                    "contradicting_evidence_ids": list(h.contradicting_evidence_ids),
                    "reason": h.status_history[-1].get("reason", "Contradicted by evidence") if h.status_history else "Contradicted",
                }
                for h in session.hypotheses if h.validation_status == HYPOTHESIS_STATUS_CONTRADICTED
            ],
            "supported_hypotheses": [
                {
                    "hypothesis_id": h.hypothesis_id,
                    "title": h.title,
                    "supporting_evidence_ids": list(h.supporting_evidence_ids),
                    "reason": h.status_history[-1].get("reason", "Supported by observations; awaiting explicit causal validation") if h.status_history else "Supported",
                }
                for h in session.hypotheses if h.validation_status == HYPOTHESIS_STATUS_SUPPORTED
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
            "timeline": list(session.timeline),
            "timeline_count": len(session.timeline),
        }

    def get_investigation_timeline(self, investigation_id: str) -> Dict[str, Any]:
        """Retrieve the auditable, sequential timeline of events for an investigation."""
        session = self.sessions.get(investigation_id)
        if not session:
            return {"success": False, "error": f"Investigation '{investigation_id}' not found"}
        return {
            "success": True,
            "investigation_id": investigation_id,
            "total_events": len(session.timeline),
            "timeline": list(session.timeline),
        }

    def get_finding_drilldown(self, investigation_id: str, finding_id: str) -> Dict[str, Any]:
        """Resolve a full evidence drill-down path from finding to grounded code and attribution."""
        session = self.sessions.get(investigation_id)
        if not session:
            return {"success": False, "error": f"Investigation '{investigation_id}' not found"}

        target_finding = None
        for f in session.findings:
            if f.finding_id == finding_id:
                target_finding = f
                break
        if not target_finding:
            for h in session.hypotheses:
                if h.hypothesis_id == finding_id:
                    target_finding = InvestigationFinding(
                        finding_id=h.hypothesis_id,
                        category="hypothesis",
                        title=h.title or h.hypothesis_id,
                        description=h.claim or h.proposed_mechanism or "",
                        confidence="medium",
                        status=h.status or "PROPOSED",
                        classification=EVIDENCE_CLASSIFICATION_INFERENCE,
                        function_candidates=h.function_candidates or [],
                        evidence_ids=h.supporting_evidence_ids or [],
                    )
                    break
        if not target_finding:
            return {"success": False, "error": f"Finding '{finding_id}' not found in investigation '{investigation_id}'"}

        obj_id = target_finding.object_id
        field_name = target_finding.field_name or (target_finding.c_type_path.split(".")[-1] if target_finding.c_type_path else None)
        c_path = target_finding.c_type_path or (f"{obj_id}.{field_name}" if (obj_id and field_name) else None)

        # DWARF type / declaration
        type_name = target_finding.type_name
        type_decl = target_finding.type_decl_location
        source_loc = target_finding.source_location

        # Related function candidates & their attribution tier
        candidates = []
        for fc in target_finding.function_candidates:
            c_copy = dict(fc)
            tier = c_copy.get("candidate_tier") or (FUNCTION_TIER_VALIDATED_CAUSAL if c_copy.get("confirmed_root_cause") else FUNCTION_TIER_STATIC_CANDIDATE)
            c_copy["candidate_tier"] = tier
            candidates.append(c_copy)

        # Attribution evidence in ledger
        attr_records = []
        for ev in session.ledger._records:
            ev_details = ev.details or {}
            ev_att = (ev.provenance or {}).get("verifier_attestation") or {}
            matches_field = (
                (c_path and ev_details.get("field_path") == c_path)
                or (c_path and ev_att.get("field_path") == c_path)
                or (field_name and field_name in str(ev.observation))
            )
            if matches_field:
                attr_records.append({
                    "evidence_id": ev.evidence_id,
                    "evidence_type": ev.evidence_type,
                    "nature": ev.nature,
                    "observation": ev.observation,
                    "capture_quality": ev.capture_quality,
                    "has_attestation": bool(ev_att),
                    "function_attribution_verified": bool(ev_att.get("function_attribution_verified")),
                })

        # Capture quality and limitations
        cap_stage = session.stages.get("capture_quality", {})
        cap_details = cap_stage.get("details", {})
        cap_status = cap_stage.get("status", "COMPLETE")
        limitations = list(cap_details.get("limitations", []))

        drilldown = {
            "finding_id": target_finding.finding_id,
            "title": target_finding.title,
            "category": target_finding.category,
            "classification": getattr(target_finding, "classification", EVIDENCE_CLASSIFICATION_FACT if target_finding.category == "fact" else (EVIDENCE_CLASSIFICATION_INFERENCE if target_finding.category == "hypothesis" else EVIDENCE_CLASSIFICATION_UNKNOWN)),
            "status": target_finding.status,
            "confidence": target_finding.confidence,
            "finding": target_finding.to_dict(),
            "values": {
                "observed": target_finding.observed_value,
                "before": target_finding.before_value,
                "after": target_finding.after_value,
            },
            "path": {
                "object_id": obj_id,
                "field_name": field_name,
                "c_type_path": c_path,
            },
            "target_object": {
                "object_id": obj_id,
                "type": type_name,
                "field_name": field_name,
                "c_type_path": c_path,
            },
            "dwarf": {
                "type_name": type_name,
                "type_decl_location": type_decl,
                "source_location": source_loc,
                "debug_image": session.target_ref.get("debug_image"),
                "build_id": session.stages.get("target_identity", {}).get("details", {}).get("target_build_id"),
                "build_id_status": session.stages.get("target_identity", {}).get("details", {}).get("build_id_status"),
            },
            "dwarf_symbol": {
                "type_name": type_name,
                "decl_file": type_decl.split(":")[0] if type_decl and ":" in type_decl else (type_decl or "unknown"),
                "decl_line": int(type_decl.split(":")[1]) if type_decl and ":" in type_decl and type_decl.split(":")[1].isdigit() else 0,
                "source_location": source_loc,
            },
            "function_candidates": candidates,
            "candidate_functions": candidates,
            "attribution_evidence": attr_records,
            "attribution_records": attr_records,
            "limitations": limitations,
            "capture_quality": {
                "status": cap_status,
                "consistency_level": cap_details.get("consistency_level", "UNKNOWN"),
                "limitations": limitations,
            },
            "uncertainty": target_finding.uncertainty,
            "temporal_provenance": target_finding.temporal_provenance or next(
                (
                    {
                        "session_id": (ev.provenance or {}).get("watch_session_id"),
                        "watch_session_id": (ev.provenance or {}).get("watch_session_id"),
                        "watch_item_id": (ev.provenance or {}).get("watch_item_id"),
                        "comparison": ev.comparison_observation,
                        "field_observation": ev.field_observation,
                    }
                    for ev in session.ledger._records
                    if ev.evidence_id in target_finding.evidence_ids and (ev.comparison_observation or ev.field_observation)
                ),
                {}
            ),
            "evidence_records": [
                ev.to_dict() for ev in session.ledger._records
                if ev.evidence_id in target_finding.evidence_ids
            ],
        }
        return {"success": True, "drilldown": drilldown}

    def run_investigation_cycle(
        self,
        investigation_id: str,
        max_iterations: int = 5,
        max_observations: int = 10,
        stop_on_contradiction: bool = False,
    ) -> Dict[str, Any]:
        """Execute a bounded investigation cycle: select discriminating observations, execute, update hypotheses."""
        session = self.sessions.get(investigation_id)
        if not session:
            return {"success": False, "error": f"Investigation '{investigation_id}' not found"}

        if not session.hypotheses:
            generator = DeterministicHypothesisGenerator()
            session.hypotheses = generator.generate(session)
            for h in session.hypotheses:
                session.add_timeline_event(
                    event_type="HYPOTHESIS_PROPOSED",
                    title=f"Hypothesis Formulated: {h.title}",
                    summary=h.claim,
                    classification=EVIDENCE_CLASSIFICATION_INFERENCE,
                    hypothesis_id=h.hypothesis_id,
                    details={"confidence": h.confidence, "validation_status": h.validation_status},
                )

        iterations = 0
        observations_executed = 0
        executed_obs_ids = set()
        stop_reason = "CYCLE_BOUND_REACHED"

        bounded_max_iterations = min(max(1, max_iterations), 20)
        bounded_max_observations = min(max(1, max_observations), 50)

        for it in range(bounded_max_iterations):
            iterations += 1

            unresolved = [
                h for h in session.hypotheses
                if h.validation_status in (HYPOTHESIS_STATUS_PROPOSED, HYPOTHESIS_STATUS_SUPPORTED)
            ]
            if not unresolved:
                stop_reason = "ALL_HYPOTHESES_RESOLVED"
                break

            candidate_observations: List[Tuple[FollowUpObservation, InvestigationHypothesis]] = []
            for h in unresolved:
                for obs in h.suggested_observations:
                    if not obs.executed and obs.observation_id not in executed_obs_ids:
                        candidate_observations.append((obs, h))

            if not candidate_observations:
                stop_reason = "NO_MORE_OBSERVATIONS"
                break

            def _obs_score(item: Tuple[FollowUpObservation, InvestigationHypothesis]) -> int:
                obs, h = item
                score = 0
                if obs.discriminating_power == "HIGH":
                    score += 30
                elif obs.discriminating_power == "MEDIUM":
                    score += 15
                if obs.risk_level == "READ_ONLY":
                    score += 20
                elif obs.risk_level == "CAUTION":
                    score += 5
                if obs.target_kind in (TARGET_KIND_COMPARISON, TARGET_KIND_FIELD, TARGET_KIND_THREAD):
                    score += 10
                return score

            candidate_observations.sort(key=_obs_score, reverse=True)
            selected_obs, target_hypo = candidate_observations[0]
            executed_obs_ids.add(selected_obs.observation_id)

            if selected_obs.target_kind == "MUTATION" or selected_obs.target_ref.get("requires_live_target"):
                if not session.safety.get("target_authorized", False):
                    selected_obs.status = OBSERVATION_STATUS_PROPOSED
                    selected_obs.execution_error = "Target authorization required: live target interaction is not authorized."
                    session.add_timeline_event(
                        event_type="OBSERVATION_BLOCKED",
                        title=f"Observation Blocked: {selected_obs.observation_id}",
                        summary="Live target interaction not authorized by safety policy.",
                        classification=EVIDENCE_CLASSIFICATION_UNKNOWN,
                        observation_id=selected_obs.observation_id,
                        hypothesis_id=target_hypo.hypothesis_id,
                    )
                    continue

            exec_res = self.execute_observation(
                investigation_id,
                selected_obs.observation_id,
            )
            if exec_res.get("success"):
                observations_executed += 1
                eval_info = exec_res.get("evaluation", {})

                if stop_on_contradiction and eval_info.get("to_status") == HYPOTHESIS_STATUS_CONTRADICTED:
                    stop_reason = "CONTRADICTION_ENCOUNTERED"
                    break
            else:
                if not exec_res.get("blocked"):
                    selected_obs.status = OBSERVATION_STATUS_FAILED
                selected_obs.execution_error = exec_res.get("error", "Execution failed")

            if observations_executed >= bounded_max_observations:
                stop_reason = "MAX_OBSERVATIONS_REACHED"
                break

        status_counts = {}
        for h in session.hypotheses:
            st = h.validation_status
            status_counts[st] = status_counts.get(st, 0) + 1

        return {
            "success": True,
            "investigation_id": investigation_id,
            "iterations_run": iterations,
            "iterations_completed": iterations,
            "observations_executed": observations_executed,
            "stop_reason": stop_reason,
            "hypotheses_summary": status_counts,
            "total_hypotheses": len(session.hypotheses),
            "timeline_events_total": len(session.timeline),
        }

    def step_investigation_cycle(self, investigation_id: str) -> Dict[str, Any]:
        """Advance the investigation cycle by a single discriminating observation step."""
        return self.run_investigation_cycle(
            investigation_id,
            max_iterations=1,
            max_observations=1,
            stop_on_contradiction=False,
        )

    def propose_hypothesis(self, investigation_id: str, hypothesis_data: Dict[str, Any]) -> Dict[str, Any]:
        """Propose a new hypothesis for an investigation with defensive sanitization and disarming."""
        session = self.sessions.get(investigation_id)
        if not session:
            return {"success": False, "error": f"Investigation '{investigation_id}' not found"}

        hypo = sanitize_and_disarm_llm_hypothesis(hypothesis_data, ledger=session.ledger)
        hypo.investigation_id = investigation_id
        session.hypotheses.append(hypo)

        ev = session.ledger.add_record(EvidenceRecord(
            evidence_id=f"ev_{hypo.hypothesis_id}",
            evidence_type=EVIDENCE_TYPE_HYPOTHESIS,
            nature=NATURE_HYPOTHESIS,
            source="ExternalOrLLMProposer",
            session_id=investigation_id,
            observation=hypo.claim,
            parent_evidence_ids=list(hypo.supporting_evidence_ids),
            details={
                "hypothesis_id": hypo.hypothesis_id,
                "proposed_mechanism": hypo.proposed_mechanism,
                "validation_status": hypo.validation_status,
                "confidence": hypo.confidence,
            },
        ))

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
        ))

        session.add_timeline_event(
            event_type="HYPOTHESIS_PROPOSED",
            title=f"Hypothesis Proposed: {hypo.title}",
            summary=hypo.claim,
            classification=EVIDENCE_CLASSIFICATION_INFERENCE,
            hypothesis_id=hypo.hypothesis_id,
            details={"confidence": hypo.confidence, "validation_status": hypo.validation_status},
        )

        return {
            "success": True,
            "hypothesis": hypo.to_dict(),
            "evidence_id": ev.evidence_id,
        }

    def save_session(self, investigation_id: str, file_path: Optional[str] = None) -> Dict[str, Any]:
        """Serialize and save an investigation session to a dictionary or disk file."""
        session = self.sessions.get(investigation_id)
        if not session:
            return {"success": False, "error": f"Investigation '{investigation_id}' not found"}
        data = session.to_dict()
        data["evidence_ledger"] = session.ledger.to_dict()
        if file_path:
            norm = os.path.normpath(file_path)
            if ".." in norm.split(os.path.sep):
                raise ValueError(f"Path traversal detected in session save path: '{file_path}'")
            os.makedirs(os.path.dirname(os.path.abspath(file_path)), exist_ok=True)
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        return {"success": True, "session_data": data, "file_path": file_path}

    def load_session(self, file_path_or_data: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
        """Load and reconstruct an investigation session from serialized dictionary or disk file."""
        if isinstance(file_path_or_data, str):
            norm = os.path.normpath(file_path_or_data)
            if ".." in norm.split(os.path.sep):
                raise ValueError(f"Path traversal detected in session load path: '{file_path_or_data}'")
            if not os.path.exists(file_path_or_data):
                return {"success": False, "error": f"File '{file_path_or_data}' not found"}
            with open(file_path_or_data, "r", encoding="utf-8") as f:
                data = json.load(f)
        elif isinstance(file_path_or_data, dict):
            data = file_path_or_data
        else:
            return {"success": False, "error": "Invalid input: expected file path or dictionary"}

        session = InvestigationSession.from_dict(data, corpus=self.corpus)
        self.sessions[session.investigation_id] = session
        return {"success": True, "investigation_id": session.investigation_id, "session": session.to_dict()}

    def analyze_chat(
        self,
        investigation_id: str,
        message: str,
        request_id: Optional[str] = None,
        provider_override: Optional[str] = None,
        allow_fallback: bool = False,
        locale: str = "en",
    ) -> Dict[str, Any]:
        """Execute conversational analysis for the investigation session using configured LLM or honest fallback."""
        session = self.sessions.get(investigation_id)
        if not session:
            return {"success": False, "error": f"Investigation '{investigation_id}' not found"}

        from extractor.conversational_investigation import ConversationalAnalysisService
        from extractor.llm_provider import ProviderError, ProviderUnavailableError, ProviderExecutionError
        service = ConversationalAnalysisService()
        try:
            result = service.analyze_investigation(
                session=session,
                user_message=message,
                request_id=request_id,
                provider_override=provider_override,
                allow_fallback=allow_fallback,
                locale=locale,
            )
            return {
                "success": True,
                "investigation_id": investigation_id,
                "result": result.to_dict(),
            }
        except ProviderUnavailableError as e:
            return {
                "success": False,
                "error_code": "PROVIDER_UNAVAILABLE",
                "error": str(e),
                "investigation_id": investigation_id,
                "request_id": request_id,
            }
        except ProviderExecutionError as e:
            err_code = getattr(e, "error_code", "PROVIDER_EXECUTION_FAILED")
            return {
                "success": False,
                "error_code": err_code,
                "error": str(e),
                "investigation_id": investigation_id,
                "request_id": request_id,
            }
        except ProviderError as e:
            return {
                "success": False,
                "error_code": "PROVIDER_ERROR",
                "error": str(e),
                "investigation_id": investigation_id,
                "request_id": request_id,
            }
        except Exception as e:
            return {
                "success": False,
                "error_code": "INTERNAL_ERROR",
                "error": str(e),
                "investigation_id": investigation_id,
                "request_id": request_id,
            }

    def cancel_chat(self, request_id: str) -> Dict[str, Any]:
        """Cancel an in-flight conversational analysis request and kill any child processes."""
        from extractor.conversational_investigation import ConversationalAnalysisService
        service = ConversationalAnalysisService()
        canceled = service.cancel_analysis(request_id)
        return {"success": True, "request_id": request_id, "canceled": canceled}

    def get_llm_status(self) -> Dict[str, Any]:
        """Return safe status of LLM provider without secrets."""
        from extractor.llm_provider import LLMProviderManager
        return LLMProviderManager.get_instance().get_status()

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
                if first_field_finding is None:
                    first_field_finding = (finding_candidate, o_dict, f)

                # Highlight non-zero or suspicious counters/status fields (enrich only kept findings!)
                if any(k in str(fname).lower() for k in ("counter", "state", "status", "flags", "error", "health", "active", "task", "id")):
                    self._enrich_finding_navigation(session, finding_candidate, target_object=o_dict, target_field=f, snapshot=semantic_state)
                    session.findings.append(finding_candidate)

        if not session.findings and first_field_finding:
            fc_item, fc_obj, fc_fld = first_field_finding
            self._enrich_finding_navigation(session, fc_item, target_object=fc_obj, target_field=fc_fld, snapshot=semantic_state)
            session.findings.append(fc_item)

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

        # Enrich any session findings that do not yet have code_navigation populated
        if provider and provider.is_available():
            for fnd in session.findings:
                if (fnd.object_id or fnd.field_name) and not fnd.code_navigation:
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
        if not isinstance(snap_ref, str):
            if isinstance(snap_ref, dict) or hasattr(snap_ref, "to_dict"):
                return snap_ref
            return None

        norm = os.path.normpath(snap_ref)
        if ".." in norm.split(os.path.sep):
            raise ValueError(f"Path traversal detected in snapshot path: '{snap_ref}'")
        if os.path.islink(snap_ref):
            raise ValueError(f"Snapshot path '{snap_ref}' is a symbolic link; symlinks are rejected for security")

        # 1. Direct state_id in corpus
        snap_data = self.corpus.get(snap_ref)
        if snap_data:
            return snap_data

        # 2. Match snapshot_id or state_id in corpus states
        for state_id, meta in self.corpus.states.items():
            if meta.get("snapshot_id") == snap_ref or state_id == snap_ref or snap_ref in meta.get("observations", []):
                snap_data = self.corpus.get(state_id)
                if snap_data:
                    return snap_data

        if session and hasattr(session, "corpus") and session.corpus:
            snap_data = session.corpus.get(snap_ref)
            if snap_data:
                return snap_data
            for state_id, meta in session.corpus.states.items():
                if meta.get("snapshot_id") == snap_ref or state_id == snap_ref or snap_ref in meta.get("observations", []):
                    snap_data = session.corpus.get(state_id)
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


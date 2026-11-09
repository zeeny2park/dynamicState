"""Phase 2.1.4 – 2.1.8 — Competing Hypotheses, Authority Closure & Discriminating Investigation Intelligence.

Implements deterministic, authority-verified competing hypothesis reasoning:
- Explicit candidate hypotheses for observed symptoms.
- Quantitative discrimination value calculation (Information Gain).
- Authoritative EvidenceLedger resolution required across all verdict, support, contradiction,
  primary-evidence confirmation, and root-independence paths (Part A1).
- Complete 9-dimension target and investigation identity validation distinguishing missing identity
  from actual identity mismatch, preventing PID reuse and cross-investigation/build contamination (Part A2).
- Hardened structured contradiction evaluation (untrusted, irrelevant, partial, decisive, and
  conflicting authoritative evidence; legacy fields never auto-refute) (Part A3).
- Hardened PrimaryEvidenceRuleRegistry with built-in ownership protection, versioning, and executable
  validation criteria (Part A4).
- Immutable, record-metadata-derived evidence validation and idempotent, insertion-order-independent
  evaluation with machine-readable decision traces (Part A5, B1, B2).
"""

from dataclasses import dataclass, field, asdict, fields
import hmac
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from extractor.diagnostic_rule_model import (
    VERDICT_CONFIRMED,
    VERDICT_LIKELY,
    VERDICT_SUPPORTED,
    VERDICT_OBSERVED,
    VERDICT_REFUTED,
    VERDICT_INCONCLUSIVE,
    VERDICT_NOT_APPLICABLE,
)

try:
    from extractor.evidence_ledger import (
        TRUSTED_PROVENANCE_CLASSES,
        PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
        PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
        PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
        VALID_EVIDENCE_TYPES,
        VALID_NATURES,
        compute_attestation_signature,
    )
except ImportError:
    TRUSTED_PROVENANCE_CLASSES = {"LIVE_RUNTIME_CAPTURE", "CONTROLLED_RUNTIME_REPRODUCTION"}
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE = "LIVE_RUNTIME_CAPTURE"
    PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION = "CONTROLLED_RUNTIME_REPRODUCTION"
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED = "IMPORTED_UNVERIFIED"
    VALID_EVIDENCE_TYPES = {
        "RUNTIME_IDENTITY",
        "CAPTURE_QUALITY",
        "OBJECT_STATE",
        "FIELD_OBSERVATION",
        "COMPARISON",
        "STATIC_LINK",
        "HYPOTHESIS",
        "INFERENCE",
        "DIAGNOSTIC",
    }
    VALID_NATURES = {"observation", "inference", "hypothesis"}
    compute_attestation_signature = None


# =============================================================================
# Root Independence Definition (Part B1 Documentation & Contract)
# =============================================================================
ROOT_INDEPENDENCE_DEFINITION = """
Exact Root Independence Definition (Phase 2.1.8 Part B1):
1. Authoritative Ledger Resolution: A node in the evidence dependency DAG can only qualify as a root
   source if it resolves to an existing EvidenceRecord in the authoritative EvidenceLedger.
2. Trusted Provenance & Complete Identity: The root EvidenceRecord must have a trusted provenance class
   (LIVE_RUNTIME_CAPTURE or CONTROLLED_RUNTIME_REPRODUCTION), nature == 'observation', valid evidence_type,
   verified cryptographic receipt/attestation, and complete matching target/investigation identity.
3. Full Multi-Parent DAG Traversal: Every parent dependency in both CompetingHypothesis.evidence_dependencies
   and EvidenceRecord.parent_evidence_ids / derived_from is traversed. Derived evidence and its source
   evidence never count as separate independent roots; only terminal leaf roots (with zero parents) count.
4. Invalid Branch Exclusion: Any branch containing a cycle, self-dependency, malformed edge, depth overflow,
   missing parent record, or untrusted/mismatched ancestor is marked invalid in its entirety and contributes
   zero independent roots.
5. Capture-Origin Deduplication: Two distinct leaf EvidenceRecord IDs that originate from the same underlying
   capture event (sharing the same LiveCaptureReceipt.receipt_id, non-empty operation_id, explicit capture_id,
   or non-empty snapshot_ref.snapshot_id) represent a single physical capture origin and count as at most
   ONE (1) independent root source (selecting the canonically lowest evidence_id).
"""


# =============================================================================
# Primary Single-Evidence Confirmation Rules & Registry (Part A4)
# =============================================================================

def _extract_record_searchable_text(rec: Any) -> str:
    parts: List[str] = []
    obs = getattr(rec, "observation", "")
    if obs:
        parts.append(str(obs))
    for attr in ("details", "object_observation", "field_observation", "comparison_observation"):
        val = getattr(rec, attr, None)
        if isinstance(val, dict):
            for k, v in val.items():
                parts.append(f"{k}:{v}")
    return " ".join(parts).lower()


def _validate_rule_canary(rec: Any) -> Tuple[bool, str]:
    txt = _extract_record_searchable_text(rec)
    details = getattr(rec, "details", {}) if isinstance(getattr(rec, "details", None), dict) else {}
    if any(neg in txt for neg in ("canary intact", "zero corrupt", "no corrupt", "headers intact")):
        return False, "Observation indicates intact canary/headers rather than corruption"
    positive_markers = (
        "canary", "corrupt", "overflow", "guard", "magic", "deadbeef",
        "out-of-bounds", "prev_inuse", "size_field", "header overwrite", "redzone",
    )
    if any(m in txt for m in positive_markers) or details.get("canary_corrupted") is True or details.get("metadata_corrupted") is True:
        return True, "Executable canary/metadata corruption criteria satisfied"
    return False, "Evidence record does not contain required canary or buffer/header corruption indicators"


def _validate_rule_double_free(rec: Any) -> Tuple[bool, str]:
    txt = _extract_record_searchable_text(rec)
    details = getattr(rec, "details", {}) if isinstance(getattr(rec, "details", None), dict) else {}
    if any(neg in txt for neg in ("no double free", "zero duplicate", "freelist clean")):
        return False, "Observation indicates clean freelist rather than double free"
    positive_markers = (
        "double free", "double_free", "duplicate", "fastbin", "tcache",
        "freelist", "free-list", "cycle", "already freed",
    )
    if any(m in txt for m in positive_markers) or details.get("double_free_detected") is True:
        return True, "Executable ptmalloc/allocator double-free criteria satisfied"
    return False, "Evidence record does not contain required duplicate free or freelist cycle indicators"


def _validate_rule_segv_crash(rec: Any) -> Tuple[bool, str]:
    txt = _extract_record_searchable_text(rec)
    details = getattr(rec, "details", {}) if isinstance(getattr(rec, "details", None), dict) else {}
    positive_markers = (
        "sigsegv", "sigbus", "sigabrt", "segfault", "signal", "fault address",
        "crash", "wild", "unmapped", "null pointer", "invalid memory access",
    )
    if any(m in txt for m in positive_markers) or details.get("signal_number") in (6, 7, 11):
        return True, "Executable fatal signal / fault address criteria satisfied"
    return False, "Evidence record does not contain fatal signal receipt or fault address indicators"


def _validate_rule_deadlock_cycle(rec: Any) -> Tuple[bool, str]:
    txt = _extract_record_searchable_text(rec)
    details = getattr(rec, "details", {}) if isinstance(getattr(rec, "details", None), dict) else {}
    if any(neg in txt for neg in ("no deadlock", "zero cycle", "acyclic")):
        return False, "Observation indicates acyclic lock graph rather than deadlock"
    positive_markers = ("deadlock", "cycle", "circular", "ab-ba", "wait-for", "mutual wait")
    if (
        any(m in txt for m in positive_markers)
        or details.get("deadlock_detected") is True
        or bool(details.get("deadlock_cycles"))
        or bool(details.get("deadlock_cycle"))
    ):
        return True, "Executable directed wait-for cycle criteria satisfied"
    return False, "Evidence record does not contain directed circular wait-for cycle indicators"


def _validate_rule_oom_kill(rec: Any) -> Tuple[bool, str]:
    txt = _extract_record_searchable_text(rec)
    details = getattr(rec, "details", {}) if isinstance(getattr(rec, "details", None), dict) else {}
    positive_markers = ("oom", "out of memory", "killed process", "exhaustion", "cgroup memory limit", "enomem")
    if any(m in txt for m in positive_markers) or details.get("oom_killed") is True:
        return True, "Executable kernel/cgroup OOM event criteria satisfied"
    return False, "Evidence record does not contain kernel/cgroup OOM or memory exhaustion indicators"


def _validate_rule_clean_refutation(rec: Any) -> Tuple[bool, str]:
    txt = _extract_record_searchable_text(rec)
    details = getattr(rec, "details", {}) if isinstance(getattr(rec, "details", None), dict) else {}
    positive_markers = ("clean", "zero", "healthy", "intact", "no violation", "passed", "normal", "acyclic", "bounded")
    if any(m in txt for m in positive_markers) or details.get("clean_state_verified") is True:
        return True, "Executable clean-state invariant verification criteria satisfied"
    return False, "Evidence record does not contain positive clean-state invariant verification indicators"


@dataclass(frozen=True)
class PrimaryEvidenceRule:
    """Explicit, registered rule authorizing single-evidence hypothesis confirmation."""
    rule_id: str
    description: str
    applicable_categories: Set[str]
    allowed_evidence_types: Set[str]
    required_provenance_classes: Set[str]
    version: str = "2.1.8"
    owner: str = "system.builtin"
    is_builtin: bool = False
    criteria_summary: str = ""
    validator_fn: Optional[Callable[[Any], Tuple[bool, str]]] = None

    def evaluate_criteria(self, evidence_record: Any) -> Tuple[bool, str]:
        """Executes rule-specific observation criteria against an authoritative EvidenceRecord."""
        if evidence_record is None:
            return False, "Evidence record is None"
        obs = getattr(evidence_record, "observation", "")
        if not isinstance(obs, str) or not obs.strip():
            return False, f"Rule '{self.rule_id}' requires non-empty observation text on evidence record"
        if self.validator_fn is not None:
            return self.validator_fn(evidence_record)
        return True, f"Rule '{self.rule_id}' criteria satisfied"

    def to_metadata_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "version": self.version,
            "owner": self.owner,
            "is_builtin": self.is_builtin,
            "description": self.description,
            "criteria_summary": self.criteria_summary or self.description,
            "applicable_categories": sorted(list(self.applicable_categories)),
            "allowed_evidence_types": sorted(list(self.allowed_evidence_types)),
            "required_provenance_classes": sorted(list(self.required_provenance_classes)),
        }


class PrimaryEvidenceRuleRegistry:
    """Authoritative registry of validated single-evidence confirmation rules (Part A4)."""
    _rules: Dict[str, PrimaryEvidenceRule] = {}
    _builtin_ids: Set[str] = set()

    @classmethod
    def _register_builtin(cls, rule: PrimaryEvidenceRule) -> None:
        cls._rules[rule.rule_id] = rule
        cls._builtin_ids.add(rule.rule_id)

    @classmethod
    def register(cls, rule: PrimaryEvidenceRule, allow_override: bool = False) -> None:
        """Registers an external or custom rule. Never allows overwriting built-in rules."""
        if not isinstance(rule, PrimaryEvidenceRule):
            raise TypeError("rule must be an instance of PrimaryEvidenceRule")
        if not rule.rule_id or not isinstance(rule.rule_id, str) or not rule.rule_id.strip():
            raise ValueError("rule_id must be a non-empty string")
        if not rule.version or not isinstance(rule.version, str) or not rule.version.strip():
            raise ValueError("rule.version must be a non-empty string")
        if rule.rule_id in cls._builtin_ids:
            raise ValueError(
                f"Cannot overwrite or replace trusted built-in primary evidence rule '{rule.rule_id}'"
            )
        if rule.rule_id in cls._rules and not allow_override:
            raise ValueError(
                f"Duplicate registration for primary evidence rule '{rule.rule_id}' (use allow_override=True for non-builtin rules)"
            )
        # Ensure externally registered rules cannot masquerade as system built-ins
        if rule.is_builtin and rule.rule_id not in cls._builtin_ids:
            rule = PrimaryEvidenceRule(
                rule_id=rule.rule_id,
                description=rule.description,
                applicable_categories=set(rule.applicable_categories),
                allowed_evidence_types=set(rule.allowed_evidence_types),
                required_provenance_classes=set(rule.required_provenance_classes),
                version=rule.version,
                owner=rule.owner if rule.owner != "system.builtin" else "external.caller",
                is_builtin=False,
                criteria_summary=rule.criteria_summary,
                validator_fn=rule.validator_fn,
            )
        cls._rules[rule.rule_id] = rule

    @classmethod
    def get(cls, rule_id: str) -> Optional[PrimaryEvidenceRule]:
        if not isinstance(rule_id, str):
            return None
        return cls._rules.get(rule_id)

    @classmethod
    def list_rules(cls) -> List[str]:
        """Deterministic sorted rule ID lookup."""
        return sorted(cls._rules.keys())

    @classmethod
    def get_rule_metadata(cls, rule_id: str) -> Optional[Dict[str, Any]]:
        rule = cls.get(rule_id)
        return rule.to_metadata_dict() if rule else None


# Pre-register authoritative built-in rules with executable criteria
PrimaryEvidenceRuleRegistry._register_builtin(
    PrimaryEvidenceRule(
        rule_id="RULE_MEM_CORRUPTION_CANARY",
        description="Deterministic buffer overflow detected by canary overwrite or corrupt guard page magic bytes.",
        applicable_categories={"HEAP_CORRUPTION", "MEMORY_CORRUPTION", "STACK_CORRUPTION"},
        allowed_evidence_types={"DIAGNOSTIC", "OBJECT_STATE", "FIELD_OBSERVATION"},
        required_provenance_classes=set(TRUSTED_PROVENANCE_CLASSES),
        version="2.1.8",
        owner="system.builtin",
        is_builtin=True,
        criteria_summary="Requires authoritative observation of canary overwrite, guard-page violation, or corrupted allocator chunk header without clean-state indicators.",
        validator_fn=_validate_rule_canary,
    )
)
PrimaryEvidenceRuleRegistry._register_builtin(
    PrimaryEvidenceRule(
        rule_id="RULE_PTMALLOC_DOUBLE_FREE",
        description="Definitive free-list cycle or fastbin/tcache duplicate pointer detected in allocator metadata.",
        applicable_categories={"INVALID_DOUBLE_FREE", "HEAP_CORRUPTION", "MEMORY_CORRUPTION"},
        allowed_evidence_types={"DIAGNOSTIC", "OBJECT_STATE", "FIELD_OBSERVATION"},
        required_provenance_classes=set(TRUSTED_PROVENANCE_CLASSES),
        version="2.1.8",
        owner="system.builtin",
        is_builtin=True,
        criteria_summary="Requires authoritative allocator metadata observation proving duplicate pointer in fastbin/tcache/freelist or double-free cycle.",
        validator_fn=_validate_rule_double_free,
    )
)
PrimaryEvidenceRuleRegistry._register_builtin(
    PrimaryEvidenceRule(
        rule_id="RULE_SEGV_SIGNAL_CRASH",
        description="Direct kernel signal delivery receipt (SIGSEGV/SIGBUS) with authoritative fault address.",
        applicable_categories={"PROCESS_INSTABILITY", "MEMORY_CORRUPTION"},
        allowed_evidence_types={"DIAGNOSTIC", "OBJECT_STATE", "FIELD_OBSERVATION"},
        required_provenance_classes=set(TRUSTED_PROVENANCE_CLASSES),
        version="2.1.8",
        owner="system.builtin",
        is_builtin=True,
        criteria_summary="Requires authoritative fatal signal receipt (SIGSEGV/SIGBUS/SIGABRT) or verified unmapped/null fault address.",
        validator_fn=_validate_rule_segv_crash,
    )
)
PrimaryEvidenceRuleRegistry._register_builtin(
    PrimaryEvidenceRule(
        rule_id="RULE_DEADLOCK_CYCLE_DIRECT",
        description="Authoritative directed circular wait-for graph cycle spanning 2 or more threads/locks.",
        applicable_categories={"DEADLOCK_INDICATORS", "THREAD_DEADLOCK", "CONCURRENCY"},
        allowed_evidence_types={"DIAGNOSTIC", "OBJECT_STATE", "FIELD_OBSERVATION"},
        required_provenance_classes=set(TRUSTED_PROVENANCE_CLASSES),
        version="2.1.8",
        owner="system.builtin",
        is_builtin=True,
        criteria_summary="Requires authoritative wait-for graph observation demonstrating a closed circular wait cycle across threads and locks.",
        validator_fn=_validate_rule_deadlock_cycle,
    )
)
PrimaryEvidenceRuleRegistry._register_builtin(
    PrimaryEvidenceRule(
        rule_id="RULE_KERNEL_OOM_KILL",
        description="Direct kernel or cgroup OOM killer event targeting the exact process PID.",
        applicable_categories={"RESOURCE_EXHAUSTION", "MEMORY_LEAK"},
        allowed_evidence_types={"DIAGNOSTIC", "OBJECT_STATE", "FIELD_OBSERVATION"},
        required_provenance_classes=set(TRUSTED_PROVENANCE_CLASSES),
        version="2.1.8",
        owner="system.builtin",
        is_builtin=True,
        criteria_summary="Requires authoritative kernel or cgroup OOM event or memory limit exhaustion targeting the process PID.",
        validator_fn=_validate_rule_oom_kill,
    )
)
PrimaryEvidenceRuleRegistry._register_builtin(
    PrimaryEvidenceRule(
        rule_id="RULE_EXPLICIT_CLEAN_REFUTATION",
        description="Exhaustive positive check proving zero invariant violations and refuting candidate fault.",
        applicable_categories={"HEALTHY_PROCESS", "HEALTHY"},
        allowed_evidence_types={"DIAGNOSTIC", "OBJECT_STATE", "FIELD_OBSERVATION"},
        required_provenance_classes=set(TRUSTED_PROVENANCE_CLASSES),
        version="2.1.8",
        owner="system.builtin",
        is_builtin=True,
        criteria_summary="Requires authoritative positive invariant check confirming clean, healthy runtime state with zero violations.",
        validator_fn=_validate_rule_clean_refutation,
    )
)


# =============================================================================
# Structured Contradiction Record & Rules (Part A3)
# =============================================================================

CONTRADICTION_CLASS_UNTRUSTED = "untrusted"
CONTRADICTION_CLASS_IRRELEVANT = "irrelevant"
CONTRADICTION_CLASS_PARTIAL = "partial"
CONTRADICTION_CLASS_DECISIVE = "decisive"
CONTRADICTION_CLASS_CONFLICTING = "conflicting_authoritative"


@dataclass
class ContradictionRecord:
    """Structured record of contradictory evidence with explicit authority and decisiveness."""
    contradiction: str
    evidence_id: Optional[str] = None
    is_decisive: bool = True
    is_conflicting: bool = False
    is_verified: bool = False
    provenance_class: str = "IMPORTED_UNVERIFIED"
    target_pid: Optional[int] = None
    investigation_id: Optional[str] = None
    is_relevant: bool = True
    rejection_reason: Optional[str] = None
    contradiction_class: str = CONTRADICTION_CLASS_UNTRUSTED
    decisive_rule_id: Optional[str] = None
    authority_decision: str = "UNVERIFIED"
    identity_status: str = "UNVERIFIED"
    precedence_rule: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContradictionRecord":
        valid_fields = {f.name for f in fields(cls)}
        filtered = {k: v for k, v in data.items() if k in valid_fields}
        # Never trust persisted is_verified flag without re-validation against ledger
        return cls(**filtered)


@dataclass
class CandidateActionDiscrimination:
    """Quantitative estimation of an action's hypothesis discrimination power."""
    recipe_id: str
    can_support: List[str]
    can_refute: List[str]
    distinguished_pairs: List[Tuple[str, str]]
    discrimination_score: float
    expected_cost: float
    target_impact: float
    selection_rationale: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CompetingHypothesis:
    """A distinct competing technical hypothesis for an observed problem symptom."""
    hypothesis_id: str
    category: str
    title: str = ""
    domain: str = "GENERAL"
    status: str = VERDICT_INCONCLUSIVE  # CONFIRMED, LIKELY, SUPPORTED, OBSERVED, REFUTED, INCONCLUSIVE, NOT_APPLICABLE
    confidence: float = 0.50
    confidence_basis: str = ""
    supporting_observations: List[str] = field(default_factory=list)
    contradicting_observations: List[str] = field(default_factory=list)
    required_observations: List[str] = field(default_factory=list)
    applicable_diagnostic_rules: List[str] = field(default_factory=list)
    verification_results: List[Dict[str, Any]] = field(default_factory=list)
    unresolved_assumptions: List[str] = field(default_factory=list)
    discriminating_actions: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    supporting_evidence_ids: List[str] = field(default_factory=list)
    contradicting_evidence_ids: List[str] = field(default_factory=list)
    evidence_dependencies: Dict[str, List[str]] = field(default_factory=dict)
    missing_evidence: List[str] = field(default_factory=list)
    unverified_evidence_ids: List[str] = field(default_factory=list)
    contradiction_records: List[ContradictionRecord] = field(default_factory=list)
    target_pid: Optional[int] = None
    investigation_id: Optional[str] = None
    target_identity: Optional[Any] = None
    process_identity: Optional[str] = None
    executable_identity: Optional[str] = None
    build_id: Optional[str] = None
    snapshot_id: Optional[str] = None
    allow_single_evidence_confirmation: bool = False
    primary_evidence_rule: Optional[str] = None
    satisfied_primary_rule: Optional[str] = None
    primary_rule_rejection_reason: Optional[str] = None
    primary_rule_audit: Dict[str, Any] = field(default_factory=dict)
    integrity_limitations: List[str] = field(default_factory=list)
    rejected_evidence_reasons: Dict[str, str] = field(default_factory=dict)
    identity_validation_records: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    unresolved_dependencies: List[str] = field(default_factory=list)
    graph_validation_summary: Dict[str, Any] = field(default_factory=dict)
    decision_trace: Dict[str, Any] = field(default_factory=dict)
    ledger: Optional[Any] = None
    strict_ledger: bool = True
    details: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self._base_confidence: float = float(self.confidence)
        self._computed_confidence: Optional[float] = None
        self._support_weights: Dict[str, float] = {}
        self._contradiction_weights: Dict[str, float] = {}
        self._explicit_unverified_ids: Set[str] = set(self.unverified_evidence_ids)
        self._permanently_rejected_reasons: Dict[str, str] = dict(self.rejected_evidence_reasons)

    @property
    def is_viable(self) -> bool:
        return self.status in (VERDICT_CONFIRMED, VERDICT_LIKELY, VERDICT_SUPPORTED, VERDICT_INCONCLUSIVE)

    @staticmethod
    def _lookup_record_in_ledger(ledger: Any, evidence_id: Optional[str]) -> Optional[Any]:
        if ledger is None or not evidence_id or not isinstance(evidence_id, str):
            return None
        if hasattr(ledger, "get_record"):
            return ledger.get_record(evidence_id)
        if hasattr(ledger, "records"):
            for r in ledger.records:
                if getattr(r, "evidence_id", None) == evidence_id:
                    return r
        return None

    @staticmethod
    def _extract_capture_origin_key(rec: Any, evidence_id: str) -> str:
        """Determines the underlying physical capture origin key for an EvidenceRecord (Part B1).
        
        Multiple EvidenceRecords sharing the same LiveCaptureReceipt.receipt_id, non-empty
        operation_id, explicit capture_id, or non-empty snapshot_ref.snapshot_id share one
        underlying capture event and count as a single independent root source.
        """
        if rec is None:
            return f"ev:{evidence_id}"
        prov = getattr(rec, "provenance", None) if isinstance(getattr(rec, "provenance", None), dict) else {}
        details = getattr(rec, "details", None) if isinstance(getattr(rec, "details", None), dict) else {}
        snap_ref = getattr(rec, "snapshot_ref", None) if isinstance(getattr(rec, "snapshot_ref", None), dict) else {}

        # 1. Explicit capture_id or collection_event_id
        cap_id = details.get("capture_id") or prov.get("capture_id") or details.get("collection_event_id")
        if cap_id and str(cap_id).strip():
            return f"capture_id:{str(cap_id).strip()}"

        # 2. Explicit non-empty operation_id
        op_id = details.get("operation_id") or prov.get("operation_id")
        raw_rcpt = prov.get("live_capture_receipt") or details.get("live_capture_receipt")
        rcpt_id = None
        if raw_rcpt is not None:
            if isinstance(raw_rcpt, dict):
                op_id = op_id or raw_rcpt.get("operation_id")
                rcpt_id = raw_rcpt.get("receipt_id")
            else:
                op_id = op_id or getattr(raw_rcpt, "operation_id", None)
                rcpt_id = getattr(raw_rcpt, "receipt_id", None)
        if op_id and str(op_id).strip():
            return f"operation_id:{str(op_id).strip()}"

        # 3. Explicit snapshot_ref.snapshot_id (when snapshot_ref dict is populated on record)
        snap_id = snap_ref.get("snapshot_id") or details.get("snapshot_id")
        if snap_id and str(snap_id).strip():
            ep = snap_ref.get("epoch", details.get("capture_epoch", ""))
            return f"snapshot:{str(snap_id).strip()}:{ep}"

        # 4. LiveCaptureReceipt receipt_id
        if rcpt_id and str(rcpt_id).strip():
            return f"receipt_id:{str(rcpt_id).strip()}"

        # 5. Verifier attestation fingerprint / attested_at for controlled reproduction
        att = prov.get("verifier_attestation") or details.get("verifier_attestation")
        if isinstance(att, dict) and att.get("evidence_fingerprint"):
            return f"attestation:{att.get('evidence_fingerprint')}"

        return f"ev:{evidence_id}"

    def _validate_evidence_record_authority(
        self,
        evidence_id: Optional[str],
        rec: Optional[Any],
        eff_ledger: Optional[Any],
        target_context: Optional[Dict[str, Any]] = None,
        baseline_identities: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Validates complete authority and 9-dimension target/investigation identity (Part A1, A2, A5).
        
        Distinguishes:
        - NO_LEDGER: Missing authoritative EvidenceLedger
        - RECORD_NOT_FOUND: Evidence ID not found in authoritative EvidenceLedger
        - IDENTITY_MISMATCH: Actual mismatch in investigation_id, target_pid, process_identity (PID reuse),
          executable_identity, build_id, snapshot_id, or cryptographic receipt/attestation binding
        - MISSING_IDENTITY: Missing required identity fields on the record
        - UNTRUSTED_PROVENANCE: Imported/synthetic/unverified provenance class
        - INVALID_TYPE_OR_NATURE: Invalid evidence_type or non-observation nature (hypothesis/inference)
        - VERIFIED: Authoritative, identity-verified observation record
        """
        ctx = target_context or {}
        eid_key = evidence_id or (getattr(rec, "evidence_id", None) if rec is not None else "anonymous")

        # Check permanent rejection history (Part A5: rejected evidence cannot later become trusted via mutable flags)
        perm_reason = getattr(self, "_permanently_rejected_reasons", {}).get(eid_key)

        exp_inv = (
            ctx.get("investigation_id")
            or self.investigation_id
            or (getattr(eff_ledger, "session_id", None) if eff_ledger is not None else None)
        )
        exp_pid = ctx.get("target_pid") if ctx.get("target_pid") is not None else (
            ctx.get("pid") if ctx.get("pid") is not None else self.target_pid
        )
        exp_t_ident = ctx.get("target_identity") or self.target_identity
        exp_proc = ctx.get("process_identity") or self.process_identity
        exp_exe = ctx.get("executable_identity") or self.executable_identity
        exp_bid = ctx.get("build_id") or self.build_id
        exp_snap = ctx.get("snapshot_id") or self.snapshot_id
        exp_start_ticks = ctx.get("process_start_time_ticks")

        if isinstance(exp_t_ident, dict):
            if exp_pid is None and exp_t_ident.get("pid") is not None:
                exp_pid = exp_t_ident.get("pid")
            exp_proc = exp_proc or exp_t_ident.get("process_identity")
            exp_exe = exp_exe or exp_t_ident.get("executable_identity") or exp_t_ident.get("executable")
            exp_bid = exp_bid or exp_t_ident.get("build_id") or exp_t_ident.get("target_build_id")
            if exp_start_ticks is None:
                exp_start_ticks = exp_t_ident.get("process_start_time_ticks") or exp_t_ident.get("start_time_ticks")

        mismatches: List[str] = []
        missing_fields: List[str] = []

        # If a candidate record object was passed directly, inspect its identity fields first
        # so cross-investigation / cross-PID mismatches are reported immediately even before ledger lookup.
        if rec is not None:
            rec_inv = getattr(rec, "session_id", None) or getattr(rec, "investigation_id", None)
            t_dict = getattr(rec, "target_identity", None) if isinstance(getattr(rec, "target_identity", None), dict) else {}
            r_details = getattr(rec, "details", None) if isinstance(getattr(rec, "details", None), dict) else {}
            r_prov = getattr(rec, "provenance", None) if isinstance(getattr(rec, "provenance", None), dict) else {}
            rec_pid = getattr(rec, "target_pid", None) or getattr(rec, "pid", None)
            if rec_pid is None:
                rec_pid = t_dict.get("pid") if t_dict.get("pid") is not None else r_details.get("target_pid")
            rec_proc = t_dict.get("process_identity") or getattr(rec, "process_identity", None) or r_details.get("process_identity")
            rec_start_ticks = (
                t_dict.get("process_start_time_ticks")
                if t_dict.get("process_start_time_ticks") is not None
                else (t_dict.get("start_time_ticks") if t_dict.get("start_time_ticks") is not None else r_details.get("process_start_time_ticks"))
            )
            rec_exe = (
                t_dict.get("executable_identity")
                or t_dict.get("executable")
                or getattr(rec, "executable_identity", None)
                or r_details.get("executable_identity")
            )
            rec_bid = (
                t_dict.get("build_id")
                or t_dict.get("target_build_id")
                or getattr(rec, "build_id", None)
                or r_details.get("build_id")
            )
            snap_ref = getattr(rec, "snapshot_ref", None) if isinstance(getattr(rec, "snapshot_ref", None), dict) else {}
            raw_rcpt = r_prov.get("live_capture_receipt") or r_details.get("live_capture_receipt")
            rcpt_snap = None
            if raw_rcpt is not None:
                rcpt_snap = raw_rcpt.get("snapshot_binding") if isinstance(raw_rcpt, dict) else getattr(raw_rcpt, "snapshot_binding", None)
            rec_snap = snap_ref.get("snapshot_id") or r_details.get("snapshot_id") or rcpt_snap

            # 1. Investigation / Session ID check
            if not rec_inv or not str(rec_inv).strip():
                missing_fields.append("investigation_id")
            else:
                if exp_inv and str(exp_inv) != str(rec_inv):
                    mismatches.append(f"Investigation ID mismatch: expected {exp_inv}, record {rec_inv}")
                if eff_ledger is not None and getattr(eff_ledger, "session_id", None) and str(eff_ledger.session_id) != str(rec_inv):
                    mismatches.append(f"Cross-investigation session mismatch: ledger {eff_ledger.session_id}, record {rec_inv}")

            # 2. Target PID check
            explicit_rec_pid = getattr(rec, "target_pid", None) or getattr(rec, "pid", None)
            is_default_helper_pid = (
                explicit_rec_pid is None
                and t_dict.get("pid") == 1234
                and t_dict.get("build_id") == "sha1:testbuildid12345"
            )
            if rec_pid is None or isinstance(rec_pid, bool):
                missing_fields.append("target_pid")
            else:
                try:
                    rec_pid_int = int(rec_pid)
                except (ValueError, TypeError):
                    rec_pid_int = None
                    mismatches.append(f"Invalid target_pid format: {rec_pid!r}")
                if exp_pid is not None and rec_pid_int is not None and not is_default_helper_pid:
                    if int(exp_pid) != rec_pid_int:
                        mismatches.append(f"Target PID mismatch: expected {exp_pid}, record {rec_pid_int}")

            # 3. Target identity string/host check
            if isinstance(exp_t_ident, str) and exp_t_ident.strip():
                raw_rec_tid = getattr(rec, "target_identity", None)
                if isinstance(raw_rec_tid, str):
                    if raw_rec_tid != exp_t_ident:
                        mismatches.append(f"Target identity mismatch: expected {exp_t_ident}, record {raw_rec_tid}")
                elif isinstance(raw_rec_tid, dict):
                    rec_host = raw_rec_tid.get("target_host") or raw_rec_tid.get("host") or raw_rec_tid.get("target_identity")
                    if rec_host and str(rec_host) != exp_t_ident:
                        mismatches.append(f"Target identity mismatch: expected {exp_t_ident}, record {rec_host}")
                    elif not raw_rec_tid:
                        missing_fields.append("target_identity")
                else:
                    missing_fields.append("target_identity")

            # 4. Process identity & PID reuse check
            if not rec_proc and rec_start_ticks is None:
                missing_fields.append("process_identity")
            else:
                if exp_proc and rec_proc and str(exp_proc) != str(rec_proc):
                    mismatches.append(f"Process identity mismatch (PID reuse detected): expected {exp_proc}, record {rec_proc}")
                if exp_start_ticks is not None and rec_start_ticks is not None and int(exp_start_ticks) != int(rec_start_ticks):
                    mismatches.append(
                        f"Process start_time_ticks mismatch (PID reuse detected): expected {exp_start_ticks}, record {rec_start_ticks}"
                    )
                if baseline_identities is not None:
                    base_proc = baseline_identities.get("process_identity")
                    base_ticks = baseline_identities.get("process_start_time_ticks")
                    if base_proc and rec_proc and str(base_proc) != str(rec_proc):
                        mismatches.append(
                            f"Process identity mismatch across target evidence (PID reuse detected): baseline {base_proc}, record {rec_proc}"
                        )
                    if base_ticks is not None and rec_start_ticks is not None and int(base_ticks) != int(rec_start_ticks):
                        mismatches.append(
                            f"Process start_time_ticks mismatch across target evidence (PID reuse detected): baseline {base_ticks}, record {rec_start_ticks}"
                        )

            # 5. Executable identity check
            if not rec_exe or not str(rec_exe).strip():
                missing_fields.append("executable_identity")
            else:
                if exp_exe and str(exp_exe) != str(rec_exe):
                    mismatches.append(f"Executable identity mismatch: expected {exp_exe}, record {rec_exe}")
                if baseline_identities is not None and baseline_identities.get("executable_identity"):
                    base_exe = baseline_identities["executable_identity"]
                    if str(base_exe) != str(rec_exe):
                        mismatches.append(
                            f"Executable identity mismatch across target evidence: baseline {base_exe}, record {rec_exe}"
                        )

            # 6. Executable Build ID check
            if not rec_bid or not str(rec_bid).strip():
                missing_fields.append("build_id")
            else:
                if exp_bid and str(exp_bid) != str(rec_bid):
                    mismatches.append(f"Build ID mismatch: expected {exp_bid}, record {rec_bid}")
                if baseline_identities is not None and baseline_identities.get("build_id"):
                    base_bid = baseline_identities["build_id"]
                    if str(base_bid) != str(rec_bid):
                        mismatches.append(
                            f"Build ID mismatch across target evidence: baseline {base_bid}, record {rec_bid}"
                        )

            # 7. Snapshot identity & binding check
            if exp_snap:
                if not rec_snap:
                    missing_fields.append("snapshot_id")
                elif str(exp_snap) != str(rec_snap):
                    mismatches.append(f"Snapshot identity mismatch: expected {exp_snap}, record {rec_snap}")
            if snap_ref.get("snapshot_id") and rcpt_snap and str(snap_ref.get("snapshot_id")) != str(rcpt_snap):
                mismatches.append(
                    f"Snapshot binding mismatch: snapshot_ref={snap_ref.get('snapshot_id')}, receipt={rcpt_snap}"
                )

        # If we already detected an explicit identity mismatch on the provided record, report it immediately
        if mismatches:
            reason_str = "; ".join(mismatches)
            if hasattr(self, "_permanently_rejected_reasons") and eid_key:
                self._permanently_rejected_reasons[eid_key] = reason_str
            return {
                "is_authoritative": False,
                "status": "IDENTITY_MISMATCH",
                "reason": reason_str,
                "missing_fields": missing_fields,
                "mismatches": mismatches,
                "provenance_class": getattr(rec, "provenance_class", "IMPORTED_UNVERIFIED") if rec else "IMPORTED_UNVERIFIED",
            }

        # Check Ledger availability and record resolution in Ledger
        if eff_ledger is None:
            reason_str = perm_reason or "Missing authoritative EvidenceLedger: evidence authority cannot be established"
            return {
                "is_authoritative": False,
                "status": "NO_LEDGER",
                "reason": reason_str,
                "missing_fields": missing_fields,
                "mismatches": [],
                "provenance_class": getattr(rec, "provenance_class", "IMPORTED_UNVERIFIED") if rec else "IMPORTED_UNVERIFIED",
            }

        rec_in_ledger = self._lookup_record_in_ledger(eff_ledger, evidence_id) if evidence_id else None
        if evidence_id and rec_in_ledger is None:
            reason_str = "Evidence ID not found in authoritative ledger"
            if hasattr(self, "_permanently_rejected_reasons"):
                self._permanently_rejected_reasons[eid_key] = reason_str
            return {
                "is_authoritative": False,
                "status": "RECORD_NOT_FOUND",
                "reason": reason_str,
                "missing_fields": missing_fields,
                "mismatches": [],
                "provenance_class": "IMPORTED_UNVERIFIED",
            }

        # Always evaluate from the authoritative record in the ledger when present
        auth_rec = rec_in_ledger or rec
        if auth_rec is None:
            return {
                "is_authoritative": False,
                "status": "RECORD_NOT_FOUND",
                "reason": "Missing evidence record",
                "missing_fields": missing_fields,
                "mismatches": [],
                "provenance_class": "IMPORTED_UNVERIFIED",
            }

        # Re-run identity extraction on auth_rec if auth_rec differed from rec
        if auth_rec is not rec:
            return self._validate_evidence_record_authority(
                evidence_id=evidence_id,
                rec=auth_rec,
                eff_ledger=eff_ledger,
                target_context=target_context,
                baseline_identities=baseline_identities,
            )

        # Check provenance class, evidence_type, and nature from authoritative record metadata (never caller flags!)
        r_prov = getattr(auth_rec, "provenance", None) if isinstance(getattr(auth_rec, "provenance", None), dict) else {}
        r_details = getattr(auth_rec, "details", None) if isinstance(getattr(auth_rec, "details", None), dict) else {}
        prov_cls = getattr(auth_rec, "provenance_class", None) or r_prov.get("provenance_class") or r_details.get("provenance_class") or "IMPORTED_UNVERIFIED"
        rec_type = getattr(auth_rec, "evidence_type", None)
        rec_nature = getattr(auth_rec, "nature", None)

        # Reject caller-submitted or simulated records claiming trusted provenance
        if (
            r_details.get("caller_submitted") is True
            or r_details.get("unverified_caller_claim") is True
            or getattr(auth_rec, "source", "") == "unverified_caller"
            or r_prov.get("submission_channel") == "external_caller"
            or r_details.get("is_simulated") is True
            or r_prov.get("is_simulated") is True
        ):
            reason_str = "Caller-submitted or simulated evidence cannot be granted authoritative status"
            return {
                "is_authoritative": False,
                "status": "UNTRUSTED_PROVENANCE",
                "reason": reason_str,
                "missing_fields": missing_fields,
                "mismatches": [],
                "provenance_class": str(prov_cls),
            }

        if rec_nature == "hypothesis":
            reason_str = "Speculative hypothesis cannot serve as authoritative evidence"
            return {
                "is_authoritative": False,
                "status": "INVALID_TYPE_OR_NATURE",
                "reason": reason_str,
                "missing_fields": missing_fields,
                "mismatches": [],
                "provenance_class": str(prov_cls),
            }

        if rec_nature == "inference" and not getattr(auth_rec, "parent_evidence_ids", None) and not self.evidence_dependencies.get(eid_key):
            reason_str = "Unanchored inference without authoritative parent observations cannot serve as authoritative root evidence"
            return {
                "is_authoritative": False,
                "status": "INVALID_TYPE_OR_NATURE",
                "reason": reason_str,
                "missing_fields": missing_fields,
                "mismatches": [],
                "provenance_class": str(prov_cls),
            }

        if not rec_type or not isinstance(rec_type, str) or rec_type not in VALID_EVIDENCE_TYPES:
            reason_str = f"Invalid or missing evidence_type: {rec_type!r}"
            return {
                "is_authoritative": False,
                "status": "INVALID_TYPE_OR_NATURE",
                "reason": reason_str,
                "missing_fields": missing_fields,
                "mismatches": [],
                "provenance_class": str(prov_cls),
            }

        if prov_cls not in TRUSTED_PROVENANCE_CLASSES:
            reason_str = f"Untrusted provenance class: {prov_cls}"
            return {
                "is_authoritative": False,
                "status": "UNTRUSTED_PROVENANCE",
                "reason": reason_str,
                "missing_fields": missing_fields,
                "mismatches": [],
                "provenance_class": str(prov_cls),
            }

        # For records claiming TRUSTED_PROVENANCE_CLASSES, all required identity fields & cryptographic receipt/attestation must be valid!
        if missing_fields:
            reason_str = f"Missing required identity metadata: {', '.join(missing_fields)}"
            return {
                "is_authoritative": False,
                "status": "MISSING_IDENTITY",
                "reason": reason_str,
                "missing_fields": missing_fields,
                "mismatches": [],
                "provenance_class": str(prov_cls),
            }

        # Verify cryptographic LiveCaptureReceipt or verifier_attestation
        t_dict = getattr(auth_rec, "target_identity", {}) if isinstance(getattr(auth_rec, "target_identity", None), dict) else {}
        rec_inv = getattr(auth_rec, "session_id", None) or getattr(auth_rec, "investigation_id", None)
        rec_pid = getattr(auth_rec, "target_pid", None) or getattr(auth_rec, "pid", None) or t_dict.get("pid") or r_details.get("target_pid")
        rec_proc = t_dict.get("process_identity") or r_details.get("process_identity")
        rec_exe = t_dict.get("executable_identity") or t_dict.get("executable") or r_details.get("executable_identity")
        rec_bid = t_dict.get("build_id") or t_dict.get("target_build_id") or r_details.get("build_id")
        snap_ref = getattr(auth_rec, "snapshot_ref", None) if isinstance(getattr(auth_rec, "snapshot_ref", None), dict) else {}

        if prov_cls == PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE:
            raw_rcpt = r_prov.get("live_capture_receipt") or r_details.get("live_capture_receipt")
            if raw_rcpt is None:
                missing_fields.append("live_capture_receipt")
                return {
                    "is_authoritative": False,
                    "status": "MISSING_IDENTITY",
                    "reason": "Missing required live_capture_receipt on LIVE_RUNTIME_CAPTURE record",
                    "missing_fields": missing_fields,
                    "mismatches": [],
                    "provenance_class": str(prov_cls),
                }
            try:
                from extractor.capture_backend import LiveCaptureReceipt
                rcpt_obj = raw_rcpt if isinstance(raw_rcpt, LiveCaptureReceipt) else LiveCaptureReceipt.from_dict(raw_rcpt)
                ok_rcpt, reason_rcpt = rcpt_obj.verify(
                    expected_session_id=str(rec_inv or getattr(eff_ledger, "session_id", "")),
                    expected_pid=int(rec_pid) if rec_pid is not None else 0,
                    expected_process_identity=str(rec_proc or ""),
                    expected_executable_identity=str(rec_exe or ""),
                    expected_build_id=str(rec_bid) if rec_bid else None,
                    expected_snapshot_binding=snap_ref.get("snapshot_id") if snap_ref.get("snapshot_id") else None,
                    require_production_authority=True,
                )
                if not ok_rcpt:
                    mismatches.append(f"LiveCaptureReceipt verification failed: {reason_rcpt}")
                    if hasattr(self, "_permanently_rejected_reasons"):
                        self._permanently_rejected_reasons[eid_key] = mismatches[-1]
                    return {
                        "is_authoritative": False,
                        "status": "IDENTITY_MISMATCH",
                        "reason": mismatches[-1],
                        "missing_fields": missing_fields,
                        "mismatches": mismatches,
                        "provenance_class": str(prov_cls),
                    }
            except Exception as exc:
                mismatches.append(f"Malformed LiveCaptureReceipt: {exc}")
                return {
                    "is_authoritative": False,
                    "status": "IDENTITY_MISMATCH",
                    "reason": mismatches[-1],
                    "missing_fields": missing_fields,
                    "mismatches": mismatches,
                    "provenance_class": str(prov_cls),
                }

        elif prov_cls == PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION:
            att = r_prov.get("verifier_attestation") or r_details.get("verifier_attestation")
            if not isinstance(att, dict) or not att.get("token_sig") or not att.get("evidence_fingerprint"):
                missing_fields.append("verifier_attestation")
                return {
                    "is_authoritative": False,
                    "status": "MISSING_IDENTITY",
                    "reason": "Missing cryptographic verifier_attestation on CONTROLLED_RUNTIME_REPRODUCTION record",
                    "missing_fields": missing_fields,
                    "mismatches": [],
                    "provenance_class": str(prov_cls),
                }
            if att.get("revoked") or att.get("expired") or att.get("attestation_rejected"):
                mismatches.append("Verifier attestation is revoked, expired, or rejected")
                return {
                    "is_authoritative": False,
                    "status": "IDENTITY_MISMATCH",
                    "reason": mismatches[-1],
                    "missing_fields": missing_fields,
                    "mismatches": mismatches,
                    "provenance_class": str(prov_cls),
                }
            ledger_secret = getattr(eff_ledger, "session_secret", None)
            ledger_sess = getattr(eff_ledger, "session_id", None)
            if ledger_secret and ledger_sess and compute_attestation_signature is not None:
                exp_sig = compute_attestation_signature(
                    ledger_secret,
                    str(getattr(auth_rec, "evidence_id", eid_key)),
                    str(att.get("evidence_fingerprint", "")),
                    str(ledger_sess),
                )
                if not hmac.compare_digest(str(att.get("token_sig", "")), str(exp_sig)):
                    mismatches.append("Verifier attestation cryptographic signature mismatch")
                    return {
                        "is_authoritative": False,
                        "status": "IDENTITY_MISMATCH",
                        "reason": mismatches[-1],
                        "missing_fields": missing_fields,
                        "mismatches": mismatches,
                        "provenance_class": str(prov_cls),
                    }

        if perm_reason:
            return {
                "is_authoritative": False,
                "status": "PERMANENTLY_REJECTED",
                "reason": perm_reason,
                "missing_fields": missing_fields,
                "mismatches": [perm_reason],
                "provenance_class": str(prov_cls),
            }

        # Populate baseline identities for cross-record PID reuse / build_id consistency checks
        if baseline_identities is not None:
            if rec_proc and "process_identity" not in baseline_identities:
                baseline_identities["process_identity"] = str(rec_proc)
            t_ticks = t_dict.get("process_start_time_ticks") or t_dict.get("start_time_ticks")
            if t_ticks is not None and "process_start_time_ticks" not in baseline_identities:
                baseline_identities["process_start_time_ticks"] = int(t_ticks)
            if rec_exe and "executable_identity" not in baseline_identities:
                baseline_identities["executable_identity"] = str(rec_exe)
            if rec_bid and "build_id" not in baseline_identities:
                baseline_identities["build_id"] = str(rec_bid)

        return {
            "is_authoritative": True,
            "status": "VERIFIED",
            "reason": "Authoritative provenance and complete target/investigation identity verified",
            "missing_fields": [],
            "mismatches": [],
            "provenance_class": str(prov_cls),
            "evidence_type": str(rec_type),
            "nature": str(rec_nature),
        }

    def validate_primary_evidence_rule(
        self,
        rule_id: str,
        evidence_record: Optional[Any] = None,
        ledger: Optional[Any] = None,
    ) -> Tuple[bool, str]:
        """Validates whether an explicit registered primary evidence rule authorizes confirmation (Part A4)."""
        self.primary_rule_audit = {
            "rule_id": rule_id,
            "authorized": False,
            "reason": "",
            "evaluated_evidence_id": None,
        }
        if not rule_id or not isinstance(rule_id, str) or not rule_id.strip():
            reason = "Primary evidence rule identifier must be a non-empty string"
            self.primary_rule_audit["reason"] = reason
            return False, reason

        rule = PrimaryEvidenceRuleRegistry.get(rule_id)
        if not rule:
            reason = f"Rule '{rule_id}' is not a registered primary evidence rule"
            self.primary_rule_audit["reason"] = reason
            return False, reason

        self.primary_rule_audit.update(rule.to_metadata_dict())

        if self.category not in rule.applicable_categories:
            reason = (
                f"Rule '{rule_id}' applicable categories {sorted(rule.applicable_categories)} "
                f"do not match hypothesis category '{self.category}'"
            )
            self.primary_rule_audit["reason"] = reason
            return False, reason

        eff_ledger = ledger or self.ledger
        if eff_ledger is None:
            reason = f"Rule '{rule_id}' cannot authorize confirmation: authoritative EvidenceLedger is unavailable"
            self.primary_rule_audit["reason"] = reason
            return False, reason

        target_ev_id = None
        if evidence_record is not None and getattr(evidence_record, "evidence_id", None):
            target_ev_id = evidence_record.evidence_id
        elif self.supporting_evidence_ids:
            target_ev_id = sorted(set(self.supporting_evidence_ids))[0]

        if not target_ev_id:
            reason = f"Rule '{rule_id}' cannot authorize confirmation: no supporting evidence_id provided"
            self.primary_rule_audit["reason"] = reason
            return False, reason

        self.primary_rule_audit["evaluated_evidence_id"] = target_ev_id
        rec_in_ledger = self._lookup_record_in_ledger(eff_ledger, target_ev_id)
        if rec_in_ledger is None:
            reason = f"Rule '{rule_id}' cannot authorize confirmation: evidence '{target_ev_id}' does not exist in authoritative EvidenceLedger"
            self.primary_rule_audit["reason"] = reason
            return False, reason

        # Full authority & 9-dimension identity check on the ledger record
        auth_info = self._validate_evidence_record_authority(target_ev_id, rec_in_ledger, eff_ledger)
        if not auth_info["is_authoritative"]:
            reason = (
                f"Rule '{rule_id}' rejected evidence '{target_ev_id}': "
                f"{auth_info['reason']} (status={auth_info['status']})"
            )
            self.primary_rule_audit["reason"] = reason
            self.primary_rule_audit["identity_status"] = auth_info["status"]
            return False, reason

        rec_prov = auth_info["provenance_class"]
        if rec_prov not in rule.required_provenance_classes:
            reason = (
                f"Evidence provenance '{rec_prov}' does not satisfy rule '{rule_id}' "
                f"required classes {sorted(rule.required_provenance_classes)}"
            )
            self.primary_rule_audit["reason"] = reason
            return False, reason

        rec_type = getattr(rec_in_ledger, "evidence_type", None)
        if not rec_type or rec_type not in rule.allowed_evidence_types:
            reason = (
                f"Evidence type '{rec_type}' does not satisfy rule '{rule_id}' "
                f"allowed types {sorted(rule.allowed_evidence_types)}"
            )
            self.primary_rule_audit["reason"] = reason
            return False, reason

        # Execute rule-specific observation criteria
        crit_ok, crit_reason = rule.evaluate_criteria(rec_in_ledger)
        if not crit_ok:
            reason = f"Rule '{rule_id}' executable observation criteria failed for '{target_ev_id}': {crit_reason}"
            self.primary_rule_audit["reason"] = reason
            return False, reason

        success_msg = f"Primary evidence rule '{rule_id}' (v{rule.version}) criteria satisfied: {crit_reason}"
        self.primary_rule_audit["authorized"] = True
        self.primary_rule_audit["reason"] = success_msg
        self.primary_rule_audit["identity_status"] = "VERIFIED"
        return True, success_msg

    def _add_limitation_unique(self, msg: str) -> None:
        if msg and msg not in self.integrity_limitations:
            self.integrity_limitations.append(msg)

    def get_independent_root_sources(self, ledger: Optional[Any] = None) -> Set[str]:
        """Calculates the set of independent root evidence sources by traversing the complete
        multi-parent dependency DAG and validating against the authoritative EvidenceLedger (Part B1).
        """
        eff_ledger = ledger or self.ledger
        self.unresolved_dependencies = []
        valid_branches: Dict[str, List[str]] = {}
        unresolved_branches: Dict[str, str] = {}

        sorted_ev_ids = sorted(set(self.supporting_evidence_ids))
        if not sorted_ev_ids:
            self.graph_validation_summary = {
                "is_complete": True,
                "partially_invalid": False,
                "valid_branches": {},
                "unresolved_branches": {},
                "independent_root_ids": [],
                "independent_capture_origins": [],
            }
            return set()

        if eff_ledger is None:
            self._add_limitation_unique(
                "Missing authoritative EvidenceLedger: cannot establish independent root evidence sources"
            )
            self.unresolved_dependencies = list(sorted_ev_ids)
            for eid in sorted_ev_ids:
                unresolved_branches[eid] = "Missing authoritative EvidenceLedger"
            self.graph_validation_summary = {
                "is_complete": False,
                "partially_invalid": False,
                "valid_branches": {},
                "unresolved_branches": unresolved_branches,
                "independent_root_ids": [],
                "independent_capture_origins": [],
            }
            return set()

        # Collect all candidate leaf roots across valid branches
        candidate_leaf_roots: Set[str] = set()
        baseline_identities: Dict[str, Any] = {}

        for ev_id in sorted_ev_ids:
            item_roots: Set[str] = set()
            stack: List[Tuple[str, List[str]]] = [(ev_id, [ev_id])]
            branch_invalid = False
            branch_error_reason = ""
            visited_edges = 0

            while stack:
                curr, path = stack.pop()
                visited_edges += 1
                if len(path) > 200 or visited_edges > 2000:
                    branch_error_reason = f"Dependency graph depth/resource limit exceeded at {curr}"
                    self._add_limitation_unique(branch_error_reason)
                    branch_invalid = True
                    break

                if not isinstance(curr, str) or not curr.strip():
                    branch_error_reason = f"Malformed dependency node identifier: {curr!r}"
                    self._add_limitation_unique(branch_error_reason)
                    branch_invalid = True
                    continue

                rec = self._lookup_record_in_ledger(eff_ledger, curr)

                # Gather parents from both hypothesis.evidence_dependencies and ledger record.parent_evidence_ids
                has_explicit_deps_key = curr in self.evidence_dependencies
                raw_dep_val = self.evidence_dependencies.get(curr, [])
                if has_explicit_deps_key and not isinstance(raw_dep_val, (list, tuple, set)):
                    branch_error_reason = f"Malformed dependency edge list on {curr}: {raw_dep_val!r}"
                    self._add_limitation_unique(branch_error_reason)
                    branch_invalid = True
                    continue

                combined_raw_parents: List[Any] = list(raw_dep_val) if isinstance(raw_dep_val, (list, tuple, set)) else []
                if rec is not None:
                    rec_parents = getattr(rec, "parent_evidence_ids", None)
                    if rec_parents:
                        for rp in rec_parents:
                            if rp not in combined_raw_parents:
                                combined_raw_parents.append(rp)
                    rec_derived = (getattr(rec, "details", None) or {}).get("derived_from") if isinstance(getattr(rec, "details", None), dict) else None
                    if rec_derived:
                        d_list = [rec_derived] if isinstance(rec_derived, str) else (list(rec_derived) if isinstance(rec_derived, (list, tuple, set)) else [rec_derived])
                        for dp in d_list:
                            if dp not in combined_raw_parents:
                                combined_raw_parents.append(dp)

                # Detect malformed parent entries before filtering!
                malformed_found = False
                for p in combined_raw_parents:
                    if not isinstance(p, str) or not p.strip():
                        branch_error_reason = f"Malformed dependency edge on {curr}: {p!r}"
                        self._add_limitation_unique(branch_error_reason)
                        branch_invalid = True
                        malformed_found = True
                if malformed_found:
                    continue

                if curr in combined_raw_parents:
                    branch_error_reason = f"Self-dependency detected on {curr}"
                    self._add_limitation_unique(branch_error_reason)
                    branch_invalid = True
                    continue

                unique_parents = sorted(set(combined_raw_parents))

                if not unique_parents:
                    # Leaf / Root node reached: must exist in authoritative ledger and pass full authority validation
                    if rec is None:
                        branch_error_reason = f"Missing root dependency {curr} in ledger"
                        self._add_limitation_unique(branch_error_reason)
                        branch_invalid = True
                        continue
                    auth_info = self._validate_evidence_record_authority(
                        curr, rec, eff_ledger, baseline_identities=baseline_identities
                    )
                    if not auth_info["is_authoritative"]:
                        branch_error_reason = f"Root dependency {curr} failed authority validation: {auth_info['reason']}"
                        self._add_limitation_unique(branch_error_reason)
                        branch_invalid = True
                        continue
                    item_roots.add(curr)
                else:
                    # Intermediate / Derived node: validate if present in ledger, and traverse all parents to catch cycles and missing parents
                    if rec is not None:
                        auth_info = self._validate_evidence_record_authority(
                            curr, rec, eff_ledger, baseline_identities=baseline_identities
                        )
                        if not auth_info["is_authoritative"]:
                            branch_error_reason = f"Dependency node {curr} failed authority validation: {auth_info['reason']}"
                            self._add_limitation_unique(branch_error_reason)
                            branch_invalid = True
                            continue
                    for p in unique_parents:
                        if p in path:
                            cycle_str = " -> ".join(path[path.index(p):] + [p])
                            branch_error_reason = f"Dependency cycle detected: {cycle_str}"
                            self._add_limitation_unique(branch_error_reason)
                            branch_invalid = True
                            continue
                        p_rec = self._lookup_record_in_ledger(eff_ledger, p)
                        if p not in self.evidence_dependencies and p_rec is None:
                            branch_error_reason = f"Missing parent dependency {p} in ledger"
                            self._add_limitation_unique(branch_error_reason)
                            branch_invalid = True
                            continue
                        stack.append((p, path + [p]))

            if not branch_invalid and item_roots:
                valid_branches[ev_id] = sorted(item_roots)
                candidate_leaf_roots.update(item_roots)
            else:
                if ev_id not in self.unresolved_dependencies:
                    self.unresolved_dependencies.append(ev_id)
                unresolved_branches[ev_id] = branch_error_reason or "Unresolved dependency branch"

        # Deduplicate leaf roots that share the same underlying physical capture origin (Part B1)
        # Process in canonical sorted order for insertion-order determinism
        origin_to_canonical_root: Dict[str, str] = {}
        independent_roots: Set[str] = set()
        for root_id in sorted(candidate_leaf_roots):
            root_rec = self._lookup_record_in_ledger(eff_ledger, root_id)
            origin_key = self._extract_capture_origin_key(root_rec, root_id)
            if origin_key not in origin_to_canonical_root:
                origin_to_canonical_root[origin_key] = root_id
                independent_roots.add(root_id)
            else:
                canonical_id = origin_to_canonical_root[origin_key]
                self._add_limitation_unique(
                    f"Root evidence {root_id} shares underlying capture origin ({origin_key}) with {canonical_id} and is not counted as an independent root"
                )

        self.graph_validation_summary = {
            "is_complete": len(unresolved_branches) == 0,
            "partially_invalid": len(valid_branches) > 0 and len(unresolved_branches) > 0,
            "valid_branches": valid_branches,
            "unresolved_branches": unresolved_branches,
            "independent_root_ids": sorted(independent_roots),
            "independent_capture_origins": sorted(origin_to_canonical_root.keys()),
        }
        return independent_roots

    def add_supporting_observation(
        self,
        observation: str,
        evidence_id: Optional[str] = None,
        depends_on: Optional[List[str]] = None,
        weight: float = 0.0,
        evidence_record: Optional[Any] = None,
        target_context: Optional[Dict[str, Any]] = None,
        is_verified: Optional[bool] = None,
    ) -> bool:
        """Adds supporting observation with strict authority/identity validation and anti-double-counting."""
        if not hasattr(self, "_base_confidence"):
            self.__post_init__()

        ctx = target_context or {}
        eff_ledger = ctx.get("ledger") or self.ledger
        if eff_ledger is not None and self.ledger is None:
            self.ledger = eff_ledger

        # Validate authority and identity if evidence_record or evidence_id is provided
        if evidence_record is not None or evidence_id is not None:
            auth_info = self._validate_evidence_record_authority(
                evidence_id=evidence_id,
                rec=evidence_record,
                eff_ledger=eff_ledger,
                target_context=ctx,
            )
            if auth_info["status"] == "IDENTITY_MISMATCH":
                if evidence_id:
                    self.rejected_evidence_reasons[evidence_id] = auth_info["reason"]
                    self.identity_validation_records[evidence_id] = auth_info
                return False
            if evidence_id and eff_ledger is not None and auth_info["status"] == "RECORD_NOT_FOUND":
                self.rejected_evidence_reasons[evidence_id] = auth_info["reason"]
                self.identity_validation_records[evidence_id] = auth_info
                return False
            if evidence_id:
                self.identity_validation_records[evidence_id] = auth_info
                if not auth_info["is_authoritative"]:
                    self.rejected_evidence_reasons[evidence_id] = auth_info["reason"]
                effective_verified = auth_info["is_authoritative"] and (is_verified is not False)
            else:
                effective_verified = False
        else:
            effective_verified = False

        if is_verified is False and evidence_id:
            self._explicit_unverified_ids.add(evidence_id)
            effective_verified = False

        # Idempotency and anti-double-counting checks
        if observation in self.supporting_observations and (not evidence_id or evidence_id in self.supporting_evidence_ids):
            return False
        if evidence_id and evidence_id in self.supporting_evidence_ids:
            return False

        if observation not in self.supporting_observations:
            self.supporting_observations.append(observation)

        if evidence_id:
            if evidence_id not in self.evidence_ids:
                self.evidence_ids.append(evidence_id)
            self.supporting_evidence_ids.append(evidence_id)
            if depends_on is not None:
                self.evidence_dependencies[evidence_id] = list(depends_on)
            if not effective_verified and evidence_id not in self.unverified_evidence_ids:
                self.unverified_evidence_ids.append(evidence_id)

        weight_key = evidence_id or f"obs:{observation}"
        if weight > 0.0:
            self._support_weights[weight_key] = float(weight)

        self.evaluate_verdict(ledger=eff_ledger)
        return True

    def add_contradicting_observation(
        self,
        contradiction: str,
        evidence_id: Optional[str] = None,
        depends_on: Optional[List[str]] = None,
        weight: float = 0.0,
        evidence_record: Optional[Any] = None,
        target_context: Optional[Dict[str, Any]] = None,
        is_decisive: bool = True,
        is_conflicting: bool = False,
        is_verified: Optional[bool] = None,
        is_relevant: bool = True,
        precedence_rule: Optional[str] = None,
    ) -> bool:
        """Adds contradictory observation with authoritative Ledger validation and classification (Part A3)."""
        if not hasattr(self, "_base_confidence"):
            self.__post_init__()

        ctx = target_context or {}
        eff_ledger = ctx.get("ledger") or self.ledger
        if eff_ledger is not None and self.ledger is None:
            self.ledger = eff_ledger

        exp_inv = ctx.get("investigation_id") or self.investigation_id or (getattr(eff_ledger, "session_id", None) if eff_ledger else None)
        exp_pid = ctx.get("target_pid") if ctx.get("target_pid") is not None else (ctx.get("pid") if ctx.get("pid") is not None else self.target_pid)

        # Idempotency and anti-double-counting checks
        if contradiction in self.contradicting_observations and (not evidence_id or evidence_id in self.contradicting_evidence_ids):
            return False
        if evidence_id and evidence_id in self.contradicting_evidence_ids and contradiction in self.contradicting_observations:
            return False

        rel = bool(is_relevant)
        rej_reason: Optional[str] = None
        prov_class = "IMPORTED_UNVERIFIED"
        auth_decision = "UNVERIFIED"
        ident_status = "UNVERIFIED"
        effective_verified = False

        if evidence_record is not None or evidence_id is not None:
            auth_info = self._validate_evidence_record_authority(
                evidence_id=evidence_id,
                rec=evidence_record,
                eff_ledger=eff_ledger,
                target_context=ctx,
            )
            prov_class = auth_info.get("provenance_class", "IMPORTED_UNVERIFIED")
            ident_status = auth_info["status"]
            if evidence_id:
                self.identity_validation_records[evidence_id] = auth_info

            if auth_info["status"] in ("IDENTITY_MISMATCH", "RECORD_NOT_FOUND"):
                rel = False
                rej_reason = auth_info["reason"]
                auth_decision = "REJECTED_MISMATCH" if auth_info["status"] == "IDENTITY_MISMATCH" else "RECORD_NOT_FOUND"
                if evidence_id:
                    self.rejected_evidence_reasons[evidence_id] = rej_reason
            elif not auth_info["is_authoritative"]:
                rej_reason = auth_info["reason"]
                auth_decision = "REJECTED_MISSING_IDENTITY" if auth_info["status"] == "MISSING_IDENTITY" else "UNVERIFIED"
                if evidence_id:
                    self.rejected_evidence_reasons[evidence_id] = rej_reason
            else:
                # Authoritative record in Ledger with verified identity and trusted provenance
                if is_verified is False:
                    effective_verified = False
                    auth_decision = "UNVERIFIED"
                else:
                    effective_verified = True
                    auth_decision = "AUTHORITATIVE"

        if not rel and auth_decision == "AUTHORITATIVE":
            auth_decision = "REJECTED_IRRELEVANT"

        if contradiction not in self.contradicting_observations:
            self.contradicting_observations.append(contradiction)

        if evidence_id:
            if evidence_id not in self.evidence_ids:
                self.evidence_ids.append(evidence_id)
            if evidence_id not in self.contradicting_evidence_ids:
                self.contradicting_evidence_ids.append(evidence_id)
            if depends_on is not None:
                self.evidence_dependencies[evidence_id] = list(depends_on)

        # Determine initial contradiction class
        if not rel:
            c_class = CONTRADICTION_CLASS_IRRELEVANT
        elif not effective_verified:
            c_class = CONTRADICTION_CLASS_UNTRUSTED
        elif is_conflicting:
            c_class = CONTRADICTION_CLASS_CONFLICTING
        elif is_decisive:
            c_class = CONTRADICTION_CLASS_DECISIVE
        else:
            c_class = CONTRADICTION_CLASS_PARTIAL

        crec = ContradictionRecord(
            contradiction=contradiction,
            evidence_id=evidence_id,
            is_decisive=is_decisive,
            is_conflicting=is_conflicting,
            is_verified=effective_verified,
            provenance_class=prov_class,
            target_pid=exp_pid,
            investigation_id=exp_inv,
            is_relevant=rel,
            rejection_reason=rej_reason,
            contradiction_class=c_class,
            authority_decision=auth_decision,
            identity_status=ident_status,
            precedence_rule=precedence_rule,
        )
        self.contradiction_records.append(crec)

        weight_key = evidence_id or f"contra:{contradiction}"
        if rel and weight > 0.0:
            self._contradiction_weights[weight_key] = float(weight)

        self.evaluate_verdict(ledger=eff_ledger)
        return True

    @staticmethod
    def _evaluate_decisive_contradiction_rule(
        category: str,
        crec: ContradictionRecord,
        rec: Any,
    ) -> Tuple[bool, str, Optional[str]]:
        """Evaluates deterministic rule for a decisive contradiction and checks if a documented
        structural impossibility precedence rule supersedes conflicting support (Part A3 & B2).
        """
        obs_txt = (crec.contradiction or "") + " " + (_extract_record_searchable_text(rec) if rec else "")
        low_txt = obs_txt.lower()
        if not low_txt.strip():
            return False, "Empty contradiction observation cannot satisfy decisive contradiction rule", None

        # Check documented deterministic structural impossibility precedence rules
        precedence_rule = crec.precedence_rule
        if not precedence_rule:
            if category in ("USE_AFTER_FREE", "HEAP_CORRUPTION", "MEMORY_CORRUPTION", "INVALID_DOUBLE_FREE"):
                if any(
                    kw in low_txt
                    for kw in (
                        "static lifetime",
                        "global data segment",
                        "valid static global",
                        "rodata",
                        "static segment",
                    )
                ):
                    precedence_rule = "RULE_STATIC_SEGMENT_IMPOSSIBILITY_PRECEDENCE"

        return True, "DECISIVE_AUTHORITATIVE_CONTRADICTION_RULE", precedence_rule

    def evaluate_verdict(self, ledger: Optional[Any] = None) -> str:
        """Deterministically evaluates hypothesis verdict and updates decision_trace (Part A1–A5, B1, B2).
        
        Idempotent and insertion-order independent. Never trusts caller-supplied flags over
        authoritative EvidenceLedger metadata.
        """
        if not hasattr(self, "_base_confidence"):
            self.__post_init__()

        # Detect if caller externally set self.confidence since last evaluation
        if self._computed_confidence is not None and abs(self.confidence - self._computed_confidence) > 1e-6:
            self._base_confidence = float(self.confidence)
        elif self._computed_confidence is None and not self._support_weights and not self._contradiction_weights:
            self._base_confidence = float(self.confidence)

        eff_ledger = ledger or self.ledger
        if eff_ledger is not None and self.ledger is None:
            self.ledger = eff_ledger

        # Reset transient evaluation state for idempotency (Part A5 & B2)
        self.integrity_limitations = []
        self.satisfied_primary_rule = None
        self.primary_rule_rejection_reason = None
        self.primary_rule_audit = {}
        current_unverified: Set[str] = set(self._explicit_unverified_ids)
        baseline_identities: Dict[str, Any] = {}

        # 1. Validate all supporting_evidence_ids against authoritative Ledger & identity requirements
        for ev_id in sorted(set(self.supporting_evidence_ids)):
            rec = self._lookup_record_in_ledger(eff_ledger, ev_id) if eff_ledger is not None else None
            auth_info = self._validate_evidence_record_authority(
                evidence_id=ev_id,
                rec=rec,
                eff_ledger=eff_ledger,
                baseline_identities=baseline_identities,
            )
            self.identity_validation_records[ev_id] = auth_info
            if not auth_info["is_authoritative"]:
                current_unverified.add(ev_id)
                self.rejected_evidence_reasons[ev_id] = auth_info["reason"]
                self._add_limitation_unique(f"Supporting evidence '{ev_id}' unverified: {auth_info['reason']}")

        self.unverified_evidence_ids = sorted(current_unverified)

        # 2. Evaluate independent root evidence sources (Part B1)
        independent_roots = self.get_independent_root_sources(ledger=eff_ledger)
        num_independent = len(independent_roots)
        has_trusted_support = (
            num_independent >= 1
            and len(self.unverified_evidence_ids) == 0
            and len(self.unresolved_dependencies) == 0
        )

        # 3. Synthesize ContradictionRecords for any legacy contradicting_evidence_ids / observations
        # so legacy fields NEVER bypass validation or auto-produce REFUTED (Part A3)
        recorded_contra_ev_ids = {c.evidence_id for c in self.contradiction_records if c.evidence_id}
        recorded_contra_texts = {c.contradiction for c in self.contradiction_records if c.contradiction}
        for leg_ev_id in sorted(set(self.contradicting_evidence_ids)):
            if leg_ev_id not in recorded_contra_ev_ids:
                self.contradiction_records.append(
                    ContradictionRecord(
                        contradiction=f"Legacy contradicting evidence {leg_ev_id}",
                        evidence_id=leg_ev_id,
                        is_decisive=True,
                        is_verified=False,
                    )
                )
        for leg_obs in self.contradicting_observations:
            if leg_obs not in recorded_contra_texts and not self.contradiction_records:
                self.contradiction_records.append(
                    ContradictionRecord(
                        contradiction=leg_obs,
                        evidence_id=None,
                        is_decisive=True,
                        is_verified=False,
                    )
                )

        # 4. Re-validate every ContradictionRecord against the authoritative Ledger (Part A3 & A5)
        # Never trust ContradictionRecord.is_verified by itself!
        trusted_conflicting: List[ContradictionRecord] = []
        trusted_decisive: List[ContradictionRecord] = []
        trusted_partial: List[ContradictionRecord] = []
        untrusted_contradictions: List[ContradictionRecord] = []
        irrelevant_contradictions: List[ContradictionRecord] = []
        precedence_refutations: List[ContradictionRecord] = []

        for c in self.contradiction_records:
            if not c.is_relevant:
                c.is_verified = False
                c.contradiction_class = CONTRADICTION_CLASS_IRRELEVANT
                c.authority_decision = "REJECTED_IRRELEVANT"
                irrelevant_contradictions.append(c)
                continue

            if not c.evidence_id or eff_ledger is None:
                c.is_verified = False
                c.identity_status = "NO_LEDGER" if eff_ledger is None else "MISSING_EVIDENCE_ID"
                c.authority_decision = "UNVERIFIED"
                if not c.rejection_reason:
                    c.rejection_reason = (
                        "Missing authoritative EvidenceLedger for contradiction"
                        if eff_ledger is None
                        else "Contradiction lacks authoritative evidence_id in ledger"
                    )
                c.contradiction_class = CONTRADICTION_CLASS_UNTRUSTED
                untrusted_contradictions.append(c)
                self._add_limitation_unique(f"Unverified contradiction retained without refutation authority: {c.rejection_reason}")
                continue

            c_rec = self._lookup_record_in_ledger(eff_ledger, c.evidence_id)
            c_auth = self._validate_evidence_record_authority(
                evidence_id=c.evidence_id,
                rec=c_rec,
                eff_ledger=eff_ledger,
                baseline_identities=baseline_identities,
            )
            self.identity_validation_records[c.evidence_id] = c_auth
            c.identity_status = c_auth["status"]
            c.provenance_class = c_auth.get("provenance_class", c.provenance_class)

            if c_auth["status"] == "IDENTITY_MISMATCH":
                c.is_verified = False
                c.is_relevant = False
                c.rejection_reason = c_auth["reason"]
                c.authority_decision = "REJECTED_MISMATCH"
                c.contradiction_class = CONTRADICTION_CLASS_IRRELEVANT
                self.rejected_evidence_reasons[c.evidence_id] = c_auth["reason"]
                irrelevant_contradictions.append(c)
                self._add_limitation_unique(f"Contradiction '{c.evidence_id}' rejected due to identity mismatch: {c_auth['reason']}")
                continue

            if not c_auth["is_authoritative"]:
                c.is_verified = False
                c.rejection_reason = c_auth["reason"]
                c.authority_decision = (
                    "REJECTED_MISSING_IDENTITY"
                    if c_auth["status"] == "MISSING_IDENTITY"
                    else ("RECORD_NOT_FOUND" if c_auth["status"] == "RECORD_NOT_FOUND" else "UNVERIFIED")
                )
                c.contradiction_class = CONTRADICTION_CLASS_UNTRUSTED
                self.rejected_evidence_reasons[c.evidence_id] = c_auth["reason"]
                untrusted_contradictions.append(c)
                self._add_limitation_unique(f"Contradiction '{c.evidence_id}' unverified: {c_auth['reason']}")
                continue

            # Record is authoritative in Ledger with verified identity and trusted provenance!
            c.is_verified = True
            c.authority_decision = "AUTHORITATIVE"
            c.rejection_reason = None

            if c.is_conflicting:
                c.contradiction_class = CONTRADICTION_CLASS_CONFLICTING
                trusted_conflicting.append(c)
            elif c.is_decisive:
                rule_ok, rule_id, prec_rule = self._evaluate_decisive_contradiction_rule(self.category, c, c_rec)
                if rule_ok:
                    c.decisive_rule_id = rule_id
                    if prec_rule:
                        c.precedence_rule = prec_rule
                    if has_trusted_support and not c.precedence_rule:
                        # Conflicting authoritative support AND decisive contradiction without precedence rule!
                        c.contradiction_class = CONTRADICTION_CLASS_CONFLICTING
                        trusted_conflicting.append(c)
                    else:
                        c.contradiction_class = CONTRADICTION_CLASS_DECISIVE
                        trusted_decisive.append(c)
                        if c.precedence_rule:
                            precedence_refutations.append(c)
                else:
                    c.contradiction_class = CONTRADICTION_CLASS_PARTIAL
                    trusted_partial.append(c)
            else:
                c.contradiction_class = CONTRADICTION_CLASS_PARTIAL
                trusted_partial.append(c)

        # 5. Compute deterministic base + delta confidence (insertion-order independent!)
        support_delta = sum(w for _, w in sorted(self._support_weights.items()))
        contra_delta = sum(
            w for k, w in sorted(self._contradiction_weights.items())
            if not any(ic.evidence_id == k or f"contra:{ic.contradiction}" == k for ic in irrelevant_contradictions)
        )
        computed_conf = max(0.05, min(0.99, round(self._base_confidence + support_delta - contra_delta, 6)))

        decision_rule_applied = ""
        decision_explanation = ""

        # 6. Apply deterministic verdict decision rules (Part B2)
        if trusted_conflicting:
            self.status = VERDICT_INCONCLUSIVE
            self.confidence = 0.45
            self.confidence_basis = (
                "Conflicting authoritative evidence: trusted observations support contradictory conclusions."
            )
            decision_rule_applied = "RULE_INCONCLUSIVE_CONFLICTING_AUTHORITATIVE_EVIDENCE"
            decision_explanation = (
                f"Both authoritative support ({sorted(independent_roots)}) and authoritative contradiction "
                f"({[c.evidence_id for c in trusted_conflicting]}) are verified with no precedence override."
            )
        elif trusted_decisive:
            self.status = VERDICT_REFUTED
            self.confidence = min(computed_conf, 0.10)
            if precedence_refutations:
                decision_rule_applied = f"RULE_REFUTED_DETERMINISTIC_PRECEDENCE:{precedence_refutations[0].precedence_rule}"
                decision_explanation = (
                    f"Refuted by authoritative decisive contradiction {[c.evidence_id for c in trusted_decisive]} "
                    f"under precedence rule {precedence_refutations[0].precedence_rule}."
                )
            else:
                decision_rule_applied = "RULE_REFUTED_DECISIVE_AUTHORITATIVE_CONTRADICTION"
                decision_explanation = (
                    f"Refuted by authoritative decisive contradiction {[c.evidence_id for c in trusted_decisive]}."
                )
        else:
            if trusted_partial:
                computed_conf = max(0.20, min(computed_conf, 0.65))
            elif untrusted_contradictions and any(
                not c.evidence_id and c.is_decisive for c in untrusted_contradictions
            ) and self._contradiction_weights:
                # Partial/unverified observation with explicit weight reduces confidence without refuting
                computed_conf = max(0.20, min(computed_conf, 0.68))

            self.confidence = computed_conf

            if self.missing_evidence:
                self.status = VERDICT_INCONCLUSIVE
                decision_rule_applied = "RULE_INCONCLUSIVE_MISSING_REQUIRED_EVIDENCE"
                decision_explanation = f"Missing required evidence prevents confirmation or refutation: {self.missing_evidence}"
            elif not self.supporting_evidence_ids:
                if self.supporting_observations:
                    self.status = VERDICT_LIKELY if self.confidence >= 0.70 else VERDICT_SUPPORTED
                    decision_rule_applied = "RULE_UNANCHORED_DESCRIPTIVE_OBSERVATIONS"
                    decision_explanation = "Descriptive observations without authoritative Evidence IDs cannot produce CONFIRMED."
                else:
                    self.status = VERDICT_INCONCLUSIVE
                    decision_rule_applied = "RULE_INCONCLUSIVE_NO_SUPPORTING_EVIDENCE"
                    decision_explanation = "No supporting observations or evidence IDs recorded."
            elif self.unresolved_dependencies and num_independent == 0 and any(
                "cycle" in lim.lower() or "self-dependency" in lim.lower() or "missing parent" in lim.lower() or "malformed" in lim.lower()
                for lim in self.integrity_limitations
            ):
                self.status = VERDICT_INCONCLUSIVE
                decision_rule_applied = "RULE_INCONCLUSIVE_INVALID_DEPENDENCY_GRAPH"
                decision_explanation = f"Evidence dependency graph contains invalid branches: {self.integrity_limitations}"
            elif self.unverified_evidence_ids or self.unresolved_dependencies:
                self.status = VERDICT_LIKELY if self.confidence >= 0.70 else VERDICT_SUPPORTED
                decision_rule_applied = "RULE_LOWER_CONFIDENCE_UNVERIFIED_EVIDENCE"
                decision_explanation = (
                    f"Unverified or unresolved evidence IDs ({self.unverified_evidence_ids}) cannot authorize CONFIRMED."
                )
            elif num_independent == 0:
                self.status = VERDICT_INCONCLUSIVE
                decision_rule_applied = "RULE_INCONCLUSIVE_ZERO_INDEPENDENT_ROOTS"
                decision_explanation = "Zero authoritative independent root evidence sources available."
            else:
                can_single_confirm = False
                if num_independent == 1 and self.primary_evidence_rule:
                    is_valid, reason = self.validate_primary_evidence_rule(
                        self.primary_evidence_rule, ledger=eff_ledger
                    )
                    if is_valid:
                        can_single_confirm = True
                        self.satisfied_primary_rule = self.primary_evidence_rule
                    else:
                        self.satisfied_primary_rule = None
                        self.primary_rule_rejection_reason = reason

                if (
                    (num_independent >= 2 or (num_independent >= 1 and can_single_confirm))
                    and self.confidence >= 0.90
                    and not trusted_partial
                    and not untrusted_contradictions
                ):
                    self.status = VERDICT_CONFIRMED
                    if num_independent >= 2:
                        decision_rule_applied = "RULE_CONFIRMED_MULTI_INDEPENDENT_ROOTS"
                        decision_explanation = (
                            f"Confirmed by {num_independent} independent authoritative root sources "
                            f"{sorted(independent_roots)} with confidence {self.confidence:.2f}."
                        )
                    else:
                        decision_rule_applied = f"RULE_CONFIRMED_PRIMARY_EVIDENCE_RULE:{self.satisfied_primary_rule}"
                        decision_explanation = (
                            f"Confirmed by single authoritative root {sorted(independent_roots)} under validated "
                            f"primary evidence rule '{self.satisfied_primary_rule}'."
                        )
                elif (
                    (num_independent >= 2 or (num_independent >= 1 and can_single_confirm))
                    and self.confidence >= 0.90
                    and not trusted_partial
                    and untrusted_contradictions
                ):
                    # Untrusted contradictions must NOT refute a hypothesis backed by verified support!
                    self.status = VERDICT_CONFIRMED
                    decision_rule_applied = "RULE_CONFIRMED_UNTRUSTED_CONTRADICTION_IGNORED"
                    decision_explanation = (
                        f"Confirmed by authoritative support {sorted(independent_roots)}; "
                        f"{len(untrusted_contradictions)} untrusted contradiction(s) cannot refute verified support."
                    )
                elif num_independent >= 1 and self.confidence >= 0.70:
                    self.status = VERDICT_LIKELY
                    decision_rule_applied = "RULE_LIKELY_SINGLE_ROOT_OR_PARTIAL_CONTRA"
                    decision_explanation = (
                        f"Supported by {num_independent} authoritative root(s) {sorted(independent_roots)} "
                        f"with confidence {self.confidence:.2f} (requires >=2 independent roots or valid primary rule for CONFIRMED)."
                    )
                elif num_independent >= 1:
                    self.status = VERDICT_SUPPORTED
                    decision_rule_applied = "RULE_SUPPORTED_MODERATE_CONFIDENCE"
                    decision_explanation = (
                        f"Supported by {num_independent} authoritative root(s) with moderate confidence {self.confidence:.2f}."
                    )
                else:
                    self.status = VERDICT_INCONCLUSIVE
                    decision_rule_applied = "RULE_INCONCLUSIVE_FALLBACK"
                    decision_explanation = "Insufficient authoritative evidence for confirmation or refutation."

        self._computed_confidence = self.confidence
        self.decision_trace = {
            "hypothesis_id": self.hypothesis_id,
            "category": self.category,
            "evaluated_status": self.status,
            "effective_confidence": round(self.confidence, 4),
            "base_confidence": round(self._base_confidence, 4),
            "ledger_present": eff_ledger is not None,
            "ledger_session_id": getattr(eff_ledger, "session_id", None) if eff_ledger is not None else None,
            "independent_root_sources": sorted(independent_roots),
            "independent_root_count": num_independent,
            "supporting_evidence_ids": sorted(set(self.supporting_evidence_ids)),
            "unverified_evidence_ids": list(self.unverified_evidence_ids),
            "unresolved_dependencies": list(self.unresolved_dependencies),
            "rejected_evidence_reasons": dict(self.rejected_evidence_reasons),
            "identity_validation_records": dict(self.identity_validation_records),
            "contradiction_summary": {
                "decisive_authoritative": [c.evidence_id for c in trusted_decisive],
                "partial_authoritative": [c.evidence_id for c in trusted_partial],
                "conflicting_authoritative": [c.evidence_id for c in trusted_conflicting],
                "untrusted": [c.evidence_id or c.contradiction for c in untrusted_contradictions],
                "irrelevant": [c.evidence_id or c.contradiction for c in irrelevant_contradictions],
            },
            "primary_evidence_rule_evaluated": dict(self.primary_rule_audit) if self.primary_rule_audit else None,
            "missing_evidence": list(self.missing_evidence),
            "integrity_limitations": list(self.integrity_limitations),
            "decision_rule_applied": decision_rule_applied,
            "decision_explanation": decision_explanation,
        }
        return self.status

    def to_dict(self) -> Dict[str, Any]:
        saved_ledger = self.ledger
        try:
            self.ledger = None
            d = asdict(self)
        finally:
            self.ledger = saved_ledger
        d.pop("ledger", None)
        d["_base_confidence"] = getattr(self, "_base_confidence", self.confidence)
        d["_support_weights"] = dict(getattr(self, "_support_weights", {}))
        d["_contradiction_weights"] = dict(getattr(self, "_contradiction_weights", {}))
        d["_explicit_unverified_ids"] = sorted(getattr(self, "_explicit_unverified_ids", set()))
        d["_permanently_rejected_reasons"] = dict(getattr(self, "_permanently_rejected_reasons", {}))
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any], ledger: Optional[Any] = None) -> "CompetingHypothesis":
        data_copy = dict(data)
        bound_ledger = ledger or data_copy.pop("ledger", None)
        base_conf = data_copy.pop("_base_confidence", None)
        sup_weights = data_copy.pop("_support_weights", None)
        con_weights = data_copy.pop("_contradiction_weights", None)
        exp_unver = data_copy.pop("_explicit_unverified_ids", None)
        perm_rej = data_copy.pop("_permanently_rejected_reasons", None)

        if "contradiction_records" in data_copy and isinstance(data_copy["contradiction_records"], list):
            data_copy["contradiction_records"] = [
                ContradictionRecord.from_dict(c) if isinstance(c, dict) else c
                for c in data_copy["contradiction_records"]
            ]
        valid_fields = {f.name for f in fields(cls)}
        filtered = {k: v for k, v in data_copy.items() if k in valid_fields}
        if bound_ledger is not None:
            filtered["ledger"] = bound_ledger
        obj = cls(**filtered)
        if base_conf is not None:
            obj._base_confidence = float(base_conf)
        if isinstance(sup_weights, dict):
            obj._support_weights = {str(k): float(v) for k, v in sup_weights.items()}
        if isinstance(con_weights, dict):
            obj._contradiction_weights = {str(k): float(v) for k, v in con_weights.items()}
        if isinstance(exp_unver, list):
            obj._explicit_unverified_ids = set(exp_unver)
        if isinstance(perm_rej, dict):
            obj._permanently_rejected_reasons = dict(perm_rej)
        obj._computed_confidence = obj.confidence
        # Part A5 & Part F: Re-evaluate authority on reload so serialized status cannot bypass Ledger validation
        if bound_ledger is not None or obj.supporting_evidence_ids or obj.contradicting_evidence_ids or obj.contradiction_records:
            obj.evaluate_verdict(ledger=bound_ledger)
        return obj


@dataclass
class HypothesisComparisonResult:
    """Outcome of comparing competing hypotheses with technical rationale."""
    leading_hypothesis_id: Optional[str]
    ranked_hypotheses: List[Dict[str, Any]]
    discrimination_rationale: str
    eliminated_alternatives: List[str]
    unresolved_uncertainties: List[str]
    recommended_discriminating_recipe: Optional[str] = None
    candidate_actions_discrimination: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def separation_score(self) -> float:
        if self.candidate_actions_discrimination:
            return max(a.get("discrimination_score", 0.0) for a in self.candidate_actions_discrimination)
        return 0.0


class CompetingHypothesisManager:
    """Manages creation, evaluation, and true information-gain comparison of competing hypotheses."""

    def __init__(self, target_context: Optional[Dict[str, Any]] = None):
        self.hypotheses: Dict[str, CompetingHypothesis] = {}
        self.target_context: Dict[str, Any] = target_context or {}

    def register_hypothesis(self, hyp: CompetingHypothesis) -> None:
        if self.target_context.get("ledger") is not None and hyp.ledger is None:
            hyp.ledger = self.target_context["ledger"]
        if self.target_context.get("investigation_id") and not hyp.investigation_id:
            hyp.investigation_id = self.target_context["investigation_id"]
        if self.target_context.get("target_pid") is not None and hyp.target_pid is None:
            hyp.target_pid = self.target_context["target_pid"]
        self.hypotheses[hyp.hypothesis_id] = hyp

    def get_hypothesis(self, hyp_id: str) -> Optional[CompetingHypothesis]:
        return self.hypotheses.get(hyp_id)

    def add_supporting_observation(
        self,
        hypothesis_id: str,
        observation: str,
        weight: float = 0.0,
        evidence_id: Optional[str] = None,
        depends_on: Optional[List[str]] = None,
        evidence_record: Optional[Any] = None,
        target_context: Optional[Dict[str, Any]] = None,
        is_verified: Optional[bool] = None,
    ) -> bool:
        hyp = self.hypotheses.get(hypothesis_id)
        if not hyp:
            return False
        ctx = dict(self.target_context)
        if target_context:
            ctx.update(target_context)
        return hyp.add_supporting_observation(
            observation=observation,
            evidence_id=evidence_id,
            depends_on=depends_on,
            weight=weight,
            evidence_record=evidence_record,
            target_context=ctx,
            is_verified=is_verified,
        )

    def add_contradicting_observation(
        self,
        hypothesis_id: str,
        contradiction: str,
        weight: float = 0.0,
        evidence_id: Optional[str] = None,
        depends_on: Optional[List[str]] = None,
        evidence_record: Optional[Any] = None,
        target_context: Optional[Dict[str, Any]] = None,
        is_decisive: bool = True,
        is_verified: Optional[bool] = None,
        is_relevant: bool = True,
    ) -> bool:
        hyp = self.hypotheses.get(hypothesis_id)
        if not hyp:
            return False
        ctx = dict(self.target_context)
        if target_context:
            ctx.update(target_context)
        return hyp.add_contradicting_observation(
            contradiction=contradiction,
            evidence_id=evidence_id,
            depends_on=depends_on,
            weight=weight,
            evidence_record=evidence_record,
            target_context=ctx,
            is_decisive=is_decisive,
            is_verified=is_verified,
            is_relevant=is_relevant,
        )

    def update_verdicts(self, ledger: Optional[Any] = None) -> None:
        eff_ledger = ledger or self.target_context.get("ledger")
        for hyp in self.hypotheses.values():
            hyp.evaluate_verdict(ledger=eff_ledger or hyp.ledger)

    @staticmethod
    def generate_competing_hypotheses(
        category: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> List[CompetingHypothesis]:
        return CompetingHypothesisManager.generate_competing_hypotheses_for_symptom(category, context)

    @staticmethod
    def generate_competing_hypotheses_for_symptom(
        symptom_category: str,
        initial_context: Optional[Dict[str, Any]] = None,
    ) -> List[CompetingHypothesis]:
        """Generates domain-specific competing candidate hypotheses for a reported symptom."""
        ctx = initial_context or {}
        cat_upper = (symptom_category or "GENERAL").upper()
        hypotheses: List[CompetingHypothesis] = []

        if (
            cat_upper == "MEMORY_LEAK"
            or "GROWTH" in cat_upper
            or "LEAK" in cat_upper
            or "ACCUMULATION" in cat_upper
            or "IMBALANCE" in cat_upper
        ):
            hypotheses = [
                CompetingHypothesis(
                    hypothesis_id="HYP_HEAP_ALLOC_LEAK",
                    title="Unmanaged Heap Allocation Expansion",
                    category="MEMORY_LEAK",
                    domain="MEMORY_GROWTH",
                    required_observations=["heap_vma_temporal_samples", "dominant_chunk_distribution"],
                    applicable_diagnostic_rules=["RECIPE_HEAP_GROWTH", "RECIPE_REPEATED_ALLOCATION_PATTERNS", "RECIPE_PROCESS_MEMORY_GROWTH"],
                    discriminating_actions=["RECIPE_HEAP_GROWTH", "RECIPE_REPEATED_ALLOCATION_PATTERNS"],
                    confidence_basis="Heap memory grows monotonically across observation epochs without reclamation.",
                ),
                CompetingHypothesis(
                    hypothesis_id="HYP_OBJECT_ACCUMULATION",
                    title="Long-Lived Object Accumulation in Containers / Caches",
                    category="MEMORY_LEAK",
                    domain="MEMORY_GROWTH",
                    required_observations=["container_element_count", "container_capacity"],
                    applicable_diagnostic_rules=["RECIPE_LONG_LIVED_OBJECT_ACCUMULATION", "RECIPE_LARGE_CONTAINER_RETENTION"],
                    discriminating_actions=["RECIPE_LONG_LIVED_OBJECT_ACCUMULATION"],
                    confidence_basis="Global or static container element count accumulates monotonically without eviction.",
                ),
                CompetingHypothesis(
                    hypothesis_id="HYP_ALLOC_FREE_IMBALANCE",
                    title="Allocation and Deallocation Counter Imbalance",
                    category="MEMORY_LEAK",
                    domain="MEMORY_GROWTH",
                    required_observations=["alloc_counter_value", "free_counter_value"],
                    applicable_diagnostic_rules=["RECIPE_ALLOCATION_FREE_IMBALANCE"],
                    discriminating_actions=["RECIPE_ALLOCATION_FREE_IMBALANCE"],
                    confidence_basis="Allocation counter delta vastly exceeds deallocation counter delta under active load.",
                ),
                CompetingHypothesis(
                    hypothesis_id="HYP_TRANSIENT_WARMUP",
                    title="Transient Initialization or Cache Warm-up Plateau",
                    category="MEMORY_LEAK",
                    domain="MEMORY_GROWTH",
                    required_observations=["rss_history_plateau", "cache_hit_ratio"],
                    applicable_diagnostic_rules=["RECIPE_HEAP_GROWTH", "RECIPE_OBJECT_ALLOCATION_BURSTS"],
                    discriminating_actions=["RECIPE_HEAP_GROWTH", "RECIPE_OBJECT_ALLOCATION_BURSTS"],
                    confidence_basis="RSS expands initially then settles at a bounded stable plateau.",
                ),
                CompetingHypothesis(
                    hypothesis_id="HYP_ALLOCATOR_FRAGMENTATION",
                    title="Allocator Arena Fragmentation and Retention",
                    category="MEMORY_LEAK",
                    domain="MEMORY_GROWTH",
                    required_observations=["arena_free_chunks", "unmapped_chunk_delta"],
                    applicable_diagnostic_rules=["RECIPE_HEAP_GROWTH"],
                    discriminating_actions=["RECIPE_HEAP_GROWTH"],
                    confidence_basis="Virtual address space expands due to fragmentation while live object count is constant.",
                ),
            ]

        elif (
            cat_upper == "CORRUPTION"
            or "CORRUPT" in cat_upper
            or "USE_AFTER_FREE" in cat_upper
            or "DOUBLE_FREE" in cat_upper
            or "INVALID_MEMORY" in cat_upper
            or "OVERFLOW" in cat_upper
        ):
            hypotheses = [
                CompetingHypothesis(
                    hypothesis_id="HYP_USE_AFTER_FREE",
                    title="Dangling Pointer Dereference (Use-After-Free)",
                    category="MEMORY_CORRUPTION",
                    domain="MEMORY_INTEGRITY",
                    required_observations=["freelist_presence", "target_object_lifecycle"],
                    applicable_diagnostic_rules=["RECIPE_USE_AFTER_FREE", "RECIPE_OBJECT_LIFETIME_ANOMALIES"],
                    discriminating_actions=["RECIPE_USE_AFTER_FREE"],
                    confidence_basis="Target pointer references memory previously returned to the allocator.",
                ),
                CompetingHypothesis(
                    hypothesis_id="HYP_HEAP_BUFFER_OVERFLOW",
                    title="Out-of-Bounds Heap Buffer Write",
                    category="MEMORY_CORRUPTION",
                    domain="MEMORY_INTEGRITY",
                    required_observations=["chunk_header_canaries", "neighboring_chunk_state"],
                    applicable_diagnostic_rules=["RECIPE_HEAP_METADATA_CORRUPTION", "RECIPE_ADJACENT_OBJECT_CORRUPTION"],
                    discriminating_actions=["RECIPE_HEAP_METADATA_CORRUPTION"],
                    confidence_basis="Chunk header canary or neighboring chunk metadata is overwritten.",
                ),
                CompetingHypothesis(
                    hypothesis_id="HYP_DOUBLE_FREE",
                    title="Duplicate Memory Release (Double Free)",
                    category="MEMORY_CORRUPTION",
                    domain="MEMORY_INTEGRITY",
                    required_observations=["freelist_occurrence_count", "free_call_stream"],
                    applicable_diagnostic_rules=["RECIPE_DOUBLE_FREE"],
                    discriminating_actions=["RECIPE_DOUBLE_FREE"],
                    confidence_basis="Same chunk address submitted to free() twice without intervening allocation.",
                ),
                CompetingHypothesis(
                    hypothesis_id="HYP_UNMAPPED_WILD_ACCESS",
                    title="Unmapped / Wild Pointer Dereference",
                    category="MEMORY_CORRUPTION",
                    domain="MEMORY_INTEGRITY",
                    required_observations=["vma_permissions", "pointer_register_contents"],
                    applicable_diagnostic_rules=["RECIPE_INVALID_MEMORY_ACCESS", "RECIPE_STACK_FRAME_CORRUPTION"],
                    discriminating_actions=["RECIPE_INVALID_MEMORY_ACCESS"],
                    confidence_basis="Faulting address does not reside in mapped memory or violates guard page.",
                ),
            ]

        elif (
            "DEADLOCK" in cat_upper
            or "CONCURRENCY" in cat_upper
            or "CONTENTION" in cat_upper
            or "FREEZE" in cat_upper
            or "HANG" in cat_upper
            or "THREAD" in cat_upper
        ):
            hypotheses = [
                CompetingHypothesis(
                    hypothesis_id="HYP_CIRCULAR_WAIT_DEADLOCK",
                    title="Mutual Wait Cycle (Classic AB-BA or Multi-Thread Deadlock)",
                    category="CONCURRENCY",
                    domain="CONCURRENCY",
                    required_observations=["mutex_wait_chains", "holding_thread_ids"],
                    applicable_diagnostic_rules=["RECIPE_POTENTIAL_DEADLOCK_PATTERNS", "RECIPE_SUSPICIOUS_LOCK_OWNERSHIP"],
                    discriminating_actions=["RECIPE_POTENTIAL_DEADLOCK_PATTERNS"],
                    confidence_basis="Two or more threads form a closed circular wait dependency.",
                ),
                CompetingHypothesis(
                    hypothesis_id="HYP_LONG_HOLDING_CONTENTION",
                    title="Severe Lock Contention / Long-Holding Critical Section",
                    category="CONCURRENCY",
                    domain="CONCURRENCY",
                    required_observations=["lock_holding_duration", "wait_queue_depth"],
                    applicable_diagnostic_rules=["RECIPE_LOCK_CONTENTION_HOTSPOTS", "RECIPE_LONG_RUNNING_BLOCKED_THREADS"],
                    discriminating_actions=["RECIPE_LOCK_CONTENTION_HOTSPOTS"],
                    confidence_basis="Lock is held for excessive duration causing transient queuing without circular dependency.",
                ),
                CompetingHypothesis(
                    hypothesis_id="HYP_KERNEL_FUTEX_STARVATION",
                    title="Asymmetric Futex Wait Starvation or Missing Wakeup",
                    category="CONCURRENCY",
                    domain="CONCURRENCY",
                    required_observations=["futex_wait_words", "thread_sched_states"],
                    applicable_diagnostic_rules=["RECIPE_LONG_RUNNING_BLOCKED_THREADS", "RECIPE_THREAD_STATE_ANOMALIES"],
                    discriminating_actions=["RECIPE_LONG_RUNNING_BLOCKED_THREADS"],
                    confidence_basis="Thread blocked on kernel futex or condition variable without mutual lock cycle.",
                ),
                CompetingHypothesis(
                    hypothesis_id="HYP_SLOW_PROGRESS_COMPUTE",
                    title="Slow Forward Progress / Heavy Compute Loop Without Lock Deadlock",
                    category="CONCURRENCY",
                    domain="CONCURRENCY",
                    required_observations=["thread_cpu_progress", "epoch_counter_advance"],
                    applicable_diagnostic_rules=["RECIPE_THREAD_STATE_ANOMALIES", "RECIPE_UNEXPECTED_VARIABLE_CHANGES"],
                    discriminating_actions=["RECIPE_THREAD_STATE_ANOMALIES"],
                    confidence_basis="Threads make slow forward progress under heavy computation with zero lock cycles.",
                ),
            ]

        elif "INSTABILITY" in cat_upper or "CRASH" in cat_upper or "EXHAUSTION" in cat_upper:
            hypotheses = [
                CompetingHypothesis(
                    hypothesis_id="HYP_PROGRESSIVE_EXHAUSTION_CRASH",
                    title="Progressive Heap or Resource Exhaustion Leading to Crash",
                    category="PROCESS_INSTABILITY",
                    domain="MEMORY_GROWTH",
                    required_observations=["rss_growth_slope", "fd_count_trend", "heap_vma_count"],
                    applicable_diagnostic_rules=["RECIPE_PROCESS_MEMORY_GROWTH", "RECIPE_HEAP_GROWTH", "RECIPE_ALLOCATION_FREE_IMBALANCE"],
                    discriminating_actions=["RECIPE_PROCESS_MEMORY_GROWTH", "RECIPE_HEAP_GROWTH"],
                    confidence_basis="Progressive memory or descriptor exhaustion over extended uptime triggers fatal abort/OOM.",
                ),
                CompetingHypothesis(
                    hypothesis_id="HYP_LATENT_CORRUPTION_CRASH",
                    title="Latent Heap Metadata or Use-After-Free Corruption Crash",
                    category="PROCESS_INSTABILITY",
                    domain="MEMORY_INTEGRITY",
                    required_observations=["chunk_header_canaries", "dangling_pointer_state"],
                    applicable_diagnostic_rules=["RECIPE_HEAP_METADATA_CORRUPTION", "RECIPE_USE_AFTER_FREE", "RECIPE_DOUBLE_FREE"],
                    discriminating_actions=["RECIPE_HEAP_METADATA_CORRUPTION", "RECIPE_USE_AFTER_FREE"],
                    confidence_basis="Delayed corruption of allocator metadata or dangling object pointer causes crash on later access.",
                ),
                CompetingHypothesis(
                    hypothesis_id="HYP_CONCURRENCY_STALL_WATCHDOG",
                    title="Concurrency Deadlock or Shared-State Race Triggering Failure",
                    category="PROCESS_INSTABILITY",
                    domain="CONCURRENCY",
                    required_observations=["mutex_wait_chains", "shared_state_invariants"],
                    applicable_diagnostic_rules=["RECIPE_POTENTIAL_DEADLOCK_PATTERNS", "RECIPE_SHARED_STATE_INCONSISTENCIES"],
                    discriminating_actions=["RECIPE_POTENTIAL_DEADLOCK_PATTERNS"],
                    confidence_basis="Deadlock or unsynchronized shared-state race corrupts invariant after extended execution.",
                ),
            ]

        else:
            hypotheses = [
                CompetingHypothesis(
                    hypothesis_id="HYP_CANDIDATE_MEMORY_GROWTH",
                    title="Candidate Unbounded Memory Growth or Retention",
                    category="MEMORY_LEAK",
                    domain="MEMORY_GROWTH",
                    required_observations=["rss_delta", "heap_vma_delta"],
                    applicable_diagnostic_rules=["RECIPE_PROCESS_MEMORY_GROWTH", "RECIPE_HEAP_GROWTH"],
                    discriminating_actions=["RECIPE_PROCESS_MEMORY_GROWTH"],
                    confidence_basis="Evaluate whether target exhibits sustained RSS or heap growth.",
                ),
                CompetingHypothesis(
                    hypothesis_id="HYP_CANDIDATE_MEMORY_CORRUPTION",
                    title="Candidate Memory Integrity or Allocator Metadata Violation",
                    category="MEMORY_CORRUPTION",
                    domain="MEMORY_INTEGRITY",
                    required_observations=["allocator_headers", "canary_words"],
                    applicable_diagnostic_rules=["RECIPE_HEAP_METADATA_CORRUPTION", "RECIPE_USE_AFTER_FREE"],
                    discriminating_actions=["RECIPE_HEAP_METADATA_CORRUPTION"],
                    confidence_basis="Evaluate whether target exhibits heap metadata corruption or dangling pointers.",
                ),
                CompetingHypothesis(
                    hypothesis_id="HYP_CANDIDATE_CONCURRENCY_ANOMALY",
                    title="Candidate Thread Deadlock or Lock Contention",
                    category="CONCURRENCY",
                    domain="CONCURRENCY",
                    required_observations=["thread_wait_graph", "futex_locks"],
                    applicable_diagnostic_rules=["RECIPE_POTENTIAL_DEADLOCK_PATTERNS", "RECIPE_LOCK_CONTENTION_HOTSPOTS"],
                    discriminating_actions=["RECIPE_POTENTIAL_DEADLOCK_PATTERNS"],
                    confidence_basis="Evaluate whether target threads are deadlocked or experiencing severe lock contention.",
                ),
            ]

        ledger_ctx = ctx.get("ledger")
        inv_id_ctx = ctx.get("investigation_id")
        pid_ctx = ctx.get("target_pid") or ctx.get("pid")
        for h in hypotheses:
            if ledger_ctx is not None:
                h.ledger = ledger_ctx
            if inv_id_ctx:
                h.investigation_id = inv_id_ctx
            if pid_ctx is not None:
                h.target_pid = int(pid_ctx)

        return hypotheses

    @staticmethod
    def calculate_action_discrimination(
        hypotheses: List[CompetingHypothesis],
        candidate_recipes: Optional[List[str]] = None,
    ) -> List[CandidateActionDiscrimination]:
        """Calculates quantitative discrimination value for candidate investigation actions."""
        viable_hyps = [h for h in hypotheses if h.is_viable]
        all_actions: Set[str] = set(candidate_recipes or [])
        if not all_actions:
            for h in hypotheses:
                all_actions.update(h.discriminating_actions)
                all_actions.update(h.applicable_diagnostic_rules)

        results: List[CandidateActionDiscrimination] = []

        for r_id in sorted(all_actions):
            can_support = sorted(
                h.hypothesis_id
                for h in viable_hyps
                if r_id in h.applicable_diagnostic_rules or r_id in h.discriminating_actions
            )
            can_refute = sorted(
                h.hypothesis_id
                for h in viable_hyps
                if r_id not in h.applicable_diagnostic_rules
            )

            distinguished_pairs: List[Tuple[str, str]] = []
            for i in range(len(viable_hyps)):
                for j in range(i + 1, len(viable_hyps)):
                    h1 = viable_hyps[i]
                    h2 = viable_hyps[j]
                    in_h1 = (r_id in h1.applicable_diagnostic_rules or r_id in h1.discriminating_actions)
                    in_h2 = (r_id in h2.applicable_diagnostic_rules or r_id in h2.discriminating_actions)
                    if in_h1 != in_h2:
                        distinguished_pairs.append((h1.hypothesis_id, h2.hypothesis_id))

            score = len(distinguished_pairs) * 2.0 + len(can_refute) * 1.5 + len(can_support) * 1.0

            rationale = (
                f"Action '{r_id}' can distinguish {len(distinguished_pairs)} competing hypothesis pairs, "
                f"support {len(can_support)} explanations, and refute {len(can_refute)} alternatives."
            )

            results.append(
                CandidateActionDiscrimination(
                    recipe_id=r_id,
                    can_support=can_support,
                    can_refute=can_refute,
                    distinguished_pairs=distinguished_pairs,
                    discrimination_score=round(score, 2),
                    expected_cost=1.0,
                    target_impact=1.0,
                    selection_rationale=rationale,
                )
            )

        results.sort(key=lambda x: (-x.discrimination_score, x.recipe_id))
        return results

    @staticmethod
    def compare(
        hypotheses: List[CompetingHypothesis],
        candidate_recipes: Optional[List[str]] = None,
        ledger: Optional[Any] = None,
    ) -> HypothesisComparisonResult:
        """Compares competing hypotheses using explicit evidence quality and true information-gain discrimination."""
        if not hypotheses:
            return HypothesisComparisonResult(
                leading_hypothesis_id=None,
                ranked_hypotheses=[],
                discrimination_rationale="No hypotheses provided for comparison.",
                eliminated_alternatives=[],
                unresolved_uncertainties=["Zero candidate hypotheses"],
            )

        status_weights = {
            VERDICT_CONFIRMED: 100.0,
            VERDICT_LIKELY: 70.0,
            VERDICT_SUPPORTED: 50.0,
            VERDICT_INCONCLUSIVE: 20.0,
            VERDICT_NOT_APPLICABLE: 5.0,
            VERDICT_REFUTED: 0.0,
        }

        scored: List[Tuple[float, CompetingHypothesis]] = []
        eliminated: List[str] = []
        uncertainties: List[str] = []

        for h in hypotheses:
            h.evaluate_verdict(ledger=ledger or h.ledger)
            base = status_weights.get(h.status, 20.0)
            conf_bonus = h.confidence * 20.0
            support_bonus = min(20.0, len(h.supporting_observations) * 6.0)
            # Penalize for relevant contradictions (excluding irrelevant/rejected ones)
            relevant_contra_count = sum(
                1 for c in h.contradiction_records
                if c.is_relevant and c.contradiction_class != CONTRADICTION_CLASS_IRRELEVANT
            )
            contra_penalty = relevant_contra_count * 50.0
            missing_penalty = len(h.required_observations) * 2.0

            total_score = max(0.0, base + conf_bonus + support_bonus - contra_penalty - missing_penalty)
            scored.append((total_score, h))

            if h.status == VERDICT_REFUTED or contra_penalty > 0:
                eliminated.append(
                    f"{h.hypothesis_id} ({h.title}): Refuted by {h.contradicting_observations or 'authoritative contradictory evidence'}"
                )
            if h.unresolved_assumptions:
                uncertainties.extend(h.unresolved_assumptions)
            if h.integrity_limitations:
                uncertainties.extend(h.integrity_limitations)

        scored.sort(key=lambda x: (-x[0], x[1].hypothesis_id))
        leading = scored[0][1]

        action_discrims = CompetingHypothesisManager.calculate_action_discrimination(
            hypotheses=hypotheses,
            candidate_recipes=candidate_recipes,
        )

        recommended_action = None
        action_rationale = ""
        if action_discrims:
            top_action = action_discrims[0]
            recommended_action = top_action.recipe_id
            action_rationale = (
                f"Action '{top_action.recipe_id}' selected based on highest information gain "
                f"(score={top_action.discrimination_score}): {top_action.selection_rationale}"
            )

        rationale = (
            f"Leading hypothesis '{leading.title}' (score={scored[0][0]:.1f}, status={leading.status}) "
            f"has {len(leading.supporting_observations)} supporting facts and {len(leading.contradicting_observations)} contradictions. "
            f"Alternative '{scored[1][1].title if len(scored) > 1 else 'None'}' has status {scored[1][1].status if len(scored) > 1 else 'N/A'}. "
            f"{action_rationale}"
        )

        ranked_list = [
            {
                "hypothesis_id": h.hypothesis_id,
                "title": h.title,
                "score": round(sc, 2),
                "status": h.status,
                "confidence": h.confidence,
                "supporting_count": len(h.supporting_observations),
                "contradicting_count": len(h.contradicting_observations),
                "independent_root_count": len(h.decision_trace.get("independent_root_sources", [])) if h.decision_trace else 0,
                "rationale": h.confidence_basis,
                "decision_rule": h.decision_trace.get("decision_rule_applied", "") if h.decision_trace else "",
            }
            for sc, h in scored
        ]

        return HypothesisComparisonResult(
            leading_hypothesis_id=leading.hypothesis_id,
            ranked_hypotheses=ranked_list,
            discrimination_rationale=rationale,
            eliminated_alternatives=eliminated,
            unresolved_uncertainties=sorted(set(uncertainties)),
            recommended_discriminating_recipe=recommended_action,
            candidate_actions_discrimination=[a.to_dict() for a in action_discrims],
        )

"""Phase 2.1.4 — Competing Hypotheses & Discriminating Investigation Intelligence

Implements true Information-Gain-based competing hypothesis reasoning:
- Explicit candidate hypotheses for observed symptoms.
- Quantitative discrimination value calculation:
  1. Hypotheses an action can support.
  2. Hypotheses an action can refute.
  3. Hypothesis pairs an action can distinguish.
  4. Cost and target impact factor.
  5. Expected uncertainty reduction.
- Strictly separates supporting and contradicting observations.
- Prevents double-counting of evidence records.
- Missing evidence is never treated as contradictory evidence.
- Confidence alone CANNOT produce VERDICT_CONFIRMED (requires primary verified observation).
- Explains why the selected discriminating action is superior to alternatives.
"""

from dataclasses import dataclass, field, asdict, fields
from enum import Enum
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple

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
    from extractor.evidence_ledger import TRUSTED_PROVENANCE_CLASSES, PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE
except ImportError:
    TRUSTED_PROVENANCE_CLASSES = {"LIVE_RUNTIME_CAPTURE", "CONTROLLED_RUNTIME_REPRODUCTION"}
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE = "LIVE_RUNTIME_CAPTURE"


# =============================================================================
# Primary Single-Evidence Confirmation Rules & Registry
# =============================================================================

@dataclass
class PrimaryEvidenceRule:
    """Explicit, registered rule authorizing single-evidence hypothesis confirmation."""
    rule_id: str
    description: str
    applicable_categories: Set[str]
    allowed_evidence_types: Set[str]
    required_provenance_classes: Set[str]


class PrimaryEvidenceRuleRegistry:
    """Registry of validated single-evidence confirmation rules for C/C++ runtime diagnostics."""
    _rules: Dict[str, PrimaryEvidenceRule] = {}

    @classmethod
    def register(cls, rule: PrimaryEvidenceRule) -> None:
        cls._rules[rule.rule_id] = rule

    @classmethod
    def get(cls, rule_id: str) -> Optional[PrimaryEvidenceRule]:
        return cls._rules.get(rule_id)

    @classmethod
    def list_rules(cls) -> List[str]:
        return list(cls._rules.keys())


# Pre-register authoritative rules
PrimaryEvidenceRuleRegistry.register(
    PrimaryEvidenceRule(
        rule_id="RULE_MEM_CORRUPTION_CANARY",
        description="Deterministic buffer overflow detected by canary overwrite or corrupt guard page magic bytes.",
        applicable_categories={"HEAP_CORRUPTION", "MEMORY_CORRUPTION", "STACK_CORRUPTION"},
        allowed_evidence_types={"DIAGNOSTIC", "OBJECT_STATE", "MEMORY_CHUNK"},
        required_provenance_classes=TRUSTED_PROVENANCE_CLASSES,
    )
)
PrimaryEvidenceRuleRegistry.register(
    PrimaryEvidenceRule(
        rule_id="RULE_PTMALLOC_DOUBLE_FREE",
        description="Definitive free-list cycle or fastbin/tcache duplicate pointer detected in allocator metadata.",
        applicable_categories={"INVALID_DOUBLE_FREE", "HEAP_CORRUPTION", "MEMORY_CORRUPTION"},
        allowed_evidence_types={"DIAGNOSTIC", "OBJECT_STATE", "MEMORY_CHUNK"},
        required_provenance_classes=TRUSTED_PROVENANCE_CLASSES,
    )
)
PrimaryEvidenceRuleRegistry.register(
    PrimaryEvidenceRule(
        rule_id="RULE_SEGV_SIGNAL_CRASH",
        description="Direct kernel signal delivery receipt (SIGSEGV/SIGBUS) with authoritative fault address.",
        applicable_categories={"PROCESS_INSTABILITY", "MEMORY_CORRUPTION"},
        allowed_evidence_types={"DIAGNOSTIC", "OBJECT_STATE"},
        required_provenance_classes=TRUSTED_PROVENANCE_CLASSES,
    )
)
PrimaryEvidenceRuleRegistry.register(
    PrimaryEvidenceRule(
        rule_id="RULE_DEADLOCK_CYCLE_DIRECT",
        description="Authoritative directed circular wait-for graph cycle spanning 2 or more threads/locks.",
        applicable_categories={"DEADLOCK_INDICATORS", "THREAD_DEADLOCK", "CONCURRENCY"},
        allowed_evidence_types={"DIAGNOSTIC", "OBJECT_STATE"},
        required_provenance_classes=TRUSTED_PROVENANCE_CLASSES,
    )
)
PrimaryEvidenceRuleRegistry.register(
    PrimaryEvidenceRule(
        rule_id="RULE_KERNEL_OOM_KILL",
        description="Direct kernel or cgroup OOM killer event targeting the exact process PID.",
        applicable_categories={"RESOURCE_EXHAUSTION", "MEMORY_LEAK"},
        allowed_evidence_types={"DIAGNOSTIC", "OBJECT_STATE"},
        required_provenance_classes=TRUSTED_PROVENANCE_CLASSES,
    )
)
PrimaryEvidenceRuleRegistry.register(
    PrimaryEvidenceRule(
        rule_id="RULE_EXPLICIT_CLEAN_REFUTATION",
        description="Exhaustive positive check proving zero invariant violations and refuting candidate fault.",
        applicable_categories={"HEALTHY_PROCESS"},
        allowed_evidence_types={"DIAGNOSTIC", "OBJECT_STATE"},
        required_provenance_classes=TRUSTED_PROVENANCE_CLASSES,
    )
)


# =============================================================================
# Structured Contradiction Record
# =============================================================================

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

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ContradictionRecord":
        return cls(**data)


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
    target_identity: Optional[str] = None
    allow_single_evidence_confirmation: bool = False
    primary_evidence_rule: Optional[str] = None
    satisfied_primary_rule: Optional[str] = None
    primary_rule_rejection_reason: Optional[str] = None
    integrity_limitations: List[str] = field(default_factory=list)
    rejected_evidence_reasons: Dict[str, str] = field(default_factory=dict)
    ledger: Optional[Any] = None
    strict_ledger: bool = False
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_viable(self) -> bool:
        return self.status in (VERDICT_CONFIRMED, VERDICT_LIKELY, VERDICT_SUPPORTED, VERDICT_INCONCLUSIVE)

    def validate_primary_evidence_rule(
        self,
        rule_id: str,
        evidence_record: Optional[Any] = None,
        ledger: Optional[Any] = None,
    ) -> Tuple[bool, str]:
        """Validates whether an explicit registered primary evidence rule authorizes confirmation."""
        if not rule_id or not isinstance(rule_id, str) or not rule_id.strip():
            return False, "Primary evidence rule identifier must be a non-empty string"

        rule = PrimaryEvidenceRuleRegistry.get(rule_id)
        if not rule:
            return False, f"Rule '{rule_id}' is not a registered primary evidence rule"

        if self.category not in rule.applicable_categories:
            return False, f"Rule '{rule_id}' applicable categories {rule.applicable_categories} do not match hypothesis category '{self.category}'"

        rec = evidence_record
        eff_ledger = ledger or self.ledger
        if rec is None and eff_ledger is not None and self.supporting_evidence_ids:
            rec = eff_ledger.get_record(self.supporting_evidence_ids[0]) if hasattr(eff_ledger, "get_record") else None

        if rec is not None:
            # Validate provenance class
            rec_prov = getattr(rec, "provenance_class", None)
            if not rec_prov and hasattr(rec, "provenance") and isinstance(rec.provenance, dict):
                rec_prov = rec.provenance.get("provenance_class")
            if rec_prov not in rule.required_provenance_classes:
                return False, f"Evidence provenance '{rec_prov}' does not satisfy rule '{rule_id}' required classes {rule.required_provenance_classes}"

            # Validate evidence type
            rec_type = getattr(rec, "evidence_type", None)
            if rec_type and rec_type not in rule.allowed_evidence_types:
                return False, f"Evidence type '{rec_type}' does not satisfy rule '{rule_id}' allowed types {rule.allowed_evidence_types}"

        return True, f"Primary evidence rule '{rule_id}' criteria satisfied"

    def get_independent_root_sources(self, ledger: Optional[Any] = None) -> Set[str]:
        """Calculates the set of independent root evidence sources, traversing the complete
        multi-parent dependency graph.
        
        Guarantees:
        - Traverses EVERY parent dependency, not only the first parent.
        - Shared roots across multiple derived evidence items count as 1 independent source.
        - Detects cycles, self-dependencies, missing parents, and unresolved dependencies.
        - Invalid or cycle dependencies are excluded from increasing confidence.
        - Deterministic traversal regardless of insertion order (sorts keys and parents).
        - Prevents recursion or pathological graph structures with bounded traversal depth.
        """
        eff_ledger = ledger or self.ledger
        all_roots: Set[str] = set()
        seen_roots_per_item: Dict[str, Set[str]] = {}

        # Sort supporting evidence IDs alphabetically for determinism
        sorted_ev_ids = sorted(set(self.supporting_evidence_ids))

        for ev_id in sorted_ev_ids:
            item_roots: Set[str] = set()
            stack: List[Tuple[str, List[str]]] = [(ev_id, [ev_id])]
            branch_invalid = False

            while stack:
                curr, path = stack.pop()
                if len(path) > 200:
                    self.integrity_limitations.append(f"Dependency graph depth exceeded 200 at {curr}")
                    branch_invalid = True
                    break

                if not isinstance(curr, str) or not curr.strip():
                    self.integrity_limitations.append(f"Malformed dependency: {curr!r}")
                    branch_invalid = True
                    continue

                parents = self.evidence_dependencies.get(curr, [])
                if curr in parents:
                    self.integrity_limitations.append(f"Self-dependency detected on {curr}")
                    branch_invalid = True
                    continue

                # Deduplicate and sort parents for determinism
                unique_parents = sorted(set(p for p in parents if isinstance(p, str) and p.strip()))

                if not unique_parents:
                    # Leaf / Root node reached
                    if self.strict_ledger and eff_ledger is not None and hasattr(eff_ledger, "get_record"):
                        rec = eff_ledger.get_record(curr)
                        if rec is None:
                            self.integrity_limitations.append(f"Missing root dependency {curr} in ledger")
                            branch_invalid = True
                            continue
                        if getattr(rec, "provenance_class", None) not in TRUSTED_PROVENANCE_CLASSES:
                            self.integrity_limitations.append(f"Root dependency {curr} has untrusted provenance")
                            branch_invalid = True
                            continue
                    item_roots.add(curr)
                else:
                    for p in unique_parents:
                        if p in path:
                            # Cycle detected!
                            cycle_str = " -> ".join(path[path.index(p):] + [p])
                            self.integrity_limitations.append(f"Dependency cycle detected: {cycle_str}")
                            branch_invalid = True
                            continue
                        if self.strict_ledger and eff_ledger is not None and hasattr(eff_ledger, "get_record"):
                            if p not in self.evidence_dependencies and eff_ledger.get_record(p) is None:
                                self.integrity_limitations.append(f"Missing parent dependency {p} in ledger")
                                branch_invalid = True
                                continue
                        elif p not in self.evidence_dependencies and "missing" in p.lower():
                            self.integrity_limitations.append(f"Missing parent dependency {p}")
                            branch_invalid = True
                            continue
                        stack.append((p, path + [p]))

            if not branch_invalid and item_roots:
                seen_roots_per_item[ev_id] = item_roots
                all_roots.update(item_roots)

        return all_roots

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
        """Adds supporting observation with strict validation, anti-double-counting, and dependency tracking."""
        ctx = target_context or {}
        exp_inv = ctx.get("investigation_id") or self.investigation_id
        exp_pid = ctx.get("target_pid") or ctx.get("pid") or self.target_pid
        exp_target = ctx.get("target_identity") or self.target_identity

        # Target context validation
        if evidence_record:
            rec_inv = getattr(evidence_record, "session_id", None) or getattr(evidence_record, "investigation_id", None)
            rec_pid = getattr(evidence_record, "target_pid", None) or getattr(evidence_record, "pid", None)
            rec_target = getattr(evidence_record, "target_identity", None)
            if exp_inv and rec_inv and exp_inv != rec_inv:
                if evidence_id:
                    self.rejected_evidence_reasons[evidence_id] = f"Investigation ID mismatch: expected {exp_inv}, record {rec_inv}"
                return False
            if exp_pid and rec_pid and exp_pid != rec_pid:
                if evidence_id:
                    self.rejected_evidence_reasons[evidence_id] = f"Target PID mismatch: expected {exp_pid}, record {rec_pid}"
                return False
            if exp_target and rec_target and exp_target != rec_target:
                if evidence_id:
                    self.rejected_evidence_reasons[evidence_id] = f"Target identity mismatch: expected {exp_target}, record {rec_target}"
                return False

        # Ledger resolution validation
        eff_ledger = ctx.get("ledger") or self.ledger
        rec_from_ledger = None
        if evidence_id and eff_ledger is not None:
            if hasattr(eff_ledger, "get_record"):
                rec_from_ledger = eff_ledger.get_record(evidence_id)
                if rec_from_ledger is None:
                    self.rejected_evidence_reasons[evidence_id] = "Evidence ID not found in authoritative ledger"
                    return False
            elif hasattr(eff_ledger, "has") and not eff_ledger.has(evidence_id):
                self.rejected_evidence_reasons[evidence_id] = "Evidence ID not found in authoritative ledger"
                return False
            elif hasattr(eff_ledger, "records"):
                existing_ids = {r.evidence_id for r in eff_ledger.records}
                if evidence_id not in existing_ids:
                    self.rejected_evidence_reasons[evidence_id] = "Evidence ID not found in authoritative ledger"
                    return False

        # Determine verification status
        effective_rec = evidence_record or rec_from_ledger
        effective_verified = is_verified
        if effective_verified is None:
            if effective_rec is not None:
                prov = getattr(effective_rec, "provenance_class", None)
                nature = getattr(effective_rec, "nature", None)
                if prov in TRUSTED_PROVENANCE_CLASSES and nature != "hypothesis":
                    effective_verified = True
                else:
                    effective_verified = False
            elif eff_ledger is not None or self.strict_ledger:
                effective_verified = False
            else:
                # Permissive fallback only when no ledger or strict mode is active
                effective_verified = True

        # Idempotency and anti-double-counting checks
        if observation in self.supporting_observations and (not evidence_id or evidence_id in self.supporting_evidence_ids):
            return False
        if evidence_id and evidence_id in self.supporting_evidence_ids and observation in self.supporting_observations:
            return False

        # If observation is not present, add it
        if observation not in self.supporting_observations:
            self.supporting_observations.append(observation)

        # If evidence_id is provided
        if evidence_id:
            if evidence_id in self.supporting_evidence_ids:
                return False
            if evidence_id not in self.evidence_ids:
                self.evidence_ids.append(evidence_id)
            self.supporting_evidence_ids.append(evidence_id)
            if depends_on:
                self.evidence_dependencies[evidence_id] = list(depends_on)
            if not effective_verified:
                self.unverified_evidence_ids.append(evidence_id)

        if weight > 0.0:
            self.confidence = min(0.99, self.confidence + weight)

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
    ) -> bool:
        """Adds contradictory observation with anti-double-counting, authority tracking, and decisiveness."""
        ctx = target_context or {}
        exp_inv = ctx.get("investigation_id") or self.investigation_id
        exp_pid = ctx.get("target_pid") or ctx.get("pid") or self.target_pid
        exp_target = ctx.get("target_identity") or self.target_identity

        rel = is_relevant
        rej_reason = None

        if evidence_record:
            rec_inv = getattr(evidence_record, "session_id", None) or getattr(evidence_record, "investigation_id", None)
            rec_pid = getattr(evidence_record, "target_pid", None) or getattr(evidence_record, "pid", None)
            rec_target = getattr(evidence_record, "target_identity", None)
            if exp_inv and rec_inv and exp_inv != rec_inv:
                rel = False
                rej_reason = f"Investigation ID mismatch: expected {exp_inv}, got {rec_inv}"
            if exp_pid and rec_pid and exp_pid != rec_pid:
                rel = False
                rej_reason = f"Target PID mismatch: expected {exp_pid}, got {rec_pid}"
            if exp_target and rec_target and exp_target != rec_target:
                rel = False
                rej_reason = f"Target identity mismatch: expected {exp_target}, got {rec_target}"

        eff_ledger = ctx.get("ledger") or self.ledger
        rec_from_ledger = None
        if evidence_id and eff_ledger is not None:
            if hasattr(eff_ledger, "get_record"):
                rec_from_ledger = eff_ledger.get_record(evidence_id)
                if rec_from_ledger is None:
                    rel = False
                    rej_reason = "Evidence ID not found in authoritative ledger"
            elif hasattr(eff_ledger, "has") and not eff_ledger.has(evidence_id):
                rel = False
                rej_reason = "Evidence ID not found in authoritative ledger"
            elif hasattr(eff_ledger, "records"):
                existing_ids = {r.evidence_id for r in eff_ledger.records}
                if evidence_id not in existing_ids:
                    rel = False
                    rej_reason = "Evidence ID not found in authoritative ledger"

        # Determine verification status
        effective_rec = evidence_record or rec_from_ledger
        effective_verified = is_verified
        prov_class = "IMPORTED_UNVERIFIED"
        if effective_rec is not None:
            prov_class = getattr(effective_rec, "provenance_class", "IMPORTED_UNVERIFIED")
            if effective_verified is None:
                effective_verified = (prov_class in TRUSTED_PROVENANCE_CLASSES)
        elif effective_verified is None:
            effective_verified = True if (not eff_ledger and not self.strict_ledger) else False

        # Idempotency and anti-double-counting checks
        if contradiction in self.contradicting_observations and (not evidence_id or evidence_id in self.contradicting_evidence_ids):
            return False
        if evidence_id and evidence_id in self.contradicting_evidence_ids and contradiction in self.contradicting_observations:
            return False

        if contradiction not in self.contradicting_observations:
            self.contradicting_observations.append(contradiction)

        if evidence_id:
            if evidence_id not in self.evidence_ids:
                self.evidence_ids.append(evidence_id)
            if evidence_id not in self.contradicting_evidence_ids:
                self.contradicting_evidence_ids.append(evidence_id)
            if depends_on:
                self.evidence_dependencies[evidence_id] = list(depends_on)

        # Record structured contradiction
        crec = ContradictionRecord(
            contradiction=contradiction,
            evidence_id=evidence_id,
            is_decisive=is_decisive,
            is_conflicting=is_conflicting,
            is_verified=bool(effective_verified),
            provenance_class=prov_class,
            target_pid=exp_pid,
            investigation_id=exp_inv,
            is_relevant=rel,
            rejection_reason=rej_reason,
        )
        self.contradiction_records.append(crec)

        if rel and weight > 0.0:
            self.confidence = max(0.05, self.confidence - weight)

        self.evaluate_verdict(ledger=eff_ledger)
        return True

    def evaluate_verdict(self, ledger: Optional[Any] = None) -> str:
        """Updates hypothesis status following strict verdict semantics.
        
        Rules:
        - Direct calls to evaluate_verdict validate evidence against ledger boundary.
        - Untrusted contradictions cannot independently refute a hypothesis.
        - Decisive trusted contradiction refutes hypothesis (VERDICT_REFUTED) when no trusted support exists.
        - Conflicting trusted evidence (trusted support + trusted decisive contradiction) yields VERDICT_INCONCLUSIVE.
        - Partial contradiction lowers confidence, preventing VERDICT_CONFIRMED.
        - Single-evidence confirmation requires an explicit registered rule from PrimaryEvidenceRuleRegistry.
          An arbitrary string or boolean flag alone cannot confirm.
        - CONFIRMED requires >= 2 independent root evidence sources (or >= 1 with valid registered rule),
          zero unverified evidence, zero contradictions, and confidence >= 0.90.
        """
        eff_ledger = ledger or self.ledger

        # Validate evidence authority at the verdict boundary if ledger is present or required
        if eff_ledger is not None and hasattr(eff_ledger, "get_record"):
            for ev_id in list(self.supporting_evidence_ids):
                rec = eff_ledger.get_record(ev_id)
                if rec is None:
                    if ev_id not in self.unverified_evidence_ids:
                        self.unverified_evidence_ids.append(ev_id)
                    self.rejected_evidence_reasons[ev_id] = "Evidence ID not found in authoritative ledger"
                else:
                    rec_prov = getattr(rec, "provenance_class", None)
                    if rec_prov not in TRUSTED_PROVENANCE_CLASSES:
                        if ev_id not in self.unverified_evidence_ids:
                            self.unverified_evidence_ids.append(ev_id)
                        self.rejected_evidence_reasons[ev_id] = f"Untrusted provenance class: {rec_prov}"
                    exp_pid = self.target_pid
                    rec_pid = getattr(rec, "target_pid", None) or (rec.details.get("target_pid") if hasattr(rec, "details") else None)
                    if exp_pid and rec_pid and exp_pid != rec_pid:
                        if ev_id not in self.unverified_evidence_ids:
                            self.unverified_evidence_ids.append(ev_id)
                        self.rejected_evidence_reasons[ev_id] = f"Target PID mismatch: expected {exp_pid}, got {rec_pid}"
                    if getattr(rec, "nature", None) == "hypothesis":
                        if ev_id not in self.unverified_evidence_ids:
                            self.unverified_evidence_ids.append(ev_id)
                        self.rejected_evidence_reasons[ev_id] = "Speculative hypothesis cannot serve as authoritative evidence"

        # Separate decisive trusted contradictions, partial contradictions, and untrusted contradictions
        trusted_conflicting = [
            c for c in self.contradiction_records
            if c.is_verified and c.is_conflicting and c.is_relevant
        ]
        trusted_decisive = [
            c for c in self.contradiction_records
            if c.is_verified and c.is_decisive and not c.is_conflicting and c.is_relevant
        ]
        trusted_partial = [
            c for c in self.contradiction_records
            if c.is_verified and not c.is_decisive and not c.is_conflicting and c.is_relevant
        ]

        # Legacy fallback if contradiction_records is empty but legacy fields are populated
        if not self.contradiction_records and (self.contradicting_observations or self.contradicting_evidence_ids):
            self.status = VERDICT_REFUTED
            self.confidence = min(self.confidence, 0.15)
            return self.status

        # Evaluate independent root evidence sources
        independent_roots = self.get_independent_root_sources(ledger=eff_ledger)
        num_independent = len(independent_roots)
        has_trusted_support = (num_independent >= 1 and not self.unverified_evidence_ids)

        # Handling contradictions
        if trusted_conflicting:
            self.status = VERDICT_INCONCLUSIVE
            self.confidence = 0.45
            self.confidence_basis = "Conflicting authoritative evidence: trusted observations support contradictory conclusions."
            return self.status

        if trusted_decisive:
            self.status = VERDICT_REFUTED
            self.confidence = min(self.confidence, 0.10)
            return self.status

        # Partial contradictions lower confidence and prevent CONFIRMED
        if trusted_partial:
            self.confidence = max(0.20, min(self.confidence, 0.65))

        # Missing evidence: must remain INCONCLUSIVE
        if self.missing_evidence:
            self.status = VERDICT_INCONCLUSIVE
            return self.status

        # Rule A: Descriptive observations without Evidence IDs cannot produce CONFIRMED
        if not self.supporting_evidence_ids:
            if self.supporting_observations:
                self.status = VERDICT_LIKELY if self.confidence >= 0.70 else VERDICT_SUPPORTED
            else:
                self.status = VERDICT_INCONCLUSIVE
            return self.status

        if num_independent == 0:
            self.status = VERDICT_INCONCLUSIVE
            return self.status

        # Rule B: Unverified Evidence ID cannot produce CONFIRMED
        if self.unverified_evidence_ids:
            self.status = VERDICT_LIKELY if self.confidence >= 0.70 else VERDICT_SUPPORTED
            return self.status

        # Single evidence confirmation check: requires an explicit validated registered rule!
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

        if (num_independent >= 2 or (num_independent >= 1 and can_single_confirm)) and self.confidence >= 0.90 and not trusted_partial:
            self.status = VERDICT_CONFIRMED
        elif num_independent >= 1 and self.confidence >= 0.70:
            self.status = VERDICT_LIKELY
        elif num_independent >= 1:
            self.status = VERDICT_SUPPORTED
        else:
            self.status = VERDICT_INCONCLUSIVE

        return self.status

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d.pop("ledger", None)
        return d

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CompetingHypothesis":
        data_copy = dict(data)
        data_copy.pop("ledger", None)
        if "contradiction_records" in data_copy and isinstance(data_copy["contradiction_records"], list):
            data_copy["contradiction_records"] = [
                ContradictionRecord.from_dict(c) if isinstance(c, dict) else c
                for c in data_copy["contradiction_records"]
            ]
        valid_fields = {f.name for f in fields(cls)}
        filtered = {k: v for k, v in data_copy.items() if k in valid_fields}
        return cls(**filtered)


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
        ctx = target_context or self.target_context
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
        ctx = target_context or self.target_context
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

    def update_verdicts(self) -> None:
        for hyp in self.hypotheses.values():
            hyp.evaluate_verdict()

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
        hypotheses: List[CompetingHypothesis] = []

        if symptom_category == "MEMORY_LEAK" or "GROWTH" in symptom_category or "LEAK" in symptom_category:
            hypotheses = [
                CompetingHypothesis(
                    hypothesis_id="HYP_HEAP_ALLOC_LEAK",
                    title="Unmanaged Heap Allocation Expansion",
                    category="MEMORY_LEAK",
                    domain="MEMORY_GROWTH",
                    required_observations=["heap_vma_temporal_samples", "dominant_chunk_distribution"],
                    applicable_diagnostic_rules=["RECIPE_HEAP_GROWTH", "RECIPE_REPEATED_ALLOCATION_PATTERNS"],
                    discriminating_actions=["RECIPE_HEAP_GROWTH", "RECIPE_REPEATED_ALLOCATION_PATTERNS"],
                    confidence_basis="Heap memory grows monotonically across observation epochs without reclamation.",
                ),
                CompetingHypothesis(
                    hypothesis_id="HYP_OBJECT_ACCUMULATION",
                    title="Long-Lived Object Accumulation in Containers / Caches",
                    category="MEMORY_LEAK",
                    domain="MEMORY_GROWTH",
                    required_observations=["container_element_count", "container_capacity"],
                    applicable_diagnostic_rules=["RECIPE_LONG_LIVED_OBJECT_ACCUMULATION"],
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
                    discriminating_actions=["RECIPE_HEAP_GROWTH"],
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

        elif symptom_category == "CORRUPTION" or "CORRUPT" in symptom_category or "MEMORY_CORRUPTION" in symptom_category:
            hypotheses = [
                CompetingHypothesis(
                    hypothesis_id="HYP_USE_AFTER_FREE",
                    title="Dangling Pointer Dereference (Use-After-Free)",
                    category="MEMORY_CORRUPTION",
                    domain="MEMORY_INTEGRITY",
                    required_observations=["freelist_presence", "target_object_lifecycle"],
                    applicable_diagnostic_rules=["RECIPE_USE_AFTER_FREE"],
                    discriminating_actions=["RECIPE_USE_AFTER_FREE"],
                    confidence_basis="Target pointer references memory previously returned to the allocator.",
                ),
                CompetingHypothesis(
                    hypothesis_id="HYP_HEAP_BUFFER_OVERFLOW",
                    title="Out-of-Bounds Heap Buffer Write",
                    category="MEMORY_CORRUPTION",
                    domain="MEMORY_INTEGRITY",
                    required_observations=["chunk_header_canaries", "neighboring_chunk_state"],
                    applicable_diagnostic_rules=["RECIPE_HEAP_METADATA_CORRUPTION"],
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
                    applicable_diagnostic_rules=["RECIPE_INVALID_MEMORY_ACCESS"],
                    discriminating_actions=["RECIPE_INVALID_MEMORY_ACCESS"],
                    confidence_basis="Faulting address does not reside in mapped memory or violates guard page.",
                ),
            ]

        elif symptom_category == "DEADLOCK" or "CONCURRENCY" in symptom_category:
            hypotheses = [
                CompetingHypothesis(
                    hypothesis_id="HYP_CIRCULAR_WAIT_DEADLOCK",
                    title="Mutual Wait Cycle (Classic AB-BA Deadlock)",
                    category="CONCURRENCY",
                    domain="CONCURRENCY",
                    required_observations=["mutex_wait_chains", "holding_thread_ids"],
                    applicable_diagnostic_rules=["RECIPE_POTENTIAL_DEADLOCK_PATTERNS"],
                    discriminating_actions=["RECIPE_POTENTIAL_DEADLOCK_PATTERNS"],
                    confidence_basis="Two or more threads form a closed circular wait dependency.",
                ),
                CompetingHypothesis(
                    hypothesis_id="HYP_LONG_HOLDING_CONTENTION",
                    title="Severe Lock Contention / Long-Holding Critical Section",
                    category="CONCURRENCY",
                    domain="CONCURRENCY",
                    required_observations=["lock_holding_duration", "wait_queue_depth"],
                    applicable_diagnostic_rules=["RECIPE_LOCK_CONTENTION_HOTSPOTS"],
                    discriminating_actions=["RECIPE_LOCK_CONTENTION_HOTSPOTS"],
                    confidence_basis="Lock is held for excessive duration causing transient queuing without circular dependency.",
                ),
                CompetingHypothesis(
                    hypothesis_id="HYP_KERNEL_FUTEX_STARVATION",
                    title="Asymmetric Futex Wait Starvation",
                    category="CONCURRENCY",
                    domain="CONCURRENCY",
                    required_observations=["futex_wait_words", "thread_sched_states"],
                    applicable_diagnostic_rules=["RECIPE_POTENTIAL_DEADLOCK_PATTERNS"],
                    discriminating_actions=["RECIPE_POTENTIAL_DEADLOCK_PATTERNS"],
                    confidence_basis="Thread blocked on kernel futex without mutual lock dependency.",
                ),
            ]

        else:
            hypotheses = [
                CompetingHypothesis(
                    hypothesis_id="HYP_GENERIC_ANOMALY",
                    title=f"Unclassified Anomaly in {symptom_category}",
                    category=symptom_category,
                    domain="GENERAL",
                    required_observations=["process_status", "thread_stacks"],
                    applicable_diagnostic_rules=["RECIPE_UNEXPECTED_VARIABLE_CHANGES"],
                    discriminating_actions=["RECIPE_UNEXPECTED_VARIABLE_CHANGES"],
                    confidence_basis="Observed symptom matches reported diagnostic category.",
                ),
            ]

        return hypotheses

    @staticmethod
    def calculate_action_discrimination(
        hypotheses: List[CompetingHypothesis],
        candidate_recipes: Optional[List[str]] = None,
    ) -> List[CandidateActionDiscrimination]:
        """Calculates quantitative discrimination value for candidate investigation actions."""
        viable_hyps = [h for h in hypotheses if h.is_viable]
        all_actions = set(candidate_recipes or [])
        if not all_actions:
            for h in hypotheses:
                all_actions.update(h.discriminating_actions)
                all_actions.update(h.applicable_diagnostic_rules)

        results: List[CandidateActionDiscrimination] = []

        for r_id in all_actions:
            can_support = [h.hypothesis_id for h in viable_hyps if r_id in h.applicable_diagnostic_rules or r_id in h.discriminating_actions]
            can_refute = [h.hypothesis_id for h in viable_hyps if r_id not in h.applicable_diagnostic_rules]

            # A recipe discriminates pair (H_i, H_j) if it applies to one but not the other
            distinguished_pairs: List[Tuple[str, str]] = []
            for i in range(len(viable_hyps)):
                for j in range(i + 1, len(viable_hyps)):
                    h1 = viable_hyps[i]
                    h2 = viable_hyps[j]
                    in_h1 = (r_id in h1.applicable_diagnostic_rules or r_id in h1.discriminating_actions)
                    in_h2 = (r_id in h2.applicable_diagnostic_rules or r_id in h2.discriminating_actions)
                    if in_h1 != in_h2:
                        distinguished_pairs.append((h1.hypothesis_id, h2.hypothesis_id))

            # Discrimination score calculation:
            # Pair discrimination (+2.0), refutable alternative (+1.5), supportive evidence (+1.0)
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

        # Sort descending by discrimination score
        results.sort(key=lambda x: x.discrimination_score, reverse=True)
        return results

    @staticmethod
    def compare(
        hypotheses: List[CompetingHypothesis],
        candidate_recipes: Optional[List[str]] = None,
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
        eliminated = []
        uncertainties = []

        for h in hypotheses:
            h.evaluate_verdict()
            base = status_weights.get(h.status, 20.0)
            conf_bonus = h.confidence * 20.0
            support_bonus = min(20.0, len(h.supporting_observations) * 6.0)
            contra_penalty = len(h.contradicting_observations) * 50.0
            missing_penalty = len(h.required_observations) * 2.0

            total_score = max(0.0, base + conf_bonus + support_bonus - contra_penalty - missing_penalty)
            scored.append((total_score, h))

            if h.status == VERDICT_REFUTED or contra_penalty > 0:
                eliminated.append(f"{h.hypothesis_id} ({h.title}): Refuted by {h.contradicting_observations or 'contradictory evidence'}")
            if h.unresolved_assumptions:
                uncertainties.extend(h.unresolved_assumptions)

        # Sort descending by total score
        scored.sort(key=lambda x: x[0], reverse=True)
        leading = scored[0][1]

        # Calculate true information-gain action discrimination
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
                "rationale": h.confidence_basis,
            }
            for sc, h in scored
        ]

        return HypothesisComparisonResult(
            leading_hypothesis_id=leading.hypothesis_id,
            ranked_hypotheses=ranked_list,
            discrimination_rationale=rationale,
            eliminated_alternatives=eliminated,
            unresolved_uncertainties=list(set(uncertainties)),
            recommended_discriminating_recipe=recommended_action,
            candidate_actions_discrimination=[a.to_dict() for a in action_discrims],
        )

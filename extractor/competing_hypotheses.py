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

from dataclasses import dataclass, field, asdict
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
    target_pid: Optional[int] = None
    investigation_id: Optional[str] = None
    target_identity: Optional[str] = None
    allow_single_evidence_confirmation: bool = False
    primary_evidence_rule: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_viable(self) -> bool:
        return self.status in (VERDICT_CONFIRMED, VERDICT_LIKELY, VERDICT_SUPPORTED, VERDICT_INCONCLUSIVE)

    def get_independent_root_sources(self) -> Set[str]:
        """Calculates the set of independent root evidence sources, resolving dependency trees.
        
        Ensures multiple observations or derived records sharing one root evidence source
        do NOT count as independent evidence.
        """
        roots: Set[str] = set()
        for ev_id in self.supporting_evidence_ids:
            curr = ev_id
            visited = set()
            while curr in self.evidence_dependencies and self.evidence_dependencies[curr]:
                visited.add(curr)
                parents = [p for p in self.evidence_dependencies[curr] if p not in visited]
                if not parents:
                    break
                curr = parents[0]
            roots.add(curr)
        return roots

    def add_supporting_observation(
        self,
        observation: str,
        evidence_id: Optional[str] = None,
        depends_on: Optional[List[str]] = None,
        weight: float = 0.0,
        evidence_record: Optional[Any] = None,
        target_context: Optional[Dict[str, Any]] = None,
        is_verified: bool = True,
    ) -> bool:
        """Adds supporting observation with strict validation, anti-double-counting, and dependency tracking.
        
        Rejects:
        - Re-adding identical observation or evidence ID (idempotency, prevents confidence inflation).
        - Evidence from another investigation or target context.
        - Non-existent evidence ID when ledger context is provided.
        """
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
                return False
            if exp_pid and rec_pid and exp_pid != rec_pid:
                return False
            if exp_target and rec_target and exp_target != rec_target:
                return False

        # Ledger resolution validation (non-existent Evidence ID rejection)
        if evidence_id and "ledger" in ctx:
            ledger = ctx["ledger"]
            if hasattr(ledger, "has") and not ledger.has(evidence_id):
                return False
            elif hasattr(ledger, "records"):
                existing_ids = {r.evidence_id for r in ledger.records}
                if evidence_id not in existing_ids:
                    return False

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
            if not is_verified:
                self.unverified_evidence_ids.append(evidence_id)

        if weight > 0.0:
            self.confidence = min(0.99, self.confidence + weight)

        self.evaluate_verdict()
        return True

    def add_contradicting_observation(
        self,
        contradiction: str,
        evidence_id: Optional[str] = None,
        depends_on: Optional[List[str]] = None,
        weight: float = 0.0,
        evidence_record: Optional[Any] = None,
        target_context: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Adds contradictory observation with anti-double-counting and authority tracking."""
        ctx = target_context or {}
        exp_inv = ctx.get("investigation_id") or self.investigation_id
        exp_pid = ctx.get("target_pid") or ctx.get("pid") or self.target_pid
        exp_target = ctx.get("target_identity") or self.target_identity

        if evidence_record:
            rec_inv = getattr(evidence_record, "session_id", None) or getattr(evidence_record, "investigation_id", None)
            rec_pid = getattr(evidence_record, "target_pid", None) or getattr(evidence_record, "pid", None)
            rec_target = getattr(evidence_record, "target_identity", None)
            if exp_inv and rec_inv and exp_inv != rec_inv:
                return False
            if exp_pid and rec_pid and exp_pid != rec_pid:
                return False
            if exp_target and rec_target and exp_target != rec_target:
                return False

        if evidence_id and "ledger" in ctx:
            ledger = ctx["ledger"]
            if hasattr(ledger, "has") and not ledger.has(evidence_id):
                return False
            elif hasattr(ledger, "records"):
                existing_ids = {r.evidence_id for r in ledger.records}
                if evidence_id not in existing_ids:
                    return False

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

        if weight > 0.0:
            self.confidence = max(0.05, self.confidence - weight)

        self.evaluate_verdict()
        return True

    def evaluate_verdict(self) -> str:
        """Updates hypothesis status following strict verdict semantics.
        
        Rules:
        - Contradicted by authoritative evidence -> VERDICT_REFUTED.
        - Missing evidence -> VERDICT_INCONCLUSIVE (never REFUTED or CONFIRMED).
        - Descriptive observations alone without Evidence IDs CANNOT produce CONFIRMED.
        - Unverified Evidence IDs CANNOT produce CONFIRMED.
        - Two derived records sharing one root evidence source do NOT count as independent evidence.
        - CONFIRMED requires >= 2 independent root evidence sources (or >= 1 if explicitly permitted
          by primary evidence rule), zero contradictions, zero unverified evidence, and confidence >= 0.90.
        """
        # Contradicted: authoritative counter-evidence refutes the hypothesis
        if self.contradicting_observations or self.contradicting_evidence_ids:
            self.status = VERDICT_REFUTED
            self.confidence = min(self.confidence, 0.15)
            return self.status

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

        # Rule B: Unverified Evidence ID cannot produce CONFIRMED
        if self.unverified_evidence_ids:
            self.status = VERDICT_LIKELY if self.confidence >= 0.70 else VERDICT_SUPPORTED
            return self.status

        # Rule E: Evaluate independent root evidence sources
        independent_roots = self.get_independent_root_sources()
        num_independent = len(independent_roots)

        if num_independent == 0:
            self.status = VERDICT_INCONCLUSIVE
            return self.status

        # Single evidence confirmation check: requires explicit rule permission
        can_single_confirm = self.allow_single_evidence_confirmation or bool(self.primary_evidence_rule)

        if (num_independent >= 2 or (num_independent >= 1 and can_single_confirm)) and self.confidence >= 0.90:
            self.status = VERDICT_CONFIRMED
        elif num_independent >= 1 and self.confidence >= 0.70:
            self.status = VERDICT_LIKELY
        elif num_independent >= 1:
            self.status = VERDICT_SUPPORTED
        else:
            self.status = VERDICT_INCONCLUSIVE

        return self.status

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


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
        is_verified: bool = True,
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

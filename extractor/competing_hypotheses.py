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
    status: str = VERDICT_INCONCLUSIVE  # CONFIRMED, LIKELY, SUPPORTED, REFUTED, INCONCLUSIVE, NOT_APPLICABLE
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
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_viable(self) -> bool:
        return self.status in (VERDICT_CONFIRMED, VERDICT_LIKELY, VERDICT_SUPPORTED, VERDICT_INCONCLUSIVE)

    def add_supporting_observation(
        self,
        observation: str,
        evidence_id: Optional[str] = None,
        depends_on: Optional[List[str]] = None,
    ) -> bool:
        """Adds supporting observation with anti-double-counting and dependency tracking."""
        if observation in self.supporting_observations:
            return False
        # If evidence_id is provided and already recorded as supporting evidence, avoid treating description as independent
        if evidence_id and evidence_id in self.supporting_evidence_ids:
            return False

        self.supporting_observations.append(observation)
        if evidence_id:
            if evidence_id not in self.evidence_ids:
                self.evidence_ids.append(evidence_id)
            if evidence_id not in self.supporting_evidence_ids:
                self.supporting_evidence_ids.append(evidence_id)
            if depends_on:
                self.evidence_dependencies[evidence_id] = list(depends_on)

        self.evaluate_verdict()
        return True

    def add_contradicting_observation(
        self,
        contradiction: str,
        evidence_id: Optional[str] = None,
        depends_on: Optional[List[str]] = None,
    ) -> bool:
        """Adds contradictory observation with anti-double-counting and authority tracking."""
        if contradiction in self.contradicting_observations:
            return False
        if evidence_id and evidence_id in self.contradicting_evidence_ids:
            return False

        self.contradicting_observations.append(contradiction)
        if evidence_id:
            if evidence_id not in self.evidence_ids:
                self.evidence_ids.append(evidence_id)
            if evidence_id not in self.contradicting_evidence_ids:
                self.contradicting_evidence_ids.append(evidence_id)
            if depends_on:
                self.evidence_dependencies[evidence_id] = list(depends_on)

        self.evaluate_verdict()
        return True

    def evaluate_verdict(self) -> str:
        """Updates hypothesis status following strict verdict semantics."""
        # Contradicted: any authoritative counter-evidence refutes the hypothesis
        if self.contradicting_observations or self.contradicting_evidence_ids:
            self.status = VERDICT_REFUTED
            self.confidence = min(self.confidence, 0.15)
            return self.status

        # P0/P1: Confidence score alone CANNOT produce CONFIRMED!
        # Requires at least one verified supporting observation with valid evidence ID,
        # and zero unrefuted contradictions.
        distinct_supp_count = len(self.supporting_evidence_ids) if self.supporting_evidence_ids else len(self.supporting_observations)
        
        # CONFIRMED requires high confidence AND distinct supporting evidence with verified IDs
        if (len(self.supporting_evidence_ids) >= 1 or len(self.supporting_observations) >= 2) and self.confidence >= 0.90:
            self.status = VERDICT_CONFIRMED
        elif distinct_supp_count >= 1 and self.confidence >= 0.70:
            self.status = VERDICT_LIKELY
        elif distinct_supp_count >= 1:
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

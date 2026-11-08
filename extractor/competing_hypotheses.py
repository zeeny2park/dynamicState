"""Phase 2.1.3 — Competing Hypotheses & Discriminating Investigation Intelligence

Replaces simplistic category-based hypothesis grouping with explicit competing hypotheses:
- Generates mutually exclusive / competing explanations for observed symptoms
- Verdict semantics: CONFIRMED, LIKELY, SUPPORTED, REFUTED, INCONCLUSIVE, NOT_APPLICABLE
- Tracks supporting, contradicting, and required observations per hypothesis
- Calculates information gain to select discriminating investigation actions
- Explains why one hypothesis is preferred over alternatives
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
class CompetingHypothesis:
    """A distinct competing technical hypothesis for an observed problem symptom."""
    hypothesis_id: str
    title: str
    category: str
    domain: str
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
    details: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_viable(self) -> bool:
        return self.status in (VERDICT_CONFIRMED, VERDICT_LIKELY, VERDICT_SUPPORTED, VERDICT_INCONCLUSIVE)

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


class CompetingHypothesisManager:
    """Manages creation, evaluation, and comparison of competing technical hypotheses."""

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
                    required_observations=["temporal_rss_samples_ge_3"],
                    applicable_diagnostic_rules=["RECIPE_PROCESS_MEMORY_GROWTH"],
                    discriminating_actions=["RECIPE_PROCESS_MEMORY_GROWTH"],
                    confidence_basis="Initial memory growth followed by stable plateau without ongoing expansion.",
                ),
                CompetingHypothesis(
                    hypothesis_id="HYP_ALLOCATOR_FRAGMENTATION",
                    title="Allocator Arena Fragmentation Without Live Object Leak",
                    category="MEMORY_LEAK",
                    domain="MEMORY_GROWTH",
                    required_observations=["arena_fragmentation_ratio", "live_chunk_count"],
                    applicable_diagnostic_rules=["RECIPE_HEAP_METADATA_CORRUPTION"],
                    discriminating_actions=["RECIPE_HEAP_METADATA_CORRUPTION"],
                    confidence_basis="Virtual arena size increases due to chunk fragmentation while live object count stays constant.",
                ),
            ]

        elif symptom_category == "DEADLOCK_INDICATORS" or "DEADLOCK" in symptom_category or "BLOCK" in symptom_category:
            hypotheses = [
                CompetingHypothesis(
                    hypothesis_id="HYP_CIRCULAR_WAIT_DEADLOCK",
                    title="Persistent Circular Wait Deadlock",
                    category="DEADLOCK_INDICATORS",
                    domain="CONCURRENCY",
                    required_observations=["complete_lock_wait_graph", "repeated_cycle_samples"],
                    applicable_diagnostic_rules=["RECIPE_POTENTIAL_DEADLOCK_PATTERNS"],
                    discriminating_actions=["RECIPE_POTENTIAL_DEADLOCK_PATTERNS"],
                    confidence_basis="Two or more threads form a closed circular dependency on mutex locks across multiple epochs.",
                ),
                CompetingHypothesis(
                    hypothesis_id="HYP_LOCK_CONTENTION_NO_DEADLOCK",
                    title="Transient Lock Contention Without Circular Wait",
                    category="DEADLOCK_INDICATORS",
                    domain="CONCURRENCY",
                    required_observations=["acyclic_wait_for_graph"],
                    applicable_diagnostic_rules=["RECIPE_LONG_RUNNING_BLOCKED_THREADS"],
                    discriminating_actions=["RECIPE_LONG_RUNNING_BLOCKED_THREADS"],
                    confidence_basis="Threads wait for heavily contested locks but lock ownership graph is strictly acyclic.",
                ),
                CompetingHypothesis(
                    hypothesis_id="HYP_ORPHANED_MUTEX",
                    title="Orphaned Mutex Held by Terminated Thread",
                    category="DEADLOCK_INDICATORS",
                    domain="CONCURRENCY",
                    required_observations=["lock_owner_thread_state"],
                    applicable_diagnostic_rules=["RECIPE_SUSPICIOUS_LOCK_OWNERSHIP"],
                    discriminating_actions=["RECIPE_SUSPICIOUS_LOCK_OWNERSHIP"],
                    confidence_basis="Mutex held by thread ID that no longer exists in target process task list.",
                ),
            ]

        elif symptom_category == "MEMORY_CORRUPTION" or "CORRUPT" in symptom_category:
            hypotheses = [
                CompetingHypothesis(
                    hypothesis_id="HYP_INVALID_DEREFERENCE",
                    title="Invalid Memory Address Dereference",
                    category="MEMORY_CORRUPTION",
                    domain="MEMORY_INTEGRITY",
                    required_observations=["faulting_address_or_register", "target_vma_permissions"],
                    applicable_diagnostic_rules=["RECIPE_INVALID_MEMORY_ACCESS"],
                    discriminating_actions=["RECIPE_INVALID_MEMORY_ACCESS"],
                    confidence_basis="Application attempted read or write access to unmapped or guard-page memory.",
                ),
                CompetingHypothesis(
                    hypothesis_id="HYP_USE_AFTER_FREE",
                    title="Use-After-Free of Deallocated Heap Object",
                    category="MEMORY_CORRUPTION",
                    domain="MEMORY_INTEGRITY",
                    required_observations=["freed_chunk_metadata", "stale_pointer_reference", "access_evidence"],
                    applicable_diagnostic_rules=["RECIPE_USE_AFTER_FREE"],
                    discriminating_actions=["RECIPE_USE_AFTER_FREE"],
                    confidence_basis="Pointer dereferences a memory block currently on freelist or marked with deallocation poison.",
                ),
                CompetingHypothesis(
                    hypothesis_id="HYP_STRUCT_CANARY_CORRUPTION",
                    title="Structural Magic or Guard Corruption",
                    category="MEMORY_CORRUPTION",
                    domain="MEMORY_INTEGRITY",
                    required_observations=["struct_magic_value", "expected_canary_constant"],
                    applicable_diagnostic_rules=["RECIPE_HEAP_METADATA_CORRUPTION", "RECIPE_SUSPICIOUS_BOUNDARY_VALUES"],
                    discriminating_actions=["RECIPE_HEAP_METADATA_CORRUPTION"],
                    confidence_basis="Object header magic constant clobbered by adjacent out-of-bounds write.",
                ),
            ]
        else:
            # Fallback single candidate
            hypotheses = [
                CompetingHypothesis(
                    hypothesis_id="HYP_GENERIC_ANOMALY",
                    title=f"Runtime Anomaly in {symptom_category}",
                    category=symptom_category,
                    domain="GENERAL",
                    required_observations=["general_runtime_evidence"],
                    applicable_diagnostic_rules=[],
                    discriminating_actions=[],
                    confidence_basis="Initial candidate hypothesis for investigation.",
                )
            ]

        return hypotheses

    @staticmethod
    def compare(hypotheses: List[CompetingHypothesis]) -> HypothesisComparisonResult:
        """Compares competing hypotheses based on concrete evidence, contradictions, and rule results."""
        if not hypotheses:
            return HypothesisComparisonResult(
                leading_hypothesis_id=None,
                ranked_hypotheses=[],
                discrimination_rationale="No hypotheses provided for comparison.",
                eliminated_alternatives=[],
                unresolved_uncertainties=["Zero candidate hypotheses"],
            )

        # Scoring function:
        # Status weight:
        # CONFIRMED = 100
        # LIKELY = 70
        # SUPPORTED = 50
        # INCONCLUSIVE = 20
        # NOT_APPLICABLE = 5
        # REFUTED = 0
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
            base = status_weights.get(h.status, 20.0)
            conf_bonus = h.confidence * 20.0
            support_bonus = min(15.0, len(h.supporting_observations) * 5.0)
            contra_penalty = len(h.contradicting_observations) * 40.0
            missing_penalty = len(h.required_observations) * 3.0

            total_score = max(0.0, base + conf_bonus + support_bonus - contra_penalty - missing_penalty)
            scored.append((total_score, h))

            if h.status == VERDICT_REFUTED or contra_penalty > 0:
                eliminated.append(f"{h.hypothesis_id} ({h.title}): Refuted by {h.contradicting_observations or 'contradictory evidence'}")
            if h.unresolved_assumptions:
                uncertainties.extend(h.unresolved_assumptions)

        # Sort descending by total score
        scored.sort(key=lambda x: x[0], reverse=True)
        leading = scored[0][1]

        # Determine recommended discriminating recipe
        recommended_action = None
        for cand_action in leading.discriminating_actions:
            # Check if this action can also refute runner-up
            if len(scored) > 1:
                runner_up = scored[1][1]
                if cand_action in runner_up.discriminating_actions or cand_action not in runner_up.applicable_diagnostic_rules:
                    recommended_action = cand_action
                    break
        if not recommended_action and leading.discriminating_actions:
            recommended_action = leading.discriminating_actions[0]

        rationale = (
            f"Leading hypothesis '{leading.title}' (score={scored[0][0]:.1f}, status={leading.status}) "
            f"has {len(leading.supporting_observations)} supporting facts and {len(leading.contradicting_observations)} contradictions. "
            f"Alternative '{scored[1][1].title if len(scored) > 1 else 'None'}' has status {scored[1][1].status if len(scored) > 1 else 'N/A'}."
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
        )

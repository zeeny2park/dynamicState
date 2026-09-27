"""Deterministic candidate ranker for Phase 5 Agent Runtime Protocol.

Evaluates structural and execution signals to prioritize mutation candidates
for technical exploration without any non-deterministic LLM dependency.
"""

from typing import Any, Dict, List, Optional, Set

from .agent_models import AgentMutationCandidate, AgentStateContext
from .explorer import MutationCandidate


class CandidateRanker:
    """Ranks mutation candidates deterministically based on technical exploration signals."""

    # Branch-sensitive naming keywords
    BRANCH_KEYWORDS = {
        "retry", "retries", "state", "status", "flag", "flagged", "mode",
        "cond", "condition", "type", "kind", "valid", "enabled", "priority",
        "error", "code", "active", "is_"
    }

    # Invariant and container paired keywords
    INVARIANT_KEYWORDS = {
        "length", "capacity", "size", "count", "limit", "max", "min", "bound"
    }

    def __init__(self):
        pass

    def rank(self, candidates: List[Any], context: Optional[AgentStateContext] = None,
             recent_changed_fields: Optional[Set[str]] = None) -> List[AgentMutationCandidate]:
        """Rank candidates deterministically and return sorted AgentMutationCandidate list."""
        recent_fields = recent_changed_fields or set()
        reachable_objects: Set[str] = set()
        if context and context.objects:
            reachable_objects = {obj.get("object_id") for obj in context.objects if isinstance(obj, dict)}

        ranked_list: List[AgentMutationCandidate] = []

        for cand in candidates:
            # Normalize candidate data whether dict or MutationCandidate
            if isinstance(cand, dict):
                c_id = cand["candidate_id"]
                snap_id = cand["snapshot_id"]
                obj_id = cand["object_id"]
                f_name = cand.get("field") or cand.get("field_path", "")
                f_type = cand["type"]
                curr_val = cand["current_value"]
                prop_val = cand["proposed_value"]
                reason = cand.get("reason", "unknown")
            else:
                c_id = cand.candidate_id
                snap_id = cand.snapshot_id
                obj_id = cand.object_id
                f_name = cand.field_path
                f_type = cand.type
                curr_val = cand.current_value
                prop_val = cand.proposed_value
                reason = cand.reason

            score = 1.0  # Base priority score
            ranking_reasons: List[str] = []

            # 1. Enum symbolic transition (+4.0)
            if "enum" in f_type.lower() or reason in ("ENUM_MEMBER", "ENUM_TRANSITION"):
                score += 4.0
                ranking_reasons.append("ENUM_TRANSITION")

            # 2. Numeric boundary (+3.0)
            if any(b_tag in reason for b_tag in ("BOUNDARY", "ZERO", "MIN", "MAX", "OVERFLOW", "UNDERFLOW")):
                score += 3.0
                ranking_reasons.append("NUMERIC_BOUNDARY")

            # 3. Branch-sensitive field naming (+2.5)
            f_lower = f_name.lower()
            if any(k in f_lower for k in self.BRANCH_KEYWORDS):
                score += 2.5
                ranking_reasons.append("BRANCH_SENSITIVE")

            # 4. Recently changed field in recent transitions (+2.0)
            full_path = f"{obj_id}.{f_name}"
            if f_name in recent_fields or full_path in recent_fields:
                score += 2.0
                ranking_reasons.append("RECENTLY_CHANGED")

            # 5. Invariant-related paired field (+1.5)
            if any(k in f_lower for k in self.INVARIANT_KEYWORDS):
                score += 1.5
                ranking_reasons.append("INVARIANT_RELATED")

            # 6. Execution-reachable object (+1.0)
            if obj_id in reachable_objects:
                score += 1.0
                ranking_reasons.append("EXECUTION_REACHABLE")

            # 7. Pointer transition (+2.0)
            if "*" in f_type or reason == "POINTER_NULL":
                score += 2.0
                ranking_reasons.append("POINTER_TRANSITION")

            agent_cand = AgentMutationCandidate(
                candidate_id=c_id,
                snapshot_id=snap_id,
                object_id=obj_id,
                field=f_name,
                type=f_type,
                current_value=curr_val,
                proposed_value=prop_val,
                reason=reason,
                priority_score=round(score, 2),
                ranking_reasons=sorted(ranking_reasons)
            )
            ranked_list.append(agent_cand)

        # Sort descending by priority_score, then candidate_id for stability
        ranked_list.sort(key=lambda c: (-c.priority_score, c.candidate_id))
        return ranked_list

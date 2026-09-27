"""Deterministic invariant candidate detector for Phase 5 Agent Runtime Protocol.

Extracts potential structural and semantic invariant hypotheses from runtime observations.
Important: These are strictly unconfirmed hypotheses ('invariant_candidate') for future agent reasoning.
"""

from typing import Any, Dict, List, Optional

from .agent_models import AgentInvariantCandidate


class InvariantDetector:
    """Detects structural and range invariant candidates deterministically from runtime state."""

    LENGTH_ALIASES = {"length", "len", "size", "count"}
    CAPACITY_ALIASES = {"capacity", "cap", "max_size", "limit"}

    def __init__(self):
        pass

    def detect(self, snapshot_data: Any) -> List[AgentInvariantCandidate]:
        """Examine a snapshot and propose deterministic invariant candidates."""
        data = snapshot_data.to_dict() if hasattr(snapshot_data, "to_dict") else dict(snapshot_data)
        persistent = data.get("persistent") or {}
        objects = persistent.get("objects") or data.get("objects") or []

        candidates: List[AgentInvariantCandidate] = []
        seen_expressions = set()

        for obj in objects:
            if not isinstance(obj, dict):
                continue
            obj_type = obj.get("type", "Unknown")
            obj_id = obj.get("object_id", "")
            fields = obj.get("fields") or []

            field_map: Dict[str, Any] = {}
            for f in fields:
                if isinstance(f, dict):
                    field_map[f.get("name", "")] = f

            # 1. Paired length <= capacity bounds
            len_fields = [k for k in field_map if k.lower() in self.LENGTH_ALIASES]
            cap_fields = [k for k in field_map if k.lower() in self.CAPACITY_ALIASES]

            for lf in len_fields:
                for cf in cap_fields:
                    val_len = field_map[lf].get("value")
                    val_cap = field_map[cf].get("value")
                    if isinstance(val_len, (int, float)) and isinstance(val_cap, (int, float)):
                        expr = f"{obj_type}.{lf} <= {obj_type}.{cf}"
                        if expr not in seen_expressions:
                            seen_expressions.add(expr)
                            evidence = [f"{obj_id}: {lf}={val_len} <= {cf}={val_cap}"]
                            candidates.append(AgentInvariantCandidate(
                                expression=expr,
                                category="bounds",
                                evidence=evidence,
                                status="unconfirmed_candidate"
                            ))

            # 2. Non-negative range candidate for numeric counters / retries / indices
            for f_name, f_data in field_map.items():
                f_val = f_data.get("value")
                f_type = f_data.get("type", "").lower()
                if isinstance(f_val, int) and f_val >= 0:
                    if any(k in f_name.lower() for k in ("retry", "count", "index", "length", "size", "packets")):
                        expr = f"{obj_type}.{f_name} >= 0"
                        if expr not in seen_expressions:
                            seen_expressions.add(expr)
                            candidates.append(AgentInvariantCandidate(
                                expression=expr,
                                category="range",
                                evidence=[f"{obj_id}: {f_name}={f_val} (observed >= 0)"],
                                status="unconfirmed_candidate"
                            ))

            # 3. Pointer non-null validity
            for f_name, f_data in field_map.items():
                f_ref = f_data.get("object_ref")
                f_type = f_data.get("type", "")
                if "*" in f_type and f_ref is not None:
                    expr = f"{obj_type}.{f_name} != nullptr"
                    if expr not in seen_expressions:
                        seen_expressions.add(expr)
                        candidates.append(AgentInvariantCandidate(
                            expression=expr,
                            category="validity",
                            evidence=[f"{obj_id}: {f_name} points to valid {f_ref}"],
                            status="unconfirmed_candidate"
                        ))

        # Sort candidates deterministically by expression
        candidates.sort(key=lambda c: c.expression)
        return candidates

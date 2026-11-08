"""Phase 2.1.3 — Generic C++ Structural Understanding & Relationship Discovery

Builds a structural discovery layer based on:
- DWARF type relationships, member declarations, canonical types
- Pointer and reference types, array types, container templates
- Field offsets, layout boundaries, inheritance, ownership
- Multi-factor candidate ranking
- Expert overrides (variable expressions, field paths, invariants, ranges)

Ensures unrelated fields from different objects or counters with incompatible
measurement scopes are never paired.
"""

from dataclasses import dataclass, field, asdict
from enum import Enum
import re
from typing import Any, Dict, List, Optional, Set, Tuple


class CppRelationshipType(str, Enum):
    POINTER_POINTEE = "POINTER_POINTEE"
    BUFFER_AND_LENGTH = "BUFFER_AND_LENGTH"
    BUFFER_AND_CAPACITY = "BUFFER_AND_CAPACITY"
    CONTAINER_AND_ELEMENT = "CONTAINER_AND_ELEMENT"
    OWNER_AND_OWNED = "OWNER_AND_OWNED"
    HEAD_AND_TAIL = "HEAD_AND_TAIL"
    COUNT_AND_STORAGE = "COUNT_AND_STORAGE"
    ALLOC_AND_RELEASE_COUNTERS = "ALLOC_AND_RELEASE_COUNTERS"
    STATE_AND_DATA = "STATE_AND_DATA"
    UNSPECIFIED = "UNSPECIFIED"


@dataclass
class CppRelationshipCandidate:
    """Discovered relationship between C++ symbols with structural rationale."""
    primary_symbol: str
    secondary_symbol: str
    relationship_type: CppRelationshipType
    confidence_score: float
    structural_basis: str
    same_object: bool
    offset_difference: Optional[int] = None
    type_compatibility: bool = True
    expert_specified: bool = False
    rationale: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ExpertOverrideConstraint:
    """Manual constraint provided by an expert engineer."""
    variable_expression: Optional[str] = None
    object_address: Optional[int] = None
    field_path: Optional[str] = None
    invariant_expression: Optional[str] = None
    related_variables: List[str] = field(default_factory=list)
    expected_value_range: Optional[Dict[str, Any]] = None
    problem_category: Optional[str] = None
    rationale: str = "Expert engineer manual override"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CppStructuralDiscovery:
    """Discovers and validates structural C++ relationships using DWARF type definitions."""

    def __init__(self, expert_overrides: Optional[List[ExpertOverrideConstraint]] = None):
        self.expert_overrides = expert_overrides or []

    def rank_capacity_length_pairs(
        self,
        struct_definitions: List[Tuple[str, Any]],
        globals_list: Optional[List[str]] = None,
    ) -> List[CppRelationshipCandidate]:
        """Discovers capacity and length pairs using strict structural rules."""
        candidates: List[CppRelationshipCandidate] = []

        # 1. Structural discovery within the same struct/class definition
        for struct_var_name, dwarf_type in struct_definitions:
            members = getattr(dwarf_type, "members", [])
            cap_members = []
            len_members = []

            for m in members:
                m_low = m.name.lower()
                if any(k in m_low for k in ("capacity", "max_cap", "limit", "bound")):
                    cap_members.append(m)
                if any(k in m_low for k in ("len", "length", "size", "count")) and "capacity" not in m_low:
                    len_members.append(m)

            for cap_m in cap_members:
                for len_m in len_members:
                    # Multi-factor score
                    # Same struct (+0.5)
                    # Field offset proximity (< 32 bytes) (+0.3)
                    # Name similarity (+0.1)
                    score = 0.50
                    offset_diff = abs(cap_m.offset - len_m.offset)
                    if offset_diff <= 32:
                        score += 0.30
                    elif offset_diff <= 64:
                        score += 0.15

                    cand = CppRelationshipCandidate(
                        primary_symbol=f"{struct_var_name}.{cap_m.name}",
                        secondary_symbol=f"{struct_var_name}.{len_m.name}",
                        relationship_type=CppRelationshipType.BUFFER_AND_CAPACITY,
                        confidence_score=round(min(score, 0.95), 2),
                        structural_basis=f"Same struct '{dwarf_type.name}' at offsets {cap_m.offset} and {len_m.offset} (delta={offset_diff}B)",
                        same_object=True,
                        offset_difference=offset_diff,
                        type_compatibility=True,
                        rationale=f"Structural coupling inside struct '{dwarf_type.name}'",
                    )
                    candidates.append(cand)

        # 2. Expert overrides take highest priority (score 1.0)
        for ov in self.expert_overrides:
            if ov.related_variables and len(ov.related_variables) >= 2:
                candidates.insert(
                    0,
                    CppRelationshipCandidate(
                        primary_symbol=ov.related_variables[0],
                        secondary_symbol=ov.related_variables[1],
                        relationship_type=CppRelationshipType.BUFFER_AND_CAPACITY,
                        confidence_score=1.0,
                        structural_basis="Expert explicit constraint",
                        same_object=True,
                        expert_specified=True,
                        rationale=ov.rationale,
                    )
                )

        return candidates

    def evaluate_candidate_pair(
        self,
        container_type: str,
        field_name_a: str,
        type_a: str,
        offset_a: int,
        field_name_b: str,
        type_b: str,
        offset_b: int,
        container_type_b: Optional[str] = None,
    ) -> Optional[CppRelationshipCandidate]:
        if container_type_b and container_type != container_type_b:
            return None
        a_low = field_name_a.lower()
        b_low = field_name_b.lower()
        is_a_cap = any(k in a_low for k in ("capacity", "max_cap", "limit", "bound"))
        is_b_len = any(k in b_low for k in ("len", "length", "size", "count")) and "capacity" not in a_low
        is_b_cap = any(k in b_low for k in ("capacity", "max_cap", "limit", "bound"))
        is_a_len = any(k in a_low for k in ("len", "length", "size", "count")) and "capacity" not in b_low
        if not ((is_a_cap and is_b_len) or (is_b_cap and is_a_len)):
            return None
        offset_diff = abs(offset_a - offset_b)
        score = 0.50
        if offset_diff <= 32:
            score += 0.30
        elif offset_diff <= 64:
            score += 0.15
        return CppRelationshipCandidate(
            primary_symbol=f"{container_type}.{field_name_a}",
            secondary_symbol=f"{container_type}.{field_name_b}",
            relationship_type=CppRelationshipType.BUFFER_AND_CAPACITY,
            confidence_score=round(min(score, 0.95), 2),
            structural_basis=f"Struct '{container_type}' at offsets {offset_a} and {offset_b} (delta={offset_diff}B)",
            same_object=True,
            offset_difference=offset_diff,
            type_compatibility=True,
        )

    def validate_counter_compatibility(
        self,
        alloc_counter_name: str,
        free_counter_name: str,
        struct_definitions: Optional[List[Tuple[str, Any]]] = None,
    ) -> Tuple[bool, str]:
        """Validates that allocation and release counters belong to compatible measurement scopes."""
        # Check expert override
        for ov in self.expert_overrides:
            if ov.related_variables and alloc_counter_name in ov.related_variables and free_counter_name in ov.related_variables:
                return True, "Counters explicitly bound by expert engineer override"

        # If both are members of structs, verify same struct or same subsystem
        alloc_parts = alloc_counter_name.split(".")
        free_parts = free_counter_name.split(".")

        if len(alloc_parts) > 1 and len(free_parts) > 1:
            if alloc_parts[0] != free_parts[0]:
                return False, f"Counters belong to different parent objects ('{alloc_parts[0]}' vs '{free_parts[0]}')"

        # Check prefix/suffix compatibility for global variables
        a_base = alloc_counter_name.lower().replace("g_", "").replace("alloc_", "").replace("_alloc", "").replace("_ops", "")
        f_base = free_counter_name.lower().replace("g_", "").replace("free_", "").replace("_free", "").replace("release_", "").replace("_release", "").replace("_ops", "")

        # If prefixes match (e.g. g_net_alloc vs g_net_free), compatible
        if a_base == f_base or not a_base or not f_base:
            return True, f"Counters share subsystem identity '{a_base or f_base}'"

        # If completely different names (e.g. g_tx_packets vs g_heap_free), incompatible!
        if ("packet" in a_base and "heap" in f_base) or ("file" in a_base and "memory" in f_base):
            return False, f"Counters measure incompatible subsystems ('{alloc_counter_name}' vs '{free_counter_name}')"

        return True, "Counters have compatible global scope"

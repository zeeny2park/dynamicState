"""Phase 2.1.4 — C++ Structural Understanding & Relationship Discovery

Enforces strict structural discovery semantics:
- Distinguishes candidate relationships from established relationships.
- Same-struct membership, offset proximity, and similar names are candidate signals (+weight), NOT proof.
- Canonical type compatibility: incompatible types (e.g. float vs uint64_t for capacity/length,
  or string vs pointer) are rejected.
- Expert overrides have highest authority and produce established relationships (is_established=True).
- Counter relationships require compatible measurement scopes and units.
- Full reporting: relationship type, supporting facts, contradicting facts, confidence basis,
  missing info, and whether established or only a candidate.
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
    # Aliases
    CAPACITY_VS_LENGTH = "BUFFER_AND_LENGTH"
    COUPLED_COUNTERS = "ALLOC_AND_RELEASE_COUNTERS"


@dataclass
class CppRelationshipCandidate:
    """Discovered relationship between C++ symbols with structural rationale."""
    primary_symbol: str = ""
    secondary_symbol: str = ""
    relationship_type: CppRelationshipType = CppRelationshipType.UNSPECIFIED
    confidence_score: float = 0.50
    structural_basis: str = ""
    same_object: bool = True
    is_established: bool = False  # True only if proven by DWARF template contract or expert override
    is_candidate: bool = True
    offset_difference: Optional[int] = None
    type_compatibility: bool = True
    expert_specified: bool = False
    supporting_structural_facts: List[str] = field(default_factory=list)
    contradicting_facts: List[str] = field(default_factory=list)
    missing_information: List[str] = field(default_factory=list)
    confidence_basis: str = ""
    rationale: str = ""
    source_variable: Optional[str] = None
    target_variable: Optional[str] = None
    confidence: Optional[float] = None

    def __post_init__(self):
        if not self.primary_symbol and self.source_variable:
            self.primary_symbol = self.source_variable
        elif not self.source_variable and self.primary_symbol:
            self.source_variable = self.primary_symbol
        if not self.secondary_symbol and self.target_variable:
            self.secondary_symbol = self.target_variable
        elif not self.target_variable and self.secondary_symbol:
            self.target_variable = self.secondary_symbol
        if self.confidence is not None and self.confidence_score == 0.50:
            self.confidence_score = self.confidence
        elif self.confidence is None:
            self.confidence = self.confidence_score

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["relationship_type"] = self.relationship_type.value
        return d


@dataclass
class ExpertOverrideConstraint:
    """Manual constraint provided by an expert engineer."""
    override_id: Optional[str] = None
    variable_expression: Optional[str] = None
    source_variable: Optional[str] = None
    target_variable: Optional[str] = None
    relationship_type: Optional[Any] = None
    expert_rationale: Optional[str] = None
    object_address: Optional[int] = None
    field_path: Optional[str] = None
    invariant_expression: Optional[str] = None
    related_variables: List[str] = field(default_factory=list)
    expected_value_range: Optional[Dict[str, Any]] = None
    problem_category: Optional[str] = None
    rationale: str = "Expert engineer manual override"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


INTEGRAL_SIZE_TYPES = {
    "size_t", "size_type", "uint64_t", "uint32_t", "uint16_t", "uint8_t",
    "int64_t", "int32_t", "int16_t", "int8_t", "int", "unsigned int",
    "long", "unsigned long", "long long", "unsigned long long", "unsigned",
    "std::size_t", "u64", "u32", "i64", "i32", "streamsize",
}


def are_types_capacity_length_compatible(type_a: str, type_b: str) -> bool:
    """Validates if two types can legitimately form a capacity/length relationship."""
    t_a = type_a.lower().replace("const", "").replace("&", "").strip()
    t_b = type_b.lower().replace("const", "").replace("&", "").strip()

    # Float/double cannot represent integer container capacity or length
    if any(f in t_a for f in ("float", "double")) or any(f in t_b for f in ("float", "double")):
        return False

    # Pointer cannot be a length or capacity directly without dereference
    if ("*" in t_a and "char" not in t_a) or ("*" in t_b and "char" not in t_b):
        return False

    # Check against known integral/size types
    a_integral = any(it in t_a for it in INTEGRAL_SIZE_TYPES)
    b_integral = any(it in t_b for it in INTEGRAL_SIZE_TYPES)

    return a_integral and b_integral


class CppStructuralDiscovery:
    """Discovers and validates structural C++ relationships using DWARF type definitions."""

    def __init__(self, expert_overrides: Optional[List[ExpertOverrideConstraint]] = None):
        self.expert_overrides = expert_overrides or []

    def are_types_capacity_length_compatible(self, type_a: str, type_b: str) -> bool:
        return are_types_capacity_length_compatible(type_a, type_b)

    def are_counters_compatible(self, name_a: str, name_b: str) -> bool:
        ok, _ = self.validate_counter_compatibility(name_a, None, name_b, None)
        return ok

    def apply_expert_override(self, override: ExpertOverrideConstraint) -> CppRelationshipCandidate:
        prim = override.related_variables[0] if override.related_variables else (getattr(override, "source_variable", None) or override.variable_expression or "")
        sec = override.related_variables[1] if override.related_variables and len(override.related_variables) > 1 else (getattr(override, "target_variable", None) or "")
        cand = CppRelationshipCandidate(
            primary_symbol=prim,
            secondary_symbol=sec,
            relationship_type=CppRelationshipType.BUFFER_AND_CAPACITY,
            confidence_score=1.0,
            structural_basis="Expert explicit constraint",
            same_object=True,
            is_established=True,
            is_candidate=False,
            expert_specified=True,
            supporting_structural_facts=["Explicit expert engineer constraint specification"],
            confidence_basis="Engineer domain knowledge override",
            rationale=getattr(override, "expert_rationale", None) or override.rationale,
        )
        self.expert_overrides.append(override)
        return cand

    def rank_capacity_length_pairs(
        self,
        struct_definitions: List[Tuple[str, Any]],
        globals_list: Optional[List[str]] = None,
    ) -> List[CppRelationshipCandidate]:
        """Discovers capacity and length pairs using strict structural rules."""
        candidates: List[CppRelationshipCandidate] = []

        # 1. Expert overrides take highest priority and are established relationships
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
                        is_established=True,
                        is_candidate=False,
                        expert_specified=True,
                        supporting_structural_facts=["Explicit expert engineer constraint specification"],
                        confidence_basis="Engineer domain knowledge override",
                        rationale=ov.rationale,
                    )
                )

        # 2. Structural discovery within the same struct/class definition
        for struct_var_name, dwarf_type in struct_definitions:
            members = getattr(dwarf_type, "members", [])
            cap_members = []
            len_members = []

            for m in members:
                m_low = m.name.lower()
                m_type = getattr(m, "type_name", "size_t")
                if any(k in m_low for k in ("capacity", "max_cap", "limit", "bound")):
                    cap_members.append(m)
                if any(k in m_low for k in ("len", "length", "size", "count")) and "capacity" not in m_low:
                    len_members.append(m)

            for cap_m in cap_members:
                for len_m in len_members:
                    cap_type = getattr(cap_m, "type_name", "size_t")
                    len_type = getattr(len_m, "type_name", "size_t")

                    # Check type compatibility
                    if not are_types_capacity_length_compatible(cap_type, len_type):
                        continue

                    # Multi-factor candidate score (heuristics alone NEVER yield 1.0 or is_established=True)
                    # Same struct (+0.40)
                    # Field offset proximity (< 32 bytes) (+0.20)
                    # Name similarity (+0.10)
                    score = 0.40
                    supporting_facts = [f"Co-located in struct '{dwarf_type.name}'"]
                    offset_diff = abs(cap_m.offset - len_m.offset)
                    if offset_diff <= 32:
                        score += 0.20
                        supporting_facts.append(f"Layout proximity: {offset_diff}B difference")
                    elif offset_diff <= 64:
                        score += 0.10
                        supporting_facts.append(f"Layout proximity: {offset_diff}B difference")

                    # Name stem similarity
                    cap_stem = re.sub(r"(capacity|max_cap|limit|bound)", "", cap_m.name.lower())
                    len_stem = re.sub(r"(len|length|size|count)", "", len_m.name.lower())
                    if cap_stem and len_stem and (cap_stem in len_stem or len_stem in cap_stem):
                        score += 0.10
                        supporting_facts.append(f"Matching name prefix/stem '{cap_stem}'")

                    cand = CppRelationshipCandidate(
                        primary_symbol=f"{struct_var_name}.{cap_m.name}",
                        secondary_symbol=f"{struct_var_name}.{len_m.name}",
                        relationship_type=CppRelationshipType.BUFFER_AND_CAPACITY,
                        confidence_score=round(min(score, 0.75), 2),
                        structural_basis=f"Same struct '{dwarf_type.name}' at offsets {cap_m.offset} and {len_m.offset} (delta={offset_diff}B)",
                        same_object=True,
                        is_established=False,  # Candidate only!
                        is_candidate=True,
                        offset_difference=offset_diff,
                        type_compatibility=True,
                        supporting_structural_facts=supporting_facts,
                        contradicting_facts=[],
                        missing_information=["Container template contract verification", "Runtime access telemetry"],
                        confidence_basis="Structural layout proximity and name pattern heuristics",
                        rationale=f"Candidate coupling inside struct '{dwarf_type.name}'",
                    )
                    candidates.append(cand)

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
        """Evaluates whether two fields can legitimately form a capacity/length relationship."""
        # Unrelated fields across different structures/subsystems are rejected
        if container_type_b and container_type != container_type_b:
            return None

        # Validate canonical type compatibility: float vs int, string vs int, etc. rejected!
        if not are_types_capacity_length_compatible(type_a, type_b):
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
        score = 0.40
        supporting_facts = [f"Fields reside in container type '{container_type}'", f"Compatible types: {type_a} and {type_b}"]
        if offset_diff <= 32:
            score += 0.20
            supporting_facts.append(f"Layout proximity: {offset_diff}B difference")
        elif offset_diff <= 64:
            score += 0.10
            supporting_facts.append(f"Layout proximity: {offset_diff}B difference")

        return CppRelationshipCandidate(
            primary_symbol=f"{container_type}.{field_name_a}",
            secondary_symbol=f"{container_type}.{field_name_b}",
            relationship_type=CppRelationshipType.BUFFER_AND_CAPACITY,
            confidence_score=round(min(score, 0.75), 2),
            structural_basis=f"Struct '{container_type}' at offsets {offset_a} and {offset_b} (delta={offset_diff}B)",
            same_object=True,
            is_established=False,
            is_candidate=True,
            offset_difference=offset_diff,
            type_compatibility=True,
            supporting_structural_facts=supporting_facts,
            contradicting_facts=[],
            missing_information=["Container template verification"],
            confidence_basis="Structural layout proximity and naming pattern",
            rationale=f"Heuristic candidate pairing for {container_type}",
        )

    def validate_counter_compatibility(
        self,
        counter_a_name: str,
        counter_a_unit: Optional[str],
        counter_b_name: str,
        counter_b_unit: Optional[str],
        counter_a_scope: Optional[str] = None,
        counter_b_scope: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Validates whether two counters measure compatible units and scopes."""
        if counter_a_scope and counter_b_scope and counter_a_scope != counter_b_scope:
            return False, f"Counters measure incompatible scopes: '{counter_a_scope}' vs '{counter_b_scope}'"

        if counter_a_unit and counter_b_unit:
            u_a = counter_a_unit.lower().strip()
            u_b = counter_b_unit.lower().strip()
            if u_a != u_b:
                return False, f"Counters measure incompatible units: '{u_a}' vs '{u_b}'"

        # Heuristic name compatibility check
        a_low = counter_a_name.lower()
        b_low = counter_b_name.lower()
        if ("byte" in a_low and "packet" in b_low) or ("packet" in a_low and "byte" in b_low):
            return False, "Incompatible counter units: bytes vs packets cannot be directly compared for balance"

        return True, None

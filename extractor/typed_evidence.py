"""Typed evidence read by hypothesis verification (roadmap stage 1, rows 1 and 2).

Every evidence item the engine collects (``AdaptiveInvestigationSession.collected_evidence``) is a dict built from
one recipe evaluation (``RecipeEvaluationResult``) and the observation it evaluated.  That dict stays the evidence
record (it is persisted, reported and referenced by id); this module adds its typed part under the key
``typed_evidence`` and is the only thing the verification rules read.  No rule reads the prose of an evidence item
(finding / counter-indicator text, descriptions, summaries): rewording a message cannot change a verdict.

Fields of :class:`TypedEvidence`:

* ``kind``         what was observed (``OBSERVATION_KINDS``: address mapping, heap integrity, memory trend, ...);
  ``rule`` is the recipe whose rule produced it, ``category`` the problem category it was filed under.
* ``polarity``     SUPPORTS (the rule found the anomaly it looks for), CONTRADICTS (it looked and found the
  invariant holding) or NEUTRAL (it could not decide).
* ``measured``     the rule's measured values: the numbers, booleans and enumerated values of its result details.
* ``scope``        what was looked at: subject (variable / pointer), address, number of samples / walks and the
  observation window in seconds when the observation has them.
* ``complete`` / ``incomplete_reasons``   whether the observation was complete; reason codes when it was cut
  (``INCOMPLETE_*``: lock graph with unresolvable owners, lock owners not decodable, heap not walked, ...).
* ``consistency_checked``   True when the observation was re-read and found stable, False when a re-read changed,
  None when the rule does not re-read.
* ``invariants``   what this evidence asserts about each verification invariant: ``VIOLATED`` or ``HOLDS``
  (absent: says nothing).  One verification criterion reads one invariant (``CRITERION_INVARIANT``).
* ``has_observation``, ``subject``      an observed value exists / the named variable it was read from.
* ``certainty_cap``, ``fault_confirmed``, ``corruption_confirmed``   what the rule allows the observation to
  prove (a cap at PROBABLE; a confirmed leak / corruption).

The invariant claims are derived once, here, from structured fields of the rule result (details flags and enumerated
values), the recipe id and category, and structured keys of the observation.  Where the previous string search
matched a word that a rule always writes (a category name, a recipe id, a fixed fact), the claim is spelled out
below as the structured condition that produces that word, with a comment naming the old match.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

SPEC_VERSION = 1
TYPED_EVIDENCE_KEY = "typed_evidence"

POLARITY_SUPPORTS = "SUPPORTS"
POLARITY_CONTRADICTS = "CONTRADICTS"
POLARITY_NEUTRAL = "NEUTRAL"

VIOLATED = "VIOLATED"
HOLDS = "HOLDS"

# Verification invariants (one per executable verification criterion)
INV_ADDRESS_VALID = "ADDRESS_VALID"              # a probed pointer targets valid mapped memory
INV_NO_POISON = "NO_POISON_PATTERN"              # no allocator poison / corrupted magic in the observed memory
INV_MEMORY_BOUNDED = "MEMORY_BOUNDED"            # the observed resource does not grow without bound
INV_NO_CIRCULAR_WAIT = "NO_CIRCULAR_WAIT"        # the lock wait-for graph has no cycle
INV_STATE_LEGAL = "STATE_LEGAL"                  # state values / transitions stay in their domain

CRITERION_INVARIANT: Dict[str, str] = {
    "CRIT_POINTER_VALID_VMA": INV_ADDRESS_VALID,
    "CRIT_NO_POISON_PATTERN": INV_NO_POISON,
    "CRIT_RSS_GROWTH_STABLE": INV_MEMORY_BOUNDED,
    "CRIT_CHUNK_RECLAMATION": INV_MEMORY_BOUNDED,
    "CRIT_NO_CIRCULAR_WAIT": INV_NO_CIRCULAR_WAIT,
    "CRIT_VALID_STATE_DOMAIN": INV_STATE_LEGAL,
    "CRIT_LEGAL_STATE_TRANSITION": INV_STATE_LEGAL,
}

# Incompleteness reason codes
INCOMPLETE_LOCK_GRAPH = "LOCK_GRAPH_INCOMPLETE"          # waiting threads whose lock owner could not be resolved
INCOMPLETE_LOCK_OWNER_UNSUPPORTED = "LOCK_OWNER_UNSUPPORTED"
INCOMPLETE_HEAP_NOT_WALKED = "HEAP_NOT_WALKED"
INCOMPLETE_RULE_UNDECIDED = "RULE_UNDECIDED"              # the rule could not decide from what was observed

# Verification scope (stage 1): an observation cut for one of these reasons cannot show that the invariant holds.
# (A /proc trend may clear MEMORY_BOUNDED without a heap walk; the poison / magic invariant needs the heap read.)
INVARIANT_SCOPE_REASONS: Dict[str, frozenset] = {
    INV_NO_POISON: frozenset({INCOMPLETE_HEAP_NOT_WALKED, INCOMPLETE_RULE_UNDECIDED}),
    INV_NO_CIRCULAR_WAIT: frozenset({INCOMPLETE_LOCK_GRAPH, INCOMPLETE_LOCK_OWNER_UNSUPPORTED,
                                     INCOMPLETE_RULE_UNDECIDED}),
    INV_ADDRESS_VALID: frozenset({INCOMPLETE_RULE_UNDECIDED}),
    INV_MEMORY_BOUNDED: frozenset({INCOMPLETE_RULE_UNDECIDED}),
    INV_STATE_LEGAL: frozenset({INCOMPLETE_RULE_UNDECIDED}),
}

# Verification criteria families.  A problem category selects the criteria that verify its hypotheses; the table is
# the explicit form of the former category-name substring test (CORRUPTION/FREE, LEAK/GROWTH, DEADLOCK/CONCURRENCY,
# STATE/VARIABLE); tests/test_typed_evidence.py checks it against every registered category.
FAMILY_CORRUPTION = "CORRUPTION"
FAMILY_GROWTH = "GROWTH"
FAMILY_DEADLOCK = "DEADLOCK"
FAMILY_STATE = "STATE"
FAMILY_GENERIC = "GENERIC"
CATEGORY_FAMILY: Dict[str, str] = {
    "MEMORY_CORRUPTION": FAMILY_CORRUPTION,
    "STACK_CORRUPTION": FAMILY_CORRUPTION,
    "USE_AFTER_FREE": FAMILY_CORRUPTION,
    "INVALID_DOUBLE_FREE": FAMILY_CORRUPTION,
    "MEMORY_LEAK": FAMILY_GROWTH,
    "FD_LEAK": FAMILY_GROWTH,
    "THREAD_LEAK": FAMILY_GROWTH,
    "MAPPING_GROWTH": FAMILY_GROWTH,
    "DEADLOCK_INDICATORS": FAMILY_DEADLOCK,
    "SELF_DEADLOCK": FAMILY_DEADLOCK,
    "ABNORMAL_VARIABLE_CHANGES": FAMILY_STATE,
    "UNEXPECTED_STATE_TRANSITIONS": FAMILY_STATE,
    "FUNCTIONAL_STATE_INCONSISTENCY": FAMILY_STATE,
    # GENERIC (one invariant-preserved criterion that no evidence decides): DATA_RACE_INDICATORS, HEAP_RETENTION,
    # LOCK_CONTENTION, ORPHAN_LOCK, PROCESS_INSTABILITY, RESOURCE_EXHAUSTION and anything not listed.
}


def criteria_family(category: Optional[str]) -> str:
    return CATEGORY_FAMILY.get(str(category or ""), FAMILY_GENERIC)


# What each recipe observes.  A recipe not listed (a plugin added later) is described by its domain.
OBSERVATION_KINDS: Dict[str, str] = {
    "RECIPE_INVALID_MEMORY_ACCESS": "ADDRESS_MAPPING",
    "RECIPE_UNEXPECTED_NULL_OR_INVALID_POINTERS": "ADDRESS_MAPPING",
    "RECIPE_INVALID_FREE": "ADDRESS_MAPPING",
    "RECIPE_HEAP_METADATA_CORRUPTION": "HEAP_INTEGRITY",
    "RECIPE_SUSPICIOUS_ALLOCATION_PATTERNS": "HEAP_INTEGRITY",
    "RECIPE_USE_AFTER_FREE": "HEAP_INTEGRITY",
    "RECIPE_FREED_MEMORY_USE": "HEAP_INTEGRITY",
    "RECIPE_DOUBLE_FREE": "HEAP_INTEGRITY",
    "RECIPE_PROCESS_MEMORY_GROWTH": "MEMORY_TREND",
    "RECIPE_HEAP_GROWTH": "MEMORY_TREND",
    "RECIPE_ALLOCATION_FREE_IMBALANCE": "MEMORY_TREND",
    "RECIPE_OBJECT_LIFETIME_ANOMALIES": "MEMORY_TREND",
    "RECIPE_REPEATED_ALLOCATION_PATTERNS": "MEMORY_TREND",
    "RECIPE_LONG_LIVED_OBJECT_ACCUMULATION": "MEMORY_TREND",
    "RECIPE_MAPPING_GROWTH": "MEMORY_TREND",
    "RECIPE_HEAP_RETENTION": "MEMORY_TREND",
    "RECIPE_FD_LEAK": "RESOURCE_TREND",
    "RECIPE_THREAD_LEAK": "RESOURCE_TREND",
    "RECIPE_POTENTIAL_DEADLOCK_PATTERNS": "LOCK_GRAPH",
    "RECIPE_SUSPICIOUS_LOCK_OWNERSHIP": "LOCK_GRAPH",
    "RECIPE_ORPHAN_LOCK": "LOCK_GRAPH",
    "RECIPE_SELF_DEADLOCK": "LOCK_GRAPH",
    "RECIPE_LOCK_CONTENTION": "LOCK_GRAPH",
    "RECIPE_THREAD_STATE_ANOMALIES": "THREAD_PROGRESS",
    "RECIPE_LONG_RUNNING_BLOCKED_THREADS": "THREAD_PROGRESS",
    "RECIPE_UNEXPECTED_VARIABLE_CHANGES": "STATE_VALUE",
    "RECIPE_SUSPICIOUS_BOUNDARY_VALUES": "STATE_VALUE",
    "RECIPE_INCONSISTENT_RELATED_VARIABLES": "STATE_VALUE",
    "RECIPE_SHARED_STATE_INCONSISTENCIES": "STATE_VALUE",
    "RECIPE_STATE_TRANSITION_VIOLATIONS": "STATE_TRANSITION",
}

# Enumerated (non-prose) string values of rule details that are measurements.
_ENUM_DETAIL_KEYS = ("violation_type", "leak_verdict", "classification", "concurrency_state", "state",
                     "certainty_cap", "finding_category", "finding_severity", "heap_check_status",
                     "memory_integrity_mode", "lock_owner_status", "expectation")

_STATUS_POLARITY = {"SUPPORTED": POLARITY_SUPPORTS, "CONTRADICTED": POLARITY_CONTRADICTS}


@dataclass
class TypedEvidence:
    """The typed part of one collected evidence item (see the module docstring)."""
    evidence_id: str = ""
    kind: str = "UNKNOWN"
    rule: str = ""
    category: str = ""
    polarity: str = POLARITY_NEUTRAL
    measured: Dict[str, Any] = field(default_factory=dict)
    scope: Dict[str, Any] = field(default_factory=dict)
    complete: bool = True
    incomplete_reasons: List[str] = field(default_factory=list)
    consistency_checked: Optional[bool] = None
    invariants: Dict[str, str] = field(default_factory=dict)
    has_observation: bool = False
    subject: Optional[str] = None
    certainty_cap: Optional[str] = None
    fault_confirmed: bool = False
    corruption_confirmed: bool = False
    spec_version: int = SPEC_VERSION

    def violates(self, invariant: str) -> bool:
        return self.invariants.get(invariant) == VIOLATED

    def upholds(self, invariant: str) -> bool:
        """The evidence asserts the invariant holds AND its observation covered what the invariant needs (an
        observation cut for a reason that matters to this invariant cannot clear it: stage 1, verification scope)."""
        if self.invariants.get(invariant) != HOLDS:
            return False
        return not (set(self.incomplete_reasons) & INVARIANT_SCOPE_REASONS.get(invariant, frozenset()))

    def claims_hold_without_scope(self, invariant: str) -> bool:
        """It asserts HOLDS, but its observation was cut for a reason that matters to the invariant."""
        return self.invariants.get(invariant) == HOLDS and not self.upholds(invariant)

    @property
    def lock_graph_incomplete(self) -> bool:
        return INCOMPLETE_LOCK_GRAPH in self.incomplete_reasons

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TypedEvidence":
        known = set(cls.__dataclass_fields__)
        return cls(**{k: v for k, v in data.items() if k in known})


def _dict(v: Any) -> Dict[str, Any]:
    return v if isinstance(v, dict) else {}


def _is_number(v: Any) -> bool:
    return isinstance(v, (int, float)) and not isinstance(v, bool)


# ------------------------------------------------------------------------------------------- invariant claims
def _address_valid(pol: str, rid: str, det: Dict[str, Any], obs: Dict[str, Any]) -> Optional[str]:
    if pol == POLARITY_SUPPORTS:
        if det.get("violation_type") in ("NULL_POINTER_DEREFERENCE", "UNMAPPED_OR_GUARD_PAGE",
                                         # "within NULL guard page" fact of RECIPE_INVALID_MEMORY_ACCESS
                                         "CONFIRMED_INVALID_DEREFERENCE"):
            return VIOLATED
        # was: "NULL" in str(evidence) - matched the id of this recipe in every one of its positive findings
        if rid == "RECIPE_UNEXPECTED_NULL_OR_INVALID_POINTERS":
            return VIOLATED
        # was: "NULL" in str(evidence) - the provider's violation type of a pointer value inside the NULL page
        if obs.get("violation_type") == "NULL_PAGE_POINTER_VALUE":
            return VIOLATED
    elif pol == POLARITY_CONTRADICTS:
        # "validly mapped" fact <=> violation_type NONE_VALID_VMA; a clean idle NULL pointer
        if det.get("is_healthy") or det.get("violation_type") in ("NONE_IDLE_NULL_POINTER", "NONE_VALID_VMA"):
            return HOLDS
    return None


def _no_poison(pol: str, rid: str, cat: str, det: Dict[str, Any], obs: Dict[str, Any]) -> Optional[str]:
    if pol == POLARITY_SUPPORTS:
        if det.get("magic_corrupted"):
            return VIOLATED
        # was: "magic" / "poison" in str(evidence) - the provider's keys magic_corrupted / observed_magic (set only
        # when a magic/canary variable holds a poison constant) and poison_pattern (poison bytes at the probed
        # pointer); the name-hint cap of the rule names them too
        if obs.get("magic_corrupted") or obs.get("observed_magic") is not None or obs.get("poison_pattern") \
                or obs.get("corruption_hint_source") is not None or det.get("corruption_hint_only"):
            return VIOLATED
        # Defect 1 (fixed, stage 1): the former "poison" in str(evidence) matched the text "poison_detected=<bool>"
        # that RECIPE_USE_AFTER_FREE writes into every positive finding, whatever the bool, so a use-after-free
        # without poison bytes claimed poison.  The rule now records the bool it measured; only True claims it.
        if rid == "RECIPE_USE_AFTER_FREE" and det.get("uaf_confirmed") and det.get("poison_detected") is True:
            return VIOLATED
    elif pol == POLARITY_CONTRADICTS:
        # The former "clean" / "valid" in str(evidence) matched words that are no observation of the memory's bytes:
        # Defect 2 (fixed): the category INVALID_DOUBLE_FREE ("invalid" contains "valid");
        # Defect 3 (fixed): the recipe ids RECIPE_INVALID_* / *_NULL_OR_INVALID_* (same substring);
        # Defect 4 (fixed): the details key object_valid, which RECIPE_INVALID_MEMORY_ACCESS writes into every
        #   negative result (True by default, whether or not any object header / magic was read).
        # None of them claims anything now.  What does observe the bytes:
        if det.get("canaries_intact"):          # the heap chunk canaries were read and are intact ("Canaries valid")
            return HOLDS
        if _magic_observed_intact(obs):         # an object header / magic value was read and is not corrupted
            return HOLDS
    return None


def _magic_observed_intact(obs: Dict[str, Any]) -> bool:
    """The observation carries a magic / canary / object-header reading and it is intact (an explicit value in the
    observation, never a default the rule writes into its result)."""
    if obs.get("magic_corrupted") is False or obs.get("canary_corrupted") is False:
        return True
    return obs.get("canary_valid") is True or obs.get("object_valid") is True


_NO_GROWTH_CLASSIFICATIONS = ("STABLE_PLATEAU",)


def _memory_bounded(pol: str, rid: str, cat: str, det: Dict[str, Any], obs: Dict[str, Any]) -> Optional[str]:
    if pol == POLARITY_SUPPORTS:
        # was: "growth" / "leak" in str(evidence) - every positive finding of a growth-family category carries its
        # category name (MEMORY_LEAK, FD_LEAK, THREAD_LEAK, MAPPING_GROWTH): the rule found growth
        if criteria_family(cat) == FAMILY_GROWTH or det.get("growth_confirmed"):
            return VIOLATED
    elif pol == POLARITY_CONTRADICTS:
        if det.get("transient_warmup"):
            return HOLDS
        # was: "stable" / "plateau" in str(evidence).  Structured producers of those words:
        if det.get("classification") in _NO_GROWTH_CLASSIFICATIONS:          # memory trend STABLE_PLATEAU
            return HOLDS
        if det.get("leak_verdict") == "NO_GROWTH" \
                or _dict(obs.get("leak_investigation")).get("verdict") == "NO_GROWTH":   # "in-use heap stable"
            return HOLDS
        if det.get("heap_stable") or det.get("population_stable") or det.get("stable_container"):
            return HOLDS
        if obs.get("thread_count_trend") == "stable":                       # thread sampler trend value
            return HOLDS
    return None


def _no_circular_wait(pol: str, cat: str, det: Dict[str, Any]) -> Optional[str]:
    if pol == POLARITY_SUPPORTS:
        # was: "deadlock" in str(evidence) - every positive finding of DEADLOCK_INDICATORS / SELF_DEADLOCK carries
        # its category name
        if criteria_family(cat) == FAMILY_DEADLOCK or det.get("deadlock_detected"):
            return VIOLATED
    elif pol == POLARITY_CONTRADICTS:
        # was: "acyclic" / "no circular wait" in str(evidence): the facts of a complete acyclic wait-for graph
        if det.get("lock_graph_acyclic") or det.get("state") == "NO_DEADLOCK_ACYCLIC":
            return HOLDS
    return None


def _state_legal(pol: str, rid: str, cat: str, det: Dict[str, Any]) -> Optional[str]:
    if pol == POLARITY_SUPPORTS:
        if det.get("field_inconsistency") or det.get("illegal_transition_confirmed") or det.get("boundary_violation"):
            return VIOLATED
        # was: "transition" / "boundary" in str(evidence) - the category name UNEXPECTED_STATE_TRANSITIONS and the
        # recipe id RECIPE_SUSPICIOUS_BOUNDARY_VALUES
        if cat == "UNEXPECTED_STATE_TRANSITIONS" or rid == "RECIPE_SUSPICIOUS_BOUNDARY_VALUES":
            return VIOLATED
    elif pol == POLARITY_CONTRADICTS:
        # was: "authorized" / "within bounds" in str(evidence): an authorized transition / a value within bounds
        if det.get("illegal_transition_confirmed") is False:
            return HOLDS
        if rid == "RECIPE_UNEXPECTED_VARIABLE_CHANGES" and det.get("violation_confirmed") is False:
            return HOLDS
    return None


# ------------------------------------------------------------------------------------------- completeness / scope
def _incomplete_reasons(status: str, det: Dict[str, Any], obs: Dict[str, Any]) -> List[str]:
    out: List[str] = []
    if det.get("incomplete_lock_graph"):
        out.append(INCOMPLETE_LOCK_GRAPH)
    if det.get("lock_owner_unsupported") or obs.get("lock_owner_unsupported"):
        out.append(INCOMPLETE_LOCK_OWNER_UNSUPPORTED)
    heap = _dict(_dict(obs.get("memory_integrity")).get("heap"))
    if heap.get("status") in ("NOT_CHECKED", "UNSUPPORTED", "LIMITED"):
        out.append(INCOMPLETE_HEAP_NOT_WALKED)
    if status not in ("SUPPORTED", "CONTRADICTED", "NOT_APPLICABLE", ""):
        out.append(INCOMPLETE_RULE_UNDECIDED)
    return out


def _consistency_checked(det: Dict[str, Any], obs: Dict[str, Any]) -> Optional[bool]:
    """Re-read stability of the observation, where the rule re-reads (heap integrity, free lists, freed chunks)."""
    if det.get("transient_cycle"):
        return False
    heap = _dict(_dict(obs.get("memory_integrity")).get("heap"))
    defects = [d for d in heap.get("defects") or [] if isinstance(d, dict)]
    if defects:
        return all(bool(d.get("stable")) for d in defects)
    for key in ("free_list_repeats", "freed_memory_use"):
        rec = _dict(obs.get(key))
        if rec.get("status") == "COMPLETED":
            return True
    if heap.get("status") in ("COMPLETED", "PARTIAL"):
        return True
    return None


def _scope(ev: Dict[str, Any], obs: Dict[str, Any]) -> Dict[str, Any]:
    li = _dict(obs.get("leak_investigation"))
    trend = _dict(obs.get("memory_trend"))
    sampling = _dict(obs.get("thread_sampling"))
    samples = None
    for v in (li.get("walks"), obs.get("epoch_count"), trend.get("samples"), sampling.get("samples"),
              obs.get("observation_window_samples")):
        if _is_number(v):
            samples = int(v)
            break
    window_s = None
    for v in (li.get("window_s"), trend.get("window_s"), sampling.get("window_sec")):
        if _is_number(v):
            window_s = float(v)
            break
    out: Dict[str, Any] = {"rule": ev.get("recipe_id")}
    if ev.get("symbol"):
        out["subject"] = ev.get("symbol")
    if ev.get("address") is not None:
        out["address"] = ev.get("address")
    if samples is not None:
        out["samples"] = samples
    if window_s is not None:
        out["window_s"] = window_s
    return out


def _measured(det: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    for k, v in det.items():
        if isinstance(v, bool) or _is_number(v):
            out[k] = v
    for k in _ENUM_DETAIL_KEYS:
        v = det.get(k)
        if isinstance(v, str):
            out[k] = v
    return out


def derive_typed_evidence(ev: Dict[str, Any], domain: Optional[str] = None) -> TypedEvidence:
    """The typed part of an evidence dict, derived from its structured fields only."""
    det = _dict(ev.get("details"))
    obs = _dict(ev.get("raw_observation"))
    status = str(ev.get("status") or "")
    pol = _STATUS_POLARITY.get(status, POLARITY_NEUTRAL)
    rid = str(ev.get("recipe_id") or "")
    cat = str(ev.get("problem_category") or "")
    invariants: Dict[str, str] = {}
    for inv, claim in ((INV_ADDRESS_VALID, _address_valid(pol, rid, det, obs)),
                       (INV_NO_POISON, _no_poison(pol, rid, cat, det, obs)),
                       (INV_MEMORY_BOUNDED, _memory_bounded(pol, rid, cat, det, obs)),
                       (INV_NO_CIRCULAR_WAIT, _no_circular_wait(pol, cat, det)),
                       (INV_STATE_LEGAL, _state_legal(pol, rid, cat, det))):
        if claim is not None:
            invariants[inv] = claim
    reasons = _incomplete_reasons(status, det, obs)
    cap = det.get("certainty_cap")
    return TypedEvidence(
        evidence_id=str(ev.get("evidence_id") or ""),
        kind=OBSERVATION_KINDS.get(rid) or str(domain or ev.get("domain") or "UNKNOWN"),
        rule=rid,
        category=cat,
        polarity=pol,
        measured=_measured(det),
        scope=_scope(ev, obs),
        complete=not reasons,
        incomplete_reasons=reasons,
        consistency_checked=_consistency_checked(det, obs),
        invariants=invariants,
        has_observation=ev.get("observed_value") is not None,
        subject=str(ev["symbol"]) if ev.get("symbol") else None,
        certainty_cap=str(cap) if isinstance(cap, str) else None,
        fault_confirmed=bool(det.get("leak_confirmed") or det.get("corruption_confirmed")),
        corruption_confirmed=bool(det.get("corruption_confirmed")),
    )


def attach_typed_evidence(ev: Dict[str, Any]) -> Dict[str, Any]:
    """Adds the typed part to an evidence dict at the place it is produced (returns the same dict)."""
    ev[TYPED_EVIDENCE_KEY] = derive_typed_evidence(ev).to_dict()
    return ev


def typed_evidence_of(ev: Dict[str, Any]) -> TypedEvidence:
    """The typed part of a collected evidence item; derived on the fly for an item persisted before it existed."""
    t = ev.get(TYPED_EVIDENCE_KEY) if isinstance(ev, dict) else None
    if isinstance(t, dict):
        return TypedEvidence.from_dict(t)
    return derive_typed_evidence(ev if isinstance(ev, dict) else {})

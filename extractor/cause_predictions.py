"""What each competing cause predicts about the typed evidence, and the outcome the evidence gives each cause.

Roadmap stage 1 (one hypothesis model) and stage 4 (expected outcomes).  A competing-hypothesis candidate
(``CompetingHypothesis``) is one explanation of the symptom.  Before this module a candidate took the verdict of the
verified hypothesis that consumed the evidence of any of its rules, so every cause that merely shared a check with the
real fault read "supported" (warm-up and fragmentation next to the leak, contention and futex starvation next to the
deadlock).  Here the outcome of a cause is what the evidence says about THAT cause:

* **Signals.**  ``SIGNALS`` turns a typed evidence item (``extractor.typed_evidence.TypedEvidence``: kind, category,
  polarity, invariant claims, measured enum / bool / number fields, completeness) into an observed value of a named
  signal, for example ``heap_in_use_trend = SUSTAINED`` or ``wait_cycle = PERSISTENT``.  Only typed fields are read;
  no text.  When several items observe the same signal the value earliest in the signal's ``values`` order wins (the
  stronger observation: a cycle that persisted over a re-read beats one acyclic snapshot).
* **Predictions.**  ``CAUSE_PREDICTIONS`` declares, per candidate id, the values it predicts for some signals:
  ``defining`` (what makes the cause what it is; ``match`` says whether all or any of them must be seen) and
  ``expected`` (what else must hold if the cause is true).  Signals a cause does not mention are indifferent to it.
* **Outcome** (``evaluate_causes``):
  - *refuted*: an observed signal value lies outside what the cause predicts (any ``expected``; for ``match="any"``
    every ``defining`` signal observed and outside);
  - *supported*: not refuted, its defining signals seen with the predicted values, at least one of them a positive
    observation (``positive`` values of the signal: something seen, not the absence of something), and for every
    rival still standing one of those observations is a value the rival does not predict (the evidence discriminates
    in its favour).  Rivals are the other candidates of the same domain not declared ``compatible``;
  - *undecided*, reason ``NOT_DISTINGUISHED``: it has matching observations, but they are shared with a rival still
    standing or its own defining observation is missing (shared evidence never supports a cause);
  - *undecided*, reason ``NOT_OBSERVED``: nothing observed bears on it.

The final verdict does not come from here (it is the verified ``ExpertHypothesis``); this module only decides how
the candidates read next to it.  ``predicted_outcomes`` reuses the same declarations to say, before a check runs,
which open causes each possible outcome of the check would separate (stage 4, expected-outcome tables).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, FrozenSet, Iterable, List, Optional, Tuple

from extractor.typed_evidence import (
    INV_ADDRESS_VALID,
    INV_MEMORY_BOUNDED,
    INV_NO_CIRCULAR_WAIT,
    INV_STATE_LEGAL,
    POLARITY_CONTRADICTS,
    POLARITY_SUPPORTS,
    TypedEvidence,
    typed_evidence_of,
)

OUTCOME_SUPPORTED = "supported"
OUTCOME_REFUTED = "refuted"
OUTCOME_UNDECIDED = "undecided"

REASON_DISCRIMINATING = "DISCRIMINATING_EVIDENCE"
REASON_CONTRADICTED = "CONTRADICTED_BY_EVIDENCE"
REASON_NOT_DISTINGUISHED = "NOT_DISTINGUISHED"
REASON_NOT_OBSERVED = "NOT_OBSERVED"


def _num(v: Any) -> Optional[float]:
    return float(v) if isinstance(v, (int, float)) and not isinstance(v, bool) else None


# ------------------------------------------------------------------------------------------------ signals
# Each extractor reads one typed evidence item and returns the value it observes for the signal, or None.

_SUSTAINED_LEAK_VERDICTS = frozenset({"LEAK_UNREACHABLE", "UNBOUNDED_GROWTH_OWNED"})
_SUSTAINED_CLASSES = frozenset({"CONFIRMED_LEAK", "LIVE_ALLOCATION_GROWTH", "OBJECT_ACCUMULATION", "PROBABLE_LEAK"})
_TRANSIENT_CLASSES = frozenset({"INITIALIZATION_WARMUP", "CACHE_WARMUP", "TRANSIENT_BURST", "PERIODIC_RECLAMATION"})
_FLAT_CLASSES = frozenset({"STABLE_PLATEAU", "HEAP_RESERVATION_GROWTH"})


def _heap_in_use_trend(te: TypedEvidence) -> Optional[str]:
    """The in-use (live) heap over the observation window: SUSTAINED = grew across every heap walk without a drop;
    TRANSIENT = rose then fell; GREW = larger at the end than at the start, the path in between not observed (the
    first-to-last heap delta of the legacy rule: a warm-up looks the same); FLAT = did not grow (also: the heap
    mapping grew while the live allocations stayed constant)."""
    m = te.measured
    lv, cl = m.get("leak_verdict"), m.get("classification")
    if lv in _SUSTAINED_LEAK_VERDICTS or cl in _SUSTAINED_CLASSES:
        return "SUSTAINED"
    if lv == "IN_USE_SHRANK" or m.get("transient_warmup") is True or cl in _TRANSIENT_CLASSES:
        return "TRANSIENT"
    if m.get("heap_growth_confirmed") is True:
        return "GREW"
    if lv in ("NO_GROWTH", "NO_GROWTH_TREND") or cl in _FLAT_CLASSES or m.get("heap_stable") is True \
            or m.get("vma_reservation_only") is True:
        return "FLAT"
    return None


def _growth_owner(te: TypedEvidence) -> Optional[str]:
    """Whether the blocks that grew are still referenced from a named owner (container / global) or unreachable."""
    m = te.measured
    if m.get("leak_verdict") == "LEAK_UNREACHABLE":
        return "UNREACHABLE"
    if m.get("leak_verdict") == "UNBOUNDED_GROWTH_OWNED" or m.get("object_accumulation_confirmed") is True:
        return "REFERENCED"
    return None


def _alloc_counter_balance(te: TypedEvidence) -> Optional[str]:
    v = te.measured.get("imbalance_confirmed")
    if v is True and te.polarity == POLARITY_SUPPORTS:
        return "IMBALANCED"
    if v is False and te.polarity == POLARITY_CONTRADICTS and te.complete:
        return "BALANCED"
    return None


def _wait_cycle(te: TypedEvidence) -> Optional[str]:
    """The wait-for graph between threads: a cycle that persisted over re-reads, one seen once, or none."""
    if te.violates(INV_NO_CIRCULAR_WAIT):
        if te.measured.get("is_persistent") is True or te.measured.get("state") == "PERSISTENT_DEADLOCK":
            return "PERSISTENT"
        return "SEEN"
    if te.measured.get("transient_cycle") is True:
        return "SEEN"
    if te.upholds(INV_NO_CIRCULAR_WAIT):
        return "NONE"
    return None


def _threads_blocked(te: TypedEvidence) -> Optional[str]:
    m = te.measured
    if m.get("persistent_block") is True or (_num(m.get("blocked_thread_count")) or 0) > 0:
        return "BLOCKED"
    if m.get("threads_healthy") is True or (m.get("blocked_thread_count") == 0 and te.polarity == POLARITY_CONTRADICTS
                                            and te.complete):
        return "NOT_BLOCKED"
    return None


def _thread_state(te: TypedEvidence) -> Optional[str]:
    v = te.measured.get("thread_state_anomaly")
    if v is True:
        return "ANOMALOUS"
    if v is False and te.complete:
        return "NORMAL"
    return None


def _by_polarity(present: str, absent: str, need_inspected: bool = False) -> Callable[[TypedEvidence], Optional[str]]:
    """SUPPORTS -> ``present``; a complete CONTRADICTS -> ``absent`` (with ``need_inspected``: only when the check
    inspected at least one mutex, so a target without locks says nothing about lock owners)."""
    def ext(te: TypedEvidence) -> Optional[str]:
        if te.polarity == POLARITY_SUPPORTS:
            return present
        if te.polarity == POLARITY_CONTRADICTS and te.complete:
            if need_inspected and not (_num(te.measured.get("mutexes_inspected")) or 0) > 0:
                return None
            return absent
        return None
    return ext


def _heap_header_damage(te: TypedEvidence) -> Optional[str]:
    if te.polarity == POLARITY_SUPPORTS:
        return "DAMAGED"
    if te.polarity == POLARITY_CONTRADICTS and te.complete and te.measured.get("heap_check_status") == "COMPLETED":
        return "INTACT"
    return None


def _invariant(inv: str, violated: str, holds: str) -> Callable[[TypedEvidence], Optional[str]]:
    def ext(te: TypedEvidence) -> Optional[str]:
        if te.violates(inv):
            return violated
        if te.upholds(inv):
            return holds
        return None
    return ext


@dataclass(frozen=True)
class Signal:
    """One observable property of the target.  ``kinds`` / ``categories``: the typed evidence it is read from (kind,
    and when given the problem category the evidence was filed under); ``values``: the possible values, strongest
    first; ``positive``: the values that are a thing seen rather than the absence of one."""
    name: str
    kinds: FrozenSet[str]
    values: Tuple[str, ...]
    positive: FrozenSet[str]
    extract: Callable[[TypedEvidence], Optional[str]]
    categories: Optional[FrozenSet[str]] = None

    def reads(self, te: TypedEvidence) -> bool:
        return te.kind in self.kinds and (self.categories is None or te.category in self.categories)


def _sig(name, kinds, values, positive, extract, categories=None) -> Signal:
    return Signal(name, frozenset(kinds), tuple(values), frozenset(positive), extract,
                  frozenset(categories) if categories else None)


SIGNALS: Dict[str, Signal] = {s.name: s for s in (
    _sig("heap_in_use_trend", ["MEMORY_TREND"], ["SUSTAINED", "TRANSIENT", "GREW", "FLAT"],
         ["SUSTAINED", "TRANSIENT", "GREW"],
         _heap_in_use_trend, ["MEMORY_LEAK"]),
    _sig("growth_owner", ["MEMORY_TREND"], ["UNREACHABLE", "REFERENCED"], ["UNREACHABLE", "REFERENCED"],
         _growth_owner, ["MEMORY_LEAK"]),
    _sig("alloc_counter_balance", ["MEMORY_TREND"], ["IMBALANCED", "BALANCED"], ["IMBALANCED"],
         _alloc_counter_balance),
    _sig("memory_bounded", ["MEMORY_TREND"], ["UNBOUNDED", "BOUNDED"], ["UNBOUNDED"],
         _invariant(INV_MEMORY_BOUNDED, "UNBOUNDED", "BOUNDED")),
    _sig("resource_bounded", ["RESOURCE_TREND"], ["UNBOUNDED", "BOUNDED"], ["UNBOUNDED"],
         _invariant(INV_MEMORY_BOUNDED, "UNBOUNDED", "BOUNDED")),
    _sig("wait_cycle", ["LOCK_GRAPH"], ["PERSISTENT", "SEEN", "NONE"], ["PERSISTENT", "SEEN"], _wait_cycle,
         ["DEADLOCK_INDICATORS"]),
    _sig("threads_blocked", ["THREAD_PROGRESS"], ["BLOCKED", "NOT_BLOCKED"], ["BLOCKED"], _threads_blocked),
    # an anomalous thread state (runaway, zombie or D-state thread) is not specific to one cause: never positive
    _sig("thread_state", ["THREAD_PROGRESS"], ["ANOMALOUS", "NORMAL"], [], _thread_state),
    _sig("lock_queueing", ["LOCK_GRAPH"], ["QUEUED", "NOT_QUEUED"], ["QUEUED"],
         _by_polarity("QUEUED", "NOT_QUEUED"), ["LOCK_CONTENTION"]),
    _sig("lock_owner_gone", ["LOCK_GRAPH"], ["GONE", "ALIVE"], ["GONE"],
         _by_polarity("GONE", "ALIVE", need_inspected=True), ["ORPHAN_LOCK"]),
    _sig("self_wait", ["LOCK_GRAPH"], ["PRESENT", "ABSENT"], ["PRESENT"],
         _by_polarity("PRESENT", "ABSENT", need_inspected=True), ["SELF_DEADLOCK"]),
    _sig("heap_header_damage", ["HEAP_INTEGRITY"], ["DAMAGED", "INTACT"], ["DAMAGED"], _heap_header_damage,
         ["MEMORY_CORRUPTION"]),
    _sig("freed_block_use", ["HEAP_INTEGRITY"], ["USED", "NONE"], ["USED"], _by_polarity("USED", "NONE"),
         ["USE_AFTER_FREE"]),
    _sig("free_list_repeat", ["HEAP_INTEGRITY"], ["REPEATED", "NONE"], ["REPEATED"], _by_polarity("REPEATED", "NONE"),
         ["INVALID_DOUBLE_FREE"]),
    _sig("address_validity", ["ADDRESS_MAPPING"], ["INVALID", "VALID"], ["INVALID"],
         _invariant(INV_ADDRESS_VALID, "INVALID", "VALID")),
    _sig("state_consistency", ["STATE_VALUE", "STATE_TRANSITION"], ["VIOLATED", "LEGAL"], ["VIOLATED"],
         _invariant(INV_STATE_LEGAL, "VIOLATED", "LEGAL")),
)}


# ------------------------------------------------------------------------------------------------ predictions
@dataclass(frozen=True)
class CausePrediction:
    """What one competing cause predicts (see the module docstring)."""
    defining: Dict[str, FrozenSet[str]]
    expected: Dict[str, FrozenSet[str]] = field(default_factory=dict)
    match: str = "all"                      # "all" / "any" of the defining signals
    compatible: FrozenSet[str] = frozenset()  # other candidates that can be true at the same time

    def accepted(self, signal: str) -> Optional[FrozenSet[str]]:
        if signal in self.defining:
            return self.defining[signal]
        return self.expected.get(signal)

    def signals(self) -> List[str]:
        return list(self.defining) + [s for s in self.expected if s not in self.defining]


def _p(defining: Dict[str, Iterable[str]], expected: Optional[Dict[str, Iterable[str]]] = None, match: str = "all",
       compatible: Iterable[str] = ()) -> CausePrediction:
    return CausePrediction({k: frozenset(v) for k, v in defining.items()},
                           {k: frozenset(v) for k, v in (expected or {}).items()}, match, frozenset(compatible))


_NO_CYCLE = ("NONE", "SEEN")      # no wait-for cycle, or one that did not persist (a lock hand-off)
_GROWING = ("SUSTAINED", "GREW")  # the live heap is larger at the end of the window

CAUSE_PREDICTIONS: Dict[str, CausePrediction] = {
    # memory growth: what grew, whether it kept growing, and whether anything still references it
    "HYP_HEAP_ALLOC_LEAK": _p({"heap_in_use_trend": _GROWING, "growth_owner": ["UNREACHABLE"]},
                              compatible=["HYP_ALLOC_FREE_IMBALANCE"]),
    "HYP_OBJECT_ACCUMULATION": _p({"heap_in_use_trend": _GROWING, "growth_owner": ["REFERENCED"]},
                                  compatible=["HYP_ALLOC_FREE_IMBALANCE"]),
    "HYP_ALLOC_FREE_IMBALANCE": _p({"alloc_counter_balance": ["IMBALANCED"]}, {"heap_in_use_trend": _GROWING},
                                   compatible=["HYP_HEAP_ALLOC_LEAK", "HYP_OBJECT_ACCUMULATION"]),
    # a warm-up ends at a plateau: it may look like first-to-last growth, never like growth across every walk
    "HYP_TRANSIENT_WARMUP": _p({"heap_in_use_trend": ["TRANSIENT", "GREW", "FLAT"]}),
    "HYP_ALLOCATOR_FRAGMENTATION": _p({"heap_in_use_trend": ["FLAT"]}),
    # heap integrity: which allocator structure is damaged and how
    "HYP_USE_AFTER_FREE": _p({"freed_block_use": ["USED"]}),
    "HYP_HEAP_BUFFER_OVERFLOW": _p({"heap_header_damage": ["DAMAGED"]}),
    "HYP_DOUBLE_FREE": _p({"free_list_repeat": ["REPEATED"]}),
    "HYP_UNMAPPED_WILD_ACCESS": _p({"address_validity": ["INVALID"]}),
    # threads that stop: a persistent cycle, a queue on a held lock, a missing wake-up, or slow compute
    "HYP_CIRCULAR_WAIT_DEADLOCK": _p({"wait_cycle": ["PERSISTENT"]}, {"threads_blocked": ["BLOCKED"]}),
    "HYP_LONG_HOLDING_CONTENTION": _p({"lock_queueing": ["QUEUED"]},
                                      {"wait_cycle": _NO_CYCLE, "lock_owner_gone": ["ALIVE"], "self_wait": ["ABSENT"]}),
    "HYP_KERNEL_FUTEX_STARVATION": _p({"threads_blocked": ["BLOCKED"], "wait_cycle": _NO_CYCLE},
                                      {"lock_queueing": ["NOT_QUEUED"], "lock_owner_gone": ["ALIVE"],
                                       "self_wait": ["ABSENT"]}),
    "HYP_SLOW_PROGRESS_COMPUTE": _p({"thread_state": ["ANOMALOUS"]}, {"wait_cycle": _NO_CYCLE}),
    # process instability (different domains: not rivals of one another)
    "HYP_PROGRESSIVE_EXHAUSTION_CRASH": _p({"memory_bounded": ["UNBOUNDED"], "resource_bounded": ["UNBOUNDED"]},
                                           match="any"),
    "HYP_LATENT_CORRUPTION_CRASH": _p({"heap_header_damage": ["DAMAGED"], "freed_block_use": ["USED"],
                                       "free_list_repeat": ["REPEATED"]}, match="any"),
    "HYP_CONCURRENCY_STALL_WATCHDOG": _p({"wait_cycle": ["PERSISTENT"], "state_consistency": ["VIOLATED"]},
                                         match="any"),
    # general symptom: one broad candidate per domain
    "HYP_CANDIDATE_MEMORY_GROWTH": _p({"memory_bounded": ["UNBOUNDED"]}),
    "HYP_CANDIDATE_MEMORY_CORRUPTION": _p({"heap_header_damage": ["DAMAGED"], "freed_block_use": ["USED"],
                                           "free_list_repeat": ["REPEATED"], "address_validity": ["INVALID"]},
                                          match="any"),
    "HYP_CANDIDATE_CONCURRENCY_ANOMALY": _p({"wait_cycle": ["PERSISTENT"], "lock_queueing": ["QUEUED"],
                                             "self_wait": ["PRESENT"], "lock_owner_gone": ["GONE"]}, match="any"),
}


def prediction_of(candidate_id: str) -> Optional[CausePrediction]:
    return CAUSE_PREDICTIONS.get(str(candidate_id or ""))


# ------------------------------------------------------------------------------------------------ observation
@dataclass
class Observed:
    """The value a signal took in this investigation, with the evidence behind it."""
    signal: str
    value: str
    evidence_ids: List[str]
    rules: List[str]
    values_seen: Dict[str, List[str]]          # every value observed -> evidence ids (several when they disagree)

    def to_dict(self) -> Dict[str, Any]:
        return {"signal": self.signal, "observed": self.value, "evidence_ids": list(self.evidence_ids),
                "rules": list(self.rules), "values_seen": {k: list(v) for k, v in self.values_seen.items()}}


def observe_signals(evidence: Iterable[Dict[str, Any]]) -> Dict[str, Observed]:
    """The signals the collected evidence observed (typed part of each item only)."""
    seen: Dict[str, Dict[str, List[Tuple[str, str]]]] = {}
    for ev in evidence:
        if not isinstance(ev, dict):
            continue
        te = typed_evidence_of(ev)
        for sig in SIGNALS.values():
            if not sig.reads(te):
                continue
            v = sig.extract(te)
            if v is None or v not in sig.values:
                continue
            seen.setdefault(sig.name, {}).setdefault(v, []).append((te.evidence_id, te.rule))
    out: Dict[str, Observed] = {}
    for name, by_value in seen.items():
        order = SIGNALS[name].values
        best = min(by_value, key=order.index)
        items = by_value[best]
        out[name] = Observed(signal=name, value=best,
                             evidence_ids=[e for e, _ in items if e],
                             rules=list(dict.fromkeys(r for _, r in items if r)),
                             values_seen={v: [e for e, _ in its if e] for v, its in by_value.items()})
    return out


# ------------------------------------------------------------------------------------------------ outcomes
def _rivals(cid: str, domain_of: Dict[str, str], pred: CausePrediction) -> List[str]:
    """Candidates that cannot be true together with ``cid``: same domain, declared on both sides, not compatible."""
    out = []
    for other, dom in domain_of.items():
        op = CAUSE_PREDICTIONS.get(other)
        if other == cid or op is None or dom != domain_of.get(cid):
            continue
        if other in pred.compatible or cid in op.compatible:
            continue
        out.append(other)
    return out


def _contradictions(pred: CausePrediction, obs: Dict[str, Observed]) -> List[Dict[str, Any]]:
    """The observations outside what the cause predicts (defining first): non-empty = refuted."""
    out = []
    defin = [(s, acc) for s, acc in pred.defining.items()]
    bad = [(s, acc) for s, acc in defin if s in obs and obs[s].value not in acc]
    if pred.match == "all" or (bad and len(bad) == len(defin)):
        out += [dict(obs[s].to_dict(), predicted=sorted(acc), role="defining") for s, acc in bad]
    for s in pred.expected:
        if s in obs and obs[s].value not in pred.expected[s]:
            out.append(dict(obs[s].to_dict(), predicted=sorted(pred.expected[s]), role="expected"))
    # a thing seen (a persistent cycle) says more against a cause than the absence of something: first
    out.sort(key=lambda m: m["observed"] not in SIGNALS[m["signal"]].positive)
    return out


def _matches(pred: CausePrediction, obs: Dict[str, Observed]) -> List[Dict[str, Any]]:
    return [dict(obs[s].to_dict(), predicted=sorted(pred.accepted(s) or ()),
                 role="defining" if s in pred.defining else "expected")
            for s in pred.signals() if s in obs and obs[s].value in (pred.accepted(s) or ())]


def _defining_satisfied(pred: CausePrediction, obs: Dict[str, Observed]) -> bool:
    hits = [s for s, acc in pred.defining.items() if s in obs and obs[s].value in acc]
    return bool(hits) if pred.match == "any" else len(hits) == len(pred.defining)


def evaluate_causes(candidates: List[Tuple[str, str]], evidence: Iterable[Dict[str, Any]],
                    observed: Optional[Dict[str, Observed]] = None) -> Dict[str, Dict[str, Any]]:
    """The outcome the evidence gives each declared candidate.

    ``candidates``: ``(candidate id, domain)`` of the investigation's candidate set (undeclared ids are skipped).
    Returns ``{candidate id: {outcome, reason, matched, contradicted, decisive, rivals_not_distinguished, ...}}``."""
    obs = observed if observed is not None else observe_signals(evidence)
    domain_of = {cid: dom for cid, dom in candidates if cid in CAUSE_PREDICTIONS}
    contra = {cid: _contradictions(CAUSE_PREDICTIONS[cid], obs) for cid in domain_of}
    refuted = {cid for cid, c in contra.items() if c}
    out: Dict[str, Dict[str, Any]] = {}
    for cid in domain_of:
        pred = CAUSE_PREDICTIONS[cid]
        matched = _matches(pred, obs)
        rec: Dict[str, Any] = {"matched": matched, "contradicted": contra[cid], "decisive": [],
                               "rivals_not_distinguished": []}
        if cid in refuted:
            rec.update(outcome=OUTCOME_REFUTED, reason=REASON_CONTRADICTED)
            out[cid] = rec
            continue
        positive = [m for m in matched if m["role"] == "defining" and m["observed"] in SIGNALS[m["signal"]].positive]
        standing = [r for r in _rivals(cid, domain_of, pred) if r not in refuted]
        # a rival is told apart when one of the positive defining observations is a value it does not predict
        undistinguished = [r for r in standing
                           if not any(p["observed"] not in (CAUSE_PREDICTIONS[r].accepted(p["signal"]) or ())
                                      for p in positive)]
        if positive and _defining_satisfied(pred, obs) and not undistinguished:
            rec.update(outcome=OUTCOME_SUPPORTED, reason=REASON_DISCRIMINATING, decisive=positive)
        elif matched:
            # shared evidence: name the rivals that predict the same observations (or every rival still standing when
            # its own defining observation is missing)
            shared = [r for r in standing
                      if all(m["observed"] in (CAUSE_PREDICTIONS[r].accepted(m["signal"]) or ()) for m in matched)]
            rec.update(outcome=OUTCOME_UNDECIDED, reason=REASON_NOT_DISTINGUISHED,
                       rivals_not_distinguished=undistinguished or shared or standing)
        else:
            rec.update(outcome=OUTCOME_UNDECIDED, reason=REASON_NOT_OBSERVED)
        out[cid] = rec
    return out


# ------------------------------------------------------------------------------------------------ expected outcomes
def signals_of_kinds(kinds: Iterable[str], categories: Optional[Iterable[str]] = None) -> List[str]:
    """The signals typed evidence of these kinds (and problem categories) can observe."""
    ks, cs = set(kinds), set(categories or ())
    return [s.name for s in SIGNALS.values()
            if s.kinds & ks and (s.categories is None or not cs or s.categories & cs)]


def predicted_outcomes(signals: Iterable[str], open_candidates: List[str]) -> List[Dict[str, Any]]:
    """For each value the given signals can take: the open candidates it would support (predicted with a positive
    value), keep (predicted or indifferent) and refute (outside what they predict).  The expected-outcome table of a
    check that observes these signals (stage 4)."""
    rows = []
    for name in signals:
        sig = SIGNALS.get(name)
        if sig is None:
            continue
        for v in sig.values:
            sup, ref = [], []
            for cid in open_candidates:
                pred = CAUSE_PREDICTIONS.get(cid)
                acc = pred.accepted(name) if pred else None
                if acc is None:
                    continue
                if v in acc:
                    if name in pred.defining and v in sig.positive:
                        sup.append(cid)
                else:
                    ref.append(cid)
            rows.append({"signal": name, "value": v, "supports": sup, "refutes": ref})
    return rows

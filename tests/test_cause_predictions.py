"""Competing causes read what the evidence says about each of them (extractor.cause_predictions).

Before: a candidate took the verdict of the verified hypothesis that consumed the evidence of any of its rules, so a
cause that merely shared a check with the real fault read "supported" (warm-up and fragmentation next to a leak,
contention and futex starvation next to a deadlock), and the cause matching a finding found by a check outside its
declared rules read "undecided".

Unit tests drive the binding with typed evidence; the live tests diagnose a leak target and a deadlock target of the
accuracy benchmark and read the "other causes considered" table of the report.
"""

import os
import shutil
import sys
import unittest

from extractor.cause_predictions import (
    CAUSE_PREDICTIONS,
    OUTCOME_REFUTED,
    OUTCOME_SUPPORTED,
    OUTCOME_UNDECIDED,
    REASON_NOT_DISTINGUISHED,
    SIGNALS,
    evaluate_causes,
    observe_signals,
    predicted_outcomes,
)
from extractor.competing_hypotheses import (
    SYMPTOM_CANDIDATE_SET,
    CompetingHypothesisManager,
    candidate_verdict_source,
)
from extractor.typed_evidence import TYPED_EVIDENCE_KEY, TypedEvidence
from tests.support.tmpdirs import temp_dir

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _ev(eid, rule, kind, category, polarity, measured=None, invariants=None, complete=True, reasons=None):
    te = TypedEvidence(evidence_id=eid, kind=kind, rule=rule, category=category, polarity=polarity,
                       measured=dict(measured or {}), invariants=dict(invariants or {}), complete=complete,
                       incomplete_reasons=list(reasons or []))
    return {"evidence_id": eid, "recipe_id": rule, TYPED_EVIDENCE_KEY: te.to_dict(),
            # prose that names every cause: the binding must not read it
            "finding": "warm-up fragmentation contention futex starvation deadlock leak overflow"}


def _cands(symptom):
    return CompetingHypothesisManager.generate_competing_hypotheses_for_symptom(symptom)


def _outcomes(symptom, evidence):
    return evaluate_causes([(c.hypothesis_id, c.domain) for c in _cands(symptom)], evidence)


# typed evidence the real rules record (shapes taken from diagnoses of the benchmark targets)
def _owned_leak():
    m = {"leak_verdict": "UNBOUNDED_GROWTH_OWNED", "growth_confirmed": True, "classification": "OBJECT_ACCUMULATION"}
    return [_ev("ev_g", "RECIPE_PROCESS_MEMORY_GROWTH", "MEMORY_TREND", "MEMORY_LEAK", "SUPPORTS", m,
                {"MEMORY_BOUNDED": "VIOLATED"}),
            _ev("ev_h", "RECIPE_HEAP_GROWTH", "MEMORY_TREND", "MEMORY_LEAK", "SUPPORTS",
                {"leak_verdict": "UNBOUNDED_GROWTH_OWNED", "heap_growth_confirmed": True},
                {"MEMORY_BOUNDED": "VIOLATED"}),
            _ev("ev_o", "RECIPE_LONG_LIVED_OBJECT_ACCUMULATION", "MEMORY_TREND", "MEMORY_LEAK", "SUPPORTS",
                {"leak_verdict": "UNBOUNDED_GROWTH_OWNED", "object_accumulation_confirmed": True},
                {"MEMORY_BOUNDED": "VIOLATED"})]


def _unreachable_leak():
    return [_ev("ev_g", "RECIPE_PROCESS_MEMORY_GROWTH", "MEMORY_TREND", "MEMORY_LEAK", "SUPPORTS",
                {"leak_verdict": "LEAK_UNREACHABLE", "classification": "CONFIRMED_LEAK"}, {"MEMORY_BOUNDED": "VIOLATED"})]


def _deadlock():
    return [_ev("ev_c", "RECIPE_POTENTIAL_DEADLOCK_PATTERNS", "LOCK_GRAPH", "DEADLOCK_INDICATORS", "SUPPORTS",
                {"deadlock_confirmed": True, "is_persistent": True, "state": "PERSISTENT_DEADLOCK"},
                {"NO_CIRCULAR_WAIT": "VIOLATED"}),
            _ev("ev_b", "RECIPE_LONG_RUNNING_BLOCKED_THREADS", "THREAD_PROGRESS", "DEADLOCK_INDICATORS", "SUPPORTS",
                {"blocked_thread_count": 2, "deadlock_detected": True}, {"NO_CIRCULAR_WAIT": "VIOLATED"}),
            _ev("ev_q", "RECIPE_LOCK_CONTENTION", "LOCK_GRAPH", "LOCK_CONTENTION", "CONTRADICTS", {"mutexes": 2})]


def _contention():
    return [_ev("ev_q", "RECIPE_LOCK_CONTENTION", "LOCK_GRAPH", "LOCK_CONTENTION", "SUPPORTS",
                {"queued_fraction": 1.0, "samples": 5}),
            _ev("ev_a", "RECIPE_POTENTIAL_DEADLOCK_PATTERNS", "LOCK_GRAPH", "DEADLOCK_INDICATORS", "CONTRADICTS",
                {"lock_graph_acyclic": True}, {"NO_CIRCULAR_WAIT": "HOLDS"}),
            _ev("ev_t", "RECIPE_THREAD_STATE_ANOMALIES", "THREAD_PROGRESS", "DEADLOCK_INDICATORS", "CONTRADICTS",
                {"thread_state_anomaly": False, "threads_healthy": True})]


class _Verified:
    def __init__(self, hid, category, status, supporting=(), contradicting=(), confidence=0.9):
        self.hypothesis_id, self.category, self.status, self.confidence = hid, category, status, confidence
        self.supporting_evidence = [{"evidence_id": e} for e in supporting]
        self.contradicting_evidence = [{"evidence_id": e} for e in contradicting]
        self.confidence_basis = ""


class DeclarationsTest(unittest.TestCase):
    def test_every_generated_candidate_declares_its_predictions(self):
        seen = set()
        for symptom in set(SYMPTOM_CANDIDATE_SET) | {"GENERAL"}:
            for c in _cands(symptom):
                seen.add(c.hypothesis_id)
                self.assertIn(c.hypothesis_id, CAUSE_PREDICTIONS, c.hypothesis_id)
        self.assertEqual(seen, set(CAUSE_PREDICTIONS))

    def test_predictions_name_real_signals_and_values(self):
        for cid, p in CAUSE_PREDICTIONS.items():
            self.assertTrue(p.defining, cid)
            self.assertIn(p.match, ("all", "any"), cid)
            for s in p.signals():
                self.assertIn(s, SIGNALS, (cid, s))
                self.assertTrue(set(p.accepted(s)) <= set(SIGNALS[s].values), (cid, s))
            for other in p.compatible:
                self.assertIn(cid, CAUSE_PREDICTIONS[other].compatible, (cid, other))

    def test_signal_extractors_read_typed_fields_only(self):
        # the same typed evidence with any wording gives the same signals
        a = observe_signals(_deadlock())
        b = [dict(e, finding="all clear", counter_indicator="no cycle") for e in _deadlock()]
        self.assertEqual({k: v.value for k, v in a.items()}, {k: v.value for k, v in observe_signals(b).items()})


class LeakCausesTest(unittest.TestCase):
    def test_growth_reachable_from_a_container(self):
        o = _outcomes("MEMORY_LEAK", _owned_leak())
        self.assertEqual(o["HYP_OBJECT_ACCUMULATION"]["outcome"], OUTCOME_SUPPORTED)
        # growth that never drops and is still referenced contradicts a warm-up, fragmentation and a dropped pointer
        for cid in ("HYP_TRANSIENT_WARMUP", "HYP_ALLOCATOR_FRAGMENTATION", "HYP_HEAP_ALLOC_LEAK"):
            self.assertEqual(o[cid]["outcome"], OUTCOME_REFUTED, cid)
            self.assertTrue(o[cid]["contradicted"], cid)
        self.assertEqual(o["HYP_TRANSIENT_WARMUP"]["contradicted"][0]["observed"], "SUSTAINED")
        self.assertEqual(o["HYP_HEAP_ALLOC_LEAK"]["contradicted"][0]["observed"], "REFERENCED")
        # the counter imbalance was not observed: the shared growth does not support it
        self.assertEqual(o["HYP_ALLOC_FREE_IMBALANCE"]["outcome"], OUTCOME_UNDECIDED)
        self.assertEqual(o["HYP_ALLOC_FREE_IMBALANCE"]["reason"], REASON_NOT_DISTINGUISHED)

    def test_unreachable_growth(self):
        o = _outcomes("MEMORY_LEAK", _unreachable_leak())
        self.assertEqual(o["HYP_HEAP_ALLOC_LEAK"]["outcome"], OUTCOME_SUPPORTED)
        self.assertEqual(o["HYP_OBJECT_ACCUMULATION"]["outcome"], OUTCOME_REFUTED)

    def test_shared_growth_supports_no_cause(self):
        # first-to-last heap growth alone: a leak, an accumulation and a warm-up all predict it
        ev = [_ev("ev_h", "RECIPE_HEAP_GROWTH", "MEMORY_TREND", "MEMORY_LEAK", "SUPPORTS",
                  {"heap_growth_confirmed": True}, {"MEMORY_BOUNDED": "VIOLATED"})]
        o = _outcomes("MEMORY_LEAK", ev)
        for cid in ("HYP_HEAP_ALLOC_LEAK", "HYP_OBJECT_ACCUMULATION", "HYP_TRANSIENT_WARMUP"):
            self.assertEqual(o[cid]["outcome"], OUTCOME_UNDECIDED, cid)
            self.assertEqual(o[cid]["reason"], REASON_NOT_DISTINGUISHED, cid)
            self.assertTrue(o[cid]["rivals_not_distinguished"], cid)
        self.assertFalse([c for c, r in o.items() if r["outcome"] == OUTCOME_SUPPORTED])

    def test_shrinking_heap_refutes_the_leaks(self):
        ev = [_ev("ev_h", "RECIPE_HEAP_GROWTH", "MEMORY_TREND", "MEMORY_LEAK", "CONTRADICTS",
                  {"leak_verdict": "IN_USE_SHRANK", "transient_warmup": True}, {"MEMORY_BOUNDED": "HOLDS"})]
        o = _outcomes("MEMORY_LEAK", ev)
        for cid in ("HYP_HEAP_ALLOC_LEAK", "HYP_OBJECT_ACCUMULATION", "HYP_ALLOCATOR_FRAGMENTATION"):
            self.assertEqual(o[cid]["outcome"], OUTCOME_REFUTED, cid)
        self.assertEqual(o["HYP_TRANSIENT_WARMUP"]["outcome"], OUTCOME_SUPPORTED)


class ConcurrencyCausesTest(unittest.TestCase):
    def test_persistent_cycle(self):
        o = _outcomes("DEADLOCK_INDICATORS", _deadlock())
        self.assertEqual(o["HYP_CIRCULAR_WAIT_DEADLOCK"]["outcome"], OUTCOME_SUPPORTED)
        for cid in ("HYP_LONG_HOLDING_CONTENTION", "HYP_KERNEL_FUTEX_STARVATION", "HYP_SLOW_PROGRESS_COMPUTE"):
            self.assertEqual(o[cid]["outcome"], OUTCOME_REFUTED, cid)
            # the persistent cycle is what rules them out (a thing seen comes before an absence)
            self.assertEqual((o[cid]["contradicted"][0]["signal"], o[cid]["contradicted"][0]["observed"]),
                             ("wait_cycle", "PERSISTENT"), cid)

    def test_queue_on_a_lock_without_cycle(self):
        o = _outcomes("DEADLOCK_INDICATORS", _contention())
        self.assertEqual(o["HYP_LONG_HOLDING_CONTENTION"]["outcome"], OUTCOME_SUPPORTED)
        for cid in ("HYP_CIRCULAR_WAIT_DEADLOCK", "HYP_KERNEL_FUTEX_STARVATION", "HYP_SLOW_PROGRESS_COMPUTE"):
            self.assertEqual(o[cid]["outcome"], OUTCOME_REFUTED, cid)

    def test_blocked_threads_alone_do_not_tell_deadlock_from_starvation(self):
        ev = [_ev("ev_b", "RECIPE_LONG_RUNNING_BLOCKED_THREADS", "THREAD_PROGRESS", "DEADLOCK_INDICATORS",
                  "SUPPORTS", {"blocked_thread_count": 2})]
        o = _outcomes("DEADLOCK_INDICATORS", ev)
        for cid in ("HYP_CIRCULAR_WAIT_DEADLOCK", "HYP_KERNEL_FUTEX_STARVATION"):
            self.assertEqual(o[cid]["outcome"], OUTCOME_UNDECIDED, cid)
            self.assertEqual(o[cid]["reason"], REASON_NOT_DISTINGUISHED, cid)

    def test_incomplete_lock_graph_does_not_clear_a_cycle(self):
        ev = [_ev("ev_a", "RECIPE_POTENTIAL_DEADLOCK_PATTERNS", "LOCK_GRAPH", "DEADLOCK_INDICATORS", "CONTRADICTS",
                  {"lock_graph_acyclic": True}, {"NO_CIRCULAR_WAIT": "HOLDS"}, complete=False,
                  reasons=["LOCK_GRAPH_INCOMPLETE"])]
        self.assertNotIn("wait_cycle", observe_signals(ev))
        self.assertNotEqual(_outcomes("DEADLOCK_INDICATORS", ev)["HYP_CIRCULAR_WAIT_DEADLOCK"]["outcome"],
                            OUTCOME_REFUTED)


class BindingTest(unittest.TestCase):
    def test_cause_of_the_finding_is_bound_to_the_check_that_found_it(self):
        # the overflow was found by the heap metadata walk; the bound rules are that check, whatever the candidate's
        # own declared rules are
        ev = [_ev("ev_m", "RECIPE_HEAP_METADATA_CORRUPTION", "HEAP_INTEGRITY", "MEMORY_CORRUPTION", "SUPPORTS",
                  {"corruption_confirmed": True, "heap_check_status": "COMPLETED"}),
              _ev("ev_f", "RECIPE_FREED_MEMORY_USE", "HEAP_INTEGRITY", "USE_AFTER_FREE", "CONTRADICTS",
                  {"freed_memory_checked": True}),
              _ev("ev_d", "RECIPE_DOUBLE_FREE", "HEAP_INTEGRITY", "INVALID_DOUBLE_FREE", "CONTRADICTS",
                  {"free_lists_checked": True, "double_free_confirmed": False})]
        cands = {c.hypothesis_id: c for c in _cands("MEMORY_CORRUPTION")}
        o = evaluate_causes([(c.hypothesis_id, c.domain) for c in cands.values()], ev)
        verified = [_Verified("HYP_01", "MEMORY_CORRUPTION", "CONFIRMED", supporting=["ev_m"]),
                    _Verified("HYP_02", "USE_AFTER_FREE", "REFUTED", contradicting=["ev_f"])]
        src = candidate_verdict_source(cands["HYP_HEAP_BUFFER_OVERFLOW"], verified, o["HYP_HEAP_BUFFER_OVERFLOW"])
        self.assertEqual((src["status"], src["hypothesis_id"], src["rules"]),
                         ("CONFIRMED", "HYP_01", ["RECIPE_HEAP_METADATA_CORRUPTION"]))
        self.assertEqual(src["supporting_evidence_ids"], ["ev_m"])
        uaf = candidate_verdict_source(cands["HYP_USE_AFTER_FREE"], verified, o["HYP_USE_AFTER_FREE"])
        self.assertEqual((uaf["status"], uaf["rules"]), ("REFUTED", ["RECIPE_FREED_MEMORY_USE"]))
        wild = candidate_verdict_source(cands["HYP_UNMAPPED_WILD_ACCESS"], verified, o["HYP_UNMAPPED_WILD_ACCESS"])
        self.assertEqual((wild["status"], wild["reason"]), ("INCONCLUSIVE", "NOT_OBSERVED"))

    def test_shared_evidence_never_takes_the_verified_verdict(self):
        cands = {c.hypothesis_id: c for c in _cands("MEMORY_LEAK")}
        ev = _owned_leak()
        o = evaluate_causes([(c.hypothesis_id, c.domain) for c in cands.values()], ev)
        verified = [_Verified("HYP_01", "MEMORY_LEAK", "LIKELY", supporting=[e["evidence_id"] for e in ev])]
        st = {cid: candidate_verdict_source(c, verified, o[cid])["status"] for cid, c in cands.items()}
        self.assertEqual(st, {"HYP_OBJECT_ACCUMULATION": "LIKELY", "HYP_HEAP_ALLOC_LEAK": "REFUTED",
                              "HYP_TRANSIENT_WARMUP": "REFUTED", "HYP_ALLOCATOR_FRAGMENTATION": "REFUTED",
                              "HYP_ALLOC_FREE_IMBALANCE": "INCONCLUSIVE"})

    def test_expected_outcome_table(self):
        rows = predicted_outcomes(["wait_cycle"], ["HYP_CIRCULAR_WAIT_DEADLOCK", "HYP_KERNEL_FUTEX_STARVATION"])
        by_v = {r["value"]: r for r in rows}
        self.assertEqual(by_v["PERSISTENT"]["supports"], ["HYP_CIRCULAR_WAIT_DEADLOCK"])
        self.assertEqual(by_v["PERSISTENT"]["refutes"], ["HYP_KERNEL_FUTEX_STARVATION"])
        self.assertEqual(by_v["NONE"]["refutes"], ["HYP_CIRCULAR_WAIT_DEADLOCK"])


# ------------------------------------------------------------------------------------------------ live
def _benchmark():
    sys.path.insert(0, os.path.join(ROOT, "benchmarks", "diagnosis_accuracy"))
    import run_benchmark as rb  # noqa: E402
    return rb


@unittest.skipUnless(shutil.which("gcc"), "gcc not available: cannot build the benchmark targets")
class LiveCompetingCausesTest(unittest.TestCase):
    """Diagnose a leak target and a deadlock target; read section F and the report's causes table."""

    def _diagnose(self, target_id):
        from extractor.expert_diagnostic_engine import diagnose
        rb = _benchmark()
        gt = next(g for g in rb.load_ground_truth() if g["id"] == target_id)
        tmp = temp_dir(self, "cause_pred_")
        binary = rb.build_target(gt, tmp)
        proc = rb._launch(binary, gt)
        self.addCleanup(rb._kill, proc)
        rb._wait_ready(proc, gt)
        return diagnose(proc.pid, binary, gt["symptom"], corpus_dir=os.path.join(tmp, "corpus"),
                        include_report=True).to_dict()

    def _check(self, target_id, want_supported, fault_category):
        from extractor import report_story as rs
        from extractor.human_report import check_rows
        res = self._diagnose(target_id)
        self.assertIn(res["verdict"], ("CONFIRMED_FAULT", "PROBABLE_FAULT"), target_id)
        cands = res["report"]["section_f_competing_hypotheses"]["competing_candidates"]
        by_id = {c["hypothesis_id"]: c for c in cands}
        supported = [c["hypothesis_id"] for c in cands if c["status"] in ("CONFIRMED", "LIKELY", "SUPPORTED")]
        # at most one of the mutually exclusive causes is supported, and it is the one matching the finding
        self.assertEqual(supported, [want_supported], target_id)
        src = by_id[want_supported]["verdict_source"]
        self.assertEqual(src["outcome"], "supported")
        found = {r for f in res["findings"] if f.get("category") == fault_category for r in f.get("recipe_ids") or []}
        self.assertTrue(set(src["rules"]) & found, (src["rules"], found))
        for cid, c in by_id.items():
            if cid == want_supported:
                continue
            self.assertIn(c["status"], ("REFUTED", "INCONCLUSIVE"), cid)
            self.assertTrue(c["verdict_source"].get("reason"), cid)
        # the report table: the same outcomes, each with what decided it
        table = rs.competing_causes("ko", res, res["report"], check_rows(res, res["report"]))
        causes = [c for item in table for c in item["causes"]]
        self.assertTrue(causes)
        self.assertEqual([c["id"] for c in causes if c["outcome"] == "supported"], [want_supported])
        for c in causes:
            self.assertTrue(c["evidence"], c["id"])
            if c["outcome"] == "ruled_out":
                self.assertIn("이 원인과 맞지 않음", c["evidence"], c["id"])
        return by_id

    def test_leak_reachable_from_a_container(self):
        by_id = self._check("leak_registry", "HYP_OBJECT_ACCUMULATION", "MEMORY_LEAK")
        for cid in ("HYP_TRANSIENT_WARMUP", "HYP_ALLOCATOR_FRAGMENTATION"):
            self.assertEqual(by_id[cid]["status"], "REFUTED", cid)

    def test_deadlock(self):
        by_id = self._check("deadlock_pipeline", "HYP_CIRCULAR_WAIT_DEADLOCK", "DEADLOCK_INDICATORS")
        for cid in ("HYP_LONG_HOLDING_CONTENTION", "HYP_KERNEL_FUTEX_STARVATION"):
            self.assertEqual(by_id[cid]["status"], "REFUTED", cid)
            self.assertEqual(by_id[cid]["verdict_source"]["signals"][0]["observed"], "PERSISTENT", cid)


if __name__ == "__main__":
    unittest.main()

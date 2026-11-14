"""Orphan lock and self-deadlock diagnoses (extractor/recipe_plugins/lock_faults.py) on synthetic observations."""
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from extractor import diagnostic_recipes as dr  # noqa: E402
from extractor import report_registry as rr  # noqa: E402
from extractor.human_report import render_human_report  # noqa: E402
from extractor.recipe_plugins import lock_faults as lf  # noqa: E402
from extractor.report_visuals import build_visual_summary  # noqa: E402

EVIL = "<img src=x onerror=alert(1)>"
OWNER, W1, W2 = 900, 901, 902


def _lock(addr="0x10", owner=OWNER, word=2, typ="pthread_mutex_t", name="m_cfg", waiters=(W1, W2)):
    return {"lock_label": name, "address": addr, "type": typ, "state_word": word, "recursion_count": 0,
            "owner_id": owner, "waiter_ids": list(waiters)}


def _sample(t, threads, locks, waits):
    return {"t_s": t, "thread_ids": [x[0] for x in threads], "thread_labels": {str(a): b for a, b in threads},
            "locks": locks, "waits": [dict(w, lock_label=w.get("lock_label", "m_cfg")) for w in waits],
            "wait_frames": {str(w["thread_id"]): [{"function_name": "reader", "source_location": "t.c:19"}] for w in waits},
            "status": "ANOMALIES_DETECTED", "lock_owner_status": "SUPPORTED", "limitations": []}


def _wait(tid, name="reader", addr="0x10", owner=OWNER):
    return {"thread_id": tid, "thread_label": name, "address": addr, "owner_id": owner}


def _samples(threads, locks, waits, n=2):
    return [_sample(0.0 + 0.15 * k, threads, locks, waits) for k in range(n)]


def _obs(samples, exists=lambda tid: False, **extra):
    lw = {"samples": samples, "lock_owner_status": "SUPPORTED"}
    lw.update(lf.analyse(samples, exists))
    lw.update(extra)
    return {lf.OBS_LOCK_WAIT_STATE: lw}


def _run(rid, data):
    r = dr.DiagnosticRecipeRegistry.get_recipe(rid)
    return r.rule(r, data)


ORPHAN = _obs(_samples([(1, "main"), (W1, "reader"), (W2, "reader")], [_lock()], [_wait(W1), _wait(W2)]))
SELF = _obs(_samples([(1, "main"), (W1, "refresher")], [_lock(owner=W1, name="m_state", waiters=(W1,))],
                     [_wait(W1, "refresher", owner=W1)]))
HEALTHY = _obs(_samples([(1, "main"), (W1, "w"), (W2, "w")], [_lock(owner=W1, waiters=(W2,))], [_wait(W2, "w", owner=W1)]))


class TestRegistration(unittest.TestCase):
    def test_baseline_recipes_and_categories(self):
        for rid, cat in ((lf.RECIPE_ORPHAN_LOCK, "ORPHAN_LOCK"), (lf.RECIPE_SELF_DEADLOCK, "SELF_DEADLOCK")):
            self.assertIn(rid, dr.BASELINE_RECIPE_IDS)
            self.assertIn(cat, dr.ALL_PROBLEM_CATEGORIES)
            self.assertIsNotNone(rr.recipe_label(rid))
            self.assertIsNotNone(rr.category_label(cat))


class TestOrphanRule(unittest.TestCase):
    def test_owner_gone_with_waiters_is_supported(self):
        r = _run(lf.RECIPE_ORPHAN_LOCK, ORPHAN)
        self.assertEqual(r.status, dr.RECIPE_STATUS_SUPPORTED)
        self.assertEqual(r.details["waiting_threads"], 2)
        self.assertIn("m_cfg", r.confidence_basis)
        self.assertGreaterEqual(r.confidence, 0.9)
        # the self-deadlock rule must not fire on it
        self.assertEqual(_run(lf.RECIPE_SELF_DEADLOCK, ORPHAN).status, dr.RECIPE_STATUS_CONTRADICTED)

    def test_orphan_without_waiters_is_supported_with_lower_confidence(self):
        d = _obs(_samples([(1, "main")], [_lock(waiters=())], []))
        r = _run(lf.RECIPE_ORPHAN_LOCK, d)
        self.assertEqual(r.status, dr.RECIPE_STATUS_SUPPORTED)
        self.assertLess(r.confidence, 0.9)

    def test_healthy_lock_is_contradicted(self):
        r = _run(lf.RECIPE_ORPHAN_LOCK, HEALTHY)
        self.assertEqual(r.status, dr.RECIPE_STATUS_CONTRADICTED)
        self.assertEqual(_run(lf.RECIPE_SELF_DEADLOCK, HEALTHY).status, dr.RECIPE_STATUS_CONTRADICTED)

    def test_unlocked_mutex_with_stale_owner_is_not_an_orphan(self):
        d = _obs(_samples([(1, "main")], [_lock(word=0, waiters=())], []))
        self.assertEqual(_run(lf.RECIPE_ORPHAN_LOCK, d).status, dr.RECIPE_STATUS_CONTRADICTED)

    def test_robust_owner_died_word_is_not_reported(self):
        d = _obs(_samples([(1, "main")], [_lock(word=0x40000000 | 2, waiters=())], []))
        self.assertEqual(_run(lf.RECIPE_ORPHAN_LOCK, d).status, dr.RECIPE_STATUS_CONTRADICTED)

    def test_non_mutex_type_is_not_decoded(self):
        d = _obs(_samples([(1, "main")], [_lock(typ="sem_t", waiters=())], []))
        # not decoded, so no mutex was inspected: "nothing inspected", not a pass (and never an orphan)
        self.assertEqual(_run(lf.RECIPE_ORPHAN_LOCK, d).status, dr.RECIPE_STATUS_INSUFFICIENT_EVIDENCE)

    def test_owner_alive_outside_the_process_is_not_an_orphan(self):
        d = _obs(_samples([(1, "main")], [_lock(waiters=())], []), exists=lambda tid: True)
        r = _run(lf.RECIPE_ORPHAN_LOCK, d)
        self.assertEqual(r.status, dr.RECIPE_STATUS_CONTRADICTED)
        self.assertIn("process-shared", r.confidence_basis)

    def test_unverifiable_owner_is_insufficient_evidence(self):
        d = _obs(_samples([(1, "main")], [_lock(waiters=())], []), exists=lambda tid: None)
        self.assertEqual(_run(lf.RECIPE_ORPHAN_LOCK, d).status, dr.RECIPE_STATUS_INSUFFICIENT_EVIDENCE)

    def test_owner_visible_in_one_sample_is_not_an_orphan(self):
        s = _samples([(1, "main")], [_lock(waiters=())], [])
        s[0]["thread_ids"].append(OWNER)             # the thread existed at the first sample
        self.assertEqual(_run(lf.RECIPE_ORPHAN_LOCK, _obs(s)).status, dr.RECIPE_STATUS_CONTRADICTED)

    def test_not_enough_evidence(self):
        for data in ({}, {lf.OBS_LOCK_WAIT_STATE: {"samples": [], "unavailable": "boom"}},
                     _obs(_samples([(1, "main")], [_lock()], [], n=1)),
                     {lf.OBS_LOCK_WAIT_STATE: dict(ORPHAN[lf.OBS_LOCK_WAIT_STATE], lock_owner_status="NOT_SUPPORTED_ON_TARGET")}):
            for rid in (lf.RECIPE_ORPHAN_LOCK, lf.RECIPE_SELF_DEADLOCK):
                self.assertEqual(_run(rid, data).status, dr.RECIPE_STATUS_INSUFFICIENT_EVIDENCE)


class TestSelfDeadlockRule(unittest.TestCase):
    def test_wait_on_own_mutex_is_supported(self):
        r = _run(lf.RECIPE_SELF_DEADLOCK, SELF)
        self.assertEqual(r.status, dr.RECIPE_STATUS_SUPPORTED)
        self.assertIn("m_state", r.confidence_basis)
        self.assertIn("refresher", r.confidence_basis)
        self.assertEqual(_run(lf.RECIPE_ORPHAN_LOCK, SELF).status, dr.RECIPE_STATUS_CONTRADICTED)

    def test_wait_seen_in_one_sample_only_is_not_enough(self):
        s = _samples([(1, "main"), (W1, "r")], [_lock(owner=W1, waiters=(W1,))], [_wait(W1, "r", owner=W1)])
        s[0]["waits"] = []
        self.assertEqual(_run(lf.RECIPE_SELF_DEADLOCK, _obs(s)).status, dr.RECIPE_STATUS_CONTRADICTED)

    def test_thread_that_is_scheduled_between_samples_is_not_stuck(self):
        # a busy lock handed on between threads: the waiter is its own owner in a sample only because the owner word was
        # read just after its futex wait ended; its context-switch count moved, so it is not a self-deadlock
        def mk(sw):
            s = _samples([(1, "main"), (W1, "r")], [_lock(owner=W1, waiters=(W1,))], [_wait(W1, "r", owner=W1)])
            for smp, v in zip(s, sw):
                smp["switches"] = {str(W1): v}
            return s
        self.assertEqual(_run(lf.RECIPE_SELF_DEADLOCK, _obs(mk([40, 52]))).status, dr.RECIPE_STATUS_CONTRADICTED)
        self.assertEqual(_run(lf.RECIPE_SELF_DEADLOCK, _obs(mk([40, 40]))).status, dr.RECIPE_STATUS_SUPPORTED)
        self.assertEqual(_run(lf.RECIPE_SELF_DEADLOCK, _obs(mk([None, None]))).status, dr.RECIPE_STATUS_SUPPORTED)

    def test_other_owner_is_a_normal_wait(self):
        self.assertEqual(_run(lf.RECIPE_SELF_DEADLOCK, HEALTHY).status, dr.RECIPE_STATUS_CONTRADICTED)


def _result(rid, cat, data, evil=False):
    check = {"recipe_id": rid, "status": "FAIL", "name": "x", "actual_observations": data}
    f = {"category": cat, "severity": "HIGH", "status": "PROBABLE_CAUSE", "description": "d", "recipe_ids": [rid],
         "subject_details": [{"kind": "lock", "name": "m_cfg"}, {"kind": "thread_name", "name": "reader"}], "observed": ["seen"]}
    return {"verdict": "PROBABLE_FAULT", "confidence": 0.7, "findings": [f], "not_covered": [],
            "checks_run": [{"recipe_id": rid, "status": "FAIL"}], "target": {"pid": 1, "process_name": "p"},
            "report": {"section_d_detailed_inspection_results": {"checks": [check]}}}


class TestPresentation(unittest.TestCase):
    def _html(self, rid, cat, data, lang):
        res = _result(rid, cat, data)
        return build_visual_summary(res, res["report"], lang), render_human_report(res, res["report"], lang)

    def test_orphan_picture_and_text(self):
        h, md = self._html(lf.RECIPE_ORPHAN_LOCK, "ORPHAN_LOCK", ORPHAN, "en")
        self.assertIn("How the lock became orphaned", h)
        self.assertIn("dsv-stepper", h)
        self.assertIn("dsv-chip-rec", h)                 # the acquisition is reconstructed
        self.assertIn("dsv-chip-obs", h)                 # the exit and the waits were observed
        self.assertIn("data-steps=\"5\"", h)             # take, exit, 2 waits, closing banner
        self.assertIn("ORPHANED LOCK", h)
        self.assertIn("is locked by tid 900", md)
        self.assertNotRegex(h + md, "[가-힣]")

    def test_orphan_korean(self):
        h, md = self._html(lf.RECIPE_ORPHAN_LOCK, "ORPHAN_LOCK", ORPHAN, "ko")
        self.assertIn("락이 주인 없이 남게 된 순서", h)
        self.assertIn("주인 없는 락", h)
        self.assertIn("주인 없는 락 (소유 스레드 종료)", md)

    def test_self_deadlock_picture_and_text(self):
        h, md = self._html(lf.RECIPE_SELF_DEADLOCK, "SELF_DEADLOCK", SELF, "en")
        self.assertIn("How the thread blocked itself", h)
        self.assertIn('data-steps="3"', h)
        self.assertIn("SELF-DEADLOCK", h)
        self.assertIn("t.c:19", h)
        self.assertIn("which it holds itself", md)
        self.assertNotRegex(h + md, "[가-힣]")
        hk, mk = self._html(lf.RECIPE_SELF_DEADLOCK, "SELF_DEADLOCK", SELF, "ko")
        self.assertIn("스레드가 스스로 멈추게 된 순서", hk)
        self.assertIn("자기 교착", hk)

    def test_everything_from_the_target_is_escaped_and_no_script(self):
        bad = _obs(_samples([(1, "main"), (W1, EVIL), (W2, EVIL)], [_lock(name=EVIL)], [_wait(W1, EVIL), _wait(W2, EVIL)]))
        bad[lf.OBS_LOCK_WAIT_STATE]["orphan_locks"][0]["lock_name"] = EVIL
        for w in bad[lf.OBS_LOCK_WAIT_STATE]["orphan_locks"][0]["waiters"]:
            w["waiter_name"] = EVIL
            w["source_location"] = EVIL
        selfd = {lf.OBS_LOCK_WAIT_STATE: {"samples": SELF[lf.OBS_LOCK_WAIT_STATE]["samples"], "self_waits": [
            {"lock_name": EVIL, "waiter_tid": 5, "waiter_name": EVIL, "samples_seen": 2, "source_location": EVIL,
             "call_path": [{"function_name": EVIL, "source_location": EVIL}, {"function_name": EVIL, "source_location": EVIL}]}]}}
        for rid, cat, d in ((lf.RECIPE_ORPHAN_LOCK, "ORPHAN_LOCK", bad), (lf.RECIPE_SELF_DEADLOCK, "SELF_DEADLOCK", selfd)):
            for lang in ("en", "ko"):
                h, _ = self._html(rid, cat, d, lang)
                self.assertNotIn(EVIL, h)
                self.assertIn("&lt;img", h)
                self.assertNotIn("<script", h)
                self.assertNotRegex(h, r"<[^>]+\son\w+\s*=")

    def test_no_evidence_draws_nothing_and_never_raises(self):
        for rid, cat in ((lf.RECIPE_ORPHAN_LOCK, "ORPHAN_LOCK"), (lf.RECIPE_SELF_DEADLOCK, "SELF_DEADLOCK")):
            h, md = self._html(rid, cat, {}, "en")
            self.assertNotIn("dsv-stepper", h)
            self.assertIn("Finding 1", h)


if __name__ == "__main__":
    unittest.main()

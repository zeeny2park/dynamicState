"""Lock contention diagnosis (extractor/recipe_plugins/lock_contention.py): rule on synthetic sampler output,
the sampler's per-sample lock digest, presentation, and live checks on the benchmark targets."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from extractor import diagnostic_recipes as dr  # noqa: E402
from extractor import report_registry as rr  # noqa: E402
from extractor import thread_sampler as ts  # noqa: E402
from extractor.human_report import render_human_report  # noqa: E402
from extractor.recipe_plugins import lock_contention as lc  # noqa: E402
from extractor.report_visuals import build_visual_summary  # noqa: E402
from tests.support.fixture_process import fixture_popen

EVIL = "<img src=x onerror=alert(1)>"
HANGUL = "[가-힣]"
ADDR = "0x601040"


def _lock(waiters, owner, word=2, addr=ADDR, name="table_mu"):
    return {"lock": name, "address": addr, "type": "pthread_mutex_t", "state_word": word, "owner_tid": owner,
            "owner_name": "worker", "waiter_tids": list(waiters)}


def _sample(k, waiters, owner, work, locks=None, threads=(900, 901, 902, 903, 904, 905)):
    return {"index": k + 1, "t_s": round(0.15 * k, 3), "locks": locks if locks is not None else [_lock(waiters, owner)],
            "owner_work": {str(owner): work} if work is not None else {}, "thread_ids": list(threads)}


def _rows():
    return [{"tid": t, "name": "worker", "top_function": "hold_for_ms", "top_source_location": "t.c:%d" % (20 + t % 3)}
            for t in (900, 901, 902, 903, 904, 905)]


def _obs(samples, cycle=False, rows=None):
    o = lc.analyse(samples, rows if rows is not None else _rows(), cycle)
    o["sampling_status"] = "OK"
    return {lc.OBS_LOCK_CONTENTION: o}


def _run(data):
    r = dr.DiagnosticRecipeRegistry.get_recipe(lc.RECIPE_LOCK_CONTENTION)
    return r.rule(r, data)


W5 = [901, 902, 903, 904, 905]
S, C, I = dr.RECIPE_STATUS_SUPPORTED, dr.RECIPE_STATUS_CONTRADICTED, dr.RECIPE_STATUS_INSUFFICIENT_EVIDENCE


class TestRule(unittest.TestCase):
    def test_contended_with_owner_handed_on_is_supported_info(self):
        owners = [900, 901, 900, 902, 903]
        r = _run(_obs([_sample(k, [w for w in W5 if w != owners[k]], owners[k], 10 + k) for k in range(5)]))
        self.assertEqual(r.status, S)
        self.assertEqual(r.details["finding_severity"], "INFO")
        self.assertTrue(r.details["non_fault"])
        self.assertEqual(r.details["finding_category"], "LOCK_CONTENTION")
        self.assertEqual(r.details["certainty_cap"], "PROBABLE")
        self.assertEqual(r.details["contended_locks"][0]["lock_name"], "table_mu")

    def test_same_owner_that_keeps_running_is_supported(self):
        r = _run(_obs([_sample(k, W5, 900, 100 + 20 * k) for k in range(5)]))
        self.assertEqual(r.status, S)
        self.assertIn("advanced", r.supporting_facts[0])

    def test_three_of_four_samples_is_the_support_bar(self):
        base = [_sample(k, W5, 900, 10 * k) for k in range(4)]
        base[1] = _sample(1, [901], 900, 10)                       # one waiter only: not queued
        self.assertEqual(_run(_obs(base)).status, S)               # 3 of 4 = 75 %
        base[2] = _sample(2, [], None, None)
        self.assertEqual(_run(_obs(base)).status, I)               # 2 of 4 = 50 %: between the bars

    def test_briefly_contended_is_contradicted(self):
        s = [_sample(0, [901, 902], 900, 5), _sample(1, [], None, None), _sample(2, [], None, None),
             _sample(3, [], None, None), _sample(4, [], None, None)]
        r = _run(_obs(s))
        self.assertEqual(r.status, C)                              # 1 of 5 = 20 % <= 40 %
        self.assertNotIn("finding_severity", r.details)

    def test_single_waiter_is_not_a_queue(self):
        r = _run(_obs([_sample(k, [901], 900, 10 * k) for k in range(5)]))
        self.assertEqual(r.status, C)

    def test_no_mutex_at_all_is_contradicted(self):
        r = _run(_obs([_sample(k, [], None, None, locks=[]) for k in range(5)]))
        self.assertEqual(r.status, C)

    def test_too_few_samples_is_insufficient(self):
        r = _run(_obs([_sample(k, W5, 900, 10 * k) for k in range(3)]))
        self.assertEqual(r.status, I)
        self.assertIn("need 4", r.confidence_basis)
        self.assertEqual(_run({}).status, I)

    def test_stalled_owner_is_not_contention(self):
        # same owner, counters frozen, waiters in every sample: a stall (deadlock / blocked-thread checks own it)
        r = _run(_obs([_sample(k, W5, 900, 77) for k in range(5)]))
        self.assertEqual(r.status, I)
        self.assertIn("no progress", r.confidence_basis)
        self.assertNotIn("finding_severity", r.details)

    def test_orphan_owner_is_not_contention(self):
        threads = (901, 902, 903, 904, 905)                         # owner 900 is not a thread of the process
        r = _run(_obs([_sample(k, W5, 900, None, threads=threads) for k in range(5)]))
        self.assertEqual(r.status, I)
        self.assertIn("not a thread of the process", r.confidence_basis)

    def test_wait_cycle_is_not_contention(self):
        owners = [900, 901, 900, 901, 900]
        r = _run(_obs([_sample(k, W5, owners[k], 10 + k) for k in range(5)], cycle=True))
        self.assertEqual(r.status, I)
        self.assertIn("deadlock", r.confidence_basis)

    def test_unlocked_word_has_no_owner(self):
        s = [_sample(k, W5, 900, 10, locks=[_lock(W5, 900, word=0)]) for k in range(5)]
        o = lc.analyse(s)
        self.assertEqual(o["mutexes"][0]["owner_tids"], [])
        self.assertEqual(_run({lc.OBS_LOCK_CONTENTION: dict(o)}).status, I)    # waiters but no owner seen: no progress

    def test_where_comes_from_the_thread_rows(self):
        o = lc.analyse([_sample(k, W5, 900, 10 * k) for k in range(5)], _rows())
        self.assertEqual(o["mutexes"][0]["owner_where"][0]["source_location"], "t.c:20")
        self.assertEqual(len(o["mutexes"][0]["waiter_where"]), 3)     # capped


class TestRegistration(unittest.TestCase):
    def test_registered_as_baseline_with_labels(self):
        self.assertIn(lc.RECIPE_LOCK_CONTENTION, dr.BASELINE_RECIPE_IDS)
        self.assertEqual(rr.category_label("LOCK_CONTENTION")[0], "threads queue on one lock (lock contention)")
        self.assertEqual(rr.recipe_label(lc.RECIPE_LOCK_CONTENTION)[0], "CONCURRENCY")

    def test_thresholds_do_not_change_the_shared_sampler_config(self):
        r = dr.DiagnosticRecipeRegistry.get_recipe(lc.RECIPE_LOCK_CONTENTION)
        self.assertEqual(repr(ts.ThreadSamplingConfig.from_thresholds(r.thresholds_and_conditions)),
                         repr(ts.ThreadSamplingConfig()))


class TestSamplerDigest(unittest.TestCase):
    def test_digest_and_owner_work(self):
        info = {"threads": [{"tid": 901, "waiting_on_lock": {"lock_address": ADDR}},
                            {"tid": 902, "waiting_on_lock": {"lock_address": ADDR}}, {"tid": 900}],
                "locks": [{"name": "m", "runtime_address": ADDR, "type_name": "pthread_mutex_t", "lock_state_word": 2,
                           "owner_tid": 900, "owner_thread_name": "w"}]}
        d = ts._lock_digest(info)
        self.assertEqual(d[0]["waiter_tids"], [901, 902])
        self.assertEqual(d[0]["owner_tid"], 900)

        def smp(i, t, ticks):
            return {"index": i, "t": t, "locks": d, "threads": {900: {"utime_ticks": ticks, "stime_ticks": 1,
                                                                      "voluntary_ctxt_switches": 2,
                                                                      "nonvoluntary_ctxt_switches": 3}}}
        series = type("S", (), {"samples": [smp(1, 10.0, 5), smp(2, 10.15, 9), {"index": 3, "t": 10.3, "threads": {},
                                                                                  "locks": None}]})()
        rows = ts.lock_wait_samples(series)
        self.assertEqual([r["owner_work"] for r in rows], [{"900": 11}, {"900": 15}])   # sample without inspection skipped
        self.assertEqual(rows[1]["t_s"], 0.15)


def _result(obs, verdict="DEGRADED", severity="INFO"):
    rid = lc.RECIPE_LOCK_CONTENTION
    f = {"category": "LOCK_CONTENTION", "severity": severity, "status": "PROBABLE_CAUSE", "description": "d",
         "recipe_ids": [rid], "subjects": ["table_mu"], "subject_details": [{"kind": "lock", "name": "table_mu"}],
         "observed": ["seen"]}
    check = {"recipe_id": rid, "status": "FAIL", "name": "n",
             "actual_observations": dict(obs, thread_summary=[
                 {"tid": 901, "name": EVIL, "states": ["S"] * 5, "waiting_on_lock": "table_mu", "top_function": "w",
                  "top_source_location": "t.c:30", "cpu_share": 0.0}]),
             }
    return {"verdict": verdict, "confidence": 0.7, "findings": [f], "not_covered": [],
            "checks_run": [{"recipe_id": rid, "status": "FAIL"}], "target": {"pid": 1, "process_name": "p"},
            "report": {"section_d_detailed_inspection_results": {"checks": [check]}}}


class TestPresentation(unittest.TestCase):
    def _res(self):
        owners = [900, 901, 900, 902, 903]
        s = [_sample(k, [w for w in W5 if w != owners[k]], owners[k], 10 + k) for k in range(5)]
        rows = _rows()
        rows[0]["name"] = EVIL
        rows[0]["top_source_location"] = EVIL
        o = lc.analyse(s, rows)
        o["mutexes"][0]["lock_name"] = EVIL
        o["sampling_status"] = "OK"
        return _result({lc.OBS_LOCK_CONTENTION: o})

    def test_text_en_ko(self):
        res = self._res()
        en = render_human_report(res, res["report"], "en")
        self.assertIn("at least 2 threads were blocked waiting for it in 5 of 5 samples", en)
        self.assertIn("the owner of the lock was different in different samples".lower(), en.lower())
        self.assertIn("slowdown, not a fault", en)
        self.assertIn("How long each hold lasts was not measured", en)
        self.assertNotRegex(en, HANGUL)
        ko = render_human_report(res, res["report"], "ko")
        self.assertIn("5번의 샘플 중 5번에서 2개 이상의 스레드가 이 락을 기다렸습니다", ko)

    def test_picture_is_escaped_and_complete(self):
        res = self._res()
        for lang in ("en", "ko"):
            h = build_visual_summary(res, res["report"], lang)
            self.assertNotIn("<script", h)
            self.assertNotIn(EVIL, h)
            self.assertNotRegex(h, r"<[^>]*\son[a-z]+\s*=")        # no event-handler attribute in any tag
            if lang == "en":
                self.assertNotRegex(h, HANGUL)
            self.assertIn("&lt;img src=x onerror=alert(1)&gt;", h)
            self.assertIn("dsv-smp", h)                             # per-sample waiter strip
            self.assertIn("dsv-chip-no", h)                         # hold time: not observed
            self.assertNotIn("in the cycle", h)                         # waiters are not "in a cycle"
        en = build_visual_summary(res, res["report"], "en")
        self.assertIn("Where the lock is held", en)
        self.assertIn("Threads waiting for it", en)
        self.assertIn("Not observed: how long each hold lasts.", en)

    def test_no_picture_without_evidence(self):
        self.assertEqual(lc.lock_contention_finding_viz(type("L", (), {"i": 0})(), {}, None), "")


TARGETS = os.path.join(ROOT, "benchmarks", "diagnosis_accuracy", "targets")


@unittest.skipUnless(shutil.which("gcc") and sys.platform.startswith("linux"), "gcc / Linux needed")
class TestLiveTargets(unittest.TestCase):
    """One diagnose per target (a few seconds each)."""

    def _run(self, name, symptom="the process feels slow, check for lock problems"):
        from extractor.expert_diagnostic_engine import diagnose
        tmp = tempfile.mkdtemp(prefix="lkc_")
        self.addCleanup(shutil.rmtree, tmp, True)
        exe = os.path.join(tmp, name)
        subprocess.run(["gcc", "-g", "-O0", "-pthread", os.path.join(TARGETS, name + ".c"), "-o", exe], check=True)
        p = fixture_popen([exe], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        self.addCleanup(p.wait)
        self.addCleanup(p.kill)
        self.assertEqual(p.stdout.readline().strip(), b"READY")
        time.sleep(0.3)
        r = diagnose(p.pid, None, symptom, corpus_dir=tmp).to_dict()
        with open(r["report_path"]) as fh:
            return r, json.load(fh)

    def test_convoy_is_degraded_not_a_fault(self):
        r, _ = self._run("lock_convoy")
        self.assertEqual(r["verdict"], "DEGRADED", r["summary"])
        self.assertEqual([(x["category"], x["severity"]) for x in r["findings"]], [("LOCK_CONTENTION", "INFO")])
        self.assertIn("table_mu", r["findings"][0]["subjects"])

    def test_ordinary_contention_stays_healthy(self):
        r, _ = self._run("ok_contention")
        # the message carries what could not be decided: this live check has failed intermittently in long runs
        why = [(x.get("kind"), x.get("item"), x.get("reason")) for x in r.get("not_covered") or []
               if x.get("kind") != "recipes_not_planned"]
        self.assertEqual(r["verdict"], "HEALTHY", f"{r['summary']} | not_covered={why} | "
                                                  f"blocking={(r.get('healthy_scope') or {}).get('blocking')}")


if __name__ == "__main__":
    unittest.main()

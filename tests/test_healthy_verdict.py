"""HEALTHY verdict of diagnose() (RULE_5B_HEALTHY_WITHIN_BASELINE_SCOPE, docs/HEALTHY_VERDICT.md).

Real processes, fixtures compiled at test time (gcc -g -O0, no architecture-specific code), children killed:
* healthy idle fixture -> HEALTHY, healthy_scope lists every baseline check and what was not checked;
* the same fixture with mutex-owner decoding patched to unsupported -> INCONCLUSIVE (a baseline check that could not
  answer its question for a target-support reason blocks HEALTHY);
* a healthy fixture whose heap is above the baseline walk cap -> HEALTHY with heap integrity listed as not checked;
* an unreadable / nonexistent PID -> INCONCLUSIVE, never healthy;
* each benchmark defect kind (deadlock, spin, leak, overrun) with the generic symptom: its baseline check still
  FAILs, the finding is produced, the verdict is not HEALTHY;
* the human summary (en, ko) of the healthy case states "healthy within the checked scope" and what was not
  checked in its first sentence; CLI and MCP pass healthy_scope through;
plus rule-level unit tests (no process) for every blocking condition.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest import mock

from extractor import healthy_verdict as hv
from extractor import watch_session as ws
from extractor.diagnostic_recipes import (
    BASELINE_RECIPE_IDS, RECIPE_STATUS_CONTRADICTED, RECIPE_STATUS_INSUFFICIENT_EVIDENCE, DiagnosticRecipeRegistry,
)
from extractor.expert_diagnostic_engine import diagnose
from extractor.human_report import render_human_report
from extractor.target_abi import FEATURE_MUTEX_OWNER, SUPPORT_NOT_SUPPORTED_ON_TARGET, SupportDecision

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "benchmarks", "diagnosis_accuracy"))
import run_benchmark as rb  # noqa: E402
from tests.support.fixture_process import fixture_popen

GENERIC = "general health check"

# acceptor thread parked in poll() on a pipe nobody writes, main thread in pause(): an idle server
IDLE_C = r"""
#define _GNU_SOURCE
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
static int lsn[2];
static void *acceptor(void *a) { struct pollfd p = { .fd = lsn[0], .events = POLLIN }; (void)a;
  pthread_setname_np(pthread_self(), "acceptor"); for (;;) poll(&p, 1, -1); return 0; }
int main(void) { pthread_t t; pipe(lsn); pthread_create(&t, 0, acceptor, 0); usleep(300000);
  printf("READY\n"); fflush(stdout); for (;;) pause(); }
"""

# ~24 MiB of live 4 KiB blocks in the main arena (above the 8 MiB baseline heap-walk cap), then idle; no growth
BIGHEAP_C = r"""
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define N 6144
static void *g_blocks[N];
int main(void) { for (int i = 0; i < N; i++) { g_blocks[i] = malloc(4000); memset(g_blocks[i], i & 0xff, 4000); }
  printf("READY\n"); fflush(stdout); for (;;) pause(); }
"""

_real_check_support = ws.check_support


def _owner_unsupported(abi, feature):
    if feature == FEATURE_MUTEX_OWNER:
        return SupportDecision(feature, SUPPORT_NOT_SUPPORTED_ON_TARGET, "not supported on this target (patched for test)")
    return _real_check_support(abi, feature)


def _gt(target_id):
    return next(g for g in rb.load_ground_truth() if g["id"] == target_id)


@unittest.skipUnless(shutil.which("gcc"), "gcc not available: cannot compile real-process fixtures")
class TestHealthyVerdictRealProcesses(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="healthy_")
        cls.addClassCleanup(shutil.rmtree, cls.tmp, True)
        cls.corpus = os.path.join(cls.tmp, "corpus")
        cls.bins = {}
        for name, src in (("idle", IDLE_C), ("bigheap", BIGHEAP_C)):
            c = os.path.join(cls.tmp, name + ".c")
            with open(c, "w") as fh:
                fh.write(src)
            out = os.path.join(cls.tmp, name)
            subprocess.run(["gcc", "-g", "-O0", "-Wl,--build-id=sha1", c, "-o", out, "-pthread"], check=True)
            cls.bins[name] = out

    def _launch(self, name):
        proc = fixture_popen([self.bins[name]], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL)

        def _kill():
            try:
                proc.kill()
            except OSError:
                pass
            proc.wait()
            proc.stdout.close()
        self.addCleanup(_kill)
        line = proc.stdout.readline()  # blocks until READY (the fixture prints it once, in its steady state)
        self.assertIn(b"READY", line)
        time.sleep(0.3)
        self.assertIsNone(proc.poll(), "fixture exited prematurely")
        return proc

    def _diag(self, name, symptom=GENERIC, **kw):
        proc = self._launch(name)
        return diagnose(proc.pid, self.bins[name], symptom, corpus_dir=self.corpus, **kw).to_dict()

    def _assert_healthy(self, d):
        hs = d["healthy_scope"]
        self.assertEqual(d["verdict"], "HEALTHY", (hs.get("blocking"), d["not_covered"]))
        self.assertTrue(hs["healthy"])
        self.assertEqual(hs["blocking"], [])
        self.assertEqual(hs["rule"], hv.HEALTHY_RULE_ID)
        self.assertEqual(d["findings"], [])
        self.assertEqual({c["recipe_id"] for c in hs["checked"]}, set(BASELINE_RECIPE_IDS))
        self.assertFalse([c for c in d["checks_run"] if c["status"] == "FAIL"])
        self.assertFalse(any(n["kind"] in hv.BLOCKING_KINDS for n in d["not_covered"]), d["not_covered"])
        self.assertIn("outside_baseline", {x["kind"] for x in hs["not_checked"]})
        self.assertTrue(d["summary"].startswith("Verdict HEALTHY: healthy within the checked scope"), d["summary"])
        self.assertIn("Not checked:", d["summary"])
        return hs

    def test_idle_fixture_is_healthy_with_scope(self):
        d = self._diag("idle", include_report=True)
        hs = self._assert_healthy(d)
        # the idle waits are listed as not judged, never as a pass of the wait itself
        lw = [x for x in hs["not_checked"] if x["kind"] == "long_wait_not_judged"]
        self.assertTrue(lw, hs["not_checked"])
        self.assertIn("acceptor", lw[0]["item"])
        self.assertTrue(any(n["kind"] == "long_wait_not_judged" for n in d["not_covered"]))
        # the saved/inline report agrees with the result
        self.assertEqual(d["report"]["section_a_executive_summary"]["overall_result"], "HEALTHY")
        self.assertEqual(d["report"]["section_a_executive_summary"]["decision_rule_id"], hv.HEALTHY_RULE_ID)
        self.assertTrue(d["report"]["healthy_scope"]["healthy"])
        # human summary: first sentence = healthy within scope + what was not checked (en, ko); glossary has it too
        for lang, healthy_txt, nc_txt, gloss in (
                ("en", "is healthy within the checked scope", "Not checked:", "healthy = every baseline check"),
                ("ko", "점검한 범위 안에서 정상입니다", "점검하지 못한 것:", "정상 = 모든 기본")):
            text = render_human_report(d, d.get("report"), lang=lang)
            first = text.split("\n## ", 2)[1].split("\n\n")[2].split("\n")[0]   # after the verdict line
            self.assertIn(healthy_txt, first, text)
            self.assertIn(nc_txt, first)
            self.assertIn("acceptor", first)
            self.assertIn(gloss, text)
            self.assertNotIn("could not decide" if lang == "en" else "판단 불가입니다", first)

    def test_lock_owner_unsupported_is_not_healthy(self):
        # The lock-owner support check runs in extractor.inspection.threads since the IMP-017 cleanup; patch it
        # there (and keep the watch_session re-export patched for any remaining caller).
        from extractor.inspection import threads as _threads
        with mock.patch.object(_threads, "check_support", _owner_unsupported), \
                mock.patch.object(ws, "check_support", _owner_unsupported):
            d = self._diag("idle")
        hs = d["healthy_scope"]
        self.assertEqual(d["verdict"], "INCONCLUSIVE", hs)
        self.assertFalse(hs["healthy"])
        blocked = {b["item"] for b in hs["blocking"]}
        self.assertTrue(blocked & {"RECIPE_POTENTIAL_DEADLOCK_PATTERNS", "RECIPE_SUSPICIOUS_LOCK_OWNERSHIP",
                                   "RECIPE_LONG_RUNNING_BLOCKED_THREADS"}, hs["blocking"])
        self.assertTrue(any(n["kind"] == "unsupported_on_target" for n in d["not_covered"]))
        self.assertNotIn("healthy within", d["summary"])

    def test_heap_above_baseline_cap_is_healthy_with_heap_integrity_not_checked(self):
        d = self._diag("bigheap")
        hs = self._assert_healthy(d)
        heap = [x for x in hs["not_checked"] if x["kind"] == "integrity_not_checked"]
        self.assertTrue(heap, hs["not_checked"])
        self.assertIn("heap integrity", heap[0]["label"])
        self.assertIn("baseline walk cap", heap[0]["label"])
        self.assertIn("heap integrity", d["summary"])
        hm = [c for c in d["checks_run"] if c["recipe_id"] == "RECIPE_HEAP_METADATA_CORRUPTION"]
        self.assertTrue(hm and all(c["status"] == "INCONCLUSIVE" for c in hm), hm)  # not turned into a pass

    def test_nonexistent_and_unreadable_pid_are_inconclusive(self):
        with open("/proc/sys/kernel/pid_max") as fh:
            dead = int(fh.read()) + 1000
        pids = [dead] + ([2] if os.geteuid() != 0 and os.path.isdir("/proc/2") else [])
        for pid in pids:
            with self.subTest(pid=pid):
                d = diagnose(pid, corpus_dir=self.corpus).to_dict()
                self.assertEqual(d["verdict"], "INCONCLUSIVE")
                self.assertFalse(d["healthy_scope"]["healthy"])
                self.assertIn("target_unreadable", {b["kind"] for b in d["healthy_scope"]["blocking"]})

    def test_cli_and_mcp_pass_healthy_scope_through(self):
        import scripts.mcp_server as mcp_srv
        proc = self._launch("idle")
        mcp_out = json.loads(mcp_srv.runtime_diagnose_process(pid=proc.pid, debug_image=self.bins["idle"]))
        cli = subprocess.run([sys.executable, "-m", "extractor.cli", "diagnose", "--pid", str(proc.pid),
                              "--debug-image", self.bins["idle"], "--corpus", self.corpus, "--json"],
                             capture_output=True, text=True, cwd=ROOT, timeout=180)
        self.assertEqual(cli.returncode, 0, cli.stderr)
        cli_out = json.loads(cli.stdout)
        for out in (mcp_out, cli_out):
            self.assertEqual(out["verdict"], "HEALTHY", out["healthy_scope"])
            self.assertTrue(out["healthy_scope"]["healthy"])
            self.assertIn("healthy within the checked scope", out["human_summary"])


@unittest.skipUnless(shutil.which("gcc"), "gcc not available: cannot compile real-process fixtures")
class TestDefectFixturesStillFailTheirCheck(unittest.TestCase):
    """Each benchmark defect kind, with the generic symptom (the widest HEALTHY opportunity): the baseline check that
    owns the defect still FAILs, the finding is there, and the HEALTHY rule blocks."""

    CASES = (("deadlock_circular", "RECIPE_POTENTIAL_DEADLOCK_PATTERNS", "deadlock"),
             ("spin_flag", "RECIPE_THREAD_STATE_ANOMALIES", "busy_wait"),
             ("leak_lru_cache", "RECIPE_PROCESS_MEMORY_GROWTH", "memory_leak"),
             ("overflow_tbl", "RECIPE_HEAP_METADATA_CORRUPTION", "heap_overflow"))

    def test_each_defect_kind_fails_its_check(self):
        tmp = tempfile.mkdtemp(prefix="healthy_defects_")
        self.addCleanup(shutil.rmtree, tmp, True)
        for target, recipe, kind in self.CASES:
            with self.subTest(target=target):
                box = {}

                def fn(pid, image, symptom, corpus):
                    box["r"] = diagnose(pid, image, symptom, corpus_dir=corpus).to_dict()
                    return box["r"]
                row = rb.run_target(_gt(target), tmp, fn, symptom_mode="generic")  # builds, runs, kills
                d = box.get("r")
                self.assertIsNotNone(d, row.get("error"))
                self.assertNotEqual(d["verdict"], "HEALTHY")
                self.assertFalse(d["healthy_scope"]["healthy"])
                self.assertTrue(any(c["recipe_id"] == recipe and c["status"] == "FAIL" for c in d["checks_run"]),
                                d["checks_run"])
                self.assertTrue(any(f["category"] in rb.KIND_CATEGORIES[kind] for f in d["findings"]), d["findings"])
                self.assertIn("check_fail", {b["kind"] for b in d["healthy_scope"]["blocking"]})


def _chk(rid, status="PASS", obs=None, ti="ok"):
    return SimpleNamespace(recipe_id=rid, status=status, actual_observations=obs or {}, limitations=[],
                           missing_evidence=[], technical_interpretation=ti)


class TestHealthyRule(unittest.TestCase):
    """The rule itself, on synthetic check rows (no process)."""

    def _eval(self, checks=None, nc=None, findings=None, verdict="INCONCLUSIVE"):
        checks = [_chk(r) for r in BASELINE_RECIPE_IDS] if checks is None else checks
        return hv.evaluate(verdict=verdict, findings=findings or [], checks=checks, not_covered=nc or [],
                           baseline_ids=BASELINE_RECIPE_IDS)

    def test_all_baseline_pass_is_healthy(self):
        s = self._eval()
        self.assertTrue(s["healthy"], s["blocking"])
        self.assertEqual(s["not_checked"][-1]["kind"], "outside_baseline")

    def test_each_blocking_condition(self):
        base = [_chk(r) for r in BASELINE_RECIPE_IDS]
        cases = {
            "baseline missing": dict(checks=base[1:]),
            "baseline inconclusive": dict(checks=[_chk(BASELINE_RECIPE_IDS[0], "INCONCLUSIVE")] + base[1:]),
            "baseline error": dict(checks=[_chk(BASELINE_RECIPE_IDS[0], "ERROR")] + base[1:]),
            "baseline not applicable": dict(checks=[_chk(BASELINE_RECIPE_IDS[0], "NOT_APPLICABLE")] + base[1:]),
            "symptom check FAIL": dict(checks=base + [_chk("RECIPE_USE_AFTER_FREE", "FAIL")]),
            "finding": dict(findings=[{"category": "MEMORY_LEAK"}]),
            "fault verdict": dict(verdict="PROBABLE_FAULT"),
            "degraded verdict": dict(verdict="DEGRADED"),
            "budget exhausted": dict(nc=[{"kind": "budget_exhausted", "item": "observation budget", "reason": "x"}]),
            "baseline not run": dict(nc=[{"kind": "baseline_check_not_run", "item": "RECIPE_FD_LEAK", "reason": "x"}]),
            "stage failed": dict(nc=[{"kind": "stage_failed", "item": "run_to_completion", "reason": "x"}]),
            "abi detection": dict(nc=[{"kind": "abi_detection_failed", "item": "target ABI", "reason": "x"}]),
            "engine limitation": dict(nc=[{"kind": "limitation", "item": "engine", "reason": "x"}]),
            "unknown kind": dict(nc=[{"kind": "something_new", "item": "x", "reason": "x"}]),
            "heap byte budget": dict(checks=[c for c in base if c.recipe_id != "RECIPE_HEAP_METADATA_CORRUPTION"] + [
                _chk("RECIPE_HEAP_METADATA_CORRUPTION", "INCONCLUSIVE", {"memory_integrity": {
                    "heap": {"status": "NOT_CHECKED", "not_checked_reason": "byte_budget"},
                    "globals": {"status": "COMPLETED"}, "stacks": {"status": "COMPLETED"}}})]),
            "heap cap but globals not run": dict(checks=[c for c in base if c.recipe_id != "RECIPE_HEAP_METADATA_CORRUPTION"] + [
                _chk("RECIPE_HEAP_METADATA_CORRUPTION", "INCONCLUSIVE", {"memory_integrity": {
                    "heap": {"status": "NOT_CHECKED", "not_checked_reason": "above_baseline_cap"},
                    "globals": {"status": "NOT_RUN"}, "stacks": {"status": "COMPLETED"}}})]),
        }
        for name, kw in cases.items():
            with self.subTest(name):
                s = self._eval(**kw)
                self.assertFalse(s["healthy"], s)
                self.assertTrue(s["blocking"])

    def test_scope_limits_do_not_block(self):
        base = [c for c in (_chk(r) for r in BASELINE_RECIPE_IDS) if c.recipe_id != "RECIPE_HEAP_METADATA_CORRUPTION"]
        heap = _chk("RECIPE_HEAP_METADATA_CORRUPTION", "INCONCLUSIVE", {"memory_integrity": {
            "heap": {"status": "NOT_CHECKED", "not_checked_reason": "above_baseline_cap",
                     "estimated_heap_bytes": 64 << 20, "baseline_cap_bytes": 8 << 20},
            "globals": {"status": "COMPLETED"}, "stacks": {"status": "COMPLETED"}}})
        nc = [{"kind": "unsupported_on_target", "item": "tcb_scan", "reason": "x"},
              {"kind": "check_inconclusive", "item": "RECIPE_USE_AFTER_FREE", "reason": "x"},
              {"kind": "check_inconclusive", "item": "RECIPE_HEAP_METADATA_CORRUPTION", "reason": "cap"},
              {"kind": "integrity_not_checked", "item": "memory_integrity", "reason": "cap"},
              {"kind": "long_wait_not_judged", "item": "worker (tid 7)", "reason": "read"},
              {"kind": "recipes_not_planned", "item": "RECIPE_DOUBLE_FREE", "reason": "x"}]
        s = self._eval(checks=base + [heap, _chk("RECIPE_USE_AFTER_FREE", "INCONCLUSIVE")], nc=nc)
        self.assertTrue(s["healthy"], s["blocking"])
        kinds = [x["kind"] for x in s["not_checked"]]
        self.assertEqual(kinds[0], "integrity_not_checked")  # most consequential first
        for k in ("long_wait_not_judged", "unsupported_on_target", "symptom_checks_without_result", "outside_baseline"):
            self.assertIn(k, kinds)
        self.assertEqual(kinds.count("integrity_not_checked"), 1)
        self.assertIn("64.0 MiB", s["not_checked"][0]["label"])

    def test_double_free_check_skipped_for_the_heap_cap_is_a_scope_limit(self):
        self.assertIn("RECIPE_DOUBLE_FREE", BASELINE_RECIPE_IDS)
        base = [_chk(r) for r in BASELINE_RECIPE_IDS if r != "RECIPE_DOUBLE_FREE"]
        capped = {"free_list_repeats": {"status": "NOT_CHECKED", "findings": [],
                                        "heap_not_checked_reason": "above_baseline_cap"}}
        s = self._eval(checks=base + [_chk("RECIPE_DOUBLE_FREE", "INCONCLUSIVE", capped)])
        self.assertTrue(s["healthy"], s["blocking"])
        item = [x for x in s["not_checked"] if x["kind"] == "double_free_not_checked"]
        self.assertTrue(item and "baseline walk cap" in item[0]["label"], s["not_checked"])
        for name, obs in (("byte budget", {"free_list_repeats": {"status": "NOT_CHECKED", "findings": [],
                                                                 "heap_not_checked_reason": "byte_budget"}}),
                          ("lists not walked completely", {"free_list_repeats": {"status": "INCOMPLETE",
                                                                                "findings": []}}),
                          ("unsupported allocator", {"free_list_repeats": {"status": "UNSUPPORTED", "findings": []}})):
            with self.subTest(name):
                s = self._eval(checks=base + [_chk("RECIPE_DOUBLE_FREE", "INCONCLUSIVE", obs)])
                self.assertFalse(s["healthy"])
                self.assertEqual(s["blocking"][0]["item"], "RECIPE_DOUBLE_FREE")

    def test_outside_baseline_says_what_the_heap_walk_cannot_see(self):
        # use-after-free and double free are looked for by baseline checks now (RECIPE_FREED_MEMORY_USE,
        # RECIPE_DOUBLE_FREE); the label must not claim they are not looked for
        en, ko = hv.OUTSIDE_BASELINE
        self.assertNotIn("use-after-free, double free, data races", en)
        self.assertIn("data races and program-logic errors", en)
        self.assertIn("re-allocated in between", en)
        self.assertNotRegex(en, "[가-힣]")
        self.assertIn("데이터 레이스", ko)

    def test_symptom_question_needs_a_completed_check(self):
        # stage 1 verification scope: the categories a specific symptom asks about are answered by a PASS check
        base = [_chk(r) for r in BASELINE_RECIPE_IDS]

        def ev(cats, checks=None, nc=None):
            return hv.evaluate(verdict="INCONCLUSIVE", findings=[], checks=base if checks is None else checks,
                               not_covered=nc or [], baseline_ids=BASELINE_RECIPE_IDS, symptom_categories=cats)

        # answered by a baseline check of the category (memory growth / deadlock): unchanged
        for cats in (["MEMORY_LEAK"], ["DEADLOCK_INDICATORS"], ["LOCK_CONTENTION", "DEADLOCK_INDICATORS"], [], None):
            with self.subTest(cats=cats):
                self.assertTrue(ev(cats)["healthy"], ev(cats)["blocking"])
        # a category whose only checks reached no result: INCONCLUSIVE with the reason stated
        s = ev(["UNEXPECTED_STATE_TRANSITIONS"],
               checks=base + [_chk("RECIPE_STATE_TRANSITION_VIOLATIONS", "INCONCLUSIVE")])
        self.assertFalse(s["healthy"])
        gap = [b for b in s["blocking"] if b["kind"] == "symptom_question_unanswered"]
        self.assertEqual([b["item"] for b in gap], ["UNEXPECTED_STATE_TRANSITIONS"])
        self.assertIn("RECIPE_STATE_TRANSITION_VIOLATIONS INCONCLUSIVE", gap[0]["reason"])
        # ... or that could not run in this mode
        s = ev(["UNEXPECTED_STATE_TRANSITIONS"],
               nc=[{"kind": "unsupported_in_mode", "item": "RECIPE_STATE_TRANSITION_VIOLATIONS",
                    "capability": "caller_specification", "reason": "x"}])
        self.assertFalse(s["healthy"])
        self.assertIn("not supported in this mode", s["blocking"][0]["reason"])
        # the same check with a clear result answers it
        s = ev(["UNEXPECTED_STATE_TRANSITIONS"], checks=base + [_chk("RECIPE_STATE_TRANSITION_VIOLATIONS")])
        self.assertTrue(s["healthy"], s["blocking"])
        # a category no recipe looks at is not a question this tool can be asked
        self.assertTrue(ev(["NO_SUCH_CATEGORY"])["healthy"])

    def test_unsupported_feature_of_a_baseline_check_blocks(self):
        base = [_chk(r) for r in BASELINE_RECIPE_IDS if r != "RECIPE_POTENTIAL_DEADLOCK_PATTERNS"]
        s = self._eval(checks=base + [_chk("RECIPE_POTENTIAL_DEADLOCK_PATTERNS", "INCONCLUSIVE")],
                       nc=[{"kind": "unsupported_on_target", "item": "RECIPE_POTENTIAL_DEADLOCK_PATTERNS",
                            "reason": "not checked: lock-owner decoding is not supported on this target"}])
        self.assertFalse(s["healthy"])
        self.assertEqual(s["blocking"][0]["item"], "RECIPE_POTENTIAL_DEADLOCK_PATTERNS")


class TestLongWaitRecipeDecision(unittest.TestCase):
    """RECIPE_LONG_RUNNING_BLOCKED_THREADS clears only the lock-wait question, and only when it was fully observed."""

    LW = [{"tid": 7, "name": "worker", "syscall": "read", "wait_kind": "read", "waited_at_least_sec": 0.7}]

    def _data(self, **over):
        d = {"thread_sampling": {"status": "OK", "window_sec": 0.7}, "threads_healthy": True,
             "long_wait_threads": self.LW, "long_wait_findings": ["worker stayed in read"], "stalled_lock_waits": [],
             "blocked_threads": [], "blocked_duration_sec": 0.0}
        d.update(over)
        return d

    def _eval(self, data):
        return DiagnosticRecipeRegistry.evaluate_recipe("RECIPE_LONG_RUNNING_BLOCKED_THREADS", data)

    def test_complete_observation_contradicts_with_long_wait_not_judged(self):
        r = self._eval(self._data())
        self.assertEqual(r.status, RECIPE_STATUS_CONTRADICTED, r.confidence_basis)
        self.assertEqual(r.details["expectation"], "UNKNOWN")
        self.assertEqual(r.details["long_waits_not_judged"][0]["name"], "worker")
        self.assertIn("cannot determine whether expected", r.confidence_basis)
        self.assertFalse(r.supporting_facts)

    def test_incomplete_observation_stays_insufficient(self):
        for name, over in (("owner unsupported", {"lock_owner_unsupported": True}),
                           ("sampling unusable", {"thread_sampling": {"status": "INSUFFICIENT_SAMPLES"}}),
                           ("incomplete lock graph", {"incomplete_lock_graph": True}),
                           ("threads not healthy", {"threads_healthy": None})):
            with self.subTest(name):
                self.assertEqual(self._eval(self._data(**over)).status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)


if __name__ == "__main__":
    unittest.main()

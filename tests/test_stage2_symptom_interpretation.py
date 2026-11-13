"""Stage 2: the same problem described in different words gives the same investigation plan.

Pure tests: plan construction needs no live process (InvestigationPlanner.create_plan accepts no target
assessment).  The paraphrase groups live in tests/data/symptom_paraphrases.json (development set) and
tests/data/symptom_paraphrases_heldout.json (held out: not looked at while the classifier was tuned).

Roadmap metric "planned-check agreement of rephrased sentences" = fraction of phrasings (reference excluded) whose
set of planned checks equals the reference phrasing's set.  Baseline with the unchanged keyword classifier,
recorded before the fix: development 86/141 = 61.0 %, held-out 32/51 = 62.7 %.
Run with ``-s`` to see the per-group table.
"""

import argparse
import json
import os
import re
import sys
import tempfile
import types
import unittest
from unittest import mock

from extractor.expert_diagnostic_engine import (
    DiagnoseResult, ExpertDiagnosticEngine, InvestigationPlanner, ProblemClassifier,
)
from extractor import symptom_interpretation as si
from extractor.human_report import render_human_report

DATA = os.path.join(os.path.dirname(__file__), "data")


def _load(name):
    with open(os.path.join(DATA, name), encoding="utf-8") as fh:
        return json.load(fh)["groups"]


DEV = _load("symptom_paraphrases.json")
HELD = {g["id"]: g["phrases"] for g in _load("symptom_paraphrases_heldout.json")}

_CLASSIFIER = ProblemClassifier()
_PLANNER = InvestigationPlanner()


def plan_checks(text, fields=None):
    """The set of recipe ids the plan for this symptom contains (no live process involved)."""
    cl = _CLASSIFIER.classify(text, fields)
    return frozenset(s.recipe_id for s in _PLANNER.create_plan(cl, None).steps)


BROAD = plan_checks("general health check")


class ParaphraseGroups(unittest.TestCase):
    def test_every_group_agrees_with_its_reference_plan(self):
        table, fails = [], []
        tot_dev = [0, 0]
        tot_held = [0, 0]
        for g in DEV:
            ref = plan_checks(g["phrases"][0])
            dev_ok = [p for p in g["phrases"][1:] if plan_checks(p) == ref]
            held = HELD[g["id"]]
            held_ok = [p for p in held if plan_checks(p) == ref]
            tot_dev[0] += len(dev_ok); tot_dev[1] += len(g["phrases"]) - 1
            tot_held[0] += len(held_ok); tot_held[1] += len(held)
            table.append(f"{g['id']:22s} dev {len(dev_ok)}/{len(g['phrases']) - 1}  held-out {len(held_ok)}/{len(held)}")
            fails += [(g["id"], p) for p in g["phrases"][1:] + held if plan_checks(p) != ref]
        print("\nplanned-check agreement per group\n" + "\n".join(table))
        print(f"TOTAL dev {tot_dev[0]}/{tot_dev[1]} = {tot_dev[0] / tot_dev[1]:.3f}   "
              f"held-out {tot_held[0]}/{tot_held[1]} = {tot_held[0] / tot_held[1]:.3f}")
        self.assertEqual(fails, [], "phrasings whose plan differs from the group reference")

    def test_every_phrasing_gets_the_groups_symptom_class(self):
        wrong = []
        for g in DEV:
            for p in g["phrases"] + HELD[g["id"]]:
                r = si.interpret_symptom(p)
                if (r.symptom_class, r.understood) != (g["expected_class"], True):
                    wrong.append((g["id"], p, r.symptom_class, r.reason))
        self.assertEqual(wrong, [])

    def test_groups_cover_every_class_and_have_enough_phrasings(self):
        self.assertEqual({g["expected_class"] for g in DEV}, set(si.CLASSES))
        for g in DEV:
            n = len(g["phrases"]) + len(HELD[g["id"]])
            self.assertTrue(8 <= n <= 14, (g["id"], n))
            self.assertTrue(any(re.search("[가-힣]", p) for p in g["phrases"] + HELD[g["id"]]), g["id"])
            self.assertTrue(any(not re.search("[가-힣]", p) for p in g["phrases"] + HELD[g["id"]]), g["id"])

    def test_known_misclassification_memory_growth_is_not_state_inconsistency(self):
        cl = _CLASSIFIER.classify("memory usage of this process keeps growing")
        self.assertEqual(cl.primary_category, "MEMORY_LEAK")
        self.assertEqual(cl.symptom_class, "memory_growth")
        self.assertIn("RECIPE_HEAP_GROWTH", plan_checks("memory usage of this process keeps growing"))

    def test_precedence_and_word_boundaries(self):
        c = lambda t: si.interpret_symptom(t).symptom_class
        self.assertEqual(c("file descriptor leak"), "fd_leak")          # "leak" there is not a memory leak
        self.assertEqual(c("it leaks threads"), "thread_growth")
        self.assertEqual(c("glibc aborts with double free detected"), "double_free")  # not a generic crash
        self.assertEqual(c("Use-After-Free in handler()"), "use_after_free")
        self.assertEqual(c("메모리누수"), "memory_growth")                # no spaces
        self.assertEqual(c("메모리가 누수되는 것 같아요"), "memory_growth")  # particle between the words
        self.assertEqual(c("the process is hanging"), "hang_deadlock")  # inflections match (stem)
        self.assertNotEqual(c("the chain is long"), "hang_deadlock")   # a word inside a word is not a hit
        self.assertEqual(c("the stackoverflow answer"), si.NOT_UNDERSTOOD_CLASS)


class Confidence(unittest.TestCase):
    LOW_TEXTS = {
        "no_match": ["hello", "프로세스가 이상해요", "something is weird about this"],
        "weak_evidence": ["lock", "mutex"],
        "conflicting_classes": ["the process hangs and memory keeps growing", "it is slow and crashes",
                                "프로세스가 멈추고 메모리도 계속 늘어요"],
    }

    def test_definition(self):
        # HIGH <=> best >= MIN_CLASS_SCORE and best >= DOMINANCE * runner-up
        self.assertEqual(si.classify_scores({})[:3], (None, si.CONF_LOW, si.REASON_NO_MATCH))
        self.assertEqual(si.classify_scores({"a": 1.0})[:3], (None, si.CONF_LOW, si.REASON_WEAK))
        self.assertEqual(si.classify_scores({"a": 2.0, "b": 2.0})[:3], (None, si.CONF_LOW, si.REASON_CONFLICT))
        self.assertEqual(si.classify_scores({"a": 3.0, "b": 2.0})[:3], (None, si.CONF_LOW, si.REASON_CONFLICT))
        cls, level, reason, conf, _ = si.classify_scores({"a": 4.0, "b": 2.0})
        self.assertEqual((cls, level, reason), ("a", si.CONF_HIGH, si.REASON_OK))
        self.assertTrue(0.0 < conf <= 0.95)

    def test_low_confidence_falls_back_to_the_broad_plan(self):
        for reason, texts in self.LOW_TEXTS.items():
            for t in texts:
                with self.subTest(text=t):
                    r = si.interpret_symptom(t)
                    self.assertEqual((r.confidence_level, r.reason, r.understood), (si.CONF_LOW, reason, False))
                    self.assertTrue(r.broad_plan)
                    cl = _CLASSIFIER.classify(t)
                    self.assertTrue(cl.is_vague)
                    self.assertFalse(cl.understood)
                    self.assertEqual(plan_checks(t), BROAD)
                    self.assertGreater(len(BROAD), len(plan_checks("the process hangs")))
                    self.assertNotEqual(plan_checks(t), plan_checks("memory usage keeps growing"))

    def test_clear_text_and_explicit_health_check_are_understood(self):
        for t in ("memory usage keeps growing", "the process hangs", "general health check", "", "프로세스 상태를 점검해줘"):
            with self.subTest(text=t):
                r = si.interpret_symptom(t)
                self.assertTrue(r.understood)
                self.assertEqual(r.confidence_level, si.CONF_HIGH)

    def test_plan_rationale_and_session_state_say_so(self):
        with tempfile.TemporaryDirectory() as tmp:
            sess = ExpertDiagnosticEngine(corpus_dir=tmp).start_investigation(problem_statement="hello", pid=None)
            sess._step_classify()
            res = sess.classification_result
            self.assertFalse(res.understood)
            self.assertEqual(res.interpretation["reason"], si.REASON_NO_MATCH)
            ev = [e for e in sess.timeline if e.get("event_type") == "PROBLEM_CLASSIFIED" or "PROBLEM_CLASSIFIED" in str(e)]
            self.assertTrue(ev and "understood" in json.dumps(ev[0], default=str))
        plan = _PLANNER.create_plan(_CLASSIFIER.classify("hello"), None)
        self.assertIn("not understood specifically", plan.plan_rationale)

    def test_report_states_it_in_english_and_korean(self):
        res = DiagnoseResult().to_dict()
        res["symptom_interpretation"] = si.interpret_symptom("hello").to_dict()
        en = render_human_report(res, lang="en")
        ko = render_human_report(res, lang="ko")
        self.assertIn("not understood specifically", en)
        self.assertIn("broad plan", en)
        self.assertIn("no known symptom wording was recognised", en)
        self.assertIn("구체적으로 이해하지 못했습니다", ko)
        self.assertIn("넓은 계획", ko)
        note = [ln for ln in ko.splitlines() if "넓은 계획" in ln][0]
        self.assertIsNone(re.search("[A-Za-z]", note), "Korean note must not contain English words")
        conflict = si.interpret_symptom("the process hangs and memory keeps growing").to_dict()
        res["symptom_interpretation"] = conflict
        self.assertIn("several different problems", render_human_report(res, lang="en"))
        # understood symptom: no note
        res["symptom_interpretation"] = si.interpret_symptom("the process hangs").to_dict()
        self.assertNotIn("not understood specifically", render_human_report(res, lang="en"))
        # a result without the field (older saved results) renders as before
        self.assertNotIn("not understood specifically", render_human_report(DiagnoseResult().to_dict(), lang="en"))

    def test_diagnose_result_carries_the_interpretation_field(self):
        self.assertEqual(DiagnoseResult().to_dict()["symptom_interpretation"], {})


class StructuredFields(unittest.TestCase):
    def test_kind_takes_precedence_over_text(self):
        r = si.interpret_symptom("memory usage keeps growing", {"symptom_kind": "hang_deadlock"})
        self.assertEqual((r.symptom_class, r.source, r.understood), ("hang_deadlock", si.SOURCE_STRUCTURED, True))
        self.assertEqual(r.text_class, "memory_growth")
        self.assertEqual(plan_checks("memory usage keeps growing", {"symptom_kind": "hang_deadlock"}),
                         plan_checks("the process hangs"))

    def test_kind_rescues_text_that_is_not_understood(self):
        f = {"symptom_kind": "memory_growth"}
        self.assertEqual(plan_checks("hello", f), plan_checks("memory usage keeps growing"))
        self.assertEqual(plan_checks(None, f), plan_checks("memory usage keeps growing"))

    def test_free_text_alone_is_unchanged_by_empty_fields(self):
        for t in ("memory usage keeps growing", "hello", "general health check", ""):
            self.assertEqual(plan_checks(t, None), plan_checks(t, {}))
            self.assertEqual(plan_checks(t, None), plan_checks(t, {"symptom_kind": None, "related_objects": []}))

    def test_other_fields_do_not_change_a_clear_plan_and_area_helps_without_text(self):
        base = plan_checks("memory usage keeps growing")
        f = {"symptom_frequency": "intermittent", "symptom_duration": "3 hours", "affected_area": "memory",
             "related_objects": ["g_cache", "Cache::put()", "the request queue"]}
        self.assertEqual(plan_checks("memory usage keeps growing", f), base)
        self.assertEqual(plan_checks("", {"affected_area": "memory"}), base)
        cl = _CLASSIFIER.classify("hello", f)
        self.assertIn("g_cache", cl.extracted_entities["variables"])
        self.assertIn("Cache::put", cl.extracted_entities["functions"])
        self.assertIn("the request queue", cl.extracted_entities["related_objects"])
        self.assertNotIn("the request queue", cl.extracted_entities["variables"])
        self.assertEqual(cl.interpretation["fields"]["symptom_frequency"], "intermittent")

    def test_validation(self):
        bad = [{"symptom_kind": "nonsense"}, {"symptom_frequency": "sometimes-ish"}, {"affected_area": "gpu"},
               {"related_objects": [1]}, {"related_objects": ["x"] * 21}, {"symptom_duration": "x" * 201},
               {"colour": "red"}]
        for b in bad:
            with self.subTest(b=b):
                with self.assertRaises(si.SymptomFieldError):
                    si.parse_symptom_fields(b)
        f = si.parse_symptom_fields({"symptom_kind": "Memory-Growth", "related_objects": "g_x"})
        self.assertEqual((f.symptom_kind, f.related_objects), ("memory_growth", ("g_x",)))
        self.assertIsNone(si.parse_symptom_fields({}))

    def test_diagnose_reports_invalid_fields_without_raising(self):
        from extractor.expert_diagnostic_engine import diagnose
        res = diagnose(os.getpid(), symptom_fields={"symptom_kind": "nonsense"})
        self.assertEqual(res.verdict, "INCONCLUSIVE")
        self.assertTrue(any(n["kind"] == "invalid_symptom_fields" for n in res.not_covered))

    def test_session_persistence_keeps_the_fields(self):
        from extractor.expert_diagnostic_engine import AdaptiveInvestigationSession
        with tempfile.TemporaryDirectory() as tmp:
            sess = ExpertDiagnosticEngine(corpus_dir=tmp).start_investigation(
                problem_statement="x", pid=None, symptom_fields={"symptom_kind": "fd_leak", "related_objects": ["a"]})
            back = AdaptiveInvestigationSession.from_dict(json.loads(json.dumps(sess.to_dict(), default=str)))
            self.assertEqual(back.symptom_fields, sess.symptom_fields)
            self.assertEqual(back.symptom_fields.symptom_kind, "fd_leak")


class EntryPointsAgree(unittest.TestCase):
    """The CLI, the MCP tool and the web API accept the same fields and hand the same ones to diagnose()."""

    FIELDS = {"symptom_kind": "fd_leak", "symptom_frequency": "constant", "symptom_duration": "2 days",
              "affected_area": "files", "related_objects": ["g_conn_pool", "Server::accept()"]}
    TEXT = "something is odd"

    def _capture(self):
        seen = {}

        def fake(pid, **kw):
            seen.update(kw)
            return {"success": True, "verdict": "INCONCLUSIVE"}, "summary"
        return seen, fake

    def _via_cli(self):
        from extractor import cli
        seen, fake = self._capture()
        argv = ["dynamic-state", "diagnose", "-p", "4242", "--symptom", self.TEXT, "--symptom-kind", "fd_leak",
                "--symptom-frequency", "constant", "--symptom-duration", "2 days", "--affected-area", "files",
                "--related-object", "g_conn_pool", "--related-object", "Server::accept()", "--json"]
        with mock.patch.object(sys, "argv", argv), mock.patch("extractor.human_report.diagnose_with_summary", fake):
            with self.assertRaises(SystemExit) as cm:
                with mock.patch("builtins.print"):
                    cli.main()
        self.assertEqual(cm.exception.code, 0)
        return seen

    def _via_mcp(self):
        import scripts.mcp_server as mcp_srv
        seen, fake = self._capture()
        with mock.patch("extractor.human_report.diagnose_with_summary", fake):
            out = json.loads(mcp_srv.runtime_diagnose_process(pid=4242, symptom=self.TEXT, **self.FIELDS))
        self.assertTrue(out.get("success", True), out)
        return seen

    def _via_web(self):
        from extractor.web.server import WebApiAdapter
        seen, fake = self._capture()
        adapter = WebApiAdapter(types.SimpleNamespace(expert_diagnostic_engine=None, watch_session_manager=object(), corpus_dir=tempfile.gettempdir()))
        with mock.patch("extractor.human_report.diagnose_with_summary", fake):
            out = adapter.diagnose_api({"pid": 4242, "symptom": self.TEXT, **self.FIELDS})
        self.assertTrue(out["success"], out)
        return seen

    def test_same_fields_same_plan(self):
        want = si.parse_symptom_fields(self.FIELDS)
        plans = []
        for name, via in (("cli", self._via_cli), ("mcp", self._via_mcp), ("web", self._via_web)):
            with self.subTest(entry=name):
                seen = via()
                fields = si.parse_symptom_fields(seen.get("symptom_fields"))
                self.assertEqual(fields, want)
                self.assertEqual(seen["symptom"], self.TEXT)
                plans.append(plan_checks(seen["symptom"], fields))
        self.assertEqual(len(set(plans)), 1)
        self.assertEqual(plans[0], plan_checks(self.TEXT, self.FIELDS))
        self.assertEqual(plans[0], plan_checks("file descriptor leak"))

    def test_free_text_alone_passes_no_fields_anywhere(self):
        import scripts.mcp_server as mcp_srv
        seen, fake = self._capture()
        with mock.patch("extractor.human_report.diagnose_with_summary", fake):
            mcp_srv.runtime_diagnose_process(pid=4242, symptom="memory keeps growing")
        self.assertIsNone(seen.get("symptom_fields"))

    def test_the_three_entry_points_expose_exactly_the_shared_field_names(self):
        import inspect
        import scripts.mcp_server as mcp_srv
        shared = set(si.SYMPTOM_FIELD_NAMES)
        mcp_params = set(inspect.signature(mcp_srv.runtime_diagnose_process).parameters)
        self.assertTrue(shared <= mcp_params, shared - mcp_params)
        parser = argparse.ArgumentParser()
        si.add_cli_arguments(parser)
        self.assertEqual({a.dest for a in parser._actions} - {"help"}, shared)
        # the CLI's diagnose sub-command really uses the shared definition
        from extractor import cli
        src = inspect.getsource(cli.main)
        self.assertIn("add_cli_arguments", src)
        self.assertIn("fields_from_mapping", src)

    def test_invalid_field_is_rejected_by_mcp_and_web(self):
        import scripts.mcp_server as mcp_srv
        from extractor.web.server import WebApiAdapter
        out = json.loads(mcp_srv.runtime_diagnose_process(pid=4242, symptom_kind="nonsense"))
        self.assertFalse(out["success"])
        self.assertIn("symptom_kind", json.dumps(out))
        web = WebApiAdapter(types.SimpleNamespace(expert_diagnostic_engine=None, watch_session_manager=object(), corpus_dir=tempfile.gettempdir())).diagnose_api(
            {"pid": 4242, "symptom_kind": "nonsense"})
        self.assertEqual(web["error"]["code"], "INVALID_PARAM")


if __name__ == "__main__":
    unittest.main()

"""One report path in ``runtime_export_incident_report`` and the reproducibility section.

Pure tests on saved ``diagnose()`` results (``tests/fixtures/ko_report``); nothing here touches a live process.

  * both call shapes (``investigation_id`` and ``pid``) reach the same generator
    (``incident_report.export_incident_report``) and end as a ``DiagnosticReport`` with the same sections;
  * a diagnosis exported both ways has the same verdict, findings, checks and section headings;
  * the legacy keys of the investigation-id call are still returned;
  * ``ReproducibilitySection``: model, build-ID status, recipe order and versions, timestamps, "unknown" where the engine
    recorded nothing, rendering in Markdown / HTML in en / ko (no English sentence in Korean).
"""
import gzip
import inspect
import json
import os
import re
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import extractor.expert_diagnostic_engine as ede  # noqa: E402
import extractor.incident_report as ir  # noqa: E402
import scripts.mcp_server as mcp_srv  # noqa: E402
from extractor.diagnostic_methodology import DiagnosticCheck  # noqa: E402
from extractor.diagnostic_report import DiagnosticReport  # noqa: E402
from extractor.reproducibility import (  # noqa: E402
    ReproducibilitySection, build_reproducibility, render_html, render_markdown)
from tests.test_korean_report_language import english_sentences  # noqa: E402

FIXTURES = os.path.join(ROOT, "tests", "fixtures", "ko_report")


def _load(name):
    with gzip.open(os.path.join(FIXTURES, name + ".json.gz"), "rt", encoding="utf-8") as f:
        return json.load(f)


class _Saved:
    def __init__(self, d):
        self.d = d

    def to_dict(self):
        return json.loads(json.dumps(self.d))


def _fake_session(saved):
    """An investigation session as far as the report adapter reads it, rebuilt from a saved diagnose() result."""
    report = saved["report"]
    checks = [DiagnosticCheck.from_dict(c) for c in report["section_d_detailed_inspection_results"]["checks"]]
    concl = SimpleNamespace(confidence=saved["confidence"], confidence_basis="", stop_reason=saved.get("stop_reason"),
                            diagnostic_limitations=[], missing_evidence_and_unknowns=[])
    return SimpleNamespace(
        pid=saved["target"]["pid"], companion_elf=saved["target"]["debug_image"], adapter=None, state=saved["state"],
        investigation_id=saved["investigation_id"], checks=checks, collected_evidence_records=[], conclusion=concl,
        budget_tracker=None, build_diagnostic_report=lambda: DiagnosticReport.from_dict(json.loads(json.dumps(report))))


def _export_fresh(saved, lang="en", **kw):
    original = ede.diagnose
    ede.diagnose = lambda *a, **k: _Saved(saved)
    try:
        return ir.export_incident_report(pid=saved["target"]["pid"], language=lang, **kw)
    finally:
        ede.diagnose = original


def _headings(md):
    return [ln for ln in md.splitlines() if ln.startswith("## ")]


class TestSingleGenerationPath(unittest.TestCase):
    def test_mcp_function_has_one_generation_call(self):
        src = inspect.getsource(mcp_srv.runtime_export_incident_report)
        self.assertEqual(src.count("watch_session_manager.export_incident_report("), 1)
        self.assertNotIn("sess.export_report", src)
        self.assertNotIn("build_diagnostic_report", src)

    def test_both_call_shapes_reach_the_same_generator(self):
        saved = _load("overflow_ring")
        sess = _fake_session(saved)
        calls = []
        real = ir.export_incident_report

        def spy(*a, **k):
            calls.append(k.get("session"))
            return real(*a, **k)

        eng = mcp_srv.runtime.expert_diagnostic_engine
        with mock.patch.object(ir, "export_incident_report", spy), \
                mock.patch.object(eng, "get_session", lambda i: sess if i == saved["investigation_id"] else None), \
                mock.patch.object(ede, "diagnose", lambda *a, **k: _Saved(saved)):
            by_id = json.loads(mcp_srv.runtime_export_incident_report(investigation_id=saved["investigation_id"]))
            by_pid = json.loads(mcp_srv.runtime_export_incident_report(pid=saved["target"]["pid"]))
        self.assertEqual(len(calls), 2)
        self.assertIs(calls[0], sess)
        self.assertIsNone(calls[1])
        self.assertTrue(by_id["success"] and by_pid["success"], (by_id.get("error"), by_pid.get("error")))
        self.assertEqual(_headings(by_id["report_markdown"]), _headings(by_pid["report_markdown"]))

    def test_equivalent_content_both_ways(self):
        for name in ("overflow_ring", "deadlock_circular", "leak_lru_cache"):
            for lang in ("en", "ko"):
                saved = _load(name)
                fresh = _export_fresh(saved, lang)
                stored = ir.export_incident_report(pid=saved["target"]["pid"], language=lang,
                                                   session=_fake_session(saved))
                self.assertEqual(fresh["verdict"], stored["verdict"], name)
                self.assertEqual([(f["category"], f["status"], f["subjects"]) for f in fresh["findings"]],
                                 [(f["category"], f["status"], f["subjects"]) for f in stored["findings"]], name)
                self.assertEqual(_headings(fresh["report_markdown"]), _headings(stored["report_markdown"]), name)
                for html in (fresh["report_html"], stored["report_html"]):
                    for marker in ('class="dsv"', 'id="dsv-findings"', 'id="human-summary"', 'id="reproducibility"',
                                   'id="dsv-detail"'):
                        self.assertIn(marker, html, f"{name}/{lang}: {marker}")
                self.assertEqual(sorted(fresh["reproducibility"]), sorted(stored["reproducibility"]))
                self.assertEqual([r["recipe_id"] for r in fresh["reproducibility"]["recipes"]],
                                 [r["recipe_id"] for r in stored["reproducibility"]["recipes"]])

    def test_legacy_keys_of_the_investigation_id_call(self):
        saved = _load("overflow_ring")
        sess = _fake_session(saved)
        eng = mcp_srv.runtime.expert_diagnostic_engine
        with tempfile.TemporaryDirectory() as tmp, \
                mock.patch.object(eng, "get_session", lambda i: sess):
            for fmt, ext in (("markdown", "md"), ("html", "html"), ("json", "json")):
                path = os.path.join(tmp, f"r.{ext}")
                out = json.loads(mcp_srv.runtime_export_incident_report(
                    investigation_id=saved["investigation_id"], format=fmt, output_path=path))
                self.assertTrue(out["success"], out)
                for k in ("investigation_id", "format", "output_path", "overall_verdict", "confirmed_problems",
                          "probable_problems", "checks_summary", "report"):
                    self.assertIn(k, out, k)
                self.assertEqual(out["investigation_id"], saved["investigation_id"])
                self.assertEqual(out["format"], fmt)
                self.assertEqual(out["output_path"], os.path.realpath(path) if out["output_path"] != path else path)
                self.assertTrue(os.path.exists(path))
                with open(path, encoding="utf-8") as fh:
                    body = fh.read()
                if fmt == "markdown":
                    self.assertIn("Executive Summary", body)          # the A-I appendix, as the old export had it
                    self.assertIn("## 6. Reproducibility", body)
                    self.assertEqual(out["report"], body)
                elif fmt == "html":
                    self.assertIn("<html", body.lower())
                    self.assertEqual(out["report"], body)
                else:
                    self.assertIn("section_a_executive_summary", json.loads(body))
                    self.assertIn("section_j_reproducibility", out["report"])
                self.assertEqual(set(out["checks_summary"]), {
                    "checks_total", "checks_passed", "checks_failed", "checks_inconclusive", "checks_not_executed",
                    "checks_skipped"})
            self.assertGreater(out["checks_summary"]["checks_total"], 0)

    def test_unknown_investigation_id_falls_back_to_the_pid_diagnosis(self):
        saved = _load("overflow_ring")
        eng = mcp_srv.runtime.expert_diagnostic_engine
        with mock.patch.object(eng, "get_session", lambda i: None), \
                mock.patch.object(ede, "diagnose", lambda *a, **k: _Saved(saved)):
            out = json.loads(mcp_srv.runtime_export_incident_report(investigation_id="inv_gone", pid=1234))
        self.assertTrue(out["success"])
        self.assertIs(out["investigation_found"], False)
        self.assertEqual(out["verdict"], saved["verdict"])


class TestReproducibilityModel(unittest.TestCase):
    def setUp(self):
        self.saved = _load("overflow_ring")
        self.report = self.saved["report"]

    def test_recipes_in_execution_order_with_versions_and_times(self):
        rep = build_reproducibility(self.report, self.saved)
        ran = [c for c in self.report["section_d_detailed_inspection_results"]["checks"]
               if c["status"] not in ("NOT_EXECUTED", "SKIPPED")]
        self.assertEqual([r["recipe_id"] for r in rep.recipes],
                         [c["recipe_id"] for c in sorted(ran, key=lambda c: c["start_timestamp"])])
        self.assertEqual([r["order"] for r in rep.recipes], list(range(1, len(rep.recipes) + 1)))
        by_id = {c["recipe_id"]: c["recipe_version"] for c in ran}
        self.assertEqual({r["recipe_id"]: r["recipe_version"] for r in rep.recipes}, by_id)
        self.assertIn("1.0.0", by_id.values())
        self.assertTrue(all(v for v in by_id.values()))
        self.assertTrue(all(r["started_at"] and r["ended_at"] for r in rep.recipes))
        self.assertNotIn("RECIPE_SUSPICIOUS_BOUNDARY_VALUES", [r["recipe_id"] for r in rep.recipes])  # SKIPPED: not run
        self.assertEqual(rep.observation["samples_collected"], 42)
        self.assertEqual(rep.observation["started_at"], self.report["section_b_target_context"]["investigation_start_time"])
        self.assertEqual(rep.target_arch, "aarch64")
        self.assertEqual(rep.target_libc, "glibc")                      # libc_version was not detected: not invented

    def test_build_id_status(self):
        rep = build_reproducibility(self.report, self.saved)
        self.assertEqual(rep.build_id_checks[0]["status"], "UNKNOWN")      # the fixture recorded no comparison
        self.assertEqual(rep.build_id_checks[0]["note"], "not_recorded")
        for status, p, d in (("MATCHED", "aa", "aa"), ("MISMATCHED", "aa", "bb"), ("UNKNOWN", None, "bb")):
            rpt = json.loads(json.dumps(self.report))
            rpt["section_b_target_context"]["build_id_check"] = {"status": status, "process_build_id": p, "debug_build_id": d}
            row = build_reproducibility(rpt, self.saved).build_id_checks[0]
            self.assertEqual((row["status"], row["process_build_id"], row["debug_build_id"]), (status, p, d))

    def test_unknown_where_nothing_was_recorded(self):
        rep = build_reproducibility({}, {})
        self.assertIsNone(rep.target_arch)
        self.assertIsNone(rep.target_libc)
        self.assertEqual(rep.recipes, [])
        self.assertIsNone(rep.observation["samples_collected"])
        self.assertEqual(rep.build_id_checks[0]["status"], "UNKNOWN")
        remote = build_reproducibility({}, {"target": {"host": "10.0.0.1", "transport": "ssh"}})
        self.assertIsNone(remote.target_kernel)                          # a remote kernel is not read from this host
        md = "\n".join(render_markdown(rep, "en"))
        self.assertIn("unknown", md)
        self.assertIn("알 수 없음", "\n".join(render_markdown(rep, "ko")))

    def test_model_round_trip_and_report_field(self):
        rep = build_reproducibility(self.report, self.saved)
        self.assertEqual(ReproducibilitySection.from_dict(rep.to_dict()), rep)
        dr = DiagnosticReport.from_dict(self.report)
        self.assertIsNone(dr.section_j_reproducibility)
        dr.section_j_reproducibility = rep
        back = DiagnosticReport.from_dict(json.loads(dr.to_json()))
        self.assertEqual(back.section_j_reproducibility, rep)
        self.assertIn("Reproducibility", dr.to_markdown())
        self.assertIn('id="reproducibility"', dr.to_html())
        self.assertIn("재현 정보", dr.to_markdown("ko"))

    def test_build_id_check_is_a_target_context_field(self):
        sec = json.loads(json.dumps(self.report["section_b_target_context"]))
        sec["build_id_check"] = {"status": "MATCHED", "process_build_id": "aa", "debug_build_id": "aa"}
        rpt = json.loads(json.dumps(self.report))
        rpt["section_b_target_context"] = sec
        self.assertEqual(DiagnosticReport.from_dict(rpt).to_dict()["section_b_target_context"]["build_id_check"]["status"],
                         "MATCHED")


class TestReproducibilityRendering(unittest.TestCase):
    def test_incident_report_has_the_section_in_every_rendering(self):
        saved = _load("deadlock_circular")
        for lang, title, unknown in (("en", "## 6. Reproducibility", "unknown"), ("ko", "## 6. 재현 정보", "알 수 없음")):
            out = _export_fresh(saved, lang)
            md = out["report_markdown"]
            self.assertIn(title, md)
            self.assertIn(unknown, md)
            self.assertIn("RECIPE_", md.split(title)[1])
            self.assertIn("1.0.0", md.split(title)[1])
            body = out["report_html"][out["report_html"].find("<body>"):]
            visual = body[:body.find('<details class="dsv-detail"')]
            self.assertIn('id="reproducibility"', visual)               # in the body, not in the collapsed block
            self.assertIn(f'lang="{lang}"', visual)
            self.assertEqual(out["reproducibility"]["recipes"][0]["order"], 1)
            self.assertEqual(out["verdict"], saved["verdict"])

    def test_korean_section_has_no_english_sentence_and_is_complete(self):
        for name in ("overflow_ring", "ok_idle_server", "ok_scenario_a", "uaf_jobq"):
            out = _export_fresh(_load(name), "ko")
            md_part = out["report_markdown"].split("## 6. 재현 정보")[1]
            body = out["report_html"][out["report_html"].find("<body>"):]
            html_part = body[body.find('id="reproducibility"'):body.find('<details class="dsv-detail"')]
            for label, text in (("md", md_part), ("html", html_part)):
                self.assertEqual(english_sentences(text), [], f"{name} {label}")
            for word in ("도구와 대상", "빌드 ID", "관측 구간", "실행한 레시피"):
                self.assertIn(word, md_part)
                self.assertIn(word, html_part)

    def test_english_sections_present_and_html_escaped(self):
        rep = ReproducibilitySection(
            build_id_checks=[{"module": "<b>x</b>", "debug_image": "/d", "process_build_id": "aa",
                              "debug_build_id": "bb", "status": "MISMATCHED"}],
            recipes=[{"order": 1, "recipe_id": "RECIPE_X", "recipe_version": "1.2.3", "status": "PASS",
                      "started_at": "t0", "ended_at": "t1", "samples": 5}])
        html = render_html(rep, "en")
        self.assertIn("&lt;b&gt;x&lt;/b&gt;", html)
        self.assertNotIn("<b>x</b>", html)
        self.assertIn("mismatched", html)
        self.assertNotIn("<script", html)
        md = "\n".join(render_markdown(rep, "en"))
        self.assertIn("`1.2.3`", md)
        self.assertIn("`mismatched`", md)
        self.assertIn("`5`", md)


if __name__ == "__main__":
    unittest.main()

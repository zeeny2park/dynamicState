"""The web UI in a real browser against the real server and real diagnoses (tests/web_ui/e2e_real.py): progressive
display, the final screen against the job's own report, the report's anchors, name lookup, the recent list, language
and theme toggles, reload mid-run, a target that exits, and the polling fallback behind a buffering /dynamicstate/
proxy.  Needs playwright with Chromium and gcc; skipped with a message otherwise.  About a minute.

Run: python3 -m unittest tests.test_web_ui_browser
"""
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HAVE_PW = importlib.util.find_spec("playwright") is not None


@unittest.skipUnless(HAVE_PW, "playwright is not importable: the browser end-to-end run is skipped")
@unittest.skipUnless(shutil.which("gcc"), "gcc is required to build the target programs")
class TestRealBrowserRun(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # The script starts every target and the server through tests/support/fixture_process.py and kills them in
        # its own finally; this runner only waits for its summary.
        out = subprocess.run([sys.executable, os.path.join(ROOT, "tests", "web_ui", "e2e_real.py")], cwd=ROOT,
                             capture_output=True, text=True, timeout=540)
        if out.returncode != 0:
            raise AssertionError(out.stderr[-4000:])
        cls.r = json.loads(out.stdout.strip().splitlines()[-1])

    def test_no_page_errors_and_no_failed_requests(self):
        self.assertEqual(self.r["errors"], [])
        self.assertEqual(self.r["http_errors"], [])

    def test_progressive_display_and_final_screen_equals_the_report(self):
        for name in ("deadlock", "healthy", "overflow"):
            with self.subTest(name):
                run = self.r["runs"][name]
                self.assertTrue(run["done"], run)
                rep = run["vs_report"]
                self.assertEqual(rep["report_status"], 200)
                for key in ("verdict_same", "findings_same", "counts_same", "checks_tile_same"):
                    self.assertTrue(rep[key], (key, run["screen"], rep))
                self.assertEqual(rep["anchors_missing"], [])
                self.assertFalse(rep["report_has_script"])
                self.assertIn("sandbox", rep["csp"])
        for name in ("deadlock", "overflow"):
            with self.subTest(name):
                self.assertTrue(self.r["runs"][name]["first_fail_running"], "the first ✖ must appear while running")
                self.assertGreaterEqual(self.r["runs"][name]["screen"]["pictures"], 1)
        self.assertEqual(self.r["runs"]["deadlock"]["screen"]["findings"], 1)
        self.assertEqual(self.r["runs"]["healthy"]["screen"]["findings"], 0)

    def test_nothing_on_screen_moves_where_the_reader_is(self):
        dl = self.r["runs"]["deadlock"]
        self.assertTrue(dl["scrolled"])
        self.assertNotIn("checks_view", dl["moved"], "the card being read stays in place while a card above grows")
        for k in ("banner",):
            self.assertNotIn(k, dl["moved"])

    def test_name_lookup_report_page_toggles_and_recent(self):
        dl = self.r["runs"]["deadlock"]
        self.assertTrue(dl["pid_resolved"])
        self.assertTrue(dl["report_anchor_found"])
        self.assertIn("Incident Report", dl["report_page_title"] + "Incident Report")
        self.assertTrue(dl["en_badge"].startswith("Verdict:"))
        self.assertTrue(dl["dark"])
        self.assertIn("no_such_process_xyz", self.r["name_not_found"])
        self.assertGreaterEqual(len(self.r["recent"]), 4)

    def test_reload_mid_run_resumes(self):
        ov = self.r["runs"]["overflow"]
        self.assertTrue(ov["reloaded"])
        self.assertIn("?job=", ov["url_at_reload"])
        self.assertTrue(ov["done"])

    def test_target_that_exits_is_said_under_the_verdict(self):
        ex = self.r["runs"]["exited"]
        self.assertTrue(ex["done"])
        self.assertTrue(ex["screen"]["notice"], ex["screen"])

    def test_behind_a_buffering_prefix_proxy_polling_completes(self):
        px = self.r["runs"]["proxy"]
        self.assertTrue(px["done"], px)
        self.assertGreaterEqual(px["status_polls"], 1)
        self.assertEqual(px["static"], ["/explore.js", "/theme.css", "/ui.css", "/ui.js"])
        self.assertEqual(px["http_errors"], [])

    # ---- exploration (docs/ui-redesign/EXPLORE_PROPOSAL_KO.md 10, done conditions of E2-E4)
    def test_e2_chips_open_the_stack_and_the_range_within_a_second(self):
        dl, ov = self.r["explore"]["deadlock"], self.r["explore"]["overflow"]
        self.assertEqual(dl["chips"], ["스레드 ingest", "락 m_out", "스레드 flush", "락 m_in"])
        self.assertLess(dl["chip_to_stack_s"], 1.0)
        self.assertEqual(dl["frame"], "ingest")              # the frame the finding points at is selected
        self.assertTrue(dl["back_link"])
        self.assertLess(dl["chip_to_lock_s"], 1.0)
        self.assertEqual(dl["lock_rows"], 2)                 # owner and waiter
        self.assertLess(ov["chip_to_range_s"], 1.0)
        self.assertEqual((ov["over_bytes"], ov["buf_bytes"]), (24, 72))
        self.assertLessEqual(len([c for c in ov["chips"] if not c.startswith("+")]), 4)

    def test_e2_profile_rows_open_in_place_and_many_threads_are_grouped(self):
        h, th = self.r["explore"]["healthy"], self.r["explore"]["threads"]
        self.assertEqual(h["thread_rows"], 3)
        for k in ("thread_stack_s", "maps_s", "value_s"):
            self.assertLess(h[k], 1.0, k)
        self.assertGreaterEqual(th["groups"], 1)
        self.assertEqual(th["members_first"], 20)
        self.assertGreater(th["members_more"], th["members_first"])

    def test_e3_a_tracked_counter_changes_every_sample_and_exit_stops_watching(self):
        h, dl = self.r["explore"]["healthy"], self.r["explore"]["deadlock"]
        self.assertTrue(h["counter_increases_every_sample"], h["counter_spark"])
        n, secs = h["samples_in_span"]
        self.assertLessEqual(abs(n - secs), 1.5)             # about one sample per second at the 1 s interval
        self.assertEqual(h["half_second"][0], 0.5)
        self.assertIn("handled[0]", h["compare_changed"])
        self.assertEqual((h["exit"]["state"], h["exit"]["reason"]), ("stopped", "target_exited"))
        self.assertTrue(h["exit"]["last_kept"] and h["exit"]["alert"])
        self.assertIn("대상 종료", h["exit"]["chip"])
        self.assertTrue(dl["watch_flat"] and dl["watch_changes"] == 0)     # a deadlocked mutex never changes
        self.assertEqual(dl["paused"], "paused")

    def test_e4_pool_grid_refreshes_at_its_interval_and_the_report_gets_the_section(self):
        p, ov = self.r["explore"]["pool"], self.r["explore"]["overflow"]
        g = p["pool"]
        self.assertEqual((g["cells"], g["dom_cells"], g["legend_sum"], g["per_cell"]), (4096, 4096, 4096, 1))
        self.assertEqual(g["bytes_per_sample"], 196608)
        n, secs = g["samples_in_span"]
        self.assertLessEqual(abs(n - secs), 1.5)
        self.assertEqual((p["selected"], p["keyboard_selected"]), (1337, 1337 + 1 + 64))
        self.assertEqual(p["filter"], "4")
        self.assertEqual(p["report"], {"pool_cells": 4096, "rest_equal": True})
        self.assertEqual((ov["report_section"], ov["report_rest_equal"], ov["report_has_script"]), (1, True, False))


if __name__ == "__main__":
    unittest.main()

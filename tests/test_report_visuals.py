"""The visual front section of the HTML incident report (extractor/report_visuals.py).

Synthetic results only: no process is started.  The live path is covered by tests/test_incident_report_html.py.
"""
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from extractor.report_visuals import build_visual_summary, wrap_detail  # noqa: E402

EVIL = "<script>alert(1)</script>"


def _check(rid, status, obs=None, **kw):
    c = {"check_id": "CHK_" + rid, "recipe_id": rid, "name": rid.title(), "status": status,
         "technical_rationale": "CONCURRENCY", "technical_interpretation": kw.pop("interp", "Check executed"),
         "limitations": [], "missing_evidence": [], "duration_seconds": 0.01, "actual_observations": obs or {}}
    c.update(kw)
    return c


def _result(verdict, findings, checks, not_covered=()):
    report = {"section_d_detailed_inspection_results": {"checks": checks}}
    return {"verdict": verdict, "confidence": 0.9, "findings": findings, "not_covered": list(not_covered),
            "checks_run": [{"recipe_id": c["recipe_id"], "status": c["status"]} for c in checks if c["status"] != "SKIPPED"],
            "collection_impact": {"measured_stop_ms": 0.0, "zero_stop": True, "bytes_read": 4096},
            "target": {"pid": 42, "process_name": "demo"}, "duration_s": 1.5, "report": report}


def _thread(tid, name, lock, owner_tid, owner_name, loc, text):
    return {"tid": tid, "name": name, "states": ["S"] * 4, "cpu_share": 0.0, "top_function": name,
            "top_source_location": loc, "top_source_line_exact": True, "top_source_text": text,
            "waiting_on_lock": lock, "lock_owner_tid": owner_tid, "lock_owner_name": owner_name, "syscall": "futex"}


def deadlock_result(n_threads=2):
    names = ["alpha", "beta", "gamma"][:n_threads]
    cyc, rows = [], []
    for i, nm in enumerate(names):
        j = (i + 1) % n_threads
        cyc.append({"waiter_tid": 100 + i, "waiter_name": nm, "lock_name": f"m_{names[j]}", "lock_address": hex(0x1000 + j),
                    "owner_tid": 100 + j, "owner_name": names[j]})
        rows.append(_thread(100 + i, nm, f"m_{names[j]}", 100 + j, names[j], f"dl.c:{10 + i}", f"pthread_mutex_lock(&m_{names[j]});"))
    obs = {"deadlock_detected": True, "deadlock_cycle": cyc, "cycle_persistent": True, "observation_count": 2,
           "stalled_lock_waits": rows, "thread_summary": rows,
           "thread_sampling": {"samples_collected": 4, "window_sec": 0.5}}
    f = {"category": "DEADLOCK_INDICATORS", "severity": "CRITICAL", "status": "CONFIRMED_ROOT_CAUSE",
         "description": "cycle", "recipe_ids": ["RECIPE_POTENTIAL_DEADLOCK_PATTERNS"],
         "subject_details": [{"kind": "lock", "name": "m_alpha"}], "observed": ["Cycle verified"]}
    return _result("CONFIRMED_FAULT", [f],
                   [_check("RECIPE_POTENTIAL_DEADLOCK_PATTERNS", "FAIL", obs, interp="Cycle verified"),
                    _check("RECIPE_FD_LEAK", "PASS", interp="fds stable"),
                    _check("RECIPE_USE_AFTER_FREE", "INCONCLUSIVE", {"missing_capability": "DYNAMIC_EVENT_TRACING"}),
                    _check("RECIPE_STATE_TRANSITION_VIOLATIONS", "SKIPPED")],
                   [{"kind": "recipes_not_planned", "item": "RECIPE_DOUBLE_FREE,RECIPE_INVALID_FREE", "reason": "not selected"},
                    {"kind": "long_wait_not_judged", "item": "main (tid 99)", "reason": "idle wait " + EVIL}])


def overflow_result(usable=72, past=24, name="rb.buf", victim="aux", pattern="repeated byte 0x6d",
                    size_field="0x6d6d6d6d6d6d6d6d"):
    ua = 0x5000_02a0
    defect = {"kind": "chunk_header_damaged", "stable": True, "stable_rereads": 2,
              "details": {"observed_size_field": size_field},
              "damage": {"usable_end": hex(ua + usable), "bytes_past_usable_end": past, "pattern": pattern,
                         "extent_basis": pattern + " written over the size field", "continues_buffer_content": True},
              "overflowing_buffer": {"chunk_address": hex(ua - 16), "user_address": hex(ua), "usable_size": usable,
                                     "variable": name.split(".")[0], "variable_path": name},
              "victim": ({"chunk_address": hex(ua + usable - 8), "state": "in_use", "variable_path": victim}
                         if victim else {"chunk_address": hex(ua + usable - 8), "state": "top"})}
    f = {"category": "MEMORY_CORRUPTION", "severity": "CRITICAL", "status": "CONFIRMED_ROOT_CAUSE",
         "description": "heap chunk header damaged", "recipe_ids": ["RECIPE_HEAP_METADATA_CORRUPTION"],
         "subject_details": [{"kind": "variable", "name": name}]}
    return _result("CONFIRMED_FAULT", [f], [_check("RECIPE_HEAP_METADATA_CORRUPTION", "FAIL",
                                                   {"memory_integrity": {"heap": {"defects": [defect]}}})])


def leak_result():
    walks = [{"t": 10.0 + i * 0.3, "in_use_bytes": 4_000_000 + i * 600_000, "in_use_count": 4000 + i * 600, "status": "OK"}
             for i in range(4)]
    li = {"walks": 4, "window_s": 0.9, "heap_walks": walks,
          "growth_owners": [{"variable": "reg_head", "variable_path": "reg_head(->next)*", "blocks_delta": 1800,
                             "bytes_delta": 1_800_000, "rate_kb_per_s": 1953.1, "allocating_thread_name": "intake",
                             "allocating_thread_tid": 7}]}
    f = {"category": "MEMORY_LEAK", "severity": "MEDIUM", "status": "PROBABLE_CAUSE", "description": "growth",
         "recipe_ids": ["RECIPE_HEAP_GROWTH"], "subject_details": [{"kind": "variable", "name": "reg_head"}]}
    return _result("PROBABLE_FAULT", [f], [_check("RECIPE_HEAP_GROWTH", "FAIL", {"leak_investigation": li})])


def uaf_result(written=False):
    x = {"level": "candidate", "freed_chunk": "0x7000", "user_address": "0x7010", "chunk_size": 64,
         "free_list": "tcache bin 2", "written_while_free": written, "observed_free_in_reads": 4, "window_s": 1.1,
         "variable_path": "cur", "dangling_pointers": [{"variable_path": "cur", "slot_address": "0x4020"}]}
    f = {"category": "USE_AFTER_FREE", "severity": "WARNING", "status": "PROBABLE_CAUSE", "description": "dangling",
         "recipe_ids": ["RECIPE_FREED_MEMORY_USE"], "subject_details": [{"kind": "variable", "name": "cur"}]}
    return _result("PROBABLE_FAULT", [f], [_check("RECIPE_FREED_MEMORY_USE", "FAIL", {"freed_memory_use": {"findings": [x]}})])


class TestVisualSummary(unittest.TestCase):
    def _html(self, res, lang="en", **kw):
        h = build_visual_summary(res, res.get("report"), lang, title=kw.get("title", "T"), summary_md=kw.get("summary_md", ""))
        self.assertNotRegex(h, r"""(?:src|href)\s*=\s*["']?(?:https?:)?//""")
        self.assertNotIn("@import", h)
        self.assertNotIn("<script", h)                                               # interaction is CSS only
        self.assertNotRegex(h, r"\son[a-z]+\s*=")                                    # no inline event handlers
        self.assertNotIn("http://", h)
        self.assertNotIn("https://", h)
        self.assertNotRegex(h, r"url\((?!#)")                                       # only in-document references
        if lang == "en":
            self.assertNotRegex(h, "[가-힣]")
        return h

    def test_deadlock_sequence_has_one_step_per_event(self):
        for n in (2, 3):
            h = self._html(deadlock_result(n))
            self.assertIn(f'data-steps="{2 * n + 1}"', h)           # n acquisitions, n waits, the closed cycle
            for k in range(1, 2 * n + 2):
                self.assertIn(f'<li data-step="{k}" ', h)
                self.assertIn(f'class="dsv-r dsv-r{k}"', h)                          # one selectable step each
            self.assertIn("<svg", h)
            self.assertIn("dl.c:10", h)
            self.assertIn("pthread_mutex_lock(&amp;m_beta);", h)
            # the acquisitions are inferred from ownership, the waits were seen: the labels must say so
            lis = re.findall(r'<li data-step="\d+".*?</li>', h, re.S)
            self.assertTrue(all("dsv-chip-rec" in li for li in lis[:n]))
            self.assertTrue(all("dsv-chip-obs" in li and "dsv-chip-rec" not in li for li in lis[n:]))

    def test_deadlock_korean_labels(self):
        h = self._html(deadlock_result(), "ko")
        self.assertIn("스레드들이 멈추게 된 순서", h)
        self.assertIn("재구성", h)
        self.assertIn('lang="ko"', h)

    def test_overflow_map_matches_the_evidence(self):
        h = self._html(overflow_result(usable=72, past=24))
        self.assertEqual(len(re.findall(r'class="dsv-cell dsv-c-buf ', h)), 9)      # 72 usable bytes = 9 words
        self.assertEqual(len(re.findall(r'class="dsv-cell dsv-c-over ', h)), 3)     # 24 bytes past = 3 words
        self.assertIn("rb.buf: usable 72 bytes", h)
        self.assertIn("24 bytes written past the end", h)
        self.assertIn("size field", h)
        self.assertIn("next block: aux", h)
        self.assertIn("0x6d6d6d6d6d6d6d6d", h)
        self.assertIn("not observed", h)                                             # the writer is not known

    def test_overflow_partial_word_large_buffer_and_top_victim(self):
        h = self._html(overflow_result(usable=4096, past=18, victim=None, pattern="printable text",
                                       size_field="0x666e6f635f6d6f72"))
        self.assertIn("… 4040 bytes …", h)                                           # 512 words, 7 drawn
        self.assertEqual(len(re.findall(r'class="dsv-cell dsv-c-over ', h)), 3)     # 18 bytes -> 3 words, last partial
        self.assertIn("linear-gradient(90deg, var(--bad-bg) 25%", h)                 # 2 of 8 bytes in the last word
        self.assertIn("rom_conf", h)                                                 # the size field read as text
        self.assertIn("unallocated heap (top)", h)

    def test_overflow_without_usable_evidence_draws_nothing(self):
        res = overflow_result()
        d = res["report"]["section_d_detailed_inspection_results"]["checks"][0]["actual_observations"]
        del d["memory_integrity"]["heap"]["defects"][0]["damage"]["bytes_past_usable_end"]
        h = self._html(res)
        self.assertNotIn("dsv-mem", h.split("</style>", 1)[1])
        self.assertIn("heap chunk header damaged", h)                                # falls back to the description

    def test_leak_chart_and_owner(self):
        h = self._html(leak_result())
        self.assertEqual(h.count('<circle class="dsv-pt"'), 4)
        self.assertIn("reg_head(-&gt;next)*", h)
        self.assertIn("+1800 blocks", h)
        self.assertIn("intake (tid 7)", h)

    def test_uaf_states_whether_a_use_was_seen(self):
        self.assertIn("No write into the freed block was observed", self._html(uaf_result(False)))
        self.assertIn("A write into the block was observed", self._html(uaf_result(True)))

    def test_checklist_groups_reasons_and_links(self):
        h = self._html(deadlock_result())
        for status, n in (("FAIL", 1), ("PASS", 1), ("INCONCLUSIVE", 1), ("SKIPPED", 3)):
            self.assertEqual(h.count(f'<details class="dsv-ck dsv-s-{status}" data-status="{status}">'), n, status)
        self.assertIn("DYNAMIC_EVENT_TRACING", h)                                    # why the check gave no answer
        self.assertIn("Not selected for this symptom.", h)
        self.assertIn('href="#dsv-finding-1"', h)                                    # failing check -> its finding
        self.assertIn("not evidence of health", h)
        self.assertIn("Also not examined", h)

    def test_result_status_wins_over_report_status(self):
        res = deadlock_result()
        res["checks_run"][1]["status"] = "INCONCLUSIVE"                              # RECIPE_FD_LEAK
        h = self._html(res)
        self.assertEqual(h.count('data-status="PASS"'), 0)
        self.assertEqual(h.count('data-status="INCONCLUSIVE"'), 2)

    def test_step_classes_drive_the_css_stepper(self):
        h = self._html(deadlock_result(2))
        # an element of step 3 is hidden while step 1 or 2 is selected, and highlighted on step 3
        self.assertRegex(h, r'<li data-step="3" class="dsv-h1 dsv-h2 dsv-c3" style="--d:2"')
        self.assertIn(".dsv-r2:checked ~ .dsv-h2", h)
        self.assertEqual(len(set(re.findall(r'name="(dsv-step-[^"]+)"', h))), 1)     # one radio group per sequence
        long = deadlock_result(3)
        cyc = long["report"]["section_d_detailed_inspection_results"]["checks"][0]["actual_observations"]["deadlock_cycle"]
        for i in range(3, 9):                                                         # 9 threads -> 19 steps > limit
            cyc.append({"waiter_tid": 100 + i, "waiter_name": f"t{i}", "lock_name": f"L{i}", "owner_tid": 101 + i, "owner_name": f"t{i + 1}"})
        self.assertNotIn('name="dsv-step-', self._html(long))                        # too long: drawn, not steppable

    def test_no_finding_texts(self):
        healthy = _result("HEALTHY", [], [_check("RECIPE_FD_LEAK", "PASS")])
        self.assertIn("No problem was found within the checked scope", self._html(healthy))
        incon = _result("INCONCLUSIVE", [], [])
        h = self._html(incon)
        self.assertIn("not a statement that the process is healthy", h)
        self.assertIn("No check record is available", h)

    def test_everything_from_the_target_is_escaped(self):
        res = deadlock_result()
        cyc = res["report"]["section_d_detailed_inspection_results"]["checks"][0]["actual_observations"]["deadlock_cycle"]
        cyc[0]["lock_name"] = cyc[1]["lock_name"] = EVIL
        res["findings"][0]["observed"] = [EVIL]
        res["findings"][0]["subject_details"] = [{"kind": "variable", "name": EVIL}]
        res["target"]["process_name"] = EVIL
        ov = overflow_result(name=EVIL, victim=EVIL)
        for r in (res, ov):
            h = build_visual_summary(r, r["report"], "ko", title=EVIL, summary_md="## 1. x\n\n`" + EVIL + "`\n")
            self.assertNotIn(EVIL, h)
            self.assertNotIn("<script", h)
            self.assertIn("&lt;script&gt;", h)

    def test_malformed_input_never_raises(self):
        for res in ({}, {"findings": [None, {"category": "DEADLOCK_INDICATORS"}], "checks_run": [None, {}], "not_covered": [None]},
                    {"verdict": "X", "findings": [{"category": "MEMORY_CORRUPTION", "recipe_ids": None}], "report": {"section_d_detailed_inspection_results": {"checks": [{"recipe_id": "R", "actual_observations": {"memory_integrity": {"heap": {"defects": [{"overflowing_buffer": {}, "damage": {}}]}}}}]}}}):
            self.assertIn("dsv", build_visual_summary(res, None, "en"))

    def test_wrap_detail(self):
        page = '<html><body><div class="report-card">A. Executive Summary</div></body></html>'
        out = wrap_detail(page, "Detail " + EVIL)
        self.assertIn('<details class="dsv-detail" id="dsv-detail">', out)
        self.assertNotIn(EVIL, out)
        self.assertLess(out.index("<details"), out.index("A. Executive Summary"))
        self.assertEqual(wrap_detail("<p>x</p>", "d"), "<p>x</p>")


if __name__ == "__main__":
    unittest.main()

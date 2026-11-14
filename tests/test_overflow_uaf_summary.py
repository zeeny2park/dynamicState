"""Dedicated plain-language summaries for heap buffer overflow and use-after-free (presentation only)."""
import copy
import os
import re
import sys
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from extractor.human_report import render_human_report  # noqa: E402
from extractor.recipe_plugins.heap_overflow_text import overflow_sentences  # noqa: E402
from extractor.recipe_plugins.use_after_free import uaf_sentences  # noqa: E402

DEFECT = {
    "kind": "chunk_header_damaged", "at": "0x1e0", "reason": "invalid chunk size 0x6d6d6d6d6d6d6d68",
    "stable": True, "stable_rereads": 2,
    "details": {"observed_size_field": "0x6d6d6d6d6d6d6d6d"},
    "damage": {"usable_end": "0x2e8", "bytes_past_usable_end": 24, "pattern": "repeated byte 0x6d",
               "continues_buffer_content": True, "extent_basis": "internal english basis text"},
    "overflowing_buffer": {"user_address": "0x2a0", "usable_size": 72, "variable": "rb", "variable_path": "rb.buf"},
    "victim": {"chunk_address": "0x2e0", "state": "in_use", "variable": "aux", "variable_path": "aux"},
    "description": "heap chunk header damaged at 0x1e0 ...",
}
UAF = {
    "level": "candidate", "freed_chunk": "0x2d0", "user_address": "0x2e0", "chunk_size": 64,
    "free_list": "tcache bin 2 (chunk size 64) of the tcache at 0x5010, entry 0 of 1",
    "written_while_free": False, "observed_free_in_reads": 4, "window_s": 2.484,
    "variable": "cur", "variable_path": "cur",
    "dangling_pointers": [{"variable": "cur", "variable_path": "cur", "owner_kind": "static"}],
}


def _result(category, rid, obs_key, obs):
    f = {"category": category, "severity": "CRITICAL", "status": "CONFIRMED_ROOT_CAUSE", "description": "d",
         "recipe_ids": [rid], "subject_details": [{"kind": "variable", "name": "rb"}], "observed": ["engine english text"]}
    check = {"recipe_id": rid, "status": "FAIL", "name": "n", "actual_observations": {obs_key: obs}}
    return {"verdict": "CONFIRMED_FAULT", "confidence": 0.9, "findings": [f], "not_covered": [],
            "checks_run": [{"recipe_id": rid, "status": "FAIL"}], "target": {"pid": 1, "process_name": "p"},
            "report": {"section_d_detailed_inspection_results": {"checks": [check]}}}


def _ov_result(defect):
    return _result("MEMORY_CORRUPTION", "RECIPE_HEAP_METADATA_CORRUPTION", "memory_integrity",
                   {"heap": {"defects": [defect]}})


class TestOverflowSummary(unittest.TestCase):
    def test_states_buffer_size_and_overrun_in_both_languages(self):
        en = " ".join(overflow_sentences(0, DEFECT))
        ko = " ".join(overflow_sentences(1, DEFECT))
        for s in (en, ko):
            self.assertIn("`rb.buf`", s)
            self.assertIn("72", s)
            self.assertIn("24", s)
            self.assertIn("`aux`", s)
            self.assertIn("`0x6d`", s)
        self.assertIn("Inferred, not seen", en)
        self.assertIn("추정", ko)
        self.assertNotIn("internal english basis text", en + ko)

    def test_missing_values_degrade_without_placeholders(self):
        d = copy.deepcopy(DEFECT)
        for k in ("usable_size", "variable", "variable_path"):
            d["overflowing_buffer"].pop(k)
        d["damage"].pop("bytes_past_usable_end")
        d["damage"].pop("pattern")
        d["victim"] = {}
        d["details"] = {}
        d["stable"] = False
        for i in (0, 1):
            s = " ".join(overflow_sentences(i, d))
            self.assertNotRegex(s, r"None|\{|\}|\?\?|\bnull\b")
            self.assertNotIn("0 bytes", s)

    def test_rendered_in_human_summary_and_other_corruption_stays_generic(self):
        res = _ov_result(DEFECT)
        ko = render_human_report(res, res["report"], "ko")
        self.assertIn("사용 가능 크기가 72바이트인 힙 버퍼", ko)
        en = render_human_report(res, res["report"], "en")
        self.assertIn("is a heap buffer with 72 usable bytes", en)
        other = copy.deepcopy(DEFECT)
        other["kind"] = "free_chunk_link_damaged"
        res2 = _ov_result(other)
        self.assertNotIn("heap buffer with 72", render_human_report(res2, res2["report"], "en"))


class TestUafSummary(unittest.TestCase):
    def test_pointer_block_and_free_list(self):
        en = " ".join(uaf_sentences(0, UAF))
        ko = " ".join(uaf_sentences(1, UAF))
        self.assertIn("The pointer `cur` still holds the address of a heap block (64 bytes, at `0x2e0`)", en)
        self.assertIn("포인터 `cur`이(가) 이미 해제된 힙 블록(크기 64바이트, 주소 `0x2e0`)", ko)
        self.assertIn("4 reads over 2.48 s", en)
        self.assertIn("not proven", en)
        self.assertIn("입증되지 않았습니다", ko)
        self.assertIn("아레나", " ".join(uaf_sentences(1, dict(UAF, free_list="fastbin 2 (chunk size 64) of arena 0"))))

    def test_written_while_free_names_the_pointer_as_inference(self):
        x = dict(UAF, level="confirmed", written_while_free=True, write_evidence="payload changed")
        en = " ".join(uaf_sentences(0, x))
        self.assertIn("Seen: the block's contents changed", en)
        self.assertIn("Inferred: because `cur` still points", en)

    def test_no_pointer_and_missing_values(self):
        x = {"level": "probable", "freed_chunk": "0x2d0", "written_while_free": True}
        for i in (0, 1):
            s = " ".join(uaf_sentences(i, x))
            self.assertNotRegex(s, r"None|\{|\}|\?\?")
            self.assertIn("`0x2d0`", s)
        self.assertIn("owner is unknown", " ".join(uaf_sentences(0, x)))

    def test_rendered_in_human_summary(self):
        res = _result("USE_AFTER_FREE", "RECIPE_FREED_MEMORY_USE", "freed_memory_use", {"findings": [UAF]})
        ko = render_human_report(res, res["report"], "ko")
        self.assertIn("포인터 `cur`", ko)
        self.assertNotIn("engine english text", ko)


if __name__ == "__main__":
    unittest.main()

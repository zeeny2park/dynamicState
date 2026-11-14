"""Roadmap stage 3: object relation model (extractor.object_relations) and its report line.

Pure tests over the observation shapes the checks record (no target): every finding kind gets one chain per memory
object with exactly one node per role, every link says how it was established, a link the evidence does not establish
is ``not_established`` with a reason (never a guessed name), and the report renders the chain without changing the
section order or showing percentages.
"""

import unittest

from extractor import human_report
from extractor.object_relations import LINK_KINDS, NOT_ESTABLISHED, ROLES, attach_object_relations, build_relations


def _report(rid, obs):
    return {"section_d_detailed_inspection_results": {"checks": [
        {"recipe_id": rid, "status": "FAIL", "actual_observations": obs},
        {"recipe_id": "RECIPE_OTHER", "status": "PASS", "actual_observations": {"deadlock_cycle": [
            {"lock_name": "ignored", "owner_tid": 1}]}}]}}


def _finding(rid, cat="X"):
    return {"category": cat, "recipe_ids": [rid, "RECIPE_OTHER"], "subjects": [], "status": "PROBABLE_CAUSE"}


LEAK = {"leak_investigation": {"walks": 4, "growth_owners": [
    {"variable": "g_registry", "variable_path": "g_registry[*]", "owner_kind": "global", "blocks_delta": 1780,
     "bytes_delta": 175168, "allocating_thread_name": "intake", "allocating_thread_tid": 42,
     "arena_evidence": "arena 1: attached_threads=1",
     "container": {"decoded": True, "type": "std::vector<Record*>", "size_last": 3860, "capacity": 4096}}],
    "unreachable_growth": [{"chunk_size": 560, "blocks_delta": 10, "bytes_delta": 5600, "mmapped": True}]}}


class TestModel(unittest.TestCase):
    def _chains(self, rid, obs):
        f = _finding(rid)
        rel = build_relations(f, _report(rid, obs))
        for ch in rel["chains"]:
            self.assertEqual([n["role"] for n in ch["nodes"]], list(ROLES))
            self.assertEqual(len(ch["links"]), 2)
            for ln in ch["links"]:
                self.assertIn(ln["how"], LINK_KINDS)
                self.assertTrue(ln["basis"])
                if not ln["established"]:
                    self.assertEqual(ln["how"], "not_established")
                    self.assertIn(ln["reason"], NOT_ESTABLISHED)
                    target = next(n for n in ch["nodes"] if n["id"] == ln["target"])
                    self.assertFalse(target["established"])
                    self.assertIsNone(target["name"])          # nothing guessed
        return rel["chains"]

    @staticmethod
    def _how(ch):
        return {x["target"]: (x["how"], x.get("reason")) for x in ch["links"]}

    def test_leak_owned_and_unreachable(self):
        owned, unreach = self._chains("RECIPE_PROCESS_MEMORY_GROWTH", LEAK)
        self.assertEqual(self._how(owned), {"v": ("typed_pointer_path", None), "t": ("arena_attribution", None)})
        self.assertEqual(owned["nodes"][1]["attrs"]["container"]["size_last"], 3860)
        self.assertEqual(owned["nodes"][2]["name"], "intake")
        self.assertEqual(self._how(unreach), {"v": ("not_established", "unreachable"),
                                              "t": ("not_established", "mmapped_no_arena")})

    def test_lock_kinds(self):
        (c,) = self._chains("R", {"deadlock_cycle": [{"waiter_tid": 1, "lock_name": "g_a", "lock_address": "0x10",
                                                      "owner_tid": 2, "owner_name": "w2"}]})
        self.assertEqual(self._how(c), {"v": ("debug_symbol", None), "t": ("lock_owner_field", None)})
        (c,) = self._chains("R", {"deadlock_cycle": [{"lock_name": "0x5000", "lock_address": "0x5000", "owner_tid": 2}]})
        self.assertEqual(self._how(c)["v"], ("not_established", "no_symbol"))
        (o, s) = self._chains("R", {"lock_wait_state": {
            "orphan_locks": [{"lock_name": "m_cfg", "lock_address": "0x18", "owner_tid": 7, "owner_alive": False}],
            "self_waits": [{"lock_name": "m_state", "lock_address": "0x28", "waiter_tid": 8, "waiter_name": "r"}]}})
        self.assertEqual(o["nodes"][2]["attrs"]["tid"], 7)
        self.assertFalse(o["nodes"][2]["attrs"]["alive"])
        self.assertEqual(s["nodes"][2]["name"], "r")
        (c,) = self._chains("R", {"lock_contention": {"mutexes": [{"lock_name": "mu", "address": "0x1",
                                                                    "owner_tids": [1, 2]}]}})
        self.assertEqual(self._how(c)["t"], ("not_established", "owner_changed"))

    def test_memory_defects_and_mapping(self):
        (c,) = self._chains("R", {"freed_memory_use": {"findings": [{"freed_chunk": "0xa0", "chunk_size": 64,
                                                                      "dangling_pointers": [{"variable_path": "cur"}]}]}})
        self.assertEqual(self._how(c), {"v": ("dangling_pointer", None), "t": ("not_established", "untraced_use")})
        (c,) = self._chains("R", {"free_list_repeats": {"findings": [{"freed_chunk": "0xb0", "owners": []}]}})
        self.assertEqual(self._how(c), {"v": ("not_established", "no_owner_variable"),
                                        "t": ("not_established", "untraced_free")})
        (h, g) = self._chains("R", {"memory_integrity": {
            "heap": {"defects": [{"kind": "top_chunk_damaged", "overflowing_buffer": {
                "user_address": "0xc0", "variable": "tbl", "variable_path": "tbl[3]"}}]},
            "globals": {"candidates": [{"overflowed_array": {"variable": "name", "variable_path": "name", "size": 8},
                                        "overwritten_neighbour": {"variable": "count"}}]}}})
        self.assertEqual(self._how(h)["v"], ("typed_pointer_path", None))
        self.assertEqual((g["nodes"][0]["kind"], self._how(g)["v"]), ("global_storage", ("debug_symbol", None)))
        (m,) = self._chains("R", {"mapping_growth": {"grown_mappings": [{"start": "0x1000", "added_kb": 64}],
                                                     "outside_growth_kb": 64,
                                                     "owner_search": {"owners": [{"variable": "store",
                                                                                  "variable_path": "store.head",
                                                                                  "pointers_into_new_ranges": 1}]},
                                                     "growth_thread": {"status": "AMBIGUOUS"}}})
        self.assertEqual(self._how(m), {"v": ("pointer_into_mapping", None), "t": ("not_established", "no_single_thread")})

    def test_thread_only_finding_and_no_evidence(self):
        (c,) = self._chains("R", {"runaway_threads": [{"tid": 5, "name": "poller"}]})
        self.assertEqual(self._how(c), {"v": ("not_established", "not_memory"), "t": ("thread_samples", None)})
        self.assertFalse(c["nodes"][0]["established"])
        rel = build_relations(_finding("R"), _report("R", {"fd_count": 3}))
        self.assertEqual(rel["chains"], [])
        self.assertTrue(rel["note"])

    def test_failing_checks_only_and_attach_never_raises(self):
        f = _finding("NOPE")
        rel = build_relations(f, _report("R", LEAK))
        self.assertEqual(rel["chains"], [])
        fs = [_finding("RECIPE_PROCESS_MEMORY_GROWTH"), "junk"]
        attach_object_relations(fs, {"section_d_detailed_inspection_results": {"checks": "broken"}})
        self.assertIn("object_relations", fs[0])


class TestReport(unittest.TestCase):
    def _result(self):
        f = dict(_finding("RECIPE_PROCESS_MEMORY_GROWTH", "MEMORY_LEAK"), subjects=["g_registry", "intake"],
                 subject_details=[{"kind": "variable", "name": "g_registry"}, {"kind": "thread_name", "name": "intake"}],
                 severity="MEDIUM")
        rep = _report("RECIPE_PROCESS_MEMORY_GROWTH", LEAK)
        attach_object_relations([f], rep)
        return {"verdict": "PROBABLE_FAULT", "findings": [f], "target": {"pid": 1, "process_name": "p"},
                "report": rep}

    def test_chain_line_in_both_languages(self):
        r = self._result()
        ko = human_report.render_human_report(r, lang="ko")
        line = next(x for x in ko.splitlines() if "**관계**" in x)
        self.assertIn("힙 블록 +1780개", line)
        self.assertIn("← (관측한 포인터 경로) 변수 `g_registry[*]`(`std::vector<Record*>`, 원소 3860개)", line)
        self.assertIn("← (아레나 귀속) 스레드 `intake` (tid 42)", line)
        second = [x for x in ko.splitlines() if "**관계**" in x][1]
        self.assertIn("확인되지 않음: 참조가 남아 있지 않음", second)
        self.assertNotRegex(line, r"\d+\s*%")
        en = human_report.render_human_report(r, lang="en")
        self.assertIn("(not established: no reference remains) variable", en)
        self.assertNotRegex("\n".join(x for x in en.splitlines() if "**Relation**" in x), r"\d+\s*%")

    def test_section_order_unchanged(self):
        self.assertEqual(human_report.REPORT_SECTION_ORDER,
                         ("conclusion", "tiles", "target", "profile", "findings", "checks", "not_examined", "next",
                          "hypothesis", "method", "reproducibility", "reference"))

    def test_finding_block_facts_carry_the_line(self):
        # the facts list of a finding block is what both the Markdown and the HTML renderer print
        comp = human_report.compose(self._result(), lang="ko")
        self.assertTrue(any("**관계**" in x for x in comp["blocks"][0]["facts"]))


if __name__ == "__main__":
    unittest.main()

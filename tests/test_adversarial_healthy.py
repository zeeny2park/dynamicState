"""Healthy programs whose NAMES and VALUES look like faults must be diagnosed as not faulty.

Principle (IMP-018 / IMP-009): a variable's name can rank candidates but is never evidence; the DWARF type, the layout
and an observed relation are.  Regressions covered (all found as false PROBABLE / CONFIRMED faults on healthy
processes):

* a variable named magic / canary / tag holding 0xDEADBEEF was "corrupted" (it is often the VALID magic): without an
  expected value (a specification, or the same field of sibling array elements disagreeing) a magic value is a
  neutral note;
* the first name containing "alloc" and the first containing "free" were compared as a counter pair, and a static
  ratio (alloc >= 5 x free) was a leak: pairs now need integer types, one scope and the same name stem, and an
  imbalance needs the gap to GROW over the observation window;
* every name containing max/limit/capacity was paired with every name containing len/size/count ("silent" was a
  length): same rule as counters, plus two identical reads of a violation;
* a container's "size" member (a pool's block size) or a growing statistic in a pointer+integer struct was read as
  retained objects: a count is accumulation only when memory grows with it in the same window;
* a sentinel value (-1, all-ones, INT_MAX) in a state variable was a boundary violation: it needs an expected range;
* a type whose name merely contains "lock" (clock_t, struct block_stats) was read as a pthread mutex.

Three layers: pure (tokeniser, pairing, rules), discovery on the compiled adversarial programs, and the full matrix
(every program x every symptom kind through ``diagnose()``: no fault verdict, no finding).  Programs live in
``tests/fixtures/adversarial_healthy/`` (shared with the accuracy benchmark's "adversarial healthy" suite).
"""
import os
import shutil
import subprocess
import time
import unittest

from extractor.diagnostic_recipes import (
    RECIPE_STATUS_CONTRADICTED, RECIPE_STATUS_INSUFFICIENT_EVIDENCE, RECIPE_STATUS_SUPPORTED,
    DiagnosticRecipeRegistry as Registry,
)
from extractor.runtime_evidence_provider import (
    ROLE_ALLOC, ROLE_CAPACITY, ROLE_FREE, ROLE_LENGTH, RuntimeEvidenceProvider, name_tokens, related_pairs,
)
from tests.support import adversarial_healthy as adv
from tests.support.fixture_process import fixture_popen
from tests.support.tmpdirs import temp_dir

HAVE_CC = bool(shutil.which("gcc") and shutil.which("g++"))


class NameTokensTest(unittest.TestCase):
    def test_whole_tokens_not_substrings(self):
        self.assertEqual(name_tokens("silent"), ["silent"])          # not "len"
        self.assertEqual(name_tokens("stage"), ["stage"])            # not "tag"
        self.assertEqual(name_tokens("freelist_len"), ["freelist", "len"])
        self.assertEqual(name_tokens("allocCount"), ["alloc", "count"])
        self.assertEqual(name_tokens("g_stat.allocations"), ["allocations"])
        self.assertEqual(name_tokens("HTTPServerMaxLen"), ["http", "server", "max", "len"])

    def test_pairs_need_the_same_stem(self):
        self.assertEqual(related_pairs(["alloc_total", "free_slots", "malloc_threshold", "release_version"],
                                       ROLE_ALLOC, ROLE_FREE), [])
        self.assertEqual(related_pairs(["allocations", "freelist_len", "reclaim_interval"], ROLE_ALLOC, ROLE_FREE), [])
        self.assertEqual(related_pairs(["pool_allocs", "pool_frees"], ROLE_ALLOC, ROLE_FREE),
                         [("pool_allocs", "pool_frees")])
        self.assertEqual(related_pairs(["max_fd", "byte_count", "limit", "payload_length"], ROLE_CAPACITY, ROLE_LENGTH),
                         [])
        self.assertEqual(related_pairs(["max_retries", "file_size", "silent", "name_len"], ROLE_CAPACITY, ROLE_LENGTH),
                         [])
        self.assertEqual(related_pairs(["capacity", "length"], ROLE_CAPACITY, ROLE_LENGTH), [("capacity", "length")])


class RulesWithoutRelationTest(unittest.TestCase):
    """The rules themselves: a value without a relation or an expected value is not a fault."""

    def test_static_counter_ratio_is_not_an_imbalance(self):
        r = Registry.evaluate_recipe("RECIPE_ALLOCATION_FREE_IMBALANCE", {"alloc_count": 10000, "free_count": 5})
        self.assertEqual(r.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        grown = Registry.evaluate_recipe("RECIPE_ALLOCATION_FREE_IMBALANCE",
                                         {"alloc_count": 10000, "free_count": 5, "alloc_delta": 900, "free_delta": 0})
        self.assertEqual(grown.status, RECIPE_STATUS_SUPPORTED)

    def test_count_growth_needs_memory_growth(self):
        flat = Registry.evaluate_recipe("RECIPE_LONG_LIVED_OBJECT_ACCUMULATION",
                                        {"container_size_delta": 5000, "container_name": "g_v.n",
                                         "heap_growth_bytes": 0, "rss_history_kb": [9000, 9000, 9004]})
        self.assertEqual(flat.status, RECIPE_STATUS_CONTRADICTED)
        unknown = Registry.evaluate_recipe("RECIPE_LONG_LIVED_OBJECT_ACCUMULATION", {"container_size_delta": 5000})
        self.assertEqual(unknown.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        grew = Registry.evaluate_recipe("RECIPE_LONG_LIVED_OBJECT_ACCUMULATION",
                                        {"container_size_delta": 5000, "heap_growth_bytes": 8 << 20})
        self.assertEqual(grew.status, RECIPE_STATUS_SUPPORTED)

    def test_one_container_size_reading_is_not_accumulation(self):
        r = Registry.evaluate_recipe("RECIPE_LONG_LIVED_OBJECT_ACCUMULATION", {"container_size": 4096})
        self.assertEqual(r.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)

    def test_sentinel_needs_an_expected_range(self):
        for v in (-1, 0xFFFFFFFF, 0x7FFFFFFF):
            r = Registry.evaluate_recipe("RECIPE_SUSPICIOUS_BOUNDARY_VALUES", {"value": v})
            self.assertEqual(r.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE, v)
            r = Registry.evaluate_recipe("RECIPE_SUSPICIOUS_BOUNDARY_VALUES", {"value": v, "valid_range": (0, 100)})
            self.assertEqual(r.status, RECIPE_STATUS_SUPPORTED, v)


@unittest.skipUnless(HAVE_CC, "needs gcc and g++")
class DiscoveryOnAdversarialProgramsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out = temp_dir(cls, "adv_disc_")
        cls.bins = {n: adv.build(n, cls.out) for n in ("magic", "counters", "caplen", "containers", "siblings",
                                                       "cpp_pool_stats", "ring_counters")}

    def _disc(self, name):
        return RuntimeEvidenceProvider._discover_dwarf_symbols(RuntimeEvidenceProvider.__new__(RuntimeEvidenceProvider),
                                                               self.bins[name])

    def test_unrelated_names_form_no_pairs(self):
        for n in ("counters", "caplen", "ring_counters"):
            d = self._disc(n)
            self.assertEqual(d["alloc_free_pairs"], [], n)
            self.assertEqual(d["capacity_length_pairs"], [], n)

    def test_real_pairs_by_type_scope_and_stem(self):
        d = self._disc("cpp_pool_stats")
        self.assertIn(("g_pool.allocCount", "g_pool.freeCount"), d["alloc_free_pairs"])
        self.assertIn(("g_pool.queueCap", "g_pool.queueLen"), d["capacity_length_pairs"])
        self.assertNotIn(("g_pool.maxPending", "g_pool.pendingBytes"), d["capacity_length_pairs"])

    def test_magic_candidates_are_integers_and_stage_is_not_a_tag(self):
        d = self._disc("magic")
        self.assertNotIn("g_hdr.stage", d["magic_canaries"])
        self.assertNotIn("g_hdr.tag", d["magic_canaries"])
        self.assertIn("g_hdr.magic", d["magic_canaries"])
        self.assertEqual(self._disc("siblings")["magic_sibling_arrays"][0][0], "g_slots")

    def test_plain_struct_size_member_is_not_a_container_size(self):
        d = self._disc("containers")
        self.assertIn("g_buffer_pool", d["containers"])   # ranked by its name...
        # ... but the collector reads a size only from a decoded container (see the matrix test): the provider
        # skips g_buffer_pool because its value carries no "container" marker


SIBLING_DEFECT_C = r"""
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
struct obj { uint32_t magic; int id; };
struct obj g_objs[6] = { {0xDEADBEEF, 1}, {0xDEADBEEF, 2}, {0xDEADBEEF, 3}, {0x41414141, 4}, {0xDEADBEEF, 5}, {0, 6} };
int main(void) { printf("READY\n"); fflush(stdout); for (;;) pause(); }
"""


@unittest.skipUnless(HAVE_CC, "needs gcc and g++")
class SiblingMagicTruePositiveTest(unittest.TestCase):
    """The expected value of a magic comes from its siblings: one element alone disagreeing is still detected."""

    def test_odd_sibling_is_flagged_with_its_expected_value(self):
        d = temp_dir(self, "adv_sib_")
        src = os.path.join(d, "sib.c")
        with open(src, "w") as fh:
            fh.write(SIBLING_DEFECT_C)
        exe = os.path.join(d, "sib")
        subprocess.run(["gcc", "-g", "-O0", src, "-o", exe], check=True)
        p = fixture_popen([exe], stdout=subprocess.PIPE, text=True)
        self.addCleanup(lambda: (p.kill(), p.wait(timeout=5), p.stdout.close()))
        p.stdout.readline()
        obs, _ = RuntimeEvidenceProvider().collect_for_recipe(
            Registry.get_recipe("RECIPE_HEAP_METADATA_CORRUPTION"), p.pid, exe)
        self.assertTrue(obs.get("magic_corrupted"))
        self.assertEqual(obs.get("corruption_hint_variable"), "g_objs[3].magic")
        self.assertEqual(obs.get("expected_magic"), "0xdeadbeef")
        self.assertEqual(obs.get("observed_magic"), "0x41414141")


@unittest.skipUnless(HAVE_CC, "needs gcc and g++")
class AdversarialHealthyMatrixTest(unittest.TestCase):
    """Every adversarial program x every symptom kind: no CONFIRMED/PROBABLE fault, no FAULT/DEGRADED, no finding."""

    @classmethod
    def setUpClass(cls):
        cls.out = temp_dir(cls, "adv_matrix_")
        cls.corpus = os.path.join(cls.out, "corpus")
        cls.bins = {n: adv.build(n, cls.out) for n in adv.programs()}

    def test_at_least_ten_programs_including_cpp(self):
        self.assertGreaterEqual(len(adv.programs()), 10)
        self.assertTrue(any(adv.source_of(n).endswith(".cpp") for n in adv.programs()))

    def _matrix(self, name):
        from extractor.expert_diagnostic_engine import diagnose
        bad = []
        for kind in adv.SYMPTOM_KINDS:
            p = fixture_popen([self.bins[name]], stdout=subprocess.PIPE, text=True)
            try:
                p.stdout.readline()
                time.sleep(0.3)
                r = diagnose(p.pid, self.bins[name], corpus_dir=self.corpus, **adv.diagnose_kwargs(kind)).to_dict()
                v = adv.violations(r)
                if v:
                    bad.append((kind, v))
            finally:
                p.kill()
                p.wait()
                p.stdout.close()
        self.assertEqual(bad, [], f"{name}: healthy program diagnosed as faulty")


def _add_matrix_tests():
    for n in adv.programs():
        setattr(AdversarialHealthyMatrixTest, f"test_{n}", lambda self, n=n: self._matrix(n))


_add_matrix_tests()


if __name__ == "__main__":
    unittest.main()

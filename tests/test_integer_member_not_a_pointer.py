"""An integer whose NAME looks like a pointer is not a pointer, and a low pointer value is not a dereference.

Regression for a false PROBABLE_FAULT on a healthy process (examples/pool_demo.cpp): the member
``int32_t total_buffers`` (value 32) contains "buf", was collected as a pointer candidate, its value 0x20 was taken as
an address inside the NULL page, and RECIPE_INVALID_MEMORY_ACCESS confirmed an access fault because the live
observation carries no ``dereference_attempted`` key (the guard only recognised an explicit ``False``).

Three layers, each tested on its own and end to end with a real process:
* discovery: pointer candidates come from the DWARF type only;
* observation: only the value of a pointer-typed expression becomes an address; a NULL-page pointer value is
  recorded with ``dereference_attempted: False``;
* rule: a low address is a fault only with positive evidence of a dereference - a missing key is not evidence.
"""

import os
import subprocess
import sys
import unittest

from extractor.diagnostic_recipes import (
    RECIPE_STATUS_INSUFFICIENT_EVIDENCE, RECIPE_STATUS_SUPPORTED, DiagnosticRecipeRegistry,
)
from extractor.expert_diagnostic_engine import diagnose
from extractor.runtime_evidence_provider import RuntimeEvidenceProvider
from tests.support.fixture_process import fixture_popen
from tests.support.tmpdirs import temp_dir

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Healthy and idle.  Every integer member is named like something the old name heuristic took for a pointer
# ("ptr", "addr", "payload", "buf", "cache", "record") and holds a small value that would land in the NULL page.
ADVERSARIAL_C = r"""
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
struct Stats {
    int32_t total_buffers;      /* 32 */
    int32_t ptr_count;          /* 7 */
    uint16_t addr_family;       /* 2 */
    int32_t payload_len;        /* 100 */
    int64_t cache_hits;         /* 4000 */
    int32_t record_count;       /* 12 */
    char *name;                 /* a real, valid pointer */
};
struct Stats g_stats;
struct Stats *g_stats_ptr = &g_stats;
int main(void) {
    g_stats.total_buffers = 32; g_stats.ptr_count = 7; g_stats.addr_family = 2; g_stats.payload_len = 100;
    g_stats.cache_hits = 4000; g_stats.record_count = 12; g_stats.name = malloc(64);
    printf("READY\n"); fflush(stdout);
    for (;;) pause();
}
"""

INT_MEMBERS = ("total_buffers", "ptr_count", "addr_family", "payload_len", "cache_hits", "record_count")
FAULT_VERDICTS = ("CONFIRMED_FAULT", "PROBABLE_FAULT", "FAULT", "DEGRADED")


class LowAddressRuleTest(unittest.TestCase):
    """Rule level, no process."""

    def setUp(self):
        self.registry = DiagnosticRecipeRegistry()

    def test_live_observation_shape_is_not_a_fault(self):
        # exactly what the live provider records for a pointer value inside the NULL page, minus the new key:
        # the rule must not read the missing key as "dereferenced"
        obs = {"faulting_address": "0x20", "address": 0x20, "target_address": 0x20, "pointer_value": "0x20",
               "pointer_name": "g.p", "is_mapped": False, "vma_permissions": "---p",
               "violation_type": "NULL_PAGE_POINTER_VALUE"}
        res = self.registry.evaluate_recipe("RECIPE_INVALID_MEMORY_ACCESS", obs)
        self.assertEqual(res.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)
        self.assertFalse(res.details.get("access_fault_confirmed", False))

    def test_explicit_false_and_none_are_not_a_fault(self):
        for value in (False, None):
            with self.subTest(dereference_attempted=value):
                res = self.registry.evaluate_recipe(
                    "RECIPE_INVALID_MEMORY_ACCESS", {"pointer_address": 0x10, "dereference_attempted": value})
                self.assertEqual(res.status, RECIPE_STATUS_INSUFFICIENT_EVIDENCE)

    def test_positive_dereference_evidence_still_confirms(self):
        for extra in ({"dereference_attempted": True}, {"dereferenced": True}, {"fault_context": {"signal": 11}}):
            with self.subTest(extra=extra):
                res = self.registry.evaluate_recipe("RECIPE_INVALID_MEMORY_ACCESS", dict({"pointer_address": 0x10}, **extra))
                self.assertEqual(res.status, RECIPE_STATUS_SUPPORTED)


class IntegerMemberLiveTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = temp_dir(cls)
        cls.corpus = os.path.join(cls.tmp, "corpus")
        cls.bins = {}
        src = os.path.join(cls.tmp, "adversarial.c")
        with open(src, "w") as f:
            f.write(ADVERSARIAL_C)
        cls.bins["adversarial"] = os.path.join(cls.tmp, "adversarial")
        subprocess.run(["gcc", "-g", "-O0", "-o", cls.bins["adversarial"], src], check=True)
        cls.bins["pool_demo"] = os.path.join(cls.tmp, "pool_demo")
        subprocess.run(["g++", "-g", "-O0", "-o", cls.bins["pool_demo"],
                        os.path.join(ROOT, "examples", "pool_demo.cpp")], check=True)

    def _start(self, name):
        proc = fixture_popen([self.bins[name]], stdout=subprocess.PIPE, text=True)
        self.addCleanup(lambda: (proc.kill(), proc.wait(), proc.stdout.close()))
        proc.stdout.readline()
        return proc

    def test_discovery_takes_pointers_from_the_dwarf_type_only(self):
        syms = RuntimeEvidenceProvider(corpus_dir=self.corpus)._discover_dwarf_symbols(self.bins["adversarial"])
        pointers = set(syms["pointers"])
        for member in INT_MEMBERS:
            self.assertNotIn(f"g_stats.{member}", pointers)
        self.assertIn("g_stats.name", pointers)
        self.assertIn("g_stats_ptr", pointers)

    def test_value_of_an_integer_is_never_an_address(self):
        proc = self._start("adversarial")
        prov = RuntimeEvidenceProvider(corpus_dir=self.corpus)
        elf = self.bins["adversarial"]
        for member in INT_MEMBERS:
            item, _ = prov.evaluate_dwarf_expression(proc.pid, elf, f"g_stats.{member}")
            self.assertEqual(item.get("status"), "OBSERVED", member)
            self.assertIsNone(prov._pointer_value(elf, item), member)
        item, _ = prov.evaluate_dwarf_expression(proc.pid, elf, "g_stats.name")
        self.assertGreater(prov._pointer_value(elf, item), 4096)

    def test_healthy_process_with_pointer_like_integer_names_is_not_a_fault(self):
        for name in ("adversarial", "pool_demo"):
            # the general health check, a crash symptom (plans the invalid-access check), and a symptom naming
            # the integer (user-extracted entities are candidates too)
            for symptom in (None, "the process crashes with a segmentation fault",
                            "invalid memory access through total_buffers"):
                with self.subTest(target=name, symptom=symptom):
                    proc = self._start(name)
                    d = diagnose(proc.pid, self.bins[name], symptom, corpus_dir=self.corpus).to_dict()
                    self.assertNotIn(d.get("verdict"), FAULT_VERDICTS, d.get("human_summary"))
                    self.assertEqual(d.get("findings") or [], [])
                    proc.kill()
        # with no symptom nothing else stands in the way of a clean result
        proc = self._start("pool_demo")
        self.assertEqual(diagnose(proc.pid, self.bins["pool_demo"], corpus_dir=self.corpus).to_dict().get("verdict"),
                         "HEALTHY")


if __name__ == "__main__":
    unittest.main()

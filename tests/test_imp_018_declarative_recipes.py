"""IMP-018: declarative recipes (observations + rule, collectors per observation kind), only observed facts as
supporting evidence, and the fd-leak recipe/category defined in one file (extractor/recipe_plugins/fd_leak.py)."""

import inspect
import os
import shutil
import subprocess
import tempfile
import time
import unittest

from extractor import diagnostic_recipes as dr
from extractor import runtime_evidence_provider as rep
from extractor.diagnostic_recipes import (
    BASELINE_RECIPE_IDS,
    DiagnosticRecipe,
    DiagnosticRecipeRegistry,
    RecipeEvaluationResult,
    register_recipe,
)
from extractor.expert_diagnostic_engine import ExpertDiagnosticEngine, diagnose
from extractor.runtime_evidence_provider import RuntimeEvidenceProvider, register_observation_collector
from tests.support.fixture_process import fixture_popen

FD_LEAK_SRC = r"""
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
int main(void) {
    puts("READY"); fflush(stdout);
    for (;;) { open("/dev/null", O_RDONLY); usleep(50000); }
}
"""

NEUTRAL_SRC = r"""
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
enum phase { P_IDLE, P_RUN, P_DONE };
struct bag { void **items; unsigned long n; };
struct bag g_bag;
enum phase g_phase = P_RUN;
int main(void) {
    g_bag.items = calloc(8, sizeof(void *)); g_bag.n = 3;
    puts("READY"); fflush(stdout);
    for (;;) sleep(1);
}
"""

NULL_GLOBALS_SRC = r"""
#include <stdio.h>
#include <unistd.h>
struct node { int v; struct node *next; };
struct node *g_head = NULL;
char *g_buffer = NULL;
int g_worker_state = 999;   /* a plain value, not an observed transition */
int main(void) {
    puts("READY"); fflush(stdout);
    for (;;) sleep(1);
}
"""


def _build(tmp, name, src):
    c = os.path.join(tmp, name + ".c")
    with open(c, "w") as fh:
        fh.write(src)
    out = os.path.join(tmp, name)
    subprocess.check_call(["gcc", "-g", "-O0", "-o", out, c])
    return out


def _start(path):
    p = fixture_popen([path], stdout=subprocess.PIPE)
    p.stdout.readline()
    time.sleep(0.3)
    return p


@unittest.skipUnless(shutil.which("gcc"), "needs gcc")
class TestDeclarativeRecipes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="imp018_")
        cls.fdleak = _build(cls.tmp, "fdleak", FD_LEAK_SRC)
        cls.nullg = _build(cls.tmp, "null_globals", NULL_GLOBALS_SRC)
        cls.neutral = _build(cls.tmp, "neutral", NEUTRAL_SRC)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _proc(self, path):
        p = _start(path)
        self.addCleanup(lambda: (p.kill(), p.wait(timeout=5)))
        return p

    def test_every_recipe_declares_observations_and_a_rule(self):
        recipes = DiagnosticRecipeRegistry.list_recipes()
        self.assertGreaterEqual(len(recipes), 23)
        for r in recipes:
            self.assertTrue(r.observations, r.recipe_id)
            self.assertTrue(r.rule is not None or r.recipe_id in dr._RULES, r.recipe_id)
            for kind in r.observations:
                self.assertTrue(kind in rep.OBSERVATION_COLLECTORS or kind == "process_info", (r.recipe_id, kind))
        self.assertNotIn("rid ==", inspect.getsource(dr._evaluate_specific_recipe_rules))
        self.assertNotIn("rid ==", inspect.getsource(dr._evaluate_specific_recipe))
        self.assertNotIn("recipe_id ==", inspect.getsource(RuntimeEvidenceProvider.collect_for_recipe))
        self.assertIn("rule", DiagnosticRecipe(**{**_minimal_fields(), "recipe_id": "X"}).__dataclass_fields__)

    def test_new_recipe_registers_from_one_definition(self):
        """A recipe plus its new observation kind, defined in one place, runs through the normal pipeline."""
        seen = {}

        def collect_cmdline(provider, ctx):
            with open(f"/proc/{ctx['pid']}/cmdline", "rb") as fh:
                ctx["observation_data"]["cmdline_argc"] = len([a for a in fh.read().split(b"\0") if a])
            seen["called"] = True
            return None

        def rule(recipe, data):
            return RecipeEvaluationResult(recipe_id=recipe.recipe_id, status=dr.RECIPE_STATUS_CONTRADICTED,
                                          confidence=0.9, confidence_basis=f"argc {data.get('cmdline_argc')}")

        register_observation_collector("test_cmdline", collect_cmdline)
        rec = register_recipe(DiagnosticRecipe(**{**_minimal_fields(), "recipe_id": "RECIPE_TEST_IMP018",
                                                  "observations": ("test_cmdline",), "rule": rule}))
        self.addCleanup(lambda: (dr._RECIPES.pop("RECIPE_TEST_IMP018", None),
                                 rep.OBSERVATION_COLLECTORS.pop("test_cmdline", None)))
        p = self._proc(self.nullg)
        data, _ = RuntimeEvidenceProvider().collect_for_recipe(rec, p.pid, companion_elf=self.nullg)
        self.assertTrue(seen.get("called"))
        res = DiagnosticRecipeRegistry.evaluate_recipe(rec, data)
        self.assertEqual(res.status, dr.RECIPE_STATUS_CONTRADICTED)
        self.assertEqual(res.confidence_basis, "argc 1")

    def test_null_globals_and_large_values_are_not_findings(self):
        p = self._proc(self.nullg)
        prov = RuntimeEvidenceProvider()
        for rid in ("RECIPE_INVALID_MEMORY_ACCESS", "RECIPE_UNEXPECTED_NULL_OR_INVALID_POINTERS",
                    "RECIPE_STATE_TRANSITION_VIOLATIONS"):
            rec = DiagnosticRecipeRegistry.get_recipe(rid)
            data, _ = prov.collect_for_recipe(rec, p.pid, companion_elf=self.nullg)
            self.assertNotEqual(data.get("violation_type"), "NULL_POINTER_DEREFERENCE", rid)
            self.assertFalse(data.get("transition_violation"), rid)
            self.assertNotEqual(DiagnosticRecipeRegistry.evaluate_recipe(rec, data).status,
                                dr.RECIPE_STATUS_SUPPORTED, rid)
        res = diagnose(p.pid, debug_image=self.nullg, symptom="the program crashed with SIGSEGV",
                       engine=ExpertDiagnosticEngine(corpus_dir=os.path.join(self.tmp, "c_null")))
        cats = {f["category"] for f in res.findings}
        self.assertNotIn("MEMORY_CORRUPTION", cats)
        self.assertNotIn("UNEXPECTED_STATE_TRANSITIONS", cats)

    def test_fd_leak_is_found_with_its_trend(self):
        self.assertIn("RECIPE_FD_LEAK", BASELINE_RECIPE_IDS)
        p = self._proc(self.fdleak)
        res = diagnose(p.pid, debug_image=self.fdleak,
                       engine=ExpertDiagnosticEngine(corpus_dir=os.path.join(self.tmp, "c_fd")))
        fd = [f for f in res.findings if f["category"] == "FD_LEAK"]
        self.assertTrue(fd, res.findings)
        self.assertIn("/dev/null", fd[0]["subjects"])
        self.assertTrue(any("open fds" in o and "->" in o for o in fd[0]["observed"]), fd[0]["observed"])
        self.assertIn(res.verdict, ("CONFIRMED_FAULT", "PROBABLE_FAULT"))

    def test_structure_based_candidates_without_name_keywords(self):
        syms = RuntimeEvidenceProvider()._discover_dwarf_symbols(self.neutral)
        self.assertIn("g_bag.n", syms["container_counts"])   # pointer + integer count member
        self.assertIn("g_phase", syms["state_vars"])          # enum-typed
        p = self._proc(self.neutral)
        rec = DiagnosticRecipeRegistry.get_recipe("RECIPE_LONG_LIVED_OBJECT_ACCUMULATION")
        data, _ = RuntimeEvidenceProvider().collect_for_recipe(rec, p.pid, companion_elf=self.neutral)
        self.assertEqual(data.get("container_name"), "g_bag.n")
        self.assertEqual(data.get("container_size"), 3)

    def test_idle_process_has_no_fd_leak(self):
        p = self._proc(self.nullg)
        rec = DiagnosticRecipeRegistry.get_recipe("RECIPE_FD_LEAK")
        data, _ = RuntimeEvidenceProvider().collect_for_recipe(rec, p.pid, companion_elf=self.nullg)
        self.assertEqual(len(data["fd_usage"]["samples"]), 3)
        self.assertEqual(DiagnosticRecipeRegistry.evaluate_recipe(rec, data).status, dr.RECIPE_STATUS_CONTRADICTED)


def _minimal_fields():
    return dict(recipe_id="", version="1", name="test", domain=dr.DOMAIN_ABNORMAL_STATE,
                applicable_problem_categories=[dr.CATEGORY_PROCESS_INSTABILITY], required_prerequisites=[],
                evidence_sources=[], collection_steps=[], analysis_rules=[], thresholds_and_conditions={},
                supporting_evidence_criteria=[], contradicting_evidence_criteria=[], verification_procedure="",
                stop_conditions=[], limitations=[], output_structure={})


if __name__ == "__main__":
    unittest.main()

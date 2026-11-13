"""Checks that can never reach a conclusion in zero-stop mode are declared "not supported in this mode".

A recipe whose verdict rule reads values no collector fills in (allocation sizes, a free() history, the allowed
states of a state machine, ...) always ended INCONCLUSIVE.  Such a recipe declares the capability it needs
(``requires_capabilities``); plan construction leaves it out while the mode lacks the capability, and the report lists
its question as "not examined" (kind ``unsupported_in_mode``), also inside the scope of a HEALTHY verdict.

Pure tests (no process): the declaration, the plan content, the producer table, the HEALTHY scope.
Live tests (compiled fixtures): every recipe that stays plannable reaches a conclusion on a real process.
"""

import ast
import os
import shutil
import subprocess
import tempfile
import time
import unittest

from extractor import diagnostic_recipes as dr
from extractor import healthy_verdict as hv
from extractor.diagnostic_methodology import CheckStatus
from extractor.diagnostic_recipes import (
    ALL_PROBLEM_CATEGORIES,
    AVAILABLE_CAPABILITIES,
    BASELINE_RECIPE_IDS,
    CAP_ALLOCATION_TRACING,
    CAPABILITY_DESCRIPTIONS,
    DiagnosticRecipe,
    DiagnosticRecipeRegistry as Registry,
    register_recipe,
)
from extractor.expert_diagnostic_engine import ExpertDiagnosticEngine, InvestigationPlanner, ProblemClassifier, diagnose

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The six checks of the roadmap (stage 1, row 4) plus the shared-state check: what each needs and why.
UNSUPPORTED = {
    "RECIPE_USE_AFTER_FREE": "allocation_tracing",
    "RECIPE_SUSPICIOUS_ALLOCATION_PATTERNS": "allocation_tracing",
    "RECIPE_OBJECT_LIFETIME_ANOMALIES": "allocation_tracing",
    "RECIPE_UNEXPECTED_VARIABLE_CHANGES": "caller_specification",
    "RECIPE_STATE_TRANSITION_VIOLATIONS": "caller_specification",
    "RECIPE_SHARED_STATE_INCONSISTENCIES": "stopped_snapshot",
}

# Input keys with which a rule can reach SUPPORTED / CONTRADICTED, as alternatives (each group: all keys needed).
# Traced from the rule code (extractor/diagnostic_recipes.py ``_rule_*``) to the collectors in this table's test.
DECISIVE_INPUTS = {
    # recipes that stay plannable: some group must be producible
    "RECIPE_INVALID_MEMORY_ACCESS": [{"is_healthy"}, {"faulting_address", "is_mapped"}],
    "RECIPE_INVALID_FREE": [{"allocator_inspector", "target_address"}],
    "RECIPE_HEAP_METADATA_CORRUPTION": [{"magic_corrupted"}],
    "RECIPE_PROCESS_MEMORY_GROWTH": [{"rss_history_kb", "epoch_count"}],
    "RECIPE_HEAP_GROWTH": [{"heap_series_kb", "epoch_count"}],
    "RECIPE_ALLOCATION_FREE_IMBALANCE": [{"alloc_count", "free_count"}],
    "RECIPE_REPEATED_ALLOCATION_PATTERNS": [{"alloc_delta", "free_delta"}],
    "RECIPE_LONG_LIVED_OBJECT_ACCUMULATION": [{"container_size"}],
    "RECIPE_INCONSISTENT_RELATED_VARIABLES": [{"capacity", "length"}],
    "RECIPE_UNEXPECTED_NULL_OR_INVALID_POINTERS": [{"pointer_value", "is_mapped"}],
    "RECIPE_SUSPICIOUS_BOUNDARY_VALUES": [{"observed_value"}],
    "RECIPE_THREAD_STATE_ANOMALIES": [{"threads_healthy"}, {"runaway_threads"}],
    "RECIPE_SUSPICIOUS_LOCK_OWNERSHIP": [{"callstacks_info"}],
    "RECIPE_POTENTIAL_DEADLOCK_PATTERNS": [{"callstacks_info"}],
    "RECIPE_LONG_RUNNING_BLOCKED_THREADS": [{"thread_sampling"}],
    # recipes that are declared unsupported: no group may be producible
    "RECIPE_USE_AFTER_FREE": [{"in_freelist"}, {"is_freed_object"}, {"is_freed"}, {"has_lifetime_evidence"},
                              {"lifetime_evidence_available"}, {"quarantine_record_found"},
                              {"target_slot_status"}, {"is_active_chunk"}],
    "RECIPE_SUSPICIOUS_ALLOCATION_PATTERNS": [{"requested_bytes"}, {"allocation_size"}],
    "RECIPE_OBJECT_LIFETIME_ANOMALIES": [{"lifetime_expired"}, {"dangling_reference"}, {"lifetime_valid"}],
    "RECIPE_UNEXPECTED_VARIABLE_CHANGES": [{"valid_range"}, {"expected_bounds"}, {"out_of_bounds"}],
    "RECIPE_STATE_TRANSITION_VIOLATIONS": [{"allowed_states"}, {"allowed_transitions"}, {"state_specification"},
                                           {"transition_violation"}, {"is_illegal_transition"}],
    "RECIPE_SHARED_STATE_INCONSISTENCIES": [{"shared_invariant_violated"}, {"torn_shared_state"},
                                            {"shared_invariant_intact"}],
}

# Keys the engine adds to every rule's input (not collector output).
_ENGINE_CONTEXT = {"allocator_inspector", "allocator", "structural_discovery", "invariant_evaluator",
                   "concurrency_graph", "wait_for_graph", "observation_window", "window", "pid", "companion_elf"}
_COLLECTOR_FILES = ("runtime_evidence_provider.py", "memory_integrity.py", "thread_sampler.py", "leak_attribution.py")


def _string_constants(path):
    with open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read())
    return {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)}


def _producible_keys():
    keys = set(_ENGINE_CONTEXT)
    for f in _COLLECTOR_FILES:
        keys |= _string_constants(os.path.join(ROOT, "extractor", f))
    return keys


def _rule_read_keys(rule):
    """Every literal key a verdict rule reads from its input dict (second parameter)."""
    import inspect
    import textwrap
    tree = ast.parse(textwrap.dedent(inspect.getsource(rule)))
    fn = tree.body[0]
    param = fn.args.args[1].arg
    out = set()
    for x in ast.walk(fn):
        if (isinstance(x, ast.Call) and isinstance(x.func, ast.Attribute) and x.func.attr == "get"
                and isinstance(x.func.value, ast.Name) and x.func.value.id == param
                and x.args and isinstance(x.args[0], ast.Constant)):
            out.add(x.args[0].value)
        if (isinstance(x, ast.Subscript) and isinstance(x.value, ast.Name) and x.value.id == param
                and isinstance(x.slice, ast.Constant)):
            out.add(x.slice.value)
        if (isinstance(x, ast.Compare) and isinstance(x.left, ast.Constant) and isinstance(x.left.value, str)
                and isinstance(x.comparators[0], ast.Name) and x.comparators[0].id == param):
            out.add(x.left.value)
    return out


def _core_rule(recipe):
    return recipe.rule or dr._RULES.get(recipe.recipe_id)


class TestDeclaration(unittest.TestCase):
    def test_exactly_the_unsupported_recipes_declare_a_capability(self):
        declared = {r.recipe_id: r.requires_capabilities[0] for r in Registry.list_recipes() if r.requires_capabilities}
        self.assertEqual(declared, UNSUPPORTED)
        for rid in UNSUPPORTED:
            r = Registry.get_recipe(rid)
            self.assertIn(r.requires_capabilities[0], CAPABILITY_DESCRIPTIONS)
            self.assertTrue(r.unsupported_question.endswith(")") or r.unsupported_question.endswith("?"), rid)
            self.assertFalse(Registry.is_plannable(r))
            self.assertIsNone(Registry.get_plannable_recipe(rid))
            self.assertIsNotNone(Registry.get_recipe(rid), "the recipe is kept, only left out of plans")

    def test_no_baseline_recipe_needs_a_capability_and_registration_refuses_it(self):
        for rid in BASELINE_RECIPE_IDS:
            self.assertEqual(Registry.get_recipe(rid).requires_capabilities, (), rid)
            self.assertTrue(Registry.is_plannable(rid))
        fields = {f: getattr(Registry.get_recipe("RECIPE_HEAP_GROWTH"), f)
                  for f in DiagnosticRecipe.__dataclass_fields__ if f != "rule"}
        fields.update(recipe_id="RECIPE_TEST_BASELINE_CAP", requires_capabilities=(CAP_ALLOCATION_TRACING,))
        with self.assertRaises(ValueError):
            register_recipe(DiagnosticRecipe(**fields), baseline=True)
        self.assertNotIn("RECIPE_TEST_BASELINE_CAP", dr._RECIPES)
        self.assertNotIn("RECIPE_TEST_BASELINE_CAP", BASELINE_RECIPE_IDS)

    def test_a_provided_capability_makes_the_recipe_plannable_again(self):
        old = dr.AVAILABLE_CAPABILITIES
        dr.AVAILABLE_CAPABILITIES = frozenset({CAP_ALLOCATION_TRACING})
        try:
            self.assertTrue(Registry.is_plannable("RECIPE_USE_AFTER_FREE"))
            self.assertFalse(Registry.is_plannable("RECIPE_UNEXPECTED_VARIABLE_CHANGES"))
            self.assertIn("RECIPE_USE_AFTER_FREE", {r.recipe_id for r in Registry.list_recipes(plannable_only=True)})
        finally:
            dr.AVAILABLE_CAPABILITIES = old
        self.assertEqual(AVAILABLE_CAPABILITIES, frozenset())
        self.assertFalse(Registry.is_plannable("RECIPE_USE_AFTER_FREE"))

    def test_to_dict_and_from_dict_keep_the_declaration(self):
        r = Registry.get_recipe("RECIPE_USE_AFTER_FREE")
        d = r.to_dict()
        self.assertEqual(d["requires_capabilities"], ["allocation_tracing"])
        self.assertEqual(DiagnosticRecipe.from_dict(d).requires_capabilities, ("allocation_tracing",))


class TestPlanContent(unittest.TestCase):
    SYMPTOMS = ("", "general health check", "the service stopped responding", "memory leak growing",
                "deadlock between threads", "random crash with corrupted data", "variable has an unexpected value",
                "state machine is in the wrong state", "data race on shared state", "use after free",
                "object lifetime problem", "suspicious allocation sizes", "something is wrong")

    def _ids(self, symptom):
        return [s.recipe_id for s in InvestigationPlanner().create_plan(ProblemClassifier().classify(symptom), None).steps]

    def test_default_symptom_plan_has_no_unexpected_variable_change_noise(self):
        for symptom in ("", "general health check", "something is wrong"):
            with self.subTest(symptom=symptom):
                ids = self._ids(symptom)
                self.assertNotIn("RECIPE_UNEXPECTED_VARIABLE_CHANGES", ids)
                self.assertTrue(set(BASELINE_RECIPE_IDS) <= set(ids))
                self.assertTrue(ids)

    def test_no_plan_contains_a_recipe_the_mode_cannot_execute(self):
        for symptom in self.SYMPTOMS:
            with self.subTest(symptom=symptom):
                ids = self._ids(symptom)
                self.assertFalse(set(ids) & set(UNSUPPORTED), set(ids) & set(UNSUPPORTED))
                self.assertEqual(len(ids), len(set(ids)))
                self.assertTrue(all(Registry.is_plannable(i) for i in ids))

    def test_no_category_selects_an_unsupported_recipe(self):
        for cat in sorted(ALL_PROBLEM_CATEGORIES):
            got = {r.recipe_id for r in Registry.get_recipes_for_category(cat, plannable_only=True)}
            self.assertFalse(got & set(UNSUPPORTED), cat)

    def test_symptom_specific_plans_keep_their_supported_recipes(self):
        self.assertIn("RECIPE_HEAP_GROWTH", self._ids("memory leak growing"))
        self.assertIn("RECIPE_POTENTIAL_DEADLOCK_PATTERNS", self._ids("deadlock between threads"))
        self.assertIn("RECIPE_SUSPICIOUS_BOUNDARY_VALUES", self._ids("variable has an unexpected value"))


class TestEveryInputHasAProducer(unittest.TestCase):
    """The static equivalent of "no check is inconclusive by construction": the inputs with which a rule can
    conclude must be filled in by a collector; for the recipes declared unsupported they must not be."""

    @classmethod
    def setUpClass(cls):
        cls.producible = _producible_keys()

    def test_every_plannable_core_recipe_has_a_producible_decisive_input(self):
        for r in Registry.list_recipes(plannable_only=True):
            if r.recipe_id not in DECISIVE_INPUTS:
                continue  # plugin recipes: their collector is in the same file; covered by the live test
            with self.subTest(recipe=r.recipe_id):
                self.assertTrue(any(g <= self.producible for g in DECISIVE_INPUTS[r.recipe_id]),
                                f"no collector fills in any input with which {r.recipe_id} can conclude")

    def test_every_decisive_input_is_read_by_the_rule(self):
        for rid, groups in DECISIVE_INPUTS.items():
            rule = _core_rule(Registry.get_recipe(rid))
            read = _rule_read_keys(rule)
            for g in groups:
                with self.subTest(recipe=rid, group=sorted(g)):
                    self.assertTrue(g <= read, f"{rid}: the rule does not read {sorted(g - read)}")

    def test_declared_unsupported_recipes_really_lack_a_producer(self):
        for rid in UNSUPPORTED:
            with self.subTest(recipe=rid):
                for g in DECISIVE_INPUTS[rid]:
                    self.assertFalse(g <= self.producible,
                                     f"{sorted(g)} is now produced: {rid} may no longer need its declared capability")

    def test_every_plannable_recipe_has_a_rule_and_registered_observations(self):
        from extractor.runtime_evidence_provider import OBSERVATION_COLLECTORS
        for r in Registry.list_recipes(plannable_only=True):
            with self.subTest(recipe=r.recipe_id):
                self.assertIsNotNone(_core_rule(r))
                for kind in r.observations:
                    self.assertTrue(kind in OBSERVATION_COLLECTORS or kind == "process_info")


class _Check:
    def __init__(self, rid, status):
        self.recipe_id, self.status = rid, status
        self.limitations, self.missing_evidence, self.actual_observations = [], [], {}
        self.technical_interpretation = "looked, nothing there"


class TestHealthyScope(unittest.TestCase):
    def _scope(self, not_covered, statuses=None):
        statuses = statuses or {}
        checks = [_Check(rid, statuses.get(rid, CheckStatus.PASS)) for rid in BASELINE_RECIPE_IDS]
        return hv.evaluate(verdict="HEALTHY", findings=[], checks=checks, not_covered=not_covered,
                           baseline_ids=BASELINE_RECIPE_IDS)

    def _nc(self):
        return [{"kind": "unsupported_in_mode", "item": "RECIPE_USE_AFTER_FREE,RECIPE_OBJECT_LIFETIME_ANOMALIES",
                 "capability": "allocation_tracing", "reason": "not supported in this mode: needs allocation tracing"},
                {"kind": "unsupported_in_mode", "item": "RECIPE_UNEXPECTED_VARIABLE_CHANGES",
                 "capability": "caller_specification", "reason": "x"}]

    def test_unexamined_questions_are_listed_in_the_healthy_scope_and_do_not_block(self):
        scope = self._scope(self._nc())
        self.assertTrue(scope["healthy"], scope["blocking"])
        items = [x for x in scope["not_checked"] if x["kind"] == "unsupported_in_mode"]
        self.assertEqual(len(items), 2)
        self.assertIn("use after free", items[0]["label"])
        self.assertIn("allocation tracing", items[0]["label"])
        self.assertIn("not examined", items[0]["label"])
        self.assertTrue(items[0]["label_ko"] and items[0]["label_ko"] != items[0]["label"])
        self.assertIn("unexpected variable changes", items[1]["label"])
        self.assertEqual(scope["not_checked"][-1]["kind"], "outside_baseline")

    def test_excluding_checks_never_clears_a_failing_or_undecided_baseline_check(self):
        for st in (CheckStatus.FAIL, CheckStatus.INCONCLUSIVE):
            scope = self._scope(self._nc(), {"RECIPE_PROCESS_MEMORY_GROWTH": st})
            self.assertFalse(scope["healthy"], st)
        no_baseline = hv.evaluate(verdict="HEALTHY", findings=[], checks=[], not_covered=self._nc(),
                                  baseline_ids=BASELINE_RECIPE_IDS)
        self.assertFalse(no_baseline["healthy"])

    def test_the_summary_sentence_names_the_unexamined_questions(self):
        s = hv.summary_sentence(self._scope(self._nc()), len(BASELINE_RECIPE_IDS), max_items=5)
        self.assertIn("Not checked:", s)
        self.assertIn("not examined: use after free", s)

    def test_kind_is_a_declared_scope_kind(self):
        self.assertIn("unsupported_in_mode", hv.SCOPE_KINDS)
        self.assertNotIn("unsupported_in_mode", hv.BLOCKING_KINDS)


class TestReportRendering(unittest.TestCase):
    """The not-examined questions are shown in the HTML check list and the human report, in both languages."""

    NC = [{"kind": "unsupported_in_mode", "item": "RECIPE_USE_AFTER_FREE,RECIPE_OBJECT_LIFETIME_ANOMALIES",
           "capability": "allocation_tracing", "reason": "not supported in this mode: needs allocation tracing"}]

    def _result(self):
        chk = {"check_id": "CHK_1", "recipe_id": "RECIPE_FD_LEAK", "name": "fd", "status": "PASS",
               "technical_rationale": "RESOURCE", "technical_interpretation": "fds stable", "limitations": [],
               "missing_evidence": [], "duration_seconds": 0.01, "actual_observations": {}}
        return {"verdict": "INCONCLUSIVE", "confidence": 0.5, "findings": [], "not_covered": list(self.NC),
                "checks_run": [{"recipe_id": "RECIPE_FD_LEAK", "status": "PASS"}],
                "collection_impact": {"measured_stop_ms": 0.0, "zero_stop": True, "bytes_read": 1},
                "target": {"pid": 42, "process_name": "demo"}, "duration_s": 1.0,
                "report": {"section_d_detailed_inspection_results": {"checks": [chk]}}}

    def test_html_check_list_says_not_examined_in_both_languages(self):
        from extractor.report_visuals import build_visual_summary
        en = build_visual_summary(self._result(), self._result()["report"], "en")
        ko = build_visual_summary(self._result(), self._result()["report"], "ko")
        html_en = en if isinstance(en, str) else str(en)
        html_ko = ko if isinstance(ko, str) else str(ko)
        self.assertIn("RECIPE_USE_AFTER_FREE,RECIPE_OBJECT_LIFETIME_ANOMALIES", html_en)
        self.assertIn("not examined", html_en)
        self.assertIn("allocation tracing", html_en)
        self.assertIn("점검하지 않음", html_ko)
        self.assertIn("할당 추적", html_ko)
        self.assertNotIn("not supported in this mode", html_ko)

    def test_human_report_lists_them_in_the_not_examined_section(self):
        from extractor import human_report
        res = self._result()
        for lang, needle in (("en", "Not examined"), ("ko", "점검하지 않은 항목")):
            text = human_report.render_human_report(res, res["report"], lang)
            self.assertIn("RECIPE_USE_AFTER_FREE", text, lang)
            self.assertIn(needle, text, lang)


FIXTURE_HEALTHY = r"""
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
enum phase { P_IDLE, P_RUN };
struct bag { void **items; unsigned long n; };
struct bag g_bag;
enum phase g_phase = P_RUN;
int *g_ptr;
unsigned long g_alloc_count = 5, g_free_count = 5;
unsigned long g_capacity = 64, g_length = 3;
unsigned int g_magic = 0x600dcafe;
int g_mode = 7;
pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static void *worker(void *a) {
    for (;;) { pthread_mutex_lock(&g_lock); g_length = 3; pthread_mutex_unlock(&g_lock); usleep(20000); }
}
int main(void) {
    pthread_t t; pthread_create(&t, 0, worker, 0);
    g_bag.items = calloc(8, sizeof(void *)); g_bag.n = 3;
    g_ptr = malloc(64);
    puts("READY"); fflush(stdout);
    for (;;) sleep(1);
}
"""

# Values that only the positive branches of the rules react to: a sentinel state value, a length above its
# capacity, an allocation counter that climbs while the free counter stays at zero.
FIXTURE_ANOMALOUS = r"""
#include <stdio.h>
#include <unistd.h>
int g_mode = -1;
unsigned long g_alloc_count = 0, g_free_count = 0;
unsigned long g_capacity = 8, g_length = 20;
int main(void) {
    puts("READY"); fflush(stdout);
    for (;;) { g_alloc_count++; usleep(500); }
}
"""

_INCONCLUSIVE = ("INCONCLUSIVE", "ERROR", "NOT_APPLICABLE", "UNSUPPORTED", "NOT_EXECUTED", "SKIPPED")


@unittest.skipUnless(shutil.which("gcc"), "needs gcc")
class TestLiveEveryPlannableRecipeConcludes(unittest.TestCase):
    """Runs every recipe that is still plannable against real processes.  A recipe that never reaches a verdict
    on any of them is inconclusive by construction and must declare its missing capability instead."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="unsupported_recipes_")
        cls.exe = {}
        for name, src in (("healthy", FIXTURE_HEALTHY), ("anomalous", FIXTURE_ANOMALOUS)):
            c = os.path.join(cls.tmp, name + ".c")
            with open(c, "w") as fh:
                fh.write(src)
            cls.exe[name] = os.path.join(cls.tmp, name)
            subprocess.check_call(["gcc", "-g", "-O0", "-pthread", "-o", cls.exe[name], c])
        cls.engine = ExpertDiagnosticEngine(corpus_dir=os.path.join(cls.tmp, "corpus"))

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def _start(self, name):
        p = subprocess.Popen([self.exe[name]], stdout=subprocess.PIPE)
        p.stdout.readline()
        time.sleep(0.3)
        self.addCleanup(lambda: (p.kill(), p.wait(timeout=5)))
        return p

    def test_every_plannable_recipe_reaches_a_conclusion_on_a_live_process(self):
        conclusive = {}
        for name in ("healthy", "anomalous"):
            p = self._start(name)
            for r in Registry.list_recipes(plannable_only=True):
                res = self.engine.run_recipe(r.recipe_id, pid=p.pid, companion_elf=self.exe[name])
                st = str(res["status"])
                if st not in _INCONCLUSIVE:
                    conclusive.setdefault(r.recipe_id, []).append((name, st))
        # a recipe that compares counters across the session's epochs needs a diagnosis of several checks
        p = self._start("anomalous")
        res = diagnose(p.pid, self.exe["anomalous"], "memory leak growing")
        for c in res.checks_run:
            if str(c["status"]) not in _INCONCLUSIVE:
                conclusive.setdefault(c["recipe_id"], []).append(("diagnose", str(c["status"])))
        never = [r.recipe_id for r in Registry.list_recipes(plannable_only=True) if r.recipe_id not in conclusive]
        self.assertEqual(never, [], f"inconclusive on every fixture: {never}")

    def test_default_symptom_diagnosis_runs_none_of_them_and_lists_them_as_not_examined(self):
        p = self._start("healthy")
        res = diagnose(p.pid, self.exe["healthy"], "general health check")
        ran = {c["recipe_id"] for c in res.checks_run}
        self.assertFalse(ran & set(UNSUPPORTED), ran & set(UNSUPPORTED))
        self.assertNotIn("RECIPE_UNEXPECTED_VARIABLE_CHANGES", ran)
        rows = [n for n in res.not_covered if n["kind"] == "unsupported_in_mode"]
        listed = {x for n in rows for x in n["item"].split(",")}
        self.assertEqual(listed, set(UNSUPPORTED))
        for n in rows:
            self.assertTrue(n["reason"].startswith("not supported in this mode"), n)
        self.assertFalse([n for n in res.not_covered if n["kind"] == "recipes_not_planned"
                          and set(n["item"].split(",")) & set(UNSUPPORTED)])
        if res.verdict == "HEALTHY":
            kinds = [x["kind"] for x in res.healthy_scope["not_checked"]]
            self.assertEqual(kinds.count("unsupported_in_mode"), 3)
        # no check ended undecided only because the mode cannot answer it
        self.assertFalse([c for c in res.checks_run
                          if c["recipe_id"] in UNSUPPORTED and str(c["status"]) in _INCONCLUSIVE])


if __name__ == "__main__":
    unittest.main()

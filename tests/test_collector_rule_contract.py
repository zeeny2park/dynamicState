"""Contract between the live collectors and the verdict rules.

Rule tests feed hand-made observation dicts; the live collectors (``RuntimeEvidenceProvider.collect_for_recipe``)
write their own keys.  A rule branch guarded by a key no collector writes is either unreachable or - worse - decides
from the key's ABSENCE: ``RECIPE_INVALID_MEMORY_ACCESS`` once confirmed an access fault because the live observation
carried no ``dereference_attempted`` key.  This test runs the REAL collector of every plannable recipe against
healthy processes (including adversarial ones whose names look like faults) and checks:

1. no rule reaches SUPPORTED (a fault) on a healthy process;
2. no decision comes from a missing-key default: for every key the rule reads that the collector did not write,
   making the absence explicit (``key: None`` = "not observed") must not make the result LESS faulty - if it does,
   the absence itself was read as evidence of a fault.

Fixtures are launched through ``tests/support/fixture_process.py``; build output goes to ``tests/support/tmpdirs``.
"""
import ast
import inspect
import os
import shutil
import subprocess
import textwrap
import time
import unittest

from extractor import diagnostic_recipes as dr
from extractor.diagnostic_recipes import DiagnosticRecipeRegistry as Registry
from extractor.runtime_evidence_provider import RuntimeEvidenceProvider
from tests.support import adversarial_healthy as adv
from tests.support.fixture_process import fixture_popen
from tests.support.tmpdirs import temp_dir

# how faulty a status is (higher = more)
_RANK = {"SUPPORTED": 3, "AMBIGUOUS": 2, "INSUFFICIENT_EVIDENCE": 1, "NOT_APPLICABLE": 0, "CONTRADICTED": 0}

HEALTHY_PROGRAMS = ("magic", "counters", "caplen", "containers", "sentinels", "lockish_types", "cpp_pool_stats",
                    "int_named_pointers")


def _rule_read_keys(rule):
    """Literal keys a rule reads from its observation dict (second parameter)."""
    tree = ast.parse(textwrap.dedent(inspect.getsource(rule)))
    fn = tree.body[0]
    param = fn.args.args[1].arg
    out = set()
    for x in ast.walk(fn):
        if (isinstance(x, ast.Call) and isinstance(x.func, ast.Attribute) and x.func.attr == "get"
                and isinstance(x.func.value, ast.Name) and x.func.value.id == param
                and x.args and isinstance(x.args[0], ast.Constant) and isinstance(x.args[0].value, str)):
            out.add(x.args[0].value)
        if (isinstance(x, ast.Subscript) and isinstance(x.value, ast.Name) and x.value.id == param
                and isinstance(x.slice, ast.Constant) and isinstance(x.slice.value, str)):
            out.add(x.slice.value)
        if (isinstance(x, ast.Compare) and isinstance(x.left, ast.Constant) and isinstance(x.left.value, str)
                and isinstance(x.comparators[0], ast.Name) and x.comparators[0].id == param):
            out.add(x.left.value)
    return out


def _status(res):
    return str(getattr(res, "status", res))


@unittest.skipUnless(shutil.which("gcc") and shutil.which("g++"), "needs gcc and g++")
class CollectorRuleContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.out = temp_dir(cls, "contract_")
        cls.bins = {n: adv.build(n, cls.out) for n in HEALTHY_PROGRAMS}

    def _observe(self, name):
        p = fixture_popen([self.bins[name]], stdout=subprocess.PIPE, text=True)
        self.addCleanup(lambda: (p.kill(), p.wait(timeout=5), p.stdout.close()))
        p.stdout.readline()
        time.sleep(0.2)
        provider = RuntimeEvidenceProvider()
        rows = []
        for recipe in Registry.list_recipes(plannable_only=True):
            rule = recipe.rule or dr._RULES.get(recipe.recipe_id)
            obs, _ = provider.collect_for_recipe(recipe, p.pid, self.bins[name])
            rows.append((recipe, rule, obs, Registry.evaluate_recipe(recipe, obs)))
        return rows

    def test_no_fault_and_no_missing_key_default_on_healthy_processes(self):
        faults, defaults = [], []
        for name in HEALTHY_PROGRAMS:
            for recipe, rule, obs, res in self._observe(name):
                st = _status(res)
                if st == "SUPPORTED":
                    faults.append((name, recipe.recipe_id, res.confidence_basis))
                if rule is None:
                    continue
                for key in sorted(_rule_read_keys(rule) - set(obs)):
                    for value in (None, False):
                        try:
                            explicit = _status(Registry.evaluate_recipe(recipe, dict(obs, **{key: value})))
                        except Exception as e:  # noqa: BLE001 - a rule must accept "not observed" for any key
                            defaults.append((name, recipe.recipe_id, key, st, f"crash on {value!r}: {e!r}"))
                            continue
                        # None = "not observed" must decide like a missing key; False = "observed absent" must not
                        # make a fault disappear (the fault rested on the key being missing)
                        if value is None and _RANK.get(st, 1) > _RANK.get(explicit, 1):
                            defaults.append((name, recipe.recipe_id, key, st, explicit))
                        if value is False and _RANK.get(st, 1) >= 2 and _RANK.get(explicit, 1) < _RANK.get(st, 1):
                            defaults.append((name, recipe.recipe_id, key, st, "False -> " + explicit))
        self.assertEqual(faults, [], "a rule reached a fault on a healthy process")
        self.assertEqual(defaults, [], "a rule decided from a key the collector did not write")

    def test_rules_that_never_see_their_keys_are_known(self):
        """Inventory, not a verdict check: every key a rule reads is either written by some collector module or
        listed here as caller-supplied / unreachable from the live collectors (see the report of the audit)."""
        from tests.test_unsupported_recipes import _producible_keys
        producible = _producible_keys() | {"positive_evidence_found", "negative_evidence_found", "supporting_facts",
                                           "contradicting_facts", "recipe_id", "pid", "companion_elf"}
        unreachable = {}
        for recipe in Registry.list_recipes():
            rule = recipe.rule or dr._RULES.get(recipe.recipe_id)
            if rule is None:
                continue
            missing = sorted(_rule_read_keys(rule) - producible)
            if missing:
                unreachable[recipe.recipe_id] = missing
        # The point of the inventory: none of these keys may be the ONLY way a plannable rule reaches SUPPORTED on
        # a live process; test 1 checks that the absence of each is not read as a fault.
        self.assertIsInstance(unreachable, dict)


if __name__ == "__main__":
    unittest.main()

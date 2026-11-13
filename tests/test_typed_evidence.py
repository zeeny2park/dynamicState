"""Stage 1 (rows 1-2): hypothesis verification reads typed evidence, never words inside rendered evidence.

* the typed evidence spec (extractor.typed_evidence): fields, round trip, claims per invariant, criteria families;
* wording independence: the same observations with every human-readable string replaced (by neutral text, and by
  text full of the words the former string search looked for) give the same hypothesis verdicts and the same
  per-criterion supporting / contradicting classification;
* a static guard: no substring / case-folding / regex test on rendered evidence in the verification path.

Pure unit tests: no target process, no live reads.
"""

import ast
import copy
import inspect
import os
import shutil
import tempfile
import textwrap
import unittest
from types import SimpleNamespace
from typing import Any, Dict, List, Tuple

from extractor import healthy_verdict, typed_evidence
from extractor.diagnostic_recipes import ALL_PROBLEM_CATEGORIES, DiagnosticRecipeRegistry
from extractor.expert_diagnostic_engine import AdaptiveInvestigationSession
from extractor.typed_evidence import (
    CATEGORY_FAMILY,
    FAMILY_CORRUPTION,
    FAMILY_DEADLOCK,
    FAMILY_GENERIC,
    FAMILY_GROWTH,
    FAMILY_STATE,
    HOLDS,
    INCOMPLETE_LOCK_GRAPH,
    INV_ADDRESS_VALID,
    INV_MEMORY_BOUNDED,
    INV_NO_CIRCULAR_WAIT,
    INV_NO_POISON,
    INV_STATE_LEGAL,
    POLARITY_CONTRADICTS,
    POLARITY_SUPPORTS,
    TYPED_EVIDENCE_KEY,
    VIOLATED,
    TypedEvidence,
    attach_typed_evidence,
    criteria_family,
    derive_typed_evidence,
    typed_evidence_of,
)

# Every word the former verification string search (and the clean / inconclusive statement checks) looked for.
LEGACY_WORDS = ("growth leak stable plateau deadlock blocked acyclic no circular wait NULL unmapped validly mapped "
                "magic poison clean valid transition boundary authorized within bounds inconclusive "
                "No abnormal runtime indicators observed")


def _evidence_from_recipe(recipe_id: str, data: Dict[str, Any], n: int, symbol: str = None) -> List[Dict[str, Any]]:
    """Evidence dicts for one recipe evaluation, built as AdaptiveInvestigationSession._step_collect_next does."""
    recipe = DiagnosticRecipeRegistry.get_recipe(recipe_id)
    res = DiagnosticRecipeRegistry.evaluate_recipe(recipe, dict(data))
    obs = dict(data)
    observed = obs.get("observed_value") if obs.get("observed_value") is not None else obs
    base = {"recipe_id": recipe.recipe_id, "domain": recipe.domain, "finding_classification": "OBSERVED_FACT",
            "details": res.details, "raw_observation": obs, "symbol": symbol,
            "correlation": {"source_context": ["int g_magic_canary = 0; /* poison NULL growth deadlock */"]},
            "step_id": "step_%02d" % n, "provenance_class": "LIVE_RUNTIME_CAPTURE"}
    out = []
    for i, fact in enumerate(res.supporting_facts):
        out.append(dict(base, evidence_id="ev_s_%d_%d" % (n, i), status="SUPPORTED", finding=fact,
                        problem_category=res.details.get("finding_category") or recipe.problem_category,
                        observed_value=observed))
    for i, fact in enumerate(res.contradicting_facts):
        out.append(dict(base, evidence_id="ev_c_%d_%d" % (n, i), status="CONTRADICTED", counter_indicator=fact,
                        problem_category=recipe.problem_category, observed_value=obs.get("observed_value")))
    if not out:
        out.append(dict(base, evidence_id="ev_b_%d" % n, status=res.status, problem_category=recipe.problem_category,
                        observed_value=observed))
    return [attach_typed_evidence(e) for e in out]


# (recipe id, observation, subject) - one observation per recipe; categories end up in separate hypotheses
SCENARIOS: Dict[str, List[Tuple[str, Dict[str, Any], Any]]] = {
    "unmapped_access": [("RECIPE_INVALID_MEMORY_ACCESS",
                         {"faulting_address": "0xbaadf00d", "is_mapped": False, "vma_permissions": "---p"}, None)],
    "invalid_free_on_stack": [("RECIPE_INVALID_FREE", {"pointer_address": 4096, "vma_name": "[stack]"}, None)],
    "null_pointer_in_active_state": [("RECIPE_UNEXPECTED_NULL_OR_INVALID_POINTERS",
                                      {"pointer_value": "0x0", "is_active_lifecycle": True}, "g_cfg.data")],
    "valid_mapped_pointer": [("RECIPE_INVALID_MEMORY_ACCESS",
                              {"faulting_address": "0x55550000", "is_mapped": True, "vma_permissions": "rw-p"}, None)],
    "rss_growth": [("RECIPE_PROCESS_MEMORY_GROWTH",
                    {"rss_history_kb": [10000, 12000, 14000, 16000], "epoch_count": 4}, None)],
    "heap_stable": [("RECIPE_HEAP_GROWTH", {"heap_series_kb": [100, 100, 100], "epoch_count": 3}, None)],
    "deadlock_persistent": [("RECIPE_POTENTIAL_DEADLOCK_PATTERNS",
                             {"thread_locks": {"1": {"holding": ["A"], "waiting_for": "B"},
                                               "2": {"holding": ["B"], "waiting_for": "A"}},
                              "is_persistent": True, "observation_count": 3}, None)],
    "lock_graph_acyclic": [("RECIPE_POTENTIAL_DEADLOCK_PATTERNS",
                            {"thread_locks": {"1": {"holding": ["A"]}, "2": {"waiting_for": "A"}}}, None)],
    "lock_graph_incomplete": [("RECIPE_POTENTIAL_DEADLOCK_PATTERNS",
                               {"thread_locks": {"1": {"waiting_for": "A"}}, "incomplete_lock_graph": True}, None)],
    "illegal_transition": [("RECIPE_STATE_TRANSITION_VIOLATIONS",
                            {"allowed_states": [0, 1, 2], "current_state": 9, "state_before": 1}, "g_state")],
    "value_out_of_bounds": [("RECIPE_UNEXPECTED_VARIABLE_CHANGES",
                             {"current_value": 500, "valid_range": [0, 100]}, "g_level")],
    "value_within_bounds": [("RECIPE_UNEXPECTED_VARIABLE_CHANGES",
                             {"current_value": 50, "valid_range": [0, 100]}, "g_level")],
    "canary_hint_only": [("RECIPE_HEAP_METADATA_CORRUPTION",
                          {"magic_corrupted": True, "observed_magic": "0xdeadbeef",
                           "corruption_hint_source": "variable_name_poison_value",
                           "corruption_hint_variable": "g_magic_canary"}, None)],
    "mixed_corruption_and_refuted_leak": [
        ("RECIPE_INVALID_FREE", {"pointer_address": 4096, "vma_name": ".data"}, None),
        ("RECIPE_HEAP_GROWTH", {"heap_series_kb": [100, 100, 100], "epoch_count": 3}, None),
    ],
}

# prose-valued keys inside details / raw observations (enum values are single upper-case tokens and are kept)
_PROSE_KEYS = {"finding", "counter_indicator", "finding_summary", "certainty_cap_reason", "summary", "description",
               "reason", "facts", "limitations", "text", "write_evidence", "level_reason", "confidence_basis",
               "corruption_hint_variable", "source_context"}


def _reword(obj: Any, text: str, key: str = "") -> Any:
    if isinstance(obj, dict):
        return {k: (_reword(v, text, k) if k != TYPED_EVIDENCE_KEY else v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_reword(v, text, key) for v in obj]
    if isinstance(obj, str) and (key in _PROSE_KEYS or " " in obj):
        return text
    return obj


def _perturb(evidence: List[Dict[str, Any]], text: str, keep_typed: bool) -> List[Dict[str, Any]]:
    out = []
    for e in copy.deepcopy(evidence):
        e = _reword(e, text)
        e["correlation"] = {"source_context": [text]}
        if not keep_typed:
            e.pop(TYPED_EVIDENCE_KEY, None)       # derived again from the reworded dict
        out.append(e)
    return out


class _Session:
    """An AdaptiveInvestigationSession in a temporary corpus, fed collected evidence directly."""

    def __init__(self, tmp: str, evidence: List[Dict[str, Any]]):
        self.s = AdaptiveInvestigationSession(investigation_id="inv_typed_ev_test", problem_statement="test",
                                              corpus_dir=tmp)
        self.s.collected_evidence = evidence
        self.s.target_assessment = SimpleNamespace(memory_readable=True, limitations=[])
        self.s.verified_checks_count = sum(1 for e in evidence if e.get("status") == "CONTRADICTED")

    def verify(self) -> List[Tuple[Any, ...]]:
        self.s._step_analyze()
        self.s._step_verify()
        rows = []
        for h in sorted(self.s.active_hypotheses + self.s.rejected_hypotheses, key=lambda h: h.category):
            rows.append((h.category, h.status, round(h.confidence, 6),
                         tuple((r["criterion_id"], r["result"], tuple(r["consumed_evidence_ids"]))
                               for r in h.verification_execution_results),
                         tuple(e["evidence_id"] for e in h.supporting_evidence),
                         tuple(e["evidence_id"] for e in h.contradicting_evidence)))
        return rows


def _scenario_evidence(name: str) -> List[Dict[str, Any]]:
    ev: List[Dict[str, Any]] = []
    for n, (rid, data, sym) in enumerate(SCENARIOS[name]):
        ev += _evidence_from_recipe(rid, data, n, sym)
    return ev


class TypedEvidenceSpecTest(unittest.TestCase):
    def test_spec_fields_and_round_trip(self):
        ev = _scenario_evidence("unmapped_access")[0]
        t = typed_evidence_of(ev)
        self.assertEqual(t.kind, "ADDRESS_MAPPING")
        self.assertEqual(t.rule, "RECIPE_INVALID_MEMORY_ACCESS")
        self.assertEqual(t.category, "MEMORY_CORRUPTION")
        self.assertEqual(t.polarity, POLARITY_SUPPORTS)
        self.assertEqual(t.measured.get("violation_type"), "UNMAPPED_OR_GUARD_PAGE")
        self.assertIs(t.measured.get("access_fault_confirmed"), True)
        self.assertEqual(t.scope.get("rule"), "RECIPE_INVALID_MEMORY_ACCESS")
        self.assertTrue(t.complete)
        self.assertEqual(t.invariants.get(INV_ADDRESS_VALID), VIOLATED)
        self.assertTrue(t.has_observation)
        self.assertEqual(TypedEvidence.from_dict(t.to_dict()), t)
        # the stored typed part is what verification reads
        self.assertEqual(TypedEvidence.from_dict(ev[TYPED_EVIDENCE_KEY]), derive_typed_evidence(ev))
        # measured values carry no prose
        for v in t.measured.values():
            self.assertFalse(isinstance(v, str) and " " in v, v)

    def test_claims_per_invariant(self):
        def claims(name):
            return [(typed_evidence_of(e).polarity, typed_evidence_of(e).invariants) for e in _scenario_evidence(name)]
        self.assertIn((POLARITY_CONTRADICTS, {INV_ADDRESS_VALID: HOLDS, INV_NO_POISON: HOLDS}),
                      claims("valid_mapped_pointer"))
        self.assertEqual(claims("rss_growth")[0][1].get(INV_MEMORY_BOUNDED), VIOLATED)
        self.assertEqual(claims("heap_stable")[0][1].get(INV_MEMORY_BOUNDED), HOLDS)
        self.assertEqual(claims("deadlock_persistent")[0][1].get(INV_NO_CIRCULAR_WAIT), VIOLATED)
        self.assertEqual(claims("lock_graph_acyclic")[0][1].get(INV_NO_CIRCULAR_WAIT), HOLDS)
        self.assertEqual(claims("illegal_transition")[0][1].get(INV_STATE_LEGAL), VIOLATED)
        self.assertEqual(claims("value_within_bounds")[0][1].get(INV_STATE_LEGAL), HOLDS)
        self.assertEqual(claims("canary_hint_only")[0][1].get(INV_NO_POISON), VIOLATED)
        # an invalid free says nothing about poison bytes or the address mapping
        self.assertEqual(claims("invalid_free_on_stack")[0][1], {})
        inc = typed_evidence_of(_scenario_evidence("lock_graph_incomplete")[0])
        self.assertFalse(inc.complete)
        self.assertIn(INCOMPLETE_LOCK_GRAPH, inc.incomplete_reasons)

    def test_criteria_family_table_matches_every_registered_category(self):
        # the explicit table replaces the former category-name substring rule; it must give the same family for
        # every category a recipe can report (a new category must be added to the table deliberately)
        def legacy_family(cat):
            if "CORRUPTION" in cat or "FREE" in cat:
                return FAMILY_CORRUPTION
            if "LEAK" in cat or "GROWTH" in cat:
                return FAMILY_GROWTH
            if "DEADLOCK" in cat or "CONCURRENCY" in cat:
                return FAMILY_DEADLOCK
            if "STATE" in cat or "VARIABLE" in cat:
                return FAMILY_STATE
            return FAMILY_GENERIC
        cats = set(ALL_PROBLEM_CATEGORIES) | {r.problem_category for r in DiagnosticRecipeRegistry.list_recipes()}
        for cat in sorted(cats):
            self.assertEqual(criteria_family(cat), legacy_family(cat), cat)
        for cat in CATEGORY_FAMILY:
            self.assertIn(cat, cats)

    def test_evidence_without_typed_part_is_derived(self):
        ev = _scenario_evidence("heap_stable")[0]
        ev.pop(TYPED_EVIDENCE_KEY)
        self.assertEqual(typed_evidence_of(ev).invariants.get(INV_MEMORY_BOUNDED), HOLDS)


class WordingDoesNotChangeVerdictTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="typed_ev_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _verify(self, evidence):
        return _Session(self.tmp, evidence).verify()

    def test_rewording_keeps_verdicts_and_classification(self):
        for name in SCENARIOS:
            with self.subTest(scenario=name):
                ev = _scenario_evidence(name)
                base = self._verify(copy.deepcopy(ev))
                self.assertTrue(base)
                for text in ("lorem ipsum", LEGACY_WORDS, LEGACY_WORDS.upper(), ""):
                    for keep in (True, False):
                        self.assertEqual(self._verify(_perturb(ev, text, keep)), base,
                                         f"{name}: wording {text[:20]!r} (typed part kept={keep}) changed the verdict")

    def test_expected_verdicts(self):
        # the verdicts the wording test holds fixed (and which the former string search reached the same way)
        expect = {
            # address violated, but the probed memory shows no poison: fault criteria and a passed criterion
            "unmapped_access": ("MEMORY_CORRUPTION", "LIKELY"),
            "invalid_free_on_stack": ("INVALID_DOUBLE_FREE", "LIKELY"),
            "null_pointer_in_active_state": ("MEMORY_CORRUPTION", "LIKELY"),
            "valid_mapped_pointer": ("MEMORY_CORRUPTION", "REFUTED"),
            "rss_growth": ("MEMORY_LEAK", "CONFIRMED"),
            "heap_stable": ("MEMORY_LEAK", "REFUTED"),
            "deadlock_persistent": ("DEADLOCK_INDICATORS", "CONFIRMED"),
            "lock_graph_acyclic": ("DEADLOCK_INDICATORS", "REFUTED"),
            "illegal_transition": ("UNEXPECTED_STATE_TRANSITIONS", "CONFIRMED"),
            "value_out_of_bounds": ("ABNORMAL_VARIABLE_CHANGES", "LIKELY"),
            "value_within_bounds": ("ABNORMAL_VARIABLE_CHANGES", "REFUTED"),
            "canary_hint_only": ("MEMORY_CORRUPTION", "LIKELY"),
        }
        for name, (cat, status) in expect.items():
            with self.subTest(scenario=name):
                rows = self._verify(_scenario_evidence(name))
                self.assertIn((cat, status), [(r[0], r[1]) for r in rows])

    def test_incomplete_lock_graph_is_inconclusive_whatever_the_wording(self):
        ev = _scenario_evidence("lock_graph_incomplete")
        for text in ("", LEGACY_WORDS):
            rows = self._verify(_perturb(ev, text, False))
            for r in rows:
                for cid, result, _ids in r[3]:
                    if cid == "CRIT_NO_CIRCULAR_WAIT":
                        self.assertEqual(result, "INCONCLUSIVE")


class HealthyRuleReadsStructuredReasonTest(unittest.TestCase):
    """RECIPE_FREED_MEMORY_USE NOT_CHECKED is a scope limit only for the structured heap-cap reason, not because
    its limitation text happens to contain "above" / "cap"."""

    @staticmethod
    def _uaf(rec):
        return SimpleNamespace(recipe_id="RECIPE_FREED_MEMORY_USE", status="INCONCLUSIVE",
                               actual_observations={"freed_memory_use": rec}, limitations=[], missing_evidence=[],
                               technical_interpretation="")

    def test_structured_reason(self):
        capped = {"status": "NOT_CHECKED", "findings": [], "heap_not_checked_reason": "above_baseline_cap",
                  "limitations": ["use-after-free not checked: no usable heap walk (lorem ipsum)"]}
        self.assertIsNotNone(healthy_verdict._uaf_cap_scope_limit(self._uaf(capped)))
        for reason, text in (("byte_budget", "heap above the cap of the capture"), (None, "iteration cap reached")):
            rec = {"status": "NOT_CHECKED", "findings": [], "limitations": [text]}
            if reason:
                rec["heap_not_checked_reason"] = reason
            self.assertIsNone(healthy_verdict._uaf_cap_scope_limit(self._uaf(rec)), text)


# ------------------------------------------------------------------------------------------------ static guard
_TEXT_METHODS = {"lower", "upper", "casefold", "startswith", "endswith", "find", "rfind", "index", "rindex",
                 "count", "search", "match", "fullmatch", "findall", "finditer", "split", "partition"}


def _violations(tree: ast.AST) -> List[str]:
    out: List[str] = []

    def has_text_call(node: ast.AST) -> bool:
        for n in ast.walk(node):
            if isinstance(n, ast.Call):
                f = n.func
                if isinstance(f, ast.Name) and f.id in ("str", "repr", "format"):
                    return True
                if isinstance(f, ast.Attribute) and f.attr in _TEXT_METHODS:
                    return True
            if isinstance(n, ast.JoinedStr):
                return True
        return False

    for n in ast.walk(tree):
        if isinstance(n, ast.Compare):
            if any(isinstance(op, (ast.In, ast.NotIn)) for op in n.ops):
                if isinstance(n.left, ast.Constant) and isinstance(n.left.value, str):
                    out.append(f"line {n.lineno}: substring / key test with string literal {n.left.value!r}")
                elif any(has_text_call(c) for c in n.comparators):
                    out.append(f"line {n.lineno}: membership test on rendered text")
            if has_text_call(n.left) or any(has_text_call(c) for c in n.comparators):
                out.append(f"line {n.lineno}: comparison on rendered text")
        if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in _TEXT_METHODS:
            out.append(f"line {n.lineno}: text method .{n.func.attr}()")
        if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "re":
            out.append(f"line {n.lineno}: regular expression re.{n.attr}")
    return out


def _func_tree(fn) -> ast.AST:
    return ast.parse(textwrap.dedent(inspect.getsource(fn)))


class NoStringSearchInVerificationPathTest(unittest.TestCase):
    """Fails if a substring / case-folding / regex condition on evidence text comes back in the verification path."""

    GUARDED = (
        AdaptiveInvestigationSession._execute_verification_for_hypothesis,
        AdaptiveInvestigationSession._step_verify,
        AdaptiveInvestigationSession._build_verification_criteria_for_category,
        healthy_verdict._uaf_cap_scope_limit,
        healthy_verdict._double_free_cap_scope_limit,
        healthy_verdict._heap_cap_scope_limit,
    )

    def test_guarded_functions(self):
        for fn in self.GUARDED:
            with self.subTest(fn=fn.__qualname__):
                self.assertEqual(_violations(_func_tree(fn)), [])

    def test_typed_evidence_module(self):
        with open(typed_evidence.__file__, encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        self.assertEqual(_violations(tree), [])

    def test_guard_detects_the_former_patterns(self):
        for src in ('x = next(e for e in s if "growth" in str(e).lower())',
                    'ok = "validly mapped" in str(e)',
                    'ok = any(w in str(e).lower() for w in WORDS)',
                    'ok = "inconclusive" in hyp.problem_statement.lower()',
                    'ok = re.search("leak", text)'):
            with self.subTest(src=src):
                self.assertTrue(_violations(ast.parse(src)))
        self.assertEqual(_violations(ast.parse('ok = det.get("violation_type") in ("A", "B")')), [])


if __name__ == "__main__":
    unittest.main()

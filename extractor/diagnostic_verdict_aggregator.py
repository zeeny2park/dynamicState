"""Phase 2.1.6 – 2.1.8 — Centralized Diagnostic Verdict Aggregation Policy (Part B3).

Provides a deterministic, unified policy and documented decision table for deriving overall
investigation results across all check statuses and hypothesis states.

Documented Verdict Decision Table (Phase 2.1.8 Part B3):
+------------------------------------+------------------------------------------------------------+--------------------+
| Rule ID                            | Condition                                                  | Overall Verdict    |
+------------------------------------+------------------------------------------------------------+--------------------+
| RULE_1_CONFIRMED_FAULT             | >=1 CONFIRMED fault hypothesis OR >=1 required FAIL check  | CONFIRMED_FAULT    |
|                                    | that satisfies invariant + authoritative evidence criteria.|                    |
|                                    | Takes precedence over incomplete lifecycle or other PASS.  |                    |
+------------------------------------+------------------------------------------------------------+--------------------+
| RULE_2_PROBABLE_FAULT              | Zero confirmed faults, AND (>=1 LIKELY/SUPPORTED/PROPOSED  | PROBABLE_FAULT     |
|                                    | fault hypothesis OR >=1 required FAIL check whose evidence |                    |
|                                    | or invariant confirmation criteria are unverified/manual). |                    |
+------------------------------------+------------------------------------------------------------+--------------------+
| RULE_3_DEGRADED_OPTIONAL_FAIL      | Zero confirmed/probable faults, zero required FAILs, AND   | DEGRADED           |
|                                    | >=1 applicable optional check with status == FAIL.         |                    |
+------------------------------------+------------------------------------------------------------+--------------------+
| RULE_4_ABORTED_LIFECYCLE           | Zero faults/degraded, AND lifecycle_state in               | ABORTED            |
|                                    | {BLOCKED, FAILED, ABORTED}.                                |                    |
+------------------------------------+------------------------------------------------------------+--------------------+
| RULE_5_HEALTHY_VERIFIED            | lifecycle_state == COMPLETED, zero confirmed/probable      | HEALTHY            |
|                                    | faults, zero FAIL checks (required or optional),           |                    |
|                                    | total_checks >= 1, executed_checks >= 1, passed_checks >=1,|                    |
|                                    | required_checks >= 1 and 100% required PASS,               |                    |
|                                    | 100% required_scope covered by PASS checks,                |                    |
|                                    | zero INCONCLUSIVE/ERROR/NOT_EXECUTED/SKIPPED/UNSUPPORTED,  |                    |
|                                    | zero unjustified NOT_APPLICABLE checks,                    |                    |
|                                    | zero unresolved fault hypotheses,                          |                    |
|                                    | explicit clean-state evidence or all fault hyps REFUTED,   |                    |
|                                    | and zero blocking collection/integrity limitations.        |                    |
+------------------------------------+------------------------------------------------------------+--------------------+
| RULE_5B_HEALTHY_WITHIN_BASELINE_   | Applied by ``diagnose`` after this table (one rule, one    | HEALTHY            |
| SCOPE (extractor.healthy_verdict)  | vocabulary): every baseline check executed and cleared     |                    |
|                                    | (PASS; heap above the baseline walk cap is a listed scope  |                    |
|                                    | limit), no finding, no FAIL, no blocking not_covered kind  |                    |
|                                    | (collection failure, budget exhausted, ...).  Scope limits |                    |
|                                    | are listed in healthy_scope.not_checked.  A RULE_5 HEALTHY |                    |
|                                    | that fails RULE_5B is reported INCONCLUSIVE.               |                    |
+------------------------------------+------------------------------------------------------------+--------------------+
| RULE_6_INCONCLUSIVE_FALLBACK       | Any remaining state (empty checks, missing required_scope, | INCONCLUSIVE       |
|                                    | unexecuted/inconclusive/errored/skipped checks, missing    |                    |
|                                    | explicit clean evidence, unjustified NOT_APPLICABLE,       |                    |
|                                    | blocking limitations, or incomplete lifecycle).            |                    |
+------------------------------------+------------------------------------------------------------+--------------------+
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from .diagnostic_methodology import CheckStatus, DiagnosticCheck
from .typed_evidence import FAMILY_CORRUPTION, FAMILY_DEADLOCK, FAMILY_GROWTH, criteria_family

try:
    from .evidence_ledger import TRUSTED_PROVENANCE_CLASSES
except ImportError:
    TRUSTED_PROVENANCE_CLASSES = {"LIVE_RUNTIME_CAPTURE", "CONTROLLED_RUNTIME_REPRODUCTION"}


VERDICT_CONFIRMED_FAULT = "CONFIRMED_FAULT"
VERDICT_PROBABLE_FAULT = "PROBABLE_FAULT"
VERDICT_FAULT = "FAULT"
VERDICT_DEGRADED = "DEGRADED"
VERDICT_HEALTHY = "HEALTHY"
VERDICT_INCONCLUSIVE = "INCONCLUSIVE"
VERDICT_ABORTED = "ABORTED"

ALL_OVERALL_VERDICTS = {
    VERDICT_CONFIRMED_FAULT,
    VERDICT_PROBABLE_FAULT,
    VERDICT_FAULT,
    VERDICT_DEGRADED,
    VERDICT_HEALTHY,
    VERDICT_INCONCLUSIVE,
    VERDICT_ABORTED,
}

VERDICT_DECISION_TABLE: List[Dict[str, Any]] = [
    {
        "priority": 1,
        "rule_id": "RULE_1_CONFIRMED_FAULT",
        "verdict": VERDICT_CONFIRMED_FAULT,
        "criteria": (
            "At least one active fault hypothesis has status == CONFIRMED (backed by authoritative ledger evidence) "
            "or at least one required DiagnosticCheck has status == FAIL with satisfied invariant and evidence confirmation criteria."
        ),
    },
    {
        "priority": 2,
        "rule_id": "RULE_2_PROBABLE_FAULT",
        "verdict": VERDICT_PROBABLE_FAULT,
        "criteria": (
            "Zero confirmed faults, and either at least one active hypothesis is LIKELY/SUPPORTED/PROPOSED "
            "or a required DiagnosticCheck has status == FAIL without full authoritative root-cause confirmation criteria."
        ),
    },
    {
        "priority": 3,
        "rule_id": "RULE_3_DEGRADED_OPTIONAL_FAIL",
        "verdict": VERDICT_DEGRADED,
        "criteria": "Zero confirmed/probable faults on required checks, and at least one optional check has status == FAIL.",
    },
    {
        "priority": 4,
        "rule_id": "RULE_4_ABORTED_LIFECYCLE",
        "verdict": VERDICT_ABORTED,
        "criteria": "No faults or degraded state detected, and investigation lifecycle_state is BLOCKED, FAILED, or ABORTED.",
    },
    {
        "priority": 5,
        "rule_id": "RULE_5_HEALTHY_VERIFIED",
        "verdict": VERDICT_HEALTHY,
        "criteria": (
            "lifecycle_state == COMPLETED, 100% required checks and required_scope passed, zero FAIL/ERROR/INCONCLUSIVE/"
            "NOT_EXECUTED/SKIPPED/UNSUPPORTED checks, zero unjustified NOT_APPLICABLE checks, explicit clean-state evidence, "
            "and zero blocking limitations."
        ),
    },
    {
        "priority": 5,
        "rule_id": "RULE_5B_HEALTHY_WITHIN_BASELINE_SCOPE",
        "verdict": VERDICT_HEALTHY,
        "criteria": (
            "Applied by diagnose() (extractor.healthy_verdict): every baseline recipe executed and every check of it "
            "PASSed (a heap above the baseline walk cap is a listed scope limit), no finding of any severity, no FAIL "
            "check, no blocking not_covered kind (collection failure, stage failure, budget exhausted, baseline check "
            "not run, engine limitation, unknown kind). Scope limits are listed in healthy_scope.not_checked."
        ),
    },
    {
        "priority": 6,
        "rule_id": "RULE_6_INCONCLUSIVE_FALLBACK",
        "verdict": VERDICT_INCONCLUSIVE,
        "criteria": (
            "Any incomplete coverage, empty check set, missing required_scope, unexecuted/inconclusive/errored/skipped check, "
            "unjustified NOT_APPLICABLE check, missing clean-state evidence, blocking limitation, or non-completed lifecycle."
        ),
    },
]

# Stage 1 (zero string search in the verdict path): no rule below reads the prose of a limitation, check name or
# description.  Limitations are blocking as a whole (a limitation is something the investigation could not do;
# ``diagnose`` blocks HEALTHY on every engine limitation the same way, RULE_5B kind "limitation"); a caller that
# knows a limitation is only informational passes it as a structured item {"text": ..., "blocking": False}.


def _check_category(c: Any) -> str:
    """Problem category of a check: its own ``category`` attribute, else its recipe's registered category."""
    cat = getattr(c, "category", None)
    if cat:
        return str(cat)
    try:
        from .diagnostic_recipes import DiagnosticRecipeRegistry
        r = DiagnosticRecipeRegistry.get_recipe(str(getattr(c, "recipe_id", "") or ""))
    except Exception:
        r = None
    return r.problem_category if r is not None else ""


def limitation_text(lim: Any) -> str:
    """Display text of a limitation item (a string, or a structured {"text", "blocking", "kind"} dict)."""
    if isinstance(lim, dict):
        return str(lim.get("text") or lim.get("kind") or "")
    return str(lim)


def limitation_is_blocking(lim: Any) -> bool:
    """A limitation blocks HEALTHY unless it is a structured item that declares itself non-blocking."""
    if isinstance(lim, dict):
        return lim.get("blocking") is not False
    return bool(str(lim))


@dataclass
class AggregatedVerdict:
    """Deterministic result bundle derived from comprehensive investigation analysis."""
    overall_result: str  # CONFIRMED_FAULT, PROBABLE_FAULT, FAULT, DEGRADED, HEALTHY, INCONCLUSIVE, ABORTED
    verdict_rationale: str
    contributing_factors: List[str] = field(default_factory=list)
    limiting_factors: List[str] = field(default_factory=list)
    confirmed_problems: List[str] = field(default_factory=list)
    probable_problems: List[str] = field(default_factory=list)
    critical_risks: List[str] = field(default_factory=list)
    unresolved_questions: List[str] = field(default_factory=list)
    recommended_next_actions: List[str] = field(default_factory=list)
    inspection_coverage: Dict[str, Any] = field(default_factory=dict)
    determining_checks: List[str] = field(default_factory=list)
    determining_hypotheses: List[str] = field(default_factory=list)
    decision_rule_id: str = ""
    decision_trace: Dict[str, Any] = field(default_factory=dict)

    @property
    def verdict(self) -> str:
        return self.overall_result

    def to_dict(self) -> Dict[str, Any]:
        return {
            "overall_result": self.overall_result,
            "verdict_rationale": self.verdict_rationale,
            "contributing_factors": list(self.contributing_factors),
            "limiting_factors": list(self.limiting_factors),
            "confirmed_problems": list(self.confirmed_problems),
            "probable_problems": list(self.probable_problems),
            "critical_risks": list(self.critical_risks),
            "unresolved_questions": list(self.unresolved_questions),
            "recommended_next_actions": list(self.recommended_next_actions),
            "inspection_coverage": dict(self.inspection_coverage),
            "determining_checks": list(self.determining_checks),
            "determining_hypotheses": list(self.determining_hypotheses),
            "decision_rule_id": self.decision_rule_id,
            "decision_trace": dict(self.decision_trace),
        }


class DiagnosticVerdictAggregator:
    """Centralized diagnostic verdict aggregation engine (Part B3)."""

    @staticmethod
    def _is_not_applicable_justified(c: DiagnosticCheck, target_assessment: Optional[Any] = None) -> bool:
        rule_str = getattr(c, "applicability_rule", None)
        crit = getattr(c, "applicability_criteria", None)

        has_rule = isinstance(rule_str, str) and bool(rule_str.strip())
        has_non_empty_crit = False
        if isinstance(crit, dict) and crit:
            has_non_empty_crit = any(
                v is not None and v != "" and v != [] and v != {} and v is not False
                for v in crit.values()
            )

        if not has_rule and not has_non_empty_crit:
            return False

        # Validate against target_assessment if provided: a check declared not applicable because it needs symbols
        # is unjustified on a target that has them (structured criterion, not the wording of the rule)
        if target_assessment is not None and isinstance(crit, dict):
            if crit.get("requires_symbols") is True and getattr(target_assessment, "symbols_available", None) is True:
                return False
        return True

    @staticmethod
    def _does_required_fail_satisfy_confirmation(
        c: DiagnosticCheck,
        active_hypotheses: List[Any],
        evidence_records: Optional[List[Any]],
    ) -> bool:
        """Determines whether a required FAIL check satisfies defined confirmation criteria (Part B3).
        
        Prevents equating an arbitrary manually assigned FAIL status with an independently verified
        root cause while preserving confirmation for verified invariant failures.
        """
        # 1. Explicit caller/check flags indicating unverified or manual assignment
        if getattr(c, "is_verified", None) is False or getattr(c, "confirmation_criteria_met", None) is False:
            return False
        if getattr(c, "manual_override", False) is True or getattr(c, "arbitrary_fail", False) is True:
            return False

        # 2. If active_hypotheses are present and evaluated, check whether any fault hypothesis is CONFIRMED
        non_healthy_hyps = [
            h for h in active_hypotheses
            if getattr(h, "category", "") not in ("HEALTHY_PROCESS", "HEALTHY")
        ]
        confirmed_hyps = [h for h in non_healthy_hyps if getattr(h, "status", "") == "CONFIRMED"]
        if confirmed_hyps:
            return True
        if non_healthy_hyps and not confirmed_hyps:
            # Hypotheses were evaluated for this investigation and none reached CONFIRMED
            # (e.g., evidence was unverified or lacked independent roots). Do not let check status bypass hypothesis authority!
            return False

        # 3. If evidence_records list was explicitly provided, require that the check's evidence_ids
        #    (or at least one trusted record in evidence_records) back the failure with trusted provenance.
        if evidence_records:
            trusted_ids = {
                getattr(r, "evidence_id", None)
                for r in evidence_records
                if getattr(r, "provenance_class", None) in TRUSTED_PROVENANCE_CLASSES
                and getattr(r, "nature", "observation") == "observation"
            }
            chk_ev_ids = getattr(c, "evidence_ids", None) or []
            if chk_ev_ids:
                return any(eid in trusted_ids for eid in chk_ev_ids)
            return len(trusted_ids) > 0

        # 4. Standalone check (no hypotheses, no evidence records): confirmed unless the check is flagged as manual /
        # arbitrary / unverified (the structured flags of step 1).  Stage 1: the name, description or
        # interpretation of a check is never read (they used to be searched for "manual", "arbitrary", ...).
        return True

    @staticmethod
    def aggregate(
        lifecycle_state: str,
        stop_reason: Optional[str],
        checks: List[DiagnosticCheck],
        active_hypotheses: List[Any],
        rejected_hypotheses: Optional[List[Any]] = None,
        limitations: Optional[List[str]] = None,
        target_assessment: Optional[Any] = None,
        evidence_records: Optional[List[Any]] = None,
        required_scope: Optional[List[str]] = None,
    ) -> AggregatedVerdict:
        rej_hyps = rejected_hypotheses or []
        lim_items = list(limitations or [])
        lims = [limitation_text(x) for x in lim_items]

        # Categorize required vs optional checks
        required_checks: List[DiagnosticCheck] = []
        optional_checks: List[DiagnosticCheck] = []
        for c in checks:
            is_req = getattr(c, "is_required", getattr(c, "required", True))
            if is_req:
                required_checks.append(c)
            else:
                optional_checks.append(c)

        # Coverage breakdown
        total_checks = len(checks)
        passed_checks = sum(1 for c in checks if c.status == CheckStatus.PASS)
        failed_checks = sum(1 for c in checks if c.status == CheckStatus.FAIL)
        inconclusive_checks = sum(1 for c in checks if c.status == CheckStatus.INCONCLUSIVE)
        not_applicable_checks = sum(1 for c in checks if c.status == CheckStatus.NOT_APPLICABLE)
        not_executed_checks = sum(1 for c in checks if c.status == CheckStatus.NOT_EXECUTED)
        error_checks = sum(1 for c in checks if c.status == CheckStatus.ERROR)
        skipped_checks = sum(1 for c in checks if c.status == getattr(CheckStatus, "SKIPPED", "SKIPPED"))
        unsupported_checks = sum(1 for c in checks if c.status == getattr(CheckStatus, "UNSUPPORTED", "UNSUPPORTED"))

        required_failed = [c for c in required_checks if c.status == CheckStatus.FAIL]
        optional_failed = [c for c in optional_checks if c.status == CheckStatus.FAIL]
        required_passed = sum(1 for c in required_checks if c.status == CheckStatus.PASS)
        required_unexecuted = sum(
            1 for c in required_checks
            if c.status in (
                CheckStatus.NOT_EXECUTED,
                getattr(CheckStatus, "SKIPPED", "SKIPPED"),
                getattr(CheckStatus, "UNSUPPORTED", "UNSUPPORTED"),
            )
        )

        # Validate NOT_APPLICABLE checks
        unjustified_not_applicable = [
            c for c in checks
            if c.status == CheckStatus.NOT_APPLICABLE
            and not DiagnosticVerdictAggregator._is_not_applicable_justified(c, target_assessment)
        ]

        # Validate required_scope coverage if specified
        missing_required_scope: List[str] = []
        if required_scope:
            for req_item in required_scope:
                req_norm = str(req_item).strip()
                if not req_norm:
                    continue
                matched_pass = any(
                    c.status == CheckStatus.PASS
                    and (
                        c.check_id == req_norm
                        or getattr(c, "recipe_id", None) == req_norm
                        or getattr(c, "category", None) == req_norm
                    )
                    for c in checks
                )
                if not matched_pass:
                    missing_required_scope.append(req_norm)

        coverage = {
            "total_checks": total_checks,
            "passed_checks": passed_checks,
            "failed_checks": failed_checks,
            "inconclusive_checks": inconclusive_checks,
            "not_applicable_checks": not_applicable_checks,
            "not_executed_checks": not_executed_checks,
            "error_checks": error_checks,
            "skipped_checks": skipped_checks,
            "unsupported_checks": unsupported_checks,
            "executed_checks": passed_checks + failed_checks + inconclusive_checks + error_checks,
            "required_checks_count": len(required_checks),
            "required_checks_passed": required_passed,
            "required_failed_count": len(required_failed),
            "optional_failed_count": len(optional_failed),
            "unjustified_not_applicable_count": len(unjustified_not_applicable),
            "missing_required_scope": missing_required_scope,
        }

        confirmed_problems: List[str] = []
        probable_problems: List[str] = []
        unresolved_questions: List[str] = []
        contributing_factors: List[str] = []
        limiting_factors: List[str] = list(lims)
        determining_checks: List[str] = []
        determining_hypotheses: List[str] = []
        problem_categories: List[Any] = []   # (problem text, problem category) for the risk classification

        # 1. Inspect active hypotheses (re-validating CompetingHypothesis against bound ledger if present)
        for h in active_hypotheses:
            if hasattr(h, "evaluate_verdict") and getattr(h, "ledger", None) is not None:
                h.evaluate_verdict()
            h_id = getattr(h, "hypothesis_id", str(h))
            h_cat = getattr(h, "category", "")
            h_stat = getattr(h, "status", "")
            h_stmt = getattr(h, "problem_statement", getattr(h, "title", str(h)))
            h_basis = getattr(h, "confidence_basis", "")

            if h_cat in ("HEALTHY_PROCESS", "HEALTHY"):
                if h_stat == "CONFIRMED":
                    determining_hypotheses.append(h_id)
                continue

            if h_stat == "CONFIRMED":
                if hasattr(h, "supporting_evidence_ids") and hasattr(h, "ledger"):
                    if getattr(h, "ledger", None) is None and getattr(h, "supporting_evidence_ids", None):
                        h.evaluate_verdict()
                        h_stat = h.status
                if h_stat == "CONFIRMED":
                    confirmed_problems.append(h_stmt)
                    problem_categories.append((h_stmt, h_cat))
                    determining_hypotheses.append(h_id)
                    contributing_factors.append(
                        f"Confirmed fault [{h_id}]: {h_stmt} ({h_basis or 'verified by deterministic criteria'})"
                    )
                    continue

            if h_stat in ("LIKELY", "PROPOSED", "SUPPORTED"):
                probable_problems.append(h_stmt)
                problem_categories.append((h_stmt, h_cat))
                determining_hypotheses.append(h_id)
                contributing_factors.append(
                    f"Probable cause [{h_id}]: {h_stmt} ({h_basis or 'supported by live observations'})"
                )
            elif h_stat == "INCONCLUSIVE":
                unresolved_questions.append(h_stmt)

        # 2. Inspect failed required checks against confirmation criteria (Part B3)
        for c in required_failed:
            determining_checks.append(c.check_id)
            f_msg = f"Check failed: {c.name or c.check_id} ({c.technical_interpretation or 'decision criteria violated'})"
            problem_categories.append((f_msg, _check_category(c)))
            if DiagnosticVerdictAggregator._does_required_fail_satisfy_confirmation(c, active_hypotheses, evidence_records):
                if f_msg not in confirmed_problems:
                    confirmed_problems.append(f_msg)
                contributing_factors.append(f"Confirmed required check failure [{c.check_id}]: {c.description or c.name}")
            else:
                if f_msg not in probable_problems:
                    probable_problems.append(f_msg)
                contributing_factors.append(
                    f"Unconfirmed required check failure [{c.check_id}]: {c.description or c.name} (lacks independent root-cause confirmation)"
                )
                limiting_factors.append(
                    f"Required check [{c.check_id}] failed without verified root-cause confirmation criteria."
                )

        # 3. Inspect failed optional checks
        for c in optional_failed:
            determining_checks.append(c.check_id)
            limiting_factors.append(f"Optional check failed [{c.check_id}]: {c.name or c.description}")

        # Critical risks: by the problem category of the hypothesis / failed check (criteria family), never by the
        # words of the problem text
        critical_risks: List[str] = []
        for p, cat in problem_categories:
            if p not in confirmed_problems and p not in probable_problems:
                continue
            fam = criteria_family(cat)
            if fam in (FAMILY_CORRUPTION, FAMILY_DEADLOCK):
                risk_msg = f"Critical memory safety or concurrency risk: {p}"
            elif fam == FAMILY_GROWTH or cat == "RESOURCE_EXHAUSTION":
                risk_msg = f"Resource exhaustion risk: {p}"
            else:
                continue
            if risk_msg not in critical_risks:
                critical_risks.append(risk_msg)

        # Coverage & environmental limitations
        if inconclusive_checks > 0:
            limiting_factors.append(f"{inconclusive_checks} diagnostic checks produced INCONCLUSIVE results.")
        if not_executed_checks > 0:
            limiting_factors.append(f"{not_executed_checks} planned diagnostic checks were NOT_EXECUTED.")
        if skipped_checks > 0:
            limiting_factors.append(f"{skipped_checks} diagnostic checks were SKIPPED.")
        if unsupported_checks > 0:
            limiting_factors.append(f"{unsupported_checks} diagnostic checks were UNSUPPORTED.")
        if error_checks > 0:
            limiting_factors.append(f"{error_checks} diagnostic checks encountered execution errors.")
        if unjustified_not_applicable:
            limiting_factors.append(
                f"{len(unjustified_not_applicable)} check(s) marked NOT_APPLICABLE without explicit applicability rule."
            )
        if missing_required_scope:
            limiting_factors.append(
                f"Missing required scope coverage: {', '.join(missing_required_scope)}."
            )
        if target_assessment and getattr(target_assessment, "limitations", None):
            for t_lim in target_assessment.limitations:
                if t_lim not in limiting_factors:
                    limiting_factors.append(t_lim)

        # Helper to build decision_trace
        def _build_trace(rule_id: str, result: str, reason: str) -> Dict[str, Any]:
            return {
                "decision_rule_id": rule_id,
                "overall_result": result,
                "lifecycle_state": lifecycle_state,
                "stop_reason": stop_reason,
                "determining_checks": list(determining_checks),
                "determining_hypotheses": list(determining_hypotheses),
                "confirmed_problems_count": len(confirmed_problems),
                "probable_problems_count": len(probable_problems),
                "optional_failed_count": len(optional_failed),
                "inspection_coverage": dict(coverage),
                "explanation": reason,
            }

        # ---------------------------------------------------------------------
        # Decision Policy (Follows VERDICT_DECISION_TABLE)
        # ---------------------------------------------------------------------

        # Rule 1: CONFIRMED_FAULT takes top precedence (never hidden by unrelated PASS checks or incomplete lifecycle)
        if confirmed_problems:
            overall_result = VERDICT_CONFIRMED_FAULT
            rule_id = "RULE_1_CONFIRMED_FAULT"
            rationale = (
                f"Investigation confirmed {len(confirmed_problems)} deterministic runtime fault(s) "
                f"backed by verified evidence and invariant failures (determining checks: {determining_checks or ['N/A']}, "
                f"determining hypotheses: {determining_hypotheses or ['N/A']}). "
                "Unrelated passing checks or lifecycle state do not obscure verified faults."
            )
            recs = [
                "Remediate verified fault invariant violations immediately.",
                "Review code locations identified in source correlation.",
            ]
            return AggregatedVerdict(
                overall_result=overall_result,
                verdict_rationale=rationale,
                contributing_factors=contributing_factors,
                limiting_factors=limiting_factors,
                confirmed_problems=confirmed_problems,
                probable_problems=probable_problems,
                critical_risks=critical_risks,
                unresolved_questions=unresolved_questions,
                recommended_next_actions=recs,
                inspection_coverage=coverage,
                determining_checks=determining_checks,
                determining_hypotheses=determining_hypotheses,
                decision_rule_id=rule_id,
                decision_trace=_build_trace(rule_id, overall_result, rationale),
            )

        # Rule 2: PROBABLE_FAULT (probable causes or unconfirmed required check failures; never CONFIRMED_FAULT or HEALTHY)
        if probable_problems:
            overall_result = VERDICT_PROBABLE_FAULT
            rule_id = "RULE_2_PROBABLE_FAULT"
            rationale = (
                f"Identified {len(probable_problems)} probable cause(s) or unconfirmed check failure(s) "
                f"(determining checks: {determining_checks or ['N/A']}, determining hypotheses: {determining_hypotheses or ['N/A']}). "
                "Conclusive invariant verification or independent root evidence was incomplete, so findings remain probable rather than confirmed."
            )
            recs = [
                "Execute discriminating recipes to isolate probable causes.",
                "Acquire additional independent authoritative runtime observations for definitive confirmation.",
            ]
            return AggregatedVerdict(
                overall_result=overall_result,
                verdict_rationale=rationale,
                contributing_factors=contributing_factors,
                limiting_factors=limiting_factors,
                confirmed_problems=[],
                probable_problems=probable_problems,
                critical_risks=critical_risks,
                unresolved_questions=unresolved_questions,
                recommended_next_actions=recs,
                inspection_coverage=coverage,
                determining_checks=determining_checks,
                determining_hypotheses=determining_hypotheses,
                decision_rule_id=rule_id,
                decision_trace=_build_trace(rule_id, overall_result, rationale),
            )

        # Rule 3: Optional check failure -> DEGRADED (any applicable FAIL prevents HEALTHY)
        if optional_failed:
            overall_result = VERDICT_DEGRADED
            rule_id = "RULE_3_DEGRADED_OPTIONAL_FAIL"
            rationale = (
                f"Investigation identified {len(optional_failed)} failed optional check(s) ({determining_checks}) "
                "while required checks passed. Target process is operating in a DEGRADED state. Any applicable FAIL check prevents HEALTHY."
            )
            recs = [
                "Investigate degraded subsystem observations highlighted in optional check failures.",
                "Determine if degraded state impacts non-critical telemetry or precursors to severe failure.",
            ]
            return AggregatedVerdict(
                overall_result=overall_result,
                verdict_rationale=rationale,
                contributing_factors=contributing_factors,
                limiting_factors=limiting_factors,
                confirmed_problems=[],
                probable_problems=[],
                critical_risks=critical_risks,
                unresolved_questions=unresolved_questions,
                recommended_next_actions=recs,
                inspection_coverage=coverage,
                determining_checks=determining_checks,
                determining_hypotheses=determining_hypotheses,
                decision_rule_id=rule_id,
                decision_trace=_build_trace(rule_id, overall_result, rationale),
            )

        # Rule 4: Aborted / Blocked / Failed lifecycle
        if lifecycle_state in ("BLOCKED", "FAILED", "ABORTED"):
            overall_result = VERDICT_ABORTED
            rule_id = "RULE_4_ABORTED_LIFECYCLE"
            rationale = f"Investigation was interrupted or blocked prior to diagnostic conclusion (state: {lifecycle_state})."
            return AggregatedVerdict(
                overall_result=overall_result,
                verdict_rationale=rationale,
                contributing_factors=contributing_factors,
                limiting_factors=limiting_factors,
                confirmed_problems=[],
                probable_problems=[],
                critical_risks=[],
                unresolved_questions=unresolved_questions,
                recommended_next_actions=["Resolve environment/capability blocks and re-run investigation."],
                inspection_coverage=coverage,
                determining_checks=determining_checks,
                determining_hypotheses=determining_hypotheses,
                decision_rule_id=rule_id,
                decision_trace=_build_trace(rule_id, overall_result, rationale),
            )

        # Rule 5: HEALTHY evaluation — strict positive coverage & clean-state requirements
        has_explicit_clean_evidence = (
            stop_reason in ("ALL_HYPOTHESES_REFUTED", "EXPLICIT_HEALTHY_CONFIRMED")
            or any(
                getattr(h, "category", "") in ("HEALTHY_PROCESS", "HEALTHY")
                and getattr(h, "status", "") == "CONFIRMED"
                for h in active_hypotheses
            )
        )
        has_sufficient_coverage = (
            total_checks >= 1
            and coverage["executed_checks"] >= 1
            and passed_checks >= 1
            and len(required_checks) >= 1
            and required_passed == len(required_checks)
            and failed_checks == 0
            and inconclusive_checks == 0
            and error_checks == 0
            and required_unexecuted == 0
            and not_executed_checks == 0
            and skipped_checks == 0
            and unsupported_checks == 0
            and len(unjustified_not_applicable) == 0
            and len(missing_required_scope) == 0
            and len(unresolved_questions) == 0
        )
        # Structured blocking decision (stage 1): a caller limitation blocks unless declared non-blocking; the target
        # assessment blocks when memory is unreadable or it recorded a limitation; a failed collection record
        # blocks.  The factors this function added itself (inconclusive / unexecuted checks, ...) are already
        # coverage conditions above.
        blocking_limitations = [limitation_text(x) for x in lim_items if limitation_is_blocking(x)]
        if target_assessment is not None:
            if getattr(target_assessment, "memory_readable", True) is False:
                blocking_limitations.append("target memory unreadable")
            blocking_limitations += [limitation_text(x) for x in (getattr(target_assessment, "limitations", None) or [])
                                     if limitation_is_blocking(x)]
        for rec in evidence_records or []:
            if str(getattr(rec, "collection_status", "") or "") == "FAILED":
                blocking_limitations.append(f"collection failed: {getattr(rec, 'evidence_id', '')}")
        has_no_blocking_limitations = not blocking_limitations

        if (
            lifecycle_state == "COMPLETED"
            and not confirmed_problems
            and not probable_problems
            and has_explicit_clean_evidence
            and has_sufficient_coverage
            and has_no_blocking_limitations
        ):
            overall_result = VERDICT_HEALTHY
            rule_id = "RULE_5_HEALTHY_VERIFIED"
            determining_checks = [c.check_id for c in checks if c.status == CheckStatus.PASS]
            rationale = (
                f"Target process verified healthy within investigated scope. "
                f"All {coverage['executed_checks']} diagnostic checks ({determining_checks}) passed with zero anomalies, "
                "and candidate fault hypotheses were refuted by deterministic observation evidence."
            )
            recs = ["No immediate diagnostic remediation required: runtime verified clean within investigated scope."]
            return AggregatedVerdict(
                overall_result=overall_result,
                verdict_rationale=rationale,
                contributing_factors=[
                    "All evaluated safety invariants satisfied.",
                    "Plausible candidate fault hypotheses refuted by live observations.",
                ],
                limiting_factors=limiting_factors,
                confirmed_problems=[],
                probable_problems=[],
                critical_risks=[],
                unresolved_questions=[],
                recommended_next_actions=recs,
                inspection_coverage=coverage,
                determining_checks=determining_checks,
                determining_hypotheses=determining_hypotheses,
                decision_rule_id=rule_id,
                decision_trace=_build_trace(rule_id, overall_result, rationale),
            )

        # Rule 6: INCONCLUSIVE fallback
        overall_result = VERDICT_INCONCLUSIVE
        rule_id = "RULE_6_INCONCLUSIVE_FALLBACK"
        reasons: List[str] = []
        if total_checks == 0:
            reasons.append("no diagnostic checks were configured or executed (empty check set)")
        if failed_checks > 0:
            reasons.append(f"{failed_checks} check(s) failed preventing clean state confirmation")
        if inconclusive_checks > 0:
            reasons.append(f"{inconclusive_checks} check(s) were inconclusive")
            determining_checks.extend(c.check_id for c in checks if c.status == CheckStatus.INCONCLUSIVE)
        if not_executed_checks > 0:
            reasons.append(f"{not_executed_checks} planned check(s) were not executed")
            determining_checks.extend(c.check_id for c in checks if c.status == CheckStatus.NOT_EXECUTED)
        if skipped_checks > 0:
            reasons.append(f"{skipped_checks} check(s) were skipped")
        if unsupported_checks > 0:
            reasons.append(f"{unsupported_checks} check(s) were unsupported")
        if error_checks > 0:
            reasons.append(f"{error_checks} check(s) encountered errors")
            determining_checks.extend(c.check_id for c in checks if c.status == CheckStatus.ERROR)
        if passed_checks == 0 and total_checks > 0:
            reasons.append("zero checks produced a definitive PASS result")
        if len(unjustified_not_applicable) > 0:
            reasons.append(f"{len(unjustified_not_applicable)} check(s) marked NOT_APPLICABLE without explicit applicability rule")
            determining_checks.extend(c.check_id for c in unjustified_not_applicable)
        if len(missing_required_scope) > 0:
            reasons.append(f"required scope items not covered by passing checks: {missing_required_scope}")
        if len(unresolved_questions) > 0:
            reasons.append(f"{len(unresolved_questions)} candidate hypothesis(es) remain unresolved/inconclusive")
        if not has_explicit_clean_evidence:
            reasons.append("no explicit clean evidence was acquired to confirm healthy state")
        if not has_no_blocking_limitations:
            reasons.append("blocking collection or environmental limitations exist")
        if lifecycle_state != "COMPLETED":
            reasons.append(f"investigation lifecycle is not completed (state: {lifecycle_state})")

        rationale = (
            f"Investigation concluded as INCONCLUSIVE because {'; '.join(reasons)}. "
            "Absence of detected faults does not constitute proof of healthy operation."
        )
        recs = [
            "Acquire additional targeted runtime observations for unverified domains.",
            "Inspect reported limitations to resolve missing capabilities or irregular sampling.",
        ]
        return AggregatedVerdict(
            overall_result=overall_result,
            verdict_rationale=rationale,
            contributing_factors=contributing_factors,
            limiting_factors=limiting_factors,
            confirmed_problems=[],
            probable_problems=[],
            critical_risks=[],
            unresolved_questions=unresolved_questions or ["Target status inconclusive due to incomplete verification coverage."],
            recommended_next_actions=recs,
            inspection_coverage=coverage,
            determining_checks=sorted(set(determining_checks)),
            determining_hypotheses=determining_hypotheses,
            decision_rule_id=rule_id,
            decision_trace=_build_trace(rule_id, overall_result, rationale),
        )


# ---------------------------------------------------------------------------------------------------------------
# IMP-017: the one user-visible verdict vocabulary is ALL_OVERALL_VERDICTS above.  Older interfaces that still
# carry a "health score" or a legacy status word get them from these explicit boundary mappings, never from a
# verdict decided elsewhere.
# ---------------------------------------------------------------------------------------------------------------

FAULT_VERDICTS = frozenset({VERDICT_CONFIRMED_FAULT, VERDICT_PROBABLE_FAULT, VERDICT_FAULT})


def health_score_for(verdict: str, findings: Optional[List[Dict[str, Any]]] = None) -> Optional[int]:
    """Legacy 0..100 health score derived from a verdict of the one vocabulary (display only).

    INCONCLUSIVE / ABORTED (and anything unknown) -> None: an unexamined process has no score.  HEALTHY -> 100.
    Fault / DEGRADED -> 100 minus 30 per CRITICAL, 15 per HIGH and 5 per other finding (floor 0; at most 90 so a
    fault never reads as a clean 100).
    """
    if verdict == VERDICT_HEALTHY:
        return 100
    if verdict not in FAULT_VERDICTS and verdict != VERDICT_DEGRADED:
        return None
    fs = [f for f in (findings or []) if isinstance(f, dict)]
    crit = sum(1 for f in fs if str(f.get("severity") or "").upper() == "CRITICAL")
    high = sum(1 for f in fs if str(f.get("severity") or "").upper() == "HIGH")
    other = len(fs) - crit - high
    return max(0, min(90, 100 - crit * 30 - high * 15 - other * 5))


def verdict_for_scan(findings: Optional[List[Dict[str, Any]]]) -> str:
    """Verdict of a single-shot finding SCAN (auto-triage, symptom scan) in the one vocabulary.

    A scan has no required checks, so it can never satisfy RULE_5 (HEALTHY): a clean scan is INCONCLUSIVE ("no
    finding within the scan; run diagnose for a verdict"), a failed collection is INCONCLUSIVE, and a scan finding
    is at most PROBABLE_FAULT (it was not confirmed by a recipe check).
    """
    if findings:
        return VERDICT_PROBABLE_FAULT
    return VERDICT_INCONCLUSIVE


# Final-diagnosis labels of the assertion/hypothesis verifier (extractor.verdict_engine.DIAG_*) -> the one
# vocabulary.  "No issue within the inspected scope" and "refuted" are not HEALTHY: no required-check coverage
# stands behind them (RULE_5), so they map to INCONCLUSIVE.
FINAL_DIAGNOSIS_TO_VERDICT = {
    "CONFIRMED": VERDICT_CONFIRMED_FAULT,
    "SUSPECTED": VERDICT_PROBABLE_FAULT,
    "PARTIALLY_CONFIRMED": VERDICT_PROBABLE_FAULT,
    "REFUTED": VERDICT_INCONCLUSIVE,
    "NO_ISSUE_DETECTED_WITHIN_SCOPE": VERDICT_INCONCLUSIVE,
    "NO_ISSUE_DETECTED": VERDICT_INCONCLUSIVE,
    "INCONCLUSIVE": VERDICT_INCONCLUSIVE,
}


def to_overall_verdict(label: Optional[str]) -> str:
    """Map a verdict-like label onto ALL_OVERALL_VERDICTS (identity for labels already in it; unknown ->
    INCONCLUSIVE)."""
    if label in ALL_OVERALL_VERDICTS:
        return str(label)
    return FINAL_DIAGNOSIS_TO_VERDICT.get(str(label or ""), VERDICT_INCONCLUSIVE)

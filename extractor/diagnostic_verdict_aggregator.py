"""Phase 2.1.6 & 2.1.7 — Centralized Diagnostic Verdict Aggregation Policy.

Provides a deterministic, unified policy for deriving overall investigation results.

Guarantees:
- HEALTHY requires sufficient completed inspection coverage and explicit evidence supporting clean state.
- Any applicable FAIL check (required or optional) prevents HEALTHY.
- A fault or confirmed failure takes precedence over lifecycle completion.
- Optional check failure yields DEGRADED, never HEALTHY.
- INCONCLUSIVE remains the result when important checks are inconclusive, unexecuted, errored, or blocked.
- NOT_EXECUTED, ERROR, INCONCLUSIVE, UNSUPPORTED, and NOT_APPLICABLE never count as PASS.
- NOT_APPLICABLE must be justified by an explicit applicability rule/criteria.
- Empty checks or insufficient required-scope coverage never produce HEALTHY.
- Investigation lifecycle state (e.g. COMPLETED) remains strictly distinct from diagnostic verdict (HEALTHY vs INCONCLUSIVE).
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from .diagnostic_methodology import CheckStatus, DiagnosticCheck


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
        }


class DiagnosticVerdictAggregator:
    """Centralized diagnostic verdict aggregation engine."""

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
        lims = list(limitations or [])
        ev_records = evidence_records or []

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

        # Required vs Optional breakdown
        required_failed = [c for c in required_checks if c.status == CheckStatus.FAIL]
        optional_failed = [c for c in optional_checks if c.status == CheckStatus.FAIL]
        required_passed = sum(1 for c in required_checks if c.status == CheckStatus.PASS)
        required_unexecuted = sum(1 for c in required_checks if c.status in (CheckStatus.NOT_EXECUTED, getattr(CheckStatus, "SKIPPED", "SKIPPED")))

        # Check for unjustified NOT_APPLICABLE checks
        unjustified_not_applicable = [
            c for c in checks
            if c.status == CheckStatus.NOT_APPLICABLE and not (
                getattr(c, "applicability_criteria", None) or (getattr(c, "applicability_rule", None) and str(c.applicability_rule).strip())
            )
        ]

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
        }

        # 1. Identify confirmed problems & probable problems
        confirmed_problems: List[str] = []
        probable_problems: List[str] = []
        unresolved_questions: List[str] = []
        contributing_factors: List[str] = []
        limiting_factors: List[str] = list(lims)

        for h in active_hypotheses:
            h_stat = getattr(h, "status", "")
            h_stmt = getattr(h, "problem_statement", getattr(h, "title", str(h)))
            h_basis = getattr(h, "confidence_basis", "")

            if h_stat == "CONFIRMED":
                confirmed_problems.append(h_stmt)
                contributing_factors.append(f"Confirmed fault: {h_stmt} ({h_basis or 'verified by deterministic criteria'})")
            elif h_stat in ("LIKELY", "PROPOSED", "SUPPORTED"):
                probable_problems.append(h_stmt)
                contributing_factors.append(f"Probable cause: {h_stmt} ({h_basis or 'supported by live observations'})")
            elif h_stat == "INCONCLUSIVE":
                unresolved_questions.append(h_stmt)

        # Incorporate failed required checks into confirmed problems / contributing factors
        for c in required_failed:
            f_msg = f"Check failed: {c.name or c.check_id} ({c.technical_interpretation or 'decision criteria violated'})"
            if f_msg not in confirmed_problems:
                confirmed_problems.append(f_msg)
            contributing_factors.append(f"Required check failure [{c.check_id}]: {c.description or c.name}")

        for c in optional_failed:
            limiting_factors.append(f"Optional check failed [{c.check_id}]: {c.name or c.description}")

        # Critical risks from confirmed problems
        critical_risks: List[str] = []
        for p in confirmed_problems:
            up = p.upper()
            if any(k in up for k in ("CORRUPTION", "FREE", "DEADLOCK", "OVERFLOW", "WILD")):
                critical_risks.append(f"Critical memory safety or concurrency risk: {p}")
            elif any(k in up for k in ("LEAK", "EXHAUSTION")):
                critical_risks.append(f"Resource exhaustion risk: {p}")

        # Check coverage limits
        if inconclusive_checks > 0:
            limiting_factors.append(f"{inconclusive_checks} diagnostic checks produced INCONCLUSIVE results.")
        if not_executed_checks > 0:
            limiting_factors.append(f"{not_executed_checks} planned diagnostic checks were NOT_EXECUTED.")
        if error_checks > 0:
            limiting_factors.append(f"{error_checks} diagnostic checks encountered execution errors.")
        if unjustified_not_applicable:
            limiting_factors.append(f"{len(unjustified_not_applicable)} check(s) marked NOT_APPLICABLE without explicit applicability rule.")
        if target_assessment and getattr(target_assessment, "limitations", None):
            for t_lim in target_assessment.limitations:
                if t_lim not in limiting_factors:
                    limiting_factors.append(t_lim)

        # ---------------------------------------------------------------------
        # Decision Policy
        # ---------------------------------------------------------------------

        # Rule 1: Confirmed fault takes top precedence (never hidden by unrelated PASS checks or COMPLETED lifecycle)
        if confirmed_problems:
            overall_result = VERDICT_CONFIRMED_FAULT
            rationale = (
                f"Investigation confirmed {len(confirmed_problems)} deterministic runtime fault(s) "
                f"backed by verified evidence and invariant failures. Unrelated passing checks or completed lifecycle do not obscure verified faults."
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
            )

        # Rule 2: Probable causes (never presented as confirmed root causes)
        if probable_problems:
            overall_result = VERDICT_PROBABLE_FAULT
            rationale = (
                f"Identified {len(probable_problems)} probable cause(s) supported by runtime evidence. "
                "Conclusive invariant verification was incomplete, so findings remain probable rather than confirmed."
            )
            recs = [
                "Execute discriminating recipes to isolate probable causes.",
                "Increase temporal sampling duration or enable compiler instrumentation (e.g. ASan) for definitive confirmation.",
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
            )

        # Rule 3: Optional check failure -> DEGRADED
        # Any applicable FAIL check prevents HEALTHY. If only optional checks failed, system is DEGRADED.
        if optional_failed:
            overall_result = VERDICT_DEGRADED
            rationale = (
                f"Investigation identified {len(optional_failed)} failed optional check(s) while required checks passed. "
                "Target process is operating in a DEGRADED or partially compromised state. Any applicable FAIL check prevents HEALTHY."
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
            )

        # Rule 4: Aborted / Failed lifecycle
        if lifecycle_state in ("BLOCKED", "FAILED", "ABORTED"):
            overall_result = VERDICT_ABORTED
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
            )

        # Rule 5: HEALTHY evaluation — strict requirements
        # HEALTHY cannot be inferred merely from absence of faults!
        # It requires:
        # a) lifecycle_state == COMPLETED
        # b) zero confirmed and zero probable problems
        # c) zero failed checks (both required and optional!)
        # d) total checks >= 1 and executed_checks >= 1 (non-empty!)
        # e) at least one required check exists and 100% of required checks passed
        # f) zero inconclusive checks
        # g) zero error checks
        # h) zero unexecuted required checks
        # i) zero unjustified NOT_APPLICABLE checks
        # j) not all checks are NOT_APPLICABLE (must have positive executed PASS checks)
        # k) explicit positive clean evidence or all hypotheses refuted
        # l) zero blocking limitations
        has_explicit_clean_evidence = (
            stop_reason in ("ALL_HYPOTHESES_REFUTED", "EXPLICIT_HEALTHY_CONFIRMED")
            or any(getattr(h, "category", "") == "HEALTHY_PROCESS" and getattr(h, "status", "") == "CONFIRMED" for h in active_hypotheses)
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
            and len(unjustified_not_applicable) == 0
        )
        has_no_blocking_limitations = not any(
            any(kw in l.lower() for kw in ("failed", "irregular", "unresolved", "clock regression", "regression detected"))
            for l in limiting_factors
        )

        if (
            lifecycle_state == "COMPLETED"
            and not confirmed_problems
            and not probable_problems
            and has_explicit_clean_evidence
            and has_sufficient_coverage
            and has_no_blocking_limitations
        ):
            overall_result = VERDICT_HEALTHY
            rationale = (
                f"Target process verified healthy within investigated scope. "
                f"All {coverage['executed_checks']} diagnostic checks passed with zero anomalies, "
                "and candidate fault hypotheses were refuted by deterministic observation evidence."
            )
            recs = ["No immediate diagnostic remediation required: runtime verified clean within investigated scope."]
            return AggregatedVerdict(
                overall_result=overall_result,
                verdict_rationale=rationale,
                contributing_factors=["All evaluated safety invariants satisfied.", "Plausible candidate fault hypotheses refuted by live observations."],
                limiting_factors=limiting_factors,
                confirmed_problems=[],
                probable_problems=[],
                critical_risks=[],
                unresolved_questions=[],
                recommended_next_actions=recs,
                inspection_coverage=coverage,
            )

        # Rule 6: INCONCLUSIVE — when checks are inconclusive, unexecuted, errored, or clean evidence is missing
        overall_result = VERDICT_INCONCLUSIVE
        reasons = []
        if total_checks == 0:
            reasons.append("no diagnostic checks were configured or executed (empty check set)")
        if failed_checks > 0:
            reasons.append(f"{failed_checks} check(s) failed preventing clean state confirmation")
        if inconclusive_checks > 0:
            reasons.append(f"{inconclusive_checks} check(s) were inconclusive")
        if not_executed_checks > 0:
            reasons.append(f"{not_executed_checks} planned check(s) were not executed")
        if error_checks > 0:
            reasons.append(f"{error_checks} check(s) encountered errors")
        if passed_checks == 0 and total_checks > 0:
            reasons.append("zero checks produced a definitive PASS result")
        if len(unjustified_not_applicable) > 0:
            reasons.append(f"{len(unjustified_not_applicable)} check(s) marked NOT_APPLICABLE without explicit applicability rule")
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
        )

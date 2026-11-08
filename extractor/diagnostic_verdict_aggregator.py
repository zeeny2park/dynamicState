"""Phase 2.1.6 — Centralized Diagnostic Verdict Aggregation Policy.

Provides a deterministic, unified policy for deriving overall investigation results.

Guarantees:
- HEALTHY requires sufficient completed inspection coverage and explicit evidence supporting clean state.
- INCONCLUSIVE remains the result when important checks are inconclusive, unexecuted, errored, or blocked.
- NOT_EXECUTED and NOT_APPLICABLE never count as PASS.
- A confirmed fault is never hidden by unrelated passing checks.
- A probable cause is never presented as a confirmed root cause.
- Investigation lifecycle state (e.g. COMPLETED) remains strictly distinct from diagnostic verdict (HEALTHY vs INCONCLUSIVE).
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set

from .diagnostic_methodology import CheckStatus, DiagnosticCheck


VERDICT_CONFIRMED_FAULT = "CONFIRMED_FAULT"
VERDICT_PROBABLE_FAULT = "PROBABLE_FAULT"
VERDICT_HEALTHY = "HEALTHY"
VERDICT_INCONCLUSIVE = "INCONCLUSIVE"
VERDICT_ABORTED = "ABORTED"

ALL_OVERALL_VERDICTS = {
    VERDICT_CONFIRMED_FAULT,
    VERDICT_PROBABLE_FAULT,
    VERDICT_HEALTHY,
    VERDICT_INCONCLUSIVE,
    VERDICT_ABORTED,
}


@dataclass
class AggregatedVerdict:
    """Deterministic result bundle derived from comprehensive investigation analysis."""
    overall_result: str  # CONFIRMED_FAULT, PROBABLE_FAULT, HEALTHY, INCONCLUSIVE, ABORTED
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
    ) -> AggregatedVerdict:
        rej_hyps = rejected_hypotheses or []
        lims = list(limitations or [])
        ev_records = evidence_records or []

        # Coverage breakdown
        total_checks = len(checks)
        passed_checks = sum(1 for c in checks if c.status == CheckStatus.PASS)
        failed_checks = sum(1 for c in checks if c.status == CheckStatus.FAIL)
        inconclusive_checks = sum(1 for c in checks if c.status == CheckStatus.INCONCLUSIVE)
        not_applicable_checks = sum(1 for c in checks if c.status == CheckStatus.NOT_APPLICABLE)
        not_executed_checks = sum(1 for c in checks if c.status == CheckStatus.NOT_EXECUTED)
        error_checks = sum(1 for c in checks if c.status == CheckStatus.ERROR)

        coverage = {
            "total_checks": total_checks,
            "passed_checks": passed_checks,
            "failed_checks": failed_checks,
            "inconclusive_checks": inconclusive_checks,
            "not_applicable_checks": not_applicable_checks,
            "not_executed_checks": not_executed_checks,
            "error_checks": error_checks,
            "executed_checks": passed_checks + failed_checks + inconclusive_checks + error_checks,
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
        if target_assessment and getattr(target_assessment, "limitations", None):
            for t_lim in target_assessment.limitations:
                if t_lim not in limiting_factors:
                    limiting_factors.append(t_lim)

        # ---------------------------------------------------------------------
        # Decision Policy
        # ---------------------------------------------------------------------

        # Rule 1: Confirmed fault takes top precedence (never hidden by unrelated PASS checks)
        if confirmed_problems:
            overall_result = VERDICT_CONFIRMED_FAULT
            rationale = (
                f"Investigation confirmed {len(confirmed_problems)} deterministic runtime fault(s) "
                f"backed by verified evidence and invariant failures. Unrelated passing checks do not obscure verified faults."
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

        # Rule 3: Aborted / Failed lifecycle
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

        # Rule 4: HEALTHY evaluation — strict requirements
        # HEALTHY cannot be inferred merely from absence of faults!
        # It requires:
        # a) lifecycle_state == COMPLETED
        # b) zero confirmed and zero probable problems
        # c) explicit positive clean evidence or all hypotheses refuted
        # d) total executed checks >= 1
        # e) zero inconclusive checks
        # f) zero error checks
        # g) zero unexecuted required checks
        # h) no blocking limitations
        has_explicit_clean_evidence = (
            stop_reason in ("ALL_HYPOTHESES_REFUTED", "EXPLICIT_HEALTHY_CONFIRMED")
            or any(getattr(h, "category", "") == "HEALTHY_PROCESS" and getattr(h, "status", "") == "CONFIRMED" for h in active_hypotheses)
        )
        has_sufficient_coverage = (
            coverage["executed_checks"] >= 1
            and inconclusive_checks == 0
            and error_checks == 0
            and not_executed_checks == 0
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

        # Rule 5: INCONCLUSIVE — when checks are inconclusive, unexecuted, errored, or clean evidence is missing
        overall_result = VERDICT_INCONCLUSIVE
        reasons = []
        if inconclusive_checks > 0:
            reasons.append(f"{inconclusive_checks} check(s) were inconclusive")
        if not_executed_checks > 0:
            reasons.append(f"{not_executed_checks} planned check(s) were not executed")
        if error_checks > 0:
            reasons.append(f"{error_checks} check(s) encountered errors")
        if not has_explicit_clean_evidence:
            reasons.append("no explicit clean evidence was acquired to confirm healthy state")
        if not has_no_blocking_limitations:
            reasons.append("blocking collection or environmental limitations exist")

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

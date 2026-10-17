"""Phase 26 Quality Verification and Grounded Metrics Evaluation Engine.

Provides explicit, trustworthy computation of investigation quality metrics with:
- Exact numerators and denominators.
- Explicit NOT_EVALUABLE conditions when eligible cases are zero.
- Strict isolation from production prompts and inference context.
- Zero reliance on unittest execution order or shared mutable test state.
"""

from dataclasses import asdict, dataclass, field
import json
from typing import Any, Dict, List, Optional, Tuple, Union

NOT_EVALUABLE = "NOT_EVALUABLE"


@dataclass
class QualityMetric:
    """Represents a single evaluated quality metric with strict provenance."""
    name: str
    numerator: int
    denominator: int
    value: Union[float, str]
    is_evaluable: bool
    target_threshold: Optional[str] = None
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "numerator": self.numerator,
            "denominator": self.denominator,
            "value": self.value,
            "is_evaluable": self.is_evaluable,
            "target_threshold": self.target_threshold,
            "formatted": f"{self.value:.1f}% ({self.numerator}/{self.denominator})" if self.is_evaluable else NOT_EVALUABLE,
            "description": self.description,
        }


def compute_metric(
    name: str,
    numerator: int,
    denominator: int,
    target_threshold: Optional[str] = None,
    description: str = "",
) -> QualityMetric:
    """Compute a quality metric with honest NOT_EVALUABLE handling when denominator is zero."""
    if denominator == 0:
        return QualityMetric(
            name=name,
            numerator=numerator,
            denominator=denominator,
            value=NOT_EVALUABLE,
            is_evaluable=False,
            target_threshold=target_threshold,
            description=description,
        )
    rate = (numerator / denominator) * 100.0
    return QualityMetric(
        name=name,
        numerator=numerator,
        denominator=denominator,
        value=round(rate, 2),
        is_evaluable=True,
        target_threshold=target_threshold,
        description=description,
    )


@dataclass
class QualityMetricsReport:
    """Comprehensive, auditable quality metrics report."""
    scenarios_executed: int = 0
    scenarios_passed: int = 0
    unsupported_claims_attempted: int = 0
    unsupported_claims_rejected: int = 0
    invalid_evidence_attempted: int = 0
    invalid_evidence_rejected: int = 0
    unverified_candidates_evaluated: int = 0
    false_causal_promotions: int = 0
    scenario_details: Dict[str, Dict[str, Any]] = field(default_factory=dict)

    @property
    def scenario_pass_rate(self) -> QualityMetric:
        return compute_metric(
            name="Scenario Execution & Pass Rate",
            numerator=self.scenarios_passed,
            denominator=self.scenarios_executed,
            target_threshold="100.0%",
            description="Proportion of required test scenarios executed and passing without failure.",
        )

    @property
    def unsupported_claim_rejection_rate(self) -> QualityMetric:
        return compute_metric(
            name="Unsupported Claim Rejection Rate",
            numerator=self.unsupported_claims_rejected,
            denominator=self.unsupported_claims_attempted,
            target_threshold="100.0%",
            description="Proportion of ungrounded or fabricated factual claims downgraded or disarmed.",
        )

    @property
    def invalid_evidence_rejection_rate(self) -> QualityMetric:
        return compute_metric(
            name="Invalid Evidence Reference Rejection Rate",
            numerator=self.invalid_evidence_rejected,
            denominator=self.invalid_evidence_attempted,
            target_threshold="100.0%",
            description="Proportion of fabricated or irrelevant EvidenceLedger citations stripped.",
        )

    @property
    def false_positive_causal_promotion_rate(self) -> QualityMetric:
        return compute_metric(
            name="False-Positive Causal Promotion Rate",
            numerator=self.false_causal_promotions,
            denominator=self.unverified_candidates_evaluated,
            target_threshold="0.0%",
            description="Proportion of unverified static candidates incorrectly promoted to VALIDATED_CAUSAL_FUNCTION.",
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario_pass_rate": self.scenario_pass_rate.to_dict(),
            "unsupported_claim_rejection_rate": self.unsupported_claim_rejection_rate.to_dict(),
            "invalid_evidence_rejection_rate": self.invalid_evidence_rejection_rate.to_dict(),
            "false_positive_causal_promotion_rate": self.false_positive_causal_promotion_rate.to_dict(),
            "counts": {
                "scenarios_executed": self.scenarios_executed,
                "scenarios_passed": self.scenarios_passed,
                "unsupported_claims_attempted": self.unsupported_claims_attempted,
                "unsupported_claims_rejected": self.unsupported_claims_rejected,
                "invalid_evidence_attempted": self.invalid_evidence_attempted,
                "invalid_evidence_rejected": self.invalid_evidence_rejected,
                "unverified_candidates_evaluated": self.unverified_candidates_evaluated,
                "false_causal_promotions": self.false_causal_promotions,
            },
            "scenario_details": self.scenario_details,
        }

    def render_table(self) -> str:
        lines = [
            "================================================================================",
            " Phase 26 Quality Metrics Report",
            "================================================================================",
            f" {'Metric Name':<42} | {'Value':<16} | {'Target':<8} | {'Eligible'}",
            "--------------------------------------------------------------------------------",
        ]
        metrics = [
            self.scenario_pass_rate,
            self.unsupported_claim_rejection_rate,
            self.invalid_evidence_rejection_rate,
            self.false_positive_causal_promotion_rate,
        ]
        for m in metrics:
            val_str = f"{m.value:.1f}% ({m.numerator}/{m.denominator})" if m.is_evaluable else NOT_EVALUABLE
            elig_str = "YES" if m.is_evaluable else "NO (0 cases)"
            lines.append(f" {m.name:<42} | {val_str:<16} | {str(m.target_threshold):<8} | {elig_str}")
        lines.append("================================================================================")
        return "\n".join(lines)

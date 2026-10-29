"""Verdict Engine and Zero-CDN Incident Reporting Model.

Defines a strict 4-layer verdict classification:
1. Observation Status (OBSERVED, READ_ERROR, TIMEOUT, RESTRICTED)
2. Assertion Verdict (PASS, FAIL, ABSTAIN)
3. Hypothesis State (PROPOSED, SUPPORTED, CONTRADICTED, INCONCLUSIVE)
4. Final Diagnosis (CONFIRMED, SUSPECTED, NO_ISSUE_DETECTED, INCONCLUSIVE)

Strict Invariants:
- ABSTAIN is never counted as PASS or FAIL.
- Function attribution without causal proof capability cannot be CONFIRMED (strictly capped at SUSPECTED).
- 100% standalone, zero-CDN HTML reporting with inline CSS and SVG.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import html
import json
import uuid
from typing import Any, Dict, List, Optional, Tuple, Union

from .evidence_ledger import (
    ATTRIBUTION_BASIS_CALL_STACK,
    ATTRIBUTION_BASIS_EXECUTION_TRACE,
    ATTRIBUTION_BASIS_SINGLE_WRITER,
    PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    TRUSTED_PROVENANCE_CLASSES,
)


# 1. Observation Status
OBS_STATUS_OBSERVED = "OBSERVED"
OBS_STATUS_READ_ERROR = "READ_ERROR"
OBS_STATUS_TIMEOUT = "TIMEOUT"
OBS_STATUS_RESTRICTED = "RESTRICTED"
OBS_STATUS_UNKNOWN = "UNKNOWN"

# 2. Assertion Verdict
ASSERTION_PASS = "PASS"
ASSERTION_FAIL = "FAIL"
ASSERTION_ABSTAIN = "ABSTAIN"

# 3. Hypothesis State
HYP_STATE_PROPOSED = "PROPOSED"
HYP_STATE_SUPPORTED = "SUPPORTED"
HYP_STATE_CONTRADICTED = "CONTRADICTED"
HYP_STATE_INCONCLUSIVE = "INCONCLUSIVE"

# 4. Final Diagnosis
DIAG_CONFIRMED = "CONFIRMED"
DIAG_SUSPECTED = "SUSPECTED"
DIAG_NO_ISSUE_DETECTED = "NO_ISSUE_DETECTED"
DIAG_INCONCLUSIVE = "INCONCLUSIVE"


@dataclass
class AssertionEvaluation:
    raw_assertion: str
    lhs_expression: str
    resolved_expression: str
    operator: str
    expected: Any
    observed_value: Any
    observation_status: str
    verdict: str  # PASS, FAIL, ABSTAIN
    reason: str = ""
    runtime_address: Optional[int] = None
    was_coerced: bool = False
    evidence_id: Optional[str] = None


@dataclass
class DiagnosticVerdict:
    hypothesis: str
    final_diagnosis: str  # CONFIRMED, SUSPECTED, NO_ISSUE_DETECTED, INCONCLUSIVE
    hypothesis_state: str  # SUPPORTED, CONTRADICTED, INCONCLUSIVE
    confidence_score: float
    total_assertions: int
    passed_count: int
    failed_count: int
    abstain_count: int
    assertion_evaluations: List[AssertionEvaluation]
    causal_attribution_verified: bool
    attribution_basis: Optional[str]
    provenance_class: str
    target_identity: Dict[str, Any]
    limitations: List[str]
    budget_usage: Dict[str, Any]
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class VerdictEngine:
    """Evaluates observations and assertions to produce defensible diagnoses."""

    @staticmethod
    def evaluate_assertion(
        raw_assertion: str,
        lhs: str,
        op: str,
        rhs_raw: Optional[str],
        observed_value: Any,
        obs_status: str,
        res_expr: str = "",
        rt_addr: Optional[int] = None,
        was_coerced: bool = False,
        evidence_id: Optional[str] = None,
    ) -> AssertionEvaluation:
        """Evaluates a single assertion with strict ABSTAIN isolation."""
        res_expr = res_expr or lhs

        # 1. Check if observation failed -> strictly ABSTAIN
        if obs_status != OBS_STATUS_OBSERVED:
            return AssertionEvaluation(
                raw_assertion=raw_assertion,
                lhs_expression=lhs,
                resolved_expression=res_expr,
                operator=op,
                expected=rhs_raw,
                observed_value=observed_value,
                observation_status=obs_status,
                verdict=ASSERTION_ABSTAIN,
                reason=f"Observation could not be completed (status: {obs_status})",
                runtime_address=rt_addr,
                was_coerced=was_coerced,
                evidence_id=evidence_id,
            )

        # 2. Compare values
        passed, expected_val = VerdictEngine._compare_values(observed_value, op, rhs_raw)
        verdict = ASSERTION_PASS if passed else ASSERTION_FAIL
        reason = "Assertion condition satisfied" if passed else f"Observed '{observed_value}' did not satisfy '{op} {expected_val}'"

        return AssertionEvaluation(
            raw_assertion=raw_assertion,
            lhs_expression=lhs,
            resolved_expression=res_expr,
            operator=op,
            expected=expected_val,
            observed_value=observed_value,
            observation_status=obs_status,
            verdict=verdict,
            reason=reason,
            runtime_address=rt_addr,
            was_coerced=was_coerced,
            evidence_id=evidence_id,
        )

    @staticmethod
    def _compare_values(observed: Any, op: str, rhs_raw: Optional[str]) -> Tuple[bool, Any]:
        """Strict type and operator comparison."""
        def _is_null_like(v: Any) -> bool:
            if v is None:
                return True
            if isinstance(v, (int, float)) and v == 0:
                return True
            if isinstance(v, str) and v.lower() in ("0", "0x0", "null", "nullptr", "none"):
                return True
            return False

        if op == "IS_NULL":
            return _is_null_like(observed), "NULL"
        if op == "NOT_NULL":
            return not _is_null_like(observed), "NOT NULL"

        if rhs_raw is None:
            return False, None

        s_rhs = str(rhs_raw).strip()

        # Coerce numeric comparison if possible
        num_obs = None
        num_rhs = None
        if isinstance(observed, (int, float)) and not isinstance(observed, bool):
            num_obs = float(observed)
        elif isinstance(observed, str):
            try:
                num_obs = float(int(observed, 16)) if observed.startswith("0x") else float(observed)
            except Exception:
                num_obs = None

        try:
            num_rhs = float(int(s_rhs, 16)) if s_rhs.startswith("0x") else float(s_rhs)
        except Exception:
            num_rhs = None

        if num_obs is not None and num_rhs is not None:
            if op in ("==", "="):
                return num_obs == num_rhs, num_rhs
            if op in ("!=", "<>"):
                return num_obs != num_rhs, num_rhs
            if op == ">=":
                return num_obs >= num_rhs, num_rhs
            if op == "<=":
                return num_obs <= num_rhs, num_rhs
            if op == ">":
                return num_obs > num_rhs, num_rhs
            if op == "<":
                return num_obs < num_rhs, num_rhs

        # String fallback
        str_obs = str(observed).strip()
        if op in ("==", "="):
            return str_obs == s_rhs, s_rhs
        if op in ("!=", "<>"):
            return str_obs != s_rhs, s_rhs

        return False, s_rhs

    @classmethod
    def synthesize_verdict(
        cls,
        hypothesis: str,
        evaluations: List[AssertionEvaluation],
        target_identity: Dict[str, Any],
        causal_attribution_verified: bool = False,
        attribution_basis: Optional[str] = None,
        provenance_class: str = PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
        budget_usage: Optional[Dict[str, Any]] = None,
        extra_limitations: Optional[List[str]] = None,
    ) -> DiagnosticVerdict:
        """Synthesizes final diagnosis following strict causal and abstain invariants."""
        total = len(evaluations)
        passed = sum(1 for e in evaluations if e.verdict == ASSERTION_PASS)
        failed = sum(1 for e in evaluations if e.verdict == ASSERTION_FAIL)
        abstained = sum(1 for e in evaluations if e.verdict == ASSERTION_ABSTAIN)

        limitations: List[str] = list(extra_limitations or [])

        # 1. Hypothesis State
        if total == 0:
            hyp_state = HYP_STATE_INCONCLUSIVE
            confidence = 0.0
        elif abstained > 0:
            hyp_state = HYP_STATE_INCONCLUSIVE
            confidence = round(passed / float(total), 3)
            limitations.append(f"{abstained} assertion(s) yielded ABSTAIN due to observation failures.")
        elif failed > 0:
            hyp_state = HYP_STATE_CONTRADICTED
            confidence = round(passed / float(total), 3)
        elif passed == total:
            hyp_state = HYP_STATE_SUPPORTED
            confidence = 1.0
        else:
            hyp_state = HYP_STATE_INCONCLUSIVE
            confidence = round(passed / float(total), 3)

        # 2. Final Diagnosis with Causal Invariant Gate
        if total == 0 or abstained == total:
            diagnosis = DIAG_INCONCLUSIVE
        elif abstained > 0 and passed == 0 and failed == 0:
            diagnosis = DIAG_INCONCLUSIVE
        elif failed > 0:
            diagnosis = DIAG_NO_ISSUE_DETECTED if passed == 0 else DIAG_INCONCLUSIVE
        elif passed == total and total > 0:
            # All assertions passed! Now check causal attribution
            if attribution_basis == ATTRIBUTION_BASIS_CALL_STACK and not causal_attribution_verified:
                diagnosis = DIAG_SUSPECTED
                limitations.append(
                    "Function was observed on call stack (correlation), but causal link was not proven via single-writer reproduction or execution trace. Capped at SUSPECTED."
                )
            elif causal_attribution_verified and provenance_class in TRUSTED_PROVENANCE_CLASSES:
                diagnosis = DIAG_CONFIRMED
            elif provenance_class not in TRUSTED_PROVENANCE_CLASSES:
                diagnosis = DIAG_SUSPECTED
                limitations.append(f"Provenance class '{provenance_class}' is synthetic/unverified; diagnosis capped at SUSPECTED.")
            else:
                diagnosis = DIAG_CONFIRMED
        else:
            diagnosis = DIAG_INCONCLUSIVE

        return DiagnosticVerdict(
            hypothesis=hypothesis,
            final_diagnosis=diagnosis,
            hypothesis_state=hyp_state,
            confidence_score=confidence,
            total_assertions=total,
            passed_count=passed,
            failed_count=failed,
            abstain_count=abstained,
            assertion_evaluations=evaluations,
            causal_attribution_verified=causal_attribution_verified,
            attribution_basis=attribution_basis,
            provenance_class=provenance_class,
            target_identity=target_identity,
            limitations=limitations,
            budget_usage=budget_usage or {},
        )


class ZeroCdnReporter:
    """Generates 100% self-contained HTML and normalized JSON incident reports."""

    @staticmethod
    def render_json(verdict: DiagnosticVerdict, metadata: Optional[Dict[str, Any]] = None) -> str:
        """Serializes verdict to normalized machine-readable JSON."""
        data = asdict(verdict)
        if metadata:
            data["report_metadata"] = metadata
        return json.dumps(data, indent=2, sort_keys=True)

    @staticmethod
    def render_html(
        verdict: DiagnosticVerdict,
        title: str = "dynamicState Zero-Stop Incident Report",
        remediation_checklist: Optional[List[str]] = None,
    ) -> str:
        """Renders an elegant, self-contained HTML report with NO external CDN dependencies."""
        v_color = {
            DIAG_CONFIRMED: "#ef4444",      # Red
            DIAG_SUSPECTED: "#f59e0b",      # Amber
            DIAG_NO_ISSUE_DETECTED: "#10b981", # Green
            DIAG_INCONCLUSIVE: "#6b7280",   # Gray
        }.get(verdict.final_diagnosis, "#6b7280")

        esc = html.escape

        # Inline SVG Badge
        badge_svg = f"""<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="{v_color}" stroke-width="3" stroke-linecap="round" stroke-linejoin="round" style="vertical-align: -2px; margin-right: 6px;"><circle cx="12" cy="12" r="10"></circle><polyline points="12 6 12 12 16 14"></polyline></svg>"""

        # Build table rows for assertions
        rows_html = []
        for a in verdict.assertion_evaluations:
            badge_class = {
                ASSERTION_PASS: "badge-pass",
                ASSERTION_FAIL: "badge-fail",
                ASSERTION_ABSTAIN: "badge-abstain",
            }.get(a.verdict, "badge-abstain")

            rows_html.append(f"""
            <tr>
                <td style="font-family: monospace; font-size: 13px;">{esc(a.raw_assertion)}</td>
                <td><span class="badge {badge_class}">{esc(a.verdict)}</span></td>
                <td style="font-family: monospace; font-size: 12px;">{esc(str(a.observed_value))}</td>
                <td style="font-family: monospace; font-size: 12px;">{esc(str(a.expected))}</td>
                <td style="font-size: 12px; color: #64748b;">{esc(a.reason)}</td>
            </tr>
            """)

        rows_str = "".join(rows_html)

        # Build limitations items
        limitations_html = ""
        if verdict.limitations:
            lim_items = "".join(f"<li>{esc(lim)}</li>" for lim in verdict.limitations)
            limitations_html = f"""
            <div class="card warning-card">
                <div class="card-title">⚠️ Investigation Limitations & Invariant Guards</div>
                <ul style="margin: 8px 0 0 20px; font-size: 13px; color: #92400e;">
                    {lim_items}
                </ul>
            </div>
            """

        # Build remediation items
        remediation_html = ""
        if remediation_checklist:
            rem_items = "".join(f"<li>{esc(item)}</li>" for item in remediation_checklist)
            remediation_html = f"""
            <div class="card">
                <div class="card-title">📋 Remediation & Verification Checklist</div>
                <ul style="margin: 8px 0 0 20px; font-size: 13px; color: #334155;">
                    {rem_items}
                </ul>
            </div>
            """

        budget = verdict.budget_usage.get("metrics", {})
        stop_ms = budget.get("target_stop_duration_ms", 0.0)
        bytes_read = budget.get("bytes_read", 0)
        lat_us = budget.get("observation_latency_us", 0.0)

        html_doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{esc(title)}</title>
<style>
  :root {{
    --bg-page: #f8fafc;
    --bg-card: #ffffff;
    --text-main: #0f172a;
    --text-muted: #64748b;
    --border-card: #e2e8f0;
  }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background-color: var(--bg-page);
    color: var(--text-main);
    margin: 0;
    padding: 32px 16px;
    line-height: 1.5;
  }}
  .container {{
    max-width: 960px;
    margin: 0 auto;
  }}
  .header {{
    border-bottom: 2px solid var(--border-card);
    padding-bottom: 16px;
    margin-bottom: 24px;
  }}
  .header h1 {{
    font-size: 22px;
    margin: 0 0 8px 0;
    font-weight: 700;
  }}
  .meta-bar {{
    display: flex;
    flex-wrap: wrap;
    gap: 16px;
    font-size: 13px;
    color: var(--text-muted);
  }}
  .card {{
    background: var(--bg-card);
    border: 1px solid var(--border-card);
    border-radius: 8px;
    padding: 20px;
    margin-bottom: 20px;
    box-shadow: 0 1px 3px rgba(0,0,0,0.03);
  }}
  .warning-card {{
    background: #fffbeb;
    border-color: #fde68a;
  }}
  .card-title {{
    font-size: 15px;
    font-weight: 600;
    margin-bottom: 12px;
    color: #1e293b;
  }}
  .verdict-banner {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px 20px;
    border-radius: 8px;
    background: {v_color}15;
    border: 1px solid {v_color}40;
    margin-bottom: 20px;
  }}
  .verdict-title {{
    font-size: 18px;
    font-weight: 700;
    color: {v_color};
  }}
  .verdict-conf {{
    font-size: 14px;
    color: var(--text-muted);
    font-weight: 500;
  }}
  .grid-metrics {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 12px;
    margin-bottom: 20px;
  }}
  .metric-box {{
    background: #f1f5f9;
    border-radius: 6px;
    padding: 12px;
    text-align: center;
  }}
  .metric-value {{
    font-size: 18px;
    font-weight: 700;
    color: #0f172a;
  }}
  .metric-label {{
    font-size: 11px;
    text-transform: uppercase;
    color: #64748b;
    margin-top: 4px;
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    margin-top: 8px;
  }}
  th {{
    text-align: left;
    font-size: 12px;
    text-transform: uppercase;
    color: var(--text-muted);
    padding: 8px 12px;
    border-bottom: 1px solid var(--border-card);
  }}
  td {{
    padding: 10px 12px;
    border-bottom: 1px solid var(--border-card);
    vertical-align: middle;
  }}
  .badge {{
    display: inline-block;
    padding: 3px 8px;
    border-radius: 12px;
    font-size: 11px;
    font-weight: 700;
    text-transform: uppercase;
  }}
  .badge-pass {{
    background: #dcfce7;
    color: #166534;
  }}
  .badge-fail {{
    background: #fee2e2;
    color: #991b1b;
  }}
  .badge-abstain {{
    background: #f1f5f9;
    color: #475569;
  }}
  footer {{
    text-align: center;
    font-size: 12px;
    color: #94a3b8;
    margin-top: 32px;
  }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <h1>{esc(title)}</h1>
    <div class="meta-bar">
      <span><strong>Target PID:</strong> {esc(str(verdict.target_identity.get("pid", "N/A")))}</span>
      <span><strong>Companion ELF:</strong> {esc(str(verdict.target_identity.get("companion_elf", "N/A")))}</span>
      <span><strong>Timestamp:</strong> {esc(verdict.generated_at)}</span>
    </div>
  </div>

  <div class="verdict-banner">
    <div class="verdict-title">{badge_svg}{esc(verdict.final_diagnosis)}</div>
    <div class="verdict-conf">Confidence: {int(verdict.confidence_score * 100)}% | State: {esc(verdict.hypothesis_state)}</div>
  </div>

  <div class="grid-metrics">
    <div class="metric-box">
      <div class="metric-value">{stop_ms:.2f} ms</div>
      <div class="metric-label">Target Stop Duration</div>
    </div>
    <div class="metric-box">
      <div class="metric-value">{lat_us:.1f} µs</div>
      <div class="metric-label">Observation Latency</div>
    </div>
    <div class="metric-box">
      <div class="metric-value">{bytes_read} B</div>
      <div class="metric-label">Bytes Read</div>
    </div>
    <div class="metric-box">
      <div class="metric-value">{verdict.passed_count}/{verdict.total_assertions}</div>
      <div class="metric-label">Assertions Passed</div>
    </div>
  </div>

  {limitations_html}

  <div class="card">
    <div class="card-title">🔍 Declarative Hypothesis & Assertion Proof Matrix</div>
    <div style="font-size: 14px; margin-bottom: 12px; color: #334155;">
      <strong>Target Hypothesis:</strong> <em>{esc(verdict.hypothesis)}</em>
    </div>
    <table>
      <thead>
        <tr>
          <th>Assertion</th>
          <th>Verdict</th>
          <th>Observed</th>
          <th>Expected</th>
          <th>Details</th>
        </tr>
      </thead>
      <tbody>
        {rows_str}
      </tbody>
    </table>
  </div>

  {remediation_html}

  <footer>
    Generated by dynamicState Adaptive Investigation Engine (Zero-Stop Architecture)
  </footer>
</div>
</body>
</html>
"""
        return html_doc

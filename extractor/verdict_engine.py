"""Verdict Engine and Zero-CDN Incident Reporting Model.

Defines a strict 4-layer verdict classification:
1. Observation Status (OBSERVED, READ_ERROR, TIMEOUT, RESTRICTED, UNKNOWN)
2. Assertion Verdict (PASS, FAIL, ABSTAIN)
3. Hypothesis State (PROPOSED, SUPPORTED, CONTRADICTED, INCONCLUSIVE, VALIDATED)
4. Final Diagnosis:
   - NO_ISSUE_DETECTED_WITHIN_SCOPE (and backward-compatible NO_ISSUE_DETECTED)
   - SUSPECTED
   - PARTIALLY_CONFIRMED
   - CONFIRMED
   - REFUTED
   - INCONCLUSIVE

Strict Invariants:
- ABSTAIN is never counted as PASS or FAIL.
- Failed/restricted reads never produce NO_ISSUE_DETECTED_WITHIN_SCOPE, PASS, or FAIL.
- Function attribution from call-stack correlation or static DWARF reference alone is capped at SUSPECTED.
- Memory leak hypotheses from a single snapshot/sample alone are capped at SUSPECTED/INCONCLUSIVE.
- Untrusted/imported/unverified provenance caps verdicts at SUSPECTED or INCONCLUSIVE.
- 100% standalone, zero-CDN HTML reporting with inline CSS and SVG.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import html
import json
import os
from typing import Any, Dict, List, Optional, Tuple, Union

from .evidence_ledger import (
    ATTRIBUTION_BASIS_CALL_STACK,
    ATTRIBUTION_BASIS_EXECUTION_TRACE,
    ATTRIBUTION_BASIS_SINGLE_WRITER,
    NATURE_HYPOTHESIS,
    NATURE_INFERENCE,
    NATURE_OBSERVATION,
    PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    PROVENANCE_CLASS_SYNTHETIC_FIXTURE,
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
HYP_STATE_VALIDATED = "VALIDATED"

# 4. Final Diagnosis
DIAG_CONFIRMED = "CONFIRMED"
DIAG_SUSPECTED = "SUSPECTED"
DIAG_PARTIALLY_CONFIRMED = "PARTIALLY_CONFIRMED"
DIAG_REFUTED = "REFUTED"
DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE = "NO_ISSUE_DETECTED_WITHIN_SCOPE"
DIAG_NO_ISSUE_DETECTED = "NO_ISSUE_DETECTED"
DIAG_INCONCLUSIVE = "INCONCLUSIVE"

VALID_FINAL_DIAGNOSES = {
    DIAG_CONFIRMED,
    DIAG_SUSPECTED,
    DIAG_PARTIALLY_CONFIRMED,
    DIAG_REFUTED,
    DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE,
    DIAG_NO_ISSUE_DETECTED,
    DIAG_INCONCLUSIVE,
}

# 5. Explicit Stopping Reasons (Phase 2.0 Section 7)
STOP_SUFFICIENT_EVIDENCE = "SUFFICIENT_EVIDENCE"
STOP_ALL_HYPOTHESES_REFUTED = "ALL_HYPOTHESES_REFUTED"
STOP_NO_USEFUL_SAFE_OBSERVATION = "NO_USEFUL_SAFE_OBSERVATION_REMAINS"
STOP_DIMINISHING_RETURNS = "DIMINISHING_INFORMATION_GAIN"
STOP_BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
STOP_REPEATED_FAILURE = "REPEATED_OBSERVATION_FAILURE"
STOP_CAPABILITY_UNAVAILABLE = "CAPABILITY_UNAVAILABLE"
STOP_USER_CANCELED = "USER_CANCELED"

VALID_STOP_REASONS = {
    STOP_SUFFICIENT_EVIDENCE,
    STOP_ALL_HYPOTHESES_REFUTED,
    STOP_NO_USEFUL_SAFE_OBSERVATION,
    STOP_DIMINISHING_RETURNS,
    STOP_BUDGET_EXHAUSTED,
    STOP_REPEATED_FAILURE,
    STOP_CAPABILITY_UNAVAILABLE,
    STOP_USER_CANCELED,
}


def sanitize_report_output_path(
    path_str: Optional[str],
    file_type: str = "report",
) -> Tuple[Optional[str], Optional[str]]:
    """Sanitizes and validates output path against system paths and symlink traversal.

    Returns:
        (sanitized_abs_path, error_message)
    """
    if not path_str or not str(path_str).strip():
        return None, None
    raw = str(path_str).strip()
    if "\x00" in raw:
        return None, f"Invalid path containing null bytes: {raw}"
    abs_path = os.path.abspath(raw)
    real_path = os.path.realpath(abs_path)

    forbidden_prefixes = (
        "/etc/", "/proc/", "/sys/", "/dev/", "/boot/",
        "/bin/", "/sbin/", "/usr/", "/lib/", "/lib64/",
    )
    for p in (abs_path, real_path):
        clean_p = p.rstrip("/") + "/"
        if any(clean_p.startswith(fp) for fp in forbidden_prefixes):
            return (
                None,
                f"Refusing to write {file_type} to protected system path: {raw} (resolved: {real_path})",
            )

    return abs_path, None


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
    provenance_class: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DiagnosticVerdict:
    hypothesis: str
    final_diagnosis: str  # CONFIRMED, SUSPECTED, PARTIALLY_CONFIRMED, REFUTED, NO_ISSUE_DETECTED_WITHIN_SCOPE, NO_ISSUE_DETECTED, INCONCLUSIVE
    hypothesis_state: str  # PROPOSED, SUPPORTED, CONTRADICTED, INCONCLUSIVE, VALIDATED
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
    # Extended Phase 2.0 auditable fields
    inspected_scope: Dict[str, Any] = field(default_factory=dict)
    uninspected_scope: Dict[str, Any] = field(default_factory=dict)
    evidence_coverage: Dict[str, Any] = field(default_factory=dict)
    supporting_evidence_ids: List[str] = field(default_factory=list)
    contradicting_evidence_ids: List[str] = field(default_factory=list)
    confidence_rationale: str = ""
    provenance_limitations: List[str] = field(default_factory=list)
    stop_reason: str = STOP_SUFFICIENT_EVIDENCE
    stop_explanation: str = ""
    recommended_next_steps: List[Dict[str, Any]] = field(default_factory=list)
    competing_hypotheses: List[Dict[str, Any]] = field(default_factory=list)
    observed_facts: List[Dict[str, Any]] = field(default_factory=list)
    inferences: List[Dict[str, Any]] = field(default_factory=list)
    unknowns: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class VerdictEngine:
    """Evaluates observations, competing hypotheses, and assertions to produce defensible diagnoses."""

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
        provenance_class: Optional[str] = None,
    ) -> AssertionEvaluation:
        """Evaluates a single assertion with strict ABSTAIN isolation."""
        res_expr = res_expr or lhs

        if obs_status != OBS_STATUS_OBSERVED:
            return AssertionEvaluation(
                raw_assertion=raw_assertion,
                lhs_expression=lhs,
                resolved_expression=res_expr,
                operator=op,
                expected=rhs_raw,
                observed_value=observed_value if obs_status == OBS_STATUS_OBSERVED else None,
                observation_status=obs_status,
                verdict=ASSERTION_ABSTAIN,
                reason=f"Observation could not be completed (status: {obs_status})",
                runtime_address=rt_addr,
                was_coerced=was_coerced,
                evidence_id=evidence_id,
                provenance_class=provenance_class,
            )

        passed, expected_val = VerdictEngine._compare_values(observed_value, op, rhs_raw)
        verdict = ASSERTION_PASS if passed else ASSERTION_FAIL
        reason = (
            "Assertion condition satisfied"
            if passed
            else f"Observed '{observed_value}' did not satisfy '{op} {expected_val}'"
        )

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
            provenance_class=provenance_class,
        )

    @staticmethod
    def _compare_values(observed: Any, op: str, rhs_raw: Optional[str]) -> Tuple[bool, Any]:
        """Strict type and operator comparison."""
        def _is_null_like(v: Any) -> bool:
            if v is None:
                return True
            if isinstance(v, (int, float)) and not isinstance(v, bool) and v == 0:
                return True
            if isinstance(v, str) and v.strip().lower() in ("0", "0x0", "null", "nullptr", "none"):
                return True
            return False

        if op == "IS_NULL":
            return _is_null_like(observed), "NULL"
        if op == "NOT_NULL":
            return not _is_null_like(observed), "NOT NULL"

        if rhs_raw is None:
            return False, None

        s_rhs = str(rhs_raw).strip()

        if s_rhs.lower() in ("0", "0x0", "null", "nullptr", "none") and op in ("==", "="):
            if _is_null_like(observed):
                return True, 0
        if s_rhs.lower() in ("0", "0x0", "null", "nullptr", "none") and op in ("!=", "<>"):
            if not _is_null_like(observed):
                return True, 0

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
        provenance_class: str = PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
        budget_usage: Optional[Dict[str, Any]] = None,
        extra_limitations: Optional[List[str]] = None,
        inspected_scope: Optional[Dict[str, Any]] = None,
        uninspected_scope: Optional[Dict[str, Any]] = None,
        evidence_coverage: Optional[Dict[str, Any]] = None,
        supporting_evidence_ids: Optional[List[str]] = None,
        contradicting_evidence_ids: Optional[List[str]] = None,
        confidence_rationale: Optional[str] = None,
        stop_reason: str = STOP_SUFFICIENT_EVIDENCE,
        stop_explanation: str = "",
        recommended_next_steps: Optional[List[Dict[str, Any]]] = None,
        competing_hypotheses: Optional[List[Dict[str, Any]]] = None,
        observed_facts: Optional[List[Dict[str, Any]]] = None,
        inferences: Optional[List[Dict[str, Any]]] = None,
        unknowns: Optional[List[Dict[str, Any]]] = None,
    ) -> DiagnosticVerdict:
        """Synthesizes final diagnosis following strict causal, provenance, and abstain invariants."""
        total = len(evaluations)
        passed = sum(1 for e in evaluations if e.verdict == ASSERTION_PASS)
        failed = sum(1 for e in evaluations if e.verdict == ASSERTION_FAIL)
        abstained = sum(1 for e in evaluations if e.verdict == ASSERTION_ABSTAIN)

        limitations: List[str] = list(extra_limitations or [])
        prov_limitations: List[str] = []

        # 1. Hypothesis State
        if total == 0:
            hyp_state = HYP_STATE_INCONCLUSIVE
            confidence = 0.0
        elif abstained > 0 and passed == 0 and failed == 0:
            hyp_state = HYP_STATE_INCONCLUSIVE
            confidence = 0.0
            limitations.append(f"{abstained} assertion(s) yielded ABSTAIN due to observation failures.")
        elif abstained > 0:
            hyp_state = HYP_STATE_INCONCLUSIVE
            confidence = round(passed / float(total), 3)
            limitations.append(f"{abstained} assertion(s) yielded ABSTAIN due to observation failures.")
        elif failed > 0 and passed == 0:
            hyp_state = HYP_STATE_CONTRADICTED
            confidence = round(failed / float(total), 3)
        elif failed > 0 and passed > 0:
            hyp_state = HYP_STATE_INCONCLUSIVE
            confidence = round(passed / float(total), 3)
        elif passed == total:
            hyp_state = HYP_STATE_SUPPORTED
            confidence = 1.0
        else:
            hyp_state = HYP_STATE_INCONCLUSIVE
            confidence = round(passed / float(total), 3)

        # Resolve effective provenance class (lowest trust level wins)
        eff_provenance_class = provenance_class
        for e in evaluations:
            e_prov = getattr(e, "provenance_class", None)
            if e_prov and e_prov not in TRUSTED_PROVENANCE_CLASSES:
                eff_provenance_class = e_prov
                break

        # 2. Final Diagnosis with Causal Invariant Gate
        if total == 0 or abstained == total:
            diagnosis = DIAG_INCONCLUSIVE
        elif abstained > 0 and passed == 0 and failed == 0:
            diagnosis = DIAG_INCONCLUSIVE
        elif failed > 0 and passed == 0:
            diagnosis = DIAG_REFUTED
        elif failed > 0 and passed > 0:
            diagnosis = DIAG_PARTIALLY_CONFIRMED
        elif passed == total and total > 0:
            if attribution_basis == ATTRIBUTION_BASIS_CALL_STACK and not causal_attribution_verified:
                diagnosis = DIAG_SUSPECTED
                msg = (
                    "Function was observed on call stack (correlation), but causal link was not proven "
                    "via single-writer reproduction or execution trace. Capped at SUSPECTED."
                )
                limitations.append(msg)
                prov_limitations.append(msg)
            elif causal_attribution_verified and eff_provenance_class in TRUSTED_PROVENANCE_CLASSES:
                diagnosis = DIAG_CONFIRMED
            elif eff_provenance_class not in TRUSTED_PROVENANCE_CLASSES:
                diagnosis = DIAG_SUSPECTED
                msg = f"Provenance class '{eff_provenance_class}' is synthetic/unverified; diagnosis capped at SUSPECTED."
                limitations.append(msg)
                prov_limitations.append(msg)
            else:
                diagnosis = DIAG_CONFIRMED
        else:
            diagnosis = DIAG_INCONCLUSIVE

        if eff_provenance_class not in TRUSTED_PROVENANCE_CLASSES:
            if diagnosis == DIAG_CONFIRMED:
                diagnosis = DIAG_SUSPECTED
                msg = f"Provenance class '{eff_provenance_class}' is synthetic/unverified; diagnosis capped at SUSPECTED."
                if msg not in limitations:
                    limitations.append(msg)
                if msg not in prov_limitations:
                    prov_limitations.append(msg)
            elif diagnosis in (DIAG_NO_ISSUE_DETECTED, DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE):
                diagnosis = DIAG_INCONCLUSIVE
                msg = (
                    f"Provenance class '{eff_provenance_class}' is synthetic/unverified; "
                    f"cannot certify {diagnosis}. Reclassified as INCONCLUSIVE."
                )
                limitations.append(msg)
                prov_limitations.append(msg)

        supp_ids = list(
            supporting_evidence_ids
            if supporting_evidence_ids is not None
            else [e.evidence_id for e in evaluations if e.verdict == ASSERTION_PASS and e.evidence_id]
        )
        contra_ids = list(
            contradicting_evidence_ids
            if contradicting_evidence_ids is not None
            else [e.evidence_id for e in evaluations if e.verdict == ASSERTION_FAIL and e.evidence_id]
        )

        rationale = confidence_rationale or (
            f"Evaluated {total} assertion(s): {passed} PASS, {failed} FAIL, {abstained} ABSTAIN "
            f"under provenance '{eff_provenance_class}'."
        )

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
            provenance_class=eff_provenance_class,
            target_identity=target_identity,
            limitations=limitations,
            budget_usage=budget_usage or {},
            inspected_scope=inspected_scope or {},
            uninspected_scope=uninspected_scope or {},
            evidence_coverage=evidence_coverage or {
                "total_assertions": total,
                "passed": passed,
                "failed": failed,
                "abstained": abstained,
                "provenance_class": eff_provenance_class,
            },
            supporting_evidence_ids=supp_ids,
            contradicting_evidence_ids=contra_ids,
            confidence_rationale=rationale,
            provenance_limitations=prov_limitations,
            stop_reason=stop_reason,
            stop_explanation=stop_explanation or rationale,
            recommended_next_steps=list(recommended_next_steps or []),
            competing_hypotheses=list(competing_hypotheses or []),
            observed_facts=list(observed_facts or []),
            inferences=list(inferences or []),
            unknowns=list(unknowns or []),
        )

    @classmethod
    def synthesize_process_health_verdict(
        cls,
        goal: str,
        hypotheses: List[Any],
        ledger: Any,
        target_identity: Dict[str, Any],
        inspected_scope: Dict[str, Any],
        uninspected_scope: Dict[str, Any],
        budget_usage: Dict[str, Any],
        stop_reason: str,
        stop_explanation: str,
        provenance_class: str = PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
        capture_quality: Optional[Dict[str, Any]] = None,
        assertion_evaluations: Optional[List[AssertionEvaluation]] = None,
        temporal_samples_count: int = 1,
        causal_attribution_verified: bool = False,
        attribution_basis: Optional[str] = None,
        extra_limitations: Optional[List[str]] = None,
        recommended_next_steps: Optional[List[Dict[str, Any]]] = None,
    ) -> DiagnosticVerdict:
        """Synthesizes an auditable, calibrated Process Health Verdict from competing hypotheses and ledger evidence."""
        evals = list(assertion_evaluations or [])
        limitations = list(extra_limitations or [])
        prov_limitations: List[str] = []

        records = list(getattr(ledger, "_records", [])) if ledger else []
        obs_records = [r for r in records if getattr(r, "nature", "") == NATURE_OBSERVATION]
        collected_obs = [
            r for r in obs_records
            if (r.details or {}).get("collection_status", "COLLECTED") == "COLLECTED"
            and (r.details or {}).get("result_category") not in (
                "OBSERVATION_FAILED", "OBSERVATION_UNAVAILABLE", "BUDGET_REJECTED"
            )
            and r.evidence_type not in ("runtime_identity", "capture_quality")
        ]
        partial_obs = [
            r for r in obs_records
            if (r.details or {}).get("collection_status") == "PARTIAL"
        ]
        failed_or_abstain_obs = [
            r for r in obs_records
            if (r.details or {}).get("collection_status") in ("FAILED", "ABSTAIN")
            or (r.details or {}).get("result_category") in ("OBSERVATION_FAILED", "OBSERVATION_UNAVAILABLE")
        ]

        # Determine effective provenance class (lowest trust level across records wins)
        eff_prov = provenance_class
        for r in obs_records:
            r_prov = (r.provenance or {}).get("provenance_class") or (r.details or {}).get("provenance_class")
            if r_prov == PROVENANCE_CLASS_IMPORTED_UNVERIFIED:
                eff_prov = PROVENANCE_CLASS_IMPORTED_UNVERIFIED
                break
            if r_prov == PROVENANCE_CLASS_SYNTHETIC_FIXTURE and eff_prov in TRUSTED_PROVENANCE_CLASSES:
                eff_prov = PROVENANCE_CLASS_SYNTHETIC_FIXTURE

        cq = capture_quality or {}
        cq_status = cq.get("completeness") or cq.get("status") or "COMPLETE"
        cq_consistency = cq.get("consistency_level") or "ZERO_STOP_ATOMIC"
        is_partial_capture = (cq_status == "PARTIAL") or len(partial_obs) > 0
        is_untrusted_capture = cq_status in ("FAILED", "INVALID", "UNTRUSTED")
        is_unverified_prov = eff_prov not in TRUSTED_PROVENANCE_CLASSES

        if is_unverified_prov:
            msg = f"Provenance '{eff_prov}' is unverified/imported; verdicts cannot be upgraded to CONFIRMED or NO_ISSUE_DETECTED_WITHIN_SCOPE."
            limitations.append(msg)
            prov_limitations.append(msg)
        if is_partial_capture:
            msg = "Capture quality or observation coverage is PARTIAL; unread or concurrent regions may mask state."
            limitations.append(msg)
            prov_limitations.append(msg)
        if is_untrusted_capture:
            msg = f"Capture quality is '{cq_status}'; runtime facts cannot be trusted."
            limitations.append(msg)
            prov_limitations.append(msg)

        # Classify hypotheses into defect hypotheses vs benign/normal competing explanations
        defect_hypos = []
        benign_hypos = []
        for h in hypotheses:
            is_benign = bool((getattr(h, "provenance", {}) or {}).get("is_benign_explanation"))
            if is_benign:
                benign_hypos.append(h)
            else:
                defect_hypos.append(h)

        supported_defects = [
            h for h in defect_hypos
            if getattr(h, "validation_status", "") in (HYP_STATE_SUPPORTED, HYP_STATE_VALIDATED)
        ]
        contradicted_defects = [
            h for h in defect_hypos
            if getattr(h, "validation_status", "") == HYP_STATE_CONTRADICTED
        ]
        proposed_defects = [
            h for h in defect_hypos
            if getattr(h, "validation_status", "") in (HYP_STATE_PROPOSED, HYP_STATE_INCONCLUSIVE)
        ]
        supported_benign = [
            h for h in benign_hypos
            if getattr(h, "validation_status", "") in (HYP_STATE_SUPPORTED, HYP_STATE_VALIDATED)
        ]

        all_supp_ids: List[str] = []
        all_contra_ids: List[str] = []
        for h in hypotheses:
            for eid in getattr(h, "supporting_evidence_ids", []):
                if eid not in all_supp_ids:
                    all_supp_ids.append(eid)
            for eid in getattr(h, "contradicting_evidence_ids", []):
                if eid not in all_contra_ids:
                    all_contra_ids.append(eid)

        # ---------------------------------------------------------------------
        # Strict Trust Gate for NO_ISSUE_DETECTED_WITHIN_SCOPE
        # ---------------------------------------------------------------------
        healthy_blockers: List[str] = []
        if eff_prov != PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE:
            healthy_blockers.append("UNVERIFIED_PROVENANCE_CANNOT_PROVE_HEALTH")
        if cq_status != "COMPLETE" or is_partial_capture or is_untrusted_capture:
            healthy_blockers.append("PARTIAL_CAPTURE_CANNOT_PROVE_HEALTH")
        if len(failed_or_abstain_obs) > 0:
            healthy_blockers.append("RESTRICTED_OBSERVATION_CANNOT_PROVE_HEALTH")
        unavail_caps = (uninspected_scope or {}).get("unavailable_capabilities", {})
        core_caps = {"process_alive", "memory_read_available", "memory_maps_available"}
        if (set(unavail_caps.keys()) & core_caps) or stop_reason == STOP_CAPABILITY_UNAVAILABLE:
            healthy_blockers.append("RESTRICTED_OBSERVATION_CANNOT_PROVE_HEALTH")
        if stop_reason in (
            STOP_BUDGET_EXHAUSTED,
            STOP_CAPABILITY_UNAVAILABLE,
            STOP_REPEATED_FAILURE,
            STOP_USER_CANCELED,
        ) or budget_usage.get("budget_ok") is False:
            healthy_blockers.append("RESTRICTED_OBSERVATION_CANNOT_PROVE_HEALTH")
        if len(collected_obs) == 0:
            healthy_blockers.append("RESTRICTED_OBSERVATION_CANNOT_PROVE_HEALTH")

        # Required limitation tag
        if "UNINSPECTED_SCOPE_EXCLUDED" not in limitations:
            limitations.append("UNINSPECTED_SCOPE_EXCLUDED")
        for b in healthy_blockers:
            if b not in limitations:
                limitations.append(b)
            if b not in prov_limitations:
                prov_limitations.append(b)

        can_certify_healthy = len(healthy_blockers) == 0

        # Evaluate verdict state
        if is_untrusted_capture or stop_reason in (STOP_CAPABILITY_UNAVAILABLE, STOP_REPEATED_FAILURE):
            final_diag = DIAG_INCONCLUSIVE
            hyp_state = HYP_STATE_INCONCLUSIVE
            conf_score = 0.0
            conf_rationale = (
                f"Investigation is INCONCLUSIVE because required observations failed or were restricted "
                f"(stop_reason={stop_reason}, failed/abstained={len(failed_or_abstain_obs)})."
            )
        elif len(collected_obs) == 0 and len(partial_obs) == 0:
            final_diag = DIAG_INCONCLUSIVE
            hyp_state = HYP_STATE_INCONCLUSIVE
            conf_score = 0.0
            conf_rationale = "No runtime observations were successfully collected; cannot assess process health."
        elif supported_defects:
            primary_h = max(supported_defects, key=lambda x: getattr(x, "confidence_score", 0.5))
            h_cat = getattr(primary_h, "anomaly_category", None) or (getattr(primary_h, "provenance", {}) or {}).get("anomaly_category")
            # Check if competing benign hypotheses for this defect were contradicted
            comp_ids = set(getattr(primary_h, "competing_hypothesis_ids", []))
            comp_hypos = [h for h in hypotheses if getattr(h, "hypothesis_id", "") in comp_ids]
            all_comp_contradicted = bool(comp_hypos) and all(
                getattr(ch, "validation_status", "") == HYP_STATE_CONTRADICTED for ch in comp_hypos
            )
            has_contra_on_primary = len(getattr(primary_h, "contradicting_evidence_ids", [])) > 0

            # Guard 1: Single-snapshot memory growth cannot be CONFIRMED leak
            is_single_sample_memory_leak = (
                h_cat == "MEMORY_GROWTH" and temporal_samples_count < 2
            )
            if is_single_sample_memory_leak:
                limitations.append(
                    "Memory leak cannot be CONFIRMED from a single snapshot/sample alone; temporal growth evidence across multiple samples is required."
                )

            # Guard 2: Call-stack correlation alone cannot be CONFIRMED
            if attribution_basis == ATTRIBUTION_BASIS_CALL_STACK and not causal_attribution_verified:
                limitations.append(
                    "Call-stack presence alone is correlational and does not prove causal root-cause; capped at SUSPECTED."
                )

            if (
                is_unverified_prov
                or is_partial_capture
                or is_single_sample_memory_leak
                or stop_reason == STOP_BUDGET_EXHAUSTED
                or (attribution_basis == ATTRIBUTION_BASIS_CALL_STACK and not causal_attribution_verified)
            ):
                final_diag = DIAG_SUSPECTED if not all_comp_contradicted else (
                    DIAG_SUSPECTED if (is_unverified_prov or is_single_sample_memory_leak) else DIAG_PARTIALLY_CONFIRMED
                )
                hyp_state = HYP_STATE_SUPPORTED
                conf_score = min(0.65, max(0.35, float(getattr(primary_h, "confidence_score", 0.55))))
                conf_rationale = (
                    f"Hypothesis '{primary_h.title}' is supported by {len(primary_h.supporting_evidence_ids)} independent observation(s), "
                    f"but verdict is capped at {final_diag} due to provenance/temporal/budget/correlation constraints."
                )
            elif has_contra_on_primary or not all_comp_contradicted:
                final_diag = DIAG_PARTIALLY_CONFIRMED if len(primary_h.supporting_evidence_ids) >= 2 else DIAG_SUSPECTED
                hyp_state = HYP_STATE_SUPPORTED
                conf_score = min(0.78, max(0.45, float(getattr(primary_h, "confidence_score", 0.65))))
                conf_rationale = (
                    f"Hypothesis '{primary_h.title}' is supported by {len(primary_h.supporting_evidence_ids)} observation(s), "
                    f"with {len(comp_hypos)} competing hypothesis(es) partially resolved."
                )
            else:
                final_diag = DIAG_CONFIRMED
                hyp_state = HYP_STATE_VALIDATED if causal_attribution_verified else HYP_STATE_SUPPORTED
                conf_score = min(0.92, max(0.75, float(getattr(primary_h, "confidence_score", 0.85))))
                conf_rationale = (
                    f"Hypothesis '{primary_h.title}' is confirmed by {len(primary_h.supporting_evidence_ids)} independent observation(s) "
                    f"and competing explanation(s) were refuted."
                )
        elif defect_hypos and len(contradicted_defects) == len(defect_hypos):
            # All material defect hypotheses were refuted!
            if not can_certify_healthy:
                final_diag = DIAG_INCONCLUSIVE
                hyp_state = HYP_STATE_INCONCLUSIVE
                conf_score = 0.4
                conf_rationale = (
                    f"All {len(contradicted_defects)} candidate defect hypothesis(es) were contradicted within inspected scope, "
                    f"but cannot certify NO_ISSUE_DETECTED_WITHIN_SCOPE due to: {', '.join(sorted(set(healthy_blockers)))}."
                )
            elif supported_benign:
                final_diag = DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE
                hyp_state = HYP_STATE_CONTRADICTED
                conf_score = 0.85
                conf_rationale = (
                    f"All {len(contradicted_defects)} candidate defect hypothesis(es) were refuted by follow-up observations "
                    f"and benign operational state was supported within the inspected scope."
                )
            else:
                final_diag = DIAG_REFUTED
                hyp_state = HYP_STATE_CONTRADICTED
                conf_score = 0.82
                conf_rationale = f"All {len(contradicted_defects)} material defect hypothesis(es) were refuted by direct evidence."
        elif proposed_defects:
            # Hypotheses remain unresolved (e.g., budget exhausted or temporal evidence insufficient)
            final_diag = DIAG_SUSPECTED if any(len(getattr(h, "supporting_evidence_ids", [])) > 0 for h in proposed_defects) else DIAG_INCONCLUSIVE
            hyp_state = HYP_STATE_INCONCLUSIVE
            conf_score = 0.35 if final_diag == DIAG_SUSPECTED else 0.2
            conf_rationale = (
                f"{len(proposed_defects)} hypothesis(es) remain unresolved (stop_reason={stop_reason}); "
                f"additional discriminating observations are required."
            )
        else:
            # No defect hypotheses generated after initial triage
            if not can_certify_healthy:
                final_diag = DIAG_INCONCLUSIVE
                hyp_state = HYP_STATE_INCONCLUSIVE
                conf_score = 0.25
                conf_rationale = (
                    f"No defect was observed, but cannot certify NO_ISSUE_DETECTED_WITHIN_SCOPE due to: "
                    f"{', '.join(sorted(set(healthy_blockers)))}."
                )
            else:
                final_diag = DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE
                hyp_state = HYP_STATE_SUPPORTED
                conf_score = 0.85
                conf_rationale = (
                    f"Low-impact triage across {len(collected_obs)} observation(s) found no actionable anomalies "
                    f"within the inspected scope ({', '.join(inspected_scope.get('domains', ['process_health']))}). "
                    f"Uninspected domains/regions remain outside this certification."
                )

        # Summarize facts, inferences, unknowns
        observed_facts = [
            {
                "evidence_id": r.evidence_id,
                "source": r.source,
                "observation": r.observation,
                "provenance_class": r.provenance_class,
                "collection_status": (r.details or {}).get("collection_status", "COLLECTED"),
            }
            for r in collected_obs
        ]
        inferences = [
            {
                "hypothesis_id": h.hypothesis_id,
                "title": h.title,
                "claim": h.claim,
                "status": h.validation_status,
                "confidence": h.confidence,
                "confidence_score": getattr(h, "confidence_score", 0.5),
            }
            for h in hypotheses
        ]
        unknowns = [
            {
                "evidence_id": r.evidence_id,
                "source": r.source,
                "description": r.observation,
                "reason": (r.details or {}).get("error") or (r.details or {}).get("result_category") or "UNAVAILABLE",
            }
            for r in failed_or_abstain_obs
        ]
        for un_key, un_reason in (uninspected_scope.get("unavailable_capabilities", {}) or {}).items():
            unknowns.append({
                "evidence_id": None,
                "source": un_key,
                "description": f"Capability '{un_key}' was not inspected",
                "reason": str(un_reason),
            })

        competing_summary = [
            h.to_dict() if hasattr(h, "to_dict") else dict(h)
            for h in hypotheses
        ]

        total_ast = len(evals)
        passed_ast = sum(1 for e in evals if e.verdict == ASSERTION_PASS)
        failed_ast = sum(1 for e in evals if e.verdict == ASSERTION_FAIL)
        abstain_ast = sum(1 for e in evals if e.verdict == ASSERTION_ABSTAIN)

        return DiagnosticVerdict(
            hypothesis=goal,
            final_diagnosis=final_diag,
            hypothesis_state=hyp_state,
            confidence_score=round(conf_score, 3),
            total_assertions=total_ast,
            passed_count=passed_ast,
            failed_count=failed_ast,
            abstain_count=abstain_ast,
            assertion_evaluations=evals,
            causal_attribution_verified=causal_attribution_verified,
            attribution_basis=attribution_basis,
            provenance_class=eff_prov,
            target_identity=target_identity,
            limitations=limitations,
            budget_usage=budget_usage or {},
            inspected_scope=inspected_scope,
            uninspected_scope=uninspected_scope,
            evidence_coverage={
                "collected_observations_count": len(collected_obs),
                "partial_observations_count": len(partial_obs),
                "failed_or_abstained_count": len(failed_or_abstain_obs),
                "temporal_samples_count": temporal_samples_count,
                "provenance_class": eff_prov,
                "capture_completeness": cq_status,
                "consistency_level": cq_consistency,
            },
            supporting_evidence_ids=all_supp_ids,
            contradicting_evidence_ids=all_contra_ids,
            confidence_rationale=conf_rationale,
            provenance_limitations=prov_limitations,
            stop_reason=stop_reason,
            stop_explanation=stop_explanation,
            recommended_next_steps=list(recommended_next_steps or []),
            competing_hypotheses=competing_summary,
            observed_facts=observed_facts,
            inferences=inferences,
            unknowns=unknowns,
        )


class ZeroCdnReporter:
    """Generates 100% self-contained HTML and normalized JSON incident reports."""

    @staticmethod
    def render_json(verdict: Union[DiagnosticVerdict, Dict[str, Any]], metadata: Optional[Dict[str, Any]] = None) -> str:
        """Serializes verdict to normalized machine-readable JSON."""
        data = asdict(verdict) if hasattr(verdict, "__dataclass_fields__") else dict(verdict)
        if metadata:
            data["report_metadata"] = metadata
        return json.dumps(data, indent=2, sort_keys=True)

    def generate_html_report(self, title: str, report_data: Dict[str, Any]) -> str:
        """Instance helper used by InvestigationManager.generate_report."""
        adap = report_data.get("adaptive_investigation", {})
        diag = adap.get("verdict") or report_data.get("status") or DIAG_INCONCLUSIVE
        conf = float(adap.get("confidence", 0.5))
        verdict_obj = DiagnosticVerdict(
            hypothesis=report_data.get("goal", title),
            final_diagnosis=diag,
            hypothesis_state=diag,
            confidence_score=conf,
            total_assertions=0,
            passed_count=0,
            failed_count=0,
            abstain_count=0,
            assertion_evaluations=[],
            causal_attribution_verified=False,
            attribution_basis=None,
            provenance_class=PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
            target_identity=report_data.get("target_identity", {}),
            limitations=[],
            budget_usage=adap.get("budget_summary", {}),
        )
        return self.render_html(verdict_obj, title=title)

    @staticmethod
    def render_html(
        verdict: DiagnosticVerdict,
        title: str = "dynamicState Zero-Stop Incident Report",
        remediation_checklist: Optional[List[str]] = None,
    ) -> str:
        """Renders an elegant, self-contained HTML report with NO external CDN dependencies."""
        v_color = {
            DIAG_CONFIRMED: "#ef4444",              # Red (Confirmed Incident / Root Cause)
            DIAG_SUSPECTED: "#f59e0b",              # Amber (Suspected)
            DIAG_PARTIALLY_CONFIRMED: "#f59e0b",    # Amber (Partially Confirmed)
            DIAG_REFUTED: "#3b82f6",                # Blue (Refuted Hypothesis)
            DIAG_NO_ISSUE_DETECTED: "#10b981",      # Green (Healthy / Normal)
            DIAG_NO_ISSUE_DETECTED_WITHIN_SCOPE: "#10b981",
            DIAG_INCONCLUSIVE: "#6b7280",           # Gray (Inconclusive)
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

        limitations_html = ""
        if verdict.limitations:
            lim_items = "".join(f"<li>{esc(lim)}</li>" for lim in verdict.limitations)
            limitations_html = f"""
            <div class="card warning-card">
                <div class="card-title">Investigation Limitations &amp; Invariant Guards</div>
                <ul style="margin: 8px 0 0 20px; font-size: 13px; color: #92400e;">
                    {lim_items}
                </ul>
            </div>
            """

        remediation_html = ""
        if remediation_checklist:
            rem_items = "".join(f"<li>{esc(item)}</li>" for item in remediation_checklist)
            remediation_html = f"""
            <div class="card">
                <div class="card-title">Remediation &amp; Verification Checklist</div>
                <ul style="margin: 8px 0 0 20px; font-size: 13px; color: #334155;">
                    {rem_items}
                </ul>
            </div>
            """

        budget = verdict.budget_usage.get("metrics", {})
        stop_ms = float(budget.get("target_stop_duration_ms", 0.0))
        bytes_read = int(budget.get("bytes_read", 0))
        lat_us = float(budget.get("observation_latency_us", 0.0))

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
      <span><strong>Provenance:</strong> {esc(getattr(verdict, "provenance_class", "N/A"))}</span>
      <span><strong>Stop Reason:</strong> {esc(getattr(verdict, "stop_reason", "N/A"))}</span>
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
    <div class="card-title">Adaptive Investigation Evidence Ledger &amp; Proof Matrix</div>
    <div style="font-size: 14px; margin-bottom: 12px; color: #334155;">
      <strong>Target Hypothesis / Goal:</strong> <em>{esc(verdict.hypothesis)}</em><br>
      <strong>Confidence Rationale:</strong> {esc(getattr(verdict, "confidence_rationale", ""))}
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

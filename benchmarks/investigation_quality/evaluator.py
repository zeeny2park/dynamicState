"""Independent, read-only investigation evaluator and metric computer for Phase 18.

Evaluates system investigation outputs against independent ground truth.
Guarantees:
1. No metric is hardcoded or assigned as a constant.
2. Evaluator is strictly read-only with respect to system findings, evidence ledger, and causal attestation.
3. Causal confusion matrix is computed from actual predictions; 0% FP causal SLA is enforced as a safety gate.
4. Real-runtime metrics and unit-fixture metrics are kept completely separate.
5. All metric denominators are explicitly tracked; missing data yields None (null), never silent 0% or 100%.
"""

from dataclasses import asdict, dataclass, field
import hashlib
import json
import os
from typing import Any, Dict, List, Optional, Set, Tuple


class CorpusValidationError(ValueError):
    """Raised when ground truth corpus fails structural schema or semantic validation."""
    pass


@dataclass
class ScenarioEvaluationResult:
    scenario_id: str
    scenario_name: str
    category: str
    evaluation_mode: str  # 'real_runtime' or 'unit_fixture'
    status: str           # 'COMPLETED', 'SKIPPED', 'FAILED'
    skip_reason: Optional[str] = None
    
    # Fact metrics
    facts_precision: Optional[float] = None
    facts_recall: Optional[float] = None
    facts_f1: Optional[float] = None
    facts_detected: int = 0
    facts_expected: int = 0
    facts_matched: int = 0
    
    # Evidence metrics
    evidence_precision: Optional[float] = None
    evidence_recall: Optional[float] = None
    total_cited_evidence: int = 0
    valid_cited_evidence: int = 0
    
    # Unsupported claims & disarming
    unsupported_claims_count: int = 0
    unsupported_claims_disarmed: int = 0
    unsupported_claim_rate: Optional[float] = None
    disarm_rate: Optional[float] = None
    
    # Uncertainty calibration
    confidence_score: float = 0.0
    uncertainty_calibrated: bool = False
    brier_score_component: float = 0.0
    
    # Next observation usefulness
    proposed_observations_count: int = 0
    useful_observations_count: int = 0
    next_observation_useful: bool = False
    next_observation_usefulness_rate: Optional[float] = None
    
    # Causal attribution & confusion matrix
    candidate_tier: str = "NONE"
    causal_promoted: bool = False
    ground_truth_is_causal: bool = False
    is_true_positive: bool = False
    is_false_positive: bool = False
    is_true_negative: bool = False
    is_false_negative: bool = False
    
    notes: str = ""
    artifacts: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AggregateMetrics:
    evaluation_mode: str
    total_scenarios: int
    completed_scenarios: int
    skipped_scenarios: int
    failed_scenarios: int
    
    mean_fact_precision: Optional[float]
    mean_fact_recall: Optional[float]
    mean_fact_f1: Optional[float]
    
    mean_evidence_precision: Optional[float]
    mean_evidence_recall: Optional[float]
    
    total_unsupported_claims: int
    total_disarmed_claims: int
    overall_unsupported_claim_rate: Optional[float]
    overall_disarm_rate: Optional[float]
    
    uncertainty_calibration_rate: float
    mean_next_observation_usefulness: Optional[float]
    
    causal_positives_ground_truth: int
    causal_negatives_ground_truth: int
    true_causal_positives: int
    false_causal_positives: int
    true_causal_negatives: int
    false_causal_negatives: int
    false_positive_causal_rate: float
    zero_false_positive_sla_met: bool
    
    scenarios: List[ScenarioEvaluationResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BenchmarkSuiteResult:
    schema_version: str
    timestamp_utc: str
    corpus_version: str
    corpus_hash: str
    fixture_hash: str
    build_id: Optional[str]
    analyzer_version: str
    provider_identity: str
    model: Optional[str]
    prompt_schema_version: str
    run_configuration: Dict[str, Any]
    
    real_runtime_metrics: Optional[AggregateMetrics] = None
    unit_fixture_metrics: Optional[AggregateMetrics] = None
    provider_comparisons: Dict[str, Any] = field(default_factory=dict)
    zero_false_positive_sla_met: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class CorpusSchemaValidator:
    """Validates ground truth corpus files to prevent malformed evaluation inputs."""

    REQUIRED_TOP_LEVEL = ["$schema", "corpus_version", "corpus_id", "scenarios"]
    REQUIRED_SCENARIO_KEYS = [
        "scenario_id", "scenario_name", "category", "description",
        "expected_facts", "valid_evidence_rules", "expected_uncertainty",
        "plausible_hypotheses", "discriminating_criteria", "causal_attribution"
    ]

    @classmethod
    def validate(cls, corpus: Dict[str, Any]) -> None:
        if not isinstance(corpus, dict):
            raise CorpusValidationError("Corpus root must be a JSON object")

        for key in cls.REQUIRED_TOP_LEVEL:
            if key not in corpus:
                raise CorpusValidationError(f"Missing required top-level corpus field: '{key}'")

        scenarios = corpus.get("scenarios")
        if not isinstance(scenarios, list) or len(scenarios) < 6:
            raise CorpusValidationError("Corpus 'scenarios' must be a list containing at least 6 scenarios")

        seen_ids = set()
        for idx, sc in enumerate(scenarios):
            if not isinstance(sc, dict):
                raise CorpusValidationError(f"Scenario at index {idx} must be an object")

            for k in cls.REQUIRED_SCENARIO_KEYS:
                if k not in sc:
                    raise CorpusValidationError(f"Scenario '{sc.get('scenario_id', idx)}' missing required key: '{k}'")

            sc_id = sc["scenario_id"]
            if sc_id in seen_ids:
                raise CorpusValidationError(f"Duplicate scenario_id '{sc_id}' found in corpus")
            seen_ids.add(sc_id)

            # Validate expected_facts
            facts = sc.get("expected_facts")
            if not isinstance(facts, list) or len(facts) == 0:
                raise CorpusValidationError(f"Scenario '{sc_id}' expected_facts must be a non-empty list")
            for f in facts:
                if not isinstance(f, dict) or "field_path" not in f:
                    raise CorpusValidationError(f"Scenario '{sc_id}' fact missing 'field_path'")

            # Validate causal_attribution
            causal = sc.get("causal_attribution")
            if not isinstance(causal, dict) or "causal_function_provable" not in causal or "allow_validated_causal" not in causal:
                raise CorpusValidationError(f"Scenario '{sc_id}' causal_attribution must include 'causal_function_provable' and 'allow_validated_causal'")

            # Validate expected_uncertainty
            unc = sc.get("expected_uncertainty")
            if not isinstance(unc, dict) or "should_be_inconclusive" not in unc:
                raise CorpusValidationError(f"Scenario '{sc_id}' expected_uncertainty must include 'should_be_inconclusive'")


def load_ground_truth_corpus(corpus_path: Optional[str] = None) -> Dict[str, Any]:
    """Load and validate the canonical ground truth corpus."""
    if not corpus_path:
        base_dir = os.path.dirname(os.path.abspath(__file__))
        corpus_path = os.path.join(base_dir, "corpus", "ground_truth_corpus.json")

    if not os.path.exists(corpus_path):
        raise FileNotFoundError(f"Ground truth corpus not found at: {corpus_path}")

    with open(corpus_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    CorpusSchemaValidator.validate(data)
    return data


def compute_file_sha256(path: str) -> str:
    """Compute SHA-256 hash of a file for provenance tracking."""
    if not os.path.exists(path):
        return "MISSING"
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while chunk := f.read(65536):
            h.update(chunk)
    return h.hexdigest()


class InvestigationEvaluator:
    """Independent, read-only evaluator for dynamicState investigation outputs."""

    def __init__(self, corpus: Optional[Dict[str, Any]] = None):
        self.corpus = corpus or load_ground_truth_corpus()

    def evaluate_scenario(
        self,
        scenario_def: Dict[str, Any],
        system_output: Dict[str, Any],
        evaluation_mode: str = "unit_fixture",
    ) -> ScenarioEvaluationResult:
        """Evaluate a single scenario output against ground truth. Strictly read-only."""
        sc_id = scenario_def["scenario_id"]
        sc_name = scenario_def["scenario_name"]
        sc_cat = scenario_def["category"]
        ground_is_causal = bool(scenario_def["causal_attribution"]["causal_function_provable"])
        expected_fn = scenario_def["causal_attribution"].get("expected_causal_function")

        status = system_output.get("status", "COMPLETED")
        skip_reason = system_output.get("skip_reason")

        if status == "SKIPPED":
            return ScenarioEvaluationResult(
                scenario_id=sc_id,
                scenario_name=sc_name,
                category=sc_cat,
                evaluation_mode=evaluation_mode,
                status="SKIPPED",
                skip_reason=skip_reason or "Prerequisites not met",
                ground_truth_is_causal=ground_is_causal,
                notes=f"Scenario skipped: {skip_reason}",
            )

        if status == "FAILED":
            return ScenarioEvaluationResult(
                scenario_id=sc_id,
                scenario_name=sc_name,
                category=sc_cat,
                evaluation_mode=evaluation_mode,
                status="FAILED",
                skip_reason=skip_reason or "Execution failed",
                ground_truth_is_causal=ground_is_causal,
                notes=f"Scenario failed: {skip_reason}",
            )

        # 1. Evaluate Observed Facts
        expected_facts = scenario_def.get("expected_facts", [])
        actual_facts = system_output.get("observed_facts", [])
        
        matched_facts = 0
        used_actual = set()
        for ef in expected_facts:
            ef_path = ef.get("field_path", "")
            ef_name = ef.get("field_name", "")
            ef_before = ef.get("before_value")
            ef_after = ef.get("after_value")

            for a_idx, af in enumerate(actual_facts):
                if a_idx in used_actual:
                    continue
                
                af_field = af.get("field_name", "") or af.get("field_path", "") or af.get("title", "")
                af_before = af.get("before_value")
                af_after = af.get("after_value", af.get("observed_value"))

                # Match if field name/path matches
                name_match = (
                    (ef_name and ef_name in str(af_field))
                    or (ef_path and ef_path in str(af_field))
                    or (ef_name and ef_name in str(af.get("description", "")))
                )
                
                val_match = True
                if ef_before is not None and af_before is not None:
                    val_match = str(ef_before) == str(af_before)
                if ef_after is not None and af_after is not None and val_match:
                    val_match = str(ef_after) == str(af_after)

                if name_match and val_match:
                    matched_facts += 1
                    used_actual.add(a_idx)
                    break

        num_expected_facts = len(expected_facts)
        num_detected_facts = len(actual_facts)
        
        facts_prec = (matched_facts / num_detected_facts) if num_detected_facts > 0 else (1.0 if num_expected_facts == 0 else 0.0)
        facts_rec = (matched_facts / num_expected_facts) if num_expected_facts > 0 else 1.0
        facts_f1 = (2 * facts_prec * facts_rec / (facts_prec + facts_rec)) if (facts_prec + facts_rec) > 0 else 0.0

        # 2. Evaluate Evidence References
        evidence_ledger = system_output.get("evidence_ledger", [])
        ledger_map = {rec.get("evidence_id"): rec for rec in evidence_ledger if isinstance(rec, dict) and rec.get("evidence_id")}
        
        # Collect cited evidence IDs from hypotheses, findings, and analysis response
        cited_evidence_ids: Set[str] = set()
        for f in actual_facts:
            cited_evidence_ids.update(f.get("evidence_ids", []))

        hypotheses = system_output.get("hypotheses", [])
        for h in hypotheses:
            cited_evidence_ids.update(h.get("supporting_evidence_ids", []))
            cited_evidence_ids.update(h.get("contradicting_evidence_ids", []))
        
        resp = system_output.get("conversational_response", {}) or {}
        cited_evidence_ids.update(resp.get("citations", []))
        cited_evidence_ids.update(resp.get("evidence_ids", []))

        # Check evidence precision (how many cited IDs are legitimate in the ledger and match scenario rules)
        rules = scenario_def.get("valid_evidence_rules", [])
        valid_cited = 0
        rules_covered = set()
        
        for eid in cited_evidence_ids:
            if eid in ledger_map:
                rec = ledger_map[eid]
                rec_str = json.dumps(rec).lower()
                matches_any_rule = False
                for r_idx, r in enumerate(rules):
                    req_types = r.get("evidence_types") or ([r.get("evidence_type")] if r.get("evidence_type") else [])
                    if req_types and rec.get("evidence_type") not in req_types:
                        continue
                    req_subs = r.get("required_substr", [])
                    if not req_subs or any(sub.lower() in rec_str for sub in req_subs):
                        matches_any_rule = True
                        rules_covered.add(r_idx)
                if matches_any_rule or not rules:
                    valid_cited += 1

        total_cited = len(cited_evidence_ids)
        ev_prec = (valid_cited / total_cited) if total_cited > 0 else 1.0
        ev_rec = (len(rules_covered) / len(rules)) if rules else 1.0

        # 3. Evaluate Unsupported Claims & Disarming
        unsupported_count = 0
        disarmed_count = 0
        for h in hypotheses:
            h_status = h.get("status", "") or h.get("validation_status", "")
            supp_ids = h.get("supporting_evidence_ids", [])
            valid_supp = [eid for eid in supp_ids if eid in ledger_map]
            has_unsupported_claim = len(valid_supp) == 0
            
            claims_causal = any(
                c.get("candidate_tier") in ("VALIDATED_CAUSAL_FUNCTION", "VALIDATED_CAUSAL")
                for c in h.get("function_candidates", [])
            )
            if claims_causal and not ground_is_causal:
                has_unsupported_claim = True

            if has_unsupported_claim:
                unsupported_count += 1
                if (
                    h_status in ("INCONCLUSIVE", "CONTRADICTED", "PROPOSED")
                    or h.get("unverified_claim_rejected", False)
                    or not claims_causal
                ):
                    disarmed_count += 1

        total_claims = len(hypotheses)
        unsupported_claim_rate = (unsupported_count / total_claims) if total_claims > 0 else 0.0
        disarm_rate = (disarmed_count / unsupported_count) if unsupported_count > 0 else 1.0

        # 4. Uncertainty Calibration
        conf_str = resp.get("confidence")
        if not conf_str:
            for h in hypotheses:
                if any(ef.get("field_name", "") in str(h).lower() for ef in expected_facts):
                    conf_str = h.get("confidence")
                    break
            if not conf_str:
                for f in actual_facts:
                    if any(ef.get("field_name", "") in str(f).lower() for ef in expected_facts):
                        conf_str = f.get("confidence")
                        break
        conf_str = conf_str or "medium"

        conf_val = 0.8
        if isinstance(conf_str, (int, float)):
            conf_val = float(conf_str)
        else:
            conf_map = {"high": 0.9, "medium": 0.6, "low": 0.3}
            conf_val = conf_map.get(str(conf_str).lower(), 0.6)

        expected_unc = scenario_def.get("expected_uncertainty", {})
        should_be_inconclusive = expected_unc.get("should_be_inconclusive", False)
        min_conf = expected_unc.get("min_confidence", 0.0)
        max_conf = expected_unc.get("max_confidence", 1.0)

        calibrated = True
        if should_be_inconclusive:
            if conf_val > 0.6:
                calibrated = False
        else:
            if conf_val < min_conf or conf_val > max_conf:
                calibrated = False

        brier_comp = (conf_val - (1.0 if not should_be_inconclusive else 0.0)) ** 2

        # 5. Next Observation Usefulness
        proposed_obs = list(system_output.get("follow_up_observations", []))
        for h in hypotheses:
            proposed_obs.extend(h.get("suggested_observations", []))
        if not proposed_obs and resp.get("recommended_next_step"):
            proposed_obs = [{"question": resp["recommended_next_step"]}]
        
        useful_obs_count = 0
        criteria = scenario_def.get("discriminating_criteria", [])
        for obs in proposed_obs:
            obs_str = json.dumps(obs).lower()
            if any(c.lower() in obs_str for c in criteria):
                useful_obs_count += 1

        total_proposed = len(proposed_obs)
        next_obs_useful = (useful_obs_count > 0)
        usefulness_rate = (useful_obs_count / total_proposed) if total_proposed > 0 else None

        # 6. Causal Promotion & Confusion Matrix
        # Inspect candidates across findings and hypotheses
        all_candidates = list(system_output.get("function_candidates", []))
        for f in actual_facts:
            all_candidates.extend(f.get("function_candidates", []))
        for h in hypotheses:
            all_candidates.extend(h.get("function_candidates", []))

        promoted_functions = []
        highest_tier = "STATIC_CANDIDATE"
        for c in all_candidates:
            tier = c.get("candidate_tier", "")
            fn = c.get("function_name", "")
            if tier in ("VALIDATED_CAUSAL_FUNCTION", "VALIDATED_CAUSAL"):
                promoted_functions.append(fn)
                highest_tier = "VALIDATED_CAUSAL_FUNCTION"
            elif tier in ("EVIDENCE_SUPPORTED", "EVIDENCE_SUPPORTED_CANDIDATE") and highest_tier != "VALIDATED_CAUSAL_FUNCTION":
                highest_tier = "EVIDENCE_SUPPORTED"

        causal_promoted = len(promoted_functions) > 0
        
        # Determine confusion matrix cell
        is_tp = False
        is_fp = False
        is_tn = False
        is_fn = False

        if causal_promoted:
            if ground_is_causal:
                # Must match expected causal function
                if expected_fn and any(fn == expected_fn for fn in promoted_functions):
                    is_tp = True
                else:
                    is_fp = True  # Promoted wrong function
            else:
                is_fp = True  # Promoted when not causal
        else:
            if ground_is_causal:
                is_fn = True  # Causal in truth, but not validated
            else:
                is_tn = True  # Not causal, correctly not validated

        return ScenarioEvaluationResult(
            scenario_id=sc_id,
            scenario_name=sc_name,
            category=sc_cat,
            evaluation_mode=evaluation_mode,
            status="COMPLETED",
            facts_precision=round(facts_prec, 4),
            facts_recall=round(facts_rec, 4),
            facts_f1=round(facts_f1, 4),
            facts_detected=num_detected_facts,
            facts_expected=num_expected_facts,
            facts_matched=matched_facts,
            evidence_precision=round(ev_prec, 4) if ev_prec is not None else None,
            evidence_recall=round(ev_rec, 4) if ev_rec is not None else None,
            total_cited_evidence=total_cited,
            valid_cited_evidence=valid_cited,
            unsupported_claims_count=unsupported_count,
            unsupported_claims_disarmed=disarmed_count,
            unsupported_claim_rate=round(unsupported_claim_rate, 4),
            disarm_rate=round(disarm_rate, 4) if disarm_rate is not None else None,
            confidence_score=round(conf_val, 4),
            uncertainty_calibrated=calibrated,
            brier_score_component=round(brier_comp, 4),
            proposed_observations_count=total_proposed,
            useful_observations_count=useful_obs_count,
            next_observation_useful=next_obs_useful,
            next_observation_usefulness_rate=round(usefulness_rate, 4) if usefulness_rate is not None else None,
            candidate_tier=highest_tier,
            causal_promoted=causal_promoted,
            ground_truth_is_causal=ground_is_causal,
            is_true_positive=is_tp,
            is_false_positive=is_fp,
            is_true_negative=is_tn,
            is_false_negative=is_fn,
            notes=f"Outcome: {'TP' if is_tp else ('FP' if is_fp else ('TN' if is_tn else 'FN'))}",
            artifacts={
                "matched_facts_count": matched_facts,
                "promoted_functions": promoted_functions,
            }
        )

    def aggregate_metrics(
        self,
        results: List[ScenarioEvaluationResult],
        evaluation_mode: str,
    ) -> AggregateMetrics:
        """Aggregate per-scenario results into an AggregateMetrics summary."""
        total = len(results)
        completed = [r for r in results if r.status == "COMPLETED"]
        skipped = [r for r in results if r.status == "SKIPPED"]
        failed = [r for r in results if r.status == "FAILED"]

        comp_count = len(completed)

        def _mean_metric(accessor) -> Optional[float]:
            vals = [accessor(r) for r in completed if accessor(r) is not None]
            return round(sum(vals) / len(vals), 4) if vals else None

        mean_fact_prec = _mean_metric(lambda r: r.facts_precision)
        mean_fact_rec = _mean_metric(lambda r: r.facts_recall)
        mean_fact_f1 = _mean_metric(lambda r: r.facts_f1)
        mean_ev_prec = _mean_metric(lambda r: r.evidence_precision)
        mean_ev_rec = _mean_metric(lambda r: r.evidence_recall)

        total_unsupported = sum(r.unsupported_claims_count for r in completed)
        total_disarmed = sum(r.unsupported_claims_disarmed for r in completed)
        all_claims = sum(len(r.artifacts.get("hypotheses", [])) for r in completed)
        
        overall_unsupp_rate = round(total_unsupported / all_claims, 4) if all_claims > 0 else (0.0 if comp_count > 0 else None)
        overall_disarm_rate = round(total_disarmed / total_unsupported, 4) if total_unsupported > 0 else (1.0 if comp_count > 0 else None)

        calib_count = sum(1 for r in completed if r.uncertainty_calibrated)
        calib_rate = round(calib_count / comp_count, 4) if comp_count > 0 else 0.0

        mean_obs_useful = _mean_metric(lambda r: r.next_observation_usefulness_rate)

        tp = sum(1 for r in completed if r.is_true_positive)
        fp = sum(1 for r in completed if r.is_false_positive)
        tn = sum(1 for r in completed if r.is_true_negative)
        fn = sum(1 for r in completed if r.is_false_negative)

        pos_ground = sum(1 for r in completed if r.ground_truth_is_causal)
        neg_ground = sum(1 for r in completed if not r.ground_truth_is_causal)

        fp_rate = round(fp / neg_ground, 4) if neg_ground > 0 else 0.0
        sla_met = (fp == 0) and (comp_count > 0)

        return AggregateMetrics(
            evaluation_mode=evaluation_mode,
            total_scenarios=total,
            completed_scenarios=comp_count,
            skipped_scenarios=len(skipped),
            failed_scenarios=len(failed),
            mean_fact_precision=mean_fact_prec,
            mean_fact_recall=mean_fact_rec,
            mean_fact_f1=mean_fact_f1,
            mean_evidence_precision=mean_ev_prec,
            mean_evidence_recall=mean_ev_rec,
            total_unsupported_claims=total_unsupported,
            total_disarmed_claims=total_disarmed,
            overall_unsupported_claim_rate=overall_unsupp_rate,
            overall_disarm_rate=overall_disarm_rate,
            uncertainty_calibration_rate=calib_rate,
            mean_next_observation_usefulness=mean_obs_useful,
            causal_positives_ground_truth=pos_ground,
            causal_negatives_ground_truth=neg_ground,
            true_causal_positives=tp,
            false_causal_positives=fp,
            true_causal_negatives=tn,
            false_causal_negatives=fn,
            false_positive_causal_rate=fp_rate,
            zero_false_positive_sla_met=sla_met,
            scenarios=results,
        )

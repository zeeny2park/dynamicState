"""Phase 2.1.5 – 2.1.8 — Comprehensive Diagnostic Report Architecture (Part E1 & E2).

Defines the versioned, unified diagnostic report schema (Sections A through I) and all 20 required
engineering report items, providing a single source of truth driving:
1. MCP tool responses
2. Web UI investigation views
3. HTML incident reports
4. Exported machine-readable JSON & Markdown reports

Explicitly separates the 5 epistemic levels required by Part E1:
- observation (direct runtime observation)
- derived_evidence (evidence derived from parent observations or multi-epoch deltas)
- hypothesis (candidate competing hypothesis under evaluation)
- probable_cause (supported/likely cause lacking full confirmation criteria)
- confirmed_root_cause (authoritatively verified root cause)
"""

from dataclasses import asdict, dataclass, field, fields
from datetime import datetime, timezone
import html
import json
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from .diagnostic_methodology import CheckStatus, DiagnosticCheck, DiagnosticMethodology


SCHEMA_VERSION = "2.1.5"

# Epistemic & Finding Classifications (Part E1)
CLASSIFICATION_OBSERVED_SYMPTOM = "OBSERVED_SYMPTOM"
CLASSIFICATION_DERIVED_EVIDENCE = "DERIVED_EVIDENCE"
CLASSIFICATION_HYPOTHESIS = "HYPOTHESIS"
CLASSIFICATION_ANOMALY = "ANOMALY"
CLASSIFICATION_PROBABLE_CAUSE = "PROBABLE_CAUSE"
CLASSIFICATION_CONFIRMED_ROOT_CAUSE = "CONFIRMED_ROOT_CAUSE"

EPISTEMIC_OBSERVATION = "observation"
EPISTEMIC_DERIVED_EVIDENCE = "derived_evidence"
EPISTEMIC_HYPOTHESIS = "hypothesis"
EPISTEMIC_PROBABLE_CAUSE = "probable_cause"
EPISTEMIC_CONFIRMED_ROOT_CAUSE = "confirmed_root_cause"


def _filter_dataclass_fields(cls: Any, data: Dict[str, Any]) -> Dict[str, Any]:
    valid = {f.name for f in fields(cls)}
    return {k: v for k, v in data.items() if k in valid}


@dataclass
class FindingRecord:
    """Explicit finding record distinguishing observations, derived evidence, hypotheses, probable causes, and confirmed root causes."""
    finding_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    classification: str  # OBSERVED_SYMPTOM, DERIVED_EVIDENCE, HYPOTHESIS, ANOMALY, PROBABLE_CAUSE, CONFIRMED_ROOT_CAUSE
    problem_description: str
    affected_entity: Optional[str] = None  # Object, variable, thread, or memory region
    observed_behavior: str = ""
    technical_explanation: str = ""
    supporting_evidence_ids: List[str] = field(default_factory=list)
    contradicting_evidence_ids: List[str] = field(default_factory=list)
    applicable_diagnostic_rules: List[str] = field(default_factory=list)
    source_references: List[str] = field(default_factory=list)
    causal_relationships: List[str] = field(default_factory=list)
    confidence_basis: str = ""
    verification_status: str = "UNVERIFIED"
    epistemic_level: str = EPISTEMIC_OBSERVATION

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FindingRecord":
        return cls(**_filter_dataclass_fields(cls, data))


@dataclass
class ExecutiveSummarySection:
    target_identity: str
    investigation_id: str
    overall_result: str  # CONFIRMED_FAULT, PROBABLE_FAULT, DEGRADED, INCONCLUSIVE, HEALTHY, ABORTED
    most_important_findings: List[str] = field(default_factory=list)
    confirmed_problems: List[str] = field(default_factory=list)
    probable_problems: List[str] = field(default_factory=list)
    critical_risks: List[str] = field(default_factory=list)
    unresolved_questions: List[str] = field(default_factory=list)
    recommended_next_actions: List[str] = field(default_factory=list)
    verdict_rationale: str = ""
    contributing_factors: List[str] = field(default_factory=list)
    limiting_factors: List[str] = field(default_factory=list)
    determining_checks: List[str] = field(default_factory=list)
    determining_hypotheses: List[str] = field(default_factory=list)
    decision_rule_id: str = ""
    problem_statement: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExecutiveSummarySection":
        return cls(**_filter_dataclass_fields(cls, data))


@dataclass
class TargetContextSection:
    target_process_name: str
    pid: Optional[int]
    process_start_identity: Optional[str] = None
    binary_path: Optional[str] = None
    build_id: Optional[str] = None
    companion_elf: Optional[str] = None
    target_capabilities: List[str] = field(default_factory=list)
    collection_mode: str = "ZERO_STOP_LIVE_RUNTIME"
    observation_interval_sec: Optional[float] = None
    observation_duration_sec: Optional[float] = None
    investigation_start_time: str = ""
    investigation_end_time: str = ""
    collection_failures: List[str] = field(default_factory=list)
    environmental_limitations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TargetContextSection":
        return cls(**_filter_dataclass_fields(cls, data))


@dataclass
class DiagnosticStrategySection:
    initial_classification: str
    classification_confidence: float
    methodology_name: str
    methodology_selection_reason: str
    recipes_executed: List[str] = field(default_factory=list)
    recipes_excluded: List[Dict[str, str]] = field(default_factory=list)
    scope_narrowing_sequence: List[str] = field(default_factory=list)
    key_observations_driving_decisions: List[str] = field(default_factory=list)
    information_gain_prioritization: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DiagnosticStrategySection":
        return cls(**_filter_dataclass_fields(cls, data))


@dataclass
class DetailedInspectionResultsSection:
    checks_total: int
    checks_passed: int
    checks_failed: int
    checks_inconclusive: int
    checks_not_applicable: int
    checks_not_executed: int
    checks_error: int
    checks_skipped: int = 0
    checks_unsupported: int = 0
    required_checks_count: int = 0
    required_checks_passed: int = 0
    missing_coverage: List[str] = field(default_factory=list)
    checks: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DetailedInspectionResultsSection":
        return cls(**_filter_dataclass_fields(cls, data))


@dataclass
class FindingsSection:
    confirmed_root_causes: List[FindingRecord] = field(default_factory=list)
    probable_causes: List[FindingRecord] = field(default_factory=list)
    anomalies: List[FindingRecord] = field(default_factory=list)
    observed_symptoms: List[FindingRecord] = field(default_factory=list)
    derived_evidence: List[FindingRecord] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "confirmed_root_causes": [f.to_dict() for f in self.confirmed_root_causes],
            "probable_causes": [f.to_dict() for f in self.probable_causes],
            "anomalies": [f.to_dict() for f in self.anomalies],
            "observed_symptoms": [f.to_dict() for f in self.observed_symptoms],
            "derived_evidence": [f.to_dict() for f in self.derived_evidence],
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FindingsSection":
        return cls(
            confirmed_root_causes=[FindingRecord.from_dict(x) if isinstance(x, dict) else x for x in data.get("confirmed_root_causes", [])],
            probable_causes=[FindingRecord.from_dict(x) if isinstance(x, dict) else x for x in data.get("probable_causes", [])],
            anomalies=[FindingRecord.from_dict(x) if isinstance(x, dict) else x for x in data.get("anomalies", [])],
            observed_symptoms=[FindingRecord.from_dict(x) if isinstance(x, dict) else x for x in data.get("observed_symptoms", [])],
            derived_evidence=[FindingRecord.from_dict(x) if isinstance(x, dict) else x for x in data.get("derived_evidence", [])],
        )


@dataclass
class CompetingHypothesesSection:
    leading_hypothesis_id: Optional[str]
    hypotheses: List[Dict[str, Any]] = field(default_factory=list)
    ranking_rationale: str = ""
    eliminated_alternatives: List[Dict[str, str]] = field(default_factory=list)
    missing_evidence_preventing_conclusions: List[str] = field(default_factory=list)
    double_counting_protections_applied: bool = True
    competing_candidates: List[Dict[str, Any]] = field(default_factory=list)
    primary_evidence_rules_evaluated: List[Dict[str, Any]] = field(default_factory=list)
    rejected_evidence: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CompetingHypothesesSection":
        return cls(**_filter_dataclass_fields(cls, data))


@dataclass
class EvidenceIndexEntry:
    evidence_id: str
    collection_method: str
    target_pid: Optional[int]
    timestamp: str
    duration_sec: float
    provenance_class: str
    raw_observation: Any
    normalized_observation: Any
    correlated_source: Optional[Dict[str, Any]] = None
    associated_checks: List[str] = field(default_factory=list)
    associated_hypotheses: List[str] = field(default_factory=list)
    associated_findings: List[str] = field(default_factory=list)
    parent_evidence_ids: List[str] = field(default_factory=list)
    epistemic_level: str = EPISTEMIC_OBSERVATION
    authority_status: str = "VERIFIED"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvidenceIndexEntry":
        return cls(**_filter_dataclass_fields(cls, data))


@dataclass
class EvidenceAndProvenanceSection:
    evidence_count: int
    evidence_records: List[EvidenceIndexEntry] = field(default_factory=list)
    independent_root_sources: List[str] = field(default_factory=list)
    dependency_graph: Dict[str, List[str]] = field(default_factory=dict)
    rejected_or_unverified_evidence: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_count": self.evidence_count,
            "evidence_records": [e.to_dict() for e in self.evidence_records],
            "independent_root_sources": list(self.independent_root_sources),
            "dependency_graph": dict(self.dependency_graph),
            "rejected_or_unverified_evidence": dict(self.rejected_or_unverified_evidence),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvidenceAndProvenanceSection":
        recs = [
            EvidenceIndexEntry.from_dict(e) if isinstance(e, dict) else e
            for e in data.get("evidence_records", [])
        ]
        return cls(
            evidence_count=data.get("evidence_count", len(recs)),
            evidence_records=recs,
            independent_root_sources=list(data.get("independent_root_sources", [])),
            dependency_graph=dict(data.get("dependency_graph", {})),
            rejected_or_unverified_evidence=dict(data.get("rejected_or_unverified_evidence", {})),
        )


@dataclass
class LimitationsSection:
    unexecuted_checks: List[str] = field(default_factory=list)
    unsupported_capabilities: List[str] = field(default_factory=list)
    collection_failures: List[str] = field(default_factory=list)
    missing_symbols_or_dwarf: List[str] = field(default_factory=list)
    incomplete_temporal_observations: List[str] = field(default_factory=list)
    incomplete_lock_graphs: List[str] = field(default_factory=list)
    unavailable_allocator_metadata: List[str] = field(default_factory=list)
    unverified_causal_relationships: List[str] = field(default_factory=list)
    confidence_limiting_factors: List[str] = field(default_factory=list)
    missing_identity_records: List[str] = field(default_factory=list)
    mismatched_identity_records: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LimitationsSection":
        return cls(**_filter_dataclass_fields(cls, data))


@dataclass
class FinalConclusionsSection:
    overall_conclusion: str
    confirmed_problems: List[str] = field(default_factory=list)
    probable_problems: List[str] = field(default_factory=list)
    ruled_out_hypotheses: List[Dict[str, str]] = field(default_factory=list)
    remaining_uncertainties: List[str] = field(default_factory=list)
    recommended_next_diagnostic_steps: List[str] = field(default_factory=list)
    expected_information_value: List[str] = field(default_factory=list)
    safe_remediation_suggestions: List[str] = field(default_factory=list)
    verdict_rationale: str = ""
    decision_trace: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FinalConclusionsSection":
        return cls(**_filter_dataclass_fields(cls, data))


@dataclass
class DiagnosticReport:
    """Master structured diagnostic report for Phase 2.1.8 (Sections A–I + 20 Required Engineering Items)."""
    report_id: str
    investigation_id: str
    schema_version: str = SCHEMA_VERSION
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    section_a_executive_summary: Optional[ExecutiveSummarySection] = None
    section_b_target_context: Optional[TargetContextSection] = None
    section_c_diagnostic_strategy: Optional[DiagnosticStrategySection] = None
    section_d_detailed_inspection_results: Optional[DetailedInspectionResultsSection] = None
    section_e_findings_and_root_cause: Optional[FindingsSection] = None
    section_f_competing_hypotheses: Optional[CompetingHypothesesSection] = None
    section_g_evidence_and_provenance: Optional[EvidenceAndProvenanceSection] = None
    section_h_limitations_and_unverified: Optional[LimitationsSection] = None
    section_i_final_conclusions: Optional[FinalConclusionsSection] = None

    def build_epistemic_hierarchy(self) -> Dict[str, List[Dict[str, Any]]]:
        """Explicitly separates the 5 epistemic classes required by Part E1:
        1. observation
        2. derived_evidence
        3. hypothesis
        4. probable_cause
        5. confirmed_root_cause
        """
        sec_e = self.section_e_findings_and_root_cause
        sec_f = self.section_f_competing_hypotheses
        sec_g = self.section_g_evidence_and_provenance

        observations: List[Dict[str, Any]] = []
        derived_ev: List[Dict[str, Any]] = []
        if sec_g:
            for ev in sec_g.evidence_records:
                entry = {
                    "evidence_id": ev.evidence_id,
                    "method": ev.collection_method,
                    "provenance_class": ev.provenance_class,
                    "observed_value": ev.normalized_observation,
                    "parent_evidence_ids": list(ev.parent_evidence_ids),
                    "epistemic_level": EPISTEMIC_DERIVED_EVIDENCE if ev.parent_evidence_ids else EPISTEMIC_OBSERVATION,
                }
                if ev.parent_evidence_ids or ev.epistemic_level == EPISTEMIC_DERIVED_EVIDENCE:
                    derived_ev.append(entry)
                else:
                    observations.append(entry)
        if sec_e and sec_e.derived_evidence:
            for df in sec_e.derived_evidence:
                derived_ev.append(df.to_dict())

        hypotheses_list: List[Dict[str, Any]] = []
        if sec_f:
            for h in sec_f.hypotheses:
                hypotheses_list.append({
                    "hypothesis_id": h.get("hypothesis_id"),
                    "statement": h.get("problem_statement") or h.get("title"),
                    "status": h.get("status"),
                    "confidence": h.get("confidence"),
                    "epistemic_level": EPISTEMIC_HYPOTHESIS,
                })

        probable_list = [f.to_dict() for f in (sec_e.probable_causes if sec_e else [])]
        confirmed_list = [f.to_dict() for f in (sec_e.confirmed_root_causes if sec_e else [])]

        return {
            EPISTEMIC_OBSERVATION: observations,
            EPISTEMIC_DERIVED_EVIDENCE: derived_ev,
            EPISTEMIC_HYPOTHESIS: hypotheses_list,
            EPISTEMIC_PROBABLE_CAUSE: probable_list,
            EPISTEMIC_CONFIRMED_ROOT_CAUSE: confirmed_list,
        }

    def build_20_required_items(self) -> Dict[str, Any]:
        """Builds the explicit 20-item structure mandated by Phase 2.1.8 Part E1."""
        sec_a = self.section_a_executive_summary
        sec_b = self.section_b_target_context
        sec_c = self.section_c_diagnostic_strategy
        sec_d = self.section_d_detailed_inspection_results
        sec_e = self.section_e_findings_and_root_cause
        sec_f = self.section_f_competing_hypotheses
        sec_g = self.section_g_evidence_and_provenance
        sec_h = self.section_h_limitations_and_unverified
        sec_i = self.section_i_final_conclusions

        checks_list = sec_d.checks if sec_d else []
        executed_checks = [c for c in checks_list if c.get("status") in ("PASS", "FAIL", "INCONCLUSIVE", "ERROR")]
        skipped_or_unexec = [
            c for c in checks_list
            if c.get("status") in ("NOT_EXECUTED", "SKIPPED", "UNSUPPORTED", "NOT_APPLICABLE")
        ]

        return {
            "1_executive_summary_and_overall_verdict": {
                "overall_verdict": sec_a.overall_result if sec_a else "INCONCLUSIVE",
                "verdict_rationale": sec_a.verdict_rationale if sec_a else "",
                "most_important_findings": sec_a.most_important_findings if sec_a else [],
                "determining_checks": sec_a.determining_checks if sec_a else [],
                "determining_hypotheses": sec_a.determining_hypotheses if sec_a else [],
            },
            "2_target_identity_and_process_metadata": sec_b.to_dict() if sec_b else {},
            "3_investigation_context_and_capabilities": {
                "capabilities": sec_b.target_capabilities if sec_b else [],
                "collection_mode": sec_b.collection_mode if sec_b else "ZERO_STOP_LIVE_RUNTIME",
                "environmental_limitations": sec_b.environmental_limitations if sec_b else [],
            },
            "4_initial_symptom_and_classification": {
                "problem_statement": sec_a.problem_statement if sec_a else "",
                "initial_classification": sec_c.initial_classification if sec_c else "UNKNOWN",
                "classification_confidence": sec_c.classification_confidence if sec_c else 0.0,
            },
            "5_selected_diagnostic_methodology": {
                "methodology_name": sec_c.methodology_name if sec_c else "",
                "selection_reason": sec_c.methodology_selection_reason if sec_c else "",
                "scope_narrowing_sequence": sec_c.scope_narrowing_sequence if sec_c else [],
            },
            "6_executed_checks_and_recipes": executed_checks,
            "7_skipped_unsupported_not_applicable_unexecuted_checks": {
                "checks": skipped_or_unexec,
                "excluded_recipes": sec_c.recipes_excluded if sec_c else [],
            },
            "8_actual_runtime_observations": [
                e.to_dict() for e in (sec_g.evidence_records if sec_g else [])
            ],
            "9_evidence_provenance_and_authority_status": {
                "evidence_count": sec_g.evidence_count if sec_g else 0,
                "records": [
                    {
                        "evidence_id": e.evidence_id,
                        "provenance_class": e.provenance_class,
                        "authority_status": e.authority_status,
                        "epistemic_level": e.epistemic_level,
                    }
                    for e in (sec_g.evidence_records if sec_g else [])
                ],
                "rejected_or_unverified": sec_g.rejected_or_unverified_evidence if sec_g else {},
            },
            "10_evidence_dependency_graph_and_independent_root_sources": {
                "independent_root_sources": sec_g.independent_root_sources if sec_g else [],
                "dependency_graph": sec_g.dependency_graph if sec_g else {},
            },
            "11_confirmed_root_causes": [f.to_dict() for f in (sec_e.confirmed_root_causes if sec_e else [])],
            "12_probable_causes": [f.to_dict() for f in (sec_e.probable_causes if sec_e else [])],
            "13_rejected_hypotheses_and_refutation_evidence": sec_f.eliminated_alternatives if sec_f else [],
            "14_unresolved_hypotheses_and_missing_evidence": {
                "unresolved_questions": sec_a.unresolved_questions if sec_a else [],
                "missing_evidence": sec_f.missing_evidence_preventing_conclusions if sec_f else [],
            },
            "15_source_symbol_dwarf_correlation": [
                {
                    "evidence_id": e.evidence_id,
                    "correlated_source": e.correlated_source,
                }
                for e in (sec_g.evidence_records if sec_g else [])
                if e.correlated_source
            ],
            "16_primary_evidence_rules_used": sec_f.primary_evidence_rules_evaluated if sec_f else [],
            "17_contradictions_and_conflict_handling": [
                {
                    "hypothesis_id": ch.get("hypothesis_id"),
                    "contradiction_records": ch.get("contradiction_records", []),
                    "contradiction_summary": (ch.get("decision_trace") or {}).get("contradiction_summary", {}),
                }
                for ch in (sec_f.competing_candidates if sec_f else [])
            ],
            "18_limitations_and_unverified_areas": sec_h.to_dict() if sec_h else {},
            "19_recommended_next_diagnostic_steps": sec_i.recommended_next_diagnostic_steps if sec_i else [],
            "20_safe_remediation_guidance": sec_i.safe_remediation_suggestions if sec_i else [],
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "report_id": self.report_id,
            "investigation_id": self.investigation_id,
            "generated_at": self.generated_at,
            "section_a_executive_summary": self.section_a_executive_summary.to_dict() if self.section_a_executive_summary else {},
            "section_b_target_context": self.section_b_target_context.to_dict() if self.section_b_target_context else {},
            "section_c_diagnostic_strategy": self.section_c_diagnostic_strategy.to_dict() if self.section_c_diagnostic_strategy else {},
            "section_d_detailed_inspection_results": self.section_d_detailed_inspection_results.to_dict() if self.section_d_detailed_inspection_results else {},
            "section_e_findings_and_root_cause": self.section_e_findings_and_root_cause.to_dict() if self.section_e_findings_and_root_cause else {},
            "section_f_competing_hypotheses": self.section_f_competing_hypotheses.to_dict() if self.section_f_competing_hypotheses else {},
            "section_g_evidence_and_provenance": self.section_g_evidence_and_provenance.to_dict() if self.section_g_evidence_and_provenance else {},
            "section_h_limitations_and_unverified": self.section_h_limitations_and_unverified.to_dict() if self.section_h_limitations_and_unverified else {},
            "section_i_final_conclusions": self.section_i_final_conclusions.to_dict() if self.section_i_final_conclusions else {},
            "epistemic_hierarchy": self.build_epistemic_hierarchy(),
            "report_20_items": self.build_20_required_items(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "DiagnosticReport":
        return cls(
            report_id=data.get("report_id", "rep_unknown"),
            investigation_id=data.get("investigation_id", "inv_unknown"),
            schema_version=data.get("schema_version", SCHEMA_VERSION),
            generated_at=data.get("generated_at", datetime.now(timezone.utc).isoformat()),
            section_a_executive_summary=ExecutiveSummarySection.from_dict(data["section_a_executive_summary"]) if data.get("section_a_executive_summary") else None,
            section_b_target_context=TargetContextSection.from_dict(data["section_b_target_context"]) if data.get("section_b_target_context") else None,
            section_c_diagnostic_strategy=DiagnosticStrategySection.from_dict(data["section_c_diagnostic_strategy"]) if data.get("section_c_diagnostic_strategy") else None,
            section_d_detailed_inspection_results=DetailedInspectionResultsSection.from_dict(data["section_d_detailed_inspection_results"]) if data.get("section_d_detailed_inspection_results") else None,
            section_e_findings_and_root_cause=FindingsSection.from_dict(data["section_e_findings_and_root_cause"]) if data.get("section_e_findings_and_root_cause") else None,
            section_f_competing_hypotheses=CompetingHypothesesSection.from_dict(data["section_f_competing_hypotheses"]) if data.get("section_f_competing_hypotheses") else None,
            section_g_evidence_and_provenance=EvidenceAndProvenanceSection.from_dict(data["section_g_evidence_and_provenance"]) if data.get("section_g_evidence_and_provenance") else None,
            section_h_limitations_and_unverified=LimitationsSection.from_dict(data["section_h_limitations_and_unverified"]) if data.get("section_h_limitations_and_unverified") else None,
            section_i_final_conclusions=FinalConclusionsSection.from_dict(data["section_i_final_conclusions"]) if data.get("section_i_final_conclusions") else None,
        )

    @classmethod
    def from_json(cls, json_str: str) -> "DiagnosticReport":
        return cls.from_dict(json.loads(json_str))

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_markdown(self) -> str:
        sec_a = self.section_a_executive_summary
        sec_b = self.section_b_target_context
        sec_c = self.section_c_diagnostic_strategy
        sec_d = self.section_d_detailed_inspection_results
        sec_e = self.section_e_findings_and_root_cause
        sec_f = self.section_f_competing_hypotheses
        sec_g = self.section_g_evidence_and_provenance
        sec_h = self.section_h_limitations_and_unverified
        sec_i = self.section_i_final_conclusions

        md = [
            "# dynamicState Expert Diagnostic Incident Report",
            f"**Report ID**: `{self.report_id}` | **Investigation ID**: `{self.investigation_id}` | **Schema**: `v{self.schema_version}`  ",
            f"**Generated**: `{self.generated_at}`  ",
            "",
            "---",
            "## 1. Problem Description & Executive Summary (Section A)",
        ]
        if sec_a:
            md.extend([
                f"- **Overall Result**: `{sec_a.overall_result}`",
                f"- **Target Identity**: {sec_a.target_identity}",
                f"- **Verdict Rationale**: {sec_a.verdict_rationale}",
                f"- **Decision Rule ID**: `{sec_a.decision_rule_id or 'N/A'}`",
                f"- **Determining Checks**: `{', '.join(sec_a.determining_checks) if sec_a.determining_checks else 'N/A'}`",
                f"- **Determining Hypotheses**: `{', '.join(sec_a.determining_hypotheses) if sec_a.determining_hypotheses else 'N/A'}`",
                "",
                "### Confirmed Root Causes vs Suspected Problems",
            ])
            if sec_a.confirmed_problems:
                md.append("#### [CONFIRMED PROBLEMS]")
                for p in sec_a.confirmed_problems:
                    md.append(f"- **[CONFIRMED]** {p}")
            else:
                md.append("- No confirmed root causes.")

            if sec_a.probable_problems:
                md.append("#### [PROBABLE / SUSPECTED PROBLEMS]")
                for p in sec_a.probable_problems:
                    md.append(f"- **[PROBABLE]** {p}")

            if sec_a.contributing_factors:
                md.append("#### [CONTRIBUTING FACTORS]")
                for cf in sec_a.contributing_factors:
                    md.append(f"- {cf}")

            if sec_a.limiting_factors:
                md.append("#### [LIMITING FACTORS]")
                for lf in sec_a.limiting_factors:
                    md.append(f"- {lf}")

            if sec_a.critical_risks:
                md.append("#### [CRITICAL RISKS]")
                for r in sec_a.critical_risks:
                    md.append(f"- ⚠️ {r}")

            if sec_a.unresolved_questions:
                md.append("#### [UNRESOLVED QUESTIONS]")
                for q in sec_a.unresolved_questions:
                    md.append(f"- ❓ {q}")

        md.extend([
            "",
            "---",
            "## 2. Target Information & Investigation Context (Section B)",
        ])
        if sec_b:
            md.extend([
                f"- **Process Name**: `{sec_b.target_process_name}` (PID: `{sec_b.pid}`)",
                f"- **Process Start Identity**: `{sec_b.process_start_identity or 'N/A'}`",
                f"- **Binary / Build ID**: `{sec_b.binary_path}` | Build ID: `{sec_b.build_id or 'N/A'}`",
                f"- **Companion ELF**: `{sec_b.companion_elf or 'N/A'}`",
                f"- **Collection Mode**: `{sec_b.collection_mode}` (Interval: `{sec_b.observation_interval_sec}s`, Duration: `{sec_b.observation_duration_sec}s`)",
                f"- **Timestamps**: Start: `{sec_b.investigation_start_time}` | End: `{sec_b.investigation_end_time}`",
                f"- **Target Capabilities**: `{', '.join(sec_b.target_capabilities) if sec_b.target_capabilities else 'NONE'}`",
            ])
            if sec_b.collection_failures:
                md.append(f"- **Collection Failures**: {'; '.join(sec_b.collection_failures)}")
            if sec_b.environmental_limitations:
                md.append(f"- **Environmental Limitations**: {'; '.join(sec_b.environmental_limitations)}")

        md.extend([
            "",
            "---",
            "## 3. Initial Classification & Diagnostic Strategy (Section C)",
        ])
        if sec_c:
            md.extend([
                f"- **Initial Problem Classification**: `{sec_c.initial_classification}` (Confidence: `{sec_c.classification_confidence * 100:.1f}%`)",
                f"- **Selected Methodology**: `{sec_c.methodology_name}`",
                f"- **Selection Rationale**: {sec_c.methodology_selection_reason}",
                f"- **Executed Recipes**: `{', '.join(sec_c.recipes_executed)}`",
            ])
            if sec_c.key_observations_driving_decisions:
                md.append(f"- **Key Observations Driving Decisions**: {'; '.join(sec_c.key_observations_driving_decisions)}")
            if sec_c.information_gain_prioritization:
                md.append(f"- **Information-Gain Prioritization**: {'; '.join(sec_c.information_gain_prioritization)}")
            if sec_c.recipes_excluded:
                md.append("- **Excluded Recipes**:")
                for ex in sec_c.recipes_excluded:
                    md.append(f"  - `{ex.get('recipe_id')}`: {ex.get('reason_excluded')}")

        md.extend([
            "",
            "---",
            "## 4. Investigation Scope",
        ])
        if sec_c and sec_c.scope_narrowing_sequence:
            for sn in sec_c.scope_narrowing_sequence:
                md.append(f"- {sn}")
        else:
            md.append("- Target process memory regions, threads, and relevant variables.")

        md.extend([
            "",
            "---",
            "## 5. Executed Diagnostic Procedures & Inspection Results (Section D)",
        ])
        if sec_d:
            extra_counts = (
                f" | SKIPPED: `{sec_d.checks_skipped}`"
                f" | UNSUPPORTED: `{sec_d.checks_unsupported}`"
                f" | Required Passed: `{sec_d.required_checks_passed}/{sec_d.required_checks_count}`"
            )
            md.append(
                f"**Summary**: Total Checks: `{sec_d.checks_total}` | "
                f"PASS: `{sec_d.checks_passed}` | FAIL: `{sec_d.checks_failed}` | "
                f"INCONCLUSIVE: `{sec_d.checks_inconclusive}` | NOT_APPLICABLE: `{sec_d.checks_not_applicable}` | "
                f"NOT_EXECUTED: `{sec_d.checks_not_executed}` | ERROR: `{sec_d.checks_error}`{extra_counts}\n"
            )
            if sec_d.missing_coverage:
                md.append(f"- **Missing Required Coverage**: `{', '.join(sec_d.missing_coverage)}`\n")
            for c in sec_d.checks:
                status_badge = f"[{c.get('status')}]"
                md.append(f"### {status_badge} `{c.get('check_id')}`: {c.get('name')}")
                md.append(f"- **Recipe**: `{c.get('recipe_id')}` (v`{c.get('recipe_version')}`)")
                md.append(f"- **Technical Principle**: {c.get('technical_rationale')}")
                md.append(f"- **Decision Criteria**: `{c.get('decision_criteria')}`")
                md.append(f"- **Inspected Entity**: `{c.get('inspected_entity') or 'Target Address Space'}`")
                md.append(f"- **Actual Observations**: `{c.get('actual_observations')}`")
                md.append(f"- **Technical Interpretation**: {c.get('technical_interpretation') or 'No anomalies detected.'}")
                if c.get("supporting_evidence_ids"):
                    md.append(f"- **Supporting Evidence IDs**: `{', '.join(c.get('supporting_evidence_ids'))}`")
                if c.get("contradicting_evidence_ids"):
                    md.append(f"- **Contradicting Evidence IDs**: `{', '.join(c.get('contradicting_evidence_ids'))}`")
                if c.get("limitations"):
                    md.append(f"- **Limitations**: {'; '.join(c.get('limitations'))}")
                dur_val = c.get("duration_seconds")
                dur_str = f"{dur_val:.4f}s" if (dur_val is not None and isinstance(dur_val, (int, float))) else "UNKNOWN"
                md.append(f"- **Duration**: `{dur_str}` (Start: `{c.get('start_timestamp') or 'N/A'}`)\n")

        md.extend([
            "---",
            "## 6. Actual Observations & Derived Evidence",
        ])
        if sec_g:
            for obs in sec_g.evidence_records:
                ep_tag = "[DERIVED EVIDENCE]" if (obs.parent_evidence_ids or obs.epistemic_level == EPISTEMIC_DERIVED_EVIDENCE) else "[OBSERVED FACT]"
                md.append(
                    f"- `[{obs.evidence_id}]` {ep_tag} Method: `{obs.collection_method}` | "
                    f"Authority: `{obs.authority_status}` | Value: `{obs.normalized_observation}`"
                )
            md.append("")

        md.extend([
            "---",
            "## 7. Confirmed Findings & Technical Root Cause (Section E)",
        ])
        if sec_e:
            all_findings = (
                sec_e.confirmed_root_causes +
                sec_e.probable_causes +
                sec_e.anomalies +
                sec_e.observed_symptoms +
                sec_e.derived_evidence
            )
            if all_findings:
                for f in all_findings:
                    cls_badge = f"[{f.classification}]"
                    sev_badge = f"[{f.severity}]"
                    md.append(f"### {cls_badge} {sev_badge} `{f.finding_id}`: {f.problem_description}")
                    md.append(f"- **Classification**: `{f.classification}` | **Epistemic Level**: `{f.epistemic_level}` | **Verification**: `{f.verification_status}`")
                    md.append(f"- **Affected Entity**: `{f.affected_entity or 'Unspecified'}`")
                    md.append(f"- **Observed Behavior**: {f.observed_behavior}")
                    md.append(f"- **Technical Explanation**: {f.technical_explanation}")
                    md.append(f"- **Confidence Basis**: {f.confidence_basis}")
                    if f.supporting_evidence_ids:
                        md.append(f"- **Supporting Evidence**: `{', '.join(f.supporting_evidence_ids)}`")
                    if f.contradicting_evidence_ids:
                        md.append(f"- **Contradicting Evidence**: `{', '.join(f.contradicting_evidence_ids)}`")
                    if f.source_references:
                        md.append(f"- **Source Locations**: `{', '.join(f.source_references)}`")
                    if f.causal_relationships:
                        md.append(f"- **Causal Links**: {'; '.join(f.causal_relationships)}")
                    md.append("")
            else:
                md.append("- No abnormal findings detected.\n")

        md.extend([
            "---",
            "## 8. Probable Causes",
        ])
        if sec_a and sec_a.probable_problems:
            for pp in sec_a.probable_problems:
                md.append(f"- {pp}")
        else:
            md.append("- None identified.")

        md.extend([
            "",
            "---",
            "## 9. Rejected Hypotheses & Refutation Evidence (Section F)",
        ])
        if sec_f and sec_f.eliminated_alternatives:
            for ea in sec_f.eliminated_alternatives:
                md.append(f"- **[REFUTED]** `{ea.get('hypothesis_id')}`: {ea.get('rationale')}")
        else:
            md.append("- None.")

        md.extend([
            "",
            "---",
            "## 10. Unresolved Hypotheses, Primary Evidence Rules & Contradiction Handling",
        ])
        if sec_f:
            unresolved = [h for h in sec_f.hypotheses if h.get("status") in ("PROPOSED", "LIKELY", "SUPPORTED", "INCONCLUSIVE")]
            if unresolved:
                for uh in unresolved:
                    md.append(f"- **[{uh.get('status')}]** `{uh.get('hypothesis_id')}`: {uh.get('problem_statement') or uh.get('title')}")
            else:
                md.append("- None.")
            if sec_f.primary_evidence_rules_evaluated:
                md.append("\n### Primary Evidence Rules Evaluated")
                for pr in sec_f.primary_evidence_rules_evaluated:
                    md.append(f"- Rule `{pr.get('rule_id')}` (v`{pr.get('version', '2.1.8')}`): authorized=`{pr.get('authorized')}` ({pr.get('reason')})")
            if sec_f.rejected_evidence:
                md.append("\n### Rejected / Unverified Evidence Decisions")
                for re_id, re_reason in sorted(sec_f.rejected_evidence.items()):
                    md.append(f"- `{re_id}`: {re_reason}")

        md.extend([
            "",
            "---",
            "## 11. Evidence-to-Source Mapping, Dependency Graph & Provenance Index (Section G)",
        ])
        if sec_g:
            md.append(f"Total Navigable Evidence Records: `{sec_g.evidence_count}`")
            md.append(f"- **Independent Root Evidence Sources**: `{', '.join(sec_g.independent_root_sources) if sec_g.independent_root_sources else 'NONE'}`")
            if sec_g.dependency_graph:
                md.append(f"- **Evidence Dependency Graph**: `{json.dumps(sec_g.dependency_graph, sort_keys=True)}`")
            md.append("")
            for ev in sec_g.evidence_records:
                md.append(f"### `[{ev.evidence_id}]` ({ev.provenance_class}) [{ev.epistemic_level}]")
                md.append(
                    f"- **Method**: `{ev.collection_method}` | **Target PID**: `{ev.target_pid}` | "
                    f"**Timestamp**: `{ev.timestamp}` | **Duration**: `{ev.duration_sec:.6f}s` | "
                    f"**Authority**: `{ev.authority_status}`"
                )
                if ev.parent_evidence_ids:
                    md.append(f"- **Parent Evidence IDs**: `{', '.join(ev.parent_evidence_ids)}`")
                md.append(f"- **Normalized Observation**: `{ev.normalized_observation}`")
                if ev.correlated_source:
                    corr = ev.correlated_source
                    md.append(
                        f"- **Source Mapping**: `{corr.get('demangled_symbol')}` at "
                        f"`{corr.get('source_file')}:{corr.get('source_line')}` "
                        f"(Runtime: `{corr.get('runtime_address')}`, Bias: `{corr.get('load_bias')}`)"
                    )
                if ev.associated_checks:
                    md.append(f"- **Consumed in Checks**: `{', '.join(ev.associated_checks)}`")
                md.append("")

        md.extend([
            "---",
            "## 12. Missing Evidence & Limitations (Section H)",
        ])
        if sec_h:
            md.append("> *Note: Absence of evidence is never presented as evidence of absence.*\n")
            if sec_h.unexecuted_checks:
                md.append(f"- **Unexecuted Checks**: {'; '.join(sec_h.unexecuted_checks)}")
            if sec_h.unsupported_capabilities:
                md.append(f"- **Unsupported Capabilities**: {'; '.join(sec_h.unsupported_capabilities)}")
            if sec_h.collection_failures:
                md.append(f"- **Failed Collections**: {'; '.join(sec_h.collection_failures)}")
            if sec_h.missing_symbols_or_dwarf:
                md.append(f"- **Missing Symbols / DWARF**: {'; '.join(sec_h.missing_symbols_or_dwarf)}")
            if sec_h.incomplete_temporal_observations:
                md.append(f"- **Incomplete Temporal Samples**: {'; '.join(sec_h.incomplete_temporal_observations)}")
            if sec_h.incomplete_lock_graphs:
                md.append(f"- **Incomplete Lock Graphs**: {'; '.join(sec_h.incomplete_lock_graphs)}")
            if sec_h.unavailable_allocator_metadata:
                md.append(f"- **Unavailable Allocator Metadata**: {'; '.join(sec_h.unavailable_allocator_metadata)}")
            if sec_h.unverified_causal_relationships:
                md.append(f"- **Unverified Causal Relationships**: {'; '.join(sec_h.unverified_causal_relationships)}")
            if sec_h.missing_identity_records:
                md.append(f"- **Missing Identity Metadata Records**: {'; '.join(sec_h.missing_identity_records)}")
            if sec_h.mismatched_identity_records:
                md.append(f"- **Mismatched Identity Records**: {'; '.join(sec_h.mismatched_identity_records)}")
            if sec_h.confidence_limiting_factors:
                md.append(f"- **Confidence Limiting Factors**: {'; '.join(sec_h.confidence_limiting_factors)}")

        md.extend([
            "",
            "---",
            "## 13. Recommended Next Actions & Final Conclusion (Section I)",
        ])
        if sec_i:
            md.extend([
                f"### Overall Conclusion: `{sec_i.overall_conclusion}`",
                f"- **Verdict Rationale**: {sec_i.verdict_rationale or (sec_a.verdict_rationale if sec_a else '')}",
                "",
                "#### Confirmed Problems",
            ])
            if sec_i.confirmed_problems:
                for cp in sec_i.confirmed_problems:
                    md.append(f"- **[CONFIRMED]** {cp}")
            else:
                md.append("- None.")

            md.append("\n#### Probable Problems")
            if sec_i.probable_problems:
                for pp in sec_i.probable_problems:
                    md.append(f"- **[PROBABLE]** {pp}")
            else:
                md.append("- None.")

            if sec_i.remaining_uncertainties:
                md.append("\n#### Remaining Uncertainty")
                for ru in sec_i.remaining_uncertainties:
                    md.append(f"- {ru}")

            md.append("\n#### Recommended Next Diagnostic Actions")
            for na in sec_i.recommended_next_diagnostic_steps:
                md.append(f"- [ ] {na}")

            if sec_i.safe_remediation_suggestions:
                md.append("\n#### Safe Remediation Suggestions")
                for rm in sec_i.safe_remediation_suggestions:
                    md.append(f"- 🔧 {rm}")

        return "\n".join(md)

    def to_html(self) -> str:
        """Renders complete, standalone, HTML-escaped engineering diagnostic report without truncation."""
        sec_a = self.section_a_executive_summary
        sec_b = self.section_b_target_context
        sec_c = self.section_c_diagnostic_strategy
        sec_d = self.section_d_detailed_inspection_results
        sec_e = self.section_e_findings_and_root_cause
        sec_f = self.section_f_competing_hypotheses
        sec_g = self.section_g_evidence_and_provenance
        sec_h = self.section_h_limitations_and_unverified
        sec_i = self.section_i_final_conclusions

        def badge(text: str, color_type: str = "") -> str:
            colors = {
                "CONFIRMED": "#b91c1c; color: #fff",
                "CONFIRMED_FAULT": "#b91c1c; color: #fff",
                "FAULT": "#b91c1c; color: #fff",
                "FAIL": "#b91c1c; color: #fff",
                "DEGRADED": "#ea580c; color: #fff",
                "LIKELY": "#d97706; color: #fff",
                "PROBABLE": "#d97706; color: #fff",
                "PROBABLE_FAULT": "#d97706; color: #fff",
                "SUPPORTED": "#2563eb; color: #fff",
                "PASS": "#15803d; color: #fff",
                "HEALTHY": "#15803d; color: #fff",
                "INCONCLUSIVE": "#6b7280; color: #fff",
                "NOT_APPLICABLE": "#4b5563; color: #fff",
                "NOT_EXECUTED": "#9ca3af; color: #111",
                "SKIPPED": "#64748b; color: #fff",
                "UNSUPPORTED": "#64748b; color: #fff",
                "ERROR": "#dc2626; color: #fff",
                "REFUTED": "#475569; color: #fff",
                "CRITICAL": "#991b1b; color: #fff",
                "HIGH": "#c2410c; color: #fff",
                "MEDIUM": "#d97706; color: #fff",
                "LOW": "#0284c7; color: #fff",
            }
            style = colors.get(str(text).upper(), "background: #475569; color: #fff")
            return f'<span style="display:inline-block; padding: 2px 8px; border-radius: 4px; font-weight:600; font-size:11px; font-family:monospace; background:{style}">{html.escape(str(text))}</span>'

        css = """
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.5; color: #1e293b; background: #f8fafc; margin: 0; padding: 24px; }
        .report-card { max-width: 1100px; margin: 0 auto; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); padding: 36px; }
        h1 { font-size: 24px; border-bottom: 2px solid #0f172a; padding-bottom: 8px; margin-top: 0; color: #0f172a; }
        h2 { font-size: 18px; color: #1e293b; border-bottom: 1px solid #cbd5e1; padding-bottom: 6px; margin-top: 32px; }
        h3 { font-size: 15px; color: #334155; margin-top: 18px; margin-bottom: 6px; }
        .meta-bar { background: #f1f5f9; padding: 12px 16px; border-radius: 6px; font-size: 13px; font-family: monospace; margin-bottom: 24px; border-left: 4px solid #3b82f6; }
        table { width: 100%; border-collapse: collapse; margin-top: 12px; margin-bottom: 16px; font-size: 13px; }
        th, td { border: 1px solid #e2e8f0; padding: 8px 12px; text-align: left; vertical-align: top; }
        th { background: #f8fafc; font-weight: 600; color: #475569; }
        tr:nth-child(even) { background: #fafafa; }
        .code-box { background: #0f172a; color: #f8fafc; padding: 10px 14px; border-radius: 6px; font-family: monospace; font-size: 12px; overflow-x: auto; }
        .alert-box { background: #fffbeb; border: 1px solid #fef3c7; border-left: 4px solid #f59e0b; padding: 12px 16px; border-radius: 4px; font-size: 13px; margin: 16px 0; }
        ul { margin-top: 4px; padding-left: 20px; font-size: 13px; }
        li { margin-bottom: 4px; }
        details { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 6px; padding: 8px 12px; margin-bottom: 10px; font-size: 13px; }
        summary { font-weight: 600; cursor: pointer; }
        """

        html_out = [
            "<!DOCTYPE html>",
            "<html>",
            "<head>",
            '<meta charset="utf-8">',
            f"<title>Diagnostic Report: {html.escape(self.investigation_id)}</title>",
            f"<style>{css}</style>",
            "</head>",
            "<body>",
            '<div class="report-card">',
            "<h1>dynamicState Deterministic Diagnostic Report</h1>",
            '<div class="meta-bar">',
            f"<strong>Report ID:</strong> {html.escape(self.report_id)} | ",
            f"<strong>Investigation ID:</strong> {html.escape(self.investigation_id)} | ",
            f"<strong>Schema:</strong> v{html.escape(self.schema_version)} | ",
            f"<strong>Generated:</strong> {html.escape(self.generated_at)}",
            "</div>",
        ]

        # Section A
        if sec_a:
            html_out.extend([
                "<h2>A. Executive Summary</h2>",
                f"<p><strong>Overall Result:</strong> {badge(sec_a.overall_result)} &nbsp;&nbsp; <strong>Target:</strong> {html.escape(sec_a.target_identity)}</p>",
                f"<p><strong>Problem Statement:</strong> {html.escape(sec_a.problem_statement)}</p>",
                f"<p><strong>Verdict Rationale:</strong> {html.escape(sec_a.verdict_rationale)}</p>",
                "<table>",
                "<tr><th>Category</th><th>Details</th></tr>",
                f"<tr><td><strong>Confirmed Problems</strong></td><td>{('<br>'.join(html.escape(p) for p in sec_a.confirmed_problems)) if sec_a.confirmed_problems else '<em>None confirmed</em>'}</td></tr>",
                f"<tr><td><strong>Probable / Suspected</strong></td><td>{('<br>'.join(html.escape(p) for p in sec_a.probable_problems)) if sec_a.probable_problems else '<em>None</em>'}</td></tr>",
                f"<tr><td><strong>Contributing Factors</strong></td><td>{('<br>'.join(html.escape(c) for c in sec_a.contributing_factors)) if sec_a.contributing_factors else '<em>None</em>'}</td></tr>",
                f"<tr><td><strong>Limiting Factors</strong></td><td>{('<br>'.join(html.escape(l) for l in sec_a.limiting_factors)) if sec_a.limiting_factors else '<em>None</em>'}</td></tr>",
                f"<tr><td><strong>Critical Risks</strong></td><td>{('<br>'.join(html.escape(r) for r in sec_a.critical_risks)) if sec_a.critical_risks else '<em>None</em>'}</td></tr>",
                f"<tr><td><strong>Unresolved Questions</strong></td><td>{('<br>'.join(html.escape(q) for q in sec_a.unresolved_questions)) if sec_a.unresolved_questions else '<em>None</em>'}</td></tr>",
                f"<tr><td><strong>Determining Checks / Hypotheses</strong></td><td>Checks: <code>{html.escape(', '.join(sec_a.determining_checks))}</code> | Hypotheses: <code>{html.escape(', '.join(sec_a.determining_hypotheses))}</code></td></tr>",
                "</table>",
            ])

        # Section B
        if sec_b:
            html_out.extend([
                "<h2>B. Target and Investigation Context</h2>",
                "<table>",
                f"<tr><td><strong>Process / PID</strong></td><td><code>{html.escape(sec_b.target_process_name)}</code> (PID: {html.escape(str(sec_b.pid))}) | Start Identity: <code>{html.escape(str(sec_b.process_start_identity or 'N/A'))}</code></td></tr>",
                f"<tr><td><strong>Binary / Build ID</strong></td><td><code>{html.escape(str(sec_b.binary_path))}</code> | Build ID: <code>{html.escape(str(sec_b.build_id))}</code></td></tr>",
                f"<tr><td><strong>Companion ELF</strong></td><td><code>{html.escape(str(sec_b.companion_elf))}</code></td></tr>",
                f"<tr><td><strong>Collection Mode</strong></td><td>{html.escape(sec_b.collection_mode)} (Interval: {sec_b.observation_interval_sec}s, Duration: {sec_b.observation_duration_sec}s)</td></tr>",
                f"<tr><td><strong>Execution Window</strong></td><td>Start: {html.escape(sec_b.investigation_start_time)}<br>End: {html.escape(sec_b.investigation_end_time)}</td></tr>",
                f"<tr><td><strong>Target Capabilities</strong></td><td><code>{html.escape(', '.join(sec_b.target_capabilities))}</code></td></tr>",
                f"<tr><td><strong>Collection Failures / Limitations</strong></td><td>{html.escape('; '.join(sec_b.collection_failures + sec_b.environmental_limitations)) or '<em>None</em>'}</td></tr>",
                "</table>",
            ])

        # Section C
        if sec_c:
            excl_html = "<br>".join(
                f"<code>{html.escape(str(ex.get('recipe_id')))}</code>: {html.escape(str(ex.get('reason_excluded')))}"
                for ex in sec_c.recipes_excluded
            )
            html_out.extend([
                "<h2>C. Diagnostic Strategy</h2>",
                f"<p><strong>Classification:</strong> <code>{html.escape(sec_c.initial_classification)}</code> (Confidence: {sec_c.classification_confidence*100:.1f}%)</p>",
                f"<p><strong>Methodology:</strong> <strong>{html.escape(sec_c.methodology_name)}</strong></p>",
                f"<p><em>Selection Rationale:</em> {html.escape(sec_c.methodology_selection_reason)}</p>",
                f"<p><strong>Executed Recipes:</strong> <code>{html.escape(', '.join(sec_c.recipes_executed))}</code></p>",
                f"<details><summary>Excluded Recipes ({len(sec_c.recipes_excluded)})</summary><div>{excl_html or 'None'}</div></details>",
            ])

        # Section D
        if sec_d:
            extra_html = (
                f" | SKIPPED: {badge(str(sec_d.checks_skipped), 'SKIPPED')}"
                f" | UNSUPPORTED: {badge(str(sec_d.checks_unsupported), 'UNSUPPORTED')}"
                f" | Required Passed: <strong>{sec_d.required_checks_passed}/{sec_d.required_checks_count}</strong>"
            )
            html_out.extend([
                "<h2>D. Detailed Inspection Results</h2>",
                f"<p>Total Checks: <strong>{sec_d.checks_total}</strong> | "
                f"PASS: {badge(str(sec_d.checks_passed), 'PASS')} | "
                f"FAIL: {badge(str(sec_d.checks_failed), 'FAIL')} | "
                f"INCONCLUSIVE: {badge(str(sec_d.checks_inconclusive), 'INCONCLUSIVE')} | "
                f"NOT_APPLICABLE: {badge(str(sec_d.checks_not_applicable), 'NOT_APPLICABLE')} | "
                f"NOT_EXECUTED: {badge(str(sec_d.checks_not_executed), 'NOT_EXECUTED')} | "
                f"ERROR: {badge(str(sec_d.checks_error), 'ERROR')}{extra_html}</p>",
                "<table>",
                "<tr><th>Status</th><th>Check ID</th><th>Recipe</th><th>Criteria</th><th>Observations</th><th>Interpretation</th><th>Duration</th></tr>",
            ])
            for c in sec_d.checks:
                dur_val = c.get("duration_seconds")
                dur_str = f"{dur_val:.4f}s" if (dur_val is not None and isinstance(dur_val, (int, float))) else "UNKNOWN"
                html_out.append(
                    f"<tr>"
                    f"<td>{badge(c.get('status', 'UNKNOWN'), c.get('status', ''))}</td>"
                    f"<td><code>{html.escape(str(c.get('check_id', '')))}</code></td>"
                    f"<td><code>{html.escape(str(c.get('recipe_id', '')))}</code></td>"
                    f"<td><small>{html.escape(str(c.get('decision_criteria', '')))}</small></td>"
                    f"<td><code>{html.escape(str(c.get('actual_observations', '')))}</code></td>"
                    f"<td>{html.escape(str(c.get('technical_interpretation', '')))}</td>"
                    f"<td><small>{dur_str}</small></td>"
                    f"</tr>"
                )
            html_out.append("</table>")

        # Section E
        if sec_e:
            html_out.append("<h2>E. Findings and Root Cause Analysis</h2>")
            all_f = (
                sec_e.confirmed_root_causes
                + sec_e.probable_causes
                + sec_e.anomalies
                + sec_e.observed_symptoms
                + sec_e.derived_evidence
            )
            if all_f:
                for f in all_f:
                    html_out.extend([
                        "<details open>",
                        f"<summary>{badge(f.classification)} {badge(f.severity)} <code>{html.escape(f.finding_id)}</code> [{html.escape(f.epistemic_level)}]: {html.escape(f.problem_description)}</summary>",
                        "<div style='padding: 8px 0;'>",
                        f"<p><strong>Affected Entity:</strong> <code>{html.escape(str(f.affected_entity))}</code></p>",
                        f"<p><strong>Observed Behavior:</strong> {html.escape(f.observed_behavior)}</p>",
                        f"<p><strong>Technical Explanation:</strong> {html.escape(f.technical_explanation)}</p>",
                        f"<p><strong>Confidence Basis:</strong> {html.escape(f.confidence_basis)}</p>",
                        f"<p><strong>Evidence IDs:</strong> <code>{html.escape(', '.join(f.supporting_evidence_ids))}</code></p>",
                        f"<p><strong>Source References:</strong> <code>{html.escape(', '.join(f.source_references))}</code></p>",
                        "</div>",
                        "</details>",
                    ])
            else:
                html_out.append("<p><em>No abnormal findings recorded.</em></p>")

        # Section F
        if sec_f:
            html_out.extend([
                "<h2>F. Competing Hypotheses</h2>",
                f"<p><strong>Leading Hypothesis:</strong> <code>{html.escape(str(sec_f.leading_hypothesis_id))}</code></p>",
                f"<p><em>Discrimination Rationale:</em> {html.escape(sec_f.ranking_rationale)}</p>",
                "<table>",
                "<tr><th>Status</th><th>Hypothesis ID</th><th>Confidence</th><th>Supporting Evidence</th><th>Contradicting Evidence</th></tr>",
            ])
            for h in sec_f.hypotheses:
                supp = h.get("supporting_evidence_ids") or []
                contra = h.get("contradicting_evidence_ids") or []
                stmt = h.get("problem_statement") or h.get("title") or ""
                html_out.append(
                    f"<tr>"
                    f"<td>{badge(h.get('status', 'INCONCLUSIVE'))}</td>"
                    f"<td><strong>{html.escape(str(h.get('hypothesis_id', '')))}</strong><br><small>{html.escape(str(stmt))}</small></td>"
                    f"<td>{float(h.get('confidence', 0.0))*100:.1f}%</td>"
                    f"<td><code>{html.escape(', '.join(supp)) if supp else 'None'}</code></td>"
                    f"<td><code>{html.escape(', '.join(contra)) if contra else 'None'}</code></td>"
                    f"</tr>"
                )
            html_out.append("</table>")

        # Section G
        if sec_g:
            html_out.extend([
                "<h2>G. Evidence & Provenance Index</h2>",
                f"<p>Total Registered Evidence Records: <strong>{sec_g.evidence_count}</strong> | Independent Roots: <code>{html.escape(', '.join(sec_g.independent_root_sources))}</code></p>",
                "<table>",
                "<tr><th>Evidence ID</th><th>Epistemic Level</th><th>Method</th><th>Provenance / Authority</th><th>Observed Value</th><th>Source Location</th></tr>",
            ])
            for ev in sec_g.evidence_records:
                corr_str = "N/A"
                if ev.correlated_source:
                    corr_str = f"{ev.correlated_source.get('demangled_symbol') or ''} ({ev.correlated_source.get('source_file')}:{ev.correlated_source.get('source_line')})"
                html_out.append(
                    f"<tr>"
                    f"<td><code>{html.escape(ev.evidence_id)}</code></td>"
                    f"<td><code>{html.escape(ev.epistemic_level)}</code></td>"
                    f"<td><code>{html.escape(ev.collection_method)}</code></td>"
                    f"<td><small>{html.escape(ev.provenance_class)} ({html.escape(ev.authority_status)})</small></td>"
                    f"<td><code>{html.escape(str(ev.normalized_observation))}</code></td>"
                    f"<td><small>{html.escape(corr_str)}</small></td>"
                    f"</tr>"
                )
            html_out.append("</table>")

        # Section H
        if sec_h:
            html_out.extend([
                "<h2>H. Limitations and Unverified Areas</h2>",
                '<div class="alert-box"><strong>Caution:</strong> Absence of evidence is never presented as evidence of absence.</div>',
                "<ul>",
            ])
            if sec_h.unexecuted_checks:
                html_out.append(f"<li><strong>Unexecuted Checks:</strong> {html.escape('; '.join(sec_h.unexecuted_checks))}</li>")
            if sec_h.unsupported_capabilities:
                html_out.append(f"<li><strong>Unsupported Capabilities:</strong> {html.escape('; '.join(sec_h.unsupported_capabilities))}</li>")
            if sec_h.collection_failures:
                html_out.append(f"<li><strong>Failed Collections:</strong> {html.escape('; '.join(sec_h.collection_failures))}</li>")
            if sec_h.missing_symbols_or_dwarf:
                html_out.append(f"<li><strong>Missing Symbols / DWARF:</strong> {html.escape('; '.join(sec_h.missing_symbols_or_dwarf))}</li>")
            if sec_h.incomplete_temporal_observations:
                html_out.append(f"<li><strong>Incomplete Temporal Samples:</strong> {html.escape('; '.join(sec_h.incomplete_temporal_observations))}</li>")
            if sec_h.incomplete_lock_graphs:
                html_out.append(f"<li><strong>Incomplete Lock Graphs:</strong> {html.escape('; '.join(sec_h.incomplete_lock_graphs))}</li>")
            if sec_h.unavailable_allocator_metadata:
                html_out.append(f"<li><strong>Unavailable Allocator Metadata:</strong> {html.escape('; '.join(sec_h.unavailable_allocator_metadata))}</li>")
            if sec_h.unverified_causal_relationships:
                html_out.append(f"<li><strong>Unverified Causal Relationships:</strong> {html.escape('; '.join(sec_h.unverified_causal_relationships))}</li>")
            if sec_h.missing_identity_records:
                html_out.append(f"<li><strong>Missing Identity Records:</strong> {html.escape('; '.join(sec_h.missing_identity_records))}</li>")
            if sec_h.mismatched_identity_records:
                html_out.append(f"<li><strong>Mismatched Identity Records:</strong> {html.escape('; '.join(sec_h.mismatched_identity_records))}</li>")
            if sec_h.confidence_limiting_factors:
                html_out.append(f"<li><strong>Confidence Limiting Factors:</strong> {html.escape('; '.join(sec_h.confidence_limiting_factors))}</li>")
            html_out.append("</ul>")

        # Section I
        if sec_i:
            html_out.extend([
                "<h2>I. Final Conclusions and Recommendations</h2>",
                f"<p><strong>Overall Verdict:</strong> {badge(sec_i.overall_conclusion)}</p>",
                f"<p><strong>Rationale:</strong> {html.escape(sec_i.verdict_rationale or (sec_a.verdict_rationale if sec_a else ''))}</p>",
                "<h3>Confirmed Problems</h3><ul>",
            ])
            for cp in sec_i.confirmed_problems:
                html_out.append(f"<li>{html.escape(cp)}</li>")
            if not sec_i.confirmed_problems:
                html_out.append("<li><em>None</em></li>")
            html_out.append("</ul><h3>Probable Problems</h3><ul>")
            for pp in sec_i.probable_problems:
                html_out.append(f"<li>{html.escape(pp)}</li>")
            if not sec_i.probable_problems:
                html_out.append("<li><em>None</em></li>")
            html_out.append("</ul><h3>Recommended Diagnostic Actions</h3><ul>")
            for act in sec_i.recommended_next_diagnostic_steps:
                html_out.append(f"<li>{html.escape(act)}</li>")
            html_out.append("</ul>")
            if sec_i.safe_remediation_suggestions:
                html_out.append("<h3>Safe Remediation Suggestions</h3><ul>")
                for rem in sec_i.safe_remediation_suggestions:
                    html_out.append(f"<li>🔧 {html.escape(rem)}</li>")
                html_out.append("</ul>")

        html_out.extend([
            "</div>",
            "</body>",
            "</html>",
        ])
        return "\n".join(html_out)

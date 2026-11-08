"""Phase 2.1.5 — Comprehensive Diagnostic Report Architecture.

Defines the versioned, unified diagnostic report schema (Sections A through I),
providing a single source of truth driving:
1. MCP tool responses
2. Web UI investigation views
3. HTML incident reports
4. Exported machine-readable JSON & Markdown reports

Separates diagnostic result models, evidence provenance, report assembly, and rendering.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import html
import json
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from .diagnostic_methodology import CheckStatus, DiagnosticCheck, DiagnosticMethodology


SCHEMA_VERSION = "2.1.5"

# Finding Classifications
CLASSIFICATION_OBSERVED_SYMPTOM = "OBSERVED_SYMPTOM"
CLASSIFICATION_ANOMALY = "ANOMALY"
CLASSIFICATION_PROBABLE_CAUSE = "PROBABLE_CAUSE"
CLASSIFICATION_CONFIRMED_ROOT_CAUSE = "CONFIRMED_ROOT_CAUSE"


@dataclass
class FindingRecord:
    """Explicit finding record distinguishing symptoms, anomalies, probable causes, and confirmed root causes."""
    finding_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL
    classification: str  # OBSERVED_SYMPTOM, ANOMALY, PROBABLE_CAUSE, CONFIRMED_ROOT_CAUSE
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

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "FindingRecord":
        return cls(**data)


@dataclass
class ExecutiveSummarySection:
    target_identity: str
    investigation_id: str
    overall_result: str  # CONFIRMED_FAULT, PROBABLE_FAULT, INCONCLUSIVE, HEALTHY, ABORTED
    most_important_findings: List[str] = field(default_factory=list)
    confirmed_problems: List[str] = field(default_factory=list)
    probable_problems: List[str] = field(default_factory=list)
    critical_risks: List[str] = field(default_factory=list)
    unresolved_questions: List[str] = field(default_factory=list)
    recommended_next_actions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


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


@dataclass
class DetailedInspectionResultsSection:
    checks_total: int
    checks_passed: int
    checks_failed: int
    checks_inconclusive: int
    checks_not_applicable: int
    checks_not_executed: int
    checks_error: int
    checks: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class FindingsSection:
    confirmed_root_causes: List[FindingRecord] = field(default_factory=list)
    probable_causes: List[FindingRecord] = field(default_factory=list)
    anomalies: List[FindingRecord] = field(default_factory=list)
    observed_symptoms: List[FindingRecord] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "confirmed_root_causes": [f.to_dict() for f in self.confirmed_root_causes],
            "probable_causes": [f.to_dict() for f in self.probable_causes],
            "anomalies": [f.to_dict() for f in self.anomalies],
            "observed_symptoms": [f.to_dict() for f in self.observed_symptoms],
        }


@dataclass
class CompetingHypothesesSection:
    leading_hypothesis_id: Optional[str]
    hypotheses: List[Dict[str, Any]] = field(default_factory=list)
    ranking_rationale: str = ""
    eliminated_alternatives: List[Dict[str, str]] = field(default_factory=list)
    missing_evidence_preventing_conclusions: List[str] = field(default_factory=list)
    double_counting_protections_applied: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


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

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class EvidenceAndProvenanceSection:
    evidence_count: int
    evidence_records: List[EvidenceIndexEntry] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_count": self.evidence_count,
            "evidence_records": [e.to_dict() for e in self.evidence_records],
        }


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

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


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

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class DiagnosticReport:
    """Master structured diagnostic report for Phase 2.1.5."""
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
        }

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
            f"# dynamicState Expert Diagnostic Incident Report",
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
            md.append(
                f"**Summary**: Total Checks: `{sec_d.checks_total}` | "
                f"PASS: `{sec_d.checks_passed}` | FAIL: `{sec_d.checks_failed}` | "
                f"INCONCLUSIVE: `{sec_d.checks_inconclusive}` | NOT_APPLICABLE: `{sec_d.checks_not_applicable}` | "
                f"NOT_EXECUTED: `{sec_d.checks_not_executed}` | ERROR: `{sec_d.checks_error}`\n"
            )
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
                md.append(f"- **Duration**: `{c.get('duration_seconds', 0.0):.4f}s` (Start: `{c.get('start_timestamp')}`)\n")

        md.extend([
            "---",
            "## 6. Actual Observations",
        ])
        if sec_g:
            for obs in sec_g.evidence_records[:10]:
                md.append(f"- `[{obs.evidence_id}]` [OBSERVED FACT] Method: `{obs.collection_method}` | Value: `{obs.normalized_observation}`")
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
                sec_e.observed_symptoms
            )
            if all_findings:
                for f in all_findings:
                    cls_badge = f"[{f.classification}]"
                    sev_badge = f"[{f.severity}]"
                    md.append(f"### {cls_badge} {sev_badge} `{f.finding_id}`: {f.problem_description}")
                    md.append(f"- **Classification**: `{f.classification}` | **Verification**: `{f.verification_status}`")
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
            "## 9. Rejected Hypotheses (Section F)",
        ])
        if sec_f and sec_f.eliminated_alternatives:
            for ea in sec_f.eliminated_alternatives:
                md.append(f"- **[REFUTED]** `{ea.get('hypothesis_id')}`: {ea.get('rationale')}")
        else:
            md.append("- None.")

        md.extend([
            "",
            "---",
            "## 10. Unresolved Hypotheses",
        ])
        if sec_f:
            unresolved = [h for h in sec_f.hypotheses if h.get("status") in ("PROPOSED", "LIKELY", "INCONCLUSIVE")]
            if unresolved:
                for uh in unresolved:
                    md.append(f"- **[{uh.get('status')}]** {uh.get('problem_statement') or uh.get('title')}")
            else:
                md.append("- None.")

        md.extend([
            "",
            "---",
            "## 11. Evidence-to-Source Mapping & Provenance Index (Section G)",
        ])
        if sec_g:
            md.append(f"Total Navigable Evidence Records: `{sec_g.evidence_count}`\n")
            for ev in sec_g.evidence_records:
                md.append(f"### `[{ev.evidence_id}]` ({ev.provenance_class})")
                md.append(f"- **Method**: `{ev.collection_method}` | **Target PID**: `{ev.target_pid}` | **Timestamp**: `{ev.timestamp}`")
                md.append(f"- **Normalized Observation**: `{ev.normalized_observation}`")
                if ev.correlated_source:
                    corr = ev.correlated_source
                    md.append(f"- **Source Mapping**: `{corr.get('demangled_symbol')}` at `{corr.get('source_file')}:{corr.get('source_line')}` (Runtime: `{corr.get('runtime_address')}`, Bias: `{corr.get('load_bias')}`)")
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
        """Renders complete, standalone, professional engineering diagnostic report."""
        sec_a = self.section_a_executive_summary
        sec_b = self.section_b_target_context
        sec_c = self.section_c_diagnostic_strategy
        sec_d = self.section_d_detailed_inspection_results
        sec_e = self.section_e_findings_and_root_cause
        sec_f = self.section_f_competing_hypotheses
        sec_g = self.section_g_evidence_and_provenance
        sec_h = self.section_h_limitations_and_unverified
        sec_i = self.section_i_final_conclusions

        def badge(text: str, color_type: str) -> str:
            colors = {
                "CONFIRMED": "#b91c1c; color: #fff",
                "FAIL": "#b91c1c; color: #fff",
                "LIKELY": "#d97706; color: #fff",
                "PROBABLE": "#d97706; color: #fff",
                "SUPPORTED": "#2563eb; color: #fff",
                "PASS": "#15803d; color: #fff",
                "HEALTHY": "#15803d; color: #fff",
                "INCONCLUSIVE": "#6b7280; color: #fff",
                "NOT_APPLICABLE": "#4b5563; color: #fff",
                "NOT_EXECUTED": "#9ca3af; color: #111",
                "ERROR": "#dc2626; color: #fff",
                "REFUTED": "#475569; color: #fff",
                "CRITICAL": "#991b1b; color: #fff",
                "HIGH": "#c2410c; color: #fff",
                "MEDIUM": "#d97706; color: #fff",
                "LOW": "#0284c7; color: #fff",
            }
            style = colors.get(text.upper(), "background: #475569; color: #fff")
            return f'<span style="display:inline-block; padding: 2px 8px; border-radius: 4px; font-weight:600; font-size:11px; font-family:monospace; background:{style}">{html.escape(text)}</span>'

        css = """
        body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; line-height: 1.5; color: #1e293b; background: #f8fafc; margin: 0; padding: 24px; }
        .report-card { max-width: 1100px; margin: 0 auto; background: #ffffff; border: 1px solid #e2e8f0; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05); padding: 36px; }
        h1 { font-size: 24px; border-bottom: 2px solid #0f172a; padding-bottom: 8px; margin-top: 0; color: #0f172a; }
        h2 { font-size: 18px; color: #1e293b; border-bottom: 1px solid #cbd5e1; padding-bottom: 6px; margin-top: 32px; }
        h3 { font-size: 15px; color: #334155; margin-top: 18px; margin-bottom: 6px; }
        .meta-bar { background: #f1f5f9; padding: 12px 16px; border-radius: 6px; font-size: 13px; font-family: monospace; margin-bottom: 24px; border-left: 4px solid #3b82f6; }
        table { width: 100%; border-collapse: collapse; margin-top: 12px; margin-bottom: 16px; font-size: 13px; }
        th, td { border: 1px solid #e2e8f0; padding: 8px 12px; text-align: left; }
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
            f"<h1>dynamicState Deterministic Diagnostic Report</h1>",
            f'<div class="meta-bar">',
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
                f"<p><strong>Overall Result:</strong> {badge(sec_a.overall_result, 'RES')} &nbsp;&nbsp; <strong>Target:</strong> {html.escape(sec_a.target_identity)}</p>",
                "<table>",
                "<tr><th>Category</th><th>Details</th></tr>",
                f"<tr><td><strong>Confirmed Problems</strong></td><td>{('<br>'.join(html.escape(p) for p in sec_a.confirmed_problems)) if sec_a.confirmed_problems else '<em>None confirmed</em>'}</td></tr>",
                f"<tr><td><strong>Probable / Suspected</strong></td><td>{('<br>'.join(html.escape(p) for p in sec_a.probable_problems)) if sec_a.probable_problems else '<em>None</em>'}</td></tr>",
                f"<tr><td><strong>Critical Risks</strong></td><td>{('<br>'.join(html.escape(r) for r in sec_a.critical_risks)) if sec_a.critical_risks else '<em>None</em>'}</td></tr>",
                f"<tr><td><strong>Unresolved Questions</strong></td><td>{('<br>'.join(html.escape(q) for q in sec_a.unresolved_questions)) if sec_a.unresolved_questions else '<em>None</em>'}</td></tr>",
                "</table>",
            ])

        # Section B
        if sec_b:
            html_out.extend([
                "<h2>B. Target and Investigation Context</h2>",
                "<table>",
                f"<tr><td><strong>Process / PID</strong></td><td><code>{html.escape(sec_b.target_process_name)}</code> (PID: {sec_b.pid})</td></tr>",
                f"<tr><td><strong>Binary / Build ID</strong></td><td><code>{html.escape(str(sec_b.binary_path))}</code> | Build ID: <code>{html.escape(str(sec_b.build_id))}</code></td></tr>",
                f"<tr><td><strong>Companion ELF</strong></td><td><code>{html.escape(str(sec_b.companion_elf))}</code></td></tr>",
                f"<tr><td><strong>Collection Mode</strong></td><td>{html.escape(sec_b.collection_mode)} (Interval: {sec_b.observation_interval_sec}s, Duration: {sec_b.observation_duration_sec}s)</td></tr>",
                f"<tr><td><strong>Execution Window</strong></td><td>Start: {html.escape(sec_b.investigation_start_time)}<br>End: {html.escape(sec_b.investigation_end_time)}</td></tr>",
                f"<tr><td><strong>Target Capabilities</strong></td><td><code>{html.escape(', '.join(sec_b.target_capabilities))}</code></td></tr>",
                "</table>",
            ])

        # Section C
        if sec_c:
            html_out.extend([
                "<h2>C. Diagnostic Strategy</h2>",
                f"<p><strong>Classification:</strong> <code>{html.escape(sec_c.initial_classification)}</code> (Confidence: {sec_c.classification_confidence*100:.1f}%)</p>",
                f"<p><strong>Methodology:</strong> <strong>{html.escape(sec_c.methodology_name)}</strong></p>",
                f"<p><em>Selection Rationale:</em> {html.escape(sec_c.methodology_selection_reason)}</p>",
                f"<p><strong>Executed Recipes:</strong> <code>{html.escape(', '.join(sec_c.recipes_executed))}</code></p>",
            ])

        # Section D
        if sec_d:
            html_out.extend([
                "<h2>D. Detailed Inspection Results</h2>",
                f"<p>Total Checks: <strong>{sec_d.checks_total}</strong> | "
                f"PASS: {badge(str(sec_d.checks_passed), 'PASS')} | "
                f"FAIL: {badge(str(sec_d.checks_failed), 'FAIL')} | "
                f"INCONCLUSIVE: {badge(str(sec_d.checks_inconclusive), 'INCONCLUSIVE')} | "
                f"NOT_APPLICABLE: {badge(str(sec_d.checks_not_applicable), 'NOT_APPLICABLE')}</p>",
                "<table>",
                "<tr><th>Status</th><th>Check ID</th><th>Recipe</th><th>Criteria</th><th>Observations</th><th>Interpretation</th></tr>",
            ])
            for c in sec_d.checks:
                html_out.append(
                    f"<tr>"
                    f"<td>{badge(c.get('status', 'UNKNOWN'), c.get('status'))}</td>"
                    f"<td><code>{html.escape(c.get('check_id', ''))}</code></td>"
                    f"<td><code>{html.escape(c.get('recipe_id', ''))}</code></td>"
                    f"<td><small>{html.escape(str(c.get('decision_criteria', '')))}</small></td>"
                    f"<td><code>{html.escape(str(c.get('actual_observations', ''))[:120])}</code></td>"
                    f"<td>{html.escape(c.get('technical_interpretation', ''))}</td>"
                    f"</tr>"
                )
            html_out.append("</table>")

        # Section E
        if sec_e:
            html_out.append("<h2>E. Findings and Root Cause Analysis</h2>")
            all_f = sec_e.confirmed_root_causes + sec_e.probable_causes + sec_e.anomalies + sec_e.observed_symptoms
            if all_f:
                for f in all_f:
                    html_out.extend([
                        f"<details open>",
                        f"<summary>{badge(f.classification, f.classification)} {badge(f.severity, f.severity)} <code>{html.escape(f.finding_id)}</code>: {html.escape(f.problem_description)}</summary>",
                        f"<div style='padding: 8px 0;'>",
                        f"<p><strong>Affected Entity:</strong> <code>{html.escape(str(f.affected_entity))}</code></p>",
                        f"<p><strong>Observed Behavior:</strong> {html.escape(f.observed_behavior)}</p>",
                        f"<p><strong>Technical Explanation:</strong> {html.escape(f.technical_explanation)}</p>",
                        f"<p><strong>Evidence IDs:</strong> <code>{html.escape(', '.join(f.supporting_evidence_ids))}</code></p>",
                        f"<p><strong>Source References:</strong> <code>{html.escape(', '.join(f.source_references))}</code></p>",
                        f"</div>",
                        f"</details>",
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
                html_out.append(
                    f"<tr>"
                    f"<td>{badge(h.get('status', 'INCONCLUSIVE'), h.get('status'))}</td>"
                    f"<td><strong>{html.escape(h.get('hypothesis_id', ''))}</strong><br><small>{html.escape(h.get('problem_statement', ''))}</small></td>"
                    f"<td>{h.get('confidence', 0.0)*100:.1f}%</td>"
                    f"<td><code>{html.escape(', '.join(supp)) if supp else 'None'}</code></td>"
                    f"<td><code>{html.escape(', '.join(contra)) if contra else 'None'}</code></td>"
                    f"</tr>"
                )
            html_out.append("</table>")

        # Section G
        if sec_g:
            html_out.extend([
                "<h2>G. Evidence & Provenance Index</h2>",
                f"<p>Total Registered Evidence Records: <strong>{sec_g.evidence_count}</strong></p>",
                "<table>",
                "<tr><th>Evidence ID</th><th>Method</th><th>Provenance</th><th>Observed Value</th><th>Source Location</th></tr>",
            ])
            for ev in sec_g.evidence_records:
                corr_str = "N/A"
                if ev.correlated_source:
                    corr_str = f"{ev.correlated_source.get('demangled_symbol') or ''} ({ev.correlated_source.get('source_file')}:{ev.correlated_source.get('source_line')})"
                html_out.append(
                    f"<tr>"
                    f"<td><code>{html.escape(ev.evidence_id)}</code></td>"
                    f"<td><code>{html.escape(ev.collection_method)}</code></td>"
                    f"<td><small>{html.escape(ev.provenance_class)}</small></td>"
                    f"<td><code>{html.escape(str(ev.normalized_observation)[:100])}</code></td>"
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
            html_out.append("</ul>")

        # Section I
        if sec_i:
            html_out.extend([
                "<h2>I. Final Conclusions and Recommendations</h2>",
                f"<p><strong>Overall Verdict:</strong> {badge(sec_i.overall_conclusion, 'VERDICT')}</p>",
                "<h3>Recommended Diagnostic Actions</h3>",
                "<ul>",
            ])
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

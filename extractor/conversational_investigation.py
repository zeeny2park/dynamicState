"""Phase 15: Conversational Analysis Service & Evidence-Grounded Response Processing.

Provides:
1. ConversationalAnalysisService: Assembles compact context from InvestigationSession,
   formats system/user prompts, queries configured LLM provider, validates schema,
   sanitizes claims against ledger secrets, and records auditable timeline events.
2. StructuredAnalysisResult: Machine-readable conversational analysis output.
3. Schema & Trust Enforcement: Strips fabricated evidence IDs, disarms caller-claimed
   validation status, and ensures LLM output never promotes candidate functions to
   VALIDATED_CAUSAL_FUNCTION.
"""

from dataclasses import asdict, dataclass, field
import hashlib
import json
import logging
import os
import re
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from extractor.evidence_ledger import (
    EvidenceLedger,
    EvidenceRecord,
)
from extractor.temporal_investigation import redact_sensitive_content
from extractor.hypothesis import (
    EVIDENCE_CLASSIFICATION_FACT,
    EVIDENCE_CLASSIFICATION_INFERENCE,
    EVIDENCE_CLASSIFICATION_INFERRED_HYPOTHESIS,
    FUNCTION_TIER_STATIC_CANDIDATE,
    FUNCTION_TIER_EVIDENCE_SUPPORTED,
    FUNCTION_TIER_VALIDATED_CAUSAL,
    FUNCTION_TIER_UNVERIFIED,
    HYPOTHESIS_STATUS_PROPOSED,
    HYPOTHESIS_STATUS_SUPPORTED,
    HYPOTHESIS_STATUS_VALIDATED,
    HYPOTHESIS_STATUS_INCONCLUSIVE,
    OBSERVATION_STATUS_PROPOSED,
    FollowUpObservation,
    InvestigationHypothesis,
    sanitize_and_disarm_llm_hypothesis,
)
from extractor.llm_provider import (
    BaseLLMProvider,
    DeterministicFallbackProvider,
    LLMProviderManager,
    ProviderCancelledError,
    ProviderError,
    ProviderExecutionError,
    ProviderOutputLimitExceededError,
    ProviderTimeoutError,
    ProviderUnavailableError,
)

logger = logging.getLogger("dynamicstate.conversational_investigation")


@dataclass
class StructuredAnalysisResult:
    """Structured, evidence-grounded response from the conversational analysis service."""
    summary: str
    observed_facts: List[Dict[str, Any]] = field(default_factory=list)
    hypotheses: List[Dict[str, Any]] = field(default_factory=list)
    unknowns: List[str] = field(default_factory=list)
    evidence_refs: List[str] = field(default_factory=list)
    alternative_explanations: List[str] = field(default_factory=list)
    proposed_observations: List[Dict[str, Any]] = field(default_factory=list)
    safety_notes: List[str] = field(default_factory=list)
    next_steps: List[str] = field(default_factory=list)
    provider_metadata: Dict[str, Any] = field(default_factory=dict)
    validation_status: str = "VALIDATED_CLEAN"
    unverified_claims_disarmed: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ConversationalAnalysisService:
    """Manages conversational LLM analysis grounded strictly in investigation session evidence."""

    def __init__(self, provider_manager: Optional[LLMProviderManager] = None):
        self.provider_manager = provider_manager or LLMProviderManager.get_instance()

    def build_compact_context(
        self,
        session: Any,
        user_message: str,
    ) -> Dict[str, Any]:
        """Construct compact, privacy-safe context from the active investigation session.

        Sensitive Data Minimization:
        - Raw memory dumps, hex buffers, and full process memory maps are strictly omitted.
        - Only semantic diff facts, DWARF type/source linkages, function names, and ledger IDs
          are transmitted.
        """
        t_ref = getattr(session, "target_ref", {}) or {}
        stages = getattr(session, "stages", {}) or {}

        # 1. Target Identity & Build ID
        ident_stage = stages.get("target_identity", {}).get("details", {}) or {}
        target_info = {
            "pid": ident_stage.get("pid") or t_ref.get("pid"),
            "executable": ident_stage.get("executable") or t_ref.get("executable"),
            "build_id": ident_stage.get("target_build_id") or t_ref.get("build_id"),
            "build_id_status": ident_stage.get("build_id_status", "UNKNOWN"),
            "debug_image": ident_stage.get("debug_image") or t_ref.get("debug_image"),
        }

        # 2. Capture Quality
        cap_stage = stages.get("capture_quality", {}).get("details", {}) or {}
        capture_quality = {
            "completeness": cap_stage.get("completeness", "COMPLETE"),
            "consistency_level": cap_stage.get("consistency_level", "STOPPED"),
            "capture_source": t_ref.get("capture_source", "process_vm_readv"),
        }

        # 3. Grounded Observed Facts & Findings
        findings_summary: List[Dict[str, Any]] = []
        findings = getattr(session, "findings", []) or []
        for f in findings:
            f_dict = f.to_dict() if hasattr(f, "to_dict") else dict(f)
            code_nav = f_dict.get("code_navigation") or {}
            findings_summary.append({
                "finding_id": f_dict.get("finding_id"),
                "category": f_dict.get("category"),
                "title": f_dict.get("title"),
                "field_path": f_dict.get("field_name") or f_dict.get("field_path"),
                "before_value": f_dict.get("before_value"),
                "after_value": f_dict.get("after_value"),
                "observed_value": f_dict.get("observed_value"),
                "uncertainty": f_dict.get("uncertainty"),
                "dwarf_type": code_nav.get("type_name") or f_dict.get("type_name"),
                "source_location": code_nav.get("source_location") or f_dict.get("source_location"),
                "confidence": f_dict.get("confidence", "high"),
                "evidence_ids": f_dict.get("evidence_ids", []),
            })

        # 4. Current Candidate Functions
        candidate_functions: List[Dict[str, Any]] = []
        for f in findings:
            for c in getattr(f, "function_candidates", []) or []:
                c_dict = c if isinstance(c, dict) else c.to_dict()
                candidate_functions.append({
                    "function_name": c_dict.get("function_name") or c_dict.get("name"),
                    "candidate_tier": c_dict.get("candidate_tier", FUNCTION_TIER_STATIC_CANDIDATE),
                    "source_file": c_dict.get("source_file"),
                    "line": c_dict.get("line"),
                    "score": c_dict.get("score"),
                })

        # 5. Current Hypotheses & Explanations
        hypotheses_summary: List[Dict[str, Any]] = []
        hypotheses = getattr(session, "hypotheses", []) or []
        for h in hypotheses:
            h_dict = h.to_dict() if hasattr(h, "to_dict") else dict(h)
            hypotheses_summary.append({
                "hypothesis_id": h_dict.get("hypothesis_id"),
                "title": h_dict.get("title"),
                "claim": h_dict.get("claim"),
                "status": h_dict.get("status"),
                "candidate_fields": h_dict.get("candidate_fields", []),
                "supporting_evidence_ids": h_dict.get("supporting_evidence_ids", []),
            })

        # 6. Valid Ledger Evidence IDs
        ledger = getattr(session, "ledger", None)
        valid_evidence_ids: List[str] = []
        if ledger and hasattr(ledger, "_by_id"):
            valid_evidence_ids = list(ledger._by_id.keys())
        elif ledger and hasattr(ledger, "get_all_records"):
            valid_evidence_ids = [r.evidence_id for r in ledger.get_all_records()]

        # 7. Unresolved Follow-Up Observations
        observations_summary: List[Dict[str, Any]] = []
        obs_list = getattr(session, "follow_up_observations", []) or []
        for obs in obs_list:
            o_dict = obs.to_dict() if hasattr(obs, "to_dict") else dict(obs)
            observations_summary.append({
                "observation_id": o_dict.get("observation_id"),
                "question": o_dict.get("question"),
                "target_kind": o_dict.get("target_kind"),
                "status": o_dict.get("status"),
                "executed": o_dict.get("executed", False),
            })

        temporal_summary = t_ref.get("temporal_summary")
        temporal_plan = t_ref.get("temporal_plan")
        temporal_ctx = None
        if temporal_summary or temporal_plan:
            temporal_ctx = {
                "plan": temporal_plan,
                "summary": temporal_summary,
                "capture_limitations": "Captured via LOW_IMPACT zero-stop. Snapshot proximity does NOT prove actual read, write, or guard violation.",
            }

        context = {
            "investigation_id": getattr(session, "investigation_id", "inv_unknown"),
            "goal": getattr(session, "goal", "State inspection"),
            "target_identity": target_info,
            "capture_quality": capture_quality,
            "observed_facts": findings_summary,
            "candidate_functions": candidate_functions,
            "current_hypotheses": hypotheses_summary,
            "evidence_ledger_ids": valid_evidence_ids,
            "follow_up_observations": observations_summary,
            "temporal_context": temporal_ctx,
            "user_query": user_message,
        }

        # Context Fingerprint
        raw_json = json.dumps(context, sort_keys=True)
        fingerprint = hashlib.sha256(raw_json.encode("utf-8")).hexdigest()
        context["context_fingerprint"] = fingerprint

        return context

    def format_prompt(
        self,
        context: Dict[str, Any],
        conversation_history: Optional[List[Dict[str, str]]] = None,
        locale: str = "en",
    ) -> List[Dict[str, str]]:
        """Format system and user messages directing the LLM to return strict evidence-grounded JSON."""
        # Sanitize locale: support 'ko' and 'en'
        clean_locale = "ko" if str(locale).lower().strip() in ("ko", "kor", "korean") else "en"

        lang_instruction = ""
        if clean_locale == "ko":
            lang_instruction = (
                "\n\nLANGUAGE INSTRUCTION (MANDATORY):\n"
                "The user's active UI locale is Korean ('ko').\n"
                "You MUST write ALL natural-language text in fluent, professional Korean (한국어).\n"
                "This includes: 'summary', descriptions in 'observed_facts', hypothesis 'title' and 'claim', "
                "'unknowns', 'alternative_explanations', questions in 'proposed_observations', 'safety_notes', "
                "and 'next_steps'.\n"
                "TECHNICAL INTEGRITY RULES:\n"
                "- Do NOT translate C/C++ symbol names, function names, variable names, or struct/field paths "
                "(e.g., keep worker_status, transition_worker_state, counter, ptr literal in their original form).\n"
                "- Do NOT translate source file paths, line numbers, memory addresses (e.g. 0x...), or DWARF type names.\n"
                "- Do NOT translate evidence IDs (e.g. ev_...).\n"
                "- Keep all JSON keys exactly as defined in the schema.\n"
                "- Keep machine-readable status strings (e.g. PROPOSED, STATIC_CANDIDATE, READ_ONLY) in English."
            )
        else:
            lang_instruction = (
                "\n\nLANGUAGE INSTRUCTION:\n"
                "The user's active UI locale is English ('en').\n"
                "Write all natural-language summaries, claims, unknowns, and next steps in English.\n"
                "Preserve technical symbols, field paths, addresses, and JSON keys in their literal form."
            )

        system_prompt = (
            "You are an expert C/C++ systems debugger and root-cause investigator working with dynamicState.\n"
            "Your task is to analyze runtime evidence from process memory snapshots, DWARF debug information, "
            "and state transitions, and answer the user's investigation questions.\n\n"
            "STRICT OPERATIONAL & TRUST INVARIANTS:\n"
            "1. Ground all conclusions in the provided runtime evidence. Never fabricate evidence.\n"
            "2. Under NO circumstances can you validate a function candidate as the confirmed root cause. "
            "Candidate functions remain STATIC_CANDIDATE or EVIDENCE_SUPPORTED until independently proven by execution traces.\n"
            "3. Any evidence references ('evidence_refs') MUST only use IDs listed in 'evidence_ledger_ids'. "
            "Do NOT invent new evidence IDs.\n"
            "4. Clearly distinguish verified FACTS from HYPOTHESES and UNKNOWNS.\n"
            "5. Propose non-invasive discriminating observations to help narrow down competing explanations.\n"
            "6. You MUST respond ONLY with a single valid JSON object adhering to this schema:\n"
            "{\n"
            '  "summary": "Clear, concise diagnostic summary of the problem and evidence.",\n'
            '  "observed_facts": [{"fact": "Description of verified fact", "field_path": "...", "value_change": "..."}],\n'
            '  "hypotheses": [\n'
            '    {\n'
            '      "title": "Short title",\n'
            '      "claim": "Detailed causal explanation",\n'
            '      "candidate_function": "Function name if applicable",\n'
            '      "status": "PROPOSED"\n'
            '    }\n'
            '  ],\n'
            '  "unknowns": ["List of missing observations or uncertainties"],\n'
            '  "evidence_refs": ["List of referenced evidence IDs from evidence_ledger_ids"],\n'
            '  "alternative_explanations": ["Other possibilities considered and rejected"],\n'
            '  "proposed_observations": [\n'
            '    {\n'
            '      "question": "What discriminating question does this observation answer?",\n'
            '      "target_kind": "FIELD | COMPARISON | THREAD",\n'
            '      "target_field": "Field path if inspecting a field",\n'
            '      "risk": "READ_ONLY | MUTATION"\n'
            '    }\n'
            '  ],\n'
            '  "safety_notes": ["Safety prerequisites or live process warnings"],\n'
            '  "next_steps": ["Concrete recommended next action for the operator"]\n'
            "}"
            + lang_instruction
        )

        user_content = (
            f"Investigation Context:\n```json\n{json.dumps(context, indent=2)}\n```\n\n"
            f"User Question: {context.get('user_query', 'Analyze this state change and identify candidate writer functions.')}"
        )

        messages: List[Dict[str, str]] = [{"role": "system", "content": system_prompt}]
        if conversation_history:
            for turn in conversation_history[-6:]:  # Keep recent history
                messages.append(turn)
        messages.append({"role": "user", "content": user_content})

        return messages

    def _is_fact_grounded(
        self,
        fact_item: Dict[str, Any],
        session: Optional[Any],
        ledger: Optional[EvidenceLedger],
    ) -> Tuple[bool, str]:
        """Verify whether an asserted fact corresponds to verified session findings or ledger records.
        
        Strict Trust Invariants:
        - Absence of session context, empty findings list, or empty ledger NEVER makes arbitrary claims trusted.
        - Matching substrings or field-name overlaps do NOT establish ground truth.
        - Asserted values must be consistent with observed runtime values.
        """
        if not session and not ledger:
            return False, "no session or ledger context available to ground fact"

        findings = getattr(session, "findings", []) or [] if session else []
        ledger_records = []
        if ledger and hasattr(ledger, "_records"):
            ledger_records = getattr(ledger, "_records", [])
        elif ledger and hasattr(ledger, "get_all_records"):
            ledger_records = ledger.get_all_records()

        if not findings and not ledger_records:
            return False, "no session findings or ledger records available to ground fact"

        fact_text = (str(fact_item.get("fact") or "") + " " + str(fact_item.get("title") or "")).lower()
        field_path = str(fact_item.get("field_path") or "").strip().lower()

        def _match_path(target: str, cand: str) -> bool:
            """Exact or strict struct-member dot/arrow match (rejects arbitrary substring overlap)."""
            if not target or not cand:
                return False
            t = target.strip().lower()
            c = cand.strip().lower()
            if t == c:
                return True
            if c.endswith("." + t) or c.endswith("->" + t):
                return True
            if t.endswith("." + c) or t.endswith("->" + c):
                return True
            return False

        # If a specific field_path is asserted in the fact item
        if field_path:
            # Check findings
            for f in findings:
                f_path = str(getattr(f, "c_type_path", "") or getattr(f, "field_name", "") or "").strip().lower()
                if _match_path(field_path, f_path):
                    asserted_val = str(fact_item.get("observed_value") or fact_item.get("value") or fact_item.get("value_change") or "").strip().lower()
                    if asserted_val:
                        f_vals = [str(v).lower() for v in (getattr(f, "observed_value", None), getattr(f, "after_value", None), getattr(f, "current_value", None)) if v is not None]
                        if f_vals and not any(asserted_val == v or asserted_val in v for v in f_vals):
                            return False, f"asserted value '{asserted_val}' contradicts observed finding value {f_vals}"
                    return True, f"matched verified finding field '{f_path}'"

            # Check ledger records
            for r in ledger_records:
                fld_obs = getattr(r, "field_observation", {}) or {}
                if fld_obs:
                    var_name = str(fld_obs.get("variable_name", "")).strip().lower()
                    if _match_path(field_path, var_name):
                        return True, f"matched ledger field variable '{var_name}'"
                cmp_obs = getattr(r, "comparison_observation", {}) or {}
                if cmp_obs:
                    item_name = str(cmp_obs.get("item_name", "")).strip().lower()
                    if _match_path(field_path, item_name):
                        return True, f"matched ledger comparison item '{item_name}'"
                details = getattr(r, "details", {}) or {}
                det_path = str(details.get("field_path") or details.get("field") or "").strip().lower()
                if _match_path(field_path, det_path):
                    return True, f"matched ledger record details field '{det_path}'"

            return False, f"field '{field_path}' does not match any observed session finding or ledger record"

        # If no field_path is specified, fact must describe an observed finding or ledger event
        for f in findings:
            f_title = str(getattr(f, "title", "") or "").lower()
            f_desc = str(getattr(f, "description", "") or "").lower()
            f_path = str(getattr(f, "c_type_path", "") or getattr(f, "field_name", "") or "").lower()
            if f_path and re.search(r"\b" + re.escape(f_path) + r"\b", fact_text):
                return True, f"matched finding path '{f_path}' in fact statement"
            if f_title:
                keywords = [w for w in re.findall(r"\w+", f_title) if len(w) >= 4 and w not in ("with", "from", "that", "this", "were", "been", "during", "have")]
                if keywords and all(kw in fact_text for kw in keywords[:3]):
                    return True, f"matched finding title '{f.finding_id}'"

        for r in ledger_records:
            obs = str(getattr(r, "observation", "")).lower()
            if obs:
                keywords = [w for w in re.findall(r"\w+", obs) if len(w) >= 4 and w not in ("with", "from", "that", "this", "were", "been", "during", "have")]
                if keywords and all(kw in fact_text for kw in keywords[:3]):
                    return True, f"matched ledger record '{r.evidence_id}'"

        return False, "no corresponding runtime finding or ledger record"

    def _validate_function_candidate(self, fn_name: str, session: Optional[Any]) -> Tuple[str, str]:
        """Validate proposed function candidate against companion ELF symbols or findings.
        
        Returns:
            Tuple of (status, reason) where status is 'VALID', 'FABRICATED', or 'UNVERIFIED'.
        """
        if not fn_name:
            return "UNVERIFIED", "empty function name"
        if not session:
            return "STATIC", "no session context provided; retained as static candidate"

        clean_name = fn_name.split("(")[0].strip()

        # Check session findings candidates
        findings = getattr(session, "findings", []) or []
        for f in findings:
            for c in getattr(f, "function_candidates", []) or []:
                c_name = c.get("function_name") if isinstance(c, dict) else getattr(c, "function_name", "")
                if c_name and clean_name == c_name:
                    return "VALID", "matched finding candidate"

        # Check debug image symbols
        t_ref = getattr(session, "target_ref", {}) or {}
        debug_elf = t_ref.get("companion_elf_path") or t_ref.get("debug_image")
        if not debug_elf or not os.path.exists(debug_elf):
            return "UNVERIFIED", "companion debug ELF binary not available"

        try:
            from extractor.debug_image import inspect_elf
            info = inspect_elf(debug_elf)
            if info.is_stripped and not info.has_debug_info:
                return "UNVERIFIED", "companion ELF is stripped of debug info and symbols"

            import subprocess
            cmd = ["nm", "-C", debug_elf]
            proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
            if proc.returncode != 0 or not proc.stdout.strip():
                return "UNVERIFIED", "companion ELF has no readable symbol table"
            lines = proc.stdout.splitlines()
            symbols = set()
            for line in lines:
                parts = line.strip().split(maxsplit=2)
                if len(parts) >= 3:
                    symbols.add(parts[2].split("(")[0].strip())
            if not symbols:
                return "UNVERIFIED", "companion ELF symbol table empty"
            if clean_name in symbols:
                return "VALID", "matched companion ELF symbol"
            return "FABRICATED", f"function '{clean_name}' not found in companion ELF symbols"
        except Exception as e:
            return "UNVERIFIED", f"could not inspect companion ELF symbols: {e}"

    def _record_is_relevant(self, record: EvidenceRecord, claim_text: str, context: Optional[Dict[str, Any]] = None) -> bool:
        """Verify whether cited EvidenceRecord actually relates to the claim subject."""
        ev_type = getattr(record, "evidence_type", "")
        claim_lower = claim_text.lower()

        # 1. RUNTIME_IDENTITY cannot support memory corruption, write, or root-cause claims
        if ev_type == "RUNTIME_IDENTITY":
            if any(kw in claim_lower for kw in (
                "mutate", "corrupt", "overrun", "overflow", "guard", "write", "access",
                "root cause", "changed from", "transition", "pointer", "leak", "boundary"
            )):
                return False
            return True

        # 2. CAPTURE_QUALITY cannot support root cause or boundary crossing claims
        if ev_type == "CAPTURE_QUALITY":
            if any(kw in claim_lower for kw in ("root cause", "overrun", "overflow", "violation", "corrupt", "fault")):
                return False
            if any(kw in claim_lower for kw in ("gap", "quality", "consistency", "non_atomic", "partial", "complete", "sampling")):
                return True
            return True

        # 3. STATIC_LINK cannot prove dynamic runtime access or validated execution
        if ev_type == "STATIC_LINK":
            if any(kw in claim_lower for kw in ("actually executed", "validated root cause", "occurred at runtime", "wrote to memory")):
                return False
            return True

        return True

    def parse_and_validate_response(
        self,
        raw_response: str,
        valid_evidence_ids: List[str],
        ledger: Optional[EvidenceLedger] = None,
        session: Optional[Any] = None,
    ) -> Tuple[Dict[str, Any], List[str]]:
        """Parse JSON response, validate schema, and disarm unverified claims."""
        disarmed_claims: List[str] = []

        if ledger is None and session and hasattr(session, "ledger"):
            ledger = session.ledger
        if not valid_evidence_ids and ledger:
            valid_evidence_ids = list(ledger._by_id.keys()) if hasattr(ledger, "_by_id") else [r.evidence_id for r in ledger.get_all_records()]

        # 1. Clean markdown JSON formatting if present
        text = raw_response.strip()
        if "```json" in text:
            match = re.search(r"```json\s*(.*?)\s*```", text, re.DOTALL)
            if match:
                text = match.group(1).strip()
        elif "```" in text:
            match = re.search(r"```\s*(.*?)\s*```", text, re.DOTALL)
            if match:
                text = match.group(1).strip()

        is_malformed = False
        try:
            data = json.loads(text)
        except Exception:
            start = text.find("{")
            end = text.rfind("}")
            if start != -1 and end != -1 and end > start:
                try:
                    data = json.loads(text[start : end + 1])
                except Exception:
                    data = {}
                    is_malformed = True
            else:
                data = {}
                is_malformed = True

        if not isinstance(data, dict):
            data = {}
            is_malformed = True

        if is_malformed and raw_response.strip():
            disarmed_claims.append("Malformed model response could not be parsed as valid JSON schema")

        # 2. Enforce Default Schema and apply secret redaction
        summary = redact_sensitive_content(str(data.get("summary") or "Investigation conversational analysis complete."))
        raw_facts = list(data.get("observed_facts", []))
        raw_hypotheses = list(data.get("hypotheses", []))
        unknowns = [redact_sensitive_content(str(u)) for u in data.get("unknowns", [])]
        raw_evidence_refs = list(data.get("evidence_refs", []))
        alternatives = [redact_sensitive_content(str(a)) for a in data.get("alternative_explanations", [])]
        raw_observations = list(data.get("proposed_observations", []))
        safety_notes = [redact_sensitive_content(str(s)) for s in data.get("safety_notes", [])]
        next_steps = [redact_sensitive_content(str(n)) for n in data.get("next_steps", [])]

        # 3. Grounded Factual Claims Validation
        sanitized_facts: List[Dict[str, Any]] = []
        for f in raw_facts:
            if not isinstance(f, dict):
                continue
            f_clean = {k: redact_sensitive_content(v) for k, v in f.items()}
            is_grounded, ground_reason = self._is_fact_grounded(f_clean, session, ledger)
            if is_grounded:
                # Sanitize any fact-level evidence references
                if "evidence_ids" in f_clean and isinstance(f_clean["evidence_ids"], list):
                    valid_f_refs = []
                    for fref in f_clean["evidence_ids"]:
                        fref_str = str(fref).strip()
                        if fref_str not in valid_evidence_ids:
                            continue
                        if ledger:
                            f_rec = ledger.get_record(fref_str)
                            if f_rec and not self._record_is_relevant(f_rec, f_clean.get("fact", "") + " " + f_clean.get("field_path", "")):
                                continue
                        valid_f_refs.append(fref_str)
                    f_clean["evidence_ids"] = valid_f_refs
                sanitized_facts.append(f_clean)
            else:
                f_desc = f_clean.get("fact") or f_clean.get("title") or json.dumps(f_clean)
                disarmed_claims.append(f"Downgraded unsupported observed fact: '{str(f_desc)[:60]}' ({ground_reason})")
                unknowns.append(f"Model asserted unverified fact '{str(f_desc)[:60]}', but this was not verified in runtime observations.")

        # 4. Strip Fabricated or Unsupported Evidence References
        sanitized_evidence_refs: List[str] = []
        for ref in raw_evidence_refs:
            ref_str = str(ref).strip()
            if ref_str not in valid_evidence_ids:
                disarmed_claims.append(f"Stripped fabricated evidence reference '{ref_str}'")
                continue
            if ledger:
                rec = ledger.get_record(ref_str)
                if rec and not self._record_is_relevant(rec, summary):
                    disarmed_claims.append(f"Stripped unsupported evidence reference '{ref_str}' (record nature '{rec.evidence_type}' does not substantiate claim)")
                    continue
            sanitized_evidence_refs.append(ref_str)

        # 5. Sanitize and Disarm Hypotheses
        sanitized_hypotheses: List[Dict[str, Any]] = []
        for h in raw_hypotheses:
            if not isinstance(h, dict):
                continue
            h_copy = dict(h)
            h_copy["investigation_id"] = ""
            h_copy["hypothesis_id"] = h_copy.get("hypothesis_id") or f"hypo_chat_{uuid.uuid4().hex[:8]}"
            h_claim = str(h_copy.get("claim") or h_copy.get("title") or "")

            # Disarm any claimed VALIDATED status
            claimed_status = h_copy.get("status")
            if claimed_status == HYPOTHESIS_STATUS_VALIDATED:
                disarmed_claims.append(f"Demoted claimed status VALIDATED to PROPOSED in hypothesis '{h_copy.get('title')}'")
            h_copy["status"] = HYPOTHESIS_STATUS_PROPOSED

            # Handle candidate functions and validate against companion symbols
            cand_fn = h_copy.get("candidate_function") or h_copy.get("function_name")
            if cand_fn:
                cand_fn_str = str(cand_fn).strip()
                sym_status, sym_reason = self._validate_function_candidate(cand_fn_str, session)
                if sym_status == "FABRICATED":
                    disarmed_claims.append(f"Stripped fabricated function candidate '{cand_fn_str}' ({sym_reason})")
                    h_copy.pop("candidate_function", None)
                    h_copy.pop("function_name", None)
                    h_copy["function_candidates"] = []
                    unknowns.append(f"Model proposed candidate function '{cand_fn_str}', but symbol was not found in companion ELF.")
                elif sym_status == "UNVERIFIED":
                    disarmed_claims.append(f"Labeled unverified function candidate '{cand_fn_str}' as UNVERIFIED ({sym_reason})")
                    h_copy["function_candidates"] = [{
                        "function_name": cand_fn_str,
                        "candidate_tier": FUNCTION_TIER_UNVERIFIED,
                        "confirmed_root_cause": False,
                        "tier_limitation": "Companion ELF debug symbols unavailable or unverified; candidate cannot be validated as causal."
                    }]
                else:
                    h_copy["function_candidates"] = [{
                        "function_name": cand_fn_str,
                        "candidate_tier": FUNCTION_TIER_STATIC_CANDIDATE,
                        "confirmed_root_cause": False,
                        "tier_limitation": "Proposed via conversational analysis; requires independent runtime execution verification."
                    }]
            elif "function_candidates" in h_copy and isinstance(h_copy["function_candidates"], list):
                sanitized_cands = []
                for fc in h_copy["function_candidates"]:
                    if not isinstance(fc, dict):
                        continue
                    fc_name = str(fc.get("function_name") or fc.get("name") or "").strip()
                    if not fc_name:
                        continue
                    sym_status, sym_reason = self._validate_function_candidate(fc_name, session)
                    if sym_status == "FABRICATED":
                        disarmed_claims.append(f"Stripped fabricated function candidate '{fc_name}' ({sym_reason})")
                        unknowns.append(f"Candidate function '{fc_name}' was not found in companion ELF symbols.")
                        continue
                    tier = FUNCTION_TIER_UNVERIFIED if sym_status == "UNVERIFIED" else FUNCTION_TIER_STATIC_CANDIDATE
                    sanitized_cands.append({
                        "function_name": fc_name,
                        "candidate_tier": tier,
                        "confirmed_root_cause": False,
                        "tier_limitation": "Requires independent runtime execution verification." if tier != FUNCTION_TIER_UNVERIFIED else "Companion ELF debug symbols unavailable; unverified."
                    })
                h_copy["function_candidates"] = sanitized_cands

            # Validate supporting evidence refs on the hypothesis
            if "supporting_evidence_ids" in h_copy and isinstance(h_copy["supporting_evidence_ids"], list):
                valid_hypo_refs = []
                for href in h_copy["supporting_evidence_ids"]:
                    href_str = str(href).strip()
                    if href_str not in valid_evidence_ids:
                        disarmed_claims.append(f"Stripped fabricated evidence reference '{href_str}' from hypothesis '{h_copy.get('title')}'")
                        continue
                    if ledger:
                        h_rec = ledger.get_record(href_str)
                        if h_rec and not self._record_is_relevant(h_rec, h_claim):
                            disarmed_claims.append(f"Stripped unsupported evidence reference '{href_str}' from hypothesis '{h_copy.get('title')}'")
                            continue
                    valid_hypo_refs.append(href_str)
                h_copy["supporting_evidence_ids"] = valid_hypo_refs

            # Redact sensitive content in hypothesis fields
            for k in ("title", "claim", "proposed_mechanism", "uncertainty"):
                if k in h_copy and h_copy[k]:
                    h_copy[k] = redact_sensitive_content(h_copy[k])

            # Run through canonical disarmer
            disarmed_h = sanitize_and_disarm_llm_hypothesis(h_copy, ledger=ledger)
            sanitized_hypotheses.append(disarmed_h.to_dict())

        # 6. Sanitize Proposed Observations
        sanitized_observations: List[Dict[str, Any]] = []
        for idx, obs in enumerate(raw_observations):
            if not isinstance(obs, dict):
                continue
            o_copy = dict(obs)
            obs_id = o_copy.get("observation_id") or f"obs_chat_{uuid.uuid4().hex[:8]}"
            q = redact_sensitive_content(o_copy.get("question") or f"Inspect target field for hypothesis {idx+1}")
            kind = str(o_copy.get("target_kind", "FIELD")).upper()
            if kind not in ("FIELD", "COMPARISON", "THREAD", "MUTATION"):
                kind = "FIELD"

            requires_auth = (kind == "MUTATION") or ("MUTATION" in str(o_copy.get("risk", "")).upper())
            sanitized_observations.append({
                "observation_id": obs_id,
                "question": q,
                "target_kind": kind,
                "target_ref": {"field_path": o_copy.get("target_field") or o_copy.get("field_path", "")},
                "status": OBSERVATION_STATUS_PROPOSED,
                "executed": False,
                "requires_authorization": requires_auth,
                "safety_constraints": ["REQUIRES_AUTHORIZATION"] if requires_auth else ["READ_ONLY"],
            })

        validated_dict = {
            "summary": summary,
            "observed_facts": sanitized_facts,
            "hypotheses": sanitized_hypotheses,
            "unknowns": unknowns,
            "evidence_refs": sanitized_evidence_refs,
            "alternative_explanations": alternatives,
            "proposed_observations": sanitized_observations,
            "safety_notes": safety_notes,
            "next_steps": next_steps,
        }

        return validated_dict, disarmed_claims

    def cancel_analysis(self, request_id: str) -> bool:
        """Cancel an in-flight analysis request and terminate its child process."""
        return self.provider_manager.cancel_request(request_id)

    def analyze_investigation(
        self,
        session: Any,
        user_message: str,
        request_id: Optional[str] = None,
        provider_override: Optional[str] = None,
        allow_fallback: bool = False,
        locale: str = "en",
    ) -> StructuredAnalysisResult:
        """Execute end-to-end conversational analysis for an investigation session."""
        req_id = request_id or f"req_{int(time.time())}_{uuid.uuid4().hex[:6]}"
        clean_locale = "ko" if str(locale).lower().strip() in ("ko", "kor", "korean") else "en"
        start_time = time.time()
        self.provider_manager.track_request_start()

        try:
            if req_id and self.provider_manager.is_cancelled(req_id):
                raise ProviderCancelledError(f"Request {req_id} was cancelled before starting")

            # Step 1: Gather compact context
            context = self.build_compact_context(session, user_message)
            fingerprint = context["context_fingerprint"]
            valid_evidence_ids = context.get("evidence_ledger_ids", [])

            # Step 2: Resolve provider & truthful selection
            configured_default = self.provider_manager.config.provider_type
            clean_override = (provider_override or "").lower().strip()

            if clean_override and clean_override not in ("auto", ""):
                selected_provider = clean_override
                is_explicit_selection = (clean_override != "none")
            else:
                selected_provider = configured_default if configured_default != "auto" else "none"
                is_explicit_selection = False

            provider = self.provider_manager.get_provider(clean_override or None)
            health = provider.check_health()

            # Step 3: Format Prompt
            chat_history = getattr(session, "chat_history", []) or []
            messages = self.format_prompt(context, chat_history, locale=clean_locale)

            # Step 4: Execute Call with Truthful Handling
            is_fallback = False
            invoked_provider = selected_provider
            model_name = health.model
            execution_status = "MODEL_ROUNDTRIP_VERIFIED"
            fallback_reason = None

            if req_id and self.provider_manager.is_cancelled(req_id):
                raise ProviderCancelledError(f"Request {req_id} was cancelled before provider invocation")

            if is_explicit_selection:
                # User explicitly selected an LLM provider: must not silently fall back
                if not health.reachable:
                    if not allow_fallback:
                        err_msg = health.error or f"Provider '{selected_provider}' is not reachable or binary was not found"
                        raise ProviderUnavailableError(
                            f"Selected provider '{selected_provider}' is unavailable: {err_msg}. "
                            "Please verify provider configuration or select '결정론적 규칙 엔진 (Fallback)'."
                        )
                    logger.warning("Selected provider %s is unreachable; falling back to deterministic reasoning", selected_provider)
                    is_fallback = True
                    invoked_provider = "deterministic_fallback"
                    model_name = "deterministic-engine"
                    execution_status = "FALLBACK"
                    fallback_reason = health.error or f"Provider '{selected_provider}' unreachable"
                    raw_response = DeterministicFallbackProvider().chat_completion(messages, json_mode=True, request_id=req_id)
                else:
                    try:
                        raw_response = provider.chat_completion(messages, json_mode=True, request_id=req_id)
                        invoked_provider = health.provider_type
                        model_name = health.model
                        execution_status = "MODEL_ROUNDTRIP_VERIFIED"
                    except ProviderCancelledError:
                        raise
                    except Exception as exc:
                        if not allow_fallback:
                            raise ProviderExecutionError(
                                f"Selected provider '{selected_provider}' execution failed: {exc}. "
                                "Please check logs or select '결정론적 규칙 엔진 (Fallback)'."
                            )
                        logger.warning("Selected provider %s failed: %s; falling back to deterministic reasoning", selected_provider, exc)
                        is_fallback = True
                        invoked_provider = "deterministic_fallback"
                        model_name = "deterministic-engine"
                        execution_status = "FALLBACK"
                        fallback_reason = str(exc)
                        raw_response = DeterministicFallbackProvider().chat_completion(messages, json_mode=True, request_id=req_id)
            elif selected_provider == "none":
                # Deterministic fallback directly requested
                is_fallback = True
                invoked_provider = "deterministic_fallback"
                model_name = "deterministic-engine"
                execution_status = "DETERMINISTIC_RULES"
                raw_response = DeterministicFallbackProvider().chat_completion(messages, json_mode=True, request_id=req_id)
            else:
                # Auto-detect or configured default
                if health.reachable and not health.is_fallback:
                    try:
                        raw_response = provider.chat_completion(messages, json_mode=True, request_id=req_id)
                        invoked_provider = health.provider_type
                        model_name = health.model
                        execution_status = "MODEL_ROUNDTRIP_VERIFIED"
                    except ProviderCancelledError:
                        raise
                    except Exception as exc:
                        logger.warning("Default provider %s failed: %s; falling back to deterministic reasoning", health.provider_type, exc)
                        is_fallback = True
                        invoked_provider = "deterministic_fallback"
                        model_name = "deterministic-engine"
                        execution_status = "FALLBACK"
                        fallback_reason = str(exc)
                        raw_response = DeterministicFallbackProvider().chat_completion(messages, json_mode=True, request_id=req_id)
                else:
                    is_fallback = True
                    invoked_provider = "deterministic_fallback"
                    model_name = "deterministic-engine"
                    execution_status = "DETERMINISTIC_RULES" if selected_provider == "none" else "FALLBACK"
                    fallback_reason = health.error or "No responsive LLM provider configured"
                    raw_response = DeterministicFallbackProvider().chat_completion(messages, json_mode=True, request_id=req_id)

            if req_id and self.provider_manager.is_cancelled(req_id):
                raise ProviderCancelledError(f"Request {req_id} was cancelled before response parsing")

            # Step 5: Validate and Sanitize Response
            validated_data, disarmed = self.parse_and_validate_response(
                raw_response,
                valid_evidence_ids=valid_evidence_ids,
                ledger=getattr(session, "ledger", None),
                session=session,
            )

            if req_id and self.provider_manager.is_cancelled(req_id):
                raise ProviderCancelledError(f"Request {req_id} was cancelled; session state unmutated")

            duration_ms = round((time.time() - start_time) * 1000.0, 2)

            meta = {
                "request_id": req_id,
                "locale": clean_locale,
                "configured_default_provider": configured_default,
                "selected_provider": selected_provider,
                "invoked_provider": invoked_provider,
                "provider": invoked_provider,
                "model": model_name,
                "duration_ms": duration_ms,
                "is_fallback": is_fallback,
                "is_cli": invoked_provider in ("gemini", "cline", "cli", "agy", "acp", "gemini-acp"),
                "execution_status": execution_status,
                "fallback_reason": fallback_reason,
                "context_fingerprint": fingerprint,
                "timestamp": time.time(),
            }

            validation_status = (
                "FALLBACK_DETERMINISTIC" if is_fallback
                else ("SANITIZED_CLAIMS_DISARMED" if disarmed else "VALIDATED_CLEAN")
            )

            result = StructuredAnalysisResult(
                summary=validated_data["summary"],
                observed_facts=validated_data["observed_facts"],
                hypotheses=validated_data["hypotheses"],
                unknowns=validated_data["unknowns"],
                evidence_refs=validated_data["evidence_refs"],
                alternative_explanations=validated_data["alternative_explanations"],
                proposed_observations=validated_data["proposed_observations"],
                safety_notes=validated_data["safety_notes"],
                next_steps=validated_data["next_steps"],
                provider_metadata=meta,
                validation_status=validation_status,
                unverified_claims_disarmed=disarmed,
            )

            # Step 6: Update Session State
            # Attach sanitized hypotheses
            for h_dict in validated_data["hypotheses"]:
                try:
                    hypo_obj = InvestigationHypothesis.from_dict(h_dict)
                    if not any(existing.hypothesis_id == hypo_obj.hypothesis_id for existing in session.hypotheses):
                        session.hypotheses.append(hypo_obj)
                except Exception:
                    pass

            # Attach proposed observations
            for obs_dict in validated_data["proposed_observations"]:
                try:
                    obs_obj = FollowUpObservation(
                        observation_id=obs_dict["observation_id"],
                        question=obs_dict["question"],
                        target_kind=obs_dict.get("target_kind", "FIELD"),
                        target_ref=obs_dict.get("target_ref", {}),
                        status=OBSERVATION_STATUS_PROPOSED,
                        executed=False,
                        safety_constraints=obs_dict.get("safety_constraints", ["READ_ONLY"]),
                    )
                    if not any(existing.observation_id == obs_obj.observation_id for existing in session.follow_up_observations):
                        session.follow_up_observations.append(obs_obj)
                except Exception:
                    pass

            # Step 7: Record Audit Timeline Event (NO credentials)
            if hasattr(session, "add_timeline_event"):
                session.add_timeline_event(
                    event_type="CONVERSATIONAL_ANALYSIS_COMPLETED",
                    title=f"Conversational Analysis: {result.summary[:60]}",
                    summary=result.summary,
                    classification=EVIDENCE_CLASSIFICATION_INFERENCE,
                    details={
                        "request_id": req_id,
                        "locale": clean_locale,
                        "configured_default_provider": configured_default,
                        "selected_provider": selected_provider,
                        "invoked_provider": invoked_provider,
                        "provider": invoked_provider,
                        "model": model_name,
                        "is_fallback": is_fallback,
                        "is_cli": meta.get("is_cli", False),
                        "execution_status": execution_status,
                        "fallback_reason": fallback_reason,
                        "context_fingerprint": fingerprint,
                        "validation_status": validation_status,
                        "disarmed_claims_count": len(disarmed),
                    },
                )

            # Record turn in chat history
            if isinstance(session, dict):
                if "chat_history" not in session:
                    session["chat_history"] = []
                session["chat_history"].append({"role": "user", "content": user_message})
                session["chat_history"].append({"role": "assistant", "content": json.dumps(result.to_dict())})
            elif hasattr(session, "chat_history"):
                if getattr(session, "chat_history") is None:
                    session.chat_history = []
                session.chat_history.append({"role": "user", "content": user_message})
                session.chat_history.append({"role": "assistant", "content": json.dumps(result.to_dict())})
            elif hasattr(session, "__dict__"):
                session.chat_history = getattr(session, "chat_history", None) or []
                session.chat_history.append({"role": "user", "content": user_message})
                session.chat_history.append({"role": "assistant", "content": json.dumps(result.to_dict())})

            return result

        finally:
            self.provider_manager.track_request_end()

"""Evidence Adapter: Bridges live DWARF observation results to EvidenceLedger.

Translates raw dictionaries from WatchSessionManager and live observation tools
into cryptographically-traceable EvidenceRecord instances while preserving 100%
of the original return dictionaries for backward compatibility.
"""

from dataclasses import asdict
from datetime import datetime, timezone
import hashlib
import json
import uuid
from typing import Any, Dict, List, Optional, Tuple, Union

from .evidence_ledger import (
    EVIDENCE_SCHEMA_VERSION,
    EVIDENCE_TYPE_CAPTURE_QUALITY,
    EVIDENCE_TYPE_COMPARISON,
    EVIDENCE_TYPE_DIAGNOSTIC,
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EVIDENCE_TYPE_HYPOTHESIS,
    EVIDENCE_TYPE_INFERENCE,
    EVIDENCE_TYPE_OBJECT_STATE,
    EVIDENCE_TYPE_RUNTIME_IDENTITY,
    EVIDENCE_TYPE_STATIC_LINK,
    EvidenceLedger,
    EvidenceRecord,
    NATURE_HYPOTHESIS,
    NATURE_INFERENCE,
    NATURE_OBSERVATION,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
    PROVENANCE_CLASS_SYNTHETIC_FIXTURE,
    VALID_EVIDENCE_TYPES,
)


COLLECTION_STATUS_COLLECTED = "COLLECTED"
COLLECTION_STATUS_PARTIAL = "PARTIAL"
COLLECTION_STATUS_FAILED = "FAILED"
COLLECTION_STATUS_ABSTAIN = "ABSTAIN"

CONSISTENCY_ZERO_STOP_ATOMIC = "ZERO_STOP_ATOMIC"
CONSISTENCY_CONSISTENT = "CONSISTENT"
CONSISTENCY_WEAK_UNSTOPPED = "WEAK_UNSTOPPED"
CONSISTENCY_CONCURRENT = "CONCURRENT"


def compute_payload_digest(data: Any) -> Tuple[str, int]:
    """Computes a SHA-256 digest and size of serialized data."""
    try:
        raw = json.dumps(data, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(raw).hexdigest(), len(raw)
    except Exception:
        raw = str(data).encode("utf-8")
        return hashlib.sha256(raw).hexdigest(), len(raw)


class EvidenceAdapter:
    """Non-intrusive adapter for transforming tool output dicts into EvidenceRecords."""

    def __init__(self, default_provenance_class: str = PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE):
        self.default_provenance_class = default_provenance_class

    def adapt_symbol_evaluation(
        self,
        eval_result: Dict[str, Any],
        target_identity: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        finding_id: Optional[str] = None,
    ) -> List[EvidenceRecord]:
        """Translates evaluate_symbol_paths output into field/object observation records."""
        records: List[EvidenceRecord] = []
        eff_target = target_identity or {
            "pid": eval_result.get("pid"),
            "companion_elf": eval_result.get("companion_elf"),
        }
        timestamp = datetime.now(timezone.utc).isoformat()
        results = eval_result.get("results", [])

        for idx, item in enumerate(results):
            expr = item.get("expression") or f"expr_{idx}"
            status = item.get("status", "UNKNOWN")
            value = item.get("value")
            rt_addr = item.get("runtime_address")
            type_name = item.get("type")

            limitations: List[str] = []
            if status != "OBSERVED":
                limitations.append(f"read_status_{status.lower()}")

            coll_status = (
                COLLECTION_STATUS_COLLECTED
                if status == "OBSERVED"
                else (COLLECTION_STATUS_ABSTAIN if status in ("READ_ERROR", "TIMEOUT", "RESTRICTED") else COLLECTION_STATUS_PARTIAL)
            )

            rec_id = f"evi_sym_{uuid.uuid4().hex[:10]}"
            obs_desc = f"Observed '{expr}' = {value} (status: {status})" if status == "OBSERVED" else f"Evaluation of '{expr}' yielded status '{status}'"

            rec = EvidenceRecord(
                evidence_id=rec_id,
                evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
                nature=NATURE_OBSERVATION,
                source="evaluate_symbol_paths",
                timestamp=timestamp,
                session_id=session_id,
                finding_id=finding_id,
                observation=obs_desc,
                target_identity=eff_target,
                field_observation={
                    "field_path": expr,
                    "resolved_expression": item.get("resolved_expression") or expr,
                    "value": value,
                    "type_name": type_name,
                    "runtime_address": rt_addr,
                    "evaluation_status": status,
                    "was_coerced": item.get("was_coerced", False),
                },
                provenance={
                    "provenance_class": self.default_provenance_class,
                    "tool": "runtime_eval_memory_path",
                    "stop_duration_ms": eval_result.get("stop_duration_ms", 0.0),
                    "consistency_level": CONSISTENCY_WEAK_UNSTOPPED if eval_result.get("stop_duration_ms", 0.0) == 0.0 else CONSISTENCY_ZERO_STOP_ATOMIC,
                },
                details={
                    "collection_status": coll_status,
                    "limitations": limitations,
                    "self_repair": item.get("self_repair"),
                },
            )
            records.append(rec)

        return records

    def adapt_hypothesis_verification(
        self,
        verify_result: Dict[str, Any],
        target_identity: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        finding_id: Optional[str] = None,
    ) -> Tuple[EvidenceRecord, List[EvidenceRecord]]:
        """Adapts verify_runtime_hypothesis result into a primary hypothesis record and child observation records."""
        child_records: List[EvidenceRecord] = []
        eff_target = target_identity or {
            "pid": verify_result.get("pid"),
            "companion_elf": verify_result.get("companion_elf"),
        }
        timestamp = datetime.now(timezone.utc).isoformat()
        assertion_results = verify_result.get("assertion_results", [])

        # Create child observation records for each assertion
        for a_idx, a_item in enumerate(assertion_results):
            a_id = f"evi_ast_{uuid.uuid4().hex[:10]}"
            ev_status = a_item.get("evaluation_status", "UNKNOWN")
            is_passed = a_item.get("passed", False)

            # Strict collection status:
            if ev_status == "OBSERVED":
                coll_status = COLLECTION_STATUS_COLLECTED
                a_nature = NATURE_OBSERVATION
            elif ev_status in ("READ_ERROR", "TIMEOUT", "RESTRICTED", "UNKNOWN"):
                coll_status = COLLECTION_STATUS_ABSTAIN
                a_nature = NATURE_OBSERVATION
            else:
                coll_status = COLLECTION_STATUS_PARTIAL
                a_nature = NATURE_OBSERVATION

            child_rec = EvidenceRecord(
                evidence_id=a_id,
                evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
                nature=a_nature,
                source="verify_runtime_hypothesis",
                timestamp=timestamp,
                session_id=session_id,
                finding_id=finding_id,
                observation=f"Assertion '{a_item.get('assertion')}': passed={is_passed} (observed={a_item.get('observed_value')}, expected={a_item.get('expected')})",
                target_identity=eff_target,
                field_observation={
                    "assertion": a_item.get("assertion"),
                    "lhs_expression": a_item.get("lhs_expression"),
                    "resolved_expression": a_item.get("resolved_expression"),
                    "operator": a_item.get("operator"),
                    "expected": a_item.get("expected"),
                    "observed_value": a_item.get("observed_value"),
                    "evaluation_status": ev_status,
                    "passed": is_passed,
                },
                provenance={
                    "provenance_class": self.default_provenance_class,
                    "tool": "runtime_verify_hypothesis",
                    "stop_duration_ms": verify_result.get("stop_duration_ms", 0.0),
                },
                details={
                    "collection_status": coll_status,
                    "was_coerced": a_item.get("was_coerced", False),
                },
            )
            child_records.append(child_rec)

        parent_ids = [c.evidence_id for c in child_records]
        hyp_text = verify_result.get("hypothesis", "")
        raw_verdict = verify_result.get("verdict", "INCONCLUSIVE")
        confidence = verify_result.get("confidence_score", 0.0)

        # Separate large correlated slot owners
        slot_owners = verify_result.get("correlated_slot_owners", {})
        owners_digest, owners_size = compute_payload_digest(slot_owners)

        # Primary hypothesis record
        primary_rec = EvidenceRecord(
            evidence_id=f"evi_hyp_{uuid.uuid4().hex[:10]}",
            evidence_type=EVIDENCE_TYPE_HYPOTHESIS,
            nature=NATURE_HYPOTHESIS,
            source="verify_runtime_hypothesis",
            timestamp=timestamp,
            session_id=session_id,
            finding_id=finding_id,
            observation=f"Hypothesis '{hyp_text}' evaluated with verdict '{raw_verdict}' (confidence: {confidence})",
            parent_evidence_ids=parent_ids,
            target_identity=eff_target,
            provenance={
                "provenance_class": self.default_provenance_class,
                "tool": "runtime_verify_hypothesis",
                "stop_duration_ms": verify_result.get("stop_duration_ms", 0.0),
                "verification_latency_us": verify_result.get("verification_latency_us", 0.0),
            },
            details={
                "hypothesis_text": hyp_text,
                "verdict": raw_verdict,
                "confidence_score": confidence,
                "total_assertions": verify_result.get("total_assertions", len(assertion_results)),
                "passed_assertions": verify_result.get("passed_assertions", 0),
                "failed_assertions": verify_result.get("failed_assertions", 0),
                "slot_owners_digest": owners_digest,
                "slot_owners_count": len(slot_owners),
                "correlated_slot_owners_summary": {k: len(v) for k, v in slot_owners.items()},
            },
        )

        return primary_rec, child_records

    def adapt_generic_tool_output(
        self,
        tool_name: str,
        tool_result: Dict[str, Any],
        evidence_type: str = EVIDENCE_TYPE_DIAGNOSTIC,
        nature: str = NATURE_OBSERVATION,
        target_identity: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        finding_id: Optional[str] = None,
    ) -> EvidenceRecord:
        """Adapts arbitrary diagnostic or structural tool outputs, separating large payloads."""
        eff_target = target_identity or {
            "pid": tool_result.get("pid"),
            "companion_elf": tool_result.get("companion_elf") or tool_result.get("companion_elf_path"),
        }
        timestamp = datetime.now(timezone.utc).isoformat()
        digest, size_bytes = compute_payload_digest(tool_result)

        # Check for error or collection status
        success = tool_result.get("success", True)
        error = tool_result.get("error")
        coll_status = COLLECTION_STATUS_COLLECTED if success and not error else COLLECTION_STATUS_FAILED

        # Extract large strings or charts to separate payload reference
        compact_details: Dict[str, Any] = {
            "tool_name": tool_name,
            "collection_status": coll_status,
            "payload_digest": digest,
            "payload_size_bytes": size_bytes,
            "stop_duration_ms": tool_result.get("stop_duration_ms", 0.0),
        }

        # Selectively copy compact key metadata
        for k in (
            "verdict", "confidence_score", "matched_threads", "active_slots", "total_slots",
            "leak_count", "corrupted_count", "anomaly_score", "drift_score", "summary"
        ):
            if k in tool_result:
                val = tool_result[k]
                if isinstance(val, (int, float, str, bool)):
                    compact_details[k] = val
                elif isinstance(val, list):
                    compact_details[f"{k}_count"] = len(val)

        # Validate evidence type
        final_ev_type = evidence_type if evidence_type in VALID_EVIDENCE_TYPES else EVIDENCE_TYPE_DIAGNOSTIC

        rec = EvidenceRecord(
            evidence_id=f"evi_diag_{uuid.uuid4().hex[:10]}",
            evidence_type=final_ev_type,
            nature=nature,
            source=tool_name,
            timestamp=timestamp,
            session_id=session_id,
            finding_id=finding_id,
            observation=f"Diagnostic result from tool '{tool_name}' (status: {coll_status})",
            target_identity=eff_target,
            provenance={
                "provenance_class": self.default_provenance_class,
                "tool": tool_name,
                "stop_duration_ms": tool_result.get("stop_duration_ms", 0.0),
            },
            details=compact_details,
        )
        return rec

    def record_into_ledger(
        self,
        records: Union[EvidenceRecord, List[EvidenceRecord]],
        ledger: Optional[EvidenceLedger],
    ) -> List[EvidenceRecord]:
        """Safely appends one or more records into an EvidenceLedger if provided."""
        if not ledger:
            return records if isinstance(records, list) else [records]

        added: List[EvidenceRecord] = []
        rec_list = records if isinstance(records, list) else [records]
        for r in rec_list:
            try:
                ledger.add_record(r)
                added.append(r)
            except Exception:
                # If duplicate or schema issue, continue safely
                pass
        return added

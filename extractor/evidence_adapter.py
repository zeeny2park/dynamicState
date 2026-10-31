"""Evidence Adapter: Bridges live DWARF and runtime observation results to EvidenceLedger.

Translates raw dictionaries from WatchSessionManager, InspectionModules, and live
observation tools into cryptographically-traceable EvidenceRecord instances while:
- Strictly separating OBSERVED_FACT (NATURE_OBSERVATION) from INFERENCE and HYPOTHESIS
- Computing semantic digests independent of volatile timestamps or random IDs
- Classifying every observation into explicit result categories:
  NEW_EVIDENCE, DUPLICATE_EVIDENCE, NO_NEW_EVIDENCE, PARTIAL_EVIDENCE,
  OBSERVATION_FAILED, OBSERVATION_UNAVAILABLE, BUDGET_REJECTED
- Preserving provenance ceilings (imported/unverified data is never upgraded to live capture)
"""

from datetime import datetime, timezone
import hashlib
import json
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple, Union

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
    LiveCaptureReceipt,
    NATURE_HYPOTHESIS,
    NATURE_INFERENCE,
    NATURE_OBSERVATION,
    PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    PROVENANCE_CLASS_SYNTHETIC_FIXTURE,
    TRUSTED_PROVENANCE_CLASSES,
    VALID_EVIDENCE_TYPES,
    verify_live_capture_receipt,
)


COLLECTION_STATUS_COLLECTED = "COLLECTED"
COLLECTION_STATUS_PARTIAL = "PARTIAL"
COLLECTION_STATUS_FAILED = "FAILED"
COLLECTION_STATUS_ABSTAIN = "ABSTAIN"

CONSISTENCY_ZERO_STOP_ATOMIC = "ZERO_STOP_ATOMIC"
CONSISTENCY_CONSISTENT = "CONSISTENT"
CONSISTENCY_WEAK_UNSTOPPED = "WEAK_UNSTOPPED"
CONSISTENCY_CONCURRENT = "CONCURRENT"

# Explicit Observation Result Categories (Phase 2.0 Section 6)
RESULT_NEW_EVIDENCE = "NEW_EVIDENCE"
RESULT_DUPLICATE_EVIDENCE = "DUPLICATE_EVIDENCE"
RESULT_NO_NEW_EVIDENCE = "NO_NEW_EVIDENCE"
RESULT_PARTIAL_EVIDENCE = "PARTIAL_EVIDENCE"
RESULT_OBSERVATION_FAILED = "OBSERVATION_FAILED"
RESULT_OBSERVATION_UNAVAILABLE = "OBSERVATION_UNAVAILABLE"
RESULT_BUDGET_REJECTED = "BUDGET_REJECTED"

VALID_OBSERVATION_RESULT_CATEGORIES = {
    RESULT_NEW_EVIDENCE,
    RESULT_DUPLICATE_EVIDENCE,
    RESULT_NO_NEW_EVIDENCE,
    RESULT_PARTIAL_EVIDENCE,
    RESULT_OBSERVATION_FAILED,
    RESULT_OBSERVATION_UNAVAILABLE,
    RESULT_BUDGET_REJECTED,
}

VOLATILE_PAYLOAD_KEYS = {
    "timestamp",
    "generated_at",
    "created_at",
    "updated_at",
    "completed_at",
    "evidence_id",
    "session_id",
    "finding_id",
    "observation_id",
    "event_id",
    "latency_us",
    "observation_latency_us",
    "verification_latency_us",
    "report_latency_us",
    "wall_clock_elapsed_ms",
    "elapsed_ms",
}


def strip_volatile_fields(data: Any) -> Any:
    """Recursively removes volatile timestamps, latencies, and random IDs for semantic hashing."""
    if isinstance(data, dict):
        return {
            str(k): strip_volatile_fields(v)
            for k, v in sorted(data.items(), key=lambda x: str(x[0]))
            if str(k) not in VOLATILE_PAYLOAD_KEYS
        }
    if isinstance(data, (list, tuple)):
        return [strip_volatile_fields(x) for x in data]
    return data


def compute_payload_digest(data: Any) -> Tuple[str, int]:
    """Computes a SHA-256 digest and byte size of canonicalized data."""
    try:
        cleaned = strip_volatile_fields(data)
        raw = json.dumps(cleaned, sort_keys=True, default=str).encode("utf-8")
        return hashlib.sha256(raw).hexdigest(), len(raw)
    except Exception:
        raw = str(data).encode("utf-8")
        return hashlib.sha256(raw).hexdigest(), len(raw)


def compute_semantic_evidence_digest(
    source: str,
    payload: Any,
    target_identity: Optional[Dict[str, Any]] = None,
    epoch: int = 0,
) -> str:
    """Computes a deterministic semantic identity digest excluding timestamps and random IDs."""
    canonical = {
        "source": str(source or ""),
        "epoch": int(epoch),
        "target": strip_volatile_fields(target_identity or {}),
        "payload": strip_volatile_fields(payload),
    }
    raw = json.dumps(canonical, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class EvidenceAdapter:
    """Non-intrusive adapter for transforming tool output dicts into EvidenceRecords."""

    def __init__(
        self,
        default_provenance_class: str = PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
        receipt: Optional[Any] = None,
        session_secret: Optional[str] = None,
    ):
        self.default_provenance_class = default_provenance_class
        self.receipt = receipt
        self.session_secret = session_secret

    def _resolve_provenance_class(
        self,
        payload: Optional[Dict[str, Any]] = None,
        target_identity: Optional[Dict[str, Any]] = None,
        override_provenance: Optional[str] = None,
        receipt: Optional[Any] = None,
    ) -> str:
        """Resolves provenance class ensuring LIVE_RUNTIME_CAPTURE requires an authentic receipt."""
        # 1. Synthetic fixture check: fixtures remain synthetic
        if isinstance(payload, dict):
            if payload.get("is_synthetic") is True or (payload.get("provenance") or {}).get("is_synthetic") is True:
                return PROVENANCE_CLASS_SYNTHETIC_FIXTURE
            if payload.get("provenance_class") == PROVENANCE_CLASS_SYNTHETIC_FIXTURE:
                return PROVENANCE_CLASS_SYNTHETIC_FIXTURE
        if isinstance(target_identity, dict):
            if target_identity.get("is_synthetic") is True or target_identity.get("provenance_class") == PROVENANCE_CLASS_SYNTHETIC_FIXTURE:
                return PROVENANCE_CLASS_SYNTHETIC_FIXTURE
        if override_provenance == PROVENANCE_CLASS_SYNTHETIC_FIXTURE or self.default_provenance_class == PROVENANCE_CLASS_SYNTHETIC_FIXTURE:
            return PROVENANCE_CLASS_SYNTHETIC_FIXTURE

        # 2. Check for imported / unverified flags
        if override_provenance == PROVENANCE_CLASS_IMPORTED_UNVERIFIED:
            return PROVENANCE_CLASS_IMPORTED_UNVERIFIED
        if isinstance(payload, dict) and payload.get("provenance_class") == PROVENANCE_CLASS_IMPORTED_UNVERIFIED:
            return PROVENANCE_CLASS_IMPORTED_UNVERIFIED
        if isinstance(target_identity, dict) and target_identity.get("provenance_class") == PROVENANCE_CLASS_IMPORTED_UNVERIFIED:
            return PROVENANCE_CLASS_IMPORTED_UNVERIFIED

        # 3. Controlled reproduction check
        if override_provenance == PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION:
            return PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION

        # 4. Check for authentic live capture receipt
        active_rcpt = receipt or getattr(self, "receipt", None) or getattr(self, "live_capture_receipt", None)
        if isinstance(payload, dict):
            active_rcpt = active_rcpt or payload.get("capture_receipt") or payload.get("live_receipt")
            prov_d = payload.get("provenance")
            if isinstance(prov_d, dict):
                active_rcpt = active_rcpt or prov_d.get("capture_receipt") or prov_d.get("live_receipt")

        exp_pid = target_identity.get("pid") if isinstance(target_identity, dict) else (payload.get("pid") if isinstance(payload, dict) else None)
        active_auth = getattr(self, "verification_authority", None)
        rcpt_ok, _ = verify_live_capture_receipt(
            active_rcpt,
            secret=self.session_secret,
            verification_authority=active_auth,
            expected_pid=exp_pid,
        )
        if rcpt_ok:
            return PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE

        # Without an authentic verified receipt, live capture CANNOT be granted.
        # Fall back to unverified imported provenance.
        return PROVENANCE_CLASS_IMPORTED_UNVERIFIED

    def adapt_raw_observation(
        self,
        module_id: str,
        domain: str,
        raw_payload: Dict[str, Any],
        collection_status: str = COLLECTION_STATUS_COLLECTED,
        error_reason: Optional[str] = None,
        target_identity: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        epoch: int = 0,
    ) -> Dict[str, Any]:
        """Adapts a raw observation payload with strict ABSTAIN preservation on failure."""
        if collection_status in (COLLECTION_STATUS_ABSTAIN, COLLECTION_STATUS_FAILED) or error_reason:
            status = "ABSTAIN" if collection_status == COLLECTION_STATUS_ABSTAIN else "FAILED"
        else:
            status = "COLLECTED"

        sem_digest = compute_semantic_evidence_digest(
            source=module_id,
            payload=raw_payload,
            target_identity=target_identity,
            epoch=epoch,
        )
        return {
            "module_id": module_id,
            "domain": domain,
            "status": status,
            "collection_status": collection_status,
            "error_reason": error_reason or "",
            "payload": raw_payload,
            "semantic_digest": sem_digest,
            "session_id": session_id,
        }

    def adapt_symbol_evaluation(
        self,
        eval_result: Dict[str, Any],
        target_identity: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        finding_id: Optional[str] = None,
        epoch: int = 0,
    ) -> List[EvidenceRecord]:
        """Translates evaluate_symbol_paths output into field/object observation records."""
        records: List[EvidenceRecord] = []
        eff_target = target_identity or {
            "pid": eval_result.get("pid"),
            "companion_elf": eval_result.get("companion_elf"),
        }
        prov_cls = self._resolve_provenance_class(eval_result, eff_target)
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

            if status == "OBSERVED":
                coll_status = COLLECTION_STATUS_COLLECTED
                res_cat = RESULT_NEW_EVIDENCE
            elif status in ("READ_ERROR", "TIMEOUT"):
                coll_status = COLLECTION_STATUS_ABSTAIN
                res_cat = RESULT_OBSERVATION_FAILED
            elif status in ("RESTRICTED", "SYMBOL_NOT_FOUND", "UNAVAILABLE"):
                coll_status = COLLECTION_STATUS_ABSTAIN
                res_cat = RESULT_OBSERVATION_UNAVAILABLE
            else:
                coll_status = COLLECTION_STATUS_PARTIAL
                res_cat = RESULT_PARTIAL_EVIDENCE

            sem_digest = compute_semantic_evidence_digest(
                source="evaluate_symbol_paths",
                payload={"expr": expr, "status": status, "value": value, "type": type_name},
                target_identity=eff_target,
                epoch=epoch,
            )

            rec_id = f"evi_sym_{sem_digest[:10]}"
            obs_desc = (
                f"Observed '{expr}' = {value} (status: {status})"
                if status == "OBSERVED"
                else f"Evaluation of '{expr}' yielded non-observed status '{status}'"
            )

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
                    "value": value if status == "OBSERVED" else None,
                    "type_name": type_name,
                    "runtime_address": rt_addr,
                    "evaluation_status": status,
                    "was_coerced": item.get("was_coerced", False),
                },
                provenance={
                    "provenance_class": prov_cls,
                    "tool": "runtime_eval_memory_path",
                    "stop_duration_ms": eval_result.get("stop_duration_ms", 0.0),
                    "consistency_level": (
                        CONSISTENCY_WEAK_UNSTOPPED
                        if eval_result.get("stop_duration_ms", 0.0) == 0.0
                        else CONSISTENCY_ZERO_STOP_ATOMIC
                    ),
                },
                capture_quality={
                    "completeness": "COMPLETE" if status == "OBSERVED" else "FAILED",
                    "status": "COMPLETE" if status == "OBSERVED" else "FAILED",
                    "consistency_level": (
                        "NON_ATOMIC" if eval_result.get("stop_duration_ms", 0.0) == 0.0 else "STOPPED"
                    ),
                },
                details={
                    "collection_status": coll_status,
                    "result_category": res_cat,
                    "semantic_digest": sem_digest,
                    "epoch": epoch,
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
        epoch: int = 0,
    ) -> Tuple[EvidenceRecord, List[EvidenceRecord]]:
        """Adapts verify_runtime_hypothesis result into a primary hypothesis record and child observation records."""
        child_records: List[EvidenceRecord] = []
        eff_target = target_identity or {
            "pid": verify_result.get("pid"),
            "companion_elf": verify_result.get("companion_elf"),
        }
        prov_cls = self._resolve_provenance_class(verify_result, eff_target)
        timestamp = datetime.now(timezone.utc).isoformat()
        assertion_results = verify_result.get("assertion_results", [])

        for a_idx, a_item in enumerate(assertion_results):
            ev_status = a_item.get("evaluation_status", "UNKNOWN")
            is_passed = a_item.get("passed", False)

            if ev_status == "OBSERVED":
                coll_status = COLLECTION_STATUS_COLLECTED
            elif ev_status in ("READ_ERROR", "TIMEOUT", "RESTRICTED", "UNKNOWN", "SYMBOL_NOT_FOUND"):
                coll_status = COLLECTION_STATUS_ABSTAIN
            else:
                coll_status = COLLECTION_STATUS_PARTIAL

            sem_digest = compute_semantic_evidence_digest(
                source="verify_runtime_hypothesis",
                payload={
                    "assertion": a_item.get("assertion"),
                    "lhs": a_item.get("lhs_expression"),
                    "observed": a_item.get("observed_value"),
                    "status": ev_status,
                },
                target_identity=eff_target,
                epoch=epoch,
            )
            a_id = f"evi_ast_{sem_digest[:10]}"

            child_rec = EvidenceRecord(
                evidence_id=a_id,
                evidence_type=EVIDENCE_TYPE_FIELD_OBSERVATION,
                nature=NATURE_OBSERVATION,
                source="verify_runtime_hypothesis",
                timestamp=timestamp,
                session_id=session_id,
                finding_id=finding_id,
                observation=(
                    f"Assertion '{a_item.get('assertion')}': passed={is_passed} "
                    f"(observed={a_item.get('observed_value')}, expected={a_item.get('expected')})"
                ),
                target_identity=eff_target,
                field_observation={
                    "assertion": a_item.get("assertion"),
                    "lhs_expression": a_item.get("lhs_expression"),
                    "resolved_expression": a_item.get("resolved_expression"),
                    "operator": a_item.get("operator"),
                    "expected": a_item.get("expected"),
                    "observed_value": a_item.get("observed_value") if ev_status == "OBSERVED" else None,
                    "evaluation_status": ev_status,
                    "passed": is_passed if ev_status == "OBSERVED" else False,
                },
                provenance={
                    "provenance_class": prov_cls,
                    "tool": "runtime_verify_hypothesis",
                    "stop_duration_ms": verify_result.get("stop_duration_ms", 0.0),
                },
                details={
                    "collection_status": coll_status,
                    "semantic_digest": sem_digest,
                    "epoch": epoch,
                    "was_coerced": a_item.get("was_coerced", False),
                },
            )
            child_records.append(child_rec)

        parent_ids = [c.evidence_id for c in child_records]
        hyp_text = verify_result.get("hypothesis", "")
        raw_verdict = verify_result.get("verdict", "INCONCLUSIVE")
        confidence = verify_result.get("confidence_score", 0.0)

        slot_owners = verify_result.get("correlated_slot_owners", {})
        owners_digest, _ = compute_payload_digest(slot_owners)
        hyp_digest = compute_semantic_evidence_digest(
            source="verify_runtime_hypothesis_primary",
            payload={"hypothesis": hyp_text, "verdict": raw_verdict, "parents": parent_ids},
            target_identity=eff_target,
            epoch=epoch,
        )

        primary_rec = EvidenceRecord(
            evidence_id=f"evi_hyp_{hyp_digest[:10]}",
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
                "provenance_class": prov_cls,
                "tool": "runtime_verify_hypothesis",
                "stop_duration_ms": verify_result.get("stop_duration_ms", 0.0),
                "verification_latency_us": verify_result.get("verification_latency_us", 0.0),
            },
            details={
                "hypothesis_text": hyp_text,
                "verdict": raw_verdict,
                "confidence_score": confidence,
                "semantic_digest": hyp_digest,
                "total_assertions": verify_result.get("total_assertions", len(assertion_results)),
                "passed_assertions": verify_result.get("passed_assertions", 0),
                "failed_assertions": verify_result.get("failed_assertions", 0),
                "slot_owners_digest": owners_digest,
                "slot_owners_count": len(slot_owners),
                "correlated_slot_owners_summary": {k: len(v) for k, v in slot_owners.items()},
            },
        )

        return primary_rec, child_records

    def classify_tool_result_category(
        self,
        tool_name: str,
        tool_result: Dict[str, Any],
        ledger: Optional[EvidenceLedger] = None,
        target_identity: Optional[Dict[str, Any]] = None,
        epoch: int = 0,
    ) -> Tuple[str, str, str]:
        """Determines (result_category, collection_status, semantic_digest) for a tool output."""
        sem_digest = compute_semantic_evidence_digest(
            source=tool_name,
            payload=tool_result,
            target_identity=target_identity,
            epoch=epoch,
        )

        explicit_cat = tool_result.get("result_category")
        if explicit_cat == RESULT_BUDGET_REJECTED or tool_result.get("budget_rejected") or tool_result.get("error_code") == "BUDGET_EXHAUSTED":
            return RESULT_BUDGET_REJECTED, COLLECTION_STATUS_ABSTAIN, sem_digest

        if (
            explicit_cat == RESULT_OBSERVATION_UNAVAILABLE
            or tool_result.get("unavailable")
            or tool_result.get("status") in ("RESTRICTED", "UNAVAILABLE", "SYMBOL_NOT_FOUND")
            or tool_result.get("error_code") in ("PREREQUISITE_UNAVAILABLE", "TARGET_SYMBOL_UNAVAILABLE", "CAPABILITY_UNAVAILABLE", "RESTRICTED", "SYMBOL_NOT_FOUND")
        ):
            return RESULT_OBSERVATION_UNAVAILABLE, COLLECTION_STATUS_ABSTAIN, sem_digest

        success = tool_result.get("success", True)
        error = tool_result.get("error")
        status = tool_result.get("status")
        if not success or error or status in ("READ_ERROR", "TIMEOUT", "FAILED"):
            return RESULT_OBSERVATION_FAILED, COLLECTION_STATUS_ABSTAIN, sem_digest

        # Check for duplicate semantic digest in ledger
        if ledger is not None:
            for existing in ledger._records:
                ex_details = existing.details or {}
                if ex_details.get("semantic_digest") == sem_digest:
                    return RESULT_DUPLICATE_EVIDENCE, COLLECTION_STATUS_COLLECTED, sem_digest

        # Check for partial observation
        if (
            tool_result.get("partial") is True
            or status == "PARTIAL"
            or tool_result.get("capture_status") == "PARTIAL"
            or tool_result.get("collection_status") == COLLECTION_STATUS_PARTIAL
        ):
            return RESULT_PARTIAL_EVIDENCE, COLLECTION_STATUS_PARTIAL, sem_digest

        if "results" in tool_result and isinstance(tool_result["results"], list):
            res_list = tool_result["results"]
            if not res_list:
                return RESULT_NO_NEW_EVIDENCE, COLLECTION_STATUS_COLLECTED, sem_digest
            obs_cnt = sum(1 for r in res_list if isinstance(r, dict) and r.get("status", "OBSERVED") == "OBSERVED")
            fail_cnt = len(res_list) - obs_cnt
            if obs_cnt == 0:
                return RESULT_OBSERVATION_FAILED, COLLECTION_STATUS_ABSTAIN, sem_digest
            if fail_cnt > 0:
                return RESULT_PARTIAL_EVIDENCE, COLLECTION_STATUS_PARTIAL, sem_digest

        # Check if tool returned an empty / no-op payload with no substantive evidence
        substantive_keys = {
            "threads", "contended_locks", "deadlock_detected", "findings", "results",
            "active_slots", "total_slots", "leak_count", "corrupted_pointers", "corrupted_count",
            "matched_threads", "variables", "symbols", "regions", "modules", "counter", "value",
            "observed_facts", "queue_depth", "pending_items", "frames", "locals", "status_summary",
        }
        has_substantive = False
        for k, v in tool_result.items():
            if k in ("success", "pid", "companion_elf", "companion_elf_path", "profile_id", "stop_duration_ms",
                     "measured_bytes_read", "charged_bytes", "used_conservative_byte_estimate", "observation_latency_us",
                     "bytes_read", "result_category"):
                continue
            if k in substantive_keys or v not in (None, [], {}, ""):
                if v not in (None, [], {}, ""):
                    has_substantive = True
                    break

        if not has_substantive or tool_result.get("no_new_evidence") is True:
            return RESULT_NO_NEW_EVIDENCE, COLLECTION_STATUS_COLLECTED, sem_digest

        return RESULT_NEW_EVIDENCE, COLLECTION_STATUS_COLLECTED, sem_digest

    def adapt_generic_tool_output(
        self,
        tool_name: str,
        tool_result: Dict[str, Any],
        evidence_type: str = EVIDENCE_TYPE_DIAGNOSTIC,
        nature: str = NATURE_OBSERVATION,
        target_identity: Optional[Dict[str, Any]] = None,
        session_id: Optional[str] = None,
        finding_id: Optional[str] = None,
        ledger: Optional[EvidenceLedger] = None,
        epoch: int = 0,
    ) -> EvidenceRecord:
        """Adapts diagnostic or structural tool outputs, preserving semantic digest and result category."""
        # Rule: Never create an OBSERVED_FACT (NATURE_OBSERVATION) from an inference or hypothesis
        if evidence_type == EVIDENCE_TYPE_HYPOTHESIS or tool_result.get("is_hypothesis"):
            nature = NATURE_HYPOTHESIS
        elif evidence_type == EVIDENCE_TYPE_INFERENCE or tool_result.get("is_inference"):
            nature = NATURE_INFERENCE

        eff_target = target_identity or {
            "pid": tool_result.get("pid"),
            "companion_elf": tool_result.get("companion_elf") or tool_result.get("companion_elf_path"),
        }
        prov_cls = self._resolve_provenance_class(tool_result, eff_target)
        timestamp = datetime.now(timezone.utc).isoformat()
        digest, size_bytes = compute_payload_digest(tool_result)
        res_cat, coll_status, sem_digest = self.classify_tool_result_category(
            tool_name=tool_name,
            tool_result=tool_result,
            ledger=ledger,
            target_identity=eff_target,
            epoch=epoch,
        )

        compact_details: Dict[str, Any] = {
            "tool_name": tool_name,
            "collection_status": coll_status,
            "result_category": res_cat,
            "semantic_digest": sem_digest,
            "epoch": epoch,
            "payload_digest": digest,
            "payload_size_bytes": size_bytes,
            "stop_duration_ms": tool_result.get("stop_duration_ms", 0.0),
            "measured_bytes_read": tool_result.get("measured_bytes_read"),
            "charged_bytes": tool_result.get("charged_bytes"),
        }

        if tool_result.get("error"):
            compact_details["error"] = str(tool_result["error"])
        if tool_result.get("error_code"):
            compact_details["error_code"] = str(tool_result["error_code"])

        for k in (
            "verdict", "confidence_score", "matched_threads", "active_slots", "total_slots",
            "leak_count", "corrupted_count", "corrupted_pointers", "anomaly_score", "drift_score",
            "summary", "deadlock_detected", "contended_locks", "blocked_threads", "outcome",
            "target_function", "field_path", "thread_id",
        ):
            if k in tool_result:
                val = tool_result[k]
                if isinstance(val, (int, float, str, bool)):
                    compact_details[k] = val
                elif isinstance(val, list):
                    compact_details[f"{k}_count"] = len(val)
                    if len(val) <= 16:
                        compact_details[k] = val

        final_ev_type = evidence_type if evidence_type in VALID_EVIDENCE_TYPES else EVIDENCE_TYPE_DIAGNOSTIC
        cq_completeness = (
            "COMPLETE"
            if coll_status == COLLECTION_STATUS_COLLECTED
            else ("PARTIAL" if coll_status == COLLECTION_STATUS_PARTIAL else "FAILED")
        )
        cq_consistency = (
            tool_result.get("consistency_level")
            or ("STOPPED" if tool_result.get("stop_duration_ms", 0.0) > 0 else "ZERO_STOP_ATOMIC")
        )

        rec = EvidenceRecord(
            evidence_id=f"evi_diag_{sem_digest[:10]}",
            evidence_type=final_ev_type,
            nature=nature,
            source=tool_name,
            timestamp=timestamp,
            session_id=session_id,
            finding_id=finding_id,
            observation=(
                tool_result.get("observation")
                or f"Diagnostic result from '{tool_name}' (category: {res_cat}, status: {coll_status})"
            ),
            target_identity=eff_target,
            provenance={
                "provenance_class": prov_cls,
                "tool": tool_name,
                "stop_duration_ms": tool_result.get("stop_duration_ms", 0.0),
            },
            capture_quality={
                "completeness": cq_completeness,
                "status": cq_completeness,
                "consistency_level": cq_consistency,
            },
            details=compact_details,
        )
        return rec

    def record_into_ledger(
        self,
        records: Union[EvidenceRecord, List[EvidenceRecord]],
        ledger: Optional[EvidenceLedger],
    ) -> List[EvidenceRecord]:
        """Safely appends one or more non-duplicate, non-empty records into an EvidenceLedger."""
        if not ledger:
            return records if isinstance(records, list) else [records]

        added: List[EvidenceRecord] = []
        rec_list = records if isinstance(records, list) else [records]
        for r in rec_list:
            r_details = r.details if hasattr(r, "details") else (r.get("details") if isinstance(r, dict) and "details" in r else (r if isinstance(r, dict) else {}))
            res_cat = r_details.get("result_category")
            # Invariant: Empty responses and duplicates must not increase evidence count
            if res_cat in (RESULT_NO_NEW_EVIDENCE, RESULT_DUPLICATE_EVIDENCE):
                continue

            sem_dig = r_details.get("semantic_digest")
            if sem_dig:
                dup = next(
                    (ex for ex in ledger._records if (ex.details or {}).get("semantic_digest") == sem_dig),
                    None,
                )
                if dup is not None:
                    continue
            try:
                rec_obj = ledger.add_record(r)
                added.append(rec_obj)
            except Exception:
                pass
        return added

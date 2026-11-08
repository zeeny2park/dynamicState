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
    NATURE_HYPOTHESIS,
    NATURE_INFERENCE,
    NATURE_OBSERVATION,
    PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    PROVENANCE_CLASS_SYNTHETIC,
    PROVENANCE_CLASS_SYNTHETIC_FIXTURE,
    TRUSTED_PROVENANCE_CLASSES,
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

    def __init__(self, default_provenance_class: str = PROVENANCE_CLASS_IMPORTED_UNVERIFIED):
        self.default_provenance_class = default_provenance_class

    def _resolve_provenance_class(
        self,
        payload: Optional[Dict[str, Any]] = None,
        target_identity: Optional[Dict[str, Any]] = None,
        override_provenance: Optional[str] = None,
        session_id: Optional[str] = None,
        live_receipt: Optional[Any] = None,
    ) -> str:
        """Resolves provenance class with fail-closed trust boundaries.

        Rules:
        - Default to untrusted/imported provenance (IMPORTED_UNVERIFIED).
        - Never accept caller-provided provenance_class or target_identity flags as authority.
        - Never upgrade based only on payload metadata.
        - Live evidence requires independently verified capture receipt with production authority.
        - Controlled reproduction requires independently verified execution proof.
        - Synthetic and imported provenance ceilings are strictly preserved.
        """
        p_dict = payload if isinstance(payload, dict) else {}
        prov_dict = p_dict.get("provenance") if isinstance(p_dict.get("provenance"), dict) else {}
        t_ident = target_identity if isinstance(target_identity, dict) else {}

        # 1. Synthetic ceiling: If any source indicates synthetic/simulated, clamp to SYNTHETIC_FIXTURE
        is_synthetic = bool(
            p_dict.get("is_synthetic")
            or prov_dict.get("is_synthetic")
            or t_ident.get("is_synthetic")
            or p_dict.get("provenance_class") in (PROVENANCE_CLASS_SYNTHETIC, PROVENANCE_CLASS_SYNTHETIC_FIXTURE)
            or prov_dict.get("provenance_class") in (PROVENANCE_CLASS_SYNTHETIC, PROVENANCE_CLASS_SYNTHETIC_FIXTURE)
            or t_ident.get("provenance_class") in (PROVENANCE_CLASS_SYNTHETIC, PROVENANCE_CLASS_SYNTHETIC_FIXTURE)
            or override_provenance in (PROVENANCE_CLASS_SYNTHETIC, PROVENANCE_CLASS_SYNTHETIC_FIXTURE)
            or any(p_dict.get(k) is not None for k in ("force_failed", "force_error", "force_contradiction", "simulated_outcome"))
            or any(prov_dict.get(k) is not None for k in ("force_failed", "force_error", "force_contradiction", "simulated_outcome"))
        )
        if is_synthetic:
            return PROVENANCE_CLASS_SYNTHETIC_FIXTURE

        # 2. Caller-submitted or imported ceiling
        if (
            p_dict.get("caller_submitted")
            or p_dict.get("unverified_caller_claim")
            or prov_dict.get("submission_channel") == "external_caller"
            or t_ident.get("caller_submitted")
            or p_dict.get("provenance_class") == PROVENANCE_CLASS_IMPORTED_UNVERIFIED
            or prov_dict.get("provenance_class") == PROVENANCE_CLASS_IMPORTED_UNVERIFIED
            or t_ident.get("provenance_class") == PROVENANCE_CLASS_IMPORTED_UNVERIFIED
            or override_provenance == PROVENANCE_CLASS_IMPORTED_UNVERIFIED
        ):
            return PROVENANCE_CLASS_IMPORTED_UNVERIFIED

        # 3. Controlled runtime reproduction requires authentic verifier attestation or execution proof
        if (
            override_provenance == PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION
            or p_dict.get("provenance_class") == PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION
            or prov_dict.get("provenance_class") == PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION
        ):
            att = prov_dict.get("verifier_attestation") or p_dict.get("verifier_attestation")
            if att and isinstance(att, dict) and att.get("token_sig") and not att.get("attestation_rejected"):
                return PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION
            return PROVENANCE_CLASS_IMPORTED_UNVERIFIED

        # 4. Genuine LIVE_RUNTIME_CAPTURE requires an authentic, verified LiveCaptureReceipt
        rcpt = live_receipt or prov_dict.get("live_capture_receipt") or p_dict.get("live_capture_receipt")
        if rcpt is not None and t_ident.get("pid"):
            from .capture_backend import LiveCaptureReceipt
            try:
                rcpt_obj = rcpt if isinstance(rcpt, LiveCaptureReceipt) else LiveCaptureReceipt.from_dict(rcpt)
                exp_pid = t_ident.get("pid")
                exp_bid = t_ident.get("build_id") or t_ident.get("target_build_id")
                exp_proc = t_ident.get("process_identity")
                exp_exe = t_ident.get("executable_identity") or t_ident.get("executable")
                ok, _ = rcpt_obj.verify(
                    expected_session_id=session_id or p_dict.get("session_id"),
                    expected_pid=exp_pid,
                    expected_process_identity=exp_proc,
                    expected_executable_identity=exp_exe,
                    expected_build_id=exp_bid,
                    require_production_authority=True,
                )
                if ok:
                    return PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE
            except Exception:
                pass

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
        rcpt = eval_result.get("live_capture_receipt") or (eval_result.get("provenance") or {}).get("live_capture_receipt")
        prov_cls = self._resolve_provenance_class(eval_result, eff_target, session_id=session_id, live_receipt=rcpt)
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
                    **({"live_capture_receipt": rcpt if isinstance(rcpt, dict) else rcpt.to_dict()} if rcpt is not None else {}),
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
                    **({"observation_digest": (rcpt if isinstance(rcpt, dict) else rcpt.to_dict()).get("observation_digest")} if rcpt and (rcpt if isinstance(rcpt, dict) else getattr(rcpt, "to_dict", lambda: {})()).get("observation_digest") else {}),
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
        rcpt = verify_result.get("live_capture_receipt") or (verify_result.get("provenance") or {}).get("live_capture_receipt")
        prov_cls = self._resolve_provenance_class(verify_result, eff_target, session_id=session_id, live_receipt=rcpt)
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
                **({"live_capture_receipt": rcpt if isinstance(rcpt, dict) else rcpt.to_dict()} if rcpt is not None else {}),
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
        evidence_id: Optional[str] = None,
        observation: Optional[str] = None,
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
        rcpt = tool_result.get("live_capture_receipt") or (tool_result.get("provenance") or {}).get("live_capture_receipt")
        prov_cls = self._resolve_provenance_class(tool_result, eff_target, session_id=session_id, live_receipt=rcpt)
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

        if eff_target.get("pid"):
            compact_details["target_pid"] = eff_target["pid"]

        # Preserve recipe, investigation, and source correlation metadata
        for meta_k in (
            "recipe_id", "step_id", "finding", "finding_classification",
            "problem_category", "domain", "address", "symbol", "observed_value",
            "raw_observation", "normalized_observation", "correlation",
        ):
            if meta_k in tool_result and tool_result[meta_k] is not None:
                compact_details[meta_k] = tool_result[meta_k]

        if rcpt and prov_cls == PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE:
            rcpt_dict = rcpt if isinstance(rcpt, dict) else (rcpt.to_dict() if hasattr(rcpt, "to_dict") else {})
            compact_details["live_capture_receipt"] = rcpt_dict
            if rcpt_dict.get("observation_digest"):
                compact_details["observation_digest"] = rcpt_dict["observation_digest"]

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

        # Disarm caller-supplied confidence and authority upgrades on unverified inputs
        if (
            tool_result.get("caller_submitted")
            or tool_result.get("unverified_caller_claim")
            or prov_cls == PROVENANCE_CLASS_IMPORTED_UNVERIFIED
            or tool_name.startswith("unverified_")
        ):
            compact_details["caller_submitted"] = True
            compact_details.pop("confidence_score", None)
            compact_details.pop("confidence", None)
            compact_details.pop("verdict", None)

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

        obs_text = (
            observation
            or tool_result.get("observation")
            or tool_result.get("finding")
            or f"Diagnostic result from '{tool_name}' (category: {res_cat}, status: {coll_status})"
        )

        eff_ev_id = evidence_id or tool_result.get("evidence_id") or f"evi_diag_{sem_digest[:10]}"

        prov_dict: Dict[str, Any] = {
            "provenance_class": prov_cls,
            "tool": tool_name,
            "module_id": tool_result.get("recipe_id") or tool_name,
            "stop_duration_ms": tool_result.get("stop_duration_ms", 0.0),
        }
        if rcpt is not None and prov_cls == PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE:
            prov_dict["live_capture_receipt"] = rcpt if isinstance(rcpt, dict) else rcpt.to_dict()

        rec = EvidenceRecord(
            evidence_id=eff_ev_id,
            evidence_type=final_ev_type,
            nature=nature,
            source=tool_name,
            timestamp=timestamp,
            session_id=session_id,
            finding_id=finding_id,
            observation=str(obs_text),
            target_identity=eff_target,
            provenance=prov_dict,
            capture_quality={
                "completeness": cq_completeness,
                "status": cq_completeness,
                "consistency_level": cq_consistency,
            },
            details=compact_details,
        )
        if eff_target and eff_target.get("pid"):
            rec.target_pid = eff_target["pid"]
        return rec

    def record_into_ledger(
        self,
        records: Union[EvidenceRecord, List[EvidenceRecord]],
        ledger: Optional[EvidenceLedger],
        raise_on_error: bool = False,
    ) -> List[EvidenceRecord]:
        """Safely appends one or more non-duplicate records into an EvidenceLedger."""
        if not ledger:
            return records if isinstance(records, list) else [records]

        added: List[EvidenceRecord] = []
        rec_list = records if isinstance(records, list) else [records]
        for r in rec_list:
            sem_dig = (r.details or {}).get("semantic_digest")
            if sem_dig:
                dup = next(
                    (ex for ex in ledger._records if (ex.details or {}).get("semantic_digest") == sem_dig),
                    None,
                )
                if dup is not None:
                    continue
            try:
                ledger.add_record(r)
                added.append(r)
            except Exception as e:
                if raise_on_error:
                    raise
        return added

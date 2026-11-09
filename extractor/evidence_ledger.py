"""Evidence Ledger: Machine-readable, versioned evidence model for dynamicState investigations.

Provides a structured, immutable record of runtime facts, capture quality metrics,
typed object interpretations, observation comparisons, and static-code linkages,
strictly distinguishing direct observations from speculative inferences.
"""

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import hashlib
import hmac
import json
import math
import re
import threading
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from .canonical_json import rfc8785_canonical_json, rfc8785_canonical_str


PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE = "LIVE_RUNTIME_CAPTURE"
PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION = "CONTROLLED_RUNTIME_REPRODUCTION"
PROVENANCE_CLASS_SYNTHETIC = "SYNTHETIC"
PROVENANCE_CLASS_SYNTHETIC_FIXTURE = "SYNTHETIC_FIXTURE"
PROVENANCE_CLASS_IMPORTED_UNVERIFIED = "IMPORTED_UNVERIFIED"

TRUSTED_PROVENANCE_CLASSES = {
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
}

SYNTHETIC_PROVENANCE_CLASSES = {
    PROVENANCE_CLASS_SYNTHETIC,
    PROVENANCE_CLASS_SYNTHETIC_FIXTURE,
}

VALID_PROVENANCE_CLASSES = {
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
    PROVENANCE_CLASS_SYNTHETIC,
    PROVENANCE_CLASS_SYNTHETIC_FIXTURE,
    PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
}

OBSERVATION_OUTCOME_SUPPORTED = "SUPPORTED"
OBSERVATION_OUTCOME_CONTRADICTED = "CONTRADICTED"
OBSERVATION_OUTCOME_INCONCLUSIVE = "INCONCLUSIVE"
OBSERVATION_OUTCOME_ABSTAIN = "ABSTAIN"

VALID_OBSERVATION_OUTCOMES = {
    OBSERVATION_OUTCOME_SUPPORTED,
    OBSERVATION_OUTCOME_CONTRADICTED,
    OBSERVATION_OUTCOME_INCONCLUSIVE,
    OBSERVATION_OUTCOME_ABSTAIN,
}

# Genuine supported function attribution mechanisms
ATTRIBUTION_BASIS_CALL_STACK = "call_stack_observation"
ATTRIBUTION_BASIS_EXECUTION_TRACE = "runtime_execution_trace"
ATTRIBUTION_BASIS_SINGLE_WRITER = "controlled_single_writer_isolation"

VALID_ATTRIBUTION_BASES = {
    ATTRIBUTION_BASIS_CALL_STACK,
    ATTRIBUTION_BASIS_EXECUTION_TRACE,
    ATTRIBUTION_BASIS_SINGLE_WRITER,
}


# Explicit evidence trust levels
CLAIM_ARTIFACT_INTEGRITY_VERIFIED = "ARTIFACT_INTEGRITY_VERIFIED"
CLAIM_CAPTURE_PROVENANCE_VERIFIED = "CAPTURE_PROVENANCE_VERIFIED"
CLAIM_TARGET_IDENTITY_VERIFIED = "TARGET_IDENTITY_VERIFIED"
CLAIM_STATE_TRANSITION_VERIFIED = "STATE_TRANSITION_VERIFIED"
CLAIM_FUNCTION_ATTRIBUTION_VERIFIED = "FUNCTION_ATTRIBUTION_VERIFIED"

ALL_TRUST_CLAIMS = {
    CLAIM_ARTIFACT_INTEGRITY_VERIFIED,
    CLAIM_CAPTURE_PROVENANCE_VERIFIED,
    CLAIM_TARGET_IDENTITY_VERIFIED,
    CLAIM_STATE_TRANSITION_VERIFIED,
    CLAIM_FUNCTION_ATTRIBUTION_VERIFIED,
}


@dataclass(frozen=True)
class ControlledExecutionResult:
    """Authentic execution receipt produced by a verified runtime execution or controlled reproduction."""
    execution_id: str
    investigation_id: str
    target_function: str
    field_path: str
    before_value: Any
    after_value: Any
    execution_status: str  # "REPRODUCED" or "SUCCESS"
    capture_quality: Dict[str, Any]
    hypothesis_id: str = ""
    evidence_id: str = ""
    before_snapshot_ref: Optional[str] = None
    after_snapshot_ref: Optional[str] = None
    before_snapshot_hash: Optional[str] = None
    after_snapshot_hash: Optional[str] = None
    target_identity: Optional[Dict[str, Any]] = None
    backend_type: str = "controlled_runtime"
    provenance_class: str = PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION
    function_attribution_verified: bool = False
    attribution_basis: str = ""
    attribution_limitation: str = ""
    verified_claims: Tuple[str, ...] = ()
    executed_at: str = ""
    receipt_signature: str = ""
    signature_version: str = "v2_rfc8785"

    def __post_init__(self):
        if not isinstance(self.verified_claims, tuple):
            object.__setattr__(self, "verified_claims", tuple(sorted(self.verified_claims or ())))

    @property
    def is_function_attribution_verified(self) -> bool:
        if self.function_attribution_verified is not None:
            return bool(self.function_attribution_verified) or (CLAIM_FUNCTION_ATTRIBUTION_VERIFIED in getattr(self, "verified_claims", ()))
        return False

    @property
    def state_transition_verified(self) -> bool:
        return (
            CLAIM_STATE_TRANSITION_VERIFIED in getattr(self, "verified_claims", ())
            or (self.execution_status in ("REPRODUCED", "SUCCESS", "CONFIRMED") and self.before_value is not None and self.after_value is not None)
        )

    def verify_authenticity(self, session_secret: str, allow_legacy: bool = True) -> bool:
        """Verify the cryptographic authenticity of this execution receipt against session secret.
        
        Enforces strict signature version compliance and legacy migration policy:
        - 'v2_rfc8785': Verified strictly using RFC 8785 canonical JSON HMAC-SHA256. Fails closed without implicit downgrade.
        - 'v1_legacy', 'v1_legacy_unversioned': Verified using legacy delimiter HMAC-SHA256 only when explicitly allowed.
        - Any unrecognized version fails closed.
        """
        if not self.receipt_signature:
            return False
        sig_ver = getattr(self, "signature_version", "v2_rfc8785") or "v2_rfc8785"
        if sig_ver == "v2_rfc8785":
            try:
                expected_v2 = compute_receipt_signature(session_secret, self)
                return hmac.compare_digest(self.receipt_signature, expected_v2)
            except Exception:
                return False
        elif sig_ver in ("v1_legacy", "v1_legacy_unversioned"):
            if not allow_legacy:
                return False
            try:
                expected_v1 = compute_legacy_receipt_signature(session_secret, self)
                return hmac.compare_digest(self.receipt_signature, expected_v1)
            except Exception:
                return False
        return False

    def to_dict(self) -> Dict[str, Any]:
        """Serialize ControlledExecutionResult into JSON-serializable dictionary."""
        return {
            "execution_id": self.execution_id,
            "investigation_id": self.investigation_id,
            "target_function": self.target_function,
            "field_path": self.field_path,
            "before_value": self.before_value,
            "after_value": self.after_value,
            "execution_status": self.execution_status,
            "capture_quality": dict(self.capture_quality) if isinstance(self.capture_quality, dict) else {},
            "hypothesis_id": self.hypothesis_id,
            "evidence_id": self.evidence_id,
            "before_snapshot_ref": self.before_snapshot_ref,
            "after_snapshot_ref": self.after_snapshot_ref,
            "before_snapshot_hash": self.before_snapshot_hash,
            "after_snapshot_hash": self.after_snapshot_hash,
            "target_identity": dict(self.target_identity) if isinstance(self.target_identity, dict) else None,
            "backend_type": self.backend_type,
            "provenance_class": self.provenance_class,
            "function_attribution_verified": self.function_attribution_verified,
            "attribution_basis": self.attribution_basis,
            "attribution_limitation": self.attribution_limitation,
            "verified_claims": list(self.verified_claims),
            "executed_at": self.executed_at,
            "receipt_signature": self.receipt_signature,
            "signature_version": getattr(self, "signature_version", "v2_rfc8785"),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ControlledExecutionResult":
        """Reconstruct ControlledExecutionResult from dictionary.
        
        Legacy migration policy:
        - If 'signature_version' is present, it is preserved ('v2_rfc8785', 'v1_legacy', etc.).
        - If 'signature_version' is missing or empty (historical record), it is marked
          as 'v1_legacy_unversioned' so that it can only be verified via explicit legacy policy
          and cannot be confused with modern v2 receipts.
        """
        if not isinstance(data, dict):
            raise TypeError(f"Expected dict for ControlledExecutionResult, got {type(data).__name__}")
        allowed = cls.__dataclass_fields__.keys()
        filtered = {k: v for k, v in data.items() if k in allowed}
        if "signature_version" not in filtered or not filtered["signature_version"]:
            filtered["signature_version"] = "v1_legacy_unversioned"
        if "verified_claims" in filtered and filtered["verified_claims"] is not None:
            filtered["verified_claims"] = tuple(filtered["verified_claims"])
        return cls(**filtered)


def migrate_legacy_execution_result(
    result: "ControlledExecutionResult",
    session_secret: str,
) -> "ControlledExecutionResult":
    """Migrate a legitimate historical legacy execution receipt to RFC 8785 v2 format.

    Validates historical authenticity using legacy v1 verification. If authentic,
    re-signs the structured payload using RFC 8785 JCS HMAC-SHA256 and sets
    signature_version='v2_rfc8785'. If unauthentic or tampered, raises ValueError.
    """
    if not result.verify_authenticity(session_secret, allow_legacy=True):
        raise ValueError(
            f"Cannot migrate legacy execution receipt '{result.execution_id}': authenticity verification failed"
        )
    res_temp = ControlledExecutionResult(
        execution_id=result.execution_id,
        investigation_id=result.investigation_id,
        target_function=result.target_function,
        field_path=result.field_path,
        before_value=result.before_value,
        after_value=result.after_value,
        execution_status=result.execution_status,
        capture_quality=dict(result.capture_quality) if isinstance(result.capture_quality, dict) else {},
        target_identity=dict(result.target_identity) if isinstance(result.target_identity, dict) else None,
        hypothesis_id=result.hypothesis_id,
        evidence_id=result.evidence_id,
        before_snapshot_ref=result.before_snapshot_ref,
        after_snapshot_ref=result.after_snapshot_ref,
        before_snapshot_hash=result.before_snapshot_hash,
        after_snapshot_hash=result.after_snapshot_hash,
        backend_type=result.backend_type,
        provenance_class=result.provenance_class,
        function_attribution_verified=result.function_attribution_verified,
        attribution_basis=result.attribution_basis,
        attribution_limitation=result.attribution_limitation,
        verified_claims=result.verified_claims,
        executed_at=result.executed_at,
        receipt_signature="",
        signature_version="v2_rfc8785",
    )
    sig_v2 = compute_receipt_signature(session_secret, res_temp)
    return ControlledExecutionResult(
        execution_id=res_temp.execution_id,
        investigation_id=res_temp.investigation_id,
        target_function=res_temp.target_function,
        field_path=res_temp.field_path,
        before_value=res_temp.before_value,
        after_value=res_temp.after_value,
        execution_status=res_temp.execution_status,
        capture_quality=res_temp.capture_quality,
        target_identity=res_temp.target_identity,
        hypothesis_id=res_temp.hypothesis_id,
        evidence_id=res_temp.evidence_id,
        before_snapshot_ref=res_temp.before_snapshot_ref,
        after_snapshot_ref=res_temp.after_snapshot_ref,
        before_snapshot_hash=res_temp.before_snapshot_hash,
        after_snapshot_hash=res_temp.after_snapshot_hash,
        backend_type=res_temp.backend_type,
        provenance_class=res_temp.provenance_class,
        function_attribution_verified=res_temp.function_attribution_verified,
        attribution_basis=res_temp.attribution_basis,
        attribution_limitation=res_temp.attribution_limitation,
        verified_claims=res_temp.verified_claims,
        executed_at=res_temp.executed_at,
        receipt_signature=sig_v2,
        signature_version="v2_rfc8785",
    )


def strip_sensitive_session_secrets(obj: Any) -> Any:
    """Recursively strip raw session secrets and bearer tokens from data structures.

    Targeted specifically to prevent leaking raw session secrets and raw bearer tokens
    through nested dictionary or list structures, without removing legitimate fields.
    """
    if isinstance(obj, dict):
        cleaned = {}
        for k, v in obj.items():
            if k in ("session_secret", "_session_secret", "raw_session_secret"):
                continue
            if k == "token" and isinstance(v, str) and len(v) in (32, 64):
                # Raw token hex in verifier_attestation
                continue
            cleaned[k] = strip_sensitive_session_secrets(v)
        return cleaned
    elif isinstance(obj, list):
        return [strip_sensitive_session_secrets(elem) for elem in obj]
    elif isinstance(obj, tuple):
        return tuple(strip_sensitive_session_secrets(elem) for elem in obj)
    return obj


def canonicalize_receipt_value(val: Any) -> str:
    """Canonicalize values using RFC 8785 canonical JSON string.
    
    Fails closed: does not silently convert uncanonicalizable values or fallback to str().
    """
    return rfc8785_canonical_str(val)


def compute_controlled_execution_payload(result: "ControlledExecutionResult", version: str = "v2_rfc8785") -> Dict[str, Any]:
    """Construct an unambiguous structured payload containing all security-relevant fields for signing."""
    tid = dict(result.target_identity or {})
    cq = dict(result.capture_quality or {})
    prov_cls = getattr(result, "provenance_class", PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION)
    attr_ver = getattr(result, "is_function_attribution_verified", getattr(result, "function_attribution_verified", False))
    attr_basis = getattr(result, "attribution_basis", "")
    claims = list(sorted(getattr(result, "verified_claims", ()) or ()))

    return {
        "version": version,
        "execution_id": str(result.execution_id),
        "investigation_id": str(result.investigation_id),
        "hypothesis_id": str(result.hypothesis_id or ""),
        "evidence_id": str(result.evidence_id or ""),
        "target_function": str(result.target_function),
        "field_path": str(result.field_path),
        "before_value": result.before_value,
        "after_value": result.after_value,
        "execution_status": str(result.execution_status),
        "backend_type": str(result.backend_type),
        "provenance_class": str(prov_cls),
        "function_attribution_verified": bool(attr_ver),
        "attribution_basis": str(attr_basis),
        "verified_claims": claims,
        "before_snapshot_ref": result.before_snapshot_ref,
        "after_snapshot_ref": result.after_snapshot_ref,
        "before_snapshot_hash": result.before_snapshot_hash,
        "after_snapshot_hash": result.after_snapshot_hash,
        "target_identity": tid,
        "capture_quality": cq,
        "executed_at": str(result.executed_at),
    }


def compute_receipt_signature(session_secret: str, result: "ControlledExecutionResult") -> str:
    """Compute HMAC-SHA256 signature over RFC 8785 canonical JSON bytes of the structured payload."""
    payload = compute_controlled_execution_payload(result, version="v2_rfc8785")
    canonical_bytes = rfc8785_canonical_json(payload)
    return hmac.new(session_secret.encode("utf-8"), canonical_bytes, hashlib.sha256).hexdigest()


def compute_legacy_receipt_signature(session_secret: str, result: "ControlledExecutionResult") -> str:
    """Legacy v1 delimiter-concatenation signature for backward-compatibility verification only."""
    tid_str = json.dumps(result.target_identity or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    cq_str = json.dumps(result.capture_quality or {}, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    before_str = canonicalize_receipt_value(result.before_value)
    after_str = canonicalize_receipt_value(result.after_value)
    prov_cls = getattr(result, "provenance_class", PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION)
    attr_ver = getattr(result, "is_function_attribution_verified", getattr(result, "function_attribution_verified", False))
    attr_basis = getattr(result, "attribution_basis", "")
    claims_str = ",".join(sorted(getattr(result, "verified_claims", ()) or ()))
    raw = (
        f"{result.execution_id}|{result.investigation_id}|{result.hypothesis_id}|"
        f"{result.evidence_id}|{result.target_function}|{result.field_path}|"
        f"{before_str}|{after_str}|{result.execution_status}|"
        f"{result.backend_type}|{prov_cls}|{attr_ver}|{attr_basis}|{claims_str}|"
        f"{result.before_snapshot_ref}|{result.after_snapshot_ref}|"
        f"{result.before_snapshot_hash}|{result.after_snapshot_hash}|"
        f"{tid_str}|{cq_str}|{result.executed_at}"
    )
    return hmac.new(session_secret.encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).hexdigest()


def validate_controlled_execution_target_identity(
    expected_tid: Optional[Dict[str, Any]],
    receipt_tid: Optional[Dict[str, Any]],
) -> Tuple[bool, str]:
    """Validate target identity binding between expected identity and execution receipt.

    Enforces required fields: pid, process_identity, executable_identity, and build_id.
    Fails closed on missing fields, empty strings, or mismatches.
    Explicit Build ID semantics:
    - If neither expected nor receipt provides a build_id (both empty/None), target genuinely lacks ELF build_id (allowed).
    - If one side has build_id but the other lacks it, or both have different non-empty values -> fail closed.
    """
    if not expected_tid or not isinstance(expected_tid, dict):
        return False, "Target identity validation failed: missing or invalid expected target_identity"
    if not receipt_tid or not isinstance(receipt_tid, dict):
        return False, "Target identity validation failed: missing or invalid receipt target_identity"

    # 1. PID
    exp_pid = expected_tid.get("pid")
    rcpt_pid = receipt_tid.get("pid")
    if exp_pid is None or rcpt_pid is None or isinstance(exp_pid, bool) or isinstance(rcpt_pid, bool):
        return False, f"Target identity validation failed: PID missing or boolean (expected={exp_pid}, receipt={rcpt_pid})"
    try:
        if int(exp_pid) != int(rcpt_pid) or int(exp_pid) <= 0:
            return False, f"Target identity validation failed: PID mismatch or non-positive (expected={exp_pid}, receipt={rcpt_pid})"
    except (ValueError, TypeError):
        return False, f"Target identity validation failed: PID non-integer (expected={exp_pid}, receipt={rcpt_pid})"

    # 2. Process identity
    exp_proc = str(expected_tid.get("process_identity") or "").strip()
    rcpt_proc = str(receipt_tid.get("process_identity") or "").strip()
    if not exp_proc or not rcpt_proc:
        return False, f"Target identity validation failed: process_identity missing (expected='{exp_proc}', receipt='{rcpt_proc}')"
    if exp_proc != rcpt_proc:
        return False, f"Target identity validation failed: process_identity mismatch (expected='{exp_proc}', receipt='{rcpt_proc}')"

    # 3. Executable identity
    exp_exe = str(expected_tid.get("executable_identity") or expected_tid.get("executable") or expected_tid.get("binary_path") or "").strip()
    rcpt_exe = str(receipt_tid.get("executable_identity") or receipt_tid.get("executable") or receipt_tid.get("binary_path") or "").strip()
    if not exp_exe or not rcpt_exe:
        return False, f"Target identity validation failed: executable_identity missing (expected='{exp_exe}', receipt='{rcpt_exe}')"
    if exp_exe != rcpt_exe:
        return False, f"Target identity validation failed: executable_identity mismatch (expected='{exp_exe}', receipt='{rcpt_exe}')"

    # 4. Build ID
    exp_bid = str(expected_tid.get("build_id") or expected_tid.get("target_build_id") or "").strip().lower()
    rcpt_bid = str(receipt_tid.get("build_id") or receipt_tid.get("target_build_id") or "").strip().lower()
    if exp_bid and not rcpt_bid:
        return False, f"Target identity validation failed: receipt missing build_id when expected='{exp_bid}'"
    if rcpt_bid and not exp_bid:
        return False, f"Target identity validation failed: expected identity missing build_id when receipt='{rcpt_bid}'"
    if exp_bid and rcpt_bid and exp_bid != rcpt_bid:
        return False, f"Target identity validation failed: build_id mismatch (expected='{exp_bid}', receipt='{rcpt_bid}')"

    return True, "Target identity successfully verified"


def is_atomic_or_stopped_consistency(cons: Any) -> bool:
    """Check if consistency level represents atomic or stopped execution."""
    if not cons:
        return False
    u = str(cons).upper()
    if "NON_ATOMIC" in u or "NON-ATOMIC" in u or "INCONSISTENT" in u:
        return False
    return u in ("STOPPED", "ATOMIC", "CONSISTENT", "PROCESS_STOPPED_MEMORY_SNAPSHOT", "SIGNAL_STOPPED") or "STOPPED" in u or "ATOMIC" in u or "CONSISTENT" in u


class CausalVerificationCapability:
    """Internal single-use capability token granting authority to attest causal proof.

    Can only be minted by TrustedCausalVerifier within an active InvestigationSession
    after independent verification of an authentic execution result.
    Cannot be serialized, constructed by external callers, or reused across investigations/records.
    """
    def __init__(
        self,
        investigation_id: str,
        capability_key: str,
        evidence_id: str,
        target_function: str,
        field_path: str,
        hypothesis_id: str,
        provenance_class: str = PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
        function_attribution_verified: bool = False,
        attribution_basis: str = "",
        verified_claims: Tuple[str, ...] = (),
        attribution_limitation: str = "",
    ):
        self._investigation_id = investigation_id
        self._capability_key = capability_key
        self._evidence_id = evidence_id
        self._target_function = target_function
        self._field_path = field_path
        self._hypothesis_id = hypothesis_id
        self._provenance_class = provenance_class
        self._function_attribution_verified = function_attribution_verified
        self._attribution_basis = attribution_basis
        self._verified_claims = tuple(sorted(verified_claims or ()))
        self._attribution_limitation = attribution_limitation
        self._consumed = False

    def is_valid_for(
        self,
        ledger_or_session: Any,
        evidence_id: str,
        target_function: Optional[str] = None,
        field_path: Optional[str] = None,
        hypothesis_id: Optional[str] = None,
    ) -> bool:
        if self._consumed:
            return False
        inv_id = getattr(ledger_or_session, "investigation_id", None) or getattr(ledger_or_session, "session_id", None)
        key = getattr(ledger_or_session, "_capability_key", None)
        if not key or self._capability_key != key or inv_id != self._investigation_id:
            return False
        if self._evidence_id and str(evidence_id or "").strip() != str(self._evidence_id).strip():
            return False
        if target_function and self._target_function and str(target_function).strip() != str(self._target_function).strip():
            return False
        if field_path and self._field_path and str(field_path).strip() != str(self._field_path).strip():
            return False
        if hypothesis_id is not None:
            eff_h = str(hypothesis_id).strip()
            cap_h = str(self._hypothesis_id or "").strip()
            if eff_h != cap_h:
                return False
        return True

    def consume(self) -> None:
        if self._consumed:
            raise RuntimeError("CausalVerificationCapability has already been consumed")
        self._consumed = True

    @property
    def is_consumed(self) -> bool:
        return self._consumed

    @property
    def hypothesis_id(self) -> str:
        return self._hypothesis_id

    @property
    def target_function(self) -> str:
        return self._target_function

    @property
    def attribution_limitation(self) -> str:
        return self._attribution_limitation

    @property
    def field_path(self) -> str:
        return self._field_path

    @property
    def evidence_id(self) -> str:
        return self._evidence_id

    @property
    def provenance_class(self) -> str:
        return self._provenance_class

    @property
    def function_attribution_verified(self) -> bool:
        return self._function_attribution_verified

    @property
    def attribution_basis(self) -> str:
        return self._attribution_basis

    @property
    def verified_claims(self) -> Tuple[str, ...]:
        return self._verified_claims

    def __repr__(self) -> str:
        return (
            f"<CausalVerificationCapability inv={self._investigation_id!r} "
            f"ev={self._evidence_id!r} fn={self._target_function!r} "
            f"field={self._field_path!r} consumed={self._consumed}>"
        )

    def __str__(self) -> str:
        return self.__repr__()


def normalize_path_tokens(path: str) -> List[str]:
    """Tokenize dot-separated or bracket-indexed paths into canonical lowercase segments."""
    if not path:
        return []
    s = re.sub(r"\[(\d+)\]", r".\1", path.strip())
    return [p.lower() for p in s.split(".") if p]


def is_exact_semantic_path_match(
    diff_path: str,
    diff_field: str,
    target_path: str,
    obj_id: Optional[str] = None,
    target_obj_id: Optional[str] = None,
    obj_type: Optional[str] = None,
) -> bool:
    """Compare intended field path using exact semantic path matching on dot boundaries.

    Prevents loose substring and suffix cross-object collisions
    (e.g., 'ThreadCounter.counter' matching 'State.counter').
    Supports object identity disambiguation and array index normalization.
    """
    if not target_path:
        return False

    if target_obj_id and obj_id and target_obj_id != obj_id:
        return False

    dp = (diff_path or "").strip()
    df = (diff_field or "").strip()
    tp = target_path.strip()

    if dp == tp or (df and df == tp):
        return True

    full_candidates = [dp]
    if df and not dp.endswith(f".{df}") and dp != df:
        full_candidates.append(f"{dp}.{df}")
    if df and df != dp:
        full_candidates.append(df)
    if obj_id:
        if df:
            full_candidates.append(f"{obj_id}.{df}")
        if dp:
            full_candidates.append(f"{obj_id}.{dp}")
    if obj_type and df:
        full_candidates.append(f"{obj_type}.{df}")

    t_tokens = normalize_path_tokens(tp)
    if not t_tokens:
        return False

    for cand in full_candidates:
        c_tokens = normalize_path_tokens(cand)
        if not c_tokens:
            continue
        if len(t_tokens) > 1:
            if len(c_tokens) >= len(t_tokens) and c_tokens[-len(t_tokens):] == t_tokens:
                return True
        else:
            if c_tokens[-1] == t_tokens[0]:
                return True
    return False


def find_matching_diff_changes(
    changes: List[Dict[str, Any]],
    target_field_path: str,
    target_obj_id: Optional[str] = None,
) -> Tuple[List[Dict[str, Any]], Optional[str]]:
    """Find changes matching target_field_path, detecting cross-object ambiguity.

    Returns: (matching_changes, ambiguity_error_message)
    """
    matches = []
    for chg in changes:
        p = chg.get("path") or ""
        f = chg.get("field") or ""
        oid = chg.get("object_id")
        otype = chg.get("type")
        if is_exact_semantic_path_match(
            diff_path=p,
            diff_field=f,
            target_path=target_field_path,
            obj_id=oid,
            target_obj_id=target_obj_id,
            obj_type=otype,
        ):
            matches.append(chg)

    if not matches:
        return [], None

    # Check for ambiguity: multiple changes across distinct object instances
    distinct_objects = set()
    for m in matches:
        key = m.get("object_id") or m.get("address") or m.get("type") or id(m)
        distinct_objects.add(key)

    if len(distinct_objects) > 1 and not target_obj_id:
        obj_names = sorted(str(k) for k in distinct_objects)
        return matches, (
            f"Ambiguous field path match: multiple changes match '{target_field_path}' "
            f"across {len(distinct_objects)} distinct objects ({obj_names}); specify object ID to disambiguate"
        )

    return matches, None


def compute_evidence_fingerprint(
    record: "EvidenceRecord",
    target_function: Optional[str] = None,
    field_path: Optional[str] = None,
    hypothesis_id: Optional[str] = None,
    target_identity: Optional[Dict[str, Any]] = None,
    provenance_class: Optional[str] = None,
    function_attribution_verified: Optional[bool] = None,
    attribution_basis: Optional[str] = None,
    verified_claims: Optional[Union[Tuple[str, ...], List[str], Set[str]]] = None,
) -> str:
    """Compute a deterministic SHA256 digest sealing content, scope, hypothesis, target identity, quality, and ancestry."""
    p_details = record.details or {}
    p_prov = record.provenance or {}
    att = p_prov.get("verifier_attestation") or {}

    fn = target_function or att.get("target_function") or p_details.get("target_function") or ""
    fld = field_path or att.get("field_path") or p_details.get("field_path") or ""
    hypo = hypothesis_id or att.get("hypothesis_id") or ""

    t_id = target_identity or att.get("target_identity") or record.target_identity or {}
    t_id_str = f"{t_id.get('pid')}:{t_id.get('build_id')}:{t_id.get('binary_path')}" if t_id else ""
    rec_t_id = record.target_identity or {}
    rec_t_id_str = f"{rec_t_id.get('pid')}:{rec_t_id.get('build_id')}:{rec_t_id.get('binary_path')}" if rec_t_id else ""

    cq = record.capture_quality or {}
    cq_str = f"{cq.get('completeness')}:{cq.get('consistency_level')}"
    parents_str = ",".join(sorted(record.parent_evidence_ids or []))
    snap_str = str(record.snapshot_ref or "")

    prov_cls = provenance_class or att.get("provenance_class") or p_prov.get("provenance_class") or p_details.get("provenance_class") or ""
    if function_attribution_verified is not None:
        attr_ver = str(function_attribution_verified)
    else:
        attr_ver = str(att.get("function_attribution_verified", p_details.get("function_attribution_verified", False)))
    if attribution_basis is not None:
        attr_basis = str(attribution_basis)
    else:
        attr_basis = str(att.get("attribution_basis", p_details.get("attribution_basis", "")))

    if verified_claims is not None:
        claims_str = ",".join(sorted(verified_claims))
    else:
        claims_str = ",".join(sorted(att.get("verified_claims", p_details.get("verified_claims", []))))

    raw = (
        f"{record.evidence_id}|{record.observation}|{fld}|{fn}|"
        f"{hypo}|{t_id_str}|{rec_t_id_str}|{snap_str}|"
        f"{parents_str}|{cq_str}|{prov_cls}|{attr_ver}|{attr_basis}|{claims_str}|{record.session_id}"
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def compute_attestation_signature(
    session_secret: str,
    evidence_id: str,
    fingerprint: str,
    investigation_id: str,
) -> str:
    """Compute an HMAC-SHA256 signature binding the session secret, record ID, fingerprint, and investigation ID."""
    msg = f"{investigation_id}:{evidence_id}:{fingerprint}"
    return hmac.new(session_secret.encode("utf-8"), msg.encode("utf-8"), hashlib.sha256).hexdigest()


EVIDENCE_SCHEMA_VERSION = "1.0.0"

# Evidence Types
EVIDENCE_TYPE_RUNTIME_IDENTITY = "RUNTIME_IDENTITY"
EVIDENCE_TYPE_CAPTURE_QUALITY = "CAPTURE_QUALITY"
EVIDENCE_TYPE_OBJECT_STATE = "OBJECT_STATE"
EVIDENCE_TYPE_FIELD_OBSERVATION = "FIELD_OBSERVATION"
EVIDENCE_TYPE_COMPARISON = "COMPARISON"
EVIDENCE_TYPE_STATIC_LINK = "STATIC_LINK"
EVIDENCE_TYPE_HYPOTHESIS = "HYPOTHESIS"
EVIDENCE_TYPE_INFERENCE = "INFERENCE"
EVIDENCE_TYPE_DIAGNOSTIC = "DIAGNOSTIC"

VALID_EVIDENCE_TYPES = {
    EVIDENCE_TYPE_RUNTIME_IDENTITY,
    EVIDENCE_TYPE_CAPTURE_QUALITY,
    EVIDENCE_TYPE_OBJECT_STATE,
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EVIDENCE_TYPE_COMPARISON,
    EVIDENCE_TYPE_STATIC_LINK,
    EVIDENCE_TYPE_HYPOTHESIS,
    EVIDENCE_TYPE_INFERENCE,
    EVIDENCE_TYPE_DIAGNOSTIC,
}

DIAGNOSTIC_EVIDENCE_TYPES = {
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EVIDENCE_TYPE_OBJECT_STATE,
    EVIDENCE_TYPE_COMPARISON,
    EVIDENCE_TYPE_DIAGNOSTIC,
}

ALLOWED_PRIMARY_OPERATION_EVIDENCE_TYPES = {
    EVIDENCE_TYPE_OBJECT_STATE,
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EVIDENCE_TYPE_RUNTIME_IDENTITY,
    EVIDENCE_TYPE_CAPTURE_QUALITY,
    EVIDENCE_TYPE_DIAGNOSTIC,
}

ALLOWED_DERIVED_OPERATION_EVIDENCE_TYPES = {
    EVIDENCE_TYPE_OBJECT_STATE,
    EVIDENCE_TYPE_FIELD_OBSERVATION,
    EVIDENCE_TYPE_COMPARISON,
    EVIDENCE_TYPE_INFERENCE,
    EVIDENCE_TYPE_DIAGNOSTIC,
}

# Nature classification: direct observation vs inference
NATURE_OBSERVATION = "observation"
NATURE_INFERENCE = "inference"
NATURE_HYPOTHESIS = "hypothesis"

VALID_NATURES = {NATURE_OBSERVATION, NATURE_INFERENCE, NATURE_HYPOTHESIS}


@dataclass
class EvidenceRecord:
    """Individual machine-readable evidence entry with full provenance."""
    evidence_id: Optional[str] = None
    evidence_type: str = EVIDENCE_TYPE_OBJECT_STATE
    nature: str = NATURE_OBSERVATION  # "observation", "inference", or "hypothesis"
    source: str = "runtime_collector"  # e.g., "raw_snapshot", "offline_analyzer", "dwarf", "static_provider", "state_diff"
    timestamp: str = ""
    session_id: Optional[str] = None
    finding_id: Optional[str] = None
    observation: str = ""
    parent_evidence_ids: List[str] = field(default_factory=list)

    # Provenance details
    provenance: Dict[str, Any] = field(default_factory=dict)

    # Specific evidence categories (all optional for schema flexibility and backward compatibility)
    target_identity: Optional[Dict[str, Any]] = None
    snapshot_ref: Optional[Dict[str, Any]] = None
    capture_quality: Optional[Dict[str, Any]] = None
    object_observation: Optional[Dict[str, Any]] = None
    field_observation: Optional[Dict[str, Any]] = None
    static_code_link: Optional[Dict[str, Any]] = None
    comparison_observation: Optional[Dict[str, Any]] = None
    uncertainty: Optional[str] = None
    details: Dict[str, Any] = field(default_factory=dict)
    schema_version: str = EVIDENCE_SCHEMA_VERSION

    def __post_init__(self):
        if self.evidence_id is not None:
            if not isinstance(self.evidence_id, str) or not self.evidence_id.strip():
                raise ValueError("evidence_id must be a non-empty string")
        else:
            self.evidence_id = f"ev_{uuid.uuid4().hex[:12]}"

        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if not isinstance(self.evidence_type, str) or not self.evidence_type.strip():
            raise ValueError("evidence_type must be a non-empty string")
        if self.evidence_type not in VALID_EVIDENCE_TYPES:
            raise ValueError(f"Invalid evidence_type '{self.evidence_type}'. Expected one of {sorted(VALID_EVIDENCE_TYPES)}")
        if self.nature not in VALID_NATURES:
            raise ValueError(f"Invalid evidence nature '{self.nature}'. Expected one of {sorted(VALID_NATURES)}")
        if self.session_id is not None and (not isinstance(self.session_id, str) or not self.session_id.strip()):
            raise ValueError("session_id must be a non-empty string when provided")
        if self.finding_id is not None and (not isinstance(self.finding_id, str) or not self.finding_id.strip()):
            raise ValueError("finding_id must be a non-empty string when provided")
        if not isinstance(self.parent_evidence_ids, (list, tuple)):
            raise TypeError("parent_evidence_ids must be a list of strings")
        for pid in self.parent_evidence_ids:
            if not isinstance(pid, str) or not pid.strip():
                raise ValueError(f"Invalid parent_evidence_id '{pid}' in parent_evidence_ids")
        if self.evidence_id in self.parent_evidence_ids:
            raise ValueError(f"Self-reference detected: record cannot have its own evidence_id '{self.evidence_id}' as a parent")

    @property
    def summary(self) -> str:
        return self.observation

    @summary.setter
    def summary(self, val: str) -> None:
        self.observation = val

    @property
    def provenance_class(self) -> str:
        if isinstance(self.provenance, dict) and self.provenance.get("provenance_class"):
            return str(self.provenance["provenance_class"])
        if isinstance(self.details, dict) and self.details.get("provenance_class"):
            return str(self.details["provenance_class"])
        return PROVENANCE_CLASS_IMPORTED_UNVERIFIED

    @property
    def attribution_level(self) -> str:
        if isinstance(self.details, dict) and self.details.get("attribution_level"):
            return str(self.details["attribution_level"])
        basis = None
        if isinstance(self.provenance, dict):
            basis = self.provenance.get("attribution_basis")
        if not basis and isinstance(self.details, dict):
            basis = self.details.get("attribution_basis")
        if basis == ATTRIBUTION_BASIS_SINGLE_WRITER and self.provenance_class in TRUSTED_PROVENANCE_CLASSES:
            return "CONFIRMED"
        return "SUSPECTED"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to JSON-serializable dictionary without None values for optional fields."""
        prov_copy = strip_sensitive_session_secrets(dict(self.provenance)) if self.provenance else {}
        if "verifier_attestation" in prov_copy and isinstance(prov_copy["verifier_attestation"], dict):
            safe_att = dict(prov_copy["verifier_attestation"])
            safe_att.pop("token", None)
            prov_copy["verifier_attestation"] = safe_att
        if "live_capture_receipt" in prov_copy and hasattr(prov_copy["live_capture_receipt"], "to_dict"):
            prov_copy["live_capture_receipt"] = prov_copy["live_capture_receipt"].to_dict()

        details_copy = strip_sensitive_session_secrets(dict(self.details)) if self.details else {}
        if "live_capture_receipt" in details_copy and hasattr(details_copy["live_capture_receipt"], "to_dict"):
            details_copy["live_capture_receipt"] = details_copy["live_capture_receipt"].to_dict()

        obs_copy = strip_sensitive_session_secrets(self.observation) if isinstance(self.observation, (dict, list)) else self.observation

        data: Dict[str, Any] = {
            "evidence_id": self.evidence_id,
            "evidence_type": self.evidence_type,
            "nature": self.nature,
            "source": self.source,
            "timestamp": self.timestamp,
            "observation": obs_copy,
            "parent_evidence_ids": list(self.parent_evidence_ids),
            "schema_version": self.schema_version,
            "provenance": prov_copy,
            "details": details_copy,
        }
        if self.session_id is not None:
            data["session_id"] = self.session_id
        if self.finding_id is not None:
            data["finding_id"] = self.finding_id
        if self.target_identity is not None:
            data["target_identity"] = self.target_identity
        if self.snapshot_ref is not None:
            data["snapshot_ref"] = self.snapshot_ref
        if self.capture_quality is not None:
            data["capture_quality"] = self.capture_quality
        if self.object_observation is not None:
            data["object_observation"] = self.object_observation
        if self.field_observation is not None:
            data["field_observation"] = self.field_observation
        if self.static_code_link is not None:
            data["static_code_link"] = self.static_code_link
        if self.comparison_observation is not None:
            data["comparison_observation"] = self.comparison_observation
        if self.uncertainty is not None:
            data["uncertainty"] = self.uncertainty
        return data

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvidenceRecord":
        """Deserialize from dictionary, maintaining backward compatibility with missing fields."""
        eid = data.get("evidence_id")
        if "evidence_id" in data and eid is not None:
            if not isinstance(eid, str) or not eid.strip():
                raise ValueError("evidence_id in data must be a non-empty string")
        elif eid is None:
            eid = f"ev_{uuid.uuid4().hex[:12]}"

        # Normalize evidence_type for legacy compatibility
        etype = data.get("evidence_type", EVIDENCE_TYPE_OBJECT_STATE)
        if isinstance(etype, str) and etype.upper() in VALID_EVIDENCE_TYPES:
            etype = etype.upper()
        elif etype not in VALID_EVIDENCE_TYPES:
            raise ValueError(f"Invalid evidence_type '{etype}'. Expected one of {sorted(VALID_EVIDENCE_TYPES)}")

        # Normalize nature for legacy compatibility
        nat = data.get("nature", NATURE_OBSERVATION)
        if isinstance(nat, str) and nat.lower() in VALID_NATURES:
            nat = nat.lower()
        elif nat not in VALID_NATURES:
            raise ValueError(f"Invalid nature '{nat}'. Expected one of {sorted(VALID_NATURES)}")

        parent_ids = data.get("parent_evidence_ids")
        if parent_ids is None:
            prov = data.get("provenance", {})
            if isinstance(prov, dict):
                parent_ids = prov.get("parent_evidence_ids", [])
            else:
                parent_ids = []
        elif not isinstance(parent_ids, (list, tuple)):
            raise TypeError("parent_evidence_ids must be a list or tuple of strings")

        # Validate dictionary fields if provided
        for field_name in [
            "snapshot_ref", "target_identity", "capture_quality",
            "object_observation", "field_observation", "static_code_link",
            "comparison_observation", "provenance", "details"
        ]:
            if field_name in data and data[field_name] is not None and not isinstance(data[field_name], dict):
                raise TypeError(f"Field '{field_name}' must be a dictionary when provided, got {type(data[field_name]).__name__}")

        obs_val = data.get("observation") or data.get("summary") or ""
        details_val = dict(data.get("details", {}))
        if "contradicts_hypothesis_id" in data and "contradicts_hypothesis_id" not in details_val:
            details_val["contradicts_hypothesis_id"] = data["contradicts_hypothesis_id"]

        return cls(
            evidence_id=eid,
            evidence_type=etype,
            nature=nat,
            source=data.get("source", "unknown"),
            timestamp=data.get("timestamp", ""),
            session_id=data.get("session_id"),
            finding_id=data.get("finding_id"),
            observation=obs_val,
            parent_evidence_ids=list(parent_ids or []),
            provenance=data.get("provenance", {}),
            target_identity=data.get("target_identity"),
            snapshot_ref=data.get("snapshot_ref"),
            capture_quality=data.get("capture_quality"),
            object_observation=data.get("object_observation"),
            field_observation=data.get("field_observation"),
            static_code_link=data.get("static_code_link"),
            comparison_observation=data.get("comparison_observation"),
            uncertainty=data.get("uncertainty"),
            details=details_val,
            schema_version=data.get("schema_version", EVIDENCE_SCHEMA_VERSION),
        )


class EvidenceLedger:
    """Versioned container and query index for evidence records within an investigation."""

    def __init__(
        self,
        session_id: Optional[str] = None,
        schema_version: str = EVIDENCE_SCHEMA_VERSION,
        session_secret: Optional[str] = None,
        capability_key: Optional[str] = None,
        trust_store: Optional[Any] = None,
    ):
        self.session_id: str = session_id or f"inv_sess_{uuid.uuid4().hex[:8]}"
        self.schema_version: str = schema_version
        self.session_secret: str = session_secret or uuid.uuid4().hex
        self._capability_key: str = capability_key or uuid.uuid4().hex
        self.created_at: str = datetime.now(timezone.utc).isoformat()
        self._records: List[EvidenceRecord] = []
        self._by_id: Dict[str, EvidenceRecord] = {}
        self._by_type: Dict[str, List[EvidenceRecord]] = {}
        self._by_finding: Dict[str, List[EvidenceRecord]] = {}
        if trust_store is not None:
            self.trust_store = trust_store
        else:
            try:
                from .capture_backend import get_default_trust_store
                self.trust_store = get_default_trust_store()
            except ImportError:
                self.trust_store = None
        self._used_causal_attestation_ids: Set[str] = set()
        self._causal_attestation_to_evidence_id: Dict[str, str] = {}
        self._used_execution_ids: Set[str] = set()
        self._execution_to_evidence_id: Dict[str, str] = {}
        self._used_operation_ids: Dict[str, Dict[str, Any]] = {}
        self._operation_to_evidence_ids: Dict[str, List[str]] = {}
        self._operation_to_receipt_id: Dict[str, str] = {}
        self._lock: threading.RLock = threading.RLock()

    def remove_record(self, evidence_id: str) -> Optional[EvidenceRecord]:
        """Remove a record from the ledger (e.g. for rollback on attestation failure)."""
        with self._lock:
            rec = self._by_id.pop(evidence_id, None)
            if rec:
                if rec in self._records:
                    self._records.remove(rec)
                if rec.evidence_type in self._by_type and rec in self._by_type[rec.evidence_type]:
                    self._by_type[rec.evidence_type].remove(rec)
                if rec.finding_id and rec.finding_id in self._by_finding and rec in self._by_finding[rec.finding_id]:
                    self._by_finding[rec.finding_id].remove(rec)
            return rec

    @property
    def capability_key(self) -> str:
        return self._capability_key

    @property
    def records(self) -> List[EvidenceRecord]:
        with self._lock:
            return list(self._records)

    def record_evidence(
        self,
        module_id: str,
        domain: str = "GENERIC",
        provenance_class: str = PROVENANCE_CLASS_IMPORTED_UNVERIFIED,
        attribution_basis: Optional[str] = None,
        evidence_payload: Optional[Dict[str, Any]] = None,
        nature: str = NATURE_OBSERVATION,
        observation: Optional[str] = None,
    ) -> EvidenceRecord:
        """Records an observation with explicit provenance class and causal attribution level."""
        attr_level = (
            "CONFIRMED"
            if (attribution_basis == ATTRIBUTION_BASIS_SINGLE_WRITER and provenance_class in TRUSTED_PROVENANCE_CLASSES)
            else "SUSPECTED"
        )
        details = dict(evidence_payload or {})
        details.update({
            "module_id": module_id,
            "domain": domain,
            "provenance_class": provenance_class,
            "attribution_basis": attribution_basis,
            "attribution_level": attr_level,
        })
        rec = EvidenceRecord(
            evidence_id=f"ev_{uuid.uuid4().hex[:10]}",
            evidence_type=EVIDENCE_TYPE_DIAGNOSTIC,
            nature=nature,
            source=module_id,
            session_id=self.session_id,
            observation=observation or f"Evidence from {module_id} ({domain})",
            provenance={
                "provenance_class": provenance_class,
                "attribution_basis": attribution_basis,
                "module_id": module_id,
            },
            details=details,
        )
        return self.add_record(rec)

    def issue_verification_capability(
        self,
        evidence_id: str = "",
        target_function: str = "",
        field_path: str = "",
        hypothesis_id: Optional[str] = None,
        execution_result: Optional[ControlledExecutionResult] = None,
    ) -> CausalVerificationCapability:
        """Issue an internal unforgeable capability strictly after authentic execution receipt verification."""
        with self._lock:
            if execution_result is None or not isinstance(execution_result, ControlledExecutionResult):
                raise ValueError("Capability issuance requires an authentic ControlledExecutionResult verified against session secret")

            if not execution_result.verify_authenticity(self.session_secret):
                raise ValueError("Capability issuance rejected: execution receipt signature verification failed")

            if execution_result.investigation_id != self.session_id:
                raise ValueError(f"Capability issuance rejected: execution receipt belongs to investigation '{execution_result.investigation_id}', not '{self.session_id}'")

            # Single-use: reject replayed execution receipts
            if execution_result.execution_id in self._used_execution_ids:
                raise ValueError(f"Capability issuance rejected: execution receipt '{execution_result.execution_id}' has already been consumed")

            # Evidence ID scope binding
            eff_eid = str(evidence_id or execution_result.evidence_id or "").strip()
            rcpt_eid = str(execution_result.evidence_id or "").strip()
            if not eff_eid or not rcpt_eid:
                raise ValueError("Capability issuance rejected: evidence_id is required and non-empty")
            if evidence_id and eff_eid != rcpt_eid:
                raise ValueError(f"Capability issuance rejected: execution receipt evidence '{rcpt_eid}' does not match '{evidence_id}'")

            # Target function scope binding
            eff_fn = str(target_function or execution_result.target_function or "").strip()
            rcpt_fn = str(execution_result.target_function or "").strip()
            if not eff_fn or not rcpt_fn:
                raise ValueError("Capability issuance rejected: target_function is required and non-empty")
            if target_function and eff_fn != rcpt_fn:
                raise ValueError(f"Capability issuance rejected: execution receipt target_function '{rcpt_fn}' does not match '{target_function}'")

            # Field path scope binding
            eff_field = str(field_path or execution_result.field_path or "").strip()
            rcpt_field = str(execution_result.field_path or "").strip()
            if not eff_field or not rcpt_field:
                raise ValueError("Capability issuance rejected: field_path is required and non-empty")
            if field_path and eff_field != rcpt_field:
                raise ValueError(f"Capability issuance rejected: execution receipt field_path '{rcpt_field}' does not match '{field_path}'")

            # Hypothesis ID scope binding:
            eff_hypo = str(hypothesis_id if hypothesis_id is not None else (execution_result.hypothesis_id or "")).strip()
            rcpt_hypo = str(execution_result.hypothesis_id or "").strip()
            if hypothesis_id is not None and str(hypothesis_id).strip() != rcpt_hypo:
                raise ValueError(f"Capability issuance rejected: execution receipt hypothesis '{rcpt_hypo}' does not match '{hypothesis_id}'")

            # Target identity validation
            if getattr(self, "target_identity", None):
                ok_tid, tid_reason = validate_controlled_execution_target_identity(self.target_identity, execution_result.target_identity)
                if not ok_tid:
                    raise ValueError(f"Capability issuance rejected: {tid_reason}")

            if execution_result.execution_status not in ("REPRODUCED", "SUCCESS", "CONFIRMED"):
                raise ValueError(f"Capability issuance rejected: execution receipt status '{execution_result.execution_status}' does not prove reproduction")

            cq = execution_result.capture_quality or {}
            comp = cq.get("completeness") or cq.get("status")
            cons = cq.get("consistency_level") or cq.get("consistency_classification")
            if comp != "COMPLETE" or not is_atomic_or_stopped_consistency(cons):
                raise ValueError(f"Capability issuance rejected: execution receipt capture quality ({comp}, {cons}) is not complete and atomic")

            # Consume receipt single-use atomically
            self._used_execution_ids.add(execution_result.execution_id)
            self._execution_to_evidence_id[execution_result.execution_id] = eff_eid

        return CausalVerificationCapability(
            investigation_id=self.session_id,
            capability_key=self._capability_key,
            evidence_id=eff_eid,
            target_function=eff_fn,
            field_path=eff_field,
            hypothesis_id=eff_hypo,
            provenance_class=getattr(execution_result, "provenance_class", PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION),
            function_attribution_verified=getattr(execution_result, "is_function_attribution_verified", getattr(execution_result, "function_attribution_verified", False)),
            attribution_basis=getattr(execution_result, "attribution_basis", ""),
            verified_claims=getattr(execution_result, "verified_claims", ()),
            attribution_limitation=getattr(execution_result, "attribution_limitation", ""),
        )

    def attest_causal_proof(
        self,
        evidence_id: str,
        target_function: Optional[str] = None,
        field_path: Optional[str] = None,
        verification_type: str = "deterministic_reproduction",
        capability: Optional[CausalVerificationCapability] = None,
        execution_provenance: Optional[Dict[str, Any]] = None,
        hypothesis_id: Optional[str] = None,
        target_identity: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Attest an authentic proof record in this ledger with the session secret and cryptographic binding."""
        with self._lock:
            rec = self.get_record(evidence_id)
            if not rec:
                raise ValueError(f"Evidence record '{evidence_id}' does not exist in ledger")

            p_details = rec.details or {}
            p_prov = rec.provenance or {}
            if (
                p_details.get("caller_submitted") is True
                or p_details.get("unverified_caller_claim") is True
                or rec.source == "unverified_caller"
                or p_prov.get("submission_channel") == "external_caller"
            ):
                raise ValueError(f"Cannot attest causal proof: record '{evidence_id}' originated from unverified external caller")

            cq = rec.capture_quality
            if not cq or not isinstance(cq, dict):
                raise ValueError(f"Cannot attest causal proof: record '{evidence_id}' lacks capture quality metadata")
            comp = cq.get("completeness") or cq.get("status")
            if comp != "COMPLETE":
                raise ValueError(f"Cannot attest causal proof: record '{evidence_id}' has non-complete capture quality '{comp}'")
            cons = cq.get("consistency_level") or cq.get("consistency_classification") or p_details.get("consistency_classification")
            if not is_atomic_or_stopped_consistency(cons) or p_details.get("is_non_atomic") is True:
                raise ValueError(f"Cannot attest causal proof: record '{evidence_id}' lacks atomic/stopped consistency '{cons}'")

            if rec.session_id and rec.session_id != self.session_id:
                raise ValueError(f"Cannot attest causal proof: record '{evidence_id}' belongs to session '{rec.session_id}', not '{self.session_id}'")

            # Authority check: Strictly require genuine internal verification capability!
            # Caller-supplied booleans, status strings, or raw execution_provenance dictionaries cannot authorize attestation.
            if capability is None or not isinstance(capability, CausalVerificationCapability):
                raise ValueError(
                    f"Cannot attest causal proof: record '{evidence_id}' lacks genuine execution provenance or internal verification capability. "
                    "Caller-supplied booleans, status strings, or execution_provenance dictionaries cannot authorize attestation."
                )

            eff_fn = target_function or capability.target_function
            eff_field = field_path or capability.field_path
            eff_hypo = hypothesis_id or capability.hypothesis_id

            if not capability.is_valid_for(
                self,
                evidence_id=evidence_id,
                target_function=eff_fn,
                field_path=eff_field,
                hypothesis_id=eff_hypo,
            ):
                raise ValueError(
                    f"Cannot attest causal proof: capability is invalid, expired, cross-session, scope-mismatched, or already consumed for record '{evidence_id}'."
                )

            # Single-use: Consume capability immediately
            capability.consume()

            eff_tid = dict(target_identity or rec.target_identity or {})
            rec.target_identity = dict(eff_tid)
            rec.details["target_identity"] = dict(eff_tid)
            eff_prov_cls = getattr(capability, "provenance_class", PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION)
            eff_attr_ver = getattr(capability, "function_attribution_verified", False)
            eff_attr_basis = getattr(capability, "attribution_basis", "")
            eff_claims = getattr(capability, "verified_claims", ())

            # Compute tamper-evident fingerprint and HMAC signature
            fingerprint = compute_evidence_fingerprint(
                record=rec,
                target_function=eff_fn,
                field_path=eff_field,
                hypothesis_id=eff_hypo,
                target_identity=eff_tid,
                provenance_class=eff_prov_cls,
                function_attribution_verified=eff_attr_ver,
                attribution_basis=eff_attr_basis,
                verified_claims=eff_claims,
            )
            token_sig = compute_attestation_signature(self.session_secret, rec.evidence_id, fingerprint, self.session_id)

            # Stamp authentic internal attestation (without exposing raw session secret)
            rec.provenance["verifier_attestation"] = {
                "token_sig": token_sig,
                "evidence_fingerprint": fingerprint,
                "investigation_id": self.session_id,
                "hypothesis_id": eff_hypo,
                "target_function": eff_fn,
                "field_path": eff_field,
                "target_identity": eff_tid,
                "provenance_class": eff_prov_cls,
                "function_attribution_verified": eff_attr_ver,
                "attribution_basis": eff_attr_basis,
                "attribution_limitation": getattr(capability, "attribution_limitation", ""),
                "verified_claims": list(eff_claims),
                "verification_type": verification_type,
                "attested_at": datetime.now(timezone.utc).isoformat(),
            }
        rec.provenance["provenance_class"] = eff_prov_cls
        rec.details["provenance_class"] = eff_prov_cls
        rec.details["function_attribution_verified"] = eff_attr_ver
        rec.details["attribution_basis"] = eff_attr_basis
        rec.details["attribution_limitation"] = getattr(capability, "attribution_limitation", "")
        rec.details["verified_claims"] = list(eff_claims)
        rec.details["verified_transition"] = True
        rec.details["causal_proof"] = True
        if execution_provenance and isinstance(execution_provenance, dict):
            safe_exec_prov = {
                k: v for k, v in execution_provenance.items()
                if k not in ("token", "token_sig", "provenance_class")
            }
            safe_exec_prov["provenance_class"] = eff_prov_cls
            rec.details["execution_provenance"] = safe_exec_prov
        if eff_fn and "target_function" not in rec.details:
            rec.details["target_function"] = eff_fn
        if eff_field and "field_path" not in rec.details:
            rec.details["field_path"] = eff_field
        return True

    def add_record(self, record: Union[EvidenceRecord, Dict[str, Any]]) -> EvidenceRecord:
        """Add an evidence record to the ledger, rejecting duplicate IDs."""
        with self._lock:
            if isinstance(record, dict):
                record = EvidenceRecord.from_dict(record)
            if not record.session_id:
                record.session_id = self.session_id

            _orig_causal = set(getattr(self, "_used_causal_attestation_ids", set()))
            _orig_causal_to_eid = dict(getattr(self, "_causal_attestation_to_evidence_id", {}))
            _orig_exec = set(getattr(self, "_used_execution_ids", set()))
            _orig_exec_to_eid = dict(getattr(self, "_execution_to_evidence_id", {}))
            _orig_used_op = {k: dict(v) for k, v in getattr(self, "_used_operation_ids", {}).items()}
            _orig_op_to_ev = {k: list(v) for k, v in getattr(self, "_operation_to_evidence_ids", {}).items()}
            _orig_op_to_rcpt = dict(getattr(self, "_operation_to_receipt_id", {}))

            try:
                # Schema validation
                self.validate_record(record)

                if record.evidence_id in self._by_id:
                    raise ValueError(f"Duplicate evidence_id '{record.evidence_id}': record with this ID already exists in ledger.")

                # Atomically update durable trust store if configured
                if getattr(self, "trust_store", None):
                    p_prov = record.provenance or {}
                    p_details = record.details or {}
                    raw_causal = p_prov.get("causal_attestation") or p_details.get("causal_attestation")
                    if raw_causal and not hasattr(self.trust_store, "consume_attestation"):
                        c_id = getattr(raw_causal, "attestation_id", None) or (raw_causal.get("attestation_id") if isinstance(raw_causal, dict) else None)
                        if c_id:
                            self.trust_store.record_used_attestation(c_id)

                    # P0-2: Bind operation in trust store
                    op_id = (record.details or {}).get("operation_id")
                    if not op_id and record.provenance:
                        lcr = record.provenance.get("live_capture_receipt")
                        if lcr:
                            op_id = lcr.get("operation_id") if isinstance(lcr, dict) else getattr(lcr, "operation_id", None)
                        if not op_id and raw_causal:
                            op_id = raw_causal.get("operation_id") if isinstance(raw_causal, dict) else getattr(raw_causal, "operation_id", None)
                    if op_id:
                        t_ident = record.target_identity or {}
                        pid_val = t_ident.get("pid")
                        eff_pid = int(pid_val) if pid_val is not None and not isinstance(pid_val, bool) else 0
                        op_meta = {
                            "evidence_id": record.evidence_id,
                            "process_identity": str(t_ident.get("process_identity", "")),
                            "executable_identity": str(t_ident.get("executable_identity") or t_ident.get("executable", "")),
                            "build_id": str(t_ident.get("build_id", "")),
                        }
                        if t_ident.get("target_host"):
                            op_meta["target_host"] = str(t_ident["target_host"])
                        if (record.details or {}).get("derived_from"):
                            op_meta["derived_from"] = record.details["derived_from"]
                        if record.parent_evidence_ids:
                            op_meta["parent_evidence_ids"] = list(record.parent_evidence_ids)
                        if (record.details or {}).get("observation_digest"):
                            op_meta["observation_digest"] = str(record.details["observation_digest"])
                        if (record.details or {}).get("parent_evidence_digest"):
                            op_meta["parent_evidence_digest"] = str(record.details["parent_evidence_digest"])

                        self.trust_store.record_used_operation(
                            op_id=str(op_id),
                            session_id=record.session_id or self.session_id,
                            pid=eff_pid,
                            metadata=op_meta,
                            allow_idempotent=True,
                        )
                        if hasattr(self.trust_store, "bind_operation_evidence"):
                            self.trust_store.bind_operation_evidence(
                                str(op_id),
                                record.evidence_id,
                                derived_from=(record.details or {}).get("derived_from"),
                                parent_evidence_ids=record.parent_evidence_ids,
                                parent_evidence_digest=(record.details or {}).get("parent_evidence_digest"),
                            )

                self._records.append(record)
                self._by_id[record.evidence_id] = record
                self._by_type.setdefault(record.evidence_type, []).append(record)
                if record.finding_id:
                    self._by_finding.setdefault(record.finding_id, []).append(record)
            except Exception:
                self._used_causal_attestation_ids = _orig_causal
                self._causal_attestation_to_evidence_id = _orig_causal_to_eid
                self._used_execution_ids = _orig_exec
                self._execution_to_evidence_id = _orig_exec_to_eid
                self._used_operation_ids = _orig_used_op
                self._operation_to_evidence_ids = _orig_op_to_ev
                self._operation_to_receipt_id = _orig_op_to_rcpt
                raise

            return record

    def record(
        self,
        evidence_type: str = EVIDENCE_TYPE_OBJECT_STATE,
        nature: str = NATURE_OBSERVATION,
        source: str = "runtime_collector",
        observation: str = "",
        details: Optional[Dict[str, Any]] = None,
        summary: Optional[str] = None,
        capture_quality: Optional[Dict[str, Any]] = None,
        finding_id: Optional[str] = None,
        parent_evidence_ids: Optional[List[str]] = None,
        session_id: Optional[str] = None,
        provenance: Optional[Dict[str, Any]] = None,
        target_identity: Optional[Dict[str, Any]] = None,
        snapshot_ref: Optional[Dict[str, Any]] = None,
        field_observation: Optional[Dict[str, Any]] = None,
        object_observation: Optional[Dict[str, Any]] = None,
    ) -> EvidenceRecord:
        """Convenience method to construct, validate, and add an evidence record to the ledger."""
        obs_text = observation or summary or ""
        rec = EvidenceRecord(
            evidence_id=f"ev_{uuid.uuid4().hex[:10]}",
            evidence_type=evidence_type,
            nature=nature,
            source=source,
            session_id=session_id or self.session_id,
            finding_id=finding_id,
            observation=obs_text,
            details=details or {},
            capture_quality=capture_quality or {"completeness": "COMPLETE", "consistency_level": "STOPPED"},
            parent_evidence_ids=parent_evidence_ids or [],
            provenance=provenance or {},
            target_identity=target_identity or {},
            snapshot_ref=snapshot_ref or {},
            field_observation=field_observation or {},
            object_observation=object_observation or {},
        )
        self.add_record(rec)
        return rec

    def validate_record(self, record: EvidenceRecord) -> None:
        """Validate record structure, types, and consistency transactionally."""
        with self._lock:
            _orig_causal = set(getattr(self, "_used_causal_attestation_ids", set()))
            _orig_causal_to_eid = dict(getattr(self, "_causal_attestation_to_evidence_id", {}))
            _orig_exec = set(getattr(self, "_used_execution_ids", set()))
            _orig_exec_to_eid = dict(getattr(self, "_execution_to_evidence_id", {}))
            _orig_used_op = {k: dict(v) for k, v in getattr(self, "_used_operation_ids", {}).items()}
            _orig_op_to_ev = {k: list(v) for k, v in getattr(self, "_operation_to_evidence_ids", {}).items()}
            _orig_op_to_rcpt = dict(getattr(self, "_operation_to_receipt_id", {}))
            try:
                self._do_validate_record(record)
            except Exception:
                self._used_causal_attestation_ids = _orig_causal
                self._causal_attestation_to_evidence_id = _orig_causal_to_eid
                self._used_execution_ids = _orig_exec
                self._execution_to_evidence_id = _orig_exec_to_eid
                self._used_operation_ids = _orig_used_op
                self._operation_to_evidence_ids = _orig_op_to_ev
                self._operation_to_receipt_id = _orig_op_to_rcpt
                raise

    def _do_validate_record(self, record: EvidenceRecord) -> None:
        """Validate record structure, types, and consistency."""
        if not record.evidence_id or not isinstance(record.evidence_id, str) or not record.evidence_id.strip():
            raise ValueError("EvidenceRecord must have a valid non-empty string evidence_id")
        if not record.evidence_type or not isinstance(record.evidence_type, str) or record.evidence_type not in VALID_EVIDENCE_TYPES:
            raise ValueError(f"Invalid evidence_type '{record.evidence_type}'. Expected one of {sorted(VALID_EVIDENCE_TYPES)}")
        if not record.nature or record.nature not in VALID_NATURES:
            raise ValueError(f"Invalid nature '{record.nature}'. Expected one of {sorted(VALID_NATURES)}")
        if record.session_id is not None and (not isinstance(record.session_id, str) or not record.session_id.strip()):
            raise ValueError("session_id must be a non-empty string when provided")
        if record.finding_id is not None and (not isinstance(record.finding_id, str) or not record.finding_id.strip()):
            raise ValueError("finding_id must be a non-empty string when provided")
        if not isinstance(record.parent_evidence_ids, (list, tuple)):
            raise TypeError("parent_evidence_ids must be a list or tuple of strings")
        for pid in record.parent_evidence_ids:
            if not isinstance(pid, str) or not pid.strip():
                raise ValueError(f"Invalid parent_evidence_id '{pid}' in parent_evidence_ids: must be a non-empty string")
            if pid not in self._by_id:
                raise ValueError(f"EvidenceRecord '{record.evidence_id}' references nonexistent parent record '{pid}'")
            # Graph cycle detection
            visited = set()
            to_visit = [pid]
            while to_visit:
                curr = to_visit.pop()
                if curr == record.evidence_id:
                    raise ValueError(f"Cycle detected in evidence dependency graph for record '{record.evidence_id}': self is reachable from parent '{pid}'")
                if curr in visited:
                    continue
                visited.add(curr)
                parent_rec = self._by_id.get(curr)
                if parent_rec and parent_rec.parent_evidence_ids:
                    to_visit.extend(parent_rec.parent_evidence_ids)

        if record.evidence_id in record.parent_evidence_ids:
            raise ValueError(f"Self-reference detected: record cannot have its own evidence_id '{record.evidence_id}' as a parent")
        for field_name, val in [
            ("snapshot_ref", record.snapshot_ref),
            ("target_identity", record.target_identity),
            ("capture_quality", record.capture_quality),
            ("object_observation", record.object_observation),
            ("field_observation", record.field_observation),
            ("static_code_link", record.static_code_link),
            ("comparison_observation", record.comparison_observation),
            ("provenance", record.provenance),
            ("details", record.details),
        ]:
            if val is not None and not isinstance(val, dict):
                raise TypeError(f"Field '{field_name}' must be a dictionary when provided, got {type(val).__name__}")

        # Invalidate unauthenticated, caller-forged, or tampered verifier attestations
        if record.provenance and "verifier_attestation" in record.provenance:
            att = record.provenance.get("verifier_attestation")
            if not isinstance(att, dict):
                record.provenance["verifier_attestation"] = None
                record.provenance["attestation_rejected"] = "Malformed verifier attestation structure"
            elif not att.get("token_sig") or att.get("investigation_id") != self.session_id:
                record.provenance["verifier_attestation"] = None
                record.provenance["attestation_rejected"] = "Invalid, unverified, or cross-session attestation token"
            else:
                expected_fp = compute_evidence_fingerprint(
                    record,
                    target_function=att.get("target_function"),
                    field_path=att.get("field_path"),
                    hypothesis_id=att.get("hypothesis_id"),
                    target_identity=att.get("target_identity"),
                    provenance_class=att.get("provenance_class"),
                    function_attribution_verified=att.get("function_attribution_verified"),
                    attribution_basis=att.get("attribution_basis"),
                )
                expected_sig = compute_attestation_signature(self.session_secret, record.evidence_id, expected_fp, self.session_id)
                if att.get("evidence_fingerprint") != expected_fp or not hmac.compare_digest(str(att.get("token_sig", "")), str(expected_sig)):
                    record.provenance["verifier_attestation"] = None
                    record.provenance["attestation_rejected"] = "Attestation signature mismatch or post-issuance tampering detected"

        # Disarm attestation if record is marked caller_submitted
        p_details = record.details or {}
        p_prov = record.provenance or {}
        if (
            p_details.get("caller_submitted") is True
            or p_details.get("unverified_caller_claim") is True
            or record.source == "unverified_caller"
            or p_prov.get("submission_channel") == "external_caller"
        ):
            if record.provenance:
                record.provenance["verifier_attestation"] = None
                record.provenance.pop("function_attribution_verified", None)
                record.provenance.pop("attribution_basis", None)
                if record.provenance.get("provenance_class") in TRUSTED_PROVENANCE_CLASSES:
                    record.provenance["provenance_class"] = PROVENANCE_CLASS_IMPORTED_UNVERIFIED
            if record.details:
                record.details.pop("execution_provenance", None)
                record.details.pop("function_attribution_verified", None)
                record.details.pop("attribution_basis", None)
                if record.details.get("provenance_class") in TRUSTED_PROVENANCE_CLASSES:
                    record.details["provenance_class"] = PROVENANCE_CLASS_IMPORTED_UNVERIFIED

        # Enforce explicit provenance class validity and synthetic/imported/live separation
        prov_cls = record.provenance_class
        if prov_cls not in VALID_PROVENANCE_CLASSES:
            raise ValueError(f"Invalid provenance_class '{prov_cls}'. Expected one of {sorted(VALID_PROVENANCE_CLASSES)}")

        is_sim = bool(
            p_details.get("is_simulated") is True
            or p_prov.get("is_simulated") is True
            or any(p_details.get(k) is not None for k in ("force_failed", "force_error", "force_contradiction", "simulated_outcome"))
            or any(p_prov.get(k) is not None for k in ("force_failed", "force_error", "force_contradiction", "simulated_outcome"))
        )
        auth_lvl = p_prov.get("authority_level") or p_details.get("authority_level")
        if prov_cls in TRUSTED_PROVENANCE_CLASSES:
            if is_sim:
                raise ValueError(f"Prohibited synthetic-to-live escalation: simulated record '{record.evidence_id}' cannot claim {prov_cls}")
            if auth_lvl in ("TEST", "SYNTHETIC"):
                raise ValueError(f"Prohibited authority escalation: test/synthetic authority '{auth_lvl}' cannot claim {prov_cls}")
            for par_id in record.parent_evidence_ids:
                par_rec = self._by_id.get(par_id)
                if par_rec and par_rec.provenance_class in SYNTHETIC_PROVENANCE_CLASSES:
                    raise ValueError(
                        f"Prohibited synthetic-to-live escalation: record '{record.evidence_id}' derives from synthetic parent '{par_id}' ({par_rec.provenance_class})"
                    )

        # Validate attached LiveCaptureReceipt on LIVE_RUNTIME_CAPTURE records
        if prov_cls == PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE:
            raw_live_rcpt = p_prov.get("live_capture_receipt") or p_details.get("live_capture_receipt")
            if raw_live_rcpt is None:
                raise ValueError(f"LIVE_RUNTIME_CAPTURE record '{record.evidence_id}' requires an authentic LiveCaptureReceipt")
            if not record.target_identity or not isinstance(record.target_identity, dict):
                raise ValueError(f"LIVE_RUNTIME_CAPTURE record '{record.evidence_id}' missing required target identity")
            t_ident = record.target_identity
            exp_pid = t_ident.get("pid")
            exp_proc_id = t_ident.get("process_identity")
            exp_exe_id = t_ident.get("executable_identity") or t_ident.get("executable")
            if exp_pid is None or not exp_proc_id or not exp_exe_id:
                raise ValueError(f"LIVE_RUNTIME_CAPTURE record '{record.evidence_id}' missing required process/executable identity fields in target_identity")

            from .capture_backend import LiveCaptureReceipt
            try:
                rcpt_obj = raw_live_rcpt if isinstance(raw_live_rcpt, LiveCaptureReceipt) else LiveCaptureReceipt.from_dict(raw_live_rcpt)
            except Exception as rcpt_err:
                raise ValueError(f"LiveCaptureReceipt malformed for record '{record.evidence_id}': {rcpt_err}")

            exp_bid = t_ident.get("build_id") or t_ident.get("target_build_id")
            exp_snap = (record.snapshot_ref or {}).get("snapshot_id") if isinstance(record.snapshot_ref, dict) else None
            ok_rcpt, reason_rcpt = rcpt_obj.verify(
                expected_session_id=record.session_id or self.session_id,
                expected_pid=exp_pid,
                expected_process_identity=exp_proc_id,
                expected_executable_identity=exp_exe_id,
                expected_build_id=exp_bid,
                expected_snapshot_binding=exp_snap,
                require_production_authority=True,
            )
            if not ok_rcpt:
                raise ValueError(f"LiveCaptureReceipt rejected for record '{record.evidence_id}': {reason_rcpt}")

            exp_epoch = p_details.get("epoch", p_details.get("capture_epoch", (record.snapshot_ref or {}).get("epoch") if isinstance(record.snapshot_ref, dict) else None))
            if exp_epoch is not None and not isinstance(exp_epoch, bool):
                try:
                    exp_ep_int = int(exp_epoch)
                    rcpt_ep_int = int(rcpt_obj.capture_epoch)
                except (ValueError, TypeError):
                    exp_ep_int = None
                    rcpt_ep_int = None
                if exp_ep_int is not None and rcpt_ep_int is not None and exp_ep_int != rcpt_ep_int:
                    raise ValueError(f"LiveCaptureReceipt capture_epoch mismatch for record '{record.evidence_id}': expected {exp_epoch}, got {rcpt_obj.capture_epoch}")

            # A.3.11: Probe receipt isolation
            if record.evidence_type in DIAGNOSTIC_EVIDENCE_TYPES and getattr(rcpt_obj, "operation_type", "diagnostic") == "probe":
                raise ValueError(f"Probe read receipt cannot attest to diagnostic evidence record '{record.evidence_id}'")

            # A.3.11: Observation digest binding
            rec_obs_dig = (record.details or {}).get("observation_digest") or (record.details or {}).get("expected_observation_digest")
            if not rec_obs_dig and "payload_digest" in (record.details or {}):
                rec_obs_dig = (record.details or {}).get("payload_digest")
            if getattr(rcpt_obj, "observation_digest", "") and rec_obs_dig:
                if str(rcpt_obj.observation_digest) != str(rec_obs_dig):
                    raise ValueError(
                        f"Mismatched observation digest for record '{record.evidence_id}': "
                        f"receipt={rcpt_obj.observation_digest}, record={rec_obs_dig}"
                    )
        elif prov_cls == PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION:
            att = p_prov.get("verifier_attestation") or p_details.get("verifier_attestation")
            if not att or not isinstance(att, dict) or att.get("attestation_rejected") or not att.get("token_sig"):
                raise ValueError(f"CONTROLLED_RUNTIME_REPRODUCTION record '{record.evidence_id}' requires a valid cryptographically authenticated verifier attestation")
            if att.get("revoked") or att.get("expired"):
                raise ValueError(f"CONTROLLED_RUNTIME_REPRODUCTION attestation is revoked or expired for '{record.evidence_id}'")
            if att.get("investigation_id") and str(att["investigation_id"]) != str(self.session_id):
                raise ValueError(f"CONTROLLED_RUNTIME_REPRODUCTION attestation session mismatch: expected '{self.session_id}', got '{att.get('investigation_id')}'")

            # Verify cryptographic attestation signature
            fp = att.get("evidence_fingerprint")
            if not fp:
                raise ValueError(f"CONTROLLED_RUNTIME_REPRODUCTION missing evidence_fingerprint for '{record.evidence_id}'")
            expected_sig = compute_attestation_signature(self.session_secret, record.evidence_id, fp, self.session_id)
            if not hmac.compare_digest(str(att.get("token_sig", "")), str(expected_sig)):
                raise ValueError(f"CONTROLLED_RUNTIME_REPRODUCTION cryptographic signature verification failed for '{record.evidence_id}'")

            # Target identity validation if ledger has target_identity
            if getattr(self, "target_identity", None):
                ok_tid, tid_reason = validate_controlled_execution_target_identity(self.target_identity, record.target_identity)
                if not ok_tid:
                    raise ValueError(f"CONTROLLED_RUNTIME_REPRODUCTION target identity mismatch for '{record.evidence_id}': {tid_reason}")

            # Single-use execution receipt consumption
            c_res = p_prov.get("controlled_execution_result") or p_details.get("controlled_execution_result")
            if c_res and isinstance(c_res, dict):
                eid = c_res.get("execution_id")
                if eid:
                    bound_ev = self._execution_to_evidence_id.get(eid)
                    if bound_ev is not None and bound_ev != record.evidence_id:
                        raise ValueError(f"Controlled execution receipt '{eid}' was issued for evidence '{bound_ev}', cannot be used for '{record.evidence_id}'")
                    if bound_ev is None and eid in self._used_execution_ids:
                        raise ValueError(f"Controlled execution receipt '{eid}' has already been consumed in this ledger")
                    self._used_execution_ids.add(eid)
                    self._execution_to_evidence_id[eid] = record.evidence_id

        # Derivation and Self-Reference validation (applicable across all provenance classes)
        if record.parent_evidence_ids and record.evidence_id in record.parent_evidence_ids:
            raise ValueError(
                f"Self-referential derivation rejected: record '{record.evidence_id}' lists itself in parent_evidence_ids"
            )
        if record.details and record.details.get("derived_from") == record.evidence_id:
            raise ValueError(
                f"Self-referential derivation rejected: record '{record.evidence_id}' has derived_from equal to itself"
            )

        # Operation replay & type validation metadata extraction
        op_id = getattr(rcpt_obj, "operation_id", None) if 'rcpt_obj' in locals() and rcpt_obj else None
        rcpt_id = getattr(rcpt_obj, "receipt_id", None) if 'rcpt_obj' in locals() and rcpt_obj else None
        rcpt_obs_dig = getattr(rcpt_obj, "observation_digest", "") if 'rcpt_obj' in locals() and rcpt_obj else ""
        rcpt_op_type = getattr(rcpt_obj, "operation_type", "") if 'rcpt_obj' in locals() and rcpt_obj else ""

        if not op_id:
            raw_rc = p_prov.get("live_capture_receipt") or (record.details or {}).get("live_capture_receipt")
            if raw_rc:
                from .capture_backend import LiveCaptureReceipt
                if isinstance(raw_rc, LiveCaptureReceipt):
                    op_id = getattr(raw_rc, "operation_id", None)
                    rcpt_id = getattr(raw_rc, "receipt_id", None)
                    rcpt_obs_dig = getattr(raw_rc, "observation_digest", "")
                    rcpt_op_type = getattr(raw_rc, "operation_type", "")
                elif isinstance(raw_rc, dict):
                    op_id = raw_rc.get("operation_id")
                    rcpt_id = raw_rc.get("receipt_id")
                    rcpt_obs_dig = raw_rc.get("observation_digest", "")
                    rcpt_op_type = raw_rc.get("operation_type", "")

        if not op_id and record.details:
            op_id = record.details.get("operation_id")
        if not rcpt_id and record.details and "receipt_id" in record.details:
            rcpt_id = record.details["receipt_id"]
        if not op_id and record.provenance and "causal_attestation" in record.provenance:
            ca = record.provenance["causal_attestation"]
            op_id = getattr(ca, "operation_id", None) if hasattr(ca, "operation_id") else (ca.get("operation_id") if isinstance(ca, dict) else None)

        # Validate derived_from if present
        derived_from = (record.details or {}).get("derived_from")
        if derived_from:
            if isinstance(derived_from, str):
                derived_list = [derived_from]
            elif isinstance(derived_from, (list, tuple)):
                derived_list = list(derived_from)
            else:
                derived_list = []
            for d_src in derived_list:
                if d_src not in self._by_id:
                    raise ValueError(
                        f"Derived record '{record.evidence_id}' references nonexistent source observation '{d_src}'"
                    )
            if not record.parent_evidence_ids and derived_list:
                record.parent_evidence_ids = list(derived_list)
            for d_src in derived_list:
                if d_src not in record.parent_evidence_ids:
                    raise ValueError(
                        f"Derived record '{record.evidence_id}' missing source '{d_src}' in parent_evidence_ids"
                    )

        # Deep validation of parent_evidence_ids (session identity, cross-target, and canonical parent digest)
        if record.parent_evidence_ids:
            for p_id in record.parent_evidence_ids:
                if p_id not in self._by_id:
                    raise ValueError(
                        f"Referenced parent evidence '{p_id}' for record '{record.evidence_id}' does not exist in ledger"
                    )
                p_rec = self._by_id[p_id]
                if p_rec.session_id != (record.session_id or self.session_id):
                    raise ValueError(
                        f"Cross-session derivation rejected for '{record.evidence_id}': parent '{p_id}' belongs to session "
                        f"'{p_rec.session_id}', record belongs to '{record.session_id or self.session_id}'"
                    )
                p_tident = p_rec.target_identity or {}
                r_tident = record.target_identity or {}
                if p_tident.get("pid") and r_tident.get("pid") and int(p_tident["pid"]) != int(r_tident["pid"]):
                    raise ValueError(
                        f"Cross-target derivation rejected: parent '{p_id}' PID {p_tident['pid']} != record PID {r_tident['pid']} (PID mismatch)"
                    )
                if p_tident.get("target_host") and r_tident.get("target_host") and str(p_tident["target_host"]) != str(r_tident["target_host"]):
                    raise ValueError(
                        f"Cross-target derivation rejected: parent '{p_id}' host {p_tident['target_host']} != record host {r_tident['target_host']}"
                    )
                if op_id and p_tident.get("process_identity") and r_tident.get("process_identity") and str(p_tident["process_identity"]) != str(r_tident["process_identity"]):
                    raise ValueError(
                        f"Cross-target derivation rejected: parent '{p_id}' process {p_tident['process_identity']} != record process {r_tident['process_identity']}"
                    )
                exp_p_digest = compute_evidence_fingerprint(p_rec)
                p_digs = (record.details or {}).get("parent_evidence_digests")
                if isinstance(p_digs, dict) and p_id in p_digs:
                    if p_digs[p_id] != exp_p_digest:
                        raise ValueError(
                            f"Parent evidence digest mismatch for record '{record.evidence_id}' referencing '{p_id}': "
                            f"expected '{exp_p_digest}', got '{p_digs[p_id]}'"
                        )
                elif len(record.parent_evidence_ids) == 1 and record.details and "parent_evidence_digest" in record.details:
                    actual_p_digest = record.details["parent_evidence_digest"]
                    if actual_p_digest != exp_p_digest:
                        raise ValueError(
                            f"Parent evidence digest mismatch for record '{record.evidence_id}' referencing '{p_id}': "
                            f"expected '{exp_p_digest}', got '{actual_p_digest}'"
                        )
                else:
                    if record.details is None:
                        record.details = {}
                    record.details.setdefault("parent_evidence_digests", {})[p_id] = exp_p_digest
                    if len(record.parent_evidence_ids) == 1:
                        record.details["parent_evidence_digest"] = exp_p_digest


        if op_id:
            if not hasattr(self, "_used_operation_ids"):
                self._used_operation_ids: Dict[str, Dict[str, Any]] = {}
            if not hasattr(self, "_operation_to_evidence_ids"):
                self._operation_to_evidence_ids: Dict[str, List[str]] = {}
            if not hasattr(self, "_operation_to_receipt_id"):
                self._operation_to_receipt_id: Dict[str, str] = {}

            if rcpt_id:
                if op_id in self._operation_to_receipt_id:
                    bound_rcpt = self._operation_to_receipt_id[op_id]
                    if bound_rcpt != rcpt_id:
                        raise ValueError(
                            f"Receipt-to-operation conflict: operation '{op_id}' is already bound to receipt '{bound_rcpt}', "
                            f"cannot bind to different receipt '{rcpt_id}'"
                        )
                else:
                    self._operation_to_receipt_id[op_id] = rcpt_id

            # Operation evidence type validation
            if op_id in self._operation_to_evidence_ids:
                if record.evidence_type not in ALLOWED_DERIVED_OPERATION_EVIDENCE_TYPES:
                    raise ValueError(
                        f"Evidence type '{record.evidence_type}' is not permitted to share capture operation ID '{op_id}'"
                    )
            else:
                is_causal_comparison = (record.evidence_type == EVIDENCE_TYPE_COMPARISON and (
                    p_prov.get("causal_attestation") or (record.details or {}).get("causal_attestation")
                ))
                if record.evidence_type not in ALLOWED_PRIMARY_OPERATION_EVIDENCE_TYPES and not is_causal_comparison:
                    raise ValueError(
                        f"Evidence type '{record.evidence_type}' is not permitted as primary record for capture operation ID '{op_id}'"
                    )

            if derived_from:
                for d_src in (derived_from if isinstance(derived_from, (list, tuple)) else [derived_from]):
                    src_rec = self._by_id.get(d_src)
                    if src_rec:
                        src_op = (src_rec.details or {}).get("operation_id")
                        if not src_op and (src_rec.provenance or {}).get("live_capture_receipt"):
                            slcr = src_rec.provenance["live_capture_receipt"]
                            src_op = slcr.get("operation_id") if isinstance(slcr, dict) else getattr(slcr, "operation_id", None)
                        if record.evidence_type != EVIDENCE_TYPE_COMPARISON and src_op and str(src_op) != str(op_id):
                            raise ValueError(
                                f"Derivation operation mismatch: source '{d_src}' belongs to operation '{src_op}', "
                                f"derived record '{record.evidence_id}' claims operation '{op_id}'"
                            )

            if op_id in self._operation_to_evidence_ids:
                if not derived_from:
                    if record.evidence_id not in self._operation_to_evidence_ids[op_id]:
                        raise ValueError(
                            f"Receipt replay detected for operation '{op_id}' across different evidence records: "
                            f"operation is already bound to primary observation '{self._operation_to_evidence_ids[op_id][0]}'. "
                            f"Multiple records from one operation must explicitly derive from the primary observation via 'derived_from' and 'parent_evidence_ids'."
                        )
                if record.evidence_id not in self._operation_to_evidence_ids[op_id]:
                    self._operation_to_evidence_ids[op_id].append(record.evidence_id)
            else:
                self._operation_to_evidence_ids[op_id] = [record.evidence_id]

            t_ident = record.target_identity or {}
            rec_pid = t_ident.get("pid")
            eff_pid = int(rec_pid) if rec_pid is not None and not isinstance(rec_pid, bool) else None

            if op_id in self._used_operation_ids:
                prev = self._used_operation_ids[op_id]
                if prev.get("session_id") != (record.session_id or self.session_id):
                    raise ValueError(f"Receipt replay across sessions rejected for operation '{op_id}'")
                if eff_pid is not None and prev.get("pid") is not None and prev["pid"] != eff_pid:
                    raise ValueError(f"Receipt replay across PIDs rejected for operation '{op_id}'")

            eff_field = (record.field_observation or {}).get("field_path") or (record.details or {}).get("field_path") or ""
            rec_used_op = {
                "session_id": record.session_id or self.session_id,
                "pid": eff_pid,
                "process_identity": str(t_ident.get("process_identity", "")),
                "executable_identity": str(t_ident.get("executable_identity") or t_ident.get("executable", "")),
                "build_id": str(t_ident.get("build_id", "")),
                "target_host": str(t_ident.get("target_host", "")),
                "receipt_id": str(rcpt_id or ""),
                "observation_digest": str(rcpt_obs_dig or (record.details or {}).get("observation_digest", "")),
                "operation_type": str(rcpt_op_type or (record.details or {}).get("operation_type", "capture")),
                "evidence_id": self._operation_to_evidence_ids[op_id][0],
                "evidence_ids": list(self._operation_to_evidence_ids[op_id]),
                "recorded_at": (record.timestamp or datetime.now(timezone.utc).isoformat()),
                "observation": record.observation,
                "field": eff_field,
            }
            if (record.details or {}).get("parent_evidence_digest"):
                rec_used_op["parent_evidence_digest"] = record.details["parent_evidence_digest"]
            if (record.details or {}).get("derived_from"):
                rec_used_op["derived_from"] = record.details["derived_from"]
            if record.parent_evidence_ids:
                rec_used_op["parent_evidence_ids"] = list(record.parent_evidence_ids)
            self._used_operation_ids[op_id] = rec_used_op

        # P0 Cryptographic Causal Attestation Verification
        raw_causal = p_prov.get("causal_attestation") or p_details.get("causal_attestation")
        if raw_causal is not None:
            from .capture_backend import CausalAttestation
            if isinstance(raw_causal, CausalAttestation):
                c_att = raw_causal
            elif isinstance(raw_causal, dict):
                try:
                    c_att = CausalAttestation.from_dict(raw_causal)
                except Exception as e:
                    raise ValueError(f"Malformed CausalAttestation on record '{record.evidence_id}': {e}")
            else:
                raise ValueError(f"Invalid causal_attestation on record '{record.evidence_id}'")

            # Validate target identity mandatory fields on attestation
            c_ident = c_att.target_identity or {}
            c_pid = c_ident.get("pid")
            c_proc = c_ident.get("process_identity")
            c_exe = c_ident.get("executable_identity") or c_ident.get("executable")
            if c_pid is None or int(c_pid) <= 1:
                raise ValueError(f"CausalAttestation target identity missing valid PID on record '{record.evidence_id}'")
            if not c_proc or not str(c_proc).strip():
                raise ValueError(f"CausalAttestation target identity missing process_identity on record '{record.evidence_id}'")
            if not c_exe or not str(c_exe).strip():
                raise ValueError(f"CausalAttestation target identity missing executable_identity on record '{record.evidence_id}'")

            r_ident = record.target_identity or {}
            r_pid = r_ident.get("pid")
            r_proc = r_ident.get("process_identity")
            r_exe = r_ident.get("executable_identity") or r_ident.get("executable")
            r_bid = r_ident.get("build_id")

            eff_ts = getattr(self, "trust_store", None)
            if eff_ts and hasattr(eff_ts, "consume_attestation"):
                from .capture_backend import TrustConsumptionStatus
                cons_res = eff_ts.consume_attestation(
                    attestation=c_att,
                    evidence_id=record.evidence_id,
                    session_id=record.session_id or self.session_id,
                    expected_pid=r_pid,
                    expected_process_identity=r_proc,
                    expected_executable_identity=r_exe,
                    expected_build_id=r_bid,
                    expected_target_host=r_ident.get("target_host"),
                )
                if not cons_res.is_accepted:
                    if cons_res.status == TrustConsumptionStatus.PERSISTENCE_FAILURE:
                        raise RuntimeError(cons_res.reason)
                    raise ValueError(f"CausalAttestation rejected for record '{record.evidence_id}': [{cons_res.status.value}] {cons_res.reason}")
            else:
                ok_att, err_att = c_att.verify(
                    expected_session_id=record.session_id or self.session_id,
                    expected_pid=r_pid,
                    expected_process_identity=r_proc,
                    expected_executable_identity=r_exe,
                    expected_build_id=r_bid,
                    expected_target_host=r_ident.get("target_host"),
                    trust_store=eff_ts,
                )
                if not ok_att:
                    raise ValueError(f"CausalAttestation rejected for record '{record.evidence_id}': {err_att}")

                if eff_ts and hasattr(eff_ts, "is_attestation_used") and eff_ts.is_attestation_used(c_att.attestation_id):
                    bound_eid = getattr(self, "_causal_attestation_to_evidence_id", {}).get(c_att.attestation_id)
                    if bound_eid != record.evidence_id:
                        raise ValueError(f"Replay of causal attestation ID '{c_att.attestation_id}' rejected by durable trust store on record '{record.evidence_id}'")

            if c_pid is not None and r_pid is not None and int(c_pid) != int(r_pid):
                raise ValueError(f"CausalAttestation target PID mismatch for record '{record.evidence_id}': attestation has {c_pid}, record has {r_pid}")

            if not hasattr(self, "_used_causal_attestation_ids"):
                self._used_causal_attestation_ids: Set[str] = set()
            if not hasattr(self, "_causal_attestation_to_evidence_id"):
                self._causal_attestation_to_evidence_id: Dict[str, str] = {}

            if c_att.attestation_id in self._causal_attestation_to_evidence_id:
                bound_eid = self._causal_attestation_to_evidence_id[c_att.attestation_id]
                if bound_eid != record.evidence_id:
                    raise ValueError(f"Replay of causal attestation ID '{c_att.attestation_id}' rejected on record '{record.evidence_id}'")
            else:
                self._causal_attestation_to_evidence_id[c_att.attestation_id] = record.evidence_id
                self._used_causal_attestation_ids.add(c_att.attestation_id)

            # Precondition evidence verification
            if not c_att.precondition_evidence_id or c_att.precondition_evidence_id not in self._by_id:
                raise ValueError(f"CausalAttestation references nonexistent precondition evidence '{c_att.precondition_evidence_id}'")
            pre_rec = self._by_id[c_att.precondition_evidence_id]

            # Verify same session
            if pre_rec.session_id and record.session_id and str(pre_rec.session_id) != str(record.session_id):
                raise ValueError(
                    f"CausalAttestation cross-session evidence binding rejected: "
                    f"pre='{pre_rec.session_id}', post='{record.session_id}'"
                )

            # Verify same target PID
            pre_pid = (pre_rec.target_identity or {}).get("pid")
            if pre_pid is not None and r_pid is not None and int(pre_pid) != int(r_pid):
                raise ValueError(
                    f"CausalAttestation cross-target evidence binding rejected: "
                    f"pre PID {pre_pid} != post PID {r_pid}"
                )

            # Verify postcondition evidence consistency if already in ledger
            if c_att.postcondition_evidence_id in self._by_id:
                post_rec = self._by_id[c_att.postcondition_evidence_id]
                post_pid = (post_rec.target_identity or {}).get("pid")
                if post_pid is not None and pre_pid is not None and int(post_pid) != int(pre_pid):
                    raise ValueError(f"CausalAttestation cross-target evidence binding rejected: pre PID {pre_pid} != post PID {post_pid}")
                if post_rec.session_id and pre_rec.session_id and str(post_rec.session_id) != str(pre_rec.session_id):
                    raise ValueError(f"CausalAttestation cross-session evidence binding rejected: pre='{pre_rec.session_id}', post='{post_rec.session_id}'")

            # Verify operation ID matching
            rec_op = (record.details or {}).get("operation_id")
            if rec_op and str(c_att.operation_id) != str(rec_op):
                raise ValueError(f"CausalAttestation operation ID mismatch: attestation={c_att.operation_id}, record={rec_op}")

            raw_rcpt = p_prov.get("live_capture_receipt") or p_details.get("live_capture_receipt")
            if raw_rcpt:
                rcpt_op = raw_rcpt.get("operation_id") if isinstance(raw_rcpt, dict) else getattr(raw_rcpt, "operation_id", None)
                if rcpt_op and not str(rcpt_op).startswith("ctx_") and str(c_att.operation_id) != str(rcpt_op):
                    raise ValueError(
                        f"CausalAttestation operation ID '{c_att.operation_id}' does not match "
                        f"live capture receipt operation ID '{rcpt_op}'"
                    )

            # Verify intervention details authorization
            if not c_att.intervention_details or not isinstance(c_att.intervention_details, dict):
                raise ValueError(f"CausalAttestation on record '{record.evidence_id}' missing verifiable intervention_details")
            if not any(k in c_att.intervention_details for k in ("intervention_id", "verified_intervention", "authorized_by", "action", "transition_id")):
                raise ValueError(f"CausalAttestation on record '{record.evidence_id}' lacks verifiable intervention authorization or identity")

        if (
            p_details.get("causal_proof") is True
            or p_details.get("deterministic_transition_verified") is True
            or p_details.get("transition_verified") is True
            or p_prov.get("causally_verified") is True
        ) and not raw_causal and not p_prov.get("verifier_attestation"):
            raise ValueError(f"Caller-supplied causal_proof=True on record '{record.evidence_id}' rejected: missing valid cryptographic CausalAttestation")

        # Reject synthetic or imported provenance escalation to production authority
        prov_cls = p_prov.get("provenance_class") or record.provenance_class
        if prov_cls in ("SYNTHETIC", "SYNTHETIC_FIXTURE", "IMPORTED_UNVERIFIED"):
            lcr = p_prov.get("live_capture_receipt")
            if lcr:
                lcr_auth = lcr.get("authority_level") if isinstance(lcr, dict) else getattr(lcr, "authority_level", None)
                if lcr_auth == "PRODUCTION":
                    raise ValueError(f"Synthetic or imported evidence '{record.evidence_id}' cannot claim PRODUCTION authority live_capture_receipt")
            if raw_causal:
                ca_auth = raw_causal.get("authority_level") if isinstance(raw_causal, dict) else getattr(raw_causal, "authority_level", None)
                if ca_auth == "PRODUCTION":
                    raise ValueError(f"Synthetic or imported evidence '{record.evidence_id}' cannot claim PRODUCTION authority causal_attestation")


    def transition_provenance(
        self,
        evidence_id: str,
        target_provenance_class: str,
        live_receipt: Optional[Any] = None,
        expected_target_identity: Optional[Dict[str, Any]] = None,
    ) -> EvidenceRecord:
        """Enforce fail-closed provenance transitions on an existing EvidenceRecord.

        Rules:
        - SYNTHETIC / SYNTHETIC_FIXTURE can NEVER transition to LIVE_RUNTIME_CAPTURE or CONTROLLED_RUNTIME_REPRODUCTION.
        - IMPORTED_UNVERIFIED can ONLY transition to LIVE_RUNTIME_CAPTURE if a valid, authenticated LiveCaptureReceipt
          matching the session and target identity is provided.
        """
        rec = self.get_record(evidence_id)
        if not rec:
            raise ValueError(f"EvidenceRecord '{evidence_id}' not found in ledger")
        if target_provenance_class not in VALID_PROVENANCE_CLASSES:
            raise ValueError(f"Invalid target_provenance_class '{target_provenance_class}'")

        cur_cls = rec.provenance_class
        if cur_cls in SYNTHETIC_PROVENANCE_CLASSES and target_provenance_class not in SYNTHETIC_PROVENANCE_CLASSES:
            raise ValueError(
                f"Prohibited provenance transition: {cur_cls} cannot escalate to {target_provenance_class}"
            )

        if target_provenance_class == PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE and cur_cls != PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE:
            if live_receipt is None:
                raise ValueError(
                    f"Prohibited provenance transition: {cur_cls} -> LIVE_RUNTIME_CAPTURE requires an authentic LiveCaptureReceipt"
                )
            from .capture_backend import LiveCaptureReceipt
            rcpt_obj = live_receipt if isinstance(live_receipt, LiveCaptureReceipt) else LiveCaptureReceipt.from_dict(live_receipt)
            t_id = expected_target_identity or rec.target_identity or {}
            ok, reason = rcpt_obj.verify(
                expected_session_id=rec.session_id or self.session_id,
                expected_pid=t_id.get("pid"),
                expected_process_identity=t_id.get("process_identity"),
                expected_executable_identity=t_id.get("executable_identity") or t_id.get("executable"),
                expected_build_id=t_id.get("build_id") or t_id.get("target_build_id"),
                require_production_authority=True,
            )
            if not ok:
                raise ValueError(f"LiveCaptureReceipt verification failed for provenance transition: {reason}")
            rec.provenance["live_capture_receipt"] = rcpt_obj.to_dict()

        rec.provenance["provenance_class"] = target_provenance_class
        if "provenance_class" in rec.details:
            rec.details["provenance_class"] = target_provenance_class
        return rec

    def get_record(self, evidence_id: str) -> Optional[EvidenceRecord]:
        """Look up record by unique ID."""
        return self._by_id.get(evidence_id)

    def has(self, evidence_id: str) -> bool:
        """Checks if evidence record exists in ledger."""
        return evidence_id in self._by_id

    def __contains__(self, evidence_id: str) -> bool:
        return evidence_id in self._by_id

    def __len__(self) -> int:
        """Returns the total number of admitted evidence records."""
        return len(self._records)

    def get_records(self) -> List[EvidenceRecord]:
        """Returns a snapshot copy of all admitted evidence records."""
        return list(self._records)

    def find_by_semantic_digest(self, semantic_digest: str) -> Optional[EvidenceRecord]:
        """Look up existing record by semantic digest for deduplication."""
        if not semantic_digest:
            return None
        for r in self._records:
            if (r.details or {}).get("semantic_digest") == semantic_digest:
                return r
        return None

    def has_semantic_digest(self, semantic_digest: str) -> bool:
        """Checks if a record with the specified semantic digest already exists."""
        return self.find_by_semantic_digest(semantic_digest) is not None

    def query(
        self,
        evidence_type: Optional[str] = None,
        nature: Optional[str] = None,
        finding_id: Optional[str] = None,
        source: Optional[str] = None,
        object_id: Optional[str] = None,
    ) -> List[EvidenceRecord]:
        """Query evidence records matching given filters."""
        results = self._records
        if evidence_type:
            results = [r for r in results if r.evidence_type == evidence_type]
        if nature:
            results = [r for r in results if r.nature == nature]
        if finding_id:
            results = [r for r in results if r.finding_id == finding_id]
        if source:
            results = [r for r in results if r.source == source]
        if object_id:
            results = [
                r for r in results
                if (r.object_observation and r.object_observation.get("object_id") == object_id)
                or (r.field_observation and r.field_observation.get("object_id") == object_id)
            ]
        return results

    def trace_provenance_chain(self, evidence_id: str) -> List[Dict[str, Any]]:
        """Trace recursive provenance lineage for an evidence record with cycle detection and deterministic ordering."""
        chain: List[Dict[str, Any]] = []
        visited: Set[str] = set()

        def _dfs(eid: str, path: List[str]):
            if eid in path:
                # Cycle detected
                chain.append({
                    "evidence_id": eid,
                    "status": "CYCLE_DETECTED",
                    "cycle_path": path + [eid],
                    "reason": f"Cyclic provenance lineage detected involving '{eid}'.",
                })
                return

            if eid in visited:
                return
            visited.add(eid)

            rec = self.get_record(eid)
            if not rec:
                chain.append({
                    "evidence_id": eid,
                    "status": "UNRESOLVED_PARENT",
                    "reason": f"Parent evidence '{eid}' not found in ledger.",
                })
                return

            step = {
                "evidence_id": rec.evidence_id,
                "evidence_type": rec.evidence_type,
                "nature": rec.nature,
                "source": rec.source,
                "parent_evidence_ids": list(rec.parent_evidence_ids),
                "provenance": rec.provenance,
                "snapshot_ref": rec.snapshot_ref,
                "target_identity": rec.target_identity,
                "object_info": rec.object_observation or rec.field_observation,
                "static_link": rec.static_code_link,
                "status": "RESOLVED",
            }
            chain.append(step)

            if eid in rec.parent_evidence_ids:
                chain.append({
                    "evidence_id": eid,
                    "status": "SELF_REFERENCE",
                    "reason": f"Self-referencing parent found on evidence '{eid}'.",
                })
                return

            # Traverse parents deterministically (sorted)
            sorted_parents = sorted(rec.parent_evidence_ids)
            for pid in sorted_parents:
                _dfs(pid, path + [eid])

        _dfs(evidence_id, [])
        return chain

    def get_provenance_chain(self, finding_id: Optional[str] = None, evidence_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Trace provenance link chain from finding/evidence down to artifact/snapshot."""
        if evidence_id:
            return self.trace_provenance_chain(evidence_id)

        if finding_id:
            records = self.query(finding_id=finding_id)
            combined_chain: List[Dict[str, Any]] = []
            seen_eids: Set[str] = set()
            for r in records:
                sub_chain = self.trace_provenance_chain(r.evidence_id)
                for item in sub_chain:
                    eid = item.get("evidence_id")
                    if eid and eid not in seen_eids:
                        seen_eids.add(eid)
                        combined_chain.append(item)
            return combined_chain

        return []

    def migrate_legacy_evidence(self, evidence_id: str) -> bool:
        """Migrate a stored legacy execution record to v2 RFC 8785 format in-place."""
        with self._lock:
            rec = self.get_record(evidence_id)
            if not rec or not rec.provenance:
                return False
            exec_dict = rec.provenance.get("controlled_execution_result")
            if not exec_dict or not isinstance(exec_dict, dict):
                return False
            exec_res = ControlledExecutionResult.from_dict(exec_dict)
            if getattr(exec_res, "signature_version", None) in ("v1_legacy", "v1_legacy_unversioned"):
                migrated_res = migrate_legacy_execution_result(exec_res, self.session_secret)
                rec.provenance["controlled_execution_result"] = migrated_res.to_dict()
                if isinstance(rec.details, dict) and "controlled_execution_result" in rec.details:
                    rec.details["controlled_execution_result"] = migrated_res.to_dict()
                return True
            return False

    def to_dict(self) -> Dict[str, Any]:
        """Serialize full ledger to dictionary."""
        return strip_sensitive_session_secrets({
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "created_at": self.created_at,
            "record_count": len(self._records),
            "used_causal_attestation_ids": list(getattr(self, "_used_causal_attestation_ids", set())),
            "causal_attestation_to_evidence_id": dict(getattr(self, "_causal_attestation_to_evidence_id", {})),
            "operation_to_evidence_ids": {k: list(v) for k, v in getattr(self, "_operation_to_evidence_ids", {}).items()},
            "operation_to_receipt_id": dict(getattr(self, "_operation_to_receipt_id", {})),
            "used_operation_ids": getattr(self, "_used_operation_ids", {}),
            "records": [r.to_dict() for r in self._records],
        })

    def to_json(self, indent: Optional[int] = 2) -> str:
        """Serialize ledger to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: Dict[str, Any], trust_store: Optional[Any] = None) -> "EvidenceLedger":
        """Reconstruct EvidenceLedger from serialized dictionary.

        Authoritative indexes are rebuilt strictly from validated records and compared
        against serialized indexes rather than blindly merged. Rejects forged mappings,
        invalid parent relationships, cardinality violations, and inconsistent identity.
        Failed reconstruction admits no partial state.
        """
        if not isinstance(data, dict):
            raise ValueError("EvidenceLedger serialization data must be a dictionary")

        schema_ver = data.get("schema_version", EVIDENCE_SCHEMA_VERSION)
        session_id = data.get("session_id")
        ledger = cls(
            session_id=session_id,
            schema_version=schema_ver,
            trust_store=trust_store,
        )
        ledger.created_at = data.get("created_at", ledger.created_at)
        ledger._used_causal_attestation_ids = set()
        ledger._causal_attestation_to_evidence_id = {}
        ledger._used_operation_ids = {}
        ledger._operation_to_evidence_ids = {}
        ledger._operation_to_receipt_id = {}

        seen_ids = set()
        raw_records = data.get("records", [])
        if not isinstance(raw_records, list):
            raise ValueError("Serialized ledger 'records' field must be a list")

        # 1. Transactionally validate and add each record, rebuilding authoritative state
        for rec_data in raw_records:
            if not isinstance(rec_data, dict):
                raise ValueError("Malformed evidence record in serialized ledger: must be a dictionary")
            rec = EvidenceRecord.from_dict(rec_data)
            if rec.evidence_id in seen_ids:
                raise ValueError(f"Duplicate evidence_id '{rec.evidence_id}' during ledger reconstruction")
            seen_ids.add(rec.evidence_id)
            ledger.add_record(rec)

        # 2. Extract rebuilt authoritative indexes
        rebuilt_causal_ids = set(ledger._used_causal_attestation_ids)
        rebuilt_causal_to_eid = dict(ledger._causal_attestation_to_evidence_id)
        rebuilt_used_ops = dict(ledger._used_operation_ids)
        rebuilt_op_to_ev = {k: list(v) for k, v in ledger._operation_to_evidence_ids.items()}
        rebuilt_op_to_rcpt = dict(ledger._operation_to_receipt_id)

        # 3. Strictly compare serialized indexes against rebuilt authoritative indexes
        if "used_causal_attestation_ids" in data:
            ser_causal_ids = set(data.get("used_causal_attestation_ids", []))
            if ser_causal_ids != rebuilt_causal_ids:
                raise ValueError(
                    f"Authoritative index mismatch during reconstruction: serialized used_causal_attestation_ids "
                    f"differs from validated records index (serialized={ser_causal_ids}, rebuilt={rebuilt_causal_ids})"
                )

        if "causal_attestation_to_evidence_id" in data:
            ser_causal_to_eid = dict(data.get("causal_attestation_to_evidence_id", {}))
            if ser_causal_to_eid != rebuilt_causal_to_eid:
                raise ValueError(
                    f"Forged or conflicting index detected: serialized causal_attestation_to_evidence_id "
                    f"does not match authoritative validated records mapping"
                )

        if "operation_to_receipt_id" in data:
            ser_op_to_rcpt = dict(data.get("operation_to_receipt_id", {}))
            if ser_op_to_rcpt != rebuilt_op_to_rcpt:
                raise ValueError(
                    f"Forged or conflicting index detected: serialized operation_to_receipt_id "
                    f"does not match authoritative validated records mapping"
                )

        if "operation_to_evidence_ids" in data:
            ser_op_to_ev = {k: list(v) for k, v in data.get("operation_to_evidence_ids", {}).items()}
            if set(ser_op_to_ev.keys()) != set(rebuilt_op_to_ev.keys()):
                raise ValueError(
                    f"Operation mapping mismatch: serialized operation keys differ from validated records"
                )
            for op_k, ev_list in ser_op_to_ev.items():
                if len(ev_list) != len(set(ev_list)):
                    raise ValueError(
                        f"Duplicate evidence ID detected in serialized operation_to_evidence_ids for operation '{op_k}': {ev_list}"
                    )
                rebuilt_list = rebuilt_op_to_ev.get(op_k, [])
                if ev_list != rebuilt_list:
                    raise ValueError(
                        f"Evidence mapping mismatch for operation '{op_k}': "
                        f"serialized={ev_list}, rebuilt={rebuilt_list}"
                    )

        if "used_operation_ids" in data:
            ser_used_ops = dict(data.get("used_operation_ids", {}))
            if set(ser_used_ops.keys()) != set(rebuilt_used_ops.keys()):
                missing = set(rebuilt_used_ops.keys()) - set(ser_used_ops.keys())
                extra = set(ser_used_ops.keys()) - set(rebuilt_used_ops.keys())
                raise ValueError(
                    f"Forged operation mapping detected: key-set mismatch between serialized and rebuilt "
                    f"used_operation_ids: missing={sorted(list(missing))}, extra={sorted(list(extra))}"
                )
            ALLOWED_OP_FIELDS = {
                "session_id", "pid", "process_identity", "executable_identity",
                "build_id", "target_host", "receipt_id", "observation_digest",
                "operation_type", "evidence_id", "evidence_ids", "recorded_at",
                "observation", "field", "parent_evidence_digest", "derived_from",
                "parent_evidence_ids", "physical_bytes_read", "physical_reads_count",
                "adapter_id", "initial_flag"
            }
            for op_k, op_dict in ser_used_ops.items():
                if not isinstance(op_dict, dict):
                    raise ValueError(f"used_operation_ids entry '{op_k}' must be a dictionary")
                rebuilt_rec = rebuilt_used_ops[op_k]

                # 1. Reject unexpected fields where schema requires strictness
                for fld in op_dict.keys():
                    if fld not in ALLOWED_OP_FIELDS:
                        raise ValueError(f"Unexpected metadata field '{fld}' in serialized used_operation_ids for operation '{op_k}'")

                # 2. Canonical metadata fields validation (detect missing and conflicting metadata)
                for canon_f in (
                    "session_id", "pid", "process_identity", "executable_identity",
                    "build_id", "target_host", "receipt_id", "observation_digest",
                    "operation_type", "evidence_id", "recorded_at"
                ):
                    rebuilt_val = rebuilt_rec.get(canon_f)
                    ser_val = op_dict.get(canon_f)
                    # Missing metadata check: if non-empty in rebuilt record, must be present and non-empty in serialized
                    if rebuilt_val is not None and str(rebuilt_val) != "" and (ser_val is None or str(ser_val) == ""):
                        raise ValueError(f"Missing canonical metadata field '{canon_f}' in serialized used_operation_ids for operation '{op_k}'")
                    # Conflicting metadata check
                    if ser_val is not None and rebuilt_val is not None and str(ser_val) != "" and str(rebuilt_val) != "":
                        if canon_f == "pid":
                            if int(ser_val) != int(rebuilt_val):
                                raise ValueError(f"PID inconsistency for operation '{op_k}': serialized={ser_val}, rebuilt={rebuilt_val}")
                        elif canon_f == "session_id":
                            if str(ser_val) != str(rebuilt_val):
                                raise ValueError(f"Session inconsistency for operation '{op_k}': serialized={ser_val}, rebuilt={rebuilt_val}")
                        elif str(ser_val) != str(rebuilt_val):
                            raise ValueError(f"Metadata conflict / metadata mismatch for operation '{op_k}', field '{canon_f}': serialized={ser_val}, rebuilt={rebuilt_val}")

                # 3. Canonical ordered evidence_ids validation and duplicate rejection
                if "evidence_ids" in op_dict:
                    ser_eids = op_dict["evidence_ids"]
                    if not isinstance(ser_eids, list):
                        raise ValueError(f"evidence_ids for operation '{op_k}' must be a list")
                    if len(ser_eids) != len(set(ser_eids)):
                        raise ValueError(f"Duplicate evidence ID detected in used_operation_ids evidence_ids for operation '{op_k}'")
                    rebuilt_eids = rebuilt_rec.get("evidence_ids", [])
                    if ser_eids != rebuilt_eids:
                        raise ValueError(f"Canonical ordered evidence_ids mismatch for operation '{op_k}': serialized={ser_eids}, rebuilt={rebuilt_eids}")

        return ledger

    @classmethod
    def from_json(cls, json_str: str) -> "EvidenceLedger":
        """Reconstruct EvidenceLedger from JSON string."""
        return cls.from_dict(json.loads(json_str))


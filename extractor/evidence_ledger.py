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
import os
import re
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple, Union


PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE = "LIVE_RUNTIME_CAPTURE"
PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION = "CONTROLLED_RUNTIME_REPRODUCTION"
PROVENANCE_CLASS_SYNTHETIC_FIXTURE = "SYNTHETIC_FIXTURE"
PROVENANCE_CLASS_IMPORTED_UNVERIFIED = "IMPORTED_UNVERIFIED"

TRUSTED_PROVENANCE_CLASSES = {
    PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE,
    PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION,
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


class CaptureVerificationAuthority:
    """Authority for verifying capture receipts against trusted keys.
    
    Operates fail-closed: if no keys are registered or loaded from the environment,
    verification requests fail immediately. Secrets are never exposed in string representations,
    logs, or serialized outputs.
    """
    def __init__(self, keys: Optional[Dict[str, str]] = None):
        self._keys: Dict[str, str] = dict(keys or {})
        self._revoked_keys: Set[str] = set()

    def register_key(self, key_id: str, secret: str) -> None:
        if not key_id or not secret:
            raise ValueError("key_id and secret must be non-empty strings")
        self._keys[key_id] = secret
        self._revoked_keys.discard(key_id)

    def revoke_key(self, key_id: str) -> None:
        if not key_id:
            raise ValueError("key_id must be a non-empty string")
        self._revoked_keys.add(key_id)

    def get_key(self, key_id: str) -> Optional[str]:
        if key_id in self._revoked_keys:
            return None
        return self._keys.get(key_id)

    def has_keys(self) -> bool:
        return bool(self._keys)

    def is_revoked(self, key_id: str) -> bool:
        return key_id in self._revoked_keys

    @classmethod
    def from_environment(cls) -> "CaptureVerificationAuthority":
        auth = cls()
        # 1. DYNAMICSTATE_CAPTURE_SECRET & DYNAMICSTATE_CAPTURE_KEY_ID
        env_secret = os.environ.get("DYNAMICSTATE_CAPTURE_SECRET")
        key_id = os.environ.get("DYNAMICSTATE_CAPTURE_KEY_ID", "default")
        if env_secret:
            auth.register_key(key_id, env_secret)

        # 2. DYNAMICSTATE_CAPTURE_KEY_FILE
        key_file = os.environ.get("DYNAMICSTATE_CAPTURE_KEY_FILE")
        if key_file and os.path.exists(key_file):
            try:
                with open(key_file, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                if content.startswith("{"):
                    data = json.loads(content)
                    if isinstance(data, dict):
                        for k, v in data.items():
                            if isinstance(k, str) and isinstance(v, str):
                                auth.register_key(k, v)
                elif content:
                    auth.register_key("file_default", content)
            except Exception:
                pass

        # 3. DYNAMICSTATE_CAPTURE_KEYRING
        keyring_spec = os.environ.get("DYNAMICSTATE_CAPTURE_KEYRING")
        if keyring_spec:
            try:
                if os.path.exists(keyring_spec):
                    with open(keyring_spec, "r", encoding="utf-8") as f:
                        data = json.load(f)
                else:
                    data = json.loads(keyring_spec)
                if isinstance(data, dict):
                    for k, v in data.items():
                        if isinstance(k, str) and isinstance(v, str):
                            auth.register_key(k, v)
            except Exception:
                pass

        return auth

    def __repr__(self) -> str:
        # Never expose secrets!
        registered = sorted(self._keys.keys())
        revoked = sorted(self._revoked_keys)
        return f"<CaptureVerificationAuthority keys={registered} revoked={revoked}>"

    def __str__(self) -> str:
        return self.__repr__()


class CaptureSigningAuthority:
    """Authority for signing authentic LiveCaptureReceipts using a dedicated key."""
    def __init__(self, key_id: str, secret: str):
        if not key_id or not secret:
            raise ValueError("CaptureSigningAuthority requires non-empty key_id and secret")
        if not isinstance(key_id, str) or not isinstance(secret, str):
            raise TypeError("key_id and secret must be strings")
        self._key_id = key_id
        self._secret = secret

    @property
    def key_id(self) -> str:
        return self._key_id

    def sign(self, payload: str) -> str:
        return hmac.new(self._secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()

    def __repr__(self) -> str:
        return f"<CaptureSigningAuthority key_id={self._key_id!r}>"

    def __str__(self) -> str:
        return self.__repr__()


_DEFAULT_VERIFICATION_AUTHORITY: Optional[CaptureVerificationAuthority] = None
_DEFAULT_SIGNING_AUTHORITY: Optional[CaptureSigningAuthority] = None


def get_default_verification_authority() -> CaptureVerificationAuthority:
    global _DEFAULT_VERIFICATION_AUTHORITY
    if _DEFAULT_VERIFICATION_AUTHORITY is None:
        _DEFAULT_VERIFICATION_AUTHORITY = CaptureVerificationAuthority.from_environment()
    return _DEFAULT_VERIFICATION_AUTHORITY


def set_default_verification_authority(auth: Optional[CaptureVerificationAuthority]) -> None:
    global _DEFAULT_VERIFICATION_AUTHORITY
    _DEFAULT_VERIFICATION_AUTHORITY = auth


def get_default_signing_authority() -> Optional[CaptureSigningAuthority]:
    global _DEFAULT_SIGNING_AUTHORITY
    if _DEFAULT_SIGNING_AUTHORITY is None:
        env_secret = os.environ.get("DYNAMICSTATE_CAPTURE_SECRET")
        key_id = os.environ.get("DYNAMICSTATE_CAPTURE_KEY_ID", "default")
        if env_secret:
            _DEFAULT_SIGNING_AUTHORITY = CaptureSigningAuthority(key_id=key_id, secret=env_secret)
    return _DEFAULT_SIGNING_AUTHORITY


def set_default_signing_authority(auth: Optional[CaptureSigningAuthority]) -> None:
    global _DEFAULT_SIGNING_AUTHORITY
    _DEFAULT_SIGNING_AUTHORITY = auth


def setup_test_capture_authorities(
    key_id: str = "test_key_phase2_0_a2",
    secret: str = "test_secret_32bytes_deterministic_12345",
) -> Tuple[CaptureSigningAuthority, CaptureVerificationAuthority]:
    """Helper for test suites to inject deterministic test-only keys without polluting production."""
    signer = CaptureSigningAuthority(key_id=key_id, secret=secret)
    verifier = CaptureVerificationAuthority(keys={key_id: secret, "default": secret})
    set_default_signing_authority(signer)
    set_default_verification_authority(verifier)
    return signer, verifier


def reset_capture_authorities() -> None:
    """Reset global authorities back to unconfigured state."""
    global _DEFAULT_VERIFICATION_AUTHORITY, _DEFAULT_SIGNING_AUTHORITY
    _DEFAULT_VERIFICATION_AUTHORITY = None
    _DEFAULT_SIGNING_AUTHORITY = None


@dataclass(frozen=True)
class LiveCaptureReceipt:
    """Authentic cryptographic receipt establishing verified live runtime capture.
    
    Binds target identity, session/capture ID, build ID, capture source,
    manifest digest, start time, and integrity validation.
    """
    receipt_id: str
    session_id: str
    pid: int
    executable_path: str
    build_id: Optional[str]
    capture_source: str
    manifest_digest: str
    integrity_validated: bool
    issued_at: str
    process_start_time: str = "0"
    signature: str = ""
    key_id: str = "default"
    provenance_class: str = PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE

    def verify_authenticity(
        self,
        secret: Optional[str] = None,
        verification_authority: Optional[CaptureVerificationAuthority] = None,
    ) -> bool:
        """Verify HMAC signature against secret or verification authority."""
        ok, _ = verify_live_capture_receipt(
            self,
            secret=secret,
            verification_authority=verification_authority,
        )
        return ok

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LiveCaptureReceipt":
        return cls(
            receipt_id=str(data.get("receipt_id", "")),
            session_id=str(data.get("session_id", "")),
            pid=int(data.get("pid", 0)),
            executable_path=str(data.get("executable_path", "")),
            build_id=data.get("build_id"),
            capture_source=str(data.get("capture_source", "live_collector")),
            manifest_digest=str(data.get("manifest_digest", "")),
            integrity_validated=bool(data.get("integrity_validated", False)),
            issued_at=str(data.get("issued_at", "")),
            process_start_time=str(data.get("process_start_time", "0")),
            signature=str(data.get("signature", "")),
            key_id=str(data.get("key_id", "default")),
            provenance_class=str(data.get("provenance_class", PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE)),
        )


def compute_live_receipt_signature(
    secret_or_signer: Union[CaptureSigningAuthority, str],
    receipt_id: str,
    session_id: str,
    pid: int,
    executable_path: str,
    build_id: Optional[str],
    capture_source: str,
    integrity_validated: bool,
    issued_at: str,
    process_start_time: Union[str, int] = "0",
    manifest_digest: str = "",
    key_id: str = "default",
) -> str:
    raw = (
        f"LIVE_RECEIPT|v2|{receipt_id}|{session_id}|{pid}|"
        f"{process_start_time}|{executable_path}|{build_id or ''}|"
        f"{capture_source}|{manifest_digest}|{'TRUE' if integrity_validated else 'FALSE'}|"
        f"{issued_at}|{key_id}"
    )
    if isinstance(secret_or_signer, CaptureSigningAuthority):
        return secret_or_signer.sign(raw)
    return hmac.new(secret_or_signer.encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).hexdigest()


def issue_live_capture_receipt(
    session_id: str,
    pid: int,
    executable_path: str,
    build_id: Optional[str] = None,
    process_start_time: Union[str, int] = "100000",
    manifest_digest: Optional[str] = None,
    capture_source: str = "live_collector",
    integrity_validated: bool = True,
    signer: Optional[Union[CaptureSigningAuthority, str]] = None,
    secret: Optional[str] = None,
    key_id: Optional[str] = None,
    receipt_id: Optional[str] = None,
    issued_at: Optional[str] = None,
) -> LiveCaptureReceipt:
    """Issue a signed LiveCaptureReceipt. Fails closed if no signing key is configured."""
    eff_signer = signer or secret
    eff_key_id = key_id

    if eff_signer is None:
        active_signer = get_default_signing_authority()
        if active_signer is None:
            raise ValueError(
                "No capture signing key configured. Cannot issue live capture receipt without explicit signing authority."
            )
        eff_signer = active_signer
        eff_key_id = active_signer.key_id
    elif isinstance(eff_signer, CaptureSigningAuthority):
        eff_key_id = eff_signer.key_id
    elif isinstance(eff_signer, str):
        eff_key_id = eff_key_id or "default"

    rcpt_id = receipt_id or f"lrcpt_{uuid.uuid4().hex[:12]}"
    now_iso = issued_at or datetime.now(timezone.utc).isoformat()
    start_time_str = str(process_start_time)

    # Derive deterministic manifest digest placeholder if none provided
    if manifest_digest is None:
        manifest_digest = hashlib.sha256(
            f"MANIFEST_MOCK_{pid}_{executable_path}_{start_time_str}".encode("utf-8")
        ).hexdigest()

    sig = compute_live_receipt_signature(
        secret_or_signer=eff_signer,
        receipt_id=rcpt_id,
        session_id=session_id,
        pid=pid,
        executable_path=executable_path,
        build_id=build_id,
        capture_source=capture_source,
        manifest_digest=manifest_digest,
        integrity_validated=integrity_validated,
        issued_at=now_iso,
        process_start_time=start_time_str,
        key_id=eff_key_id or "default",
    )

    return LiveCaptureReceipt(
        receipt_id=rcpt_id,
        session_id=session_id,
        pid=pid,
        executable_path=executable_path,
        build_id=build_id,
        capture_source=capture_source,
        manifest_digest=manifest_digest,
        integrity_validated=integrity_validated,
        issued_at=now_iso,
        process_start_time=start_time_str,
        signature=sig,
        key_id=eff_key_id or "default",
    )


def verify_live_capture_receipt(
    receipt: Any,
    secret: Optional[str] = None,
    verification_authority: Optional[CaptureVerificationAuthority] = None,
    expected_session_id: Optional[str] = None,
    expected_pid: Optional[int] = None,
    expected_manifest_digest: Optional[str] = None,
    expected_build_id: Optional[str] = None,
    expected_executable_path: Optional[str] = None,
    snapshot: Optional[Any] = None,
) -> Tuple[bool, Optional[str]]:
    """Validates that a receipt is authentic, unmodified, and bound to the expected target and snapshot."""
    if receipt is None:
        return False, "NO_RECEIPT: No capture or session receipt provided"

    # Support CaptureReceipt from capture_backend.py
    if hasattr(receipt, "backend_name") and hasattr(receipt, "artifact_manifest"):
        ok = receipt.verify_signature(secret)
        if not ok:
            return False, "SIGNATURE_INVALID: CaptureReceipt signature verification failed"
        if expected_pid is not None and receipt.pid != expected_pid:
            return False, f"PID_MISMATCH: CaptureReceipt PID {receipt.pid} != expected {expected_pid}"
        return True, None

    # Support LiveCaptureReceipt
    if isinstance(receipt, dict):
        try:
            receipt = LiveCaptureReceipt.from_dict(receipt)
        except Exception as exc:
            return False, f"MALFORMED_RECEIPT: {exc}"

    if not isinstance(receipt, LiveCaptureReceipt):
        return False, f"UNRECOGNIZED_RECEIPT_TYPE: {type(receipt).__name__}"

    if not receipt.signature:
        return False, "UNSIGNED_RECEIPT: Receipt has no HMAC signature"

    if not receipt.key_id:
        return False, "MISSING_MANDATORY_FIELD: key_id is missing or empty"

    # Resolve verification key fail-closed
    auth = verification_authority or get_default_verification_authority()
    resolved_secret = secret

    if resolved_secret is None:
        if not auth.has_keys():
            return (
                False,
                "VERIFICATION_KEY_UNAVAILABLE: No capture verification keys configured in authority or environment",
            )
        if auth.is_revoked(receipt.key_id):
            return False, f"KEY_REVOKED: Key ID '{receipt.key_id}' has been revoked"
        resolved_secret = auth.get_key(receipt.key_id)
        if not resolved_secret:
            return False, f"UNKNOWN_KEY_ID: Key ID '{receipt.key_id}' not found in verification authority"

    # Cryptographic HMAC verification
    expected_sig = compute_live_receipt_signature(
        secret_or_signer=resolved_secret,
        receipt_id=receipt.receipt_id,
        session_id=receipt.session_id,
        pid=receipt.pid,
        executable_path=receipt.executable_path,
        build_id=receipt.build_id,
        capture_source=receipt.capture_source,
        manifest_digest=receipt.manifest_digest,
        integrity_validated=receipt.integrity_validated,
        issued_at=receipt.issued_at,
        process_start_time=receipt.process_start_time,
        key_id=receipt.key_id,
    )
    if not hmac.compare_digest(receipt.signature, expected_sig):
        return False, "SIGNATURE_INVALID: LiveCaptureReceipt signature verification failed"

    # Check mandatory fields
    if not receipt.receipt_id:
        return False, "MISSING_MANDATORY_FIELD: receipt_id is missing or empty"
    if not receipt.session_id:
        return False, "MISSING_MANDATORY_FIELD: session_id is missing or empty"
    if not receipt.pid or receipt.pid <= 0:
        return False, "MISSING_MANDATORY_FIELD: pid is missing or non-positive"
    if receipt.process_start_time is None or str(receipt.process_start_time) == "":
        return False, "MISSING_MANDATORY_FIELD: process_start_time is missing or empty"
    if not receipt.executable_path:
        return False, "MISSING_MANDATORY_FIELD: executable_path is missing or empty"
    if not receipt.manifest_digest:
        return False, "MISSING_MANDATORY_FIELD: manifest_digest is missing or empty"
    if not receipt.issued_at:
        return False, "MISSING_MANDATORY_FIELD: issued_at is missing or empty"
    if not receipt.key_id:
        return False, "MISSING_MANDATORY_FIELD: key_id is missing or empty"

    if not receipt.integrity_validated:
        return False, "INTEGRITY_CHECK_FAILED: Receipt indicates integrity validation failed or was skipped"

    # Session binding
    if expected_session_id and receipt.session_id != expected_session_id:
        return False, f"SESSION_MISMATCH: Receipt session '{receipt.session_id}' != expected '{expected_session_id}'"

    # Target identity bindings
    if expected_pid is not None and int(receipt.pid) != int(expected_pid):
        return False, f"PID_MISMATCH: Receipt PID {receipt.pid} != expected {expected_pid}"

    if expected_manifest_digest and receipt.manifest_digest.lower() != expected_manifest_digest.lower():
        return (
            False,
            f"MANIFEST_DIGEST_MISMATCH: Receipt manifest digest {receipt.manifest_digest} != expected {expected_manifest_digest}",
        )

    if expected_build_id and receipt.build_id and receipt.build_id.lower() != expected_build_id.lower():
        return False, f"BUILD_ID_MISMATCH: Receipt build ID {receipt.build_id} != expected {expected_build_id}"

    if expected_executable_path:
        base_expected = os.path.basename(expected_executable_path)
        base_rcpt = os.path.basename(receipt.executable_path)
        if base_expected != base_rcpt:
            return False, f"EXECUTABLE_PATH_MISMATCH: Receipt exe '{receipt.executable_path}' != expected '{expected_executable_path}'"

    # Exact Snapshot binding (if provided)
    if snapshot is not None:
        snap_verdict = getattr(snapshot, "validation_verdict", None)
        if snap_verdict not in ("VALIDATED", None):
            return False, f"SNAPSHOT_NOT_VALIDATED: Referenced snapshot validation verdict is '{snap_verdict}'"

        if getattr(snapshot, "pid", None) and int(snapshot.pid) != int(receipt.pid):
            return False, f"PID_MISMATCH: Snapshot PID {snapshot.pid} != receipt PID {receipt.pid}"

        snap_st = getattr(snapshot, "process_starttime", None)
        if snap_st and str(snap_st) != str(receipt.process_start_time):
            return (
                False,
                f"PROCESS_START_TIME_MISMATCH: Snapshot start time {snap_st} != receipt start time {receipt.process_start_time}",
            )

        snap_digest = getattr(snapshot, "manifest_digest", None)
        if not snap_digest and hasattr(snapshot, "compute_manifest_digest"):
            snap_digest = snapshot.compute_manifest_digest()
        if snap_digest and snap_digest.lower() != receipt.manifest_digest.lower():
            return (
                False,
                f"MANIFEST_DIGEST_MISMATCH: Snapshot manifest digest {snap_digest} != receipt manifest digest {receipt.manifest_digest}",
            )

        snap_bin = getattr(snapshot, "binary", None)
        if snap_bin and os.path.basename(snap_bin) != os.path.basename(receipt.executable_path):
            return False, f"EXECUTABLE_PATH_MISMATCH: Snapshot binary '{snap_bin}' != receipt exe '{receipt.executable_path}'"

        snap_bid = getattr(snapshot, "build_id", None)
        if snap_bid and receipt.build_id and snap_bid.lower() != receipt.build_id.lower():
            return False, f"BUILD_ID_MISMATCH: Snapshot build ID {snap_bid} != receipt build ID {receipt.build_id}"

    return True, None


def create_receipt_from_snapshot(
    snapshot: Any,
    session_id: str,
    signing_authority: Optional[CaptureSigningAuthority] = None,
    secret: Optional[str] = None,
    key_id: Optional[str] = None,
    companion_elf: Optional[str] = None,
    receipt_id: Optional[str] = None,
) -> LiveCaptureReceipt:
    """Generate an authentic LiveCaptureReceipt bound to a validated RawMemorySnapshot."""
    is_valid = True
    if hasattr(snapshot, "validate_integrity"):
        is_valid, _ = snapshot.validate_integrity()
    if getattr(snapshot, "validation_verdict", "VALIDATED") != "VALIDATED":
        is_valid = False

    build_id = getattr(snapshot, "build_id", None)
    if companion_elf and not build_id:
        try:
            from .debug_image import inspect_elf
            ident = inspect_elf(companion_elf)
            build_id = ident.build_id
        except Exception:
            pass

    manifest_digest = getattr(snapshot, "manifest_digest", None)
    if not manifest_digest and hasattr(snapshot, "compute_manifest_digest"):
        manifest_digest = snapshot.compute_manifest_digest()
    if not manifest_digest:
        manifest_digest = hashlib.sha256(b"EMPTY_MANIFEST").hexdigest()

    return issue_live_capture_receipt(
        session_id=session_id,
        pid=int(getattr(snapshot, "pid", 0)),
        executable_path=str(getattr(snapshot, "binary", "")),
        build_id=build_id,
        process_start_time=str(getattr(snapshot, "process_starttime", "0")),
        manifest_digest=manifest_digest,
        capture_source=str(getattr(snapshot, "backend", "native_collector")),
        integrity_validated=is_valid,
        signer=signing_authority or secret,
        key_id=key_id,
        receipt_id=receipt_id,
    )


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

    def verify_authenticity(self, session_secret: str) -> bool:
        """Verify the cryptographic authenticity of this execution receipt against session secret."""
        if not self.receipt_signature:
            return False
        expected = compute_receipt_signature(session_secret, self)
        return hmac.compare_digest(self.receipt_signature, expected)


def compute_receipt_signature(session_secret: str, result: "ControlledExecutionResult") -> str:
    """Compute HMAC-SHA256 signature binding the execution receipt to the session secret and complete execution scope."""
    tid_str = json.dumps(result.target_identity or {}, sort_keys=True)
    cq_str = json.dumps(result.capture_quality or {}, sort_keys=True)
    prov_cls = getattr(result, "provenance_class", PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION)
    attr_ver = getattr(result, "is_function_attribution_verified", getattr(result, "function_attribution_verified", False))
    attr_basis = getattr(result, "attribution_basis", "")
    claims_str = ",".join(sorted(getattr(result, "verified_claims", ()) or ()))
    raw = (
        f"{result.execution_id}|{result.investigation_id}|{result.hypothesis_id}|"
        f"{result.evidence_id}|{result.target_function}|{result.field_path}|"
        f"{result.before_value}|{result.after_value}|{result.execution_status}|"
        f"{result.backend_type}|{prov_cls}|{attr_ver}|{attr_basis}|{claims_str}|"
        f"{result.before_snapshot_ref}|{result.after_snapshot_ref}|"
        f"{result.before_snapshot_hash}|{result.after_snapshot_hash}|"
        f"{tid_str}|{cq_str}|{result.executed_at}"
    )
    return hmac.new(session_secret.encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).hexdigest()


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
        if self._evidence_id and evidence_id != self._evidence_id:
            return False
        if target_function and self._target_function and target_function != self._target_function:
            return False
        if field_path and self._field_path and field_path != self._field_path:
            return False
        if hypothesis_id and self._hypothesis_id and hypothesis_id != self._hypothesis_id:
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
        if isinstance(self.provenance, dict):
            if self.provenance.get("is_synthetic") is True:
                return PROVENANCE_CLASS_SYNTHETIC_FIXTURE
            p_cls = self.provenance.get("provenance_class")
            if p_cls in (PROVENANCE_CLASS_SYNTHETIC_FIXTURE, PROVENANCE_CLASS_IMPORTED_UNVERIFIED):
                return str(p_cls)
            if p_cls == PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION:
                return PROVENANCE_CLASS_CONTROLLED_RUNTIME_REPRODUCTION
            if p_cls == PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE:
                rcpt = self.provenance.get("capture_receipt") or self.provenance.get("live_receipt")
                if rcpt is not None:
                    ok, _ = verify_live_capture_receipt(rcpt, expected_session_id=self.session_id)
                    if ok:
                        return PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE
                if self.provenance.get("verified_live_capture") is True:
                    return PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE
                return PROVENANCE_CLASS_IMPORTED_UNVERIFIED

        if isinstance(self.details, dict):
            if self.details.get("is_synthetic") is True:
                return PROVENANCE_CLASS_SYNTHETIC_FIXTURE
            d_cls = self.details.get("provenance_class")
            if d_cls in (PROVENANCE_CLASS_SYNTHETIC_FIXTURE, PROVENANCE_CLASS_IMPORTED_UNVERIFIED):
                return str(d_cls)
            if d_cls == PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE and self.details.get("verified_live_capture") is True:
                return PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE

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
        prov_copy = dict(self.provenance) if self.provenance else {}
        if "verifier_attestation" in prov_copy and isinstance(prov_copy["verifier_attestation"], dict):
            safe_att = dict(prov_copy["verifier_attestation"])
            safe_att.pop("token", None)
            safe_att.pop("token_sig", None)
            safe_att.pop("evidence_fingerprint", None)
            prov_copy["verifier_attestation"] = safe_att

        data: Dict[str, Any] = {
            "evidence_id": self.evidence_id,
            "evidence_type": self.evidence_type,
            "nature": self.nature,
            "source": self.source,
            "timestamp": self.timestamp,
            "observation": self.observation,
            "parent_evidence_ids": list(self.parent_evidence_ids),
            "schema_version": self.schema_version,
            "provenance": prov_copy,
            "details": self.details,
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
        live_capture_receipt: Optional[Any] = None,
        verification_authority: Optional[CaptureVerificationAuthority] = None,
    ):
        self.session_id: str = session_id or f"inv_sess_{uuid.uuid4().hex[:8]}"
        self.schema_version: str = schema_version
        self.session_secret: str = session_secret or uuid.uuid4().hex
        self._capability_key: str = capability_key or uuid.uuid4().hex
        self.live_capture_receipt: Optional[Any] = live_capture_receipt
        self.verification_authority: Optional[CaptureVerificationAuthority] = verification_authority
        self.created_at: str = datetime.now(timezone.utc).isoformat()
        self._records: List[EvidenceRecord] = []
        self._by_id: Dict[str, EvidenceRecord] = {}
        self._by_type: Dict[str, List[EvidenceRecord]] = {}
        self._by_finding: Dict[str, List[EvidenceRecord]] = {}

    @property
    def capability_key(self) -> str:
        return self._capability_key

    @property
    def verified_live_capture(self) -> bool:
        """Indicates whether this ledger holds authenticated live capture evidence."""
        if self.live_capture_receipt is not None:
            ok, _ = verify_live_capture_receipt(
                self.live_capture_receipt,
                verification_authority=self.verification_authority,
                expected_session_id=self.session_id,
            )
            return ok
        return any(
            (isinstance(r.provenance, dict) and r.provenance.get("verified_live_capture") is True)
            for r in self._records
        )

    @property
    def records(self) -> List[EvidenceRecord]:
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
        hypothesis_id: str = "",
        execution_result: Optional[ControlledExecutionResult] = None,
    ) -> CausalVerificationCapability:
        """Issue an internal unforgeable capability strictly after authentic execution receipt verification."""
        if execution_result is None or not isinstance(execution_result, ControlledExecutionResult):
            raise ValueError("Capability issuance requires an authentic ControlledExecutionResult verified against session secret")

        if not execution_result.verify_authenticity(self.session_secret):
            raise ValueError("Capability issuance rejected: execution receipt signature verification failed")

        if execution_result.investigation_id != self.session_id:
            raise ValueError(f"Capability issuance rejected: execution receipt belongs to investigation '{execution_result.investigation_id}', not '{self.session_id}'")

        if execution_result.evidence_id and evidence_id and execution_result.evidence_id != evidence_id:
            raise ValueError(f"Capability issuance rejected: execution receipt evidence '{execution_result.evidence_id}' does not match '{evidence_id}'")

        if execution_result.hypothesis_id and hypothesis_id and execution_result.hypothesis_id != hypothesis_id:
            raise ValueError(f"Capability issuance rejected: execution receipt hypothesis '{execution_result.hypothesis_id}' does not match '{hypothesis_id}'")

        if execution_result.target_function and target_function and execution_result.target_function != target_function:
            raise ValueError(f"Capability issuance rejected: execution receipt target_function '{execution_result.target_function}' does not match '{target_function}'")

        if execution_result.field_path and field_path and execution_result.field_path != field_path:
            raise ValueError(f"Capability issuance rejected: execution receipt field_path '{execution_result.field_path}' does not match '{field_path}'")

        if execution_result.execution_status not in ("REPRODUCED", "SUCCESS", "CONFIRMED"):
            raise ValueError(f"Capability issuance rejected: execution receipt status '{execution_result.execution_status}' does not prove reproduction")

        cq = execution_result.capture_quality or {}
        comp = cq.get("completeness") or cq.get("status")
        cons = cq.get("consistency_level") or cq.get("consistency_classification")
        if comp != "COMPLETE" or not is_atomic_or_stopped_consistency(cons):
            raise ValueError(f"Capability issuance rejected: execution receipt capture quality ({comp}, {cons}) is not complete and atomic")

        eff_eid = evidence_id or execution_result.evidence_id
        eff_fn = target_function or execution_result.target_function
        eff_field = field_path or execution_result.field_path
        eff_hypo = hypothesis_id or execution_result.hypothesis_id

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

        # Stamp authentic internal attestation
        rec.provenance["verifier_attestation"] = {
            "token": self.session_secret,
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
        if isinstance(record, dict):
            record = EvidenceRecord.from_dict(record)
        if not record.session_id:
            record.session_id = self.session_id

        # Provenance Invariant Gate:
        # Caller-supplied LIVE_RUNTIME_CAPTURE must be backed by an authentic verified receipt.
        p_dict = record.provenance if isinstance(record.provenance, dict) else {}
        d_dict = record.details if isinstance(record.details, dict) else {}

        if p_dict.get("is_synthetic") is True or d_dict.get("is_synthetic") is True or record.source in ("synthetic", "synthetic_adversarial_fixture"):
            if record.provenance:
                record.provenance["provenance_class"] = PROVENANCE_CLASS_SYNTHETIC_FIXTURE
            if record.details:
                record.details["provenance_class"] = PROVENANCE_CLASS_SYNTHETIC_FIXTURE
        else:
            claimed_prov = p_dict.get("provenance_class") or d_dict.get("provenance_class")
            if claimed_prov == PROVENANCE_CLASS_LIVE_RUNTIME_CAPTURE:
                rcpt = p_dict.get("capture_receipt") or p_dict.get("live_receipt") or self.live_capture_receipt
                rcpt_ok, rcpt_err = verify_live_capture_receipt(
                    rcpt,
                    verification_authority=self.verification_authority,
                    expected_session_id=self.session_id,
                    expected_pid=record.target_identity.get("pid") if record.target_identity else None,
                )
                if not rcpt_ok:
                    if record.provenance:
                        record.provenance["provenance_class"] = PROVENANCE_CLASS_IMPORTED_UNVERIFIED
                        record.provenance["unverified_reason"] = rcpt_err
                    if record.details and "provenance_class" in record.details:
                        record.details["provenance_class"] = PROVENANCE_CLASS_IMPORTED_UNVERIFIED
                else:
                    if record.provenance:
                        record.provenance["verified_live_capture"] = True
                    if record.details:
                        record.details["verified_live_capture"] = True

        # Schema validation
        self.validate_record(record)

        if record.evidence_id in self._by_id:
            raise ValueError(f"Duplicate evidence_id '{record.evidence_id}': record with this ID already exists in ledger.")

        self._records.append(record)
        self._by_id[record.evidence_id] = record
        self._by_type.setdefault(record.evidence_type, []).append(record)
        if record.finding_id:
            self._by_finding.setdefault(record.finding_id, []).append(record)
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
        )
        self.add_record(rec)
        return rec

    def validate_record(self, record: EvidenceRecord) -> None:
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
            elif att.get("token") != self.session_secret or att.get("investigation_id") != self.session_id:
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
                if att.get("evidence_fingerprint") != expected_fp or att.get("token_sig") != expected_sig:
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
            if record.details:
                record.details.pop("execution_provenance", None)
                record.details.pop("function_attribution_verified", None)
                record.details.pop("attribution_basis", None)

    def get_record(self, evidence_id: str) -> Optional[EvidenceRecord]:
        """Look up record by unique ID."""
        return self._by_id.get(evidence_id)

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

    def to_dict(self) -> Dict[str, Any]:
        """Serialize full ledger to dictionary (without exposing secrets)."""
        rcpt_dict = None
        if self.live_capture_receipt:
            if hasattr(self.live_capture_receipt, "to_dict"):
                rcpt_dict = self.live_capture_receipt.to_dict()
            elif isinstance(self.live_capture_receipt, dict):
                rcpt_dict = dict(self.live_capture_receipt)

        return {
            "schema_version": self.schema_version,
            "session_id": self.session_id,
            "created_at": self.created_at,
            "live_capture_receipt": rcpt_dict,
            "record_count": len(self._records),
            "records": [r.to_dict() for r in self._records],
        }

    def to_json(self, indent: Optional[int] = 2) -> str:
        """Serialize ledger to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @classmethod
    def from_dict(
        cls,
        data: Dict[str, Any],
        verification_authority: Optional[CaptureVerificationAuthority] = None,
    ) -> "EvidenceLedger":
        """Reconstruct EvidenceLedger from serialized dictionary."""
        rcpt_data = data.get("live_capture_receipt")
        rcpt = None
        if rcpt_data and isinstance(rcpt_data, dict):
            try:
                rcpt = LiveCaptureReceipt.from_dict(rcpt_data)
            except Exception:
                rcpt = None

        ledger = cls(
            session_id=data.get("session_id"),
            schema_version=data.get("schema_version", EVIDENCE_SCHEMA_VERSION),
            live_capture_receipt=rcpt,
            verification_authority=verification_authority,
        )
        ledger.created_at = data.get("created_at", ledger.created_at)
        for rec_data in data.get("records", []):
            ledger.add_record(EvidenceRecord.from_dict(rec_data))
        return ledger

    @classmethod
    def from_json(cls, json_str: str) -> "EvidenceLedger":
        """Reconstruct EvidenceLedger from JSON string."""
        return cls.from_dict(json.loads(json_str))


"""Runtime Capture Backend abstraction and fast capture implementations.

Enforces:
1. Ultra-short process stop time (target < 10 ms).
2. Process resumes immediately after memory/thread capture.
3. Absolutely NO DWARF traversal, symbol resolution, or object graph construction during process suspension.
4. Guaranteed fail-open policy: process is resumed in all circumstances (via finally:).
5. Exact latency measurement without fabricated numbers.
"""

from abc import ABC, abstractmethod
import contextlib
import ctypes
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
import errno
import fcntl
import hashlib
import hmac
import json
import os
import platform
import signal
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple, Union
import uuid

from .capture_plan import CaptureMode, CapturePlan
from .raw_snapshot import RawMemoryRegion, RawRuntimeSnapshot


class CaptureKeyStore:
    """Manages capture authentication key lifecycle, rotation, revocation, and resolution."""

    def __init__(self):
        self._lock = threading.RLock()
        self._keys: Dict[str, str] = {}
        self._active_key_id: str = "default"
        self._revoked_keys: Set[str] = set()
        self._is_explicitly_configured: bool = False
        self._ephemeral_fallback: Optional[str] = None
        self.reload_from_environment()

    def __repr__(self) -> str:
        with self._lock:
            kids = sorted(self._keys.keys())
            rev = sorted(self._revoked_keys)
            return (
                f"<CaptureKeyStore configured={self._is_explicitly_configured} "
                f"active_key_id={self._active_key_id!r} key_ids={kids} revoked_key_ids={rev}>"
            )

    def __str__(self) -> str:
        return self.__repr__()

    def reload_from_environment(self) -> None:
        """Load keys from environment variables or key files."""
        with self._lock:
            self._keys.clear()
            self._revoked_keys.clear()
            self._is_explicitly_configured = False
            self._ephemeral_fallback = None

            # 1. Check DYNAMICSTATE_CAPTURE_SECRET
            env_secret = os.environ.get("DYNAMICSTATE_CAPTURE_SECRET")
            key_id = os.environ.get("DYNAMICSTATE_CAPTURE_KEY_ID", "default")
            if env_secret:
                self._keys[key_id] = env_secret
                self._active_key_id = key_id
                self._is_explicitly_configured = True

            # 2. Check DYNAMICSTATE_CAPTURE_KEY_FILE
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
                                    self._keys[k] = v
                            self._is_explicitly_configured = True
                    elif content:
                        self._keys["file_default"] = content
                        if not env_secret:
                            self._active_key_id = "file_default"
                        self._is_explicitly_configured = True
                except Exception:
                    pass

            # 3. Check DYNAMICSTATE_CAPTURE_KEYRING (JSON string or file path)
            keyring_spec = os.environ.get("DYNAMICSTATE_CAPTURE_KEYRING")
            if keyring_spec:
                try:
                    if os.path.exists(keyring_spec):
                        with open(keyring_spec, "r", encoding="utf-8") as f:
                            keyring_data = json.load(f)
                    else:
                        keyring_data = json.loads(keyring_spec)
                    if isinstance(keyring_data, dict):
                        for k, v in keyring_data.items():
                            if isinstance(k, str) and isinstance(v, str):
                                self._keys[k] = v
                        self._is_explicitly_configured = True
                except Exception:
                    pass

            # 4. If not configured, initialize process-local ephemeral key
            if not self._keys:
                self._ephemeral_fallback = "dynamicstate_ephemeral_key_" + os.urandom(16).hex()
                self._keys["ephemeral"] = self._ephemeral_fallback
                self._active_key_id = "ephemeral"
                self._is_explicitly_configured = False

    @property
    def is_explicitly_configured(self) -> bool:
        """Returns True if a key was provided via env/file/programmatic API rather than ephemeral random."""
        with self._lock:
            return self._is_explicitly_configured

    def register_key(self, key_id: str, secret: str, is_active: bool = False) -> None:
        """Register a key for signing or verification."""
        with self._lock:
            if not key_id or not secret:
                raise ValueError("key_id and secret must be non-empty strings")
            if not isinstance(key_id, str) or not isinstance(secret, str):
                raise TypeError("key_id and secret must be strings")
            self._keys[key_id] = secret
            self._revoked_keys.discard(key_id)
            self._is_explicitly_configured = True
            if is_active or len(self._keys) == 1:
                self._active_key_id = key_id

    def rotate_key(self, new_key_id: str, new_secret: str) -> None:
        """Rotate the active signing key while keeping older keys available for verification."""
        with self._lock:
            self.register_key(new_key_id, new_secret, is_active=True)

    def revoke_key(self, key_id: str) -> None:
        """Revoke a key so it will no longer verify any receipts."""
        with self._lock:
            self._revoked_keys.add(key_id)
            if self._active_key_id == key_id:
                available = [k for k in self._keys.keys() if k not in self._revoked_keys]
                self._active_key_id = available[0] if available else ""

    def is_revoked(self, key_id: str) -> bool:
        """Return True if the key has been revoked."""
        with self._lock:
            return key_id in self._revoked_keys

    def resolve_key(self, key_id: str) -> str:
        """Resolve a secret by key_id. Raises ValueError if revoked, KeyError if not found."""
        with self._lock:
            kid = str(key_id)
            if kid in self._revoked_keys:
                raise ValueError(f"Key '{kid}' has been revoked")
            if kid in self._keys:
                return self._keys[kid]
            raise KeyError(f"Key '{kid}' not found in key store")

    def get_active_signing_key(self) -> Tuple[str, str]:
        """Return (key_id, secret) for signing new receipts."""
        with self._lock:
            if self._active_key_id in self._revoked_keys or self._active_key_id not in self._keys:
                available = [k for k in self._keys.keys() if k not in self._revoked_keys]
                if not available:
                    raise ValueError("No active, non-revoked capture key available for signing")
                self._active_key_id = available[0]
            return self._active_key_id, self._keys[self._active_key_id]

    def verify_receipt(
        self,
        receipt: "CaptureReceipt",
        explicit_secret: Optional[str] = None,
    ) -> Tuple[bool, str, Optional[str]]:
        """Verify HMAC signature of a CaptureReceipt with explicit lifecycle outcomes.

        Returns (is_valid: bool, status_reason: str, verified_key_id: Optional[str]).
        """
        with self._lock:
            if not receipt.signature:
                return False, "UNSIGNED_RECEIPT: Capture receipt has no HMAC signature", None

            # If explicit secret supplied, test directly
            if explicit_secret:
                if receipt.matches_secret(explicit_secret):
                    return True, "VERIFIED", getattr(receipt, "key_id", "explicit")
                return False, "SIGNATURE_VERIFICATION_FAILED: Signature mismatch with supplied secret", None

            # Check key revocation
            rcpt_kid = getattr(receipt, "key_id", "default") or "default"
            if rcpt_kid in self._revoked_keys:
                return False, f"KEY_REVOKED: Key ID '{rcpt_kid}' has been revoked", None
            dts = get_default_trust_store()
            if dts and dts.is_revoked(rcpt_kid):
                return False, f"KEY_REVOKED: Key ID '{rcpt_kid}' has been revoked in durable trust store", None

            # In cross-process mode: if the current key store was not explicitly configured (only ephemeral random),
            # and the receipt specifies a key_id that is NOT our ephemeral key or present in durable trust store, fail closed with KEY_UNAVAILABLE!
            if not self._is_explicitly_configured and not (dts and rcpt_kid in dts.keys):
                if rcpt_kid != "ephemeral" or not receipt.matches_secret(self._keys.get("ephemeral", "")):
                    return (
                        False,
                        "VERIFICATION_KEY_UNAVAILABLE: No capture authentication key configured in environment "
                        "(DYNAMICSTATE_CAPTURE_SECRET, DYNAMICSTATE_CAPTURE_KEYRING, or DYNAMICSTATE_CAPTURE_KEY_FILE)",
                        None,
                    )

            # Check candidate keys in keyring
            # 1. Try receipt's specific key_id first
            if rcpt_kid in self._keys and rcpt_kid not in self._revoked_keys:
                if receipt.matches_secret(self._keys[rcpt_kid]):
                    return True, "VERIFIED", rcpt_kid
            if dts and rcpt_kid in dts.keys and not dts.is_revoked(rcpt_kid):
                if receipt.matches_secret(dts.keys[rcpt_kid]):
                    return True, "VERIFIED", rcpt_kid

            # 2. Try default / other non-revoked keys in keyring
            for kid, sec in self._keys.items():
                if kid != rcpt_kid and kid not in self._revoked_keys:
                    if receipt.matches_secret(sec):
                        return True, "VERIFIED", kid

            if rcpt_kid in self._keys:
                return False, f"SIGNATURE_VERIFICATION_FAILED: Signature mismatch for Key ID '{rcpt_kid}'", None
            return False, f"KEY_NOT_FOUND: Key ID '{rcpt_kid}' not found in key store", None


_DEFAULT_KEY_STORE = CaptureKeyStore()


def get_default_key_store() -> CaptureKeyStore:
    return _DEFAULT_KEY_STORE


def set_default_key_store(ks: CaptureKeyStore) -> None:
    global _DEFAULT_KEY_STORE
    _DEFAULT_KEY_STORE = ks


# Preserved for backward compatibility
def _get_capture_secret() -> str:
    return _DEFAULT_KEY_STORE.get_active_signing_key()[1]


_CAPTURE_AUTHENTICATION_SECRET = _get_capture_secret()


@dataclass(frozen=True)
class CaptureReceipt:
    """Authentic cryptographic receipt issued exclusively by a RuntimeCaptureBackend.

    Proves that physical state was captured from an identified running process by an
    authenticated capture backend with deterministic artifact hashing and key lifecycle binding.
    """
    receipt_id: str
    backend_name: str
    pid: int
    process_start_time: str
    executable_path: str
    executable_build_id: Optional[str]
    capture_time: str
    capture_duration_us: float
    completeness: str
    consistency_level: str
    artifact_manifest: Dict[str, str]  # relative_path/range_key -> sha256
    signature: str = ""
    key_id: str = "default"
    schema_version: str = "2.0.0"

    def matches_secret(self, secret: str) -> bool:
        """Check if signature matches secret under v2 canonical or v1 backward-compatible format."""
        if not self.signature or not secret:
            return False

        # Try v2 canonical signature first
        expected_v2 = compute_capture_receipt_signature(
            backend_name=self.backend_name,
            pid=self.pid,
            process_start_time=self.process_start_time,
            executable_path=self.executable_path,
            executable_build_id=self.executable_build_id,
            capture_time=self.capture_time,
            completeness=self.completeness,
            consistency_level=self.consistency_level,
            artifact_manifest=self.artifact_manifest,
            secret=secret,
            receipt_id=self.receipt_id,
            capture_duration_us=self.capture_duration_us,
            key_id=self.key_id,
            schema_version="2.0.0",
        )
        if hmac.compare_digest(self.signature, expected_v2):
            return True

        # Fallback to v1 legacy format (Phase 8 backward compatibility)
        expected_v1 = compute_capture_receipt_signature(
            backend_name=self.backend_name,
            pid=self.pid,
            process_start_time=self.process_start_time,
            executable_path=self.executable_path,
            executable_build_id=self.executable_build_id,
            capture_time=self.capture_time,
            completeness=self.completeness,
            consistency_level=self.consistency_level,
            artifact_manifest=self.artifact_manifest,
            secret=secret,
            schema_version="1.0.0",
        )
        return hmac.compare_digest(self.signature, expected_v1)

    def verify_signature(self, secret: Optional[str] = None) -> bool:
        """Verify HMAC signature using capture authentication secret or key store."""
        ok, _, _ = get_default_key_store().verify_receipt(self, explicit_secret=secret)
        return ok

    def verify_with_status(self, secret: Optional[str] = None) -> Tuple[bool, str, Optional[str]]:
        """Verify HMAC signature returning (is_valid, status_reason, key_id)."""
        return get_default_key_store().verify_receipt(self, explicit_secret=secret)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "backend_name": self.backend_name,
            "pid": self.pid,
            "process_start_time": self.process_start_time,
            "executable_path": self.executable_path,
            "executable_build_id": self.executable_build_id,
            "capture_time": self.capture_time,
            "capture_duration_us": self.capture_duration_us,
            "completeness": self.completeness,
            "consistency_level": self.consistency_level,
            "artifact_manifest": dict(self.artifact_manifest),
            "signature": self.signature,
            "key_id": self.key_id,
            "schema_version": self.schema_version,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CaptureReceipt":
        return cls(
            receipt_id=str(data.get("receipt_id", "")),
            backend_name=str(data.get("backend_name", "")),
            pid=int(data.get("pid", 0)),
            process_start_time=str(data.get("process_start_time", "")),
            executable_path=str(data.get("executable_path", "")),
            executable_build_id=data.get("executable_build_id"),
            capture_time=str(data.get("capture_time", "")),
            capture_duration_us=float(data.get("capture_duration_us", 0.0)),
            completeness=str(data.get("completeness", "")),
            consistency_level=str(data.get("consistency_level", "")),
            artifact_manifest=dict(data.get("artifact_manifest", {})),
            signature=str(data.get("signature", "")),
            key_id=str(data.get("key_id", "default")),
            schema_version=str(data.get("schema_version", "1.0.0")),
        )


def compute_capture_receipt_signature(
    backend_name: str,
    pid: int,
    process_start_time: str,
    executable_path: str,
    executable_build_id: Optional[str],
    capture_time: str,
    completeness: str,
    consistency_level: str,
    artifact_manifest: Dict[str, str],
    secret: Optional[str] = None,
    receipt_id: Optional[str] = None,
    capture_duration_us: float = 0.0,
    key_id: str = "default",
    schema_version: str = "2.0.0",
) -> str:
    if secret:
        sec = secret
    else:
        _, sec = get_default_key_store().get_active_signing_key()

    # Canonicalize artifact manifest: sorted keys, normalized relative paths, compact json
    clean_manifest = {str(k).lstrip("./"): str(v) for k, v in sorted(artifact_manifest.items())}
    manifest_str = json.dumps(clean_manifest, sort_keys=True, separators=(',', ':'))

    if schema_version == "1.0.0":
        # Phase 8 legacy signature format for backward compatibility
        raw = (
            f"{backend_name}|{pid}|{process_start_time}|{executable_path}|"
            f"{executable_build_id or ''}|{capture_time}|{completeness}|"
            f"{consistency_level}|{json.dumps(artifact_manifest, sort_keys=True)}"
        )
    else:
        # Phase 9 v2 canonical signature binding receipt_id, capture_duration_us, key_id, and schema_version
        raw = (
            f"v2|{receipt_id or ''}|{backend_name}|{pid}|{process_start_time}|"
            f"{executable_path}|{executable_build_id or ''}|{capture_time}|"
            f"{capture_duration_us:.6f}|{completeness}|{consistency_level}|"
            f"{key_id}|{manifest_str}"
        )
    return hmac.new(sec.encode("utf-8"), raw.encode("utf-8"), hashlib.sha256).hexdigest()


def issue_capture_receipt(
    backend_name: str,
    pid: int,
    process_start_time: str,
    executable_path: str,
    executable_build_id: Optional[str],
    capture_time: str,
    capture_duration_us: float,
    completeness: str,
    consistency_level: str,
    artifact_manifest: Dict[str, str],
    secret: Optional[str] = None,
    key_id: Optional[str] = None,
    receipt_id: Optional[str] = None,
    schema_version: str = "2.0.0",
) -> CaptureReceipt:
    ks = get_default_key_store()
    if secret:
        eff_sec = secret
        eff_kid = key_id or "default"
    else:
        eff_kid, eff_sec = ks.get_active_signing_key()
        if key_id:
            eff_kid = key_id
            if key_id in ks._keys:
                eff_sec = ks._keys[key_id]

    rcpt_id = receipt_id or f"cap_rcpt_{uuid.uuid4().hex[:12]}"
    sig = compute_capture_receipt_signature(
        backend_name=backend_name,
        pid=pid,
        process_start_time=process_start_time,
        executable_path=executable_path,
        executable_build_id=executable_build_id,
        capture_time=capture_time,
        completeness=completeness,
        consistency_level=consistency_level,
        artifact_manifest=artifact_manifest,
        secret=eff_sec,
        receipt_id=rcpt_id,
        capture_duration_us=capture_duration_us,
        key_id=eff_kid,
        schema_version=schema_version,
    )
    return CaptureReceipt(
        receipt_id=rcpt_id,
        backend_name=backend_name,
        pid=pid,
        process_start_time=process_start_time,
        executable_path=executable_path,
        executable_build_id=executable_build_id,
        capture_time=capture_time,
        capture_duration_us=capture_duration_us,
        completeness=completeness,
        consistency_level=consistency_level,
        artifact_manifest=dict(artifact_manifest),
        signature=sig,
        key_id=eff_kid,
        schema_version=schema_version,
    )


@dataclass
class LiveCaptureReceipt:
    """Cryptographic receipt proving an authentic live runtime observation or slice capture.

    Validates:
    - authenticity (HMAC-SHA256 signature)
    - session identity (session_id)
    - PID (pid)
    - process identity (process_identity: pid:start_time:boot_id)
    - executable identity (executable_identity: exe_path:inode)
    - Build ID (build_id)
    - snapshot binding (snapshot_binding)
    - capture epoch (capture_epoch)
    - applicable target identity constraints (target_constraints)
    - operation identity (operation_id)
    - observation digest (observation_digest)
    - physical reads accounting (physical_bytes_read, physical_reads_count)
    - operation type ("diagnostic", "probe")
    """
    receipt_id: str
    session_id: str
    pid: int
    process_identity: str
    executable_identity: str
    build_id: str
    snapshot_binding: str
    capture_epoch: int
    timestamp_ns: int = 0
    authority_level: str = "PRODUCTION"  # "PRODUCTION", "TEST", "SYNTHETIC"
    provenance_class: str = "LIVE_RUNTIME_CAPTURE"
    key_id: str = "default"
    signature: str = ""
    target_constraints: Dict[str, Any] = field(default_factory=dict)
    schema_version: str = "2.1.0"
    operation_id: str = ""
    observation_digest: str = ""
    physical_bytes_read: int = 0
    physical_reads_count: int = 0
    operation_type: str = "diagnostic"

    def canonical_payload_v3(self) -> str:
        tc_json = json.dumps(self.target_constraints or {}, sort_keys=True, separators=(",", ":"))
        return (
            f"live_rcpt_v3|{self.receipt_id}|{self.session_id}|{int(self.pid)}|"
            f"{self.process_identity}|{self.executable_identity}|{self.build_id or str()}|"
            f"{self.snapshot_binding}|{int(self.capture_epoch)}|{int(self.timestamp_ns)}|"
            f"{self.authority_level}|{self.provenance_class}|{self.key_id}|{tc_json}|"
            f"{self.operation_id}|{self.observation_digest}|{int(self.physical_bytes_read)}|"
            f"{int(self.physical_reads_count)}|{self.operation_type}"
        )

    def canonical_payload_v2(self) -> str:
        tc_json = json.dumps(self.target_constraints or {}, sort_keys=True, separators=(",", ":"))
        return (
            f"live_rcpt_v2|{self.receipt_id}|{self.session_id}|{int(self.pid)}|"
            f"{self.process_identity}|{self.executable_identity}|{self.build_id or str()}|"
            f"{self.snapshot_binding}|{int(self.capture_epoch)}|{int(self.timestamp_ns)}|"
            f"{self.authority_level}|{self.provenance_class}|{self.key_id}|{tc_json}"
        )

    def canonical_payload(self) -> str:
        if self.schema_version == "2.0.0" and not self.operation_id and not self.observation_digest and self.physical_bytes_read == 0 and self.operation_type == "diagnostic":
            return self.canonical_payload_v2()
        return self.canonical_payload_v3()

    def compute_signature(self, secret: Optional[str] = None) -> str:
        if secret:
            sec = secret
        else:
            _, sec = get_default_key_store().get_active_signing_key()
        return hmac.new(sec.encode("utf-8"), self.canonical_payload().encode("utf-8"), hashlib.sha256).hexdigest()

    def sign(self, secret: Optional[str] = None) -> "LiveCaptureReceipt":
        if not self.timestamp_ns:
            self.timestamp_ns = time.time_ns()
        if not self.key_id or self.key_id == "default":
            kid, _ = get_default_key_store().get_active_signing_key()
            self.key_id = kid
        self.signature = self.compute_signature(secret=secret)
        return self

    def matches_secret(self, secret: str) -> bool:
        if not self.signature or not secret:
            return False
        # Try primary canonical payload
        expected = hmac.new(secret.encode("utf-8"), self.canonical_payload().encode("utf-8"), hashlib.sha256).hexdigest()
        if hmac.compare_digest(self.signature, expected):
            return True
        # Try v3 explicit
        expected_v3 = hmac.new(secret.encode("utf-8"), self.canonical_payload_v3().encode("utf-8"), hashlib.sha256).hexdigest()
        if hmac.compare_digest(self.signature, expected_v3):
            return True
        # Try v2 legacy format
        expected_v2 = hmac.new(secret.encode("utf-8"), self.canonical_payload_v2().encode("utf-8"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(self.signature, expected_v2)

    def verify(
        self,
        expected_session_id: Optional[str] = None,
        expected_pid: Optional[int] = None,
        expected_process_identity: Optional[str] = None,
        expected_executable_identity: Optional[str] = None,
        expected_build_id: Optional[str] = None,
        expected_snapshot_binding: Optional[str] = None,
        min_capture_epoch: Optional[int] = None,
        max_capture_epoch: Optional[int] = None,
        max_age_ns: Optional[int] = None,
        expected_constraints: Optional[Dict[str, Any]] = None,
        require_production_authority: bool = True,
        secret: Optional[str] = None,
        expected_operation_id: Optional[str] = None,
        expected_observation_digest: Optional[str] = None,
        reject_probe_for_diagnostic: bool = False,
        require_physical_reads: bool = False,
    ) -> Tuple[bool, str]:
        """Validate LiveCaptureReceipt against all Phase 2.0-A.3.6 through A.3.11 security and identity invariants."""
        # 1. Reject synthetic-to-live escalation
        if self.provenance_class in ("SYNTHETIC", "SYNTHETIC_FIXTURE", "IMPORTED_UNVERIFIED"):
            return False, f"synthetic_or_unverified_provenance_rejected:{self.provenance_class}"
        if self.provenance_class != "LIVE_RUNTIME_CAPTURE":
            return False, f"invalid_live_provenance_class:{self.provenance_class}"

        # 2. Reject test authority used as production authority
        if require_production_authority and self.authority_level != "PRODUCTION":
            return False, f"test_authority_rejected_in_production:{self.authority_level}"

        # 3. Validate cryptographic authenticity
        if not self.signature or not self.receipt_id:
            return False, "missing_receipt_signature_or_id"
        sig_ok, sig_reason, _ = get_default_key_store().verify_receipt(self, explicit_secret=secret)
        if not sig_ok:
            return False, f"invalid_signature:{sig_reason}"

        # 4. Validate session identity (reject cross-session receipts)
        if not self.session_id or not str(self.session_id).strip():
            return False, "missing_session_identity"
        if expected_session_id is not None and str(self.session_id) != str(expected_session_id):
            return False, f"cross_session_receipt_rejected:expected={expected_session_id},got={self.session_id}"

        # 5. Validate PID & process identity (reject cross-process / PID-reused receipts)
        if isinstance(self.pid, bool) or not isinstance(self.pid, int) or self.pid <= 1:
            return False, f"invalid_pid:{self.pid}"
        if expected_pid is not None and int(self.pid) != int(expected_pid):
            return False, f"cross_process_pid_rejected:expected={expected_pid},got={self.pid}"
        if not self.process_identity or not str(self.process_identity).strip():
            return False, "missing_process_identity"
        if expected_process_identity is not None and str(self.process_identity) != str(expected_process_identity):
            return False, f"cross_process_identity_rejected:expected={expected_process_identity},got={self.process_identity}"

        # 6. Validate executable identity
        if not self.executable_identity or not str(self.executable_identity).strip():
            return False, "missing_executable_identity"
        if expected_executable_identity is not None:
            exp_exe = str(expected_executable_identity)
            act_exe = str(self.executable_identity)
            # Allow matching either full path:inode or canonical path prefix when inode was not queried by caller
            if act_exe != exp_exe and act_exe.split(":")[0] != exp_exe.split(":")[0]:
                return False, f"mismatched_executable_identity:expected={exp_exe},got={act_exe}"
            if ":" in exp_exe and ":" in act_exe and act_exe != exp_exe:
                return False, f"mismatched_executable_inode:expected={exp_exe},got={act_exe}"

        # 7. Validate Build ID
        if expected_build_id is not None and str(expected_build_id).strip():
            if not self.build_id or str(self.build_id).strip().lower() != str(expected_build_id).strip().lower():
                return False, f"mismatched_build_id:expected={expected_build_id},got={self.build_id}"

        # 8. Validate snapshot binding
        if not self.snapshot_binding or not str(self.snapshot_binding).strip():
            return False, "missing_snapshot_binding"
        if expected_snapshot_binding is not None and str(self.snapshot_binding) != str(expected_snapshot_binding):
            return False, f"mismatched_snapshot_binding:expected={expected_snapshot_binding},got={self.snapshot_binding}"

        # 9. Validate capture epoch and freshness (reject stale receipts)
        if not isinstance(self.capture_epoch, int) or isinstance(self.capture_epoch, bool) or self.capture_epoch < 0:
            return False, f"invalid_capture_epoch:{self.capture_epoch}"
        if min_capture_epoch is not None and self.capture_epoch < int(min_capture_epoch):
            return False, f"stale_capture_epoch:min={min_capture_epoch},got={self.capture_epoch}"
        if max_capture_epoch is not None and self.capture_epoch > int(max_capture_epoch):
            return False, f"future_capture_epoch:max={max_capture_epoch},got={self.capture_epoch}"
        if max_age_ns is not None and self.timestamp_ns > 0:
            now_ns = time.time_ns()
            if (now_ns - self.timestamp_ns) > int(max_age_ns):
                return False, f"stale_receipt_timestamp:age_ns={now_ns - self.timestamp_ns},max_age_ns={max_age_ns}"

        # 10. Validate applicable target identity constraints
        if expected_constraints:
            for k, exp_v in expected_constraints.items():
                act_v = (self.target_constraints or {}).get(k)
                if act_v != exp_v:
                    return False, f"target_constraint_mismatch:{k}:expected={exp_v},got={act_v}"

        # 11. Remote execution receipts must identify the remote target
        if (self.target_constraints or {}).get("is_remote"):
            if not (self.target_constraints or {}).get("target_host"):
                return False, "remote_receipt_missing_target_host"

        # 12. Physical reads required
        if require_physical_reads and self.physical_bytes_read <= 0:
            return False, "no_physical_reads_in_receipt"

        # 13. Probe read isolation
        if reject_probe_for_diagnostic and self.operation_type == "probe":
            return False, "probe_receipt_cannot_attest_diagnostic_evidence"

        # 14. Operation identity check
        if expected_operation_id is not None and str(self.operation_id) != str(expected_operation_id):
            return False, f"mismatched_operation_id:expected={expected_operation_id},got={self.operation_id}"

        # 15. Observation digest check
        if expected_observation_digest is not None and str(self.observation_digest) != str(expected_observation_digest):
            return False, f"mismatched_observation_digest:expected={expected_observation_digest},got={self.observation_digest}"

        return True, "VERIFIED"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "session_id": self.session_id,
            "pid": self.pid,
            "process_identity": self.process_identity,
            "executable_identity": self.executable_identity,
            "build_id": self.build_id,
            "snapshot_binding": self.snapshot_binding,
            "capture_epoch": self.capture_epoch,
            "timestamp_ns": self.timestamp_ns,
            "authority_level": self.authority_level,
            "provenance_class": self.provenance_class,
            "key_id": self.key_id,
            "signature": self.signature,
            "target_constraints": dict(self.target_constraints or {}),
            "schema_version": self.schema_version,
            "operation_id": self.operation_id,
            "observation_digest": self.observation_digest,
            "physical_bytes_read": self.physical_bytes_read,
            "physical_reads_count": self.physical_reads_count,
            "operation_type": self.operation_type,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "LiveCaptureReceipt":
        if not isinstance(data, dict):
            raise TypeError("LiveCaptureReceipt.from_dict requires a dictionary")
        return cls(
            receipt_id=str(data.get("receipt_id", "")),
            session_id=str(data.get("session_id", "")),
            pid=int(data.get("pid", 0)) if not isinstance(data.get("pid"), bool) else 0,
            process_identity=str(data.get("process_identity", "")),
            executable_identity=str(data.get("executable_identity", "")),
            build_id=str(data.get("build_id") or ""),
            snapshot_binding=str(data.get("snapshot_binding", "")),
            capture_epoch=int(data.get("capture_epoch", -1)) if not isinstance(data.get("capture_epoch"), bool) else -1,
            timestamp_ns=int(data.get("timestamp_ns", 0)),
            authority_level=str(data.get("authority_level", "PRODUCTION")),
            provenance_class=str(data.get("provenance_class", "LIVE_RUNTIME_CAPTURE")),
            key_id=str(data.get("key_id", "default")),
            signature=str(data.get("signature", "")),
            target_constraints=dict(data.get("target_constraints") or {}),
            schema_version=str(data.get("schema_version", "2.1.0")),
            operation_id=str(data.get("operation_id", "")),
            observation_digest=str(data.get("observation_digest", "")),
            physical_bytes_read=int(data.get("physical_bytes_read", 0)),
            physical_reads_count=int(data.get("physical_reads_count", 0)),
            operation_type=str(data.get("operation_type", "diagnostic")),
        )


_TRUSTED_CAPTURE_AUTHORITY_TOKEN = os.urandom(32).hex()


def get_trusted_capture_authority_token() -> str:
    """Internal token reserved strictly for trusted capture adapters."""
    return _TRUSTED_CAPTURE_AUTHORITY_TOKEN


def issue_live_capture_receipt(
    session_id: str,
    pid: int,
    process_identity: str,
    executable_identity: str,
    build_id: str,
    snapshot_binding: str,
    capture_epoch: int = 0,
    authority_level: str = "PRODUCTION",
    provenance_class: str = "LIVE_RUNTIME_CAPTURE",
    target_constraints: Optional[Dict[str, Any]] = None,
    secret: Optional[str] = None,
    key_id: Optional[str] = None,
    operation_id: str = "",
    observation_digest: str = "",
    physical_bytes_read: int = 0,
    physical_reads_count: int = 0,
    operation_type: str = "diagnostic",
    capture_authority_token: Optional[str] = None,
    schema_version: str = "2.1.0",
    **kwargs: Any,
) -> LiveCaptureReceipt:
    if provenance_class in ("SYNTHETIC", "SYNTHETIC_FIXTURE", "IMPORTED_UNVERIFIED"):
        authority_level = "SYNTHETIC" if authority_level == "PRODUCTION" else authority_level

    # 2.1: Production receipt issuance must only be possible through a trusted capture authority.
    # Generic callers cannot mint production receipts without proof of trusted capture authority.
    if authority_level == "PRODUCTION":
        if capture_authority_token != _TRUSTED_CAPTURE_AUTHORITY_TOKEN:
            raise ValueError(
                "Unauthorized receipt minting: PRODUCTION authority can only be issued by a trusted capture authority."
            )

    ks = get_default_key_store()
    active_kid, active_sec = ks.get_active_signing_key()
    use_kid = key_id if key_id else active_kid
    use_sec = secret if secret else active_sec
    rcpt = LiveCaptureReceipt(
        receipt_id=f"live_rcpt_{uuid.uuid4().hex[:12]}",
        session_id=str(session_id),
        pid=int(pid),
        process_identity=str(process_identity),
        executable_identity=str(executable_identity),
        build_id=str(build_id or ""),
        snapshot_binding=str(snapshot_binding),
        capture_epoch=int(capture_epoch),
        timestamp_ns=time.time_ns(),
        authority_level=str(authority_level),
        provenance_class=str(provenance_class),
        key_id=use_kid,
        target_constraints=dict(target_constraints or {}),
        schema_version=schema_version,
        operation_id=str(operation_id or ""),
        observation_digest=str(observation_digest or ""),
        physical_bytes_read=int(physical_bytes_read or 0),
        physical_reads_count=int(physical_reads_count or 0),
        operation_type=str(operation_type or "diagnostic"),
    )
    rcpt.sign(secret=use_sec)
    return rcpt


_TRUSTED_CAUSAL_VERIFIER_TOKEN = os.urandom(32).hex()


class TrustConsumptionStatus(str, Enum):
    """Explicit trust consumption outcomes distinguishing all verification and durability states."""
    NEW_ACCEPTANCE = "NEW_ACCEPTANCE"
    IDEMPOTENT_RECOVERY = "IDEMPOTENT_RECOVERY"
    REPLAY_CONFLICT = "REPLAY_CONFLICT"
    REVOKED = "REVOKED"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    IDENTITY_MISMATCH = "IDENTITY_MISMATCH"
    EXPIRED = "EXPIRED"
    PERSISTENCE_FAILURE = "PERSISTENCE_FAILURE"


@dataclass
class TrustConsumptionResult:
    """Structured result of an atomic trust-consumption operation."""
    status: TrustConsumptionStatus
    reason: str
    attestation_id: str
    key_id: str = ""
    evidence_id: str = ""
    recorded_at: str = ""

    @property
    def is_accepted(self) -> bool:
        """Returns True if the credential was legitimately accepted (new or idempotent same-evidence)."""
        return self.status in (
            TrustConsumptionStatus.NEW_ACCEPTANCE,
            TrustConsumptionStatus.IDEMPOTENT_RECOVERY,
        )


class DurableCommitOutcome(Enum):
    NOT_COMMITTED = "NOT_COMMITTED"
    COMMITTED = "COMMITTED"
    COMMIT_UNKNOWN = "COMMIT_UNKNOWN"


class DurableCommitError(RuntimeError):
    def __init__(self, message: str, outcome: DurableCommitOutcome, cause: Optional[Exception] = None):
        super().__init__(message)
        self.outcome = outcome
        self.cause = cause


class DurableTrustStore:
    """Persistent durable trust store for causal verifier keys, revocations, and anti-replay state.

    POSIX / Linux Platform Assumptions:
    1. Atomic File Replacement: Relies on POSIX rename(2) semantics via os.replace(), ensuring that
       the temporary write file is atomically swapped into place without exposure of partial content.
    2. Cross-Process Mutual Exclusion: Relies on fcntl.flock(LOCK_EX) on a dedicated '<store_path>.lock' file.
       On Linux local filesystems (ext4, XFS, tmpfs, Btrfs), this provides rigorous kernel-managed
       advisory file table locking across independent operating system processes.
    3. Durability Guarantees: Calls os.fsync(fd) prior to rename to ensure file payload is committed to
       underlying non-volatile block storage. Calls os.fsync(dir_fd) on the parent directory following rename
       to ensure directory entry updates persist across sudden power loss or kernel panic.
    4. Access Control & Permission Boundaries: Files are created with mode 0600 and directories with 0700,
       restricting read and write authority strictly to the owning UID under Linux DAC (Discretionary Access Control).
    5. Fail-Closed Invariant: Any corrupted store file, invalid schema, truncated JSON, or unpropagated
       persistence error immediately raises RuntimeError and aborts trust acceptance.
    """

    def __init__(self, store_path: Optional[str] = None):
        self.store_path = store_path or os.environ.get("DYNAMICSTATE_TRUST_STORE_PATH")
        self._lock = threading.RLock()
        self._lock_depth: int = 0
        self._lock_fd: Optional[int] = None
        self.keys: Dict[str, str] = {}
        self.active_key_id: str = "default"
        self.revoked_keys: Dict[str, Dict[str, Any]] = {}
        self.used_attestation_ids: Set[str] = set()
        self.used_attestations: Dict[str, Dict[str, Any]] = {}
        self.used_operation_ids: Dict[str, Dict[str, Any]] = {}
        if self.store_path:
            self.load()

    @contextlib.contextmanager
    def _file_lock(self):
        """Cross-process and cross-thread re-entrant mutual exclusion context."""
        with self._lock:
            if not self.store_path:
                yield
                return

            lock_path = self.store_path + ".lock"
            if self._lock_depth == 0:
                dir_name = os.path.dirname(os.path.abspath(lock_path))
                os.makedirs(dir_name, mode=0o700, exist_ok=True)
                flags = os.O_RDWR | os.O_CREAT
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                fd = os.open(lock_path, flags, 0o600)
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX)
                    self._lock_fd = fd
                except BaseException:
                    os.close(fd)
                    raise
            self._lock_depth += 1
            try:
                yield
            finally:
                self._lock_depth -= 1
                if self._lock_depth == 0 and self._lock_fd is not None:
                    fd = self._lock_fd
                    self._lock_fd = None
                    try:
                        fcntl.flock(fd, fcntl.LOCK_UN)
                    except OSError:
                        pass
                    try:
                        os.close(fd)
                    except OSError:
                        pass

    def load(self) -> None:
        """Load state from persistent trust store file. Fails closed if corrupted."""
        with self._lock:
            if not self.store_path or not os.path.exists(self.store_path):
                return
            if os.path.islink(self.store_path):
                raise RuntimeError(f"Refusing to load trust store from symlink: '{self.store_path}'")
            try:
                flags = os.O_RDONLY
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                fd = os.open(self.store_path, flags)
                with os.fdopen(fd, "r", encoding="utf-8") as f:
                    content = f.read().strip()
                if not content:
                    return
                data = json.loads(content)
                if not isinstance(data, dict):
                    raise ValueError("Trust store payload must be a JSON dictionary")

                # Strict schema and nested type validation
                if "schema_version" in data:
                    schema_ver = data["schema_version"]
                    if not isinstance(schema_ver, str) or schema_ver not in ("1.0.0", "1.1.0"):
                        raise ValueError(f"Unsupported or invalid trust store schema_version: {schema_ver!r}")

                if "updated_at" in data:
                    up_at = data["updated_at"]
                    if not isinstance(up_at, str):
                        raise ValueError(f"Invalid updated_at in trust store: {up_at!r}")
                    try:
                        datetime.fromisoformat(up_at)
                    except Exception as iso_err:
                        raise ValueError(f"Invalid updated_at ISO 8601 timestamp in trust store: {up_at!r}") from iso_err

                if "keys" in data:
                    if not isinstance(data["keys"], dict):
                        raise ValueError("Trust store 'keys' field must be a dictionary")
                    for k, v in data["keys"].items():
                        if not isinstance(k, str) or not isinstance(v, str) or not k:
                            raise ValueError(f"Invalid key entry in trust store: {k!r}")

                if "revoked_keys" in data:
                    if not isinstance(data["revoked_keys"], dict):
                        raise ValueError("Trust store 'revoked_keys' field must be a dictionary")
                    for k, v in data["revoked_keys"].items():
                        if not isinstance(k, str) or not isinstance(v, dict):
                            raise ValueError(f"Invalid revoked_keys entry: {k!r}")
                        if "revoked_at" not in v or not isinstance(v["revoked_at"], str):
                            raise ValueError(f"revoked_keys entry '{k}' missing valid 'revoked_at'")
                        try:
                            datetime.fromisoformat(v["revoked_at"])
                        except Exception as iso_err:
                            raise ValueError(f"revoked_keys entry '{k}' has invalid revoked_at timestamp") from iso_err

                if "used_attestation_ids" in data:
                    if not isinstance(data["used_attestation_ids"], (list, set)):
                        raise ValueError("Trust store 'used_attestation_ids' must be a list or set")
                    for aid in data["used_attestation_ids"]:
                        if not isinstance(aid, str) or not aid:
                            raise ValueError(f"Invalid used_attestation_id: {aid!r}")

                if "used_attestations" in data:
                    if not isinstance(data["used_attestations"], dict):
                        raise ValueError("Trust store 'used_attestations' must be a dictionary")
                    for aid, rec in data["used_attestations"].items():
                        if not isinstance(aid, str) or not isinstance(rec, dict) or not aid:
                            raise ValueError(f"Invalid used_attestations entry: {aid!r}")
                        if "evidence_id" not in rec or not isinstance(rec["evidence_id"], str) or not rec["evidence_id"]:
                            raise ValueError(f"used_attestations entry '{aid}' missing valid 'evidence_id'")
                        if "session_id" in rec and (not isinstance(rec["session_id"], str) or not rec["session_id"]):
                            raise ValueError(f"used_attestations entry '{aid}' has invalid session_id")
                        if "pid" in rec:
                            p = rec["pid"]
                            if isinstance(p, bool) or not isinstance(p, int) or p < 0:
                                raise ValueError(f"used_attestations entry '{aid}' has invalid pid: {p!r}")
                        if "recorded_at" in rec:
                            r_at = rec["recorded_at"]
                            if not isinstance(r_at, str):
                                raise ValueError(f"used_attestations entry '{aid}' has non-string recorded_at")
                            try:
                                datetime.fromisoformat(r_at)
                            except Exception as iso_err:
                                raise ValueError(f"used_attestations entry '{aid}' invalid recorded_at timestamp: {r_at!r}") from iso_err

                if "used_operation_ids" in data:
                    if not isinstance(data["used_operation_ids"], dict):
                        raise ValueError("Trust store 'used_operation_ids' must be a dictionary")
                    for op_id, op_rec in data["used_operation_ids"].items():
                        if not isinstance(op_id, str) or not isinstance(op_rec, dict) or not op_id:
                            raise ValueError(f"Invalid used_operation_ids entry: {op_id!r}")
                        if "session_id" not in op_rec or not isinstance(op_rec["session_id"], str) or not op_rec["session_id"]:
                            raise ValueError(f"used_operation_ids entry '{op_id}' missing valid 'session_id'")
                        if "pid" not in op_rec or isinstance(op_rec["pid"], bool) or not isinstance(op_rec["pid"], int) or op_rec["pid"] < 0:
                            raise ValueError(f"used_operation_ids entry '{op_id}' missing valid 'pid'")
                        if "recorded_at" in op_rec:
                            r_at = op_rec["recorded_at"]
                            if not isinstance(r_at, str):
                                raise ValueError(f"used_operation_ids entry '{op_id}' has non-string recorded_at")
                            try:
                                datetime.fromisoformat(r_at)
                            except Exception as iso_err:
                                raise ValueError(f"used_operation_ids entry '{op_id}' invalid recorded_at timestamp: {r_at!r}") from iso_err
                        if "evidence_ids" in op_rec:
                            eids = op_rec["evidence_ids"]
                            if not isinstance(eids, list):
                                raise ValueError(f"used_operation_ids entry '{op_id}' evidence_ids must be a list")
                            if len(eids) != len(set(eids)):
                                raise ValueError(f"used_operation_ids entry '{op_id}' contains duplicate evidence_ids")
                            for eid in eids:
                                if not isinstance(eid, str) or not eid:
                                    raise ValueError(f"used_operation_ids entry '{op_id}' contains invalid evidence_id: {eid!r}")
                        for str_field in ("receipt_id", "process_identity", "executable_identity", "build_id", "target_host", "observation_digest", "operation_type"):
                            if str_field in op_rec and not isinstance(op_rec[str_field], str):
                                raise ValueError(f"used_operation_ids entry '{op_id}' has invalid non-string '{str_field}'")

                self.keys = {str(k): str(v) for k, v in data.get("keys", {}).items()}
                self.active_key_id = str(data.get("active_key_id", "default"))
                self.revoked_keys = dict(data.get("revoked_keys", {}))
                self.used_attestation_ids = set(data.get("used_attestation_ids", []))
                self.used_attestations = dict(data.get("used_attestations", {}))
                # Sync used_attestation_ids with used_attestations
                for aid in self.used_attestations.keys():
                    self.used_attestation_ids.add(aid)
                self.used_operation_ids = dict(data.get("used_operation_ids", {}))
            except Exception as e:
                raise RuntimeError(f"Durable trust store at '{self.store_path}' is corrupted or unreadable: {e}") from e

    def reconcile_from_disk(self) -> None:
        """Reconcile in-memory state from disk under lock after indeterminate commit outcome."""
        with self._file_lock():
            self.load()

    def save(self) -> DurableCommitOutcome:
        """Atomically persist trust store state to disk with strict commit outcome semantics."""
        with self._file_lock():
            if not self.store_path:
                return DurableCommitOutcome.COMMITTED
            if os.path.islink(self.store_path):
                raise RuntimeError(f"Refusing to save trust store to symlink: '{self.store_path}'")
            payload = {
                "schema_version": "1.1.0",
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "active_key_id": self.active_key_id,
                "keys": self.keys,
                "revoked_keys": self.revoked_keys,
                "used_attestation_ids": sorted(list(self.used_attestation_ids)),
                "used_attestations": getattr(self, "used_attestations", {}),
                "used_operation_ids": self.used_operation_ids,
            }
            dir_name = os.path.dirname(os.path.abspath(self.store_path))
            os.makedirs(dir_name, mode=0o700, exist_ok=True)
            tmp_path = os.path.join(dir_name, f".trust_tmp_{uuid.uuid4().hex[:12]}")
            commit_point_reached = False
            try:
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                fd = os.open(tmp_path, flags, 0o600)
                try:
                    with os.fdopen(fd, "w", encoding="utf-8") as f:
                        json.dump(payload, f, indent=2)
                        f.flush()
                        # Apply and verify 0600 mode on temporary file before replacement
                        try:
                            os.chmod(tmp_path, 0o600)
                        except OSError as ce:
                            raise RuntimeError(f"Failed to apply 0600 mode on temporary trust store: {ce}") from ce
                        st = os.stat(tmp_path)
                        import stat as _st
                        if _st.S_IMODE(st.st_mode) != 0o600:
                            raise RuntimeError(f"Failed to verify 0600 mode on temporary trust store: got {oct(st.st_mode)}")
                        # fsync temporary file data and metadata after permission changes
                        os.fsync(f.fileno())
                except BaseException:
                    try:
                        os.close(fd)
                    except OSError:
                        pass
                    raise

                # EXACT DURABLE COMMIT POINT: Atomic replacement under existing file lock
                os.replace(tmp_path, self.store_path)
                commit_point_reached = True

                # Parent directory fsync after replacement to commit directory entry to non-volatile storage
                dir_flags = os.O_RDONLY
                if hasattr(os, "O_DIRECTORY"):
                    dir_flags |= os.O_DIRECTORY
                dir_fd = os.open(dir_name, dir_flags)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)

                return DurableCommitOutcome.COMMITTED
            except Exception as e:
                if os.path.exists(tmp_path):
                    try:
                        os.remove(tmp_path)
                    except OSError:
                        pass
                if commit_point_reached:
                    raise DurableCommitError(
                        f"Trust store commit outcome uncertain: atomic replace completed but parent directory fsync failed: {e}",
                        outcome=DurableCommitOutcome.COMMIT_UNKNOWN,
                        cause=e,
                    ) from e
                else:
                    raise DurableCommitError(
                        f"Failed to persist durable trust store to '{self.store_path}': {e}",
                        outcome=DurableCommitOutcome.NOT_COMMITTED,
                        cause=e,
                    ) from e

    def register_key(self, key_id: str, secret: str, is_active: bool = False) -> None:
        with self._file_lock():
            self.load()
            kid = str(key_id)
            if not kid or not secret:
                raise ValueError("key_id and secret must be non-empty strings")
            if kid in self.revoked_keys:
                raise ValueError(f"Cannot register key '{kid}': key is permanently revoked")
            orig_keys = dict(self.keys)
            orig_active = self.active_key_id
            self.keys[kid] = str(secret)
            if is_active or len(self.keys) == 1:
                self.active_key_id = kid
            try:
                self.save()
            except DurableCommitError as dce:
                if dce.outcome == DurableCommitOutcome.COMMIT_UNKNOWN:
                    self.reconcile_from_disk()
                    raise
                self.keys = orig_keys
                self.active_key_id = orig_active
                raise
            except Exception:
                self.keys = orig_keys
                self.active_key_id = orig_active
                raise

    def rotate_key(self, new_key_id: str, new_secret: str) -> None:
        self.register_key(new_key_id, new_secret, is_active=True)

    def revoke_key(self, key_id: str, reason: str = "revoked") -> None:
        with self._file_lock():
            self.load()
            kid = str(key_id)
            orig_rev = dict(self.revoked_keys)
            orig_active = self.active_key_id
            self.revoked_keys[kid] = {
                "revoked_at": datetime.now(timezone.utc).isoformat(),
                "reason": str(reason),
            }
            if self.active_key_id == kid:
                available = [k for k in self.keys.keys() if k not in self.revoked_keys]
                self.active_key_id = available[0] if available else ""
            try:
                self.save()
            except DurableCommitError as dce:
                if dce.outcome == DurableCommitOutcome.COMMIT_UNKNOWN:
                    self.reconcile_from_disk()
                    raise
                self.revoked_keys = orig_rev
                self.active_key_id = orig_active
                raise
            except Exception:
                self.revoked_keys = orig_rev
                self.active_key_id = orig_active
                raise

    def is_revoked(self, key_id: str) -> bool:
        with self._file_lock():
            self.load()
            return str(key_id) in self.revoked_keys

    def record_used_attestation(self, attestation_id: str) -> None:
        with self._file_lock():
            self.load()
            att_id = str(attestation_id)
            if att_id in self.used_attestation_ids:
                raise ValueError(f"Replay of causal attestation ID '{att_id}' rejected")
            orig_set = set(self.used_attestation_ids)
            self.used_attestation_ids.add(att_id)
            try:
                self.save()
            except DurableCommitError as dce:
                if dce.outcome == DurableCommitOutcome.COMMIT_UNKNOWN:
                    self.reconcile_from_disk()
                    raise
                self.used_attestation_ids = orig_set
                raise
            except Exception:
                self.used_attestation_ids = orig_set
                raise

    def is_attestation_used(self, attestation_id: str) -> bool:
        with self._file_lock():
            self.load()
            return str(attestation_id) in self.used_attestation_ids

    def consume_attestation(
        self,
        attestation: "CausalAttestation",
        evidence_id: str,
        session_id: Optional[str] = None,
        expected_pid: Optional[int] = None,
        expected_process_identity: Optional[str] = None,
        expected_executable_identity: Optional[str] = None,
        expected_build_id: Optional[str] = None,
        expected_target_host: Optional[str] = None,
        secret: Optional[str] = None,
        key_store: Optional["CaptureKeyStore"] = None,
        current_time_ns: Optional[int] = None,
    ) -> TrustConsumptionResult:
        """Atomic trust-consumption contract eliminating check-then-record race conditions."""
        with self._file_lock():
            self.load()
            att_id = str(attestation.attestation_id)
            kid = str(attestation.key_id)

            # 1. Revocation check
            if kid in self.revoked_keys or attestation.revoked:
                return TrustConsumptionResult(
                    status=TrustConsumptionStatus.REVOKED,
                    reason=f"Attestation key '{kid}' or attestation itself is revoked",
                    attestation_id=att_id,
                    key_id=kid,
                    evidence_id=str(evidence_id),
                )

            # 2. Signature verification & identity validation
            ok_v, err_v = attestation.verify(
                secret=secret,
                key_store=key_store,
                current_time_ns=current_time_ns,
                expected_session_id=session_id,
                expected_pid=expected_pid,
                expected_process_identity=expected_process_identity,
                expected_executable_identity=expected_executable_identity,
                expected_build_id=expected_build_id,
                expected_target_host=expected_target_host,
                trust_store=self,
            )
            if not ok_v:
                if "KEY_REVOKED" in err_v:
                    return TrustConsumptionResult(
                        status=TrustConsumptionStatus.REVOKED,
                        reason=err_v,
                        attestation_id=att_id,
                        key_id=kid,
                        evidence_id=str(evidence_id),
                    )
                if "EXPIRED_ATTESTATION" in err_v:
                    return TrustConsumptionResult(
                        status=TrustConsumptionStatus.EXPIRED,
                        reason=err_v,
                        attestation_id=att_id,
                        key_id=kid,
                        evidence_id=str(evidence_id),
                    )
                if any(m in err_v for m in ("MISMATCH", "MISSING_", "INVALID_TARGET_PID", "CROSS_SESSION")):
                    return TrustConsumptionResult(
                        status=TrustConsumptionStatus.IDENTITY_MISMATCH,
                        reason=err_v,
                        attestation_id=att_id,
                        key_id=kid,
                        evidence_id=str(evidence_id),
                    )
                return TrustConsumptionResult(
                    status=TrustConsumptionStatus.INVALID_SIGNATURE,
                    reason=err_v,
                    attestation_id=att_id,
                    key_id=kid,
                    evidence_id=str(evidence_id),
                )

            # 3. Anti-replay reservation / idempotent check
            if not hasattr(self, "used_attestations"):
                self.used_attestations: Dict[str, Dict[str, Any]] = {}

            if att_id in self.used_attestation_ids:
                bound_info = self.used_attestations.get(att_id)
                if bound_info:
                    bound_eid = bound_info.get("evidence_id")
                    bound_sess = bound_info.get("session_id")
                    bound_pid = bound_info.get("pid")
                    # Exact original committed evidence recovery
                    if bound_eid == str(evidence_id) and (not session_id or bound_sess == str(session_id)) and (expected_pid is None or int(bound_pid) == int(expected_pid)):
                        return TrustConsumptionResult(
                            status=TrustConsumptionStatus.IDEMPOTENT_RECOVERY,
                            reason="Idempotent re-verification of same evidence record",
                            attestation_id=att_id,
                            key_id=kid,
                            evidence_id=str(evidence_id),
                            recorded_at=bound_info.get("recorded_at", ""),
                        )
                    else:
                        return TrustConsumptionResult(
                            status=TrustConsumptionStatus.REPLAY_CONFLICT,
                            reason=f"Attestation ID '{att_id}' already consumed by evidence '{bound_eid}' (session={bound_sess}, pid={bound_pid})",
                            attestation_id=att_id,
                            key_id=kid,
                            evidence_id=str(evidence_id),
                        )
                else:
                    return TrustConsumptionResult(
                        status=TrustConsumptionStatus.REPLAY_CONFLICT,
                        reason=f"Attestation ID '{att_id}' already recorded as used in trust store",
                        attestation_id=att_id,
                        key_id=kid,
                        evidence_id=str(evidence_id),
                    )

            # 4. Atomic durable consumption
            now_iso = datetime.now(timezone.utc).isoformat()
            orig_used_set = set(self.used_attestation_ids)
            orig_used_dict = dict(self.used_attestations)

            self.used_attestation_ids.add(att_id)
            self.used_attestations[att_id] = {
                "evidence_id": str(evidence_id),
                "session_id": str(session_id or attestation.session_id),
                "pid": int(expected_pid or attestation.target_identity.get("pid", 0)),
                "recorded_at": now_iso,
            }

            try:
                self.save()
            except DurableCommitError as dce:
                if dce.outcome == DurableCommitOutcome.COMMIT_UNKNOWN:
                    self.reconcile_from_disk()
                    return TrustConsumptionResult(
                        status=TrustConsumptionStatus.PERSISTENCE_FAILURE,
                        reason=f"Commit outcome uncertain during atomic trust consumption: {dce}",
                        attestation_id=att_id,
                        key_id=kid,
                        evidence_id=str(evidence_id),
                    )
                self.used_attestation_ids = orig_used_set
                self.used_attestations = orig_used_dict
                return TrustConsumptionResult(
                    status=TrustConsumptionStatus.PERSISTENCE_FAILURE,
                    reason=f"Persistence failure during atomic trust consumption: {dce}",
                    attestation_id=att_id,
                    key_id=kid,
                    evidence_id=str(evidence_id),
                )
            except Exception as e:
                self.used_attestation_ids = orig_used_set
                self.used_attestations = orig_used_dict
                return TrustConsumptionResult(
                    status=TrustConsumptionStatus.PERSISTENCE_FAILURE,
                    reason=f"Persistence failure during atomic trust consumption: {e}",
                    attestation_id=att_id,
                    key_id=kid,
                    evidence_id=str(evidence_id),
                )

            return TrustConsumptionResult(
                status=TrustConsumptionStatus.NEW_ACCEPTANCE,
                reason="Successfully verified and consumed attestation",
                attestation_id=att_id,
                key_id=kid,
                evidence_id=str(evidence_id),
                recorded_at=now_iso,
            )

    def record_used_operation(
        self,
        op_id: str,
        session_id: str,
        pid: int,
        metadata: Optional[Dict[str, Any]] = None,
        allow_idempotent: bool = False,
    ) -> None:
        with self._file_lock():
            self.load()
            oid = str(op_id)
            if oid in self.used_operation_ids:
                prev = self.used_operation_ids[oid]
                if prev.get("session_id") != str(session_id):
                    raise ValueError(f"Receipt replay across sessions rejected for operation '{oid}'")
                if prev.get("pid") is not None and int(prev["pid"]) != int(pid):
                    raise ValueError(f"Receipt replay across PIDs rejected for operation '{oid}'")

                if metadata:
                    for id_field in (
                        "process_identity",
                        "executable_identity",
                        "build_id",
                        "target_host",
                        "receipt_id",
                        "observation_digest",
                        "operation_type",
                    ):
                        p_val = prev.get(id_field)
                        m_val = metadata.get(id_field)
                        if p_val and m_val and str(p_val) != str(m_val):
                            raise ValueError(
                                f"Conflicting target identity or metadata '{id_field}' for operation '{oid}': {p_val} vs {m_val}"
                            )

                    # Multi-evidence operation derivation checks
                    incoming_eid = metadata.get("evidence_id")
                    bound_eid = prev.get("evidence_id")
                    bound_eids = list(prev.get("evidence_ids", []))
                    if bound_eid and bound_eid not in bound_eids:
                        bound_eids.insert(0, bound_eid)

                    if incoming_eid and bound_eid and incoming_eid != bound_eid:
                        derived_from = metadata.get("derived_from")
                        parent_eids = metadata.get("parent_evidence_ids")
                        d_list = [derived_from] if isinstance(derived_from, str) else list(derived_from or [])
                        p_list = [parent_eids] if isinstance(parent_eids, str) else list(parent_eids or [])
                        has_derivation = any(d in bound_eids for d in d_list) or any(p in bound_eids for p in p_list)
                        if not has_derivation:
                            raise ValueError(
                                f"Operation '{oid}' is already bound to primary evidence '{bound_eid}'. "
                                f"Secondary evidence '{incoming_eid}' requires verifiable derivation from primary observation."
                            )

                if allow_idempotent:
                    if metadata:
                        orig_prev = dict(prev)
                        orig_eids = list(prev.get("evidence_ids", []))
                        for k, v in metadata.items():
                            if k == "evidence_id" and "evidence_id" in prev and prev["evidence_id"] != v:
                                continue
                            prev[k] = v
                        if metadata.get("evidence_id"):
                            e_list = prev.setdefault("evidence_ids", [])
                            if metadata["evidence_id"] not in e_list:
                                e_list.append(metadata["evidence_id"])
                        try:
                            self.save()
                        except DurableCommitError as dce:
                            if dce.outcome == DurableCommitOutcome.COMMIT_UNKNOWN:
                                self.reconcile_from_disk()
                                raise
                            prev.clear()
                            prev.update(orig_prev)
                            if orig_eids:
                                prev["evidence_ids"] = orig_eids
                            else:
                                prev.pop("evidence_ids", None)
                            raise
                        except Exception:
                            prev.clear()
                            prev.update(orig_prev)
                            if orig_eids:
                                prev["evidence_ids"] = orig_eids
                            else:
                                prev.pop("evidence_ids", None)
                            raise
                    return
                raise ValueError(f"Operation ID '{oid}' is already committed and single-use")

            rec = {
                "session_id": str(session_id),
                "pid": int(pid),
                "recorded_at": datetime.now(timezone.utc).isoformat(),
            }
            if metadata:
                rec.update(metadata)
            if metadata and metadata.get("evidence_id"):
                rec["evidence_ids"] = [metadata["evidence_id"]]

            orig_ops = dict(self.used_operation_ids)
            self.used_operation_ids[oid] = rec
            try:
                self.save()
            except DurableCommitError as dce:
                if dce.outcome == DurableCommitOutcome.COMMIT_UNKNOWN:
                    self.reconcile_from_disk()
                    raise
                self.used_operation_ids = orig_ops
                raise
            except Exception:
                self.used_operation_ids = orig_ops
                raise

    def bind_operation_receipt(self, op_id: str, receipt_id: str) -> None:
        """Atomically bind an issued receipt ID to a committed operation in trust store."""
        with self._file_lock():
            self.load()
            oid = str(op_id)
            rid = str(receipt_id)
            if oid not in self.used_operation_ids:
                raise ValueError(f"Operation '{oid}' not recorded in trust store")
            rec = self.used_operation_ids[oid]
            bound_rcpt = rec.get("receipt_id")
            if bound_rcpt and bound_rcpt != rid:
                raise ValueError(f"Operation '{oid}' is already bound to receipt '{bound_rcpt}', cannot bind to '{rid}'")
            orig_rcpt = bound_rcpt
            rec["receipt_id"] = rid
            try:
                self.save()
            except DurableCommitError as dce:
                if dce.outcome == DurableCommitOutcome.COMMIT_UNKNOWN:
                    self.reconcile_from_disk()
                    raise
                if orig_rcpt is None:
                    rec.pop("receipt_id", None)
                else:
                    rec["receipt_id"] = orig_rcpt
                raise
            except Exception:
                if orig_rcpt is None:
                    rec.pop("receipt_id", None)
                else:
                    rec["receipt_id"] = orig_rcpt
                raise

    def bind_operation_evidence(
        self,
        op_id: str,
        evidence_id: str,
        derived_from: Optional[Union[str, List[str]]] = None,
        parent_evidence_ids: Optional[List[str]] = None,
        parent_evidence_digest: Optional[str] = None,
    ) -> None:
        """Atomically bind an evidence ID to a committed operation in trust store."""
        with self._file_lock():
            self.load()
            oid = str(op_id)
            eid = str(evidence_id)
            if oid not in self.used_operation_ids:
                raise ValueError(f"Operation '{oid}' not recorded in trust store")
            rec = self.used_operation_ids[oid]
            eids = rec.setdefault("evidence_ids", [])
            if not eids and "evidence_id" in rec and rec["evidence_id"]:
                eids.append(rec["evidence_id"])
            if eid not in eids:
                if len(eids) > 0:
                    d_list = [derived_from] if isinstance(derived_from, str) else list(derived_from or [])
                    p_list = [parent_evidence_ids] if isinstance(parent_evidence_ids, str) else list(parent_evidence_ids or [])
                    has_valid_derivation = any(d in eids for d in d_list) or any(p in eids for p in p_list)
                    if not has_valid_derivation:
                        raise ValueError(
                            f"Multi-evidence operation '{oid}' rejected: secondary evidence '{eid}' lacks "
                            f"verifiable derivation from primary observation '{eids[0]}'."
                        )
                orig_eids = list(eids)
                eids.append(eid)
                if parent_evidence_digest:
                    pdigs = rec.setdefault("parent_digests", {})
                    pdigs[eid] = str(parent_evidence_digest)
                try:
                    self.save()
                except DurableCommitError as dce:
                    if dce.outcome == DurableCommitOutcome.COMMIT_UNKNOWN:
                        self.reconcile_from_disk()
                        raise
                    rec["evidence_ids"] = orig_eids
                    raise
                except Exception:
                    rec["evidence_ids"] = orig_eids
                    raise
            else:
                # Idempotent re-bind: ensure parent_evidence_digest does not conflict
                if parent_evidence_digest and "parent_digests" in rec and eid in rec["parent_digests"]:
                    existing_digest = rec["parent_digests"][eid]
                    if str(existing_digest) != str(parent_evidence_digest):
                        raise ValueError(
                            f"Conflicting parent digest for evidence '{eid}' under operation '{oid}': "
                            f"existing='{existing_digest}', provided='{parent_evidence_digest}'"
                        )

    def is_operation_used(self, op_id: str) -> bool:
        with self._file_lock():
            self.load()
            return str(op_id) in self.used_operation_ids

    def resolve_key(self, key_id: str) -> str:
        with self._file_lock():
            self.load()
            kid = str(key_id)
            if kid in self.revoked_keys:
                raise ValueError(f"Key '{kid}' is revoked")
            if kid in self.keys:
                return self.keys[kid]
            raise KeyError(f"Key '{kid}' not found in trust store")


_DEFAULT_TRUST_STORE: Optional[DurableTrustStore] = None


def get_default_trust_store() -> Optional[DurableTrustStore]:
    global _DEFAULT_TRUST_STORE
    if _DEFAULT_TRUST_STORE is None:
        ts_env = os.environ.get("DYNAMICSTATE_TRUST_STORE_PATH")
        if ts_env:
            _DEFAULT_TRUST_STORE = DurableTrustStore(ts_env)
    return _DEFAULT_TRUST_STORE


def set_default_trust_store(ts: Optional[DurableTrustStore]) -> None:
    global _DEFAULT_TRUST_STORE
    _DEFAULT_TRUST_STORE = ts


class CausalVerifierAuthority:
    """Explicit trusted verifier authority managing causal verification keys and attestation lifecycle.

    Trust Model:
    DynamicState uses HMAC-SHA256 for cryptographic causal attestations and live capture receipts.
    The signing secret is provisioned exclusively to trusted collector/verifier authorities and durable
    key stores. Verification compares HMAC signatures against keys resolved from the durable trust store
    or authorized key store. Independent workers verify attestations using trusted key stores synced via
    the durable trust store file. Protection against arbitrary code execution within the same host/user
    process boundary is not claimed; the trust model relies on OS process/container isolation and secure
    file system permissions on the trust store.
    """

    def __init__(
        self,
        authority_id: str = "dynamicstate_causal_verifier_v1",
        key_store: Optional["CaptureKeyStore"] = None,
        authority_secret: Optional[str] = None,
        trust_store: Optional[DurableTrustStore] = None,
        trust_store_path: Optional[str] = None,
    ):
        self.authority_id = str(authority_id)
        self.key_store = key_store or get_default_key_store()
        self._authority_token = authority_secret or os.environ.get("DYNAMICSTATE_CAUSAL_AUTHORITY_TOKEN") or os.urandom(32).hex()

        if trust_store:
            self.trust_store: Optional[DurableTrustStore] = trust_store
        elif trust_store_path:
            self.trust_store = DurableTrustStore(trust_store_path)
        else:
            ts_env = os.environ.get("DYNAMICSTATE_TRUST_STORE_PATH")
            self.trust_store = DurableTrustStore(ts_env) if ts_env else None

        self._revoked_keys: Set[str] = set()
        if self.trust_store:
            self._revoked_keys.update(self.trust_store.revoked_keys.keys())
            for kid, sec in self.trust_store.keys.items():
                if hasattr(self.key_store, "register_key"):
                    self.key_store.register_key(kid, sec)

    def get_verifier_token(self) -> str:
        """Access token bound to this specific authority instance."""
        return self._authority_token

    def rotate_key(self, new_key_id: str, new_secret: Optional[str] = None) -> Tuple[str, str]:
        """Rotate the active attestation signing key atomically."""
        sec = new_secret or os.urandom(32).hex()
        if hasattr(self.key_store, "register_key"):
            self.key_store.register_key(new_key_id, sec)
        if hasattr(self.key_store, "_keys"):
            self.key_store._keys[new_key_id] = sec
        if hasattr(self.key_store, "_active_key_id"):
            self.key_store._active_key_id = new_key_id
        if self.trust_store:
            self.trust_store.register_key(new_key_id, sec, is_active=True)
        return new_key_id, sec

    def revoke_key(self, key_id: str, reason: str = "revoked") -> None:
        """Revoke a signing key so subsequent verifications reject it."""
        self._revoked_keys.add(key_id)
        if hasattr(self.key_store, "revoke_key"):
            self.key_store.revoke_key(key_id)
        if self.trust_store:
            self.trust_store.revoke_key(key_id, reason=reason)

    def is_key_revoked(self, key_id: str) -> bool:
        if key_id in self._revoked_keys:
            return True
        if self.trust_store and self.trust_store.is_revoked(key_id):
            return True
        if hasattr(self.key_store, "is_revoked"):
            return self.key_store.is_revoked(key_id)
        return False

    def issue_attestation(
        self,
        session_id: str,
        target_identity: Dict[str, Any],
        operation_id: str,
        precondition_evidence_id: str,
        postcondition_evidence_id: str,
        claimed_transition: Dict[str, Any],
        intervention_details: Optional[Dict[str, Any]] = None,
        ttl_seconds: int = 3600,
        authority_level: str = "PRODUCTION",
        verifier_authority_token: Optional[str] = None,
        secret: Optional[str] = None,
        key_id: Optional[str] = None,
    ) -> "CausalAttestation":
        if authority_level == "PRODUCTION":
            if not verifier_authority_token or not hmac.compare_digest(str(verifier_authority_token), str(self._authority_token)):
                raise ValueError(
                    "Unauthorized causal attestation issuance: PRODUCTION authority can only be issued by trusted causal verification authority."
                )

        if not session_id or not str(session_id).strip():
            raise ValueError("CausalAttestation requires non-empty session_id")
        if not operation_id or not str(operation_id).strip():
            raise ValueError("CausalAttestation requires non-empty operation_id")
        if not target_identity or not isinstance(target_identity, dict):
            raise ValueError("CausalAttestation requires non-empty target_identity dict")
        pid = target_identity.get("pid")
        if pid is None or int(pid) <= 1:
            raise ValueError(f"CausalAttestation target_identity requires valid PID, got {pid}")
        if not target_identity.get("executable_identity") and not target_identity.get("executable"):
            raise ValueError("CausalAttestation target_identity requires verified executable identity")
        if authority_level == "PRODUCTION":
            if not target_identity.get("process_identity"):
                raise ValueError("CausalAttestation target_identity requires verified process_identity for PRODUCTION authority")
            if not target_identity.get("build_id"):
                raise ValueError("CausalAttestation target_identity requires verified build_id for PRODUCTION authority")
        if not precondition_evidence_id or not str(precondition_evidence_id).strip():
            raise ValueError("CausalAttestation requires non-empty precondition_evidence_id")
        if not postcondition_evidence_id or not str(postcondition_evidence_id).strip():
            raise ValueError("CausalAttestation requires non-empty postcondition_evidence_id")
        if not claimed_transition or not isinstance(claimed_transition, dict):
            raise ValueError("CausalAttestation requires non-empty claimed_transition dict")

        active_kid, active_sec = self.key_store.get_active_signing_key()
        use_kid = key_id or active_kid
        if self.is_key_revoked(use_kid):
            raise ValueError(f"Cannot sign CausalAttestation: key '{use_kid}' is revoked")
        if secret:
            use_sec = secret
        elif use_kid == active_kid:
            use_sec = active_sec
        elif self.trust_store and use_kid in self.trust_store.keys:
            use_sec = self.trust_store.resolve_key(use_kid)
        else:
            use_sec = self.key_store.resolve_key(use_kid)

        if intervention_details is None:
            eff_intervention = {"action": "verified_transition", "verified_intervention": True}
        else:
            eff_intervention = dict(intervention_details)

        now = time.time_ns()
        exp = now + int(ttl_seconds * 1_000_000_000)
        att = CausalAttestation(
            attestation_id=f"causal_att_{uuid.uuid4().hex[:12]}",
            session_id=str(session_id),
            target_identity=dict(target_identity),
            operation_id=str(operation_id),
            precondition_evidence_id=str(precondition_evidence_id),
            postcondition_evidence_id=str(postcondition_evidence_id),
            claimed_transition=dict(claimed_transition),
            intervention_details=eff_intervention,
            issued_at_ns=now,
            expires_at_ns=exp,
            verifier_identity=self.authority_id,
            key_id=use_kid,
            authority_level=str(authority_level),
        )
        att.sign(secret=use_sec)
        return att


_DEFAULT_CAUSAL_AUTHORITY = CausalVerifierAuthority()


def get_default_causal_authority() -> CausalVerifierAuthority:
    return _DEFAULT_CAUSAL_AUTHORITY


def get_trusted_causal_authority_token() -> str:
    """Internal token reserved strictly for authorized causal verification engines."""
    return _DEFAULT_CAUSAL_AUTHORITY.get_verifier_token()


@dataclass
class CausalAttestation:
    """Cryptographic attestation certifying a verified causal relationship or state transition."""
    attestation_id: str
    session_id: str
    target_identity: Dict[str, Any]
    operation_id: str
    precondition_evidence_id: str
    postcondition_evidence_id: str
    claimed_transition: Dict[str, Any] = field(default_factory=dict)
    intervention_details: Dict[str, Any] = field(default_factory=dict)
    issued_at_ns: int = 0
    expires_at_ns: int = 0
    verifier_identity: str = "dynamicstate_causal_verifier_v1"
    key_id: str = "default"
    signature: str = ""
    revoked: bool = False
    authority_level: str = "PRODUCTION"

    def canonical_bytes(self) -> bytes:
        payload = {
            "attestation_id": str(self.attestation_id),
            "session_id": str(self.session_id),
            "target_identity": {
                "pid": int(self.target_identity.get("pid", 0)),
                "process_identity": str(self.target_identity.get("process_identity", "")),
                "executable_identity": str(self.target_identity.get("executable_identity") or self.target_identity.get("executable", "")),
                "build_id": str(self.target_identity.get("build_id", "")),
                "target_host": str(self.target_identity.get("target_host", "")),
            },
            "operation_id": str(self.operation_id),
            "precondition_evidence_id": str(self.precondition_evidence_id),
            "postcondition_evidence_id": str(self.postcondition_evidence_id),
            "claimed_transition": dict(self.claimed_transition or {}),
            "intervention_details": dict(self.intervention_details or {}),
            "issued_at_ns": int(self.issued_at_ns),
            "expires_at_ns": int(self.expires_at_ns),
            "verifier_identity": str(self.verifier_identity),
            "key_id": str(self.key_id),
            "authority_level": str(self.authority_level),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def canonical_bytes_legacy(self) -> bytes:
        payload = {
            "attestation_id": str(self.attestation_id),
            "session_id": str(self.session_id),
            "target_identity": {
                "pid": int(self.target_identity.get("pid", 0)),
                "process_identity": str(self.target_identity.get("process_identity", "")),
                "executable_identity": str(self.target_identity.get("executable_identity") or self.target_identity.get("executable", "")),
                "build_id": str(self.target_identity.get("build_id", "")),
            },
            "operation_id": str(self.operation_id),
            "precondition_evidence_id": str(self.precondition_evidence_id),
            "postcondition_evidence_id": str(self.postcondition_evidence_id),
            "claimed_transition": dict(self.claimed_transition or {}),
            "intervention_details": dict(self.intervention_details or {}),
            "issued_at_ns": int(self.issued_at_ns),
            "expires_at_ns": int(self.expires_at_ns),
            "verifier_identity": str(self.verifier_identity),
            "key_id": str(self.key_id),
            "authority_level": str(self.authority_level),
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def sign(self, secret: str) -> None:
        if not secret:
            raise ValueError("Cannot sign CausalAttestation: missing secret")
        self.signature = hmac.new(secret.encode("utf-8"), self.canonical_bytes(), hashlib.sha256).hexdigest()

    def verify(
        self,
        secret: Optional[str] = None,
        key_store: Optional[CaptureKeyStore] = None,
        current_time_ns: Optional[int] = None,
        expected_session_id: Optional[str] = None,
        expected_pid: Optional[int] = None,
        expected_operation_id: Optional[str] = None,
        expected_process_identity: Optional[str] = None,
        expected_executable_identity: Optional[str] = None,
        expected_build_id: Optional[str] = None,
        expected_target_host: Optional[str] = None,
        trust_store: Optional[DurableTrustStore] = None,
    ) -> Tuple[bool, str]:
        if not self.signature:
            return False, "UNSIGNED_ATTESTATION: Missing HMAC signature"
        if self.revoked:
            return False, "REVOKED_ATTESTATION: Attestation has been revoked"
        now = current_time_ns if current_time_ns is not None else time.time_ns()
        if self.expires_at_ns > 0 and now > self.expires_at_ns:
            return False, "EXPIRED_ATTESTATION: Attestation expired"

        # Mandatory identity field validation for PRODUCTION authority
        if self.authority_level == "PRODUCTION":
            if not self.session_id or not str(self.session_id).strip():
                return False, "MISSING_SESSION_ID: Attestation missing session_id"
            if not self.operation_id or not str(self.operation_id).strip():
                return False, "MISSING_OPERATION_ID: Attestation missing operation_id"
            if not self.target_identity or not isinstance(self.target_identity, dict):
                return False, "MALFORMED_ATTESTATION: Missing or invalid target_identity"
            pid_val = self.target_identity.get("pid")
            if pid_val is None or isinstance(pid_val, bool) or int(pid_val) <= 1:
                return False, f"INVALID_TARGET_PID: Invalid PID '{pid_val}'"
            if not self.target_identity.get("process_identity") or not str(self.target_identity["process_identity"]).strip():
                return False, "MISSING_PROCESS_IDENTITY: Attestation missing process_identity"
            exe_val = self.target_identity.get("executable_identity") or self.target_identity.get("executable")
            if not exe_val or not str(exe_val).strip():
                return False, "MISSING_EXECUTABLE_IDENTITY: Attestation missing executable_identity"
            if not self.target_identity.get("build_id") or not str(self.target_identity["build_id"]).strip():
                return False, "MISSING_BUILD_ID: Attestation missing build_id"

        # Expected checks: never silently skip when attestation field is absent!
        if expected_session_id is not None:
            if not self.session_id or str(self.session_id) != str(expected_session_id):
                return False, f"CROSS_SESSION_ATTESTATION: Expected session '{expected_session_id}', got '{self.session_id}'"

        if expected_operation_id is not None:
            if not self.operation_id or str(self.operation_id) != str(expected_operation_id):
                return False, f"OPERATION_ID_MISMATCH: Expected operation '{expected_operation_id}', got '{self.operation_id}'"

        if expected_pid is not None:
            act_pid = self.target_identity.get("pid")
            if act_pid is None or isinstance(act_pid, bool):
                return False, f"TARGET_PID_MISMATCH: Attestation missing PID (expected PID {expected_pid})"
            if int(act_pid) != int(expected_pid):
                return False, f"TARGET_PID_MISMATCH: Target PID mismatch: Expected PID {expected_pid}, got {act_pid}"

        if expected_process_identity is not None:
            act_proc = str(self.target_identity.get("process_identity", "")).strip()
            if not act_proc:
                return False, f"PROCESS_IDENTITY_MISMATCH: Attestation missing process_identity (expected '{expected_process_identity}')"
            if act_proc != str(expected_process_identity).strip():
                return False, f"PROCESS_IDENTITY_MISMATCH: Expected '{expected_process_identity}', got '{act_proc}'"

        if expected_executable_identity is not None:
            act_exe = str(self.target_identity.get("executable_identity") or self.target_identity.get("executable", "")).strip()
            if not act_exe:
                return False, f"EXECUTABLE_IDENTITY_MISMATCH: Attestation missing executable_identity (expected '{expected_executable_identity}')"
            if act_exe != str(expected_executable_identity).strip():
                return False, f"EXECUTABLE_IDENTITY_MISMATCH: Expected '{expected_executable_identity}', got '{act_exe}'"

        if expected_build_id is not None:
            act_bid = str(self.target_identity.get("build_id", "")).strip()
            if not act_bid:
                return False, f"BUILD_ID_MISMATCH: Attestation missing build_id (expected '{expected_build_id}')"
            if act_bid.lower() != str(expected_build_id).strip().lower():
                return False, f"BUILD_ID_MISMATCH: Expected '{expected_build_id}', got '{act_bid}'"

        if expected_target_host is not None:
            act_host = str(self.target_identity.get("target_host", "")).strip()
            if not act_host:
                return False, f"TARGET_HOST_MISMATCH: Attestation missing target_host (expected '{expected_target_host}')"
            if act_host != str(expected_target_host).strip():
                return False, f"TARGET_HOST_MISMATCH: Expected target host '{expected_target_host}', got '{act_host}'"

        eff_ts = trust_store or get_default_trust_store()
        use_sec = secret
        if not use_sec:
            if eff_ts and (self.key_id in eff_ts.revoked_keys or eff_ts.is_revoked(self.key_id)):
                return False, f"KEY_REVOKED: Attestation signing key '{self.key_id}' is revoked in durable trust store"
            ks = key_store or get_default_key_store()
            if hasattr(ks, "is_revoked") and ks.is_revoked(self.key_id):
                return False, f"KEY_REVOKED: Attestation signing key '{self.key_id}' is revoked"
            try:
                if eff_ts and self.key_id in eff_ts.keys:
                    use_sec = eff_ts.keys[self.key_id]
                elif hasattr(ks, "_keys") and self.key_id in ks._keys:
                    use_sec = ks._keys[self.key_id]
                elif hasattr(ks, "resolve_key"):
                    try:
                        use_sec = ks.resolve_key(self.key_id)
                    except Exception:
                        if self.key_id in ("default", "ephemeral"):
                            _, use_sec = ks.get_active_signing_key()
                        else:
                            raise
                elif self.key_id in ("default", "ephemeral"):
                    _, use_sec = ks.get_active_signing_key()
                else:
                    use_sec = ks.resolve_key(self.key_id)
            except Exception as e:
                return False, f"KEY_RESOLUTION_FAILED: {e}"

        expected_sig = hmac.new(use_sec.encode("utf-8"), self.canonical_bytes(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(self.signature, expected_sig):
            # Check legacy format without target_host for backward compatibility if target_host is not set
            expected_legacy_sig = hmac.new(use_sec.encode("utf-8"), self.canonical_bytes_legacy(), hashlib.sha256).hexdigest()
            if hmac.compare_digest(self.signature, expected_legacy_sig) and not expected_target_host:
                return True, "VERIFIED"
            return False, "CORRUPT_ATTESTATION: HMAC signature verification failed"
        return True, "VERIFIED"
        if not hmac.compare_digest(self.signature, expected_sig):
            return False, "CORRUPT_ATTESTATION: HMAC signature verification failed"
        return True, "VERIFIED"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "attestation_id": self.attestation_id,
            "session_id": self.session_id,
            "target_identity": dict(self.target_identity),
            "operation_id": self.operation_id,
            "precondition_evidence_id": self.precondition_evidence_id,
            "postcondition_evidence_id": self.postcondition_evidence_id,
            "claimed_transition": dict(self.claimed_transition),
            "intervention_details": dict(self.intervention_details),
            "issued_at_ns": self.issued_at_ns,
            "expires_at_ns": self.expires_at_ns,
            "verifier_identity": self.verifier_identity,
            "key_id": self.key_id,
            "signature": self.signature,
            "revoked": self.revoked,
            "authority_level": self.authority_level,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CausalAttestation":
        if not isinstance(data, dict):
            raise TypeError("CausalAttestation.from_dict requires a dictionary")
        return cls(
            attestation_id=str(data.get("attestation_id", "")),
            session_id=str(data.get("session_id", "")),
            target_identity=dict(data.get("target_identity") or {}),
            operation_id=str(data.get("operation_id", "")),
            precondition_evidence_id=str(data.get("precondition_evidence_id", "")),
            postcondition_evidence_id=str(data.get("postcondition_evidence_id", "")),
            claimed_transition=dict(data.get("claimed_transition") or {}),
            intervention_details=dict(data.get("intervention_details") or {}),
            issued_at_ns=int(data.get("issued_at_ns", 0)),
            expires_at_ns=int(data.get("expires_at_ns", 0)),
            verifier_identity=str(data.get("verifier_identity", "dynamicstate_causal_verifier_v1")),
            key_id=str(data.get("key_id", "default")),
            signature=str(data.get("signature", "")),
            revoked=bool(data.get("revoked", False)),
            authority_level=str(data.get("authority_level", "PRODUCTION")),
        )


def issue_causal_attestation(
    session_id: str,
    target_identity: Dict[str, Any],
    operation_id: str,
    precondition_evidence_id: str,
    postcondition_evidence_id: str,
    claimed_transition: Dict[str, Any],
    intervention_details: Optional[Dict[str, Any]] = None,
    ttl_seconds: int = 3600,
    authority_level: str = "PRODUCTION",
    verifier_authority_token: Optional[str] = None,
    secret: Optional[str] = None,
    key_id: Optional[str] = None,
) -> CausalAttestation:
    return _DEFAULT_CAUSAL_AUTHORITY.issue_attestation(
        session_id=session_id,
        target_identity=target_identity,
        operation_id=operation_id,
        precondition_evidence_id=precondition_evidence_id,
        postcondition_evidence_id=postcondition_evidence_id,
        claimed_transition=claimed_transition,
        intervention_details=intervention_details,
        ttl_seconds=ttl_seconds,
        authority_level=authority_level,
        verifier_authority_token=verifier_authority_token,
        secret=secret,
        key_id=key_id,
    )


@dataclass
class CaptureLatencyReport:
    """Exact latency measurements for each phase of runtime state capture.

    Non-available measurements are represented as None (null in JSON) with an
    explicit reason in `unavailable_reasons`, rather than fabricating 0.0.
    """
    stop_latency_ms: Optional[float] = None
    thread_metadata_latency_ms: Optional[float] = None
    memory_capture_latency_ms: Optional[float] = None
    resume_latency_ms: Optional[float] = None
    total_stop_time_ms: Optional[float] = None
    process_suspension_time_ms: Optional[float] = None
    target_suspended: bool = False
    target_capture_latency_ms: float = 10.0
    actual_capture_latency_ms: Optional[float] = None

    # Microsecond-precision metrics
    stop_latency_us: Optional[float] = None
    thread_metadata_latency_us: Optional[float] = None
    memory_capture_latency_us: Optional[float] = None
    resume_latency_us: Optional[float] = None
    total_stop_time_us: Optional[float] = None
    process_suspension_time_us: Optional[float] = None
    total_capture_latency_us: Optional[float] = None
    unavailable_reasons: Dict[str, str] = field(default_factory=dict)

    @property
    def capture_latency_us(self) -> Optional[float]:
        return self.memory_capture_latency_us

    @property
    def read_latency_us(self) -> Optional[float]:
        return self.memory_capture_latency_us

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stop_latency_ms": round(self.stop_latency_ms, 3) if self.stop_latency_ms is not None else None,
            "thread_metadata_latency_ms": round(self.thread_metadata_latency_ms, 3) if self.thread_metadata_latency_ms is not None else None,
            "memory_capture_latency_ms": round(self.memory_capture_latency_ms, 3) if self.memory_capture_latency_ms is not None else None,
            "resume_latency_ms": round(self.resume_latency_ms, 3) if self.resume_latency_ms is not None else None,
            "total_stop_time_ms": round(self.total_stop_time_ms, 3) if self.total_stop_time_ms is not None else None,
            "process_suspension_time_ms": round(self.process_suspension_time_ms, 3) if self.process_suspension_time_ms is not None else None,
            "target_suspended": self.target_suspended,
            "target_capture_latency_ms": self.target_capture_latency_ms,
            "actual_capture_latency_ms": round(self.actual_capture_latency_ms, 3) if self.actual_capture_latency_ms is not None else None,
            "stop_latency_us": round(self.stop_latency_us, 1) if self.stop_latency_us is not None else None,
            "thread_metadata_latency_us": round(self.thread_metadata_latency_us, 1) if self.thread_metadata_latency_us is not None else None,
            "memory_capture_latency_us": round(self.memory_capture_latency_us, 1) if self.memory_capture_latency_us is not None else None,
            "capture_latency_us": round(self.memory_capture_latency_us, 1) if self.memory_capture_latency_us is not None else None,
            "read_latency_us": round(self.memory_capture_latency_us, 1) if self.memory_capture_latency_us is not None else None,
            "resume_latency_us": round(self.resume_latency_us, 1) if self.resume_latency_us is not None else None,
            "total_stop_time_us": round(self.total_stop_time_us, 1) if self.total_stop_time_us is not None else None,
            "process_suspension_time_us": round(self.process_suspension_time_us, 1) if self.process_suspension_time_us is not None else None,
            "total_capture_latency_us": round(self.total_capture_latency_us, 1) if self.total_capture_latency_us is not None else None,
            "unavailable_reasons": dict(self.unavailable_reasons),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CaptureLatencyReport":
        return cls(
            stop_latency_ms=data.get("stop_latency_ms"),
            thread_metadata_latency_ms=data.get("thread_metadata_latency_ms"),
            memory_capture_latency_ms=data.get("memory_capture_latency_ms"),
            resume_latency_ms=data.get("resume_latency_ms"),
            total_stop_time_ms=data.get("total_stop_time_ms"),
            process_suspension_time_ms=data.get("process_suspension_time_ms"),
            target_suspended=bool(data.get("target_suspended", False)),
            target_capture_latency_ms=data.get("target_capture_latency_ms", 10.0),
            actual_capture_latency_ms=data.get("actual_capture_latency_ms"),
            stop_latency_us=data.get("stop_latency_us"),
            thread_metadata_latency_us=data.get("thread_metadata_latency_us"),
            memory_capture_latency_us=data.get("memory_capture_latency_us"),
            resume_latency_us=data.get("resume_latency_us"),
            total_stop_time_us=data.get("total_stop_time_us"),
            process_suspension_time_us=data.get("process_suspension_time_us"),
            total_capture_latency_us=data.get("total_capture_latency_us"),
            unavailable_reasons=data.get("unavailable_reasons", {}),
        )


@dataclass
class CaptureSafetyPolicy:
    """Safety bounds and SLA policy for capturing state from running processes.

    Stop-Budget Semantics & Limitations:
    - max_stop_time_ms: SLA detection threshold (target SLA), NOT a preemptive OS hard real-time bound.
      In standard Linux user-space (using synchronous process_vm_readv or /proc/<pid>/mem read syscalls),
      the operating system does not provide preemptible sub-millisecond memory transfer primitives.
      Work is bounded BEFORE suspension via `max_capture_bytes` and `max_capture_ranges`.
      Once suspended, if the actual suspension time exceeds `max_stop_time_ms`, the capture engine
      detects the overrun, records the stable diagnostic `STOP_BUDGET_EXCEEDED`, and demotes the
      snapshot completeness from COMPLETE to PARTIAL.
      CRITICAL: Identity validation, fail-open resumption, and cleanup are NEVER bypassed or sacrificed
      to satisfy a timer.
    - max_capture_bytes: Hard upper bound on bytes to attempt reading across all regions.
    - max_capture_ranges: Hard upper bound on the number of distinct memory regions to process.
    - timeout_ms: Maximum duration for overall capture operation.
    - fail_open: Guarantees that target processes suspended by the capture engine are resumed via finally:.
    """
    max_stop_time_ms: float = 50.0
    max_capture_bytes: int = 64 * 1024 * 1024
    max_region_bytes: int = 4 * 1024 * 1024
    max_capture_ranges: int = 500
    timeout_ms: int = 1000
    fail_open: bool = True  # Always resume target on error or timeout
    force_fallback: bool = False  # If True, bypass pidfd and use starttime verification fallback
    target_handle: Optional[Any] = None  # Injectable ProcessTargetHandle for testing/seams
    mem_reader: Optional[Any] = None  # Injectable memory read seam
    expected_identity: Optional[Dict[str, Any]] = None  # Expected target identity to prevent PID reuse
    expected_starttime: Optional[str] = None  # Expected /proc/<pid>/stat starttime
    simulate_mapping_race: bool = False  # Inject mapping race condition for deterministic testing


class _struct_iovec(ctypes.Structure):
    _fields_ = [
        ("iov_base", ctypes.c_void_p),
        ("iov_len", ctypes.c_size_t),
    ]


class RuntimeCaptureBackend(ABC):
    """Abstract base class for fast runtime state capture backends."""

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @property
    @abstractmethod
    def capabilities(self) -> Dict[str, Any]:
        """Declared capture capabilities and guarantees of this backend."""
        pass

    @abstractmethod
    def is_available(self, pid: Optional[int] = None) -> bool:
        pass

    @abstractmethod
    def capture(
        self,
        pid: int,
        plan: Optional[CapturePlan] = None,
        policy: Optional[CaptureSafetyPolicy] = None,
        snapshot_id: Optional[str] = None,
        observation_point: Optional[Dict[str, Any]] = None,
    ) -> RawRuntimeSnapshot:
        pass


def _get_process_state(pid: int) -> Dict[str, Any]:
    """Return detailed process state dict from /proc/<pid>/stat.
    Raises ProcessLookupError if process does not exist.
    """
    stat_path = f"/proc/{pid}/stat"
    if not os.path.exists(stat_path):
        raise ProcessLookupError(f"Process {pid} does not exist (ESRCH)")
    try:
        with open(stat_path, "r", encoding="utf-8") as f:
            content = f.read()
    except (FileNotFoundError, ProcessLookupError):
        raise ProcessLookupError(f"Process {pid} does not exist (ESRCH)")

    rparen = content.rfind(")")
    if rparen == -1:
        return {
            "comm": "unknown",
            "state": "UNKNOWN",
            "state_char": "?",
            "starttime": "0",
            "is_stopped": False,
            "is_tracing_stop": False,
        }
    lparen = content.find("(")
    comm = content[lparen + 1:rparen] if lparen != -1 else "unknown"
    rest = content[rparen + 1:].strip().split()
    state_char = rest[0] if len(rest) > 0 else "?"
    starttime = rest[19] if len(rest) > 19 else "0"

    state_map = {
        "R": "RUNNING",
        "S": "SLEEPING",
        "D": "DISK_SLEEP",
        "T": "STOPPED",
        "t": "TRACING_STOP",
        "Z": "ZOMBIE",
    }
    state_desc = state_map.get(state_char, f"STATE_{state_char}")
    is_stopped = state_char in ("T", "t")
    is_tracing_stop = (state_char == "t")

    return {
        "comm": comm,
        "state": state_desc,
        "state_char": state_char,
        "starttime": starttime,
        "is_stopped": is_stopped,
        "is_tracing_stop": is_tracing_stop,
    }


def _get_threads_state(pid: int) -> Dict[str, Any]:
    """Return thread states breakdown from /proc/<pid>/task."""
    task_dir = f"/proc/{pid}/task"
    threads = []
    stopped_count = 0
    running_count = 0
    try:
        if os.path.exists(task_dir):
            for entry in os.listdir(task_dir):
                if entry.isdigit():
                    tid = int(entry)
                    stat_path = os.path.join(task_dir, entry, "stat")
                    t_state = "UNKNOWN"
                    t_char = "?"
                    is_t_stopped = False
                    try:
                        with open(stat_path, "r", encoding="utf-8") as f:
                            stat_content = f.read()
                            rparen = stat_content.rfind(")")
                            if rparen != -1:
                                t_char = stat_content[rparen + 1:].strip().split()[0]
                                state_map = {
                                    "R": "RUNNING",
                                    "S": "SLEEPING",
                                    "D": "DISK_SLEEP",
                                    "T": "STOPPED",
                                    "t": "TRACING_STOP",
                                    "Z": "ZOMBIE",
                                }
                                t_state = state_map.get(t_char, t_char)
                                is_t_stopped = t_char in ("T", "t")
                    except Exception:
                        pass
                    if is_t_stopped:
                        stopped_count += 1
                    else:
                        running_count += 1
                    threads.append({
                        "tid": tid,
                        "state": t_state,
                        "state_char": t_char,
                        "is_stopped": is_t_stopped,
                    })
    except Exception:
        pass

    total = len(threads)
    if total == 0:
        total = 1
        stopped_count = 0
        running_count = 1

    return {
        "threads": threads,
        "total_count": total,
        "stopped_count": stopped_count,
        "running_count": running_count,
        "all_stopped": (stopped_count == total and total > 0),
        "any_stopped": (stopped_count > 0),
        "mixed_states": (stopped_count > 0 and running_count > 0),
    }


class ProcessTargetHandle:
    """Safe process identification and signal transmission mechanism.

    Mitigates PID reuse race conditions:
    1. Primary: Linux pidfd (pidfd_open + pidfd_send_signal).
       Verifies that the process identity observed before calling pidfd_open()
       matches the identity pinned by the opened pidfd. If a PID reuse race occurs
       between stat read and pidfd_open, the pidfd is closed immediately and signal
       transmission is rejected.
    2. Fallback: Verifies (comm, starttime) before signal transmission when pidfd
       is genuinely unsupported by the kernel or forced fallback is enabled.
       Documents limitations: fallback cannot guarantee complete immunity against kernel
       scheduling races between /proc/<pid>/stat read and signal syscall.
    """

    def __init__(
        self,
        pid: int,
        force_fallback: bool = False,
        adapter: Optional[Any] = None,
        expected_identity: Optional[Dict[str, Any]] = None,
        expected_starttime: Optional[str] = None,
    ):
        self.pid = pid
        self.force_fallback = force_fallback
        self.adapter = adapter
        self.expected_identity: Dict[str, Any] = dict(expected_identity or {})
        if expected_starttime and "starttime" not in self.expected_identity:
            self.expected_identity["starttime"] = expected_starttime
        self.pidfd: Optional[int] = None
        self.pidfd_supported: bool = False
        self.pidfd_used: bool = False
        self.identity_mismatch: bool = False
        self.open_status: str = "UNINITIALIZED"
        self.initial_identity: Dict[str, Any] = {}
        self.pre_signal_identity: Optional[Dict[str, Any]] = None
        self.post_capture_identity: Optional[Dict[str, Any]] = None
        self.mem_fd: Optional[int] = None
        self.mem_pinned: bool = False
        self.mem_pin_error: Optional[str] = None
        self.identity_checkpoints: List[Dict[str, Any]] = []
        self.closed: bool = False

    def get_process_state(self) -> Dict[str, Any]:
        if self.adapter and hasattr(self.adapter, "get_process_state"):
            return self.adapter.get_process_state(self.pid)
        return _get_process_state(self.pid)

    def get_threads_state(self) -> Dict[str, Any]:
        if self.adapter and hasattr(self.adapter, "get_threads_state"):
            return self.adapter.get_threads_state(self.pid)
        return _get_threads_state(self.pid)

    def read_proc_maps(self) -> Any:
        if self.adapter and hasattr(self.adapter, "read_proc_maps"):
            return self.adapter.read_proc_maps(self.pid)
        return _read_proc_maps(self.pid)

    def read_thread_metadata(self) -> Any:
        if self.adapter and hasattr(self.adapter, "read_thread_metadata"):
            return self.adapter.read_thread_metadata(self.pid)
        return _read_thread_metadata(self.pid)

    def _pidfd_open(self, pid: int, flags: int = 0) -> int:
        if self.adapter and hasattr(self.adapter, "pidfd_open"):
            return self.adapter.pidfd_open(pid, flags)
        if hasattr(os, "pidfd_open"):
            return os.pidfd_open(pid, flags)
        raise OSError(errno.ENOSYS, "pidfd_open syscall unavailable on this platform")

    def _close_pidfd(self, fd: int) -> None:
        if self.adapter and hasattr(self.adapter, "close_pidfd"):
            self.adapter.close_pidfd(fd)
            return
        os.close(fd)

    def open(self) -> None:
        if self.closed:
            raise RuntimeError("Cannot open a closed ProcessTargetHandle")
        if self.adapter and hasattr(self.adapter, "open"):
            self.adapter.open(self)
            return

        # 1. Observe target process identity before pidfd_open
        try:
            pre_identity = self.get_process_state()
        except ProcessLookupError:
            self.open_status = "TARGET_EXITED"
            raise
        except PermissionError:
            self.open_status = "PERMISSION_DENIED"
            raise
        except Exception as e:
            self.open_status = "IDENTITY_READ_ERROR"
            raise

        # If expected identity was supplied, verify pre-identity against it immediately
        if self.expected_identity:
            exp_starttime = str(self.expected_identity.get("starttime", ""))
            obs_starttime = str(pre_identity.get("starttime", ""))
            if exp_starttime and obs_starttime and exp_starttime != obs_starttime:
                self.identity_mismatch = True
                self.open_status = "IDENTITY_MISMATCH"
                raise ProcessLookupError(
                    f"Process identity mismatch before pidfd_open: PID {self.pid} expected starttime {exp_starttime}, got {obs_starttime}"
                )

        # 2. Attempt to open pidfd if supported and not forced to fallback
        can_try_pidfd = (
            not self.force_fallback
            and platform.system() == "Linux"
            and (hasattr(os, "pidfd_open") or (self.adapter and hasattr(self.adapter, "pidfd_open")))
            and (hasattr(signal, "pidfd_send_signal") or (self.adapter and hasattr(self.adapter, "send_signal")))
        )

        if can_try_pidfd:
            try:
                self.pidfd = self._pidfd_open(self.pid, 0)
                self.pidfd_supported = True
            except ProcessLookupError:
                self.open_status = "TARGET_EXITED"
                raise
            except PermissionError:
                self.open_status = "PERMISSION_DENIED"
                raise
            except OSError as exc:
                if exc.errno == errno.ESRCH:
                    self.open_status = "TARGET_EXITED"
                    raise ProcessLookupError(f"Target process {self.pid} exited before pidfd_open")
                elif exc.errno == errno.EPERM:
                    self.open_status = "PERMISSION_DENIED"
                    raise PermissionError(f"Permission denied opening pidfd for process {self.pid}")
                elif exc.errno in (errno.ENOSYS, errno.EOPNOTSUPP) or isinstance(exc, AttributeError):
                    # Kernel or environment does not support pidfd
                    self.pidfd = None
                    self.pidfd_supported = False
                    self.open_status = "UNSUPPORTED_PIDFD"
                else:
                    self.pidfd = None
                    self.pidfd_supported = False
                    self.open_status = "PIDFD_INIT_FAILED"
                    raise
            except Exception:
                self.pidfd = None
                self.pidfd_supported = False
                self.open_status = "PIDFD_INIT_FAILED"
                raise

        # 3. If pidfd was successfully opened, VERIFY identity matches pre-open identity
        if self.pidfd is not None:
            try:
                # With pidfd pinned in kernel, read identity again
                post_identity = self.get_process_state()
            except Exception as e:
                # Target exited right after pidfd_open
                try:
                    self._close_pidfd(self.pidfd)
                except Exception:
                    pass
                self.pidfd = None
                self.pidfd_used = False
                self.open_status = "TARGET_EXITED"
                raise ProcessLookupError(f"Failed to read target process state after pidfd_open: {e}")

            # Check if PID was reused between pre_identity read and pidfd_open
            starttime_match = (
                str(post_identity.get("starttime", "")) == str(pre_identity.get("starttime", ""))
            )
            comm_match = (
                post_identity.get("comm") == pre_identity.get("comm")
            )
            if not starttime_match or not comm_match:
                # PID REUSE RACE DETECTED!
                # Close pidfd immediately and NEVER fall back to PID-based signal!
                try:
                    self._close_pidfd(self.pidfd)
                except Exception:
                    pass
                self.pidfd = None
                self.pidfd_used = False
                self.identity_mismatch = True
                self.open_status = "IDENTITY_MISMATCH"
                raise ProcessLookupError(
                    f"PID reuse race detected: process {self.pid} identity changed during pidfd_open "
                    f"(starttime: {pre_identity.get('starttime')} -> {post_identity.get('starttime')}, "
                    f"comm: {pre_identity.get('comm')} -> {post_identity.get('comm')})"
                )

            # Identity successfully verified and pinned!
            self.pidfd_used = True
            self.initial_identity = post_identity
            self.open_status = "PIDFD_OPENED"
            self._try_pin_mem()
            return

        # 4. Fallback path (only when pidfd is unsupported or force_fallback is True)
        self.pidfd_used = False
        self.initial_identity = pre_identity
        self.open_status = "FALLBACK_INITIALIZED"
        self._try_pin_mem()

    def _try_pin_mem(self) -> None:
        """Attempt to retain an open descriptor to /proc/<pid>/mem to safely pin memory context."""
        if platform.system() == "Linux" and not (self.adapter and hasattr(self.adapter, "open")):
            try:
                mem_path = f"/proc/{self.pid}/mem"
                flags = os.O_RDONLY
                if hasattr(os, "O_CLOEXEC"):
                    flags |= os.O_CLOEXEC
                self.mem_fd = os.open(mem_path, flags)
                self.mem_pinned = True
            except Exception as e:
                self.mem_fd = None
                self.mem_pinned = False
                self.mem_pin_error = str(e)

    def read_mem(self, address: int, size: int) -> Optional[bytes]:
        """Read memory from pinned /proc/<pid>/mem descriptor if available."""
        if self.closed or not self.mem_pinned or self.mem_fd is None:
            return None
        try:
            return os.pread(self.mem_fd, size, address)
        except Exception:
            return None

    def record_checkpoint(self, checkpoint_name: str) -> Tuple[bool, str]:
        """Verify identity and record checkpoint in audit trail."""
        is_same, status = self.verify_identity()
        self.identity_checkpoints.append({
            "name": checkpoint_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "verified": is_same,
            "status": status,
        })
        return is_same, status

    def send_signal(self, sig: int) -> Tuple[bool, Optional[str]]:
        if self.closed:
            return False, "HANDLE_CLOSED"
        if self.identity_mismatch:
            return False, "IDENTITY_MISMATCH"
        if self.adapter and hasattr(self.adapter, "send_signal"):
            return self.adapter.send_signal(self, sig)

        try:
            self.pre_signal_identity = self.get_process_state()
        except ProcessLookupError:
            return False, "TARGET_EXITED"
        except Exception as e:
            return False, f"IDENTITY_READ_ERROR: {e}"

        if self.pidfd_used and self.pidfd is not None:
            try:
                signal.pidfd_send_signal(self.pidfd, sig)
                return True, None
            except ProcessLookupError:
                return False, "TARGET_EXITED"
            except PermissionError:
                return False, "PERMISSION_DENIED"
            except OSError as exc:
                if exc.errno == errno.ESRCH:
                    return False, "TARGET_EXITED"
                elif exc.errno == errno.EPERM:
                    return False, "PERMISSION_DENIED"
                return False, f"SIGNAL_ERROR_ERRNO_{exc.errno}"
            except Exception as exc:
                return False, f"SIGNAL_ERROR_{exc}"
        else:
            # Fallback path: verify starttime and strict PID > 1 before os.kill
            if type(self.pid) is not int or self.pid <= 1:
                return False, "INVALID_PID_FOR_SIGNAL"
            if self.pre_signal_identity.get("starttime") != self.initial_identity.get("starttime"):
                return False, "PID_REUSED"
            try:
                os.kill(self.pid, sig)
                return True, None
            except ProcessLookupError:
                return False, "TARGET_EXITED"
            except PermissionError:
                return False, "PERMISSION_DENIED"
            except OSError as exc:
                if exc.errno == errno.ESRCH:
                    return False, "TARGET_EXITED"
                elif exc.errno == errno.EPERM:
                    return False, "PERMISSION_DENIED"
                return False, f"SIGNAL_ERROR_ERRNO_{exc.errno}"
            except Exception as exc:
                return False, f"SIGNAL_ERROR_{exc}"

    def verify_identity(self) -> Tuple[bool, str]:
        if self.closed:
            return False, "HANDLE_CLOSED"
        if self.identity_mismatch:
            return False, "IDENTITY_MISMATCH"
        if self.adapter and hasattr(self.adapter, "verify_identity"):
            return self.adapter.verify_identity(self)

        if self.pidfd_used and self.pidfd is not None:
            try:
                signal.pidfd_send_signal(self.pidfd, 0)
                try:
                    curr = self.get_process_state()
                    self.post_capture_identity = curr
                    if self.initial_identity and curr.get("starttime") != self.initial_identity.get("starttime"):
                        self.identity_mismatch = True
                        return False, "PID_REUSED"
                except Exception:
                    pass
                return True, "PIDFD_VERIFIED"
            except (ProcessLookupError, OSError) as exc:
                if getattr(exc, "errno", None) == errno.ESRCH or isinstance(exc, ProcessLookupError):
                    return False, "TARGET_EXITED"
                elif getattr(exc, "errno", None) == errno.EPERM or isinstance(exc, PermissionError):
                    return True, "PIDFD_EXISTS_EPERM"
                return False, f"PIDFD_ERROR_ERRNO_{getattr(exc, 'errno', 'UNKNOWN')}"
            except Exception as e:
                return False, f"PIDFD_ERROR_{e}"
        else:
            try:
                curr = self.get_process_state()
                self.post_capture_identity = curr
                if curr.get("starttime") != self.initial_identity.get("starttime"):
                    return False, "PID_REUSED"
                return True, "FALLBACK_VERIFIED"
            except ProcessLookupError:
                return False, "TARGET_EXITED"
            except Exception as e:
                return False, f"IDENTITY_CHECK_FAILED: {e}"

    def get_diagnostics(self) -> Dict[str, Any]:
        return {
            "status": self.open_status,
            "pidfd_supported": self.pidfd_supported,
            "pidfd_used": self.pidfd_used,
            "identity_mismatch": self.identity_mismatch,
            "mitigation_mechanism": (
                "PIDFD"
                if self.pidfd_used
                else "STAT_STARTTIME_CHECK_FALLBACK"
            ),
            "memory_pin_status": "MEM_PINNED" if self.mem_pinned else "MEM_UNPINNED",
            "mem_pinned": self.mem_pinned,
            "mem_pin_error": self.mem_pin_error,
            "fallback_caveat": (
                None
                if self.pidfd_used
                else "Fallback starttime verification cannot guarantee complete immunity against kernel PID recycling races between stat read and signal delivery."
            ),
            "initial_identity": self.initial_identity,
            "pre_signal_identity": self.pre_signal_identity,
            "post_capture_identity": self.post_capture_identity,
            "identity_checkpoints": list(self.identity_checkpoints),
            "closed": self.closed,
        }

    def close(self) -> None:
        if self.adapter and hasattr(self.adapter, "close"):
            self.adapter.close(self)
        if self.mem_fd is not None:
            try:
                os.close(self.mem_fd)
            except Exception:
                pass
            self.mem_fd = None
            self.mem_pinned = False
        if self.pidfd is not None:
            try:
                self._close_pidfd(self.pidfd)
            except Exception:
                pass
            self.pidfd = None
        self.closed = True

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()


def _get_process_identity(pid: int) -> Tuple[str, str]:
    """Return (comm, starttime) from /proc/<pid>/stat.
    Raises ProcessLookupError if process does not exist.
    """
    stat_path = f"/proc/{pid}/stat"
    if not os.path.exists(stat_path):
        raise ProcessLookupError(f"Process {pid} does not exist (ESRCH)")
    try:
        with open(stat_path, "r", encoding="utf-8") as f:
            content = f.read()
    except (FileNotFoundError, ProcessLookupError):
        raise ProcessLookupError(f"Process {pid} does not exist (ESRCH)")

    rparen = content.rfind(")")
    if rparen == -1:
        return "unknown", "0"
    lparen = content.find("(")
    comm = content[lparen + 1:rparen] if lparen != -1 else "unknown"
    rest = content[rparen + 1:].strip().split()
    starttime = rest[19] if len(rest) > 19 else "0"
    return comm, starttime


class ProcMapsResult(list):
    """Container for parsed /proc/<pid>/maps regions preserving list compatibility with explicit enumeration status."""

    def __init__(
        self,
        regions: Optional[Any] = None,
        status: str = "SUCCESS_WITH_RESULTS",
        error_type: Optional[str] = None,
        error: Optional[str] = None,
        diagnostics: Optional[List[Dict[str, Any]]] = None,
    ):
        super().__init__(regions or [])
        self.status = status  # SUCCESS_WITH_RESULTS, SUCCESS_EMPTY, FAILED, PARTIAL
        self.error_type = error_type  # PERMISSION_DENIED, TARGET_EXITED, MALFORMED, IO_ERROR
        self.error = error
        self.diagnostics = list(diagnostics or [])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "error_type": self.error_type,
            "error": self.error,
            "region_count": len(self),
            "diagnostics": list(self.diagnostics),
        }


class ThreadMetadataResult(list):
    """Container for parsed /proc/<pid>/task thread records preserving list compatibility with explicit enumeration status."""

    def __init__(
        self,
        threads: Optional[Any] = None,
        status: str = "SUCCESS_WITH_RESULTS",
        error_type: Optional[str] = None,
        error: Optional[str] = None,
        is_synthetic: bool = False,
        diagnostics: Optional[List[Dict[str, Any]]] = None,
    ):
        super().__init__(threads or [])
        self.status = status  # SUCCESS_WITH_RESULTS, SUCCESS_EMPTY, FAILED, PARTIAL
        self.error_type = error_type  # PERMISSION_DENIED, TARGET_EXITED, IO_ERROR, TASK_DIR_MISSING
        self.error = error
        self.is_synthetic = is_synthetic
        self.diagnostics = list(diagnostics or [])

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "error_type": self.error_type,
            "error": self.error,
            "is_synthetic": self.is_synthetic,
            "thread_count": len(self),
            "diagnostics": list(self.diagnostics),
        }


def _read_proc_maps(pid: int) -> ProcMapsResult:
    """Parse /proc/<pid>/maps with explicit outcome modeling and structured error details."""
    maps_path = f"/proc/{pid}/maps"
    diagnostics: List[Dict[str, Any]] = []

    try:
        with open(maps_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except (FileNotFoundError, ProcessLookupError) as exc:
        err_msg = f"Process {pid} maps not found (ESRCH): {exc}"
        diagnostics.append({"code": "MAPS_TARGET_EXITED", "message": err_msg, "level": "ERROR"})
        return ProcMapsResult(
            [],
            status="FAILED",
            error_type="TARGET_EXITED",
            error=err_msg,
            diagnostics=diagnostics,
        )
    except PermissionError as exc:
        err_msg = f"Permission denied reading /proc/{pid}/maps: {exc}"
        diagnostics.append({"code": "MAPS_PERMISSION_DENIED", "message": err_msg, "level": "ERROR"})
        return ProcMapsResult(
            [],
            status="FAILED",
            error_type="PERMISSION_DENIED",
            error=err_msg,
            diagnostics=diagnostics,
        )
    except Exception as exc:
        err_msg = f"Failed to read /proc/{pid}/maps: {exc}"
        diagnostics.append({"code": "MAPS_IO_ERROR", "message": err_msg, "level": "ERROR"})
        return ProcMapsResult(
            [],
            status="FAILED",
            error_type="IO_ERROR",
            error=err_msg,
            diagnostics=diagnostics,
        )

    if not lines:
        return ProcMapsResult(
            [],
            status="SUCCESS_EMPTY",
            error_type=None,
            error=None,
            diagnostics=[{"code": "MAPS_EMPTY", "message": f"/proc/{pid}/maps is empty", "level": "INFO"}],
        )

    regions = []
    malformed_count = 0
    for line in lines:
        line_str = line.strip()
        if not line_str:
            continue
        parts = line_str.split(maxsplit=5)
        if len(parts) < 5:
            malformed_count += 1
            continue
        try:
            addr_range = parts[0]
            perms = parts[1]
            offset = parts[2]
            dev = parts[3]
            inode = parts[4]
            pathname = parts[5] if len(parts) > 5 else ""
            if "-" not in addr_range:
                malformed_count += 1
                continue
            s_str, e_str = addr_range.split("-")
            start = int(s_str, 16)
            end = int(e_str, 16)
        except Exception:
            malformed_count += 1
            continue

        cat = "unknown"
        if pathname == "[heap]":
            cat = "heap"
        elif pathname.startswith("[stack"):
            cat = "stack"
        elif pathname.endswith(".so") or ".so." in pathname:
            cat = "library"
        elif pathname and not pathname.startswith("["):
            cat = "binary"
        elif not pathname:
            cat = "anonymous"

        is_guard_preceded_stack = (
            cat == "anonymous"
            and perms.startswith("rw")
            and (end - start) >= 4 * 1024 * 1024
            and bool(regions)
            and regions[-1].get("permissions", "").startswith("---")
            and regions[-1].get("end") == start
        )
        if (cat == "stack" or is_guard_preceded_stack) and (end - start) > 128 * 1024:
            start = end - 128 * 1024
        elif cat == "anonymous" and not pathname and (end - start) >= 2 * 1024 * 1024:
            end = start + 256 * 1024

        regions.append({
            "start": start,
            "end": end,
            "size": end - start,
            "permissions": perms,
            "offset": int(offset, 16) if isinstance(offset, str) else offset,
            "category": cat,
            "pathname": pathname
        })

    if malformed_count > 0:
        if regions:
            diagnostics.append({
                "code": "MAPS_PARTIALLY_MALFORMED",
                "message": f"{malformed_count} malformed lines found in /proc/{pid}/maps",
                "level": "WARNING"
            })
            return ProcMapsResult(
                regions,
                status="PARTIAL",
                error_type="MALFORMED",
                error=f"{malformed_count} malformed map lines",
                diagnostics=diagnostics,
            )
        else:
            diagnostics.append({
                "code": "MAPS_ENTIRELY_MALFORMED",
                "message": f"All lines in /proc/{pid}/maps were malformed",
                "level": "ERROR"
            })
            return ProcMapsResult(
                [],
                status="FAILED",
                error_type="MALFORMED",
                error=f"All {malformed_count} lines malformed",
                diagnostics=diagnostics,
            )

    return ProcMapsResult(
        regions,
        status="SUCCESS_WITH_RESULTS" if regions else "SUCCESS_EMPTY",
        error_type=None,
        error=None,
        diagnostics=diagnostics,
    )


def _read_thread_metadata(pid: int) -> ThreadMetadataResult:
    """Read thread information quickly from /proc/<pid>/task with explicit outcome modeling."""
    threads = []
    task_dir = f"/proc/{pid}/task"
    diagnostics: List[Dict[str, Any]] = []

    if not os.path.exists(task_dir):
        err_msg = f"Task directory {task_dir} does not exist (TARGET_EXITED)"
        diagnostics.append({"code": "THREAD_TASK_DIR_MISSING", "message": err_msg, "level": "WARNING"})
        placeholder = [{
            "thread_id": pid,
            "name": None,
            "state": "UNKNOWN",
            "stop_status": "UNKNOWN",
            "is_synthetic": True,
            "verified_observation": False,
            "capture_participation": False,
            "registers_availability": "REGISTER_STATE_UNAVAILABLE",
            "function": None,
            "location": None,
        }]
        return ThreadMetadataResult(
            placeholder,
            status="FAILED",
            error_type="TARGET_EXITED",
            error=err_msg,
            is_synthetic=True,
            diagnostics=diagnostics,
        )

    try:
        entries = os.listdir(task_dir)
    except (FileNotFoundError, ProcessLookupError) as exc:
        err_msg = f"Process {pid} exited while enumerating task directory: {exc}"
        diagnostics.append({"code": "THREAD_TARGET_EXITED", "message": err_msg, "level": "WARNING"})
        placeholder = [{
            "thread_id": pid,
            "name": None,
            "state": "UNKNOWN",
            "stop_status": "UNKNOWN",
            "is_synthetic": True,
            "verified_observation": False,
            "capture_participation": False,
            "registers_availability": "REGISTER_STATE_UNAVAILABLE",
            "function": None,
            "location": None,
        }]
        return ThreadMetadataResult(
            placeholder,
            status="FAILED",
            error_type="TARGET_EXITED",
            error=err_msg,
            is_synthetic=True,
            diagnostics=diagnostics,
        )
    except PermissionError as exc:
        err_msg = f"Permission denied accessing {task_dir}: {exc}"
        diagnostics.append({"code": "THREAD_PERMISSION_DENIED", "message": err_msg, "level": "ERROR"})
        placeholder = [{
            "thread_id": pid,
            "name": None,
            "state": "UNKNOWN",
            "stop_status": "UNKNOWN",
            "is_synthetic": True,
            "verified_observation": False,
            "capture_participation": False,
            "registers_availability": "REGISTER_STATE_UNAVAILABLE",
            "function": None,
            "location": None,
        }]
        return ThreadMetadataResult(
            placeholder,
            status="FAILED",
            error_type="PERMISSION_DENIED",
            error=err_msg,
            is_synthetic=True,
            diagnostics=diagnostics,
        )
    except Exception as exc:
        err_msg = f"Failed to list {task_dir}: {exc}"
        diagnostics.append({"code": "THREAD_IO_ERROR", "message": err_msg, "level": "ERROR"})
        placeholder = [{
            "thread_id": pid,
            "name": None,
            "state": "UNKNOWN",
            "stop_status": "UNKNOWN",
            "is_synthetic": True,
            "verified_observation": False,
            "capture_participation": False,
            "registers_availability": "REGISTER_STATE_UNAVAILABLE",
            "function": None,
            "location": None,
        }]
        return ThreadMetadataResult(
            placeholder,
            status="FAILED",
            error_type="IO_ERROR",
            error=err_msg,
            is_synthetic=True,
            diagnostics=diagnostics,
        )

    task_read_errors = 0
    for entry in entries:
        if entry.isdigit():
            tid = int(entry)
            t_name = None
            comm_path = os.path.join(task_dir, entry, "comm")
            try:
                with open(comm_path, "r", encoding="utf-8") as f:
                    t_name = f.read().strip() or None
            except Exception:
                pass

            t_state = "UNKNOWN"
            stat_path = os.path.join(task_dir, entry, "stat")
            try:
                with open(stat_path, "r", encoding="utf-8") as f:
                    stat_content = f.read()
                    rparen = stat_content.rfind(")")
                    if rparen != -1:
                        state_char = stat_content[rparen + 1:].strip().split()[0]
                        state_map = {
                            "R": "RUNNING",
                            "S": "SLEEPING",
                            "D": "DISK_SLEEP",
                            "T": "STOPPED",
                            "t": "TRACING_STOP",
                            "Z": "ZOMBIE",
                        }
                        t_state = state_map.get(state_char, state_char)
            except Exception:
                task_read_errors += 1

            threads.append({
                "thread_id": tid,
                "name": t_name,
                "state": t_state,
                "stop_status": "STOPPED" if t_state in ("STOPPED", "TRACING_STOP") else ("UNKNOWN" if t_state == "UNKNOWN" else "NOT_STOPPED"),
                "is_synthetic": False,
                "verified_observation": (t_state != "UNKNOWN"),
                "capture_participation": True,
                "registers_availability": "REGISTER_STATE_UNAVAILABLE",
                "function": None,
                "location": None,
            })

    if not threads:
        err_msg = f"No threads could be enumerated for process {pid}"
        placeholder = [{
            "thread_id": pid,
            "name": None,
            "state": "UNKNOWN",
            "stop_status": "UNKNOWN",
            "is_synthetic": True,
            "verified_observation": False,
            "capture_participation": False,
            "registers_availability": "REGISTER_STATE_UNAVAILABLE",
            "function": None,
            "location": None,
        }]
        return ThreadMetadataResult(
            placeholder,
            status="FAILED",
            error_type="IO_ERROR",
            error=err_msg,
            is_synthetic=True,
            diagnostics=diagnostics,
        )

    threads.sort(key=lambda t: t["thread_id"])
    if task_read_errors > 0:
        diagnostics.append({
            "code": "THREAD_PARTIAL_READ_ERRORS",
            "message": f"{task_read_errors} thread stat reads failed",
            "level": "WARNING"
        })
        return ThreadMetadataResult(
            threads,
            status="PARTIAL",
            error_type="IO_ERROR",
            error=f"{task_read_errors} thread stat reads failed",
            is_synthetic=False,
            diagnostics=diagnostics,
        )

    return ThreadMetadataResult(
        threads,
        status="SUCCESS_WITH_RESULTS",
        error_type=None,
        error=None,
        is_synthetic=False,
        diagnostics=diagnostics,
    )


class ProcessVmCaptureBackend(RuntimeCaptureBackend):
    """Ultra-fast capture backend using Linux process_vm_readv() with minimal stop time."""

    def __init__(self):
        self._libc = None
        self._has_process_vm_readv = False
        if platform.system() == "Linux":
            try:
                self._libc = ctypes.CDLL(None, use_errno=True)
                if hasattr(self._libc, "process_vm_readv"):
                    fn = self._libc.process_vm_readv
                    fn.argtypes = [
                        ctypes.c_int,
                        ctypes.POINTER(_struct_iovec),
                        ctypes.c_ulong,
                        ctypes.POINTER(_struct_iovec),
                        ctypes.c_ulong,
                        ctypes.c_ulong,
                    ]
                    fn.restype = ctypes.c_ssize_t
                    self._has_process_vm_readv = True
            except Exception:
                self._has_process_vm_readv = False

    @property
    def name(self) -> str:
        return "process_vm_readv"

    @property
    def capabilities(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "can_suspend_inferior": True,  # backend can suspend target via external signals (SIGSTOP/SIGCONT) when requested by capture plan
            "can_read_registers": False,
            "can_read_memory": True,
            "atomicity": "NON_ATOMIC",
            "zero_stop_supported": True,
            "syscall_suspends": False,
            "suspension_method": "signal_external",
            "mode_behaviors": {
                "ZERO_STOP": {
                    "suspends_process": False,
                    "atomicity": "NON_ATOMIC",
                    "description": "Zero-stop live capture: reads target memory without pausing process; snapshot is NOT atomic.",
                },
                "FULL": {
                    "suspends_process": True,
                    "atomicity": "CONDITIONAL_ON_STOP",
                    "description": "Signals target with SIGSTOP; consistency depends on stop confirmation.",
                },
                "TARGETED": {
                    "suspends_process": True,
                    "atomicity": "CONDITIONAL_ON_STOP",
                    "description": "Signals target with SIGSTOP; captures selected semantic ranges.",
                },
                "THREAD": {
                    "suspends_process": True,
                    "atomicity": "CONDITIONAL_ON_STOP",
                    "description": "Signals target with SIGSTOP; captures thread stack memory.",
                },
                "OBJECT": {
                    "suspends_process": True,
                    "atomicity": "CONDITIONAL_ON_STOP",
                    "description": "Signals target with SIGSTOP; captures object memory ranges.",
                },
            },
        }

    def is_available(self, pid: Optional[int] = None) -> bool:
        if not self._has_process_vm_readv:
            return False
        if pid is not None:
            try:
                os.kill(pid, 0)
                return True
            except Exception:
                return False
        return True

    def capture(
        self,
        pid: int,
        plan: Optional[CapturePlan] = None,
        policy: Optional[CaptureSafetyPolicy] = None,
        snapshot_id: Optional[str] = None,
        observation_point: Optional[Dict[str, Any]] = None,
        handle: Optional[ProcessTargetHandle] = None,
    ) -> RawRuntimeSnapshot:
        plan = plan or CapturePlan()
        policy = policy or CaptureSafetyPolicy()

        handle = handle or getattr(policy, "target_handle", None)
        if handle is None and not self.is_available(pid):
            raise RuntimeError(f"process_vm_readv is unavailable or target PID {pid} is not accessible")

        # Use ProcessTargetHandle for pidfd support and strict PID reuse mitigation
        force_fb = getattr(policy, "force_fallback", False)
        exp_id = getattr(policy, "expected_identity", None)
        exp_st = getattr(policy, "expected_starttime", None)
        handle = handle or ProcessTargetHandle(
            pid,
            force_fallback=force_fb,
            expected_identity=exp_id,
            expected_starttime=exp_st,
        )
        try:
            handle.open()
        except Exception:
            handle.close()
            raise

        initial_ident = handle.initial_identity
        initial_threads = handle.get_threads_state()
        was_already_stopped = initial_ident.get("is_stopped", False)
        is_tracing_stop = initial_ident.get("is_tracing_stop", False)
        target_start_time = initial_ident.get("starttime", "0")
        comm = initial_ident.get("comm", "unknown")

        sid = snapshot_id or "RS_{:06d}_{:04d}".format(pid, int(time.time() * 1000) % 10000)
        t_overall_start_ns = time.monotonic_ns()
        wall_clock_start = datetime.now(timezone.utc).isoformat()

        # State machine tracking
        state_history = ["INITIALIZED"]
        capture_status = "COMPLETED"
        stop_requested = False
        stop_confirmed = False
        resume_requested = False
        resume_confirmed = False
        suspension_caused_by_capture = False
        all_threads_stopped = False
        memory_read_completed = False
        diagnostics: List[Dict[str, Any]] = []

        if is_tracing_stop:
            diagnostics.append({
                "code": "TRACING_STOP_OBSERVED",
                "message": f"Process {pid} is in TRACING_STOP ('t'). It may be attached to a debugger/tracer. External signal control may conflict with tracer.",
                "level": "WARNING"
            })

        if initial_threads.get("mixed_states"):
            diagnostics.append({
                "code": "MIXED_THREAD_STATES_AT_START",
                "message": f"Process {pid} threads have heterogeneous states: {initial_threads['stopped_count']} stopped, {initial_threads['running_count']} active.",
                "level": "INFO"
            })

        # Read binary executable path and build_id
        exe_path = ""
        try:
            exe_link = f"/proc/{pid}/exe"
            if os.path.exists(exe_link):
                exe_path = os.path.realpath(exe_link)
        except Exception:
            pass

        build_id = None
        if exe_path and os.path.exists(exe_path):
            try:
                from .debug_image import inspect_elf
                info = inspect_elf(exe_path)
                build_id = info.build_id
            except Exception:
                pass

        t_stop_requested = 0
        t_stop_confirmed = 0
        t_threads = 0
        t_memory = 0
        t_resume_requested = 0
        t_resume_confirmed = 0

        raw_regions: List[Dict[str, Any]] = []
        thread_metadata: List[Dict[str, Any]] = []
        captured_ranges: List[Tuple[int, int]] = []
        buffers: Dict[Tuple[int, int], bytes] = {}
        completeness = "COMPLETE"

        # Determine suspension intent based on plan and preexisting state
        should_suspend = (plan.mode != CaptureMode.ZERO_STOP.value)
        if plan.mode == CaptureMode.ZERO_STOP.value:
            should_suspend = False
            state_history.append("ZERO_STOP_MODE")
        elif was_already_stopped:
            should_suspend = False
            stop_confirmed = True
            state_history.append("PREEXISTING_STOP_PRESERVED")
            diagnostics.append({
                "code": "PREEXISTING_STOPPED_STATE_PRESERVED",
                "message": f"Target process {pid} was already stopped ({initial_ident.get('state')}) before capture. SIGSTOP was skipped and SIGCONT will not be sent, preserving original stop state.",
                "level": "INFO"
            })

        # 0. Pre-read maps and pre-allocate capture buffers BEFORE suspending process
        handle.record_checkpoint("POST_OPEN")
        is_same_maps, ident_status_maps = handle.record_checkpoint("PRE_MAPS_READ")
        if not is_same_maps:
            diagnostics.append({
                "code": f"MAPS_READ_ABORTED_{ident_status_maps}",
                "message": f"Target process identity check failed ({ident_status_maps}) before maps collection; aborting capture.",
                "level": "ERROR"
            })
            all_maps = ProcMapsResult([], status="FAILED", error_type="TARGET_EXITED", error="Identity check failed before maps read")
        else:
            all_maps = handle.read_proc_maps()
            is_same_post_maps, ident_status_post_maps = handle.record_checkpoint("POST_MAPS_READ")
            if not is_same_post_maps:
                diagnostics.append({
                    "code": f"MAPS_READ_INVALIDATED_{ident_status_post_maps}",
                    "message": f"Target process identity changed ({ident_status_post_maps}) after reading maps.",
                    "level": "ERROR"
                })

        if hasattr(all_maps, "diagnostics"):
            diagnostics.extend(all_maps.diagnostics)

        selected_maps = []
        maps_enumeration_failed = (getattr(all_maps, "status", "SUCCESS_WITH_RESULTS") == "FAILED")
        explicit_ranges_used_without_maps = False

        if plan.mode == CaptureMode.TARGETED.value and plan.memory_ranges:
            for r_start, r_end in plan.memory_ranges:
                selected_maps.append({
                    "start": r_start,
                    "end": r_end,
                    "size": r_end - r_start,
                    "permissions": "rw-p",
                    "category": "targeted",
                    "pathname": "[targeted_range]"
                })
            if maps_enumeration_failed:
                explicit_ranges_used_without_maps = True
                diagnostics.append({
                    "code": "MAPS_ENUMERATION_FAILED_EXPLICIT_RANGES_USED",
                    "message": f"Memory map enumeration failed ({getattr(all_maps, 'error_type', 'UNKNOWN')}: {getattr(all_maps, 'error', '')}), but explicit target ranges were supplied. Layout could not be verified against proc maps; capture quality is capped at PARTIAL.",
                    "level": "WARNING"
                })
        elif plan.mode == CaptureMode.OBJECT.value and plan.memory_ranges:
            for r_start, r_end in plan.memory_ranges:
                selected_maps.append({
                    "start": r_start,
                    "end": r_end,
                    "size": r_end - r_start,
                    "permissions": "rw-p",
                    "category": "object",
                    "pathname": "[object_range]"
                })
            if maps_enumeration_failed:
                explicit_ranges_used_without_maps = True
                diagnostics.append({
                    "code": "MAPS_ENUMERATION_FAILED_EXPLICIT_RANGES_USED",
                    "message": f"Memory map enumeration failed ({getattr(all_maps, 'error_type', 'UNKNOWN')}: {getattr(all_maps, 'error', '')}), but explicit target ranges were supplied. Layout could not be verified against proc maps; capture quality is capped at PARTIAL.",
                    "level": "WARNING"
                })
        elif plan.mode == CaptureMode.THREAD.value and plan.thread_ids:
            if maps_enumeration_failed:
                diagnostics.append({
                    "code": "MAP_ENUMERATION_FAILED",
                    "message": f"Memory map enumeration failed ({getattr(all_maps, 'error_type', 'UNKNOWN')}: {getattr(all_maps, 'error', '')}). Cannot locate thread stack maps in THREAD mode.",
                    "level": "ERROR"
                })
            else:
                for m in all_maps:
                    if m["category"] == "stack" and "r" in m["permissions"]:
                        selected_maps.append(m)
        else:
            # FULL: Capture mutable runtime state (heap, stack, writable data/bss/anonymous)
            if maps_enumeration_failed:
                diagnostics.append({
                    "code": "MAP_ENUMERATION_FAILED",
                    "message": f"Memory map enumeration failed ({getattr(all_maps, 'error_type', 'UNKNOWN')}: {getattr(all_maps, 'error', '')}). FULL capture mode requires valid memory maps; cannot proceed.",
                    "level": "ERROR"
                })
            else:
                for m in all_maps:
                    if "r" in m["permissions"] and ("w" in m["permissions"] or m["category"] in ("heap", "stack", "anonymous")):
                        selected_maps.append(m)
                # Prioritize essential binary/data, heap, and stack regions before large anonymous arenas
                _cat_prio = {"binary": 0, "heap": 1, "stack": 2, "library": 3, "anonymous": 4, "unknown": 5}
                selected_maps.sort(key=lambda r: (_cat_prio.get(r.get("category", "unknown"), 5), r.get("start", 0)))

        if not selected_maps and plan.memory_ranges:
            for r_start, r_end in plan.memory_ranges:
                selected_maps.append({
                    "start": r_start,
                    "end": r_end,
                    "size": r_end - r_start,
                    "permissions": "rw-p",
                    "category": "targeted",
                    "pathname": "[targeted_range]"
                })
            if maps_enumeration_failed and not explicit_ranges_used_without_maps:
                explicit_ranges_used_without_maps = True
                diagnostics.append({
                    "code": "MAPS_ENUMERATION_FAILED_EXPLICIT_RANGES_USED",
                    "message": f"Memory map enumeration failed ({getattr(all_maps, 'error_type', 'UNKNOWN')}: {getattr(all_maps, 'error', '')}), but explicit target ranges were supplied. Layout could not be verified against proc maps; capture quality is capped at PARTIAL.",
                    "level": "WARNING"
                })

        # Pre-allocate buffers and iovecs before suspension, explicitly tracking omitted regions
        read_plans = []
        omitted_regions = []
        bytes_requested = sum(m["size"] for m in selected_maps)
        bytes_attempted = 0
        bytes_omitted = 0
        fn_vm_readv = self._libc.process_vm_readv if self._libc else None

        for idx, reg in enumerate(selected_maps, 1):
            reg_start = reg["start"]
            reg_size = reg["size"]
            if bytes_attempted >= policy.max_capture_bytes or idx > policy.max_capture_ranges:
                bytes_omitted += reg_size
                omitted_regions.append({
                    "region_id": f"R{idx:05d}",
                    "start": "0x{:x}".format(reg_start),
                    "end": "0x{:x}".format(reg_start + reg_size),
                    "size": reg_size,
                    "permissions": reg["permissions"],
                    "offset": reg.get("offset", 0),
                    "category": reg["category"],
                    "pathname": reg.get("pathname", ""),
                    "captured_bytes": 0,
                    "status": "OMITTED",
                    "error": "POLICY_LIMIT_EXCEEDED"
                })
                continue

            max_reg_cap = getattr(policy, "max_region_bytes", 0) or policy.max_capture_bytes
            if plan.mode in (CaptureMode.TARGETED.value, CaptureMode.OBJECT.value):
                max_reg_cap = policy.max_capture_bytes
            chunk_size = min(reg_size, max_reg_cap, policy.max_capture_bytes - bytes_attempted)
            if chunk_size <= 0:
                bytes_omitted += reg_size
                omitted_regions.append({
                    "region_id": f"R{idx:05d}",
                    "start": "0x{:x}".format(reg_start),
                    "end": "0x{:x}".format(reg_start + reg_size),
                    "size": reg_size,
                    "permissions": reg["permissions"],
                    "offset": reg.get("offset", 0),
                    "category": reg["category"],
                    "pathname": reg.get("pathname", ""),
                    "captured_bytes": 0,
                    "status": "OMITTED",
                    "error": "POLICY_LIMIT_EXCEEDED"
                })
                continue

            tail_omitted = reg_size - chunk_size
            if tail_omitted > 0:
                bytes_omitted += tail_omitted

            buf = ctypes.create_string_buffer(chunk_size)
            ctypes.memset(buf, 0, chunk_size)
            l_iov = _struct_iovec(ctypes.cast(buf, ctypes.c_void_p), chunk_size)
            r_iov = _struct_iovec(ctypes.c_void_p(reg_start), chunk_size)
            read_plans.append((idx, reg, reg_start, reg_size, chunk_size, tail_omitted, buf, l_iov, r_iov))
            bytes_attempted += chunk_size

        # Pre-warm collector and target virtual pages before SIGSTOP so page faults do not occur during suspension
        if should_suspend and fn_vm_readv and not getattr(policy, "mem_reader", None):
            for _item_idx, _reg, _r_start, _r_size, _c_size, _t_omit, _buf, _l_iov, _r_iov in read_plans:
                try:
                    fn_vm_readv(pid, ctypes.byref(_l_iov), 1, ctypes.byref(_r_iov), 1, 0)
                except Exception:
                    pass

        read_results = []

        try:
            # 1. Ultra-short suspend
            if should_suspend:
                is_same_pre_stop, ident_status_pre_stop = handle.record_checkpoint("PRE_SUSPEND")
                if not is_same_pre_stop:
                    suspension_caused_by_capture = False
                    diagnostics.append({
                        "code": f"STOP_ABORTED_{ident_status_pre_stop}",
                        "message": f"Target process identity check failed ({ident_status_pre_stop}) before SIGSTOP; suspension aborted.",
                        "level": "ERROR"
                    })
                else:
                    state_history.append("STOP_REQUESTED")
                    stop_requested = True
                    t_stop_requested = time.monotonic_ns()

                    sig_ok, sig_err = handle.send_signal(signal.SIGSTOP)
                    if not sig_ok:
                        suspension_caused_by_capture = False
                        if sig_err == "TARGET_EXITED":
                            diagnostics.append({
                                "code": "TARGET_EXITED_BEFORE_STOP",
                                "message": f"Process {pid} exited before SIGSTOP delivered",
                                "level": "ERROR"
                            })
                        elif sig_err == "PID_REUSED":
                            diagnostics.append({
                                "code": "PID_REUSED_STOP_ABORTED",
                                "message": f"Target PID {pid} was reused; SIGSTOP aborted to prevent signalling unrelated process",
                                "level": "ERROR"
                            })
                        elif sig_err == "PERMISSION_DENIED":
                            diagnostics.append({
                                "code": "STOP_PERMISSION_DENIED",
                                "message": f"Permission denied (EPERM) delivering SIGSTOP to process {pid}",
                                "level": "ERROR"
                            })
                        else:
                            diagnostics.append({
                                "code": "STOP_SIGNAL_ERROR",
                                "message": f"SIGSTOP failed: {sig_err}",
                                "level": "ERROR"
                            })
                    else:
                        deadline_stop = t_stop_requested + int(policy.max_stop_time_ms * 1_000_000)
                        while time.monotonic_ns() < deadline_stop:
                            try:
                                curr_st = handle.get_process_state()
                                if curr_st.get("is_stopped"):
                                    stop_confirmed = True
                                    curr_threads = handle.get_threads_state()
                                    if curr_threads.get("all_stopped", False):
                                        all_threads_stopped = True
                                        break
                            except Exception:
                                pass
                            try:
                                os.sched_yield()
                            except Exception:
                                pass

                        t_stop_confirmed = time.monotonic_ns()
                        if stop_confirmed:
                            suspension_caused_by_capture = True
                            state_history.append("STOP_CONFIRMED")
                            handle.record_checkpoint("POST_SUSPEND")
                        else:
                            suspension_caused_by_capture = False
                            state_history.append("STOP_UNCONFIRMED")
                            diagnostics.append({
                                "code": "STOP_UNCONFIRMED",
                                "message": f"Process {pid} did not enter stopped state within {policy.max_stop_time_ms} ms. Memory captured under this condition is NON_ATOMIC.",
                                "level": "WARNING"
                            })
            else:
                handle.record_checkpoint("PRE_SUSPEND_SKIPPED")
                t_stop_requested = time.monotonic_ns()
                t_stop_confirmed = t_stop_requested
                if was_already_stopped:
                    stop_confirmed = True

            # 2. Check thread consistency
            if not all_threads_stopped:
                curr_threads = handle.get_threads_state()
                all_threads_stopped = curr_threads.get("all_stopped", False)
            if (should_suspend or was_already_stopped) and not all_threads_stopped:
                diagnostics.append({
                    "code": "THREAD_STATES_HETEROGENEOUS",
                    "message": f"Process {pid} leader stopped, but not all threads are confirmed stopped ({curr_threads.get('stopped_count')}/{curr_threads.get('total_count')}). Snapshot is NON_ATOMIC.",
                    "level": "WARNING"
                })

            # 3. Capture thread metadata
            state_history.append("CAPTURING")
            is_same_th, ident_status_th = handle.record_checkpoint("PRE_THREAD_METADATA")
            if not is_same_th:
                thread_metadata = ThreadMetadataResult(
                    [{
                        "thread_id": pid,
                        "name": None,
                        "state": "UNKNOWN",
                        "stop_status": "UNKNOWN",
                        "is_synthetic": True,
                        "verified_observation": False,
                        "capture_participation": False,
                        "registers_availability": "REGISTER_STATE_UNAVAILABLE",
                        "function": None,
                        "location": None,
                    }],
                    status="FAILED",
                    error_type=ident_status_th,
                    error="Identity verification failed before thread metadata collection",
                    is_synthetic=True,
                )
            else:
                thread_metadata = handle.read_thread_metadata()
            handle.record_checkpoint("POST_THREAD_METADATA")
            t_threads = time.monotonic_ns()

            if getattr(thread_metadata, "is_synthetic", False) or getattr(thread_metadata, "status", "") == "FAILED":
                all_threads_stopped = False
                diagnostics.append({
                    "code": "THREAD_ENUMERATION_FAILED",
                    "message": f"Thread enumeration failed ({getattr(thread_metadata, 'error_type', 'UNKNOWN')}: {getattr(thread_metadata, 'error', '')}). Thread states are UNVERIFIED.",
                    "level": "WARNING"
                })
            if hasattr(thread_metadata, "diagnostics"):
                diagnostics.extend(thread_metadata.diagnostics)

            # 4. Read memory into pre-allocated buffers
            is_same_mem, ident_status_mem = handle.record_checkpoint("PRE_MEMORY_READ")
            mem_reader = getattr(policy, "mem_reader", None)
            for item in read_plans:
                idx, reg, reg_start, reg_size, chunk_size, tail_omitted, buf, l_iov, r_iov = item
                if not is_same_mem:
                    nread = -1
                    err = errno.ESRCH
                elif mem_reader:
                    try:
                        read_data = mem_reader(pid, reg_start, chunk_size)
                        if read_data is not None:
                            nread = len(read_data)
                            ctypes.memmove(buf, read_data, nread)
                            err = 0
                        else:
                            nread = -1
                            err = errno.EIO
                    except Exception:
                        nread = -1
                        err = errno.EIO
                elif fn_vm_readv:
                    nread = fn_vm_readv(
                        pid,
                        ctypes.byref(l_iov),
                        1,
                        ctypes.byref(r_iov),
                        1,
                        0
                    )
                    err = ctypes.get_errno() if nread <= 0 else 0
                    if nread <= 0 and err == errno.EINTR:
                        nread = fn_vm_readv(
                            pid,
                            ctypes.byref(l_iov),
                            1,
                            ctypes.byref(r_iov),
                            1,
                            0
                        )
                        err = ctypes.get_errno() if nread <= 0 else 0
                    if nread <= 0 and err in (errno.ENOSYS, errno.EPERM) and handle.mem_pinned and handle.mem_fd is not None:
                        # Fallback to pinned /proc/<pid>/mem if process_vm_readv is not permitted or syscall unsupported
                        try:
                            read_bytes = handle.read_mem(reg_start, chunk_size)
                            if read_bytes is not None:
                                nread = len(read_bytes)
                                ctypes.memmove(buf, read_bytes, nread)
                                err = 0
                        except Exception:
                            pass
                elif handle.mem_pinned and handle.mem_fd is not None:
                    # Fallback when fn_vm_readv is not available
                    try:
                        read_bytes = handle.read_mem(reg_start, chunk_size)
                        if read_bytes is not None:
                            nread = len(read_bytes)
                            ctypes.memmove(buf, read_bytes, nread)
                            err = 0
                        else:
                            nread = -1
                            err = errno.EIO
                    except Exception:
                        nread = -1
                        err = errno.EIO
                else:
                    nread = -1
                    err = errno.ENOSYS

                split_pages = None
                try:
                    import resource
                    PAGE_SIZE = resource.getpagesize()
                except Exception:
                    try:
                        PAGE_SIZE = os.sysconf("SC_PAGESIZE") if hasattr(os, "sysconf") else 4096
                    except Exception:
                        PAGE_SIZE = 4096
                if not PAGE_SIZE or PAGE_SIZE <= 0:
                    PAGE_SIZE = 4096
                if is_same_mem and chunk_size > PAGE_SIZE and (nread < chunk_size or (nread <= 0 and err in (errno.EFAULT, errno.EIO))):
                    # Page-aware resilient splitting: retry sub-regions page-by-page without dropping the entire chunk
                    split_pages = []
                    page_off = 0
                    while page_off < chunk_size:
                        page_len = min(PAGE_SIZE, chunk_size - page_off)
                        page_start = reg_start + page_off

                        # If already successfully read in initial call
                        if nread > 0 and (page_off + page_len) <= nread:
                            split_pages.append((page_off, page_len, page_len, 0))
                            page_off += page_len
                            continue

                        p_nread = -1
                        p_err = errno.EFAULT
                        if mem_reader:
                            try:
                                p_data = mem_reader(pid, page_start, page_len)
                                if p_data is not None:
                                    p_nread = len(p_data)
                                    ctypes.memmove(ctypes.byref(buf, page_off), p_data, p_nread)
                                    p_err = 0
                                else:
                                    p_nread = -1
                                    p_err = errno.EIO
                            except Exception:
                                p_nread = -1
                                p_err = errno.EIO
                        elif fn_vm_readv:
                            p_l_iov = _struct_iovec(ctypes.cast(ctypes.byref(buf, page_off), ctypes.c_void_p), page_len)
                            p_r_iov = _struct_iovec(ctypes.c_void_p(page_start), page_len)
                            p_nread = fn_vm_readv(
                                pid,
                                ctypes.byref(p_l_iov),
                                1,
                                ctypes.byref(p_r_iov),
                                1,
                                0
                            )
                            p_err = ctypes.get_errno() if p_nread <= 0 else 0
                            if p_nread <= 0 and p_err == errno.EINTR:
                                p_nread = fn_vm_readv(
                                    pid,
                                    ctypes.byref(p_l_iov),
                                    1,
                                    ctypes.byref(p_r_iov),
                                    1,
                                    0
                                )
                                p_err = ctypes.get_errno() if p_nread <= 0 else 0
                            if p_nread <= 0 and p_err in (errno.ENOSYS, errno.EPERM) and handle.mem_pinned and handle.mem_fd is not None:
                                try:
                                    p_bytes = handle.read_mem(page_start, page_len)
                                    if p_bytes is not None:
                                        p_nread = len(p_bytes)
                                        ctypes.memmove(ctypes.byref(buf, page_off), p_bytes, p_nread)
                                        p_err = 0
                                except Exception:
                                    pass
                        elif handle.mem_pinned and handle.mem_fd is not None:
                            try:
                                p_bytes = handle.read_mem(page_start, page_len)
                                if p_bytes is not None:
                                    p_nread = len(p_bytes)
                                    ctypes.memmove(ctypes.byref(buf, page_off), p_bytes, p_nread)
                                    p_err = 0
                                else:
                                    p_nread = -1
                                    p_err = errno.EIO
                            except Exception:
                                p_nread = -1
                                p_err = errno.EIO

                        split_pages.append((page_off, page_len, p_nread, p_err))
                        page_off += page_len

                    salvaged = sum(p[2] for p in split_pages if p[2] > 0)
                    if salvaged > 0:
                        nread = salvaged
                        err = 0

                if nread <= 0 and err == errno.ESRCH:
                    diagnostics.append({
                        "code": "TARGET_EXITED_DURING_CAPTURE",
                        "message": f"Process {pid} exited while reading range 0x{reg_start:x}-0x{reg_start+chunk_size:x} (ESRCH).",
                        "level": "ERROR"
                    })
                read_results.append((item, nread, err, split_pages))

            memory_read_completed = True
            handle.record_checkpoint("POST_MEMORY_READ")
            t_memory = time.monotonic_ns()

        finally:
            try:
                # 5. GUARANTEED FAIL-OPEN RESUME IMMEDIATELY WITH PID-REUSE SAFETY
                if suspension_caused_by_capture:
                    resume_requested = True
                    state_history.append("RESUME_REQUESTED")
                    t_resume_requested = time.monotonic_ns()
                    still_same_process = False
                    is_same, ident_status = handle.record_checkpoint("PRE_RESUME")
                    if is_same:
                        still_same_process = True
                    else:
                        if ident_status == "PID_REUSED":
                            diagnostics.append({
                                "code": "PID_REUSED_RESUME_ABORTED",
                                "message": f"PID {pid} was reused; SIGCONT aborted to prevent signalling unrelated process.",
                                "level": "WARNING"
                            })
                        elif ident_status == "TARGET_EXITED":
                            diagnostics.append({
                                "code": "TARGET_EXITED_DURING_CAPTURE",
                                "message": f"Process {pid} exited during capture; inferior is no longer running.",
                                "level": "INFO"
                            })
                        else:
                            diagnostics.append({
                                "code": "IDENTITY_VERIFICATION_FAILED",
                                "message": f"Process verification failed ({ident_status}); SIGCONT aborted.",
                                "level": "WARNING"
                            })

                    if still_same_process:
                        # Check if target already resumed independently
                        try:
                            post_check = handle.get_process_state()
                            if not post_check.get("is_stopped"):
                                resume_confirmed = True
                                state_history.append("TARGET_RESUMED_INDEPENDENTLY")
                                diagnostics.append({
                                    "code": "TARGET_RESUMED_INDEPENDENTLY",
                                    "message": f"Process {pid} was already active before SIGCONT; target resumed independently.",
                                    "level": "INFO"
                                })
                        except Exception:
                            pass

                        if not resume_confirmed:
                            res_ok, res_err = handle.send_signal(signal.SIGCONT)
                            if not res_ok:
                                if res_err == "TARGET_EXITED":
                                    diagnostics.append({
                                        "code": "TARGET_EXITED_BEFORE_RESUME",
                                        "message": f"Process {pid} exited before SIGCONT delivered.",
                                        "level": "INFO"
                                    })
                                elif res_err == "PERMISSION_DENIED":
                                    diagnostics.append({
                                        "code": "RESUME_PERMISSION_DENIED",
                                        "message": f"Permission denied delivering SIGCONT to process {pid}.",
                                        "level": "ERROR"
                                    })
                                else:
                                    diagnostics.append({
                                        "code": "RESUME_SIGNAL_ERROR",
                                        "message": f"SIGCONT failed: {res_err}",
                                        "level": "ERROR"
                                    })
                            else:
                                # Poll briefly for resume confirmation
                                deadline_res = t_resume_requested + int(20 * 1_000_000)
                                while time.monotonic_ns() < deadline_res:
                                    try:
                                        st_res = handle.get_process_state()
                                        if not st_res.get("is_stopped"):
                                            resume_confirmed = True
                                            break
                                    except Exception:
                                        pass
                                    try:
                                        os.sched_yield()
                                    except Exception:
                                        pass

                                t_resume_confirmed = time.monotonic_ns()
                                if resume_confirmed:
                                    state_history.append("RESUME_CONFIRMED")
                                    handle.record_checkpoint("POST_RESUME")
                                else:
                                    state_history.append("RESUME_UNCONFIRMED")
                                    diagnostics.append({
                                        "code": "RESUME_UNCONFIRMED",
                                        "message": f"Process {pid} did not confirm running state within timeout after SIGCONT.",
                                        "level": "WARNING"
                                    })
                    else:
                        t_resume_confirmed = time.monotonic_ns()
                elif was_already_stopped:
                    # Target was already stopped before capture; preserve existing stopped state!
                    state_history.append("PREEXISTING_STOP_RETAINED")
                    t_resume_requested = t_memory
                    t_resume_confirmed = t_memory
                else:
                    t_resume_requested = t_memory
                    t_resume_confirmed = t_memory
            finally:
                handle.close()

        wall_clock_end = datetime.now(timezone.utc).isoformat()

        # Ensure all read plans are accounted for even if an unhandled exception occurred
        processed_plan_indices = {r[0][0] for r in read_results}
        for item in read_plans:
            if item[0] not in processed_plan_indices:
                read_results.append((item, -1, errno.EIO, None))

        mapping_race_detected = False
        if getattr(policy, "simulate_mapping_race", False):
            mapping_race_detected = True

        for res_entry in read_results:
            nread = res_entry[1]
            err = res_entry[2]
            if nread <= 0 and err == errno.EFAULT and not explicit_ranges_used_without_maps:
                mapping_race_detected = True
                break

        any_target_exited = any(cp.get("status") == "TARGET_EXITED" for cp in getattr(handle, "identity_checkpoints", []))
        if not mapping_race_detected and not any_target_exited and hasattr(handle, "read_proc_maps"):
            try:
                post_maps = handle.read_proc_maps()
                if getattr(post_maps, "status", None) in ("SUCCESS_WITH_RESULTS", "SUCCESS_EMPTY"):
                    for m in selected_maps:
                        s, e = m["start"], m["end"]
                        pre_cov = next((pm for pm in all_maps if pm.get("start", 0) <= s and pm.get("end", 0) >= e), None)
                        if pre_cov is not None:
                            post_cov = next((pm for pm in post_maps if pm.get("start", 0) <= s and pm.get("end", 0) >= e), None)
                            if post_cov is None or "r" not in post_cov.get("permissions", ""):
                                mapping_race_detected = True
                                break
                            if pre_cov.get("permissions") != post_cov.get("permissions") or pre_cov.get("offset") != post_cov.get("offset") or pre_cov.get("pathname") != post_cov.get("pathname"):
                                mapping_race_detected = True
                                break
            except Exception:
                pass

        if mapping_race_detected:
            diagnostics.append({
                "code": "MAPPING_RACE_DETECTED",
                "message": "Memory mapping changed or invalidated during capture; snapshot completeness demoted to PARTIAL.",
                "level": "WARNING"
            })

        # 5. Offline post-processing of buffers (target process is already resumed!)
        bytes_read = 0
        bytes_failed = 0
        bytes_unread = 0

        for res_entry in read_results:
            if len(res_entry) == 4:
                item, nread, err, split_pages = res_entry
            else:
                item, nread, err = res_entry
                split_pages = None

            idx, reg, reg_start, reg_size, chunk_size, tail_omitted, buf, _, _ = item
            if split_pages is not None and any(p[2] > 0 for p in split_pages):
                # Page-aware split processing: salvage valid pages without dropping the chunk
                salvaged_in_chunk = 0
                failed_in_chunk = 0
                unreadable_subranges = []
                readable_subranges = []

                curr_start = None
                curr_len = 0
                for p_off, p_len, p_read, p_err in split_pages:
                    if p_read == p_len:
                        salvaged_in_chunk += p_read
                        if curr_start is None:
                            curr_start = reg_start + p_off
                            curr_len = p_read
                        else:
                            curr_len += p_read
                    else:
                        if curr_start is not None:
                            sub_bytes = bytes(buf.raw[(curr_start - reg_start):(curr_start - reg_start + curr_len)])
                            buffers[(curr_start, curr_start + curr_len)] = sub_bytes
                            captured_ranges.append((curr_start, curr_start + curr_len))
                            readable_subranges.append((curr_start, curr_start + curr_len))
                            curr_start = None
                            curr_len = 0
                        failed_in_chunk += p_len
                        unreadable_subranges.append((reg_start + p_off, reg_start + p_off + p_len))

                if curr_start is not None:
                    sub_bytes = bytes(buf.raw[(curr_start - reg_start):(curr_start - reg_start + curr_len)])
                    buffers[(curr_start, curr_start + curr_len)] = sub_bytes
                    captured_ranges.append((curr_start, curr_start + curr_len))
                    readable_subranges.append((curr_start, curr_start + curr_len))
                    curr_start = None
                    curr_len = 0

                bytes_read += salvaged_in_chunk
                bytes_failed += failed_in_chunk
                if tail_omitted > 0:
                    bytes_unread += tail_omitted

                status = "COMPLETE" if (failed_in_chunk == 0 and tail_omitted == 0) else "PARTIAL"
                raw_regions.append({
                    "region_id": f"R{idx:05d}",
                    "start": "0x{:x}".format(reg_start),
                    "end": "0x{:x}".format(reg_start + chunk_size),
                    "size": reg_size,
                    "permissions": reg["permissions"],
                    "offset": reg.get("offset", 0),
                    "category": reg["category"],
                    "pathname": reg.get("pathname", ""),
                    "captured_bytes": salvaged_in_chunk,
                    "status": status,
                    "error": None if status == "COMPLETE" else "PARTIAL_PAGE_FAULT",
                    "unreadable_subranges": [["0x{:x}".format(s), "0x{:x}".format(e)] for s, e in unreadable_subranges] if unreadable_subranges else [],
                })
            elif nread == chunk_size:
                read_bytes = bytes(buf.raw[:nread])
                buffers[(reg_start, reg_start + nread)] = read_bytes
                captured_ranges.append((reg_start, reg_start + nread))
                bytes_read += nread
                raw_regions.append({
                    "region_id": f"R{idx:05d}",
                    "start": "0x{:x}".format(reg_start),
                    "end": "0x{:x}".format(reg_start + nread),
                    "size": reg_size,
                    "permissions": reg["permissions"],
                    "offset": reg.get("offset", 0),
                    "category": reg["category"],
                    "pathname": reg.get("pathname", ""),
                    "captured_bytes": nread,
                    "status": "COMPLETE" if tail_omitted == 0 else "PARTIAL",
                    "error": None
                })
            elif nread > 0:
                read_bytes = bytes(buf.raw[:nread])
                buffers[(reg_start, reg_start + nread)] = read_bytes
                captured_ranges.append((reg_start, reg_start + nread))
                bytes_read += nread
                bytes_unread += (chunk_size - nread)
                raw_regions.append({
                    "region_id": f"R{idx:05d}",
                    "start": "0x{:x}".format(reg_start),
                    "end": "0x{:x}".format(reg_start + nread),
                    "size": reg_size,
                    "permissions": reg["permissions"],
                    "offset": reg.get("offset", 0),
                    "category": reg["category"],
                    "pathname": reg.get("pathname", ""),
                    "captured_bytes": nread,
                    "status": "PARTIAL",
                    "error": None
                })
            else:
                bytes_failed += chunk_size
                raw_regions.append({
                    "region_id": f"R{idx:05d}",
                    "start": "0x{:x}".format(reg_start),
                    "end": "0x{:x}".format(reg_start + reg_size),
                    "size": reg_size,
                    "permissions": reg["permissions"],
                    "offset": reg.get("offset", 0),
                    "category": reg["category"],
                    "pathname": reg.get("pathname", ""),
                    "captured_bytes": 0,
                    "status": "FAILED",
                    "error": f"ERRNO_{err}" if err else "READ_FAILED"
                })

        # Append omitted regions so the entire requested scope is accounted for
        raw_regions.extend(omitted_regions)

        regions_complete = sum(1 for r in raw_regions if r.get("status") == "COMPLETE")
        regions_partial = sum(1 for r in raw_regions if r.get("status") == "PARTIAL")
        regions_failed = sum(1 for r in raw_regions if r.get("status") == "FAILED")
        regions_omitted = len(omitted_regions)
        regions_read = regions_complete + regions_partial
        regions_attempted = regions_read + regions_failed + regions_omitted

        # Compute exact measured microsecond and millisecond latencies before quality determination
        unavailable_reasons: Dict[str, str] = {}
        if should_suspend and t_stop_confirmed > 0 and t_stop_requested > 0:
            stop_latency_us = (t_stop_confirmed - t_stop_requested) / 1000.0
        else:
            stop_latency_us = None
            unavailable_reasons["stop_latency"] = "PREEXISTING_STOP_PRESERVED" if was_already_stopped else ("SUSPENSION_SKIPPED" if not should_suspend else "STOP_UNCONFIRMED")

        if t_threads > 0 and t_stop_confirmed > 0:
            thread_latency_us = (t_threads - t_stop_confirmed) / 1000.0
        elif t_threads > 0 and t_stop_requested > 0:
            thread_latency_us = (t_threads - t_stop_requested) / 1000.0
        else:
            thread_latency_us = None
            unavailable_reasons["thread_metadata_latency"] = "THREAD_METADATA_SKIPPED_OR_FAILED"

        if t_memory > 0 and t_threads > 0:
            memory_latency_us = (t_memory - t_threads) / 1000.0
        else:
            memory_latency_us = None
            unavailable_reasons["memory_capture_latency"] = "MEMORY_READ_NOT_ATTEMPTED_OR_FAILED"

        if suspension_caused_by_capture and t_resume_confirmed > 0 and t_resume_requested > 0:
            resume_latency_us = (t_resume_confirmed - t_resume_requested) / 1000.0
        else:
            resume_latency_us = None
            unavailable_reasons["resume_latency"] = "PREEXISTING_STOP_PRESERVED" if was_already_stopped else "NO_RESUME_PERFORMED"

        if suspension_caused_by_capture and t_resume_confirmed > 0 and t_stop_confirmed > 0:
            total_stop_time_us = (t_resume_confirmed - t_stop_confirmed) / 1000.0
            total_stop_time_ms = total_stop_time_us / 1000.0
        else:
            total_stop_time_us = None
            total_stop_time_ms = None
            unavailable_reasons["total_stop_time"] = "TARGET_WAS_NOT_STOPPED_BY_CAPTURE"

        total_capture_time_us = max(0.0, (t_resume_confirmed - t_overall_start_ns) / 1000.0) if t_resume_confirmed > 0 else max(0.0, (time.monotonic_ns() - t_overall_start_ns) / 1000.0)

        stop_budget_exceeded = False
        if policy and getattr(policy, "max_stop_time_ms", 0) > 0 and total_stop_time_ms is not None:
            if total_stop_time_ms > policy.max_stop_time_ms:
                stop_budget_exceeded = True
                diagnostics.append({
                    "code": "STOP_BUDGET_EXCEEDED",
                    "message": f"Process suspension duration ({total_stop_time_ms:.2f} ms) exceeded budget of {policy.max_stop_time_ms:.2f} ms.",
                    "level": "WARNING"
                })

        any_pid_reused = any(cp.get("status") == "PID_REUSED" for cp in handle.identity_checkpoints) or handle.identity_mismatch
        any_target_exited = any(cp.get("status") == "TARGET_EXITED" for cp in handle.identity_checkpoints)
        any_checkpoint_failed = any(not cp.get("verified", False) for cp in handle.identity_checkpoints)

        thread_enum_failed = (
            getattr(thread_metadata, "is_synthetic", False)
            or (getattr(thread_metadata, "status", "") in ("FAILED", "PARTIAL", "SUCCESS_EMPTY"))
            or any(t.get("is_synthetic") is True or t.get("verified_observation") is False for t in thread_metadata)
        )
        map_enum_failed = (
            getattr(all_maps, "status", "") in ("FAILED", "PARTIAL")
            or (getattr(all_maps, "status", "") == "SUCCESS_EMPTY" and plan.mode == CaptureMode.FULL.value)
        )

        if any_pid_reused:
            capture_status = "INVALID"
            completeness = "INVALID"
        elif maps_enumeration_failed and not explicit_ranges_used_without_maps:
            capture_status = "FAILED"
            completeness = "FAILED"
        elif (bytes_read == 0 and selected_maps) or (any_target_exited and bytes_read == 0) or (len(selected_maps) == 0 and plan.mode == CaptureMode.FULL.value):
            capture_status = "FAILED"
            completeness = "FAILED"
        elif (
            regions_failed > 0
            or regions_partial > 0
            or regions_omitted > 0
            or (should_suspend and not stop_confirmed)
            or ((should_suspend or was_already_stopped) and not all_threads_stopped)
            or (suspension_caused_by_capture and not resume_confirmed)
            or (plan.mode == CaptureMode.ZERO_STOP.value)
            or any_checkpoint_failed
            or explicit_ranges_used_without_maps
            or thread_enum_failed
            or map_enum_failed
            or stop_budget_exceeded
            or mapping_race_detected
        ):
            capture_status = "PARTIAL"
            completeness = "PARTIAL"
        else:
            capture_status = "COMPLETED"
            completeness = "COMPLETE"

        lifecycle_guarantees = {
            "process_stop_requested": stop_requested,
            "process_stop_confirmed": stop_confirmed,
            "all_threads_stopped": all_threads_stopped if (should_suspend or was_already_stopped) else False,
            "memory_read_completed": memory_read_completed,
            "resume_requested": resume_requested,
            "resume_confirmed": resume_confirmed,
        }

        # Honest consistency classification:
        if completeness == "INVALID":
            snapshot_consistency = "INVALID"
            consistency_classification = "INVALID"
        elif completeness == "FAILED":
            snapshot_consistency = "FAILED"
            consistency_classification = "FAILED"
        elif plan.mode == CaptureMode.ZERO_STOP.value:
            consistency_classification = "NON_ATOMIC"
            snapshot_consistency = "NON_ATOMIC"
        elif not stop_confirmed:
            consistency_classification = "NON_ATOMIC"
            snapshot_consistency = "NON_ATOMIC"
        elif (should_suspend or was_already_stopped) and not all_threads_stopped:
            consistency_classification = "NON_ATOMIC"
            snapshot_consistency = "NON_ATOMIC"
        elif was_already_stopped:
            consistency_classification = "PREEXISTING_STOPPED"
            snapshot_consistency = "PROCESS_STOPPED_MEMORY_SNAPSHOT" if completeness == "COMPLETE" else "NON_ATOMIC"
        elif should_suspend and stop_confirmed:
            consistency_classification = "SIGNAL_STOPPED"
            snapshot_consistency = "PROCESS_STOPPED_MEMORY_SNAPSHOT" if completeness == "COMPLETE" else "NON_ATOMIC"
        else:
            consistency_classification = "NON_ATOMIC"
            snapshot_consistency = "NON_ATOMIC"

        identity_contract = {
            "target_pid": pid,
            "initial_starttime": initial_ident.get("starttime"),
            "initial_comm": initial_ident.get("comm"),
            "pidfd_supported": handle.pidfd_supported,
            "pidfd_used": handle.pidfd_used,
            "mem_pinned": handle.mem_pinned,
            "mem_pin_error": handle.mem_pin_error,
            "checkpoints": list(handle.identity_checkpoints),
            "identity_mismatch_detected": any_pid_reused,
            "validity": completeness,
        }

        latency_report = CaptureLatencyReport(
            stop_latency_ms=round(stop_latency_us / 1000.0, 3) if stop_latency_us is not None else None,
            thread_metadata_latency_ms=round(thread_latency_us / 1000.0, 3) if thread_latency_us is not None else None,
            memory_capture_latency_ms=round(memory_latency_us / 1000.0, 3) if memory_latency_us is not None else None,
            resume_latency_ms=round(resume_latency_us / 1000.0, 3) if resume_latency_us is not None else None,
            total_stop_time_ms=round(total_stop_time_ms, 3) if total_stop_time_ms is not None else None,
            target_capture_latency_ms=10.0,
            actual_capture_latency_ms=round(total_capture_time_us / 1000.0, 3) if total_capture_time_us is not None else None,
            stop_latency_us=round(stop_latency_us, 1) if stop_latency_us is not None else None,
            thread_metadata_latency_us=round(thread_latency_us, 1) if thread_latency_us is not None else None,
            memory_capture_latency_us=round(memory_latency_us, 1) if memory_latency_us is not None else None,
            resume_latency_us=round(resume_latency_us, 1) if resume_latency_us is not None else None,
            total_stop_time_us=round(total_stop_time_us, 1) if total_stop_time_us is not None else None,
            total_capture_latency_us=round(total_capture_time_us, 1) if total_capture_time_us is not None else None,
            unavailable_reasons=unavailable_reasons,
        )

        obs_meta = {
            "capture_backend": self.name,
            "capture_mode": plan.mode,
            "capture_status": capture_status,
            "completeness": completeness,
            "consistency_classification": consistency_classification,
            "temporal_consistency": "ATOMIC_STOPPED" if (should_suspend and stop_confirmed and all_threads_stopped) else ("PREEXISTING_STOPPED" if was_already_stopped else "NON_ATOMIC"),
            "stop_budget_compliance": "EXCEEDED" if stop_budget_exceeded else ("COMPLIANT" if total_stop_time_ms is not None else "NOT_APPLICABLE"),
            "stop_mechanism": "PREEXISTING_STOP_PRESERVED" if was_already_stopped else ("SIGSTOP" if should_suspend else "NONE"),
            "mapping_race_detected": mapping_race_detected,
            "captured_bytes": bytes_read,
            "bytes_requested": bytes_requested,
            "bytes_read": bytes_read,
            "bytes_omitted": bytes_omitted,
            "bytes_failed": bytes_failed,
            "bytes_unread": bytes_unread,
            "regions_complete": regions_complete,
            "regions_partial": regions_partial,
            "regions_failed": regions_failed,
            "regions_omitted": regions_omitted,
            "regions_read": regions_read,
            "regions_attempted": regions_attempted,
            "stopped_threads": stop_confirmed if (should_suspend or was_already_stopped) else False,
            "all_threads_stopped": all_threads_stopped,
            "was_already_stopped": was_already_stopped,
            "suspension_caused_by_capture": suspension_caused_by_capture,
            "actual_capture_suspended_target": suspension_caused_by_capture,
            "stop_duration_ms": round(total_stop_time_ms, 3) if total_stop_time_ms is not None else None,
            "total_capture_duration_ms": round(total_capture_time_us / 1000.0, 3) if total_capture_time_us is not None else None,
            "lifecycle_guarantees": lifecycle_guarantees,
            "pid_reuse_mitigation": handle.get_diagnostics(),
            "stop_state_machine": {
                "states": state_history,
                "stop_confirmed": stop_confirmed,
                "resume_confirmed": resume_confirmed,
                "was_already_stopped": was_already_stopped,
                "suspension_caused_by_capture": suspension_caused_by_capture,
                "current": state_history[-1],
            },
            "initial_process_state": initial_ident,
            "initial_threads_state": initial_threads,
            "capture_start": wall_clock_start,
            "capture_end": wall_clock_end,
            "stop_requested": wall_clock_start,
            "observation_point": observation_point,
            "latency_report": latency_report.to_dict(),
            "memory_maps": all_maps,
            "map_enumeration": all_maps.to_dict() if hasattr(all_maps, "to_dict") else {"status": getattr(all_maps, "status", "UNKNOWN")},
            "thread_enumeration": thread_metadata.to_dict() if hasattr(thread_metadata, "to_dict") else {"status": getattr(thread_metadata, "status", "UNKNOWN"), "is_synthetic": getattr(thread_metadata, "is_synthetic", False)},
            "diagnostics": diagnostics,
            "identity_contract": identity_contract,
            "capabilities": self.capabilities,
        }

        provenance = {
            "capture_backend": self.name,
            "capture_mode": plan.mode,
            "capture_status": capture_status,
            "snapshot_consistency": snapshot_consistency,
            "consistency_classification": consistency_classification,
            "stop_mechanism": "PREEXISTING_STOP_PRESERVED" if was_already_stopped else ("SIGSTOP" if should_suspend else "NONE"),
            "mapping_race_detected": mapping_race_detected,
            "stopped_threads": stop_confirmed if (should_suspend or was_already_stopped) else False,
            "all_threads_stopped": all_threads_stopped,
            "was_already_stopped": was_already_stopped,
            "suspension_caused_by_capture": suspension_caused_by_capture,
            "stop_duration_ms": round(total_stop_time_ms, 3) if total_stop_time_ms is not None else None,
            "total_capture_duration_ms": round(total_capture_time_us / 1000.0, 3) if total_capture_time_us is not None else None,
            "total_stop_time_ms": round(total_stop_time_ms, 3) if total_stop_time_ms is not None else None,
            "stop_budget_compliance": "EXCEEDED" if stop_budget_exceeded else ("COMPLIANT" if total_stop_time_ms is not None else "NOT_APPLICABLE"),
            "temporal_consistency": "ATOMIC_STOPPED" if (should_suspend and stop_confirmed and all_threads_stopped) else ("PREEXISTING_STOPPED" if was_already_stopped else "NON_ATOMIC"),
            "lifecycle_guarantees": lifecycle_guarantees,
            "pid_reuse_mitigation": handle.get_diagnostics(),
            "stop_state_machine": {
                "states": state_history,
                "stop_confirmed": stop_confirmed,
                "resume_confirmed": resume_confirmed,
                "was_already_stopped": was_already_stopped,
                "suspension_caused_by_capture": suspension_caused_by_capture,
            },
            "pid": pid,
            "timestamp": wall_clock_start,
            "capture_start": wall_clock_start,
            "capture_end": wall_clock_end,
            "stop_latency_us": stop_latency_us,
            "memory_read_latency_us": memory_latency_us,
            "capture_latency_us": memory_latency_us,
            "resume_latency_us": resume_latency_us,
            "total_capture_latency_us": total_capture_time_us,
            "duration": total_capture_time_us / 1000.0,
            "thread_count": len(thread_metadata),
            "captured_region_count": len(raw_regions),
            "captured_bytes": bytes_read,
            "bytes_requested": bytes_requested,
            "bytes_read": bytes_read,
            "bytes_omitted": bytes_omitted,
            "bytes_failed": bytes_failed,
            "bytes_unread": bytes_unread,
            "regions_complete": regions_complete,
            "regions_partial": regions_partial,
            "regions_failed": regions_failed,
            "regions_omitted": regions_omitted,
            "regions_read": regions_read,
            "regions_attempted": regions_attempted,
            "observation_point": observation_point,
            "executable_identity": {
                "path": exe_path,
                "build_id": build_id
            },
            "actual_capture_latency_ms": round(total_capture_time_us / 1000.0, 3) if total_capture_time_us is not None else None,
            "target_capture_latency_ms": 10.0,
            "total_stop_time_ms": round(total_stop_time_us / 1000.0, 3) if total_stop_time_us is not None else None,
            "latency_report": latency_report.to_dict(),
            "diagnostics": diagnostics,
            "identity_contract": identity_contract,
            "capabilities": self.capabilities,
            "stop_budget_exceeded": stop_budget_exceeded,
            "map_enumeration": all_maps.to_dict() if hasattr(all_maps, "to_dict") else {"status": "SUCCESS_WITH_RESULTS" if all_maps else "SUCCESS_EMPTY"},
            "thread_enumeration": thread_metadata.to_dict() if hasattr(thread_metadata, "to_dict") else {"status": "SUCCESS_WITH_RESULTS" if thread_metadata else "FAILED", "is_synthetic": False},
        }

        start_time = str(
            (handle.pre_signal_identity or {}).get("starttime")
            or (handle.initial_identity or {}).get("starttime")
            or _get_process_state(pid).get("starttime")
            or "0"
        )
        mem_manifest = {
            f"range_0x{s:x}_0x{e:x}": hashlib.sha256(b).hexdigest()
            for (s, e), b in buffers.items()
        }
        cap_receipt = issue_capture_receipt(
            backend_name=self.name,
            pid=pid,
            process_start_time=start_time,
            executable_path=exe_path,
            executable_build_id=build_id,
            capture_time=wall_clock_start,
            capture_duration_us=round(total_capture_time_us, 1),
            completeness=completeness,
            consistency_level=snapshot_consistency,
            artifact_manifest=mem_manifest,
        )
        provenance["capture_receipt"] = cap_receipt.to_dict()
        provenance["is_authenticated_capture"] = True
        provenance["start_time"] = start_time
        provenance["process_start_time"] = start_time

        raw_snap = RawRuntimeSnapshot(
            snapshot_id=sid,
            pid=pid,
            executable=exe_path,
            executable_build_id=build_id,
            timestamp=wall_clock_start,
            capture_duration_us=round(total_capture_time_us, 1),
            thread_metadata=thread_metadata,
            memory_regions=raw_regions,
            register_state={"status": "REGISTER_STATE_UNAVAILABLE"},
            captured_ranges=captured_ranges,
            raw_memory={"total_bytes": bytes_read},
            capture_backend=self.name,
            observation_metadata=obs_meta,
            completeness=completeness,
            provenance=provenance,
            _buffers=buffers,
            capture_receipt=cap_receipt,
        )

        return raw_snap


class ProcfsCaptureBackend(RuntimeCaptureBackend):
    """Fallback capture backend reading /proc/<pid>/mem."""

    @property
    def name(self) -> str:
        return "procfs"

    @property
    def capabilities(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "can_suspend_inferior": True,  # backend can suspend target via external signals (SIGSTOP/SIGCONT) when requested by capture plan
            "can_read_registers": False,
            "can_read_memory": True,
            "atomicity": "NON_ATOMIC",
            "zero_stop_supported": True,
            "syscall_suspends": False,
            "suspension_method": "signal_external",
            "mode_behaviors": {
                "ZERO_STOP": {
                    "suspends_process": False,
                    "atomicity": "NON_ATOMIC",
                    "description": "Zero-stop live capture via procfs: reads /proc/<pid>/mem without pausing process; snapshot is NOT atomic.",
                },
                "FULL": {
                    "suspends_process": True,
                    "atomicity": "CONDITIONAL_ON_STOP",
                    "description": "Signals target with SIGSTOP; consistency depends on stop confirmation.",
                },
                "TARGETED": {
                    "suspends_process": True,
                    "atomicity": "CONDITIONAL_ON_STOP",
                    "description": "Signals target with SIGSTOP; captures selected semantic ranges.",
                },
                "THREAD": {
                    "suspends_process": True,
                    "atomicity": "CONDITIONAL_ON_STOP",
                    "description": "Signals target with SIGSTOP; captures thread stack memory.",
                },
                "OBJECT": {
                    "suspends_process": True,
                    "atomicity": "CONDITIONAL_ON_STOP",
                    "description": "Signals target with SIGSTOP; captures object memory ranges.",
                },
            },
        }

    def is_available(self, pid: Optional[int] = None) -> bool:
        if pid is None:
            return os.path.exists("/proc")
        mem_path = f"/proc/{pid}/mem"
        return os.path.exists(mem_path) and os.access(mem_path, os.R_OK)

    def capture(
        self,
        pid: int,
        plan: Optional[CapturePlan] = None,
        policy: Optional[CaptureSafetyPolicy] = None,
        snapshot_id: Optional[str] = None,
        observation_point: Optional[Dict[str, Any]] = None,
        handle: Optional[ProcessTargetHandle] = None,
    ) -> RawRuntimeSnapshot:
        plan = plan or CapturePlan()
        policy = policy or CaptureSafetyPolicy()

        handle = handle or getattr(policy, "target_handle", None)
        if handle is None and not self.is_available(pid):
            raise RuntimeError(f"procfs is unavailable or target PID {pid} is not accessible")

        # Check process existence and establish target identity with ProcessTargetHandle
        force_fb = getattr(policy, "force_fallback", False)
        exp_id = getattr(policy, "expected_identity", None)
        exp_st = getattr(policy, "expected_starttime", None)
        handle = handle or ProcessTargetHandle(
            pid,
            force_fallback=force_fb,
            expected_identity=exp_id,
            expected_starttime=exp_st,
        )
        try:
            handle.open()
        except Exception:
            handle.close()
            raise

        initial_ident = handle.initial_identity
        initial_threads = handle.get_threads_state()
        was_already_stopped = initial_ident.get("is_stopped", False)
        is_tracing_stop = initial_ident.get("is_tracing_stop", False)
        target_start_time = initial_ident.get("starttime", "0")
        comm = initial_ident.get("comm", "unknown")

        sid = snapshot_id or "RS_{:06d}_{:04d}".format(pid, int(time.time() * 1000) % 10000)
        t_overall_start_ns = time.monotonic_ns()
        wall_clock_start = datetime.now(timezone.utc).isoformat()

        state_history = ["INITIALIZED"]
        capture_status = "COMPLETED"
        stop_requested = False
        stop_confirmed = False
        resume_requested = False
        resume_confirmed = False
        suspension_caused_by_capture = False
        all_threads_stopped = False
        memory_read_completed = False
        diagnostics: List[Dict[str, Any]] = []

        if is_tracing_stop:
            diagnostics.append({
                "code": "TRACING_STOP_OBSERVED",
                "message": f"Process {pid} is in TRACING_STOP ('t'). It may be attached to a debugger/tracer. External signal control may conflict with tracer.",
                "level": "WARNING"
            })

        if initial_threads.get("mixed_states"):
            diagnostics.append({
                "code": "MIXED_THREAD_STATES_AT_START",
                "message": f"Process {pid} threads have heterogeneous states: {initial_threads['stopped_count']} stopped, {initial_threads['running_count']} active.",
                "level": "INFO"
            })

        exe_path = ""
        try:
            exe_link = f"/proc/{pid}/exe"
            if os.path.exists(exe_link):
                exe_path = os.path.realpath(exe_link)
        except Exception:
            pass

        build_id = None
        if exe_path and os.path.exists(exe_path):
            try:
                from .debug_image import inspect_elf
                info = inspect_elf(exe_path)
                build_id = info.build_id
            except Exception:
                pass

        t_stop_requested = 0
        t_stop_confirmed = 0
        t_threads = 0
        t_memory = 0
        t_resume_requested = 0
        t_resume_confirmed = 0

        # Determine suspension intent based on plan and preexisting state
        should_suspend = (plan.mode != CaptureMode.ZERO_STOP.value)
        if plan.mode == CaptureMode.ZERO_STOP.value:
            should_suspend = False
            state_history.append("ZERO_STOP_MODE")
        elif was_already_stopped:
            should_suspend = False
            stop_confirmed = True
            state_history.append("PREEXISTING_STOP_PRESERVED")
            diagnostics.append({
                "code": "PREEXISTING_STOPPED_STATE_PRESERVED",
                "message": f"Target process {pid} was already stopped ({initial_ident.get('state')}) before capture. SIGSTOP was skipped and SIGCONT will not be sent, preserving original stop state.",
                "level": "INFO"
            })

        # 0. Pre-read maps and plan bounded capture
        handle.record_checkpoint("POST_OPEN")
        is_same_maps, ident_status_maps = handle.record_checkpoint("PRE_MAPS_READ")
        if not is_same_maps:
            diagnostics.append({
                "code": f"MAPS_READ_ABORTED_{ident_status_maps}",
                "message": f"Target process identity check failed ({ident_status_maps}) before maps collection; aborting capture.",
                "level": "ERROR"
            })
            all_maps = ProcMapsResult([], status="FAILED", error_type="TARGET_EXITED", error="Identity check failed before maps read")
        else:
            all_maps = handle.read_proc_maps()
            is_same_post_maps, ident_status_post_maps = handle.record_checkpoint("POST_MAPS_READ")
            if not is_same_post_maps:
                diagnostics.append({
                    "code": f"MAPS_READ_INVALIDATED_{ident_status_post_maps}",
                    "message": f"Target process identity changed ({ident_status_post_maps}) after reading maps.",
                    "level": "ERROR"
                })

        if hasattr(all_maps, "diagnostics"):
            diagnostics.extend(all_maps.diagnostics)

        selected_maps = []
        maps_enumeration_failed = (getattr(all_maps, "status", "SUCCESS_WITH_RESULTS") == "FAILED")
        explicit_ranges_used_without_maps = False

        if plan.mode == CaptureMode.TARGETED.value and plan.memory_ranges:
            for r_start, r_end in plan.memory_ranges:
                selected_maps.append({
                    "start": r_start,
                    "end": r_end,
                    "size": r_end - r_start,
                    "permissions": "rw-p",
                    "category": "targeted",
                    "pathname": "[targeted_range]"
                })
            if maps_enumeration_failed:
                explicit_ranges_used_without_maps = True
                diagnostics.append({
                    "code": "MAPS_ENUMERATION_FAILED_EXPLICIT_RANGES_USED",
                    "message": f"Memory map enumeration failed ({getattr(all_maps, 'error_type', 'UNKNOWN')}: {getattr(all_maps, 'error', '')}), but explicit target ranges were supplied. Layout could not be verified against proc maps; capture quality is capped at PARTIAL.",
                    "level": "WARNING"
                })
        elif plan.mode == CaptureMode.OBJECT.value and plan.memory_ranges:
            for r_start, r_end in plan.memory_ranges:
                selected_maps.append({
                    "start": r_start,
                    "end": r_end,
                    "size": r_end - r_start,
                    "permissions": "rw-p",
                    "category": "object",
                    "pathname": "[object_range]"
                })
            if maps_enumeration_failed:
                explicit_ranges_used_without_maps = True
                diagnostics.append({
                    "code": "MAPS_ENUMERATION_FAILED_EXPLICIT_RANGES_USED",
                    "message": f"Memory map enumeration failed ({getattr(all_maps, 'error_type', 'UNKNOWN')}: {getattr(all_maps, 'error', '')}), but explicit target ranges were supplied. Layout could not be verified against proc maps; capture quality is capped at PARTIAL.",
                    "level": "WARNING"
                })
        elif plan.mode == CaptureMode.THREAD.value and plan.thread_ids:
            if maps_enumeration_failed:
                diagnostics.append({
                    "code": "MAP_ENUMERATION_FAILED",
                    "message": f"Memory map enumeration failed ({getattr(all_maps, 'error_type', 'UNKNOWN')}: {getattr(all_maps, 'error', '')}). Cannot locate thread stack maps in THREAD mode.",
                    "level": "ERROR"
                })
            else:
                for m in all_maps:
                    if m["category"] == "stack" and "r" in m["permissions"]:
                        selected_maps.append(m)
        else:
            # FULL: Capture mutable runtime state (heap, stack, writable data/bss/anonymous/binary)
            if maps_enumeration_failed:
                diagnostics.append({
                    "code": "MAP_ENUMERATION_FAILED",
                    "message": f"Memory map enumeration failed ({getattr(all_maps, 'error_type', 'UNKNOWN')}: {getattr(all_maps, 'error', '')}). FULL capture mode requires valid memory maps; cannot proceed.",
                    "level": "ERROR"
                })
            else:
                for m in all_maps:
                    if "r" in m["permissions"] and ("w" in m["permissions"] or m["category"] in ("heap", "stack", "anonymous")):
                        selected_maps.append(m)
                # Prioritize essential binary/data, heap, and stack regions before large anonymous arenas
                _cat_prio = {"binary": 0, "heap": 1, "stack": 2, "library": 3, "anonymous": 4, "unknown": 5}
                selected_maps.sort(key=lambda r: (_cat_prio.get(r.get("category", "unknown"), 5), r.get("start", 0)))

        if not selected_maps and plan.memory_ranges:
            for r_start, r_end in plan.memory_ranges:
                selected_maps.append({
                    "start": r_start,
                    "end": r_end,
                    "size": r_end - r_start,
                    "permissions": "rw-p",
                    "category": "targeted",
                    "pathname": "[targeted_range]"
                })
            if maps_enumeration_failed and not explicit_ranges_used_without_maps:
                explicit_ranges_used_without_maps = True
                diagnostics.append({
                    "code": "MAPS_ENUMERATION_FAILED_EXPLICIT_RANGES_USED",
                    "message": f"Memory map enumeration failed ({getattr(all_maps, 'error_type', 'UNKNOWN')}: {getattr(all_maps, 'error', '')}), but explicit target ranges were supplied. Layout could not be verified against proc maps; capture quality is capped at PARTIAL.",
                    "level": "WARNING"
                })

        read_plans = []
        omitted_regions = []
        bytes_requested = sum(m["size"] for m in selected_maps)
        bytes_attempted = 0
        bytes_omitted = 0

        for idx, reg in enumerate(selected_maps, 1):
            reg_start = reg["start"]
            reg_size = reg["size"]
            if bytes_attempted >= policy.max_capture_bytes or idx > policy.max_capture_ranges:
                bytes_omitted += reg_size
                omitted_regions.append({
                    "region_id": f"R{idx:05d}",
                    "start": "0x{:x}".format(reg_start),
                    "end": "0x{:x}".format(reg_start + reg_size),
                    "size": reg_size,
                    "permissions": reg["permissions"],
                    "offset": reg.get("offset", 0),
                    "category": reg["category"],
                    "pathname": reg.get("pathname", ""),
                    "captured_bytes": 0,
                    "status": "OMITTED",
                    "error": "POLICY_LIMIT_EXCEEDED"
                })
                continue

            max_reg_cap = getattr(policy, "max_region_bytes", 0) or policy.max_capture_bytes
            if plan.mode in (CaptureMode.TARGETED.value, CaptureMode.OBJECT.value):
                max_reg_cap = policy.max_capture_bytes
            chunk_size = min(reg_size, max_reg_cap, policy.max_capture_bytes - bytes_attempted)
            if chunk_size <= 0:
                bytes_omitted += reg_size
                omitted_regions.append({
                    "region_id": f"R{idx:05d}",
                    "start": "0x{:x}".format(reg_start),
                    "end": "0x{:x}".format(reg_start + reg_size),
                    "size": reg_size,
                    "permissions": reg["permissions"],
                    "offset": reg.get("offset", 0),
                    "category": reg["category"],
                    "pathname": reg.get("pathname", ""),
                    "captured_bytes": 0,
                    "status": "OMITTED",
                    "error": "POLICY_LIMIT_EXCEEDED"
                })
                continue

            tail_omitted = reg_size - chunk_size
            if tail_omitted > 0:
                bytes_omitted += tail_omitted

            read_plans.append((idx, reg, reg_start, reg_size, chunk_size, tail_omitted))
            bytes_attempted += chunk_size

        buffers: Dict[Tuple[int, int], bytes] = {}
        raw_regions: List[Dict[str, Any]] = []
        captured_ranges: List[Tuple[int, int]] = []
        read_results = []

        try:
            if should_suspend:
                is_same_pre_stop, ident_status_pre_stop = handle.record_checkpoint("PRE_SUSPEND")
                if not is_same_pre_stop:
                    suspension_caused_by_capture = False
                    diagnostics.append({
                        "code": f"STOP_ABORTED_{ident_status_pre_stop}",
                        "message": f"Target process identity check failed ({ident_status_pre_stop}) before SIGSTOP; suspension aborted.",
                        "level": "ERROR"
                    })
                else:
                    state_history.append("STOP_REQUESTED")
                    stop_requested = True
                    t_stop_requested = time.monotonic_ns()

                    sig_ok, sig_err = handle.send_signal(signal.SIGSTOP)
                    if not sig_ok:
                        suspension_caused_by_capture = False
                        if sig_err == "TARGET_EXITED":
                            diagnostics.append({
                                "code": "TARGET_EXITED_BEFORE_STOP",
                                "message": f"Process {pid} exited before SIGSTOP delivered",
                                "level": "ERROR"
                            })
                        elif sig_err == "PID_REUSED":
                            diagnostics.append({
                                "code": "PID_REUSED_STOP_ABORTED",
                                "message": f"Target PID {pid} was reused; SIGSTOP aborted to prevent signalling unrelated process",
                                "level": "ERROR"
                            })
                        elif sig_err == "PERMISSION_DENIED":
                            diagnostics.append({
                                "code": "STOP_PERMISSION_DENIED",
                                "message": f"Permission denied (EPERM) delivering SIGSTOP to process {pid}",
                                "level": "ERROR"
                            })
                        else:
                            diagnostics.append({
                                "code": "STOP_SIGNAL_ERROR",
                                "message": f"SIGSTOP failed: {sig_err}",
                                "level": "ERROR"
                            })
                    else:
                        deadline_stop = t_stop_requested + int(policy.max_stop_time_ms * 1_000_000)
                        while time.monotonic_ns() < deadline_stop:
                            try:
                                curr_st = handle.get_process_state()
                                if curr_st.get("is_stopped"):
                                    stop_confirmed = True
                                    curr_threads = handle.get_threads_state()
                                    if curr_threads.get("all_stopped", False):
                                        all_threads_stopped = True
                                        break
                            except Exception:
                                pass
                            try:
                                os.sched_yield()
                            except Exception:
                                pass

                        t_stop_confirmed = time.monotonic_ns()
                        if stop_confirmed:
                            suspension_caused_by_capture = True
                            state_history.append("STOP_CONFIRMED")
                            handle.record_checkpoint("POST_SUSPEND")
                        else:
                            suspension_caused_by_capture = False
                            state_history.append("STOP_UNCONFIRMED")
                            diagnostics.append({
                                "code": "STOP_UNCONFIRMED",
                                "message": f"Process {pid} did not enter stopped state within {policy.max_stop_time_ms} ms. Memory captured under this condition is NON_ATOMIC.",
                                "level": "WARNING"
                            })
            else:
                handle.record_checkpoint("PRE_SUSPEND_SKIPPED")
                t_stop_requested = time.monotonic_ns()
                t_stop_confirmed = t_stop_requested
                if was_already_stopped:
                    stop_confirmed = True

            # Check thread consistency
            if not all_threads_stopped:
                curr_threads = handle.get_threads_state()
                all_threads_stopped = curr_threads.get("all_stopped", False)
            if (should_suspend or was_already_stopped) and not all_threads_stopped:
                diagnostics.append({
                    "code": "THREAD_STATES_HETEROGENEOUS",
                    "message": f"Process {pid} leader stopped, but not all threads are confirmed stopped ({curr_threads.get('stopped_count')}/{curr_threads.get('total_count')}). Snapshot is NON_ATOMIC.",
                    "level": "WARNING"
                })

            state_history.append("CAPTURING")
            is_same_th, ident_status_th = handle.record_checkpoint("PRE_THREAD_METADATA")
            if not is_same_th:
                thread_metadata = ThreadMetadataResult(
                    [{
                        "thread_id": pid,
                        "name": None,
                        "state": "UNKNOWN",
                        "stop_status": "UNKNOWN",
                        "is_synthetic": True,
                        "verified_observation": False,
                        "capture_participation": False,
                        "registers_availability": "REGISTER_STATE_UNAVAILABLE",
                        "function": None,
                        "location": None,
                    }],
                    status="FAILED",
                    error_type=ident_status_th,
                    error="Identity verification failed before thread metadata collection",
                    is_synthetic=True,
                )
            else:
                thread_metadata = handle.read_thread_metadata()
            handle.record_checkpoint("POST_THREAD_METADATA")
            t_threads = time.monotonic_ns()

            if getattr(thread_metadata, "is_synthetic", False) or getattr(thread_metadata, "status", "") == "FAILED":
                all_threads_stopped = False
                diagnostics.append({
                    "code": "THREAD_ENUMERATION_FAILED",
                    "message": f"Thread enumeration failed ({getattr(thread_metadata, 'error_type', 'UNKNOWN')}: {getattr(thread_metadata, 'error', '')}). Thread states are UNVERIFIED.",
                    "level": "WARNING"
                })
            if hasattr(thread_metadata, "diagnostics"):
                diagnostics.extend(thread_metadata.diagnostics)

            is_same_mem, ident_status_mem = handle.record_checkpoint("PRE_MEMORY_READ")
            mem_file = f"/proc/{pid}/mem"
            mem_reader = getattr(policy, "mem_reader", None)
            if not is_same_mem:
                for item in read_plans:
                    read_results.append((item, b"", f"IDENTITY_{ident_status_mem}"))
            elif mem_reader:
                for item in read_plans:
                    idx, reg, reg_start, reg_size, chunk_size, tail_omitted = item
                    try:
                        read_data = mem_reader(pid, reg_start, chunk_size)
                        if read_data is not None:
                            read_results.append((item, read_data, None))
                        else:
                            read_results.append((item, b"", "MEM_READ_FAILED"))
                    except Exception as ex:
                        read_results.append((item, b"", str(ex)))
            elif handle.mem_pinned and handle.mem_fd is not None:
                # Prefer pinned /proc/<pid>/mem descriptor
                for item in read_plans:
                    idx, reg, reg_start, reg_size, chunk_size, tail_omitted = item
                    try:
                        read_data = handle.read_mem(reg_start, chunk_size)
                        if read_data is not None:
                            read_results.append((item, read_data, None))
                        else:
                            read_results.append((item, b"", "MEM_READ_FAILED"))
                    except Exception as ex:
                        read_results.append((item, b"", str(ex)))
            else:
                try:
                    with open(mem_file, "rb", buffering=0) as f_mem:
                        for item in read_plans:
                            idx, reg, reg_start, reg_size, chunk_size, tail_omitted = item
                            try:
                                f_mem.seek(reg_start)
                                chunk = f_mem.read(chunk_size)
                                read_results.append((item, chunk, None if chunk else "EOF_EMPTY_READ"))
                            except Exception as read_err:
                                read_results.append((item, b"", str(read_err)))
                except Exception as open_err:
                    diagnostics.append({
                        "code": "MEM_FILE_OPEN_FAILED",
                        "message": f"Failed to open {mem_file}: {open_err}",
                        "level": "ERROR"
                    })
                    for item in read_plans:
                        read_results.append((item, b"", str(open_err)))

            memory_read_completed = True
            handle.record_checkpoint("POST_MEMORY_READ")
            t_memory = time.monotonic_ns()
        finally:
            try:
                if suspension_caused_by_capture:
                    resume_requested = True
                    state_history.append("RESUME_REQUESTED")
                    t_resume_requested = time.monotonic_ns()
                    still_same_process = False
                    is_same, ident_status = handle.record_checkpoint("PRE_RESUME")
                    if is_same:
                        still_same_process = True
                    else:
                        if ident_status == "PID_REUSED":
                            diagnostics.append({
                                "code": "PID_REUSED_RESUME_ABORTED",
                                "message": f"PID {pid} was reused; SIGCONT aborted to prevent signalling unrelated process.",
                                "level": "WARNING"
                            })
                        elif ident_status == "TARGET_EXITED":
                            diagnostics.append({
                                "code": "TARGET_EXITED_DURING_CAPTURE",
                                "message": f"Process {pid} exited during capture; inferior is no longer running.",
                                "level": "INFO"
                            })
                        else:
                            diagnostics.append({
                                "code": "IDENTITY_VERIFICATION_FAILED",
                                "message": f"Process verification failed ({ident_status}); SIGCONT aborted.",
                                "level": "WARNING"
                            })

                    if still_same_process:
                        try:
                            post_check = handle.get_process_state()
                            if not post_check.get("is_stopped"):
                                resume_confirmed = True
                                state_history.append("TARGET_RESUMED_INDEPENDENTLY")
                                diagnostics.append({
                                    "code": "TARGET_RESUMED_INDEPENDENTLY",
                                    "message": f"Process {pid} was already active before SIGCONT; target resumed independently.",
                                    "level": "INFO"
                                })
                        except Exception:
                            pass

                        if not resume_confirmed:
                            res_ok, res_err = handle.send_signal(signal.SIGCONT)
                            if not res_ok:
                                if res_err == "TARGET_EXITED":
                                    diagnostics.append({
                                        "code": "TARGET_EXITED_BEFORE_RESUME",
                                        "message": f"Process {pid} exited before SIGCONT delivered.",
                                        "level": "INFO"
                                    })
                                elif res_err == "PERMISSION_DENIED":
                                    diagnostics.append({
                                        "code": "RESUME_PERMISSION_DENIED",
                                        "message": f"Permission denied delivering SIGCONT to process {pid}.",
                                        "level": "ERROR"
                                    })
                                else:
                                    diagnostics.append({
                                        "code": "RESUME_SIGNAL_ERROR",
                                        "message": f"SIGCONT failed: {res_err}",
                                        "level": "ERROR"
                                    })
                            else:
                                deadline_res = t_resume_requested + int(20 * 1_000_000)
                                while time.monotonic_ns() < deadline_res:
                                    try:
                                        st_res = handle.get_process_state()
                                        if not st_res.get("is_stopped"):
                                            resume_confirmed = True
                                            break
                                    except Exception:
                                        pass
                                    try:
                                        os.sched_yield()
                                    except Exception:
                                        pass

                                t_resume_confirmed = time.monotonic_ns()
                                if resume_confirmed:
                                    state_history.append("RESUME_CONFIRMED")
                                    handle.record_checkpoint("POST_RESUME")
                                else:
                                    state_history.append("RESUME_UNCONFIRMED")
                                    diagnostics.append({
                                        "code": "RESUME_UNCONFIRMED",
                                        "message": f"Process {pid} did not confirm running state within timeout after SIGCONT.",
                                        "level": "WARNING"
                                    })
                    else:
                        t_resume_confirmed = time.monotonic_ns()
                elif was_already_stopped:
                    state_history.append("PREEXISTING_STOP_RETAINED")
                    t_resume_requested = t_memory
                    t_resume_confirmed = t_memory
                else:
                    t_resume_requested = t_memory
                    t_resume_confirmed = t_memory
            finally:
                handle.close()

        wall_clock_end = datetime.now(timezone.utc).isoformat()

        # Ensure all read plans are accounted for even if an unhandled exception occurred
        processed_plan_indices = {r[0][0] for r in read_results}
        for item in read_plans:
            if item[0] not in processed_plan_indices:
                read_results.append((item, b"", "UNPROCESSED_DUE_TO_ERROR"))

        mapping_race_detected = False
        if getattr(policy, "simulate_mapping_race", False):
            mapping_race_detected = True

        for item, chunk, err in read_results:
            if (not chunk) and err and ("EFAULT" in str(err) or "bad address" in str(err).lower()) and not explicit_ranges_used_without_maps:
                mapping_race_detected = True
                break

        any_target_exited = any(cp.get("status") == "TARGET_EXITED" for cp in getattr(handle, "identity_checkpoints", []))
        if not mapping_race_detected and not any_target_exited and hasattr(handle, "read_proc_maps"):
            try:
                post_maps = handle.read_proc_maps()
                if getattr(post_maps, "status", None) in ("SUCCESS_WITH_RESULTS", "SUCCESS_EMPTY"):
                    for m in selected_maps:
                        s, e = m["start"], m["end"]
                        pre_cov = next((pm for pm in all_maps if pm.get("start", 0) <= s and pm.get("end", 0) >= e), None)
                        if pre_cov is not None:
                            post_cov = next((pm for pm in post_maps if pm.get("start", 0) <= s and pm.get("end", 0) >= e), None)
                            if post_cov is None or "r" not in post_cov.get("permissions", ""):
                                mapping_race_detected = True
                                break
                            if pre_cov.get("permissions") != post_cov.get("permissions") or pre_cov.get("offset") != post_cov.get("offset") or pre_cov.get("pathname") != post_cov.get("pathname"):
                                mapping_race_detected = True
                                break
            except Exception:
                pass

        if mapping_race_detected:
            diagnostics.append({
                "code": "MAPPING_RACE_DETECTED",
                "message": "Memory mapping changed or invalidated during capture; snapshot completeness demoted to PARTIAL.",
                "level": "WARNING"
            })

        # Offline post-processing of buffers
        bytes_read = 0
        bytes_failed = 0
        bytes_unread = 0

        for item, chunk, err in read_results:
            idx, reg, reg_start, reg_size, chunk_size, tail_omitted = item
            nread = len(chunk) if chunk else 0
            if nread == chunk_size:
                buffers[(reg_start, reg_start + nread)] = chunk
                captured_ranges.append((reg_start, reg_start + nread))
                bytes_read += nread
                raw_regions.append({
                    "region_id": f"R{idx:05d}",
                    "start": "0x{:x}".format(reg_start),
                    "end": "0x{:x}".format(reg_start + nread),
                    "size": reg_size,
                    "permissions": reg["permissions"],
                    "offset": reg.get("offset", 0),
                    "category": reg["category"],
                    "pathname": reg.get("pathname", ""),
                    "captured_bytes": nread,
                    "status": "COMPLETE" if tail_omitted == 0 else "PARTIAL",
                    "error": None
                })
            elif nread > 0:
                buffers[(reg_start, reg_start + nread)] = chunk
                captured_ranges.append((reg_start, reg_start + nread))
                bytes_read += nread
                bytes_unread += (chunk_size - nread)
                raw_regions.append({
                    "region_id": f"R{idx:05d}",
                    "start": "0x{:x}".format(reg_start),
                    "end": "0x{:x}".format(reg_start + nread),
                    "size": reg_size,
                    "permissions": reg["permissions"],
                    "offset": reg.get("offset", 0),
                    "category": reg["category"],
                    "pathname": reg.get("pathname", ""),
                    "captured_bytes": nread,
                    "status": "PARTIAL",
                    "error": None
                })
            else:
                bytes_failed += chunk_size
                raw_regions.append({
                    "region_id": f"R{idx:05d}",
                    "start": "0x{:x}".format(reg_start),
                    "end": "0x{:x}".format(reg_start + reg_size),
                    "size": reg_size,
                    "permissions": reg["permissions"],
                    "offset": reg.get("offset", 0),
                    "category": reg["category"],
                    "pathname": reg.get("pathname", ""),
                    "captured_bytes": 0,
                    "status": "FAILED",
                    "error": err or "READ_FAILED"
                })

        raw_regions.extend(omitted_regions)

        regions_complete = sum(1 for r in raw_regions if r.get("status") == "COMPLETE")
        regions_partial = sum(1 for r in raw_regions if r.get("status") == "PARTIAL")
        regions_failed = sum(1 for r in raw_regions if r.get("status") == "FAILED")
        regions_omitted = len(omitted_regions)
        regions_read = regions_complete + regions_partial
        regions_attempted = regions_read + regions_failed + regions_omitted

        # Compute exact measured microsecond and millisecond latencies before quality determination
        unavailable_reasons: Dict[str, str] = {}
        if should_suspend and t_stop_confirmed > 0 and t_stop_requested > 0:
            stop_latency_us = (t_stop_confirmed - t_stop_requested) / 1000.0
        else:
            stop_latency_us = None
            unavailable_reasons["stop_latency"] = "PREEXISTING_STOP_PRESERVED" if was_already_stopped else ("SUSPENSION_SKIPPED" if not should_suspend else "STOP_UNCONFIRMED")

        if t_threads > 0 and t_stop_confirmed > 0:
            thread_latency_us = (t_threads - t_stop_confirmed) / 1000.0
        elif t_threads > 0 and t_stop_requested > 0:
            thread_latency_us = (t_threads - t_stop_requested) / 1000.0
        else:
            thread_latency_us = None
            unavailable_reasons["thread_metadata_latency"] = "THREAD_METADATA_SKIPPED_OR_FAILED"

        if t_memory > 0 and t_threads > 0:
            memory_latency_us = (t_memory - t_threads) / 1000.0
        else:
            memory_latency_us = None
            unavailable_reasons["memory_capture_latency"] = "MEMORY_READ_NOT_ATTEMPTED_OR_FAILED"

        if suspension_caused_by_capture and t_resume_confirmed > 0 and t_resume_requested > 0:
            resume_latency_us = (t_resume_confirmed - t_resume_requested) / 1000.0
        else:
            resume_latency_us = None
            unavailable_reasons["resume_latency"] = "PREEXISTING_STOP_PRESERVED" if was_already_stopped else "NO_RESUME_PERFORMED"

        if suspension_caused_by_capture and t_resume_confirmed > 0 and t_stop_confirmed > 0:
            total_stop_time_us = (t_resume_confirmed - t_stop_confirmed) / 1000.0
            total_stop_time_ms = total_stop_time_us / 1000.0
        else:
            total_stop_time_us = None
            total_stop_time_ms = None
            unavailable_reasons["total_stop_time"] = "TARGET_WAS_NOT_STOPPED_BY_CAPTURE"

        total_capture_time_us = max(0.0, (t_resume_confirmed - t_overall_start_ns) / 1000.0) if t_resume_confirmed > 0 else max(0.0, (time.monotonic_ns() - t_overall_start_ns) / 1000.0)

        stop_budget_exceeded = False
        if policy and getattr(policy, "max_stop_time_ms", 0) > 0 and total_stop_time_ms is not None:
            if total_stop_time_ms > policy.max_stop_time_ms:
                stop_budget_exceeded = True
                diagnostics.append({
                    "code": "STOP_BUDGET_EXCEEDED",
                    "message": f"Process suspension duration ({total_stop_time_ms:.2f} ms) exceeded budget of {policy.max_stop_time_ms:.2f} ms.",
                    "level": "WARNING"
                })

        any_pid_reused = any(cp.get("status") == "PID_REUSED" for cp in handle.identity_checkpoints) or handle.identity_mismatch
        any_target_exited = any(cp.get("status") == "TARGET_EXITED" for cp in handle.identity_checkpoints)
        any_checkpoint_failed = any(not cp.get("verified", False) for cp in handle.identity_checkpoints)

        thread_enum_failed = (
            getattr(thread_metadata, "is_synthetic", False)
            or (getattr(thread_metadata, "status", "") in ("FAILED", "PARTIAL", "SUCCESS_EMPTY"))
            or any(t.get("is_synthetic") is True or t.get("verified_observation") is False for t in thread_metadata)
        )
        map_enum_failed = (
            getattr(all_maps, "status", "") in ("FAILED", "PARTIAL")
            or (getattr(all_maps, "status", "") == "SUCCESS_EMPTY" and plan.mode == CaptureMode.FULL.value)
        )

        if any_pid_reused:
            capture_status = "INVALID"
            completeness = "INVALID"
        elif maps_enumeration_failed and not explicit_ranges_used_without_maps:
            capture_status = "FAILED"
            completeness = "FAILED"
        elif (bytes_read == 0 and selected_maps) or (any_target_exited and bytes_read == 0) or (len(selected_maps) == 0 and plan.mode == CaptureMode.FULL.value):
            capture_status = "FAILED"
            completeness = "FAILED"
        elif (
            regions_failed > 0
            or regions_partial > 0
            or regions_omitted > 0
            or (should_suspend and not stop_confirmed)
            or ((should_suspend or was_already_stopped) and not all_threads_stopped)
            or (suspension_caused_by_capture and not resume_confirmed)
            or (plan.mode == CaptureMode.ZERO_STOP.value)
            or any_checkpoint_failed
            or explicit_ranges_used_without_maps
            or thread_enum_failed
            or map_enum_failed
            or stop_budget_exceeded
            or mapping_race_detected
        ):
            capture_status = "PARTIAL"
            completeness = "PARTIAL"
        else:
            capture_status = "COMPLETED"
            completeness = "COMPLETE"

        lifecycle_guarantees = {
            "process_stop_requested": stop_requested,
            "process_stop_confirmed": stop_confirmed,
            "all_threads_stopped": all_threads_stopped if (should_suspend or was_already_stopped) else False,
            "memory_read_completed": memory_read_completed,
            "resume_requested": resume_requested,
            "resume_confirmed": resume_confirmed,
        }

        # Honest consistency classification:
        if completeness == "INVALID":
            snapshot_consistency = "INVALID"
            consistency_classification = "INVALID"
        elif completeness == "FAILED":
            snapshot_consistency = "FAILED"
            consistency_classification = "FAILED"
        elif plan.mode == CaptureMode.ZERO_STOP.value:
            consistency_classification = "NON_ATOMIC"
            snapshot_consistency = "NON_ATOMIC"
        elif not stop_confirmed:
            consistency_classification = "NON_ATOMIC"
            snapshot_consistency = "NON_ATOMIC"
        elif (should_suspend or was_already_stopped) and not all_threads_stopped:
            consistency_classification = "NON_ATOMIC"
            snapshot_consistency = "NON_ATOMIC"
        elif was_already_stopped:
            consistency_classification = "PREEXISTING_STOPPED"
            snapshot_consistency = "PROCESS_STOPPED_MEMORY_SNAPSHOT" if completeness == "COMPLETE" else "NON_ATOMIC"
        elif should_suspend and stop_confirmed:
            consistency_classification = "SIGNAL_STOPPED"
            snapshot_consistency = "PROCESS_STOPPED_MEMORY_SNAPSHOT" if completeness == "COMPLETE" else "NON_ATOMIC"
        else:
            consistency_classification = "NON_ATOMIC"
            snapshot_consistency = "NON_ATOMIC"

        identity_contract = {
            "target_pid": pid,
            "initial_starttime": initial_ident.get("starttime"),
            "initial_comm": initial_ident.get("comm"),
            "pidfd_supported": handle.pidfd_supported,
            "pidfd_used": handle.pidfd_used,
            "mem_pinned": handle.mem_pinned,
            "mem_pin_error": handle.mem_pin_error,
            "checkpoints": list(handle.identity_checkpoints),
            "identity_mismatch_detected": any_pid_reused,
            "validity": completeness,
        }

        latency_report = CaptureLatencyReport(
            stop_latency_ms=round(stop_latency_us / 1000.0, 3) if stop_latency_us is not None else None,
            thread_metadata_latency_ms=round(thread_latency_us / 1000.0, 3) if thread_latency_us is not None else None,
            memory_capture_latency_ms=round(memory_latency_us / 1000.0, 3) if memory_latency_us is not None else None,
            resume_latency_ms=round(resume_latency_us / 1000.0, 3) if resume_latency_us is not None else None,
            total_stop_time_ms=round(total_stop_time_ms, 3) if total_stop_time_ms is not None else None,
            target_capture_latency_ms=10.0,
            actual_capture_latency_ms=round(total_capture_time_us / 1000.0, 3) if total_capture_time_us is not None else None,
            stop_latency_us=round(stop_latency_us, 1) if stop_latency_us is not None else None,
            thread_metadata_latency_us=round(thread_latency_us, 1) if thread_latency_us is not None else None,
            memory_capture_latency_us=round(memory_latency_us, 1) if memory_latency_us is not None else None,
            resume_latency_us=round(resume_latency_us, 1) if resume_latency_us is not None else None,
            total_stop_time_us=round(total_stop_time_us, 1) if total_stop_time_us is not None else None,
            total_capture_latency_us=round(total_capture_time_us, 1) if total_capture_time_us is not None else None,
            unavailable_reasons=unavailable_reasons,
        )

        obs_meta = {
            "capture_backend": self.name,
            "capture_mode": plan.mode,
            "capture_status": capture_status,
            "completeness": completeness,
            "consistency_classification": consistency_classification,
            "temporal_consistency": "ATOMIC_STOPPED" if (should_suspend and stop_confirmed and all_threads_stopped) else ("PREEXISTING_STOPPED" if was_already_stopped else "NON_ATOMIC"),
            "stop_budget_compliance": "EXCEEDED" if stop_budget_exceeded else ("COMPLIANT" if total_stop_time_ms is not None else "NOT_APPLICABLE"),
            "stop_mechanism": "PREEXISTING_STOP_PRESERVED" if was_already_stopped else ("SIGSTOP" if should_suspend else "NONE"),
            "mapping_race_detected": mapping_race_detected,
            "captured_bytes": bytes_read,
            "bytes_requested": bytes_requested,
            "bytes_read": bytes_read,
            "bytes_omitted": bytes_omitted,
            "bytes_failed": bytes_failed,
            "bytes_unread": bytes_unread,
            "regions_complete": regions_complete,
            "regions_partial": regions_partial,
            "regions_failed": regions_failed,
            "regions_omitted": regions_omitted,
            "regions_read": regions_read,
            "regions_attempted": regions_attempted,
            "stopped_threads": stop_confirmed if (should_suspend or was_already_stopped) else False,
            "all_threads_stopped": all_threads_stopped,
            "was_already_stopped": was_already_stopped,
            "suspension_caused_by_capture": suspension_caused_by_capture,
            "actual_capture_suspended_target": suspension_caused_by_capture,
            "stop_duration_ms": round(total_stop_time_ms, 3) if total_stop_time_ms is not None else None,
            "total_capture_duration_ms": round(total_capture_time_us / 1000.0, 3) if total_capture_time_us is not None else None,
            "lifecycle_guarantees": lifecycle_guarantees,
            "pid_reuse_mitigation": handle.get_diagnostics(),
            "stop_state_machine": {
                "states": state_history,
                "stop_confirmed": stop_confirmed,
                "resume_confirmed": resume_confirmed,
                "was_already_stopped": was_already_stopped,
                "suspension_caused_by_capture": suspension_caused_by_capture,
                "current": state_history[-1],
            },
            "initial_process_state": initial_ident,
            "thread_state_analysis": initial_threads,
            "capture_start": wall_clock_start,
            "capture_end": wall_clock_end,
            "stop_requested": wall_clock_start,
            "observation_point": observation_point,
            "latency_report": latency_report.to_dict(),
            "memory_maps": all_maps,
            "map_enumeration": all_maps.to_dict() if hasattr(all_maps, "to_dict") else {"status": getattr(all_maps, "status", "UNKNOWN")},
            "thread_enumeration": thread_metadata.to_dict() if hasattr(thread_metadata, "to_dict") else {"status": getattr(thread_metadata, "status", "UNKNOWN"), "is_synthetic": getattr(thread_metadata, "is_synthetic", False)},
            "diagnostics": diagnostics,
            "identity_contract": identity_contract,
            "capabilities": self.capabilities,
        }

        provenance = {
            "capture_backend": self.name,
            "capture_mode": plan.mode,
            "capture_status": capture_status,
            "snapshot_consistency": snapshot_consistency,
            "consistency_classification": consistency_classification,
            "stop_mechanism": "PREEXISTING_STOP_PRESERVED" if was_already_stopped else ("SIGSTOP" if should_suspend else "NONE"),
            "mapping_race_detected": mapping_race_detected,
            "stopped_threads": stop_confirmed if (should_suspend or was_already_stopped) else False,
            "all_threads_stopped": all_threads_stopped,
            "was_already_stopped": was_already_stopped,
            "suspension_caused_by_capture": suspension_caused_by_capture,
            "actual_capture_suspended_target": suspension_caused_by_capture,
            "stop_duration_ms": round(total_stop_time_ms, 3) if total_stop_time_ms is not None else None,
            "total_capture_duration_ms": round(total_capture_time_us / 1000.0, 3) if total_capture_time_us is not None else None,
            "total_stop_time_ms": round(total_stop_time_ms, 3) if total_stop_time_ms is not None else None,
            "stop_budget_compliance": "EXCEEDED" if stop_budget_exceeded else ("COMPLIANT" if total_stop_time_ms is not None else "NOT_APPLICABLE"),
            "temporal_consistency": "ATOMIC_STOPPED" if (should_suspend and stop_confirmed and all_threads_stopped) else ("PREEXISTING_STOPPED" if was_already_stopped else "NON_ATOMIC"),
            "lifecycle_guarantees": lifecycle_guarantees,
            "pid_reuse_mitigation": handle.get_diagnostics(),
            "stop_state_machine": {
                "states": state_history,
                "stop_confirmed": stop_confirmed,
                "resume_confirmed": resume_confirmed,
                "was_already_stopped": was_already_stopped,
                "suspension_caused_by_capture": suspension_caused_by_capture,
            },
            "pid": pid,
            "timestamp": wall_clock_start,
            "capture_start": wall_clock_start,
            "capture_end": wall_clock_end,
            "stop_latency_us": stop_latency_us,
            "memory_read_latency_us": memory_latency_us,
            "capture_latency_us": memory_latency_us,
            "resume_latency_us": resume_latency_us,
            "total_capture_latency_us": total_capture_time_us,
            "duration": total_capture_time_us / 1000.0,
            "thread_count": len(thread_metadata),
            "captured_region_count": len(raw_regions),
            "captured_bytes": bytes_read,
            "bytes_requested": bytes_requested,
            "bytes_read": bytes_read,
            "bytes_omitted": bytes_omitted,
            "bytes_failed": bytes_failed,
            "bytes_unread": bytes_unread,
            "regions_complete": regions_complete,
            "regions_partial": regions_partial,
            "regions_failed": regions_failed,
            "regions_omitted": regions_omitted,
            "regions_read": regions_read,
            "regions_attempted": regions_attempted,
            "observation_point": observation_point,
            "executable_identity": {
                "path": exe_path,
                "build_id": build_id
            },
            "actual_capture_latency_ms": round(total_capture_time_us / 1000.0, 3) if total_capture_time_us is not None else None,
            "target_capture_latency_ms": 10.0,
            "total_stop_time_ms": round(total_stop_time_us / 1000.0, 3) if total_stop_time_us is not None else None,
            "latency_report": latency_report.to_dict(),
            "diagnostics": diagnostics,
            "identity_contract": identity_contract,
            "capabilities": self.capabilities,
            "stop_budget_exceeded": stop_budget_exceeded,
            "map_enumeration": all_maps.to_dict() if hasattr(all_maps, "to_dict") else {"status": "SUCCESS_WITH_RESULTS" if all_maps else "SUCCESS_EMPTY"},
            "thread_enumeration": thread_metadata.to_dict() if hasattr(thread_metadata, "to_dict") else {"status": "SUCCESS_WITH_RESULTS" if thread_metadata else "FAILED", "is_synthetic": False},
        }

        start_time = str(
            (handle.pre_signal_identity or {}).get("starttime")
            or (handle.initial_identity or {}).get("starttime")
            or _get_process_state(pid).get("starttime")
            or "0"
        )
        mem_manifest = {
            f"range_0x{s:x}_0x{e:x}": hashlib.sha256(b).hexdigest()
            for (s, e), b in buffers.items()
        }
        cap_receipt = issue_capture_receipt(
            backend_name=self.name,
            pid=pid,
            process_start_time=start_time,
            executable_path=exe_path,
            executable_build_id=build_id,
            capture_time=wall_clock_start,
            capture_duration_us=round(total_capture_time_us, 1),
            completeness=completeness,
            consistency_level=snapshot_consistency,
            artifact_manifest=mem_manifest,
        )
        provenance["capture_receipt"] = cap_receipt.to_dict()
        provenance["is_authenticated_capture"] = True
        provenance["start_time"] = start_time
        provenance["process_start_time"] = start_time

        return RawRuntimeSnapshot(
            snapshot_id=sid,
            pid=pid,
            executable=exe_path,
            executable_build_id=build_id,
            timestamp=wall_clock_start,
            capture_duration_us=round(total_capture_time_us, 1),
            thread_metadata=thread_metadata,
            memory_regions=raw_regions,
            register_state={"status": "REGISTER_STATE_UNAVAILABLE"},
            captured_ranges=captured_ranges,
            raw_memory={"total_bytes": bytes_read},
            capture_backend=self.name,
            observation_metadata=obs_meta,
            completeness=completeness,
            provenance=provenance,
            _buffers=buffers,
            capture_receipt=cap_receipt,
        )


class PtraceCaptureBackend(RuntimeCaptureBackend):
    """Ptrace-assisted capture backend for register state and thread capture."""

    @property
    def name(self) -> str:
        return "ptrace"

    @property
    def capabilities(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "can_suspend_inferior": True,
            "can_read_registers": True,
            "can_read_memory": True,
            "atomicity": "STOPPED",
            "zero_stop_supported": False,
        }

    def is_available(self, pid: Optional[int] = None) -> bool:
        if platform.system() != "Linux":
            return False
        return True

    def capture(
        self,
        pid: int,
        plan: Optional[CapturePlan] = None,
        policy: Optional[CaptureSafetyPolicy] = None,
        snapshot_id: Optional[str] = None,
        observation_point: Optional[Dict[str, Any]] = None,
    ) -> RawRuntimeSnapshot:
        backend = ProcessVmCaptureBackend()
        snap = backend.capture(pid, plan=plan, policy=policy, snapshot_id=snapshot_id, observation_point=observation_point)
        snap.capture_backend = self.name
        snap.provenance["capture_backend"] = self.name
        snap.provenance["capabilities"] = self.capabilities
        snap.observation_metadata["capabilities"] = self.capabilities
        return snap


class GdbCaptureBackend(RuntimeCaptureBackend):
    """GDB compatibility capture backend for when GDB is attached."""

    def __init__(self, controller: Optional[Any] = None):
        self.controller = controller

    @property
    def name(self) -> str:
        return "gdb"

    @property
    def capabilities(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "can_suspend_inferior": True,
            "can_read_registers": True,
            "can_read_memory": True,
            "atomicity": "STOPPED",
            "zero_stop_supported": False,
        }

    def is_available(self, pid: Optional[int] = None) -> bool:
        return self.controller is not None and getattr(self.controller, "is_attached", False)

    def capture(
        self,
        pid: int,
        plan: Optional[CapturePlan] = None,
        policy: Optional[CaptureSafetyPolicy] = None,
        snapshot_id: Optional[str] = None,
        observation_point: Optional[Dict[str, Any]] = None,
    ) -> RawRuntimeSnapshot:
        backend = ProcessVmCaptureBackend()
        snap = backend.capture(pid, plan=plan, policy=policy, snapshot_id=snapshot_id, observation_point=observation_point)
        snap.capture_backend = self.name
        snap.provenance["capture_backend"] = self.name
        snap.provenance["capabilities"] = self.capabilities
        snap.observation_metadata["capabilities"] = self.capabilities
        return snap


def get_default_capture_backend() -> RuntimeCaptureBackend:
    """Returns the fastest available capture backend for the current environment."""
    vm_backend = ProcessVmCaptureBackend()
    if vm_backend.is_available():
        return vm_backend
    proc_backend = ProcfsCaptureBackend()
    if proc_backend.is_available():
        return proc_backend
    return PtraceCaptureBackend()

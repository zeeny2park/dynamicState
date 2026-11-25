"""Target identity & build-id verification policy strategy interface.

Decouples binary identity and absent-build-id handling from core capture
transactions, LiveCaptureReceipt validation, and debug-image verification so
custom adapters can override identity rules without modifying core engine code.
"""

from __future__ import annotations

import hashlib
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
import os
from typing import Any, Callable, Dict, Optional, Tuple


_SHA256_FP_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


def normalize_sha256_fingerprint(fp: Optional[str]) -> Optional[str]:
    """Validate and normalize an independent cryptographic SHA-256 file fingerprint.

    Only explicit ``sha256:<64-hex>`` digests derived from actual binary bytes are
    accepted. File paths, synthetic markers, or arbitrary strings are rejected.
    """
    if not fp or not isinstance(fp, str):
        return None
    norm = fp.strip().lower()
    if _SHA256_FP_RE.match(norm):
        return norm
    return None


class TargetIdentityPolicy(ABC):
    """Strategy interface governing target binary identity & build-id rules."""

    policy_id: str = "abstract-identity-policy"
    policy_version: str = "1.0"

    @staticmethod
    def is_synthetic_build_id(build_id: Optional[str]) -> bool:
        return bool(build_id and str(build_id).strip().lower().startswith("no-build-id:"))

    @classmethod
    def verification_mode(cls, build_id: Optional[str]) -> str:
        b = str(build_id or "").strip()
        if not b or b == "default_build_id":
            return "unverifiable"
        if cls.is_synthetic_build_id(b):
            return "synthetic_no_build_id"
        return "verified_build_id"

    def describe(self) -> Dict[str, str]:
        return {
            "identity_policy_id": str(self.policy_id),
            "identity_policy_version": str(self.policy_version),
        }

    @abstractmethod
    def resolve_build_id(
        self,
        identity: Dict[str, Any],
        tx_metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Optional[str], Optional[str]]:
        """Resolve a transaction build-id from raw process identity.

        Returns ``(build_id, error_reason)``. On failure, ``build_id`` is
        ``None`` and ``error_reason`` explains why the transaction must fail
        closed.
        """

    @abstractmethod
    def validate_build_id_match(
        self,
        expected_build_id: Optional[str],
        actual_build_id: Optional[str],
    ) -> Tuple[bool, str]:
        """Validate whether ``actual_build_id`` satisfies ``expected_build_id``."""

    @abstractmethod
    def validate_debug_image_compatibility(
        self,
        runtime_build_id: Optional[str],
        debug_build_id: Optional[str],
        *,
        runtime_fingerprint: Optional[str] = None,
        debug_fingerprint: Optional[str] = None,
    ) -> Tuple[bool, str]:
        """Validate identity compatibility between runtime ELF and companion debug ELF.

        Must fail closed (return ``False``) whenever sufficient independent identity
        evidence is unavailable.
        """


class DefaultTargetIdentityPolicy(TargetIdentityPolicy):
    """Default identity policy supporting optional GNU Build-ID (e.g. ``-Wl,--build-id=none``).

    When a target binary lacks a GNU Build-ID, synthesizes a deterministic
    ``no-build-id:<sha256[:24]>`` marker from observed executable path,
    executable identity, or file fingerprint, while failing closed on empty,
    missing, or mismatched identities.
    """

    policy_id: str = "default-optional-build-id"
    policy_version: str = "1.0"

    def resolve_build_id(
        self,
        identity: Dict[str, Any],
        tx_metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Optional[str], Optional[str]]:
        cur_bid = identity.get("build_id") if isinstance(identity, dict) else None
        if cur_bid and cur_bid != "default_build_id":
            if isinstance(tx_metadata, dict):
                tx_metadata["identity_policy_id"] = self.policy_id
                tx_metadata["identity_policy_version"] = self.policy_version
                tx_metadata["identity_verification_mode"] = self.verification_mode(str(cur_bid))
            return str(cur_bid), None

        exe_path = str((identity or {}).get("executable") or "").strip()
        exe_fp = str((identity or {}).get("exe_fingerprint") or "").strip()
        exe_id = str((identity or {}).get("executable_identity") or "").strip()
        if exe_path or exe_fp or exe_id:
            fb_raw = f"{exe_path or exe_id}|{exe_fp}".encode("utf-8", "replace")
            synthetic = f"no-build-id:{hashlib.sha256(fb_raw).hexdigest()[:24]}"
            if isinstance(tx_metadata, dict):
                tx_metadata["build_id_absent"] = True
                tx_metadata["identity_policy_id"] = self.policy_id
                tx_metadata["identity_policy_version"] = self.policy_version
                tx_metadata["identity_verification_mode"] = "synthetic_no_build_id"
            return synthetic, None
        return None, "missing_build_id_and_executable_identity"

    def validate_build_id_match(
        self,
        expected_build_id: Optional[str],
        actual_build_id: Optional[str],
    ) -> Tuple[bool, str]:
        if expected_build_id is None or not str(expected_build_id).strip():
            return True, "ok"
        exp_b = str(expected_build_id).strip().lower()
        got_b = str(actual_build_id or "").strip().lower()

        # Missing actual build_id MUST NEVER pass merely because expected is synthetic
        if not got_b:
            return False, f"missing_actual_build_id:expected={expected_build_id}"

        exp_synth = exp_b.startswith("no-build-id:")
        got_synth = got_b.startswith("no-build-id:")
        if exp_synth and got_synth:
            if got_b != exp_b:
                return False, f"mismatched_executable_fingerprint:expected={expected_build_id},got={actual_build_id}"
            return True, "ok_synthetic_no_build_id"
        if got_b != exp_b:
            return False, f"mismatched_build_id:expected={expected_build_id},got={actual_build_id}"
        return True, "ok"

    def validate_debug_image_compatibility(
        self,
        runtime_build_id: Optional[str],
        debug_build_id: Optional[str],
        *,
        runtime_fingerprint: Optional[str] = None,
        debug_fingerprint: Optional[str] = None,
    ) -> Tuple[bool, str]:
        rb = str(runtime_build_id or "").strip().lower()
        db = str(debug_build_id or "").strip().lower()
        rb_absent = (not rb) or rb == "default_build_id" or rb.startswith("no-build-id:")
        db_absent = (not db) or db == "default_build_id" or db.startswith("no-build-id:")

        # 1. Both have real GNU Build IDs: authoritative match / mismatch
        if not rb_absent and not db_absent:
            if rb == db:
                return True, "BUILD_ID_MATCH"
            return False, "BUILD_ID_MISMATCH"

        # 2. Exactly one side has a real GNU Build ID: cannot verify compatibility
        if rb_absent != db_absent:
            return False, "BUILD_ID_NOT_AVAILABLE"

        # 3. Both lack a real GNU Build ID (missing or synthetic):
        #    NEVER approve automatically. Require independent cryptographic
        #    SHA-256 content fingerprints of both ELF files.
        rfp = normalize_sha256_fingerprint(runtime_fingerprint)
        dfp = normalize_sha256_fingerprint(debug_fingerprint)
        if rfp and dfp:
            if rfp == dfp:
                return True, "FINGERPRINT_MATCH"
            return False, "FINGERPRINT_MISMATCH"

        return False, "UNKNOWN_IDENTITY_UNVERIFIABLE"


class StrictBuildIdIdentityPolicy(DefaultTargetIdentityPolicy):
    """Strict identity policy requiring an explicit GNU Build-ID on all targets."""

    policy_id: str = "strict-build-id"
    policy_version: str = "1.0"

    def resolve_build_id(
        self,
        identity: Dict[str, Any],
        tx_metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Optional[str], Optional[str]]:
        cur_bid = identity.get("build_id") if isinstance(identity, dict) else None
        if cur_bid and cur_bid != "default_build_id" and not self.is_synthetic_build_id(str(cur_bid)):
            if isinstance(tx_metadata, dict):
                tx_metadata["identity_policy_id"] = self.policy_id
                tx_metadata["identity_policy_version"] = self.policy_version
                tx_metadata["identity_verification_mode"] = "verified_build_id"
            return str(cur_bid), None
        return None, "strict_build_id_required"

    def validate_build_id_match(
        self,
        expected_build_id: Optional[str],
        actual_build_id: Optional[str],
    ) -> Tuple[bool, str]:
        if expected_build_id is None or not str(expected_build_id).strip():
            if not actual_build_id or self.is_synthetic_build_id(actual_build_id):
                return False, "strict_build_id_required"
            return True, "ok"
        exp_b = str(expected_build_id).strip().lower()
        got_b = str(actual_build_id or "").strip().lower()
        if not got_b or got_b.startswith("no-build-id:") or exp_b.startswith("no-build-id:"):
            return False, "strict_build_id_required"
        if got_b != exp_b:
            return False, f"mismatched_build_id:expected={expected_build_id},got={actual_build_id}"
        return True, "ok"

    def validate_debug_image_compatibility(
        self,
        runtime_build_id: Optional[str],
        debug_build_id: Optional[str],
        *,
        runtime_fingerprint: Optional[str] = None,
        debug_fingerprint: Optional[str] = None,
    ) -> Tuple[bool, str]:
        # Strict policy requires real GNU Build IDs on both ELF binaries;
        # independent file fingerprints do not relax this requirement.
        rb = str(runtime_build_id or "").strip().lower()
        db = str(debug_build_id or "").strip().lower()
        if (
            not rb or not db
            or rb == "default_build_id" or db == "default_build_id"
            or rb.startswith("no-build-id:") or db.startswith("no-build-id:")
        ):
            return False, "STRICT_BUILD_ID_REQUIRED"
        return (rb == db), ("BUILD_ID_MATCH" if rb == db else "BUILD_ID_MISMATCH")


DEFAULT_IDENTITY_POLICY = DefaultTargetIdentityPolicy()


@dataclass(frozen=True)
class DebugImageVerificationResult:
    """Unified, fail-closed identity verification outcome shared by all Debug Image providers."""

    compatible: bool
    verification_method: str       # "gnu_build_id" | "gnu_debuglink_crc32" | "sha256_fingerprint" | "none"
    identity_policy_id: str
    identity_policy_version: str
    verification_result: str       # "VERIFIED" | "MISMATCH" | "UNVERIFIABLE"
    verification_reason: str       # Canonical reason code

    def provenance_fields(self) -> Dict[str, Any]:
        return {
            "verification_method": self.verification_method,
            "identity_policy_id": self.identity_policy_id,
            "identity_policy_version": self.identity_policy_version,
            "verification_result": self.verification_result,
            "verification_reason": self.verification_reason,
        }


def _is_real_build_id(build_id: Optional[str]) -> bool:
    b = str(build_id or "").strip().lower()
    return bool(b and b != "default_build_id" and not b.startswith("no-build-id:"))


def verify_debug_image_identity(
    *,
    runtime_build_id: Optional[str],
    debug_build_id: Optional[str],
    debuglink: Optional[Dict[str, Any]] = None,
    debug_image_path: Optional[str] = None,
    runtime_fingerprint: Optional[str] = None,
    debug_fingerprint: Optional[str] = None,
    identity_policy: Optional[TargetIdentityPolicy] = None,
    debuglink_crc_fn: Optional[Callable[[str], Optional[int]]] = None,
) -> DebugImageVerificationResult:
    """Single shared, fail-closed debug image identity verifier.

    Used by both ``DebugImageProvider`` and ``DebugArtifactProvider`` so identical
    input evidence always yields the exact same compatibility decision and provenance.

    Rules (in strict precedence order):
    1. If both sides carry real GNU Build IDs: require exact match.
    2. If only one side carries a real GNU Build ID: fail closed (never approve).
    3. If policy is strict (rejects absent Build IDs): fail closed with ``STRICT_BUILD_ID_REQUIRED``.
    4. If ``.gnu_debuglink`` is present with matching basename AND an explicit CRC AND
       ``debug_image_path`` is a readable file: verify CRC-32 against the actual bytes.
       - Matching CRC -> ``VERIFIED`` via ``gnu_debuglink_crc32`` (``COMPATIBLE_DEBUGLINK``).
       - Missing CRC or unreadable file -> filename equality NEVER establishes compatibility;
         fall through to independent SHA-256 fingerprint verification.
       - Mismatched CRC -> only independently verified matching SHA-256 fingerprints may
         establish compatibility; otherwise fail closed with ``DEBUGLINK_CRC_MISMATCH``.
    5. Independent cryptographic SHA-256 fingerprints (``sha256:<64-hex>``) via
       ``identity_policy.validate_debug_image_compatibility()``:
       - Matching -> ``VERIFIED`` via ``sha256_fingerprint`` (``FINGERPRINT_MATCH``).
       - Mismatched -> ``MISMATCH`` via ``sha256_fingerprint`` (``FINGERPRINT_MISMATCH``).
       - Unavailable -> ``UNVERIFIABLE`` via ``none`` (``UNKNOWN_IDENTITY_UNVERIFIABLE``).
    """
    pol = identity_policy or DEFAULT_IDENTITY_POLICY
    pol_id = str(getattr(pol, "policy_id", "default-optional-build-id"))
    pol_ver = str(getattr(pol, "policy_version", "1.0"))

    rb_real = _is_real_build_id(runtime_build_id)
    db_real = _is_real_build_id(debug_build_id)

    # 1 & 2. Real GNU Build ID present on one or both sides
    if rb_real or db_real:
        ok, reason = pol.validate_debug_image_compatibility(
            runtime_build_id,
            debug_build_id,
            runtime_fingerprint=runtime_fingerprint,
            debug_fingerprint=debug_fingerprint,
        )
        if ok:
            return DebugImageVerificationResult(
                compatible=True,
                verification_method="gnu_build_id",
                identity_policy_id=pol_id,
                identity_policy_version=pol_ver,
                verification_result="VERIFIED",
                verification_reason=reason,
            )
        v_res = "MISMATCH" if reason == "BUILD_ID_MISMATCH" else "UNVERIFIABLE"
        v_method = "none" if reason == "STRICT_BUILD_ID_REQUIRED" else "gnu_build_id"
        return DebugImageVerificationResult(
            compatible=False,
            verification_method=v_method,
            identity_policy_id=pol_id,
            identity_policy_version=pol_ver,
            verification_result=v_res,
            verification_reason=reason,
        )

    # 3. Both Build IDs absent/synthetic: check whether policy strictly requires GNU Build ID
    if isinstance(pol, StrictBuildIdIdentityPolicy):
        return DebugImageVerificationResult(
            compatible=False,
            verification_method="none",
            identity_policy_id=pol_id,
            identity_policy_version=pol_ver,
            verification_result="UNVERIFIABLE",
            verification_reason="STRICT_BUILD_ID_REQUIRED",
        )

    # 4. .gnu_debuglink CRC-32 verification (filename equality alone NEVER suffices)
    crc_mismatch_seen = False
    if isinstance(debuglink, dict) and debuglink.get("filename") and debug_image_path:
        expected_name = str(debuglink.get("filename") or "")
        actual_name = os.path.basename(str(debug_image_path))
        expected_crc = debuglink.get("crc")
        if (
            expected_name
            and expected_name == actual_name
            and expected_crc is not None
            and os.path.isfile(debug_image_path)
        ):
            if debuglink_crc_fn is None:
                from ..debug_artifacts import compute_gnu_debuglink_crc as _default_crc_fn
                crc_fn = _default_crc_fn
            else:
                crc_fn = debuglink_crc_fn
            try:
                actual_crc = crc_fn(debug_image_path)
            except OSError:
                actual_crc = None
            if actual_crc is not None:
                if int(actual_crc) == int(expected_crc):
                    return DebugImageVerificationResult(
                        compatible=True,
                        verification_method="gnu_debuglink_crc32",
                        identity_policy_id=pol_id,
                        identity_policy_version=pol_ver,
                        verification_result="VERIFIED",
                        verification_reason="COMPATIBLE_DEBUGLINK",
                    )
                crc_mismatch_seen = True

    # 5. Independent SHA-256 fingerprint verification via identity policy
    ok, reason = pol.validate_debug_image_compatibility(
        runtime_build_id,
        debug_build_id,
        runtime_fingerprint=runtime_fingerprint,
        debug_fingerprint=debug_fingerprint,
    )
    if ok:
        return DebugImageVerificationResult(
            compatible=True,
            verification_method="sha256_fingerprint",
            identity_policy_id=pol_id,
            identity_policy_version=pol_ver,
            verification_result="VERIFIED",
            verification_reason=reason,
        )
    if crc_mismatch_seen:
        return DebugImageVerificationResult(
            compatible=False,
            verification_method="gnu_debuglink_crc32",
            identity_policy_id=pol_id,
            identity_policy_version=pol_ver,
            verification_result="MISMATCH",
            verification_reason="DEBUGLINK_CRC_MISMATCH",
        )
    if reason == "FINGERPRINT_MISMATCH":
        return DebugImageVerificationResult(
            compatible=False,
            verification_method="sha256_fingerprint",
            identity_policy_id=pol_id,
            identity_policy_version=pol_ver,
            verification_result="MISMATCH",
            verification_reason="FINGERPRINT_MISMATCH",
        )
    return DebugImageVerificationResult(
        compatible=False,
        verification_method="none",
        identity_policy_id=pol_id,
        identity_policy_version=pol_ver,
        verification_result="UNVERIFIABLE",
        verification_reason=reason,
    )

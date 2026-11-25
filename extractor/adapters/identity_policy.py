"""Target identity & build-id verification policy strategy interface.

Decouples binary identity and absent-build-id handling from core capture
transactions, LiveCaptureReceipt validation, and debug-image verification so
custom adapters can override identity rules without modifying core engine code.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Tuple


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
    ) -> Tuple[bool, str]:
        """Validate build-id compatibility between runtime ELF and companion debug ELF."""


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
    ) -> Tuple[bool, str]:
        rb = str(runtime_build_id or "").strip().lower()
        db = str(debug_build_id or "").strip().lower()
        rb_absent = (not rb) or rb.startswith("no-build-id:")
        db_absent = (not db) or db.startswith("no-build-id:")
        if not rb_absent and not db_absent:
            if rb == db:
                return True, "BUILD_ID_MATCH"
            return False, "BUILD_ID_MISMATCH"
        if rb_absent and db_absent:
            return True, "COMPATIBLE_NO_BUILD_ID"
        return False, "BUILD_ID_NOT_AVAILABLE"


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
    ) -> Tuple[bool, str]:
        rb = str(runtime_build_id or "").strip().lower()
        db = str(debug_build_id or "").strip().lower()
        if not rb or not db or rb.startswith("no-build-id:") or db.startswith("no-build-id:"):
            return False, "STRICT_BUILD_ID_REQUIRED"
        return (rb == db), ("BUILD_ID_MATCH" if rb == db else "BUILD_ID_MISMATCH")


DEFAULT_IDENTITY_POLICY = DefaultTargetIdentityPolicy()

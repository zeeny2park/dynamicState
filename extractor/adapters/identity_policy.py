"""Target identity & build-id verification policy strategy interface.

Decouples binary identity and absent-build-id handling from core capture
transactions and verification receipts so custom adapters can override identity
rules without modifying core engine code.
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional, Tuple


class TargetIdentityPolicy(ABC):
    """Strategy interface governing target binary identity & build-id rules."""

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
    executable identity, or file fingerprint, while still failing closed on
    empty/corrupt identities.
    """

    def resolve_build_id(
        self,
        identity: Dict[str, Any],
        tx_metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Optional[str], Optional[str]]:
        cur_bid = identity.get("build_id") if isinstance(identity, dict) else None
        if cur_bid and cur_bid != "default_build_id":
            return str(cur_bid), None

        exe_path = str((identity or {}).get("executable") or "").strip()
        exe_fp = str((identity or {}).get("exe_fingerprint") or "").strip()
        exe_id = str((identity or {}).get("executable_identity") or "").strip()
        if exe_path or exe_fp or exe_id:
            fb_raw = f"{exe_path or exe_id}|{exe_fp}".encode("utf-8", "replace")
            synthetic = f"no-build-id:{hashlib.sha256(fb_raw).hexdigest()[:24]}"
            if isinstance(tx_metadata, dict):
                tx_metadata["build_id_absent"] = True
            return synthetic, None
        return None, "missing_build_id"

    def validate_build_id_match(
        self,
        expected_build_id: Optional[str],
        actual_build_id: Optional[str],
    ) -> Tuple[bool, str]:
        if expected_build_id is None or not str(expected_build_id).strip():
            return True, "ok"
        exp_b = str(expected_build_id).strip().lower()
        got_b = str(actual_build_id or "").strip().lower()
        exp_absent = exp_b.startswith("no-build-id:")
        got_absent = (not got_b) or got_b.startswith("no-build-id:")
        if exp_absent and got_absent:
            if got_b and got_b != exp_b:
                return False, f"mismatched_build_id:expected={expected_build_id},got={actual_build_id}"
            return True, "ok_no_build_id"
        if not got_b or got_b != exp_b:
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

    def resolve_build_id(
        self,
        identity: Dict[str, Any],
        tx_metadata: Optional[Dict[str, Any]] = None,
    ) -> Tuple[Optional[str], Optional[str]]:
        cur_bid = identity.get("build_id") if isinstance(identity, dict) else None
        if cur_bid and cur_bid != "default_build_id" and not str(cur_bid).lower().startswith("no-build-id:"):
            return str(cur_bid), None
        return None, "strict_build_id_required"

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

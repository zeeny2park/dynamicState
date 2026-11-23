"""Persistent collected-bundle store keyed by (host, pid, start_time, boot_id, build_id).

Enables high-latency multi-hop SSH / xssh workflows to:
1. Persist Wave-1 upfront snapshots and collected metadata atomically to disk.
2. Reuse already-collected data to finish diagnosis to completion (including
   ``continue_collected_only=True``) with zero additional remote exec calls when
   the target's full process identity matches ``(host, pid, start_time, boot_id, build_id)``.
3. Prevent PID-reuse or reboot cross-contamination by requiring ``start_time``,
   ``boot_id``, and ``build_id`` alignment whenever those fields are known.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class BundleIdentityKey:
    host: str
    pid: int
    start_time: str = ""
    boot_id: str = ""
    build_id: str = ""

    def normalized(self) -> "BundleIdentityKey":
        return BundleIdentityKey(
            host=str(self.host or "").strip(),
            pid=int(self.pid),
            start_time=str(self.start_time or "").strip(),
            boot_id=str(self.boot_id or "").strip(),
            build_id=str(self.build_id or "").strip().lower(),
        )

    def storage_id(self) -> str:
        k = self.normalized()
        raw = f"{k.host}|{k.pid}|{k.start_time}|{k.boot_id}|{k.build_id}".encode("utf-8")
        return hashlib.sha256(raw).hexdigest()[:24]

    def to_dict(self) -> Dict[str, Any]:
        k = self.normalized()
        return {
            "host": k.host,
            "pid": k.pid,
            "start_time": k.start_time,
            "boot_id": k.boot_id,
            "build_id": k.build_id,
            "bundle_id": k.storage_id(),
        }

    def matches(self, other: "BundleIdentityKey") -> bool:
        a = self.normalized()
        b = other.normalized()
        if a.host != b.host or a.pid != b.pid:
            return False
        # Require exact match on build_id, start_time, and boot_id whenever both sides provide them;
        # if either side has start_time/boot_id and the other differs, reject to prevent PID reuse.
        if a.build_id and b.build_id and a.build_id != b.build_id:
            return False
        if (a.start_time or b.start_time) and a.start_time != b.start_time:
            return False
        if (a.boot_id or b.boot_id) and a.boot_id != b.boot_id:
            return False
        return True


def _atomic_write_json(path: str, payload: Dict[str, Any]) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".ds_bundle_", suffix=".tmp", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, sort_keys=True)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                pass
        os.replace(tmp_path, path)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


class RemoteCollectedBundleStore:
    """File-backed store for upfront remote diagnostic bundles."""

    def __init__(self, base_dir: Optional[str] = None):
        root = base_dir or os.path.join(tempfile.gettempdir(), "dynamicstate_remote_bundles")
        self.bundle_dir = os.path.join(os.path.abspath(root), "remote_bundles")

    def _bundle_path(self, key: BundleIdentityKey) -> str:
        return os.path.join(self.bundle_dir, f"bundle_{key.storage_id()}.json")

    def save_bundle(
        self,
        key: BundleIdentityKey,
        *,
        snapshot: Optional[Dict[str, Any]] = None,
        identity: Optional[Dict[str, Any]] = None,
        investigation_id: Optional[str] = None,
        memory_slices: Optional[Dict[str, str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        norm = key.normalized()
        record: Dict[str, Any] = {
            "schema_version": 1,
            "key": norm.to_dict(),
            "saved_at_epoch_s": time.time(),
            "investigation_id": investigation_id,
            "identity": dict(identity or {}),
            "snapshot": dict(snapshot or {}),
            "memory_slices": dict(memory_slices or {}),
            "metadata": dict(metadata or {}),
        }
        _atomic_write_json(self._bundle_path(norm), record)
        return record

    def load_bundle(self, key: BundleIdentityKey) -> Optional[Dict[str, Any]]:
        norm = key.normalized()
        path = self._bundle_path(norm)
        if not os.path.isfile(path):
            return None
        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception:
            return None
        kd = data.get("key") if isinstance(data, dict) else None
        if not isinstance(kd, dict):
            return None
        stored_key = BundleIdentityKey(
            host=str(kd.get("host") or ""),
            pid=int(kd.get("pid") or 0),
            start_time=str(kd.get("start_time") or ""),
            boot_id=str(kd.get("boot_id") or ""),
            build_id=str(kd.get("build_id") or ""),
        )
        if not norm.matches(stored_key):
            return None
        return data

    def find_latest(
        self,
        *,
        host: str,
        pid: int,
        build_id: str = "",
        start_time: str = "",
        boot_id: str = "",
    ) -> Optional[Dict[str, Any]]:
        """Finds the newest bundle matching (host, pid, build_id) and (when given) start_time/boot_id."""
        if not os.path.isdir(self.bundle_dir):
            return None
        want_host = str(host or "").strip()
        want_pid = int(pid)
        want_bid = str(build_id or "").strip().lower()
        want_st = str(start_time or "").strip()
        want_boot = str(boot_id or "").strip()
        best: Optional[Dict[str, Any]] = None
        best_ts = -1.0
        for fname in os.listdir(self.bundle_dir):
            if not (fname.startswith("bundle_") and fname.endswith(".json")):
                continue
            fpath = os.path.join(self.bundle_dir, fname)
            try:
                with open(fpath, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
            except Exception:
                continue
            kd = data.get("key") if isinstance(data, dict) else None
            if not isinstance(kd, dict):
                continue
            if str(kd.get("host") or "").strip() != want_host:
                continue
            if int(kd.get("pid") or -1) != want_pid:
                continue
            stored_bid = str(kd.get("build_id") or "").strip().lower()
            if want_bid and stored_bid and stored_bid != want_bid:
                continue
            if want_bid and not stored_bid:
                continue
            stored_st = str(kd.get("start_time") or "").strip()
            if want_st and stored_st != want_st:
                continue
            stored_boot = str(kd.get("boot_id") or "").strip()
            if want_boot and stored_boot != want_boot:
                continue
            ts = float(data.get("saved_at_epoch_s") or 0.0)
            if ts > best_ts:
                best_ts = ts
                best = data
        return best

    def invalidate(self, key: BundleIdentityKey) -> bool:
        path = self._bundle_path(key.normalized())
        if os.path.isfile(path):
            try:
                os.unlink(path)
                return True
            except OSError:
                return False
        return False

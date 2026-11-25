"""Diagnosis baseline persistence, strict target identity matching, and regression diffing.

Saves lightweight, deterministic snapshots of each completed ``diagnose`` run
under ``<corpus_dir>/baselines/`` with:
- Strict target identity compatibility checks (``EXACT``, ``COMPATIBLE``, ``WEAK``,
  ``MISMATCH``, ``UNKNOWN``) preventing cross-host or process-name-only auto-matching
  and validating explicitly supplied baseline files.
- Atomic file writes (temp + fsync + replace), advisory file locking against
  concurrent lost updates, corrupted ``index.json`` auto-recovery, strict
  ``investigation_id`` filename validation, and real file pruning on retention cap.
- Rich baseline intelligence comparing RSS/heap/FD/thread/lock metrics, thread
  role/state distributions, liveness activity deltas, added/removed/growing C++
  containers, finding recurrence, and sustained-growth vs single-point-spike
  classification.
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import os
import re
import tempfile
import time
from typing import Any, Dict, Iterator, List, Optional, Tuple

BASELINE_SCHEMA_VERSION = "1.1"
DEFAULT_MAX_BASELINES = 200
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_LOCAL_HOSTS = frozenset({"", "local", "localhost", "127.0.0.1", "::1"})


def _num(val: Any) -> Optional[float]:
    if isinstance(val, bool) or val is None:
        return None
    if isinstance(val, (int, float)):
        return float(val)
    try:
        return float(val)
    except (TypeError, ValueError):
        return None


def _int_or_none(val: Any) -> Optional[int]:
    n = _num(val)
    return int(round(n)) if n is not None else None


def _norm_host(host: Any) -> str:
    if host is None:
        return "local"
    s = str(host).strip().lower()
    return "local" if s in _LOCAL_HOSTS else s


def _norm_str(val: Any) -> str:
    return str(val).strip() if val is not None and str(val).strip() else ""


def sanitize_investigation_id(inv_id: Any) -> Optional[str]:
    """Validate an investigation_id for safe use as a baseline filename stem."""
    if inv_id is None:
        return None
    s = str(inv_id).strip()
    if not s or ".." in s or "/" in s or "\\" in s:
        return None
    if not _SAFE_ID_RE.match(s):
        return None
    return s


def _validate_snapshot_record(data: Any) -> bool:
    """Ensure a baseline JSON record is complete and structurally valid."""
    if not isinstance(data, dict):
        return False
    if not data.get("schema_version") or not sanitize_investigation_id(data.get("investigation_id")):
        return False
    if not isinstance(data.get("metrics"), dict) or not isinstance(data.get("target"), dict):
        return False
    return True


def _series_trend(series: Any) -> str:
    """Classify an in-window numeric series as rising, falling, or stable."""
    if not isinstance(series, list):
        return "unknown"
    vals = [_num(x) for x in series]
    nums = [v for v in vals if v is not None]
    if len(nums) < 2:
        return "unknown"
    diffs = [nums[i + 1] - nums[i] for i in range(len(nums) - 1)]
    net = nums[-1] - nums[0]
    if net > 0 and all(d >= 0 for d in diffs) and any(d > 0 for d in diffs):
        return "rising"
    if net < 0 and all(d <= 0 for d in diffs) and any(d < 0 for d in diffs):
        return "falling"
    return "stable"


# ------------------------------------------------------------------ 1. Strict Target Identity Matching
def evaluate_target_identity_match(
    current_target: Optional[Dict[str, Any]],
    baseline_target: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    """Evaluate compatibility between current target and a candidate baseline target.

    Returns ``{"status": "EXACT"|"COMPATIBLE"|"WEAK"|"MISMATCH"|"UNKNOWN",
    "reason": str, "matched_fields": [...], "mismatched_fields": [...],
    "auto_selectable": bool}``.
    """
    ct = current_target if isinstance(current_target, dict) else {}
    bt = baseline_target if isinstance(baseline_target, dict) else {}

    c_host = _norm_host(ct.get("host") or ct.get("remote_host"))
    b_host = _norm_host(bt.get("host") or bt.get("remote_host"))
    c_bid = _norm_str(ct.get("build_id")).lower()
    b_bid = _norm_str(bt.get("build_id")).lower()
    c_bin = _norm_str(ct.get("binary_path") or ct.get("executable"))
    b_bin = _norm_str(bt.get("binary_path") or bt.get("executable"))
    c_proc = _norm_str(ct.get("process_name"))
    b_proc = _norm_str(bt.get("process_name"))

    matched: List[str] = []
    mismatched: List[str] = []

    if c_host != b_host:
        mismatched.append("host")
        return {
            "status": "MISMATCH",
            "reason": f"host_mismatch ({c_host} != {b_host})",
            "matched_fields": matched,
            "mismatched_fields": mismatched,
            "auto_selectable": False,
        }
    matched.append("host")

    c_arch = _norm_str((ct.get("abi") or {}).get("architecture") if isinstance(ct.get("abi"), dict) else ct.get("arch"))
    b_arch = _norm_str((bt.get("abi") or {}).get("architecture") if isinstance(bt.get("abi"), dict) else bt.get("arch"))
    if c_arch and b_arch and c_arch.lower() != b_arch.lower():
        mismatched.append("arch")
        return {
            "status": "MISMATCH",
            "reason": f"arch_mismatch ({c_arch} != {b_arch})",
            "matched_fields": matched,
            "mismatched_fields": mismatched,
            "auto_selectable": False,
        }

    bid_match: Optional[bool] = (c_bid == b_bid) if (c_bid and b_bid) else None
    bin_match: Optional[bool] = (c_bin == b_bin) if (c_bin and b_bin) else None
    proc_match: Optional[bool] = (c_proc == b_proc) if (c_proc and b_proc) else None

    if bid_match is True:
        matched.append("build_id")
    elif bid_match is False:
        mismatched.append("build_id")

    if bin_match is True:
        matched.append("binary_path")
    elif bin_match is False:
        mismatched.append("binary_path")

    if proc_match is True:
        matched.append("process_name")
    elif proc_match is False:
        mismatched.append("process_name")

    if bid_match is None and bin_match is None and proc_match is None:
        return {
            "status": "UNKNOWN",
            "reason": "insufficient_identity_fields",
            "matched_fields": matched,
            "mismatched_fields": mismatched,
            "auto_selectable": False,
        }

    if bid_match is True:
        if bin_match is False:
            return {
                "status": "COMPATIBLE",
                "reason": "same_build_id_different_path",
                "matched_fields": matched,
                "mismatched_fields": mismatched,
                "auto_selectable": True,
            }
        return {
            "status": "EXACT",
            "reason": "host_and_build_id_match",
            "matched_fields": matched,
            "mismatched_fields": mismatched,
            "auto_selectable": True,
        }

    if bin_match is True:
        if bid_match is False:
            return {
                "status": "COMPATIBLE",
                "reason": "same_binary_path_different_build_id",
                "matched_fields": matched,
                "mismatched_fields": mismatched,
                "auto_selectable": True,
            }
        if proc_match is not False:
            return {
                "status": "EXACT" if proc_match is True else "COMPATIBLE",
                "reason": "host_and_binary_path_match",
                "matched_fields": matched,
                "mismatched_fields": mismatched,
                "auto_selectable": True,
            }

    if bin_match is False:
        return {
            "status": "MISMATCH",
            "reason": f"binary_path_mismatch ({c_bin} != {b_bin})",
            "matched_fields": matched,
            "mismatched_fields": mismatched,
            "auto_selectable": False,
        }

    if bid_match is False:
        return {
            "status": "MISMATCH",
            "reason": "build_id_mismatch_without_binary_path_match",
            "matched_fields": matched,
            "mismatched_fields": mismatched,
            "auto_selectable": False,
        }

    if proc_match is False:
        return {
            "status": "MISMATCH",
            "reason": f"process_name_mismatch ({c_proc} != {b_proc})",
            "matched_fields": matched,
            "mismatched_fields": mismatched,
            "auto_selectable": False,
        }

    if proc_match is True:
        return {
            "status": "WEAK",
            "reason": "process_name_only_match",
            "matched_fields": matched,
            "mismatched_fields": mismatched,
            "auto_selectable": False,
        }

    return {
        "status": "UNKNOWN",
        "reason": "insufficient_identity_fields",
        "matched_fields": matched,
        "mismatched_fields": mismatched,
        "auto_selectable": False,
    }


def _matches_target(
    entry: Dict[str, Any],
    *,
    process_name: Optional[str] = None,
    binary_path: Optional[str] = None,
    build_id: Optional[str] = None,
    host: Optional[str] = None,
    arch: Optional[str] = None,
) -> bool:
    """Return True only when candidate entry is auto-selectable (EXACT or COMPATIBLE)."""
    curr = {
        "process_name": process_name,
        "binary_path": binary_path,
        "build_id": build_id,
        "host": host,
        "arch": arch,
    }
    res = evaluate_target_identity_match(curr, entry)
    return bool(res["auto_selectable"])


# ------------------------------------------------------------------ 2. Snapshot Extraction
def extract_baseline_snapshot(
    result: Dict[str, Any],
    profile: Optional[Dict[str, Any]] = None,
    notable_observations: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Build a compact, JSON-serializable baseline record from a diagnosis."""
    res = result if isinstance(result, dict) else {}
    prof = profile if isinstance(profile, dict) else (res.get("process_profile") or {})
    target = res.get("target") if isinstance(res.get("target"), dict) else {}
    summary = prof.get("summary") if isinstance(prof.get("summary"), dict) else {}
    mem = prof.get("memory") if isinstance(prof.get("memory"), dict) else {}
    threads = prof.get("threads") if isinstance(prof.get("threads"), dict) else {}
    resources = prof.get("resources") if isinstance(prof.get("resources"), dict) else {}
    locks = prof.get("locks") if isinstance(prof.get("locks"), dict) else {}
    liveness = prof.get("liveness") if isinstance(prof.get("liveness"), dict) else {}

    rss_kb = _int_or_none(summary.get("rss_kb"))
    if rss_kb is None and isinstance(mem.get("rss"), dict):
        rss_kb = _int_or_none(mem["rss"].get("v"))
    rss_series = (mem.get("rss_series") or {}).get("v") if isinstance(mem.get("rss_series"), dict) else None
    heap_kb = _int_or_none(summary.get("heap_kb"))
    thread_count = _int_or_none(summary.get("threads"))
    if thread_count is None and isinstance(threads.get("count"), dict):
        thread_count = _int_or_none(threads["count"].get("v"))
    fd_obj = resources.get("fds") if isinstance(resources.get("fds"), dict) else {}
    fd_count = _int_or_none(summary.get("fds"))
    if fd_count is None:
        fd_count = _int_or_none(fd_obj.get("v"))
    fd_limit = _int_or_none(fd_obj.get("limit")) or _int_or_none(
        (resources.get("fd_limit") or {}).get("v")
        if isinstance(resources.get("fd_limit"), dict) else resources.get("fd_limit")
    )
    fd_series = fd_obj.get("series") if isinstance(fd_obj.get("series"), list) else None

    containers: Dict[str, int] = {}
    for c in (mem.get("containers") or []):
        if isinstance(c, dict) and c.get("variable") and _int_or_none(c.get("size")) is not None:
            containers[str(c["variable"])] = int(c["size"])

    lock_contention_count = 0
    for lk in (locks.get("items") or []):
        if isinstance(lk, dict) and (_int_or_none(lk.get("samples_queued") or lk.get("queued_samples")) or 0) > 0:
            lock_contention_count += 1

    role_groups: Dict[str, Dict[str, Any]] = {}
    for g in (threads.get("role_groups") or liveness.get("role_summary") or []):
        if isinstance(g, dict) and g.get("role"):
            rkey = f"{g['role']}:{g.get('state', 'unknown')}"
            role_groups[rkey] = {
                "role": str(g["role"]),
                "state": str(g.get("state") or "unknown"),
                "count": int(g.get("count") or 1),
                "cpu_time_ms_delta": _num(g.get("cpu_time_ms_delta")),
            }

    notable_ids = sorted({
        str(n.get("id") or n.get("category") or "")
        for n in (notable_observations or [])
        if isinstance(n, dict) and (n.get("id") or n.get("category"))
    })

    abi = target.get("abi") if isinstance(target.get("abi"), dict) else {}
    arch = _norm_str(abi.get("architecture") or target.get("arch"))

    return {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "investigation_id": res.get("investigation_id"),
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "captured_epoch": round(time.time(), 3),
        "verdict": str(res.get("verdict") or "INCONCLUSIVE"),
        "target": {
            "pid": target.get("pid"),
            "process_name": target.get("process_name"),
            "binary_path": target.get("binary_path") or target.get("executable"),
            "build_id": target.get("build_id"),
            "debug_image": target.get("debug_image"),
            "host": _norm_host(target.get("host") or target.get("remote_host")),
            "arch": arch or None,
        },
        "metrics": {
            "rss_kb": rss_kb,
            "rss_trend": _series_trend(rss_series),
            "heap_kb": heap_kb,
            "heap_kind": summary.get("heap_kind"),
            "threads": thread_count,
            "thread_states": dict(threads.get("states") or {}),
            "thread_roles": role_groups,
            "fds": fd_count,
            "fd_limit": fd_limit,
            "fd_trend": _series_trend(fd_series),
            "contended_locks": lock_contention_count,
            "containers": containers,
            "observation_window_s": _num(liveness.get("window_s")) or _num((prof.get("window") or {}).get("seconds")),
            "liveness_status": liveness.get("status"),
            "cpu_time_ms_delta": _num(liveness.get("cpu_time_ms_delta")),
            "voluntary_switches_delta": _int_or_none(liveness.get("voluntary_switches_delta")),
            "involuntary_switches_delta": _int_or_none(liveness.get("involuntary_switches_delta")),
            "total_switches_delta": _int_or_none(liveness.get("total_switches_delta")),
            "io_syscalls_delta": _int_or_none(liveness.get("io_syscalls_delta")),
        },
        "finding_categories": sorted({
            str(f.get("category")) for f in (res.get("findings") or [])
            if isinstance(f, dict) and f.get("category")
        }),
        "notable_ids": notable_ids,
    }


# ------------------------------------------------------------------ 3. Durable Atomic Persistence & Recovery
def _baselines_dir(corpus_dir: str) -> str:
    return os.path.join(corpus_dir, "baselines")


def _index_path(corpus_dir: str) -> str:
    return os.path.join(_baselines_dir(corpus_dir), "index.json")


def _lock_path(corpus_dir: str) -> str:
    return os.path.join(_baselines_dir(corpus_dir), ".index.lock")


@contextlib.contextmanager
def _index_lock(corpus_dir: str) -> Iterator[None]:
    bdir = _baselines_dir(corpus_dir)
    os.makedirs(bdir, exist_ok=True)
    lp = _lock_path(corpus_dir)
    fd = os.open(lp, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _atomic_write_json(path: str, payload: Any) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp_", suffix=".json", dir=parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, default=str)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, path)
    except Exception:
        try:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _entry_from_snapshot(snap: Dict[str, Any], path: str) -> Dict[str, Any]:
    tgt = snap.get("target") or {}
    return {
        "investigation_id": snap["investigation_id"],
        "path": path,
        "captured_at": snap.get("captured_at"),
        "captured_epoch": snap.get("captured_epoch") or 0.0,
        "verdict": snap.get("verdict"),
        "process_name": tgt.get("process_name"),
        "binary_path": tgt.get("binary_path"),
        "build_id": tgt.get("build_id"),
        "host": _norm_host(tgt.get("host")),
        "arch": tgt.get("arch"),
    }


def _rebuild_index(bdir: str) -> List[Dict[str, Any]]:
    """Scan valid ``*.baseline.json`` files to recover a corrupted or missing index."""
    entries: List[Dict[str, Any]] = []
    if not os.path.isdir(bdir):
        return entries
    for fname in os.listdir(bdir):
        if not fname.endswith(".baseline.json") or fname.startswith(".tmp_"):
            continue
        full = os.path.join(bdir, fname)
        if not os.path.isfile(full):
            continue
        try:
            with open(full, "r", encoding="utf-8") as fh:
                snap = json.loads(fh.read())
            if _validate_snapshot_record(snap):
                entries.append(_entry_from_snapshot(snap, full))
        except (OSError, ValueError):
            continue
    entries.sort(key=lambda e: float(e.get("captured_epoch") or 0.0))
    return entries


def _read_or_recover_index(corpus_dir: str) -> Tuple[List[Dict[str, Any]], bool]:
    """Read index.json; if corrupted/unreadable, recover by scanning valid snapshots."""
    idx_path = _index_path(corpus_dir)
    bdir = _baselines_dir(corpus_dir)
    if os.path.isfile(idx_path):
        try:
            with open(idx_path, "r", encoding="utf-8") as fh:
                raw = json.loads(fh.read())
            if isinstance(raw, list):
                valid = [e for e in raw if isinstance(e, dict) and sanitize_investigation_id(e.get("investigation_id"))]
                return valid, False
        except (OSError, ValueError):
            pass
        rebuilt = _rebuild_index(bdir)
        return rebuilt, True
    if os.path.isdir(bdir):
        rebuilt = _rebuild_index(bdir)
        if rebuilt:
            return rebuilt, True
    return [], False


def _safe_unlink_in_dir(path: str, bdir: str) -> None:
    try:
        real_dir = os.path.realpath(bdir)
        real_path = os.path.realpath(path)
        if real_path.startswith(real_dir + os.sep) and os.path.isfile(real_path):
            os.unlink(real_path)
    except OSError:
        pass


def save_diagnosis_baseline(
    corpus_dir: Optional[str],
    result: Dict[str, Any],
    profile: Optional[Dict[str, Any]] = None,
    notable_observations: Optional[List[Dict[str, Any]]] = None,
    *,
    max_entries: int = DEFAULT_MAX_BASELINES,
) -> Optional[str]:
    """Atomically persist a baseline snapshot with file locking and retention pruning."""
    if not corpus_dir:
        return None
    try:
        snap = extract_baseline_snapshot(result, profile, notable_observations)
        raw_id = snap.get("investigation_id")
        safe_id = sanitize_investigation_id(raw_id)
        if not safe_id:
            safe_id = f"diag_{int(time.time() * 1000)}_{os.getpid()}"
        snap["investigation_id"] = safe_id
        if not _validate_snapshot_record(snap):
            return None

        bdir = _baselines_dir(corpus_dir)
        path = os.path.join(bdir, f"{safe_id}.baseline.json")
        _atomic_write_json(path, snap)

        cap = max(1, int(max_entries))
        with _index_lock(corpus_dir):
            entries, _ = _read_or_recover_index(corpus_dir)
            entries = [e for e in entries if e.get("investigation_id") != safe_id]
            entries.append(_entry_from_snapshot(snap, path))
            if len(entries) > cap:
                evicted = entries[:-cap]
                entries = entries[-cap:]
                for old in evicted:
                    old_path = old.get("path") or os.path.join(bdir, f"{old.get('investigation_id')}.baseline.json")
                    _safe_unlink_in_dir(str(old_path), bdir)
            _atomic_write_json(_index_path(corpus_dir), entries)
        return path
    except Exception:  # noqa: BLE001 - baseline persistence must never fail diagnosis
        return None


def resolve_diagnosis_baseline(
    corpus_dir: Optional[str],
    selector: str,
    *,
    process_name: Optional[str] = None,
    binary_path: Optional[str] = None,
    build_id: Optional[str] = None,
    host: Optional[str] = None,
    arch: Optional[str] = None,
    exclude_investigation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Resolve a baseline snapshot with explicit identity compatibility evaluation."""
    curr_target = {
        "process_name": process_name,
        "binary_path": binary_path,
        "build_id": build_id,
        "host": _norm_host(host),
        "arch": arch,
    }
    if not selector or not str(selector).strip():
        return {"found": False, "baseline": None, "identity_match": None, "reason": "empty_selector", "prior_baselines": []}
    sel = str(selector).strip()

    if os.path.isfile(sel):
        try:
            with open(sel, "r", encoding="utf-8") as fh:
                data = json.loads(fh.read())
            if isinstance(data, dict):
                snap = data if _validate_snapshot_record(data) else (
                    extract_baseline_snapshot(data, data.get("process_profile"), data.get("notable_observations"))
                    if "target" in data else None
                )
                if not snap or not isinstance(snap.get("metrics"), dict):
                    return {"found": False, "baseline": None, "identity_match": None,
                            "reason": "incomplete_baseline_snapshot", "prior_baselines": []}
                id_match = evaluate_target_identity_match(curr_target, snap.get("target"))
                if id_match["status"] == "MISMATCH":
                    return {"found": False, "baseline": None, "identity_match": id_match,
                            "reason": f"target_identity_mismatch: {id_match['reason']}", "prior_baselines": []}
                return {"found": True, "baseline": snap, "identity_match": id_match,
                        "reason": "explicit_file", "prior_baselines": []}
        except (OSError, ValueError):
            return {"found": False, "baseline": None, "identity_match": None,
                    "reason": "unreadable_baseline_file", "prior_baselines": []}

    if not corpus_dir:
        return {"found": False, "baseline": None, "identity_match": None,
                "reason": "no_corpus_dir", "prior_baselines": []}

    bdir = _baselines_dir(corpus_dir)

    safe_sel = sanitize_investigation_id(sel)
    if safe_sel and sel.lower() not in ("latest", "latest_healthy", "auto"):
        direct = os.path.join(bdir, f"{safe_sel}.baseline.json")
        if os.path.isfile(direct):
            try:
                with open(direct, "r", encoding="utf-8") as fh:
                    data = json.loads(fh.read())
                if not _validate_snapshot_record(data):
                    return {"found": False, "baseline": None, "identity_match": None,
                            "reason": "incomplete_baseline_snapshot", "prior_baselines": []}
                id_match = evaluate_target_identity_match(curr_target, data.get("target"))
                if id_match["status"] == "MISMATCH":
                    return {"found": False, "baseline": None, "identity_match": id_match,
                            "reason": f"target_identity_mismatch: {id_match['reason']}", "prior_baselines": []}
                return {"found": True, "baseline": data, "identity_match": id_match,
                        "reason": "explicit_id", "prior_baselines": []}
            except (OSError, ValueError):
                return {"found": False, "baseline": None, "identity_match": None,
                        "reason": "unreadable_baseline_file", "prior_baselines": []}
        return {"found": False, "baseline": None, "identity_match": None,
                "reason": "baseline_id_not_found", "prior_baselines": []}

    try:
        with _index_lock(corpus_dir):
            entries, recovered = _read_or_recover_index(corpus_dir)
            if recovered and entries:
                try:
                    _atomic_write_json(_index_path(corpus_dir), entries)
                except OSError:
                    pass
    except OSError:
        entries, _ = _read_or_recover_index(corpus_dir)

    want_healthy = sel.lower() == "latest_healthy"
    matched_snaps: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
    rejected_weak_or_mismatch: Optional[Dict[str, Any]] = None

    for entry in reversed(entries):
        if not isinstance(entry, dict):
            continue
        eid = sanitize_investigation_id(entry.get("investigation_id"))
        if not eid:
            continue
        if exclude_investigation_id and eid == exclude_investigation_id:
            continue
        if want_healthy and entry.get("verdict") != "HEALTHY":
            continue
        id_match = evaluate_target_identity_match(curr_target, entry)
        if not id_match["auto_selectable"]:
            if rejected_weak_or_mismatch is None:
                rejected_weak_or_mismatch = id_match
            continue
        p = entry.get("path") or os.path.join(bdir, f"{eid}.baseline.json")
        if not os.path.isfile(p):
            continue
        try:
            with open(p, "r", encoding="utf-8") as fh:
                data = json.loads(fh.read())
            if not _validate_snapshot_record(data):
                continue
            snap_match = evaluate_target_identity_match(curr_target, data.get("target"))
            if not snap_match["auto_selectable"]:
                if rejected_weak_or_mismatch is None:
                    rejected_weak_or_mismatch = snap_match
                continue
            matched_snaps.append((data, snap_match))
            if len(matched_snaps) >= 3:
                break
        except (OSError, ValueError):
            continue

    if matched_snaps:
        primary, primary_match = matched_snaps[0]
        priors = [s for s, _ in matched_snaps[1:]]
        return {"found": True, "baseline": primary, "identity_match": primary_match,
                "reason": "auto_matched", "prior_baselines": priors}

    return {
        "found": False,
        "baseline": None,
        "identity_match": rejected_weak_or_mismatch,
        "reason": (f"no_compatible_baseline ({rejected_weak_or_mismatch['status']}: {rejected_weak_or_mismatch['reason']})"
                   if rejected_weak_or_mismatch else "no_matching_baseline"),
        "prior_baselines": [],
    }


def load_diagnosis_baseline(
    corpus_dir: Optional[str],
    selector: str,
    *,
    process_name: Optional[str] = None,
    binary_path: Optional[str] = None,
    build_id: Optional[str] = None,
    host: Optional[str] = None,
    arch: Optional[str] = None,
    exclude_investigation_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Backward-compatible wrapper returning the resolved baseline dict or None."""
    res = resolve_diagnosis_baseline(
        corpus_dir, selector, process_name=process_name, binary_path=binary_path,
        build_id=build_id, host=host, arch=arch, exclude_investigation_id=exclude_investigation_id,
    )
    return res["baseline"] if res.get("found") else None


# ------------------------------------------------------------------ 4. Rich Baseline Intelligence Diff
def _metric_delta(
    name: str,
    unit: str,
    prev: Optional[float],
    curr: Optional[float],
    *,
    drift_pct: float = 15.0,
    regression_pct: float = 35.0,
    min_abs: float = 1.0,
) -> Optional[Dict[str, Any]]:
    if prev is None or curr is None:
        return None
    delta = curr - prev
    pct = (delta / prev * 100.0) if prev > 0 else (100.0 if delta > 0 else 0.0)
    status = "stable"
    if abs(delta) >= min_abs:
        if delta > 0 and pct >= regression_pct:
            status = "regression"
        elif delta > 0 and pct >= drift_pct:
            status = "drift"
        elif delta < 0 and abs(pct) >= drift_pct:
            status = "improved"
    return {
        "metric": name,
        "unit": unit,
        "baseline": round(prev, 2) if isinstance(prev, float) and not prev.is_integer() else int(prev),
        "current": round(curr, 2) if isinstance(curr, float) and not curr.is_integer() else int(curr),
        "delta": round(delta, 2) if isinstance(delta, float) and not delta.is_integer() else int(delta),
        "delta_pct": round(pct, 1),
        "status": status,
    }


def _has_sustained_growth(
    metric_key: str,
    trend_key: Optional[str],
    curr_metrics: Dict[str, Any],
    base_metrics: Dict[str, Any],
    prior_baselines: Optional[List[Dict[str, Any]]] = None,
) -> Tuple[bool, str]:
    """Determine whether positive growth is corroborated as sustained vs a single-point spike."""
    if trend_key and curr_metrics.get(trend_key) == "rising":
        return True, "in_window_rising_trend"
    c_val = _num(curr_metrics.get(metric_key))
    b_val = _num(base_metrics.get(metric_key))
    if c_val is not None and b_val is not None and c_val > b_val and prior_baselines:
        for p in prior_baselines:
            pm = (p.get("metrics") or {}) if isinstance(p, dict) else {}
            p_val = _num(pm.get(metric_key))
            if p_val is not None and b_val > p_val:
                return True, "multi_snapshot_repeated_growth"
    return False, "single_point_elevation"


def compare_diagnosis_baseline(
    current_snapshot: Dict[str, Any],
    baseline_snapshot: Dict[str, Any],
    *,
    identity_match: Optional[Dict[str, Any]] = None,
    prior_baselines: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """Compare current diagnosis snapshot against a prior baseline snapshot."""
    id_match = identity_match or evaluate_target_identity_match(
        current_snapshot.get("target"), baseline_snapshot.get("target")
    )
    if id_match.get("status") == "MISMATCH":
        return {
            "available": False,
            "reason": f"target_identity_mismatch: {id_match.get('reason')}",
            "identity_match": id_match,
        }

    cm = current_snapshot.get("metrics") or {}
    bm = baseline_snapshot.get("metrics") or {}

    metric_rows: List[Dict[str, Any]] = []
    specs: List[Tuple[str, str, str, Optional[str], float, float, float]] = [
        ("rss_kb", "KB", "rss_kb", "rss_trend", 15.0, 35.0, 1024.0),
        ("heap_kb", "KB", "heap_kb", None, 15.0, 35.0, 512.0),
        ("threads", "count", "threads", None, 20.0, 50.0, 2.0),
        ("fds", "count", "fds", "fd_trend", 20.0, 50.0, 4.0),
        ("contended_locks", "count", "contended_locks", None, 50.0, 100.0, 1.0),
    ]
    sustained_regressions: List[str] = []
    single_point_spikes: List[str] = []

    for label, unit, key, trend_k, dp, rp, mabs in specs:
        row = _metric_delta(label, unit, _num(bm.get(key)), _num(cm.get(key)),
                            drift_pct=dp, regression_pct=rp, min_abs=mabs)
        if row is not None:
            if row["status"] == "regression" and key in ("rss_kb", "heap_kb", "fds"):
                sustained, basis = _has_sustained_growth(key, trend_k, cm, bm, prior_baselines)
                row["growth_basis"] = basis
                if sustained:
                    sustained_regressions.append(label)
                else:
                    row["status"] = "drift"
                    row["single_point_spike"] = True
                    single_point_spikes.append(label)
            elif row["status"] == "regression":
                sustained_regressions.append(label)
            metric_rows.append(row)

    activity_diffs: List[Dict[str, Any]] = []
    for a_key, a_unit, mabs in (
        ("cpu_time_ms_delta", "ms", 10.0),
        ("total_switches_delta", "count", 10.0),
        ("io_syscalls_delta", "count", 5.0),
    ):
        arow = _metric_delta(a_key, a_unit, _num(bm.get(a_key)), _num(cm.get(a_key)),
                             drift_pct=30.0, regression_pct=100.0, min_abs=mabs)
        if arow is not None:
            activity_diffs.append(arow)

    liveness_transition = None
    b_liv, c_liv = bm.get("liveness_status"), cm.get("liveness_status")
    if b_liv and c_liv and b_liv != c_liv:
        liveness_transition = {"baseline": b_liv, "current": c_liv}

    b_roles = bm.get("thread_roles") if isinstance(bm.get("thread_roles"), dict) else {}
    c_roles = cm.get("thread_roles") if isinstance(cm.get("thread_roles"), dict) else {}
    thread_role_diffs: List[Dict[str, Any]] = []
    for rkey in sorted(set(b_roles) | set(c_roles)):
        br = b_roles.get(rkey)
        cr = c_roles.get(rkey)
        bc = int(br.get("count") or 0) if isinstance(br, dict) else 0
        cc = int(cr.get("count") or 0) if isinstance(cr, dict) else 0
        if bc != cc:
            role_name = (cr or br or {}).get("role") or rkey.split(":", 1)[0]
            state_name = (cr or br or {}).get("state") or (rkey.split(":", 1)[1] if ":" in rkey else "unknown")
            change = "added" if bc == 0 else ("removed" if cc == 0 else "changed")
            thread_role_diffs.append({
                "role": role_name, "state": state_name,
                "baseline_count": bc, "current_count": cc, "delta": cc - bc, "change": change,
            })

    b_cont = bm.get("containers") if isinstance(bm.get("containers"), dict) else {}
    c_cont = cm.get("containers") if isinstance(cm.get("containers"), dict) else {}
    added_containers = [{"variable": v, "current": int(c_cont[v])} for v in sorted(set(c_cont) - set(b_cont))]
    removed_containers = [{"variable": v, "baseline": int(b_cont[v])} for v in sorted(set(b_cont) - set(c_cont))]
    container_diffs: List[Dict[str, Any]] = []
    for var in sorted(set(b_cont) & set(c_cont)):
        row = _metric_delta(var, "elements", _num(b_cont[var]), _num(c_cont[var]),
                            drift_pct=20.0, regression_pct=50.0, min_abs=10.0)
        if row is not None:
            container_diffs.append(row)

    b_notable = set(baseline_snapshot.get("notable_ids") or [])
    c_notable = set(current_snapshot.get("notable_ids") or [])
    new_notable = sorted(c_notable - b_notable)
    resolved_notable = sorted(b_notable - c_notable)

    b_findings = set(baseline_snapshot.get("finding_categories") or [])
    c_findings = set(current_snapshot.get("finding_categories") or [])
    new_findings = sorted(c_findings - b_findings)
    recurring_findings = sorted(c_findings & b_findings)
    resolved_findings = sorted(b_findings - c_findings)

    all_statuses = [r["status"] for r in metric_rows + container_diffs]
    has_container_reg = any(r["status"] == "regression" for r in container_diffs)
    if new_findings or recurring_findings or sustained_regressions or has_container_reg:
        reg_status = "REGRESSION"
    elif (new_notable or "drift" in all_statuses or single_point_spikes
          or added_containers or removed_containers or thread_role_diffs or liveness_transition):
        reg_status = "DRIFT"
    elif resolved_findings or (resolved_notable and not new_notable) or (
        "improved" in all_statuses and "drift" not in all_statuses
    ):
        reg_status = "IMPROVED"
    else:
        reg_status = "STABLE"

    b_id = baseline_snapshot.get("investigation_id") or "baseline"
    b_at = baseline_snapshot.get("captured_at") or ""
    b_verdict = baseline_snapshot.get("verdict") or "UNKNOWN"

    highlights_en: List[str] = []
    highlights_ko: List[str] = []
    for r in metric_rows:
        if r["delta"] == 0:
            continue
        sign = "+" if r["delta"] > 0 else ""
        spike_en = " (single-point spike)" if r.get("single_point_spike") else ""
        spike_ko = " (단발 급증)" if r.get("single_point_spike") else ""
        highlights_en.append(f"{r['metric']}: {r['baseline']} -> {r['current']} {r['unit']} ({sign}{r['delta_pct']}%){spike_en}")
        highlights_ko.append(f"{r['metric']}: {r['baseline']} -> {r['current']} {r['unit']} ({sign}{r['delta_pct']}%){spike_ko}")
    if liveness_transition:
        highlights_en.append(f"liveness {liveness_transition['baseline']} -> {liveness_transition['current']}")
        highlights_ko.append(f"활동성 {liveness_transition['baseline']} -> {liveness_transition['current']}")
    if recurring_findings:
        highlights_en.append(f"recurring findings: {', '.join(recurring_findings)}")
        highlights_ko.append(f"재발 결함: {', '.join(recurring_findings)}")
    if new_notable:
        highlights_en.append(f"new watchlist items: {', '.join(new_notable)}")
        highlights_ko.append(f"신규 주의 관찰 항목: {', '.join(new_notable)}")
    if resolved_notable:
        highlights_en.append(f"resolved watchlist items: {', '.join(resolved_notable)}")
        highlights_ko.append(f"해소된 주의 관찰 항목: {', '.join(resolved_notable)}")

    summary_en = (
        f"Compared with baseline {b_id} ({b_verdict}, match {id_match['status']}): {reg_status}"
        + (f" — {'; '.join(highlights_en[:3])}" if highlights_en else " — all tracked metrics unchanged")
    )
    ko_status = {
        "REGRESSION": "회귀 감지",
        "DRIFT": "변화(드리프트) 관측",
        "IMPROVED": "개선됨",
        "STABLE": "안정(변화 없음)",
    }.get(reg_status, reg_status)
    summary_ko = (
        f"기준선 {b_id} ({b_verdict}, 일치도 {id_match['status']}) 대비 {ko_status}"
        + (f" — {'; '.join(highlights_ko[:3])}" if highlights_ko else " — 주요 지표 변화 없음")
    )

    return {
        "available": True,
        "identity_match": id_match,
        "baseline_investigation_id": b_id,
        "baseline_captured_at": b_at,
        "baseline_verdict": b_verdict,
        "regression_status": reg_status,
        "sustained_regressions": sustained_regressions,
        "single_point_spikes": single_point_spikes,
        "metrics": metric_rows,
        "activity_diffs": activity_diffs,
        "liveness_transition": liveness_transition,
        "thread_role_diffs": thread_role_diffs,
        "containers": container_diffs,
        "added_containers": added_containers,
        "removed_containers": removed_containers,
        "new_findings": new_findings,
        "recurring_findings": recurring_findings,
        "resolved_findings": resolved_findings,
        "new_notable": new_notable,
        "resolved_notable": resolved_notable,
        "summary_en": summary_en,
        "summary_ko": summary_ko,
    }

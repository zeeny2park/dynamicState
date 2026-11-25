"""Diagnosis baseline persistence and regression diffing.

Saves lightweight, deterministic snapshots of each completed ``diagnose`` run
(``process_profile`` metrics, liveness summary, and notable observations) under
``<corpus_dir>/baselines/`` so future diagnoses can compare against a previous
snapshot (``compare_baseline="latest" | "latest_healthy" | "<id>" | "<path>"``)
instead of concluding only "no fault at this single point in time".
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional, Tuple

BASELINE_SCHEMA_VERSION = "1.0"


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
    heap_kb = _int_or_none(summary.get("heap_kb"))
    thread_count = _int_or_none(summary.get("threads"))
    if thread_count is None and isinstance(threads.get("count"), dict):
        thread_count = _int_or_none(threads["count"].get("v"))
    fd_count = _int_or_none(summary.get("fds"))
    if fd_count is None and isinstance(resources.get("fds"), dict):
        fd_count = _int_or_none(resources["fds"].get("v"))
    fd_limit = _int_or_none((resources.get("fd_limit") or {}).get("v") if isinstance(resources.get("fd_limit"), dict) else resources.get("fd_limit"))

    containers: Dict[str, int] = {}
    for c in (mem.get("containers") or []):
        if isinstance(c, dict) and c.get("variable") and _int_or_none(c.get("size")) is not None:
            containers[str(c["variable"])] = int(c["size"])

    lock_contention_count = 0
    for lk in (locks.get("items") or []):
        if isinstance(lk, dict) and (_int_or_none(lk.get("samples_queued")) or 0) > 0:
            lock_contention_count += 1

    notable_ids = sorted({
        str(n.get("id") or n.get("category") or "")
        for n in (notable_observations or [])
        if isinstance(n, dict) and (n.get("id") or n.get("category"))
    })

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
            "host": target.get("host") or target.get("remote_host"),
        },
        "metrics": {
            "rss_kb": rss_kb,
            "heap_kb": heap_kb,
            "heap_kind": summary.get("heap_kind"),
            "threads": thread_count,
            "thread_states": dict(threads.get("states") or {}),
            "fds": fd_count,
            "fd_limit": fd_limit,
            "contended_locks": lock_contention_count,
            "containers": containers,
            "liveness_status": liveness.get("status"),
            "cpu_time_ms_delta": _num(liveness.get("cpu_time_ms_delta")),
            "total_switches_delta": _int_or_none(liveness.get("total_switches_delta")),
            "io_syscalls_delta": _int_or_none(liveness.get("io_syscalls_delta")),
        },
        "finding_categories": sorted({
            str(f.get("category")) for f in (res.get("findings") or [])
            if isinstance(f, dict) and f.get("category")
        }),
        "notable_ids": notable_ids,
    }


def _baselines_dir(corpus_dir: str) -> str:
    return os.path.join(corpus_dir, "baselines")


def _index_path(corpus_dir: str) -> str:
    return os.path.join(_baselines_dir(corpus_dir), "index.json")


def save_diagnosis_baseline(
    corpus_dir: Optional[str],
    result: Dict[str, Any],
    profile: Optional[Dict[str, Any]] = None,
    notable_observations: Optional[List[Dict[str, Any]]] = None,
) -> Optional[str]:
    """Persist a baseline snapshot to ``<corpus_dir>/baselines/`` and update index.json."""
    if not corpus_dir:
        return None
    snap = extract_baseline_snapshot(result, profile, notable_observations)
    inv_id = str(snap.get("investigation_id") or f"diag_{int(time.time() * 1000)}")
    snap["investigation_id"] = inv_id
    bdir = _baselines_dir(corpus_dir)
    try:
        os.makedirs(bdir, exist_ok=True)
        path = os.path.join(bdir, f"{inv_id}.baseline.json")
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(snap, fh, indent=2, default=str)
        idx_path = _index_path(corpus_dir)
        entries: List[Dict[str, Any]] = []
        if os.path.isfile(idx_path):
            try:
                with open(idx_path, "r", encoding="utf-8") as _fh:
                    raw = json.loads(_fh.read())
                if isinstance(raw, list):
                    entries = [e for e in raw if isinstance(e, dict)]
            except (OSError, ValueError):
                entries = []
        entries = [e for e in entries if e.get("investigation_id") != inv_id]
        entries.append({
            "investigation_id": inv_id,
            "path": path,
            "captured_at": snap["captured_at"],
            "captured_epoch": snap["captured_epoch"],
            "verdict": snap["verdict"],
            "process_name": snap["target"].get("process_name"),
            "binary_path": snap["target"].get("binary_path"),
            "build_id": snap["target"].get("build_id"),
            "host": snap["target"].get("host"),
        })
        # Keep the 200 most recent entries bounded on disk
        entries = entries[-200:]
        with open(idx_path, "w", encoding="utf-8") as fh:
            json.dump(entries, fh, indent=2)
        return path
    except OSError:
        return None


def _matches_target(
    entry: Dict[str, Any],
    *,
    process_name: Optional[str] = None,
    binary_path: Optional[str] = None,
    build_id: Optional[str] = None,
    host: Optional[str] = None,
) -> bool:
    if host and entry.get("host") and entry.get("host") != host:
        return False
    if build_id and entry.get("build_id"):
        return entry.get("build_id") == build_id
    if binary_path and entry.get("binary_path"):
        return entry.get("binary_path") == binary_path
    if process_name and entry.get("process_name"):
        return entry.get("process_name") == process_name
    return True


def load_diagnosis_baseline(
    corpus_dir: Optional[str],
    selector: str,
    *,
    process_name: Optional[str] = None,
    binary_path: Optional[str] = None,
    build_id: Optional[str] = None,
    host: Optional[str] = None,
    exclude_investigation_id: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Load a baseline snapshot by ``"latest"``, ``"latest_healthy"``, investigation ID, or file path."""
    if not selector or not str(selector).strip():
        return None
    sel = str(selector).strip()
    # Direct file path
    if os.path.isfile(sel):
        try:
            with open(sel, "r", encoding="utf-8") as _fh:
                data = json.loads(_fh.read())
            if isinstance(data, dict):
                if "metrics" in data:
                    return data
                # Allow passing a full DiagnoseResult or report JSON directly
                return extract_baseline_snapshot(data, data.get("process_profile"), data.get("notable_observations"))
        except (OSError, ValueError):
            return None

    if not corpus_dir:
        return None
    bdir = _baselines_dir(corpus_dir)
    direct = os.path.join(bdir, f"{sel}.baseline.json")
    if os.path.isfile(direct):
        try:
            with open(direct, "r", encoding="utf-8") as _fh:
                data = json.loads(_fh.read())
            return data if isinstance(data, dict) else None
        except (OSError, ValueError):
            return None

    idx_path = _index_path(corpus_dir)
    if not os.path.isfile(idx_path):
        return None
    try:
        with open(idx_path, "r", encoding="utf-8") as _fh:
            entries = json.loads(_fh.read())
    except (OSError, ValueError):
        return None
    if not isinstance(entries, list):
        return None

    want_healthy = sel.lower() == "latest_healthy"
    want_latest = sel.lower() in ("latest", "latest_healthy", "auto")
    for entry in reversed(entries):
        if not isinstance(entry, dict):
            continue
        eid = entry.get("investigation_id")
        if exclude_investigation_id and eid == exclude_investigation_id:
            continue
        if not want_latest:
            if eid != sel:
                continue
        else:
            if want_healthy and entry.get("verdict") != "HEALTHY":
                continue
            if not _matches_target(entry, process_name=process_name, binary_path=binary_path,
                                   build_id=build_id, host=host):
                continue
        p = entry.get("path") or os.path.join(bdir, f"{eid}.baseline.json")
        if os.path.isfile(p):
            try:
                with open(p, "r", encoding="utf-8") as _fh:
                    data = json.loads(_fh.read())
                if isinstance(data, dict):
                    return data
            except (OSError, ValueError):
                continue
    return None


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


def compare_diagnosis_baseline(
    current_snapshot: Dict[str, Any],
    baseline_snapshot: Dict[str, Any],
) -> Dict[str, Any]:
    """Compare current diagnosis snapshot against a prior baseline snapshot."""
    cm = current_snapshot.get("metrics") or {}
    bm = baseline_snapshot.get("metrics") or {}

    metric_rows: List[Dict[str, Any]] = []
    specs: List[Tuple[str, str, str, float, float, float]] = [
        ("rss_kb", "KB", "rss_kb", 15.0, 35.0, 1024.0),
        ("heap_kb", "KB", "heap_kb", 15.0, 35.0, 512.0),
        ("threads", "count", "threads", 20.0, 50.0, 2.0),
        ("fds", "count", "fds", 20.0, 50.0, 4.0),
        ("contended_locks", "count", "contended_locks", 50.0, 100.0, 1.0),
    ]
    for label, unit, key, dp, rp, mabs in specs:
        row = _metric_delta(label, unit, _num(bm.get(key)), _num(cm.get(key)),
                            drift_pct=dp, regression_pct=rp, min_abs=mabs)
        if row is not None:
            metric_rows.append(row)

    # Container size diffs
    b_cont = bm.get("containers") or {}
    c_cont = cm.get("containers") or {}
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
    resolved_findings = sorted(b_findings - c_findings)

    all_statuses = [r["status"] for r in metric_rows + container_diffs]
    if new_findings or "regression" in all_statuses:
        reg_status = "REGRESSION"
    elif new_notable or "drift" in all_statuses:
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
        highlights_en.append(f"{r['metric']}: {r['baseline']} -> {r['current']} {r['unit']} ({sign}{r['delta_pct']}%)")
        highlights_ko.append(f"{r['metric']}: {r['baseline']} -> {r['current']} {r['unit']} ({sign}{r['delta_pct']}%)")
    if new_notable:
        highlights_en.append(f"new watchlist items: {', '.join(new_notable)}")
        highlights_ko.append(f"신규 주의 관찰 항목: {', '.join(new_notable)}")
    if resolved_notable:
        highlights_en.append(f"resolved watchlist items: {', '.join(resolved_notable)}")
        highlights_ko.append(f"해소된 주의 관찰 항목: {', '.join(resolved_notable)}")

    summary_en = (
        f"Compared with baseline {b_id} ({b_verdict}): {reg_status}"
        + (f" — {'; '.join(highlights_en[:3])}" if highlights_en else " — all tracked metrics unchanged")
    )
    ko_status = {
        "REGRESSION": "회귀 감지",
        "DRIFT": "변화(드리프트) 관측",
        "IMPROVED": "개선됨",
        "STABLE": "안정(변화 없음)",
    }.get(reg_status, reg_status)
    summary_ko = (
        f"기준선 {b_id} ({b_verdict}) 대비 {ko_status}"
        + (f" — {'; '.join(highlights_ko[:3])}" if highlights_ko else " — 주요 지표 변화 없음")
    )

    return {
        "available": True,
        "baseline_investigation_id": b_id,
        "baseline_captured_at": b_at,
        "baseline_verdict": b_verdict,
        "regression_status": reg_status,
        "metrics": metric_rows,
        "containers": container_diffs,
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "new_notable": new_notable,
        "resolved_notable": resolved_notable,
        "summary_en": summary_en,
        "summary_ko": summary_ko,
    }

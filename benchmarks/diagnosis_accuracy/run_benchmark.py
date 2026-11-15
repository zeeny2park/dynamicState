#!/usr/bin/env python3
"""IMP-013: ground-truth accuracy benchmark for ``diagnose`` on real processes.

For each target (ground_truth/<id>.json + a C source): build with gcc -g -O0 -pthread, launch, wait for the
target to reach its steady state, call ``diagnose(pid, debug_image, symptom)`` exactly once with the symptom
text from the ground-truth file, kill the target, and score the returned dict against the ground truth.

The scorer never sees confidence and never tunes anything: a low score is a valid result.
Exit status is non-zero only if the runner itself crashes; a low score never fails the run.
"""

import argparse
import datetime
import glob
import hashlib
import json
import math
import os
import platform
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple


HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)
from tests.support.fixture_process import FixtureLimitExceeded, FixtureProcess, fixture_popen  # noqa: E402

GT_DIR = os.path.join(HERE, "ground_truth")
# Held-out suite (stage 3 validation): programs written after the static-candidate heuristics, in other styles
# (C++, multi-file, wrappers, function pointers, macros, -O2). Own manifest directory, run only with
# --suite heldout and reported in its own results file; it never enters the main suite's totals.
HELDOUT_GT_DIR = os.path.join(HERE, "heldout", "ground_truth")
SUITES = {"main": GT_DIR, "heldout": HELDOUT_GT_DIR}
RESULTS_DIR = os.path.join(HERE, "results")

SCHEMA_VERSION = 2
LINE_TOLERANCE = 3
READY_TIMEOUT_S = 20.0
DIAGNOSE_TIMEOUT_S = 90.0

# ---------------------------------------------------------------------------------------------------------
# The single place that defines what counts as "the diagnoser named this kind of defect".
# A finding matches a defect kind only if its `category` is listed here for that kind.
# ---------------------------------------------------------------------------------------------------------
KIND_CATEGORIES: Dict[str, frozenset] = {
    "memory_leak": frozenset({"MEMORY_LEAK"}),
    "heap_overflow": frozenset({"MEMORY_CORRUPTION"}),
    "use_after_free": frozenset({"USE_AFTER_FREE"}),
    "double_free": frozenset({"INVALID_DOUBLE_FREE"}),
    "deadlock": frozenset({"DEADLOCK_INDICATORS"}),
    "busy_wait": frozenset({"PROCESS_INSTABILITY", "RESOURCE_EXHAUSTION"}),
    "thread_growth": frozenset({"THREAD_LEAK"}),
    "long_stall": frozenset({"PROCESS_INSTABILITY"}),
    "mapping_growth": frozenset({"MAPPING_GROWTH"}),   # memory growth outside malloc (mmap, custom pool)
    "heap_retention": frozenset({"HEAP_RETENTION"}),   # fragmentation: a degradation, its targets are unscored
    "lock_contention": frozenset({"LOCK_CONTENTION"}),  # a degradation: its targets are unscored
    "orphan_lock": frozenset({"ORPHAN_LOCK"}),
    "self_deadlock": frozenset({"SELF_DEADLOCK"}),
}
# `long_stall`, `heap_retention` and `lock_contention` stay here only so unscored rows can be labelled and described; they never
# enter a total.
DEFECT_KINDS = tuple(KIND_CATEGORIES)
# A ground-truth record may carry "scored": false (+ "scored_reason"). Such targets are still built, run and
# printed, but are excluded from every detection / cause-name / location / false-positive total and rate.
HEALTHY_KIND = "none"
FAULT_VERDICTS = frozenset({"CONFIRMED_FAULT", "PROBABLE_FAULT", "FAULT"})
CLEARED_VERDICTS = frozenset({"HEALTHY"})
NAME_CLASSES = ("variables", "locks", "threads", "functions")
PRIMARY_CLASSES = ("variables", "locks", "threads")  # functions count as primary only if nothing else is declared
ORIGINS = ("project_fixture", "external_style", "new")

GT_REQUIRED = ("id", "origin", "naming", "kind", "source", "language", "symptom", "ready", "causes",
               "locations", "notes")


# ------------------------------------------------------------------------------------------------ loading
def load_ground_truth(gt_dir: str = GT_DIR) -> List[Dict[str, Any]]:
    out = []
    for path in sorted(glob.glob(os.path.join(gt_dir, "*.json"))):
        with open(path, encoding="utf-8") as fh:
            out.append(json.load(fh))
    return out


def validate_ground_truth(gt: Dict[str, Any], repo_root: str = REPO_ROOT) -> List[str]:
    """Return a list of schema problems (empty if the file is well formed)."""
    errs = []
    for key in GT_REQUIRED:
        if key not in gt:
            errs.append(f"missing key {key}")
    if errs:
        return errs
    if "scored" in gt:
        if not isinstance(gt["scored"], bool):
            errs.append("scored must be a boolean")
        elif gt["scored"] is False and not str(gt.get("scored_reason", "")).strip():
            errs.append("unscored target needs a scored_reason")
        elif gt["scored"] is False and gt["kind"] == HEALTHY_KIND:
            errs.append("a healthy control cannot be unscored")
    if gt["kind"] != HEALTHY_KIND and gt["kind"] not in KIND_CATEGORIES:
        errs.append(f"unknown kind {gt['kind']}")
    if gt["origin"] not in ORIGINS:
        errs.append(f"unknown origin {gt['origin']}")
    if gt["naming"] not in ("neutral", "project"):
        errs.append(f"unknown naming {gt['naming']}")
    if gt["ready"].get("mode") not in ("stdout_marker", "settle"):
        errs.append("ready.mode must be stdout_marker or settle")
    if not str(gt["symptom"]).strip():
        errs.append("empty symptom")
    if set(gt["causes"]) != set(NAME_CLASSES):
        errs.append(f"causes must have exactly {NAME_CLASSES}")
    elif not all(isinstance(gt["causes"][c], list) and all(isinstance(x, str) for x in gt["causes"][c])
                 for c in NAME_CLASSES):
        errs.append("causes values must be lists of strings")
    src = os.path.join(repo_root, gt["source"])
    if not os.path.isfile(src):
        errs.append(f"source not found: {gt['source']}")
        return errs
    sources = source_files(gt)
    if gt["source"] not in sources:
        errs.append("sources must include source")
    for extra in sources:
        if not os.path.isfile(os.path.join(repo_root, extra)):
            errs.append(f"source not found: {extra}")
    if errs:
        return errs
    b = gt.get("build")
    if b is not None:
        if (not isinstance(b, dict) or b.get("compiler") not in ("gcc", "g++")
                or b.get("opt") not in ("-O0", "-O1", "-O2", "-O3", "-Os")):
            errs.append("build needs compiler gcc|g++ and opt -O0..-O3|-Os")
        elif not isinstance(b.get("flags", []), list):
            errs.append("build.flags must be a list")
    if gt["kind"] == HEALTHY_KIND:
        if gt["locations"] or any(gt["causes"][c] for c in NAME_CLASSES):
            errs.append("healthy control must have no causes and no locations")
    else:
        if not gt["locations"]:
            errs.append("defect target needs at least one location")
        if not any(gt["causes"][c] for c in NAME_CLASSES):
            errs.append("defect target needs at least one cause name")
        for loc in gt["locations"]:
            if loc.get("file") not in sources:
                errs.append(f"location file {loc.get('file')} is not one of the sources")
                continue
            lines = open(os.path.join(repo_root, loc["file"]), encoding="utf-8").read().splitlines()
            ln = loc.get("line")
            if not isinstance(ln, int) or not (1 <= ln <= len(lines)):
                errs.append(f"bad line {ln}")
            elif loc.get("text") not in lines[ln - 1]:
                errs.append(f"line {ln} does not contain {loc.get('text')!r}")
    if gt["origin"] == "project_fixture" and not gt["source"].startswith("tests/fixtures/real_runtime/"):
        errs.append("project_fixture must reference tests/fixtures/real_runtime")
    if gt["origin"] != "project_fixture":
        text = "\n".join(_with_headers(repo_root, sources)).lower()
        text = text.replace("lock_guard", "")  # the C++ standard library's name, not an announcing word
        for banned in ("leak", "overflow", "canary", "guard", "deadbeef", "uaf", "dangling"):
            if banned in text:
                errs.append(f"source contains announcing word {banned!r}")
    return errs


def source_files(gt: Dict[str, Any]) -> List[str]:
    """Translation units of a target (repository-relative): ``sources`` when given (multi-file targets), else
    the single ``source``."""
    return list(gt.get("sources") or [gt["source"]])


def _with_headers(repo_root: str, sources: List[str]) -> List[str]:
    """Text of the sources and of the local headers next to them (for the announcing-word check)."""
    out, seen = [], set()
    for s in sources:
        d = os.path.dirname(os.path.join(repo_root, s))
        for p in [os.path.join(repo_root, s)] + sorted(glob.glob(os.path.join(d, "*.h"))):
            if p not in seen and os.path.isfile(p):
                seen.add(p)
                out.append(open(p, encoding="utf-8").read())
    return out


# ------------------------------------------------------------------------------------------------ scoring
def is_scored(gt: Dict[str, Any]) -> bool:
    return gt.get("scored", True) is not False


def _file_line_subjects(subjects: List[str]) -> List[tuple]:
    out = []
    for s in subjects:
        m = re.match(r"^(.*):(\d+)$", str(s))
        if m:
            out.append((os.path.basename(m.group(1)), int(m.group(2))))
    return out


def score_result(gt: Dict[str, Any], result: Optional[Dict[str, Any]], error: Optional[str] = None) -> Dict[str, Any]:
    """Score one ``DiagnoseResult.to_dict()`` against one ground-truth record. Pure function."""
    row: Dict[str, Any] = {"id": gt["id"], "kind": gt["kind"], "origin": gt["origin"], "naming": gt["naming"],
                           "scored": is_scored(gt)}
    if not row["scored"]:
        row["scored_reason"] = gt.get("scored_reason", "")
    if result is None:
        row.update(error=error or "no result", verdict=None, finding_categories=[], subjects=[],
                   not_covered_kinds=[], capture_mode=None, measured_stop_ms=None, non_zero_stop=None)
        if gt["kind"] == HEALTHY_KIND:
            row.update(false_positive=False, not_cleared=False, cleared=False)
        else:
            row.update(detected=False, name_match="none", location_match=False, false_clear=False,
                       location_candidate_rank=None, location_candidate_hit=False,
                       location_candidates_shown=False, location_candidate_wrong=False)
        return row

    findings = list(result.get("findings") or [])
    impact = result.get("collection_impact") or {}
    verdict = result.get("verdict")
    raw_confidence = result.get("confidence")
    confidence = (float(raw_confidence) if isinstance(raw_confidence, (int, float))
                  and not isinstance(raw_confidence, bool) and math.isfinite(float(raw_confidence))
                  and 0.0 <= float(raw_confidence) <= 1.0 else None)
    decisive_verdict = verdict in FAULT_VERDICTS or verdict in CLEARED_VERDICTS
    row["verdict_confidence"] = confidence
    row["verdict_confidence_correct"] = (
        (verdict in FAULT_VERDICTS) == (gt["kind"] != HEALTHY_KIND) if decisive_verdict else None
    )
    all_subjects = [s for f in findings for s in (f.get("subjects") or [])]
    mode = impact.get("capture_mode")
    stop_ms = impact.get("measured_stop_ms")
    row.update(
        verdict=verdict,
        finding_categories=[str(f.get("category")) for f in findings],
        finding_status=[f.get("status") for f in findings],
        subjects=all_subjects,
        not_covered_kinds=sorted({str(n.get("kind")) for n in (result.get("not_covered") or [])}),
        capture_mode=mode,
        measured_stop_ms=stop_ms,
        non_zero_stop=bool((impact.get("zero_stop") is False) or (stop_ms or 0) > 0
                           or "ZERO_STOP" not in str(mode)),
    )

    if gt["kind"] == HEALTHY_KIND:
        fp = verdict in FAULT_VERDICTS or bool(findings)
        row.update(false_positive=fp, cleared=(not fp and verdict in CLEARED_VERDICTS),
                   not_cleared=(not fp and verdict not in CLEARED_VERDICTS))
        return row

    cats = KIND_CATEGORIES[gt["kind"]]
    matching = [f for f in findings if str(f.get("category")) in cats]
    row["detected"] = bool(matching)
    row["false_clear"] = verdict == "HEALTHY"  # told "nothing is wrong" about a real defect
    subj = {s for f in matching for s in (f.get("subjects") or [])}
    by_class = {}
    for cls in NAME_CLASSES:
        exp = gt["causes"][cls]
        by_class[cls] = {"expected": exp, "found": [n for n in exp if n in subj]}
    row["names_by_class"] = by_class
    primary = [c for c in PRIMARY_CLASSES if gt["causes"][c]] or ["functions"]
    p_exp = sum(len(gt["causes"][c]) for c in primary)
    p_found = sum(len(by_class[c]["found"]) for c in primary)
    any_found = sum(len(v["found"]) for v in by_class.values())
    if matching and p_exp and p_found == p_exp:
        row["name_match"] = "full"
    elif matching and any_found:
        row["name_match"] = "partial"
    else:
        row["name_match"] = "none"
    fl = _file_line_subjects(sorted(subj))
    row["location_match"] = bool(matching) and any(
        os.path.basename(loc["file"]) == f and abs(loc["line"] - ln) <= LINE_TOLERANCE
        for loc in gt["locations"] for f, ln in fl)
    # Static location candidates (findings[].location_candidates): statically derived, never observed. Scored
    # separately from `location_match` (which counts only subjects, i.e. what the diagnosis observed / named):
    # the best (lowest) rank among the matching findings' candidates that lies within the same tolerance.
    row["location_candidate_rank"] = candidate_rank(gt, matching)
    row["location_candidate_hit"] = row["location_candidate_rank"] is not None
    # A candidate list that is shown but does not contain the true location misleads the reader (worse than none).
    row["location_candidates_shown"] = candidates_shown(matching)
    row["location_candidate_wrong"] = row["location_candidates_shown"] and not row["location_candidate_hit"]
    # time the engine spent deriving them (all findings; part of diagnose_s)
    row["location_candidates_s"] = round(sum(float((f.get("location_candidates") or {}).get("elapsed_s") or 0.0)
                                             for f in findings if isinstance(f.get("location_candidates"), dict)), 3)
    return row


def candidate_rank(gt: Dict[str, Any], findings: List[Dict[str, Any]]) -> Optional[int]:
    best: Optional[int] = None
    for f in findings:
        lc = f.get("location_candidates") if isinstance(f.get("location_candidates"), dict) else {}
        for c in lc.get("candidates") or []:
            if not isinstance(c, dict) or not isinstance(c.get("rank"), int):
                continue
            m = re.match(r"^(.*):(\d+)$", str(c.get("location") or ""))
            if m and any(os.path.basename(loc["file"]) == os.path.basename(m.group(1))
                         and abs(loc["line"] - int(m.group(2))) <= LINE_TOLERANCE for loc in gt["locations"]):
                best = c["rank"] if best is None else min(best, c["rank"])
    return best


def candidates_shown(findings: List[Dict[str, Any]]) -> bool:
    """Some matching finding carries at least one static location candidate."""
    return any(isinstance(f.get("location_candidates"), dict) and bool(f["location_candidates"].get("candidates"))
               for f in findings)


def _stats(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    d = [r for r in rows if r["kind"] != HEALTHY_KIND]
    h = [r for r in rows if r["kind"] == HEALTHY_KIND]
    counts = {
        "defect_targets": len(d),
        "detected": sum(1 for r in d if r.get("detected")),
        "name_full": sum(1 for r in d if r.get("name_match") == "full"),
        "name_partial": sum(1 for r in d if r.get("name_match") == "partial"),
        "location_match": sum(1 for r in d if r.get("location_match")),
        # static candidates (not observed): reported next to, never added to, location_match
        "location_candidate_hit": sum(1 for r in d if r.get("location_candidate_hit")),
        "location_candidate_rank1": sum(1 for r in d if r.get("location_candidate_rank") == 1),
        "location_candidates_shown": sum(1 for r in d if r.get("location_candidates_shown")),
        "location_candidate_wrong": sum(1 for r in d if r.get("location_candidate_wrong")),
        "false_clears": sum(1 for r in d if r.get("false_clear")),
        "healthy_targets": len(h),
        "cleared": sum(1 for r in h if r.get("cleared")),
        "not_cleared": sum(1 for r in h if r.get("not_cleared")),
        "false_positives": sum(1 for r in h if r.get("false_positive")),
        "errors": sum(1 for r in rows if r.get("error")),
        "non_zero_stop": sum(1 for r in rows if r.get("non_zero_stop")),
    }
    metrics = {
        "detection": (counts["detected"], counts["defect_targets"]),
        "cause_name_full": (counts["name_full"], counts["defect_targets"]),
        "cause_name_partial": (counts["name_partial"], counts["defect_targets"]),
        "exact_location": (counts["location_match"], counts["defect_targets"]),
        "candidate_recall": (counts["location_candidate_hit"], counts["defect_targets"]),
        "candidate_rank1": (counts["location_candidate_rank1"], counts["defect_targets"]),
        "healthy_cleared": (counts["cleared"], counts["healthy_targets"]),
        "healthy_false_positive": (counts["false_positives"], counts["healthy_targets"]),
    }
    counts["valid_targets"] = sum(1 for r in rows if not r.get("error"))
    counts["rates"] = {name: _wilson_rate(successes, total) for name, (successes, total) in metrics.items()}
    return counts


def _wilson_rate(successes: int, total: int, z: float = 1.96) -> Dict[str, Any]:
    """Wilson 95% interval for a binomial rate; error rows remain in the denominator as misses."""
    if total <= 0:
        return {"successes": successes, "n": total, "rate": None, "ci95": None}
    p = successes / total
    z2 = z * z
    denom = 1.0 + z2 / total
    center = (p + z2 / (2.0 * total)) / denom
    half = z * ((p * (1.0 - p) / total + z2 / (4.0 * total * total)) ** 0.5) / denom
    return {"successes": successes, "n": total, "rate": round(p, 4),
            "ci95": [round(max(0.0, center - half), 4), round(min(1.0, center + half), 4)]}


def validate_benchmark_report(report: Dict[str, Any]) -> List[str]:
    """Validate required provenance and row shape before a result can be authoritative."""
    errors = []
    for key in ("schema_version", "environment", "environment_start", "authority", "authority_reasons",
                "dataset", "rows"):
        if key not in report:
            errors.append(f"missing report field: {key}")
    if report.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION}")
    if report.get("authority") not in ("AUTHORITATIVE", "NON_AUTHORITATIVE"):
        errors.append("authority must be AUTHORITATIVE or NON_AUTHORITATIVE")
    env = report.get("environment") if isinstance(report.get("environment"), dict) else {}
    if not env.get("commit") or env.get("dirty") not in (True, False, None):
        errors.append("environment commit/dirty provenance is malformed")
    dataset = report.get("dataset") if isinstance(report.get("dataset"), dict) else {}
    if not dataset.get("version") or not isinstance(report.get("rows"), list):
        errors.append("dataset fingerprint or rows are missing")
    for index, row in enumerate(report.get("rows") or []):
        if not isinstance(row, dict):
            errors.append(f"row {index} must be an object")
            continue
        if "build" not in row or not isinstance(row.get("build"), dict):
            errors.append(f"row {index} is missing build provenance")
    return errors


def summarize(all_rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Totals over scored rows only. Unscored rows are listed under ``unscored`` and change nothing else."""
    rows = [r for r in all_rows if r.get("scored", True)]
    unscored = [r for r in all_rows if not r.get("scored", True)]
    d_total = sum(1 for r in rows if r["kind"] != HEALTHY_KIND)
    overall = _stats(rows)
    overall["detection_rate"] = round(overall["detected"] / d_total, 4) if d_total else None
    overall["cause_name_match_rate"] = round(overall["name_full"] / d_total, 4) if d_total else None
    return {
        "overall": overall,
        "unscored": {
            "note": "informational; excluded from every total and rate in this report",
            "targets": [{k: r.get(k) for k in ("id", "kind", "scored_reason", "verdict", "detected", "name_match",
                                                "location_match", "location_candidate_rank",
                                                "location_candidate_wrong", "false_clear",
                                                "finding_categories", "subjects",
                                                "error")}
                        for r in unscored],
        },
        "per_kind": {k: _stats([r for r in rows if r["kind"] == k]) for k in DEFECT_KINDS
                     if any(r["kind"] == k for r in rows)},
        "per_origin": {o: _stats([r for r in rows if r["origin"] == o]) for o in ORIGINS},
        "per_naming": {n: _stats([r for r in rows if r["naming"] == n]) for n in ("neutral", "project")},
        "verdict_confidence_calibration": _confidence_calibration(rows),
    }


def _confidence_calibration(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Compare terminal fault/healthy verdict confidence with binary fault-presence correctness."""
    eligible = [r for r in rows if isinstance(r.get("verdict_confidence"), (int, float))
                and isinstance(r.get("verdict_confidence_correct"), bool)]
    edges = (0.0, 0.2, 0.4, 0.6, 0.8, 1.0000001)
    bins = []
    for lo, hi in zip(edges, edges[1:]):
        bucket = [r for r in eligible if lo <= float(r["verdict_confidence"]) < hi]
        bins.append({
            "range": [lo, min(1.0, hi)],
            "n": len(bucket),
            "mean_confidence": round(sum(float(r["verdict_confidence"]) for r in bucket) / len(bucket), 4)
            if bucket else None,
            "accuracy": round(sum(bool(r["verdict_confidence_correct"]) for r in bucket) / len(bucket), 4)
            if bucket else None,
        })
    return {
        "target": "terminal fault-versus-healthy verdict correctness",
        "eligible_targets": len(eligible),
        "abstentions_or_unknown_confidence": len(rows) - len(eligible),
        "brier_score": round(sum((float(r["verdict_confidence"]) -
                                   float(r["verdict_confidence_correct"])) ** 2 for r in eligible) / len(eligible), 4)
        if eligible else None,
        "bins": bins,
    }


# ------------------------------------------------------------------------------------------------ timing / repeat
def check_timings(result: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Per executed check wall time, from the engine's own ``checks_run[].duration_s``. Pure function."""
    out = []
    for c in (result or {}).get("checks_run") or []:
        d = c.get("duration_s")
        out.append({"check_id": c.get("check_id"), "recipe_id": c.get("recipe_id"), "name": c.get("name"),
                    "status": c.get("status"), "duration_s": float(d) if isinstance(d, (int, float)) else None})
    return out


def verdict_agreement(verdicts: List[Optional[str]]) -> Dict[str, Any]:
    """Distribution of verdicts over repeated runs and the share equal to the most common one. Pure function.
    A run without a verdict (error) counts as the verdict "ERROR"; ties go to the verdict seen first."""
    labels = [v if v else "ERROR" for v in verdicts]
    dist: Dict[str, int] = {}
    for v in labels:
        dist[v] = dist.get(v, 0) + 1
    if not labels:
        return {"runs": 0, "distribution": {}, "modal_verdict": None, "agreement_rate": None}
    modal = max(dist, key=lambda k: (dist[k], -labels.index(k)))
    return {"runs": len(labels), "distribution": dist, "modal_verdict": modal,
            "agreement_rate": round(dist[modal] / len(labels), 4)}


def summarize_repeat(rows: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Overall repeat-verdict agreement over rows that carry a ``repeat`` entry (None if no row does).
    ``mean_agreement_rate`` = mean of per-target rates; ``pooled_agreement_rate`` = sum of modal counts / sum of runs.
    Unscored targets are listed per target but kept out of the overall figures. Pure function."""
    rep = [r for r in rows if isinstance(r.get("repeat"), dict) and r["repeat"].get("runs")]
    if not rep:
        return None
    use = [r for r in rep if r.get("scored", True)]
    rates = [r["repeat"]["agreement_rate"] for r in use]
    modal = sum(r["repeat"]["distribution"][r["repeat"]["modal_verdict"]] for r in use)
    runs = sum(r["repeat"]["runs"] for r in use)
    return {
        "targets": len(use),
        "runs_per_target": sorted({r["repeat"]["runs"] for r in use}),
        "mean_agreement_rate": round(sum(rates) / len(rates), 4) if rates else None,
        "pooled_agreement_rate": round(modal / runs, 4) if runs else None,
        "fully_agreeing_targets": sum(1 for x in rates if x == 1.0),
        "per_target": {r["id"]: {**r["repeat"], "scored": r.get("scored", True)} for r in rep},
    }


def summarize_timing(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Diagnosis wall time over rows (all targets, scored or not) and per-check mean/max/count keyed by check_id.
    Uses every run of a row when ``check_runs`` is present, else its single ``checks``. Pure function."""
    diag = [r["diagnose_s"] for r in rows if isinstance(r.get("diagnose_s"), (int, float))]
    per: Dict[str, List[float]] = {}
    names: Dict[str, str] = {}
    for r in rows:
        for run in (r.get("check_runs") or [r.get("checks") or []]):
            for c in run:
                if isinstance(c.get("duration_s"), (int, float)):
                    per.setdefault(str(c["check_id"]), []).append(float(c["duration_s"]))
                    names[str(c["check_id"])] = c.get("name") or ""
    return {
        "diagnose_s": {"mean": round(sum(diag) / len(diag), 3), "max": max(diag), "n": len(diag)} if diag else None,
        "per_check": {k: {"name": names[k], "mean_s": round(sum(v) / len(v), 4), "max_s": round(max(v), 4),
                          "n": len(v)} for k, v in sorted(per.items(), key=lambda kv: -max(kv[1]))},
    }


# ------------------------------------------------------------------------------------------------ running
def working_tree_state(repo_root: str = REPO_ROOT) -> Dict[str, Any]:
    """Inspect the complete worktree, including untracked files; failure is never treated as clean."""
    try:
        res = subprocess.run(["git", "status", "--porcelain=v1", "--untracked-files=all"], cwd=repo_root,
                             capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"dirty": None, "check_ok": False, "error": f"{type(exc).__name__}: {exc}"}
    if res.returncode != 0:
        return {"dirty": None, "check_ok": False, "error": (res.stderr or "git status failed").strip()[:500]}
    return {"dirty": bool(res.stdout.strip()), "check_ok": True, "error": None}


def clean_run_output_allowed(path: str, repo_root: str = REPO_ROOT) -> bool:
    """A clean official run may write outside the checkout or to a Git-ignored artifact path."""
    resolved = os.path.realpath(os.path.abspath(path))
    root = os.path.realpath(repo_root)
    try:
        inside_repo = os.path.commonpath((root, resolved)) == root
    except ValueError:
        inside_repo = False
    if not inside_repo:
        return True
    try:
        res = subprocess.run(["git", "check-ignore", "-q", "--", resolved], cwd=root,
                             capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return False
    return res.returncode == 0


def _authoritative_run(start: Dict[str, Any], end: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """A benchmark is authoritative only when both complete-tree checks pass on the same clean commit."""
    reasons = []
    for label, env in (("start", start), ("end", end)):
        if not env.get("dirty_check_ok"):
            reasons.append(f"{label}: working-tree cleanliness could not be verified")
        elif env.get("dirty") is not False:
            reasons.append(f"{label}: working tree is dirty")
    if not start.get("commit") or start.get("commit") == "unknown":
        reasons.append("start: source commit is unavailable")
    if start.get("commit") != end.get("commit"):
        reasons.append("source commit changed during benchmark")
    return not reasons, reasons


def _target_provenance_reasons(rows: List[Dict[str, Any]]) -> List[str]:
    """Each benchmark target needs enough build identity to reproduce the measured binary."""
    reasons = []
    for row in rows:
        build = row.get("build") if isinstance(row.get("build"), dict) else {}
        target_id = str(row.get("id") or "unknown-target")
        if not build.get("build_id"):
            reasons.append(f"{target_id}: ELF build ID is unavailable")
        if build.get("inspection_error"):
            reasons.append(f"{target_id}: ELF identity inspection failed")
        if not build.get("compiler"):
            reasons.append(f"{target_id}: compiler is unavailable")
    return reasons


def dataset_fingerprint(suite_root: str, subdirs: Tuple[str, ...] = ("ground_truth", "targets")) -> str:
    """Hash ground-truth manifests and target sources for one suite, including local headers."""
    digest = hashlib.sha256()
    for subdir in subdirs:
        root = os.path.join(suite_root, subdir)
        for path in sorted(glob.glob(os.path.join(root, "**", "*"), recursive=True)):
            if not os.path.isfile(path):
                continue
            rel = os.path.relpath(path, suite_root).replace(os.sep, "/")
            digest.update(rel.encode("utf-8"))
            digest.update(b"\0")
            with open(path, "rb") as fh:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    digest.update(chunk)
            digest.update(b"\0")
    return digest.hexdigest()


def find_dataset_source_overlaps(main_gt_dir: str = GT_DIR, heldout_gt_dir: str = HELDOUT_GT_DIR,
                                 repo_root: str = REPO_ROOT) -> List[Dict[str, str]]:
    """Find exact source-content duplicates between tuning and held-out target manifests."""
    def fingerprints(gt_dir: str) -> Dict[str, str]:
        by_hash: Dict[str, List[str]] = {}
        for gt in load_ground_truth(gt_dir):
            digest = hashlib.sha256()
            for rel in sorted(source_files(gt)):
                path = os.path.join(repo_root, rel)
                with open(path, "rb") as fh:
                    content = fh.read()
                digest.update(len(content).to_bytes(8, "big"))
                digest.update(content)
            by_hash.setdefault(digest.hexdigest(), []).append(str(gt["id"]))
        return {fingerprint: target_id for fingerprint, target_ids in by_hash.items() for target_id in target_ids}

    main = fingerprints(main_gt_dir)
    heldout = fingerprints(heldout_gt_dir)
    return [{"main_target": main[digest], "heldout_target": heldout[digest], "source_sha256": digest}
            for digest in sorted(set(main) & set(heldout))]


def environment() -> Dict[str, Any]:
    def sh(*cmd):
        try:
            return subprocess.run(cmd, cwd=REPO_ROOT, capture_output=True, text=True, timeout=20).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return ""
    try:
        import ctypes
        libc = ctypes.CDLL(None)
        libc.gnu_get_libc_version.restype = ctypes.c_char_p
        glibc = libc.gnu_get_libc_version().decode()
    except (OSError, AttributeError):
        glibc = "unknown"
    tree = working_tree_state()
    return {
        "commit": sh("git", "rev-parse", "HEAD") or "unknown",
        "dirty": tree["dirty"],
        "dirty_check_ok": tree["check_ok"],
        "dirty_check_error": tree["error"],
        "arch": platform.machine(),
        "kernel": platform.release(),
        "glibc": glibc,
        "python": platform.python_version(),
        "compiler": (sh("gcc", "--version").splitlines() or ["gcc not found"])[0],
        "date_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def build_command(gt: Dict[str, Any], out: str) -> List[str]:
    """``gcc -g -O0`` on the single source unless the record has a ``build`` block (compiler, optimisation
    level, extra flags) and/or ``sources`` (multi-file targets)."""
    b = gt.get("build") or {}
    return ([b.get("compiler", "gcc"), "-g", b.get("opt", "-O0")] + list(b.get("flags") or [])
            + ["-pthread", "-Wl,--build-id=sha1"] + source_files(gt) + ["-o", out])


def build_target(gt: Dict[str, Any], out_dir: str) -> str:
    out = os.path.join(out_dir, gt["id"])
    subprocess.run(build_command(gt, out), cwd=REPO_ROOT, check=True, capture_output=True, timeout=120)
    return out


def target_build_metadata(gt: Dict[str, Any], binary: Optional[str]) -> Dict[str, Any]:
    """Record the exact per-target build recipe and ELF identity used by the benchmark."""
    cmd = build_command(gt, "<benchmark-output>")
    b = gt.get("build") or {}
    meta: Dict[str, Any] = {
        "command": cmd,
        "compiler": b.get("compiler", "gcc"),
        "optimization": b.get("opt", "-O0"),
        "flags": list(b.get("flags") or []),
        "debug_info_expected": True,
        "build_id": None,
        "target_arch": None,
        "debug_info_present": None,
        "inspection_error": None,
    }
    if binary is None:
        return meta
    try:
        from extractor.debug_image import inspect_elf
        ident = inspect_elf(binary)
        meta.update({"build_id": ident.build_id, "target_arch": ident.architecture,
                     "debug_info_present": ident.has_debug_info})
    except Exception as exc:  # noqa: BLE001 - retain the row but make missing provenance visible
        meta["inspection_error"] = f"{type(exc).__name__}: {exc}"[:500]
    return meta


def _wait_ready(proc: subprocess.Popen, gt: Dict[str, Any]) -> None:
    ready = gt["ready"]
    if ready["mode"] == "settle":
        time.sleep(float(ready["seconds"]))
        if proc.poll() is not None:
            raise RuntimeError("target exited before steady state")
        return
    sel = selectors.DefaultSelector()
    sel.register(proc.stdout, selectors.EVENT_READ)
    deadline = time.monotonic() + READY_TIMEOUT_S
    buf = b""
    while time.monotonic() < deadline:
        for _key, _ in sel.select(0.2):
            chunk = os.read(proc.stdout.fileno(), 4096)
            if not chunk:
                raise RuntimeError("target closed stdout before READY")
            buf += chunk
        if b"READY" in buf:
            return
        if proc.poll() is not None:
            raise RuntimeError("target exited before READY")
    raise RuntimeError("timeout waiting for READY")


# Defect kinds whose target keeps allocating or spawning while it runs. With --repeat each repeat gets a fresh
# process, so every repeat diagnoses the target at the same age (a single process would grow for minutes and
# the later repeats would see a different, much larger state than the first).
GROWTH_KINDS = frozenset({"memory_leak", "mapping_growth", "thread_growth"})


def _launch(binary: str, gt: Dict[str, Any], repeat_slots: int = 1) -> FixtureProcess:
    """Start the target through the shared containment launcher (tests/support/fixture_process.py): it dies with the
    benchmark however the benchmark ends (SIGKILL included), is killed by a resident-memory watchdog and by a hard
    lifetime limit. A benchmark killed from outside once left a leak target growing to 21 GB."""
    lifetime = READY_TIMEOUT_S + repeat_slots * DIAGNOSE_TIMEOUT_S + 60.0
    return fixture_popen([binary], stdin=subprocess.DEVNULL,
                         stdout=subprocess.PIPE if gt["ready"]["mode"] == "stdout_marker" else subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL, max_lifetime_s=lifetime, name=gt["id"])


def _kill(proc: FixtureProcess) -> None:
    proc.kill_tree()
    if proc.stdout:
        proc.stdout.close()


def _default_diagnose(pid, debug_image, symptom, corpus_dir):
    sys.path.insert(0, REPO_ROOT)
    from extractor.expert_diagnostic_engine import diagnose
    return diagnose(pid, debug_image, symptom, corpus_dir=corpus_dir).to_dict()


GENERIC_SYMPTOM = "general health check"


def run_target(gt: Dict[str, Any], tmp: str, diagnose_fn: Callable, symptom_mode: str = "ground_truth",
               repeat: int = 1) -> Dict[str, Any]:
    """Build, launch, diagnose once (``repeat`` times if > 1, same process, or a fresh one per repeat for growth-type targets; scoring uses the first run), kill, score. ``diagnose_fn(pid, debug_image, symptom, corpus_dir)`` -> dict."""
    t_start = time.monotonic()
    symptom = gt["symptom"] if symptom_mode == "ground_truth" else GENERIC_SYMPTOM
    try:
        binary = build_target(gt, tmp)
    except (subprocess.SubprocessError, OSError) as exc:
        row = score_result(gt, None, f"build failed: {exc}")
        row["build"] = target_build_metadata(gt, None)
        row["wall_s"] = round(time.monotonic() - t_start, 2)
        return row
    build_meta = target_build_metadata(gt, binary)
    restart = repeat > 1 and gt.get("kind") in GROWTH_KINDS
    proc = _launch(binary, gt, 1 if restart else max(1, repeat))
    result, error, diag_s = None, None, None
    runs: List[Dict[str, Any]] = []  # one entry per diagnose call: {"result", "error", "diagnose_s"}
    try:
        _wait_ready(proc, gt)
        for _i in range(max(1, repeat)):
            if _i > 0 and restart:
                _kill(proc)
                proc = _launch(binary, gt, 1)
                _wait_ready(proc, gt)
            box: Dict[str, Any] = {}

            def _call():
                try:
                    box["result"] = diagnose_fn(proc.pid, binary, symptom, os.path.join(tmp, "corpus"))
                except BaseException as exc:  # noqa: BLE001 - a crash in the system under test is a result row
                    box["error"] = f"{type(exc).__name__}: {exc}"

            t0 = time.monotonic()
            th = threading.Thread(target=_call, daemon=True)
            th.start()
            th.join(DIAGNOSE_TIMEOUT_S)
            run_s = round(time.monotonic() - t0, 2)
            if th.is_alive():
                runs.append({"result": None, "diagnose_s": run_s,
                             "error": f"diagnose did not return within {DIAGNOSE_TIMEOUT_S:.0f}s (hang)"})
                break  # the hung thread still uses the target; do not call again
            try:
                proc.check()  # the watchdog killed the target (memory ceiling / lifetime): never score that run
            except FixtureLimitExceeded as exc:
                runs.append({"result": None, "diagnose_s": run_s, "error": f"target setup failed: {exc}"})
                break
            runs.append({"result": box.get("result"), "error": box.get("error"), "diagnose_s": run_s})
            # Each diagnosis leaves tens of MB of session and report files in the corpus; the benchmark only uses the
            # returned result, so drop them per run (35 targets x 20 repeats filled a 45 GB disk otherwise).
            shutil.rmtree(os.path.join(tmp, "corpus"), ignore_errors=True)
        result, error, diag_s = runs[0]["result"], runs[0]["error"], runs[0]["diagnose_s"]
    except (RuntimeError, OSError) as exc:
        error = f"target setup failed: {exc}"
    finally:
        _kill(proc)
    row = score_result(gt, result, error)
    row["diagnose_s"] = diag_s
    row["checks"] = check_timings(result)
    if repeat > 1 and runs:
        row["repeat"] = verdict_agreement([(r["result"] or {}).get("verdict") for r in runs])
        row["repeat"]["requested"] = repeat
        row["repeat"]["diagnose_s"] = [r["diagnose_s"] for r in runs]
        row["check_runs"] = [check_timings(r["result"]) for r in runs]
    row["wall_s"] = round(time.monotonic() - t_start, 2)
    row["symptom"] = symptom
    row["build"] = build_meta
    return row


def run_all(targets: List[Dict[str, Any]], diagnose_fn: Callable = _default_diagnose,
            symptom_mode: str = "ground_truth", repeat: int = 1, suite: str = "main",
            environment_start: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    t0 = time.monotonic()
    env_start = environment_start or environment()
    tmp = tempfile.mkdtemp(prefix="diagacc_")
    try:
        rows = [run_target(gt, tmp, diagnose_fn, symptom_mode, repeat) for gt in targets]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    env_end = environment()
    is_authoritative, authority_reasons = _authoritative_run(env_start, env_end)
    authority_reasons.extend(_target_provenance_reasons(rows))
    source_overlaps = find_dataset_source_overlaps()
    if source_overlaps:
        authority_reasons.append(f"main/held-out contain {len(source_overlaps)} exact source duplicate(s)")
    is_authoritative = not authority_reasons
    suite_root = os.path.dirname(SUITES.get(suite, GT_DIR))
    report = {
        "schema_version": SCHEMA_VERSION,
        "environment": env_end,
        "environment_start": env_start,
        "authority": "AUTHORITATIVE" if is_authoritative else "NON_AUTHORITATIVE",
        "authority_reasons": authority_reasons,
        "symptom_mode": symptom_mode,
        "suite": suite,
        "dataset": {"version": dataset_fingerprint(suite_root),
                    "target_ids": [g["id"] for g in targets],
                    "manifest_directory": os.path.relpath(SUITES.get(suite, GT_DIR), REPO_ROOT),
                    "source_overlaps_with_other_suite": source_overlaps},
        "category_to_kind": {k: sorted(v) for k, v in KIND_CATEGORIES.items()},
        "line_tolerance": LINE_TOLERANCE,
        "totals": summarize(rows),
        "total_wall_s": round(time.monotonic() - t0, 1),
        "timing": summarize_timing(rows),
        "rows": rows,
    }
    if repeat > 1:
        report["repeat_requested"] = repeat
        report["repeat_agreement"] = summarize_repeat(rows)
    try:
        report["host_loadavg"] = list(os.getloadavg())  # at the end of the run; other jobs may share the host
    except OSError:
        pass
    schema_errors = validate_benchmark_report(report)
    report["schema_errors"] = schema_errors
    if schema_errors:
        report["authority_reasons"].extend(f"schema: {error}" for error in schema_errors)
        report["authority"] = "NON_AUTHORITATIVE"
    return report


def _adversarial_diagnose(pid, debug_image, kind, corpus_dir):
    from extractor.expert_diagnostic_engine import diagnose
    from tests.support import adversarial_healthy as adv
    return diagnose(pid, debug_image, corpus_dir=corpus_dir, **adv.diagnose_kwargs(kind)).to_dict()


def run_adversarial(diagnose_fn: Callable = _adversarial_diagnose,
                    programs: Optional[List[str]] = None) -> Dict[str, Any]:
    """The "adversarial healthy" suite: healthy programs whose names / values look like faults
    (tests/fixtures/adversarial_healthy), each diagnosed under every symptom kind.  Reported on its own: it is not
    part of the scored 21 defect + 8 healthy targets.  A fault verdict or any finding is a false positive."""
    from tests.support import adversarial_healthy as adv
    t0 = time.monotonic()
    tmp = tempfile.mkdtemp(prefix="diagacc_adv_")
    rows: List[Dict[str, Any]] = []
    try:
        corpus = os.path.join(tmp, "corpus")
        for name in programs or adv.programs():
            try:
                binary = adv.build(name, tmp)
            except subprocess.CalledProcessError as e:
                rows.append({"program": name, "kind": None, "error": f"build failed: {e.stderr[-300:]}"})
                continue
            source = adv.source_of(name)
            compiler = "g++" if source.endswith(".cpp") else "gcc"
            build_meta = target_build_metadata({"build": {"compiler": compiler, "opt": "-O0",
                                                          "flags": ["-g", "-fno-omit-frame-pointer", "-pthread"]}},
                                               binary)
            # adv.build selects gcc/g++ based on the source extension; record that exact command.
            build_meta["command"] = [build_meta["compiler"], "-g", "-O0", "-fno-omit-frame-pointer",
                                     "-pthread", source, "-o", "<benchmark-output>"]
            for kind in adv.SYMPTOM_KINDS:
                row: Dict[str, Any] = {"program": name, "symptom_kind": kind, "build": build_meta}
                proc = fixture_popen([binary], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                     stderr=subprocess.DEVNULL, max_lifetime_s=READY_TIMEOUT_S + DIAGNOSE_TIMEOUT_S + 60,
                                     name="adv_" + name)
                try:
                    proc.stdout.readline()
                    time.sleep(0.3)
                    t1 = time.monotonic()
                    res = diagnose_fn(proc.pid, binary, kind, corpus)
                    row["diagnose_s"] = round(time.monotonic() - t1, 2)
                    row["verdict"] = res.get("verdict")
                    row["violations"] = adv.violations(res)
                    row["false_positive"] = bool(row["violations"])
                except Exception as e:  # noqa: BLE001 - one failing run is an error row, not a crashed suite
                    row["error"] = f"{type(e).__name__}: {e}"[:300]
                finally:
                    _kill(proc)
                rows.append(row)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    ok_rows = [r for r in rows if "error" not in r]
    target_builds = {name: next((r["build"] for r in rows if r.get("program") == name and r.get("build")),
                                None) for name in sorted({r["program"] for r in rows})}
    return {
        "programs": sorted({r["program"] for r in rows}),
        "runs": len(ok_rows),
        "false_positives": sum(1 for r in ok_rows if r["false_positive"]),
        "fault_verdicts": sum(1 for r in ok_rows if r.get("verdict") in adv.FAULT_VERDICTS),
        "errors": len(rows) - len(ok_rows),
        "verdicts": {v: sum(1 for r in ok_rows if r.get("verdict") == v) for v in sorted({str(r.get("verdict")) for r in ok_rows})},
        "wall_s": round(time.monotonic() - t0, 1),
        "target_builds": target_builds,
        "rows": rows,
    }


def format_adversarial(adv_report: Dict[str, Any]) -> str:
    lines = ["", f"adversarial healthy suite (separate; not in the totals above): {len(adv_report['programs'])} programs, "
                 f"{adv_report['runs']} runs, false positives {adv_report['false_positives']} "
                 f"(fault verdicts {adv_report['fault_verdicts']}), errors {adv_report['errors']}; verdicts "
                 + ", ".join(f"{k} {n}" for k, n in adv_report["verdicts"].items())]
    for r in adv_report["rows"]:
        if r.get("false_positive") or r.get("error"):
            lines.append(f"  {r['program']:24} {str(r.get('symptom_kind')):20} {str(r.get('verdict')):16} "
                         f"{r.get('error') or '; '.join(r['violations'])}")
    return "\n".join(lines)


def format_table(report: Dict[str, Any]) -> str:
    lines = [f"{'target':20} {'kind':15} {'origin':15} {'verdict':16} {'det':>3} {'names':>7} {'loc':>3} {'cand':>5}"
             f"  categories"]
    def row_line(r):
        if r["kind"] == HEALTHY_KIND:
            det = "FP" if r.get("false_positive") else ("ok" if r.get("cleared") else "nc")
            names = loc = cand = "-"
        else:
            det = "yes" if r.get("detected") else "no"
            names = r.get("name_match", "none")
            loc = "yes" if r.get("location_match") else "no"
            cand = (f"#{r['location_candidate_rank']}" if r.get("location_candidate_rank")
                    else "WRONG" if r.get("location_candidate_wrong") else "-")
        extra = f"ERROR {r['error']}" if r.get("error") else ",".join(sorted(set(r["finding_categories"]))) or "-"
        return (f"{r['id']:20} {r['kind']:15} {r['origin']:15} {str(r['verdict']):16} {det:>3} {names:>7} {loc:>3}"
                f" {cand:>5}  {extra}")

    lines.extend(row_line(r) for r in report["rows"] if r.get("scored", True))
    unscored_rows = [r for r in report["rows"] if not r.get("scored", True)]
    t = report["totals"]
    o = t["overall"]
    lines.append("")
    lines.append(f"scored defects: detected {o['detected']}/{o['defect_targets']}, cause names full {o['name_full']}"
                 f" partial {o['name_partial']}, location {o['location_match']}")
    lines.append(f"static location candidates (not observed; not in 'location'): contain the true location "
                 f"{o['location_candidate_hit']}/{o['defect_targets']}, at rank 1 {o['location_candidate_rank1']}; "
                 f"shown {o['location_candidates_shown']}, wrong (shown, true location not among them) "
                 f"{o['location_candidate_wrong']}")
    lines.append(f"healthy: cleared {o['cleared']}, not cleared {o['not_cleared']}, false positives "
                 f"{o['false_positives']} (of {o['healthy_targets']}), false clears {o['false_clears']} (of "
                 f"{o['defect_targets']} defects); errors {o['errors']}; "
                 f"non-zero-stop collections {o['non_zero_stop']}")
    for k, s in t["per_kind"].items():
        if s["defect_targets"]:
            lines.append(f"  {k:15} detected {s['detected']}/{s['defect_targets']}  names {s['name_full']}/"
                         f"{s['defect_targets']}  false clears {s['false_clears']}")
    for k, s in t["per_origin"].items():
        if s["defect_targets"] or s["healthy_targets"]:
            lines.append(f"  origin {k:15} detected {s['detected']}/{s['defect_targets']}  names "
                         f"{s['name_full']}/{s['defect_targets']}  healthy FP {s['false_positives']}/"
                         f"{s['healthy_targets']} nc {s['not_cleared']}")
    if unscored_rows:
        lines.append("")
        lines.append("unscored (informational; not in any total above; a fault verdict here is reported, not penalised)")
        lines.extend(row_line(r) for r in unscored_rows)
        for r in unscored_rows:
            lines.append(f"  {r['id']}: {r.get('scored_reason', '')}")
    tm = report.get("timing") or {}
    if tm.get("diagnose_s"):
        lines.append("")
        lines.append(f"diagnose time per target (first run): mean {tm['diagnose_s']['mean']}s max {tm['diagnose_s']['max']}s; "
                     f"slowest checks (mean/max s over {'all runs' if report.get('repeat_requested') else 'targets'}):")
        for cid, c in list(tm["per_check"].items())[:5]:
            lines.append(f"  {cid:28} {c['mean_s']:7.3f} {c['max_s']:7.3f}  n={c['n']}  {c['name']}")
    ra = report.get("repeat_agreement")
    if ra:
        lines.append("")
        lines.append(f"repeat-verdict agreement ({ra['runs_per_target']} runs/target): mean {ra['mean_agreement_rate']}, "
                     f"pooled {ra['pooled_agreement_rate']}, fully agreeing {ra['fully_agreeing_targets']}/{ra['targets']} scored targets")
        for tid, v in ra["per_target"].items():
            dist = ", ".join(f"{k} {n}" for k, n in sorted(v["distribution"].items(), key=lambda kv: -kv[1]))
            lines.append(f"  {tid:20} {v['agreement_rate']:5}  {dist}{'' if v['scored'] else '  (unscored)'}")
    if report.get("host_loadavg"):
        lines.append("host loadavg at end of run: " + " ".join(f"{x:.2f}" for x in report["host_loadavg"]))
    lines.append(f"total wall time {report['total_wall_s']}s")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--only", nargs="+", metavar="TARGET", help="run only these target ids")
    ap.add_argument("--output", help="results JSON path (default results/<date>-<arch>-<commit>.json)")
    ap.add_argument("--symptom", choices=("ground_truth", "generic"), default="ground_truth",
                    help="symptom text: the ground-truth file's (default) or 'general health check' for every target")
    ap.add_argument("--repeat", type=int, default=1, metavar="N",
                    help="diagnose each target N times (default 1 = off) and report verdict agreement")
    ap.add_argument("--suite", choices=tuple(SUITES), default="main",
                    help="target set: the main benchmark (default) or the held-out validation suite, reported "
                         "separately (results file suffix -heldout)")
    ap.add_argument("--list", action="store_true", help="list targets and exit")
    ap.add_argument("--require-clean", action="store_true",
                    help="refuse to run unless the complete Git working tree is clean; official runs should use this")
    ap.add_argument("--adversarial", choices=("on", "off", "only"), default="on",
                    help="the separately reported adversarial-healthy suite (tests/fixtures/adversarial_healthy): "
                         "on (default, after the targets), off, or only")
    args = ap.parse_args(argv)
    targets = load_ground_truth(SUITES[args.suite])
    if args.list:
        for gt in targets:
            print(f"{gt['id']:20} {gt['kind']:15} {gt['origin']:15} {gt['naming']:8} {gt['source']}")
        return 0
    env_start = environment()
    if args.require_clean and (not env_start.get("dirty_check_ok") or env_start.get("dirty") is not False or
                               not env_start.get("commit") or env_start.get("commit") == "unknown"):
        print("refusing official benchmark: working tree is dirty or cleanliness could not be verified",
              file=sys.stderr)
        if env_start.get("dirty_check_error"):
            print(env_start["dirty_check_error"], file=sys.stderr)
        return 2
    if args.only:
        known = {g["id"] for g in targets}
        bad = [o for o in args.only if o not in known]
        if bad:
            print(f"unknown target(s): {bad}", file=sys.stderr)
            return 2
        targets = [g for g in targets if g["id"] in args.only]
    if args.require_clean:
        if args.adversarial == "only":
            default_name = f"{datetime.date.today().isoformat()}-adversarial.json"
        else:
            default_name = (f"{datetime.date.today().isoformat()}-{env_start['arch']}-{env_start['commit'][:7]}"
                            f"{'' if args.suite == 'main' else '-' + args.suite}"
                            f"{'' if args.symptom == 'ground_truth' else '-generic-symptom'}"
                            f"{'' if args.repeat <= 1 else '-repeat%d' % args.repeat}.json")
        planned_out = args.output or os.path.join(RESULTS_DIR, default_name)
        if not clean_run_output_allowed(planned_out):
            print("refusing official benchmark: output must be outside the checkout or Git-ignored",
                  file=sys.stderr)
            return 2
    if args.adversarial == "only":
        adv_report = run_adversarial()
        env_end = environment()
        is_authoritative, authority_reasons = _authoritative_run(env_start, env_end)
        adv_build_rows = [{"id": name, "build": build} for name, build in adv_report.get("target_builds", {}).items()]
        authority_reasons.extend(_target_provenance_reasons(adv_build_rows))
        if adv_report.get("errors"):
            authority_reasons.append(f"adversarial suite had {adv_report['errors']} failed run(s)")
        is_authoritative = not authority_reasons
        adv_report.update({"schema_version": SCHEMA_VERSION, "environment": env_end,
                           "environment_start": env_start,
                           "dataset": {"version": dataset_fingerprint(os.path.join(REPO_ROOT, "tests", "fixtures"),
                                                                         ("adversarial_healthy",)),
                                       "suite": "adversarial_healthy"},
                           "authority": "AUTHORITATIVE" if is_authoritative else "NON_AUTHORITATIVE",
                           "authority_reasons": authority_reasons})
        schema_errors = validate_benchmark_report(adv_report)
        adv_report["schema_errors"] = schema_errors
        if schema_errors:
            adv_report["authority_reasons"].extend(f"schema: {error}" for error in schema_errors)
            adv_report["authority"] = "NON_AUTHORITATIVE"
            is_authoritative = False
        out = args.output or os.path.join(RESULTS_DIR, f"{datetime.date.today().isoformat()}-adversarial.json")
        with open(out, "w", encoding="utf-8") as fh:
            json.dump(adv_report, fh, indent=2)
            fh.write("\n")
        print(format_adversarial(adv_report))
        print(f"benchmark authority: {adv_report['authority']}" +
              (f" ({'; '.join(authority_reasons)})" if authority_reasons else ""))
        print(f"results written to {out}")
        return 2 if args.require_clean and not is_authoritative else 0
    report = run_all(targets, symptom_mode=args.symptom, repeat=max(1, args.repeat), suite=args.suite,
                     environment_start=env_start)
    if args.adversarial == "on" and not args.only:
        report["adversarial_healthy"] = run_adversarial()
    env_end = environment()
    _, source_reasons = _authoritative_run(env_start, env_end)
    authority_reasons = source_reasons + _target_provenance_reasons(report["rows"])
    if report.get("dataset", {}).get("source_overlaps_with_other_suite"):
        overlap_count = len(report["dataset"]["source_overlaps_with_other_suite"])
        authority_reasons.append(f"main/held-out contain {overlap_count} exact source duplicate(s)")
    if isinstance(report.get("adversarial_healthy"), dict):
        adversarial = report["adversarial_healthy"]
        adv_build_rows = [{"id": name, "build": build}
                          for name, build in adversarial.get("target_builds", {}).items()]
        authority_reasons.extend(_target_provenance_reasons(adv_build_rows))
        if adversarial.get("errors"):
            authority_reasons.append(f"adversarial suite had {adversarial['errors']} failed run(s)")
    authority_reasons.extend(f"schema: {error}" for error in validate_benchmark_report(report))
    report["environment"] = env_end
    report["authority_reasons"] = authority_reasons
    report["authority"] = "AUTHORITATIVE" if not authority_reasons else "NON_AUTHORITATIVE"
    env = report["environment"]
    out = args.output or os.path.join(
        RESULTS_DIR, f"{datetime.date.today().isoformat()}-{env['arch']}-{env['commit'][:7]}"
        f"{'' if args.suite == 'main' else '-' + args.suite}"
        f"{'' if args.symptom == 'ground_truth' else '-generic-symptom'}"
        f"{'' if args.repeat <= 1 else '-repeat%d' % args.repeat}.json")
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
        fh.write("\n")
    print(format_table(report))
    print(f"benchmark authority: {report['authority']}" +
          (f" ({'; '.join(report['authority_reasons'])})" if report["authority_reasons"] else ""))
    if report.get("adversarial_healthy"):
        print(format_adversarial(report["adversarial_healthy"]))
    print(f"results written to {out}")
    sys.stdout.flush()
    if any(r.get("error", "").endswith("(hang)") for r in report["rows"]):
        os._exit(2 if args.require_clean and report["authority"] != "AUTHORITATIVE" else 0)
    return 2 if args.require_clean and report["authority"] != "AUTHORITATIVE" else 0


if __name__ == "__main__":
    sys.exit(main())

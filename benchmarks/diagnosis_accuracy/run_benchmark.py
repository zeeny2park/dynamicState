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
import json
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
from typing import Any, Callable, Dict, List, Optional

HERE = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.abspath(os.path.join(HERE, "..", ".."))
GT_DIR = os.path.join(HERE, "ground_truth")
RESULTS_DIR = os.path.join(HERE, "results")

SCHEMA_VERSION = 1
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
    "long_stall": frozenset({"PROCESS_INSTABILITY"}),
}
# `long_stall` stays here only so unscored stall rows can be labelled and described; it never enters a total.
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
    lines = open(src, encoding="utf-8").read().splitlines()
    if gt["kind"] == HEALTHY_KIND:
        if gt["locations"] or any(gt["causes"][c] for c in NAME_CLASSES):
            errs.append("healthy control must have no causes and no locations")
    else:
        if not gt["locations"]:
            errs.append("defect target needs at least one location")
        if not any(gt["causes"][c] for c in NAME_CLASSES):
            errs.append("defect target needs at least one cause name")
        for loc in gt["locations"]:
            if loc.get("file") != gt["source"]:
                errs.append(f"location file {loc.get('file')} != source")
            ln = loc.get("line")
            if not isinstance(ln, int) or not (1 <= ln <= len(lines)):
                errs.append(f"bad line {ln}")
            elif loc.get("text") not in lines[ln - 1]:
                errs.append(f"line {ln} does not contain {loc.get('text')!r}")
    if gt["origin"] == "project_fixture" and not gt["source"].startswith("tests/fixtures/real_runtime/"):
        errs.append("project_fixture must reference tests/fixtures/real_runtime")
    if gt["origin"] != "project_fixture":
        text = open(src, encoding="utf-8").read().lower()
        for banned in ("leak", "overflow", "canary", "guard", "deadbeef", "uaf", "dangling"):
            if banned in text:
                errs.append(f"source contains announcing word {banned!r}")
    return errs


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
            row.update(detected=False, name_match="none", location_match=False, false_clear=False)
        return row

    findings = list(result.get("findings") or [])
    impact = result.get("collection_impact") or {}
    verdict = result.get("verdict")
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
    return row


def _stats(rows: List[Dict[str, Any]]) -> Dict[str, Any]:
    d = [r for r in rows if r["kind"] != HEALTHY_KIND]
    h = [r for r in rows if r["kind"] == HEALTHY_KIND]
    return {
        "defect_targets": len(d),
        "detected": sum(1 for r in d if r.get("detected")),
        "name_full": sum(1 for r in d if r.get("name_match") == "full"),
        "name_partial": sum(1 for r in d if r.get("name_match") == "partial"),
        "location_match": sum(1 for r in d if r.get("location_match")),
        "false_clears": sum(1 for r in d if r.get("false_clear")),
        "healthy_targets": len(h),
        "cleared": sum(1 for r in h if r.get("cleared")),
        "not_cleared": sum(1 for r in h if r.get("not_cleared")),
        "false_positives": sum(1 for r in h if r.get("false_positive")),
        "errors": sum(1 for r in rows if r.get("error")),
        "non_zero_stop": sum(1 for r in rows if r.get("non_zero_stop")),
    }


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
                                                "location_match", "false_clear", "finding_categories", "subjects",
                                                "error")}
                        for r in unscored],
        },
        "per_kind": {k: _stats([r for r in rows if r["kind"] == k]) for k in DEFECT_KINDS
                     if any(r["kind"] == k for r in rows)},
        "per_origin": {o: _stats([r for r in rows if r["origin"] == o]) for o in ORIGINS},
        "per_naming": {n: _stats([r for r in rows if r["naming"] == n]) for n in ("neutral", "project")},
    }


# ------------------------------------------------------------------------------------------------ running
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
    return {
        "commit": sh("git", "rev-parse", "HEAD") or "unknown",
        "dirty": bool(sh("git", "status", "--porcelain", "--", "extractor", "benchmarks/diagnosis_accuracy")),
        "arch": platform.machine(),
        "kernel": platform.release(),
        "glibc": glibc,
        "python": platform.python_version(),
        "compiler": (sh("gcc", "--version").splitlines() or ["gcc not found"])[0],
        "date_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }


def build_target(gt: Dict[str, Any], out_dir: str) -> str:
    out = os.path.join(out_dir, gt["id"])
    subprocess.run(["gcc", "-g", "-O0", "-pthread", "-Wl,--build-id=sha1", gt["source"], "-o", out],
                   cwd=REPO_ROOT, check=True, capture_output=True, timeout=120)
    return out


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


def _kill(proc: subprocess.Popen) -> None:
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except OSError:
        try:
            proc.kill()
        except OSError:
            pass
    try:
        proc.wait(timeout=10)
    except subprocess.SubprocessError:
        pass
    if proc.stdout:
        proc.stdout.close()


def _default_diagnose(pid, debug_image, symptom, corpus_dir):
    sys.path.insert(0, REPO_ROOT)
    from extractor.expert_diagnostic_engine import diagnose
    return diagnose(pid, debug_image, symptom, corpus_dir=corpus_dir).to_dict()


GENERIC_SYMPTOM = "general health check"


def run_target(gt: Dict[str, Any], tmp: str, diagnose_fn: Callable, symptom_mode: str = "ground_truth") -> Dict[str, Any]:
    """Build, launch, diagnose once, kill, score. ``diagnose_fn(pid, debug_image, symptom, corpus_dir)`` -> dict."""
    t_start = time.monotonic()
    symptom = gt["symptom"] if symptom_mode == "ground_truth" else GENERIC_SYMPTOM
    try:
        binary = build_target(gt, tmp)
    except (subprocess.SubprocessError, OSError) as exc:
        row = score_result(gt, None, f"build failed: {exc}")
        row["wall_s"] = round(time.monotonic() - t_start, 2)
        return row
    proc = subprocess.Popen([binary], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE if gt["ready"]["mode"] == "stdout_marker" else subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, start_new_session=True)
    result, error, diag_s = None, None, None
    try:
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
        diag_s = round(time.monotonic() - t0, 2)
        if th.is_alive():
            error = f"diagnose did not return within {DIAGNOSE_TIMEOUT_S:.0f}s (hang)"
        else:
            result, error = box.get("result"), box.get("error")
    except (RuntimeError, OSError) as exc:
        error = f"target setup failed: {exc}"
    finally:
        _kill(proc)
    row = score_result(gt, result, error)
    row["diagnose_s"] = diag_s
    row["wall_s"] = round(time.monotonic() - t_start, 2)
    row["symptom"] = symptom
    return row


def run_all(targets: List[Dict[str, Any]], diagnose_fn: Callable = _default_diagnose,
            symptom_mode: str = "ground_truth") -> Dict[str, Any]:
    t0 = time.monotonic()
    tmp = tempfile.mkdtemp(prefix="diagacc_")
    try:
        rows = [run_target(gt, tmp, diagnose_fn, symptom_mode) for gt in targets]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return {
        "schema_version": SCHEMA_VERSION,
        "environment": environment(),
        "symptom_mode": symptom_mode,
        "category_to_kind": {k: sorted(v) for k, v in KIND_CATEGORIES.items()},
        "line_tolerance": LINE_TOLERANCE,
        "totals": summarize(rows),
        "total_wall_s": round(time.monotonic() - t0, 1),
        "rows": rows,
    }


def format_table(report: Dict[str, Any]) -> str:
    lines = [f"{'target':20} {'kind':15} {'origin':15} {'verdict':16} {'det':>3} {'names':>7} {'loc':>3}  categories"]
    def row_line(r):
        if r["kind"] == HEALTHY_KIND:
            det = "FP" if r.get("false_positive") else ("ok" if r.get("cleared") else "nc")
            names = loc = "-"
        else:
            det = "yes" if r.get("detected") else "no"
            names = r.get("name_match", "none")
            loc = "yes" if r.get("location_match") else "no"
        extra = f"ERROR {r['error']}" if r.get("error") else ",".join(sorted(set(r["finding_categories"]))) or "-"
        return f"{r['id']:20} {r['kind']:15} {r['origin']:15} {str(r['verdict']):16} {det:>3} {names:>7} {loc:>3}  {extra}"

    lines.extend(row_line(r) for r in report["rows"] if r.get("scored", True))
    unscored_rows = [r for r in report["rows"] if not r.get("scored", True)]
    t = report["totals"]
    o = t["overall"]
    lines.append("")
    lines.append(f"scored defects: detected {o['detected']}/{o['defect_targets']}, cause names full {o['name_full']}"
                 f" partial {o['name_partial']}, location {o['location_match']}")
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
    lines.append(f"total wall time {report['total_wall_s']}s")
    return "\n".join(lines)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--only", nargs="+", metavar="TARGET", help="run only these target ids")
    ap.add_argument("--output", help="results JSON path (default results/<date>-<arch>-<commit>.json)")
    ap.add_argument("--symptom", choices=("ground_truth", "generic"), default="ground_truth",
                    help="symptom text: the ground-truth file's (default) or 'general health check' for every target")
    ap.add_argument("--list", action="store_true", help="list targets and exit")
    args = ap.parse_args(argv)
    targets = load_ground_truth()
    if args.list:
        for gt in targets:
            print(f"{gt['id']:20} {gt['kind']:15} {gt['origin']:15} {gt['naming']:8} {gt['source']}")
        return 0
    if args.only:
        known = {g["id"] for g in targets}
        bad = [o for o in args.only if o not in known]
        if bad:
            print(f"unknown target(s): {bad}", file=sys.stderr)
            return 2
        targets = [g for g in targets if g["id"] in args.only]
    report = run_all(targets, symptom_mode=args.symptom)
    env = report["environment"]
    out = args.output or os.path.join(
        RESULTS_DIR, f"{datetime.date.today().isoformat()}-{env['arch']}-{env['commit'][:7]}"
        f"{'' if args.symptom == 'ground_truth' else '-generic-symptom'}.json")
    os.makedirs(os.path.dirname(os.path.abspath(out)), exist_ok=True)
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2)
        fh.write("\n")
    print(format_table(report))
    print(f"results written to {out}")
    sys.stdout.flush()
    if any(r.get("error", "").endswith("(hang)") for r in report["rows"]):
        os._exit(0)  # a hung diagnose thread must not keep the runner alive
    return 0


if __name__ == "__main__":
    sys.exit(main())

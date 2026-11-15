#!/usr/bin/env python3
"""Verdict stability under host load: run ``diagnose`` N times per benchmark target while this script keeps K
busy-loop processes running, and print the verdict distribution (plus the evidence that decided each run).

    python3 benchmarks/diagnosis_accuracy/load_repro.py --targets spin_yield ok_contention --n 20 --load 2
    python3 benchmarks/diagnosis_accuracy/load_repro.py --targets lock_convoy --n 8 --load 16 --allow-heavy-load --jsonl /tmp/r.jsonl

``--load K``: K processes spinning in ``while True: pass`` (nice +10) for the whole run. By default K is capped at
half the available CPUs (maximum 2); ``--allow-heavy-load`` overrides that cap and is only for a disposable,
isolated environment. Other load on the host is not controlled: the 1-minute load average at the start of every run
is printed next to its verdict. ``--test-style`` diagnoses like tests/test_lock_contention.py (no debug image,
symptom "the process feels slow, check for lock problems", 0.3 s settle).

Measured on aarch64 / 4 cores (2026-11-13): before the fixes of this change, spin_yield was HEALTHY in 30/30 runs at
--load 8 and 16 (a missed busy wait) and lock_convoy at --load 16 lost its LOCK_CONTENTION finding to the 20 s budget
in 16/16 runs.  Not a test: the result depends on the machine and on whatever else runs on it.
"""
import argparse
import collections
import json
import subprocess
import os
import shutil
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, ROOT)
sys.path.insert(0, HERE)
import run_benchmark as rb  # noqa: E402
from tests.support.fixture_process import fixture_popen  # noqa: E402

TEST_SYMPTOM = "the process feels slow, check for lock problems"


_SPIN = [sys.executable, "-c", "while True: pass"]
MAX_DIAGNOSES = 100
MAX_LOAD_PROCESSES = 16
MAX_HOG_LIFETIME_S = 6 * 60 * 60


def _available_cpus() -> int:
    """Respect the process affinity when choosing a conservative load cap."""
    try:
        return max(1, len(os.sched_getaffinity(0)))
    except (AttributeError, OSError):
        return max(1, os.cpu_count() or 1)


def _lower_priority() -> None:
    # These workers exist to create background load, not to compete with the
    # diagnoser, SSH daemon, or other normal-priority work.
    os.nice(10)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--targets", nargs="+", required=True)
    ap.add_argument("--n", type=int, default=20, help=f"diagnoses per target (1..{MAX_DIAGNOSES})")
    ap.add_argument("--load", type=int, default=0, help="busy-loop processes kept running")
    ap.add_argument("--allow-heavy-load", action="store_true",
                    help="allow load above the safe cap; use only in a disposable isolated environment")
    ap.add_argument("--test-style", action="store_true")
    ap.add_argument("--jsonl", help="append one record per run here")
    a = ap.parse_args(argv)
    if not 1 <= a.n <= MAX_DIAGNOSES:
        ap.error(f"--n must be between 1 and {MAX_DIAGNOSES}")
    if a.load < 0:
        ap.error("--load must be zero or greater")
    if a.load > MAX_LOAD_PROCESSES:
        ap.error(f"--load must not exceed the absolute safety limit of {MAX_LOAD_PROCESSES}")
    if len(set(a.targets)) != len(a.targets):
        ap.error("--targets must not contain duplicates")
    cpu_count = _available_cpus()
    safe_load_cap = min(2, cpu_count // 2)
    if a.load > safe_load_cap and not a.allow_heavy_load:
        ap.error(f"--load {a.load} exceeds the safe cap of {safe_load_cap} for {cpu_count} available CPU(s); "
                 "reduce --load or explicitly use --allow-heavy-load only in an isolated disposable environment")
    if a.load > safe_load_cap:
        print("WARNING: heavy CPU load explicitly enabled; do not run on a shared host or over its only SSH path.",
              file=sys.stderr, flush=True)
    gts = {g["id"]: g for g in rb.load_ground_truth()}
    unknown = [t for t in a.targets if t not in gts]
    if unknown:
        ap.error(f"unknown target(s): {unknown}")
    # Contained: the spinners die with this script (also on SIGKILL) and after
    # a bounded hard lifetime. Keep cleanup active even if spawning a worker fails.
    max_lifetime = max(1800.0, min(MAX_HOG_LIFETIME_S, a.n * len(a.targets) * 120.0))
    hogs = []
    out = {}
    try:
        for _ in range(a.load):
            hogs.append(fixture_popen(_SPIN, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                      stderr=subprocess.DEVNULL, preexec_fn=_lower_priority,
                                      max_lifetime_s=max_lifetime))
        if hogs:
            print(f"Starting {len(hogs)} low-priority CPU-load process(es) on {cpu_count} available CPU(s).",
                  file=sys.stderr, flush=True)
            time.sleep(1.0)
        for tid in a.targets:
            dist: collections.Counter = collections.Counter()
            for i in range(a.n):
                tmp = tempfile.mkdtemp(prefix="loadrepro_")
                box = {}

                def diag(pid, binary, symptom, corpus_dir):
                    from extractor.expert_diagnostic_engine import diagnose
                    if a.test_style:
                        time.sleep(0.3)
                        binary, symptom = None, TEST_SYMPTOM
                    box["r"] = diagnose(pid, binary, symptom, corpus_dir=corpus_dir).to_dict()
                    return box["r"]
                load1 = os.getloadavg()[0]
                try:
                    row = rb.run_target(gts[tid], tmp, diag)
                finally:
                    shutil.rmtree(tmp, True)
                r = box.get("r") or {}
                v = row.get("verdict") or f"ERROR: {row.get('error')}"
                dist[v] += 1
                rec = {"target": tid, "i": i, "load": a.load, "load1": round(load1, 1), "verdict": v,
                       "diagnose_s": row.get("diagnose_s"),
                       "categories": [f.get("category") for f in r.get("findings") or []],
                       "blocking": [(b.get("kind"), b.get("item")) for b in (r.get("healthy_scope") or {}).get("blocking") or []],
                       "summary": (r.get("summary") or "")[-160:]}
                print(f"{tid} {i} {v} load1={rec['load1']} t={rec['diagnose_s']} {rec['categories']} {rec['blocking'][:3]}",
                      flush=True)
                if a.jsonl:
                    with open(a.jsonl, "a") as fh:
                        fh.write(json.dumps(rec) + "\n")
            out[tid] = dict(dist)
    finally:
        for p in hogs:
            p.kill_tree()
    print(json.dumps({"load": a.load, "n": a.n, "test_style": a.test_style, "verdicts": out}))
    return 0


if __name__ == "__main__":
    sys.exit(main())

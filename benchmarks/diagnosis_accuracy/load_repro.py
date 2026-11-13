#!/usr/bin/env python3
"""Verdict stability under host load: run ``diagnose`` N times per benchmark target while this script keeps K
busy-loop processes running, and print the verdict distribution (plus the evidence that decided each run).

    python3 benchmarks/diagnosis_accuracy/load_repro.py --targets spin_yield ok_contention --n 20 --load 16
    python3 benchmarks/diagnosis_accuracy/load_repro.py --targets lock_convoy --n 8 --load 16 --jsonl /tmp/r.jsonl

``--load K``: K processes spinning in ``while True: pass`` (nice 0, no affinity) for the whole run; 4x the core count
is "heavy".  Other load on the host is not controlled: the 1-minute load average at the start of every run is printed
next to its verdict.  ``--test-style`` diagnoses like tests/test_lock_contention.py (no debug image, symptom "the
process feels slow, check for lock problems", 0.3 s settle).

Measured on aarch64 / 4 cores (2026-11-13): before the fixes of this change, spin_yield was HEALTHY in 30/30 runs at
--load 8 and 16 (a missed busy wait) and lock_convoy at --load 16 lost its LOCK_CONTENTION finding to the 20 s budget
in 16/16 runs.  Not a test: the result depends on the machine and on whatever else runs on it.
"""
import argparse
import collections
import json
import multiprocessing as mp
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

TEST_SYMPTOM = "the process feels slow, check for lock problems"


def _spin() -> None:
    while True:
        pass


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--targets", nargs="+", required=True)
    ap.add_argument("--n", type=int, default=20, help="diagnoses per target")
    ap.add_argument("--load", type=int, default=0, help="busy-loop processes kept running")
    ap.add_argument("--test-style", action="store_true")
    ap.add_argument("--jsonl", help="append one record per run here")
    a = ap.parse_args(argv)
    gts = {g["id"]: g for g in rb.load_ground_truth()}
    unknown = [t for t in a.targets if t not in gts]
    if unknown:
        ap.error(f"unknown target(s): {unknown}")
    hogs = [mp.Process(target=_spin, daemon=True) for _ in range(a.load)]
    for p in hogs:
        p.start()
    time.sleep(1.0)
    out = {}
    try:
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
            p.terminate()
    print(json.dumps({"load": a.load, "n": a.n, "test_style": a.test_style, "verdicts": out}))
    return 0


if __name__ == "__main__":
    sys.exit(main())

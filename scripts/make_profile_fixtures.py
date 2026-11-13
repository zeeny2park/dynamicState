#!/usr/bin/env python3
"""Make the small process-profile fixtures (``tests/fixtures/profile/*.json.gz``) from full diagnose results.

A full result with ``include_report=True`` is several MB (call stacks, per-thread records).  The profile reads only a
part of it, so each fixture keeps the whole result shape but prunes the bulk the profile never reads: call-stack
frames shrink to the four fields it uses, per-thread stack and variable records to the stack size.  The profile built
from a pruned fixture equals the one built from the full result (``tests/test_process_profile.py`` checks the figures).

    python3 scripts/make_profile_fixtures.py SRC_DIR NAME[:NAME...]     # SRC_DIR/NAME.json.gz -> tests/fixtures/profile/

SRC files are made by running ``diagnose(pid, image, symptom, include_report=True).to_dict()`` on a benchmark target
(see ``scripts/make_sample_reports.py`` for how targets are started through ``tests/support/fixture_process.py``).
"""
import gzip
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(REPO, "tests", "fixtures", "profile")
DROP_KEYS = {"long_wait_threads", "historical_observations", "thread_findings", "long_wait_findings", "pt_loads"}


def prune_obs(o):
    o = {k: v for k, v in o.items() if k not in DROP_KEYS}
    cs = o.get("callstacks_info")
    if isinstance(cs, dict):
        thr = []
        for t in cs.get("threads") or []:
            frames = [{k: f[k] for k in ("function_name", "module", "module_path", "source_location") if f.get(k)}
                      for f in (t.get("callstack") or [])[:8] if isinstance(f, dict)]
            thr.append({k: t.get(k) for k in ("tid", "name", "state", "syscall", "waiting_on_lock") if k in t} | {"callstack": frames})
        o["callstacks_info"] = {k: cs[k] for k in ("status", "target_abi", "threads_inspected", "lock_owner_status") if k in cs} | {"threads": thr}
    if isinstance(o.get("threads"), list):
        keep = ("tid", "name", "state", "cpus_allowed_list", "sched_policy", "syscall")
        o["threads"] = [{k: t[k] for k in keep if k in t} | {"stack_info": {"size": (t.get("stack_info") or {}).get("size")}}
                        for t in o["threads"] if isinstance(t, dict)]
    if isinstance(o.get("thread_summary"), list):
        o["thread_summary"] = [{k: v for k, v in t.items() if k not in ("syscall_samples", "top_frames")} for t in o["thread_summary"]]
    return o


def prune(res):
    rep = res.get("report") or {}
    keep = {"section_b_target_context": rep.get("section_b_target_context"),
            "section_d_detailed_inspection_results": {"checks": [
                {"recipe_id": c.get("recipe_id"), "status": c.get("status"),
                 "actual_observations": prune_obs(c.get("actual_observations") or {})}
                for c in (rep.get("section_d_detailed_inspection_results") or {}).get("checks", [])]}}
    out = {k: v for k, v in res.items() if k != "report"}
    out["report"] = keep
    return out


def main(argv):
    src, names = argv[1], argv[2].split(":")
    os.makedirs(OUT, exist_ok=True)
    for name in names:
        with gzip.open(os.path.join(src, name + ".json.gz"), "rt", encoding="utf-8") as fh:
            res = json.load(fh)
        out = os.path.join(OUT, name.split(".")[0] + ".json.gz")
        with gzip.open(out, "wt", encoding="utf-8") as fh:
            json.dump(prune(res), fh, separators=(",", ":"))
        print(out, os.path.getsize(out))


if __name__ == "__main__":
    main(sys.argv)

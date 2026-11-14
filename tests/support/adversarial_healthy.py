"""Adversarial HEALTHY programs: healthy processes whose names and values look like faults.

Each program in ``tests/fixtures/adversarial_healthy/`` is healthy by construction, but its variables are named like
the things a name heuristic looks for (magic / canary / tag, alloc / free counters, capacity / length, pools /
caches / leaks, state / status / heartbeat, locks / owners) or hold poison-looking / sentinel values that are valid
in that program (0xDEADBEEF as the real magic, -1 as "not configured").  The principle they enforce (IMP-018 /
IMP-009): a variable's name can rank candidates but is never evidence; the DWARF type, the layout and an observed
relation are.

Shared by ``tests/test_adversarial_healthy.py`` (every program x every symptom kind must stay non-faulty, no
finding) and the accuracy benchmark (``benchmarks/diagnosis_accuracy/run_benchmark.py --adversarial``, reported
as a separate "adversarial healthy" suite).  Launch through ``tests.support.fixture_process`` only.
"""
import os
import subprocess
from typing import Any, Dict, List, Optional, Tuple

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SOURCE_DIR = os.path.join(ROOT, "tests", "fixtures", "adversarial_healthy")

# symptom kinds every program is diagnosed under (None = the default health check)
SYMPTOM_KINDS: Tuple[Optional[str], ...] = (None, "crash_corruption", "memory_growth", "hang_deadlock",
                                            "state_inconsistency", "variable_anomaly")
FAULT_VERDICTS = ("CONFIRMED_FAULT", "PROBABLE_FAULT", "FAULT", "DEGRADED")


def programs() -> List[str]:
    """Program names (source basename without extension), sorted."""
    return sorted(os.path.splitext(f)[0] for f in os.listdir(SOURCE_DIR) if f.endswith((".c", ".cpp")))


def source_of(name: str) -> str:
    for ext in (".c", ".cpp"):
        p = os.path.join(SOURCE_DIR, name + ext)
        if os.path.exists(p):
            return p
    raise FileNotFoundError(name)


def build(name: str, out_dir: str) -> str:
    """Compile one program with debug info into ``out_dir``; returns the binary path."""
    src = source_of(name)
    out = os.path.join(out_dir, name)
    cc = "g++" if src.endswith(".cpp") else "gcc"
    subprocess.run([cc, "-g", "-O0", "-fno-omit-frame-pointer", "-pthread", src, "-o", out],
                   check=True, capture_output=True, text=True)
    return out


def violations(result: Dict[str, Any]) -> List[str]:
    """What makes a diagnosis of a healthy program wrong: a fault verdict or any finding."""
    out = []
    if result.get("verdict") in FAULT_VERDICTS:
        out.append("verdict %s" % result.get("verdict"))
    for f in result.get("findings") or []:
        out.append("finding %s" % (f.get("category") or f.get("recipe_id") or f.get("check") or "?"))
    return out


def diagnose_kwargs(kind: Optional[str]) -> Dict[str, Any]:
    return {"symptom_fields": {"symptom_kind": kind}} if kind else {}

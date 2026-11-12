#!/usr/bin/env python3
"""Target throughput with vs without collection (IMP-020).

The target is a small C program that counts loop iterations and prints "<monotonic_ns> <count>" every 50 ms.
Throughput = iterations per second between two printed progress lines, so it is measured by the target itself.
For each repetition the benchmark measures N seconds idle, then N seconds while a diagnosis-like read sequence
runs against the target: one thread sample (`read_thread_samples`) every `--interval-ms` (default 100) plus a heap walk (the
1 MiB buffer in 4 KiB reads) per cycle.  Idle and loaded windows alternate (ABAB) to cancel drift; the delta is
(idle - loaded) / idle in percent, reported per repetition and as median.

Scenarios:
  local_unpinned      LocalTargetAdapter, target and diagnosis scheduled freely (multi-core host)
  local_same_core     both pinned to ONE cpu: the worst case, a single-core board
  remote_same_core    collector daemon (real native collector behind a local `sh` transport, as the tests do)
                      reading the target; target and collector pinned to ONE cpu, the host-side driver is not
                      (on a real board it is on another machine)

A negative delta means the loaded windows were faster than the idle ones (noise).  Differences below the
run-to-run spread (see `idle_cv_pct`) are not significant.  Single-cpu pinning makes the diagnosis compete for the
target's CPU, which is the effect worth measuring; on a multi-core host the unpinned case mostly measures cache
and memory-bus interference.

    python3 benchmarks/collection_impact_benchmark.py --smoke            # ~5 s, no file written
    python3 benchmarks/collection_impact_benchmark.py --seconds 3 --reps 5 --output benchmarks/collection_impact/results/<name>.json
"""

import argparse
import json
import os
import shutil
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from benchmarks.capture_benchmark import collect_environment_metadata  # noqa: E402
from extractor.collection_impact import CollectionImpactMeter  # noqa: E402
from extractor.target_adapter import LocalTargetAdapter, RemoteSshTargetAdapter  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA_VERSION = 1

FIXTURE_C = r"""
#include <stdio.h>
#include <time.h>
#include <sys/prctl.h>
static unsigned char buf[1 << 20];
static long long now_ns(void) { struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t); return t.tv_sec * 1000000000LL + t.tv_nsec; }
int main(void) {
    prctl(0x59616d61, (unsigned long)-1, 0, 0, 0);            /* PR_SET_PTRACER_ANY */
    for (unsigned long i = 0; i < sizeof(buf); i++) buf[i] = (unsigned char)(i * 7 + 3);
    printf("BASE %lu\n", (unsigned long)(size_t)buf); fflush(stdout);
    volatile unsigned long long n = 0, sink = 0;
    long long next = now_ns() + 50000000LL;
    for (;;) {
        for (int k = 0; k < 20000; k++) { n++; sink += buf[(n * 31) & ((1 << 20) - 1)]; }
        if (now_ns() >= next) { printf("%lld %llu\n", now_ns(), n); fflush(stdout); next += 50000000LL; }
    }
}
"""


class Target:
    """The fixture process; a reader thread keeps the latest (timestamp, count) progress lines."""

    def __init__(self, exe: str, cpu: Optional[int]):
        pre = (lambda: os.sched_setaffinity(0, {cpu})) if cpu is not None else None
        self.proc = subprocess.Popen([exe], stdout=subprocess.PIPE, text=True, preexec_fn=pre)
        self.base = int(self.proc.stdout.readline().split()[1])
        self.pid = self.proc.pid
        self.points: List[Tuple[int, int]] = []
        self._lock = threading.Lock()
        self._t = threading.Thread(target=self._read, daemon=True)
        self._t.start()

    def _read(self) -> None:
        for line in self.proc.stdout:
            f = line.split()
            if len(f) == 2:
                with self._lock:
                    self.points.append((int(f[0]), int(f[1])))

    def mark(self) -> int:
        with self._lock:
            return len(self.points)

    def rate_between(self, i0: int, i1: int) -> Optional[float]:
        """Iterations per second between progress points i0..i1 (the target's own clock)."""
        with self._lock:
            pts = self.points[i0:i1]
        if len(pts) < 2:
            return None
        (t0, c0), (t1, c1) = pts[0], pts[-1]
        return (c1 - c0) / ((t1 - t0) / 1e9) if t1 > t0 else None

    def stop(self) -> None:
        self.proc.kill()
        self.proc.wait()
        self.proc.stdout.close()


def diagnosis_like_load(adapter: Any, target: Target, seconds: float, interval_ms: float) -> Dict[str, Any]:
    """Thread-sampling window + heap walk, repeated for `seconds`; returns what it did."""
    cycles = reads = 0
    nbytes = 0
    t_end = time.monotonic() + seconds
    slices = [(target.base + off, 4096) for off in range(0, 1 << 20, 4096)]
    while time.monotonic() < t_end:
        adapter.read_thread_samples(target.pid, {})
        res = adapter.read_memory_batch(target.pid, slices)
        nbytes += sum(len(d) for d, st, _ in res if d)
        reads += len(slices)
        cycles += 1
        time.sleep(interval_ms / 1000.0)
    return {"cycles": cycles, "reads": reads, "bytes_read": nbytes}


def _window(target: Target, seconds: float, load: Optional[Any]) -> Dict[str, Any]:
    time.sleep(0.15)                                  # settle after the previous window
    i0 = target.mark()
    out: Dict[str, Any] = {}
    if load is None:
        time.sleep(seconds)
    else:
        out = load()
    i1 = target.mark()
    return {"rate": target.rate_between(i0, i1), **out}


def run_scenario(name: str, exe: str, collector: Optional[str], seconds: float, reps: int,
                 interval_ms: float) -> Dict[str, Any]:
    pinned = name != "local_unpinned"
    cpu = sorted(os.sched_getaffinity(0))[0] if pinned else None
    saved_aff = os.sched_getaffinity(0)
    if pinned and name.startswith("local"):
        os.sched_setaffinity(0, {cpu})                # the diagnosing process lives on the target's only cpu
    # remote: only the target and the collector share the one cpu; the host-side driver runs elsewhere
    target = Target(exe, cpu)
    adapter: Any
    if name.startswith("remote"):
        def runner(args, timeout, input_bytes=None):
            r = subprocess.run(["sh", "-c", args[-1]], input=input_bytes, capture_output=True, timeout=timeout)
            return r.returncode, r.stdout.decode(), r.stderr.decode()

        def streamer(args):
            return subprocess.Popen(["sh", "-c", args[-1]], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.DEVNULL,
                                    preexec_fn=(lambda: os.sched_setaffinity(0, {cpu})))
        adapter = RemoteSshTargetAdapter(host="localhost", command_runner=runner, stream_opener=streamer,
                                         collector_path=collector)
    else:
        adapter = LocalTargetAdapter()
    reps_out: List[Dict[str, Any]] = []
    try:
        time.sleep(0.3)
        for r in range(reps):
            idle = _window(target, seconds, None)
            meter = CollectionImpactMeter(adapter, target.pid).start()
            loaded = _window(target, seconds, lambda: diagnosis_like_load(adapter, target, seconds, interval_ms))
            imp = meter.finish(bytes_read=loaded.get("bytes_read"), measured_stop_ms=0.0).to_dict()
            delta = None
            if idle["rate"] and loaded["rate"]:
                delta = round((idle["rate"] - loaded["rate"]) / idle["rate"] * 100.0, 2)
            reps_out.append({
                "idle_iter_per_s": round(idle["rate"]) if idle["rate"] else None,
                "loaded_iter_per_s": round(loaded["rate"]) if loaded["rate"] else None,
                "throughput_delta_pct": delta,
                "diagnosis": {k: loaded[k] for k in ("cycles", "reads", "bytes_read")},
                "target_cpu_ms_during_window": imp["target"].get("cpu_ms"),
                "attributable_cpu_ms": imp["diagnosis_attributable"].get("attributable_cpu_ms"),
                "attributable_basis": imp["diagnosis_attributable"].get("basis"),
                "collector_max_rss_kb": imp["diagnosis_attributable"].get("collector_max_rss_kb"),
                "target_ctx_switches": imp["target"].get("ctx_switches"),
                "target_runqueue_wait_ms": imp["target"].get("runqueue_wait_ms"),
            })
    finally:
        adapter.close()
        target.stop()
        os.sched_setaffinity(0, saved_aff)
    deltas = [x["throughput_delta_pct"] for x in reps_out if x["throughput_delta_pct"] is not None]
    idles = [x["idle_iter_per_s"] for x in reps_out if x["idle_iter_per_s"]]
    loadeds = [x["loaded_iter_per_s"] for x in reps_out if x["loaded_iter_per_s"]]
    return {
        "scenario": name,
        "pinned_to_cpu": cpu,
        "repetitions": reps_out,
        "median_idle_iter_per_s": statistics.median(idles) if idles else None,
        "median_loaded_iter_per_s": statistics.median(loadeds) if loadeds else None,
        "median_throughput_delta_pct": round(statistics.median(deltas), 2) if deltas else None,
        "min_delta_pct": min(deltas) if deltas else None,
        "max_delta_pct": max(deltas) if deltas else None,
        "idle_cv_pct": round(statistics.pstdev(idles) / statistics.mean(idles) * 100.0, 2) if len(idles) > 1 else None,
    }


def build_fixtures(workdir: str) -> Tuple[str, Optional[str]]:
    src = os.path.join(workdir, "counter.c")
    with open(src, "w") as f:
        f.write(FIXTURE_C)
    exe = os.path.join(workdir, "counter")
    subprocess.run(["cc", "-O1", "-o", exe, src], check=True, capture_output=True)
    build = os.path.join(workdir, "collector")
    shutil.copytree(os.path.join(REPO_ROOT, "target", "collector"), build,
                    ignore=shutil.ignore_patterns("*.o", "dist", "dynamicstate-collector", "test_crypto"))
    r = subprocess.run(["make", "-C", build, "dynamicstate-collector"], capture_output=True)
    return exe, (os.path.join(build, "dynamicstate-collector") if r.returncode == 0 else None)


def run_benchmark(seconds: float, reps: int, interval_ms: float, scenarios: List[str]) -> Dict[str, Any]:
    t0 = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="ci_bench_") as wd:
        exe, collector = build_fixtures(wd)
        results = []
        for name in scenarios:
            if name.startswith("remote") and not collector:
                results.append({"scenario": name, "skipped": "native collector did not build"})
                continue
            results.append(run_scenario(name, exe, collector, seconds, reps, interval_ms))
    return {
        "schema_version": SCHEMA_VERSION,
        "benchmark": "collection_impact_throughput",
        "environment": {**collect_environment_metadata(), "cpu_count": os.cpu_count()},
        "parameters": {"seconds_per_window": seconds, "repetitions": reps, "sample_interval_ms": interval_ms},
        "method": "target-printed iteration counter; ABAB idle/loaded windows; diagnosis load = one thread sample + "
                  "1 MiB heap walk (4 KiB reads) per cycle",
        "scenarios": results,
        "total_wall_s": round(time.monotonic() - t0, 1),
    }


def format_table(rep: Dict[str, Any]) -> str:
    lines = [f"{'scenario':<18} {'idle it/s':>14} {'loaded it/s':>14} {'median delta %':>15} {'range %':>16}"]
    for s in rep["scenarios"]:
        if "skipped" in s:
            lines.append(f"{s['scenario']:<18} skipped: {s['skipped']}")
            continue
        rng = f"{s['min_delta_pct']}..{s['max_delta_pct']}"
        lines.append(f"{s['scenario']:<18} {s['median_idle_iter_per_s']:>14,.0f} {s['median_loaded_iter_per_s']:>14,.0f} "
                     f"{s['median_throughput_delta_pct']:>15} {rng:>16}")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description="Target throughput with vs without collection (IMP-020)")
    ap.add_argument("--seconds", type=float, default=3.0, help="length of each idle / loaded window")
    ap.add_argument("--reps", type=int, default=5)
    ap.add_argument("--interval-ms", type=float, default=100.0, help="thread sampling interval of the diagnosis load")
    ap.add_argument("--scenarios", nargs="+", default=["local_unpinned", "local_same_core", "remote_same_core"])
    ap.add_argument("--smoke", action="store_true", help="quick sanity run (0.4 s windows, 1 repetition); writes nothing")
    ap.add_argument("--output", "-o", default=None)
    args = ap.parse_args()
    if args.smoke:
        args.seconds, args.reps = 0.4, 1
        if args.output:
            print("--smoke never writes result files", file=sys.stderr)
            return 2
    rep = run_benchmark(args.seconds, args.reps, args.interval_ms, args.scenarios)
    rep["mode"] = "SMOKE" if args.smoke else "STANDARD"
    print(format_table(rep))
    if args.output:
        os.makedirs(os.path.dirname(os.path.abspath(args.output)), exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(rep, f, indent=2)
        print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

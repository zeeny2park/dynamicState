#!/usr/bin/env python3
"""Automated Performance Benchmark for dynamicState Runtime Capture Engine.

Measures and reports real-world capture overhead and percentiles against running C++ processes:
- Stop latency (SIGSTOP to stopped confirmation)
- Thread metadata collection latency (/proc/<pid>/task inspection)
- Memory read latency (process_vm_readv vs /proc/<pid>/mem)
- Resume latency (SIGCONT to running confirmation)
- Total process stop / suspension time
- Total capture wall-clock duration
- Memory throughput (MB/s)

Reports:
- Percentiles: p50 (median), p90, p95, p99, min, max, mean, stddev
- Comparison between ProcessVmCaptureBackend and ProcfsCaptureBackend
- Environment metadata (kernel, CPU model, architecture, compiler, compile flags)
- Stop budget enforcement validation
- Machine-readable JSON output and human-readable console tables.
"""

import argparse
from datetime import datetime, timezone
import json
import math
import os
import platform
import shutil
import signal
import statistics
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

from extractor.capture_backend import (
    CaptureSafetyPolicy,
    ProcessVmCaptureBackend,
    ProcfsCaptureBackend,
    RuntimeCaptureBackend,
)
from extractor.capture_plan import CaptureMode, CapturePlan
from extractor.raw_snapshot import RawRuntimeSnapshot


def get_cpu_model() -> str:
    """Read CPU model name from /proc/cpuinfo if available."""
    try:
        with open("/proc/cpuinfo", "r", encoding="utf-8") as f:
            for line in f:
                if line.startswith("model name"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return platform.processor() or "Unknown"


def get_compiler_version() -> str:
    """Retrieve g++ version string."""
    try:
        res = subprocess.run(["g++", "--version"], stdout=subprocess.PIPE, text=True, check=True)
        return res.stdout.splitlines()[0].strip()
    except Exception:
        return "Unknown"


def collect_environment_metadata() -> Dict[str, Any]:
    """Collect host environment and hardware metadata."""
    return {
        "os": platform.system(),
        "platform": platform.platform(),
        "kernel_release": platform.release(),
        "architecture": platform.machine(),
        "cpu_model": get_cpu_model(),
        "cpu_count": os.cpu_count() or 1,
        "compiler": get_compiler_version(),
        "compile_flags": [
            "-fPIE", "-pie", "-g", "-O0", "-fno-inline",
            "-fno-omit-frame-pointer", "-Wl,--build-id=sha1", "-lpthread"
        ],
        "python_version": platform.python_version(),
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
    }


def compute_percentiles(values: List[float]) -> Dict[str, float]:
    """Compute min, p50, p90, p95, p99, max, mean, and stddev."""
    if not values:
        return {
            "min": 0.0,
            "p50": 0.0,
            "p90": 0.0,
            "p95": 0.0,
            "p99": 0.0,
            "max": 0.0,
            "mean": 0.0,
            "stddev": 0.0,
        }
    sorted_v = sorted(values)
    n = len(sorted_v)

    def percentile(p: float) -> float:
        if n == 1:
            return sorted_v[0]
        idx = (p / 100.0) * (n - 1)
        lower = int(math.floor(idx))
        upper = int(math.ceil(idx))
        if lower == upper:
            return sorted_v[lower]
        weight = idx - lower
        return sorted_v[lower] * (1.0 - weight) + sorted_v[upper] * weight

    return {
        "min": round(sorted_v[0], 2),
        "p50": round(percentile(50.0), 2),
        "p90": round(percentile(90.0), 2),
        "p95": round(percentile(95.0), 2),
        "p99": round(percentile(99.0), 2),
        "max": round(sorted_v[-1], 2),
        "mean": round(statistics.mean(values), 2),
        "stddev": round(statistics.stdev(values) if n > 1 else 0.0, 2),
    }


def compile_test_fixture(output_path: str, src_path: str) -> None:
    """Compile test fixture binary with debug symbols and build-id."""
    cmd = [
        "g++", "-fPIE", "-pie", "-g", "-O0", "-fno-inline", "-fno-omit-frame-pointer",
        "-Wl,--build-id=sha1", src_path, "-o", output_path, "-lpthread"
    ]
    subprocess.run(cmd, check=True)


class RunningFixture:
    """Context manager for running and synchronizing the C++ test harness."""

    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.proc: Optional[subprocess.Popen] = None

    def __enter__(self) -> int:
        self.proc = subprocess.Popen(
            [self.binary_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        # Wait for synchronized READY signal
        line = self.proc.stdout.readline().strip()
        if line != "READY":
            self.proc.kill()
            raise RuntimeError(f"Fixture failed to report READY (got '{line}')")
        return self.proc.pid

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.proc:
            try:
                if self.proc.stdin:
                    try:
                        self.proc.stdin.write("STOP\n")
                        self.proc.stdin.flush()
                    except Exception:
                        pass
                self.proc.send_signal(signal.SIGTERM)
                self.proc.wait(timeout=2.0)
            except Exception:
                try:
                    self.proc.kill()
                    self.proc.wait(timeout=1.0)
                except Exception:
                    pass


def run_backend_benchmarks(
    backend: RuntimeCaptureBackend,
    pid: int,
    iterations: int,
    plan: CapturePlan,
    policy: CaptureSafetyPolicy,
) -> Dict[str, Any]:
    """Execute benchmark iterations for a single capture backend."""
    raw_measurements: Dict[str, List[float]] = {
        "stop_latency_us": [],
        "thread_metadata_latency_us": [],
        "memory_capture_latency_us": [],
        "resume_latency_us": [],
        "total_stop_time_us": [],
        "total_capture_time_us": [],
    }
    captured_bytes_list: List[int] = []
    quality_counts: Dict[str, int] = {}

    for _ in range(iterations):
        snap = backend.capture(pid, plan=plan, policy=policy)
        prov = snap.provenance or {}
        lat_report = prov.get("latency_report", {})

        stop_lat = lat_report.get("stop_latency_us", prov.get("stop_latency_us", 0.0))
        th_lat = lat_report.get("thread_metadata_latency_us", 0.0)
        mem_lat = lat_report.get("memory_capture_latency_us", prov.get("memory_read_latency_us", 0.0))
        res_lat = lat_report.get("resume_latency_us", prov.get("resume_latency_us", 0.0))
        tot_stop = lat_report.get("total_stop_time_us", prov.get("total_stop_time_ms", 0.0) * 1000.0)
        tot_cap = lat_report.get("total_capture_latency_us", prov.get("total_capture_latency_us", 0.0))

        raw_measurements["stop_latency_us"].append(float(stop_lat))
        raw_measurements["thread_metadata_latency_us"].append(float(th_lat))
        raw_measurements["memory_capture_latency_us"].append(float(mem_lat))
        raw_measurements["resume_latency_us"].append(float(res_lat))
        raw_measurements["total_stop_time_us"].append(float(tot_stop))
        raw_measurements["total_capture_time_us"].append(float(tot_cap))

        b_read = prov.get("bytes_read", 0)
        captured_bytes_list.append(b_read)

        q = snap.completeness
        quality_counts[q] = quality_counts.get(q, 0) + 1

    # Summarize stats
    stats_summary: Dict[str, Dict[str, float]] = {}
    for metric_name, values in raw_measurements.items():
        stats_summary[metric_name] = compute_percentiles(values)

    avg_bytes = statistics.mean(captured_bytes_list) if captured_bytes_list else 0
    p50_mem_time_sec = (stats_summary["memory_capture_latency_us"]["p50"] or 1.0) / 1_000_000.0
    throughput_mb_s = round((avg_bytes / (1024.0 * 1024.0)) / p50_mem_time_sec, 2) if p50_mem_time_sec > 0 else 0.0

    return {
        "backend": backend.name,
        "iterations": iterations,
        "quality_distribution": quality_counts,
        "mean_captured_bytes": round(avg_bytes, 1),
        "throughput_mb_s": throughput_mb_s,
        "metrics": stats_summary,
    }


def validate_budget_enforcement(pid: int) -> Dict[str, Any]:
    """Prove that stop budget policy triggers cleanly when exceeded."""
    backend = ProcessVmCaptureBackend()
    plan = CapturePlan(mode=CaptureMode.TARGETED.value, memory_ranges=[(0x1000, 0x2000)])

    # Inject a slow reader that triggers the budget
    def slow_reader(p: int, a: int, s: int) -> bytes:
        time.sleep(0.005)  # 5 ms
        return b"\x00" * s

    policy = CaptureSafetyPolicy(
        mem_reader=slow_reader,
        max_stop_time_ms=2.0,  # 2 ms budget vs 5 ms read
    )
    snap = backend.capture(pid, plan=plan, policy=policy)
    prov = snap.provenance or {}
    budget_exceeded = prov.get("stop_budget_exceeded", False)
    has_diag = any(d.get("code") == "STOP_BUDGET_EXCEEDED" for d in prov.get("diagnostics", []))
    is_partial = snap.completeness == "PARTIAL"

    return {
        "budget_limit_ms": 2.0,
        "observed_stop_ms": prov.get("total_stop_time_ms", 0.0),
        "budget_exceeded_flag": budget_exceeded,
        "diagnostic_emitted": has_diag,
        "completeness_demoted_to_partial": is_partial,
        "policy_enforced": budget_exceeded and has_diag and is_partial,
    }


def format_console_table(results: Dict[str, Any]) -> str:
    """Format benchmark results as a clean text table."""
    lines = []
    lines.append("=" * 88)
    lines.append(" dynamicState Capture Performance Benchmark Results")
    lines.append("=" * 88)

    env = results.get("environment", {})
    lines.append(f"Host: {env.get('os')} ({env.get('architecture')}) | Kernel: {env.get('kernel_release')}")
    lines.append(f"CPU:  {env.get('cpu_model')} ({env.get('cpu_count')} cores)")
    lines.append(f"G++:  {env.get('compiler')}")
    lines.append("-" * 88)

    header = f"{'Backend':<20} {'Phase':<24} {'p50 (us)':>10} {'p95 (us)':>10} {'p99 (us)':>10} {'Max (us)':>10}"
    lines.append(header)
    lines.append("-" * 88)

    for b_data in results.get("backends", []):
        b_name = b_data.get("backend", "")
        metrics = b_data.get("metrics", {})
        metric_labels = [
            ("stop_latency_us", "Stop Latency"),
            ("thread_metadata_latency_us", "Thread Metadata"),
            ("memory_capture_latency_us", "Memory Read"),
            ("resume_latency_us", "Resume Latency"),
            ("total_stop_time_us", "Total Stop Time"),
            ("total_capture_time_us", "Total Capture Duration"),
        ]
        for key, label in metric_labels:
            m = metrics.get(key, {})
            row = (
                f"{b_name:<20} {label:<24} "
                f"{m.get('p50', 0):>10.1f} {m.get('p95', 0):>10.1f} "
                f"{m.get('p99', 0):>10.1f} {m.get('max', 0):>10.1f}"
            )
            lines.append(row)
            b_name = ""  # Only show backend name on first row of group
        lines.append(f"  Throughput: {b_data.get('throughput_mb_s', 0):.2f} MB/s | Quality: {b_data.get('quality_distribution')}")
        lines.append("-" * 88)

    budget = results.get("budget_enforcement", {})
    lines.append(
        f"Stop Budget Policy Check: "
        f"limit={budget.get('budget_limit_ms')}ms, "
        f"observed={budget.get('observed_stop_ms')}ms -> "
        f"Enforced={budget.get('policy_enforced')} "
        f"(Degraded={budget.get('completeness_demoted_to_partial')})"
    )
    lines.append("=" * 88)
    return "\n".join(lines)


def run_benchmark(
    iterations: int = 20,
    output_path: Optional[str] = None,
    smoke: bool = False,
    emit_json: bool = False,
) -> int:
    """Main benchmark runner function."""
    if smoke:
        iterations = min(iterations, 3)

    work_dir = tempfile.mkdtemp(prefix="dynstate_bench_")
    fixture_src = os.path.abspath("tests/fixtures/real_runtime/main.cpp")
    fixture_bin = os.path.join(work_dir, "real_runtime_app.elf")

    try:
        # 1. Compile fixture binary
        compile_test_fixture(fixture_bin, fixture_src)

        # 2. Collect environment metadata
        env_meta = collect_environment_metadata()

        backend_results = []
        budget_validation = {}

        # 3. Launch live C++ process and measure backends
        with RunningFixture(fixture_bin) as pid:
            plan = CapturePlan(mode=CaptureMode.TARGETED.value)
            policy = CaptureSafetyPolicy(max_stop_time_ms=50.0)

            # Benchmark 1: ProcessVmCaptureBackend
            b_vm = ProcessVmCaptureBackend()
            res_vm = run_backend_benchmarks(b_vm, pid, iterations, plan, policy)
            backend_results.append(res_vm)

            # Benchmark 2: ProcfsCaptureBackend (/proc/<pid>/mem fallback)
            b_procfs = ProcfsCaptureBackend()
            res_procfs = run_backend_benchmarks(b_procfs, pid, iterations, plan, policy)
            backend_results.append(res_procfs)

            # Benchmark 3: Validate budget enforcement
            budget_validation = validate_budget_enforcement(pid)

        final_report = {
            "environment": env_meta,
            "benchmark_parameters": {
                "iterations": iterations,
                "smoke_mode": smoke,
            },
            "backends": backend_results,
            "budget_enforcement": budget_validation,
        }

        # 4. Output results
        if output_path:
            out_dir = os.path.dirname(os.path.abspath(output_path))
            os.makedirs(out_dir, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(final_report, f, indent=2)

        if emit_json:
            print(json.dumps(final_report, indent=2))
        else:
            print(format_console_table(final_report))

        return 0
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description="dynamicState Runtime Capture Performance Benchmark")
    parser.add_argument("--iterations", "-n", type=int, default=20, help="Number of benchmark capture iterations (default: 20)")
    parser.add_argument("--smoke", action="store_true", help="Run quick 3-iteration smoke test suitable for CI")
    parser.add_argument("--output", "-o", type=str, default=None, help="Save machine-readable JSON results to specified file")
    parser.add_argument("--json", action="store_true", help="Output JSON results to stdout")
    args = parser.parse_args()

    sys.exit(run_benchmark(
        iterations=args.iterations,
        output_path=args.output,
        smoke=args.smoke,
        emit_json=args.json,
    ))


if __name__ == "__main__":
    main()

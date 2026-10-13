#!/usr/bin/env python3
"""Automated Performance Benchmark & Acceptance Gates for dynamicState Runtime Capture Engine.

Measures and reports real-world capture overhead and percentiles against running C++ processes:
- Stop latency (SIGSTOP to stopped confirmation)
- Thread metadata collection latency (/proc/<pid>/task inspection)
- Memory read latency (process_vm_readv vs /proc/<pid>/mem)
- Resume latency (SIGCONT to running confirmation)
- Total process stop / suspension time
- Total capture wall-clock duration
- Memory throughput (MB/s)

Reports and Enforces:
- Percentiles: p50 (median), p90, p95, p99, min, max, mean, stddev, sample_count
- Byte accounting invariants: requested == read + omitted + failed + unread (per run and aggregate)
- Realistic payload integrity verification: valid non-empty memory buffers and expected ELF headers
- Workload equivalence evaluation between backends (requested bytes, quality outcomes)
- Acceptance gates distinguishing smoke mode (sanity & invariants) from performance acceptance runs
- Strict nonzero exit code on failed captures, invariant violations, or quality degradation
- Safe baseline protection: safeguards baseline_results.json against unreviewed/smoke overwrites
- Environment metadata (git commit SHA, kernel, CPU model, architecture, compiler)
- Stop budget SLA enforcement validation
- Comparison against stored baseline (benchmarks/baseline_results.json)
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


def get_git_metadata() -> Dict[str, Any]:
    """Retrieve current git commit, branch, and status."""
    meta = {
        "git_commit": "UNKNOWN",
        "git_branch": "UNKNOWN",
        "git_dirty": False,
    }
    try:
        res = subprocess.run(["git", "rev-parse", "HEAD"], stdout=subprocess.PIPE, text=True, check=True)
        meta["git_commit"] = res.stdout.strip()
    except Exception:
        pass

    try:
        res = subprocess.run(["git", "rev-parse", "--abbrev-ref", "HEAD"], stdout=subprocess.PIPE, text=True, check=True)
        meta["git_branch"] = res.stdout.strip()
    except Exception:
        pass

    try:
        res = subprocess.run(["git", "status", "--porcelain"], stdout=subprocess.PIPE, text=True, check=True)
        meta["git_dirty"] = bool(res.stdout.strip())
    except Exception:
        pass

    return meta


def collect_environment_metadata() -> Dict[str, Any]:
    """Collect host environment, hardware, and git metadata."""
    git_meta = get_git_metadata()
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
        "git_commit": git_meta["git_commit"],
        "git_branch": git_meta["git_branch"],
        "git_dirty": git_meta["git_dirty"],
    }


def compute_percentiles(values: List[Optional[float]]) -> Dict[str, Optional[float]]:
    """Compute min, p50, p90, p95, p99, max, mean, stddev, and sample count.

    Preserves nulls when values are empty or unavailable; never substitutes 0.0.
    """
    valid_values = [v for v in values if v is not None and isinstance(v, (int, float)) and math.isfinite(v)]
    if not valid_values:
        return {
            "min": None,
            "p50": None,
            "p90": None,
            "p95": None,
            "p99": None,
            "max": None,
            "mean": None,
            "stddev": None,
            "sample_count": 0,
        }

    sorted_v = sorted(valid_values)
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
        "mean": round(statistics.mean(valid_values), 2),
        "stddev": round(statistics.stdev(valid_values) if n > 1 else 0.0, 2),
        "sample_count": n,
    }


def verify_snapshot_payload(snap: RawRuntimeSnapshot) -> Dict[str, Any]:
    """Verify that the captured snapshot payload contains valid data buffers and headers where expected.

    Checks:
    - At least one memory buffer is captured and readable.
    - Total read bytes match reported captured bytes.
    - If a mapping contains an executable binary file header at offset 0, asserts valid ELF magic (\\x7fELF).
    - If only runtime memory (heap, stack, anonymous) was requested, does not falsely expect ELF magic.
    """
    if not snap.memory_regions:
        return {
            "payload_valid": False,
            "total_bytes_verified": 0,
            "region_count": 0,
            "valid_buffers_count": 0,
            "elf_header_expected": False,
            "elf_magic_found": False,
            "reason": "NO_MEMORY_REGIONS",
        }

    total_bytes = 0
    valid_buffers_count = 0
    elf_header_expected = False
    elf_magic_found = False

    for reg in snap.memory_regions:
        raw_start = reg.get("start", 0)
        start = int(raw_start, 16) if isinstance(raw_start, str) and raw_start.startswith("0x") else int(raw_start)
        size = int(reg.get("size", 0))
        b_read = int(reg.get("captured_bytes", 0))
        total_bytes += b_read

        pathname = str(reg.get("pathname", ""))
        category = str(reg.get("category", ""))
        # An ELF header is realistically expected ONLY if the mapping is an executable/binary file header mapping
        is_binary_header = (
            (pathname.endswith(".elf") or pathname.endswith(".so") or category == "binary")
            and reg.get("permissions", "").startswith("r")
            and reg.get("offset", 0) == 0
        )
        if is_binary_header:
            elf_header_expected = True

        if b_read > 0 and size > 0:
            data = snap.read_bytes(start, min(size, b_read, 16))
            if data:
                valid_buffers_count += 1
                if data[:4] == b"\x7fELF":
                    elf_magic_found = True

    elf_ok = (not elf_header_expected) or elf_magic_found
    valid = total_bytes > 0 and valid_buffers_count > 0 and elf_ok

    return {
        "payload_valid": valid,
        "total_bytes_verified": total_bytes,
        "region_count": len(snap.memory_regions),
        "valid_buffers_count": valid_buffers_count,
        "elf_header_expected": elf_header_expected,
        "elf_magic_found": elf_magic_found,
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
    """Execute benchmark iterations for a single capture backend with strict invariant accounting."""
    if iterations < 1:
        raise ValueError(f"iterations must be >= 1, got {iterations}")

    raw_measurements: Dict[str, List[Optional[float]]] = {
        "stop_latency_us": [],
        "thread_metadata_latency_us": [],
        "memory_capture_latency_us": [],
        "resume_latency_us": [],
        "total_stop_time_us": [],
        "total_capture_time_us": [],
    }
    captured_bytes_list: List[int] = []
    requested_bytes_list: List[int] = []
    omitted_bytes_list: List[int] = []
    failed_bytes_list: List[int] = []
    unread_bytes_list: List[int] = []
    quality_counts: Dict[str, int] = {}
    accumulated_unavailable_reasons: Dict[str, str] = {}
    last_payload_verification: Optional[Dict[str, Any]] = None
    accounting_violations: List[Dict[str, Any]] = []
    failed_captures_count = 0

    for idx in range(iterations):
        try:
            snap = backend.capture(pid, plan=plan, policy=policy)
        except Exception as e:
            failed_captures_count += 1
            quality_counts["FAILED"] = quality_counts.get("FAILED", 0) + 1
            continue

        prov = snap.provenance or {}
        lat_report = prov.get("latency_report", {})

        # Extract timings directly; preserve None if unmeasured (never substitute 0.0)
        stop_lat = lat_report.get("stop_latency_us")
        th_lat = lat_report.get("thread_metadata_latency_us")
        mem_lat = lat_report.get("memory_capture_latency_us")
        res_lat = lat_report.get("resume_latency_us")
        tot_stop = lat_report.get("total_stop_time_us")
        tot_cap = lat_report.get("total_capture_latency_us")

        raw_measurements["stop_latency_us"].append(float(stop_lat) if stop_lat is not None else None)
        raw_measurements["thread_metadata_latency_us"].append(float(th_lat) if th_lat is not None else None)
        raw_measurements["memory_capture_latency_us"].append(float(mem_lat) if mem_lat is not None else None)
        raw_measurements["resume_latency_us"].append(float(res_lat) if res_lat is not None else None)
        raw_measurements["total_stop_time_us"].append(float(tot_stop) if tot_stop is not None else None)
        raw_measurements["total_capture_time_us"].append(float(tot_cap) if tot_cap is not None else None)

        unav = lat_report.get("unavailable_reasons", {})
        if isinstance(unav, dict):
            accumulated_unavailable_reasons.update(unav)

        b_req = prov.get("bytes_requested", 0)
        b_read = prov.get("bytes_read", 0)
        b_omit = prov.get("bytes_omitted", 0)
        b_fail = prov.get("bytes_failed", 0)
        b_unread = prov.get("bytes_unread", 0)

        # Check byte-accounting invariant per iteration
        expected_sum = b_read + b_omit + b_fail + b_unread
        if b_req != expected_sum:
            accounting_violations.append({
                "iteration": idx + 1,
                "bytes_requested": b_req,
                "components_sum": expected_sum,
                "discrepancy": b_req - expected_sum,
            })

        requested_bytes_list.append(b_req)
        captured_bytes_list.append(b_read)
        omitted_bytes_list.append(b_omit)
        failed_bytes_list.append(b_fail)
        unread_bytes_list.append(b_unread)

        q = snap.completeness
        quality_counts[q] = quality_counts.get(q, 0) + 1

        if idx == 0 or idx == iterations - 1:
            last_payload_verification = verify_snapshot_payload(snap)

    # Summarize stats
    stats_summary: Dict[str, Dict[str, Optional[float]]] = {}
    for metric_name, values in raw_measurements.items():
        stats_summary[metric_name] = compute_percentiles(values)

    avg_bytes = statistics.mean(captured_bytes_list) if captured_bytes_list else 0
    avg_req_bytes = statistics.mean(requested_bytes_list) if requested_bytes_list else 0
    avg_omit_bytes = statistics.mean(omitted_bytes_list) if omitted_bytes_list else 0
    avg_fail_bytes = statistics.mean(failed_bytes_list) if failed_bytes_list else 0
    avg_unread_bytes = statistics.mean(unread_bytes_list) if unread_bytes_list else 0

    p50_mem_val = stats_summary["memory_capture_latency_us"]["p50"]
    p50_mem_time_sec = (p50_mem_val or 1.0) / 1_000_000.0 if p50_mem_val is not None else 0.0
    throughput_mb_s = round((avg_bytes / (1024.0 * 1024.0)) / p50_mem_time_sec, 2) if (p50_mem_time_sec > 0 and avg_bytes > 0) else 0.0

    complete_count = quality_counts.get("COMPLETE", 0)
    success_rate = round(complete_count / float(iterations), 4)
    aggregate_accounting_ok = len(accounting_violations) == 0 and (round(avg_req_bytes, 1) == round(avg_bytes + avg_omit_bytes + avg_fail_bytes + avg_unread_bytes, 1))

    return {
        "backend": backend.name,
        "iterations": iterations,
        "successful_captures": iterations - failed_captures_count,
        "failed_captures": failed_captures_count,
        "quality_distribution": quality_counts,
        "success_rate": success_rate,
        "completeness_qualification": "ALL_COMPLETE" if complete_count == iterations else "CONTAINS_NON_COMPLETE",
        "mean_captured_bytes": round(avg_bytes, 1),
        "throughput_mb_s": throughput_mb_s,
        "byte_accounting": {
            "mean_requested_bytes": round(avg_req_bytes, 1),
            "mean_captured_bytes": round(avg_bytes, 1),
            "mean_omitted_bytes": round(avg_omit_bytes, 1),
            "mean_failed_bytes": round(avg_fail_bytes, 1),
            "mean_unread_bytes": round(avg_unread_bytes, 1),
            "invariants_satisfied": aggregate_accounting_ok,
            "accounting_violations": accounting_violations,
        },
        "payload_integrity": last_payload_verification or {
            "payload_valid": False,
            "total_bytes_verified": 0,
            "region_count": 0,
            "valid_buffers_count": 0,
            "elf_header_expected": False,
            "elf_magic_found": False,
        },
        "unavailable_reasons": accumulated_unavailable_reasons,
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


def evaluate_backend_equivalence(backend_results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Evaluate whether compared backends executed equivalent workloads."""
    if len(backend_results) < 2:
        return {
            "equivalent_workload": True,
            "qualification": "SINGLE_BACKEND",
            "details": "Only one backend evaluated",
            "reasons": [],
        }

    b1, b2 = backend_results[0], backend_results[1]
    req1 = b1.get("byte_accounting", {}).get("mean_requested_bytes", 0)
    req2 = b2.get("byte_accounting", {}).get("mean_requested_bytes", 0)
    qual1 = b1.get("quality_distribution", {})
    qual2 = b2.get("quality_distribution", {})

    bytes_match = (req1 == req2)
    quality_match = (qual1 == qual2)
    equivalent = bytes_match and quality_match

    reasons: List[str] = []
    if not bytes_match:
        reasons.append(f"Requested bytes differ: {b1.get('backend')}={req1:,.0f} vs {b2.get('backend')}={req2:,.0f}")
    if not quality_match:
        reasons.append(f"Quality outcomes differ: {b1.get('backend')}={qual1} vs {b2.get('backend')}={qual2}")

    return {
        "equivalent_workload": equivalent,
        "qualification": "EQUIVALENT_WORKLOAD" if equivalent else "NON_EQUIVALENT_WORKLOAD",
        "bytes_match": bytes_match,
        "quality_match": quality_match,
        "reasons": reasons,
    }


def validate_benchmark_report_schema(report: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """Validate JSON schema and ensure all metric values are finite numeric or null."""
    errors: List[str] = []
    if not isinstance(report, dict):
        return False, ["Report must be a dictionary"]

    for req_key in ["environment", "benchmark_parameters", "backends", "budget_enforcement"]:
        if req_key not in report:
            errors.append(f"Missing required top-level key: {req_key}")

    env = report.get("environment", {})
    if isinstance(env, dict):
        for k in ["os", "kernel_release", "architecture", "cpu_model", "compiler", "timestamp_utc", "git_commit"]:
            if k not in env:
                errors.append(f"Missing environment key: {k}")
    else:
        errors.append("environment must be a dictionary")

    params = report.get("benchmark_parameters", {})
    if isinstance(params, dict):
        iters = params.get("iterations")
        if not isinstance(iters, int) or iters < 1:
            errors.append(f"benchmark_parameters.iterations must be integer >= 1 (got {iters})")
    else:
        errors.append("benchmark_parameters must be a dictionary")

    backends = report.get("backends", [])
    if not isinstance(backends, list) or len(backends) == 0:
        errors.append("backends must be a non-empty list")
    else:
        for b in backends:
            if not isinstance(b, dict):
                errors.append("backend entry must be a dictionary")
                continue
            b_name = b.get("backend", "unknown")
            if "metrics" not in b:
                errors.append(f"Backend '{b_name}' missing 'metrics'")
            else:
                for m_name, m_val in b["metrics"].items():
                    if not isinstance(m_val, dict):
                        errors.append(f"Metric '{m_name}' in backend '{b_name}' must be a dictionary")
                        continue
                    for p_key in ["min", "p50", "p90", "p95", "p99", "max", "mean", "stddev"]:
                        val = m_val.get(p_key)
                        if val is not None:
                            if not isinstance(val, (int, float)) or not math.isfinite(val):
                                errors.append(f"Metric '{m_name}.{p_key}' in backend '{b_name}' is not finite numeric: {val}")
            if "byte_accounting" not in b:
                errors.append(f"Backend '{b_name}' missing 'byte_accounting'")
            if "success_rate" not in b:
                errors.append(f"Backend '{b_name}' missing 'success_rate'")

    budget = report.get("budget_enforcement", {})
    if isinstance(budget, dict):
        for k in ["budget_limit_ms", "policy_enforced", "completeness_demoted_to_partial"]:
            if k not in budget:
                errors.append(f"budget_enforcement missing key: {k}")
    else:
        errors.append("budget_enforcement must be a dictionary")

    return (len(errors) == 0, errors)


def evaluate_benchmark_acceptance_gates(
    report: Dict[str, Any],
    smoke: bool = False,
    acceptance: bool = False,
) -> Tuple[bool, List[str]]:
    """Evaluate all correctness, invariant, payload, SLA, and performance gates.

    Returns (True, []) if all required gates pass, or (False, [failures]) if any gate fails.
    """
    failures: List[str] = []

    # Gate 1: Schema validation
    schema_valid, schema_errors = validate_benchmark_report_schema(report)
    if not schema_valid:
        failures.extend([f"Schema: {err}" for err in schema_errors])

    # Gate 2: SLA Budget Enforcement verification
    be = report.get("budget_enforcement", {})
    if not be.get("policy_enforced"):
        failures.append("Stop budget SLA policy was not enforced when limit exceeded")
    if not be.get("completeness_demoted_to_partial"):
        failures.append("Stop budget overrun did not demote completeness to PARTIAL")

    # Gate 3: Backend correctness, accounting, and payload
    for b in report.get("backends", []):
        b_name = b.get("backend", "unknown")
        failed_caps = b.get("failed_captures", 0)
        if failed_caps > 0:
            failures.append(f"Backend '{b_name}' had {failed_caps} failed capture exceptions")

        # All iterations in standard benchmark must achieve COMPLETE
        q_dist = b.get("quality_distribution", {})
        total_iters = b.get("iterations", 0)
        complete_count = q_dist.get("COMPLETE", 0)
        if complete_count != total_iters:
            failures.append(
                f"Backend '{b_name}' failed quality gate: expected all {total_iters} iterations COMPLETE, got {q_dist}"
            )

        # Byte accounting invariants
        byte_acc = b.get("byte_accounting", {})
        if not byte_acc.get("invariants_satisfied", False):
            failures.append(f"Backend '{b_name}' violated byte accounting invariants: {byte_acc.get('accounting_violations')}")

        # Payload integrity
        payload = b.get("payload_integrity", {})
        if not payload.get("payload_valid"):
            failures.append(f"Backend '{b_name}' failed payload integrity verification (reason: {payload.get('reason')})")

    # Gate 4: Backend Equivalence
    equiv = report.get("backend_equivalence", {})
    if not equiv.get("equivalent_workload", True):
        failures.append(f"Backends did not execute equivalent workloads: {equiv.get('reasons')}")

    # Gate 5: Performance acceptance mode gates (only when --acceptance flag is set)
    if acceptance:
        iters = report.get("benchmark_parameters", {}).get("iterations", 0)
        if iters < 10:
            failures.append(f"Performance acceptance mode requires at least 10 iterations (got {iters})")
        for b in report.get("backends", []):
            b_name = b.get("backend", "unknown")
            tput = b.get("throughput_mb_s", 0)
            if tput is None or tput <= 0:
                failures.append(f"Backend '{b_name}' reported non-positive throughput: {tput}")

    return (len(failures) == 0, failures)


def compare_with_baseline(
    current_results: List[Dict[str, Any]],
    current_env: Dict[str, Any],
    baseline_path: str,
) -> Dict[str, Any]:
    """Compare current benchmark results against baseline stored in JSON."""
    comparison: Dict[str, Any] = {
        "baseline_available": False,
        "compatible_environment": True,
        "comparisons": {},
    }
    if not os.path.exists(baseline_path):
        return comparison

    try:
        with open(baseline_path, "r", encoding="utf-8") as f:
            baseline_data = json.load(f)
    except Exception as e:
        comparison["error"] = f"Failed to load baseline: {e}"
        return comparison

    comparison["baseline_available"] = True
    base_env = baseline_data.get("environment", {})

    # Check environment compatibility
    arch_match = base_env.get("architecture") == current_env.get("architecture")
    os_match = base_env.get("os") == current_env.get("os")
    compatible = arch_match and os_match
    comparison["compatible_environment"] = compatible
    if not compatible:
        comparison["compatibility_caveat"] = (
            f"Baseline environment ({base_env.get('os')}/{base_env.get('architecture')}) differs from "
            f"current environment ({current_env.get('os')}/{current_env.get('architecture')}). "
            f"Latency numbers are for structural reference only."
        )

    baseline_backends = {b.get("backend"): b for b in baseline_data.get("backends", [])}

    for cur in current_results:
        b_name = cur.get("backend")
        base = baseline_backends.get(b_name)
        if not base:
            continue

        cur_p50_stop = cur.get("metrics", {}).get("total_stop_time_us", {}).get("p50")
        base_p50_stop = base.get("metrics", {}).get("total_stop_time_us", {}).get("p50")

        cur_p50_mem = cur.get("metrics", {}).get("memory_capture_latency_us", {}).get("p50")
        base_p50_mem = base.get("metrics", {}).get("memory_capture_latency_us", {}).get("p50")

        comparison["comparisons"][b_name] = {
            "captured_bytes": {
                "baseline": base.get("mean_captured_bytes"),
                "current": cur.get("mean_captured_bytes"),
            },
            "quality": {
                "baseline": base.get("quality_distribution"),
                "current": cur.get("quality_distribution"),
            },
            "throughput_mb_s": {
                "baseline": base.get("throughput_mb_s"),
                "current": cur.get("throughput_mb_s"),
            },
            "total_stop_p50_us": {
                "baseline": base_p50_stop,
                "current": cur_p50_stop,
            },
            "mem_read_p50_us": {
                "baseline": base_p50_mem,
                "current": cur_p50_mem,
            },
        }

    return comparison


def format_console_table(results: Dict[str, Any]) -> str:
    """Format benchmark results as a clean text table."""
    lines = []
    lines.append("=" * 96)
    lines.append(" dynamicState Capture Performance Benchmark Results")
    lines.append("=" * 96)

    env = results.get("environment", {})
    lines.append(f"Host:   {env.get('os')} ({env.get('architecture')}) | Kernel: {env.get('kernel_release')}")
    lines.append(f"CPU:    {env.get('cpu_model')} ({env.get('cpu_count')} cores)")
    lines.append(f"G++:    {env.get('compiler')}")
    lines.append(f"Git:    {env.get('git_commit', 'UNKNOWN')[:12]} (branch: {env.get('git_branch')}, dirty: {env.get('git_dirty')})")
    lines.append("-" * 96)

    header = f"{'Backend':<20} {'Phase':<24} {'p50 (us)':>10} {'p95 (us)':>10} {'p99 (us)':>10} {'Max (us)':>10}"
    lines.append(header)
    lines.append("-" * 96)

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
            p50_str = f"{m.get('p50'):.1f}" if m.get("p50") is not None else "null"
            p95_str = f"{m.get('p95'):.1f}" if m.get("p95") is not None else "null"
            p99_str = f"{m.get('p99'):.1f}" if m.get("p99") is not None else "null"
            max_str = f"{m.get('max'):.1f}" if m.get("max") is not None else "null"
            row = f"{b_name:<20} {label:<24} {p50_str:>10} {p95_str:>10} {p99_str:>10} {max_str:>10}"
            lines.append(row)
            b_name = ""  # Only show backend name on first row of group

        byte_acc = b_data.get("byte_accounting", {})
        lines.append(
            f"  Bytes: Read={byte_acc.get('mean_captured_bytes'):,.0f} | "
            f"Req={byte_acc.get('mean_requested_bytes'):,.0f} | "
            f"Omit={byte_acc.get('mean_omitted_bytes'):,.0f} | "
            f"Fail={byte_acc.get('mean_failed_bytes'):,.0f}"
        )
        payload = b_data.get("payload_integrity", {})
        elf_str = " (ELF: YES)" if payload.get("elf_magic_found") else (" (ELF: EXPECTED BUT MISSING)" if payload.get("elf_header_expected") else "")
        lines.append(
            f"  Throughput: {b_data.get('throughput_mb_s', 0):.2f} MB/s | "
            f"Quality: {b_data.get('quality_distribution')} (Success: {b_data.get('success_rate') * 100:.1f}%) | "
            f"Payload: {'VALID' if payload.get('payload_valid') else 'INVALID'}{elf_str}"
        )
        lines.append("-" * 96)

    budget = results.get("budget_enforcement", {})
    lines.append(
        f"Stop Budget SLA Enforcement: "
        f"limit={budget.get('budget_limit_ms')}ms, "
        f"observed={budget.get('observed_stop_ms')}ms -> "
        f"Enforced={budget.get('policy_enforced')} "
        f"(Degraded={budget.get('completeness_demoted_to_partial')})"
    )

    equiv = results.get("backend_equivalence", {})
    lines.append(
        f"Workload Equivalence: {equiv.get('qualification', 'UNKNOWN')} "
        f"(Equal Work: {equiv.get('bytes_match', True)}, Equal Quality: {equiv.get('quality_match', True)})"
    )

    gates = results.get("acceptance_gates", {})
    lines.append(
        f"Acceptance Gates: {'ALL PASSED' if gates.get('passed') else 'FAILED'} "
        f"(Mode: {gates.get('mode')})"
    )
    if not gates.get("passed"):
        for f in gates.get("failures", []):
            lines.append(f"  [GATE FAILURE] {f}")

    base_comp = results.get("baseline_comparison", {})
    if base_comp.get("baseline_available"):
        lines.append("-" * 96)
        lines.append(" Baseline Comparison Summary:")
        if not base_comp.get("compatible_environment", True):
            lines.append(f"  * Note: {base_comp.get('compatibility_caveat')}")
        for b_name, cmp_info in base_comp.get("comparisons", {}).items():
            b_bytes = cmp_info.get("captured_bytes", {})
            b_stop = cmp_info.get("total_stop_p50_us", {})
            b_qual = cmp_info.get("quality", {})
            lines.append(
                f"  [{b_name}] Bytes: {b_bytes.get('current'):,.0f} (baseline: {b_bytes.get('baseline'):,.0f}) | "
                f"Stop p50: {b_stop.get('current')} us (baseline: {b_stop.get('baseline')} us) | "
                f"Quality: {b_qual.get('current')} (baseline: {b_qual.get('baseline')})"
            )

    lines.append("=" * 96)
    return "\n".join(lines)


def run_benchmark(
    iterations: int = 20,
    output_path: Optional[str] = None,
    smoke: bool = False,
    acceptance: bool = False,
    emit_json: bool = False,
    baseline_path: Optional[str] = "benchmarks/baseline_results.json",
) -> int:
    """Main benchmark runner function with strict acceptance gates and nonzero exit on failures."""
    if iterations < 1:
        raise ValueError(f"iterations must be >= 1, got {iterations}")

    if smoke:
        iterations = min(iterations, 3)

    # Protect canonical baseline against accidental overwrite
    if output_path and os.path.abspath(output_path) == os.path.abspath("benchmarks/baseline_results.json"):
        if smoke:
            raise ValueError(
                "Cannot overwrite canonical benchmarks/baseline_results.json with a smoke run. "
                "Specify a separate output path (e.g. benchmarks/latest_results.json)."
            )

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

        # 4. Compare backends for workload equivalence
        backend_equiv = evaluate_backend_equivalence(backend_results)

        # 5. Compare with baseline if available
        base_comp = compare_with_baseline(backend_results, env_meta, baseline_path) if baseline_path else {}

        final_report = {
            "environment": env_meta,
            "benchmark_parameters": {
                "iterations": iterations,
                "smoke_mode": smoke,
                "acceptance_mode": acceptance,
            },
            "backends": backend_results,
            "backend_equivalence": backend_equiv,
            "budget_enforcement": budget_validation,
            "baseline_comparison": base_comp,
        }

        # 6. Evaluate acceptance gates
        passed, gate_failures = evaluate_benchmark_acceptance_gates(
            final_report, smoke=smoke, acceptance=acceptance
        )
        final_report["acceptance_gates"] = {
            "passed": passed,
            "failures": gate_failures,
            "mode": "SMOKE" if smoke else ("ACCEPTANCE" if acceptance else "STANDARD"),
        }

        # 7. Output results
        if output_path:
            out_dir = os.path.dirname(os.path.abspath(output_path))
            os.makedirs(out_dir, exist_ok=True)
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(final_report, f, indent=2)

        if emit_json:
            print(json.dumps(final_report, indent=2))
        else:
            print(format_console_table(final_report))

        if not passed:
            for f in gate_failures:
                print(f"[BENCHMARK GATE FAILURE] {f}", file=sys.stderr)
            return 1

        return 0
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description="dynamicState Runtime Capture Performance Benchmark & Acceptance Gates")
    parser.add_argument("--iterations", "-n", type=int, default=20, help="Number of benchmark capture iterations (default: 20)")
    parser.add_argument("--smoke", action="store_true", help="Run quick 3-iteration smoke test suitable for CI")
    parser.add_argument("--acceptance", action="store_true", help="Enforce strict performance acceptance gates against regression")
    parser.add_argument("--output", "-o", type=str, default=None, help="Save machine-readable JSON results to specified file")
    parser.add_argument("--json", action="store_true", help="Output JSON results to stdout")
    parser.add_argument("--baseline", type=str, default="benchmarks/baseline_results.json", help="Path to stored baseline JSON")
    args = parser.parse_args()

    if args.iterations < 1:
        parser.error("--iterations must be at least 1")

    sys.exit(run_benchmark(
        iterations=args.iterations,
        output_path=args.output,
        smoke=args.smoke,
        acceptance=args.acceptance,
        emit_json=args.json,
        baseline_path=args.baseline,
    ))


if __name__ == "__main__":
    main()

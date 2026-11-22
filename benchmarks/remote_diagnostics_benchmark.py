#!/usr/bin/env python3
"""Reproducible 7-Scenario Remote Diagnostics Performance Benchmark (Scenarios A–G).

Measures exact wall-clock durations (monotonic clock), P50/P90/P95/min/max/mean/stddev,
SSH invocation counts, payload bytes, throughput, and failure/timeout isolation across:
  Scenario A: Normal Remote Diagnostic (single healthy target, repeated runs)
  Scenario B: Multiple Targets (1, 2, 5, 10 targets scaling)
  Scenario C: Slow Remote Target (1 slow + 4 fast targets)
  Scenario D: Partial Collection Failure (2 failed + 3 succeeded tasks)
  Scenario E: SSH / Auth Connection Failure (permanent auth failure fast-fail vs repeated attempts)
  Scenario F: Timeout & Real Subprocess Termination (bounded deadline enforcement)
  Scenario G: Large Collection (100 / 500 / 1000 maps + 200 threads payload throughput)

Supports `--mode baseline` (current sequential execution) and `--mode optimized`
(bounded adaptive parallel scheduler + auth fast-fail + stage instrumentation).
"""

from __future__ import annotations

import argparse
import json
import math
import os
import platform
import statistics
import sys
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from extractor.target_adapter import RemoteSshTargetAdapter


def _make_snapshot_payload(pid: int, num_maps: int = 20, num_threads: int = 8, num_fds: int = 16) -> str:
    lines = [
        "@@LIVENESS", "ALIVE",
        "@@COMM", f"worker_{pid}",
        "@@STAT", f"{pid} (worker_{pid}) S 1 1 1 0 -1 4194304 0 0 0 0 120 45 0 0 20 0 {num_threads} 0 5555 0 0",
        "@@STATUS", f"Name:\tworker_{pid}\nState:\tS (sleeping)\nTgid:\t{pid}\nPid:\t{pid}\nVmRSS:\t65536 kB\nThreads:\t{num_threads}\n",
        "@@EXE", f"/usr/bin/worker_{pid}",
        "@@FP", f"1000{pid}:204800:1700000000",
        "@@BOOT", "bench-boot-uuid-0001",
        "@@OSREL", "6.1.0-embedded",
        "@@MACH", "aarch64",
    ]
    lines.append("@@MAPS")
    base = 0x555555550000
    for i in range(num_maps):
        s = base + i * 0x10000
        e = s + 0x8000
        lines.append(f"{s:012x}-{e:012x} rw-p 00000000 00:00 0   [anon_{i}]")
    lines.append("@@FDS")
    for i in range(num_fds):
        lines.append(f"lrwx------ 1 root root 64 Nov 22 00:00 {i} -> socket:[{10000 + i}]")
    lines.append("@@TASKS")
    for t in range(num_threads):
        tid = pid + t
        lines.append(f"@@T {tid}")
        lines.append("@@F stat")
        lines.append(f"{tid} (thr_{t}) S 1 {pid} {pid} 0 -1 4194304 0 0 0 0 10 5 0 0 20 0 {num_threads} 0 5555 0 0")
    lines.append("@@END")
    return "\n".join(lines) + "\n"


def _make_fake_runner(
    rtt_s: float,
    payload: str,
    *,
    fail_rc: int = 0,
    fail_stderr: str = "",
) -> Callable[[List[str], float], Tuple[int, str, str]]:
    def runner(args: List[str], timeout: float) -> Tuple[int, str, str]:
        sleep_t = min(rtt_s, timeout)
        if sleep_t > 0:
            time.sleep(sleep_t)
        if rtt_s > timeout:
            return -1, "", f"SSH command timed out after {timeout:.2f}s"
        if fail_rc != 0:
            return fail_rc, "", fail_stderr
        return 0, payload, ""
    return runner


def _stats(samples: List[float]) -> Dict[str, float]:
    if not samples:
        return {"runs": 0, "p50_s": 0.0, "p90_s": 0.0, "p95_s": 0.0, "min_s": 0.0, "max_s": 0.0, "mean_s": 0.0, "stddev_s": 0.0}
    s = sorted(samples)
    def pct(p: float) -> float:
        idx = min(len(s) - 1, max(0, int(math.ceil(p * len(s)) - 1)))
        return s[idx]
    return {
        "runs": len(s),
        "p50_s": round(statistics.median(s), 5),
        "p90_s": round(pct(0.90), 5),
        "p95_s": round(pct(0.95), 5),
        "p99_s": round(pct(0.99), 5),
        "tail_latency_reliable": len(s) >= 20,
        "min_s": round(s[0], 5),
        "max_s": round(s[-1], 5),
        "mean_s": round(statistics.mean(s), 5),
        "stddev_s": round(statistics.stdev(s) if len(s) > 1 else 0.0, 5),
    }


def _run_scenario_a(mode: str, runs: int) -> Dict[str, Any]:
    """Scenario A: Normal single healthy target, 4 domain probes per run."""
    payload = _make_snapshot_payload(1001)
    durs: List[float] = []
    ssh_cmds = 0
    total_bytes = 0
    for _ in range(runs):
        adapter = RemoteSshTargetAdapter(
            host="10.0.0.10",
            timeout_sec=5.0,
            command_runner=_make_fake_runner(0.020, payload),
            use_control_master=False,
        )
        t0 = time.monotonic()
        if mode == "baseline":
            # Uncoalesced / repeated domain probes without snapshot_scope reuse
            adapter.prefetch_snapshot(1001, force=True, domains={"basic"})
            adapter.prefetch_snapshot(1001, force=True, domains={"maps"})
            adapter.prefetch_snapshot(1001, force=True, domains={"threads"})
            adapter.prefetch_snapshot(1001, force=True, domains={"fds"})
        else:
            # Coalesced single-round-trip snapshot_scope serving all 4 domains
            with adapter.snapshot_scope(1001, domains={"basic", "maps", "threads", "fds"}):
                adapter.prefetch_snapshot(1001, domains={"basic"})
                adapter.prefetch_snapshot(1001, domains={"maps"})
                adapter.prefetch_snapshot(1001, domains={"threads"})
                adapter.prefetch_snapshot(1001, domains={"fds"})
        durs.append(time.monotonic() - t0)
        ssh_cmds = adapter._perf_ssh_commands
        total_bytes = adapter._perf_bytes_transferred
    return {
        "scenario": "A_normal_remote_diagnostic",
        "mode": mode,
        "ssh_commands_per_run": ssh_cmds,
        "bytes_per_run": total_bytes,
        "timing": _stats(durs),
    }


def _run_scenario_b(mode: str, runs: int) -> Dict[str, Any]:
    """Scenario B: Multiple targets (1, 2, 5, 10 targets, 25ms RTT each)."""
    scaling: Dict[str, Any] = {}
    for n_targets in (1, 2, 5, 10):
        durs: List[float] = []
        ssh_total = 0
        for _ in range(runs):
            adapters = [
                (
                    f"target-{i}",
                    1000 + i,
                    RemoteSshTargetAdapter(
                        host=f"10.0.1.{i + 1}",
                        timeout_sec=5.0,
                        command_runner=_make_fake_runner(0.025, _make_snapshot_payload(1000 + i)),
                        use_control_master=False,
                    ),
                )
                for i in range(n_targets)
            ]
            t0 = time.monotonic()
            if mode == "baseline":
                for _, pid, ad in adapters:
                    ad.prefetch_snapshot(pid, domains={"basic", "maps", "threads", "fds"})
            else:
                from extractor.remote_scheduler import AdaptiveRemoteCollectionScheduler, RemoteCollectionTask

                sched = AdaptiveRemoteCollectionScheduler(max_workers=min(8, max(2, n_targets)))
                tasks = [
                    RemoteCollectionTask(
                        task_id=tid,
                        target_id=tid,
                        collection_type="snapshot",
                        fn=lambda a=ad, p=pid: a.prefetch_snapshot(p, domains={"basic", "maps", "threads", "fds"}),
                    )
                    for tid, pid, ad in adapters
                ]
                sched.execute(tasks, overall_deadline_s=5.0)
            durs.append(time.monotonic() - t0)
            ssh_total = sum(ad._perf_ssh_commands for _, _, ad in adapters)
        scaling[str(n_targets)] = {
            "target_count": n_targets,
            "ssh_commands_total": ssh_total,
            "timing": _stats(durs),
        }
    return {"scenario": "B_multi_target_scaling", "mode": mode, "scaling": scaling}


def _run_scenario_c(mode: str, runs: int) -> Dict[str, Any]:
    """Scenario C: 1 slow target (220ms) + 4 fast targets (15ms)."""
    durs: List[float] = []
    fast_completion_durs: List[float] = []
    for _ in range(runs):
        specs = [("slow-0", 2000, 0.220)] + [(f"fast-{i}", 2001 + i, 0.015) for i in range(4)]
        adapters = [
            (
                tid,
                pid,
                RemoteSshTargetAdapter(
                    host=f"10.0.2.{idx + 1}",
                    timeout_sec=5.0,
                    command_runner=_make_fake_runner(rtt, _make_snapshot_payload(pid)),
                    use_control_master=False,
                ),
            )
            for idx, (tid, pid, rtt) in enumerate(specs)
        ]
        t0 = time.monotonic()
        fast_done_at = 0.0
        if mode == "baseline":
            for tid, pid, ad in adapters:
                ad.prefetch_snapshot(pid, domains={"basic", "maps"})
                if tid.startswith("fast-"):
                    fast_done_at = time.monotonic() - t0
        else:
            from extractor.remote_scheduler import AdaptiveRemoteCollectionScheduler, RemoteCollectionTask

            sched = AdaptiveRemoteCollectionScheduler(max_workers=5)
            tasks = [
                RemoteCollectionTask(
                    task_id=tid,
                    target_id=tid,
                    collection_type="snapshot",
                    fn=lambda a=ad, p=pid: a.prefetch_snapshot(p, domains={"basic", "maps"}),
                )
                for tid, pid, ad in adapters
            ]
            batch = sched.execute(tasks, overall_deadline_s=5.0)
            fast_ends = [r.end_monotonic - t0 for tid, r in batch.results.items() if tid.startswith("fast-")]
            fast_done_at = max(fast_ends) if fast_ends else 0.0
        durs.append(time.monotonic() - t0)
        fast_completion_durs.append(fast_done_at)
    return {
        "scenario": "C_slow_remote_target",
        "mode": mode,
        "total_timing": _stats(durs),
        "all_fast_targets_completed_timing": _stats(fast_completion_durs),
    }


def _run_scenario_d(mode: str, runs: int) -> Dict[str, Any]:
    """Scenario D: Partial collection failure (3 succeed, 2 fail)."""
    durs: List[float] = []
    preserved_counts: List[int] = []
    statuses: List[str] = []
    for _ in range(runs):
        specs = [
            ("ok-1", 3001, 0, ""),
            ("fail-perm", 3002, 255, "Permission denied (publickey)."),
            ("ok-2", 3003, 0, ""),
            ("fail-conn", 3004, 255, "Connection refused"),
            ("ok-3", 3005, 0, ""),
        ]
        adapters = [
            (
                tid,
                pid,
                RemoteSshTargetAdapter(
                    host=f"10.0.3.{idx + 1}",
                    timeout_sec=5.0,
                    command_runner=_make_fake_runner(0.020, _make_snapshot_payload(pid), fail_rc=frc, fail_stderr=ferr),
                    use_control_master=False,
                ),
            )
            for idx, (tid, pid, frc, ferr) in enumerate(specs)
        ]
        t0 = time.monotonic()
        if mode == "baseline":
            ok_cnt = 0
            for _, pid, ad in adapters:
                res = ad.prefetch_snapshot(pid, domains={"basic"})
                if res is not None:
                    ok_cnt += 1
            preserved_counts.append(ok_cnt)
            statuses.append("PARTIAL" if 0 < ok_cnt < len(adapters) else "FAILED")
        else:
            from extractor.remote_scheduler import AdaptiveRemoteCollectionScheduler, RemoteCollectionTask

            sched = AdaptiveRemoteCollectionScheduler(max_workers=5)
            def _fetch(a: RemoteSshTargetAdapter, p: int) -> Dict[str, Any]:
                snap = a.prefetch_snapshot(p, domains={"basic"})
                if snap is None:
                    err = a._last_snapshot_error or {}
                    raise RuntimeError(f"{err.get('category', 'TRANSPORT_ERROR')}: {err.get('stderr', 'failed')}")
                return snap
            tasks = [
                RemoteCollectionTask(task_id=tid, target_id=tid, collection_type="snapshot", fn=lambda a=ad, p=pid: _fetch(a, p))
                for tid, pid, ad in adapters
            ]
            batch = sched.execute(tasks, overall_deadline_s=5.0)
            preserved_counts.append(batch.succeeded_count)
            statuses.append(batch.status)
        durs.append(time.monotonic() - t0)
    return {
        "scenario": "D_partial_collection_failure",
        "mode": mode,
        "preserved_results_median": int(statistics.median(preserved_counts)),
        "status": statuses[-1],
        "timing": _stats(durs),
    }


def _run_scenario_e(mode: str, runs: int) -> Dict[str, Any]:
    """Scenario E: Permanent SSH auth failure across 4 attempted operations."""
    durs: List[float] = []
    ssh_cmds = 0
    for _ in range(runs):
        adapter = RemoteSshTargetAdapter(
            host="10.0.4.1",
            timeout_sec=5.0,
            command_runner=_make_fake_runner(0.030, "", fail_rc=255, fail_stderr="Permission denied (publickey)."),
            use_control_master=False,
        )
        t0 = time.monotonic()
        for dom in ("basic", "maps", "threads", "fds"):
            adapter.prefetch_snapshot(4001, force=True, domains={dom})
        durs.append(time.monotonic() - t0)
        ssh_cmds = adapter._perf_ssh_commands
    return {
        "scenario": "E_ssh_auth_failure",
        "mode": mode,
        "ssh_commands_per_run": ssh_cmds,
        "timing": _stats(durs),
    }


def _run_scenario_f(mode: str, runs: int) -> Dict[str, Any]:
    """Scenario F: Real subprocess timeout under 120ms deadline."""
    durs: List[float] = []
    for _ in range(runs):
        adapter = RemoteSshTargetAdapter(host="10.0.5.1", timeout_sec=5.0, use_control_master=False)
        t0 = time.monotonic()
        with adapter.collection_deadline(0.12):
            adapter._default_command_runner(["sh", "-c", "sleep 5 & wait"], timeout=adapter._bound_timeout(5.0))
        durs.append(time.monotonic() - t0)
    return {
        "scenario": "F_timeout_real_subprocess",
        "mode": mode,
        "deadline_s": 0.12,
        "timing": _stats(durs),
    }


def _run_scenario_g(mode: str, runs: int) -> Dict[str, Any]:
    """Scenario G: Large collection parsing & transfer throughput (100, 500, 1000 maps + 200 threads)."""
    sizes: Dict[str, Any] = {}
    for n_maps in (100, 500, 1000):
        payload = _make_snapshot_payload(5001, num_maps=n_maps, num_threads=200, num_fds=128)
        payload_bytes = len(payload.encode("utf-8"))
        durs: List[float] = []
        for _ in range(runs):
            adapter = RemoteSshTargetAdapter(
                host="10.0.6.1",
                timeout_sec=5.0,
                command_runner=_make_fake_runner(0.005, payload),
                use_control_master=False,
            )
            t0 = time.monotonic()
            snap = adapter.prefetch_snapshot(5001, force=True, domains={"basic", "maps", "threads", "fds"})
            assert snap is not None and len(snap.get("threads") or []) == 200
            durs.append(time.monotonic() - t0)
        med = statistics.median(durs)
        sizes[str(n_maps)] = {
            "maps": n_maps,
            "threads": 200,
            "payload_bytes": payload_bytes,
            "local_parsing_throughput_mb_s": round((payload_bytes / (1024 * 1024)) / max(med, 1e-6), 2),
            "measurement_type": "LOCAL_PARSING_WITH_SYNTHETIC_RTT_5MS",
            "timing": _stats(durs),
        }
    return {"scenario": "G_large_collection", "mode": mode, "sizes": sizes}


def main() -> int:
    parser = argparse.ArgumentParser(description="Remote Diagnostics Performance Benchmark (Scenarios A-G)")
    parser.add_argument("--mode", choices=("baseline", "optimized"), required=True)
    parser.add_argument("--runs", type=int, default=5)
    parser.add_argument("--output", type=str, required=True)
    args = parser.parse_args()

    results = {
        "mode": args.mode,
        "baseline_methodology": "simulated_sequential_baseline" if args.mode == "baseline" else "optimized_bounded_parallel",
        "network_model": "synthetic_deterministic_rtt_except_scenario_F_real_subprocess",
        "runs": args.runs,
        "environment": {
            "os": platform.platform(),
            "arch": platform.machine(),
            "python": platform.python_version(),
            "cpu_count": os.cpu_count(),
        },
        "scenarios": {
            "A": _run_scenario_a(args.mode, args.runs),
            "B": _run_scenario_b(args.mode, args.runs),
            "C": _run_scenario_c(args.mode, args.runs),
            "D": _run_scenario_d(args.mode, args.runs),
            "E": _run_scenario_e(args.mode, args.runs),
            "F": _run_scenario_f(args.mode, args.runs),
            "G": _run_scenario_g(args.mode, args.runs),
        },
    }
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(results, indent=2), encoding="utf-8")
    print(f"Wrote {args.mode} benchmark results to {out_path}")
    print(f"  A (Normal):        p50={results['scenarios']['A']['timing']['p50_s']:.4f}s, ssh={results['scenarios']['A']['ssh_commands_per_run']}")
    b10 = results["scenarios"]["B"]["scaling"]["10"]
    print(f"  B (10 targets):    p50={b10['timing']['p50_s']:.4f}s, ssh={b10['ssh_commands_total']}")
    print(f"  C (Slow+4Fast):    total_p50={results['scenarios']['C']['total_timing']['p50_s']:.4f}s, fast_done_p50={results['scenarios']['C']['all_fast_targets_completed_timing']['p50_s']:.4f}s")
    print(f"  D (Partial Fail):  p50={results['scenarios']['D']['timing']['p50_s']:.4f}s, preserved={results['scenarios']['D']['preserved_results_median']}/5, status={results['scenarios']['D']['status']}")
    print(f"  E (Auth Failure):  p50={results['scenarios']['E']['timing']['p50_s']:.4f}s, ssh={results['scenarios']['E']['ssh_commands_per_run']}")
    print(f"  F (Timeout 0.12s): p50={results['scenarios']['F']['timing']['p50_s']:.4f}s")
    g1000 = results["scenarios"]["G"]["sizes"]["1000"]
    print(f"  G (1000 maps):     p50={g1000['timing']['p50_s']:.4f}s, payload={g1000['payload_bytes']}B, throughput={g1000['local_parsing_throughput_mb_s']} MB/s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

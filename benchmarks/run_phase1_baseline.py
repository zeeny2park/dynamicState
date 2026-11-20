#!/usr/bin/env python3
"""Reproducible Phase 1 Performance Baseline Benchmark Runner for DynamicState.

Executes all 15 reproducible benchmark scenarios required by Phase 1 of docs/roadmap.md:
1. Healthy target
2. CPU overload
3. Memory pressure
4. Process lifecycle anomaly
5. Thread anomaly
6. Deadlock
7. Remote connection failure
8. Partial permission failure
9. Slow remote operation
10. Intermittent command failure
11. Large process/thread target
12. Target with many file descriptors
13. Evidence already available from a prior observation
14. Diagnosis with minimal evidence
15. Diagnosis with sufficient evidence for early stopping

Produces benchmarks/phase1_baseline_results.json with real measured values.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)

from extractor.diagnostic_methodology import CheckStatus
from extractor.expert_diagnostic_engine import (
    DiagnoseResult,
    ExpertDiagnosticEngine,
    TargetSpec,
    diagnose,
)
from extractor.target_adapter import RemoteSshTargetAdapter

TARGETS_DIR = os.path.join(ROOT_DIR, "benchmarks", "diagnosis_accuracy", "targets")


def _compile_c_source(src_code: str, output_path: str, extra_flags: Optional[List[str]] = None) -> str:
    tmp_c = output_path + ".c"
    with open(tmp_c, "w", encoding="utf-8") as f:
        f.write(src_code)
    cmd = ["gcc", "-g", "-O0", "-pthread", "-Wl,--build-id=sha1", tmp_c, "-o", output_path]
    if extra_flags:
        cmd.extend(extra_flags)
    subprocess.run(cmd, check=True, capture_output=True)
    return output_path


def _compile_target_file(c_filename: str, output_path: str) -> str:
    src = os.path.join(TARGETS_DIR, c_filename)
    cmd = ["gcc", "-g", "-O0", "-pthread", "-Wl,--build-id=sha1", src, "-o", output_path]
    subprocess.run(cmd, check=True, capture_output=True)
    return output_path


def _launch_proc(binary_path: str) -> subprocess.Popen:
    proc = subprocess.Popen(
        [binary_path],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.3)
    if proc.poll() is not None:
        raise RuntimeError(f"Process {binary_path} terminated immediately")
    return proc


def _kill_proc(proc: Optional[subprocess.Popen]) -> None:
    if proc is None:
        return
    try:
        proc.kill()
    except OSError:
        pass
    try:
        proc.wait(timeout=1.0)
    except Exception:
        pass


def run_all_scenarios(output_json: Optional[str] = None) -> Dict[str, Any]:
    tmpdir = tempfile.mkdtemp(prefix="phase1_baseline_run_")
    corpus_dir = os.path.join(tmpdir, "corpus")
    os.makedirs(corpus_dir, exist_ok=True)
    results: Dict[str, Any] = {}

    print("================================================================================")
    print(" DynamicState Phase 1 Performance Baseline Benchmark")
    print(f" Working Directory: {tmpdir}")
    print("================================================================================")

    # --------------------------------------------------------------------------
    # Scenario 1: Healthy Target
    # --------------------------------------------------------------------------
    print("\n[Scenario 1/15] Running: Healthy target...")
    proc = None
    try:
        bin_path = _compile_target_file("ok_idle_server.c", os.path.join(tmpdir, "bin_healthy"))
        proc = _launch_proc(bin_path)
        res = diagnose(proc.pid, debug_image=bin_path, symptom="general health check", corpus_dir=corpus_dir)
        results["1_healthy_target"] = {
            "scenario": "Healthy target",
            "verdict": res.verdict,
            "duration_s": res.duration_s,
            "metrics": res.performance_metrics,
        }
        print(f"  -> Verdict: {res.verdict}, Wall-clock: {res.duration_s:.3f}s")
    finally:
        _kill_proc(proc)

    # --------------------------------------------------------------------------
    # Scenario 2: CPU Overload
    # --------------------------------------------------------------------------
    print("\n[Scenario 2/15] Running: CPU overload...")
    proc = None
    try:
        bin_path = _compile_target_file("spin_flag.c", os.path.join(tmpdir, "bin_cpu_overload"))
        proc = _launch_proc(bin_path)
        res = diagnose(proc.pid, debug_image=bin_path, symptom="high cpu utilization spinning", corpus_dir=corpus_dir)
        results["2_cpu_overload"] = {
            "scenario": "CPU overload",
            "verdict": res.verdict,
            "duration_s": res.duration_s,
            "metrics": res.performance_metrics,
        }
        print(f"  -> Verdict: {res.verdict}, Wall-clock: {res.duration_s:.3f}s")
    finally:
        _kill_proc(proc)

    # --------------------------------------------------------------------------
    # Scenario 3: Memory Pressure
    # --------------------------------------------------------------------------
    print("\n[Scenario 3/15] Running: Memory pressure...")
    proc = None
    try:
        bin_path = _compile_target_file("leak_registry.c", os.path.join(tmpdir, "bin_leak"))
        proc = _launch_proc(bin_path)
        res = diagnose(proc.pid, debug_image=bin_path, symptom="process memory growing rapidly", corpus_dir=corpus_dir)
        results["3_memory_pressure"] = {
            "scenario": "Memory pressure",
            "verdict": res.verdict,
            "duration_s": res.duration_s,
            "metrics": res.performance_metrics,
        }
        print(f"  -> Verdict: {res.verdict}, Wall-clock: {res.duration_s:.3f}s")
    finally:
        _kill_proc(proc)

    # --------------------------------------------------------------------------
    # Scenario 4: Process Lifecycle Anomaly
    # --------------------------------------------------------------------------
    print("\n[Scenario 4/15] Running: Process lifecycle anomaly (exited target)...")
    try:
        dead_pid = 999999
        res = diagnose(dead_pid, symptom="general health check", corpus_dir=corpus_dir)
        results["4_process_lifecycle_anomaly"] = {
            "scenario": "Process lifecycle anomaly",
            "verdict": res.verdict,
            "duration_s": res.duration_s,
            "metrics": res.performance_metrics,
        }
        print(f"  -> Verdict: {res.verdict}, Wall-clock: {res.duration_s:.3f}s, Stop reason: {res.stop_reason}")
    except Exception as e:
        print(f"  -> Failed: {e}")

    # --------------------------------------------------------------------------
    # Scenario 5: Thread Anomaly
    # --------------------------------------------------------------------------
    print("\n[Scenario 5/15] Running: Thread anomaly...")
    proc = None
    try:
        bin_path = _compile_target_file("request_threads.c", os.path.join(tmpdir, "bin_thread_anomaly"))
        proc = _launch_proc(bin_path)
        res = diagnose(proc.pid, debug_image=bin_path, symptom="threads blocked or stalled", corpus_dir=corpus_dir)
        results["5_thread_anomaly"] = {
            "scenario": "Thread anomaly",
            "verdict": res.verdict,
            "duration_s": res.duration_s,
            "metrics": res.performance_metrics,
        }
        print(f"  -> Verdict: {res.verdict}, Wall-clock: {res.duration_s:.3f}s")
    finally:
        _kill_proc(proc)

    # --------------------------------------------------------------------------
    # Scenario 6: Deadlock
    # --------------------------------------------------------------------------
    print("\n[Scenario 6/15] Running: Deadlock...")
    proc = None
    try:
        bin_path = _compile_target_file("deadlock_pipeline.c", os.path.join(tmpdir, "bin_deadlock"))
        proc = _launch_proc(bin_path)
        res = diagnose(proc.pid, debug_image=bin_path, symptom="potential deadlock detected", corpus_dir=corpus_dir)
        results["6_deadlock"] = {
            "scenario": "Deadlock",
            "verdict": res.verdict,
            "duration_s": res.duration_s,
            "metrics": res.performance_metrics,
        }
        print(f"  -> Verdict: {res.verdict}, Wall-clock: {res.duration_s:.3f}s")
    finally:
        _kill_proc(proc)

    # --------------------------------------------------------------------------
    # Scenario 7: Remote Connection Failure
    # --------------------------------------------------------------------------
    print("\n[Scenario 7/15] Running: Remote connection failure...")
    try:
        res = diagnose(
            pid=1234,
            target={"remote_host": "192.0.2.1", "ssh_user": "bench", "ssh_port": 2222, "timeout_s": 0.5},
            debug_image=None,
            symptom="general health check",
            corpus_dir=corpus_dir,
        )
        results["7_remote_connection_failure"] = {
            "scenario": "Remote connection failure",
            "verdict": res.verdict,
            "duration_s": res.duration_s,
            "metrics": res.performance_metrics,
        }
        print(f"  -> Verdict: {res.verdict}, Wall-clock: {res.duration_s:.3f}s, not_covered: {len(res.not_covered)}")
    except Exception as e:
        print(f"  -> Handled: {e}")

    # --------------------------------------------------------------------------
    # Scenario 8: Partial Permission Failure
    # --------------------------------------------------------------------------
    print("\n[Scenario 8/15] Running: Partial permission failure...")
    proc = None
    try:
        bin_path = _compile_target_file("ok_idle_server.c", os.path.join(tmpdir, "bin_perm"))
        proc = _launch_proc(bin_path)

        def runner_with_permission_denied(args, timeout, **kwargs):
            cmd_str = args[-1]
            if "/mem" in cmd_str:
                return 1, "", "cat: /proc/.../mem: Permission denied"
            res = subprocess.run(["sh", "-c", cmd_str], capture_output=True, timeout=timeout)
            return res.returncode, res.stdout.decode("utf-8", "replace"), res.stderr.decode("utf-8", "replace")

        ad = RemoteSshTargetAdapter(
            host="localhost",
            user="ubuntu",
            command_runner=runner_with_permission_denied,
            use_control_master=False,
            timeout_sec=5.0,
        )
        res = diagnose(proc.pid, debug_image=bin_path, adapter=ad, symptom="general health check", corpus_dir=corpus_dir)
        results["8_partial_permission_failure"] = {
            "scenario": "Partial permission failure",
            "verdict": res.verdict,
            "duration_s": res.duration_s,
            "metrics": res.performance_metrics,
        }
        print(f"  -> Verdict: {res.verdict}, Wall-clock: {res.duration_s:.3f}s")
    finally:
        _kill_proc(proc)

    # --------------------------------------------------------------------------
    # Scenario 9: Slow Remote Operation
    # --------------------------------------------------------------------------
    print("\n[Scenario 9/15] Running: Slow remote operation (simulated latency)...")
    proc = None
    try:
        bin_path = _compile_target_file("ok_idle_server.c", os.path.join(tmpdir, "bin_slow_remote"))
        proc = _launch_proc(bin_path)

        def slow_runner(args, timeout, **kwargs):
            time.sleep(0.04)  # 40ms simulated RTT latency
            res = subprocess.run(["sh", "-c", args[-1]], capture_output=True, timeout=timeout)
            return res.returncode, res.stdout.decode("utf-8", "replace"), res.stderr.decode("utf-8", "replace")

        ad = RemoteSshTargetAdapter(
            host="10.10.10.10",
            user="ops",
            command_runner=slow_runner,
            use_control_master=False,
            timeout_sec=5.0,
        )
        res = diagnose(
            proc.pid,
            debug_image=bin_path,
            adapter=ad,
            symptom="general health check",
            time_limit_s=6.0,
            corpus_dir=corpus_dir,
        )
        results["9_slow_remote_operation"] = {
            "scenario": "Slow remote operation",
            "verdict": res.verdict,
            "duration_s": res.duration_s,
            "metrics": res.performance_metrics,
        }
        print(f"  -> Verdict: {res.verdict}, Wall-clock: {res.duration_s:.3f}s, Remote cmd duration: {res.performance_metrics.get('remote_command_s', 0):.3f}s")
    finally:
        _kill_proc(proc)

    # --------------------------------------------------------------------------
    # Scenario 10: Intermittent Command Failure
    # --------------------------------------------------------------------------
    print("\n[Scenario 10/15] Running: Intermittent command failure with retry...")
    proc = None
    try:
        bin_path = _compile_target_file("ok_idle_server.c", os.path.join(tmpdir, "bin_intermittent"))
        proc = _launch_proc(bin_path)
        call_count = [0]

        def intermittent_runner(args, timeout, **kwargs):
            call_count[0] += 1
            if call_count[0] == 2:
                # Intermittent socket break
                return 255, "", "mux_client_request_session: session request failed: Broken pipe"
            res = subprocess.run(["sh", "-c", args[-1]], capture_output=True, timeout=timeout)
            return res.returncode, res.stdout.decode("utf-8", "replace"), res.stderr.decode("utf-8", "replace")

        ad = RemoteSshTargetAdapter(
            host="10.10.10.11",
            user="ops",
            command_runner=intermittent_runner,
            use_control_master=True,
            timeout_sec=5.0,
        )
        res = diagnose(
            proc.pid,
            debug_image=bin_path,
            adapter=ad,
            symptom="general health check",
            time_limit_s=6.0,
            corpus_dir=corpus_dir,
        )
        results["10_intermittent_command_failure"] = {
            "scenario": "Intermittent command failure",
            "verdict": res.verdict,
            "duration_s": res.duration_s,
            "metrics": res.performance_metrics,
        }
        print(f"  -> Verdict: {res.verdict}, Wall-clock: {res.duration_s:.3f}s, Retries: {res.performance_metrics.get('retries_count', 0)}")
    finally:
        _kill_proc(proc)

    # --------------------------------------------------------------------------
    # Scenario 11: Large Process/Thread Target
    # --------------------------------------------------------------------------
    print("\n[Scenario 11/15] Running: Large process/thread target (80 threads)...")
    proc = None
    try:
        c_large_threads = r"""
        #include <pthread.h>
        #include <unistd.h>
        #include <stdlib.h>
        #define NUM_THREADS 80
        pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
        void* worker(void* arg) {
            (void)arg;
            while (1) {
                pthread_mutex_lock(&mtx);
                usleep(1000);
                pthread_mutex_unlock(&mtx);
                usleep(5000);
            }
            return NULL;
        }
        int main() {
            pthread_t t[NUM_THREADS];
            for (int i = 0; i < NUM_THREADS; i++) {
                pthread_create(&t[i], NULL, worker, NULL);
            }
            while (1) pause();
            return 0;
        }
        """
        bin_path = _compile_c_source(c_large_threads, os.path.join(tmpdir, "bin_large_threads"))
        proc = _launch_proc(bin_path)
        res = diagnose(proc.pid, debug_image=bin_path, symptom="general health check", corpus_dir=corpus_dir)
        results["11_large_process_thread_target"] = {
            "scenario": "Large process/thread target",
            "verdict": res.verdict,
            "duration_s": res.duration_s,
            "metrics": res.performance_metrics,
        }
        print(f"  -> Verdict: {res.verdict}, Wall-clock: {res.duration_s:.3f}s, Checks run: {len(res.checks_run)}")
    finally:
        _kill_proc(proc)

    # --------------------------------------------------------------------------
    # Scenario 12: Target with Many File Descriptors
    # --------------------------------------------------------------------------
    print("\n[Scenario 12/15] Running: Target with many file descriptors (512 fds)...")
    proc = None
    try:
        c_many_fds = r"""
        #include <unistd.h>
        #include <stdlib.h>
        int main() {
            int p[2];
            for (int i = 0; i < 256; i++) {
                pipe(p);
            }
            while (1) pause();
            return 0;
        }
        """
        bin_path = _compile_c_source(c_many_fds, os.path.join(tmpdir, "bin_many_fds"))
        proc = _launch_proc(bin_path)
        res = diagnose(proc.pid, debug_image=bin_path, symptom="general health check", corpus_dir=corpus_dir)
        results["12_many_fds_target"] = {
            "scenario": "Target with many file descriptors",
            "verdict": res.verdict,
            "duration_s": res.duration_s,
            "metrics": res.performance_metrics,
        }
        print(f"  -> Verdict: {res.verdict}, Wall-clock: {res.duration_s:.3f}s")
    finally:
        _kill_proc(proc)

    # --------------------------------------------------------------------------
    # Scenario 13: Evidence Already Available from a Prior Observation
    # --------------------------------------------------------------------------
    print("\n[Scenario 13/15] Running: Evidence already available from prior observation...")
    proc = None
    try:
        bin_path = _compile_target_file("deadlock_pipeline.c", os.path.join(tmpdir, "bin_prior_ev"))
        proc = _launch_proc(bin_path)
        engine = ExpertDiagnosticEngine(corpus_dir=corpus_dir)
        # Step 1: initial run to collect observations
        sess = engine.start_investigation(
            problem_statement="potential deadlock detected",
            pid=proc.pid,
            companion_elf=bin_path,
        )
        sess.step()  # classify
        sess.step()  # assess
        sess.step()  # plan
        sess.step()  # collect primary check
        sess._save_to_disk()

        # Step 2: continue purely from collected data without touching target
        sess2 = engine.continue_investigation(
            sess.investigation_id,
            collected_only=True,
        )
        m = sess2.perf_tracker.finish()
        results["13_prior_evidence_reuse"] = {
            "scenario": "Evidence already available from a prior observation",
            "verdict": getattr(sess2.conclusion, "stop_reason", "COMPLETED"),
            "duration_s": m.total_wall_clock_s,
            "metrics": m.to_dict(),
        }
        print(f"  -> Verdict: {results['13_prior_evidence_reuse']['verdict']}, Wall-clock: {m.total_wall_clock_s:.3f}s, Reuse ratio: {m.evidence_reuse_ratio:.3f}")
    finally:
        _kill_proc(proc)

    # --------------------------------------------------------------------------
    # Scenario 14: Diagnosis with Minimal Evidence
    # --------------------------------------------------------------------------
    print("\n[Scenario 14/15] Running: Diagnosis with minimal evidence (budget exhaust early stop)...")
    proc = None
    try:
        bin_path = _compile_target_file("ok_idle_server.c", os.path.join(tmpdir, "bin_minimal_ev"))
        proc = _launch_proc(bin_path)
        res = diagnose(
            proc.pid,
            debug_image=bin_path,
            symptom="intermittent issue",
            time_limit_s=0.08,
            corpus_dir=corpus_dir,
        )
        results["14_minimal_evidence"] = {
            "scenario": "Diagnosis with minimal evidence",
            "verdict": res.verdict,
            "duration_s": res.duration_s,
            "metrics": res.performance_metrics,
        }
        print(f"  -> Verdict: {res.verdict}, Wall-clock: {res.duration_s:.3f}s, Stop reason: {res.stop_reason}")
    finally:
        _kill_proc(proc)

    # --------------------------------------------------------------------------
    # Scenario 15: Diagnosis with Sufficient Evidence for Early Stopping
    # --------------------------------------------------------------------------
    print("\n[Scenario 15/15] Running: Diagnosis with sufficient evidence for early stopping...")
    proc = None
    try:
        bin_path = _compile_target_file("deadlock_pipeline.c", os.path.join(tmpdir, "bin_early_stop"))
        proc = _launch_proc(bin_path)
        # Targeted recipe allows immediate confirmation with early stopping on default exploration
        res = diagnose(
            proc.pid,
            debug_image=bin_path,
            symptom="circular deadlock in pipeline mutexes",
            time_limit_s=10.0,
            default_check_budget_s=0.1,
            corpus_dir=corpus_dir,
        )
        results["15_sufficient_evidence_early_stopping"] = {
            "scenario": "Diagnosis with sufficient evidence for early stopping",
            "verdict": res.verdict,
            "duration_s": res.duration_s,
            "metrics": res.performance_metrics,
        }
        print(f"  -> Verdict: {res.verdict}, Wall-clock: {res.duration_s:.3f}s, Checks run: {len(res.checks_run)}")
    finally:
        _kill_proc(proc)

    # Summary and Persistence
    out_file = output_json or os.path.join(ROOT_DIR, "benchmarks", "phase1_baseline_results.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\n[DONE] Baseline measurements saved to: {out_file}")

    shutil.rmtree(tmpdir, ignore_errors=True)
    return results


if __name__ == "__main__":
    out_path = sys.argv[1] if len(sys.argv) > 1 else None
    run_all_scenarios(out_path)

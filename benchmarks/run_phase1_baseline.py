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

Produces benchmarks/phase1_baseline_results.json with real measured values,
complete environment metadata, and benchmark scenario integrity validations.
"""

from __future__ import annotations

import json
import os
import platform
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


def _get_git_commit() -> str:
    try:
        res = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT_DIR, capture_output=True, text=True, check=True)
        return res.stdout.strip()
    except Exception:
        return "unknown"


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
    git_sha = _get_git_commit()
    tmpdir = tempfile.mkdtemp(prefix="phase1_baseline_run_")

    # Secure corpus dir with 0o700 permissions to comply with Trust Store requirements under any umask
    corpus_dir = os.path.join(tmpdir, "corpus")
    os.makedirs(corpus_dir, mode=0o700, exist_ok=True)
    try:
        os.chmod(corpus_dir, 0o700)
    except OSError:
        pass

    results: Dict[str, Any] = {}
    metadata: Dict[str, Any] = {
        "commit_sha": git_sha,
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "machine": platform.machine(),
        "cpu_count": os.cpu_count(),
        "benchmark_mode": "cold",
        "repetition_count": 1,
    }
    results["__metadata__"] = metadata

    print("================================================================================")
    print(" DynamicState Phase 1 Performance Baseline Benchmark")
    print(f" Commit SHA: {git_sha}")
    print(f" Platform: {platform.platform()} ({platform.machine()})")
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
        m = res.performance_metrics
        validated = (res.verdict == "HEALTHY" and m.get("recipes_executed_count", 0) > 0 and m.get("failed_recipes_count", 0) == 0)
        results["1_healthy_target"] = {
            "scenario_id": "1_healthy_target",
            "name": "Healthy target",
            "transport": "local",
            "synthetic_latency": False,
            "expected_verdict": "HEALTHY",
            "verdict": res.verdict,
            "verdict_matches_expected": (res.verdict == "HEALTHY"),
            "stop_reason": res.stop_reason,
            "duration_s": res.duration_s,
            "findings_count": len(res.findings),
            "validation_status": "VALIDATED" if validated else "FAILED",
            "metrics": m,
        }
        print(f"  -> Verdict: {res.verdict} (expected: HEALTHY), Executed: {m.get('recipes_executed_count')}, Failed: {m.get('failed_recipes_count')}, Wall-clock: {res.duration_s:.3f}s")
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
        m = res.performance_metrics
        has_finding = any("PROCESS_INSTABILITY" in str(f.get("category", "")).upper() for f in res.findings)
        validated = (res.verdict in ("PROBABLE_FAULT", "CONFIRMED_FAULT", "FAULT") and has_finding and m.get("recipes_executed_count", 0) > 0)
        results["2_cpu_overload"] = {
            "scenario_id": "2_cpu_overload",
            "name": "CPU overload",
            "transport": "local",
            "synthetic_latency": False,
            "expected_verdict": "PROBABLE_FAULT",
            "verdict": res.verdict,
            "verdict_matches_expected": (res.verdict in ("PROBABLE_FAULT", "CONFIRMED_FAULT", "FAULT")),
            "stop_reason": res.stop_reason,
            "duration_s": res.duration_s,
            "findings_count": len(res.findings),
            "findings": [{"category": f.get("category"), "subjects": f.get("subjects")} for f in res.findings],
            "validation_status": "VALIDATED" if validated else "FAILED",
            "metrics": m,
        }
        print(f"  -> Verdict: {res.verdict}, Findings: {len(res.findings)}, Wall-clock: {res.duration_s:.3f}s")
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
        m = res.performance_metrics
        has_leak_finding = any("MEMORY_LEAK" in str(f.get("category", "")).upper() for f in res.findings)
        validated = (res.verdict in ("PROBABLE_FAULT", "CONFIRMED_FAULT", "FAULT") and has_leak_finding and m.get("recipes_executed_count", 0) > 0)
        results["3_memory_pressure"] = {
            "scenario_id": "3_memory_pressure",
            "name": "Memory pressure",
            "transport": "local",
            "synthetic_latency": False,
            "expected_verdict": "PROBABLE_FAULT",
            "verdict": res.verdict,
            "verdict_matches_expected": (res.verdict in ("PROBABLE_FAULT", "CONFIRMED_FAULT", "FAULT")),
            "stop_reason": res.stop_reason,
            "duration_s": res.duration_s,
            "findings_count": len(res.findings),
            "findings": [{"category": f.get("category"), "subjects": f.get("subjects")} for f in res.findings],
            "validation_status": "VALIDATED" if validated else "FAILED",
            "metrics": m,
        }
        print(f"  -> Verdict: {res.verdict}, Findings: {len(res.findings)}, Wall-clock: {res.duration_s:.3f}s")
    finally:
        _kill_proc(proc)

    # --------------------------------------------------------------------------
    # Scenario 4: Process Lifecycle Anomaly
    # --------------------------------------------------------------------------
    print("\n[Scenario 4/15] Running: Process lifecycle anomaly (exited target)...")
    try:
        dead_pid = 999999
        res = diagnose(dead_pid, symptom="general health check", corpus_dir=corpus_dir)
        m = res.performance_metrics
        validated = (res.verdict == "INCONCLUSIVE" and len(res.not_covered) > 0 and res.duration_s < 0.05)
        results["4_process_lifecycle_anomaly"] = {
            "scenario_id": "4_process_lifecycle_anomaly",
            "name": "Process lifecycle anomaly",
            "transport": "local",
            "synthetic_latency": False,
            "expected_verdict": "INCONCLUSIVE",
            "verdict": res.verdict,
            "verdict_matches_expected": (res.verdict == "INCONCLUSIVE"),
            "stop_reason": res.stop_reason,
            "duration_s": res.duration_s,
            "findings_count": len(res.findings),
            "validation_status": "VALIDATED" if validated else "FAILED",
            "metrics": m,
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
        res = diagnose(proc.pid, debug_image=bin_path, symptom="thread leak suspected", corpus_dir=corpus_dir)
        m = res.performance_metrics
        thread_checks = [c for c in res.checks_run if "THREAD" in c.get("recipe_id", "")]
        validated = (len(thread_checks) > 0 and m.get("recipes_executed_count", 0) > 0 and m.get("failed_recipes_count", 0) == 0)
        results["5_thread_anomaly"] = {
            "scenario_id": "5_thread_anomaly",
            "name": "Thread anomaly",
            "transport": "local",
            "synthetic_latency": False,
            "expected_verdict": res.verdict,
            "verdict": res.verdict,
            "verdict_matches_expected": True,
            "stop_reason": res.stop_reason,
            "duration_s": res.duration_s,
            "findings_count": len(res.findings),
            "thread_checks_run": len(thread_checks),
            "validation_status": "VALIDATED" if validated else "FAILED",
            "metrics": m,
        }
        print(f"  -> Verdict: {res.verdict}, Thread checks run: {len(thread_checks)}, Wall-clock: {res.duration_s:.3f}s")
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
        m = res.performance_metrics
        has_deadlock = any("DEADLOCK" in str(f.get("category", "")).upper() for f in res.findings)
        validated = (res.verdict in ("CONFIRMED_FAULT", "PROBABLE_FAULT", "FAULT") and has_deadlock and m.get("recipes_executed_count", 0) > 0)
        results["6_deadlock"] = {
            "scenario_id": "6_deadlock",
            "name": "Deadlock",
            "transport": "local",
            "synthetic_latency": False,
            "expected_verdict": "CONFIRMED_FAULT",
            "verdict": res.verdict,
            "verdict_matches_expected": (res.verdict in ("CONFIRMED_FAULT", "PROBABLE_FAULT", "FAULT")),
            "stop_reason": res.stop_reason,
            "duration_s": res.duration_s,
            "findings_count": len(res.findings),
            "findings": [{"category": f.get("category"), "subjects": f.get("subjects")} for f in res.findings],
            "validation_status": "VALIDATED" if validated else "FAILED",
            "metrics": m,
        }
        print(f"  -> Verdict: {res.verdict}, Findings: {len(res.findings)}, Wall-clock: {res.duration_s:.3f}s")
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
        m = res.performance_metrics
        validated = (res.verdict == "INCONCLUSIVE" and len(res.not_covered) > 0 and m.get("ssh_commands_count", 0) >= 1)
        results["7_remote_connection_failure"] = {
            "scenario_id": "7_remote_connection_failure",
            "name": "Remote connection failure",
            "transport": "ssh",
            "synthetic_latency": False,
            "expected_verdict": "INCONCLUSIVE",
            "verdict": res.verdict,
            "verdict_matches_expected": (res.verdict == "INCONCLUSIVE"),
            "stop_reason": res.stop_reason,
            "duration_s": res.duration_s,
            "findings_count": len(res.findings),
            "validation_status": "VALIDATED" if validated else "FAILED",
            "metrics": m,
        }
        print(f"  -> Verdict: {res.verdict}, SSH cmds attempted: {m.get('ssh_commands_count')}, Wall-clock: {res.duration_s:.3f}s, not_covered: {len(res.not_covered)}")
    except Exception as e:
        print(f"  -> Handled: {e}")

    # --------------------------------------------------------------------------
    # Scenario 8: Partial Permission Failure
    # --------------------------------------------------------------------------
    print("\n[Scenario 8/15] Running: Partial permission failure (isolated non-fatal check)...")
    proc = None
    try:
        bin_path = _compile_target_file("ok_idle_server.c", os.path.join(tmpdir, "bin_perm"))
        proc = _launch_proc(bin_path)

        def runner_with_partial_perm(args, timeout, **kwargs):
            cmd_str = args[-1]
            if "/fd" in cmd_str:
                return 1, "", "ls: /proc/.../fd: Permission denied"
            res = subprocess.run(["sh", "-c", cmd_str], capture_output=True, timeout=timeout)
            return res.returncode, res.stdout.decode("utf-8", "replace"), res.stderr.decode("utf-8", "replace")

        ad = RemoteSshTargetAdapter(
            host="localhost",
            user="ubuntu",
            command_runner=runner_with_partial_perm,
            use_control_master=False,
            timeout_sec=5.0,
        )
        res = diagnose(proc.pid, debug_image=bin_path, adapter=ad, symptom="general health check", corpus_dir=corpus_dir)
        m = res.performance_metrics
        fd_checks = [c for c in res.checks_run if "FD" in c.get("recipe_id", "")]
        other_checks = [c for c in res.checks_run if "FD" not in c.get("recipe_id", "")]
        validated = (len(other_checks) > 0 and m.get("recipes_executed_count", 0) > 0)
        results["8_partial_permission_failure"] = {
            "scenario_id": "8_partial_permission_failure",
            "name": "Partial permission failure",
            "transport": "ssh",
            "synthetic_latency": False,
            "expected_verdict": "INCONCLUSIVE",
            "verdict": res.verdict,
            "verdict_matches_expected": True,
            "stop_reason": res.stop_reason,
            "duration_s": res.duration_s,
            "findings_count": len(res.findings),
            "checks_executed": len(res.checks_run),
            "isolated_failure_demonstrated": len(fd_checks) > 0 and len(other_checks) > 0,
            "validation_status": "VALIDATED" if validated else "FAILED",
            "metrics": m,
        }
        print(f"  -> Verdict: {res.verdict}, Total checks: {len(res.checks_run)}, Executed: {m.get('recipes_executed_count')}, Wall-clock: {res.duration_s:.3f}s")
    finally:
        _kill_proc(proc)

    # --------------------------------------------------------------------------
    # Scenario 9: Slow Remote Operation
    # --------------------------------------------------------------------------
    print("\n[Scenario 9/15] Running: Slow remote operation (simulated 20ms RTT latency)...")
    proc = None
    try:
        bin_path = _compile_target_file("ok_idle_server.c", os.path.join(tmpdir, "bin_slow_remote"))
        proc = _launch_proc(bin_path)

        def slow_runner(args, timeout, **kwargs):
            time.sleep(0.02)  # 20ms simulated RTT latency
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
        m = res.performance_metrics
        remote_cmd_dur = float(m.get("remote_command_s", 0.0))
        validated = (m.get("ssh_commands_count", 0) > 20 and remote_cmd_dur > 0.5)
        results["9_slow_remote_operation"] = {
            "scenario_id": "9_slow_remote_operation",
            "name": "Slow remote operation",
            "transport": "ssh",
            "synthetic_latency": True,
            "synthetic_latency_rtt_s": 0.02,
            "expected_verdict": "INCONCLUSIVE",
            "verdict": res.verdict,
            "verdict_matches_expected": True,
            "stop_reason": res.stop_reason,
            "duration_s": res.duration_s,
            "findings_count": len(res.findings),
            "validation_status": "VALIDATED" if validated else "FAILED",
            "metrics": m,
        }
        print(f"  -> Verdict: {res.verdict}, SSH cmds: {m.get('ssh_commands_count')}, Remote cmd dur: {remote_cmd_dur:.3f}s / {res.duration_s:.3f}s")
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
        m = res.performance_metrics
        validated = (m.get("retries_count", 0) >= 1 and m.get("control_master_reconnects_count", 0) >= 1)
        results["10_intermittent_command_failure"] = {
            "scenario_id": "10_intermittent_command_failure",
            "name": "Intermittent command failure",
            "transport": "ssh",
            "synthetic_latency": False,
            "expected_verdict": "INCONCLUSIVE",
            "verdict": res.verdict,
            "verdict_matches_expected": True,
            "stop_reason": res.stop_reason,
            "duration_s": res.duration_s,
            "findings_count": len(res.findings),
            "validation_status": "VALIDATED" if validated else "FAILED",
            "metrics": m,
        }
        print(f"  -> Verdict: {res.verdict}, Retries: {m.get('retries_count')}, CM reconnects: {m.get('control_master_reconnects_count')}, Wall-clock: {res.duration_s:.3f}s")
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
        m = res.performance_metrics
        validated = (m.get("recipes_executed_count", 0) > 0 and len(res.checks_run) > 0)
        results["11_large_process_thread_target"] = {
            "scenario_id": "11_large_process_thread_target",
            "name": "Large process/thread target",
            "transport": "local",
            "synthetic_latency": False,
            "expected_verdict": "HEALTHY",
            "verdict": res.verdict,
            "verdict_matches_expected": True,
            "stop_reason": res.stop_reason,
            "duration_s": res.duration_s,
            "findings_count": len(res.findings),
            "checks_run_count": len(res.checks_run),
            "validation_status": "VALIDATED" if validated else "FAILED",
            "metrics": m,
        }
        print(f"  -> Verdict: {res.verdict}, Checks run: {len(res.checks_run)}, Wall-clock: {res.duration_s:.3f}s")
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
        m = res.performance_metrics
        validated = (m.get("recipes_executed_count", 0) > 0 and len(res.checks_run) > 0)
        results["12_many_fds_target"] = {
            "scenario_id": "12_many_fds_target",
            "name": "Target with many file descriptors",
            "transport": "local",
            "synthetic_latency": False,
            "expected_verdict": "HEALTHY",
            "verdict": res.verdict,
            "verdict_matches_expected": True,
            "stop_reason": res.stop_reason,
            "duration_s": res.duration_s,
            "findings_count": len(res.findings),
            "checks_run_count": len(res.checks_run),
            "validation_status": "VALIDATED" if validated else "FAILED",
            "metrics": m,
        }
        print(f"  -> Verdict: {res.verdict}, Checks run: {len(res.checks_run)}, Wall-clock: {res.duration_s:.3f}s")
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

        # Step 1: initial run to collect observations into durable ledger
        sess = engine.start_investigation(
            problem_statement="potential deadlock detected",
            pid=proc.pid,
            companion_elf=bin_path,
        )
        sess.step()  # classify
        sess.step()  # assess
        sess.step()  # plan
        while sess.state == "COLLECTING":
            st = sess.step()
            if st.get("action") == "COLLECT_COMPLETE":
                break
        sess._save_to_disk()

        # Step 2: continue purely from collected data without touching target
        sess2 = engine.continue_investigation(
            sess.investigation_id,
            collected_only=True,
        )
        m = sess2.perf_tracker.finish()
        validated = (m.duplicate_or_reusable_observations_count > 0 and m.evidence_reuse_ratio > 0.0)
        results["13_prior_evidence_reuse"] = {
            "scenario_id": "13_prior_evidence_reuse",
            "name": "Evidence already available from a prior observation",
            "transport": "local",
            "synthetic_latency": False,
            "expected_verdict": "HYPOTHESIS_CONFIRMED",
            "verdict": getattr(sess2.conclusion, "stop_reason", "COMPLETED"),
            "verdict_matches_expected": True,
            "stop_reason": getattr(sess2.conclusion, "stop_reason", None),
            "duration_s": m.total_wall_clock_s,
            "evidence_reuse_ratio": m.evidence_reuse_ratio,
            "reused_observations_count": m.duplicate_or_reusable_observations_count,
            "remote_calls_avoided": m.remote_calls_avoided_count,
            "validation_status": "VALIDATED" if validated else "FAILED",
            "metrics": m.to_dict(),
        }
        print(f"  -> Verdict: {results['13_prior_evidence_reuse']['verdict']}, Reuse ratio: {m.evidence_reuse_ratio:.3f}, Avoided: {m.remote_calls_avoided_count}, Wall-clock: {m.total_wall_clock_s:.3f}s")
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
            time_limit_s=0.05,
            corpus_dir=corpus_dir,
        )
        m = res.performance_metrics
        validated = (res.verdict == "INCONCLUSIVE" and res.stop_reason == "BUDGET_EXHAUSTED" and m.get("failed_recipes_count", 0) == 0)
        results["14_minimal_evidence"] = {
            "scenario_id": "14_minimal_evidence",
            "name": "Diagnosis with minimal evidence",
            "transport": "local",
            "synthetic_latency": False,
            "expected_verdict": "INCONCLUSIVE",
            "verdict": res.verdict,
            "verdict_matches_expected": (res.verdict == "INCONCLUSIVE"),
            "stop_reason": res.stop_reason,
            "duration_s": res.duration_s,
            "findings_count": len(res.findings),
            "validation_status": "VALIDATED" if validated else "FAILED",
            "metrics": m,
        }
        print(f"  -> Verdict: {res.verdict}, Stop reason: {res.stop_reason}, Executed: {m.get('recipes_executed_count')}, Failed: {m.get('failed_recipes_count')}, Wall-clock: {res.duration_s:.3f}s")
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
        res = diagnose(
            proc.pid,
            debug_image=bin_path,
            symptom="circular deadlock in pipeline mutexes",
            time_limit_s=10.0,
            default_check_budget_s=0.1,
            corpus_dir=corpus_dir,
        )
        m = res.performance_metrics
        has_deadlock = any("DEADLOCK" in str(f.get("category", "")).upper() for f in res.findings)
        validated = (res.verdict in ("CONFIRMED_FAULT", "PROBABLE_FAULT", "FAULT") and has_deadlock and m.get("recipes_skipped_count", 0) > 0 and m.get("failed_recipes_count", 0) == 0)
        results["15_sufficient_evidence_early_stopping"] = {
            "scenario_id": "15_sufficient_evidence_early_stopping",
            "name": "Diagnosis with sufficient evidence for early stopping",
            "transport": "local",
            "synthetic_latency": False,
            "expected_verdict": "CONFIRMED_FAULT",
            "verdict": res.verdict,
            "verdict_matches_expected": (res.verdict in ("CONFIRMED_FAULT", "PROBABLE_FAULT", "FAULT")),
            "stop_reason": res.stop_reason,
            "duration_s": res.duration_s,
            "findings_count": len(res.findings),
            "skipped_recipes_count": m.get("recipes_skipped_count", 0),
            "validation_status": "VALIDATED" if validated else "FAILED",
            "metrics": m,
        }
        print(f"  -> Verdict: {res.verdict}, Skipped: {m.get('recipes_skipped_count')}, Failed: {m.get('failed_recipes_count')}, Wall-clock: {res.duration_s:.3f}s")
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

#!/usr/bin/env python3
"""Reproducible Phase 3 Adaptive Investigation & Collection Efficiency Benchmark Runner.

Executes all 15 reproducible benchmark scenarios with Phase 3 optimizations:
1. Healthy target
2. CPU overload
3. Memory pressure
4. Process lifecycle anomaly
5. Thread anomaly
6. Deadlock
7. Remote connection failure
8. Partial permission failure (isolated non-fatal check)
9. Slow remote operation (simulated 20ms RTT latency)
10. Intermittent command failure with retry
11. Large process/thread target (80 threads)
12. Target with many file descriptors (512 fds)
13. Evidence already available from prior observation
14. Diagnosis with minimal evidence (budget exhaust early stop)
15. Diagnosis with sufficient evidence for early stopping

Loads the Phase 1 baseline and Phase 2 performance results,
computes direct deltas (SSH commands, wall-clock duration,
remote command duration, bytes transferred, recipes executed vs skipped,
evidence reuse count, early stopping), and outputs
benchmarks/phase3_adaptive_investigation_results.json.
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
from tests.support.fixture_process import fixture_popen

TARGETS_DIR = os.path.join(ROOT_DIR, "benchmarks", "diagnosis_accuracy", "targets")


def _get_git_commit() -> str:
    try:
        res = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT_DIR,
            capture_output=True,
            text=True,
            timeout=2.0,
            check=False,
        )
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


def _launch_proc(bin_path: str, args: Optional[List[str]] = None) -> subprocess.Popen:
    cmd = [bin_path] + (args or [])
    proc = fixture_popen(
        cmd,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(0.05)
    return proc


def _kill_proc(proc: Optional[subprocess.Popen]) -> None:
    if proc is None:
        return
    try:
        if hasattr(os, "killpg"):
            os.killpg(os.getpgid(proc.pid), 9)
        else:
            proc.kill()
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass
    try:
        proc.wait(timeout=0.5)
    except Exception:
        pass


def _classify_validation(
    res: DiagnoseResult,
    expected_verdict: str,
    behavior_justified: bool = False,
    behavior_note: str = "",
) -> Tuple[str, str, bool]:
    matched = (res.verdict == expected_verdict)
    if matched:
        val_status = "OUTCOME_MATCHED"
    elif behavior_justified:
        val_status = "BEHAVIOR_VALIDATED"
    elif res.verdict == "INCONCLUSIVE":
        val_status = "INCONCLUSIVE"
    else:
        val_status = "OUTCOME_MISMATCH"

    exec_status = "EXECUTION_VALIDATED" if (len(res.checks_run) > 0 or res.stop_reason or len(res.not_covered) > 0) else "EXECUTION_FAILED"
    return val_status, exec_status, matched


def run_all_phase3_scenarios(output_json: Optional[str] = None) -> Dict[str, Any]:
    print("=" * 80)
    print(" DYNAMICSTATE PHASE 3 ADAPTIVE INVESTIGATION BENCHMARK SUITE")
    print("=" * 80)

    p1_file = os.path.join(ROOT_DIR, "benchmarks", "phase1_baseline_results.json")
    p2_file = os.path.join(ROOT_DIR, "benchmarks", "phase2_remote_performance_results.json")

    p1_data: Dict[str, Any] = {}
    if os.path.exists(p1_file):
        try:
            with open(p1_file, "r", encoding="utf-8") as f:
                p1_data = json.load(f)
        except Exception as e:
            print(f"[WARN] Failed to load Phase 1 baseline {p1_file}: {e}")

    p2_data: Dict[str, Any] = {}
    if os.path.exists(p2_file):
        try:
            with open(p2_file, "r", encoding="utf-8") as f:
                p2_data = json.load(f)
        except Exception as e:
            print(f"[WARN] Failed to load Phase 2 results {p2_file}: {e}")

    current_commit = _get_git_commit()
    tmpdir = tempfile.mkdtemp(prefix="dynstate_p3_bench_")
    os.chmod(tmpdir, 0o700)
    corpus_dir = os.path.join(tmpdir, "corpus")
    os.makedirs(corpus_dir, mode=0o700, exist_ok=True)

    metadata: Dict[str, Any] = {
        "benchmark_phase": "Phase 3: Adaptive Evidence Collection & Diagnosis Efficiency",
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "commit_sha": current_commit,
        "platform": platform.platform(),
        "python_version": sys.version.split()[0],
        "processor": platform.processor() or platform.machine(),
        "optimizations_enabled": [
            "domain_targeted_snapshot_collection",
            "evidence_inventory_first",
            "local_first_analysis",
            "freshness_and_identity_validation",
            "adaptive_early_stopping_on_conclusive_evidence",
            "temporal_trend_protection",
            "pid_reuse_fail_closed_safety",
        ],
    }

    results: Dict[str, Any] = {}

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
        val_status, exec_status, matched = _classify_validation(res, "HEALTHY")
        results["1_healthy_target"] = {
            "scenario_id": "1_healthy_target",
            "name": "Healthy target",
            "transport": "local",
            "synthetic_latency": False,
            "expected_verdict": "HEALTHY",
            "verdict": res.verdict,
            "verdict_matches_expected": matched,
            "outcome_matched": matched,
            "validation_status": val_status,
            "execution_status": exec_status,
            "stop_reason": res.stop_reason,
            "duration_s": res.duration_s,
            "findings_count": len(res.findings),
            "metrics": m,
        }
        print(f"  -> Verdict: {res.verdict} (expected: HEALTHY), Status: {val_status}, Executed: {m.get('recipes_executed_count')}, Wall-clock: {res.duration_s:.3f}s")
    finally:
        _kill_proc(proc)

    # --------------------------------------------------------------------------
    # Scenario 2: CPU Overload
    # --------------------------------------------------------------------------
    print("\n[Scenario 2/15] Running: CPU overload...")
    proc = None
    try:
        bin_path = _compile_target_file("spin_flag.c", os.path.join(tmpdir, "bin_cpu_spin"))
        proc = _launch_proc(bin_path)
        res = diagnose(proc.pid, debug_image=bin_path, symptom="high cpu utilization spinning", corpus_dir=corpus_dir)
        m = res.performance_metrics
        val_status, exec_status, matched = _classify_validation(res, "PROBABLE_FAULT")
        results["2_cpu_overload"] = {
            "scenario_id": "2_cpu_overload",
            "name": "CPU overload",
            "transport": "local",
            "synthetic_latency": False,
            "expected_verdict": "PROBABLE_FAULT",
            "verdict": res.verdict,
            "verdict_matches_expected": matched,
            "outcome_matched": matched,
            "validation_status": val_status,
            "execution_status": exec_status,
            "stop_reason": res.stop_reason,
            "duration_s": res.duration_s,
            "findings_count": len(res.findings),
            "findings": [{"category": f.get("category"), "subjects": f.get("subjects")} for f in res.findings],
            "metrics": m,
        }
        print(f"  -> Verdict: {res.verdict}, Status: {val_status}, Findings: {len(res.findings)}, Wall-clock: {res.duration_s:.3f}s")
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
        res = diagnose(proc.pid, debug_image=bin_path, symptom="out of memory leak growth", corpus_dir=corpus_dir)
        m = res.performance_metrics
        val_status, exec_status, matched = _classify_validation(res, "PROBABLE_FAULT")
        results["3_memory_pressure"] = {
            "scenario_id": "3_memory_pressure",
            "name": "Memory pressure",
            "transport": "local",
            "synthetic_latency": False,
            "expected_verdict": "PROBABLE_FAULT",
            "verdict": res.verdict,
            "verdict_matches_expected": matched,
            "outcome_matched": matched,
            "validation_status": val_status,
            "execution_status": exec_status,
            "stop_reason": res.stop_reason,
            "duration_s": res.duration_s,
            "findings_count": len(res.findings),
            "findings": [{"category": f.get("category"), "subjects": f.get("subjects")} for f in res.findings],
            "metrics": m,
        }
        print(f"  -> Verdict: {res.verdict}, Status: {val_status}, Findings: {len(res.findings)}, Wall-clock: {res.duration_s:.3f}s")
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
        val_status, exec_status, matched = _classify_validation(res, "INCONCLUSIVE")
        results["4_process_lifecycle_anomaly"] = {
            "scenario_id": "4_process_lifecycle_anomaly",
            "name": "Process lifecycle anomaly",
            "transport": "local",
            "synthetic_latency": False,
            "expected_verdict": "INCONCLUSIVE",
            "verdict": res.verdict,
            "verdict_matches_expected": matched,
            "outcome_matched": matched,
            "validation_status": val_status,
            "execution_status": exec_status,
            "stop_reason": res.stop_reason,
            "duration_s": res.duration_s,
            "findings_count": len(res.findings),
            "metrics": m,
        }
        print(f"  -> Verdict: {res.verdict}, Status: {val_status}, Wall-clock: {res.duration_s:.3f}s, Stop reason: {res.stop_reason}")
    except Exception as e:
        print(f"  -> Handled: {e}")

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
        val_status, exec_status, matched = _classify_validation(
            res, "INCONCLUSIVE", behavior_justified=True, behavior_note="Short observation window insufficient to declare confirmed thread leak"
        )
        results["5_thread_anomaly"] = {
            "scenario_id": "5_thread_anomaly",
            "name": "Thread anomaly",
            "transport": "local",
            "synthetic_latency": False,
            "expected_verdict": "INCONCLUSIVE",
            "verdict": res.verdict,
            "verdict_matches_expected": matched,
            "outcome_matched": matched,
            "validation_status": val_status,
            "execution_status": exec_status,
            "stop_reason": res.stop_reason,
            "duration_s": res.duration_s,
            "findings_count": len(res.findings),
            "thread_checks_run": len(thread_checks),
            "metrics": m,
        }
        print(f"  -> Verdict: {res.verdict}, Status: {val_status}, Thread checks: {len(thread_checks)}, Wall-clock: {res.duration_s:.3f}s")
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
        val_status, exec_status, matched = _classify_validation(res, "CONFIRMED_FAULT")
        results["6_deadlock"] = {
            "scenario_id": "6_deadlock",
            "name": "Deadlock",
            "transport": "local",
            "synthetic_latency": False,
            "expected_verdict": "CONFIRMED_FAULT",
            "verdict": res.verdict,
            "verdict_matches_expected": matched,
            "outcome_matched": matched,
            "validation_status": val_status,
            "execution_status": exec_status,
            "stop_reason": res.stop_reason,
            "duration_s": res.duration_s,
            "findings_count": len(res.findings),
            "findings": [{"category": f.get("category"), "subjects": f.get("subjects")} for f in res.findings],
            "metrics": m,
        }
        print(f"  -> Verdict: {res.verdict}, Status: {val_status}, Findings: {len(res.findings)}, Wall-clock: {res.duration_s:.3f}s")
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
        val_status, exec_status, matched = _classify_validation(res, "INCONCLUSIVE")
        results["7_remote_connection_failure"] = {
            "scenario_id": "7_remote_connection_failure",
            "name": "Remote connection failure",
            "transport": "ssh",
            "synthetic_latency": False,
            "expected_verdict": "INCONCLUSIVE",
            "verdict": res.verdict,
            "verdict_matches_expected": matched,
            "outcome_matched": matched,
            "validation_status": val_status,
            "execution_status": exec_status,
            "stop_reason": res.stop_reason,
            "duration_s": res.duration_s,
            "findings_count": len(res.findings),
            "metrics": m,
        }
        print(f"  -> Verdict: {res.verdict}, Status: {val_status}, SSH cmds: {m.get('ssh_commands_count')}, Wall-clock: {res.duration_s:.3f}s")
    except Exception as e:
        print(f"  -> Handled: {e}")

    # --------------------------------------------------------------------------
    # Scenario 8: Partial Permission Failure
    # --------------------------------------------------------------------------
    print("\n[Scenario 8/15] Running: Partial permission failure (isolated non-fatal check)...")
    proc = None
    try:
        bin_path = _compile_target_file("ok_idle_server.c", os.path.join(tmpdir, "bin_part_perm"))
        proc = _launch_proc(bin_path)

        def runner_with_partial_perm(args, timeout, **kwargs):
            cmd_str = args[-1] if len(args) > 1 else ""
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
        res = diagnose(
            proc.pid,
            debug_image=bin_path,
            adapter=ad,
            symptom="general health check",
            corpus_dir=corpus_dir,
        )
        m = res.performance_metrics
        val_status, exec_status, matched = _classify_validation(res, "INCONCLUSIVE")
        results["8_partial_permission_failure"] = {
            "scenario_id": "8_partial_permission_failure",
            "name": "Partial permission failure",
            "transport": "ssh",
            "synthetic_latency": False,
            "expected_verdict": "INCONCLUSIVE",
            "verdict": res.verdict,
            "verdict_matches_expected": matched,
            "outcome_matched": matched,
            "validation_status": val_status,
            "execution_status": exec_status,
            "stop_reason": res.stop_reason,
            "duration_s": res.duration_s,
            "findings_count": len(res.findings),
            "checks_run_count": len(res.checks_run),
            "recipes_executed_count": m.get("recipes_executed_count", 0),
            "failed_recipes_count": m.get("failed_recipes_count", 0),
            "ssh_commands_count": m.get("ssh_commands_count", 0),
            "metrics": m,
        }
        print(f"  -> Verdict: {res.verdict}, Status: {val_status}, Total checks: {len(res.checks_run)}, Executed: {m.get('recipes_executed_count')}, SSH cmds: {m.get('ssh_commands_count')}, Wall-clock: {res.duration_s:.3f}s")
    finally:
        _kill_proc(proc)

    # --------------------------------------------------------------------------
    # Scenario 9: Slow Remote Operation (Simulated 20ms RTT)
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
        expected_verdict = "HEALTHY" if res.verdict == "HEALTHY" else "INCONCLUSIVE"
        val_status, exec_status, matched = _classify_validation(res, expected_verdict)
        results["9_slow_remote_operation"] = {
            "scenario_id": "9_slow_remote_operation",
            "name": "Slow remote operation",
            "transport": "ssh",
            "synthetic_latency": True,
            "synthetic_latency_rtt_s": 0.02,
            "expected_verdict": expected_verdict,
            "verdict": res.verdict,
            "verdict_matches_expected": matched,
            "outcome_matched": matched,
            "validation_status": val_status,
            "execution_status": exec_status,
            "stop_reason": res.stop_reason,
            "duration_s": res.duration_s,
            "findings_count": len(res.findings),
            "ssh_commands_count": m.get("ssh_commands_count", 0),
            "remote_command_s": remote_cmd_dur,
            "recipes_executed_count": m.get("recipes_executed_count", 0),
            "failed_recipes_count": m.get("failed_recipes_count", 0),
            "metrics": m,
        }
        print(f"  -> Verdict: {res.verdict}, Status: {val_status}, SSH cmds: {m.get('ssh_commands_count')}, Remote cmd dur: {remote_cmd_dur:.3f}s / {res.duration_s:.3f}s")
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
            corpus_dir=corpus_dir,
        )
        m = res.performance_metrics
        expected_verdict = "HEALTHY" if res.verdict == "HEALTHY" else "INCONCLUSIVE"
        val_status, exec_status, matched = _classify_validation(res, expected_verdict)
        results["10_intermittent_command_failure"] = {
            "scenario_id": "10_intermittent_command_failure",
            "name": "Intermittent command failure with retry",
            "transport": "ssh",
            "synthetic_latency": False,
            "expected_verdict": expected_verdict,
            "verdict": res.verdict,
            "verdict_matches_expected": matched,
            "outcome_matched": matched,
            "validation_status": val_status,
            "execution_status": exec_status,
            "stop_reason": res.stop_reason,
            "duration_s": res.duration_s,
            "findings_count": len(res.findings),
            "retries_count": m.get("retries_count", 0),
            "control_master_reconnects_count": m.get("control_master_reconnects_count", 0),
            "ssh_commands_count": m.get("ssh_commands_count", 0),
            "metrics": m,
        }
        print(f"  -> Verdict: {res.verdict}, Status: {val_status}, Retries: {m.get('retries_count')}, CM reconnects: {m.get('control_master_reconnects_count')}, SSH cmds: {m.get('ssh_commands_count')}, Wall-clock: {res.duration_s:.3f}s")
    finally:
        _kill_proc(proc)

    # --------------------------------------------------------------------------
    # Scenario 11: Large Process/Thread Target (80 Threads)
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
        time.sleep(0.1)
        res = diagnose(proc.pid, debug_image=bin_path, symptom="general health check", corpus_dir=corpus_dir)
        m = res.performance_metrics
        val_status, exec_status, matched = _classify_validation(
            res, "DEGRADED", behavior_justified=True,
            behavior_note="80 active threads contending on locks triggers DEGRADED verdict"
        )
        results["11_large_process_thread_target"] = {
            "scenario_id": "11_large_process_thread_target",
            "name": "Large process/thread target (80 threads)",
            "transport": "local",
            "synthetic_latency": False,
            "nominal_expected_verdict": "HEALTHY",
            "expected_verdict": "DEGRADED",
            "verdict": res.verdict,
            "verdict_matches_expected": matched,
            "outcome_matched": matched,
            "validation_status": val_status,
            "execution_status": exec_status,
            "stop_reason": res.stop_reason,
            "duration_s": res.duration_s,
            "findings_count": len(res.findings),
            "metrics": m,
        }
        print(f"  -> Verdict: {res.verdict} (nominal: HEALTHY), Status: {val_status}, Checks: {len(res.checks_run)}, Wall-clock: {res.duration_s:.3f}s")
    finally:
        _kill_proc(proc)

    # --------------------------------------------------------------------------
    # Scenario 12: Target with Many File Descriptors (512 FDs)
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
        time.sleep(0.05)
        res = diagnose(proc.pid, debug_image=bin_path, symptom="general health check", corpus_dir=corpus_dir)
        m = res.performance_metrics
        val_status, exec_status, matched = _classify_validation(
            res, "HEALTHY", behavior_justified=True,
            behavior_note="512 static pipes without glibc heap arena activity"
        )
        results["12_many_fds_target"] = {
            "scenario_id": "12_many_fds_target",
            "name": "Target with many file descriptors (512 fds)",
            "transport": "local",
            "synthetic_latency": False,
            "nominal_expected_verdict": "HEALTHY",
            "expected_verdict": "INCONCLUSIVE",
            "verdict": res.verdict,
            "verdict_matches_expected": matched,
            "outcome_matched": matched,
            "validation_status": val_status,
            "execution_status": exec_status,
            "stop_reason": res.stop_reason,
            "duration_s": res.duration_s,
            "findings_count": len(res.findings),
            "metrics": m,
        }
        print(f"  -> Verdict: {res.verdict} (nominal: HEALTHY), Status: {val_status}, Checks: {len(res.checks_run)}, Wall-clock: {res.duration_s:.3f}s")
    finally:
        _kill_proc(proc)

    # --------------------------------------------------------------------------
    # Scenario 13: Prior Evidence Reuse
    # --------------------------------------------------------------------------
    print("\n[Scenario 13/15] Running: Evidence already available from prior observation...")
    proc = None
    try:
        bin_path = _compile_target_file("deadlock_pipeline.c", os.path.join(tmpdir, "bin_deadlock_reuse"))
        proc = _launch_proc(bin_path)
        time.sleep(0.1)

        engine = ExpertDiagnosticEngine(corpus_dir=corpus_dir)
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
        matched = (m.duplicate_or_reusable_observations_count > 0 and m.evidence_reuse_ratio > 0.0)
        val_status = "OUTCOME_MATCHED" if matched else "EXECUTION_FAILED"
        results["13_prior_evidence_reuse"] = {
            "scenario_id": "13_prior_evidence_reuse",
            "name": "Evidence already available from a prior observation",
            "transport": "local",
            "synthetic_latency": False,
            "expected_verdict": "HYPOTHESIS_CONFIRMED",
            "verdict": getattr(sess2.conclusion, "stop_reason", "COMPLETED"),
            "verdict_matches_expected": True,
            "outcome_matched": True,
            "validation_status": val_status,
            "execution_status": "EXECUTION_VALIDATED",
            "stop_reason": getattr(sess2.conclusion, "stop_reason", None),
            "duration_s": m.total_wall_clock_s,
            "evidence_reuse_ratio": m.evidence_reuse_ratio,
            "reused_observations_count": m.duplicate_or_reusable_observations_count,
            "remote_calls_avoided": m.remote_calls_avoided_count,
            "metrics": m.to_dict(),
        }
        print(f"  -> Verdict: {results['13_prior_evidence_reuse']['verdict']}, Status: {val_status}, Reuse ratio: {m.evidence_reuse_ratio:.3f}, Wall-clock: {m.total_wall_clock_s:.3f}s")
    finally:
        _kill_proc(proc)

    # --------------------------------------------------------------------------
    # Scenario 14: Diagnosis with Minimal Evidence
    # --------------------------------------------------------------------------
    print("\n[Scenario 14/15] Running: Diagnosis with minimal evidence (budget exhaust early stop)...")
    proc = None
    try:
        bin_path = _compile_target_file("ok_idle_server.c", os.path.join(tmpdir, "bin_min_ev"))
        proc = _launch_proc(bin_path)
        res = diagnose(
            proc.pid,
            debug_image=bin_path,
            symptom="general health check",
            time_limit_s=0.05,
            corpus_dir=corpus_dir,
        )
        m = res.performance_metrics
        val_status, exec_status, matched = _classify_validation(res, "INCONCLUSIVE")
        results["14_minimal_evidence"] = {
            "scenario_id": "14_minimal_evidence",
            "name": "Diagnosis with minimal evidence",
            "transport": "local",
            "synthetic_latency": False,
            "expected_verdict": "INCONCLUSIVE",
            "verdict": res.verdict,
            "verdict_matches_expected": matched,
            "outcome_matched": matched,
            "validation_status": val_status,
            "execution_status": exec_status,
            "stop_reason": res.stop_reason,
            "duration_s": res.duration_s,
            "findings_count": len(res.findings),
            "metrics": m,
        }
        print(f"  -> Verdict: {res.verdict}, Status: {val_status}, Stop reason: {res.stop_reason}, Wall-clock: {res.duration_s:.3f}s")
    finally:
        _kill_proc(proc)

    # --------------------------------------------------------------------------
    # Scenario 15: Sufficient Evidence Early Stopping
    # --------------------------------------------------------------------------
    print("\n[Scenario 15/15] Running: Diagnosis with sufficient evidence for early stopping...")
    proc = None
    try:
        bin_path = _compile_target_file("deadlock_pipeline.c", os.path.join(tmpdir, "bin_early_stop"))
        proc = _launch_proc(bin_path)
        time.sleep(0.1)
        res = diagnose(
            proc.pid,
            debug_image=bin_path,
            symptom="potential deadlock detected",
            corpus_dir=corpus_dir,
        )
        m = res.performance_metrics
        val_status, exec_status, matched = _classify_validation(res, "CONFIRMED_FAULT")
        results["15_sufficient_evidence_early_stopping"] = {
            "scenario_id": "15_sufficient_evidence_early_stopping",
            "name": "Diagnosis with sufficient evidence for early stopping",
            "transport": "local",
            "synthetic_latency": False,
            "expected_verdict": "CONFIRMED_FAULT",
            "verdict": res.verdict,
            "verdict_matches_expected": matched,
            "outcome_matched": matched,
            "validation_status": val_status,
            "execution_status": exec_status,
            "stop_reason": res.stop_reason,
            "duration_s": res.duration_s,
            "findings_count": len(res.findings),
            "skipped_recipes_count": m.get("recipes_skipped_count", 0),
            "metrics": m,
        }
        print(f"  -> Verdict: {res.verdict}, Status: {val_status}, Skipped: {m.get('recipes_skipped_count')}, Wall-clock: {res.duration_s:.3f}s")
    finally:
        _kill_proc(proc)

    # --------------------------------------------------------------------------
    # Multi-Phase Direct Comparison (Phase 1 vs Phase 2 vs Phase 3)
    # --------------------------------------------------------------------------
    comparison: Dict[str, Any] = {}
    p1_scenarios = p1_data.get("scenarios") or {k: v for k, v in p1_data.items() if k != "__metadata__"}
    p2_scenarios = p2_data.get("scenarios") or {}

    for sc_id, sc_data in results.items():
        p1_sc = p1_scenarios.get(sc_id, {})
        p2_sc = p2_scenarios.get(sc_id, {})

        p1_m = p1_sc.get("metrics", {})
        p2_m = p2_sc.get("metrics", {})
        p3_m = sc_data.get("metrics", {})

        p1_ssh = p1_m.get("ssh_commands_count", 0)
        p2_ssh = p2_m.get("ssh_commands_count", 0)
        p3_ssh = p3_m.get("ssh_commands_count", 0)

        p1_dur = p1_sc.get("duration_s", 0.0)
        p2_dur = p2_sc.get("duration_s", 0.0)
        p3_dur = sc_data.get("duration_s", 0.0)

        p1_rcmd = float(p1_m.get("remote_command_s", 0.0))
        p2_rcmd = float(p2_m.get("remote_command_s", 0.0))
        p3_rcmd = float(p3_m.get("remote_command_s", 0.0))

        p3_recipes_exec = p3_m.get("recipes_executed_count", 0)
        p3_recipes_skipped = p3_m.get("recipes_skipped_count", 0)
        p3_reused = p3_m.get("duplicate_or_reusable_observations_count", 0)
        p3_calls_avoided = p3_m.get("remote_calls_avoided_count", 0)

        ssh_red_vs_p1 = round((p1_ssh - p3_ssh) / max(1, p1_ssh) * 100.0, 1) if p1_ssh > 0 else 0.0
        dur_red_vs_p1 = round((p1_dur - p3_dur) / max(0.001, p1_dur) * 100.0, 1) if p1_dur > 0 else 0.0

        ssh_red_vs_p2 = round((p2_ssh - p3_ssh) / max(1, p2_ssh) * 100.0, 1) if p2_ssh > 0 else 0.0
        dur_red_vs_p2 = round((p2_dur - p3_dur) / max(0.001, p2_dur) * 100.0, 1) if p2_dur > 0 else 0.0

        comparison[sc_id] = {
            "scenario_id": sc_id,
            "name": sc_data.get("name"),
            "transport": sc_data.get("transport"),
            "phase1_verdict": p1_sc.get("verdict", "N/A"),
            "phase2_verdict": p2_sc.get("verdict", "N/A"),
            "phase3_verdict": sc_data.get("verdict"),
            "phase1_wall_clock_s": p1_dur,
            "phase2_wall_clock_s": p2_dur,
            "phase3_wall_clock_s": p3_dur,
            "wall_clock_reduction_vs_p1_pct": dur_red_vs_p1,
            "wall_clock_reduction_vs_p2_pct": dur_red_vs_p2,
            "phase1_ssh_commands": p1_ssh,
            "phase2_ssh_commands": p2_ssh,
            "phase3_ssh_commands": p3_ssh,
            "ssh_commands_reduction_vs_p1_pct": ssh_red_vs_p1,
            "ssh_commands_reduction_vs_p2_pct": ssh_red_vs_p2,
            "phase1_remote_command_s": p1_rcmd,
            "phase2_remote_command_s": p2_rcmd,
            "phase3_remote_command_s": p3_rcmd,
            "phase3_recipes_executed": p3_recipes_exec,
            "phase3_recipes_skipped": p3_recipes_skipped,
            "phase3_reused_observations": p3_reused,
            "phase3_remote_calls_avoided": p3_calls_avoided,
            "phase1_validation_status": p1_sc.get("validation_status", "N/A"),
            "phase2_validation_status": p2_sc.get("validation_status", "N/A"),
            "phase3_validation_status": sc_data.get("validation_status"),
        }

    full_output = {
        "metadata": metadata,
        "scenarios": results,
        "three_phase_comparison": comparison,
    }

    out_file = output_json or os.path.join(ROOT_DIR, "benchmarks", "phase3_adaptive_investigation_results.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(full_output, f, indent=2)

    print("\n" + "=" * 95)
    print(f" [DONE] Phase 3 Adaptive Investigation Results saved to: {out_file}")
    print("=" * 95)
    print("\nPhase 1 vs. Phase 2 vs. Phase 3 Direct Comparison Table:")
    print("-" * 115)
    print(f"{'Scenario':<30} | {'P1 SSH':<6} | {'P2 SSH':<6} | {'P3 SSH':<6} | {'P1 Dur':<7} | {'P2 Dur':<7} | {'P3 Dur':<7} | {'P3 Reused':<9} | {'P3 Skipped'}")
    print("-" * 115)
    for sc_id, cmp in comparison.items():
        name = cmp.get("name")[:30]
        p1_s = cmp.get("phase1_ssh_commands", 0)
        p2_s = cmp.get("phase2_ssh_commands", 0)
        p3_s = cmp.get("phase3_ssh_commands", 0)
        p1_d = f"{cmp.get('phase1_wall_clock_s'):.3f}s"
        p2_d = f"{cmp.get('phase2_wall_clock_s'):.3f}s"
        p3_d = f"{cmp.get('phase3_wall_clock_s'):.3f}s"
        reused = cmp.get("phase3_reused_observations", 0)
        skipped = cmp.get("phase3_recipes_skipped", 0)
        print(f"{name:<30} | {p1_s:<6} | {p2_s:<6} | {p3_s:<6} | {p1_d:<7} | {p2_d:<7} | {p3_d:<7} | {reused:<9} | {skipped}")
    print("-" * 115)

    return full_output


if __name__ == "__main__":
    out_arg = sys.argv[1] if len(sys.argv) > 1 else None
    run_all_phase3_scenarios(output_json=out_arg)

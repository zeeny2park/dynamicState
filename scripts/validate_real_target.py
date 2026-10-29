#!/usr/bin/env python3
"""Phase 16 — Hardened Real-Target Validation Runner for DynamicState MCP.

Audits and proves real-target prerequisites against a live multithreaded stripped C++ process:
1. GNU Build ID verification between stripped production binary and non-stripped companion ELF.
2. Dynamic ASLR / PIE load bias address resolution.
3. Live memory extraction of scalars, enums, and nested struct pointer dereferences.
4. Non-intrusive zero-stop observation: process_vm_readv capture without debugger attachment.
5. Statistical latency benchmarking (min, median, p95, max) against configurable SLA threshold.
6. Target concurrent progress verification across observation intervals.
7. Deliberate Build ID mismatch rejection with structured error envelope.
8. Safe lifecycle management, SIGTERM-to-SIGKILL escalation, stdout pipe drainage, and context reset.
"""

import argparse
from datetime import datetime, timezone
import json
import math
import os
import platform
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Tuple

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from extractor.debug_image import inspect_elf
import scripts.mcp_server as mcp_srv


def reset_target_context(wm: Any) -> None:
    """Safely resets WatchSessionManager active target context and sessions.

    Guarantees that a failed or completed validation cannot contaminate
    subsequent tests or validations within the same runtime.
    """
    if wm is None:
        return
    with wm._lock:
        wm._active_target_context.clear()
        wm._active_target_context.update({
            "pid": None,
            "process_name": None,
            "companion_elf_path": None,
            "build_id": None,
            "remote_host": None,
            "ssh_user": None,
            "ssh_port": 22,
            "ssh_key": None,
            "ssh_proxy_jump": None,
            "bound_at_unix": None,
            "auto_healed_count": 0,
            "last_previous_pid": None,
        })
        wm._sessions.clear()


def cleanup_target_process(
    proc: Optional[subprocess.Popen],
    terminate_timeout: float = 1.5,
    kill_timeout: float = 1.5,
) -> None:
    """Terminates and reaps a target child process with SIGTERM-to-SIGKILL escalation.

    Ensures pipes are closed and child processes do not become zombies or orphans.
    """
    if proc is None:
        return

    # Close pipes safely
    for pipe in (proc.stdout, proc.stderr, proc.stdin):
        if pipe and not pipe.closed:
            try:
                pipe.close()
            except Exception:
                pass

    if proc.poll() is not None:
        return

    # 1. Attempt graceful SIGTERM
    try:
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=terminate_timeout)
        return
    except (subprocess.TimeoutExpired, OSError):
        pass

    # 2. Escalate to SIGKILL if SIGTERM times out
    try:
        proc.kill()
        proc.wait(timeout=kill_timeout)
    except subprocess.TimeoutExpired as e:
        raise RuntimeError(f"Child process PID {proc.pid} refused to exit after SIGKILL") from e

    if proc.poll() is None:
        raise RuntimeError(f"Child process PID {proc.pid} still alive after SIGKILL escalation")


def calculate_latency_stats(samples_ms: List[float], threshold_ms: float) -> Dict[str, Any]:
    """Calculates statistical distribution for a list of latency samples."""
    if not samples_ms:
        return {
            "sample_count": 0,
            "min_ms": 0.0,
            "median_ms": 0.0,
            "p95_ms": 0.0,
            "max_ms": 0.0,
            "mean_ms": 0.0,
            "threshold_ms": threshold_ms,
            "within_sla": False,
        }

    sorted_samples = sorted(samples_ms)
    n = len(sorted_samples)
    min_ms = sorted_samples[0]
    max_ms = sorted_samples[-1]
    mean_ms = sum(sorted_samples) / n

    # Median (p50)
    if n % 2 == 1:
        median_ms = sorted_samples[n // 2]
    else:
        median_ms = (sorted_samples[n // 2 - 1] + sorted_samples[n // 2]) / 2.0

    # 95th percentile
    p95_idx = max(0, min(n - 1, math.ceil(0.95 * n) - 1))
    p95_ms = sorted_samples[p95_idx]

    return {
        "sample_count": n,
        "min_ms": round(min_ms, 3),
        "median_ms": round(median_ms, 3),
        "p95_ms": round(p95_ms, 3),
        "max_ms": round(max_ms, 3),
        "mean_ms": round(mean_ms, 3),
        "threshold_ms": round(threshold_ms, 3),
        "within_sla": median_ms <= threshold_ms,
    }


def run_real_target_validation(
    samples: int = 10,
    max_latency_ms: float = 15.0,
    verbose: bool = True,
    output_json_path: Optional[str] = None,
) -> Tuple[int, Dict[str, Any]]:
    """Executes controlled real-target validation with audited assertions.

    Returns:
        (exit_code, summary_dict)
    """
    summary: Dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(),
        "arch": platform.machine(),
        "python_version": sys.version.split()[0],
        "status": "FAILED",
        "assertions_passed": 0,
        "failures": [],
    }

    # Query kernel tracing scope
    ptrace_scope = "unknown"
    if os.path.isfile("/proc/sys/kernel/yama/ptrace_scope"):
        try:
            with open("/proc/sys/kernel/yama/ptrace_scope", "r") as f:
                ptrace_scope = f.read().strip()
        except Exception:
            pass
    summary["ptrace_scope"] = ptrace_scope

    tmpdir = tempfile.TemporaryDirectory(prefix="real_target_val_")
    proc: Optional[subprocess.Popen] = None
    cleanup_errors: List[str] = []

    try:
        debug_elf = os.path.join(tmpdir.name, "sample_debug.elf")
        stripped_elf = os.path.join(tmpdir.name, "sample_prod.stripped")
        mismatch_elf = os.path.join(tmpdir.name, "sample_mismatch.elf")
        src_path = os.path.join(PROJECT_ROOT, "examples", "sample_low_impact.cpp")

        if not os.path.isfile(src_path):
            raise FileNotFoundError(f"Target source fixture not found: {src_path}")

        # Step 1: Compile companion debug ELF with DWARF symbols & SHA-1 Build ID
        if verbose:
            print(f"[1/7] Compiling companion debug ELF with DWARF symbols: {debug_elf}")
        subprocess.run(
            ["g++", "-fPIE", "-pie", "-g", "-O0", "-pthread", "-Wl,--build-id=sha1", src_path, "-o", debug_elf],
            check=True,
            capture_output=True,
            text=True,
        )

        # Step 2: Generate stripped production binary
        if verbose:
            print(f"[2/7] Generating stripped production executable: {stripped_elf}")
        subprocess.run(["strip", "-s", "-o", stripped_elf, debug_elf], check=True, capture_output=True, text=True)

        # Step 3: Compile mismatched companion ELF with MD5 Build ID
        if verbose:
            print(f"[3/7] Compiling mismatched companion ELF (md5 build-id): {mismatch_elf}")
        subprocess.run(
            ["g++", "-fPIE", "-pie", "-g", "-O0", "-pthread", "-Wl,--build-id=md5", src_path, "-o", mismatch_elf],
            check=True,
            capture_output=True,
            text=True,
        )

        # Pre-flight binary identity verification
        debug_ident = inspect_elf(debug_elf)
        stripped_ident = inspect_elf(stripped_elf)
        mismatch_ident = inspect_elf(mismatch_elf)

        assert debug_ident.build_id, "Companion debug ELF missing GNU Build ID"
        assert stripped_ident.build_id, "Stripped production binary missing GNU Build ID"
        assert debug_ident.build_id == stripped_ident.build_id, (
            f"Companion Build ID ({debug_ident.build_id}) must match stripped binary ({stripped_ident.build_id})"
        )
        assert mismatch_ident.build_id != debug_ident.build_id, "Mismatched companion ELF must have different Build ID"
        summary["assertions_passed"] += 4

        # Step 4: Spawn production stripped target process
        if verbose:
            print("[4/7] Spawning live production stripped target process...")
        proc = subprocess.Popen([stripped_elf, "20"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

        # Read ready handshake with bounded poll loop to avoid indefinite blocking
        ready_line = ""
        handshake_start = time.time()
        while time.time() - handshake_start < 5.0:
            if proc.poll() is not None:
                stderr_out = proc.stderr.read() if proc.stderr else ""
                raise RuntimeError(f"Target process exited prematurely (code {proc.returncode}): {stderr_out}")
            line = proc.stdout.readline() if proc.stdout else ""
            if line:
                ready_line = line.strip()
                break
            time.sleep(0.01)

        if not ready_line or "READY: PID=" not in ready_line:
            raise RuntimeError(f"Failed to receive READY handshake from target process: '{ready_line}'")

        expected_pid_str = f"PID={proc.pid}"
        assert expected_pid_str in ready_line, f"Handshake PID mismatch: {ready_line} vs {proc.pid}"
        summary["assertions_passed"] += 1
        if verbose:
            print(f"      Target ready signal: {ready_line}")

        # Step 5: Execute runtime_target_connect
        if verbose:
            print(f"[5/7] Executing runtime_target_connect for PID {proc.pid}...")
        t_conn_start = time.perf_counter()
        raw_conn = mcp_srv.runtime_target_connect(pid=proc.pid, companion_elf=debug_elf)
        conn_latency_ms = (time.perf_counter() - t_conn_start) * 1000
        res_conn = json.loads(raw_conn)

        assert res_conn.get("success") is True, f"Connection failed: {res_conn}"
        assert res_conn.get("pid") == proc.pid, f"PID mismatch: {res_conn.get('pid')} vs {proc.pid}"
        assert res_conn.get("build_id") == debug_ident.build_id, (
            f"Build ID verification mismatch: expected {debug_ident.build_id}, got {res_conn.get('build_id')}"
        )
        load_bias = res_conn.get("load_bias")
        assert load_bias and load_bias.startswith("0x"), f"Invalid load bias format: {load_bias}"
        threads_count = res_conn.get("threads_count", 0)
        assert threads_count >= 2, f"Expected at least 2 threads (main + worker), found {threads_count}"
        summary["assertions_passed"] += 5

        summary["target"] = {
            "pid": proc.pid,
            "threads_count": threads_count,
            "load_bias": load_bias,
            "build_id": res_conn.get("build_id"),
            "companion_elf": debug_elf,
            "connection_latency_ms": round(conn_latency_ms, 2),
        }

        if verbose:
            print(f"      Connection success: True, latency: {conn_latency_ms:.2f}ms")
            print(f"      Build ID verified: {res_conn.get('build_id')}")
            print(f"      Load bias resolved: {load_bias}")
            print(f"      Threads detected: {threads_count}")

        # Step 6: Multi-sample zero-stop memory observation & latency benchmarking
        if verbose:
            print(f"[6/7] Performing {samples} live zero-stop memory observations...")

        target_expressions = [
            "global_session->packet_count",
            "global_session->state",
            "global_session->buffer->length",
            "global_session->retry",
        ]

        # Warm-up observation
        raw_warmup = mcp_srv.runtime_eval_memory_path(expressions=target_expressions)
        res_warmup = json.loads(raw_warmup)
        assert res_warmup.get("success") is True, f"Warmup evaluation failed: {res_warmup}"
        summary["assertions_passed"] += 1

        # Benchmark samples
        eval_samples_ms: List[float] = []
        last_eval_res: Optional[Dict[str, Any]] = None

        for _ in range(samples):
            t_sample_start = time.perf_counter()
            raw_eval = mcp_srv.runtime_eval_memory_path(expressions=target_expressions)
            sample_latency_ms = (time.perf_counter() - t_sample_start) * 1000
            eval_samples_ms.append(sample_latency_ms)
            last_eval_res = json.loads(raw_eval)
            assert last_eval_res.get("success") is True, f"Sample evaluation failed: {last_eval_res}"

        latency_stats = calculate_latency_stats(eval_samples_ms, threshold_ms=max_latency_ms)
        summary["latency_benchmark"] = latency_stats

        # Assert SLA threshold on median latency
        assert latency_stats["within_sla"], (
            f"Median evaluation latency {latency_stats['median_ms']}ms exceeded SLA threshold {max_latency_ms}ms"
        )
        summary["assertions_passed"] += 1

        if verbose:
            print(f"      Latency Distribution ({samples} samples): "
                  f"min={latency_stats['min_ms']}ms, "
                  f"median={latency_stats['median_ms']}ms, "
                  f"p95={latency_stats['p95_ms']}ms, "
                  f"max={latency_stats['max_ms']}ms "
                  f"(SLA threshold: {max_latency_ms}ms)")

        # Validate result set contents and invariant bounds
        assert last_eval_res is not None
        evaluated_items = last_eval_res.get("results", [])
        assert len(evaluated_items) == len(target_expressions), (
            f"Expected {len(target_expressions)} results, got {len(evaluated_items)}"
        )

        observed_vals: Dict[str, Any] = {}
        for item in evaluated_items:
            expr = item.get("expression")
            assert expr in target_expressions, f"Unexpected expression in result set: {expr}"
            assert item.get("status") == "OBSERVED", f"Expression {expr} status not OBSERVED: {item.get('status')}"
            assert item.get("error") is None, f"Expression {expr} returned error: {item.get('error')}"
            runtime_addr = item.get("runtime_address")
            assert runtime_addr and runtime_addr.startswith("0x"), f"Expression {expr} invalid runtime address"
            observed_vals[expr] = item.get("value")
            summary["assertions_passed"] += 4

        # Specific invariant checks on observed values
        val_packet = observed_vals["global_session->packet_count"]
        val_state = observed_vals["global_session->state"]
        val_buf_len = observed_vals["global_session->buffer->length"]
        val_retry = observed_vals["global_session->retry"]

        assert isinstance(val_packet, int) and val_packet >= 100, f"Unexpected packet_count: {val_packet}"
        assert val_state == "CONNECTED (1)" or val_state == 1, f"Unexpected state: {val_state}"
        assert val_buf_len == 64, f"Unexpected buffer->length: {val_buf_len}"
        assert isinstance(val_retry, int) and (0 <= val_retry <= 4), f"Unexpected retry count: {val_retry}"
        summary["assertions_passed"] += 4

        summary["observed_expressions"] = {
            "packet_count": val_packet,
            "state": str(val_state),
            "buffer_length": val_buf_len,
            "retry": val_retry,
        }

        # Verify concurrent worker progress across observation window
        time.sleep(0.04)
        raw_followup = mcp_srv.runtime_eval_memory_path(expressions=["global_session->packet_count"])
        res_followup = json.loads(raw_followup)
        assert res_followup.get("success") is True
        followup_packet = int(res_followup["results"][0]["value"])
        progress_delta = followup_packet - val_packet
        assert progress_delta > 0, (
            f"Target worker thread stalled: packet_count did not advance ({val_packet} -> {followup_packet})"
        )
        summary["assertions_passed"] += 2

        summary["worker_progress"] = {
            "initial_packet_count": val_packet,
            "followup_packet_count": followup_packet,
            "delta": progress_delta,
            "continued_execution": True,
        }

        if verbose:
            print(f"      Target worker progress: packet_count {val_packet} -> {followup_packet} (delta = {progress_delta})")

        # Verify explicit non-atomic consistency metadata
        consistency = last_eval_res.get("consistency", {})
        assert consistency.get("process_stopped") is False, "Target must report process_stopped=False"
        assert consistency.get("is_atomic_read") is False, "Target must report is_atomic_read=False"
        assert consistency.get("causal_guarantee") == "NONE", "Target must report causal_guarantee='NONE'"
        summary["assertions_passed"] += 3

        summary["consistency_metadata"] = {
            "process_stopped": consistency.get("process_stopped"),
            "is_atomic_read": consistency.get("is_atomic_read"),
            "causal_guarantee": consistency.get("causal_guarantee"),
            "mechanism": consistency.get("mechanism"),
        }

        # Step 7: Test deliberate Build ID mismatch rejection
        if verbose:
            print("[7/7] Testing deliberate Build ID mismatch rejection...")
        raw_mismatch = mcp_srv.runtime_eval_memory_path(
            pid=proc.pid,
            companion_elf=mismatch_elf,
            expressions=["global_session->packet_count"],
        )
        res_mismatch = json.loads(raw_mismatch)

        assert res_mismatch.get("success") is False, "Mismatched companion ELF must not succeed"
        assert res_mismatch.get("error_code") == "BUILD_ID_MISMATCH", (
            f"Expected BUILD_ID_MISMATCH error code, got {res_mismatch.get('error_code')}"
        )
        err_msg = res_mismatch.get("error") or res_mismatch.get("error_message", "")
        assert mismatch_ident.build_id in err_msg, f"Error message missing mismatched Build ID: {err_msg}"
        summary["assertions_passed"] += 3

        summary["mismatch_rejection"] = {
            "rejected": True,
            "error_code": res_mismatch.get("error_code"),
            "verified_build_id": debug_ident.build_id,
            "rejected_build_id": mismatch_ident.build_id,
        }

        if verbose:
            print(f"      Mismatched companion rejected cleanly with error_code: {res_mismatch.get('error_code')}")
            print("\n=== REAL-TARGET CONTROLLED VALIDATION: ALL CHECKS PASSED ===")

        summary["status"] = "PASSED"
        return 0, summary

    except Exception as e:
        summary["status"] = "FAILED"
        summary["failures"].append(f"{type(e).__name__}: {e}")
        if verbose:
            print(f"\nERROR: Validation failed: {type(e).__name__}: {e}", file=sys.stderr)
        return 1, summary

    finally:
        # Structured, isolated cleanup guaranteed on both success and every failure path
        try:
            cleanup_target_process(proc)
        except Exception as e:
            cleanup_errors.append(f"Process cleanup failed: {e}")

        try:
            reset_target_context(mcp_srv.runtime.watch_session_manager)
        except Exception as e:
            cleanup_errors.append(f"Context reset failed: {e}")

        try:
            tmpdir.cleanup()
        except Exception as e:
            cleanup_errors.append(f"Temporary directory cleanup failed: {e}")

        if cleanup_errors:
            summary["cleanup_errors"] = cleanup_errors
            if verbose:
                for ce in cleanup_errors:
                    print(f"WARNING during cleanup: {ce}", file=sys.stderr)

        if output_json_path:
            try:
                with open(output_json_path, "w", encoding="utf-8") as f:
                    json.dump(summary, f, indent=2)
            except Exception as e:
                print(f"Failed to write output JSON to {output_json_path}: {e}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description="dynamicState Phase 16 Real-Target Validation Runner")
    parser.add_argument("--samples", type=int, default=10, help="Number of benchmark samples (default: 10)")
    parser.add_argument("--max-latency-ms", type=float, default=15.0, help="Max median latency SLA in ms (default: 15.0)")
    parser.add_argument("--json", type=str, default=None, help="Optional output path for machine-readable JSON summary")
    parser.add_argument("--quiet", "-q", action="store_true", help="Quiet mode")
    args = parser.parse_args()

    exit_code, summary = run_real_target_validation(
        samples=args.samples,
        max_latency_ms=args.max_latency_ms,
        verbose=not args.quiet,
        output_json_path=args.json,
    )

    if args.quiet and not args.json:
        print(f"Status: {summary['status']}, Assertions: {summary['assertions_passed']}")

    return exit_code


if __name__ == "__main__":
    sys.exit(main())

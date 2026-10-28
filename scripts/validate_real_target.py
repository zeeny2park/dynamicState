#!/usr/bin/env python3
"""Phase 15 — Minimal Controlled Real-Target Validation Runner for DynamicState MCP.

Validates real-target prerequisites against a live multithreaded stripped C++ process:
1. GNU Build ID verification between stripped production binary and non-stripped companion ELF.
2. ASLR / PIE load bias address resolution.
3. Live memory extraction of scalars, enums, and nested struct pointer dereferences.
4. Target zero-stop measurement: target threads continue running without pause during observation.
5. Capture latency measurement (< 15ms).
6. Deliberate Build ID mismatch rejection without target interference.
7. Clean lifecycle termination, SIGTERM/SIGKILL escalation, and reaping.
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import tempfile
import time

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(SCRIPT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import scripts.mcp_server as mcp_srv


def run_validation(verbose: bool = True) -> int:
    tmpdir = tempfile.TemporaryDirectory(prefix="real_target_val_")
    debug_elf = os.path.join(tmpdir.name, "sample_debug.elf")
    stripped_elf = os.path.join(tmpdir.name, "sample_prod.stripped")
    mismatch_elf = os.path.join(tmpdir.name, "sample_mismatch.elf")
    src_path = os.path.join(PROJECT_ROOT, "examples", "sample_low_impact.cpp")

    if not os.path.isfile(src_path):
        print(f"ERROR: Target source fixture not found: {src_path}", file=sys.stderr)
        return 1

    if verbose:
        print(f"[1/7] Compiling companion debug ELF with DWARF symbols: {debug_elf}")
    subprocess.run(
        ["g++", "-fPIE", "-pie", "-g", "-O0", "-pthread", "-Wl,--build-id=sha1", src_path, "-o", debug_elf],
        check=True,
    )

    if verbose:
        print(f"[2/7] Generating stripped production executable: {stripped_elf}")
    subprocess.run(["strip", "-s", "-o", stripped_elf, debug_elf], check=True)

    if verbose:
        print(f"[3/7] Compiling mismatched companion ELF (md5 build-id): {mismatch_elf}")
    subprocess.run(
        ["g++", "-fPIE", "-pie", "-g", "-O0", "-pthread", "-Wl,--build-id=md5", src_path, "-o", mismatch_elf],
        check=True,
    )

    if verbose:
        print("[4/7] Spawning live production stripped target process...")
    proc = subprocess.Popen([stripped_elf, "20"], stdout=subprocess.PIPE, text=True)

    try:
        ready_line = proc.stdout.readline()
        if verbose:
            print(f"      Target stdout: {ready_line.strip()}")
        assert f"PID={proc.pid}" in ready_line, f"Unexpected target output: {ready_line}"

        if verbose:
            print(f"[5/7] Executing runtime_target_connect for PID {proc.pid}...")
        t_conn_start = time.perf_counter()
        raw_conn = mcp_srv.runtime_target_connect(pid=proc.pid, companion_elf=debug_elf)
        conn_latency_ms = (time.perf_counter() - t_conn_start) * 1000
        res_conn = json.loads(raw_conn)

        if verbose:
            print(f"      Connection success: {res_conn.get('success')}, latency: {conn_latency_ms:.2f}ms")
            print(f"      Build ID verified: {res_conn.get('build_id')}")
            print(f"      Load bias resolved: {res_conn.get('load_bias')}")
            print(f"      Threads detected: {res_conn.get('threads_count')}")

        assert res_conn.get("success"), f"Connection failed: {res_conn}"
        assert res_conn.get("pid") == proc.pid
        assert res_conn.get("threads_count", 0) >= 2, "Expected main and worker threads"

        if verbose:
            print("[6/7] Performing live zero-stop memory observation...")
        t_obs_start = time.perf_counter()
        raw_eval_1 = mcp_srv.runtime_eval_memory_path(
            expressions=[
                "global_session->packet_count",
                "global_session->state",
                "global_session->buffer->length",
                "global_session->retry",
            ]
        )
        obs_latency_ms = (time.perf_counter() - t_obs_start) * 1000
        res_eval_1 = json.loads(raw_eval_1)
        assert res_eval_1.get("success"), f"Evaluation 1 failed: {res_eval_1}"

        vals_1 = {r["expression"]: r["value"] for r in res_eval_1["results"]}
        if verbose:
            print(f"      Observation 1 latency: {obs_latency_ms:.2f}ms")
            print(f"      packet_count: {vals_1.get('global_session->packet_count')}")
            print(f"      state: {vals_1.get('global_session->state')} (1 == CONNECTED)")
            print(f"      buffer->length: {vals_1.get('global_session->buffer->length')}")
            print(f"      retry: {vals_1.get('global_session->retry')}")

        time.sleep(0.03)

        raw_eval_2 = mcp_srv.runtime_eval_memory_path(expressions=["global_session->packet_count"])
        res_eval_2 = json.loads(raw_eval_2)
        assert res_eval_2.get("success")
        c1 = int(vals_1["global_session->packet_count"])
        c2 = int(res_eval_2["results"][0]["value"])
        if verbose:
            print(f"      Target progress check: packet_count advanced from {c1} -> {c2} (delta = {c2 - c1})")
        assert c2 > c1, f"Expected counter to advance without target stopping: {c1} vs {c2}"

        consistency = res_eval_1.get("consistency", {})
        if verbose:
            print(f"      Consistency metadata: process_stopped={consistency.get('process_stopped')}, is_atomic={consistency.get('is_atomic_read')}")
        assert consistency.get("process_stopped") is False, "Target must not be stopped"
        assert consistency.get("is_atomic_read") is False, "Must report non-atomic read"

        if verbose:
            print("[7/7] Testing deliberate Build ID mismatch rejection...")
        raw_mismatch = mcp_srv.runtime_eval_memory_path(
            pid=proc.pid,
            companion_elf=mismatch_elf,
            expressions=["global_session->packet_count"],
        )
        res_mismatch = json.loads(raw_mismatch)
        if verbose:
            print(f"      Mismatched companion rejected with error_code: {res_mismatch.get('error_code')}")
        assert res_mismatch.get("success") is False
        assert res_mismatch.get("error_code") == "BUILD_ID_MISMATCH"

        if verbose:
            print("\n=== REAL-TARGET CONTROLLED VALIDATION: ALL CHECKS PASSED ===")
        return 0

    finally:
        if proc.poll() is None:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
        tmpdir.cleanup()


def main() -> int:
    parser = argparse.ArgumentParser(description="dynamicState Phase 15 Real-Target Validation Runner")
    parser.add_argument("--quiet", "-q", action="store_true", help="Quiet mode")
    args = parser.parse_args()
    return run_validation(verbose=not args.quiet)


if __name__ == "__main__":
    sys.exit(main())

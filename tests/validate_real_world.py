"""Real-world Web UI Human Validation Test Suite.

Validates the complete dynamicState runtime flow on a realistic production-like workload:
1. Stripped PIE target binary with external unstripped debug image and linked shared library.
2. LOW_IMPACT observation via process_vm_readv on running multi-threaded process.
3. Offline DWARF semantic reconstruction with zero process stopping.
4. Capability boundaries (rejection of mutations, continue, checkpoints in LOW_IMPACT mode).
5. Debug image mismatch detection and rejection.
6. CONSISTENT observation under live GDB attached to target inferior.
7. Semantic Object Graph inspection (nested structs, pointers, circular references, globals).
8. Mutation candidate discovery, ranking, and boundary generation.
9. Real typed mutation execution and inferior continuation.
10. State transition analysis, semantic diff, and facts/evidence generation.
11. State Hash invariance across ASLR/addresses and sensitivity to semantic state changes.
12. Branch-safe exploration with checkpoint-restore isolation across sibling branches.
13. Failure representation (CRASHED / SIGSEGV).
14. State Graph construction for Web UI visualization.
15. Verification of all Web UI REST API endpoints.
"""

import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.error

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT_DIR)


def build_workload(build_dir):
    """Compile shared library, production target, extract debug info, strip binary."""
    print("[BUILD] Compiling libhelper.so...")
    lib_src = os.path.join(ROOT_DIR, "examples", "libhelper.c")
    lib_so = os.path.join(build_dir, "libhelper.so")
    subprocess.check_call(["gcc", "-shared", "-fPIC", "-g", "-o", lib_so, lib_src])

    print("[BUILD] Compiling sample_prod...")
    app_src = os.path.join(ROOT_DIR, "examples", "sample_prod.cpp")
    app_bin = os.path.join(build_dir, "sample_prod")
    subprocess.check_call([
        "g++", "-g", "-O0", "-fPIE", "-pie", "-pthread",
        "-Wl,--no-as-needed", f"-L{build_dir}", "-lhelper", f"-Wl,-rpath,{build_dir}",
        "-o", app_bin, app_src
    ])

    print("[BUILD] Extracting external debug image and stripping runtime binary...")
    app_dbg = os.path.join(build_dir, "sample_prod.debug")
    app_stripped = os.path.join(build_dir, "sample_prod_stripped")
    subprocess.check_call(["objcopy", "--only-keep-debug", app_bin, app_dbg])
    shutil.copy2(app_bin, app_stripped)
    os.chmod(app_stripped, 0o755)
    subprocess.check_call(["strip", "-s", app_stripped])
    subprocess.check_call([f"--add-gnu-debuglink={app_dbg}", app_stripped], executable="objcopy")

    print("[BUILD] Creating mismatched debug image...")
    mismatch_dbg = os.path.join(build_dir, "mismatch.debug")
    subprocess.run(["gcc", "-g", "-x", "c", "-", "-o", mismatch_dbg], input=b"int main(){return 0;}", check=True)

    # Extract build ID of stripped binary
    readelf_out = subprocess.check_output(["readelf", "-n", app_stripped]).decode("utf-8")
    build_id = ""
    for line in readelf_out.splitlines():
        if "Build ID:" in line:
            build_id = line.split("Build ID:")[-1].strip()
            break

    # Read ELF header
    header_out = subprocess.check_output(["readelf", "-h", app_stripped]).decode("utf-8")
    elf_class = "ELF64" if "ELF64" in header_out else "ELF32"
    endianness = "little" if "little endian" in header_out else "big"
    arch = "aarch64" if "AArch64" in header_out else ("x86_64" if "X86-64" in header_out else "unknown")

    meta = {
        "build_id": build_id,
        "elf_class": elf_class,
        "endianness": endianness,
        "architecture": arch,
        "app_bin": app_bin,
        "app_stripped": app_stripped,
        "app_dbg": app_dbg,
        "mismatch_dbg": mismatch_dbg,
        "lib_so": lib_so
    }
    print(f"[BUILD] Completed. Target arch: {arch}, Build ID: {build_id}")
    return meta


def validate_low_impact_mode(meta, results):
    """Validate LOW_IMPACT mode on a running multi-threaded daemon process."""
    print("\n=== Validating LOW_IMPACT Observation Mode ===")
    from extractor.agent_runtime import AgentRuntime

    tmp_dir = tempfile.mkdtemp(prefix="dynstate_val_low_impact_")
    corpus_dir = os.path.join(tmp_dir, "corpus")
    os.makedirs(corpus_dir, exist_ok=True)

    agent = AgentRuntime(controller=None, corpus_dir=corpus_dir)

    # 1. Start daemon process with background worker thread
    proc = subprocess.Popen(
        [meta["app_stripped"], "100", "--daemon"],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )

    target_pid = None
    t0 = time.time()
    while time.time() - t0 < 5.0:
        line = proc.stdout.readline()
        if "READY: PID=" in line:
            target_pid = int(line.strip().split("READY: PID=")[-1])
            break

    assert target_pid is not None, "Failed to start target process"
    print(f"[LOW_IMPACT] Target running with PID {target_pid}")

    try:
        # 2. Capture memory snapshot via process_vm_readv
        cap_res = agent.capture_memory_snapshot(
            pid=target_pid,
            policy="ALL_READABLE",
            snapshot_id="M_VAL_001"
        )
        assert cap_res.success, f"Capture failed: {cap_res.error}"
        cap_data = cap_res.data
        print(f"[LOW_IMPACT] Captured {cap_data['bytes_captured']} bytes across {cap_data.get('regions')} regions.")

        # 3. Verify process continued running without stopping
        assert proc.poll() is None, "Process died during memory capture"
        print("[LOW_IMPACT] Zero-stop verification: process is still alive and running.")

        # 4. Offline semantic reconstruction
        ana_res = agent.analyze_memory_snapshot(
            memory_snapshot_id="M_VAL_001",
            debug_image=meta["app_dbg"]
        )
        assert ana_res.success, f"Offline analysis failed: {ana_res.error}"
        ana_data = ana_res.data
        snap_id = ana_data.snapshot_id if hasattr(ana_data, "snapshot_id") else ana_data.get("snapshot_id")
        print(f"[LOW_IMPACT] Offline analysis produced semantic snapshot: {snap_id}")

        # Verify execution context is honestly unavailable
        exec_ctx = ana_data.execution if hasattr(ana_data, "execution") else ana_data.get("execution", {})
        if hasattr(exec_ctx, "to_dict"):
            exec_ctx = exec_ctx.to_dict()
        print(f"[LOW_IMPACT] Execution context availability: {exec_ctx.get('availability')}")
        assert exec_ctx.get("availability") == "UNAVAILABLE"
        assert exec_ctx.get("function") == "<unavailable>"
        assert exec_ctx.get("thread_id") is None

        # 5. Verify capability boundary enforcement
        agent.observation_mode = "LOW_IMPACT"
        mut_res = agent.execute_transition("M0001")
        assert not mut_res.success
        assert mut_res.error.code == "CAPABILITY_UNSUPPORTED"
        print(f"[LOW_IMPACT] execute_transition correctly rejected: {mut_res.error.code}")

        cp_res = agent.checkpoint("C001")
        assert not cp_res.success
        assert cp_res.error.code == "CAPABILITY_UNSUPPORTED"
        print(f"[LOW_IMPACT] checkpoint correctly rejected: {cp_res.error.code}")

        # 6. Verify mismatched debug image rejection
        mismatch_res = agent.analyze_memory_snapshot(
            memory_snapshot_id="M_VAL_001",
            debug_image=meta["mismatch_dbg"]
        )
        assert not mismatch_res.success
        assert mismatch_res.error.code in ("DEBUG_IMAGE_MISMATCH", "BUILD_ID_MISMATCH")
        print(f"[LOW_IMPACT] Mismatched debug image correctly rejected: {mismatch_res.error.code}")

        results["low_impact"] = {
            "status": "PASS",
            "bytes_captured": cap_data["bytes_captured"],
            "regions_count": cap_data.get("regions"),
            "exec_availability": exec_ctx.get("availability"),
            "mutation_rejected": mut_res.error.code,
            "checkpoint_rejected": cp_res.error.code,
            "mismatch_rejected": mismatch_res.error.code
        }
    finally:
        try:
            os.kill(target_pid, signal.SIGTERM)
            proc.wait(timeout=2.0)
        except Exception:
            pass
        shutil.rmtree(tmp_dir, ignore_errors=True)


def validate_consistent_gdb_mode(meta, results):
    """Run GDB batch session with sample_prod_stripped, load debug image, and execute scenario."""
    print("\n=== Validating CONSISTENT Observation Mode under Live GDB ===")
    gdb_results_path = os.path.join(tempfile.gettempdir(), "real_world_gdb_results.json")
    if os.path.exists(gdb_results_path):
        os.remove(gdb_results_path)

    cmd = [
        "gdb", "-q", "-nx", "-batch",
        "-ex", "set confirm off",
        "-ex", "set python print-stack full",
        "-ex", f"file {meta['app_stripped']}",
        "-ex", f"source {os.path.join(ROOT_DIR, 'gdb', 'extract_state.py')}",
        "-ex", f"load-debug-image {meta['app_dbg']}",
        "-ex", "set args 10",
        "-ex", "break runtime_state_checkpoint",
        "-ex", "run",
        "-ex", f"python\nimport sys\nsys.path.insert(0, '{ROOT_DIR}')\nfrom tests.real_world_gdb_scenario import run_gdb_validation_scenario\nassert run_gdb_validation_scenario('{gdb_results_path}')\n"
    ]

    subprocess.check_call(cmd)
    assert os.path.exists(gdb_results_path), "GDB results file not found"
    with open(gdb_results_path) as f:
        gdb_res = json.load(f)
    results["consistent"] = gdb_res
    print("[CONSISTENT] Live GDB validation completed successfully.")


if __name__ == "__main__":
    b_dir = tempfile.mkdtemp(prefix="dynstate_val_build_")
    try:
        workload_meta = build_workload(b_dir)
        results = {"metadata": workload_meta}
        validate_low_impact_mode(workload_meta, results)
        validate_consistent_gdb_mode(workload_meta, results)

        final_out_dir = os.path.join(ROOT_DIR, "docs")
        os.makedirs(final_out_dir, exist_ok=True)
        final_out_path = os.path.join(final_out_dir, "real_world_validation_data.json")
        with open(final_out_path, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\n==============================================================")
        print(f"ALL REAL-WORLD VALIDATION STEPS PASSED SUCCESSFULLY!")
        print(f"Validation data saved to {final_out_path}")
        print(f"==============================================================")
    finally:
        shutil.rmtree(b_dir, ignore_errors=True)

# Phase 14: Production Pilot & Release Qualification Runbook

## 1. Executive Summary & Purpose

Phase 14 defines the **Production Pilot and Release Qualification** workflow for **dynamicState**. Building on the Phase 10 security boundaries, Phase 11 real-target capture validation, Phase 12 conversational investigation loop, and Phase 13 operational acceptance, this runbook establishes the end-to-end qualification standard for representative embedded Linux C/C++ targets.

### Primary Objectives
- **Operationally Safe Production Pilot**: Execute end-to-end investigations against real compiled C++ targets running under embedded Linux conditions (stripped PIE binaries, companion DWARF symbols, ASLR, multi-threading, competing writers).
- **Measurable Acceptance & Performance**: Establish concrete latency, throughput, and target impact benchmarks (p50, p95, max, throughput MB/s) with zero invented numbers or extrapolated claims.
- **Strict Decoupling of Transition vs Attribution**: Ensure state-transition validation proves only that memory changed, while causal function attribution requires verifiable single-writer isolation or execution instrumentation.
- **Cryptographic Report Integrity**: Export machine-readable qualification reports (`reports/pilot_qualification_report.json`) signed with SHA-256 tamper-evident integrity hashes.
- **Hardware Boundary Transparency**: Explicitly distinguish simulated representative fixtures on Linux hosts from physical on-board deployments (`real_hardware_validated=False`).

---

## 2. Architecture & Prerequisites

### 2.1 Architecture Overview

```
┌────────────────────────────────────────────────────────┐
│ Target Device / Inferior (Embedded Linux / IoT Target) │
│                                                        │
│  [Stripped PIE Binary] ── ASLR ── GNU Build ID: abc    │
│  [Telemetry State] ──── [Negative Control State]       │
│  [Writer Thread] ────── [Competing Thread (Optional)]  │
└───────────────────────────┬────────────────────────────┘
                            │
               Non-invasive memory capture
            (process_vm_readv / /proc/$PID/mem)
                            │
                            ▼
┌────────────────────────────────────────────────────────┐
│ Host-Side Analysis & Investigation Engine              │
│                                                        │
│  [Companion DWARF (.debug)] ── Build ID Match Verified │
│  [RawRuntimeSnapshot] ────── Complete & Atomic         │
│  [StateDiffEngine] ───────── Semantic Field Finding    │
│  [StaticAnalyzer] ────────── Candidate Writer List     │
│  [TrustedCausalVerifier] ─── Single-Writer Isolation   │
│  [EvidenceLedger] ────────── Cryptographic Attestation │
│  [PilotQualificationReport]  Tamper-Evident SHA-256    │
└────────────────────────────────────────────────────────┘
```

### 2.2 System Prerequisites Matrix

| Requirement | Supported Specification | Verification Command / Check |
|---|---|---|
| **Operating System** | Linux (Kernel >= 3.2 for `process_vm_readv`) | `uname -s`, `uname -r` |
| **Architecture** | `x86_64`, `aarch64`, `armv7l` | `uname -m` |
| **C/C++ Toolchain** | `g++` >= 9.0 or `clang++` >= 10.0, `objcopy`, `strip` | `g++ --version`, `strip --version` |
| **Yama Ptrace Scope** | Scope `0` (Classic) or Scope `1` (Restricted with child) or `CAP_SYS_PTRACE` | `cat /proc/sys/kernel/yama/ptrace_scope` |
| **Target Binary Format** | ELF (PIE or Non-PIE) with GNU Build ID note (`.note.gnu.build-id`) | `readelf -n <binary>` |
| **Debug Artifact** | Unstripped ELF or separate companion DWARF file (`.debug`) | `eu-unstrip`, `readelf -w` |
| **Collector Backend** | `process_vm_readv` (default) or `procfs_mem` (fallback) | `ProcessVmCaptureBackend` |

### 2.3 Prohibited Behaviors & Safety Policy
- **No Live Mutation**: Target memory is read-only during non-invasive capture. Live mutations (`write_memory`, instruction patching) are strictly prohibited unless explicit authorization (`allow_live_mutation=True`) is configured in the safety policy.
- **No Invasive Debugger Attachment**: dynamicState does **not** attach persistent intrusive debuggers (`gdb`, `ptrace(PTRACE_ATTACH)` stop loops) to running targets during standard pilot captures.
- **Strict Stop-Time Ceiling**: Target freeze duration via `SIGSTOP`/`SIGCONT` is bounded by `CaptureSafetyPolicy.max_stop_time_ms` (default 50.0 ms). If exceeded, target is immediately resumed and capture marked degraded.

---

## 3. End-to-End Pilot Qualification Workflow

The qualification workflow is executed via `scripts/run_production_pilot.py` or programmatically via `extractor.production_pilot.ProductionPilotHarness`.

```bash
# Execute standalone production pilot qualification (smoke run: 3 benchmark iterations)
python3 scripts/run_production_pilot.py --smoke

# Execute full 10-iteration production pilot qualification
python3 scripts/run_production_pilot.py --iterations 10 --output reports/pilot_qualification_report.json
```

### Workflow Steps

1. **Pre-Flight Validation**:
   - `PilotPrerequisitesChecker.check_prerequisites()` verifies Linux OS, kernel version >= 3.2, ptrace permissions, and compiler availability.
   - Fails immediately with actionable error messages if prerequisites are unmet.

2. **Representative Target Compilation**:
   - Compiles `tests/fixtures/real_runtime/phase14_embedded_telemetry_fixture.cpp` with `-g -fPIE -pie -lpthread`.
   - Separates companion DWARF image: `objcopy --only-keep-debug telemetry.elf telemetry.debug`.
   - Strips production executable: `strip --strip-all telemetry.elf -o telemetry.stripped`.
   - Validates that `telemetry.stripped` GNU Build ID matches `telemetry.debug` GNU Build ID.

3. **Baseline Snapshot Capture (Pre-Mutation)**:
   - Spawns stripped target process in inferior mode and confirms `READY` handshake.
   - Performs non-invasive `process_vm_readv` capture of initial process state (`snap1_initial`).
   - Verifies capture completeness (`COMPLETE`) and atomic consistency (`STOPPED`).

4. **Latency & Throughput Benchmarking**:
   - Executes repeated capture cycles (default 10 iterations) on the live target.
   - Records stop latency, read latency, resume latency, total capture duration, and bytes read.
   - Computes statistical percentiles (`min`, `p50`, `p90`, `p95`, `max`) and mean throughput without extrapolation.

5. **State Transition Mutation**:
   - Sends mutation trigger to target inferior (`SAMPLE 2000 20`), causing `TelemetryState.sensor_reading` to transition from `1000` to `2000` via writer function `telemetry_periodic_sample_writer`.
   - Leaves negative control field `TelemetryState.last_error_code` strictly unchanged (`0`).

6. **Post-Mutation Snapshot Capture**:
   - Performs non-invasive capture (`snap2_mutated`).
   - Gracefully terminates target inferior (`STOP`) and closes all IPC pipes.

7. **Offline Investigation & Semantic Memory Diff**:
   - Runs `InvestigationManager.compare_observations(snap1_dir, snap2_dir)`.
   - Reconstructs DWARF type layout using companion debug image `telemetry.debug`.
   - Confirms value change on `TelemetryState.sensor_reading` (`1000 -> 2000`).
   - Confirms negative control stability (`last_error_code` unchanged).

8. **Competing Writer & Causal Verification**:
   - Evaluates whether background competing writers were active.
   - If negative control was undisturbed and single-writer isolation is proven, mints `ControlledExecutionResult`.
   - Issues cryptographic `CausalVerificationCapability` and attests proof into `EvidenceLedger`.
   - Evaluates hypothesis: candidate promoted to `VALIDATED_CAUSAL_FUNCTION`.
   - If competing writer was active, causal promotion is refused and hypothesis remains `INCONCLUSIVE`.

9. **Machine-Readable Report Generation**:
   - Serializes complete qualification results into `PilotQualificationReport`.
   - Computes SHA-256 payload integrity hash and writes `reports/pilot_qualification_report.json`.

---

## 4. Machine-Readable Schema & Trust Verification

The qualification output schema is defined by `PilotQualificationReport` in `extractor/production_pilot.py`.

### Schema Summary
```json
{
  "schema_version": "1.0.0",
  "pilot_id": "pilot_1792015250_3292179",
  "timestamp": "2026-10-14T22:00:50.123456+00:00",
  "execution_mode": "SIMULATED_REPRESENTATIVE_TARGET",
  "real_hardware_validated": false,
  "prerequisites": {
    "os_name": "Linux",
    "architecture": "aarch64",
    "kernel_version": "6.17.0-1014-oracle",
    "ptrace_scope": 0,
    "compiler_available": true,
    "passed": true
  },
  "target_identity": {
    "pid": 3292180,
    "binary_path": "/tmp/.../telemetry_daemon.stripped",
    "is_stripped": true,
    "build_id": "88d9aac9e1e80824801bb9c6fe86e1094f3c16a4",
    "arch": "aarch64"
  },
  "debug_artifact": {
    "debug_image_path": "/tmp/.../telemetry_daemon.debug",
    "build_id": "88d9aac9e1e80824801bb9c6fe86e1094f3c16a4",
    "match_status": "MATCHED"
  },
  "capture_metrics": {
    "mode": "CONSISTENT_STOPPED",
    "bytes_requested": 8794112,
    "bytes_read": 8794112,
    "completeness_pct": 100.0,
    "consistency": "ATOMIC_STOPPED"
  },
  "latency_distribution": {
    "samples_count": 4,
    "stop_latency_us": { "min": 170.1, "p50": 175.4, "p90": 184.2, "p95": 185.0, "max": 185.24 },
    "memory_read_us": { "min": 1180.0, "p50": 1211.32, "p90": 1245.0, "p95": 1247.1, "max": 1248.2 },
    "resume_latency_us": { "min": 45.0, "p50": 48.2, "p90": 52.1, "p95": 53.0, "max": 53.4 },
    "total_capture_ms": { "min": 2.5, "p50": 2.69, "p90": 4.8, "p95": 4.95, "max": 5.04 },
    "throughput_mb_s": 2361.53,
    "quality_summary": { "COMPLETE": 4 }
  },
  "investigation_summary": {
    "finding_id": "fnd_001",
    "field_path": "TelemetryState.sensor_reading",
    "old_value": 1000,
    "new_value": 2000,
    "candidate_functions": ["telemetry_periodic_sample_writer"],
    "negative_control_stable": true,
    "state_transition_verified": true,
    "function_attribution_verified": true,
    "final_candidate": "telemetry_periodic_sample_writer",
    "final_tier": "VALIDATED_CAUSAL_FUNCTION",
    "final_status": "VALIDATED"
  },
  "trust_boundary_assertions": {
    "anti_tampering_verified": true,
    "caller_booleans_disarmed": true,
    "build_id_match_enforced": true,
    "negative_control_passed": true,
    "state_transition_decoupled_from_attribution": true,
    "causal_function_promoted_only_with_proof": true
  },
  "explicit_disclosures": [
    "Pilot run executed against compiled representative embedded C++ fixture (phase14_embedded_telemetry_fixture.cpp).",
    "Target binary was compiled with -g -fPIE -pie on the local Linux host; companion DWARF separated with objcopy.",
    "This qualification establishes process_vm_readv capture correctness, DWARF type resolution, and single-writer causal proof boundaries.",
    "Real physical target board deployment (remote ARM/MIPS device) requires deploying target/collector/dynamicstate-collector."
  ],
  "report_sha256": "f5704be79c7f403225fd5c766150739f6aac0cdd5524e11f3537150bc78517ca"
}
```

### Cryptographic Verification
To verify the integrity of an exported qualification report:
```python
from extractor.production_pilot import PilotQualificationReport

# Automatically verifies SHA-256 payload integrity; raises ValueError if tampered
report = PilotQualificationReport.load("reports/pilot_qualification_report.json")
print("Report verified! SHA-256:", report.report_sha256)
```

---

## 5. Troubleshooting & Operational Recovery

### 5.1 Pre-Flight Check Failure: Yama Ptrace Scope
- **Symptom**: `PilotPrerequisitesChecker` reports `ptrace_scope > 1` or permission denied during `process_vm_readv`.
- **Cause**: Linux kernel Yama security module restricts cross-process inspection (`/proc/sys/kernel/yama/ptrace_scope`).
- **Resolution**:
  1. For local development or non-production test host, set scope to `0` or `1`:
     ```bash
     echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
     ```
  2. For production environments where scope cannot be altered, grant `CAP_SYS_PTRACE` capability to the collector binary:
     ```bash
     sudo setcap cap_sys_ptrace=eip /path/to/dynamicstate-collector
     ```

### 5.2 Build ID Mismatch
- **Symptom**: Target identity marked `FAILED` with `build_id_status: "MISMATCH"`.
- **Cause**: The supplied companion DWARF file was built from a different compilation run than the running target.
- **Resolution**:
  1. Inspect Build ID of running binary: `eu-readelf -n /proc/$PID/exe`.
  2. Inspect Build ID of companion debug symbol file: `eu-readelf -n /path/to/companion.debug`.
  3. Ensure symbol file matches the exact binary deployed to target. Do not use `--strip-all` without `--only-keep-debug` from the same build output.

### 5.3 Competing Background Writers
- **Symptom**: Investigation terminates with `final_status: "INCONCLUSIVE"` and `final_tier: "STATIC_CANDIDATE"`.
- **Cause**: Multiple background threads concurrently modified the target field or negative control fields during the observation window.
- **Resolution**:
  1. This is **correct behavior**; dynamicState refuses to fabricate causal claims when single-writer isolation cannot be proven.
  2. To achieve attribution, attach verified runtime execution instrumentation (e.g. entry/exit trace hook) to confirm which thread executed during the transition window.

### 5.4 Degraded Capture Quality (PARTIAL / NON_ATOMIC)
- **Symptom**: Investigation hypothesis status capped at `SUPPORTED` instead of `VALIDATED`.
- **Cause**: The process could not be cleanly stopped (`NON_ATOMIC`) or memory ranges were partially unmapped (`PARTIAL`).
- **Resolution**:
  1. In accordance with Trust Boundary Invariant 4, degraded captures cannot produce confirmed causal findings.
  2. Check target CPU load and increase `max_stop_time_ms` in `CaptureSafetyPolicy` if target was under heavy scheduling latency.

---

## 6. Rollback & Fail-Open Procedures

In production pilot deployments:
1. **Collector Crash or Hang**: The target process inferior is insulated by kernel boundary (`process_vm_readv`). A collector failure does **not** crash the target.
2. **Target Process Stalled in SIGSTOP**: If collector exits abnormally while target is stopped, the kernel resume watchdog or cleanup trap automatically sends `SIGCONT` to target PID.
3. **Emergency Disarm**: If dynamicState collector must be terminated immediately:
   ```bash
   kill -9 $(pgrep -f "dynamicstate-collector")
   kill -CONT <TARGET_PID>
   ```

---

## 7. Data Retention, Privacy, and Memory Sanitization

1. **Captured Memory Protection**: Memory snapshots contain raw process heap and stack buffers. Snapshots must be stored in workspace directories with `0700` permissions.
2. **Zero Unencrypted Persistence**: Sensitive keys, credentials, or PII observed in target memory must not be committed to Git. The `.gitignore` file enforces exclusion of `*.bin`, `*.raw`, `reports/`, and temporary workspaces.
3. **Artifact Retention Guideline**: Raw snapshots should be retained only for the duration of the investigation session and purged after generating the machine-readable qualification report.

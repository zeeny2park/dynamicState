# Debug Image Identity Fail-Closed & Adapter Closure Verification

- **Repository**: `https://github.com/zeeny2park/dynamicState`
- **Baseline HEAD**: `034f2ce47e90f421b7a604719a596417662bb9f0`
- **Branch**: `fix/debug-image-identity-fail-closed`
- **Date**: 2026-11-26
- **Final Verdict**: **CONDITIONAL GO** (all local identity, caller, adapter, trust-store, CLI, MCP, Web API, and real-ELF regression tests pass; pending GitHub Actions `Test Suite` and `GDB 9.2 Compatibility` run on the new commit SHA after push)

---

## 1. Original Issue & Root Cause

### Issue A — Primary Fail-Open in `DefaultTargetIdentityPolicy.validate_debug_image_compatibility()`
- **Location**: `extractor/adapters/identity_policy.py:133-148` (baseline `034f2ce`)
- **Root Cause**: When both `runtime_build_id` and `debug_build_id` were absent (`None`, `""`) or synthetic (`no-build-id:...`), `validate_debug_image_compatibility()` unconditionally returned `(True, "COMPATIBLE_NO_BUILD_ID")`. Any two unrelated ELF binaries compiled without GNU Build IDs (e.g. `-Wl,--build-id=none`) were approved as compatible without any independent identity evidence.

### Issue B — Secondary Fail-Open in `DebugArtifactProvider.verify()`
- **Location**: `extractor/debug_artifacts.py:170-194` (baseline `034f2ce`)
- **Root Cause**: `DebugArtifactProvider.verify()` only checked Build ID equality inside `if module.build_id:`. Whenever `module.build_id` was `None` or empty, the entire Build ID check was skipped and `verify()` returned `CompatibilityResult(compatible=True, reason="COMPATIBLE")` — even when the debug image had a different Build ID or belonged to an unrelated binary. This affected `OfflineMemoryAnalyzer.analyze()` (`extractor/offline_analyzer.py:443`).

### Issue C — URI Secret Parameter Leakage in `TargetAdapterRegistry.describe()`
- **Location**: `extractor/adapters/registry.py:18-29, 328-343` (baseline `034f2ce`)
- **Root Cause**: `_redact_secrets()` removed secret keys from dicts (e.g. `token`), but preserved the raw `target_uri` string inside `transport_params["target_uri"]`, allowing query secrets (such as `?token=supersecret`) or userinfo passwords to appear in sanitized transport descriptions.

### Issue D — Clock Source Mismatch in `DebugImageProvider.verify()`
- **Location**: `extractor/debug_image.py:548` (baseline `034f2ce`)
- **Root Cause**: `t0 = time.monotonic()` was subtracted from `time.perf_counter()` on the policy-rejection branch.

---

## 2. Exact Source Locations & Call Graph

```text
TargetIdentityPolicy.validate_debug_image_compatibility()
  [extractor/adapters/identity_policy.py:62, 146, 206]
    ▲
    ├── DebugImageProvider.verify(runtime_binary_path)
    │     [extractor/debug_image.py:451 -> 552]
    │       ├── extract_state.snapshot()
    │       │     [extractor/extract_state.py:16] -> raises RuntimeError("DEBUG_IMAGE_INCOMPATIBLE: ...") before gdb symbol-file
    │       ├── RuntimeController.load_debug_image()
    │       │     [extractor/runtime_controller.py:225] -> raises RuntimeError("DEBUG_IMAGE_INCOMPATIBLE: ...") before gdb symbol-file
    │       ├── RuntimeController.runtime_info()
    │       │     [extractor/runtime_controller.py:299] -> records verified/compatible/reason in provenance
    │       ├── GdbBackend.snapshot()
    │       │     [extractor/execution.py:67, 87] -> records verified/compatible/reason in provenance
    │       └── OfflineMemoryAnalyzer.analyze() (fallback provider branch)
    │             [extractor/offline_analyzer.py:447] -> raises ValueError("DEBUG_IMAGE_UNVERIFIABLE: ..." | "DEBUG_IMAGE_MISMATCH: ...")
    │
    └── DebugArtifactProvider.verify(module, debug_artifact_path)
          [extractor/debug_artifacts.py:120 -> 208]
            └── OfflineMemoryAnalyzer.analyze() (primary artifact branch)
                  [extractor/offline_analyzer.py:443] -> raises ValueError("DEBUG_IMAGE_UNVERIFIABLE: ..." | "DEBUG_IMAGE_MISMATCH: ...")
```

All callers verified:
- No caller converts `UNKNOWN_IDENTITY_UNVERIFIABLE`, `BUILD_ID_NOT_AVAILABLE`, `FINGERPRINT_MISMATCH`, or `STRICT_BUILD_ID_REQUIRED` into success.
- DWARF loading (`GdbDebugInfoProvider`, `gdb.execute("symbol-file ...")`) is blocked before execution whenever `compat.compatible` is `False`.
- `DebugImageProvider.get_provenance()` records `verified=False`, `compatible=False`, exact `reason`, `identity_policy_id`, and `identity_policy_version`.

---

## 3. Identity Verification Contract

### Equivalence & Fail-Closed Truth Table

| Runtime Build ID | Debug Build ID | Independent SHA-256 Fingerprints | `DefaultTargetIdentityPolicy` | `StrictBuildIdIdentityPolicy` |
| :--- | :--- | :--- | :--- | :--- |
| Real (`A`) | Real (`A`) | N/A | `(True, "BUILD_ID_MATCH")` | `(True, "BUILD_ID_MATCH")` |
| Real (`A`) | Real (`B`) | N/A | `(False, "BUILD_ID_MISMATCH")` | `(False, "BUILD_ID_MISMATCH")` |
| Real (`A`) | Missing / Synthetic | N/A | `(False, "BUILD_ID_NOT_AVAILABLE")` | `(False, "STRICT_BUILD_ID_REQUIRED")` |
| Missing / Synthetic | Real (`A`) | N/A | `(False, "BUILD_ID_NOT_AVAILABLE")` | `(False, "STRICT_BUILD_ID_REQUIRED")` |
| Missing / Synthetic | Missing / Synthetic | Missing / Invalid / Path-like | `(False, "UNKNOWN_IDENTITY_UNVERIFIABLE")` | `(False, "STRICT_BUILD_ID_REQUIRED")` |
| Missing / Synthetic | Missing / Synthetic | Both valid `sha256:<64hex>`, `rfp != dfp` | `(False, "FINGERPRINT_MISMATCH")` | `(False, "STRICT_BUILD_ID_REQUIRED")` |
| Missing / Synthetic | Missing / Synthetic | Both valid `sha256:<64hex>`, `rfp == dfp` | `(True, "FINGERPRINT_MATCH")` | `(False, "STRICT_BUILD_ID_REQUIRED")` |

### Documented Fingerprint Contract
- **Validation**: `normalize_sha256_fingerprint()` accepts strictly `^sha256:[0-9a-f]{64}$`. File paths, synthetic `no-build-id:...` tokens, or arbitrary strings are rejected as `None`.
- **Computation**: `compute_elf_sha256(path)` computes the whole-file SHA-256 over actual file bytes only when `os.path.isfile(path)` is true; otherwise returns `None`. Matching paths never imply matching binaries.
- **No-Build-ID Runtime Capture Preserved**: `DefaultTargetIdentityPolicy.resolve_build_id()` continues to synthesize deterministic `no-build-id:<sha256[:24]>` markers for live runtime capture transactions so runtime binaries built with `-Wl,--build-id=none` remain capturable without weakening debug-image compatibility verification.

---

## 4. Changes Made

1. **`extractor/adapters/identity_policy.py`**
   - Added `normalize_sha256_fingerprint()`.
   - Extended `validate_debug_image_compatibility()` with keyword-only optional `runtime_fingerprint` and `debug_fingerprint` parameters (backward-compatible with 2-arg callers).
   - Removed fail-open `COMPATIBLE_NO_BUILD_ID`; returns `FINGERPRINT_MATCH` / `FINGERPRINT_MISMATCH` only on valid independent `sha256:<64hex>` digests, and `UNKNOWN_IDENTITY_UNVERIFIABLE` otherwise.
   - Kept `StrictBuildIdIdentityPolicy` strictly requiring real GNU Build IDs (`STRICT_BUILD_ID_REQUIRED`).
2. **`extractor/debug_image.py`**
   - Added `compute_elf_sha256()` and optional `identity_policy` argument on `DebugImageProvider.__init__()`.
   - Routed absent/synthetic Build ID verification through `identity_policy.validate_debug_image_compatibility(..., runtime_fingerprint=..., debug_fingerprint=...)`.
   - Added `.gnu_debuglink` CRC-32 verification when the debug file exists on disk.
   - Fixed `time.perf_counter()` -> `time.monotonic()` on line 548 and recorded `identity_policy_id` / `identity_policy_version` in `get_provenance()`.
3. **`extractor/debug_artifacts.py`**
   - Closed the missing-`module.build_id` fail-open by delegating absent/synthetic Build ID verification to `identity_policy.validate_debug_image_compatibility()` (with `.gnu_debuglink` CRC fallback and `compute_elf_sha256()`).
4. **`extractor/offline_analyzer.py`**
   - Distinguished `DEBUG_IMAGE_UNVERIFIABLE` from `DEBUG_IMAGE_MISMATCH` in raised `ValueError` messages.
5. **`extractor/adapters/registry.py`**
   - Added `_redact_uri_secrets()` inside `_redact_secrets()` so secret query parameters and userinfo passwords inside `target_uri` are stripped from `describe()` outputs.
6. **Tests**
   - Added `tests/test_debug_image_identity_fail_closed.py` (17 tests covering policy matrix, real GCC `-Wl,--build-id=none` ELFs, `DebugImageProvider`, `DebugArtifactProvider`, `extract_state`, `OfflineMemoryAnalyzer`, and pure custom remote adapter contract).
   - Updated 2 outdated fail-open assertions in `tests/test_adapter_extensibility.py` and `tests/test_build_id_optional_and_single_download_bundle.py`.

---

## 5. Regression Test Matrix

- **Execution Environment**: Linux x86_64 sandbox VM, Python `3.11.2`, GCC `12.2.0`, `pytest 9.2.0`, native `target/collector/dynamicstate-collector` built, `kernel.yama.ptrace_scope=1`, `TMPDIR` on executable filesystem, no Docker, no GDB installed.

| Suite / Command | Status | Ran | Passed | Skipped | Failed/Err | Notes |
| :--- | :--- | ---: | ---: | ---: | ---: | :--- |
| `python3 -m unittest tests/test_debug_image_identity_fail_closed.py` | **PASS** | 17 | 17 | 0 | 0 | New fail-closed & custom remote contract suite |
| `python3 -m unittest tests/test_debug_image.py` | **PASS** | 8 | 8 | 0 | 0 | Existing Build ID & debuglink tests |
| `python3 -m unittest tests/test_debug_artifacts.py` | **PASS** | 7 | 7 | 0 | 0 | Existing artifact resolution & verification |
| `python3 -m unittest tests/test_build_id_optional_and_single_download_bundle.py` | **PASS** | 7 | 7 | 0 | 0 | Native collector built; 0 skipped |
| `python3 -m unittest tests/test_adapter_integration_closure.py` | **PASS** | 8 | 8 | 0 | 0 | P1/P2 adapter integration closure |
| `python3 -m unittest tests/test_adapter_extensibility.py` | **PASS** | 5 | 5 | 0 | 0 | Registry, URI, metadata, policy |
| `python3 -m pytest tests/test_trust_boundary_provenance.py -v` | **PASS** | 3 | 3 | 0 | 0 | Quarantine & parent provenance |
| `python3 scripts/run_unittest.py tests/test_phase2_0_a_3_13_identity_fail_closed.py` | **PASS** | 2 | 2 | 0 | 0 | Capture tx identity fail-closed |
| `python3 -m unittest tests/test_phase2_0_a_3_14_explicit_transaction_receipt.py` | **PASS** | 6 | 6 | 0 | 0 | Receipt validation |
| `python3 -m unittest tests/test_phase2_0_a_3_14_target_identity_and_measurement.py` | **PASS** | 3 | 3 | 0 | 0 | Target identity & SLA |
| `python3 -m unittest tests/test_phase2_0_a_3_16_strict_identity_verification.py` | **PASS** | 6 | 6 | 0 | 0 | Strict identity invariants |
| `python3 -m unittest tests/test_phase2_0_a_3_16_durable_trust_store_integration.py` | **PASS** | 5 | 5 | 0 | 0 | Durable trust store |
| `python3 -m unittest tests/test_phase3_1_1_identity_verification_and_mock_compat.py` | **PASS** | 9 | 9 | 0 | 0 | Identity & mock compat |
| `python3 scripts/run_unittest.py tests/test_capture_lifecycle_seam.py` | **PASS** | 54 | 54 | 0 | 0 | Capture lifecycle & seam |
| `python3 scripts/run_unittest.py tests/test_deadlock_real_process_baseline.py` | **PASS** | 4 | 4 | 0 | 0 | Real C++ child-process deadlock baseline |
| `python3 scripts/run_unittest.py tests/test_phase16_cli_security_and_truthfulness.py` | **PASS** | 18 | 18 | 0 | 0 | CLI provider security |
| `python3 scripts/run_unittest.py tests/test_remote_collection_correctness_closure.py` | **PASS** | 9 | 9 | 0 | 0 | Remote collection closure |
| `python3 scripts/run_unittest.py tests/test_remote_file_transfer_pipeline_integrity.py` | **PASS** | 14 | 14 | 0 | 0 | Remote transfer integrity |
| `python3 -m unittest tests/test_cli.py` | **PASS** | 5 | 5 | 0 | 0 | CLI smoke & flags |
| `python3 -m unittest tests/test_web_api.py` | **PASS** | 26 | 26 | 0 | 0 | Web API & remote time limits |
| `python3 -m unittest tests/test_web_readonly_routes.py` | **PASS** | 11 | 11 | 0 | 0 | Read-only routes |
| `python3 -m unittest tests/test_web_ui.py` | **PASS** | 23 | 23 | 0 | 0 | Dynamic Web UI rendering |
| `python3 -m unittest tests/test_phase2_1_mcp_and_ui_integration.py` | **PASS** | 2 | 2 | 0 | 0 | MCP & UI integration |
| `python3 -m unittest tests/test_ci_workflow_parity.py` | **PASS** | 8 | 8 | 0 | 0 | CI workflow parity |
| `tests/test_phase17_process_isolation_regression.py` | **ENV-FAIL (3/10)** | 10 | 7 | 0 | 3 | Grandchild reaping checks fail under sandbox container PID-1; verified on Ubuntu 22.04 CI |
| Sibling cross-process `ptrace` CLI tests (`yama.ptrace_scope=0`) | **NOT RUN** | 0 | 0 | 0 | 0 | Sandbox kernel has `yama.ptrace_scope=1` (read-only without root) |
| GDB 9.2 Docker Compatibility (`docker/gdb92/Dockerfile`) | **NOT RUN** | 0 | 0 | 0 | 0 | Docker & GDB not installed in sandbox VM |

**Local Verified Subtotal (excluding ENV-FAIL / NOT RUN)**: **260 tests ran, 260 passed, 0 skipped, 0 failed**.

---

## 6. CI Workflow Evidence

Workflows configured in `.github/workflows/`:
- `test.yml` (`Test Suite`, `ubuntu-22.04`, sets `kernel.yama.ptrace_scope=0`, builds `target/collector`, runs full unittest & benchmark matrix)
- `gdb92.yml` (`GDB 9.2 Compatibility`, `ubuntu-22.04`, builds `docker/gdb92/Dockerfile` and runs `tests/integration_gdb92.py --direct` + multithread branch isolation)
- `embedded-matrix.yml` (`Embedded Target Matrix (QEMU)`, manual/weekly schedule only)

Recorded GitHub Actions runs on **baseline commit `034f2ce47e90f421b7a604719a596417662bb9f0`**:
- **Test Suite**: `completed / success` — [https://github.com/zeeny2park/dynamicState/actions/runs/45596033842](https://github.com/zeeny2park/dynamicState/actions/runs/45596033842)
- **GDB 9.2 Compatibility**: `completed / success` — [https://github.com/zeeny2park/dynamicState/actions/runs/45596033967](https://github.com/zeeny2park/dynamicState/actions/runs/45596033967)

> **Post-fix CI Status**: **NOT RUN** — the new fail-closed fix commit has not yet been pushed to `origin` from this sandbox (no GitHub push credentials). Pushing the branch/patch will trigger both `Test Suite` and `GDB 9.2 Compatibility` on the new SHA.

---

## 7. Custom Remote Integration Scope & Remaining Limitations

### Explicit Verification Tier Separation
1. **Registry / URI Dispatch Verification — VERIFIED**: Tested via `TargetAdapterRegistry.register()`, `dispatch("customrpc://...")`, and `describe()` secret redaction (including URI query secret stripping) using `_PureCustomRemoteAdapter(TargetExecutionAdapter)` in `tests/test_debug_image_identity_fail_closed.py`.
2. **Adapter Capture Lifecycle Verification — VERIFIED**: Tested `begin_capture_transaction()` -> `read_memory()` -> `commit_capture_transaction()` -> `issue_live_receipt_for_session()` -> `LiveCaptureReceipt.verify(identity_policy=...)` with `DurableTrustStore` on `_PureCustomRemoteAdapter` (not subclassing `LocalTargetAdapter` or `RemoteSshTargetAdapter`).
3. **Real Remote Execution Verification — NOT RUN**: No live non-SSH custom remote daemon/transport was executed over a network.

### Remaining Limitations
- **Direct `RemoteSshTargetAdapter` instantiation in 2 legacy modules**: `extractor/web/explore.py:175` (Web Explorer) and `extractor/watch_session.py:466` (Watch Session) still instantiate `RemoteSshTargetAdapter` directly rather than dispatching through `DEFAULT_ADAPTER_REGISTRY`. Core diagnosis (`expert_diagnostic_engine.py`, `web/server.py`, `cli.py`, `mcp_server.py`) uses the registry and generic `adapter.is_remote()`.
- **Stripped binary + separate unstripped `.debug` without Build ID or `.gnu_debuglink`**: Whole-file SHA-256 differs after `strip -s`, so pairing a stripped binary with a separate unstripped `.debug` file that has neither GNU Build ID nor `.gnu_debuglink` intentionally fails closed (`FINGERPRINT_MISMATCH`).
- **Sandbox environment gaps**: `yama.ptrace_scope=1`, container PID-1 grandchild reaping (`test_phase17_process_isolation_regression.py`), and absence of Docker/GDB 9.2 prevent local execution of those CI-only suites until pushed to GitHub Actions.

---

## 8. Final Verdict: **CONDITIONAL GO**

- **Met**:
  - Debug Image compatibility can no longer be approved without either matching real GNU Build IDs, valid `.gnu_debuglink` (filename + CRC when on disk), or independently computed matching `sha256:<64hex>` content fingerprints.
  - Both fail-open paths (`DefaultTargetIdentityPolicy.validate_debug_image_compatibility` and `DebugArtifactProvider.verify`) and the URI query secret leak in `TargetAdapterRegistry.describe()` are closed and covered by regression tests.
  - All 260 locally runnable tests across identity, callers, adapters, trust-store, CLI, MCP, and Web API pass with 0 skips and 0 failures.
- **Condition for Full GO**:
  - Push the patch/commit to GitHub and confirm green runs of `.github/workflows/test.yml` (including `yama.ptrace_scope=0` sibling ptrace & `test_phase17_process_isolation_regression.py`) and `.github/workflows/gdb92.yml` on the new commit SHA.

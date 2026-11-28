# Unified Debug Image Identity Verification Closure

- **Repository**: `https://github.com/zeeny2park/dynamicState`
- **Baseline HEAD**: `1fcdc4c380a05aebe5392f04ebed3e6ecc474302`
- **Branch**: `fix/unified-debug-image-verification`
- **Date**: 2026-11-26
- **Final Verdict**: **CONDITIONAL GO** (all unified provider parity, `.gnu_debuglink` fail-closed, caller, and local regression tests pass; pending GitHub Actions `Test Suite` and `GDB 9.2 Compatibility` green runs on the new commit SHA after push)

---

## 1. Root Cause

Two separate `.gnu_debuglink` fail-open paths remained in `1fcdc4c380a05aebe5392f04ebed3e6ecc474302` due to duplicated, subtly divergent verification logic across the two Debug Image providers:

1. **`extractor/debug_image.py:559-578`** (`DebugImageProvider.verify()`): initialized `crc_ok = True` and only computed CRC-32 inside `if expected_crc is not None and os.path.isfile(self.debug_image_path):`. Whenever `.gnu_debuglink` lacked a CRC (`crc=None`) or `debug_image_path` was not a readable file on disk, `expected_name == actual_name and crc_ok` evaluated to `True`, approving the debug image as `COMPATIBLE_DEBUGLINK` based solely on filename equality.
2. **`extractor/debug_artifacts.py:196-214`** (`DebugArtifactProvider.verify()`): contained the exact same duplicated `crc_ok = True` pattern, approving filename-only `.gnu_debuglink` matches whenever CRC was absent or unreadable.
3. **Divergent logic & incomplete provenance**: `DebugImageProvider` and `DebugArtifactProvider` maintained separate copies of Build ID, `.gnu_debuglink`, and SHA-256 fingerprint branching, and `CompatibilityResult` / `get_provenance()` did not expose `verification_method`, `verification_result`, or canonical `verification_reason` to distinguish CRC-32 verification from SHA-256 or GNU Build ID verification.

---

## 2. All Affected Call Sites

```text
verify_debug_image_identity()
  [extractor/adapters/identity_policy.py:224]
    ▲
    ├── DebugImageProvider.verify(runtime_binary_path)
    │     [extractor/debug_image.py:451 -> 539]
    │       ├── extract_state.snapshot()
    │       │     [extractor/extract_state.py:16] -> raises RuntimeError("DEBUG_IMAGE_INCOMPATIBLE: ...") before gdb symbol-file
    │       ├── RuntimeController.load_debug_image()
    │       │     [extractor/runtime_controller.py:225] -> raises RuntimeError("DEBUG_IMAGE_INCOMPATIBLE: ...") before gdb symbol-file
    │       ├── RuntimeController.runtime_info()
    │       │     [extractor/runtime_controller.py:299] -> records provenance
    │       ├── GdbBackend.snapshot()
    │       │     [extractor/execution.py:67, 87] -> records provenance
    │       └── OfflineMemoryAnalyzer.analyze() (provider fallback)
    │             [extractor/offline_analyzer.py:447] -> raises ValueError("DEBUG_IMAGE_UNVERIFIABLE: ..." | "DEBUG_IMAGE_MISMATCH: ...")
    │
    └── DebugArtifactProvider.verify(module, debug_artifact_path)
          [extractor/debug_artifacts.py:120 -> 172]
            └── OfflineMemoryAnalyzer.analyze() (primary artifact path)
                  [extractor/offline_analyzer.py:443] -> raises ValueError("DEBUG_IMAGE_UNVERIFIABLE: ..." | "DEBUG_IMAGE_MISMATCH: ...")
```

---

## 3. Unified Verification Contract

Both `DebugImageProvider.verify()` and `DebugArtifactProvider.verify()` now delegate identity verification to the single shared function `verify_debug_image_identity()` (`extractor/adapters/identity_policy.py`), returning an immutable `DebugImageVerificationResult` with explicit provenance fields:

- `verification_method`: `"gnu_build_id"` | `"gnu_debuglink_crc32"` | `"sha256_fingerprint"` | `"none"`
- `identity_policy_id`: policy identifier (e.g. `"default-optional-build-id"`, `"strict-build-id"`)
- `identity_policy_version`: policy version (e.g. `"1.0"`)
- `verification_result`: `"VERIFIED"` | `"MISMATCH"` | `"UNVERIFIABLE"`
- `verification_reason`: canonical reason code (`BUILD_ID_MATCH`, `BUILD_ID_MISMATCH`, `BUILD_ID_NOT_AVAILABLE`, `COMPATIBLE_DEBUGLINK`, `DEBUGLINK_CRC_MISMATCH`, `FINGERPRINT_MATCH`, `FINGERPRINT_MISMATCH`, `STRICT_BUILD_ID_REQUIRED`, `UNKNOWN_IDENTITY_UNVERIFIABLE`)

### Precedence & Truth Table (Identical Across Both Providers)

| Input Evidence | `compatible` | `verification_method` | `verification_result` | `verification_reason` |
| :--- | :--- | :--- | :--- | :--- |
| Real Build IDs match (`A == A`) | `True` | `gnu_build_id` | `VERIFIED` | `BUILD_ID_MATCH` |
| Real Build IDs differ (`A != B`) | `False` | `gnu_build_id` | `MISMATCH` | `BUILD_ID_MISMATCH` |
| One real Build ID, one missing/synthetic | `False` | `gnu_build_id` (`none` if strict) | `UNVERIFIABLE` | `BUILD_ID_NOT_AVAILABLE` (`STRICT_BUILD_ID_REQUIRED`) |
| Both Build IDs absent/synthetic + `StrictBuildIdIdentityPolicy` | `False` | `none` | `UNVERIFIABLE` | `STRICT_BUILD_ID_REQUIRED` |
| Absent Build IDs + `.gnu_debuglink` basename match + valid CRC-32 over actual bytes | `True` | `gnu_debuglink_crc32` | `VERIFIED` | `COMPATIBLE_DEBUGLINK` |
| Absent Build IDs + `.gnu_debuglink` basename match + incorrect CRC-32 (and no matching SHA-256) | `False` | `gnu_debuglink_crc32` | `MISMATCH` | `DEBUGLINK_CRC_MISMATCH` |
| Absent Build IDs + `.gnu_debuglink` basename match + **missing CRC** + no matching SHA-256 | `False` | `none` | `UNVERIFIABLE` | `UNKNOWN_IDENTITY_UNVERIFIABLE` |
| Absent Build IDs + `.gnu_debuglink` basename mismatch + no matching SHA-256 | `False` | `none` | `UNVERIFIABLE` | `UNKNOWN_IDENTITY_UNVERIFIABLE` |
| Absent Build IDs + matching verified `sha256:<64hex>` fingerprints | `True` | `sha256_fingerprint` | `VERIFIED` | `FINGERPRINT_MATCH` |
| Absent Build IDs + mismatched verified `sha256:<64hex>` fingerprints | `False` | `sha256_fingerprint` | `MISMATCH` | `FINGERPRINT_MISMATCH` |
| Absent Build IDs + no valid fingerprints | `False` | `none` | `UNVERIFIABLE` | `UNKNOWN_IDENTITY_UNVERIFIABLE` |

- CRC-32 verification is always reported as `verification_method="gnu_debuglink_crc32"`, never as `"sha256_fingerprint"`.
- Runtime capture without GNU Build IDs remains supported via `DefaultTargetIdentityPolicy.resolve_build_id()`.

---

## 4. Changes & Source Locations

1. **`extractor/adapters/identity_policy.py`**
   - Added `DebugImageVerificationResult`, `_is_real_build_id()`, and `verify_debug_image_identity()`.
2. **`extractor/debug_image.py`**
   - Extended `CompatibilityResult` with `verification_method`, `identity_policy_id`, `identity_policy_version`, `verification_result`, `verification_reason`.
   - Replaced duplicated identity/debuglink logic in `DebugImageProvider.verify()` with `verify_debug_image_identity()`.
   - Updated `DebugImageProvider.get_provenance()` to expose all 5 explicit provenance fields.
3. **`extractor/debug_artifacts.py`**
   - Replaced duplicated identity/debuglink logic in `DebugArtifactProvider.verify()` with `verify_debug_image_identity()`, preserving legacy `DEBUG_IMAGE_MISMATCH` `reason` on real runtime Build ID mismatch while exposing canonical `verification_reason`, `verification_method`, and `verification_result`.
4. **Tests**
   - Added `tests/test_unified_debug_image_verification.py` (12 tests verifying strict parity across both providers, all `.gnu_debuglink` CRC cases, `OfflineMemoryAnalyzer`, and GDB `symbol-file` blocking).
   - Updated `tests/test_debug_image.py::test_verify_debuglink_fallback` to verify actual CRC-32 bytes on a real temporary debug file rather than relying on the old nonexistent-file fail-open.

---

## 5. Regression Test Results

- **Environment**: Linux x86_64 sandbox VM, Python `3.11.2`, GCC `12.2.0`, `pytest 9.2.0`, native `target/collector/dynamicstate-collector` built, `kernel.yama.ptrace_scope=1`, no Docker, no GDB installed.

| Suite | Status | Ran | Passed | Skipped | Fail/Err | Notes |
| :--- | :--- | ---: | ---: | ---: | ---: | :--- |
| `tests/test_unified_debug_image_verification.py` | **PASS** | 12 | 12 | 0 | 0 | New parity, debuglink CRC, OfflineMemoryAnalyzer & GDB block suite |
| `tests/test_debug_image_identity_fail_closed.py` | **PASS** | 17 | 17 | 0 | 0 | Identity policy matrix & custom remote contract |
| `tests/test_debug_image.py` | **PASS** | 8 | 8 | 0 | 0 | Updated real-byte CRC debuglink test |
| `tests/test_debug_artifacts.py` | **PASS** | 7 | 7 | 0 | 0 | Artifact discovery & verification |
| `tests/test_adapter_integration_closure.py` | **PASS** | 8 | 8 | 0 | 0 | Adapter integration closure |
| `tests/test_adapter_extensibility.py` | **PASS** | 5 | 5 | 0 | 0 | Registry, URI, metadata, policy |
| `tests/test_build_id_optional_and_single_download_bundle.py` | **PASS** | 7 | 7 | 0 | 0 | Native collector built; 0 skipped |
| `tests/test_trust_boundary_provenance.py` (`pytest`) | **PASS** | 3 | 3 | 0 | 0 | Quarantine & parent provenance |
| `tests/test_phase2_1_mcp_and_ui_integration.py` | **PASS** | 2 | 2 | 0 | 0 | MCP & UI integration |
| `tests/test_binary_identity.py` | **PASS** | 5 | 5 | 0 | 0 | ELF `.note.gnu.build-id` & `.gnu_debuglink` parsing |
| `tests/test_phase2_0_a_3_13_identity_fail_closed.py` | **PASS** | 2 | 2 | 0 | 0 | Capture tx identity fail-closed |
| `tests/test_phase2_0_a_3_14_explicit_transaction_receipt.py` | **PASS** | 6 | 6 | 0 | 0 | Receipt validation |
| `tests/test_phase2_0_a_3_16_strict_identity_verification.py` | **PASS** | 6 | 6 | 0 | 0 | Strict identity invariants |
| `tests/test_phase3_1_1_identity_verification_and_mock_compat.py` | **PASS** | 9 | 9 | 0 | 0 | Identity & mock compat |
| `tests/test_deadlock_real_process_baseline.py` | **PASS** | 4 | 4 | 0 | 0 | Real C++ child-process deadlock baseline |
| `tests/test_cli.py` | **PASS** | 5 | 5 | 0 | 0 | CLI smoke & flags |
| `tests/test_web_api.py` | **PASS** | 26 | 26 | 0 | 0 | Web API |
| `tests/test_web_readonly_routes.py` | **PASS** | 11 | 11 | 0 | 0 | Read-only routes |
| `tests/test_web_ui.py` | **PASS** | 23 | 23 | 0 | 0 | Web UI |
| `tests/test_ci_workflow_parity.py` | **PASS** | 8 | 8 | 0 | 0 | CI workflow parity |
| `tests/test_audit_hardening.py` | **ENV-ERR (1/20)** | 20 | 19 | 0 | 1 | All 19 identity/debuglink tests PASS (incl. AUDIT-D & AUDIT-E); 1 error is `FileNotFoundError: 'gdb'` in `test_audit_003_gdb_batch_invocation_path_with_spaces` |
| GDB 9.2 Docker Compatibility (`gdb92.yml`) | **NOT RUN** | 0 | 0 | 0 | 0 | Docker & GDB not installed in sandbox VM |
| Sibling cross-process `ptrace` CLI tests (`yama.ptrace_scope=0`) | **NOT RUN** | 0 | 0 | 0 | 0 | Sandbox kernel has `yama.ptrace_scope=1` |

**Local Verified Subtotal**: **193 passed, 0 skipped, 1 environment-blocked error (`gdb` binary unavailable)**.

---

## 6. CI Workflow Evidence

Recorded GitHub Actions runs on **baseline commit `1fcdc4c380a05aebe5392f04ebed3e6ecc474302`**:
- **Test Suite**: `completed / success` — [https://github.com/zeeny2park/dynamicState/actions/runs/45720140891](https://github.com/zeeny2park/dynamicState/actions/runs/45720140891)
- **GDB 9.2 Compatibility**: `completed / success` — [https://github.com/zeeny2park/dynamicState/actions/runs/45720140820](https://github.com/zeeny2park/dynamicState/actions/runs/45720140820)

> **Post-fix CI Status**: **NOT RUN** — the new commit has not yet been pushed to GitHub from this sandbox (no push credentials). Pushing the branch/patch will execute both `Test Suite` and `GDB 9.2 Compatibility` on the exact final commit SHA.

---

## 7. Remaining Limitations

- `DebugArtifactProvider.find_debug_artifact()` (`extractor/debug_artifacts.py:98-102`) still permits discovering an adjacent candidate file when `.gnu_debuglink` omits CRC, but discovery does not imply approval: `verify()` always runs afterward and fails closed (`UNKNOWN_IDENTITY_UNVERIFIABLE` or `FINGERPRINT_MISMATCH`) unless independent matching SHA-256 fingerprints verify identical bytes.
- Full CI verification on the final commit SHA (including `gdb`-dependent tests such as `test_audit_003_gdb_batch_invocation_path_with_spaces`, `yama.ptrace_scope=0` sibling ptrace tests, and `gdb92.yml`) requires pushing to GitHub Actions.

---

## 8. Final Verdict: **CONDITIONAL GO**

- **Met**:
  - Single shared `verify_debug_image_identity()` enforces identical fail-closed rules in both `DebugImageProvider` and `DebugArtifactProvider`.
  - No filename-only `.gnu_debuglink` approval remains anywhere in the verification path; missing CRC fails closed to `UNKNOWN_IDENTITY_UNVERIFIABLE` (unless independently verified matching SHA-256 fingerprints exist), and bad CRC fails closed with `DEBUGLINK_CRC_MISMATCH`.
  - Provenance explicitly separates `gnu_build_id`, `gnu_debuglink_crc32`, `sha256_fingerprint`, and `none`.
  - All 12 new parity/debuglink tests and all 193 locally runnable tests pass with 0 skips.
- **Condition for Full GO**:
  - Push the commit/patch to GitHub and confirm green `Test Suite` and `GDB 9.2 Compatibility` runs on the exact final commit SHA.

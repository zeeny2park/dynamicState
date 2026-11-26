# Identity Policy Fallback Authorization Closure

- **Repository**: `https://github.com/zeeny2park/dynamicState`
- **Baseline HEAD**: `0864b0f771b731b63be25f38371da97893f1351c`
- **Branch**: `fix/identity-policy-fallback-authorization`
- **Date**: 2026-11-26
- **Final Verdict**: **CONDITIONAL GO** (custom policy fallback authorization is enforced fail-closed across both providers and all 196 locally runnable tests pass; pending push to GitHub Actions to confirm green `Test Suite` and `GDB 9.2 Compatibility` runs on the final commit SHA)

---

## 1. Root Cause

In baseline `0864b0f771b731b63be25f38371da97893f1351c`, `verify_debug_image_identity()` (`extractor/adapters/identity_policy.py:352`) guarded `.gnu_debuglink` CRC-32 fallback using a concrete-class check:

```python
if isinstance(pol, StrictBuildIdIdentityPolicy):
    return DebugImageVerificationResult(..., verification_reason="STRICT_BUILD_ID_REQUIRED")
```

Because `TargetIdentityPolicy` is an extensible strategy interface, any custom policy subclassing `TargetIdentityPolicy` directly (rather than `StrictBuildIdIdentityPolicy`) bypassed this concrete-class check. Even when the custom policy's `validate_debug_image_compatibility()` rejected absent or synthetic Build IDs, `verify_debug_image_identity()` proceeded to step 4 and approved the debug image whenever a matching `.gnu_debuglink` CRC-32 was present.

---

## 2. Policy Authorization Contract

Replaced the concrete-class `isinstance` check with an explicit, polymorphic, **fail-closed by default** policy authorization method on `TargetIdentityPolicy`:

- **`TargetIdentityPolicy.authorize_debuglink_fallback(runtime_build_id, debug_build_id) -> Tuple[bool, str]`** (`extractor/adapters/identity_policy.py:96`):
  - Default implementation returns `(False, "DEBUGLINK_FALLBACK_NOT_AUTHORIZED")`.
  - Any custom `TargetIdentityPolicy` subclass MUST explicitly override this method and return `(True, ...)` to allow `.gnu_debuglink` CRC-32 fallback.
- **`DefaultTargetIdentityPolicy.authorize_debuglink_fallback(...)`** (`extractor/adapters/identity_policy.py:209`):
  - Returns `(True, "DEBUGLINK_FALLBACK_ALLOWED")` when both runtime and debug Build IDs are absent/synthetic; otherwise `(False, "BUILD_ID_NOT_AVAILABLE")`.
- **`StrictBuildIdIdentityPolicy.authorize_debuglink_fallback(...)`** (`extractor/adapters/identity_policy.py:280`):
  - Unconditionally returns `(False, "STRICT_BUILD_ID_REQUIRED")`.
- **`verify_debug_image_identity(...)`** (`extractor/adapters/identity_policy.py:391`):
  - Calls `dl_allowed, _ = pol.authorize_debuglink_fallback(runtime_build_id, debug_build_id)` before attempting `.gnu_debuglink` CRC-32 verification.
  - When `dl_allowed` is `False`, `.gnu_debuglink` fallback is never attempted and the verifier delegates directly to `pol.validate_debug_image_compatibility(...)`, preserving the policy's exact rejection reason and never overriding a policy rejection.
  - Both `DebugImageProvider.verify()` (`extractor/debug_image.py:542`) and `DebugArtifactProvider.verify()` (`extractor/debug_artifacts.py:175`) call `verify_debug_image_identity()`, ensuring identical decisions and provenance (`verification_method`, `identity_policy_id`, `identity_policy_version`, `verification_result`, `verification_reason`).

---

## 3. Before / After Behavior Matrix

| Policy | Scenario | Before (`0864b0f`) | After (this fix) |
| :--- | :--- | :--- | :--- |
| `DefaultTargetIdentityPolicy` | Absent Build ID + valid `.gnu_debuglink` CRC | `True` (`COMPATIBLE_DEBUGLINK`, `gnu_debuglink_crc32`) | `True` (`COMPATIBLE_DEBUGLINK`, `gnu_debuglink_crc32`) |
| `StrictBuildIdIdentityPolicy` | Absent Build ID + valid `.gnu_debuglink` CRC | `False` (`STRICT_BUILD_ID_REQUIRED`) | `False` (`STRICT_BUILD_ID_REQUIRED`) |
| **Custom strict `TargetIdentityPolicy`** (not subclassing `StrictBuildIdIdentityPolicy`) | Absent Build ID + valid `.gnu_debuglink` CRC | **`True` (`COMPATIBLE_DEBUGLINK`) — BYPASS!** | **`False` (`CUSTOM_BUILD_ID_REQUIRED`, `none`, `UNVERIFIABLE`)** |
| **Custom `TargetIdentityPolicy`** overriding `authorize_debuglink_fallback -> True` | Absent Build ID + valid `.gnu_debuglink` CRC | `True` (`COMPATIBLE_DEBUGLINK`) | `True` (`COMPATIBLE_DEBUGLINK`, `gnu_debuglink_crc32`) |
| **Custom `TargetIdentityPolicy`** overriding `authorize_debuglink_fallback -> True` | Absent Build ID + missing CRC | `False` (`CUSTOM_SHA256_DISALLOWED`) | `False` (`CUSTOM_SHA256_DISALLOWED`, `none`, `UNVERIFIABLE`) |
| **Custom `TargetIdentityPolicy`** overriding `authorize_debuglink_fallback -> True` | Absent Build ID + incorrect CRC | `False` (`DEBUGLINK_CRC_MISMATCH`) | `False` (`DEBUGLINK_CRC_MISMATCH`, `gnu_debuglink_crc32`, `MISMATCH`) |
| **Custom `TargetIdentityPolicy`** rejecting SHA-256 fallback | Absent Build ID + matching SHA-256 | `False` (`CUSTOM_SHA256_DISALLOWED`) | `False` (`CUSTOM_SHA256_DISALLOWED`, `none`, `UNVERIFIABLE`) |
| Any policy | Real Build IDs match / mismatch | `True` (`BUILD_ID_MATCH`) / `False` (`BUILD_ID_MISMATCH`) | `True` (`BUILD_ID_MATCH`) / `False` (`BUILD_ID_MISMATCH`) |

---

## 4. Regression Test Results

- **Environment**: Linux x86_64 sandbox VM, Python `3.11.2`, GCC `12.2.0`, `pytest 9.2.0`, native `target/collector/dynamicstate-collector` built, `kernel.yama.ptrace_scope=1`, no Docker, no GDB installed.

| Suite | Status | Ran | Passed | Skipped | Fail/Err | Notes |
| :--- | :--- | ---: | ---: | ---: | ---: | :--- |
| `tests/test_unified_debug_image_verification.py` | **PASS** | 15 | 15 | 0 | 0 | Includes new tests 13–15: custom strict policy bypass block, custom debuglink-authorized policy, custom SHA-256 rejection, Build ID match/mismatch, both providers & provenance parity |
| `tests/test_debug_image_identity_fail_closed.py` | **PASS** | 17 | 17 | 0 | 0 | Identity policy matrix & custom remote contract |
| `tests/test_debug_image.py` | **PASS** | 8 | 8 | 0 | 0 | Build ID & real-byte CRC debuglink tests |
| `tests/test_debug_artifacts.py` | **PASS** | 7 | 7 | 0 | 0 | Artifact discovery & verification |
| `tests/test_adapter_integration_closure.py` | **PASS** | 8 | 8 | 0 | 0 | Adapter integration closure |
| `tests/test_adapter_extensibility.py` | **PASS** | 5 | 5 | 0 | 0 | Registry, URI, metadata, policy |
| `tests/test_build_id_optional_and_single_download_bundle.py` | **PASS** | 7 | 7 | 0 | 0 | Native collector built; 0 skipped |
| `tests/test_trust_boundary_provenance.py` (`pytest`) | **PASS** | 3 | 3 | 0 | 0 | Quarantine & parent provenance |
| `tests/test_binary_identity.py` | **PASS** | 5 | 5 | 0 | 0 | ELF identity parsing |
| `tests/test_phase2_0_a_3_13_identity_fail_closed.py` | **PASS** | 2 | 2 | 0 | 0 | Capture tx identity fail-closed |
| `tests/test_phase2_0_a_3_14_explicit_transaction_receipt.py` | **PASS** | 6 | 6 | 0 | 0 | Receipt validation |
| `tests/test_phase2_0_a_3_16_strict_identity_verification.py` | **PASS** | 6 | 6 | 0 | 0 | Strict identity invariants |
| `tests/test_phase3_1_1_identity_verification_and_mock_compat.py` | **PASS** | 9 | 9 | 0 | 0 | Identity & mock compat |
| `tests/test_deadlock_real_process_baseline.py` | **PASS** | 4 | 4 | 0 | 0 | Real C++ deadlock baseline |
| `tests/test_cli.py` | **PASS** | 5 | 5 | 0 | 0 | CLI smoke & flags |
| `tests/test_web_api.py` | **PASS** | 26 | 26 | 0 | 0 | Web API |
| `tests/test_web_readonly_routes.py` | **PASS** | 11 | 11 | 0 | 0 | Read-only routes |
| `tests/test_web_ui.py` | **PASS** | 23 | 23 | 0 | 0 | Web UI |
| `tests/test_phase2_1_mcp_and_ui_integration.py` | **PASS** | 2 | 2 | 0 | 0 | MCP & UI integration |
| `tests/test_ci_workflow_parity.py` | **PASS** | 8 | 8 | 0 | 0 | CI workflow parity |
| `tests/test_audit_hardening.py` | **ENV-ERR (1/20)** | 20 | 19 | 0 | 1 | All 19 identity/debuglink tests PASS; 1 error (`FileNotFoundError: 'gdb'`) in `test_audit_003_gdb_batch_invocation_path_with_spaces` |
| GDB 9.2 Compatibility (`gdb92.yml`) | **NOT RUN** | 0 | 0 | 0 | 0 | Docker & GDB not installed in sandbox VM |
| Sibling cross-process `ptrace` CLI tests (`yama.ptrace_scope=0`) | **NOT RUN** | 0 | 0 | 0 | 0 | Sandbox kernel has `yama.ptrace_scope=1` |

**Local Verified Subtotal**: **196 passed, 0 skipped, 1 environment-blocked error (`gdb` unavailable)**.

---

## 5. GitHub Actions CI Evidence

Recorded GitHub Actions runs on **baseline commit `0864b0f771b731b63be25f38371da97893f1351c`**:
- **Test Suite**: `completed / success` — [https://github.com/zeeny2park/dynamicState/actions/runs/45732462357](https://github.com/zeeny2park/dynamicState/actions/runs/45732462357)
- **GDB 9.2 Compatibility**: `completed / success` — [https://github.com/zeeny2park/dynamicState/actions/runs/45732462349](https://github.com/zeeny2park/dynamicState/actions/runs/45732462349)

> **Post-fix CI Status**: **NOT RUN** — this sandbox has no GitHub push credentials (`gh`/SSH/PAT), so the final commit could not be pushed from here. Pushing the delivered patch/commit will trigger both `Test Suite` and `GDB 9.2 Compatibility` on the final commit SHA.

---

## 6. Remaining Limitations

- Custom policies that subclass `DefaultTargetIdentityPolicy` (rather than `TargetIdentityPolicy`) inherit `DefaultTargetIdentityPolicy.authorize_debuglink_fallback()` and must override `authorize_debuglink_fallback()` if they wish to revoke `.gnu_debuglink` fallback; subclassing `TargetIdentityPolicy` directly is fail-closed by default.
- Full CI verification on the exact final commit SHA (`Test Suite` including `gdb`-dependent tests and `yama.ptrace_scope=0`, plus `GDB 9.2 Compatibility`) requires pushing to GitHub Actions.

---

## 7. Final Verdict: **CONDITIONAL GO**

- **Met**:
  - Concrete-class `isinstance(pol, StrictBuildIdIdentityPolicy)` check removed from `verify_debug_image_identity()`.
  - Explicit fail-closed `TargetIdentityPolicy.authorize_debuglink_fallback()` contract enforced identically across both `DebugImageProvider` and `DebugArtifactProvider`.
  - Custom strict policies can no longer be bypassed by matching `.gnu_debuglink` CRCs, and custom policies that reject SHA-256 fallback cannot be overridden.
  - All 15 tests in `tests/test_unified_debug_image_verification.py` and 196 locally runnable tests pass with 0 skips.
- **Condition for Full GO**:
  - Apply the patch, push to GitHub, and verify green runs of `Test Suite` and `GDB 9.2 Compatibility` on the exact final commit SHA.

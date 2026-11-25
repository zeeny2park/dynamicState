# Adapter Architecture Integration & Identity Policy Closure Report

- **Baseline Commit**: `2ef43938ef01857ef1dce60ee64599b74fe296e7`
- **Closure Branch**: `fix/adapter-integration-identity-closure`
- **Date**: 2026-11-25
- **Final Verdict**: **CONDITIONAL GO** (All 140 executed integration and regression tests across CaptureTransaction, LiveCaptureReceipt, DurableTrustStore, Generic Transport API, Dynamic Web UI, Registry, and CLI passed; pytest-only trust suites and `ptrace_scope=0` cross-process CLI suites were `NOT RUN` in this sandbox and must run in CI.)

## 1. Audit Findings (Severity & Source Locations)

| ID | Severity | Area | Finding & Root Cause | Source Location |
| :--- | :--- | :--- | :--- | :--- |
| **F-01** | **P1** | Identity Policy Propagation | `issue_live_receipt_for_session()` ignored `self.get_identity_policy()` and read raw `ident.get("build_id") or ""`, omitting synthetic `no-build-id:` resolution and omitting policy provenance (`identity_policy_id`, `identity_policy_version`, `identity_verification_mode`) from signed `target_constraints`. | `extractor/target_adapter.py:1348-1375` |
| **F-02** | **P1** | Missing Build ID Loophole | `DefaultTargetIdentityPolicy.validate_build_id_match()` treated an empty `actual_build_id` (`""`) as matching a synthetic `no-build-id:...` expected identity, allowing unverifiable/missing actual executable identity to pass verification. | `extractor/adapters/identity_policy.py:73-84` |
| **F-03** | **P1** | Silent Policy Fallback | `LiveCaptureReceipt.verify()` had no `identity_policy` parameter and silently fell back to `DEFAULT_IDENTITY_POLICY` even when a non-default policy had captured the receipt, failing to detect capture-vs-validation policy mismatches. | `extractor/capture_backend.py:568-640` |
| **F-04** | **P2** | Generic Remote Time Limit | `WebApiAdapter._parse_diagnose_request()` capped `time_limit_s` using `params.get("remote_host") not in (None, "")`, causing custom remote transports (`transport="xssh"`, `target_uri="xssh://..."`) without `remote_host` to be capped at the local limit instead of `DIAGNOSE_REMOTE_MAX_TIME_LIMIT_S`. Required custom transport fields were also not validated. | `extractor/web/server.py:3368-3415` |
| **F-05** | **P2** | Registry Scheme Ownership & Concurrency | `TargetAdapterRegistry` had no lock (`RLock`) for concurrent access, and `register()` silently overwrote URI scheme ownership held by another registered transport. | `extractor/adapters/registry.py:114-180` |
| **F-06** | **P2** | URI & Secret Validation | `parse_target_uri()` silently accepted port `0`, whitespace/control chars, and duplicate query parameter keys (`parse_qsl` overwrite); `describe()` did not recursively redact secrets returned by a custom `describe_fn`. | `extractor/adapters/uri.py:21-46`, `extractor/adapters/registry.py:259-271` |

## 2. Changes Made

1. **`extractor/adapters/identity_policy.py`**:
   - Added `policy_id`, `policy_version`, `is_synthetic_build_id()`, `verification_mode()` (`verified_build_id` / `synthetic_no_build_id` / `unverifiable`), and `describe()` to `TargetIdentityPolicy`.
   - Closed F-02: `DefaultTargetIdentityPolicy.validate_build_id_match()` now fails closed (`missing_actual_build_id`) whenever `actual_build_id` is empty against a non-empty (including `no-build-id:...`) `expected_build_id`, and returns `mismatched_executable_fingerprint` on mismatched synthetic hashes.
   - Tightened `StrictBuildIdIdentityPolicy.validate_build_id_match()` to reject both empty and `no-build-id:` synthetic markers.
2. **`extractor/target_adapter.py`**:
   - Updated `issue_live_receipt_for_session()` to resolve `build_id` through `self.get_identity_policy()`, record HMAC-signed `identity_policy_id`, `identity_policy_version`, and `identity_verification_mode` in `target_constraints`, and attach `rcpt._identity_policy = id_policy`.
3. **`extractor/capture_backend.py`**:
   - Added `identity_policy: Optional[Any] = None` to `LiveCaptureReceipt.verify()`.
   - Enforced fail-closed checks: `identity_policy_mismatch` when validator policy differs from captured `identity_policy_id`, and `missing_required_identity_policy` when a deserialized receipt recorded a non-default policy without supplying that policy (no silent fallback to `DEFAULT_IDENTITY_POLICY`). Legacy receipts without `identity_policy_id` remain backward-compatible.
4. **`extractor/web/server.py`**:
   - Deferred `time_limit_s` capping in `_parse_diagnose_request()` until transport metadata is resolved from `DEFAULT_ADAPTER_REGISTRY`, using `desc.metadata.is_remote` to select `DIAGNOSE_REMOTE_MAX_TIME_LIMIT_S` vs `DIAGNOSE_MAX_TIME_LIMIT_S`.
   - Added `DEFAULT_ADAPTER_REGISTRY.validate_transport_params()` validation for missing/empty required fields and malformed `target_uri` / `transport_params`.
5. **`extractor/adapters/registry.py` & `extractor/adapters/uri.py`**:
   - Added `threading.RLock` across all `TargetAdapterRegistry` operations.
   - Enforced unambiguous URI scheme ownership (raising `ValueError` on cross-transport collisions unless `allow_scheme_override=True`), clean stale-scheme cleanup on `replace=True` / `unregister()`, and `scheme_owner()` inspection.
   - Hardened `parse_target_uri()` against invalid ports (`0`, `>65535`), whitespace/control characters, invalid schemes, and duplicate query parameters.
   - Added recursive `_redact_secrets()` defense-in-depth on `describe()` (including custom `describe_fn` outputs) and `discover_destinations()` outputs, with `discovery_error: True` isolation on discovery exceptions.
6. **`tests/test_adapter_integration_closure.py` & `tests/test_adapter_extensibility.py`**:
   - Added end-to-end integration tests through `CaptureTransaction`, `commit_capture_transaction`, `issue_live_receipt_for_session`, `DurableTrustStore`, `LiveCaptureReceipt.verify()`, `WebApiAdapter._parse_diagnose_request`, `TargetAdapterRegistry`, URI validation, and secret redaction.

## 3. Identity-Policy Lifecycle Verification

| Stage | Verified Behavior |
| :--- | :--- |
| `Adapter.get_identity_policy()` | Returns adapter-selected `TargetIdentityPolicy` (`DefaultTargetIdentityPolicy`, `StrictBuildIdIdentityPolicy`, or custom policy). |
| `CaptureTransaction` (`commit_capture_transaction`) | Calls `pol.resolve_build_id(cur_ident, target_tx.metadata)`; records `identity_policy_id`, `identity_policy_version`, `identity_verification_mode`; `StrictBuildIdIdentityPolicy` raises `MissingIdentityFieldError` on absent Build ID. |
| `LiveCaptureReceipt` issuance (`issue_live_receipt_for_session`) | Uses `self.get_identity_policy()` to resolve `build_id`, embeds signed provenance in `target_constraints`, attaches `_identity_policy`, and binds operation receipt in `DurableTrustStore`. |
| `LiveCaptureReceipt.verify()` | Enforces exact policy match (`identity_policy_mismatch` on divergence), blocks silent fallback for non-default recorded policies (`missing_required_identity_policy`), rejects empty actual Build ID against synthetic expected (`missing_actual_build_id`), and rejects mismatched executable fingerprints (`mismatched_executable_fingerprint`). |
| Snapshot Binding & Trust Store | `DurableTrustStore.used_operation_ids[tx.transaction_id]["receipt_id"] == rcpt.receipt_id` and `expected_snapshot_binding` verified end-to-end. |

## 4. Local / SSH / Custom Transport Comparison

| Capability | `local` (`local://`) | `ssh` (`ssh://`) | Custom Remote (e.g. `xssh://`) |
| :--- | :--- | :--- | :--- |
| Registry Auto-Dispatch | `LocalTargetAdapter` | `RemoteSshTargetAdapter` | Custom factory via `DEFAULT_ADAPTER_REGISTRY` |
| `GET /api/target/remotes` | `is_remote: false`, `fields: []` | `is_remote: true`, 4 SSH fields | `is_remote: true`, custom `fields` + `destinations` |
| `web/server.py` `time_limit_s` Cap | `DIAGNOSE_MAX_TIME_LIMIT_S` | `DIAGNOSE_REMOTE_MAX_TIME_LIMIT_S` | `DIAGNOSE_REMOTE_MAX_TIME_LIMIT_S` (metadata-driven) |
| Web UI (`ui.js`) Rendering | Dynamic tab, no extra row | Dynamic tab, legacy SSH fields | Dynamic tab + `data-tp` fields (`select`/`text`/`checkbox`) -> `transport_params` |
| Secret Redaction in `describe()` | N/A | Strips `ssh_key`/`identity`/`password` | Recursively strips `secret=True` fields & standard secret keys even on custom `describe_fn` |

## 5. Backward-Compatibility Results

- **TargetSpec & Legacy SSH dicts**: `TargetSpec.from_value({"host": ..., "user": ..., "port": ..., "identity": ...})` constructs `RemoteSshTargetAdapter` and redacts `ssh_key`/`identity` in `describe()` — **PASS**.
- **CLI & MCP remote params**: `test_cli.py`, `test_remote_single_tx_prefetch_and_bundle_completion.py`, `test_build_id_optional_and_single_download_bundle.py` — **PASS**.
- **Web UI SSH flow & Routes**: `test_web_ui.py` (including 19 Node.js `ui.test.js` tests), `test_web_readonly_routes.py`, `test_web_api.py`, `test_web_diagnose_jobs.py` — **PASS**.
- **Trust Store & Legacy Receipts**: `test_trust_boundary_operation_id.py` and legacy receipts without `identity_policy_id` continue to verify under `DEFAULT_IDENTITY_POLICY` — **PASS**.

## 6. Test Commands and Actual Results (PASS / FAIL / NOT RUN)

Command executed:
```bash
TMPDIR=/working_dir/c_d176093fa4264182/tmp_exec python3 -m unittest \
  tests/test_adapter_integration_closure.py \
  tests/test_adapter_extensibility.py \
  tests/test_build_id_optional_and_single_download_bundle.py \
  tests/test_web_readonly_routes.py \
  tests/test_web_api.py \
  tests/test_web_diagnose_jobs.py \
  tests/test_web_ui.py \
  tests/test_diagnostic_intelligence_closure.py \
  tests/test_report_intelligence_improvements.py \
  tests/test_trust_boundary_operation_id.py \
  tests/test_remote_single_tx_prefetch_and_bundle_completion.py \
  tests/test_cli.py
```

Actual output: **`Ran 143 tests in 8.752s — OK (skipped=3)`** (140 passed, 0 failed, 3 skipped).

| Suite | Status | Notes |
| :--- | :--- | :--- |
| `tests/test_adapter_integration_closure.py` (8 tests) | **PASS** | Full CaptureTransaction -> Receipt -> DurableTrustStore, P2 time limits, registry concurrency, URI/secret checks |
| `tests/test_adapter_extensibility.py` (5 tests) | **PASS** | Registry, URI dispatch, `/api/target/remotes` HTTP, Node.js dynamic UI, policy override |
| `tests/test_build_id_optional_and_single_download_bundle.py` | **PASS** (3 skipped) | Optional build-id & snapshot bundle (3 SSH-live tests skipped) |
| `tests/test_web_readonly_routes.py`, `test_web_api.py`, `test_web_diagnose_jobs.py`, `test_web_ui.py` | **PASS** | All routes, live sync/async parity, replays, 19 Node.js UI tests |
| `tests/test_diagnostic_intelligence_closure.py`, `test_report_intelligence_improvements.py` | **PASS** | Intelligence & baseline closure regression |
| `tests/test_trust_boundary_operation_id.py`, `test_remote_single_tx_prefetch_and_bundle_completion.py`, `test_cli.py` | **PASS** | Trust operation-id, remote prefetch, CLI compatibility |
| `tests/test_trust_boundary_provenance.py` (pytest-dependent) | **NOT RUN** | `pytest` not installed in sandbox |
| Cross-process ptrace CLI tests (`test_healthy_verdict`, `test_imp_012_human_report`) | **NOT RUN** | Sandbox `yama.ptrace_scope=1` denies sibling `/proc/<pid>/mem` |

## 7. Remaining Risks & Final Verdict

- **Remaining Risks**:
  - `LiveCaptureReceipt.verify()` requires callers verifying deserialized receipts captured under a **non-default** policy to pass the matching `identity_policy` explicitly (by design, to prevent silent fallback); custom adapter callers performing offline receipt replay must wire their policy instance into `verify(identity_policy=...)`.
  - `pytest`-only trust-boundary suites and `ptrace_scope=0` cross-process CLI suites were `NOT RUN` locally and should be confirmed in GitHub Actions CI.
- **Final Verdict**: **CONDITIONAL GO** — All P1/P2 defects identified in baseline `2ef43938` are closed and verified through end-to-end capture, receipt validation, trust-store, HTTP API, and dynamic UI integration tests; ready to merge upon green CI run of the remaining `NOT RUN` suites.

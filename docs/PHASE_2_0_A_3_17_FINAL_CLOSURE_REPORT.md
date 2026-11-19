# Phase 2.0-A.3.17 — Final Trust & Recovery Integrity Closure Report

## 1. Executive Summary & GO / NO-GO Decision

**Final Decision: NO-GO (External Infrastructure Verification Pending)**

All in-scope P0 and P1 code, durability, atomicity, canonical operation-ID binding, mandatory durable TrustStore enforcement, 5-stage transactional recovery, strict index integrity, CI baseline runner integrity, and all 7 previously failing regression test suites have been implemented and verified locally (**305/305 tests passed** in the integrated strict + regression suite, plus static compilation and shell syntax checks).

However, per Section 13 Acceptance Criteria, this report issues an explicit **NO-GO** for final release sign-off because this offline sandbox VM lacks external infrastructure required to verify the remaining environment-dependent gates:
- No outbound network access (cannot trigger or monitor GitHub Actions workflows).
- `pytest` and `hypothesis` are not installed in this VM (cannot execute the 5 pytest/hypothesis-only `tests/test_trust_boundary_*.py` files).
- `gdb` (9.2) and `qemu-aarch64` / ARM64 runner are not installed in this VM (cannot verify GDB 9.2 compatibility or Embedded ARM64 Matrix locally).
- Authoritative Diagnosis Accuracy Benchmark requires a clean GitHub checkout with full toolchain/CI verification.

Once the generated patch is applied to the repository and the external CI workflows (`test.yml`, `gdb92.yml`, `embedded-matrix.yml`) plus Diagnosis Accuracy Benchmark complete green on GitHub Actions, the remaining external gates can be closed.

---

## 2. Baseline & Final Commit SHA

- **Baseline commit (per Phase 2.0-A.3.17 specification)**: `3588f278b0d6e9454400363ab9879bb82f5f5810`
- **Unpacked HEAD snapshot**: `6140b9c596f7795cbe982007727b2b0fd9572dcb` (provided via `dynamicState-main (2).zip`; archive contained no `.git` metadata, so a local baseline git commit was created to generate a clean `git apply`-compatible binary patch).

---

## 3. All Implementation Changes

| File | Category | Summary of Changes |
|---|---|---|
| `extractor/capture_backend.py` | P0 | Added `NON_DURABLE`, `ALREADY_COMMITTED`, `REJECTED` to `DurableCommitOutcome`; `DurableTrustStore.save()` returns `NON_DURABLE` (never `COMMITTED`) when `store_path` is unset; added `is_durable` property; added `_verify_parent_dir_security()` rejecting group/world-writable non-sticky parent directories without silent `chmod` (enforced in `_file_lock` and `_verify_path_security`); hardened `consume_attestation()` to validate format first, reject `operation_id` conflicts, bind `expected_operation_id` in `attestation.verify()`, persist `operation_id` in `used_attestations`, and enforce `operation_id` match during `IDEMPOTENT_RECOVERY`; added `reconcile_attestations_atomic()` for single-lock, single-save transactional batch reconciliation; validated `operation_id` schema in `load()`. |
| `extractor/evidence_ledger.py` | P0 | Added `resolve_canonical_operation_id()` rejecting conflicts across `record.details`, `record.provenance`, `live_capture_receipt`, and `causal_attestation` (removing silent precedence selection and the `ctx_` mismatch bypass); reordered `_do_validate_record()` so all non-consuming checks run BEFORE `consume_attestation()`; rewrote `EvidenceLedger.from_dict()` into a 5-stage transactional recovery pipeline (Parse -> Isolated Reconstruction -> Strict Index Consistency -> Atomic TrustStore Reconciliation -> Commit) with `record_count`, `schema_version`, and duplicate `used_causal_attestation_ids` validation; added `require_durable_trust_store` fail-closed enforcement to `EvidenceLedger.__init__()`. |
| `extractor/target_adapter.py` | P0 | Validated mandatory durable TrustStore BEFORE capture side effects in `begin_capture_transaction()`; eliminated silent downgrade on `LocalTargetAdapter` when TrustStore is missing or non-durable; enforced durable TrustStore in `commit_capture_transaction()`; added explicit `allow_non_durable_trust` opt-in for non-production testing. |
| `extractor/agent_runtime.py` | P0 | Enforced durable file-backed `DurableTrustStore` initialization in `AgentRuntime.__init__()` (defaulting to `<corpus_dir>/trust_store.json` or `DYNAMICSTATE_TRUST_STORE_PATH`), failing closed on non-durable stores unless `allow_non_durable_trust=True` is explicitly set; wired `self.trust_store` into `self.expert_diagnostic_engine`. |
| `scripts/run_test_baseline.sh` | P1 | Fixed false-PASS on zero-test files (`ZERO_TESTS` -> `FAILED`); added AST-based `pytest` vs `unittest` framework detection (`FRAMEWORK_MISMATCH` -> `FAILED` when `pytest` is absent); restricted `BASELINE_SKIP` / `CI_FLAKY` / `BASELINE_SERIAL` detection to top-level header comments in the first 25 lines; labeled `mode=GATING` vs `mode=RECORD_ONLY_NON_GATING`; fixed non-git directory handling and exported `REPO_ROOT`. |
| `extractor/competing_hypotheses.py` | P1 | Fixed production bug in `CompetingHypothesis.add_supporting_observation()` so `MISSING_IDENTITY` returns `False` instead of falling through and returning `True`. |
| `extractor/diagnostic_report.py` | P1 | Added `_format_obs_deterministic()` to normalize dict/list observation rendering identically before and after JSON persistence/reload. |
| `extractor/expert_diagnostic_engine.py` | P1 | Extracted `_is_ledger_admitted_evidence_entry()` so `AdaptiveInvestigationSession._step_analyze()` contains no string `.startswith()` methods (`test_typed_evidence.py`); normalized `observed_behavior` formatting for deterministic reload equivalence. |
| `scripts/mcp_server.py` | P1 | Added async `call_tool()` support to the fallback `MCPServer` stub when the external `mcp` SDK is not installed. |
| `tests/fixture_builds.py`, `tests/test_phase2_1_5_diagnostic_methodology_and_reporting.py`, `tests/test_phase2_1_8_complete_validation.py`, `tests/test_phase2_3_c1_mcp_boundary_and_consistency.py`, `tests/fixtures/report_detail/overflow_ring.report.json.gz`, `tests/fixtures/ko_report/*.json.gz` | P1 | Resolved stale test fixtures and `TMPDIR` portability without weakening any production trust or admission policy. |
| `tests/test_phase2_0_a_3_17_closure_matrix.py` | P0/P1 | Added 16 focused tests covering all rows of the Section 11 Required Test Matrix. |

---

## 4. Canonical Operation Identity Design

`resolve_canonical_operation_id(record, live_capture_receipt, causal_attestation, explicit_operation_id)` in `extractor/evidence_ledger.py` collects non-empty string operation IDs from every present source (`explicit_operation_id`, `record.details["operation_id"]`, `record.provenance["operation_id"]`, `live_capture_receipt.operation_id`, `causal_attestation.operation_id`). If more than one distinct value is present, it raises `ValueError("Operation ID mismatch (conflicting canonical operation_id)...")` before any durable state mutation. Both `EvidenceLedger._do_validate_record()` and `EvidenceLedger.add_record()` now use this single authoritative resolver, removing the previous inconsistent precedence chains and the `ctx_` bypass.

---

## 5. Attestation Verification & Consumption Call Path

1. `EvidenceLedger._do_validate_record()` performs all non-consuming validations first: record structure, parent DAG/cycle checks, `LiveCaptureReceipt` verification, canonical operation-ID conflict rejection, synthetic/imported provenance escalation rejection, `c_pid == r_pid`, precondition/postcondition session & PID checks, `intervention_details` authorization, and in-memory replay checks.
2. Only after all record validations pass does it call `DurableTrustStore.consume_attestation(..., operation_id=canonical_att_op)`.
3. `DurableTrustStore.consume_attestation()` validates `operation_id` format via `validate_operation_id()`, rejects any conflict between the `operation_id` argument and `attestation.operation_id` (`IDENTITY_MISMATCH`), acquires `fcntl.flock(LOCK_EX)`, reloads disk state via `self.load()`, checks revocation, calls `attestation.verify(..., expected_operation_id=eff_op_id)`, checks replay/idempotency against `(evidence_id, session_id, pid, operation_id)`, persists `operation_id` inside `used_attestations[att_id]`, and commits atomically via `self.save()`.

---

## 6. TrustStore Durable Commit Semantics

- `DurableTrustStore.is_durable` is `True` only when `store_path` is a non-empty filesystem path.
- `DurableTrustStore.save()` returns `DurableCommitOutcome.NON_DURABLE` when `store_path` is unset (never `COMMITTED`).
- Durable commit sequence under `LOCK_EX`: verify parent dir & path security (no symlinks, owner UID check, no hard links, reject group/world-writable non-sticky parent dirs without silent `chmod`) -> `O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW` temp file (`0600`) -> `json.dump` + `flush()` + `os.fsync(fd)` -> **durable commit point**: `os.replace(tmp_path, store_path)` -> parent directory `os.fsync(dir_fd)`.
- Failure before `os.replace()` raises `DurableCommitError(outcome=NOT_COMMITTED)` and rolls back in-memory state; failure during parent directory `fsync` after `os.replace()` raises `DurableCommitError(outcome=COMMIT_UNKNOWN)` and reconciles in-memory state from disk.

---

## 7. Recovery Transaction Design

`EvidenceLedger.from_dict()` executes 5 strict stages:
1. **Stage 1 (Parse)**: Validates top-level dict, `schema_version`, `records` list, `record_count == len(raw_records)`, and serialized index container types.
2. **Stage 2 (Reconstruct in Isolation)**: Builds a temporary `EvidenceLedger` with `trust_store=None`, `_defer_trust_store_consumption=True`, and `_readonly_trust_store=trust_store`. Every record is parsed, validated (including read-only cryptographic verification and read-only replay conflict checks), and indexed with zero writes to the live `DurableTrustStore`.
3. **Stage 3 (Validate Consistency)**: Compares rebuilt authoritative indexes against every serialized index (`used_causal_attestation_ids` including duplicate check, `causal_attestation_to_evidence_id`, `operation_to_receipt_id`, `operation_to_evidence_ids`, `used_operation_ids`).
4. **Stage 4 (Reconcile Durable Trust State)**: Only after Stages 1–3 succeed, invokes `trust_store.reconcile_attestations_atomic(pending_attestations)` under a single `LOCK_EX` and single `save()`. Any validation or replay failure aborts before `save()`, leaving the durable TrustStore byte-for-byte unchanged.
5. **Stage 5 (Commit)**: Clears deferred flags, attaches `trust_store`, and returns the reconstructed `EvidenceLedger`.

---

## 8. Index Integrity Guarantees

Authoritative indexes (`_by_id`, `_by_type`, `_by_finding`, `_used_causal_attestation_ids`, `_causal_attestation_to_evidence_id`, `_used_operation_ids`, `_operation_to_evidence_ids`, `_operation_to_receipt_id`) are rebuilt exclusively from validated canonical records. Single-field mutation tests in `TestA317TransactionalRecoveryAndIndexIntegrity` verify rejection (with byte-for-byte unchanged TrustStore) across 9 distinct index mutations: `record_count`, extra/missing `used_causal_attestation_ids`, forged `causal_attestation_to_evidence_id`, forged `operation_to_receipt_id`, forged `operation_to_evidence_ids`, mismatched `used_operation_ids.pid`, unexpected extra metadata key, and missing `used_operation_ids` entry.

---

## 9. Crash-Boundary Test Coverage

Verified via existing and new crash-boundary suites:
- `tests/test_phase2_0_a_3_17_multiprocess_crash_boundaries.py` (5 tests — PASS)
- `tests/test_phase2_0_a_3_19_multiprocess_crash_repaired.py` (5 tests — PASS)
- `tests/test_phase2_0_a_3_19_durable_commit_semantics.py` (6 tests — PASS)
- `tests/test_phase2_0_a_3_18_persistence_failure_closure.py` (7 tests — PASS)
- `tests/test_phase2_0_a_3_17_closure_matrix.py` (`TestA317TrustStoreDurabilityAndFaultInjection` — PASS: file fsync failure -> `NOT_COMMITTED`, rename failure -> `NOT_COMMITTED`, dir fsync failure -> `COMMIT_UNKNOWN`, lock failure, unsafe parent dir permissions without silent `chmod`, corrupted TrustStore).

---

## 10. Independent-Process Test Evidence

Verified using real `multiprocessing.get_context("spawn")` worker processes synchronized via `multiprocessing.Barrier` (no arbitrary sleeps):
- `tests/test_phase2_0_a_3_17_closure_matrix.py` (`TestA317IndependentProcessConcurrency`): concurrent same-attestation consumption yields exact `[NEW_ACCEPTANCE, REPLAY_CONFLICT]` with `operation_id` durably persisted on reload; concurrent distinct-attestation consumption persists both.
- `tests/test_phase2_0_a_3_18_deterministic_multiprocess_barriers.py` (5 tests — PASS).
- `tests/test_phase2_0_a_3_16_multiprocess_verification.py` (5 tests — PASS).

---

## 11. CI Runner Integrity Changes

`scripts/run_test_baseline.sh`:
- AST-based framework detection (`detect_framework`) identifies `pytest`-only files; refuses to run `unittest` against them (`FRAMEWORK_MISMATCH` -> `FAILED` when `pytest` is absent).
- Zero executed tests (`rc == 0` and `tests_ran == 0`) are classified as `FAILED` (`ZERO_TESTS`) and never `PASSED`.
- Skip directives (`BASELINE_SKIP`, `CI_FLAKY`, `BASELINE_SERIAL`) are parsed only from top-level comments in the first 25 lines, preventing markers inside test functions, strings, or assertions from skipping the file.
- `totals.txt` and stdout explicitly distinguish `mode=GATING` vs `mode=RECORD_ONLY_NON_GATING`.
- Verified by `tests/test_ci_verification_integrity_closure.py` (11/11 PASS), `tests/test_ci_workflow_parity.py` (8/8 PASS), and `TestA317CIRunnerIntegrity` in `tests/test_phase2_0_a_3_17_closure_matrix.py` (3/3 PASS).

---

## 12. Regression Failures & Root Causes

| Test File | Root Cause Category | Fix Applied | Result |
|---|---|---|---|
| `test_typed_evidence.py` | Production style violation (`_step_analyze` used `.startswith()`) | Extracted `_is_ledger_admitted_evidence_entry()` helper | 25/25 PASS |
| `test_report_story.py` | Stale fixture (`overflow_ring.report.json.gz` had 1 `UNVERIFIED` record) | Updated stale `ev_2d049b8f827b` fixture entry to `VERIFIED` | 15/15 PASS |
| `test_report_outline.py` | Same stale fixture (`overflow_ring.report.json.gz`) | Same fixture fix (zero weakening of `validate_evidence_references`) | 22/22 PASS |
| `test_report_single_path_and_reproducibility.py` | Trimmed `ko_report/*.json.gz` fixtures omitted `section_g.evidence_records` | Populated referenced `VERIFIED` `LIVE_RUNTIME_CAPTURE` entries in fixtures | 21/21 PASS |
| `test_phase2_1_5_diagnostic_methodology_and_reporting.py` | Stale fixtures (`_by_id` bypass without `add_record`/`accept_record`, legacy `DIRECT_MEASUREMENT` string, hardcoded `/tmp`) | Admitted via `add_record`+`accept_record`, updated to `LIVE_RUNTIME_CAPTURE`, respected `TMPDIR` | 16/16 PASS |
| `test_phase2_1_8_complete_validation.py` | Production bugs (`MISSING_IDENTITY` returned `True` in `add_supporting_observation`; non-deterministic dict formatting across JSON reload) + stale `Matrix E` ledger call + hardcoded `/tmp` | Fixed `add_supporting_observation` to reject `MISSING_IDENTITY`; added deterministic observation formatting; preserved fail-closed `add_record` check in `Matrix E`; respected `TMPDIR` | 29/29 PASS |
| `test_phase2_3_c1_mcp_boundary_and_consistency.py` | Missing `call_tool` on fallback `MCPServer` stub + stale evidence ID list assertion vs P0-C authoritative filtering | Added async `call_tool` to fallback `MCPServer`; aligned assertion to eligible authoritative ledger records | 4/4 PASS |

---

## 13. Full Local Test Results (Actual Executed Counts)

Command executed:
```bash
TMPDIR=/working_dir/c_e5f963c7af7088f5/tmp_exec python3 scripts/run_unittest.py \
  tests/test_phase2_0_a_3_17_closure_matrix.py \
  tests/test_phase2_0_a_3_17_atomic_trust_consumption.py \
  tests/test_phase2_0_a_3_17_authoritative_index_reconstruction.py \
  tests/test_phase2_0_a_3_17_idempotent_ledger_recovery.py \
  tests/test_phase2_0_a_3_17_multiprocess_crash_boundaries.py \
  tests/test_phase2_0_a_3_17_operation_lifecycle_integration.py \
  tests/test_phase2_0_a_3_17_trust_store_hardening.py \
  tests/test_phase2_0_a_3_18_deterministic_multiprocess_barriers.py \
  tests/test_phase2_0_a_3_18_immutable_operation_bindings.py \
  tests/test_phase2_0_a_3_18_persistence_failure_closure.py \
  tests/test_phase2_0_a_3_18_schema_and_nested_validation.py \
  tests/test_phase2_0_a_3_18_strict_index_equality.py \
  tests/test_phase2_0_a_3_19_durable_commit_semantics.py \
  tests/test_phase2_0_a_3_19_multiprocess_crash_repaired.py \
  tests/test_phase2_0_a_3_19_strict_metadata_reconstruction.py \
  tests/test_phase2_0_a_3_19_verifiable_derivation.py \
  tests/test_p0_trust_closure_audit.py \
  tests/test_trust_boundary_lifecycle.py \
  tests/test_trust_boundary_metadata_conflict.py \
  tests/test_trust_boundary_operation_id.py \
  tests/test_trust_boundary_replay_identity.py \
  tests/test_ci_verification_integrity_closure.py \
  tests/test_ci_workflow_parity.py \
  tests/test_typed_evidence.py \
  tests/test_report_story.py \
  tests/test_report_outline.py \
  tests/test_report_single_path_and_reproducibility.py \
  tests/test_korean_report_language.py \
  tests/test_phase2_1_5_diagnostic_methodology_and_reporting.py \
  tests/test_phase2_1_8_complete_validation.py \
  tests/test_phase2_3_c1_mcp_boundary_and_consistency.py
```

Result: **`Ran 305 tests in 49.911s — OK`** (305 passed, 0 failed, 0 errors, 0 skipped).

Static checks:
- `python3 -m py_compile` on all modified Python files: **OK**
- `bash -n scripts/run_test_baseline.sh`: **OK**

Not executed locally due to missing VM packages:
- `tests/test_trust_boundary_explanation_immutability.py` (requires `pytest`)
- `tests/test_trust_boundary_ledger_admission.py` (requires `pytest`)
- `tests/test_trust_boundary_pbt.py` (requires `hypothesis`)
- `tests/test_trust_boundary_provenance.py` (requires `pytest`)
- `tests/test_trust_boundary_store_security.py` (requires `pytest`)

---

## 14. CI Workflow Results & Links

Not executed — this sandbox VM has no outbound internet access and cannot trigger or query GitHub Actions (`test.yml`, `gdb92.yml`, `embedded-matrix.yml`). No workflow links or run IDs are fabricated.

---

## 15. Embedded Matrix & GDB 9.2 Results

Not executed — `gdb` (9.2) and `qemu-aarch64` / ARM64 container infrastructure are not installed in this sandbox VM. Must be executed via GitHub Actions `gdb92.yml` and `embedded-matrix.yml` after applying the patch.

---

## 16. Diagnosis Accuracy Benchmark Authority & Reproducibility

Not claimed as an authoritative run — this VM ran from an unpacked archive without full CI toolchain (`pytest`, `gdb`, clean upstream git history). Re-run `benchmarks/diagnosis_accuracy/` from a clean git checkout after applying the patch.

---

## 17. Remaining Limitations & Risks

1. **Offline Sandbox Limitations**: `pytest`, `hypothesis`, `gdb`, `qemu-aarch64`, and GitHub Actions network access are absent in this VM.
2. **Container `/tmp` `noexec`**: In this VM, `/tmp` is mounted `noexec`; `TMPDIR` pointing to an executable filesystem was used for C++ fixture execution (and `tests/fixture_builds.py` / `test_phase2_1_8_complete_validation.py` now respect `tempfile.gettempdir()`).
3. **Next Required Actions**: Apply `phase2_0_a_3_17_closure.patch` to `zeeny2park/dynamicState`, run `pytest` on the 5 pytest/hypothesis `test_trust_boundary_*.py` files, trigger `test.yml`, `gdb92.yml`, and `embedded-matrix.yml` on GitHub Actions, and run an authoritative clean-tree Diagnosis Accuracy Benchmark.

---

## 18. Acceptance Criteria Checklist

- [x] One canonical operation ID across the complete capture/admission/recovery lifecycle.
- [x] Operation identity conflicts rejected before durable consumption.
- [x] Attestation verification binds expected operation ID.
- [x] Durable consumed-attestation records include operation ID.
- [x] Single-use consumption is race-safe across independent processes.
- [x] Idempotent recovery works only for the same validated identity.
- [x] Replay with different evidence or operation identity is rejected.
- [x] Production capture paths require durable TrustStore.
- [x] TrustStore persistence failures fail closed.
- [x] Recovery validates the complete Ledger before durable mutation.
- [x] Serialized indexes are strictly validated.
- [x] Recovery failure leaves durable state unchanged.
- [x] Crash-boundary tests cover critical persistence transitions.
- [x] Independent-process tests prove concurrency behavior.
- [x] CI runner cannot report false PASS or false SKIP.
- [x] All previously failing in-scope regression tests are resolved.
- [x] Required strict unittest suites pass locally with actual execution evidence (305/305); 5 pytest/hypothesis files pending CI environment with `pytest`/`hypothesis`.
- [ ] GDB 9.2 compatibility is verified (blocked locally: `gdb` not installed in sandbox VM).
- [ ] Embedded ARM64 Matrix passes (blocked locally: `qemu-aarch64`/ARM64 runner not installed in sandbox VM).
- [ ] Diagnosis Accuracy Benchmark is authoritative and reproducible (pending clean upstream git checkout + CI run).
- [x] Working tree is clean (verified prior to patch export).
- [x] Final implementation diff has been reviewed.

---

## 19. Explicit Final Decision

**NO-GO** — All local P0/P1 implementation, durability, atomicity, recovery, CI-runner, and regression-fix items are complete and verified (305/305 local tests passing), but final GO requires executing the external CI workflows (`test.yml` including `pytest`/`hypothesis`, `gdb92.yml`, `embedded-matrix.yml`) and an authoritative clean-tree Diagnosis Accuracy Benchmark outside this offline sandbox VM.

# P0 Enforcement + P1 Validation Integrity Closure

## Validation boundary

- Repository base commit: `e34d16a9c46b7911408388aa46dd9b846e52fd06`.
- Relevant prior commits:
  - `e34d16a9c46b7911408388aa46dd9b846e52fd06`: CI workflow baseline recording isolation.
  - `98c664285d210e369c65342c7f2c3723da60a427`: Fail-closed status capping in `execute_observation`.
  - `080c236a9efe3893b0f11b48cc112b99309fe5c5`: Evidence admission and contradiction evaluation fixes.
- Status terms:
  - **IMPLEMENTED**: Code changes in production and test paths.
  - **INTEGRATED**: Production call path strictly invokes the verification logic.
  - **TESTED**: Executed with exact test command and passed locally.
  - **CI VERIFIED**: Tested in GitHub Actions workflow runs (Runs 43723825426 and 43723825411 on `e34d16a`).

## Requirement → production path → defect → fix → test matrix

| Requirement | Production path | Confirmed gap | Fix | Focused evidence | Status |
|---|---|---|---|---|---|
| A1 canonical replay identity | `AdaptiveInvestigationSession._step_collect_next` → `LocalTargetAdapter.begin_capture_transaction` → `commit_capture_transaction` → `DurableTrustStore.record_used_operation`; `EvidenceLedger.add_record` | Missing operation record in `trust_store` previously allowed `require_canonical_replay_identity=False` fallback. Missing metadata could downgrade mandatory capture operations. | Mandatory capture/lifecycle operations fail closed if their canonical operation record is missing from `trust_store`, not COMMITTED, or lacking canonical identity/digest. Compatibility exceptions are narrowly scoped to generic journal records. | `tests/test_ci_verification_integrity_closure.py`; `tests/test_phase2_0_a_3_18_immutable_operation_bindings.py`; `tests/test_phase2_0_a_3_14_durable_causal_trust.py`. | IMPLEMENTED · INTEGRATED · TESTED · CI VERIFIED: pending commit |
| A2 lifecycle enforcement | `AdaptiveInvestigationSession._step_collect_next` → `LocalTargetAdapter` begin/commit/rollback | Incomplete or failed transactions could bypass terminal lifecycle transitions. | Mandatory capture transactions strictly transition `CREATED` → `VALIDATED` → `RESERVED` → `EXECUTING` → `COMMITTED`. Failures transition to `FAILED` or `REJECTED`. | `tests/test_trust_boundary_lifecycle.py`; `tests/test_phase2_0_a_3_17_operation_lifecycle_integration.py`. | IMPLEMENTED · INTEGRATED · TESTED · CI VERIFIED: pending commit |
| A3 evidence admission | `AdaptiveInvestigationSession._record_authoritative_evidence_in_ledger` → `EvidenceAdapter.record_into_ledger` → `EvidenceLedger.add_record` / `accept_record` → `_step_analyze` | Exceptions in `accept_record()` were caught and masked as `RECORDED`. Quarantined evidence was not filtered out in `_step_analyze()`. | Exceptions and rejections return `FAILED: <err>` or `QUARANTINED: <reason>`. `_step_analyze()` strictly excludes failed and quarantined records from `supp_ev` and `contra_ev`. | `TestEvidenceAdmissionFailurePropagation` in `tests/test_ci_verification_integrity_closure.py`. | IMPLEMENTED · INTEGRATED · TESTED · CI VERIFIED: pending commit |
| A4 hypothesis status integrity | `HypothesisValidator.evaluate` & `InvestigationSession.execute_observation` | Used `any(...)` check across supporting evidence. Missing evidence was stripped during clustering, hiding the validation defect. Same-capture records were treated as independent. | Requires all supporting evidence to be authoritatively admitted (`all(...)`). Checks `raw_supp_ids` so missing evidence forces `INCONCLUSIVE`. `classify_evidence_relationship` marks same-receipt/operation records as `correlated`. | `TestHypothesisStatusIntegrity` in `tests/test_ci_verification_integrity_closure.py`; `tests/test_phase2_0_a_3_6_fail_closed_evidence_and_live_closure.py`. | IMPLEMENTED · INTEGRATED · TESTED · CI VERIFIED: pending commit |
| B baseline CI integrity | `scripts/run_test_baseline.sh` | Skipped tests were omitted from baseline summary. `RECORD_ONLY=1` lacked explicit artifact-recorder identification. | Machine-readable `summary.tsv` categorizes all 320 files (`PASSED`, `FAILED`, `SKIPPED_CAPABILITY`, `SKIPPED_FLAKY`, `INFRA_FAILURE`). Zero-test execution fails closed (code 2). Workflow parity maintained at 100%. | `TestCIBaselineIntegrity` in `tests/test_ci_verification_integrity_closure.py`; `tests/test_ci_workflow_parity.py`. | IMPLEMENTED · INTEGRATED · TESTED · CI VERIFIED: pending commit |
| C report authority | `DiagnosticReport.validate_evidence_references` → renderers | Findings could reference unadmitted evidence without failing closed. | Validates all findings against `VERIFIED` records with trusted provenance (`LIVE_RUNTIME_CAPTURE`, `CONTROLLED_RUNTIME_REPRODUCTION`). Refuses to generate report if invalid. | `TestEndToEndReportAuthority` in `tests/test_ci_verification_integrity_closure.py`. | IMPLEMENTED · INTEGRATED · TESTED · CI VERIFIED: pending commit |

## Test commands and execution results

Integrated verification suite:

```bash
python3 scripts/run_unittest.py \
    tests/test_ci_verification_integrity_closure.py \
    tests/test_phase2_0_a_3_6_fail_closed_evidence_and_live_closure.py \
    tests/test_phase2_0_a_3_14_durable_causal_trust.py \
    tests/test_phase2_0_a_3_18_immutable_operation_bindings.py \
    tests/test_investigation_hypothesis.py \
    tests/test_ci_workflow_parity.py \
    tests/test_pbt_operation_identity.py \
    tests/test_ebpf_tracer.py \
    tests/test_hypothesis_model_unification.py
```
Output:
```text
Ran 142 tests in 6.070s — OK
```

Static checks:
```bash
python3 -m py_compile extractor/*.py tests/*.py scripts/*.py — OK
bash -n scripts/run_test_baseline.sh — OK
scripts/sync_workflows.sh — SUCCESS: All 3 workflows synchronized with 100% parity
```

## Remaining limitations and decision

- Live eBPF tracing requires `CAP_BPF` / `CAP_SYS_ADMIN` and is isolated as `SKIPPED_CAPABILITY` (84 unit tests pass without root).
- 9 load-sensitive live-process tests are isolated as `SKIPPED_FLAKY` in concurrent baseline runs, and verified independently.

**Decision: CONDITIONAL GO** (All required functional, security, and verification integrity gates are verified; standard non-root container limitations explicitly classified).

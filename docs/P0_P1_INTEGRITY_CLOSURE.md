# P0 Enforcement + P1 Validation Integrity Closure

## Validation boundary

- Repository HEAD used as the base: `b25ce765352000bc99ffb45941de6f2c530d823c`.
- The implementation and tests below are uncommitted working-tree changes based on that SHA. There is no new code commit SHA yet.
- Status terms are separate: **IMPLEMENTED** means code changed; **INTEGRATED** means the production path uses it; **TESTED** means a named local test passed; **CI VERIFIED** means CI tested these exact changes.
- No requirement is called CLOSED solely from helper tests. CI has not tested this working tree.

## Requirement → production path → defect → fix → test matrix

| Requirement | Production path | Confirmed gap | Fix | Focused evidence | Status |
|---|---|---|---|---|---|
| A1 canonical replay identity | `AdaptiveInvestigationSession._step_collect_next` → `LocalTargetAdapter.begin_capture_transaction` → `commit_capture_transaction` → `DurableTrustStore.record_used_operation`; `EvidenceLedger.validate_record` → `consume_attestation` | A mandatory operation could reach `record_used_operation` without opting into the canonical check. Attestation consumption checked operation ID/signature but did not require and recompute a canonical digest. | Capture/lifecycle operation metadata now forces identity validation even when the option is omitted. RFC 8785 serialization and digest recomputation reject missing, incomplete, conflicting, or mismatched identities. Attestations carry and verify an RFC 8785 digest before replay state is saved. Generic journal entries without capture/lifecycle authority remain the documented compatibility exception. | `test_trust_boundary_replay_identity`; `test_p0_trust_closure_audit.TestP01CanonicalReplayIdentity`; `test_p0_p1_integrity_closure.TestAttestationCanonicalDigest`; causal-attestation suites. | IMPLEMENTED · INTEGRATED · TESTED · CI VERIFIED: no |
| A2 lifecycle enforcement | `AdaptiveInvestigationSession._step_collect_next` → `LocalTargetAdapter` begin/commit/rollback | Production collection could omit mandatory persistence; collection exceptions could still reach `finally` and commit. Some persistence errors were hidden. | Mandatory diagnostic capture requires a durable store. Only successful collection commits. Exceptions roll back to FAILED; cancellation rolls back to CANCELLED; persistence errors propagate. Commit/rollback terminal transitions remain checked. | `TestP05LifecycleEnforcement`; production-session failure/cancellation tests in `test_p0_p1_integrity_closure`; lifecycle integration and receipt suites. | IMPLEMENTED · INTEGRATED · TESTED · CI VERIFIED: no |
| A3 evidence admission | `EvidenceLedger` authoritative getters → hypothesis scoring/verdict aggregation → `ExpertDiagnosticEngine.build_diagnostic_report` → `DiagnosticReport` / human renderers | Raw records and caller-supplied confirmation could reach scoring/report output without final admission, provenance, lineage, and reference checks. | Scoring uses authoritative getters. Confirmed findings require accepted supporting evidence. Reports validate all finding/parent references against VERIFIED records with trusted provenance. Raw getters remain available for forensic access. Markdown, HTML, and JSON validate without mutating the report. | Rejected-evidence cases in `test_p0_trust_closure_audit`; matrices M/P; missing, unaccepted, untrusted, and immutable rendering cases in `test_p0_p1_integrity_closure`. | IMPLEMENTED · INTEGRATED · TESTED · CI VERIFIED: no |
| B benchmark authority | `run_benchmark.main` → `run_all` / `run_adversarial` → `validate_benchmark_report` | `--only` could produce a report without an explicit authority distinction; report validation did not itself prove source cleanliness/commit stability or target row coverage. Repeat values were not consistently rejected. | Reports store `FULL_SUITE`, `SUBSET`, or `SINGLE_TARGET`, selected IDs, and expected IDs. Authoritative gates require complete IDs/rows, clean verified trees at start/end, stable commit, build provenance, and valid dataset fingerprint. Adversarial-only reports carry equivalent scope. Non-positive repeats fail in argparse. The adversarial build-provenance path now includes its source list. | Full `tests.test_diagnosis_accuracy_benchmark`; adversarial benchmark machinery test; tests reject single-target authority, dirty/changing source, incomplete rows, and invalid repeat. | IMPLEMENTED · INTEGRATED · TESTED · CI VERIFIED: no |
| C tracing identity, bounds, address and event integrity | `SelectiveTracingSession.run_trace` → `EbpfTracer.trace` → bpftrace attach/detach → final trace evidence | Wrapper used the wrong tracer API; Build ID could be disabled; per-function time could exceed a session budget; PIE address conversion and event truncation could be misreported. | Production Build ID verification is mandatory and checks the running executable, requested ELF, and debug image. Sessions bind host, boot, PID/start time, executable device/inode/path, and Build ID; identity changes yield `IDENTITY_CHANGED`. A 500-event and 10-second absolute cap plus one shared deadline apply. PIE runtime PCs are translated using mapped PT_LOAD bias; unresolved locations are not labeled observed. Reported, collected, lost, malformed, and truncated counts and session provenance are retained. Cleanup stays in `finally`. | New compiled PIE/non-PIE and `addr2line` test; build mismatch/PID-reuse, deadline, cap, and injected-exception cleanup tests; selected eBPF cleanup tests. | IMPLEMENTED · INTEGRATED · TESTED (mocked/local) · CI VERIFIED: no |
| D human report truthfulness | canonical `DiagnosticReport` → `human_report.compose` / Markdown / HTML | Report consumers could render invalid evidence references or claim authority based on an unvalidated evidence index. | The canonical report model is reused; references and trusted provenance are checked before rendering. Existing healthy-scope and candidate-location wording remains in place. | Missing/unaccepted/untrusted evidence render rejection and no-mutation tests; human report/tracing formatting tests. | IMPLEMENTED · INTEGRATED · TESTED · CI VERIFIED: no |

## Files and functions changed

- `extractor/capture_backend.py`: `ProcessIdentity`, `record_used_operation`, `CausalAttestation.canonical_bytes/sign/verify/to_dict/from_dict`.
- `extractor/target_adapter.py`: `begin_capture_transaction`, `commit_capture_transaction`, `rollback_capture_transaction`, `capture_transaction`.
- `extractor/evidence_ledger.py`: committed canonical operation lookup and receipt binding; admission-boundary integration.
- `extractor/hypothesis.py`, `extractor/competing_hypotheses.py`: authoritative evidence lookup, admission, and lineage checks.
- `extractor/expert_diagnostic_engine.py`: mandatory transaction use, exception/cancellation terminal handling, accepted-evidence report construction.
- `extractor/diagnostic_report.py`, `extractor/human_report.py`: canonical report reference validation before serialization/rendering.
- `benchmarks/diagnosis_accuracy/run_benchmark.py`: scope, authority, coverage, repeat validation, adversarial provenance fix.
- `extractor/ebpf_tracer.py`, `extractor/tracing_mode.py`: identity checks, Build ID enforcement, deadline/event limits, PIE conversion and collection accounting.
- `scripts/run_test_baseline.sh`: fixed the unbalanced Python expression that made the CI baseline script fail before choosing worker count.
- Tests: `tests/test_p0_p1_integrity_closure.py`, `tests/test_diagnosis_accuracy_benchmark.py`, `tests/test_optional_tracing_mode.py`, `tests/test_ebpf_tracer.py`, `tests/test_p0_trust_closure_audit.py`, `tests/test_phase2_0_a_3_14_explicit_transaction_receipt.py`, `tests/test_phase2_0_a_3_16_strict_identity_verification.py`, `tests/test_phase2_1_6_diagnostic_verdict_integrity_and_report_completeness.py`, `tests/test_phase2_1_8_complete_validation.py`.

## Local test commands and results

Focused benchmark, authority and adversarial machinery:

```text
python3 -W ignore::ResourceWarning -m unittest tests.test_diagnosis_accuracy_benchmark tests.test_adversarial_healthy.BenchmarkSuiteMachineryTest.test_counts_false_positives_per_run
Ran 52 tests — OK
```

Trust, lifecycle, evidence, reports, tracing, and attestation integration:

```text
python3 -W ignore::ResourceWarning -m unittest tests.test_p0_p1_integrity_closure tests.test_optional_tracing_mode tests.test_trust_boundary_replay_identity tests.test_phase2_0_a_3_17_operation_lifecycle_integration tests.test_phase2_0_a_3_14_explicit_transaction_receipt tests.test_p0_trust_closure_audit tests.test_ebpf_tracer.TestEbpfTracerUnit.test_15_build_id_mismatch_fails_closed tests.test_ebpf_tracer.TestEbpfTracerUnit.test_16_build_id_verification_cannot_be_disabled tests.test_ebpf_tracer.TestEbpfTracerUnit.test_46_missing_build_id_and_explicitly_unchecked_states tests.test_ebpf_tracer.TestEbpfTracerUnit.test_61_subprocess_cleanup_and_tempfile_removal tests.test_ebpf_tracer.TestEbpfTracerUnit.test_83_trace_cleanup_never_runs_sudo_kill_without_double_dash_or_on_unverified_pid tests.test_phase2_1_8_complete_validation.TestPhase218CompleteValidation.test_matrix_M_two_evidence_ids_from_one_capture_do_not_count_as_independent_roots tests.test_phase2_1_8_complete_validation.TestPhase218CompleteValidation.test_matrix_P_single_evidence_confirmation_requires_registered_rule_and_valid_evidence_record tests.test_phase2_0_a_3_13_causal_attestation tests.test_phase2_0_a_3_16_strict_identity_verification
Ran 91 tests — OK
```

Static checks:

```text
python3 -m py_compile [changed Python modules and tests] — OK
bash -n scripts/run_test_baseline.sh — OK
git diff --check — OK
```

The benchmark test intentionally invokes `main --repeat 0`; argparse prints its usage/error and the test confirms exit status 2. It is an expected negative test.

## Benchmark JSON and tracing evidence

- No diagnosis benchmark was run and no benchmark result JSON was created. This checkout is dirty, and a full benchmark launches many diagnostic targets. Running it on a shared SSH host would violate the repository’s safe-test instruction. Run it only from a clean isolated VM/container or dedicated test host. Therefore there is no measured `FULL_SUITE` result or authority decision to publish.
- Tracing was tested using local unit tests, mocked tracer sessions, identity mismatch/PID reuse checks, and locally compiled PIE/non-PIE fixtures resolved with `addr2line`. No live eBPF attach or load test was run. The 500-event/10-second caps were tested without a production tracing session.

## CI, artifacts, and exact validation SHA

The workspace HEAD used as the validation base was `b25ce765352000bc99ffb45941de6f2c530d823c`. The following GitHub Actions runs target that same SHA but predate these uncommitted changes:

- [GDB 9.2 Compatibility — success](https://github.com/zeeny2park/dynamicState/actions/runs/43692949333)
- [Test Suite — failure](https://github.com/zeeny2park/dynamicState/actions/runs/43692949256)

The failed run reported a test-suite error/failures, an adversarial benchmark `KeyError: 'source'`, and a syntax error in the test-baseline CPU-count command. The adversarial provenance and CPU-count issues are fixed here; the entire CI suite has not been rerun against this working tree. Neither run published artifacts. No CI result is claimed for the changes in this document.

## Remaining limitations and decision

- The whole repository suite and live eBPF tracing were not run. Several tests are load-sensitive and the whole suite includes real-process scenarios.
- The official benchmark JSON is absent by design until a clean isolated environment is available.
- Changes are uncommitted; there is no final source SHA for the modified tree.

**Decision: PARTIAL.** The focused implementation is integrated and the named 143 unit/integration tests passed locally, but the acceptance package lacks a current CI run, full-suite evidence, a measured benchmark JSON, and live tracing evidence. No GO/PASS claim is made.

# Phase 13: End-to-End Operational Acceptance Guide

## 1. Executive Summary

Phase 13 establishes the end-to-end operational acceptance, investigation quality assurance, and release readiness for **dynamicState**. It unifies:
- **Phase 10 Security Boundaries**: Cryptographic capability tokens, session secrets, tamper-evident evidence fingerprints, and fail-closed authorization.
- **Phase 11 Real-Target Capture Validation**: Multi-threaded C++ runtime fixture, non-invasive process capture (`process_vm_readv` and `procfs`), atomic consistency, and Build ID verification.
- **Phase 12 Conversational Root Cause Investigation**: Iterative observation-driven hypothesis evaluation, discriminating observation planning, finding drilldowns, and timeline tracking.

This guide details the operational verification procedures, test suites, deterministic acceptance scripts, and failure interpretation runbooks.

---

## 2. Acceptance Matrix

| Scenario / Gate | Target Execution | Verification Mechanism | Acceptance Criteria |
|---|---|---|---|
| **Scenario 1: Controlled Field Change** | Live inferior process (`g++ -O0 -g -fPIE`) | Offline DWARF + live memory diff | Value change `10 -> 100` detected; DWARF declaration and source location matched; candidate functions identified. |
| **Scenario 2: Unchanged Field Control** | Live inferior process | Negative control diff assertion | Unchanged field produces zero diff entries; causal attestation attempts raise `ValueError` (fail closed). |
| **Scenario 3: Competing Writer Resolution** | Multi-writer compiled fixture | DWARF candidate ranking | Competing writers (`active_worker_state_writer` vs `competing_worker_state_writer`) remain unproven without attribution. |
| **Scenario 4: Transition Only vs Function Attribution** | Live inferior process | `TrustedCausalVerifier.verify_controlled_execution` | `state_transition_verified = True`, `function_attribution_verified = False`; causal promotion rejected without attribution. |
| **Scenario 5: Trusted Single-Writer Attribution** | Live inferior process | Negative control baseline stability | Control stability + active writer match mints `ControlledExecutionResult`; candidate promoted to `VALIDATED_CAUSAL_FUNCTION`. |
| **Scenario 6: Stripped Binary with Companion** | Stripped production ELF (`strip -s`) | Matching debug ELF companion | GNU Build IDs match; target identity marked `COMPLETED` (`VERIFIED_MATCH`); full DWARF types and candidates available. |
| **Scenario 7: Mismatched Companion Safety** | Stripped production ELF | Mismatched debug ELF companion | GNU Build IDs mismatch; target identity marked `FAILED` or `BUILD_ID_MISMATCH`; misleading symbol resolution rejected. |
| **Scenario 8: Multithreaded Competing Writers** | Inferior with active background thread | Single-writer isolation control baseline | Background writer causes control baseline drift (`10 -> 555`); single-writer isolation rejected; attribution marked False. |
| **Scenario 9: Degradation Boundaries** | Dead PID / degraded capture | Capture safety policy | Dead PID raises `RuntimeError` (`ESRCH`); `NON_ATOMIC` and `PARTIAL` captures cap hypothesis confidence at `SUPPORTED`. |
| **Scenario 10: Session Persistence Integrity** | Serialized investigation session | Revalidation from ledger & corpus | Tampered hypotheses, forged evidence records, or modified snapshot hashes fail verification and disarm claims. |

---

## 3. Architecture & Trust Boundaries

```
[Target Inferior (C++)]
          │
          ▼ (process_vm_readv / procfs)
[RawRuntimeSnapshot] (Captured bytes, Build ID, PID, Atomic timestamp)
          │
          ▼ (Offline DWARF Reconstructor)
[StateDiffEngine] ──► [InvestigationFinding] (Before/After values, DWARF types, Candidate functions)
          │
          ▼ (Deterministic Hypothesis Generator)
[InvestigationHypothesis] ──► [FollowUpObservation] (Discriminating observation plan)
          │
          ▼ (TrustedCausalVerifier)
[ControlledExecutionResult] ──► [CausalVerificationCapability] ──► [EvidenceLedger Attestation]
          │
          ▼ (HypothesisValidator.evaluate)
[Promoted Hypothesis] (VALIDATED_CAUSAL_FUNCTION with verified root cause)
```

### Trust Boundary Invariants
1. **No Promotion Without Independent Attribution**: Static candidate functions, DWARF call references, naming heuristics, or LLM explanations can **never** be promoted to `VALIDATED_CAUSAL_FUNCTION` without verified runtime execution traces or controlled single-writer isolation.
2. **State Transition vs Function Attribution**: State-transition validation proves that memory changed between snapshots; function-attribution validation proves *which* function performed the write. The two remain strictly decoupled.
3. **Fail-Closed Target Identity**: Mismatches between process Build ID, debug companion Build ID, or snapshot target identity halt symbol resolution and reject causal attestations.
4. **Immutable Evidence Provenance**: All attestation records in the `EvidenceLedger` are cryptographically sealed with session-scoped HMAC-SHA256 signatures and tamper-evident fingerprints.

---

## 4. Operational Runbooks

### Runbook 1: Executing the Full Operational Acceptance Suite
The Phase 13 operational acceptance test suite exercises all 10 real C++ runtime scenarios, conversational investigation workflows, and security regression gates.

```bash
python3 -m unittest tests/test_phase13_operational_acceptance.py -v
```

**Expected Outcome:**
- 16 tests executed in ~12–15 seconds.
- 0 failures, 0 errors, status `OK`.

### Runbook 2: Running the End-to-End Demonstration Script
The automated acceptance demonstration script compiles real C++ code, spawns an inferior process, executes live memory captures, triggers controlled mutations, performs offline differential analysis, executes single-writer verification, and outputs the final report.

```bash
python3 scripts/run_e2e_operational_acceptance.py
```

**Options:**
- `--work-dir <path>`: Specify directory for compiled artifacts and snapshots (defaults to a safe temporary directory).
- `--keep-artifacts`: Preserve compiled binaries and snapshot directories on exit for manual inspection.

**Expected Output:**
```text
[OK] [STEP 1] Compilation complete. GNU Build ID verified.
[OK] [STEP 2] Target inferior running. Handshake confirmed.
[OK] [STEP 3] Initial snapshot saved.
[OK] [STEP 4] Mutation acknowledged by inferior.
[OK] [STEP 5] Post-mutation snapshot saved.
[OK] [STEP 6] Inferior terminated cleanly.
[OK] [STEP 7] Investigation established. Debug companion Build ID verified match.
[OK] [STEP 8] Detected state transition on WorkerState.counter: 10 -> 100.
[OK] [STEP 9] Drilldown verified: field WorkerState.counter, candidates identified.
[OK] [STEP 10] Hypothesis formulated with discriminating observation plan.
[OK] [STEP 11] Controlled single-writer isolation receipt verified.
[OK] [STEP 12] Evidence record signed and attested with session capability.
[OK] [STEP 13] Candidate 'active_worker_state_writer' promoted to VALIDATED_CAUSAL_FUNCTION!
[OK] [STEP 14] Final report generated.
==============================================================================
 PHASE 13 OPERATIONAL ACCEPTANCE: ALL 14 PIPELINE CHECKS PASSED
==============================================================================
```

### Runbook 3: Running Complete Regression Suites
To verify all unit, integration, and security tests across all phases (Phase 1 through Phase 13):

```bash
./run_all_tests.sh
```

---

## 5. Failure Diagnosis & Interpretation

| Symptom / Error Message | Root Cause | Remediation |
|---|---|---|
| `Live reproduction rejected: snapshot consistency not atomic/stopped` | Target process was captured while actively executing or mutating memory (`NON_ATOMIC`). | Ensure target process is stopped via SIGSTOP / `CONDITIONAL_ON_STOP` or execute within an atomic quiescence window. |
| `Negative control baseline failed: field 'X' mutated during control period` | Target field changed while candidate writer function was inactive, indicating concurrency or drift. | Check for background threads or unisolated competing writers. Single-writer attribution cannot be established. |
| `Debug Image Build ID Mismatch: Expected ... does not match ...` | The provided debug ELF companion does not match the binary running in production. | Provide the exact matching debug companion corresponding to the production Build ID. |
| `Procfs is unavailable or target PID ... is not accessible` | The target PID exited before capture, or insufficient OS permissions (`EPERM` / `ESRCH`). | Verify inferior process is running and permissions allow `process_vm_readv` or `/proc/<pid>/mem` access. |
| `Capability issuance rejected: execution receipt signature verification failed` | Attempt to forge or replay an execution receipt across investigations or tampering detected. | Do not manipulate receipt fields; all receipts must be minted by `TrustedCausalVerifier` in the same session. |

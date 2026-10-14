# Runtime Provenance & Causal Validation Specification

## 1. Threat Model & Provenance Trust Boundary

In dynamic runtime analysis and autonomous debugging, an adversarial or untrusted caller must not be able to elevate arbitrary claims into cryptographically attested causal proof.

### What a Signed Receipt Proves
A signed receipt (`ControlledExecutionResult` bearing an HMAC-SHA256 signature) proves:
1. **Internal Verification Authorization**: The receipt was minted by `TrustedCausalVerifier` or `InvestigationManager` possessing the internal session secret.
2. **Scope Sealing**: The exact execution parameters—investigation ID, hypothesis ID, evidence ID, target function candidate, field path, before/after values, snapshot hashes, target process identity, provenance class, and verified attribution flag—were bound together at issuance.
3. **Single-Use Capability**: The receipt satisfies the prerequisites to issue a single-use `CausalVerificationCapability`, preventing replay attacks across hypotheses, evidence records, or investigations.

### What a Signed Receipt Does NOT Prove
- An HMAC signature alone **does not prove** that physical CPU execution occurred if the underlying snapshot files were crafted on disk by an untrusted entity prior to receipt issuance.
- A signature does not prove that a particular function caused a state transition unless **function attribution** was independently verified.
- Static references (DWARF locations, call graphs, or heuristic rankings) are correlations, **not proof** of runtime execution or write causality.
- The trusted computing boundary requires that snapshot artifacts originate from verified kernel capture backends (`process_vm_readv`, `ptrace`, `procfs`) with verifiable process lifecycle identity (PID, start time, executable build ID).

### Attacker Capabilities Assumed
- **Untrusted API/ARP Caller**: External clients can invoke public REST/ARP endpoints, pass arbitrary dictionaries, spoof parameters (`function_attribution_verified=True`, `execution_status="REPRODUCED"`), or submit crafted evidence.
- **Local Filesystem Access**: Untrusted callers may attempt path traversal (`../`), symlink substitution, or tampering with serialized snapshots on disk.
- **Session Secret Secrecy**: The per-session HMAC secret and capability keys are ephemeral and strictly internal; external callers cannot forge valid signatures.

---

## 2. Snapshot Artifact Integrity & Manifest Hashing

`compute_snapshot_artifact_hash()` enforces end-to-end artifact integrity:

### Deterministic Manifest Algorithm
1. **Recursive Traversal**: In directory-based snapshots, all files affecting semantic reconstruction or memory comparison are traversed (e.g., `snapshot_metadata.json`, `metadata.json`, `maps.json`, `threads.json`, and all `memory/range_*.bin` payloads).
2. **Deterministic Manifest**: Entries are formatted as `"{relative_path}:{file_size}:{sha256_digest}\n"` and sorted lexicographically by normalized relative path.
3. **Path Traversal & Symlink Rejection**: Any path containing parent directory traversal (`..`) or symbolic links is strictly rejected.
4. **Digest Computation**: The final artifact hash is the SHA256 digest of the complete concatenated manifest.

### Integrity Guarantees
- Modifying, truncating, or corrupting a raw memory `.bin` file after receipt creation is detected immediately.
- Adding, deleting, or renaming any metadata or payload file invalidates the snapshot hash.
- Re-verification occurs both at receipt issuance and at the time of causal proof attestation.
- Missing, deleted, or replaced artifacts post-receipt immediately abort attestation.

---

## 3. Canonical Provenance Classes

To prevent test fixtures or imported artifacts from impersonating live runtime captures, every evidence record and execution receipt carries an authenticated provenance class:

| Provenance Class | Description | Can Promote to `VALIDATED`? |
| :--- | :--- | :--- |
| **`LIVE_RUNTIME_CAPTURE`** | Memory captured directly from a running process via verified kernel interface with atomic/stopped consistency. | **Yes** (Subject to diff & quality checks) |
| **`CONTROLLED_RUNTIME_REPRODUCTION`** | Deterministic state transition produced and verified under controlled inferior execution. | **Yes** (Subject to diff & quality checks) |
| **`SYNTHETIC_FIXTURE`** | Test fixture, in-memory mock, or adversarial simulation. | **No** (Strictly capped at `SUPPORTED`) |
| **`IMPORTED_UNVERIFIED`** | Third-party or deserialized archive lacking local cryptographic attestation. | **No** (Strictly capped at `SUPPORTED`) |

---

---

## 4. Explicit Evidence Trust Levels & Claims

Phase 8 establishes five distinct, non-conflated trust claims across the evidence lifecycle:

1. **`ARTIFACT_INTEGRITY_VERIFIED`**: The snapshot directory or file bytes match a recorded deterministic manifest digest.
2. **`CAPTURE_PROVENANCE_VERIFIED`**: The snapshot is cryptographically linked to an authenticated capture operation via an HMAC-signed `CaptureReceipt` issued by trusted backend code.
3. **`TARGET_IDENTITY_VERIFIED`**: The capture operation is bound to a verified OS process instance (PID, process start time from `/proc/<pid>/stat`, and ELF build ID).
4. **`STATE_TRANSITION_VERIFIED`**: The target field value transition is observed between eligible captures with `COMPLETE` completeness, atomic/stopped consistency, and unambiguous semantic path matching.
5. **`FUNCTION_ATTRIBUTION_VERIFIED`**: Independent evidence (single-writer isolation or execution tracing) proves the candidate function's causal write responsibility.

> [!IMPORTANT]
> A hash proves integrity relative to a recorded digest, NOT authenticity of the original capture.
> A signed receipt proves what the trusted verifier accepted, NOT that caller-provided parameters were true.
> These five claims are tracked and sealed independently in `ControlledExecutionResult.verified_claims`.

---

## 5. Capture Backend Authentication, Key Lifecycle & `CaptureReceipt`

To guarantee that snapshot artifacts originate from authenticated kernel captures rather than imported files or fabricated JSON:

1. **Internal Minting**: `CaptureReceipt` is minted directly inside trusted capture backends (`ProcessVmCaptureBackend`, `ProcfsCaptureBackend`) immediately following memory extraction.
2. **Cryptographic Binding (Schema 2.0.0)**: The receipt binds:
   - Receipt unique identifier (`receipt_id`) and capture duration (`capture_duration_us`).
   - Target process PID and start time (epoch ticks from `/proc/<pid>/stat`).
   - Executable build ID and binary path.
   - Capture backend type and capture timestamp.
   - Completeness (`COMPLETE`) and consistency level (`STOPPED`).
   - Active Key ID (`key_id`) from the key store.
   - Deterministic artifact manifest (`compute_capture_receipt_signature()` with canonicalized sorted paths and compact JSON).
   - HMAC-SHA256 signature using the active signing key from `CaptureKeyStore`.
3. **Key Lifecycle Architecture (`CaptureKeyStore`)**:
   - **Configured vs. Ephemeral Fallback**: When `DYNAMICSTATE_CAPTURE_SECRET`, `DYNAMICSTATE_CAPTURE_KEY_FILE`, or `DYNAMICSTATE_CAPTURE_KEYRING` is set, explicit keys are registered and marked as configured. In local unconfigured runs, a process-local ephemeral key is used; cross-process receipt verification against an unconfigured store fails closed with `VERIFICATION_KEY_UNAVAILABLE`.
   - **Key Rotation**: New signing keys can be rotated in via `rotate_key(new_key_id, new_secret)` without invalidating existing receipts signed with older keys in the keyring.
   - **Key Revocation**: Compromised or retired keys can be revoked via `revoke_key(key_id)`; receipts signed with revoked keys immediately evaluate to `KEY_REVOKED`.
   - **Secret Non-Leakage**: Secrets are never serialized into receipts, snapshot metadata, JSON files, API responses, or exception messages.
4. **Storage & Verification**: When serialized to disk via `RawRuntimeSnapshot.save()`, `capture_receipt.json` is generated. Upon loading or live verification:
   - The HMAC signature is verified against the key store (`verify_with_status()`).
   - The artifact manifest is recomputed across all metadata and memory `.bin` files; extra, missing, or altered files are detected and marked `TAMPERED`.
   - Any symbolic link in the snapshot hierarchy is strictly rejected to prevent symlink redirection attacks.
   - Snapshots lacking a receipt are cleanly loaded and marked `UNVERIFIED_LEGACY`.
   - For live processes, process start time is cross-checked against `/proc/<pid>/stat` to defeat PID recycling.

---

## 6. Decoupling State Transition Validation from Function Attribution

State transition verification and root-cause function attribution are strictly separated:

```
[Snapshot Diff Verified]
         │
         ├──► Hypothesis Status: VALIDATED (state transition established)
         │
         └──► Function Candidate Attribution
                     │
                     ├── [Single-Writer Isolation with Baseline Control] ──► VALIDATED_CAUSAL_FUNCTION (confirmed_root_cause=True)
                     │
                     ├── [Execution Trace with Trace Collector Record] ─────► VALIDATED_CAUSAL_FUNCTION (confirmed_root_cause=True)
                     │
                     └── [Call Stack Observation or Heuristic Ranking] ─────► EVIDENCE_SUPPORTED_CANDIDATE (confirmed_root_cause=False)
```

### Call Stack Presence vs. Write Causality
Observing a function on an active thread call stack proves temporal correlation, **not write causality**:
- A function on a call stack may be an innocent caller, a reader, or an idle waiter.
- `call_stack_observation` qualifies a function as an `EVIDENCE_SUPPORTED_CANDIDATE`, but does **not** grant `FUNCTION_ATTRIBUTION_VERIFIED` or confirm root cause.

### Supported Attribution Mechanisms
1. **`controlled_single_writer_isolation`**: Requires a verified negative control baseline record (`control_evidence_id`) in the ledger demonstrating field stability when the candidate is inactive, plus isolated active writer activation.
2. **`runtime_execution_trace`**: Requires an authenticated execution trace record (`trace_evidence_id`) from a trusted trace collector confirming that the candidate executed the write.

### Function Candidate Tiers
1. **`STATIC_CANDIDATE`**: Identified via static DWARF/ELF analysis. Invariant: *Can never become a confirmed root cause solely by finding association or state transition without verified runtime attribution.*
2. **`EVIDENCE_SUPPORTED_CANDIDATE`**: Correlated with runtime observation or verified state transition, but lacks independent causal write attribution (`confirmed_root_cause=False`).
3. **`VALIDATED_CAUSAL_FUNCTION`**: Confirmed root cause writer (`confirmed_root_cause=True`). Requires `function_attribution_verified=True` backed by single-writer isolation or execution tracing.

---

## 7. Object-Aware Field-Path Matching & Ambiguity Handling

To eliminate loose substring or suffix collisions, comparisons use object-aware path matching (`is_exact_semantic_path_match` and `find_matching_diff_changes`):
- `ThreadCounter.counter` does **not** match `State.counter`.
- `items[0].value` does **not** match `items[1].value`.
- `Session.worker.state.counter` **matches** `State.counter` when terminal segment tokens align on dot boundaries (`["state", "counter"]`).
- **Ambiguity Detection**: If multiple distinct objects in the snapshot diff match the requested field path (e.g., two instances of `State` both modifying `counter`), `find_matching_diff_changes` raises an explicit ambiguity error requiring the caller to specify a target `object_id`.

---

## 8. Test Suite Classification, Operational Tiers & Coverage

Test suites are categorized into four distinct operational tiers:

### Testing Tiers
1. **UNIT TESTED**:
   - `tests/test_causal_validation_hardening.py` (83 tests): Verifies HMAC signatures, receipt tamper detection, token zero-leakage, key store concurrency, capability scope and single-use consumption, artifact manifest hashing, Phase 8 trust claims (A–L), and Phase 9 cross-process offline exchange.
   - `tests/test_capture_safety_and_diff_accuracy.py` (27 tests): Verifies memory diffing, partial capture handling, path prefix sanitization, and state change accuracy.
   - `tests/test_capture_lifecycle_seam.py` (54 tests): Verifies process attachment lifecycle, PID pinning, state recovery seams, and `/proc/<pid>/stat` validation.
2. **INTEGRATION TESTED**:
   - `tests/test_investigation_hypothesis.py`: Verifies multi-step hypothesis evaluation, evidence linking, and REST/ARP disarming.
   - `tests/test_multithread_exploration.py`: Verifies branch isolation and multithreaded deterministic execution.
   - `tests/test_ci_workflow_parity.py` (7 tests): Verifies 100% byte parity and structural YAML schema between canonical `ci/workflows/` and local test runners.
3. **REAL TARGET VALIDATED**:
   - `tests/test_real_runtime_validation.py` (20 tests): Live process validation against compiled C/C++ targets under Linux `process_vm_readv` and ptrace with real stop/read/resume latency measurements.
   - `tests/test_cpp_e2e_investigation.py` (5 tests): Real-world end-to-end investigation pipeline on compiled C++ PIE binaries with active thread workers and ASLR.
   - `tests/test_phase10_ci_security_gates.py` (16 tests): Dedicated CI security acceptance suite featuring compiled C++ positive controls and cross-process negative controls.
4. **CI VERIFIED**:
   - Canonical pipeline defined in `ci/workflows/test.yml` and enforced locally via `run_all_tests.sh`. All tests execute with `set -euo pipefail` and fail closed on any non-zero exit code.

---

## 9. Known Limitations & Out-of-Scope Proof Claims

1. **PID Reuse Mitigation**: Relies on `/proc/<pid>/stat` start-time ticks. On systems without `/proc` or non-Linux kernels, PID recycling cannot be verified without container/cgroup namespaces.
2. **Zero-Stop Captures**: `process_vm_readv` captures performed without pausing the inferior thread group are classified as `NON_ATOMIC` and are capped at `SUPPORTED`.
3. **Attribution without Instrumentation**: When a process is captured without thread call stack metadata or instruction trace records, the engine validates that the state transition occurred between captures, but conservatively flags function attribution as unverified.
4. **Canonical Benchmark Baselines**: `benchmarks/baseline_results.json` represents static canonical baseline metrics and is strictly preserved. Synthetic adversarial scenarios are never conflated with real-world accuracy numbers.

---

## 10. Phase 10: Independent Trust Verification & CI Acceptance Gates

Phase 10 enforces all evidence authenticity and causal validation guarantees through automated, non-bypassable CI security gates:

1. **Gate 1: Trust-Boundary Ingress Gate** (`TestTrustBoundaryIngressGates`)
   - Untrusted caller booleans, fabricated execution dictionaries, and forged verifier tokens via REST or ARP are disarmed immediately.
   - Single-writer attribution is rejected if the control baseline experienced drift.
   - Degraded capture quality (`PARTIAL` or non-atomic consistency) caps hypotheses at `SUPPORTED`.
   - Capabilities enforce strict scope binding (investigation ID, evidence ID, target function, field path) and fail closed on reuse.
2. **Gate 2: Key Lifecycle & Concurrency Gate** (`TestKeyLifecycleAndConcurrencyGates`)
   - Thread-safe, atomic key registration, rotation, and revocation under concurrent load (`threading.RLock`).
   - Revoked keys immediately fail closed (`KEY_REVOKED`).
   - Corrupted or malformed key files/keyrings are handled safely without crashing.
   - Strict zero-leakage contract: secrets and capability keys are never exposed in `__repr__`, `__str__`, `to_dict()`, JSON logs, or API payloads.
3. **Gate 3: Artifact Integrity & Anti-Tampering Gate** (`TestArtifactIntegrityAndAntiTamperingGates`)
   - Any payload byte modification, manifest file deletion, or unexpected extra file injection marks snapshots as `TAMPERED`.
   - Path traversal (`..`) and symbolic links (directory or file) are rejected with `ValueError`.
   - All 12 security-critical fields of `CaptureReceipt` Schema 2.0.0 are verified to be tamper-evident.
   - Legacy snapshots lacking receipts load safely as `UNVERIFIED_LEGACY`.
4. **Gate 4: Real-World C++ Cross-Process Acceptance Gate** (`TestRealWorldCppCrossProcessAcceptanceGate`)
   - End-to-end positive control with compiled C++ PIE binary, live kernel capture with receipt issuance, inferior termination, and post-mortem offline verification in a clean session.
   - Negative control ensuring that analysis sessions with mismatched keys fail closed when `require_capture_provenance=True`.

---

## 11. Trust-Boundary Security Matrix

| # | Boundary Name | Ingress Point | Trusted Inputs | Attacker-Controlled Inputs | Required Security Checks | Failure Status / Outcome | Verifying Regression Tests |
| :- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | **Native Capture Backend** | `ProcessVmCaptureBackend`, `ProcfsCaptureBackend` | Kernel syscall returns, `/proc/<pid>/stat` start time, ELF Build ID | Inferior memory contents, PID (reuse risk) | `CAP_SYS_PTRACE`, inferior stopped state (`T`/`t`), start time validation, atomic payload read | `INCONCLUSIVE`, `CAPTURE_ERROR`, `NON_ATOMIC` | `test_real_runtime_validation.py`, `test_capture_lifecycle_seam.py` |
| **2** | **Receipt Issuance** | `issue_capture_receipt()` | Backend name, PID, start time, binary path, build ID, duration, completeness, consistency, manifest | Public constructor arguments if invoked externally | Active key lookup from `CaptureKeyStore`, HMAC-SHA256 signing over canonical Schema 2.0.0 payload | `ValueError` if required fields missing or key invalid | `test_phase10_ci_security_gates.py:test_gate_receipt_all_security_fields_tamper_evident` |
| **3** | **Snapshot Save & Load** | `RawRuntimeSnapshot.save()`, `load()` | Internal metadata, memory buffers | Directory paths, files on disk, injected symlinks, extra scripts | Reject `..` in path segments, reject directory and file symlinks recursively, verify receipt HMAC, recompute manifest digests | `ValueError` (traversal/symlink), `TAMPERED` (byte tampering / extra files), `UNVERIFIED_LEGACY` | `test_phase10_ci_security_gates.py:TestArtifactIntegrityAndAntiTamperingGates` (5 tests) |
| **4** | **Cross-Process Receipt Verification** | `verify_capture_provenance()`, `CaptureReceipt.verify_with_status()` | Configured `CaptureKeyStore` (env, key file, keyring) | Serialized `capture_receipt.json`, disk payload, foreign `key_id` | Key existence, revocation check, constant-time HMAC comparison, manifest matching | `VERIFICATION_KEY_UNAVAILABLE`, `KEY_REVOKED`, `SIGNATURE_MISMATCH`, `TAMPERED` | `test_phase10_ci_security_gates.py:TestKeyLifecycleAndConcurrencyGates`, `test_phase9_cross_process_offline_exchange_scenarios` |
| **5** | **Investigation Creation & Corpus Registration** | `InvestigationManager.start_investigation()` | Ephemeral session secret, UUID session ID | `goal`, `memory_snapshot_path`, `debug_image`, metadata dicts | Path traversal and symlink rejection, snapshot receipt verification, isolated ledger initialization | `ValueError`, `FileNotFoundError` | `test_investigation_hypothesis.py`, `test_causal_validation_hardening.py:test_phase5_case_d` |
| **6** | **REST API Ingress** | `WebApiAdapter` (`evaluate_hypothesis`, `add_evidence`) | Runtime manager instance, active sessions | JSON HTTP body: `deterministic_transition_verified`, forged tokens, caller claims | Strip unverified attestation tokens, mark evidence `source="unverified_caller"`, disarm attribution booleans, cap hypothesis at `SUPPORTED` | `INVALID_PARAM`, disarmed evaluation without promotion | `test_phase10_ci_security_gates.py:test_gate_rest_arp_caller_boolean_disarmed`, `test_case_k_api_and_arp_injection_fails_safely` |
| **7** | **Autonomous Reasoner Pipeline (ARP)** | `AgentRuntime.dispatch_action()` | Internal runtime state, session ledger | `AgentAction` parameters, action type, candidate function flags | Enforce action permission, require authentic ledger proof record (`proof_evidence_id`), disarm caller-supplied flags | Action rejected or disarmed; `unverified_claim_rejected=True` | `test_investigation_hypothesis.py`, `test_phase5_case_m_rest_and_arp_payloads_cannot_inject_trusted_receipts` |
| **8** | **Evidence Ledger Attestation** | `EvidenceLedger.attest_causal_proof()` | Internal `CausalVerificationCapability`, session ID | Caller `EvidenceRecord` fields, external provenance dicts | Capability HMAC matches `_capability_key`, capability not consumed, exact scope match (investigation, evidence, fn, field), reject unverified caller claims | `ValueError` ("invalid capability", "already consumed", "scope-mismatched") | `test_phase10_ci_security_gates.py:test_gate_capability_scope_and_reuse_enforcement` |
| **9** | **Controlled Execution Verification** | `TrustedCausalVerifier.verify_execution_and_attest()` | Session secret, resolved snapshot artifacts, diff engine | Target function, field path, claimed before/after values, caller provenance | Reject caller-supplied execution dictionaries, resolve snapshots without symlinks, verify diff matches values, check control baseline stability, verify complete & atomic capture quality | `ValueError` ("Fabricated execution values", "Degraded capture quality", "Control baseline drifted") | `test_phase10_ci_security_gates.py:test_gate_single_writer_baseline_drift_rejection`, `test_gate_degraded_capture_quality_caps_hypothesis` |
| **10** | **Causal Attestation & Hypothesis Promotion** | `HypothesisValidator.evaluate()`, `InvestigationManager.evaluate_hypothesis()` | Ledger records, verifier attestation in proof record | `deterministic_transition_verified` flag, `proof_evidence_id`, candidate nominations | Require authentic verifier attestation with valid HMAC signature, verify `STATE_TRANSITION_VERIFIED`, promote function to `VALIDATED_CAUSAL_FUNCTION` (`confirmed_root_cause=True`) ONLY with verified attribution (single-writer or trace). Static DWARF candidates never promoted without runtime proof. | Hypothesis capped at `SUPPORTED`; candidate capped at `EVIDENCE_SUPPORTED` / `STATIC` with `confirmed_root_cause=False` | `test_phase10_ci_security_gates.py:test_gate_static_dwarf_candidate_never_promoted_without_instrumentation`, `test_gate_cpp_compiled_process_offline_verification_e2e` |

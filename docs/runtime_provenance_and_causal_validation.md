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

## 5. Capture Backend Authentication & `CaptureReceipt`

To guarantee that snapshot artifacts originate from authenticated kernel captures rather than imported files or fabricated JSON:

1. **Internal Minting**: `CaptureReceipt` is minted directly inside trusted capture backends (`ProcessVmCaptureBackend`, `ProcfsCaptureBackend`) immediately following memory extraction.
2. **Cryptographic Binding**: The receipt binds:
   - Target process PID and start time (epoch ticks from `/proc/<pid>/stat`).
   - Executable build ID and binary path.
   - Capture backend type and capture timestamp.
   - Completeness (`COMPLETE`) and consistency level (`STOPPED`).
   - Artifact manifest digest (`compute_snapshot_artifact_hash()`).
   - HMAC-SHA256 signature using the internal session secret.
3. **Storage & Verification**: When serialized to disk via `RawRuntimeSnapshot.save()`, `capture_receipt.json` is generated. Upon loading or live verification:
   - The HMAC signature is verified against the session secret.
   - The artifact manifest is recomputed across all metadata and memory `.bin` files; extra, missing, or altered files are detected.
   - Any symbolic link in the snapshot hierarchy is strictly rejected to prevent symlink redirection attacks.
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

## 8. Test Suite Classification & Coverage

Test suites are categorized into distinct operational tiers:

- **Category A (Unit Tests & Synthetic Adversarial Fixtures)**: 77 tests in `tests/test_causal_validation_hardening.py` verifying attestation security, HMAC signatures, tamper detection, capability consumption, Phase 8 trust levels (Tests A–L), and adversarial ingress hardening.
- **Category B (Artifact Integrity & Manifest Hashing)**: Recursive directory payload hashing, file addition/deletion/modification detection, and path traversal/symlink rejection.
- **Category C (Offline Reconstruction Tests)**: DWARF type recovery, layout mutation caveats, and offline object graph decoders (`test_offline_analyzer.py`, `test_dwarf_semantic_reconstruction.py`).
- **Category D (Real Local C++ Process Tests)**: 5 end-to-end integration scenarios in `tests/test_cpp_e2e_investigation.py` and positive control in `test_causal_validation_hardening.py` running live compiled binaries with `g++`, stdin/stdout synchronization, thread workers, and kernel capture backends.
- **Category E (Capture Backend Dependency Tests)**: Tests utilizing `/proc/<pid>/mem`, `/proc/<pid>/maps`, and `process_vm_readv`.
- **Category F (Unavailable Environment Fallbacks)**: Clearly marked as NOT RUN when platform dependencies are absent (e.g., non-Linux kernel interfaces).

---

## 9. Known Limitations & Out-of-Scope Proof Claims

1. **PID Reuse**: Mitigation relies on `/proc/<pid>/stat` start time checks; on non-Linux platforms or without `/proc`, PID reuse cannot be cryptographically proven without OS container/cgroup isolation.
2. **Zero-Stop Captures**: `process_vm_readv` captures without pausing the target are classified as `NON_ATOMIC` and are capped at `SUPPORTED`.
3. **Attribution without Instrumentation**: When a process is captured without thread call stack metadata or hardware instruction tracing, the engine proves that the state transition occurred between snapshots, but conservatively marks function attribution as unverified.
4. **Canonical Benchmark Baselines**: `benchmarks/baseline_results.json` represents static reference numbers and is strictly preserved. Synthetic scenario results are not claimed as real-world precision/recall benchmarks.

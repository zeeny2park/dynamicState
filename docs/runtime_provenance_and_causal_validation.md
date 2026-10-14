# Runtime Provenance & Causal Validation Specification

## 1. Threat Model & Provenance Trust Boundary

In dynamic runtime analysis and autonomous debugging, an adversarial or untrusted caller must not be able to elevate arbitrary claims into cryptographically attested causal proof.

### What a Signed Receipt Proves
A signed receipt (`ControlledExecutionResult` bearing an HMAC-SHA256 signature) proves:
1. **Internal Verification Authorization**: The receipt was minted by `TrustedCausalVerifier` or `InvestigationManager` possessing the internal session secret.
2. **Scope Sealing**: The exact execution parameters—investigation ID, hypothesis ID, evidence ID, target function candidate, field path, before/after values, snapshot hashes, and target process identity—were bound together at issuance.
3. **Single-Use Capability**: The receipt satisfies the prerequisites to issue a single-use `CausalVerificationCapability`, preventing replay attacks across hypotheses, evidence records, or investigations.

### What a Signed Receipt Does NOT Prove
- An HMAC signature alone **does not prove** that physical CPU execution occurred if the underlying snapshot files were crafted on disk by an untrusted entity prior to receipt issuance.
- A signature does not prove that a particular function caused a state transition unless **function attribution** was independently verified.
- The trusted computing boundary requires that snapshot artifacts originate from verified kernel capture backends (`process_vm_readv`, `ptrace`, `procfs`) with verifiable process lifecycle identity (PID, starttime, executable build ID).

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

## 4. Hypothesis Statuses & Function Candidate Tiers

State transition verification and function attribution are decoupled:

```
[Snapshot Diff Verified]
         │
         ├──► Hypothesis Status: VALIDATED
         │
         └──► Function Candidate Attribution
                     │
                     ├── [Attribution Verified (call stack / trace)] ──► VALIDATED_CAUSAL_FUNCTION (confirmed_root_cause=True)
                     │
                     └── [Attribution Unverified] ─────────────────────► EVIDENCE_SUPPORTED_CANDIDATE (confirmed_root_cause=False)
```

### Hypothesis Validation Lifecycle
- **`PROPOSED`**: Initial hypothesis synthesized from state diff or fact finding.
- **`SUPPORTED`**: Hypothesis is backed by observation, but causal proof is absent, capture quality is degraded (`PARTIAL`, `NON_ATOMIC`), or provenance class is synthetic (`SYNTHETIC_FIXTURE`).
- **`VALIDATED`**: A verified causal proof record from a trusted provenance class (`LIVE_RUNTIME_CAPTURE` or `CONTROLLED_RUNTIME_REPRODUCTION`) with `COMPLETE` completeness and atomic/stopped consistency confirms the deterministic state transition.
- **`CONTRADICTED`**: Contradictory evidence (e.g. idle drift, zero execution, or conflicting state) dominates and permanently blocks validation.
- **`INCONCLUSIVE`**: Capture quality is `FAILED` or `INVALID`, or cyclic/missing evidence ancestry is detected.

### Function Candidate Tiers
1. **`STATIC_CANDIDATE`**: Identified via static DWARF/ELF analysis. Invariant: *Can never become a confirmed root cause solely by finding association.*
2. **`EVIDENCE_SUPPORTED_CANDIDATE`**: Correlated with runtime observation or verified state transition, but lacks independent function attribution proof.
3. **`VALIDATED_CAUSAL_FUNCTION`**: Confirmed root cause writer (`confirmed_root_cause=True`). Requires `function_attribution_verified=True` established by thread call frame observation, execution breakpoint, or instrumented single-writer verification.

---

## 5. Exact Semantic Path Matching

To eliminate loose substring or suffix collisions (e.g. `ThreadCounter.counter` matching `State.counter`), path comparisons use exact segment matching on dot boundaries (`is_exact_semantic_path_match`):
- `ThreadCounter.counter` does **not** match `State.counter`.
- `GlobalState.counter_2` does **not** match `State.counter`.
- `Session.worker.state.counter` **matches** `State.counter` because the terminal segments align on dot boundaries (`["state", "counter"]`).
- `WorkerState.counter` **matches** `WorkerState.counter`.

---

## 6. Known Limitations & Out-of-Scope Proof Claims

1. **PID Reuse**: Mitigation relies on `/proc/<pid>/stat` starttime checks; on non-Linux platforms or without `/proc`, PID reuse cannot be cryptographically proven without OS container/cgroup isolation.
2. **Zero-Stop Captures**: `process_vm_readv` captures without pausing the target are classified as `NON_ATOMIC` and are capped at `SUPPORTED`.
3. **Attribution without Instrumentation**: When a process is captured without thread call stack metadata or hardware instruction tracing, the engine proves that the state transition occurred between snapshots, but conservatively marks function attribution as unverified.

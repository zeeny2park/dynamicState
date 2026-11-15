# DynamicState — Integrated Requirements & Implementation Specification

## 1. Mission

Repository: https://github.com/zeeny2park/dynamicState

Primary objective:

Strengthen DynamicState as an expert-grade, evidence-driven runtime diagnostic platform for embedded Linux C/C++ systems.

The implementation must prioritize:

1. Evidence trust and provenance integrity
2. Deterministic diagnostic correctness
3. Hypothesis validation and root-cause reasoning
4. Reproducible evaluation
5. Secure and resilient operation
6. High-quality, traceable reports
7. Reliable MCP interfaces

This is an implementation and correctness-improvement project, not an architecture replacement.

The product is intended for experienced software and embedded-system engineers. It does not need to optimize for non-technical users or introduce unnecessary UI complexity.

The LLM is an explanation and interaction layer. It must not replace deterministic diagnostic algorithms or independently alter diagnostic conclusions.

---

## 2. Mandatory Engineering Principles

### 2.1 Audit Before Implementation

Before changing code:

- Inspect the latest main branch and record the exact commit SHA.
- Read the existing PRD, requirements, implementation reports, and handoff documents.
- Trace every relevant implementation through its actual runtime call path.
- Identify existing implementations before adding new ones.
- Verify whether each reported defect still exists.
- Identify existing tests and their actual coverage.
- Identify incomplete, duplicated, disconnected, or unused implementations.
- Produce a requirement-to-code-to-test traceability matrix.

Do not implement a feature merely because it appears in this specification.

If a requirement is already correctly implemented and verified, document the evidence and mark it COMPLETE.

### 2.2 No Duplicate Implementation

Do not:

- Create a second implementation of an existing capability.
- Introduce parallel data models without demonstrating necessity.
- Add unnecessary abstractions or frameworks.
- Replace existing architecture without measurable justification.
- Reimplement existing MCP tools under different names.
- Expand diagnostic recipes or investigation scope unnecessarily.

Prefer correcting and consolidating existing code.

### 2.3 Test-First Development

For each confirmed defect:

1. Create a regression test that reproduces the defect.
2. Confirm that the test fails against the current implementation.
3. Implement the smallest appropriate correction.
4. Confirm the regression test passes.
5. Run relevant existing tests.
6. Run broader tests where appropriate.
7. Record the actual results.

A test that was not executed must never be reported as PASS.

### 2.4 Scope Control

Implement P0 requirements first.

Do not begin unrelated P1/P2 improvements until P0 acceptance criteria are satisfied.

Do not introduce new product features unless they are strictly necessary to satisfy an explicit requirement.

---

# 3. P0 — Evidence Trust and Security

## FR-TRUST-001: Operation Identity Validation

Every runtime operation must have a validated identity before it can consume durable trust-related state.

Requirements:

- Validate operation identifiers before durable Attestation consumption.
- Validate identifier format, length, and semantic consistency.
- Reject malformed, incomplete, or conflicting operation identities.
- Ensure validation and durable state transitions cannot be reordered in a way that permits invalid operations.
- Failed validation must not leave partially consumed trust state.

Acceptance criteria:

- Invalid operation IDs cannot consume durable Attestation state.
- Validation failure leaves no partially committed operation.
- Concurrent operations cannot bypass identity validation.
- Regression tests cover malformed IDs, duplicate IDs, and interrupted execution.

## FR-TRUST-002: Replay Protection Identity

Replay protection must use a complete, canonical operation identity.

At minimum, evaluate and include the following fields where applicable:

- Operation ID
- Operation kind
- Host identity
- Boot ID
- PID
- Process start time
- Process/session identity
- Target identity
- Build ID
- Request scope
- Normalized request parameters
- Schema/version identity

Requirements:

- Define a canonical serialization format.
- Define which fields are mandatory for each operation type.
- Compare the complete canonical identity during replay validation.
- Reject incomplete identities where required.
- Do not rely on PID alone because of PID reuse.
- Do not treat a matching operation ID as sufficient proof of identity.
- Ensure identity comparisons are stable across serialization and recovery.

Acceptance criteria:

- Replaying the same operation is rejected or handled according to the defined idempotency policy.
- Reusing an operation ID with a different target or scope is rejected.
- PID reuse cannot cause unrelated operations to share replay identity.
- Missing mandatory identity fields fail closed.
- Canonical serialization tests cover ordering, normalization, and missing fields.

## FR-TRUST-003: Metadata Monotonicity and Identity Conflict

Metadata updates must never silently weaken or overwrite previously established identity.

Rules:

1. Missing or empty metadata must not overwrite valid existing identity.
2. Identical metadata may be accepted.
3. Conflicting identity metadata must be recorded as an explicit Identity Conflict.
4. Conflicting metadata must not silently replace trusted metadata.
5. Evidence associated with unresolved identity conflicts must not be promoted to authoritative evidence.

Acceptance criteria:

- Empty metadata cannot erase an existing Build ID or target identity.
- Conflicting metadata is detectable and auditable.
- Conflict resolution is explicit.
- Downstream diagnostic processing cannot treat unresolved conflicting identity as trusted.

## FR-TRUST-004: Evidence Ledger Admission Boundary

Evidence admission must be a strict trust boundary.

Define explicit admission states:

- ACCEPTED
- REJECTED
- QUARANTINED
- NOT_COVERED
- PARTIAL

Requirements:

- Rejected evidence must never contribute to hypothesis scoring.
- Rejected evidence must never contribute to diagnostic verdicts.
- Rejected evidence must never be used as authoritative root-cause evidence.
- Quarantined evidence may be retained for audit but cannot be treated as accepted evidence.
- NOT_COVERED must remain distinguishable from REJECTED.
- PARTIAL must identify which portions were accepted and which were not.
- Admission failures must be visible in diagnostic and audit outputs.
- Preserve rejected evidence for forensic review where appropriate.

Acceptance criteria:

- Failed Ledger admission cannot influence downstream diagnostic conclusions.
- Every evidence item has an explicit admission state.
- Hypothesis scoring uses only eligible evidence.
- Tests verify that rejected and quarantined evidence cannot affect verdicts.

## FR-TRUST-005: TrustStore Filesystem Security

Review and harden TrustStore and related persistent security state.

Requirements:

- Validate file type.
- Validate owner UID.
- Validate directory ownership and permissions.
- Reject unexpected symbolic links.
- Evaluate hard-link risks.
- Use safe lock-file creation and opening.
- Prevent unsafe path traversal.
- Protect against TOCTOU races.
- Prefer directory-FD-relative operations where appropriate.
- Ensure atomic writes and crash recovery.
- Validate existing persistent state before trusting it.
- Define explicit permission policies.

Use restrictive permissions such as 0600 for sensitive files and 0700 for sensitive directories where appropriate.

Do not blindly hard-code these permissions across every supported deployment. Define platform and deployment policy explicitly.

Acceptance criteria:

- Unexpected file types and ownership are rejected.
- Symlink and unsafe path scenarios are tested.
- Lock ownership and concurrent access are validated.
- Interrupted writes cannot produce silently trusted partial state.
- Security failures fail closed.

## FR-TRUST-006: Evidence Provenance Integrity

Every authoritative evidence item must have sufficient provenance.

Required provenance fields should include, where applicable:

- Operation ID
- Operation kind
- Target identity
- Host identity
- Boot ID
- Process identity
- Process start time
- Build ID
- Capture/session identity
- Timestamp and clock semantics
- Capture consistency mode
- Evidence origin
- Admission result
- Integrity validation result
- Parent evidence references
- Derived evidence references

Requirements:

- Provenance must be preserved across evidence transformations.
- Derived evidence must retain references to its source evidence.
- Missing mandatory provenance must prevent authoritative promotion.
- Provenance conflicts must be explicitly represented.
- Provenance references must resolve to valid evidence records.
- Evidence lineage must be auditable.

Acceptance criteria:

- Every authoritative conclusion can be traced to source evidence.
- Missing provenance cannot silently become trusted.
- Derived evidence cannot lose its source lineage.
- Invalid or dangling evidence references are detected.

## FR-TRUST-007: Operation Lifecycle Integrity

Define and enforce operation lifecycle transitions.

Suggested lifecycle states:

- CREATED
- VALIDATED
- RESERVED
- EXECUTING
- COMMITTED
- REJECTED
- FAILED
- CANCELLED
- PARTIAL

Requirements:

- Define valid transitions explicitly.
- Reject invalid state transitions.
- Preserve operation identity throughout the lifecycle.
- Ensure durable state matches the actual operation state.
- Define recovery behavior after process termination or system interruption.
- Distinguish failure before execution from failure after partial execution.
- Ensure retries cannot bypass replay protection.

Acceptance criteria:

- Invalid lifecycle transitions are rejected.
- Recovery produces a consistent operation state.
- Partial execution is distinguishable from successful commit.
- Repeated execution cannot create inconsistent durable records.

---

# 4. P1 — Diagnostic Correctness

Proceed only after P0 acceptance criteria are met.

## FR-DIAG-001: Static Location Candidate Integrity

Review static location candidate generation and ranking.

Requirements:

- Candidate generation must use actual available DWARF/source/runtime evidence.
- Candidate ranking must be deterministic.
- Missing debug information must not be represented as a confirmed location.
- Candidate locations must be distinguishable from verified root causes.
- Candidate provenance must be retained.
- Avoid ranking candidates using unsupported assumptions.

Acceptance criteria:

- Every candidate has traceable supporting evidence.
- Ranking is reproducible.
- Unavailable source information is explicitly represented.
- Candidate results cannot automatically become confirmed root causes.

## FR-DIAG-002: Hypothesis Invariants

Review the unified hypothesis model and all downstream consumers.

Requirements:

- Define hypothesis lifecycle and state invariants.
- Ensure evidence references are valid.
- Ensure rejected evidence cannot contribute to hypotheses.
- Distinguish supporting and contradicting evidence.
- Prevent contradictory states.
- Define deterministic hypothesis ranking.
- Preserve uncertainty when evidence is insufficient.

Acceptance criteria:

- Invalid hypothesis states are rejected.
- Hypothesis scoring is reproducible.
- Contradicting evidence is represented explicitly.
- No unsupported root-cause conclusion is produced.

## FR-DIAG-003: Adaptive Investigation Budget Integrity

Review adaptive investigation and budget management.

Requirements:

- Every investigation operation must respect defined budgets.
- Budget reservation and consumption must be auditable.
- Failed or interrupted operations must not silently corrupt accounting.
- Avoid duplicate work when equivalent evidence already exists.
- Prefer investigations with high expected diagnostic value.
- Ensure adaptive narrowing does not eliminate viable hypotheses without evidence.

Acceptance criteria:

- Budget accounting is consistent.
- Investigation decisions are explainable.
- Repeated equivalent requests do not create uncontrolled duplicate work.
- Insufficient budget produces an explicit incomplete result.

## FR-DIAG-004: Confidence and Abstention

Review confidence calculation and diagnostic verdict aggregation.

Requirements:

- Confidence must be based on traceable evidence.
- Candidate ranking must not be confused with probability.
- Insufficient evidence must produce an explicit abstention or inconclusive result.
- Contradictory evidence must reduce or qualify confidence appropriately.
- A high-ranking candidate must not automatically become a root-cause verdict.
- Define explicit criteria for confirmed, probable, inconclusive, and rejected conclusions.

Acceptance criteria:

- No unsupported certainty is presented.
- Confidence and evidence sufficiency are distinguishable.
- Abstention behavior is deterministic.
- Every verdict explains the evidence and decision criteria.

---

# 5. P1 — C++ ABI and Runtime Decoding

## FR-CPP-001: C++ Runtime Decoder Correctness

Review C++ container and object decoding.

Requirements:

- Validate supported ABI assumptions.
- Validate architecture-specific layouts.
- Handle unsupported container layouts safely.
- Avoid interpreting invalid memory as valid object state.
- Distinguish decoded values from inferred values.
- Preserve source address and type information.
- Detect truncated or inconsistent memory snapshots.

Acceptance criteria:

- Supported layouts have explicit tests.
- Unsupported layouts fail safely.
- Decoding results are reproducible.
- Invalid memory does not generate authoritative object values.

## FR-CPP-002: Cross-Architecture Consistency

Support and validate x86_64 and AArch64.

Requirements:

- Maintain architecture-specific ABI tests.
- Validate type layouts and pointer interpretation.
- Compare logical diagnostic results across architectures.
- Do not assume identical binary layouts.
- Record architecture and compiler metadata in test artifacts.

Acceptance criteria:

- Both architectures pass their applicable test suites.
- Differences are explained and documented.
- Cross-architecture comparison uses logical semantics rather than raw memory-layout equality.

---

# 6. P1 — Optional Runtime Tracing

## FR-TRACE-001: eBPF Tracing Lifecycle

Review the existing optional eBPF tracing implementation.

Requirements:

- Validate attach and detach lifecycle.
- Ensure resources are released after errors and cancellation.
- Detect event loss.
- Distinguish missing events from evidence of absence.
- Preserve process and session identity.
- Ensure tracing failures do not invalidate unrelated snapshot evidence.
- Keep tracing optional.

Acceptance criteria:

- Attach/detach behavior is tested.
- Resource cleanup is verified.
- Event loss is explicitly reported.
- Unsupported environments degrade safely.

## FR-TRACE-002: Trace Evidence Integration

Requirements:

- Integrate trace events with the existing evidence model.
- Preserve timestamps and clock semantics.
- Maintain source provenance.
- Avoid treating trace absence as proof that an event did not occur.
- Ensure trace evidence follows the same admission and trust rules as other evidence.

Acceptance criteria:

- Trace evidence is traceable.
- Event loss and coverage limitations are explicit.
- Rejected trace evidence cannot influence diagnostic conclusions.

---

# 7. P1 — Benchmark and Evaluation

## FR-BENCH-001: Reproducible Evaluation

Maintain reproducible evaluation datasets and procedures.

Requirements:

- Record exact repository commit SHA.
- Record dataset manifest and version.
- Record test environment.
- Record architecture.
- Record compiler and build configuration.
- Record random seed where applicable.
- Record benchmark command and execution parameters.
- Preserve raw output and machine-readable results.
- Distinguish clean and dirty working trees.
- Never present results from a dirty tree as clean baseline results.

Acceptance criteria:

- Every benchmark result can be reproduced.
- Dataset identity is explicit.
- Results are attributable to a specific source revision.
- Missing artifacts are not treated as successful runs.

## FR-BENCH-002: Functional and Diagnostic Accuracy

Evaluate separately:

1. Defect detection
2. Candidate recall
3. Top-ranked root-cause accuracy
4. Exact-location accuracy
5. False-positive rate
6. Abstention correctness

Requirements:

- Define ground truth.
- Distinguish candidate accuracy from root-cause accuracy.
- Report sample counts and denominators.
- Include false-positive and false-negative results.
- Do not merge unrelated datasets into one accuracy figure.

Acceptance criteria:

- All metrics have explicit definitions.
- Each result includes sample count and dataset identity.
- Results are independently reproducible.

## FR-BENCH-003: Performance Evaluation

Measure separately from diagnostic accuracy:

- Capture latency
- Target stop time
- Memory consumption
- Host-side analysis time
- Evidence processing cost
- MCP request latency
- Resource usage

Requirements:

- Record test environment.
- Record target architecture.
- Use repeatable procedures.
- Report distributions where appropriate, not only averages.
- Include measurement limitations.

Acceptance criteria:

- Performance results are reproducible.
- Functional accuracy is not conflated with performance.
- No unsupported performance claim is published.

---

# 8. P1 — Explanation Layer

## FR-EXPLAIN-001: Deterministic Diagnosis Explanation

Integrate the LLM as a read-only explanation layer.

Requirements:

- Diagnosis must be completed independently of LLM explanation.
- Explanation input must be an immutable snapshot of the diagnostic result.
- Explanation output must be represented separately from DiagnoseResult.
- LLM must not modify:
  - Evidence records
  - Evidence admission state
  - Hypothesis scores
  - Diagnostic confidence
  - Diagnostic verdict
  - Root-cause classification
- Every explanation claim must reference valid evidence IDs or diagnostic fields.
- Unsupported claims must be identified as interpretation or uncertainty.
- Explanation failure must not invalidate the deterministic diagnosis.
- Explanation must not fabricate evidence or references.

Suggested conceptual separation:

DiagnoseResult:
- evidence
- hypotheses
- scores
- verdict
- confidence
- provenance
- limitations

ExplanationResult:
- summary
- reasoning narrative
- evidence references
- uncertainty explanation
- recommended next investigation

Acceptance criteria:

- LLM explanation cannot mutate DiagnoseResult.
- Invalid evidence references are rejected.
- Explanation can be regenerated without changing diagnosis.
- LLM failure does not affect diagnostic validity.
- All factual explanation claims are traceable.

---

# 9. P1 — Report Integrity

## FR-REPORT-001: Canonical Report Source

HTML and Markdown reports must be generated from the same canonical diagnostic result.

Requirements:

- Report generation must not mutate diagnosis or evidence.
- Preserve evidence references and provenance.
- Distinguish facts, hypotheses, interpretations, and recommendations.
- Show missing or unavailable information explicitly.
- Do not present candidates as confirmed root causes.
- Preserve diagnostic uncertainty and abstention.
- Ensure consistent conclusions across HTML and Markdown outputs.

Acceptance criteria:

- Both formats contain equivalent diagnostic conclusions.
- Every root-cause claim has traceable evidence.
- Report rendering cannot modify the source diagnosis.
- Unsupported conclusions are not introduced during rendering.

## FR-REPORT-002: Evidence Traceability

Requirements:

- Every finding links to its supporting evidence.
- Every hypothesis links to supporting and contradicting evidence.
- Every conclusion identifies its decision basis.
- Missing evidence references are detectable.
- Evidence lineage is available for audit.

Acceptance criteria:

- No authoritative conclusion lacks traceable evidence.
- Broken references are detected.
- Evidence lineage remains intact in exported reports.

## FR-REPORT-003: Report Reproducibility

Requirements:

- Preserve source revision and diagnostic session identity.
- Record report generation metadata.
- Ensure equivalent input produces equivalent substantive conclusions.
- Avoid timestamps or presentation metadata affecting diagnostic semantics.

Acceptance criteria:

- Reports are attributable to a specific diagnosis and source revision.
- Repeated rendering does not change diagnostic meaning.
- Report metadata is auditable.

---

# 10. P1 — MCP Contract Integrity

## FR-MCP-001: MCP Tool Contract

Review existing MCP tool interfaces.

Requirements:

- Validate input schemas.
- Validate required parameters.
- Define error semantics.
- Distinguish invalid input, unavailable target, partial result, and internal failure.
- Preserve operation identity.
- Avoid silently converting errors into empty successful results.

Acceptance criteria:

- Invalid inputs fail explicitly.
- Tool outputs have stable, documented schemas.
- Error conditions are distinguishable.

## FR-MCP-002: Diagnostic Workflow Consistency

Requirements:

- MCP tools must use the same deterministic diagnostic core as other interfaces.
- No separate diagnostic implementation should be introduced for MCP.
- Preserve investigation and evidence context where appropriate.
- Prevent LLM-generated arguments from bypassing validation.
- Ensure evidence admission rules apply to all MCP entry points.

Acceptance criteria:

- MCP and non-MCP diagnostic paths produce equivalent results for equivalent inputs.
- Validation is enforced consistently.
- No MCP-specific trust bypass exists.

## FR-MCP-003: MCP Output Traceability

Requirements:

- Return structured findings.
- Include evidence references.
- Include hypothesis status.
- Include confidence and limitations.
- Distinguish confirmed results from candidates.
- Expose partial and inconclusive outcomes.

Acceptance criteria:

- MCP results are sufficient to explain how a conclusion was reached.
- Evidence references resolve correctly.
- Missing information is explicit.

---

# 11. NFR — Security

## NFR-SECURITY-001: Security Rules

Define security rules based on the actual DynamicState threat model.

Requirements:

- Identify protected assets.
- Identify trust boundaries.
- Identify relevant attackers and failure scenarios.
- Define security invariants.
- Map each rule to implementation and tests.
- Separate universally applicable rules from deployment-specific rules.
- Treat critical trust-boundary violations as blocking failures.

Acceptance criteria:

- Every blocking security rule has a test or documented verification method.
- Security exceptions are explicit and justified.
- Unsupported platforms are not silently treated as verified.

---

# 12. NFR — Property-Based Testing

## NFR-PBT-001: Property-Based Test Policy

Apply property-based testing to critical invariants.

Priority targets:

- Operation identity
- Replay protection
- Evidence admission
- Provenance consistency
- Lifecycle transitions
- Metadata monotonicity
- TrustStore state
- Serialization and deserialization
- Hypothesis invariants

Requirements:

- Use deterministic seeds for reproducibility.
- Record seed and failing input.
- Minimize counterexamples where supported.
- Promote important discovered failures into permanent regression tests.
- Separate fast PR checks from extended/nightly testing.
- Do not create excessively slow or unstable mandatory CI jobs.

Acceptance criteria:

- Critical invariants have property-based coverage.
- Failures are reproducible.
- Minimized failures can be converted into regression tests.
- Test execution status is accurately reported.

---

# 13. NFR — Resilience

## NFR-RESILIENCY-001: Core Operation Resilience

Validate:

- Process interruption
- System interruption
- Partial writes
- Failed commits
- Concurrent operations
- Retry behavior
- Recovery behavior
- Resource cleanup

Requirements:

- Preserve trust boundaries during recovery.
- Prevent partial operations from appearing committed.
- Ensure cleanup occurs after failure.
- Define explicit behavior for partial results.

Acceptance criteria:

- Recovery tests demonstrate consistent state.
- No partial commit is silently accepted.
- Resource leaks are detected.

## NFR-RESILIENCY-002: Remote Session Isolation

Validate remote execution and collection failure scenarios.

Scenarios:

- SSH disconnect
- Proxy or tunnel failure
- Partial collector response
- Collector termination
- Retry after timeout
- PID reuse
- Stale session evidence
- Target reboot
- Build ID mismatch
- Resource exhaustion

Requirements:

- Isolate failed sessions.
- Prevent stale evidence from being associated with a new process.
- Preserve operation identity across retries.
- Distinguish transport failure from target-side failure.
- Clean up temporary resources.
- Never treat incomplete remote output as complete evidence.

Acceptance criteria:

- Session failures cannot contaminate unrelated investigations.
- Stale evidence is detected.
- Partial responses are explicitly represented.
- Retry behavior is deterministic and auditable.

---

# 14. NFR — Development Process

## NFR-PROCESS-001: Requirement Traceability

Every requirement must map to:

- Existing implementation or planned code change
- Actual runtime call path
- Regression test
- Verification command
- Verification result
- Relevant artifact or commit

Use the following status values:

- NOT_STARTED
- IN_PROGRESS
- IMPLEMENTED
- VERIFIED
- BLOCKED
- NOT_APPLICABLE

Do not mark a requirement VERIFIED based only on code inspection.

## NFR-PROCESS-002: Completion Reporting

Every implementation phase must provide:

1. Repository baseline SHA
2. Scope completed
3. Confirmed defects
4. Changes made
5. Files modified
6. Tests added
7. Test commands executed
8. Actual test results
9. Skipped tests and reasons
10. Remaining risks
11. Requirement traceability matrix
12. GO / NO-GO / PARTIAL verdict

A successful unit test run does not automatically prove full system correctness.

Do not claim complete verification if integration, architecture-specific, or remote tests remain unexecuted.

---

# 15. Architecture and Deployment Constraints

Preserve the existing product architecture unless a demonstrated defect requires a change.

Mandatory constraints:

- Embedded target collector remains lightweight.
- No Python, GDB, web server, or LLM dependency on the embedded target.
- Host-side DWARF analysis remains the primary analysis approach.
- Remote execution continues to use the existing external collection architecture.
- Existing xssh MCP functionality remains responsible for multi-hop SSH operations.
- eBPF remains optional.
- Do not introduce unnecessary daemon or IPC architecture.
- Do not introduce a new UI project.
- MCP and high-quality reports remain primary product interfaces.

Assume the collector and LLM operate inside the user's internal secure network, but do not treat this assumption as a reason to omit trust-boundary validation.

---

# 16. Traceability Alignment with Existing PRD

Use existing PRD requirement IDs wherever possible.

| This Specification | Existing PRD Mapping |
|---|---|
| FR-TRUST-001 | REQ-TRUST-001 |
| FR-TRUST-002 | REQ-TRUST-002 |
| FR-TRUST-003 | REQ-TRUST-003 |
| FR-TRUST-004 | REQ-TRUST-004 |
| FR-TRUST-005 | REQ-TRUST-005 |
| FR-TRUST-006 | Extension of trust/provenance requirements |
| FR-TRUST-007 | Extension of trust/lifecycle requirements |
| FR-DIAG-001 | REQ-DIAG-001 |
| FR-DIAG-002 | REQ-DIAG-002 |
| FR-DIAG-003 | REQ-DIAG-003 |
| FR-DIAG-004 | REQ-DIAG-004 |
| FR-CPP-001 | REQ-CPP-001 |
| FR-CPP-002 | REQ-CPP-002 |
| FR-TRACE-001 | REQ-TRACE-001 |
| FR-TRACE-002 | REQ-TRACE-002 |
| FR-BENCH-001 | REQ-BENCH-001 |
| FR-BENCH-002 | REQ-BENCH-002 |
| FR-BENCH-003 | REQ-BENCH-003 |
| FR-EXPLAIN-001 | REQ-MCP-002 and REQ-REPORT-001 |
| FR-REPORT-001 | REQ-REPORT-001 |
| FR-REPORT-002 | REQ-REPORT-002 |
| FR-REPORT-003 | REQ-REPORT-003 |
| FR-MCP-001 | REQ-MCP-001 |
| FR-MCP-002 | REQ-MCP-002 |
| FR-MCP-003 | REQ-MCP-003 |
| NFR-SECURITY-001 | REQ-TRUST-005 |
| NFR-PBT-001 | Validation strategy for REQ-TRUST-001 through REQ-TRUST-005 |
| NFR-RESILIENCY-001 | Existing resilience requirements and REQ-TRACE-001 where applicable |
| NFR-RESILIENCY-002 | Extension of remote execution and collection requirements |
| NFR-PROCESS-001 | Existing PRD process and traceability sections |

If the actual PRD contains different IDs or definitions, inspect it and reconcile the mapping explicitly. Do not invent requirement IDs or silently change existing definitions.

---

# 17. Implementation Priority

Follow this order.

## Phase 0 — Audit and Baseline

- Inspect latest repository state.
- Read PRD and current implementation reports.
- Map requirements to code and tests.
- Verify which defects remain reproducible.
- Establish a clean baseline.

Deliverable: Audit and Gap Analysis.

## Phase 1 — P0 Trust Closure

Implement and verify:

1. Operation identity validation
2. Replay identity completeness
3. Metadata monotonicity and conflict handling
4. Evidence Ledger admission boundary
5. TrustStore filesystem security
6. Evidence provenance integrity
7. Operation lifecycle integrity

Deliverable: P0 Trust Closure Report.

Do not proceed to P1 until P0 is verified.

## Phase 2 — Diagnostic Correctness

Implement only confirmed gaps in:

- Static location candidates
- Hypothesis invariants
- Adaptive investigation budgets
- Confidence and abstention

Deliverable: Diagnostic Correctness Report.

## Phase 3 — C++ and Optional Tracing

Verify:

- C++ decoder correctness
- x86_64 and AArch64 behavior
- eBPF lifecycle
- Trace evidence integration

Deliverable: Architecture and Tracing Verification Report.

## Phase 4 — Evaluation and Explanation

Verify:

- Benchmark reproducibility
- Diagnostic accuracy
- Performance evaluation
- Read-only LLM explanation

Deliverable: Evaluation and Explanation Report.

## Phase 5 — Reports, MCP, and Resilience

Verify:

- Report integrity
- MCP contract consistency
- Remote session isolation
- Failure recovery
- Resource cleanup

Deliverable: Final Product Verification Report.

---

# 18. Final Acceptance Criteria

The project can be declared GO only when:

1. All P0 requirements are VERIFIED.
2. Rejected evidence cannot influence diagnostic conclusions.
3. Replay protection uses complete operation identity.
4. TrustStore security checks are enforced.
5. Provenance is preserved through the complete evidence lifecycle.
6. Operation lifecycle and recovery behavior are consistent.
7. Diagnostic conclusions remain deterministic.
8. LLM explanation cannot mutate diagnostic results.
9. Benchmark results are attributable and reproducible.
10. Reports preserve evidence traceability.
11. MCP interfaces enforce the same trust and validation rules.
12. Critical regression and security tests pass.
13. No critical unresolved failure is hidden by a successful aggregate test count.

Use exactly one of:

- GO: All mandatory acceptance criteria verified.
- NO-GO: A critical requirement is violated.
- PARTIAL: Some requirements are verified, but mandatory verification remains incomplete.

A PARTIAL result must never be represented as GO.

---

# 19. Immediate Coding Agent Instructions

Start with Phase 0 only.

Do not immediately implement everything.

First:

1. Inspect the latest main branch.
2. Record the exact HEAD SHA and working tree status.
3. Read the current PRD and relevant reports.
4. Trace the seven P0 trust requirements through actual runtime call paths.
5. Identify existing implementations and tests.
6. Reproduce each suspected defect.
7. Create a requirement-to-code-to-test matrix.
8. Identify the smallest implementation sequence.
9. Report which requirements are already correctly implemented.
10. Report which requirements remain defective or unverified.

Then propose the P0 implementation plan.

Do not begin implementation until the audit establishes the actual remaining gaps.

The final audit must clearly distinguish:

- Implemented and verified
- Implemented but not verified
- Partially implemented
- Missing
- Defective
- Not applicable

Avoid duplicate implementation, unnecessary refactoring, unrelated UI work, and scope expansion.

The goal is not to maximize the number of changed files or tests.

The goal is to close the actual correctness and trust gaps with the smallest verifiable changes.


Repository:
https://github.com/zeeny2park/dynamicState

Baseline:
Always inspect the actual latest main HEAD before making changes.
Do not assume any previously reviewed commit is still current.

============================================================
MISSION
============================================================

Improve DynamicState remote diagnosis speed and reliability.

The current remote diagnosis implementation has experienced problems
including:

1. Excessively slow remote diagnosis.
2. Too many remote collection operations.
3. Repeated collection of the same or overlapping information.
4. Sequential collection that unnecessarily increases total latency.
5. Exceptions during remote collection causing excessive failure
   propagation or terminating the entire diagnosis.
6. Incomplete partial-result preservation.
7. Inefficient analysis and hypothesis re-evaluation.
8. Insufficient visibility into where diagnosis time is spent.
9. Deadline, retry, and checkpoint behavior potentially contributing
   to excessive latency.
10. A remote collection architecture that can unnecessarily dominate
    overall diagnosis duration.

The goal is not simply to make SSH faster.

The goal is to reduce remote dependency, reduce unnecessary collection,
perform more analysis using already available evidence, improve
collection efficiency, isolate failures, and preserve useful results.

Implement the improvements. Do not stop after producing a review,
proposal, roadmap, or design document.

============================================================
CORE DESIGN PRINCIPLES
============================================================

A. Remote collection must not own the entire diagnosis lifecycle.

B. A collection failure must not automatically terminate diagnosis.

C. Every remote operation must have an explicit result state.

D. Evidence must be reused when it is valid.

E. Remote collection must be driven by evidence gaps.

F. Independent operations may run concurrently with bounded resource usage.

G. Dependent operations must respect their dependency graph.

H. Local analysis must continue when remote collection is unavailable,
   provided the remaining evidence supports meaningful analysis.

I. The diagnosis must not invent missing evidence or convert collection
   failure into healthy or abnormal evidence.

J. Security and target identity violations must remain fail-closed.

K. No feature should sacrifice correctness or target safety for speed.

L. Preserve existing MCP contracts and compatibility wherever possible.

M. Avoid unnecessary architectural rewrites.

============================================================
PHASE 0 — REPOSITORY AND PERFORMANCE BASELINE
============================================================

Inspect the actual latest HEAD.

Review the complete remote diagnosis call paths, including but not
limited to:

- extractor/expert_diagnostic_engine.py
- extractor/target_adapter.py
- extractor/web/diagnose_jobs.py
- Remote collection providers
- Collection recipes
- Investigation planner
- Hypothesis engine
- Evidence ledger
- Evidence normalization
- Correlation and source analysis
- Checkpoint and recovery
- MCP diagnosis tools
- Benchmark code
- Relevant tests

Do not assume the above list is complete.

Trace the execution from a diagnosis request through:

1. Job creation
2. Session initialization
3. Plan construction
4. Recipe selection
5. Remote collection
6. Evidence admission
7. Evidence normalization
8. Analysis
9. Hypothesis evaluation
10. Replanning
11. Conclusion
12. Report generation
13. Persistence

Identify actual bottlenecks using source code, execution traces,
instrumentation, and benchmarks.

Do not optimize based on assumptions alone.

============================================================
PHASE 1 — ESTABLISH A TRUSTWORTHY PERFORMANCE BASELINE
============================================================

Before making performance changes, measure the existing implementation.

Instrument the diagnosis pipeline.

Measure:

- Total diagnosis wall-clock duration
- Plan generation duration
- Local analysis duration
- Remote connection establishment
- SSH command execution
- Remote command duration
- Retry duration
- Collection duration per recipe
- Collection duration per evidence type
- Evidence normalization duration
- Correlation duration
- Hypothesis evaluation duration
- Replanning duration
- Checkpoint duration
- Report generation duration

Measure remote costs:

- Number of SSH commands
- Number of SSH connections
- Number of ControlMaster reconnects
- Number of retries
- Remote bytes transferred
- Local bytes processed
- Number of collection operations
- Number of duplicate or reusable observations
- Target impact where measurable

Measure investigation efficiency:

- Number of recipes planned
- Number of recipes executed
- Number of recipes skipped
- Number of failed recipes
- Number of remote calls avoided
- Evidence reuse ratio
- Time spent collecting evidence
- Time spent analyzing evidence
- Number of hypotheses
- Number of hypotheses eliminated
- Number of replans

Use monotonic clocks for durations.

Ensure measurement instrumentation does not significantly alter
diagnosis performance.

Establish reproducible benchmark scenarios:

1. Healthy target
2. CPU overload
3. Memory pressure
4. Process lifecycle anomaly
5. Thread anomaly
6. Deadlock
7. Remote connection failure
8. Partial permission failure
9. Slow remote operation
10. Intermittent command failure
11. Large process/thread target
12. Target with many file descriptors
13. Evidence already available from a prior observation
14. Diagnosis with minimal evidence
15. Diagnosis with sufficient evidence for early stopping

Produce a baseline report containing actual numbers.

Do not invent baseline values.

============================================================
PHASE 2 — REMOTE COLLECTION FAILURE ISOLATION
============================================================

Audit every remote collection call and exception propagation path.

Determine which failures currently:

- Abort a recipe
- Abort a collection batch
- Abort the investigation
- Abort report generation
- Cause session state corruption
- Lose partial evidence
- Produce misleading conclusions

Introduce or improve a typed collection result model if an equivalent
implementation does not already exist.

Collection results must distinguish:

- SUCCESS
- EMPTY
- PARTIAL
- TIMEOUT
- UNAVAILABLE
- UNSUPPORTED
- PERMISSION_DENIED
- INVALID_DATA
- FAILED
- CANCELLED

A result should preserve, where appropriate:

- Collection identifier
- Target identity
- PID / TID
- Collection source
- Operation identifier
- Started timestamp
- Completed timestamp
- Duration
- Status
- Error classification
- Error details
- Data
- Completeness
- Provenance
- Observation time/window
- Retry count
- Data validity
- Partial-result status

Do not confuse:

- Empty data
- Missing data
- Unsupported operation
- Permission failure
- Timeout
- Remote disconnect
- Parsing failure
- Invalid evidence
- Cancelled operation

Each failure must affect only the smallest safe scope.

Expected failure isolation hierarchy:

Remote operation failure
    -> affected operation

Collection batch failure
    -> affected batch members only

Recipe failure
    -> affected recipe/check only

Analysis failure
    -> affected analysis node only

Hypothesis evaluation failure
    -> affected hypothesis evaluation only

Target identity/security violation
    -> fail-closed for affected operation/session

Global cancellation
    -> stop new work and finalize cancellation

Global deadline
    -> stop new work and finalize deadline exhaustion

============================================================
PHASE 3 — PARTIAL EVIDENCE PRESERVATION
============================================================

Ensure remote collection can preserve partial evidence.

If a batch contains:

A = SUCCESS
B = SUCCESS
C = TIMEOUT
D = PERMISSION_DENIED
E = SUCCESS

Do not discard A, B, and E because C or D failed.

Ensure:

- Each collection has independent result status.
- Successful evidence is admitted independently.
- Failed collection metadata is retained.
- Partial evidence remains available for local analysis.
- Analysis continues where dependencies are satisfied.
- Failed evidence is never treated as successful evidence.
- Completeness is tracked.
- Conclusions explicitly account for missing evidence.
- Confidence does not increase because evidence was unavailable.
- Reports distinguish complete and partial diagnosis.

Do not use broad exception handling to silently return empty dictionaries,
lists, strings, or default values that imply successful collection.

============================================================
PHASE 4 — REMOTE COLLECTION COALESCING
============================================================

Inspect the existing recipes and remote collection methods.

Identify overlapping requests for:

- Process information
- Process status
- CPU information
- Memory information
- Thread information
- Thread state
- File descriptors
- Socket state
- Memory maps
- Runtime metadata
- Stack data
- Target identity
- Other relevant /proc or /sys data

Implement collection coalescing where it is safe and beneficial.

Instead of:

Recipe A -> SSH -> Process metadata
Recipe B -> SSH -> Process metadata
Recipe C -> SSH -> Process metadata
Recipe D -> SSH -> Thread metadata

Prefer:

Collection planner
    |
    v
Shared observation requirements
    |
    v
Coalesced remote collection
    |
    +-- Process metadata
    +-- Thread metadata
    +-- Memory metadata
    +-- Other required data
    |
    v
Evidence repository
    |
    +-- Recipe A
    +-- Recipe B
    +-- Recipe C
    +-- Recipe D

Requirements:

- Do not collect everything unconditionally.
- Do not increase target impact.
- Do not make one large fragile command where a failure loses all data.
- Prefer independently parseable collection sections.
- A failed section must not invalidate successful sections.
- Preserve provenance for each data section.
- Reuse valid observations.
- Prevent duplicate remote operations within the same observation window.
- Support targeted follow-up collection.
- Preserve target identity and evidence trust requirements.

============================================================
PHASE 5 — EVIDENCE REUSE AND OBSERVATION CACHE
============================================================

Inspect existing evidence storage before introducing new cache structures.

Implement reuse of existing evidence wherever possible.

Use an observation identity based on the necessary dimensions, such as:

- Target identity
- Process identity
- PID / TID
- Collection type
- Observation time/window
- Data schema
- Source
- Collection parameters

Do not use PID alone as an identity.

Evidence reuse must respect:

- Target identity
- PID reuse
- Process lifecycle
- Target boot/session changes
- Evidence freshness
- Observation consistency
- Data validity
- Source trust
- Collection parameters
- Schema compatibility

Use explicit freshness policies per evidence type.

Avoid reusing stale dynamic evidence.

Reuse static or slowly changing information when its validity can
be established.

Do not create an unrestricted global cache.

Cache lifetime and invalidation must be bounded and explicit.

Measure:

- Cache hits
- Cache misses
- Reuse rate
- Remote operations avoided
- Stale-data rejection rate
- Performance improvement

============================================================
PHASE 6 — LOCAL-FIRST EVIDENCE INVESTIGATION
========================================================================

Change the investigation strategy so remote collection is not the
automatic first action for every recipe.

Preferred flow:

1. Inventory currently available evidence.
2. Validate target and evidence identity.
3. Check freshness and completeness.
4. Perform local analysis.
5. Identify unresolved hypotheses.
6. Identify missing evidence.
7. Determine which missing evidence can distinguish hypotheses.
8. Select the smallest necessary collection set.
9. Execute targeted remote collection.
10. Analyze new evidence.
11. Re-evaluate hypotheses.
12. Stop when sufficient, budget exhausted, or further investigation
    has insufficient expected value.

Do not run remote collection merely because a recipe exists.

Implement an explicit evidence-gap decision.

Every proposed collection should have a reason, such as:

- Required by a hypothesis
- Distinguishes competing hypotheses
- Resolves contradictory evidence
- Validates a candidate root cause
- Improves confidence
- Required for a safety or identity check

When no useful collection remains:

- Stop.
- Produce the best supported result.
- Return INCONCLUSIVE when evidence is insufficient.

============================================================
PHASE 7 — ADAPTIVE COLLECTION PRIORITIZATION
============================================================

Improve investigation planning using the evidence already available.

Prioritize collection by:

- Expected information value
- Ability to distinguish hypotheses
- Evidence strength
- Missing dependency
- Collection cost
- Remote latency
- Target impact
- Remaining time budget
- Safety
- Confidence improvement

Avoid expensive collection that is unlikely to change the conclusion.

Do not introduce an unnecessarily complex probabilistic framework.

A deterministic, explainable scoring or decision mechanism is preferred
if it achieves the objective.

Collection planner must expose the reason a collection was selected.

Implement early stopping when:

- A root cause is adequately supported.
- Competing hypotheses are sufficiently eliminated.
- Additional evidence has low expected value.
- The target or remote transport is no longer available.
- The budget is exhausted.
- Additional collection could unnecessarily impact the target.

Do not stop merely because a confidence threshold was reached if
contradicting evidence remains unresolved.

============================================================
PHASE 8 — DEPENDENCY-AWARE EXECUTION
========================================================================

Audit the current recipe dependency graph.

Classify operations:

A. Independent local analysis
B. Independent remote collection
C. Remote collection dependent on previous evidence
D. Analysis dependent on other analysis
E. Final conclusion/report operations

Implement bounded parallel execution for independent operations
where beneficial.

Do not parallelize blindly.

Ensure:

- Explicit dependencies
- Bounded concurrency
- Per-target concurrency limit
- Per-transport concurrency limit
- Per-operation timeout
- Overall deadline
- Cancellation propagation
- No duplicate collection
- Deterministic evidence admission
- Thread safety
- No unsafe shared mutable session state
- Correct transaction isolation
- Target impact controls

Use the existing transport architecture.

Do not introduce new dependencies without a compelling reason.

Prefer lightweight implementation suitable for embedded-target
diagnosis where the target cannot run additional services.

============================================================
PHASE 9 — REMOTE COMMAND EFFICIENCY
============================================================

Review the SSH implementation and optimize actual bottlenecks.

Inspect:

- SSH command construction
- Connection establishment
- ControlMaster reuse
- Control socket lifecycle
- Connection retries
- Timeout handling
- Command serialization
- Remote shell startup overhead
- Output transfer
- Parsing overhead
- Command logging
- Command duplication

Consider and implement only improvements justified by measurements:

- Connection reuse
- Command coalescing
- Batch collection
- Targeted command execution
- Reduced payload
- Efficient parsing
- Bounded concurrency
- Retry elimination
- Avoiding redundant SSH sessions
- Better timeout allocation
- Reduced shell startup overhead

Do not introduce an always-running target daemon.

Do not require new target packages.

Do not add target-side Python.

Do not make target modifications to accelerate diagnosis.

Keep remote collection low-impact.

============================================================
PHASE 10 — INCREMENTAL LOCAL ANALYSIS
============================================================

Review whether analysis is unnecessarily repeated after each evidence
addition or collection step.

Identify reusable analysis products:

- Parsed evidence
- Process mapping
- Thread mapping
- Memory mapping
- Object reconstruction
- Source correlation
- Hypothesis evaluations
- Diagnostic check results

Implement incremental recomputation where safe.

Use dependency tracking and invalidation.

When evidence changes, recompute only affected analysis nodes.

Requirements:

- Correct invalidation
- No stale results
- Deterministic output
- Safe recovery
- Correct provenance
- No cross-target contamination

Retain a full recomputation path as a correctness reference.

Add tests comparing incremental and full recomputation.

Do not implement an elaborate framework if simple memoization and
dependency invalidation are sufficient.

============================================================
PHASE 11 — ANALYSIS PERFORMANCE
============================================================

Identify expensive local analysis.

Review:

- Repeated parsing
- Repeated source lookup
- Repeated symbol lookup
- Repeated memory map traversal
- Duplicate evidence correlation
- Excessive deep copies
- Serialization overhead
- Large session rewrites
- Quadratic algorithms
- Inefficient graph traversal
- Repeated hypothesis evaluation
- Excessive report generation work

Optimize only measured bottlenecks.

Where possible:

- Reuse immutable parsed data.
- Use indexes.
- Avoid repeated normalization.
- Reduce unnecessary copies.
- Use efficient lookup structures.
- Cache deterministic computations.
- Avoid full-session serialization during every small update.
- Preserve durability guarantees.
- Preserve trust and provenance guarantees.

Do not weaken persistence or evidence integrity for speed.

============================================================
PHASE 12 — EXCEPTION AND FAILURE TAXONOMY
============================================================

Review every broad exception handler in the diagnosis path.

Especially inspect patterns like:

try:
    operation()
except Exception:
    pass

and:

try:
    result = operation()
except Exception:
    result = {}

Replace silent failure with structured error recording.

Use a common error classification where appropriate.

Ensure errors are visible in:

- Investigation state
- Timeline
- Diagnostic checks
- Evidence completeness
- Final report
- MCP result

Avoid flooding the report with duplicate errors.

Preserve original exception type and relevant context.

Do not expose secrets, credentials, private keys, command-line secrets,
or sensitive environment values in error reports.

============================================================
PHASE 13 — CHECKPOINT, DEADLINE, CANCELLATION
========================================================================

Verify the latest resilience implementation.

Checkpoint:

- Do not report success after failed persistence.
- Preserve last successful checkpoint time.
- Expose checkpoint degradation.
- Avoid expensive repeated full-session writes.
- Preserve recovery integrity.

Deadline:

- All remote operations must respect remaining time.
- Retry must consume the same overall budget.
- No new collection after deadline.
- Local analysis should continue if it is still safe and budget allows.
- Deadline exhaustion must not silently become normal completion.

Cancellation:

- Stop new collection.
- Interrupt active operations where possible.
- Preserve valid collected evidence.
- Complete safe local analysis if policy permits.
- Generate partial report.
- Use explicit CANCELLED / PARTIAL status.
- Prevent normal SUCCESS after cancellation.

Circuit breaker:

- Use structured error classification.
- Avoid false triggers.
- Avoid unnecessary retries.
- Preserve collected evidence.
- Record why collection was stopped.

============================================================
PHASE 14 — TESTING
========================================================================

Add deterministic tests for:

REMOTE COLLECTION

- Successful collection
- Empty collection
- Partial batch success
- One member of a batch failing
- Multiple independent failures
- Timeout
- Permission failure
- Unsupported command
- Malformed output
- Remote disconnect
- Target exit
- PID reuse
- Stale evidence
- Target identity change

FAULT TOLERANCE

- Recipe exception
- Parsing exception
- Correlation exception
- Analysis exception
- Hypothesis evaluation exception
- Report generation exception
- Checkpoint failure
- Disk full
- Recovery after partial state
- Cancellation race
- Deadline during remote operation
- Deadline during retry
- Circuit breaker threshold
- Circuit breaker recovery

PERFORMANCE

- Remote call count
- Duplicate collection elimination
- Evidence reuse
- Batch collection
- Local analysis reuse
- Bounded concurrency
- Large target
- Large thread count
- Large FD count
- Slow SSH
- No SSH available
- Warm evidence
- Cold evidence

CORRECTNESS

- Partial evidence never treated as complete.
- Missing evidence never treated as healthy.
- Failure does not increase confidence.
- Evidence provenance is preserved.
- Incremental analysis matches full analysis.
- Parallel analysis matches deterministic serial analysis
  where results are expected to be equivalent.
- No cross-target evidence contamination.
- No unsafe target-side impact.

Use deterministic synchronization, mocked time, and barriers.
Avoid arbitrary sleep-based tests.

============================================================
PHASE 15 — PERFORMANCE COMPARISON
============================================================

Run the baseline scenarios again after implementation.

Compare before and after:

- Total diagnosis duration
- Median duration
- P95 duration
- Remote command count
- SSH connection count
- Retry count
- Remote bytes
- Local analysis time
- Evidence reuse ratio
- Collection failures
- Partial diagnosis success rate
- Root-cause accuracy
- False positive rate
- False negative rate
- Target impact

Report actual numbers.

Do not claim speedup without comparable runs.

Use repeated runs where appropriate.

Separate:

- Cold start
- Warm connection
- Warm evidence
- Target complexity
- Remote latency
- Local analysis

Do not optimize only for a small local test target.

Validate against realistic C/C++ target scenarios.

Performance goals should be derived from actual baseline measurements.

Prefer reducing unnecessary remote work over increasing concurrency
or target load.

============================================================
PHASE 16 — MCP AND REPORTING
============================================================

Preserve existing MCP interfaces unless changes are necessary.

Ensure diagnosis results clearly expose:

- Complete or partial
- Remote collection status
- Collection failures
- Evidence completeness
- Checkpoint status
- Deadline status
- Cancellation status
- Diagnosis duration
- Remote collection duration
- Local analysis duration
- Number of remote operations
- Number of retries
- Number of reused observations
- Root cause confidence
- Missing evidence
- Remaining investigation opportunities

Do not overload the report with implementation details.

Provide a concise summary and a detailed technical evidence section.

============================================================
PHASE 17 — DOCUMENTATION
============================================================

Update the existing authoritative documentation.

Do not create redundant documents.

Document:

- Current remote collection architecture
- Collection failure isolation
- Evidence reuse
- Collection batching
- Adaptive investigation
- Concurrency limits
- Deadline behavior
- Cancellation semantics
- Checkpoint behavior
- Benchmark methodology
- Before/after results
- Target impact
- Known limitations

Update PRD acceptance criteria if necessary.

============================================================
ACCEPTANCE CRITERIA
============================================================

The phase is complete only when:

[ ] Latest repository state was inspected.
[ ] Actual bottlenecks were identified.
[ ] Baseline performance was measured.
[ ] Remote collection failures no longer unnecessarily abort diagnosis.
[ ] Partial evidence is preserved.
[ ] Evidence reuse is implemented where valid.
[ ] Duplicate remote operations are reduced.
[ ] Remote command coalescing is implemented where beneficial.
[ ] Local analysis is performed before unnecessary remote collection.
[ ] Collection is driven by evidence gaps.
[ ] Independent operations use safe bounded concurrency where beneficial.
[ ] Dependent operations respect their dependency graph.
[ ] Incremental analysis is implemented where justified.
[ ] Deadline and retry budgets are correct.
[ ] Cancellation semantics are correct.
[ ] Checkpoint failure is visible and recoverable.
[ ] Circuit breaker behavior is correct.
[ ] Security and provenance remain intact.
[ ] Diagnostic accuracy has not regressed.
[ ] Before/after benchmark results are available.
[ ] Relevant regression tests pass.
[ ] Full CI is verified against the final SHA.
[ ] Documentation reflects actual implementation.
[ ] Working tree is clean.

============================================================
IMPLEMENTATION RULES
============================================================

- Do not stop at analysis.
- Do not stop at a design proposal.
- Implement the actual changes.
- Do not reimplement existing capabilities.
- Do not add unrelated features.
- Do not weaken tests.
- Do not silently convert exceptions into success.
- Do not compromise evidence integrity.
- Do not increase target impact unnecessarily.
- Do not introduce target-side daemons or new dependencies.
- Prefer small, cohesive changes.
- Preserve backward compatibility where practical.
- Fix root causes instead of adding defensive layers blindly.
- Run focused tests after each logical change.
- Run the full relevant test suite before completion.

If an improvement is already implemented, verify it and avoid duplication.

If a requested optimization is not justified by measurements,
do not implement it merely to satisfy the checklist.

============================================================
FINAL REPORT
============================================================

Create or update the appropriate existing phase report.

Include:

1. Executive summary
2. Baseline SHA
3. Final SHA
4. Actual bottlenecks
5. Root causes of slow diagnosis
6. Root causes of diagnosis cancellation/failure
7. Changes implemented
8. Files changed
9. Call paths
10. Collection architecture before/after
11. Evidence reuse implementation
12. Batch collection implementation
13. Parallel execution implementation
14. Incremental analysis implementation
15. Exception isolation behavior
16. Cancellation and deadline behavior
17. Tests added
18. Tests executed
19. Test counts and actual results
20. CI links
21. Before/after performance table
22. Diagnosis accuracy comparison
23. Target impact analysis
24. Remaining limitations
25. GO / NO-GO decision

Performance table:

Metric                    Before       After        Improvement
----------------------------------------------------------------
Total diagnosis time
Remote collection time
Local analysis time
SSH command count
SSH connection count
Retry count
Transferred bytes
Evidence reuse rate
Collection failure rate
Partial diagnosis rate
Root cause accuracy
Target impact

Use real measured values only.

If performance improvement cannot be demonstrated, state why.

Do not claim GO unless the correctness, reliability, performance,
and regression acceptance criteria are supported by evidence.

============================================================
FINAL EXECUTION DIRECTIVE
============================================================

Execute this phase as a performance and reliability engineering task,
not as a feature development task.

The primary objective is:

Reduce diagnosis time by reducing unnecessary remote collection,
improving evidence reuse, optimizing local analysis, and executing
independent work efficiently.

The secondary objective is:

Ensure remote collection failures, individual recipe exceptions,
partial data, and analysis failures do not unnecessarily terminate
the entire diagnosis.

Preserve security, evidence integrity, provenance, and target safety.

Finish implementation, verification, benchmark comparison, and reporting.


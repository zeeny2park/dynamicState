# Agent Runtime Protocol (ARP)

The **Agent Runtime Protocol (ARP)** defines the semantic contract between a Coding Agent and the dynamicState Runtime Engine.

---

## Architectural Principle

```text
    Coding Agent (Autonomous Reasoning Layer)
          │
          │ Agent Runtime Protocol (JSON-Serializable Semantic Contract)
          │ (Future MCP Server / CLI / Remote RPC / Python API)
          ▼
    AgentRuntime (Reference Implementation)
          │
          ▼
    RuntimeController
          │
          ├── Semantic Object Graph
          ├── Typed Mutation & State Restorer
          ├── Systematic State Explorer
          └── External Debug Image & Provenance
                 │
                 ▼
                GDB
                 │
                 ▼
         Production Binary
```

### Core Separation of Responsibilities

1. **Agent does NOT touch GDB commands, raw memory addresses, or DWARF internals.**  
   All communication uses semantic concepts: `Object`, `Field`, `State`, `MutationCandidate`, `Transition`, `Exploration`, `Evidence`, `Capability`.
2. **Deterministic & Transport-Agnostic**:  
   The protocol is defined via standard JSON schemas, ensuring it can be bound to local Python objects, a CLI JSON stream, or future Model Context Protocol (MCP) tool adapters without altering the core runtime engine.
3. **Strict Validation & Safety Boundary**:  
   Arbitrary memory writes, shell commands, GDB evaluations, and pointer fabrication are strictly rejected. Mutations can only be selected from validated `MutationCandidate` proposals.

---

## JSON Schemas

The protocol schemas are located in this directory:

- [`actions.schema.json`](actions.schema.json): Specification for agent action requests (`OBSERVE`, `SNAPSHOT`, `INSPECT_OBJECT`, `EXECUTE_TRANSITION`, etc.).
- [`results.schema.json`](results.schema.json): Standardized response envelope (`success`, `action`, `data`, `error`, `performance`).
- [`context.schema.json`](context.schema.json): Compact semantic state context (`AgentStateContext`).
- [`mutations.schema.json`](mutations.schema.json): Pre-validated and ranked mutation candidate structure (`AgentMutationCandidate`).

---

## Action Reference

| Action | Parameters | Description |
| :--- | :--- | :--- |
| `OBSERVE` | None | Returns compact `AgentStateContext` of the current stopped runtime state. |
| `SNAPSHOT` | `snapshot_id?` | Captures a persistent `RuntimeSnapshot` and returns its context. |
| `LIST_OBJECTS` | `snapshot_id?` | Lists reachable semantic objects (`object_id`, `type`, `storage`). |
| `INSPECT_OBJECT` | `object_id`, `snapshot_id?` | Returns detailed field values and object references for a semantic object. |
| `INSPECT_FIELD` | `object_id`, `field_path`, `snapshot_id?` | Inspects a single field, its DWARF type, current value, and mutability. |
| `LIST_MUTATION_CANDIDATES` | `snapshot_id?` | Returns ranked, type-checked `AgentMutationCandidate` options. |
| `CHECKPOINT` | `checkpoint_id?` | Creates a branch-safe process checkpoint (fork backend). |
| `RESTORE` | `checkpoint_id` | Restores the inferior process to an exact checkpoint state. |
| `EXECUTE_TRANSITION` | `candidate_id` or `candidate`, `timeout_ms?` | Restores parent, applies mutation, continues execution, captures child, and returns `AgentTransition` with semantic facts and evidence. |
| `INSPECT_TRANSITION` | `transition_id` | Retrieves structured facts, execution result, and evidence for a transition. |
| `INSPECT_STATE` | `state_id` | Retrieves indexed corpus state details and metadata. |
| `LIST_STATES` | None | Lists all discovered unique states in the state corpus. |
| `GET_CAPABILITIES` | None | Returns supported runtime, debug, and mutation capabilities. |
| `EXPLORE` | `max_steps?`, `timeout_ms?`, `max_states?` | Autonomous branch-safe state exploration loop returning `AgentExplorationResult`. |
| `STATE_HASH` | `snapshot_id?` | Computes or retrieves the SHA-256 semantic state hash. |
| `DETECT_INVARIANTS` | `snapshot_id?` | Deterministically identifies structural invariant candidates. |

---

## Structured Result & Error Codes

Every action returns an `AgentActionResult` envelope:

```json
{
  "success": true,
  "action": "INSPECT_OBJECT",
  "data": {
    "object_id": "obj_0001",
    "type": "Session",
    "storage": "heap",
    "fields": [
      { "name": "retry", "type": "uint32_t", "value": 2 },
      { "name": "state", "type": "SessionState", "value": "CONNECTED" }
    ]
  },
  "error": null,
  "performance": { "total_ms": 0.42 }
}
```

When `success` is `false`, `error` contains one of the standard error codes:

- `INVALID_OBJECT`, `INVALID_FIELD`, `INVALID_CANDIDATE`
- `SNAPSHOT_NOT_FOUND`, `STATE_NOT_FOUND`, `TRANSITION_NOT_FOUND`, `CHECKPOINT_NOT_FOUND`
- `MUTATION_REJECTED`, `TYPE_CONVERSION_ERROR`, `RANGE_ERROR`, `UNSUPPORTED_TYPE`
- `TIMEOUT`, `CRASHED`
- `CAPABILITY_UNSUPPORTED`, `SAFETY_LIMIT_REACHED`, `RUNTIME_NOT_STOPPED`
- `DEBUG_IMAGE_MISMATCH`, `RUNTIME_ERROR`

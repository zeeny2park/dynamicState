# Dynamic State Snapshot Consistency Model

## 1. Executive Summary

Dynamic State provides **ultra-fast runtime state capture** combined with **offline DWARF semantic reconstruction**.
This document defines the formal contract and consistency guarantees of a `RawRuntimeSnapshot` and its resulting `SemanticState`.

```
Target Process (Active)
       │
       │ SIGSTOP (confirmed)
       ▼
Process Stopped in Kernel
       │
       │ process_vm_readv (microseconds)
       ▼
Raw Physical Memory Copied
       │
       │ SIGCONT (immediate fail-open resume)
       ▼
Target Process Resumed & Continues Execution
       │
       ▼ [OFFLINE ANALYSIS]
DwarfRuntimeResolver + TypedMemoryReader
       │
       ▼
SemanticState (Real C++ Object Graph)
```

---

## 2. What a Dynamic State Snapshot Guarantees

1. **Process-Stopped Physical Memory Consistency (`PROCESS_STOPPED_MEMORY_SNAPSHOT`)**:
   - The memory buffers recorded in a `RawRuntimeSnapshot` represent the exact physical memory state of the target process while all threads in the thread group were suspended by the kernel.
   - No memory modifications occur while `process_vm_readv` copies memory pages.
   - Pointers read from memory point to addresses valid at that precise suspension instant.

2. **Immediate Fail-Open Resume Guarantee**:
   - The process stop duration is constrained strictly to the microsecond/millisecond duration required to copy targeted virtual memory ranges into pre-allocated buffers.
   - In all circumstances (success, timeout, exception, or cancellation), `SIGCONT` is guaranteed to be delivered to resume target execution immediately.
   - Heavy operations—such as ELF loading, DWARF compilation unit indexing, type resolution, graph traversal, cycle detection, state hashing, and UI rendering—are **never** executed while the target process is stopped.

3. **Authentic Provenance Without Data Fabrication (Zero Fabrication Policy)**:
   - Every decoded semantic value (`int`, `float`, pointer, enum) is read directly from bytes captured in the snapshot.
   - If an object or field points to an address range that was omitted from capture (e.g. partial capture mode or memory limit reached), the system explicitly records `status: "MEMORY_NOT_CAPTURED"` and `value: null`.
   - The system **never** fabricates zeros or synthetic placeholder values when memory was uncaptured.
   - Overall state status transparently escalates to `PARTIAL`.

4. **Deterministic Canonical Identity & Cycle Termination**:
   - Object identity is uniquely defined by `(runtime_address, canonical_type)`.
   - Multiple pointers pointing to the same instance (e.g., `A -> C`, `B -> C`) resolve to the exact same canonical `object_id`.
   - Cyclic reference structures (e.g., $A \leftrightarrow B$) terminate safely without infinite recursion.

5. **Strict Build ID and Binary Matching**:
   - The GNU Build ID (`.note.gnu.build-id`) of the captured process executable is checked against the external DWARF artifact.
   - If build IDs do not match, offline reconstruction rejects analysis with `SYMBOL_MISMATCH` unless explicitly overridden via `--allow-symbol-mismatch`.

---

## 3. What a Dynamic State Snapshot Does NOT Guarantee (Non-Guarantees)

1. **No Application-Level Transactional Consistency**:
   - `SIGSTOP` halts threads at arbitrary machine instruction boundaries (`RIP`/`PC`).
   - If multiple threads are cooperating to perform a multi-step logical invariant without synchronization (or midway through an atomic sequence), the snapshot will reflect whatever intermediate memory state existed when the signal took effect.
   - Dynamic State does **not** roll back or advance application-level business transactions.

2. **No Thread Synchronization State Guarantee**:
   - Mutexes, futexes, condition variables, and semaphores reflect their physical lock-word status at the instant of capture.
   - The snapshot does not predict or guarantee which thread would acquire a contended lock next upon resumption.

3. **Stack / Local Variable Reconstitution Requires Call-Frame Unwinding**:
   - While global and static variables and reachable heap objects are resolved authoritatively via link-time DIEs and typed pointer edges, stack frame local variables require architecture-specific register state unwinding (CFI / DWARF Call Frame Information).
   - If register state was not captured during suspension, local variables are reported as `REGISTER_STATE_UNAVAILABLE`.

4. **Uncaptured Memory is Inaccessible**:
   - Only address ranges captured in the `RawRuntimeSnapshot` buffers can be decoded.
   - Dynamic State deliberately refuses to communicate with the live process after the capture phase ends.

---

## 4. State Status Taxonomy

| Status | Definition |
| :--- | :--- |
| `COMPLETE` | All roots, members, and referenced heap objects were fully resolved within captured memory buffers. |
| `PARTIAL` | One or more referenced memory ranges were uncaptured or exceeded capture limits; missing fields are `null` with `MEMORY_NOT_CAPTURED`. |
| `SYMBOL_MISMATCH` | The snapshot binary GNU Build ID does not match the external DWARF debug artifact. |
| `LOAD_BIAS_UNRESOLVED` | The runtime memory mapping for a PIE binary could not be found in the snapshot maps, preventing safe link-to-runtime address translation. |
| `MEMORY_NOT_CAPTURED` | Specific field or pointed-to address range was omitted from the physical snapshot. |
| `REGISTER_STATE_UNAVAILABLE` | Thread execution registers were not captured, preventing stack frame analysis. |
| `UNRESOLVED` | No global or static variable roots were found in the debug artifact. |
| `SYNTHETIC` | Explicitly marked placeholder objects used only when synthetic fallback is requested. |
| `DECODE_ERROR` | Malformed DWARF or corrupted memory buffer encountered during offline decoding. |

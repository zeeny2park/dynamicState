# dynamicState — GDB Compatibility & Verification Matrix

## 1. Overview & Verification Taxonomy

Embedded and server development environments utilize a wide span of GDB releases—from legacy LTS releases (GDB 9.2 on Ubuntu 20.04 or Yocto Dunfell) to cutting-edge debuggers (GDB 14/15 on modern Linux distributions).

To prevent overclaiming and maintain strict technical honesty, dynamicState categorizes its compatibility claims under four rigorous verification levels:

| Verification Level | Definition |
| :--- | :--- |
| **DESIGN** | Feature is designed according to GDB Python API documentation and specifications. |
| **MOCK / UNIT VERIFIED** | Validated via Python unit test suite against mock GDB modules and synthesized failure modes. |
| **REAL GDB 9.2 VERIFIED** | Executed and asserted against genuine GNU gdb 9.2 binary (`Ubuntu 9.2-0ubuntu1~20.04.2`) in containerized integration test suite (`tests/integration_gdb92.py`). |
| **REAL TARGET VALIDATED** | Executed against real running Linux target processes with live memory extraction. |

---

## 2. GDB Version Compatibility Matrix

| GDB Version | Status / Verification Level | `Frame.level()` Handling | Version Parsing (`get_gdb_version`) | Stack & Object Traversal | External Debug Image |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **GDB < 9.0** | **UNSUPPORTED** | N/A | Returns `status="RESOLVED"`, marks incompatible | Unsupported | Unsupported |
| **GDB 9.2** | **REAL GDB 9.2 VERIFIED** | Missing; falls back to caller depth without `AttributeError` | `(9, 2, "9.2")`, `supports_frame_level()=False` | Verified (live frames, structs, pointers) | Verified (`.gnu_debuglink`, Build ID) |
| **GDB 10.x** | **UNIT TESTED** | Missing; falls back to caller depth | `(10, x, ...)`, `supports_frame_level()=False` | Designed & Unit Tested | Designed & Unit Tested |
| **GDB 11.x** | **UNIT TESTED** | Supported natively by GDB | `(11, x, ...)`, `supports_frame_level()=True` | Designed & Unit Tested | Designed & Unit Tested |
| **GDB 12 - 14** | **UNIT TESTED** | Supported natively | `(12..14, x, ...)`, `supports_frame_level()=True` | Designed & Unit Tested | Designed & Unit Tested |
| **GDB 15.1** | **REAL TARGET VALIDATED** | Supported natively | `(15, 1, "15.1")`, `supports_frame_level()=True` | Verified natively on Ubuntu 24.04 (host) | Verified natively |
| **Unknown / None** | **UNIT TESTED** | Conservative fallback | `status="UNKNOWN"`, `major=None`, `minor=None` | Safe degradation | Conservative |

---

## 3. Key Compatibility Mechanisms in `extractor/gdb_compat.py`

### 3.1. Elimination of Silent Version Fallback
Previous implementations silently defaulted missing GDB modules to `(9, 2, "9.2")`.
Under dynamicState's **Uncertainty-First** principle, unknown GDB environments return:
```python
GdbVersion(major=None, minor=None, raw="UNKNOWN", status="UNKNOWN")
```
No assumptions or guessed version numbers are ever injected.

### 3.2. `Frame.level()` Graceful Degradation
`gdb.Frame.level()` was only introduced in GDB 11.0. In GDB 9.2 and 10.x, invoking `frame.level()` raises:
```
AttributeError: 'gdb.Frame' object has no attribute 'level'
```
`get_frame_level(frame, fallback_level)` intercepts this condition:
```python
def get_frame_level(frame: Any, fallback_level: int = 0) -> int:
    if frame is None:
        return fallback_level
    if hasattr(frame, "level") and callable(getattr(frame, "level")):
        try:
            return int(frame.level())
        except Exception:
            pass
    return fallback_level
```
In `extractor/execution.py`, `current_level` is tracked during `.older()` traversal, guaranteeing accurate frame indices across all GDB versions.

---

## 4. Reproducing Real GDB 9.2 Verification

To execute the genuine GDB 9.2 verification test suite:

```bash
# 1. Build the GDB 9.2 verification container (Ubuntu 20.04 LTS)
docker build -t dynamicstate-gdb92:latest docker/gdb92

# 2. Run the integration test suite
docker run --rm -v $(pwd):/workspace dynamicstate-gdb92:latest python3 tests/integration_gdb92.py --direct
```

Expected output:
```
=== GDB 9.2 Verification Environment ===
GNU gdb (Ubuntu 9.2-0ubuntu1~20.04.2) 9.2
Python 3.8.10
=== Running dynamicState GDB 9.2 Integration Tests ===
_run_native_gdb92_verification (__main__.RealGdb92IntegrationTests)
Execute the real GDB 9.2 test scenario natively. ... REAL_GDB_9_2_VERIFICATION_PASS
ok
```

---

## 5. Multithread Checkpoint & Branch Isolation across GDB Versions

### 5.1. Ground Truth of GDB's Built-in Checkpoint Command
GDB's built-in `checkpoint` command relies on the OS `fork()` primitive.
In GDB source code (`gdb/linux-fork.c`):
```c
if (linux_fork_multiple_threads ())
  error (_("checkpoint: can't checkpoint multiple threads."));
```
Because Linux `fork()` duplicates only the calling thread, attempting to fork a multithreaded process drops all background threads, leaving mutexes held by those threads permanently deadlocked in the clone. This restriction exists identically across **GDB 9.2**, **GDB 12**, and **GDB 15**.

### 5.2. Verification Matrix for Multithread Branch Isolation

| Target Type | Restore Backend | GDB 9.2 (Docker) | GDB 15.1 (Host) | Branch Isolation Guarantee |
| :--- | :--- | :--- | :--- | :--- |
| **Single-Thread Process** | `GDB_CHECKPOINT` | Verified | Verified | Copy-on-Write fork clone per mutation branch |
| **Multithread Process (Launched)** | `RESTART` | Verified | Verified | Deterministic restart to observation breakpoint; all threads/TLS/mutexes clean |
| **Multithread Process (Attached)** | `NONE` | Verified | Verified | Explicitly `UNAVAILABLE`; reports safe alternatives to avoid non-isolated mutations |

### 5.3. Reproducing Multithread Verification in GDB 9.2 Container

```bash
docker run --rm -v $(pwd):/workspace -w /workspace dynamicstate-gdb92:latest python3 -m unittest tests/test_multithread_exploration.py
```
Expected output:
```
Ran 18 tests in ...
OK
```

---

## 6. Multithread Restart Determinism & Branch Isolation Architecture

### 6.1. The Principle of Restart-Based Checkpoint/Restore
In multithreaded Linux processes, GDB native `checkpoint` (which issues `fork()`) only duplicates the calling thread and deadlocks any mutex held by background threads. dynamicState resolves this through `RestartBasedRestorer`:
```text
Parent State (at predefined observation breakpoint)
      │
      ├── Branch A (Mutate -> Continue -> Child State A)
      │
      ├── restore() -> Process Restart -> Breakpoint Re-hit
      │                 ├── Inferior stopped validation
      │                 ├── Breakpoint location validation
      │                 └── Thread count validation
      │
      ├── Branch B (Mutate -> Continue -> Child State B)
      │
      └── restore() -> Process Restart -> Breakpoint Re-hit
                        │
                        ▼
            Parent State Reproducibility:
            hash(Parent) == hash(R1) == hash(R2)
            hash(A) != hash(Parent), hash(B) != hash(Parent), hash(A) != hash(B)
```

### 6.2. Pre-Exploration Determinism Verification
Before running autonomous exploration loops across sibling mutation branches, dynamicState verifies that process restarts produce identical semantic states:
- Parent snapshot is captured: `h_parent = compute_state_hash(snap_parent)`.
- A dry-run restart is performed: `restorer.restore(cp)`.
- Restored snapshot is captured: `h_restored = compute_state_hash(snap_restored)`.
- If `h_parent == h_restored`, status is marked `VERIFIED`.
- If hashes differ due to unmanaged external I/O, timestamps, or entropy, the runtime never fakes determinism; it marks the state `NON_DETERMINISTIC` with reason `RESTART_REPRODUCTION_FAILED` and provides field-level mismatch diffs. Under `safe` determinism policy, exploration safely halts with `NON_DETERMINISTIC_RUNTIME_STATE`.

### 6.3. Internal OS Synchronization Structure & Futex Filtering
Glibc condition variables (`pthread_cond_t`), mutexes (`pthread_mutex_t`), and cancellation buffers (`_condvar_cleanup_buffer`) maintain internal futex wait sequences (`wseq`, `__wseq`, `__g1_orig_size`, `__g_refs`, `__wrefs`). In multithreaded programs, OS kernel scheduler thread arrival order naturally causes these internal counters to increment or permute between executions, even when the user application state is 100% deterministic.
dynamicState filters internal synchronization types (`pthread_cond`, `pthread_mutex`, `condition_variable`, `std::mutex`) and internal scheduler metadata fields (`wseq`, `__futex`, `__g1_orig_size`, `__g_refs`, etc.) from semantic state hashing and diffing, ensuring state hashes reflect strictly user application semantics.

### 6.4. Attached vs. Launched Process Limitations
- **Launched Inferior (`run`)**: Full restart capability (`RESTART`). The target was launched under GDB control with known arguments and environment. Restoring to the parent observation breakpoint is fully supported.
- **Attached Inferior (`attach <pid>`)**: Cannot be re-executed via `run` (doing so would launch a separate binary rather than returning to the attached process context). Checkpoint restore is marked `NONE`, branch isolation is marked `UNAVAILABLE`, and the runtime provides safe alternative actions (`OBSERVE`, `SNAPSHOT`, `LIST_OBJECTS`, `INSPECT_OBJECT`, `LIST_MUTATION_CANDIDATES`).

### 6.5. Thread-Local Storage (TLS) Determinism
Each thread's `thread_local` variables (`t_thread_id`, `t_worker_state`, `t_worker_counter`) are inspected across all live threads (`verify_tls_determinism`). The restorer ensures that per-thread TLS states match exactly between parent and restored inferior runs.

### 6.6. Web UI & Agent API Visualization
- **Web UI Exploration Panel**: Displays real-time Checkpoint Backend (`GDB_CHECKPOINT` / `RESTART` / `NONE`), Checkpoint Semantics (`MEMORY_CHECKPOINT` / `RESTART_TO_OBSERVATION_POINT`), Thread Scope (`SINGLE_THREAD` / `MULTITHREAD`), Determinism Status (`VERIFIED` / `UNKNOWN` / `FAILED` / `NON_DETERMINISTIC`), and Branch Isolation (`SUPPORTED` / `CONDITIONAL` / `UNAVAILABLE`).
- **Interactive Verification**: Includes an interactive **"Verify Restart Determinism"** button (`/api/runtime/verify_determinism`) allowing human engineers and agents to test state reproducibility on demand before launching long-running state explorations.


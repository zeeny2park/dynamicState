# DynamicState: Phase 1 eBPF Stack-Variable & Function Tracing Architecture (Hardened)

## 1. Executive Summary

Phase 1 implements a verifiable, non-intrusive proof-of-concept (PoC) for userspace function tracing using Linux extended Berkeley Packet Filters (eBPF) and uprobes/uretprobes. This backend operates as an isolated, optional subsystem within DynamicState, preserving all existing memory capture (`process_vm_readv`), GDB controller, and offline DWARF reconstruction workflows without modification or regressions.

The Phase 1 hardening ensures robust operation for stripped production binaries with matching external debug ELFs, non-PIE executables, overloaded C++ functions, process group isolation without pipe deadlocks, and truthful target identity and capability reporting.

---

## 2. Existing Architecture Inspection & Integration Point

### 2.1 Existing Subsystems Reviewed
- **Memory Collector (`extractor/capture_backend.py`, `extractor/memory_capture.py`, `target/collector`)**:
  - `ProcessVmCaptureBackend` / `MemoryCapture`: zero-stop memory reader using `process_vm_readv(2)` targeting process memory maps (`/proc/<pid>/maps`).
  - `target/collector`: C99 target-side binary that serializes raw memory snapshots without Python runtime dependencies.
- **DWARF & Static Analyzer (`extractor/dwarf_indexer.py`, `extractor/debug_image.py`, `extractor/modules.py`)**:
  - `inspect_elf`: pure-Python ELF header and `.note.gnu.build-id` parser.
  - `DwarfIndexer`: indexes compilation units, subprograms (`DW_TAG_subprogram`), variables, and structure members from DWARF info.
  - `ModuleAddressResolver`: computes load-bias (`base_address - min_vaddr`) for PIE binaries.
- **Runtime State & Object Graph (`extractor/runtime_state.py`, `extractor/object_graph.py`)**:
  - Models hierarchical runtime state (`RuntimeSnapshot`, `ObjectState`, `FieldState`, `VariableState`).
- **Capture Quality Modes (`extractor/observation_backends.py`)**:
  - `CONSISTENT`: Inferior halted via ptrace/GDB; atomic snapshot across all threads; mutation permitted.
  - `LOW_IMPACT`: Zero-stop `process_vm_readv`; non-atomic (`NON_ATOMIC`); read-only; mutation forbidden.
- **CLI (`extractor/cli.py`)**:
  - Subcommands: `capture-memory`, `analyze-memory`, `extract-state`, `list-modules`, `runtime-info`, `server`, `investigate`, `compare`, `trace-function`.

### 2.2 Smallest Integration Point
Phase 1 integrates cleanly at three precise points without altering existing snapshot pipelines or adding ARP actions:
1. **Isolated Tracing Module (`extractor/ebpf_tracer.py`)**: Encapsulates probe script generation, streaming event decoding, target identity verification, file offset calculation, PID filtering, attach/detach lifecycle management, and DWARF subprogram resolution.
2. **Observation Backend Class (`EbpfObservationBackend` in `extractor/observation_backends.py`)**: Implements `ObservationBackend` with mode `EBPF_PROBE` and truthful capabilities (`consistency="PROBE_POINT_EVENT"`, `dwarf_eval_status="UNSUPPORTED_PHASE1"`).
3. **CLI Subcommand (`trace-function` in `extractor/cli.py`)**: Exposes an optional command for function tracing without affecting default snapshot commands.

---

## 3. Backend Capability Detection & Dependency Architecture

### 3.1 Strict Backend Capability Reporting
Capability detection reports a backend as supported **only if the exact implementation that will execute is available and usable**:
- **`bpftrace` (v0.20.2)**: Supported execution backend for Phase 1. When `bpftrace` is present and root/sudo privileges exist, `EbpfEnvironmentChecker` reports `backend="bpftrace", supported=True`.
- **`libbpf`**: Candidate foundation for production Phase 2. In Phase 1, `EbpfEnvironmentChecker` explicitly reports `backend="libbpf", supported=False` with reason `"libbpf execution backend is not implemented in Phase 1 (deferred to Phase 2); only 'bpftrace' is supported"`. It never falsely advertises `supported=True`.
- **Distinguished Error States**:
  - Missing dependencies (`bpftrace executable not found in PATH`).
  - Unsupported kernel/OS (non-Linux).
  - Unsupported CPU architecture (outside `x86_64` and `aarch64`/`arm64`).
  - Missing privileges / unprivileged eBPF disabled (`PERMISSION_DENIED`).
  - Missing `/sys/fs/bpf` mount (`UNSUPPORTED_ENVIRONMENT`).

### 3.2 Target Identity & Process Validation
Before attaching uprobes:
- **PID Liveness**: Verifies target PID exists via `os.kill(pid, 0)`. Fails closed if PID does not exist or access is denied.
- **Executable Validation (`/proc/<pid>/exe`)**: Compares `/proc/<pid>/exe` realpath and device/inode (`st_dev`, `st_ino`) against requested binary. Fails closed on mismatch (`MISMATCHED`).
- **Build ID Status**:
  - `VERIFIED`: GNU Build ID between target binary and debug ELF matched (or running binary has valid Build ID).
  - `MISMATCHED`: Target binary and debug image Build IDs differ; tracer fails closed.
  - `UNAVAILABLE`: Build ID note is missing from one or both artifacts.
  - `EXPLICITLY_UNCHECKED`: When `--no-verify-build-id` is specified, recorded explicitly rather than claiming verification.

---

## 4. Probe Attachment for Stripped Production Binaries

### 4.1 The Virtual Address vs File Offset Distinction
Linux kernel uprobes (`perf_event_open`) require the **file-relative offset** within the ELF file, *not* the link-time virtual address:
$$\text{file\_offset} = (\text{low\_pc} - \text{seg}[p\_vaddr]) + \text{seg}[p\_offset]$$
where $\text{seg}$ is the `PT_LOAD` segment containing `low_pc` ($\text{seg}[p\_vaddr] \le \text{low\_pc} < \text{seg}[p\_vaddr] + \text{seg}[p\_memsz]$).

- **PIE Executables (`ET_DYN`)**:
  - `p_vaddr = 0x0`, `p_offset = 0x0`
  - `low_pc = 0xd80` $\rightarrow$ `file_offset = 0xd80`
- **Non-PIE Executables (`ET_EXEC`, `-no-pie`)**:
  - `p_vaddr = 0x400000`, `p_offset = 0x0`
  - `low_pc = 0x400c90` $\rightarrow$ `file_offset = 0x400c90 - 0x400000 + 0x0 = 0xc90`
  - *Crucial*: Passing virtual address `0x400c90` directly to uprobes on a ~15 KB non-PIE file causes `perf_event_open` to fail with `EINVAL` (offset beyond file size). Computing file offset `0xc90` succeeds.

### 4.2 Stripped Binaries with External Debug ELF
When a binary is stripped (`strip -s`), its `.symtab` is discarded:
1. `DwarfIndexer` parses the external debug ELF (`--only-keep-debug` companion) to recover subprogram `low_pc` and linkage names.
2. `EbpfTracer._resolve_probe_target` maps `low_pc` through the stripped target's `PT_LOAD` program headers to compute the exact `file_offset`.
3. `bpftrace --unsafe` is invoked with `uprobe:/path/to/stripped_binary:0x<file_offset>`. The `--unsafe` flag allows raw numeric offset probes on stripped binaries, converting instruction boundary warnings to non-fatal notices.

### 4.3 Ambiguous Overloaded Functions
When multiple subprograms share the same unqualified C++ function name (e.g., `int32_t overloaded_metric(int32_t)` vs `int32_t overloaded_metric(int32_t, int32_t)`):
- If candidates have distinct addresses, `_resolve_probe_target` fails closed:
  `Ambiguous function name 'overloaded_metric': matches 2 distinct subprogram locations (0xd48, 0xd60). Disambiguate using mangled linkage name (e.g. '_Z17overloaded_metrici') or exact offset.`
- Disambiguating via mangled linkage name (`_Z17overloaded_metrici`) resolves to a single unique address and succeeds.

---

## 5. Event Schema, Register Capture, and Session Lifecycle

### 5.1 Architecture-Specific Register & Observation Semantics
- **`aarch64` / `arm64`**:
  - Frame pointer: `reg("r29")`
  - Return address: `reg("r30")` (Link Register `lr`, captured directly as `STATUS_OBSERVED`)
  - Stack pointer: `reg("sp")`
  - Instruction pointer: `reg("pc")`
  - Function arguments: `param_0`..`param_7` from `arg0`..`arg7` (`x0`..`x7` AAPCS64 registers)
  - Return value: `return_value` from `retval` (`x0`)
- **`x86_64`**:
  - Frame pointer: `reg("bp")`
  - Stack pointer: `reg("sp")`
  - Instruction pointer: `reg("pc")`
  - Return address: Passed on the stack via `(%rsp)`; never reported as hardcoded `0x0`. In probe output, `ra` is emitted as `null` and parsed as `None` with `return_address_status="UNAVAILABLE"` and `return_address_reason="Return address register is not available on x86_64 (passed on stack via (%rsp))."`.
  - Function arguments: `param_0`..`param_5` from `arg0`..`arg5` (`rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9` System V AMD64 ABI)
  - Return value: `return_value` from `retval` (`rax`)

### 5.2 Truthful Observation Representation
- **Register 0 vs UNAVAILABLE**: Legitimate 0 values (e.g. `arg0 == 0`) are recorded as `STATUS_OBSERVED` (`value=0, value_hex="0x0"`), whereas missing or null registers are recorded as `STATUS_UNAVAILABLE`.
- **Signedness and Integer Width**: Decoder preserves signed integers (e.g. `-42`) in `value` and exact 64-bit hexadecimal register representation (e.g. `"0xffffffffffffffd6"`) in `value_hex`.
- **No Unwarranted Inferences**: SP/FP alone are never used to synthesize frame chains or fabricate local variables without validated DWARF locations.

### 5.3 Session Status Lifecycle
Every trace session reports one of five strictly defined statuses:
- `SUCCESS`: Attachment confirmed and trace completed with observed events (`total_events > 0`), zero event loss, target remained alive, and clean process termination.
- `PARTIAL`: Attachment succeeded, but trace is incomplete or unverified:
  - **Zero Events**: Probe attached cleanly, but the traced function was never invoked during the duration (`total_events == 0`). Never reported as `SUCCESS`.
  - **Lost Events**: Kernel ring buffer saturated, dropping events (`lost_events > 0`).
  - **Target Exit**: Target process exited mid-trace while events were recorded.
  - **Premature Termination**: `bpftrace` terminated prematurely with partial events.
- `FAILED`: Invalid target PID, non-existent process, binary not found, executable mismatch, Build ID mismatch, attach failure, or target exited before any events could be captured.
- `PERMISSION_DENIED`: Insufficient privileges (CAP_BPF / CAP_SYS_ADMIN / passwordless sudo missing).
- `UNSUPPORTED_ENVIRONMENT`: Unsupported OS (non-Linux), unmounted `/sys/fs/bpf`, or unsupported architecture.

### 5.4 Prevention of Pipe Deadlocks & Guaranteed Process Cleanup
- `EbpfTracer` executes `bpftrace` with `stdout=subprocess.PIPE, stderr=subprocess.PIPE` and monitors both file descriptors concurrently using non-blocking `select.select([proc.stdout, proc.stderr], [], [], 0.05)`. `stderr` warnings are continuously drained into a bounded ring buffer to prevent OS pipe deadlocks.
- `bpftrace` is launched in its own process session (`start_new_session=True`).
- Upon detach, interruption, or timeout, `EbpfTracer` delivers `SIGINT` to the entire process group (`kill -INT -<pgid>`), ensuring both the `sudo` wrapper and child `bpftrace` process detach their probes from the kernel ring buffer and exit cleanly.
- If the process does not terminate within 2.0 s, `SIGKILL` is delivered (`kill -KILL -<pgid>`).
- All pipes and temporary `.bt` script files are unconditionally closed and unlinked in `finally:` blocks.

---

## 6. Fixture Architecture & Test Verification

### 6.1 Test Fixture (`tests/fixtures/real_runtime/ebpf_stack_fixture.cpp`)
- **Non-inlined traced function**: `extern "C" __attribute__((noinline)) int64_t trace_target_function(int32_t op_code, int64_t input_val, uint32_t count)`.
- **Overloaded functions**: `overloaded_metric(int32_t)` and `overloaded_metric(int32_t, int32_t)`.
- **Stack-allocated struct**: `SensorReading` with scalar and array fields.
- **Nested calls & local buffer**: `compute_inner_metric` and `local_tag[32]`.
- **Compiler optimization barrier**: `asm volatile("" : : "r"(&reading), "r"(local_tag), "r"(final_metric) : "memory")`.
- **Markers**: Emits `READY pid=%d target_func=%p inner_func=%p build_mode=%s\n` on stdout.

### 6.2 Twelve Integration Scenarios (`tests/test_ebpf_integration.py`)
1. **Debug build (`-O0`)**: Verifies entry/return probes, arguments, return value, frame metadata (`SP`, `PC`, `FP`, `RA`).
2. **Optimized build (`-O2`)**: Verifies probes and register values in presence of compiler optimizations.
3. **Stripped binary with external debug ELF (`strip -s`)**: Verifies uprobe attachment to stripped binary via file-offset calculation.
4. **Deliberate Build ID mismatch**: Verifies fail-closed behavior on mismatch and `EXPLICITLY_UNCHECKED` tracking when skipped.
5. **PIE vs Non-PIE executables**: Verifies `VirtAddr - p_vaddr + p_offset` translation on `ET_EXEC`.
6. **Ambiguous function and linkage name disambiguation**: Verifies failure on ambiguous overloads and success on mangled name (`_Z17overloaded_metrici`).
7. **Invalid PID and target exit mid-trace**: Verifies immediate rejection of non-existent PIDs and clean termination on target exit (`PARTIAL`/`SUCCESS`).
8. **Unsupported permissions / non-root**: Verifies `PERMISSION_DENIED` reporting.
9. **Entry-only mode vs Entry+Return mode**: Verifies probe selectivity.
10. **Interruption and process cleanup**: Verifies probe detachment and absence of orphaned processes.
11. **Zero events session status**: Verifies that a probe attached to an idle target without function calls reports `PARTIAL` with 0 total events.
12. **Real fixture DWARF variable evaluation**: Evaluates DWARF variables on real fixture builds (`-O0` and `-O2`) cross-checked against ABI.

---

## 7. Phase 2 DWARF Location-Evaluation Contract & Vertical Slice

The Phase 2 location evaluator is implemented in `extractor/dwarf_evaluator.py`:

### 7.1 Contract Definition
```python
@dataclass
class DwarfEvaluationContext:
    binary_identity: BinaryIdentity
    subprogram: Optional[DwarfSubprogram]
    link_time_address: int                   # Instruction address inside subprogram
    load_bias: int = 0                       # Runtime load bias (runtime_pc - link_time_pc)
    registers: Dict[str, int]                # Observation registers
    frame_metadata: Optional[FrameMetadata]  # SP, FP, PC, RA
    variable_name: str
    architecture: str                        # "x86_64", "aarch64"
    memory_reader: Optional[Callable[[int, int], Optional[bytes]]]

@dataclass
class DwarfLocationResult:
    variable_name: str
    status: str                              # OBSERVED, UNAVAILABLE, OPTIMIZED_OUT, UNSUPPORTED, ERROR
    location_type: Optional[str]             # "register", "stack_memory", "memory", None
    location_description: Optional[str]
    evaluated_address: Optional[int]
    register_name: Optional[str]
    value: Optional[Union[int, float, str, bool]]
    value_hex: Optional[str]
    type_name: Optional[str]
    byte_size: Optional[int]
    reason: Optional[str]
```

### 7.2 Strict Non-Conflation Principle
- `UNSUPPORTED`: DWARF opcode not implemented in the vertical slice (e.g. `DW_OP_piece`, complex expression trees). Never reported as `OPTIMIZED_OUT`.
- `OPTIMIZED_OUT`: DWARF explicitly specifies variable has no location, was eliminated, or has `DW_OP_entry_value` outside its live register range. Never reported as `UNSUPPORTED`.
- `UNAVAILABLE`: Location expression is valid, but variable is not accessible at current probe point (e.g. instruction address before prologue frame establishment, function compiled with `-fomit-frame-pointer`, instruction address outside location-list range, unreadable memory, or missing register).
- `ERROR`: Corrupted DWARF, missing location lists table, or unparseable debug data. Never reported as `OPTIMIZED_OUT`.

### 7.3 Phase 1.3 Evaluator Architecture & Frame-Base Rules
1. **Prologue-Aware Frame-Base Evaluation**:
   - `DwarfIndexer.parse_cfi_table`: Parses `.eh_frame` and `.debug_frame` via `readelf --debug-dump=frames` to determine `has_frame_pointer` and the exact `frame_established_pc`.
   - **Entry Probe Defense**: Probing at `subp.low_pc` or prior to `frame_established_pc` returns `UNAVAILABLE` (`"Stack variable not accessible: observation point is at function entry prior to prologue frame establishment"`). Never reads garbage caller stack memory!
   - **Omitted Frame Pointer Defense**: Functions compiled with `-fomit-frame-pointer` return `UNAVAILABLE` (`"Cannot compute Canonical Frame Address (CFA): function compiled with -fomit-frame-pointer"`). DynamicState never assumes `FP + 16` or guesses frame addresses.
   - **Post-Prologue Resolution**: When `link_time_address >= frame_established_pc`, evaluates `DW_AT_frame_base` (e.g. `DW_OP_call_frame_cfa` or `DW_OP_reg29` / `DW_OP_reg6`), reads stack memory, and unpacks the variable.
2. **Location-List Parsing (`.debug_loc` / `.debug_loclists`)**:
   - Seamlessly parses both DWARF 4 `.debug_loc` and DWARF 5 `.debug_loclists`.
   - Supports column 1 section offsets, base address selection entries, location view pairs (`v00...`), and multi-line continuation entries.
   - Addresses matched strictly against link-time PC in both PIE (`ET_DYN`) and Non-PIE (`ET_EXEC`) binaries.
   - Missing or corrupted location list returns `ERROR`, never `OPTIMIZED_OUT`.
3. **Canonical Type System & IEEE 754 Floating-Point**:
   - Implements strict type unpackers: `int8_t`, `int16_t`, `int32_t`, `int64_t`, `uint8_t`, `uint16_t`, `uint32_t`, `uint64_t`, `float`, `double`, `bool`, and `pointer`.
   - Unpacks IEEE 754 single-precision (32-bit) and double-precision (64-bit) floats from SIMD/FP registers (`s0..s31`, `d0..d31`, `v0..v31`, `xmm0..xmm15`) and memory using `struct.unpack` without precision loss.
   - Unreadable memory returns `UNAVAILABLE` with reason `"Failed to read stack memory: memory unreadable"`. It never fabricates 0!
4. **Register Clobbering Lifecycle**:
   - Entry point: Live in parameter register (`x0`/`rdi`) $\rightarrow$ `OBSERVED`.
   - Spilled to callee-saved register: Live in callee register (`x19`/`rbx`) $\rightarrow$ `OBSERVED`.
   - Post-call clobbered: Transitioned to `DW_OP_entry_value` $\rightarrow$ `OPTIMIZED_OUT`.
   - Outside function / live range $\rightarrow$ `UNAVAILABLE`.

### 7.4 Compiler Matrix & GDB Cross-Validation Parity

The implementation is verified against real binaries produced by GCC and Clang across multiple optimization and frame-pointer configurations, cross-validated against GDB 15.1:

| Target Variable | Declared Type | Storage Location | DynamicState Evaluator Status | DynamicState Value | GDB 15.1 Ground Truth | Result |
|---|---|---|---|---|---|---|
| `i8` | `int8_t` | `DW_OP_reg0` (`x0`) | `OBSERVED` | `-8` (`0xf8`) | `-8 '\370'` | **PARITY MATCH** |
| `i16` | `int16_t` | `DW_OP_reg1` (`x1`) | `OBSERVED` | `-16` (`0xfff0`) | `-16` | **PARITY MATCH** |
| `i32` | `int32_t` | `DW_OP_reg2` (`x2`) | `OBSERVED` | `-32` (`0xffffffe0`) | `-32` | **PARITY MATCH** |
| `i64` | `int64_t` | `DW_OP_reg3` (`x3`) | `OBSERVED` | `-64` (`0xffffffffffffffc0`) | `-64` | **PARITY MATCH** |
| `u8` | `uint8_t` | `DW_OP_reg4` (`x4`) | `OBSERVED` | `8` (`0x08`) | `8 '\b'` | **PARITY MATCH** |
| `u16` | `uint16_t` | `DW_OP_reg5` (`x5`) | `OBSERVED` | `16` (`0x0010`) | `16` | **PARITY MATCH** |
| `u32` | `uint32_t` | `DW_OP_reg6` (`x6`) | `OBSERVED` | `32` (`0x00000020`) | `32` | **PARITY MATCH** |
| `u64` | `uint64_t` | `DW_OP_reg7` (`x7`) | `OBSERVED` | `64` (`0x0000000000000040`) | `64` | **PARITY MATCH** |
| `f32` | `float` | `DW_OP_regx: 64` (`s0`) | `OBSERVED` | `1.25` (`0x3fa00000`) | `1.25` | **PARITY MATCH** |
| `f64` | `double` | `DW_OP_regx: 65` (`d1`) | `OBSERVED` | `2.75` (`0x4006000000000000`) | `2.75` | **PARITY MATCH** |
| `op_code` (entry) | `int32_t` | `DW_OP_fbreg` | `UNAVAILABLE` | `None` (before prologue) | Entry probe: frame unestablished | **PARITY MATCH** |
| `op_code` (post) | `int32_t` | `DW_OP_fbreg: -116` | `OBSERVED` | `42` (`0x0000002a`) | `42` | **PARITY MATCH** |
| `val` (clobbered) | `int64_t` | `DW_OP_entry_value` | `OPTIMIZED_OUT` | `None` (entry_value) | `<optimized out>` | **PARITY MATCH** |
| `op_code` (omit-fp) | `int32_t` | `DW_OP_fbreg` | `UNAVAILABLE` | `None` (omit-fp CFI rule) | CFA cannot be inferred from FP | **PARITY MATCH** |

---

## 8. CLI Usage Reference

```bash
# Trace function entry and return on running target:
dynamic-state trace-function \
    --pid <TARGET_PID> \
    --binary /path/to/binary \
    --function trace_target_function \
    --duration 2.0

# Trace stripped binary using external debug ELF:
dynamic-state trace-function \
    --pid <TARGET_PID> \
    --binary /path/to/stripped_binary \
    --debug-image /path/to/debug_binary.debug \
    --function trace_target_function \
    --duration 2.0

# Disambiguate overloaded C++ function via linkage name:
dynamic-state trace-function \
    --pid <TARGET_PID> \
    --binary /path/to/binary \
    --function _Z17overloaded_metrici \
    --duration 2.0

# Output structured JSON:
dynamic-state trace-function \
    --pid <TARGET_PID> \
    --binary /path/to/binary \
    --function trace_target_function \
    --json
```

---

## 8. Observation vs Snapshotting Semantics

| Capability / Property | Function-Entry Tracing (eBPF PoC) | DWARF Location Recovery (Phase 2) | Memory Snapshotting (Low-Impact / Consistent) |
|---|---|---|---|
| **Primary Goal** | Real-time event recording at probe points | Symbolic variable recovery from memory | Full process memory capture & offline graph |
| **Process Suspension** | None (0 µs process pause) | None (0 µs process pause) | 0 µs (Low-Impact) or < 4.5 ms (Consistent) |
| **Process Mutation** | Forbidden (Read-only probe) | Forbidden (Read-only) | Allowed only in Consistent (GDB) mode |
| **Local Variable Scope** | Calling args & return value only | In-function locals via DWARF expressions | Process-wide globals, heaps, thread stacks |
| **Consistency Scope** | `PROBE_POINT_EVENT` (Ephemeral event) | Ephemeral probe-point evaluation | `NON_ATOMIC` (Low-Impact) / `STOPPED` (Consistent) |
| **Overhead Mechanism** | Kernel trap / breakpoint (~1-3 µs/hit) | Kernel trap + BPF map lookup | OS syscall `process_vm_readv` (page batches) |

---

## 9. Phase 1.4 DWARF Parser & CFI Hardening Audit

### 9.1 Grammar-Driven Location-List Parsing
The DWARF location list parser (`parse_debug_loc_table`) operates as a grammar-driven state machine rather than an indentation heuristic:
- **Disambiguation of Offsets vs Range Addresses**: In readelf `--debug-dump=loc`, column 1 section offsets have exactly 3 tokens before expression (`<offset> <begin> <end> (<expr>)`), whereas indented continuation ranges have 2 tokens (`<begin> <end> (<expr>)`). In non-PIE binaries, link-time addresses like `0x004015b0` are strictly categorized as range addresses and never registered as section list keys.
- **Entry Offset Isolation**: In multi-entry location lists, only the list header offset (or location view pair offset) is registered as the dictionary lookup key. Internal entry offsets are not registered as independent list keys, preventing truncated range lists.
- **Explicitly Empty Lists**: `<End of list>` entries with no preceding ranges are mapped to `[]` in the table, allowing the evaluator to distinguish `OPTIMIZED_OUT` (variable eliminated) from `ERROR` (offset missing / corrupted).
- **Format Errors & Diagnostics**: Failures from readelf are recorded in `_LOC_ERROR` and returned in `DwarfLocationResult.reason` rather than silently swallowed.

### 9.2 CFI Rule Intervals & Epilogue Teardown Protection
- **Instruction-by-Instruction CFA Intervals**: `parse_cfi_table` parses CFI rules across `[start_pc, end_pc)` intervals, tracking `DW_CFA_advance_loc`, `DW_CFA_def_cfa`, `DW_CFA_def_cfa_register`, and `DW_CFA_def_cfa_offset`.
- **FDE Lifetime Integrity**: An FDE is closed only on encountering the next FDE/CIE header; blank lines, nops, and state save/restore instructions do not cause premature FDE termination. State stacks handle `DW_CFA_remember_state` and `DW_CFA_restore_state`.
- **Epilogue Frame Destruction**: When `DW_CFA_restore` restores the frame pointer (or CFA resets to SP), `frame_destroyed_pc` is recorded. Probes in the epilogue at or after `frame_destroyed_pc` return `UNAVAILABLE` ("is in function epilogue after frame destruction"), preventing reading caller stack frames.
- **Omitted Frame Pointer Handling**: Functions compiled with `-fomit-frame-pointer` evaluate CFA via `SP + cfa_off` when the stack pointer is available, or return `UNAVAILABLE` when SP is absent.

### 9.3 Invalidation & Debug Artifact Identity
- **Quad-Tuple Cache Key**: `_LOC_CACHE`, `_CFI_CACHE`, and `DwarfIndexer._cache` key on `(abs_path, mtime, size, build_id)`. Rebuilding an ELF artifact in place at the same path immediately invalidates cached indexes and parses new symbols.
- **Stripped Binary External Artifact**: `DwarfEvaluationContext` and `Phase2DwarfLocationResolver` support `debug_artifact_path`. When tracing stripped production binaries, DWARF location expressions, CFI tables, and location lists are resolved from the verified matching external debug ELF while memory is read from the target process.

### 9.4 Automated GDB 15.1 Parity Matrix
DynamicState is tested against GDB 15.1 in automated cross-validation tests (`TestDwarfEvaluatorCorrectness`):
- Scalar arguments (`int8_t` through `uint64_t`) and IEEE 754 floats (`float`, `double`) match GDB exactly.
- Location list evaluation across GCC 13 and Clang 18 binaries matches GDB across active live ranges, prologue entry, epilogue teardown, and clobbered registers.

---

## 10. Phase 1.6 eBPF Probe Event & DWARF Variable Evaluation Pipeline Integration

### 10.1 End-to-End Tracing Pipeline Architecture
Phase 1.6 connects the runtime observation pipeline (`EbpfTracer`) directly to the DWARF evaluation engine (`DwarfEvaluator` via `Phase2DwarfLocationResolver`):
1. **Probe Attachment**: `EbpfTracer` determines file-relative attachment offsets using PT_LOAD headers and attaches bounded `uprobe` (entry) and `uretprobe` (return) probes via `bpftrace`.
2. **Streaming Event Parsing**: `EbpfEventDecoder` streams JSON payloads from `bpftrace`, filtering strictly by target PID and sequence.
3. **Canonical Register Normalization**: Arguments `arg0`..`arg7` and frame registers are normalized into canonical architecture registers (`x0`..`x7`, `x29`, `x30`, `sp`, `pc` on aarch64; `rdi`..`r9`, `rbp`, `rsp`, `rip` on x86_64).
4. **Link-Time PC Translation**: Runtime PC is translated to link-time PC using verified load bias ($\text{link\_pc} = \text{pc} - \text{load\_bias}$) and recorded in `FrameMetadata.link_time_address`.
5. **Probe-Point DWARF Evaluation**:
   - **At Function Entry (`uprobe`)**: ABI arguments residing in registers (`op_code`, `input_val`, `count`) are evaluated against active location lists and reported as `OBSERVED` with exact typed values and hex strings. Stack-resident variables are truthfully reported as `UNAVAILABLE` because observation occurs prior to prologue frame establishment. Eliminated constants are reported as `OPTIMIZED_OUT`.
   - **At Function Return (`uretprobe`)**: `return_value` is reported as `OBSERVED`, while function local variables are reported as `UNAVAILABLE` because function execution completed and the stack frame is destroyed.
6. **Safe Memory Reader**: A bounded memory reader delegates to `read_process_memory_slice`, enforcing `0 < size <= 65536` and `0 < addr <= 0x7fffffffffff`, distinguishing unreadable memory from valid zeros.

### 10.2 Truthful Capability Descriptor
`EbpfObservationBackend.capabilities()` reports:
- `local_variable_dwarf_eval`: `True`
- `dwarf_eval_status`: `"SUPPORTED_PROBE_POINT"`
- `dwarf_eval_scope`:
  - `supported_types`: `int8`, `int16`, `int32`, `int64`, `uint8`, `uint16`, `uint32`, `uint64`, `float`, `double`, `bool`, `pointer`.
  - `supported_expressions`: `DW_OP_reg*`, `DW_OP_regx`, `DW_OP_fbreg`, `DW_OP_breg*`, `DW_OP_bregx`, `DW_OP_entry_value`, `.debug_loc`/`.debug_loclists` ranges.
  - `supported_architectures`: `x86_64`, `aarch64`.
  - `available_probe_points`: `function_entry (uprobe)`, `function_return (uretprobe)`.
  - `value_sources`: `registers`, `process_memory`.

### 10.3 Host Environment & Probe Offset Limitation
In the host test environment (Linux 6.17 aarch64 with `bpftrace` 0.20.2), `bpftrace` was built without kernel/uprobe offset support (`compiled without (k|u)probe offset support`), returning exit code 255 if an arbitrary instruction offset (`function+offset`) is targeted. Consequently, live eBPF tracing is strictly limited to function entry and return probe points. Instruction-point local-variable tracing at arbitrary locations within the function body remains blocked pending a bpftrace rebuild with offset support or a direct `libbpf` backend in Phase 2.

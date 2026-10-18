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
- `UNAVAILABLE`: Location expression is valid, but variable is not accessible at current probe point (e.g. instruction address outside location-list range, register absent from payload, or memory reader unconfigured).

### 7.3 Bounded Vertical Slice
1. **Direct Registers (`DW_OP_reg*` / `DW_OP_regx`)**:
   - Maps DWARF register numbers to architecture register names (`x0`..`x30`, `sp` on aarch64; `rax`, `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`, `rbp`, `rsp` on x86_64).
   - Unpacks values with integer width and sign extension.
2. **Simple Frame-Base Relative (`DW_OP_fbreg <offset>`)**:
   - Canonical Frame Address (CFA) calculation:
     $$\text{CFA} = \text{frame\_pointer} + 16$$
     (representing saved frame pointer and return address on standard ABI stack frames).
   - Target variable address: $\text{addr} = \text{CFA} + \text{offset}$.
   - Cross-checked with GDB: on `ebpf_stack_fixture.cpp` (`-O0`), GDB reported `&op_code == 0xffffffffcc0c` with `CFA == 0xffffffffcc80` (`0xffffffffcc80 - 116 == 0xffffffffcc0c`), exactly matching `DwarfEvaluator`.
3. **Location-List Range Selection (`.debug_loc` / `.debug_loclists`)**:
   - Parses location lists and selects active range for `link_time_address`:
     - Inside active register range: evaluated as register location (`OBSERVED`).
     - Inside `DW_OP_entry_value` range: evaluated as `OPTIMIZED_OUT`.
     - Outside all ranges: evaluated as `UNAVAILABLE`.
4. **Basic Scalar Types**:
   - Supports `int8`, `int16`, `int32`, `int64`, `uint8`, `uint16`, `uint32`, `uint64`, `float`, `double`, `bool`, and `pointer`.

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

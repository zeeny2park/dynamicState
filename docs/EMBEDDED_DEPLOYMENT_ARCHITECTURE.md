# dynamicState — Embedded Deployment Architecture & Toolchain Guide

## 1. Executive Summary & Design Principles

dynamicState is designed to observe and explore runtime memory states of C/C++ applications across diverse execution environments, ranging from high-performance x86_64 servers to resource-constrained ARM / AArch64 / RISC-V embedded target boards.

To ensure viability in real-world embedded systems, dynamicState enforces strict **Separation of Concerns**:

```
+-----------------------------------------------------------------------------------+
|                           DEVELOPER HOST WORKSTATION                              |
|                                                                                   |
|   +---------------------------------------------------------------------------+   |
|   | Human-Centric Web UI (Optional)                                            |   |
|   | http://localhost:8080 (Browser: Chrome, Firefox)                          |   |
|   +---------------------------------------------------------------------------+   |
|                                     | HTTP REST API                               |
|   +---------------------------------------------------------------------------+   |
|   | dynamicState Core Engine (Python 3.9+)                                    |   |
|   | - AgentRuntime / MCP Protocol                                             |   |
|   | - Semantic Object Graph Extractor & State Corpus                          |   |
|   | - Offline DWARF / ELF Parser & Build ID Verifier                          |   |
|   | - GDB Compatibility Layer (GDB 9.2 - 15.x)                                |   |
|   +---------------------------------------------------------------------------+   |
|                                     |                                             |
|        Unstripped ELF with DWARF    | Debugger Protocol (RSP) or Memory Dump      |
|        (/path/to/app.debug)         |                                             |
+-------------------------------------|---------------------------------------------+
                                      |
                     Network / Serial / File Transfer
                                      |
+-----------------------------------------------------------------------------------+
|                        EMBEDDED TARGET BOARD (Linux)                              |
|                                                                                   |
|  * ZERO Python installation required                                              |
|  * ZERO Web server running on target                                              |
|  * Runs stripped production binaries (-fPIE / ASLR enabled)                       |
|                                                                                   |
|  Pattern 1: Remote GDB (gdbserver :2345 /app/prod_bin)                            |
|  Pattern 2: Zero-Python Memory Capture (scripts/target_capture.sh <PID>)          |
+-----------------------------------------------------------------------------------+
```

### Key Architectural Rules
1. **Target Board is Python-Free**:
   - The embedded device does **not** need Python installed.
   - The embedded device does **not** need dynamicState code deployed on it.
2. **Web Server is 100% Optional and Host-Only**:
   - The Web UI server (`DynamicStateWebServer`) runs exclusively on the developer's host workstation.
   - The dynamicState core engine functions completely standalone without the Web server (via CLI, Python SDK, or MCP server).
3. **Debug Artifacts Remain on Host**:
   - Unstripped binaries, external `.debug` images, and symbol tables remain securely on the host workstation.
   - Target boards run stripped production binaries.
4. **Hostile Uncertainty Over Guesses**:
   - When architecture, endianness, or debug link information cannot be verified, it is reported as `UNKNOWN` or `UNAVAILABLE` rather than guessing.

---

## 2. Embedded Deployment Patterns

### Pattern 1: Remote GDB (`gdbserver` Attached or Launch)

This pattern provides full **CONSISTENT** observation, breakpoint stops, typed mutations, and branch-safe checkpoint-restore exploration.

```mermaid
sequenceDiagram
    autonumber
    participant Target as Embedded Target Board
    participant HostGDB as Host GDB / gdb-multiarch
    participant DynState as Host dynamicState Engine
    participant Browser as Host Web Browser (Optional)

    Target->>Target: Start gdbserver :2345 /app/sensor_node (PID 412)
    DynState->>HostGDB: Launch GDB with python script & load sensor_node.debug
    HostGDB->>Target: GDB Remote Serial Protocol (RSP) -> connect :2345
    Target-->>HostGDB: Inferior stopped at main / checkpoint
    HostGDB->>DynState: Extract ExecutionContext & Semantic Object Graph
    DynState->>DynState: Build State state_000001 (Hash & Corpus)
    opt Human Inspection
        Browser->>DynState: GET /api/runtime & /api/states/state_000001/objects
        DynState-->>Browser: JSON payload -> Render Memory Explorer
    end
```

#### Step-by-Step Instructions

1. **On Target Board**:
   Launch the target process under `gdbserver` or attach to an existing PID:
   ```bash
   # Launch new process:
   gdbserver :2345 /usr/bin/sensor_node

   # Or attach to running PID:
   gdbserver --attach :2345 412
   ```

2. **On Host Workstation**:
   Start dynamicState using the cross-debugger or multiarch GDB:
   ```bash
   # Option A: Start optional Web UI on developer machine
   python3 -m extractor server \
     --host 127.0.0.1 \
     --port 8080 \
     --debug-image /build/sensor_node.debug \
     --binary /build/sensor_node

   # Connect GDB to target board
   # (Inside GDB session or scripted via RuntimeController):
   target remote 192.168.1.100:2345
   ```

---

### Pattern 2: Native C99 Process Memory Collector (`target/collector/`)

This is the **recommended production approach** for resource-constrained Linux targets (ARM, MIPS, RISC-V, x86). It provides high-speed, safe **LOW_IMPACT** observation without stopping the process, without installing GDB, and with **zero Python or web dependencies** on the target board.

```mermaid
sequenceDiagram
    autonumber
    participant TargetApp as Running Target Process (PID 890)
    participant Collector as dynamicstate-collector (Native C99)
    participant Host as Host Workstation (dynamicState)

    Note over TargetApp: Running mission-critical C/C++ application
    Collector->>TargetApp: Read /proc/890/maps (parse categories)
    Collector->>TargetApp: Read memory via process_vm_readv / pread
    Collector->>Collector: Package metadata.json, manifest.json, maps.json, memory/
    Note over TargetApp: Process never stopped; zero downtime; zero python
    Collector->>Host: Transfer raw snapshot bundle (scp / tftp / NFS)
    Host->>Host: RawMemorySnapshot.load() & Offline DWARF reconstruction
    Host->>Host: Produce Semantic Snapshot S_M_001 & Memory Breakdown
```

#### Step-by-Step Instructions

1. **Build the Collector for Target Architecture**:
   Cross-compile on host or build natively:
   ```bash
   # Cross-compile for ARM:
   cd target/collector
   CC=arm-linux-gnueabihf-gcc make
   ```

2. **On Target Board**:
   Run the lightweight binary [`target/collector/dynamicstate-collector`](file:///home/ubuntu/workspace/ut/target/collector):
   ```bash
   ./dynamicstate-collector -p 890 -o /tmp/snapshot_890
   ```
   Output bundle generated:
   ```
   /tmp/snapshot_890/
   ├── metadata.json       # PID, capture timestamp, page size, kernel/arch info
   ├── manifest.json       # Precise region boundaries, permissions, status
   ├── maps.json           # Categorized memory maps (heap, stack, global, etc.)
   ├── maps.txt            # Raw /proc/$PID/maps copy for provenance
   └── memory/             # Binary memory segment dumps
       ├── region_000001.bin
       ├── region_000002.bin
       └── ...
   ```

3. **Transfer to Host Workstation**:
   ```bash
   scp -r root@192.168.1.100:/tmp/snapshot_890 /home/developer/snapshots/
   ```

4. **On Host Workstation**:
   Load and explore the raw snapshot:
   ```python
   from extractor.memory_snapshot import RawMemorySnapshot
   from extractor.memory_snapshot_summary import build_memory_snapshot_summary

   snapshot = RawMemorySnapshot.load("/home/developer/snapshots/snapshot_890")
   summary = build_memory_snapshot_summary({"snapshot_id": snapshot.snapshot_id}, raw_memory_snapshot=snapshot)
   print(f"Captured {summary.captured_bytes} bytes across {len(summary.regions)} regions.")
   ```

---

### Pattern 3: Shell Prototype Script (`scripts/target_capture.sh`)

> **Note**: This is a lightweight POSIX shell prototype useful for rapid triage where cross-compilation toolchains are not immediately available. For production environments, prefer the native C99 collector (Pattern 2).

1. **On Target Board**:
   Run [`scripts/target_capture.sh`](file:///home/ubuntu/workspace/ut/scripts/target_capture.sh):
   ```bash
   chmod +x scripts/target_capture.sh
   ./scripts/target_capture.sh 890 /tmp/snapshot_890
   ```

2. **Transfer to Host Workstation**:
   Transfer the `/tmp/snapshot_890` directory to the host for analysis.

---

## 3. GDB Version Compatibility & Defense Layer

Embedded cross-toolchains frequently bundle older LTS GDB releases (such as **GDB 9.2** in Ubuntu 20.04 LTS or Yocto Dunfell) or modern versions (GDB 14/15).

dynamicState provides a dedicated GDB compatibility module in [`extractor/gdb_compat.py`](file:///home/ubuntu/workspace/ut/extractor/gdb_compat.py) to guarantee deterministic operation without crashes.

### Compatibility Matrix

| Feature | GDB 9.2 | GDB 10.x | GDB 11.x+ | dynamicState Compat Handling (`extractor/gdb_compat.py`) |
| :--- | :--- | :--- | :--- | :--- |
| `gdb.Frame.level()` | ❌ Not available | ❌ Not available | ✅ Available | Track stack depth manually during frame traversal; fallback to depth counter |
| `gdb.Frame.function()` | ⚠️ May return `None` | ⚠️ May return `None` | ✅ Available | Safe wrapper returning function name string or `None` |
| `gdb.Frame.pc()` | ✅ Available | ✅ Available | ✅ Available | Safe wrapper returning integer PC |
| `gdb.Progspace.filename` | ⚠️ May raise `AttributeError` | ✅ Available | ✅ Available | Try-catch attribute access, fallback to `None` |
| `gdb.Thread.is_stopped()` | ⚠️ Attribute differences | ✅ Available | ✅ Available | Check `is_stopped()` -> `is_valid()` -> fallback `True` |
| Python API Version | Python 3.8+ | Python 3.8+ | Python 3.10+ | Pure Python standard library constructs only |

### Implementation Detail: `get_frame_level` Fallback

In GDB 9.2 and 10.x, calling `frame.level()` raises `AttributeError: 'gdb.Frame' object has no attribute 'level'`.

In `extractor/gdb_compat.py`:
```python
def get_frame_level(frame: Any, fallback_level: int = 0) -> int:
    """Safely get frame level across all GDB versions (GDB 9.2+)."""
    if hasattr(frame, "level"):
        try:
            return frame.level()
        except Exception:
            pass
    return fallback_level
```

In `extractor/execution.py`:
```python
stack_depth = 0
while frame is not None and len(frames) < max_depth:
    level = get_frame_level(frame, fallback_level=stack_depth)
    # ... record frame info ...
    frame = frame.older()
    stack_depth += 1
```

---

## 4. Web Server Process Model & Clean Ctrl+C Shutdown

### The SocketServer Deadlock Issue
In standard Python `socketserver.TCPServer`, calling `server.shutdown()` from the **same thread** that is currently blocked in `serve_forever()` results in an immediate permanent deadlock (as documented in Python stdlib).

### Non-Deadlocking Server Loop Design
dynamicState implements `run_server_loop(server)` in [`extractor/web/server.py`](file:///home/ubuntu/workspace/ut/extractor/web/server.py):

```python
def run_server_loop(server: DynamicStateWebServer):
    """Run server loop with non-deadlocking signal handling."""
    stop_event = threading.Event()

    def _sig_handler(sig, frame):
        stop_event.set()

    signal.signal(signal.SIGINT, _sig_handler)
    signal.signal(signal.SIGTERM, _sig_handler)

    server_thread = threading.Thread(
        target=lambda: server.serve_forever(poll_interval=0.2),
        daemon=True
    )
    server_thread.start()

    try:
        while not stop_event.is_set():
            stop_event.wait(timeout=0.2)
    finally:
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=1.0)
```

**Benefits**:
- Hitting `Ctrl+C` immediately wakes up the main thread.
- `server.shutdown()` is called from the main thread while `serve_forever` is in a background thread.
- Port is immediately freed (`SO_REUSEADDR`).
- Exits cleanly with status code `0`.

---

## 5. Command-Line Reference

```bash
# 1. Launch Web UI server with active GDB controller:
python3 -m extractor server --host 127.0.0.1 --port 8080 --binary /app/target --debug-image /app/target.debug

# 2. Launch Web UI server in offline viewing mode for an existing state corpus:
python3 -m extractor server --host 127.0.0.1 --port 8080 --corpus /path/to/corpus_dir

# 3. Capture zero-Python memory dump on embedded target:
./scripts/target_capture.sh <PID> [output_directory]

# 4. Run full test suite including GDB compatibility:
python3 -m unittest discover tests
```

---

## 6. Target-Side Native Collector Hardening & Multithread Branch Isolation

### 6.1. Race Condition Detection in Target-Side Memory Collection
When capturing memory on live, non-stopped targets without `ptrace`, dynamicState hardens against memory-layout changes:
1. **Mapping Race Detection (`mapping_race_detected`)**:
   - Compares memory layout before and after capture (`collector_compare_maps`).
   - If dynamic `mmap`, `munmap`, or `mprotect` changes permissions, offsets, or ranges during reading, `mapping_race_detected = true` and snapshot status becomes `PARTIAL`.
2. **Process Lifetime & PID Recycling Check (`process_starttime`)**:
   - Parses field 22 from `/proc/<pid>/stat` before and after capture.
   - If the target process exits or is recycled into another process with the same PID, `process_exited = true` and capture aborts cleanly.

### 6.2. Multithread Branch Isolation in Embedded Deployment
- **Launched Target Programs**: Remote GDB sessions that launch the target with an entry/observation breakpoint support `RESTART` backend, ensuring clean branch isolation across multithreaded mutations.
- **Attached Target Programs**: Processes attached via `attach <pid>` or `gdbserver --attach` report `branch_isolation.status = "UNAVAILABLE"`, preventing dangerous non-isolated mutations while enabling safe observation (`OBSERVE`, `SNAPSHOT`, `INSPECT_OBJECT`).


# DynamicState

> **Agent-Native Runtime Engine & Non-Intrusive State Explorer for C/C++ Systems**

[![Linux](https://img.shields.io/badge/Platform-Linux%20x86__64-blue.svg)](#prerequisites)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue.svg)](#prerequisites)
[![Architecture](https://img.shields.io/badge/Agent-Native-brightgreen.svg)](#agent-runtime-protocol-and-mcp-server)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Safety](https://img.shields.io/badge/Safety-Hardened%20Signals%20%26%20AST%20Audited-success.svg)](#safety-boundaries-and-defensive-hardening)

**DynamicState** is a high-performance, agent-native runtime exploration and live-system debugging platform tailored for Linux C/C++ binaries. It enables both human engineers and autonomous AI coding agents to observe, reconstruct, and navigate live execution state without arbitrary heap corruption or disruptive debugger halts.

---

## 🌟 Key Highlights

- **Zero-Stop Non-Intrusive Memory Capture (`LOW_IMPACT` Mode)**  
  Capture live process memory at wire speed using Linux `process_vm_readv()` without pausing or halting critical production threads.
- **Offline Semantic Object Graph Reconstruction**  
  Resolve memory dumps against external unstripped ELF debug images via DWARF symbol resolution, type canonicalization, and pointer chasing—bypassing raw guesswork.
- **External Debug Image & Build ID Binding**  
  Seamlessly inspect stripped production binaries using external `nostrip` binaries or `.debug` files validated against GNU Build-ID and `.gnu_debuglink` CRC32 checksums.
- **Consistent State Exploration & Checkpointing (`CONSISTENT` Mode)**  
  Perform deterministic state-space branching, typed mutations, and instant rollback using GDB fork checkpoints for root-cause reproduction.
- **Agent Runtime Protocol (ARP) & MCP Server**  
  Full Model Context Protocol (MCP) integration with over 45 native tools, equipping LLM coding agents (Gemini, Claude, Antigravity) with structured runtime introspection.
- **Real-Time Web Workspace UI**  
  Interactive browser-based live dashboard with reverse-proxy support, subpath awareness, live trace cards, callstack/lock visualizers, and memory integrity monitors.
- **Industrial Safety & Defensive Hardening**  
  Ast-verified signal dispatch, PID bounds checking (strict rejection of PID <= 1 and boolean inputs), safe `kill --` delimiters, and `AbortController` timeouts.

---

## 🏗️ Architecture & Exploration Pipeline

DynamicState separates observation from live process interference through a clean, multi-layered architecture:

```text
               Autonomous AI Agent / Web UI / CLI
                                │
                                │ Agent Runtime Protocol (JSON-RPC / MCP)
                                ▼
                         AgentRuntime
                                │
       ┌────────────────────────┴────────────────────────┐
       ▼ [LOW_IMPACT Mode]                               ▼ [CONSISTENT Mode]
 Non-Intrusive Live Capture                     Deterministic State Explorer
  (process_vm_readv)                             (GDB Checkpoints & Ptrace)
       │                                                 │
       ├── Zero process halt (0.00ms stop)               ├── Controlled breakpoint stop
       ├── Accurate PT_LOAD load_bias computation        ├── Typed field mutation
       ├── Build ID & .gnu_debuglink verification        ├── Rollback & branch exploration
       └── RawMemorySnapshot persistence                 └── Semantic diff & state hash
               │                                                 │
               ▼                                                 ▼
     OfflineMemoryAnalyzer                             RuntimeController
               │                                                 │
               └───────────────┬─────────────────────────────────┘
                               ▼
                   Semantic Object Graph
          (DWARF Typed Roots: Globals / Locals / Heap)
```

### Core Invariant: Semantic Reachability over Brute-Force Scanning

DynamicState is **not** a blind heap scanner. It never traverses `/proc/<pid>/mem` haphazardly. Instead, state exploration is anchored to typed roots:

```text
Typed Roots (Global / Static / Frame Locals / Thread Stacks)
    ↓
DWARF Type Canonicalization & Member Offsets
    ↓
Target Object Resolution (Virtual Address, DWARF Tag)
    ↓
Pointer Dereference & Boundary Validation
    ↓
Recursive Semantic Reachability Traversal
```

Memory mapping `/proc/<pid>/maps` is strictly consulted to classify storage classes (`global`, `heap`, `stack`, `mmap`), not to invent synthetic addresses.

---

## 🚀 Quickstart

### Prerequisites

- **Linux** (x86_64 or aarch64, kernel 4.10+)
- **Python 3.9+** (with standard libraries; `pyelftools` recommended)
- **GDB** (optional, required only for `CONSISTENT` checkpointing mode)
- Sufficient permissions to inspect target processes (`CAP_SYS_PTRACE` or sudo access for tracing)

### Installation

Clone the repository:

```bash
git clone https://github.com/zeeny2park/dynamicState.git
cd dynamicState
```

---

## 💻 CLI Usage

DynamicState provides dedicated entry points in `./bin/` for both operators and agents:

### 1. Launch the Real-Time Workspace Web Service

Start the integrated web workspace server:

```bash
./bin/dynamic-state-workspace --host 127.0.0.1 --port 8000
```

Open `http://localhost:8000/workspace` in your browser. The web UI automatically connects to local or remote targets and provides:
- Live process selection & connection validation
- Memory pool visualizer & linked structure traverser
- Callstack & pthread lock inspection
- Memory corruption & integrity audits
- Natural language agent chat assistant

### 2. Capture Zero-Stop Memory (`LOW_IMPACT`)

Capture raw memory of a live running process without stopping it:

```bash
python3 -m extractor.capture_backend capture-memory --pid 12345 --output-dir /tmp/snapshot_12345
```

### 3. Offline Semantic Analysis

Analyze a captured snapshot against an unstripped binary:

```bash
python3 -m extractor.capture_backend analyze-memory \
  --snapshot-dir /tmp/snapshot_12345 \
  --debug-image /path/to/unstripped_binary.debug
```

---

## 🤖 Model Context Protocol (MCP) Server

DynamicState includes a production-grade MCP server for autonomous agents:

```bash
python3 scripts/mcp_server.py
```

### Agent Configuration (e.g. Claude Desktop, Antigravity, Cursor)

Add the server to your agent's MCP settings:

```json
{
  "mcpServers": {
    "dynamicstate": {
      "command": "python3",
      "args": ["/absolute/path/to/dynamicState/scripts/mcp_server.py"],
      "env": {
        "PYTHONPATH": "/absolute/path/to/dynamicState"
      }
    }
  }
}
```

### Key MCP Tools

| Tool Name | Description |
| :--- | :--- |
| `runtime_target_connect` | Discover and bind a target PID to its external companion ELF image. |
| `runtime_capture_memory` | Non-intrusively capture process memory (`LOW_IMPACT`). |
| `runtime_eval_memory_path` | Evaluate DWARF-typed expressions (e.g., `*g_service.config.port`). |
| `runtime_capture_and_diff` | Compare two temporal snapshots to reveal mutated fields and state drift. |
| `runtime_inspect_thread_callstack_and_locks` | Inspect callstacks across all threads along with active mutex/rwlock owners. |
| `runtime_audit_memory_integrity` | Detect heap canary corruption, dangling pointers, and boundary overruns. |
| `runtime_traverse_linked_structure` | Walk linked lists, trees, and STL containers safely up to max depth. |
| `runtime_run_diagnostic_recipe` | Execute predefined diagnostic suites (Leak Detection, Deadlock Triage, etc.). |

---

## 🧪 Testing & Verification

DynamicState enforces rigorous automated testing covering eBPF tracing, signal dispatch, memory integrity, web services, and agent protocol conformance:

### Running Test Suites

Run the complete test suite:

```bash
./scripts/run_all_tests.sh
```

Or execute focused regression and hardening suites directly:

```bash
# Web Service & MCP Comprehensive Defensive Hardening
python3 -m unittest tests/test_phase52_web_and_mcp_defensive_hardening.py

# eBPF Tracer & Signal / AST Safety Audits
python3 -m unittest tests/test_ebpf_tracer.py

# Real Workspace Web Service Tests
python3 -m unittest tests/test_phase51_real_workspace_web_service.py

# Watch Session & Temporal State Tests
python3 -m unittest tests/test_phase21_watch_session.py
```

---

## 🛡️ Safety Boundaries and Defensive Hardening

DynamicState is engineered with zero-compromise safety guarantees for production environments:

1. **Strict Signal & PID Isolation**:
   - Every `kill` command is dispatched with explicit `--` parameter termination to prevent procps negative PID option misparsing (`kill -INT -- -<PGID>`).
   - Hardened PID guards reject non-integer, negative, or reserved PIDs (`pid <= 1`).
   - Process group killing is restricted exclusively to confirmed session leaders (`child_pgid == child_pid`).

2. **Web & API Defensiveness**:
   - All REST endpoints reject malformed JSON and adversarial parameter types gracefully.
   - Per-card failure isolation in `/api/workspace/chat` ensures one failed query never degrades healthy cards.
   - Browser client uses `AbortController` timeouts and automatic 3-strike circuit breakers for unresponsive targets.

3. **Memory Safety Contract**:
   - Zero-stop memory reads via `process_vm_readv` never modify inferior process memory or write to inferior address spaces.
   - Bounded recursion limits on pointer dereferencing and cyclic container detection prevent infinite loops and runaway allocations.

---

## 📂 Project Structure

```text
dynamicState/
├── bin/
│   └── dynamic-state-workspace      # Web service launcher script
├── extractor/
│   ├── capture_backend.py          # process_vm_readv memory capture engine
│   ├── dwarf_indexer.py            # DWARF debugging information parser
│   ├── ebpf_tracer.py              # bpftrace / eBPF kernel tracing adapter
│   ├── explorer.py                 # Deterministic state-space explorer
│   ├── llm_provider.py             # LLM provider integration & CLI wrappers
│   ├── runtime_controller.py       # GDB checkpoint & restore backend
│   ├── state_hash.py               # Canonical semantic state hasher
│   ├── target_adapter.py           # Target process inspection & liveness
│   ├── watch_session.py            # Persistent temporal watch sessions
│   └── web/
│       ├── server.py               # Production REST API & WebSocket server
│       └── workspace_static/       # Browser UI (HTML5, Tailwind, JS)
├── scripts/
│   ├── mcp_server.py               # Model Context Protocol (MCP) server
│   └── run_all_tests.sh            # Automated end-to-end test runner
├── tests/                          # 80+ comprehensive test suites
└── docs/                           # Architectural specs & practical playbooks
```

---

## 📄 License

DynamicState is released under the **Apache License 2.0**. See [LICENSE](LICENSE) for details.

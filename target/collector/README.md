# dynamicState Native Target Collector

A lightweight, zero-dependency C99 memory snapshot collector designed for embedded and remote Linux targets.

## Overview

In embedded and low-resource environments, target boards cannot run Python, GDB, or web servers. `dynamicstate-collector` runs directly on the target device to capture raw process memory and memory maps with minimal footprint and zero non-libc dependencies.

```
Target Board (ARM / MIPS / RISC-V / x86)
┌──────────────────────────────────────┐
│  Target Process (C/C++ App)          │
│  ▲                                   │
│  │ (process_vm_readv / pread)        │
│  dynamicstate-collector (Native C99) │
│  │                                   │
│  ▼                                   │
│  Raw Snapshot Bundle                 │
│  (metadata, manifest, maps, memory/) │
└──────────────────┬───────────────────┘
                   │ scp / tftp / nfs
Host Machine (x86_64 / macOS)
┌──────────────────▼───────────────────┐
│  dynamicState Core (Python + Web UI) │
│  - RawMemorySnapshot.load()          │
│  - Offline DWARF / Debug Image Parse │
│  - Semantic Object Graph             │
│  - Web UI Memory Explorer            │
└──────────────────────────────────────┘
```

> **Note on `scripts/target_capture.sh`**:
> `scripts/target_capture.sh` is an early shell script prototype (using BusyBox `sh`, `dd`, `awk`).
> For production and embedded deployments, use this native C collector (`target/collector/dynamicstate-collector`).

## Building

### Native Build
```bash
make
# or
mkdir build && cd build && cmake .. && make
```

### Cross-Compilation (Embedded Toolchains)
```bash
# ARM 64-bit (aarch64)
CC=aarch64-linux-gnu-gcc make

# MIPS
CC=mips-linux-gnu-gcc make

# RISC-V 64-bit
CC=riscv64-linux-gnu-gcc make
```

The resulting binary `dynamicstate-collector` is a single statically or dynamically linked executable with no external libraries beyond standard libc (`-lc`).

## Usage

```bash
# Capture PID 1234 to output directory
./dynamicstate-collector -p 1234 -o /tmp/snapshot_1234

# Capture only stack and heap
./dynamicstate-collector -p 1234 -o /tmp/snapshot_1234 --policy heap_stack

# Capture with byte limits (max 32MB total, max 16MB per region)
./dynamicstate-collector -p 1234 -o /tmp/snapshot_1234 -m 32 --max-region 16
```

### Options

| Flag | Long Option | Description | Default |
|------|-------------|-------------|---------|
| `-p` | `--pid <PID>` | Process ID to capture | Required |
| `-o` | `--output <DIR>` | Output directory for snapshot bundle | `raw_snapshot_<PID>` |
| `-m` | `--max-mb <MB>` | Maximum total bytes to capture | 64 MB |
| | `--max-region <MB>` | Maximum bytes per region | 32 MB |
| | `--policy <NAME>` | Filtering: `all`, `heap_stack`, `writable` | `all` |
| | `--backend <NAME>` | Memory backend: `auto`, `process_vm_readv`, `pread` | `auto` |
| `-v` | `--verbose` | Verbose debug logging | Disabled |
| `-h` | `--help` | Display usage instructions | |

## Snapshot Bundle Structure

The output directory forms a complete dynamicState raw snapshot bundle:

```
snapshot_dir/
├── metadata.json       # Capture timings, architecture, consistency status
├── manifest.json       # Per-region boundaries, permissions, status
├── maps.json           # Parsed memory map entries
├── maps.txt            # Raw /proc/<pid>/maps copy for provenance
└── memory/             # Binary memory region dumps
    ├── region_000001.bin
    ├── region_000002.bin
    └── ...
```

This bundle can be transferred to any host machine running dynamicState and loaded directly via:
```python
from extractor.memory_snapshot import RawMemorySnapshot
snapshot = RawMemorySnapshot.load("path/to/snapshot_dir")
```

### Lightweight Slice Read & Persistent Daemon Modes (Phase 2)

For high-frequency remote watch sessions and deep pointer-chain traversal without writing snapshot files to embedded flash/tmpfs:

```bash
# 1. One-shot zero-disk slice read (outputs compact JSON with hex bytes to stdout)
./dynamicstate-collector -p 1234 --read-slices 0x555555558000:16,0x555555558020:4

# 2. Persistent stdio RPC daemon mode (for SSH ControlMaster / streaming pipelines)
./dynamicstate-collector --daemon
# Commands on stdin:
#   PING
#   READ 1234 0x555555558000:16,0x555555558020:4
#   QUIT
```

**Daemon wire protocol** (used by `RemoteSshTargetAdapter` over one persistent SSH session, IMP-021):

- Framing: one request per stdin line, exactly one reply per stdout line (JSON). Payload bytes are
  hex-encoded, so a reply never contains a raw newline and needs no length prefix.
- `PING` -> `{"success":true,"status":"PONG"}`; `QUIT`/`EXIT` -> `{"success":true,"status":"BYE"}` and exit;
  `READ <pid> <addr:size[,addr:size...]>` -> the same JSON object as `--read-slices`
  (`{"success":true,"pid":..,"backend":..,"slices":[{"address","size","bytes_read","status","hex"}],"duration_us":..}`),
  one entry per requested slice, in order. Errors are single-line `{"success":false,"error":"..."}`
  (`MISSING_SLICES_SPEC`, `INVALID_PID`, `UNKNOWN_COMMAND`, `INVALID_ARGS`, `TARGET_TERMINATED`, `PERMISSION_DENIED`).
- Limits: the request line buffer is 8192 bytes (a longer line would be split and desynchronise the stream), so
  the host keeps each `READ` below ~7000 characters and splits larger batches; each slice is capped at 65536 bytes.
- Lifetime: the daemon exits on `QUIT` and on stdin EOF (also when the SSH session or the host process dies), so
  no collector is orphaned on the target. The host starts it as `exec <collector> --daemon` and falls back to
  per-call `--read-slices` when the daemon cannot be established (old collector, exec denied).

### Thread information (`THREADS`, `--threads`; collector >= 1.1.0, IMP-011)

One reply carries every thread of a process, so a thread sample costs one exchange regardless of the thread count:

```bash
./dynamicstate-collector -p 1234 --threads [--after-tid 5000]    # one-shot, one JSON line
THREADS 1234 [after_tid]                                          # daemon command
```

Reply (one line, `success:true`):
`{"success":true,"pid":P,"clk_tck":100,"threads":[T,...],"count":N,"more":false,"next_after_tid":0,"truncated":false,"duration_us":..}`
with one object `T` per thread, ordered by tid:

| field | source | notes |
|-------|--------|-------|
| `tid`, `comm`, `state`, `utime`, `stime` | `task/TID/stat` | `comm` is the text between the first `(` and the LAST `)` (names may contain spaces and parentheses); `utime`/`stime` in clock ticks |
| `startstack`, `kstkesp`, `cpu` (processor last run on), `rt_prio`, `policy` | `stat` | |
| `vol`, `invol`, `cpus_allowed`, `mems_allowed` | `task/TID/status` | `*_ctxt_switches`, `Cpus_allowed_list`, `Mems_allowed_list` |
| `syscall` | `task/TID/syscall`, raw line | `"nr a0..a5 sp pc"`, `"-1 sp pc"` or `"running"`; omitted when unreadable |
| `io` = `{"syscr","syscw"}` | `task/TID/io` | omitted without privileges |
| `sched` = `{"run_ns","wait_ns","slices"}` | `task/TID/schedstat` | run time, run-queue wait, timeslices; omitted without `CONFIG_SCHED_INFO` |

All 64-bit counters are printed as `unsigned long long`, so 32-bit ARM targets are exact.  A thread that exits
while the directory is being enumerated is skipped (never an error).  Replies are paged: at most 128 threads per
reply; `more:true` plus `next_after_tid` tells the caller to repeat the request with that tid as `after_tid`.
At most 16384 tids are enumerated per request (`truncated:true` beyond that).  Errors use the usual
`{"success":false,"error":..}` line: `INVALID_PID`, `INVALID_ARGS` (bad `after_tid`), `TARGET_TERMINATED`,
`PERMISSION_DENIED`.  A collector older than 1.1.0 answers `UNKNOWN_COMMAND` (or rejects `--threads`); the host then
falls back to ONE batched POSIX-sh command that cats the same `/proc` files of all threads.

### Multi-architecture static builds (`make dist`)
```bash
make dist   # dist/{aarch64,x86_64}/dynamicstate-collector, static; prints which arches were skipped
```
Host-side deployment (`ensure_remote_collector`) picks `dist/<arch>/` by the target's `uname -m`, streams it over SSH stdin, tries fallback locations (`/var/tmp`, `/dev/shm`; override with `DYNAMICSTATE_COLLECTOR_DEST` / `DYNAMICSTATE_COLLECTOR_FALLBACK_DESTS`) when the primary is noexec, and redeploys when `dynamicstate-collector --version` differs from the local binary's version (see `VERSION`).

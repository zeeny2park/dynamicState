# DynamicState — Remote Collection Correctness & Transfer Optimization Closure

**Repository:** [zeeny2park/dynamicState](https://github.com/zeeny2park/dynamicState)
**Target Upstream Commit Reviewed:** `b691c8ef8459fefeb9e492e3cec5036d4c4bd933`
**Local Mirror Baseline Commit:** `920844f`
**Closure Scope:** Narrow, evidence-driven correctness hardening and transfer-efficiency validation across remote memory slice coalescing, remote ELF image negative caching, gzip file-transfer error semantics, and SSH connection resilience.

---

## 1. Executive Summary

This closure pass audited the remote collection resilience, memory slice coalescing, and compressed file transfer changes introduced through commit `b691c8ef8459fefeb9e492e3cec5036d4c4bd933` and resolved three concrete correctness defects without altering the remote diagnostics architecture or weakening any Phase 2.0-A.3.17–A.3.19 guarantees:

1. **Memory Slice Coalescing Safety (Finding 1 — `SOURCE VERIFIED`, `TEST VERIFIED`):** `_coalesce_memory_slices()` previously merged positive address gaps up to 256 bytes without checking `/proc/<pid>/maps` VMA boundaries. It now merges positive gaps only when both slices reside in the exact same readable VMA, falls back strictly to `gap=0` (duplicates, overlaps, and contiguous slices only) when mappings are unavailable, and executes a single bounded individual-slice fallback (capped at 32 slices, respecting remaining deadline budget, non-recursive, bypassed on SSH transport errors) if a multi-member merged read returns partial or unavailable data.
2. **Remote ELF Image Negative Cache Isolation (Finding 2 — `SOURCE VERIFIED`, `TEST VERIFIED`):** `RemoteImageResolver.__call__()` previously cached `None` in the process-global `_CACHE` for 30 seconds whenever `read_target_file()` returned `None`, poisoning subsequent lookups after transient SSH timeouts or connection resets. It now inspects `adapter._last_file_read_error` and negative-caches only confirmed permanent failures (`FILE_MISSING`, `PERMISSION_DENIED`, `INVALID_DATA`, oversized binary, or non-ELF header), while never negative-caching `TIMEOUT`, `TRANSPORT_ERROR`, `CANCELLED`, or unexpected exceptions.
3. **Gzip Pipeline Error Semantics (Finding 3 — `SOURCE VERIFIED`, `TEST VERIFIED`):** `read_target_file()` previously ran `head | gzip | base64` in POSIX `sh` without `pipefail` or pre-checks, allowing missing or unreadable files to yield an empty gzip stream (`b""`) with exit code `0`. It now runs POSIX `sh` pre-checks (`@@ERR:FILE_MISSING`, `@@ERR:PERMISSION_DENIED`, `@@ERR:PIPELINE_FAIL`, `@@EMPTY`), uses `gzip -1 -c` for `n_bytes >= 8192` with automatic `@@RAW` fallback when `gzip` is absent, and populates structured `self._last_file_read_error` metadata on every failure path while preserving `b""` for genuinely empty readable files and `/proc` virtual files.
4. **Compression & Resilience Validation (`LOCAL_CPU`, `SYNTHETIC`, `TEST VERIFIED`):** Local CPU and synthetic network benchmarks confirm `gzip -1` reduces transfer payload by 47–52% on real ELF binaries (`/bin/ls`, `libc.so.6`) with negligible incompressible overhead (+48 B, +0.95 ms CPU on 64 KB random data). All 221 local regression tests across 21 suites and the native C collector crypto self-test pass with 0 failures and 0 skips. Remote GitHub Actions CI and real ARM64/WAN target measurements remain `NOT VERIFIED` from this offline environment.

---

## 2. Evidence Classification Legend

Every claim in this report carries one or more of the following evidence labels:

| Label | Meaning |
| --- | --- |
| `SOURCE VERIFIED` | Confirmed by direct inspection of repository source code and git diff. |
| `TEST VERIFIED` | Confirmed by deterministic automated unit/integration test execution in this environment. |
| `LOCAL_CPU` | Measured directly on local Linux x86_64 host CPU (`gzip -1` / `zlib` decompress). |
| `SYNTHETIC` | Modeled mathematically from measured payload sizes and CPU timings under explicit bandwidth/RTT assumptions. |
| `SIMULATED` | Verified using mocked SSH/subprocess adapters or fault-injection doubles. |
| `REAL_TARGET_MEASURED` | Measured over an actual remote SSH link to a physical target device (none collected in this offline sandbox). |
| `NOT VERIFIED` | Could not be verified in this environment due to explicit environmental constraints (offline sandbox, no GitHub API access, no `mcp>=2.0`/`gdb`/`docker`). |

---

## 3. Finding 1 — Memory Slice Coalescing Correctness

### Audit Finding (`SOURCE VERIFIED`)
In `extractor/target_adapter.py`, `_coalesce_memory_slices()` previously merged adjacent slices whenever `gap <= max_gap` (default 256 bytes) regardless of virtual memory area (VMA) boundaries. Merging across unmapped gaps, guard pages (`---p`), or different permission boundaries could convert two individually readable slices into a single failed or partial remote memory read.

### Fix Implemented (`SOURCE VERIFIED`, `TEST VERIFIED`)
- **Mapping-Aware Coalescing (`extractor/target_adapter.py`):**
  - Updated `_coalesce_memory_slices(slices, max_gap=256, max_merged_size=COLLECTOR_MAX_SLICE, mappings=None)` to require that positive gaps (`gap > 0`) are merged **only** when both the current merged span and the next slice fall strictly inside the exact same readable mapping (`start <= addr` and `end >= addr + length` with `'r'` permission).
  - When `mappings` is `None` or empty, effective `max_gap` is forced to `0`, coalescing only duplicates, overlaps, and strictly contiguous slices (`gap <= 0`).
  - Added `_cached_readable_mappings(pid)` to reuse already-cached `/proc/<pid>/maps` entries without issuing extra remote SSH round trips.
- **Bounded Individual-Slice Fallback (`extractor/target_adapter.py`):**
  - Extracted `_read_batch_raw_shell(pid, target_slices)` and updated `read_memory_batch()` so that if a multi-member merged slice fails (`status != "OK"`) or returns fewer bytes than required for a member slice (and the failure is **not** an SSH transport/timeout error), `read_memory_batch()` executes a single non-recursive individual-read fallback for the affected original slices, bounded to at most 32 slices and gated on `remaining_deadline_sec() > 0.05`.
  - Original slice order, slice status, error classification, and physical-read accounting (`_record_physical_read()`) are preserved.

### Verification (`TEST VERIFIED`, `SIMULATED`)
- `TestFinding1MemorySliceCoalescingCorrectness` in `tests/test_remote_collection_correctness_closure.py` (3/3 PASS):
  - `test_unknown_mappings_only_coalesces_duplicates_overlaps_and_contiguous`
  - `test_same_readable_mapping_merges_gap_but_different_or_guard_mapping_never_merges`
  - `test_bounded_individual_fallback_recovers_readable_slices_when_merged_read_fails`
- Updated `tests/test_remote_connection_resilience_and_coalescing.py` to pass explicit same-VMA mappings where positive-gap coalescing is asserted (all tests PASS).

---

## 4. Finding 2 — Remote ELF Image Negative Cache

### Audit Finding (`SOURCE VERIFIED`)
In `extractor/remote_module_images.py`, `RemoteImageResolver.__call__()` stored `None` in the module-global `_CACHE` (30-second TTL) whenever `adapter.read_target_file()` returned `None`. Because `read_target_file()` returns `None` for both permanent failures (missing file, permission denied) and transient SSH failures (timeout, connection reset, transport error, cancellation), a transient transport glitch poisoned symbol/image resolution for 30 seconds across retries.

### Fix Implemented (`SOURCE VERIFIED`, `TEST VERIFIED`)
- Added `self._last_file_read_error: Optional[Dict[str, Any]] = None` to `RemoteSshTargetAdapter.__init__` and populated it with structured `category` (`FILE_MISSING`, `PERMISSION_DENIED`, `INVALID_DATA`, `TIMEOUT`, `TRANSPORT_ERROR`, `CANCELLED`, `AUTH_FAILURE`, etc.) on every failure path in `read_target_file()`.
- Updated `RemoteImageResolver.__call__()` to inspect `getattr(self.adapter, "_last_file_read_error", None)` when `read_target_file()` returns `None`:
  - **Do NOT negative-cache:** `TIMEOUT`, `TRANSPORT_ERROR`, `CANCELLED`, unknown/missing transient error categories, or raised exceptions.
  - **Negative-cache only confirmed permanent failures:** `FILE_MISSING`, `PERMISSION_DENIED`, `INVALID_DATA`, oversized binary exceeding `max_bytes`, or non-ELF magic bytes.
  - Preserved thread safety under `_CACHE_LOCK` for concurrent resolver calls.

### Verification (`TEST VERIFIED`, `SIMULATED`)
- `TestFinding2RemoteElfImageNegativeCache` in `tests/test_remote_collection_correctness_closure.py` (3/3 PASS):
  - `test_transient_none_return_from_read_target_file_does_not_poison_cache`
  - `test_permanent_missing_permission_oversize_and_non_elf_are_negative_cached`
  - `test_concurrent_resolver_calls_do_not_corrupt_cache`

---

## 5. Finding 3 — Gzip Pipeline Error Semantics

### Audit Finding (`SOURCE VERIFIED`)
In `extractor/target_adapter.py`, `read_target_file()` previously piped `head -c N path | gzip -c | base64` inside POSIX `sh`. Without `pipefail`, a failing `head` on a missing or unreadable file still passed 0 bytes to `gzip`, which emitted a valid 20-byte empty gzip header and exited `0`, causing `read_target_file()` to return `b""` instead of `None` and misclassifying missing/unreadable files as empty files.

### Fix Implemented (`SOURCE VERIFIED`, `TEST VERIFIED`)
- Rewrote the POSIX `sh` command in `RemoteSshTargetAdapter.read_target_file()` with zero target-side Python dependency and optional `gzip`:
  1. Explicit pre-checks before running the pipeline:
     - `[ ! -e path ]` -> `@@ERR:FILE_MISSING` -> returns `None`, `_last_file_read_error["category"] = "FILE_MISSING"`
     - `[ ! -r path ]` -> `@@ERR:PERMISSION_DENIED` -> returns `None`, `_last_file_read_error["category"] = "PERMISSION_DENIED"`
     - `[ -d path ]` or `head -c 1 path >/dev/null 2>&1` failure -> `@@ERR:PIPELINE_FAIL` -> returns `None`, `_last_file_read_error["category"] = "INVALID_DATA"`
  2. For `n_bytes >= 8192`: uses `gzip -1 -c` (fast compression) when `command -v gzip` succeeds (`@@GZ`), automatically falling back to `@@RAW` (or `@@EMPTY` for 0-byte readable files) when `gzip` is absent.
  3. For `n_bytes < 8192`: uses `@@RAW` (or `@@EMPTY` for 0-byte readable files).
  4. Handles `/proc` virtual files (where `st_size == 0` but content is non-empty) correctly because `head -c 1` succeeds and `head -c N` reads actual bytes.
  5. Retains backwards compatibility with plain base64 mock outputs while returning `None` (`INVALID_DATA`) on corrupt base64, corrupt gzip, empty remote stdout, or `@@ERR:PIPELINE_FAIL`.

### Verification (`TEST VERIFIED`)
- `TestFinding3GzipPipelineErrorSemantics` in `tests/test_remote_collection_correctness_closure.py` (2/2 PASS):
  - `test_real_posix_sh_distinguishes_missing_unreadable_empty_and_valid_gzip_files` (executed directly against real `/bin/sh`, `head`, `gzip -1`, and `base64` on local temp files)
  - `test_pipeline_failure_and_corrupt_base64_and_ssh_failure_return_none_with_category`
- Existing `tests/test_remote_transfer_compression_and_edge_cases.py`: all tests PASS.

---

## 6. Compression Performance Validation (`LOCAL_CPU` + `SYNTHETIC`)

Measured on local Linux x86_64 host (2 vCPUs, Python 3.11.2, `gzip -1` level 1) comparing raw base64 (`@@RAW`) vs gzip-1 base64 (`@@GZ`). Network transfer times are **synthetic models** (`payload_bytes * 8 / bandwidth_bps + rtt_ms`) added to measured local compress + decompress CPU time. No `REAL_TARGET_MEASURED` WAN/ARM64 numbers were collected in this offline environment.

| Payload | Raw Bytes | Base64 Raw Bytes | Base64 `gzip -1` Bytes | Wire Ratio (`gz/raw`) | Local `gzip -1` CPU (`LOCAL_CPU`) | Local `gunzip` CPU (`LOCAL_CPU`) | Synthetic 1 Mbps / 50 ms RTT (`RAW` vs `GZ`) | Synthetic 100 Mbps / 5 ms RTT (`RAW` vs `GZ`) |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `ELF /bin/ls` | 151,344 | 201,792 | 96,028 | 0.48 | 2.21 ms | 0.84 ms | 1,664.3 ms vs 821.3 ms | 21.1 ms vs 15.7 ms |
| `ELF libc.so.6` (first 1 MB) | 1,048,576 | 1,398,104 | 737,104 | 0.53 | 15.81 ms | 6.37 ms | 11,234.8 ms vs 5,969.0 ms | 116.8 ms vs 86.2 ms |
| Small 4 KB (below 8 KB threshold) | 4,096 | 5,464 | 92 | 0.02 | 0.06 ms | 0.02 ms | 93.7 ms vs 50.8 ms | 5.4 ms vs 5.1 ms |
| Threshold 8 KB | 8,192 | 10,924 | 124 | 0.01 | 0.02 ms | 0.01 ms | 137.4 ms vs 51.0 ms | 5.9 ms vs 5.0 ms |
| Compressible 64 KB | 65,536 | 87,384 | 708 | 0.01 | 0.10 ms | 0.03 ms | 749.1 ms vs 55.8 ms | 12.0 ms vs 5.2 ms |
| Incompressible 64 KB (`os.urandom`) | 65,536 | 87,384 | 87,432 | 1.00 | 0.95 ms | 0.03 ms | 749.1 ms vs 750.4 ms | 12.0 ms vs 13.0 ms |
| Large 1 MB ELF-like | 1,048,576 | 1,398,104 | 8,952 | 0.01 | 1.32 ms | 0.91 ms | 11,234.8 ms vs 123.8 ms | 116.8 ms vs 7.9 ms |

### Engineering Assessment (`LOCAL_CPU`, `SYNTHETIC`)
- On real stripped ELF binaries (`/bin/ls`, `libc.so.6`), `gzip -1` cuts base64 wire volume roughly in half (0.48–0.53x), saving ~0.84 s on `/bin/ls` and ~5.27 s on 1 MB of `libc.so.6` over a synthetic 1 Mbps link, and still nets positive savings even at 100 Mbps / 5 ms RTT.
- On incompressible 64 KB random payloads, `gzip -1` adds only +48 B (+0.05%) and +0.98 ms total CPU time (+1.3 ms at 1 Mbps, +1.0 ms at 100 Mbps).
- Conclusion: The 8 KB threshold with `gzip -1` is well-calibrated; adaptive compression heuristics are unnecessary complexity.

---

## 7. Connection Resilience & Failure Classification Audit

Verified in `extractor/target_adapter.py` (`SOURCE VERIFIED`, `TEST VERIFIED`, `SIMULATED`):
- **Permanent failures fast-fail cleanly:** Authentication failure (`Permission denied (publickey)`), host key verification failure, and DNS/hostname resolution failure trigger immediate per-adapter fast-fail without retry-loop stalls.
- **Transient failures are never permanently cached:** SSH timeouts (`TIMEOUT`) and connection resets (`TRANSPORT_ERROR`) are excluded from permanent adapter-level fast-fail caching and from `RemoteImageResolver` global negative caching (`TestPhase3ConnectionResilienceGaps.test_timeout_and_connection_reset_never_cached_permanently` PASS).
- **Cross-adapter isolation:** Per-adapter permanent failure state (`_permanent_ssh_failure`) is instance-scoped and cannot contaminate separate adapter instances or subsequent sessions.

---

## 8. Regression & Static Verification Summary

All local verification commands executed on the final patched tree (`TEST VERIFIED`):

| Verification Step | Command / Scope | Result |
| --- | --- | --- |
| Python syntax check | `python3 -m py_compile` on all 5 modified/added Python files | PASS |
| Native C collector build | `make -C target/collector all` (GCC 12.2.0, `-Wall -Wextra -std=c99`) | PASS (0 warnings, 0 errors) |
| Native C crypto self-test | `./target/collector/test_crypto --selftest` | PASS (FIPS 180-4 & RFC 4231) |
| New closure suite | `tests/test_remote_collection_correctness_closure.py` | 9/9 PASS (0.029 s) |
| Core remote, collector, adversarial & CI parity suites (12 modules) | `test_remote_collection_correctness_closure`, `test_remote_connection_resilience_and_coalescing`, `test_remote_transfer_compression_and_edge_cases`, `test_remote_scheduler_deadline_and_cancellation`, `test_remote_diagnostics_performance`, `test_phase2_remote_performance`, `test_remote_collection_bounds_and_isolation`, `test_remote_resilience_and_long_diagnosis`, `test_finalization_review2_adversarial`, `test_final_product_stability_and_edge_cases`, `test_target_collector`, `test_ci_workflow_parity` | 157/157 PASS (17.168 s, 0 skipped) |
| Phase 2.0-A.3.17 / A.3.18 / A.3.19 durability & recovery suites (9 modules) | `tests/test_phase2_0_a_3_17_*.py`, `test_phase2_0_a_3_18_persistence_failure_closure.py`, `test_phase2_0_a_3_19_durable_commit_semantics.py` | 64/64 PASS (2.710 s, 0 skipped) |
| **Combined Total** | **21 test modules** | **221/221 PASS (0 failed, 0 errors, 0 skipped)** |

---

## 9. CI Workflow Parity (`SOURCE VERIFIED`, `TEST VERIFIED`)

- Added step `Run Remote Collection Correctness and Compression Closure Tests` (`python3 scripts/run_unittest.py tests/test_remote_collection_correctness_closure.py`) to `ci/workflows/test.yml` and synchronized byte-for-byte to `.github/workflows/test.yml`.
- Verified parity via `tests/test_ci_workflow_parity.py` (PASS).

---

## 10. Changed Files Inventory (`SOURCE VERIFIED`)

| File | Change Type | Purpose |
| --- | --- | --- |
| `extractor/target_adapter.py` | Modified | Mapping-aware `_coalesce_memory_slices()`, `_cached_readable_mappings()`, `_read_batch_raw_shell()`, bounded individual fallback in `read_memory_batch()`, POSIX `sh` pre-checked `read_target_file()` with `gzip -1` and structured `_last_file_read_error`. |
| `extractor/remote_module_images.py` | Modified | Skip global `_CACHE` negative caching on transient file-read errors (`TIMEOUT`, `TRANSPORT_ERROR`, `CANCELLED`, exceptions); cache only confirmed permanent failures. |
| `tests/test_remote_collection_correctness_closure.py` | Added | 9 targeted regression tests covering Findings 1, 2, 3, real `/bin/sh` pipeline semantics, concurrency, and Phase 3 transient timeout/reset isolation. |
| `tests/test_remote_connection_resilience_and_coalescing.py` | Modified | Pass explicit same-VMA mappings in positive-gap coalescing assertions to match strict VMA-safety invariant. |
| `ci/workflows/test.yml` | Modified | Register `tests/test_remote_collection_correctness_closure.py` in CI test workflow. |
| `.github/workflows/test.yml` | Modified | Byte-for-byte mirror of `ci/workflows/test.yml`. |
| `docs/REMOTE_COLLECTION_CORRECTNESS_AND_COMPRESSION_CLOSURE.md` | Added | This closure report. |

---

## 11. Unverified Items & Explicit Limitations (`NOT VERIFIED`)

1. **Remote GitHub Actions CI (`NOT VERIFIED`):** This offline sandbox has no outbound network access to `https://github.com/zeeny2park/dynamicState`, so remote GitHub Actions workflow runs for the patch cannot be triggered or observed here.
2. **Real-Target WAN / Embedded ARM64 Transfer Latency (`NOT VERIFIED`):** Compression timings on an actual ARM64 embedded target over a live SSH link were not measured; only `LOCAL_CPU` timings and `SYNTHETIC` network models are reported.
3. **Optional Dependencies (`NOT VERIFIED`):** `mcp>=2.0`, `pytest`, `hypothesis`, `gdb`, and `docker` are not installed in this environment, so MCP integration, GDB 9.2 compatibility, and containerized remote SSH tests must run in GitHub Actions after applying the patch.

---

## 12. Patch Verification & Application Instructions

The incremental patch `dynamicstate-remote-correctness-closure.patch` is generated cleanly against the local mirror of `b691c8ef8459fefeb9e492e3cec5036d4c4bd933` (`920844f`) with native collector build artifacts cleaned prior to diffing, and verified via `git apply --check` on a clean archive checkout.

Apply to the repository at `b691c8ef8459fefeb9e492e3cec5036d4c4bd933`:

```bash
git apply --check dynamicstate-remote-correctness-closure.patch
git apply dynamicstate-remote-correctness-closure.patch
```

---

## 13. Closure Verdict

**Conditional Closure — Ready to Apply and Run Remote CI (`SOURCE VERIFIED`, `TEST VERIFIED`).**
All three audited correctness defects (VMA-unsafe memory slice coalescing, transient negative-cache poisoning in `RemoteImageResolver`, and silent `b""` masking in the POSIX `sh` gzip transfer pipeline) are fixed and verified by 221/221 passing local tests plus native C collector self-tests. Final sign-off requires applying the incremental patch to `zeeny2park/dynamicState` and confirming green GitHub Actions runs (`Full Test Suite` and `GDB 9.2 Compatibility`).

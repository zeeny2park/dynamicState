# Embedded target verification matrix (IMP-014)

## Supported scope

The product targets **x86-64 and ARM64 (aarch64), little-endian, glibc**.  x86-64 is verified natively by the regular CI
job (`ci/workflows/test.yml`), so the QEMU matrix covers the one target that CI cannot run natively: ARM64 + glibc.

**ARM32 and musl are out of scope.**  They are not part of this matrix and are not diagnosed: `extractor/target_abi.py`
refuses them explicitly (`NOT_SUPPORTED_ON_TARGET` / `unsupported_on_target`) instead of guessing, so a wrong answer is
never produced if the tool is pointed at such a target (synthetic coverage: `tests/test_target_abi_detection.py`).  The
collector is shipped for `aarch64` and `x86_64` only; for any other `uname -m` the deploy falls back to the shell path
and never uploads a binary of the wrong architecture.

## What the matrix does

It boots a real guest under QEMU system emulation (1 vCPU, 128 MB RAM, TCG, user-mode networking, SSH forwarded on
`127.0.0.1` only) and drives the product's remote path from the host: `RemoteSshTargetAdapter` (collector deploy,
daemon channel, `dd` fallback), ABI detection, `RuntimeEvidenceProvider.collect_for_recipe` (deadlock recipe),
`HeapWalker`.

| entry | CPU / machine | userland | libc | BusyBox |
|---|---|---|---|---|
| `aarch64-glibc` | cortex-a72, `virt`, qemu-system-aarch64 | Debian trixie (libc6 2.41) | glibc | Debian busybox-static 1.37 |

The harness is generic (entry table in `scripts/qemu_matrix/entries.py`, checks, result schema, cleanup); another
glibc x86-64 / ARM64 entry can be added as one table row plus its expected support row.

The guest is an initramfs only (kernel = Debian trixie `linux-image-6.12.107+deb13-arm64`; dropbear sshd; init script in
`scripts/qemu_matrix/images.py`).  The shell tools the product calls on the target (`dd`, `tail`, `head`, `base64`,
`readlink`, `tr`, `cat`) are **BusyBox applets** - no GNU coreutils variant was tested.

## How to run

```bash
sudo apt-get install -y qemu-system-arm gcc-aarch64-linux-gnu gcc-x86-64-linux-gnu openssh-client dpkg-dev xz-utils
make -C target/collector dist
python3 -m scripts.qemu_matrix prepare          # explicit: downloads + verifies + builds the guest image (cached)
python3 -m scripts.qemu_matrix run              # all entries; --out DIR; --timeout S
python3 -m scripts.qemu_matrix summary DIR      # markdown table from result JSONs
```

`qemu-system-arm` is the Debian/Ubuntu package that provides both `qemu-system-arm` and `qemu-system-aarch64`; the
harness uses only `qemu-system-aarch64` (no `qemu-img`, `qemu-system-misc` or `qemu-utils` needed).

Cache: `~/.cache/dynamicstate-qemu/` (override `DYNAMICSTATE_QEMU_CACHE`); everything there is derived and
disposable.  The throwaway SSH key is generated per run in a temp dir inside the cache and deleted afterwards.
Results: `<out>/<entry>.json` (schema `dynamicstate.qemu_matrix.v1`, `scripts/qemu_matrix/results.py`),
`host.json` (host versions, host deadlock reference, download manifest) and `summary.md`.  Every guest is torn
down in `finally` (SIGTERM, then SIGKILL on the process group, plus atexit/SIGINT/SIGTERM handlers and a per-entry
watchdog timer); the run ends by asserting that no `qemu-system*` process is left.

Tests: `tests/test_imp014_qemu_matrix_logic.py` (no QEMU; argument building, memory limits, result schema,
teardown with a fake VM, initramfs/cpio, download verification), `tests/test_imp014_find_processes_regression.py`,
`tests/test_imp014_qemu_matrix_qemu.py` (boots the guest; skipped with a reason unless qemu, the cross compiler,
collector binaries and the cached image exist; never downloads).  CI: `ci/workflows/embedded-matrix.yml` (manual +
weekly, not on push).  Real board: `docs/EMBEDDED_BOARD_RUN.md`.

## Checks and statuses

PASS / FAIL / BLOCKED (cannot run because of a known product limitation) / SKIPPED.  (`UNSUPPORTED-AS-EXPECTED` and the
`known_defect` tag remain in the result schema but no check produces them for the supported scope.)

C1 deploy (arch dir chosen from `uname -m`, static ELF, `--version` equals `target/collector/VERSION`) + slice read of a
known buffer; C1b noexec primary location falls back; C2a daemon channel (30 reads, exactly 1 collector process on the
target, 0 after close); C2b no-collector fallback with BusyBox `dd`/`tail`/`head` on unaligned and page-crossing
ranges (singly and batched) and an unmapped address; C3 ABI detection and the support table; C4a deadlock diagnosis of
`proc_thread_circular_deadlock.c` (`-g -pthread`, debug ELF on the host, vs. the same fixture diagnosed natively on the
host); C4b remote heap walk; C4c futex syscall name; C5 cost; C6 process discovery / identity / maps.

## Result of the committed run (`docs/test_baseline/qemu_matrix/`, host aarch64 4 cores, no KVM, QEMU 8.2.2)

| check | aarch64-glibc |
|---|---|
| C1 collector deploy + slice read | PASS (aarch64, 857 472 B, collector v1.1.0) |
| C1b noexec fallback location | PASS |
| C2a daemon channel | PASS |
| C2b no-collector BusyBox fallback | PASS |
| C3 ABI detection | PASS aarch64/64/little/glibc |
| C4a deadlock | PASS: SUPPORTED, locks g_mutex_a/g_mutex_b = host |
| C4b remote heap walk | BLOCKED (see open items) |
| C4c futex syscall name | PASS (threads reported as futex, blocked, with sp/pc) |
| C5 cost | PASS |
| C6 discovery / identity / maps | PASS |
| overall | PASS |
| entry wall time | 133 s |

Cost on the constrained TCG guest (absolute times are pessimistic; the ratios matter):

| | deadlock diagnosis | 100 reads: daemon | 100 reads: collector per call | 100 reads: BusyBox dd | 20 reads, identity pinned (daemon) |
|---|---|---|---|---|---|
| aarch64-glibc | 19.9 s / 70 ssh cmds | 0.55 s / 1 | 25.3 s / 100 | 28.6 s / 100 | 21.5 s / 81 |

A matrix run takes about 2.5 minutes after the image is cached (boot to SSH about 9 s).

## Open items and findings

* **BLOCKED (open product gap)** remote heap walk on aarch64+glibc (C4b): `HeapWalker` answers
  `INCONCLUSIVE_ABI_UNDETECTED` because it cannot identify the glibc version of a remote target (the version probe is
  local-only).  Honest answer, but the supported combination cannot be exercised remotely until this is fixed.
* **Fixed** - `RemoteSshTargetAdapter.find_processes` could never work: the remote script contained a raw NUL
  (`'\000'`) and a raw newline in `tr` arguments, so every call failed on every target.  Fixed in
  `extractor/target_adapter.py`; regression `tests/test_imp014_find_processes_regression.py`.
* Cost finding: with a pinned identity every `read_memory` re-reads the identity (about 4 ssh commands, about 1 s per
  read on the guest); the unpinned daemon read costs about 5 ms.
* Not verified: real silicon (see `docs/EMBEDDED_BOARD_RUN.md`), KVM, GNU-coreutils userland, big-endian, x86 host
  running the QEMU workflow (the GitHub runner is x86_64 with QEMU 6.2; the workflow is untested there), the
  Release/GPG signature of the Debian indexes (integrity relies on HTTPS + SHA256 chains).

## What is downloaded

System packages: `qemu-system-arm` (provides `qemu-system-aarch64`) and `gcc-aarch64-linux-gnu`,
`gcc-x86-64-linux-gnu` (collector builds), `dpkg-dev`, `xz-utils`, `openssh-client`.

Downloads (13 files, about 107 MB): only the files the ARM64 guest needs (Debian trixie arm64: kernel deb,
`busybox-static`, `dropbear-bin`, `libc6` and its library closure, plus the `Release` and `Packages.xz` indexes).  All go to the cache, none are
committed; the full URL / sha256 / size list is in `docs/test_baseline/qemu_matrix/host.json`.  Debian files are
checked against `Packages.xz`, which is checked against `Release`.

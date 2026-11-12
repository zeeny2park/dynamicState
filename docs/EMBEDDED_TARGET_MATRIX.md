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
host); C4b remote heap walk; C4c futex syscall name; C4d the one-call `diagnose(target=...)` entry point (IMP-006) against
the guest's deadlock fixture over SSH, compared with `diagnose()` on the same fixture natively on the host (verdict,
categories, lock names; collector deploy decision, ABI/glibc identification and the recorded remote gaps are exercised
on the way); C5 cost; C6 process discovery / identity / maps.

## Result of the committed run (`docs/test_baseline/qemu_matrix/`, host aarch64 4 cores, no KVM, QEMU 8.2.2)

| check | aarch64-glibc |
|---|---|
| C1 collector deploy + slice read | PASS (aarch64, 923 648 B, collector v1.3.0) |
| C1b noexec fallback location | PASS |
| C2a daemon channel | PASS |
| C2b no-collector BusyBox fallback | PASS |
| C3 ABI detection | PASS aarch64/64/little/glibc |
| C4a deadlock | PASS: SUPPORTED, locks g_mutex_a/g_mutex_b = host |
| C4b remote heap walk | PASS: OK, 3 chunks in 1 arena (was BLOCKED: glibc version not identified remotely) |
| C4c futex syscall name | PASS (threads reported as futex, blocked, with sp/pc) |
| C4d `diagnose()` over SSH vs. host | PASS: CONFIRMED_FAULT, DEADLOCK_INDICATORS, locks g_mutex_a/g_mutex_b = host; 20.9 s, 8 ssh commands + 429 daemon exchanges, 491 KB read, zero-stop (before IMP-022: 215.8 s, 797 ssh commands, 16.7 MB on the wire) |
| C5 cost | PASS |
| C6 discovery / identity / maps | PASS |
| overall | PASS |
| entry wall time | 183 s (was 356 s before IMP-022) |

Cost on the constrained TCG guest (absolute times are pessimistic; the ratios matter):

| | deadlock diagnosis | 100 reads: daemon | 100 reads: collector per call | 100 reads: BusyBox dd | 20 reads, identity pinned (daemon) |
|---|---|---|---|---|---|
| aarch64-glibc | 4.2 s / 2 ssh cmds | 0.77 s / 1 | 44.1 s / 100 | 42.2 s / 100 | 0.14 s / 0 (was 20.8 s / 81) |

A matrix run takes about 3 minutes after the image is cached (boot to SSH about 9 s); C4d is about 21 s.  (The
per-call rows vary with host load: the same run measured 25 s / 24 s before; the ratios matter.)

## Open items and findings

* **Fixed** - remote heap walk (C4b, was BLOCKED): the glibc version was read from the mapped libc through the
  collector as designed, but the collector returns at most 64 KiB per slice and the host asked for whole segments
  (up to 4 MiB): every large read came back `PARTIAL` and the walker concluded "version not identified".  The adapter now
  splits large slices into 64 KiB pieces and reassembles them (`COLLECTOR_MAX_SLICE`), which also fixes every other large
  remote read (heap regions).  The banner is now read backwards in 128 KiB chunks and cached per session.
* **Fixed** - the remote deadlock result was INCONCLUSIVE for struct-member mutexes: the lock-candidate widening
  (`variable.member`, futex addresses) skipped remote targets; it now takes the per-thread syscalls from the collector's
  thread sample.
* **Fixed (IMP-022)** - a remote diagnosis was chatty: 797 ssh commands / 216 s for one deadlock diagnosis on the guest.
  The adapter's per-session command log (`collection_impact["remote_commands"]`, printed by C4d) attributed them to:
  identity re-verification 628 (79 %: per read `readlink` + 64 KiB ELF header + `/proc/PID/stat` + `boot_id`, 169 of
  them carrying the 64 KiB header = 15 MB), `/proc/PID/maps` 76, liveness 51, `/proc/PID/status` 23, file reads/stat 11,
  other 8; the daemon channel itself served 134 exchanges in 3 s.  Now: the collector (1.3.0) has `IDENT <pid> [HDR]`
  (stat, exe link, exe fingerprint ino:size:mtime, boot_id, machine, optional ELF header) and `PROCFILE <pid> <maps|status|
  stat|limits|comm>`; identity, verification, maps, status, liveness and those file reads are one daemon exchange each,
  the ELF header is transferred and parsed once per executable image (cache key path + fingerprint), and without the
  new commands (old collector / no collector) identity is ONE shell command instead of four.  Verification still
  compares start time, executable, boot_id and now the executable's inode/size/mtime on every read (strict, no TTL).
  Result: 8 ssh commands + 429 daemon exchanges, 20.9 s, 2.0 MB on the wire.  Remaining ssh: deploy probes (uname,
  version, copy), the daemon open, `ls -l /proc/PID/fd` and library-image reads (5 `other`).  OpenSSH
  `ControlMaster` reuse is now auto-enabled for the real `ssh` binary (off when a command runner is injected or
  `DYNAMICSTATE_SSH_CONTROLMASTER=0`, silent fallback when ssh rejects the options); the matrix harness injects its own
  counting runner, so its numbers do not include it, and it was not measured on a real network.  The default remote
  budget (120 s) and the 10x remote heap-walk wall cap are unchanged.
* Remote gaps that stay (reported in `not_covered` as `remote_limitation`, never guessed): TLS/TCB discovery, stacks of
  threads that were running, symbols of libraries that cannot be fetched.
* **Fixed** - `RemoteSshTargetAdapter.find_processes` could never work: the remote script contained a raw NUL
  (`'\000'`) and a raw newline in `tr` arguments, so every call failed on every target.  Fixed in
  `extractor/target_adapter.py`; regression `tests/test_imp014_find_processes_regression.py`.
* Cost finding (fixed by IMP-022): with a pinned identity every `read_memory` re-read the identity (about 4 ssh commands,
  about 1 s per read on the guest); it is now one daemon exchange, about 7 ms per read with the pin.
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

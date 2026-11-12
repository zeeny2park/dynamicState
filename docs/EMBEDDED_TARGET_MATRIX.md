# Embedded target verification matrix (IMP-014)

Until this item, ARM32 and musl were only exercised with synthetic inputs.  The matrix boots real guests under
QEMU system emulation (1 vCPU, 128 MB RAM, TCG, user-mode networking, SSH forwarded on `127.0.0.1` only) and drives
the product's remote path from the host: `RemoteSshTargetAdapter` (collector deploy, daemon channel, `dd`
fallback), ABI detection, `RuntimeEvidenceProvider.collect_for_recipe` (deadlock recipe), `HeapWalker`.

| entry | CPU / machine | userland | libc | BusyBox |
|---|---|---|---|---|
| `arm32-glibc` | cortex-a15, `virt,highmem=off`, qemu-system-arm | Debian trixie (libc6 2.41) | glibc | Debian busybox-static 1.37 |
| `arm32-musl` | same | Alpine v3.22 minirootfs (musl 1.2.5) | musl | Alpine BusyBox 1.37 |
| `aarch64-glibc` | cortex-a72, `virt`, qemu-system-aarch64 | Debian trixie | glibc | Debian busybox-static 1.37 |

Guests are an initramfs only (kernel = Debian trixie `linux-image-6.12.107+deb13-{armmp,arm64}`; dropbear sshd; init
script in `scripts/qemu_matrix/images.py`).  The shell tools the product calls on the target (`dd`, `tail`, `head`,
`base64`, `readlink`, `tr`, `cat`) are **BusyBox applets in every entry** - no GNU coreutils variant was tested.

## How to run

```bash
sudo apt-get install -y qemu-system-arm gcc-arm-linux-gnueabihf gcc-aarch64-linux-gnu openssh-client dpkg-dev xz-utils
make -C target/collector dist
python3 -m scripts.qemu_matrix prepare          # explicit: downloads + verifies + builds guest images (~185 MB, cached)
python3 -m scripts.qemu_matrix run              # all entries; or: run arm32-musl; --out DIR; --timeout S
python3 -m scripts.qemu_matrix summary DIR      # markdown table from result JSONs
```

Cache: `~/.cache/dynamicstate-qemu/` (override `DYNAMICSTATE_QEMU_CACHE`); everything there is derived and
disposable.  The throwaway SSH key is generated per run in a temp dir inside the cache and deleted afterwards.
Results: `<out>/<entry>.json` (schema `dynamicstate.qemu_matrix.v1`, `scripts/qemu_matrix/results.py`),
`host.json` (host versions, host deadlock reference, download manifest) and `summary.md`.  Every guest is torn
down in `finally` (SIGTERM, then SIGKILL on the process group, plus atexit/SIGINT/SIGTERM handlers and a per-entry
watchdog timer); the run ends by asserting that no `qemu-system*` process is left.

Tests: `tests/test_imp014_qemu_matrix_logic.py` (no QEMU; argument building, memory limits, result schema,
teardown with a fake VM, initramfs/cpio, download verification), `tests/test_imp014_find_processes_regression.py`,
`tests/test_imp014_qemu_matrix_qemu.py` (boots the guests; skipped with a reason unless qemu, cross compilers,
collector binaries and cached images exist; never downloads).  CI: `ci/workflows/embedded-matrix.yml` (manual +
weekly, not on push).  Real board: `docs/EMBEDDED_BOARD_RUN.md`.

## Checks and statuses

PASS / FAIL / UNSUPPORTED-AS-EXPECTED (the support table answered "not supported" explicitly and no value was
produced) / BLOCKED (cannot run because of a known product limitation) / SKIPPED.  A FAIL carrying a
`known_defect` tag does not fail the run.

C1 deploy (arch dir chosen from `uname -m`, static ELF, `--version` equals `target/collector/VERSION`) + slice read of a
known buffer; C1b noexec primary location falls back; C2a daemon channel (30 reads, exactly 1 collector process on the
target, 0 after close); C2b no-collector fallback with BusyBox `dd`/`tail`/`head` on unaligned and page-crossing
ranges (singly and batched) and an unmapped address; C3 ABI detection and the support table; C4a deadlock diagnosis of
`proc_thread_circular_deadlock.c` (`-g -pthread`, debug ELF on the host, vs. the same fixture diagnosed natively on the
host); C4b heap walk gating; C4c futex syscall name; C4d recipe verdict on an unsupported target; C5 cost; C6 process
discovery / identity / maps.

## Result of the committed run (`docs/test_baseline/qemu_matrix/`, host aarch64 4 cores, no KVM, QEMU 8.2.2)

| check | arm32-glibc | arm32-musl | aarch64-glibc |
|---|---|---|---|
| C1 collector deploy + slice read | PASS (arm, 567 328 B, v1.0.0) | PASS (arm, v1.0.0) | PASS (aarch64, 857 088 B, v1.0.0) |
| C1b noexec fallback location | PASS | PASS | PASS |
| C2a daemon channel | PASS | PASS | PASS |
| C2b no-collector BusyBox fallback | PASS (7 ranges) | PASS | PASS |
| C3 ABI detection | PASS arm/32/little/glibc | PASS arm/32/little/musl | PASS aarch64/64/little/glibc |
| C4a deadlock | UNSUPPORTED-AS-EXPECTED (mutex_owner NOT_SUPPORTED_ON_TARGET, no owner TID, no cycle) | UNSUPPORTED-AS-EXPECTED | PASS: SUPPORTED, locks g_mutex_a/g_mutex_b = host |
| C4b heap-walk gating | UNSUPPORTED-AS-EXPECTED (UNSUPPORTED_ALLOCATOR, 0 chunks) | UNSUPPORTED-AS-EXPECTED | BLOCKED (see gaps) |
| C4c futex syscall name | BLOCKED | BLOCKED | BLOCKED |
| C4d recipe verdict on unsupported | FAIL (DEF-ARM-1) | FAIL (DEF-ARM-1) | SKIPPED |
| C5 cost | PASS | PASS | PASS |
| C6 discovery / identity / maps | PASS | PASS | PASS |
| overall | PASS | PASS | PASS |
| entry wall time | 180 s | 248 s | 168 s |

Cost on the constrained TCG guest (absolute times are pessimistic; the ratios matter):

| | deadlock diagnosis | 100 reads: daemon | 100 reads: collector per call | 100 reads: BusyBox dd | 20 reads, identity pinned (daemon) |
|---|---|---|---|---|---|
| arm32-glibc | 30.6 s / 91 ssh cmds | 0.73 s / 1 | 32.0 s / 100 | 40.6 s / 100 | 29.3 s / 81 |
| arm32-musl | 59.0 s / 91 | 1.09 s / 1 | 41.3 s / 100 | 52.6 s / 100 | 32.7 s / 81 |
| aarch64-glibc | 27.2 s / 76 | 0.65 s / 1 | 33.8 s / 100 | 37.3 s / 100 | 23.1 s / 81 |

A full matrix run takes about 10 minutes after the images are cached (boot to SSH 10-17 s; image preparation ~1 min).

## Defects and gaps found

* **Fixed** - `RemoteSshTargetAdapter.find_processes` could never work: the remote script contained a raw NUL (`'\000'`)
  and a raw newline in `tr` arguments, so every call failed with "embedded null byte" (rc -1, empty list) on every
  target, not only ARM.  Fixed in `extractor/target_adapter.py`; regression `tests/test_imp014_find_processes_regression.py`.
* **DEF-ARM-1 (not fixed; `diagnostic_recipes`/evidence provider belong to other work)** - on ARM32 (glibc and musl) the
  evidence layer correctly says `lock_owner_status = NOT_SUPPORTED_ON_TARGET`, but the deadlock recipe then evaluates
  to `CONTRADICTED` ("verified complete acyclic graph, no wait cycles") - a silent false negative.  Expected:
  INSUFFICIENT_EVIDENCE / NOT_APPLICABLE.  The matrix records it as FAIL with the defect tag (check C4d).
* **BLOCKED** futex syscall names: `RemoteSshTargetAdapter.get_threads` returns only tid/name/state (no syscall /
  wchan).  The matrix confirms the ABI table maps the guest's raw numbers (arm 240, aarch64 98) to `futex`; the
  product path cannot report them until the collector thread-info command lands.  The aarch64 deadlock is still found
  (stack-pointer scan, frames marked `scan_estimated`, no CFI unwinding remotely).
* **BLOCKED** remote heap walk on aarch64+glibc: `HeapWalker` answers `INCONCLUSIVE_ABI_UNDETECTED` because the glibc
  version of a remote target cannot be identified (version probe is local-only).  Honest answer, but the supported
  combination cannot be exercised remotely.
* Cost finding: with a pinned identity every `read_memory` re-reads the identity (about 4 ssh commands, 1.2-1.6 s per read
  on the guest); the unpinned daemon read costs 7 ms.
* Not verified: real silicon, KVM, GNU-coreutils userland, ARMv5/v6, big-endian, musl on aarch64, x86 host
  (the GitHub runner is x86_64 with QEMU 6.2; the workflow is untested there), Release/GPG signature of the
  Debian/Alpine indexes (integrity relies on HTTPS + SHA256 chains).

## What was installed and downloaded

System packages (apt, this run): `qemu-system-arm` (also provides `qemu-system-aarch64`), `qemu-system-misc`,
`qemu-utils` (the last two turned out not to be needed) and dependencies `acl libbrlapi0.8 libcacard0 libdaxctl1 libfdt1
libibverbs1 libndctl6 libpcsclite1 libpmem1 librdmacm1t64 libslirp0 liburing2 libusbredirparser1t64 qemu-system-common
qemu-system-data`.  Already present: `arm-linux-gnueabihf-gcc`, `aarch64-linux-gnu-gcc`, `x86_64-linux-gnu-gcc`.

Downloads (35 files, 184 MB, all in the cache, none committed; full URL/sha256/size list in
`docs/test_baseline/qemu_matrix/host.json`).  Debian files are checked against `Packages.xz` which is checked against
`Release`; Alpine minirootfs against the published `.sha256`; Alpine apks against the APKINDEX `C:` checksum.  Main items:

| URL | sha256 | bytes |
|---|---|---|
| deb.debian.org/debian/pool/main/l/linux/linux-image-6.12.107+deb13-armmp_6.12.107-1_armhf.deb | 9db6efc15fcc408acdc417911bdb7ac2c3ee0dd04fd1535a16b34744293a4380 | 56512584 |
| deb.debian.org/debian/pool/main/l/linux-signed-arm64/linux-image-6.12.107+deb13-arm64_6.12.107-1_arm64.deb | 20c92f3f97dd466e0400a6fcb792bde85af842fbb5e8b471370065e3de9d9fc9 | 92902468 |
| deb.debian.org/debian/pool/main/g/glibc/libc6_2.41-12+deb13u4_armhf.deb | 4fc6fed8d77d01c0dacb5fda8b880a8c8a669575936de5761b693077a6f6c2ec | 2260832 |
| deb.debian.org/debian/pool/main/g/glibc/libc6_2.41-12+deb13u4_arm64.deb | 8784eda966b189c777a384dac5ce009e8fc9b52d006926c5a013e7fa8aa688cc | 2483572 |
| dl-cdn.alpinelinux.org/alpine/v3.22/releases/armv7/alpine-minirootfs-3.22.8-armv7.tar.gz | a641f002abf617db94379110ffa798e0ed9903dbcec2bb1caa79df1fc7af8e8c | 3130793 |
| dl-cdn.alpinelinux.org/alpine/v3.22/main/armv7/musl-dev-1.2.5-r13.apk | 64cb621ca0ccf1cff50689a4bdde97a28204433c0c3ae70d590a71b99cb61e60 | 2289276 |

Plus busybox-static, dropbear-bin and their library closure (Debian), dropbear/zlib/utmps/skalibs/musl/libgcc (Alpine),
and the Release / Packages / APKINDEX files.  musl test programs are cross-compiled on the host with the Debian
cross gcc against the Alpine musl sysroot (`-nostdinc -nostdlib`, musl crt + `libc.musl-armv7.so.1`), dynamic with
PT_INTERP `/lib/ld-musl-armhf.so.1`.

# Running the matrix checks on one real board (manual procedure)

The QEMU matrix (`docs/EMBEDDED_TARGET_MATRIX.md`) executes the collector and the diagnosis path on an emulated
ARM64 (aarch64, glibc) guest.  Supported scope: x86-64 and ARM64 with glibc; ARM32 and musl boards are out of scope
(the tool refuses them explicitly, see `extractor/target_abi.py`), so this procedure is for an ARM64 glibc board.  Emulation does not prove behaviour on real silicon (timing, kernel configuration,
vendor BusyBox builds, `ptrace_scope`, read-only root filesystems).  This page is the procedure to run
the **same checks** against one physical board and to record the result.

**No real-board record exists in this repository yet.**  `docs/test_baseline/qemu_matrix/` contains emulator
results only.  The first person who runs this on a board adds the filled-in record below; do not edit the
template into a record unless the commands were actually run on the board.

## 0. Prerequisites

Board: Linux, reachable over SSH as root (or as the user that owns the test processes; same-user
`/proc/<pid>/mem` reads need `kernel.yama.ptrace_scope=0` or root), a writable directory that allows
execution (`/tmp` by default; check `mount | grep -E ' /tmp | / '` for `noexec`), `dd`, `head`, `tail`,
`base64`, `readlink`, `cat` (BusyBox is fine), and an SSH server (dropbear or OpenSSH).

Host: this repository, Python 3.10+, `ssh`, `aarch64-linux-gnu-gcc` (cross toolchain for an ARM64 board) and the
static collectors (`make -C target/collector dist`).  The board's libc must be glibc.

## 1. Collect the board facts (paste back verbatim)

```bash
ssh root@BOARD 'uname -a; cat /proc/cpuinfo | head -25; cat /proc/meminfo | head -3; cat /proc/sys/kernel/yama/ptrace_scope 2>&1;
  busybox 2>&1 | head -2; ls -l /lib/ld-* /lib/*/ld-* 2>&1; mount | grep -E " / | /tmp "; ps --help 2>&1 | head -2'
```

## 2. Build the collectors and run the checks

```bash
make -C target/collector dist
python3 -m unittest tests/test_imp014_qemu_matrix_logic.py        # harness sanity on the host

# ARM64 (aarch64) glibc board
python3 -m scripts.qemu_matrix board --host BOARD_IP --user root --key ~/.ssh/id_board \
    --arch aarch64 --cc aarch64-linux-gnu-gcc --board-name myboard-v1 \
    --notes "ARM64 SBC, Debian 12" --out board_record
```

Options: `--port`, `--workdir DIR` (exec-capable directory on the board, default `/tmp`), `--uname-m` to override the
expected `uname -m`.  The command uploads two test programs to the board, starts them, runs checks C1-C6 exactly as
in the emulator matrix, kills the programs and removes the files.  Result: `board_record/<board-name>.json`
(+ a PASS/FAIL line per check on stdout).

Things that are *expected* and not failures: `BLOCKED` for the futex-syscall check while the remote adapter has no
thread-info collector command, and `BLOCKED` for the heap walk (the heap walker cannot identify the glibc version of
a remote target; see `docs/EMBEDDED_TARGET_MATRIX.md`).

## 3. What to paste back

1. The output of step 1.
2. `board_record/<board-name>.json` (small, no secrets) - commit it as `docs/test_baseline/board_<board-name>.json`.
3. The record below, filled in.

## 4. Record template (copy; fill in only from real runs)

```markdown
### Board record: <board-name>

| field | value |
|---|---|
| date (UTC) | |
| operator | |
| board / SoC | |
| CPU arch / `uname -m` | |
| kernel (`uname -r`) | |
| RAM (MemTotal) / cores | |
| glibc version | |
| userland (BusyBox version / coreutils) | |
| sshd (dropbear/openssh) | |
| `ptrace_scope` / running as | |
| work directory + noexec? | |
| repository commit | |
| result JSON | `docs/test_baseline/board_<name>.json` |

| check | status (PASS / FAIL / BLOCKED / SKIPPED) | observed (copy `summary`) |
|---|---|---|
| C1 collector deploy + slice read | | |
| C2a daemon channel | | |
| C2b no-collector fallback (BusyBox dd/tail/head) | | |
| C3 ABI detection | | |
| C4a deadlock diagnosis | | |
| C4b remote heap walk | | |
| C4c futex syscall names | | |
| C5 cost (deadlock s / cmds; 100 reads daemon / oneshot / dd) | | |

Deviations from the emulator matrix and defects found (command, observed output, expected):
-
```

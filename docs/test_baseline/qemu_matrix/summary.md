| check | arm32-glibc | arm32-musl | aarch64-glibc |
|---|---|---|---|
| Collector deploys (arch, static, version) + slice read returns expected bytes | PASS | PASS | PASS |
| Deploy falls back to another location when the primary is noexec | PASS | PASS | PASS |
| Daemon channel: N reads, one collector process | PASS | PASS | PASS |
| No-collector fallback with the guest's BusyBox dd/tail/head, unaligned ranges | PASS | PASS | PASS |
| ABI detection via remote adapter (arch / word size / endianness / libc) | PASS | PASS | PASS |
| Deadlock diagnosis vs. host result (or explicit unsupported) | UNSUPPORTED-AS-EXPECTED | UNSUPPORTED-AS-EXPECTED | PASS |
| glibc-only checks (heap walk, mutex owner) gated | UNSUPPORTED-AS-EXPECTED | UNSUPPORTED-AS-EXPECTED | BLOCKED |
| futex waiters carry the right syscall name | BLOCKED | BLOCKED | BLOCKED |
| Recipe verdict on an unsupported target | FAIL (DEF-ARM-1) | FAIL (DEF-ARM-1) | SKIPPED |
| Collection cost (wall time, remote commands) | PASS | PASS | PASS |
| Process discovery / identity / maps via BusyBox shell tools | PASS | PASS | PASS |
| overall | PASS | PASS | PASS |
| run time (s) | 180.1 | 248.1 | 167.9 |

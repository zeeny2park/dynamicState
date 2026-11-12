| check | aarch64-glibc |
|---|---|
| Collector deploys (arch, static, version) + slice read returns expected bytes | PASS |
| Deploy falls back to another location when the primary is noexec | PASS |
| Daemon channel: N reads, one collector process | PASS |
| No-collector fallback with the guest's BusyBox dd/tail/head, unaligned ranges | PASS |
| ABI detection via remote adapter (arch / word size / endianness / libc) | PASS |
| Deadlock diagnosis vs. host result | PASS |
| Remote heap walk (glibc allocator) | PASS |
| futex waiters carry the right syscall name | PASS |
| diagnose() over SSH on the guest's deadlock fixture vs. host result | PASS |
| Collection cost (wall time, remote commands) | PASS |
| Process discovery / identity / maps via BusyBox shell tools | PASS |
| overall | PASS |
| run time (s) | 330.3 |

"""Test helper: answer the adapter's single-exchange identity probe (IMP-022) from per-command legacy mocks.

Older tests describe the target as "command text -> reply" for ``readlink``/``cat .../stat``/``boot_id``/``head -c``
(one ssh command each).  The adapter now asks for all of it in ONE shell command with ``@@SECTION`` markers;
``legacy_probe_reply`` runs the legacy responder once per original command and assembles the sectioned output.
"""
import re
from typing import Callable, Tuple

Reply = Tuple[int, str, str]


def is_ident_probe(cmd: str) -> bool:
    return "@@EXE" in cmd and "@@END" in cmd


def legacy_probe_reply(cmd: str, respond: Callable[[str], Reply]) -> Reply:
    m = re.search(r"/proc/(\d+)/exe", cmd)
    pid = m.group(1) if m else "0"
    p = f"/proc/{pid}"
    queries = [
        ("EXE", f"readlink -f {p}/exe 2>/dev/null || readlink {p}/exe 2>/dev/null"),
        ("STAT", f"cat {p}/stat 2>/dev/null"),
        ("BOOT", "cat /proc/sys/kernel/random/boot_id 2>/dev/null"),
        ("FP", f"stat -L -c %i:%s:%Y {p}/exe 2>/dev/null"),
        ("MACH", "uname -m 2>/dev/null"),
    ]
    if "@@HDR" in cmd:
        queries.append(("HDR", f"head -c 65536 {p}/exe 2>/dev/null | base64"))
    out = []
    for name, q in queries:
        rc, text, _ = respond(q)
        out.append(f"@@{name}")
        if rc == 0 and text:
            out.append(text.rstrip("\n"))
    out.append("@@END")
    return 0, "\n".join(out) + "\n", ""

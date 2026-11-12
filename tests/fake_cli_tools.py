"""Hermetic stand-ins for locally installed LLM CLI tools (gemini/agy/cline/paseo/agy-acp).

The resolver and command-builder tests used to assert that real developer-machine tools exist.  These
helpers create fake executables in a temporary HOME / PATH so the real resolution and command-building
logic runs unchanged on any host (not collected as a test module).
"""

import contextlib
import os
import stat
import sys
import tempfile
from typing import Iterable, Iterator
from unittest.mock import patch

_VERSION_SCRIPT = "#!/bin/sh\necho 'fake-cli 1.0.0'\nexit 0\n"

_ACP_SCRIPT = f"""#!{sys.executable}
import json, sys
line = sys.stdin.readline()
req = json.loads(line) if line else {{}}
sys.stdout.write(json.dumps({{"jsonrpc": "2.0", "id": req.get("id", 1),
                              "result": {{"agentInfo": {{"name": "Fake ACP"}}, "protocolVersion": 1}}}}) + "\\n")
sys.stdout.flush()
"""


def _write_executable(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(text)
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


@contextlib.contextmanager
def fake_cli_environment(executables: Iterable[str] = (), acp: bool = False) -> Iterator[str]:
    """Run with PATH limited to a temp dir holding fake `executables`, and HOME pointing at a temp dir.

    With ``acp=True`` a fake ACP server (answers the JSON-RPC ``initialize`` handshake) is installed at the
    default ``~/.gemini/antigravity/agy-acp/dist/agy-acp-linux-{arm64,x64}`` locations.
    Yields the fake HOME directory.
    """
    with tempfile.TemporaryDirectory(prefix="fake_cli_home_") as home:
        bin_dir = os.path.join(home, "bin")
        os.makedirs(bin_dir)
        for name in executables:
            _write_executable(os.path.join(bin_dir, name), _VERSION_SCRIPT)
        if acp:
            dist = os.path.join(home, ".gemini", "antigravity", "agy-acp", "dist")
            for arch in ("arm64", "x64"):
                _write_executable(os.path.join(dist, f"agy-acp-linux-{arch}"), _ACP_SCRIPT)
        with patch.dict(os.environ, {"PATH": bin_dir, "HOME": home}):
            yield home

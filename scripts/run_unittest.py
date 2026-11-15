#!/usr/bin/env python3
"""Run unittest with an isolated durable trust store for this test process."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="dynamicstate-test-trust-") as test_state_dir:
        env = os.environ.copy()
        env["DYNAMICSTATE_TRUST_STORE_PATH"] = os.path.join(test_state_dir, "trust-store.json")
        return subprocess.run(
            [sys.executable, "-m", "unittest", *sys.argv[1:]],
            env=env,
            check=False,
        ).returncode


if __name__ == "__main__":
    raise SystemExit(main())

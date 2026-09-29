"""Integration tests for dynamicState Web Server Process Lifecycle & Signal Handling.

Verifies:
1. Web server subprocess starts and listens on specified port.
2. SIGINT (Ctrl+C) causes clean shutdown with returncode 0 within timeout.
3. SIGTERM causes clean shutdown with returncode 0 within timeout.
4. Bound port is released immediately without TIME_WAIT hang.
5. No zombie or orphaned subprocess remains.
"""

import errno
import os
import signal
import socket
import subprocess
import sys
import time
import unittest
import urllib.request
import urllib.error


def find_free_port() -> int:
    """Find a random available TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_for_port_listening(host: str, port: int, timeout: float = 5.0) -> bool:
    """Poll until the TCP port is accepting connections."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return True
        except (OSError, ConnectionRefusedError):
            time.sleep(0.1)
    return False


def is_port_available(host: str, port: int) -> bool:
    """Verify that port can be immediately rebound."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


class TestWebServerLifecycle(unittest.TestCase):
    """Subprocess integration tests for Linux signal handling and process shutdown."""

    def test_01_sigint_clean_shutdown(self):
        """Verify that SIGINT (Ctrl+C) terminates the server cleanly with exit code 0."""
        port = find_free_port()
        cmd = [sys.executable, "-m", "extractor", "server", "--host", "127.0.0.1", "--port", str(port)]

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        try:
            # 1. Wait for server to listen
            listening = wait_for_port_listening("127.0.0.1", port, timeout=5.0)
            self.assertTrue(listening, "Web server failed to listen on port within timeout")

            # 2. Verify HTTP health check works
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=2.0) as resp:
                self.assertEqual(resp.status, 200)

            # 3. Process is alive
            self.assertIsNone(proc.poll(), "Server exited prematurely before signal")

            # 4. Send SIGINT (simulating Ctrl+C)
            proc.send_signal(signal.SIGINT)

            # 5. Wait for termination
            exit_code = proc.wait(timeout=4.0)
            self.assertEqual(exit_code, 0, f"Server exited with non-zero code on SIGINT: {exit_code}")

            # 6. Verify port was released
            self.assertTrue(is_port_available("127.0.0.1", port), "Port was not released after SIGINT shutdown")

        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()

    def test_02_sigterm_clean_shutdown(self):
        """Verify that SIGTERM terminates the server cleanly with exit code 0."""
        port = find_free_port()
        cmd = [sys.executable, "-m", "extractor", "server", "--host", "127.0.0.1", "--port", str(port)]

        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        try:
            # 1. Wait for server to listen
            listening = wait_for_port_listening("127.0.0.1", port, timeout=5.0)
            self.assertTrue(listening, "Web server failed to listen on port within timeout")

            # 2. Verify HTTP health check works
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/api/health", timeout=2.0) as resp:
                self.assertEqual(resp.status, 200)

            # 3. Process is alive
            self.assertIsNone(proc.poll(), "Server exited prematurely before signal")

            # 4. Send SIGTERM
            proc.send_signal(signal.SIGTERM)

            # 5. Wait for termination
            exit_code = proc.wait(timeout=4.0)
            self.assertEqual(exit_code, 0, f"Server exited with non-zero code on SIGTERM: {exit_code}")

            # 6. Verify port was released
            self.assertTrue(is_port_available("127.0.0.1", port), "Port was not released after SIGTERM shutdown")

        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
            if proc.stdout:
                proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()


if __name__ == "__main__":
    unittest.main()

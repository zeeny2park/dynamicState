"""Optional-dependency guard for the Playwright browser E2E tests (not collected as a test module)."""

import unittest
from typing import Optional

try:  # playwright is intentionally not a CI dependency
    from playwright.sync_api import sync_playwright
except ImportError:  # pragma: no cover - depends on host
    sync_playwright = None

NOT_INSTALLED_REASON = "playwright is not installed (pip install playwright && playwright install chromium)"


def browser_unavailable_reason() -> Optional[str]:
    """Return a skip reason when Playwright or its Chromium build is unusable, else None."""
    if sync_playwright is None:
        return NOT_INSTALLED_REASON
    try:
        with sync_playwright() as pw:
            import os
            if not os.path.exists(pw.chromium.executable_path):
                return "playwright Chromium browser is not installed (playwright install chromium)"
    except Exception as exc:  # driver missing, sandbox problems, ...
        return f"playwright cannot start on this host: {exc!r}"
    return None


def skip_unless_browser_available() -> None:
    """Call first thing in setUpClass, before any fixture is built, to skip cleanly."""
    reason = browser_unavailable_reason()
    if reason:
        raise unittest.SkipTest(reason)

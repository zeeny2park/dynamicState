"""Per-test temporary directories that are removed on teardown (no fixed /tmp paths, nothing left behind).

``temp_dir(testcase)`` returns a fresh directory and registers its removal with ``testcase.addCleanup`` (or
``addClassCleanup`` for a class), so a test never shares state with an earlier or concurrent run.
``tests/test_tmp_path_policy.py`` fails when a test hard-codes a ``/tmp/`` output path.
"""
import shutil
import tempfile


def temp_dir(owner, prefix: str = "ds_test_") -> str:
    """A new directory removed when the test (instance) or test class (``owner`` is a class) finishes."""
    path = tempfile.mkdtemp(prefix=prefix)
    cleanup = owner.addClassCleanup if isinstance(owner, type) else owner.addCleanup
    cleanup(shutil.rmtree, path, True)
    return path

"""Test package.  Importing any ``tests.*`` module installs a safety net against leftover temp directories.

Many tests create scratch directories with ``tempfile.mkdtemp`` and clean them in a ``tearDown*`` that is skipped
when the runner is interrupted or a ``setUpClass`` fails half way.  Every directory created through
``tempfile.mkdtemp`` in a test process is therefore also removed when the interpreter exits normally.  New tests
should still prefer ``tempfile.TemporaryDirectory`` / ``tests.support.tmpdirs.temp_dir``.
"""
import atexit
import shutil
import tempfile

_created = []
_orig_mkdtemp = tempfile.mkdtemp


def _tracking_mkdtemp(*args, **kwargs):
    path = _orig_mkdtemp(*args, **kwargs)
    _created.append(path)
    return path


def _sweep():
    for path in reversed(_created):
        shutil.rmtree(path, ignore_errors=True)


if tempfile.mkdtemp is _orig_mkdtemp:
    tempfile.mkdtemp = _tracking_mkdtemp
    atexit.register(_sweep)


# Tests that do not pass a corpus_dir would write into /tmp/dynamicstate_corpus (20-40 MB per diagnosis, forever).
# Give the whole test process its own default corpus, removed at exit.
import os as _os
if not _os.environ.get("DYNAMICSTATE_CORPUS_DIR"):
    _os.environ["DYNAMICSTATE_CORPUS_DIR"] = tempfile.mkdtemp(prefix="ds_test_corpus_")

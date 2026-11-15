"""Tests for DurableTrustStore Filesystem Security and Atomic Durability (US-TRUST-005 / FR-TRUST-005)."""

import os
from pathlib import Path
import pytest
from extractor.capture_backend import (
    DurableTrustStore,
    SecurityViolationError,
)


def test_durable_trust_store_rejects_symlink_path(tmp_path: Path):
    """Verify that targeting a symlink raises SecurityViolationError."""
    real_file = tmp_path / "real_store.json"
    real_file.write_text("{}", encoding="utf-8")
    real_file.chmod(0o600)

    symlink_file = tmp_path / "symlink_store.json"
    symlink_file.symlink_to(real_file)

    with pytest.raises(SecurityViolationError, match="[Ss]ymlink"):
        DurableTrustStore(str(symlink_file))

    store = DurableTrustStore()
    store.store_path = str(symlink_file)
    with pytest.raises(SecurityViolationError, match="[Ss]ymlink"):
        store.load()

    with pytest.raises(SecurityViolationError, match="[Ss]ymlink"):
        store.save()


def test_durable_trust_store_sets_0600_permissions_on_save(tmp_path: Path):
    """Verify saved file has 0600 permissions."""
    store_file = tmp_path / "secure_store.json"
    store = DurableTrustStore(str(store_file))
    store.save()

    mode = os.stat(store_file).st_mode & 0o777
    assert mode == 0o600


def test_durable_trust_store_cleans_up_stale_temp_files(tmp_path: Path):
    """Verify stale .trust_tmp_* files are reclaimed on load."""
    stale_tmp = tmp_path / ".trust_tmp_crashed_12345"
    stale_tmp.write_text("partial data", encoding="utf-8")
    assert stale_tmp.exists()

    store_file = tmp_path / "valid_store.json"
    store = DurableTrustStore(str(store_file))
    store.save()

    # Loading the store should scan and remove stale temp files in its directory
    store.load()
    assert not stale_tmp.exists()

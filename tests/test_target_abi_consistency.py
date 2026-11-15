"""Tests for Target ABI Cross-Architecture Consistency (US-CPP-001 / FR-CPP-002)."""

import pytest
from extractor.target_abi import (
    DETECTION_DETECTED,
    FEATURE_ALLOCATOR_CHUNKS,
    FEATURE_MUTEX_OWNER,
    LIBC_GLIBC,
    SUPPORT_NOT_SUPPORTED_ON_TARGET,
    SUPPORT_SUPPORTED,
    TargetABI,
    check_support,
)


def test_supported_abi_combinations_for_x86_and_aarch64():
    """Verify both x86_64 and aarch64 with glibc are supported for core features."""
    abi_x86 = TargetABI(
        status=DETECTION_DETECTED,
        architecture="x86_64",
        libc=LIBC_GLIBC,
        word_size=64,
        endianness="little",
    )
    abi_arm = TargetABI(
        status=DETECTION_DETECTED,
        architecture="aarch64",
        libc=LIBC_GLIBC,
        word_size=64,
        endianness="little",
    )

    assert check_support(abi_x86, FEATURE_MUTEX_OWNER).status == SUPPORT_SUPPORTED
    assert check_support(abi_arm, FEATURE_MUTEX_OWNER).status == SUPPORT_SUPPORTED

    assert check_support(abi_x86, FEATURE_ALLOCATOR_CHUNKS).status == SUPPORT_SUPPORTED
    assert check_support(abi_arm, FEATURE_ALLOCATOR_CHUNKS).status == SUPPORT_SUPPORTED


def test_unsupported_abi_combination_fails_closed():
    """Verify unsupported architecture returns SUPPORT_NOT_SUPPORTED_ON_TARGET."""
    abi_unsupported = TargetABI(
        status=DETECTION_DETECTED,
        architecture="mips32",
        libc="musl",
        word_size=32,
        endianness="big",
    )
    res = check_support(abi_unsupported, FEATURE_MUTEX_OWNER)
    assert res.status == SUPPORT_NOT_SUPPORTED_ON_TARGET


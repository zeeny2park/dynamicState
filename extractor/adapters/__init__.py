"""Extensible Target Adapter package.

Provides:
- ``TargetAdapterRegistry`` & ``DEFAULT_ADAPTER_REGISTRY`` for registering custom
  target adapters (e.g. ``xssh``, ``adb``, ``k8s``) without editing core files.
- Schema / URI automatic dispatch (``parse_target_uri``, ``dispatch_target_adapter``).
- ``TargetIdentityPolicy`` strategy interface for overriding build-id & target
  identity verification per adapter.
- Built-in ``local`` and ``ssh`` adapters registered automatically.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .identity_policy import (
    DEFAULT_IDENTITY_POLICY,
    DefaultTargetIdentityPolicy,
    StrictBuildIdIdentityPolicy,
    TargetIdentityPolicy,
)
from .local import LOCAL_TRANSPORT_METADATA, register_local_adapter
from .registry import (
    DEFAULT_ADAPTER_REGISTRY,
    TargetAdapterDescriptor,
    TargetAdapterRegistry,
    TransportFieldSpec,
    TransportMetadata,
    register_adapter,
)
from .ssh import SSH_TRANSPORT_METADATA, register_ssh_adapter
from .uri import ParsedTargetUri, parse_target_uri

# Register built-in transports once on package import
register_local_adapter(DEFAULT_ADAPTER_REGISTRY)
register_ssh_adapter(DEFAULT_ADAPTER_REGISTRY)


def dispatch_target_adapter(spec_or_uri: Any, **overrides: Any) -> Any:
    """Instantiate a target adapter from a URI, generic dict, or TargetSpec."""
    return DEFAULT_ADAPTER_REGISTRY.dispatch(spec_or_uri, **overrides)


def list_transport_metadata(*, include_destinations: bool = True) -> List[Dict[str, Any]]:
    """Return UI/API metadata for all registered target transports."""
    return DEFAULT_ADAPTER_REGISTRY.list_transport_metadata(include_destinations=include_destinations)


__all__ = [
    "DEFAULT_ADAPTER_REGISTRY",
    "DEFAULT_IDENTITY_POLICY",
    "DefaultTargetIdentityPolicy",
    "LOCAL_TRANSPORT_METADATA",
    "ParsedTargetUri",
    "SSH_TRANSPORT_METADATA",
    "StrictBuildIdIdentityPolicy",
    "TargetAdapterDescriptor",
    "TargetAdapterRegistry",
    "TargetIdentityPolicy",
    "TransportFieldSpec",
    "TransportMetadata",
    "dispatch_target_adapter",
    "list_transport_metadata",
    "parse_target_uri",
    "register_adapter",
]

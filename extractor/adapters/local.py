"""Built-in Local target adapter registration."""

from __future__ import annotations

from typing import Any, Dict

from .registry import TargetAdapterRegistry, TransportMetadata
from .uri import ParsedTargetUri


LOCAL_TRANSPORT_METADATA = TransportMetadata(
    id="local",
    label_en="Local",
    label_ko="로컬",
    uri_schemes=("local",),
    is_remote=False,
    requires_debug_image=False,
    fields=(),
    order=10,
)


def _local_factory(params: Dict[str, Any]) -> Any:
    from ..target_adapter import LocalTargetAdapter
    return LocalTargetAdapter()


def _local_uri_to_params(parsed: ParsedTargetUri) -> Dict[str, Any]:
    return dict(parsed.query)


def _local_describe(params: Dict[str, Any]) -> Dict[str, Any]:
    return {"transport": "local"}


def register_local_adapter(registry: TargetAdapterRegistry) -> None:
    registry.register(
        "local",
        factory=_local_factory,
        metadata=LOCAL_TRANSPORT_METADATA,
        uri_schemes=("local",),
        uri_to_params=_local_uri_to_params,
        describe_fn=_local_describe,
        replace=True,
    )

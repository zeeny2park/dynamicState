"""Schema / URI parser for automatic target adapter dispatch."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Optional
from urllib.parse import parse_qsl, urlparse


@dataclass(frozen=True)
class ParsedTargetUri:
    """Normalized components of a target URI (e.g. ``ssh://root@10.0.0.5:2222?ssh_key=...``)."""

    scheme: str
    host: Optional[str] = None
    user: Optional[str] = None
    port: Optional[int] = None
    path: str = ""
    query: Dict[str, str] = field(default_factory=dict)
    raw: str = ""


def parse_target_uri(uri: str) -> ParsedTargetUri:
    """Parse a target URI into scheme, host, user, port, path, and query parameters."""
    if not isinstance(uri, str) or "://" not in uri.strip():
        raise ValueError(f"invalid target URI (expected '<scheme>://...'): {uri!r}")
    raw = uri.strip()
    parsed = urlparse(raw)
    scheme = (parsed.scheme or "").strip().lower()
    if not scheme:
        raise ValueError(f"target URI missing scheme: {uri!r}")
    host = parsed.hostname
    user = parsed.username
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"invalid port in target URI {uri!r}: {exc}") from exc
    query = {k: v for k, v in parse_qsl(parsed.query, keep_blank_values=False)}
    return ParsedTargetUri(
        scheme=scheme,
        host=host,
        user=user,
        port=port,
        path=parsed.path or "",
        query=query,
        raw=raw,
    )

"""Schema / URI parser for automatic target adapter dispatch."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, Optional
from urllib.parse import parse_qsl, urlparse

_SCHEME_RE = re.compile(r"^[a-z][a-z0-9+.-]*$")


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
    """Parse and strictly validate a target URI.

    Rejects malformed URIs, control/whitespace characters, invalid schemes,
    out-of-range ports (must be 1..65535), and duplicate query parameter keys.
    """
    if not isinstance(uri, str) or "://" not in uri.strip():
        raise ValueError(f"invalid target URI (expected '<scheme>://...'): {uri!r}")
    raw = uri.strip()
    if any(ch.isspace() or ord(ch) < 32 for ch in raw):
        raise ValueError(f"malformed target URI contains whitespace or control characters: {uri!r}")

    parsed = urlparse(raw)
    scheme = (parsed.scheme or "").strip().lower()
    if not scheme or not _SCHEME_RE.match(scheme):
        raise ValueError(f"invalid target URI scheme: {scheme!r}")

    host = parsed.hostname
    user = parsed.username
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"invalid port in target URI {uri!r}: {exc}") from exc
    if port is not None and not (1 <= port <= 65535):
        raise ValueError(f"port out of range (1..65535) in target URI: {port}")

    query: Dict[str, str] = {}
    for k, v in parse_qsl(parsed.query, keep_blank_values=True):
        if k in query:
            raise ValueError(f"duplicate query parameter '{k}' in target URI")
        if v != "":
            query[k] = v

    return ParsedTargetUri(
        scheme=scheme,
        host=host,
        user=user,
        port=port,
        path=parsed.path or "",
        query=query,
        raw=raw,
    )

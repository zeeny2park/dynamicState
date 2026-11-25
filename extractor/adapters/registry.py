"""Extensible Target Adapter Registry with schema/URI dispatch and UI transport metadata."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Type

from .uri import ParsedTargetUri, parse_target_uri


@dataclass(frozen=True)
class TransportFieldSpec:
    """Declarative UI/API parameter specification for a transport mode."""

    name: str
    label_en: str
    label_ko: str
    field_type: str = "text"  # "text" | "number" | "select" | "checkbox"
    required: bool = False
    placeholder_en: str = ""
    placeholder_ko: str = ""
    default: Any = None
    options: Tuple[Dict[str, str], ...] = ()
    secret: bool = False
    flex: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "name": self.name,
            "label": {"en": self.label_en, "ko": self.label_ko},
            "type": self.field_type,
            "required": bool(self.required),
            "placeholder": {"en": self.placeholder_en, "ko": self.placeholder_ko},
            "secret": bool(self.secret),
        }
        if self.default is not None:
            out["default"] = self.default
        if self.options:
            out["options"] = list(self.options)
        if self.flex:
            out["flex"] = self.flex
        return out


@dataclass
class TransportMetadata:
    """Generic metadata exposed by ``GET /api/target/remotes`` for dynamic UI rendering."""

    id: str
    label_en: str
    label_ko: str
    uri_schemes: Tuple[str, ...] = ()
    is_remote: bool = True
    requires_debug_image: bool = False
    fields: Tuple[TransportFieldSpec, ...] = ()
    discover_destinations: Optional[Callable[[], List[Dict[str, Any]]]] = None
    order: int = 50

    def to_dict(self, include_destinations: bool = True) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "id": self.id,
            "label": {"en": self.label_en, "ko": self.label_ko},
            "uri_schemes": list(self.uri_schemes or (self.id,)),
            "is_remote": bool(self.is_remote),
            "requires_debug_image": bool(self.requires_debug_image),
            "fields": [f.to_dict() for f in self.fields],
            "order": int(self.order),
        }
        if include_destinations and callable(self.discover_destinations):
            try:
                dests = self.discover_destinations() or []
                out["destinations"] = [d for d in dests if isinstance(d, dict)]
            except Exception:  # noqa: BLE001 - destination discovery must never break metadata API
                out["destinations"] = []
        return out


@dataclass
class TargetAdapterDescriptor:
    """Registered adapter entry in ``TargetAdapterRegistry``."""

    transport_id: str
    factory: Callable[[Dict[str, Any]], Any]
    metadata: TransportMetadata
    uri_schemes: Tuple[str, ...] = ()
    uri_to_params: Optional[Callable[[ParsedTargetUri], Dict[str, Any]]] = None
    describe_fn: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None


def _default_uri_to_params(parsed: ParsedTargetUri) -> Dict[str, Any]:
    params: Dict[str, Any] = dict(parsed.query)
    if parsed.host:
        params.setdefault("host", parsed.host)
        params.setdefault("target_name", parsed.host)
    if parsed.user:
        params.setdefault("user", parsed.user)
    if parsed.port is not None:
        params.setdefault("port", parsed.port)
    if parsed.path and parsed.path.strip("/"):
        params.setdefault("path", parsed.path.strip("/"))
    return params


class TargetAdapterRegistry:
    """Registry supporting custom target adapters, URI auto-dispatch, and metadata discovery."""

    def __init__(self) -> None:
        self._by_id: Dict[str, TargetAdapterDescriptor] = {}
        self._by_scheme: Dict[str, str] = {}

    def register(
        self,
        transport_id: str,
        *,
        factory: Callable[[Dict[str, Any]], Any],
        metadata: Optional[TransportMetadata] = None,
        uri_schemes: Optional[Iterable[str]] = None,
        uri_to_params: Optional[Callable[[ParsedTargetUri], Dict[str, Any]]] = None,
        describe_fn: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
        replace: bool = False,
    ) -> TargetAdapterDescriptor:
        tid = str(transport_id or "").strip().lower()
        if not tid:
            raise ValueError("transport_id must be a non-empty string")
        if tid in self._by_id and not replace:
            raise ValueError(f"transport '{tid}' is already registered (pass replace=True to override)")
        schemes = tuple(dict.fromkeys(
            str(s).strip().lower() for s in (uri_schemes or (metadata.uri_schemes if metadata else ()) or (tid,)) if s
        ))
        meta = metadata or TransportMetadata(
            id=tid,
            label_en=tid.upper(),
            label_ko=tid.upper(),
            uri_schemes=schemes,
            is_remote=(tid != "local"),
        )
        desc = TargetAdapterDescriptor(
            transport_id=tid,
            factory=factory,
            metadata=meta,
            uri_schemes=schemes,
            uri_to_params=uri_to_params or _default_uri_to_params,
            describe_fn=describe_fn,
        )
        # Clean old scheme mappings on replace
        if tid in self._by_id:
            for s in list(self._by_scheme):
                if self._by_scheme[s] == tid:
                    del self._by_scheme[s]
        self._by_id[tid] = desc
        for s in schemes:
            self._by_scheme[s] = tid
        return desc

    def unregister(self, transport_id: str) -> bool:
        tid = str(transport_id or "").strip().lower()
        if tid not in self._by_id:
            return False
        del self._by_id[tid]
        for s in list(self._by_scheme):
            if self._by_scheme[s] == tid:
                del self._by_scheme[s]
        return True

    def get(self, transport_id: str) -> Optional[TargetAdapterDescriptor]:
        return self._by_id.get(str(transport_id or "").strip().lower())

    def resolve_scheme(self, scheme: str) -> Optional[TargetAdapterDescriptor]:
        tid = self._by_scheme.get(str(scheme or "").strip().lower())
        return self._by_id.get(tid) if tid else None

    def list_ids(self) -> List[str]:
        return [d.transport_id for d in sorted(self._by_id.values(), key=lambda x: (x.metadata.order, x.transport_id))]

    def list_transport_metadata(self, *, include_destinations: bool = True) -> List[Dict[str, Any]]:
        descs = sorted(self._by_id.values(), key=lambda x: (x.metadata.order, x.transport_id))
        return [d.metadata.to_dict(include_destinations=include_destinations) for d in descs]

    def normalize_request(self, spec_or_uri: Any) -> Tuple[str, Dict[str, Any]]:
        """Resolve a URI string, generic payload dict, or legacy SSH dict into ``(transport_id, params)``."""
        if spec_or_uri is None:
            return "local", {}

        if isinstance(spec_or_uri, str):
            parsed = parse_target_uri(spec_or_uri)
            desc = self.resolve_scheme(parsed.scheme)
            if desc is None:
                raise ValueError(f"unsupported target URI scheme '{parsed.scheme}'")
            params = desc.uri_to_params(parsed) if desc.uri_to_params else _default_uri_to_params(parsed)
            params.setdefault("target_uri", parsed.raw)
            return desc.transport_id, params

        if isinstance(spec_or_uri, dict):
            raw = dict(spec_or_uri)
            uri = raw.get("target_uri") or raw.get("uri")
            if isinstance(uri, str) and "://" in uri.strip():
                tid, uri_params = self.normalize_request(uri)
                merged = dict(uri_params)
                tp = raw.get("transport_params")
                if isinstance(tp, dict):
                    merged.update(tp)
                for k, v in raw.items():
                    if k not in ("target_uri", "uri", "transport", "transport_params") and v is not None:
                        merged.setdefault(k, v)
                return tid, merged

            tid = str(raw.get("transport") or "").strip().lower()
            tp = raw.get("transport_params")
            if tid:
                params = dict(tp) if isinstance(tp, dict) else {}
                for k, v in raw.items():
                    if k not in ("transport", "transport_params") and v is not None:
                        params.setdefault(k, v)
                return tid, params

            # Legacy SSH dict detection (remote_host / host without explicit transport)
            if raw.get("remote_host") or raw.get("host"):
                return "ssh", raw
            return "local", raw

        # Duck-typed TargetSpec object
        if hasattr(spec_or_uri, "transport") and getattr(spec_or_uri, "transport", None):
            tid = str(getattr(spec_or_uri, "transport")).strip().lower()
            tp = getattr(spec_or_uri, "transport_params", None)
            params = dict(tp) if isinstance(tp, dict) else {}
            for attr in ("remote_host", "ssh_user", "ssh_port", "ssh_key", "ssh_proxy_jump",
                         "auto_deploy_collector", "collector_path", "use_snapshot_bundle",
                         "timeout_s", "command_runner", "stream_opener", "target_uri"):
                v = getattr(spec_or_uri, attr, None)
                if v is not None and attr not in params:
                    params[attr] = v
            return tid, params

        if hasattr(spec_or_uri, "remote_host"):
            params = {
                attr: getattr(spec_or_uri, attr, None)
                for attr in ("remote_host", "ssh_user", "ssh_port", "ssh_key", "ssh_proxy_jump",
                             "auto_deploy_collector", "collector_path", "use_snapshot_bundle",
                             "timeout_s", "command_runner", "stream_opener")
                if getattr(spec_or_uri, attr, None) is not None
            }
            return ("ssh" if params.get("remote_host") else "local"), params

        raise ValueError(f"unsupported target specification: {type(spec_or_uri).__name__}")

    def dispatch(self, spec_or_uri: Any, **overrides: Any) -> Any:
        """Instantiate the matching TargetExecutionAdapter from a URI, dict, or TargetSpec."""
        tid, params = self.normalize_request(spec_or_uri)
        desc = self.get(tid)
        if desc is None:
            raise ValueError(f"unknown target transport '{tid}' (registered: {', '.join(self.list_ids())})")
        merged = dict(params)
        merged.update({k: v for k, v in overrides.items() if v is not None})
        return desc.factory(merged)

    def describe(self, spec_or_uri: Any) -> Dict[str, Any]:
        """Return a sanitized transport description (never containing secret fields)."""
        tid, params = self.normalize_request(spec_or_uri)
        desc = self.get(tid)
        if desc and desc.describe_fn:
            return desc.describe_fn(params)
        secret_fields = {f.name for f in (desc.metadata.fields if desc else ()) if f.secret}
        secret_fields |= {"ssh_key", "key_file", "identity", "password", "token", "secret"}
        safe_params = {k: v for k, v in params.items() if k not in secret_fields and v is not None}
        out: Dict[str, Any] = {"transport": tid}
        if safe_params:
            out["transport_params"] = safe_params
        host = safe_params.get("remote_host") or safe_params.get("host") or safe_params.get("target_name")
        if host:
            out["host"] = host
        return out


DEFAULT_ADAPTER_REGISTRY = TargetAdapterRegistry()


def register_adapter(
    transport_id: str,
    *,
    metadata: Optional[TransportMetadata] = None,
    uri_schemes: Optional[Iterable[str]] = None,
    uri_to_params: Optional[Callable[[ParsedTargetUri], Dict[str, Any]]] = None,
    describe_fn: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None,
    registry: Optional[TargetAdapterRegistry] = None,
    replace: bool = False,
) -> Callable[[Callable[[Dict[str, Any]], Any]], Callable[[Dict[str, Any]], Any]]:
    """Decorator registering an adapter factory with the target adapter registry."""
    target_reg = registry or DEFAULT_ADAPTER_REGISTRY

    def _decorator(fn: Callable[[Dict[str, Any]], Any]) -> Callable[[Dict[str, Any]], Any]:
        target_reg.register(
            transport_id,
            factory=fn,
            metadata=metadata,
            uri_schemes=uri_schemes,
            uri_to_params=uri_to_params,
            describe_fn=describe_fn,
            replace=replace,
        )
        return fn

    return _decorator

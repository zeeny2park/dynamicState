"""Built-in Remote SSH target adapter registration."""

from __future__ import annotations

from typing import Any, Dict

from .registry import TargetAdapterRegistry, TransportFieldSpec, TransportMetadata
from .uri import ParsedTargetUri


SSH_TRANSPORT_METADATA = TransportMetadata(
    id="ssh",
    label_en="SSH",
    label_ko="SSH",
    uri_schemes=("ssh",),
    is_remote=True,
    requires_debug_image=True,
    fields=(
        TransportFieldSpec(
            name="remote_host",
            label_en="Host",
            label_ko="호스트",
            field_type="text",
            required=True,
            placeholder_en="Host (IP or name)",
            placeholder_ko="호스트 (IP 또는 이름)",
        ),
        TransportFieldSpec(
            name="ssh_user",
            label_en="SSH User",
            label_ko="SSH 사용자",
            field_type="text",
            required=False,
            placeholder_en="SSH user",
            placeholder_ko="SSH 사용자",
        ),
        TransportFieldSpec(
            name="ssh_port",
            label_en="Port",
            label_ko="포트",
            field_type="text",
            required=False,
            placeholder_en="Port (22)",
            placeholder_ko="포트 (22)",
            default=22,
            flex=".4",
        ),
        TransportFieldSpec(
            name="ssh_key",
            label_en="Key file",
            label_ko="키 파일 경로",
            field_type="text",
            required=False,
            placeholder_en="Key file path",
            placeholder_ko="키 파일 경로",
            secret=True,
        ),
    ),
    order=20,
)


def _ssh_uri_to_params(parsed: ParsedTargetUri) -> Dict[str, Any]:
    params: Dict[str, Any] = dict(parsed.query)
    if parsed.host:
        params["remote_host"] = parsed.host
    if parsed.user:
        params["ssh_user"] = parsed.user
    if parsed.port is not None:
        params["ssh_port"] = parsed.port
    return params


def _ssh_factory(params: Dict[str, Any]) -> Any:
    from ..target_adapter import RemoteSshTargetAdapter

    host = params.get("remote_host") or params.get("host")
    if not host or not str(host).strip():
        raise ValueError("target.remote_host is required for an ssh target")
    user = params.get("ssh_user") or params.get("user")
    port = int(params.get("ssh_port") or params.get("port") or 22)
    key_file = params.get("ssh_key") or params.get("key_file") or params.get("identity")
    proxy_jump = params.get("ssh_proxy_jump") or params.get("proxy_jump")
    collector_path = params.get("collector_path")
    use_snapshot_bundle = bool(params.get("use_snapshot_bundle", True))
    kw: Dict[str, Any] = {}
    if params.get("command_runner") is not None:
        kw["command_runner"] = params["command_runner"]
    if params.get("stream_opener") is not None:
        kw["stream_opener"] = params["stream_opener"]
    if params.get("timeout_s"):
        kw["timeout_sec"] = float(params["timeout_s"])
    elif params.get("timeout_sec"):
        kw["timeout_sec"] = float(params["timeout_sec"])
    return RemoteSshTargetAdapter(
        host=str(host).strip(),
        user=str(user).strip() if user else None,
        port=port,
        key_file=str(key_file).strip() if key_file else None,
        proxy_jump=str(proxy_jump).strip() if proxy_jump else None,
        collector_path=str(collector_path).strip() if collector_path else None,
        use_snapshot_bundle=use_snapshot_bundle,
        **kw,
    )


def _ssh_describe(params: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "transport": "ssh",
        "host": params.get("remote_host") or params.get("host"),
        "user": params.get("ssh_user") or params.get("user"),
        "port": int(params.get("ssh_port") or params.get("port") or 22),
        "proxy_jump": params.get("ssh_proxy_jump") or params.get("proxy_jump"),
        "auto_deploy_collector": bool(params.get("auto_deploy_collector", False)),
        "use_snapshot_bundle": bool(params.get("use_snapshot_bundle", True)),
    }


def register_ssh_adapter(registry: TargetAdapterRegistry) -> None:
    registry.register(
        "ssh",
        factory=_ssh_factory,
        metadata=SSH_TRANSPORT_METADATA,
        uri_schemes=("ssh",),
        uri_to_params=_ssh_uri_to_params,
        describe_fn=_ssh_describe,
        replace=True,
    )

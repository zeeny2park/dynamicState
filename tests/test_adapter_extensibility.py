"""Tests for Custom Adapter extensibility architecture:
1. extractor/adapters/ package + TargetAdapterRegistry
2. Schema / URI automatic dispatch (local://, ssh://, custom xssh://)
3. Generic Transport Metadata API (GET /api/target/remotes + generic transport_params)
4. Web UI dynamic mode & field rendering from metadata (Node.js ui.js test)
5. TargetIdentityPolicy strategy hook override per adapter
"""

from __future__ import annotations

import http.client
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from extractor.adapters import (  # noqa: E402
    DEFAULT_ADAPTER_REGISTRY,
    DefaultTargetIdentityPolicy,
    StrictBuildIdIdentityPolicy,
    TargetAdapterRegistry,
    TargetIdentityPolicy,
    TransportFieldSpec,
    TransportMetadata,
    parse_target_uri,
)
from extractor.agent_runtime import AgentRuntime  # noqa: E402
from extractor.capture_backend import LiveCaptureReceipt  # noqa: E402
from extractor.expert_diagnostic_engine import TargetSpec  # noqa: E402
from extractor.target_adapter import (  # noqa: E402
    LocalTargetAdapter,
    RemoteSshTargetAdapter,
    TargetExecutionAdapter,
)
from extractor.web.server import run_server  # noqa: E402


class _FakeXsshAdapter(LocalTargetAdapter):
    """Minimal custom remote adapter demonstrating zero-core-edit extensibility."""

    def __init__(self, target_name: str, *, strict_policy: bool = False):
        super().__init__()
        self.target_name = target_name
        self._strict_policy = strict_policy

    def is_remote(self) -> bool:
        return True

    def target_host(self) -> str:
        return self.target_name

    def get_identity_policy(self) -> TargetIdentityPolicy:
        return StrictBuildIdIdentityPolicy() if self._strict_policy else DefaultTargetIdentityPolicy()


def _xssh_metadata() -> TransportMetadata:
    return TransportMetadata(
        id="xssh",
        label_en="XSSH",
        label_ko="XSSH",
        uri_schemes=("xssh",),
        is_remote=True,
        requires_debug_image=True,
        fields=(
            TransportFieldSpec(
                name="target_name",
                label_en="Target Board",
                label_ko="대상 보드",
                field_type="select",
                required=True,
                placeholder_en="Select target board",
                placeholder_ko="대상 보드 선택",
            ),
        ),
        discover_destinations=lambda: [
            {"value": "board-alpha", "label": {"en": "Board Alpha", "ko": "보드 알파"}},
            {"value": "board-beta", "label": {"en": "Board Beta", "ko": "보드 베타"}},
        ],
        order=30,
    )


class TestAdapterRegistryAndUriDispatch(unittest.TestCase):
    def test_uri_parsing_and_builtin_dispatch(self):
        p = parse_target_uri("ssh://root@10.0.0.5:2222?ssh_key=/keys/id_ed25519")
        self.assertEqual(p.scheme, "ssh")
        self.assertEqual(p.user, "root")
        self.assertEqual(p.host, "10.0.0.5")
        self.assertEqual(p.port, 2222)
        self.assertEqual(p.query["ssh_key"], "/keys/id_ed25519")

        local_ad = DEFAULT_ADAPTER_REGISTRY.dispatch("local://")
        self.assertIsInstance(local_ad, LocalTargetAdapter)

        ssh_ad = DEFAULT_ADAPTER_REGISTRY.dispatch("ssh://root@10.0.0.5:2222")
        self.assertIsInstance(ssh_ad, RemoteSshTargetAdapter)
        self.assertEqual(ssh_ad.host, "10.0.0.5")
        self.assertEqual(ssh_ad.user, "root")
        self.assertEqual(ssh_ad.port, 2222)

    def test_custom_adapter_registration_uri_and_target_spec_dispatch(self):
        try:
            DEFAULT_ADAPTER_REGISTRY.register(
                "xssh",
                factory=lambda p: _FakeXsshAdapter(str(p.get("target_name") or p.get("host") or "")),
                metadata=_xssh_metadata(),
                uri_schemes=("xssh",),
                replace=True,
            )

            # 1) URI dispatch
            ad_uri = DEFAULT_ADAPTER_REGISTRY.dispatch("xssh://board-alpha")
            self.assertIsInstance(ad_uri, _FakeXsshAdapter)
            self.assertEqual(ad_uri.target_name, "board-alpha")

            # 2) Generic dict via TargetSpec
            spec = TargetSpec.from_value({"transport": "xssh", "transport_params": {"target_name": "board-beta"}})
            ad_spec = spec.build_adapter()
            self.assertIsInstance(ad_spec, _FakeXsshAdapter)
            self.assertEqual(ad_spec.target_name, "board-beta")
            desc = spec.describe()
            self.assertEqual(desc["transport"], "xssh")
            self.assertEqual(desc["host"], "board-beta")

            # 3) URI string via TargetSpec
            spec_uri = TargetSpec.from_value("xssh://board-alpha")
            self.assertEqual(spec_uri.transport, "xssh")
            self.assertEqual(spec_uri.build_adapter().target_name, "board-alpha")
        finally:
            DEFAULT_ADAPTER_REGISTRY.unregister("xssh")


class TestGenericTransportMetadataApiAndDynamicUi(unittest.TestCase):
    def test_remotes_api_exposes_custom_transport_without_server_edits(self):
        DEFAULT_ADAPTER_REGISTRY.register(
            "xssh",
            factory=lambda p: _FakeXsshAdapter(str(p.get("target_name") or p.get("host") or "")),
            metadata=_xssh_metadata(),
            uri_schemes=("xssh",),
            replace=True,
        )
        tmp = tempfile.TemporaryDirectory(prefix="dynstate_ext_")
        server = run_server(AgentRuntime(corpus_dir=os.path.join(tmp.name, "corpus")), host="127.0.0.1", port=0)
        port = server.server_address[1]
        th = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
        th.start()
        try:
            conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
            hdrs = {}
            if getattr(server, "session_token", None):
                hdrs["X-Session-Token"] = server.session_token
            conn.request("GET", "/api/target/remotes", headers=hdrs)
            resp = conn.getresponse()
            body = json.loads(resp.read().decode("utf-8"))
            conn.close()

            self.assertEqual(resp.status, 200)
            self.assertTrue(body["success"])
            by_id = {t["id"]: t for t in body["transports"]}
            self.assertIn("local", by_id)
            self.assertIn("ssh", by_id)
            self.assertIn("xssh", by_id)
            self.assertEqual(by_id["xssh"]["fields"][0]["name"], "target_name")
            self.assertEqual(by_id["xssh"]["fields"][0]["type"], "select")
            self.assertEqual(len(by_id["xssh"]["destinations"]), 2)

            # _parse_diagnose_request accepts generic transport + transport_params
            parsed = server.adapter._parse_diagnose_request({
                "pid": 4242,
                "transport": "xssh",
                "transport_params": {"target_name": "board-alpha"},
            })
            self.assertTrue(parsed["success"], parsed)
            self.assertEqual(parsed["args"]["remote_target"]["transport"], "xssh")
            self.assertEqual(parsed["args"]["remote_target"]["transport_params"]["target_name"], "board-alpha")
        finally:
            server.shutdown()
            server.server_close()
            tmp.cleanup()
            DEFAULT_ADAPTER_REGISTRY.unregister("xssh")

    def test_ui_js_renders_custom_transport_tabs_and_select_dynamically(self):
        script = r"""
const fs = require("fs");
const vm = require("vm");
const code = fs.readFileSync("extractor/web/ui/ui.js", "utf8");
const ctx = { globalThis: {} };
ctx.globalThis = ctx;
vm.runInNewContext(code, ctx);
const DS = ctx.DS || ctx.DSUI;
const ui = {
  lang: "ko",
  form: { mode: "xssh", transport_params: { xssh: { target_name: "board-beta" } } },
  transports: [
    { id: "local", label: { en: "Local", ko: "로컬" }, is_remote: false, fields: [] },
    { id: "ssh", label: { en: "SSH", ko: "SSH" }, is_remote: true, fields: [] },
    {
      id: "xssh", label: { en: "XSSH", ko: "XSSH" }, is_remote: true,
      fields: [{ name: "target_name", label: { en: "Target", ko: "대상" }, type: "select", required: true, placeholder: { en: "Select", ko: "선택" } }],
      destinations: [{ value: "board-alpha", label: { en: "Alpha", ko: "알파" } }, { value: "board-beta", label: { en: "Beta", ko: "베타" } }]
    }
  ],
  jobs: [], examples: [], jobsState: "empty"
};
const html = DS.renderIdle(ui, "ko");
if (!html.includes('data-mode="xssh"')) throw new Error("missing xssh tab");
if (!html.includes('data-tp="target_name"')) throw new Error("missing generic data-tp select");
if (!html.includes('value="board-beta" selected')) throw new Error("missing selected destination option");
console.log("DYNAMIC_UI_OK");
"""
        out = subprocess.run(["node", "-e", script], cwd=ROOT, capture_output=True, text=True, timeout=10)
        self.assertEqual(out.returncode, 0, out.stdout + out.stderr)
        self.assertIn("DYNAMIC_UI_OK", out.stdout)


class TestTargetIdentityPolicyHook(unittest.TestCase):
    def test_default_vs_strict_identity_policy_override(self):
        default_ad = _FakeXsshAdapter("board-a", strict_policy=False)
        strict_ad = _FakeXsshAdapter("board-a", strict_policy=True)

        raw_ident = {"executable": "/opt/app", "exe_fingerprint": "123:456:789", "build_id": None}
        meta_def = {}
        bid, err = default_ad.get_identity_policy().resolve_build_id(raw_ident, meta_def)
        self.assertIsNotNone(bid)
        self.assertTrue(bid.startswith("no-build-id:"))
        self.assertTrue(meta_def.get("build_id_absent"))
        self.assertIsNone(err)

        # Strict policy override rejects absent build_id
        bid_s, err_s = strict_ad.get_identity_policy().resolve_build_id(raw_ident, {})
        self.assertIsNone(bid_s)
        self.assertEqual(err_s, "strict_build_id_required")

        # Default policy accepts matching synthetic no-build-id marker in LiveCaptureReceipt
        ok, _ = default_ad.get_identity_policy().validate_build_id_match(bid, bid)
        self.assertTrue(ok)
        ok_empty, _ = default_ad.get_identity_policy().validate_build_id_match(bid, "")
        self.assertFalse(ok_empty)
        ok_compat, reason_compat = default_ad.get_identity_policy().validate_debug_image_compatibility(None, None)
        self.assertFalse(ok_compat)
        self.assertEqual(reason_compat, "UNKNOWN_IDENTITY_UNVERIFIABLE")

        # Strict policy rejects absent build-id debug image compatibility
        ok_strict, reason_strict = strict_ad.get_identity_policy().validate_debug_image_compatibility(None, None)
        self.assertFalse(ok_strict)
        self.assertEqual(reason_strict, "STRICT_BUILD_ID_REQUIRED")


if __name__ == "__main__":
    unittest.main()

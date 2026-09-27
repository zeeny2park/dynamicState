import copy
import json
import tempfile
import unittest

from extractor.debug_image import BinaryIdentity, CompatibilityResult, DebugImageProvider
from extractor.runtime_state import ExecutionState, PersistentState, RuntimeState
from extractor.snapshot import RuntimeSnapshot
from extractor.state_hash import compute_state_hash
from tests.test_state_hash import make_snapshot


class DebugImageProvenanceTests(unittest.TestCase):
    def test_provider_provenance_structure(self):
        provider = DebugImageProvider()
        provider.runtime_identity = BinaryIdentity(
            path="/opt/bin/app",
            elf_class="ELF64",
            architecture="aarch64",
            endianness="little",
            build_id="BUILD_123",
            stripped=True
        )
        provider.debug_identity = BinaryIdentity(
            path="/opt/debug/app.debug",
            elf_class="ELF64",
            architecture="aarch64",
            endianness="little",
            build_id="BUILD_123",
            stripped=False,
            has_debug_info=True
        )
        provider.compatibility = CompatibilityResult(
            compatible=True,
            reason="COMPATIBLE",
            verification_ms=0.5
        )
        provider.load_ms = 1.2
        provider.identity_check_ms = 0.8
        provider.verification_ms = 0.5

        prov = provider.get_provenance()
        self.assertIn("runtime_binary", prov)
        self.assertIn("debug_image", prov)
        self.assertIn("performance", prov)

        rb = prov["runtime_binary"]
        self.assertEqual(rb["path"], "/opt/bin/app")
        self.assertEqual(rb["build_id"], "BUILD_123")
        self.assertTrue(rb["stripped"])

        di = prov["debug_image"]
        self.assertEqual(di["path"], "/opt/debug/app.debug")
        self.assertEqual(di["build_id"], "BUILD_123")
        self.assertEqual(di["source"], "external")
        self.assertTrue(di["verified"])
        self.assertTrue(di["compatible"])

        perf = prov["performance"]
        self.assertEqual(perf["debug_image_load_ms"], 1.2)
        self.assertEqual(perf["binary_identity_check_ms"], 0.8)
        self.assertEqual(perf["debug_image_verification_ms"], 0.5)

    def test_runtime_state_and_snapshot_provenance(self):
        provenance = {
            "runtime_binary": {
                "path": "/bin/sample",
                "build_id": "ABCDEF123456",
                "stripped": True
            },
            "debug_image": {
                "path": "/debug/sample.debug",
                "build_id": "ABCDEF123456",
                "source": "external",
                "verified": True
            }
        }

        rstate = RuntimeState(
            schema_version="0.2",
            process={"pid": 100, "binary": "/bin/sample"},
            execution=ExecutionState(),
            objects=[],
            persistent=PersistentState(),
            provenance=provenance
        )

        r_dict = rstate.to_dict()
        self.assertIn("provenance", r_dict)
        self.assertEqual(r_dict["provenance"]["debug_image"]["source"], "external")

        snap = RuntimeSnapshot.from_runtime_state(rstate, "S001")
        s_dict = snap.to_dict()
        self.assertIn("provenance", s_dict)
        self.assertEqual(s_dict["provenance"]["runtime_binary"]["build_id"], "ABCDEF123456")

        # Test write_json and reload
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", delete=False) as f:
            snap_path = f.name
        try:
            snap.write_json(snap_path)
            with open(snap_path, encoding="utf-8") as f:
                reloaded = json.load(f)
            self.assertIn("provenance", reloaded)
            self.assertEqual(reloaded["provenance"]["debug_image"]["path"], "/debug/sample.debug")
        finally:
            import os
            os.unlink(snap_path)

    def test_state_hash_invariance_to_provenance_and_build_ids(self):
        """State hash must remain strictly identical whether extracted from unstripped or stripped+debug."""
        snap1 = make_snapshot(retry=2, state="CONNECTED")
        snap1["provenance"] = {
            "runtime_binary": {"path": "/opt/app", "build_id": "BUILD_A", "stripped": False},
            "debug_image": {"path": "/opt/app", "build_id": "BUILD_A", "source": "embedded", "verified": True}
        }

        snap2 = make_snapshot(retry=2, state="CONNECTED")
        snap2["provenance"] = {
            "runtime_binary": {"path": "/var/production/app_stripped", "build_id": "BUILD_B", "stripped": True},
            "debug_image": {"path": "/ci/debug_artifacts/app.debug", "build_id": "BUILD_B", "source": "external", "verified": True}
        }

        hash1 = compute_state_hash(snap1)
        hash2 = compute_state_hash(snap2)

        self.assertEqual(hash1, hash2, "Semantic state hash must be completely independent of build identity and debug image provenance!")


if __name__ == "__main__":
    unittest.main()

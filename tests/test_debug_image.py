import unittest

from extractor.debug_image import BinaryIdentity, CompatibilityResult, DebugImageProvider


class DebugImageProviderTests(unittest.TestCase):
    def setUp(self):
        self.provider = DebugImageProvider()

    def test_compatibility_result_dataclass(self):
        res = CompatibilityResult(
            compatible=True,
            reason="COMPATIBLE",
            verification_ms=1.23
        )
        d = res.to_dict()
        self.assertTrue(d["compatible"])
        self.assertEqual(d["reason"], "COMPATIBLE")
        self.assertEqual(d["verification_ms"], 1.23)

    def test_verify_architecture_mismatch(self):
        """Debug image with aarch64 must reject runtime binary with x86_64."""
        self.provider.debug_identity = BinaryIdentity(
            path="/opt/debug/app.debug",
            elf_class="ELF64",
            architecture="aarch64",
            endianness="little",
            build_id="build123",
            has_debug_info=True
        )

        # Mock inspect_elf behavior by replacing runtime identity verification
        def mock_inspect(path):
            return BinaryIdentity(
                path=path,
                elf_class="ELF64",
                architecture="x86_64",
                endianness="little",
                build_id="build123",
                stripped=True
            )

        import extractor.debug_image as di_module
        old_inspect = di_module.inspect_elf
        di_module.inspect_elf = mock_inspect
        try:
            res = self.provider.verify("/opt/bin/app")
            self.assertFalse(res.compatible)
            self.assertEqual(res.reason, "ARCHITECTURE_MISMATCH")
        finally:
            di_module.inspect_elf = old_inspect

    def test_verify_build_id_mismatch(self):
        """Matching architecture but mismatched build_id must be rejected."""
        self.provider.debug_identity = BinaryIdentity(
            path="/opt/debug/app.debug",
            elf_class="ELF64",
            architecture="aarch64",
            endianness="little",
            build_id="BUILD_DEBUG_1111",
            has_debug_info=True
        )

        def mock_inspect(path):
            return BinaryIdentity(
                path=path,
                elf_class="ELF64",
                architecture="aarch64",
                endianness="little",
                build_id="BUILD_RUNTIME_2222",
                stripped=True
            )

        import extractor.debug_image as di_module
        old_inspect = di_module.inspect_elf
        di_module.inspect_elf = mock_inspect
        try:
            res = self.provider.verify("/opt/bin/app")
            self.assertFalse(res.compatible)
            self.assertEqual(res.reason, "BUILD_ID_MISMATCH")
        finally:
            di_module.inspect_elf = old_inspect

    def test_verify_build_id_matching(self):
        """Matching architecture and matching build_id must be accepted."""
        self.provider.debug_identity = BinaryIdentity(
            path="/opt/debug/app.debug",
            elf_class="ELF64",
            architecture="aarch64",
            endianness="little",
            build_id="MATCHING_BUILD_ID_9999",
            has_debug_info=True
        )

        def mock_inspect(path):
            return BinaryIdentity(
                path=path,
                elf_class="ELF64",
                architecture="aarch64",
                endianness="little",
                build_id="MATCHING_BUILD_ID_9999",
                stripped=True
            )

        import extractor.debug_image as di_module
        old_inspect = di_module.inspect_elf
        di_module.inspect_elf = mock_inspect
        try:
            res = self.provider.verify("/opt/bin/app")
            self.assertTrue(res.compatible)
            self.assertEqual(res.reason, "COMPATIBLE")
            self.assertIsNotNone(res.runtime_identity)
            self.assertIsNotNone(res.debug_identity)
        finally:
            di_module.inspect_elf = old_inspect

    def test_verify_debuglink_fallback(self):
        """When Build ID is missing in runtime binary, fallback to .gnu_debuglink matching."""
        self.provider.debug_image_path = "/opt/debug/app.debug"
        self.provider.debug_identity = BinaryIdentity(
            path="/opt/debug/app.debug",
            elf_class="ELF64",
            architecture="aarch64",
            endianness="little",
            build_id=None,
            has_debug_info=True
        )

        def mock_inspect(path):
            return BinaryIdentity(
                path=path,
                elf_class="ELF64",
                architecture="aarch64",
                endianness="little",
                build_id=None,
                debuglink={"filename": "app.debug", "crc": 0x1234},
                stripped=True
            )

        import extractor.debug_image as di_module
        old_inspect = di_module.inspect_elf
        di_module.inspect_elf = mock_inspect
        try:
            res = self.provider.verify("/opt/bin/app")
            self.assertTrue(res.compatible)
            self.assertEqual(res.reason, "COMPATIBLE_DEBUGLINK")
        finally:
            di_module.inspect_elf = old_inspect

    def test_verify_stripped_debug_image_rejected(self):
        """A debug image that lacks debug information must be rejected."""
        self.provider.debug_identity = BinaryIdentity(
            path="/opt/debug/app.debug",
            elf_class="ELF64",
            architecture="aarch64",
            endianness="little",
            build_id="BUILD_123",
            stripped=True,
            has_debug_info=False
        )

        def mock_inspect(path):
            return BinaryIdentity(
                path=path,
                elf_class="ELF64",
                architecture="aarch64",
                endianness="little",
                build_id="BUILD_123",
                stripped=True
            )

        import extractor.debug_image as di_module
        old_inspect = di_module.inspect_elf
        di_module.inspect_elf = mock_inspect
        try:
            res = self.provider.verify("/opt/bin/app")
            self.assertFalse(res.compatible)
            self.assertEqual(res.reason, "DEBUG_INFO_MISSING")
        finally:
            di_module.inspect_elf = old_inspect

    def test_verify_runtime_binary_not_found(self):
        self.provider.debug_identity = BinaryIdentity(
            path="/opt/debug/app.debug",
            elf_class="ELF64",
            architecture="aarch64",
            endianness="little",
            build_id="BUILD_123",
            has_debug_info=True
        )
        res = self.provider.verify("/path/to/definitely/nonexistent/app")
        self.assertFalse(res.compatible)
        self.assertEqual(res.reason, "RUNTIME_BINARY_NOT_FOUND")

    def test_module_debug_images_mapping(self):
        """Test shared library debug image registration and retrieval."""
        self.provider.register_module_debug_image("libsample.so", "/opt/debug/libsample.so.debug")
        self.assertEqual(
            self.provider.get_module_debug_image("libsample.so"),
            "/opt/debug/libsample.so.debug"
        )
        self.assertIsNone(self.provider.get_module_debug_image("libunknown.so"))


if __name__ == "__main__":
    unittest.main()

import os
import struct
import sys
import tempfile
import unittest

from extractor.debug_image import BinaryIdentity, inspect_elf


class BinaryIdentityTests(unittest.TestCase):
    def test_inspect_current_system_binary(self):
        """Test inspect_elf on standard system binaries."""
        path = sys.executable  # /usr/bin/python3
        if not os.path.exists(path):
            path = "/bin/bash"

        ident = inspect_elf(path)
        self.assertIsInstance(ident, BinaryIdentity)
        self.assertEqual(ident.path, os.path.abspath(path))
        self.assertIn(ident.elf_class, ("ELF32", "ELF64"))
        self.assertIn(ident.endianness, ("little", "big"))
        self.assertIn(ident.architecture, ("x86_64", "aarch64", "arm", "x86", "riscv"))
        self.assertIsInstance(ident.stripped, bool)
        self.assertIsInstance(ident.has_debug_info, bool)
        if ident.build_id is not None:
            self.assertIsInstance(ident.build_id, str)
            self.assertGreater(len(ident.build_id), 0)

    def test_nonexistent_file(self):
        """inspect_elf must raise FileNotFoundError for nonexistent paths."""
        with self.assertRaises(FileNotFoundError):
            inspect_elf("/path/to/nonexistent/binary_xyz")

    def test_invalid_elf_magic(self):
        """inspect_elf must raise ValueError for non-ELF files."""
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(b"NOT_AN_ELF_BINARY_CONTENT")
            temp_path = f.name
        try:
            with self.assertRaisesRegex(ValueError, "Invalid ELF magic"):
                inspect_elf(temp_path)
        finally:
            os.unlink(temp_path)

    def test_truncated_elf_file(self):
        """inspect_elf must raise ValueError for truncated ELF headers."""
        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(b"\x7fELF\x02\x01\x01\x00")  # only 8 bytes
            temp_path = f.name
        try:
            with self.assertRaises(ValueError):
                inspect_elf(temp_path)
        finally:
            os.unlink(temp_path)

    def test_synthetic_elf64_parsing(self):
        """Test synthetic ELF64 binary with .note.gnu.build-id and .gnu_debuglink."""
        # Construct a minimal ELF64 in memory
        endian = "<"
        ei_class = 2  # 64-bit
        ei_data = 1   # little-endian
        e_machine = 183  # aarch64

        ident = b"\x7fELF" + bytes([ei_class, ei_data, 1, 0]) + b"\x00" * 8

        # Section string table (shstrtab)
        # We need section names: "", ".shstrtab", ".note.gnu.build-id", ".gnu_debuglink", ".debug_info"
        strtab = b"\x00.shstrtab\x00.note.gnu.build-id\x00.gnu_debuglink\x00.debug_info\x00"
        idx_shstrtab = strtab.find(b".shstrtab")
        idx_buildid = strtab.find(b".note.gnu.build-id")
        idx_debuglink = strtab.find(b".gnu_debuglink")
        idx_debuginfo = strtab.find(b".debug_info")

        # Build ID note: namesz=4 ("GNU\0"), descsz=20 (hex 1234...40 chars), type=3
        fake_build_id_bytes = bytes.fromhex("0123456789abcdef0123456789abcdef01234567")
        note_content = struct.pack(endian + "III", 4, 20, 3) + b"GNU\x00" + fake_build_id_bytes

        # Debuglink content: filename "test.debug\0" + padding + crc 0x12345678
        dl_str = b"test.debug\x00"
        dl_padded = dl_str + b"\x00" * ((4 - (len(dl_str) % 4)) % 4)
        dl_content = dl_padded + struct.pack(endian + "I", 0x12345678)

        # File layout:
        # 0..64: ELF Header
        # 64..64+len(strtab): shstrtab
        # next: note_content
        # next: dl_content
        # next: section headers
        offset_strtab = 64
        offset_note = offset_strtab + len(strtab)
        offset_dl = offset_note + len(note_content)
        offset_sh = offset_dl + len(dl_content)

        # 5 sections: [0]=NULL, [1]=.shstrtab, [2]=.note.gnu.build-id, [3]=.gnu_debuglink, [4]=.debug_info
        shentsize = 64
        shnum = 5
        shstrndx = 1

        hdr = struct.pack(
            endian + "HHIQQQIHHHHHH",
            2,            # e_type (EXEC)
            e_machine,    # e_machine (183 = aarch64)
            1,            # e_version
            0x400000,     # e_entry
            0,            # e_phoff
            offset_sh,    # e_shoff
            0,            # e_flags
            64,           # e_ehsize
            0,            # e_phentsize
            0,            # e_phnum
            shentsize,    # e_shentsize
            shnum,        # e_shnum
            shstrndx      # e_shstrndx
        )

        def make_sh(name_idx, s_type, s_offset, s_size):
            return struct.pack(endian + "IIQQQQIIQQ", name_idx, s_type, 0, 0, s_offset, s_size, 0, 0, 4, 0)

        sh_null = make_sh(0, 0, 0, 0)
        sh_strtab = make_sh(idx_shstrtab, 3, offset_strtab, len(strtab))
        sh_note = make_sh(idx_buildid, 7, offset_note, len(note_content))
        sh_dl = make_sh(idx_debuglink, 1, offset_dl, len(dl_content))
        sh_dinfo = make_sh(idx_debuginfo, 1, 0, 0)

        sh_table = sh_null + sh_strtab + sh_note + sh_dl + sh_dinfo

        payload = ident + hdr + strtab + note_content + dl_content + sh_table

        with tempfile.NamedTemporaryFile("wb", delete=False) as f:
            f.write(payload)
            temp_path = f.name

        try:
            parsed = inspect_elf(temp_path)
            self.assertEqual(parsed.elf_class, "ELF64")
            self.assertEqual(parsed.architecture, "aarch64")
            self.assertEqual(parsed.endianness, "little")
            self.assertEqual(parsed.build_id, "0123456789abcdef0123456789abcdef01234567")
            self.assertIsNotNone(parsed.debuglink)
            self.assertEqual(parsed.debuglink["filename"], "test.debug")
            self.assertEqual(parsed.debuglink["crc"], 0x12345678)
            self.assertTrue(parsed.has_debug_info)
        finally:
            os.unlink(temp_path)


if __name__ == "__main__":
    unittest.main()

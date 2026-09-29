"""Unit tests for GDB Python API compatibility layer."""

import unittest
from unittest.mock import MagicMock

from extractor.gdb_compat import (
    get_frame_function,
    get_frame_level,
    get_frame_pc,
    get_gdb_version,
    get_progspace_filename,
    is_thread_stopped,
)


class GdbCompatTests(unittest.TestCase):
    def test_get_gdb_version(self):
        mock_gdb_9 = MagicMock()
        mock_gdb_9.VERSION = "9.2"
        v9 = get_gdb_version(mock_gdb_9)
        self.assertEqual(v9.major, 9)
        self.assertEqual(v9.minor, 2)
        self.assertEqual(v9.status, "RESOLVED")
        self.assertTrue(v9.is_known())
        self.assertFalse(v9.supports_frame_level())
        # Tuple unpacking compatibility
        self.assertEqual(tuple(v9), (9, 2, "9.2"))

        mock_gdb_11 = MagicMock()
        mock_gdb_11.VERSION = "11.1-ubuntu"
        v11 = get_gdb_version(mock_gdb_11)
        self.assertEqual(v11.major, 11)
        self.assertEqual(v11.minor, 1)
        self.assertEqual(v11.status, "RESOLVED")
        self.assertTrue(v11.supports_frame_level())
        self.assertEqual(tuple(v11), (11, 1, "11.1-ubuntu"))

        mock_gdb_15 = MagicMock()
        mock_gdb_15.VERSION = "15.1-1ubuntu1~24.04.1"
        v15 = get_gdb_version(mock_gdb_15)
        self.assertEqual(v15.major, 15)
        self.assertEqual(v15.minor, 1)
        self.assertTrue(v15.supports_frame_level())

        # NEVER fall back to (9, 2, "9.2") on None or unknown
        v_none = get_gdb_version(None)
        self.assertIsNone(v_none.major)
        self.assertIsNone(v_none.minor)
        self.assertEqual(v_none.status, "UNKNOWN")
        self.assertFalse(v_none.is_known())
        self.assertFalse(v_none.supports_frame_level())

        mock_unknown = MagicMock()
        mock_unknown.VERSION = "custom-gdb-without-digits"
        v_unk = get_gdb_version(mock_unknown)
        self.assertIsNone(v_unk.major)
        self.assertEqual(v_unk.status, "UNKNOWN")
        self.assertFalse(v_unk.is_known())

    def test_get_frame_level_gdb_11_plus(self):
        """Modern GDB frames have .level() method."""
        frame = MagicMock()
        frame.level.return_value = 3
        self.assertEqual(get_frame_level(frame, fallback_level=0), 3)

    def test_get_frame_level_gdb_9_2(self):
        """GDB 9.2/10 frames lack .level() method."""
        class MockFrameGdb9:
            pass

        frame = MockFrameGdb9()
        self.assertEqual(get_frame_level(frame, fallback_level=2), 2)
        self.assertEqual(get_frame_level(None, fallback_level=5), 5)

    def test_get_frame_function_and_pc(self):
        frame = MagicMock()
        frame.name.return_value = "process_packet"
        frame.pc.return_value = 0x401000

        self.assertEqual(get_frame_function(frame), "process_packet")
        self.assertEqual(get_frame_pc(frame), 0x401000)

        # Faulty frame
        faulty = MagicMock()
        faulty.name.side_effect = RuntimeError("cannot read name")
        faulty.pc.side_effect = RuntimeError("cannot read pc")
        self.assertEqual(get_frame_function(faulty), "<unknown>")
        self.assertIsNone(get_frame_pc(faulty))

    def test_get_progspace_filename(self):
        mock_gdb = MagicMock()
        mock_ps = MagicMock()
        mock_ps.filename = "/bin/sample_app"
        mock_gdb.current_progspace.return_value = mock_ps

        self.assertEqual(get_progspace_filename(mock_gdb), "/bin/sample_app")
        self.assertIsNone(get_progspace_filename(None))

    def test_is_thread_stopped(self):
        thread = MagicMock()
        thread.is_stopped.return_value = True
        self.assertTrue(is_thread_stopped(thread))

        thread.is_stopped.return_value = False
        self.assertFalse(is_thread_stopped(thread))

        self.assertFalse(is_thread_stopped(None))


if __name__ == "__main__":
    unittest.main()

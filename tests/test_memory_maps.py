import unittest

from extractor.memory_maps import MemoryMapProvider, MemoryRegion


class MemoryMapTests(unittest.TestCase):
    def test_classifies_only_addresses_in_known_regions(self):
        provider = MemoryMapProvider(None)
        provider._regions = [
            MemoryRegion(0x1000, 0x2000, "rw-p", "[heap]", "heap"),
            MemoryRegion(0x3000, 0x4000, "rw-p", "[stack]", "stack"),
        ]
        self.assertEqual(provider.classify(0x1001), "heap")
        self.assertEqual(provider.classify("0x3001"), "stack")
        self.assertEqual(provider.classify(0x9000), "unknown")

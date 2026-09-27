"""Linux process mapping reader; it classifies known addresses only."""

from dataclasses import dataclass


@dataclass(frozen=True)
class MemoryRegion:
    start: int
    end: int
    permissions: str
    path: str
    kind: str


class MemoryMapProvider:
    def __init__(self, pid, binary=None):
        self.pid = pid
        self.binary = binary
        self._regions = None

    def get_regions(self):
        if self._regions is not None:
            return self._regions
        regions = []
        if not self.pid:
            self._regions = regions
            return regions
        try:
            with open("/proc/{}/maps".format(self.pid), encoding="utf-8") as maps:
                for line in maps:
                    parts = line.rstrip("\n").split(None, 5)
                    if len(parts) < 5:
                        continue
                    start_text, end_text = parts[0].split("-", 1)
                    path = parts[5] if len(parts) == 6 else ""
                    regions.append(MemoryRegion(int(start_text, 16), int(end_text, 16),
                                                parts[1], path, self._kind(parts[1], path)))
        except (OSError, ValueError):
            pass
        self._regions = regions
        return regions

    def classify(self, address):
        if address is None:
            return "unknown"
        try:
            number = int(address, 16) if isinstance(address, str) else int(address)
        except (TypeError, ValueError):
            return "unknown"
        for region in self.get_regions():
            if region.start <= number < region.end:
                return region.kind
        return "unknown"

    def _kind(self, permissions, path):
        if path == "[heap]":
            return "heap"
        if path.startswith("[stack"):
            return "stack"
        if permissions.endswith("s"):
            return "shared"
        # File-backed mapping of the main executable contains globals/static
        # storage. This is a mapping classification, not a lifetime claim.
        if self.binary and path and path == self.binary:
            return "global"
        if path and not path.startswith("["):
            return "mmap"
        return "unknown"

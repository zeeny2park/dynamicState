"""Linux process_vm_readv memory capture engine for Phase 5.1.

Copies readable memory regions from an inferior process without stopping execution,
enforcing safety bounds (max total bytes, max region bytes, timeouts) and tracking
partial reads / errors at per-region granularity.
"""

import ctypes
import os
import platform
import time
from typing import Any, Dict, List, Optional, Tuple

from .memory_maps import MemoryMapProvider, MemoryRegion
from .memory_snapshot import CapturedRegion, RawMemorySnapshot
from .snapshot_consistency import NON_ATOMIC, SnapshotConsistency
from .snapshot_regions import (
    DEFAULT_MAX_REGION_BYTES,
    DEFAULT_MAX_TOTAL_BYTES,
    POLICY_ALL_READABLE,
    filter_regions,
)


class _struct_iovec(ctypes.Structure):
    _fields_ = [
        ("iov_base", ctypes.c_void_p),
        ("iov_len", ctypes.c_size_t),
    ]


class MemoryCapture:
    """Non-intrusive memory capture engine utilizing Linux process_vm_readv()."""

    def __init__(self, page_size: int = 4096):
        self.page_size = page_size
        self._libc = None
        self._has_process_vm_readv = False

        if platform.system() == "Linux":
            try:
                self._libc = ctypes.CDLL(None, use_errno=True)
                if hasattr(self._libc, "process_vm_readv"):
                    fn = self._libc.process_vm_readv
                    fn.argtypes = [
                        ctypes.c_int,                    # pid
                        ctypes.POINTER(_struct_iovec),   # local_iov
                        ctypes.c_ulong,                  # liovcnt
                        ctypes.POINTER(_struct_iovec),   # remote_iov
                        ctypes.c_ulong,                  # riovcnt
                        ctypes.c_ulong                   # flags
                    ]
                    fn.restype = ctypes.c_ssize_t
                    self._has_process_vm_readv = True
            except Exception:
                self._has_process_vm_readv = False

    @property
    def is_supported(self) -> bool:
        return self._has_process_vm_readv

    def capture(
        self,
        pid: int,
        policy: str = POLICY_ALL_READABLE,
        output_dir: Optional[str] = None,
        max_bytes: int = DEFAULT_MAX_TOTAL_BYTES,
        max_region_bytes: int = DEFAULT_MAX_REGION_BYTES,
        timeout_ms: int = 2000,
        snapshot_id: Optional[str] = None,
        selected_ranges: Optional[List[Tuple[int, int]]] = None,
    ) -> RawMemorySnapshot:
        """Capture memory regions from target process without halting it."""
        if not self._has_process_vm_readv:
            raise RuntimeError("process_vm_readv is not supported on this platform/kernel")

        # 1. PID and process validation
        if not isinstance(pid, int) or pid <= 0:
            raise ValueError(f"Invalid pid: {pid}")

        proc_dir = f"/proc/{pid}"
        if not os.path.exists(proc_dir):
            raise ProcessLookupError(f"Process with PID {pid} does not exist (ESRCH)")

        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            raise ProcessLookupError(f"Process with PID {pid} is not running (ESRCH)")
        except PermissionError:
            raise PermissionError(f"Permission denied inspecting PID {pid} (EPERM)")

        # 2. Binary path detection
        binary_path = ""
        exe_link = os.path.join(proc_dir, "exe")
        if os.path.exists(exe_link):
            try:
                binary_path = os.path.realpath(exe_link)
            except Exception:
                pass

        # 3. Snapshot ID and output setup
        sid = snapshot_id or "M{:04d}".format(int(time.time() * 1000) % 10000)
        target_dir = output_dir or os.path.join("memory_snapshots", sid)
        mem_dir = os.path.join(target_dir, "memory")
        os.makedirs(mem_dir, exist_ok=True)

        # 4. Read memory maps
        map_provider = MemoryMapProvider(pid, binary=binary_path)
        all_regions = map_provider.get_regions()
        selected_regions = filter_regions(
            all_regions,
            policy=policy,
            selected_ranges=selected_ranges,
            max_total_bytes=max_bytes,
            max_region_bytes=max_region_bytes,
        )

        # 5. Capture memory regions via process_vm_readv
        t_start_ns = time.monotonic_ns()
        captured_regions: List[CapturedRegion] = []
        bytes_requested = 0
        bytes_captured = 0
        partial_reads = 0
        failed_reads = 0

        fn_vm_readv = self._libc.process_vm_readv
        deadline_ns = t_start_ns + (timeout_ms * 1_000_000)

        for idx, region in enumerate(selected_regions, start=1):
            if time.monotonic_ns() > deadline_ns:
                # Timeout limit reached
                break

            reg_id = "R{:06d}".format(idx)
            req_size = region.size
            bytes_requested += req_size

            # Allocate local buffer
            buf = ctypes.create_string_buffer(req_size)
            l_iov = _struct_iovec(ctypes.cast(buf, ctypes.c_void_p), req_size)
            r_iov = _struct_iovec(ctypes.c_void_p(region.start), req_size)

            nread = fn_vm_readv(
                pid,
                ctypes.byref(l_iov),
                1,
                ctypes.byref(r_iov),
                1,
                0
            )

            if nread < 0:
                err = ctypes.get_errno()
                err_str = "EFAULT" if err == 14 else ("ESRCH" if err == 3 else ("EPERM" if err == 1 else f"ERRNO_{err}"))
                failed_reads += 1
                captured_regions.append(CapturedRegion(
                    region_id=reg_id,
                    start=region.start,
                    end=region.end,
                    size=req_size,
                    permissions=region.permissions,
                    category=region.category,
                    pathname=region.pathname,
                    requested=req_size,
                    captured=0,
                    status="FAILED",
                    filename=None,
                    error=err_str
                ))
            elif nread < req_size:
                # Partial read
                partial_reads += 1
                bytes_captured += nread
                rel_file = os.path.join("memory", f"region_{idx:06d}.bin")
                bin_path = os.path.join(target_dir, rel_file)
                with open(bin_path, "wb") as f_bin:
                    f_bin.write(buf.raw[:nread])

                captured_regions.append(CapturedRegion(
                    region_id=reg_id,
                    start=region.start,
                    end=region.start + nread,
                    size=req_size,
                    permissions=region.permissions,
                    category=region.category,
                    pathname=region.pathname,
                    requested=req_size,
                    captured=nread,
                    status="PARTIAL",
                    filename=rel_file,
                    error=f"PARTIAL_READ_{nread}_OF_{req_size}"
                ))
            else:
                # Complete read
                bytes_captured += nread
                rel_file = os.path.join("memory", f"region_{idx:06d}.bin")
                bin_path = os.path.join(target_dir, rel_file)
                with open(bin_path, "wb") as f_bin:
                    f_bin.write(buf.raw[:nread])

                captured_regions.append(CapturedRegion(
                    region_id=reg_id,
                    start=region.start,
                    end=region.end,
                    size=req_size,
                    permissions=region.permissions,
                    category=region.category,
                    pathname=region.pathname,
                    requested=req_size,
                    captured=nread,
                    status="COMPLETE",
                    filename=rel_file,
                    error=None
                ))

        t_end_ns = time.monotonic_ns()
        duration_us = (t_end_ns - t_start_ns) / 1000.0

        # Determine overall status
        if not captured_regions or (failed_reads == len(captured_regions)):
            overall_status = "FAILED"
        elif partial_reads > 0 or failed_reads > 0:
            overall_status = "PARTIAL"
        else:
            overall_status = "COMPLETE"

        # Determine architecture
        arch = platform.machine()
        if arch in ("x86_64", "AMD64"):
            arch_norm = "x86_64"
        elif arch in ("aarch64", "arm64"):
            arch_norm = "aarch64"
        else:
            arch_norm = arch

        raw_snapshot = RawMemorySnapshot(
            snapshot_id=sid,
            pid=pid,
            binary=binary_path,
            timestamp_ns=t_start_ns,
            capture_mode="LOW_IMPACT",
            backend="process_vm_readv",
            architecture=arch_norm,
            endianness="little",
            page_size=self.page_size,
            status=overall_status,
            regions_requested=len(selected_regions),
            regions_captured=len([r for r in captured_regions if r.captured > 0]),
            bytes_requested=bytes_requested,
            bytes_captured=bytes_captured,
            partial_reads=partial_reads,
            failed_reads=failed_reads,
            duration_us=duration_us,
            capture_start_ns=t_start_ns,
            capture_end_ns=t_end_ns,
            consistency=SnapshotConsistency(
                level=NON_ATOMIC,
                capture_start_ns=t_start_ns,
                capture_end_ns=t_end_ns,
                duration_us=duration_us,
                partial_reads=partial_reads,
                failed_reads=failed_reads,
            ).to_dict(),
            output_dir=os.path.abspath(target_dir),
            regions=captured_regions,
            maps=[r.to_dict() for r in all_regions],
        )

        raw_snapshot.save(target_dir)
        return raw_snapshot

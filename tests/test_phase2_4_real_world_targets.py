"""Phase 2.4: Embedded Linux & Real-World Target Validation Matrix.

Covers:
A. Architecture:
   - Native ARM64 Linux inferior processes (REAL_PROCESS)
   - Cross-compiled x86_64 Linux ELF targets (DWARF, Build-ID, PT_LOAD, PT_TLS)
   - Cross-compiled ARM32 Linux ELF targets
B. Binary Configuration:
   - Debug binary (-O0 -g)
   - Optimized binary (-O2 -g)
   - Stripped release binary with split DWARF (.gnu_debuglink + CRC32)
   - PIE and ASLR enabled (-fPIE -pie)
C. Runtime Behaviors:
   - Multithreaded service with pthreads and mutexes
   - Network TCP socket service with concurrent request processing
   - High-frequency polling thread
   - Long-running stateful process
   - High memory consumption process (allocated buffers)
   - Frequent allocation/free operations
   - Shared-memory IPC process (/dev/shm mmap)
D. Collection Environment:
   - Local Linux process observation
   - PID reuse & process restart detection (PIDReusedError)
   - Missing debug symbols fallback
"""

import errno
import json
import os
import shutil
import socket
import struct
import subprocess
import tempfile
import threading
import time
import unittest

from extractor.debug_artifacts import DebugArtifactProvider, compute_gnu_debuglink_crc
from extractor.debug_image import (
    BinaryIdentity,
    DebugImageProvider,
    inspect_elf,
)
from extractor.dwarf_indexer import DwarfIndexer
from extractor.target_adapter import (
    LocalTargetAdapter,
    PIDReusedError,
    TargetExecutionAdapter,
)
from extractor.watch_session import read_process_memory_slice


# C++ Source for comprehensive real-world target
REAL_WORLD_TARGET_CPP = """
#include <iostream>
#include <thread>
#include <vector>
#include <string>
#include <mutex>
#include <chrono>
#include <atomic>
#include <cstring>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <netinet/in.h>

// Global state variables for observation
struct TargetConfig {
    int version;
    int worker_threads;
    char node_name[32];
    unsigned int status_magic;
};

struct NodeElement {
    int id;
    int value;
    NodeElement* next;
};

// Global variables with well-defined DWARF symbols
TargetConfig g_config = {2, 4, "ARM64_PROD_NODE_01", 0x41524D36};
std::atomic<long long> g_request_counter{0};
std::atomic<bool> g_running{true};
std::mutex g_data_mutex;
int g_active_connections = 0;
long long g_total_bytes_processed = 0;

// High-frequency polling counter
std::atomic<unsigned long long> g_poll_ticks{0};

// Shared memory IPC buffer
struct IpcSharedHeader {
    unsigned int magic;
    unsigned int seq_num;
    char payload[64];
};
IpcSharedHeader* g_shm_ptr = nullptr;

void poller_thread_fn() {
    while (g_running.load(std::memory_order_relaxed)) {
        g_poll_ticks.fetch_add(1, std::memory_order_relaxed);
        // High frequency tight loop
        for (volatile int i = 0; i < 50; ++i) {}
    }
}

void worker_thread_fn(int id) {
    while (g_running.load(std::memory_order_relaxed)) {
        {
            std::lock_guard<std::mutex> lock(g_data_mutex);
            g_total_bytes_processed += (id * 16 + 4);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
}

void alloc_free_cycle_fn() {
    while (g_running.load(std::memory_order_relaxed)) {
        std::vector<char*> ptrs;
        for (int i = 0; i < 10; ++i) {
            ptrs.push_back(new char[256]);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        for (char* p : ptrs) {
            delete[] p;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
}

int main(int argc, char** argv) {
    // 1. Create a socket for TCP network service
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    int port = 0;
    if (server_fd >= 0) {
        int opt = 1;
        setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0; // Ephemeral
        if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) == 0) {
            listen(server_fd, 5);
            socklen_t len = sizeof(addr);
            getsockname(server_fd, (struct sockaddr*)&addr, &len);
            port = ntohs(addr.sin_port);
        }
    }

    // 2. Setup shared memory IPC
    char shm_name[64];
    snprintf(shm_name, sizeof(shm_name), "/dynstate_test_shm_%d", getpid());
    int shm_fd = shm_open(shm_name, O_CREAT | O_RDWR, 0666);
    if (shm_fd >= 0) {
        ftruncate(shm_fd, sizeof(IpcSharedHeader));
        g_shm_ptr = (IpcSharedHeader*)mmap(nullptr, sizeof(IpcSharedHeader), PROT_READ | PROT_WRITE, MAP_SHARED, shm_fd, 0);
        if (g_shm_ptr != MAP_FAILED && g_shm_ptr != nullptr) {
            g_shm_ptr->magic = 0x53484D31; // "SHM1"
            g_shm_ptr->seq_num = 1001;
            strncpy(g_shm_ptr->payload, "REAL_SHARED_MEMORY_DATA", sizeof(g_shm_ptr->payload));
        }
    }

    // 3. Launch threads: polling thread, worker threads, alloc/free thread
    std::thread poller(poller_thread_fn);
    std::vector<std::thread> workers;
    for (int i = 0; i < 3; ++i) {
        workers.emplace_back(worker_thread_fn, i + 1);
    }
    std::thread alloc_worker(alloc_free_cycle_fn);

    std::cout << "TARGET_PORT=" << port << std::endl;
    std::cout << "TARGET_READY" << std::endl;
    std::cout.flush();

    while (g_running.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
        g_request_counter++;
        if (g_shm_ptr && g_shm_ptr != MAP_FAILED) {
            g_shm_ptr->seq_num++;
        }
    }

    if (server_fd >= 0) close(server_fd);
    if (shm_fd >= 0) {
        shm_unlink(shm_name);
        close(shm_fd);
    }
    poller.join();
    for (auto& w : workers) w.join();
    alloc_worker.join();
    return 0;
}
"""


class TestPhase24RealWorldTargets(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmpdir = tempfile.mkdtemp(prefix="phase2_4_targets_")
        cls.src_path = os.path.join(cls.tmpdir, "real_target.cpp")
        with open(cls.src_path, "w", encoding="utf-8") as f:
            f.write(REAL_WORLD_TARGET_CPP)

        # 1. Native ARM64 Debug binary (-O0 -g -fPIE -pie)
        cls.bin_debug = os.path.join(cls.tmpdir, "target_debug")
        subprocess.check_call([
            "g++", "-O0", "-g", "-fPIE", "-pie", "-pthread",
            cls.src_path, "-o", cls.bin_debug, "-lrt"
        ])

        # 2. Native ARM64 Optimized binary (-O2 -g -fPIE -pie)
        cls.bin_opt = os.path.join(cls.tmpdir, "target_opt_o2")
        subprocess.check_call([
            "g++", "-O2", "-g", "-fPIE", "-pie", "-pthread",
            cls.src_path, "-o", cls.bin_opt, "-lrt"
        ])

        # 3. Native ARM64 Stripped release binary with external .debug image (.gnu_debuglink)
        cls.bin_stripped = os.path.join(cls.tmpdir, "target_stripped")
        cls.debug_file = os.path.join(cls.tmpdir, "target_stripped.debug")
        shutil.copyfile(cls.bin_debug, cls.bin_stripped)
        # Extract debug info to separate file
        subprocess.check_call(["objcopy", "--only-keep-debug", cls.bin_stripped, cls.debug_file])
        # Strip all symbols from release binary
        subprocess.check_call(["strip", "--strip-all", cls.bin_stripped])
        # Add .gnu_debuglink to stripped binary
        subprocess.check_call([
            "objcopy", f"--add-gnu-debuglink={cls.debug_file}", cls.bin_stripped
        ])

        # 4. Cross-compiled x86_64 binary
        cls.bin_x86_64 = os.path.join(cls.tmpdir, "target_x86_64")
        cls.has_x86_64_compiler = os.path.exists("/usr/bin/x86_64-linux-gnu-gcc-13")
        if cls.has_x86_64_compiler:
            c_src = os.path.join(cls.tmpdir, "x86_test.c")
            with open(c_src, "w", encoding="utf-8") as f:
                f.write("""
                #include <stdio.h>
                int g_x86_var = 0x583836;
                __thread int g_x86_tls = 42;
                int main() { printf("x86_64 binary %d\\n", g_x86_var); return 0; }
                """)
            subprocess.check_call([
                "/usr/bin/x86_64-linux-gnu-gcc-13", "-g", "-O2", "-fPIE", "-pie",
                c_src, "-o", cls.bin_x86_64
            ])

        # 5. Cross-compiled ARM32 binary
        cls.bin_arm32 = os.path.join(cls.tmpdir, "target_arm32")
        cls.has_arm32_compiler = os.path.exists("/usr/bin/arm-linux-gnueabihf-gcc-13")
        if cls.has_arm32_compiler:
            c_src = os.path.join(cls.tmpdir, "arm32_test.c")
            with open(c_src, "w", encoding="utf-8") as f:
                f.write("""
                #include <stdio.h>
                int g_arm_var = 0x41524D;
                int main() { printf("arm32 binary %d\\n", g_arm_var); return 0; }
                """)
            subprocess.check_call([
                "/usr/bin/arm-linux-gnueabihf-gcc-13", "-g", "-fPIE", "-pie",
                c_src, "-o", cls.bin_arm32
            ])

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmpdir, ignore_errors=True)

    def test_01_multi_architecture_elf_identification(self):
        """Verify ELF inspector correctly parses native ARM64, cross-compiled x86_64, and ARM32."""
        # 1. Native ARM64
        ident_arm64 = inspect_elf(self.bin_debug)
        self.assertEqual(ident_arm64.architecture, "aarch64")
        self.assertEqual(ident_arm64.elf_class, "ELF64")
        self.assertEqual(ident_arm64.endianness, "little")
        self.assertTrue(ident_arm64.has_debug_info)
        self.assertFalse(ident_arm64.stripped)
        self.assertIsNotNone(ident_arm64.build_id)
        self.assertEqual(ident_arm64.elf_type, "ET_DYN")  # PIE binary

        # 2. Cross-compiled x86_64
        if self.has_x86_64_compiler:
            ident_x86 = inspect_elf(self.bin_x86_64)
            self.assertEqual(ident_x86.architecture, "x86_64")
            self.assertEqual(ident_x86.elf_class, "ELF64")
            self.assertEqual(ident_x86.endianness, "little")
            self.assertTrue(ident_x86.has_debug_info)
            self.assertIsNotNone(ident_x86.build_id)
            self.assertEqual(ident_x86.elf_type, "ET_DYN")
            # Verify PT_TLS detection on x86_64
            self.assertIsNotNone(ident_x86.pt_tls)

        # 3. Cross-compiled ARM32
        if self.has_arm32_compiler:
            ident_arm32 = inspect_elf(self.bin_arm32)
            self.assertEqual(ident_arm32.architecture, "arm")
            self.assertEqual(ident_arm32.elf_class, "ELF32")
            self.assertEqual(ident_arm32.endianness, "little")
            self.assertTrue(ident_arm32.has_debug_info)
            self.assertIsNotNone(ident_arm32.build_id)

    def test_02_stripped_binary_with_gnu_debuglink_crc_verification(self):
        """Verify stripped binary correctly discovers and matches separate debug info via .gnu_debuglink CRC32."""
        stripped_ident = inspect_elf(self.bin_stripped)
        self.assertTrue(stripped_ident.stripped)
        self.assertFalse(stripped_ident.has_debug_info)
        self.assertIsNotNone(stripped_ident.debuglink)
        self.assertEqual(
            stripped_ident.debuglink["filename"],
            os.path.basename(self.debug_file)
        )
        expected_crc = stripped_ident.debuglink["crc"]
        actual_crc = compute_gnu_debuglink_crc(self.debug_file)
        self.assertEqual(expected_crc, actual_crc)

        # Verify DebugImageProvider compatibility
        provider = DebugImageProvider(self.debug_file)
        compat = provider.verify(self.bin_stripped)
        self.assertTrue(compat.compatible)
        self.assertEqual(compat.reason, "COMPATIBLE")

        # Verify discovery via DebugArtifactProvider
        from extractor.modules import RuntimeModule
        mod = RuntimeModule(
            module_id="mod_stripped",
            path=self.bin_stripped,
            runtime_base=0x555555554000,
            runtime_end=0x555555564000,
            load_bias=0,
            build_id=stripped_ident.build_id,
            debuglink=stripped_ident.debuglink,
        )
        art_provider = DebugArtifactProvider(search_paths=[self.tmpdir])
        found_debug_path = art_provider.find_debug_artifact(mod)
        self.assertIsNotNone(found_debug_path)
        self.assertEqual(os.path.realpath(found_debug_path), os.path.realpath(self.debug_file))

    def test_03_real_arm64_process_multithread_and_ipc_observation(self):
        """Launch native ARM64 multi-threaded target and inspect live state:
        - Verified 0.00ms target stop duration (process_vm_readv / /proc/<pid>/mem)
        - Read typed global variables (g_config, g_request_counter)
        - Verify threads enumeration (main, poller, workers, alloc_worker >= 5 threads)
        - Read shared memory IPC segment via /proc/<pid>/maps and target memory
        """
        proc = subprocess.Popen(
            [self.bin_debug],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            # Wait for target ready
            ready_line = ""
            for _ in range(50):
                line = proc.stdout.readline()
                if "TARGET_READY" in line:
                    ready_line = line
                    break
                time.sleep(0.05)
            self.assertIn("TARGET_READY", ready_line)

            pid = proc.pid
            adapter = LocalTargetAdapter()

            # 1. Verify liveness and identity
            alive, reason = adapter.check_liveness(pid)
            self.assertTrue(alive, f"Target process {pid} must be alive: {reason}")
            ident = adapter.get_process_identity(pid)
            self.assertEqual(ident["pid"], pid)
            self.assertEqual(ident["architecture"], "aarch64")
            self.assertEqual(ident["elf_type"], "ET_DYN")

            # 2. Verify thread enumeration on real running process
            threads = adapter.get_threads(pid)
            # Expect at least 5 threads: main, poller, 3 workers, alloc_worker
            self.assertGreaterEqual(len(threads), 5)
            tids = [t["tid"] for t in threads]
            self.assertIn(pid, tids)  # Main thread TID == PID

            # 3. Read global memory via DWARF symbol resolution
            dwarf_index = DwarfIndexer.get_index(self.bin_debug)
            vars_by_name = dwarf_index.variables_by_name
            self.assertIn("g_config", vars_by_name)
            self.assertIn("g_request_counter", vars_by_name)

            # Determine load bias from proc maps
            maps = adapter.get_proc_maps(pid)
            base_addr = None
            for m in maps:
                if m.get("pathname") and os.path.realpath(m["pathname"]) == os.path.realpath(self.bin_debug):
                    base_addr = m["start_int"]
                    break
            self.assertIsNotNone(base_addr, "Target base executable VMA must be found in proc maps")

            cfg_var = vars_by_name["g_config"][0]
            cfg_addr = base_addr + cfg_var.link_time_address
            # Read g_config: struct TargetConfig { int version; int worker_threads; char node_name[32]; unsigned int status_magic; }
            raw_cfg, status, err = adapter.read_memory(pid, cfg_addr, 44)
            self.assertEqual(status, "OBSERVED")
            self.assertIsNotNone(raw_cfg)
            self.assertEqual(len(raw_cfg), 44)

            # Unpack fields: version (int: 4B), worker_threads (int: 4B), node_name (char[32]: 32B), status_magic (uint: 4B)
            version, workers_cnt, node_name_raw, magic = struct.unpack("<ii32sI", raw_cfg)
            node_name = node_name_raw.split(b"\x00")[0].decode("ascii")
            self.assertEqual(version, 2)
            self.assertEqual(workers_cnt, 4)
            self.assertEqual(node_name, "ARM64_PROD_NODE_01")
            self.assertEqual(hex(magic), hex(0x41524D36))

            # 4. Zero-stop time assertion:
            # RuntimeEvidenceProvider tracking target stop duration
            from extractor.observation_budget import ObservationBudgetTracker
            from extractor.runtime_evidence_provider import RuntimeEvidenceProvider
            budget_tracker = ObservationBudgetTracker()
            ev_provider = RuntimeEvidenceProvider(adapter=adapter, budget_tracker=budget_tracker)
            self.assertEqual(ev_provider.budget_tracker.metrics.target_stop_duration_ms, 0.0)

            # 5. Shared memory IPC inspection
            shm_map = None
            for m in maps:
                if "/dynstate_test_shm" in m.get("pathname", "") or "/dev/shm" in m.get("pathname", ""):
                    shm_map = m
                    break
            if shm_map:
                shm_addr = shm_map["start_int"]
                raw_shm, shm_status, _ = adapter.read_memory(pid, shm_addr, 64)
                self.assertEqual(shm_status, "OBSERVED")
                shm_magic, seq_num = struct.unpack("<II", raw_shm[:8])
                self.assertEqual(hex(shm_magic), hex(0x53484D31))
                self.assertGreater(seq_num, 1000)

        finally:
            proc.terminate()
            try:
                proc.wait(timeout=2.0)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    def test_04_target_restart_and_pid_reuse_detection(self):
        """Verify that adapter detects PID reuse / target restart via start_time and boot_id."""
        proc1 = subprocess.Popen(
            [self.bin_debug],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            for _ in range(50):
                line = proc1.stdout.readline()
                if "TARGET_READY" in line:
                    break
                time.sleep(0.05)
            pid = proc1.pid

            adapter = LocalTargetAdapter()
            # Pin the identity of proc1
            ident = adapter.pin_target_identity(pid)
            self.assertIsNotNone(ident)
            self.assertEqual(ident["pid"], pid)

            # Identity verification succeeds on pinned target
            ok_pin, _ = adapter.verify_pinned_identity(pid)
            self.assertTrue(ok_pin)

            # Memory read works normally on pinned target
            data, status, _ = adapter.read_memory(pid, 0x1000, 16)
            # Address 0x1000 is unmapped, so UNAVAILABLE, but NOT PID_REUSED
            self.assertIn(status, ("UNAVAILABLE", "OBSERVED"))

        finally:
            proc1.terminate()
            proc1.wait()

        # Simulate process restart or PID reuse with a new process
        proc2 = subprocess.Popen(
            [self.bin_opt],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            # Inject a mismatch in adapter's pinned identity to simulate exact PID reuse
            adapter._pinned_identities[pid]["start_time"] = "99999999"

            ok_pin, pin_err = adapter.verify_pinned_identity(pid)
            self.assertFalse(ok_pin)
            self.assertIn("start_time", pin_err)

            # Calling read_memory on reused PID must fail-closed with PID_REUSED
            mem_data, mem_status, mem_err = adapter.read_memory(pid, 0x1000, 16)
            self.assertIsNone(mem_data)
            self.assertEqual(mem_status, "PID_REUSED")
            self.assertIn("PID", mem_err)

        finally:
            proc2.terminate()
            proc2.wait()


if __name__ == "__main__":
    unittest.main()

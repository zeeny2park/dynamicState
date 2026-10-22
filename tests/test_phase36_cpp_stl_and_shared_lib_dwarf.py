"""Phase 36 (Phase 5 & Phase 6 Roadmap) Test Suite:
1. Phase 5: C++ STL Container Pretty-Decoding, Indexing & Smart Pointer Dereferencing
   (`std::string` SSO & heap, `std::vector<T>`, `std::unique_ptr<T>`, `std::shared_ptr<T>`).
2. Phase 6: Shared Library (`.so`) Multi-Module DWARF Symbol Binding & Per-Module `PT_LOAD` `load_bias` Relocation.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from extractor.agent_runtime import AgentRuntime
from extractor.watch_session import WatchSessionManager
from extractor.web.server import WebApiAdapter
import scripts.mcp_server as mcp_srv


class TestPhase36CppStlAndSharedLibDwarf(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.work_dir = tempfile.mkdtemp(prefix="dynstate_p36_")
        cls.corpus_dir = os.path.join(cls.work_dir, "corpus")
        os.makedirs(cls.corpus_dir, exist_ok=True)

        # 1. Create C++ Shared Library source (libsensor_plugin.so)
        so_src = os.path.join(cls.work_dir, "sensor_plugin.cpp")
        with open(so_src, "w", encoding="utf-8") as f:
            f.write("""
#include <stdint.h>

struct PluginSensorState {
    int sensor_id;
    int reading;
    int status_code;
};

extern "C" {
    PluginSensorState g_plugin_state = {501, 777, 1};

    void update_plugin_sensor(int new_reading, int new_status) {
        g_plugin_state.reading = new_reading;
        g_plugin_state.status_code = new_status;
    }

    int get_plugin_reading() {
        return g_plugin_state.reading;
    }
}
""")
        cls.so_debug_bin = os.path.join(cls.work_dir, "libsensor_plugin_debug.so")
        cls.so_stripped_bin = os.path.join(cls.work_dir, "libsensor_plugin.so")
        subprocess.run(
            [
                "g++", "-shared", "-fPIC", "-g", "-O0", "-fno-inline",
                "-Wl,--build-id=sha1", so_src, "-o", cls.so_debug_bin
            ],
            check=True,
        )
        subprocess.run(["strip", "-s", "-o", cls.so_stripped_bin, cls.so_debug_bin], check=True)

        # 2. Create Main C++ Executable using STL containers + linking against libsensor_plugin.so
        app_src = os.path.join(cls.work_dir, "stl_so_app.cpp")
        with open(app_src, "w", encoding="utf-8") as f:
            f.write("""
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <unistd.h>
#include <sys/prctl.h>

extern "C" void update_plugin_sensor(int new_reading, int new_status);
extern "C" int get_plugin_reading();

struct ChannelInfo {
    int id;
    int score;
};

std::string g_device_name = "EdgeGateway_V2";
std::string g_long_token = "LONG_HEAP_ALLOCATED_STRING_BEYOND_SSO_BUFFER_THRESHOLD_12345";
std::vector<int> g_readings = {10, 20, 30, 40};
std::vector<ChannelInfo> g_channels = {{1, 100}, {2, 200}, {3, 300}};
std::unique_ptr<ChannelInfo> g_active_channel;
std::shared_ptr<ChannelInfo> g_backup_channel;

int main() {
    prctl(0x59616d61, -1, 0, 0, 0);
    g_active_channel = std::make_unique<ChannelInfo>(ChannelInfo{7, 700});
    g_backup_channel = std::make_shared<ChannelInfo>(ChannelInfo{9, 900});

    // Touch shared library symbol so linker keeps it active
    if (get_plugin_reading() == 0) {
        update_plugin_sensor(1, 1);
    }

    std::cout << "READY" << std::endl;
    std::cout.flush();

    std::string cmd;
    while (std::getline(std::cin, cmd)) {
        if (cmd == "MUTATE_ALL") {
            g_device_name = "EdgeGateway_Mutated";
            g_channels[1].score = 250;
            g_active_channel->score = 750;
            update_plugin_sensor(888, 2);
            std::cout << "MUTATED" << std::endl;
            std::cout.flush();
        } else if (cmd == "STOP") {
            break;
        }
    }
    return 0;
}
""")
        cls.app_debug_bin = os.path.join(cls.work_dir, "stl_so_app_debug.elf")
        cls.app_stripped_bin = os.path.join(cls.work_dir, "stl_so_app.stripped")
        subprocess.run(
            [
                "g++", "-fPIE", "-pie", "-g", "-O0", "-fno-inline", "-fno-omit-frame-pointer",
                "-Wl,--build-id=sha1", f"-Wl,-rpath,{cls.work_dir}",
                app_src, cls.so_stripped_bin, "-o", cls.app_debug_bin
            ],
            check=True,
        )
        subprocess.run(["strip", "-s", "-o", cls.app_stripped_bin, cls.app_debug_bin], check=True)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.work_dir, ignore_errors=True)

    def setUp(self):
        self._procs = []

    def tearDown(self):
        for p in self._procs:
            try:
                p.kill()
                p.wait(timeout=2)
            except Exception:
                pass
            for s in (p.stdin, p.stdout, p.stderr):
                if s:
                    try:
                        s.close()
                    except Exception:
                        pass

    def _start_target(self) -> subprocess.Popen:
        p = subprocess.Popen(
            [self.app_stripped_bin],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self._procs.append(p)
        deadline = time.time() + 3.0
        while time.time() < deadline:
            line = p.stdout.readline()
            if "READY" in line:
                break
        return p

    def test_01_cpp_stl_containers_string_vector_and_smart_pointers(self):
        """Verify Phase 5 decoding, indexing, and dereferencing of std::string, std::vector, std::unique_ptr, and std::shared_ptr."""
        proc = self._start_target()
        mgr = WatchSessionManager(corpus_dir=self.corpus_dir)

        res = mgr.evaluate_symbol_paths(
            pid=proc.pid,
            companion_elf_path=self.app_debug_bin,
            expressions=[
                "g_device_name",
                "g_long_token",
                "g_readings",
                "g_readings[2]",
                "g_channels",
                "g_channels[1].score",
                "g_channels[99]",
                "g_active_channel",
                "g_active_channel->score",
                "g_backup_channel->id",
            ],
        )
        by_ex = {r["expression"]: r for r in res["results"]}

        # 1. std::string (SSO and heap-allocated)
        self.assertEqual(by_ex["g_device_name"]["status"], "OBSERVED")
        self.assertEqual(by_ex["g_device_name"]["value"], "EdgeGateway_V2")
        self.assertEqual(by_ex["g_long_token"]["status"], "OBSERVED")
        self.assertEqual(by_ex["g_long_token"]["value"], "LONG_HEAP_ALLOCATED_STRING_BEYOND_SSO_BUFFER_THRESHOLD_12345")

        # 2. std::vector<int> and element indexing
        self.assertEqual(by_ex["g_readings"]["status"], "OBSERVED")
        self.assertEqual(by_ex["g_readings"]["value"]["container"], "std::vector")
        self.assertEqual(by_ex["g_readings"]["value"]["size"], 4)
        self.assertEqual(by_ex["g_readings"]["value"]["elements"], [10, 20, 30, 40])
        self.assertEqual(by_ex["g_readings[2]"]["status"], "OBSERVED")
        self.assertEqual(by_ex["g_readings[2]"]["value"], 30)

        # 3. std::vector<ChannelInfo> and struct element field path `g_channels[1].score`
        self.assertEqual(by_ex["g_channels"]["status"], "OBSERVED")
        self.assertEqual(by_ex["g_channels"]["value"]["size"], 3)
        self.assertEqual(by_ex["g_channels[1].score"]["status"], "OBSERVED")
        self.assertEqual(by_ex["g_channels[1].score"]["value"], 200)
        self.assertEqual(by_ex["g_channels[99]"]["status"], "OUT_OF_BOUNDS")

        # 4. std::unique_ptr<ChannelInfo> and std::shared_ptr<ChannelInfo>
        self.assertEqual(by_ex["g_active_channel"]["status"], "OBSERVED")
        self.assertEqual(by_ex["g_active_channel"]["value"]["smart_ptr"], "std::unique_ptr")
        self.assertEqual(by_ex["g_active_channel"]["value"]["target"]["score"], 700)
        self.assertEqual(by_ex["g_active_channel->score"]["status"], "OBSERVED")
        self.assertEqual(by_ex["g_active_channel->score"]["value"], 700)
        self.assertEqual(by_ex["g_backup_channel->id"]["status"], "OBSERVED")
        self.assertEqual(by_ex["g_backup_channel->id"]["value"], 9)

    def test_02_shared_library_so_multi_dwarf_binding_and_mutation_diff(self):
        """Verify Phase 6 shared library (.so) DWARF symbol binding, per-module load_bias, and mutation diffing."""
        proc = self._start_target()
        mgr = WatchSessionManager(corpus_dir=self.corpus_dir)
        combined_elfs = f"{self.app_debug_bin},{self.so_debug_bin}"

        # 1. Verify get_memory_map_and_threads discovers both main binary and libsensor_plugin.so
        map_data = mgr.get_memory_map_and_threads(proc.pid, companion_elf_path=combined_elfs)
        mod_names = [m["module"] for m in map_data.get("loaded_debug_modules", [])]
        self.assertTrue(any("libsensor_plugin.so" in m for m in mod_names), f"Expected libsensor_plugin.so in {mod_names}")
        var_names = {v["name"]: v for v in map_data["discoverable_variables"]}
        self.assertIn("g_plugin_state", var_names)
        self.assertEqual(var_names["g_plugin_state"]["memory_category"], "shared_library")

        # 2. Evaluate shared library globals alongside main executable STL containers
        ev = mgr.evaluate_symbol_paths(
            pid=proc.pid,
            companion_elf_path=combined_elfs,
            expressions=[
                "g_plugin_state",
                "g_plugin_state.reading",
                "libsensor_plugin.so::g_plugin_state.sensor_id",
                "g_channels[1].score",
            ],
        )
        by_ex = {r["expression"]: r for r in ev["results"]}
        self.assertEqual(by_ex["g_plugin_state"]["status"], "OBSERVED")
        self.assertEqual(by_ex["g_plugin_state"]["value"]["reading"], 777)
        self.assertEqual(by_ex["g_plugin_state.reading"]["value"], 777)
        self.assertEqual(by_ex["libsensor_plugin.so::g_plugin_state.sensor_id"]["value"], 501)
        self.assertEqual(by_ex["g_channels[1].score"]["value"], 200)

        # 3. Trigger live mutation across both main executable STL objects and shared library (.so) state
        def _mutate():
            time.sleep(0.12)
            try:
                proc.stdin.write("MUTATE_ALL\n")
                proc.stdin.flush()
            except Exception:
                pass

        th = threading.Thread(target=_mutate, daemon=True)
        th.start()
        diff_res = mgr.capture_and_diff_expressions(
            pid=proc.pid,
            companion_elf_path=combined_elfs,
            expressions=[
                "g_device_name",
                "g_channels[1].score",
                "g_active_channel->score",
                "g_plugin_state.reading",
                "g_plugin_state.sensor_id",
            ],
            wait_ms=300,
        )
        th.join(timeout=1.0)

        changed = {c["path"]: (c["before"], c["after"]) for c in diff_res["changed"]}
        unchanged = {u["path"]: u["value"] for u in diff_res["unchanged"]}

        self.assertEqual(changed.get("g_device_name"), ("EdgeGateway_V2", "EdgeGateway_Mutated"))
        self.assertEqual(changed.get("g_channels[1].score"), (200, 250))
        self.assertEqual(changed.get("g_active_channel->score"), (700, 750))
        self.assertEqual(changed.get("g_plugin_state.reading"), (777, 888))
        self.assertEqual(unchanged.get("g_plugin_state.sensor_id"), 501)


if __name__ == "__main__":
    unittest.main()

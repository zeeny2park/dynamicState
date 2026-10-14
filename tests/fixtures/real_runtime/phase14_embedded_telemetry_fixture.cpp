#include <iostream>
#include <string>
#include <sstream>
#include <thread>
#include <atomic>
#include <chrono>
#include <unistd.h>
#include <signal.h>
#include <cstdint>

// Phase 14 Representative Embedded Linux Telemetry Target Fixture
// Models an embedded IoT / industrial controller daemon with typed telemetry structs.

struct TelemetryState {
    uint32_t sensor_reading;
    uint32_t status_flags;
    uint32_t sample_counter;
    uint32_t last_error_code;
};

struct DeviceConfig {
    uint32_t device_id;
    uint16_t sample_interval_ms;
    uint16_t reserved;
};

struct NegativeControlState {
    uint32_t baseline_token;
    uint32_t untouched_counter;
};

// Global roots for DWARF semantic traversal and offset resolution
TelemetryState g_telemetry_state = {1000, 1, 10, 0};
DeviceConfig g_device_config = {42, 50, 0};
NegativeControlState g_negative_control = {0xCAFE, 5555};

std::atomic<bool> g_running{true};
std::atomic<bool> g_competing_active{false};
std::atomic<uint64_t> g_competing_ticks{0};

// 1. Primary active writer: legitimate periodic telemetry sampler
void telemetry_periodic_sample_writer(uint32_t new_reading, uint32_t new_flags, uint32_t new_counter) {
    g_telemetry_state.sensor_reading = new_reading;
    g_telemetry_state.status_flags = new_flags;
    g_telemetry_state.sample_counter = new_counter;
}

// 2. Competing writer: asynchronous emergency override writing to the same field
void telemetry_emergency_override_writer(uint32_t override_reading, uint32_t override_counter) {
    g_telemetry_state.sensor_reading = override_reading;
    g_telemetry_state.sample_counter = override_counter;
}

// 3. Error state mutator
void telemetry_error_flag_writer(uint32_t err_code) {
    g_telemetry_state.last_error_code = err_code;
}

// 4. Read-only diagnostic function
uint32_t telemetry_read_only_status() {
    return g_telemetry_state.sensor_reading + g_negative_control.untouched_counter;
}

// Background thread simulating concurrent asynchronous writer
void telemetry_background_interferer() {
    while (g_running.load(std::memory_order_relaxed)) {
        if (g_competing_active.load(std::memory_order_relaxed)) {
            telemetry_emergency_override_writer(9999, 8888);
            g_competing_ticks++;
        }
        std::this_thread::sleep_for(std::chrono::microseconds(100));
    }
}

void sig_handler(int) {
    g_running.store(false, std::memory_order_relaxed);
}

int main(int argc, char** argv) {
    signal(SIGTERM, sig_handler);
    signal(SIGINT, sig_handler);

    std::thread comp_t(telemetry_background_interferer);

    // Initial handshake signal for process synchronizer
    std::cout << "READY" << std::endl;
    std::cout.flush();

    // Command listener on stdin
    std::string line;
    while (g_running.load(std::memory_order_relaxed) && std::getline(std::cin, line)) {
        if (line.rfind("SAMPLE", 0) == 0) {
            uint32_t reading = 2000;
            uint32_t counter = 20;
            std::istringstream iss(line);
            std::string cmd;
            iss >> cmd >> reading >> counter;
            telemetry_periodic_sample_writer(reading, 2, counter);
            std::cout << "SAMPLE_MUTATED" << std::endl;
            std::cout.flush();
        } else if (line.rfind("OVERRIDE", 0) == 0) {
            uint32_t reading = 9999;
            uint32_t counter = 99;
            std::istringstream iss(line);
            std::string cmd;
            iss >> cmd >> reading >> counter;
            telemetry_emergency_override_writer(reading, counter);
            std::cout << "OVERRIDE_MUTATED" << std::endl;
            std::cout.flush();
        } else if (line.rfind("ERROR", 0) == 0) {
            uint32_t err = 500;
            std::istringstream iss(line);
            std::string cmd;
            iss >> cmd >> err;
            telemetry_error_flag_writer(err);
            std::cout << "ERROR_MUTATED" << std::endl;
            std::cout.flush();
        } else if (line == "ENABLE_COMPETING") {
            g_competing_active.store(true, std::memory_order_relaxed);
            std::cout << "COMPETING_ENABLED" << std::endl;
            std::cout.flush();
        } else if (line == "DISABLE_COMPETING") {
            g_competing_active.store(false, std::memory_order_relaxed);
            std::cout << "COMPETING_DISABLED" << std::endl;
            std::cout.flush();
        } else if (line == "NOOP") {
            std::cout << "NOOP_DONE" << std::endl;
            std::cout.flush();
        } else if (line == "STOP") {
            g_running.store(false, std::memory_order_relaxed);
            std::cout << "STOPPED" << std::endl;
            std::cout.flush();
            break;
        }
    }

    g_running.store(false, std::memory_order_relaxed);
    if (comp_t.joinable()) {
        comp_t.join();
    }
    return 0;
}

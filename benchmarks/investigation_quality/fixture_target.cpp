/**
 * Phase 17 Investigation Quality Benchmark C++ Target Fixture.
 *
 * Implements 6 distinct, deterministic state-space scenarios:
 * 1. Valid Transition: Clean deterministic state transition via known causal writer.
 * 2. Stale / Inconsistent Field: Partial struct mutation leaving cached field stale.
 * 3. Invalid Enum / State: Field mutated to illegal out-of-range value (999).
 * 4. Null / Invalid Pointer: Non-zero buffer size accompanied by null data pointer.
 * 5. Cross-Thread Non-Atomic Ambiguity: Competing unsynchronized thread writers.
 * 6. Negative Control: External / unassociated state change with no causal writer in binary.
 */

#include <iostream>
#include <cstdint>
#include <thread>
#include <atomic>
#include <chrono>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <signal.h>

// Scenario 1: Valid Transition
enum WorkerStatus {
    STATUS_INITIALIZING = 1,
    STATUS_RUNNING = 2,
    STATUS_STOPPED = 3
};

// Scenario 3: Invalid Enum / State
enum DeviceMode {
    MODE_IDLE = 0,
    MODE_ACTIVE = 1,
    MODE_STANDBY = 2
};

struct InvariantTarget {
    // Scenario 1: Valid transition
    int worker_status;

    // Scenario 2: Stale / Inconsistent field
    int epoch_id;
    int cached_epoch;

    // Scenario 3: Invalid enum / out-of-range value
    int device_mode;

    // Scenario 4: Null / invalid pointer
    uint64_t buffer_size;
    void* data_ptr;

    // Scenario 5: Cross-thread non-atomic ambiguity
    uint64_t unsynchronized_metric;

    // Scenario 6: Negative control (unassociated field)
    uint64_t unassociated_field;
};

// Global root instance referenced by DWARF
InvariantTarget g_target;

// Dedicated causal functions
void transition_worker_state(int new_status) {
    g_target.worker_status = new_status;
}

void update_epoch_partial(int new_epoch) {
    g_target.epoch_id = new_epoch;
    // Note: intentionally omits updating g_target.cached_epoch to create invariant drift
}

void set_illegal_device_mode(int mode) {
    g_target.device_mode = mode;
}

void allocate_invalid_buffer(uint64_t size) {
    g_target.buffer_size = size;
    g_target.data_ptr = nullptr;
}

// Scenario 5: Competing worker threads
std::atomic<bool> g_competing_running{false};

void competing_writer_a() {
    while (g_competing_running.load(std::memory_order_relaxed)) {
        g_target.unsynchronized_metric++;
        std::this_thread::sleep_for(std::chrono::microseconds(50));
    }
}

void competing_writer_b() {
    while (g_competing_running.load(std::memory_order_relaxed)) {
        g_target.unsynchronized_metric += 10;
        std::this_thread::sleep_for(std::chrono::microseconds(50));
    }
}

// Scenario 6: Static candidate in binary that has NO causal relationship to unassociated_field
void unrelated_helper_function() {
    // Does not write to unassociated_field
    volatile int dummy = 42;
    (void)dummy;
}

void init_state() {
    g_target.worker_status = STATUS_INITIALIZING;
    g_target.epoch_id = 1;
    g_target.cached_epoch = 1;
    g_target.device_mode = MODE_IDLE;
    g_target.buffer_size = 0;
    g_target.data_ptr = nullptr;
    g_target.unsynchronized_metric = 100;
    g_target.unassociated_field = 100;
}

int main(int argc, char** argv) {
    init_state();

    if (argc > 1 && strcmp(argv[1], "--mutate-all") == 0) {
        // Apply all 6 scenario mutations
        transition_worker_state(STATUS_RUNNING);
        update_epoch_partial(10);
        set_illegal_device_mode(999);
        allocate_invalid_buffer(4096);
        g_target.unassociated_field = 200; // Simulated external change
    }

    std::cout << "READY worker_status=" << g_target.worker_status
              << " epoch_id=" << g_target.epoch_id
              << " cached_epoch=" << g_target.cached_epoch
              << " device_mode=" << g_target.device_mode
              << " buffer_size=" << g_target.buffer_size
              << " data_ptr=" << g_target.data_ptr
              << " metric=" << g_target.unsynchronized_metric
              << " unassociated=" << g_target.unassociated_field
              << std::endl;

    return 0;
}
